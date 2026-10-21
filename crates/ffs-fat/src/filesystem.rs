//! FsOps adapter for the native FAT reader and ordered offline writer.
//! Native mutation and its cache publication are serialized against every
//! mounted read and write. This is not a crash-atomic transaction protocol;
//! FAT node identities remain mount-local, not export-stable handles.

mod exchange;
mod health;
mod lifetime;

use super::reader::replacement::{
    create_in_volume, mkdir_in_volume, rename_in_volume, rmdir_in_volume, set_attr_in_volume,
    sync_volume, truncate_in_volume, unlink_in_volume, write_range_in_volume,
};
use super::reader::{Directory, Entry, FatVolume, FileChain, MAX_CHAIN_CLUSTERS, checkpoint};
use asupersync::Cx;
use ffs_core::{
    DirEntry, FiemapExtent, FileType, FsOps, FsStat, InodeAttr, ReaddirPage, RequestScope,
    SeekWhence, SetAttrRequest,
};
use ffs_error::{FfsError, Result};
use ffs_ondisk::fat::{FatKind, FatTimestamp};
use ffs_types::{InodeNumber, ParseError};
use health::{MountHealth, OperationGuard};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

const ROOT: InodeNumber = InodeNumber(1);
const MAX_NODES: usize = 131_072;
const MAX_CACHED_CHAINS: usize = 1024;
const DIRECTORY_PAGE: usize = 256;
const FIRST_SYNTHETIC_INO: u64 = 1_u64 << 48;
// Reserve cookies 1/2 for dot entries and stay inside FUSE's signed d_off.
const MAX_SYNTHETIC_INO: u64 = (1_u64 << 63) - 3;

#[derive(Clone)]
struct Node {
    parent: InodeNumber,
    entry: Option<Entry>,
}

impl Node {
    fn directory(&self) -> Result<Directory> {
        self.entry
            .as_ref()
            .map_or(Ok(Directory::Root), Entry::directory)
    }
}

struct State {
    nodes: BTreeMap<InodeNumber, Node>,
    slot_to_ino: BTreeMap<u64, InodeNumber>,
    next_synthetic_ino: u64,
    chains: BTreeMap<InodeNumber, Arc<FileChain>>,
    cached_clusters: usize,
    free_clusters: Option<u64>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            nodes: BTreeMap::new(),
            slot_to_ino: BTreeMap::new(),
            next_synthetic_ino: FIRST_SYNTHETIC_INO,
            chains: BTreeMap::new(),
            cached_clusters: 0,
            free_clusters: None,
        }
    }
}

impl State {
    fn ensure_new_node(&self, writable: bool) -> Result<()> {
        if self.nodes.len() >= MAX_NODES {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::ENOMEM,
            )));
        }
        if writable && self.next_synthetic_ino > MAX_SYNTHETIC_INO {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::EOVERFLOW,
            )));
        }
        Ok(())
    }
}

pub struct FatFs {
    volume: FatVolume,
    operations: RwLock<()>,
    health: MountHealth,
    state: Mutex<State>,
    lifetime: Mutex<lifetime::Lifetime>,
    uid: u32,
    gid: u32,
    writable: bool,
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(315_532_800, |d| d.as_secs().max(315_532_800))
}

/// Validate all representability constraints before a truncate can publish.
/// FAT stores local calendar fields; retain the adapter's UTC projection and
/// let the native encoder round mtime to two seconds and atime to one day.
fn requested_fat_time(time: SystemTime) -> Result<u64> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| FfsError::Io(std::io::Error::from_raw_os_error(libc::EINVAL)))?
        .as_secs();
    if !(315_532_800..4_354_819_200).contains(&seconds) {
        return Err(FfsError::Io(std::io::Error::from_raw_os_error(
            libc::EINVAL,
        )));
    }
    Ok(seconds)
}

fn map_mutation_error(error: anyhow::Error) -> FfsError {
    let error = match error.downcast::<FfsError>() {
        Ok(ffs_err) => return ffs_err,
        Err(other) => other,
    };
    let error = match error.downcast::<std::io::Error>() {
        Ok(io_err) => return FfsError::Io(io_err),
        Err(other) => other,
    };
    let msg = error.to_string();
    if msg.contains("already exists") {
        FfsError::Exists
    } else if msg.contains("is not empty") {
        FfsError::NotEmpty
    } else if msg.contains("read-only")
        || msg.contains("cannot unlink the root")
        || msg.contains("cannot remove the root")
        || msg.contains("cannot rename the root")
    {
        FfsError::PermissionDenied
    } else if msg.contains("into a descendant") {
        FfsError::Format(msg)
    } else if msg.contains("insufficient") {
        FfsError::NoSpace
    } else {
        FfsError::Format(msg)
    }
}

impl FatFs {
    /// Construct a read-only filesystem view. Mutation requires the separate
    /// explicit `new_with_mode` entry point and writable backing authority.
    pub fn new(cx: &Cx, volume: FatVolume, uid: u32, gid: u32) -> Result<Self> {
        Self::new_with_mode(cx, volume, uid, gid, false)
    }

    pub fn new_with_mode(
        cx: &Cx,
        volume: FatVolume,
        uid: u32,
        gid: u32,
        writable: bool,
    ) -> Result<Self> {
        checkpoint(cx)?;
        // Reject an unreadable root before exposing a mount, not after INIT.
        volume.directory_size(cx, Directory::Root)?;
        let entries = volume.list(cx, Directory::Root)?;
        let _ = Self::checked_names(&entries)?;
        let mut state = State::default();
        state.nodes.insert(
            ROOT,
            Node {
                parent: ROOT,
                entry: None,
            },
        );
        checkpoint(cx)?;
        let (volume, epoch) = volume.with_mutation_observer();
        Ok(Self {
            volume,
            operations: RwLock::new(()),
            health: MountHealth::new(epoch),
            state: Mutex::new(state),
            lifetime: Mutex::new(lifetime::Lifetime::default()),
            uid,
            gid,
            writable,
        })
    }

    fn operation(&self, cx: &Cx, mutation: bool) -> Result<OperationGuard<'_>> {
        // Always acquire the gate before `state`; private helpers never
        // reacquire it. Failure publication happens before releasing it.
        self.health.operation(cx, &self.operations, mutation)
    }

    fn ensure_writable(&self) -> Result<()> {
        if !self.writable {
            return Err(FfsError::ReadOnly);
        }
        Ok(())
    }

    fn state(&self) -> Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("FAT namespace lock poisoned")))
    }

    fn node(&self, cx: &Cx, ino: InodeNumber) -> Result<Node> {
        checkpoint(cx)?;
        let node = self
            .state()?
            .nodes
            .get(&ino)
            .cloned()
            .ok_or_else(|| FfsError::NotFound(format!("FAT inode {}", ino.0)))?;
        checkpoint(cx)?;
        Ok(node)
    }

    fn path_for_inode(&self, ino: InodeNumber) -> Result<String> {
        if ino == ROOT {
            return Ok("/".to_owned());
        }
        let state = self.state()?;
        let mut components = Vec::new();
        let mut current = ino;
        for _ in 0..=256 {
            let node = state
                .nodes
                .get(&current)
                .ok_or_else(|| FfsError::NotFound(format!("FAT inode {}", current.0)))?;
            if current == ROOT {
                components.reverse();
                return Ok(format!("/{}", components.join("/")));
            }
            let entry = node
                .entry
                .as_ref()
                .ok_or_else(|| FfsError::NotFound(format!("FAT inode {}", current.0)))?;
            components.push(entry.name()?);
            current = node.parent;
        }
        Err(FfsError::NameTooLong)
    }

    fn child_path(&self, parent: InodeNumber, name: &OsStr) -> Result<(String, String)> {
        let name_str = name.to_str().ok_or_else(|| {
            FfsError::UnsupportedFeature("FAT requires a UTF-8 presentation name".into())
        })?;
        if name_str.is_empty()
            || matches!(name_str, "." | "..")
            || name_str.contains(['/', '\\', '\0'])
        {
            return Err(FfsError::Format("invalid FAT path component".into()));
        }
        let parent_path = self.path_for_inode(parent)?;
        let full = if parent_path == "/" {
            format!("/{name_str}")
        } else {
            format!("{parent_path}/{name_str}")
        };
        Ok((full, name_str.to_owned()))
    }

    /// Both rename entry points hold the same exclusive operation gate across
    /// destination lookup, native publication and mount-identity updates.
    /// NOREPLACE is a namespace exclusion rule, not crash-atomic FAT metadata.
    fn rename_locked(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        name: &OsStr,
        new_parent: InodeNumber,
        new_name: &OsStr,
        no_replace: bool,
    ) -> Result<()> {
        checkpoint(cx)?;
        self.ensure_writable()?;
        let parent_dir = self.node(cx, parent)?.directory()?;
        let new_parent_dir = self.node(cx, new_parent)?.directory()?;
        let (from_path, from_name) = self.child_path(parent, name)?;
        let (to_path, to_name) = self.child_path(new_parent, new_name)?;
        let src_before = self.visible_lookup(cx, parent_dir, &from_name)?;
        let dst_before = match self.volume.lookup(cx, new_parent_dir, &to_name) {
            Ok(entry) => {
                self.require_unreserved_target(entry.offset)?;
                Some(entry)
            }
            Err(FfsError::NotFound(_)) => None,
            Err(error) => return Err(error),
        };
        // Aliases, case variants and the source itself are existing targets
        // too. Refuse before registering nodes or publishing any disk writes.
        if no_replace && dst_before.is_some() {
            return Err(FfsError::Exists);
        }
        if let Some(target) = &dst_before
            && target.offset != src_before.offset
            && !target.native.is_directory()
        {
            let target_ino = self.state()?.slot_to_ino.get(&target.offset).copied();
            if let Some(target_ino) = target_ino
                && self.pinned(target_ino)?
            {
                return self
                    .replace_pinned_locked(cx, parent, name, new_parent, new_name, target_ino);
            }
        }
        let src_ino = self.register(cx, parent, src_before.clone())?;

        rename_in_volume(cx, &self.volume, &from_path, &to_path, false)
            .map_err(map_mutation_error)?;

        let new_entry = self.volume.lookup(cx, new_parent_dir, &to_name)?;
        let mut state = self.state()?;
        state.free_clusters = None;
        if let Some(overwritten) = dst_before
            && overwritten.offset != src_before.offset
            && let Some(dst_ino) = state.slot_to_ino.remove(&overwritten.offset)
            && dst_ino != src_ino
        {
            Self::invalidate_cached_chain(&mut state, dst_ino);
            state.nodes.remove(&dst_ino);
        }
        state.slot_to_ino.remove(&src_before.offset);
        state.slot_to_ino.insert(new_entry.offset, src_ino);
        Self::invalidate_cached_chain(&mut state, src_ino);
        if let Some(node) = state.nodes.get_mut(&src_ino) {
            node.parent = new_parent;
            node.entry = Some(new_entry);
        }
        Ok(())
    }

    fn invalidate_cached_chain(state: &mut State, ino: InodeNumber) {
        if let Some(prev) = state.chains.remove(&ino) {
            state.cached_clusters = state
                .cached_clusters
                .saturating_sub(prev.clusters.capacity());
        }
    }

    fn refresh_node_from_path(&self, cx: &Cx, ino: InodeNumber, path: &str) -> Result<Node> {
        let entry = self
            .volume
            .resolve(cx, path)?
            .ok_or_else(|| FfsError::NotFound(path.to_owned()))?;
        let mut state = self.state()?;
        Self::invalidate_cached_chain(&mut state, ino);
        state.free_clusters = None;
        let old_offset = state
            .nodes
            .get(&ino)
            .ok_or_else(|| FfsError::NotFound(format!("FAT inode {}", ino.0)))?
            .entry
            .as_ref()
            .map(|e| e.offset);
        if let Some(old) = old_offset
            && old != entry.offset
        {
            state.slot_to_ino.remove(&old);
        }
        state.slot_to_ino.insert(entry.offset, ino);
        let node = state
            .nodes
            .get_mut(&ino)
            .ok_or_else(|| FfsError::NotFound(format!("FAT inode {}", ino.0)))?;
        node.entry = Some(entry);
        Ok(node.clone())
    }

    fn register(&self, cx: &Cx, parent: InodeNumber, entry: Entry) -> Result<InodeNumber> {
        checkpoint(cx)?;
        let mut state = self.state()?;
        if entry.native.is_directory() {
            let mut ancestor = parent;
            for depth in 0..=256 {
                let node = state.nodes.get(&ancestor).ok_or_else(|| {
                    FfsError::NotFound(format!("FAT ancestor inode {}", ancestor.0))
                })?;
                let cluster = node.entry.as_ref().map_or_else(
                    || {
                        (self.volume.geometry.kind() == FatKind::Fat32)
                            .then_some(self.volume.geometry.root_cluster())
                    },
                    |entry| Some(entry.native.first_cluster),
                );
                if cluster == Some(entry.native.first_cluster) {
                    return Err(FfsError::Corruption {
                        block: entry.offset / 512,
                        detail: "FAT directory links to an ancestor".into(),
                    });
                }
                if ancestor == ROOT {
                    break;
                }
                if depth == 256 {
                    return Err(FfsError::NameTooLong);
                }
                ancestor = node.parent;
            }
        }
        if let Some(&mapped_ino) = state.slot_to_ino.get(&entry.offset) {
            let existing =
                state
                    .nodes
                    .get_mut(&mapped_ino)
                    .ok_or_else(|| FfsError::Corruption {
                        block: entry.offset / 512,
                        detail: "FAT slot mapping has no live node".into(),
                    })?;
            let changed = existing
                .entry
                .as_ref()
                .is_none_or(|old| old.native != entry.native);
            if existing.parent != parent || (!self.writable && changed) {
                return Err(FfsError::Corruption {
                    block: entry.offset / 512,
                    detail: "FAT namespace identity changed or is cross-linked".into(),
                });
            }
            existing.entry = Some(entry);
            if changed {
                Self::invalidate_cached_chain(&mut state, mapped_ino);
                state.free_clusters = None;
            }
            return Ok(mapped_ino);
        }

        state.ensure_new_node(self.writable)?;
        let ino = if self.writable {
            // A deleted/replaced slot can be reused while the kernel still
            // holds the old node ID. Never let that ID address another file.
            let allocated = InodeNumber(state.next_synthetic_ino);
            state.next_synthetic_ino += 1;
            allocated
        } else {
            // Preserve the immutable adapter's existing slot-based identity.
            InodeNumber(entry.offset / 32 + 2)
        };
        if state.nodes.contains_key(&ino) {
            return Err(FfsError::Corruption {
                block: entry.offset / 512,
                detail: "FAT node ID already belongs to another slot".into(),
            });
        }
        state.slot_to_ino.insert(entry.offset, ino);
        state.nodes.insert(
            ino,
            Node {
                parent,
                entry: Some(entry),
            },
        );
        drop(state);
        checkpoint(cx)?;
        Ok(ino)
    }

    /// Reject display/short-alias collisions before publishing a listing using
    /// the volume's selected OEM case pairs, never host locale/normalization.
    fn checked_names(entries: &[Entry]) -> Result<Vec<String>> {
        let mut owners = BTreeMap::new();
        let mut names = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            let name = entry.name()?;
            let alias = entry.short_alias();
            for candidate in std::iter::once(name.as_str()).chain(alias.as_deref()) {
                if owners
                    .insert(entry.oem_code_page.name_key(candidate), index)
                    .is_some_and(|old| old != index)
                {
                    return Err(FfsError::Corruption {
                        block: entry.offset / 512,
                        detail: "ambiguous FAT display name or short alias".into(),
                    });
                }
            }
            names.push(name);
        }
        Ok(names)
    }

    fn mutable_readdir(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        parent: InodeNumber,
        offset: u64,
        entries: Vec<Entry>,
        names: Vec<String>,
    ) -> Result<ReaddirPage> {
        let mut page = Vec::with_capacity(entries.len() + 2);
        for (cookie, target, name) in [(1, ino, b".".as_slice()), (2, parent, b"..".as_slice())] {
            page.push(DirEntry {
                ino: target,
                offset: cookie,
                kind: FileType::Directory,
                name: name.to_vec(),
            });
        }
        for (entry, name) in entries.into_iter().zip(names) {
            checkpoint(cx)?;
            let kind = if entry.native.is_directory() {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            let target = self.register(cx, ino, entry)?;
            page.push(DirEntry {
                ino: target,
                offset: target.0 + 2,
                kind,
                name: name.into_bytes(),
            });
        }
        // Physical cluster order may be fragmented. Neither physical offsets
        // nor indexes in a filtered listing are restartable mutation cookies.
        // Existing IDs/cookies survive unrelated deletions and slot reuse.
        page.sort_unstable_by_key(|entry| entry.offset);
        let end_cookie = page.last().map(|entry| entry.offset);
        page.retain(|entry| entry.offset > offset);
        page.truncate(DIRECTORY_PAGE);
        checkpoint(cx)?;
        Ok(ReaddirPage::new(page).with_end_cookie(end_cookie))
    }

    fn chain(&self, cx: &Cx, ino: InodeNumber, entry: &Entry) -> Result<Arc<FileChain>> {
        checkpoint(cx)?;
        let cached = self.state()?.chains.get(&ino).cloned();
        if let Some(chain) = cached {
            checkpoint(cx)?;
            return Ok(chain);
        }
        // No device I/O under the namespace lock.
        let chain = Arc::new(self.volume.file_chain(cx, entry)?);
        let retained = chain.clusters.capacity();
        if retained > MAX_CHAIN_CLUSTERS {
            return Ok(chain);
        }
        let mut state = self.state()?;
        if let Some(existing) = state.chains.get(&ino) {
            let existing = Arc::clone(existing);
            drop(state);
            checkpoint(cx)?;
            return Ok(existing);
        }
        while state.cached_clusters + retained > MAX_CHAIN_CLUSTERS
            || state.chains.len() >= MAX_CACHED_CHAINS
        {
            let Some((_, previous)) = state.chains.pop_first() else {
                break;
            };
            state.cached_clusters -= previous.clusters.capacity();
        }
        state.cached_clusters += retained;
        state.chains.insert(ino, Arc::clone(&chain));
        drop(state);
        checkpoint(cx)?;
        Ok(chain)
    }

    fn attributes(&self, cx: &Cx, ino: InodeNumber, node: &Node) -> Result<InodeAttr> {
        checkpoint(cx)?;
        let (kind, size, blocks, nlink) = if node
            .entry
            .as_ref()
            .is_none_or(|entry| entry.native.is_directory())
        {
            let directory = node.directory()?;
            let size = self.volume.directory_size(cx, directory)?;
            let children = self.volume.list(cx, directory)?;
            let nlink = 2 + children
                .iter()
                .filter(|entry| entry.native.is_directory())
                .count() as u32;
            (FileType::Directory, size, size.div_ceil(512), nlink)
        } else {
            let entry = node
                .entry
                .as_ref()
                .ok_or_else(|| FfsError::NotFound(format!("FAT inode {}", ino.0)))?;
            let chain = self.chain(cx, ino, entry)?;
            let blocks =
                chain.clusters.len() as u64 * u64::from(self.volume.geometry.cluster_bytes()) / 512;
            (FileType::RegularFile, u64::from(chain.size), blocks, 1)
        };
        let (atime, mtime, crtime) = if let Some(entry) = &node.entry {
            (
                fat_wall_time(entry.native.accessed_timestamp(), entry.offset)?,
                fat_wall_time(entry.native.modified_timestamp(), entry.offset)?,
                fat_wall_time(entry.native.created_timestamp(), entry.offset)?,
            )
        } else {
            (UNIX_EPOCH, UNIX_EPOCH, UNIX_EPOCH)
        };
        let read_only_attr = node
            .entry
            .as_ref()
            .is_some_and(|entry| entry.native.attributes & 0x01 != 0);
        let perm = match (self.writable, kind, read_only_attr) {
            (false, FileType::Directory, _) | (true, FileType::Directory, true) => 0o555,
            (true, FileType::Directory, false) => 0o755,
            (false, _, _) | (true, _, true) => 0o444,
            (true, _, false) => 0o644,
        };
        checkpoint(cx)?;
        Ok(InodeAttr {
            ino,
            size,
            blocks,
            atime,
            mtime,
            ctime: UNIX_EPOCH,
            crtime,
            kind,
            perm,
            nlink: if self.retained(ino)? { 0 } else { nlink },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: self.volume.geometry.cluster_bytes(),
            generation: 1,
        })
    }
}

const FIEMAP_EXTENT_LAST: u32 = 0x0001;
const FIEMAP_EXTENT_NOT_ALIGNED: u32 = 0x0100;
const FIEMAP_EXTENT_UNWRITTEN: u32 = 0x0800;

fn fiemap_corrupt(offset: u64, detail: impl Into<String>) -> FfsError {
    FfsError::Corruption {
        block: offset / 512,
        detail: detail.into(),
    }
}

/// Map the complete verified FAT allocation chain into native physical extents.
///
/// FAT has no sparse/unwritten extent grammar: logical bytes before EOF are data.
/// Retained allocation beyond EOF (KEEP_SIZE and final-cluster slack) is reported
/// as UNWRITTEN so callers can see allocated blocks without treating them as file
/// contents. Physical offsets are relative to the selected FAT volume.
fn fat_fiemap(
    cx: &Cx,
    chain: &FileChain,
    cluster_bytes: u32,
    data_start: u64,
    volume_bytes: u64,
    start: u64,
    length: u64,
) -> Result<Vec<FiemapExtent>> {
    checkpoint(cx)?;
    if cluster_bytes == 0 {
        return Err(fiemap_corrupt(0, "zero FAT FIEMAP cluster size"));
    }
    if chain.clusters.len() > MAX_CHAIN_CLUSTERS {
        return Err(FfsError::UnsupportedFeature(
            "FAT FIEMAP chain exceeds the mounted allocation budget".into(),
        ));
    }
    let cluster_bytes = u64::from(cluster_bytes);
    let capacity = u64::try_from(chain.clusters.len())
        .ok()
        .and_then(|clusters| clusters.checked_mul(cluster_bytes))
        .ok_or_else(|| fiemap_corrupt(0, "FAT FIEMAP logical capacity overflow"))?;
    if u64::from(chain.size) > capacity {
        return Err(fiemap_corrupt(
            u64::from(chain.size),
            "FAT FIEMAP chain is shorter than the directory-entry size",
        ));
    }
    if length == 0 || chain.clusters.is_empty() {
        return Ok(Vec::new());
    }
    let query_end = start.saturating_add(length);
    let query = (start, query_end);
    let file_size = u64::from(chain.size);
    let mut result = Vec::new();
    let mut index = 0_usize;

    let mut emit =
        |logical: u64, physical: u64, extent_length: u64, mut flags: u32| -> Result<()> {
            if extent_length == 0 {
                return Ok(());
            }
            let end = logical
                .checked_add(extent_length)
                .ok_or_else(|| fiemap_corrupt(logical, "FAT FIEMAP extent end overflow"))?;
            if end == capacity {
                flags |= FIEMAP_EXTENT_LAST;
            }
            if !logical.is_multiple_of(cluster_bytes)
                || !physical.is_multiple_of(cluster_bytes)
                || !extent_length.is_multiple_of(cluster_bytes)
            {
                flags |= FIEMAP_EXTENT_NOT_ALIGNED;
            }
            if logical >= query.1 || end <= query.0 {
                return Ok(());
            }
            result
                .try_reserve(1)
                .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
            result.push(FiemapExtent {
                logical,
                physical,
                length: extent_length,
                flags,
            });
            Ok(())
        };

    while index < chain.clusters.len() {
        checkpoint(cx)?;
        let first = chain.clusters[index];
        if first < 2 {
            return Err(fiemap_corrupt(
                index as u64 * cluster_bytes,
                "reserved cluster appears in FAT FIEMAP chain",
            ));
        }
        let mut end_index = index + 1;
        while end_index < chain.clusters.len()
            && chain.clusters[end_index - 1].checked_add(1) == Some(chain.clusters[end_index])
        {
            end_index += 1;
        }

        let logical = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_mul(cluster_bytes))
            .ok_or_else(|| fiemap_corrupt(0, "FAT FIEMAP logical offset overflow"))?;
        let cluster_delta = u64::from(first - 2);
        let physical = cluster_delta
            .checked_mul(cluster_bytes)
            .and_then(|delta| data_start.checked_add(delta))
            .ok_or_else(|| fiemap_corrupt(logical, "FAT FIEMAP physical offset overflow"))?;
        let run_clusters = u64::try_from(end_index - index)
            .map_err(|_| fiemap_corrupt(logical, "FAT FIEMAP run length overflow"))?;
        let run_length = run_clusters
            .checked_mul(cluster_bytes)
            .ok_or_else(|| fiemap_corrupt(logical, "FAT FIEMAP run byte length overflow"))?;
        let run_end = logical
            .checked_add(run_length)
            .ok_or_else(|| fiemap_corrupt(logical, "FAT FIEMAP logical run overflow"))?;
        let physical_end = physical
            .checked_add(run_length)
            .ok_or_else(|| fiemap_corrupt(logical, "FAT FIEMAP physical run overflow"))?;
        if physical_end > volume_bytes {
            return Err(fiemap_corrupt(
                logical,
                "FAT FIEMAP physical run exceeds the selected volume",
            ));
        }

        let initialized_end = file_size.clamp(logical, run_end);
        emit(logical, physical, initialized_end - logical, 0)?;
        emit(
            initialized_end,
            physical + (initialized_end - logical),
            run_end - initialized_end,
            FIEMAP_EXTENT_UNWRITTEN,
        )?;
        index = end_index;
    }

    checkpoint(cx)?;
    Ok(result)
}

impl FsOps for FatFs {
    fn getattr(&self, cx: &Cx, _scope: &mut RequestScope, ino: InodeNumber) -> Result<InodeAttr> {
        let _operation = self.operation(cx, false)?;
        let node = self.node(cx, ino)?;
        self.attributes(cx, ino, &node)
    }

    fn lookup(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> Result<InodeAttr> {
        let _operation = self.operation(cx, false)?;
        let node = self.node(cx, parent)?;
        let directory = node.directory()?;
        let name = name.to_str().ok_or_else(|| {
            FfsError::UnsupportedFeature("FAT lookup requires a UTF-8 presentation name".into())
        })?;
        match name {
            "." => self.attributes(cx, parent, &node),
            ".." => {
                let ancestor = self.node(cx, node.parent)?;
                self.attributes(cx, node.parent, &ancestor)
            }
            _ => {
                let entry = self.visible_lookup(cx, directory, name)?;
                let ino = self.register(cx, parent, entry)?;
                self.attributes(cx, ino, &self.node(cx, ino)?)
            }
        }
    }

    fn readdir(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
    ) -> Result<ReaddirPage> {
        let _operation = self.operation(cx, false)?;
        let node = self.node(cx, ino)?;
        let entries = self.visible_entries(self.volume.list(cx, node.directory()?)?)?;
        let names = Self::checked_names(&entries)?;
        if self.writable {
            return self.mutable_readdir(cx, ino, node.parent, offset, entries, names);
        }
        let end_cookie = entries.len() as u64 + 2;
        let mut page = Vec::new();
        for (cookie, target, name) in [
            (1, ino, b".".as_slice()),
            (2, node.parent, b"..".as_slice()),
        ] {
            if cookie > offset {
                page.push(DirEntry {
                    ino: target,
                    offset: cookie,
                    kind: FileType::Directory,
                    name: name.to_vec(),
                });
            }
        }
        for (index, (entry, name)) in entries.into_iter().zip(names).enumerate() {
            checkpoint(cx)?;
            let cookie = index as u64 + 3;
            if cookie <= offset {
                continue;
            }
            if page.len() >= DIRECTORY_PAGE {
                break;
            }
            let kind = if entry.native.is_directory() {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            let target = self.register(cx, ino, entry)?;
            page.push(DirEntry {
                ino: target,
                offset: cookie,
                kind,
                name: name.into_bytes(),
            });
        }
        checkpoint(cx)?;
        Ok(ReaddirPage::new(page).with_end_cookie(Some(end_cookie)))
    }

    fn read(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>> {
        let _operation = self.operation(cx, false)?;
        let node = self.node(cx, ino)?;
        let entry = node.entry.as_ref().ok_or(FfsError::IsDirectory)?;
        let chain = self.chain(cx, ino, entry)?;
        self.volume.read(cx, &chain, offset, size as usize)
    }

    fn open(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        flags: i32,
    ) -> Result<(u64, u32)> {
        let operation = self.operation(cx, flags & libc::O_TRUNC != 0)?;
        checkpoint(cx)?;
        let wants_write = flags & libc::O_ACCMODE != libc::O_RDONLY
            || flags & (libc::O_TRUNC | libc::O_CREAT) != 0;
        if wants_write && !self.writable {
            return Err(FfsError::ReadOnly);
        }
        let mut node = self.node(cx, ino)?;
        let entry = node.entry.as_ref().ok_or(FfsError::IsDirectory)?;
        if entry.native.is_directory() {
            return Err(FfsError::IsDirectory);
        }
        if wants_write && entry.native.attributes & 0x01 != 0 {
            return Err(FfsError::PermissionDenied);
        }
        // Handle exhaustion is a preflight failure, never an O_TRUNC failure
        // after the existing contents have already been shortened.
        let handle = self.reserve_open(ino)?;
        if flags & libc::O_TRUNC != 0 {
            let path = self.path_for_inode(ino)?;
            truncate_in_volume(cx, &self.volume, &path, 0, now_unix_secs())
                .map_err(map_mutation_error)?;
            node = self.refresh_node_from_path(cx, ino, &path)?;
        }
        let entry = node.entry.as_ref().ok_or(FfsError::IsDirectory)?;
        self.chain(cx, ino, entry)?;
        operation.complete((handle.accept(), 0))
    }

    fn create(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
        _uid: u32,
        _gid: u32,
    ) -> Result<InodeAttr> {
        let operation = self.operation(cx, true)?;
        checkpoint(cx)?;
        self.ensure_writable()?;
        self.state()?.ensure_new_node(true)?;
        let parent_node = self.node(cx, parent)?;
        let parent_dir = parent_node.directory()?;
        let (path, name_str) = self.child_path(parent, name)?;
        let read_only = (mode & 0o222) == 0;
        create_in_volume(cx, &self.volume, &path, &[], now_unix_secs(), read_only)
            .map_err(map_mutation_error)?;
        self.state()?.free_clusters = None;
        let entry = self.volume.lookup(cx, parent_dir, &name_str)?;
        let ino = self.register(cx, parent, entry)?;
        let node = self.node(cx, ino)?;
        operation.complete(self.attributes(cx, ino, &node)?)
    }

    fn mkdir(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        _mode: u16,
        _uid: u32,
        _gid: u32,
    ) -> Result<InodeAttr> {
        let operation = self.operation(cx, true)?;
        checkpoint(cx)?;
        self.ensure_writable()?;
        self.state()?.ensure_new_node(true)?;
        let parent_node = self.node(cx, parent)?;
        let parent_dir = parent_node.directory()?;
        let (path, name_str) = self.child_path(parent, name)?;
        mkdir_in_volume(cx, &self.volume, &path, now_unix_secs(), false)
            .map_err(map_mutation_error)?;
        self.state()?.free_clusters = None;
        let entry = self.volume.lookup(cx, parent_dir, &name_str)?;
        let ino = self.register(cx, parent, entry)?;
        let node = self.node(cx, ino)?;
        operation.complete(self.attributes(cx, ino, &node)?)
    }

    fn write(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        data: &[u8],
    ) -> Result<u32> {
        let operation = self.operation(cx, true)?;
        checkpoint(cx)?;
        self.ensure_writable()?;
        let node = self.node(cx, ino)?;
        let entry = node.entry.as_ref().ok_or(FfsError::IsDirectory)?;
        if entry.native.is_directory() {
            return Err(FfsError::IsDirectory);
        }
        if entry.native.attributes & 0x01 != 0 {
            return Err(FfsError::PermissionDenied);
        }
        let path = self.path_for_inode(ino)?;
        let written = write_range_in_volume(cx, &self.volume, &path, offset, data, now_unix_secs())
            .map_err(map_mutation_error)?;
        self.refresh_node_from_path(cx, ino, &path)?;
        let written = u32::try_from(written)
            .map_err(|_| FfsError::Format("FAT write size overflow".into()))?;
        operation.complete(written)
    }

    fn copy_file_range(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino_in: InodeNumber,
        offset_in: u64,
        ino_out: InodeNumber,
        offset_out: u64,
        len: u64,
    ) -> Result<u64> {
        // Pin both native identities and their allocation for the WHOLE copy,
        // including preflight and cache publication. Do not recursively call
        // FsOps::read/write while this exclusive operation gate is held.
        let operation = self.operation(cx, true)?;
        if len == 0 {
            return operation.complete(0);
        }
        self.ensure_writable()?;
        let from = self.path_for_inode(ino_in)?;
        let to = self.path_for_inode(ino_out)?;
        let copied = self
            .volume
            .copy_range(cx, &from, offset_in, &to, offset_out, len, now_unix_secs())
            .map_err(map_mutation_error)?;
        if copied != 0 {
            self.refresh_node_from_path(cx, ino_out, &to)?;
        }
        checkpoint(cx)?;
        operation.complete(copied)
    }

    fn setattr(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        attrs: &SetAttrRequest,
    ) -> Result<InodeAttr> {
        let operation = self.operation(cx, true)?;
        self.ensure_writable()?;
        let mut node = self.node(cx, ino)?;
        // Ownership is a mount projection, not a field FAT can persist.
        // Accept an explicit no-op, never silently claim a changed owner.
        if attrs.uid.is_some_and(|uid| uid != self.uid)
            || attrs.gid.is_some_and(|gid| gid != self.gid)
        {
            return Err(FfsError::PermissionDenied);
        }
        let directory = node
            .entry
            .as_ref()
            .is_none_or(|entry| entry.native.is_directory());
        if attrs.size.is_some() && directory {
            return Err(FfsError::IsDirectory);
        }
        if attrs.size.is_some_and(|size| size > u64::from(u32::MAX)) {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(libc::EFBIG)));
        }
        if ino == ROOT {
            // Neither FAT16's fixed root nor FAT32's root has a parent entry
            // in which this profile could store mode or native timestamps.
            if attrs.mode.is_some_and(|mode| mode != 0o755)
                || attrs.atime.is_some_and(|time| time != UNIX_EPOCH)
                || attrs.mtime.is_some_and(|time| time != UNIX_EPOCH)
            {
                return Err(FfsError::UnsupportedFeature(
                    "FAT root attributes are fixed mount projections".into(),
                ));
            }
            return operation.complete(self.attributes(cx, ino, &node)?);
        }
        let read_only = attrs
            .mode
            .map(|mode| {
                let (writable_mode, readonly_mode) = if directory {
                    (0o755, 0o555)
                } else {
                    (0o644, 0o444)
                };
                if mode == writable_mode {
                    Ok(false)
                } else if mode == readonly_mode {
                    Ok(true)
                } else {
                    Err(FfsError::UnsupportedFeature(
                        "FAT mode must match the native read-only-bit projection".into(),
                    ))
                }
            })
            .transpose()?;
        let modified_secs = attrs.mtime.map(requested_fat_time).transpose()?;
        let accessed_secs = attrs.atime.map(requested_fat_time).transpose()?;
        if attrs.size.is_some()
            && node
                .entry
                .as_ref()
                .is_some_and(|entry| entry.native.attributes & 1 != 0)
        {
            return Err(FfsError::PermissionDenied);
        }
        // All deterministic policy/calendar/size failures have now been
        // rejected without writes. The following native operations remain
        // separately durable, not an atomic multi-attribute transaction.
        let path = self.path_for_inode(ino)?;
        if let Some(new_size) = attrs.size {
            truncate_in_volume(cx, &self.volume, &path, new_size, now_unix_secs())
                .map_err(map_mutation_error)?;
            // Do not retain the old chain if a later metadata update fails.
            node = self.refresh_node_from_path(cx, ino, &path)?;
        }
        if read_only.is_some() || modified_secs.is_some() || accessed_secs.is_some() {
            set_attr_in_volume(
                cx,
                &self.volume,
                &path,
                read_only,
                modified_secs,
                accessed_secs,
            )
            .map_err(map_mutation_error)?;
            node = self.refresh_node_from_path(cx, ino, &path)?;
        }
        operation.complete(self.attributes(cx, ino, &node)?)
    }

    fn unlink(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> Result<()> {
        let operation = self.operation(cx, true)?;
        checkpoint(cx)?;
        self.ensure_writable()?;
        let parent_node = self.node(cx, parent)?;
        let parent_dir = parent_node.directory()?;
        let (path, name_str) = self.child_path(parent, name)?;
        let existing_entry = self.visible_lookup(cx, parent_dir, &name_str)?;
        if existing_entry.native.is_directory() {
            return Err(FfsError::IsDirectory);
        }
        let existing_ino = self
            .state()?
            .slot_to_ino
            .get(&existing_entry.offset)
            .copied();
        if let Some(ino) = existing_ino
            && self.pinned(ino)?
        {
            self.retain_unlink_locked(cx, parent, &path, &existing_entry, ino)?;
            return operation.complete(());
        }
        unlink_in_volume(cx, &self.volume, &path, false).map_err(map_mutation_error)?;
        let mut state = self.state()?;
        state.free_clusters = None;
        if let Some(removed_ino) = state.slot_to_ino.remove(&existing_entry.offset) {
            Self::invalidate_cached_chain(&mut state, removed_ino);
            state.nodes.remove(&removed_ino);
        }
        drop(state);
        operation.complete(())
    }

    fn rmdir(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> Result<()> {
        let operation = self.operation(cx, true)?;
        checkpoint(cx)?;
        self.ensure_writable()?;
        let parent_node = self.node(cx, parent)?;
        let parent_dir = parent_node.directory()?;
        let (path, name_str) = self.child_path(parent, name)?;
        let existing_entry = self.visible_lookup(cx, parent_dir, &name_str)?;
        if !existing_entry.native.is_directory() {
            return Err(FfsError::NotDirectory);
        }
        rmdir_in_volume(cx, &self.volume, &path, false).map_err(map_mutation_error)?;
        let mut state = self.state()?;
        state.free_clusters = None;
        if let Some(removed_ino) = state.slot_to_ino.remove(&existing_entry.offset) {
            state.nodes.remove(&removed_ino);
        }
        drop(state);
        operation.complete(())
    }

    fn rename(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        new_parent: InodeNumber,
        new_name: &OsStr,
    ) -> Result<()> {
        let operation = self.operation(cx, true)?;
        self.rename_locked(cx, parent, name, new_parent, new_name, false)?;
        operation.complete(())
    }

    fn rename2(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        new_parent: InodeNumber,
        new_name: &OsStr,
        flags: u32,
    ) -> Result<()> {
        let operation = self.operation(cx, true)?;
        if flags == libc::RENAME_EXCHANGE {
            self.exchange_locked(cx, parent, name, new_parent, new_name)?;
            return operation.complete(());
        }
        if flags != 0 && flags != libc::RENAME_NOREPLACE {
            // Whiteout and invalid combinations need distinct native protocols.
            // Never silently degrade them into overwrite rename.
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::EINVAL,
            )));
        }
        self.rename_locked(
            cx,
            parent,
            name,
            new_parent,
            new_name,
            flags == libc::RENAME_NOREPLACE,
        )?;
        operation.complete(())
    }

    fn readlink(&self, cx: &Cx, _scope: &mut RequestScope, ino: InodeNumber) -> Result<Vec<u8>> {
        let _operation = self.operation(cx, false)?;
        self.node(cx, ino)?;
        Err(FfsError::Io(std::io::Error::from_raw_os_error(
            libc::EINVAL,
        )))
    }

    fn statfs(&self, cx: &Cx, _scope: &mut RequestScope, ino: InodeNumber) -> Result<FsStat> {
        let _operation = self.operation(cx, false)?;
        self.node(cx, ino)?;
        let cached = self.state()?.free_clusters;
        let free = if let Some(free) = cached {
            free
        } else {
            let free = self.volume.free_clusters(cx)?;
            self.state()?.free_clusters = Some(free);
            free
        };
        checkpoint(cx)?;
        Ok(FsStat {
            blocks: u64::from(self.volume.geometry.cluster_count()),
            blocks_free: free,
            blocks_available: free,
            files: 0,
            files_free: 0,
            block_size: self.volume.geometry.cluster_bytes(),
            name_max: 255,
            fragment_size: self.volume.geometry.cluster_bytes(),
        })
    }

    fn flush(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _fh: u64,
        _lock_owner: u64,
    ) -> Result<()> {
        // Closing/duplicating a handle is not another fsync, but must not hide
        // a sticky write or durability failure behind the trait's no-op default.
        let _operation = self.operation(cx, false)?;
        checkpoint(cx)
    }

    fn install_open_handle_oracle(&self, oracle: ffs_core::vfs::OpenHandleOracle) {
        self.install_lifetime_oracle(oracle);
    }

    fn release(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        request: ffs_core::vfs::ReleaseRequest,
    ) -> Result<()> {
        let operation = self.operation(cx, true)?;
        self.release_open(request.ino, request.fh)?;
        self.reap_retained_locked(cx, request.ino, false)?;
        operation.complete(())
    }

    fn finalize_unlinked_inode(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> Result<bool> {
        let operation = self.operation(cx, true)?;
        let reclaimed = self.reap_retained_locked(cx, ino, false)?;
        operation.complete(reclaimed)
    }

    fn fsync(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        _fh: u64,
        _datasync: bool,
    ) -> Result<()> {
        let operation = self.operation(cx, true)?;
        self.node(cx, ino)?;
        if self.writable {
            sync_volume(cx, &self.volume).map_err(map_mutation_error)?;
        }
        checkpoint(cx)?;
        operation.complete(())
    }

    fn fsyncdir(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        _fh: u64,
        _datasync: bool,
    ) -> Result<()> {
        let operation = self.operation(cx, true)?;
        self.node(cx, ino)?.directory()?;
        if self.writable {
            sync_volume(cx, &self.volume).map_err(map_mutation_error)?;
        }
        checkpoint(cx)?;
        operation.complete(())
    }

    fn flush_on_destroy(&self, cx: &Cx) -> Result<()> {
        let operation = self.operation(cx, true)?;
        if self.writable {
            self.reap_all_retained_locked(cx)?;
            sync_volume(cx, &self.volume).map_err(map_mutation_error)?;
        }
        checkpoint(cx)?;
        operation.complete(())
    }

    fn fallocate(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        length: u64,
        mode: i32,
    ) -> Result<()> {
        let operation = self.operation(cx, true)?;
        self.ensure_writable()?;
        let node = self.node(cx, ino)?;
        let entry = node.entry.as_ref().ok_or(FfsError::IsDirectory)?;
        if entry.native.is_directory() {
            return Err(FfsError::IsDirectory);
        }
        if entry.native.attributes & 1 != 0 {
            return Err(FfsError::PermissionDenied);
        }
        let path = self.path_for_inode(ino)?;
        self.volume
            .preallocate(cx, &path, offset, length, mode, now_unix_secs())
            .map_err(map_mutation_error)?;
        // KEEP_SIZE changes st_blocks and free space even though st_size and
        // the directory record may be unchanged. Invalidate both caches.
        self.refresh_node_from_path(cx, ino, &path)?;
        operation.complete(())
    }

    fn fiemap(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        start: u64,
        length: u64,
    ) -> Result<Vec<FiemapExtent>> {
        let _operation = self.operation(cx, false)?;
        let node = self.node(cx, ino)?;
        let entry = node
            .entry
            .as_ref()
            .ok_or_else(|| FfsError::Io(std::io::Error::from_raw_os_error(libc::EINVAL)))?;
        if entry.native.is_directory() {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::EINVAL,
            )));
        }
        let chain = self.chain(cx, ino, entry)?;
        let data_start = self
            .volume
            .geometry
            .cluster_offset(2)
            .map_err(|error| fiemap_corrupt(0, error.to_string()))?;
        fat_fiemap(
            cx,
            &chain,
            self.volume.geometry.cluster_bytes(),
            data_start,
            self.volume.geometry.volume_bytes(),
            start,
            length,
        )
    }

    fn lseek(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        whence: SeekWhence,
    ) -> Result<u64> {
        let _operation = self.operation(cx, false)?;
        let node = self.node(cx, ino)?;
        let entry = node.entry.as_ref().ok_or(FfsError::IsDirectory)?;
        let chain = self.chain(cx, ino, entry)?;
        if offset >= u64::from(chain.size) {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(libc::ENXIO)));
        }
        checkpoint(cx)?;
        match whence {
            SeekWhence::Data => Ok(offset),
            SeekWhence::Hole => Ok(u64::from(chain.size)),
            _ => Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::EINVAL,
            ))),
        }
    }
}

/// Native FAT timestamps have no timezone. Project available fields
/// onto UTC deterministically; preserve unknown timestamps as epoch zero.
/// Report invalid native fields at their directory record, not at block zero.
fn fat_wall_time(
    timestamp: std::result::Result<Option<FatTimestamp>, ParseError>,
    offset: u64,
) -> Result<SystemTime> {
    let Some(timestamp) = timestamp.map_err(|error| FfsError::Corruption {
        block: offset / 512,
        detail: format!("invalid FAT timestamp: {error}"),
    })?
    else {
        return Ok(UNIX_EPOCH);
    };
    UNIX_EPOCH
        .checked_add(timestamp.utc_projection())
        .ok_or_else(|| FfsError::Format("FAT timestamp is outside host SystemTime range".into()))
}

companion_bin_tests! {
#[cfg(test)]
mod preallocation_tests;

#[cfg(test)]
mod tests {
    use super::*;

    mod copy;
    mod operations;

    fn extent(logical: u64, physical: u64, length: u64, flags: u32) -> FiemapExtent {
        FiemapExtent {
            logical,
            physical,
            length,
            flags,
        }
    }

    #[test]
    fn fat_fiemap_preserves_fragmentation_and_query_extent_boundaries() {
        let cx = Cx::for_testing();
        let chain = FileChain {
            clusters: vec![5, 6, 10, 11, 12],
            size: 5 * 512,
        };
        let extents = fat_fiemap(&cx, &chain, 512, 4096, 64 * 1024, 0, u64::MAX).unwrap();
        assert_eq!(
            extents,
            vec![
                extent(0, 4096 + 3 * 512, 2 * 512, 0),
                extent(2 * 512, 4096 + 8 * 512, 3 * 512, FIEMAP_EXTENT_LAST),
            ]
        );
        assert_eq!(
            fat_fiemap(&cx, &chain, 512, 4096, 64 * 1024, 1500, 1).unwrap(),
            vec![extent(
                2 * 512,
                4096 + 8 * 512,
                3 * 512,
                FIEMAP_EXTENT_LAST
            )]
        );
        assert_eq!(fat_fiemap(&cx, &chain, 512, 4096, 64 * 1024, 3000, 1)
            .unwrap(), [] as [ffs_core::FiemapExtent; 0]);
    }

    #[test]
    fn fat_fiemap_exposes_keep_size_allocation_as_unwritten() {
        let cx = Cx::for_testing();
        let chain = FileChain {
            clusters: vec![20, 21, 22, 23],
            size: 1300,
        };
        assert_eq!(
            fat_fiemap(&cx, &chain, 512, 4096, 64 * 1024, 0, u64::MAX).unwrap(),
            vec![
                extent(0, 4096 + 18 * 512, 1300, FIEMAP_EXTENT_NOT_ALIGNED),
                extent(
                    1300,
                    4096 + 18 * 512 + 1300,
                    4 * 512 - 1300,
                    FIEMAP_EXTENT_LAST | FIEMAP_EXTENT_NOT_ALIGNED | FIEMAP_EXTENT_UNWRITTEN,
                ),
            ]
        );

        let large_clusters = FileChain {
            clusters: vec![2, 3],
            size: 1,
        };
        assert_eq!(
            fat_fiemap(&cx, &large_clusters, 4096, 32 * 1024, 128 * 1024, 0, u64::MAX)
                .unwrap(),
            vec![
                extent(0, 32 * 1024, 1, FIEMAP_EXTENT_NOT_ALIGNED),
                extent(
                    1,
                    32 * 1024 + 1,
                    8191,
                    FIEMAP_EXTENT_LAST | FIEMAP_EXTENT_NOT_ALIGNED | FIEMAP_EXTENT_UNWRITTEN,
                ),
            ]
        );
    }

    #[test]
    fn fat_fiemap_rejects_invalid_or_cancelled_native_maps() {
        let cx = Cx::for_testing();
        for chain in [
            FileChain {
                clusters: vec![1],
                size: 1,
            },
            FileChain {
                clusters: vec![2],
                size: 513,
            },
        ] {
            assert!(matches!(
                fat_fiemap(&cx, &chain, 512, 4096, 64 * 1024, 0, u64::MAX),
                Err(FfsError::Corruption { .. })
            ));
        }
        let overflow = FileChain {
            clusters: vec![u32::MAX],
            size: 1,
        };
        assert!(matches!(
            fat_fiemap(&cx, &overflow, 4096, u64::MAX - 1024, u64::MAX, 0, u64::MAX),
            Err(FfsError::Corruption { .. })
        ));

        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        assert!(matches!(
            fat_fiemap(
                &cancelled,
                &FileChain {
                    clusters: vec![2],
                    size: 1,
                },
                512,
                4096,
                64 * 1024,
                0,
                u64::MAX,
            ),
            Err(FfsError::Cancelled)
        ));
    }

    #[test]
    fn mounted_fat_fiemap_reports_allocated_tail_and_rejects_directories() {
        let (_directory, fs) = writable_fat16();
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let ino = create_file(&fs, "MAP.BIN");
        fs.write(&cx, &mut scope, ino, 0, &[0xA5; 701]).unwrap();
        fs.fallocate(
            &cx,
            &mut scope,
            ino,
            0,
            u64::from(fs.volume.geometry.cluster_bytes()) * 3,
            libc::FALLOC_FL_KEEP_SIZE,
        )
        .unwrap();
        let node = fs.node(&cx, ino).unwrap();
        let chain = fs.chain(&cx, ino, node.entry.as_ref().unwrap()).unwrap();
        let extents = fs.fiemap(&cx, &mut scope, ino, 0, u64::MAX).unwrap();
        assert_ne!(extents, [] as [ffs_core::FiemapExtent; 0]);
        assert_eq!(
            extents[0].physical,
            fs.volume
                .geometry
                .cluster_offset(chain.clusters[0])
                .unwrap()
        );
        assert!(extents.iter().any(|extent| extent.flags & FIEMAP_EXTENT_UNWRITTEN != 0));
        assert_ne!(extents.last().unwrap().flags & FIEMAP_EXTENT_LAST, 0);
        assert!(matches!(
            fs.fiemap(&cx, &mut scope, ROOT, 0, u64::MAX),
            Err(FfsError::Io(error)) if error.raw_os_error() == Some(libc::EINVAL)
        ));
    }

    #[test]
    fn native_wall_time_preserves_precision_absence_and_error_location() {
        let timestamp = fat_wall_time(FatTimestamp::parse(0x585D, 0x645C, 157).map(Some), 4096)
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap();
        assert_eq!(
            (timestamp.as_secs(), timestamp.subsec_nanos()),
            (1_709_210_097, 570_000_000)
        );
        assert_eq!(fat_wall_time(Ok(None), 4096).unwrap(), UNIX_EPOCH);
        assert!(matches!(
            fat_wall_time(FatTimestamp::parse(0, 0, 0).map(Some), 4096),
            Err(FfsError::Corruption { block: 8, .. })
        ));
    }

    fn writable_fat16() -> (tempfile::TempDir, FatFs) {
        use clap::Parser as _;

        let cx = Cx::for_testing();
        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("volume.fat");
        let cli = crate::Cli::try_parse_from([
            "ffs-fat",
            "format",
            image.to_str().unwrap(),
            "--kind",
            "fat16",
            "--size-mib",
            "4",
        ])
        .unwrap();
        let crate::Command::Format { options } = cli.command else {
            panic!("expected formatter options");
        };
        crate::formatter::create(&cx, &options).unwrap();
        let args = crate::reader::ImageArgs {
            image,
            offset: 0,
            length: None,
            oem_code_page: ffs_ondisk::fat::FatOemCodePage::Ascii,
            sidecar: None,
        };
        let volume = crate::reader::replacement::open_volume(&cx, &args, true).unwrap();
        let fs = FatFs::new_with_mode(&cx, volume, 1000, 1000, true).unwrap();
        (directory, fs)
    }

    #[test]
    fn fat16_operation_gate_shares_reads_and_excludes_mutation() {
        let (_directory, fs) = writable_fat16();
        let cx = Cx::for_testing();
        let reader = fs.operation(&cx, false).unwrap();
        assert!(fs.operations.try_read().is_ok());
        assert!(matches!(
            fs.operations.try_write(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        drop(reader);
        let writer = fs.operation(&cx, true).unwrap();
        assert!(matches!(
            fs.operations.try_read(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        assert!(matches!(
            fs.operations.try_write(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        drop(writer);
        assert!(fs.operations.try_write().is_ok());
    }

    #[test]
    fn fat16_panicked_mutation_gate_fails_closed() {
        let (_directory, fs) = writable_fat16();
        let cx = Cx::for_testing();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _writer = fs.operation(&cx, true).unwrap();
            panic!("injected interruption while holding the mutation gate");
        }));
        assert!(panic.is_err());
        assert!(matches!(
            fs.getattr(&cx, &mut RequestScope::empty(), ROOT),
            Err(FfsError::Io(_))
        ));
        assert!(matches!(fs.flush_on_destroy(&cx), Err(FfsError::Io(_))));
    }

    #[test]
    fn fat16_parallel_range_writes_preserve_all_updates() {
        const WORKERS: usize = 8;
        const STRIDE: usize = 512;
        const PAYLOAD: usize = 37;
        let (_directory, fs) = writable_fat16();
        let cx = Cx::for_testing();
        let file = fs
            .create(
                &cx,
                &mut RequestScope::empty(),
                ROOT,
                OsStr::new("parallel.bin"),
                0o644,
                1000,
                1000,
            )
            .unwrap();
        let barrier = std::sync::Barrier::new(WORKERS);
        std::thread::scope(|threads| {
            for worker in 0..WORKERS {
                let fs = &fs;
                let barrier = &barrier;
                let ino = file.ino;
                threads.spawn(move || {
                    let cx = Cx::for_testing();
                    let payload = [u8::try_from(worker + 1).unwrap(); PAYLOAD];
                    barrier.wait();
                    assert_eq!(
                        fs.write(
                            &cx,
                            &mut RequestScope::empty(),
                            ino,
                            (worker * STRIDE) as u64,
                            &payload,
                        )
                        .unwrap(),
                        PAYLOAD as u32
                    );
                });
            }
        });
        let length = (WORKERS - 1) * STRIDE + PAYLOAD;
        let mut expected = vec![0; length];
        for worker in 0..WORKERS {
            expected[worker * STRIDE..worker * STRIDE + PAYLOAD]
                .fill(u8::try_from(worker + 1).unwrap());
        }
        assert_eq!(
            fs.read(&cx, &mut RequestScope::empty(), file.ino, 0, length as u32)
                .unwrap(),
            expected
        );
        assert_eq!(
            fs.getattr(&cx, &mut RequestScope::empty(), file.ino)
                .unwrap()
                .size,
            length as u64
        );
        let check = fs.volume.check(&cx).unwrap();
        assert!(check.clean && check.complete && check.namespace_complete);
    }

    #[test]
    fn fat16_parallel_creates_keep_allocation_and_namespace_consistent() {
        const WORKERS: usize = 8;
        let (_directory, fs) = writable_fat16();
        let barrier = std::sync::Barrier::new(WORKERS);
        std::thread::scope(|threads| {
            for worker in 0..WORKERS {
                let fs = &fs;
                let barrier = &barrier;
                threads.spawn(move || {
                    let cx = Cx::for_testing();
                    let name = format!("file{worker}.bin");
                    let payload = vec![u8::try_from(worker + 1).unwrap(); 1061];
                    barrier.wait();
                    let file = fs
                        .create(
                            &cx,
                            &mut RequestScope::empty(),
                            ROOT,
                            OsStr::new(&name),
                            0o644,
                            1000,
                            1000,
                        )
                        .unwrap();
                    fs.write(&cx, &mut RequestScope::empty(), file.ino, 0, &payload)
                        .unwrap();
                });
            }
        });
        let cx = Cx::for_testing();
        for worker in 0..WORKERS {
            let name = format!("file{worker}.bin");
            let file = fs
                .lookup(&cx, &mut RequestScope::empty(), ROOT, OsStr::new(&name))
                .unwrap();
            assert_eq!(
                fs.read(&cx, &mut RequestScope::empty(), file.ino, 0, 1061)
                    .unwrap(),
                vec![u8::try_from(worker + 1).unwrap(); 1061]
            );
        }
        let check = fs.volume.check(&cx).unwrap();
        assert!(check.clean && check.complete && check.namespace_complete);
        assert_eq!(check.files, WORKERS as u64);
    }

    fn create_file(fs: &FatFs, name: &str) -> InodeNumber {
        fs.create(
            &Cx::for_testing(),
            &mut RequestScope::empty(),
            ROOT,
            OsStr::new(name),
            0o644,
            1000,
            1000,
        )
        .unwrap()
        .ino
    }

    #[test]
    fn fat16_reused_slots_never_resurrect_retired_file_ids() {
        let (_directory, fs) = writable_fat16();
        let cx = Cx::for_testing();
        let first = create_file(&fs, "FIRST.BIN");
        let first_slot = fs.node(&cx, first).unwrap().entry.unwrap().offset;
        fs.write(&cx, &mut RequestScope::empty(), first, 0, b"old")
            .unwrap();
        fs.unlink(&cx, &mut RequestScope::empty(), ROOT, OsStr::new("FIRST.BIN"))
            .unwrap();
        let second = create_file(&fs, "SECOND.BIN");
        assert_eq!(fs.node(&cx, second).unwrap().entry.unwrap().offset, first_slot);
        assert_ne!(first, second);
        fs.write(&cx, &mut RequestScope::empty(), second, 0, b"new")
            .unwrap();
        assert!(matches!(
            fs.read(&cx, &mut RequestScope::empty(), first, 0, 3),
            Err(FfsError::NotFound(_))
        ));
        assert!(matches!(
            fs.write(&cx, &mut RequestScope::empty(), first, 0, b"BAD"),
            Err(FfsError::NotFound(_))
        ));
        assert_eq!(
            fs.read(&cx, &mut RequestScope::empty(), second, 0, 3).unwrap(),
            b"new"
        );
    }

    #[test]
    fn fat16_reused_directory_slots_never_resurrect_retired_ids() {
        let (_directory, fs) = writable_fat16();
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let first = fs.mkdir(&cx, &mut scope, ROOT, OsStr::new("OLD"), 0o755, 1000, 1000)
            .unwrap();
        fs.rmdir(&cx, &mut scope, ROOT, OsStr::new("OLD")).unwrap();
        let second = fs.mkdir(&cx, &mut scope, ROOT, OsStr::new("NEW"), 0o755, 1000, 1000)
            .unwrap();
        assert_ne!(first.ino, second.ino);
        assert!(matches!(fs.readdir(&cx, &mut scope, first.ino, 0), Err(FfsError::NotFound(_))));
        assert_eq!(fs.lookup(&cx, &mut scope, ROOT, OsStr::new("NEW")).unwrap().ino, second.ino);
    }

    #[test]
    fn fat16_readdir_cookies_survive_deletion_and_slot_reuse() {
        let (_directory, fs) = writable_fat16();
        let cx = Cx::for_testing();
        for name in ["A.TXT", "B.TXT", "C.TXT"] {
            create_file(&fs, name);
        }
        let first_page = fs.readdir(&cx, &mut RequestScope::empty(), ROOT, 0).unwrap();
        let cursor = first_page.iter().find(|entry| entry.name == b"A.TXT").unwrap().offset;
        let old_end = first_page.end_cookie().unwrap();
        fs.unlink(&cx, &mut RequestScope::empty(), ROOT, OsStr::new("A.TXT"))
            .unwrap();
        create_file(&fs, "D.TXT");
        let resumed = fs.readdir(&cx, &mut RequestScope::empty(), ROOT, cursor).unwrap();
        let names: Vec<_> = resumed.iter().map(ffs_core::DirEntry::name_str).collect();
        assert_eq!(names, ["B.TXT", "C.TXT", "D.TXT"]);
        // The FUSE directory handle can still cap enumeration at its opening
        // end cookie, without hiding any unchanged, previously unseen entry.
        let bounded: Vec<_> = resumed.iter()
            .filter(|entry| entry.offset <= old_end)
            .map(ffs_core::DirEntry::name_str)
            .collect();
        assert_eq!(bounded, ["B.TXT", "C.TXT"]);
        assert!(resumed.iter().all(|entry| entry.offset > cursor));
    }

    #[test]
    fn fat16_aliases_and_renames_keep_one_mount_identity() {
        let (_directory, fs) = writable_fat16();
        let cx = Cx::for_testing();
        let ino = create_file(&fs, "A detailed report.txt");
        let alias = fs.node(&cx, ino).unwrap().entry.unwrap().short_alias().unwrap();
        assert_eq!(
            fs.lookup(&cx, &mut RequestScope::empty(), ROOT, OsStr::new(&alias)).unwrap().ino,
            ino
        );
        fs.rename(
            &cx,
            &mut RequestScope::empty(),
            ROOT,
            OsStr::new("A detailed report.txt"),
            ROOT,
            OsStr::new("FINAL.TXT"),
        )
        .unwrap();
        assert_eq!(
            fs.lookup(&cx, &mut RequestScope::empty(), ROOT, OsStr::new("FINAL.TXT")).unwrap().ino,
            ino
        );
        assert_ne!(create_file(&fs, "FRESH.TXT"), ino);
    }

    #[test]
    fn fat16_inode_exhaustion_refuses_creation_before_native_writes() {
        let (directory, fs) = writable_fat16();
        let cx = Cx::for_testing();
        fs.state().unwrap().next_synthetic_ino = MAX_SYNTHETIC_INO;
        let last = create_file(&fs, "LAST.TXT");
        assert_eq!(last.0, MAX_SYNTHETIC_INO);
        let page = fs.readdir(&cx, &mut RequestScope::empty(), ROOT, 0).unwrap();
        assert_eq!(page.end_cookie(), Some((1_u64 << 63) - 1));
        let image = directory.path().join("volume.fat");
        let before = std::fs::read(&image).unwrap();
        for directory_request in [false, true] {
            let result = if directory_request {
                fs.mkdir(&cx, &mut RequestScope::empty(), ROOT, OsStr::new("NO"), 0o755, 1000, 1000)
            } else {
                fs.create(
                    &cx,
                    &mut RequestScope::empty(),
                    ROOT,
                    OsStr::new("NO.TXT"),
                    0o644,
                    1000,
                    1000,
                )
            };
            assert!(matches!(
                result,
                Err(FfsError::Io(error)) if error.raw_os_error() == Some(libc::EOVERFLOW)
            ));
            assert_eq!(std::fs::read(&image).unwrap(), before);
        }
    }

    #[test]
    fn fat16_setattr_rejects_invalid_times_before_truncating() {
        use std::time::Duration;

        let (directory, fs) = writable_fat16();
        let cx = Cx::for_testing();
        let ino = create_file(&fs, "KEEP.BIN");
        fs.write(&cx, &mut RequestScope::empty(), ino, 0, b"keep these bytes").unwrap();
        let image = directory.path().join("volume.fat");
        let before = std::fs::read(&image).unwrap();
        for time in [
            UNIX_EPOCH - Duration::from_secs(1),
            UNIX_EPOCH,
            UNIX_EPOCH + Duration::from_secs(315_532_799),
            UNIX_EPOCH + Duration::from_hours(1_209_672),
        ] {
            for access_time in [false, true] {
                let mut attrs = SetAttrRequest { size: Some(0), ..Default::default() };
                if access_time { attrs.atime = Some(time); } else { attrs.mtime = Some(time); }
                assert!(matches!(
                    fs.setattr(&cx, &mut RequestScope::empty(), ino, &attrs),
                    Err(FfsError::Io(error)) if error.raw_os_error() == Some(libc::EINVAL)
                ));
                assert_eq!(std::fs::read(&image).unwrap(), before);
                assert_eq!(
                    fs.read(&cx, &mut RequestScope::empty(), ino, 0, 64).unwrap(),
                    b"keep these bytes"
                );
            }
        }
    }

    #[test]
    fn fat16_setattr_refuses_unrepresentable_metadata_without_writes() {
        let (directory, fs) = writable_fat16();
        let cx = Cx::for_testing();
        let ino = create_file(&fs, "KEEP.BIN");
        fs.write(&cx, &mut RequestScope::empty(), ino, 0, b"original").unwrap();
        let image = directory.path().join("volume.fat");
        let before = std::fs::read(&image).unwrap();
        for attrs in [
            SetAttrRequest { uid: Some(1001), size: Some(0), ..Default::default() },
            SetAttrRequest { gid: Some(1001), size: Some(0), ..Default::default() },
            SetAttrRequest { mode: Some(0o600), size: Some(0), ..Default::default() },
            SetAttrRequest { mode: Some(0o755), size: Some(0), ..Default::default() },
            SetAttrRequest { mode: Some(0o4644), size: Some(0), ..Default::default() },
            SetAttrRequest { size: Some(u64::from(u32::MAX) + 1), ..Default::default() },
        ] {
            assert!(fs.setattr(&cx, &mut RequestScope::empty(), ino, &attrs).is_err());
            assert_eq!(std::fs::read(&image).unwrap(), before);
        }
        assert_eq!(fs.getattr(&cx, &mut RequestScope::empty(), ino).unwrap().size, 8);
    }

    #[test]
    fn fat16_setattr_persists_size_time_and_readonly_projection() {
        use std::time::Duration;

        let (_directory, fs) = writable_fat16();
        let cx = Cx::for_testing();
        let ino = create_file(&fs, "META.BIN");
        fs.write(&cx, &mut RequestScope::empty(), ino, 0, b"abc").unwrap();
        let time = UNIX_EPOCH + Duration::new(1_709_210_097, 570_000_000);
        let attrs = SetAttrRequest {
            mode: Some(0o444), uid: Some(1000), gid: Some(1000),
            size: Some(9), atime: Some(time), mtime: Some(time),
        };
        let actual = fs.setattr(&cx, &mut RequestScope::empty(), ino, &attrs).unwrap();
        assert_eq!((actual.size, actual.perm), (9, 0o444));
        assert_eq!(actual.mtime, UNIX_EPOCH + Duration::from_secs(1_709_210_096));
        assert_eq!(actual.atime, UNIX_EPOCH + Duration::from_hours(474_768));
        assert_eq!(fs.read(&cx, &mut RequestScope::empty(), ino, 0, 9).unwrap(), b"abc\0\0\0\0\0\0");
        assert!(matches!(
            fs.write(&cx, &mut RequestScope::empty(), ino, 0, b"x"),
            Err(FfsError::PermissionDenied)
        ));
        fs.setattr(&cx, &mut RequestScope::empty(), ino,
            &SetAttrRequest { mode: Some(0o644), ..Default::default() }).unwrap();
        fs.write(&cx, &mut RequestScope::empty(), ino, 0, b"x").unwrap();
        assert!(fs.volume.check(&cx).unwrap().clean);
    }

    #[test]
    fn fat16_root_setattr_accepts_only_explicit_noops() {
        let (directory, fs) = writable_fat16();
        let cx = Cx::for_testing();
        let image = directory.path().join("volume.fat");
        let before = std::fs::read(&image).unwrap();
        for attrs in [
            SetAttrRequest { size: Some(0), ..Default::default() },
            SetAttrRequest { mode: Some(0o555), ..Default::default() },
            SetAttrRequest { mtime: Some(SystemTime::now()), ..Default::default() },
            SetAttrRequest { uid: Some(0), ..Default::default() },
        ] {
            assert!(fs.setattr(&cx, &mut RequestScope::empty(), ROOT, &attrs).is_err());
            assert_eq!(std::fs::read(&image).unwrap(), before);
        }
        let attrs = SetAttrRequest {
            mode: Some(0o755), uid: Some(1000), gid: Some(1000),
            atime: Some(UNIX_EPOCH), mtime: Some(UNIX_EPOCH), size: None,
        };
        assert_eq!(fs.setattr(&cx, &mut RequestScope::empty(), ROOT, &attrs).unwrap().ino, ROOT);
        assert_eq!(std::fs::read(&image).unwrap(), before);
    }

    #[test]
    fn requested_fat_time_admits_both_native_calendar_boundaries() {
        use std::time::Duration;
        for seconds in [315_532_800, 4_354_819_199] {
            assert_eq!(requested_fat_time(UNIX_EPOCH + Duration::from_secs(seconds)).unwrap(), seconds);
        }
    }
}
}
