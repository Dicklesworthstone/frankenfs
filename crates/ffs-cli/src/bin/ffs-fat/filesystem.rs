//! Read-only FsOps adapter for the same native reader used by inspect/ls/cat.
//! Slot-based IDs are safe only for this immutable, mount-lifetime namespace;
//! they are deliberately not a promise of FAT write or export-stable handles.

use super::reader::replacement::{
    create_in_volume, mkdir_in_volume, rename_in_volume, rmdir_in_volume, set_attr_in_volume,
    sync_volume, truncate_in_volume, unlink_in_volume, write_range_in_volume,
};
use super::reader::{Directory, Entry, FatVolume, FileChain, MAX_CHAIN_CLUSTERS, checkpoint};
use asupersync::Cx;
use ffs_core::{
    DirEntry, FileType, FsOps, FsStat, InodeAttr, ReaddirPage, RequestScope, SeekWhence,
    SetAttrRequest,
};
use ffs_error::{FfsError, Result};
use ffs_ondisk::fat::{FatKind, FatTimestamp};
use ffs_types::{InodeNumber, ParseError};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

const ROOT: InodeNumber = InodeNumber(1);
const MAX_NODES: usize = 131_072;
const MAX_CACHED_CHAINS: usize = 1024;
const DIRECTORY_PAGE: usize = 256;
const FIRST_SYNTHETIC_INO: u64 = 1_u64 << 48;

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

pub struct FatFs {
    volume: FatVolume,
    state: Mutex<State>,
    uid: u32,
    gid: u32,
    writable: bool,
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(315_532_800, |d| d.as_secs().max(315_532_800))
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
        Ok(Self {
            volume,
            state: Mutex::new(state),
            uid,
            gid,
            writable,
        })
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
        if let Some(&mapped_ino) = state.slot_to_ino.get(&entry.offset)
            && let Some(existing) = state.nodes.get_mut(&mapped_ino)
        {
            if !self.writable
                && (existing.parent != parent
                    || existing
                        .entry
                        .as_ref()
                        .is_none_or(|old| old.native != entry.native))
            {
                return Err(FfsError::Corruption {
                    block: entry.offset / 512,
                    detail: "FAT namespace identity changed or is cross-linked".into(),
                });
            }
            existing.parent = parent;
            existing.entry = Some(entry);
            return Ok(mapped_ino);
        }

        let default_ino = InodeNumber(entry.offset / 32 + 2);
        let ino = if let Some(existing) = state.nodes.get(&default_ino) {
            let same_slot = existing
                .entry
                .as_ref()
                .is_some_and(|old| old.offset == entry.offset);
            if same_slot {
                if !self.writable
                    && (existing.parent != parent
                        || existing
                            .entry
                            .as_ref()
                            .is_none_or(|old| old.native != entry.native))
                {
                    return Err(FfsError::Corruption {
                        block: entry.offset / 512,
                        detail: "FAT namespace identity changed or is cross-linked".into(),
                    });
                }
                let existing_mut = state.nodes.get_mut(&default_ino).expect("checked above");
                existing_mut.parent = parent;
                existing_mut.entry = Some(entry.clone());
                state.slot_to_ino.insert(entry.offset, default_ino);
                return Ok(default_ino);
            }
            let allocated = InodeNumber(state.next_synthetic_ino);
            state.next_synthetic_ino += 1;
            allocated
        } else {
            default_ino
        };

        if state.nodes.len() >= MAX_NODES {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::ENOMEM,
            )));
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
            nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: self.volume.geometry.cluster_bytes(),
            generation: 1,
        })
    }
}

impl FsOps for FatFs {
    fn getattr(&self, cx: &Cx, _scope: &mut RequestScope, ino: InodeNumber) -> Result<InodeAttr> {
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
                let entry = self.volume.lookup(cx, directory, name)?;
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
        let node = self.node(cx, ino)?;
        let entries = self.volume.list(cx, node.directory()?)?;
        let names = Self::checked_names(&entries)?;
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
        if flags & libc::O_TRUNC != 0 {
            let path = self.path_for_inode(ino)?;
            truncate_in_volume(cx, &self.volume, &path, 0, now_unix_secs())
                .map_err(map_mutation_error)?;
            node = self.refresh_node_from_path(cx, ino, &path)?;
        }
        let entry = node.entry.as_ref().ok_or(FfsError::IsDirectory)?;
        self.chain(cx, ino, entry)?;
        Ok((0, 0))
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
        checkpoint(cx)?;
        self.ensure_writable()?;
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
        self.attributes(cx, ino, &node)
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
        checkpoint(cx)?;
        self.ensure_writable()?;
        let parent_node = self.node(cx, parent)?;
        let parent_dir = parent_node.directory()?;
        let (path, name_str) = self.child_path(parent, name)?;
        mkdir_in_volume(cx, &self.volume, &path, now_unix_secs(), false)
            .map_err(map_mutation_error)?;
        self.state()?.free_clusters = None;
        let entry = self.volume.lookup(cx, parent_dir, &name_str)?;
        let ino = self.register(cx, parent, entry)?;
        let node = self.node(cx, ino)?;
        self.attributes(cx, ino, &node)
    }

    fn write(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        data: &[u8],
    ) -> Result<u32> {
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
        u32::try_from(written).map_err(|_| FfsError::Format("FAT write size overflow".into()))
    }

    fn setattr(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        attrs: &SetAttrRequest,
    ) -> Result<InodeAttr> {
        checkpoint(cx)?;
        self.ensure_writable()?;
        if ino == ROOT {
            let node = self.node(cx, ROOT)?;
            return self.attributes(cx, ROOT, &node);
        }
        let path = self.path_for_inode(ino)?;
        if let Some(new_size) = attrs.size {
            truncate_in_volume(cx, &self.volume, &path, new_size, now_unix_secs())
                .map_err(map_mutation_error)?;
        }
        let read_only = attrs.mode.map(|mode| (mode & 0o222) == 0);
        let modified_secs = attrs
            .mtime
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs().max(315_532_800));
        let accessed_secs = attrs
            .atime
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs().max(315_532_800));
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
        }
        let node = self.refresh_node_from_path(cx, ino, &path)?;
        self.attributes(cx, ino, &node)
    }

    fn unlink(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> Result<()> {
        checkpoint(cx)?;
        self.ensure_writable()?;
        let parent_node = self.node(cx, parent)?;
        let parent_dir = parent_node.directory()?;
        let (path, name_str) = self.child_path(parent, name)?;
        let existing_entry = self.volume.lookup(cx, parent_dir, &name_str)?;
        if existing_entry.native.is_directory() {
            return Err(FfsError::IsDirectory);
        }
        unlink_in_volume(cx, &self.volume, &path, false).map_err(map_mutation_error)?;
        let mut state = self.state()?;
        state.free_clusters = None;
        if let Some(removed_ino) = state.slot_to_ino.remove(&existing_entry.offset) {
            Self::invalidate_cached_chain(&mut state, removed_ino);
            state.nodes.remove(&removed_ino);
        } else {
            let fallback_ino = InodeNumber(existing_entry.offset / 32 + 2);
            if state
                .nodes
                .get(&fallback_ino)
                .and_then(|n| n.entry.as_ref())
                .is_some_and(|e| e.offset == existing_entry.offset)
            {
                Self::invalidate_cached_chain(&mut state, fallback_ino);
                state.nodes.remove(&fallback_ino);
            }
        }
        Ok(())
    }

    fn rmdir(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> Result<()> {
        checkpoint(cx)?;
        self.ensure_writable()?;
        let parent_node = self.node(cx, parent)?;
        let parent_dir = parent_node.directory()?;
        let (path, name_str) = self.child_path(parent, name)?;
        let existing_entry = self.volume.lookup(cx, parent_dir, &name_str)?;
        if !existing_entry.native.is_directory() {
            return Err(FfsError::NotDirectory);
        }
        rmdir_in_volume(cx, &self.volume, &path, false).map_err(map_mutation_error)?;
        let mut state = self.state()?;
        state.free_clusters = None;
        if let Some(removed_ino) = state.slot_to_ino.remove(&existing_entry.offset) {
            state.nodes.remove(&removed_ino);
        } else {
            let fallback_ino = InodeNumber(existing_entry.offset / 32 + 2);
            if state
                .nodes
                .get(&fallback_ino)
                .and_then(|n| n.entry.as_ref())
                .is_some_and(|e| e.offset == existing_entry.offset)
            {
                state.nodes.remove(&fallback_ino);
            }
        }
        Ok(())
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
        checkpoint(cx)?;
        self.ensure_writable()?;
        let parent_dir = self.node(cx, parent)?.directory()?;
        let new_parent_dir = self.node(cx, new_parent)?.directory()?;
        let (from_path, from_name) = self.child_path(parent, name)?;
        let (to_path, to_name) = self.child_path(new_parent, new_name)?;
        let src_before = self.volume.lookup(cx, parent_dir, &from_name)?;
        let dst_before = self.volume.lookup(cx, new_parent_dir, &to_name).ok();
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

    fn readlink(&self, cx: &Cx, _scope: &mut RequestScope, ino: InodeNumber) -> Result<Vec<u8>> {
        self.node(cx, ino)?;
        Err(FfsError::Io(std::io::Error::from_raw_os_error(
            libc::EINVAL,
        )))
    }

    fn statfs(&self, cx: &Cx, _scope: &mut RequestScope, ino: InodeNumber) -> Result<FsStat> {
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

    fn fsync(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        _fh: u64,
        _datasync: bool,
    ) -> Result<()> {
        self.node(cx, ino)?;
        if self.writable {
            sync_volume(cx, &self.volume).map_err(map_mutation_error)?;
        }
        checkpoint(cx)
    }

    fn fsyncdir(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        _fh: u64,
        _datasync: bool,
    ) -> Result<()> {
        self.node(cx, ino)?.directory()?;
        if self.writable {
            sync_volume(cx, &self.volume).map_err(map_mutation_error)?;
        }
        checkpoint(cx)
    }

    fn flush_on_destroy(&self, cx: &Cx) -> Result<()> {
        if self.writable {
            sync_volume(cx, &self.volume).map_err(map_mutation_error)?;
        }
        checkpoint(cx)
    }

    fn lseek(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        whence: SeekWhence,
    ) -> Result<u64> {
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

/// Native FAT timestamps have no timezone. Project available native fields
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
