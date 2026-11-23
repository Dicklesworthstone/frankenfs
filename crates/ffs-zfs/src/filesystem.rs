//! ZPL filesystem operations over an immutable view or an admitted native writer.
//!
//! Immutable extraction views retain synthetic host ownership and permissions.
//! Writable heads retain the single pool transaction owner and publish each
//! mutation through its native TXG boundary. Snapshots stay read-only; native
//! object generations and mount-local identities prevent reuse through stale
//! inodes. Open regular files survive final unlink or replacement through the
//! native unlinked set and are reclaimed after the last backend handle closes.
//! Native ACL evaluation and reclamation of external ownership remain unsupported.

mod writable;

use super::reader::dmu::zpl::Zpl;
use asupersync::Cx;
use ffs_core::vfs::XattrSetMode;
use ffs_core::{
    DirEntry, FileType, FsOps, InodeAttr, ReaddirPage, RequestScope, SeekWhence, SetAttrRequest,
};
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs_zpl::{Kind, Metadata, Timestamp};
use ffs_types::InodeNumber;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
pub use writable::ZfsMountWriteOptions;
use writable::{MutableView, WriterState, errno, native_timestamp};

const ROOT: InodeNumber = InodeNumber(1);
const CTL_FLAG: u64 = 1_u64 << 62;
pub const ZFS_CTL_INO: InodeNumber = InodeNumber(CTL_FLAG);
pub const ZFS_SNAPDIR_INO: InodeNumber = InodeNumber(CTL_FLAG | 1);
const MAX_NODES: usize = 131_072;
const MAX_DIRECTORY_CACHE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CACHED_DIRECTORIES: usize = 32;
const PAGE_ENTRIES: usize = 256;

const fn snap_root_ino(snap_idx: u16) -> InodeNumber {
    InodeNumber(CTL_FLAG | ((snap_idx as u64) << 48) | 1)
}

const fn decode_snap_idx(ino: InodeNumber) -> Option<u16> {
    if ino.0 & CTL_FLAG == 0 {
        return None;
    }
    let idx = ((ino.0 >> 48) & 0x3FFF) as u16;
    if idx == 0 { None } else { Some(idx) }
}

fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

fn corrupt(detail: &str) -> FfsError {
    FfsError::Corruption {
        block: 0,
        detail: detail.into(),
    }
}

fn unsupported(detail: &str) -> FfsError {
    FfsError::UnsupportedFeature(detail.into())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    object: u64,
    generation: u64,
    kind: Kind,
    // A file may have hard links in several directories. Only directory parents
    // are unique and participate in the mount's ancestry checks.
    directory_parent: Option<u64>,
}

impl Identity {
    fn from_metadata(object: u64, metadata: &Metadata) -> Self {
        Self {
            object,
            generation: metadata.generation,
            kind: metadata.kind,
            directory_parent: (metadata.kind == Kind::Directory).then_some(metadata.parent),
        }
    }
}

struct CachedDirectory {
    ino: InodeNumber,
    rows: Arc<Vec<DirEntry>>,
    bytes: usize,
}

struct ViewState {
    view: Zpl,
    root_ino: InodeNumber,
    root_parent_ino: InodeNumber,
    ino_prefix: u64,
    nodes: BTreeMap<InodeNumber, Identity>,
    directories: VecDeque<CachedDirectory>,
    directory_bytes: usize,
    mutable: Option<MutableView>,
}

impl ViewState {
    fn new(
        cx: &Cx,
        mut view: Zpl,
        root_ino: InodeNumber,
        root_parent_ino: InodeNumber,
        ino_prefix: u64,
    ) -> Result<Self> {
        checkpoint(cx)?;
        let (root, _) = view.stat(cx, view.root)?;
        let identity = Identity::from_metadata(view.root, &root);
        let mut state = Self {
            view,
            root_ino,
            root_parent_ino,
            ino_prefix,
            nodes: BTreeMap::from([(root_ino, identity)]),
            directories: VecDeque::new(),
            directory_bytes: 0,
            mutable: None,
        };
        state.directory(cx, root_ino)?;
        Ok(state)
    }

    fn inode(&self, object: u64) -> Result<InodeNumber> {
        if object == self.view.root {
            return Ok(self.root_ino);
        }
        if object == 0 || object >= (1 << 48) - 1 {
            return Err(corrupt("invalid ZPL mount object number"));
        }
        if let Some(mutable) = &self.mutable {
            return mutable
                .objects
                .get(&object)
                .copied()
                .ok_or_else(|| FfsError::NotFound("ZPL mount parent identity".into()));
        }
        Ok(InodeNumber(self.ino_prefix | (object + 1)))
    }

    fn metadata(&mut self, cx: &Cx, ino: InodeNumber) -> Result<(Metadata, u64)> {
        checkpoint(cx)?;
        let expected = *self
            .nodes
            .get(&ino)
            .ok_or_else(|| FfsError::NotFound(format!("ZPL mount inode {}", ino.0)))?;
        let (metadata, allocated) = self.view.stat(cx, expected.object)?;
        let actual = Identity::from_metadata(expected.object, &metadata);
        if actual.generation != expected.generation
            || actual.kind != expected.kind
            || (self.mutable.is_none() && actual.directory_parent != expected.directory_parent)
        {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::ESTALE,
            )));
        }
        Ok((metadata, allocated))
    }

    fn directory(&mut self, cx: &Cx, ino: InodeNumber) -> Result<Arc<Vec<DirEntry>>> {
        let (metadata, _) = self.metadata(cx, ino)?;
        if metadata.kind != Kind::Directory {
            return Err(FfsError::NotDirectory);
        }
        if let Some(index) = self.directories.iter().position(|entry| entry.ino == ino) {
            let cached = self
                .directories
                .remove(index)
                .ok_or_else(|| corrupt("ZPL directory cache entry disappeared"))?;
            let rows = Arc::clone(&cached.rows);
            self.directories.push_back(cached);
            checkpoint(cx)?;
            return Ok(rows);
        }
        let object = self.nodes[&ino].object;
        let parent = if ino == self.root_ino {
            let root_lookup_parent = self.inode(metadata.parent)?;
            if self.metadata(cx, root_lookup_parent)?.0.kind != Kind::Directory {
                return Err(corrupt("ZPL mount directory parent is not a directory"));
            }
            self.root_parent_ino
        } else {
            let p = self.inode(metadata.parent)?;
            if self.metadata(cx, p)?.0.kind != Kind::Directory {
                return Err(corrupt("ZPL mount directory parent is not a directory"));
            }
            p
        };
        let mut entries = self.view.list(cx, object)?;
        entries.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        let cookie_base = self.cookie_base();
        let mut rows = vec![
            DirEntry {
                ino,
                offset: cookie_base | 1,
                kind: FileType::Directory,
                name: b".".to_vec(),
            },
            DirEntry {
                ino: parent,
                offset: cookie_base | 2,
                kind: FileType::Directory,
                name: b"..".to_vec(),
            },
        ];
        let mut pending = BTreeMap::new();
        let mut pending_objects = BTreeMap::new();
        let mut next_ino = self.mutable.as_ref().map_or(0, |view| view.next_ino);
        for entry in entries {
            checkpoint(cx)?;
            let identity = Identity::from_metadata(entry.object, &entry.metadata);
            let kind = file_type(entry.metadata.kind)?;
            let target =
                self.stage_identity(identity, &mut pending, &mut pending_objects, &mut next_ino)?;
            rows.push(DirEntry {
                ino: target,
                offset: cookie_base | (rows.len() as u64 + 1),
                kind,
                name: entry.name,
            });
        }
        // Validate the entire native directory and all identities before any
        // part becomes visible. Failed reads cannot publish a partial listing.
        checkpoint(cx)?;
        self.nodes.extend(pending);
        if let Some(mutable) = &mut self.mutable {
            mutable.objects.extend(pending_objects);
            mutable.next_ino = next_ino;
        }
        let bytes = rows.capacity() * std::mem::size_of::<DirEntry>()
            + rows.iter().map(|row| row.name.capacity()).sum::<usize>();
        let rows = Arc::new(rows);
        while self.directory_bytes + bytes > MAX_DIRECTORY_CACHE_BYTES
            || self.directories.len() >= MAX_CACHED_DIRECTORIES
        {
            let Some(old) = self.directories.pop_front() else {
                break;
            };
            self.directory_bytes -= old.bytes;
        }
        if bytes <= MAX_DIRECTORY_CACHE_BYTES {
            self.directory_bytes += bytes;
            self.directories.push_back(CachedDirectory {
                ino,
                rows: Arc::clone(&rows),
                bytes,
            });
        }
        Ok(rows)
    }
}

#[derive(Clone)]
struct SnapDirEntry {
    name: Vec<u8>,
    snap_idx: u16,
}

struct State {
    head: ViewState,
    snapshot_dir: Option<Vec<SnapDirEntry>>,
    snap_idx_by_guid: BTreeMap<u64, u16>,
    snap_name_by_idx: BTreeMap<u16, Vec<u8>>,
    next_snap_idx: u16,
    snapshots: BTreeMap<u16, ViewState>,
    writer: Option<WriterState>,
    recovery_required: bool,
}

impl State {
    fn rebuild_snapshot_dir(&mut self, cx: &Cx) -> Result<()> {
        if !self.head.view.has_snapshot_dir() {
            return Err(FfsError::NotFound("ZPL snapshot control directory".into()));
        }
        let snaps = self.head.view.snapshots(cx)?;
        let mut active_indices = BTreeSet::new();
        let mut next_names = BTreeMap::new();
        let mut dir_entries = Vec::with_capacity(snaps.len());
        for snap in snaps {
            let idx = if let Some(&existing) = self.snap_idx_by_guid.get(&snap.guid) {
                existing
            } else {
                if self.next_snap_idx == 0 || self.next_snap_idx > 0x3FFF {
                    return Err(unsupported("snapshot index overflow"));
                }
                let allocated = self.next_snap_idx;
                self.next_snap_idx = self.next_snap_idx.saturating_add(1);
                self.snap_idx_by_guid.insert(snap.guid, allocated);
                allocated
            };
            active_indices.insert(idx);
            next_names.insert(idx, snap.name.clone());
            dir_entries.push(SnapDirEntry {
                name: snap.name,
                snap_idx: idx,
            });
        }
        self.snapshots.retain(|idx, _| active_indices.contains(idx));
        self.snap_name_by_idx = next_names;
        self.snapshot_dir = Some(dir_entries);
        Ok(())
    }

    pub(super) fn invalidate_snapshots_locked(&mut self, cx: &Cx) -> Result<()> {
        self.snapshot_dir = None;
        if self.head.view.has_snapshot_dir() {
            self.rebuild_snapshot_dir(cx)?;
        }
        Ok(())
    }

    fn ensure_snapshot_dir(&mut self, cx: &Cx) -> Result<&[SnapDirEntry]> {
        if !self.head.view.has_snapshot_dir() {
            return Err(FfsError::NotFound("ZPL snapshot control directory".into()));
        }
        if self.snapshot_dir.is_none() {
            self.rebuild_snapshot_dir(cx)?;
        }
        Ok(self.snapshot_dir.as_deref().unwrap_or(&[]))
    }

    fn snapshot_view(&mut self, cx: &Cx, snap_idx: u16) -> Result<&mut ViewState> {
        checkpoint(cx)?;
        if !self.snapshots.contains_key(&snap_idx) {
            let _ = self.ensure_snapshot_dir(cx)?;
            let name = self
                .snap_name_by_idx
                .get(&snap_idx)
                .ok_or_else(|| FfsError::NotFound(format!("ZPL snapshot index {snap_idx}")))?
                .clone();
            let snap_zpl = self.head.view.open_snapshot(cx, &name)?;
            let prefix = CTL_FLAG | (u64::from(snap_idx) << 48);
            let root_ino = snap_root_ino(snap_idx);
            let view_state = ViewState::new(cx, snap_zpl, root_ino, ZFS_SNAPDIR_INO, prefix)?;
            self.snapshots.insert(snap_idx, view_state);
        }
        self.snapshots
            .get_mut(&snap_idx)
            .ok_or_else(|| FfsError::NotFound(format!("ZPL snapshot index {snap_idx}")))
    }

    fn view_for_ino(&mut self, cx: &Cx, ino: InodeNumber) -> Result<&mut ViewState> {
        if let Some(snap_idx) = decode_snap_idx(ino) {
            self.snapshot_view(cx, snap_idx)
        } else if ino.0 & CTL_FLAG != 0 {
            Err(FfsError::NotFound(format!("ZPL control inode {}", ino.0)))
        } else {
            Ok(&mut self.head)
        }
    }
}

pub struct ZfsFs {
    state: Mutex<State>,
    uid: u32,
    gid: u32,
}

impl ZfsFs {
    pub fn new(cx: &Cx, view: Zpl, uid: u32, gid: u32) -> Result<Self> {
        let head = ViewState::new(cx, view, ROOT, ROOT, 0)?;
        Ok(Self {
            state: Mutex::new(State {
                head,
                snapshot_dir: None,
                snap_idx_by_guid: BTreeMap::new(),
                snap_name_by_idx: BTreeMap::new(),
                next_snap_idx: 1,
                snapshots: BTreeMap::new(),
                writer: None,
                recovery_required: false,
            }),
            uid,
            gid,
        })
    }

    /// Validate a read-only open request without instantiating writable `O_TRUNC` code.
    /// A writable owner still retains a lifetime handle, including for snapshots.
    pub fn open_read_only(&self, cx: &Cx, ino: InodeNumber, flags: i32) -> Result<(u64, u32)> {
        checkpoint(cx)?;
        if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & (libc::O_TRUNC | libc::O_CREAT) != 0
        {
            return Err(FfsError::ReadOnly);
        }
        if ino == ZFS_CTL_INO || ino == ZFS_SNAPDIR_INO {
            return Err(FfsError::IsDirectory);
        }
        let mut state = self.state(cx)?;
        let metadata = state.view_for_ino(cx, ino)?.metadata(cx, ino)?.0;
        match metadata.kind {
            Kind::Directory => return Err(FfsError::IsDirectory),
            Kind::Regular => {}
            _ => return Err(unsupported("ZPL open requires a regular file")),
        }
        if flags & libc::O_DIRECTORY != 0 {
            return Err(FfsError::NotDirectory);
        }
        if state.writer.is_some() {
            let handle = state.next_open_handle()?;
            state.publish_open_handle(ino, handle);
            return Ok((handle, 0));
        }
        Ok((0, 0))
    }

    /// Query read-only filesystem space statistics without referencing writer state.
    pub fn statfs_read_only(&self, cx: &Cx, ino: InodeNumber) -> Result<ffs_core::FsStat> {
        let mut state = self.state(cx)?;
        let space_info = if ino == ZFS_CTL_INO || ino == ZFS_SNAPDIR_INO {
            if !state.head.view.has_snapshot_dir() {
                return Err(FfsError::NotFound("ZPL control directory".into()));
            }
            state.head.view.statfs_info()
        } else {
            let view_state = state.view_for_ino(cx, ino)?;
            view_state.metadata(cx, ino)?;
            view_state.view.statfs_info()
        };
        checkpoint(cx)?;
        Ok(space_info)
    }

    /// Validate `fsync` on a read-only mount without referencing writer sync paths.
    pub fn fsync_read_only(&self, cx: &Cx, ino: InodeNumber, fh: u64) -> Result<()> {
        let mut state = self.state(cx)?;
        state.validate_handle(ino, fh)?;
        if ino != ZFS_CTL_INO && ino != ZFS_SNAPDIR_INO {
            state.view_for_ino(cx, ino)?.metadata(cx, ino)?;
        }
        checkpoint(cx)
    }

    /// Validate `fsyncdir` on a read-only mount without referencing writer sync paths.
    pub fn fsyncdir_read_only(&self, cx: &Cx, ino: InodeNumber) -> Result<()> {
        let mut state = self.state(cx)?;
        if ino == ZFS_CTL_INO || ino == ZFS_SNAPDIR_INO {
            if !state.head.view.has_snapshot_dir() {
                return Err(FfsError::NotFound("ZPL control directory".into()));
            }
            return checkpoint(cx);
        }
        if state.view_for_ino(cx, ino)?.metadata(cx, ino)?.0.kind != Kind::Directory {
            return Err(FfsError::NotDirectory);
        }
        checkpoint(cx)
    }

    fn state(&self, cx: &Cx) -> Result<MutexGuard<'_, State>> {
        checkpoint(cx)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("ZPL mount state poisoned")))?;
        checkpoint(cx)?;
        if state.recovery_required {
            return Err(errno(libc::EIO));
        }
        state.refresh_head(cx)?;
        state.refresh_snapshots(cx)?;
        Ok(state)
    }

    fn ctl_attributes(
        &self,
        cx: &Cx,
        state: &mut State,
        ino: InodeNumber,
        nlink: u32,
    ) -> Result<InodeAttr> {
        if !state.head.view.has_snapshot_dir() {
            return Err(FfsError::NotFound("ZPL control directory".into()));
        }
        let (root_meta, _) = state.head.metadata(cx, ROOT)?;
        Ok(InodeAttr {
            ino,
            size: u64::from(nlink),
            blocks: 0,
            atime: system_time(root_meta.times[0])?,
            mtime: system_time(root_meta.times[1])?,
            ctime: system_time(root_meta.times[2])?,
            crtime: system_time(root_meta.times[3])?,
            kind: FileType::Directory,
            perm: 0o555,
            nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            generation: 1,
        })
    }

    fn attributes(&self, cx: &Cx, state: &mut State, ino: InodeNumber) -> Result<InodeAttr> {
        if ino == ZFS_CTL_INO {
            return self.ctl_attributes(cx, state, ZFS_CTL_INO, 3);
        }
        if ino == ZFS_SNAPDIR_INO {
            let count = state.ensure_snapshot_dir(cx)?.len();
            let nlink = u32::try_from(2 + count).unwrap_or(u32::MAX);
            return self.ctl_attributes(cx, state, ZFS_SNAPDIR_INO, nlink);
        }
        let native_ownership = state.writer.is_some();
        let writable_head = native_ownership && ino.0 & CTL_FLAG == 0;
        let view_state = state.view_for_ino(cx, ino)?;
        let (metadata, allocated) = view_state.metadata(cx, ino)?;
        let kind = file_type(metadata.kind)?;
        let perm = if native_ownership {
            let native = (metadata.mode & 0o7777) as u16;
            if writable_head {
                native
            } else {
                native & !0o222
            }
        } else {
            match kind {
                FileType::Directory => 0o555,
                FileType::Symlink => 0o777,
                _ => 0o444,
            }
        };
        let (uid, gid) = if native_ownership {
            (
                u32::try_from(metadata.uid).map_err(|_| errno(libc::EOVERFLOW))?,
                u32::try_from(metadata.gid).map_err(|_| errno(libc::EOVERFLOW))?,
            )
        } else {
            (self.uid, self.gid)
        };
        let nlink = u32::try_from(metadata.links)
            .map_err(|_| FfsError::Io(std::io::Error::from_raw_os_error(libc::EOVERFLOW)))?;
        Ok(InodeAttr {
            ino,
            size: metadata.size,
            blocks: allocated.div_ceil(512),
            atime: system_time(metadata.times[0])?,
            mtime: system_time(metadata.times[1])?,
            ctime: system_time(metadata.times[2])?,
            crtime: system_time(metadata.times[3])?,
            kind,
            perm,
            nlink,
            uid,
            gid,
            rdev: 0,
            blksize: 4096,
            generation: metadata.generation,
        })
    }
}

impl FsOps for ZfsFs {
    fn requires_stateful_open(&self) -> bool {
        // A poisoned writer must never silently downgrade to stateless OPEN.
        self.state
            .lock()
            .map_or(true, |state| state.writer.is_some())
    }

    fn supports_posix_acl(&self) -> bool {
        false
    }

    fn begin_request_scope(&self, cx: &Cx, op: ffs_core::vfs::RequestOp) -> Result<RequestScope> {
        // RELEASE must reach its lifetime cleanup even if the request is
        // already cancelled. Other operations retain normal admission.
        if op != ffs_core::vfs::RequestOp::Release {
            checkpoint(cx)?;
        }
        Ok(RequestScope::empty())
    }

    fn getattr(&self, cx: &Cx, _scope: &mut RequestScope, ino: InodeNumber) -> Result<InodeAttr> {
        let mut state = self.state(cx)?;
        self.attributes(cx, &mut state, ino)
    }

    fn lookup(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> Result<InodeAttr> {
        let name = name.as_bytes();
        if name.len() > 255 {
            return Err(FfsError::NameTooLong);
        }
        if name.is_empty() || name.contains(&0) || name.contains(&b'/') {
            return Err(FfsError::Format("invalid ZPL mount path component".into()));
        }
        let mut state = self.state(cx)?;
        if parent == ROOT && name == b".zfs" && state.head.view.has_snapshot_dir() {
            return self.ctl_attributes(cx, &mut state, ZFS_CTL_INO, 3);
        }
        if parent == ZFS_CTL_INO {
            if !state.head.view.has_snapshot_dir() {
                return Err(FfsError::NotFound("ZPL control directory".into()));
            }
            return match name {
                b"." => self.ctl_attributes(cx, &mut state, ZFS_CTL_INO, 3),
                b".." => self.attributes(cx, &mut state, ROOT),
                b"snapshot" => self.attributes(cx, &mut state, ZFS_SNAPDIR_INO),
                _ => Err(FfsError::NotFound("ZPL control entry".into())),
            };
        }
        if parent == ZFS_SNAPDIR_INO {
            if !state.head.view.has_snapshot_dir() {
                return Err(FfsError::NotFound("ZPL snapshot directory".into()));
            }
            return match name {
                b"." => self.attributes(cx, &mut state, ZFS_SNAPDIR_INO),
                b".." => self.ctl_attributes(cx, &mut state, ZFS_CTL_INO, 3),
                _ => {
                    let entries = state.ensure_snapshot_dir(cx)?;
                    let index = entries
                        .binary_search_by(|candidate| candidate.name.as_slice().cmp(name))
                        .map_err(|_| FfsError::NotFound("ZFS named snapshot".into()))?;
                    let snap_idx = entries[index].snap_idx;
                    let root_ino = state.snapshot_view(cx, snap_idx)?.root_ino;
                    self.attributes(cx, &mut state, root_ino)
                }
            };
        }
        let rows = state.view_for_ino(cx, parent)?.directory(cx, parent)?;
        let target = match name {
            b"." => parent,
            b".." => rows[1].ino,
            _ => {
                let index = rows[2..]
                    .binary_search_by(|row| row.name.as_slice().cmp(name))
                    .map_err(|_| FfsError::NotFound("ZPL mount path component".into()))?;
                rows[index + 2].ino
            }
        };
        self.attributes(cx, &mut state, target)
    }

    fn readdir(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
    ) -> Result<ReaddirPage> {
        let mut state = self.state(cx)?;
        if ino == ZFS_CTL_INO {
            if !state.head.view.has_snapshot_dir() {
                return Err(FfsError::NotFound("ZPL control directory".into()));
            }
            let rows = [
                DirEntry {
                    ino: ZFS_CTL_INO,
                    offset: 1,
                    kind: FileType::Directory,
                    name: b".".to_vec(),
                },
                DirEntry {
                    ino: ROOT,
                    offset: 2,
                    kind: FileType::Directory,
                    name: b"..".to_vec(),
                },
                DirEntry {
                    ino: ZFS_SNAPDIR_INO,
                    offset: 3,
                    kind: FileType::Directory,
                    name: b"snapshot".to_vec(),
                },
            ];
            let start = rows.partition_point(|row| row.offset <= offset);
            let end = rows.len().min(start + PAGE_ENTRIES);
            checkpoint(cx)?;
            return Ok(ReaddirPage::new(rows[start..end].to_vec())
                .with_end_cookie(Some(rows.len() as u64)));
        }
        if ino == ZFS_SNAPDIR_INO {
            let entries = state.ensure_snapshot_dir(cx)?.to_vec();
            let mut rows = Vec::with_capacity(2 + entries.len());
            rows.push(DirEntry {
                ino: ZFS_SNAPDIR_INO,
                offset: 1,
                kind: FileType::Directory,
                name: b".".to_vec(),
            });
            rows.push(DirEntry {
                ino: ZFS_CTL_INO,
                offset: 2,
                kind: FileType::Directory,
                name: b"..".to_vec(),
            });
            for entry in entries {
                rows.push(DirEntry {
                    ino: snap_root_ino(entry.snap_idx),
                    offset: rows.len() as u64 + 1,
                    kind: FileType::Directory,
                    name: entry.name,
                });
            }
            let start = rows.partition_point(|row| row.offset <= offset);
            let end = rows.len().min(start + PAGE_ENTRIES);
            checkpoint(cx)?;
            return Ok(ReaddirPage::new(rows[start..end].to_vec())
                .with_end_cookie(Some(rows.len() as u64)));
        }
        let view_state = state.view_for_ino(cx, ino)?;
        view_state.validate_cookie(offset)?;
        let rows = view_state.directory(cx, ino)?;
        let start = rows.partition_point(|row| row.offset <= offset);
        let end = rows.len().min(start + PAGE_ENTRIES);
        checkpoint(cx)?;
        Ok(ReaddirPage::new(rows[start..end].to_vec())
            .with_end_cookie(rows.last().map(|row| row.offset)))
    }

    fn read(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>> {
        if ino == ZFS_CTL_INO || ino == ZFS_SNAPDIR_INO {
            return Err(FfsError::IsDirectory);
        }
        let mut state = self.state(cx)?;
        let view_state = state.view_for_ino(cx, ino)?;
        view_state.metadata(cx, ino)?;
        let object = view_state.nodes[&ino].object;
        view_state.view.read(cx, object, offset, size as usize)
    }

    fn get_inode_flags(&self, cx: &Cx, _scope: &mut RequestScope, ino: InodeNumber) -> Result<u32> {
        checkpoint(cx)?;
        if ino == ZFS_CTL_INO || ino == ZFS_SNAPDIR_INO {
            return Ok(ffs_types::EXT4_IMMUTABLE_FL);
        }
        let mut state = self.state(cx)?;
        let metadata = state.view_for_ino(cx, ino)?.metadata(cx, ino)?.0;
        let mut flags = 0_u32;
        if metadata.flags & 0x0000_0010_0000_0000 != 0 {
            flags |= ffs_types::EXT4_IMMUTABLE_FL;
        }
        if metadata.flags & 0x0000_0040_0000_0000 != 0 {
            flags |= ffs_types::EXT4_APPEND_FL;
        }
        Ok(flags)
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
        let mut state = self.state(cx)?;
        if wants_write && (state.writer.is_none() || ino.0 & CTL_FLAG != 0) {
            return Err(FfsError::ReadOnly);
        }
        if ino == ZFS_CTL_INO || ino == ZFS_SNAPDIR_INO {
            return Err(FfsError::IsDirectory);
        }
        let metadata = state.view_for_ino(cx, ino)?.metadata(cx, ino)?.0;
        match metadata.kind {
            Kind::Directory => return Err(FfsError::IsDirectory),
            Kind::Regular => {}
            _ => return Err(unsupported("ZPL open requires a regular file")),
        }
        if flags & libc::O_DIRECTORY != 0 {
            return Err(FfsError::NotDirectory);
        }
        if state.writer.is_none() {
            return Ok((0, 0));
        }
        if flags & libc::O_ACCMODE == libc::O_ACCMODE {
            return Err(errno(libc::EINVAL));
        }
        // Native DOS read-only and immutable flags are admission checks on
        // writable opens. Existing authorized handles remain governed by the
        // transaction engine's mutation-specific native flag rules.
        if wants_write && metadata.flags & (0x0000_0001_0000_0000 | 0x0000_0010_0000_0000) != 0 {
            return Err(FfsError::PermissionDenied);
        }
        if wants_write && metadata.flags & 0x0000_0040_0000_0000 != 0 && flags & libc::O_APPEND == 0
        {
            return Err(FfsError::PermissionDenied);
        }
        let handle = state.next_open_handle()?;
        if flags & libc::O_TRUNC != 0 {
            state.admit_data_mutation(cx, ino, &metadata)?;
            let object = state.head.nodes[&ino].object;
            let timestamp = native_timestamp(SystemTime::now())?;
            state.mutate(cx, |engine, dataset| {
                engine.truncate_file(
                    cx,
                    dataset,
                    object,
                    0,
                    timestamp,
                    crate::ZfsDataChecksum::default(),
                )
            })?;
        }
        state.publish_open_handle(ino, handle);
        Ok((handle, 0))
    }

    fn create(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> Result<InodeAttr> {
        self.create_with_handle(cx, parent, name, mode, uid, gid, None)
            .map(|(attr, _, _)| attr)
    }

    #[allow(clippy::too_many_arguments)]
    fn create_open(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
        uid: u32,
        gid: u32,
        flags: i32,
    ) -> Result<(InodeAttr, u64, u32)> {
        self.create_with_handle(cx, parent, name, mode, uid, gid, Some(flags))
    }

    fn mkdir(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> Result<InodeAttr> {
        let mut state = self.state(cx)?;
        let parent_object = state.writable_parent(cx, parent, name.as_bytes())?;
        let (mode, gid) = state.creation_mode_gid(cx, parent, mode & 0o7777, gid, true)?;
        state.reserve_identity()?;
        let timestamp = native_timestamp(SystemTime::now())?;
        let object = state.mutate(cx, |engine, dataset| {
            engine.mkdir(
                cx,
                dataset,
                parent_object,
                name.as_bytes(),
                mode,
                u64::from(uid),
                u64::from(gid),
                timestamp,
            )
        })?;
        state.publish_committed(|state| {
            state.refresh_head(cx)?;
            let ino = state.head.remember_object(cx, object)?;
            self.attributes(cx, state, ino)
        })
    }

    fn symlink(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        target: &Path,
        uid: u32,
        gid: u32,
    ) -> Result<InodeAttr> {
        let mut state = self.state(cx)?;
        let parent_object = state.writable_parent(cx, parent, name.as_bytes())?;
        let (_, gid) = state.creation_mode_gid(cx, parent, 0o777, gid, false)?;
        state.reserve_identity()?;
        let timestamp = native_timestamp(SystemTime::now())?;
        let object = state.mutate(cx, |engine, dataset| {
            engine.create_symlink(
                cx,
                dataset,
                parent_object,
                name.as_bytes(),
                target.as_os_str().as_bytes(),
                u64::from(uid),
                u64::from(gid),
                timestamp,
                crate::ZfsDataChecksum::default(),
            )
        })?;
        state.publish_committed(|state| {
            state.refresh_head(cx)?;
            let ino = state.head.remember_object(cx, object)?;
            self.attributes(cx, state, ino)
        })
    }

    fn write(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        data: &[u8],
    ) -> Result<u32> {
        let mut state = self.state(cx)?;
        let metadata = state.writable_metadata(cx, ino)?;
        if metadata.kind == Kind::Directory {
            return Err(FfsError::IsDirectory);
        }
        if metadata.kind != Kind::Regular {
            return Err(unsupported("ZPL writes require a regular file"));
        }
        // Direct FsOps callers need the same native admission as OPEN. This
        // profile does not mutate DOS flags, so existing writable handles do
        // not need to survive a later change to the native read-only flag.
        if metadata.flags & 0x0000_0001_0000_0000 != 0 {
            return Err(FfsError::PermissionDenied);
        }
        let written = u32::try_from(data.len()).map_err(|_| errno(libc::EFBIG))?;
        if data.is_empty() {
            return Ok(0);
        }
        state.admit_data_mutation(cx, ino, &metadata)?;
        let object = state.head.nodes[&ino].object;
        let timestamp = native_timestamp(SystemTime::now())?;
        state.mutate(cx, |engine, dataset| {
            engine.write_file_data(
                cx,
                dataset,
                object,
                offset,
                data,
                timestamp,
                crate::ZfsDataChecksum::default(),
            )
        })?;
        Ok(written)
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
        let mut state = self.state(cx)?;
        let metadata = state.writable_metadata(cx, ino)?;
        let operation = if mode == (libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE) {
            crate::ZfsFileRangeOperation::PunchHole
        } else if mode == libc::FALLOC_FL_ZERO_RANGE {
            crate::ZfsFileRangeOperation::ZeroRange { keep_size: false }
        } else if mode == (libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE) {
            crate::ZfsFileRangeOperation::ZeroRange { keep_size: true }
        } else {
            return Err(unsupported(
                "ZPL fallocate supports only PUNCH_HOLE|KEEP_SIZE and ZERO_RANGE with optional KEEP_SIZE",
            ));
        };
        if metadata.kind == Kind::Directory {
            return Err(FfsError::IsDirectory);
        }
        if metadata.kind != Kind::Regular {
            return Err(unsupported("ZPL range mutation requires a regular file"));
        }
        state.admit_data_mutation(cx, ino, &metadata)?;
        let object = state.head.nodes[&ino].object;
        let timestamp = native_timestamp(SystemTime::now())?;
        state.mutate(cx, |engine, dataset| {
            engine.edit_file_range(
                cx,
                dataset,
                object,
                offset,
                length,
                operation,
                timestamp,
                crate::ZfsDataChecksum::default(),
            )
        })?;
        // No result metadata is needed. Preserve a known committed outcome if
        // cancellation arrived after its barrier; the next request refreshes.
        Ok(())
    }

    fn setattr(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        attrs: &SetAttrRequest,
    ) -> Result<InodeAttr> {
        let mut state = self.state(cx)?;
        let metadata = state.writable_metadata(cx, ino)?;
        let allow_mode_owner = state
            .writer
            .as_ref()
            .is_some_and(|w| w.allow_mode_and_owner_setattr);

        // Strip Linux FUSE file-type bits (e.g. S_IFREG | 0o644) after checking
        // they agree with the target inode's native ZPL kind.
        let req_perm = match attrs.mode {
            Some(raw_mode) => {
                let ftype = u32::from(raw_mode) & libc::S_IFMT;
                if ftype != 0 {
                    let expected_ftype = match metadata.kind {
                        Kind::Directory => libc::S_IFDIR,
                        Kind::Regular => libc::S_IFREG,
                        Kind::Symlink => libc::S_IFLNK,
                        _ => 0,
                    };
                    if ftype != expected_ftype {
                        return Err(unsupported(
                            "requested file type disagrees with ZPL inode kind",
                        ));
                    }
                }
                Some(raw_mode & 0o7777)
            }
            None => None,
        };

        if !allow_mode_owner
            && (req_perm.is_some_and(|mode| u64::from(mode) != metadata.mode & 0o7777)
                || attrs.uid.is_some_and(|uid| u64::from(uid) != metadata.uid)
                || attrs.gid.is_some_and(|gid| u64::from(gid) != metadata.gid))
        {
            return Err(unsupported(
                "native ZPL mode and ownership changes are not implemented",
            ));
        }

        let mode_update = if allow_mode_owner {
            req_perm.filter(|&m| u64::from(m) != metadata.mode & 0o7777)
        } else {
            None
        };
        let uid_update = if allow_mode_owner {
            attrs.uid.map(u64::from).filter(|&u| u != metadata.uid)
        } else {
            None
        };
        let gid_update = if allow_mode_owner {
            attrs.gid.map(u64::from).filter(|&g| g != metadata.gid)
        } else {
            None
        };

        let native_attrs = crate::ZfsPosixSetAttr {
            size: attrs.size,
            atime: attrs.atime.map(native_timestamp).transpose()?,
            mtime: attrs.mtime.map(native_timestamp).transpose()?,
            mode: mode_update,
            uid: uid_update,
            gid: gid_update,
            clear_suid_sgid: false,
        };
        if attrs.size.is_some() {
            if metadata.kind == Kind::Directory {
                return Err(FfsError::IsDirectory);
            }
            if metadata.kind != Kind::Regular {
                return Err(unsupported("ZPL truncate requires a regular file"));
            }
            state.admit_data_mutation(cx, ino, &metadata)?;
        }
        if native_attrs.size.is_some()
            || native_attrs.atime.is_some()
            || native_attrs.mtime.is_some()
            || native_attrs.mode.is_some()
            || native_attrs.uid.is_some()
            || native_attrs.gid.is_some()
        {
            let object = state.head.nodes[&ino].object;
            let timestamp = native_timestamp(SystemTime::now())?;
            state.mutate(cx, |engine, dataset| {
                engine.set_posix_attributes(
                    cx,
                    dataset,
                    object,
                    &native_attrs,
                    timestamp,
                    crate::ZfsDataChecksum::default(),
                )
            })?;
            return state.publish_committed(|state| {
                state.refresh_head(cx)?;
                self.attributes(cx, state, ino)
            });
        }
        self.attributes(cx, &mut state, ino)
    }

    fn link(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        new_parent: InodeNumber,
        new_name: &OsStr,
    ) -> Result<InodeAttr> {
        let mut state = self.state(cx)?;
        state.writable_metadata(cx, ino)?;
        let object = state.head.nodes[&ino].object;
        let parent = state.writable_parent(cx, new_parent, new_name.as_bytes())?;
        let timestamp = native_timestamp(SystemTime::now())?;
        state.mutate(cx, |engine, dataset| {
            engine.link_entry(cx, dataset, object, parent, new_name.as_bytes(), timestamp)
        })?;
        state.publish_committed(|state| {
            state.refresh_head(cx)?;
            self.attributes(cx, state, ino)
        })
    }

    fn unlink(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> Result<()> {
        self.remove_entry(cx, parent, name, false)
    }

    fn rmdir(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> Result<()> {
        self.remove_entry(cx, parent, name, true)
    }

    fn rename(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        new_parent: InodeNumber,
        new_name: &OsStr,
    ) -> Result<()> {
        self.rename2(cx, scope, parent, name, new_parent, new_name, 0)
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
        let mut state = self.state(cx)?;
        let source_parent = state.writable_parent(cx, parent, name.as_bytes())?;
        let target_parent = state.writable_parent(cx, new_parent, new_name.as_bytes())?;
        if flags & !libc::RENAME_NOREPLACE != 0 {
            return Err(errno(libc::EINVAL));
        }
        let source = state.child(cx, parent, name.as_bytes())?;
        let object = state.head.nodes[&source].object;
        let retained = match state.child(cx, new_parent, new_name.as_bytes()) {
            Ok(target) => {
                if flags & libc::RENAME_NOREPLACE != 0 {
                    return Err(FfsError::Exists);
                }
                if target == source {
                    return Ok(());
                }
                let metadata = state.head.metadata(cx, target)?.0;
                if metadata.kind == Kind::Directory {
                    state.reject_pinned_reclamation(target)?;
                }
                (metadata.kind == Kind::Regular
                    && metadata.links <= 1
                    && state.has_open_handles(target))
                .then(|| {
                    (
                        target,
                        crate::ZfsUnlinkedObject {
                            object: state.head.nodes[&target].object,
                            generation: metadata.generation,
                        },
                    )
                })
            }
            Err(FfsError::NotFound(_)) => None,
            Err(error) => return Err(error),
        };
        let timestamp = native_timestamp(SystemTime::now())?;
        state.mutate(cx, |engine, dataset| {
            if let Some((_, identity)) = retained {
                engine.rename_retaining_open_target(
                    cx,
                    dataset,
                    source_parent,
                    name.as_bytes(),
                    target_parent,
                    new_name.as_bytes(),
                    Some(object),
                    identity,
                    timestamp,
                )
            } else {
                engine.rename_entry(
                    cx,
                    dataset,
                    source_parent,
                    name.as_bytes(),
                    target_parent,
                    new_name.as_bytes(),
                    Some(object),
                    timestamp,
                )
            }
        })?;
        if let Some((ino, identity)) = retained {
            state.remember_unlinked(ino, identity);
        }
        Ok(())
    }

    fn readlink(&self, cx: &Cx, _scope: &mut RequestScope, ino: InodeNumber) -> Result<Vec<u8>> {
        if ino == ZFS_CTL_INO || ino == ZFS_SNAPDIR_INO {
            return Err(FfsError::Format("ZPL inode is not a symbolic link".into()));
        }
        let mut state = self.state(cx)?;
        let view_state = state.view_for_ino(cx, ino)?;
        if view_state.metadata(cx, ino)?.0.kind != Kind::Symlink {
            return Err(FfsError::Format("ZPL inode is not a symbolic link".into()));
        }
        let object = view_state.nodes[&ino].object;
        view_state.view.readlink(cx, object)
    }

    fn listxattr(&self, cx: &Cx, ino: InodeNumber) -> Result<Vec<String>> {
        if ino == ZFS_CTL_INO || ino == ZFS_SNAPDIR_INO {
            return Ok(Vec::new());
        }
        let mut state = self.state(cx)?;
        let view_state = state.view_for_ino(cx, ino)?;
        view_state.metadata(cx, ino)?;
        let object = view_state.nodes[&ino].object;
        view_state.view.listxattr(cx, object)
    }

    fn getxattr(&self, cx: &Cx, ino: InodeNumber, name: &str) -> Result<Option<Vec<u8>>> {
        if ino == ZFS_CTL_INO || ino == ZFS_SNAPDIR_INO {
            return Ok(None);
        }
        let mut state = self.state(cx)?;
        let view_state = state.view_for_ino(cx, ino)?;
        view_state.metadata(cx, ino)?;
        let object = view_state.nodes[&ino].object;
        view_state.view.getxattr(cx, object, name)
    }

    fn setxattr(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        name: &str,
        value: &[u8],
        mode: XattrSetMode,
    ) -> Result<()> {
        let mut state = self.state(cx)?;
        state.writable_metadata(cx, ino)?;
        let object = state.head.nodes[&ino].object;
        let native_mode = match mode {
            XattrSetMode::Set => crate::ZfsXattrSetMode::Auto,
            XattrSetMode::Create => crate::ZfsXattrSetMode::Create,
            XattrSetMode::Replace => crate::ZfsXattrSetMode::Replace,
        };
        let timestamp = native_timestamp(SystemTime::now())?;
        state.mutate(cx, |engine, dataset| {
            engine.set_xattr(cx, dataset, object, name, value, native_mode, timestamp)
        })?;
        state.publish_committed(|state| state.refresh_head(cx))
    }

    fn removexattr(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        name: &str,
    ) -> Result<bool> {
        let mut state = self.state(cx)?;
        state.writable_metadata(cx, ino)?;
        let object = state.head.nodes[&ino].object;
        if name == "security.capability" {
            if state.head.view.has_file_capabilities(cx, object)? {
                return Err(unsupported(
                    "native ZPL capability removal is not implemented",
                ));
            }
            // FUSE's killpriv path asks to drop capabilities before ordinary writes.
            // A proven-absent attribute needs no mutation; a present one is refused.
            return Ok(false);
        }
        if !name.starts_with("user.") {
            return Err(unsupported("only the ZPL user xattr namespace is exposed"));
        }
        let timestamp = native_timestamp(SystemTime::now())?;
        match state.mutate(cx, |engine, dataset| {
            engine.remove_xattr(cx, dataset, object, name, timestamp)
        }) {
            Ok(_) => {
                state.publish_committed(|state| state.refresh_head(cx))?;
                Ok(true)
            }
            Err(FfsError::RequestRejected { errno, .. }) if errno == libc::ENODATA => Ok(false),
            Err(err) => Err(err),
        }
    }

    fn fsync(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        fh: u64,
        _datasync: bool,
    ) -> Result<()> {
        let mut state = self.state(cx)?;
        state.validate_handle(ino, fh)?;
        if ino != ZFS_CTL_INO && ino != ZFS_SNAPDIR_INO {
            state.view_for_ino(cx, ino)?.metadata(cx, ino)?;
        }
        state.sync(cx)
    }

    fn fsyncdir(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        _fh: u64,
        _datasync: bool,
    ) -> Result<()> {
        let mut state = self.state(cx)?;
        if ino == ZFS_CTL_INO || ino == ZFS_SNAPDIR_INO {
            if !state.head.view.has_snapshot_dir() {
                return Err(FfsError::NotFound("ZPL control directory".into()));
            }
            return state.sync(cx);
        }
        if state.view_for_ino(cx, ino)?.metadata(cx, ino)?.0.kind != Kind::Directory {
            return Err(FfsError::NotDirectory);
        }
        state.sync(cx)
    }

    fn flush(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        fh: u64,
        _lock_owner: u64,
    ) -> Result<()> {
        let state = self.state(cx)?;
        state.validate_handle(ino, fh)
    }

    fn release(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        request: ffs_core::vfs::ReleaseRequest,
    ) -> Result<()> {
        // Releasing a backend lifetime pin is required even when the request
        // was cancelled or a previous durable commit still needs view refresh.
        // Otherwise a failed RELEASE would permanently prevent reclamation.
        let mut state = self.state.lock().map_err(|_| errno(libc::EIO))?;
        state.release_open_handle(request)?;
        if state.recovery_required {
            return Err(errno(libc::EIO));
        }
        state.reap_closed_orphan(cx, request.ino)?;
        if request.flush {
            state.sync(cx)?;
        }
        checkpoint(cx)
    }

    fn finalize_unlinked_inode(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> Result<bool> {
        self.state(cx)?.reap_closed_orphan(cx, ino)
    }

    fn sync_fs(&self, cx: &Cx, _scope: &mut RequestScope) -> Result<()> {
        let mut state = self.state(cx)?;
        state.reap_closed_orphans(cx)?;
        state.sync(cx)
    }

    fn default_commit_interval(&self) -> Option<std::time::Duration> {
        self.is_writable()
            .unwrap_or(false)
            .then_some(std::time::Duration::from_secs(5))
    }

    fn periodic_commit(&self, cx: &Cx) -> Result<bool> {
        if !self.is_writable()? {
            return Ok(false);
        }
        let mut scope = RequestScope::empty();
        self.sync_fs(cx, &mut scope)?;
        Ok(true)
    }

    fn flush_on_destroy(&self, cx: &Cx) -> Result<()> {
        let mut state = self.state(cx)?;
        state.reap_closed_orphans(cx)?;
        state.sync(cx)
    }

    fn statfs(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> Result<ffs_core::FsStat> {
        let mut state = self.state(cx)?;
        let mut space_info = if ino == ZFS_CTL_INO || ino == ZFS_SNAPDIR_INO {
            if !state.head.view.has_snapshot_dir() {
                return Err(FfsError::NotFound("ZPL control directory".into()));
            }
            state.head.view.statfs_info()
        } else {
            let view_state = state.view_for_ino(cx, ino)?;
            view_state.metadata(cx, ino)?;
            view_state.view.statfs_info()
        };
        checkpoint(cx)?;
        if let Some(writer) = &state.writer {
            let fragment_size = u64::from(space_info.fragment_size);
            if fragment_size == 0 {
                return Err(corrupt("ZPL statfs fragment size is zero"));
            }
            let pool_free = writer.engine.free_bytes();
            let mut mos = writer.engine.open_read_objects(cx)?;
            if ino.0 & CTL_FLAG == 0
                && let Some((referenced, avail)) = crate::transaction::dataset_statfs_quota_space(
                    cx,
                    &mut mos,
                    &writer.dataset,
                    pool_free,
                )?
            {
                space_info.blocks = referenced.saturating_add(avail) / fragment_size;
                space_info.blocks_free = avail / fragment_size;
                space_info.blocks_available = space_info.blocks_free;
            } else {
                space_info.blocks = writer.engine.storage_identity().asize / fragment_size;
                space_info.blocks_free = pool_free / fragment_size;
                space_info.blocks_available = space_info.blocks_free;
            }
        }
        Ok(space_info)
    }

    fn lseek(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        whence: SeekWhence,
    ) -> Result<u64> {
        checkpoint(cx)?;
        if ino == ZFS_CTL_INO || ino == ZFS_SNAPDIR_INO {
            return Err(unsupported("ZPL seek requires a regular file"));
        }
        let mut state = self.state(cx)?;
        let view_state = state.view_for_ino(cx, ino)?;
        view_state.metadata(cx, ino)?;
        let object = view_state.nodes[&ino].object;
        view_state.view.seek(cx, object, offset, whence)
    }
}

fn file_type(kind: Kind) -> Result<FileType> {
    match kind {
        Kind::Directory => Ok(FileType::Directory),
        Kind::Regular => Ok(FileType::RegularFile),
        Kind::Symlink => Ok(FileType::Symlink),
        _ => Err(unsupported(
            "ZPL extraction mount does not expose special files",
        )),
    }
}

fn system_time(time: Timestamp) -> Result<SystemTime> {
    // Native seconds are signed; nanoseconds are always a positive fraction.
    // For -1 + 0.5 seconds, subtract one second and then add the fraction.
    let seconds = Duration::from_secs(time.seconds.unsigned_abs());
    let base = if time.seconds < 0 {
        UNIX_EPOCH.checked_sub(seconds)
    } else {
        UNIX_EPOCH.checked_add(seconds)
    };
    base.and_then(|base| base.checked_add(Duration::from_nanos(u64::from(time.nanos))))
        .ok_or_else(|| unsupported("ZPL timestamp is outside the host time range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_keep_negative_fractional_seconds_and_native_precision() {
        assert_eq!(
            system_time(Timestamp {
                seconds: -1,
                nanos: 500_000_000
            })
            .unwrap(),
            UNIX_EPOCH - Duration::from_millis(500)
        );
        assert_eq!(
            system_time(Timestamp {
                seconds: 1,
                nanos: 123
            })
            .unwrap(),
            UNIX_EPOCH + Duration::new(1, 123)
        );
    }
}
