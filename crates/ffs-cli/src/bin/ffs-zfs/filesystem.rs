//! Read-only extraction mount of one explicitly selected ZPL head or snapshot.
//!
//! The view owns its immutable leaf and its root-local block cache. Native
//! object numbers identify hard links within this mount; generations are checked
//! on every access. Host ownership/modes are synthetic, not a ZFS ACL projection.

use crate::reader::dmu::zpl::Zpl;
use asupersync::Cx;
use ffs_core::{DirEntry, FileType, FsOps, InodeAttr, ReaddirPage, RequestScope, SeekWhence};
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs_zpl::{Kind, Metadata, Timestamp};
use ffs_types::InodeNumber;
use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        Ok(InodeNumber(self.ino_prefix | (object + 1)))
    }

    fn metadata(&mut self, cx: &Cx, ino: InodeNumber) -> Result<(Metadata, u64)> {
        checkpoint(cx)?;
        let expected = *self
            .nodes
            .get(&ino)
            .ok_or_else(|| FfsError::NotFound(format!("ZPL mount inode {}", ino.0)))?;
        let (metadata, allocated) = self.view.stat(cx, expected.object)?;
        if Identity::from_metadata(expected.object, &metadata) != expected {
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
        let mut rows = vec![
            DirEntry {
                ino,
                offset: 1,
                kind: FileType::Directory,
                name: b".".to_vec(),
            },
            DirEntry {
                ino: parent,
                offset: 2,
                kind: FileType::Directory,
                name: b"..".to_vec(),
            },
        ];
        let mut pending = BTreeMap::new();
        for entry in entries {
            checkpoint(cx)?;
            let target = self.inode(entry.object)?;
            let identity = Identity::from_metadata(entry.object, &entry.metadata);
            let kind = file_type(entry.metadata.kind)?;
            if self
                .nodes
                .get(&target)
                .or_else(|| pending.get(&target))
                .is_some_and(|previous| *previous != identity)
            {
                return Err(corrupt(
                    "ZPL mount object has conflicting native identities",
                ));
            }
            if !self.nodes.contains_key(&target) {
                pending.insert(target, identity);
                if self.nodes.len() + pending.len() > MAX_NODES {
                    return Err(unsupported("ZPL mount exceeds 131072 object identities"));
                }
            }
            rows.push(DirEntry {
                ino: target,
                offset: rows.len() as u64 + 1,
                kind,
                name: entry.name,
            });
        }
        // Validate the entire native directory and all identities before any
        // part becomes visible. Failed reads cannot publish a partial listing.
        checkpoint(cx)?;
        self.nodes.extend(pending);
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

struct State {
    head: ViewState,
    snapshot_names: Option<Vec<Vec<u8>>>,
    snapshots: BTreeMap<u16, ViewState>,
}

impl State {
    fn ensure_snapshot_names(&mut self, cx: &Cx) -> Result<&[Vec<u8>]> {
        if !self.head.view.has_snapshot_dir() {
            return Err(FfsError::NotFound("ZPL snapshot control directory".into()));
        }
        if self.snapshot_names.is_none() {
            let snaps = self.head.view.snapshots(cx)?;
            self.snapshot_names = Some(snaps.into_iter().map(|s| s.name).collect());
        }
        Ok(self.snapshot_names.as_deref().unwrap_or(&[]))
    }

    fn snapshot_view(&mut self, cx: &Cx, snap_idx: u16) -> Result<&mut ViewState> {
        checkpoint(cx)?;
        if !self.snapshots.contains_key(&snap_idx) {
            let names = self.ensure_snapshot_names(cx)?;
            let name = names
                .get(usize::from(snap_idx.saturating_sub(1)))
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
                snapshot_names: None,
                snapshots: BTreeMap::new(),
            }),
            uid,
            gid,
        })
    }

    fn state(&self, cx: &Cx) -> Result<MutexGuard<'_, State>> {
        checkpoint(cx)?;
        let state = self
            .state
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("ZPL mount state poisoned")))?;
        checkpoint(cx)?;
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
            let count = state.ensure_snapshot_names(cx)?.len();
            let nlink = u32::try_from(2 + count).unwrap_or(u32::MAX);
            return self.ctl_attributes(cx, state, ZFS_SNAPDIR_INO, nlink);
        }
        let view_state = state.view_for_ino(cx, ino)?;
        let (metadata, allocated) = view_state.metadata(cx, ino)?;
        let kind = file_type(metadata.kind)?;
        let perm = match kind {
            FileType::Directory => 0o555,
            FileType::Symlink => 0o777,
            _ => 0o444,
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
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            generation: metadata.generation,
        })
    }
}

impl FsOps for ZfsFs {
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
                    let names = state.ensure_snapshot_names(cx)?;
                    let index = names
                        .binary_search_by(|candidate| candidate.as_slice().cmp(name))
                        .map_err(|_| FfsError::NotFound("ZFS named snapshot".into()))?;
                    let snap_idx = u16::try_from(index + 1)
                        .map_err(|_| unsupported("snapshot index overflow"))?;
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
            let rows = vec![
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
            let names = state.ensure_snapshot_names(cx)?.to_vec();
            let mut rows = Vec::with_capacity(2 + names.len());
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
            for (idx, name) in names.into_iter().enumerate() {
                let snap_idx =
                    u16::try_from(idx + 1).map_err(|_| unsupported("snapshot index overflow"))?;
                rows.push(DirEntry {
                    ino: snap_root_ino(snap_idx),
                    offset: rows.len() as u64 + 1,
                    kind: FileType::Directory,
                    name,
                });
            }
            let start = rows.partition_point(|row| row.offset <= offset);
            let end = rows.len().min(start + PAGE_ENTRIES);
            checkpoint(cx)?;
            return Ok(ReaddirPage::new(rows[start..end].to_vec())
                .with_end_cookie(Some(rows.len() as u64)));
        }
        let rows = state.view_for_ino(cx, ino)?.directory(cx, ino)?;
        let start = rows.partition_point(|row| row.offset <= offset);
        let end = rows.len().min(start + PAGE_ENTRIES);
        checkpoint(cx)?;
        Ok(ReaddirPage::new(rows[start..end].to_vec()).with_end_cookie(Some(rows.len() as u64)))
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

    fn open(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        flags: i32,
    ) -> Result<(u64, u32)> {
        checkpoint(cx)?;
        if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & (libc::O_TRUNC | libc::O_CREAT) != 0
        {
            return Err(FfsError::ReadOnly);
        }
        if ino == ZFS_CTL_INO || ino == ZFS_SNAPDIR_INO {
            return Err(FfsError::IsDirectory);
        }
        let mut state = self.state(cx)?;
        let kind = state.view_for_ino(cx, ino)?.metadata(cx, ino)?.0.kind;
        match kind {
            Kind::Directory => Err(FfsError::IsDirectory),
            Kind::Regular => Ok((0, 0)),
            _ => Err(unsupported("ZPL open requires a regular file")),
        }
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

    fn fsync(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        _fh: u64,
        _datasync: bool,
    ) -> Result<()> {
        let mut state = self.state(cx)?;
        if ino != ZFS_CTL_INO && ino != ZFS_SNAPDIR_INO {
            state.view_for_ino(cx, ino)?.metadata(cx, ino)?;
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

    fn statfs(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> Result<ffs_core::FsStat> {
        let mut state = self.state(cx)?;
        if ino == ZFS_CTL_INO || ino == ZFS_SNAPDIR_INO {
            if !state.head.view.has_snapshot_dir() {
                return Err(FfsError::NotFound("ZPL control directory".into()));
            }
            checkpoint(cx)?;
            return Ok(state.head.view.statfs_info());
        }
        let view_state = state.view_for_ino(cx, ino)?;
        view_state.metadata(cx, ino)?;
        checkpoint(cx)?;
        Ok(view_state.view.statfs_info())
    }

    fn lseek(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        whence: SeekWhence,
    ) -> Result<u64> {
        if ino == ZFS_CTL_INO || ino == ZFS_SNAPDIR_INO {
            return Err(unsupported("ZPL seek requires a regular file"));
        }
        let mut state = self.state(cx)?;
        let (metadata, _) = state.view_for_ino(cx, ino)?.metadata(cx, ino)?;
        if metadata.kind != Kind::Regular {
            return Err(unsupported("ZPL seek requires a regular file"));
        }
        if offset >= metadata.size {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(libc::ENXIO)));
        }
        // A conservative legal sparse-file projection. Compressed allocation
        // and embedded payload boundaries do not define logical file holes.
        match whence {
            SeekWhence::Data => Ok(offset),
            SeekWhence::Hole => Ok(metadata.size),
            _ => Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::EINVAL,
            ))),
        }
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
