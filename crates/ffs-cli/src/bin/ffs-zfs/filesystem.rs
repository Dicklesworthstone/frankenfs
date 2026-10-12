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
const MAX_NODES: usize = 131_072;
const MAX_DIRECTORY_CACHE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CACHED_DIRECTORIES: usize = 32;
const PAGE_ENTRIES: usize = 256;

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

struct State {
    view: Zpl,
    nodes: BTreeMap<InodeNumber, Identity>,
    directories: VecDeque<CachedDirectory>,
    directory_bytes: usize,
}

impl State {
    fn inode(&self, object: u64) -> Result<InodeNumber> {
        if object == self.view.root {
            return Ok(ROOT);
        }
        if object == 0 || object >= 1 << 48 {
            return Err(corrupt("invalid ZPL mount object number"));
        }
        Ok(InodeNumber(object + 1))
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
        let parent = self.inode(metadata.parent)?;
        if self.metadata(cx, parent)?.0.kind != Kind::Directory {
            return Err(corrupt("ZPL mount directory parent is not a directory"));
        }
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

pub struct ZfsFs {
    state: Mutex<State>,
    uid: u32,
    gid: u32,
}

impl ZfsFs {
    pub fn new(cx: &Cx, mut view: Zpl, uid: u32, gid: u32) -> Result<Self> {
        checkpoint(cx)?;
        let (root, _) = view.stat(cx, view.root)?;
        let identity = Identity::from_metadata(view.root, &root);
        let mut state = State {
            view,
            nodes: BTreeMap::from([(ROOT, identity)]),
            directories: VecDeque::new(),
            directory_bytes: 0,
        };
        // A bad root is refused before FUSE INIT, including corrupt children.
        state.directory(cx, ROOT)?;
        Ok(Self {
            state: Mutex::new(state),
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

    fn attributes(&self, cx: &Cx, state: &mut State, ino: InodeNumber) -> Result<InodeAttr> {
        let (metadata, allocated) = state.metadata(cx, ino)?;
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
        let rows = state.directory(cx, parent)?;
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
        let rows = self.state(cx)?.directory(cx, ino)?;
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
        let mut state = self.state(cx)?;
        state.metadata(cx, ino)?;
        let object = state.nodes[&ino].object;
        state.view.read(cx, object, offset, size as usize)
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
        let kind = self.state(cx)?.metadata(cx, ino)?.0.kind;
        match kind {
            Kind::Directory => Err(FfsError::IsDirectory),
            Kind::Regular => Ok((0, 0)),
            _ => Err(unsupported("ZPL open requires a regular file")),
        }
    }

    fn readlink(&self, cx: &Cx, _scope: &mut RequestScope, ino: InodeNumber) -> Result<Vec<u8>> {
        let mut state = self.state(cx)?;
        if state.metadata(cx, ino)?.0.kind != Kind::Symlink {
            return Err(FfsError::Format("ZPL inode is not a symbolic link".into()));
        }
        let object = state.nodes[&ino].object;
        state.view.readlink(cx, object)
    }

    fn listxattr(&self, cx: &Cx, ino: InodeNumber) -> Result<Vec<String>> {
        let mut state = self.state(cx)?;
        state.metadata(cx, ino)?;
        let object = state.nodes[&ino].object;
        state.view.listxattr(cx, object)
    }

    fn getxattr(&self, cx: &Cx, ino: InodeNumber, name: &str) -> Result<Option<Vec<u8>>> {
        let mut state = self.state(cx)?;
        state.metadata(cx, ino)?;
        let object = state.nodes[&ino].object;
        state.view.getxattr(cx, object, name)
    }

    fn fsync(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        _fh: u64,
        _datasync: bool,
    ) -> Result<()> {
        self.state(cx)?.metadata(cx, ino)?;
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
        if self.state(cx)?.metadata(cx, ino)?.0.kind != Kind::Directory {
            return Err(FfsError::NotDirectory);
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
        let (metadata, _) = self.state(cx)?.metadata(cx, ino)?;
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
