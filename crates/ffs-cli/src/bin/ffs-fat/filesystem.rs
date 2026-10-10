//! Read-only FsOps adapter for the same native reader used by inspect/ls/cat.
//! Slot-based IDs are safe only for this immutable, mount-lifetime namespace;
//! they are deliberately not a promise of FAT write or export-stable handles.

use crate::reader::{Directory, Entry, FatVolume, FileChain, MAX_CHAIN_CLUSTERS, checkpoint};
use asupersync::Cx;
use ffs_core::{
    DirEntry, FileType, FsOps, FsStat, InodeAttr, ReaddirPage, RequestScope, SeekWhence,
};
use ffs_error::{FfsError, Result};
use ffs_ondisk::fat::FatKind;
use ffs_types::InodeNumber;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const ROOT: InodeNumber = InodeNumber(1);
const MAX_NODES: usize = 131_072;
const MAX_CACHED_CHAINS: usize = 1024;
const DIRECTORY_PAGE: usize = 256;

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

#[derive(Default)]
struct State {
    nodes: BTreeMap<InodeNumber, Node>,
    chains: BTreeMap<InodeNumber, Arc<FileChain>>,
    cached_clusters: usize,
    free_clusters: Option<u64>,
}

pub struct FatFs {
    volume: FatVolume,
    state: Mutex<State>,
    uid: u32,
    gid: u32,
}

impl FatFs {
    pub fn new(cx: &Cx, volume: FatVolume, uid: u32, gid: u32) -> Result<Self> {
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
        })
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

    fn register(&self, cx: &Cx, parent: InodeNumber, entry: Entry) -> Result<InodeNumber> {
        checkpoint(cx)?;
        let ino = InodeNumber(entry.offset / 32 + 2);
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
        if let Some(existing) = state.nodes.get(&ino) {
            if existing.parent != parent
                || existing
                    .entry
                    .as_ref()
                    .is_none_or(|old| old.native != entry.native)
            {
                return Err(FfsError::Corruption {
                    block: entry.offset / 512,
                    detail: "FAT namespace identity changed or is cross-linked".into(),
                });
            }
            return Ok(ino);
        }
        if state.nodes.len() >= MAX_NODES {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::ENOMEM,
            )));
        }
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

    /// Reject display/short-alias collisions before publishing a listing. ASCII
    /// folding is explicit; no host locale or guessed Unicode normalization.
    fn checked_names(entries: &[Entry]) -> Result<Vec<String>> {
        let mut owners = BTreeMap::new();
        let mut names = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            let name = entry.name()?;
            let alias = entry.native.ascii_short_name();
            for candidate in std::iter::once(name.as_str()).chain(alias.as_deref()) {
                if owners
                    .insert(candidate.to_ascii_lowercase(), index)
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
        let mtime = node.entry.as_ref().map_or(Ok(UNIX_EPOCH), |entry| {
            fat_wall_time(entry.native.modified_date, entry.native.modified_time)
        })?;
        checkpoint(cx)?;
        Ok(InodeAttr {
            ino,
            size,
            blocks,
            atime: UNIX_EPOCH,
            mtime,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind,
            perm: if kind == FileType::Directory {
                0o555
            } else {
                0o444
            },
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
        if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & (libc::O_TRUNC | libc::O_CREAT) != 0
        {
            return Err(FfsError::ReadOnly);
        }
        let node = self.node(cx, ino)?;
        let entry = node.entry.as_ref().ok_or(FfsError::IsDirectory)?;
        self.chain(cx, ino, entry)?;
        Ok((0, 0))
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

/// FAT stores a wall clock without a timezone. Project its modification fields
/// onto UTC deterministically; do not guess the machine that wrote the image's
/// timezone. Unavailable access/change/creation timestamps remain epoch zero.
fn fat_wall_time(date: u16, time: u16) -> Result<SystemTime> {
    if date == 0 && time == 0 {
        return Ok(UNIX_EPOCH);
    }
    let year = 1980 + u64::from(date >> 9);
    let month = usize::from((date >> 5) & 15);
    let day = u64::from(date & 31);
    let hour = u64::from(time >> 11);
    let minute = u64::from((time >> 5) & 63);
    let second = u64::from(time & 31) * 2;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let months = [
        31_u64,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month)
        || day == 0
        || day > months[month - 1]
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(FfsError::Corruption {
            block: 0,
            detail: "invalid FAT modification timestamp".into(),
        });
    }
    let before = |year: u64| {
        let last = year - 1;
        365 * last + last / 4 - last / 100 + last / 400
    };
    let days = before(year) - before(1970) + months[..month - 1].iter().sum::<u64>() + day - 1;
    UNIX_EPOCH
        .checked_add(Duration::from_secs(
            days * 86_400 + hour * 3600 + minute * 60 + second,
        ))
        .ok_or_else(|| FfsError::Format("FAT timestamp is outside host SystemTime range".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fat_time_uses_calendar_rules_and_preserves_two_second_precision() {
        let date = ((2024 - 1980) << 9) | (2 << 5) | 29;
        let time = (12 << 11) | (34 << 5) | 28;
        assert_eq!(
            fat_wall_time(date, time)
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1_709_210_096
        );
        assert!(fat_wall_time(((2023 - 1980) << 9) | (2 << 5) | 29, 0).is_err());
        assert!(fat_wall_time((1 << 5) | 1, 31).is_err());
        assert!(fat_wall_time(1, 0).is_err());
        assert_eq!(fat_wall_time(0, 0).unwrap(), UNIX_EPOCH);
    }
}
