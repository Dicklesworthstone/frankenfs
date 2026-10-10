//! Read-only FsOps for an immutable NTFS image. Native file references, not
//! pathnames, identify nodes, so DOS aliases and hard links share one inode.
//! Permissions are an explicit host projection, not an interpretation of ACLs.

use super::{
    Cx, DATA, FfsError, NtfsFileRecord, NtfsReference, NtfsValue, NtfsVolume, Result, Stream,
    checkpoint, corrupt, parse, unsupported,
};
use ffs_core::{
    DirEntry, FileType, FsOps, FsStat, InodeAttr, ReaddirPage, RequestScope, SeekWhence,
};
use ffs_ondisk::ntfs::index::NtfsFileName;
use ffs_types::InodeNumber;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const ROOT: InodeNumber = InodeNumber(1);
const I30: &[u16] = &[36, 73, 51, 48];
const PAGE_ENTRIES: usize = 256;
const UNIX_FILETIME: u64 = 116_444_736_000_000_000;
const TICKS_PER_SECOND: u64 = 10_000_000;
const MAX_CACHED_ATTRIBUTES: usize = 4096;
const MAX_CACHED_STREAMS: usize = 8;
const MAX_CACHED_DIRECTORIES: usize = 64;
const DIRECTORY_CACHE_BYTES: usize = 16 * 1024 * 1024;

struct DirectorySnapshot {
    rows: Vec<DirEntry>,
    exact: Vec<(Vec<u16>, InodeNumber)>,
    folded: Vec<(Vec<u16>, Option<InodeNumber>)>,
}

impl DirectorySnapshot {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.rows.capacity() * std::mem::size_of::<DirEntry>()
            + self
                .rows
                .iter()
                .map(|entry| entry.name.capacity())
                .sum::<usize>()
            + self.exact.capacity() * std::mem::size_of::<(Vec<u16>, InodeNumber)>()
            + self
                .exact
                .iter()
                .map(|(name, _)| name.capacity() * 2)
                .sum::<usize>()
            + self.folded.capacity() * std::mem::size_of::<(Vec<u16>, Option<InodeNumber>)>()
            + self
                .folded
                .iter()
                .map(|(name, _)| name.capacity() * 2)
                .sum::<usize>()
    }
}

#[derive(Default)]
struct Cache {
    attributes: BTreeMap<InodeNumber, InodeAttr>,
    streams: BTreeMap<InodeNumber, Arc<Stream>>,
    directories: BTreeMap<InodeNumber, Arc<DirectorySnapshot>>,
    directory_bytes: usize,
    statistics: Option<FsStat>,
}

pub struct NtfsFs {
    volume: NtfsVolume,
    root: NtfsReference,
    upcase: Vec<u16>,
    uid: u32,
    gid: u32,
    cache: Mutex<Cache>,
}

impl NtfsFs {
    pub fn new(cx: &Cx, volume: NtfsVolume, uid: u32, gid: u32) -> Result<Self> {
        checkpoint(cx)?;
        let record = volume.record(cx, 5, None)?;
        if !record.is_directory() {
            return Err(corrupt(0, "NTFS root is not a directory"));
        }
        let upcase_record = volume.record(cx, 10, None)?;
        let stream = volume.data_stream(cx, &upcase_record, &[])?;
        if stream.size != 131_072 || stream.initialized != stream.size {
            return Err(corrupt(0, "invalid NTFS UpCase initialized length"));
        }
        let bytes = volume.read(cx, &stream, 0, 131_072)?;
        let upcase: Vec<_> = bytes
            .chunks_exact(2)
            .map(|word| u16::from_le_bytes([word[0], word[1]]))
            .collect();
        for (index, &upper) in upcase.iter().enumerate() {
            if index.is_multiple_of(1024) {
                checkpoint(cx)?;
            }
            if upcase[usize::from(upper)] != upper {
                return Err(corrupt(0, "non-idempotent NTFS UpCase table"));
            }
        }
        for lower in b'a'..=b'z' {
            if upcase[usize::from(lower)] != u16::from(lower.to_ascii_uppercase()) {
                return Err(corrupt(0, "invalid NTFS UpCase ASCII mapping"));
            }
        }
        let fs = Self {
            root: reference(&record),
            volume,
            upcase,
            uid,
            gid,
            cache: Mutex::new(Cache::default()),
        };
        fs.describe(cx, ROOT)?;
        fs.directory(cx, ROOT)?;
        checkpoint(cx)?;
        Ok(fs)
    }

    fn cache(&self) -> Result<MutexGuard<'_, Cache>> {
        self.cache
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("NTFS mount cache poisoned")))
    }

    fn inode(&self, reference: NtfsReference) -> Result<InodeNumber> {
        if reference == self.root {
            return Ok(ROOT);
        }
        if reference.record == 5
            || reference.record > u64::from(u32::MAX)
            || reference.sequence == 0
        {
            return Err(corrupt(0, "invalid NTFS mount file reference"));
        }
        // The reader admits u32 record numbers. The sequence occupies the next
        // 16 bits; +2 reserves zero and FUSE's mandatory root node one.
        Ok(InodeNumber(
            ((u64::from(reference.sequence) << 32) | reference.record) + 2,
        ))
    }

    fn record(&self, cx: &Cx, ino: InodeNumber) -> Result<NtfsFileRecord> {
        checkpoint(cx)?;
        let reference = if ino == ROOT {
            self.root
        } else {
            let encoded = ino
                .0
                .checked_sub(2)
                .ok_or_else(|| FfsError::NotFound(format!("NTFS inode {}", ino.0)))?;
            let sequence = u16::try_from(encoded >> 32)
                .map_err(|_| corrupt(0, "NTFS inode exceeds reference encoding"))?;
            let reference = NtfsReference {
                record: encoded & 0xFFFF_FFFF,
                sequence,
            };
            if sequence == 0 || reference.record == 5 {
                return Err(corrupt(0, "noncanonical NTFS mount inode"));
            }
            reference
        };
        self.volume
            .record(cx, reference.record, Some(reference.sequence))
    }

    fn parent_reference(&self, cx: &Cx, record: &NtfsFileRecord) -> Result<NtfsReference> {
        if !record.is_directory() {
            return Err(FfsError::NotDirectory);
        }
        if reference(record) == self.root {
            return Ok(self.root);
        }
        let catalog = self.volume.attributes(cx, record)?;
        let mut parent = None;
        for attr in catalog.all()? {
            checkpoint(cx)?;
            if attr.kind == 0xC0 {
                return Err(unsupported("NTFS reparse directory is not mounted"));
            }
            if attr.kind != 0x30 {
                continue;
            }
            if attr.flags != 0 {
                return Err(corrupt(0, "transformed NTFS FILE_NAME"));
            }
            let NtfsValue::Resident(value) = attr.value else {
                return Err(corrupt(0, "nonresident NTFS FILE_NAME"));
            };
            let next = NtfsFileName::parse(value)
                .map_err(|error| parse(&error))?
                .parent;
            if parent.is_some_and(|old| old != next) {
                return Err(corrupt(0, "NTFS directory has multiple native parents"));
            }
            parent = Some(next);
        }
        parent.ok_or_else(|| corrupt(0, "NTFS directory has no native parent"))
    }

    fn parent(&self, cx: &Cx, record: &NtfsFileRecord) -> Result<InodeNumber> {
        let first = self.parent_reference(cx, record)?;
        let mut current = first;
        let mut seen = BTreeSet::from([u64::from(record.number)]);
        for _ in 0..256 {
            checkpoint(cx)?;
            if current == self.root {
                return self.inode(first);
            }
            if !seen.insert(current.record) {
                return Err(corrupt(0, "NTFS directory ancestry is cyclic"));
            }
            let ancestor = self
                .volume
                .record(cx, current.record, Some(current.sequence))?;
            current = self.parent_reference(cx, &ancestor)?;
        }
        Err(unsupported("NTFS directory ancestry exceeds 256 levels"))
    }

    fn describe(&self, cx: &Cx, ino: InodeNumber) -> Result<InodeAttr> {
        checkpoint(cx)?;
        let hit = self.cache()?.attributes.get(&ino).cloned();
        if let Some(hit) = hit {
            checkpoint(cx)?;
            return Ok(hit);
        }
        let attr = self.describe_uncached(cx, ino)?;
        checkpoint(cx)?;
        let mut cache = self.cache()?;
        if cache.attributes.len() >= MAX_CACHED_ATTRIBUTES {
            cache.attributes.pop_first();
        }
        cache.attributes.insert(ino, attr.clone());
        drop(cache);
        checkpoint(cx)?;
        Ok(attr)
    }

    fn describe_uncached(&self, cx: &Cx, ino: InodeNumber) -> Result<InodeAttr> {
        let record = self.record(cx, ino)?;
        let catalog = self.volume.attributes(cx, &record)?;
        let all = catalog.all()?;
        if all.iter().any(|attr| attr.kind == 0xC0) {
            return Err(unsupported("NTFS reparse objects are not mounted"));
        }
        let standard = catalog.select(&self.volume.geometry, 0x10, &[])?;
        if !standard.resident() || !matches!(standard.size, 48 | 72) {
            return Err(corrupt(0, "invalid resident NTFS STANDARD_INFORMATION"));
        }
        let times = self.volume.read(cx, &standard, 0, 72)?;
        let flags = u32::from_le_bytes(
            times[32..36]
                .try_into()
                .map_err(|_| corrupt(0, "truncated NTFS file attributes"))?,
        );
        if flags & 0x400 != 0 {
            return Err(unsupported("NTFS reparse file attribute is not mounted"));
        }
        if flags & 0x4000 != 0 {
            return Err(unsupported("NTFS encrypted file is not mounted"));
        }
        let (kind, size, blocks) = if record.is_directory() {
            self.parent(cx, &record)?;
            // Directory logical size is a host projection; count only native
            // external index allocation, never manufacture file DATA bytes.
            let allocation = if all.iter().any(|attr| attr.kind == 0xA0 && attr.name == I30) {
                Some(catalog.select(&self.volume.geometry, 0xA0, I30)?)
            } else {
                None
            };
            (
                FileType::Directory,
                0,
                allocation.map_or(0, |stream| stream.allocated.div_ceil(512)),
            )
        } else {
            let stream = catalog.select(&self.volume.geometry, DATA, &[])?;
            let blocks = if stream.resident() {
                0
            } else {
                stream.allocated.div_ceil(512)
            };
            (FileType::RegularFile, stream.size, blocks)
        };
        if record.hard_links == 0 {
            return Err(corrupt(0, "live NTFS base record has zero links"));
        }
        let time = |offset| -> Result<SystemTime> {
            let raw = times
                .get(offset..offset + 8)
                .ok_or_else(|| corrupt(0, "short NTFS timestamp"))?;
            filetime(u64::from_le_bytes(
                raw.try_into()
                    .map_err(|_| corrupt(0, "short NTFS timestamp"))?,
            ))
        };
        checkpoint(cx)?;
        Ok(InodeAttr {
            ino,
            size,
            blocks,
            crtime: time(0)?,
            mtime: time(8)?,
            ctime: time(16)?,
            atime: time(24)?,
            kind,
            perm: if kind == FileType::Directory {
                0o555
            } else {
                0o444
            },
            nlink: u32::from(record.hard_links),
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: self.volume.geometry.cluster_bytes(),
            generation: u64::from(record.sequence),
        })
    }

    fn directory(&self, cx: &Cx, ino: InodeNumber) -> Result<Arc<DirectorySnapshot>> {
        checkpoint(cx)?;
        let hit = self.cache()?.directories.get(&ino).cloned();
        if let Some(hit) = hit {
            checkpoint(cx)?;
            return Ok(hit);
        }
        // Parser/device work is outside the cache lock. Only a fully validated
        // snapshot can be published; errors and partial trees are never cached.
        let snapshot = Arc::new(self.directory_uncached(cx, ino)?);
        let bytes = snapshot.retained_bytes();
        checkpoint(cx)?;
        if bytes <= DIRECTORY_CACHE_BYTES {
            let mut cache = self.cache()?;
            if let Some(existing) = cache.directories.get(&ino).cloned() {
                drop(cache);
                checkpoint(cx)?;
                return Ok(existing);
            }
            while cache.directory_bytes + bytes > DIRECTORY_CACHE_BYTES
                || cache.directories.len() >= MAX_CACHED_DIRECTORIES
            {
                let Some((_, old)) = cache.directories.pop_first() else {
                    break;
                };
                cache.directory_bytes -= old.retained_bytes();
            }
            cache.directory_bytes += bytes;
            cache.directories.insert(ino, Arc::clone(&snapshot));
        }
        checkpoint(cx)?;
        Ok(snapshot)
    }

    fn directory_uncached(&self, cx: &Cx, ino: InodeNumber) -> Result<DirectorySnapshot> {
        let record = self.record(cx, ino)?;
        let parent = self.parent(cx, &record)?;
        let native = self.volume.list_directory(cx, &record)?;
        let mut entries = vec![
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
        let mut names = BTreeMap::new();
        let mut exact = BTreeMap::new();
        let mut folded = BTreeMap::new();
        for entry in native {
            checkpoint(cx)?;
            let name = String::from_utf16(&entry.filename.name)
                .map_err(|_| unsupported("NTFS name cannot be represented losslessly as UTF-8"))?;
            if name.len() > 255 {
                return Err(FfsError::NameTooLong);
            }
            let target = self.inode(entry.reference)?;
            exact.insert(entry.filename.name.clone(), target);
            if entry.filename.namespace != 0 {
                let key: Vec<_> = entry
                    .filename
                    .name
                    .iter()
                    .map(|unit| self.upcase[usize::from(*unit)])
                    .collect();
                let value = folded.entry(key).or_insert(Some(target));
                if *value != Some(target) {
                    *value = None;
                }
            }
            if let Some(old) = names.insert(name.clone(), target) {
                if old != target {
                    return Err(corrupt(0, "NTFS mount name collision"));
                }
                continue;
            }
            if entry.directory {
                if target == ino || target == ROOT {
                    return Err(corrupt(
                        0,
                        "NTFS directory entry aliases itself or the mount root",
                    ));
                }
                let child = self.volume.record(
                    cx,
                    entry.reference.record,
                    Some(entry.reference.sequence),
                )?;
                if self.parent(cx, &child)? != ino {
                    return Err(corrupt(0, "NTFS directory parent differs from its listing"));
                }
            }
            entries.push(DirEntry {
                ino: target,
                offset: entries.len() as u64 + 1,
                kind: if entry.directory {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                },
                name: name.into_bytes(),
            });
        }
        checkpoint(cx)?;
        Ok(DirectorySnapshot {
            rows: entries,
            exact: exact.into_iter().collect(),
            folded: folded.into_iter().collect(),
        })
    }

    fn stream(&self, cx: &Cx, ino: InodeNumber) -> Result<Arc<Stream>> {
        checkpoint(cx)?;
        let hit = self.cache()?.streams.get(&ino).cloned();
        if let Some(hit) = hit {
            checkpoint(cx)?;
            return Ok(hit);
        }
        // A caller need not have issued LOOKUP first. Enforce metadata-side
        // reparse/EFS admission on OPEN and READ as well as GETATTR.
        self.describe(cx, ino)?;
        let record = self.record(cx, ino)?;
        let catalog = self.volume.attributes(cx, &record)?;
        if record.is_directory() {
            return Err(FfsError::IsDirectory);
        }
        if catalog.all()?.iter().any(|attr| attr.kind == 0xC0) {
            return Err(unsupported("NTFS reparse data is not mounted"));
        }
        let stream = Arc::new(catalog.select(&self.volume.geometry, DATA, &[])?);
        checkpoint(cx)?;
        let mut cache = self.cache()?;
        if let Some(existing) = cache.streams.get(&ino).cloned() {
            drop(cache);
            checkpoint(cx)?;
            return Ok(existing);
        }
        if cache.streams.len() >= MAX_CACHED_STREAMS {
            cache.streams.pop_first();
        }
        cache.streams.insert(ino, Arc::clone(&stream));
        drop(cache);
        checkpoint(cx)?;
        Ok(stream)
    }

    fn count_free(&self, cx: &Cx, bitmap: &Stream, bits: u64) -> Result<u64> {
        let bytes = bits.div_ceil(8);
        if bitmap.initialized < bytes || bitmap.size < bytes {
            return Err(corrupt(
                0,
                "NTFS allocation bitmap does not cover its namespace",
            ));
        }
        match &bitmap.storage {
            super::Storage::Compressed(_) => {
                return Err(corrupt(0, "compressed NTFS allocation bitmap"));
            }
            super::Storage::Mapped(runs) => {
                let clusters = bytes.div_ceil(u64::from(self.volume.geometry.cluster_bytes()));
                if runs
                    .iter()
                    .any(|run| run.vcn < clusters && run.lcn.is_none())
                {
                    return Err(corrupt(0, "sparse hole in NTFS allocation bitmap"));
                }
            }
            super::Storage::Resident(_) => {}
        }
        let mut offset = 0;
        let mut used = 0_u64;
        while offset < bytes {
            checkpoint(cx)?;
            let length = (bytes - offset).min(65_536) as usize;
            let data = self.volume.read(cx, bitmap, offset, length)?;
            if data.len() != length {
                return Err(corrupt(0, "short NTFS allocation bitmap"));
            }
            for (index, &value) in data.iter().enumerate() {
                if index.is_multiple_of(4096) {
                    checkpoint(cx)?;
                }
                let remaining = bits - (offset + index as u64) * 8;
                let mask = if remaining >= 8 {
                    u8::MAX
                } else {
                    (1_u8 << remaining) - 1
                };
                used += u64::from((value & mask).count_ones());
            }
            offset += length as u64;
        }
        checkpoint(cx)?;
        Ok(bits - used)
    }
}

impl FsOps for NtfsFs {
    fn getattr(&self, cx: &Cx, _scope: &mut RequestScope, ino: InodeNumber) -> Result<InodeAttr> {
        self.describe(cx, ino)
    }

    fn lookup(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> Result<InodeAttr> {
        if self.describe(cx, parent)?.kind != FileType::Directory {
            return Err(FfsError::NotDirectory);
        }
        if name == OsStr::new(".") {
            return self.describe(cx, parent);
        }
        let directory = self.directory(cx, parent)?;
        if name == OsStr::new("..") {
            return self.describe(cx, directory.rows[1].ino);
        }
        let name = name
            .to_str()
            .ok_or_else(|| unsupported("NTFS lookup requires lossless UTF-8"))?;
        if name.is_empty() || name.contains(['/', '\\', '\0']) {
            return Err(FfsError::Format("invalid NTFS path component".into()));
        }
        if name.len() > 255 {
            return Err(FfsError::NameTooLong);
        }
        let units: Vec<u16> = name.encode_utf16().collect();
        let target = if let Ok(index) = directory.exact.binary_search_by(|(key, _)| key.cmp(&units))
        {
            directory.exact[index].1
        } else {
            let folded: Vec<_> = units
                .iter()
                .map(|unit| self.upcase[usize::from(*unit)])
                .collect();
            let index = directory
                .folded
                .binary_search_by(|(key, _)| key.cmp(&folded))
                .map_err(|_| FfsError::NotFound(format!("NTFS name {name}")))?;
            directory.folded[index]
                .1
                .ok_or_else(|| corrupt(0, "ambiguous NTFS folded mount name"))?
        };
        self.describe(cx, target)
    }

    fn readdir(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
    ) -> Result<ReaddirPage> {
        let snapshot = self.directory(cx, ino)?;
        let entries = &snapshot.rows;
        let end = entries.len() as u64;
        let start = entries.partition_point(|entry| entry.offset <= offset);
        let page = entries[start..entries.len().min(start + PAGE_ENTRIES)].to_vec();
        checkpoint(cx)?;
        Ok(ReaddirPage::new(page).with_end_cookie(Some(end)))
    }

    fn read(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>> {
        let stream = self.stream(cx, ino)?;
        self.volume.read(cx, &stream, offset, size as usize)
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
        self.stream(cx, ino)?;
        Ok((0, 0))
    }

    fn readlink(&self, cx: &Cx, _scope: &mut RequestScope, ino: InodeNumber) -> Result<Vec<u8>> {
        self.record(cx, ino)?;
        Err(unsupported("NTFS reparse translation is not implemented"))
    }

    fn statfs(&self, cx: &Cx, _scope: &mut RequestScope, ino: InodeNumber) -> Result<FsStat> {
        self.describe(cx, ino)?;
        let hit = self.cache()?.statistics.clone();
        if let Some(hit) = hit {
            checkpoint(cx)?;
            return Ok(hit);
        }
        let record = self.volume.record(cx, 6, None)?;
        let bitmap = self.volume.select_stream(cx, &record, DATA, &[])?;
        let blocks = self.volume.geometry.cluster_count();
        let free = self.count_free(cx, &bitmap, blocks)?;
        let record = self.volume.record(cx, 0, None)?;
        let bitmap = self.volume.select_stream(cx, &record, 0xB0, &[])?;
        let files = self.volume.record_count();
        let files_free = self.count_free(cx, &bitmap, files)?;
        let statistics = FsStat {
            blocks,
            blocks_free: free,
            blocks_available: free,
            files,
            files_free,
            block_size: self.volume.geometry.cluster_bytes(),
            fragment_size: self.volume.geometry.cluster_bytes(),
            name_max: 255,
        };
        checkpoint(cx)?;
        self.cache()?.statistics = Some(statistics.clone());
        checkpoint(cx)?;
        Ok(statistics)
    }

    fn fsync(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        _fh: u64,
        _datasync: bool,
    ) -> Result<()> {
        self.record(cx, ino)?;
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
        let record = self.record(cx, ino)?;
        if !record.is_directory() {
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
        let stream = self.stream(cx, ino)?;
        if offset >= stream.size {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(libc::ENXIO)));
        }
        // Conservative legal SEEK_DATA/HOLE projection, also for compressed
        // units: compression padding is not a logical hole in the file.
        match whence {
            SeekWhence::Data => Ok(offset),
            SeekWhence::Hole => Ok(stream.size),
            _ => Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::EINVAL,
            ))),
        }
    }
}

fn reference(record: &NtfsFileRecord) -> NtfsReference {
    NtfsReference {
        record: u64::from(record.number),
        sequence: record.sequence,
    }
}

fn filetime(ticks: u64) -> Result<SystemTime> {
    if ticks > i64::MAX as u64 {
        return Err(corrupt(0, "negative NTFS timestamp"));
    }
    let delta = ticks.abs_diff(UNIX_FILETIME);
    let duration = Duration::new(
        delta / TICKS_PER_SECOND,
        ((delta % TICKS_PER_SECOND) * 100) as u32,
    );
    let time = if ticks >= UNIX_FILETIME {
        UNIX_EPOCH.checked_add(duration)
    } else {
        UNIX_EPOCH.checked_sub(duration)
    };
    time.ok_or_else(|| unsupported("NTFS timestamp is outside host SystemTime range"))
}

#[cfg(test)]
mod tests;
