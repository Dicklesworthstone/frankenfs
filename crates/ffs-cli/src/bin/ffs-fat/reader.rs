//! Native FAT image reads for the experimental `ffs-fat` companion CLI.
//!
//! The backing must remain offline/immutable. Our shared advisory lock excludes
//! cooperating exclusive users, not kernel mounts or unrelated writers. No
//! method in this module writes, replays, repairs, or marks an image dirty.

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::fat::{FatDirEntry, FatDirectoryDecoder, FatEntry, FatGeometry, FatKind};
use ffs_types::{ByteOffset, ParseError};
use std::collections::BTreeSet;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

const MAX_DIRECTORY_SLOTS: usize = 65_536;
pub const MAX_CHAIN_CLUSTERS: usize = 8_388_608; // At most 32 MiB of cluster addresses.
const MAX_READ_BYTES: usize = 16 * 1024 * 1024;

pub fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

fn parse_error(error: ParseError) -> FfsError {
    FfsError::Format(error.to_string())
}

fn corrupt(offset: u64, detail: impl Into<String>) -> FfsError {
    FfsError::Corruption {
        block: offset / 512,
        detail: detail.into(),
    }
}

fn allocate(len: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|error| FfsError::Format(format!("FAT read allocation failed: {error}")))?;
    bytes.resize(len, 0);
    Ok(bytes)
}

/// Unlike FileByteDevice::open, this never attempts an O_RDWR open.
struct ReadOnlyImage {
    file: File,
    len: u64,
}

impl ByteDevice for ReadOnlyImage {
    fn len_bytes(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        self.file.read_exact_at(buf, offset.0)?;
        checkpoint(cx)
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _buf: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Directory {
    Root,
    Cluster(u32),
}

#[derive(Debug, Clone)]
pub struct Entry {
    /// Volume-relative short-entry position. Stable only on an immutable image.
    pub offset: u64,
    pub native: FatDirEntry,
}

impl Entry {
    /// Lossless UTF-8 long names and ASCII short names only. OEM code-page
    /// selection and Windows-equivalent non-ASCII collation remain future work.
    pub fn name(&self) -> Result<String> {
        let name = if let Some(units) = &self.native.long_name {
            String::from_utf16(units).map_err(|_| {
                FfsError::UnsupportedFeature("FAT name contains unpaired UTF-16 surrogates".into())
            })?
        } else {
            self.native.ascii_short_name().ok_or_else(|| {
                FfsError::UnsupportedFeature("FAT short name requires an OEM code page".into())
            })?
        };
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.chars().any(|c| c == '\0' || c == '/' || c == '\\')
        {
            return Err(corrupt(
                self.offset,
                "FAT name is not a safe path component",
            ));
        }
        if name.len() > 255 {
            return Err(FfsError::NameTooLong);
        }
        Ok(name)
    }

    pub fn directory(&self) -> Result<Directory> {
        if !self.native.is_directory() {
            return Err(FfsError::NotDirectory);
        }
        Ok(Directory::Cluster(self.native.first_cluster))
    }
}

/// Verified allocation map. Extra allocated clusters are retained for accounting
/// but are never exposed beyond the directory entry's logical file size.
#[derive(Debug)]
pub struct FileChain {
    pub clusters: Vec<u32>,
    pub size: u32,
}

pub struct FatVolume {
    device: Box<dyn ByteDevice>,
    base: u64,
    pub geometry: FatGeometry,
}

impl FatVolume {
    pub fn open(cx: &Cx, path: &Path, base: u64, length: Option<u64>) -> Result<Self> {
        checkpoint(cx)?;
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(FfsError::UnsupportedFeature(
                "ffs-fat currently accepts offline regular image files, not raw devices".into(),
            ));
        }
        file.try_lock_shared()
            .map_err(|error| FfsError::Format(format!("cannot lock FAT image: {error}")))?;
        let len = metadata.len();
        let length = length.unwrap_or_else(|| len.saturating_sub(base));
        Self::from_device(cx, Box::new(ReadOnlyImage { file, len }), base, length)
    }

    pub fn from_device(
        cx: &Cx,
        device: Box<dyn ByteDevice>,
        base: u64,
        length: u64,
    ) -> Result<Self> {
        checkpoint(cx)?;
        let end = base
            .checked_add(length)
            .ok_or_else(|| FfsError::InvalidGeometry("FAT volume range overflow".into()))?;
        if length < 512 || end > device.len_bytes() {
            return Err(FfsError::InvalidGeometry(
                "FAT volume range exceeds backing".into(),
            ));
        }
        let mut boot = [0_u8; 512];
        device.read_exact_at(cx, ByteOffset(base), &mut boot)?;
        checkpoint(cx)?;
        let geometry = FatGeometry::parse(&boot, length).map_err(parse_error)?;
        let volume = Self {
            device,
            base,
            geometry,
        };
        volume.validate_admission(cx, &boot)?;
        checkpoint(cx)?;
        Ok(volume)
    }

    fn read_exact(&self, cx: &Cx, offset: u64, bytes: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| corrupt(offset, "FAT read range overflow"))?;
        if end > self.geometry.volume_bytes() {
            return Err(corrupt(offset, "FAT read outside selected volume"));
        }
        let physical = self
            .base
            .checked_add(offset)
            .ok_or_else(|| corrupt(offset, "FAT physical offset overflow"))?;
        self.device.read_exact_at(cx, ByteOffset(physical), bytes)?;
        checkpoint(cx)
    }

    fn copies(&self) -> std::ops::Range<u8> {
        if self.geometry.mirrored() {
            0..self.geometry.fat_count()
        } else {
            let active = self.geometry.active_fat();
            active..active + 1
        }
    }

    fn validate_admission(&self, cx: &Cx, boot: &[u8; 512]) -> Result<()> {
        let media = boot[21];
        if media != 0xF0 && media < 0xF8 {
            return Err(corrupt(21, "invalid FAT media descriptor"));
        }
        let width = self.geometry.kind().entry_bytes() as usize;
        let state_offset = match self.geometry.kind() {
            FatKind::Fat16 => 37,
            FatKind::Fat32 => 65,
        };
        if boot[state_offset] & 1 != 0 {
            return Err(FfsError::UnsupportedFeature(
                "dirty FAT volume: use native recovery on a separate copy first".into(),
            ));
        }
        for copy in self.copies() {
            let start =
                self.geometry.entry_offset(copy, 2).map_err(parse_error)? - 2 * width as u64;
            let mut header = [0_u8; 8];
            self.read_exact(cx, start, &mut header[..2 * width])?;
            let (first, second, expected, clean) = match self.geometry.kind() {
                FatKind::Fat16 => (
                    u32::from(u16::from_le_bytes([header[0], header[1]])),
                    u32::from(u16::from_le_bytes([header[2], header[3]])),
                    0xFF00 | u32::from(media),
                    0xFFFF,
                ),
                FatKind::Fat32 => (
                    u32::from_le_bytes([header[0], header[1], header[2], header[3]]) & 0x0FFF_FFFF,
                    u32::from_le_bytes([header[4], header[5], header[6], header[7]]) & 0x0FFF_FFFF,
                    0x0FFF_FF00 | u32::from(media),
                    0x0FFF_FFFF,
                ),
            };
            if first != expected {
                return Err(corrupt(start, "invalid FAT reserved entry zero"));
            }
            if second != clean {
                return Err(FfsError::UnsupportedFeature(format!(
                    "FAT copy {copy} is dirty, has recorded I/O errors, or has an invalid reserved entry"
                )));
            }
        }
        if let Some(sector) = self.geometry.backup_boot_sector() {
            let offset = u64::from(sector) * u64::from(self.geometry.sector_bytes());
            let mut backup = [0_u8; 512];
            self.read_exact(cx, offset, &mut backup)?;
            let geometry = FatGeometry::parse(&backup, self.geometry.volume_bytes())
                .map_err(|error| corrupt(offset, error.to_string()))?;
            if geometry != self.geometry || backup[21] != media {
                return Err(corrupt(
                    offset,
                    "FAT primary and backup boot geometry disagree",
                ));
            }
        }
        // FSInfo free counts are hints. Read-only operation never repairs them.
        Ok(())
    }

    fn cluster_offset(&self, cluster: u32) -> Result<u64> {
        self.geometry
            .cluster_offset(cluster)
            .map_err(|error| corrupt(0, error.to_string()))
    }

    pub fn list(&self, cx: &Cx, directory: Directory) -> Result<Vec<Entry>> {
        checkpoint(cx)?;
        let mut decoder = FatDirectoryDecoder::default();
        let mut entries = Vec::new();
        let mut slots = 0_usize;
        let mut table = FatTable::new(self);
        let fixed = match directory {
            Directory::Root => self.geometry.fixed_root(),
            Directory::Cluster(_) => None,
        };
        if let Some((start, length)) = fixed {
            let mut bytes = allocate(self.geometry.sector_bytes() as usize)?;
            for offset in (start..start + length).step_by(bytes.len()) {
                self.read_exact(cx, offset, &mut bytes)?;
                self.decode_directory(&mut decoder, &bytes, offset, &mut entries, &mut slots)?;
                if decoder.ended() {
                    break;
                }
            }
        } else {
            let mut cluster = match directory {
                Directory::Root => self.geometry.root_cluster(),
                Directory::Cluster(cluster) => cluster,
            };
            let mut seen = BTreeSet::new();
            let mut bytes = allocate(self.geometry.cluster_bytes() as usize)?;
            loop {
                checkpoint(cx)?;
                let offset = self.cluster_offset(cluster)?;
                if !seen.insert(cluster) {
                    return Err(corrupt(offset, "cyclic FAT directory chain"));
                }
                let next = table.next(cx, cluster)?;
                self.read_exact(cx, offset, &mut bytes)?;
                self.decode_directory(&mut decoder, &bytes, offset, &mut entries, &mut slots)?;
                if decoder.ended() {
                    break;
                }
                if let Some(next) = next {
                    cluster = next;
                } else {
                    break;
                }
            }
        }
        checkpoint(cx)?;
        Ok(entries)
    }

    fn decode_directory(
        &self,
        decoder: &mut FatDirectoryDecoder,
        bytes: &[u8],
        offset: u64,
        entries: &mut Vec<Entry>,
        slots: &mut usize,
    ) -> Result<()> {
        for (index, bytes) in bytes.chunks_exact(32).enumerate() {
            if *slots >= MAX_DIRECTORY_SLOTS {
                return Err(FfsError::UnsupportedFeature(
                    "FAT directory exceeds 65536 slots".into(),
                ));
            }
            *slots += 1;
            let slot: &[u8; 32] = bytes
                .try_into()
                .map_err(|_| corrupt(offset, "short FAT directory record"))?;
            let position = offset + (index as u64) * 32;
            let native = decoder
                .push(slot, self.geometry.kind())
                .map_err(|error| corrupt(position, error.to_string()))?;
            if let Some(native) = native {
                if native.short_name == *b".          " || native.short_name == *b"..         " {
                    continue;
                }
                if native.is_directory() || native.first_cluster != 0 {
                    self.cluster_offset(native.first_cluster)?;
                } else if native.size != 0 {
                    return Err(corrupt(position, "nonempty FAT file has no first cluster"));
                }
                entries.push(Entry {
                    offset: position,
                    native,
                });
            }
            if decoder.ended() {
                break;
            }
        }
        Ok(())
    }

    pub fn lookup(&self, cx: &Cx, directory: Directory, name: &str) -> Result<Entry> {
        checkpoint(cx)?;
        if name.is_empty() || name.contains(['/', '\\', '\0']) || matches!(name, "." | "..") {
            return Err(FfsError::Format("expected one FAT path component".into()));
        }
        let mut found = None;
        for entry in self.list(cx, directory)? {
            checkpoint(cx)?;
            let displayed = entry.name()?;
            let short = entry.native.ascii_short_name();
            if displayed.eq_ignore_ascii_case(name)
                || short
                    .as_deref()
                    .is_some_and(|alias| alias.eq_ignore_ascii_case(name))
            {
                if found.is_some() {
                    return Err(corrupt(entry.offset, "ambiguous FAT name or short alias"));
                }
                found = Some(entry);
            }
        }
        checkpoint(cx)?;
        found.ok_or(FfsError::NotFound)
    }

    /// Resolve an image path without following any host path or native '..'.
    /// A root path returns None. Parent traversal is rejected by this CLI API.
    pub fn resolve(&self, cx: &Cx, path: &str) -> Result<Option<Entry>> {
        checkpoint(cx)?;
        let mut directory = Directory::Root;
        let components: Vec<_> = path
            .split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .take(257)
            .collect();
        if path.len() > 65_536 || components.len() > 256 {
            return Err(FfsError::NameTooLong);
        }
        let mut ancestors = BTreeSet::new();
        if self.geometry.kind() == FatKind::Fat32 {
            ancestors.insert(self.geometry.root_cluster());
        }
        let mut result = None;
        for (index, component) in components.iter().enumerate() {
            if *component == ".." {
                return Err(FfsError::Format(
                    "parent traversal is not accepted in image paths".into(),
                ));
            }
            let entry = self.lookup(cx, directory, component)?;
            if entry.native.is_directory() && !ancestors.insert(entry.native.first_cluster) {
                return Err(corrupt(entry.offset, "FAT directory links to an ancestor"));
            }
            if index + 1 < components.len() || path.ends_with('/') {
                directory = entry.directory()?;
            }
            result = Some(entry);
        }
        checkpoint(cx)?;
        Ok(result)
    }

    /// Validate the complete allocation chain before serving any of its bytes.
    /// Brent cycle detection uses constant auxiliary memory. The address vector
    /// is explicitly capped; free, bad, reserved, missing and conflicting
    /// links are errors, never successful short reads or synthesized zeroes.
    pub fn file_chain(&self, cx: &Cx, entry: &Entry) -> Result<FileChain> {
        checkpoint(cx)?;
        if entry.native.is_directory() {
            return Err(FfsError::IsDirectory);
        }
        let size = entry.native.size;
        let required = u64::from(size).div_ceil(u64::from(self.geometry.cluster_bytes()));
        let mut clusters = Vec::new();
        if required > u64::from(self.geometry.cluster_count()) {
            return Err(corrupt(
                entry.offset,
                "FAT file size exceeds the volume's data capacity",
            ));
        }
        if entry.native.first_cluster == 0 {
            if size != 0 {
                return Err(corrupt(entry.offset, "nonempty FAT file has no chain"));
            }
            return Ok(FileChain { clusters, size });
        }
        let limit = MAX_CHAIN_CLUSTERS.min(self.geometry.cluster_count() as usize);
        let mut table = FatTable::new(self);
        let mut cluster = entry.native.first_cluster;
        let mut anchor = cluster;
        let mut power = 1_u64;
        let mut distance = 0_u64;
        loop {
            checkpoint(cx)?;
            self.cluster_offset(cluster)?;
            if clusters.len() == limit {
                return Err(corrupt(
                    entry.offset,
                    "FAT chain exceeds the volume or 32 MiB map budget",
                ));
            }
            if clusters.len() == clusters.capacity() {
                clusters
                    .try_reserve_exact(1024.min(limit - clusters.len()))
                    .map_err(|error| {
                        FfsError::Format(format!("FAT chain allocation failed: {error}"))
                    })?;
            }
            clusters.push(cluster);
            let Some(next) = table.next(cx, cluster)? else {
                break;
            };
            distance += 1;
            if next == anchor {
                return Err(corrupt(entry.offset, "cyclic FAT file chain"));
            }
            if distance == power {
                anchor = next;
                power *= 2;
                distance = 0;
            }
            cluster = next;
        }
        if (clusters.len() as u64) < required {
            return Err(corrupt(entry.offset, "FAT chain ends before logical EOF"));
        }
        checkpoint(cx)?;
        Ok(FileChain { clusters, size })
    }

    pub fn read(&self, cx: &Cx, chain: &FileChain, offset: u64, size: usize) -> Result<Vec<u8>> {
        checkpoint(cx)?;
        if size > MAX_READ_BYTES {
            return Err(FfsError::Format("FAT read request exceeds 16 MiB".into()));
        }
        let length = (u64::from(chain.size).saturating_sub(offset)).min(size as u64) as usize;
        let mut result = allocate(length)?;
        let cluster_bytes = u64::from(self.geometry.cluster_bytes());
        let mut done = 0;
        while done < length {
            let file_offset = offset + done as u64;
            let index = (file_offset / cluster_bytes) as usize;
            let within = file_offset % cluster_bytes;
            let cluster = chain
                .clusters
                .get(index)
                .ok_or_else(|| corrupt(0, "FAT file map does not cover read"))?;
            let count = (length - done).min((cluster_bytes - within) as usize);
            let physical = self.cluster_offset(*cluster)? + within;
            self.read_exact(cx, physical, &mut result[done..done + count])?;
            done += count;
        }
        checkpoint(cx)?;
        Ok(result)
    }

    /// Exact free-cluster count from admitted FAT copies, not FSInfo hints.
    pub fn free_clusters(&self, cx: &Cx) -> Result<u64> {
        let mut table = FatTable::new(self);
        let mut free = 0_u64;
        for cluster in 2..=self.geometry.cluster_count() + 1 {
            checkpoint(cx)?;
            if self.geometry.cluster_offset(cluster).is_ok()
                && table.entry(cx, cluster)? == FatEntry::Free
            {
                free += 1;
            }
        }
        checkpoint(cx)?;
        Ok(free)
    }
}

/// Two bounded sector caches, not an in-memory copy of a potentially huge FAT.
struct FatTable<'a> {
    volume: &'a FatVolume,
    sectors: [Option<(u64, Vec<u8>)>; 2],
}

impl<'a> FatTable<'a> {
    fn new(volume: &'a FatVolume) -> Self {
        Self {
            volume,
            sectors: [None, None],
        }
    }

    fn entry(&mut self, cx: &Cx, cluster: u32) -> Result<FatEntry> {
        checkpoint(cx)?;
        let geometry = &self.volume.geometry;
        let sector_bytes = u64::from(geometry.sector_bytes());
        let mut previous = None;
        for copy in self.volume.copies() {
            let position = geometry.entry_offset(copy, cluster).map_err(parse_error)?;
            let start = position / sector_bytes * sector_bytes;
            let cache = &mut self.sectors[usize::from(copy)];
            if cache.as_ref().is_none_or(|(offset, _)| *offset != start) {
                let mut bytes = allocate(geometry.sector_bytes() as usize)?;
                self.volume.read_exact(cx, start, &mut bytes)?;
                *cache = Some((start, bytes));
            }
            let (_, bytes) = cache
                .as_ref()
                .ok_or_else(|| corrupt(position, "FAT sector cache was not populated"))?;
            let at = (position - start) as usize;
            let value = match geometry.kind() {
                FatKind::Fat16 => u32::from(u16::from_le_bytes([bytes[at], bytes[at + 1]])),
                FatKind::Fat32 => {
                    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
                        & 0x0FFF_FFFF
                }
            };
            if previous.is_some_and(|other| other != value) {
                return Err(corrupt(
                    position,
                    format!("FAT copies disagree at cluster {cluster}"),
                ));
            }
            previous = Some(value);
        }
        checkpoint(cx)?;
        let value = previous.ok_or_else(|| corrupt(0, "no admitted FAT copy"))?;
        Ok(geometry.kind().decode_entry(value))
    }

    fn next(&mut self, cx: &Cx, cluster: u32) -> Result<Option<u32>> {
        match self.entry(cx, cluster)? {
            FatEntry::End => Ok(None),
            FatEntry::Next(next) => {
                self.volume.cluster_offset(next)?;
                Ok(Some(next))
            }
            state => Err(corrupt(
                self.volume.cluster_offset(cluster)?,
                format!("invalid {state:?} link in live FAT chain at cluster {cluster}"),
            )),
        }
    }
}

#[cfg(test)]
mod tests;
