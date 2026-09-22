//! Snapshot-based, external RaptorQ protection for offline image files.
//!
//! Unlike an on-image repair tail, a sidecar never assumes that ext4/btrfs
//! allocator space is free. Every image byte, including filesystem metadata
//! and the final partial block, is protected. Parity and checksums live in a
//! separate, exclusively created file. Memory usage is bounded by one group.
//!
//! The image MUST be offline. Advisory locks exclude cooperating users of this
//! API, not kernel mounts or unrelated writers. A final reread detects changes
//! during capture but is not a substitute for an offline filesystem snapshot.
//! These checksums detect accidental corruption; they do not authenticate an
//! archive supplied by an adversary. A sidecar describes one saved generation,
//! not permission to roll back subsequent legitimate filesystem writes.

use crate::codec::encode_group;
use asupersync::Cx;
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, GroupNumber};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;
use tempfile::NamedTempFile;

const MAGIC: &[u8; 8] = b"FFSRQSC2";
const VERSION: u32 = 2;
pub(crate) const HEADER_BYTES: usize = 128;
const GROUP_PREFIX_BYTES: usize = 32;
const DIGEST_BYTES: usize = 32;
const MAX_GROUP_BYTES: u64 = 4 * 1024 * 1024;

/// Resource limits and redundancy for a new protection snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SidecarOptions {
    pub block_size: u32,
    pub group_blocks: u32,
    pub repair_symbols: u32,
}

impl Default for SidecarOptions {
    fn default() -> Self {
        Self {
            block_size: 4096,
            group_blocks: 256,
            repair_symbols: 16,
        }
    }
}

impl SidecarOptions {
    pub(crate) fn validate(self) -> Result<()> {
        if !(512..=65_536).contains(&self.block_size) || !self.block_size.is_power_of_two() {
            return Err(FfsError::InvalidGeometry(
                "sidecar block size must be a power of two in 512..=65536".to_owned(),
            ));
        }
        if !(2..=1024).contains(&self.group_blocks)
            || self.repair_symbols == 0
            || self.repair_symbols > self.group_blocks
            || u64::from(self.block_size) * u64::from(self.group_blocks) > MAX_GROUP_BYTES
        {
            return Err(FfsError::InvalidGeometry(
                "sidecar requires 2..=1024 source blocks, 1..=group_blocks repair symbols, and at most 4 MiB per group".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Identity of the saved protection point, independent of the current image.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProtectionInfo {
    pub format_version: u32,
    pub image_bytes: u64,
    pub block_size: u32,
    pub group_blocks: u32,
    pub repair_symbols_per_group: u32,
    pub groups: u32,
    pub sidecar_bytes: u64,
    pub snapshot_blake3: String,
}

/// Comparison with a saved protection point. Changed bytes are not necessarily
/// corruption: they can also be legitimate writes made after the snapshot.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SidecarReport {
    pub protection: ProtectionInfo,
    pub current_image_bytes: u64,
    pub checked_blocks: u64,
    pub changed_blocks: u64,
    pub unreadable_blocks: u64,
    pub valid_repair_symbols: u64,
    pub invalid_repair_symbols: u64,
    pub matches_snapshot: bool,
}

impl SidecarReport {
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.matches_snapshot && self.invalid_repair_symbols == 0
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Header {
    pub(crate) options: SidecarOptions,
    pub(crate) image_bytes: u64,
    pub(crate) groups: u32,
    pub(crate) seed: [u8; 16],
    pub(crate) snapshot_digest: [u8; 32],
}

impl Header {
    fn new(options: SidecarOptions, image_bytes: u64, seed: [u8; 16]) -> Result<Self> {
        options.validate()?;
        if image_bytes == 0 {
            return Err(FfsError::InvalidGeometry(
                "cannot protect an empty image".to_owned(),
            ));
        }
        let blocks = image_bytes.div_ceil(u64::from(options.block_size));
        let groups = u32::try_from(blocks.div_ceil(u64::from(options.group_blocks)))
            .map_err(|_| corrupt("sidecar group count exceeds u32"))?;
        let header = Self {
            options,
            image_bytes,
            groups,
            seed,
            snapshot_digest: [0; 32],
        };
        header.expected_len()?;
        Ok(header)
    }

    pub(crate) fn block_count(&self) -> u64 {
        self.image_bytes.div_ceil(u64::from(self.options.block_size))
    }

    pub(crate) fn group_geometry(&self, index: u32) -> Result<(u64, u32)> {
        if index >= self.groups {
            return Err(corrupt("sidecar group index out of range"));
        }
        let first = u64::from(index) * u64::from(self.options.group_blocks);
        let count = (self.block_count() - first).min(u64::from(self.options.group_blocks));
        Ok((first, count as u32))
    }

    pub(crate) fn real_block_len(&self, block: u64) -> usize {
        self.image_bytes
            .saturating_sub(block * u64::from(self.options.block_size))
            .min(u64::from(self.options.block_size)) as usize
    }

    fn expected_len(&self) -> Result<u64> {
        let symbols = u128::from(self.groups) * u128::from(self.options.repair_symbols);
        let size = HEADER_BYTES as u128
            + u128::from(self.groups) * (GROUP_PREFIX_BYTES + DIGEST_BYTES) as u128
            + u128::from(self.block_count()) * DIGEST_BYTES as u128
            + symbols * (u128::from(self.options.block_size) + 4 + DIGEST_BYTES as u128);
        u64::try_from(size).map_err(|_| corrupt("sidecar length overflow"))
    }

    fn group_offset(&self, index: u32) -> Result<u64> {
        self.group_geometry(index)?;
        let stride = (GROUP_PREFIX_BYTES + DIGEST_BYTES) as u64
            + u64::from(self.options.group_blocks) * DIGEST_BYTES as u64
            + u64::from(self.options.repair_symbols)
                * (u64::from(self.options.block_size) + 4 + DIGEST_BYTES as u64);
        // Geometry validation caps both factors well below u64::MAX.
        Ok(HEADER_BYTES as u64 + u64::from(index) * stride)
    }

    fn prefix(&self, index: u32) -> Result<[u8; GROUP_PREFIX_BYTES]> {
        let (first, count) = self.group_geometry(index)?;
        let mut raw = [0; GROUP_PREFIX_BYTES];
        raw[..4].copy_from_slice(&index.to_le_bytes());
        raw[4..8].copy_from_slice(&count.to_le_bytes());
        raw[8..16].copy_from_slice(&first.to_le_bytes());
        raw[16..20].copy_from_slice(&self.options.repair_symbols.to_le_bytes());
        Ok(raw)
    }

    fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut raw = [0; HEADER_BYTES];
        raw[..8].copy_from_slice(MAGIC);
        raw[8..12].copy_from_slice(&VERSION.to_le_bytes());
        raw[12..16].copy_from_slice(&self.options.block_size.to_le_bytes());
        raw[16..20].copy_from_slice(&self.options.group_blocks.to_le_bytes());
        raw[20..24].copy_from_slice(&self.options.repair_symbols.to_le_bytes());
        raw[24..32].copy_from_slice(&self.image_bytes.to_le_bytes());
        raw[32..40].copy_from_slice(&u64::from(self.groups).to_le_bytes());
        raw[40..56].copy_from_slice(&self.seed);
        raw[56..88].copy_from_slice(&self.snapshot_digest);
        let digest = blake3::hash(&raw[..88]);
        raw[88..120].copy_from_slice(digest.as_bytes());
        raw
    }

    fn decode(raw: &[u8; HEADER_BYTES]) -> Result<Self> {
        if &raw[..8] != MAGIC
            || read_u32(raw, 8)? != VERSION
            || raw[120..].iter().any(|&byte| byte != 0)
            || raw[88..120] != blake3::hash(&raw[..88]).as_bytes()[..]
        {
            return Err(corrupt("invalid, unsupported, or incomplete sidecar header"));
        }
        let options = SidecarOptions {
            block_size: read_u32(raw, 12)?,
            group_blocks: read_u32(raw, 16)?,
            repair_symbols: read_u32(raw, 20)?,
        };
        let mut seed = [0; 16];
        seed.copy_from_slice(&raw[40..56]);
        let mut header = Self::new(options, read_u64(raw, 24)?, seed)?;
        if read_u64(raw, 32)? != u64::from(header.groups) {
            return Err(corrupt("sidecar group count disagrees with image geometry"));
        }
        header.snapshot_digest.copy_from_slice(&raw[56..88]);
        Ok(header)
    }

    pub(crate) fn info(&self) -> Result<ProtectionInfo> {
        Ok(ProtectionInfo {
            format_version: VERSION,
            image_bytes: self.image_bytes,
            block_size: self.options.block_size,
            group_blocks: self.options.group_blocks,
            repair_symbols_per_group: self.options.repair_symbols,
            groups: self.groups,
            sidecar_bytes: self.expected_len()?,
            snapshot_blake3: blake3::Hash::from_bytes(self.snapshot_digest)
                .to_hex()
                .to_string(),
        })
    }
}

pub(crate) fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

pub(crate) fn corrupt(message: &str) -> FfsError {
    FfsError::Corruption {
        block: 0,
        detail: message.to_owned(),
    }
}

fn read_u32(raw: &[u8], offset: usize) -> Result<u32> {
    let bytes = raw
        .get(offset..offset + 4)
        .ok_or_else(|| corrupt("short u32"))?;
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| corrupt("short u32"))?,
    ))
}

fn read_u64(raw: &[u8], offset: usize) -> Result<u64> {
    let bytes = raw
        .get(offset..offset + 8)
        .ok_or_else(|| corrupt("short u64"))?;
    Ok(u64::from_le_bytes(
        bytes.try_into().map_err(|_| corrupt("short u64"))?,
    ))
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

pub(crate) fn source_digest(header: &Header, block: u64, bytes: &[u8]) -> [u8; 32] {
    digest_parts(
        b"ffs-sidecar-source-v2",
        &[&header.seed, &block.to_le_bytes(), bytes],
    )
}

fn symbol_digest(
    header: &Header,
    group: u32,
    group_digest: &[u8; 32],
    esi: u32,
    bytes: &[u8],
) -> [u8; 32] {
    // The seed may repeat when two generations share their image prefix.
    // Bind parity to this group's complete source digest table, not just its
    // address and ESI, so transplanted stale parity cannot verify as healthy.
    digest_parts(
        b"ffs-sidecar-symbol-v2",
        &[
            &header.seed,
            &group.to_le_bytes(),
            group_digest,
            &esi.to_le_bytes(),
            bytes,
        ],
    )
}

pub(crate) fn parent_path(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Lock the actual image inode for the entire operation, including aliases.
/// Never open the source image for writing.
pub(crate) fn open_image(cx: &Cx, path: &Path) -> Result<File> {
    checkpoint(cx)?;
    let image = File::open(path)?;
    if !image.metadata()?.is_file() {
        return Err(FfsError::InvalidGeometry(
            "sidecar operations require a regular offline image file".to_owned(),
        ));
    }
    image.try_lock().map_err(io::Error::from)?;
    checkpoint(cx)?;
    Ok(image)
}

/// Publish a fully written and synced file without replacing an existing path.
/// The final name is never exposed with a partial image or incomplete archive.
pub(crate) fn publish_new(cx: &Cx, staged: NamedTempFile, path: &Path) -> Result<()> {
    checkpoint(cx)?;
    let parent = File::open(parent_path(path))?;
    staged.as_file().sync_all()?;
    checkpoint(cx)?;
    let _published = staged
        .persist_noclobber(path)
        .map_err(|error| FfsError::Io(error.error))?;
    // Publication has committed. Finish its durability barrier even if a
    // cancellation arrives now, rather than leaving a visible unsynced name.
    parent.sync_all()?;
    Ok(())
}

#[derive(Debug)]
pub(crate) struct MemoryGroup {
    pub(crate) first: u64,
    pub(crate) block_size: u32,
    pub(crate) blocks: Vec<Vec<u8>>,
}

impl BlockDevice for MemoryGroup {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        checkpoint(cx)?;
        let bytes = block
            .0
            .checked_sub(self.first)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| self.blocks.get(index))
            .ok_or_else(|| corrupt("source block outside captured group"))?;
        Ok(BlockBuf::new(bytes.clone()))
    }

    fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        self.first + self.blocks.len() as u64
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)
    }
}

pub(crate) fn load_source(
    cx: &Cx,
    image: &File,
    header: &Header,
    index: u32,
    tolerate_errors: bool,
) -> Result<(MemoryGroup, Vec<u32>)> {
    let (first, count) = header.group_geometry(index)?;
    let mut blocks = Vec::with_capacity(count as usize);
    let mut unreadable = Vec::new();
    for relative in 0..count {
        checkpoint(cx)?;
        let block = first + u64::from(relative);
        let mut bytes = vec![0; header.options.block_size as usize];
        let read = image.read_exact_at(
            &mut bytes[..header.real_block_len(block)],
            block * u64::from(header.options.block_size),
        );
        checkpoint(cx)?;
        if let Err(error) = read {
            if !tolerate_errors {
                return Err(error.into());
            }
            bytes.fill(0);
            unreadable.push(relative);
        }
        blocks.push(bytes);
    }
    Ok((
        MemoryGroup {
            first,
            block_size: header.options.block_size,
            blocks,
        },
        unreadable,
    ))
}

pub(crate) struct GroupRecord {
    pub(crate) hashes: Vec<[u8; 32]>,
    pub(crate) symbols: Vec<(u32, Vec<u8>)>,
    pub(crate) invalid_symbols: u64,
}

pub(crate) struct Archive {
    file: File,
    pub(crate) header: Header,
}

impl Archive {
    pub(crate) fn open(cx: &Cx, path: &Path) -> Result<Self> {
        checkpoint(cx)?;
        let file = File::open(path)?;
        file.try_lock_shared().map_err(io::Error::from)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(corrupt("sidecar must be a regular file"));
        }
        let mut raw = [0; HEADER_BYTES];
        file.read_exact_at(&mut raw, 0)?;
        let header = Header::decode(&raw)?;
        if metadata.len() != header.expected_len()? {
            return Err(corrupt("sidecar is truncated or has trailing data"));
        }
        checkpoint(cx)?;
        Ok(Self { file, header })
    }

    pub(crate) fn read_group(&self, cx: &Cx, index: u32) -> Result<GroupRecord> {
        checkpoint(cx)?;
        let (_, count) = self.header.group_geometry(index)?;
        let mut offset = self.header.group_offset(index)?;
        let mut metadata = vec![0; GROUP_PREFIX_BYTES + count as usize * DIGEST_BYTES];
        self.file.read_exact_at(&mut metadata, offset)?;
        offset += metadata.len() as u64;
        let mut group_digest = [0; DIGEST_BYTES];
        self.file.read_exact_at(&mut group_digest, offset)?;
        offset += DIGEST_BYTES as u64;
        if metadata[..GROUP_PREFIX_BYTES] != self.header.prefix(index)?
            || group_digest != digest_parts(b"ffs-sidecar-group-v2", &[&self.header.seed, &metadata])
        {
            return Err(corrupt("sidecar group metadata checksum or geometry mismatch"));
        }
        let hashes = metadata[GROUP_PREFIX_BYTES..]
            .chunks_exact(DIGEST_BYTES)
            .map(|bytes| {
                let mut hash = [0; DIGEST_BYTES];
                hash.copy_from_slice(bytes);
                hash
            })
            .collect();
        let mut symbols = Vec::with_capacity(self.header.options.repair_symbols as usize);
        let mut seen = BTreeSet::new();
        let mut invalid_symbols = 0;
        for _ in 0..self.header.options.repair_symbols {
            checkpoint(cx)?;
            let mut esi_bytes = [0; 4];
            self.file.read_exact_at(&mut esi_bytes, offset)?;
            offset += 4;
            let esi = u32::from_le_bytes(esi_bytes);
            let mut data = vec![0; self.header.options.block_size as usize];
            self.file.read_exact_at(&mut data, offset)?;
            offset += data.len() as u64;
            let mut digest = [0; DIGEST_BYTES];
            self.file.read_exact_at(&mut digest, offset)?;
            offset += DIGEST_BYTES as u64;
            if esi < count
                || digest != symbol_digest(&self.header, index, &group_digest, esi, &data)
                || !seen.insert(esi)
            {
                invalid_symbols += 1;
            } else {
                symbols.push((esi, data));
            }
        }
        checkpoint(cx)?;
        Ok(GroupRecord {
            hashes,
            symbols,
            invalid_symbols,
        })
    }
}

fn hash_image(cx: &Cx, image: &File, bytes: u64) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0; 1024 * 1024];
    let mut offset = 0;
    while offset < bytes {
        checkpoint(cx)?;
        let count = (bytes - offset).min(buffer.len() as u64) as usize;
        image.read_exact_at(&mut buffer[..count], offset)?;
        hasher.update(&buffer[..count]);
        offset += count as u64;
    }
    checkpoint(cx)?;
    Ok(*hasher.finalize().as_bytes())
}

/// Create a new, durable sidecar for an offline image without changing the image
/// or overwriting an existing archive. No partial archive is published on error.
pub fn protect(
    cx: &Cx,
    image_path: &Path,
    sidecar_path: &Path,
    options: SidecarOptions,
) -> Result<ProtectionInfo> {
    options.validate()?;
    let image = open_image(cx, image_path)?;
    let image_bytes = image.metadata()?.len();
    let mut seed_input = vec![0; image_bytes.min(4096) as usize];
    image.read_exact_at(&mut seed_input, 0)?;
    let digest = digest_parts(
        b"ffs-sidecar-seed-v2",
        &[&image_bytes.to_le_bytes(), &seed_input],
    );
    let mut seed = [0; 16];
    seed.copy_from_slice(&digest[..16]);
    let mut header = Header::new(options, image_bytes, seed)?;
    let mut staged = NamedTempFile::new_in(parent_path(sidecar_path))?;
    staged.write_all(&[0; HEADER_BYTES])?;
    let mut snapshot = blake3::Hasher::new();
    for index in 0..header.groups {
        let (source, _) = load_source(cx, &image, &header, index, false)?;
        let mut metadata = header.prefix(index)?.to_vec();
        for (relative, data) in source.blocks.iter().enumerate() {
            let block = source.first + relative as u64;
            metadata.extend_from_slice(&source_digest(&header, block, data));
            snapshot.update(&data[..header.real_block_len(block)]);
        }
        let encoded = encode_group(
            cx,
            &source,
            &header.seed,
            GroupNumber(index),
            BlockNumber(source.first),
            source.blocks.len() as u32,
            options.repair_symbols,
        )?;
        checkpoint(cx)?;
        if encoded.repair_symbols.len() != options.repair_symbols as usize {
            return Err(corrupt("encoder returned an incomplete repair symbol set"));
        }
        let group_digest = digest_parts(b"ffs-sidecar-group-v2", &[&header.seed, &metadata]);
        staged.write_all(&metadata)?;
        staged.write_all(&group_digest)?;
        for symbol in encoded.repair_symbols {
            staged.write_all(&symbol.esi.to_le_bytes())?;
            staged.write_all(&symbol.data)?;
            staged.write_all(&symbol_digest(
                &header,
                index,
                &group_digest,
                symbol.esi,
                &symbol.data,
            ))?;
        }
    }
    header.snapshot_digest = *snapshot.finalize().as_bytes();
    if image.metadata()?.len() != image_bytes
        || hash_image(cx, &image, image_bytes)? != header.snapshot_digest
    {
        return Err(corrupt(
            "image changed during protection; take the filesystem offline and retry",
        ));
    }
    if staged.as_file().metadata()?.len() != header.expected_len()? {
        return Err(corrupt("encoded sidecar length disagrees with geometry"));
    }
    staged.as_file().write_all_at(&header.encode(), 0)?;
    publish_new(cx, staged, sidecar_path)?;
    header.info()
}

/// Verify all source-block digests and repair-symbol payload digests using the
/// saved generation. This is read-only, including when corruption is found.
pub fn verify(cx: &Cx, image_path: &Path, sidecar_path: &Path) -> Result<SidecarReport> {
    let archive = Archive::open(cx, sidecar_path)?;
    let image = open_image(cx, image_path)?;
    let header = &archive.header;
    let mut report = SidecarReport {
        protection: header.info()?,
        current_image_bytes: image.metadata()?.len(),
        checked_blocks: 0,
        changed_blocks: 0,
        unreadable_blocks: 0,
        valid_repair_symbols: 0,
        invalid_repair_symbols: 0,
        matches_snapshot: false,
    };
    let mut snapshot = blake3::Hasher::new();
    for index in 0..header.groups {
        let record = archive.read_group(cx, index)?;
        let (source, unreadable) = load_source(cx, &image, header, index, true)?;
        report.valid_repair_symbols += record.symbols.len() as u64;
        report.invalid_repair_symbols += record.invalid_symbols;
        report.unreadable_blocks += unreadable.len() as u64;
        for (relative, (data, expected)) in source.blocks.iter().zip(&record.hashes).enumerate() {
            let block = source.first + relative as u64;
            report.checked_blocks += 1;
            if unreadable.binary_search(&(relative as u32)).is_err()
                && source_digest(header, block, data) != *expected
            {
                report.changed_blocks += 1;
            }
            snapshot.update(&data[..header.real_block_len(block)]);
        }
    }
    checkpoint(cx)?;
    report.matches_snapshot = report.current_image_bytes == header.image_bytes
        && image.metadata()?.len() == header.image_bytes
        && report.changed_blocks == 0
        && report.unreadable_blocks == 0
        && snapshot.finalize().as_bytes() == &header.snapshot_digest;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf, Vec<u8>) {
        let dir = tempfile::tempdir().expect("directory");
        let image = dir.path().join("image.img");
        let sidecar = dir.path().join("image.ffs-rq");
        let bytes: Vec<u8> = (0..19 * 512 + 37)
            .map(|index| ((index * 31 + index / 512) % 251) as u8)
            .collect();
        std::fs::write(&image, &bytes).expect("image");
        (dir, image, sidecar, bytes)
    }

    fn options() -> SidecarOptions {
        SidecarOptions {
            block_size: 512,
            group_blocks: 8,
            repair_symbols: 4,
        }
    }

    #[test]
    fn sidecar_protects_every_byte_and_final_partial_block_without_image_writes() {
        let (_dir, image, sidecar, bytes) = fixture();
        let cx = Cx::for_testing();
        let info = protect(&cx, &image, &sidecar, options()).expect("protect");
        assert_eq!(info.format_version, 2);
        assert_eq!(info.groups, 3);
        assert_eq!(info.image_bytes, bytes.len() as u64);
        assert_eq!(std::fs::read(&image).expect("unchanged"), bytes);
        assert_eq!(
            info.sidecar_bytes,
            std::fs::metadata(&sidecar).expect("metadata").len()
        );
        let report = verify(&cx, &image, &sidecar).expect("verify");
        assert!(report.is_healthy());
        assert_eq!(report.checked_blocks, 20);
        assert_eq!(report.valid_repair_symbols, 12);
    }

    #[test]
    fn sidecar_reports_changed_source_and_corrupt_parity_independently() {
        let (_dir, image, sidecar, _) = fixture();
        let cx = Cx::for_testing();
        protect(&cx, &image, &sidecar, options()).expect("protect");
        File::options()
            .write(true)
            .open(&image)
            .expect("image")
            .write_all_at(&[255], 513)
            .expect("damage");
        let archive = Archive::open(&cx, &sidecar).expect("archive");
        let parity = archive.header.group_offset(0).expect("offset") + 32 + 8 * 32 + 32 + 4;
        drop(archive);
        let file = File::options()
            .read(true)
            .write(true)
            .open(&sidecar)
            .expect("sidecar");
        let mut byte = [0];
        file.read_exact_at(&mut byte, parity).expect("read");
        byte[0] ^= 1;
        file.write_all_at(&byte, parity).expect("damage");
        let report = verify(&cx, &image, &sidecar).expect("verify");
        assert_eq!(report.changed_blocks, 1);
        assert_eq!(report.invalid_repair_symbols, 1);
        assert_eq!(report.valid_repair_symbols, 11);
        assert!(!report.is_healthy());
    }

    #[test]
    fn sidecar_rejects_parity_transplanted_from_a_different_source_generation() {
        let (_dir, image, sidecar, original) = fixture();
        let cx = Cx::for_testing();
        protect(&cx, &image, &sidecar, options()).expect("first protection point");
        // Change a block AFTER the 4096-byte seed prefix. Both captures have
        // exactly the same seed, group addresses, ESI values, and geometry.
        File::options()
            .write(true)
            .open(&image)
            .expect("image")
            .write_all_at(&[255], 4096)
            .expect("new generation");
        let newer = sidecar.with_extension("newer");
        protect(&cx, &image, &newer, options()).expect("second protection point");
        let first = Archive::open(&cx, &sidecar).expect("first archive");
        let second = Archive::open(&cx, &newer).expect("second archive");
        assert_eq!(first.header.seed, second.header.seed);
        assert_ne!(first.header.snapshot_digest, second.header.snapshot_digest);
        let parity_offset = first.header.group_offset(1).expect("group") + 32 + 8 * 32 + 32;
        let mut stale = vec![0; 4 * (4 + 512 + 32)];
        second.file.read_exact_at(&mut stale, parity_offset).expect("other parity");
        drop(first);
        drop(second);
        File::options()
            .write(true)
            .open(&sidecar)
            .expect("first archive")
            .write_all_at(&stale, parity_offset)
            .expect("transplant independently checksummed parity");
        std::fs::write(&image, original).expect("restore original source generation");
        let report = verify(&cx, &image, &sidecar).expect("verify mixed archive");
        assert!(report.matches_snapshot, "the source still matches its protection point");
        assert_eq!(report.invalid_repair_symbols, 4);
        assert_eq!(report.valid_repair_symbols, 8);
        assert!(!report.is_healthy(), "stale parity is not healthy redundancy");
    }

    #[test]
    fn sidecar_refuses_the_unbound_v1_format_even_with_a_valid_header_checksum() {
        let (_dir, image, sidecar, _) = fixture();
        let cx = Cx::for_testing();
        protect(&cx, &image, &sidecar, options()).expect("protect");
        let file = File::options().read(true).write(true).open(&sidecar).expect("sidecar");
        let mut raw = [0; HEADER_BYTES];
        file.read_exact_at(&mut raw, 0).expect("header");
        raw[..8].copy_from_slice(b"FFSRQSC1");
        raw[8..12].copy_from_slice(&1_u32.to_le_bytes());
        let digest = blake3::hash(&raw[..88]);
        raw[88..120].copy_from_slice(digest.as_bytes());
        file.write_all_at(&raw, 0).expect("old header");
        assert!(verify(&cx, &image, &sidecar).is_err());
    }

    #[test]
    fn sidecar_rejects_truncated_archive_and_corrupt_source_digest_table() {
        let (_dir, image, sidecar, _) = fixture();
        let cx = Cx::for_testing();
        protect(&cx, &image, &sidecar, options()).expect("protect");
        let file = File::options()
            .read(true)
            .write(true)
            .open(&sidecar)
            .expect("sidecar");
        let mut byte = [0];
        file.read_exact_at(&mut byte, 160).expect("read");
        byte[0] ^= 1;
        file.write_all_at(&byte, 160).expect("damage");
        assert!(verify(&cx, &image, &sidecar).is_err());
        file.set_len(128).expect("truncate");
        assert!(verify(&cx, &image, &sidecar).is_err());
    }

    #[test]
    fn sidecar_refuses_overwrite_and_cancelled_capture_never_publishes() {
        let (_dir, image, sidecar, bytes) = fixture();
        std::fs::write(&sidecar, b"existing archive").expect("existing");
        let cx = Cx::for_testing();
        assert!(protect(&cx, &image, &sidecar, options()).is_err());
        assert_eq!(std::fs::read(&sidecar).expect("retained"), b"existing archive");
        cx.set_cancel_requested(true);
        let other = sidecar.with_extension("cancelled");
        assert!(matches!(
            protect(&cx, &image, &other, options()),
            Err(FfsError::Cancelled)
        ));
        assert!(!other.exists());
        assert_eq!(std::fs::read(image).expect("source retained"), bytes);
    }

    #[test]
    fn sidecar_rejects_unbounded_geometry_and_incomplete_header() {
        let (_dir, image, sidecar, _) = fixture();
        let cx = Cx::for_testing();
        let bad = SidecarOptions {
            group_blocks: u32::MAX,
            ..options()
        };
        assert!(protect(&cx, &image, &sidecar, bad).is_err());
        assert!(!sidecar.exists());
        std::fs::write(&sidecar, [0; HEADER_BYTES]).expect("incomplete");
        assert!(verify(&cx, &image, &sidecar).is_err());
    }
}
