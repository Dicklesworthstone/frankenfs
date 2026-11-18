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

/// Mutable image I/O with external, restart-safe repair coverage.
pub mod live;

use crate::codec::encode_group;
use crate::por::{PorKey, compute_authenticator, verify_authenticator};
use asupersync::Cx;
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, GroupNumber};
use serde::{Deserialize, Serialize};
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
        self.image_bytes
            .div_ceil(u64::from(self.options.block_size))
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
            return Err(corrupt(
                "invalid, unsupported, or incomplete sidecar header",
            ));
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
            || group_digest
                != digest_parts(b"ffs-sidecar-group-v2", &[&self.header.seed, &metadata])
        {
            return Err(corrupt(
                "sidecar group metadata checksum or geometry mismatch",
            ));
        }
        let hashes = metadata[GROUP_PREFIX_BYTES..]
            .as_chunks::<DIGEST_BYTES>()
            .0
            .to_vec();
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

// ── Whole-Storage-Set Manifest, Provenance & Native Commit Binding (`bd-tqrnc`) ─

/// Magic bytes for a sealed multi-member storage-set protection manifest.
pub const SET_MANIFEST_MAGIC: &[u8; 8] = b"FFSRQSM3";
/// Magic bytes written durably at offset 0 before any member mutation begins.
pub const SET_PENDING_MAGIC: &[u8; 8] = b"FFSRQPM3";
/// Current storage-set manifest schema version.
pub const SET_MANIFEST_VERSION: u32 = 3;
pub(crate) const SET_MANIFEST_PREFIX_BYTES: usize = 64;
const SET_MANIFEST_TRAILER_BYTES: usize = 64;
const SET_MANIFEST_FLAG_AUTHENTICATED: u32 = 1;
const MAX_SET_MANIFEST_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Required role of an individual member within a protected storage set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    Data,
    Log,
    Special,
}

/// Bounded physical geometry of one member and its RaptorQ group layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberSliceGeometry {
    pub backing_bytes: u64,
    pub offset: u64,
    pub length: u64,
    pub block_size: u32,
    pub group_blocks: u32,
    pub repair_symbols: u32,
    pub groups: u32,
}

/// Cryptographic binding of one member's sidecar archive inside a [`StorageSetManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberProtectionBinding {
    pub member_index: u32,
    pub role: MemberRole,
    pub native_member_id: [u8; 16],
    pub geometry: MemberSliceGeometry,
    pub archive_filename: String,
    pub header_blake3: [u8; 32],
    pub snapshot_digest: [u8; 32],
    pub tables_root: [u8; 32],
}

/// Required topology of the complete storage set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum StorageSetTopology {
    SingleData,
    Ext4WithExternalLog,
    BtrfsDevices {
        num_devices: u32,
    },
    ZfsSingleLeaf,
    ZfsMirror {
        width: u8,
    },
    ZfsMultiMemberReadOnly {
        vdev_children: u32,
        member_count: u32,
    },
}

/// Selected logical view (partition, dataset, subvolume) bound to the storage set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedViewIdentity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition_selector: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zfs_dataset: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub btrfs_subvolume_id: Option<u64>,
}

/// Format-native durable commit/generation identity bound to a sealed protection point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "format")]
pub enum NativeCommitBinding {
    UninterpretedRaw,
    Ext4 {
        uuid: [u8; 16],
        blocks_count: u64,
        journal_uuid: [u8; 16],
        journal_inum: u32,
        state: u16,
    },
    Btrfs {
        fsid: [u8; 16],
        generation: u64,
        root_bytenr: u64,
        chunk_root_bytenr: u64,
        log_root: u64,
        num_devices: u64,
    },
    Fat {
        kind: String,
        volume_id: u32,
        total_sectors: u64,
        clean: bool,
    },
    Ntfs {
        volume_serial: u64,
        volume_bytes: u64,
        cluster_bytes: u32,
        record_bytes: u32,
        index_bytes: u32,
        mft_cluster: u64,
        mirror_cluster: u64,
        boot_blake3: [u8; 32],
        transaction_id: u32,
        commit_lsn: u64,
        checkpoint_lsn: Option<u64>,
        generation: u64,
        operation_digest: [u8; 32],
    },
    Zfs {
        pool_guid: u64,
        top_guid: u64,
        member_guids: Vec<u64>,
        guid_sum: u64,
        version: u64,
        ashift: u8,
        asize: u64,
        label_txg: u64,
        committed_txg: u64,
        published_slot: u32,
        root_bp_blake3: [u8; 32],
        generation: u64,
        operation_digest: [u8; 32],
    },
}

impl NativeCommitBinding {
    /// Concise deterministic summary string for audit ledgers and operator status.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::UninterpretedRaw => "raw".to_owned(),
            Self::Ext4 {
                blocks_count,
                journal_inum,
                state,
                ..
            } => format!("ext4:blocks={blocks_count}:j_inum={journal_inum}:state={state}"),
            Self::Btrfs {
                generation,
                root_bytenr,
                log_root,
                num_devices,
                ..
            } => {
                format!(
                    "btrfs:gen={generation}:root={root_bytenr}:log={log_root}:devs={num_devices}"
                )
            }
            Self::Fat {
                kind,
                volume_id,
                total_sectors,
                clean,
            } => format!("fat:{kind}:vol={volume_id:#010x}:sectors={total_sectors}:clean={clean}"),
            Self::Ntfs {
                volume_serial,
                transaction_id,
                commit_lsn,
                generation,
                ..
            } => format!(
                "ntfs:serial={volume_serial:#018x}:tx={transaction_id}:lsn={commit_lsn}:gen={generation}"
            ),
            Self::Zfs {
                pool_guid,
                committed_txg,
                published_slot,
                generation,
                ..
            } => format!(
                "zfs:pool={pool_guid}:txg={committed_txg}:slot={published_slot}:gen={generation}"
            ),
        }
    }
}

/// Provenance status recorded in a [`StorageSetManifest`].
///
/// Unkeyed BLAKE3 checksum agreement detects accidental corruption only; it is
/// NEVER authenticated provenance without a trusted root key (`PorKey`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum ProvenanceAuth {
    UnauthenticatedChecksum,
    AuthenticatedTrustedRoot { key_id: [u8; 16], mac_hex: String },
}

/// Caller trust policy when admitting or verifying a [`StorageSetManifest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustPolicy {
    /// Admit unauthenticated manifests (`authenticated_provenance = false`) or verify
    /// keyed manifests when no trusted root is mandated.
    AllowUnauthenticated,
    /// Require a valid constant-time `PorKey` keyed-BLAKE3 authenticator over the
    /// manifest; unauthenticated manifests or wrong-key MACs fail closed.
    RequireTrustedRoot { key: PorKey },
}

/// Derive a non-secret 16-byte key identifier from a 32-byte [`PorKey`].
#[must_use]
pub fn por_key_id(key: &PorKey) -> [u8; 16] {
    let full = digest_parts(b"ffs-sidecar-root-key-id-v3", &[key]);
    let mut id = [0_u8; 16];
    id.copy_from_slice(&full[..16]);
    id
}

/// Compute the Merkle-flat BLAKE3 root over all per-group `table_digest`s in a member archive.
#[must_use]
pub fn tables_root_digest(tables: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ffs-sidecar-tables-root-v3");
    hasher.update(&(tables.len() as u64).to_le_bytes());
    for table in tables {
        hasher.update(table);
    }
    *hasher.finalize().as_bytes()
}

/// Whole-storage-set manifest (`FFSRQSM3`) binding every required `Data`/`Log`/`Special`
/// member archive, slice geometry, topology, view, and native commit token into a
/// single atomic seal point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSetManifest {
    pub set_id: [u8; 16],
    pub generation: u64,
    pub filesystem: String,
    pub topology: StorageSetTopology,
    pub view: ProtectedViewIdentity,
    pub native_binding: NativeCommitBinding,
    pub members: Vec<MemberProtectionBinding>,
    pub provenance: ProvenanceAuth,
}

impl StorageSetManifest {
    /// Hex representation of `set_id` for structured telemetry and evidence ledgers.
    #[must_use]
    pub fn set_id_hex(&self) -> String {
        let mut out = String::with_capacity(32);
        for byte in self.set_id {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// Whether this manifest carries authenticated provenance from a trusted root key.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        matches!(
            self.provenance,
            ProvenanceAuth::AuthenticatedTrustedRoot { .. }
        )
    }

    /// Encode this manifest into its canonical binary envelope (`FFSRQSM3`), signing
    /// with `signing_key` when provided.
    pub fn encode(&self, signing_key: Option<&PorKey>) -> Result<Vec<u8>> {
        if self.generation == 0 {
            return Err(corrupt("storage-set manifest generation must be non-zero"));
        }
        if self.members.is_empty() {
            return Err(corrupt(
                "storage-set manifest must bind at least one member",
            ));
        }
        for (idx, member) in self.members.iter().enumerate() {
            if member.member_index as usize != idx {
                return Err(corrupt(
                    "storage-set manifest member indices must be contiguous 0..N",
                ));
            }
            if member.geometry.length == 0
                || member
                    .geometry
                    .offset
                    .checked_add(member.geometry.length)
                    .is_none_or(|end| end > member.geometry.backing_bytes)
            {
                return Err(corrupt(
                    "storage-set manifest member slice exceeds backing geometry",
                ));
            }
        }
        let mut normalized = self.clone();
        normalized.provenance = ProvenanceAuth::UnauthenticatedChecksum;
        let body_bytes = serde_json::to_vec(&normalized)
            .map_err(|err| corrupt(&format!("encode storage-set manifest JSON: {err}")))?;
        if body_bytes.len() > MAX_SET_MANIFEST_PAYLOAD_BYTES {
            return Err(corrupt("storage-set manifest payload exceeds 4 MiB bound"));
        }
        let payload_len = u32::try_from(body_bytes.len())
            .map_err(|_| corrupt("storage-set manifest payload overflows u32"))?;
        let flags = if signing_key.is_some() {
            SET_MANIFEST_FLAG_AUTHENTICATED
        } else {
            0
        };
        let mut prefix = [0_u8; SET_MANIFEST_PREFIX_BYTES];
        prefix[..8].copy_from_slice(SET_MANIFEST_MAGIC);
        prefix[8..12].copy_from_slice(&SET_MANIFEST_VERSION.to_le_bytes());
        prefix[12..20].copy_from_slice(&self.generation.to_le_bytes());
        prefix[20..36].copy_from_slice(&self.set_id);
        prefix[36..40].copy_from_slice(&payload_len.to_le_bytes());
        prefix[40..44].copy_from_slice(&flags.to_le_bytes());
        let prefix_hash = blake3::hash(&prefix[..44]);
        prefix[44..64].copy_from_slice(&prefix_hash.as_bytes()[..20]);

        let body_blake3 = digest_parts(
            b"ffs-storage-set-manifest-v3",
            &[&prefix[..44], &body_bytes],
        );
        let mac = signing_key.map_or([0_u8; 32], |key| {
            compute_authenticator(key, self.generation, &body_blake3)
        });

        let mut raw = Vec::with_capacity(
            SET_MANIFEST_PREFIX_BYTES + body_bytes.len() + SET_MANIFEST_TRAILER_BYTES,
        );
        raw.extend_from_slice(&prefix);
        raw.extend_from_slice(&body_bytes);
        raw.extend_from_slice(&body_blake3);
        raw.extend_from_slice(&mac);
        Ok(raw)
    }

    /// Decode and validate a [`StorageSetManifest`] from raw bytes against `trust_policy`.
    pub fn decode(raw: &[u8], trust_policy: TrustPolicy) -> Result<Self> {
        if raw.len() < SET_MANIFEST_PREFIX_BYTES + SET_MANIFEST_TRAILER_BYTES {
            return Err(corrupt("truncated storage-set manifest"));
        }
        if &raw[..8] == SET_PENDING_MAGIC {
            return Err(corrupt(
                "storage-set manifest has an unfinished write epoch; reconcile offline",
            ));
        }
        if &raw[..8] != SET_MANIFEST_MAGIC || read_u32(raw, 8)? != SET_MANIFEST_VERSION {
            return Err(corrupt(
                "invalid, unsupported, or incomplete storage-set manifest header",
            ));
        }
        let prefix_hash = blake3::hash(&raw[..44]);
        if raw[44..64] != prefix_hash.as_bytes()[..20] {
            return Err(corrupt("storage-set manifest prefix checksum mismatch"));
        }
        let generation = read_u64(raw, 12)?;
        let mut set_id = [0_u8; 16];
        set_id.copy_from_slice(&raw[20..36]);
        let payload_len = read_u32(raw, 36)? as usize;
        let flags = read_u32(raw, 40)?;
        if flags & !SET_MANIFEST_FLAG_AUTHENTICATED != 0
            || payload_len > MAX_SET_MANIFEST_PAYLOAD_BYTES
        {
            return Err(corrupt("unsupported storage-set manifest flags or length"));
        }
        let expected_total = SET_MANIFEST_PREFIX_BYTES + payload_len + SET_MANIFEST_TRAILER_BYTES;
        if raw.len() != expected_total {
            return Err(corrupt("storage-set manifest size mismatch"));
        }
        let body_bytes = &raw[SET_MANIFEST_PREFIX_BYTES..SET_MANIFEST_PREFIX_BYTES + payload_len];
        let trailer = &raw[SET_MANIFEST_PREFIX_BYTES + payload_len..];
        let mut stored_blake3 = [0_u8; 32];
        stored_blake3.copy_from_slice(&trailer[..32]);
        let mut stored_mac = [0_u8; 32];
        stored_mac.copy_from_slice(&trailer[32..64]);

        let expected_blake3 =
            digest_parts(b"ffs-storage-set-manifest-v3", &[&raw[..44], body_bytes]);
        if stored_blake3 != expected_blake3 {
            return Err(corrupt("storage-set manifest body checksum mismatch"));
        }

        let mut decoded: Self = serde_json::from_slice(body_bytes)
            .map_err(|err| corrupt(&format!("decode storage-set manifest JSON: {err}")))?;
        if decoded.generation != generation || decoded.set_id != set_id || generation == 0 {
            return Err(corrupt(
                "storage-set manifest envelope disagrees with body identity",
            ));
        }
        if decoded.members.is_empty() {
            return Err(corrupt("storage-set manifest contains zero members"));
        }
        for (idx, member) in decoded.members.iter().enumerate() {
            if member.member_index as usize != idx
                || member.geometry.length == 0
                || member
                    .geometry
                    .offset
                    .checked_add(member.geometry.length)
                    .is_none_or(|end| end > member.geometry.backing_bytes)
            {
                return Err(corrupt(
                    "storage-set manifest member index or slice geometry invalid",
                ));
            }
        }

        let is_signed = flags & SET_MANIFEST_FLAG_AUTHENTICATED != 0;
        match trust_policy {
            TrustPolicy::RequireTrustedRoot { key } => {
                if !is_signed
                    || !verify_authenticator(&key, generation, &expected_blake3, &stored_mac)
                {
                    return Err(corrupt(
                        "unauthenticated or wrong-key storage-set manifest; checksum agreement is not trusted provenance",
                    ));
                }
                let mac_hex = blake3::Hash::from_bytes(stored_mac).to_hex().to_string();
                decoded.provenance = ProvenanceAuth::AuthenticatedTrustedRoot {
                    key_id: por_key_id(&key),
                    mac_hex,
                };
            }
            TrustPolicy::AllowUnauthenticated => {
                if !is_signed && stored_mac != [0_u8; 32] {
                    return Err(corrupt(
                        "unsigned storage-set manifest carries non-zero MAC bytes",
                    ));
                }
                // Without the secret root key, even a signed manifest cannot be
                // elevated to AuthenticatedTrustedRoot!
                decoded.provenance = ProvenanceAuth::UnauthenticatedChecksum;
            }
        }
        Ok(decoded)
    }
}

/// Tests that spawn a child process hold this exclusively while the child
/// runs; tests that hold flocked image or archive descriptors hold it shared.
/// A spawned child inherits every test thread's open descriptors until it
/// execs, and a flock belongs to the open file description, so a lock a
/// sibling test had just released stayed held by the child and the sibling's
/// reopen failed with WouldBlock (two sidecar tests per run, never the same
/// two).
#[cfg(test)]
pub(crate) static TEST_CHILD_PROCESS_GATE: std::sync::RwLock<()> = std::sync::RwLock::new(());

/// Shared side of [`TEST_CHILD_PROCESS_GATE`], held for a test's lifetime.
#[cfg(test)]
pub(crate) fn test_flock_holder() -> std::sync::RwLockReadGuard<'static, ()> {
    TEST_CHILD_PROCESS_GATE
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture's directory plus the flock guard, released together.
    struct FixtureDir {
        _dir: tempfile::TempDir,
        _flocks: std::sync::RwLockReadGuard<'static, ()>,
    }

    fn fixture() -> (FixtureDir, std::path::PathBuf, std::path::PathBuf, Vec<u8>) {
        let flocks = test_flock_holder();
        let dir = tempfile::tempdir().expect("directory");
        let image = dir.path().join("image.img");
        let sidecar = dir.path().join("image.ffs-rq");
        let bytes: Vec<u8> = (0_usize..19 * 512 + 37)
            .map(|index| u8::try_from((index * 31 + index / 512) % 251).expect("fits u8"))
            .collect();
        std::fs::write(&image, &bytes).expect("image");
        (
            FixtureDir {
                _dir: dir,
                _flocks: flocks,
            },
            image,
            sidecar,
            bytes,
        )
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
        second
            .file
            .read_exact_at(&mut stale, parity_offset)
            .expect("other parity");
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
        assert!(
            report.matches_snapshot,
            "the source still matches its protection point"
        );
        assert_eq!(report.invalid_repair_symbols, 4);
        assert_eq!(report.valid_repair_symbols, 8);
        assert!(
            !report.is_healthy(),
            "stale parity is not healthy redundancy"
        );
    }

    #[test]
    fn sidecar_refuses_the_unbound_v1_format_even_with_a_valid_header_checksum() {
        let (_dir, image, sidecar, _) = fixture();
        let cx = Cx::for_testing();
        protect(&cx, &image, &sidecar, options()).expect("protect");
        let file = File::options()
            .read(true)
            .write(true)
            .open(&sidecar)
            .expect("sidecar");
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
        assert_eq!(
            std::fs::read(&sidecar).expect("retained"),
            b"existing archive"
        );
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
