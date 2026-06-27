#![forbid(unsafe_code)]
//! Higher-level btrfs operations: tree traversal, item enumeration.
//!
//! Builds on `ffs_ondisk::btrfs` parsing primitives. I/O-agnostic —
//! callers provide a read callback for physical byte access.

pub mod crash_consistency;
pub mod writeback;

use asupersync::Cx;
use ffs_mvcc::{CommitError, MvccStore, Transaction};
pub use ffs_ondisk::btrfs::*;
use ffs_types::{BlockNumber, CommitSeq, ParseError, Snapshot, TxnId};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;
use tracing::{debug, info, trace, warn};

/// A single leaf item yielded by tree traversal: key + raw payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsLeafEntry {
    pub key: BtrfsKey,
    pub data: Vec<u8>,
}

/// btrfs objectid for the root tree.
pub const BTRFS_ROOT_TREE_OBJECTID: u64 = 1;
/// btrfs objectid for the default filesystem tree.
pub const BTRFS_FS_TREE_OBJECTID: u64 = 5;

/// btrfs item type constants used by the read-only VFS path.
pub const BTRFS_ITEM_INODE_ITEM: u8 = 1;
pub const BTRFS_ITEM_DIR_ITEM: u8 = 84;
pub const BTRFS_ITEM_DIR_INDEX: u8 = 96;
pub const BTRFS_ITEM_INODE_REF: u8 = 12;
pub const BTRFS_ITEM_XATTR_ITEM: u8 = 24;
pub const BTRFS_ITEM_EXTENT_DATA: u8 = 108;
pub const BTRFS_ITEM_ROOT_ITEM: u8 = 132;

/// btrfs item type constants for extent/block-group management (write path).
pub const BTRFS_ITEM_EXTENT_ITEM: u8 = 168;
pub const BTRFS_ITEM_METADATA_ITEM: u8 = 169;
pub const BTRFS_ITEM_TREE_BLOCK_REF: u8 = 176;
pub const BTRFS_ITEM_EXTENT_DATA_REF: u8 = 178;
pub const BTRFS_ITEM_BLOCK_GROUP_ITEM: u8 = 192;
pub const BTRFS_ITEM_DEV_ITEM: u8 = 216;
/// Data-checksum item in the csum tree (kernel: `BTRFS_EXTENT_CSUM_KEY`).
pub const BTRFS_ITEM_EXTENT_CSUM: u8 = 128;
pub const BTRFS_ITEM_CHUNK: u8 = 228;
pub const BTRFS_ITEM_FREE_SPACE_INFO: u8 = 198;
pub const BTRFS_ITEM_FREE_SPACE_EXTENT: u8 = 199;
pub const BTRFS_ITEM_FREE_SPACE_BITMAP: u8 = 200;

/// Well-known tree objectids (kernel: fs/btrfs/btrfs_tree.h).
pub const BTRFS_EXTENT_TREE_OBJECTID: u64 = 2;
pub const BTRFS_CHUNK_TREE_OBJECTID: u64 = 3;
pub const BTRFS_DEV_TREE_OBJECTID: u64 = 4;
/// Root tree's dir entry inode (kernel: `BTRFS_ROOT_TREE_DIR_OBJECTID`).
pub const BTRFS_ROOT_TREE_DIR_OBJECTID: u64 = 6;
/// Data-checksum tree (kernel: `BTRFS_CSUM_TREE_OBJECTID`).
pub const BTRFS_CSUM_TREE_OBJECTID: u64 = 7;
/// Quota tree (kernel: `BTRFS_QUOTA_TREE_OBJECTID`).
pub const BTRFS_QUOTA_TREE_OBJECTID: u64 = 8;
/// Subvolume UUID lookup tree (kernel: `BTRFS_UUID_TREE_OBJECTID`).
pub const BTRFS_UUID_TREE_OBJECTID: u64 = 9;
/// Free-space tree v2 (kernel: `BTRFS_FREE_SPACE_TREE_OBJECTID`).
pub const BTRFS_FREE_SPACE_TREE_OBJECTID: u64 = 10;
/// Block-group tree v2 (kernel: `BTRFS_BLOCK_GROUP_TREE_OBJECTID`).
pub const BTRFS_BLOCK_GROUP_TREE_OBJECTID: u64 = 11;
/// Objectid shared by all data-checksum items in the csum tree
/// (kernel: `BTRFS_EXTENT_CSUM_OBJECTID`, defined as `-10`).
pub const BTRFS_EXTENT_CSUM_OBJECTID: u64 = 0xFFFF_FFFF_FFFF_FFF6;
/// On-disk size of a single crc32c data checksum (kernel: `BTRFS_CSUM_SIZE`
/// for the crc32c algorithm).
pub const BTRFS_CRC32C_CSUM_SIZE: usize = 4;

/// Block group type flags.
pub const BTRFS_BLOCK_GROUP_DATA: u64 = 1;
pub const BTRFS_BLOCK_GROUP_SYSTEM: u64 = 2;
pub const BTRFS_BLOCK_GROUP_METADATA: u64 = 4;

/// Directory entry type values stored in btrfs dir items.
pub const BTRFS_FT_UNKNOWN: u8 = 0;
pub const BTRFS_FT_REG_FILE: u8 = 1;
pub const BTRFS_FT_DIR: u8 = 2;
pub const BTRFS_FT_CHRDEV: u8 = 3;
pub const BTRFS_FT_BLKDEV: u8 = 4;
pub const BTRFS_FT_FIFO: u8 = 5;
pub const BTRFS_FT_SOCK: u8 = 6;
pub const BTRFS_FT_SYMLINK: u8 = 7;

/// File extent type values in EXTENT_DATA payloads.
pub const BTRFS_FILE_EXTENT_INLINE: u8 = 0;
pub const BTRFS_FILE_EXTENT_REG: u8 = 1;
pub const BTRFS_FILE_EXTENT_PREALLOC: u8 = 2;

/// Compression type values in EXTENT_DATA payloads.
pub const BTRFS_COMPRESS_NONE: u8 = 0;
pub const BTRFS_COMPRESS_ZLIB: u8 = 1;
pub const BTRFS_COMPRESS_LZO: u8 = 2;
pub const BTRFS_COMPRESS_ZSTD: u8 = 3;

// ── btrfs inode flags (from fs/btrfs/btrfs_inode.h) ────────────────────────
/// Do not checksum data.
pub const BTRFS_INODE_NODATASUM: u64 = 1 << 0;
/// Do not COW data (implies NODATASUM).
pub const BTRFS_INODE_NODATACOW: u64 = 1 << 1;
/// Read-only inode (subvolume-level).
pub const BTRFS_INODE_READONLY: u64 = 1 << 2;
/// Do not compress data.
pub const BTRFS_INODE_NOCOMPRESS: u64 = 1 << 3;
/// Has preallocated extents.
pub const BTRFS_INODE_PREALLOC: u64 = 1 << 4;
/// Sync writes (O_SYNC equivalent).
pub const BTRFS_INODE_SYNC: u64 = 1 << 5;
/// Immutable inode.
pub const BTRFS_INODE_IMMUTABLE: u64 = 1 << 6;
/// Append-only inode.
pub const BTRFS_INODE_APPEND: u64 = 1 << 7;
/// Do not dump (nodump).
pub const BTRFS_INODE_NODUMP: u64 = 1 << 8;
/// Do not update atime.
pub const BTRFS_INODE_NOATIME: u64 = 1 << 9;
/// Sync directory changes.
pub const BTRFS_INODE_DIRSYNC: u64 = 1 << 10;
/// Compress data.
pub const BTRFS_INODE_COMPRESS: u64 = 1 << 11;

/// Compute the btrfs `DIR_ITEM`/`XATTR_ITEM` name hash (the key `offset`).
///
/// btrfs hashes entry names with `crc32c` seeded with `~1` (the kernel's
/// `btrfs_name_hash` = `crc32c((u32)~1, name, len)`), using the *raw*
/// continuation value with no final bit inversion. The `crc32c` crate's
/// `crc32c_append(crc, data)` follows the streaming convention
/// `out = !raw(!crc, data)`, so the raw kernel hash `raw(~1, name)` is obtained
/// as `!crc32c_append(!~1, name) = !crc32c_append(1, name)`.
///
/// Using a plain seed-0 `crc32c` here (as earlier revisions did) produced the
/// standard reflected crc32c instead, so FrankenFS-written `DIR_ITEM` keys did
/// not match the hash real `btrfs check` recomputes from the stored name
/// (bd-x36qn: "Dir items with mismatch hash"). This restores on-disk parity.
#[inline]
#[must_use]
pub fn btrfs_name_hash(name: &[u8]) -> u32 {
    !ffs_types::crc32c_append(1, name)
}

/// Compute the btrfs `hash_extent_data_ref` — the `offset` (third) component of
/// a keyed `EXTENT_DATA_REF` item's key for a shared data extent.
///
/// Mirrors the kernel `fs/btrfs/extent-tree.c::hash_extent_data_ref`:
/// ```text
/// high = crc32c(~0, root_objectid_le64)               // raw continuation
/// low  = crc32c(crc32c(~0, owner_le64), offset_le64)   // raw, chained
/// return ((u64)high << 31) ^ (u64)low
/// ```
/// where the kernel's `crc32c(seed, data)` is the *raw* running value. Using the
/// same btrfs-check-validated convention as [`btrfs_name_hash`] (bd-x36qn) —
/// `raw(seed, data) = !crc32c_append(!seed, data)` — gives
/// `raw(~0, d) = !crc32c_append(0, d)`, and the chained `raw(raw(~0, owner),
/// offset) = !crc32c_append(crc32c_append(0, owner), offset)` (the inner
/// `crc32c_append` continuation matches the kernel's running CRC over
/// `owner ++ offset`).
#[must_use]
pub fn hash_extent_data_ref(root: u64, owner: u64, offset: u64) -> u64 {
    let high = !ffs_types::crc32c_append(0, &root.to_le_bytes());
    let low = !ffs_types::crc32c_append(
        ffs_types::crc32c_append(0, &owner.to_le_bytes()),
        &offset.to_le_bytes(),
    );
    (u64::from(high) << 31) ^ u64::from(low)
}

/// Build the csum-tree leaf item for one on-disk data extent.
///
/// btrfs stores data checksums in the csum tree (`BTRFS_CSUM_TREE_OBJECTID`) as
/// `EXTENT_CSUM` items. Each item's key is
/// `{ objectid: BTRFS_EXTENT_CSUM_OBJECTID, type: BTRFS_ITEM_EXTENT_CSUM,
/// offset: <logical byte address of the extent start> }`, and its value is a
/// densely packed array of one crc32c per `sectorsize` bytes of extent data,
/// each stored little-endian (`BTRFS_CRC32C_CSUM_SIZE` bytes). The kernel
/// verifies every data read against these checksums on a `datasum`
/// filesystem, so a file written without them is unreadable (EIO).
///
/// This is the pure foundational primitive for csum-tree population (bd-x3fcu):
/// it computes the key and packed checksum bytes for a single contiguous
/// extent. Wiring it into the COW commit (capturing extents during write,
/// inserting these items, and updating the csum root) is the follow-on work.
///
/// `data` must be the on-disk (sector-padded) extent bytes, i.e. a non-empty
/// whole multiple of `sectorsize`; `sectorsize` must be non-zero. Either
/// violation returns [`BtrfsMutationError::InvalidConfig`] rather than
/// producing a silently truncated checksum run.
///
/// # Errors
/// Returns [`BtrfsMutationError::InvalidConfig`] if `sectorsize` is zero or if
/// `data.len()` is not a positive multiple of `sectorsize`.
pub fn build_extent_csum_item(
    disk_bytenr: u64,
    data: &[u8],
    sectorsize: usize,
) -> Result<(BtrfsKey, Vec<u8>), BtrfsMutationError> {
    if sectorsize == 0 {
        return Err(BtrfsMutationError::InvalidConfig(
            "sectorsize must be non-zero",
        ));
    }
    if data.is_empty() || data.len() % sectorsize != 0 {
        return Err(BtrfsMutationError::InvalidConfig(
            "data must be a positive whole multiple of sectorsize",
        ));
    }
    let sectors = data.len() / sectorsize;
    let mut value = Vec::with_capacity(sectors * BTRFS_CRC32C_CSUM_SIZE);
    for sector in data.chunks_exact(sectorsize) {
        let csum = ffs_types::crc32c(sector);
        value.extend_from_slice(&csum.to_le_bytes());
    }
    let key = BtrfsKey {
        objectid: BTRFS_EXTENT_CSUM_OBJECTID,
        item_type: BTRFS_ITEM_EXTENT_CSUM,
        offset: disk_bytenr,
    };
    Ok((key, value))
}

/// Maximum number of crc32c data checksums that fit in a single EXTENT_CSUM
/// item in a leaf of `nodesize` bytes.
///
/// A leaf is `BTRFS_HEADER_SIZE` (101) of header plus item slots; a single
/// item costs its 25-byte item entry plus its value bytes. So the value of one
/// EXTENT_CSUM item that is alone in a leaf can be at most
/// `nodesize - 101 - 25` bytes, i.e. `(nodesize - 126) / 4` crc32c checksums.
/// Items at or below this bound always fit in a leaf (the B-tree handles
/// packing several smaller items per leaf); the kernel accepts an EXTENT_CSUM
/// item of any valid length, so any split that respects this bound is
/// kernel-readable.
#[must_use]
pub fn max_data_csums_per_item(nodesize: u32) -> usize {
    let usable = (nodesize as usize).saturating_sub(101 + 25);
    (usable / BTRFS_CRC32C_CSUM_SIZE).max(1)
}

/// Build the csum-tree leaf items for one contiguous on-disk data extent,
/// splitting into multiple EXTENT_CSUM items so each fits in a leaf.
///
/// [`build_extent_csum_item`] packs every sector's checksum into a single
/// item, which overflows a leaf once an extent has more than
/// [`max_data_csums_per_item`] sectors (a multi-MiB extent). btrfs stores such
/// an extent's checksums across several EXTENT_CSUM items, each keyed by the
/// disk bytenr of the first sector it covers. This returns that ordered set:
/// each item covers up to `max_csums_per_item` consecutive sectors, and item
/// `n`'s key offset is `disk_bytenr + n * max_csums_per_item * sectorsize`.
///
/// `data` must be a non-empty whole multiple of `sectorsize`; `sectorsize` and
/// `max_csums_per_item` must be non-zero. Pass
/// `max_data_csums_per_item(nodesize)` for `max_csums_per_item`.
///
/// # Errors
/// Returns [`BtrfsMutationError::InvalidConfig`] on a zero `sectorsize` /
/// `max_csums_per_item`, or `data` that is not a positive multiple of
/// `sectorsize`.
pub fn build_extent_csum_items(
    disk_bytenr: u64,
    data: &[u8],
    sectorsize: usize,
    max_csums_per_item: usize,
) -> Result<Vec<(BtrfsKey, Vec<u8>)>, BtrfsMutationError> {
    if max_csums_per_item == 0 {
        return Err(BtrfsMutationError::InvalidConfig(
            "max_csums_per_item must be non-zero",
        ));
    }
    // build_extent_csum_item validates sectorsize / data shape.
    let chunk_bytes =
        max_csums_per_item
            .checked_mul(sectorsize)
            .ok_or(BtrfsMutationError::InvalidConfig(
                "max_csums_per_item * sectorsize overflows",
            ))?;
    if chunk_bytes == 0 {
        return Err(BtrfsMutationError::InvalidConfig(
            "sectorsize must be non-zero",
        ));
    }
    if data.is_empty() || data.len() % sectorsize != 0 {
        return Err(BtrfsMutationError::InvalidConfig(
            "data must be a positive whole multiple of sectorsize",
        ));
    }
    let mut items = Vec::with_capacity(data.len().div_ceil(chunk_bytes));
    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + chunk_bytes).min(data.len());
        let chunk_bytenr =
            disk_bytenr
                .checked_add(offset as u64)
                .ok_or(BtrfsMutationError::InvalidConfig(
                    "extent disk bytenr overflows",
                ))?;
        items.push(build_extent_csum_item(
            chunk_bytenr,
            &data[offset..end],
            sectorsize,
        )?);
        offset = end;
    }
    Ok(items)
}

/// Look up the expected crc32c for the on-disk sector at `disk_bytenr` among a
/// set of EXTENT_CSUM items (the read-side counterpart of
/// [`build_extent_csum_items`]).
///
/// `items` are `(key, packed_csums)` pairs as stored in the csum tree, each key
/// carrying the disk bytenr of the item's first sector in `key.offset` (the
/// caller gathers the relevant items via a tree range query; order does not
/// matter). Returns the checksum recorded for the sector that begins at
/// `disk_bytenr`, or `None` if no item covers it or `disk_bytenr` is not
/// sector-aligned to an item's coverage. A reader/scrub feeds the result to
/// [`verify_extent_csum`] (or compares directly) to detect data corruption.
#[must_use]
pub fn lookup_data_block_csum(
    items: &[(BtrfsKey, Vec<u8>)],
    disk_bytenr: u64,
    sectorsize: usize,
) -> Option<u32> {
    if sectorsize == 0 {
        return None;
    }
    // The covering item is the one with the greatest offset <= disk_bytenr
    // whose checksum run actually reaches disk_bytenr.
    let mut best: Option<(u64, &[u8])> = None;
    for (key, value) in items {
        if key.item_type != BTRFS_ITEM_EXTENT_CSUM || key.objectid != BTRFS_EXTENT_CSUM_OBJECTID {
            continue;
        }
        if key.offset > disk_bytenr {
            continue;
        }
        if best.is_none_or(|(off, _)| key.offset > off) {
            best = Some((key.offset, value.as_slice()));
        }
    }
    let (item_offset, value) = best?;
    let delta = disk_bytenr.checked_sub(item_offset)?;
    let delta = usize::try_from(delta).ok()?;
    if delta % sectorsize != 0 {
        return None;
    }
    let index = delta / sectorsize;
    let base = index.checked_mul(BTRFS_CRC32C_CSUM_SIZE)?;
    let end = base.checked_add(BTRFS_CRC32C_CSUM_SIZE)?;
    if end > value.len() {
        return None; // beyond this item's coverage
    }
    Some(u32::from_le_bytes([
        value[base],
        value[base + 1],
        value[base + 2],
        value[base + 3],
    ]))
}

/// First-mismatch detail from [`verify_extent_csum`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CsumMismatch {
    /// Zero-based index of the first sector whose checksum did not match.
    pub sector_index: usize,
    /// The crc32c recorded in the csum tree for that sector.
    pub expected: u32,
    /// The crc32c actually computed over the on-disk sector bytes.
    pub actual: u32,
}

/// Verify a contiguous on-disk data extent against its packed crc32c checksums.
///
/// Read-side inverse of [`build_extent_csum_item`]: given the extent's
/// sector-padded bytes and the densely packed little-endian crc32c-per-sector
/// value from its EXTENT_CSUM item, recompute each sector's crc32c (the same
/// `ffs_types::crc32c` the kernel uses) and compare. The kernel returns EIO on
/// the first mismatch when reading a `datasum` file; a reader or scrub built on
/// this can do the same instead of silently returning corrupted data.
///
/// # Errors
/// - `Err(Err(BtrfsMutationError::InvalidConfig))` if `sectorsize` is zero,
///   `data` is not a positive whole multiple of `sectorsize`, or
///   `expected_csums` length does not match the sector count.
/// - `Err(Ok(CsumMismatch))` on the first sector whose checksum does not match.
pub fn verify_extent_csum(
    data: &[u8],
    sectorsize: usize,
    expected_csums: &[u8],
) -> Result<(), Result<CsumMismatch, BtrfsMutationError>> {
    if sectorsize == 0 {
        return Err(Err(BtrfsMutationError::InvalidConfig(
            "sectorsize must be non-zero",
        )));
    }
    if data.is_empty() || data.len() % sectorsize != 0 {
        return Err(Err(BtrfsMutationError::InvalidConfig(
            "data must be a positive whole multiple of sectorsize",
        )));
    }
    let sectors = data.len() / sectorsize;
    if expected_csums.len() != sectors * BTRFS_CRC32C_CSUM_SIZE {
        return Err(Err(BtrfsMutationError::InvalidConfig(
            "expected_csums length does not match sector count",
        )));
    }
    for (index, sector) in data.chunks_exact(sectorsize).enumerate() {
        let base = index * BTRFS_CRC32C_CSUM_SIZE;
        let expected = u32::from_le_bytes([
            expected_csums[base],
            expected_csums[base + 1],
            expected_csums[base + 2],
            expected_csums[base + 3],
        ]);
        let actual = ffs_types::crc32c(sector);
        if actual != expected {
            return Err(Ok(CsumMismatch {
                sector_index: index,
                expected,
                actual,
            }));
        }
    }
    Ok(())
}

/// Convert btrfs inode flags to generic FS_*_FL flags for `FS_IOC_GETFLAGS`.
///
/// Maps kernel `btrfs_inode_flags_to_fsflags()` from `fs/btrfs/ioctl.c`.
#[must_use]
pub fn btrfs_inode_flags_to_fsflags(btrfs_flags: u64) -> u32 {
    use ffs_types::{
        EXT4_APPEND_FL, EXT4_COMPR_FL, EXT4_DIRSYNC_FL, EXT4_IMMUTABLE_FL, EXT4_NOATIME_FL,
        EXT4_NOCOMPR_FL, EXT4_NODUMP_FL, EXT4_SYNC_FL, FS_NOCOW_FL,
    };

    let mut fs_flags: u32 = 0;
    if btrfs_flags & BTRFS_INODE_SYNC != 0 {
        fs_flags |= EXT4_SYNC_FL;
    }
    if btrfs_flags & BTRFS_INODE_IMMUTABLE != 0 {
        fs_flags |= EXT4_IMMUTABLE_FL;
    }
    if btrfs_flags & BTRFS_INODE_APPEND != 0 {
        fs_flags |= EXT4_APPEND_FL;
    }
    if btrfs_flags & BTRFS_INODE_NODUMP != 0 {
        fs_flags |= EXT4_NODUMP_FL;
    }
    if btrfs_flags & BTRFS_INODE_NOATIME != 0 {
        fs_flags |= EXT4_NOATIME_FL;
    }
    if btrfs_flags & BTRFS_INODE_DIRSYNC != 0 {
        fs_flags |= EXT4_DIRSYNC_FL;
    }
    if btrfs_flags & BTRFS_INODE_NODATACOW != 0 {
        fs_flags |= FS_NOCOW_FL;
    }
    if btrfs_flags & BTRFS_INODE_COMPRESS != 0 {
        fs_flags |= EXT4_COMPR_FL;
    }
    if btrfs_flags & BTRFS_INODE_NOCOMPRESS != 0 {
        fs_flags |= EXT4_NOCOMPR_FL;
    }
    fs_flags
}

/// Convert generic FS_*_FL flags to btrfs inode flags for `FS_IOC_SETFLAGS`.
///
/// Maps kernel `btrfs_ioctl_setflags()` flag conversion from `fs/btrfs/ioctl.c`.
/// Only user-settable flags are converted; kernel-internal flags are ignored.
#[must_use]
pub fn fsflags_to_btrfs_inode_flags(fs_flags: u32) -> u64 {
    use ffs_types::{
        EXT4_APPEND_FL, EXT4_COMPR_FL, EXT4_DIRSYNC_FL, EXT4_IMMUTABLE_FL, EXT4_NOATIME_FL,
        EXT4_NOCOMPR_FL, EXT4_NODUMP_FL, EXT4_SYNC_FL, FS_NOCOW_FL,
    };

    let mut btrfs_flags: u64 = 0;
    if fs_flags & EXT4_SYNC_FL != 0 {
        btrfs_flags |= BTRFS_INODE_SYNC;
    }
    if fs_flags & EXT4_IMMUTABLE_FL != 0 {
        btrfs_flags |= BTRFS_INODE_IMMUTABLE;
    }
    if fs_flags & EXT4_APPEND_FL != 0 {
        btrfs_flags |= BTRFS_INODE_APPEND;
    }
    if fs_flags & EXT4_NODUMP_FL != 0 {
        btrfs_flags |= BTRFS_INODE_NODUMP;
    }
    if fs_flags & EXT4_NOATIME_FL != 0 {
        btrfs_flags |= BTRFS_INODE_NOATIME;
    }
    if fs_flags & EXT4_DIRSYNC_FL != 0 {
        btrfs_flags |= BTRFS_INODE_DIRSYNC;
    }
    if fs_flags & FS_NOCOW_FL != 0 {
        // NODATACOW implies NODATASUM
        btrfs_flags |= BTRFS_INODE_NODATACOW | BTRFS_INODE_NODATASUM;
    }
    if fs_flags & EXT4_COMPR_FL != 0 {
        btrfs_flags |= BTRFS_INODE_COMPRESS;
    }
    if fs_flags & EXT4_NOCOMPR_FL != 0 {
        btrfs_flags |= BTRFS_INODE_NOCOMPRESS;
    }
    btrfs_flags
}

/// Mask of FS_*_FL flags that are user-settable on btrfs inodes.
pub const BTRFS_USER_SETTABLE_FSFLAGS: u32 = {
    use ffs_types::{
        EXT4_APPEND_FL, EXT4_COMPR_FL, EXT4_DIRSYNC_FL, EXT4_IMMUTABLE_FL, EXT4_NOATIME_FL,
        EXT4_NOCOMPR_FL, EXT4_NODUMP_FL, EXT4_SYNC_FL,
    };
    const FS_NOCOW_FL: u32 = 0x0080_0000;
    EXT4_SYNC_FL
        | EXT4_IMMUTABLE_FL
        | EXT4_APPEND_FL
        | EXT4_NODUMP_FL
        | EXT4_NOATIME_FL
        | EXT4_DIRSYNC_FL
        | FS_NOCOW_FL
        | EXT4_COMPR_FL
        | EXT4_NOCOMPR_FL
};

/// Convert btrfs inode flags to FS_XFLAG_* for `FS_IOC_FSGETXATTR`.
///
/// Maps kernel `btrfs_iflags_to_xflags()` from `fs/btrfs/ioctl.c`.
/// Unlike [`btrfs_inode_flags_to_fsflags`], this produces FS_XFLAG_* bits
/// rather than FS_*_FL bits.
#[must_use]
pub fn btrfs_inode_flags_to_xflags(btrfs_flags: u64) -> u32 {
    const FS_XFLAG_SYNC: u32 = 0x0000_0020;
    const FS_XFLAG_IMMUTABLE: u32 = 0x0000_0008;
    const FS_XFLAG_APPEND: u32 = 0x0000_0010;
    const FS_XFLAG_NODUMP: u32 = 0x0000_0080;
    const FS_XFLAG_NOATIME: u32 = 0x0000_0040;
    const FS_XFLAG_NODEFRAG: u32 = 0x0000_2000;

    let mut xflags: u32 = 0;
    if btrfs_flags & BTRFS_INODE_SYNC != 0 {
        xflags |= FS_XFLAG_SYNC;
    }
    if btrfs_flags & BTRFS_INODE_IMMUTABLE != 0 {
        xflags |= FS_XFLAG_IMMUTABLE;
    }
    if btrfs_flags & BTRFS_INODE_APPEND != 0 {
        xflags |= FS_XFLAG_APPEND;
    }
    if btrfs_flags & BTRFS_INODE_NODUMP != 0 {
        xflags |= FS_XFLAG_NODUMP;
    }
    if btrfs_flags & BTRFS_INODE_NOATIME != 0 {
        xflags |= FS_XFLAG_NOATIME;
    }
    if btrfs_flags & BTRFS_INODE_NOCOMPRESS != 0 {
        xflags |= FS_XFLAG_NODEFRAG;
    }
    if xflags != 0 {
        const FS_XFLAG_HASATTR: u32 = 0x8000_0000;
        xflags |= FS_XFLAG_HASATTR;
    }
    xflags
}

/// Convert FS_XFLAG_* to btrfs inode flags for `FS_IOC_FSSETXATTR`.
///
/// Maps kernel `btrfs_xflags_to_iflags()` from `fs/btrfs/ioctl.c`.
/// Inverse of [`btrfs_inode_flags_to_xflags`].
#[must_use]
pub fn xflags_to_btrfs_inode_flags(xflags: u32) -> u64 {
    const FS_XFLAG_SYNC: u32 = 0x0000_0020;
    const FS_XFLAG_IMMUTABLE: u32 = 0x0000_0008;
    const FS_XFLAG_APPEND: u32 = 0x0000_0010;
    const FS_XFLAG_NODUMP: u32 = 0x0000_0080;
    const FS_XFLAG_NOATIME: u32 = 0x0000_0040;
    const FS_XFLAG_NODEFRAG: u32 = 0x0000_2000;

    let mut btrfs_flags: u64 = 0;
    if xflags & FS_XFLAG_SYNC != 0 {
        btrfs_flags |= BTRFS_INODE_SYNC;
    }
    if xflags & FS_XFLAG_IMMUTABLE != 0 {
        btrfs_flags |= BTRFS_INODE_IMMUTABLE;
    }
    if xflags & FS_XFLAG_APPEND != 0 {
        btrfs_flags |= BTRFS_INODE_APPEND;
    }
    if xflags & FS_XFLAG_NODUMP != 0 {
        btrfs_flags |= BTRFS_INODE_NODUMP;
    }
    if xflags & FS_XFLAG_NOATIME != 0 {
        btrfs_flags |= BTRFS_INODE_NOATIME;
    }
    if xflags & FS_XFLAG_NODEFRAG != 0 {
        btrfs_flags |= BTRFS_INODE_NOCOMPRESS;
    }
    btrfs_flags
}

/// Mask of FS_XFLAG_* that are user-settable on btrfs inodes.
pub const BTRFS_USER_SETTABLE_XFLAGS: u32 = {
    const FS_XFLAG_SYNC: u32 = 0x0000_0020;
    const FS_XFLAG_IMMUTABLE: u32 = 0x0000_0008;
    const FS_XFLAG_APPEND: u32 = 0x0000_0010;
    const FS_XFLAG_NODUMP: u32 = 0x0000_0080;
    const FS_XFLAG_NOATIME: u32 = 0x0000_0040;
    const FS_XFLAG_NODEFRAG: u32 = 0x0000_2000;
    FS_XFLAG_SYNC
        | FS_XFLAG_IMMUTABLE
        | FS_XFLAG_APPEND
        | FS_XFLAG_NODUMP
        | FS_XFLAG_NOATIME
        | FS_XFLAG_NODEFRAG
};

/// Highest valid btrfs tree level. The kernel's `BTRFS_MAX_LEVEL` is the
/// level count (8), so valid on-disk levels are `0..=7`.
pub const BTRFS_MAX_TREE_LEVEL: u8 = 7;

/// Internal MVCC metadata block base used for btrfs transaction manifests.
const BTRFS_TX_META_BASE_BLOCK: u64 = 0x4_0000_0000;
/// Internal MVCC metadata block base used for tree-root pointer updates.
const BTRFS_TX_TREE_ROOT_BASE_BLOCK: u64 = 0x4_1000_0000;
/// Internal MVCC metadata block base used for pending-free ledgers.
const BTRFS_TX_PENDING_FREE_BASE_BLOCK: u64 = 0x4_2000_0000;

const BTRFS_ROOT_ITEM_LEGACY_SIZE: usize = 239;
const BTRFS_ROOT_ITEM_GENERATION_OFFSET: usize = 160;
const BTRFS_ROOT_ITEM_ROOT_DIRID_OFFSET: usize = 168;
const BTRFS_ROOT_ITEM_BYTENR_OFFSET: usize = 176;
const BTRFS_ROOT_ITEM_FLAGS_OFFSET: usize = 208;
const BTRFS_ROOT_ITEM_REFS_OFFSET: usize = 216;
const BTRFS_ROOT_ITEM_LEVEL_OFFSET: usize = 238;
const BTRFS_ROOT_ITEM_GENERATION_V2_OFFSET: usize = 239;
const BTRFS_ROOT_ITEM_UUID_OFFSET: usize = 247;
const BTRFS_ROOT_ITEM_PARENT_UUID_OFFSET: usize = 263;
const BTRFS_ROOT_ITEM_UUID_END: usize = BTRFS_ROOT_ITEM_UUID_OFFSET + 16;
const BTRFS_ROOT_ITEM_PARENT_UUID_END: usize = BTRFS_ROOT_ITEM_PARENT_UUID_OFFSET + 16;

/// Full ROOT_ITEM size with V2 extension fields.
pub const BTRFS_ROOT_ITEM_SIZE: usize = 279;

/// Parsed subset of `btrfs_root_item` needed for tree bootstrapping,
/// subvolume enumeration, and snapshot navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsRootItem {
    /// Logical address of the tree root block (`bytenr`).
    pub bytenr: u64,
    /// Root tree level (`0` for leaf roots).
    pub level: u8,
    /// Generation when this root was last modified.
    pub generation: u64,
    /// Directory inode for the root of this subvolume (typically 256).
    pub root_dirid: u64,
    /// Flags (bit 0 = read-only subvolume).
    pub flags: u64,
    /// Reference count.
    pub refs: u64,
    /// UUID of this subvolume/snapshot (zero if not set).
    pub uuid: [u8; 16],
    /// Parent UUID — set when this is a snapshot (identifies source subvolume).
    pub parent_uuid: [u8; 16],
}

impl BtrfsRootItem {
    /// Update a ROOT_ITEM blob in-place with new root location and generation.
    ///
    /// This patches the bytenr, level, generation, and generation_v2 fields
    /// at their known offsets, preserving all other fields (inode_item, etc.).
    ///
    /// # Arguments
    /// * `data` - Mutable ROOT_ITEM data (must be at least 279 bytes)
    /// * `bytenr` - New root node location
    /// * `level` - New root level
    /// * `generation` - Current transaction generation
    pub fn patch_root_commit(
        data: &mut [u8],
        bytenr: u64,
        level: u8,
        generation: u64,
    ) -> Result<(), ParseError> {
        if data.len() < BTRFS_ROOT_ITEM_SIZE {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_ROOT_ITEM_SIZE,
                offset: 0,
                actual: data.len(),
            });
        }
        // Update bytenr at offset 176
        data[BTRFS_ROOT_ITEM_BYTENR_OFFSET..BTRFS_ROOT_ITEM_BYTENR_OFFSET + 8]
            .copy_from_slice(&bytenr.to_le_bytes());
        // Update generation at offset 160
        data[BTRFS_ROOT_ITEM_GENERATION_OFFSET..BTRFS_ROOT_ITEM_GENERATION_OFFSET + 8]
            .copy_from_slice(&generation.to_le_bytes());
        // Update level at offset 238
        data[BTRFS_ROOT_ITEM_LEVEL_OFFSET] = level;
        // Update generation_v2 at offset 239 (must match generation for UUID fields to be valid)
        data[BTRFS_ROOT_ITEM_GENERATION_V2_OFFSET..BTRFS_ROOT_ITEM_GENERATION_V2_OFFSET + 8]
            .copy_from_slice(&generation.to_le_bytes());
        Ok(())
    }

    /// Update the flags field in a ROOT_ITEM blob in-place.
    ///
    /// # Arguments
    /// * `data` - Mutable ROOT_ITEM data (must be at least 279 bytes)
    /// * `flags` - New flags value
    pub fn patch_flags(data: &mut [u8], flags: u64) -> Result<(), ParseError> {
        if data.len() < BTRFS_ROOT_ITEM_SIZE {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_ROOT_ITEM_SIZE,
                offset: 0,
                actual: data.len(),
            });
        }
        data[BTRFS_ROOT_ITEM_FLAGS_OFFSET..BTRFS_ROOT_ITEM_FLAGS_OFFSET + 8]
            .copy_from_slice(&flags.to_le_bytes());
        Ok(())
    }

    /// Create a minimal ROOT_ITEM blob suitable for new trees.
    ///
    /// Sets essential fields (bytenr, level, generation, root_dirid, refs)
    /// and zeros the rest (inode_item, drop_progress, etc.).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; BTRFS_ROOT_ITEM_SIZE];
        // generation at offset 160
        buf[BTRFS_ROOT_ITEM_GENERATION_OFFSET..BTRFS_ROOT_ITEM_GENERATION_OFFSET + 8]
            .copy_from_slice(&self.generation.to_le_bytes());
        // root_dirid at offset 168
        buf[BTRFS_ROOT_ITEM_ROOT_DIRID_OFFSET..BTRFS_ROOT_ITEM_ROOT_DIRID_OFFSET + 8]
            .copy_from_slice(&self.root_dirid.to_le_bytes());
        // bytenr at offset 176
        buf[BTRFS_ROOT_ITEM_BYTENR_OFFSET..BTRFS_ROOT_ITEM_BYTENR_OFFSET + 8]
            .copy_from_slice(&self.bytenr.to_le_bytes());
        // flags at offset 208
        buf[BTRFS_ROOT_ITEM_FLAGS_OFFSET..BTRFS_ROOT_ITEM_FLAGS_OFFSET + 8]
            .copy_from_slice(&self.flags.to_le_bytes());
        // refs at offset 216 (u32)
        #[allow(clippy::cast_possible_truncation)]
        let refs_u32 = self.refs.min(u64::from(u32::MAX)) as u32;
        buf[BTRFS_ROOT_ITEM_REFS_OFFSET..BTRFS_ROOT_ITEM_REFS_OFFSET + 4]
            .copy_from_slice(&refs_u32.to_le_bytes());
        // level at offset 238
        buf[BTRFS_ROOT_ITEM_LEVEL_OFFSET] = self.level;
        // generation_v2 at offset 239
        buf[BTRFS_ROOT_ITEM_GENERATION_V2_OFFSET..BTRFS_ROOT_ITEM_GENERATION_V2_OFFSET + 8]
            .copy_from_slice(&self.generation.to_le_bytes());
        // uuid at offset 247
        buf[BTRFS_ROOT_ITEM_UUID_OFFSET..BTRFS_ROOT_ITEM_UUID_END].copy_from_slice(&self.uuid);
        // parent_uuid at offset 263
        buf[BTRFS_ROOT_ITEM_PARENT_UUID_OFFSET..BTRFS_ROOT_ITEM_PARENT_UUID_END]
            .copy_from_slice(&self.parent_uuid);
        buf
    }
}

/// A parsed btrfs ROOT_REF item linking parent subvolume to child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsRootRef {
    /// Directory inode in parent subvolume containing this entry.
    pub dirid: u64,
    /// Sequence number.
    pub sequence: u64,
    /// Name of the subvolume entry.
    pub name: Vec<u8>,
}

/// One decoded btrfs INODE_REF entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsInodeRef {
    /// Directory index for the name within the parent inode.
    pub index: u64,
    /// Directory entry name for this child in the parent directory.
    pub name: Vec<u8>,
}

impl BtrfsInodeRef {
    /// Fallibly serialize to the on-disk INODE_REF entry layout.
    ///
    /// Layout: index(8) + name_len(2) + name bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidField`] when the name cannot fit in the
    /// on-disk `u16` `name_len` field.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, ParseError> {
        let name_len = btrfs_name_len_u16(self.name.len(), "inode_ref.name_len")?;
        let mut buf = Vec::with_capacity(10 + usize::from(name_len));
        buf.extend_from_slice(&self.index.to_le_bytes());
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&self.name);
        Ok(buf)
    }

    /// Serialize to the on-disk INODE_REF entry layout.
    ///
    /// Layout: index(8) + name_len(2) + name bytes.
    ///
    /// # Panics
    ///
    /// Panics when the name cannot fit in the on-disk `u16` `name_len` field.
    /// Use [`Self::try_to_bytes`] when serializing untrusted or caller-owned names.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("BtrfsInodeRef name length exceeds u16::MAX")
    }
}

fn btrfs_name_len_u16(len: usize, field: &'static str) -> Result<u16, ParseError> {
    if len == 0 {
        return Err(ParseError::InvalidField {
            field,
            reason: "must be non-zero",
        });
    }
    u16::try_from(len).map_err(|_| ParseError::InvalidField {
        field,
        reason: "name length exceeds u16::MAX",
    })
}

/// Descriptor for an enumerated btrfs subvolume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsSubvolume {
    /// Subvolume object ID (also the tree ID).
    pub id: u64,
    /// Parent subvolume ID (0 if top-level).
    pub parent_id: u64,
    /// Name of the subvolume (from ROOT_REF).
    pub name: String,
    /// Generation when last modified.
    pub generation: u64,
    /// Whether this subvolume is read-only.
    pub read_only: bool,
    /// Logical address of the subvolume's root tree block.
    pub bytenr: u64,
    /// Root tree level.
    pub level: u8,
}

/// Descriptor for an enumerated btrfs snapshot.
///
/// A snapshot is a read-only subvolume whose `parent_uuid` is non-zero,
/// indicating which subvolume it was created from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsSnapshot {
    /// Snapshot subvolume ID.
    pub id: u64,
    /// Source subvolume ID (the subvolume this is a snapshot of).
    pub source_id: u64,
    /// Name of the snapshot.
    pub name: String,
    /// Generation when the snapshot was created.
    pub generation: u64,
    /// UUID of this snapshot.
    pub uuid: [u8; 16],
    /// UUID of the source subvolume.
    pub parent_uuid: [u8; 16],
    /// Logical address of the snapshot's root tree block.
    pub bytenr: u64,
    /// Root tree level.
    pub level: u8,
}

/// Type of change detected in a generation-based snapshot diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotChangeType {
    /// Item was added (present in newer, absent in older).
    Added,
    /// Item was modified (present in both, newer generation).
    Modified,
    /// Item was deleted (present in older, absent in newer).
    Deleted,
}

/// A single change entry from a generation-based snapshot diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDiffEntry {
    /// Inode objectid of the changed file.
    pub inode: u64,
    /// Type of change.
    pub change_type: SnapshotChangeType,
}

/// btrfs ROOT_REF item type (parent → child subvolume link).
pub const BTRFS_ITEM_ROOT_REF: u8 = 156;
/// btrfs ROOT_BACKREF item type (child → parent subvolume link).
pub const BTRFS_ITEM_ROOT_BACKREF: u8 = 144;
/// Flag bit in `BtrfsRootItem::flags` indicating a read-only subvolume.
pub const BTRFS_ROOT_SUBVOL_RDONLY: u64 = 1 << 0;
/// First free objectid for user subvolumes.
pub const BTRFS_FIRST_FREE_OBJECTID: u64 = 256;

/// Parsed subset of `btrfs_inode_item` needed for read-only VFS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsInodeItem {
    /// Transaction generation when this inode was created.
    ///
    /// Used as the FUSE/NFS generation number for stale-handle detection.
    /// Since btrfs objectids are never reused, the creation-time transaction
    /// generation uniquely identifies this inode incarnation.
    pub generation: u64,
    pub size: u64,
    pub nbytes: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub rdev: u64,
    /// Inode flags from kernel `btrfs_inode_item.flags` at offset 64.
    ///
    /// Common flags (from `fs/btrfs/btrfs_inode.h`):
    /// - `BTRFS_INODE_NODATASUM` (0x1): do not checksum data
    /// - `BTRFS_INODE_NODATACOW` (0x2): no COW for data
    /// - `BTRFS_INODE_READONLY` (0x4): read-only inode
    /// - `BTRFS_INODE_NOCOMPRESS` (0x8): do not compress
    /// - `BTRFS_INODE_PREALLOC` (0x10): has preallocated extents
    /// - `BTRFS_INODE_SYNC` (0x20): sync on write
    /// - `BTRFS_INODE_IMMUTABLE` (0x40): immutable
    /// - `BTRFS_INODE_APPEND` (0x80): append-only
    /// - `BTRFS_INODE_NODUMP` (0x100): do not dump
    /// - `BTRFS_INODE_NOATIME` (0x200): no atime updates
    /// - `BTRFS_INODE_DIRSYNC` (0x400): sync dir changes
    /// - `BTRFS_INODE_COMPRESS` (0x800): compress data
    pub flags: u64,
    pub atime_sec: u64,
    pub atime_nsec: u32,
    pub ctime_sec: u64,
    pub ctime_nsec: u32,
    pub mtime_sec: u64,
    pub mtime_nsec: u32,
    pub otime_sec: u64,
    pub otime_nsec: u32,
}

impl BtrfsInodeItem {
    /// Serialize to the 160-byte on-disk representation.
    ///
    /// Layout matches the kernel `btrfs_inode_item` struct. Fields we do not
    /// track (block_group, sequence, reserved) are zeroed.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 160];
        buf[0..8].copy_from_slice(&self.generation.to_le_bytes());
        // transid at 8..16 (zero)
        buf[16..24].copy_from_slice(&self.size.to_le_bytes());
        buf[24..32].copy_from_slice(&self.nbytes.to_le_bytes());
        // block_group at 32..40 (zero)
        buf[40..44].copy_from_slice(&self.nlink.to_le_bytes());
        buf[44..48].copy_from_slice(&self.uid.to_le_bytes());
        buf[48..52].copy_from_slice(&self.gid.to_le_bytes());
        buf[52..56].copy_from_slice(&self.mode.to_le_bytes());
        buf[56..64].copy_from_slice(&self.rdev.to_le_bytes());
        buf[64..72].copy_from_slice(&self.flags.to_le_bytes());
        // sequence at 72..80 (zero)
        // reserved[4] at 80..112 (zero)
        buf[112..120].copy_from_slice(&self.atime_sec.to_le_bytes());
        buf[120..124].copy_from_slice(&self.atime_nsec.to_le_bytes());
        buf[124..132].copy_from_slice(&self.ctime_sec.to_le_bytes());
        buf[132..136].copy_from_slice(&self.ctime_nsec.to_le_bytes());
        buf[136..144].copy_from_slice(&self.mtime_sec.to_le_bytes());
        buf[144..148].copy_from_slice(&self.mtime_nsec.to_le_bytes());
        buf[148..156].copy_from_slice(&self.otime_sec.to_le_bytes());
        buf[156..160].copy_from_slice(&self.otime_nsec.to_le_bytes());
        buf
    }
}

/// One decoded directory entry from DIR_ITEM / DIR_INDEX payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsDirItem {
    pub child_objectid: u64,
    pub child_key_type: u8,
    pub child_key_offset: u64,
    pub file_type: u8,
    pub name: Vec<u8>,
}

impl BtrfsDirItem {
    /// Fallibly serialize to the on-disk DIR_ITEM / DIR_INDEX layout.
    ///
    /// Layout: location key (objectid:8 + type:1 + offset:8) + transid(8) +
    /// data_len(2) + name_len(2) + file_type(1) + name bytes.
    /// `transid` is set to zero (not tracked in our VFS layer).
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidField`] when the name cannot fit in the
    /// on-disk `u16` `name_len` field.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, ParseError> {
        let name_len = btrfs_name_len_u16(self.name.len(), "dir_item.name_len")?;
        let mut buf = vec![0u8; 30 + usize::from(name_len)];
        buf[0..8].copy_from_slice(&self.child_objectid.to_le_bytes());
        buf[8] = self.child_key_type;
        buf[9..17].copy_from_slice(&self.child_key_offset.to_le_bytes());
        // transid at 17..25 (zero)
        // data_len at 25..27 (zero — no trailing payload)
        buf[27..29].copy_from_slice(&name_len.to_le_bytes());
        buf[29] = self.file_type;
        buf[30..].copy_from_slice(&self.name);
        Ok(buf)
    }

    /// Serialize to the on-disk DIR_ITEM / DIR_INDEX layout.
    ///
    /// Layout: location key (objectid:8 + type:1 + offset:8) + transid(8) +
    /// data_len(2) + name_len(2) + file_type(1) + name bytes.
    /// `transid` is set to zero (not tracked in our VFS layer).
    ///
    /// # Panics
    ///
    /// Panics when the name cannot fit in the on-disk `u16` `name_len` field.
    /// Use [`Self::try_to_bytes`] when serializing untrusted or caller-owned names.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("BtrfsDirItem name length exceeds u16::MAX")
    }
}

/// Parsed XATTR_ITEM payload.
///
/// Uses the same on-disk layout as `BtrfsDirItem` but with `data_len > 0`:
/// the value bytes follow the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsXattrItem {
    /// The extended attribute name (e.g. `user.foo`).
    pub name: Vec<u8>,
    /// The extended attribute value.
    pub value: Vec<u8>,
}

/// Parse one or more XATTR_ITEM entries from the concatenated payload bytes.
///
/// The format is the same DIR_ITEM header (30 bytes) followed by `name_len`
/// bytes of name and `data_len` bytes of value.
pub fn parse_xattr_items(data: &[u8]) -> Result<Vec<BtrfsXattrItem>, ParseError> {
    const HEADER: usize = 30;
    let mut out = Vec::new();
    let mut cur = 0_usize;
    while cur < data.len() {
        if cur + HEADER > data.len() {
            return Err(ParseError::InsufficientData {
                needed: HEADER,
                offset: cur,
                actual: data.len() - cur,
            });
        }
        let data_len = usize::from(u16::from_le_bytes([data[cur + 25], data[cur + 26]]));
        let name_len = usize::from(u16::from_le_bytes([data[cur + 27], data[cur + 28]]));
        if name_len == 0 {
            return Err(ParseError::InvalidField {
                field: "xattr.name_len",
                reason: "must be non-zero",
            });
        }

        let name_start = cur + HEADER;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(ParseError::InvalidField {
                field: "xattr.name_len",
                reason: "overflow",
            })?;
        let value_end = name_end
            .checked_add(data_len)
            .ok_or(ParseError::InvalidField {
                field: "xattr.data_len",
                reason: "overflow",
            })?;

        if value_end > data.len() {
            return Err(ParseError::InsufficientData {
                needed: value_end,
                offset: cur,
                actual: data.len(),
            });
        }

        out.push(BtrfsXattrItem {
            name: data[name_start..name_end].to_vec(),
            value: data[name_end..value_end].to_vec(),
        });
        cur = value_end;
    }
    Ok(out)
}

/// Parsed EXTENT_DATA payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtrfsExtentData {
    /// Inline extent payload bytes.
    Inline {
        generation: u64,
        ram_bytes: u64,
        compression: u8,
        data: Vec<u8>,
    },
    /// Regular or preallocated extent that references on-disk bytes.
    ///
    /// `disk_bytenr` is a logical bytenr in btrfs address space.
    Regular {
        generation: u64,
        ram_bytes: u64,
        extent_type: u8,
        compression: u8,
        disk_bytenr: u64,
        disk_num_bytes: u64,
        extent_offset: u64,
        num_bytes: u64,
    },
}

impl BtrfsExtentData {
    /// Serialize to the on-disk EXTENT_DATA layout.
    ///
    /// Fixed header (21 bytes): generation(8) + ram_bytes(8) + compression(1)
    /// + encryption(1) + other_encoding(2) + type(1).
    ///   Inline: header + data bytes.
    ///   Regular: header + disk_bytenr(8) + disk_num_bytes(8) + offset(8) + num_bytes(8).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Inline {
                generation,
                ram_bytes,
                compression,
                data,
            } => {
                let mut buf = vec![0u8; 21 + data.len()];
                buf[0..8].copy_from_slice(&generation.to_le_bytes());
                buf[8..16].copy_from_slice(&ram_bytes.to_le_bytes());
                buf[16] = *compression;
                // encryption at 17 (zero)
                // other_encoding at 18..20 (zero)
                buf[20] = BTRFS_FILE_EXTENT_INLINE;
                buf[21..21 + data.len()].copy_from_slice(data);
                buf
            }
            Self::Regular {
                generation,
                ram_bytes,
                extent_type,
                compression,
                disk_bytenr,
                disk_num_bytes,
                extent_offset,
                num_bytes,
            } => {
                let mut buf = vec![0u8; 53];
                buf[0..8].copy_from_slice(&generation.to_le_bytes());
                buf[8..16].copy_from_slice(&ram_bytes.to_le_bytes());
                buf[16] = *compression;
                // encryption at 17 (zero)
                // other_encoding at 18..20 (zero)
                buf[20] = *extent_type;
                buf[21..29].copy_from_slice(&disk_bytenr.to_le_bytes());
                buf[29..37].copy_from_slice(&disk_num_bytes.to_le_bytes());
                buf[37..45].copy_from_slice(&extent_offset.to_le_bytes());
                buf[45..53].copy_from_slice(&num_bytes.to_le_bytes());
                buf
            }
        }
    }
}

fn read_exact<const N: usize>(
    data: &[u8],
    off: usize,
    field: &'static str,
) -> Result<[u8; N], ParseError> {
    let end = off.checked_add(N).ok_or(ParseError::InvalidField {
        field,
        reason: "offset overflow",
    })?;
    let Some(slice) = data.get(off..end) else {
        return Err(ParseError::InsufficientData {
            needed: end,
            offset: off,
            actual: data.len(),
        });
    };
    let mut out = [0_u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

fn read_u16(data: &[u8], off: usize, field: &'static str) -> Result<u16, ParseError> {
    Ok(u16::from_le_bytes(read_exact::<2>(data, off, field)?))
}

fn read_u32(data: &[u8], off: usize, field: &'static str) -> Result<u32, ParseError> {
    Ok(u32::from_le_bytes(read_exact::<4>(data, off, field)?))
}

fn read_u64(data: &[u8], off: usize, field: &'static str) -> Result<u64, ParseError> {
    Ok(u64::from_le_bytes(read_exact::<8>(data, off, field)?))
}

/// Parse the subset of `btrfs_root_item` needed to find the FS tree root,
/// enumerate subvolumes, and identify snapshots.
///
/// Layout (stable for the supported on-disk variants):
/// - offset 160: `generation` (u64)
/// - offset 168: `root_dirid` (u64)
/// - offset 176: `bytenr` (u64)
/// - offset 208: `flags` (u64)
/// - offset 216: `refs` (u32)
/// - offset 238: `level` (u8)
/// - offset 239: `generation_v2` (u64) — validates newer optional fields
/// - offset 247: `uuid` (16 bytes) — zero if absent/stale, rejected if partial and valid
/// - offset 263: `parent_uuid` (16 bytes) — zero if absent/stale, rejected if partial and valid
pub fn parse_root_item(data: &[u8]) -> Result<BtrfsRootItem, ParseError> {
    if data.len() < BTRFS_ROOT_ITEM_LEGACY_SIZE {
        return Err(ParseError::InsufficientData {
            needed: BTRFS_ROOT_ITEM_LEGACY_SIZE,
            offset: 0,
            actual: data.len(),
        });
    }
    if data.len() > BTRFS_ROOT_ITEM_LEGACY_SIZE && data.len() < BTRFS_ROOT_ITEM_UUID_OFFSET {
        return Err(ParseError::InvalidField {
            field: "root_item.generation_v2",
            reason: "partial extension field",
        });
    }

    let generation = read_u64(
        data,
        BTRFS_ROOT_ITEM_GENERATION_OFFSET,
        "root_item.generation",
    )?;
    let root_dirid = read_u64(
        data,
        BTRFS_ROOT_ITEM_ROOT_DIRID_OFFSET,
        "root_item.root_dirid",
    )?;
    let bytenr = read_u64(data, BTRFS_ROOT_ITEM_BYTENR_OFFSET, "root_item.bytenr")?;
    let flags = read_u64(data, BTRFS_ROOT_ITEM_FLAGS_OFFSET, "root_item.flags")?;
    let refs = u64::from(read_u32(
        data,
        BTRFS_ROOT_ITEM_REFS_OFFSET,
        "root_item.refs",
    )?);
    let level = read_exact::<1>(data, BTRFS_ROOT_ITEM_LEVEL_OFFSET, "root_item.level")?[0];

    // UUID-era fields are valid only when generation_v2 matches generation;
    // older kernels can leave stale values behind after modifying the root.
    let extended_fields_valid = if data.len() >= BTRFS_ROOT_ITEM_UUID_OFFSET {
        read_u64(
            data,
            BTRFS_ROOT_ITEM_GENERATION_V2_OFFSET,
            "root_item.generation_v2",
        )? == generation
    } else {
        false
    };
    if extended_fields_valid
        && data.len() > BTRFS_ROOT_ITEM_UUID_OFFSET
        && data.len() < BTRFS_ROOT_ITEM_UUID_END
    {
        return Err(ParseError::InvalidField {
            field: "root_item.uuid",
            reason: "partial extension field",
        });
    }
    if extended_fields_valid
        && data.len() > BTRFS_ROOT_ITEM_PARENT_UUID_OFFSET
        && data.len() < BTRFS_ROOT_ITEM_PARENT_UUID_END
    {
        return Err(ParseError::InvalidField {
            field: "root_item.parent_uuid",
            reason: "partial extension field",
        });
    }

    let uuid = if extended_fields_valid && data.len() >= BTRFS_ROOT_ITEM_UUID_END {
        read_exact::<16>(data, BTRFS_ROOT_ITEM_UUID_OFFSET, "root_item.uuid")?
    } else {
        [0u8; 16]
    };
    let parent_uuid = if extended_fields_valid && data.len() >= BTRFS_ROOT_ITEM_PARENT_UUID_END {
        read_exact::<16>(
            data,
            BTRFS_ROOT_ITEM_PARENT_UUID_OFFSET,
            "root_item.parent_uuid",
        )?
    } else {
        [0u8; 16]
    };

    if bytenr == 0 {
        return Err(ParseError::InvalidField {
            field: "root_item.bytenr",
            reason: "must be non-zero",
        });
    }
    if level > BTRFS_MAX_TREE_LEVEL {
        return Err(ParseError::InvalidField {
            field: "root_item.level",
            reason: "exceeds maximum btrfs tree level",
        });
    }

    Ok(BtrfsRootItem {
        bytenr,
        level,
        generation,
        root_dirid,
        flags,
        refs,
        uuid,
        parent_uuid,
    })
}

/// Parse a ROOT_REF item payload.
///
/// Layout:
/// - offset 0: `dirid` (u64) — directory inode in parent subvolume
/// - offset 8: `sequence` (u64)
/// - offset 16: `name_len` (u16)
/// - offset 18: name bytes (variable length)
pub fn parse_root_ref(data: &[u8]) -> Result<BtrfsRootRef, ParseError> {
    if data.len() < 18 {
        return Err(ParseError::InsufficientData {
            needed: 18,
            offset: 0,
            actual: data.len(),
        });
    }
    let dirid = read_u64(data, 0, "root_ref.dirid")?;
    let sequence = read_u64(data, 8, "root_ref.sequence")?;
    let name_len = u16::from_le_bytes([data[16], data[17]]);
    if name_len == 0 {
        return Err(ParseError::InvalidField {
            field: "root_ref.name_len",
            reason: "must be non-zero",
        });
    }
    let name_end = 18 + usize::from(name_len);
    if data.len() < name_end {
        return Err(ParseError::InsufficientData {
            needed: name_end - 18,
            offset: 18,
            actual: data.len() - 18,
        });
    }
    if data.len() > name_end {
        return Err(ParseError::InvalidField {
            field: "root_ref.name_len",
            reason: "does not match payload length",
        });
    }
    Ok(BtrfsRootRef {
        dirid,
        sequence,
        name: data[18..name_end].to_vec(),
    })
}

/// Parse one or more INODE_REF entries from a raw btrfs payload.
pub fn parse_inode_refs(data: &[u8]) -> Result<Vec<BtrfsInodeRef>, ParseError> {
    const HEADER: usize = 10;
    let mut out = Vec::new();
    let mut cur = 0_usize;
    while cur < data.len() {
        if cur + HEADER > data.len() {
            return Err(ParseError::InsufficientData {
                needed: HEADER,
                offset: cur,
                actual: data.len() - cur,
            });
        }

        let index = read_u64(data, cur, "inode_ref.index")?;
        let name_len = usize::from(read_u16(data, cur + 8, "inode_ref.name_len")?);
        if name_len == 0 {
            return Err(ParseError::InvalidField {
                field: "inode_ref.name_len",
                reason: "must be non-zero",
            });
        }
        let name_start = cur + HEADER;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(ParseError::InvalidField {
                field: "inode_ref.name_len",
                reason: "overflow",
            })?;
        if name_end > data.len() {
            return Err(ParseError::InsufficientData {
                needed: name_end - cur,
                offset: cur,
                actual: data.len() - cur,
            });
        }

        out.push(BtrfsInodeRef {
            index,
            name: data[name_start..name_end].to_vec(),
        });
        cur = name_end;
    }
    Ok(out)
}

/// Enumerate subvolumes from root tree leaf entries.
///
/// Takes all leaf entries from the root tree (obtained via `walk_tree`)
/// and extracts subvolume information by correlating ROOT_ITEM and ROOT_REF
/// entries for objectids >= 256 (user subvolumes).
#[must_use]
pub fn enumerate_subvolumes(entries: &[BtrfsLeafEntry]) -> Vec<BtrfsSubvolume> {
    let mut subvols = Vec::new();

    // Collect ROOT_ITEM entries for user subvolumes
    for entry in entries {
        if entry.key.item_type != BTRFS_ITEM_ROOT_ITEM {
            continue;
        }
        let id = entry.key.objectid;
        if id < BTRFS_FIRST_FREE_OBJECTID {
            continue;
        }
        let Ok(root) = parse_root_item(&entry.data) else {
            continue;
        };

        // Find matching ROOT_REF for this subvolume
        let (parent_id, name) = entries
            .iter()
            .find_map(|e| {
                if e.key.item_type == BTRFS_ITEM_ROOT_REF && e.key.offset == id {
                    let rref = parse_root_ref(&e.data).ok()?;
                    let name = String::from_utf8_lossy(&rref.name).into_owned();
                    Some((e.key.objectid, name))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| (0, format!("subvol-{id}")));

        subvols.push(BtrfsSubvolume {
            id,
            parent_id,
            name,
            generation: root.generation,
            read_only: root.flags & BTRFS_ROOT_SUBVOL_RDONLY != 0,
            bytenr: root.bytenr,
            level: root.level,
        });
    }

    subvols
}

/// Check if a UUID is non-zero (i.e., has been set).
fn uuid_is_set(uuid: &[u8; 16]) -> bool {
    uuid.iter().any(|&b| b != 0)
}

/// Enumerate snapshots from root tree leaf entries.
///
/// A snapshot is a subvolume whose `parent_uuid` is non-zero, indicating
/// it was created as a snapshot of another subvolume.
#[must_use]
pub fn enumerate_snapshots(entries: &[BtrfsLeafEntry]) -> Vec<BtrfsSnapshot> {
    let mut snapshots = Vec::new();

    // First pass: collect all ROOT_ITEM entries with parent_uuid set
    for entry in entries {
        if entry.key.item_type != BTRFS_ITEM_ROOT_ITEM {
            continue;
        }
        let id = entry.key.objectid;
        if id < BTRFS_FIRST_FREE_OBJECTID {
            continue;
        }
        let Ok(root) = parse_root_item(&entry.data) else {
            continue;
        };
        if !uuid_is_set(&root.parent_uuid) {
            continue;
        }

        // Find the source subvolume by matching parent_uuid to uuid
        let source_id = entries
            .iter()
            .find_map(|e| {
                if e.key.item_type != BTRFS_ITEM_ROOT_ITEM {
                    return None;
                }
                let src = parse_root_item(&e.data).ok()?;
                if src.uuid == root.parent_uuid {
                    Some(e.key.objectid)
                } else {
                    None
                }
            })
            .unwrap_or(0);

        // Find matching ROOT_REF for the snapshot name
        let name = entries
            .iter()
            .find_map(|e| {
                if e.key.item_type == BTRFS_ITEM_ROOT_REF && e.key.offset == id {
                    let rref = parse_root_ref(&e.data).ok()?;
                    Some(String::from_utf8_lossy(&rref.name).into_owned())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| format!("snap-{id}"));

        snapshots.push(BtrfsSnapshot {
            id,
            source_id,
            name,
            generation: root.generation,
            uuid: root.uuid,
            parent_uuid: root.parent_uuid,
            bytenr: root.bytenr,
            level: root.level,
        });
    }

    snapshots
}

/// Compute a generation-based diff between two sets of tree leaf entries.
///
/// Compares inode items by objectid. An inode is:
/// - **Added** if it exists in `newer` but not `older`.
/// - **Deleted** if it exists in `older` but not `newer`.
/// - **Modified** if it exists in both but the `newer` entry has a higher
///   generation in its inode item.
///
/// This is a simplified diff that does NOT produce full paths — it
/// operates on inode objectids only.
#[must_use]
pub fn snapshot_diff_by_generation(
    older_entries: &[BtrfsLeafEntry],
    newer_entries: &[BtrfsLeafEntry],
) -> Vec<SnapshotDiffEntry> {
    use std::collections::BTreeMap;

    // Collect inode items (type 1) by objectid with generation
    let collect_inodes = |entries: &[BtrfsLeafEntry]| -> BTreeMap<u64, u64> {
        entries
            .iter()
            .filter(|e| e.key.item_type == BTRFS_ITEM_INODE_ITEM)
            .filter_map(|e| {
                let inode = parse_inode_item(&e.data).ok()?;
                Some((e.key.objectid, inode.generation))
            })
            .collect()
    };

    let old_inodes = collect_inodes(older_entries);
    let new_inodes = collect_inodes(newer_entries);
    let mut diffs = Vec::new();

    // Deleted: in old but not in new
    for &oid in old_inodes.keys() {
        if !new_inodes.contains_key(&oid) {
            diffs.push(SnapshotDiffEntry {
                inode: oid,
                change_type: SnapshotChangeType::Deleted,
            });
        }
    }

    // Added or Modified
    for (&oid, &new_gen) in &new_inodes {
        match old_inodes.get(&oid) {
            None => {
                diffs.push(SnapshotDiffEntry {
                    inode: oid,
                    change_type: SnapshotChangeType::Added,
                });
            }
            Some(&old_gen) if new_gen > old_gen => {
                diffs.push(SnapshotDiffEntry {
                    inode: oid,
                    change_type: SnapshotChangeType::Modified,
                });
            }
            _ => {}
        }
    }

    diffs.sort_by_key(|d| d.inode);
    diffs
}

/// Parse the subset of `btrfs_inode_item` needed for read-only VFS operations.
pub fn parse_inode_item(data: &[u8]) -> Result<BtrfsInodeItem, ParseError> {
    const INODE_ITEM_SIZE: usize = 160;
    const NANOS_PER_SECOND: u32 = 1_000_000_000;

    if data.len() < INODE_ITEM_SIZE {
        return Err(ParseError::InsufficientData {
            needed: INODE_ITEM_SIZE,
            offset: 0,
            actual: data.len(),
        });
    }
    if data.len() > INODE_ITEM_SIZE {
        return Err(ParseError::InvalidField {
            field: "inode_item.size",
            reason: "does not match fixed inode item size",
        });
    }

    let atime_nsec = read_u32(data, 120, "inode_item.atime_nsec")?;
    let ctime_nsec = read_u32(data, 132, "inode_item.ctime_nsec")?;
    let mtime_nsec = read_u32(data, 144, "inode_item.mtime_nsec")?;
    let otime_nsec = read_u32(data, 156, "inode_item.otime_nsec")?;
    for (field, nsec) in [
        ("inode_item.atime_nsec", atime_nsec),
        ("inode_item.ctime_nsec", ctime_nsec),
        ("inode_item.mtime_nsec", mtime_nsec),
        ("inode_item.otime_nsec", otime_nsec),
    ] {
        if nsec >= NANOS_PER_SECOND {
            return Err(ParseError::InvalidField {
                field,
                reason: "must be less than 1_000_000_000",
            });
        }
    }

    Ok(BtrfsInodeItem {
        generation: read_u64(data, 0, "inode_item.generation")?,
        size: read_u64(data, 16, "inode_item.size")?,
        nbytes: read_u64(data, 24, "inode_item.nbytes")?,
        nlink: read_u32(data, 40, "inode_item.nlink")?,
        uid: read_u32(data, 44, "inode_item.uid")?,
        gid: read_u32(data, 48, "inode_item.gid")?,
        mode: read_u32(data, 52, "inode_item.mode")?,
        rdev: read_u64(data, 56, "inode_item.rdev")?,
        flags: read_u64(data, 64, "inode_item.flags")?,
        atime_sec: read_u64(data, 112, "inode_item.atime_sec")?,
        atime_nsec,
        ctime_sec: read_u64(data, 124, "inode_item.ctime_sec")?,
        ctime_nsec,
        mtime_sec: read_u64(data, 136, "inode_item.mtime_sec")?,
        mtime_nsec,
        otime_sec: read_u64(data, 148, "inode_item.otime_sec")?,
        otime_nsec,
    })
}

/// Parse one or more directory entries from a DIR_ITEM or DIR_INDEX payload.
pub fn parse_dir_items(data: &[u8]) -> Result<Vec<BtrfsDirItem>, ParseError> {
    const HEADER: usize = 30; // disk_key(17) + transid(8) + data_len(2) + name_len(2) + type(1)

    let mut out = Vec::new();
    let mut cur = 0_usize;
    while cur < data.len() {
        if cur + HEADER > data.len() {
            return Err(ParseError::InsufficientData {
                needed: HEADER,
                offset: cur,
                actual: data.len() - cur,
            });
        }

        let child_objectid = read_u64(data, cur, "dir_item.location.objectid")?;
        let child_key_type = data[cur + 8];
        let child_key_offset = read_u64(data, cur + 9, "dir_item.location.offset")?;
        // transid at +17..+25 (currently unused in VFS path)
        let data_len = usize::from(read_u16(data, cur + 25, "dir_item.data_len")?);
        let name_len = usize::from(read_u16(data, cur + 27, "dir_item.name_len")?);
        let file_type = data[cur + 29];
        if name_len == 0 {
            return Err(ParseError::InvalidField {
                field: "dir_item.name_len",
                reason: "must be non-zero",
            });
        }
        if data_len != 0 {
            return Err(ParseError::InvalidField {
                field: "dir_item.data_len",
                reason: "must be zero for directory entries",
            });
        }

        let name_start = cur + HEADER;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(ParseError::InvalidField {
                field: "dir_item.name_len",
                reason: "overflow",
            })?;

        if name_end > data.len() {
            return Err(ParseError::InsufficientData {
                needed: name_end - cur,
                offset: cur,
                actual: data.len() - cur,
            });
        }

        out.push(BtrfsDirItem {
            child_objectid,
            child_key_type,
            child_key_offset,
            file_type,
            name: data[name_start..name_end].to_vec(),
        });

        cur = name_end;
    }

    Ok(out)
}

/// Parse an EXTENT_DATA payload for regular or inline extents.
pub fn parse_extent_data(data: &[u8]) -> Result<BtrfsExtentData, ParseError> {
    const FIXED: usize = 21; // generation(8) + ram_bytes(8) + compression(1) + encryption(1) + other_encoding(2) + type(1)
    const REGULAR_SIZE: usize = FIXED + 32; // disk_bytenr + disk_num_bytes + extent_offset + num_bytes

    if data.len() < FIXED {
        return Err(ParseError::InsufficientData {
            needed: FIXED,
            offset: 0,
            actual: data.len(),
        });
    }

    let generation = read_u64(data, 0, "extent_data.generation")?;
    let ram_bytes = read_u64(data, 8, "extent_data.ram_bytes")?;
    let compression = data[16];
    let encryption = data[17];
    let other_encoding = read_u16(data, 18, "extent_data.other_encoding")?;
    let extent_type = data[20];
    if !matches!(
        compression,
        BTRFS_COMPRESS_NONE | BTRFS_COMPRESS_ZLIB | BTRFS_COMPRESS_LZO | BTRFS_COMPRESS_ZSTD
    ) {
        return Err(ParseError::InvalidField {
            field: "extent_data.compression",
            reason: "unsupported compression",
        });
    }
    if encryption != 0 {
        return Err(ParseError::InvalidField {
            field: "extent_data.encryption",
            reason: "unsupported encryption",
        });
    }
    if other_encoding != 0 {
        return Err(ParseError::InvalidField {
            field: "extent_data.other_encoding",
            reason: "unsupported other encoding",
        });
    }
    match extent_type {
        BTRFS_FILE_EXTENT_INLINE => {
            parse_inline_extent_data(generation, ram_bytes, compression, &data[FIXED..])
        }
        BTRFS_FILE_EXTENT_REG | BTRFS_FILE_EXTENT_PREALLOC => {
            // disk_bytenr + disk_num_bytes + extent_offset + num_bytes
            if data.len() < REGULAR_SIZE {
                return Err(ParseError::InsufficientData {
                    needed: REGULAR_SIZE,
                    offset: 0,
                    actual: data.len(),
                });
            }
            if data.len() > REGULAR_SIZE {
                return Err(ParseError::InvalidField {
                    field: "extent_data.length",
                    reason: "trailing bytes after fixed extent payload",
                });
            }
            let disk_bytenr = read_u64(data, 21, "extent_data.disk_bytenr")?;
            let disk_num_bytes = read_u64(data, 29, "extent_data.disk_num_bytes")?;
            let extent_offset = read_u64(data, 37, "extent_data.offset")?;
            let num_bytes = read_u64(data, 45, "extent_data.num_bytes")?;

            // Validate source-slice arithmetic for extents that read from
            // backing bytes. Compressed extents slice the decompressed
            // `ram_bytes` payload, while uncompressed extents address
            // `disk_num_bytes` bytes from `disk_bytenr`.
            if compression != BTRFS_COMPRESS_NONE || disk_bytenr != 0 {
                let extent_end =
                    extent_offset
                        .checked_add(num_bytes)
                        .ok_or(ParseError::InvalidField {
                            field: "extent_data.extent_offset+num_bytes",
                            reason: "source slice arithmetic overflow",
                        })?;
                if compression != BTRFS_COMPRESS_NONE && extent_end > ram_bytes {
                    return Err(ParseError::InvalidField {
                        field: "extent_data.extent_offset+num_bytes",
                        reason: "source slice exceeds ram_bytes",
                    });
                }
                if compression == BTRFS_COMPRESS_NONE && extent_end > disk_num_bytes {
                    return Err(ParseError::InvalidField {
                        field: "extent_data.extent_offset+num_bytes",
                        reason: "source slice exceeds disk_num_bytes",
                    });
                }
            }

            Ok(BtrfsExtentData::Regular {
                generation,
                ram_bytes,
                extent_type,
                compression,
                disk_bytenr,
                disk_num_bytes,
                extent_offset,
                num_bytes,
            })
        }
        _ => Err(ParseError::InvalidField {
            field: "extent_data.type",
            reason: "unsupported extent type",
        }),
    }
}

fn parse_inline_extent_data(
    generation: u64,
    ram_bytes: u64,
    compression: u8,
    inline_data: &[u8],
) -> Result<BtrfsExtentData, ParseError> {
    validate_inline_extent_ram_bytes(compression, inline_data.len(), ram_bytes)?;
    Ok(BtrfsExtentData::Inline {
        generation,
        ram_bytes,
        compression,
        data: inline_data.to_vec(),
    })
}

fn validate_inline_extent_ram_bytes(
    compression: u8,
    inline_len: usize,
    ram_bytes: u64,
) -> Result<(), ParseError> {
    if compression != BTRFS_COMPRESS_NONE {
        return Ok(());
    }
    let inline_len = u64::try_from(inline_len).map_err(|_| ParseError::InvalidField {
        field: "extent_data.inline_len",
        reason: "does not fit u64",
    })?;
    if inline_len != ram_bytes {
        return Err(ParseError::InvalidField {
            field: "extent_data.ram_bytes",
            reason: "uncompressed inline length mismatch",
        });
    }
    Ok(())
}

/// Walk a btrfs tree from `root_logical` down to all leaves, collecting items.
///
/// `read_physical` reads `nodesize` bytes at the given physical byte offset.
/// `chunks` provides the logical→physical address mapping.
///
/// Returns all leaf items in key order (left-to-right DFS).
/// The traversal is bounded: it rejects levels > 7 and validates nritems
/// against block capacity at each node.
pub fn walk_tree(
    read_physical: &mut dyn FnMut(u64) -> Result<Vec<u8>, ParseError>,
    chunks: &[BtrfsChunkEntry],
    root_logical: u64,
    nodesize: u32,
    csum_type: u16,
) -> Result<Vec<BtrfsLeafEntry>, ParseError> {
    let mut walker = BtrfsTreeWalker {
        read_physical,
        chunks,
        nodesize,
        csum_type,
        out: Vec::new(),
        active_path: HashSet::new(),
        visited_nodes: HashSet::new(),
        range: None,
    };
    walker.walk_node(root_logical)?;
    Ok(walker.out)
}

/// Walk a btrfs b-tree but descend only into subtrees that can contain a key
/// in the half-open range `[lo, hi)`, returning exactly the leaf entries whose
/// key falls in that range.
///
/// This is the targeted-descent counterpart to [`walk_tree`]: instead of
/// visiting every node (O(N) reads), it binary-prunes internal-node children
/// whose key span cannot overlap the requested range, reading only the
/// O(log N) nodes along the covering paths. The returned entries are identical
/// to `walk_tree(...).into_iter().filter(|e| lo <= e.key < hi)` — same items,
/// same order — but without reading subtrees that hold no matching key.
pub fn walk_tree_range(
    read_physical: &mut dyn FnMut(u64) -> Result<Vec<u8>, ParseError>,
    chunks: &[BtrfsChunkEntry],
    root_logical: u64,
    nodesize: u32,
    csum_type: u16,
    lo: BtrfsKey,
    hi: BtrfsKey,
) -> Result<Vec<BtrfsLeafEntry>, ParseError> {
    let mut walker = BtrfsTreeWalker {
        read_physical,
        chunks,
        nodesize,
        csum_type,
        out: Vec::new(),
        active_path: HashSet::new(),
        visited_nodes: HashSet::new(),
        range: Some((lo, hi)),
    };
    walker.walk_node(root_logical)?;
    Ok(walker.out)
}

struct BtrfsTreeWalker<'a> {
    read_physical: &'a mut dyn FnMut(u64) -> Result<Vec<u8>, ParseError>,
    chunks: &'a [BtrfsChunkEntry],
    nodesize: u32,
    csum_type: u16,
    out: Vec<BtrfsLeafEntry>,
    active_path: HashSet<u64>,
    visited_nodes: HashSet<u64>,
    /// When `Some((lo, hi))`, prune internal-node children and leaf items
    /// outside the half-open key range `[lo, hi)`. `None` walks the whole tree.
    range: Option<(BtrfsKey, BtrfsKey)>,
}

impl BtrfsTreeWalker<'_> {
    fn walk_node(&mut self, logical: u64) -> Result<(), ParseError> {
        let nodesize_u64 = u64::from(self.nodesize);
        if nodesize_u64 == 0 {
            return Err(ParseError::InvalidField {
                field: "nodesize",
                reason: "zero nodesize",
            });
        }
        if logical % nodesize_u64 != 0 {
            return Err(ParseError::InvalidField {
                field: "logical_address",
                reason: "not aligned to nodesize",
            });
        }
        if !self.active_path.insert(logical) {
            return Err(ParseError::InvalidField {
                field: "logical_address",
                reason: "cycle detected in btrfs tree pointers",
            });
        }
        if !self.visited_nodes.insert(logical) {
            return Err(ParseError::InvalidField {
                field: "logical_address",
                reason: "duplicate node reference in btrfs tree pointers",
            });
        }

        let mapping =
            map_logical_to_physical(self.chunks, logical)?.ok_or(ParseError::InvalidField {
                field: "logical_address",
                reason: "not covered by any chunk",
            })?;

        let block = (self.read_physical)(mapping.physical)?;
        let ns = usize::try_from(self.nodesize)
            .map_err(|_| ParseError::IntegerConversion { field: "nodesize" })?;
        if block.len() != ns {
            return Err(ParseError::InsufficientData {
                needed: ns,
                offset: 0,
                actual: block.len(),
            });
        }

        // Verify checksum before parsing.
        ffs_ondisk::verify_btrfs_tree_block_checksum(&block, self.csum_type)?;

        let header = BtrfsHeader::parse_from_block(&block)?;
        header.validate(block.len(), Some(logical))?;

        if header.level == 0 {
            collect_leaf_items(&block, &mut self.out, self.range.as_ref())?;
        } else {
            let (_, ptrs) = parse_internal_items(&block)?;
            for (idx, kp) in ptrs.iter().enumerate() {
                if kp.blockptr % nodesize_u64 != 0 {
                    return Err(ParseError::InvalidField {
                        field: "blockptr",
                        reason: "not aligned to nodesize",
                    });
                }
                // Targeted descent: child `idx` covers the key span
                // `[kp.key, next_key)` (the next sibling's key, or +inf for the
                // last child). Skip it when that span cannot overlap [lo, hi).
                if let Some((lo, hi)) = self.range.as_ref() {
                    // Span starts at or after `hi` -> no overlap (keys sorted).
                    if key_cmp(&kp.key, hi) != Ordering::Less {
                        // All later children start even higher; stop early.
                        break;
                    }
                    // Span ends at or before `lo` -> no overlap. The span end is
                    // the next sibling's key; the last child's span is unbounded.
                    if let Some(next) = ptrs.get(idx + 1) {
                        if key_cmp(&next.key, lo) != Ordering::Greater {
                            continue;
                        }
                    }
                }
                self.walk_node(kp.blockptr)?;
            }
        }

        self.active_path.remove(&logical);
        Ok(())
    }
}

fn collect_leaf_items(
    block: &[u8],
    out: &mut Vec<BtrfsLeafEntry>,
    range: Option<&(BtrfsKey, BtrfsKey)>,
) -> Result<(), ParseError> {
    let (_, items) = parse_leaf_items(block)?;
    for item in &items {
        if let Some((lo, hi)) = range {
            // Keep only items in the half-open range [lo, hi).
            if key_cmp(&item.key, lo) == Ordering::Less || key_cmp(&item.key, hi) != Ordering::Less
            {
                continue;
            }
        }
        let off = usize::try_from(item.data_offset).map_err(|_| ParseError::IntegerConversion {
            field: "data_offset",
        })?;
        let sz = usize::try_from(item.data_size)
            .map_err(|_| ParseError::IntegerConversion { field: "data_size" })?;
        let end = off.checked_add(sz).ok_or(ParseError::InvalidField {
            field: "data_offset",
            reason: "overflow",
        })?;
        if end > block.len() {
            return Err(ParseError::InvalidField {
                field: "data_offset",
                reason: "item data extends past block",
            });
        }
        out.push(BtrfsLeafEntry {
            key: item.key,
            data: block[off..end].to_vec(),
        });
    }
    Ok(())
}

fn key_cmp(lhs: &BtrfsKey, rhs: &BtrfsKey) -> Ordering {
    lhs.objectid
        .cmp(&rhs.objectid)
        .then_with(|| lhs.item_type.cmp(&rhs.item_type))
        .then_with(|| lhs.offset.cmp(&rhs.offset))
}

/// Errors returned by in-memory btrfs COW tree mutation APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtrfsMutationError {
    InvalidConfig(&'static str),
    InvalidRange,
    KeyAlreadyExists,
    KeyNotFound,
    MissingNode(u64),
    NoSpace,
    BrokenInvariant(&'static str),
    AddressOverflow,
}

impl std::fmt::Display for BtrfsMutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
            Self::InvalidRange => write!(f, "invalid key range"),
            Self::KeyAlreadyExists => write!(f, "key already exists"),
            Self::KeyNotFound => write!(f, "key not found"),
            Self::MissingNode(block) => write!(f, "missing tree node {block}"),
            Self::NoSpace => write!(f, "no space left in matching block groups"),
            Self::BrokenInvariant(msg) => write!(f, "broken invariant: {msg}"),
            Self::AddressOverflow => write!(f, "address overflow"),
        }
    }
}

/// Key/value payload stored in leaf nodes for the in-memory COW model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsTreeItem {
    pub key: BtrfsKey,
    pub data: Vec<u8>,
}

/// In-memory btrfs B-tree node model used for mutation planning and testing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtrfsCowNode {
    Leaf {
        items: Vec<BtrfsTreeItem>,
    },
    Internal {
        keys: Vec<BtrfsKey>,
        children: Vec<u64>,
    },
}

/// btrfs node header size in bytes.
pub const BTRFS_HEADER_SIZE: usize = 101;
/// btrfs tree-block header `flags`: the block has been written (low bit). Real
/// btrfs always sets this on committed blocks.
pub const BTRFS_HEADER_FLAG_WRITTEN: u64 = 1 << 0;
/// Backref revision stored in the high byte of the header `flags` field.
///
/// `flags >> 56` selects the revision. Modern filesystems use the MIXED
/// revision (1): it tells readers the extent backrefs are inline. Writing the
/// OLD revision (0) makes `btrfs check` interpret the extent items with the old
/// separate-backref format, so it ignores FrankenFS's inline `TREE_BLOCK_REF`s
/// and reports "extent item 0 / no backref item" for every metadata block
/// (bd-fdwuh).
pub const BTRFS_MIXED_BACKREF_REV: u64 = 1;
/// Bit position of the backref revision within the header `flags` field.
pub const BTRFS_BACKREF_REV_SHIFT: u64 = 56;
/// The header `flags` value FrankenFS writes for every committed tree block:
/// WRITTEN, MIXED backref revision.
pub const BTRFS_HEADER_FLAGS_COMMITTED: u64 =
    BTRFS_HEADER_FLAG_WRITTEN | (BTRFS_MIXED_BACKREF_REV << BTRFS_BACKREF_REV_SHIFT);
/// btrfs leaf item descriptor size in bytes.
pub const BTRFS_ITEM_SIZE: usize = 25;
/// btrfs internal key-pointer size in bytes.
pub const BTRFS_KEY_PTR_SIZE: usize = 33;

/// Parameters for serializing a btrfs node to on-disk format.
#[derive(Debug, Clone)]
pub struct BtrfsNodeSerializeParams {
    /// Filesystem UUID (16 bytes).
    pub fsid: [u8; 16],
    /// Chunk tree UUID (16 bytes).
    pub chunk_tree_uuid: [u8; 16],
    /// Byte offset where this node will be written on disk.
    pub bytenr: u64,
    /// Header flags (BTRFS_HEADER_FLAG_*).
    pub flags: u64,
    /// Current transaction generation.
    pub generation: u64,
    /// Tree ID that owns this node (e.g., FS_TREE = 5).
    pub owner: u64,
    /// Node size in bytes (from superblock, default 16384).
    pub nodesize: u32,
    /// Level of this node in the tree (0 = leaf, 1+ = internal).
    /// For leaves this is ignored (always 0). For internal nodes
    /// this must be > 0 and represent the actual tree depth.
    pub level: u8,
    /// Child generation values for internal nodes (indexed by child position).
    pub child_generations: Vec<u64>,
    /// On-disk byte offsets (typically btrfs *logical* addresses) for the
    /// internal-node children, when those differ from the in-memory block
    /// numbers carried by `BtrfsCowNode::Internal { children, .. }`.
    ///
    /// During production writeback the in-memory block numbers are not
    /// addresses btrfs can resolve through the chunk tree, so the
    /// destination is the address that `BtrfsAllocState::alloc_metadata_for_tree`
    /// handed out for that child node. When this vector is empty (its
    /// default), serialization falls back to writing the in-memory
    /// `children[i]` value verbatim — that path is preserved for the
    /// simulator and standalone serializer tests.
    pub child_bytenrs: Vec<u64>,
}

impl BtrfsCowNode {
    /// Serialize this node to on-disk btrfs format.
    ///
    /// Returns a byte vector of exactly `params.nodesize` bytes.
    pub fn serialize(
        &self,
        params: &BtrfsNodeSerializeParams,
    ) -> Result<Vec<u8>, BtrfsMutationError> {
        let nodesize = params.nodesize as usize;
        if nodesize < BTRFS_HEADER_SIZE {
            return Err(BtrfsMutationError::InvalidConfig(
                "nodesize too small for header",
            ));
        }

        let mut buf = vec![0u8; nodesize];

        // Write header fields (skip checksum at 0..32, computed last)
        // fsid at 0x20
        buf[0x20..0x30].copy_from_slice(&params.fsid);
        // bytenr at 0x30
        buf[0x30..0x38].copy_from_slice(&params.bytenr.to_le_bytes());
        // flags at 0x38
        buf[0x38..0x40].copy_from_slice(&params.flags.to_le_bytes());
        // chunk_tree_uuid at 0x40
        buf[0x40..0x50].copy_from_slice(&params.chunk_tree_uuid);
        // generation at 0x50
        buf[0x50..0x58].copy_from_slice(&params.generation.to_le_bytes());
        // owner at 0x58
        buf[0x58..0x60].copy_from_slice(&params.owner.to_le_bytes());

        match self {
            Self::Leaf { items } => {
                // nritems at 0x60
                let nritems = u32::try_from(items.len())
                    .map_err(|_| BtrfsMutationError::InvalidConfig("too many items"))?;
                buf[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
                // level at 0x64 = 0 for leaf
                buf[0x64] = 0;

                // Serialize items: item descriptors at header end, data from tail
                let mut item_offset = BTRFS_HEADER_SIZE;
                let mut data_end = nodesize;

                for item in items {
                    // Check space for item descriptor
                    if item_offset + BTRFS_ITEM_SIZE > data_end {
                        return Err(BtrfsMutationError::InvalidConfig("node overflow: items"));
                    }
                    // Check space for item data
                    let data_size = item.data.len();
                    if data_end < data_size || data_end - data_size < item_offset + BTRFS_ITEM_SIZE
                    {
                        return Err(BtrfsMutationError::InvalidConfig("node overflow: data"));
                    }

                    // Write item data from tail
                    data_end -= data_size;
                    buf[data_end..data_end + data_size].copy_from_slice(&item.data);

                    // Write item descriptor (25 bytes)
                    // key: objectid (8), type (1), offset (8) = 17 bytes
                    buf[item_offset..item_offset + 8]
                        .copy_from_slice(&item.key.objectid.to_le_bytes());
                    buf[item_offset + 8] = item.key.item_type;
                    buf[item_offset + 9..item_offset + 17]
                        .copy_from_slice(&item.key.offset.to_le_bytes());
                    // data offset (from header end) at 0x11
                    let data_offset = u32::try_from(data_end - BTRFS_HEADER_SIZE)
                        .map_err(|_| BtrfsMutationError::InvalidConfig("data offset overflow"))?;
                    buf[item_offset + 17..item_offset + 21]
                        .copy_from_slice(&data_offset.to_le_bytes());
                    // data size at 0x15
                    let size = u32::try_from(data_size)
                        .map_err(|_| BtrfsMutationError::InvalidConfig("data size overflow"))?;
                    buf[item_offset + 21..item_offset + 25].copy_from_slice(&size.to_le_bytes());

                    item_offset += BTRFS_ITEM_SIZE;
                }
            }
            Self::Internal { keys, children } => {
                if keys.len() + 1 != children.len() {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "keys.len + 1 != children.len",
                    ));
                }
                // nritems at 0x60 = number of key-pointers = children.len()
                let nritems = u32::try_from(children.len())
                    .map_err(|_| BtrfsMutationError::InvalidConfig("too many children"))?;
                buf[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
                // level at 0x64 > 0 for internal nodes
                if params.level == 0 {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "internal node level must be > 0",
                    ));
                }
                buf[0x64] = params.level;

                // Serialize key-pointers (33 bytes each)
                let mut kp_offset = BTRFS_HEADER_SIZE;
                for (i, child_ptr) in children.iter().enumerate() {
                    if kp_offset + BTRFS_KEY_PTR_SIZE > nodesize {
                        return Err(BtrfsMutationError::InvalidConfig("node overflow: key-ptrs"));
                    }

                    // key (17 bytes): use keys[i] if i < keys.len(), else use a max key
                    let key = if i < keys.len() {
                        &keys[i]
                    } else {
                        // Last child has no separator key in our model; use max key
                        static MAX_KEY: BtrfsKey = BtrfsKey {
                            objectid: u64::MAX,
                            item_type: u8::MAX,
                            offset: u64::MAX,
                        };
                        &MAX_KEY
                    };
                    buf[kp_offset..kp_offset + 8].copy_from_slice(&key.objectid.to_le_bytes());
                    buf[kp_offset + 8] = key.item_type;
                    buf[kp_offset + 9..kp_offset + 17].copy_from_slice(&key.offset.to_le_bytes());
                    // blockptr at 0x11 — prefer the explicit override (the
                    // child's allocated logical address) when present; fall
                    // back to the in-memory child block number for legacy
                    // and simulator callers.
                    let child_blockptr = params.child_bytenrs.get(i).copied().unwrap_or(*child_ptr);
                    buf[kp_offset + 17..kp_offset + 25]
                        .copy_from_slice(&child_blockptr.to_le_bytes());
                    // generation at 0x19
                    let child_gen = params
                        .child_generations
                        .get(i)
                        .copied()
                        .unwrap_or(params.generation);
                    buf[kp_offset + 25..kp_offset + 33].copy_from_slice(&child_gen.to_le_bytes());

                    kp_offset += BTRFS_KEY_PTR_SIZE;
                }
            }
        }

        // Compute CRC32C over [32..nodesize) and store at [0..4)
        let crc = ffs_types::crc32c(&buf[32..]);
        buf[0..4].copy_from_slice(&crc.to_le_bytes());

        Ok(buf)
    }

    /// Tree level: 0 for leaf, 1 for internal (simplified).
    #[must_use]
    pub fn level(&self) -> u8 {
        match self {
            Self::Leaf { .. } => 0,
            Self::Internal { .. } => 1,
        }
    }

    /// Number of items (leaf) or children (internal).
    #[must_use]
    pub fn nritems(&self) -> usize {
        match self {
            Self::Leaf { items } => items.len(),
            Self::Internal { children, .. } => children.len(),
        }
    }
}

/// Block lifecycle interface for btrfs COW mutation planning.
///
/// The in-memory tree uses this to allocate new node addresses and to
/// report nodes that became unreachable after a successful mutation.
pub trait BtrfsAllocator: std::fmt::Debug + Send + Sync {
    fn alloc_block(&mut self) -> Result<u64, BtrfsMutationError>;
    fn defer_free(&mut self, block: u64);
}

/// Default in-memory allocator used by `InMemoryCowBtrfsTree`.
#[derive(Debug, Clone, Default)]
pub struct InMemoryBtrfsAllocator {
    next_block: u64,
    deferred: Vec<u64>,
}

impl InMemoryBtrfsAllocator {
    #[must_use]
    pub fn with_start(next_block: u64) -> Self {
        Self {
            next_block,
            deferred: Vec::new(),
        }
    }
}

impl BtrfsAllocator for InMemoryBtrfsAllocator {
    fn alloc_block(&mut self) -> Result<u64, BtrfsMutationError> {
        let block = self.next_block;
        self.next_block = self
            .next_block
            .checked_add(1)
            .ok_or(BtrfsMutationError::AddressOverflow)?;
        Ok(block)
    }

    fn defer_free(&mut self, block: u64) {
        self.deferred.push(block);
    }
}

/// COW B-tree mutation interface used by write-path planning code.
pub trait BtrfsBTree {
    fn insert(&mut self, key: BtrfsKey, item: &[u8]) -> Result<u64, BtrfsMutationError>;
    fn delete(&mut self, key: &BtrfsKey) -> Result<u64, BtrfsMutationError>;
    fn update(&mut self, key: &BtrfsKey, item: &[u8]) -> Result<u64, BtrfsMutationError>;
    fn range(
        &self,
        start: &BtrfsKey,
        end: &BtrfsKey,
    ) -> Result<Vec<(BtrfsKey, Vec<u8>)>, BtrfsMutationError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InsertResult {
    node_id: u64,
    split: Option<(BtrfsKey, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeleteResult {
    node_id: u64,
    deleted: bool,
}

/// In-memory COW btrfs B-tree. Every mutation allocates new nodes and advances
/// the root pointer, keeping previously-addressed nodes immutable.
#[derive(Debug)]
pub struct InMemoryCowBtrfsTree {
    max_items: usize,
    min_items: usize,
    root: u64,
    allocator: Box<dyn BtrfsAllocator>,
    deferred_frees: Vec<u64>,
    staged_allocations: Vec<u64>,
    staged_deferred_frees: Vec<u64>,
    nodes: BTreeMap<u64, BtrfsCowNode>,
}

impl InMemoryCowBtrfsTree {
    /// Create a COW B-tree with the requested maximum keys/items per node.
    ///
    /// `max_items` must be >= 3 to allow split/merge behavior.
    pub fn new(max_items: usize) -> Result<Self, BtrfsMutationError> {
        Self::with_allocator(max_items, Box::new(InMemoryBtrfsAllocator::with_start(2)))
    }

    /// Create a COW B-tree with a custom block allocator.
    pub fn with_allocator(
        max_items: usize,
        allocator: Box<dyn BtrfsAllocator>,
    ) -> Result<Self, BtrfsMutationError> {
        if max_items < 3 {
            return Err(BtrfsMutationError::InvalidConfig("max_items must be >= 3"));
        }
        let root = 1_u64;
        let mut nodes = BTreeMap::new();
        nodes.insert(root, BtrfsCowNode::Leaf { items: Vec::new() });
        Ok(Self {
            max_items,
            min_items: max_items / 2,
            root,
            allocator,
            deferred_frees: Vec::new(),
            staged_allocations: Vec::new(),
            staged_deferred_frees: Vec::new(),
            nodes,
        })
    }

    /// Current root block identifier.
    #[must_use]
    pub fn root_block(&self) -> u64 {
        self.root
    }

    /// Root node level (0 for leaf, higher for internal).
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "btrfs tree level is limited to BTRFS_MAX_LEVEL (8)"
    )]
    pub fn root_level(&self) -> u8 {
        match self.height() {
            Ok(h) if h > 0 => (h - 1) as u8,
            _ => 0,
        }
    }

    /// Look up an item by exact key, returning its data if found.
    #[must_use]
    pub fn get(&self, key: &BtrfsKey) -> Option<Vec<u8>> {
        self.search(self.root, key).ok()
    }

    fn search(&self, node_id: u64, key: &BtrfsKey) -> Result<Vec<u8>, BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { items } => {
                for item in items {
                    if key_cmp(&item.key, key) == Ordering::Equal {
                        return Ok(item.data.clone());
                    }
                }
                Err(BtrfsMutationError::KeyNotFound)
            }
            BtrfsCowNode::Internal { keys, children } => {
                let idx = keys.partition_point(|k| key_cmp(k, key) != Ordering::Greater);
                self.search(children[idx], key)
            }
        }
    }

    /// Snapshot a node by block number.
    pub fn node_snapshot(&self, block: u64) -> Result<BtrfsCowNode, BtrfsMutationError> {
        self.nodes
            .get(&block)
            .cloned()
            .ok_or(BtrfsMutationError::MissingNode(block))
    }

    /// List of blocks marked for deferred free during successful mutations.
    #[must_use]
    pub fn deferred_free_blocks(&self) -> &[u64] {
        &self.deferred_frees
    }

    /// Return tree height (`1` for a leaf root).
    pub fn height(&self) -> Result<usize, BtrfsMutationError> {
        self.height_of(self.root)
    }

    /// Validate structure invariants:
    /// - key ordering
    /// - child count relationships
    /// - balanced depth
    /// - node occupancy for non-root nodes
    pub fn validate_invariants(&self) -> Result<(), BtrfsMutationError> {
        let mut leaf_depth = None;
        self.validate_node(self.root, None, None, 1, &mut leaf_depth, true)?;
        Ok(())
    }

    fn node_ref(&self, block: u64) -> Result<&BtrfsCowNode, BtrfsMutationError> {
        self.nodes
            .get(&block)
            .ok_or(BtrfsMutationError::MissingNode(block))
    }

    fn alloc_node(&mut self, node: BtrfsCowNode) -> Result<u64, BtrfsMutationError> {
        let block = self.allocator.alloc_block()?;
        self.nodes.insert(block, node);
        self.staged_allocations.push(block);
        trace!(block, "btrfs_cow_alloc_node");
        Ok(block)
    }

    fn retire_node(&mut self, block: u64) {
        self.staged_deferred_frees.push(block);
        trace!(block, "btrfs_cow_defer_free");
    }

    fn commit_retired_nodes(&mut self) {
        for block in self.staged_deferred_frees.drain(..) {
            self.allocator.defer_free(block);
            self.deferred_frees.push(block);
        }
    }

    fn commit_allocated_nodes(&mut self) {
        self.staged_allocations.clear();
    }

    fn discard_retired_nodes(&mut self) {
        self.staged_deferred_frees.clear();
    }

    fn rollback_allocated_nodes(&mut self) {
        for block in self.staged_allocations.drain(..).rev() {
            self.nodes.remove(&block);
            self.allocator.defer_free(block);
            trace!(block, "btrfs_cow_rollback_alloc");
        }
    }

    fn rollback_mutation(&mut self) {
        self.discard_retired_nodes();
        self.rollback_allocated_nodes();
    }

    fn child_slot(keys: &[BtrfsKey], key: &BtrfsKey) -> usize {
        keys.iter()
            .position(|sep| key_cmp(key, sep) == Ordering::Less)
            .unwrap_or(keys.len())
    }

    fn insert_entry(
        &mut self,
        entry: BtrfsTreeItem,
        allow_replace: bool,
    ) -> Result<u64, BtrfsMutationError> {
        debug_assert!(self.staged_allocations.is_empty());
        debug_assert!(self.staged_deferred_frees.is_empty());
        let old_root = self.root;
        trace!(
            root = old_root,
            objectid = entry.key.objectid,
            item_type = entry.key.item_type,
            offset = entry.key.offset,
            allow_replace,
            "btrfs_cow_insert_start"
        );
        let result = match self.insert_into(self.root, entry, allow_replace) {
            Ok(result) => result,
            Err(err) => {
                self.rollback_mutation();
                return Err(err);
            }
        };
        let new_root = if let Some((separator, right_id)) = result.split {
            debug!(
                old_root,
                left_root = result.node_id,
                right_root = right_id,
                separator_objectid = separator.objectid,
                separator_type = separator.item_type,
                separator_offset = separator.offset,
                "btrfs_cow_root_split"
            );
            match self.alloc_node(BtrfsCowNode::Internal {
                keys: vec![separator],
                children: vec![result.node_id, right_id],
            }) {
                Ok(new_root) => new_root,
                Err(err) => {
                    self.rollback_mutation();
                    return Err(err);
                }
            }
        } else {
            result.node_id
        };
        self.root = new_root;
        self.commit_allocated_nodes();
        self.commit_retired_nodes();
        trace!(old_root, new_root = self.root, "btrfs_cow_insert_complete");
        Ok(self.root)
    }

    fn insert_into(
        &mut self,
        node_id: u64,
        entry: BtrfsTreeItem,
        allow_replace: bool,
    ) -> Result<InsertResult, BtrfsMutationError> {
        let node = self.node_ref(node_id)?.clone();
        let result = match node {
            BtrfsCowNode::Leaf { items } => self.insert_into_leaf(items, entry, allow_replace),
            BtrfsCowNode::Internal { keys, children } => {
                self.insert_into_internal(keys, children, entry, allow_replace)
            }
        };
        if result.is_ok() {
            self.retire_node(node_id);
        }
        result
    }

    fn insert_into_leaf(
        &mut self,
        mut items: Vec<BtrfsTreeItem>,
        entry: BtrfsTreeItem,
        allow_replace: bool,
    ) -> Result<InsertResult, BtrfsMutationError> {
        let idx = items.partition_point(|existing| key_cmp(&existing.key, &entry.key).is_lt());
        if let Some(existing) = items.get_mut(idx)
            && key_cmp(&existing.key, &entry.key) == Ordering::Equal
        {
            if allow_replace {
                trace!(
                    objectid = entry.key.objectid,
                    item_type = entry.key.item_type,
                    offset = entry.key.offset,
                    "btrfs_cow_update_leaf"
                );
                existing.data = entry.data;
                let new_id = self.alloc_node(BtrfsCowNode::Leaf { items })?;
                return Ok(InsertResult {
                    node_id: new_id,
                    split: None,
                });
            }
            return Err(BtrfsMutationError::KeyAlreadyExists);
        }

        items.insert(idx, entry);
        if items.len() <= self.max_items {
            let new_id = self.alloc_node(BtrfsCowNode::Leaf { items })?;
            return Ok(InsertResult {
                node_id: new_id,
                split: None,
            });
        }

        let mid = items.len() / 2;
        let right_items = items.split_off(mid);
        let separator =
            right_items
                .first()
                .map(|item| item.key)
                .ok_or(BtrfsMutationError::BrokenInvariant(
                    "right split leaf must not be empty",
                ))?;
        debug!(
            separator_objectid = separator.objectid,
            separator_type = separator.item_type,
            separator_offset = separator.offset,
            left_items = items.len(),
            right_items = right_items.len(),
            "btrfs_cow_leaf_split"
        );
        let left_id = self.alloc_node(BtrfsCowNode::Leaf { items })?;
        let right_id = self.alloc_node(BtrfsCowNode::Leaf { items: right_items })?;
        Ok(InsertResult {
            node_id: left_id,
            split: Some((separator, right_id)),
        })
    }

    fn insert_into_internal(
        &mut self,
        mut keys: Vec<BtrfsKey>,
        mut children: Vec<u64>,
        entry: BtrfsTreeItem,
        allow_replace: bool,
    ) -> Result<InsertResult, BtrfsMutationError> {
        if children.len() != keys.len().saturating_add(1) {
            return Err(BtrfsMutationError::BrokenInvariant(
                "internal node child count mismatch",
            ));
        }

        let idx = Self::child_slot(&keys, &entry.key);
        let child_result = self.insert_into(children[idx], entry, allow_replace)?;
        children[idx] = child_result.node_id;
        if let Some((separator, right_child)) = child_result.split {
            keys.insert(idx, separator);
            children.insert(idx + 1, right_child);
        }

        if keys.len() <= self.max_items {
            let new_id = self.alloc_node(BtrfsCowNode::Internal { keys, children })?;
            return Ok(InsertResult {
                node_id: new_id,
                split: None,
            });
        }

        let mid = keys.len() / 2;
        let separator = keys[mid];
        let right_keys = keys.split_off(mid + 1);
        let removed = keys.pop();
        if removed.is_none() {
            return Err(BtrfsMutationError::BrokenInvariant(
                "internal split separator missing",
            ));
        }
        let right_children = children.split_off(mid + 1);
        debug!(
            separator_objectid = separator.objectid,
            separator_type = separator.item_type,
            separator_offset = separator.offset,
            left_keys = keys.len(),
            right_keys = right_keys.len(),
            "btrfs_cow_internal_split"
        );
        let left_id = self.alloc_node(BtrfsCowNode::Internal { keys, children })?;
        let right_id = self.alloc_node(BtrfsCowNode::Internal {
            keys: right_keys,
            children: right_children,
        })?;
        Ok(InsertResult {
            node_id: left_id,
            split: Some((separator, right_id)),
        })
    }

    fn first_key(&self, node_id: u64) -> Result<Option<BtrfsKey>, BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { items } => Ok(items.first().map(|item| item.key)),
            BtrfsCowNode::Internal { children, .. } => {
                let Some(first_child) = children.first() else {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "internal node must have children",
                    ));
                };
                self.first_key(*first_child)
            }
        }
    }

    fn compute_internal_keys(&self, children: &[u64]) -> Result<Vec<BtrfsKey>, BtrfsMutationError> {
        if children.is_empty() {
            return Err(BtrfsMutationError::BrokenInvariant(
                "internal node must have children",
            ));
        }
        let mut keys = Vec::with_capacity(children.len().saturating_sub(1));
        for child in children.iter().skip(1) {
            let Some(separator) = self.first_key(*child)? else {
                return Err(BtrfsMutationError::BrokenInvariant(
                    "internal separator child must contain a key",
                ));
            };
            keys.push(separator);
        }
        Ok(keys)
    }

    fn alloc_internal_node(&mut self, children: Vec<u64>) -> Result<u64, BtrfsMutationError> {
        let keys = self.compute_internal_keys(&children)?;
        self.alloc_node(BtrfsCowNode::Internal { keys, children })
    }

    fn node_key_count(&self, node_id: u64) -> Result<usize, BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { items } => Ok(items.len()),
            BtrfsCowNode::Internal { keys, .. } => Ok(keys.len()),
        }
    }

    fn rotate_from_left(
        &mut self,
        left_id: u64,
        right_id: u64,
    ) -> Result<(u64, u64), BtrfsMutationError> {
        let left_node = self.node_ref(left_id)?.clone();
        let right_node = self.node_ref(right_id)?.clone();
        match (left_node, right_node) {
            (
                BtrfsCowNode::Leaf {
                    items: mut left_items,
                },
                BtrfsCowNode::Leaf {
                    items: mut right_items,
                },
            ) => {
                let moved = left_items.pop().ok_or(BtrfsMutationError::BrokenInvariant(
                    "cannot borrow from empty left leaf",
                ))?;
                right_items.insert(0, moved);
                let new_left = self.alloc_node(BtrfsCowNode::Leaf { items: left_items })?;
                let new_right = self.alloc_node(BtrfsCowNode::Leaf { items: right_items })?;
                Ok((new_left, new_right))
            }
            (
                BtrfsCowNode::Internal {
                    children: mut left_children,
                    ..
                },
                BtrfsCowNode::Internal {
                    children: mut right_children,
                    ..
                },
            ) => {
                let moved = left_children
                    .pop()
                    .ok_or(BtrfsMutationError::BrokenInvariant(
                        "cannot borrow from empty left internal",
                    ))?;
                right_children.insert(0, moved);
                let new_left = self.alloc_internal_node(left_children)?;
                let new_right = self.alloc_internal_node(right_children)?;
                Ok((new_left, new_right))
            }
            _ => Err(BtrfsMutationError::BrokenInvariant(
                "sibling node type mismatch",
            )),
        }
    }

    fn rotate_from_right(
        &mut self,
        left_id: u64,
        right_id: u64,
    ) -> Result<(u64, u64), BtrfsMutationError> {
        let left_node = self.node_ref(left_id)?.clone();
        let right_node = self.node_ref(right_id)?.clone();
        match (left_node, right_node) {
            (
                BtrfsCowNode::Leaf {
                    items: mut left_items,
                },
                BtrfsCowNode::Leaf {
                    items: mut right_items,
                },
            ) => {
                if right_items.is_empty() {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "cannot borrow from empty right leaf",
                    ));
                }
                right_items.rotate_left(1);
                let moved = right_items
                    .pop()
                    .ok_or(BtrfsMutationError::BrokenInvariant(
                        "cannot borrow from empty right leaf",
                    ))?;
                left_items.push(moved);
                let new_left = self.alloc_node(BtrfsCowNode::Leaf { items: left_items })?;
                let new_right = self.alloc_node(BtrfsCowNode::Leaf { items: right_items })?;
                Ok((new_left, new_right))
            }
            (
                BtrfsCowNode::Internal {
                    children: mut left_children,
                    ..
                },
                BtrfsCowNode::Internal {
                    children: mut right_children,
                    ..
                },
            ) => {
                if right_children.is_empty() {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "cannot borrow from empty right internal",
                    ));
                }
                right_children.rotate_left(1);
                let moved = right_children
                    .pop()
                    .ok_or(BtrfsMutationError::BrokenInvariant(
                        "cannot borrow from empty right internal",
                    ))?;
                left_children.push(moved);
                let new_left = self.alloc_internal_node(left_children)?;
                let new_right = self.alloc_internal_node(right_children)?;
                Ok((new_left, new_right))
            }
            _ => Err(BtrfsMutationError::BrokenInvariant(
                "sibling node type mismatch",
            )),
        }
    }

    fn merge_adjacent_nodes(
        &mut self,
        left_id: u64,
        right_id: u64,
    ) -> Result<u64, BtrfsMutationError> {
        let left_node = self.node_ref(left_id)?.clone();
        let right_node = self.node_ref(right_id)?.clone();
        match (left_node, right_node) {
            (
                BtrfsCowNode::Leaf {
                    items: mut left_items,
                },
                BtrfsCowNode::Leaf { items: right_items },
            ) => {
                left_items.extend(right_items);
                self.alloc_node(BtrfsCowNode::Leaf { items: left_items })
            }
            (
                BtrfsCowNode::Internal {
                    children: mut left_children,
                    ..
                },
                BtrfsCowNode::Internal {
                    children: right_children,
                    ..
                },
            ) => {
                left_children.extend(right_children);
                self.alloc_internal_node(left_children)
            }
            _ => Err(BtrfsMutationError::BrokenInvariant(
                "cannot merge different node types",
            )),
        }
    }

    fn rebalance_child(
        &mut self,
        children: &mut Vec<u64>,
        child_idx: usize,
    ) -> Result<(), BtrfsMutationError> {
        if child_idx >= children.len() {
            return Err(BtrfsMutationError::BrokenInvariant(
                "child index out of bounds",
            ));
        }
        if children.len() <= 1 {
            return Ok(());
        }

        let child_keys = self.node_key_count(children[child_idx])?;
        if child_keys >= self.min_items {
            return Ok(());
        }

        if child_idx > 0 {
            let left_keys = self.node_key_count(children[child_idx - 1])?;
            if left_keys > self.min_items {
                let old_left = children[child_idx - 1];
                let old_child = children[child_idx];
                let (new_left, new_child) =
                    self.rotate_from_left(children[child_idx - 1], children[child_idx])?;
                children[child_idx - 1] = new_left;
                children[child_idx] = new_child;
                self.retire_node(old_left);
                self.retire_node(old_child);
                debug!(
                    child_idx,
                    left_keys, child_keys, "btrfs_cow_delete_borrow_left"
                );
                return Ok(());
            }
        }

        if child_idx + 1 < children.len() {
            let right_keys = self.node_key_count(children[child_idx + 1])?;
            if right_keys > self.min_items {
                let old_child = children[child_idx];
                let old_right = children[child_idx + 1];
                let (new_child, new_right) =
                    self.rotate_from_right(children[child_idx], children[child_idx + 1])?;
                children[child_idx] = new_child;
                children[child_idx + 1] = new_right;
                self.retire_node(old_child);
                self.retire_node(old_right);
                debug!(
                    child_idx,
                    right_keys, child_keys, "btrfs_cow_delete_borrow_right"
                );
                return Ok(());
            }
        }

        if child_idx > 0 {
            let old_left = children[child_idx - 1];
            let old_child = children[child_idx];
            let merged = self.merge_adjacent_nodes(children[child_idx - 1], children[child_idx])?;
            children[child_idx - 1] = merged;
            children.remove(child_idx);
            self.retire_node(old_left);
            self.retire_node(old_child);
            debug!(merged_child = child_idx - 1, "btrfs_cow_delete_merge_left");
        } else {
            let old_child = children[child_idx];
            let old_right = children[child_idx + 1];
            let merged = self.merge_adjacent_nodes(children[child_idx], children[child_idx + 1])?;
            children[child_idx] = merged;
            children.remove(child_idx + 1);
            self.retire_node(old_child);
            self.retire_node(old_right);
            debug!(merged_child = child_idx, "btrfs_cow_delete_merge_right");
        }
        Ok(())
    }

    fn delete_from(
        &mut self,
        node_id: u64,
        key: &BtrfsKey,
    ) -> Result<DeleteResult, BtrfsMutationError> {
        let node = self.node_ref(node_id)?.clone();
        match node {
            BtrfsCowNode::Leaf { mut items } => {
                let idx = items.partition_point(|existing| key_cmp(&existing.key, key).is_lt());
                let Some(existing) = items.get(idx) else {
                    return Ok(DeleteResult {
                        node_id,
                        deleted: false,
                    });
                };
                if key_cmp(&existing.key, key) != Ordering::Equal {
                    return Ok(DeleteResult {
                        node_id,
                        deleted: false,
                    });
                }
                items.remove(idx);
                let new_id = self.alloc_node(BtrfsCowNode::Leaf { items })?;
                self.retire_node(node_id);
                Ok(DeleteResult {
                    node_id: new_id,
                    deleted: true,
                })
            }
            BtrfsCowNode::Internal { keys, mut children } => {
                if children.len() != keys.len().saturating_add(1) {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "internal node child count mismatch",
                    ));
                }
                let idx = Self::child_slot(&keys, key);
                let child_result = self.delete_from(children[idx], key)?;
                if !child_result.deleted {
                    return Ok(DeleteResult {
                        node_id,
                        deleted: false,
                    });
                }
                children[idx] = child_result.node_id;
                self.rebalance_child(&mut children, idx)?;
                let new_id = self.alloc_internal_node(children)?;
                self.retire_node(node_id);
                Ok(DeleteResult {
                    node_id: new_id,
                    deleted: true,
                })
            }
        }
    }

    fn normalized_root_after_delete(&mut self, mut root: u64) -> Result<u64, BtrfsMutationError> {
        loop {
            let root_node = self.node_ref(root)?.clone();
            let BtrfsCowNode::Internal { children, .. } = root_node else {
                break;
            };
            if children.len() != 1 {
                break;
            }
            let Some(child) = children.first() else {
                return Err(BtrfsMutationError::BrokenInvariant(
                    "internal node must have children",
                ));
            };
            let old_root = root;
            root = *child;
            self.retire_node(old_root);
        }
        Ok(root)
    }

    fn find(&self, key: &BtrfsKey) -> Result<Option<Vec<u8>>, BtrfsMutationError> {
        self.find_in(self.root, key)
    }

    fn find_in(&self, node_id: u64, key: &BtrfsKey) -> Result<Option<Vec<u8>>, BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { items } => Ok(items
                .iter()
                .find(|item| key_cmp(&item.key, key) == Ordering::Equal)
                .map(|item| item.data.clone())),
            BtrfsCowNode::Internal { keys, children } => {
                if children.len() != keys.len().saturating_add(1) {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "internal node child count mismatch",
                    ));
                }
                let idx = Self::child_slot(keys, key);
                self.find_in(children[idx], key)
            }
        }
    }

    fn height_of(&self, node_id: u64) -> Result<usize, BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { .. } => Ok(1),
            BtrfsCowNode::Internal { children, .. } => {
                let mut child_heights = children
                    .iter()
                    .map(|child| self.height_of(*child))
                    .collect::<Result<Vec<_>, _>>()?;
                let first = child_heights
                    .pop()
                    .ok_or(BtrfsMutationError::BrokenInvariant(
                        "internal node must have children",
                    ))?;
                if child_heights.iter().any(|height| *height != first) {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "tree is not height-balanced",
                    ));
                }
                Ok(first + 1)
            }
        }
    }

    fn validate_node(
        &self,
        node_id: u64,
        lower: Option<BtrfsKey>,
        upper: Option<BtrfsKey>,
        depth: usize,
        leaf_depth: &mut Option<usize>,
        is_root: bool,
    ) -> Result<(), BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { items } => {
                if !is_root && items.len() < self.min_items {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "non-root leaf underflow",
                    ));
                }
                for window in items.windows(2) {
                    if key_cmp(&window[0].key, &window[1].key) != Ordering::Less {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "leaf keys must be strictly increasing",
                        ));
                    }
                }
                for item in items {
                    if let Some(min_key) = lower
                        && key_cmp(&item.key, &min_key) == Ordering::Less
                    {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "leaf key below lower bound",
                        ));
                    }
                    if let Some(max_key) = upper
                        && key_cmp(&item.key, &max_key) != Ordering::Less
                    {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "leaf key above upper bound",
                        ));
                    }
                }
                if let Some(expected_depth) = *leaf_depth {
                    if expected_depth != depth {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "leaves must have uniform depth",
                        ));
                    }
                } else {
                    *leaf_depth = Some(depth);
                }
                Ok(())
            }
            BtrfsCowNode::Internal { keys, children } => {
                if children.len() != keys.len().saturating_add(1) {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "internal node child count mismatch",
                    ));
                }
                if !is_root && keys.len() < self.min_items {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "non-root internal underflow",
                    ));
                }
                for window in keys.windows(2) {
                    if key_cmp(&window[0], &window[1]) != Ordering::Less {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "internal separators must be strictly increasing",
                        ));
                    }
                }
                for (idx, separator) in keys.iter().enumerate() {
                    let Some(expected) = self.first_key(children[idx + 1])? else {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "separator child must contain a key",
                        ));
                    };
                    if key_cmp(separator, &expected) != Ordering::Equal {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "internal separator mismatch",
                        ));
                    }
                }
                for (idx, child) in children.iter().enumerate() {
                    let child_lower = if idx == 0 { lower } else { Some(keys[idx - 1]) };
                    let child_upper = if idx == keys.len() {
                        upper
                    } else {
                        Some(keys[idx])
                    };
                    self.validate_node(
                        *child,
                        child_lower,
                        child_upper,
                        depth + 1,
                        leaf_depth,
                        false,
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl BtrfsBTree for InMemoryCowBtrfsTree {
    fn insert(&mut self, key: BtrfsKey, item: &[u8]) -> Result<u64, BtrfsMutationError> {
        self.insert_entry(
            BtrfsTreeItem {
                key,
                data: item.to_vec(),
            },
            false,
        )
    }

    fn delete(&mut self, key: &BtrfsKey) -> Result<u64, BtrfsMutationError> {
        debug_assert!(self.staged_allocations.is_empty());
        debug_assert!(self.staged_deferred_frees.is_empty());
        let old_root = self.root;
        trace!(
            root = old_root,
            objectid = key.objectid,
            item_type = key.item_type,
            offset = key.offset,
            "btrfs_cow_delete_start"
        );
        let deleted = match self.delete_from(self.root, key) {
            Ok(deleted) => deleted,
            Err(err) => {
                self.rollback_mutation();
                return Err(err);
            }
        };
        if !deleted.deleted {
            self.rollback_mutation();
            return Err(BtrfsMutationError::KeyNotFound);
        }
        let new_root = match self.normalized_root_after_delete(deleted.node_id) {
            Ok(new_root) => new_root,
            Err(err) => {
                self.rollback_mutation();
                return Err(err);
            }
        };
        self.root = new_root;
        self.commit_allocated_nodes();
        self.commit_retired_nodes();
        trace!(old_root, new_root = self.root, "btrfs_cow_delete_complete");
        Ok(self.root)
    }

    fn update(&mut self, key: &BtrfsKey, item: &[u8]) -> Result<u64, BtrfsMutationError> {
        if self.find(key)?.is_none() {
            return Err(BtrfsMutationError::KeyNotFound);
        }
        self.insert_entry(
            BtrfsTreeItem {
                key: *key,
                data: item.to_vec(),
            },
            true,
        )
    }

    fn range(
        &self,
        start: &BtrfsKey,
        end: &BtrfsKey,
    ) -> Result<Vec<(BtrfsKey, Vec<u8>)>, BtrfsMutationError> {
        if key_cmp(start, end) == Ordering::Greater {
            return Err(BtrfsMutationError::InvalidRange);
        }
        let mut out = Vec::new();
        self.collect_range_from(self.root, start, end, &mut out)?;
        Ok(out)
    }
}

impl InMemoryCowBtrfsTree {
    /// B-tree-aware range descent. Only visits internal children whose
    /// `[keys[i-1], keys[i])` span intersects `[start, end]`, and uses
    /// `partition_point` on sorted leaves so the result is O(log N + k)
    /// per call instead of a full-tree materialisation followed by
    /// filter. bd-yt66z's `btrfs_resolve_inode_path_via_cow`
    /// fast path depends on this for its O(depth · log N) complexity.
    fn collect_range_from(
        &self,
        node_id: u64,
        start: &BtrfsKey,
        end: &BtrfsKey,
        out: &mut Vec<(BtrfsKey, Vec<u8>)>,
    ) -> Result<(), BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { items } => {
                let lo = items.partition_point(|item| key_cmp(&item.key, start).is_lt());
                for item in &items[lo..] {
                    if key_cmp(&item.key, end).is_gt() {
                        break;
                    }
                    out.push((item.key, item.data.clone()));
                }
            }
            BtrfsCowNode::Internal { keys, children } => {
                // children[i] holds keys in [keys[i-1], keys[i]); edges are
                // sentinels (-inf, +inf). Skip children whose upper bound
                // `keys[i]` is <= start (all their keys are < start), and
                // stop once a child's lower bound `keys[i-1]` is > end
                // (all remaining children are strictly past the query).
                for (i, child) in children.iter().enumerate() {
                    if let Some(high) = keys.get(i)
                        && key_cmp(high, start) != Ordering::Greater
                    {
                        continue;
                    }
                    if i > 0 && key_cmp(&keys[i - 1], end).is_gt() {
                        break;
                    }
                    self.collect_range_from(*child, start, end, out)?;
                }
            }
        }
        Ok(())
    }
}

// ── Extent allocation ───────────────────────────────────────────────────────

/// On-disk block group item: describes a contiguous region of the address space
/// and how much of it is allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsBlockGroupItem {
    /// Total bytes in this block group.
    pub total_bytes: u64,
    /// Bytes currently allocated.
    pub used_bytes: u64,
    /// Type flags (DATA, METADATA, SYSTEM).
    pub flags: u64,
}

impl BtrfsBlockGroupItem {
    /// Serialize to on-disk format (24 bytes LE).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&self.used_bytes.to_le_bytes());
        buf.extend_from_slice(&self.total_bytes.to_le_bytes()); // Note: kernel stores chunk_objectid here; we reuse for total
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf
    }

    /// Free bytes remaining.
    #[must_use]
    pub fn free_bytes(&self) -> u64 {
        self.total_bytes.saturating_sub(self.used_bytes)
    }
}

/// On-disk extent item: records a single allocated extent and its reference count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsExtentItem {
    /// Reference count.
    pub refs: u64,
    /// Generation.
    pub generation: u64,
    /// Flags.
    pub flags: u64,
}

impl BtrfsExtentItem {
    /// Extent flag: this extent holds file data (`BTRFS_EXTENT_FLAG_DATA`).
    pub const FLAG_DATA: u64 = 1;
    /// Extent flag: this is a tree block (metadata).
    pub const FLAG_TREE_BLOCK: u64 = 2;

    /// Serialize to on-disk format (24 bytes LE).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&self.refs.to_le_bytes());
        buf.extend_from_slice(&self.generation.to_le_bytes());
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf
    }
}

/// On-disk structure for data extent back-references.
///
/// This corresponds to `struct btrfs_extent_data_ref` from the kernel.
/// Key: (bytenr, EXTENT_DATA_REF, hash), Value: this 28-byte struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsExtentDataRef {
    /// Root tree containing the referencing inode.
    pub root: u64,
    /// Inode number of the referencing file.
    pub objectid: u64,
    /// Offset within the file where this extent is referenced.
    pub offset: u64,
    /// Reference count (usually 1, >1 for shared extents).
    pub count: u32,
}

impl BtrfsExtentDataRef {
    /// Parse from on-disk format (28 bytes LE).
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 28 {
            return None;
        }
        Some(Self {
            root: u64::from_le_bytes(data[0..8].try_into().ok()?),
            objectid: u64::from_le_bytes(data[8..16].try_into().ok()?),
            offset: u64::from_le_bytes(data[16..24].try_into().ok()?),
            count: u32::from_le_bytes(data[24..28].try_into().ok()?),
        })
    }

    /// Serialize to on-disk format (28 bytes LE).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(28);
        buf.extend_from_slice(&self.root.to_le_bytes());
        buf.extend_from_slice(&self.objectid.to_le_bytes());
        buf.extend_from_slice(&self.offset.to_le_bytes());
        buf.extend_from_slice(&self.count.to_le_bytes());
        buf
    }
}

/// Logical key for a physical extent in delayed reference bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtentKey {
    /// Physical byte address of the extent.
    pub bytenr: u64,
    /// Extent length in bytes.
    pub num_bytes: u64,
}

/// Reference kinds tracked by delayed references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtrfsRef {
    /// Tree block back-reference.
    TreeBlock {
        root: u64,
        owner: u64,
        offset: u64,
        level: u8,
    },
    /// Data extent back-reference.
    DataExtent {
        root: u64,
        objectid: u64,
        offset: u64,
    },
    /// Shared tree block reference.
    SharedTreeBlock { parent: u64, level: u8 },
    /// Shared data extent reference.
    SharedDataExtent { parent: u64 },
}

/// Delayed reference action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefAction {
    /// Add a back-reference (increment refcount).
    Insert,
    /// Delete a back-reference (decrement refcount).
    Delete,
}

/// A delayed reference entry queued for batch processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelayedRef {
    /// Extent this reference applies to.
    pub extent: ExtentKey,
    /// Reference shape.
    pub ref_type: BtrfsRef,
    /// Insert/delete action.
    pub action: RefAction,
    /// Monotonic sequence number for deterministic replay.
    pub sequence: u64,
}

/// Delayed reference queue keyed by extent, with deterministic sequencing.
#[derive(Debug, Clone, Default)]
pub struct DelayedRefQueue {
    refs: BTreeMap<ExtentKey, Vec<DelayedRef>>,
    pending_count: usize,
    next_sequence: u64,
}

impl DelayedRefQueue {
    /// Create an empty delayed reference queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a delayed reference action for an extent.
    pub fn queue(&mut self, extent: ExtentKey, ref_type: BtrfsRef, action: RefAction) {
        let seq = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let entry = DelayedRef {
            extent,
            ref_type,
            action,
            sequence: seq,
        };
        self.refs.entry(extent).or_default().push(entry);
        self.pending_count = self.pending_count.saturating_add(1);
    }

    /// Number of queued delayed reference entries.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Borrow pending entries for one extent key.
    #[must_use]
    pub fn pending_for(&self, extent: &ExtentKey) -> &[DelayedRef] {
        self.refs.get(extent).map_or(&[], Vec::as_slice)
    }

    /// Flush up to `limit` delayed refs into persistent refcounts.
    ///
    /// Returns number of flushed entries.
    pub fn flush(
        &mut self,
        limit: usize,
        refcounts: &mut BTreeMap<ExtentKey, u64>,
    ) -> Result<usize, BtrfsMutationError> {
        if limit == 0 || self.pending_count == 0 {
            return Ok(0);
        }

        let started = std::time::Instant::now();
        let mut flushed = 0usize;
        let mut selected = Vec::new();
        let extent_keys: Vec<ExtentKey> = self.refs.keys().copied().collect();
        let mut candidate_refcounts = refcounts.clone();

        for extent in extent_keys {
            if flushed >= limit {
                break;
            }

            let Some(entries) = self.refs.get(&extent) else {
                continue;
            };

            let remaining_budget = limit - flushed;
            let take_n = remaining_budget.min(entries.len());

            for entry in entries.iter().copied().take(take_n) {
                match entry.action {
                    RefAction::Insert => {
                        let counter = candidate_refcounts.entry(entry.extent).or_insert(0);
                        let next =
                            counter
                                .checked_add(1)
                                .ok_or(BtrfsMutationError::BrokenInvariant(
                                    "delayed ref insert overflow",
                                ))?;
                        *counter = next;
                    }
                    RefAction::Delete => match candidate_refcounts.entry(entry.extent) {
                        std::collections::btree_map::Entry::Occupied(mut occ) => {
                            let current = *occ.get();
                            if current == 0 {
                                return Err(BtrfsMutationError::BrokenInvariant(
                                    "delayed ref delete underflow",
                                ));
                            }
                            let next = current - 1;
                            if next == 0 {
                                occ.remove_entry();
                            } else {
                                *occ.get_mut() = next;
                            }
                        }
                        std::collections::btree_map::Entry::Vacant(_) => {
                            return Err(BtrfsMutationError::BrokenInvariant(
                                "delayed ref delete without prior refcount",
                            ));
                        }
                    },
                }
            }

            selected.push((extent, take_n));
            flushed = flushed.saturating_add(take_n);
        }

        let mut to_prune = Vec::new();
        for (extent, take_n) in selected {
            let Some(entries) = self.refs.get_mut(&extent) else {
                continue;
            };
            entries.drain(..take_n);
            self.pending_count = self.pending_count.saturating_sub(take_n);

            if entries.is_empty() {
                to_prune.push(extent);
            }
        }

        for extent in to_prune {
            self.refs.remove(&extent);
        }
        *refcounts = candidate_refcounts;

        debug!(
            target: "ffs::btrfs::alloc",
            flushed,
            remaining = self.pending_count,
            duration_us = started.elapsed().as_micros(),
            "delayed_ref_flush_batch"
        );

        Ok(flushed)
    }

    /// Drain all queued delayed refs in sequence order.
    pub fn drain_all(&mut self) -> Vec<DelayedRef> {
        let mut drained: Vec<DelayedRef> = self
            .refs
            .values_mut()
            .flat_map(|entries| entries.drain(..))
            .collect();
        self.refs.clear();
        self.pending_count = 0;
        drained.sort_by_key(|entry| entry.sequence);
        drained
    }
}

/// Logical tree identifier for btrfs roots.
pub type TreeId = u64;

/// Root pointer update staged by a btrfs transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeRoot {
    /// Logical bytenr of the new root node.
    pub bytenr: u64,
    /// Tree level of the root node.
    pub level: u8,
}

/// Summary returned when a transaction is aborted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsAbortSummary {
    pub txn_id: TxnId,
    pub discarded_tree_updates: usize,
    pub released_allocations: Vec<BlockNumber>,
    pub deferred_frees: Vec<BlockNumber>,
}

/// Errors from btrfs transaction orchestration.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BtrfsTransactionError {
    #[error("request checkpoint failed before transaction begin")]
    CancelledBegin,
    #[error("request checkpoint failed before transaction commit")]
    CancelledCommit,
    #[error("request checkpoint failed after transaction commit")]
    CancelledPostCommit,
    #[error("btrfs transaction already finished")]
    AlreadyFinished,
    #[error("tree root set is empty; stage at least one root update before commit")]
    EmptyRootSet,
    #[error("tree root block address overflow for tree_id={tree_id}")]
    TreeRootAddressOverflow { tree_id: TreeId },
    #[error("transaction metadata block address overflow for txn_id={txn_id:?}")]
    MetadataAddressOverflow { txn_id: TxnId },
    #[error("pending-free metadata block address overflow for txn_id={txn_id:?}")]
    PendingFreeAddressOverflow { txn_id: TxnId },
    #[error("delayed reference flush failed: {0:?}")]
    DelayedRefs(BtrfsMutationError),
    #[error("mvcc commit failed: {0}")]
    Commit(#[from] CommitError),
}

/// In-memory btrfs transaction handle bridged onto MVCC commit boundaries.
///
/// This models core btrfs transaction semantics:
/// - snapshot-at-begin reads
/// - staged tree-root updates
/// - delayed-ref accumulation + flush on commit
/// - explicit abort path with allocation cleanup bookkeeping
#[derive(Debug)]
pub struct BtrfsTransaction {
    txn_id: TxnId,
    snapshot: Snapshot,
    generation: u64,
    mvcc_txn: Option<Transaction>,
    pending_trees: BTreeMap<TreeId, TreeRoot>,
    delayed_refs: DelayedRefQueue,
    allocated: Vec<BlockNumber>,
    to_free: Vec<BlockNumber>,
}

impl BtrfsTransaction {
    /// Begin a btrfs transaction backed by an MVCC transaction.
    pub fn begin(
        store: &mut MvccStore,
        generation: u64,
        cx: &Cx,
    ) -> Result<Self, BtrfsTransactionError> {
        cx.checkpoint()
            .map_err(|_| BtrfsTransactionError::CancelledBegin)?;
        let mvcc_txn = store.begin();
        debug!(
            target: "ffs::btrfs::txn",
            txn_id = mvcc_txn.id.0,
            snapshot = mvcc_txn.snapshot.high.0,
            generation,
            "btrfs_tx_begin"
        );
        Ok(Self {
            txn_id: mvcc_txn.id,
            snapshot: mvcc_txn.snapshot,
            generation,
            mvcc_txn: Some(mvcc_txn),
            pending_trees: BTreeMap::new(),
            delayed_refs: DelayedRefQueue::new(),
            allocated: Vec::new(),
            to_free: Vec::new(),
        })
    }

    /// Transaction identifier.
    #[must_use]
    pub const fn txn_id(&self) -> TxnId {
        self.txn_id
    }

    /// Snapshot captured at begin.
    #[must_use]
    pub const fn snapshot(&self) -> Snapshot {
        self.snapshot
    }

    /// Transaction generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Staged tree-root updates.
    #[must_use]
    pub fn pending_trees(&self) -> &BTreeMap<TreeId, TreeRoot> {
        &self.pending_trees
    }

    /// Number of queued delayed references.
    #[must_use]
    pub fn delayed_ref_count(&self) -> usize {
        self.delayed_refs.pending_count()
    }

    /// Queue or replace a tree-root update.
    pub fn stage_tree_root(&mut self, tree_id: TreeId, root: TreeRoot) {
        self.pending_trees.insert(tree_id, root);
    }

    /// Stage a logical block write in the underlying MVCC transaction.
    pub fn stage_block_write(
        &mut self,
        block: BlockNumber,
        data: Vec<u8>,
    ) -> Result<(), BtrfsTransactionError> {
        let txn = self
            .mvcc_txn
            .as_mut()
            .ok_or(BtrfsTransactionError::AlreadyFinished)?;
        txn.stage_write(block, data);
        Ok(())
    }

    /// Record a newly allocated block so abort can return it for cleanup.
    pub fn track_allocation(&mut self, block: BlockNumber) {
        self.allocated.push(block);
    }

    /// Record a block to be freed after a successful commit.
    pub fn defer_free_on_commit(&mut self, block: BlockNumber) {
        self.to_free.push(block);
    }

    /// Queue a delayed reference to flush during commit.
    pub fn queue_delayed_ref(&mut self, extent: ExtentKey, ref_type: BtrfsRef, action: RefAction) {
        self.delayed_refs.queue(extent, ref_type, action);
    }

    /// Commit this transaction through MVCC.
    ///
    /// Commit steps:
    /// 1. Flush delayed refs deterministically.
    /// 2. Stage tree-root updates and metadata records.
    /// 3. Commit the MVCC transaction (FCW conflict detection).
    pub fn commit(
        mut self,
        store: &mut MvccStore,
        cx: &Cx,
    ) -> Result<CommitSeq, BtrfsTransactionError> {
        cx.checkpoint()
            .map_err(|_| BtrfsTransactionError::CancelledCommit)?;
        if self.pending_trees.is_empty() {
            return Err(BtrfsTransactionError::EmptyRootSet);
        }

        let commit_started = std::time::Instant::now();
        let delayed_ref_total = self.delayed_refs.pending_count();
        let mut materialized_refcounts = BTreeMap::new();
        if delayed_ref_total > 0 {
            self.delayed_refs
                .flush(usize::MAX, &mut materialized_refcounts)
                .map_err(BtrfsTransactionError::DelayedRefs)?;
        }

        self.stage_metadata_records()?;

        let txn = self
            .mvcc_txn
            .take()
            .ok_or(BtrfsTransactionError::AlreadyFinished)?;
        let commit_seq = store.commit(txn)?;
        let duration_us = u64::try_from(commit_started.elapsed().as_micros()).unwrap_or(u64::MAX);
        info!(
            target: "ffs::btrfs::txn",
            txn_id = self.txn_id.0,
            generation = self.generation,
            commit_seq = commit_seq.0,
            trees_modified = self.pending_trees.len(),
            delayed_refs_flushed = delayed_ref_total,
            staged_allocations = self.allocated.len(),
            pending_frees = self.to_free.len(),
            duration_us,
            "btrfs_tx_commit"
        );
        cx.checkpoint()
            .map_err(|_| BtrfsTransactionError::CancelledPostCommit)?;
        Ok(commit_seq)
    }

    /// Abort this transaction and return cleanup bookkeeping.
    #[must_use]
    pub fn abort(mut self) -> BtrfsAbortSummary {
        let _ = self.mvcc_txn.take();
        warn!(
            target: "ffs::btrfs::txn",
            txn_id = self.txn_id.0,
            generation = self.generation,
            discarded_tree_updates = self.pending_trees.len(),
            allocated = self.allocated.len(),
            deferred_frees = self.to_free.len(),
            "btrfs_tx_abort"
        );
        BtrfsAbortSummary {
            txn_id: self.txn_id,
            discarded_tree_updates: self.pending_trees.len(),
            released_allocations: self.allocated,
            deferred_frees: self.to_free,
        }
    }

    fn stage_metadata_records(&mut self) -> Result<(), BtrfsTransactionError> {
        let tx_meta_block = Self::metadata_block_for_txn(self.txn_id)?;
        self.stage_block_write(tx_meta_block, self.encode_tx_metadata())?;

        let tree_updates: Vec<(TreeId, TreeRoot)> = self
            .pending_trees
            .iter()
            .map(|(tree_id, root)| (*tree_id, *root))
            .collect();
        for (tree_id, root) in tree_updates {
            let block = Self::tree_root_block(tree_id)?;
            let payload = Self::encode_tree_root_record(self.generation, tree_id, root);
            self.stage_block_write(block, payload)?;
        }

        if !self.to_free.is_empty() {
            let free_block = Self::pending_free_block_for_txn(self.txn_id)?;
            self.stage_block_write(free_block, self.encode_pending_frees())?;
        }

        Ok(())
    }

    fn metadata_block_for_txn(txn_id: TxnId) -> Result<BlockNumber, BtrfsTransactionError> {
        BTRFS_TX_META_BASE_BLOCK
            .checked_add(txn_id.0)
            .map(BlockNumber)
            .ok_or(BtrfsTransactionError::MetadataAddressOverflow { txn_id })
    }

    fn tree_root_block(tree_id: TreeId) -> Result<BlockNumber, BtrfsTransactionError> {
        BTRFS_TX_TREE_ROOT_BASE_BLOCK
            .checked_add(tree_id)
            .map(BlockNumber)
            .ok_or(BtrfsTransactionError::TreeRootAddressOverflow { tree_id })
    }

    fn pending_free_block_for_txn(txn_id: TxnId) -> Result<BlockNumber, BtrfsTransactionError> {
        BTRFS_TX_PENDING_FREE_BASE_BLOCK
            .checked_add(txn_id.0)
            .map(BlockNumber)
            .ok_or(BtrfsTransactionError::PendingFreeAddressOverflow { txn_id })
    }

    fn encode_tx_metadata(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&self.generation.to_le_bytes());
        bytes.extend_from_slice(&self.snapshot.high.0.to_le_bytes());
        bytes.extend_from_slice(&self.txn_id.0.to_le_bytes());
        bytes.extend_from_slice(&(self.pending_trees.len() as u64).to_le_bytes());
        bytes
    }

    fn encode_pending_frees(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + self.to_free.len().saturating_mul(8));
        bytes.extend_from_slice(&(self.to_free.len() as u64).to_le_bytes());
        for block in &self.to_free {
            bytes.extend_from_slice(&block.0.to_le_bytes());
        }
        bytes
    }

    fn encode_tree_root_record(generation: u64, tree_id: TreeId, root: TreeRoot) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&generation.to_le_bytes());
        bytes.extend_from_slice(&tree_id.to_le_bytes());
        bytes.extend_from_slice(&root.bytenr.to_le_bytes());
        bytes.push(root.level);
        bytes
    }
}

/// Result of an extent allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentAllocation {
    /// Physical byte address of the allocated extent.
    pub bytenr: u64,
    /// Size of the allocated extent.
    pub num_bytes: u64,
    /// Block group the allocation came from.
    pub block_group_start: u64,
}

/// Free-space layout of one block group.
///
/// Holds the maximal free `[start, start + len)` ranges within the group's
/// span (sorted by start), as the btrfs `FREE_SPACE_TREE` records them.
/// Produced by [`BtrfsExtentAllocator::free_space_extents`] for
/// FREE_SPACE_TREE maintenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockGroupFreeSpace {
    /// Starting byte address of the block group.
    pub start: u64,
    /// Total size of the block group in bytes (the `FREE_SPACE_INFO` key offset).
    pub total_bytes: u64,
    /// Block group flags (DATA / METADATA / SYSTEM, etc.).
    pub flags: u64,
    /// Free `[start, len)` ranges within the group, sorted by start.
    pub free_ranges: Vec<(u64, u64)>,
}

/// Build the on-disk `FREE_SPACE_TREE` items for the given per-block-group free
/// space, in ascending btrfs key order.
///
/// For each block group this emits one `FREE_SPACE_INFO` item followed by one
/// `FREE_SPACE_EXTENT` item per free range — the extent-based representation
/// (`flags = 0`), which btrfs uses whenever it is at least as compact as a
/// bitmap. Item formats (confirmed against `btrfs inspect-internal dump-tree`):
///
/// * `FREE_SPACE_INFO`: key `(bg_start, 198, bg_total_bytes)`, value =
///   `extent_count: u32_le` + `flags: u32_le` (8 bytes).
/// * `FREE_SPACE_EXTENT`: key `(free_start, 199, free_len)`, empty value.
///
/// The returned items are globally sorted by `(objectid, type, offset)`, ready
/// to bulk-insert into a fresh free-space-tree btree (bd-qxo5x). Groups with no
/// free range still emit their `FREE_SPACE_INFO` with `extent_count = 0`.
#[must_use]
pub fn build_free_space_tree_items(groups: &[BlockGroupFreeSpace]) -> Vec<(BtrfsKey, Vec<u8>)> {
    let mut items = Vec::new();
    for group in groups {
        let extent_count = u32::try_from(group.free_ranges.len()).unwrap_or(u32::MAX);
        let info_key = BtrfsKey {
            objectid: group.start,
            item_type: BTRFS_ITEM_FREE_SPACE_INFO,
            offset: group.total_bytes,
        };
        let mut info_value = Vec::with_capacity(8);
        info_value.extend_from_slice(&extent_count.to_le_bytes());
        info_value.extend_from_slice(&0_u32.to_le_bytes()); // flags = 0 (extent list)
        items.push((info_key, info_value));

        for &(free_start, free_len) in &group.free_ranges {
            let extent_key = BtrfsKey {
                objectid: free_start,
                item_type: BTRFS_ITEM_FREE_SPACE_EXTENT,
                offset: free_len,
            };
            items.push((extent_key, Vec::new()));
        }
    }
    items.sort_by(|(a, _), (b, _)| {
        (a.objectid, a.item_type, a.offset).cmp(&(b.objectid, b.item_type, b.offset))
    });
    items
}

/// In-memory block group state tracked by the extent allocator.
#[derive(Debug, Clone)]
struct BlockGroupState {
    /// Starting byte address of this block group.
    start: u64,
    /// On-disk item.
    item: BtrfsBlockGroupItem,
    /// Hint for next allocation search offset within this group.
    alloc_offset: u64,
    /// Lowest offset within the group that may be handed out. Captured at
    /// registration from the group's already-used bytes, this fences off the
    /// reserved prefix (superblock / system / root region that carries no
    /// EXTENT_ITEM in the data allocator's tree). The wrap-around gap search
    /// must clamp to `start + min_usable_offset`; otherwise, when every data
    /// extent in a group rooted at logical 0 has been freed (gap scan sees an
    /// empty range set), it would reset to `start == 0` and hand out bytenr 0 —
    /// the btrfs hole/none sentinel — silently turning the write into a hole
    /// that reads back as zeros (bd-5aybu).
    min_usable_offset: u64,
}

/// Extent allocator for btrfs write path.
///
/// Manages block groups and finds free space by scanning for gaps between
/// allocated extents in the extent tree. For V1 single-device, free space
/// is determined by gap analysis (no free-space-tree optimization yet).
#[derive(Debug)]
pub struct BtrfsExtentAllocator {
    /// Block groups, keyed by start address.
    block_groups: BTreeMap<u64, BlockGroupState>,
    /// The extent tree (COW B-tree tracking allocated extents).
    extent_tree: InMemoryCowBtrfsTree,
    /// Queued delayed references for batch commit.
    delayed_ref_queue: DelayedRefQueue,
    /// Refcounts materialized by delayed-ref flush.
    extent_refcounts: BTreeMap<ExtentKey, u64>,
    /// Current transaction generation.
    generation: u64,
    /// Filesystem node size, used to size skinny `METADATA_ITEM` extents during
    /// gap analysis. A skinny `METADATA_ITEM` key encodes the tree *level* in its
    /// offset (not the byte length), so the gap finder must treat it as one
    /// `nodesize` tree block; otherwise it under-sizes live metadata to a few
    /// bytes and allocates straight into it, aliasing existing tree nodes
    /// (`btrfs check` then reports parent-transid mismatches — part of bd-x36qn).
    nodesize: u64,
}

/// Default btrfs node size (16 KiB), used until the real superblock value is set.
const BTRFS_DEFAULT_NODESIZE: u64 = 16384;

impl BtrfsExtentAllocator {
    /// Create a new extent allocator with an empty extent tree.
    pub fn new(generation: u64) -> Result<Self, BtrfsMutationError> {
        let extent_tree = InMemoryCowBtrfsTree::new(5)?;
        Ok(Self {
            block_groups: BTreeMap::new(),
            extent_tree,
            delayed_ref_queue: DelayedRefQueue::new(),
            extent_refcounts: BTreeMap::new(),
            generation,
            nodesize: BTRFS_DEFAULT_NODESIZE,
        })
    }

    /// Drop every skinny `METADATA_ITEM` whose inline `TREE_BLOCK_REF` names one
    /// of `roots` as its owning tree, returning how many were removed.
    ///
    /// FrankenFS rewrites a fixed set of trees (root/extent/fs/csum) wholesale at
    /// fresh logical addresses on every commit. The old nodes' extent items were
    /// loaded from disk and, if left in place, become stale backrefs for blocks
    /// no tree references any more — `btrfs check` then can't reconcile the
    /// extent tree (`ref mismatch` / `no backref item`), even for the unrelated
    /// chunk/dev/uuid trees, because the refcount walk is poisoned (bd-x36qn
    /// levers A+B). Removing the to-be-rewritten trees' old items *before* the
    /// commit re-adds the new nodes' items keeps the committed extent tree
    /// describing only live blocks.
    pub fn remove_metadata_items_owned_by_roots(
        &mut self,
        roots: &[u64],
    ) -> Result<usize, BtrfsMutationError> {
        let lo = BtrfsKey {
            objectid: 0,
            item_type: 0,
            offset: 0,
        };
        let hi = BtrfsKey {
            objectid: u64::MAX,
            item_type: u8::MAX,
            offset: u64::MAX,
        };
        let to_remove: Vec<BtrfsKey> = self
            .extent_tree
            .range(&lo, &hi)?
            .into_iter()
            .filter_map(|(key, value)| {
                // Skinny METADATA_ITEM value: extent_item (24 bytes) followed by
                // an inline ref { u8 type = TREE_BLOCK_REF (176), __le64 root }.
                if key.item_type != BTRFS_ITEM_METADATA_ITEM || value.len() < 33 {
                    return None;
                }
                if value[24] != BTRFS_ITEM_TREE_BLOCK_REF {
                    return None;
                }
                let root = u64::from_le_bytes(value[25..33].try_into().ok()?);
                roots.contains(&root).then_some(key)
            })
            .collect();
        let removed = to_remove.len();
        for key in to_remove {
            self.extent_tree.delete(&key)?;
        }
        Ok(removed)
    }

    /// Insert a skinny `METADATA_ITEM` + inline `TREE_BLOCK_REF` for an ALREADY
    /// allocated tree node at `bytenr` owned by `owner_root`, without reserving
    /// new space. Used at commit time to make the extent_tree's and root_tree's
    /// OWN leaves self-describing (bd-x36qn / bd-myrgc): those nodes are written
    /// at fresh addresses and reachable from the superblock but carry no extent
    /// item, which `btrfs check` rejects and which cascades into spurious
    /// "no backref" reports for every other (correct) extent.
    pub fn insert_self_metadata_item(
        &mut self,
        bytenr: u64,
        level: u8,
        owner_root: u64,
        generation: u64,
    ) -> Result<(), BtrfsMutationError> {
        let extent_item = BtrfsExtentItem {
            refs: 1,
            generation,
            flags: BtrfsExtentItem::FLAG_TREE_BLOCK,
        };
        let mut value = extent_item.to_bytes();
        value.push(BTRFS_ITEM_TREE_BLOCK_REF);
        value.extend_from_slice(&owner_root.to_le_bytes());
        let key = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_METADATA_ITEM,
            offset: u64::from(level),
        };
        self.extent_tree.insert(key, &value)?;
        Ok(())
    }

    /// Attach the inline `EXTENT_DATA_REF` backref (and `FLAG_DATA`) to the
    /// extent-tree `EXTENT_ITEM` for a regular/prealloc DATA extent.
    ///
    /// `alloc_extent` already inserts a *bare* data extent item — key
    /// `(disk_bytenr, EXTENT_ITEM(168), disk_num_bytes)`, value = the 24-byte
    /// `BtrfsExtentItem` with `flags = 0` and no backref. `btrfs check` rejects
    /// that ("referencer count mismatch" / "backpointer mismatch") because the
    /// file's `EXTENT_DATA` references the extent but the extent item records no
    /// back-reference. This rewrites the item to the kernel-valid form: refs=1,
    /// `FLAG_DATA`, followed by an inline `EXTENT_DATA_REF` (type byte 178 + the
    /// 28-byte `(root, objectid, offset, count)` struct) — the data analog of the
    /// inline `TREE_BLOCK_REF` `insert_self_metadata_item` writes for metadata.
    ///
    /// `offset` is the file logical offset of the extent's start (the
    /// `EXTENT_DATA` key offset minus its `extent_offset`); for a fresh full
    /// extent that is just the write offset. `free_extent` removes the item again
    /// via `locate_extent_key`, so write and free stay symmetric.
    ///
    /// # Errors
    /// Returns any error from updating the in-memory extent tree.
    pub fn insert_data_extent_item(
        &mut self,
        bytenr: u64,
        num_bytes: u64,
        root: u64,
        objectid: u64,
        offset: u64,
        generation: u64,
    ) -> Result<(), BtrfsMutationError> {
        let extent_item = BtrfsExtentItem {
            refs: 1,
            generation,
            flags: BtrfsExtentItem::FLAG_DATA,
        };
        let mut value = extent_item.to_bytes();
        value.push(BTRFS_ITEM_EXTENT_DATA_REF);
        let data_ref = BtrfsExtentDataRef {
            root,
            objectid,
            offset,
            count: 1,
        };
        value.extend_from_slice(&data_ref.to_bytes());
        let key = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: num_bytes,
        };
        // alloc_extent already inserted the bare item; rewrite it in place. Fall
        // back to insert for any caller that allocated with skip_extent_item.
        self.extent_tree.update(&key, &value).or_else(|err| match err {
            BtrfsMutationError::KeyNotFound => self.extent_tree.insert(key, &value),
            other => Err(other),
        })?;
        Ok(())
    }

    /// Add another reference to an existing data extent (reflink / shared
    /// extent): increment the `EXTENT_ITEM` refcount by one and insert a *keyed*
    /// `EXTENT_DATA_REF` backref for the new `(root, objectid, offset)`. The
    /// pre-existing inline backref (written by [`insert_data_extent_item`]) is
    /// left untouched, and the block group `used` accounting is unchanged —
    /// sharing an extent allocates no new space. Using a keyed backref item
    /// (key offset = [`hash_extent_data_ref`]) rather than appending an inline
    /// ref avoids re-sorting the EXTENT_ITEM's inline backref list. This is the
    /// exact inverse of the refcount-aware free planned for bd-xkvcm.
    ///
    /// # Errors
    /// Returns `KeyNotFound` if the extent item does not exist,
    /// `BrokenInvariant` if its value is malformed, `AddressOverflow` if the
    /// refcount would overflow, or any error from the extent tree.
    pub fn add_data_extent_ref(
        &mut self,
        bytenr: u64,
        num_bytes: u64,
        root: u64,
        objectid: u64,
        offset: u64,
    ) -> Result<(), BtrfsMutationError> {
        let item_key = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: num_bytes,
        };
        let mut value = self
            .extent_tree
            .get(&item_key)
            .ok_or(BtrfsMutationError::KeyNotFound)?;
        if value.len() < 8 {
            return Err(BtrfsMutationError::BrokenInvariant(
                "extent item value too short for refs field",
            ));
        }
        let refs = u64::from_le_bytes(value[0..8].try_into().expect("8 bytes"));
        let new_refs = refs
            .checked_add(1)
            .ok_or(BtrfsMutationError::AddressOverflow)?;
        value[0..8].copy_from_slice(&new_refs.to_le_bytes());
        self.extent_tree.update(&item_key, &value)?;

        let ref_key = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_EXTENT_DATA_REF,
            offset: hash_extent_data_ref(root, objectid, offset),
        };
        // If an EXTENT_DATA_REF for this exact (root, objectid, offset) already
        // exists, the kernel MERGES the new reference by incrementing the
        // existing item's count rather than failing — multiple file extents in
        // one inode can legitimately reference the same data extent at the same
        // backref key (bd-ngt1y). A keyed EXTENT_DATA_REF whose offset is
        // hash_extent_data_ref(...) can hash-collide with a DIFFERENT
        // (root, objectid, offset); only merge when the stored triple actually
        // matches, so a genuine collision still falls through to insert() and
        // keeps the prior fail-closed behavior (rather than corrupting an
        // unrelated backref's count).
        if let Some(existing) = self.extent_tree.get(&ref_key)
            && let Some(existing_ref) = BtrfsExtentDataRef::from_bytes(&existing)
            && existing_ref.root == root
            && existing_ref.objectid == objectid
            && existing_ref.offset == offset
        {
            let merged = BtrfsExtentDataRef {
                root,
                objectid,
                offset,
                count: existing_ref
                    .count
                    .checked_add(1)
                    .ok_or(BtrfsMutationError::AddressOverflow)?,
            };
            self.extent_tree.update(&ref_key, &merged.to_bytes())?;
            return Ok(());
        }
        let data_ref = BtrfsExtentDataRef {
            root,
            objectid,
            offset,
            count: 1,
        };
        self.extent_tree.insert(ref_key, &data_ref.to_bytes())?;
        Ok(())
    }

    /// Drop one reference to a SHARED data extent (refcount-aware free, bd-xkvcm)
    /// — the exact inverse of [`add_data_extent_ref`]. Decrement the
    /// `EXTENT_ITEM` refcount by one and remove this inode's `EXTENT_DATA_REF`
    /// backref for `(root, objectid, offset)`, WITHOUT freeing the extent's
    /// space (other references keep it live). The backref may be either the
    /// keyed item (the form `add_data_extent_ref` writes, located by
    /// [`hash_extent_data_ref`]) or the inline ref inside the `EXTENT_ITEM` (the
    /// form `insert_data_extent_item` writes for the first reference); both are
    /// handled. Use this only when the extent has more than one reference; a
    /// refs==1 extent is freed outright via [`free_extent`].
    ///
    /// # Errors
    /// Returns `KeyNotFound` if the extent item is absent, `BrokenInvariant` if
    /// its value is malformed, the refcount would underflow, no matching backref
    /// is found, or the inline backref list contains an unsupported ref type.
    pub fn remove_data_extent_ref(
        &mut self,
        bytenr: u64,
        num_bytes: u64,
        root: u64,
        objectid: u64,
        offset: u64,
    ) -> Result<(), BtrfsMutationError> {
        const EXTENT_ITEM_HEADER: usize = 24; // refs(8) + generation(8) + flags(8)
        const DATA_REF_PAYLOAD: usize = 28;

        let item_key = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: num_bytes,
        };
        let mut value = self
            .extent_tree
            .get(&item_key)
            .ok_or(BtrfsMutationError::KeyNotFound)?;
        if value.len() < EXTENT_ITEM_HEADER {
            return Err(BtrfsMutationError::BrokenInvariant(
                "extent item value too short for header",
            ));
        }
        let refs = u64::from_le_bytes(value[0..8].try_into().expect("8 bytes"));
        let new_refs = refs.checked_sub(1).ok_or(BtrfsMutationError::BrokenInvariant(
            "extent item refcount underflow",
        ))?;

        // Prefer the keyed EXTENT_DATA_REF (the add_data_extent_ref form).
        let ref_key = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_EXTENT_DATA_REF,
            offset: hash_extent_data_ref(root, objectid, offset),
        };
        let removed_keyed = match self.extent_tree.get(&ref_key) {
            Some(kv) => match BtrfsExtentDataRef::from_bytes(&kv) {
                Some(dr) if dr.root == root && dr.objectid == objectid && dr.offset == offset => {
                    // A keyed EXTENT_DATA_REF can hold count > 1 when
                    // add_data_extent_ref merged duplicate references (bd-ngt1y).
                    // Decrement the count and keep the item; only delete it when
                    // this was its last reference — otherwise the backref would
                    // vanish while EXTENT_ITEM.refs still counts the remaining
                    // ones, leaving a later decrement with no backref to find
                    // (bd-vrv1q).
                    if dr.count > 1 {
                        let decremented = BtrfsExtentDataRef {
                            count: dr.count - 1,
                            ..dr
                        };
                        self.extent_tree.update(&ref_key, &decremented.to_bytes())?;
                    } else {
                        self.extent_tree.delete(&ref_key)?;
                    }
                    true
                }
                _ => false,
            },
            None => false,
        };

        if !removed_keyed {
            // Remove the matching INLINE EXTENT_DATA_REF from the item value.
            let mut cursor = EXTENT_ITEM_HEADER;
            let mut found = false;
            while cursor < value.len() {
                if value[cursor] != BTRFS_ITEM_EXTENT_DATA_REF {
                    // SHARED_DATA_REF / other inline forms aren't produced by
                    // FrankenFS; refuse rather than mis-parse (atomic, no change
                    // committed yet).
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "unsupported inline backref type in extent item",
                    ));
                }
                let payload_start = cursor + 1;
                let payload_end = payload_start + DATA_REF_PAYLOAD;
                if payload_end > value.len() {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "truncated inline EXTENT_DATA_REF",
                    ));
                }
                match BtrfsExtentDataRef::from_bytes(&value[payload_start..payload_end]) {
                    Some(dr) if dr.root == root && dr.objectid == objectid && dr.offset == offset => {
                        value.drain(cursor..payload_end);
                        found = true;
                        break;
                    }
                    _ => cursor = payload_end,
                }
            }
            if !found {
                return Err(BtrfsMutationError::BrokenInvariant(
                    "no matching EXTENT_DATA_REF backref for decrement",
                ));
            }
        }

        value[0..8].copy_from_slice(&new_refs.to_le_bytes());
        self.extent_tree.update(&item_key, &value)?;
        Ok(())
    }

    /// Stamp `generation` into the existing skinny `METADATA_ITEM` extent item
    /// for the tree block at `bytenr` / `level`, leaving its refs and inline
    /// backref untouched. Returns `true` if the item was present and patched.
    ///
    /// Used at commit when a metadata tree block is rewritten in place at the
    /// new transaction generation but its extent item was loaded at the previous
    /// one: `btrfs check` requires the extent item's generation to equal the
    /// generation written into the block header, otherwise it reports a "backref
    /// generation mismatch" (bd-qxo5x, same class as bd-myrgc). The generation
    /// field always occupies bytes 8..16 of the extent-item value (`refs:u64`,
    /// `generation:u64`, `flags:u64`), independent of the inline-ref encoding.
    ///
    /// # Errors
    /// Returns any error from updating the in-memory extent tree.
    pub fn set_tree_block_generation(
        &mut self,
        bytenr: u64,
        level: u8,
        generation: u64,
    ) -> Result<bool, BtrfsMutationError> {
        let key = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_METADATA_ITEM,
            offset: u64::from(level),
        };
        let Some(mut value) = self.extent_tree.get(&key) else {
            return Ok(false);
        };
        if value.len() < 16 {
            return Ok(false);
        }
        value[8..16].copy_from_slice(&generation.to_le_bytes());
        self.extent_tree.update(&key, &value)?;
        Ok(true)
    }

    /// Number of nodes currently in the extent tree (1 == a single leaf).
    #[must_use]
    pub fn extent_tree_root_is_leaf(&self) -> bool {
        self.extent_tree.root_level() == 0
    }

    /// Set the filesystem node size used to size skinny `METADATA_ITEM` extents
    /// during gap analysis. Callers loading a real image must set this from the
    /// superblock so the gap finder fences off live metadata tree blocks.
    pub fn set_nodesize(&mut self, nodesize: u64) {
        if nodesize > 0 {
            self.nodesize = nodesize;
            // Size the extent tree's split threshold to the real node capacity.
            // The default `new(5)` is a simulator value that splits after 5
            // items, so a real fs's ~14 extent items become ~5 grossly
            // under-filled 16 KiB nodes — each an extra metadata tree block that
            // (a) lacks an EXTENT_ITEM (bd-myrgc / bd-x36qn lever A) and (b)
            // violates btrfs's non-root half-full invariant. One ~16 KiB leaf
            // holds hundreds of ~58-byte extent items, so a realistic threshold
            // collapses them to a single properly-filled leaf. set_nodesize runs
            // before any extents are loaded, so the tree is empty here and safe
            // to replace.
            let max_items = usize::try_from(nodesize.saturating_sub(101) / 64)
                .unwrap_or(5)
                .max(5);
            if let Ok(tree) = InMemoryCowBtrfsTree::new(max_items) {
                self.extent_tree = tree;
            }
        }
    }

    /// Set the transaction generation stamped into newly inserted
    /// `EXTENT_ITEM`/`METADATA_ITEM` records.
    ///
    /// btrfs records the allocating transaction's generation in each extent
    /// item, and `btrfs check` requires it to equal the generation written into
    /// the referenced tree block's header. During a commit the tree blocks are
    /// (re)written at the NEW generation, so the allocator must be advanced to
    /// that same generation before its commit-time metadata allocations —
    /// otherwise the extent item carries the previous generation and
    /// `btrfs check --mode lowmem` reports "backref generation mismatch,
    /// wanted: N, have: N-1" (bd-myrgc / bd-x36qn).
    pub fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    /// Register a block group.
    pub fn add_block_group(&mut self, start: u64, item: BtrfsBlockGroupItem) {
        debug!(
            target: "ffs::btrfs::alloc",
            start, total = item.total_bytes, used = item.used_bytes,
            flags = item.flags, "block_group_register"
        );
        self.block_groups.insert(
            start,
            BlockGroupState {
                start,
                item,
                alloc_offset: item.used_bytes,
                min_usable_offset: item.used_bytes,
            },
        );
    }

    /// Allocate a data extent of the given size.
    ///
    /// Scans block groups with `BTRFS_BLOCK_GROUP_DATA` flag for a gap
    /// large enough to hold `num_bytes`.
    pub fn alloc_data(&mut self, num_bytes: u64) -> Result<ExtentAllocation, BtrfsMutationError> {
        self.alloc_extent(num_bytes, BTRFS_BLOCK_GROUP_DATA, false, 0, 0, false)
    }

    /// Allocate a metadata extent (tree block).
    pub fn alloc_metadata(
        &mut self,
        num_bytes: u64,
    ) -> Result<ExtentAllocation, BtrfsMutationError> {
        self.alloc_metadata_for_tree(num_bytes, BTRFS_EXTENT_TREE_OBJECTID, 0)
    }

    /// Allocate a metadata extent for a specific owning tree.
    ///
    /// The allocation records both the `METADATA_ITEM` ownership item and a
    /// `TREE_BLOCK_REF` keyed by the owning root. This pins the A2 invariant
    /// that a tree node is never written before the extent tree can prove that
    /// the node's logical bytenr is allocated and referenced.
    pub fn alloc_metadata_for_tree(
        &mut self,
        num_bytes: u64,
        root: u64,
        level: u8,
    ) -> Result<ExtentAllocation, BtrfsMutationError> {
        self.alloc_extent(
            num_bytes,
            BTRFS_BLOCK_GROUP_METADATA,
            true,
            root,
            level,
            false,
        )
    }

    /// Allocate metadata for extent_tree nodes without self-referential
    /// EXTENT_ITEM insertion.
    ///
    /// When allocating space for extent_tree's own nodes during commit, we
    /// must break the recursion: extent_tree node allocations don't add new
    /// EXTENT_ITEMs (those are deferred to the next transaction).
    pub fn alloc_metadata_for_extent_tree(
        &mut self,
        num_bytes: u64,
        level: u8,
    ) -> Result<ExtentAllocation, BtrfsMutationError> {
        self.alloc_extent(
            num_bytes,
            BTRFS_BLOCK_GROUP_METADATA,
            true,
            BTRFS_EXTENT_TREE_OBJECTID,
            level,
            true, // skip EXTENT_ITEM insertion
        )
    }

    /// Allocate metadata for root_tree nodes without EXTENT_ITEM insertion.
    ///
    /// Root_tree allocations happen after extent_tree is serialized during
    /// commit. Any EXTENT_ITEMs inserted here would only exist in memory and
    /// never reach disk (bd-4nz82). We skip EXTENT_ITEM insertion entirely:
    /// - Avoids inconsistent on-disk state (extent_tree missing root_tree refs)
    /// - Root_tree blocks are small (usually single node)
    /// - Missing EXTENT_ITEMs don't affect mount or data access
    /// - `btrfs check` becomes clean instead of flagging cosmetic errors
    pub fn alloc_metadata_for_root_tree(
        &mut self,
        num_bytes: u64,
        level: u8,
    ) -> Result<ExtentAllocation, BtrfsMutationError> {
        self.alloc_extent(
            num_bytes,
            BTRFS_BLOCK_GROUP_METADATA,
            true,
            BTRFS_ROOT_TREE_OBJECTID,
            level,
            true, // skip EXTENT_ITEM insertion (bd-4nz82 fix)
        )
    }

    /// Core allocation logic.
    ///
    /// If `skip_extent_item` is true, the allocation reserves space but does
    /// NOT insert EXTENT_ITEM/METADATA_ITEM into the extent tree. This breaks
    /// the recursion when allocating extent_tree's own nodes during commit.
    #[allow(clippy::too_many_lines)]
    fn alloc_extent(
        &mut self,
        num_bytes: u64,
        required_flags: u64,
        is_metadata: bool,
        ref_root: u64,
        ref_level: u8,
        skip_extent_item: bool,
    ) -> Result<ExtentAllocation, BtrfsMutationError> {
        if num_bytes == 0 {
            return Err(BtrfsMutationError::InvalidConfig(
                "extent size must be non-zero",
            ));
        }

        // Find a block group with enough free space.
        let bg_start = self
            .block_groups
            .values()
            .find(|bg| (bg.item.flags & required_flags) != 0 && bg.item.free_bytes() >= num_bytes)
            .map(|bg| bg.start);

        let bg_start = bg_start.ok_or(BtrfsMutationError::NoSpace)?;

        debug!(
            target: "ffs::btrfs::alloc",
            block_group = bg_start,
            size_needed = num_bytes,
            "alloc_search_start"
        );

        // Find a gap in this block group by scanning allocation items in range.
        // We must include both EXTENT_ITEM (168) and METADATA_ITEM (169)
        // as both represent physical space allocations.
        let bg = &self.block_groups[&bg_start];
        let bg_end = bg
            .start
            .checked_add(bg.item.total_bytes)
            .ok_or(BtrfsMutationError::AddressOverflow)?;

        let range_start = BtrfsKey {
            objectid: bg.start,
            item_type: BTRFS_ITEM_EXTENT_ITEM, // 168
            offset: 0,
        };
        let range_end = BtrfsKey {
            objectid: bg_end,
            item_type: BTRFS_ITEM_METADATA_ITEM, // 169
            offset: u64::MAX,
        };

        let extents = self.extent_tree.range(&range_start, &range_end)?;

        // Scan for gaps between existing extents.
        let alloc_offset = self.block_groups[&bg_start].alloc_offset;
        // Lowest address this group may hand out: fences off the reserved prefix
        // (system/root region carrying no EXTENT_ITEM here). Both the forward and
        // wrap-around searches must respect it, or a fully-freed group rooted at
        // logical 0 would allocate bytenr 0 — the hole sentinel (bd-5aybu).
        let min_usable = bg_start
            .checked_add(self.block_groups[&bg_start].min_usable_offset)
            .ok_or(BtrfsMutationError::AddressOverflow)?;
        let mut cursor = bg_start
            .checked_add(alloc_offset)
            .ok_or(BtrfsMutationError::AddressOverflow)?;

        let allocated_ranges: Vec<(u64, u64)> = extents
            .iter()
            .filter_map(|(key, _)| allocation_extent_range(*key, self.nodesize))
            .collect();

        let mut found = None;
        // Try from alloc_offset first, then wrap around.
        for &(ext_start, ext_size) in &allocated_ranges {
            let ext_end = ext_start
                .checked_add(ext_size)
                .ok_or(BtrfsMutationError::AddressOverflow)?;
            if cursor < ext_start {
                let gap = ext_start - cursor;
                if gap >= num_bytes {
                    found = Some(cursor);
                    break;
                }
            }
            if ext_end > cursor {
                cursor = ext_end;
            }
        }
        // Check gap after last extent.
        if found.is_none() {
            if let Some(end) = cursor.checked_add(num_bytes) {
                if end <= bg_end {
                    found = Some(cursor);
                }
            }
        }
        // Wrap around: try from the first usable offset if we started mid-group.
        if found.is_none() && alloc_offset > 0 {
            cursor = min_usable;
            for &(ext_start, ext_size) in &allocated_ranges {
                let ext_end = ext_start
                    .checked_add(ext_size)
                    .ok_or(BtrfsMutationError::AddressOverflow)?;
                if cursor < ext_start {
                    let gap = ext_start - cursor;
                    if gap >= num_bytes {
                        found = Some(cursor);
                        break;
                    }
                }
                if ext_end > cursor {
                    cursor = ext_end;
                }
            }
            if found.is_none() {
                if let Some(end) = cursor.checked_add(num_bytes) {
                    if end <= bg_end {
                        found = Some(cursor);
                    }
                }
            }
        }

        // bytenr 0 is the btrfs hole/none sentinel and must never back a real
        // extent; refuse it defensively rather than corrupt data (bd-5aybu).
        let bytenr = found
            .filter(|&b| b != 0)
            .ok_or(BtrfsMutationError::NoSpace)?;
        let extent = ExtentKey { bytenr, num_bytes };

        debug!(
            target: "ffs::btrfs::alloc",
            block_group = bg_start,
            extent_start = bytenr,
            extent_size = num_bytes,
            "alloc_found"
        );

        // Insert EXTENT_ITEM into extent tree (unless skipped for self-allocation).
        if !skip_extent_item {
            let extent_item = BtrfsExtentItem {
                refs: 1,
                generation: self.generation,
                flags: if is_metadata {
                    BtrfsExtentItem::FLAG_TREE_BLOCK
                } else {
                    0
                },
            };
            let key = BtrfsKey {
                objectid: bytenr,
                item_type: if is_metadata {
                    BTRFS_ITEM_METADATA_ITEM
                } else {
                    BTRFS_ITEM_EXTENT_ITEM
                },
                // A skinny METADATA_ITEM key encodes the tree level in its
                // offset (not the byte length); an EXTENT_ITEM uses the length.
                // Writing num_bytes for a METADATA_ITEM produces an on-disk item
                // btrfs check reads as level 16384 -> "metadata level mismatch"
                // and cannot attribute its backref (bd-x36qn).
                offset: if is_metadata {
                    u64::from(ref_level)
                } else {
                    num_bytes
                },
            };
            // For a skinny tree block, btrfs carries the backref INLINE in the
            // METADATA_ITEM value: the 24-byte extent_item is followed by a
            // btrfs_extent_inline_ref { u8 type = TREE_BLOCK_REF_KEY (176),
            // __le64 offset = owning root objectid }. Writing a *separate*
            // TREE_BLOCK_REF item instead left btrfs check counting zero inline
            // refs ("extent item 0, found 1" + "has no backref item") — bd-x36qn.
            let mut value = extent_item.to_bytes();
            if is_metadata {
                value.push(BTRFS_ITEM_TREE_BLOCK_REF);
                value.extend_from_slice(&ref_root.to_le_bytes());
            }
            self.extent_tree.insert(key, &value)?;

            if is_metadata {
                trace!(
                    target: "ffs::btrfs::alloc",
                    bytenr,
                    root = ref_root,
                    level = ref_level,
                    "tree_block_inline_ref_insert"
                );
            }

            trace!(
                target: "ffs::btrfs::alloc",
                bytenr,
                size = num_bytes,
                refs = 1,
                "extent_item_insert"
            );
        }

        // Update block group accounting.
        if let Some(bg) = self.block_groups.get_mut(&bg_start) {
            let used_before = bg.item.used_bytes;
            bg.item.used_bytes += num_bytes;
            let alloc_end = bytenr
                .checked_add(num_bytes)
                .ok_or(BtrfsMutationError::AddressOverflow)?;
            bg.alloc_offset = alloc_end
                .checked_sub(bg_start)
                .ok_or(BtrfsMutationError::AddressOverflow)?;
            trace!(
                target: "ffs::btrfs::alloc",
                block_group = bg_start,
                used_before,
                used_after = bg.item.used_bytes,
                delta = num_bytes,
                "bg_accounting"
            );
        }

        // Queue delayed ref.
        let ref_type = if is_metadata {
            BtrfsRef::TreeBlock {
                root: ref_root,
                owner: bytenr,
                offset: num_bytes,
                level: ref_level,
            }
        } else {
            BtrfsRef::DataExtent {
                root: bg_start,
                objectid: bytenr,
                offset: num_bytes,
            }
        };
        self.delayed_ref_queue
            .queue(extent, ref_type, RefAction::Insert);
        debug!(
            target: "ffs::btrfs::alloc",
            bytenr,
            ref_type = if is_metadata { "metadata" } else { "data" },
            action = "insert",
            "delayed_ref_queue"
        );

        Ok(ExtentAllocation {
            bytenr,
            num_bytes,
            block_group_start: bg_start,
        })
    }

    /// Free an extent (decrement refcount, remove if zero).
    /// Locate the on-disk extent-tree key for an extent at `bytenr`. A skinny
    /// METADATA_ITEM is keyed by tree level (unknown to the caller) so it is
    /// found by range; an EXTENT_ITEM is matched exactly by its byte length.
    fn locate_extent_key(
        &self,
        bytenr: u64,
        num_bytes: u64,
        is_metadata: bool,
    ) -> Result<BtrfsKey, BtrfsMutationError> {
        let item_type = if is_metadata {
            BTRFS_ITEM_METADATA_ITEM
        } else {
            BTRFS_ITEM_EXTENT_ITEM
        };
        if is_metadata {
            let lo = BtrfsKey {
                objectid: bytenr,
                item_type,
                offset: 0,
            };
            let hi = BtrfsKey {
                objectid: bytenr,
                item_type,
                offset: u64::MAX,
            };
            self.extent_tree
                .range(&lo, &hi)?
                .into_iter()
                .next()
                .map(|(found_key, _)| found_key)
                .ok_or(BtrfsMutationError::KeyNotFound)
        } else {
            let key = BtrfsKey {
                objectid: bytenr,
                item_type,
                offset: num_bytes,
            };
            if self.extent_tree.range(&key, &key)?.is_empty() {
                return Err(BtrfsMutationError::KeyNotFound);
            }
            Ok(key)
        }
    }

    pub fn free_extent(
        &mut self,
        bytenr: u64,
        num_bytes: u64,
        is_metadata: bool,
    ) -> Result<(), BtrfsMutationError> {
        if num_bytes == 0 {
            return Err(BtrfsMutationError::InvalidConfig(
                "extent size must be non-zero",
            ));
        }

        debug!(
            target: "ffs::btrfs::alloc",
            bytenr, size = num_bytes, "free_search"
        );

        let key = self.locate_extent_key(bytenr, num_bytes, is_metadata)?;

        let extent_end = bytenr
            .checked_add(num_bytes)
            .ok_or(BtrfsMutationError::AddressOverflow)?;
        let mut owning_bg = None;
        for bg in self.block_groups.values() {
            let bg_end = bg
                .start
                .checked_add(bg.item.total_bytes)
                .ok_or(BtrfsMutationError::AddressOverflow)?;
            if bytenr >= bg.start && extent_end <= bg_end {
                let used_after = bg.item.used_bytes.checked_sub(num_bytes).ok_or(
                    BtrfsMutationError::BrokenInvariant("block group used bytes underflow"),
                )?;
                owning_bg = Some((bg.start, used_after));
                break;
            }
        }

        let (root, used_after) = owning_bg.ok_or(BtrfsMutationError::BrokenInvariant(
            "extent has no owning block group",
        ))?;

        // Remove from extent tree only after ownership and accounting checks pass.
        self.extent_tree.delete(&key)?;
        self.delete_backrefs_for_extent(bytenr, is_metadata)?;
        trace!(
            target: "ffs::btrfs::alloc",
            bytenr, size = num_bytes, "extent_item_remove"
        );

        // Update block group accounting.
        let bg = self
            .block_groups
            .get_mut(&root)
            .ok_or(BtrfsMutationError::BrokenInvariant(
                "extent owner block group disappeared",
            ))?;
        let used_before = bg.item.used_bytes;
        bg.item.used_bytes = used_after;
        trace!(
            target: "ffs::btrfs::alloc",
            block_group = bg.start,
            used_before,
            used_after = bg.item.used_bytes,
            delta = num_bytes,
            "bg_accounting_free"
        );

        // Queue delayed ref for delete.
        let extent = ExtentKey { bytenr, num_bytes };
        let ref_type = if is_metadata {
            BtrfsRef::TreeBlock {
                root,
                owner: bytenr,
                offset: num_bytes,
                level: 0,
            }
        } else {
            BtrfsRef::DataExtent {
                root,
                objectid: bytenr,
                offset: num_bytes,
            }
        };
        self.delayed_ref_queue
            .queue(extent, ref_type, RefAction::Delete);
        debug!(
            target: "ffs::btrfs::alloc",
            bytenr,
            ref_type = if is_metadata { "metadata" } else { "data" },
            action = "delete",
            "delayed_ref_queue"
        );

        Ok(())
    }

    /// Drain all queued delayed references (for transaction commit).
    pub fn drain_delayed_refs(&mut self) -> Vec<DelayedRef> {
        self.delayed_ref_queue.drain_all()
    }

    /// Reclaim data extents that are allocated in the extent tree but absent
    /// from the caller's durable `EXTENT_DATA` reference set.
    ///
    /// This is the recovery cleanup path for an interrupted btrfs writeback:
    /// data blocks that were allocated before their referencing metadata became
    /// durable are freed instead of leaking.
    pub fn reclaim_unreferenced_data_extents(
        &mut self,
        referenced: &HashSet<ExtentKey>,
    ) -> Result<Vec<ExtentAllocation>, BtrfsMutationError> {
        let mut orphaned = Vec::new();
        for bg in self
            .block_groups
            .values()
            .filter(|bg| (bg.item.flags & BTRFS_BLOCK_GROUP_DATA) != 0)
        {
            let bg_end = bg
                .start
                .checked_add(bg.item.total_bytes)
                .ok_or(BtrfsMutationError::AddressOverflow)?;
            let range_start = BtrfsKey {
                objectid: bg.start,
                item_type: BTRFS_ITEM_EXTENT_ITEM,
                offset: 0,
            };
            let range_end = BtrfsKey {
                objectid: bg_end,
                item_type: BTRFS_ITEM_EXTENT_ITEM,
                offset: u64::MAX,
            };
            for (key, _) in self.extent_tree.range(&range_start, &range_end)? {
                if key.objectid >= bg_end || key.item_type != BTRFS_ITEM_EXTENT_ITEM {
                    continue;
                }
                let extent = ExtentKey {
                    bytenr: key.objectid,
                    num_bytes: key.offset,
                };
                if !referenced.contains(&extent) {
                    orphaned.push(ExtentAllocation {
                        bytenr: extent.bytenr,
                        num_bytes: extent.num_bytes,
                        block_group_start: bg.start,
                    });
                }
            }
        }

        for extent in &orphaned {
            self.free_extent(extent.bytenr, extent.num_bytes, false)?;
        }

        if !orphaned.is_empty() {
            info!(
                target: "ffs::btrfs::alloc",
                reclaimed = orphaned.len(),
                bytes = orphaned.iter().map(|extent| extent.num_bytes).sum::<u64>(),
                "orphan_data_extents_reclaimed"
            );
        }

        Ok(orphaned)
    }

    /// Number of queued delayed references.
    #[must_use]
    pub fn delayed_ref_count(&self) -> usize {
        self.delayed_ref_queue.pending_count()
    }

    /// Borrow queued delayed references for an extent.
    #[must_use]
    pub fn pending_for(&self, extent: &ExtentKey) -> &[DelayedRef] {
        self.delayed_ref_queue.pending_for(extent)
    }

    /// Flush up to `limit` delayed refs into materialized refcounts.
    pub fn flush_delayed_refs(&mut self, limit: usize) -> Result<usize, BtrfsMutationError> {
        self.delayed_ref_queue
            .flush(limit, &mut self.extent_refcounts)
    }

    /// Materialized refcount for an extent.
    #[must_use]
    pub fn extent_refcount(&self, extent: ExtentKey) -> u64 {
        self.extent_refcounts.get(&extent).copied().unwrap_or(0)
    }

    /// Get block group state for inspection.
    #[must_use]
    pub fn block_group(&self, start: u64) -> Option<&BtrfsBlockGroupItem> {
        self.block_groups.get(&start).map(|bg| &bg.item)
    }

    /// Get aggregated space info per profile for `BTRFS_IOC_SPACE_INFO`.
    ///
    /// Returns a list of (flags, total_bytes, used_bytes) tuples, one per unique
    /// block group profile (Data/Metadata/System × Single/DUP/RAID).
    #[must_use]
    pub fn space_info(&self) -> Vec<(u64, u64, u64)> {
        use std::collections::BTreeMap as Map;
        let mut aggregated: Map<u64, (u64, u64)> = Map::new();
        for bg in self.block_groups.values() {
            let flags = bg.item.flags;
            let entry = aggregated.entry(flags).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(bg.item.total_bytes);
            entry.1 = entry.1.saturating_add(bg.item.used_bytes);
        }
        aggregated
            .into_iter()
            .map(|(flags, (total, used))| (flags, total, used))
            .collect()
    }

    /// Total free space across all block groups with the given type flags.
    #[must_use]
    pub fn total_free(&self, type_flags: u64) -> u64 {
        self.block_groups
            .values()
            .filter(|bg| (bg.item.flags & type_flags) != 0)
            .fold(0_u64, |total, bg| {
                total.saturating_add(bg.item.free_bytes())
            })
    }

    /// Largest currently allocatable free extent across matching block groups.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsMutationError::AddressOverflow`] if a tracked block-group
    /// or extent range cannot be represented as a half-open byte interval.
    pub fn largest_free_extent(&self, type_flags: u64) -> Result<u64, BtrfsMutationError> {
        let mut best = 0_u64;

        for bg in self
            .block_groups
            .values()
            .filter(|bg| (bg.item.flags & type_flags) != 0)
        {
            let bg_end = bg
                .start
                .checked_add(bg.item.total_bytes)
                .ok_or(BtrfsMutationError::AddressOverflow)?;
            let range_start = BtrfsKey {
                objectid: bg.start,
                item_type: BTRFS_ITEM_EXTENT_ITEM,
                offset: 0,
            };
            let range_end = BtrfsKey {
                objectid: bg_end,
                item_type: BTRFS_ITEM_METADATA_ITEM,
                offset: u64::MAX,
            };
            let mut allocated_ranges = Vec::new();
            let mut materialized_used = 0_u64;

            for (key, _) in self.extent_tree.range(&range_start, &range_end)? {
                if key.objectid >= bg_end {
                    break;
                }
                if !matches!(
                    key.item_type,
                    BTRFS_ITEM_EXTENT_ITEM | BTRFS_ITEM_METADATA_ITEM
                ) {
                    continue;
                }
                let extent_start = key.objectid.max(bg.start);
                let extent_end = key
                    .objectid
                    .checked_add(key.offset)
                    .ok_or(BtrfsMutationError::AddressOverflow)?
                    .min(bg_end);
                if extent_start < extent_end {
                    let extent_len = extent_end - extent_start;
                    materialized_used = materialized_used
                        .checked_add(extent_len)
                        .ok_or(BtrfsMutationError::AddressOverflow)?;
                    allocated_ranges.push((extent_start, extent_end));
                }
            }

            let untracked_used = bg
                .item
                .used_bytes
                .saturating_sub(materialized_used)
                .min(bg.item.total_bytes);
            if untracked_used > 0 {
                allocated_ranges.push((
                    bg.start,
                    bg.start
                        .checked_add(untracked_used)
                        .ok_or(BtrfsMutationError::AddressOverflow)?,
                ));
            }
            allocated_ranges.sort_unstable_by_key(|&(start, end)| (start, end));

            let mut cursor = bg.start;
            let mut group_best = 0_u64;
            for (extent_start, extent_end) in allocated_ranges {
                if extent_end <= cursor {
                    continue;
                }
                if cursor < extent_start {
                    group_best = group_best.max(extent_start - cursor);
                }
                cursor = extent_end;
            }

            if cursor < bg_end {
                group_best = group_best.max(bg_end - cursor);
            }
            best = best.max(group_best.min(bg.item.free_bytes()));
        }

        Ok(best)
    }

    /// Enumerate the free-space extents of every block group.
    ///
    /// For each block group, returns a [`BlockGroupFreeSpace`] listing the
    /// maximal half-open `[start, start + len)` ranges within its span not
    /// covered by any allocated extent — exactly what btrfs's `FREE_SPACE_TREE`
    /// records.
    ///
    /// This is the computational core of FREE_SPACE_TREE maintenance (bd-qxo5x):
    /// FrankenFS reallocates metadata blocks during a commit but never rewrites
    /// the on-disk free-space tree, so it goes stale and `btrfs check` rejects
    /// it ("there is no free space entry for …"). The free ranges are derived
    /// from the authoritative in-memory extent tree exactly as the allocator's
    /// own gap search does — including block-group `used_bytes` that is not
    /// materialised as an `EXTENT_ITEM`/`METADATA_ITEM` (the reserved prefix),
    /// fenced off at the group start — so the result matches what the allocator
    /// will actually hand out.
    ///
    /// # Errors
    /// Returns [`BtrfsMutationError::AddressOverflow`] if a block-group or
    /// extent range cannot be represented as a half-open byte interval, or any
    /// error from reading the in-memory extent tree.
    pub fn free_space_extents(&self) -> Result<Vec<BlockGroupFreeSpace>, BtrfsMutationError> {
        let mut result = Vec::with_capacity(self.block_groups.len());
        for bg in self.block_groups.values() {
            let bg_end = bg
                .start
                .checked_add(bg.item.total_bytes)
                .ok_or(BtrfsMutationError::AddressOverflow)?;
            let range_start = BtrfsKey {
                objectid: bg.start,
                item_type: BTRFS_ITEM_EXTENT_ITEM,
                offset: 0,
            };
            let range_end = BtrfsKey {
                objectid: bg_end,
                item_type: BTRFS_ITEM_METADATA_ITEM,
                offset: u64::MAX,
            };
            let mut allocated_ranges = Vec::new();
            let mut materialized_used = 0_u64;
            for (key, _) in self.extent_tree.range(&range_start, &range_end)? {
                if key.objectid >= bg_end {
                    break;
                }
                if !matches!(
                    key.item_type,
                    BTRFS_ITEM_EXTENT_ITEM | BTRFS_ITEM_METADATA_ITEM
                ) {
                    continue;
                }
                // A skinny METADATA_ITEM key encodes the tree LEVEL in its
                // offset, not the byte length — the block is always `nodesize`
                // bytes. An EXTENT_ITEM key offset is the real byte length.
                let extent_len = if key.item_type == BTRFS_ITEM_METADATA_ITEM {
                    self.nodesize
                } else {
                    key.offset
                };
                let extent_start = key.objectid.max(bg.start);
                let extent_end = key
                    .objectid
                    .checked_add(extent_len)
                    .ok_or(BtrfsMutationError::AddressOverflow)?
                    .min(bg_end);
                if extent_start < extent_end {
                    materialized_used = materialized_used
                        .checked_add(extent_end - extent_start)
                        .ok_or(BtrfsMutationError::AddressOverflow)?;
                    allocated_ranges.push((extent_start, extent_end));
                }
            }

            // Used bytes not represented as an extent item (the reserved
            // system/superblock prefix) are fenced off at the group start, so
            // the free-space tree never advertises them as free.
            let untracked_used = bg
                .item
                .used_bytes
                .saturating_sub(materialized_used)
                .min(bg.item.total_bytes);
            if untracked_used > 0 {
                allocated_ranges.push((
                    bg.start,
                    bg.start
                        .checked_add(untracked_used)
                        .ok_or(BtrfsMutationError::AddressOverflow)?,
                ));
            }
            allocated_ranges.sort_unstable_by_key(|&(start, end)| (start, end));

            let mut free_ranges = Vec::new();
            let mut cursor = bg.start;
            for (extent_start, extent_end) in allocated_ranges {
                if extent_end <= cursor {
                    continue;
                }
                if cursor < extent_start {
                    free_ranges.push((cursor, extent_start - cursor));
                }
                cursor = extent_end;
            }
            if cursor < bg_end {
                free_ranges.push((cursor, bg_end - cursor));
            }

            result.push(BlockGroupFreeSpace {
                start: bg.start,
                total_bytes: bg.item.total_bytes,
                flags: bg.item.flags,
                free_ranges,
            });
        }
        Ok(result)
    }

    /// Total used bytes across all block groups.
    #[must_use]
    pub fn total_used(&self) -> u64 {
        self.block_groups
            .values()
            .fold(0_u64, |total, bg| total.saturating_add(bg.item.used_bytes))
    }

    /// Recompute every block group's `used_bytes` as the sum of the
    /// `EXTENT_ITEM` / `METADATA_ITEM` lengths physically inside its range —
    /// exactly the definition `btrfs check` enforces — and write that value into
    /// both the in-memory block group and the on-disk `BLOCK_GROUP_ITEM` in the
    /// extent tree. Returns the grand total, which is the superblock `bytes_used`.
    ///
    /// This is correct-by-construction (it mirrors the checker's own accounting),
    /// so it does not depend on the in-memory `used_bytes` running tally — which
    /// at mount is seeded from a synthetic reservation, not the real on-disk
    /// figure. Call it at commit AFTER every extent item for the transaction is
    /// present (self metadata items, data extent items, csum/free-space trees)
    /// and BEFORE the extent-tree leaf is re-serialized. Without it `btrfs check`
    /// reports "block group ... used N but extent items used M" and "super bytes
    /// used N mismatches actual M" for any net-new data extent (bd-4cxkd).
    ///
    /// # Errors
    /// Returns any error from reading or updating the in-memory extent tree.
    pub fn sync_block_group_accounting(&mut self) -> Result<u64, BtrfsMutationError> {
        let groups: Vec<(u64, u64)> = self
            .block_groups
            .values()
            .map(|bg| (bg.start, bg.item.total_bytes))
            .collect();
        let nodesize = self.nodesize;
        let mut grand_total = 0_u64;
        for (start, total_bytes) in groups {
            let end = start
                .checked_add(total_bytes)
                .ok_or(BtrfsMutationError::AddressOverflow)?;
            let lo = BtrfsKey {
                objectid: start,
                item_type: BTRFS_ITEM_EXTENT_ITEM,
                offset: 0,
            };
            let hi = BtrfsKey {
                objectid: end,
                item_type: BTRFS_ITEM_METADATA_ITEM,
                offset: u64::MAX,
            };
            let used: u64 = self
                .extent_tree
                .range(&lo, &hi)?
                .iter()
                .filter_map(|(key, _)| allocation_extent_range(*key, nodesize))
                .filter(|(ext_start, _)| *ext_start >= start && *ext_start < end)
                .fold(0_u64, |acc, (_, len)| acc.saturating_add(len));

            if let Some(bg) = self.block_groups.get_mut(&start) {
                bg.item.used_bytes = used;
            }
            let bg_key = BtrfsKey {
                objectid: start,
                item_type: BTRFS_ITEM_BLOCK_GROUP_ITEM,
                offset: total_bytes,
            };
            if let Some(mut value) = self.extent_tree.get(&bg_key) {
                if value.len() >= 8 {
                    value[0..8].copy_from_slice(&used.to_le_bytes());
                    self.extent_tree.update(&bg_key, &value)?;
                }
            }
            grand_total = grand_total.saturating_add(used);
        }
        Ok(grand_total)
    }

    /// Total capacity across all block groups.
    #[must_use]
    pub fn total_capacity(&self) -> u64 {
        self.block_groups
            .values()
            .fold(0_u64, |total, bg| total.saturating_add(bg.item.total_bytes))
    }

    /// Access the underlying extent tree (for commit/writeback).
    #[must_use]
    pub fn extent_tree(&self) -> &InMemoryCowBtrfsTree {
        &self.extent_tree
    }

    /// Mutable access to the extent tree (for loading on-disk entries at mount).
    pub fn extent_tree_mut(&mut self) -> &mut InMemoryCowBtrfsTree {
        &mut self.extent_tree
    }

    /// Get all data extent back-references for a given logical address.
    ///
    /// Returns a list of (root, objectid, offset) tuples representing all
    /// files that reference the extent at `bytenr`. Used by `BTRFS_IOC_LOGICAL_INO`.
    /// Read the reference count from a data extent's `EXTENT_ITEM` (the first
    /// `u64` of its payload). Returns `None` if no such item is present. This is
    /// the authoritative shared-extent indicator: an extent with `refs > 1` is
    /// shared (reflink / snapshot / CoW) and counts inline + keyed backrefs,
    /// unlike [`Self::get_extent_data_refs`] which sees only separate
    /// `EXTENT_DATA_REF` items (a refcount-1 extent keeps its single ref inline).
    pub fn extent_item_refs(
        &self,
        bytenr: u64,
        num_bytes: u64,
    ) -> Result<Option<u64>, BtrfsMutationError> {
        let key = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: num_bytes,
        };
        let items = self.extent_tree.range(&key, &key)?;
        Ok(items.into_iter().next().and_then(|(_, data)| {
            if data.len() >= 8 {
                Some(u64::from_le_bytes(data[0..8].try_into().ok()?))
            } else {
                None
            }
        }))
    }

    pub fn get_extent_data_refs(
        &self,
        bytenr: u64,
    ) -> Result<Vec<BtrfsExtentDataRef>, BtrfsMutationError> {
        let range_start = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_EXTENT_DATA_REF,
            offset: 0,
        };
        let range_end = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_EXTENT_DATA_REF,
            offset: u64::MAX,
        };
        let refs = self.extent_tree.range(&range_start, &range_end)?;
        let mut result = Vec::new();
        for (_key, value) in refs {
            if let Some(data_ref) = BtrfsExtentDataRef::from_bytes(&value) {
                result.push(data_ref);
            }
        }
        Ok(result)
    }

    fn delete_backrefs_for_extent(
        &mut self,
        bytenr: u64,
        is_metadata: bool,
    ) -> Result<(), BtrfsMutationError> {
        let ref_item_type = if is_metadata {
            BTRFS_ITEM_TREE_BLOCK_REF
        } else {
            BTRFS_ITEM_EXTENT_DATA_REF
        };
        let range_start = BtrfsKey {
            objectid: bytenr,
            item_type: ref_item_type,
            offset: 0,
        };
        let range_end = BtrfsKey {
            objectid: bytenr,
            item_type: ref_item_type,
            offset: u64::MAX,
        };
        let refs: Vec<BtrfsKey> = self
            .extent_tree
            .range(&range_start, &range_end)?
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        for key in refs {
            self.extent_tree.delete(&key)?;
        }
        Ok(())
    }
}

fn allocation_extent_range(key: BtrfsKey, metadata_nodesize: u64) -> Option<(u64, u64)> {
    match key.item_type {
        // EXTENT_ITEM offset is the byte length (data extent size, or nodesize
        // for a non-skinny tree block).
        BTRFS_ITEM_EXTENT_ITEM => Some((key.objectid, key.offset)),
        // Skinny METADATA_ITEM offset is the tree *level*, not a length: the
        // block always spans exactly one nodesize tree block.
        BTRFS_ITEM_METADATA_ITEM => Some((key.objectid, metadata_nodesize)),
        _ => None,
    }
}

// ── btrfs multi-device support ─────────────────────────────────────────────

const BTRFS_CHUNK_ITEM_FIXED_SIZE: usize = 48;
const BTRFS_CHUNK_ITEM_STRIPE_SIZE: usize = 32;

/// Parse a single chunk item from its raw on-disk data.
///
/// The `logical_offset` is the chunk's key.offset (logical start address).
/// The data contains the fixed chunk header (48 bytes) + stripe entries.
fn parse_chunk_item(data: &[u8], logical_offset: u64) -> Result<BtrfsChunkEntry, ParseError> {
    use ffs_types::{read_le_u16, read_le_u32, read_le_u64};

    if data.len() < BTRFS_CHUNK_ITEM_FIXED_SIZE {
        return Err(ParseError::InsufficientData {
            needed: BTRFS_CHUNK_ITEM_FIXED_SIZE,
            offset: 0,
            actual: data.len(),
        });
    }

    let length = read_le_u64(data, 0)?;
    let owner = read_le_u64(data, 8)?;
    let stripe_len = read_le_u64(data, 16)?;
    let chunk_type = read_le_u64(data, 24)?;
    let io_align = read_le_u32(data, 32)?;
    let io_width = read_le_u32(data, 36)?;
    let sector_size = read_le_u32(data, 40)?;
    let num_stripes = read_le_u16(data, 44)?;
    let sub_stripes = read_le_u16(data, 46)?;

    let raid_bits = chunk_type & chunk_type_flags::RAID_MASK;
    if raid_bits.count_ones() > 1 {
        return Err(ParseError::InvalidField {
            field: "chunk_type",
            reason: "multiple RAID profiles set",
        });
    }
    if length == 0 {
        return Err(ParseError::InvalidField {
            field: "chunk_length",
            reason: "chunk has zero length",
        });
    }
    if stripe_len == 0 {
        return Err(ParseError::InvalidField {
            field: "stripe_len",
            reason: "chunk has zero stripe length",
        });
    }
    if io_align == 0 {
        return Err(ParseError::InvalidField {
            field: "io_align",
            reason: "must be non-zero",
        });
    }
    if io_width == 0 {
        return Err(ParseError::InvalidField {
            field: "io_width",
            reason: "must be non-zero",
        });
    }
    if sector_size == 0 {
        return Err(ParseError::InvalidField {
            field: "sector_size",
            reason: "must be non-zero",
        });
    }
    if num_stripes == 0 {
        return Err(ParseError::InvalidField {
            field: "stripes",
            reason: "chunk has no stripes",
        });
    }

    let stripe_count = usize::from(num_stripes);
    let stripes = parse_chunk_item_stripes(data, stripe_count)?;

    Ok(BtrfsChunkEntry {
        key: BtrfsKey {
            objectid: BTRFS_CHUNK_TREE_OBJECTID,
            item_type: BTRFS_ITEM_CHUNK,
            offset: logical_offset,
        },
        length,
        owner,
        stripe_len,
        chunk_type,
        io_align,
        io_width,
        sector_size,
        num_stripes,
        sub_stripes,
        stripes,
    })
}

fn parse_chunk_item_stripes(
    data: &[u8],
    stripe_count: usize,
) -> Result<Vec<ffs_ondisk::BtrfsStripe>, ParseError> {
    use ffs_types::read_le_u64;

    let stripe_bytes = stripe_count
        .checked_mul(BTRFS_CHUNK_ITEM_STRIPE_SIZE)
        .ok_or(ParseError::InvalidField {
            field: "stripes",
            reason: "chunk stripe payload overflows usize",
        })?;
    let required = BTRFS_CHUNK_ITEM_FIXED_SIZE
        .checked_add(stripe_bytes)
        .ok_or(ParseError::InvalidField {
            field: "stripes",
            reason: "chunk stripe payload overflows usize",
        })?;
    if data.len() < required {
        return Err(ParseError::InsufficientData {
            needed: required,
            offset: BTRFS_CHUNK_ITEM_FIXED_SIZE,
            actual: data.len(),
        });
    }
    if data.len() > required {
        return Err(ParseError::InvalidField {
            field: "stripes",
            reason: "does not match declared stripe count",
        });
    }

    let mut stripes = Vec::with_capacity(stripe_count);
    let mut off = BTRFS_CHUNK_ITEM_FIXED_SIZE;
    for _ in 0..stripe_count {
        let devid = read_le_u64(data, off)?;
        if devid == 0 {
            return Err(ParseError::InvalidField {
                field: "stripe_devid",
                reason: "must be non-zero",
            });
        }
        stripes.push(ffs_ondisk::BtrfsStripe {
            devid,
            offset: read_le_u64(data, off + 8)?,
            dev_uuid: {
                let uuid_off = off + 16;
                if uuid_off + 16 > data.len() {
                    [0u8; 16]
                } else {
                    let mut uuid = [0u8; 16];
                    uuid.copy_from_slice(&data[uuid_off..uuid_off + 16]);
                    uuid
                }
            },
        });
        off += BTRFS_CHUNK_ITEM_STRIPE_SIZE;
    }

    Ok(stripes)
}

/// Walk the chunk tree to build a complete chunk map.
///
/// The `sys_chunk_array` in the superblock provides bootstrap chunks needed to
/// locate the chunk tree itself. This function walks the chunk tree (rooted at
/// `sb.chunk_root`) using the bootstrap chunks, and returns ALL chunk entries
/// including those not in `sys_chunk_array`.
///
/// For single-device filesystems, the `sys_chunk_array` usually contains all
/// chunks. Multi-device or large filesystems may have additional chunks only
/// in the chunk tree.
pub fn walk_chunk_tree(
    read_physical: &mut dyn FnMut(u64) -> Result<Vec<u8>, ParseError>,
    sb: &BtrfsSuperblock,
    bootstrap_chunks: &[BtrfsChunkEntry],
) -> Result<Vec<BtrfsChunkEntry>, ParseError> {
    let items = walk_tree(
        read_physical,
        bootstrap_chunks,
        sb.chunk_root,
        sb.nodesize,
        sb.csum_type,
    )?;

    let mut chunks = bootstrap_chunks.to_vec();
    for item in &items {
        if item.key.item_type == BTRFS_ITEM_CHUNK {
            let chunk = parse_chunk_item(&item.data, item.key.offset)?;
            // Only add if not already in bootstrap set (avoid duplicates).
            if !chunks.iter().any(|c| c.key.offset == chunk.key.offset) {
                chunks.push(chunk);
            }
        }
    }

    // Sort by logical offset for efficient lookup.
    chunks.sort_by_key(|c| c.key.offset);
    Ok(chunks)
}

/// Walk the device tree to discover all physical devices.
///
/// The `dev_root_bytenr` is the logical address of the DEV_TREE root node,
/// obtained by looking up objectid 4 (`BTRFS_DEV_TREE_OBJECTID`) in the
/// ROOT_TREE. Returns all leaf items in the device tree.
pub fn walk_device_tree(
    read_physical: &mut dyn FnMut(u64) -> Result<Vec<u8>, ParseError>,
    dev_root_bytenr: u64,
    chunks: &[BtrfsChunkEntry],
    nodesize: u32,
    csum_type: u16,
) -> Result<Vec<BtrfsLeafEntry>, ParseError> {
    walk_tree(read_physical, chunks, dev_root_bytenr, nodesize, csum_type)
}

/// Each device is identified by its `devid` (from `DEV_ITEM` in the device tree).
/// The `read_physical` method dispatches reads to the correct device based on the
/// stripe mapping returned by `map_logical_to_stripes`.
/// Device reader: reads `len` bytes from physical offset, returns data or error.
type DeviceReader = Box<dyn Fn(u64, usize) -> Result<Vec<u8>, ffs_types::ParseError> + Send + Sync>;

/// A set of physical devices backing a btrfs filesystem.
pub struct BtrfsDeviceSet {
    /// Map from devid → device read closure.
    devices: std::collections::BTreeMap<u64, DeviceReader>,
}

impl BtrfsDeviceSet {
    /// Create an empty device set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            devices: std::collections::BTreeMap::new(),
        }
    }

    /// Register a device with the given devid.
    pub fn add_device(
        &mut self,
        devid: u64,
        reader: Box<dyn Fn(u64, usize) -> Result<Vec<u8>, ffs_types::ParseError> + Send + Sync>,
    ) {
        self.devices.insert(devid, reader);
    }

    /// Number of registered devices.
    #[must_use]
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Read `len` bytes from the device identified by `devid` at `physical_offset`.
    pub fn read_physical(
        &self,
        devid: u64,
        physical_offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, ffs_types::ParseError> {
        let reader = self
            .devices
            .get(&devid)
            .ok_or(ffs_types::ParseError::InvalidField {
                field: "devid",
                reason: "device not found in device set",
            })?;
        reader(physical_offset, len)
    }

    /// Read a logical block using the chunk map and stripe resolution.
    ///
    /// Resolves the logical address to physical stripes via `map_logical_to_stripes`,
    /// then reads from the first available stripe's device. For mirrored profiles
    /// (RAID1/10), this reads from the first mirror; fallback to other mirrors on
    /// error could be added in the future.
    pub fn read_logical(
        &self,
        chunks: &[ffs_ondisk::BtrfsChunkEntry],
        logical: u64,
        len: usize,
    ) -> Result<Vec<u8>, ffs_types::ParseError> {
        let mapping = ffs_ondisk::map_logical_to_stripes(chunks, logical)?.ok_or(
            ffs_types::ParseError::InvalidField {
                field: "logical_address",
                reason: "address not mapped in chunk table",
            },
        )?;

        // Try each stripe until one succeeds (redundancy for mirrored profiles).
        for stripe in &mapping.stripes {
            match self.read_physical(stripe.devid, stripe.physical, len) {
                Ok(data) => return Ok(data),
                Err(_) if mapping.stripes.len() > 1 => {} // Try next mirror.
                Err(e) => return Err(e),
            }
        }

        Err(ffs_types::ParseError::InvalidField {
            field: "stripe",
            reason: "all mirrors failed to read",
        })
    }
}

impl std::fmt::Debug for BtrfsDeviceSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BtrfsDeviceSet")
            .field("device_count", &self.devices.len())
            .field("devids", &self.devices.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Default for BtrfsDeviceSet {
    fn default() -> Self {
        Self::new()
    }
}

// ── btrfs send/receive stream ──────────────────────────────────────────────

/// btrfs send stream magic ("btrfs-stream\0").
pub const BTRFS_SEND_STREAM_MAGIC: &[u8; 13] = b"btrfs-stream\0";

/// btrfs send stream version.
pub const BTRFS_SEND_STREAM_VERSION: u32 = 1;

/// Send stream command types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SendCommand {
    Unspec = 0,
    Subvol = 1,
    Snapshot = 2,
    Mkfile = 3,
    Mkdir = 4,
    Mknod = 5,
    Mkfifo = 6,
    Mksock = 7,
    Symlink = 8,
    Rename = 9,
    Link = 10,
    Unlink = 11,
    Rmdir = 12,
    SetXattr = 13,
    RemoveXattr = 14,
    Write = 15,
    Clone = 16,
    Truncate = 17,
    Chmod = 18,
    Chown = 19,
    Utimes = 20,
    End = 21,
    UpdateExtent = 22,
}

impl SendCommand {
    fn from_u16(val: u16) -> Option<Self> {
        match val {
            0 => Some(Self::Unspec),
            1 => Some(Self::Subvol),
            2 => Some(Self::Snapshot),
            3 => Some(Self::Mkfile),
            4 => Some(Self::Mkdir),
            5 => Some(Self::Mknod),
            6 => Some(Self::Mkfifo),
            7 => Some(Self::Mksock),
            8 => Some(Self::Symlink),
            9 => Some(Self::Rename),
            10 => Some(Self::Link),
            11 => Some(Self::Unlink),
            12 => Some(Self::Rmdir),
            13 => Some(Self::SetXattr),
            14 => Some(Self::RemoveXattr),
            15 => Some(Self::Write),
            16 => Some(Self::Clone),
            17 => Some(Self::Truncate),
            18 => Some(Self::Chmod),
            19 => Some(Self::Chown),
            20 => Some(Self::Utimes),
            21 => Some(Self::End),
            22 => Some(Self::UpdateExtent),
            _ => None,
        }
    }
}

/// Send stream attribute types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SendAttr {
    Unspec = 0,
    Uuid = 1,
    Ctransid = 2,
    Ino = 3,
    Size = 4,
    Mode = 5,
    Uid = 6,
    Gid = 7,
    Rdev = 8,
    Ctime = 9,
    Mtime = 10,
    Atime = 11,
    Otime = 12,
    XattrName = 13,
    XattrData = 14,
    Path = 15,
    PathTo = 16,
    PathLink = 17,
    FileOffset = 18,
    Data = 19,
    CloneUuid = 20,
    CloneCtransid = 21,
    ClonePath = 22,
    CloneOffset = 23,
    CloneLen = 24,
}

/// A parsed command from a btrfs send stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendStreamCommand {
    pub cmd: SendCommand,
    pub attrs: Vec<(u16, Vec<u8>)>,
}

/// Result of parsing a btrfs send stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SendStreamParseResult {
    pub version: u32,
    pub commands: Vec<SendStreamCommand>,
}

const BTRFS_SEND_CRC32C_POLY: u32 = 0x82F6_3B78;

fn btrfs_send_crc32c(seed: u32, data: &[u8]) -> u32 {
    let mut crc = seed;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ BTRFS_SEND_CRC32C_POLY
            };
        }
    }
    crc
}

fn send_stream_command_crc32c(command: &[u8]) -> u32 {
    let mut crc = btrfs_send_crc32c(0, &command[..6]);
    crc = btrfs_send_crc32c(crc, &[0_u8; 4]);
    btrfs_send_crc32c(crc, &command[10..])
}

fn parse_send_stream_attrs(
    cmd_data: &[u8],
    cmd_data_start: usize,
) -> Result<Vec<(u16, Vec<u8>)>, ffs_types::ParseError> {
    let mut attrs = Vec::new();
    let mut attr_pos = 0;
    while attr_pos + 4 <= cmd_data.len() {
        let attr_type = u16::from_le_bytes([cmd_data[attr_pos], cmd_data[attr_pos + 1]]);
        let attr_len =
            u16::from_le_bytes([cmd_data[attr_pos + 2], cmd_data[attr_pos + 3]]) as usize;
        attr_pos += 4;
        let Some(attr_end) = attr_pos.checked_add(attr_len) else {
            return Err(ffs_types::ParseError::InvalidField {
                field: "send_stream_attr_len",
                reason: "overflow",
            });
        };
        if attr_end > cmd_data.len() {
            return Err(ffs_types::ParseError::InsufficientData {
                needed: attr_len,
                offset: cmd_data_start + attr_pos,
                actual: cmd_data.len().saturating_sub(attr_pos),
            });
        }
        attrs.push((attr_type, cmd_data[attr_pos..attr_end].to_vec()));
        attr_pos = attr_end;
    }
    if attr_pos != cmd_data.len() {
        return Err(ffs_types::ParseError::InsufficientData {
            needed: 4,
            offset: cmd_data_start + attr_pos,
            actual: cmd_data.len().saturating_sub(attr_pos),
        });
    }
    Ok(attrs)
}

/// Parse a btrfs send stream from raw bytes.
///
/// The send stream format is:
/// - 13-byte magic ("btrfs-stream\0")
/// - 4-byte version (u32 LE)
/// - Commands: each is [len(u32 LE), cmd(u16 LE), crc32(u32 LE), attrs...]
/// - Attributes: each is [type(u16 LE), len(u16 LE), data(len bytes)]
pub fn parse_send_stream(data: &[u8]) -> Result<SendStreamParseResult, ffs_types::ParseError> {
    if data.len() < 17 {
        return Err(ffs_types::ParseError::InsufficientData {
            needed: 17,
            offset: 0,
            actual: data.len(),
        });
    }

    if &data[..13] != BTRFS_SEND_STREAM_MAGIC {
        return Err(ffs_types::ParseError::InvalidField {
            field: "send_stream_magic",
            reason: "not a btrfs send stream (magic mismatch)",
        });
    }

    let version = u32::from_le_bytes([data[13], data[14], data[15], data[16]]);
    if version != BTRFS_SEND_STREAM_VERSION {
        return Err(ffs_types::ParseError::InvalidField {
            field: "send_stream_version",
            reason: "unsupported btrfs send stream version",
        });
    }
    let mut pos = 17;
    let mut commands = Vec::new();
    let mut saw_end = false;

    while pos + 10 <= data.len() {
        let command_start = pos;
        // Command header: len(u32), cmd(u16), crc32(u32)
        let cmd_len =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let cmd_type = u16::from_le_bytes([data[pos + 4], data[pos + 5]]);
        let expected_crc =
            u32::from_le_bytes([data[pos + 6], data[pos + 7], data[pos + 8], data[pos + 9]]);
        pos += 10;

        let cmd_data_start = pos;
        let Some(cmd_end) = pos.checked_add(cmd_len) else {
            return Err(ffs_types::ParseError::InvalidField {
                field: "send_stream_cmd_len",
                reason: "overflow",
            });
        };
        if cmd_end > data.len() {
            return Err(ffs_types::ParseError::InsufficientData {
                needed: cmd_len,
                offset: cmd_data_start,
                actual: data.len().saturating_sub(cmd_data_start),
            });
        }

        let computed_crc = send_stream_command_crc32c(&data[command_start..cmd_end]);
        if computed_crc != expected_crc {
            return Err(ffs_types::ParseError::InvalidField {
                field: "send_stream_crc32c",
                reason: "command crc32c mismatch",
            });
        }

        let cmd_data = &data[pos..cmd_end];
        pos = cmd_end;

        let cmd = SendCommand::from_u16(cmd_type).unwrap_or(SendCommand::Unspec);
        let attrs = parse_send_stream_attrs(cmd_data, cmd_data_start)?;
        commands.push(SendStreamCommand { cmd, attrs });
        if cmd == SendCommand::End {
            saw_end = true;
            break;
        }
    }

    if pos < data.len() {
        if saw_end {
            return Err(ffs_types::ParseError::InvalidField {
                field: "send_stream",
                reason: "trailing bytes after end command",
            });
        }
        return Err(ffs_types::ParseError::InsufficientData {
            needed: 10,
            offset: pos,
            actual: data.len().saturating_sub(pos),
        });
    }

    if !saw_end {
        return Err(ffs_types::ParseError::InvalidField {
            field: "send_stream",
            reason: "missing end command",
        });
    }

    Ok(SendStreamParseResult { version, commands })
}

/// Builder for generating btrfs send streams.
///
/// Constructs a valid send stream that can be consumed by `btrfs receive`.
/// The builder automatically handles the stream header, command framing,
/// and CRC32C computation.
#[derive(Debug, Clone, Default)]
pub struct SendStreamBuilder {
    buffer: Vec<u8>,
    has_header: bool,
    finalized: bool,
}

impl SendStreamBuilder {
    /// Create a new send stream builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            has_header: false,
            finalized: false,
        }
    }

    /// Write the stream header (magic + version).
    /// Must be called before adding any commands.
    pub fn write_header(&mut self) {
        assert!(!self.has_header, "header already written");
        self.buffer.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
        self.buffer
            .extend_from_slice(&BTRFS_SEND_STREAM_VERSION.to_le_bytes());
        self.has_header = true;
    }

    /// Add a command with attributes.
    /// Each attribute is (type, data).
    #[expect(clippy::cast_possible_truncation)]
    pub fn add_command(&mut self, cmd: SendCommand, attrs: &[(SendAttr, &[u8])]) {
        assert!(self.has_header, "must write header first");
        assert!(!self.finalized, "stream already finalized");

        let mut payload = Vec::new();
        for (atype, adata) in attrs {
            // The btrfs send TLV length field is a u16. Casting a longer
            // attribute would silently wrap the declared length and emit a
            // corrupt, unparseable stream. Callers that carry bulk data (file
            // writes) MUST chunk to `BTRFS_SEND_WRITE_CHUNK`; assert here so any
            // future caller that forgets fails loudly instead of corrupting.
            assert!(
                u16::try_from(adata.len()).is_ok(),
                "send-stream attribute data exceeds u16 TLV limit ({} > {})",
                adata.len(),
                u16::MAX
            );
            payload.extend_from_slice(&(*atype as u16).to_le_bytes());
            payload.extend_from_slice(&(adata.len() as u16).to_le_bytes());
            payload.extend_from_slice(adata);
        }

        let payload_len = payload.len() as u32;
        let full_len = 10 + payload.len();

        let mut frame = Vec::with_capacity(full_len);
        frame.extend_from_slice(&payload_len.to_le_bytes());
        frame.extend_from_slice(&(cmd as u16).to_le_bytes());
        frame.extend_from_slice(&[0_u8; 4]); // CRC placeholder
        frame.extend_from_slice(&payload);

        let crc = send_stream_command_crc32c(&frame);
        frame[6..10].copy_from_slice(&crc.to_le_bytes());

        self.buffer.extend_from_slice(&frame);
    }

    /// Add the End command and finalize the stream.
    pub fn finalize(&mut self) {
        assert!(!self.finalized, "stream already finalized");
        self.add_command(SendCommand::End, &[]);
        self.finalized = true;
    }

    /// Get the complete send stream bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        assert!(self.finalized, "must call finalize() before finish()");
        self.buffer
    }

    /// Check if the builder has been finalized.
    #[must_use]
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }
}

/// Helper to build a Subvol command (start of a full send).
#[must_use]
pub fn build_subvol_command(
    path: &[u8],
    uuid: &[u8; 16],
    ctransid: u64,
) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::Subvol,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::Uuid, uuid.to_vec()),
            (SendAttr::Ctransid, ctransid.to_le_bytes().to_vec()),
        ],
    )
}

/// Helper to build a Mkdir command.
#[must_use]
pub fn build_mkdir_command(path: &[u8], ino: u64) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::Mkdir,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::Ino, ino.to_le_bytes().to_vec()),
        ],
    )
}

/// Helper to build a Mkfile command.
#[must_use]
pub fn build_mkfile_command(path: &[u8], ino: u64) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::Mkfile,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::Ino, ino.to_le_bytes().to_vec()),
        ],
    )
}

/// Helper to build a Write command.
#[must_use]
pub fn build_write_command(
    path: &[u8],
    offset: u64,
    data: &[u8],
) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::Write,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::FileOffset, offset.to_le_bytes().to_vec()),
            (SendAttr::Data, data.to_vec()),
        ],
    )
}

/// Helper to build a Chmod command.
#[must_use]
pub fn build_chmod_command(path: &[u8], mode: u64) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::Chmod,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::Mode, mode.to_le_bytes().to_vec()),
        ],
    )
}

/// Helper to build a Chown command.
#[must_use]
pub fn build_chown_command(
    path: &[u8],
    uid: u64,
    gid: u64,
) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::Chown,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::Uid, uid.to_le_bytes().to_vec()),
            (SendAttr::Gid, gid.to_le_bytes().to_vec()),
        ],
    )
}

/// Helper to build a Utimes command.
#[must_use]
#[expect(clippy::similar_names)]
pub fn build_utimes_command(
    path: &[u8],
    atime_sec: i64,
    atime_nsec: i32,
    mtime_sec: i64,
    mtime_nsec: i32,
    ctime_sec: i64,
    ctime_nsec: i32,
) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    fn timespec_bytes(sec: i64, nsec: i32) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        buf.extend_from_slice(&sec.to_le_bytes());
        buf.extend_from_slice(&nsec.to_le_bytes());
        buf
    }
    (
        SendCommand::Utimes,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::Atime, timespec_bytes(atime_sec, atime_nsec)),
            (SendAttr::Mtime, timespec_bytes(mtime_sec, mtime_nsec)),
            (SendAttr::Ctime, timespec_bytes(ctime_sec, ctime_nsec)),
        ],
    )
}

/// Helper to build a Truncate command.
#[must_use]
pub fn build_truncate_command(path: &[u8], size: u64) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::Truncate,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::Size, size.to_le_bytes().to_vec()),
        ],
    )
}

/// Helper to build a Symlink command.
#[must_use]
pub fn build_symlink_command(
    path: &[u8],
    ino: u64,
    link_target: &[u8],
) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::Symlink,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::Ino, ino.to_le_bytes().to_vec()),
            (SendAttr::PathLink, link_target.to_vec()),
        ],
    )
}

/// Helper to build a SetXattr command.
#[must_use]
pub fn build_setxattr_command(
    path: &[u8],
    name: &[u8],
    data: &[u8],
) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::SetXattr,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::XattrName, name.to_vec()),
            (SendAttr::XattrData, data.to_vec()),
        ],
    )
}

/// Helper to build a RemoveXattr command.
#[must_use]
pub fn build_removexattr_command(
    path: &[u8],
    name: &[u8],
) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::RemoveXattr,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::XattrName, name.to_vec()),
        ],
    )
}

/// Helper to build a Rename command.
#[must_use]
pub fn build_rename_command(
    path: &[u8],
    path_to: &[u8],
) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::Rename,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::PathTo, path_to.to_vec()),
        ],
    )
}

/// Helper to build a Link command (hardlink).
#[must_use]
pub fn build_link_command(
    path: &[u8],
    path_link: &[u8],
) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::Link,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::PathLink, path_link.to_vec()),
        ],
    )
}

/// Helper to build an Unlink command.
#[must_use]
pub fn build_unlink_command(path: &[u8]) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (SendCommand::Unlink, vec![(SendAttr::Path, path.to_vec())])
}

/// Helper to build an Rmdir command.
#[must_use]
pub fn build_rmdir_command(path: &[u8]) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (SendCommand::Rmdir, vec![(SendAttr::Path, path.to_vec())])
}

/// Helper to build a Mknod command (block/char device).
#[must_use]
pub fn build_mknod_command(
    path: &[u8],
    ino: u64,
    mode: u64,
    rdev: u64,
) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::Mknod,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::Ino, ino.to_le_bytes().to_vec()),
            (SendAttr::Mode, mode.to_le_bytes().to_vec()),
            (SendAttr::Rdev, rdev.to_le_bytes().to_vec()),
        ],
    )
}

/// Helper to build a Mkfifo command.
#[must_use]
pub fn build_mkfifo_command(path: &[u8], ino: u64) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::Mkfifo,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::Ino, ino.to_le_bytes().to_vec()),
        ],
    )
}

/// Helper to build a Mksock command.
#[must_use]
pub fn build_mksock_command(path: &[u8], ino: u64) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::Mksock,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::Ino, ino.to_le_bytes().to_vec()),
        ],
    )
}

/// Helper to build a Snapshot command (start of an incremental send).
#[must_use]
pub fn build_snapshot_command(
    path: &[u8],
    uuid: &[u8; 16],
    ctransid: u64,
    clone_uuid: &[u8; 16],
    clone_ctransid: u64,
) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::Snapshot,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::Uuid, uuid.to_vec()),
            (SendAttr::Ctransid, ctransid.to_le_bytes().to_vec()),
            (SendAttr::CloneUuid, clone_uuid.to_vec()),
            (
                SendAttr::CloneCtransid,
                clone_ctransid.to_le_bytes().to_vec(),
            ),
        ],
    )
}

/// Helper to build a Clone command (extent reflink).
#[must_use]
pub fn build_clone_command(
    path: &[u8],
    offset: u64,
    len: u64,
    clone_uuid: &[u8; 16],
    clone_ctransid: u64,
    clone_path: &[u8],
    clone_offset: u64,
) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::Clone,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::FileOffset, offset.to_le_bytes().to_vec()),
            (SendAttr::CloneLen, len.to_le_bytes().to_vec()),
            (SendAttr::CloneUuid, clone_uuid.to_vec()),
            (
                SendAttr::CloneCtransid,
                clone_ctransid.to_le_bytes().to_vec(),
            ),
            (SendAttr::ClonePath, clone_path.to_vec()),
            (SendAttr::CloneOffset, clone_offset.to_le_bytes().to_vec()),
        ],
    )
}

/// Helper to build an UpdateExtent command.
#[must_use]
pub fn build_update_extent_command(
    path: &[u8],
    offset: u64,
    len: u64,
) -> (SendCommand, Vec<(SendAttr, Vec<u8>)>) {
    (
        SendCommand::UpdateExtent,
        vec![
            (SendAttr::Path, path.to_vec()),
            (SendAttr::FileOffset, offset.to_le_bytes().to_vec()),
            (SendAttr::Size, len.to_le_bytes().to_vec()),
        ],
    )
}

// ── send stream generation from FS tree ───────────────────────────────────

/// Maximum payload bytes per send-stream `DATA` attribute.
///
/// The btrfs send TLV length field is a `u16`, so a single attribute can carry
/// at most 65535 bytes. The kernel chunks file data at `BTRFS_SEND_READ_SIZE`
/// (48 KiB); matching that keeps generated `Write` commands well under the u16
/// ceiling and interoperable with `btrfs receive`.
const BTRFS_SEND_WRITE_CHUNK: usize = 48 * 1024;

/// Emit one or more `Write` commands for `data`, splitting it into
/// [`BTRFS_SEND_WRITE_CHUNK`]-sized pieces so no `DATA` attribute exceeds the
/// u16 TLV length limit. Each chunk carries its own incrementing file offset,
/// exactly as the kernel's send implementation does.
fn emit_write_chunks(builder: &mut SendStreamBuilder, path: &[u8], file_offset: u64, data: &[u8]) {
    let mut chunk_offset = file_offset;
    for chunk in data.chunks(BTRFS_SEND_WRITE_CHUNK) {
        let (cmd, attrs) = build_write_command(path, chunk_offset, chunk);
        let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
        builder.add_command(cmd, &refs);
        chunk_offset = chunk_offset.saturating_add(chunk.len() as u64);
    }
}

/// Generate a btrfs send stream from FS tree items.
///
/// This function walks the given FS tree items and produces a valid send stream
/// that can be consumed by `btrfs receive`. The stream contains:
/// - Subvol command (root)
/// - Create commands for directories, files, symlinks, special files
/// - Write commands for file data
/// - SetXattr commands for extended attributes
/// - Chmod/Chown/Utimes for metadata
/// - End command
///
/// # Arguments
/// * `items` - FS tree leaf entries from `walk_btrfs_fs_tree`
/// * `subvol_name` - Name for the subvolume in the stream
/// * `subvol_uuid` - UUID for the subvolume (16 bytes)
/// * `ctransid` - Creation transaction ID
/// * `read_extent` - Closure to read extent data: (disk_bytenr, disk_num_bytes) -> data
///
/// # Returns
/// The complete send stream bytes on success.
#[expect(clippy::too_many_lines)]
pub fn generate_send_stream<F>(
    items: &[BtrfsLeafEntry],
    subvol_name: &[u8],
    subvol_uuid: &[u8; 16],
    ctransid: u64,
    mut read_extent: F,
) -> Result<Vec<u8>, ParseError>
where
    // (disk_bytenr, disk_num_bytes, ram_bytes, compression) -> DECOMPRESSED extent
    // bytes. The callee must decompress compressed extents (ffs-btrfs has no
    // decompressor) so the slice below is always in uncompressed/logical space.
    F: FnMut(u64, u64, u64, u8) -> Result<Vec<u8>, ParseError>,
{
    let mut builder = SendStreamBuilder::new();
    builder.write_header();

    // Emit subvol command
    let (cmd, attrs) = build_subvol_command(subvol_name, subvol_uuid, ctransid);
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    // Build inode -> links mapping from INODE_REF items. key.objectid = child
    // inode, key.offset = parent inode; an item can list several names (links
    // into the same parent), and an inode can have several INODE_REF items
    // (links into different parents). Collect ALL (parent, name) links so hard
    // links beyond the first are emitted as `link` commands, not dropped.
    let mut inode_links: BTreeMap<u64, Vec<(u64, Vec<u8>)>> = BTreeMap::new();
    for entry in items {
        if entry.key.item_type == BTRFS_ITEM_INODE_REF {
            if let Ok(refs) = parse_inode_refs(&entry.data) {
                let links = inode_links.entry(entry.key.objectid).or_default();
                for r in refs {
                    links.push((entry.key.offset, r.name.clone()));
                }
            }
        }
    }
    // The primary link (first) drives path construction; the rest become hard
    // links.
    let inode_parents: BTreeMap<u64, (u64, Vec<u8>)> = inode_links
        .iter()
        .filter_map(|(&ino, links)| links.first().map(|(p, n)| (ino, (*p, n.clone()))))
        .collect();

    // Build a command PATH for an inode by walking up the parent chain. btrfs
    // send command paths are RELATIVE to the received subvolume root: no
    // subvol-name prefix and no leading slash (the receiver creates entries
    // inside the freshly-created subvol). The subvolume root inode itself is the
    // received root — its path is empty (chmod/chown/utimes of the root apply to
    // "."). A subvol-name prefix here makes every MKFILE/MKDIR/WRITE target a
    // never-created `subvol/` subdirectory, so `btrfs receive` fails with ENOENT.
    let build_path = |ino: u64| -> Vec<u8> {
        if ino == BTRFS_FIRST_FREE_OBJECTID {
            return Vec::new();
        }
        let mut components = Vec::new();
        let mut current = ino;

        while let Some((parent, name)) = inode_parents.get(&current) {
            components.push(name.clone());
            if *parent == current || *parent == BTRFS_FIRST_FREE_OBJECTID {
                break;
            }
            current = *parent;
        }

        components.reverse();
        let mut path = Vec::new();
        for comp in components {
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(&comp);
        }
        path
    };

    // Group items by objectid (inode)
    let mut inodes: BTreeMap<u64, Vec<&BtrfsLeafEntry>> = BTreeMap::new();
    for entry in items {
        inodes.entry(entry.key.objectid).or_default().push(entry);
    }

    // Emission order (bd-7ucz7): the receiver creates by PATH, so a parent
    // directory must already exist when its child is created. Emit DIRECTORIES
    // first in topological order (parent dirs before child dirs, by depth in the
    // inode_parents chain), then all non-directory inodes (whose parents are now
    // all present). Plain objectid order is parent-before-child for simple trees
    // but a rename can place a child under a higher-objectid dir, which would
    // emit the child before its parent and break the receive.
    let mut dir_inos: Vec<u64> = Vec::new();
    let mut other_inos: Vec<u64> = Vec::new();
    for (&ino, entries) in &inodes {
        if ino < BTRFS_FIRST_FREE_OBJECTID {
            continue;
        }
        let Some(inode) = entries
            .iter()
            .find(|e| e.key.item_type == BTRFS_ITEM_INODE_ITEM)
            .and_then(|e| parse_inode_item(&e.data).ok())
        else {
            continue;
        };
        #[expect(clippy::cast_possible_truncation)]
        if (inode.mode as u16) & ffs_types::S_IFMT == ffs_types::S_IFDIR {
            dir_inos.push(ino);
        } else {
            other_inos.push(ino);
        }
    }
    let dir_depth = |start: u64| -> usize {
        let mut depth = 0usize;
        let mut cur = start;
        while let Some((parent, _)) = inode_parents.get(&cur) {
            if *parent == cur || *parent == BTRFS_FIRST_FREE_OBJECTID {
                break;
            }
            cur = *parent;
            depth += 1;
            if depth > inodes.len() {
                break; // defensive: malformed cyclic parent chain
            }
        }
        depth
    };
    dir_inos.sort_by_key(|&ino| (dir_depth(ino), ino));
    let emit_order: Vec<u64> = dir_inos.into_iter().chain(other_inos).collect();

    // Process each inode
    for &ino in &emit_order {
        let entries = &inodes[&ino];
        // Skip special inodes (< BTRFS_FIRST_FREE_OBJECTID)
        if ino < BTRFS_FIRST_FREE_OBJECTID {
            continue;
        }

        // Find inode item
        let inode_entry = entries
            .iter()
            .find(|e| e.key.item_type == BTRFS_ITEM_INODE_ITEM);
        let Some(inode_entry) = inode_entry else {
            continue;
        };

        let Ok(inode) = parse_inode_item(&inode_entry.data) else {
            continue;
        };

        let path = build_path(ino);
        // Truncate mode to u16 for S_IF* comparisons (upper bits are flags)
        #[expect(clippy::cast_possible_truncation)]
        let file_type = (inode.mode as u16) & ffs_types::S_IFMT;

        // Emit create command based on type
        match file_type {
            ffs_types::S_IFDIR => {
                // Skip root directory (already created by subvol)
                if ino != BTRFS_FIRST_FREE_OBJECTID {
                    let (cmd, attrs) = build_mkdir_command(&path, ino);
                    let refs: Vec<(SendAttr, &[u8])> =
                        attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
                    builder.add_command(cmd, &refs);
                }
            }
            ffs_types::S_IFREG => {
                let (cmd, attrs) = build_mkfile_command(&path, ino);
                let refs: Vec<(SendAttr, &[u8])> =
                    attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
                builder.add_command(cmd, &refs);

                // Emit write commands for file data
                for entry in entries
                    .iter()
                    .filter(|e| e.key.item_type == BTRFS_ITEM_EXTENT_DATA)
                {
                    if entry.data.len() < 21 {
                        continue;
                    }
                    let extent_type = entry.data[20];
                    let file_offset = entry.key.offset;

                    if extent_type == 0 {
                        // Inline extent: data follows header
                        let data = &entry.data[21..];
                        emit_write_chunks(&mut builder, &path, file_offset, data);
                    } else if (extent_type == BTRFS_FILE_EXTENT_REG
                        || extent_type == BTRFS_FILE_EXTENT_PREALLOC)
                        && entry.data.len() >= 53
                    {
                        // Regular extents carry initialized data; preallocated
                        // extents are unwritten and must be represented as an
                        // extent update, not as bytes read from disk.
                        // EXTENT_DATA layout: ram_bytes@8, compression@16,
                        // type@20, then disk_bytenr/disk_num_bytes/extent_offset/
                        // num_bytes. For a COMPRESSED extent disk_num_bytes is the
                        // compressed on-disk size and extent_offset/num_bytes are
                        // in the UNCOMPRESSED space, so we must decompress before
                        // slicing (read_extent returns decompressed bytes).
                        let ram_bytes =
                            u64::from_le_bytes(entry.data[8..16].try_into().unwrap_or([0; 8]));
                        let compression = entry.data[16];
                        let disk_bytenr =
                            u64::from_le_bytes(entry.data[21..29].try_into().unwrap_or([0; 8]));
                        let disk_num_bytes =
                            u64::from_le_bytes(entry.data[29..37].try_into().unwrap_or([0; 8]));
                        let extent_offset =
                            u64::from_le_bytes(entry.data[37..45].try_into().unwrap_or([0; 8]));
                        let num_bytes =
                            u64::from_le_bytes(entry.data[45..53].try_into().unwrap_or([0; 8]));

                        if extent_type == BTRFS_FILE_EXTENT_PREALLOC || disk_bytenr == 0 {
                            let (cmd, attrs) =
                                build_update_extent_command(&path, file_offset, num_bytes);
                            let refs: Vec<(SendAttr, &[u8])> =
                                attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
                            builder.add_command(cmd, &refs);
                        } else if disk_num_bytes > 0 {
                            // Read (and, if compressed, decompress) extent data,
                            // then emit the write in uncompressed/logical space.
                            if let Ok(full_data) =
                                read_extent(disk_bytenr, disk_num_bytes, ram_bytes, compression)
                            {
                                #[expect(clippy::cast_possible_truncation)]
                                let start = extent_offset as usize;
                                #[expect(clippy::cast_possible_truncation)]
                                let end = start.saturating_add(num_bytes as usize);
                                let data = if end <= full_data.len() {
                                    &full_data[start..end]
                                } else if start < full_data.len() {
                                    &full_data[start..]
                                } else {
                                    &[]
                                };
                                emit_write_chunks(&mut builder, &path, file_offset, data);
                            }
                            // Skip extent on read error
                        }
                    }
                }

                // Truncate to exact size
                let (cmd, attrs) = build_truncate_command(&path, inode.size);
                let refs: Vec<(SendAttr, &[u8])> =
                    attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
                builder.add_command(cmd, &refs);
            }
            ffs_types::S_IFLNK => {
                // For symlinks, the target is in the inline extent
                let target = entries
                    .iter()
                    .find(|e| e.key.item_type == BTRFS_ITEM_EXTENT_DATA)
                    .and_then(|e| {
                        if e.data.len() > 21 && e.data[20] == 0 {
                            Some(&e.data[21..])
                        } else {
                            None
                        }
                    })
                    .unwrap_or(b"");
                let (cmd, attrs) = build_symlink_command(&path, ino, target);
                let refs: Vec<(SendAttr, &[u8])> =
                    attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
                builder.add_command(cmd, &refs);
            }
            ffs_types::S_IFIFO => {
                let (cmd, attrs) = build_mkfifo_command(&path, ino);
                let refs: Vec<(SendAttr, &[u8])> =
                    attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
                builder.add_command(cmd, &refs);
            }
            ffs_types::S_IFSOCK => {
                let (cmd, attrs) = build_mksock_command(&path, ino);
                let refs: Vec<(SendAttr, &[u8])> =
                    attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
                builder.add_command(cmd, &refs);
            }
            ffs_types::S_IFCHR | ffs_types::S_IFBLK => {
                let mode_with_type = u64::from(inode.mode);
                let (cmd, attrs) = build_mknod_command(&path, ino, mode_with_type, inode.rdev);
                let refs: Vec<(SendAttr, &[u8])> =
                    attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
                builder.add_command(cmd, &refs);
            }
            _ => continue,
        }

        // Emit hard links: a non-directory inode reachable by more than one name
        // is created once (above, at its primary path) and linked at each
        // additional path. All parent dirs are already emitted, so the link path
        // resolves. (Directories cannot be hard-linked.)
        if file_type != ffs_types::S_IFDIR {
            if let Some(links) = inode_links.get(&ino) {
                for (parent, name) in links.iter().skip(1) {
                    let mut link_path = build_path(*parent);
                    // Relative to the subvol root: no leading slash for a link
                    // directly under the root (whose build_path is empty).
                    if !link_path.is_empty() {
                        link_path.push(b'/');
                    }
                    link_path.extend_from_slice(name);
                    let (cmd, attrs) = build_link_command(&link_path, &path);
                    let refs: Vec<(SendAttr, &[u8])> =
                        attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
                    builder.add_command(cmd, &refs);
                }
            }
        }

        // Emit xattrs
        for entry in entries
            .iter()
            .filter(|e| e.key.item_type == BTRFS_ITEM_XATTR_ITEM)
        {
            if let Ok(xattr_items) = parse_xattr_items(&entry.data) {
                for xattr in xattr_items {
                    let (cmd, attrs) = build_setxattr_command(&path, &xattr.name, &xattr.value);
                    let refs: Vec<(SendAttr, &[u8])> =
                        attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
                    builder.add_command(cmd, &refs);
                }
            }
        }

        // Emit chmod
        let mode_bits = u64::from(inode.mode & 0o7777);
        let (cmd, attrs) = build_chmod_command(&path, mode_bits);
        let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
        builder.add_command(cmd, &refs);

        // Emit chown
        let (cmd, attrs) = build_chown_command(&path, u64::from(inode.uid), u64::from(inode.gid));
        let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
        builder.add_command(cmd, &refs);

        // Emit utimes
        #[expect(clippy::cast_possible_wrap)]
        let (cmd, attrs) = build_utimes_command(
            &path,
            inode.atime_sec as i64,
            inode.atime_nsec as i32,
            inode.mtime_sec as i64,
            inode.mtime_nsec as i32,
            inode.ctime_sec as i64,
            inode.ctime_nsec as i32,
        );
        let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
        builder.add_command(cmd, &refs);
    }

    builder.finalize();
    Ok(builder.finish())
}

// ── btrfs tree-log replay ─────────────────────────────────────────────────

/// Result of scanning the btrfs tree-log.
///
/// The tree-log is a per-subvolume journal used for efficient fsync. When
/// present (superblock `log_root != 0`), it contains items that were fsynced
/// but not yet committed in a full transaction. On mount, the tree-log must
/// be replayed to bring the FS tree to the state of the last fsync.
#[derive(Debug, Clone, Default)]
pub struct TreeLogReplayResult {
    /// Items extracted from the tree-log, in key order.
    pub items: Vec<BtrfsLeafEntry>,
    /// Number of items replayed.
    pub items_count: usize,
    /// Whether a valid tree-log was found and replayed.
    pub replayed: bool,
}

/// Replay the btrfs tree-log if present.
///
/// Checks the superblock for a non-zero `log_root`. If present, walks the
/// tree-log tree and returns all items found. The caller is responsible for
/// merging these items into the FS tree (applying inode updates, directory
/// entries, and extent mappings).
///
/// The `read_physical` closure reads a physical byte range from the device.
/// If `log_root` is 0, returns an empty result (no tree-log to replay).
pub fn replay_tree_log(
    read_physical: &mut dyn FnMut(u64) -> Result<Vec<u8>, ParseError>,
    sb: &BtrfsSuperblock,
    chunks: &[BtrfsChunkEntry],
) -> Result<TreeLogReplayResult, ParseError> {
    if sb.log_root == 0 {
        return Ok(TreeLogReplayResult::default());
    }

    tracing::info!(
        log_root = sb.log_root,
        log_root_level = sb.log_root_level,
        "btrfs tree-log replay start"
    );

    let items = walk_tree(
        read_physical,
        chunks,
        sb.log_root,
        sb.nodesize,
        sb.csum_type,
    )?;

    tracing::info!(
        items_replayed = items.len(),
        "btrfs tree-log replay complete"
    );

    Ok(TreeLogReplayResult {
        items_count: items.len(),
        items,
        replayed: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_ondisk::{BtrfsStripe, BtrfsSuperblock};
    use proptest::prelude::*;
    use std::collections::{BTreeMap, HashMap};
    use std::fmt::Write as _;
    use std::sync::{Arc, Mutex};

    const NODESIZE: u32 = 4096;
    const HEADER_SIZE: usize = 101;
    const ITEM_SIZE: usize = 25;
    const KEY_PTR_SIZE: usize = 33;

    /// Golden: the btrfs name hash must equal the value real `btrfs check`
    /// recomputes from the stored entry name. The value `0xe73b4577` for the
    /// name "x3fcu_check.txt" was captured directly from `btrfs check`
    /// ("wanted 0xe73b4577") on a FrankenFS-written image (bd-x36qn); the
    /// previous seed-0 crc32c produced the rejected `0x7f4a4789`. A second
    /// vector ("hello") pins the function against any future crc seam change.
    #[test]
    fn btrfs_name_hash_matches_kernel_btrfs_name_hash_bd_x36qn() {
        assert_eq!(btrfs_name_hash(b"x3fcu_check.txt"), 0xe73b_4577);
        // The standard reflected crc32c (seed 0) is the WRONG value that real
        // `btrfs check` rejected ("has 0x7f4a4789"); guard against regressing
        // back to it.
        assert_eq!(ffs_types::crc32c_append(0, b"x3fcu_check.txt"), 0x7f4a_4789);
        assert_ne!(btrfs_name_hash(b"x3fcu_check.txt"), 0x7f4a_4789);
    }

    #[test]
    fn hash_extent_data_ref_matches_kernel_formula() {
        // The on-disk hash for a keyed EXTENT_DATA_REF (shared data extent),
        // the offset component of its key. The kernel chains the raw CRC over
        // owner ++ offset; cross-check the function's CHAINED form against an
        // independent CONCATENATION form (same btrfs-check-validated crc
        // convention as btrfs_name_hash, bd-x36qn). If the function's CRC
        // continuation were wrong, these would diverge.
        for &(root, owner, offset) in &[
            (5_u64, 257_u64, 0_u64),
            (5, 258, 4096),
            (0x100, 0x1234, 0xdead_beef),
        ] {
            let high = !ffs_types::crc32c_append(0, &root.to_le_bytes());
            let mut owner_then_offset = owner.to_le_bytes().to_vec();
            owner_then_offset.extend_from_slice(&offset.to_le_bytes());
            let low = !ffs_types::crc32c_append(0, &owner_then_offset);
            let expected = (u64::from(high) << 31) ^ u64::from(low);
            assert_eq!(
                hash_extent_data_ref(root, owner, offset),
                expected,
                "chained CRC must equal the owner++offset concatenation for \
                 (root={root}, owner={owner}, offset={offset})"
            );
        }

        // Deterministic and input-sensitive.
        assert_eq!(
            hash_extent_data_ref(5, 257, 0),
            hash_extent_data_ref(5, 257, 0)
        );
        assert_ne!(
            hash_extent_data_ref(5, 257, 0),
            hash_extent_data_ref(5, 257, 4096)
        );
        assert_ne!(
            hash_extent_data_ref(5, 257, 0),
            hash_extent_data_ref(5, 258, 0)
        );
        // (On-disk/btrfs-check ground truth is exercised when reflink wiring
        // lands — bd-vh8p9 — which writes keyed EXTENT_DATA_REF items.)
    }

    #[test]
    fn build_extent_csum_item_packs_one_crc32c_per_sector_bd_x3fcu() {
        let sectorsize = 4096_usize;
        // Two sectors with distinct, recognizable content.
        let mut data = vec![0xAB_u8; sectorsize];
        data.extend(std::iter::repeat_n(0xCD_u8, sectorsize));

        let disk_bytenr = 0x1_0000_u64;
        let (key, value) = build_extent_csum_item(disk_bytenr, &data, sectorsize)
            .expect("aligned two-sector extent");

        // Key identifies the csum tree's single EXTENT_CSUM objectid, the
        // EXTENT_CSUM item type, and the extent's logical start as the offset.
        assert_eq!(key.objectid, BTRFS_EXTENT_CSUM_OBJECTID);
        assert_eq!(
            key.objectid,
            u64::from_le_bytes((-10_i64).to_le_bytes()),
            "EXTENT_CSUM objectid is -10"
        );
        assert_eq!(key.item_type, BTRFS_ITEM_EXTENT_CSUM);
        assert_eq!(key.item_type, 128);
        assert_eq!(key.offset, disk_bytenr);

        // One crc32c per sector, packed densely little-endian.
        assert_eq!(value.len(), 2 * BTRFS_CRC32C_CSUM_SIZE);
        let expect0 = ffs_types::crc32c(&data[..sectorsize]).to_le_bytes();
        let expect1 = ffs_types::crc32c(&data[sectorsize..]).to_le_bytes();
        assert_eq!(&value[0..4], &expect0);
        assert_eq!(&value[4..8], &expect1);
        // Distinct sector content yields distinct checksums (no accidental
        // whole-extent hashing).
        assert_ne!(&value[0..4], &value[4..8]);
    }

    #[test]
    fn build_extent_csum_item_rejects_misaligned_or_empty_bd_x3fcu() {
        // Not a whole multiple of sectorsize.
        assert!(matches!(
            build_extent_csum_item(0, &[0u8; 4097], 4096),
            Err(BtrfsMutationError::InvalidConfig(_))
        ));
        // Empty extent.
        assert!(matches!(
            build_extent_csum_item(0, &[], 4096),
            Err(BtrfsMutationError::InvalidConfig(_))
        ));
        // Zero sectorsize.
        assert!(matches!(
            build_extent_csum_item(0, &[0u8; 8], 0),
            Err(BtrfsMutationError::InvalidConfig(_))
        ));
    }

    #[test]
    fn build_extent_csum_items_splits_large_extent_across_leaf_sized_items_bd_x3fcu() {
        let sectorsize = 4096_usize;
        let max_per_item = 2_usize; // force splitting
        // 5 sectors with distinct content -> ceil(5/2) = 3 items (2,2,1).
        let mut data = Vec::new();
        for s in 0..5_u8 {
            data.extend(std::iter::repeat_n(0xA0 | s, sectorsize));
        }
        let disk_bytenr = 0x40_000_u64;
        let items =
            build_extent_csum_items(disk_bytenr, &data, sectorsize, max_per_item).expect("split");

        assert_eq!(items.len(), 3, "5 sectors / 2 per item = 3 items");
        // Item keys advance by max_per_item*sectorsize from disk_bytenr.
        assert_eq!(items[0].0.offset, disk_bytenr);
        assert_eq!(items[1].0.offset, disk_bytenr + 2 * sectorsize as u64);
        assert_eq!(items[2].0.offset, disk_bytenr + 4 * sectorsize as u64);
        // All keys carry the EXTENT_CSUM objectid + type.
        for (k, _) in &items {
            assert_eq!(k.objectid, BTRFS_EXTENT_CSUM_OBJECTID);
            assert_eq!(k.item_type, BTRFS_ITEM_EXTENT_CSUM);
        }
        // Value lengths: 2,2,1 csums * 4 bytes.
        assert_eq!(items[0].1.len(), 2 * BTRFS_CRC32C_CSUM_SIZE);
        assert_eq!(items[1].1.len(), 2 * BTRFS_CRC32C_CSUM_SIZE);
        assert_eq!(items[2].1.len(), BTRFS_CRC32C_CSUM_SIZE);
        // Concatenating all item values reproduces the single-item packing
        // (proves the split is a faithful partition, not a recompute).
        let whole = build_extent_csum_item(disk_bytenr, &data, sectorsize)
            .expect("single")
            .1;
        let joined: Vec<u8> = items.iter().flat_map(|(_, v)| v.clone()).collect();
        assert_eq!(joined, whole);
    }

    #[test]
    fn build_extent_csum_items_single_item_when_under_limit_bd_x3fcu() {
        let sectorsize = 4096_usize;
        let data = vec![0x5A_u8; sectorsize * 3];
        let items = build_extent_csum_items(0x1000, &data, sectorsize, 8).expect("fits");
        assert_eq!(
            items.len(),
            1,
            "3 sectors under the 8-per-item limit = 1 item"
        );
        assert_eq!(items[0].1.len(), 3 * BTRFS_CRC32C_CSUM_SIZE);
    }

    #[test]
    fn max_data_csums_per_item_matches_leaf_geometry_bd_x3fcu() {
        // (nodesize - 101 - 25) / 4, floored, min 1.
        assert_eq!(max_data_csums_per_item(4096), (4096 - 126) / 4);
        assert_eq!(max_data_csums_per_item(16384), (16384 - 126) / 4);
        // Degenerate tiny nodesize never returns 0.
        assert_eq!(max_data_csums_per_item(64), 1);
    }

    #[test]
    fn build_extent_csum_items_rejects_bad_args_bd_x3fcu() {
        assert!(matches!(
            build_extent_csum_items(0, &[0u8; 4096], 4096, 0),
            Err(BtrfsMutationError::InvalidConfig(_))
        ));
        assert!(matches!(
            build_extent_csum_items(0, &[0u8; 4097], 4096, 4),
            Err(BtrfsMutationError::InvalidConfig(_))
        ));
        assert!(matches!(
            build_extent_csum_items(0, &[], 4096, 4),
            Err(BtrfsMutationError::InvalidConfig(_))
        ));
    }

    #[test]
    fn verify_extent_csum_accepts_matching_and_flags_corruption_bd_x3fcu() {
        let sectorsize = 4096_usize;
        let mut data = vec![0xC3_u8; sectorsize];
        data.extend(std::iter::repeat_n(0x7E_u8, sectorsize)); // 2 sectors
        let (_key, csums) = build_extent_csum_item(0x1000, &data, sectorsize).expect("build csums");

        // Faithful data verifies clean (round-trip with the builder).
        assert_eq!(verify_extent_csum(&data, sectorsize, &csums), Ok(()));

        // Corrupt one byte in the SECOND sector -> mismatch reported at sector 1
        // with the recomputed crc, sector 0 still considered good.
        let mut corrupt = data.clone();
        corrupt[sectorsize + 10] ^= 0xFF;
        let expected_good = ffs_types::crc32c(&data[sectorsize..]);
        let result = verify_extent_csum(&corrupt, sectorsize, &csums);
        assert!(
            matches!(result, Err(Ok(_))),
            "expected a sector mismatch, got {result:?}"
        );
        if let Err(Ok(m)) = result {
            assert_eq!(m.sector_index, 1);
            assert_eq!(m.expected, expected_good);
            assert_ne!(m.actual, m.expected);
        }
    }

    #[test]
    fn verify_extent_csum_rejects_bad_args_bd_x3fcu() {
        // Zero sectorsize.
        assert!(matches!(
            verify_extent_csum(&[0u8; 8], 0, &[0u8; 8]),
            Err(Err(BtrfsMutationError::InvalidConfig(_)))
        ));
        // Non-multiple data.
        assert!(matches!(
            verify_extent_csum(&[0u8; 4097], 4096, &[0u8; 4]),
            Err(Err(BtrfsMutationError::InvalidConfig(_)))
        ));
        // Wrong csum length (2 sectors but only 1 csum).
        assert!(matches!(
            verify_extent_csum(&[0u8; 8192], 4096, &[0u8; 4]),
            Err(Err(BtrfsMutationError::InvalidConfig(_)))
        ));
    }

    #[test]
    fn lookup_data_block_csum_finds_block_across_split_items_bd_x3fcu() {
        let sectorsize = 4096_usize;
        let base = 0x80_000_u64;
        // 5 distinct sectors, split into items of 2 -> 3 items at base, base+2*ss, base+4*ss.
        let mut data = Vec::new();
        for s in 0..5_u8 {
            data.extend(std::iter::repeat_n(0x10 | s, sectorsize));
        }
        let items = build_extent_csum_items(base, &data, sectorsize, 2).expect("split");
        assert_eq!(items.len(), 3);

        let ss = u64::try_from(sectorsize).unwrap();
        // Every sector resolves to the same crc the single-item builder packs.
        for s in 0..5_usize {
            let off = s * sectorsize;
            let bytenr = base + u64::try_from(off).unwrap();
            let want = ffs_types::crc32c(&data[off..off + sectorsize]);
            assert_eq!(
                lookup_data_block_csum(&items, bytenr, sectorsize),
                Some(want),
                "sector {s} (crosses item boundaries at 2 and 4)"
            );
        }

        // Misses: before the run, past the run, and a non-sector-aligned bytenr.
        assert_eq!(lookup_data_block_csum(&items, base - ss, sectorsize), None);
        assert_eq!(
            lookup_data_block_csum(&items, base + 5 * ss, sectorsize),
            None
        );
        assert_eq!(lookup_data_block_csum(&items, base + 100, sectorsize), None);
        // Unrelated key types are ignored.
        let noise = vec![(
            BtrfsKey {
                objectid: 5,
                item_type: BTRFS_ITEM_INODE_ITEM,
                offset: base,
            },
            vec![0xFF_u8; 4],
        )];
        assert_eq!(lookup_data_block_csum(&noise, base, sectorsize), None);
    }

    fn test_key(objectid: u64) -> BtrfsKey {
        BtrfsKey {
            objectid,
            item_type: BTRFS_ITEM_INODE_ITEM,
            offset: 0,
        }
    }

    fn test_payload(objectid: u64) -> [u8; 1] {
        [u8::try_from(objectid).expect("test objectid should fit in u8")]
    }

    fn hex_lower(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut out, "{byte:02x}").expect("write to String");
        }
        out
    }

    /// Build a btrfs header in a block buffer.
    fn write_header(
        block: &mut [u8],
        bytenr: u64,
        nritems: u32,
        level: u8,
        owner: u64,
        generation: u64,
    ) {
        block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
        block[0x50..0x58].copy_from_slice(&generation.to_le_bytes());
        block[0x58..0x60].copy_from_slice(&owner.to_le_bytes());
        block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
        block[0x64] = level;
    }

    fn stamp_tree_block_crc32c(block: &mut [u8]) {
        let csum = ffs_types::crc32c(&block[0x20..]);
        block[0..4].copy_from_slice(&csum.to_le_bytes());
    }

    /// Write a leaf item entry at the given index.
    fn write_leaf_item(
        block: &mut [u8],
        idx: usize,
        objectid: u64,
        item_type: u8,
        data_off: u32,
        data_sz: u32,
    ) {
        let base = HEADER_SIZE + idx * ITEM_SIZE;
        let header_size = u32::try_from(HEADER_SIZE).expect("header size should fit in u32");
        let encoded_data_off = data_off
            .checked_sub(header_size)
            .expect("test leaf item data offset should be after header");
        block[base..base + 8].copy_from_slice(&objectid.to_le_bytes());
        block[base + 8] = item_type;
        block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
        block[base + 17..base + 21].copy_from_slice(&encoded_data_off.to_le_bytes());
        block[base + 21..base + 25].copy_from_slice(&data_sz.to_le_bytes());
    }

    fn write_leaf_item_payload(
        block: &mut [u8],
        idx: usize,
        objectid: u64,
        item_type: u8,
        data_off: u32,
        payload: &[u8],
    ) {
        let data_sz = u32::try_from(payload.len()).expect("test item payload length fits u32");
        write_leaf_item(block, idx, objectid, item_type, data_off, data_sz);
        let data_start = usize::try_from(data_off).expect("test data offset fits usize");
        let data_end = data_start
            .checked_add(payload.len())
            .expect("test item payload end fits usize");
        block[data_start..data_end].copy_from_slice(payload);
    }

    /// Write an internal key-pointer entry at the given index.
    fn write_key_ptr(
        block: &mut [u8],
        idx: usize,
        objectid: u64,
        item_type: u8,
        blockptr: u64,
        generation: u64,
    ) {
        let base = HEADER_SIZE + idx * KEY_PTR_SIZE;
        block[base..base + 8].copy_from_slice(&objectid.to_le_bytes());
        block[base + 8] = item_type;
        block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
        block[base + 17..base + 25].copy_from_slice(&blockptr.to_le_bytes());
        block[base + 25..base + 33].copy_from_slice(&generation.to_le_bytes());
    }

    /// Identity chunk: logical == physical for the range [0, 1GiB).
    fn identity_chunks() -> Vec<BtrfsChunkEntry> {
        vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0,
            },
            length: 0x4000_0000, // 1 GiB
            owner: 2,
            stripe_len: 0x1_0000,
            chunk_type: 2,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: 1,
            sub_stripes: 0,
            stripes: vec![BtrfsStripe {
                devid: 1,
                offset: 0, // identity mapping
                dev_uuid: [0; 16],
            }],
        }]
    }

    #[test]
    fn walk_chunk_tree_rejects_invalid_chunk_item() {
        let root_logical = 0x4000_u64;
        let chunks = identity_chunks();

        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, root_logical, 1, 0, BTRFS_CHUNK_TREE_OBJECTID, 1);
        let data_off = NODESIZE.saturating_sub(16);
        write_leaf_item(&mut leaf, 0, 256, BTRFS_ITEM_CHUNK, data_off, 16);
        stamp_tree_block_crc32c(&mut leaf);

        let blocks: HashMap<u64, Vec<u8>> = [(root_logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let sb = BtrfsSuperblock {
            csum: [0; 32],
            fsid: [0; 16],
            bytenr: root_logical,
            flags: 0,
            magic: 0,
            generation: 1,
            root: 0,
            chunk_root: root_logical,
            chunk_root_generation: 1,
            log_root: 0,
            total_bytes: 0,
            bytes_used: 0,
            root_dir_objectid: 0,
            num_devices: 1,
            sectorsize: 4096,
            nodesize: NODESIZE,
            stripesize: 0,
            compat_flags: 0,
            compat_ro_flags: 0,
            incompat_flags: 0,
            csum_type: 0,
            root_level: 0,
            chunk_root_level: 0,
            log_root_level: 0,
            label: String::new(),
            sys_chunk_array_size: 0,
            sys_chunk_array: Vec::new(),
        };

        let err = walk_chunk_tree(&mut read, &sb, &chunks).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn walk_single_leaf() {
        let logical = 0x4000_u64;
        let chunks = identity_chunks();

        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, logical, 2, 0, 5, 10);
        // Item 0: key=(256,1,0), data at [3000..3010]
        write_leaf_item(&mut leaf, 0, 256, 1, 3000, 10);
        leaf[3000..3010].copy_from_slice(&[0xAA; 10]);
        // Item 1: key=(257,1,0), data at [3010..3025]
        write_leaf_item(&mut leaf, 1, 257, 1, 3010, 15);
        leaf[3010..3025].copy_from_slice(&[0xBB; 15]);
        stamp_tree_block_crc32c(&mut leaf);

        let blocks: HashMap<u64, Vec<u8>> = [(logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let entries = walk_tree(&mut read, &chunks, logical, NODESIZE, 0).expect("walk");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key.objectid, 256);
        assert_eq!(entries[0].data, vec![0xAA; 10]);
        assert_eq!(entries[1].key.objectid, 257);
        assert_eq!(entries[1].data, vec![0xBB; 15]);
    }

    #[test]
    fn walk_internal_plus_leaves() {
        let root_logical = 0x1_0000_u64;
        let left_logical = 0x2_0000_u64;
        let right_logical = 0x3_0000_u64;
        let chunks = identity_chunks();

        // Root: internal node (level=1) with 2 children
        let mut root = vec![0_u8; NODESIZE as usize];
        write_header(&mut root, root_logical, 2, 1, 1, 10);
        write_key_ptr(&mut root, 0, 256, 1, left_logical, 10);
        write_key_ptr(&mut root, 1, 512, 1, right_logical, 10);

        // Leaf A: 1 item
        let mut left_leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut left_leaf, left_logical, 1, 0, 5, 10);
        write_leaf_item(&mut left_leaf, 0, 256, 1, 2000, 4);
        left_leaf[2000..2004].copy_from_slice(&[1, 2, 3, 4]);

        // Leaf B: 1 item
        let mut right_leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut right_leaf, right_logical, 1, 0, 5, 10);
        write_leaf_item(&mut right_leaf, 0, 512, 1, 2000, 4);
        right_leaf[2000..2004].copy_from_slice(&[5, 6, 7, 8]);

        stamp_tree_block_crc32c(&mut root);
        stamp_tree_block_crc32c(&mut left_leaf);
        stamp_tree_block_crc32c(&mut right_leaf);

        let blocks: HashMap<u64, Vec<u8>> = [
            (root_logical, root),
            (left_logical, left_leaf),
            (right_logical, right_leaf),
        ]
        .into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let entries = walk_tree(&mut read, &chunks, root_logical, NODESIZE, 0).expect("walk");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key.objectid, 256);
        assert_eq!(entries[0].data, vec![1, 2, 3, 4]);
        assert_eq!(entries[1].key.objectid, 512);
        assert_eq!(entries[1].data, vec![5, 6, 7, 8]);
    }

    /// Build a 2-level tree: one internal root with `objectids.len()` leaf
    /// children, each leaf holding a single item keyed `(objectid, 1, 0)` with a
    /// 4-byte payload. Returns the block map and the root logical address.
    fn build_two_level_tree(objectids: &[u64]) -> (HashMap<u64, Vec<u8>>, u64) {
        let root_logical = 0x1_0000_u64;
        let mut root = vec![0_u8; NODESIZE as usize];
        let nritems = u32::try_from(objectids.len()).expect("test child count fits u32");
        write_header(&mut root, root_logical, nritems, 1, 1, 10);
        let mut blocks: HashMap<u64, Vec<u8>> = HashMap::new();
        for (i, &oid) in objectids.iter().enumerate() {
            let leaf_logical = 0x2_0000_u64 + (i as u64) * 0x1_0000;
            write_key_ptr(&mut root, i, oid, 1, leaf_logical, 10);
            let mut leaf = vec![0_u8; NODESIZE as usize];
            write_header(&mut leaf, leaf_logical, 1, 0, 5, 10);
            write_leaf_item(&mut leaf, 0, oid, 1, 2000, 4);
            let payload = u32::try_from(oid).unwrap_or(0).to_le_bytes();
            leaf[2000..2004].copy_from_slice(&payload);
            stamp_tree_block_crc32c(&mut leaf);
            blocks.insert(leaf_logical, leaf);
        }
        stamp_tree_block_crc32c(&mut root);
        blocks.insert(root_logical, root);
        (blocks, root_logical)
    }

    #[test]
    fn walk_tree_range_isomorphic_to_filtered_full_walk_and_prunes_reads() {
        // 8 leaves spread across the keyspace under a single internal root.
        let oids: Vec<u64> = vec![100, 200, 300, 400, 500, 600, 700, 800];
        let (blocks, root_logical) = build_two_level_tree(&oids);
        let chunks = identity_chunks();

        let key = |oid: u64| BtrfsKey {
            objectid: oid,
            item_type: 0,
            offset: 0,
        };

        // Probe a spread of half-open ranges, including empty, single-hit,
        // multi-hit, boundary, and whole-tree.
        let ranges = [
            (key(0), key(50)),     // empty (below everything)
            (key(300), key(301)),  // single leaf
            (key(250), key(650)),  // spans 300,400,500,600
            (key(800), key(900)),  // last leaf only
            (key(0), key(10_000)), // whole tree
            (key(401), key(599)),  // gap-only: hits leaf keyed 500
        ];

        for (lo, hi) in ranges {
            // Reference: full walk, filtered to [lo, hi) in plain code.
            let mut full_reads = 0_u32;
            let mut read_full = |phys: u64| -> Result<Vec<u8>, ParseError> {
                full_reads += 1;
                blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                    field: "physical",
                    reason: "block not in test image",
                })
            };
            let full =
                walk_tree(&mut read_full, &chunks, root_logical, NODESIZE, 0).expect("full walk");
            let expected: Vec<_> = full
                .into_iter()
                .filter(|e| {
                    key_cmp(&e.key, &lo) != Ordering::Less && key_cmp(&e.key, &hi) == Ordering::Less
                })
                .collect();

            // Targeted descent.
            let mut range_reads = 0_u32;
            let mut read_range = |phys: u64| -> Result<Vec<u8>, ParseError> {
                range_reads += 1;
                blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                    field: "physical",
                    reason: "block not in test image",
                })
            };
            let got = walk_tree_range(&mut read_range, &chunks, root_logical, NODESIZE, 0, lo, hi)
                .expect("range walk");

            // Isomorphism: identical entries (key + data), identical order.
            assert_eq!(
                got.len(),
                expected.len(),
                "range [{lo:?},{hi:?}) entry count"
            );
            for (g, e) in got.iter().zip(expected.iter()) {
                assert_eq!(g.key, e.key, "range [{lo:?},{hi:?}) key");
                assert_eq!(g.data, e.data, "range [{lo:?},{hi:?}) data");
            }

            // Pruning: the targeted walk never reads MORE nodes than the full
            // walk, and reads strictly fewer whenever the range excludes at
            // least one leaf (every probe here except the whole-tree one).
            assert!(
                range_reads <= full_reads,
                "range [{lo:?},{hi:?}) read {range_reads} > full {full_reads}"
            );
            let hits = got.len();
            // full_reads = 1 root + 8 leaves = 9; targeted = 1 root + (leaves touched).
            // Touched leaves <= hits + 1 boundary leaf, always < 8 for these probes.
            if hits < oids.len() {
                assert!(
                    range_reads < full_reads,
                    "range [{lo:?},{hi:?}) hit {hits} leaves but read {range_reads} (no pruning vs full {full_reads})"
                );
            }
        }
    }

    #[test]
    fn walk_unmapped_address_fails() {
        let chunks = identity_chunks();
        // Address beyond the 1GiB chunk range
        let far_logical = 0x8000_0000_u64;
        let mut read = |_phys: u64| -> Result<Vec<u8>, ParseError> {
            Err(ParseError::InvalidField {
                field: "unexpected_read",
                reason: "should not be called",
            })
        };
        let err = walk_tree(&mut read, &chunks, far_logical, NODESIZE, 0).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "logical_address",
                    ..
                }
            ),
            "expected unmapped error, got: {err:?}"
        );
    }

    #[test]
    fn walk_unaligned_root_fails() {
        let chunks = identity_chunks();
        let unaligned = 0x4_001_u64;
        let mut read = |_phys: u64| -> Result<Vec<u8>, ParseError> {
            Err(ParseError::InvalidField {
                field: "unexpected_read",
                reason: "should not be called",
            })
        };
        let err = walk_tree(&mut read, &chunks, unaligned, NODESIZE, 0).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "logical_address",
                reason: "not aligned to nodesize",
            }
        ));
    }

    #[test]
    fn walk_unaligned_child_pointer_fails() {
        let root_logical = 0x1_0000_u64;
        let chunks = identity_chunks();
        let unaligned_child = 0x2_0001_u64;

        let mut root = vec![0_u8; NODESIZE as usize];
        write_header(&mut root, root_logical, 1, 1, 1, 10);
        write_key_ptr(&mut root, 0, 256, 1, unaligned_child, 10);
        stamp_tree_block_crc32c(&mut root);

        let blocks: HashMap<u64, Vec<u8>> = [(root_logical, root)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let err = walk_tree(&mut read, &chunks, root_logical, NODESIZE, 0).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "blockptr",
                reason: "not aligned to nodesize",
            }
        ));
    }

    #[test]
    fn walk_empty_leaf() {
        let logical = 0x4000_u64;
        let chunks = identity_chunks();

        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, logical, 0, 0, 5, 10);
        stamp_tree_block_crc32c(&mut leaf);

        let blocks: HashMap<u64, Vec<u8>> = [(logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let entries = walk_tree(&mut read, &chunks, logical, NODESIZE, 0).expect("walk");
        assert!(entries.is_empty());
    }

    #[test]
    fn walk_self_cycle_fails_fast() {
        let root_logical = 0x1_0000_u64;
        let chunks = identity_chunks();

        let mut root = vec![0_u8; NODESIZE as usize];
        write_header(&mut root, root_logical, 1, 1, 1, 10);
        write_key_ptr(&mut root, 0, 256, 1, root_logical, 10);
        stamp_tree_block_crc32c(&mut root);

        let blocks: HashMap<u64, Vec<u8>> = [(root_logical, root)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let err = walk_tree(&mut read, &chunks, root_logical, NODESIZE, 0).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "logical_address",
                reason: "cycle detected in btrfs tree pointers",
            }
        ));
    }

    #[test]
    fn walk_two_node_cycle_fails_fast() {
        let a_logical = 0x1_0000_u64;
        let b_logical = 0x2_0000_u64;
        let chunks = identity_chunks();

        let mut a = vec![0_u8; NODESIZE as usize];
        write_header(&mut a, a_logical, 1, 1, 1, 10);
        write_key_ptr(&mut a, 0, 256, 1, b_logical, 10);

        let mut b = vec![0_u8; NODESIZE as usize];
        write_header(&mut b, b_logical, 1, 1, 1, 10);
        write_key_ptr(&mut b, 0, 256, 1, a_logical, 10);

        stamp_tree_block_crc32c(&mut a);
        stamp_tree_block_crc32c(&mut b);

        let blocks: HashMap<u64, Vec<u8>> = [(a_logical, a), (b_logical, b)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let err = walk_tree(&mut read, &chunks, a_logical, NODESIZE, 0).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "logical_address",
                reason: "cycle detected in btrfs tree pointers",
            }
        ));
    }

    #[test]
    fn walk_duplicate_child_reference_fails_fast() {
        let root_logical = 0x1_0000_u64;
        let leaf_logical = 0x2_0000_u64;
        let chunks = identity_chunks();

        let mut root = vec![0_u8; NODESIZE as usize];
        write_header(&mut root, root_logical, 2, 1, 1, 10);
        write_key_ptr(&mut root, 0, 256, 1, leaf_logical, 10);
        write_key_ptr(&mut root, 1, 512, 1, leaf_logical, 10);

        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, leaf_logical, 0, 0, 5, 10);

        stamp_tree_block_crc32c(&mut root);
        stamp_tree_block_crc32c(&mut leaf);

        let blocks: HashMap<u64, Vec<u8>> = [(root_logical, root), (leaf_logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let err = walk_tree(&mut read, &chunks, root_logical, NODESIZE, 0).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "logical_address",
                reason: "duplicate node reference in btrfs tree pointers",
            }
        ));
    }

    #[test]
    fn cow_insert_preserves_previous_root_node() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        tree.insert(test_key(10), b"a").expect("insert first");
        let root_before = tree.root_block();
        let snapshot = tree.node_snapshot(root_before).expect("snapshot");

        tree.insert(test_key(20), b"b").expect("insert second");
        let root_after = tree.root_block();
        assert_ne!(root_before, root_after);
        assert_eq!(
            tree.node_snapshot(root_before).expect("snapshot old root"),
            snapshot
        );
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_mutations_record_deferred_node_frees() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        tree.insert(test_key(1), b"a").expect("insert 1");
        assert!(
            !tree.deferred_free_blocks().is_empty(),
            "initial mutation should retire prior root"
        );
        let deferred_before_delete = tree.deferred_free_blocks().len();
        tree.insert(test_key(2), b"b").expect("insert 2");
        tree.delete(&test_key(2)).expect("delete 2");
        assert!(
            tree.deferred_free_blocks().len() > deferred_before_delete,
            "delete path should retire replaced COW nodes"
        );
    }

    #[test]
    fn insert_split_creates_internal_root() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        for objectid in [10_u64, 20, 30, 40] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }

        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("root snapshot"),
            BtrfsCowNode::Internal { .. }
        ));
        let entries = tree
            .range(&test_key(0), &test_key(100))
            .expect("range query");
        let keys = entries
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![10, 20, 30, 40]);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn get_returns_existing_key_data() {
        let mut tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        tree.insert(test_key(10), b"hello").expect("insert");
        tree.insert(test_key(20), b"world").expect("insert");
        tree.insert(test_key(30), b"test").expect("insert");

        assert_eq!(tree.get(&test_key(10)), Some(b"hello".to_vec()));
        assert_eq!(tree.get(&test_key(20)), Some(b"world".to_vec()));
        assert_eq!(tree.get(&test_key(30)), Some(b"test".to_vec()));
        assert_eq!(tree.get(&test_key(15)), None);
        assert_eq!(tree.get(&test_key(0)), None);
        assert_eq!(tree.get(&test_key(100)), None);
    }

    #[test]
    fn root_level_is_zero_for_leaf_only_tree() {
        let tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        assert_eq!(tree.root_level(), 0);
    }

    #[test]
    fn root_level_increases_with_splits() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        assert_eq!(tree.root_level(), 0);

        // Insert enough keys to force a split
        for objectid in 1_u64..=10 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }

        // After splits, root level should be at least 1
        assert!(
            tree.root_level() >= 1,
            "expected root_level >= 1 after splits, got {}",
            tree.root_level()
        );
    }

    #[test]
    fn writeback_dag_assigns_true_per_node_levels_bd_iv5uy() {
        use crate::writeback::WriteDependencyDag;
        use std::collections::{BTreeSet, VecDeque};

        // max_items=3 → a 3-level tree needs > 3*3 leaf items; 40 forces height>=3.
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        for objectid in 1_u64..=40 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }
        let root_level = tree.root_level();
        assert!(
            root_level >= 2,
            "test needs a height>=3 tree, got root_level {root_level}"
        );

        let dag = WriteDependencyDag::from_cow_tree(&tree, 7).expect("dag");

        // BFS the tree: every node's DAG level must equal its true depth
        // (root_level - depth from the root), i.e. leaves 0, parents-of-leaves
        // 1, ..., root = root_level. The pre-fix code gave every internal node
        // level == root_level, so a middle internal at level 1 proves the fix.
        let mut levels_seen = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((tree.root_block(), 0_u8));
        while let Some((block, depth)) = queue.pop_front() {
            if !visited.insert(block) {
                continue;
            }
            let expected = root_level - depth;
            let got = dag.node_level(block).expect("block present in dag");
            assert_eq!(
                got, expected,
                "block {block} at true depth {depth} should have level {expected}, got {got}"
            );
            levels_seen.insert(got);
            if let BtrfsCowNode::Internal { children, .. } =
                tree.node_snapshot(block).expect("snapshot")
            {
                for child in children {
                    queue.push_back((child, depth + 1));
                }
            }
        }

        // A genuine height-3 tree spans levels 0, 1 and 2 — the pre-fix code
        // could only ever emit level 0 (leaves) and root_level (all internals).
        assert!(
            levels_seen.contains(&0) && levels_seen.contains(&1) && levels_seen.contains(&2),
            "expected node levels 0, 1 and 2 to be present, got {levels_seen:?}"
        );
    }

    #[test]
    fn cow_tree_delete_stress_maintains_invariants_at_height3() {
        use std::collections::BTreeSet;

        // Build a height>=3 tree, then delete every key in an interleaved order
        // (evens then odds) so merges/borrows fire across ALL internal levels —
        // previously only the height 2->1 collapse was covered.
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        let n: u64 = 60;
        for oid in 1..=n {
            tree.insert(test_key(oid), &test_payload(oid)).expect("insert");
        }
        assert!(
            tree.height().expect("height") >= 3,
            "test needs a height>=3 tree, got {}",
            tree.height().expect("height")
        );
        tree.validate_invariants().expect("invariants after build");

        let order: Vec<u64> = (1..=n)
            .filter(|x| x % 2 == 0)
            .chain((1..=n).filter(|x| x % 2 == 1))
            .collect();
        let mut remaining: BTreeSet<u64> = (1..=n).collect();
        for oid in order {
            tree.delete(&test_key(oid)).expect("delete");
            remaining.remove(&oid);

            // The tree must remain a valid, balanced btree after every delete.
            tree.validate_invariants()
                .unwrap_or_else(|e| panic!("invariants broken after deleting {oid}: {e:?}"));

            // The deleted key is gone and every remaining key still reads back.
            assert!(
                tree.get(&test_key(oid)).is_none(),
                "deleted key {oid} still present"
            );
            for &r in &remaining {
                let got = tree
                    .get(&test_key(r))
                    .unwrap_or_else(|| panic!("key {r} lost after deleting {oid}"));
                assert_eq!(
                    got,
                    test_payload(r).to_vec(),
                    "key {r} payload corrupted after deleting {oid}"
                );
            }
        }
        assert!(remaining.is_empty());
        assert_eq!(
            tree.root_level(),
            0,
            "a fully drained tree collapses back to a leaf root"
        );
    }

    #[test]
    fn delete_shrinks_to_leaf_root() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        for objectid in 1_u64..=8 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }
        let height_before = tree.height().expect("height before");

        for objectid in 2_u64..=8 {
            tree.delete(&test_key(objectid)).expect("delete");
        }

        let height_after = tree.height().expect("height after");
        assert!(height_after <= height_before);
        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("root snapshot"),
            BtrfsCowNode::Leaf { .. }
        ));
        let entries = tree
            .range(&test_key(0), &test_key(100))
            .expect("range query");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.objectid, 1);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn delete_underflow_borrows_from_right_sibling() {
        let mut tree = InMemoryCowBtrfsTree::new(4).expect("tree");
        for objectid in 1_u64..=5 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }

        tree.delete(&test_key(1)).expect("delete");
        let keys = tree
            .range(&test_key(0), &test_key(10))
            .expect("range query")
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![2, 3, 4, 5]);
        assert_eq!(tree.height().expect("height"), 2);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn delete_underflow_borrows_from_left_sibling() {
        let mut tree = InMemoryCowBtrfsTree::new(4).expect("tree");
        for objectid in [10_u64, 20, 30, 40, 50, 5] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }
        tree.delete(&test_key(50)).expect("seed delete");

        tree.delete(&test_key(40)).expect("left borrow delete");
        let keys = tree
            .range(&test_key(0), &test_key(100))
            .expect("range query")
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![5, 10, 20, 30]);
        assert_eq!(tree.height().expect("height"), 2);
        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("root snapshot"),
            BtrfsCowNode::Internal { .. }
        ));
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn delete_underflow_merges_and_shrinks_root() {
        let mut tree = InMemoryCowBtrfsTree::new(4).expect("tree");
        for objectid in 1_u64..=5 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }

        tree.delete(&test_key(5)).expect("delete first");
        tree.delete(&test_key(4)).expect("delete second");
        let keys = tree
            .range(&test_key(0), &test_key(10))
            .expect("range query")
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![1, 2, 3]);
        assert_eq!(tree.height().expect("height"), 1);
        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("root snapshot"),
            BtrfsCowNode::Leaf { .. }
        ));
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn delete_missing_key_returns_error() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        tree.insert(test_key(1), b"a").expect("insert");
        let err = tree.delete(&test_key(999)).expect_err("delete should fail");
        assert_eq!(err, BtrfsMutationError::KeyNotFound);
    }

    #[test]
    fn update_replaces_existing_value() {
        let mut tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        let key = test_key(9);
        tree.insert(key, b"old").expect("insert");
        tree.update(&key, b"new").expect("update");
        let entries = tree.range(&key, &key).expect("point range");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, b"new");
    }

    #[test]
    fn update_internal_child_rewrites_parent_and_preserves_order() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        for objectid in [10_u64, 20, 30, 40] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }
        assert_eq!(tree.height().expect("height before"), 2);
        let root_before = tree.root_block();
        let root_snapshot = tree.node_snapshot(root_before).expect("root snapshot");

        tree.update(&test_key(20), b"updated")
            .expect("update internal child");

        assert_ne!(tree.root_block(), root_before);
        assert_eq!(
            tree.node_snapshot(root_before).expect("old root snapshot"),
            root_snapshot
        );
        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("new root snapshot"),
            BtrfsCowNode::Internal { .. }
        ));
        let entries = tree
            .range(&test_key(0), &test_key(100))
            .expect("range query");
        let keys = entries
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![10, 20, 30, 40]);
        assert_eq!(entries[0].1, test_payload(10));
        assert_eq!(entries[1].1, b"updated");
        assert_eq!(entries[2].1, test_payload(30));
        assert_eq!(entries[3].1, test_payload(40));
        assert_eq!(tree.height().expect("height after"), 2);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn range_returns_inclusive_sorted_window() {
        let mut tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        for objectid in 1_u64..=6 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }

        let entries = tree.range(&test_key(2), &test_key(4)).expect("range query");
        let keys = entries
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![2, 3, 4]);
    }

    #[test]
    fn range_descends_multi_level_tree_without_full_materialisation() {
        // With max_items=3, inserting 40 keys forces several internal levels.
        // The range scan must descend B-tree-aware (skipping children whose
        // separator span is outside [start, end]) instead of materialising
        // the entire tree. The semantic check is that range() returns
        // exactly the keys in the window; the complexity improvement is
        // validated separately by the bd-yt66z resolve-path tests.
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        for objectid in 0_u64..40 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }

        // Window in the middle of the tree — must span multiple leaves and
        // skip both left and right subtrees.
        let entries = tree
            .range(&test_key(12), &test_key(27))
            .expect("range query");
        let keys = entries
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, (12_u64..=27).collect::<Vec<_>>());

        // Window below the smallest key — must return empty without error.
        let empty = tree
            .range(
                &BtrfsKey {
                    objectid: 0,
                    item_type: 0,
                    offset: 0,
                },
                &BtrfsKey {
                    objectid: 0,
                    item_type: 0,
                    offset: u64::MAX,
                },
            )
            .expect("range below tree");
        assert!(
            empty.is_empty(),
            "range below tree span must be empty, got {empty:?}"
        );

        // Window above the largest key — also empty.
        let empty = tree
            .range(&test_key(100), &test_key(200))
            .expect("range above tree");
        assert!(empty.is_empty());

        // Exact-single-key range returns just that key.
        let one = tree.range(&test_key(17), &test_key(17)).expect("point");
        let one_keys = one.iter().map(|(key, _)| key.objectid).collect::<Vec<_>>();
        assert_eq!(one_keys, vec![17_u64]);
    }

    #[test]
    fn random_mutations_preserve_invariants_and_ordering() {
        let mut tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        let mut model = BTreeMap::<u64, u8>::new();
        let mut state = 0xD1CE_D00D_CAFE_BABEu64;

        for _ in 0..1000 {
            // LCG for deterministic pseudo-random operations without extra deps.
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let objectid = (state % 128) + 1;
            let op = state % 3;
            let payload = [u8::try_from(objectid).expect("objectid should fit u8")];
            let key = test_key(objectid);

            match op {
                0 => {
                    if tree.insert(key, &payload).is_ok() {
                        model.insert(objectid, payload[0]);
                    }
                }
                1 => {
                    if tree.update(&key, &payload).is_ok() {
                        model.insert(objectid, payload[0]);
                    }
                }
                _ => {
                    if tree.delete(&key).is_ok() {
                        model.remove(&objectid);
                    }
                }
            }

            tree.validate_invariants().expect("invariants after op");
            let observed = tree
                .range(&test_key(0), &test_key(u64::MAX))
                .expect("full range");
            let observed_keys = observed
                .iter()
                .map(|(entry_key, _)| entry_key.objectid)
                .collect::<Vec<_>>();
            let model_keys = model.keys().copied().collect::<Vec<_>>();
            assert_eq!(observed_keys, model_keys);
        }
    }

    #[test]
    fn cow_adversarial_duplicate_insert_short_circuits_without_mutation() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        tree.insert(test_key(10), b"old").expect("seed insert");

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(0));
        let err = tree
            .insert(test_key(10), b"duplicate")
            .expect_err("duplicate insert should short-circuit before allocation");
        assert_eq!(err, BtrfsMutationError::KeyAlreadyExists);
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after duplicate insert"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 0);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_missing_update_short_circuits_without_mutation() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        for objectid in [10_u64, 20, 30] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(0));
        let err = tree
            .update(&test_key(40), b"missing")
            .expect_err("missing update should short-circuit before allocation");
        assert_eq!(err, BtrfsMutationError::KeyNotFound);
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after missing update"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 0);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_missing_delete_short_circuits_without_mutation() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        for objectid in [10_u64, 20, 30, 40] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }
        assert_eq!(tree.height().expect("height"), 2);

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(0));
        let err = tree
            .delete(&test_key(25))
            .expect_err("missing delete should short-circuit before allocation");
        assert_eq!(err, BtrfsMutationError::KeyNotFound);
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after missing delete"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 0);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_leaf_split_left_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        for objectid in [10_u64, 20, 30] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(0));
        let err = tree
            .insert(test_key(40), b"d")
            .expect_err("left split allocation should fail before publishing a root");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after failed left split allocation"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 0);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_leaf_split_right_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        for objectid in [10_u64, 20, 30] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(1));
        let err = tree
            .insert(test_key(40), b"d")
            .expect_err("right split allocation should fail before publishing a root");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after failed right split allocation"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 1);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_root_split_allocator_failure_is_not_visible() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        for objectid in [10_u64, 20, 30] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(2));
        let err = tree
            .insert(test_key(40), b"d")
            .expect_err("new root allocation should fail after split children allocate");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after failed split"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 2);
        tree.validate_invariants().expect("invariants");
    }

    fn seed_cow_tree_for_internal_split(tree: &mut InMemoryCowBtrfsTree) {
        for objectid in [10_u64, 20, 30, 40, 50, 60, 70, 80, 90] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }
        assert_eq!(tree.height().expect("height"), 2);
        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("root snapshot"),
            BtrfsCowNode::Internal { keys, .. } if keys.len() == 3
        ));
    }

    #[test]
    fn cow_insert_internal_split_creates_higher_root_and_preserves_order() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        seed_cow_tree_for_internal_split(&mut tree);

        tree.insert(test_key(100), &test_payload(100))
            .expect("insert triggering internal split");

        assert_eq!(tree.height().expect("height"), 3);
        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("root snapshot"),
            BtrfsCowNode::Internal { keys, children } if keys.len() == 1 && children.len() == 2
        ));
        let keys = tree
            .range(&test_key(0), &test_key(200))
            .expect("range query")
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_internal_split_left_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        seed_cow_tree_for_internal_split(&mut tree);

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(200))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(2));
        let err = tree
            .insert(test_key(100), &test_payload(100))
            .expect_err("left internal split allocation should fail after leaf split allocates");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(200))
                .expect("range after failed internal split left allocation"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 2);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_internal_split_right_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        seed_cow_tree_for_internal_split(&mut tree);

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(200))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(3));
        let err = tree.insert(test_key(100), &test_payload(100)).expect_err(
            "right internal split allocation should fail after left internal allocates",
        );
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(200))
                .expect("range after failed internal split right allocation"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 3);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_internal_root_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        seed_cow_tree_for_internal_split(&mut tree);

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(200))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(4));
        let err = tree
            .insert(test_key(100), &test_payload(100))
            .expect_err("new root allocation should fail after internal split allocates");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(200))
                .expect("range after failed internal root allocation"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 4);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_parent_rewrite_allocator_failure_does_not_retire_live_child() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        for objectid in [10_u64, 20, 30, 40] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }
        assert_eq!(tree.height().expect("height"), 2);

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(1));
        let err = tree
            .insert(test_key(25), b"new")
            .expect_err("parent rewrite allocation should fail after child rewrite allocates");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after failed parent rewrite"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 1);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_delete_borrow_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator_max(4);
        for objectid in 1_u64..=5 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(10))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(1));
        let err = tree
            .delete(&test_key(1))
            .expect_err("right-borrow allocation should fail after child rewrite allocates");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(10))
                .expect("range after failed delete borrow"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 1);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_delete_left_borrow_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator_max(4);
        for objectid in [10_u64, 20, 30, 40, 50, 5] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }
        tree.delete(&test_key(50)).expect("seed delete");

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(1));
        let err = tree
            .delete(&test_key(40))
            .expect_err("left-borrow allocation should fail after child rewrite allocates");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after failed delete left borrow"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 1);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_delete_merge_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator_max(4);
        for objectid in 1_u64..=5 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }
        tree.delete(&test_key(5)).expect("seed delete");

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(10))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(2));
        let err = tree
            .delete(&test_key(4))
            .expect_err("parent allocation should fail after merge allocation");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(10))
                .expect("range after failed delete merge"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 2);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_update_leaf_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        tree.insert(test_key(10), b"old").expect("seed insert");

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(0));
        let err = tree
            .update(&test_key(10), b"new")
            .expect_err("leaf update allocation should fail");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after failed leaf update"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 0);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_update_parent_rewrite_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        for objectid in [10_u64, 20, 30, 40] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }
        assert_eq!(tree.height().expect("height"), 2);

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(1));
        let err = tree
            .update(&test_key(20), b"updated")
            .expect_err("parent rewrite allocation should fail after update child allocates");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after failed parent update"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 1);
        tree.validate_invariants().expect("invariants");
    }

    fn lcg_next(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        *state
    }

    fn payload_from_rng(rand: u64, case: usize) -> Vec<u8> {
        let case_u64 = u64::try_from(case).expect("case should fit u64");
        (rand ^ case_u64).to_le_bytes().to_vec()
    }

    #[derive(Debug)]
    struct FailAllocatorState {
        next_block: u64,
        remaining_successful_allocs: Option<usize>,
        deferred: Vec<u64>,
    }

    #[derive(Debug)]
    struct SharedFailAllocator {
        state: Arc<Mutex<FailAllocatorState>>,
    }

    impl SharedFailAllocator {
        fn new(state: Arc<Mutex<FailAllocatorState>>) -> Self {
            Self { state }
        }
    }

    impl BtrfsAllocator for SharedFailAllocator {
        fn alloc_block(&mut self) -> Result<u64, BtrfsMutationError> {
            let mut state = lock_fail_allocator_state(&self.state);
            if let Some(remaining) = &mut state.remaining_successful_allocs {
                if *remaining == 0 {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "injected allocation failure",
                    ));
                }
                *remaining -= 1;
            }
            let block = state.next_block;
            state.next_block = state
                .next_block
                .checked_add(1)
                .ok_or(BtrfsMutationError::AddressOverflow)?;
            drop(state);
            Ok(block)
        }

        fn defer_free(&mut self, block: u64) {
            lock_fail_allocator_state(&self.state).deferred.push(block);
        }
    }

    fn cow_tree_with_shared_allocator() -> (InMemoryCowBtrfsTree, Arc<Mutex<FailAllocatorState>>) {
        cow_tree_with_shared_allocator_max(3)
    }

    fn cow_tree_with_shared_allocator_max(
        max_items: usize,
    ) -> (InMemoryCowBtrfsTree, Arc<Mutex<FailAllocatorState>>) {
        let state = Arc::new(Mutex::new(FailAllocatorState {
            next_block: 2,
            remaining_successful_allocs: None,
            deferred: Vec::new(),
        }));
        let tree = InMemoryCowBtrfsTree::with_allocator(
            max_items,
            Box::new(SharedFailAllocator::new(Arc::clone(&state))),
        )
        .expect("tree");
        (tree, state)
    }

    fn set_allocator_remaining_successes(
        state: &Arc<Mutex<FailAllocatorState>>,
        remaining: Option<usize>,
    ) {
        lock_fail_allocator_state(state).remaining_successful_allocs = remaining;
    }

    fn allocator_deferred_len(state: &Arc<Mutex<FailAllocatorState>>) -> usize {
        lock_fail_allocator_state(state).deferred.len()
    }

    fn assert_allocator_deferred_delta(
        state: &Arc<Mutex<FailAllocatorState>>,
        before: usize,
        expected_delta: usize,
    ) {
        assert_eq!(allocator_deferred_len(state), before + expected_delta);
    }

    fn lock_fail_allocator_state(
        state: &Arc<Mutex<FailAllocatorState>>,
    ) -> std::sync::MutexGuard<'_, FailAllocatorState> {
        match state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn assert_extent_non_overlap(
        allocations: &BTreeMap<u64, ExtentAllocation>,
        candidate: ExtentAllocation,
        seed: u64,
        case: usize,
    ) {
        for existing in allocations.values() {
            let candidate_end = candidate
                .bytenr
                .checked_add(candidate.num_bytes)
                .expect("candidate extent end overflow");
            let existing_end = existing
                .bytenr
                .checked_add(existing.num_bytes)
                .expect("existing extent end overflow");
            let disjoint = candidate_end <= existing.bytenr || existing_end <= candidate.bytenr;
            assert!(
                disjoint,
                "overlapping extents detected seed={seed:#x} case={case}: candidate={candidate:?} existing={existing:?}"
            );
        }
    }

    fn run_cow_property(seed: u64, cases: usize) {
        let mut tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        let mut model = BTreeMap::<u64, Vec<u8>>::new();
        let mut state = seed;

        for case in 0..cases {
            let rand = lcg_next(&mut state);
            let objectid = (rand % 256) + 1;
            let key = test_key(objectid);
            let payload = payload_from_rng(rand, case);

            match rand % 3 {
                0 => {
                    let result = tree.insert(key, &payload);
                    if result.is_ok() {
                        model.insert(objectid, payload.clone());
                    } else {
                        assert_eq!(
                            result.expect_err("duplicate insert should fail"),
                            BtrfsMutationError::KeyAlreadyExists
                        );
                    }
                }
                1 => {
                    let result = tree.update(&key, &payload);
                    if let std::collections::btree_map::Entry::Occupied(mut entry) =
                        model.entry(objectid)
                    {
                        result.expect("update existing key");
                        entry.insert(payload.clone());
                    } else {
                        assert_eq!(
                            result.expect_err("update on missing key should fail"),
                            BtrfsMutationError::KeyNotFound
                        );
                    }
                }
                _ => {
                    let result = tree.delete(&key);
                    if model.remove(&objectid).is_some() {
                        result.expect("delete existing key");
                    } else {
                        assert_eq!(
                            result.expect_err("delete on missing key should fail"),
                            BtrfsMutationError::KeyNotFound
                        );
                    }
                }
            }

            tree.validate_invariants()
                .expect("tree invariants after random operation");
            let observed = tree
                .range(&test_key(0), &test_key(u64::MAX))
                .expect("full tree range");
            let observed_pairs = observed
                .into_iter()
                .map(|(entry_key, data)| (entry_key.objectid, data))
                .collect::<Vec<_>>();
            let model_pairs = model
                .iter()
                .map(|(objectid, data)| (*objectid, data.clone()))
                .collect::<Vec<_>>();
            assert_eq!(
                observed_pairs, model_pairs,
                "cow model mismatch seed={seed:#x} case={case}"
            );
        }
    }

    fn run_allocator_property(seed: u64, cases: usize) {
        let mut alloc = BtrfsExtentAllocator::new(99).expect("allocator");
        let bg_a = 0x1_0000_u64;
        let bg_b = 0x5_0000_u64;
        alloc.add_block_group(bg_a, make_data_bg(bg_a, 0x40_000));
        alloc.add_block_group(bg_b, make_data_bg(bg_b, 0x40_000));

        let mut expected_used = BTreeMap::from([(bg_a, 0_u64), (bg_b, 0_u64)]);
        let mut live = BTreeMap::<u64, ExtentAllocation>::new();
        let mut state = seed;
        let sizes = [4096_u64, 8192, 12_288, 16_384];

        for case in 0..cases {
            let rand = lcg_next(&mut state);
            let should_free = (rand & 1) == 1 && !live.is_empty();

            if should_free {
                let idx = usize::try_from(rand).expect("rand should fit usize") % live.len();
                let extent = *live
                    .values()
                    .nth(idx)
                    .expect("index into live allocation set");
                alloc
                    .free_extent(extent.bytenr, extent.num_bytes, false)
                    .expect("free extent");
                live.remove(&extent.bytenr);
                let used = expected_used
                    .get_mut(&extent.block_group_start)
                    .expect("expected block group key");
                *used = used.saturating_sub(extent.num_bytes);
            } else {
                let size_idx = usize::try_from(rand).expect("rand should fit usize") % sizes.len();
                let size = sizes[size_idx];
                if let Ok(extent) = alloc.alloc_data(size) {
                    assert_extent_non_overlap(&live, extent, seed, case);
                    live.insert(extent.bytenr, extent);
                    let used = expected_used
                        .get_mut(&extent.block_group_start)
                        .expect("expected block group key");
                    *used = used.saturating_add(extent.num_bytes);
                }
            }

            for (bg, used) in &expected_used {
                let observed = alloc.block_group(*bg).expect("block group").used_bytes;
                assert_eq!(
                    observed, *used,
                    "allocator accounting mismatch seed={seed:#x} case={case} block_group={bg:#x}"
                );
            }
        }

        alloc
            .flush_delayed_refs(usize::MAX)
            .expect("flush delayed refs");
        for extent in live.values() {
            let key = ExtentKey {
                bytenr: extent.bytenr,
                num_bytes: extent.num_bytes,
            };
            assert_eq!(
                alloc.extent_refcount(key),
                1,
                "live extent must have refcount=1 seed={seed:#x}"
            );
        }
    }

    fn run_delayed_ref_property(seed: u64, cases: usize) {
        let mut queue = DelayedRefQueue::new();
        let mut model = BTreeMap::<ExtentKey, u64>::new();
        let extents = (0_u64..64)
            .map(|idx| ExtentKey {
                bytenr: 0x10_0000 + idx * 4096,
                num_bytes: 4096,
            })
            .collect::<Vec<_>>();

        let mut state = seed;
        for case in 0..cases {
            let rand = lcg_next(&mut state);
            let extent_idx = usize::try_from(rand).expect("rand should fit usize") % extents.len();
            let extent = extents[extent_idx];
            let current = model.get(&extent).copied().unwrap_or(0);
            let delete = (rand & 1) == 1 && current > 0;
            let ref_type = match rand % 4 {
                0 => BtrfsRef::DataExtent {
                    root: BTRFS_FS_TREE_OBJECTID,
                    objectid: extent.bytenr,
                    offset: extent.num_bytes,
                },
                1 => BtrfsRef::SharedDataExtent {
                    parent: extent.bytenr,
                },
                2 => BtrfsRef::TreeBlock {
                    root: BTRFS_EXTENT_TREE_OBJECTID,
                    owner: extent.bytenr,
                    offset: extent.num_bytes,
                    level: 0,
                },
                _ => BtrfsRef::SharedTreeBlock {
                    parent: extent.bytenr,
                    level: 0,
                },
            };
            let action = if delete {
                RefAction::Delete
            } else {
                RefAction::Insert
            };
            queue.queue(extent, ref_type, action);

            if delete {
                let updated = current - 1;
                if updated == 0 {
                    model.remove(&extent);
                } else {
                    model.insert(extent, updated);
                }
            } else {
                model.insert(extent, current + 1);
            }

            if case % 250 == 0 {
                assert_eq!(
                    queue.pending_count(),
                    case + 1,
                    "queue size mismatch seed={seed:#x} case={case}"
                );
            }
        }

        let mut observed = BTreeMap::new();
        let flushed = queue
            .flush(usize::MAX, &mut observed)
            .expect("flush delayed refs");
        assert_eq!(flushed, cases);
        assert_eq!(observed, model);
    }

    fn run_transaction_property(seed: u64, cases: usize) {
        let cx = Cx::for_request();
        let mut harness = TxPropertyHarness::new();
        let mut state = seed;

        for case in 0..cases {
            let rand = lcg_next(&mut state);
            match rand % 4 {
                0 => harness.commit_single(rand, case, &cx),
                1 => harness.abort_single(rand, case, &cx),
                2 => harness.commit_disjoint_pair(rand, case, &cx),
                _ => harness.conflict_pair(rand, case, &cx),
            }
            harness.assert_sample_visible(rand, seed, case);
        }

        harness.assert_all_visible();
    }

    #[derive(Debug, Default)]
    struct TxPropertyHarness {
        store: MvccStore,
        expected: BTreeMap<u64, Vec<u8>>,
        expected_commit_seq: u64,
    }

    impl TxPropertyHarness {
        fn new() -> Self {
            Self::default()
        }

        fn commit_single(&mut self, rand: u64, case: usize, cx: &Cx) {
            let tree_id = if (rand & 1) == 0 {
                BTRFS_FS_TREE_OBJECTID
            } else {
                BTRFS_EXTENT_TREE_OBJECTID
            };
            let block = BlockNumber(0x20_000 + (rand % 128));
            let payload = payload_from_rng(rand.rotate_left(7), case);
            let mut txn = BtrfsTransaction::begin(&mut self.store, 100 + rand, cx)
                .expect("begin transaction");
            txn.stage_tree_root(
                tree_id,
                TreeRoot {
                    bytenr: 0x1000_0000 + rand,
                    level: u8::try_from(rand % 3).expect("level should fit u8"),
                },
            );
            txn.stage_block_write(block, payload.clone())
                .expect("stage write");
            let seq = txn.commit(&mut self.store, cx).expect("commit transaction");
            self.expected_commit_seq = self.expected_commit_seq.saturating_add(1);
            assert_eq!(seq.0, self.expected_commit_seq);
            self.expected.insert(block.0, payload);
        }

        fn abort_single(&mut self, rand: u64, case: usize, cx: &Cx) {
            let block = BlockNumber(0x21_000 + (rand % 128));
            let mut txn = BtrfsTransaction::begin(&mut self.store, 200 + rand, cx)
                .expect("begin transaction");
            txn.stage_tree_root(
                BTRFS_FS_TREE_OBJECTID,
                TreeRoot {
                    bytenr: 0x2000_0000 + rand,
                    level: 1,
                },
            );
            txn.stage_block_write(block, payload_from_rng(rand, case))
                .expect("stage write");
            let _ = txn.abort();
        }

        fn commit_disjoint_pair(&mut self, rand: u64, case: usize, cx: &Cx) {
            let mut tx1 =
                BtrfsTransaction::begin(&mut self.store, 300 + rand, cx).expect("begin tx1");
            let mut tx2 =
                BtrfsTransaction::begin(&mut self.store, 300 + rand, cx).expect("begin tx2");
            let block1 = BlockNumber(0x22_000 + (rand % 64));
            let block2 = BlockNumber(0x23_000 + (rand % 64));
            let payload1 = payload_from_rng(rand, case);
            let payload2 = payload_from_rng(rand.rotate_left(13), case);

            tx1.stage_tree_root(
                BTRFS_FS_TREE_OBJECTID,
                TreeRoot {
                    bytenr: 0x3000_0000 + rand,
                    level: 0,
                },
            );
            tx1.stage_block_write(block1, payload1.clone())
                .expect("stage tx1 write");

            tx2.stage_tree_root(
                BTRFS_EXTENT_TREE_OBJECTID,
                TreeRoot {
                    bytenr: 0x3100_0000 + rand,
                    level: 0,
                },
            );
            tx2.stage_block_write(block2, payload2.clone())
                .expect("stage tx2 write");

            let s1 = tx1.commit(&mut self.store, cx).expect("commit tx1");
            let s2 = tx2.commit(&mut self.store, cx).expect("commit tx2");
            self.expected_commit_seq = self.expected_commit_seq.saturating_add(2);
            assert_eq!(s2.0, self.expected_commit_seq);
            assert_eq!(s1.0 + 1, s2.0);
            self.expected.insert(block1.0, payload1);
            self.expected.insert(block2.0, payload2);
        }

        fn conflict_pair(&mut self, rand: u64, case: usize, cx: &Cx) {
            let mut tx1 =
                BtrfsTransaction::begin(&mut self.store, 400 + rand, cx).expect("begin tx1");
            let mut tx2 =
                BtrfsTransaction::begin(&mut self.store, 400 + rand, cx).expect("begin tx2");
            let block = BlockNumber(0x24_000 + (rand % 64));
            let payload1 = payload_from_rng(rand, case);
            let payload2 = payload_from_rng(rand.rotate_right(11), case);

            tx1.stage_tree_root(
                BTRFS_FS_TREE_OBJECTID,
                TreeRoot {
                    bytenr: 0x3200_0000 + rand,
                    level: 1,
                },
            );
            tx2.stage_tree_root(
                BTRFS_FS_TREE_OBJECTID,
                TreeRoot {
                    bytenr: 0x3210_0000 + rand,
                    level: 1,
                },
            );
            tx1.stage_block_write(block, payload1.clone())
                .expect("stage tx1 write");
            tx2.stage_block_write(block, payload2)
                .expect("stage tx2 write");

            let s1 = tx1.commit(&mut self.store, cx).expect("commit tx1");
            self.expected_commit_seq = self.expected_commit_seq.saturating_add(1);
            assert_eq!(s1.0, self.expected_commit_seq);
            self.expected.insert(block.0, payload1);

            let err = tx2.commit(&mut self.store, cx).expect_err("tx2 conflict");
            assert!(
                matches!(
                    err,
                    BtrfsTransactionError::Commit(CommitError::Conflict { .. })
                ),
                "expected FCW conflict, got {err:?}"
            );
        }

        fn assert_sample_visible(&self, rand: u64, seed: u64, case: usize) {
            if self.expected.is_empty() {
                return;
            }
            let sample_idx =
                usize::try_from(rand).expect("rand should fit usize") % self.expected.len();
            let (block, payload) = self
                .expected
                .iter()
                .nth(sample_idx)
                .expect("sample expected payload");
            let snapshot = self.store.current_snapshot();
            let observed = self
                .store
                .read_visible(BlockNumber(*block), snapshot)
                .expect("sample payload should be visible");
            assert_eq!(
                observed, *payload,
                "transaction sample mismatch seed={seed:#x} case={case} block={block}"
            );
        }

        fn assert_all_visible(&self) {
            let snapshot = self.store.current_snapshot();
            for (block, payload) in &self.expected {
                let observed = self
                    .store
                    .read_visible(BlockNumber(*block), snapshot)
                    .expect("payload should be visible");
                assert_eq!(observed, *payload);
            }
        }
    }

    #[test]
    fn property_cow_seed_01_1000_cases() {
        run_cow_property(0x000A_11CE_0001, 1000);
    }

    #[test]
    fn property_cow_seed_02_1000_cases() {
        run_cow_property(0x000A_11CE_0002, 1000);
    }

    #[test]
    fn property_cow_seed_03_1000_cases() {
        run_cow_property(0x000A_11CE_0003, 1000);
    }

    #[test]
    fn property_cow_seed_04_1000_cases() {
        run_cow_property(0x000A_11CE_0004, 1000);
    }

    #[test]
    fn property_cow_seed_05_1000_cases() {
        run_cow_property(0x000A_11CE_0005, 1000);
    }

    #[test]
    fn property_allocator_seed_01_1000_cases() {
        run_allocator_property(0xB00C_A001, 1000);
    }

    #[test]
    fn property_allocator_seed_02_1000_cases() {
        run_allocator_property(0xB00C_A002, 1000);
    }

    #[test]
    fn property_delayed_refs_seed_01_1000_cases() {
        run_delayed_ref_property(0xC001_D001, 1000);
    }

    #[test]
    fn property_delayed_refs_seed_02_1000_cases() {
        run_delayed_ref_property(0xC001_D002, 1000);
    }

    #[test]
    fn property_transactions_seed_01_1000_cases() {
        run_transaction_property(0xD00D_1001, 1000);
    }

    #[test]
    fn integration_create_path_commits_inode_dir_and_extent_data() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut alloc = BtrfsExtentAllocator::new(1).expect("allocator");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x20_000));
        let extent = alloc.alloc_data(4096).expect("allocate data extent");
        alloc
            .flush_delayed_refs(usize::MAX)
            .expect("flush delayed refs");
        assert_eq!(
            alloc.extent_refcount(ExtentKey {
                bytenr: extent.bytenr,
                num_bytes: extent.num_bytes
            }),
            1
        );

        let mut txn = BtrfsTransaction::begin(&mut store, 1, &cx).expect("begin transaction");
        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x5000_0000,
                level: 1,
            },
        );
        txn.stage_block_write(BlockNumber(30_001), b"inode:256:size=11".to_vec())
            .expect("stage inode");
        txn.stage_block_write(BlockNumber(30_002), b"dir:/file.txt->256".to_vec())
            .expect("stage directory entry");
        txn.stage_block_write(BlockNumber(30_003), b"hello world".to_vec())
            .expect("stage file payload");
        txn.queue_delayed_ref(
            ExtentKey {
                bytenr: extent.bytenr,
                num_bytes: extent.num_bytes,
            },
            BtrfsRef::DataExtent {
                root: BTRFS_FS_TREE_OBJECTID,
                objectid: 256,
                offset: 0,
            },
            RefAction::Insert,
        );

        let seq = txn.commit(&mut store, &cx).expect("commit");
        assert_eq!(seq, CommitSeq(1));
        let snapshot = store.current_snapshot();
        assert_eq!(
            store
                .read_visible(BlockNumber(30_001), snapshot)
                .expect("inode visible"),
            b"inode:256:size=11".to_vec()
        );
        assert_eq!(
            store
                .read_visible(BlockNumber(30_002), snapshot)
                .expect("dir entry visible"),
            b"dir:/file.txt->256".to_vec()
        );
        assert_eq!(
            store
                .read_visible(BlockNumber(30_003), snapshot)
                .expect("payload visible"),
            b"hello world".to_vec()
        );
    }

    #[test]
    fn integration_delete_path_frees_extent_and_updates_directory() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut alloc = BtrfsExtentAllocator::new(2).expect("allocator");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x20_000));
        let extent = alloc.alloc_data(4096).expect("allocate data extent");
        alloc
            .flush_delayed_refs(usize::MAX)
            .expect("flush delayed refs");

        let mut create_tx = BtrfsTransaction::begin(&mut store, 2, &cx).expect("begin create");
        create_tx.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x5100_0000,
                level: 1,
            },
        );
        create_tx
            .stage_block_write(BlockNumber(31_001), b"dir:/tmp.bin->512".to_vec())
            .expect("stage dir entry");
        create_tx
            .stage_block_write(BlockNumber(31_002), b"inode:512:size=4096".to_vec())
            .expect("stage inode");
        create_tx.commit(&mut store, &cx).expect("commit create");

        alloc
            .free_extent(extent.bytenr, extent.num_bytes, false)
            .expect("free data extent");
        alloc
            .flush_delayed_refs(usize::MAX)
            .expect("flush delayed refs");
        assert_eq!(
            alloc.extent_refcount(ExtentKey {
                bytenr: extent.bytenr,
                num_bytes: extent.num_bytes
            }),
            0
        );

        let mut delete_tx = BtrfsTransaction::begin(&mut store, 3, &cx).expect("begin delete");
        delete_tx.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x5200_0000,
                level: 1,
            },
        );
        delete_tx
            .stage_block_write(BlockNumber(31_001), b"dir:/tmp.bin-><deleted>".to_vec())
            .expect("stage dir tombstone");
        delete_tx
            .stage_block_write(BlockNumber(31_002), b"inode:512:<deleted>".to_vec())
            .expect("stage inode tombstone");
        delete_tx.commit(&mut store, &cx).expect("commit delete");

        let snapshot = store.current_snapshot();
        assert_eq!(
            store
                .read_visible(BlockNumber(31_001), snapshot)
                .expect("dir tombstone visible")
                .as_ref(),
            b"dir:/tmp.bin-><deleted>"
        );
        assert_eq!(
            store
                .read_visible(BlockNumber(31_002), snapshot)
                .expect("inode tombstone visible")
                .as_ref(),
            b"inode:512:<deleted>"
        );
    }

    #[test]
    fn integration_overwrite_path_replaces_extent_and_payload_atomically() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut alloc = BtrfsExtentAllocator::new(4).expect("allocator");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x40_000));

        let old_extent = alloc.alloc_data(4096).expect("allocate old extent");
        alloc
            .flush_delayed_refs(usize::MAX)
            .expect("flush old extent delayed refs");

        let mut tx1 = BtrfsTransaction::begin(&mut store, 4, &cx).expect("begin tx1");
        tx1.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x5300_0000,
                level: 1,
            },
        );
        tx1.stage_block_write(BlockNumber(32_001), b"payload:old".to_vec())
            .expect("stage old payload");
        tx1.commit(&mut store, &cx).expect("commit tx1");

        let new_extent = alloc.alloc_data(4096).expect("allocate new extent");
        alloc
            .free_extent(old_extent.bytenr, old_extent.num_bytes, false)
            .expect("free old extent");
        alloc
            .flush_delayed_refs(usize::MAX)
            .expect("flush overwrite delayed refs");
        assert_eq!(
            alloc.extent_refcount(ExtentKey {
                bytenr: old_extent.bytenr,
                num_bytes: old_extent.num_bytes
            }),
            0
        );
        assert_eq!(
            alloc.extent_refcount(ExtentKey {
                bytenr: new_extent.bytenr,
                num_bytes: new_extent.num_bytes
            }),
            1
        );

        let mut tx2 = BtrfsTransaction::begin(&mut store, 5, &cx).expect("begin tx2");
        tx2.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x5400_0000,
                level: 1,
            },
        );
        tx2.stage_block_write(BlockNumber(32_001), b"payload:new".to_vec())
            .expect("stage new payload");
        tx2.commit(&mut store, &cx).expect("commit tx2");

        let snapshot = store.current_snapshot();
        assert_eq!(
            store
                .read_visible(BlockNumber(32_001), snapshot)
                .expect("new payload visible")
                .as_ref(),
            b"payload:new"
        );
    }

    #[test]
    fn integration_rename_path_moves_directory_entry_without_inode_rewrite() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();

        let mut tx1 = BtrfsTransaction::begin(&mut store, 6, &cx).expect("begin tx1");
        tx1.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x5500_0000,
                level: 1,
            },
        );
        tx1.stage_block_write(BlockNumber(33_001), b"dir:/old-name->900".to_vec())
            .expect("stage old dir entry");
        tx1.stage_block_write(BlockNumber(33_002), b"inode:900:size=128".to_vec())
            .expect("stage inode");
        tx1.commit(&mut store, &cx).expect("commit tx1");

        let mut tx2 = BtrfsTransaction::begin(&mut store, 7, &cx).expect("begin tx2");
        tx2.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x5600_0000,
                level: 1,
            },
        );
        tx2.stage_block_write(BlockNumber(33_001), b"dir:/old-name-><deleted>".to_vec())
            .expect("stage old dir tombstone");
        tx2.stage_block_write(BlockNumber(33_003), b"dir:/new-name->900".to_vec())
            .expect("stage new dir entry");
        tx2.commit(&mut store, &cx).expect("commit tx2");

        let snapshot = store.current_snapshot();
        assert_eq!(
            store
                .read_visible(BlockNumber(33_001), snapshot)
                .expect("old entry tombstone visible")
                .as_ref(),
            b"dir:/old-name-><deleted>"
        );
        assert_eq!(
            store
                .read_visible(BlockNumber(33_003), snapshot)
                .expect("new entry visible")
                .as_ref(),
            b"dir:/new-name->900"
        );
        assert_eq!(
            store
                .read_visible(BlockNumber(33_002), snapshot)
                .expect("inode still visible")
                .as_ref(),
            b"inode:900:size=128"
        );
    }

    #[test]
    fn parse_root_item_smoke() {
        let mut root = vec![0_u8; 239];
        root[176..184].copy_from_slice(&0x1234_0000_u64.to_le_bytes());
        root[238] = 0;
        let parsed = parse_root_item(&root).expect("parse root item");
        assert_eq!(parsed.bytenr, 0x1234_0000);
        assert_eq!(parsed.level, 0);
    }

    /// bd-xbqdw — Kernel-conformance pin for the btrfs_root_item field
    /// offsets per fs/btrfs/btrfs_tree.h. Each field is stamped with a
    /// UNIQUE magic value at its canonical kernel offset, then a single
    /// parse_root_item call must round-trip every field. A regression
    /// that drifted any single offset by ±1 byte would produce a
    /// distinct cross-field collision and fail this test, even though
    /// parse_root_item_smoke (which only checks bytenr+level) would
    /// still pass. The valid non-zero `level` exercises the u8 path;
    /// the all-distinct UUID byte patterns guard against UUID vs
    /// parent_uuid swap regressions.
    ///
    /// Pairs with bd-yb4r0 (ext4 dx_hash invariant pin), bd-bevt2
    /// (ext4 feature flags), bd-xt5ru (ext4 dx_hash version
    /// constants).
    #[test]
    fn parse_root_item_kernel_offsets_match_btrfs_tree_h() {
        // 279 bytes covers the full UUID-era root_item per kernel header.
        let mut root = vec![0_u8; 279];

        // Each field gets a distinct non-zero magic so an offset
        // drift produces a cross-field collision.
        let generation = 0x1111_1111_1111_1111_u64;
        let root_dirid = 0x2222_2222_2222_2222_u64;
        let bytenr = 0x3333_3333_3333_3333_u64;
        let flags = 0x4444_4444_4444_4444_u64;
        let refs: u32 = 0x5555_5555;
        let level: u8 = 4; // valid: <= BTRFS_MAX_TREE_LEVEL (8)
        let generation_v2 = generation; // extended fields valid only when matches
        let uuid = [0x77_u8; 16];
        let parent_uuid = [0x88_u8; 16];

        // Stamp at kernel offsets.
        root[160..168].copy_from_slice(&generation.to_le_bytes());
        root[168..176].copy_from_slice(&root_dirid.to_le_bytes());
        root[176..184].copy_from_slice(&bytenr.to_le_bytes());
        root[208..216].copy_from_slice(&flags.to_le_bytes());
        root[216..220].copy_from_slice(&refs.to_le_bytes());
        root[238] = level;
        root[239..247].copy_from_slice(&generation_v2.to_le_bytes());
        root[247..263].copy_from_slice(&uuid);
        root[263..279].copy_from_slice(&parent_uuid);

        let parsed = parse_root_item(&root).expect("kernel-stamped root_item must parse");

        assert_eq!(
            parsed.generation, generation,
            "generation must come from offset 160 per kernel layout"
        );
        assert_eq!(
            parsed.root_dirid, root_dirid,
            "root_dirid must come from offset 168 per kernel layout"
        );
        assert_eq!(
            parsed.bytenr, bytenr,
            "bytenr must come from offset 176 per kernel layout"
        );
        assert_eq!(
            parsed.flags, flags,
            "flags must come from offset 208 per kernel layout"
        );
        assert_eq!(
            parsed.refs,
            u64::from(refs),
            "refs must come from offset 216 (u32 zero-extended) per kernel layout"
        );
        assert_eq!(
            parsed.level, level,
            "level must come from offset 238 per kernel layout"
        );
        assert_eq!(
            parsed.uuid, uuid,
            "uuid must come from offset 247 per kernel layout (16 bytes)"
        );
        assert_eq!(
            parsed.parent_uuid, parent_uuid,
            "parent_uuid must come from offset 263 per kernel layout (16 bytes)"
        );

        // Negative MR: if generation_v2 disagrees with generation,
        // extended fields (uuid, parent_uuid) must be cleared per
        // the kernel's "stale-extension" rule.
        let mut stale = root.clone();
        stale[239..247].copy_from_slice(&(generation ^ 1).to_le_bytes());
        let parsed_stale = parse_root_item(&stale).expect("stale generation_v2 must still parse");
        assert_eq!(
            parsed_stale.uuid, [0_u8; 16],
            "stale generation_v2 must clear uuid"
        );
        assert_eq!(
            parsed_stale.parent_uuid, [0_u8; 16],
            "stale generation_v2 must clear parent_uuid"
        );
    }

    // bd-fs41s — Determinism MR for parse_root_item. Sister
    // parsers parse_xattr_items (bd-fhznm), parse_extent_data
    // (bd-3niu3), parse_inode_refs (bd-9f8ef), parse_root_ref
    // (bd-x2320) all have determinism proptests; parse_root_item
    // had only the smoke test and bd-xbqdw kernel-offset pin.
    //
    // Valid lengths per parse_root_item invariants (lib.rs:578-590):
    //   239               (legacy, no UUID extensions)
    //   247               (legacy + generation_v2 only)
    //   263               (… + uuid)
    //   279               (… + parent_uuid)
    // Lengths in (239, 247) ∪ (247, 263) ∪ (263, 279) are
    // partial-extension and the parser rejects them — sweep
    // only the canonical valid sizes.
    proptest::proptest! {
        #[test]
        fn parse_root_item_proptest_determinism(
            len in proptest::prop_oneof![
                proptest::prelude::Just(239_usize),
                proptest::prelude::Just(247_usize),
                proptest::prelude::Just(263_usize),
                proptest::prelude::Just(279_usize),
            ],
            bytenr in proptest::prelude::any::<u64>(),
        ) {
            let payload = make_root_item_payload(len, bytenr);
            let a = parse_root_item(&payload).expect("first parse");
            let b = parse_root_item(&payload).expect("second parse");
            proptest::prop_assert_eq!(a, b);
        }
    }

    #[test]
    fn root_item_to_bytes_roundtrip() {
        let item = BtrfsRootItem {
            bytenr: 0x1234_0000,
            level: 2,
            generation: 500,
            root_dirid: 256,
            flags: 0,
            refs: 1,
            uuid: [0x11; 16],
            parent_uuid: [0x22; 16],
        };
        let serialized = item.to_bytes();
        assert_eq!(serialized.len(), BTRFS_ROOT_ITEM_SIZE);
        let parsed = parse_root_item(&serialized).expect("roundtrip parse");
        assert_eq!(parsed.bytenr, item.bytenr);
        assert_eq!(parsed.level, item.level);
        assert_eq!(parsed.generation, item.generation);
        assert_eq!(parsed.root_dirid, item.root_dirid);
        assert_eq!(parsed.flags, item.flags);
        assert_eq!(parsed.refs, item.refs);
        assert_eq!(parsed.uuid, item.uuid);
        assert_eq!(parsed.parent_uuid, item.parent_uuid);
    }

    #[test]
    fn root_item_patch_root_commit_updates_fields() {
        let item = BtrfsRootItem {
            bytenr: 0x1000,
            level: 0,
            generation: 100,
            root_dirid: 256,
            flags: 0,
            refs: 1,
            uuid: [0; 16],
            parent_uuid: [0; 16],
        };
        let mut data = item.to_bytes();

        BtrfsRootItem::patch_root_commit(&mut data, 0x2000, 1, 200).expect("patch");
        let patched = parse_root_item(&data).expect("parse patched");
        assert_eq!(patched.bytenr, 0x2000);
        assert_eq!(patched.level, 1);
        assert_eq!(patched.generation, 200);
        assert_eq!(patched.root_dirid, 256);
    }

    #[test]
    fn root_item_patch_flags_updates_field() {
        let item = BtrfsRootItem {
            bytenr: 0x1000,
            level: 0,
            generation: 100,
            root_dirid: 256,
            flags: 0,
            refs: 1,
            uuid: [0; 16],
            parent_uuid: [0; 16],
        };
        let mut data = item.to_bytes();

        // Set RDONLY flag
        BtrfsRootItem::patch_flags(&mut data, BTRFS_ROOT_SUBVOL_RDONLY).expect("patch");
        let patched = parse_root_item(&data).expect("parse patched");
        assert_eq!(patched.flags, BTRFS_ROOT_SUBVOL_RDONLY);
        assert_eq!(patched.bytenr, 0x1000); // unchanged
        assert_eq!(patched.generation, 100); // unchanged

        // Clear RDONLY flag
        BtrfsRootItem::patch_flags(&mut data, 0).expect("patch");
        let cleared = parse_root_item(&data).expect("parse cleared");
        assert_eq!(cleared.flags, 0);
    }

    #[test]
    fn parse_inode_item_smoke() {
        let mut inode = [0_u8; 160];
        inode[16..24].copy_from_slice(&4096_u64.to_le_bytes());
        inode[24..32].copy_from_slice(&4096_u64.to_le_bytes());
        inode[40..44].copy_from_slice(&2_u32.to_le_bytes());
        inode[44..48].copy_from_slice(&1000_u32.to_le_bytes());
        inode[48..52].copy_from_slice(&1000_u32.to_le_bytes());
        inode[52..56].copy_from_slice(&0o040_755_u32.to_le_bytes());
        inode[112..120].copy_from_slice(&10_u64.to_le_bytes());
        inode[124..132].copy_from_slice(&11_u64.to_le_bytes());
        inode[136..144].copy_from_slice(&12_u64.to_le_bytes());
        inode[148..156].copy_from_slice(&13_u64.to_le_bytes());
        let parsed = parse_inode_item(&inode).expect("parse inode item");
        assert_eq!(parsed.size, 4096);
        assert_eq!(parsed.mode, 0o040_755);
        assert_eq!(parsed.nlink, 2);
        assert_eq!(parsed.mtime_sec, 12);
        assert_eq!(parsed.flags, 0, "flags default to 0 in smoke test");
    }

    #[test]
    fn parse_inode_item_with_flags() {
        use crate::{BTRFS_INODE_COMPRESS, BTRFS_INODE_NODATASUM};

        let mut inode = [0_u8; 160];
        // Set flags at offset 64
        let test_flags = BTRFS_INODE_NODATASUM | BTRFS_INODE_COMPRESS;
        inode[64..72].copy_from_slice(&test_flags.to_le_bytes());
        // Set mode to regular file
        inode[52..56].copy_from_slice(&0o100_644_u32.to_le_bytes());

        let parsed = parse_inode_item(&inode).expect("parse inode with flags");
        assert_eq!(parsed.flags, test_flags);
        assert!(parsed.flags & BTRFS_INODE_NODATASUM != 0);
        assert!(parsed.flags & BTRFS_INODE_COMPRESS != 0);
    }

    #[test]
    fn parse_dir_items_smoke() {
        let name = b"hello.txt";
        let mut data = vec![0_u8; 30 + name.len()];
        data[0..8].copy_from_slice(&257_u64.to_le_bytes());
        data[8] = BTRFS_ITEM_INODE_ITEM;
        data[17..25].copy_from_slice(&1_u64.to_le_bytes()); // transid
        data[25..27].copy_from_slice(&0_u16.to_le_bytes()); // data_len
        let name_len = u16::try_from(name.len()).expect("test name length should fit u16");
        data[27..29].copy_from_slice(&name_len.to_le_bytes());
        data[29] = BTRFS_FT_REG_FILE;
        data[30..30 + name.len()].copy_from_slice(name);

        let parsed = parse_dir_items(&data).expect("parse dir items");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].child_objectid, 257);
        assert_eq!(parsed[0].file_type, BTRFS_FT_REG_FILE);
        assert_eq!(parsed[0].name, name);
    }

    // bd-qwo4a — Kernel-conformance pin for parse_dir_items.
    //
    // struct btrfs_dir_item in fs/btrfs/btrfs_tree.h packs to:
    //   location.objectid u64 @0..8
    //   location.type      u8 @8
    //   location.offset    u64 @9..17
    //   transid            u64 @17..25 (discarded by parser)
    //   data_len           u16 @25..27 (must be 0 for entries)
    //   name_len           u16 @27..29 (must be non-zero)
    //   type               u8 @29
    // Total fixed header: 30 bytes; name bytes at @30..30+name_len.
    //
    // Stamp each addressable field with a unique non-zero magic
    // so any single-field offset drift produces a cross-field
    // collision. data_len stays 0 (invariant); transid carries a
    // magic that would FAIL the data_len==0 check if data_len
    // were misaligned to offset 17 — i.e. the test's success
    // pins data_len at offset 25 too.
    #[test]
    fn parse_dir_items_kernel_offsets_match_btrfs_tree_h() {
        let name = b"\x99\x99\x99\x99"; // 4-byte distinct magic for name bytes
        let mut data = vec![0_u8; 30 + name.len()];

        let objectid = 0x1111_1111_1111_1111_u64;
        let key_type: u8 = 0xAB;
        let key_offset = 0x3333_3333_3333_3333_u64;
        let transid_magic = 0x4444_4444_4444_4444_u64;
        let data_len: u16 = 0;
        let name_len = u16::try_from(name.len()).expect("test name length fits u16");
        let file_type: u8 = 0x77;

        data[0..8].copy_from_slice(&objectid.to_le_bytes());
        data[8] = key_type;
        data[9..17].copy_from_slice(&key_offset.to_le_bytes());
        data[17..25].copy_from_slice(&transid_magic.to_le_bytes());
        data[25..27].copy_from_slice(&data_len.to_le_bytes());
        data[27..29].copy_from_slice(&name_len.to_le_bytes());
        data[29] = file_type;
        data[30..30 + name.len()].copy_from_slice(name);

        let parsed = parse_dir_items(&data).expect("kernel-stamped dir_item must parse");
        assert_eq!(
            parsed.len(),
            1,
            "single-entry payload must parse to one item"
        );

        assert_eq!(
            parsed[0].child_objectid, objectid,
            "child_objectid must come from offset 0..8 per kernel layout"
        );
        assert_eq!(
            parsed[0].child_key_type, key_type,
            "child_key_type must come from offset 8 per kernel layout"
        );
        assert_eq!(
            parsed[0].child_key_offset, key_offset,
            "child_key_offset must come from offset 9..17 per kernel layout"
        );
        assert_eq!(
            parsed[0].file_type, file_type,
            "file_type must come from offset 29 per kernel layout"
        );
        assert_eq!(
            parsed[0].name, name,
            "name bytes must start at offset 30 with length name_len@27..29"
        );

        // Cross-check: a misalignment that read data_len from
        // offset 17 (where transid lives) would see 0x4444 and
        // reject with InvalidField{data_len}. The successful
        // parse above proves data_len is read from offset 25.
        // Make this explicit by mutating data_len@25 to a non-
        // zero magic and asserting the parser rejects.
        let mut bad = data.clone();
        bad[25..27].copy_from_slice(&0x5555_u16.to_le_bytes());
        let err = parse_dir_items(&bad).expect_err("non-zero data_len must reject");
        assert!(
            matches!(err, ParseError::InvalidField { field, .. } if field == "dir_item.data_len"),
            "expected InvalidField{{data_len}}, got {err:?}"
        );
    }

    #[test]
    fn parse_extent_data_regular_smoke() {
        let mut data = [0_u8; 53];
        data[20] = BTRFS_FILE_EXTENT_REG;
        data[21..29].copy_from_slice(&0x8_000_u64.to_le_bytes());
        data[29..37].copy_from_slice(&4096_u64.to_le_bytes());
        data[45..53].copy_from_slice(&128_u64.to_le_bytes());

        let parsed = parse_extent_data(&data).expect("parse extent");
        assert!(
            matches!(parsed, BtrfsExtentData::Regular { .. }),
            "expected regular extent"
        );
        if let BtrfsExtentData::Regular {
            generation,
            extent_type,
            compression,
            disk_bytenr,
            num_bytes,
            ..
        } = parsed
        {
            assert_eq!(generation, 0);
            assert_eq!(extent_type, BTRFS_FILE_EXTENT_REG);
            assert_eq!(compression, 0);
            assert_eq!(disk_bytenr, 0x8_000);
            assert_eq!(num_bytes, 128);
        }
    }

    fn make_root_item_payload(len: usize, bytenr: u64) -> Vec<u8> {
        assert!(
            len >= 239,
            "root item test payload must include fixed fields"
        );

        let mut payload = vec![0_u8; len];
        payload[160..168].copy_from_slice(&7_u64.to_le_bytes());
        payload[168..176].copy_from_slice(&256_u64.to_le_bytes());
        payload[176..184].copy_from_slice(&bytenr.to_le_bytes());
        payload[208..216].copy_from_slice(&1_u64.to_le_bytes());
        payload[216..220].copy_from_slice(&3_u32.to_le_bytes());
        payload[238] = 2;
        if len >= 247 {
            payload[239..247].copy_from_slice(&7_u64.to_le_bytes());
        }
        if len >= 263 {
            payload[247..263].copy_from_slice(&[0x11; 16]);
        }
        if len >= 279 {
            payload[263..279].copy_from_slice(&[0x22; 16]);
        }
        payload
    }

    fn make_xattr_payload(name: &[u8], value: &[u8]) -> Vec<u8> {
        let name_len = u16::try_from(name.len()).expect("test xattr name length fits u16");
        let value_len = u16::try_from(value.len()).expect("test xattr value length fits u16");

        let mut payload = Vec::with_capacity(30 + name.len() + value.len());
        payload.extend_from_slice(&[0_u8; 17]);
        payload.extend_from_slice(&[0_u8; 8]);
        payload.extend_from_slice(&value_len.to_le_bytes());
        payload.extend_from_slice(&name_len.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(name);
        payload.extend_from_slice(value);
        payload
    }

    fn assert_insufficient_data<T: std::fmt::Debug>(
        result: Result<T, ParseError>,
        needed: usize,
        offset: usize,
        actual: usize,
    ) {
        let err = result.expect_err("expected insufficient data error");
        if let ParseError::InsufficientData {
            needed: got_needed,
            offset: got_offset,
            actual: got_actual,
        } = err
        {
            assert_eq!(got_needed, needed);
            assert_eq!(got_offset, offset);
            assert_eq!(got_actual, actual);
        } else {
            assert!(
                matches!(err, ParseError::InsufficientData { .. }),
                "expected insufficient data error, got {err:?}"
            );
        }
    }

    fn assert_invalid_field<T: std::fmt::Debug>(
        result: Result<T, ParseError>,
        field: &'static str,
        reason: &'static str,
    ) {
        let err = result.expect_err("expected invalid field error");
        if let ParseError::InvalidField {
            field: got_field,
            reason: got_reason,
        } = err
        {
            assert_eq!(got_field, field);
            assert_eq!(got_reason, reason);
        } else {
            assert!(
                matches!(err, ParseError::InvalidField { .. }),
                "expected invalid field error, got {err:?}"
            );
        }
    }

    fn assert_root_item_adversarial_boundaries() {
        let valid_min = make_root_item_payload(239, 0x1234_0000);
        let parsed = parse_root_item(&valid_min).expect("parse minimal root item");
        assert_eq!(parsed.bytenr, 0x1234_0000);
        assert_eq!(parsed.generation, 7);
        assert_eq!(parsed.root_dirid, 256);
        assert_eq!(parsed.level, 2);

        let valid_generation_v2_only = make_root_item_payload(247, 0x2345_0000);
        let parsed =
            parse_root_item(&valid_generation_v2_only).expect("parse generation_v2-only root item");
        assert_eq!(parsed.bytenr, 0x2345_0000);
        assert_eq!(parsed.uuid, [0; 16]);
        assert_eq!(parsed.parent_uuid, [0; 16]);

        let valid_uuid_only = make_root_item_payload(263, 0x3456_0000);
        let parsed = parse_root_item(&valid_uuid_only).expect("parse uuid-only root item");
        assert_eq!(parsed.bytenr, 0x3456_0000);
        assert_eq!(parsed.uuid[0], 0x11);
        assert_eq!(parsed.parent_uuid, [0; 16]);

        let valid_uuid = make_root_item_payload(279, 0x5678_0000);
        let parsed = parse_root_item(&valid_uuid).expect("parse root item with uuids");
        assert_eq!(parsed.bytenr, 0x5678_0000);
        assert_eq!(parsed.uuid[0], 0x11);
        assert_eq!(parsed.parent_uuid[0], 0x22);
        assert_eq!(parsed.level, 2);

        let mut stale_uuid = valid_uuid;
        stale_uuid[239..247].copy_from_slice(&6_u64.to_le_bytes());
        let parsed = parse_root_item(&stale_uuid).expect("parse stale-uuid root item");
        assert_eq!(parsed.uuid, [0; 16]);
        assert_eq!(parsed.parent_uuid, [0; 16]);

        assert_insufficient_data(parse_root_item(&[0_u8; 238]), 239, 0, 238);
        let partial_generation_v2 = make_root_item_payload(240, 0x1234_0000);
        assert_invalid_field(
            parse_root_item(&partial_generation_v2),
            "root_item.generation_v2",
            "partial extension field",
        );
        let partial_uuid = make_root_item_payload(248, 0x1234_0000);
        assert_invalid_field(
            parse_root_item(&partial_uuid),
            "root_item.uuid",
            "partial extension field",
        );
        let partial_parent_uuid = make_root_item_payload(264, 0x1234_0000);
        assert_invalid_field(
            parse_root_item(&partial_parent_uuid),
            "root_item.parent_uuid",
            "partial extension field",
        );

        let zero_bytenr = make_root_item_payload(239, 0);
        assert_invalid_field(
            parse_root_item(&zero_bytenr),
            "root_item.bytenr",
            "must be non-zero",
        );

        let mut bad_level = make_root_item_payload(239, 0x1234_0000);
        bad_level[238] = BTRFS_MAX_TREE_LEVEL + 1;
        assert_invalid_field(
            parse_root_item(&bad_level),
            "root_item.level",
            "exceeds maximum btrfs tree level",
        );
    }

    fn assert_inode_item_adversarial_boundaries() {
        let original = BtrfsInodeItem {
            generation: u64::MAX,
            size: u64::MAX,
            nbytes: u64::MAX,
            nlink: u32::MAX,
            uid: u32::MAX,
            gid: u32::MAX,
            mode: u32::MAX,
            rdev: u64::MAX,
            flags: u64::MAX,
            atime_sec: u64::MAX,
            atime_nsec: 999_999_999,
            ctime_sec: u64::MAX,
            ctime_nsec: 999_999_999,
            mtime_sec: u64::MAX,
            mtime_nsec: 999_999_999,
            otime_sec: u64::MAX,
            otime_nsec: 999_999_999,
        };
        let bytes = original.to_bytes();
        assert_eq!(
            parse_inode_item(&bytes).expect("parse max inode item"),
            original
        );
        assert_insufficient_data(parse_inode_item(&bytes[..159]), 160, 0, 159);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_invalid_field(
            parse_inode_item(&trailing),
            "inode_item.size",
            "does not match fixed inode item size",
        );

        for (offset, field) in [
            (120, "inode_item.atime_nsec"),
            (132, "inode_item.ctime_nsec"),
            (144, "inode_item.mtime_nsec"),
            (156, "inode_item.otime_nsec"),
        ] {
            let mut invalid_nsec = bytes.clone();
            invalid_nsec[offset..offset + 4].copy_from_slice(&1_000_000_000_u32.to_le_bytes());
            assert_invalid_field(
                parse_inode_item(&invalid_nsec),
                field,
                "must be less than 1_000_000_000",
            );
        }
    }

    fn assert_dir_item_adversarial_boundaries() {
        let first = BtrfsDirItem {
            child_objectid: 258,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: BTRFS_FT_REG_FILE,
            name: b"file-a".to_vec(),
        };
        let mut second = BtrfsDirItem {
            child_objectid: 259,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: 0xff,
            name: b"unknown-type".to_vec(),
        };
        let mut payload = first.to_bytes();
        payload.extend_from_slice(&second.to_bytes());

        let parsed = parse_dir_items(&payload).expect("parse multi-entry dir payload");
        assert_eq!(parsed, [first, second.clone()]);
        assert!(
            parse_dir_items(&[])
                .expect("parse empty dir payload")
                .is_empty()
        );

        assert_insufficient_data(parse_dir_items(&[0_u8; 29]), 30, 0, 29);

        let empty_name = vec![0_u8; 30];
        assert_invalid_field(
            parse_dir_items(&empty_name),
            "dir_item.name_len",
            "must be non-zero",
        );

        let mut name_overflow = vec![0_u8; 30];
        name_overflow[27..29].copy_from_slice(&5_u16.to_le_bytes());
        assert_insufficient_data(parse_dir_items(&name_overflow), 35, 0, 30);

        second.name = b"n".to_vec();
        let mut nonzero_data_len = second.to_bytes();
        nonzero_data_len[25..27].copy_from_slice(&4_u16.to_le_bytes());
        nonzero_data_len.extend_from_slice(b"data");
        assert_invalid_field(
            parse_dir_items(&nonzero_data_len),
            "dir_item.data_len",
            "must be zero for directory entries",
        );
    }

    fn assert_xattr_item_adversarial_boundaries() {
        let mut payload = make_xattr_payload(b"user.a", b"alpha");
        payload.extend_from_slice(&make_xattr_payload(b"user.b", b""));
        let parsed = parse_xattr_items(&payload).expect("parse multi-entry xattr payload");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, b"user.a");
        assert_eq!(parsed[0].value, b"alpha");
        assert_eq!(parsed[1].name, b"user.b");
        assert!(parsed[1].value.is_empty());
        assert!(
            parse_xattr_items(&[])
                .expect("parse empty xattr payload")
                .is_empty()
        );

        assert_insufficient_data(parse_xattr_items(&[0_u8; 29]), 30, 0, 29);

        let empty_name = vec![0_u8; 30];
        assert_invalid_field(
            parse_xattr_items(&empty_name),
            "xattr.name_len",
            "must be non-zero",
        );

        let mut name_overflow = vec![0_u8; 30];
        name_overflow[27..29].copy_from_slice(&5_u16.to_le_bytes());
        assert_insufficient_data(parse_xattr_items(&name_overflow), 35, 0, 30);

        let mut value_overflow = make_xattr_payload(b"n", b"");
        value_overflow[25..27].copy_from_slice(&4_u16.to_le_bytes());
        assert_insufficient_data(parse_xattr_items(&value_overflow), 35, 0, 31);
    }

    #[allow(clippy::too_many_lines)]
    fn assert_extent_data_adversarial_boundaries() {
        let inline = BtrfsExtentData::Inline {
            generation: 9,
            ram_bytes: 3,
            compression: 0,
            data: b"abc".to_vec(),
        };
        assert_eq!(
            parse_extent_data(&inline.to_bytes()).expect("parse inline extent"),
            inline
        );

        let prealloc = BtrfsExtentData::Regular {
            generation: 10,
            ram_bytes: 8192,
            extent_type: BTRFS_FILE_EXTENT_PREALLOC,
            compression: 0,
            disk_bytenr: 0x80_000,
            disk_num_bytes: 8192,
            extent_offset: 0,
            num_bytes: 4096,
        };
        assert_eq!(
            parse_extent_data(&prealloc.to_bytes()).expect("parse prealloc extent"),
            prealloc
        );

        assert_insufficient_data(parse_extent_data(&[0_u8; 20]), 21, 0, 20);

        let mut truncated_regular = vec![0_u8; 52];
        truncated_regular[20] = BTRFS_FILE_EXTENT_REG;
        assert_insufficient_data(parse_extent_data(&truncated_regular), 53, 0, 52);

        let mut trailing_regular = prealloc.to_bytes();
        trailing_regular.push(0);
        assert_invalid_field(
            parse_extent_data(&trailing_regular),
            "extent_data.length",
            "trailing bytes after fixed extent payload",
        );

        let mut unsupported_compression = inline.to_bytes();
        unsupported_compression[16] = 0xff;
        assert_invalid_field(
            parse_extent_data(&unsupported_compression),
            "extent_data.compression",
            "unsupported compression",
        );

        let mut encrypted_inline = inline.to_bytes();
        encrypted_inline[17] = 1;
        assert_invalid_field(
            parse_extent_data(&encrypted_inline),
            "extent_data.encryption",
            "unsupported encryption",
        );

        let mut other_encoded_regular = prealloc.to_bytes();
        other_encoded_regular[18..20].copy_from_slice(&1_u16.to_le_bytes());
        assert_invalid_field(
            parse_extent_data(&other_encoded_regular),
            "extent_data.other_encoding",
            "unsupported other encoding",
        );

        let mut unknown_type = vec![0_u8; 21];
        unknown_type[20] = 0xff;
        assert_invalid_field(
            parse_extent_data(&unknown_type),
            "extent_data.type",
            "unsupported extent type",
        );

        // Compressed extent source slice arithmetic: extent_offset + num_bytes overflow.
        let overflow_extent = BtrfsExtentData::Regular {
            generation: 1,
            ram_bytes: 4096,
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: BTRFS_COMPRESS_ZSTD,
            disk_bytenr: 0x100_000,
            disk_num_bytes: 2048,
            extent_offset: u64::MAX - 100,
            num_bytes: 200,
        };
        assert_invalid_field(
            parse_extent_data(&overflow_extent.to_bytes()),
            "extent_data.extent_offset+num_bytes",
            "source slice arithmetic overflow",
        );

        // Compressed extent source slice: extent_offset + num_bytes > ram_bytes.
        let exceeds_ram_bytes = BtrfsExtentData::Regular {
            generation: 1,
            ram_bytes: 4096,
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: BTRFS_COMPRESS_ZLIB,
            disk_bytenr: 0x100_000,
            disk_num_bytes: 2048,
            extent_offset: 4000,
            num_bytes: 200,
        };
        assert_invalid_field(
            parse_extent_data(&exceeds_ram_bytes.to_bytes()),
            "extent_data.extent_offset+num_bytes",
            "source slice exceeds ram_bytes",
        );

        // Valid compressed extent: extent_offset + num_bytes == ram_bytes.
        let valid_compressed = BtrfsExtentData::Regular {
            generation: 1,
            ram_bytes: 4096,
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: BTRFS_COMPRESS_LZO,
            disk_bytenr: 0x100_000,
            disk_num_bytes: 2048,
            extent_offset: 1024,
            num_bytes: 3072,
        };
        assert_eq!(
            parse_extent_data(&valid_compressed.to_bytes()).expect("parse valid compressed"),
            valid_compressed
        );

        // Uncompressed extents must stay within their declared on-disk extent.
        let out_of_range_disk_extent = BtrfsExtentData::Regular {
            generation: 1,
            ram_bytes: 8192,
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: BTRFS_COMPRESS_NONE,
            disk_bytenr: 0x100_000,
            disk_num_bytes: 4096,
            extent_offset: 4096,
            num_bytes: 4096,
        };
        assert_invalid_field(
            parse_extent_data(&out_of_range_disk_extent.to_bytes()),
            "extent_data.extent_offset+num_bytes",
            "source slice exceeds disk_num_bytes",
        );

        // Uncompressed extent with disk_bytenr=0 (hole): validation is skipped.
        let hole_extent = BtrfsExtentData::Regular {
            generation: 1,
            ram_bytes: 0,
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: BTRFS_COMPRESS_NONE,
            disk_bytenr: 0,
            disk_num_bytes: 0,
            extent_offset: 0,
            num_bytes: 0,
        };
        assert_eq!(
            parse_extent_data(&hole_extent.to_bytes()).expect("parse hole extent"),
            hole_extent
        );
    }

    // bd-yjzhk — Canonical byte-layout snapshot for
    // BtrfsExtentData::to_bytes Regular variant. Pins the
    // encoder's exact output for a known fixture so any field-
    // order or offset drift fails with a hex diff (rather than
    // a silent round-trip with a similarly-broken parser, or a
    // bench that ticks the same nanosecond cost). Pairs with
    // bd-3niu3 (proptest round-trip MR), bd-zuqtr (Criterion
    // bench), bd-2gb89 (BtrfsDirItem canonical bytes).
    #[test]
    fn extent_data_regular_to_bytes_canonical_byte_layout() {
        let extent = BtrfsExtentData::Regular {
            generation: 0x1122_3344_5566_7788,
            ram_bytes: 0x0010_0000, // 1 MiB
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: BTRFS_COMPRESS_NONE,
            disk_bytenr: 0xDEAD_BEEF_CAFE_BABE,
            disk_num_bytes: 0x1234_5678_9ABC_DEF0,
            extent_offset: 0,
            num_bytes: 0x0010_0000,
        };
        let bytes = extent.to_bytes();

        // Source-slice validator passes: extent_offset (0) +
        // num_bytes (0x100000) = 0x100000 ≤ disk_num_bytes
        // (0x1234567890ABCDEF0). Confirm by parsing back.
        let parsed = parse_extent_data(&bytes).expect("canonical bytes parse");
        assert_eq!(parsed, extent, "canonical bytes must round-trip");

        // 53 fixed bytes — kernel-conformant struct btrfs_file_extent_item
        // header (21) + Regular tail (32). No name/inline data
        // bytes follow (Regular extents have no trailing payload).
        let expected: [u8; 53] = [
            // generation LE @0..8 = 0x1122_3344_5566_7788
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
            // ram_bytes LE @8..16 = 0x0010_0000
            0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            // compression @16 = BTRFS_COMPRESS_NONE = 0
            0x00, // encryption @17 = 0 (always; encoder hard-codes)
            0x00, // other_encoding LE @18..20 = 0 (always)
            0x00, 0x00, // extent_type @20 = BTRFS_FILE_EXTENT_REG = 1
            0x01, // disk_bytenr LE @21..29 = 0xDEAD_BEEF_CAFE_BABE
            0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE,
            // disk_num_bytes LE @29..37 = 0x1234_5678_9ABC_DEF0
            0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
            // extent_offset LE @37..45 = 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // num_bytes LE @45..53 = 0x0010_0000
            0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            bytes, expected,
            "BtrfsExtentData::to_bytes Regular canonical byte layout drifted"
        );
    }

    /// bd-swwp0 — Kernel-conformance pin for the btrfs_file_extent_item
    /// field offsets per fs/btrfs/btrfs_tree.h (struct
    /// btrfs_file_extent_item, 53 bytes for non-inline). Each field is
    /// stamped with a UNIQUE non-zero magic at its canonical kernel
    /// offset, then a single parse_extent_data call must round-trip
    /// every field. A regression that drifted any single offset by ±4
    /// bytes (one field-width) would mis-route disk_bytenr↔disk_num_bytes
    /// or extent_offset↔num_bytes silently. extent_data_regular_to_bytes_canonical_byte_layout
    /// (bd-yjzhk) pins encoder output for a single fixture; this is the
    /// parser-side companion pinning input layout directly to the
    /// kernel header for a fixture with all fields distinct.
    ///
    /// Pairs with bd-yjzhk (Regular canonical bytes), bd-fw55q (Inline
    /// canonical bytes), bd-3niu3 (proptest round-trip MR).
    #[test]
    fn parse_extent_data_kernel_offsets_match_btrfs_tree_h() {
        // Distinct non-zero magics so an offset drift produces a
        // cross-field collision. Constraint: the source-slice
        // validator requires extent_offset + num_bytes ≤ disk_num_bytes
        // when compression = NONE && disk_bytenr != 0. We stamp
        // disk_num_bytes with a maximal magic (0xFFFF_…) so any
        // plausible (extent_offset, num_bytes) pair satisfies it.
        let generation = 0x1111_1111_1111_1111_u64;
        let ram_bytes = 0x2222_2222_2222_2222_u64;
        // compression @16 = 0 (NONE; one of {0,1,2,3} required)
        // encryption  @17 = 0 (parser rejects non-zero)
        // other_enc   @18..20 = 0 (parser rejects non-zero)
        // type        @20 = REG (1); 0/2 also valid but we exercise
        //                  the Regular branch which has the most fields.
        let disk_bytenr = 0x4444_4444_4444_4444_u64;
        let disk_num_bytes = 0xFFFF_FFFF_FFFF_FFFE_u64;
        let extent_offset = 0x0000_0000_0001_0000_u64;
        let num_bytes = 0x0000_0000_0002_0000_u64;

        let mut data = vec![0_u8; 53];
        data[0..8].copy_from_slice(&generation.to_le_bytes());
        data[8..16].copy_from_slice(&ram_bytes.to_le_bytes());
        // compression already 0
        // encryption already 0
        // other_encoding already 0
        data[20] = BTRFS_FILE_EXTENT_REG;
        data[21..29].copy_from_slice(&disk_bytenr.to_le_bytes());
        data[29..37].copy_from_slice(&disk_num_bytes.to_le_bytes());
        data[37..45].copy_from_slice(&extent_offset.to_le_bytes());
        data[45..53].copy_from_slice(&num_bytes.to_le_bytes());

        let parsed = parse_extent_data(&data).expect("kernel-stamped extent_data must parse");

        assert!(
            matches!(parsed, BtrfsExtentData::Regular { .. }),
            "expected Regular variant, got {parsed:?}"
        );
        if let BtrfsExtentData::Regular {
            generation: g,
            ram_bytes: rb,
            extent_type,
            compression,
            disk_bytenr: db,
            disk_num_bytes: dnb,
            extent_offset: eo,
            num_bytes: nb,
        } = parsed
        {
            assert_eq!(g, generation, "generation @ offset 0..8");
            assert_eq!(rb, ram_bytes, "ram_bytes @ offset 8..16");
            assert_eq!(compression, BTRFS_COMPRESS_NONE, "compression @ offset 16");
            assert_eq!(extent_type, BTRFS_FILE_EXTENT_REG, "type @ offset 20");
            assert_eq!(db, disk_bytenr, "disk_bytenr @ offset 21..29");
            assert_eq!(dnb, disk_num_bytes, "disk_num_bytes @ offset 29..37");
            assert_eq!(eo, extent_offset, "extent_offset @ offset 37..45");
            assert_eq!(nb, num_bytes, "num_bytes @ offset 45..53");
        }
    }

    // bd-fw55q — Canonical byte-layout snapshot for
    // BtrfsExtentData::to_bytes Inline variant. The Inline branch
    // is a separate encoder code path from Regular (lib.rs:486-503)
    // with its own offset arithmetic — bd-yjzhk pinned Regular but
    // an offset drift in the Inline branch would not surface.
    // Pairs with bd-yjzhk (Regular canonical bytes), bd-3niu3
    // (proptest round-trip MR for both variants).
    #[test]
    fn extent_data_inline_to_bytes_canonical_byte_layout() {
        let inline_data = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let extent = BtrfsExtentData::Inline {
            generation: 0xCAFE_BABE_DEAD_BEEF,
            ram_bytes: 8, // NONE compression: must equal data.len()
            compression: BTRFS_COMPRESS_NONE,
            data: inline_data,
        };
        let bytes = extent.to_bytes();
        assert_eq!(
            bytes.len(),
            21 + 8,
            "Inline encoding is 21-byte header + data bytes"
        );

        // Round-trip through parser is a redundant cross-check against
        // bd-yjzhk's parsing layer; cheap and explicit here.
        let parsed = parse_extent_data(&bytes).expect("inline canonical bytes parse");
        assert_eq!(parsed, extent);

        // 21 fixed bytes + 8 inline data bytes = 29 total.
        let expected: [u8; 29] = [
            // generation LE @0..8 = 0xCAFE_BABE_DEAD_BEEF
            0xEF, 0xBE, 0xAD, 0xDE, 0xBE, 0xBA, 0xFE, 0xCA, // ram_bytes LE @8..16 = 8
            0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // compression @16 = BTRFS_COMPRESS_NONE = 0
            0x00, // encryption @17 = 0 (always; encoder hard-codes)
            0x00, // other_encoding LE @18..20 = 0 (always)
            0x00, 0x00, // extent_type @20 = BTRFS_FILE_EXTENT_INLINE = 0
            0x00, // inline data @21..29 = 0x11..0x88
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        assert_eq!(
            bytes, expected,
            "BtrfsExtentData::to_bytes Inline canonical byte layout drifted"
        );
    }

    /// bd-yy6f5 — Canonical byte-layout snapshot for
    /// BtrfsBlockGroupItem::to_bytes. Pins the encoder's exact 24-byte
    /// output for a magic-stamped fixture so any field-order or offset
    /// drift fails with a hex diff.
    ///
    /// Layout matches the kernel struct btrfs_block_group_item per
    /// fs/btrfs/btrfs_tree.h ONLY for `used`@0..8 and `flags`@16..24.
    /// The middle 8 bytes (kernel: `chunk_objectid` u64@8..16) are
    /// **deliberately** repurposed by our encoder to store
    /// `total_bytes` instead. The kernel conveys total_bytes via
    /// BTRFS_BLOCK_GROUP_ITEM_KEY.offset, but we don't surface that
    /// key path on the ffs side, so we co-locate `total_bytes` in the
    /// `chunk_objectid` slot. This canonical-bytes test pins that
    /// divergence so any encoder regression that wrote total_bytes to
    /// a different slot OR wrote the kernel's chunk_objectid value
    /// (instead of total_bytes) gets caught with a hex diff. Pairs
    /// with bd-7dhr1 (BtrfsExtentItem 24-byte canonical) and completes
    /// ffs-btrfs encoder canonical-bytes coverage.
    #[test]
    fn block_group_item_to_bytes_canonical_byte_layout() {
        let item = BtrfsBlockGroupItem {
            used_bytes: 0x1122_3344_5566_7788,
            total_bytes: 0x99AA_BBCC_DDEE_FF00,
            flags: 0xCAFE_BABE_DEAD_BEEF,
        };
        let bytes = item.to_bytes();
        assert_eq!(bytes.len(), 24, "btrfs_block_group_item is 24 bytes");

        let expected: [u8; 24] = [
            // used_bytes LE @0..8 = 0x1122_3344_5566_7788
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
            // total_bytes LE @8..16 = 0x99AA_BBCC_DDEE_FF00
            // Kernel slot is `chunk_objectid`; we deliberately store
            // total_bytes here (see encoder doc comment).
            0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99,
            // flags LE @16..24 = 0xCAFE_BABE_DEAD_BEEF
            0xEF, 0xBE, 0xAD, 0xDE, 0xBE, 0xBA, 0xFE, 0xCA,
        ];
        assert_eq!(
            bytes, expected,
            "BtrfsBlockGroupItem::to_bytes canonical byte layout drifted"
        );
    }

    /// bd-7dhr1 — Canonical byte-layout snapshot for
    /// BtrfsExtentItem::to_bytes. Pins the encoder's exact 24-byte
    /// output for a magic-stamped fixture so any field-order or offset
    /// drift fails with a hex diff. Layout matches struct
    /// btrfs_extent_item per fs/btrfs/btrfs_tree.h: refs u64@0..8,
    /// generation u64@8..16, flags u64@16..24. EXTENT_ITEM is written
    /// on every extent allocation; a regression that drifted
    /// refs↔generation or generation↔flags would silently corrupt
    /// every extent record. Pairs with bd-yjzhk (extent_data Regular
    /// canonical bytes), bd-fw55q (extent_data Inline canonical bytes).
    #[test]
    fn extent_item_to_bytes_canonical_byte_layout() {
        let item = BtrfsExtentItem {
            refs: 0x1122_3344_5566_7788,
            generation: 0x99AA_BBCC_DDEE_FF00,
            flags: 0xCAFE_BABE_DEAD_BEEF,
        };
        let bytes = item.to_bytes();
        assert_eq!(bytes.len(), 24, "btrfs_extent_item is 24 bytes");

        let expected: [u8; 24] = [
            // refs LE @0..8 = 0x1122_3344_5566_7788
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
            // generation LE @8..16 = 0x99AA_BBCC_DDEE_FF00
            0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99,
            // flags LE @16..24 = 0xCAFE_BABE_DEAD_BEEF
            0xEF, 0xBE, 0xAD, 0xDE, 0xBE, 0xBA, 0xFE, 0xCA,
        ];
        assert_eq!(
            bytes, expected,
            "BtrfsExtentItem::to_bytes canonical byte layout drifted"
        );
    }

    // bd-3niu3 — Property-based round-trip MR for parse_extent_data.
    //
    // BtrfsExtentData::to_bytes (lib.rs:486) and parse_extent_data
    // (lib.rs:1085) handle struct btrfs_file_extent_item from
    // fs/btrfs/btrfs_tree.h with two payload shapes:
    //   Inline:  generation u64@0 + ram_bytes u64@8 + compression u8@16
    //            + encryption u8@17 + other_encoding u16@18 + type u8@20
    //            + inline data@21..
    //   Regular: above fixed 21-byte header, then disk_bytenr u64@21
    //            + disk_num_bytes u64@29 + extent_offset u64@37
    //            + num_bytes u64@45 (53 bytes total, exact-length
    //            contract — no trailing bytes).
    //
    // Existing tests cover hand-crafted single fixtures and the
    // fuzz target at fuzz_btrfs_tree_items.rs:875 exercises encode →
    // parse, but the unit-test suite has no proptest sweep — a
    // regression in any field's offset arithmetic in either
    // direction would surface only under cargo-fuzz workflows.
    // Sweep arbitrary u64s through the simple cases (sparse holes
    // for Regular, valid uncompressed inline for Inline) plus a
    // valid-uncompressed-Regular case where source-slice arithmetic
    // is exercised, asserting encode → parse equality.
    proptest::proptest! {
        // MR-1: sparse-hole Regular round-trip. compression=NONE,
        // disk_bytenr=0 bypasses the source-slice validator so all
        // four address fields can vary freely.
        #[test]
        fn proptest_extent_data_regular_sparse_round_trip(
            generation in proptest::prelude::any::<u64>(),
            ram_bytes in proptest::prelude::any::<u64>(),
            extent_type in proptest::prop_oneof![
                proptest::prelude::Just(BTRFS_FILE_EXTENT_REG),
                proptest::prelude::Just(BTRFS_FILE_EXTENT_PREALLOC),
            ],
            disk_num_bytes in proptest::prelude::any::<u64>(),
            extent_offset in proptest::prelude::any::<u64>(),
            num_bytes in proptest::prelude::any::<u64>(),
        ) {
            let original = BtrfsExtentData::Regular {
                generation,
                ram_bytes,
                extent_type,
                compression: BTRFS_COMPRESS_NONE,
                disk_bytenr: 0, // sparse — bypasses extent_offset+num_bytes check
                disk_num_bytes,
                extent_offset,
                num_bytes,
            };
            let bytes = original.to_bytes();
            proptest::prop_assert_eq!(bytes.len(), 53);
            let parsed = parse_extent_data(&bytes)
                .expect("sparse Regular extent must round-trip");
            proptest::prop_assert_eq!(parsed, original);
        }

        // MR-2: uncompressed inline round-trip. For COMPRESS_NONE,
        // ram_bytes must equal inline data length.
        #[test]
        fn proptest_extent_data_inline_uncompressed_round_trip(
            generation in proptest::prelude::any::<u64>(),
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=256),
        ) {
            let ram_bytes = u64::try_from(data.len()).expect("len fits u64");
            let original = BtrfsExtentData::Inline {
                generation,
                ram_bytes,
                compression: BTRFS_COMPRESS_NONE,
                data,
            };
            let bytes = original.to_bytes();
            let parsed = parse_extent_data(&bytes)
                .expect("uncompressed Inline extent must round-trip");
            proptest::prop_assert_eq!(parsed, original);
        }

        // MR-3: compressed inline round-trip. For non-NONE
        // compression, ram_bytes is the decompressed size and is not
        // constrained to equal data length.
        #[test]
        fn proptest_extent_data_inline_compressed_round_trip(
            generation in proptest::prelude::any::<u64>(),
            ram_bytes in proptest::prelude::any::<u64>(),
            compression in proptest::prop_oneof![
                proptest::prelude::Just(BTRFS_COMPRESS_ZLIB),
                proptest::prelude::Just(BTRFS_COMPRESS_LZO),
                proptest::prelude::Just(BTRFS_COMPRESS_ZSTD),
            ],
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=256),
        ) {
            let original = BtrfsExtentData::Inline {
                generation,
                ram_bytes,
                compression,
                data,
            };
            let bytes = original.to_bytes();
            let parsed = parse_extent_data(&bytes)
                .expect("compressed Inline extent must round-trip");
            proptest::prop_assert_eq!(parsed, original);
        }

        // bd-whybk — MR-4 raw-bytes determinism for parse_extent_data.
        // The existing MR-1/2/3 proptests above only exercise valid
        // encode → parse round-trips. This proptest fuzzes ARBITRARY
        // 0..=128 byte buffers (covering both Ok and Err paths) and
        // asserts parse_extent_data(buf) == parse_extent_data(buf) on
        // every call. parse_extent_data is invoked on every btrfs file
        // read — the heaviest-trafficked btrfs leaf-item parser. A
        // regression that introduced HashMap iteration, allocator-
        // address dependency, or any non-deterministic per-call state
        // on either the Ok or Err path would silently surface only
        // under specific scheduling. Sister raw-bytes determinism MRs:
        // parse_root_item (bd-fs41s), parse_xattr_items (bd-fhznm),
        // parse_inode_refs (bd-9f8ef), parse_root_ref (bd-x2320),
        // parse_dir_items (bd-7pr5k), parse_inode_item (in
        // inode_item_proptest_determinism).
        #[test]
        fn proptest_parse_extent_data_raw_bytes_determinism(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=128),
        ) {
            let a = parse_extent_data(&bytes);
            let b = parse_extent_data(&bytes);
            proptest::prop_assert_eq!(a, b);
        }
    }

    #[test]
    fn btrfs_item_payload_adversarial_samples_exercise_boundaries() {
        assert_root_item_adversarial_boundaries();
        assert_inode_item_adversarial_boundaries();
        assert_dir_item_adversarial_boundaries();
        assert_xattr_item_adversarial_boundaries();
        assert_extent_data_adversarial_boundaries();
    }

    // ── Serialization round-trip tests ────────────────────────────────────

    const REPRESENTATIVE_BTRFS_ITEM_GOLDEN: &str =
        include_str!("../../../conformance/golden/btrfs_item_payloads.txt");

    fn representative_btrfs_item_golden_actual() -> String {
        let inode_ref_key = BtrfsKey {
            objectid: 258,
            item_type: BTRFS_ITEM_INODE_REF,
            offset: 256,
        };
        let inode_ref = BtrfsInodeRef {
            index: 7,
            name: b"alpha.txt".to_vec(),
        };
        let inode_ref_payload = inode_ref.to_bytes();
        let parsed_inode_refs = parse_inode_refs(&inode_ref_payload).expect("parse inode_ref");
        assert_eq!(parsed_inode_refs, vec![inode_ref.clone()]);

        let extent_key = BtrfsKey {
            objectid: 258,
            item_type: BTRFS_ITEM_EXTENT_DATA,
            offset: 0,
        };
        let extent = BtrfsExtentData::Regular {
            generation: 3,
            ram_bytes: 4096,
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: 0,
            disk_bytenr: 0x10_0000,
            disk_num_bytes: 4096,
            extent_offset: 512,
            num_bytes: 3584,
        };
        let extent_payload = extent.to_bytes();
        let parsed_extent = parse_extent_data(&extent_payload).expect("parse extent_data");
        assert_eq!(parsed_extent, extent);

        let dir_item_key = BtrfsKey {
            objectid: 256,
            item_type: BTRFS_ITEM_DIR_ITEM,
            offset: 2_214_237_132,
        };
        let dir_item = BtrfsDirItem {
            child_objectid: 258,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: BTRFS_FT_REG_FILE,
            name: b"file.txt".to_vec(),
        };
        let dir_item_payload = dir_item.to_bytes();
        let parsed_dir_items = parse_dir_items(&dir_item_payload).expect("parse dir_item");
        assert_eq!(parsed_dir_items, vec![dir_item.clone()]);

        format!(
            concat!(
                "INODE_REF\n",
                "  key=objectid:{},type:{},offset:{}\n",
                "  decoded=index:{},name:{}\n",
                "  payload_hex={}\n",
                "EXTENT_DATA\n",
                "  key=objectid:{},type:{},offset:{}\n",
                "  decoded=regular,generation:{},ram_bytes:{},disk_bytenr:{},disk_num_bytes:{},extent_offset:{},num_bytes:{}\n",
                "  payload_hex={}\n",
                "DIR_ITEM\n",
                "  key=objectid:{},type:{},offset:{}\n",
                "  decoded=child_objectid:{},child_key_type:{},child_key_offset:{},file_type:{},name:{}\n",
                "  payload_hex={}\n",
            ),
            inode_ref_key.objectid,
            inode_ref_key.item_type,
            inode_ref_key.offset,
            inode_ref.index,
            String::from_utf8_lossy(&inode_ref.name),
            hex_lower(&inode_ref_payload),
            extent_key.objectid,
            extent_key.item_type,
            extent_key.offset,
            3,
            4096,
            0x10_0000_u64,
            4096,
            512,
            3584,
            hex_lower(&extent_payload),
            dir_item_key.objectid,
            dir_item_key.item_type,
            dir_item_key.offset,
            dir_item.child_objectid,
            dir_item.child_key_type,
            dir_item.child_key_offset,
            dir_item.file_type,
            String::from_utf8_lossy(&dir_item.name),
            hex_lower(&dir_item_payload)
        )
    }

    #[test]
    fn representative_btrfs_item_payloads_exact_golden_contract() {
        assert_eq!(
            representative_btrfs_item_golden_actual(),
            REPRESENTATIVE_BTRFS_ITEM_GOLDEN
        );
    }

    #[test]
    fn inode_ref_round_trip() {
        let original = BtrfsInodeRef {
            index: 42,
            name: b"hardlink-target".to_vec(),
        };
        let bytes = original.to_bytes();
        let parsed = parse_inode_refs(&bytes).expect("round-trip parse");
        assert_eq!(parsed, vec![original]);
    }

    // bd-bq6l8 — Canonical byte-layout snapshot for
    // BtrfsInodeRef::try_to_bytes. Pins the encoder's exact output
    // for a known fixture so any field-order or offset drift fails
    // with a hex diff (rather than a silent round-trip with a
    // similarly-broken parser). Pairs with bd-kelr0 (parser kernel-
    // offset pin), bd-pt9pk (round-trip MR), bd-9f8ef (determinism
    // MR), bd-2gb89 (BtrfsDirItem canonical bytes), bd-yjzhk
    // (BtrfsExtentData Regular canonical bytes), bd-fw55q
    // (BtrfsExtentData Inline canonical bytes).
    #[test]
    fn inode_ref_to_bytes_canonical_byte_layout() {
        let entry = BtrfsInodeRef {
            index: 0xCAFE_BABE_DEAD_BEEF,
            name: b"kernel-pin-test".to_vec(),
        };
        let bytes = entry.try_to_bytes().expect("canonical fixture encodes");
        assert_eq!(bytes.len(), 10 + 15);

        // Round-trip cross-check is redundant with bd-kelr0 +
        // bd-pt9pk but cheap and explicit here.
        let parsed = parse_inode_refs(&bytes).expect("canonical bytes parse");
        assert_eq!(parsed, vec![entry]);

        // 10 fixed bytes + 15 name bytes = 25 total.
        let expected: [u8; 25] = [
            // index LE @0..8 = 0xCAFE_BABE_DEAD_BEEF
            0xEF, 0xBE, 0xAD, 0xDE, 0xBE, 0xBA, 0xFE, 0xCA, // name_len LE @8..10 = 15
            0x0F, 0x00, // name @10..25 = "kernel-pin-test"
            b'k', b'e', b'r', b'n', b'e', b'l', b'-', b'p', b'i', b'n', b'-', b't', b'e', b's',
            b't',
        ];
        assert_eq!(
            bytes, expected,
            "BtrfsInodeRef::try_to_bytes canonical byte layout drifted"
        );
    }

    // bd-kelr0 — Kernel-conformance pin for parse_inode_refs.
    //
    // struct btrfs_inode_ref in fs/btrfs/btrfs_tree.h packs to 10
    // fixed bytes:
    //   index    u64 @0..8
    //   name_len u16 @8..10
    // plus name bytes at @10..10+name_len.
    //
    // The existing inode_ref_round_trip test and the bd-pt9pk +
    // bd-9f8ef proptest MRs verify parser BEHAVIOR but do not pin
    // the white-box read offsets — a regression that drifted index
    // to offset 1..9 or name_len to offset 7..9 would be caught
    // only by the overall equality check, not by a specific offset
    // assertion. Stamp each addressable field with a unique non-
    // zero magic so any single-field offset drift produces a
    // cross-field collision.
    #[test]
    fn parse_inode_refs_kernel_offsets_match_btrfs_tree_h() {
        let name: [u8; 5] = [0x99, 0x99, 0x99, 0x99, 0x99];
        let mut data = vec![0_u8; 10 + name.len()];

        let index = 0x1111_2222_3333_4444_u64;
        let name_len = u16::try_from(name.len()).expect("name fits u16");

        data[0..8].copy_from_slice(&index.to_le_bytes());
        data[8..10].copy_from_slice(&name_len.to_le_bytes());
        data[10..10 + name.len()].copy_from_slice(&name);

        let parsed = parse_inode_refs(&data).expect("kernel-stamped inode_ref must parse");
        assert_eq!(
            parsed.len(),
            1,
            "single-entry payload must parse to one entry"
        );
        assert_eq!(
            parsed[0].index, index,
            "index must come from offset 0..8 per kernel layout"
        );
        assert_eq!(
            parsed[0].name, name,
            "name bytes must start at offset 10 with length name_len@8..10"
        );

        // Negative MR: mutate name_len@8..10 to 0 and assert the
        // parser rejects with InvalidField{field: "inode_ref.name_len"}
        // — pinning offset 8 explicitly. A regression that drifted
        // name_len's read to a different offset would either
        // accidentally read non-zero bytes (allowing this case) or
        // misalign the name slice (mismatching the equality above).
        let mut bad = data.clone();
        bad[8..10].copy_from_slice(&0_u16.to_le_bytes());
        let err = parse_inode_refs(&bad).expect_err("zero name_len must reject");
        assert!(
            matches!(err, ParseError::InvalidField { field, .. } if field == "inode_ref.name_len"),
            "rejection must specifically blame name_len, proving offset 8 is read; got {err:?}"
        );
    }

    #[test]
    fn inode_ref_try_to_bytes_rejects_name_len_overflow() {
        let original = BtrfsInodeRef {
            index: 42,
            name: vec![b'x'; usize::from(u16::MAX) + 1],
        };

        let err = original
            .try_to_bytes()
            .expect_err("oversized inode_ref name should fail before encoding");
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "inode_ref.name_len",
                reason: "name length exceeds u16::MAX",
            }
        ));
    }

    #[test]
    fn inode_ref_try_to_bytes_rejects_empty_name() {
        let original = BtrfsInodeRef {
            index: 42,
            name: Vec::new(),
        };

        let err = original
            .try_to_bytes()
            .expect_err("empty inode_ref name should fail before encoding");
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "inode_ref.name_len",
                reason: "must be non-zero",
            }
        ));
    }

    // bd-pt9pk: metamorphic proptests for parse_inode_refs.
    // The existing inode_ref_round_trip test covers ONE fixed input;
    // these proptests sweep arbitrary (index, name) pairs plus
    // multi-entry concatenations to catch any regression in the
    // cursor-advance or variable-length boundary handling.
    proptest::proptest! {
        // MR-1 single-entry round-trip: for any (index, name length 1..=64),
        // try_to_bytes(entry) ↦ parse_inode_refs ↦ [entry].
        #[test]
        fn inode_ref_proptest_single_round_trip(
            index in proptest::prelude::any::<u64>(),
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=64),
        ) {
            let entry = BtrfsInodeRef { index, name };
            let bytes = entry.try_to_bytes().expect("non-empty name encodes");
            let parsed = parse_inode_refs(&bytes).expect("round-trip parse");
            proptest::prop_assert_eq!(parsed, vec![entry]);
        }

        // MR-2 multi-entry concatenation: stamp(a)++stamp(b)++... ↦
        // parse_inode_refs ↦ [a, b, ...]. Catches cursor-advance
        // regressions (e.g., reading past name_end into the next
        // entry's index field).
        #[test]
        fn inode_ref_proptest_multi_entry_concat(
            entries in proptest::collection::vec(
                (
                    proptest::prelude::any::<u64>(),
                    proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
                ),
                2..=8,
            ),
        ) {
            let originals: Vec<BtrfsInodeRef> = entries
                .into_iter()
                .map(|(index, name)| BtrfsInodeRef { index, name })
                .collect();

            let mut bytes = Vec::new();
            for entry in &originals {
                let entry_bytes = entry.try_to_bytes().expect("non-empty name encodes");
                bytes.extend_from_slice(&entry_bytes);
            }

            let parsed = parse_inode_refs(&bytes).expect("multi-entry parse");
            proptest::prop_assert_eq!(parsed, originals);
        }

        // MR-3 inner-truncation rejection: removing any non-zero
        // suffix from a valid encoding must produce an error rather
        // than a panic or buffer over-read. (k=full length means
        // empty input which parse_inode_refs treats as Ok([]) — that
        // is an intentional contract, so we sweep 1..len, not 1..=len.)
        #[test]
        fn inode_ref_proptest_truncation_rejection(
            index in proptest::prelude::any::<u64>(),
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
            k in 1_usize..50,
        ) {
            let entry = BtrfsInodeRef { index, name };
            let bytes = entry.try_to_bytes().expect("non-empty name encodes");
            let trunc = k.min(bytes.len() - 1);
            let truncated = &bytes[..bytes.len() - trunc];
            let err = parse_inode_refs(truncated).expect_err("truncated payload must reject");
            // Specific variant intentionally not asserted to avoid
            // over-coupling to the ParseError shape; rendering must
            // succeed (covers no-panic).
            let _ = format!("{err:?}");
        }

        // bd-9f8ef MR-4 determinism: parse(payload) == parse(payload).
        // Sister parsers parse_xattr_items (bd-fhznm) and
        // parse_extent_data (bd-3niu3) have analogous determinism
        // proptests. A regression that introduced a hash-iteration
        // or allocator-address dependency in the parser path would
        // silently surface only under specific scheduling; this
        // catches it under proptest's deterministic seed sweep.
        #[test]
        fn inode_ref_proptest_determinism(
            entries in proptest::collection::vec(
                (
                    proptest::prelude::any::<u64>(),
                    proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
                ),
                1..=8,
            ),
        ) {
            let mut payload = Vec::new();
            for (index, name) in &entries {
                let entry = BtrfsInodeRef {
                    index: *index,
                    name: name.clone(),
                };
                let bytes = entry.try_to_bytes().expect("non-empty name encodes");
                payload.extend_from_slice(&bytes);
            }
            let a = parse_inode_refs(&payload).expect("first parse");
            let b = parse_inode_refs(&payload).expect("second parse");
            proptest::prop_assert_eq!(a, b);
        }
    }

    /// bd-nzs5f — Kernel-conformance pin for the btrfs_inode_item
    /// field offsets per fs/btrfs/btrfs_tree.h. Each field is stamped
    /// with a UNIQUE non-zero magic at its canonical kernel offset,
    /// then a single parse_inode_item call must round-trip every
    /// field. A regression that drifted any single offset by ±4 bytes
    /// (one field-width) would mis-route mode↔rdev or uid↔gid
    /// silently. parse_inode_item_smoke / inode_item_round_trip
    /// (which round-trip via to_bytes) cannot detect such drift if
    /// to_bytes drifts the same way.
    ///
    /// Pairs with bd-xbqdw (parse_root_item kernel pin), bd-m6chz
    /// (BTRFS_ITEM_* discriminants), bd-qyfph (BTRFS_FT_* values).
    #[test]
    fn parse_inode_item_kernel_offsets_match_btrfs_tree_h() {
        let mut item = vec![0_u8; 160];

        // Distinct non-zero magics so an offset drift produces a
        // cross-field collision.
        let generation = 0x1111_1111_1111_1111_u64;
        let size = 0x2222_2222_2222_2222_u64;
        let nbytes = 0x3333_3333_3333_3333_u64;
        let nlink: u32 = 0x4444_4444;
        let uid: u32 = 0x5555_5555;
        let gid: u32 = 0x6666_6666;
        let mode: u32 = 0o100_644; // valid regular-file mode
        let rdev = 0x7777_7777_7777_7777_u64;
        // nsec must be < 1_000_000_000 per parser invariant. Pick four
        // distinct values inside [0, 1B) so a swap regression is caught.
        let access_time = (0x8888_8888_8888_8888_u64, 100_000_001_u32);
        let change_time = (0xAAAA_AAAA_AAAA_AAAA_u64, 200_000_002_u32);
        let modification_time = (0xCCCC_CCCC_CCCC_CCCC_u64, 300_000_003_u32);
        let creation_time = (0xEEEE_EEEE_EEEE_EEEE_u64, 400_000_004_u32);

        // Stamp at kernel offsets. Skip transid (8..16), block_group
        // (32..40), flags (64..72), sequence (72..80), reserved
        // (80..112) — these are zeroed by to_bytes and not exposed
        // on BtrfsInodeItem.
        item[0..8].copy_from_slice(&generation.to_le_bytes());
        item[16..24].copy_from_slice(&size.to_le_bytes());
        item[24..32].copy_from_slice(&nbytes.to_le_bytes());
        item[40..44].copy_from_slice(&nlink.to_le_bytes());
        item[44..48].copy_from_slice(&uid.to_le_bytes());
        item[48..52].copy_from_slice(&gid.to_le_bytes());
        item[52..56].copy_from_slice(&mode.to_le_bytes());
        item[56..64].copy_from_slice(&rdev.to_le_bytes());
        item[112..120].copy_from_slice(&access_time.0.to_le_bytes());
        item[120..124].copy_from_slice(&access_time.1.to_le_bytes());
        item[124..132].copy_from_slice(&change_time.0.to_le_bytes());
        item[132..136].copy_from_slice(&change_time.1.to_le_bytes());
        item[136..144].copy_from_slice(&modification_time.0.to_le_bytes());
        item[144..148].copy_from_slice(&modification_time.1.to_le_bytes());
        item[148..156].copy_from_slice(&creation_time.0.to_le_bytes());
        item[156..160].copy_from_slice(&creation_time.1.to_le_bytes());

        let parsed = parse_inode_item(&item).expect("kernel-stamped inode_item must parse");

        assert_eq!(parsed.generation, generation, "generation @ offset 0");
        assert_eq!(parsed.size, size, "size @ offset 16");
        assert_eq!(parsed.nbytes, nbytes, "nbytes @ offset 24");
        assert_eq!(parsed.nlink, nlink, "nlink @ offset 40");
        assert_eq!(parsed.uid, uid, "uid @ offset 44");
        assert_eq!(parsed.gid, gid, "gid @ offset 48");
        assert_eq!(parsed.mode, mode, "mode @ offset 52");
        assert_eq!(parsed.rdev, rdev, "rdev @ offset 56");
        assert_eq!(parsed.atime_sec, access_time.0, "atime_sec @ offset 112");
        assert_eq!(parsed.atime_nsec, access_time.1, "atime_nsec @ offset 120");
        assert_eq!(parsed.ctime_sec, change_time.0, "ctime_sec @ offset 124");
        assert_eq!(parsed.ctime_nsec, change_time.1, "ctime_nsec @ offset 132");
        assert_eq!(
            parsed.mtime_sec, modification_time.0,
            "mtime_sec @ offset 136"
        );
        assert_eq!(
            parsed.mtime_nsec, modification_time.1,
            "mtime_nsec @ offset 144"
        );
        assert_eq!(parsed.otime_sec, creation_time.0, "otime_sec @ offset 148");
        assert_eq!(
            parsed.otime_nsec, creation_time.1,
            "otime_nsec @ offset 156"
        );
    }

    #[test]
    fn inode_item_round_trip() {
        let original = BtrfsInodeItem {
            generation: 42,
            size: 65536,
            nbytes: 65536,
            nlink: 3,
            uid: 1000,
            gid: 1000,
            mode: 0o100_644,
            rdev: 0,
            flags: 0x801, // BTRFS_INODE_NODATASUM | BTRFS_INODE_COMPRESS
            atime_sec: 1_700_000_000,
            atime_nsec: 123_456_789,
            ctime_sec: 1_700_000_001,
            ctime_nsec: 987_654_321,
            mtime_sec: 1_700_000_002,
            mtime_nsec: 111_111_111,
            otime_sec: 1_700_000_003,
            otime_nsec: 222_222_222,
        };
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), 160);
        let parsed = parse_inode_item(&bytes).expect("round-trip parse");
        assert_eq!(parsed.size, original.size);
        assert_eq!(parsed.nbytes, original.nbytes);
        assert_eq!(parsed.nlink, original.nlink);
        assert_eq!(parsed.uid, original.uid);
        assert_eq!(parsed.gid, original.gid);
        assert_eq!(parsed.mode, original.mode);
        assert_eq!(parsed.rdev, original.rdev);
        assert_eq!(parsed.flags, original.flags);
        assert_eq!(parsed.atime_sec, original.atime_sec);
        assert_eq!(parsed.atime_nsec, original.atime_nsec);
        assert_eq!(parsed.ctime_sec, original.ctime_sec);
        assert_eq!(parsed.ctime_nsec, original.ctime_nsec);
        assert_eq!(parsed.mtime_sec, original.mtime_sec);
        assert_eq!(parsed.mtime_nsec, original.mtime_nsec);
        assert_eq!(parsed.otime_sec, original.otime_sec);
        assert_eq!(parsed.otime_nsec, original.otime_nsec);
    }

    // bd-pketz — Canonical byte-layout snapshot for
    // BtrfsInodeItem::to_bytes. Pins the encoder's exact output
    // for a magic-stamped fixture so any field-order or offset
    // drift fails with a hex diff. The expected literal pins
    // BOTH magic regions AND the implicit zero regions (transid@8,
    // block_group@32, flags@64, sequence@72, reserved[4]@80) — so
    // a regression that wrote non-zero into a "skipped" field
    // would also be caught (which neither bd-nzs5f kernel-offset
    // pin nor bd-0rsx6 round-trip MR detects, because they only
    // exercise fields that the parser reads).
    //
    // Pairs with bd-bq6l8 (BtrfsInodeRef), bd-2gb89 (BtrfsDirItem),
    // bd-yjzhk + bd-fw55q (BtrfsExtentData Regular/Inline).
    #[test]
    fn inode_item_to_bytes_canonical_byte_layout() {
        let item = BtrfsInodeItem {
            generation: 0x1111_1111_1111_1111,
            size: 0x2222_2222_2222_2222,
            nbytes: 0x3333_3333_3333_3333,
            nlink: 0x4444_4444,
            uid: 0x5555_5555,
            gid: 0x6666_6666,
            mode: 0o100_644, // 0x000081A4
            rdev: 0x7777_7777_7777_7777,
            flags: 0, // no flags set
            atime_sec: 0x8888_8888_8888_8888,
            atime_nsec: 100_000_001, // 0x05F5E101
            ctime_sec: 0xAAAA_AAAA_AAAA_AAAA,
            ctime_nsec: 200_000_002, // 0x0BEBC202
            mtime_sec: 0xCCCC_CCCC_CCCC_CCCC,
            mtime_nsec: 300_000_003, // 0x11E1A303
            otime_sec: 0xEEEE_EEEE_EEEE_EEEE,
            otime_nsec: 400_000_004, // 0x17D78404
        };
        let bytes = item.to_bytes();
        assert_eq!(bytes.len(), 160);

        // Round-trip cross-check. Redundant with bd-0rsx6 but
        // explicit here.
        let parsed = parse_inode_item(&bytes).expect("canonical bytes parse");
        assert_eq!(parsed, item);

        let expected: [u8; 160] = [
            // generation LE @0..8 = 0x1111_1111_1111_1111
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // transid @8..16 (zero — encoder hard-codes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // size LE @16..24 = 0x2222_2222_2222_2222
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            // nbytes LE @24..32 = 0x3333_3333_3333_3333
            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
            // block_group @32..40 (zero — encoder hard-codes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // nlink LE @40..44 = 0x4444_4444
            0x44, 0x44, 0x44, 0x44, // uid LE @44..48 = 0x5555_5555
            0x55, 0x55, 0x55, 0x55, // gid LE @48..52 = 0x6666_6666
            0x66, 0x66, 0x66, 0x66, // mode LE @52..56 = 0x0000_81A4 (0o100_644)
            0xA4, 0x81, 0x00, 0x00, // rdev LE @56..64 = 0x7777_7777_7777_7777
            0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, // flags @64..72 (zero)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sequence @72..80 (zero)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // reserved[4] @80..112 (32 bytes zero)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // atime_sec LE @112..120 = 0x8888_8888_8888_8888
            0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
            // atime_nsec LE @120..124 = 0x05F5_E101 (100_000_001)
            0x01, 0xE1, 0xF5, 0x05, // ctime_sec LE @124..132 = 0xAAAA_AAAA_AAAA_AAAA
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            // ctime_nsec LE @132..136 = 0x0BEB_C202 (200_000_002)
            0x02, 0xC2, 0xEB, 0x0B, // mtime_sec LE @136..144 = 0xCCCC_CCCC_CCCC_CCCC
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            // mtime_nsec LE @144..148 = 0x11E1_A303 (300_000_003)
            0x03, 0xA3, 0xE1, 0x11, // otime_sec LE @148..156 = 0xEEEE_EEEE_EEEE_EEEE
            0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
            // otime_nsec LE @156..160 = 0x17D7_8404 (400_000_004)
            0x04, 0x84, 0xD7, 0x17,
        ];
        assert_eq!(
            bytes, expected,
            "BtrfsInodeItem::to_bytes canonical byte layout drifted"
        );
    }

    #[test]
    fn dir_item_round_trip() {
        let original = BtrfsDirItem {
            child_objectid: 258,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: BTRFS_FT_REG_FILE,
            name: b"my_test_file.txt".to_vec(),
        };
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), 30 + original.name.len());
        let parsed = parse_dir_items(&bytes).expect("round-trip parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], original);
    }

    // bd-2gb89 — Canonical byte-layout snapshot for
    // BtrfsDirItem::try_to_bytes. Pins the encoder's exact output
    // for a known fixture so any field-order or offset drift fails
    // with a hex diff (rather than a silent round-trip with a
    // similarly-broken parser). Pairs with bd-qwo4a (parse_dir_items
    // kernel-offset pin) and bd-78fbx (parse_dir_items round-trip
    // MR proptests) — together those three tests pin the encoder
    // bytes, the parser offsets, and their agreement separately.
    #[test]
    fn dir_item_try_to_bytes_canonical_byte_layout() {
        let item = BtrfsDirItem {
            child_objectid: 0x1122_3344_5566_7788,
            child_key_type: 0xAB,
            child_key_offset: 0xDEAD_BEEF_CAFE_BABE,
            file_type: BTRFS_FT_REG_FILE, // 1
            name: b"snapfix.txt".to_vec(),
        };
        let bytes = item.try_to_bytes().expect("canonical fixture encodes");

        // 30 fixed header bytes + 11 name bytes = 41 total.
        let expected: [u8; 41] = [
            // child_objectid LE @0..8 = 0x1122_3344_5566_7788
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // child_key_type @8 = 0xAB
            0xAB, // child_key_offset LE @9..17 = 0xDEAD_BEEF_CAFE_BABE
            0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE,
            // transid @17..25 = 0 (encoder always zero)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // data_len LE @25..27 = 0 (DIR_ITEM has no trailing payload)
            0x00, 0x00, // name_len LE @27..29 = 11
            0x0B, 0x00, // file_type @29 = 1 (BTRFS_FT_REG_FILE)
            0x01, // name @30..41 = "snapfix.txt"
            b's', b'n', b'a', b'p', b'f', b'i', b'x', b'.', b't', b'x', b't',
        ];
        assert_eq!(
            bytes, expected,
            "BtrfsDirItem::try_to_bytes canonical byte layout drifted"
        );

        // Parser-side cross-check: the canonical bytes must round-trip
        // to the exact same struct. (Redundant with bd-qwo4a kernel-pin
        // and dir_item_round_trip, but cheap and makes the failure mode
        // explicit when the encoder drifts and the parser is updated to
        // match — both must be reverted.)
        let parsed = parse_dir_items(&bytes).expect("canonical bytes parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], item);
    }

    #[test]
    fn dir_item_try_to_bytes_rejects_name_len_overflow() {
        let original = BtrfsDirItem {
            child_objectid: 258,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: BTRFS_FT_REG_FILE,
            name: vec![b'x'; usize::from(u16::MAX) + 1],
        };

        let err = original
            .try_to_bytes()
            .expect_err("oversized dir_item name should fail before encoding");
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "dir_item.name_len",
                reason: "name length exceeds u16::MAX",
            }
        ));
    }

    #[test]
    fn dir_item_try_to_bytes_rejects_empty_name() {
        let original = BtrfsDirItem {
            child_objectid: 258,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: BTRFS_FT_REG_FILE,
            name: Vec::new(),
        };

        let err = original
            .try_to_bytes()
            .expect_err("empty dir_item name should fail before encoding");
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "dir_item.name_len",
                reason: "must be non-zero",
            }
        ));
    }

    #[test]
    fn dir_item_round_trip_directory() {
        let original = BtrfsDirItem {
            child_objectid: 300,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: BTRFS_FT_DIR,
            name: b"subdir".to_vec(),
        };
        let bytes = original.to_bytes();
        let parsed = parse_dir_items(&bytes).expect("round-trip parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], original);
    }

    #[test]
    fn dir_item_multiple_entries_concatenated() {
        // btrfs stores multiple dir entries with the same hash in one payload.
        let entry_a = BtrfsDirItem {
            child_objectid: 258,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: BTRFS_FT_REG_FILE,
            name: b"file_a".to_vec(),
        };
        let entry_b = BtrfsDirItem {
            child_objectid: 259,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: BTRFS_FT_SYMLINK,
            name: b"link_b".to_vec(),
        };
        let mut payload = entry_a.to_bytes();
        payload.extend_from_slice(&entry_b.to_bytes());
        let parsed = parse_dir_items(&payload).expect("parse concatenated entries");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], entry_a);
        assert_eq!(parsed[1], entry_b);
    }

    // bd-78fbx: metamorphic proptests for parse_dir_items.
    // Existing tests cover three fixed-input dir_items. These
    // proptests sweep arbitrary (objectid, key_type, key_offset,
    // file_type, name) tuples plus N-entry concatenations to catch
    // regressions in cursor-advance and variable-length boundary
    // handling. Mirrors bd-pt9pk for parse_inode_refs.
    proptest::proptest! {
        // MR-1 single-entry round-trip.
        #[test]
        fn dir_item_proptest_single_round_trip(
            child_objectid in proptest::prelude::any::<u64>(),
            child_key_type in proptest::prelude::any::<u8>(),
            child_key_offset in proptest::prelude::any::<u64>(),
            file_type in proptest::prelude::any::<u8>(),
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=64),
        ) {
            let entry = BtrfsDirItem {
                child_objectid,
                child_key_type,
                child_key_offset,
                file_type,
                name,
            };
            let bytes = entry.try_to_bytes().expect("non-empty name encodes");
            let parsed = parse_dir_items(&bytes).expect("round-trip parse");
            proptest::prop_assert_eq!(parsed, vec![entry]);
        }

        // MR-2 multi-entry concatenation: stamp(a)++stamp(b)++... ↦
        // parse_dir_items ↦ [a, b, ...]. Catches cursor-advance bugs
        // (e.g., reading past name_end into the next entry's location
        // key fields).
        #[test]
        fn dir_item_proptest_multi_entry_concat(
            entries in proptest::collection::vec(
                (
                    proptest::prelude::any::<u64>(),
                    proptest::prelude::any::<u8>(),
                    proptest::prelude::any::<u64>(),
                    proptest::prelude::any::<u8>(),
                    proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
                ),
                2..=8,
            ),
        ) {
            let originals: Vec<BtrfsDirItem> = entries
                .into_iter()
                .map(|(objid, ktype, koffset, ftype, name)| BtrfsDirItem {
                    child_objectid: objid,
                    child_key_type: ktype,
                    child_key_offset: koffset,
                    file_type: ftype,
                    name,
                })
                .collect();

            let mut bytes = Vec::new();
            for entry in &originals {
                let entry_bytes = entry.try_to_bytes().expect("non-empty name encodes");
                bytes.extend_from_slice(&entry_bytes);
            }

            let parsed = parse_dir_items(&bytes).expect("multi-entry parse");
            proptest::prop_assert_eq!(parsed, originals);
        }

        // bd-7pr5k — MR-4 Determinism. parse_dir_items called twice
        // on the same payload must return identical results. Cheap
        // check that the parser does not depend on any hidden state
        // (allocator addresses, hash iteration order, time). Sister
        // parsers parse_xattr_items, parse_inode_refs, parse_inode_item,
        // parse_root_item, parse_extent_data all have determinism MRs.
        #[test]
        fn dir_item_proptest_determinism(
            entries in proptest::collection::vec(
                (
                    proptest::prelude::any::<u64>(),
                    proptest::prelude::any::<u8>(),
                    proptest::prelude::any::<u64>(),
                    proptest::prelude::any::<u8>(),
                    proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
                ),
                1..=8,
            ),
        ) {
            let mut payload = Vec::new();
            for (objid, ktype, koffset, ftype, name) in &entries {
                let entry = BtrfsDirItem {
                    child_objectid: *objid,
                    child_key_type: *ktype,
                    child_key_offset: *koffset,
                    file_type: *ftype,
                    name: name.clone(),
                };
                payload.extend_from_slice(&entry.try_to_bytes().expect("non-empty name encodes"));
            }
            let a = parse_dir_items(&payload).expect("first parse");
            let b = parse_dir_items(&payload).expect("second parse");
            proptest::prop_assert_eq!(a, b);
        }

        // MR-3 inner-truncation rejection: removing any non-zero
        // suffix from a valid encoding must produce an error rather
        // than a panic or buffer over-read.
        #[test]
        fn dir_item_proptest_truncation_rejection(
            child_objectid in proptest::prelude::any::<u64>(),
            child_key_type in proptest::prelude::any::<u8>(),
            child_key_offset in proptest::prelude::any::<u64>(),
            file_type in proptest::prelude::any::<u8>(),
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
            k in 1_usize..50,
        ) {
            let entry = BtrfsDirItem {
                child_objectid,
                child_key_type,
                child_key_offset,
                file_type,
                name,
            };
            let bytes = entry.try_to_bytes().expect("non-empty name encodes");
            let trunc = k.min(bytes.len() - 1);
            let truncated = &bytes[..bytes.len() - trunc];
            let err = parse_dir_items(truncated).expect_err("truncated payload must reject");
            let _ = format!("{err:?}");
        }
    }

    #[test]
    fn extent_data_inline_round_trip() {
        let data = b"Hello, btrfs inline extent!".to_vec();
        let original = BtrfsExtentData::Inline {
            generation: 0,
            ram_bytes: data.len() as u64,
            compression: 0,
            data: data.clone(),
        };
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), 21 + data.len());
        let parsed = parse_extent_data(&bytes).expect("round-trip parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn extent_data_inline_uncompressed_rejects_ram_bytes_mismatch() {
        let mut bytes = BtrfsExtentData::Inline {
            generation: 0,
            ram_bytes: 3,
            compression: BTRFS_COMPRESS_NONE,
            data: b"abcd".to_vec(),
        }
        .to_bytes();

        let err = parse_extent_data(&bytes).expect_err("oversized inline payload rejects");
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "extent_data.ram_bytes",
                reason: "uncompressed inline length mismatch",
            }
        );

        bytes[8..16].copy_from_slice(&5_u64.to_le_bytes());
        let err = parse_extent_data(&bytes).expect_err("undersized inline payload rejects");
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "extent_data.ram_bytes",
                reason: "uncompressed inline length mismatch",
            }
        );
    }

    #[test]
    fn extent_data_inline_compressed_allows_payload_len_different_from_ram_bytes() {
        let compressed_inline = BtrfsExtentData::Inline {
            generation: 1,
            ram_bytes: 4096,
            compression: BTRFS_COMPRESS_ZLIB,
            data: b"compressed payload".to_vec(),
        };

        let parsed =
            parse_extent_data(&compressed_inline.to_bytes()).expect("parse compressed inline");
        assert_eq!(parsed, compressed_inline);
    }

    #[test]
    fn extent_data_regular_round_trip() {
        let original = BtrfsExtentData::Regular {
            generation: 1,
            ram_bytes: 3500,
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: 0,
            disk_bytenr: 0x10_0000,
            disk_num_bytes: 4096,
            extent_offset: 0,
            num_bytes: 3500,
        };
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), 53);
        let parsed = parse_extent_data(&bytes).expect("round-trip parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn extent_data_prealloc_round_trip() {
        let original = BtrfsExtentData::Regular {
            generation: 1,
            ram_bytes: 7680,
            extent_type: BTRFS_FILE_EXTENT_PREALLOC,
            compression: 0,
            disk_bytenr: 0x20_0000,
            disk_num_bytes: 8192,
            extent_offset: 512,
            num_bytes: 7680,
        };
        let bytes = original.to_bytes();
        let parsed = parse_extent_data(&bytes).expect("round-trip parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn inode_item_zero_fields_round_trip() {
        let original = BtrfsInodeItem {
            generation: 0,
            size: 0,
            nbytes: 0,
            nlink: 1,
            uid: 0,
            gid: 0,
            mode: 0o100_000,
            rdev: 0,
            flags: 0,
            atime_sec: 0,
            atime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            otime_sec: 0,
            otime_nsec: 0,
        };
        let bytes = original.to_bytes();
        let parsed = parse_inode_item(&bytes).expect("round-trip parse");
        assert_eq!(parsed.size, 0);
        assert_eq!(parsed.nlink, 1);
        assert_eq!(parsed.mode, 0o100_000);
        assert_eq!(parsed.flags, 0);
    }

    #[test]
    fn inode_item_max_values_round_trip() {
        let original = BtrfsInodeItem {
            generation: u64::MAX,
            size: u64::MAX,
            nbytes: u64::MAX,
            nlink: u32::MAX,
            uid: u32::MAX,
            gid: u32::MAX,
            mode: u32::MAX,
            rdev: u64::MAX,
            flags: u64::MAX,
            atime_sec: u64::MAX,
            atime_nsec: 999_999_999,
            ctime_sec: u64::MAX,
            ctime_nsec: 999_999_999,
            mtime_sec: u64::MAX,
            mtime_nsec: 999_999_999,
            otime_sec: u64::MAX,
            otime_nsec: 999_999_999,
        };
        let bytes = original.to_bytes();
        let parsed = parse_inode_item(&bytes).expect("round-trip parse");
        assert_eq!(parsed.size, u64::MAX);
        assert_eq!(parsed.nlink, u32::MAX);
        assert_eq!(parsed.rdev, u64::MAX);
        assert_eq!(parsed.atime_sec, u64::MAX);
        assert_eq!(parsed.otime_nsec, 999_999_999);
    }

    // bd-0rsx6: metamorphic relation — every field of BtrfsInodeItem
    // must survive the to_bytes ↦ parse_inode_item round trip. The
    // existing fixed-input tests would miss any regression where
    // both writer and reader drifted the same way (e.g., off-by-4
    // in both); a proptest sweep over arbitrary field values catches
    // such symmetric drift because it would surface as a swap or
    // truncation between distinctly-valued fields. nsec values are
    // constrained to [0, 1_000_000_000) per the parser invariant.
    proptest::proptest! {
        #[test]
        fn inode_item_proptest_round_trip(
            generation in proptest::prelude::any::<u64>(),
            size in proptest::prelude::any::<u64>(),
            nbytes in proptest::prelude::any::<u64>(),
            nlink in proptest::prelude::any::<u32>(),
            uid in proptest::prelude::any::<u32>(),
            gid in proptest::prelude::any::<u32>(),
            mode in proptest::prelude::any::<u32>(),
            rdev in proptest::prelude::any::<u64>(),
            flags in proptest::prelude::any::<u64>(),
            atime_sec in proptest::prelude::any::<u64>(),
            atime_nsec in 0_u32..1_000_000_000,
            ctime_sec in proptest::prelude::any::<u64>(),
            ctime_nsec in 0_u32..1_000_000_000,
            mtime_sec in proptest::prelude::any::<u64>(),
            mtime_nsec in 0_u32..1_000_000_000,
            otime_sec in proptest::prelude::any::<u64>(),
            otime_nsec in 0_u32..1_000_000_000,
        ) {
            let original = BtrfsInodeItem {
                generation,
                size,
                nbytes,
                nlink,
                uid,
                gid,
                mode,
                rdev,
                flags,
                atime_sec,
                atime_nsec,
                ctime_sec,
                ctime_nsec,
                mtime_sec,
                mtime_nsec,
                otime_sec,
                otime_nsec,
            };
            let bytes = original.to_bytes();
            proptest::prop_assert_eq!(bytes.len(), 160, "kernel-aligned 160-byte item");
            let parsed = parse_inode_item(&bytes).expect("round-trip parse");
            proptest::prop_assert_eq!(parsed, original);
        }

        // bd-v8c1m MR-2 determinism: parse(payload) == parse(payload).
        // Sister parsers parse_xattr_items (bd-fhznm), parse_extent_data
        // (bd-3niu3), parse_inode_refs (bd-9f8ef), parse_root_ref
        // (bd-x2320), parse_root_item (bd-fs41s) all have analogous
        // determinism proptests. A regression that introduced a hash-
        // iteration-order or allocator-address dependency in
        // parse_inode_item's path would silently surface only under
        // specific scheduling.
        #[test]
        fn inode_item_proptest_determinism(
            generation in proptest::prelude::any::<u64>(),
            size in proptest::prelude::any::<u64>(),
            nbytes in proptest::prelude::any::<u64>(),
            nlink in proptest::prelude::any::<u32>(),
            uid in proptest::prelude::any::<u32>(),
            gid in proptest::prelude::any::<u32>(),
            mode in proptest::prelude::any::<u32>(),
            rdev in proptest::prelude::any::<u64>(),
            flags in proptest::prelude::any::<u64>(),
            atime_sec in proptest::prelude::any::<u64>(),
            atime_nsec in 0_u32..1_000_000_000,
            ctime_sec in proptest::prelude::any::<u64>(),
            ctime_nsec in 0_u32..1_000_000_000,
            mtime_sec in proptest::prelude::any::<u64>(),
            mtime_nsec in 0_u32..1_000_000_000,
            otime_sec in proptest::prelude::any::<u64>(),
            otime_nsec in 0_u32..1_000_000_000,
        ) {
            let item = BtrfsInodeItem {
                generation,
                size,
                nbytes,
                nlink,
                uid,
                gid,
                mode,
                rdev,
                flags,
                atime_sec,
                atime_nsec,
                ctime_sec,
                ctime_nsec,
                mtime_sec,
                mtime_nsec,
                otime_sec,
                otime_nsec,
            };
            let bytes = item.to_bytes();
            let a = parse_inode_item(&bytes).expect("first parse");
            let b = parse_inode_item(&bytes).expect("second parse");
            proptest::prop_assert_eq!(a, b);
        }
    }

    #[test]
    fn extent_data_inline_empty() {
        let original = BtrfsExtentData::Inline {
            generation: 1,
            ram_bytes: 0,
            compression: 0,
            data: vec![],
        };
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), 21);
        let parsed = parse_extent_data(&bytes).expect("round-trip parse");
        assert_eq!(parsed, original);
    }

    // ── Xattr item parse tests ───────────────────────────────────────────

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn xattr_item_round_trip() {
        // Build xattr payload in the same format btrfs_setxattr uses.
        let name = b"user.myattr";
        let value = b"some-value";
        let mut payload = Vec::with_capacity(30 + name.len() + value.len());
        payload.extend_from_slice(&[0u8; 17]); // location key
        payload.extend_from_slice(&[0u8; 8]); // transid
        payload.extend_from_slice(&(value.len() as u16).to_le_bytes());
        payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
        payload.push(0); // type
        payload.extend_from_slice(name);
        payload.extend_from_slice(value);

        let parsed = parse_xattr_items(&payload).expect("parse xattr");
        assert_eq!(parsed.len(), 1);
    }

    // bd-9rup3 — Kernel-conformance pin for parse_xattr_items.
    //
    // parse_xattr_items reuses the 30-byte struct btrfs_dir_item
    // header (objectid 0..8, key_type 8, key_offset 9..17, transid
    // 17..25, data_len 25..27, name_len 27..29, type 29) but reads
    // ONLY data_len@25..27 and name_len@27..29 — the other fields
    // are skipped past. bd-qwo4a pinned the SAME header offsets
    // for parse_dir_items but parse_xattr_items has its own copy
    // of the read_u16 calls — a regression that drifted these
    // offsets in parse_xattr_items independently would silently
    // corrupt every getxattr/listxattr through ffs_core::OpenFs
    // (12+ call sites).
    //
    // Stamp the skipped fields with unique non-zero magic so any
    // misalignment that read data_len from offset 17 (transid,
    // 0x44_44 lo16) or any other wrong location would mis-read
    // a multi-byte length and either overflow the buffer or
    // produce a value that doesn't match the stamped magic
    // bytes. Only data_len=5 + name_len=4 + 4-byte-name +
    // 5-byte-value passes.
    #[test]
    fn parse_xattr_items_kernel_offsets_match_btrfs_tree_h() {
        let name: [u8; 4] = [0xAA, 0xAA, 0xAA, 0xAA];
        let value: [u8; 5] = [0xBB, 0xBB, 0xBB, 0xBB, 0xBB];
        let mut data = vec![0_u8; 30 + name.len() + value.len()];

        let objectid = 0x1111_1111_1111_1111_u64;
        let key_type: u8 = 0xCC;
        let key_offset = 0x3333_3333_3333_3333_u64;
        let transid_magic = 0x4444_4444_4444_4444_u64;
        let data_len: u16 = u16::try_from(value.len()).expect("value len fits u16");
        let name_len: u16 = u16::try_from(name.len()).expect("name len fits u16");
        let file_type: u8 = 0xDD;

        // Stamp skipped fields — if data_len@25 or name_len@27 were
        // misaligned, they would read from these magic-bearing
        // bytes and the parser would either reject or produce
        // wrong slices.
        data[0..8].copy_from_slice(&objectid.to_le_bytes());
        data[8] = key_type;
        data[9..17].copy_from_slice(&key_offset.to_le_bytes());
        data[17..25].copy_from_slice(&transid_magic.to_le_bytes());
        // Stamp the read fields at their canonical offsets.
        data[25..27].copy_from_slice(&data_len.to_le_bytes());
        data[27..29].copy_from_slice(&name_len.to_le_bytes());
        data[29] = file_type;
        // name and value bytes follow the 30-byte header.
        data[30..30 + name.len()].copy_from_slice(&name);
        data[30 + name.len()..30 + name.len() + value.len()].copy_from_slice(&value);

        let parsed = parse_xattr_items(&data).expect("kernel-stamped xattr_item must parse");
        assert_eq!(
            parsed.len(),
            1,
            "single-entry payload must parse to one item"
        );
        assert_eq!(
            parsed[0].name, name,
            "name bytes must come from offset 30..30+name_len@27..29"
        );
        assert_eq!(
            parsed[0].value, value,
            "value bytes must come from offset 30+name_len..30+name_len+data_len@25..27"
        );

        // Negative MR: zero out name_len@27..29 — parser must
        // reject the empty-name invariant. Pins offset 27 (vs the
        // SAME bytes ending up there from a misaligned read).
        let mut bad = data.clone();
        bad[27..29].copy_from_slice(&0_u16.to_le_bytes());
        let err = parse_xattr_items(&bad).expect_err("zero name_len must reject");
        assert!(
            matches!(err, ParseError::InvalidField { field, .. } if field == "xattr.name_len"),
            "rejection must specifically blame name_len, proving offset 27 is read; got {err:?}"
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn xattr_item_empty_value() {
        let name = b"user.empty";
        let mut payload = Vec::with_capacity(30 + name.len());
        payload.extend_from_slice(&[0u8; 17]);
        payload.extend_from_slice(&[0u8; 8]);
        payload.extend_from_slice(&0_u16.to_le_bytes()); // data_len=0
        payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(name);

        let parsed = parse_xattr_items(&payload).expect("parse xattr empty value");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, name);
        assert!(parsed[0].value.is_empty());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn xattr_item_multiple_concatenated() {
        // Two xattr items concatenated (would happen with hash collisions).
        let mut payload = Vec::new();
        for (name, value) in [("user.a", b"val1" as &[u8]), ("user.b", b"val2")] {
            payload.extend_from_slice(&[0u8; 17]);
            payload.extend_from_slice(&[0u8; 8]);
            payload.extend_from_slice(&(value.len() as u16).to_le_bytes());
            payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
            payload.push(0);
            payload.extend_from_slice(name.as_bytes());
            payload.extend_from_slice(value);
        }

        let parsed = parse_xattr_items(&payload).expect("parse multiple xattrs");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, b"user.a");
        assert_eq!(parsed[0].value, b"val1");
        assert_eq!(parsed[1].name, b"user.b");
        assert_eq!(parsed[1].value, b"val2");
    }

    // bd-fhznm — Property-based round-trip MR for parse_xattr_items.
    //
    // Existing fixture tests cover hand-crafted single-entry and
    // two-entry payloads. They would not catch an off-by-one in the
    // data_len@+25 / name_len@+27 offset arithmetic that mis-aligned
    // the second-and-later entries: entry[0] would still parse
    // because cur=0 is a fixed point. These proptests sweep
    // 1..=12-entry payloads with random names (1..=128 bytes) and
    // values (0..=256 bytes), encode in the on-disk format, and
    // assert structural agreement with the parser. Determinism MR
    // is included as a cheap check against any future use of
    // hashing/iteration-order primitives in the parser path.
    fn xattr_encode_one(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
        // Mirror parse_xattr_items's 30-byte header: location key (17)
        // + transid (8) + data_len u16 LE @25 + name_len u16 LE @27.
        out.extend_from_slice(&[0_u8; 17]);
        out.extend_from_slice(&[0_u8; 8]);
        out.extend_from_slice(
            &u16::try_from(value.len())
                .expect("xattr value < u16::MAX in test")
                .to_le_bytes(),
        );
        out.extend_from_slice(
            &u16::try_from(name.len())
                .expect("xattr name < u16::MAX in test")
                .to_le_bytes(),
        );
        out.push(0); // type byte (unused by parser)
        out.extend_from_slice(name);
        out.extend_from_slice(value);
    }

    proptest::proptest! {
        // MR-1 multi-entry round-trip: encode N random (name, value)
        // pairs in the on-disk format → parse → assert vec length and
        // per-entry equality.
        #[test]
        fn proptest_xattr_items_payload_round_trip(
            entries in proptest::collection::vec(
                (
                    proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=128),
                    proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=256),
                ),
                1..=12,
            ),
        ) {
            let mut payload = Vec::new();
            for (name, value) in &entries {
                xattr_encode_one(&mut payload, name, value);
            }
            let parsed = parse_xattr_items(&payload).expect("encode → parse round-trip");
            proptest::prop_assert_eq!(parsed.len(), entries.len());
            for (i, parsed_item) in parsed.iter().enumerate() {
                proptest::prop_assert_eq!(&parsed_item.name, &entries[i].0);
                proptest::prop_assert_eq!(&parsed_item.value, &entries[i].1);
            }
        }

        // MR-2 determinism: parse(payload) == parse(payload). Cheap
        // check that the parser does not depend on any hidden state
        // (allocator addresses, hash iteration order, time).
        #[test]
        fn proptest_xattr_items_determinism(
            entries in proptest::collection::vec(
                (
                    proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=64),
                    proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=128),
                ),
                1..=8,
            ),
        ) {
            let mut payload = Vec::new();
            for (name, value) in &entries {
                xattr_encode_one(&mut payload, name, value);
            }
            let a = parse_xattr_items(&payload).expect("first parse");
            let b = parse_xattr_items(&payload).expect("second parse");
            proptest::prop_assert_eq!(a, b);
        }

        // MR-3 inner-truncation rejection: cutting any non-zero suffix
        // from a valid multi-entry encoding must reject (Err) rather
        // than panic or silently succeed with a short result. Sweeps
        // 1..bytes.len() so the empty-input contract (Ok([])) is
        // intentionally excluded.
        #[test]
        fn proptest_xattr_items_truncation_rejection(
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=64),
            value in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=128),
            k in 1_usize..50,
        ) {
            let mut payload = Vec::new();
            xattr_encode_one(&mut payload, &name, &value);
            let trunc = k.min(payload.len() - 1);
            let truncated = &payload[..payload.len() - trunc];
            // Specific error variant intentionally not asserted -- the
            // parser legitimately produces InsufficientData or
            // InvalidField depending on which field is truncated.
            proptest::prop_assert!(
                parse_xattr_items(truncated).is_err(),
                "truncated payload must reject (cut last {} of {} bytes)",
                trunc,
                payload.len()
            );
        }
    }

    // ── Extent allocator tests ──────────────────────────────────────────

    fn make_data_bg(_start: u64, size: u64) -> BtrfsBlockGroupItem {
        BtrfsBlockGroupItem {
            total_bytes: size,
            used_bytes: 0,
            flags: BTRFS_BLOCK_GROUP_DATA,
        }
    }

    fn make_meta_bg(_start: u64, size: u64) -> BtrfsBlockGroupItem {
        BtrfsBlockGroupItem {
            total_bytes: size,
            used_bytes: 0,
            flags: BTRFS_BLOCK_GROUP_METADATA,
        }
    }

    #[test]
    fn alloc_data_and_metadata_do_not_overlap_on_mixed_block_group_bd_s0ogm() {
        // On a single mixed DATA|METADATA block group, a data extent and a
        // subsequently allocated metadata extent must not share physical space
        // (else a metadata commit would overwrite freshly written data).
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        // Root the group at a realistic offset: btrfs reserves the low logical
        // region, and bytenr 0 is the hole sentinel that the allocator must
        // never hand out (bd-5aybu).
        alloc.add_block_group(
            1 << 20,
            BtrfsBlockGroupItem {
                total_bytes: 1 << 20,
                used_bytes: 0,
                flags: BTRFS_BLOCK_GROUP_DATA | BTRFS_BLOCK_GROUP_METADATA,
            },
        );

        let data = alloc.alloc_data(4096).expect("alloc data");
        let meta = alloc
            .alloc_metadata_for_tree(4096, BTRFS_FS_TREE_OBJECTID, 0)
            .expect("alloc metadata");

        let data_end = data.bytenr + 4096;
        let meta_end = meta.bytenr + 4096;
        assert!(
            data_end <= meta.bytenr || meta_end <= data.bytenr,
            "data [{:#x},{:#x}) and metadata [{:#x},{:#x}) overlap on a mixed block group",
            data.bytenr,
            data_end,
            meta.bytenr,
            meta_end
        );
    }

    #[test]
    fn alloc_metadata_does_not_alias_loaded_skinny_metadata_item_bd_x36qn() {
        // A skinny METADATA_ITEM key encodes the tree level in its offset, not a
        // byte length. The gap finder must treat such an item as occupying a full
        // nodesize tree block; otherwise it under-sizes the live node to a few
        // bytes (level 0 -> 0 bytes) and allocates straight into it — aliasing an
        // existing tree node, which `btrfs check` reports as a parent-transid
        // mismatch (bd-x36qn). Before the fix the new allocation landed on top of
        // the live block; now it is placed clear of it.
        let nodesize = 16384_u64;
        let mut alloc = BtrfsExtentAllocator::new(9).expect("alloc");
        alloc.set_nodesize(nodesize);

        let bg_start = 1_u64 << 20;
        alloc.add_block_group(
            bg_start,
            BtrfsBlockGroupItem {
                total_bytes: 1 << 20,
                used_bytes: 0,
                flags: BTRFS_BLOCK_GROUP_METADATA,
            },
        );

        // A live skinny metadata tree block sitting at the group's first usable
        // offset (level 0 -> key offset 0).
        let live = bg_start;
        alloc
            .extent_tree_mut()
            .insert(
                BtrfsKey {
                    objectid: live,
                    item_type: BTRFS_ITEM_METADATA_ITEM,
                    offset: 0,
                },
                &[],
            )
            .expect("seed skinny metadata item");

        let a = alloc
            .alloc_metadata_for_tree(nodesize, BTRFS_FS_TREE_OBJECTID, 0)
            .expect("alloc metadata");
        let a_end = a.bytenr + nodesize;
        let live_end = live + nodesize;
        assert!(
            a_end <= live || live_end <= a.bytenr,
            "new metadata [{:#x},{:#x}) aliases live skinny METADATA_ITEM [{:#x},{:#x})",
            a.bytenr,
            a_end,
            live,
            live_end,
        );
    }

    #[test]
    fn alloc_single_extent_in_empty_group() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));

        let result = alloc.alloc_data(4096).expect("alloc");
        assert_eq!(result.bytenr, 0x1_0000);
        assert_eq!(result.num_bytes, 4096);
        assert_eq!(result.block_group_start, 0x1_0000);

        // Block group accounting should be updated.
        let bg = alloc.block_group(0x1_0000).expect("bg");
        assert_eq!(bg.used_bytes, 4096);
        assert_eq!(bg.free_bytes(), 0x10_0000 - 4096);
    }

    #[test]
    fn extent_allocator_rejects_zero_byte_allocations_without_side_effects() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));
        alloc.add_block_group(0x20_0000, make_meta_bg(0x20_0000, 0x10_0000));

        assert_eq!(
            alloc.alloc_data(0),
            Err(BtrfsMutationError::InvalidConfig(
                "extent size must be non-zero"
            ))
        );
        assert_eq!(
            alloc.alloc_metadata(0),
            Err(BtrfsMutationError::InvalidConfig(
                "extent size must be non-zero"
            ))
        );

        let data_bg = alloc.block_group(0x1_0000).expect("data bg");
        let meta_bg = alloc.block_group(0x20_0000).expect("meta bg");
        assert_eq!(data_bg.used_bytes, 0);
        assert_eq!(meta_bg.used_bytes, 0);
        assert_eq!(alloc.delayed_ref_count(), 0);
    }

    #[test]
    fn extent_allocator_rejects_zero_byte_free_without_side_effects() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));

        let existing = alloc.alloc_data(4096).expect("seed alloc");
        let refs_before = alloc.delayed_ref_count();
        let used_before = alloc.block_group(0x1_0000).expect("bg").used_bytes;

        assert_eq!(
            alloc.free_extent(existing.bytenr, 0, false),
            Err(BtrfsMutationError::InvalidConfig(
                "extent size must be non-zero"
            ))
        );

        let bg = alloc.block_group(0x1_0000).expect("bg");
        assert_eq!(bg.used_bytes, used_before);
        assert_eq!(alloc.delayed_ref_count(), refs_before);
    }

    #[test]
    fn alloc_fills_group_sequentially() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));

        let a1 = alloc.alloc_data(4096).expect("first");
        let a2 = alloc.alloc_data(8192).expect("second");
        let a3 = alloc.alloc_data(4096).expect("third");

        // Allocations should be sequential.
        assert_eq!(a1.bytenr, 0x1_0000);
        assert_eq!(a2.bytenr, 0x1_0000 + 4096);
        assert_eq!(a3.bytenr, 0x1_0000 + 4096 + 8192);

        let bg = alloc.block_group(0x1_0000).expect("bg");
        assert_eq!(bg.used_bytes, 4096 + 8192 + 4096);
    }

    #[test]
    fn free_extent_creates_reclaimable_space() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));

        let a1 = alloc.alloc_data(4096).expect("first");
        let _a2 = alloc.alloc_data(4096).expect("second");

        // Free first extent.
        alloc
            .free_extent(a1.bytenr, a1.num_bytes, false)
            .expect("free");

        let bg = alloc.block_group(0x1_0000).expect("bg");
        assert_eq!(bg.used_bytes, 4096); // only second extent remains
    }

    #[test]
    fn add_data_extent_ref_shares_extent_without_new_space() {
        let mut alloc = BtrfsExtentAllocator::new(7).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));

        let a = alloc.alloc_data(4096).expect("alloc");
        // Establish the refs==1 state: EXTENT_ITEM + a single inline
        // EXTENT_DATA_REF for the first inode (objectid 256) at offset 0.
        alloc
            .insert_data_extent_item(a.bytenr, a.num_bytes, 5, 256, 0, 7)
            .expect("insert refs=1 extent item");
        assert_eq!(
            alloc.extent_item_refs(a.bytenr, a.num_bytes).expect("refs"),
            Some(1)
        );
        let used_before = alloc.block_group(0x1_0000).expect("bg").used_bytes;

        // Share the extent with a second inode (objectid 257) — a reflink.
        alloc
            .add_data_extent_ref(a.bytenr, a.num_bytes, 5, 257, 0)
            .expect("add second ref");

        // Refcount went 1 -> 2; no new space was consumed.
        assert_eq!(
            alloc.extent_item_refs(a.bytenr, a.num_bytes).expect("refs"),
            Some(2)
        );
        assert_eq!(
            alloc.block_group(0x1_0000).expect("bg").used_bytes,
            used_before,
            "sharing an extent must not change block-group used bytes"
        );

        // The new reference is a KEYED EXTENT_DATA_REF (the inline ref for 256
        // stays inside the EXTENT_ITEM, so get_extent_data_refs returns only the
        // keyed one), keyed by hash_extent_data_ref(5, 257, 0).
        let keyed = alloc.get_extent_data_refs(a.bytenr).expect("keyed refs");
        assert_eq!(keyed.len(), 1, "exactly one keyed EXTENT_DATA_REF");
        assert_eq!(
            keyed[0],
            BtrfsExtentDataRef {
                root: 5,
                objectid: 257,
                offset: 0,
                count: 1,
            }
        );
    }

    /// bd-ngt1y: adding a SECOND EXTENT_DATA_REF for the same
    /// (root, objectid, offset) must MERGE into the existing keyed item by
    /// bumping its count (kernel behavior), not fail with KeyAlreadyExists or
    /// create a duplicate item.
    #[test]
    fn add_data_extent_ref_merges_duplicate_backref_bd_ngt1y() {
        let mut alloc = BtrfsExtentAllocator::new(7).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));
        let a = alloc.alloc_data(4096).expect("alloc");
        // refs == 1: inline ref for inode 256 at offset 0.
        alloc
            .insert_data_extent_item(a.bytenr, a.num_bytes, 5, 256, 0, 7)
            .expect("insert refs=1 extent item");

        // First keyed ref for (5, 257, 0): refs 1 -> 2, keyed count 1.
        alloc
            .add_data_extent_ref(a.bytenr, a.num_bytes, 5, 257, 0)
            .expect("add keyed ref");
        // Second ref for the SAME (5, 257, 0): must merge, not error.
        alloc
            .add_data_extent_ref(a.bytenr, a.num_bytes, 5, 257, 0)
            .expect("duplicate (root,objectid,offset) ref must merge, not fail");

        // Total EXTENT_ITEM refs is now 3 (1 inline + 2 from the merged keyed ref).
        assert_eq!(
            alloc.extent_item_refs(a.bytenr, a.num_bytes).expect("refs"),
            Some(3)
        );
        // Still exactly ONE keyed EXTENT_DATA_REF, now with count 2.
        let keyed = alloc.get_extent_data_refs(a.bytenr).expect("keyed refs");
        assert_eq!(keyed.len(), 1, "duplicate merged into one keyed item");
        assert_eq!(
            keyed[0],
            BtrfsExtentDataRef {
                root: 5,
                objectid: 257,
                offset: 0,
                count: 2,
            }
        );
    }

    /// bd-vrv1q: removing a reference to a keyed EXTENT_DATA_REF whose count > 1
    /// (merged by bd-ngt1y) must DECREMENT the count and keep the item, only
    /// deleting it on the last reference — otherwise the backref vanishes while
    /// EXTENT_ITEM.refs still counts the rest, and a later decrement fails with
    /// "no matching EXTENT_DATA_REF backref for decrement".
    #[test]
    fn remove_data_extent_ref_decrements_merged_count_bd_vrv1q() {
        let mut alloc = BtrfsExtentAllocator::new(7).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));
        let a = alloc.alloc_data(4096).expect("alloc");
        // refs == 1: inline ref for inode 256.
        alloc
            .insert_data_extent_item(a.bytenr, a.num_bytes, 5, 256, 0, 7)
            .expect("insert refs=1 extent item");
        // Two refs for the SAME (5, 257, 0): merged keyed ref count == 2, refs == 3.
        alloc
            .add_data_extent_ref(a.bytenr, a.num_bytes, 5, 257, 0)
            .expect("first keyed ref");
        alloc
            .add_data_extent_ref(a.bytenr, a.num_bytes, 5, 257, 0)
            .expect("merged keyed ref");
        assert_eq!(
            alloc.extent_item_refs(a.bytenr, a.num_bytes).expect("refs"),
            Some(3)
        );

        // First removal: refs 3 -> 2, keyed item kept with count 1.
        alloc
            .remove_data_extent_ref(a.bytenr, a.num_bytes, 5, 257, 0)
            .expect("decrement merged ref");
        assert_eq!(
            alloc.extent_item_refs(a.bytenr, a.num_bytes).expect("refs"),
            Some(2)
        );
        let keyed = alloc.get_extent_data_refs(a.bytenr).expect("keyed refs");
        assert_eq!(keyed.len(), 1, "keyed ref kept after first decrement");
        assert_eq!(keyed[0].count, 1, "count decremented 2 -> 1");

        // Second removal: refs 2 -> 1, keyed item now deleted (last reference).
        alloc
            .remove_data_extent_ref(a.bytenr, a.num_bytes, 5, 257, 0)
            .expect("remove last keyed ref");
        assert_eq!(
            alloc.extent_item_refs(a.bytenr, a.num_bytes).expect("refs"),
            Some(1)
        );
        assert!(
            alloc.get_extent_data_refs(a.bytenr).expect("keyed refs").is_empty(),
            "keyed ref removed on its last reference"
        );
    }

    #[test]
    fn remove_data_extent_ref_drops_inline_and_keyed_refs() {
        let mut alloc = BtrfsExtentAllocator::new(7).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));
        let a = alloc.alloc_data(4096).expect("alloc");

        // refs == 2: an inline ref for inode 256, a keyed ref for inode 257
        // (a reflink), exactly the form the validated clone path produces.
        alloc
            .insert_data_extent_item(a.bytenr, a.num_bytes, 5, 256, 0, 7)
            .expect("inline ref (inode 256)");
        alloc
            .add_data_extent_ref(a.bytenr, a.num_bytes, 5, 257, 0)
            .expect("keyed ref (inode 257)");
        assert_eq!(
            alloc.extent_item_refs(a.bytenr, a.num_bytes).unwrap(),
            Some(2)
        );

        // Drop the INLINE ref (inode 256): refs 2 -> 1; the keyed ref survives.
        alloc
            .remove_data_extent_ref(a.bytenr, a.num_bytes, 5, 256, 0)
            .expect("drop inline ref");
        assert_eq!(
            alloc.extent_item_refs(a.bytenr, a.num_bytes).unwrap(),
            Some(1)
        );
        let keyed = alloc.get_extent_data_refs(a.bytenr).unwrap();
        assert_eq!(keyed.len(), 1, "keyed ref must survive inline removal");
        assert_eq!(keyed[0].objectid, 257);

        // Drop the KEYED ref (inode 257): refs 1 -> 0; backref removed.
        alloc
            .remove_data_extent_ref(a.bytenr, a.num_bytes, 5, 257, 0)
            .expect("drop keyed ref");
        assert_eq!(
            alloc.extent_item_refs(a.bytenr, a.num_bytes).unwrap(),
            Some(0)
        );
        assert!(alloc.get_extent_data_refs(a.bytenr).unwrap().is_empty());

        // Dropping a ref that isn't present is an atomic error (no change).
        alloc
            .insert_data_extent_item(a.bytenr, a.num_bytes, 5, 256, 0, 7)
            .expect("re-add inline");
        assert!(matches!(
            alloc.remove_data_extent_ref(a.bytenr, a.num_bytes, 5, 999, 0),
            Err(BtrfsMutationError::BrokenInvariant(_))
        ));
    }

    #[test]
    fn alloc_respects_block_group_type() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));
        alloc.add_block_group(0x20_0000, make_meta_bg(0x20_0000, 0x10_0000));

        // Data allocation should go to the data block group.
        let data = alloc.alloc_data(4096).expect("data alloc");
        assert_eq!(data.block_group_start, 0x1_0000);

        // Metadata allocation should go to the metadata block group.
        let meta = alloc.alloc_metadata(4096).expect("meta alloc");
        assert_eq!(meta.block_group_start, 0x20_0000);
    }

    #[test]
    fn alloc_metadata_records_tree_block_ref() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x20_0000, make_meta_bg(0x20_0000, 0x10_0000));

        let meta = alloc
            .alloc_metadata_for_tree(4096, BTRFS_FS_TREE_OBJECTID, 1)
            .expect("metadata alloc");
        // Skinny METADATA_ITEM is keyed by the tree level (1 here), not num_bytes.
        let metadata_key = BtrfsKey {
            objectid: meta.bytenr,
            item_type: BTRFS_ITEM_METADATA_ITEM,
            offset: 1,
        };
        let item = alloc
            .extent_tree
            .range(&metadata_key, &metadata_key)
            .expect("metadata item lookup");
        assert_eq!(item.len(), 1);

        // The TREE_BLOCK_REF backref is carried INLINE in the METADATA_ITEM
        // value: 24-byte extent_item then { u8 type=176, le64 root }.
        let value = &item[0].1;
        assert_eq!(value.len(), 24 + 1 + 8, "skinny extent_item + inline ref");
        assert_eq!(value[24], BTRFS_ITEM_TREE_BLOCK_REF, "inline ref type");
        assert_eq!(
            u64::from_le_bytes(value[25..33].try_into().expect("inline ref root")),
            BTRFS_FS_TREE_OBJECTID,
            "inline ref owning root"
        );
        // No separate TREE_BLOCK_REF item is emitted anymore.
        let ref_key = BtrfsKey {
            objectid: meta.bytenr,
            item_type: BTRFS_ITEM_TREE_BLOCK_REF,
            offset: BTRFS_FS_TREE_OBJECTID,
        };
        assert!(
            alloc
                .extent_tree
                .range(&ref_key, &ref_key)
                .expect("tree block ref lookup")
                .is_empty(),
            "backref must be inline, not a separate item"
        );
        assert_eq!(
            alloc.pending_for(&ExtentKey {
                bytenr: meta.bytenr,
                num_bytes: meta.num_bytes,
            })[0]
                .ref_type,
            BtrfsRef::TreeBlock {
                root: BTRFS_FS_TREE_OBJECTID,
                owner: meta.bytenr,
                offset: meta.num_bytes,
                level: 1,
            }
        );
    }

    #[test]
    fn free_metadata_removes_tree_block_ref() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x20_0000, make_meta_bg(0x20_0000, 0x10_0000));

        let meta = alloc
            .alloc_metadata_for_tree(4096, BTRFS_FS_TREE_OBJECTID, 0)
            .expect("metadata alloc");
        alloc
            .free_extent(meta.bytenr, meta.num_bytes, true)
            .expect("free metadata");

        // Skinny METADATA_ITEM is keyed by the tree level (0 here), not num_bytes.
        let metadata_key = BtrfsKey {
            objectid: meta.bytenr,
            item_type: BTRFS_ITEM_METADATA_ITEM,
            offset: 0,
        };
        let ref_key = BtrfsKey {
            objectid: meta.bytenr,
            item_type: BTRFS_ITEM_TREE_BLOCK_REF,
            offset: BTRFS_FS_TREE_OBJECTID,
        };
        assert!(
            alloc
                .extent_tree
                .range(&metadata_key, &metadata_key)
                .expect("metadata item lookup")
                .is_empty()
        );
        assert!(
            alloc
                .extent_tree
                .range(&ref_key, &ref_key)
                .expect("tree block ref lookup")
                .is_empty()
        );
        assert_eq!(alloc.block_group(0x20_0000).expect("meta bg").used_bytes, 0);
    }

    #[test]
    fn metadata_alloc_uses_mixed_block_group_when_present() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let mixed_start = 0x30_0000;
        alloc.add_block_group(
            mixed_start,
            BtrfsBlockGroupItem {
                total_bytes: 0x10_0000,
                used_bytes: 0,
                flags: BTRFS_BLOCK_GROUP_DATA | BTRFS_BLOCK_GROUP_METADATA,
            },
        );

        let meta = alloc.alloc_metadata(8192).expect("metadata alloc");
        assert_eq!(meta.block_group_start, mixed_start);
        assert_eq!(
            alloc
                .block_group(mixed_start)
                .expect("mixed block group")
                .used_bytes,
            8192
        );
    }

    #[test]
    fn delayed_refs_tracked() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));

        let a1 = alloc.alloc_data(4096).expect("alloc");
        let extent = ExtentKey {
            bytenr: a1.bytenr,
            num_bytes: a1.num_bytes,
        };
        assert_eq!(alloc.delayed_ref_count(), 1);
        assert_eq!(alloc.pending_for(&extent).len(), 1);

        alloc
            .free_extent(a1.bytenr, a1.num_bytes, false)
            .expect("free");
        assert_eq!(alloc.delayed_ref_count(), 2);
        assert_eq!(alloc.pending_for(&extent).len(), 2);

        let refs = alloc.drain_delayed_refs();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].action, RefAction::Insert);
        assert_eq!(refs[0].extent.bytenr, a1.bytenr);
        assert_eq!(refs[1].action, RefAction::Delete);
        assert_eq!(refs[1].extent.bytenr, a1.bytenr);

        // After drain, count is zero.
        assert_eq!(alloc.delayed_ref_count(), 0);
    }

    #[test]
    fn flush_delayed_refs_applies_refcounts() {
        let mut alloc = BtrfsExtentAllocator::new(7).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));

        let a1 = alloc.alloc_data(4096).expect("alloc");
        let extent = ExtentKey {
            bytenr: a1.bytenr,
            num_bytes: a1.num_bytes,
        };

        let flushed = alloc.flush_delayed_refs(1).expect("flush insert");
        assert_eq!(flushed, 1);
        assert_eq!(alloc.delayed_ref_count(), 0);
        assert_eq!(alloc.extent_refcount(extent), 1);

        alloc
            .free_extent(a1.bytenr, a1.num_bytes, false)
            .expect("free");
        let flushed = alloc.flush_delayed_refs(1).expect("flush delete");
        assert_eq!(flushed, 1);
        assert_eq!(alloc.extent_refcount(extent), 0);
    }

    #[test]
    fn flush_delayed_refs_respects_limit() {
        let mut alloc = BtrfsExtentAllocator::new(9).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));

        let a1 = alloc.alloc_data(4096).expect("a1");
        let a2 = alloc.alloc_data(4096).expect("a2");
        let e1 = ExtentKey {
            bytenr: a1.bytenr,
            num_bytes: a1.num_bytes,
        };
        let e2 = ExtentKey {
            bytenr: a2.bytenr,
            num_bytes: a2.num_bytes,
        };

        let flushed = alloc.flush_delayed_refs(1).expect("first flush");
        assert_eq!(flushed, 1);
        assert_eq!(alloc.delayed_ref_count(), 1);
        assert_eq!(alloc.extent_refcount(e1) + alloc.extent_refcount(e2), 1);

        let flushed = alloc.flush_delayed_refs(1).expect("second flush");
        assert_eq!(flushed, 1);
        assert_eq!(alloc.delayed_ref_count(), 0);
        assert_eq!(alloc.extent_refcount(e1), 1);
        assert_eq!(alloc.extent_refcount(e2), 1);
    }

    #[test]
    fn delayed_ref_queue_shared_extent_refcount() {
        let mut queue = DelayedRefQueue::new();
        let extent = ExtentKey {
            bytenr: 0x80_0000,
            num_bytes: 4096,
        };
        queue.queue(
            extent,
            BtrfsRef::DataExtent {
                root: 5,
                objectid: 0x200,
                offset: 0,
            },
            RefAction::Insert,
        );
        queue.queue(
            extent,
            BtrfsRef::SharedDataExtent { parent: 0x1000 },
            RefAction::Insert,
        );

        let mut refcounts = BTreeMap::new();
        let flushed = queue.flush(1024, &mut refcounts).expect("flush");
        assert_eq!(flushed, 2);
        assert_eq!(queue.pending_count(), 0);
        assert_eq!(refcounts.get(&extent), Some(&2));
    }

    #[test]
    fn delayed_ref_queue_stress_10000_refs_flushes_all() {
        let mut queue = DelayedRefQueue::new();
        let mut refcounts = BTreeMap::new();

        for i in 0..10_000_u64 {
            let extent = ExtentKey {
                bytenr: 0x10_0000 + (i * 4096),
                num_bytes: 4096,
            };
            queue.queue(
                extent,
                BtrfsRef::DataExtent {
                    root: 5,
                    objectid: i,
                    offset: 0,
                },
                RefAction::Insert,
            );
        }

        assert_eq!(queue.pending_count(), 10_000);
        let flushed = queue.flush(10_000, &mut refcounts).expect("flush");
        assert_eq!(flushed, 10_000);
        assert_eq!(queue.pending_count(), 0);
        assert_eq!(refcounts.len(), 10_000);
    }

    #[test]
    fn btrfs_tx_begin_abort_discards_staged_updates() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 7, &cx).expect("begin");

        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x2000,
                level: 1,
            },
        );
        txn.stage_block_write(BlockNumber(777), b"transient".to_vec())
            .expect("stage write");
        txn.track_allocation(BlockNumber(900));
        txn.defer_free_on_commit(BlockNumber(901));

        let summary = txn.abort();
        assert_eq!(summary.discarded_tree_updates, 1);
        assert_eq!(summary.released_allocations, vec![BlockNumber(900)]);
        assert_eq!(summary.deferred_frees, vec![BlockNumber(901)]);

        let snapshot = store.current_snapshot();
        assert!(store.read_visible(BlockNumber(777), snapshot).is_none());
    }

    #[test]
    fn btrfs_tx_commit_persists_tree_root_and_payload() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 11, &cx).expect("begin");
        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x55_0000,
                level: 2,
            },
        );
        txn.stage_block_write(BlockNumber(1234), b"hello-btrfs".to_vec())
            .expect("stage payload");
        txn.queue_delayed_ref(
            ExtentKey {
                bytenr: 0x8000,
                num_bytes: 4096,
            },
            BtrfsRef::DataExtent {
                root: BTRFS_FS_TREE_OBJECTID,
                objectid: 256,
                offset: 0,
            },
            RefAction::Insert,
        );

        let commit_seq = txn.commit(&mut store, &cx).expect("commit");
        assert_eq!(commit_seq, CommitSeq(1));

        let snapshot = store.current_snapshot();
        let payload = store
            .read_visible(BlockNumber(1234), snapshot)
            .expect("payload visible");
        assert_eq!(payload.as_ref(), b"hello-btrfs");

        let tree_block =
            BtrfsTransaction::tree_root_block(BTRFS_FS_TREE_OBJECTID).expect("tree block");
        let tree_record = store
            .read_visible(tree_block, snapshot)
            .expect("tree root record");
        assert_eq!(tree_record.len(), 25);
        assert_eq!(
            u64::from_le_bytes(tree_record[0..8].try_into().unwrap()),
            11_u64
        );
        assert_eq!(
            u64::from_le_bytes(tree_record[8..16].try_into().unwrap()),
            BTRFS_FS_TREE_OBJECTID
        );
        assert_eq!(
            u64::from_le_bytes(tree_record[16..24].try_into().unwrap()),
            0x55_0000_u64
        );
        assert_eq!(tree_record[24], 2_u8);
    }

    #[test]
    fn btrfs_tx_disjoint_trees_commit_without_fcw_conflict() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();

        let mut tx1 = BtrfsTransaction::begin(&mut store, 20, &cx).expect("begin tx1");
        let mut tx2 = BtrfsTransaction::begin(&mut store, 20, &cx).expect("begin tx2");

        tx1.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x60_0000,
                level: 1,
            },
        );
        tx2.stage_tree_root(
            BTRFS_EXTENT_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x61_0000,
                level: 0,
            },
        );

        let c1 = tx1.commit(&mut store, &cx).expect("commit tx1");
        let c2 = tx2.commit(&mut store, &cx).expect("commit tx2");
        assert_eq!(c1, CommitSeq(1));
        assert_eq!(c2, CommitSeq(2));
    }

    #[test]
    fn btrfs_tx_same_tree_conflicts_via_fcw() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();

        let mut tx1 = BtrfsTransaction::begin(&mut store, 30, &cx).expect("begin tx1");
        let mut tx2 = BtrfsTransaction::begin(&mut store, 30, &cx).expect("begin tx2");

        tx1.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x70_0000,
                level: 1,
            },
        );
        tx2.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x71_0000,
                level: 1,
            },
        );

        let _ = tx1.commit(&mut store, &cx).expect("tx1 commit");
        let err = tx2.commit(&mut store, &cx).expect_err("tx2 must conflict");
        assert!(
            matches!(
                err,
                BtrfsTransactionError::Commit(CommitError::Conflict { .. })
            ),
            "unexpected error: {err:?}"
        );
        if let BtrfsTransactionError::Commit(CommitError::Conflict { block, .. }) = err {
            let expected =
                BtrfsTransaction::tree_root_block(BTRFS_FS_TREE_OBJECTID).expect("block");
            assert_eq!(block, expected);
        }
    }

    #[test]
    fn btrfs_tx_drop_without_commit_has_no_visible_effect() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        {
            let mut txn = BtrfsTransaction::begin(&mut store, 44, &cx).expect("begin");
            txn.stage_tree_root(
                BTRFS_FS_TREE_OBJECTID,
                TreeRoot {
                    bytenr: 0x80_0000,
                    level: 1,
                },
            );
            txn.stage_block_write(BlockNumber(3210), b"uncommitted".to_vec())
                .expect("stage");
        }

        let snapshot = store.current_snapshot();
        assert!(store.read_visible(BlockNumber(3210), snapshot).is_none());
    }

    #[test]
    fn alloc_fails_when_no_space() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        // Small block group: only 100 bytes.
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 100));

        let result = alloc.alloc_data(200);
        assert!(result.is_err());
    }

    #[test]
    fn total_free_computation() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 1000));
        alloc.add_block_group(0x2_0000, make_data_bg(0x2_0000, 2000));
        alloc.add_block_group(0x3_0000, make_meta_bg(0x3_0000, 500));

        assert_eq!(alloc.total_free(BTRFS_BLOCK_GROUP_DATA), 3000);
        assert_eq!(alloc.total_free(BTRFS_BLOCK_GROUP_METADATA), 500);

        alloc.alloc_data(100).expect("alloc");
        assert_eq!(alloc.total_free(BTRFS_BLOCK_GROUP_DATA), 2900);
    }

    #[test]
    fn free_space_extents_are_the_complement_of_allocations() {
        let mut alloc = BtrfsExtentAllocator::new(7).expect("alloc");
        let bg_start = 0x10_0000_u64;
        let bg_len = 0x1_0000_u64; // 64 KiB metadata group
        alloc.add_block_group(bg_start, make_meta_bg(bg_start, bg_len));

        // An empty group is one free range spanning the whole group.
        let fse = alloc.free_space_extents().expect("fse");
        let bg = fse
            .iter()
            .find(|g| g.start == bg_start)
            .expect("group present");
        assert_eq!(bg.flags, BTRFS_BLOCK_GROUP_METADATA);
        assert_eq!(bg.free_ranges, vec![(bg_start, bg_len)]);

        // Allocate two 16 KiB metadata blocks; the free ranges must be exactly
        // the group span minus the allocations.
        let a = alloc.alloc_metadata(0x4000).expect("a");
        let b = alloc.alloc_metadata(0x4000).expect("b");
        let mut allocated = [
            (a.bytenr, a.bytenr + a.num_bytes),
            (b.bytenr, b.bytenr + b.num_bytes),
        ];
        allocated.sort_unstable();

        let fse = alloc.free_space_extents().expect("fse2");
        let free = fse
            .into_iter()
            .find(|g| g.start == bg_start)
            .expect("group present")
            .free_ranges;

        // Every free range is inside the group, disjoint, sorted, and never
        // overlaps an allocation.
        let mut prev_end = bg_start;
        for &(start, len) in &free {
            let end = start + len;
            assert!(start >= prev_end, "free ranges sorted/disjoint: {free:?}");
            assert!(end <= bg_start + bg_len, "free range within group");
            for &(as_, ae) in &allocated {
                assert!(end <= as_ || start >= ae, "free overlaps allocation");
            }
            prev_end = end;
        }
        // Free + allocated exactly tile the group (no bytes lost or double-counted).
        let free_sum: u64 = free.iter().map(|&(_, l)| l).sum();
        let alloc_sum: u64 = allocated.iter().map(|&(s, e)| e - s).sum();
        assert_eq!(free_sum + alloc_sum, bg_len, "free + allocated tiles group");
        assert_eq!(alloc_sum, 0x8000);
    }

    #[test]
    fn free_space_extents_excludes_loaded_skinny_metadata_items() {
        // Regression (bd-qxo5x): a skinny METADATA_ITEM key encodes the tree
        // LEVEL in its offset, not the byte length. Loaded extents (inserted
        // straight into the extent tree without touching the block-group
        // used_bytes accounting) must still be excluded from free space — the
        // size comes from `nodesize`, not the key offset, or the whole group is
        // wrongly reported free.
        let mut alloc = BtrfsExtentAllocator::new(9).expect("alloc");
        alloc.set_nodesize(0x4000); // 16 KiB nodes
        let bg_start = 0x1d0_0000_u64;
        let bg_len = 0x20_0000_u64;
        alloc.add_block_group(bg_start, make_meta_bg(bg_start, bg_len));

        // Two on-disk tree blocks at level 0 (offset == level), like a mount
        // would load — note used_bytes stays 0, mirroring the loaded state.
        for node in [bg_start, bg_start + 0x8000] {
            let item = BtrfsExtentItem {
                refs: 1,
                generation: 9,
                flags: BtrfsExtentItem::FLAG_TREE_BLOCK,
            };
            let mut value = item.to_bytes();
            value.push(BTRFS_ITEM_TREE_BLOCK_REF);
            value.extend_from_slice(&BTRFS_EXTENT_TREE_OBJECTID.to_le_bytes());
            let key = BtrfsKey {
                objectid: node,
                item_type: BTRFS_ITEM_METADATA_ITEM,
                offset: 0, // level 0 — NOT a byte length
            };
            alloc.extent_tree_mut().insert(key, &value).expect("insert");
        }

        let fse = alloc.free_space_extents().expect("fse");
        let free = fse
            .into_iter()
            .find(|g| g.start == bg_start)
            .expect("group present")
            .free_ranges;
        // The two 16 KiB blocks at bg_start and bg_start+0x8000 must be excluded.
        assert_eq!(
            free,
            vec![
                (bg_start + 0x4000, 0x4000),
                (bg_start + 0xc000, bg_len - 0xc000),
            ],
            "loaded metadata blocks must be excluded from free space"
        );
    }

    #[test]
    fn build_free_space_tree_items_matches_btrfs_layout() {
        let groups = vec![
            BlockGroupFreeSpace {
                start: 0x10_0000,
                total_bytes: 0x40_0000,
                flags: BTRFS_BLOCK_GROUP_DATA,
                free_ranges: vec![(0x10_0000, 0x40_0000)], // wholly free
            },
            BlockGroupFreeSpace {
                start: 0x150_0000,
                total_bytes: 0x80_0000,
                flags: BTRFS_BLOCK_GROUP_METADATA,
                free_ranges: vec![(0x150_0000, 0x4000), (0x160_0000, 0x10_0000)],
            },
        ];
        let items = build_free_space_tree_items(&groups);

        // 2 FREE_SPACE_INFO + 3 FREE_SPACE_EXTENT, globally key-sorted with
        // INFO(198) preceding EXTENT(199) within a block group.
        let k = |o: u64, t: u8, off: u64| BtrfsKey {
            objectid: o,
            item_type: t,
            offset: off,
        };
        let fsi = BTRFS_ITEM_FREE_SPACE_INFO;
        let fse = BTRFS_ITEM_FREE_SPACE_EXTENT;
        let info = |count: u32| {
            let mut v = Vec::with_capacity(8);
            v.extend_from_slice(&count.to_le_bytes());
            v.extend_from_slice(&0_u32.to_le_bytes()); // flags 0 = extent-list
            v
        };
        let expected: Vec<(BtrfsKey, Vec<u8>)> = vec![
            (k(0x10_0000, fsi, 0x40_0000), info(1)),
            (k(0x10_0000, fse, 0x40_0000), Vec::new()),
            (k(0x150_0000, fsi, 0x80_0000), info(2)),
            (k(0x150_0000, fse, 0x4000), Vec::new()),
            (k(0x160_0000, fse, 0x10_0000), Vec::new()),
        ];
        assert_eq!(items, expected);

        // An empty group still emits its FREE_SPACE_INFO with extent_count 0.
        let empty = vec![BlockGroupFreeSpace {
            start: 0x20_0000,
            total_bytes: 0x10_0000,
            flags: BTRFS_BLOCK_GROUP_SYSTEM,
            free_ranges: vec![],
        }];
        let items = build_free_space_tree_items(&empty);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].1, vec![0u8; 8]);
    }

    #[test]
    fn block_group_aggregate_counters_saturate_on_overflow() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(
            0x10_0000,
            BtrfsBlockGroupItem {
                total_bytes: u64::MAX,
                used_bytes: u64::MAX,
                flags: BTRFS_BLOCK_GROUP_DATA,
            },
        );
        alloc.add_block_group(
            0x20_0000,
            BtrfsBlockGroupItem {
                total_bytes: 1,
                used_bytes: 1,
                flags: BTRFS_BLOCK_GROUP_DATA,
            },
        );
        alloc.add_block_group(
            0x30_0000,
            BtrfsBlockGroupItem {
                total_bytes: u64::MAX,
                used_bytes: 0,
                flags: BTRFS_BLOCK_GROUP_METADATA,
            },
        );
        alloc.add_block_group(
            0x40_0000,
            BtrfsBlockGroupItem {
                total_bytes: 1,
                used_bytes: 0,
                flags: BTRFS_BLOCK_GROUP_METADATA,
            },
        );

        assert_eq!(alloc.total_used(), u64::MAX);
        assert_eq!(alloc.total_capacity(), u64::MAX);
        assert_eq!(alloc.total_free(BTRFS_BLOCK_GROUP_METADATA), u64::MAX);
        assert_eq!(
            alloc.total_free(BTRFS_BLOCK_GROUP_DATA | BTRFS_BLOCK_GROUP_METADATA),
            u64::MAX
        );
    }

    #[test]
    fn extent_item_serialization() {
        let item = BtrfsExtentItem {
            refs: 1,
            generation: 42,
            flags: 0,
        };
        let bytes = item.to_bytes();
        assert_eq!(bytes.len(), 24);
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 42);
        assert_eq!(u64::from_le_bytes(bytes[16..24].try_into().unwrap()), 0);
    }

    #[test]
    fn block_group_item_free_bytes() {
        let bg = BtrfsBlockGroupItem {
            total_bytes: 1000,
            used_bytes: 300,
            flags: BTRFS_BLOCK_GROUP_DATA,
        };
        assert_eq!(bg.free_bytes(), 700);
    }

    // ── bd-375.6: btrfs read path unit tests ────────────────────────────

    // Tree Walk Test 1: Walk root tree — all items iterated in key order
    #[test]
    fn readpath_walk_root_tree_key_order() {
        let logical = 0x4000_u64;
        let chunks = identity_chunks();

        // Build a leaf containing 3 ROOT_ITEM entries for different tree objectids.
        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, logical, 3, 0, BTRFS_ROOT_TREE_OBJECTID, 10);

        // ROOT_ITEM for FS tree (objectid=5)
        let root_payload_a = {
            let mut p = vec![0_u8; 239];
            p[176..184].copy_from_slice(&0xAAAA_0000_u64.to_le_bytes());
            p[238] = 0; // level
            p
        };
        // ROOT_ITEM for extent tree (objectid=2)
        let root_payload_b = {
            let mut p = vec![0_u8; 239];
            p[176..184].copy_from_slice(&0xBBBB_0000_u64.to_le_bytes());
            p[238] = 1;
            p
        };
        // ROOT_ITEM for chunk tree (objectid=3)
        let root_payload_c = {
            let mut p = vec![0_u8; 239];
            p[176..184].copy_from_slice(&0xCCCC_0000_u64.to_le_bytes());
            p[238] = 0;
            p
        };

        // Items placed in key order: objectid 2, 3, 5 (all type ROOT_ITEM=132)
        let data_region = NODESIZE as usize - 239 * 3;
        write_leaf_item(
            &mut leaf,
            0,
            BTRFS_EXTENT_TREE_OBJECTID,
            BTRFS_ITEM_ROOT_ITEM,
            u32::try_from(data_region).unwrap(),
            239,
        );
        leaf[data_region..data_region + 239].copy_from_slice(&root_payload_b);

        write_leaf_item(
            &mut leaf,
            1,
            BTRFS_CHUNK_TREE_OBJECTID,
            BTRFS_ITEM_ROOT_ITEM,
            u32::try_from(data_region + 239).unwrap(),
            239,
        );
        leaf[data_region + 239..data_region + 478].copy_from_slice(&root_payload_c);

        write_leaf_item(
            &mut leaf,
            2,
            BTRFS_FS_TREE_OBJECTID,
            BTRFS_ITEM_ROOT_ITEM,
            u32::try_from(data_region + 478).unwrap(),
            239,
        );
        leaf[data_region + 478..data_region + 717].copy_from_slice(&root_payload_a);
        stamp_tree_block_crc32c(&mut leaf);

        let blocks: HashMap<u64, Vec<u8>> = [(logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let entries = walk_tree(&mut read, &chunks, logical, NODESIZE, 0).expect("walk root tree");
        assert_eq!(entries.len(), 3, "expected 3 root tree items");

        // Verify strict key ordering: objectid 2 < 3 < 5
        assert_eq!(entries[0].key.objectid, BTRFS_EXTENT_TREE_OBJECTID);
        assert_eq!(entries[1].key.objectid, BTRFS_CHUNK_TREE_OBJECTID);
        assert_eq!(entries[2].key.objectid, BTRFS_FS_TREE_OBJECTID);

        for entry in &entries {
            assert_eq!(entry.key.item_type, BTRFS_ITEM_ROOT_ITEM);
            let parsed = parse_root_item(&entry.data).expect("parse root item payload");
            assert_ne!(parsed.bytenr, 0, "root item bytenr should be non-zero");
        }

        // Verify specific root items were parsed correctly
        let fs_root = parse_root_item(&entries[2].data).expect("parse FS root");
        assert_eq!(fs_root.bytenr, 0xAAAA_0000);
        assert_eq!(fs_root.level, 0);
    }

    // Tree Walk Test 2: Walk extent tree — all extents found for given inode
    #[test]
    fn readpath_walk_extent_tree_finds_extents_for_inode() {
        let logical = 0x4000_u64;
        let chunks = identity_chunks();

        // Build a leaf with an INODE_ITEM and two EXTENT_DATA items for inode 256,
        // plus an unrelated item for inode 257.
        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, logical, 4, 0, BTRFS_FS_TREE_OBJECTID, 10);

        // Inode 256 INODE_ITEM (160 bytes)
        let inode_payload = vec![0_u8; 160];
        let inode_off = 3200_u32;
        write_leaf_item(&mut leaf, 0, 256, BTRFS_ITEM_INODE_ITEM, inode_off, 160);
        leaf[inode_off as usize..(inode_off + 160) as usize].copy_from_slice(&inode_payload);

        // Inode 256 EXTENT_DATA at offset 0 (inline, 21 + 11 = 32 bytes)
        let inline_payload = BtrfsExtentData::Inline {
            generation: 0,
            ram_bytes: 11,
            compression: BTRFS_COMPRESS_NONE,
            data: b"hello world".to_vec(),
        }
        .to_bytes();
        let ext0_off = 3000_u32;
        write_leaf_item_payload(
            &mut leaf,
            1,
            256,
            BTRFS_ITEM_EXTENT_DATA,
            ext0_off,
            &inline_payload,
        );
        // Set key offset to 0 (file offset)
        let base1 = HEADER_SIZE + ITEM_SIZE;
        leaf[base1 + 9..base1 + 17].copy_from_slice(&0_u64.to_le_bytes());

        // Inode 256 EXTENT_DATA at offset 4096 (regular, 53 bytes)
        let reg_payload = BtrfsExtentData::Regular {
            generation: 0,
            ram_bytes: 4096,
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: BTRFS_COMPRESS_NONE,
            disk_bytenr: 0x10_000,
            disk_num_bytes: 4096,
            extent_offset: 0,
            num_bytes: 4096,
        }
        .to_bytes();
        let ext1_off = 3040_u32;
        write_leaf_item_payload(
            &mut leaf,
            2,
            256,
            BTRFS_ITEM_EXTENT_DATA,
            ext1_off,
            &reg_payload,
        );
        let base2 = HEADER_SIZE + 2 * ITEM_SIZE;
        leaf[base2 + 9..base2 + 17].copy_from_slice(&4096_u64.to_le_bytes());

        // Inode 257 INODE_ITEM (unrelated)
        let ext2_off = 3400_u32;
        write_leaf_item(&mut leaf, 3, 257, BTRFS_ITEM_INODE_ITEM, ext2_off, 160);
        stamp_tree_block_crc32c(&mut leaf);

        let blocks: HashMap<u64, Vec<u8>> = [(logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let all_entries = walk_tree(&mut read, &chunks, logical, NODESIZE, 0).expect("walk");

        // Filter for inode 256 EXTENT_DATA items
        let extents: Vec<_> = all_entries
            .iter()
            .filter(|e| e.key.objectid == 256 && e.key.item_type == BTRFS_ITEM_EXTENT_DATA)
            .collect();

        assert_eq!(
            extents.len(),
            2,
            "expected 2 extent_data items for inode 256"
        );
        assert_eq!(extents[0].key.offset, 0, "first extent at file offset 0");
        assert_eq!(
            extents[1].key.offset, 4096,
            "second extent at file offset 4096"
        );

        // Verify inline extent
        let inline = parse_extent_data(&extents[0].data).expect("parse inline");
        assert!(
            matches!(inline, BtrfsExtentData::Inline { .. }),
            "expected inline extent, got regular"
        );
        if let BtrfsExtentData::Inline { data, .. } = inline {
            assert_eq!(data, b"hello world", "inline extent data mismatch");
        }

        // Verify regular extent
        let regular = parse_extent_data(&extents[1].data).expect("parse regular");
        assert!(
            matches!(regular, BtrfsExtentData::Regular { .. }),
            "expected regular extent, got inline"
        );
        if let BtrfsExtentData::Regular {
            disk_bytenr,
            num_bytes,
            ..
        } = regular
        {
            assert_eq!(disk_bytenr, 0x10_000);
            assert_eq!(num_bytes, 4096);
        }
    }

    // Tree Walk Test 3: Walk directory tree — all dir entries found
    #[test]
    fn readpath_walk_directory_tree_finds_dir_entries() {
        let logical = 0x4000_u64;
        let chunks = identity_chunks();

        // Build a leaf with DIR_ITEM entries for a parent directory (objectid=256).
        let mut leaf = vec![0_u8; NODESIZE as usize];

        // Build two DIR_ITEM payloads
        let name_a = b"file.txt";
        let dir_entry_a = {
            let mut d = vec![0_u8; 30 + name_a.len()];
            d[0..8].copy_from_slice(&257_u64.to_le_bytes()); // child objectid
            d[8] = BTRFS_ITEM_INODE_ITEM; // child key type
            d[17..25].copy_from_slice(&1_u64.to_le_bytes()); // transid
            d[25..27].copy_from_slice(&0_u16.to_le_bytes()); // data_len
            let nl = u16::try_from(name_a.len()).unwrap();
            d[27..29].copy_from_slice(&nl.to_le_bytes()); // name_len
            d[29] = BTRFS_FT_REG_FILE; // file type
            d[30..30 + name_a.len()].copy_from_slice(name_a);
            d
        };

        let name_b = b"subdir";
        let dir_entry_b = {
            let mut d = vec![0_u8; 30 + name_b.len()];
            d[0..8].copy_from_slice(&258_u64.to_le_bytes());
            d[8] = BTRFS_ITEM_INODE_ITEM;
            d[17..25].copy_from_slice(&1_u64.to_le_bytes());
            d[25..27].copy_from_slice(&0_u16.to_le_bytes());
            let nl = u16::try_from(name_b.len()).unwrap();
            d[27..29].copy_from_slice(&nl.to_le_bytes());
            d[29] = BTRFS_FT_DIR;
            d[30..30 + name_b.len()].copy_from_slice(name_b);
            d
        };

        // Place two leaf items
        let file_entry_len = u32::try_from(dir_entry_a.len()).unwrap();
        let subdir_entry_len = u32::try_from(dir_entry_b.len()).unwrap();
        let off_a = 3500_u32;
        let off_b = off_a + file_entry_len;

        write_header(&mut leaf, logical, 2, 0, BTRFS_FS_TREE_OBJECTID, 10);
        write_leaf_item(
            &mut leaf,
            0,
            256,
            BTRFS_ITEM_DIR_ITEM,
            off_a,
            file_entry_len,
        );
        write_leaf_item(
            &mut leaf,
            1,
            256,
            BTRFS_ITEM_DIR_ITEM,
            off_b,
            subdir_entry_len,
        );
        // Set different key offsets (hash of name) so they are distinct items
        let base0 = HEADER_SIZE;
        leaf[base0 + 9..base0 + 17].copy_from_slice(&100_u64.to_le_bytes());
        let base1 = HEADER_SIZE + ITEM_SIZE;
        leaf[base1 + 9..base1 + 17].copy_from_slice(&200_u64.to_le_bytes());

        leaf[off_a as usize..(off_a + file_entry_len) as usize].copy_from_slice(&dir_entry_a);
        leaf[off_b as usize..(off_b + subdir_entry_len) as usize].copy_from_slice(&dir_entry_b);
        stamp_tree_block_crc32c(&mut leaf);

        let blocks: HashMap<u64, Vec<u8>> = [(logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let entries = walk_tree(&mut read, &chunks, logical, NODESIZE, 0).expect("walk");

        // Filter DIR_ITEM entries
        let dir_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.key.item_type == BTRFS_ITEM_DIR_ITEM)
            .collect();
        assert_eq!(dir_entries.len(), 2);

        let parsed_a = parse_dir_items(&dir_entries[0].data).expect("parse dir_item a");
        assert_eq!(parsed_a.len(), 1);
        assert_eq!(parsed_a[0].child_objectid, 257);
        assert_eq!(parsed_a[0].file_type, BTRFS_FT_REG_FILE);
        assert_eq!(parsed_a[0].name, b"file.txt");

        let parsed_b = parse_dir_items(&dir_entries[1].data).expect("parse dir_item b");
        assert_eq!(parsed_b.len(), 1);
        assert_eq!(parsed_b[0].child_objectid, 258);
        assert_eq!(parsed_b[0].file_type, BTRFS_FT_DIR);
        assert_eq!(parsed_b[0].name, b"subdir");
    }

    // Tree Walk Test 4: Walk with corrupt node — CRC mismatch detected
    #[test]
    fn readpath_walk_corrupt_node_crc_mismatch() {
        // Build a valid tree block with correct CRC, then corrupt it.
        let mut block = vec![0_u8; NODESIZE as usize];
        write_header(&mut block, 0x4000, 0, 0, BTRFS_FS_TREE_OBJECTID, 10);

        // Compute valid CRC32C and store it
        let csum = ffs_types::crc32c(&block[0x20..]);
        block[0..4].copy_from_slice(&csum.to_le_bytes());

        // Verify the block passes CRC check before corruption
        verify_tree_block_checksum(&block, ffs_types::BTRFS_CSUM_TYPE_CRC32C)
            .expect("CRC should be valid before corruption");

        // Corrupt a byte in the payload area
        block[0x50] ^= 0xFF;

        // Now CRC check should fail
        let err =
            verify_tree_block_checksum(&block, ffs_types::BTRFS_CSUM_TYPE_CRC32C).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "tree_block_csum",
                    reason: "CRC32C checksum mismatch",
                }
            ),
            "expected CRC mismatch error, got: {err:?}"
        );
    }

    // Tree Walk Test 5: Walk empty tree — no items, no error
    #[test]
    fn readpath_walk_empty_tree_no_items() {
        let logical = 0x8000_u64;
        let chunks = identity_chunks();

        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, logical, 0, 0, BTRFS_FS_TREE_OBJECTID, 1);
        stamp_tree_block_crc32c(&mut leaf);

        let blocks: HashMap<u64, Vec<u8>> = [(logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let entries = walk_tree(&mut read, &chunks, logical, NODESIZE, 0).expect("walk empty tree");
        assert!(entries.is_empty(), "empty tree should yield no items");
    }

    // Extent Read Test 6: Read inline extent — small file data correct
    #[test]
    fn readpath_parse_inline_extent_small_file() {
        let file_data = b"tiny inline file";
        let mut payload = vec![0_u8; 21 + file_data.len()];
        // generation(8) + ram_bytes(8) + compression(1) + encryption(1) + other_encoding(2) + type(1)
        payload[0..8].copy_from_slice(&1_u64.to_le_bytes()); // generation
        payload[8..16].copy_from_slice(&(file_data.len() as u64).to_le_bytes()); // ram_bytes
        payload[16] = 0; // compression = none
        payload[17] = 0; // encryption
        payload[18..20].copy_from_slice(&0_u16.to_le_bytes()); // other_encoding
        payload[20] = BTRFS_FILE_EXTENT_INLINE; // type
        payload[21..].copy_from_slice(file_data);

        let parsed = parse_extent_data(&payload).expect("parse inline extent");
        assert!(
            matches!(parsed, BtrfsExtentData::Inline { .. }),
            "expected inline extent, got regular"
        );
        if let BtrfsExtentData::Inline {
            compression, data, ..
        } = parsed
        {
            assert_eq!(compression, 0, "should be uncompressed");
            assert_eq!(data, file_data, "inline data mismatch");
        }
    }

    // Extent Read Test 7: Read regular extent — block data correct
    #[test]
    fn readpath_parse_regular_extent_block_data() {
        let mut payload = [0_u8; 53];
        payload[0..8].copy_from_slice(&5_u64.to_le_bytes()); // generation
        payload[8..16].copy_from_slice(&8192_u64.to_le_bytes()); // ram_bytes
        payload[16] = 0; // compression
        payload[20] = BTRFS_FILE_EXTENT_REG;
        payload[21..29].copy_from_slice(&0x20_0000_u64.to_le_bytes()); // disk_bytenr
        payload[29..37].copy_from_slice(&8192_u64.to_le_bytes()); // disk_num_bytes
        payload[37..45].copy_from_slice(&0_u64.to_le_bytes()); // extent_offset
        payload[45..53].copy_from_slice(&8192_u64.to_le_bytes()); // num_bytes

        let parsed = parse_extent_data(&payload).expect("parse regular extent");
        assert!(
            matches!(parsed, BtrfsExtentData::Regular { .. }),
            "expected regular extent, got inline"
        );
        if let BtrfsExtentData::Regular {
            extent_type,
            compression,
            disk_bytenr,
            disk_num_bytes,
            extent_offset,
            num_bytes,
            ..
        } = parsed
        {
            assert_eq!(extent_type, BTRFS_FILE_EXTENT_REG);
            assert_eq!(compression, 0);
            assert_eq!(disk_bytenr, 0x20_0000);
            assert_eq!(disk_num_bytes, 8192);
            assert_eq!(extent_offset, 0);
            assert_eq!(num_bytes, 8192);
        }
    }

    // Extent Read Test 8: Read compressed extent — compression field correct
    #[test]
    fn readpath_parse_compressed_extent_fields() {
        let mut payload = [0_u8; 53];
        payload[0..8].copy_from_slice(&3_u64.to_le_bytes()); // generation
        payload[8..16].copy_from_slice(&16384_u64.to_le_bytes()); // ram_bytes (uncompressed)
        payload[16] = 1; // compression = zlib
        payload[20] = BTRFS_FILE_EXTENT_REG;
        payload[21..29].copy_from_slice(&0x30_0000_u64.to_le_bytes()); // disk_bytenr
        payload[29..37].copy_from_slice(&4096_u64.to_le_bytes()); // disk_num_bytes (compressed)
        payload[37..45].copy_from_slice(&0_u64.to_le_bytes()); // extent_offset
        payload[45..53].copy_from_slice(&16384_u64.to_le_bytes()); // num_bytes

        let parsed = parse_extent_data(&payload).expect("parse compressed extent");
        assert!(
            matches!(parsed, BtrfsExtentData::Regular { .. }),
            "expected regular extent, got inline"
        );
        if let BtrfsExtentData::Regular {
            extent_type,
            compression,
            disk_bytenr,
            disk_num_bytes,
            num_bytes,
            ..
        } = parsed
        {
            assert_eq!(extent_type, BTRFS_FILE_EXTENT_REG);
            assert_eq!(compression, 1, "compression should be zlib (1)");
            assert_eq!(disk_bytenr, 0x30_0000);
            assert_eq!(
                disk_num_bytes, 4096,
                "compressed on-disk size should be smaller"
            );
            assert_eq!(num_bytes, 16384, "logical extent size");
        }
    }

    // Extent Read Test 9: Read prealloc extent — zeros returned
    #[test]
    fn readpath_parse_prealloc_extent_zeros() {
        let mut payload = [0_u8; 53];
        payload[0..8].copy_from_slice(&2_u64.to_le_bytes()); // generation
        payload[8..16].copy_from_slice(&65536_u64.to_le_bytes()); // ram_bytes
        payload[16] = 0; // no compression
        payload[20] = BTRFS_FILE_EXTENT_PREALLOC;
        // Prealloc extents have a disk_bytenr pointing to allocated but unwritten space.
        payload[21..29].copy_from_slice(&0x40_0000_u64.to_le_bytes()); // disk_bytenr
        payload[29..37].copy_from_slice(&65536_u64.to_le_bytes()); // disk_num_bytes
        payload[37..45].copy_from_slice(&0_u64.to_le_bytes()); // extent_offset
        payload[45..53].copy_from_slice(&65536_u64.to_le_bytes()); // num_bytes

        let parsed = parse_extent_data(&payload).expect("parse prealloc extent");
        assert!(
            matches!(parsed, BtrfsExtentData::Regular { .. }),
            "expected prealloc extent, got inline"
        );
        if let BtrfsExtentData::Regular {
            extent_type,
            compression,
            disk_bytenr,
            num_bytes,
            ..
        } = parsed
        {
            assert_eq!(
                extent_type, BTRFS_FILE_EXTENT_PREALLOC,
                "should be PREALLOC type"
            );
            assert_eq!(compression, 0, "prealloc extents are uncompressed");
            assert_eq!(disk_bytenr, 0x40_0000);
            assert_eq!(num_bytes, 65536);
        }
    }

    // Directory Listing Test 10: List root directory — all entries present
    #[test]
    fn readpath_list_root_directory_all_entries() {
        // Build a DIR_ITEM payload with 3 entries packed together
        let names: &[(&[u8], u64, u8)] = &[
            (b"bin", 257, BTRFS_FT_DIR),
            (b"etc", 258, BTRFS_FT_DIR),
            (b"init", 259, BTRFS_FT_REG_FILE),
        ];

        // Build separate DIR_ITEM payloads for each name (each is a separate leaf item)
        let mut payloads = Vec::new();
        for &(name, child_oid, ftype) in names {
            let mut d = vec![0_u8; 30 + name.len()];
            d[0..8].copy_from_slice(&child_oid.to_le_bytes());
            d[8] = BTRFS_ITEM_INODE_ITEM;
            d[17..25].copy_from_slice(&1_u64.to_le_bytes()); // transid
            d[25..27].copy_from_slice(&0_u16.to_le_bytes()); // data_len
            let nl = u16::try_from(name.len()).unwrap();
            d[27..29].copy_from_slice(&nl.to_le_bytes());
            d[29] = ftype;
            d[30..30 + name.len()].copy_from_slice(name);
            payloads.push(d);
        }

        // Parse each payload independently
        for (i, &(name, child_oid, ftype)) in names.iter().enumerate() {
            let parsed = parse_dir_items(&payloads[i]).expect("parse dir entry");
            assert_eq!(parsed.len(), 1);
            assert_eq!(parsed[0].child_objectid, child_oid);
            assert_eq!(parsed[0].file_type, ftype);
            assert_eq!(parsed[0].name, name);
        }

        // Also test parsing two entries concatenated in a single DIR_ITEM payload
        let mut combined = payloads[0].clone();
        combined.extend_from_slice(&payloads[1]);
        let parsed_combined = parse_dir_items(&combined).expect("parse combined dir entries");
        assert_eq!(parsed_combined.len(), 2);
        assert_eq!(parsed_combined[0].name, b"bin");
        assert_eq!(parsed_combined[1].name, b"etc");
    }

    // Directory Listing Test 11: List subdirectory — correct entries, correct types
    #[test]
    fn readpath_list_subdirectory_correct_types() {
        // Build DIR_ITEM payloads for a subdirectory with various file types
        let entries: &[(&[u8], u64, u8)] = &[
            (b"regular.dat", 300, BTRFS_FT_REG_FILE),
            (b"nested", 301, BTRFS_FT_DIR),
            (b"link", 302, BTRFS_FT_SYMLINK),
            (b"socket", 303, BTRFS_FT_SOCK),
        ];

        for &(name, child_oid, ftype) in entries {
            let mut d = vec![0_u8; 30 + name.len()];
            d[0..8].copy_from_slice(&child_oid.to_le_bytes());
            d[8] = BTRFS_ITEM_INODE_ITEM;
            d[17..25].copy_from_slice(&1_u64.to_le_bytes());
            d[25..27].copy_from_slice(&0_u16.to_le_bytes());
            let nl = u16::try_from(name.len()).unwrap();
            d[27..29].copy_from_slice(&nl.to_le_bytes());
            d[29] = ftype;
            d[30..30 + name.len()].copy_from_slice(name);

            let parsed = parse_dir_items(&d).expect("parse dir entry");
            assert_eq!(parsed.len(), 1, "each payload has one entry");
            assert_eq!(
                parsed[0].child_objectid, child_oid,
                "child objectid mismatch for {name:?}"
            );
            assert_eq!(
                parsed[0].file_type, ftype,
                "file type mismatch for {name:?}"
            );
            assert_eq!(parsed[0].name, name, "name mismatch");
        }
    }

    // Directory Listing Test 12: List empty directory — no entries (beyond . and ..)
    #[test]
    fn readpath_list_empty_directory_no_entries() {
        // An empty directory has no DIR_ITEM payloads (. and .. are implicit in btrfs).
        // parse_dir_items with empty input should return an empty vec.
        let parsed = parse_dir_items(&[]).expect("parse empty dir items");
        assert!(
            parsed.is_empty(),
            "empty directory should have no dir item entries"
        );
    }

    // Logical-Physical Mapping Test 13: Single-device mapping — logical → physical correct
    #[test]
    fn readpath_single_device_mapping_correct() {
        // Single chunk: logical range [1MiB, 9MiB) maps to physical [2MiB, 10MiB)
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0x10_0000, // logical start = 1 MiB
            },
            length: 0x80_0000, // 8 MiB
            owner: 2,
            stripe_len: 0x1_0000,
            chunk_type: 1, // DATA
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: 1,
            sub_stripes: 0,
            stripes: vec![BtrfsStripe {
                devid: 1,
                offset: 0x20_0000, // physical start = 2 MiB
                dev_uuid: [0; 16],
            }],
        }];

        // Test exact start of chunk
        let m0 = map_logical_to_physical(&chunks, 0x10_0000)
            .expect("no error")
            .expect("should map");
        assert_eq!(m0.devid, 1);
        assert_eq!(
            m0.physical, 0x20_0000,
            "start of chunk maps to start of stripe"
        );

        // Test middle of chunk
        let m1 = map_logical_to_physical(&chunks, 0x10_0000 + 0x4_0000)
            .expect("no error")
            .expect("should map");
        assert_eq!(m1.physical, 0x20_0000 + 0x4_0000);

        // Test end-1 of chunk
        let m2 = map_logical_to_physical(&chunks, 0x10_0000 + 0x80_0000 - 1)
            .expect("no error")
            .expect("should map");
        assert_eq!(m2.physical, 0x20_0000 + 0x80_0000 - 1);

        // Test just past end — should be None
        let m3 = map_logical_to_physical(&chunks, 0x10_0000 + 0x80_0000).expect("no error");
        assert!(m3.is_none(), "address past chunk end should not map");

        // Test before start — should be None
        let m4 = map_logical_to_physical(&chunks, 0x0F_FFFF).expect("no error");
        assert!(m4.is_none(), "address before chunk start should not map");
    }

    // Logical-Physical Mapping Test 14: sys_chunk mapping — bootstrap chunks resolve
    #[test]
    fn readpath_sys_chunk_mapping_bootstrap_resolves() {
        // Build a sys_chunk_array entry manually, parse it, then use for mapping.
        // disk_key (17) + chunk_fixed (48) + 1 stripe (32) = 97 bytes
        let mut sys_array = vec![0_u8; 97];

        // disk_key: objectid=256, type=228 (CHUNK_ITEM), offset=0x100_0000 (logical start 16 MiB)
        sys_array[0..8].copy_from_slice(&256_u64.to_le_bytes());
        sys_array[8] = 228;
        sys_array[9..17].copy_from_slice(&0x100_0000_u64.to_le_bytes());

        // chunk header: length=8MiB, owner=2, stripe_len=64K, type=SYSTEM(2)
        let c = 17;
        sys_array[c..c + 8].copy_from_slice(&(8 * 1024 * 1024_u64).to_le_bytes()); // length
        sys_array[c + 8..c + 16].copy_from_slice(&2_u64.to_le_bytes()); // owner
        sys_array[c + 16..c + 24].copy_from_slice(&(64 * 1024_u64).to_le_bytes()); // stripe_len
        sys_array[c + 24..c + 32].copy_from_slice(&2_u64.to_le_bytes()); // chunk_type
        sys_array[c + 32..c + 36].copy_from_slice(&4096_u32.to_le_bytes()); // io_align
        sys_array[c + 36..c + 40].copy_from_slice(&4096_u32.to_le_bytes()); // io_width
        sys_array[c + 40..c + 44].copy_from_slice(&4096_u32.to_le_bytes()); // sector_size
        sys_array[c + 44..c + 46].copy_from_slice(&1_u16.to_le_bytes()); // num_stripes
        sys_array[c + 46..c + 48].copy_from_slice(&0_u16.to_le_bytes()); // sub_stripes

        // stripe: devid=1, offset=0x80_0000 (physical start 8 MiB)
        let s = c + 48;
        sys_array[s..s + 8].copy_from_slice(&1_u64.to_le_bytes()); // devid
        sys_array[s + 8..s + 16].copy_from_slice(&0x80_0000_u64.to_le_bytes()); // offset

        // Parse the sys_chunk_array
        let chunks = parse_sys_chunk_array(&sys_array).expect("parse sys_chunk_array");
        assert_eq!(chunks.len(), 1, "should parse one chunk");
        assert_eq!(chunks[0].key.offset, 0x100_0000);
        assert_eq!(chunks[0].length, 8 * 1024 * 1024);
        assert_eq!(chunks[0].stripes[0].offset, 0x80_0000);

        // Use the parsed chunks for logical → physical mapping
        let mapping = map_logical_to_physical(&chunks, 0x100_0000 + 0x1000)
            .expect("no error")
            .expect("should resolve via bootstrap chunks");
        assert_eq!(mapping.devid, 1);
        assert_eq!(
            mapping.physical,
            0x80_0000 + 0x1000,
            "bootstrap chunk should resolve logical to physical"
        );

        // Verify unmapped address outside the sys_chunk range
        let miss = map_logical_to_physical(&chunks, 0x200_0000).expect("no error");
        assert!(miss.is_none(), "address outside sys_chunk should not map");
    }

    fn make_chunk_item_payload(
        length: u64,
        stripe_len: u64,
        chunk_type: u64,
        num_stripes: u16,
    ) -> Vec<u8> {
        const CHUNK_FIXED: usize = 48;
        const STRIPE_SIZE: usize = 32;

        let stripe_count = usize::from(num_stripes);
        let mut data = vec![0_u8; CHUNK_FIXED + stripe_count * STRIPE_SIZE];
        data[0..8].copy_from_slice(&length.to_le_bytes());
        data[8..16].copy_from_slice(&2_u64.to_le_bytes());
        data[16..24].copy_from_slice(&stripe_len.to_le_bytes());
        data[24..32].copy_from_slice(&chunk_type.to_le_bytes());
        data[32..36].copy_from_slice(&4096_u32.to_le_bytes());
        data[36..40].copy_from_slice(&4096_u32.to_le_bytes());
        data[40..44].copy_from_slice(&4096_u32.to_le_bytes());
        data[44..46].copy_from_slice(&num_stripes.to_le_bytes());
        data[46..48].copy_from_slice(&0_u16.to_le_bytes());

        for stripe_idx in 0..stripe_count {
            let stripe_off = CHUNK_FIXED + stripe_idx * STRIPE_SIZE;
            let devid = u64::try_from(stripe_idx + 1).expect("test stripe index fits u64");
            let physical = 0x80_0000_u64
                + u64::try_from(stripe_idx).expect("test stripe index fits u64") * 0x10_0000;
            let uuid_byte = 0xa0_u8
                .checked_add(u8::try_from(stripe_idx).expect("test stripe index fits u8"))
                .expect("test stripe uuid byte fits u8");
            data[stripe_off..stripe_off + 8].copy_from_slice(&devid.to_le_bytes());
            data[stripe_off + 8..stripe_off + 16].copy_from_slice(&physical.to_le_bytes());
            data[stripe_off + 16..stripe_off + 32].fill(uuid_byte);
        }

        data
    }

    #[test]
    fn parse_chunk_item_adversarial_samples_exercise_boundaries() {
        let chunk_type =
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0;
        let data = make_chunk_item_payload(8 * 1024 * 1024, 64 * 1024, chunk_type, 2);
        let parsed = parse_chunk_item(&data, 0x100_0000).expect("parse multi-stripe chunk");
        assert_eq!(parsed.key.objectid, BTRFS_CHUNK_TREE_OBJECTID);
        assert_eq!(parsed.key.item_type, BTRFS_ITEM_CHUNK);
        assert_eq!(parsed.key.offset, 0x100_0000);
        assert_eq!(parsed.length, 8 * 1024 * 1024);
        assert_eq!(parsed.stripe_len, 64 * 1024);
        assert_eq!(parsed.chunk_type, chunk_type);
        assert_eq!(parsed.io_align, 4096);
        assert_eq!(parsed.io_width, 4096);
        assert_eq!(parsed.sector_size, 4096);
        assert_eq!(parsed.num_stripes, 2);
        assert_eq!(parsed.stripes.len(), 2);
        assert_eq!(parsed.stripes[0].devid, 1);
        assert_eq!(parsed.stripes[0].offset, 0x80_0000);
        assert_eq!(parsed.stripes[0].dev_uuid, [0xa0; 16]);
        assert_eq!(parsed.stripes[1].devid, 2);
        assert_eq!(parsed.stripes[1].offset, 0x90_0000);
        assert_eq!(parsed.stripes[1].dev_uuid, [0xa1; 16]);

        assert_insufficient_data(parse_chunk_item(&data[..47], 0x100_0000), 48, 0, 47);

        let mut truncated_stripe = data;
        truncated_stripe.truncate(48 + 31);
        assert_insufficient_data(parse_chunk_item(&truncated_stripe, 0x100_0000), 112, 48, 79);

        let mut trailing_stripe_payload =
            make_chunk_item_payload(8 * 1024 * 1024, 64 * 1024, chunk_type, 1);
        trailing_stripe_payload.extend_from_slice(b"extra");
        assert_invalid_field(
            parse_chunk_item(&trailing_stripe_payload, 0x100_0000),
            "stripes",
            "does not match declared stripe count",
        );

        let zero_stripes = make_chunk_item_payload(8 * 1024 * 1024, 64 * 1024, chunk_type, 0);
        assert_invalid_field(
            parse_chunk_item(&zero_stripes, 0x100_0000),
            "stripes",
            "chunk has no stripes",
        );

        let zero_length = make_chunk_item_payload(0, 64 * 1024, chunk_type, 1);
        assert_invalid_field(
            parse_chunk_item(&zero_length, 0x100_0000),
            "chunk_length",
            "chunk has zero length",
        );

        let zero_stripe_len = make_chunk_item_payload(8 * 1024 * 1024, 0, chunk_type, 1);
        assert_invalid_field(
            parse_chunk_item(&zero_stripe_len, 0x100_0000),
            "stripe_len",
            "chunk has zero stripe length",
        );

        let mut zero_io_align = make_chunk_item_payload(8 * 1024 * 1024, 64 * 1024, chunk_type, 1);
        zero_io_align[32..36].copy_from_slice(&0_u32.to_le_bytes());
        assert_invalid_field(
            parse_chunk_item(&zero_io_align, 0x100_0000),
            "io_align",
            "must be non-zero",
        );

        let mut zero_io_width = make_chunk_item_payload(8 * 1024 * 1024, 64 * 1024, chunk_type, 1);
        zero_io_width[36..40].copy_from_slice(&0_u32.to_le_bytes());
        assert_invalid_field(
            parse_chunk_item(&zero_io_width, 0x100_0000),
            "io_width",
            "must be non-zero",
        );

        let mut zero_sector_size =
            make_chunk_item_payload(8 * 1024 * 1024, 64 * 1024, chunk_type, 1);
        zero_sector_size[40..44].copy_from_slice(&0_u32.to_le_bytes());
        assert_invalid_field(
            parse_chunk_item(&zero_sector_size, 0x100_0000),
            "sector_size",
            "must be non-zero",
        );

        let mut zero_stripe_devid =
            make_chunk_item_payload(8 * 1024 * 1024, 64 * 1024, chunk_type, 1);
        zero_stripe_devid[48..56].copy_from_slice(&0_u64.to_le_bytes());
        assert_invalid_field(
            parse_chunk_item(&zero_stripe_devid, 0x100_0000),
            "stripe_devid",
            "must be non-zero",
        );

        let multi_raid_type = chunk_type_flags::BTRFS_BLOCK_GROUP_DATA
            | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0
            | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1;
        let multi_raid = make_chunk_item_payload(8 * 1024 * 1024, 64 * 1024, multi_raid_type, 1);
        assert_invalid_field(
            parse_chunk_item(&multi_raid, 0x100_0000),
            "chunk_type",
            "multiple RAID profiles set",
        );
    }

    #[test]
    fn parse_chunk_item_rejects_zero_stripe_len() {
        const CHUNK_FIXED: usize = 48;
        const STRIPE_SIZE: usize = 32;
        let mut data = vec![0_u8; CHUNK_FIXED + STRIPE_SIZE];

        data[0..8].copy_from_slice(&(8 * 1024 * 1024_u64).to_le_bytes()); // length
        data[8..16].copy_from_slice(&2_u64.to_le_bytes()); // owner
        data[16..24].copy_from_slice(&0_u64.to_le_bytes()); // stripe_len (invalid)
        data[24..32].copy_from_slice(&2_u64.to_le_bytes()); // chunk_type
        data[32..36].copy_from_slice(&4096_u32.to_le_bytes()); // io_align
        data[36..40].copy_from_slice(&4096_u32.to_le_bytes()); // io_width
        data[40..44].copy_from_slice(&4096_u32.to_le_bytes()); // sector_size
        data[44..46].copy_from_slice(&1_u16.to_le_bytes()); // num_stripes
        data[46..48].copy_from_slice(&0_u16.to_le_bytes()); // sub_stripes

        let s = CHUNK_FIXED;
        data[s..s + 8].copy_from_slice(&1_u64.to_le_bytes()); // devid
        data[s + 8..s + 16].copy_from_slice(&0x80_0000_u64.to_le_bytes()); // offset

        let err = parse_chunk_item(&data, 0x100_0000).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "stripe_len",
                ..
            }
        ));
    }

    #[test]
    fn parse_chunk_item_rejects_zero_length() {
        const CHUNK_FIXED: usize = 48;
        const STRIPE_SIZE: usize = 32;
        let mut data = vec![0_u8; CHUNK_FIXED + STRIPE_SIZE];

        data[0..8].copy_from_slice(&0_u64.to_le_bytes()); // length (invalid)
        data[8..16].copy_from_slice(&2_u64.to_le_bytes()); // owner
        data[16..24].copy_from_slice(&4096_u64.to_le_bytes()); // stripe_len
        data[24..32].copy_from_slice(&2_u64.to_le_bytes()); // chunk_type
        data[32..36].copy_from_slice(&4096_u32.to_le_bytes()); // io_align
        data[36..40].copy_from_slice(&4096_u32.to_le_bytes()); // io_width
        data[40..44].copy_from_slice(&4096_u32.to_le_bytes()); // sector_size
        data[44..46].copy_from_slice(&1_u16.to_le_bytes()); // num_stripes
        data[46..48].copy_from_slice(&0_u16.to_le_bytes()); // sub_stripes

        let s = CHUNK_FIXED;
        data[s..s + 8].copy_from_slice(&1_u64.to_le_bytes()); // devid
        data[s + 8..s + 16].copy_from_slice(&0x80_0000_u64.to_le_bytes()); // offset

        let err = parse_chunk_item(&data, 0x100_0000).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "chunk_length",
                ..
            }
        ));
    }

    // ── bd-29z.2: btrfs write path unit tests ───────────────────────────

    // Extent Allocation Test 1: Allocate extent returns valid block range
    #[test]
    fn writepath_alloc_extent_returns_valid_block_range() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = 0x10_0000_u64;
        let bg_size = 0x100_000_u64; // 1 MiB
        alloc.add_block_group(bg_start, make_data_bg(bg_start, bg_size));

        let extent = alloc.alloc_data(4096).expect("alloc data");

        // Returned bytenr must lie within the block group
        assert!(
            extent.bytenr >= bg_start,
            "bytenr {:#x} should be >= block group start {bg_start:#x}",
            extent.bytenr
        );
        assert!(
            extent.bytenr + extent.num_bytes <= bg_start + bg_size,
            "extent end {:#x} should not exceed block group end {:#x}",
            extent.bytenr + extent.num_bytes,
            bg_start + bg_size
        );
        assert_eq!(
            extent.num_bytes, 4096,
            "allocated size should match request"
        );
        assert_eq!(extent.block_group_start, bg_start);
    }

    // Extent Allocation Test 2: Free extent returns blocks to free space
    #[test]
    fn writepath_free_extent_returns_blocks_to_free_space() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = 0x10_0000_u64;
        let bg_size = 0x100_000_u64;
        alloc.add_block_group(bg_start, make_data_bg(bg_start, bg_size));

        let a1 = alloc.alloc_data(8192).expect("alloc");
        let bg_after_alloc = *alloc.block_group(bg_start).expect("bg");
        assert_eq!(bg_after_alloc.used_bytes, 8192);
        assert_eq!(bg_after_alloc.free_bytes(), bg_size - 8192);

        alloc
            .free_extent(a1.bytenr, a1.num_bytes, false)
            .expect("free");
        let bg_after_free = alloc.block_group(bg_start).expect("bg");
        assert_eq!(
            bg_after_free.used_bytes, 0,
            "used should be zero after free"
        );
        assert_eq!(
            bg_after_free.free_bytes(),
            bg_size,
            "all space should be free"
        );
    }

    // Extent Allocation Test 3: Double-free detected — error returned
    #[test]
    fn writepath_double_free_detected() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, 0x100_000));

        let a1 = alloc.alloc_data(4096).expect("alloc");
        alloc
            .free_extent(a1.bytenr, a1.num_bytes, false)
            .expect("first free should succeed");

        // Second free of the same extent should fail (key already deleted from extent tree).
        let err = alloc
            .free_extent(a1.bytenr, a1.num_bytes, false)
            .expect_err("double free should be detected");
        assert_eq!(
            err,
            BtrfsMutationError::KeyNotFound,
            "double free should return KeyNotFound, got: {err:?}"
        );
    }

    // Extent Allocation Test 4: Allocate when full — ENOSPC returned
    #[test]
    fn writepath_alloc_when_full_enospc() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        // Block group with only 256 bytes of space.
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, 256));

        // First allocation fits.
        alloc.alloc_data(128).expect("first alloc should fit");

        // Second allocation exceeds remaining space.
        let err = alloc
            .alloc_data(256)
            .expect_err("allocating beyond capacity should fail");
        assert_eq!(err, BtrfsMutationError::NoSpace);
    }

    // Extent Allocation Test 5: Allocation respects block group boundaries
    #[test]
    fn writepath_alloc_respects_block_group_boundaries() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let data_bg = 0x10_0000_u64;
        let meta_bg = 0x20_0000_u64;
        alloc.add_block_group(data_bg, make_data_bg(data_bg, 0x100_000));
        alloc.add_block_group(meta_bg, make_meta_bg(meta_bg, 0x100_000));

        // Data allocation lands in data block group.
        let data_ext = alloc.alloc_data(4096).expect("data alloc");
        assert_eq!(
            data_ext.block_group_start, data_bg,
            "data extent should come from data block group"
        );
        assert!(data_ext.bytenr >= data_bg && data_ext.bytenr < data_bg + 0x100_000);

        // Metadata allocation lands in metadata block group.
        let meta_ext = alloc.alloc_metadata(4096).expect("meta alloc");
        assert_eq!(
            meta_ext.block_group_start, meta_bg,
            "metadata extent should come from metadata block group"
        );
        assert!(meta_ext.bytenr >= meta_bg && meta_ext.bytenr < meta_bg + 0x100_000);

        // Verify no cross-contamination: data BG only has data usage, meta BG only meta.
        let data_used = alloc.block_group(data_bg).expect("data bg").used_bytes;
        let meta_used = alloc.block_group(meta_bg).expect("meta bg").used_bytes;
        assert_eq!(data_used, 4096, "data bg should only have data allocation");
        assert_eq!(
            meta_used, 4096,
            "meta bg should only have metadata allocation"
        );
    }

    // COW Test 6: COW write preserves original block, allocates new
    #[test]
    fn writepath_cow_write_preserves_original() {
        let mut tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        let key = test_key(42);

        tree.insert(key, b"original").expect("insert");
        let root_v1 = tree.root_block();
        let snapshot_v1 = tree.node_snapshot(root_v1).expect("snapshot v1");

        // Update (COW write) should allocate a new root, old root preserved.
        tree.update(&key, b"modified").expect("update");
        let root_v2 = tree.root_block();

        assert_ne!(root_v1, root_v2, "COW update should allocate new root");
        assert_eq!(
            tree.node_snapshot(root_v1).expect("old snapshot"),
            snapshot_v1,
            "original root node must be preserved after COW"
        );

        // New root should contain modified data.
        let entries = tree.range(&key, &key).expect("point query");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, b"modified");
        tree.validate_invariants().expect("invariants");
    }

    // COW Test 7: COW chain produces version chain (multiple updates tracked)
    #[test]
    fn writepath_cow_chain_produces_version_chain() {
        let mut tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        let key = test_key(100);
        let mut root_versions = Vec::new();

        // Insert initial value.
        tree.insert(key, b"v1").expect("insert");
        root_versions.push(tree.root_block());

        // Perform 4 updates, capturing root at each step.
        for version in 2..=5 {
            let payload = format!("v{version}");
            tree.update(&key, payload.as_bytes()).expect("update");
            root_versions.push(tree.root_block());
        }

        // All root versions should be distinct (COW semantics).
        let unique_roots: HashSet<u64> = root_versions.iter().copied().collect();
        assert_eq!(
            unique_roots.len(),
            root_versions.len(),
            "each COW write should produce a distinct root: {root_versions:?}"
        );

        // Deferred free list should have entries from retired nodes.
        assert!(
            !tree.deferred_free_blocks().is_empty(),
            "COW chain should record deferred frees for retired nodes"
        );

        // Current value should be the latest.
        let entries = tree.range(&key, &key).expect("point query");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, b"v5");
        tree.validate_invariants().expect("invariants");
    }

    // COW Test 8: COW with MVCC — different transactions see different versions
    #[test]
    fn writepath_cow_with_mvcc_different_txns_see_versions() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let block = BlockNumber(0x5000);

        // Transaction 1: write "version-A".
        let mut tx1 = BtrfsTransaction::begin(&mut store, 1, &cx).expect("begin tx1");
        tx1.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x100_0000,
                level: 0,
            },
        );
        tx1.stage_block_write(block, b"version-A".to_vec())
            .expect("stage A");
        let seq1 = tx1.commit(&mut store, &cx).expect("commit tx1");
        let snap_after_a = store.current_snapshot();

        // Transaction 2: overwrite with "version-B".
        let mut tx2 = BtrfsTransaction::begin(&mut store, 2, &cx).expect("begin tx2");
        tx2.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x200_0000,
                level: 0,
            },
        );
        tx2.stage_block_write(block, b"version-B".to_vec())
            .expect("stage B");
        let seq2 = tx2.commit(&mut store, &cx).expect("commit tx2");
        let snap_after_b = store.current_snapshot();

        // Verify monotonic commit sequence.
        assert!(seq2.0 > seq1.0, "commit sequence should be monotonic");

        // Snapshot after tx1 should see "version-A".
        let data_a = store
            .read_visible(block, snap_after_a)
            .expect("version-A should be visible at snap_after_a");
        assert_eq!(
            data_a.as_ref(),
            b"version-A",
            "snap_after_a should see version-A"
        );

        // Snapshot after tx2 should see "version-B".
        let data_b = store
            .read_visible(block, snap_after_b)
            .expect("version-B should be visible at snap_after_b");
        assert_eq!(
            data_b.as_ref(),
            b"version-B",
            "snap_after_b should see version-B"
        );
    }

    // ── Transaction edge-case tests ───────────────────────────────────

    #[test]
    fn btrfs_tx_commit_empty_root_set_errors() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let txn = BtrfsTransaction::begin(&mut store, 1, &cx).expect("begin");
        // Commit without staging any tree roots should fail.
        let err = txn.commit(&mut store, &cx).expect_err("empty root set");
        assert!(
            matches!(err, BtrfsTransactionError::EmptyRootSet),
            "expected EmptyRootSet, got: {err:?}"
        );
    }

    #[test]
    fn btrfs_tx_stage_block_write_after_abort_errors() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 2, &cx).expect("begin");
        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x1000,
                level: 0,
            },
        );
        let _summary = txn.abort();
        // Can't stage after abort — txn is consumed by abort().
        // (This is enforced by Rust's ownership system.)
    }

    #[test]
    fn btrfs_tx_accessors_return_correct_values() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 42, &cx).expect("begin");
        assert_eq!(txn.generation(), 42);
        assert!(txn.pending_trees().is_empty());
        assert_eq!(txn.delayed_ref_count(), 0);

        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x3000,
                level: 1,
            },
        );
        assert_eq!(txn.pending_trees().len(), 1);
        assert!(txn.pending_trees().contains_key(&BTRFS_FS_TREE_OBJECTID));

        txn.queue_delayed_ref(
            ExtentKey {
                bytenr: 0x5000,
                num_bytes: 4096,
            },
            BtrfsRef::DataExtent {
                root: BTRFS_FS_TREE_OBJECTID,
                objectid: 256,
                offset: 0,
            },
            RefAction::Insert,
        );
        assert_eq!(txn.delayed_ref_count(), 1);
    }

    #[test]
    fn btrfs_tx_multiple_tree_roots_in_single_txn() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 5, &cx).expect("begin");

        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x10_0000,
                level: 1,
            },
        );
        txn.stage_tree_root(
            BTRFS_EXTENT_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x20_0000,
                level: 0,
            },
        );
        txn.stage_tree_root(
            BTRFS_CHUNK_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x30_0000,
                level: 0,
            },
        );

        assert_eq!(txn.pending_trees().len(), 3);
        let commit_seq = txn.commit(&mut store, &cx).expect("commit");
        assert_eq!(commit_seq, CommitSeq(1));

        // Verify all tree roots are persisted.
        let snap = store.current_snapshot();
        for tree_id in [
            BTRFS_FS_TREE_OBJECTID,
            BTRFS_EXTENT_TREE_OBJECTID,
            BTRFS_CHUNK_TREE_OBJECTID,
        ] {
            let block = BtrfsTransaction::tree_root_block(tree_id).expect("block");
            assert!(
                store.read_visible(block, snap).is_some(),
                "tree {tree_id} root should be visible after commit"
            );
        }
    }

    #[test]
    fn btrfs_tx_adversarial_same_tree_root_replacement_persists_last_root() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 55, &cx).expect("begin");
        let txn_id = txn.txn_id();
        let meta_block = BtrfsTransaction::metadata_block_for_txn(txn_id).expect("metadata block");

        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x10_0000,
                level: 0,
            },
        );
        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x20_0000,
                level: 2,
            },
        );
        assert_eq!(txn.pending_trees().len(), 1);

        let commit_seq = txn.commit(&mut store, &cx).expect("commit");
        assert_eq!(commit_seq, CommitSeq(1));

        let snap = store.current_snapshot();
        let metadata = store
            .read_visible(meta_block, snap)
            .expect("transaction metadata should be visible");
        assert_eq!(
            u64::from_le_bytes(metadata[24..32].try_into().unwrap()),
            1_u64,
            "same-tree replacement should count as one root update"
        );

        let tree_block =
            BtrfsTransaction::tree_root_block(BTRFS_FS_TREE_OBJECTID).expect("tree block");
        let tree_record = store
            .read_visible(tree_block, snap)
            .expect("tree root record should be visible");
        assert_eq!(
            u64::from_le_bytes(tree_record[16..24].try_into().unwrap()),
            0x20_0000_u64
        );
        assert_eq!(tree_record[24], 2_u8);
    }

    #[test]
    fn btrfs_tx_adversarial_delayed_ref_failure_leaves_no_visible_records() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 56, &cx).expect("begin");
        let txn_id = txn.txn_id();
        let meta_block = BtrfsTransaction::metadata_block_for_txn(txn_id).expect("metadata block");
        let tree_block =
            BtrfsTransaction::tree_root_block(BTRFS_FS_TREE_OBJECTID).expect("tree block");
        let payload_block = BlockNumber(0xCAFE);

        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x30_0000,
                level: 1,
            },
        );
        txn.stage_block_write(payload_block, b"must-not-commit".to_vec())
            .expect("stage payload");
        txn.queue_delayed_ref(
            ExtentKey {
                bytenr: 0x40_0000,
                num_bytes: 4096,
            },
            delayed_data_ref(700),
            RefAction::Delete,
        );

        let err = txn
            .commit(&mut store, &cx)
            .expect_err("delete without materialized refcount should fail");
        assert!(
            matches!(
                err,
                BtrfsTransactionError::DelayedRefs(BtrfsMutationError::BrokenInvariant(
                    "delayed ref delete without prior refcount"
                ))
            ),
            "unexpected error: {err:?}"
        );

        let snap = store.current_snapshot();
        assert!(store.read_visible(meta_block, snap).is_none());
        assert!(store.read_visible(tree_block, snap).is_none());
        assert!(store.read_visible(payload_block, snap).is_none());
    }

    #[test]
    fn btrfs_tx_adversarial_tree_root_overflow_leaves_no_visible_records() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 57, &cx).expect("begin");
        let txn_id = txn.txn_id();
        let meta_block = BtrfsTransaction::metadata_block_for_txn(txn_id).expect("metadata block");
        let payload_block = BlockNumber(0xD00D);

        txn.stage_tree_root(
            u64::MAX,
            TreeRoot {
                bytenr: 0x50_0000,
                level: 0,
            },
        );
        txn.stage_block_write(payload_block, b"must-not-commit".to_vec())
            .expect("stage payload");

        let err = txn
            .commit(&mut store, &cx)
            .expect_err("overflowing tree id should fail");
        assert!(
            matches!(
                err,
                BtrfsTransactionError::TreeRootAddressOverflow { tree_id } if tree_id == u64::MAX
            ),
            "unexpected error: {err:?}"
        );

        let snap = store.current_snapshot();
        assert!(
            store.read_visible(meta_block, snap).is_none(),
            "metadata staged before the overflow must not become visible"
        );
        assert!(store.read_visible(payload_block, snap).is_none());
    }

    #[test]
    fn btrfs_tx_track_allocation_and_defer_free() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 10, &cx).expect("begin");

        txn.track_allocation(BlockNumber(100));
        txn.track_allocation(BlockNumber(101));
        txn.defer_free_on_commit(BlockNumber(200));
        txn.defer_free_on_commit(BlockNumber(201));
        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x1000,
                level: 0,
            },
        );

        let summary = txn.abort();
        assert_eq!(summary.released_allocations.len(), 2);
        assert!(summary.released_allocations.contains(&BlockNumber(100)));
        assert!(summary.released_allocations.contains(&BlockNumber(101)));
        assert_eq!(summary.deferred_frees.len(), 2);
        assert!(summary.deferred_frees.contains(&BlockNumber(200)));
        assert!(summary.deferred_frees.contains(&BlockNumber(201)));
    }

    // ── Extent allocator edge-case tests ──────────────────────────────

    #[test]
    fn alloc_metadata_no_metadata_bg_fails() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        // Only add a data block group, no metadata.
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, 0x100_000));

        let result = alloc.alloc_metadata(4096);
        assert!(
            result.is_err(),
            "metadata alloc without metadata bg should fail"
        );
    }

    #[test]
    fn extent_allocator_adversarial_rejects_overflowing_block_group_range() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = u64::MAX - 1024;
        alloc.add_block_group(bg_start, make_data_bg(bg_start, 4096));

        let err = alloc
            .alloc_data(512)
            .expect_err("overflowing block group end should be rejected");
        assert_eq!(err, BtrfsMutationError::AddressOverflow);

        let bg = alloc.block_group(bg_start).expect("bg");
        assert_eq!(
            bg.used_bytes, 0,
            "failed allocation should not change accounting"
        );
        assert_eq!(alloc.delayed_ref_count(), 0);
    }

    #[test]
    fn extent_allocator_adversarial_propagates_range_scan_errors() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = 0x10_0000;
        alloc.add_block_group(bg_start, make_data_bg(bg_start, 8192));
        alloc.extent_tree.root = u64::MAX;

        let err = alloc
            .alloc_data(4096)
            .expect_err("broken allocation tree should fail closed");
        assert_eq!(err, BtrfsMutationError::MissingNode(u64::MAX));

        let bg = alloc.block_group(bg_start).expect("bg");
        assert_eq!(
            bg.used_bytes, 0,
            "failed allocation should not change accounting"
        );
        assert_eq!(alloc.delayed_ref_count(), 0);
    }

    #[test]
    fn extent_allocator_adversarial_allows_exact_tail_fit() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = 0x10_0000;
        alloc.add_block_group(bg_start, make_data_bg(bg_start, 8192));

        let first = alloc.alloc_data(4096).expect("first half");
        let second = alloc.alloc_data(4096).expect("exact tail fit");
        assert_eq!(first.bytenr, bg_start);
        assert_eq!(second.bytenr, bg_start + 4096);

        let bg = alloc.block_group(bg_start).expect("bg");
        assert_eq!(bg.used_bytes, 8192);
        assert_eq!(bg.free_bytes(), 0);

        let err = alloc
            .alloc_data(1)
            .expect_err("full block group should reject one more byte");
        assert_eq!(err, BtrfsMutationError::NoSpace);
    }

    #[test]
    fn extent_refcount_after_alloc_and_flush_is_one() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, 0x100_000));

        let ext = alloc.alloc_data(4096).expect("alloc");
        // Allocation queues a delayed ref; flush it to materialize the refcount.
        alloc.flush_delayed_refs(usize::MAX).expect("flush refs");
        let key = ExtentKey {
            bytenr: ext.bytenr,
            num_bytes: ext.num_bytes,
        };
        assert_eq!(alloc.extent_refcount(key), 1);
    }

    #[test]
    fn extent_refcount_after_free_is_zero() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, 0x100_000));

        let ext = alloc.alloc_data(4096).expect("alloc");
        alloc
            .free_extent(ext.bytenr, ext.num_bytes, false)
            .expect("free");
        // Flush delayed refs to apply both the insert and remove.
        alloc.flush_delayed_refs(usize::MAX).expect("flush refs");
        let key = ExtentKey {
            bytenr: ext.bytenr,
            num_bytes: ext.num_bytes,
        };
        assert_eq!(alloc.extent_refcount(key), 0);
    }

    #[test]
    fn extent_allocator_adversarial_rejects_free_without_owning_block_group() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, 8192));
        let bytenr = 0x20_0000;
        let key = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: 4096,
        };
        let extent_item = BtrfsExtentItem {
            refs: 1,
            generation: 1,
            flags: 0,
        };
        alloc
            .extent_tree
            .insert(key, &extent_item.to_bytes())
            .expect("insert orphan extent");

        let err = alloc
            .free_extent(bytenr, 4096, false)
            .expect_err("orphan extent should fail closed");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("extent has no owning block group")
        );

        assert_eq!(
            alloc
                .extent_tree
                .range(&key, &key)
                .expect("extent lookup should still work")
                .len(),
            1,
            "failed free should not delete the extent item"
        );
        assert_eq!(alloc.delayed_ref_count(), 0);
    }

    #[test]
    fn extent_allocator_adversarial_rejects_free_accounting_underflow() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = 0x10_0000;
        alloc.add_block_group(bg_start, make_data_bg(bg_start, 8192));
        let key = BtrfsKey {
            objectid: bg_start,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: 4096,
        };
        let extent_item = BtrfsExtentItem {
            refs: 1,
            generation: 1,
            flags: 0,
        };
        alloc
            .extent_tree
            .insert(key, &extent_item.to_bytes())
            .expect("insert inconsistent extent");

        let err = alloc
            .free_extent(bg_start, 4096, false)
            .expect_err("accounting underflow should fail closed");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("block group used bytes underflow")
        );

        let bg = alloc.block_group(bg_start).expect("bg");
        assert_eq!(bg.used_bytes, 0);
        assert_eq!(
            alloc
                .extent_tree
                .range(&key, &key)
                .expect("extent lookup should still work")
                .len(),
            1,
            "failed free should not delete the extent item"
        );
        assert_eq!(alloc.delayed_ref_count(), 0);
    }

    #[test]
    fn reclaim_unreferenced_data_extents_frees_orphans_only() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = 0x10_0000;
        alloc.add_block_group(bg_start, make_data_bg(bg_start, 16 * 4096));

        let referenced = alloc.alloc_data(4096).expect("referenced data");
        let orphan = alloc.alloc_data(8192).expect("orphan data");
        let mut durable_extent_data = HashSet::new();
        durable_extent_data.insert(ExtentKey {
            bytenr: referenced.bytenr,
            num_bytes: referenced.num_bytes,
        });

        let reclaimed = alloc
            .reclaim_unreferenced_data_extents(&durable_extent_data)
            .expect("reclaim orphan");
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].bytenr, orphan.bytenr);
        assert_eq!(reclaimed[0].num_bytes, orphan.num_bytes);

        let referenced_key = BtrfsKey {
            objectid: referenced.bytenr,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: referenced.num_bytes,
        };
        let orphan_key = BtrfsKey {
            objectid: orphan.bytenr,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: orphan.num_bytes,
        };
        assert_eq!(
            alloc
                .extent_tree
                .range(&referenced_key, &referenced_key)
                .expect("referenced extent lookup")
                .len(),
            1
        );
        assert!(
            alloc
                .extent_tree
                .range(&orphan_key, &orphan_key)
                .expect("orphan extent lookup")
                .is_empty()
        );
        assert_eq!(
            alloc.block_group(bg_start).expect("bg").used_bytes,
            referenced.num_bytes
        );
    }

    #[test]
    fn reclaim_unreferenced_data_extents_leaves_metadata_extents() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let data_start = 0x10_0000;
        let meta_start = 0x20_0000;
        alloc.add_block_group(data_start, make_data_bg(data_start, 16 * 4096));
        alloc.add_block_group(meta_start, make_meta_bg(meta_start, 16 * 4096));

        let data = alloc.alloc_data(4096).expect("orphan data");
        let meta = alloc.alloc_metadata(4096).expect("metadata");
        let reclaimed = alloc
            .reclaim_unreferenced_data_extents(&HashSet::new())
            .expect("reclaim data orphan");
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].bytenr, data.bytenr);

        // Skinny METADATA_ITEM is keyed by the tree level (0 for alloc_metadata),
        // not num_bytes.
        let meta_key = BtrfsKey {
            objectid: meta.bytenr,
            item_type: BTRFS_ITEM_METADATA_ITEM,
            offset: 0,
        };
        assert_eq!(
            alloc
                .extent_tree
                .range(&meta_key, &meta_key)
                .expect("metadata extent lookup")
                .len(),
            1,
            "metadata extents are not data-orphan cleanup candidates"
        );
        assert_eq!(
            alloc
                .block_group(meta_start)
                .expect("metadata bg")
                .used_bytes,
            meta.num_bytes
        );
    }

    #[test]
    fn total_used_and_capacity_computations() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_size = 0x100_000_u64;
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, bg_size));
        alloc.add_block_group(0x20_0000, make_meta_bg(0x20_0000, bg_size));

        assert_eq!(alloc.total_capacity(), bg_size * 2);
        assert_eq!(alloc.total_used(), 0);

        alloc.alloc_data(4096).expect("data alloc");
        alloc.alloc_metadata(8192).expect("meta alloc");

        assert_eq!(alloc.total_used(), 4096 + 8192);
        assert_eq!(alloc.total_free(BTRFS_BLOCK_GROUP_DATA), bg_size - 4096);
        assert_eq!(alloc.total_free(BTRFS_BLOCK_GROUP_METADATA), bg_size - 8192);
    }

    #[test]
    fn largest_free_extent_reports_fragmented_data_gap() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = 0x10_0000;
        alloc.add_block_group(bg_start, make_data_bg(bg_start, 16 * 4096));

        let _first = alloc.alloc_data(4 * 4096).expect("first");
        let middle = alloc.alloc_data(4 * 4096).expect("middle");
        let _last = alloc.alloc_data(4 * 4096).expect("last");
        alloc
            .free_extent(middle.bytenr, middle.num_bytes, false)
            .expect("free middle");

        assert_eq!(alloc.total_free(BTRFS_BLOCK_GROUP_DATA), 8 * 4096);
        assert_eq!(
            alloc
                .largest_free_extent(BTRFS_BLOCK_GROUP_DATA)
                .expect("largest gap"),
            4 * 4096
        );
    }

    #[test]
    fn largest_free_extent_respects_untracked_used_prefix() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = 0x10_0000;
        let mut bg = make_data_bg(bg_start, 64 * 4096);
        bg.used_bytes = 16 * 4096;
        alloc.add_block_group(bg_start, bg);

        let first = alloc.alloc_data(16 * 4096).expect("first");
        let _second = alloc.alloc_data(8 * 4096).expect("second");
        alloc
            .free_extent(first.bytenr, first.num_bytes, false)
            .expect("free first");

        assert_eq!(alloc.total_free(BTRFS_BLOCK_GROUP_DATA), 40 * 4096);
        assert_eq!(
            alloc
                .largest_free_extent(BTRFS_BLOCK_GROUP_DATA)
                .expect("largest gap"),
            24 * 4096
        );
    }

    #[test]
    fn largest_free_extent_is_scoped_by_block_group_type() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let data_start = 0x10_0000;
        let meta_start = 0x20_0000;
        alloc.add_block_group(data_start, make_data_bg(data_start, 16 * 4096));
        alloc.add_block_group(meta_start, make_meta_bg(meta_start, 32 * 4096));

        let _data = alloc.alloc_data(12 * 4096).expect("data");
        let _meta = alloc.alloc_metadata(4 * 4096).expect("metadata");

        assert_eq!(
            alloc
                .largest_free_extent(BTRFS_BLOCK_GROUP_DATA)
                .expect("data largest"),
            4 * 4096
        );
        assert_eq!(
            alloc
                .largest_free_extent(BTRFS_BLOCK_GROUP_METADATA)
                .expect("metadata largest"),
            28 * 4096
        );
    }

    #[test]
    fn drain_delayed_refs_returns_all_queued() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, 0x100_000));

        let _ext = alloc.alloc_data(4096).expect("alloc");
        // alloc_data queues a delayed ref; verify drain works.
        assert_eq!(alloc.delayed_ref_count(), 1);
        let drained = alloc.drain_delayed_refs();
        assert_eq!(drained.len(), 1);
        assert_eq!(alloc.delayed_ref_count(), 0);
    }

    #[test]
    fn multiple_allocs_sequential_in_same_bg() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, 0x100_000));

        let a1 = alloc.alloc_data(4096).expect("alloc 1");
        let a2 = alloc.alloc_data(4096).expect("alloc 2");
        let a3 = alloc.alloc_data(4096).expect("alloc 3");

        // All should come from the same block group.
        assert_eq!(a1.block_group_start, 0x10_0000);
        assert_eq!(a2.block_group_start, 0x10_0000);
        assert_eq!(a3.block_group_start, 0x10_0000);

        // None should overlap.
        let extents = [
            (a1.bytenr, a1.bytenr + a1.num_bytes),
            (a2.bytenr, a2.bytenr + a2.num_bytes),
            (a3.bytenr, a3.bytenr + a3.num_bytes),
        ];
        for i in 0..extents.len() {
            for j in (i + 1)..extents.len() {
                assert!(
                    extents[i].1 <= extents[j].0 || extents[j].1 <= extents[i].0,
                    "extents {i} and {j} overlap: {:?} vs {:?}",
                    extents[i],
                    extents[j]
                );
            }
        }

        assert_eq!(alloc.total_used(), 4096 * 3);
    }

    #[test]
    fn block_group_item_serialization_round_trip() {
        let bg = BtrfsBlockGroupItem {
            total_bytes: 0x100_000,
            used_bytes: 0x50_000,
            flags: BTRFS_BLOCK_GROUP_DATA | BTRFS_BLOCK_GROUP_METADATA,
        };
        let bytes = bg.to_bytes();
        assert_eq!(bytes.len(), 24);
        // Serialization order: used_bytes, total_bytes, flags
        assert_eq!(
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            0x50_000
        );
        assert_eq!(
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            0x100_000
        );
        assert_eq!(
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            BTRFS_BLOCK_GROUP_DATA | BTRFS_BLOCK_GROUP_METADATA
        );
        assert_eq!(bg.free_bytes(), 0x100_000 - 0x50_000);
    }

    #[test]
    fn extent_item_to_bytes_round_trip() {
        let ext = BtrfsExtentItem {
            refs: 3,
            generation: 42,
            flags: 1,
        };
        let bytes = ext.to_bytes();
        assert_eq!(bytes.len(), 24);
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 3);
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 42);
        assert_eq!(u64::from_le_bytes(bytes[16..24].try_into().unwrap()), 1);
    }

    #[test]
    fn delayed_ref_queue_drain_all_empties_queue() {
        let mut queue = DelayedRefQueue::new();
        let key = ExtentKey {
            bytenr: 0x1000,
            num_bytes: 4096,
        };
        queue.queue(
            key,
            BtrfsRef::DataExtent {
                root: BTRFS_FS_TREE_OBJECTID,
                objectid: 256,
                offset: 0,
            },
            RefAction::Insert,
        );
        queue.queue(
            key,
            BtrfsRef::DataExtent {
                root: BTRFS_FS_TREE_OBJECTID,
                objectid: 256,
                offset: 4096,
            },
            RefAction::Insert,
        );
        assert_eq!(queue.pending_count(), 2);

        let drained = queue.drain_all();
        assert_eq!(drained.len(), 2);
        assert_eq!(queue.pending_count(), 0);
    }

    #[test]
    fn delayed_ref_queue_pending_for_filters_by_extent() {
        let mut queue = DelayedRefQueue::new();
        let key_a = ExtentKey {
            bytenr: 0x1000,
            num_bytes: 4096,
        };
        let key_b = ExtentKey {
            bytenr: 0x2000,
            num_bytes: 8192,
        };
        queue.queue(
            key_a,
            BtrfsRef::DataExtent {
                root: BTRFS_FS_TREE_OBJECTID,
                objectid: 256,
                offset: 0,
            },
            RefAction::Insert,
        );
        queue.queue(
            key_b,
            BtrfsRef::DataExtent {
                root: BTRFS_FS_TREE_OBJECTID,
                objectid: 257,
                offset: 0,
            },
            RefAction::Insert,
        );
        queue.queue(
            key_a,
            BtrfsRef::DataExtent {
                root: BTRFS_FS_TREE_OBJECTID,
                objectid: 258,
                offset: 0,
            },
            RefAction::Insert,
        );

        assert_eq!(queue.pending_for(&key_a).len(), 2);
        assert_eq!(queue.pending_for(&key_b).len(), 1);
    }

    fn delayed_data_ref(objectid: u64) -> BtrfsRef {
        BtrfsRef::DataExtent {
            root: BTRFS_FS_TREE_OBJECTID,
            objectid,
            offset: 0,
        }
    }

    #[test]
    fn delayed_ref_queue_adversarial_flush_boundaries() {
        let key_a = ExtentKey {
            bytenr: 0x1000,
            num_bytes: 4096,
        };
        let key_b = ExtentKey {
            bytenr: 0x2000,
            num_bytes: 8192,
        };
        let mut queue = DelayedRefQueue::new();
        let mut refcounts = BTreeMap::new();

        queue.queue(key_a, delayed_data_ref(1), RefAction::Insert);
        assert_eq!(queue.flush(0, &mut refcounts).expect("zero-limit flush"), 0);
        assert_eq!(queue.pending_count(), 1);
        assert!(refcounts.is_empty());
        assert_eq!(queue.pending_for(&key_a).len(), 1);

        queue.queue(key_a, delayed_data_ref(2), RefAction::Insert);
        queue.queue(key_b, delayed_data_ref(3), RefAction::Insert);
        assert_eq!(queue.pending_count(), 3);

        let flushed = queue.flush(2, &mut refcounts).expect("bounded flush");
        assert_eq!(flushed, 2);
        assert_eq!(queue.pending_count(), 1);
        assert_eq!(refcounts.get(&key_a), Some(&2));
        assert_eq!(queue.pending_for(&key_a).len(), 0);
        assert_eq!(queue.pending_for(&key_b).len(), 1);
    }

    #[test]
    fn delayed_ref_queue_adversarial_delete_underflow_preserves_queue() {
        let key = ExtentKey {
            bytenr: 0x3000,
            num_bytes: 4096,
        };
        let mut queue = DelayedRefQueue::new();
        let mut refcounts = BTreeMap::new();

        queue.queue(key, delayed_data_ref(4), RefAction::Delete);
        let err = queue
            .flush(1, &mut refcounts)
            .expect_err("delete without refcount");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("delayed ref delete without prior refcount")
        );
        assert_eq!(queue.pending_count(), 1);
        assert_eq!(queue.pending_for(&key).len(), 1);
        assert!(refcounts.is_empty());
    }

    #[test]
    fn delayed_ref_queue_failed_flush_is_atomic_for_refcounts() {
        let inserted = ExtentKey {
            bytenr: 0x3000,
            num_bytes: 4096,
        };
        let missing_delete = ExtentKey {
            bytenr: 0x7000,
            num_bytes: 4096,
        };
        let mut queue = DelayedRefQueue::new();
        let mut refcounts = BTreeMap::new();

        queue.queue(inserted, delayed_data_ref(4), RefAction::Insert);
        queue.queue(missing_delete, delayed_data_ref(5), RefAction::Delete);
        let err = queue
            .flush(2, &mut refcounts)
            .expect_err("delete without refcount");

        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("delayed ref delete without prior refcount")
        );
        assert!(
            refcounts.is_empty(),
            "failed batch must not materialize earlier successful refs"
        );
        assert_eq!(queue.pending_count(), 2);
        assert_eq!(queue.pending_for(&inserted).len(), 1);
        assert_eq!(queue.pending_for(&missing_delete).len(), 1);

        refcounts.insert(missing_delete, 1);
        let flushed = queue.flush(2, &mut refcounts).expect("retry flush");
        assert_eq!(flushed, 2);
        assert_eq!(queue.pending_count(), 0);
        assert_eq!(refcounts.get(&inserted), Some(&1));
        assert!(!refcounts.contains_key(&missing_delete));
    }

    #[test]
    fn delayed_ref_queue_insert_overflow_is_atomic() {
        let key = ExtentKey {
            bytenr: 0x3000,
            num_bytes: 4096,
        };
        let mut queue = DelayedRefQueue::new();
        let mut refcounts = BTreeMap::from([(key, u64::MAX)]);

        queue.queue(key, delayed_data_ref(4), RefAction::Insert);
        let err = queue
            .flush(1, &mut refcounts)
            .expect_err("refcount overflow");

        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("delayed ref insert overflow")
        );
        assert_eq!(refcounts.get(&key), Some(&u64::MAX));
        assert_eq!(queue.pending_count(), 1);
        assert_eq!(queue.pending_for(&key).len(), 1);
    }

    #[test]
    fn delayed_ref_queue_drain_all_preserves_sequence_across_key_order() {
        let key_low = ExtentKey {
            bytenr: 0x1000,
            num_bytes: 4096,
        };
        let key_high = ExtentKey {
            bytenr: 0x9000,
            num_bytes: 4096,
        };
        let mut queue = DelayedRefQueue::new();

        queue.queue(key_high, delayed_data_ref(10), RefAction::Insert);
        queue.queue(key_low, delayed_data_ref(11), RefAction::Insert);
        queue.queue(key_high, delayed_data_ref(12), RefAction::Delete);

        let drained = queue.drain_all();
        assert_eq!(drained.len(), 3);
        assert_eq!(
            drained
                .iter()
                .map(|entry| entry.sequence)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(drained[0].extent, key_high);
        assert_eq!(drained[1].extent, key_low);
        assert_eq!(drained[2].extent, key_high);
        assert_eq!(drained[2].action, RefAction::Delete);
        assert_eq!(queue.pending_count(), 0);
        assert!(queue.pending_for(&key_low).is_empty());
        assert!(queue.pending_for(&key_high).is_empty());
    }

    // ── Subvolume enumeration tests ────────────────────────────────

    fn make_root_item_data(bytenr: u64, generation: u64, flags: u64) -> Vec<u8> {
        let mut data = vec![0_u8; 279];
        data[160..168].copy_from_slice(&generation.to_le_bytes()); // generation
        data[168..176].copy_from_slice(&256_u64.to_le_bytes()); // root_dirid
        data[176..184].copy_from_slice(&bytenr.to_le_bytes()); // bytenr
        data[208..216].copy_from_slice(&flags.to_le_bytes()); // flags
        data[216..220].copy_from_slice(&1_u32.to_le_bytes()); // refs
        // uuid at 247, parent_uuid at 263 — left as zeros
        data[238] = 0; // level
        data[239..247].copy_from_slice(&generation.to_le_bytes()); // generation_v2
        data
    }

    fn make_root_item_with_uuids(
        bytenr: u64,
        generation: u64,
        flags: u64,
        uuid: [u8; 16],
        parent_uuid: [u8; 16],
    ) -> Vec<u8> {
        let mut data = make_root_item_data(bytenr, generation, flags);
        data[247..263].copy_from_slice(&uuid);
        data[263..279].copy_from_slice(&parent_uuid);
        data
    }

    fn make_root_ref_data(dirid: u64, name: &[u8]) -> Vec<u8> {
        let mut data = vec![0_u8; 18 + name.len()];
        let name_len = u16::try_from(name.len()).expect("root ref name length must fit u16");
        data[0..8].copy_from_slice(&dirid.to_le_bytes());
        data[8..16].copy_from_slice(&0_u64.to_le_bytes()); // sequence
        data[16..18].copy_from_slice(&name_len.to_le_bytes());
        data[18..18 + name.len()].copy_from_slice(name);
        data
    }

    #[test]
    fn enumerate_subvolumes_finds_user_subvols() {
        let entries = vec![
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_data(0x1000, 10, 0),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 5,
                    item_type: BTRFS_ITEM_ROOT_REF,
                    offset: 256,
                },
                data: make_root_ref_data(256, b"mysubvol"),
            },
        ];
        let subvols = enumerate_subvolumes(&entries);
        assert_eq!(subvols.len(), 1);
        assert_eq!(subvols[0].id, 256);
        assert_eq!(subvols[0].name, "mysubvol");
        assert_eq!(subvols[0].generation, 10);
        assert!(!subvols[0].read_only);
    }

    #[test]
    fn enumerate_subvolumes_skips_system_trees() {
        let entries = vec![
            // System tree (objectid < 256) — should be skipped
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 5,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_data(0x2000, 5, 0),
            },
        ];
        let subvols = enumerate_subvolumes(&entries);
        assert!(subvols.is_empty());
    }

    #[test]
    fn enumerate_subvolumes_read_only_flag() {
        let entries = vec![BtrfsLeafEntry {
            key: BtrfsKey {
                objectid: 300,
                item_type: BTRFS_ITEM_ROOT_ITEM,
                offset: 0,
            },
            data: make_root_item_data(0x3000, 20, 1), // flags=1 = RDONLY
        }];
        let subvols = enumerate_subvolumes(&entries);
        assert_eq!(subvols.len(), 1);
        assert!(subvols[0].read_only);
    }

    #[test]
    fn enumerate_subvolumes_no_root_ref_uses_fallback_name() {
        let entries = vec![BtrfsLeafEntry {
            key: BtrfsKey {
                objectid: 500,
                item_type: BTRFS_ITEM_ROOT_ITEM,
                offset: 0,
            },
            data: make_root_item_data(0x5000, 15, 0),
        }];
        let subvols = enumerate_subvolumes(&entries);
        assert_eq!(subvols.len(), 1);
        assert_eq!(subvols[0].name, "subvol-500");
    }

    #[test]
    fn enumerate_subvolumes_malformed_root_ref_uses_fallback_name() {
        let mut malformed_ref = make_root_ref_data(256, b"broken");
        malformed_ref.truncate(20);
        let entries = vec![
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 600,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_data(0x6000, 22, 0),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 5,
                    item_type: BTRFS_ITEM_ROOT_REF,
                    offset: 600,
                },
                data: malformed_ref,
            },
        ];

        let subvols = enumerate_subvolumes(&entries);
        assert_eq!(subvols.len(), 1);
        assert_eq!(subvols[0].name, "subvol-600");
    }

    #[test]
    fn enumerate_subvolumes_trailing_root_ref_uses_fallback_name() {
        let mut malformed_ref = make_root_ref_data(256, b"broken");
        malformed_ref.extend_from_slice(b"trailing");
        let entries = vec![
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 601,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_data(0x6000, 22, 0),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 5,
                    item_type: BTRFS_ITEM_ROOT_REF,
                    offset: 601,
                },
                data: malformed_ref,
            },
        ];

        let subvols = enumerate_subvolumes(&entries);
        assert_eq!(subvols.len(), 1);
        assert_eq!(subvols[0].name, "subvol-601");
    }

    // ── Snapshot enumeration tests ─────────────────────────────────

    #[test]
    fn enumerate_snapshots_finds_snapshots() {
        let src_uuid = [1_u8; 16];
        let snap_uuid = [2_u8; 16];
        let entries = vec![
            // Source subvolume
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_with_uuids(0x1000, 10, 0, src_uuid, [0; 16]),
            },
            // Snapshot (parent_uuid = src_uuid)
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 257,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_with_uuids(0x2000, 15, 1, snap_uuid, src_uuid),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: BTRFS_ITEM_ROOT_REF,
                    offset: 257,
                },
                data: make_root_ref_data(256, b"my_snapshot"),
            },
        ];
        let snapshots = enumerate_snapshots(&entries);
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].id, 257);
        assert_eq!(snapshots[0].source_id, 256);
        assert_eq!(snapshots[0].name, "my_snapshot");
        assert_eq!(snapshots[0].generation, 15);
    }

    #[test]
    fn enumerate_snapshots_ignores_regular_subvolumes() {
        let entries = vec![BtrfsLeafEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: BTRFS_ITEM_ROOT_ITEM,
                offset: 0,
            },
            data: make_root_item_with_uuids(0x1000, 10, 0, [1; 16], [0; 16]),
        }];
        let snapshots = enumerate_snapshots(&entries);
        assert!(
            snapshots.is_empty(),
            "regular subvolume should not be listed as snapshot"
        );
    }

    #[test]
    fn enumerate_snapshots_malformed_root_ref_uses_fallback_name() {
        let src_uuid = [1_u8; 16];
        let snap_uuid = [2_u8; 16];
        let mut malformed_ref = make_root_ref_data(256, b"broken_snapshot");
        malformed_ref.truncate(21);
        let entries = vec![
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_with_uuids(0x1000, 10, 0, src_uuid, [0; 16]),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 257,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_with_uuids(0x2000, 15, 1, snap_uuid, src_uuid),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: BTRFS_ITEM_ROOT_REF,
                    offset: 257,
                },
                data: malformed_ref,
            },
        ];

        let snapshots = enumerate_snapshots(&entries);
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].name, "snap-257");
    }

    // ── Snapshot diff tests ────────────────────────────────────────

    fn make_inode_entry(objectid: u64, generation: u64) -> BtrfsLeafEntry {
        let mut data = vec![0_u8; 160];
        data[0..8].copy_from_slice(&generation.to_le_bytes()); // generation
        data[8..16].copy_from_slice(&100_u64.to_le_bytes()); // size
        data[24..28].copy_from_slice(&1_u32.to_le_bytes()); // nlink
        data[32..36].copy_from_slice(&0o100_644_u32.to_le_bytes()); // mode
        BtrfsLeafEntry {
            key: BtrfsKey {
                objectid,
                item_type: BTRFS_ITEM_INODE_ITEM,
                offset: 0,
            },
            data,
        }
    }

    fn inode_entries_from_generations(generations: &BTreeMap<u64, u64>) -> Vec<BtrfsLeafEntry> {
        generations
            .iter()
            .map(|(&objectid, &generation)| make_inode_entry(objectid, generation))
            .collect()
    }

    const REPRESENTATIVE_SUBVOLUME_SNAPSHOT_ENUMERATION_GOLDEN: &str = concat!(
        "subvolumes\n",
        "  id=256 parent=5 name=src gen=10 ro=false bytenr=0x1000 level=0\n",
        "  id=300 parent=0 name=subvol-300 gen=22 ro=true bytenr=0x3000 level=0\n",
        "  id=400 parent=5 name=snap-a gen=15 ro=true bytenr=0x2000 level=0\n",
        "snapshots\n",
        "  id=400 source=256 name=snap-a gen=15 uuid=02020202020202020202020202020202 parent_uuid=01010101010101010101010101010101 bytenr=0x2000 level=0\n",
        "diff\n",
        "  inode=100 change=deleted\n",
        "  inode=200 change=modified\n",
        "  inode=300 change=deleted\n",
        "  inode=400 change=added"
    );

    fn format_uuid_hex(uuid: [u8; 16]) -> String {
        use std::fmt::Write as _;

        let mut out = String::with_capacity(32);
        for byte in uuid {
            write!(&mut out, "{byte:02x}").expect("write to String");
        }
        out
    }

    fn representative_subvolume_snapshot_enumeration_actual() -> String {
        use std::fmt::Write as _;

        let src_uuid = [1_u8; 16];
        let snap_uuid = [2_u8; 16];
        let entries = vec![
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_with_uuids(0x1000, 10, 0, src_uuid, [0; 16]),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 300,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_data(0x3000, 22, 1),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 400,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_with_uuids(0x2000, 15, 1, snap_uuid, src_uuid),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 5,
                    item_type: BTRFS_ITEM_ROOT_REF,
                    offset: 256,
                },
                data: make_root_ref_data(256, b"src"),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 5,
                    item_type: BTRFS_ITEM_ROOT_REF,
                    offset: 400,
                },
                data: make_root_ref_data(256, b"snap-a"),
            },
        ];
        let older = vec![
            make_inode_entry(100, 5),
            make_inode_entry(200, 5),
            make_inode_entry(300, 5),
        ];
        let newer = vec![make_inode_entry(200, 10), make_inode_entry(400, 8)];
        let subvols = enumerate_subvolumes(&entries);
        let snapshots = enumerate_snapshots(&entries);
        let diffs = snapshot_diff_by_generation(&older, &newer);

        let mut out = String::new();
        out.push_str("subvolumes\n");
        for subvol in &subvols {
            writeln!(
                &mut out,
                "  id={} parent={} name={} gen={} ro={} bytenr=0x{:x} level={}",
                subvol.id,
                subvol.parent_id,
                subvol.name,
                subvol.generation,
                subvol.read_only,
                subvol.bytenr,
                subvol.level
            )
            .expect("write subvolume");
        }
        out.push_str("snapshots\n");
        for snapshot in &snapshots {
            writeln!(
                &mut out,
                "  id={} source={} name={} gen={} uuid={} parent_uuid={} bytenr=0x{:x} level={}",
                snapshot.id,
                snapshot.source_id,
                snapshot.name,
                snapshot.generation,
                format_uuid_hex(snapshot.uuid),
                format_uuid_hex(snapshot.parent_uuid),
                snapshot.bytenr,
                snapshot.level
            )
            .expect("write snapshot");
        }
        out.push_str("diff\n");
        for diff in &diffs {
            let change = match diff.change_type {
                SnapshotChangeType::Added => "added",
                SnapshotChangeType::Modified => "modified",
                SnapshotChangeType::Deleted => "deleted",
            };
            writeln!(&mut out, "  inode={} change={change}", diff.inode).expect("write diff");
        }
        out.pop();
        out
    }

    #[test]
    fn snapshot_diff_detects_added() {
        let older = vec![make_inode_entry(256, 10)];
        let newer = vec![make_inode_entry(256, 10), make_inode_entry(257, 15)];
        let diffs = snapshot_diff_by_generation(&older, &newer);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].inode, 257);
        assert_eq!(diffs[0].change_type, SnapshotChangeType::Added);
    }

    #[test]
    fn snapshot_diff_detects_deleted() {
        let older = vec![make_inode_entry(256, 10), make_inode_entry(257, 10)];
        let newer = vec![make_inode_entry(256, 10)];
        let diffs = snapshot_diff_by_generation(&older, &newer);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].inode, 257);
        assert_eq!(diffs[0].change_type, SnapshotChangeType::Deleted);
    }

    #[test]
    fn snapshot_diff_detects_modified() {
        let older = vec![make_inode_entry(256, 10)];
        let newer = vec![make_inode_entry(256, 20)]; // higher generation
        let diffs = snapshot_diff_by_generation(&older, &newer);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].inode, 256);
        assert_eq!(diffs[0].change_type, SnapshotChangeType::Modified);
    }

    #[test]
    fn snapshot_diff_identical_no_changes() {
        let older = vec![make_inode_entry(256, 10), make_inode_entry(257, 10)];
        let newer = vec![make_inode_entry(256, 10), make_inode_entry(257, 10)];
        let diffs = snapshot_diff_by_generation(&older, &newer);
        assert!(diffs.is_empty());
    }

    #[test]
    fn snapshot_diff_multiple_changes() {
        let older = vec![
            make_inode_entry(100, 5),
            make_inode_entry(200, 5),
            make_inode_entry(300, 5),
        ];
        let newer = vec![
            make_inode_entry(200, 10), // modified
            make_inode_entry(400, 8),  // added (100 and 300 deleted)
        ];
        let diffs = snapshot_diff_by_generation(&older, &newer);
        assert_eq!(diffs.len(), 4);
        // Sorted by inode
        assert_eq!(diffs[0].inode, 100);
        assert_eq!(diffs[0].change_type, SnapshotChangeType::Deleted);
        assert_eq!(diffs[1].inode, 200);
        assert_eq!(diffs[1].change_type, SnapshotChangeType::Modified);
        assert_eq!(diffs[2].inode, 300);
        assert_eq!(diffs[2].change_type, SnapshotChangeType::Deleted);
        assert_eq!(diffs[3].inode, 400);
        assert_eq!(diffs[3].change_type, SnapshotChangeType::Added);
    }

    /// Property: diff(snapshot, snapshot) is always empty for any snapshot
    /// shape. Keep this fixed-seed regression sweep alongside the proptest
    /// coverage below so a regression that flagged identical inode sets as
    /// Added or Modified surfaces immediately with a deterministic case.
    ///
    /// Implementation: deterministic LCG-driven sweep over (inode_count,
    /// generation_distribution) shapes.
    #[test]
    fn snapshot_diff_self_diff_is_always_empty() {
        // Linear congruential generator (Numerical Recipes constants) for
        // reproducible per-iteration entropy.
        let mut state: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let mut next = || -> u64 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state
        };

        for _ in 0..256 {
            let entry_count =
                usize::try_from(next() % 16).expect("value reduced modulo 16 fits in usize");
            let entries: Vec<BtrfsLeafEntry> = (0..entry_count)
                .map(|i| {
                    // Mix unique objectid (256 + i) so every entry collides
                    // exactly once with itself, with varied generations.
                    let objectid = 256 + i as u64;
                    let generation = next() % 1000;
                    make_inode_entry(objectid, generation)
                })
                .collect();
            let diffs = snapshot_diff_by_generation(&entries, &entries);
            assert!(
                diffs.is_empty(),
                "self-diff over {entry_count} entries must be empty, got {diffs:?}"
            );
        }
    }

    /// Property: diff(empty, snapshot) reports every inode in snapshot as
    /// Added. Pins the symmetry of the Added/Deleted classification.
    #[test]
    fn snapshot_diff_empty_to_snapshot_reports_all_added() {
        let mut state: u64 = 0x1234_5678_9ABC_DEF0;
        let mut next = || -> u64 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state
        };

        for _ in 0..64 {
            let entry_count =
                1 + usize::try_from(next() % 12).expect("value reduced modulo 12 fits in usize");
            let entries: Vec<BtrfsLeafEntry> = (0..entry_count)
                .map(|i| make_inode_entry(256 + i as u64, next() % 1000))
                .collect();
            let added = snapshot_diff_by_generation(&[], &entries);
            assert_eq!(added.len(), entry_count);
            assert!(
                added
                    .iter()
                    .all(|d| d.change_type == SnapshotChangeType::Added),
                "every diff entry must be Added when older is empty"
            );
            // Sorted by inode (snapshot_diff_by_generation contract).
            for window in added.windows(2) {
                assert!(window[0].inode < window[1].inode);
            }

            let deleted = snapshot_diff_by_generation(&entries, &[]);
            assert_eq!(deleted.len(), entry_count);
            assert!(
                deleted
                    .iter()
                    .all(|d| d.change_type == SnapshotChangeType::Deleted),
                "every diff entry must be Deleted when newer is empty"
            );
        }
    }

    proptest! {
        #[test]
        fn snapshot_diff_self_diff_proptest_is_empty(
            generations in proptest::collection::btree_map(256_u64..4096, any::<u64>(), 0..32),
        ) {
            let entries = inode_entries_from_generations(&generations);
            prop_assert!(snapshot_diff_by_generation(&entries, &entries).is_empty());
        }

        #[test]
        fn snapshot_diff_empty_snapshot_proptest_reports_added_and_deleted(
            generations in proptest::collection::btree_map(256_u64..4096, any::<u64>(), 0..32),
        ) {
            let entries = inode_entries_from_generations(&generations);
            let expected_inodes: Vec<u64> = generations.keys().copied().collect();

            let added = snapshot_diff_by_generation(&[], &entries);
            let added_inodes: Vec<u64> = added.iter().map(|diff| diff.inode).collect();
            prop_assert_eq!(added_inodes.as_slice(), expected_inodes.as_slice());
            prop_assert!(
                added
                    .iter()
                    .all(|diff| diff.change_type == SnapshotChangeType::Added)
            );

            let deleted = snapshot_diff_by_generation(&entries, &[]);
            let deleted_inodes: Vec<u64> = deleted.iter().map(|diff| diff.inode).collect();
            prop_assert_eq!(deleted_inodes.as_slice(), expected_inodes.as_slice());
            prop_assert!(
                deleted
                    .iter()
                    .all(|diff| diff.change_type == SnapshotChangeType::Deleted)
            );
        }

        #[test]
        fn snapshot_diff_same_inode_set_only_reports_generation_increases(
            generations in proptest::collection::btree_map(
                256_u64..4096,
                (0_u64..10_000, 0_u64..3),
                0..32,
            ),
        ) {
            let older: Vec<BtrfsLeafEntry> = generations
                .iter()
                .map(|(&objectid, &(old_generation, _delta))| {
                    make_inode_entry(objectid, old_generation)
                })
                .collect();
            let newer: Vec<BtrfsLeafEntry> = generations
                .iter()
                .map(|(&objectid, &(old_generation, delta))| {
                    make_inode_entry(objectid, old_generation + delta)
                })
                .collect();
            let expected: Vec<SnapshotDiffEntry> = generations
                .iter()
                .filter_map(|(&objectid, &(_old_generation, delta))| {
                    (delta > 0).then_some(SnapshotDiffEntry {
                        inode: objectid,
                        change_type: SnapshotChangeType::Modified,
                    })
                })
                .collect();

            prop_assert_eq!(snapshot_diff_by_generation(&older, &newer), expected);
        }
    }

    #[test]
    fn representative_subvolume_snapshot_enumeration_exact_golden_contract() {
        assert_eq!(
            representative_subvolume_snapshot_enumeration_actual(),
            REPRESENTATIVE_SUBVOLUME_SNAPSHOT_ENUMERATION_GOLDEN
        );
    }

    // ── ROOT_REF parsing tests ─────────────────────────────────────

    #[test]
    fn parse_root_ref_valid() {
        let data = make_root_ref_data(256, b"test_subvol");
        let rref = parse_root_ref(&data).unwrap();
        assert_eq!(rref.dirid, 256);
        assert_eq!(rref.name, b"test_subvol");
    }

    // bd-m9u35 — Kernel-conformance pin for parse_root_ref.
    //
    // struct btrfs_root_ref in fs/btrfs/btrfs_tree.h packs to 18
    // fixed bytes:
    //   dirid    u64 @0..8
    //   sequence u64 @8..16
    //   name_len u16 @16..18
    // plus name bytes at @18..18+name_len.
    //
    // make_root_ref_data sets sequence to 0, so existing
    // parse_root_ref_valid would not catch a regression that read
    // sequence from offset 4..12 instead of 8..16 — every other
    // test covers dirid and name only. Stamp each addressable
    // field with a unique non-zero magic so any single-field
    // offset drift produces a cross-field collision.
    #[test]
    fn parse_root_ref_kernel_offsets_match_btrfs_tree_h() {
        let name = b"\x99\x99\x99\x99\x99"; // 5-byte distinct magic
        let mut data = vec![0_u8; 18 + name.len()];

        let dirid = 0x1111_1111_1111_1111_u64;
        let sequence = 0x2222_2222_2222_2222_u64;
        let name_len = u16::try_from(name.len()).expect("test name fits u16");

        data[0..8].copy_from_slice(&dirid.to_le_bytes());
        data[8..16].copy_from_slice(&sequence.to_le_bytes());
        data[16..18].copy_from_slice(&name_len.to_le_bytes());
        data[18..18 + name.len()].copy_from_slice(name);

        let parsed = parse_root_ref(&data).expect("kernel-stamped root_ref must parse");

        assert_eq!(
            parsed.dirid, dirid,
            "dirid must come from offset 0..8 per kernel layout"
        );
        assert_eq!(
            parsed.sequence, sequence,
            "sequence must come from offset 8..16 per kernel layout"
        );
        assert_eq!(
            parsed.name, name,
            "name bytes must start at offset 18 with length name_len@16..18"
        );

        // Negative MR: the parser rejects payloads where total
        // length doesn't match 18 + name_len exactly. Append one
        // byte and assert InvalidField{name_len} — pinning the
        // exact-match contract independently of the offset
        // assertions above.
        let mut padded = data.clone();
        padded.push(0x55);
        let err = parse_root_ref(&padded).expect_err("trailing byte must reject");
        assert!(
            matches!(err, ParseError::InvalidField { field, .. } if field == "root_ref.name_len"),
            "trailing-byte rejection must blame name_len contract; got {err:?}"
        );
    }

    #[test]
    fn parse_root_ref_too_short() {
        let data = vec![0_u8; 10];
        let err = parse_root_ref(&data).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    // bd-ay4aw: metamorphic proptests for parse_root_ref.
    // Existing tests cover 3 fixed-input cases. parse_root_ref has
    // STRICT length semantics: it rejects both data.len() < name_end
    // AND data.len() > name_end (exact match required, unlike
    // parse_inode_refs which allows multiple concatenated entries).
    // These proptests sweep arbitrary (dirid, sequence, name) tuples
    // plus append/truncate variants to lock the contract.
    proptest::proptest! {
        // MR-1 round-trip: stamp a valid root_ref payload and parse
        // it back, asserting every field round-trips.
        #[test]
        fn parse_root_ref_proptest_round_trip(
            dirid in proptest::prelude::any::<u64>(),
            sequence in proptest::prelude::any::<u64>(),
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=64),
        ) {
            // Stamp payload: 8 dirid + 8 sequence + 2 name_len + name.
            let mut bytes = Vec::with_capacity(18 + name.len());
            bytes.extend_from_slice(&dirid.to_le_bytes());
            bytes.extend_from_slice(&sequence.to_le_bytes());
            let name_len = u16::try_from(name.len()).expect("name fits u16");
            bytes.extend_from_slice(&name_len.to_le_bytes());
            bytes.extend_from_slice(&name);

            let parsed = parse_root_ref(&bytes).expect("valid stamp must parse");
            proptest::prop_assert_eq!(parsed.dirid, dirid);
            proptest::prop_assert_eq!(parsed.sequence, sequence);
            proptest::prop_assert_eq!(parsed.name, name);
        }

        // MR-2 append-rejection: parse_root_ref requires exact
        // length match. Appending arbitrary non-empty suffix must
        // produce InvalidField "does not match payload length".
        #[test]
        fn parse_root_ref_proptest_append_rejection(
            dirid in proptest::prelude::any::<u64>(),
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
            suffix in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
        ) {
            let mut bytes = make_root_ref_data(dirid, &name);
            bytes.extend_from_slice(&suffix);
            let err = parse_root_ref(&bytes).expect_err("append must reject");
            // Specific variant intentionally not asserted to avoid
            // over-coupling; rendering must succeed (no-panic).
            let _ = format!("{err:?}");
        }

        // MR-3 truncation-rejection: removing any non-zero suffix
        // from a valid encoding must produce an error rather than
        // a panic or buffer over-read.
        #[test]
        fn parse_root_ref_proptest_truncation_rejection(
            dirid in proptest::prelude::any::<u64>(),
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
            k in 1_usize..50,
        ) {
            let bytes = make_root_ref_data(dirid, &name);
            let trunc = k.min(bytes.len() - 1);
            let truncated = &bytes[..bytes.len() - trunc];
            let err = parse_root_ref(truncated).expect_err("truncated must reject");
            let _ = format!("{err:?}");
        }

        // bd-x2320 MR-4 determinism: parse(payload) == parse(payload).
        // Sister parsers parse_xattr_items (bd-fhznm),
        // parse_extent_data (bd-3niu3), and parse_inode_refs
        // (bd-9f8ef) have analogous determinism proptests. A
        // regression that introduced a hash-iteration-order or
        // allocator-address dependency in parse_root_ref's path
        // would silently surface only under specific scheduling;
        // this catches it under proptest's deterministic seed sweep.
        #[test]
        fn parse_root_ref_proptest_determinism(
            dirid in proptest::prelude::any::<u64>(),
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
        ) {
            let bytes = make_root_ref_data(dirid, &name);
            let a = parse_root_ref(&bytes).expect("first parse");
            let b = parse_root_ref(&bytes).expect("second parse");
            proptest::prop_assert_eq!(a, b);
        }
    }

    #[test]
    fn parse_root_ref_adversarial_samples_exercise_boundaries() {
        let empty_name = make_root_ref_data(256, b"");
        assert_invalid_field(
            parse_root_ref(&empty_name),
            "root_ref.name_len",
            "must be non-zero",
        );

        let long_name = vec![b'a'; 255];
        let parsed = parse_root_ref(&make_root_ref_data(4096, &long_name))
            .expect("parse long root ref name");
        assert_eq!(parsed.dirid, 4096);
        assert_eq!(parsed.name, long_name);

        let mut trailing = make_root_ref_data(512, b"subvol");
        trailing.extend_from_slice(b"trailing");
        assert_invalid_field(
            parse_root_ref(&trailing),
            "root_ref.name_len",
            "does not match payload length",
        );

        assert_insufficient_data(parse_root_ref(&[0_u8; 17]), 18, 0, 17);

        let mut truncated_name = vec![0_u8; 20];
        truncated_name[16..18].copy_from_slice(&5_u16.to_le_bytes());
        assert_insufficient_data(parse_root_ref(&truncated_name), 5, 18, 2);
    }

    // ── RAID6 parity wraparound regression test ────────────────────

    #[test]
    fn raid6_parity_wraparound_selects_correct_data_device() {
        use ffs_ondisk::{
            BtrfsChunkEntry, BtrfsKey, BtrfsRaidProfile, BtrfsStripe, chunk_type_flags,
            map_logical_to_stripes,
        };

        // 4 devices, RAID6 (2 parity), stripe_len=65536, data_stripes=2
        let chunk = BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 0x100,
                item_type: 228,
                offset: 0,
            },
            length: 65536 * 2 * 8,
            owner: 2,
            stripe_len: 65536,
            chunk_type: chunk_type_flags::BTRFS_BLOCK_GROUP_DATA
                | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID6,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: 4,
            sub_stripes: 0,
            stripes: vec![
                BtrfsStripe {
                    devid: 1,
                    offset: 0x10_0000,
                    dev_uuid: [0; 16],
                },
                BtrfsStripe {
                    devid: 2,
                    offset: 0x20_0000,
                    dev_uuid: [0; 16],
                },
                BtrfsStripe {
                    devid: 3,
                    offset: 0x30_0000,
                    dev_uuid: [0; 16],
                },
                BtrfsStripe {
                    devid: 4,
                    offset: 0x40_0000,
                    dev_uuid: [0; 16],
                },
            ],
        };
        let chunks = vec![chunk];

        // Row 3: P at pos 3 (dev 4), Q at pos 0 (dev 1).
        // Data should be at pos 1 (dev 2) and pos 2 (dev 3).
        // Row 3 offset = 3 * 65536 * 2 = 393216
        let r = map_logical_to_stripes(&chunks, 393_216).unwrap().unwrap();
        assert_eq!(r.profile, BtrfsRaidProfile::Raid6);
        assert_ne!(
            r.stripes[0].devid, 1,
            "dev 1 is Q parity in row 3, must not be data target"
        );
        assert_ne!(
            r.stripes[0].devid, 4,
            "dev 4 is P parity in row 3, must not be data target"
        );
        assert_eq!(r.stripes[0].devid, 2, "data stripe 0 should be dev 2");

        // Row 3, data stripe 1
        let r2 = map_logical_to_stripes(&chunks, 393_216 + 65_536)
            .unwrap()
            .unwrap();
        assert_eq!(r2.stripes[0].devid, 3, "data stripe 1 should be dev 3");
    }

    // ── Send stream tests ───────────────────────────────────────────────

    fn make_send_stream_data() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
        data.extend_from_slice(&BTRFS_SEND_STREAM_VERSION.to_le_bytes());
        data
    }

    fn append_send_command(data: &mut Vec<u8>, cmd: u16, payload: &[u8]) {
        let payload_len =
            u32::try_from(payload.len()).expect("test send command payload length fits u32");
        let command_start = data.len();
        data.extend_from_slice(&payload_len.to_le_bytes());
        data.extend_from_slice(&cmd.to_le_bytes());
        data.extend_from_slice(&0_u32.to_le_bytes());
        data.extend_from_slice(payload);
        let crc = send_stream_command_crc32c(&data[command_start..]);
        data[command_start + 6..command_start + 10].copy_from_slice(&crc.to_le_bytes());
    }

    fn append_send_attr(payload: &mut Vec<u8>, attr_type: u16, attr_data: &[u8]) {
        let attr_len =
            u16::try_from(attr_data.len()).expect("test send attr payload length fits u16");
        payload.extend_from_slice(&attr_type.to_le_bytes());
        payload.extend_from_slice(&attr_len.to_le_bytes());
        payload.extend_from_slice(attr_data);
    }

    #[test]
    fn parse_send_stream_minimal() {
        let mut data = make_send_stream_data();
        append_send_command(&mut data, SendCommand::End as u16, &[]);

        let result = parse_send_stream(&data).unwrap();
        assert_eq!(result.version, 1);
        assert_eq!(result.commands.len(), 1);
        assert_eq!(result.commands[0].cmd, SendCommand::End);
    }

    #[test]
    fn parse_send_stream_adversarial_samples_exercise_boundaries() {
        let mut no_end = make_send_stream_data();
        append_send_command(&mut no_end, 0xffff, &[]);
        let err = parse_send_stream(&no_end).unwrap_err();
        assert!(matches!(err, ffs_types::ParseError::InvalidField { .. }));

        let mut attrs = Vec::new();
        append_send_attr(&mut attrs, 15, b"");
        append_send_attr(&mut attrs, 0xfffe, b"payload");
        let mut multi_attr = make_send_stream_data();
        append_send_command(&mut multi_attr, 4, &attrs);
        append_send_command(&mut multi_attr, 21, &[]);
        let parsed = parse_send_stream(&multi_attr).expect("parse multi-attribute command");
        assert_eq!(parsed.commands.len(), 2);
        assert_eq!(parsed.commands[0].cmd, SendCommand::Mkdir);
        assert_eq!(parsed.commands[0].attrs.len(), 2);
        assert_eq!(parsed.commands[0].attrs[0], (15, Vec::new()));
        assert_eq!(parsed.commands[0].attrs[1], (0xfffe, b"payload".to_vec()));
        assert_eq!(parsed.commands[1].cmd, SendCommand::End);

        let mut partial_header = make_send_stream_data();
        append_send_command(&mut partial_header, 4, &[]);
        partial_header.extend_from_slice(&[0xaa; 9]);
        assert_insufficient_data(parse_send_stream(&partial_header), 10, 27, 9);

        let mut end_payload = Vec::new();
        append_send_attr(&mut end_payload, 15, b"x");
        let mut end_with_payload = make_send_stream_data();
        append_send_command(&mut end_with_payload, 21, &end_payload);
        let parsed = parse_send_stream(&end_with_payload).expect("parse end command TLV payload");
        assert_eq!(parsed.commands.len(), 1);
        assert_eq!(parsed.commands[0].cmd, SendCommand::End);
        assert_eq!(parsed.commands[0].attrs, vec![(15, b"x".to_vec())]);
    }

    #[test]
    fn parse_send_stream_rejects_crc_mismatch() {
        let mut data = make_send_stream_data();
        append_send_command(&mut data, SendCommand::End as u16, &[]);
        data[23] ^= 0x01;

        let err = parse_send_stream(&data).unwrap_err();
        assert!(matches!(err, ffs_types::ParseError::InvalidField { .. }));
    }

    #[test]
    fn parse_send_stream_rejects_malformed_end_payload() {
        let mut data = make_send_stream_data();
        append_send_command(&mut data, SendCommand::End as u16, b"bad");

        let err = parse_send_stream(&data).unwrap_err();
        assert!(matches!(
            err,
            ffs_types::ParseError::InsufficientData { .. }
        ));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn parse_send_stream_with_mkdir() {
        // MKDIR command with path attribute
        let path = b"/testdir";
        let mut payload = Vec::new();
        append_send_attr(&mut payload, 15, path);
        let mut data = make_send_stream_data();
        append_send_command(&mut data, SendCommand::Mkdir as u16, &payload);
        append_send_command(&mut data, SendCommand::End as u16, &[]);

        let result = parse_send_stream(&data).unwrap();
        assert_eq!(result.commands.len(), 2);
        assert_eq!(result.commands[0].cmd, SendCommand::Mkdir);
        assert_eq!(result.commands[0].attrs.len(), 1);
        assert_eq!(result.commands[0].attrs[0].0, 15); // Path attr
        assert_eq!(result.commands[0].attrs[0].1, path);
        assert_eq!(result.commands[1].cmd, SendCommand::End);
    }

    #[test]
    fn parse_send_stream_rejects_bad_magic() {
        let data = b"not-btrfs-magic\x01\x00\x00\x00";
        assert!(parse_send_stream(data).is_err());
    }

    #[test]
    fn parse_send_stream_rejects_unsupported_version() {
        let mut data = Vec::new();
        data.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
        data.extend_from_slice(&BTRFS_SEND_STREAM_VERSION.saturating_add(1).to_le_bytes());
        append_send_command(&mut data, SendCommand::End as u16, &[]);

        let err = parse_send_stream(&data).unwrap_err();
        assert!(matches!(
            err,
            ffs_types::ParseError::InvalidField {
                field: "send_stream_version",
                ..
            }
        ));
    }

    #[test]
    fn parse_send_stream_rejects_truncated_command() {
        let mut data = Vec::new();
        data.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
        data.extend_from_slice(&1_u32.to_le_bytes());
        data.extend_from_slice(&4_u32.to_le_bytes()); // cmd_len
        data.extend_from_slice(&4_u16.to_le_bytes()); // cmd = Mkdir
        data.extend_from_slice(&0_u32.to_le_bytes()); // crc

        let err = parse_send_stream(&data).unwrap_err();
        assert!(matches!(
            err,
            ffs_types::ParseError::InsufficientData { .. }
        ));
    }

    #[test]
    fn parse_send_stream_rejects_truncated_command_header() {
        let mut data = Vec::new();
        data.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
        data.extend_from_slice(&1_u32.to_le_bytes());
        data.extend_from_slice(&[0xAA, 0xBB]); // partial command header

        let err = parse_send_stream(&data).unwrap_err();
        assert!(matches!(
            err,
            ffs_types::ParseError::InsufficientData { .. }
        ));
    }

    #[test]
    fn parse_send_stream_rejects_truncated_attribute() {
        // Command with attribute header but missing attribute payload.
        let mut payload = Vec::new();
        payload.extend_from_slice(&15_u16.to_le_bytes()); // attr type = Path
        payload.extend_from_slice(&8_u16.to_le_bytes()); // attr len (missing payload)
        let mut data = make_send_stream_data();
        append_send_command(&mut data, SendCommand::Mkdir as u16, &payload);

        let err = parse_send_stream(&data).unwrap_err();
        assert!(matches!(
            err,
            ffs_types::ParseError::InsufficientData { .. }
        ));
    }

    #[test]
    fn parse_send_stream_rejects_truncated_attribute_header() {
        let mut data = make_send_stream_data();
        append_send_command(&mut data, SendCommand::Mkdir as u16, &[0x11, 0x22]);

        let err = parse_send_stream(&data).unwrap_err();
        assert!(matches!(
            err,
            ffs_types::ParseError::InsufficientData { .. }
        ));
    }

    #[test]
    fn parse_send_stream_rejects_trailing_bytes_after_end() {
        let mut data = make_send_stream_data();
        append_send_command(&mut data, SendCommand::End as u16, &[]);
        data.extend_from_slice(&[0xEE, 0xFF]); // trailing bytes

        let err = parse_send_stream(&data).unwrap_err();
        assert!(matches!(err, ffs_types::ParseError::InvalidField { .. }));
    }

    // bd-d6o7c — Raw-bytes determinism MR for parse_send_stream.
    // parse_send_stream is invoked for every btrfs send/receive
    // workflow and dispatches CRC32C verification, command-type
    // recognition (via SendCommand::from_u16), and attribute parsing
    // (parse_send_stream_attrs) — significant surface area for
    // non-determinism. Sister parsers parse_root_item (bd-fs41s),
    // parse_xattr_items (bd-fhznm), parse_inode_refs (bd-9f8ef),
    // parse_root_ref (bd-x2320), parse_dir_items (bd-7pr5k),
    // parse_inode_item, parse_extent_data (bd-whybk) all have
    // raw-bytes determinism MRs. A regression that introduced
    // HashMap iteration, allocator-address dependency, or any non-
    // deterministic per-call state would silently surface only under
    // specific scheduling.
    proptest::proptest! {
        #[test]
        fn proptest_parse_send_stream_raw_bytes_determinism(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=256),
        ) {
            let a = parse_send_stream(&bytes);
            let b = parse_send_stream(&bytes);
            proptest::prop_assert_eq!(a, b);
        }

        // bd-gasht — btrfs_send_crc32c foundational laws.
        // btrfs_send_crc32c is the in-house CRC32C primitive (poly
        // 0x82F6_3B78 = bit-reversed Castagnoli) used by
        // send_stream_command_crc32c. The command-header CRC
        // computation (super::send_stream_command_crc32c) splits the
        // input into command[..6] || zeros[..4] || command[10..] and
        // CRC's each piece sequentially — which only works if the
        // primitive is associative. Sister bd-8pbjm (ext4_chksum),
        // bd-oviw2 (crc32c_append), bd-0djme (ext4_gdt_crc16) pin
        // the same laws for the other CRC primitives.

        /// MR-1 — Empty-suffix identity: f(seed, &[]) == seed.
        #[test]
        fn btrfs_send_crc32c_proptest_empty_suffix_is_seed_identity(
            seed in proptest::prelude::any::<u32>(),
        ) {
            proptest::prop_assert_eq!(super::btrfs_send_crc32c(seed, &[]), seed);
        }

        /// MR-2 — Associativity across two-region appends.
        #[test]
        fn btrfs_send_crc32c_proptest_associative_across_appends(
            seed in proptest::prelude::any::<u32>(),
            a in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=256),
            b in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=256),
        ) {
            let mut concat = Vec::with_capacity(a.len() + b.len());
            concat.extend_from_slice(&a);
            concat.extend_from_slice(&b);
            let direct = super::btrfs_send_crc32c(seed, &concat);
            let two_hop = super::btrfs_send_crc32c(super::btrfs_send_crc32c(seed, &a), &b);
            proptest::prop_assert_eq!(direct, two_hop);
        }

        /// MR-3 — Three-region associativity: the exact composition used
        /// by send_stream_command_crc32c (command[..6] || zeros[..4] ||
        /// command[10..]).
        #[test]
        fn btrfs_send_crc32c_proptest_associative_three_way(
            seed in proptest::prelude::any::<u32>(),
            a in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=64),
            b in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=64),
            c in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=64),
        ) {
            let mut concat = Vec::with_capacity(a.len() + b.len() + c.len());
            concat.extend_from_slice(&a);
            concat.extend_from_slice(&b);
            concat.extend_from_slice(&c);
            let direct = super::btrfs_send_crc32c(seed, &concat);
            let three_hop = super::btrfs_send_crc32c(
                super::btrfs_send_crc32c(super::btrfs_send_crc32c(seed, &a), &b),
                &c,
            );
            proptest::prop_assert_eq!(direct, three_hop);
        }
    }

    /// bd-wmkq1 — Kernel-conformance pin for BTRFS_SEND_STREAM_MAGIC
    /// and BTRFS_SEND_STREAM_VERSION per fs/btrfs/send.h. Per the
    /// kernel header:
    ///   #define BTRFS_SEND_STREAM_MAGIC "btrfs-stream"
    ///   #define BTRFS_SEND_STREAM_MAGIC_LEN 13
    ///   #define BTRFS_SEND_STREAM_VERSION 1
    /// These are read by parse_send_stream at the head of every
    /// btrfs-send/receive stream. A regression that drifted either
    /// value would silently reject all valid send streams (or accept
    /// malformed ones with a different magic).
    ///
    /// Sister pins: bd-q5dpf (tree objectids), bd-f0q7n (item-key
    /// types).
    #[test]
    fn btrfs_send_stream_constants_match_send_h() {
        // 13-byte "btrfs-stream\0" magic (12 chars + null).
        assert_eq!(
            BTRFS_SEND_STREAM_MAGIC.len(),
            13,
            "BTRFS_SEND_STREAM_MAGIC must be 13 bytes (12 chars + null)"
        );
        assert_eq!(
            BTRFS_SEND_STREAM_MAGIC, b"btrfs-stream\0",
            "BTRFS_SEND_STREAM_MAGIC bytes must equal kernel magic 'btrfs-stream\\0'"
        );
        // Stream version v1 — has been v1 since send/receive was
        // introduced; if a v2 stream appears, parse_send_stream will
        // need updating.
        assert_eq!(
            BTRFS_SEND_STREAM_VERSION, 1,
            "BTRFS_SEND_STREAM_VERSION must equal kernel value 1"
        );
    }

    /// bd-uwg89 — Kernel-conformance pin for the 23 SendCommand
    /// discriminants per `enum btrfs_send_cmd` in fs/btrfs/send.h.
    /// Each value maps a btrfs-send stream command type
    /// (parse_send_stream dispatches via SendCommand::from_u16). A
    /// regression that swapped any two values (e.g., Mkdir and Mkfile)
    /// or shifted the range would silently corrupt every consumer
    /// of send streams. Sister pins: bd-wmkq1 (BTRFS_SEND_STREAM_MAGIC
    /// + VERSION), bd-q5dpf (tree objectids), bd-f0q7n (item-key types).
    #[test]
    fn btrfs_send_command_constants_match_kernel_header() {
        // Values per fs/btrfs/send.h enum btrfs_send_cmd.
        let cases: &[(&str, SendCommand, u16)] = &[
            ("BTRFS_SEND_C_UNSPEC", SendCommand::Unspec, 0),
            ("BTRFS_SEND_C_SUBVOL", SendCommand::Subvol, 1),
            ("BTRFS_SEND_C_SNAPSHOT", SendCommand::Snapshot, 2),
            ("BTRFS_SEND_C_MKFILE", SendCommand::Mkfile, 3),
            ("BTRFS_SEND_C_MKDIR", SendCommand::Mkdir, 4),
            ("BTRFS_SEND_C_MKNOD", SendCommand::Mknod, 5),
            ("BTRFS_SEND_C_MKFIFO", SendCommand::Mkfifo, 6),
            ("BTRFS_SEND_C_MKSOCK", SendCommand::Mksock, 7),
            ("BTRFS_SEND_C_SYMLINK", SendCommand::Symlink, 8),
            ("BTRFS_SEND_C_RENAME", SendCommand::Rename, 9),
            ("BTRFS_SEND_C_LINK", SendCommand::Link, 10),
            ("BTRFS_SEND_C_UNLINK", SendCommand::Unlink, 11),
            ("BTRFS_SEND_C_RMDIR", SendCommand::Rmdir, 12),
            ("BTRFS_SEND_C_SET_XATTR", SendCommand::SetXattr, 13),
            ("BTRFS_SEND_C_REMOVE_XATTR", SendCommand::RemoveXattr, 14),
            ("BTRFS_SEND_C_WRITE", SendCommand::Write, 15),
            ("BTRFS_SEND_C_CLONE", SendCommand::Clone, 16),
            ("BTRFS_SEND_C_TRUNCATE", SendCommand::Truncate, 17),
            ("BTRFS_SEND_C_CHMOD", SendCommand::Chmod, 18),
            ("BTRFS_SEND_C_CHOWN", SendCommand::Chown, 19),
            ("BTRFS_SEND_C_UTIMES", SendCommand::Utimes, 20),
            ("BTRFS_SEND_C_END", SendCommand::End, 21),
            ("BTRFS_SEND_C_UPDATE_EXTENT", SendCommand::UpdateExtent, 22),
        ];
        for (name, cmd, expected) in cases {
            assert_eq!(
                *cmd as u16, *expected,
                "{name}: discriminant must equal kernel value {expected}"
            );
            // Verify the from_u16 round-trip recovers the same variant.
            assert_eq!(
                SendCommand::from_u16(*expected),
                Some(*cmd),
                "{name}: SendCommand::from_u16({expected}) must round-trip"
            );
        }

        // Pairwise distinctness (every command must map to a unique u16).
        let values: Vec<u16> = cases.iter().map(|&(_, _, v)| v).collect();
        let mut sorted = values.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            values.len(),
            sorted.len(),
            "SendCommand discriminants must be pairwise distinct"
        );

        // Contiguous 0..=22 range — no gaps, no overlaps.
        assert_eq!(*sorted.first().unwrap(), 0);
        assert_eq!(*sorted.last().unwrap(), 22);
        assert_eq!(sorted.len(), 23);
        for (i, &v) in sorted.iter().enumerate() {
            assert_eq!(
                v,
                u16::try_from(i).unwrap(),
                "SendCommand discriminants must be contiguous 0..=22 (gap detected)"
            );
        }

        // from_u16 must reject 23 (one past the largest valid value).
        assert_eq!(
            SendCommand::from_u16(23),
            None,
            "SendCommand::from_u16(23) must reject out-of-range values"
        );
    }

    /// bd-5i0k6 — Kernel-conformance pin for the 25 SendAttr
    /// discriminants per `enum btrfs_send_attr` in fs/btrfs/send.h.
    /// parse_send_stream_attrs reads these from attribute headers
    /// (u16 type field) and stores them as raw (u16, Vec<u8>) pairs
    /// in SendStreamCommand. A regression that swapped XattrName
    /// (13) and XattrData (14), or shifted any value, would silently
    /// corrupt every attribute parse on a btrfs send stream. Sister
    /// pin bd-uwg89 covers SendCommand discriminants.
    #[test]
    fn btrfs_send_attr_constants_match_kernel_header() {
        // Values per fs/btrfs/send.h enum btrfs_send_attr.
        let cases: &[(&str, SendAttr, u16)] = &[
            ("BTRFS_SEND_A_UNSPEC", SendAttr::Unspec, 0),
            ("BTRFS_SEND_A_UUID", SendAttr::Uuid, 1),
            ("BTRFS_SEND_A_CTRANSID", SendAttr::Ctransid, 2),
            ("BTRFS_SEND_A_INO", SendAttr::Ino, 3),
            ("BTRFS_SEND_A_SIZE", SendAttr::Size, 4),
            ("BTRFS_SEND_A_MODE", SendAttr::Mode, 5),
            ("BTRFS_SEND_A_UID", SendAttr::Uid, 6),
            ("BTRFS_SEND_A_GID", SendAttr::Gid, 7),
            ("BTRFS_SEND_A_RDEV", SendAttr::Rdev, 8),
            ("BTRFS_SEND_A_CTIME", SendAttr::Ctime, 9),
            ("BTRFS_SEND_A_MTIME", SendAttr::Mtime, 10),
            ("BTRFS_SEND_A_ATIME", SendAttr::Atime, 11),
            ("BTRFS_SEND_A_OTIME", SendAttr::Otime, 12),
            ("BTRFS_SEND_A_XATTR_NAME", SendAttr::XattrName, 13),
            ("BTRFS_SEND_A_XATTR_DATA", SendAttr::XattrData, 14),
            ("BTRFS_SEND_A_PATH", SendAttr::Path, 15),
            ("BTRFS_SEND_A_PATH_TO", SendAttr::PathTo, 16),
            ("BTRFS_SEND_A_PATH_LINK", SendAttr::PathLink, 17),
            ("BTRFS_SEND_A_FILE_OFFSET", SendAttr::FileOffset, 18),
            ("BTRFS_SEND_A_DATA", SendAttr::Data, 19),
            ("BTRFS_SEND_A_CLONE_UUID", SendAttr::CloneUuid, 20),
            ("BTRFS_SEND_A_CLONE_CTRANSID", SendAttr::CloneCtransid, 21),
            ("BTRFS_SEND_A_CLONE_PATH", SendAttr::ClonePath, 22),
            ("BTRFS_SEND_A_CLONE_OFFSET", SendAttr::CloneOffset, 23),
            ("BTRFS_SEND_A_CLONE_LEN", SendAttr::CloneLen, 24),
        ];
        for (name, attr, expected) in cases {
            assert_eq!(
                *attr as u16, *expected,
                "{name}: discriminant must equal kernel value {expected}"
            );
        }

        // Pairwise distinctness.
        let values: Vec<u16> = cases.iter().map(|&(_, _, v)| v).collect();
        let mut sorted = values.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            values.len(),
            sorted.len(),
            "SendAttr discriminants must be pairwise distinct"
        );

        // Contiguous 0..=24 range (no gaps).
        assert_eq!(*sorted.first().unwrap(), 0);
        assert_eq!(*sorted.last().unwrap(), 24);
        assert_eq!(sorted.len(), 25);
        for (i, &v) in sorted.iter().enumerate() {
            assert_eq!(
                v,
                u16::try_from(i).unwrap(),
                "SendAttr discriminants must be contiguous 0..=24 (gap detected)"
            );
        }

        // SendCommand and SendAttr discriminants overlap (both start at
        // 0 and run contiguously). The kernel uses separate enum
        // namespaces (cmd at the command-header `cmd` field, attr at
        // the attribute-table `type` field), so overlap is intentional;
        // this assert documents that the parser MUST distinguish based
        // on byte position, not numeric value.
        assert_eq!(SendCommand::Mkdir as u16, SendAttr::Size as u16);
    }

    /// bd-q5dpf — Kernel-conformance pin for the 11 BTRFS_*_TREE_OBJECTID
    /// constants + BTRFS_FIRST_FREE_OBJECTID per fs/btrfs/btrfs_tree.h.
    /// These identify every btree in btrfs (root, extent, chunk, dev,
    /// fs, csum, quota, uuid, free_space, block_group, plus the v1
    /// root_tree_dir directory entry inside the root tree). Every
    /// chunk-tree/root-tree/extent-tree/csum-tree lookup keys on these
    /// values. A regression that drifted any value would silently
    /// mis-route every tree operation — e.g., swapping the CHUNK and
    /// DEV tree IDs would make every chunk lookup hit the device-tree
    /// root and silently corrupt logical→physical address translation.
    ///
    /// Sister pins: bd-f0q7n (item-key types), bd-eiblh (ext4 incompat),
    /// bd-up9ff (compat/ro_compat), bd-wa27v (xattr), bd-mo92w
    /// (DX_HASH), bd-7stug (super flags).
    #[test]
    fn btrfs_tree_objectid_constants_match_btrfs_tree_h() {
        // Per fs/btrfs/btrfs_tree.h:
        //   #define BTRFS_ROOT_TREE_OBJECTID       1ULL
        //   #define BTRFS_EXTENT_TREE_OBJECTID     2ULL
        //   #define BTRFS_CHUNK_TREE_OBJECTID      3ULL
        //   #define BTRFS_DEV_TREE_OBJECTID        4ULL
        //   #define BTRFS_FS_TREE_OBJECTID         5ULL
        //   #define BTRFS_ROOT_TREE_DIR_OBJECTID   6ULL
        //   #define BTRFS_CSUM_TREE_OBJECTID       7ULL
        //   #define BTRFS_QUOTA_TREE_OBJECTID      8ULL
        //   #define BTRFS_UUID_TREE_OBJECTID       9ULL
        //   #define BTRFS_FREE_SPACE_TREE_OBJECTID 10ULL
        //   #define BTRFS_BLOCK_GROUP_TREE_OBJECTID 11ULL
        //   #define BTRFS_FIRST_FREE_OBJECTID      256ULL
        let cases: &[(&str, u64, u64)] = &[
            ("ROOT_TREE", BTRFS_ROOT_TREE_OBJECTID, 1),
            ("EXTENT_TREE", BTRFS_EXTENT_TREE_OBJECTID, 2),
            ("CHUNK_TREE", BTRFS_CHUNK_TREE_OBJECTID, 3),
            ("DEV_TREE", BTRFS_DEV_TREE_OBJECTID, 4),
            ("FS_TREE", BTRFS_FS_TREE_OBJECTID, 5),
            ("ROOT_TREE_DIR", BTRFS_ROOT_TREE_DIR_OBJECTID, 6),
            ("CSUM_TREE", BTRFS_CSUM_TREE_OBJECTID, 7),
            ("QUOTA_TREE", BTRFS_QUOTA_TREE_OBJECTID, 8),
            ("UUID_TREE", BTRFS_UUID_TREE_OBJECTID, 9),
            ("FREE_SPACE_TREE", BTRFS_FREE_SPACE_TREE_OBJECTID, 10),
            ("BLOCK_GROUP_TREE", BTRFS_BLOCK_GROUP_TREE_OBJECTID, 11),
            ("FIRST_FREE", BTRFS_FIRST_FREE_OBJECTID, 256),
        ];
        for (name, actual, expected) in cases {
            assert_eq!(
                actual, expected,
                "BTRFS_{name}_OBJECTID must equal kernel value {expected}"
            );
        }

        // Pairwise distinctness: every objectid must be unique. A
        // regression that aliased two would silently route both tree
        // lookups to the same key.
        let values: Vec<u64> = cases.iter().map(|&(_, v, _)| v).collect();
        let mut sorted = values.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            values.len(),
            sorted.len(),
            "BTRFS_*_TREE_OBJECTID values must be pairwise distinct"
        );

        // Reserved range contract: the named tree objectids occupy
        // 1..=11 contiguously, then FIRST_FREE_OBJECTID=256 marks the
        // boundary above which user-allocated objectids begin. The
        // kernel reserves 11 < x < 256 for future tree IDs.
        const {
            assert!(BTRFS_ROOT_TREE_OBJECTID == 1);
            assert!(BTRFS_BLOCK_GROUP_TREE_OBJECTID == 11);
            assert!(BTRFS_FIRST_FREE_OBJECTID == 256);
            assert!(BTRFS_BLOCK_GROUP_TREE_OBJECTID < BTRFS_FIRST_FREE_OBJECTID);
        }
    }

    /// bd-f0q7n — Kernel-conformance pin for the on-disk item-key
    /// type field constants declared as `BTRFS_ITEM_*` in this crate.
    /// Each value mirrors a kernel macro from `fs/btrfs/btrfs_tree.h`.
    /// A regression that swapped, e.g., BTRFS_ITEM_DIR_ITEM (84) and
    /// BTRFS_ITEM_DIR_INDEX (96) would silently mis-route every btrfs
    /// directory iteration — dir_index entries would be parsed as
    /// dir_item entries (different key.offset semantics: hash vs
    /// sequence-counter). This test pins each value plus the
    /// monotonic ordering across the reserved range.
    #[test]
    fn btrfs_item_key_constants_match_kernel_header() {
        // Values per fs/btrfs/btrfs_tree.h:
        //   #define BTRFS_INODE_ITEM_KEY        1
        //   #define BTRFS_INODE_REF_KEY        12
        //   #define BTRFS_XATTR_ITEM_KEY       24
        //   #define BTRFS_DIR_ITEM_KEY         84
        //   #define BTRFS_DIR_INDEX_KEY        96
        //   #define BTRFS_EXTENT_DATA_KEY     108
        //   #define BTRFS_ROOT_ITEM_KEY       132
        //   #define BTRFS_EXTENT_ITEM_KEY     168
        //   #define BTRFS_METADATA_ITEM_KEY   169
        //   #define BTRFS_TREE_BLOCK_REF_KEY 176
        //   #define BTRFS_EXTENT_DATA_REF_KEY 178
        //   #define BTRFS_BLOCK_GROUP_ITEM_KEY 192
        //   #define BTRFS_FREE_SPACE_INFO_KEY  198
        //   #define BTRFS_FREE_SPACE_EXTENT_KEY 199
        //   #define BTRFS_FREE_SPACE_BITMAP_KEY 200
        //   #define BTRFS_DEV_ITEM_KEY        216
        //   #define BTRFS_CHUNK_ITEM_KEY      228
        assert_eq!(BTRFS_ITEM_INODE_ITEM, 1);
        assert_eq!(BTRFS_ITEM_INODE_REF, 12);
        assert_eq!(BTRFS_ITEM_XATTR_ITEM, 24);
        assert_eq!(BTRFS_ITEM_DIR_ITEM, 84);
        assert_eq!(BTRFS_ITEM_DIR_INDEX, 96);
        assert_eq!(BTRFS_ITEM_EXTENT_DATA, 108);
        assert_eq!(BTRFS_ITEM_ROOT_ITEM, 132);
        assert_eq!(BTRFS_ITEM_EXTENT_ITEM, 168);
        assert_eq!(BTRFS_ITEM_METADATA_ITEM, 169);
        assert_eq!(BTRFS_ITEM_TREE_BLOCK_REF, 176);
        assert_eq!(BTRFS_ITEM_EXTENT_DATA_REF, 178);
        assert_eq!(BTRFS_ITEM_BLOCK_GROUP_ITEM, 192);
        assert_eq!(BTRFS_ITEM_FREE_SPACE_INFO, 198);
        assert_eq!(BTRFS_ITEM_FREE_SPACE_EXTENT, 199);
        assert_eq!(BTRFS_ITEM_FREE_SPACE_BITMAP, 200);
        assert_eq!(BTRFS_ITEM_DEV_ITEM, 216);
        assert_eq!(BTRFS_ITEM_CHUNK, 228);

        // Strict-monotonic ascending across the 15-element set; pins
        // that no two constants collide and that the implicit
        // dispatch order (small inode/ref/xattr keys before large
        // extent/chunk keys) is preserved.
        const {
            assert!(
                BTRFS_ITEM_INODE_ITEM < BTRFS_ITEM_INODE_REF
                    && BTRFS_ITEM_INODE_REF < BTRFS_ITEM_XATTR_ITEM
                    && BTRFS_ITEM_XATTR_ITEM < BTRFS_ITEM_DIR_ITEM
                    && BTRFS_ITEM_DIR_ITEM < BTRFS_ITEM_DIR_INDEX
                    && BTRFS_ITEM_DIR_INDEX < BTRFS_ITEM_EXTENT_DATA
                    && BTRFS_ITEM_EXTENT_DATA < BTRFS_ITEM_ROOT_ITEM
                    && BTRFS_ITEM_ROOT_ITEM < BTRFS_ITEM_EXTENT_ITEM
                    && BTRFS_ITEM_EXTENT_ITEM < BTRFS_ITEM_METADATA_ITEM
                    && BTRFS_ITEM_METADATA_ITEM < BTRFS_ITEM_TREE_BLOCK_REF
                    && BTRFS_ITEM_TREE_BLOCK_REF < BTRFS_ITEM_EXTENT_DATA_REF
                    && BTRFS_ITEM_EXTENT_DATA_REF < BTRFS_ITEM_BLOCK_GROUP_ITEM
                    && BTRFS_ITEM_METADATA_ITEM < BTRFS_ITEM_BLOCK_GROUP_ITEM
                    && BTRFS_ITEM_BLOCK_GROUP_ITEM < BTRFS_ITEM_FREE_SPACE_INFO
                    && BTRFS_ITEM_FREE_SPACE_INFO < BTRFS_ITEM_FREE_SPACE_EXTENT
                    && BTRFS_ITEM_FREE_SPACE_EXTENT < BTRFS_ITEM_FREE_SPACE_BITMAP
                    && BTRFS_ITEM_FREE_SPACE_BITMAP < BTRFS_ITEM_DEV_ITEM
                    && BTRFS_ITEM_DEV_ITEM < BTRFS_ITEM_CHUNK,
                "btrfs item-key constants must be strict-monotonic ascending"
            );
        }

        // Boundary checks — pin specific kernel-published gaps so a
        // future contributor adding a constant in the middle (e.g.,
        // BTRFS_ROOT_BACKREF_KEY=144) doesn't accidentally collide
        // with an existing value.
        const {
            assert!(
                BTRFS_ITEM_ROOT_ITEM == 132 && BTRFS_ITEM_EXTENT_ITEM == 168,
                "kernel reserves 133..168 for {{ROOT_BACKREF=144, ROOT_REF=156}} \
                 — these slots must remain free"
            );
            assert!(
                BTRFS_ITEM_METADATA_ITEM == 169
                    && BTRFS_ITEM_TREE_BLOCK_REF == 176
                    && BTRFS_ITEM_EXTENT_DATA_REF == 178
                    && BTRFS_ITEM_BLOCK_GROUP_ITEM == 192,
                "kernel reserves 170..192 for extent backrefs; TREE_BLOCK_REF=176 and \
                 EXTENT_DATA_REF=178 are intentionally modeled by the allocator"
            );
        }
    }

    /// bd-cwfuf — Kernel-conformance pin for directory entry file-type
    /// values stored in `struct btrfs_dir_item.type`.
    #[test]
    fn btrfs_dir_file_type_constants_match_kernel_header() {
        // Values per include/uapi/linux/btrfs_tree.h, and the kernel
        // requires 0..7 to match the common Linux file type values.
        assert_eq!(BTRFS_FT_UNKNOWN, 0);
        assert_eq!(BTRFS_FT_REG_FILE, 1);
        assert_eq!(BTRFS_FT_DIR, 2);
        assert_eq!(BTRFS_FT_CHRDEV, 3);
        assert_eq!(BTRFS_FT_BLKDEV, 4);
        assert_eq!(BTRFS_FT_FIFO, 5);
        assert_eq!(BTRFS_FT_SOCK, 6);
        assert_eq!(BTRFS_FT_SYMLINK, 7);

        const {
            assert!(
                BTRFS_FT_UNKNOWN < BTRFS_FT_REG_FILE
                    && BTRFS_FT_REG_FILE < BTRFS_FT_DIR
                    && BTRFS_FT_DIR < BTRFS_FT_CHRDEV
                    && BTRFS_FT_CHRDEV < BTRFS_FT_BLKDEV
                    && BTRFS_FT_BLKDEV < BTRFS_FT_FIFO
                    && BTRFS_FT_FIFO < BTRFS_FT_SOCK
                    && BTRFS_FT_SOCK < BTRFS_FT_SYMLINK,
                "btrfs dir file-type constants must be strict-monotonic ascending"
            );
        }
        assert_eq!(
            BTRFS_FT_SYMLINK - BTRFS_FT_UNKNOWN,
            7,
            "the supported btrfs dir file-type range must be contiguous 0..=7"
        );
    }

    /// bd-cwfuf — Kernel-conformance pin for EXTENT_DATA payload type
    /// discriminants stored in `struct btrfs_file_extent_item.type`.
    #[test]
    fn btrfs_file_extent_type_constants_match_kernel_header() {
        // Values per include/uapi/linux/btrfs_tree.h.
        assert_eq!(BTRFS_FILE_EXTENT_INLINE, 0);
        assert_eq!(BTRFS_FILE_EXTENT_REG, 1);
        assert_eq!(BTRFS_FILE_EXTENT_PREALLOC, 2);

        const {
            assert!(
                BTRFS_FILE_EXTENT_INLINE < BTRFS_FILE_EXTENT_REG
                    && BTRFS_FILE_EXTENT_REG < BTRFS_FILE_EXTENT_PREALLOC,
                "btrfs file extent type constants must be strict-monotonic ascending"
            );
        }
        assert_eq!(
            BTRFS_FILE_EXTENT_PREALLOC - BTRFS_FILE_EXTENT_INLINE,
            2,
            "the btrfs file extent type range must be contiguous 0..=2"
        );
    }

    /// bd-cwfuf — Kernel-conformance pin for btrfs compression encoding
    /// values accepted by the EXTENT_DATA parser.
    #[test]
    fn btrfs_compression_type_constants_match_kernel_header() {
        // Values per fs/btrfs/fs.h `enum btrfs_compression_type`.
        assert_eq!(BTRFS_COMPRESS_NONE, 0);
        assert_eq!(BTRFS_COMPRESS_ZLIB, 1);
        assert_eq!(BTRFS_COMPRESS_LZO, 2);
        assert_eq!(BTRFS_COMPRESS_ZSTD, 3);

        const {
            assert!(
                BTRFS_COMPRESS_NONE < BTRFS_COMPRESS_ZLIB
                    && BTRFS_COMPRESS_ZLIB < BTRFS_COMPRESS_LZO
                    && BTRFS_COMPRESS_LZO < BTRFS_COMPRESS_ZSTD,
                "btrfs compression constants must be strict-monotonic ascending"
            );
        }
        assert_eq!(
            BTRFS_COMPRESS_ZSTD - BTRFS_COMPRESS_NONE,
            3,
            "the btrfs compression type range must be contiguous 0..=3"
        );
    }

    /// bd-m6chz — Kernel-conformance pin for the 17 BTRFS_ITEM_*
    /// leaf-key type constants per `include/uapi/linux/btrfs_tree.h`.
    ///
    /// Every leaf walk in the btrfs read path dispatches to the
    /// right payload parser (parse_inode_item, parse_dir_items,
    /// parse_inode_refs, parse_xattr_items, parse_extent_data,
    /// parse_root_item, parse_root_ref, …) by matching the leaf
    /// item's `key.type` against these constants. A regression that
    /// swapped any two values (e.g., DIR_ITEM=84 ↔ DIR_INDEX=96)
    /// would silently route the wrong parser for every leaf walk
    /// but pass functional tests that only exercise INODE_ITEM.
    ///
    /// Pairs with bd-qyfph (BTRFS_FT_*), bd-cwfuf (FILE_EXTENT +
    /// COMPRESS), bd-6uu7j (chunk_type_flags), bd-khzn4 (tree
    /// objectids).
    #[test]
    fn btrfs_leaf_item_type_constants_match_kernel_header() {
        // Values per include/uapi/linux/btrfs_tree.h.
        // Read-path types.
        assert_eq!(BTRFS_ITEM_INODE_ITEM, 1);
        assert_eq!(BTRFS_ITEM_INODE_REF, 12);
        assert_eq!(BTRFS_ITEM_XATTR_ITEM, 24);
        assert_eq!(BTRFS_ITEM_DIR_ITEM, 84);
        assert_eq!(BTRFS_ITEM_DIR_INDEX, 96);
        assert_eq!(BTRFS_ITEM_EXTENT_DATA, 108);
        assert_eq!(BTRFS_ITEM_ROOT_ITEM, 132);
        // Subvolume nav.
        assert_eq!(BTRFS_ITEM_ROOT_BACKREF, 144);
        assert_eq!(BTRFS_ITEM_ROOT_REF, 156);
        // Extent / block-group / chunk management.
        assert_eq!(BTRFS_ITEM_EXTENT_ITEM, 168);
        assert_eq!(BTRFS_ITEM_METADATA_ITEM, 169);
        assert_eq!(BTRFS_ITEM_TREE_BLOCK_REF, 176);
        assert_eq!(BTRFS_ITEM_EXTENT_DATA_REF, 178);
        assert_eq!(BTRFS_ITEM_BLOCK_GROUP_ITEM, 192);
        assert_eq!(BTRFS_ITEM_FREE_SPACE_INFO, 198);
        assert_eq!(BTRFS_ITEM_FREE_SPACE_EXTENT, 199);
        assert_eq!(BTRFS_ITEM_FREE_SPACE_BITMAP, 200);
        assert_eq!(BTRFS_ITEM_DEV_ITEM, 216);
        assert_eq!(BTRFS_ITEM_CHUNK, 228);

        // Uniqueness invariant: every constant must have a distinct
        // value so the leaf-walk dispatch is unambiguous.
        let constants: [(&str, u8); 19] = [
            ("INODE_ITEM", BTRFS_ITEM_INODE_ITEM),
            ("INODE_REF", BTRFS_ITEM_INODE_REF),
            ("XATTR_ITEM", BTRFS_ITEM_XATTR_ITEM),
            ("DIR_ITEM", BTRFS_ITEM_DIR_ITEM),
            ("DIR_INDEX", BTRFS_ITEM_DIR_INDEX),
            ("EXTENT_DATA", BTRFS_ITEM_EXTENT_DATA),
            ("ROOT_ITEM", BTRFS_ITEM_ROOT_ITEM),
            ("ROOT_BACKREF", BTRFS_ITEM_ROOT_BACKREF),
            ("ROOT_REF", BTRFS_ITEM_ROOT_REF),
            ("EXTENT_ITEM", BTRFS_ITEM_EXTENT_ITEM),
            ("METADATA_ITEM", BTRFS_ITEM_METADATA_ITEM),
            ("TREE_BLOCK_REF", BTRFS_ITEM_TREE_BLOCK_REF),
            ("EXTENT_DATA_REF", BTRFS_ITEM_EXTENT_DATA_REF),
            ("BLOCK_GROUP_ITEM", BTRFS_ITEM_BLOCK_GROUP_ITEM),
            ("FREE_SPACE_INFO", BTRFS_ITEM_FREE_SPACE_INFO),
            ("FREE_SPACE_EXTENT", BTRFS_ITEM_FREE_SPACE_EXTENT),
            ("FREE_SPACE_BITMAP", BTRFS_ITEM_FREE_SPACE_BITMAP),
            ("DEV_ITEM", BTRFS_ITEM_DEV_ITEM),
            ("CHUNK", BTRFS_ITEM_CHUNK),
        ];
        for (i, &(name_a, value_a)) in constants.iter().enumerate() {
            for &(name_b, value_b) in &constants[i + 1..] {
                assert_ne!(
                    value_a, value_b,
                    "BTRFS_ITEM_{name_a} and BTRFS_ITEM_{name_b} must have distinct values"
                );
            }
        }
    }

    /// bd-qyfph — Kernel-conformance pin for the BTRFS_FT_* directory
    /// file-type constants stored in `struct btrfs_dir_item.type` per
    /// `include/uapi/linux/btrfs_tree.h`. These values mirror the kernel
    /// `DT_*` constants from `include/uapi/linux/fs.h` (UNKNOWN=0,
    /// REG=1, DIR=2, CHR=3, BLK=4, FIFO=5, SOCK=6, LNK=7).
    ///
    /// A regression that swapped any two values would silently
    /// mis-classify every directory entry by file type but pass
    /// functional tests that only round-trip through a single
    /// `BtrfsDirItem` round-trip (e.g., dir_item_round_trip uses
    /// REG_FILE only).
    ///
    /// Pairs with bd-343v3 (ext4 EXT4_FT_*), bd-cwfuf (btrfs file-extent
    /// + compression types), bd-6uu7j (btrfs chunk_type_flags),
    ///   bd-khzn4 (btrfs tree objectids).
    #[test]
    fn btrfs_ft_constants_match_kernel_header() {
        // Values per include/uapi/linux/fs.h DT_* (mirrored by
        // include/uapi/linux/btrfs_tree.h BTRFS_FT_*).
        assert_eq!(
            BTRFS_FT_UNKNOWN, 0,
            "BTRFS_FT_UNKNOWN must equal kernel DT_UNKNOWN"
        );
        assert_eq!(
            BTRFS_FT_REG_FILE, 1,
            "BTRFS_FT_REG_FILE must equal kernel DT_REG"
        );
        assert_eq!(BTRFS_FT_DIR, 2, "BTRFS_FT_DIR must equal kernel DT_DIR");
        assert_eq!(
            BTRFS_FT_CHRDEV, 3,
            "BTRFS_FT_CHRDEV must equal kernel DT_CHR"
        );
        assert_eq!(
            BTRFS_FT_BLKDEV, 4,
            "BTRFS_FT_BLKDEV must equal kernel DT_BLK"
        );
        assert_eq!(BTRFS_FT_FIFO, 5, "BTRFS_FT_FIFO must equal kernel DT_FIFO");
        assert_eq!(BTRFS_FT_SOCK, 6, "BTRFS_FT_SOCK must equal kernel DT_SOCK");
        assert_eq!(
            BTRFS_FT_SYMLINK, 7,
            "BTRFS_FT_SYMLINK must equal kernel DT_LNK"
        );

        // Strict-monotonic ascending across the contiguous 0..=7 range.
        let values: [u8; 8] = [
            BTRFS_FT_UNKNOWN,
            BTRFS_FT_REG_FILE,
            BTRFS_FT_DIR,
            BTRFS_FT_CHRDEV,
            BTRFS_FT_BLKDEV,
            BTRFS_FT_FIFO,
            BTRFS_FT_SOCK,
            BTRFS_FT_SYMLINK,
        ];
        for window in values.windows(2) {
            assert!(
                window[0] < window[1],
                "BTRFS_FT_* constants must be strict-monotonic ascending"
            );
        }
        assert_eq!(
            BTRFS_FT_SYMLINK - BTRFS_FT_UNKNOWN,
            7,
            "the BTRFS_FT_* range must be contiguous 0..=7"
        );

        // Cross-check with ext4 parity: each BTRFS_FT_* equals the
        // corresponding ext4 EXT4_FT_* (verified separately at
        // bd-343v3) — this strict equality is what lets the FUSE
        // layer use a single `u8` discriminant across both backends.
        // Asserting the integer values here is sufficient.
    }

    /// bd-3915j — Kernel-conformance pin for the ffs-btrfs copies
    /// of BTRFS_BLOCK_GROUP_{DATA,SYSTEM,METADATA}.
    ///
    /// ffs-btrfs declares its own copies of these flag constants
    /// at lib.rs:65-67 (parallel to ffs_ondisk::btrfs::chunk_type_flags::*).
    /// Both copies are needed: ffs_ondisk for the chunk-type parser
    /// layer (pinned by bd-6uu7j), ffs-btrfs for the higher-level
    /// BlockGroupItem layer used by allocator hot paths and cross-impl
    /// tests. Without this pin, a future contributor could change one
    /// copy without the other and silently produce a divergent flag
    /// dispatch (e.g. SYSTEM=4 in ffs-btrfs and SYSTEM=2 in ffs-ondisk
    /// would mis-route every system block group lookup).
    ///
    /// Per fs/btrfs/btrfs_tree.h:
    ///   #define BTRFS_BLOCK_GROUP_DATA      (1ULL << 0)
    ///   #define BTRFS_BLOCK_GROUP_SYSTEM    (1ULL << 1)
    ///   #define BTRFS_BLOCK_GROUP_METADATA  (1ULL << 2)
    ///
    /// Pin each value, the power-of-two-bit invariant, the pairwise-
    /// disjoint invariant, AND cross-check equality with the
    /// ffs_ondisk::btrfs::chunk_type_flags copies — closing the
    /// cross-crate drift hole.
    #[test]
    fn ffs_btrfs_block_group_type_flags_match_kernel_and_ondisk() {
        // 1. Pin each value to the kernel literal.
        assert_eq!(
            BTRFS_BLOCK_GROUP_DATA, 1,
            "BTRFS_BLOCK_GROUP_DATA must equal (1ULL << 0)"
        );
        assert_eq!(
            BTRFS_BLOCK_GROUP_SYSTEM, 2,
            "BTRFS_BLOCK_GROUP_SYSTEM must equal (1ULL << 1)"
        );
        assert_eq!(
            BTRFS_BLOCK_GROUP_METADATA, 4,
            "BTRFS_BLOCK_GROUP_METADATA must equal (1ULL << 2)"
        );

        // 2. Each must be a single power-of-two bit (single-flag
        // invariant — required for bitmask dispatch).
        assert!(
            BTRFS_BLOCK_GROUP_DATA.is_power_of_two(),
            "BTRFS_BLOCK_GROUP_DATA must be a single bit"
        );
        assert!(
            BTRFS_BLOCK_GROUP_SYSTEM.is_power_of_two(),
            "BTRFS_BLOCK_GROUP_SYSTEM must be a single bit"
        );
        assert!(
            BTRFS_BLOCK_GROUP_METADATA.is_power_of_two(),
            "BTRFS_BLOCK_GROUP_METADATA must be a single bit"
        );

        // 3. Pairwise disjoint (no two flags share a bit).
        assert_eq!(BTRFS_BLOCK_GROUP_DATA & BTRFS_BLOCK_GROUP_SYSTEM, 0);
        assert_eq!(BTRFS_BLOCK_GROUP_DATA & BTRFS_BLOCK_GROUP_METADATA, 0);
        assert_eq!(BTRFS_BLOCK_GROUP_SYSTEM & BTRFS_BLOCK_GROUP_METADATA, 0);

        // 4. Cross-check with the ffs_ondisk parser-layer copies —
        // the two crates must NEVER drift apart.
        assert_eq!(
            BTRFS_BLOCK_GROUP_DATA,
            ffs_ondisk::btrfs::chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
            "ffs_btrfs::BTRFS_BLOCK_GROUP_DATA must equal ffs_ondisk's copy"
        );
        assert_eq!(
            BTRFS_BLOCK_GROUP_SYSTEM,
            ffs_ondisk::btrfs::chunk_type_flags::BTRFS_BLOCK_GROUP_SYSTEM,
            "ffs_btrfs::BTRFS_BLOCK_GROUP_SYSTEM must equal ffs_ondisk's copy"
        );
        assert_eq!(
            BTRFS_BLOCK_GROUP_METADATA,
            ffs_ondisk::btrfs::chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA,
            "ffs_btrfs::BTRFS_BLOCK_GROUP_METADATA must equal ffs_ondisk's copy"
        );
    }

    /// bd-cwfuf — Kernel-conformance pin for `BTRFS_MAX_LEVEL`.
    #[test]
    fn btrfs_max_tree_level_matches_kernel_level_count() {
        // The kernel macro is a count (`BTRFS_MAX_LEVEL == 8`), while
        // this crate stores the highest valid on-disk level (`0..=7`).
        assert_eq!(BTRFS_MAX_TREE_LEVEL, 7);
        assert_eq!(BTRFS_MAX_TREE_LEVEL + 1, 8);
    }

    /// bd-khzn4 — Kernel-conformance pin for the well-known btrfs
    /// tree objectids declared in `fs/btrfs/btrfs_tree.h`. A regression
    /// that swapped, say, BTRFS_FREE_SPACE_TREE (10) and
    /// BTRFS_BLOCK_GROUP_TREE (11) would silently mis-route v2 metadata
    /// reads. This test pins each value AND the strict-monotonic
    /// ordering across the contiguous reserved range 1..=11 plus the
    /// FIRST_FREE = 256 boundary.
    #[test]
    fn btrfs_tree_objectid_constants_match_kernel_header() {
        // Values per fs/btrfs/btrfs_tree.h.
        assert_eq!(BTRFS_ROOT_TREE_OBJECTID, 1);
        assert_eq!(BTRFS_EXTENT_TREE_OBJECTID, 2);
        assert_eq!(BTRFS_CHUNK_TREE_OBJECTID, 3);
        assert_eq!(BTRFS_DEV_TREE_OBJECTID, 4);
        assert_eq!(BTRFS_FS_TREE_OBJECTID, 5);
        assert_eq!(BTRFS_ROOT_TREE_DIR_OBJECTID, 6);
        assert_eq!(BTRFS_CSUM_TREE_OBJECTID, 7);
        assert_eq!(BTRFS_QUOTA_TREE_OBJECTID, 8);
        assert_eq!(BTRFS_UUID_TREE_OBJECTID, 9);
        assert_eq!(BTRFS_FREE_SPACE_TREE_OBJECTID, 10);
        assert_eq!(BTRFS_BLOCK_GROUP_TREE_OBJECTID, 11);
        assert_eq!(BTRFS_FIRST_FREE_OBJECTID, 256);

        // Strict-monotonic ascending across the reserved range, with
        // a jump to FIRST_FREE that leaves room for non-upstream
        // tree objectids in [12, 256).
        const {
            assert!(
                BTRFS_ROOT_TREE_OBJECTID < BTRFS_EXTENT_TREE_OBJECTID
                    && BTRFS_EXTENT_TREE_OBJECTID < BTRFS_CHUNK_TREE_OBJECTID
                    && BTRFS_CHUNK_TREE_OBJECTID < BTRFS_DEV_TREE_OBJECTID
                    && BTRFS_DEV_TREE_OBJECTID < BTRFS_FS_TREE_OBJECTID
                    && BTRFS_FS_TREE_OBJECTID < BTRFS_ROOT_TREE_DIR_OBJECTID
                    && BTRFS_ROOT_TREE_DIR_OBJECTID < BTRFS_CSUM_TREE_OBJECTID
                    && BTRFS_CSUM_TREE_OBJECTID < BTRFS_QUOTA_TREE_OBJECTID
                    && BTRFS_QUOTA_TREE_OBJECTID < BTRFS_UUID_TREE_OBJECTID
                    && BTRFS_UUID_TREE_OBJECTID < BTRFS_FREE_SPACE_TREE_OBJECTID
                    && BTRFS_FREE_SPACE_TREE_OBJECTID < BTRFS_BLOCK_GROUP_TREE_OBJECTID
                    && BTRFS_BLOCK_GROUP_TREE_OBJECTID < BTRFS_FIRST_FREE_OBJECTID,
                "btrfs tree objectids must be strict-monotonic ascending"
            );
        }

        // The reserved range is contiguous 1..=11 (no gaps).
        assert_eq!(
            BTRFS_BLOCK_GROUP_TREE_OBJECTID - BTRFS_ROOT_TREE_OBJECTID,
            10,
            "the reserved tree objectid range must be contiguous 1..=11"
        );
    }

    #[test]
    fn cow_node_serialize_leaf_roundtrip() {
        use ffs_ondisk::{BtrfsHeader, parse_leaf_items, verify_btrfs_tree_block_checksum};

        const INODE_ITEM_KEY: u8 = 1;
        const DIR_ITEM_KEY: u8 = 84;

        let items = vec![
            BtrfsTreeItem {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: INODE_ITEM_KEY,
                    offset: 0,
                },
                data: vec![0xAA; 160],
            },
            BtrfsTreeItem {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: DIR_ITEM_KEY,
                    offset: 0x1234,
                },
                data: vec![0xBB; 32],
            },
        ];
        let node = BtrfsCowNode::Leaf { items };

        let params = BtrfsNodeSerializeParams {
            fsid: [0x11; 16],
            chunk_tree_uuid: [0x22; 16],
            bytenr: 0x10000,
            flags: 0,
            generation: 100,
            owner: 5,
            nodesize: 16384,
            level: 0, // leaf
            child_generations: vec![],
            child_bytenrs: vec![],
        };

        let buf = node.serialize(&params).expect("serialize should succeed");
        assert_eq!(buf.len(), 16384);

        verify_btrfs_tree_block_checksum(&buf, ffs_types::BTRFS_CSUM_TYPE_CRC32C)
            .expect("checksum should be valid");

        let hdr = BtrfsHeader::parse_from_block(&buf).expect("parse header");
        assert_eq!(hdr.bytenr, 0x10000);
        assert_eq!(hdr.generation, 100);
        assert_eq!(hdr.owner, 5);
        assert_eq!(hdr.nritems, 2);
        assert_eq!(hdr.level, 0);

        let (_, parsed_items) = parse_leaf_items(&buf).expect("parse should succeed");
        assert_eq!(parsed_items.len(), 2);
        assert_eq!(parsed_items[0].key.objectid, 256);
        assert_eq!(parsed_items[0].key.item_type, INODE_ITEM_KEY);
        assert_eq!(parsed_items[1].key.objectid, 256);
        assert_eq!(parsed_items[1].key.item_type, DIR_ITEM_KEY);
    }

    #[test]
    fn cow_node_serialize_internal_roundtrip() {
        use ffs_ondisk::{BtrfsHeader, parse_internal_items, verify_btrfs_tree_block_checksum};

        let keys = vec![
            BtrfsKey {
                objectid: 256,
                item_type: 1,
                offset: 0,
            },
            BtrfsKey {
                objectid: 512,
                item_type: 1,
                offset: 0,
            },
        ];
        let children = vec![0x20000_u64, 0x30000_u64, 0x40000_u64];
        let node = BtrfsCowNode::Internal { keys, children };

        let params = BtrfsNodeSerializeParams {
            fsid: [0x33; 16],
            chunk_tree_uuid: [0x44; 16],
            bytenr: 0x50000,
            flags: 0,
            generation: 200,
            owner: 1,
            nodesize: 16384,
            level: 1, // internal node, level 1
            child_generations: vec![190, 195, 200],
            child_bytenrs: vec![],
        };

        let buf = node.serialize(&params).expect("serialize should succeed");
        assert_eq!(buf.len(), 16384);

        verify_btrfs_tree_block_checksum(&buf, ffs_types::BTRFS_CSUM_TYPE_CRC32C)
            .expect("checksum should be valid");

        let hdr = BtrfsHeader::parse_from_block(&buf).expect("parse header");
        assert_eq!(hdr.bytenr, 0x50000);
        assert_eq!(hdr.generation, 200);
        assert_eq!(hdr.owner, 1);
        assert_eq!(hdr.nritems, 3);
        assert_eq!(hdr.level, 1);

        let (_, key_ptrs) = parse_internal_items(&buf).expect("parse should succeed");
        assert_eq!(key_ptrs.len(), 3);
        assert_eq!(key_ptrs[0].blockptr, 0x20000);
        assert_eq!(key_ptrs[0].generation, 190);
        assert_eq!(key_ptrs[1].blockptr, 0x30000);
        assert_eq!(key_ptrs[1].generation, 195);
        assert_eq!(key_ptrs[2].blockptr, 0x40000);
        assert_eq!(key_ptrs[2].generation, 200);
    }

    /// WB-I2 executable oracle: after a commit, generation is atomically g or g+1.
    ///
    /// This test verifies that `BtrfsSuperblock::patch_commit` produces a valid
    /// superblock with the new generation, and that a torn/partial write would
    /// be detected via checksum failure. The key invariant is that a reader
    /// observes either the old valid superblock (gen g) or the new valid one
    /// (gen g+1), never a torn mixture.
    #[test]
    fn wb_i2_superblock_atomic_generation_transition() {
        use ffs_ondisk::{BtrfsSuperblock, verify_btrfs_superblock_checksum};

        let sb = BtrfsSuperblock {
            csum: [0; 32],
            fsid: [0x42; 16],
            bytenr: ffs_types::BTRFS_SUPER_INFO_OFFSET as u64,
            flags: 0,
            magic: ffs_types::BTRFS_MAGIC,
            generation: 100,
            root: 0x10000,
            chunk_root: 0x20000,
            chunk_root_generation: 100,
            log_root: 0,
            total_bytes: 1_000_000_000,
            bytes_used: 500_000,
            root_dir_objectid: 6,
            num_devices: 1,
            sectorsize: 4096,
            nodesize: 16384,
            stripesize: 4096,
            compat_flags: 0,
            compat_ro_flags: 0,
            incompat_flags: 0,
            csum_type: ffs_types::BTRFS_CSUM_TYPE_CRC32C,
            root_level: 0,
            chunk_root_level: 1,
            log_root_level: 0,
            label: "wb_i2_test".to_string(),
            sys_chunk_array_size: 0,
            sys_chunk_array: vec![],
        };

        let original = sb.to_bytes();
        verify_btrfs_superblock_checksum(&original).expect("original checksum valid");
        let parsed_orig = BtrfsSuperblock::parse_superblock_region(&original).expect("parse orig");
        assert_eq!(
            parsed_orig.generation, 100,
            "pre-commit generation is g=100"
        );

        let mut committed = original;
        BtrfsSuperblock::patch_commit(&mut committed, 0x30000, 1, 101);
        verify_btrfs_superblock_checksum(&committed).expect("committed checksum valid");
        let parsed_new = BtrfsSuperblock::parse_superblock_region(&committed).expect("parse new");
        assert_eq!(
            parsed_new.generation, 101,
            "post-commit generation is g+1=101"
        );
        assert_eq!(parsed_new.root, 0x30000, "root updated to new location");
        assert_eq!(parsed_new.root_level, 1, "root_level updated");

        let mut torn = committed.clone();
        torn[0x48] ^= 0xFF;
        assert!(
            verify_btrfs_superblock_checksum(&torn).is_err(),
            "torn write detected by checksum - WB-I2 upheld"
        );

        let mut gen_mismatch = committed.clone();
        gen_mismatch[0x48..0x50].copy_from_slice(&99_u64.to_le_bytes());
        assert!(
            verify_btrfs_superblock_checksum(&gen_mismatch).is_err(),
            "generation tampering detected - WB-I2 upheld"
        );
    }

    /// ROOT_ITEM commit flow: patch_root_commit updates bytenr/level/generation.
    #[test]
    fn root_item_commit_updates_tree_location() {
        let original = BtrfsRootItem {
            bytenr: 0x1000,
            level: 0,
            generation: 50,
            root_dirid: 256,
            flags: 0,
            refs: 1,
            uuid: [0; 16],
            parent_uuid: [0; 16],
        };
        let mut data = original.to_bytes();
        let parsed_before = parse_root_item(&data).expect("parse before");
        assert_eq!(parsed_before.bytenr, 0x1000);
        assert_eq!(parsed_before.generation, 50);

        BtrfsRootItem::patch_root_commit(&mut data, 0x2000, 1, 100).expect("patch");
        let parsed_after = parse_root_item(&data).expect("parse after");
        assert_eq!(parsed_after.bytenr, 0x2000, "bytenr updated for new root");
        assert_eq!(parsed_after.level, 1, "level updated");
        assert_eq!(parsed_after.generation, 100, "generation bumped");
        assert_eq!(parsed_after.root_dirid, 256, "root_dirid preserved");
    }

    /// Roundtrip: fsflags → btrfs flags → fsflags preserves user-settable flags.
    #[test]
    fn inode_flags_roundtrip_preserves_user_settable() {
        use crate::{
            BTRFS_USER_SETTABLE_FSFLAGS, btrfs_inode_flags_to_fsflags, fsflags_to_btrfs_inode_flags,
        };

        // Test individual flags
        let test_flags = [
            ffs_types::EXT4_SYNC_FL,
            ffs_types::EXT4_IMMUTABLE_FL,
            ffs_types::EXT4_APPEND_FL,
            ffs_types::EXT4_NODUMP_FL,
            ffs_types::EXT4_NOATIME_FL,
            ffs_types::EXT4_DIRSYNC_FL,
            ffs_types::FS_NOCOW_FL,
            ffs_types::EXT4_COMPR_FL,
            ffs_types::EXT4_NOCOMPR_FL,
        ];

        for &flag in &test_flags {
            let btrfs = fsflags_to_btrfs_inode_flags(flag);
            let back = btrfs_inode_flags_to_fsflags(btrfs);
            // NOCOW sets both NODATACOW and NODATASUM, but only NOCOW comes back
            assert_eq!(back & flag, flag, "roundtrip preserves flag 0x{flag:08x}");
        }

        // Test combined flags
        let combined = BTRFS_USER_SETTABLE_FSFLAGS;
        let btrfs_combined = fsflags_to_btrfs_inode_flags(combined);
        let back_combined = btrfs_inode_flags_to_fsflags(btrfs_combined);
        assert_eq!(
            back_combined & BTRFS_USER_SETTABLE_FSFLAGS,
            BTRFS_USER_SETTABLE_FSFLAGS,
            "combined roundtrip preserves all user-settable flags"
        );
    }

    #[test]
    fn btrfs_inode_flags_to_xflags_mapping() {
        use super::{
            BTRFS_INODE_APPEND, BTRFS_INODE_IMMUTABLE, BTRFS_INODE_NOATIME, BTRFS_INODE_NOCOMPRESS,
            BTRFS_INODE_NODUMP, BTRFS_INODE_SYNC, btrfs_inode_flags_to_xflags,
        };

        const FS_XFLAG_SYNC: u32 = 0x0000_0020;
        const FS_XFLAG_IMMUTABLE: u32 = 0x0000_0008;
        const FS_XFLAG_APPEND: u32 = 0x0000_0010;
        const FS_XFLAG_NODUMP: u32 = 0x0000_0080;
        const FS_XFLAG_NOATIME: u32 = 0x0000_0040;
        const FS_XFLAG_NODEFRAG: u32 = 0x0000_2000;
        const FS_XFLAG_HASATTR: u32 = 0x8000_0000;

        assert_eq!(btrfs_inode_flags_to_xflags(0), 0);
        assert_eq!(
            btrfs_inode_flags_to_xflags(BTRFS_INODE_SYNC),
            FS_XFLAG_SYNC | FS_XFLAG_HASATTR
        );
        assert_eq!(
            btrfs_inode_flags_to_xflags(BTRFS_INODE_IMMUTABLE),
            FS_XFLAG_IMMUTABLE | FS_XFLAG_HASATTR
        );
        assert_eq!(
            btrfs_inode_flags_to_xflags(BTRFS_INODE_APPEND),
            FS_XFLAG_APPEND | FS_XFLAG_HASATTR
        );
        assert_eq!(
            btrfs_inode_flags_to_xflags(BTRFS_INODE_NODUMP),
            FS_XFLAG_NODUMP | FS_XFLAG_HASATTR
        );
        assert_eq!(
            btrfs_inode_flags_to_xflags(BTRFS_INODE_NOATIME),
            FS_XFLAG_NOATIME | FS_XFLAG_HASATTR
        );
        assert_eq!(
            btrfs_inode_flags_to_xflags(BTRFS_INODE_NOCOMPRESS),
            FS_XFLAG_NODEFRAG | FS_XFLAG_HASATTR
        );

        let combined = BTRFS_INODE_SYNC | BTRFS_INODE_NODUMP | BTRFS_INODE_NOATIME;
        let expected = FS_XFLAG_SYNC | FS_XFLAG_NODUMP | FS_XFLAG_NOATIME | FS_XFLAG_HASATTR;
        assert_eq!(btrfs_inode_flags_to_xflags(combined), expected);
    }

    #[test]
    fn xflags_to_btrfs_inode_flags_roundtrip() {
        use super::{
            BTRFS_INODE_APPEND, BTRFS_INODE_IMMUTABLE, BTRFS_INODE_NOATIME, BTRFS_INODE_NOCOMPRESS,
            BTRFS_INODE_NODUMP, BTRFS_INODE_SYNC, BTRFS_USER_SETTABLE_XFLAGS,
            btrfs_inode_flags_to_xflags, xflags_to_btrfs_inode_flags,
        };

        const FS_XFLAG_HASATTR: u32 = 0x8000_0000;

        let test_flags = [
            BTRFS_INODE_SYNC,
            BTRFS_INODE_IMMUTABLE,
            BTRFS_INODE_APPEND,
            BTRFS_INODE_NODUMP,
            BTRFS_INODE_NOATIME,
            BTRFS_INODE_NOCOMPRESS,
        ];

        for &btrfs_flag in &test_flags {
            let xflags = btrfs_inode_flags_to_xflags(btrfs_flag);
            let xflags_clean = xflags & !FS_XFLAG_HASATTR;
            let back = xflags_to_btrfs_inode_flags(xflags_clean);
            assert_eq!(
                back, btrfs_flag,
                "xflags roundtrip for btrfs flag 0x{btrfs_flag:016x}"
            );
        }

        let combined_btrfs = BTRFS_INODE_SYNC | BTRFS_INODE_NODUMP | BTRFS_INODE_NOATIME;
        let xflags = btrfs_inode_flags_to_xflags(combined_btrfs);
        let xflags_clean = xflags & !FS_XFLAG_HASATTR;
        let back = xflags_to_btrfs_inode_flags(xflags_clean);
        assert_eq!(back, combined_btrfs, "combined xflags roundtrip");

        let all_xflags = BTRFS_USER_SETTABLE_XFLAGS;
        let all_btrfs = xflags_to_btrfs_inode_flags(all_xflags);
        let back_xflags = btrfs_inode_flags_to_xflags(all_btrfs) & !FS_XFLAG_HASATTR;
        assert_eq!(back_xflags, all_xflags, "all settable xflags roundtrip");
    }

    #[test]
    fn send_stream_builder_roundtrip() {
        use super::{
            SendAttr, SendCommand, SendStreamBuilder, build_chmod_command, build_chown_command,
            build_mkdir_command, build_mkfile_command, build_subvol_command, build_write_command,
            parse_send_stream,
        };

        let mut builder = SendStreamBuilder::new();
        builder.write_header();

        let uuid = [0x11_u8; 16];
        let (cmd, attrs) = build_subvol_command(b"test_subvol", &uuid, 1);
        let attr_refs: Vec<(SendAttr, &[u8])> =
            attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
        builder.add_command(cmd, &attr_refs);

        let (cmd, attrs) = build_mkdir_command(b"test_subvol/dir1", 257);
        let attr_refs: Vec<(SendAttr, &[u8])> =
            attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
        builder.add_command(cmd, &attr_refs);

        let (cmd, attrs) = build_mkfile_command(b"test_subvol/file1.txt", 258);
        let attr_refs: Vec<(SendAttr, &[u8])> =
            attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
        builder.add_command(cmd, &attr_refs);

        let (cmd, attrs) = build_write_command(b"test_subvol/file1.txt", 0, b"hello world");
        let attr_refs: Vec<(SendAttr, &[u8])> =
            attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
        builder.add_command(cmd, &attr_refs);

        let (cmd, attrs) = build_chmod_command(b"test_subvol/file1.txt", 0o644);
        let attr_refs: Vec<(SendAttr, &[u8])> =
            attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
        builder.add_command(cmd, &attr_refs);

        let (cmd, attrs) = build_chown_command(b"test_subvol/file1.txt", 1000, 1000);
        let attr_refs: Vec<(SendAttr, &[u8])> =
            attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
        builder.add_command(cmd, &attr_refs);

        builder.finalize();
        let stream = builder.finish();

        let parsed = parse_send_stream(&stream).expect("parse roundtrip");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.commands.len(), 7); // subvol, mkdir, mkfile, write, chmod, chown, end
        assert_eq!(parsed.commands[0].cmd, SendCommand::Subvol);
        assert_eq!(parsed.commands[1].cmd, SendCommand::Mkdir);
        assert_eq!(parsed.commands[2].cmd, SendCommand::Mkfile);
        assert_eq!(parsed.commands[3].cmd, SendCommand::Write);
        assert_eq!(parsed.commands[4].cmd, SendCommand::Chmod);
        assert_eq!(parsed.commands[5].cmd, SendCommand::Chown);
        assert_eq!(parsed.commands[6].cmd, SendCommand::End);
    }

    #[test]
    #[expect(clippy::too_many_lines)]
    fn generate_send_stream_from_fs_tree_items() {
        // Create a minimal FS tree with:
        // - Root directory (inode 256)
        // - A regular file "hello.txt" (inode 257) with inline content
        // - A subdirectory "subdir" (inode 258)

        // Helper to create an inode item payload (160 bytes)
        fn make_inode_item(mode: u32, size: u64, uid: u32, gid: u32) -> Vec<u8> {
            let mut buf = vec![0u8; 160];
            buf[0..8].copy_from_slice(&1_u64.to_le_bytes()); // generation
            buf[16..24].copy_from_slice(&size.to_le_bytes()); // size
            buf[24..32].copy_from_slice(&size.to_le_bytes()); // nbytes
            buf[40..44].copy_from_slice(&1_u32.to_le_bytes()); // nlink
            buf[44..48].copy_from_slice(&uid.to_le_bytes());
            buf[48..52].copy_from_slice(&gid.to_le_bytes());
            buf[52..56].copy_from_slice(&mode.to_le_bytes());
            buf
        }

        // Helper to create an inode ref payload
        #[expect(clippy::cast_possible_truncation)]
        fn make_inode_ref(index: u64, name: &[u8]) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&index.to_le_bytes());
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            buf.extend_from_slice(name);
            buf
        }

        // Helper to create an inline extent (type 0)
        #[expect(clippy::cast_possible_truncation)]
        fn make_inline_extent(data: &[u8]) -> Vec<u8> {
            let mut buf = vec![0u8; 21];
            // First 21 bytes: generation(8) + ram_bytes(8) + compression(1) +
            // encryption(1) + other_encoding(2) + type(1)
            buf[16..20].copy_from_slice(&(data.len() as u32).to_le_bytes()); // ram_bytes (lower 32 bits)
            buf[20] = 0; // inline type
            buf.extend_from_slice(data);
            buf
        }

        let items = vec![
            // Root directory inode (256)
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: BTRFS_ITEM_INODE_ITEM,
                    offset: 0,
                },
                data: make_inode_item(0o40755, 0, 0, 0), // S_IFDIR | 0755
            },
            // Root directory self-ref (parent is itself for root)
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: BTRFS_ITEM_INODE_REF,
                    offset: 256,
                },
                data: make_inode_ref(0, b".."),
            },
            // Regular file inode (257)
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 257,
                    item_type: BTRFS_ITEM_INODE_ITEM,
                    offset: 0,
                },
                data: make_inode_item(0o10_0644, 13, 1000, 1000), // S_IFREG | 0644
            },
            // File inode ref (parent = 256, name = "hello.txt")
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 257,
                    item_type: BTRFS_ITEM_INODE_REF,
                    offset: 256,
                },
                data: make_inode_ref(1, b"hello.txt"),
            },
            // File inline extent with content
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 257,
                    item_type: BTRFS_ITEM_EXTENT_DATA,
                    offset: 0,
                },
                data: make_inline_extent(b"Hello, World!"),
            },
            // Subdirectory inode (258)
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 258,
                    item_type: BTRFS_ITEM_INODE_ITEM,
                    offset: 0,
                },
                data: make_inode_item(0o40755, 0, 0, 0), // S_IFDIR | 0755
            },
            // Subdirectory inode ref (parent = 256, name = "subdir")
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 258,
                    item_type: BTRFS_ITEM_INODE_REF,
                    offset: 256,
                },
                data: make_inode_ref(2, b"subdir"),
            },
        ];

        let uuid = [0u8; 16];
        let stream = generate_send_stream(
            &items,
            b"test_subvol",
            &uuid,
            1,
            |_bytenr: u64, _len: u64, _ram_bytes: u64, _compression: u8| {
                Err(ffs_types::ParseError::InvalidField {
                    field: "test",
                    reason: "no disk extents in test",
                })
            },
        )
        .expect("generate send stream");

        // Parse the generated stream
        let parsed = parse_send_stream(&stream).expect("parse generated stream");
        assert_eq!(parsed.version, 1);

        // Find command types
        let cmd_types: Vec<_> = parsed.commands.iter().map(|c| c.cmd).collect();

        // Must start with Subvol
        assert_eq!(cmd_types[0], SendCommand::Subvol);

        // Must end with End
        assert_eq!(*cmd_types.last().unwrap(), SendCommand::End);

        // Should contain mkdir (for subdir), mkfile (for hello.txt)
        assert!(
            cmd_types.contains(&SendCommand::Mkdir),
            "should have mkdir command"
        );
        assert!(
            cmd_types.contains(&SendCommand::Mkfile),
            "should have mkfile command"
        );
        assert!(
            cmd_types.contains(&SendCommand::Write),
            "should have write command for inline extent"
        );
        assert!(
            cmd_types.contains(&SendCommand::Chmod),
            "should have chmod command"
        );
        assert!(
            cmd_types.contains(&SendCommand::Chown),
            "should have chown command"
        );
        assert!(
            cmd_types.contains(&SendCommand::Utimes),
            "should have utimes command"
        );

        // Command PATHs must be RELATIVE to the received subvol root — no
        // subvol-name prefix, no '..' escape (bd-dnyr0). Previously every path
        // was prefixed with "test_subvol", making the stream unreceivable.
        const ATTR_PATH: u16 = SendAttr::Path as u16;
        let path_of = |cmd: SendCommand| -> Option<Vec<u8>> {
            parsed.commands.iter().find(|c| c.cmd == cmd).and_then(|c| {
                c.attrs
                    .iter()
                    .find(|(t, _)| *t == ATTR_PATH)
                    .map(|(_, v)| v.clone())
            })
        };
        // The SUBVOL command does carry the subvolume name.
        assert_eq!(path_of(SendCommand::Subvol).as_deref(), Some(&b"test_subvol"[..]));
        // Child commands are subvol-relative.
        assert_eq!(
            path_of(SendCommand::Mkfile).as_deref(),
            Some(&b"hello.txt"[..]),
            "MKFILE path must be subvol-relative (no subvol-name prefix)"
        );
        assert_eq!(
            path_of(SendCommand::Mkdir).as_deref(),
            Some(&b"subdir"[..]),
            "MKDIR path must be subvol-relative"
        );
        // No command path may carry the subvol prefix or escape the root.
        for c in &parsed.commands {
            for (t, v) in &c.attrs {
                if *t == ATTR_PATH {
                    assert!(
                        !v.starts_with(b"test_subvol/"),
                        "command path must not be subvol-name-prefixed: {:?}",
                        String::from_utf8_lossy(v)
                    );
                    assert!(
                        !v.windows(2).any(|w| w == b".."),
                        "command path must not contain '..': {:?}",
                        String::from_utf8_lossy(v)
                    );
                }
            }
        }
        // The subvol root's metadata commands apply via an empty path.
        assert!(
            parsed.commands.iter().any(|c| c.cmd == SendCommand::Chmod
                && c.attrs
                    .iter()
                    .any(|(t, v)| *t == ATTR_PATH && v.is_empty())),
            "the subvolume root's chmod must use an empty (root-relative) path"
        );
    }

    /// Regression: a file extent larger than the u16 TLV limit must be split
    /// into multiple `Write` commands, each carrying a `DATA` attribute within
    /// the 65535-byte ceiling, and the reassembled payload must equal the
    /// original extent bytes. Before chunking, the whole extent went into a
    /// single attribute whose length silently wrapped mod 65536, producing a
    /// corrupt, unparseable stream for any file with a >64 KiB extent.
    #[test]
    #[expect(clippy::too_many_lines)]
    fn generate_send_stream_chunks_large_writes() {
        const ATTR_DATA: u16 = SendAttr::Data as u16;
        const ATTR_FILE_OFFSET: u16 = SendAttr::FileOffset as u16;

        fn make_inode_item(mode: u32, size: u64, uid: u32, gid: u32) -> Vec<u8> {
            let mut buf = vec![0u8; 160];
            buf[0..8].copy_from_slice(&1_u64.to_le_bytes());
            buf[16..24].copy_from_slice(&size.to_le_bytes());
            buf[24..32].copy_from_slice(&size.to_le_bytes());
            buf[40..44].copy_from_slice(&1_u32.to_le_bytes());
            buf[44..48].copy_from_slice(&uid.to_le_bytes());
            buf[48..52].copy_from_slice(&gid.to_le_bytes());
            buf[52..56].copy_from_slice(&mode.to_le_bytes());
            buf
        }

        #[expect(clippy::cast_possible_truncation)]
        fn make_inode_ref(index: u64, name: &[u8]) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&index.to_le_bytes());
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            buf.extend_from_slice(name);
            buf
        }

        // Regular (non-inline) EXTENT_DATA item (type 1) header layout consumed
        // by `generate_send_stream`: byte 20 = type, 21..29 disk_bytenr,
        // 29..37 disk_num_bytes, 37..45 extent_offset, 45..53 num_bytes.
        fn make_regular_extent(disk_bytenr: u64, num_bytes: u64) -> Vec<u8> {
            let mut buf = vec![0u8; 53];
            buf[20] = 1;
            buf[21..29].copy_from_slice(&disk_bytenr.to_le_bytes());
            buf[29..37].copy_from_slice(&num_bytes.to_le_bytes());
            buf[37..45].copy_from_slice(&0u64.to_le_bytes());
            buf[45..53].copy_from_slice(&num_bytes.to_le_bytes());
            buf
        }

        // 100_000 bytes spans three 48 KiB chunks (48K + 48K + ~4K) and exceeds
        // the u16 ceiling, so a single-attribute encoding would corrupt.
        const EXTENT_LEN: u64 = 100_000;
        const DISK_BYTENR: u64 = 0x1_0000;
        let original: Vec<u8> = (0..EXTENT_LEN).map(|i| (i % 251) as u8).collect();

        let items = vec![
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: BTRFS_ITEM_INODE_ITEM,
                    offset: 0,
                },
                data: make_inode_item(0o40755, 0, 0, 0),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 257,
                    item_type: BTRFS_ITEM_INODE_ITEM,
                    offset: 0,
                },
                data: make_inode_item(0o100_644, EXTENT_LEN, 0, 0),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 257,
                    item_type: BTRFS_ITEM_INODE_REF,
                    offset: 256,
                },
                data: make_inode_ref(2, b"big.bin"),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 257,
                    item_type: BTRFS_ITEM_EXTENT_DATA,
                    offset: 0,
                },
                data: make_regular_extent(DISK_BYTENR, EXTENT_LEN),
            },
        ];

        let uuid = [0u8; 16];
        let original_for_read = original.clone();
        let stream = generate_send_stream(
            &items,
            b"test_subvol",
            &uuid,
            1,
            |bytenr, len, _ram_bytes, _compression| {
                assert_eq!(bytenr, DISK_BYTENR, "unexpected extent read");
                let len = usize::try_from(len).expect("len fits usize");
                Ok(original_for_read[..len].to_vec())
            },
        )
        .expect("generate send stream");

        // The stream must round-trip through the parser (it would not if any
        // attribute length had wrapped).
        let parsed = parse_send_stream(&stream).expect("parse chunked stream");

        let writes: Vec<&SendStreamCommand> = parsed
            .commands
            .iter()
            .filter(|c| c.cmd == SendCommand::Write)
            .collect();
        assert!(
            writes.len() >= 2,
            "large extent must split into multiple writes, got {}",
            writes.len()
        );

        // Reassemble the file from the Write commands, keyed by file offset, and
        // confirm every DATA attribute respects the u16 TLV ceiling.
        let mut reassembled = vec![0u8; original.len()];
        for w in &writes {
            let mut offset: Option<u64> = None;
            let mut data: Option<&[u8]> = None;
            for (atype, adata) in &w.attrs {
                if *atype == ATTR_FILE_OFFSET {
                    offset = Some(u64::from_le_bytes(
                        adata.as_slice().try_into().expect("8-byte file offset"),
                    ));
                } else if *atype == ATTR_DATA {
                    assert!(
                        u16::try_from(adata.len()).is_ok(),
                        "DATA attribute exceeds u16 TLV limit: {}",
                        adata.len()
                    );
                    data = Some(adata);
                }
            }
            let offset =
                usize::try_from(offset.expect("write has file offset")).expect("offset fits usize");
            let data = data.expect("write has data");
            reassembled[offset..offset + data.len()].copy_from_slice(data);
        }

        assert_eq!(
            reassembled, original,
            "reassembled file must match original"
        );
    }

    /// A COMPRESSED extent must emit DECOMPRESSED data in the send stream
    /// (uncompressed/logical space). Before the fix, generate_send_stream read
    /// disk_num_bytes (compressed size) and sliced [extent_offset..+num_bytes]
    /// with uncompressed offsets — out of bounds / truncated garbage. Now it
    /// passes ram_bytes + compression to the read closure (which returns the
    /// decompressed bytes) and slices in uncompressed space.
    #[test]
    fn generate_send_stream_compressed_extent_emits_decompressed_data() {
        const ATTR_FILE_OFFSET: u16 = SendAttr::FileOffset as u16;
        const ATTR_DATA: u16 = SendAttr::Data as u16;

        fn make_inode_item(mode: u32, size: u64) -> Vec<u8> {
            let mut buf = vec![0u8; 160];
            buf[0..8].copy_from_slice(&1_u64.to_le_bytes());
            buf[16..24].copy_from_slice(&size.to_le_bytes());
            buf[24..32].copy_from_slice(&size.to_le_bytes());
            buf[40..44].copy_from_slice(&1_u32.to_le_bytes());
            buf[52..56].copy_from_slice(&mode.to_le_bytes());
            buf
        }
        #[expect(clippy::cast_possible_truncation)]
        fn make_inode_ref(index: u64, name: &[u8]) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&index.to_le_bytes());
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            buf.extend_from_slice(name);
            buf
        }
        // Compressed regular EXTENT_DATA: ram_bytes@8, compression@16, type@20=1,
        // disk_bytenr@21, disk_num_bytes@29 (compressed, small), extent_offset@37,
        // num_bytes@45 (uncompressed).
        fn make_compressed_extent(
            disk_bytenr: u64,
            disk_num_bytes: u64,
            ram_bytes: u64,
        ) -> Vec<u8> {
            let mut buf = vec![0u8; 53];
            buf[8..16].copy_from_slice(&ram_bytes.to_le_bytes());
            buf[16] = BTRFS_COMPRESS_ZLIB;
            buf[20] = 1;
            buf[21..29].copy_from_slice(&disk_bytenr.to_le_bytes());
            buf[29..37].copy_from_slice(&disk_num_bytes.to_le_bytes());
            buf[37..45].copy_from_slice(&0u64.to_le_bytes());
            buf[45..53].copy_from_slice(&ram_bytes.to_le_bytes());
            buf
        }

        const RAM_BYTES: u64 = 12_000; // uncompressed size (> the compressed size)
        const DISK_NUM_BYTES: u64 = 4_000; // compressed on-disk size
        const DISK_BYTENR: u64 = 0x2_0000;
        // The decompressed file content the read closure (= ffs-core, which
        // decompresses) is expected to return.
        let decompressed: Vec<u8> = (0..RAM_BYTES).map(|i| (i % 251) as u8).collect();

        let items = vec![
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: BTRFS_ITEM_INODE_ITEM,
                    offset: 0,
                },
                data: make_inode_item(0o40755, 0),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 257,
                    item_type: BTRFS_ITEM_INODE_ITEM,
                    offset: 0,
                },
                data: make_inode_item(0o100_644, RAM_BYTES),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 257,
                    item_type: BTRFS_ITEM_INODE_REF,
                    offset: 256,
                },
                data: make_inode_ref(2, b"z.bin"),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 257,
                    item_type: BTRFS_ITEM_EXTENT_DATA,
                    offset: 0,
                },
                data: make_compressed_extent(DISK_BYTENR, DISK_NUM_BYTES, RAM_BYTES),
            },
        ];

        let uuid = [0u8; 16];
        let decompressed_for_read = decompressed.clone();
        let stream = generate_send_stream(
            &items,
            b"test_subvol",
            &uuid,
            1,
            |bytenr, disk_num_bytes, ram_bytes, compression| {
                // generate_send_stream must hand us the compression + ram_bytes so
                // we (ffs-core) can decompress; verify and return decompressed.
                assert_eq!(bytenr, DISK_BYTENR);
                assert_eq!(disk_num_bytes, DISK_NUM_BYTES, "compressed on-disk size");
                assert_eq!(ram_bytes, RAM_BYTES, "uncompressed size");
                assert_eq!(compression, BTRFS_COMPRESS_ZLIB);
                Ok(decompressed_for_read.clone())
            },
        )
        .expect("generate send stream");

        let parsed = parse_send_stream(&stream).expect("parse stream");
        let mut reassembled = vec![0u8; decompressed.len()];
        for w in parsed.commands.iter().filter(|c| c.cmd == SendCommand::Write) {
            let mut offset = None;
            let mut data: Option<&[u8]> = None;
            for (atype, adata) in &w.attrs {
                if *atype == ATTR_FILE_OFFSET {
                    offset =
                        Some(u64::from_le_bytes(adata.as_slice().try_into().unwrap()) as usize);
                } else if *atype == ATTR_DATA {
                    data = Some(adata);
                }
            }
            let (offset, data) = (offset.expect("offset"), data.expect("data"));
            reassembled[offset..offset + data.len()].copy_from_slice(data);
        }
        assert_eq!(
            reassembled, decompressed,
            "send stream of a compressed extent must carry the full DECOMPRESSED data"
        );
    }

    /// bd-7ucz7: a child must never be emitted before its parent directory, even
    /// when the child's objectid is LOWER than the parent dir's (e.g. a file
    /// renamed under a later-created dir). The receiver creates by path, so the
    /// parent mkdir must precede the child mkfile.
    #[test]
    fn generate_send_stream_emits_parent_dir_before_lower_objectid_child() {
        const ATTR_PATH: u16 = SendAttr::Path as u16;

        fn make_inode_item(mode: u32) -> Vec<u8> {
            let mut buf = vec![0u8; 160];
            buf[0..8].copy_from_slice(&1_u64.to_le_bytes());
            buf[40..44].copy_from_slice(&1_u32.to_le_bytes());
            buf[52..56].copy_from_slice(&mode.to_le_bytes());
            buf
        }
        #[expect(clippy::cast_possible_truncation)]
        fn make_inode_ref(index: u64, name: &[u8]) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&index.to_le_bytes());
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            buf.extend_from_slice(name);
            buf
        }

        // File f (objectid 257) lives under dir d (objectid 300, > 257) — as if f
        // was renamed under a later-created directory. Objectid order would emit
        // f before d.
        let items = vec![
            BtrfsLeafEntry {
                key: BtrfsKey { objectid: 256, item_type: BTRFS_ITEM_INODE_ITEM, offset: 0 },
                data: make_inode_item(0o40755),
            },
            BtrfsLeafEntry {
                key: BtrfsKey { objectid: 257, item_type: BTRFS_ITEM_INODE_ITEM, offset: 0 },
                data: make_inode_item(0o100_644),
            },
            BtrfsLeafEntry {
                key: BtrfsKey { objectid: 257, item_type: BTRFS_ITEM_INODE_REF, offset: 300 },
                data: make_inode_ref(2, b"f"),
            },
            BtrfsLeafEntry {
                key: BtrfsKey { objectid: 300, item_type: BTRFS_ITEM_INODE_ITEM, offset: 0 },
                data: make_inode_item(0o40755),
            },
            BtrfsLeafEntry {
                key: BtrfsKey { objectid: 300, item_type: BTRFS_ITEM_INODE_REF, offset: 256 },
                data: make_inode_ref(2, b"d"),
            },
        ];

        let uuid = [0u8; 16];
        let stream = generate_send_stream(&items, b"sv", &uuid, 1, |_b, _l, _r, _c| {
            Ok(Vec::new())
        })
        .expect("generate send stream");
        let parsed = parse_send_stream(&stream).expect("parse stream");

        let path_of = |c: &SendStreamCommand| -> Option<Vec<u8>> {
            c.attrs
                .iter()
                .find(|(t, _)| *t == ATTR_PATH)
                .map(|(_, d)| d.clone())
        };
        let mkdir_pos = parsed.commands.iter().position(|c| {
            c.cmd == SendCommand::Mkdir && path_of(c).as_deref() == Some(b"d".as_ref())
        });
        let mkfile_pos = parsed.commands.iter().position(|c| {
            c.cmd == SendCommand::Mkfile && path_of(c).as_deref() == Some(b"d/f".as_ref())
        });

        let mkdir_pos = mkdir_pos.expect("mkdir sv/d emitted");
        let mkfile_pos = mkfile_pos.expect("mkfile sv/d/f emitted");
        assert!(
            mkdir_pos < mkfile_pos,
            "parent dir mkdir (pos {mkdir_pos}) must precede child mkfile (pos {mkfile_pos})"
        );
    }

    /// bd-zvv7r: a hard-linked file (reachable by >1 name) must be created once
    /// at its primary path and LINKED at every additional path — not dropped.
    #[test]
    fn generate_send_stream_emits_link_for_additional_hardlinks() {
        const ATTR_PATH: u16 = SendAttr::Path as u16;
        const ATTR_PATH_LINK: u16 = SendAttr::PathLink as u16;

        fn make_inode_item(mode: u32) -> Vec<u8> {
            let mut buf = vec![0u8; 160];
            buf[0..8].copy_from_slice(&1_u64.to_le_bytes());
            buf[40..44].copy_from_slice(&2_u32.to_le_bytes()); // nlink 2
            buf[52..56].copy_from_slice(&mode.to_le_bytes());
            buf
        }
        #[expect(clippy::cast_possible_truncation)]
        fn make_inode_ref(index: u64, name: &[u8]) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&index.to_le_bytes());
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            buf.extend_from_slice(name);
            buf
        }

        // Dirs a(257) and b(258) under root; file f(259) hard-linked as a/f1 and
        // b/f2 (two INODE_REF items, distinct parents).
        let items = vec![
            BtrfsLeafEntry {
                key: BtrfsKey { objectid: 256, item_type: BTRFS_ITEM_INODE_ITEM, offset: 0 },
                data: make_inode_item(0o40755),
            },
            BtrfsLeafEntry {
                key: BtrfsKey { objectid: 257, item_type: BTRFS_ITEM_INODE_ITEM, offset: 0 },
                data: make_inode_item(0o40755),
            },
            BtrfsLeafEntry {
                key: BtrfsKey { objectid: 257, item_type: BTRFS_ITEM_INODE_REF, offset: 256 },
                data: make_inode_ref(2, b"a"),
            },
            BtrfsLeafEntry {
                key: BtrfsKey { objectid: 258, item_type: BTRFS_ITEM_INODE_ITEM, offset: 0 },
                data: make_inode_item(0o40755),
            },
            BtrfsLeafEntry {
                key: BtrfsKey { objectid: 258, item_type: BTRFS_ITEM_INODE_REF, offset: 256 },
                data: make_inode_ref(2, b"b"),
            },
            BtrfsLeafEntry {
                key: BtrfsKey { objectid: 259, item_type: BTRFS_ITEM_INODE_ITEM, offset: 0 },
                data: make_inode_item(0o100_644),
            },
            BtrfsLeafEntry {
                key: BtrfsKey { objectid: 259, item_type: BTRFS_ITEM_INODE_REF, offset: 257 },
                data: make_inode_ref(2, b"f1"),
            },
            BtrfsLeafEntry {
                key: BtrfsKey { objectid: 259, item_type: BTRFS_ITEM_INODE_REF, offset: 258 },
                data: make_inode_ref(3, b"f2"),
            },
        ];

        let uuid = [0u8; 16];
        let stream = generate_send_stream(&items, b"sv", &uuid, 1, |_b, _l, _r, _c| Ok(Vec::new()))
            .expect("generate send stream");
        let parsed = parse_send_stream(&stream).expect("parse stream");

        let attr = |c: &SendStreamCommand, t: u16| -> Option<Vec<u8>> {
            c.attrs.iter().find(|(ty, _)| *ty == t).map(|(_, d)| d.clone())
        };
        // mkfile at the primary path a/f1.
        assert!(
            parsed.commands.iter().any(|c| c.cmd == SendCommand::Mkfile
                && attr(c, ATTR_PATH).as_deref() == Some(b"a/f1".as_ref())),
            "file created once at its primary path"
        );
        // link b/f2 -> a/f1 for the second hard link.
        let link = parsed.commands.iter().find(|c| {
            c.cmd == SendCommand::Link && attr(c, ATTR_PATH).as_deref() == Some(b"b/f2".as_ref())
        });
        let link = link.expect("second hard link must emit a Link command");
        assert_eq!(
            attr(link, ATTR_PATH_LINK).as_deref(),
            Some(b"a/f1".as_ref()),
            "Link must target the primary path"
        );
    }

    #[test]
    #[expect(clippy::too_many_lines)]
    fn generate_send_stream_prealloc_extent_emits_update_extent() {
        const ATTR_PATH: u16 = SendAttr::Path as u16;
        const ATTR_FILE_OFFSET: u16 = SendAttr::FileOffset as u16;
        const ATTR_SIZE: u16 = SendAttr::Size as u16;
        const FILE_OFFSET: u64 = 8192;
        const PREALLOC_LEN: u64 = 16_384;

        fn make_inode_item(mode: u32, size: u64, uid: u32, gid: u32) -> Vec<u8> {
            let mut buf = vec![0u8; 160];
            buf[0..8].copy_from_slice(&1_u64.to_le_bytes());
            buf[16..24].copy_from_slice(&size.to_le_bytes());
            buf[24..32].copy_from_slice(&size.to_le_bytes());
            buf[40..44].copy_from_slice(&1_u32.to_le_bytes());
            buf[44..48].copy_from_slice(&uid.to_le_bytes());
            buf[48..52].copy_from_slice(&gid.to_le_bytes());
            buf[52..56].copy_from_slice(&mode.to_le_bytes());
            buf
        }

        #[expect(clippy::cast_possible_truncation)]
        fn make_inode_ref(index: u64, name: &[u8]) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&index.to_le_bytes());
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            buf.extend_from_slice(name);
            buf
        }

        fn make_prealloc_extent(disk_bytenr: u64, disk_num_bytes: u64, num_bytes: u64) -> Vec<u8> {
            let mut buf = vec![0u8; 53];
            buf[20] = BTRFS_FILE_EXTENT_PREALLOC;
            buf[21..29].copy_from_slice(&disk_bytenr.to_le_bytes());
            buf[29..37].copy_from_slice(&disk_num_bytes.to_le_bytes());
            buf[37..45].copy_from_slice(&0_u64.to_le_bytes());
            buf[45..53].copy_from_slice(&num_bytes.to_le_bytes());
            buf
        }

        fn attr_u64(command: &SendStreamCommand, attr: u16) -> u64 {
            let raw = command
                .attrs
                .iter()
                .find_map(|(candidate, value)| (*candidate == attr).then_some(value.as_slice()))
                .expect("attribute should exist");
            u64::from_le_bytes(raw.try_into().expect("attribute should be u64"))
        }

        let items = vec![
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 257,
                    item_type: BTRFS_ITEM_INODE_ITEM,
                    offset: 0,
                },
                data: make_inode_item(0o100_644, FILE_OFFSET + PREALLOC_LEN, 0, 0),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 257,
                    item_type: BTRFS_ITEM_INODE_REF,
                    offset: BTRFS_FIRST_FREE_OBJECTID,
                },
                data: make_inode_ref(1, b"prealloc.bin"),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 257,
                    item_type: BTRFS_ITEM_EXTENT_DATA,
                    offset: FILE_OFFSET,
                },
                data: make_prealloc_extent(0x40_0000, PREALLOC_LEN, PREALLOC_LEN),
            },
        ];

        let uuid = [0_u8; 16];
        let mut read_extent_called = false;
        let stream = generate_send_stream(
            &items,
            b"test_subvol",
            &uuid,
            1,
            |_bytenr: u64, _len: u64, _ram_bytes: u64, _compression: u8| {
                read_extent_called = true;
                Err(ffs_types::ParseError::InvalidField {
                    field: "test",
                    reason: "prealloc extents must not read disk bytes",
                })
            },
        )
        .expect("generate send stream");

        assert!(
            !read_extent_called,
            "preallocated extents are unwritten and must not call read_extent"
        );

        let parsed = parse_send_stream(&stream).expect("parse generated stream");
        let cmd_types: Vec<_> = parsed.commands.iter().map(|c| c.cmd).collect();
        assert!(
            cmd_types.contains(&SendCommand::Mkfile),
            "regular file should still be created"
        );
        assert!(
            !cmd_types.contains(&SendCommand::Write),
            "preallocated unwritten extent must not emit file data"
        );

        let update_extents: Vec<_> = parsed
            .commands
            .iter()
            .filter(|command| command.cmd == SendCommand::UpdateExtent)
            .collect();
        assert_eq!(
            update_extents.len(),
            1,
            "exactly one UpdateExtent command should preserve the prealloc range"
        );

        let update = update_extents[0];
        let path = update
            .attrs
            .iter()
            .find_map(|(candidate, value)| (*candidate == ATTR_PATH).then_some(value.as_slice()))
            .expect("UpdateExtent should carry path");
        assert_eq!(path, b"prealloc.bin");
        assert_eq!(attr_u64(update, ATTR_FILE_OFFSET), FILE_OFFSET);
        assert_eq!(attr_u64(update, ATTR_SIZE), PREALLOC_LEN);
    }
}
