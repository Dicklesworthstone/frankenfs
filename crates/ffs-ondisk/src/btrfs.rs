#![forbid(unsafe_code)]

use ffs_types as crc32c;
use ffs_types::{
    BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, ParseError, read_fixed,
    read_le_u16, read_le_u32, read_le_u64, trim_nul_padded,
};
use serde::{Deserialize, Serialize};
use smallvec::{SmallVec, smallvec};
use std::cmp::Ordering;

const BTRFS_HEADER_SIZE: usize = 101;
const BTRFS_ITEM_SIZE: usize = 25;
/// Size of a btrfs_key_ptr on disk (key:17 + blockptr:u64 + generation:u64).
const BTRFS_KEY_PTR_SIZE: usize = 33;
/// Maximum tree depth in btrfs (kernel enforces 8 levels, 0-7).
const BTRFS_MAX_LEVEL: u8 = 7;
const BTRFS_MAX_SUPERBLOCK_SIZE_FIELD: u32 = 256 * 1024;
const BTRFS_SUPER_LABEL_OFFSET: usize = 0x12B;
const BTRFS_SUPER_LABEL_LEN: usize = 256;
const BTRFS_SYS_CHUNK_ARRAY_MAX_U32: u32 = 2048;
const BTRFS_SYS_CHUNK_ARRAY_OFFSET: usize = 0x32B;
const BTRFS_SYS_CHUNK_ARRAY_MAX: usize = BTRFS_SYS_CHUNK_ARRAY_MAX_U32 as usize;
/// Size of a btrfs_disk_key on disk (objectid:u64 + type:u8 + offset:u64).
const BTRFS_DISK_KEY_SIZE: usize = 17;
/// Minimum chunk size: header fields before the stripe array (48 bytes).
const BTRFS_CHUNK_FIXED_SIZE: usize = 48;
/// Size of one btrfs_stripe on disk (devid:u64 + offset:u64 + dev_uuid:16).
const BTRFS_STRIPE_SIZE: usize = 32;
/// Smallest encoded sys-chunk entry: one key, one chunk header, one stripe.
const BTRFS_SYS_CHUNK_MIN_ENTRY_SIZE: usize =
    BTRFS_DISK_KEY_SIZE + BTRFS_CHUNK_FIXED_SIZE + BTRFS_STRIPE_SIZE;
/// Objectid for chunk tree items stored in sys_chunk_array.
const BTRFS_FIRST_CHUNK_TREE_OBJECTID: u64 = 256;
/// Item type for chunk tree entries in sys_chunk_array.
const BTRFS_CHUNK_ITEM_KEY: u8 = 228;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsSuperblock {
    pub csum: [u8; 32],
    pub fsid: [u8; 16],
    pub bytenr: u64,
    pub flags: u64,
    pub magic: u64,
    pub generation: u64,
    pub root: u64,
    pub chunk_root: u64,
    pub chunk_root_generation: u64,
    pub log_root: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub root_dir_objectid: u64,
    pub num_devices: u64,
    pub sectorsize: u32,
    pub nodesize: u32,
    pub stripesize: u32,
    pub compat_flags: u64,
    pub compat_ro_flags: u64,
    pub incompat_flags: u64,
    pub csum_type: u16,
    pub root_level: u8,
    pub chunk_root_level: u8,
    pub log_root_level: u8,
    pub label: String,
    pub sys_chunk_array_size: u32,
    pub sys_chunk_array: Vec<u8>,
}

impl BtrfsSuperblock {
    #[allow(clippy::too_many_lines)]
    pub fn parse_superblock_region(region: &[u8]) -> Result<Self, ParseError> {
        if region.len() < BTRFS_SUPER_INFO_SIZE {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_SUPER_INFO_SIZE,
                offset: 0,
                actual: region.len(),
            });
        }

        let magic = read_le_u64(region, 0x40)?;
        if magic != BTRFS_MAGIC {
            return Err(ParseError::InvalidMagic {
                expected: BTRFS_MAGIC,
                actual: magic,
            });
        }

        let sectorsize = read_le_u32(region, 0x90)?;
        let nodesize = read_le_u32(region, 0x94)?;
        let stripesize = read_le_u32(region, 0x9C)?;
        let total_bytes = read_le_u64(region, 0x70)?;
        let bytes_used = read_le_u64(region, 0x78)?;
        let num_devices = read_le_u64(region, 0x88)?;

        // Validate sectorsize: must be non-zero and power-of-two, 4K typical
        if sectorsize == 0 || !sectorsize.is_power_of_two() {
            return Err(ParseError::InvalidField {
                field: "sectorsize",
                reason: "must be non-zero power of two",
            });
        }
        // Validate nodesize: must be non-zero and power-of-two, typically 4K-64K
        if nodesize == 0 || !nodesize.is_power_of_two() {
            return Err(ParseError::InvalidField {
                field: "nodesize",
                reason: "must be non-zero power of two",
            });
        }
        // Validate stripesize: must be non-zero and power-of-two when set
        if stripesize != 0 && !stripesize.is_power_of_two() {
            return Err(ParseError::InvalidField {
                field: "stripesize",
                reason: "must be zero or power of two",
            });
        }
        // Sane upper bounds (256K for sector/stripe, 256K for node)
        if sectorsize > BTRFS_MAX_SUPERBLOCK_SIZE_FIELD {
            return Err(ParseError::InvalidField {
                field: "sectorsize",
                reason: "exceeds 256K upper bound",
            });
        }
        if nodesize > BTRFS_MAX_SUPERBLOCK_SIZE_FIELD {
            return Err(ParseError::InvalidField {
                field: "nodesize",
                reason: "exceeds 256K upper bound",
            });
        }
        if stripesize > BTRFS_MAX_SUPERBLOCK_SIZE_FIELD {
            return Err(ParseError::InvalidField {
                field: "stripesize",
                reason: "exceeds 256K upper bound",
            });
        }
        if total_bytes == 0 {
            return Err(ParseError::InvalidField {
                field: "total_bytes",
                reason: "must be non-zero",
            });
        }
        if bytes_used > total_bytes {
            return Err(ParseError::InvalidField {
                field: "bytes_used",
                reason: "exceeds total_bytes",
            });
        }
        if num_devices == 0 {
            return Err(ParseError::InvalidField {
                field: "num_devices",
                reason: "must be non-zero",
            });
        }

        let root_level = region[0xC6];
        let chunk_root_level = region[0xC7];
        let log_root_level = region[0xC8];
        validate_superblock_tree_level("root_level", root_level)?;
        validate_superblock_tree_level("chunk_root_level", chunk_root_level)?;
        validate_superblock_tree_level("log_root_level", log_root_level)?;
        let csum_type = read_le_u16(region, 0xC4)?;
        validate_supported_csum_type(csum_type)?;

        // Parse sys_chunk_array_size and validate
        let sys_chunk_array_size = read_le_u32(region, 0xA0)?;
        let sys_array_len =
            usize::try_from(sys_chunk_array_size).map_err(|_| ParseError::IntegerConversion {
                field: "sys_chunk_array_size",
            })?;
        if sys_array_len > BTRFS_SYS_CHUNK_ARRAY_MAX {
            return Err(ParseError::InvalidField {
                field: "sys_chunk_array_size",
                reason: "exceeds 2048 byte limit",
            });
        }

        // Extract sys_chunk_array bytes
        let array_end = BTRFS_SYS_CHUNK_ARRAY_OFFSET
            .checked_add(sys_array_len)
            .ok_or(ParseError::InvalidField {
                field: "sys_chunk_array",
                reason: "offset overflow",
            })?;
        if array_end > region.len() {
            return Err(ParseError::InsufficientData {
                needed: array_end,
                offset: BTRFS_SYS_CHUNK_ARRAY_OFFSET,
                actual: region.len(),
            });
        }
        let sys_chunk_array = region[BTRFS_SYS_CHUNK_ARRAY_OFFSET..array_end].to_vec();

        Ok(Self {
            csum: read_fixed::<32>(region, 0x00)?,
            fsid: read_fixed::<16>(region, 0x20)?,
            bytenr: read_le_u64(region, 0x30)?,
            flags: read_le_u64(region, 0x38)?,
            magic,
            generation: read_le_u64(region, 0x48)?,
            root: read_le_u64(region, 0x50)?,
            chunk_root: read_le_u64(region, 0x58)?,
            chunk_root_generation: read_le_u64(region, 0xA4)?,
            log_root: read_le_u64(region, 0x60)?,
            total_bytes,
            bytes_used,
            root_dir_objectid: read_le_u64(region, 0x80)?,
            num_devices,
            sectorsize,
            nodesize,
            stripesize,
            compat_flags: read_le_u64(region, 0xAC)?,
            compat_ro_flags: read_le_u64(region, 0xB4)?,
            incompat_flags: read_le_u64(region, 0xBC)?,
            csum_type,
            root_level,
            chunk_root_level,
            log_root_level,
            label: trim_nul_padded(&read_fixed::<BTRFS_SUPER_LABEL_LEN>(
                region,
                BTRFS_SUPER_LABEL_OFFSET,
            )?),
            sys_chunk_array_size,
            sys_chunk_array,
        })
    }

    pub fn parse_from_image(image: &[u8]) -> Result<Self, ParseError> {
        let end = BTRFS_SUPER_INFO_OFFSET
            .checked_add(BTRFS_SUPER_INFO_SIZE)
            .ok_or(ParseError::InvalidField {
                field: "superblock_offset",
                reason: "overflow",
            })?;

        if image.len() < end {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_SUPER_INFO_SIZE,
                offset: BTRFS_SUPER_INFO_OFFSET,
                actual: image.len().saturating_sub(BTRFS_SUPER_INFO_OFFSET),
            });
        }

        Self::parse_superblock_region(&image[BTRFS_SUPER_INFO_OFFSET..end])
    }

    /// Serialize this superblock to on-disk format (4096 bytes).
    ///
    /// Writes all fields to their kernel-defined offsets and computes
    /// the CRC32C checksum over bytes [0x20..4096).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; BTRFS_SUPER_INFO_SIZE];

        // fsid at 0x20
        buf[0x20..0x30].copy_from_slice(&self.fsid);
        // bytenr at 0x30
        buf[0x30..0x38].copy_from_slice(&self.bytenr.to_le_bytes());
        // flags at 0x38
        buf[0x38..0x40].copy_from_slice(&self.flags.to_le_bytes());
        // magic at 0x40
        buf[0x40..0x48].copy_from_slice(&self.magic.to_le_bytes());
        // generation at 0x48
        buf[0x48..0x50].copy_from_slice(&self.generation.to_le_bytes());
        // root at 0x50
        buf[0x50..0x58].copy_from_slice(&self.root.to_le_bytes());
        // chunk_root at 0x58
        buf[0x58..0x60].copy_from_slice(&self.chunk_root.to_le_bytes());
        // log_root at 0x60
        buf[0x60..0x68].copy_from_slice(&self.log_root.to_le_bytes());
        // total_bytes at 0x70
        buf[0x70..0x78].copy_from_slice(&self.total_bytes.to_le_bytes());
        // bytes_used at 0x78
        buf[0x78..0x80].copy_from_slice(&self.bytes_used.to_le_bytes());
        // root_dir_objectid at 0x80
        buf[0x80..0x88].copy_from_slice(&self.root_dir_objectid.to_le_bytes());
        // num_devices at 0x88
        buf[0x88..0x90].copy_from_slice(&self.num_devices.to_le_bytes());
        // sectorsize at 0x90
        buf[0x90..0x94].copy_from_slice(&self.sectorsize.to_le_bytes());
        // nodesize at 0x94
        buf[0x94..0x98].copy_from_slice(&self.nodesize.to_le_bytes());
        // leaf_size at 0x98 (deprecated, same as nodesize)
        buf[0x98..0x9C].copy_from_slice(&self.nodesize.to_le_bytes());
        // stripesize at 0x9C
        buf[0x9C..0xA0].copy_from_slice(&self.stripesize.to_le_bytes());
        let array_len = self.sys_chunk_array.len().min(BTRFS_SYS_CHUNK_ARRAY_MAX);
        let array_size = u32::try_from(array_len).unwrap_or(BTRFS_SYS_CHUNK_ARRAY_MAX_U32);

        // sys_chunk_array_size at 0xA0
        buf[0xA0..0xA4].copy_from_slice(&array_size.to_le_bytes());
        // chunk_root_generation at 0xA4
        buf[0xA4..0xAC].copy_from_slice(&self.chunk_root_generation.to_le_bytes());
        // compat_flags at 0xAC
        buf[0xAC..0xB4].copy_from_slice(&self.compat_flags.to_le_bytes());
        // compat_ro_flags at 0xB4
        buf[0xB4..0xBC].copy_from_slice(&self.compat_ro_flags.to_le_bytes());
        // incompat_flags at 0xBC
        buf[0xBC..0xC4].copy_from_slice(&self.incompat_flags.to_le_bytes());
        // csum_type at 0xC4
        buf[0xC4..0xC6].copy_from_slice(&self.csum_type.to_le_bytes());
        // root_level at 0xC6
        buf[0xC6] = self.root_level;
        // chunk_root_level at 0xC7
        buf[0xC7] = self.chunk_root_level;
        // log_root_level at 0xC8
        buf[0xC8] = self.log_root_level;
        // label at 0x12B (256 bytes, null-padded)
        let label_bytes = self.label.as_bytes();
        let label_len = label_bytes.len().min(BTRFS_SUPER_LABEL_LEN - 1);
        buf[BTRFS_SUPER_LABEL_OFFSET..BTRFS_SUPER_LABEL_OFFSET + label_len]
            .copy_from_slice(&label_bytes[..label_len]);
        // sys_chunk_array at 0x32B
        buf[BTRFS_SYS_CHUNK_ARRAY_OFFSET..BTRFS_SYS_CHUNK_ARRAY_OFFSET + array_len]
            .copy_from_slice(&self.sys_chunk_array[..array_len]);

        // Compute CRC32C over [0x20..4096) and store at [0x00..0x20)
        let csum = ffs_types::crc32c(&buf[0x20..]);
        buf[0..4].copy_from_slice(&csum.to_le_bytes());
        // Rest of csum field is zeros (CRC32C produces 4 bytes, field is 32)

        buf
    }

    /// Update an existing superblock blob in-place for a new commit.
    ///
    /// Patches root, root_level, generation, and recomputes checksum.
    pub fn patch_commit(data: &mut [u8], root: u64, root_level: u8, generation: u64) {
        // root at 0x50
        data[0x50..0x58].copy_from_slice(&root.to_le_bytes());
        // root_level at 0xC6
        data[0xC6] = root_level;
        // generation at 0x48
        data[0x48..0x50].copy_from_slice(&generation.to_le_bytes());
        // chunk_root_generation at 0xA4
        data[0xA4..0xAC].copy_from_slice(&generation.to_le_bytes());
        // Recompute checksum
        let csum = ffs_types::crc32c(&data[0x20..]);
        data[0..4].copy_from_slice(&csum.to_le_bytes());
    }
}

fn validate_superblock_tree_level(field: &'static str, level: u8) -> Result<(), ParseError> {
    if level > BTRFS_MAX_LEVEL {
        return Err(ParseError::InvalidField {
            field,
            reason: "exceeds btrfs max tree level",
        });
    }
    Ok(())
}

fn validate_supported_csum_type(csum_type: u16) -> Result<(), ParseError> {
    if csum_type != ffs_types::BTRFS_CSUM_TYPE_CRC32C {
        return Err(ParseError::InvalidField {
            field: "csum_type",
            reason: "only CRC32C (type 0) is currently supported",
        });
    }
    Ok(())
}

// ── sys_chunk_array entry types ──────────────────────────────────────────────

/// A single stripe within a btrfs chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsStripe {
    pub devid: u64,
    pub offset: u64,
    pub dev_uuid: [u8; 16],
}

/// A parsed entry from the superblock's sys_chunk_array.
///
/// Each entry consists of a `btrfs_disk_key` followed by a `btrfs_chunk`
/// (which embeds one or more `btrfs_stripe` entries).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsChunkEntry {
    pub key: BtrfsKey,
    pub length: u64,
    pub owner: u64,
    pub stripe_len: u64,
    pub chunk_type: u64,
    pub io_align: u32,
    pub io_width: u32,
    pub sector_size: u32,
    pub num_stripes: u16,
    pub sub_stripes: u16,
    pub stripes: Vec<BtrfsStripe>,
}

#[derive(Debug, Clone, Copy)]
struct BtrfsChunkHeader {
    length: u64,
    owner: u64,
    stripe_len: u64,
    chunk_type: u64,
    io_align: u32,
    io_width: u32,
    sector_size: u32,
    num_stripes: u16,
    sub_stripes: u16,
}

fn parse_sys_chunk_key(data: &[u8], cur: &mut usize) -> Result<BtrfsKey, ParseError> {
    if *cur + BTRFS_DISK_KEY_SIZE > data.len() {
        return Err(ParseError::InsufficientData {
            needed: BTRFS_DISK_KEY_SIZE,
            offset: *cur,
            actual: data.len() - *cur,
        });
    }

    let key = BtrfsKey {
        objectid: read_le_u64(data, *cur)?,
        item_type: data[*cur + 8],
        offset: read_le_u64(data, *cur + 9)?,
    };
    if key.item_type != BTRFS_CHUNK_ITEM_KEY {
        return Err(ParseError::InvalidField {
            field: "sys_chunk_key_type",
            reason: "expected CHUNK_ITEM_KEY",
        });
    }
    if key.objectid != BTRFS_FIRST_CHUNK_TREE_OBJECTID {
        return Err(ParseError::InvalidField {
            field: "sys_chunk_key_objectid",
            reason: "expected first chunk tree objectid",
        });
    }
    *cur += BTRFS_DISK_KEY_SIZE;
    Ok(key)
}

fn parse_chunk_header(data: &[u8], cur: &mut usize) -> Result<BtrfsChunkHeader, ParseError> {
    if *cur + BTRFS_CHUNK_FIXED_SIZE > data.len() {
        return Err(ParseError::InsufficientData {
            needed: BTRFS_CHUNK_FIXED_SIZE,
            offset: *cur,
            actual: data.len() - *cur,
        });
    }

    let header = BtrfsChunkHeader {
        length: read_le_u64(data, *cur)?,
        owner: read_le_u64(data, *cur + 8)?,
        stripe_len: read_le_u64(data, *cur + 16)?,
        chunk_type: read_le_u64(data, *cur + 24)?,
        io_align: read_le_u32(data, *cur + 32)?,
        io_width: read_le_u32(data, *cur + 36)?,
        sector_size: read_le_u32(data, *cur + 40)?,
        num_stripes: read_le_u16(data, *cur + 44)?,
        sub_stripes: read_le_u16(data, *cur + 46)?,
    };
    *cur += BTRFS_CHUNK_FIXED_SIZE;

    let raid_bits = header.chunk_type & chunk_type_flags::RAID_MASK;
    if raid_bits.count_ones() > 1 {
        return Err(ParseError::InvalidField {
            field: "chunk_type",
            reason: "multiple RAID profiles set",
        });
    }
    if header.length == 0 {
        return Err(ParseError::InvalidField {
            field: "chunk_length",
            reason: "chunk has zero length",
        });
    }
    if header.stripe_len == 0 {
        return Err(ParseError::InvalidField {
            field: "stripe_len",
            reason: "chunk has zero stripe length",
        });
    }
    if header.num_stripes == 0 {
        return Err(ParseError::InvalidField {
            field: "num_stripes",
            reason: "chunk must have at least one stripe",
        });
    }

    Ok(header)
}

fn parse_chunk_stripes(
    data: &[u8],
    cur: &mut usize,
    num_stripes: u16,
) -> Result<Vec<BtrfsStripe>, ParseError> {
    let stripes_count = usize::from(num_stripes);
    let stripes_bytes =
        stripes_count
            .checked_mul(BTRFS_STRIPE_SIZE)
            .ok_or(ParseError::InvalidField {
                field: "num_stripes",
                reason: "stripe count overflow",
            })?;

    if *cur + stripes_bytes > data.len() {
        return Err(ParseError::InsufficientData {
            needed: stripes_bytes,
            offset: *cur,
            actual: data.len() - *cur,
        });
    }

    let mut stripes = Vec::with_capacity(stripes_count);
    for _ in 0..stripes_count {
        let devid = read_le_u64(data, *cur)?;
        if devid == 0 {
            return Err(ParseError::InvalidField {
                field: "stripe_devid",
                reason: "must be non-zero",
            });
        }
        stripes.push(BtrfsStripe {
            devid,
            offset: read_le_u64(data, *cur + 8)?,
            dev_uuid: read_fixed::<16>(data, *cur + 16)?,
        });
        *cur += BTRFS_STRIPE_SIZE;
    }
    Ok(stripes)
}

/// Parse all entries from a sys_chunk_array byte slice.
///
/// The array contains alternating `btrfs_disk_key` + `btrfs_chunk` entries.
/// Each chunk embeds `num_stripes` stripe descriptors.
fn parse_sys_chunk_array_inner(
    data: &[u8],
    preallocate_entries: bool,
) -> Result<Vec<BtrfsChunkEntry>, ParseError> {
    let mut entries = if preallocate_entries {
        Vec::with_capacity(data.len() / BTRFS_SYS_CHUNK_MIN_ENTRY_SIZE)
    } else {
        Vec::new()
    };
    let mut cur = 0_usize;

    while cur < data.len() {
        let key = parse_sys_chunk_key(data, &mut cur)?;
        let header = parse_chunk_header(data, &mut cur)?;
        let stripes = parse_chunk_stripes(data, &mut cur, header.num_stripes)?;

        let entry = BtrfsChunkEntry {
            key,
            length: header.length,
            owner: header.owner,
            stripe_len: header.stripe_len,
            chunk_type: header.chunk_type,
            io_align: header.io_align,
            io_width: header.io_width,
            sector_size: header.sector_size,
            num_stripes: header.num_stripes,
            sub_stripes: header.sub_stripes,
            stripes,
        };
        let profile = BtrfsRaidProfile::from_chunk_type(entry.chunk_type);
        match profile {
            BtrfsRaidProfile::Single
            | BtrfsRaidProfile::Dup
            | BtrfsRaidProfile::Raid1
            | BtrfsRaidProfile::Raid1C3
            | BtrfsRaidProfile::Raid1C4 => validate_mirror_stripes(&entry, profile)?,
            _ => {}
        }
        entries.push(entry);
    }

    Ok(entries)
}

/// Parses the packed Btrfs system chunk array from a superblock.
///
/// The array contains alternating `btrfs_disk_key` + `btrfs_chunk` entries.
/// Each chunk embeds `num_stripes` stripe descriptors.
pub fn parse_sys_chunk_array(data: &[u8]) -> Result<Vec<BtrfsChunkEntry>, ParseError> {
    parse_sys_chunk_array_inner(data, false)
}

/// Benchmark-only old/new switch for the outer sys-chunk entry allocation.
#[doc(hidden)]
pub fn bench_parse_sys_chunk_array(
    data: &[u8],
    preallocate_entries: bool,
) -> Result<Vec<BtrfsChunkEntry>, ParseError> {
    parse_sys_chunk_array_inner(data, preallocate_entries)
}

// ── Logical → physical mapping ──────────────────────────────────────────────

/// Result of a logical-to-physical bytenr mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsPhysicalMapping {
    pub devid: u64,
    pub physical: u64,
}

/// Map a logical byte address to a physical (device, offset) pair using
/// only the sys_chunk_array entries.
///
/// This is the bootstrap mapping needed to read the chunk tree and root
/// tree from a single-device btrfs image. For multi-device or RAID
/// layouts, the full chunk tree is required.
///
/// Returns `Ok(Some(mapping))` if the logical address is covered,
/// `Ok(None)` if no chunk covers it, or `Err` on malformed data.
/// Resolve `logical` within a single chunk, returning `None` when the chunk
/// does not cover it. Extracted so [`map_logical_to_physical`] can share the
/// per-chunk logic between its linear and binary-search paths.
fn chunk_physical(
    chunk: &BtrfsChunkEntry,
    logical: u64,
) -> Result<Option<BtrfsPhysicalMapping>, ParseError> {
    let chunk_start = chunk.key.offset;
    let chunk_end = chunk_start
        .checked_add(chunk.length)
        .ok_or(ParseError::InvalidField {
            field: "chunk_length",
            reason: "logical range overflow",
        })?;
    if logical < chunk_start || logical >= chunk_end {
        return Ok(None);
    }
    let profile = BtrfsRaidProfile::from_chunk_type(chunk.chunk_type);
    match profile {
        BtrfsRaidProfile::Single | BtrfsRaidProfile::Dup => {
            validate_mirror_stripes(chunk, profile)?;
        }
        _ => {
            return Err(ParseError::InvalidField {
                field: "chunk_type",
                reason: "multi-device RAID profile not supported",
            });
        }
    }
    let offset_within = logical - chunk_start;
    // Use the first stripe (single-device assumption).
    let stripe = chunk.stripes.first().ok_or(ParseError::InvalidField {
        field: "stripes",
        reason: "chunk has no stripes",
    })?;
    let physical = stripe
        .offset
        .checked_add(offset_within)
        .ok_or(ParseError::InvalidField {
            field: "stripe_offset",
            reason: "physical address overflow",
        })?;
    Ok(Some(BtrfsPhysicalMapping {
        devid: stripe.devid,
        physical,
    }))
}

/// Below this chunk count the linear scan is used. Bootstrap `sys_chunk_array`
/// lists are tiny and not necessarily sorted; large lists only ever come from
/// `walk_chunk_tree`, which sorts by `key.offset`.
const CHUNK_MAP_BINARY_SEARCH_THRESHOLD: usize = 16;

pub fn map_logical_to_physical(
    chunks: &[BtrfsChunkEntry],
    logical: u64,
) -> Result<Option<BtrfsPhysicalMapping>, ParseError> {
    // Chunks cover disjoint logical ranges. For a large (sorted-by-key.offset)
    // chunk list the covering chunk is the last one whose start is <= `logical`,
    // so binary-search to that single candidate instead of scanning every chunk
    // on every logical->physical mapping (every tree-node + data-block read).
    // O(chunks) -> O(log chunks) (bd-6u6xb). Small bootstrap lists keep the
    // linear scan (correct regardless of order, cheap at that size).
    if chunks.len() > CHUNK_MAP_BINARY_SEARCH_THRESHOLD {
        let pp = chunks.partition_point(|c| c.key.offset <= logical);
        if pp == 0 {
            return Ok(None);
        }
        return chunk_physical(&chunks[pp - 1], logical);
    }
    for chunk in chunks {
        if let Some(mapping) = chunk_physical(chunk, logical)? {
            return Ok(Some(mapping));
        }
    }
    Ok(None)
}

// ── RAID profiles ───────────────────────────────────────────────────────────

/// Btrfs chunk type flags for RAID profiles (from `include/uapi/linux/btrfs.h`).
pub mod chunk_type_flags {
    /// Data chunk.
    pub const BTRFS_BLOCK_GROUP_DATA: u64 = 1 << 0;
    /// System chunk (bootstrap).
    pub const BTRFS_BLOCK_GROUP_SYSTEM: u64 = 1 << 1;
    /// Metadata chunk.
    pub const BTRFS_BLOCK_GROUP_METADATA: u64 = 1 << 2;

    // RAID profile bits (bit 3+)
    /// RAID0: striped across N devices (no redundancy).
    pub const BTRFS_BLOCK_GROUP_RAID0: u64 = 1 << 3;
    /// RAID1: mirrored on 2 devices.
    pub const BTRFS_BLOCK_GROUP_RAID1: u64 = 1 << 4;
    /// DUP: duplicate on same device (not multi-device).
    pub const BTRFS_BLOCK_GROUP_DUP: u64 = 1 << 5;
    /// RAID10: striped mirrors (N/2 stripes, each mirrored).
    pub const BTRFS_BLOCK_GROUP_RAID10: u64 = 1 << 6;
    /// RAID5: striped with single parity.
    pub const BTRFS_BLOCK_GROUP_RAID5: u64 = 1 << 7;
    /// RAID6: striped with double parity.
    pub const BTRFS_BLOCK_GROUP_RAID6: u64 = 1 << 8;
    /// RAID1C3: mirrored on 3 devices.
    pub const BTRFS_BLOCK_GROUP_RAID1C3: u64 = 1 << 9;
    /// RAID1C4: mirrored on 4 devices.
    pub const BTRFS_BLOCK_GROUP_RAID1C4: u64 = 1 << 10;

    /// Mask for RAID profile bits.
    pub const RAID_MASK: u64 = BTRFS_BLOCK_GROUP_RAID0
        | BTRFS_BLOCK_GROUP_RAID1
        | BTRFS_BLOCK_GROUP_DUP
        | BTRFS_BLOCK_GROUP_RAID10
        | BTRFS_BLOCK_GROUP_RAID5
        | BTRFS_BLOCK_GROUP_RAID6
        | BTRFS_BLOCK_GROUP_RAID1C3
        | BTRFS_BLOCK_GROUP_RAID1C4;
}

/// Identified RAID profile for a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BtrfsRaidProfile {
    /// Single device / no RAID (linear mapping).
    Single,
    /// Duplicate on same device.
    Dup,
    /// RAID0: striped, no redundancy.
    Raid0,
    /// RAID1: mirrored on 2 devices.
    Raid1,
    /// RAID1C3: mirrored on 3 devices.
    Raid1C3,
    /// RAID1C4: mirrored on 4 devices.
    Raid1C4,
    /// RAID10: striped mirrors.
    Raid10,
    /// RAID5: single parity.
    Raid5,
    /// RAID6: double parity.
    Raid6,
}

impl BtrfsRaidProfile {
    /// Identify the RAID profile from chunk_type flags.
    #[must_use]
    pub fn from_chunk_type(chunk_type: u64) -> Self {
        use chunk_type_flags::{
            BTRFS_BLOCK_GROUP_DUP, BTRFS_BLOCK_GROUP_RAID0, BTRFS_BLOCK_GROUP_RAID1,
            BTRFS_BLOCK_GROUP_RAID1C3, BTRFS_BLOCK_GROUP_RAID1C4, BTRFS_BLOCK_GROUP_RAID5,
            BTRFS_BLOCK_GROUP_RAID6, BTRFS_BLOCK_GROUP_RAID10, RAID_MASK,
        };
        let raid_bits = chunk_type & RAID_MASK;
        if raid_bits & BTRFS_BLOCK_GROUP_RAID0 != 0 {
            Self::Raid0
        } else if raid_bits & BTRFS_BLOCK_GROUP_RAID1 != 0 {
            Self::Raid1
        } else if raid_bits & BTRFS_BLOCK_GROUP_RAID1C3 != 0 {
            Self::Raid1C3
        } else if raid_bits & BTRFS_BLOCK_GROUP_RAID1C4 != 0 {
            Self::Raid1C4
        } else if raid_bits & BTRFS_BLOCK_GROUP_RAID10 != 0 {
            Self::Raid10
        } else if raid_bits & BTRFS_BLOCK_GROUP_RAID5 != 0 {
            Self::Raid5
        } else if raid_bits & BTRFS_BLOCK_GROUP_RAID6 != 0 {
            Self::Raid6
        } else if raid_bits & BTRFS_BLOCK_GROUP_DUP != 0 {
            Self::Dup
        } else {
            Self::Single
        }
    }

    /// Number of data copies available for reads (mirrors).
    #[must_use]
    pub const fn data_copies(self) -> u16 {
        match self {
            Self::Single | Self::Raid0 | Self::Raid5 | Self::Raid6 => 1,
            Self::Dup | Self::Raid1 | Self::Raid10 => 2,
            Self::Raid1C3 => 3,
            Self::Raid1C4 => 4,
        }
    }

    /// Whether this profile provides redundancy (can tolerate device loss).
    #[must_use]
    pub const fn is_redundant(self) -> bool {
        self.data_copies() > 1 || matches!(self, Self::Raid5 | Self::Raid6)
    }
}

/// Result of multi-device logical-to-physical stripe resolution.
///
/// Returns all readable stripes for a given logical address, enabling
/// the caller to select a device (round-robin, failover, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsStripeMapping {
    /// RAID profile of the chunk.
    pub profile: BtrfsRaidProfile,
    /// All readable stripes (device, physical offset) for this logical address.
    /// For RAID1: 2 entries (either can serve the read).
    /// For RAID0: 1 entry (the stripe owning this offset).
    /// For Single: 1 entry.
    /// The common one-to-four-stripe cases stay inline; permissive mirror and
    /// RAID10 layouts with more stripes spill without changing ordering.
    pub stripes: SmallVec<[BtrfsPhysicalMapping; 4]>,
}

/// Map a logical byte address to all readable stripe locations.
///
/// Unlike [`map_logical_to_physical`] which assumes single-device, this
/// function resolves the full stripe layout for the matching chunk,
/// enabling multi-device reads and failover.
pub fn map_logical_to_stripes(
    chunks: &[BtrfsChunkEntry],
    logical: u64,
) -> Result<Option<BtrfsStripeMapping>, ParseError> {
    // Chunks cover disjoint logical ranges; large (sorted-by-key.offset) lists
    // from `walk_chunk_tree` let us binary-search to the single covering chunk
    // (last one whose start is <= `logical`) instead of scanning every chunk on
    // every logical->stripe resolution. O(chunks) -> O(log chunks), the stripe
    // dual of `map_logical_to_physical` (bd-6tygu / bd-6u6xb). Small bootstrap
    // lists keep the linear scan (correct regardless of order, cheap at size).
    if chunks.len() > CHUNK_MAP_BINARY_SEARCH_THRESHOLD {
        let pp = chunks.partition_point(|c| c.key.offset <= logical);
        if pp == 0 {
            return Ok(None);
        }
        return chunk_stripes(&chunks[pp - 1], logical);
    }
    for chunk in chunks {
        if let Some(mapping) = chunk_stripes(chunk, logical)? {
            return Ok(Some(mapping));
        }
    }
    Ok(None)
}

/// Resolve `logical` to its stripe mapping within a single chunk, returning
/// `None` when the chunk does not cover it. Extracted so
/// [`map_logical_to_stripes`] can share the per-chunk logic between its linear
/// and binary-search paths.
fn chunk_stripes(
    chunk: &BtrfsChunkEntry,
    logical: u64,
) -> Result<Option<BtrfsStripeMapping>, ParseError> {
    let chunk_start = chunk.key.offset;
    let chunk_end = chunk_start
        .checked_add(chunk.length)
        .ok_or(ParseError::InvalidField {
            field: "chunk_length",
            reason: "logical range overflow",
        })?;
    if logical < chunk_start || logical >= chunk_end {
        return Ok(None);
    }
    let offset_within = logical - chunk_start;
    let profile = BtrfsRaidProfile::from_chunk_type(chunk.chunk_type);
    let stripes = resolve_chunk_stripes(chunk, offset_within, profile)?;
    Ok(Some(BtrfsStripeMapping { profile, stripes }))
}

/// Resolve stripe mappings for a single chunk at the given offset.
fn resolve_chunk_stripes(
    chunk: &BtrfsChunkEntry,
    offset_within: u64,
    profile: BtrfsRaidProfile,
) -> Result<SmallVec<[BtrfsPhysicalMapping; 4]>, ParseError> {
    match profile {
        BtrfsRaidProfile::Single
        | BtrfsRaidProfile::Dup
        | BtrfsRaidProfile::Raid1
        | BtrfsRaidProfile::Raid1C3
        | BtrfsRaidProfile::Raid1C4 => resolve_mirror_stripes(chunk, offset_within, profile),
        BtrfsRaidProfile::Raid0 => resolve_raid0_stripe(chunk, offset_within),
        BtrfsRaidProfile::Raid10 => resolve_raid10_stripes(chunk, offset_within),
        BtrfsRaidProfile::Raid5 | BtrfsRaidProfile::Raid6 => {
            resolve_raid56_stripe(chunk, offset_within, profile)
        }
    }
}

fn validate_stripe_count(chunk: &BtrfsChunkEntry) -> Result<usize, ParseError> {
    let count = usize::from(chunk.num_stripes);
    if count == 0 {
        return Err(ParseError::InvalidField {
            field: "num_stripes",
            reason: "chunk must have at least one stripe",
        });
    }
    if count != chunk.stripes.len() {
        return Err(ParseError::InvalidField {
            field: "num_stripes",
            reason: "num_stripes does not match stripe list length",
        });
    }
    Ok(count)
}

fn validate_mirror_stripes(
    chunk: &BtrfsChunkEntry,
    profile: BtrfsRaidProfile,
) -> Result<(), ParseError> {
    let count = validate_stripe_count(chunk)?;
    let required = match profile {
        BtrfsRaidProfile::Dup | BtrfsRaidProfile::Raid1 => 2,
        BtrfsRaidProfile::Raid1C3 => 3,
        BtrfsRaidProfile::Raid1C4 => 4,
        _ => 1,
    };
    if profile == BtrfsRaidProfile::Single && count != 1 {
        return Err(ParseError::InvalidField {
            field: "num_stripes",
            reason: "single chunk must have exactly one stripe",
        });
    }
    if profile != BtrfsRaidProfile::Single && count < required {
        let reason = match profile {
            BtrfsRaidProfile::Dup => "DUP chunk must have at least two stripes",
            BtrfsRaidProfile::Raid1 => "RAID1 chunk must have at least two stripes",
            BtrfsRaidProfile::Raid1C3 => "RAID1C3 chunk must have at least three stripes",
            BtrfsRaidProfile::Raid1C4 => "RAID1C4 chunk must have at least four stripes",
            _ => "mirror chunk has insufficient stripes",
        };
        return Err(ParseError::InvalidField {
            field: "num_stripes",
            reason,
        });
    }
    if profile == BtrfsRaidProfile::Dup {
        let first = chunk.stripes.first().ok_or(ParseError::InvalidField {
            field: "stripes",
            reason: "chunk has no stripes",
        })?;
        if chunk
            .stripes
            .iter()
            .any(|stripe| stripe.devid != first.devid)
        {
            return Err(ParseError::InvalidField {
                field: "stripe_devid",
                reason: "DUP chunk must use a single device",
            });
        }
    }
    Ok(())
}

/// Mirror profiles (Single/DUP/RAID1/RAID1C3/RAID1C4): all stripes are copies.
fn resolve_mirror_stripes(
    chunk: &BtrfsChunkEntry,
    offset_within: u64,
    profile: BtrfsRaidProfile,
) -> Result<SmallVec<[BtrfsPhysicalMapping; 4]>, ParseError> {
    validate_mirror_stripes(chunk, profile)?;
    chunk
        .stripes
        .iter()
        .map(|s| stripe_physical(s, offset_within))
        .collect()
}

/// RAID0: data is striped across devices.
fn resolve_raid0_stripe(
    chunk: &BtrfsChunkEntry,
    offset_within: u64,
) -> Result<SmallVec<[BtrfsPhysicalMapping; 4]>, ParseError> {
    let stripe_len = require_nonzero_stripe_len(chunk, "RAID0")?;
    validate_stripe_count(chunk)?;
    let num = u64::from(chunk.num_stripes);
    let stripe_idx = (offset_within / stripe_len) % num;
    let offset_in_stripe = offset_within % stripe_len;
    let stripe_nr = offset_within
        / stripe_len
            .checked_mul(num)
            .ok_or(ParseError::InvalidField {
                field: "stripe_len",
                reason: "RAID0 stripe_len * num_stripes overflow",
            })?;
    let idx = usize::try_from(stripe_idx).unwrap_or(usize::MAX);
    let s = chunk.stripes.get(idx).ok_or(ParseError::InvalidField {
        field: "stripe_index",
        reason: "stripe index out of range",
    })?;
    Ok(smallvec![stripe_physical_at(
        s,
        stripe_nr,
        stripe_len,
        offset_in_stripe,
    )?])
}

/// RAID10: striped mirrors (sub_stripes mirrors per data stripe).
fn resolve_raid10_stripes(
    chunk: &BtrfsChunkEntry,
    offset_within: u64,
) -> Result<SmallVec<[BtrfsPhysicalMapping; 4]>, ParseError> {
    let stripe_len = require_nonzero_stripe_len(chunk, "RAID10")?;
    validate_stripe_count(chunk)?;
    if chunk.sub_stripes == 0 {
        return Err(ParseError::InvalidField {
            field: "sub_stripes",
            reason: "RAID10 requires non-zero sub_stripes",
        });
    }
    let sub = u64::from(chunk.sub_stripes);
    let num = u64::from(chunk.num_stripes);
    if num % sub != 0 {
        return Err(ParseError::InvalidField {
            field: "num_stripes",
            reason: "RAID10 num_stripes not divisible by sub_stripes",
        });
    }
    let data_stripes = num / sub;
    if data_stripes == 0 {
        return Err(ParseError::InvalidField {
            field: "num_stripes",
            reason: "RAID10 has zero data stripes",
        });
    }
    let stripe_idx = (offset_within / stripe_len) % data_stripes;
    let offset_in_stripe = offset_within % stripe_len;
    let stripe_nr = offset_within
        / stripe_len
            .checked_mul(data_stripes)
            .ok_or(ParseError::InvalidField {
                field: "stripe_len",
                reason: "RAID10 stripe_len * data_stripes overflow",
            })?;
    let base = stripe_idx
        .checked_mul(sub)
        .ok_or(ParseError::InvalidField {
            field: "stripe_index",
            reason: "RAID10 stripe index overflow",
        })?;
    let base_usize = usize::try_from(base).map_err(|_| ParseError::InvalidField {
        field: "stripe_index",
        reason: "RAID10 stripe index overflow",
    })?;
    let sub_usize = usize::try_from(sub).map_err(|_| ParseError::InvalidField {
        field: "sub_stripes",
        reason: "RAID10 sub_stripes exceeds addressable range",
    })?;
    let stripe_off = stripe_nr
        .checked_mul(stripe_len)
        .and_then(|v| v.checked_add(offset_in_stripe))
        .ok_or(ParseError::InvalidField {
            field: "stripe_offset",
            reason: "stripe offset overflow",
        })?;

    let mut stripes = SmallVec::with_capacity(sub_usize);
    for m in 0..sub_usize {
        let idx = base_usize.checked_add(m).ok_or(ParseError::InvalidField {
            field: "stripe_index",
            reason: "stripe index overflow",
        })?;
        let s = chunk.stripes.get(idx).ok_or(ParseError::InvalidField {
            field: "stripe_index",
            reason: "stripe index out of range",
        })?;
        let physical = s
            .offset
            .checked_add(stripe_off)
            .ok_or(ParseError::InvalidField {
                field: "stripe_offset",
                reason: "physical address overflow",
            })?;
        stripes.push(BtrfsPhysicalMapping {
            devid: s.devid,
            physical,
        });
    }
    Ok(stripes)
}

/// RAID5/6: return the data stripe (parity stripes excluded).
///
/// Parity rotation: for each "row" (stripe_nr), the parity position(s) rotate
/// across devices. RAID5 has 1 parity (P), RAID6 has 2 (P + Q at adjacent
/// positions modulo num_stripes). Data stripe indices are mapped to actual
/// device positions by adjusting their rank around the parity positions; this
/// correctly handles the wrap-around case where P is at the last position
/// and Q wraps to position 0.
fn resolve_raid56_stripe(
    chunk: &BtrfsChunkEntry,
    offset_within: u64,
    profile: BtrfsRaidProfile,
) -> Result<SmallVec<[BtrfsPhysicalMapping; 4]>, ParseError> {
    let stripe_len = require_nonzero_stripe_len(chunk, "RAID5/6")?;
    validate_stripe_count(chunk)?;
    let num = u64::from(chunk.num_stripes);
    let parity_count: u64 = if profile == BtrfsRaidProfile::Raid6 {
        2
    } else {
        1
    };
    let min_stripes = parity_count + 2;
    if num < min_stripes {
        return Err(ParseError::InvalidField {
            field: "num_stripes",
            reason: "RAID5/6 requires at least two data stripes plus parity",
        });
    }
    let data_stripes = num.saturating_sub(parity_count);
    if data_stripes == 0 {
        return Err(ParseError::InvalidField {
            field: "num_stripes",
            reason: "RAID5/6 has no data stripes",
        });
    }
    let stripe_idx = (offset_within / stripe_len) % data_stripes;
    let offset_in_stripe = offset_within % stripe_len;
    let stripe_nr = offset_within
        / stripe_len
            .checked_mul(data_stripes)
            .ok_or(ParseError::InvalidField {
                field: "stripe_len",
                reason: "RAID5/6 stripe_len * data_stripes overflow",
            })?;

    // Btrfs parity rotation: P and Q rotate left (decreasing device index)
    // by 1 for each stripe_nr row. For stripe_nr=0, P is at num-1, Q at num-2.
    let rot = stripe_nr % num;
    let p_pos = (num - 1).saturating_sub(rot) % num;
    let q_pos = (num.saturating_sub(2) + num - rot) % num;

    // Map the data rank to its device position by accounting for the one or
    // two parity slots before it. This selects the same kth non-parity slot as
    // a linear scan, but its work is independent of the stripe count.
    let actual_idx = if parity_count == 1 {
        if stripe_idx < p_pos {
            stripe_idx
        } else {
            stripe_idx + 1
        }
    } else {
        let first_parity = p_pos.min(q_pos);
        let second_parity = p_pos.max(q_pos);
        let after_first = if stripe_idx < first_parity {
            stripe_idx
        } else {
            stripe_idx + 1
        };
        if after_first < second_parity {
            after_first
        } else {
            after_first + 1
        }
    };

    let idx = usize::try_from(actual_idx).unwrap_or(usize::MAX);
    let s = chunk.stripes.get(idx).ok_or(ParseError::InvalidField {
        field: "stripe_index",
        reason: "stripe index out of range",
    })?;
    Ok(smallvec![stripe_physical_at(
        s,
        stripe_nr,
        stripe_len,
        offset_in_stripe,
    )?])
}

fn require_nonzero_stripe_len(chunk: &BtrfsChunkEntry, _label: &str) -> Result<u64, ParseError> {
    if chunk.stripe_len == 0 {
        return Err(ParseError::InvalidField {
            field: "stripe_len",
            reason: "chunk has zero stripe length",
        });
    }
    Ok(chunk.stripe_len)
}

fn stripe_physical(
    s: &BtrfsStripe,
    offset_within: u64,
) -> Result<BtrfsPhysicalMapping, ParseError> {
    Ok(BtrfsPhysicalMapping {
        devid: s.devid,
        physical: s
            .offset
            .checked_add(offset_within)
            .ok_or(ParseError::InvalidField {
                field: "stripe_offset",
                reason: "physical address overflow",
            })?,
    })
}

fn stripe_physical_at(
    s: &BtrfsStripe,
    stripe_nr: u64,
    stripe_len: u64,
    offset_in_stripe: u64,
) -> Result<BtrfsPhysicalMapping, ParseError> {
    let stripe_offset = stripe_nr
        .checked_mul(stripe_len)
        .and_then(|v| v.checked_add(offset_in_stripe))
        .ok_or(ParseError::InvalidField {
            field: "stripe_offset",
            reason: "stripe offset overflow",
        })?;
    let physical = s
        .offset
        .checked_add(stripe_offset)
        .ok_or(ParseError::InvalidField {
            field: "stripe_offset",
            reason: "physical address overflow",
        })?;
    Ok(BtrfsPhysicalMapping {
        devid: s.devid,
        physical,
    })
}

// ── DEV_ITEM parsing ────────────────────────────────────────────────────────

/// Parsed btrfs device item (from the device tree or superblock).
///
/// Contains device identification and capacity information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsDevItem {
    /// Device ID (matches BtrfsStripe::devid).
    pub devid: u64,
    /// Total bytes on this device.
    pub total_bytes: u64,
    /// Bytes used on this device.
    pub bytes_used: u64,
    /// I/O alignment for this device.
    pub io_align: u32,
    /// I/O width for this device.
    pub io_width: u32,
    /// Sector size of this device.
    pub sector_size: u32,
    /// Device type (0 = regular).
    pub dev_type: u64,
    /// Generation when this item was last updated.
    pub generation: u64,
    /// Byte offset of the start of data on device.
    pub start_offset: u64,
    /// Device group (for RAID assignment).
    pub dev_group: u32,
    /// Seek speed classification.
    pub seek_speed: u8,
    /// Bandwidth classification.
    pub bandwidth: u8,
    /// Device UUID.
    pub uuid: [u8; 16],
    /// Filesystem UUID.
    pub fsid: [u8; 16],
}

/// Size of a btrfs_dev_item on disk (98 bytes).
const BTRFS_DEV_ITEM_SIZE: usize = 98;

/// Parse a DEV_ITEM from raw leaf data.
pub fn parse_dev_item(data: &[u8]) -> Result<BtrfsDevItem, ParseError> {
    if data.len() < BTRFS_DEV_ITEM_SIZE {
        return Err(ParseError::InsufficientData {
            needed: BTRFS_DEV_ITEM_SIZE,
            offset: 0,
            actual: data.len(),
        });
    }

    let devid = read_le_u64(data, 0)?;
    let total_bytes = read_le_u64(data, 8)?;
    let bytes_used = read_le_u64(data, 16)?;
    if devid == 0 {
        return Err(ParseError::InvalidField {
            field: "devid",
            reason: "must be non-zero",
        });
    }
    if total_bytes == 0 {
        return Err(ParseError::InvalidField {
            field: "total_bytes",
            reason: "must be non-zero",
        });
    }
    if bytes_used > total_bytes {
        return Err(ParseError::InvalidField {
            field: "bytes_used",
            reason: "exceeds total_bytes",
        });
    }

    Ok(BtrfsDevItem {
        devid,
        total_bytes,
        bytes_used,
        io_align: read_le_u32(data, 24)?,
        io_width: read_le_u32(data, 28)?,
        sector_size: read_le_u32(data, 32)?,
        dev_type: read_le_u64(data, 36)?,
        generation: read_le_u64(data, 44)?,
        start_offset: read_le_u64(data, 52)?,
        dev_group: read_le_u32(data, 60)?,
        seek_speed: data[64],
        bandwidth: data[65],
        uuid: read_fixed::<16>(data, 66)?,
        fsid: read_fixed::<16>(data, 82)?,
    })
}

// ── CHUNK_ITEM / DEV_EXTENT / DEV_ITEM serialization (bd-a136s) ─────────────
//
// Writers for the three on-disk structures a chunk allocation must create. The
// crate has carried parsers for all three since mount was read-only; growing a
// filesystem needs the other direction.
//
// ⚠️ EVERY WRITER HERE VALIDATES WHAT ITS PARSER VALIDATES, and refuses rather
// than emitting bytes its own parser would reject. That is not defensive
// styling: these bytes are judged by `btrfs check` and by the kernel's mount
// path, where a malformed chunk is not a parse error but an unmountable
// filesystem. A serializer that can produce input its own parser rejects is a
// silent corruption generator, so the round-trip is a type-level property here,
// enforced by refusal.

/// Byte length of a serialized `btrfs_dev_extent`.
pub const BTRFS_DEV_EXTENT_SIZE: usize = 48;

/// Key type of a `DEV_EXTENT` item — a device-tree record of which physical
/// range of a device backs which chunk. Its key is
/// `(objectid = devid, type = DEV_EXTENT, offset = physical start)`.
pub const BTRFS_DEV_EXTENT_KEY: u8 = 204;

/// Key type of a `DEV_ITEM`, which lives under objectid
/// [`BTRFS_DEV_ITEMS_OBJECTID`] in the chunk tree.
pub const BTRFS_DEV_ITEM_KEY: u8 = 216;

/// Objectid the chunk tree files `DEV_ITEM`s under.
pub const BTRFS_DEV_ITEMS_OBJECTID: u64 = 1;

/// The reverse map of a chunk: the physical range on one device that backs it.
///
/// A chunk's stripes say "this logical range lives at this physical offset on
/// device N"; the `DEV_EXTENT` says the same thing filed under the device, and
/// `btrfs check` cross-checks the two. Allocating a chunk without writing the
/// matching dev extents produces exactly the "chunk ... is not found in dev
/// extent" complaint, so the two are written together or not at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsDevExtent {
    /// Objectid of the tree owning the chunk (always the chunk tree, 3).
    pub chunk_tree: u64,
    /// Objectid of the chunk this extent backs (always
    /// `BTRFS_FIRST_CHUNK_TREE_OBJECTID`).
    pub chunk_objectid: u64,
    /// Logical start of the chunk this extent backs.
    pub chunk_offset: u64,
    /// Length of the physical range.
    pub length: u64,
    /// UUID of the chunk tree.
    pub chunk_tree_uuid: [u8; 16],
}

impl BtrfsDevExtent {
    /// Serialize into the 48-byte on-disk form.
    ///
    /// # Errors
    /// Returns [`ParseError::InvalidField`] for a zero `length`, which would
    /// describe a device extent backing nothing, and
    /// [`ParseError::InsufficientData`] if `buf` is too short.
    pub fn write_to_bytes(&self, buf: &mut [u8]) -> Result<(), ParseError> {
        if buf.len() < BTRFS_DEV_EXTENT_SIZE {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_DEV_EXTENT_SIZE,
                offset: 0,
                actual: buf.len(),
            });
        }
        if self.length == 0 {
            return Err(ParseError::InvalidField {
                field: "dev_extent_length",
                reason: "must be non-zero",
            });
        }
        buf[0..8].copy_from_slice(&self.chunk_tree.to_le_bytes());
        buf[8..16].copy_from_slice(&self.chunk_objectid.to_le_bytes());
        buf[16..24].copy_from_slice(&self.chunk_offset.to_le_bytes());
        buf[24..32].copy_from_slice(&self.length.to_le_bytes());
        buf[32..48].copy_from_slice(&self.chunk_tree_uuid);
        Ok(())
    }

    /// Serialize into a fresh 48-byte vector.
    ///
    /// # Errors
    /// As [`Self::write_to_bytes`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, ParseError> {
        let mut buf = vec![0_u8; BTRFS_DEV_EXTENT_SIZE];
        self.write_to_bytes(&mut buf)?;
        Ok(buf)
    }
}

/// Parse a `DEV_EXTENT` item from raw leaf data.
///
/// # Errors
/// Returns [`ParseError::InsufficientData`] if `data` is shorter than 48 bytes,
/// or [`ParseError::InvalidField`] for a zero length.
pub fn parse_dev_extent(data: &[u8]) -> Result<BtrfsDevExtent, ParseError> {
    if data.len() < BTRFS_DEV_EXTENT_SIZE {
        return Err(ParseError::InsufficientData {
            needed: BTRFS_DEV_EXTENT_SIZE,
            offset: 0,
            actual: data.len(),
        });
    }
    let length = read_le_u64(data, 24)?;
    if length == 0 {
        return Err(ParseError::InvalidField {
            field: "dev_extent_length",
            reason: "must be non-zero",
        });
    }
    Ok(BtrfsDevExtent {
        chunk_tree: read_le_u64(data, 0)?,
        chunk_objectid: read_le_u64(data, 8)?,
        chunk_offset: read_le_u64(data, 16)?,
        length,
        chunk_tree_uuid: read_fixed::<16>(data, 32)?,
    })
}

impl BtrfsDevItem {
    /// Serialize into the 98-byte on-disk form.
    ///
    /// # Errors
    /// Mirrors [`parse_dev_item`]'s invariants exactly — zero `devid`, zero
    /// `total_bytes`, or `bytes_used` exceeding `total_bytes` are refused, the
    /// last being the one a chunk allocation can actually get wrong: growing the
    /// filesystem must raise `bytes_used` by the chunk's device footprint, and
    /// letting it pass `total_bytes` would claim more of the device than exists.
    pub fn write_to_bytes(&self, buf: &mut [u8]) -> Result<(), ParseError> {
        if buf.len() < BTRFS_DEV_ITEM_SIZE {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_DEV_ITEM_SIZE,
                offset: 0,
                actual: buf.len(),
            });
        }
        if self.devid == 0 {
            return Err(ParseError::InvalidField {
                field: "devid",
                reason: "must be non-zero",
            });
        }
        if self.total_bytes == 0 {
            return Err(ParseError::InvalidField {
                field: "total_bytes",
                reason: "must be non-zero",
            });
        }
        if self.bytes_used > self.total_bytes {
            return Err(ParseError::InvalidField {
                field: "bytes_used",
                reason: "exceeds total_bytes",
            });
        }
        buf[0..8].copy_from_slice(&self.devid.to_le_bytes());
        buf[8..16].copy_from_slice(&self.total_bytes.to_le_bytes());
        buf[16..24].copy_from_slice(&self.bytes_used.to_le_bytes());
        buf[24..28].copy_from_slice(&self.io_align.to_le_bytes());
        buf[28..32].copy_from_slice(&self.io_width.to_le_bytes());
        buf[32..36].copy_from_slice(&self.sector_size.to_le_bytes());
        buf[36..44].copy_from_slice(&self.dev_type.to_le_bytes());
        buf[44..52].copy_from_slice(&self.generation.to_le_bytes());
        buf[52..60].copy_from_slice(&self.start_offset.to_le_bytes());
        buf[60..64].copy_from_slice(&self.dev_group.to_le_bytes());
        buf[64] = self.seek_speed;
        buf[65] = self.bandwidth;
        buf[66..82].copy_from_slice(&self.uuid);
        buf[82..98].copy_from_slice(&self.fsid);
        Ok(())
    }
}

impl BtrfsChunkEntry {
    /// Bytes this entry occupies in a `sys_chunk_array`: disk key + chunk header
    /// + one stripe per stripe.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        BTRFS_DISK_KEY_SIZE + BTRFS_CHUNK_FIXED_SIZE + self.stripes.len() * BTRFS_STRIPE_SIZE
    }

    /// Bytes this chunk occupies as a `CHUNK_ITEM` leaf VALUE — the same layout
    /// without the leading disk key, because in the chunk tree the key is the
    /// item's own key rather than embedded in its value. The `sys_chunk_array`
    /// is the only place the key is inline, which is why there are two forms.
    #[must_use]
    pub fn item_len(&self) -> usize {
        BTRFS_CHUNK_FIXED_SIZE + self.stripes.len() * BTRFS_STRIPE_SIZE
    }

    /// Validate exactly what [`parse_sys_chunk_array`] validates.
    ///
    /// # Errors
    /// Returns [`ParseError::InvalidField`] on a stripe count that disagrees
    /// with the stripe vector, a zero length / stripe_len / devid, more than one
    /// RAID profile bit, or a key that is not a `CHUNK_ITEM` under the first
    /// chunk-tree objectid.
    fn validate(&self) -> Result<(), ParseError> {
        // `num_stripes` and `stripes` can disagree, and silently writing
        // `stripes.len()` over the field would hide the caller's bug in a
        // structure nothing reads back until mount. Refuse instead.
        if usize::from(self.num_stripes) != self.stripes.len() {
            return Err(ParseError::InvalidField {
                field: "num_stripes",
                reason: "disagrees with the stripe list",
            });
        }
        if self.num_stripes == 0 {
            return Err(ParseError::InvalidField {
                field: "num_stripes",
                reason: "chunk must have at least one stripe",
            });
        }
        if self.length == 0 {
            return Err(ParseError::InvalidField {
                field: "chunk_length",
                reason: "chunk has zero length",
            });
        }
        if self.stripe_len == 0 {
            return Err(ParseError::InvalidField {
                field: "stripe_len",
                reason: "chunk has zero stripe length",
            });
        }
        if (self.chunk_type & chunk_type_flags::RAID_MASK).count_ones() > 1 {
            return Err(ParseError::InvalidField {
                field: "chunk_type",
                reason: "multiple RAID profiles set",
            });
        }
        if self.stripes.iter().any(|stripe| stripe.devid == 0) {
            return Err(ParseError::InvalidField {
                field: "stripe_devid",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }

    /// Serialize the chunk body — header + stripes, no key — as a `CHUNK_ITEM`
    /// leaf value.
    ///
    /// # Errors
    /// As [`Self::validate`].
    pub fn to_item_bytes(&self) -> Result<Vec<u8>, ParseError> {
        self.validate()?;
        let mut buf = Vec::with_capacity(self.item_len());
        buf.extend_from_slice(&self.length.to_le_bytes());
        buf.extend_from_slice(&self.owner.to_le_bytes());
        buf.extend_from_slice(&self.stripe_len.to_le_bytes());
        buf.extend_from_slice(&self.chunk_type.to_le_bytes());
        buf.extend_from_slice(&self.io_align.to_le_bytes());
        buf.extend_from_slice(&self.io_width.to_le_bytes());
        buf.extend_from_slice(&self.sector_size.to_le_bytes());
        buf.extend_from_slice(&self.num_stripes.to_le_bytes());
        buf.extend_from_slice(&self.sub_stripes.to_le_bytes());
        for stripe in &self.stripes {
            buf.extend_from_slice(&stripe.devid.to_le_bytes());
            buf.extend_from_slice(&stripe.offset.to_le_bytes());
            buf.extend_from_slice(&stripe.dev_uuid);
        }
        Ok(buf)
    }

    /// Serialize as a `sys_chunk_array` entry: inline disk key followed by the
    /// chunk body.
    ///
    /// # Errors
    /// As [`Self::validate`], plus a key that `parse_sys_chunk_array` would
    /// reject — the array is read by the KERNEL before any tree is available, so
    /// a bad key here is an unmountable filesystem rather than a bad lookup.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ParseError> {
        if self.key.item_type != BTRFS_CHUNK_ITEM_KEY {
            return Err(ParseError::InvalidField {
                field: "sys_chunk_key_type",
                reason: "expected CHUNK_ITEM_KEY",
            });
        }
        if self.key.objectid != BTRFS_FIRST_CHUNK_TREE_OBJECTID {
            return Err(ParseError::InvalidField {
                field: "sys_chunk_key_objectid",
                reason: "expected first chunk tree objectid",
            });
        }
        let body = self.to_item_bytes()?;
        let mut buf = Vec::with_capacity(self.encoded_len());
        buf.extend_from_slice(&self.key.objectid.to_le_bytes());
        buf.push(self.key.item_type);
        buf.extend_from_slice(&self.key.offset.to_le_bytes());
        buf.extend_from_slice(&body);
        Ok(buf)
    }
}

// ── Device space accounting for chunk allocation (bd-a136s) ────────────────

/// The physical ranges of one device that existing chunks already occupy,
/// sorted and coalesced.
///
/// Allocating a new chunk means choosing a physical offset on a device that no
/// existing chunk covers. Getting that wrong does not fail loudly — it writes a
/// new chunk on top of a live one — so the derivation refuses every layout it
/// does not model exactly rather than approximating one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceOccupancy {
    ranges: Vec<(u64, u64)>,
}

impl DeviceOccupancy {
    /// Derive the occupied physical ranges of device `devid` from the chunk map.
    ///
    /// # Errors
    /// Returns [`ParseError::InvalidField`] for any chunk whose profile this does
    /// not model — every STRIPED profile (RAID0/10/5/6), where a stripe covers a
    /// FRACTION of the chunk length that depends on the profile and the stripe
    /// count. Assuming the mirror rule for those would understate each stripe's
    /// physical footprint and hand out space that is in use, so they are refused
    /// until they are modelled. Mirror profiles (Single, DUP, RAID1, RAID1C3,
    /// RAID1C4) all place a full `length` at every stripe, which is the case a
    /// single-device filesystem needs.
    pub fn from_chunks(devid: u64, chunks: &[BtrfsChunkEntry]) -> Result<Self, ParseError> {
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for chunk in chunks {
            let profile = BtrfsRaidProfile::from_chunk_type(chunk.chunk_type);
            match profile {
                BtrfsRaidProfile::Single
                | BtrfsRaidProfile::Dup
                | BtrfsRaidProfile::Raid1
                | BtrfsRaidProfile::Raid1C3
                | BtrfsRaidProfile::Raid1C4 => {}
                BtrfsRaidProfile::Raid0
                | BtrfsRaidProfile::Raid10
                | BtrfsRaidProfile::Raid5
                | BtrfsRaidProfile::Raid6 => {
                    return Err(ParseError::InvalidField {
                        field: "chunk_type",
                        reason: "striped profile: per-stripe physical length not modelled",
                    });
                }
            }
            for stripe in &chunk.stripes {
                if stripe.devid != devid {
                    continue;
                }
                // Validated, not stored: a stripe whose physical range overflows
                // the address space cannot be reasoned about, and treating it as
                // absent would make its bytes look free.
                stripe
                    .offset
                    .checked_add(chunk.length)
                    .ok_or(ParseError::InvalidField {
                        field: "stripe_offset",
                        reason: "physical range overflow",
                    })?;
                ranges.push((stripe.offset, chunk.length));
            }
        }
        ranges.sort_unstable();
        Ok(Self {
            ranges: coalesce_device_ranges(ranges),
        })
    }

    /// The occupied ranges, sorted by start and non-overlapping.
    #[must_use]
    pub fn ranges(&self) -> &[(u64, u64)] {
        &self.ranges
    }

    /// Total occupied bytes on the device.
    #[must_use]
    pub fn occupied_bytes(&self) -> u64 {
        self.ranges
            .iter()
            .fold(0_u64, |total, (_, len)| total.saturating_add(*len))
    }

    /// Lowest physical offset at or above `min_offset` where `length` contiguous
    /// bytes fit below `dev_total_bytes`, or `None` when the device has no such
    /// gap.
    ///
    /// `min_offset` fences off the device's reserved head — the superblock copies
    /// and the bootstrap region — which no chunk may overlap. `None` is the
    /// honest answer for "this device is full", and is what must turn into the
    /// caller's decision to fail rather than into a smaller chunk: a chunk
    /// shorter than asked for is a different allocation, not a fallback.
    #[must_use]
    pub fn find_free(&self, length: u64, min_offset: u64, dev_total_bytes: u64) -> Option<u64> {
        if length == 0 {
            return None;
        }
        let mut cursor = min_offset;
        for &(start, len) in &self.ranges {
            let end = start.checked_add(len)?;
            if end <= cursor {
                continue;
            }
            if start >= cursor {
                let gap = start.checked_sub(cursor)?;
                // The device bound is checked here too, not only on the tail: a
                // chunk that already runs past `dev_total_bytes` (a corrupt or
                // shrunk device) must not make the gap below it look usable.
                if gap >= length && cursor.checked_add(length)? <= dev_total_bytes {
                    return Some(cursor);
                }
            }
            cursor = cursor.max(end);
        }
        // The tail past the last occupied range.
        let tail_end = cursor.checked_add(length)?;
        if tail_end <= dev_total_bytes {
            Some(cursor)
        } else {
            None
        }
    }
}

/// Merge sorted, possibly overlapping physical ranges into disjoint ones.
///
/// Mirror profiles put two stripes of the SAME chunk on one device (DUP), and
/// nothing forbids two chunks from abutting, so the input can touch or overlap.
/// `find_free` walks the list assuming it is disjoint and ascending, which is
/// why this runs first.
fn coalesce_device_ranges(sorted: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(sorted.len());
    for (start, len) in sorted {
        if len == 0 {
            continue;
        }
        let Some(end) = start.checked_add(len) else {
            // A range that overflows the address space cannot be represented;
            // keeping it out of the map would make its bytes look free, so clamp
            // it to the end of the space instead.
            merged.push((start, u64::MAX - start));
            continue;
        };
        match merged.last_mut() {
            Some((prev_start, prev_len)) if start <= prev_start.saturating_add(*prev_len) => {
                let prev_end = prev_start.saturating_add(*prev_len);
                if end > prev_end {
                    *prev_len = end - *prev_start;
                }
            }
            _ => merged.push((start, len)),
        }
    }
    merged
}

// ── Tree node types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsKey {
    pub objectid: u64,
    pub item_type: u8,
    pub offset: u64,
}

fn btrfs_key_cmp(lhs: &BtrfsKey, rhs: &BtrfsKey) -> Ordering {
    lhs.objectid
        .cmp(&rhs.objectid)
        .then_with(|| lhs.item_type.cmp(&rhs.item_type))
        .then_with(|| lhs.offset.cmp(&rhs.offset))
}

fn validate_next_key(
    previous: Option<BtrfsKey>,
    current: BtrfsKey,
    field: &'static str,
    reason: &'static str,
) -> Result<(), ParseError> {
    if let Some(previous) = previous
        && btrfs_key_cmp(&previous, &current) != Ordering::Less
    {
        return Err(ParseError::InvalidField { field, reason });
    }
    Ok(())
}

fn parse_ordered_key(
    block: &[u8],
    base: usize,
    previous_key: &mut Option<BtrfsKey>,
    field: &'static str,
    reason: &'static str,
) -> Result<BtrfsKey, ParseError> {
    let key = BtrfsKey {
        objectid: read_le_u64(block, base)?,
        item_type: block[base + 8],
        offset: read_le_u64(block, base + 9)?,
    };
    validate_next_key(*previous_key, key, field, reason)?;
    *previous_key = Some(key);
    Ok(key)
}

fn checked_item_table_end(
    nritems: usize,
    item_size: usize,
    field: &'static str,
) -> Result<usize, ParseError> {
    let item_table_bytes = nritems
        .checked_mul(item_size)
        .ok_or(ParseError::InvalidField {
            field,
            reason: "overflow",
        })?;
    BTRFS_HEADER_SIZE
        .checked_add(item_table_bytes)
        .ok_or(ParseError::InvalidField {
            field,
            reason: "overflow",
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsHeader {
    pub csum: [u8; 32],
    pub fsid: [u8; 16],
    pub bytenr: u64,
    pub flags: u64,
    pub chunk_tree_uuid: [u8; 16],
    pub generation: u64,
    pub owner: u64,
    pub nritems: u32,
    pub level: u8,
}

impl BtrfsHeader {
    pub fn parse_from_block(block: &[u8]) -> Result<Self, ParseError> {
        if block.len() < BTRFS_HEADER_SIZE {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_HEADER_SIZE,
                offset: 0,
                actual: block.len(),
            });
        }

        Ok(Self {
            csum: read_fixed::<32>(block, 0x00)?,
            fsid: read_fixed::<16>(block, 0x20)?,
            bytenr: read_le_u64(block, 0x30)?,
            flags: read_le_u64(block, 0x38)?,
            chunk_tree_uuid: read_fixed::<16>(block, 0x40)?,
            generation: read_le_u64(block, 0x50)?,
            owner: read_le_u64(block, 0x58)?,
            nritems: read_le_u32(block, 0x60)?,
            level: block[0x64],
        })
    }

    /// Validate the header against the block it was parsed from.
    ///
    /// Checks:
    /// - `bytenr` matches `expected_bytenr` (if provided).
    /// - `nritems` fits within the block, considering item size (leaf vs internal).
    /// - `level` does not exceed `BTRFS_MAX_LEVEL`.
    pub fn validate(
        &self,
        block_size: usize,
        expected_bytenr: Option<u64>,
    ) -> Result<(), ParseError> {
        if let Some(expected) = expected_bytenr
            && self.bytenr != expected
        {
            return Err(ParseError::InvalidField {
                field: "bytenr",
                reason: "header bytenr does not match expected",
            });
        }

        if self.level > BTRFS_MAX_LEVEL {
            return Err(ParseError::InvalidField {
                field: "level",
                reason: "exceeds maximum tree depth",
            });
        }

        let payload_space = block_size.saturating_sub(BTRFS_HEADER_SIZE);
        let item_size = if self.level == 0 {
            BTRFS_ITEM_SIZE
        } else {
            BTRFS_KEY_PTR_SIZE
        };
        let max_items = payload_space / item_size;
        let nritems = usize::try_from(self.nritems)
            .map_err(|_| ParseError::IntegerConversion { field: "nritems" })?;

        if nritems > max_items {
            return Err(ParseError::InvalidField {
                field: "nritems",
                reason: "item count exceeds block capacity",
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsItem {
    pub key: BtrfsKey,
    /// Absolute byte offset of this item's payload within the block.
    ///
    /// On disk, btrfs leaf item offsets are stored relative to the 101-byte
    /// leaf header. The parser normalizes them to absolute block offsets so
    /// callers can slice payload bytes directly.
    pub data_offset: u32,
    pub data_size: u32,
}

/// An internal (non-leaf) node item: a key paired with a child block pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsKeyPtr {
    pub key: BtrfsKey,
    pub blockptr: u64,
    pub generation: u64,
}

/// A u64 mask with bits `[lo, hi)` set (`0 <= lo < hi <= 64`).
#[inline]
fn word_range_mask(lo: usize, hi: usize) -> u64 {
    let high = if hi >= 64 {
        u64::MAX
    } else {
        (1_u64 << hi) - 1
    };
    let low = (1_u64 << lo) - 1;
    high & !low
}

/// Test whether byte range `[start, end)` intersects any already-set bit in the
/// coverage bitset; if it does not, set the range and return `false`. Returns
/// `true` on the first intersection without mutating the bitset. `start < end`
/// and the range must lie within `bits.len() * 64`.
fn payload_range_collides(bits: &mut [u64], start: usize, end: usize) -> bool {
    let first_word = start / 64;
    let last_word = (end - 1) / 64;
    let first_mask = word_range_mask(start % 64, 64);
    let last_mask = word_range_mask(0, (end - 1) % 64 + 1);

    if first_word == last_word {
        let mask = first_mask & last_mask;
        if bits[first_word] & mask != 0 {
            return true;
        }
        bits[first_word] |= mask;
        return false;
    }

    // Check every covered word before mutating any, so a collision leaves the
    // bitset untouched (the caller errors out immediately).
    if bits[first_word] & first_mask != 0 || bits[last_word] & last_mask != 0 {
        return true;
    }
    if bits[first_word + 1..last_word].iter().any(|&w| w != 0) {
        return true;
    }

    bits[first_word] |= first_mask;
    bits[last_word] |= last_mask;
    for word in &mut bits[first_word + 1..last_word] {
        *word = u64::MAX;
    }
    false
}

fn seed_payload_coverage_from_items(
    bits: &mut [u64],
    items: &[BtrfsItem],
) -> Result<(), ParseError> {
    for item in items {
        let size = usize::try_from(item.data_size)
            .map_err(|_| ParseError::IntegerConversion { field: "item_size" })?;
        if size == 0 {
            continue;
        }
        let start =
            usize::try_from(item.data_offset).map_err(|_| ParseError::IntegerConversion {
                field: "item_offset",
            })?;
        let end = start.checked_add(size).ok_or(ParseError::InvalidField {
            field: "item_offset",
            reason: "overflow",
        })?;
        if payload_range_collides(bits, start, end) {
            return Err(ParseError::InvalidField {
                field: "item_offset",
                reason: "item payload overlaps another item",
            });
        }
    }
    Ok(())
}

pub fn parse_leaf_items(block: &[u8]) -> Result<(BtrfsHeader, Vec<BtrfsItem>), ParseError> {
    let header = BtrfsHeader::parse_from_block(block)?;
    if header.level != 0 {
        return Err(ParseError::InvalidField {
            field: "level",
            reason: "expected leaf level 0",
        });
    }

    header.validate(block.len(), None)?;

    let nritems = usize::try_from(header.nritems)
        .map_err(|_| ParseError::IntegerConversion { field: "nritems" })?;

    let items_end = checked_item_table_end(nritems, BTRFS_ITEM_SIZE, "items")?;

    if block.len() < items_end {
        return Err(ParseError::InsufficientData {
            needed: items_end,
            offset: BTRFS_HEADER_SIZE,
            actual: block.len().saturating_sub(BTRFS_HEADER_SIZE),
        });
    }

    // Kernel-written leaves pack payloads monotonically downward from the block
    // end. Track that canonical shape with O(1) state and lazily allocate the
    // byte-granular coverage bitset only if a noncanonical payload order appears.
    // The fallback replays already accepted items into the same exact bitset
    // checker, so arbitrary valid/invalid leaves keep the old overlap semantics.
    let mut payload_coverage: Option<Vec<u64>> = None;
    let mut lowest_payload_start = block.len();
    let mut items: Vec<BtrfsItem> = Vec::with_capacity(nritems);
    let mut previous_key = None;
    let item_table = &block[BTRFS_HEADER_SIZE..items_end];
    let (item_rows, _) = item_table.as_chunks::<BTRFS_ITEM_SIZE>();
    for item in item_rows {
        let key = parse_ordered_key(
            item,
            0,
            &mut previous_key,
            "item_key",
            "leaf item keys not strictly increasing",
        )?;

        // On disk, leaf payload offsets are relative to the leaf header. Normalize
        // them to absolute block offsets for callers.
        let raw_data_offset = read_le_u32(item, 17)?;
        let header_size =
            u32::try_from(BTRFS_HEADER_SIZE).map_err(|_| ParseError::IntegerConversion {
                field: "header_size",
            })?;
        let data_offset =
            raw_data_offset
                .checked_add(header_size)
                .ok_or(ParseError::InvalidField {
                    field: "item_offset",
                    reason: "overflow",
                })?;
        let data_size = read_le_u32(item, 21)?;

        let data_offset_usize =
            usize::try_from(data_offset).map_err(|_| ParseError::IntegerConversion {
                field: "item_offset",
            })?;
        let data_size_usize = usize::try_from(data_size)
            .map_err(|_| ParseError::IntegerConversion { field: "item_size" })?;
        if data_offset_usize < items_end {
            return Err(ParseError::InvalidField {
                field: "item_offset",
                reason: "item payload overlaps header/item table",
            });
        }
        let data_end =
            data_offset_usize
                .checked_add(data_size_usize)
                .ok_or(ParseError::InvalidField {
                    field: "item_offset",
                    reason: "overflow",
                })?;

        if data_end > block.len() {
            return Err(ParseError::InvalidField {
                field: "item_offset",
                reason: "item points outside block",
            });
        }

        if data_size_usize > 0 {
            if let Some(coverage) = payload_coverage.as_mut() {
                if payload_range_collides(coverage, data_offset_usize, data_end) {
                    return Err(ParseError::InvalidField {
                        field: "item_offset",
                        reason: "item payload overlaps another item",
                    });
                }
            } else if data_end <= lowest_payload_start {
                lowest_payload_start = data_offset_usize;
            } else {
                let mut coverage = vec![0_u64; block.len().div_ceil(64)];
                seed_payload_coverage_from_items(&mut coverage, &items)?;
                if payload_range_collides(&mut coverage, data_offset_usize, data_end) {
                    return Err(ParseError::InvalidField {
                        field: "item_offset",
                        reason: "item payload overlaps another item",
                    });
                }
                payload_coverage = Some(coverage);
            }
        }

        items.push(BtrfsItem {
            key,
            data_offset,
            data_size,
        });
    }

    Ok((header, items))
}

/// Parse a btrfs internal (non-leaf) node, returning the header and key-pointer items.
///
/// Internal nodes (level > 0) contain `btrfs_key_ptr` entries that point
/// to child blocks. Each entry is 33 bytes: key (17) + blockptr (8) + generation (8).
pub fn parse_internal_items(block: &[u8]) -> Result<(BtrfsHeader, Vec<BtrfsKeyPtr>), ParseError> {
    let header = BtrfsHeader::parse_from_block(block)?;
    if header.level == 0 {
        return Err(ParseError::InvalidField {
            field: "level",
            reason: "expected internal node (level > 0)",
        });
    }

    header.validate(block.len(), None)?;

    let nritems = usize::try_from(header.nritems)
        .map_err(|_| ParseError::IntegerConversion { field: "nritems" })?;

    let table_end = checked_item_table_end(nritems, BTRFS_KEY_PTR_SIZE, "key_ptrs")?;

    if block.len() < table_end {
        return Err(ParseError::InsufficientData {
            needed: table_end,
            offset: BTRFS_HEADER_SIZE,
            actual: block.len().saturating_sub(BTRFS_HEADER_SIZE),
        });
    }

    let mut ptrs = Vec::with_capacity(nritems);
    let mut previous_key = None;
    let key_ptr_table = &block[BTRFS_HEADER_SIZE..table_end];
    let (key_ptr_rows, _) = key_ptr_table.as_chunks::<BTRFS_KEY_PTR_SIZE>();
    for key_ptr in key_ptr_rows {
        let key = parse_ordered_key(
            key_ptr,
            0,
            &mut previous_key,
            "key_ptrs.key",
            "internal item keys not strictly increasing",
        )?;

        let blockptr = read_le_u64(key_ptr, 17)?;
        let generation = read_le_u64(key_ptr, 25)?;

        if blockptr == 0 {
            return Err(ParseError::InvalidField {
                field: "blockptr",
                reason: "child block pointer is zero",
            });
        }

        ptrs.push(BtrfsKeyPtr {
            key,
            blockptr,
            generation,
        });
    }

    Ok((header, ptrs))
}

// ── Checksum verification ───────────────────────────────────────────────────

/// Verify the CRC32C checksum of a btrfs superblock.
///
/// The checksum covers `region[0x20..]` (everything after the 32-byte `csum`
/// field). The expected checksum is stored as a little-endian u32 in
/// `region[0..4]`.
///
/// Only CRC32C (`csum_type == 0`) is currently supported. Other algorithms
/// return an error.
pub fn verify_superblock_checksum(region: &[u8]) -> Result<(), ParseError> {
    if region.len() < BTRFS_SUPER_INFO_SIZE {
        return Err(ParseError::InsufficientData {
            needed: BTRFS_SUPER_INFO_SIZE,
            offset: 0,
            actual: region.len(),
        });
    }

    validate_supported_csum_type(read_le_u16(region, 0xC4)?)?;

    let stored = read_le_u32(region, 0)?;
    let computed = crc32c::crc32c(&region[0x20..BTRFS_SUPER_INFO_SIZE]);

    if stored != computed {
        return Err(ParseError::InvalidField {
            field: "superblock_csum",
            reason: "CRC32C checksum mismatch",
        });
    }

    Ok(())
}

/// Verify the CRC32C checksum of a btrfs tree block (leaf or internal node).
///
/// The checksum covers `block[0x20..block.len()]` (everything after the
/// 32-byte `csum` field in the header). The expected checksum is stored as a
/// little-endian u32 in `block[0..4]`.
///
/// Only CRC32C (`csum_type == 0`) is currently supported.
pub fn verify_tree_block_checksum(block: &[u8], csum_type: u16) -> Result<(), ParseError> {
    if block.len() < BTRFS_HEADER_SIZE {
        return Err(ParseError::InsufficientData {
            needed: BTRFS_HEADER_SIZE,
            offset: 0,
            actual: block.len(),
        });
    }

    validate_supported_csum_type(csum_type)?;

    let stored = read_le_u32(block, 0)?;
    let computed = crc32c::crc32c(&block[0x20..]);

    if stored != computed {
        return Err(ParseError::InvalidField {
            field: "tree_block_csum",
            reason: "CRC32C checksum mismatch",
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn set_valid_superblock_device_accounting(sb: &mut [u8]) {
        sb[0x70..0x78].copy_from_slice(&1_000_000_u64.to_le_bytes());
        sb[0x78..0x80].copy_from_slice(&123_456_u64.to_le_bytes());
        sb[0x88..0x90].copy_from_slice(&1_u64.to_le_bytes());
    }

    #[test]
    fn parse_superblock_smoke() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x30..0x38].copy_from_slice(&(BTRFS_SUPER_INFO_OFFSET as u64).to_le_bytes());
        sb[0x48..0x50].copy_from_slice(&9_u64.to_le_bytes());
        sb[0x50..0x58].copy_from_slice(&4096_u64.to_le_bytes());
        sb[0x58..0x60].copy_from_slice(&8192_u64.to_le_bytes());
        sb[0x60..0x68].copy_from_slice(&12288_u64.to_le_bytes());
        sb[0xA4..0xAC].copy_from_slice(&11_u64.to_le_bytes());
        sb[0x70..0x78].copy_from_slice(&1_000_000_u64.to_le_bytes());
        sb[0x78..0x80].copy_from_slice(&123_456_u64.to_le_bytes());
        sb[0x80..0x88].copy_from_slice(&6_u64.to_le_bytes());
        sb[0x88..0x90].copy_from_slice(&1_u64.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&65536_u32.to_le_bytes());
        sb[0xC4..0xC6].copy_from_slice(&ffs_types::BTRFS_CSUM_TYPE_CRC32C.to_le_bytes());
        sb[0xC6] = 0;
        sb[0xC7] = 1;
        sb[0xC8] = 2;
        sb[BTRFS_SUPER_LABEL_OFFSET..BTRFS_SUPER_LABEL_OFFSET + 3].copy_from_slice(b"ffs");

        let parsed = BtrfsSuperblock::parse_superblock_region(&sb).expect("superblock parse");
        assert_eq!(parsed.magic, BTRFS_MAGIC);
        assert_eq!(parsed.generation, 9);
        assert_eq!(parsed.chunk_root_generation, 11);
        assert_eq!(parsed.sectorsize, 4096);
        assert_eq!(parsed.nodesize, 16384);
        assert_eq!(parsed.csum_type, ffs_types::BTRFS_CSUM_TYPE_CRC32C);
        assert_eq!(parsed.label, "ffs");
    }

    #[test]
    fn superblock_to_bytes_roundtrip_preserves_chunk_root_generation() {
        let sb = BtrfsSuperblock {
            csum: [0; 32],
            fsid: [0x11; 16],
            bytenr: BTRFS_SUPER_INFO_OFFSET as u64,
            flags: 0,
            magic: BTRFS_MAGIC,
            generation: 100,
            root: 0x10000,
            chunk_root: 0x20000,
            chunk_root_generation: 77,
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
            label: "testfs".to_string(),
            sys_chunk_array_size: 0,
            sys_chunk_array: vec![],
        };
        let serialized = sb.to_bytes();
        assert_eq!(serialized.len(), BTRFS_SUPER_INFO_SIZE);

        verify_superblock_checksum(&serialized).expect("checksum valid");
        let parsed =
            BtrfsSuperblock::parse_superblock_region(&serialized).expect("roundtrip parse");
        assert_eq!(parsed.fsid, sb.fsid);
        assert_eq!(parsed.generation, sb.generation);
        assert_eq!(parsed.root, sb.root);
        assert_eq!(parsed.chunk_root, sb.chunk_root);
        assert_eq!(parsed.chunk_root_generation, sb.chunk_root_generation);
        assert_eq!(
            u64::from_le_bytes(serialized[0xA4..0xAC].try_into().expect("chunk root gen")),
            sb.chunk_root_generation
        );
        assert_eq!(parsed.sectorsize, sb.sectorsize);
        assert_eq!(parsed.nodesize, sb.nodesize);
        assert_eq!(parsed.label, sb.label);
    }

    #[test]
    fn superblock_patch_commit_updates_fields() {
        let sb = BtrfsSuperblock {
            csum: [0; 32],
            fsid: [0x22; 16],
            bytenr: BTRFS_SUPER_INFO_OFFSET as u64,
            flags: 0,
            magic: BTRFS_MAGIC,
            generation: 50,
            root: 0x1000,
            chunk_root: 0x2000,
            chunk_root_generation: 50,
            log_root: 0,
            total_bytes: 1_000_000_000,
            bytes_used: 100_000,
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
            chunk_root_level: 0,
            log_root_level: 0,
            label: String::new(),
            sys_chunk_array_size: 0,
            sys_chunk_array: vec![],
        };
        let mut data = sb.to_bytes();

        BtrfsSuperblock::patch_commit(&mut data, 0x3000, 1, 100);
        verify_superblock_checksum(&data).expect("patched checksum valid");
        let patched = BtrfsSuperblock::parse_superblock_region(&data).expect("parse patched");
        assert_eq!(patched.root, 0x3000);
        assert_eq!(patched.root_level, 1);
        assert_eq!(patched.generation, 100);
        assert_eq!(patched.chunk_root_generation, 100);
        assert_eq!(patched.fsid, sb.fsid);
    }

    /// bd-a136s. The chunk writer must reproduce, BYTE FOR BYTE, the on-disk
    /// entry the parser read.
    ///
    /// This is the strongest check available without a mount, and it is stronger
    /// than a struct round-trip (`to_bytes` then parse, compare fields): that
    /// direction passes even if writer and parser share the same wrong offset,
    /// because the error cancels. Starting from BYTES that the existing parser
    /// already accepts, and requiring the writer to reproduce them exactly,
    /// cannot cancel — a swapped field or a wrong offset moves a byte.
    ///
    /// The fixture is the crate's own representative superblock, so these are the
    /// bytes a real `sys_chunk_array` carries.
    #[test]
    fn chunk_entry_writer_reproduces_the_bytes_it_parsed_bd_a136s() {
        let sb = BtrfsSuperblock::parse_superblock_region(&representative_sys_chunk_superblock())
            .expect("sb parse");
        let original = &sb.sys_chunk_array[..97];
        let entries = parse_sys_chunk_array(original).expect("chunk parse");
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];

        assert_eq!(
            entry.encoded_len(),
            97,
            "disk key (17) + chunk header (48) + one stripe (32)"
        );
        let written = entry.to_bytes().expect("serialize");
        assert_eq!(
            written,
            original,
            "the sys_chunk_array entry must serialize back to the bytes it was read from"
        );

        // The item form is the same bytes without the leading 17-byte disk key —
        // that difference is the whole reason there are two forms, so it is
        // asserted rather than assumed.
        let item = entry.to_item_bytes().expect("serialize item");
        assert_eq!(item.len(), entry.item_len());
        assert_eq!(
            item,
            &original[BTRFS_DISK_KEY_SIZE..],
            "the CHUNK_ITEM leaf value is the entry without its inline key"
        );
    }

    /// bd-a136s. A writer that can emit bytes its own parser rejects is a silent
    /// corruption generator: nothing reads a chunk back until the kernel mounts
    /// the filesystem, at which point the failure is "not a btrfs filesystem".
    /// So every invariant the parser enforces is enforced on the way out too.
    #[test]
    fn chunk_entry_writer_refuses_what_its_parser_would_reject_bd_a136s() {
        let sb = BtrfsSuperblock::parse_superblock_region(&representative_sys_chunk_superblock())
            .expect("sb parse");
        let good = parse_sys_chunk_array(&sb.sys_chunk_array[..97]).expect("chunk parse")[0].clone();
        good.to_bytes().expect("the fixture must serialize");

        // A stripe count that disagrees with the stripe list. Writing
        // `stripes.len()` over the field would "work" and hide the caller's bug
        // in a structure nothing reads back until mount.
        let mut mismatched = good.clone();
        mismatched.num_stripes = 2;
        assert!(
            mismatched.to_bytes().is_err(),
            "num_stripes disagreeing with the stripe list must be refused, not silently corrected"
        );

        let mut zero_length = good.clone();
        zero_length.length = 0;
        assert!(zero_length.to_bytes().is_err(), "a zero-length chunk backs nothing");

        let mut zero_stripe_len = good.clone();
        zero_stripe_len.stripe_len = 0;
        assert!(zero_stripe_len.to_bytes().is_err(), "a zero stripe_len divides by zero");

        // Two RAID profile bits at once — the parser rejects it, so the writer
        // must not be able to create it.
        let mut two_profiles = good.clone();
        two_profiles.chunk_type |= chunk_type_flags::RAID_MASK;
        assert!(
            two_profiles.to_bytes().is_err(),
            "multiple RAID profile bits must be refused"
        );

        let mut zero_devid = good.clone();
        zero_devid.stripes[0].devid = 0;
        assert!(zero_devid.to_bytes().is_err(), "a stripe must name a device");

        // The key is only inline in the sys_chunk_array, and the KERNEL reads
        // that array before any tree is available — a bad key here is an
        // unmountable filesystem, not a failed lookup. The item form carries no
        // key, so it must still succeed for the same entry.
        let mut wrong_key = good.clone();
        wrong_key.key.item_type = BTRFS_CHUNK_ITEM_KEY.wrapping_add(1);
        assert!(wrong_key.to_bytes().is_err(), "a non-CHUNK_ITEM key must be refused");
        wrong_key
            .to_item_bytes()
            .expect("the item form carries no key and must still serialize");
    }

    /// bd-a136s. `DEV_EXTENT` is the reverse map of a chunk — the physical range
    /// on a device, filed under the device. `btrfs check` cross-checks it against
    /// the chunk's stripes, so a chunk allocation that writes one and not the
    /// other produces "chunk ... is not found in dev extent".
    #[test]
    fn dev_extent_round_trips_through_its_own_parser_bd_a136s() {
        let extent = BtrfsDevExtent {
            chunk_tree: 3,
            chunk_objectid: BTRFS_FIRST_CHUNK_TREE_OBJECTID,
            chunk_offset: 0x100_0000,
            length: 8 * 1024 * 1024,
            chunk_tree_uuid: [0x5A; 16],
        };
        let bytes = extent.to_bytes().expect("serialize");
        assert_eq!(bytes.len(), BTRFS_DEV_EXTENT_SIZE);
        assert_eq!(parse_dev_extent(&bytes).expect("parse"), extent);

        // Byte-level pinning of the layout, so a field reordering is caught here
        // rather than by a kernel that will not mount the result.
        assert_eq!(&bytes[0..8], &3_u64.to_le_bytes()[..]);
        assert_eq!(&bytes[16..24], &0x100_0000_u64.to_le_bytes()[..]);
        assert_eq!(&bytes[24..32], &(8 * 1024 * 1024_u64).to_le_bytes()[..]);
        assert_eq!(&bytes[32..48], &[0x5A_u8; 16][..]);

        let mut zero_len = extent;
        zero_len.length = 0;
        assert!(zero_len.to_bytes().is_err(), "a zero-length dev extent backs nothing");

        let mut short = [0_u8; BTRFS_DEV_EXTENT_SIZE - 1];
        assert!(
            extent.write_to_bytes(&mut short).is_err(),
            "a short buffer must be refused, not partially written"
        );
    }

    /// bd-a136s. The DEV_ITEM writer exists so a chunk allocation can raise
    /// `bytes_used` by the chunk's device footprint. That is the one field it
    /// mutates and the one that can be got wrong, so the `bytes_used <=
    /// total_bytes` invariant is enforced on the way out, exactly as
    /// `parse_dev_item` enforces it on the way in.
    #[test]
    fn dev_item_writer_round_trips_and_bounds_bytes_used_bd_a136s() {
        let item = BtrfsDevItem {
            devid: 1,
            total_bytes: 512 * 1024 * 1024,
            bytes_used: 64 * 1024 * 1024,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            dev_type: 0,
            generation: 7,
            start_offset: 0,
            dev_group: 0,
            seek_speed: 10,
            bandwidth: 20,
            uuid: [0xA5; 16],
            fsid: [0x3C; 16],
        };
        let mut buf = [0_u8; BTRFS_DEV_ITEM_SIZE];
        item.write_to_bytes(&mut buf).expect("serialize");
        assert_eq!(parse_dev_item(&buf).expect("parse"), item);

        // Growing the filesystem raises bytes_used; it must never pass
        // total_bytes, which would claim more of the device than exists.
        let mut overcommitted = item.clone();
        overcommitted.bytes_used = item.total_bytes + 1;
        assert!(
            overcommitted.write_to_bytes(&mut buf).is_err(),
            "bytes_used past total_bytes must be refused — this is the field a chunk \
             allocation mutates"
        );

        // Exactly full is legal: a device with no unallocated space left is a
        // valid device, and refusing it would refuse the last chunk.
        let mut exactly_full = item.clone();
        exactly_full.bytes_used = item.total_bytes;
        exactly_full
            .write_to_bytes(&mut buf)
            .expect("a fully allocated device is valid");
    }

    fn chunk_at(logical: u64, length: u64, chunk_type: u64, stripes: &[(u64, u64)]) -> BtrfsChunkEntry {
        BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: BTRFS_FIRST_CHUNK_TREE_OBJECTID,
                item_type: BTRFS_CHUNK_ITEM_KEY,
                offset: logical,
            },
            length,
            owner: 2,
            stripe_len: 65536,
            chunk_type,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: u16::try_from(stripes.len()).expect("stripe count fits"),
            sub_stripes: 0,
            stripes: stripes
                .iter()
                .map(|&(devid, offset)| BtrfsStripe {
                    devid,
                    offset,
                    dev_uuid: [0; 16],
                })
                .collect(),
        }
    }

    /// bd-a136s. A chunk allocation picks a physical offset on a device, and
    /// picking one that an existing chunk already covers does not fail loudly —
    /// it writes a new chunk on top of a live one. So the gap finder is asserted
    /// against overlap directly, not just for plausible answers.
    #[test]
    fn device_occupancy_finds_a_gap_that_overlaps_nothing_bd_a136s() {
        use chunk_type_flags::{BTRFS_BLOCK_GROUP_DATA, BTRFS_BLOCK_GROUP_METADATA};
        const MB: u64 = 1024 * 1024;

        // Two chunks on device 1 with a 4 MiB hole between them, and one chunk on
        // a different device that must be ignored entirely.
        let chunks = vec![
            chunk_at(0, 8 * MB, BTRFS_BLOCK_GROUP_METADATA, &[(1, MB)]),
            chunk_at(8 * MB, 8 * MB, BTRFS_BLOCK_GROUP_DATA, &[(1, 13 * MB)]),
            chunk_at(16 * MB, 8 * MB, BTRFS_BLOCK_GROUP_DATA, &[(2, MB)]),
        ];
        let occ = DeviceOccupancy::from_chunks(1, &chunks).expect("derive");
        assert_eq!(
            occ.ranges(),
            &[(MB, 8 * MB), (13 * MB, 8 * MB)][..],
            "device 2's chunk must not appear in device 1's occupancy"
        );
        assert_eq!(occ.occupied_bytes(), 16 * MB);

        // A 4 MiB request fits exactly in the hole at 9 MiB.
        assert_eq!(occ.find_free(4 * MB, 0, 64 * MB), Some(9 * MB));
        // A 5 MiB request does not fit the hole and must go past the tail.
        assert_eq!(occ.find_free(5 * MB, 0, 64 * MB), Some(21 * MB));

        // Whatever it returns must overlap nothing — asserted mechanically,
        // because "looks right" is how an off-by-one gets committed here.
        for length in [MB, 3 * MB, 4 * MB, 5 * MB, 16 * MB] {
            let Some(offset) = occ.find_free(length, 0, 64 * MB) else {
                continue;
            };
            let end = offset + length;
            for &(start, len) in occ.ranges() {
                assert!(
                    end <= start || offset >= start + len,
                    "allocation [{offset}, {end}) overlaps live chunk [{start}, {})",
                    start + len
                );
            }
            assert!(end <= 64 * MB, "allocation must stay on the device");
        }
    }

    /// bd-a136s. `min_offset` fences off the device's reserved head — superblock
    /// copies and the bootstrap region — and the device bound fences off the
    /// tail. Both are the difference between a valid filesystem and one the
    /// kernel refuses to mount.
    #[test]
    fn device_occupancy_respects_the_reserved_head_and_the_device_end_bd_a136s() {
        use chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA;
        const MB: u64 = 1024 * 1024;

        let empty = DeviceOccupancy::from_chunks(1, &[]).expect("derive");
        assert!(empty.ranges().is_empty());
        assert_eq!(empty.occupied_bytes(), 0);
        // An empty device still may not allocate below the reserved head.
        assert_eq!(empty.find_free(8 * MB, MB, 64 * MB), Some(MB));
        // Exactly filling the device is legal; one byte more is not.
        assert_eq!(empty.find_free(63 * MB, MB, 64 * MB), Some(MB));
        assert_eq!(empty.find_free(63 * MB + 1, MB, 64 * MB), None);
        // A zero-length chunk backs nothing and is never an answer.
        assert_eq!(empty.find_free(0, MB, 64 * MB), None);

        // A device with no room left reports None rather than a smaller offset:
        // a chunk shorter than asked for is a different allocation, not a
        // fallback, and silently shrinking it would corrupt the caller's sizing.
        let full = DeviceOccupancy::from_chunks(
            1,
            &[chunk_at(0, 63 * MB, BTRFS_BLOCK_GROUP_METADATA, &[(1, MB)])],
        )
        .expect("derive");
        assert_eq!(full.find_free(MB, MB, 64 * MB), None);
    }

    /// bd-a136s. DUP puts two stripes of the SAME chunk on ONE device, so a
    /// device's occupancy list can contain touching or overlapping ranges before
    /// it is coalesced — and `find_free` walks it assuming disjoint ascending
    /// ranges. This is the case that makes the coalescing load-bearing rather
    /// than tidy.
    #[test]
    fn device_occupancy_coalesces_dup_and_abutting_chunks_bd_a136s() {
        use chunk_type_flags::{BTRFS_BLOCK_GROUP_DUP, BTRFS_BLOCK_GROUP_METADATA};
        const MB: u64 = 1024 * 1024;

        // DUP: one chunk, two stripes on device 1, and they abut.
        let dup = chunk_at(
            0,
            8 * MB,
            BTRFS_BLOCK_GROUP_METADATA | BTRFS_BLOCK_GROUP_DUP,
            &[(1, MB), (1, 9 * MB)],
        );
        // A second chunk starting exactly where the DUP copies end.
        let abutting = chunk_at(8 * MB, 4 * MB, BTRFS_BLOCK_GROUP_METADATA, &[(1, 17 * MB)]);

        let occ = DeviceOccupancy::from_chunks(1, &[dup, abutting]).expect("derive");
        assert_eq!(
            occ.ranges(),
            &[(MB, 20 * MB)][..],
            "two abutting DUP stripes plus an abutting chunk are one contiguous run"
        );
        assert_eq!(occ.find_free(4 * MB, 0, 64 * MB), Some(21 * MB));
    }

    /// bd-a136s. A striped profile puts a FRACTION of the chunk length on each
    /// device, and the fraction depends on the profile and the stripe count.
    /// Applying the mirror rule to one would understate its physical footprint
    /// and hand out space that is in use — a silent overwrite of live data — so
    /// the unmodelled profiles are refused, not approximated.
    #[test]
    fn device_occupancy_refuses_striped_profiles_it_does_not_model_bd_a136s() {
        use chunk_type_flags::{
            BTRFS_BLOCK_GROUP_DATA, BTRFS_BLOCK_GROUP_RAID0, BTRFS_BLOCK_GROUP_RAID10,
            BTRFS_BLOCK_GROUP_RAID5, BTRFS_BLOCK_GROUP_RAID6,
        };
        const MB: u64 = 1024 * 1024;

        for profile in [
            BTRFS_BLOCK_GROUP_RAID0,
            BTRFS_BLOCK_GROUP_RAID10,
            BTRFS_BLOCK_GROUP_RAID5,
            BTRFS_BLOCK_GROUP_RAID6,
        ] {
            let chunk = chunk_at(
                0,
                8 * MB,
                BTRFS_BLOCK_GROUP_DATA | profile,
                &[(1, MB), (2, MB)],
            );
            assert!(
                DeviceOccupancy::from_chunks(1, &[chunk]).is_err(),
                "striped profile {profile:#x} must be refused until its per-stripe \
                 length is modelled — approximating it hands out live space"
            );
        }
    }

    fn representative_sys_chunk_superblock() -> [u8; BTRFS_SUPER_INFO_SIZE] {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        set_valid_superblock_device_accounting(&mut sb);
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&65536_u32.to_le_bytes());
        sb[BTRFS_SUPER_LABEL_OFFSET..BTRFS_SUPER_LABEL_OFFSET + 4].copy_from_slice(b"gold");

        // Build a sys_chunk_array entry: disk_key (17) + chunk_fixed (48) + 1 stripe (32) = 97.
        let entry_size: u32 = 97;
        sb[0xA0..0xA4].copy_from_slice(&entry_size.to_le_bytes());

        let base = BTRFS_SYS_CHUNK_ARRAY_OFFSET;
        // disk_key: objectid=256, type=228 (CHUNK_ITEM_KEY), offset=16 MiB.
        sb[base..base + 8].copy_from_slice(&256_u64.to_le_bytes());
        sb[base + 8] = 228;
        sb[base + 9..base + 17].copy_from_slice(&0x100_0000_u64.to_le_bytes());

        // chunk: length=8 MiB, owner=2, stripe_len=64 KiB, type=2 (SYSTEM).
        let c = base + 17;
        sb[c..c + 8].copy_from_slice(&(8 * 1024 * 1024_u64).to_le_bytes());
        sb[c + 8..c + 16].copy_from_slice(&2_u64.to_le_bytes());
        sb[c + 16..c + 24].copy_from_slice(&(64 * 1024_u64).to_le_bytes());
        sb[c + 24..c + 32].copy_from_slice(&2_u64.to_le_bytes());
        sb[c + 32..c + 36].copy_from_slice(&4096_u32.to_le_bytes());
        sb[c + 36..c + 40].copy_from_slice(&4096_u32.to_le_bytes());
        sb[c + 40..c + 44].copy_from_slice(&4096_u32.to_le_bytes());
        sb[c + 44..c + 46].copy_from_slice(&1_u16.to_le_bytes());
        sb[c + 46..c + 48].copy_from_slice(&0_u16.to_le_bytes());

        // stripe: devid=1, physical offset=2 MiB, uuid=zeros.
        let s = c + 48;
        sb[s..s + 8].copy_from_slice(&1_u64.to_le_bytes());
        sb[s + 8..s + 16].copy_from_slice(&0x20_0000_u64.to_le_bytes());
        sb
    }

    #[test]
    fn superblock_sys_chunk_array_parsed() {
        let parsed =
            BtrfsSuperblock::parse_superblock_region(&representative_sys_chunk_superblock())
                .expect("sb parse");
        assert_eq!(parsed.sys_chunk_array_size, 97);
        assert_eq!(parsed.sys_chunk_array.len(), 97);

        let entries = parse_sys_chunk_array(&parsed.sys_chunk_array).expect("chunk parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key.objectid, 256);
        assert_eq!(entries[0].key.item_type, 228);
        assert_eq!(entries[0].key.offset, 0x100_0000);
        assert_eq!(entries[0].length, 8 * 1024 * 1024);
        assert_eq!(entries[0].num_stripes, 1);
        assert_eq!(entries[0].stripes[0].devid, 1);
        assert_eq!(entries[0].stripes[0].offset, 0x20_0000);
    }

    #[test]
    fn representative_sys_chunk_mapping_exact_golden_contract() {
        let parsed =
            BtrfsSuperblock::parse_superblock_region(&representative_sys_chunk_superblock())
                .expect("sb parse");
        let entries = parse_sys_chunk_array(&parsed.sys_chunk_array).expect("chunk parse");
        let entry = &entries[0];
        let mapping = map_logical_to_physical(&entries, 0x108_0000)
            .expect("mapping should succeed")
            .expect("should find a mapping");

        let actual = format!(
            concat!(
                "superblock\n",
                "  label={}\n",
                "  sectorsize={}\n",
                "  nodesize={}\n",
                "  stripesize={}\n",
                "  sys_chunk_array_size={}\n",
                "entry\n",
                "  key.objectid={}\n",
                "  key.item_type={}\n",
                "  key.offset_hex=0x{:x}\n",
                "  length_hex=0x{:x}\n",
                "  owner={}\n",
                "  stripe_len_hex=0x{:x}\n",
                "  chunk_type={}\n",
                "  io_align={}\n",
                "  io_width={}\n",
                "  sector_size={}\n",
                "  num_stripes={}\n",
                "  sub_stripes={}\n",
                "  first_stripe.devid={}\n",
                "  first_stripe.offset_hex=0x{:x}\n",
                "lookup\n",
                "  logical_hex=0x1080000\n",
                "  mapping.devid={}\n",
                "  mapping.physical_hex=0x{:x}"
            ),
            parsed.label,
            parsed.sectorsize,
            parsed.nodesize,
            parsed.stripesize,
            parsed.sys_chunk_array_size,
            entry.key.objectid,
            entry.key.item_type,
            entry.key.offset,
            entry.length,
            entry.owner,
            entry.stripe_len,
            entry.chunk_type,
            entry.io_align,
            entry.io_width,
            entry.sector_size,
            entry.num_stripes,
            entry.sub_stripes,
            entry.stripes[0].devid,
            entry.stripes[0].offset,
            mapping.devid,
            mapping.physical,
        );

        assert_eq!(
            actual,
            concat!(
                "superblock\n",
                "  label=gold\n",
                "  sectorsize=4096\n",
                "  nodesize=16384\n",
                "  stripesize=65536\n",
                "  sys_chunk_array_size=97\n",
                "entry\n",
                "  key.objectid=256\n",
                "  key.item_type=228\n",
                "  key.offset_hex=0x1000000\n",
                "  length_hex=0x800000\n",
                "  owner=2\n",
                "  stripe_len_hex=0x10000\n",
                "  chunk_type=2\n",
                "  io_align=4096\n",
                "  io_width=4096\n",
                "  sector_size=4096\n",
                "  num_stripes=1\n",
                "  sub_stripes=0\n",
                "  first_stripe.devid=1\n",
                "  first_stripe.offset_hex=0x200000\n",
                "lookup\n",
                "  logical_hex=0x1080000\n",
                "  mapping.devid=1\n",
                "  mapping.physical_hex=0x280000"
            )
        );
    }

    #[test]
    fn superblock_rejects_non_power_of_two_sectorsize() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&3000_u32.to_le_bytes()); // not power of 2
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "sectorsize",
                    ..
                }
            ),
            "expected sectorsize error, got: {err:?}"
        );
    }

    #[test]
    fn superblock_rejects_non_power_of_two_nodesize() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&5000_u32.to_le_bytes()); // not power of 2
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "nodesize",
                    ..
                }
            ),
            "expected nodesize error, got: {err:?}"
        );
    }

    #[test]
    fn superblock_rejects_unsupported_csum_type() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        set_valid_superblock_device_accounting(&mut sb);
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0xC4..0xC6].copy_from_slice(&1_u16.to_le_bytes());
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "csum_type",
                reason: "only CRC32C (type 0) is currently supported",
            }
        );
    }

    #[test]
    fn superblock_rejects_zero_total_bytes() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x70..0x78].copy_from_slice(&0_u64.to_le_bytes());
        sb[0x78..0x80].copy_from_slice(&0_u64.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0xC4..0xC6].copy_from_slice(&ffs_types::BTRFS_CSUM_TYPE_CRC32C.to_le_bytes());
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "total_bytes",
                reason: "must be non-zero",
            }
        );
    }

    #[test]
    fn superblock_rejects_bytes_used_above_total() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x70..0x78].copy_from_slice(&4096_u64.to_le_bytes());
        sb[0x78..0x80].copy_from_slice(&4097_u64.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0xC4..0xC6].copy_from_slice(&ffs_types::BTRFS_CSUM_TYPE_CRC32C.to_le_bytes());
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "bytes_used",
                reason: "exceeds total_bytes",
            }
        );
    }

    #[test]
    fn superblock_rejects_zero_num_devices() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x70..0x78].copy_from_slice(&4096_u64.to_le_bytes());
        sb[0x78..0x80].copy_from_slice(&0_u64.to_le_bytes());
        sb[0x88..0x90].copy_from_slice(&0_u64.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0xC4..0xC6].copy_from_slice(&ffs_types::BTRFS_CSUM_TYPE_CRC32C.to_le_bytes());
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "num_devices",
                reason: "must be non-zero",
            }
        );
    }

    #[test]
    fn map_logical_to_physical_hit() {
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0x100_0000, // logical start = 16 MiB
            },
            length: 0x80_0000, // 8 MiB
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
                offset: 0x20_0000, // physical start = 2 MiB
                dev_uuid: [0; 16],
            }],
        }];

        // Hit: logical 16.5 MiB → physical 2.5 MiB
        let result = map_logical_to_physical(&chunks, 0x108_0000).expect("mapping should succeed");
        let mapping = result.expect("should find a mapping");
        assert_eq!(mapping.devid, 1);
        assert_eq!(mapping.physical, 0x28_0000);
    }

    #[test]
    fn map_logical_to_physical_rejects_physical_address_overflow() {
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0,
            },
            length: 8,
            owner: 2,
            stripe_len: 4,
            chunk_type: chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: 1,
            sub_stripes: 0,
            stripes: vec![BtrfsStripe {
                devid: 1,
                offset: u64::MAX - 3,
                dev_uuid: [0; 16],
            }],
        }];

        let boundary = map_logical_to_physical(&chunks, 3)
            .expect("boundary mapping should be valid")
            .expect("chunk should cover boundary logical address");
        assert_eq!(boundary.physical, u64::MAX);

        let err = map_logical_to_physical(&chunks, 4).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "stripe_offset",
                reason: "physical address overflow",
            }
        );
    }

    #[test]
    fn map_logical_rejects_overflowing_chunk_range() {
        let chunk = BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: u64::MAX - 3,
            },
            length: 8,
            owner: 2,
            stripe_len: 4,
            chunk_type: chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: 1,
            sub_stripes: 0,
            stripes: vec![BtrfsStripe {
                devid: 1,
                offset: 0,
                dev_uuid: [0; 16],
            }],
        };

        for err in [
            map_logical_to_physical(std::slice::from_ref(&chunk), u64::MAX - 3).unwrap_err(),
            map_logical_to_stripes(&[chunk], u64::MAX - 3).unwrap_err(),
        ] {
            assert_eq!(
                err,
                ParseError::InvalidField {
                    field: "chunk_length",
                    reason: "logical range overflow",
                }
            );
        }
    }

    #[test]
    fn map_logical_to_stripes_rejects_physical_address_overflow() {
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0,
            },
            length: 8,
            owner: 2,
            stripe_len: 4,
            chunk_type: chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: 1,
            sub_stripes: 0,
            stripes: vec![BtrfsStripe {
                devid: 1,
                offset: u64::MAX - 3,
                dev_uuid: [0; 16],
            }],
        }];

        let boundary = map_logical_to_stripes(&chunks, 3)
            .expect("boundary stripe mapping should be valid")
            .expect("chunk should cover boundary logical address");
        assert_eq!(boundary.profile, BtrfsRaidProfile::Single);
        assert_eq!(boundary.stripes.len(), 1);
        assert_eq!(boundary.stripes[0].physical, u64::MAX);

        let err = map_logical_to_stripes(&chunks, 4).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "stripe_offset",
                reason: "physical address overflow",
            }
        );
    }

    #[test]
    fn map_logical_to_physical_miss() {
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0x100_0000,
            },
            length: 0x80_0000,
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
                offset: 0x20_0000,
                dev_uuid: [0; 16],
            }],
        }];

        // Miss: logical address outside the chunk range
        let result = map_logical_to_physical(&chunks, 0x200_0000).expect("no error");
        assert!(result.is_none());
    }

    #[test]
    fn map_logical_to_physical_rejects_multi_device_profile() {
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0x100_0000,
            },
            length: 0x80_0000,
            owner: 2,
            stripe_len: 0x1_0000,
            chunk_type: chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: 2,
            sub_stripes: 0,
            stripes: vec![
                BtrfsStripe {
                    devid: 1,
                    offset: 0x20_0000,
                    dev_uuid: [0; 16],
                },
                BtrfsStripe {
                    devid: 2,
                    offset: 0x30_0000,
                    dev_uuid: [0; 16],
                },
            ],
        }];

        let err = map_logical_to_physical(&chunks, 0x100_0000).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "chunk_type",
                ..
            }
        ));
    }

    #[test]
    fn map_logical_to_physical_rejects_single_with_multiple_stripes() {
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0x100_0000,
            },
            length: 0x80_0000,
            owner: 2,
            stripe_len: 0x1_0000,
            chunk_type: chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: 2,
            sub_stripes: 0,
            stripes: vec![
                BtrfsStripe {
                    devid: 1,
                    offset: 0x20_0000,
                    dev_uuid: [0; 16],
                },
                BtrfsStripe {
                    devid: 1,
                    offset: 0x28_0000,
                    dev_uuid: [0; 16],
                },
            ],
        }];

        let err = map_logical_to_physical(&chunks, 0x100_0000).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "num_stripes",
                ..
            }
        ));
    }

    #[test]
    fn map_logical_to_physical_rejects_dup_with_mixed_devices() {
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0x100_0000,
            },
            length: 0x80_0000,
            owner: 2,
            stripe_len: 0x1_0000,
            chunk_type: chunk_type_flags::BTRFS_BLOCK_GROUP_DUP,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: 2,
            sub_stripes: 0,
            stripes: vec![
                BtrfsStripe {
                    devid: 1,
                    offset: 0x20_0000,
                    dev_uuid: [0; 16],
                },
                BtrfsStripe {
                    devid: 2,
                    offset: 0x28_0000,
                    dev_uuid: [0; 16],
                },
            ],
        }];

        let err = map_logical_to_physical(&chunks, 0x100_0000).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "stripe_devid",
                ..
            }
        ));
    }

    #[test]
    fn map_logical_to_physical_empty_chunks() {
        let result = map_logical_to_physical(&[], 0x1000).expect("no error");
        assert!(result.is_none());
    }

    #[test]
    fn parse_sys_chunk_array_empty() {
        let entries = parse_sys_chunk_array(&[]).expect("empty array is valid");
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_sys_chunk_array_truncated_key() {
        let data = [0_u8; 10]; // too short for a disk_key
        let err = parse_sys_chunk_array(&data).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn parse_sys_chunk_array_rejects_non_chunk_item_key() {
        let key = BtrfsKey {
            objectid: BTRFS_FIRST_CHUNK_TREE_OBJECTID,
            item_type: BTRFS_CHUNK_ITEM_KEY.wrapping_add(1),
            offset: 0,
        };
        let data = build_sys_chunk_entry(key, 1);
        let err = parse_sys_chunk_array(&data).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "sys_chunk_key_type",
                ..
            }
        ));
    }

    #[test]
    fn parse_sys_chunk_array_rejects_unexpected_objectid() {
        let key = BtrfsKey {
            objectid: BTRFS_FIRST_CHUNK_TREE_OBJECTID + 1,
            item_type: BTRFS_CHUNK_ITEM_KEY,
            offset: 0,
        };
        let data = build_sys_chunk_entry(key, 1);
        let err = parse_sys_chunk_array(&data).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "sys_chunk_key_objectid",
                ..
            }
        ));
    }

    #[test]
    fn parse_sys_chunk_array_rejects_multiple_raid_profiles() {
        let mut data = vec![0_u8; BTRFS_DISK_KEY_SIZE + BTRFS_CHUNK_FIXED_SIZE + BTRFS_STRIPE_SIZE];
        data[0..8].copy_from_slice(&256_u64.to_le_bytes());
        data[8] = 228;
        data[9..17].copy_from_slice(&0_u64.to_le_bytes());
        let c = BTRFS_DISK_KEY_SIZE;
        data[c..c + 8].copy_from_slice(&4096_u64.to_le_bytes());
        data[c + 8..c + 16].copy_from_slice(&2_u64.to_le_bytes());
        data[c + 16..c + 24].copy_from_slice(&4096_u64.to_le_bytes());
        let chunk_type = chunk_type_flags::BTRFS_BLOCK_GROUP_DATA
            | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0
            | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1;
        data[c + 24..c + 32].copy_from_slice(&chunk_type.to_le_bytes());
        data[c + 32..c + 36].copy_from_slice(&4096_u32.to_le_bytes());
        data[c + 36..c + 40].copy_from_slice(&4096_u32.to_le_bytes());
        data[c + 40..c + 44].copy_from_slice(&4096_u32.to_le_bytes());
        data[c + 44..c + 46].copy_from_slice(&1_u16.to_le_bytes());
        data[c + 46..c + 48].copy_from_slice(&0_u16.to_le_bytes());
        let s = c + BTRFS_CHUNK_FIXED_SIZE;
        data[s..s + 8].copy_from_slice(&1_u64.to_le_bytes());
        data[s + 8..s + 16].copy_from_slice(&0_u64.to_le_bytes());

        let err = parse_sys_chunk_array(&data).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "chunk_type",
                ..
            }
        ));
    }

    #[test]
    fn parse_sys_chunk_array_rejects_invalid_mirror_stripe_layouts() {
        let key = BtrfsKey {
            objectid: BTRFS_FIRST_CHUNK_TREE_OBJECTID,
            item_type: BTRFS_CHUNK_ITEM_KEY,
            offset: 0,
        };
        let c = BTRFS_DISK_KEY_SIZE;

        let mut single_extra = build_sys_chunk_entry(key, 2);
        single_extra[c + 24..c + 32]
            .copy_from_slice(&chunk_type_flags::BTRFS_BLOCK_GROUP_DATA.to_le_bytes());
        let err = parse_sys_chunk_array(&single_extra).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "num_stripes",
                reason: "single chunk must have exactly one stripe",
            }
        );

        let mut raid1_too_few = build_sys_chunk_entry(key, 1);
        raid1_too_few[c + 24..c + 32].copy_from_slice(
            &(chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1)
                .to_le_bytes(),
        );
        let err = parse_sys_chunk_array(&raid1_too_few).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "num_stripes",
                reason: "RAID1 chunk must have at least two stripes",
            }
        );

        let mut dup_mixed = build_sys_chunk_entry(key, 2);
        dup_mixed[c + 24..c + 32].copy_from_slice(
            &(chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_DUP)
                .to_le_bytes(),
        );
        let err = parse_sys_chunk_array(&dup_mixed).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "stripe_devid",
                reason: "DUP chunk must use a single device",
            }
        );
    }

    #[test]
    fn checked_item_table_end_rejects_overflow() {
        // Reasonable item counts compute a valid end past the header.
        assert!(checked_item_table_end(0, BTRFS_ITEM_SIZE, "items").is_ok());
        assert!(checked_item_table_end(100, BTRFS_ITEM_SIZE, "items").is_ok());
        // A count that overflows usize when multiplied by the item size is
        // rejected, so a corrupt header cannot drive a huge allocation.
        let err = checked_item_table_end(usize::MAX, BTRFS_ITEM_SIZE, "items").unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    reason: "overflow",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_leaf_items_smoke() {
        let mut block = vec![0_u8; 512];

        block[0x60..0x64].copy_from_slice(&1_u32.to_le_bytes());
        block[0x64] = 0;

        // first item at header+0
        let base = BTRFS_HEADER_SIZE;
        block[base..base + 8].copy_from_slice(&123_u64.to_le_bytes());
        block[base + 8] = 42;
        block[base + 9..base + 17].copy_from_slice(&999_u64.to_le_bytes());
        block[base + 17..base + 21]
            .copy_from_slice(&(400_u32 - u32::try_from(BTRFS_HEADER_SIZE).unwrap()).to_le_bytes());
        block[base + 21..base + 25].copy_from_slice(&8_u32.to_le_bytes());

        let (_, items) = parse_leaf_items(&block).expect("leaf parse");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].key.objectid, 123);
        assert_eq!(items[0].key.item_type, 42);
        assert_eq!(items[0].key.offset, 999);
        assert_eq!(items[0].data_offset, 400);
        assert_eq!(items[0].data_size, 8);
    }

    #[test]
    fn parse_leaf_items_rejects_unsorted_keys() {
        let mut block = make_block(512, 2, 0);
        let header_size = u32::try_from(BTRFS_HEADER_SIZE).expect("header size fits");

        let b0 = BTRFS_HEADER_SIZE;
        block[b0..b0 + 8].copy_from_slice(&2_u64.to_le_bytes());
        block[b0 + 8] = 1;
        block[b0 + 9..b0 + 17].copy_from_slice(&0_u64.to_le_bytes());
        block[b0 + 17..b0 + 21].copy_from_slice(&(300_u32 - header_size).to_le_bytes());
        block[b0 + 21..b0 + 25].copy_from_slice(&4_u32.to_le_bytes());

        let b1 = BTRFS_HEADER_SIZE + BTRFS_ITEM_SIZE;
        block[b1..b1 + 8].copy_from_slice(&1_u64.to_le_bytes());
        block[b1 + 8] = 1;
        block[b1 + 9..b1 + 17].copy_from_slice(&0_u64.to_le_bytes());
        block[b1 + 17..b1 + 21].copy_from_slice(&(320_u32 - header_size).to_le_bytes());
        block[b1 + 21..b1 + 25].copy_from_slice(&4_u32.to_le_bytes());

        let err = parse_leaf_items(&block).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "item_key",
                reason: "leaf item keys not strictly increasing",
            }
        );
    }

    /// Helper: build a minimal valid block with a header (zeros except nritems + level).
    fn make_block(size: usize, nritems: u32, level: u8) -> Vec<u8> {
        let mut block = vec![0_u8; size];
        block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
        block[0x64] = level;
        block
    }

    #[test]
    fn parse_internal_items_smoke() {
        let mut block = make_block(4096, 2, 1);

        // Item 0: key(256, 132, 0) → blockptr=0x4000, gen=10
        let b0 = BTRFS_HEADER_SIZE;
        block[b0..b0 + 8].copy_from_slice(&256_u64.to_le_bytes());
        block[b0 + 8] = 132;
        block[b0 + 9..b0 + 17].copy_from_slice(&0_u64.to_le_bytes());
        block[b0 + 17..b0 + 25].copy_from_slice(&0x4000_u64.to_le_bytes());
        block[b0 + 25..b0 + 33].copy_from_slice(&10_u64.to_le_bytes());

        // Item 1: key(512, 132, 100) → blockptr=0x8000, gen=10
        let b1 = BTRFS_HEADER_SIZE + BTRFS_KEY_PTR_SIZE;
        block[b1..b1 + 8].copy_from_slice(&512_u64.to_le_bytes());
        block[b1 + 8] = 132;
        block[b1 + 9..b1 + 17].copy_from_slice(&100_u64.to_le_bytes());
        block[b1 + 17..b1 + 25].copy_from_slice(&0x8000_u64.to_le_bytes());
        block[b1 + 25..b1 + 33].copy_from_slice(&10_u64.to_le_bytes());

        let (header, ptrs) = parse_internal_items(&block).expect("internal parse");
        assert_eq!(header.level, 1);
        assert_eq!(ptrs.len(), 2);
        assert_eq!(ptrs[0].key.objectid, 256);
        assert_eq!(ptrs[0].blockptr, 0x4000);
        assert_eq!(ptrs[0].generation, 10);
        assert_eq!(ptrs[1].key.objectid, 512);
        assert_eq!(ptrs[1].blockptr, 0x8000);
    }

    #[test]
    fn parse_internal_items_rejects_unsorted_keys() {
        let mut block = make_block(4096, 2, 1);

        let b0 = BTRFS_HEADER_SIZE;
        block[b0..b0 + 8].copy_from_slice(&2_u64.to_le_bytes());
        block[b0 + 8] = 1;
        block[b0 + 9..b0 + 17].copy_from_slice(&0_u64.to_le_bytes());
        block[b0 + 17..b0 + 25].copy_from_slice(&0x4000_u64.to_le_bytes());
        block[b0 + 25..b0 + 33].copy_from_slice(&10_u64.to_le_bytes());

        let b1 = BTRFS_HEADER_SIZE + BTRFS_KEY_PTR_SIZE;
        block[b1..b1 + 8].copy_from_slice(&1_u64.to_le_bytes());
        block[b1 + 8] = 1;
        block[b1 + 9..b1 + 17].copy_from_slice(&0_u64.to_le_bytes());
        block[b1 + 17..b1 + 25].copy_from_slice(&0x8000_u64.to_le_bytes());
        block[b1 + 25..b1 + 33].copy_from_slice(&10_u64.to_le_bytes());

        let err = parse_internal_items(&block).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "key_ptrs.key",
                reason: "internal item keys not strictly increasing",
            }
        );
    }

    #[test]
    fn parse_internal_items_rejects_leaf() {
        let block = make_block(4096, 0, 0);
        let err = parse_internal_items(&block).unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidField { field: "level", .. }),
            "expected level error, got: {err:?}"
        );
    }

    #[test]
    fn parse_internal_items_rejects_zero_blockptr() {
        let mut block = make_block(4096, 1, 1);
        // key is valid but blockptr is zero
        let b0 = BTRFS_HEADER_SIZE;
        block[b0..b0 + 8].copy_from_slice(&256_u64.to_le_bytes());
        block[b0 + 8] = 132;
        // blockptr stays zero (from make_block)

        let err = parse_internal_items(&block).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "blockptr",
                    ..
                }
            ),
            "expected blockptr error, got: {err:?}"
        );
    }

    /// bd-ormcf — Kernel-conformance pin for the btrfs_super_block
    /// field offsets per fs/btrfs/btrfs_tree.h. Each field is stamped
    /// with a UNIQUE non-zero magic at its canonical kernel offset,
    /// then a single BtrfsSuperblock::parse_superblock_region call
    /// must round-trip every field. The btrfs superblock is the entry
    /// point for every mount/probe; a regression that drifted any
    /// single offset would silently corrupt the bootstrap state and
    /// either fail to mount or mount with wrong tree pointers.
    ///
    /// Sister kernel pins: bd-latwe (BtrfsHeader), bd-na4cc
    /// (BtrfsDevItem), bd-h117q (size constants), bd-2zmia (slot
    /// layouts), bd-swwp0 (parse_extent_data), bd-nzs5f
    /// (parse_inode_item), bd-xbqdw (parse_root_item).
    #[test]
    #[allow(clippy::too_many_lines)]
    fn btrfs_super_block_kernel_offsets_match_btrfs_tree_h() {
        // 32-byte csum and 16-byte fsid: distinct first/last bytes so
        // a slice-direction drift surfaces.
        let mut csum = [0_u8; 32];
        csum[0] = 0xC1;
        csum[31] = 0xC2;
        let mut fsid = [0_u8; 16];
        fsid[0] = 0xF1;
        fsid[15] = 0xF2;

        // Distinct non-zero magics. Constraints:
        //   bytes_used must be <= total_bytes
        //   sectorsize / nodesize must be non-zero power-of-two <= 256K
        //   stripesize must be 0 or power-of-two <= 256K
        //   root_level / chunk_root_level / log_root_level must be <= 7
        //   csum_type must be 0..=3
        //   sys_chunk_array_size must be <= 2048
        //   magic must equal BTRFS_MAGIC
        let bytenr = 0x3030_3030_3030_3030_u64;
        let flags = 0x3838_3838_3838_3838_u64;
        let generation = 0x4848_4848_4848_4848_u64;
        let root = 0x5050_5050_5050_5050_u64;
        let chunk_root = 0x5858_5858_5858_5858_u64;
        let log_root = 0x6060_6060_6060_6060_u64;
        let total_bytes = 0x7070_7070_7070_7070_u64;
        let bytes_used = 0x0000_0000_0000_0010_u64; // small, < total_bytes
        let root_dir_objectid = 0x8080_8080_8080_8080_u64;
        let num_devices = 0x8888_8888_8888_8888_u64;
        let sectorsize: u32 = 0x1000; // 4096
        let nodesize: u32 = 0x4000; // 16384
        let stripesize: u32 = 0x10000; // 65536
        let sys_chunk_array_size: u32 = 0; // no payload to satisfy bounds easily
        let compat_flags = 0xACAC_ACAC_ACAC_ACAC_u64;
        let compat_ro_flags = 0xB4B4_B4B4_B4B4_B4B4_u64;
        let incompat_flags = 0xBCBC_BCBC_BCBC_BCBC_u64;
        let csum_type: u16 = ffs_types::BTRFS_CSUM_TYPE_CRC32C;
        let root_level: u8 = 0x05;
        let chunk_root_level: u8 = 0x06;
        let log_root_level: u8 = 0x07;
        let label_seed: &[u8] = b"FRANKEN-PIN";

        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x00..0x20].copy_from_slice(&csum);
        sb[0x20..0x30].copy_from_slice(&fsid);
        sb[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
        sb[0x38..0x40].copy_from_slice(&flags.to_le_bytes());
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x48..0x50].copy_from_slice(&generation.to_le_bytes());
        sb[0x50..0x58].copy_from_slice(&root.to_le_bytes());
        sb[0x58..0x60].copy_from_slice(&chunk_root.to_le_bytes());
        sb[0x60..0x68].copy_from_slice(&log_root.to_le_bytes());
        sb[0x70..0x78].copy_from_slice(&total_bytes.to_le_bytes());
        sb[0x78..0x80].copy_from_slice(&bytes_used.to_le_bytes());
        sb[0x80..0x88].copy_from_slice(&root_dir_objectid.to_le_bytes());
        sb[0x88..0x90].copy_from_slice(&num_devices.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&sectorsize.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&nodesize.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&stripesize.to_le_bytes());
        sb[0xA0..0xA4].copy_from_slice(&sys_chunk_array_size.to_le_bytes());
        sb[0xAC..0xB4].copy_from_slice(&compat_flags.to_le_bytes());
        sb[0xB4..0xBC].copy_from_slice(&compat_ro_flags.to_le_bytes());
        sb[0xBC..0xC4].copy_from_slice(&incompat_flags.to_le_bytes());
        sb[0xC4..0xC6].copy_from_slice(&csum_type.to_le_bytes());
        sb[0xC6] = root_level;
        sb[0xC7] = chunk_root_level;
        sb[0xC8] = log_root_level;
        sb[BTRFS_SUPER_LABEL_OFFSET..BTRFS_SUPER_LABEL_OFFSET + label_seed.len()]
            .copy_from_slice(label_seed);

        let parsed =
            BtrfsSuperblock::parse_superblock_region(&sb).expect("kernel-stamped sb must parse");

        assert_eq!(parsed.csum, csum, "csum @ 0x00..0x20");
        assert_eq!(parsed.fsid, fsid, "fsid @ 0x20..0x30");
        assert_eq!(parsed.bytenr, bytenr, "bytenr @ 0x30..0x38");
        assert_eq!(parsed.flags, flags, "flags @ 0x38..0x40");
        assert_eq!(parsed.magic, BTRFS_MAGIC, "magic @ 0x40..0x48");
        assert_eq!(parsed.generation, generation, "generation @ 0x48..0x50");
        assert_eq!(parsed.root, root, "root @ 0x50..0x58");
        assert_eq!(parsed.chunk_root, chunk_root, "chunk_root @ 0x58..0x60");
        assert_eq!(parsed.log_root, log_root, "log_root @ 0x60..0x68");
        assert_eq!(parsed.total_bytes, total_bytes, "total_bytes @ 0x70..0x78");
        assert_eq!(parsed.bytes_used, bytes_used, "bytes_used @ 0x78..0x80");
        assert_eq!(
            parsed.root_dir_objectid, root_dir_objectid,
            "root_dir_objectid @ 0x80..0x88"
        );
        assert_eq!(parsed.num_devices, num_devices, "num_devices @ 0x88..0x90");
        assert_eq!(parsed.sectorsize, sectorsize, "sectorsize @ 0x90..0x94");
        assert_eq!(parsed.nodesize, nodesize, "nodesize @ 0x94..0x98");
        assert_eq!(parsed.stripesize, stripesize, "stripesize @ 0x9C..0xA0");
        assert_eq!(
            parsed.sys_chunk_array_size, sys_chunk_array_size,
            "sys_chunk_array_size @ 0xA0..0xA4"
        );
        assert_eq!(
            parsed.compat_flags, compat_flags,
            "compat_flags @ 0xAC..0xB4"
        );
        assert_eq!(
            parsed.compat_ro_flags, compat_ro_flags,
            "compat_ro_flags @ 0xB4..0xBC"
        );
        assert_eq!(
            parsed.incompat_flags, incompat_flags,
            "incompat_flags @ 0xBC..0xC4"
        );
        assert_eq!(parsed.csum_type, csum_type, "csum_type @ 0xC4..0xC6");
        assert_eq!(parsed.root_level, root_level, "root_level @ 0xC6");
        assert_eq!(
            parsed.chunk_root_level, chunk_root_level,
            "chunk_root_level @ 0xC7"
        );
        assert_eq!(
            parsed.log_root_level, log_root_level,
            "log_root_level @ 0xC8"
        );
        assert_eq!(
            parsed.label,
            std::str::from_utf8(label_seed).unwrap(),
            "label @ BTRFS_SUPER_LABEL_OFFSET (0x12B)"
        );
    }

    /// bd-2zmia — Kernel-conformance pin for the btrfs_key_ptr slot
    /// field offsets per fs/btrfs/ctree.h. parse_internal_items reads
    /// each slot at BTRFS_HEADER_SIZE + idx*BTRFS_KEY_PTR_SIZE with
    /// disk_key (objectid u64@0, type u8@8, offset u64@9) + blockptr
    /// u64@17 + generation u64@25. Each field is stamped with a UNIQUE
    /// non-zero magic; a regression that drifted any offset would
    /// mis-route key↔blockptr silently — and parse_internal_items runs
    /// on every walk_tree internal-node descent.
    ///
    /// Sister pins: bd-latwe (BtrfsHeader fields), bd-h117q (size
    /// constants), bd-na4cc (BtrfsDevItem fields), bd-nzs5f
    /// (parse_inode_item), bd-xbqdw (parse_root_item), bd-kelr0
    /// (parse_inode_refs), bd-m9u35 (parse_root_ref), bd-swwp0
    /// (parse_extent_data).
    /// bd-usqb3 — Kernel-conformance pin for parse_chunk_header field
    /// offsets per fs/btrfs/btrfs_tree.h (struct btrfs_chunk, 48-byte
    /// fixed header). Each of 9 fields is stamped with a UNIQUE
    /// non-zero magic at its canonical kernel offset, then a single
    /// parse_sys_chunk_array call must round-trip every field. The
    /// 48-byte chunk header is read on every mount/probe of every
    /// multi-device btrfs filesystem (via parse_sys_chunk_array) and
    /// on every walk_chunk_tree descent (via parse_chunk_item, which
    /// shares parse_chunk_header). A regression that drifted any
    /// offset would mis-route chunk_type-vs-io_align silently.
    ///
    /// Sister pins: bd-latwe (BtrfsHeader), bd-na4cc (BtrfsDevItem),
    /// bd-ormcf (BtrfsSuperblock), bd-2zmia (slot layouts), bd-h117q
    /// (size constants).
    #[test]
    fn parse_chunk_header_kernel_offsets_match_btrfs_tree_h() {
        // sys_chunk_array entry layout: btrfs_disk_key (17) +
        // btrfs_chunk_fixed (48) + 1 btrfs_stripe (32) = 97 bytes.
        let mut data = vec![0_u8; 17 + 48 + 32];

        // Distinct non-zero magics. Constraints from parser:
        //   key.objectid == BTRFS_FIRST_CHUNK_TREE_OBJECTID (256)
        //   key.item_type == BTRFS_CHUNK_ITEM_KEY (228)
        //   chunk_type RAID-bits.count_ones() <= 1 (use 0 RAID bits)
        //   length, stripe_len, num_stripes != 0
        //   stripe.devid != 0
        let length = 0x0010_0000_u64; // 1 MiB chunk
        let owner = 0x8888_8888_8888_8888_u64;
        let stripe_len = 0x0001_0000_u64; // 64 KiB
        // chunk_type = DATA (single-device, no RAID bits) so
        // RAID_MASK & chunk_type == 0 (passes count_ones <= 1).
        let chunk_type = chunk_type_flags::BTRFS_BLOCK_GROUP_DATA;
        let io_align: u32 = 0x2020_2020;
        let io_width: u32 = 0x2424_2424;
        let sector_size: u32 = 0x2828_2828;
        let num_stripes: u16 = 1; // must match the trailing stripe count
        let sub_stripes: u16 = 0x2E2E;

        // disk_key @ 0..17
        data[0..8].copy_from_slice(&BTRFS_FIRST_CHUNK_TREE_OBJECTID.to_le_bytes());
        data[8] = BTRFS_CHUNK_ITEM_KEY;
        data[9..17].copy_from_slice(&0x0000_0000_0000_0010_u64.to_le_bytes());

        // chunk_header @ 17..65 (= 17 + 48)
        let base = 17;
        data[base..base + 8].copy_from_slice(&length.to_le_bytes());
        data[base + 8..base + 16].copy_from_slice(&owner.to_le_bytes());
        data[base + 16..base + 24].copy_from_slice(&stripe_len.to_le_bytes());
        data[base + 24..base + 32].copy_from_slice(&chunk_type.to_le_bytes());
        data[base + 32..base + 36].copy_from_slice(&io_align.to_le_bytes());
        data[base + 36..base + 40].copy_from_slice(&io_width.to_le_bytes());
        data[base + 40..base + 44].copy_from_slice(&sector_size.to_le_bytes());
        data[base + 44..base + 46].copy_from_slice(&num_stripes.to_le_bytes());
        data[base + 46..base + 48].copy_from_slice(&sub_stripes.to_le_bytes());

        // stripe @ 65..97: devid u64 + offset u64 + dev_uuid[16]
        let stripe_devid = 0x4141_4141_4141_4141_u64;
        let stripe_offset = 0x4949_4949_4949_4949_u64;
        let mut stripe_uuid = [0_u8; 16];
        stripe_uuid[0] = 0x51;
        stripe_uuid[15] = 0x60;
        let s_base = base + 48;
        data[s_base..s_base + 8].copy_from_slice(&stripe_devid.to_le_bytes());
        data[s_base + 8..s_base + 16].copy_from_slice(&stripe_offset.to_le_bytes());
        data[s_base + 16..s_base + 32].copy_from_slice(&stripe_uuid);

        let entries = parse_sys_chunk_array(&data).expect("kernel-stamped chunk must parse");
        assert_eq!(entries.len(), 1, "exactly one chunk entry");

        let entry = &entries[0];
        // chunk_header fields.
        assert_eq!(entry.length, length, "length @ chunk_base+0");
        assert_eq!(entry.owner, owner, "owner @ chunk_base+8");
        assert_eq!(entry.stripe_len, stripe_len, "stripe_len @ chunk_base+16");
        assert_eq!(entry.chunk_type, chunk_type, "chunk_type @ chunk_base+24");
        assert_eq!(entry.io_align, io_align, "io_align @ chunk_base+32");
        assert_eq!(entry.io_width, io_width, "io_width @ chunk_base+36");
        assert_eq!(
            entry.sector_size, sector_size,
            "sector_size @ chunk_base+40"
        );
        assert_eq!(
            entry.num_stripes, num_stripes,
            "num_stripes @ chunk_base+44"
        );
        assert_eq!(
            entry.sub_stripes, sub_stripes,
            "sub_stripes @ chunk_base+46"
        );
        // Embedded stripe fields.
        assert_eq!(entry.stripes.len(), 1);
        assert_eq!(
            entry.stripes[0].devid, stripe_devid,
            "stripe.devid @ stripe_base+0"
        );
        assert_eq!(
            entry.stripes[0].offset, stripe_offset,
            "stripe.offset @ stripe_base+8"
        );
        assert_eq!(
            entry.stripes[0].dev_uuid, stripe_uuid,
            "stripe.dev_uuid @ stripe_base+16..32"
        );
        // Size-arithmetic checks: BTRFS_CHUNK_FIXED_SIZE = 48,
        // BTRFS_STRIPE_SIZE = 32, sum + disk_key (17) = 97 bytes.
        assert_eq!(BTRFS_CHUNK_FIXED_SIZE, 48);
        assert_eq!(BTRFS_STRIPE_SIZE, 32);
    }

    #[test]
    fn parse_internal_items_kernel_slot_offsets_match_ctree_h() {
        // 4096-byte block, 1 slot, level=1 (internal node).
        let mut block = make_block(4096, 1, 1);

        // Distinct non-zero magics so an offset drift produces a
        // cross-field collision. item_type byte chosen to be unique
        // among all bytes in the slot region.
        let objectid = 0x1111_1111_1111_1111_u64;
        let item_type = 0x33_u8;
        let key_offset = 0x4444_4444_4444_4444_u64;
        let blockptr = 0x5555_5555_5555_5555_u64;
        let generation = 0x6666_6666_6666_6666_u64;

        let base = BTRFS_HEADER_SIZE;
        block[base..base + 8].copy_from_slice(&objectid.to_le_bytes());
        block[base + 8] = item_type;
        block[base + 9..base + 17].copy_from_slice(&key_offset.to_le_bytes());
        block[base + 17..base + 25].copy_from_slice(&blockptr.to_le_bytes());
        block[base + 25..base + 33].copy_from_slice(&generation.to_le_bytes());

        let (_header, ptrs) =
            parse_internal_items(&block).expect("kernel-stamped internal node must parse");

        assert_eq!(ptrs.len(), 1);
        let ptr = &ptrs[0];
        assert_eq!(ptr.key.objectid, objectid, "key.objectid @ slot+0..8");
        assert_eq!(ptr.key.item_type, item_type, "key.item_type @ slot+8");
        assert_eq!(ptr.key.offset, key_offset, "key.offset @ slot+9..17");
        assert_eq!(ptr.blockptr, blockptr, "blockptr @ slot+17..25");
        assert_eq!(ptr.generation, generation, "generation @ slot+25..33");
    }

    /// bd-2zmia — Kernel-conformance pin for the btrfs_item slot field
    /// offsets per fs/btrfs/ctree.h. parse_leaf_items reads each slot
    /// at BTRFS_HEADER_SIZE + idx*BTRFS_ITEM_SIZE with disk_key
    /// (objectid u64@0, type u8@8, offset u64@9) + payload_offset
    /// u32@17 (relative to leaf header — parser normalizes to absolute)
    /// + payload_size u32@21. Each field is stamped with a UNIQUE
    ///   non-zero magic. parse_leaf_items runs on every walk_tree
    ///   leaf-node read — the most heavily-trafficked btrfs parser.
    ///
    /// Companion to parse_internal_items_kernel_slot_offsets_match_ctree_h.
    #[test]
    fn parse_leaf_items_kernel_slot_offsets_match_ctree_h() {
        // 4096-byte block, 1 slot, level=0 (leaf node).
        let mut block = make_block(4096, 1, 0);

        let objectid = 0x1111_1111_1111_1111_u64;
        let item_type = 0x33_u8;
        let key_offset = 0x4444_4444_4444_4444_u64;
        // raw payload offset is leaf-relative; pick a value such that
        // (HEADER_SIZE + raw_offset) lands inside the block AND outside
        // the items table (items_end = HEADER + 1*ITEM_SIZE = 126).
        // Using raw_offset = 1024 → absolute payload @ 1125, payload
        // ends at 1125+8 = 1133 (≤ 4096). Distinct value so a drift
        // surfaces.
        let raw_data_offset: u32 = 1024;
        let data_size: u32 = 8;

        let base = BTRFS_HEADER_SIZE;
        block[base..base + 8].copy_from_slice(&objectid.to_le_bytes());
        block[base + 8] = item_type;
        block[base + 9..base + 17].copy_from_slice(&key_offset.to_le_bytes());
        block[base + 17..base + 21].copy_from_slice(&raw_data_offset.to_le_bytes());
        block[base + 21..base + 25].copy_from_slice(&data_size.to_le_bytes());

        let (_header, items) = parse_leaf_items(&block).expect("kernel-stamped leaf must parse");

        assert_eq!(items.len(), 1);
        let item = &items[0];
        assert_eq!(item.key.objectid, objectid, "key.objectid @ slot+0..8");
        assert_eq!(item.key.item_type, item_type, "key.item_type @ slot+8");
        assert_eq!(item.key.offset, key_offset, "key.offset @ slot+9..17");
        // Parser normalizes leaf-relative payload offset to absolute
        // by adding BTRFS_HEADER_SIZE.
        let header_size_u32 = u32::try_from(BTRFS_HEADER_SIZE).unwrap();
        assert_eq!(
            item.data_offset,
            raw_data_offset + header_size_u32,
            "data_offset @ slot+17..21 normalized = raw + HEADER_SIZE"
        );
        assert_eq!(item.data_size, data_size, "data_size @ slot+21..25");
    }

    /// bd-h117q — Kernel-conformance pin for the btrfs btree size
    /// constants used for byte-offset arithmetic in parse_leaf_items,
    /// parse_internal_items, parse_chunk_item, and
    /// BtrfsHeader::parse_from_block. Each constant must equal the
    /// canonical sizeof(struct *) per fs/btrfs/ctree.h. A regression
    /// that drifted any size by ±4 bytes (one field-width) would
    /// mis-align every leaf-slot or internal-slot read, silently
    /// corrupting every walk_tree call.
    ///
    /// Sister pins: bd-latwe (BtrfsHeader field offsets), bd-na4cc
    /// (BtrfsDevItem field offsets), bd-7dhr1 (BtrfsExtentItem
    /// canonical bytes).
    #[test]
    fn btrfs_btree_size_constants_match_ctree_h() {
        // struct btrfs_header per fs/btrfs/ctree.h:
        //   csum[32] + fsid[16] + bytenr u64 + flags u64 +
        //   chunk_tree_uuid[16] + generation u64 + owner u64 +
        //   nritems u32 + level u8 = 32+16+8+8+16+8+8+4+1 = 101
        assert_eq!(
            BTRFS_HEADER_SIZE, 101,
            "BTRFS_HEADER_SIZE must equal sizeof(struct btrfs_header) = 101"
        );
        // struct btrfs_disk_key per fs/btrfs/ctree.h:
        //   objectid u64 + type u8 + offset u64 = 8+1+8 = 17
        assert_eq!(
            BTRFS_DISK_KEY_SIZE, 17,
            "BTRFS_DISK_KEY_SIZE must equal sizeof(struct btrfs_disk_key) = 17"
        );
        // struct btrfs_item per fs/btrfs/ctree.h:
        //   key (struct btrfs_disk_key, 17) + offset u32 + size u32
        //   = 17+4+4 = 25
        assert_eq!(
            BTRFS_ITEM_SIZE, 25,
            "BTRFS_ITEM_SIZE must equal sizeof(struct btrfs_item) = 25"
        );
        assert_eq!(
            BTRFS_ITEM_SIZE,
            BTRFS_DISK_KEY_SIZE + 4 + 4,
            "BTRFS_ITEM_SIZE must equal disk_key + offset(u32) + size(u32)"
        );
        // struct btrfs_key_ptr per fs/btrfs/ctree.h:
        //   key (struct btrfs_disk_key, 17) + blockptr u64 + generation u64
        //   = 17+8+8 = 33
        assert_eq!(
            BTRFS_KEY_PTR_SIZE, 33,
            "BTRFS_KEY_PTR_SIZE must equal sizeof(struct btrfs_key_ptr) = 33"
        );
        assert_eq!(
            BTRFS_KEY_PTR_SIZE,
            BTRFS_DISK_KEY_SIZE + 8 + 8,
            "BTRFS_KEY_PTR_SIZE must equal disk_key + blockptr(u64) + generation(u64)"
        );
    }

    /// bd-latwe — Kernel-conformance pin for the btrfs_header field
    /// offsets per fs/btrfs/ctree.h (struct btrfs_header, 101 bytes).
    /// Each field is stamped with a UNIQUE non-zero magic at its
    /// canonical kernel offset, then a single
    /// BtrfsHeader::parse_from_block call must round-trip every field.
    /// A regression that drifted any single offset by ±4 bytes (one
    /// field-width) would mis-route bytenr↔flags or generation↔owner
    /// silently — and BtrfsHeader is parsed at the start of every
    /// btrfs btree node (every walk_tree call, every leaf_items /
    /// internal_items parse, every checksum verification).
    ///
    /// Sister kernel-offset pins: bd-na4cc (BtrfsDevItem), bd-xbqdw
    /// (parse_root_item), bd-nzs5f (parse_inode_item), bd-kelr0
    /// (parse_inode_refs), bd-m9u35 (parse_root_ref), bd-swwp0
    /// (parse_extent_data).
    #[test]
    fn btrfs_header_parse_from_block_kernel_offsets_match_ctree_h() {
        // 32-byte csum: distinct first/last bytes so a slice-direction
        // drift surfaces (catches subtle [u8; N] reverse).
        let mut csum = [0_u8; 32];
        csum[0] = 0x11;
        csum[31] = 0x12;
        // 16-byte fsid and chunk_tree_uuid: distinct first/last bytes.
        let mut fsid = [0_u8; 16];
        fsid[0] = 0x21;
        fsid[15] = 0x22;
        let mut chunk_tree_uuid = [0_u8; 16];
        chunk_tree_uuid[0] = 0x41;
        chunk_tree_uuid[15] = 0x42;
        // Distinct non-zero u64/u32/u8 magics.
        let bytenr = 0x3333_3333_3333_3333_u64;
        let flags = 0x3838_3838_3838_3838_u64;
        let generation = 0x5050_5050_5050_5050_u64;
        let owner = 0x5858_5858_5858_5858_u64;
        let nritems = 0x6060_6060_u32;
        // level must be ≤ BTRFS_MAX_LEVEL (7) for validate(); use 7
        // so a drift to a different byte-position would surface as a
        // different value (the 0x64 byte is unique).
        let level: u8 = 0x07;

        let mut block = vec![0_u8; BTRFS_HEADER_SIZE];
        block[0x00..0x20].copy_from_slice(&csum);
        block[0x20..0x30].copy_from_slice(&fsid);
        block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
        block[0x38..0x40].copy_from_slice(&flags.to_le_bytes());
        block[0x40..0x50].copy_from_slice(&chunk_tree_uuid);
        block[0x50..0x58].copy_from_slice(&generation.to_le_bytes());
        block[0x58..0x60].copy_from_slice(&owner.to_le_bytes());
        block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
        block[0x64] = level;

        let header =
            BtrfsHeader::parse_from_block(&block).expect("kernel-stamped header must parse");

        assert_eq!(header.csum, csum, "csum @ offset 0x00..0x20");
        assert_eq!(header.fsid, fsid, "fsid @ offset 0x20..0x30");
        assert_eq!(header.bytenr, bytenr, "bytenr @ offset 0x30..0x38");
        assert_eq!(header.flags, flags, "flags @ offset 0x38..0x40");
        assert_eq!(
            header.chunk_tree_uuid, chunk_tree_uuid,
            "chunk_tree_uuid @ offset 0x40..0x50"
        );
        assert_eq!(
            header.generation, generation,
            "generation @ offset 0x50..0x58"
        );
        assert_eq!(header.owner, owner, "owner @ offset 0x58..0x60");
        assert_eq!(header.nritems, nritems, "nritems @ offset 0x60..0x64");
        assert_eq!(header.level, level, "level @ offset 0x64");
        // Total: 0x65 = 101 bytes = BTRFS_HEADER_SIZE.
        assert_eq!(BTRFS_HEADER_SIZE, 0x65);
    }

    #[test]
    fn header_validate_bytenr_mismatch() {
        let block = make_block(4096, 0, 0);
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        // header.bytenr is 0, expected 0x1000
        let err = header.validate(4096, Some(0x1000)).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "bytenr",
                    ..
                }
            ),
            "expected bytenr error, got: {err:?}"
        );
    }

    #[test]
    fn header_validate_bytenr_match() {
        let mut block = make_block(4096, 0, 0);
        block[0x30..0x38].copy_from_slice(&0x1_0000_u64.to_le_bytes());
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        header.validate(4096, Some(0x1_0000)).expect("should match");
    }

    #[test]
    fn header_validate_nritems_overflow_leaf() {
        // A 4096-byte block can hold (4096-101)/25 = 159 leaf items max.
        let block = make_block(4096, 200, 0);
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        let err = header.validate(4096, None).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "nritems",
                    ..
                }
            ),
            "expected nritems error, got: {err:?}"
        );
    }

    #[test]
    fn header_validate_nritems_overflow_internal() {
        // A 4096-byte block can hold (4096-101)/33 = 121 internal items max.
        let block = make_block(4096, 130, 1);
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        let err = header.validate(4096, None).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "nritems",
                    ..
                }
            ),
            "expected nritems error, got: {err:?}"
        );
    }

    #[test]
    fn header_validate_level_too_high() {
        let block = make_block(4096, 0, 8); // max is 7
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        let err = header.validate(4096, None).unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidField { field: "level", .. }),
            "expected level error, got: {err:?}"
        );
    }

    #[test]
    fn parse_leaf_items_rejects_out_of_bounds_data() {
        let mut block = make_block(512, 1, 0);
        let base = BTRFS_HEADER_SIZE;
        block[base..base + 8].copy_from_slice(&1_u64.to_le_bytes());
        block[base + 8] = 1;
        // data_offset = 600 absolute, data_size = 10 — well beyond the 512-byte block
        block[base + 17..base + 21]
            .copy_from_slice(&(600_u32 - u32::try_from(BTRFS_HEADER_SIZE).unwrap()).to_le_bytes());
        block[base + 21..base + 25].copy_from_slice(&10_u32.to_le_bytes());

        let err = parse_leaf_items(&block).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "item_offset",
                    ..
                }
            ),
            "expected item_offset error, got: {err:?}"
        );
    }

    #[test]
    fn parse_leaf_items_rejects_overlapping_payload() {
        let mut block = make_block(512, 1, 0);
        let base = BTRFS_HEADER_SIZE;
        block[base..base + 8].copy_from_slice(&1_u64.to_le_bytes());
        block[base + 8] = 1;
        block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
        // raw_data_offset = 0 → absolute offset = header_size (overlaps item table)
        block[base + 17..base + 21].copy_from_slice(&0_u32.to_le_bytes());
        block[base + 21..base + 25].copy_from_slice(&4_u32.to_le_bytes());

        let err = parse_leaf_items(&block).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "item_offset",
                    ..
                }
            ),
            "expected item_offset error, got: {err:?}"
        );
    }

    #[test]
    fn parse_leaf_items_rejects_zero_length_payload_in_header() {
        let mut block = make_block(512, 1, 0);
        let base = BTRFS_HEADER_SIZE;
        block[base..base + 8].copy_from_slice(&1_u64.to_le_bytes());
        block[base + 8] = 1;
        block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
        // raw_data_offset = 0 → absolute offset = header_size (inside item table)
        block[base + 17..base + 21].copy_from_slice(&0_u32.to_le_bytes());
        // data_size = 0 to exercise zero-length validation
        block[base + 21..base + 25].copy_from_slice(&0_u32.to_le_bytes());

        let err = parse_leaf_items(&block).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "item_offset",
                    ..
                }
            ),
            "expected item_offset error, got: {err:?}"
        );
    }

    #[test]
    fn parse_leaf_items_rejects_overlapping_payloads() {
        let mut block = make_block(512, 2, 0);
        let base = BTRFS_HEADER_SIZE;
        let header_size = u32::try_from(BTRFS_HEADER_SIZE).expect("header size fits");

        // Item 0.
        block[base..base + 8].copy_from_slice(&1_u64.to_le_bytes());
        block[base + 8] = 1;
        block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
        let item0_offset = 200_u32;
        block[base + 17..base + 21].copy_from_slice(&(item0_offset - header_size).to_le_bytes());
        block[base + 21..base + 25].copy_from_slice(&20_u32.to_le_bytes());

        // Item 1 overlaps item 0 payload.
        let b1 = BTRFS_HEADER_SIZE + BTRFS_ITEM_SIZE;
        block[b1..b1 + 8].copy_from_slice(&2_u64.to_le_bytes());
        block[b1 + 8] = 2;
        block[b1 + 9..b1 + 17].copy_from_slice(&0_u64.to_le_bytes());
        let item1_offset = 210_u32; // overlaps 200..220
        block[b1 + 17..b1 + 21].copy_from_slice(&(item1_offset - header_size).to_le_bytes());
        block[b1 + 21..b1 + 25].copy_from_slice(&10_u32.to_le_bytes());

        let err = parse_leaf_items(&block).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "item_offset",
                    ..
                }
            ),
            "expected item_offset error, got: {err:?}"
        );
    }

    #[test]
    fn parse_leaf_items_accepts_noncanonical_nonoverlap_payload_order_bd_xmh5g_384() {
        let mut block = make_block(512, 2, 0);
        let base = BTRFS_HEADER_SIZE;
        let header_size = u32::try_from(BTRFS_HEADER_SIZE).expect("header size fits");

        // Item 0 sits lower in the block.
        block[base..base + 8].copy_from_slice(&1_u64.to_le_bytes());
        block[base + 8] = 1;
        block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
        let item0_offset = 200_u32;
        block[base + 17..base + 21].copy_from_slice(&(item0_offset - header_size).to_le_bytes());
        block[base + 21..base + 25].copy_from_slice(&10_u32.to_le_bytes());

        // Item 1 is non-overlapping but higher than item 0. That violates the
        // canonical downward-packing fast path and must fall back to exact
        // bitset coverage instead of being rejected as a layout assumption.
        let b1 = BTRFS_HEADER_SIZE + BTRFS_ITEM_SIZE;
        block[b1..b1 + 8].copy_from_slice(&2_u64.to_le_bytes());
        block[b1 + 8] = 2;
        block[b1 + 9..b1 + 17].copy_from_slice(&0_u64.to_le_bytes());
        let item1_offset = 300_u32;
        block[b1 + 17..b1 + 21].copy_from_slice(&(item1_offset - header_size).to_le_bytes());
        block[b1 + 21..b1 + 25].copy_from_slice(&10_u32.to_le_bytes());

        let (_, items) = parse_leaf_items(&block).expect("non-overlapping payloads parse");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].data_offset, item0_offset);
        assert_eq!(items[1].data_offset, item1_offset);
    }

    #[test]
    fn parse_internal_items_block_too_small() {
        // Block is too small to hold the declared items
        let mut block = make_block(140, 2, 1);
        // Need 101 + 2*33 = 167 bytes, but only have 140
        // Put a valid blockptr for item 0 so we fail on size not on blockptr
        let b0 = BTRFS_HEADER_SIZE;
        block[b0 + 17..b0 + 25].copy_from_slice(&0x4000_u64.to_le_bytes());

        let err = parse_internal_items(&block).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "nritems",
                    ..
                }
            ),
            "expected nritems error, got: {err:?}"
        );
    }

    // ── Checksum verification tests ──────────────────────────────────

    /// Build a valid superblock with correct CRC32C checksum.
    fn make_checksummed_sb() -> Vec<u8> {
        let mut sb = vec![0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes()); // sectorsize
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes()); // nodesize
        sb[0xC4..0xC6].copy_from_slice(&0_u16.to_le_bytes()); // csum_type=CRC32C
        // Compute CRC32C over bytes[0x20..4096] and store in bytes[0..4]
        let csum = crc32c::crc32c(&sb[0x20..BTRFS_SUPER_INFO_SIZE]);
        sb[0..4].copy_from_slice(&csum.to_le_bytes());
        sb
    }

    #[test]
    fn verify_superblock_checksum_valid() {
        let sb = make_checksummed_sb();
        verify_superblock_checksum(&sb).expect("valid checksum");
    }

    #[test]
    fn verify_superblock_checksum_corrupt() {
        let mut sb = make_checksummed_sb();
        // Flip a bit in the payload
        sb[0x50] ^= 0x01;
        let err = verify_superblock_checksum(&sb).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "superblock_csum",
                    ..
                }
            ),
            "expected checksum mismatch, got: {err:?}"
        );
    }

    #[test]
    fn verify_superblock_checksum_unsupported_type() {
        let mut sb = make_checksummed_sb();
        // Change csum_type to XXHASH64
        sb[0xC4..0xC6].copy_from_slice(&1_u16.to_le_bytes());
        let err = verify_superblock_checksum(&sb).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "csum_type",
                    ..
                }
            ),
            "expected unsupported csum_type error, got: {err:?}"
        );
    }

    #[test]
    fn verify_tree_block_checksum_valid() {
        let mut block = vec![0_u8; 16384]; // nodesize=16K
        // Set up a minimal header
        block[0x64] = 0; // level=0 (leaf)
        block[0x60..0x64].copy_from_slice(&0_u32.to_le_bytes()); // nritems=0
        // Compute CRC32C over bytes[0x20..] and store in [0..4]
        let csum = crc32c::crc32c(&block[0x20..]);
        block[0..4].copy_from_slice(&csum.to_le_bytes());
        verify_tree_block_checksum(&block, 0).expect("valid tree block checksum");
    }

    #[test]
    fn verify_tree_block_checksum_corrupt() {
        let mut block = vec![0_u8; 16384];
        let csum = crc32c::crc32c(&block[0x20..]);
        block[0..4].copy_from_slice(&csum.to_le_bytes());
        // Corrupt a byte
        block[0x30] ^= 0xFF;
        let err = verify_tree_block_checksum(&block, 0).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "tree_block_csum",
                    ..
                }
            ),
            "expected tree block checksum mismatch, got: {err:?}"
        );
    }

    // ── Edge-case tests (SilverWaterfall) ─────────────────────────────

    #[test]
    fn parse_from_image_too_small() {
        // Image is smaller than BTRFS_SUPER_INFO_OFFSET + BTRFS_SUPER_INFO_SIZE
        let image = vec![0_u8; BTRFS_SUPER_INFO_OFFSET + 100];
        let err = BtrfsSuperblock::parse_from_image(&image).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn parse_from_image_happy_path() {
        // Build a valid superblock at the correct offset
        let mut image = vec![0_u8; BTRFS_SUPER_INFO_OFFSET + BTRFS_SUPER_INFO_SIZE];
        let sb_region = &mut image[BTRFS_SUPER_INFO_OFFSET..];
        sb_region[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        set_valid_superblock_device_accounting(sb_region);
        sb_region[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb_region[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb_region[0x9C..0xA0].copy_from_slice(&4096_u32.to_le_bytes());
        sb_region[0x48..0x50].copy_from_slice(&42_u64.to_le_bytes());

        let parsed = BtrfsSuperblock::parse_from_image(&image).expect("parse from image");
        assert_eq!(parsed.magic, BTRFS_MAGIC);
        assert_eq!(parsed.generation, 42);
    }

    #[test]
    fn btrfs_key_equality_and_copy() {
        let k1 = BtrfsKey {
            objectid: 256,
            item_type: 132,
            offset: 0,
        };
        let k2 = k1; // Copy
        assert_eq!(k1, k2);

        let k3 = BtrfsKey {
            objectid: 256,
            item_type: 133,
            offset: 0,
        };
        assert_ne!(k1, k3);
    }

    #[test]
    fn btrfs_physical_mapping_equality_and_copy() {
        let m1 = BtrfsPhysicalMapping {
            devid: 1,
            physical: 0x4000,
        };
        let m2 = m1; // Copy
        assert_eq!(m1, m2);

        let m3 = BtrfsPhysicalMapping {
            devid: 2,
            physical: 0x4000,
        };
        assert_ne!(m1, m3);
    }

    #[test]
    fn header_parse_exactly_minimum_size() {
        let block = vec![0_u8; BTRFS_HEADER_SIZE];
        let header = BtrfsHeader::parse_from_block(&block).expect("parse at exact size");
        assert_eq!(header.level, 0);
        assert_eq!(header.nritems, 0);
    }

    #[test]
    fn header_parse_too_small() {
        let block = vec![0_u8; BTRFS_HEADER_SIZE - 1];
        let err = BtrfsHeader::parse_from_block(&block).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn superblock_rejects_oversized_sys_chunk_array() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        set_valid_superblock_device_accounting(&mut sb);
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&4096_u32.to_le_bytes());
        // Set sys_chunk_array_size to max+1
        let bad_size = u32::try_from(BTRFS_SYS_CHUNK_ARRAY_MAX).expect("fits u32") + 1;
        sb[0xA0..0xA4].copy_from_slice(&bad_size.to_le_bytes());
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "sys_chunk_array_size",
                ..
            }
        ));
    }

    #[test]
    fn map_logical_at_exact_chunk_start() {
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0x100_0000,
            },
            length: 0x80_0000,
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
                offset: 0x20_0000,
                dev_uuid: [0; 16],
            }],
        }];

        // Exact start should hit
        let result = map_logical_to_physical(&chunks, 0x100_0000).expect("no error");
        let mapping = result.expect("should hit at start");
        assert_eq!(mapping.physical, 0x20_0000);
    }

    #[test]
    fn map_logical_at_last_byte_of_chunk() {
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0x100_0000,
            },
            length: 0x80_0000,
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
                offset: 0x20_0000,
                dev_uuid: [0; 16],
            }],
        }];

        // Last valid address = start + length - 1
        let last_valid = 0x100_0000 + 0x80_0000 - 1;
        let result = map_logical_to_physical(&chunks, last_valid).expect("no error");
        let mapping = result.expect("should hit at last byte");
        assert_eq!(mapping.physical, 0x20_0000 + 0x80_0000 - 1);

        // One past end should miss
        let past_end = 0x100_0000 + 0x80_0000;
        let result = map_logical_to_physical(&chunks, past_end).expect("no error");
        assert!(result.is_none());
    }

    #[test]
    fn map_logical_multiple_chunks_selects_correct() {
        let chunks = vec![
            BtrfsChunkEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: 228,
                    offset: 0x100_0000,
                },
                length: 0x80_0000,
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
                    offset: 0x20_0000,
                    dev_uuid: [0; 16],
                }],
            },
            BtrfsChunkEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: 228,
                    offset: 0x200_0000,
                },
                length: 0x40_0000,
                owner: 2,
                stripe_len: 0x1_0000,
                chunk_type: 1,
                io_align: 4096,
                io_width: 4096,
                sector_size: 4096,
                num_stripes: 1,
                sub_stripes: 0,
                stripes: vec![BtrfsStripe {
                    devid: 2,
                    offset: 0xA0_0000,
                    dev_uuid: [0xFF; 16],
                }],
            },
        ];

        // Address in second chunk
        let result = map_logical_to_physical(&chunks, 0x210_0000).expect("no error");
        let mapping = result.expect("should hit second chunk");
        assert_eq!(mapping.devid, 2);
        assert_eq!(mapping.physical, 0xB0_0000);
    }

    #[test]
    fn verify_tree_block_checksum_at_minimum_size() {
        let mut block = vec![0_u8; BTRFS_HEADER_SIZE];
        let csum = crc32c::crc32c(&block[0x20..]);
        block[0..4].copy_from_slice(&csum.to_le_bytes());
        verify_tree_block_checksum(&block, 0).expect("valid at min size");
    }

    #[test]
    fn verify_tree_block_checksum_too_small() {
        let block = vec![0_u8; BTRFS_HEADER_SIZE - 1];
        let err = verify_tree_block_checksum(&block, 0).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn parse_sys_chunk_array_truncated_chunk_header() {
        // Just enough for a key but not enough for the chunk header
        let mut data = vec![0_u8; BTRFS_DISK_KEY_SIZE + 10];
        data[0..8].copy_from_slice(&256_u64.to_le_bytes());
        data[8] = 228;
        let err = parse_sys_chunk_array(&data).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn parse_sys_chunk_array_truncated_stripes() {
        // Key + chunk fixed header, but not enough for the stripes
        let mut data = vec![0_u8; BTRFS_DISK_KEY_SIZE + BTRFS_CHUNK_FIXED_SIZE];
        data[0..8].copy_from_slice(&256_u64.to_le_bytes());
        data[8] = 228;
        let c = BTRFS_DISK_KEY_SIZE;
        data[c..c + 8].copy_from_slice(&1_u64.to_le_bytes()); // length
        data[c + 16..c + 24].copy_from_slice(&4096_u64.to_le_bytes()); // stripe_len
        data[c + 44..c + 46].copy_from_slice(&2_u16.to_le_bytes()); // num_stripes=2
        let err = parse_sys_chunk_array(&data).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn header_validate_with_no_expected_bytenr() {
        let block = make_block(4096, 0, 0);
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        // Should succeed with None for expected_bytenr
        header.validate(4096, None).expect("should pass");
    }

    #[test]
    fn superblock_rejects_zero_sectorsize() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&0_u32.to_le_bytes()); // zero sectorsize
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "sectorsize",
                ..
            }
        ));
    }

    #[test]
    fn superblock_rejects_zero_nodesize() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&0_u32.to_le_bytes()); // zero nodesize
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "nodesize",
                ..
            }
        ));
    }

    #[test]
    fn superblock_rejects_tree_levels_above_max() {
        for (offset, field) in [
            (0xC6, "root_level"),
            (0xC7, "chunk_root_level"),
            (0xC8, "log_root_level"),
        ] {
            let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
            sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
            set_valid_superblock_device_accounting(&mut sb);
            sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
            sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
            sb[offset] = BTRFS_MAX_LEVEL + 1;

            let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
            assert_eq!(
                err,
                ParseError::InvalidField {
                    field,
                    reason: "exceeds btrfs max tree level",
                }
            );
        }
    }

    #[test]
    fn superblock_allows_zero_stripesize() {
        // Zero stripesize is explicitly allowed (not power-of-two check)
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        set_valid_superblock_device_accounting(&mut sb);
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&0_u32.to_le_bytes()); // zero stripesize
        let parsed = BtrfsSuperblock::parse_superblock_region(&sb).expect("zero stripesize ok");
        assert_eq!(parsed.stripesize, 0);
    }

    #[test]
    fn superblock_rejects_oversized_stripesize() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&524_288_u32.to_le_bytes());
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "stripesize",
                reason: "exceeds 256K upper bound",
            }
        );
    }

    #[test]
    fn leaf_items_zero_nritems() {
        let block = make_block(512, 0, 0);
        let (header, items) = parse_leaf_items(&block).expect("empty leaf");
        assert_eq!(header.nritems, 0);
        assert!(items.is_empty());
    }

    const REPRESENTATIVE_BTRFS_SUPERBLOCK_DEBUG_GOLDEN: &str = concat!(
        "BtrfsSuperblock { csum: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], ",
        "fsid: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], ",
        "bytenr: 0, flags: 0, magic: 5575266562640200287, generation: 0, root: 0, chunk_root: 0, ",
        "chunk_root_generation: 0, log_root: 0, total_bytes: 1000000, bytes_used: 123456, root_dir_objectid: 0, num_devices: 1, ",
        "sectorsize: 4096, nodesize: 16384, stripesize: 4096, compat_flags: 0, compat_ro_flags: 0, ",
        "incompat_flags: 0, csum_type: 0, root_level: 0, chunk_root_level: 0, log_root_level: 0, ",
        "label: \"\", sys_chunk_array_size: 0, sys_chunk_array: [] }",
    );

    fn representative_btrfs_superblock() -> BtrfsSuperblock {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        set_valid_superblock_device_accounting(&mut sb);
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&4096_u32.to_le_bytes());
        BtrfsSuperblock::parse_superblock_region(&sb).expect("parse")
    }

    #[test]
    fn superblock_debug_and_clone() {
        let parsed = representative_btrfs_superblock();
        let cloned = parsed.clone();
        assert_eq!(parsed, cloned);
        let dbg = format!("{parsed:?}");
        assert_eq!(dbg, REPRESENTATIVE_BTRFS_SUPERBLOCK_DEBUG_GOLDEN);
    }

    #[test]
    fn header_max_valid_level() {
        let block = make_block(4096, 0, BTRFS_MAX_LEVEL);
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        header.validate(4096, None).expect("max level ok");
        assert_eq!(header.level, 7);
    }

    #[test]
    fn key_ptr_debug_and_copy() {
        let kp = BtrfsKeyPtr {
            key: BtrfsKey {
                objectid: 1,
                item_type: 2,
                offset: 3,
            },
            blockptr: 0x4000,
            generation: 10,
        };
        let kp2 = kp; // Copy
        assert_eq!(kp, kp2);
        let dbg = format!("{kp:?}");
        assert_eq!(
            dbg,
            "BtrfsKeyPtr { key: BtrfsKey { objectid: 1, item_type: 2, offset: 3 }, blockptr: 16384, generation: 10 }"
        );
    }

    fn make_proptest_valid_btrfs_superblock(
        sectorsize: u32,
        nodesize: u32,
        sys_chunk_array: &[u8],
    ) -> [u8; BTRFS_SUPER_INFO_SIZE] {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        let sys_chunk_len_u32 =
            u32::try_from(sys_chunk_array.len()).expect("sys_chunk_array length fits in u32");

        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x30..0x38].copy_from_slice(&(BTRFS_SUPER_INFO_OFFSET as u64).to_le_bytes());
        sb[0x48..0x50].copy_from_slice(&1_u64.to_le_bytes());
        sb[0x50..0x58].copy_from_slice(&0x1000_u64.to_le_bytes());
        sb[0x58..0x60].copy_from_slice(&0x2000_u64.to_le_bytes());
        sb[0x60..0x68].copy_from_slice(&0_u64.to_le_bytes());
        sb[0x70..0x78].copy_from_slice(&1_000_000_u64.to_le_bytes());
        sb[0x78..0x80].copy_from_slice(&123_456_u64.to_le_bytes());
        sb[0x80..0x88].copy_from_slice(&6_u64.to_le_bytes());
        sb[0x88..0x90].copy_from_slice(&1_u64.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&sectorsize.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&nodesize.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&sectorsize.to_le_bytes());
        sb[0xA0..0xA4].copy_from_slice(&sys_chunk_len_u32.to_le_bytes());

        let array_end = BTRFS_SYS_CHUNK_ARRAY_OFFSET + sys_chunk_array.len();
        sb[BTRFS_SYS_CHUNK_ARRAY_OFFSET..array_end].copy_from_slice(sys_chunk_array);
        sb
    }

    fn make_proptest_header_block(block_size: usize, nritems: u32, level: u8) -> Vec<u8> {
        let mut block = vec![0_u8; block_size.max(BTRFS_HEADER_SIZE)];
        block[0x30..0x38].copy_from_slice(&0x1000_u64.to_le_bytes());
        block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
        block[0x64] = level;
        block
    }

    fn write_disk_key(buf: &mut [u8], base: usize, key: BtrfsKey) {
        buf[base..base + 8].copy_from_slice(&key.objectid.to_le_bytes());
        buf[base + 8] = key.item_type;
        buf[base + 9..base + 17].copy_from_slice(&key.offset.to_le_bytes());
    }

    fn build_sys_chunk_entry(key: BtrfsKey, num_stripes: u16) -> Vec<u8> {
        let stripes_count = usize::from(num_stripes);
        let entry_len =
            BTRFS_DISK_KEY_SIZE + BTRFS_CHUNK_FIXED_SIZE + stripes_count * BTRFS_STRIPE_SIZE;
        let mut data = vec![0_u8; entry_len];
        write_disk_key(&mut data, 0, key);

        let chunk_base = BTRFS_DISK_KEY_SIZE;
        data[chunk_base..chunk_base + 8].copy_from_slice(&0x10000_u64.to_le_bytes());
        data[chunk_base + 8..chunk_base + 16].copy_from_slice(&2_u64.to_le_bytes());
        data[chunk_base + 16..chunk_base + 24].copy_from_slice(&0x1000_u64.to_le_bytes());
        data[chunk_base + 24..chunk_base + 32]
            .copy_from_slice(&chunk_type_flags::BTRFS_BLOCK_GROUP_SYSTEM.to_le_bytes());
        data[chunk_base + 32..chunk_base + 36].copy_from_slice(&4096_u32.to_le_bytes());
        data[chunk_base + 36..chunk_base + 40].copy_from_slice(&4096_u32.to_le_bytes());
        data[chunk_base + 40..chunk_base + 44].copy_from_slice(&4096_u32.to_le_bytes());
        data[chunk_base + 44..chunk_base + 46].copy_from_slice(&num_stripes.to_le_bytes());
        data[chunk_base + 46..chunk_base + 48].copy_from_slice(&0_u16.to_le_bytes());

        let mut stripe_base = chunk_base + BTRFS_CHUNK_FIXED_SIZE;
        for stripe_idx in 0..stripes_count {
            let devid = u64::try_from(stripe_idx + 1).expect("stripe index fits in u64");
            data[stripe_base..stripe_base + 8].copy_from_slice(&devid.to_le_bytes());
            data[stripe_base + 8..stripe_base + 16]
                .copy_from_slice(&(stripe_idx as u64 * 0x2000).to_le_bytes());
            stripe_base += BTRFS_STRIPE_SIZE;
        }

        data
    }

    // Reproduce any failing case with:
    // PROPTEST_CASES=1 PROPTEST_SEED=<seed> cargo test -p ffs-ondisk <test_name> -- --nocapture
    proptest! {
        /// Full-struct round-trip: parsing a serialized `BtrfsSuperblock` must
        /// recover EVERY field except `csum` (which `to_bytes` recomputes as
        /// CRC32C over the rest of the block). Generates random superblocks whose
        /// fields satisfy the parser's validation (valid power-of-two geometry,
        /// non-zero total_bytes/num_devices, bytes_used <= total_bytes, tree
        /// levels in range, supported csum type, nul-free label, size-matched
        /// sys_chunk_array). Catches any field written to or read from a
        /// mismatched on-disk offset, or dropped from one side of the codec
        /// (bd-xmh5g.201).
        #[test]
        #[allow(clippy::too_many_arguments)]
        fn btrfs_proptest_superblock_to_bytes_parse_roundtrip(
            fsid in any::<[u8; 16]>(),
            bytenr in any::<u64>(),
            flags in any::<u64>(),
            generation in any::<u64>(),
            root in any::<u64>(),
            chunk_root in any::<u64>(),
            chunk_root_generation in any::<u64>(),
            log_root in any::<u64>(),
            total_bytes in 1_u64..=u64::MAX,
            bytes_used_raw in any::<u64>(),
            root_dir_objectid in any::<u64>(),
            num_devices in 1_u64..=u64::MAX,
            sector_shift in 9_u32..=17,
            node_shift in 9_u32..=17,
            stripe_choice in 0_u32..=9,
            compat_flags in any::<u64>(),
            compat_ro_flags in any::<u64>(),
            incompat_flags in any::<u64>(),
            root_level in 0_u8..=7,
            chunk_root_level in 0_u8..=7,
            log_root_level in 0_u8..=7,
            label in "[a-zA-Z0-9_]{0,15}",
            sys_chunk_array in proptest::collection::vec(any::<u8>(), 0..=64),
        ) {
            let sectorsize = 1_u32 << sector_shift;
            let nodesize = 1_u32 << node_shift;
            let stripesize = if stripe_choice == 0 {
                0
            } else {
                1_u32 << (8 + stripe_choice)
            };
            let bytes_used = bytes_used_raw.min(total_bytes);
            let sys_chunk_array_size =
                u32::try_from(sys_chunk_array.len()).expect("len fits u32");

            let mut sb = BtrfsSuperblock {
                csum: [0_u8; 32],
                fsid,
                bytenr,
                flags,
                magic: BTRFS_MAGIC,
                generation,
                root,
                chunk_root,
                chunk_root_generation,
                log_root,
                total_bytes,
                bytes_used,
                root_dir_objectid,
                num_devices,
                sectorsize,
                nodesize,
                stripesize,
                compat_flags,
                compat_ro_flags,
                incompat_flags,
                csum_type: ffs_types::BTRFS_CSUM_TYPE_CRC32C,
                root_level,
                chunk_root_level,
                log_root_level,
                label,
                sys_chunk_array_size,
                sys_chunk_array,
            };

            let bytes = sb.to_bytes();
            prop_assert_eq!(bytes.len(), BTRFS_SUPER_INFO_SIZE);
            let parsed = BtrfsSuperblock::parse_superblock_region(&bytes)
                .expect("a serialized valid superblock must re-parse");

            // `csum` is recomputed by `to_bytes`, not a round-trip input.
            sb.csum = parsed.csum;
            prop_assert_eq!(parsed, sb);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Serializer canonicalization: `sys_chunk_array_size` on disk must
        /// describe the payload bytes actually emitted, not a stale public field
        /// value carried by the in-memory struct (bd-6wubw).
        #[test]
        fn btrfs_proptest_superblock_to_bytes_canonicalizes_sys_chunk_array_size(
            sys_chunk_array in proptest::collection::vec(
                any::<u8>(),
                0..=(BTRFS_SYS_CHUNK_ARRAY_MAX + 64),
            ),
            stale_size in any::<u32>(),
        ) {
            let mut sb = representative_btrfs_superblock();
            sb.sys_chunk_array_size = stale_size;
            sb.sys_chunk_array = sys_chunk_array;

            let serialized = sb.to_bytes();
            let expected_len = sb.sys_chunk_array.len().min(BTRFS_SYS_CHUNK_ARRAY_MAX);
            let expected_size =
                u32::try_from(expected_len).expect("sys_chunk_array max fits in u32");
            let serialized_size = u32::from_le_bytes(
                serialized[0xA0..0xA4]
                    .try_into()
                    .expect("sys_chunk_array_size field is four bytes"),
            );
            prop_assert_eq!(serialized_size, expected_size);

            let parsed = BtrfsSuperblock::parse_superblock_region(&serialized)
                .expect("canonical serialized superblock must re-parse");
            prop_assert_eq!(parsed.sys_chunk_array_size, expected_size);
            prop_assert_eq!(
                parsed.sys_chunk_array.as_slice(),
                &sb.sys_chunk_array[..expected_len],
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Isomorphism oracle for the `parse_leaf_items` payload-overlap check
        /// after replacing the O(N^2) all-pairs scan with an O(log N) BTreeMap
        /// neighbour probe: build a leaf with strictly-increasing keys and
        /// in-bounds payloads (so the only possible failure is payload overlap),
        /// then assert the parser's accept/reject decision and parsed items
        /// match a brute-force all-pairs overlap reference exactly.
        #[test]
        fn btrfs_proptest_parse_leaf_overlap_matches_bruteforce(
            raw in proptest::collection::vec((0_u32..4000, 0_u32..300), 1..=48),
        ) {
            const BLOCK_SIZE: usize = 4096;
            let nritems = raw.len();
            let items_end = BTRFS_HEADER_SIZE + nritems * BTRFS_ITEM_SIZE;
            // Skip degenerate shapes with no room for payloads.
            prop_assume!(items_end < BLOCK_SIZE);
            let region_len = BLOCK_SIZE - items_end;
            let header_size = u32::try_from(BTRFS_HEADER_SIZE).unwrap();

            // Derive in-bounds (offset, size) per item from the raw values.
            let mut ranges: Vec<(usize, usize)> = Vec::new(); // size>0 only, in item order
            let mut block = make_block(BLOCK_SIZE, u32::try_from(nritems).unwrap(), 0);
            for (idx, (raw_off, raw_size)) in raw.iter().copied().enumerate() {
                let off = (raw_off as usize) % region_len;
                let max_size = region_len - off;
                let size = (raw_size as usize) % (max_size + 1);
                let data_offset_abs = items_end + off;
                let base = BTRFS_HEADER_SIZE + idx * BTRFS_ITEM_SIZE;
                block[base..base + 8].copy_from_slice(&(idx as u64).to_le_bytes());
                block[base + 8] = 1; // item_type
                block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
                let data_offset_rel = u32::try_from(data_offset_abs).unwrap() - header_size;
                block[base + 17..base + 21].copy_from_slice(&data_offset_rel.to_le_bytes());
                block[base + 21..base + 25]
                    .copy_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
                if size > 0 {
                    ranges.push((data_offset_abs, data_offset_abs + size));
                }
            }

            // Brute-force reference: any pair of size>0 payloads overlapping.
            let mut expect_reject = false;
            'outer: for i in 0..ranges.len() {
                for j in (i + 1)..ranges.len() {
                    let (a, b) = (ranges[i], ranges[j]);
                    if a.0 < b.1 && b.0 < a.1 {
                        expect_reject = true;
                        break 'outer;
                    }
                }
            }

            let parsed = parse_leaf_items(&block);
            prop_assert_eq!(parsed.is_err(), expect_reject);
            if let Ok((_, items)) = parsed {
                prop_assert_eq!(items.len(), nritems);
                for (idx, item) in items.iter().enumerate() {
                    prop_assert_eq!(item.key.objectid, idx as u64);
                }
            } else if let Err(err) = parsed {
                prop_assert_eq!(
                    err,
                    ParseError::InvalidField {
                        field: "item_offset",
                        reason: "item payload overlaps another item",
                    }
                );
            }
        }

        #[test]
        fn btrfs_proptest_parse_superblock_region_no_panic(
            region in proptest::collection::vec(any::<u8>(), 0..=(BTRFS_SUPER_INFO_SIZE * 2)),
        ) {
            let _ = BtrfsSuperblock::parse_superblock_region(&region);
        }

        #[test]
        fn btrfs_proptest_parse_from_image_no_panic(
            image in proptest::collection::vec(
                any::<u8>(),
                0..=(BTRFS_SUPER_INFO_OFFSET + BTRFS_SUPER_INFO_SIZE + 256),
            ),
        ) {
            let _ = BtrfsSuperblock::parse_from_image(&image);
        }

        // bd-vvkfy — Determinism MR for BtrfsSuperblock::parse_from_image.
        // parse_from_image is the image-level mount entry point: it
        // seeks to BTRFS_SUPER_INFO_OFFSET (65536) and parses the
        // superblock region. Sister parse_superblock_region (slice-
        // level entry) has its own determinism MR via bd-hlrcn; this
        // pins the image-level wrapper. A regression that introduced
        // non-deterministic mount-time bootstrap state would surface
        // here.
        #[test]
        fn btrfs_proptest_parse_from_image_determinism(
            image in proptest::collection::vec(
                any::<u8>(),
                0..=(BTRFS_SUPER_INFO_OFFSET + BTRFS_SUPER_INFO_SIZE + 256),
            ),
        ) {
            let a = BtrfsSuperblock::parse_from_image(&image);
            let b = BtrfsSuperblock::parse_from_image(&image);
            prop_assert_eq!(a, b);
        }

        #[test]
        fn btrfs_proptest_parse_sys_chunk_array_no_panic(
            data in proptest::collection::vec(any::<u8>(), 0..=BTRFS_SYS_CHUNK_ARRAY_MAX),
        ) {
            let _ = parse_sys_chunk_array(&data);
        }

        #[test]
        fn btrfs_proptest_parse_leaf_items_no_panic(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let _ = parse_leaf_items(&block);
        }

        #[test]
        fn btrfs_proptest_parse_internal_items_no_panic(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let _ = parse_internal_items(&block);
        }

        #[test]
        fn btrfs_proptest_header_parse_validate_no_panic(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            if let Ok(header) = BtrfsHeader::parse_from_block(&block) {
                let _ = header.validate(block.len(), None);
            }
        }

        // bd-xbmxq — Determinism MR for BtrfsHeader::validate composition.
        // validate is invoked after parse_from_block on every btrfs
        // tree-block read to gate level/nritems/bytenr correctness.
        // parse_from_block alone has its own determinism MR
        // (btrfs_proptest_btrfs_header_parse_from_block_determinism); this
        // pins the parse+validate composition. A regression that introduced
        // non-deterministic state in validate (e.g., HashMap-keyed dispatch
        // on block_size, allocator-address-keyed comparison) would silently
        // corrupt the gating decision on tree-block reads.
        #[test]
        fn btrfs_proptest_header_parse_validate_determinism(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
            expected_bytenr in prop_oneof![Just(None::<u64>), any::<u64>().prop_map(Some)],
        ) {
            let parse_a = BtrfsHeader::parse_from_block(&block);
            let parse_b = BtrfsHeader::parse_from_block(&block);
            prop_assert_eq!(&parse_a, &parse_b);
            if let Ok(header) = parse_a {
                let validate_a = header.validate(block.len(), expected_bytenr);
                let validate_b = header.validate(block.len(), expected_bytenr);
                prop_assert_eq!(validate_a, validate_b);
            }
        }

        #[test]
        fn btrfs_proptest_structured_superblock_size_invariants(
            sector_shift in 12_u32..=18,
            node_shift in 12_u32..=18,
        ) {
            let sectorsize = 1_u32 << sector_shift;
            let nodesize = 1_u32 << node_shift;
            let sb = make_proptest_valid_btrfs_superblock(sectorsize, nodesize, &[]);
            let parsed = BtrfsSuperblock::parse_superblock_region(&sb).expect("parse structured btrfs superblock");
            prop_assert!(parsed.sectorsize.is_power_of_two());
            prop_assert!(parsed.nodesize.is_power_of_two());
            prop_assert!(parsed.sectorsize <= 256 * 1024);
            prop_assert!(parsed.nodesize <= 256 * 1024);
        }

        #[test]
        fn btrfs_proptest_structured_sys_chunk_array_round_trip(
            sys_chunk_array in proptest::collection::vec(any::<u8>(), 0..=128),
        ) {
            let sb = make_proptest_valid_btrfs_superblock(4096, 16384, &sys_chunk_array);
            let parsed = BtrfsSuperblock::parse_superblock_region(&sb).expect("parse structured btrfs superblock");
            prop_assert_eq!(usize::try_from(parsed.sys_chunk_array_size).ok(), Some(sys_chunk_array.len()));
            prop_assert_eq!(parsed.sys_chunk_array, sys_chunk_array);
        }

        #[test]
        fn btrfs_proptest_header_validate_leaf_capacity(nritems in 0_u32..=159) {
            let block_size = 4096_usize;
            let block = make_proptest_header_block(block_size, nritems, 0);
            let header = BtrfsHeader::parse_from_block(&block).expect("parse header");
            prop_assert!(header.validate(block_size, Some(0x1000)).is_ok());
        }

        #[test]
        fn btrfs_proptest_header_validate_internal_capacity(
            nritems in 0_u32..=121,
            level in 1_u8..=BTRFS_MAX_LEVEL,
        ) {
            let block_size = 4096_usize;
            let block = make_proptest_header_block(block_size, nritems, level);
            let header = BtrfsHeader::parse_from_block(&block).expect("parse header");
            prop_assert!(header.validate(block_size, Some(0x1000)).is_ok());
        }

        #[test]
        fn btrfs_proptest_parse_from_image_matches_region_parser(
            sector_shift in 12_u32..=16,
            node_shift in 12_u32..=16,
            sys_chunk_array in proptest::collection::vec(any::<u8>(), 0..=128),
            prefix in proptest::collection::vec(any::<u8>(), BTRFS_SUPER_INFO_OFFSET..=BTRFS_SUPER_INFO_OFFSET),
            suffix in proptest::collection::vec(any::<u8>(), 0..=1024),
        ) {
            let sectorsize = 1_u32 << sector_shift;
            let nodesize = 1_u32 << node_shift;
            let sb = make_proptest_valid_btrfs_superblock(sectorsize, nodesize, &sys_chunk_array);
            let from_region = BtrfsSuperblock::parse_superblock_region(&sb).expect("structured region parse");

            let mut image = prefix;
            image.extend_from_slice(&sb);
            image.extend_from_slice(&suffix);

            let from_image = BtrfsSuperblock::parse_from_image(&image).expect("structured image parse");
            prop_assert_eq!(from_image, from_region);
        }

        #[test]
        fn btrfs_proptest_leaf_items_structured_key_roundtrip(
            n_items in 1_usize..=8,
            bytenr in any::<u64>(),
            item_types in proptest::collection::vec(any::<u8>(), 8),
            key_offsets in proptest::collection::vec(any::<u64>(), 8),
        ) {
            let mut block = vec![0_u8; 4096];
            block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
            let n_items_u32 = u32::try_from(n_items).expect("bounded n_items fits in u32");
            block[0x60..0x64].copy_from_slice(&n_items_u32.to_le_bytes());
            block[0x64] = 0;

            let data_offset_abs = u32::try_from(BTRFS_HEADER_SIZE + n_items * BTRFS_ITEM_SIZE)
                .expect("leaf item table endpoint fits in u32");
            let data_offset_rel = data_offset_abs
                .checked_sub(u32::try_from(BTRFS_HEADER_SIZE).expect("header size fits"))
                .expect("table endpoint always exceeds header size");

            for i in 0..n_items {
                let base = BTRFS_HEADER_SIZE + i * BTRFS_ITEM_SIZE;
                let key = BtrfsKey {
                    objectid: u64::try_from(i).expect("bounded item index fits in u64"),
                    item_type: item_types[i],
                    offset: key_offsets[i],
                };
                write_disk_key(&mut block, base, key);
                block[base + 17..base + 21].copy_from_slice(&data_offset_rel.to_le_bytes());
                block[base + 21..base + 25].copy_from_slice(&0_u32.to_le_bytes());
            }

            let (header, items) = parse_leaf_items(&block).expect("structured leaf parse");
            prop_assert_eq!(usize::try_from(header.nritems).ok(), Some(n_items));
            prop_assert_eq!(items.len(), n_items);

            for i in 0..n_items {
                prop_assert_eq!(
                    items[i].key.objectid,
                    u64::try_from(i).expect("bounded item index fits in u64")
                );
                prop_assert_eq!(items[i].key.item_type, item_types[i]);
                prop_assert_eq!(items[i].key.offset, key_offsets[i]);
                prop_assert_eq!(items[i].data_offset, data_offset_abs);
                prop_assert_eq!(items[i].data_size, 0);
            }
        }

        #[test]
        fn btrfs_proptest_internal_items_structured_roundtrip(
            n_items in 1_usize..=8,
            level in 1_u8..=BTRFS_MAX_LEVEL,
            bytenr in any::<u64>(),
            item_types in proptest::collection::vec(any::<u8>(), 8),
            key_offsets in proptest::collection::vec(any::<u64>(), 8),
            blockptrs in proptest::collection::vec(1_u64..=u64::MAX, 8),
            generations in proptest::collection::vec(any::<u64>(), 8),
        ) {
            let mut block = vec![0_u8; 4096];
            block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
            let n_items_u32 = u32::try_from(n_items).expect("bounded n_items fits in u32");
            block[0x60..0x64].copy_from_slice(&n_items_u32.to_le_bytes());
            block[0x64] = level;

            for i in 0..n_items {
                let base = BTRFS_HEADER_SIZE + i * BTRFS_KEY_PTR_SIZE;
                let key = BtrfsKey {
                    objectid: u64::try_from(i).expect("bounded item index fits in u64"),
                    item_type: item_types[i],
                    offset: key_offsets[i],
                };
                write_disk_key(&mut block, base, key);
                block[base + 17..base + 25].copy_from_slice(&blockptrs[i].to_le_bytes());
                block[base + 25..base + 33].copy_from_slice(&generations[i].to_le_bytes());
            }

            let (header, ptrs) = parse_internal_items(&block).expect("structured internal parse");
            prop_assert_eq!(header.level, level);
            prop_assert_eq!(usize::try_from(header.nritems).ok(), Some(n_items));
            prop_assert_eq!(ptrs.len(), n_items);

            for i in 0..n_items {
                prop_assert_eq!(
                    ptrs[i].key.objectid,
                    u64::try_from(i).expect("bounded item index fits in u64")
                );
                prop_assert_eq!(ptrs[i].key.item_type, item_types[i]);
                prop_assert_eq!(ptrs[i].key.offset, key_offsets[i]);
                prop_assert_eq!(ptrs[i].blockptr, blockptrs[i]);
                prop_assert_eq!(ptrs[i].generation, generations[i]);
            }
        }

        #[test]
        fn btrfs_proptest_sys_chunk_array_structured_single_entry_roundtrip(
            key_offset in any::<u64>(),
            length in 1_u64..=1_000_000_u64,
            owner in any::<u64>(),
            stripe_len in 1_u64..=1_000_000_u64,
            chunk_type in any::<u64>(),
            io_align in any::<u32>(),
            io_width in any::<u32>(),
            sector_size in 1_u32..=65536_u32,
            num_stripes in 1_u16..=4_u16,
            sub_stripes in any::<u16>(),
            devids in proptest::collection::vec(any::<u64>(), 4),
            offsets in proptest::collection::vec(any::<u64>(), 4),
        ) {
            let raid_bits = chunk_type & chunk_type_flags::RAID_MASK;
            let raid_bit = if raid_bits == 0 {
                0
            } else {
                1_u64 << raid_bits.trailing_zeros()
            };
            let sanitized_chunk_type = (chunk_type & !chunk_type_flags::RAID_MASK) | raid_bit;
            let profile = BtrfsRaidProfile::from_chunk_type(sanitized_chunk_type);
            let valid_num_stripes = match profile {
                BtrfsRaidProfile::Single => 1,
                BtrfsRaidProfile::Dup | BtrfsRaidProfile::Raid1 => num_stripes.max(2),
                BtrfsRaidProfile::Raid1C3 => num_stripes.max(3),
                BtrfsRaidProfile::Raid1C4 => 4,
                _ => num_stripes,
            };
            let stripes_count = usize::from(valid_num_stripes);
            let entry_len = BTRFS_DISK_KEY_SIZE + BTRFS_CHUNK_FIXED_SIZE + stripes_count * BTRFS_STRIPE_SIZE;
            let mut data = vec![0_u8; entry_len];

            let key = BtrfsKey {
                objectid: BTRFS_FIRST_CHUNK_TREE_OBJECTID,
                item_type: BTRFS_CHUNK_ITEM_KEY,
                offset: key_offset,
            };
            write_disk_key(&mut data, 0, key);

            let chunk_base = BTRFS_DISK_KEY_SIZE;
            data[chunk_base..chunk_base + 8].copy_from_slice(&length.to_le_bytes());
            data[chunk_base + 8..chunk_base + 16].copy_from_slice(&owner.to_le_bytes());
            data[chunk_base + 16..chunk_base + 24].copy_from_slice(&stripe_len.to_le_bytes());
            data[chunk_base + 24..chunk_base + 32].copy_from_slice(&sanitized_chunk_type.to_le_bytes());
            data[chunk_base + 32..chunk_base + 36].copy_from_slice(&io_align.to_le_bytes());
            data[chunk_base + 36..chunk_base + 40].copy_from_slice(&io_width.to_le_bytes());
            data[chunk_base + 40..chunk_base + 44].copy_from_slice(&sector_size.to_le_bytes());
            data[chunk_base + 44..chunk_base + 46].copy_from_slice(&valid_num_stripes.to_le_bytes());
            data[chunk_base + 46..chunk_base + 48].copy_from_slice(&sub_stripes.to_le_bytes());

            let mut stripe_base = chunk_base + BTRFS_CHUNK_FIXED_SIZE;
            for i in 0..stripes_count {
                let devid = if profile == BtrfsRaidProfile::Dup {
                    devids[0].saturating_add(1)
                } else {
                    devids[i].saturating_add(1)
                };
                data[stripe_base..stripe_base + 8].copy_from_slice(&devid.to_le_bytes());
                data[stripe_base + 8..stripe_base + 16].copy_from_slice(&offsets[i].to_le_bytes());
                stripe_base += BTRFS_STRIPE_SIZE;
            }

            let parsed = parse_sys_chunk_array(&data).expect("structured sys_chunk parse");
            prop_assert_eq!(parsed.len(), 1);
            let entry = &parsed[0];
            prop_assert_eq!(entry.key, key);
            prop_assert_eq!(entry.length, length);
            prop_assert_eq!(entry.owner, owner);
            prop_assert_eq!(entry.stripe_len, stripe_len);
            prop_assert_eq!(entry.chunk_type, sanitized_chunk_type);
            prop_assert_eq!(entry.io_align, io_align);
            prop_assert_eq!(entry.io_width, io_width);
            prop_assert_eq!(entry.sector_size, sector_size);
            prop_assert_eq!(entry.num_stripes, valid_num_stripes);
            prop_assert_eq!(entry.sub_stripes, sub_stripes);
            prop_assert_eq!(entry.stripes.len(), stripes_count);
            for i in 0..stripes_count {
                let expected_devid = if profile == BtrfsRaidProfile::Dup {
                    devids[0].saturating_add(1)
                } else {
                    devids[i].saturating_add(1)
                };
                prop_assert_eq!(entry.stripes[i].devid, expected_devid);
                prop_assert_eq!(entry.stripes[i].offset, offsets[i]);
            }
        }

        #[test]
        fn btrfs_proptest_map_logical_to_physical_single_chunk(
            chunk_start in 0_u64..=1_000_000_u64,
            length in 1_u64..=1_000_000_u64,
            stripe_devid in any::<u64>(),
            stripe_offset in 0_u64..=1_000_000_u64,
            delta in 0_u64..=1_000_000_u64,
        ) {
            prop_assume!(delta < length);
            let logical = chunk_start.checked_add(delta).expect("bounded logical address");
            let physical = stripe_offset.checked_add(delta).expect("bounded physical address");
            let chunk = BtrfsChunkEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: 228,
                    offset: chunk_start,
                },
                length,
                owner: 2,
                stripe_len: 64 * 1024,
                chunk_type: 1,
                io_align: 4096,
                io_width: 4096,
                sector_size: 4096,
                num_stripes: 1,
                sub_stripes: 1,
                stripes: vec![BtrfsStripe {
                    devid: stripe_devid,
                    offset: stripe_offset,
                    dev_uuid: [0_u8; 16],
                }],
            };

            let mapped = map_logical_to_physical(&[chunk], logical).expect("map should succeed");
            prop_assert_eq!(
                mapped,
                Some(BtrfsPhysicalMapping {
                    devid: stripe_devid,
                    physical,
                })
            );
        }

        /// The binary-search fast path (chunks.len() > 16) must agree with an
        /// independent linear scan for hits, gaps, and out-of-range logicals.
        /// All other map tests use <= 2 chunks, so the partition_point path
        /// (bd-6u6xb) was never exercised before.
        #[test]
        fn btrfs_proptest_map_logical_to_physical_binary_path_matches_linear(
            specs in proptest::collection::vec(
                (1_u64..=1000, 0_u64..=500, 0_u64..=10_000_000),
                17..=24,
            ),
            probe in 0_u64..=40_000,
        ) {
            // Build disjoint, ascending-by-offset Single chunks. With 17..=24
            // entries the list always exceeds CHUNK_MAP_BINARY_SEARCH_THRESHOLD.
            let mut chunks = Vec::new();
            let mut next_start = 0_u64;
            for (length, gap, stripe_offset) in &specs {
                next_start += gap;
                let start = next_start;
                chunks.push(BtrfsChunkEntry {
                    key: BtrfsKey { objectid: 256, item_type: 228, offset: start },
                    length: *length,
                    owner: 2,
                    stripe_len: 64 * 1024,
                    chunk_type: 1,
                    io_align: 4096,
                    io_width: 4096,
                    sector_size: 4096,
                    num_stripes: 1,
                    sub_stripes: 1,
                    stripes: vec![BtrfsStripe {
                        devid: 1,
                        offset: *stripe_offset,
                        dev_uuid: [0_u8; 16],
                    }],
                });
                next_start += length;
            }
            prop_assert!(chunks.len() > 16);

            let logical = probe;
            // Independent reference: the single covering chunk, if any.
            let expected = chunks
                .iter()
                .find(|c| logical >= c.key.offset && logical < c.key.offset + c.length)
                .map(|c| BtrfsPhysicalMapping {
                    devid: c.stripes[0].devid,
                    physical: c.stripes[0].offset + (logical - c.key.offset),
                });

            let got = map_logical_to_physical(&chunks, logical).expect("map should succeed");
            prop_assert_eq!(got, expected);
        }

        /// Stripe dual of the previous test: map_logical_to_stripes has the same
        /// binary-search fast path (chunks.len() > 16) and the same small-list
        /// test coverage gap. Compare its result against a linear scan using the
        /// shared chunk_stripes resolver, isolating the partition_point logic.
        #[test]
        fn btrfs_proptest_map_logical_to_stripes_binary_path_matches_linear(
            specs in proptest::collection::vec(
                (1_u64..=1000, 0_u64..=500, 0_u64..=10_000_000),
                17..=24,
            ),
            probe in 0_u64..=40_000,
        ) {
            let mut chunks = Vec::new();
            let mut next_start = 0_u64;
            for (length, gap, stripe_offset) in &specs {
                next_start += gap;
                let start = next_start;
                chunks.push(BtrfsChunkEntry {
                    key: BtrfsKey { objectid: 256, item_type: 228, offset: start },
                    length: *length,
                    owner: 2,
                    stripe_len: 64 * 1024,
                    chunk_type: 1,
                    io_align: 4096,
                    io_width: 4096,
                    sector_size: 4096,
                    num_stripes: 1,
                    sub_stripes: 1,
                    stripes: vec![BtrfsStripe {
                        devid: 1,
                        offset: *stripe_offset,
                        dev_uuid: [0_u8; 16],
                    }],
                });
                next_start += length;
            }
            prop_assert!(chunks.len() > 16);

            // Linear-scan reference via the same per-chunk resolver both paths
            // call, so any mismatch is purely a selection (partition_point) bug.
            let logical = probe;
            let mut expected = None;
            for chunk in &chunks {
                if let Some(mapping) = chunk_stripes(chunk, logical).expect("chunk_stripes") {
                    expected = Some(mapping);
                    break;
                }
            }

            let got = map_logical_to_stripes(&chunks, logical).expect("map should succeed");
            prop_assert_eq!(got, expected);
        }

        #[test]
        fn btrfs_proptest_logical_mapping_translation_covariant(
            chunk_start in 0_u64..=1_000_000_u64,
            length in 1_u64..=1_000_000_u64,
            stripe_offset in 0_u64..=1_000_000_u64,
            logical_shift in 0_u64..=1_000_000_u64,
            physical_shift in 0_u64..=1_000_000_u64,
            delta in 0_u64..=1_000_000_u64,
        ) {
            prop_assume!(delta < length);

            let logical = chunk_start
                .checked_add(delta)
                .expect("bounded logical address");
            let shifted_start = chunk_start
                .checked_add(logical_shift)
                .expect("bounded shifted chunk start");
            let shifted_logical = shifted_start
                .checked_add(delta)
                .expect("bounded shifted logical address");
            let shifted_offset = stripe_offset
                .checked_add(physical_shift)
                .expect("bounded shifted stripe offset");

            let chunks = vec![make_chunk(
                chunk_start,
                length,
                64 * 1024,
                chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
                vec![stripe(7, stripe_offset)],
                0,
            )];
            let shifted_chunks = vec![make_chunk(
                shifted_start,
                length,
                64 * 1024,
                chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
                vec![stripe(7, shifted_offset)],
                0,
            )];

            let base_physical =
                map_logical_to_physical(&chunks, logical).expect("map should succeed");
            let shifted_physical = map_logical_to_physical(&shifted_chunks, shifted_logical)
                .expect("shifted map should succeed");
            let base_stripes = map_logical_to_stripes(&chunks, logical)
                .expect("stripe map should succeed")
                .expect("logical should be covered");
            let shifted_stripes = map_logical_to_stripes(&shifted_chunks, shifted_logical)
                .expect("shifted stripe map should succeed")
                .expect("shifted logical should be covered");

            prop_assert_eq!(
                base_physical,
                Some(BtrfsPhysicalMapping {
                    devid: 7,
                    physical: stripe_offset
                        .checked_add(delta)
                        .expect("bounded base physical address"),
                })
            );
            prop_assert_eq!(
                shifted_physical,
                Some(BtrfsPhysicalMapping {
                    devid: 7,
                    physical: shifted_offset
                        .checked_add(delta)
                        .expect("bounded shifted physical address"),
                })
            );
            prop_assert_eq!(base_stripes.profile, shifted_stripes.profile);
            prop_assert_eq!(base_stripes.stripes.len(), shifted_stripes.stripes.len());
            for (base, shifted) in base_stripes.stripes.iter().zip(&shifted_stripes.stripes) {
                prop_assert_eq!(shifted.devid, base.devid);
                prop_assert_eq!(
                    shifted.physical,
                    base.physical
                        .checked_add(physical_shift)
                        .expect("bounded translated stripe physical")
                );
            }
        }

        #[test]
        fn btrfs_proptest_mapping_chunk_order_permutation_invariant(
            first_start in 0_u64..=1_000_000_u64,
            first_length in 1_u64..=1_000_000_u64,
            gap in 1_u64..=1_000_000_u64,
            second_length in 1_u64..=1_000_000_u64,
            first_offset in 0_u64..=1_000_000_u64,
            second_offset in 0_u64..=1_000_000_u64,
            delta in 0_u64..=1_000_000_u64,
            query_second in any::<bool>(),
        ) {
            let first_end = first_start
                .checked_add(first_length)
                .expect("bounded first chunk end");
            let second_start = first_end
                .checked_add(gap)
                .expect("bounded second chunk start");
            let target_start = if query_second { second_start } else { first_start };
            let target_length = if query_second { second_length } else { first_length };
            prop_assume!(delta < target_length);

            let logical = target_start
                .checked_add(delta)
                .expect("bounded query logical address");

            let first_chunk = make_chunk(
                first_start,
                first_length,
                64 * 1024,
                chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
                vec![stripe(11, first_offset)],
                0,
            );
            let second_chunk = make_chunk(
                second_start,
                second_length,
                64 * 1024,
                chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
                vec![stripe(22, second_offset)],
                0,
            );

            let ordered = vec![first_chunk.clone(), second_chunk.clone()];
            let permuted = vec![second_chunk, first_chunk];

            prop_assert_eq!(
                map_logical_to_physical(&ordered, logical),
                map_logical_to_physical(&permuted, logical)
            );
            prop_assert_eq!(
                map_logical_to_stripes(&ordered, logical),
                map_logical_to_stripes(&permuted, logical)
            );
        }

        #[test]
        fn btrfs_proptest_dup_primary_mapping_matches_single(
            chunk_start in 0_u64..=1_000_000_u64,
            length in 1_u64..=1_000_000_u64,
            first_offset in 0_u64..=1_000_000_u64,
            second_offset in 0_u64..=1_000_000_u64,
            delta in 0_u64..=1_000_000_u64,
        ) {
            prop_assume!(delta < length);

            let logical = chunk_start
                .checked_add(delta)
                .expect("bounded logical address");
            let single_chunk = vec![make_chunk(
                chunk_start,
                length,
                64 * 1024,
                chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
                vec![stripe(5, first_offset)],
                0,
            )];
            let dup_chunk = vec![make_chunk(
                chunk_start,
                length,
                64 * 1024,
                chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_DUP,
                vec![stripe(5, first_offset), stripe(5, second_offset)],
                0,
            )];

            let single_physical = map_logical_to_physical(&single_chunk, logical)
                .expect("single map should succeed")
                .expect("single chunk should cover the logical address");
            let dup_physical = map_logical_to_physical(&dup_chunk, logical)
                .expect("dup map should succeed")
                .expect("dup chunk should cover the logical address");
            let single_stripes = map_logical_to_stripes(&single_chunk, logical)
                .expect("single stripe map should succeed")
                .expect("single chunk should cover the logical address");
            let dup_stripes = map_logical_to_stripes(&dup_chunk, logical)
                .expect("dup stripe map should succeed")
                .expect("dup chunk should cover the logical address");

            prop_assert_eq!(dup_physical, single_physical);
            prop_assert_eq!(single_stripes.profile, BtrfsRaidProfile::Single);
            prop_assert_eq!(dup_stripes.profile, BtrfsRaidProfile::Dup);
            prop_assert_eq!(single_stripes.stripes.len(), 1);
            prop_assert_eq!(dup_stripes.stripes.len(), 2);
            prop_assert_eq!(dup_stripes.stripes[0], single_stripes.stripes[0]);
            prop_assert_eq!(
                dup_stripes.stripes[1],
                BtrfsPhysicalMapping {
                    devid: 5,
                    physical: second_offset
                        .checked_add(delta)
                        .expect("bounded dup replica physical")
                }
            );
        }

        #[test]
        fn btrfs_proptest_superblock_checksum_roundtrip_with_tamper_detection(
            sector_shift in 12_u32..=16,
            node_shift in 12_u32..=16,
            sys_chunk_array in proptest::collection::vec(any::<u8>(), 0..=64),
            flip_index in 0x20_usize..BTRFS_SUPER_INFO_SIZE,
        ) {
            let sectorsize = 1_u32 << sector_shift;
            let nodesize = 1_u32 << node_shift;
            let mut sb = make_proptest_valid_btrfs_superblock(sectorsize, nodesize, &sys_chunk_array);
            sb[0xC4..0xC6].copy_from_slice(&ffs_types::BTRFS_CSUM_TYPE_CRC32C.to_le_bytes());
            let csum = crc32c::crc32c(&sb[0x20..]);
            sb[0..4].copy_from_slice(&csum.to_le_bytes());

            verify_superblock_checksum(&sb).expect("checksum should verify before tamper");
            sb[flip_index] ^= 0x01;
            prop_assert!(verify_superblock_checksum(&sb).is_err());
        }

        #[test]
        fn btrfs_proptest_tree_block_checksum_roundtrip_with_tamper_detection(
            block_len in 256_usize..=4096_usize,
            seed in any::<u8>(),
            flip_index in 0x20_usize..4096_usize,
        ) {
            prop_assume!(flip_index < block_len);
            let mut block = vec![seed; block_len];
            let csum = crc32c::crc32c(&block[0x20..]);
            block[0..4].copy_from_slice(&csum.to_le_bytes());
            verify_tree_block_checksum(&block, ffs_types::BTRFS_CSUM_TYPE_CRC32C)
                .expect("tree block checksum should verify before tamper");

            block[flip_index] ^= 0x80;
            prop_assert!(
                verify_tree_block_checksum(&block, ffs_types::BTRFS_CSUM_TYPE_CRC32C).is_err()
            );
        }

        #[test]
        fn btrfs_proptest_header_validate_bytenr_match_contract(
            bytenr in any::<u64>(),
            expected in any::<u64>(),
        ) {
            let mut block = make_proptest_header_block(4096, 0, 0);
            block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
            let header = BtrfsHeader::parse_from_block(&block).expect("parse header");

            let result = header.validate(block.len(), Some(expected));
            if bytenr == expected {
                prop_assert!(result.is_ok());
            } else {
                assert!(matches!(
                    result,
                    Err(ParseError::InvalidField {
                        field: "bytenr",
                        ..
                    })
                ));
            }
        }

        #[test]
        fn btrfs_proptest_header_validate_rejects_levels_above_max(level in (BTRFS_MAX_LEVEL + 1)..=u8::MAX) {
            let block = make_proptest_header_block(4096, 0, level);
            let header = BtrfsHeader::parse_from_block(&block).expect("parse header");
            assert!(matches!(
                header.validate(block.len(), None),
                Err(ParseError::InvalidField {
                    field: "level",
                    ..
                })
            ));
        }

        #[test]
        fn btrfs_proptest_superblock_rejects_invalid_non_power_of_two_stripesize(
            stripesize in 1_u32..=200_000_u32,
        ) {
            prop_assume!(!stripesize.is_power_of_two());
            let mut sb = make_proptest_valid_btrfs_superblock(4096, 16384, &[]);
            sb[0x9C..0xA0].copy_from_slice(&stripesize.to_le_bytes());
            assert!(matches!(
                BtrfsSuperblock::parse_superblock_region(&sb),
                Err(ParseError::InvalidField {
                    field: "stripesize",
                    ..
                })
            ));
        }

        // ── Additional semantic / roundtrip proptest tests (GreenSnow) ──

        /// Superblock field preservation: construct a valid SB with random
        /// field values, parse it, verify all scalar fields are preserved.
        #[test]
        fn btrfs_proptest_superblock_fields_preserved(
            sector_shift in 12_u32..=17,
            node_shift in 12_u32..=17,
            generation in any::<u64>(),
            root in any::<u64>(),
            chunk_root in any::<u64>(),
            log_root in any::<u64>(),
            total_bytes in 1_u64..=u64::MAX,
            bytes_used_seed in any::<u64>(),
            root_dir_objectid in any::<u64>(),
            num_devices in 1_u64..=u64::MAX,
            compat_flags in any::<u64>(),
            compat_ro_flags in any::<u64>(),
            incompat_flags in any::<u64>(),
            root_level in 0_u8..=BTRFS_MAX_LEVEL,
            chunk_root_level in 0_u8..=BTRFS_MAX_LEVEL,
            log_root_level in 0_u8..=BTRFS_MAX_LEVEL,
        ) {
            let sectorsize = 1_u32 << sector_shift;
            let nodesize = 1_u32 << node_shift;
            let csum_type = ffs_types::BTRFS_CSUM_TYPE_CRC32C;
            let bytes_used = if total_bytes == u64::MAX {
                bytes_used_seed
            } else {
                bytes_used_seed % (total_bytes + 1)
            };
            let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
            sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
            sb[0x48..0x50].copy_from_slice(&generation.to_le_bytes());
            sb[0x50..0x58].copy_from_slice(&root.to_le_bytes());
            sb[0x58..0x60].copy_from_slice(&chunk_root.to_le_bytes());
            sb[0x60..0x68].copy_from_slice(&log_root.to_le_bytes());
            sb[0x70..0x78].copy_from_slice(&total_bytes.to_le_bytes());
            sb[0x78..0x80].copy_from_slice(&bytes_used.to_le_bytes());
            sb[0x80..0x88].copy_from_slice(&root_dir_objectid.to_le_bytes());
            sb[0x88..0x90].copy_from_slice(&num_devices.to_le_bytes());
            sb[0x90..0x94].copy_from_slice(&sectorsize.to_le_bytes());
            sb[0x94..0x98].copy_from_slice(&nodesize.to_le_bytes());
            sb[0x9C..0xA0].copy_from_slice(&sectorsize.to_le_bytes()); // stripesize
            sb[0xAC..0xB4].copy_from_slice(&compat_flags.to_le_bytes());
            sb[0xB4..0xBC].copy_from_slice(&compat_ro_flags.to_le_bytes());
            sb[0xBC..0xC4].copy_from_slice(&incompat_flags.to_le_bytes());
            sb[0xC4..0xC6].copy_from_slice(&csum_type.to_le_bytes());
            sb[0xC6] = root_level;
            sb[0xC7] = chunk_root_level;
            sb[0xC8] = log_root_level;

            let parsed = BtrfsSuperblock::parse_superblock_region(&sb)
                .expect("parse structured sb");
            prop_assert_eq!(parsed.magic, BTRFS_MAGIC);
            prop_assert_eq!(parsed.generation, generation);
            prop_assert_eq!(parsed.root, root);
            prop_assert_eq!(parsed.chunk_root, chunk_root);
            prop_assert_eq!(parsed.log_root, log_root);
            prop_assert_eq!(parsed.total_bytes, total_bytes);
            prop_assert_eq!(parsed.bytes_used, bytes_used);
            prop_assert_eq!(parsed.root_dir_objectid, root_dir_objectid);
            prop_assert_eq!(parsed.num_devices, num_devices);
            prop_assert_eq!(parsed.sectorsize, sectorsize);
            prop_assert_eq!(parsed.nodesize, nodesize);
            prop_assert_eq!(parsed.stripesize, sectorsize);
            prop_assert_eq!(parsed.compat_flags, compat_flags);
            prop_assert_eq!(parsed.compat_ro_flags, compat_ro_flags);
            prop_assert_eq!(parsed.incompat_flags, incompat_flags);
            prop_assert_eq!(parsed.csum_type, csum_type);
            prop_assert_eq!(parsed.root_level, root_level);
            prop_assert_eq!(parsed.chunk_root_level, chunk_root_level);
            prop_assert_eq!(parsed.log_root_level, log_root_level);
        }

        /// Superblock label preservation: random ASCII labels survive roundtrip.
        #[test]
        fn btrfs_proptest_superblock_label_preserved(
            label_bytes in proptest::collection::vec(0x21_u8..=0x7E, 0..=64),
        ) {
            let expected_label = String::from_utf8(label_bytes.clone())
                .unwrap_or_default();
            let mut sb = make_proptest_valid_btrfs_superblock(4096, 16384, &[]);
            for (i, &b) in label_bytes.iter().enumerate() {
                if i < BTRFS_SUPER_LABEL_LEN {
                    sb[BTRFS_SUPER_LABEL_OFFSET + i] = b;
                }
            }
            if label_bytes.len() < BTRFS_SUPER_LABEL_LEN {
                sb[BTRFS_SUPER_LABEL_OFFSET + label_bytes.len()] = 0;
            }

            let parsed = BtrfsSuperblock::parse_superblock_region(&sb)
                .expect("parse sb with label");
            prop_assert_eq!(parsed.label, expected_label);
        }

        /// BtrfsKey roundtrip via leaf item: write key bytes, parse, verify.
        #[test]
        fn btrfs_proptest_key_roundtrip_via_leaf(
            objectid in any::<u64>(),
            item_type in any::<u8>(),
            offset in any::<u64>(),
        ) {
            let mut block = vec![0_u8; 512];
            block[0x60..0x64].copy_from_slice(&1_u32.to_le_bytes());
            block[0x64] = 0; // leaf
            let base = BTRFS_HEADER_SIZE;
            let key = BtrfsKey { objectid, item_type, offset };
            write_disk_key(&mut block, base, key);
            block[base + 17..base + 21]
                .copy_from_slice(&(200_u32 - u32::try_from(BTRFS_HEADER_SIZE).unwrap()).to_le_bytes());
            block[base + 21..base + 25].copy_from_slice(&8_u32.to_le_bytes());

            let (_, items) = parse_leaf_items(&block).expect("parse leaf");
            prop_assert_eq!(items[0].key.objectid, objectid);
            prop_assert_eq!(items[0].key.item_type, item_type);
            prop_assert_eq!(items[0].key.offset, offset);
        }

        /// BtrfsHeader field preservation: random fields, parse, verify all.
        #[test]
        fn btrfs_proptest_header_fields_preserved(
            csum in proptest::collection::vec(any::<u8>(), 32..=32),
            fsid in proptest::collection::vec(any::<u8>(), 16..=16),
            bytenr in any::<u64>(),
            flags in any::<u64>(),
            chunk_tree_uuid in proptest::collection::vec(any::<u8>(), 16..=16),
            generation in any::<u64>(),
            owner in any::<u64>(),
            nritems in 0_u32..=10,
            level in 0_u8..=BTRFS_MAX_LEVEL,
        ) {
            let mut block = vec![0_u8; 4096];
            block[0x00..0x20].copy_from_slice(&csum);
            block[0x20..0x30].copy_from_slice(&fsid);
            block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
            block[0x38..0x40].copy_from_slice(&flags.to_le_bytes());
            block[0x40..0x50].copy_from_slice(&chunk_tree_uuid);
            block[0x50..0x58].copy_from_slice(&generation.to_le_bytes());
            block[0x58..0x60].copy_from_slice(&owner.to_le_bytes());
            block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
            block[0x64] = level;

            let header = BtrfsHeader::parse_from_block(&block)
                .expect("parse header");
            prop_assert_eq!(&header.csum, csum.as_slice());
            prop_assert_eq!(&header.fsid, fsid.as_slice());
            prop_assert_eq!(header.bytenr, bytenr);
            prop_assert_eq!(header.flags, flags);
            prop_assert_eq!(&header.chunk_tree_uuid, chunk_tree_uuid.as_slice());
            prop_assert_eq!(header.generation, generation);
            prop_assert_eq!(header.owner, owner);
            prop_assert_eq!(header.nritems, nritems);
            prop_assert_eq!(header.level, level);
        }

        /// map_logical_to_physical miss: address outside any chunk returns None.
        #[test]
        fn btrfs_proptest_logical_to_physical_miss(
            chunk_start in 0x1000_u64..=0xFFFF_FFFF,
            chunk_length in 1_u64..=0x100_0000,
        ) {
            let chunks = vec![BtrfsChunkEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: 228,
                    offset: chunk_start,
                },
                length: chunk_length,
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
                    offset: 0,
                    dev_uuid: [0; 16],
                }],
            }];

            // Address before chunk start
            if chunk_start > 0 {
                let result = map_logical_to_physical(&chunks, chunk_start - 1)
                    .expect("no error");
                prop_assert!(result.is_none(), "Address before chunk should miss");
            }

            // Address at chunk_start + length (one past end)
            if let Some(end) = chunk_start.checked_add(chunk_length) {
                let result = map_logical_to_physical(&chunks, end)
                    .expect("no error");
                prop_assert!(result.is_none(), "Address at chunk end should miss");
            }
        }

        /// Superblock rejects zero sectorsize.
        #[test]
        fn btrfs_proptest_superblock_rejects_zero_sectorsize(
            nodesize_shift in 12_u32..=17,
        ) {
            let nodesize = 1_u32 << nodesize_shift;
            let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
            sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
            sb[0x90..0x94].copy_from_slice(&0_u32.to_le_bytes());
            sb[0x94..0x98].copy_from_slice(&nodesize.to_le_bytes());
            let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
            assert!(matches!(
                err,
                ParseError::InvalidField { field: "sectorsize", .. }
            ));
        }

        /// Superblock rejects zero nodesize.
        #[test]
        fn btrfs_proptest_superblock_rejects_zero_nodesize(
            sectorsize_shift in 12_u32..=17,
        ) {
            let sectorsize = 1_u32 << sectorsize_shift;
            let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
            sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
            sb[0x90..0x94].copy_from_slice(&sectorsize.to_le_bytes());
            sb[0x94..0x98].copy_from_slice(&0_u32.to_le_bytes());
            let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
            assert!(matches!(
                err,
                ParseError::InvalidField { field: "nodesize", .. }
            ));
        }

        /// Superblock rejects sectorsize > 256K.
        #[test]
        fn btrfs_proptest_superblock_rejects_oversized_sectorsize(
            shift in 19_u32..=30,
        ) {
            let sectorsize = 1_u32 << shift;
            let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
            sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
            sb[0x90..0x94].copy_from_slice(&sectorsize.to_le_bytes());
            sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
            let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
            assert!(matches!(
                err,
                ParseError::InvalidField { field: "sectorsize", .. }
            ));
        }

        /// Superblock rejects nodesize > 256K.
        #[test]
        fn btrfs_proptest_superblock_rejects_oversized_nodesize(
            shift in 19_u32..=30,
        ) {
            let nodesize = 1_u32 << shift;
            let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
            sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
            sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
            sb[0x94..0x98].copy_from_slice(&nodesize.to_le_bytes());
            let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
            assert!(matches!(
                err,
                ParseError::InvalidField { field: "nodesize", .. }
            ));
        }

        /// Superblock rejects nonzero stripesize > 256K.
        #[test]
        fn btrfs_proptest_superblock_rejects_oversized_stripesize(
            shift in 19_u32..=30,
        ) {
            let stripesize = 1_u32 << shift;
            let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
            sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
            sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
            sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
            sb[0x9C..0xA0].copy_from_slice(&stripesize.to_le_bytes());
            let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
            assert!(matches!(
                err,
                ParseError::InvalidField { field: "stripesize", .. }
            ));
        }

        /// Header validate rejects nritems above leaf capacity.
        #[test]
        fn btrfs_proptest_header_validate_rejects_overflow_leaf(
            nritems in 160_u32..=500,
        ) {
            let block = make_proptest_header_block(4096, nritems, 0);
            let header = BtrfsHeader::parse_from_block(&block)
                .expect("parse");
            let result = header.validate(4096, None);
            prop_assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ParseError::InvalidField { field: "nritems", .. }
            ));
        }

        /// Header validate rejects nritems above internal capacity.
        #[test]
        fn btrfs_proptest_header_validate_rejects_overflow_internal(
            nritems in 122_u32..=500,
            level in 1_u8..=BTRFS_MAX_LEVEL,
        ) {
            let block = make_proptest_header_block(4096, nritems, level);
            let header = BtrfsHeader::parse_from_block(&block)
                .expect("parse");
            let result = header.validate(4096, None);
            prop_assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ParseError::InvalidField { field: "nritems", .. }
            ));
        }

        /// parse_leaf_items rejects blocks with level > 0.
        #[test]
        fn btrfs_proptest_parse_leaf_rejects_nonzero_level(
            level in 1_u8..=BTRFS_MAX_LEVEL,
        ) {
            let block = make_proptest_header_block(4096, 0, level);
            let result = parse_leaf_items(&block);
            prop_assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ParseError::InvalidField { field: "level", .. }
            ));
        }

        /// parse_internal_items rejects blocks with level == 0.
        #[test]
        fn btrfs_proptest_parse_internal_rejects_level_zero(
            nritems in 0_u32..=10,
        ) {
            let block = make_proptest_header_block(4096, nritems, 0);
            let result = parse_internal_items(&block);
            prop_assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ParseError::InvalidField { field: "level", .. }
            ));
        }

        /// verify_tree_block_checksum rejects unsupported csum_type.
        #[test]
        fn btrfs_proptest_tree_block_checksum_rejects_unsupported_type(
            csum_type in 1_u16..=u16::MAX,
        ) {
            let block = vec![0_u8; 4096];
            let result = verify_tree_block_checksum(&block, csum_type);
            prop_assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ParseError::InvalidField { field: "csum_type", .. }
            ));
        }

        /// verify_superblock_checksum rejects too-short regions.
        #[test]
        fn btrfs_proptest_superblock_checksum_rejects_short_region(
            len in 0_usize..BTRFS_SUPER_INFO_SIZE,
        ) {
            let region = vec![0_u8; len];
            let result = verify_superblock_checksum(&region);
            prop_assert!(result.is_err());
        }

        /// Superblock rejects wrong magic.
        #[test]
        fn btrfs_proptest_superblock_rejects_wrong_magic(
            magic in any::<u64>().prop_filter("not btrfs magic", |m| *m != BTRFS_MAGIC),
        ) {
            let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
            sb[0x40..0x48].copy_from_slice(&magic.to_le_bytes());
            sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
            sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
            let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
            assert!(matches!(err, ParseError::InvalidMagic { .. }));
        }

        /// parse_sys_chunk_array rejects zero num_stripes.
        #[test]
        fn btrfs_proptest_sys_chunk_array_rejects_zero_stripes(
            key_offset in any::<u64>(),
        ) {
            let mut data = vec![0_u8; BTRFS_DISK_KEY_SIZE + BTRFS_CHUNK_FIXED_SIZE];
            data[0..8].copy_from_slice(&BTRFS_FIRST_CHUNK_TREE_OBJECTID.to_le_bytes());
            data[8] = BTRFS_CHUNK_ITEM_KEY;
            data[9..17].copy_from_slice(&key_offset.to_le_bytes());
            let c = BTRFS_DISK_KEY_SIZE;
            data[c..c + 8].copy_from_slice(&1_u64.to_le_bytes());
            data[c + 16..c + 24].copy_from_slice(&4096_u64.to_le_bytes());
            // num_stripes at c+44..c+46 stays 0
            let result = parse_sys_chunk_array(&data);
            prop_assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ParseError::InvalidField { field: "num_stripes", .. }
            ));
        }

        /// parse_sys_chunk_array rejects zero chunk length.
        #[test]
        fn btrfs_proptest_sys_chunk_array_rejects_zero_chunk_length(
            key_offset in any::<u64>(),
        ) {
            let mut data = vec![0_u8; BTRFS_DISK_KEY_SIZE + BTRFS_CHUNK_FIXED_SIZE];
            data[0..8].copy_from_slice(&BTRFS_FIRST_CHUNK_TREE_OBJECTID.to_le_bytes());
            data[8] = BTRFS_CHUNK_ITEM_KEY;
            data[9..17].copy_from_slice(&key_offset.to_le_bytes());
            let c = BTRFS_DISK_KEY_SIZE;
            data[c + 16..c + 24].copy_from_slice(&4096_u64.to_le_bytes());
            data[c + 44..c + 46].copy_from_slice(&1_u16.to_le_bytes());
            let result = parse_sys_chunk_array(&data);
            prop_assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ParseError::InvalidField { field: "chunk_length", .. }
            ));
        }

        /// parse_sys_chunk_array rejects zero stripe_len.
        #[test]
        fn btrfs_proptest_sys_chunk_array_rejects_zero_stripe_len(
            key_offset in any::<u64>(),
        ) {
            let mut data = vec![0_u8; BTRFS_DISK_KEY_SIZE + BTRFS_CHUNK_FIXED_SIZE];
            data[0..8].copy_from_slice(&BTRFS_FIRST_CHUNK_TREE_OBJECTID.to_le_bytes());
            data[8] = BTRFS_CHUNK_ITEM_KEY;
            data[9..17].copy_from_slice(&key_offset.to_le_bytes());
            let c = BTRFS_DISK_KEY_SIZE;
            data[c..c + 8].copy_from_slice(&1_u64.to_le_bytes());
            data[c + 16..c + 24].copy_from_slice(&0_u64.to_le_bytes());
            data[c + 44..c + 46].copy_from_slice(&1_u16.to_le_bytes());
            let result = parse_sys_chunk_array(&data);
            prop_assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ParseError::InvalidField { field: "stripe_len", .. }
            ));
        }

        /// Superblock rejects sys_chunk_array_size > 2048.
        #[test]
        fn btrfs_proptest_superblock_rejects_oversized_sys_chunk_array(
            excess in 1_u32..=1000,
        ) {
            let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
            sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
            set_valid_superblock_device_accounting(&mut sb);
            sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
            sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
            sb[0x9C..0xA0].copy_from_slice(&4096_u32.to_le_bytes());
            let max_sys_chunk_array_size =
                u32::try_from(BTRFS_SYS_CHUNK_ARRAY_MAX).expect("constant fits in u32");
            let bad_size = max_sys_chunk_array_size + excess;
            sb[0xA0..0xA4].copy_from_slice(&bad_size.to_le_bytes());
            let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
            assert!(matches!(
                err,
                ParseError::InvalidField { field: "sys_chunk_array_size", .. }
            ));
        }

        // ── parse_dev_item metamorphic relations (bd-t2nrx) ───────────

        /// MR-1 — `parse_dev_item` never panics on arbitrary bytes of
        /// any length. Existing fixed-input tests cover a handful of
        /// hand-crafted negative cases; this proptest exercises the
        /// full input space [0, 256] bytes wide.
        #[test]
        fn btrfs_proptest_parse_dev_item_no_panic(
            data in proptest::collection::vec(any::<u8>(), 0..=256),
        ) {
            let _ = parse_dev_item(&data);
        }

        /// MR-2 — Tail-invariance: `parse_dev_item` reads exactly the
        /// first 98 bytes (BTRFS_DEV_ITEM_SIZE). For any valid input,
        /// appending arbitrary suffix bytes MUST yield the same parse
        /// result. A regression that hashed or dispatched on tail
        /// bytes would slip past the fixed-input tests.
        #[test]
        fn btrfs_proptest_parse_dev_item_tail_invariance(
            devid in 1_u64..=u64::MAX,
            total_bytes in 1_u64..=u64::MAX,
            bytes_used_pct in 0_u32..=100,
            io_align in any::<u32>(),
            io_width in any::<u32>(),
            sector_size in any::<u32>(),
            dev_type in any::<u64>(),
            generation in any::<u64>(),
            start_offset in any::<u64>(),
            dev_group in any::<u32>(),
            seek_speed in any::<u8>(),
            bandwidth in any::<u8>(),
            uuid in proptest::array::uniform16(any::<u8>()),
            fsid in proptest::array::uniform16(any::<u8>()),
            tail in proptest::collection::vec(any::<u8>(), 0..=128),
        ) {
            // bytes_used must be <= total_bytes per parse_dev_item's
            // accounting check (l. 1098). Compute it as a percentage.
            let bytes_used = total_bytes / 100 * u64::from(bytes_used_pct);

            let mut buf = [0_u8; BTRFS_DEV_ITEM_SIZE];
            buf[0..8].copy_from_slice(&devid.to_le_bytes());
            buf[8..16].copy_from_slice(&total_bytes.to_le_bytes());
            buf[16..24].copy_from_slice(&bytes_used.to_le_bytes());
            buf[24..28].copy_from_slice(&io_align.to_le_bytes());
            buf[28..32].copy_from_slice(&io_width.to_le_bytes());
            buf[32..36].copy_from_slice(&sector_size.to_le_bytes());
            buf[36..44].copy_from_slice(&dev_type.to_le_bytes());
            buf[44..52].copy_from_slice(&generation.to_le_bytes());
            buf[52..60].copy_from_slice(&start_offset.to_le_bytes());
            buf[60..64].copy_from_slice(&dev_group.to_le_bytes());
            buf[64] = seek_speed;
            buf[65] = bandwidth;
            buf[66..82].copy_from_slice(&uuid);
            buf[82..98].copy_from_slice(&fsid);

            let parsed_canonical =
                parse_dev_item(&buf).expect("canonical 98-byte payload must parse");

            let mut extended = buf.to_vec();
            extended.extend_from_slice(&tail);
            let parsed_extended = parse_dev_item(&extended)
                .expect("extended payload must parse since the parser ignores bytes >= 98");

            prop_assert_eq!(
                parsed_canonical, parsed_extended,
                "parse_dev_item must ignore bytes at offset >= 98"
            );
        }

        /// MR-3 — Field round-trip / byte-offset contract: every
        /// documented field offset is honored. Pins the 98-byte
        /// layout so any future drift in the offset table surfaces
        /// here rather than corrupting btrfs multi-device reads.
        #[test]
        fn btrfs_proptest_parse_dev_item_field_offsets(
            devid in 1_u64..=u64::MAX,
            total_bytes in 1_u64..=u64::MAX,
            bytes_used_pct in 0_u32..=100,
            io_align in any::<u32>(),
            io_width in any::<u32>(),
            sector_size in any::<u32>(),
            dev_type in any::<u64>(),
            generation in any::<u64>(),
            start_offset in any::<u64>(),
            dev_group in any::<u32>(),
            seek_speed in any::<u8>(),
            bandwidth in any::<u8>(),
            uuid in proptest::array::uniform16(any::<u8>()),
            fsid in proptest::array::uniform16(any::<u8>()),
        ) {
            let bytes_used = total_bytes / 100 * u64::from(bytes_used_pct);

            let mut buf = [0_u8; BTRFS_DEV_ITEM_SIZE];
            buf[0..8].copy_from_slice(&devid.to_le_bytes());
            buf[8..16].copy_from_slice(&total_bytes.to_le_bytes());
            buf[16..24].copy_from_slice(&bytes_used.to_le_bytes());
            buf[24..28].copy_from_slice(&io_align.to_le_bytes());
            buf[28..32].copy_from_slice(&io_width.to_le_bytes());
            buf[32..36].copy_from_slice(&sector_size.to_le_bytes());
            buf[36..44].copy_from_slice(&dev_type.to_le_bytes());
            buf[44..52].copy_from_slice(&generation.to_le_bytes());
            buf[52..60].copy_from_slice(&start_offset.to_le_bytes());
            buf[60..64].copy_from_slice(&dev_group.to_le_bytes());
            buf[64] = seek_speed;
            buf[65] = bandwidth;
            buf[66..82].copy_from_slice(&uuid);
            buf[82..98].copy_from_slice(&fsid);

            let item = parse_dev_item(&buf).expect("synthesised payload must parse");
            prop_assert_eq!(item.devid, devid);
            prop_assert_eq!(item.total_bytes, total_bytes);
            prop_assert_eq!(item.bytes_used, bytes_used);
            prop_assert_eq!(item.io_align, io_align);
            prop_assert_eq!(item.io_width, io_width);
            prop_assert_eq!(item.sector_size, sector_size);
            prop_assert_eq!(item.dev_type, dev_type);
            prop_assert_eq!(item.generation, generation);
            prop_assert_eq!(item.start_offset, start_offset);
            prop_assert_eq!(item.dev_group, dev_group);
            prop_assert_eq!(item.seek_speed, seek_speed);
            prop_assert_eq!(item.bandwidth, bandwidth);
            prop_assert_eq!(item.uuid, uuid);
            prop_assert_eq!(item.fsid, fsid);
        }

        // bd-kansf — Metamorphic relations for BtrfsRaidProfile.
        // Each MR pins a specific algebraic law of the chunk-type ->
        // RAID classification used by every read path on a multi-
        // device btrfs filesystem.

        /// MR1 — Determinism: same input always classifies the same.
        #[test]
        fn btrfs_proptest_raid_profile_determinism(chunk_type in any::<u64>()) {
            let a = BtrfsRaidProfile::from_chunk_type(chunk_type);
            let b = BtrfsRaidProfile::from_chunk_type(chunk_type);
            prop_assert_eq!(a, b);
        }

        /// MR2 — Non-RAID-bit invariance: only bits in RAID_MASK
        /// affect the classification. Toggling DATA / METADATA /
        /// SYSTEM bits MUST NOT change the profile.
        #[test]
        fn btrfs_proptest_raid_profile_only_raid_bits_matter(
            raid_bits in any::<u64>(),
            non_raid_bits in any::<u64>(),
        ) {
            let raid = raid_bits & chunk_type_flags::RAID_MASK;
            let non_raid = non_raid_bits & !chunk_type_flags::RAID_MASK;
            let p_clean = BtrfsRaidProfile::from_chunk_type(raid);
            let p_dirty = BtrfsRaidProfile::from_chunk_type(raid | non_raid);
            prop_assert_eq!(p_clean, p_dirty);
        }

        /// MR3 — Single is the default: clearing all RAID bits MUST
        /// give Single.
        #[test]
        fn btrfs_proptest_raid_profile_single_is_default(chunk_type in any::<u64>()) {
            let cleared = chunk_type & !chunk_type_flags::RAID_MASK;
            prop_assert_eq!(
                BtrfsRaidProfile::from_chunk_type(cleared),
                BtrfsRaidProfile::Single
            );
        }

        /// MR4 — data_copies bounds: 1 ≤ data_copies ≤ 4 for all
        /// classifiable chunk_type values.
        #[test]
        fn btrfs_proptest_raid_profile_data_copies_bounded(chunk_type in any::<u64>()) {
            let copies = BtrfsRaidProfile::from_chunk_type(chunk_type).data_copies();
            prop_assert!((1..=4).contains(&copies));
        }

        /// MR5 — Redundancy contract: is_redundant ⇔ (data_copies > 1
        /// OR profile in {Raid5, Raid6}). Pins the parity-vs-mirror
        /// duality.
        #[test]
        fn btrfs_proptest_raid_profile_redundancy_contract(chunk_type in any::<u64>()) {
            let p = BtrfsRaidProfile::from_chunk_type(chunk_type);
            let mirror_redundant = p.data_copies() > 1;
            let parity_redundant = matches!(p, BtrfsRaidProfile::Raid5 | BtrfsRaidProfile::Raid6);
            prop_assert_eq!(p.is_redundant(), mirror_redundant || parity_redundant);
        }

        /// MR6 — Priority order: when multiple RAID bits are set,
        /// the cascade is RAID0 > RAID1 > RAID1C3 > RAID1C4 > RAID10
        /// > RAID5 > RAID6 > DUP > Single. Set every RAID bit and
        /// verify the result is Raid0 (highest priority). Then walk
        /// down the cascade by clearing one bit at a time.
        #[test]
        fn btrfs_proptest_raid_profile_priority_cascade(extra_bits in any::<u64>()) {
            use chunk_type_flags::{
                BTRFS_BLOCK_GROUP_DUP, BTRFS_BLOCK_GROUP_RAID0, BTRFS_BLOCK_GROUP_RAID1,
                BTRFS_BLOCK_GROUP_RAID1C3, BTRFS_BLOCK_GROUP_RAID1C4, BTRFS_BLOCK_GROUP_RAID5,
                BTRFS_BLOCK_GROUP_RAID6, RAID_MASK,
            };
            // Carry arbitrary non-RAID bits through (covered by MR2,
            // but proves the cascade is robust to noise).
            let noise = extra_bits & !RAID_MASK;
            let cascade: [(u64, BtrfsRaidProfile); 8] = [
                (RAID_MASK, BtrfsRaidProfile::Raid0),
                (RAID_MASK & !BTRFS_BLOCK_GROUP_RAID0, BtrfsRaidProfile::Raid1),
                (
                    RAID_MASK & !(BTRFS_BLOCK_GROUP_RAID0 | BTRFS_BLOCK_GROUP_RAID1),
                    BtrfsRaidProfile::Raid1C3,
                ),
                (
                    RAID_MASK
                        & !(BTRFS_BLOCK_GROUP_RAID0
                            | BTRFS_BLOCK_GROUP_RAID1
                            | BTRFS_BLOCK_GROUP_RAID1C3),
                    BtrfsRaidProfile::Raid1C4,
                ),
                (
                    RAID_MASK
                        & !(BTRFS_BLOCK_GROUP_RAID0
                            | BTRFS_BLOCK_GROUP_RAID1
                            | BTRFS_BLOCK_GROUP_RAID1C3
                            | BTRFS_BLOCK_GROUP_RAID1C4),
                    BtrfsRaidProfile::Raid10,
                ),
                (
                    BTRFS_BLOCK_GROUP_RAID5 | BTRFS_BLOCK_GROUP_RAID6 | BTRFS_BLOCK_GROUP_DUP,
                    BtrfsRaidProfile::Raid5,
                ),
                (
                    BTRFS_BLOCK_GROUP_RAID6 | BTRFS_BLOCK_GROUP_DUP,
                    BtrfsRaidProfile::Raid6,
                ),
                (BTRFS_BLOCK_GROUP_DUP, BtrfsRaidProfile::Dup),
            ];
            for (input, expected) in cascade {
                prop_assert_eq!(
                    BtrfsRaidProfile::from_chunk_type(input | noise),
                    expected
                );
            }
        }

        // bd-xqf12 — Determinism MR for parse_dev_item. Sister
        // btrfs parsers (parse_xattr_items / parse_extent_data /
        // parse_inode_refs / parse_root_ref / parse_root_item /
        // parse_inode_item) all have determinism MR proptests.
        // parse_dev_item runs on every btrfs superblock parse +
        // every walk_chunk_tree DEV_ITEM read. A regression
        // introducing a hash-iteration or allocator-address
        // dependency would silently surface only under specific
        // scheduling.
        #[test]
        fn btrfs_proptest_parse_dev_item_determinism(
            devid_seed in 1_u64..=u64::MAX,
            total_bytes in 1_u64..=u64::MAX,
            io_align in any::<u32>(),
            io_width in any::<u32>(),
            sector_size in any::<u32>(),
            dev_type in any::<u64>(),
            generation in any::<u64>(),
            start_offset in any::<u64>(),
            dev_group in any::<u32>(),
            seek_speed in any::<u8>(),
            bandwidth in any::<u8>(),
            uuid in proptest::array::uniform16(any::<u8>()),
            fsid in proptest::array::uniform16(any::<u8>()),
        ) {
            // bytes_used <= total_bytes per parser invariant.
            let bytes_used = devid_seed % (total_bytes.saturating_add(1)).max(1);
            let mut data = vec![0_u8; 98];
            data[0..8].copy_from_slice(&devid_seed.to_le_bytes());
            data[8..16].copy_from_slice(&total_bytes.to_le_bytes());
            data[16..24].copy_from_slice(&bytes_used.to_le_bytes());
            data[24..28].copy_from_slice(&io_align.to_le_bytes());
            data[28..32].copy_from_slice(&io_width.to_le_bytes());
            data[32..36].copy_from_slice(&sector_size.to_le_bytes());
            data[36..44].copy_from_slice(&dev_type.to_le_bytes());
            data[44..52].copy_from_slice(&generation.to_le_bytes());
            data[52..60].copy_from_slice(&start_offset.to_le_bytes());
            data[60..64].copy_from_slice(&dev_group.to_le_bytes());
            data[64] = seek_speed;
            data[65] = bandwidth;
            data[66..82].copy_from_slice(&uuid);
            data[82..98].copy_from_slice(&fsid);

            let a = parse_dev_item(&data).expect("first parse");
            let b = parse_dev_item(&data).expect("second parse");
            prop_assert_eq!(a, b);
        }

        // bd-edl7j — Determinism MR for parse_leaf_items. Sister
        // btrfs parsers (parse_root_item / parse_root_ref /
        // parse_inode_item / parse_inode_refs / parse_dev_item) all
        // have determinism MR proptests. parse_leaf_items runs on
        // every walk_tree leaf-node read and is the most heavily-
        // trafficked btrfs parser. A regression that introduced a
        // HashMap iteration, allocator-address dependency, or any
        // non-deterministic per-call state would silently surface
        // only under specific scheduling. The MR fuzzes arbitrary
        // bytes (most rejected as Err) but Ok and Err results must
        // be identical across two calls.
        #[test]
        fn btrfs_proptest_parse_leaf_items_determinism(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let a = parse_leaf_items(&block);
            let b = parse_leaf_items(&block);
            prop_assert_eq!(a, b);
        }

        // bd-edl7j — Companion determinism MR for parse_internal_items
        // (the btree-node sibling of parse_leaf_items). Same rationale
        // as above; both code paths share the BtrfsHeader prefix +
        // bounds-checking arithmetic, but the item-vs-keyptr fork has
        // independent state.
        #[test]
        fn btrfs_proptest_parse_internal_items_determinism(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let a = parse_internal_items(&block);
            let b = parse_internal_items(&block);
            prop_assert_eq!(a, b);
        }

        // bd-vnlja — Determinism MR for parse_sys_chunk_array. This
        // bootstraps the chunk-tree mapping from the superblock; every
        // subsequent logical→physical address translation depends on
        // its output. A non-determinism regression here would corrupt
        // the entire chunk index in ways that surface only under
        // specific scheduling. Sister parsers (parse_root_item,
        // parse_root_ref, parse_inode_item, parse_inode_refs,
        // parse_dev_item, parse_leaf_items, parse_internal_items) all
        // have determinism MRs; this closes the gap for the highest-
        // leverage chunk parser.
        #[test]
        fn btrfs_proptest_parse_sys_chunk_array_determinism(
            data in proptest::collection::vec(any::<u8>(), 0..=BTRFS_SYS_CHUNK_ARRAY_MAX),
        ) {
            let a = parse_sys_chunk_array(&data);
            let b = parse_sys_chunk_array(&data);
            prop_assert_eq!(a, b);
        }

        // bd-hlrcn — Determinism MR for
        // BtrfsSuperblock::parse_superblock_region. The btrfs superblock
        // is the entry point for every mount/probe; non-determinism
        // here would silently corrupt mount-time bootstrap state.
        // Sized at BTRFS_SUPER_INFO_SIZE..=BTRFS_SUPER_INFO_SIZE so the
        // proptest fuzzes only the byte content, not the buffer length.
        // Sister parsers all have determinism MRs.
        #[test]
        fn btrfs_proptest_btrfs_superblock_parse_superblock_region_determinism(
            region in proptest::collection::vec(any::<u8>(), BTRFS_SUPER_INFO_SIZE..=BTRFS_SUPER_INFO_SIZE),
        ) {
            let a = BtrfsSuperblock::parse_superblock_region(&region);
            let b = BtrfsSuperblock::parse_superblock_region(&region);
            prop_assert_eq!(a, b);
        }

        // bd-hlrcn — Determinism MR for BtrfsHeader::parse_from_block.
        // BtrfsHeader is parsed at the start of every btrfs btree node
        // (every walk_tree call, every leaf_items / internal_items
        // parse, every checksum verification).
        #[test]
        fn btrfs_proptest_btrfs_header_parse_from_block_determinism(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let a = BtrfsHeader::parse_from_block(&block);
            let b = BtrfsHeader::parse_from_block(&block);
            prop_assert_eq!(a, b);
        }

        // bd-begr3 — Determinism MR for verify_superblock_checksum.
        // verify_superblock_checksum is invoked on every btrfs mount
        // and reads csum_type at offset 0xC4 to dispatch (currently
        // only CRC32C is supported but the dispatcher branches across
        // 4 types). Sister ext4 verify_*_checksum trio has bd-0g4j6
        // determinism MRs; this closes the btrfs side.
        #[test]
        fn btrfs_proptest_verify_superblock_checksum_determinism(
            region in proptest::collection::vec(any::<u8>(), 0..=BTRFS_SUPER_INFO_SIZE),
        ) {
            let a = verify_superblock_checksum(&region);
            let b = verify_superblock_checksum(&region);
            prop_assert_eq!(a, b);
        }

        // bd-begr3 — Determinism MR for verify_tree_block_checksum.
        // verify_tree_block_checksum is invoked on every btrfs leaf
        // and internal node read. Takes an explicit csum_type argument
        // (cycled over the 4 valid values to exercise the dispatch
        // branches in validate_supported_csum_type).
        #[test]
        fn btrfs_proptest_verify_tree_block_checksum_determinism(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
            csum_type in prop_oneof![
                Just(ffs_types::BTRFS_CSUM_TYPE_CRC32C),
                Just(ffs_types::BTRFS_CSUM_TYPE_XXHASH64),
                Just(ffs_types::BTRFS_CSUM_TYPE_SHA256),
                Just(ffs_types::BTRFS_CSUM_TYPE_BLAKE2B),
                any::<u16>(),
            ],
        ) {
            let a = verify_tree_block_checksum(&block, csum_type);
            let b = verify_tree_block_checksum(&block, csum_type);
            prop_assert_eq!(a, b);
        }

        // bd-f1k5j — btrfs_key_cmp total-order laws.
        // btrfs_key_cmp is the foundational lex ordering on
        // (objectid, item_type, offset) used by validate_next_key to
        // enforce strict-monotonic key ordering on every parsed btree
        // leaf and internal node. Pin the total-order axioms:

        // Reflexivity: cmp(a, a) == Equal.
        #[test]
        fn btrfs_proptest_key_cmp_reflexive(
            oid in any::<u64>(), ty in any::<u8>(), off in any::<u64>(),
        ) {
            let a = super::BtrfsKey { objectid: oid, item_type: ty, offset: off };
            prop_assert_eq!(super::btrfs_key_cmp(&a, &a), std::cmp::Ordering::Equal);
        }

        // Antisymmetry: cmp(a, b) == cmp(b, a).reverse() for any pair.
        #[test]
        fn btrfs_proptest_key_cmp_antisymmetric(
            a_oid in any::<u64>(), a_ty in any::<u8>(), a_off in any::<u64>(),
            b_oid in any::<u64>(), b_ty in any::<u8>(), b_off in any::<u64>(),
        ) {
            let a = super::BtrfsKey { objectid: a_oid, item_type: a_ty, offset: a_off };
            let b = super::BtrfsKey { objectid: b_oid, item_type: b_ty, offset: b_off };
            prop_assert_eq!(super::btrfs_key_cmp(&a, &b), super::btrfs_key_cmp(&b, &a).reverse());
        }

        // Transitivity: if a < b and b < c then a < c.
        #[test]
        fn btrfs_proptest_key_cmp_transitive(
            a_oid in any::<u64>(), a_ty in any::<u8>(), a_off in any::<u64>(),
            b_oid in any::<u64>(), b_ty in any::<u8>(), b_off in any::<u64>(),
            c_oid in any::<u64>(), c_ty in any::<u8>(), c_off in any::<u64>(),
        ) {
            use std::cmp::Ordering::Less;
            let a = super::BtrfsKey { objectid: a_oid, item_type: a_ty, offset: a_off };
            let b = super::BtrfsKey { objectid: b_oid, item_type: b_ty, offset: b_off };
            let c = super::BtrfsKey { objectid: c_oid, item_type: c_ty, offset: c_off };
            if super::btrfs_key_cmp(&a, &b) == Less && super::btrfs_key_cmp(&b, &c) == Less {
                prop_assert_eq!(super::btrfs_key_cmp(&a, &c), Less);
            }
        }

        // Field-priority hierarchy: objectid dominates item_type, item_type
        // dominates offset. Pins the lexicographic priority order.
        #[test]
        fn btrfs_proptest_key_cmp_objectid_dominates(
            oid_lo in any::<u64>(),
            oid_delta in 1_u64..,
            ty_a in any::<u8>(),
            ty_b in any::<u8>(),
            off_a in any::<u64>(),
            off_b in any::<u64>(),
        ) {
            let oid_hi = oid_lo.wrapping_add(oid_delta);
            // Skip wrap; we need strictly oid_lo < oid_hi.
            prop_assume!(oid_lo < oid_hi);
            let a = super::BtrfsKey { objectid: oid_lo, item_type: ty_a, offset: off_a };
            let b = super::BtrfsKey { objectid: oid_hi, item_type: ty_b, offset: off_b };
            prop_assert_eq!(super::btrfs_key_cmp(&a, &b), std::cmp::Ordering::Less,
                "lower objectid must always sort first regardless of item_type/offset");
        }

        #[test]
        fn btrfs_proptest_key_cmp_item_type_dominates_offset(
            oid in any::<u64>(),
            ty_lo in any::<u8>(),
            ty_delta in 1_u8..,
            off_a in any::<u64>(),
            off_b in any::<u64>(),
        ) {
            let ty_hi = ty_lo.wrapping_add(ty_delta);
            prop_assume!(ty_lo < ty_hi);
            let a = super::BtrfsKey { objectid: oid, item_type: ty_lo, offset: off_a };
            let b = super::BtrfsKey { objectid: oid, item_type: ty_hi, offset: off_b };
            prop_assert_eq!(super::btrfs_key_cmp(&a, &b), std::cmp::Ordering::Less,
                "lower item_type must sort first when objectid is equal, regardless of offset");
        }
    }

    // ── RAID profile identification ────────────────────────────────

    /// bd-6uu7j — Kernel-conformance pin for btrfs chunk/block-group
    /// flag bits from `include/uapi/linux/btrfs_tree.h`.
    #[test]
    fn btrfs_chunk_type_flags_match_kernel_header() {
        let flags = [
            (
                "BTRFS_BLOCK_GROUP_DATA",
                chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
                0x0001_u64,
            ),
            (
                "BTRFS_BLOCK_GROUP_SYSTEM",
                chunk_type_flags::BTRFS_BLOCK_GROUP_SYSTEM,
                0x0002,
            ),
            (
                "BTRFS_BLOCK_GROUP_METADATA",
                chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA,
                0x0004,
            ),
            (
                "BTRFS_BLOCK_GROUP_RAID0",
                chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
                0x0008,
            ),
            (
                "BTRFS_BLOCK_GROUP_RAID1",
                chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1,
                0x0010,
            ),
            (
                "BTRFS_BLOCK_GROUP_DUP",
                chunk_type_flags::BTRFS_BLOCK_GROUP_DUP,
                0x0020,
            ),
            (
                "BTRFS_BLOCK_GROUP_RAID10",
                chunk_type_flags::BTRFS_BLOCK_GROUP_RAID10,
                0x0040,
            ),
            (
                "BTRFS_BLOCK_GROUP_RAID5",
                chunk_type_flags::BTRFS_BLOCK_GROUP_RAID5,
                0x0080,
            ),
            (
                "BTRFS_BLOCK_GROUP_RAID6",
                chunk_type_flags::BTRFS_BLOCK_GROUP_RAID6,
                0x0100,
            ),
            (
                "BTRFS_BLOCK_GROUP_RAID1C3",
                chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1C3,
                0x0200,
            ),
            (
                "BTRFS_BLOCK_GROUP_RAID1C4",
                chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1C4,
                0x0400,
            ),
        ];

        for &(name, actual, expected) in &flags {
            assert_eq!(actual, expected, "{name} must match the kernel value");
            assert!(
                actual.is_power_of_two(),
                "{name} must be a single power-of-two bit"
            );
        }

        for (idx, &(left_name, left, _)) in flags.iter().enumerate() {
            for &(right_name, right, _) in &flags[idx + 1..] {
                assert_eq!(
                    left & right,
                    0,
                    "{left_name} and {right_name} must not share bits"
                );
            }
        }

        let expected_raid_mask = chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0
            | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1
            | chunk_type_flags::BTRFS_BLOCK_GROUP_DUP
            | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID10
            | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID5
            | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID6
            | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1C3
            | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1C4;
        assert_eq!(chunk_type_flags::RAID_MASK, expected_raid_mask);
        assert_eq!(chunk_type_flags::RAID_MASK, 0x07F8);
    }

    /// bd-pvbgz — Kernel-conformance pin for the 7 on-disk btrfs
    /// struct sizes from `include/uapi/linux/btrfs_tree.h`.
    ///
    /// Each constant equals `sizeof(struct ...)` under
    /// `__attribute__((packed))`. Drift in any value would silently
    /// mis-stride every leaf/internal-node walk and mis-locate every
    /// chunk descriptor on a btrfs filesystem, with NO panic — just
    /// silent on-disk corruption.
    ///
    /// The test pins both the canonical struct size AND the
    /// field-by-field sum, so a developer who shrinks/grows a const
    /// without updating the field assignments (or vice versa) fails
    /// the test. Pairs with bd-6uu7j (chunk_type flags) and bd-f0q7n
    /// (item keys) — those pin SCALAR macro values; this pins
    /// STRUCT byte-sizes.
    #[test]
    fn btrfs_on_disk_struct_sizes_match_kernel_header() {
        // struct btrfs_disk_key {
        //     __le64 objectid;   // 8
        //     __u8   type;       // 1
        //     __le64 offset;     // 8
        // } = 17 bytes packed.
        assert_eq!(BTRFS_DISK_KEY_SIZE, 17, "btrfs_disk_key sizeof");
        assert_eq!(BTRFS_DISK_KEY_SIZE, 8 + 1 + 8);

        // struct btrfs_header {
        //     u8     csum[32];           // 32
        //     u8     fsid[16];           // 16
        //     __le64 bytenr;             //  8
        //     __le64 flags;              //  8
        //     u8     chunk_tree_uuid[16];// 16
        //     __le64 generation;         //  8
        //     __le64 owner;              //  8
        //     __le32 nritems;            //  4
        //     u8     level;              //  1
        // } = 101 bytes packed.
        assert_eq!(BTRFS_HEADER_SIZE, 101, "btrfs_header sizeof");
        assert_eq!(BTRFS_HEADER_SIZE, 32 + 16 + 8 + 8 + 16 + 8 + 8 + 4 + 1);

        // struct btrfs_item {
        //     struct btrfs_disk_key key; // 17
        //     __le32 offset;             //  4
        //     __le32 size;               //  4
        // } = 25 bytes packed.
        assert_eq!(BTRFS_ITEM_SIZE, 25, "btrfs_item sizeof");
        assert_eq!(BTRFS_ITEM_SIZE, BTRFS_DISK_KEY_SIZE + 4 + 4);

        // struct btrfs_key_ptr {
        //     struct btrfs_disk_key key; // 17
        //     __le64 blockptr;           //  8
        //     __le64 generation;         //  8
        // } = 33 bytes packed.
        assert_eq!(BTRFS_KEY_PTR_SIZE, 33, "btrfs_key_ptr sizeof");
        assert_eq!(BTRFS_KEY_PTR_SIZE, BTRFS_DISK_KEY_SIZE + 8 + 8);

        // struct btrfs_stripe {
        //     __le64 devid;              //  8
        //     __le64 offset;             //  8
        //     u8     dev_uuid[16];       // 16
        // } = 32 bytes packed.
        assert_eq!(BTRFS_STRIPE_SIZE, 32, "btrfs_stripe sizeof");
        assert_eq!(BTRFS_STRIPE_SIZE, 8 + 8 + 16);

        // struct btrfs_chunk fixed prefix (the trailing stripe[1]
        // array is variable-length and not part of the fixed size):
        //     __le64 length;             //  8
        //     __le64 owner;              //  8
        //     __le64 stripe_len;         //  8
        //     __le64 type;               //  8
        //     __le32 io_align;           //  4
        //     __le32 io_width;           //  4
        //     __le32 sector_size;        //  4
        //     __le16 num_stripes;        //  2
        //     __le16 sub_stripes;        //  2
        // = 48 bytes packed (excluding stripe[]).
        assert_eq!(BTRFS_CHUNK_FIXED_SIZE, 48, "btrfs_chunk fixed prefix");
        assert_eq!(BTRFS_CHUNK_FIXED_SIZE, 8 + 8 + 8 + 8 + 4 + 4 + 4 + 2 + 2);

        // struct btrfs_dev_item {
        //     __le64 devid;          //  8
        //     __le64 total_bytes;    //  8
        //     __le64 bytes_used;     //  8
        //     __le32 io_align;       //  4
        //     __le32 io_width;       //  4
        //     __le32 sector_size;    //  4
        //     __le64 type;           //  8
        //     __le64 generation;     //  8
        //     __le64 start_offset;   //  8
        //     __le32 dev_group;      //  4
        //     u8     seek_speed;     //  1
        //     u8     bandwidth;      //  1
        //     u8     uuid[16];       // 16
        //     u8     fsid[16];       // 16
        // } = 98 bytes packed.
        assert_eq!(BTRFS_DEV_ITEM_SIZE, 98, "btrfs_dev_item sizeof");
        assert_eq!(
            BTRFS_DEV_ITEM_SIZE,
            8 + 8 + 8 + 4 + 4 + 4 + 8 + 8 + 8 + 4 + 1 + 1 + 16 + 16
        );
    }

    #[test]
    fn raid_profile_single() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(chunk_type_flags::BTRFS_BLOCK_GROUP_DATA),
            BtrfsRaidProfile::Single
        );
    }

    #[test]
    fn raid_profile_dup() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(
                chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_DUP
            ),
            BtrfsRaidProfile::Dup
        );
    }

    #[test]
    fn raid_profile_raid0() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0),
            BtrfsRaidProfile::Raid0
        );
    }

    #[test]
    fn raid_profile_raid1() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1),
            BtrfsRaidProfile::Raid1
        );
    }

    #[test]
    fn raid_profile_raid10() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(chunk_type_flags::BTRFS_BLOCK_GROUP_RAID10),
            BtrfsRaidProfile::Raid10
        );
    }

    #[test]
    fn raid_profile_raid5() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(chunk_type_flags::BTRFS_BLOCK_GROUP_RAID5),
            BtrfsRaidProfile::Raid5
        );
    }

    #[test]
    fn raid_profile_raid6() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(chunk_type_flags::BTRFS_BLOCK_GROUP_RAID6),
            BtrfsRaidProfile::Raid6
        );
    }

    #[test]
    fn raid_profile_raid1c3() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1C3),
            BtrfsRaidProfile::Raid1C3
        );
    }

    #[test]
    fn raid_profile_raid1c4() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1C4),
            BtrfsRaidProfile::Raid1C4
        );
    }

    #[test]
    fn raid_profile_data_copies() {
        assert_eq!(BtrfsRaidProfile::Single.data_copies(), 1);
        assert_eq!(BtrfsRaidProfile::Dup.data_copies(), 2);
        assert_eq!(BtrfsRaidProfile::Raid0.data_copies(), 1);
        assert_eq!(BtrfsRaidProfile::Raid1.data_copies(), 2);
        assert_eq!(BtrfsRaidProfile::Raid1C3.data_copies(), 3);
        assert_eq!(BtrfsRaidProfile::Raid1C4.data_copies(), 4);
        assert_eq!(BtrfsRaidProfile::Raid10.data_copies(), 2);
        assert_eq!(BtrfsRaidProfile::Raid5.data_copies(), 1);
        assert_eq!(BtrfsRaidProfile::Raid6.data_copies(), 1);
    }

    #[test]
    fn validate_mirror_stripes_rejects_insufficient_raid1c3_and_raid1c4() {
        let make_chunk = |num: u16| BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 0,
                item_type: 0,
                offset: 0,
            },
            length: 0,
            owner: 0,
            stripe_len: 0,
            chunk_type: 0,
            io_align: 0,
            io_width: 0,
            sector_size: 0,
            num_stripes: num,
            sub_stripes: 0,
            stripes: (0..num)
                .map(|i| BtrfsStripe {
                    devid: u64::from(i),
                    offset: 0,
                    dev_uuid: [0; 16],
                })
                .collect(),
        };

        // RAID1C3 needs >= 3 stripes; 2 is rejected with the profile-specific reason.
        let err = super::validate_mirror_stripes(&make_chunk(2), BtrfsRaidProfile::Raid1C3)
            .expect_err("RAID1C3 with 2 stripes must be rejected");
        assert!(
            matches!(err, ParseError::InvalidField { reason, .. } if reason.contains("at least three stripes")),
            "got {err:?}",
        );

        // RAID1C4 needs >= 4 stripes; 3 is rejected.
        let err = super::validate_mirror_stripes(&make_chunk(3), BtrfsRaidProfile::Raid1C4)
            .expect_err("RAID1C4 with 3 stripes must be rejected");
        assert!(
            matches!(err, ParseError::InvalidField { reason, .. } if reason.contains("at least four stripes")),
            "got {err:?}",
        );

        // The minimum valid stripe counts must pass.
        assert!(super::validate_mirror_stripes(&make_chunk(3), BtrfsRaidProfile::Raid1C3).is_ok());
        assert!(super::validate_mirror_stripes(&make_chunk(4), BtrfsRaidProfile::Raid1C4).is_ok());
    }

    #[test]
    fn validate_superblock_tree_level_rejects_above_max() {
        // Levels 0..=BTRFS_MAX_LEVEL (7) are accepted; 8+ are rejected with the
        // field name preserved. Distinct from the tree-node header level check.
        assert!(super::validate_superblock_tree_level("root_level", 0).is_ok());
        assert!(
            super::validate_superblock_tree_level("root_level", super::BTRFS_MAX_LEVEL).is_ok()
        );

        let err =
            super::validate_superblock_tree_level("chunk_root_level", super::BTRFS_MAX_LEVEL + 1)
                .expect_err("level above max must be rejected");
        assert!(
            matches!(err, ParseError::InvalidField { field, reason }
                if field == "chunk_root_level" && reason.contains("exceeds btrfs max tree level")),
            "got {err:?}",
        );

        assert!(super::validate_superblock_tree_level("log_root_level", u8::MAX).is_err());
    }

    #[test]
    fn raid_profile_redundancy() {
        assert!(!BtrfsRaidProfile::Single.is_redundant());
        assert!(!BtrfsRaidProfile::Raid0.is_redundant());
        assert!(BtrfsRaidProfile::Dup.is_redundant());
        assert!(BtrfsRaidProfile::Raid1.is_redundant());
        assert!(BtrfsRaidProfile::Raid5.is_redundant());
        assert!(BtrfsRaidProfile::Raid6.is_redundant());
        assert!(BtrfsRaidProfile::Raid10.is_redundant());
    }

    // ── Stripe resolution ──────────────────────────────────────────

    fn make_chunk(
        offset: u64,
        length: u64,
        stripe_len: u64,
        chunk_type: u64,
        stripes: Vec<BtrfsStripe>,
        sub_stripes: u16,
    ) -> BtrfsChunkEntry {
        let num_stripes = u16::try_from(stripes.len()).expect("test stripes length fits in u16");
        BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 0x100,
                item_type: 228,
                offset,
            },
            length,
            owner: 2,
            stripe_len,
            chunk_type,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes,
            sub_stripes,
            stripes,
        }
    }

    fn stripe(devid: u64, offset: u64) -> BtrfsStripe {
        BtrfsStripe {
            devid,
            offset,
            dev_uuid: [0; 16],
        }
    }

    #[test]
    fn stripe_resolve_single() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
            vec![stripe(1, 0x10_0000)],
            0,
        )];
        let result = map_logical_to_stripes(&chunks, 4096).unwrap().unwrap();
        assert_eq!(result.profile, BtrfsRaidProfile::Single);
        assert_eq!(result.stripes.len(), 1);
        assert_eq!(result.stripes[0].devid, 1);
        assert_eq!(result.stripes[0].physical, 0x10_0000 + 4096);
    }

    #[test]
    fn stripe_resolve_raid1_returns_both_mirrors() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1,
            vec![stripe(1, 0x10_0000), stripe(2, 0x20_0000)],
            0,
        )];
        let result = map_logical_to_stripes(&chunks, 4096).unwrap().unwrap();
        assert_eq!(result.profile, BtrfsRaidProfile::Raid1);
        assert_eq!(result.stripes.len(), 2);
        assert_eq!(result.stripes[0].devid, 1);
        assert_eq!(result.stripes[1].devid, 2);
        assert_eq!(result.stripes[0].physical, 0x10_0000 + 4096);
        assert_eq!(result.stripes[1].physical, 0x20_0000 + 4096);
    }

    #[test]
    fn stripe_resolve_raid1_spills_without_reordering_extra_mirrors() {
        let source_stripes: Vec<_> = (1_u64..=6)
            .map(|devid| stripe(devid, devid * 0x10_0000))
            .collect();
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65_536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1,
            source_stripes,
            0,
        )];

        let result = map_logical_to_stripes(&chunks, 4096).unwrap().unwrap();
        assert!(result.stripes.spilled());
        assert_eq!(result.stripes.len(), 6);
        for (index, mapping) in result.stripes.iter().enumerate() {
            let devid = u64::try_from(index).unwrap() + 1;
            assert_eq!(mapping.devid, devid);
            assert_eq!(mapping.physical, devid * 0x10_0000 + 4096);
        }
    }

    #[test]
    fn stripe_resolve_raid1c3_returns_all_mirrors() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1C3,
            vec![
                stripe(1, 0x10_0000),
                stripe(2, 0x20_0000),
                stripe(3, 0x30_0000),
            ],
            0,
        )];
        let result = map_logical_to_stripes(&chunks, 4096).unwrap().unwrap();
        assert_eq!(result.profile, BtrfsRaidProfile::Raid1C3);
        assert_eq!(result.stripes.len(), 3);
        assert_eq!(result.stripes[0].devid, 1);
        assert_eq!(result.stripes[1].devid, 2);
        assert_eq!(result.stripes[2].devid, 3);
        assert_eq!(result.stripes[0].physical, 0x10_0000 + 4096);
        assert_eq!(result.stripes[1].physical, 0x20_0000 + 4096);
        assert_eq!(result.stripes[2].physical, 0x30_0000 + 4096);
    }

    #[test]
    fn stripe_resolve_raid1c4_returns_all_mirrors() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1C4,
            vec![
                stripe(1, 0x10_0000),
                stripe(2, 0x20_0000),
                stripe(3, 0x30_0000),
                stripe(4, 0x40_0000),
            ],
            0,
        )];
        let result = map_logical_to_stripes(&chunks, 8192).unwrap().unwrap();
        assert_eq!(result.profile, BtrfsRaidProfile::Raid1C4);
        assert_eq!(result.stripes.len(), 4);
        assert_eq!(result.stripes[0].devid, 1);
        assert_eq!(result.stripes[1].devid, 2);
        assert_eq!(result.stripes[2].devid, 3);
        assert_eq!(result.stripes[3].devid, 4);
        assert_eq!(result.stripes[0].physical, 0x10_0000 + 8192);
        assert_eq!(result.stripes[1].physical, 0x20_0000 + 8192);
        assert_eq!(result.stripes[2].physical, 0x30_0000 + 8192);
        assert_eq!(result.stripes[3].physical, 0x40_0000 + 8192);
    }

    #[test]
    fn stripe_resolve_dup_returns_copies_on_same_device() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_DUP,
            vec![stripe(1, 0x10_0000), stripe(1, 0x20_0000)],
            0,
        )];
        let result = map_logical_to_stripes(&chunks, 4096).unwrap().unwrap();
        assert_eq!(result.profile, BtrfsRaidProfile::Dup);
        assert_eq!(result.stripes.len(), 2);
        assert_eq!(result.stripes[0].devid, 1);
        assert_eq!(result.stripes[1].devid, 1);
    }

    #[test]
    fn stripe_resolve_dup_rejects_mixed_devices() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_DUP,
            vec![stripe(1, 0x10_0000), stripe(2, 0x20_0000)],
            0,
        )];
        let err = map_logical_to_stripes(&chunks, 4096).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "stripe_devid",
                ..
            }
        ));
    }

    #[test]
    fn stripe_resolve_raid0_selects_correct_stripe() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
            vec![stripe(1, 0x10_0000), stripe(2, 0x20_0000)],
            0,
        )];
        // offset 0 -> stripe 0 (dev 1)
        let r0 = map_logical_to_stripes(&chunks, 0).unwrap().unwrap();
        assert_eq!(r0.stripes.len(), 1);
        assert_eq!(r0.stripes[0].devid, 1);

        // offset 65536 -> stripe 1 (dev 2)
        let r1 = map_logical_to_stripes(&chunks, 65536).unwrap().unwrap();
        assert_eq!(r1.stripes.len(), 1);
        assert_eq!(r1.stripes[0].devid, 2);
    }

    #[test]
    fn stripe_resolve_single_rejects_multiple_stripes() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
            vec![stripe(1, 0x10_0000), stripe(1, 0x20_0000)],
            0,
        )];

        let err = map_logical_to_stripes(&chunks, 4096).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "num_stripes",
                ..
            }
        ));
    }

    #[test]
    fn stripe_resolve_raid1_rejects_too_few_stripes() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1,
            vec![stripe(1, 0x10_0000)],
            0,
        )];

        let err = map_logical_to_stripes(&chunks, 4096).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "num_stripes",
                ..
            }
        ));
    }

    #[test]
    fn stripe_resolve_raid0_rejects_zero_stripes() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
            vec![],
            0,
        )];

        let err = map_logical_to_stripes(&chunks, 0).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "num_stripes",
                ..
            }
        ));
    }

    #[test]
    fn stripe_resolve_raid0_rejects_mismatched_stripe_count() {
        let mut chunk = make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
            vec![stripe(1, 0x10_0000), stripe(2, 0x20_0000)],
            0,
        );
        chunk.num_stripes = 3;

        let err = map_logical_to_stripes(&[chunk], 0).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "num_stripes",
                ..
            }
        ));
    }

    #[test]
    fn stripe_resolve_raid0_rejects_zero_stripe_len() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            0,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
            vec![stripe(1, 0x10_0000), stripe(2, 0x20_0000)],
            0,
        )];

        let err = map_logical_to_stripes(&chunks, 0).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "stripe_len",
                reason: "chunk has zero stripe length",
            }
        );
    }

    #[test]
    fn stripe_resolve_raid0_rejects_stripe_len_product_overflow() {
        let chunks = vec![make_chunk(
            0,
            u64::MAX,
            u64::MAX,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
            vec![stripe(1, 0x10_0000), stripe(2, 0x20_0000)],
            0,
        )];

        let err = map_logical_to_stripes(&chunks, 0).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "stripe_len",
                reason: "RAID0 stripe_len * num_stripes overflow",
            }
        );
    }

    #[test]
    fn stripe_resolve_raid0_rejects_physical_address_overflow() {
        let chunks = vec![make_chunk(
            0,
            16,
            1,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
            vec![stripe(1, u64::MAX - 1), stripe(2, 0)],
            0,
        )];

        let boundary = map_logical_to_stripes(&chunks, 2)
            .expect("boundary stripe mapping should be valid")
            .expect("chunk should cover boundary logical address");
        assert_eq!(boundary.stripes.len(), 1);
        assert_eq!(boundary.stripes[0].devid, 1);
        assert_eq!(boundary.stripes[0].physical, u64::MAX);

        let err = map_logical_to_stripes(&chunks, 4).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "stripe_offset",
                reason: "physical address overflow",
            }
        );
    }

    #[test]
    fn stripe_resolve_raid10_rejects_zero_sub_stripes() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID10,
            vec![stripe(1, 0x10_0000), stripe(2, 0x20_0000)],
            0,
        )];

        let err = map_logical_to_stripes(&chunks, 0).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "sub_stripes",
                ..
            }
        ));
    }

    #[test]
    fn stripe_resolve_raid10_rejects_non_divisible_stripes() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID10,
            vec![
                stripe(1, 0x10_0000),
                stripe(2, 0x20_0000),
                stripe(3, 0x30_0000),
            ],
            2,
        )];

        let err = map_logical_to_stripes(&chunks, 0).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "num_stripes",
                ..
            }
        ));
    }

    #[test]
    fn stripe_resolve_raid10_returns_selected_mirror_pair() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID10,
            vec![
                stripe(1, 0x10_0000),
                stripe(2, 0x20_0000),
                stripe(3, 0x30_0000),
                stripe(4, 0x40_0000),
            ],
            2,
        )];

        let mapping = map_logical_to_stripes(&chunks, 65_536)
            .expect("RAID10 mirror pair should map")
            .expect("chunk should cover logical address");
        assert_eq!(mapping.profile, BtrfsRaidProfile::Raid10);
        assert_eq!(mapping.stripes.len(), 2);
        assert_eq!(mapping.stripes[0].devid, 3);
        assert_eq!(mapping.stripes[0].physical, 0x30_0000);
        assert_eq!(mapping.stripes[1].devid, 4);
        assert_eq!(mapping.stripes[1].physical, 0x40_0000);
    }

    #[test]
    fn stripe_resolve_raid10_rejects_stripe_len_product_overflow() {
        let chunks = vec![make_chunk(
            0,
            u64::MAX,
            u64::MAX,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID10,
            vec![stripe(1, 0x10_0000), stripe(2, 0x20_0000)],
            1,
        )];

        let err = map_logical_to_stripes(&chunks, 0).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "stripe_len",
                reason: "RAID10 stripe_len * data_stripes overflow",
            }
        );
    }

    #[test]
    fn stripe_resolve_raid10_overflow_reports_error() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            4096,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID10,
            vec![stripe(1, u64::MAX - 1), stripe(2, 0x20_0000)],
            1,
        )];

        let err = map_logical_to_stripes(&chunks, 10).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "stripe_offset",
                ..
            }
        ));
    }

    #[test]
    fn stripe_resolve_raid5_rejects_too_few_stripes() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID5,
            vec![stripe(1, 0x10_0000), stripe(2, 0x20_0000)],
            0,
        )];

        let err = map_logical_to_stripes(&chunks, 0).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "num_stripes",
                ..
            }
        ));
    }

    #[test]
    fn stripe_resolve_raid6_rejects_too_few_stripes() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID6,
            vec![
                stripe(1, 0x10_0000),
                stripe(2, 0x20_0000),
                stripe(3, 0x30_0000),
            ],
            0,
        )];

        let err = map_logical_to_stripes(&chunks, 0).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "num_stripes",
                ..
            }
        ));
    }

    #[test]
    fn stripe_resolve_raid5_rejects_stripe_len_product_overflow() {
        let chunks = vec![make_chunk(
            0,
            u64::MAX,
            u64::MAX,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID5,
            vec![
                stripe(1, 0x10_0000),
                stripe(2, 0x20_0000),
                stripe(3, 0x30_0000),
            ],
            0,
        )];

        let err = map_logical_to_stripes(&chunks, 0).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "stripe_len",
                reason: "RAID5/6 stripe_len * data_stripes overflow",
            }
        );
    }

    #[test]
    fn stripe_resolve_raid5_rejects_physical_address_overflow() {
        let chunks = vec![make_chunk(
            0,
            16,
            1,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID5,
            vec![
                stripe(1, u64::MAX - 1),
                stripe(2, 0x20_0000),
                stripe(3, 0x30_0000),
            ],
            0,
        )];

        let boundary = map_logical_to_stripes(&chunks, 2)
            .expect("boundary stripe mapping should be valid")
            .expect("chunk should cover boundary logical address");
        assert_eq!(boundary.stripes.len(), 1);
        assert_eq!(boundary.stripes[0].devid, 1);
        assert_eq!(boundary.stripes[0].physical, u64::MAX);

        let err = map_logical_to_stripes(&chunks, 8).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "stripe_offset",
                reason: "physical address overflow",
            }
        );
    }

    #[test]
    fn stripe_resolve_raid5_skips_rotated_parity_position() {
        let chunks = vec![make_chunk(
            0,
            65536 * 2 * 4,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID5,
            vec![
                stripe(1, 0x10_0000),
                stripe(2, 0x20_0000),
                stripe(3, 0x30_0000),
            ],
            0,
        )];

        // Row 1: parity rotates to position 1 (device 2), so data uses positions 0 and 2.
        let data0 = map_logical_to_stripes(&chunks, 131_072)
            .expect("RAID5 row 1 data stripe 0 should map")
            .expect("chunk should cover logical address");
        assert_eq!(data0.profile, BtrfsRaidProfile::Raid5);
        assert_eq!(data0.stripes.len(), 1);
        assert_eq!(data0.stripes[0].devid, 1);
        assert_eq!(data0.stripes[0].physical, 0x10_0000 + 65_536);

        let data1 = map_logical_to_stripes(&chunks, 196_608)
            .expect("RAID5 row 1 data stripe 1 should map")
            .expect("chunk should cover logical address");
        assert_eq!(data1.stripes.len(), 1);
        assert_eq!(data1.stripes[0].devid, 3);
        assert_eq!(data1.stripes[0].physical, 0x30_0000 + 65_536);
    }

    #[test]
    fn stripe_resolve_raid6_parity_wraparound() {
        // 4 devices, RAID6 (2 parity), stripe_len=65536
        // This tests the case where P is at device 0 and Q wraps to the last device.
        let chunks = vec![make_chunk(
            0,
            // Large enough to cover multiple stripe rows
            65536 * 2 * 8, // data_stripes=2, 8 rows
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID6,
            vec![
                stripe(1, 0x10_0000),
                stripe(2, 0x20_0000),
                stripe(3, 0x30_0000),
                stripe(4, 0x40_0000),
            ],
            0,
        )];

        // Row 3 (stripe_nr=3): P at pos 0 (dev 1), Q at pos 3 (dev 4).
        // Data should be at pos 1 (dev 2) and pos 2 (dev 3).
        // offset for row 3, data stripe 0 = 3 * 65536 * 2 + 0 = 393216
        let r = map_logical_to_stripes(&chunks, 393_216).unwrap().unwrap();
        assert_eq!(r.profile, BtrfsRaidProfile::Raid6);
        assert_eq!(r.stripes.len(), 1);
        // Should NOT be dev 1 or 4
        assert_ne!(
            r.stripes[0].devid, 1,
            "stripe_nr=3: position 0 is P parity, data should not map there"
        );
        assert_eq!(
            r.stripes[0].devid, 2,
            "stripe_nr=3, data_idx=0: should map to device 2 (position 1)"
        );

        // Row 3, data stripe 1 = 393216 + 65536 = 458752
        let r2 = map_logical_to_stripes(&chunks, 458_752).unwrap().unwrap();
        assert_eq!(
            r2.stripes[0].devid, 3,
            "stripe_nr=3, data_idx=1: should map to device 3 (position 2)"
        );
    }

    #[test]
    fn stripe_resolve_no_match_returns_none() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
            vec![stripe(1, 0)],
            0,
        )];
        let result = map_logical_to_stripes(&chunks, 2_000_000).unwrap();
        assert!(result.is_none());
    }

    // ── DEV_ITEM parsing ───────────────────────────────────────────

    #[test]
    fn parse_dev_item_valid() {
        let mut data = vec![0u8; 98];
        // devid = 1
        data[0..8].copy_from_slice(&1_u64.to_le_bytes());
        // total_bytes = 1GB
        data[8..16].copy_from_slice(&(1024 * 1024 * 1024_u64).to_le_bytes());
        // bytes_used = 500MB
        data[16..24].copy_from_slice(&(500 * 1024 * 1024_u64).to_le_bytes());
        // sector_size = 4096
        data[32..36].copy_from_slice(&4096_u32.to_le_bytes());

        let item = parse_dev_item(&data).unwrap();
        assert_eq!(item.devid, 1);
        assert_eq!(item.total_bytes, 1024 * 1024 * 1024);
        assert_eq!(item.bytes_used, 500 * 1024 * 1024);
        assert_eq!(item.sector_size, 4096);
    }

    /// bd-na4cc — Kernel-conformance pin for parse_dev_item field
    /// offsets per fs/btrfs/btrfs_tree.h struct btrfs_dev_item.
    ///
    ///   devid        u64 @0..8
    ///   total_bytes  u64 @8..16
    ///   bytes_used   u64 @16..24
    ///   io_align     u32 @24..28
    ///   io_width     u32 @28..32
    ///   sector_size  u32 @32..36
    ///   dev_type     u64 @36..44
    ///   generation   u64 @44..52
    ///   start_offset u64 @52..60
    ///   dev_group    u32 @60..64
    ///   seek_speed   u8  @64
    ///   bandwidth    u8  @65
    ///   uuid         [u8;16] @66..82
    ///   fsid         [u8;16] @82..98
    /// (98 bytes total = BTRFS_DEV_ITEM_SIZE)
    ///
    /// Existing parse_dev_item_valid only verifies devid /
    /// total_bytes / bytes_used / sector_size — the other 9 fields
    /// (io_align, io_width, dev_type, generation, start_offset,
    /// dev_group, seek_speed, bandwidth, uuid, fsid) are not
    /// pinned at their offsets. A regression that drifted any of
    /// those would silently corrupt every DEV_ITEM read on btrfs
    /// mount.
    ///
    /// Stamp each addressable field with a distinct non-zero
    /// magic so any single-field offset drift produces a cross-
    /// field collision.
    #[test]
    fn parse_dev_item_kernel_offsets_match_btrfs_tree_h() {
        let mut data = vec![0_u8; 98];

        let devid = 0x1111_1111_1111_1111_u64;
        let total_bytes = 0x2222_2222_2222_2222_u64;
        let bytes_used = 0x1111_1111_1111_1110_u64; // < total_bytes
        let io_align: u32 = 0x4444_4444;
        let io_width: u32 = 0x5555_5555;
        let sector_size: u32 = 0x6666_6666;
        let dev_type = 0x7777_7777_7777_7777_u64;
        let generation = 0x8888_8888_8888_8888_u64;
        let start_offset = 0x9999_9999_9999_9999_u64;
        let dev_group: u32 = 0xAAAA_AAAA;
        let seek_speed: u8 = 0xBB;
        let bandwidth: u8 = 0xCC;
        let uuid: [u8; 16] = [0xDD; 16];
        let fsid: [u8; 16] = [0xEE; 16];

        data[0..8].copy_from_slice(&devid.to_le_bytes());
        data[8..16].copy_from_slice(&total_bytes.to_le_bytes());
        data[16..24].copy_from_slice(&bytes_used.to_le_bytes());
        data[24..28].copy_from_slice(&io_align.to_le_bytes());
        data[28..32].copy_from_slice(&io_width.to_le_bytes());
        data[32..36].copy_from_slice(&sector_size.to_le_bytes());
        data[36..44].copy_from_slice(&dev_type.to_le_bytes());
        data[44..52].copy_from_slice(&generation.to_le_bytes());
        data[52..60].copy_from_slice(&start_offset.to_le_bytes());
        data[60..64].copy_from_slice(&dev_group.to_le_bytes());
        data[64] = seek_speed;
        data[65] = bandwidth;
        data[66..82].copy_from_slice(&uuid);
        data[82..98].copy_from_slice(&fsid);

        let parsed = parse_dev_item(&data).expect("kernel-stamped dev_item must parse");

        assert_eq!(parsed.devid, devid, "devid @0..8");
        assert_eq!(parsed.total_bytes, total_bytes, "total_bytes @8..16");
        assert_eq!(parsed.bytes_used, bytes_used, "bytes_used @16..24");
        assert_eq!(parsed.io_align, io_align, "io_align @24..28");
        assert_eq!(parsed.io_width, io_width, "io_width @28..32");
        assert_eq!(parsed.sector_size, sector_size, "sector_size @32..36");
        assert_eq!(parsed.dev_type, dev_type, "dev_type @36..44");
        assert_eq!(parsed.generation, generation, "generation @44..52");
        assert_eq!(parsed.start_offset, start_offset, "start_offset @52..60");
        assert_eq!(parsed.dev_group, dev_group, "dev_group @60..64");
        assert_eq!(parsed.seek_speed, seek_speed, "seek_speed @64");
        assert_eq!(parsed.bandwidth, bandwidth, "bandwidth @65");
        assert_eq!(parsed.uuid, uuid, "uuid @66..82");
        assert_eq!(parsed.fsid, fsid, "fsid @82..98");
    }

    #[test]
    fn parse_dev_item_rejects_bytes_used_above_total() {
        let mut data = vec![0u8; 98];
        data[0..8].copy_from_slice(&1_u64.to_le_bytes());
        data[8..16].copy_from_slice(&4096_u64.to_le_bytes());
        data[16..24].copy_from_slice(&8192_u64.to_le_bytes());

        let err = parse_dev_item(&data).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "bytes_used",
                reason: "exceeds total_bytes",
            }
        );
    }

    #[test]
    fn parse_dev_item_rejects_zero_devid() {
        let mut data = vec![0u8; 98];
        data[8..16].copy_from_slice(&4096_u64.to_le_bytes());
        data[16..24].copy_from_slice(&2048_u64.to_le_bytes());

        let err = parse_dev_item(&data).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "devid",
                reason: "must be non-zero",
            }
        );
    }

    #[test]
    fn parse_dev_item_rejects_zero_total_bytes() {
        let mut data = vec![0u8; 98];
        data[0..8].copy_from_slice(&1_u64.to_le_bytes());
        let err = parse_dev_item(&data).unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "total_bytes",
                reason: "must be non-zero",
            }
        );
    }

    #[test]
    fn parse_dev_item_too_short() {
        let data = vec![0u8; 50];
        let err = parse_dev_item(&data).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }
}
