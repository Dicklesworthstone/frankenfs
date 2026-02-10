#![forbid(unsafe_code)]

use ffs_types::{
    EXT4_SUPER_MAGIC, EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE, ParseError,
    ensure_slice, ext4_block_size_from_log, read_fixed, read_le_u16, read_le_u32,
    trim_nul_padded,
};
use serde::{Deserialize, Serialize};

const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
const EXT_INIT_MAX_LEN: u16 = 1_u16 << 15;

// ext4 feature flags (incompat subset; not exhaustive)
const EXT4_FEATURE_INCOMPAT_COMPRESSION: u32 = 0x0001;
const EXT4_FEATURE_INCOMPAT_FILETYPE: u32 = 0x0002;
const EXT4_FEATURE_INCOMPAT_RECOVER: u32 = 0x0004;
const EXT4_FEATURE_INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
const EXT4_FEATURE_INCOMPAT_META_BG: u32 = 0x0010;
const EXT4_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;
const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;
const EXT4_FEATURE_INCOMPAT_MMP: u32 = 0x0100;
const EXT4_FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;
const EXT4_FEATURE_INCOMPAT_EA_INODE: u32 = 0x0400;
const EXT4_FEATURE_INCOMPAT_DIRDATA: u32 = 0x1000;
const EXT4_FEATURE_INCOMPAT_CSUM_SEED: u32 = 0x2000;
const EXT4_FEATURE_INCOMPAT_LARGEDIR: u32 = 0x4000;
const EXT4_FEATURE_INCOMPAT_INLINE_DATA: u32 = 0x8000;
const EXT4_FEATURE_INCOMPAT_ENCRYPT: u32 = 0x10000;
const EXT4_FEATURE_INCOMPAT_CASEFOLD: u32 = 0x20000;

const EXT4_INCOMPAT_REQUIRED_MASK: u32 =
    EXT4_FEATURE_INCOMPAT_FILETYPE | EXT4_FEATURE_INCOMPAT_EXTENTS;

// Bits FrankenFS v1 can parse/understand without failing mount validation.
const EXT4_INCOMPAT_ALLOWED_MASK: u32 = EXT4_FEATURE_INCOMPAT_FILETYPE
    | EXT4_FEATURE_INCOMPAT_EXTENTS
    | EXT4_FEATURE_INCOMPAT_RECOVER
    | EXT4_FEATURE_INCOMPAT_META_BG
    | EXT4_FEATURE_INCOMPAT_64BIT
    | EXT4_FEATURE_INCOMPAT_MMP
    | EXT4_FEATURE_INCOMPAT_FLEX_BG
    | EXT4_FEATURE_INCOMPAT_EA_INODE
    | EXT4_FEATURE_INCOMPAT_DIRDATA
    | EXT4_FEATURE_INCOMPAT_CSUM_SEED
    | EXT4_FEATURE_INCOMPAT_LARGEDIR;

// ext4 feature flags (ro_compat subset)
const EXT4_FEATURE_RO_COMPAT_METADATA_CSUM: u32 = 0x0400;

const EXT4_INCOMPAT_REJECT_MASK: u32 = EXT4_FEATURE_INCOMPAT_COMPRESSION
    | EXT4_FEATURE_INCOMPAT_JOURNAL_DEV
    | EXT4_FEATURE_INCOMPAT_INLINE_DATA
    | EXT4_FEATURE_INCOMPAT_ENCRYPT
    | EXT4_FEATURE_INCOMPAT_CASEFOLD;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4Superblock {
    // ── Core geometry ────────────────────────────────────────────────────
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub reserved_blocks_count: u64,
    pub free_blocks_count: u64,
    pub free_inodes_count: u32,
    pub first_data_block: u32,
    pub block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u16,
    pub first_ino: u32,
    pub desc_size: u16,

    // ── Identity ─────────────────────────────────────────────────────────
    pub magic: u16,
    pub uuid: [u8; 16],
    pub volume_name: String,
    pub last_mounted: String,

    // ── Revision & OS ────────────────────────────────────────────────────
    pub rev_level: u32,
    pub minor_rev_level: u16,
    pub creator_os: u32,

    // ── Features ─────────────────────────────────────────────────────────
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub default_mount_opts: u32,

    // ── State & error tracking ───────────────────────────────────────────
    pub state: u16,
    pub errors: u16,
    pub mnt_count: u16,
    pub max_mnt_count: u16,
    pub error_count: u32,

    // ── Timestamps ───────────────────────────────────────────────────────
    pub mtime: u32,
    pub wtime: u32,
    pub lastcheck: u32,
    pub mkfs_time: u32,
    pub first_error_time: u32,
    pub last_error_time: u32,

    // ── Journal ──────────────────────────────────────────────────────────
    pub journal_inum: u32,
    pub journal_dev: u32,
    pub journal_uuid: [u8; 16],

    // ── Htree directory hashing ──────────────────────────────────────────
    pub hash_seed: [u32; 4],
    pub def_hash_version: u8,

    // ── Flex BG ──────────────────────────────────────────────────────────
    pub log_groups_per_flex: u8,

    // ── Checksums ────────────────────────────────────────────────────────
    pub checksum_type: u8,
    pub checksum_seed: u32,
    pub checksum: u32,
}

impl Ext4Superblock {
    /// Parse an ext4 superblock from a 1024-byte superblock region.
    pub fn parse_superblock_region(region: &[u8]) -> Result<Self, ParseError> {
        if region.len() < EXT4_SUPERBLOCK_SIZE {
            return Err(ParseError::InsufficientData {
                needed: EXT4_SUPERBLOCK_SIZE,
                offset: 0,
                actual: region.len(),
            });
        }

        let magic = read_le_u16(region, 0x38)?;
        if magic != EXT4_SUPER_MAGIC {
            return Err(ParseError::InvalidMagic {
                expected: u64::from(EXT4_SUPER_MAGIC),
                actual: u64::from(magic),
            });
        }

        let blocks_lo = u64::from(read_le_u32(region, 0x04)?);
        let blocks_hi = u64::from(read_le_u32(region, 0x150)?);

        let r_blocks_lo = u64::from(read_le_u32(region, 0x08)?);
        let r_blocks_hi = u64::from(read_le_u32(region, 0x154)?);

        let free_blocks_lo = u64::from(read_le_u32(region, 0x0C)?);
        let free_blocks_hi = u64::from(read_le_u32(region, 0x158)?);

        let log_block_size = read_le_u32(region, 0x18)?;
        let Some(block_size) = ext4_block_size_from_log(log_block_size) else {
            return Err(ParseError::InvalidField {
                field: "s_log_block_size",
                reason: "invalid shift",
            });
        };

        // Read single-byte fields via ensure_slice
        let checksum_type = ensure_slice(region, 0x175, 1)?[0];
        let def_hash_version = ensure_slice(region, 0xFC, 1)?[0];
        let log_groups_per_flex = ensure_slice(region, 0x174, 1)?[0];

        Ok(Self {
            // Core geometry
            inodes_count: read_le_u32(region, 0x00)?,
            blocks_count: blocks_lo | (blocks_hi << 32),
            reserved_blocks_count: r_blocks_lo | (r_blocks_hi << 32),
            free_blocks_count: free_blocks_lo | (free_blocks_hi << 32),
            free_inodes_count: read_le_u32(region, 0x10)?,
            first_data_block: read_le_u32(region, 0x14)?,
            block_size,
            blocks_per_group: read_le_u32(region, 0x20)?,
            inodes_per_group: read_le_u32(region, 0x28)?,
            inode_size: read_le_u16(region, 0x58)?,
            first_ino: read_le_u32(region, 0x54)?,
            desc_size: read_le_u16(region, 0xFE)?,

            // Identity
            magic,
            uuid: read_fixed::<16>(region, 0x68)?,
            volume_name: trim_nul_padded(&read_fixed::<16>(region, 0x78)?),
            last_mounted: trim_nul_padded(&read_fixed::<64>(region, 0x88)?),

            // Revision & OS
            rev_level: read_le_u32(region, 0x4C)?,
            minor_rev_level: read_le_u16(region, 0x3E)?,
            creator_os: read_le_u32(region, 0x48)?,

            // Features
            feature_compat: read_le_u32(region, 0x5C)?,
            feature_incompat: read_le_u32(region, 0x60)?,
            feature_ro_compat: read_le_u32(region, 0x64)?,
            default_mount_opts: read_le_u32(region, 0x100)?,

            // State & error tracking
            state: read_le_u16(region, 0x3A)?,
            errors: read_le_u16(region, 0x3C)?,
            mnt_count: read_le_u16(region, 0x32)?,
            max_mnt_count: read_le_u16(region, 0x36)?,
            error_count: read_le_u32(region, 0x194)?,

            // Timestamps
            mtime: read_le_u32(region, 0x2C)?,
            wtime: read_le_u32(region, 0x30)?,
            lastcheck: read_le_u32(region, 0x40)?,
            mkfs_time: read_le_u32(region, 0x108)?,
            first_error_time: read_le_u32(region, 0x198)?,
            last_error_time: read_le_u32(region, 0x1CC)?,

            // Journal
            journal_inum: read_le_u32(region, 0xE0)?,
            journal_dev: read_le_u32(region, 0xE4)?,
            journal_uuid: read_fixed::<16>(region, 0xD0)?,

            // Htree directory hashing
            hash_seed: [
                read_le_u32(region, 0xEC)?,
                read_le_u32(region, 0xF0)?,
                read_le_u32(region, 0xF4)?,
                read_le_u32(region, 0xF8)?,
            ],
            def_hash_version,

            // Flex BG
            log_groups_per_flex,

            // Checksums
            checksum_type,
            checksum_seed: read_le_u32(region, 0x270)?,
            checksum: read_le_u32(region, 0x3FC)?,
        })
    }

    /// Parse an ext4 superblock from a full disk image.
    pub fn parse_from_image(image: &[u8]) -> Result<Self, ParseError> {
        let end = EXT4_SUPERBLOCK_OFFSET
            .checked_add(EXT4_SUPERBLOCK_SIZE)
            .ok_or(ParseError::InvalidField {
                field: "superblock_offset",
                reason: "overflow",
            })?;

        if image.len() < end {
            return Err(ParseError::InsufficientData {
                needed: EXT4_SUPERBLOCK_SIZE,
                offset: EXT4_SUPERBLOCK_OFFSET,
                actual: image.len().saturating_sub(EXT4_SUPERBLOCK_OFFSET),
            });
        }

        Self::parse_superblock_region(&image[EXT4_SUPERBLOCK_OFFSET..end])
    }

    #[must_use]
    pub fn has_compat(&self, mask: u32) -> bool {
        (self.feature_compat & mask) != 0
    }

    #[must_use]
    pub fn has_incompat(&self, mask: u32) -> bool {
        (self.feature_incompat & mask) != 0
    }

    #[must_use]
    pub fn has_ro_compat(&self, mask: u32) -> bool {
        (self.feature_ro_compat & mask) != 0
    }

    #[must_use]
    pub fn is_64bit(&self) -> bool {
        self.has_incompat(EXT4_FEATURE_INCOMPAT_64BIT)
    }

    #[must_use]
    pub fn group_desc_size(&self) -> u16 {
        if self.is_64bit() {
            self.desc_size.max(64)
        } else {
            32
        }
    }

    /// Number of block groups in this filesystem.
    #[must_use]
    pub fn groups_count(&self) -> u32 {
        if self.blocks_per_group == 0 {
            return 0;
        }
        let data_blocks = self.blocks_count.saturating_sub(u64::from(self.first_data_block));
        let groups = data_blocks.div_ceil(u64::from(self.blocks_per_group));
        groups as u32
    }

    /// Whether this superblock uses metadata checksums (crc32c).
    #[must_use]
    pub fn has_metadata_csum(&self) -> bool {
        self.has_ro_compat(EXT4_FEATURE_RO_COMPAT_METADATA_CSUM)
    }

    /// Compute the crc32c checksum seed used for metadata checksums.
    ///
    /// If `INCOMPAT_CSUM_SEED` is set, uses the precomputed `checksum_seed` field.
    /// Otherwise, computes `crc32c(~0, uuid)`.
    #[must_use]
    pub fn csum_seed(&self) -> u32 {
        if self.has_incompat(EXT4_FEATURE_INCOMPAT_CSUM_SEED) {
            self.checksum_seed
        } else {
            crc32c::crc32c(&self.uuid)
        }
    }

    /// Validate the superblock's own CRC32C checksum.
    pub fn validate_checksum(&self, raw_region: &[u8]) -> Result<(), ParseError> {
        if !self.has_metadata_csum() {
            return Ok(());
        }
        if raw_region.len() < EXT4_SUPERBLOCK_SIZE {
            return Err(ParseError::InsufficientData {
                needed: EXT4_SUPERBLOCK_SIZE,
                offset: 0,
                actual: raw_region.len(),
            });
        }
        // Zero out the checksum field (last 4 bytes) before computing
        let mut buf = [0_u8; EXT4_SUPERBLOCK_SIZE];
        buf.copy_from_slice(&raw_region[..EXT4_SUPERBLOCK_SIZE]);
        buf[0x3FC..0x400].copy_from_slice(&[0; 4]);
        let computed = crc32c::crc32c(&buf);
        if computed != self.checksum {
            return Err(ParseError::InvalidField {
                field: "s_checksum",
                reason: "superblock CRC32C mismatch",
            });
        }
        Ok(())
    }

    /// Validate basic geometry: blocks_per_group, inodes_per_group, counts.
    pub fn validate_geometry(&self) -> Result<(), ParseError> {
        if self.blocks_per_group == 0 {
            return Err(ParseError::InvalidField {
                field: "s_blocks_per_group",
                reason: "cannot be zero",
            });
        }
        if self.inodes_per_group == 0 {
            return Err(ParseError::InvalidField {
                field: "s_inodes_per_group",
                reason: "cannot be zero",
            });
        }
        if self.inode_size < 128 {
            return Err(ParseError::InvalidField {
                field: "s_inode_size",
                reason: "must be >= 128",
            });
        }
        if !self.inode_size.is_power_of_two() {
            return Err(ParseError::InvalidField {
                field: "s_inode_size",
                reason: "must be a power of two",
            });
        }
        if u64::from(self.first_data_block) >= self.blocks_count {
            return Err(ParseError::InvalidField {
                field: "s_first_data_block",
                reason: "first_data_block >= blocks_count",
            });
        }
        Ok(())
    }

    pub fn validate_v1(&self) -> Result<(), ParseError> {
        self.validate_geometry()?;

        if !matches!(self.block_size, 1024 | 2048 | 4096) {
            return Err(ParseError::InvalidField {
                field: "block_size",
                reason: "unsupported (FrankenFS v1 supports 1K/2K/4K ext4 only)",
            });
        }

        if (self.feature_incompat & EXT4_INCOMPAT_REQUIRED_MASK) != EXT4_INCOMPAT_REQUIRED_MASK {
            return Err(ParseError::InvalidField {
                field: "s_feature_incompat",
                reason: "missing required FILETYPE/EXTENTS features",
            });
        }

        if (self.feature_incompat & EXT4_INCOMPAT_REJECT_MASK) != 0 {
            return Err(ParseError::InvalidField {
                field: "s_feature_incompat",
                reason: "contains explicitly unsupported incompatible feature flags",
            });
        }

        if (self.feature_incompat & !EXT4_INCOMPAT_ALLOWED_MASK) != 0 {
            return Err(ParseError::InvalidField {
                field: "s_feature_incompat",
                reason: "unknown incompatible feature flags present",
            });
        }

        Ok(())
    }

    /// Compute the byte offset of a group descriptor within the GDT.
    ///
    /// The group descriptor table starts at the block after the superblock
    /// (block `first_data_block + 1` for 1K blocks, block 1 for >= 2K blocks).
    pub fn group_desc_offset(&self, group: ffs_types::GroupNumber) -> Option<u64> {
        let gdt_start_block = if self.block_size == 1024 { 2_u64 } else { 1_u64 };
        let gdt_start_byte = gdt_start_block.checked_mul(u64::from(self.block_size))?;
        let desc_offset = u64::from(group.0).checked_mul(u64::from(self.group_desc_size()))?;
        gdt_start_byte.checked_add(desc_offset)
    }

    /// Compute the byte offset of an inode within the inode table.
    ///
    /// Returns `(group, index_in_group, byte_offset_in_inode_table)`.
    /// The caller must read the group descriptor to find the inode table's
    /// starting block, then add the returned byte offset.
    #[must_use]
    pub fn inode_table_offset(&self, ino: ffs_types::InodeNumber) -> (ffs_types::GroupNumber, u32, u64) {
        let group = ffs_types::inode_to_group(ino, self.inodes_per_group);
        let index = ffs_types::inode_index_in_group(ino, self.inodes_per_group);
        let byte_offset = u64::from(index) * u64::from(self.inode_size);
        (group, index, byte_offset)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4GroupDesc {
    pub block_bitmap: u64,
    pub inode_bitmap: u64,
    pub inode_table: u64,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    pub used_dirs_count: u32,
    pub itable_unused: u32,
    pub flags: u16,
    pub checksum: u16,
}

impl Ext4GroupDesc {
    pub fn parse_from_bytes(bytes: &[u8], desc_size: u16) -> Result<Self, ParseError> {
        let desc_size_usize = usize::from(desc_size);
        if desc_size_usize < 32 {
            return Err(ParseError::InvalidField {
                field: "s_desc_size",
                reason: "descriptor size must be >= 32",
            });
        }
        if bytes.len() < desc_size_usize {
            return Err(ParseError::InsufficientData {
                needed: desc_size_usize,
                offset: 0,
                actual: bytes.len(),
            });
        }

        let block_bitmap_lo = u64::from(read_le_u32(bytes, 0x00)?);
        let inode_bitmap_lo = u64::from(read_le_u32(bytes, 0x04)?);
        let inode_table_lo = u64::from(read_le_u32(bytes, 0x08)?);
        let free_blocks_lo = u32::from(read_le_u16(bytes, 0x0C)?);
        let free_inodes_lo = u32::from(read_le_u16(bytes, 0x0E)?);
        let used_dirs_lo = u32::from(read_le_u16(bytes, 0x10)?);
        let flags = read_le_u16(bytes, 0x12)?;
        let itable_unused_lo = u32::from(read_le_u16(bytes, 0x1C)?);
        let checksum = read_le_u16(bytes, 0x1E)?;

        if desc_size_usize >= 64 {
            let block_bitmap_hi = u64::from(read_le_u32(bytes, 0x20)?);
            let inode_bitmap_hi = u64::from(read_le_u32(bytes, 0x24)?);
            let inode_table_hi = u64::from(read_le_u32(bytes, 0x28)?);

            let free_blocks_hi = u32::from(read_le_u16(bytes, 0x2C)?);
            let free_inodes_hi = u32::from(read_le_u16(bytes, 0x2E)?);
            let used_dirs_hi = u32::from(read_le_u16(bytes, 0x30)?);
            let itable_unused_hi = u32::from(read_le_u16(bytes, 0x32)?);

            Ok(Self {
                block_bitmap: block_bitmap_lo | (block_bitmap_hi << 32),
                inode_bitmap: inode_bitmap_lo | (inode_bitmap_hi << 32),
                inode_table: inode_table_lo | (inode_table_hi << 32),
                free_blocks_count: free_blocks_lo | (free_blocks_hi << 16),
                free_inodes_count: free_inodes_lo | (free_inodes_hi << 16),
                used_dirs_count: used_dirs_lo | (used_dirs_hi << 16),
                itable_unused: itable_unused_lo | (itable_unused_hi << 16),
                flags,
                checksum,
            })
        } else {
            Ok(Self {
                block_bitmap: block_bitmap_lo,
                inode_bitmap: inode_bitmap_lo,
                inode_table: inode_table_lo,
                free_blocks_count: free_blocks_lo,
                free_inodes_count: free_inodes_lo,
                used_dirs_count: used_dirs_lo,
                itable_unused: itable_unused_lo,
                flags,
                checksum,
            })
        }
    }
}

/// ext4 inode flags
const EXT4_HUGE_FILE_FL: u32 = 0x0004_0000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4Inode {
    // ── Core fields (base 128 bytes) ─────────────────────────────────────
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub links_count: u16,
    pub blocks: u64,
    pub flags: u32,
    pub generation: u32,
    pub file_acl: u64,

    // ── Timestamps (seconds) ─────────────────────────────────────────────
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub dtime: u32,

    // ── Extended timestamps (nanoseconds + epoch extension) ──────────────
    pub atime_extra: u32,
    pub ctime_extra: u32,
    pub mtime_extra: u32,
    pub crtime: u32,
    pub crtime_extra: u32,

    // ── Extended area ────────────────────────────────────────────────────
    pub extra_isize: u16,
    pub checksum: u32,
    pub projid: u32,

    // ── Extent / inline data ─────────────────────────────────────────────
    pub extent_bytes: Vec<u8>,
}

impl Ext4Inode {
    /// Parse an ext4 inode from raw bytes.
    ///
    /// `inode_size` is from the superblock (`s_inode_size`). Minimum 128 bytes,
    /// but we require at least 160 for the standard fields + i_block area.
    pub fn parse_from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 128 {
            return Err(ParseError::InsufficientData {
                needed: 128,
                offset: 0,
                actual: bytes.len(),
            });
        }

        // ── Base 128-byte area ───────────────────────────────────────────
        let uid_lo = u32::from(read_le_u16(bytes, 0x02)?);
        let gid_lo = u32::from(read_le_u16(bytes, 0x18)?);

        let size_lo = u64::from(read_le_u32(bytes, 0x04)?);
        let size_hi = if bytes.len() > 0x6E {
            u64::from(read_le_u32(bytes, 0x6C)?)
        } else {
            0
        };

        let blocks_lo = u64::from(read_le_u32(bytes, 0x1C)?);
        let flags = read_le_u32(bytes, 0x20)?;
        let generation = read_le_u32(bytes, 0x64)?;
        let file_acl_lo = u64::from(read_le_u32(bytes, 0x68)?);

        // Extent bytes: i_block[0..14] = 60 bytes at offset 0x28
        // Only read if we have enough data (some truncated test inodes may be short)
        let extent_bytes = if bytes.len() >= 0x28 + 60 {
            read_fixed::<60>(bytes, 0x28)?.to_vec()
        } else {
            vec![0_u8; 60]
        };

        // ── OS-dependent fields at 0x74..0x80 (Linux layout) ─────────────
        let (uid_hi, gid_hi, blocks_hi, file_acl_hi, checksum_lo) = if bytes.len() >= 0x80 {
            let blocks_hi = u64::from(read_le_u16(bytes, 0x74)?);
            let file_acl_hi = u64::from(read_le_u16(bytes, 0x76)?);
            let uid_hi = u32::from(read_le_u16(bytes, 0x78)?);
            let gid_hi = u32::from(read_le_u16(bytes, 0x7A)?);
            let csum_lo = u32::from(read_le_u16(bytes, 0x7C)?);
            (uid_hi, gid_hi, blocks_hi, file_acl_hi, csum_lo)
        } else {
            (0, 0, 0, 0, 0)
        };

        let blocks_raw = blocks_lo | (blocks_hi << 32);
        // If HUGE_FILE flag is set and blocks count is in filesystem blocks (not 512-byte sectors)
        // we leave it as-is; the caller can interpret based on the flag.
        let blocks = blocks_raw;

        // ── Extended area (0x80+, when inode_size > 128) ─────────────────
        let (extra_isize, checksum_hi, atime_extra, ctime_extra, mtime_extra,
             crtime, crtime_extra, projid) = if bytes.len() > 0x82 {
            let extra_isize = read_le_u16(bytes, 0x80)?;
            let extra_end = 128_usize + usize::from(extra_isize);

            let checksum_hi = if extra_end >= 0x84 && bytes.len() >= 0x84 {
                u32::from(read_le_u16(bytes, 0x82)?)
            } else {
                0
            };
            let ctime_extra = if extra_end >= 0x88 && bytes.len() >= 0x88 {
                read_le_u32(bytes, 0x84)?
            } else {
                0
            };
            let mtime_extra = if extra_end >= 0x8C && bytes.len() >= 0x8C {
                read_le_u32(bytes, 0x88)?
            } else {
                0
            };
            let atime_extra = if extra_end >= 0x90 && bytes.len() >= 0x90 {
                read_le_u32(bytes, 0x8C)?
            } else {
                0
            };
            let crtime = if extra_end >= 0x94 && bytes.len() >= 0x94 {
                read_le_u32(bytes, 0x90)?
            } else {
                0
            };
            let crtime_extra = if extra_end >= 0x98 && bytes.len() >= 0x98 {
                read_le_u32(bytes, 0x94)?
            } else {
                0
            };
            let projid = if extra_end >= 0xA0 && bytes.len() >= 0xA0 {
                read_le_u32(bytes, 0x9C)?
            } else {
                0
            };
            (extra_isize, checksum_hi, atime_extra, ctime_extra, mtime_extra,
             crtime, crtime_extra, projid)
        } else {
            (0, 0, 0, 0, 0, 0, 0, 0)
        };

        Ok(Self {
            mode: read_le_u16(bytes, 0x00)?,
            uid: uid_lo | (uid_hi << 16),
            gid: gid_lo | (gid_hi << 16),
            size: size_lo | (size_hi << 32),
            links_count: read_le_u16(bytes, 0x1A)?,
            blocks,
            flags,
            generation,
            file_acl: file_acl_lo | (file_acl_hi << 32),

            atime: read_le_u32(bytes, 0x08)?,
            ctime: read_le_u32(bytes, 0x0C)?,
            mtime: read_le_u32(bytes, 0x10)?,
            dtime: read_le_u32(bytes, 0x14)?,

            atime_extra,
            ctime_extra,
            mtime_extra,
            crtime,
            crtime_extra,

            extra_isize,
            checksum: checksum_lo | (checksum_hi << 16),
            projid,

            extent_bytes,
        })
    }

    /// Whether the HUGE_FILE flag is set (blocks counted in fs-blocks, not 512-byte sectors).
    #[must_use]
    pub fn is_huge_file(&self) -> bool {
        (self.flags & EXT4_HUGE_FILE_FL) != 0
    }

    /// Whether the EXTENTS flag is set.
    #[must_use]
    pub fn uses_extents(&self) -> bool {
        (self.flags & 0x0008_0000) != 0 // EXT4_EXTENTS_FL
    }

    /// Extract nanoseconds from an `*_extra` timestamp field.
    #[must_use]
    pub fn extra_nsec(extra: u32) -> u32 {
        extra >> 2
    }

    /// Extract epoch extension bits (adds 2^32 seconds to timestamp range).
    #[must_use]
    pub fn extra_epoch(extra: u32) -> u32 {
        extra & 0x3
    }

    /// Full access time as (seconds_since_epoch, nanoseconds).
    #[must_use]
    pub fn atime_full(&self) -> (i64, u32) {
        let epoch = i64::from(Self::extra_epoch(self.atime_extra)) << 32;
        (epoch | i64::from(self.atime), Self::extra_nsec(self.atime_extra))
    }

    /// Full modification time as (seconds_since_epoch, nanoseconds).
    #[must_use]
    pub fn mtime_full(&self) -> (i64, u32) {
        let epoch = i64::from(Self::extra_epoch(self.mtime_extra)) << 32;
        (epoch | i64::from(self.mtime), Self::extra_nsec(self.mtime_extra))
    }

    /// Full inode change time as (seconds_since_epoch, nanoseconds).
    #[must_use]
    pub fn ctime_full(&self) -> (i64, u32) {
        let epoch = i64::from(Self::extra_epoch(self.ctime_extra)) << 32;
        (epoch | i64::from(self.ctime), Self::extra_nsec(self.ctime_extra))
    }

    /// Full creation time as (seconds_since_epoch, nanoseconds).
    #[must_use]
    pub fn crtime_full(&self) -> (i64, u32) {
        let epoch = i64::from(Self::extra_epoch(self.crtime_extra)) << 32;
        (epoch | i64::from(self.crtime), Self::extra_nsec(self.crtime_extra))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4ExtentHeader {
    pub magic: u16,
    pub entries: u16,
    pub max_entries: u16,
    pub depth: u16,
    pub generation: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4Extent {
    pub logical_block: u32,
    pub raw_len: u16,
    pub physical_start: u64,
}

impl Ext4Extent {
    #[must_use]
    pub fn is_unwritten(self) -> bool {
        self.raw_len > EXT_INIT_MAX_LEN
    }

    #[must_use]
    pub fn actual_len(self) -> u16 {
        if self.raw_len <= EXT_INIT_MAX_LEN {
            self.raw_len
        } else {
            self.raw_len - EXT_INIT_MAX_LEN
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4ExtentIndex {
    pub logical_block: u32,
    pub leaf_block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtentTree {
    Leaf(Vec<Ext4Extent>),
    Index(Vec<Ext4ExtentIndex>),
}

pub fn parse_extent_tree(bytes: &[u8]) -> Result<(Ext4ExtentHeader, ExtentTree), ParseError> {
    if bytes.len() < 12 {
        return Err(ParseError::InsufficientData {
            needed: 12,
            offset: 0,
            actual: bytes.len(),
        });
    }

    let header = Ext4ExtentHeader {
        magic: read_le_u16(bytes, 0x00)?,
        entries: read_le_u16(bytes, 0x02)?,
        max_entries: read_le_u16(bytes, 0x04)?,
        depth: read_le_u16(bytes, 0x06)?,
        generation: read_le_u32(bytes, 0x08)?,
    };

    if header.magic != EXT4_EXTENT_MAGIC {
        return Err(ParseError::InvalidMagic {
            expected: u64::from(EXT4_EXTENT_MAGIC),
            actual: u64::from(header.magic),
        });
    }

    if header.entries > header.max_entries {
        return Err(ParseError::InvalidField {
            field: "eh_entries",
            reason: "entries exceed max",
        });
    }

    let entries_len = usize::from(header.entries);
    let needed =
        12_usize
            .checked_add(entries_len.saturating_mul(12))
            .ok_or(ParseError::InvalidField {
                field: "extent_entries",
                reason: "overflow",
            })?;

    if bytes.len() < needed {
        return Err(ParseError::InsufficientData {
            needed,
            offset: 12,
            actual: bytes.len().saturating_sub(12),
        });
    }

    if header.depth == 0 {
        let mut extents = Vec::with_capacity(entries_len);
        for idx in 0..entries_len {
            let base = 12 + idx * 12;
            let logical_block = read_le_u32(bytes, base)?;
            let raw_len = read_le_u16(bytes, base + 4)?;
            let start_hi = u64::from(read_le_u16(bytes, base + 6)?);
            let start_lo = u64::from(read_le_u32(bytes, base + 8)?);
            let physical_start = start_lo | (start_hi << 32);

            extents.push(Ext4Extent {
                logical_block,
                raw_len,
                physical_start,
            });
        }

        Ok((header, ExtentTree::Leaf(extents)))
    } else {
        let mut indexes = Vec::with_capacity(entries_len);
        for idx in 0..entries_len {
            let base = 12 + idx * 12;
            let logical_block = read_le_u32(bytes, base)?;
            let leaf_lo = u64::from(read_le_u32(bytes, base + 4)?);
            let leaf_hi = u64::from(read_le_u16(bytes, base + 8)?);
            let leaf_block = leaf_lo | (leaf_hi << 32);

            indexes.push(Ext4ExtentIndex {
                logical_block,
                leaf_block,
            });
        }

        Ok((header, ExtentTree::Index(indexes)))
    }
}

pub fn parse_inode_extent_tree(
    inode: &Ext4Inode,
) -> Result<(Ext4ExtentHeader, ExtentTree), ParseError> {
    parse_extent_tree(&inode.extent_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ext4_superblock_region_smoke() {
        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];

        sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x00..0x04].copy_from_slice(&100_u32.to_le_bytes());
        sb[0x04..0x08].copy_from_slice(&200_u32.to_le_bytes());
        sb[0x10..0x14].copy_from_slice(&50_u32.to_le_bytes());
        sb[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes());
        sb[0x20..0x24].copy_from_slice(&32768_u32.to_le_bytes());
        sb[0x28..0x2C].copy_from_slice(&8192_u32.to_le_bytes());
        sb[0x5C..0x60].copy_from_slice(&1_u32.to_le_bytes());
        sb[0x60..0x64].copy_from_slice(&2_u32.to_le_bytes());
        sb[0x64..0x68].copy_from_slice(&4_u32.to_le_bytes());
        sb[0x78..0x7E].copy_from_slice(b"franks");

        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("superblock parse");
        assert_eq!(parsed.inodes_count, 100);
        assert_eq!(parsed.blocks_count, 200);
        assert_eq!(parsed.block_size, 4096);
        assert_eq!(parsed.volume_name, "franks");
    }

    /// Helper: build a minimal valid superblock buffer with required geometry.
    fn make_valid_sb() -> [u8; EXT4_SUPERBLOCK_SIZE] {
        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
        sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes()); // log_block_size=2 -> 4K
        sb[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_count
        sb[0x04..0x08].copy_from_slice(&32768_u32.to_le_bytes()); // blocks_count_lo
        sb[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes()); // first_data_block
        sb[0x20..0x24].copy_from_slice(&32768_u32.to_le_bytes()); // blocks_per_group
        sb[0x28..0x2C].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_per_group
        sb[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size
        sb
    }

    #[test]
    fn validate_superblock_features_v1() {
        let mut sb = make_valid_sb();

        // required incompat bits: FILETYPE + EXTENTS
        let incompat =
            (EXT4_FEATURE_INCOMPAT_FILETYPE | EXT4_FEATURE_INCOMPAT_EXTENTS).to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);

        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        parsed.validate_v1().expect("validate");

        let mut sb2 = sb;
        // add an unknown incompat bit
        let unknown =
            (EXT4_FEATURE_INCOMPAT_FILETYPE | EXT4_FEATURE_INCOMPAT_EXTENTS | (1_u32 << 31))
                .to_le_bytes();
        sb2[0x60..0x64].copy_from_slice(&unknown);
        let parsed2 = Ext4Superblock::parse_superblock_region(&sb2).expect("parse2");
        assert!(parsed2.validate_v1().is_err());
    }

    #[test]
    fn validate_geometry_catches_bad_values() {
        let mut sb = make_valid_sb();
        let incompat =
            (EXT4_FEATURE_INCOMPAT_FILETYPE | EXT4_FEATURE_INCOMPAT_EXTENTS).to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);

        // Zero blocks_per_group
        let mut bad = sb;
        bad[0x20..0x24].copy_from_slice(&0_u32.to_le_bytes());
        let p = Ext4Superblock::parse_superblock_region(&bad).unwrap();
        assert!(p.validate_geometry().is_err());

        // inode_size not power of two
        let mut bad = sb;
        bad[0x58..0x5A].copy_from_slice(&200_u16.to_le_bytes());
        let p = Ext4Superblock::parse_superblock_region(&bad).unwrap();
        assert!(p.validate_geometry().is_err());

        // first_data_block >= blocks_count
        let mut bad = sb;
        bad[0x14..0x18].copy_from_slice(&99999_u32.to_le_bytes());
        let p = Ext4Superblock::parse_superblock_region(&bad).unwrap();
        assert!(p.validate_geometry().is_err());
    }

    #[test]
    fn superblock_new_fields_parse() {
        let mut sb = make_valid_sb();
        sb[0x2C..0x30].copy_from_slice(&1700000000_u32.to_le_bytes()); // mtime
        sb[0x3A..0x3C].copy_from_slice(&1_u16.to_le_bytes()); // state=clean
        sb[0x4C..0x50].copy_from_slice(&1_u32.to_le_bytes()); // rev_level=DYNAMIC
        sb[0x54..0x58].copy_from_slice(&11_u32.to_le_bytes()); // first_ino
        sb[0xE0..0xE4].copy_from_slice(&8_u32.to_le_bytes()); // journal_inum
        sb[0xEC..0xF0].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes()); // hash_seed[0]
        sb[0xFC] = 1; // def_hash_version=HalfMD4
        sb[0x174] = 4; // log_groups_per_flex
        sb[0x175] = 1; // checksum_type=crc32c

        let parsed = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        assert_eq!(parsed.mtime, 1_700_000_000);
        assert_eq!(parsed.state, 1);
        assert_eq!(parsed.rev_level, 1);
        assert_eq!(parsed.first_ino, 11);
        assert_eq!(parsed.journal_inum, 8);
        assert_eq!(parsed.hash_seed[0], 0xDEAD_BEEF);
        assert_eq!(parsed.def_hash_version, 1);
        assert_eq!(parsed.log_groups_per_flex, 4);
        assert_eq!(parsed.checksum_type, 1);
        assert_eq!(parsed.groups_count(), 1);
    }

    #[test]
    fn inode_location_math() {
        let sb = {
            let mut buf = make_valid_sb();
            // 4K blocks, 8192 inodes per group, inode_size=256
            buf[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes());
            Ext4Superblock::parse_superblock_region(&buf).unwrap()
        };

        // Inode 1: group 0, index 0, offset 0
        let (g, idx, off) = sb.inode_table_offset(ffs_types::InodeNumber(1));
        assert_eq!(g, ffs_types::GroupNumber(0));
        assert_eq!(idx, 0);
        assert_eq!(off, 0);

        // Inode 2 (root): group 0, index 1, offset 256
        let (g, idx, off) = sb.inode_table_offset(ffs_types::InodeNumber(2));
        assert_eq!(g, ffs_types::GroupNumber(0));
        assert_eq!(idx, 1);
        assert_eq!(off, 256);

        // Inode 8193: group 1, index 0, offset 0
        let (g, idx, off) = sb.inode_table_offset(ffs_types::InodeNumber(8193));
        assert_eq!(g, ffs_types::GroupNumber(1));
        assert_eq!(idx, 0);
        assert_eq!(off, 0);

        // Group descriptor offset: GDT starts at block 1 for 4K blocks
        let gd_off = sb.group_desc_offset(ffs_types::GroupNumber(0)).unwrap();
        assert_eq!(gd_off, 4096); // block 1 * 4096

        // Without 64BIT flag, desc size is 32
        assert_eq!(sb.group_desc_size(), 32);
        let gd_off_1 = sb.group_desc_offset(ffs_types::GroupNumber(1)).unwrap();
        assert_eq!(gd_off_1, 4096 + 32);
    }

    #[test]
    fn parse_group_desc_32_and_64() {
        let mut gd32 = [0_u8; 32];
        gd32[0x00..0x04].copy_from_slice(&123_u32.to_le_bytes());
        gd32[0x04..0x08].copy_from_slice(&456_u32.to_le_bytes());
        gd32[0x08..0x0C].copy_from_slice(&789_u32.to_le_bytes());
        gd32[0x0C..0x0E].copy_from_slice(&10_u16.to_le_bytes());
        gd32[0x0E..0x10].copy_from_slice(&11_u16.to_le_bytes());
        gd32[0x10..0x12].copy_from_slice(&12_u16.to_le_bytes());
        gd32[0x12..0x14].copy_from_slice(&0xAA55_u16.to_le_bytes());
        gd32[0x1C..0x1E].copy_from_slice(&99_u16.to_le_bytes());
        gd32[0x1E..0x20].copy_from_slice(&0x1234_u16.to_le_bytes());

        let parsed32 = Ext4GroupDesc::parse_from_bytes(&gd32, 32).expect("gd32");
        assert_eq!(parsed32.block_bitmap, 123);
        assert_eq!(parsed32.inode_bitmap, 456);
        assert_eq!(parsed32.inode_table, 789);
        assert_eq!(parsed32.free_blocks_count, 10);
        assert_eq!(parsed32.itable_unused, 99);
        assert_eq!(parsed32.flags, 0xAA55);
        assert_eq!(parsed32.checksum, 0x1234);

        let mut gd64 = [0_u8; 64];
        gd64[..32].copy_from_slice(&gd32);
        gd64[0x20..0x24].copy_from_slice(&1_u32.to_le_bytes());
        gd64[0x24..0x28].copy_from_slice(&2_u32.to_le_bytes());
        gd64[0x28..0x2C].copy_from_slice(&3_u32.to_le_bytes());
        gd64[0x2C..0x2E].copy_from_slice(&4_u16.to_le_bytes());
        gd64[0x2E..0x30].copy_from_slice(&5_u16.to_le_bytes());
        gd64[0x30..0x32].copy_from_slice(&6_u16.to_le_bytes());
        gd64[0x32..0x34].copy_from_slice(&7_u16.to_le_bytes());

        let parsed64 = Ext4GroupDesc::parse_from_bytes(&gd64, 64).expect("gd64");
        assert_eq!(parsed64.block_bitmap, (1_u64 << 32) | 0x007b_u64);
        assert_eq!(parsed64.inode_bitmap, (2_u64 << 32) | 0x01c8_u64);
        assert_eq!(parsed64.inode_table, (3_u64 << 32) | 0x0315_u64);
        assert_eq!(parsed64.free_blocks_count, 0x000a_u32 | (4_u32 << 16));
        assert_eq!(parsed64.free_inodes_count, 0x000b_u32 | (5_u32 << 16));
        assert_eq!(parsed64.used_dirs_count, 0x000c_u32 | (6_u32 << 16));
        assert_eq!(parsed64.itable_unused, 0x0063_u32 | (7_u32 << 16));
    }

    #[test]
    fn parse_inode_and_extent_leaf() {
        let mut inode = [0_u8; 256];
        inode[0x00..0x02].copy_from_slice(&0o100_644_u16.to_le_bytes());
        inode[0x04..0x08].copy_from_slice(&4096_u32.to_le_bytes());
        inode[0x6C..0x70].copy_from_slice(&0_u32.to_le_bytes());

        // extent header at i_block
        let i_block = 0x28;
        inode[i_block..i_block + 2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
        inode[i_block + 2..i_block + 4].copy_from_slice(&1_u16.to_le_bytes());
        inode[i_block + 4..i_block + 6].copy_from_slice(&4_u16.to_le_bytes());
        inode[i_block + 6..i_block + 8].copy_from_slice(&0_u16.to_le_bytes());
        inode[i_block + 8..i_block + 12].copy_from_slice(&7_u32.to_le_bytes());
        // first extent entry
        let e = i_block + 12;
        inode[e..e + 4].copy_from_slice(&0_u32.to_le_bytes());
        inode[e + 4..e + 6].copy_from_slice(&8_u16.to_le_bytes());
        inode[e + 6..e + 8].copy_from_slice(&0_u16.to_le_bytes());
        inode[e + 8..e + 12].copy_from_slice(&1234_u32.to_le_bytes());

        let parsed_inode = Ext4Inode::parse_from_bytes(&inode).expect("inode parse");
        let (_, tree) = parse_inode_extent_tree(&parsed_inode).expect("extent parse");
        match tree {
            ExtentTree::Leaf(exts) => {
                assert_eq!(exts.len(), 1);
                assert_eq!(exts[0].logical_block, 0);
                assert_eq!(exts[0].actual_len(), 8);
                assert_eq!(exts[0].physical_start, 1234);
            }
            ExtentTree::Index(_) => panic!("expected leaf"),
        }
    }

    #[test]
    fn inode_expanded_fields() {
        let mut raw = [0_u8; 256];

        // mode = regular file 0644
        raw[0x00..0x02].copy_from_slice(&0o100_644_u16.to_le_bytes());
        // uid_lo = 1000
        raw[0x02..0x04].copy_from_slice(&1000_u16.to_le_bytes());
        // size_lo = 8192
        raw[0x04..0x08].copy_from_slice(&8192_u32.to_le_bytes());
        // atime = 1700000000
        raw[0x08..0x0C].copy_from_slice(&1_700_000_000_u32.to_le_bytes());
        // ctime
        raw[0x0C..0x10].copy_from_slice(&1_700_000_100_u32.to_le_bytes());
        // mtime
        raw[0x10..0x14].copy_from_slice(&1_700_000_200_u32.to_le_bytes());
        // gid_lo = 100
        raw[0x18..0x1A].copy_from_slice(&100_u16.to_le_bytes());
        // links_count = 1
        raw[0x1A..0x1C].copy_from_slice(&1_u16.to_le_bytes());
        // blocks_lo = 16 (512-byte sectors for 8K of data)
        raw[0x1C..0x20].copy_from_slice(&16_u32.to_le_bytes());
        // flags: EXTENTS flag
        raw[0x20..0x24].copy_from_slice(&0x0008_0000_u32.to_le_bytes());
        // generation
        raw[0x64..0x68].copy_from_slice(&42_u32.to_le_bytes());
        // file_acl_lo = 0
        raw[0x68..0x6C].copy_from_slice(&0_u32.to_le_bytes());
        // size_hi = 0
        raw[0x6C..0x70].copy_from_slice(&0_u32.to_le_bytes());

        // uid_hi = 0, gid_hi = 0 (stay as 1000 / 100)
        raw[0x78..0x7A].copy_from_slice(&0_u16.to_le_bytes());
        raw[0x7A..0x7C].copy_from_slice(&0_u16.to_le_bytes());

        // extra_isize = 32 (0x80 + 32 = 0xA0, covers all extended fields)
        raw[0x80..0x82].copy_from_slice(&32_u16.to_le_bytes());
        // ctime_extra: 500_000_000 ns << 2 = 2_000_000_000
        raw[0x84..0x88].copy_from_slice(&(500_000_000_u32 << 2).to_le_bytes());
        // mtime_extra: 250_000_000 ns << 2
        raw[0x88..0x8C].copy_from_slice(&(250_000_000_u32 << 2).to_le_bytes());
        // crtime = 1_600_000_000
        raw[0x90..0x94].copy_from_slice(&1_600_000_000_u32.to_le_bytes());

        // Extent header (valid, depth 0, 0 entries)
        raw[0x28..0x2A].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
        raw[0x2A..0x2C].copy_from_slice(&0_u16.to_le_bytes());
        raw[0x2C..0x2E].copy_from_slice(&4_u16.to_le_bytes());

        let inode = Ext4Inode::parse_from_bytes(&raw).unwrap();
        assert_eq!(inode.mode, 0o100_644);
        assert_eq!(inode.uid, 1000);
        assert_eq!(inode.gid, 100);
        assert_eq!(inode.size, 8192);
        assert_eq!(inode.links_count, 1);
        assert_eq!(inode.blocks, 16);
        assert!(inode.uses_extents());
        assert_eq!(inode.generation, 42);

        // Timestamps
        assert_eq!(inode.atime, 1_700_000_000);
        assert_eq!(inode.ctime, 1_700_000_100);
        assert_eq!(inode.mtime, 1_700_000_200);

        // Extended timestamps
        let (ctime_s, ctime_ns) = inode.ctime_full();
        assert_eq!(ctime_s, 1_700_000_100);
        assert_eq!(ctime_ns, 500_000_000);

        let (mtime_s, mtime_ns) = inode.mtime_full();
        assert_eq!(mtime_s, 1_700_000_200);
        assert_eq!(mtime_ns, 250_000_000);

        // Creation time
        assert_eq!(inode.crtime, 1_600_000_000);

        // Extended inode area
        assert_eq!(inode.extra_isize, 32);
    }

    #[test]
    fn inode_32bit_uid_gid() {
        let mut raw = [0_u8; 256];
        raw[0x02..0x04].copy_from_slice(&0xFFFF_u16.to_le_bytes()); // uid_lo
        raw[0x18..0x1A].copy_from_slice(&0x1234_u16.to_le_bytes()); // gid_lo
        raw[0x78..0x7A].copy_from_slice(&0x0001_u16.to_le_bytes()); // uid_hi
        raw[0x7A..0x7C].copy_from_slice(&0x0002_u16.to_le_bytes()); // gid_hi

        let inode = Ext4Inode::parse_from_bytes(&raw).unwrap();
        assert_eq!(inode.uid, 0x0001_FFFF); // 131071
        assert_eq!(inode.gid, 0x0002_1234); // 135732
    }
}
