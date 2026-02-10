#![forbid(unsafe_code)]

use ffs_types::{
    EXT4_EXTENTS_FL, EXT4_FAST_SYMLINK_MAX, EXT4_INDEX_FL, EXT4_SUPER_MAGIC,
    EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE, EXT4_XATTR_MAGIC, ParseError, S_IFBLK, S_IFCHR,
    S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK, ensure_slice,
    ext4_block_size_from_log, read_fixed, read_le_u16, read_le_u32, trim_nul_padded,
};
use serde::{Deserialize, Serialize};

const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
const EXT_INIT_MAX_LEN: u16 = 1_u16 << 15;

// ── ext4 feature flags ─────────────────────────────────────────────────────

/// ext4 compatible feature flags (`s_feature_compat`).
///
/// These are advisory; unknown bits are safe to ignore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4CompatFeatures(pub u32);

impl Ext4CompatFeatures {
    pub const DIR_PREALLOC: Self = Self(0x0001);
    pub const IMAGIC_INODES: Self = Self(0x0002);
    pub const HAS_JOURNAL: Self = Self(0x0004);
    pub const EXT_ATTR: Self = Self(0x0008);
    pub const RESIZE_INODE: Self = Self(0x0010);
    pub const DIR_INDEX: Self = Self(0x0020);
    pub const SPARSE_SUPER2: Self = Self(0x0200);
    pub const FAST_COMMIT: Self = Self(0x0400);
    pub const STABLE_INODES: Self = Self(0x0800);
    pub const ORPHAN_FILE: Self = Self(0x1000);

    #[must_use]
    pub fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }
}

/// ext4 incompatible feature flags (`s_feature_incompat`).
///
/// Unknown bits MUST cause mount failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4IncompatFeatures(pub u32);

impl Ext4IncompatFeatures {
    pub const COMPRESSION: Self = Self(0x0001);
    pub const FILETYPE: Self = Self(0x0002);
    pub const RECOVER: Self = Self(0x0004);
    pub const JOURNAL_DEV: Self = Self(0x0008);
    pub const META_BG: Self = Self(0x0010);
    pub const EXTENTS: Self = Self(0x0040);
    pub const BIT64: Self = Self(0x0080);
    pub const MMP: Self = Self(0x0100);
    pub const FLEX_BG: Self = Self(0x0200);
    pub const EA_INODE: Self = Self(0x0400);
    pub const DIRDATA: Self = Self(0x1000);
    pub const CSUM_SEED: Self = Self(0x2000);
    pub const LARGEDIR: Self = Self(0x4000);
    pub const INLINE_DATA: Self = Self(0x8000);
    pub const ENCRYPT: Self = Self(0x10000);
    pub const CASEFOLD: Self = Self(0x20000);

    /// Features required for FrankenFS v1 ext4 parsing.
    pub const REQUIRED_V1: Self = Self(Self::FILETYPE.0 | Self::EXTENTS.0);

    /// Bits FrankenFS v1 can parse/understand without failing mount validation.
    pub const ALLOWED_V1: Self = Self(
        Self::FILETYPE.0
            | Self::EXTENTS.0
            | Self::RECOVER.0
            | Self::META_BG.0
            | Self::BIT64.0
            | Self::MMP.0
            | Self::FLEX_BG.0
            | Self::EA_INODE.0
            | Self::DIRDATA.0
            | Self::CSUM_SEED.0
            | Self::LARGEDIR.0,
    );

    /// Bits FrankenFS v1 explicitly rejects.
    pub const REJECTED_V1: Self = Self(
        Self::COMPRESSION.0
            | Self::JOURNAL_DEV.0
            | Self::INLINE_DATA.0
            | Self::ENCRYPT.0
            | Self::CASEFOLD.0,
    );

    #[must_use]
    pub fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }
}

/// ext4 read-only compatible feature flags (`s_feature_ro_compat`).
///
/// Unknown bits imply the filesystem must not be mounted read-write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4RoCompatFeatures(pub u32);

impl Ext4RoCompatFeatures {
    pub const SPARSE_SUPER: Self = Self(0x0001);
    pub const LARGE_FILE: Self = Self(0x0002);
    pub const BTREE_DIR: Self = Self(0x0004);
    pub const HUGE_FILE: Self = Self(0x0008);
    pub const GDT_CSUM: Self = Self(0x0010);
    pub const DIR_NLINK: Self = Self(0x0020);
    pub const EXTRA_ISIZE: Self = Self(0x0040);
    pub const QUOTA: Self = Self(0x0100);
    pub const BIGALLOC: Self = Self(0x0200);
    pub const METADATA_CSUM: Self = Self(0x0400);
    pub const READONLY: Self = Self(0x1000);
    pub const PROJECT: Self = Self(0x2000);
    pub const VERITY: Self = Self(0x8000);
    pub const ORPHAN_PRESENT: Self = Self(0x10000);

    #[must_use]
    pub fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }
}

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
    pub log_cluster_size: u32,
    pub cluster_size: u32,
    pub blocks_per_group: u32,
    pub clusters_per_group: u32,
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
    pub feature_compat: Ext4CompatFeatures,
    pub feature_incompat: Ext4IncompatFeatures,
    pub feature_ro_compat: Ext4RoCompatFeatures,
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
        if !matches!(block_size, 1024 | 2048 | 4096) {
            return Err(ParseError::InvalidField {
                field: "s_log_block_size",
                reason: "unsupported block size",
            });
        }

        let log_cluster_size = read_le_u32(region, 0x1C)?;
        let Some(cluster_size) = ext4_block_size_from_log(log_cluster_size) else {
            return Err(ParseError::InvalidField {
                field: "s_log_cluster_size",
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
            log_cluster_size,
            cluster_size,
            blocks_per_group: read_le_u32(region, 0x20)?,
            clusters_per_group: read_le_u32(region, 0x24)?,
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
            feature_compat: Ext4CompatFeatures(read_le_u32(region, 0x5C)?),
            feature_incompat: Ext4IncompatFeatures(read_le_u32(region, 0x60)?),
            feature_ro_compat: Ext4RoCompatFeatures(read_le_u32(region, 0x64)?),
            default_mount_opts: read_le_u32(region, 0x100)?,

            // State & error tracking
            state: read_le_u16(region, 0x3A)?,
            errors: read_le_u16(region, 0x3C)?,
            mnt_count: read_le_u16(region, 0x34)?,
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
    pub fn has_compat(&self, mask: Ext4CompatFeatures) -> bool {
        (self.feature_compat.0 & mask.0) != 0
    }

    #[must_use]
    pub fn has_incompat(&self, mask: Ext4IncompatFeatures) -> bool {
        (self.feature_incompat.0 & mask.0) != 0
    }

    #[must_use]
    pub fn has_ro_compat(&self, mask: Ext4RoCompatFeatures) -> bool {
        (self.feature_ro_compat.0 & mask.0) != 0
    }

    #[must_use]
    pub fn is_64bit(&self) -> bool {
        self.has_incompat(Ext4IncompatFeatures::BIT64)
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
    #[allow(clippy::cast_possible_truncation)] // ext4 group count is u32
    pub fn groups_count(&self) -> u32 {
        if self.blocks_per_group == 0 {
            return 0;
        }
        let data_blocks = self
            .blocks_count
            .saturating_sub(u64::from(self.first_data_block));
        let groups = data_blocks.div_ceil(u64::from(self.blocks_per_group));
        groups as u32
    }

    /// Whether this superblock uses metadata checksums (crc32c).
    #[must_use]
    pub fn has_metadata_csum(&self) -> bool {
        self.has_ro_compat(Ext4RoCompatFeatures::METADATA_CSUM)
    }

    /// Compute the crc32c checksum seed used for metadata checksums.
    ///
    /// If `INCOMPAT_CSUM_SEED` is set, uses the precomputed `checksum_seed` field.
    /// Otherwise, computes `ext4_chksum(~0, uuid)`.
    ///
    /// The kernel's `ext4_chksum(sbi, seed, data, len)` maps to
    /// `crc32c::crc32c_append(seed, data)` — **not** `crc32c::crc32c(data)`,
    /// which uses a different initial value.
    #[must_use]
    pub fn csum_seed(&self) -> u32 {
        if self.has_incompat(Ext4IncompatFeatures::CSUM_SEED) {
            self.checksum_seed
        } else {
            // kernel: ext4_chksum(sbi, ~0, uuid, 16) = crc32c_append(!0, uuid)
            crc32c::crc32c_append(!0u32, &self.uuid)
        }
    }

    /// Validate the superblock's own CRC32C checksum.
    ///
    /// The kernel computes: `ext4_chksum(sbi, ~0, sb_bytes[..0x3FC])`.
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
        // kernel: ext4_chksum(sbi, ~0, es, offsetof(s_checksum))
        let computed = crc32c::crc32c_append(!0u32, &raw_region[..0x3FC]);
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

        if (self.feature_incompat.0 & Ext4IncompatFeatures::REQUIRED_V1.0)
            != Ext4IncompatFeatures::REQUIRED_V1.0
        {
            return Err(ParseError::InvalidField {
                field: "s_feature_incompat",
                reason: "missing required FILETYPE/EXTENTS features",
            });
        }

        if (self.feature_incompat.0 & Ext4IncompatFeatures::REJECTED_V1.0) != 0 {
            return Err(ParseError::InvalidField {
                field: "s_feature_incompat",
                reason: "contains explicitly unsupported incompatible feature flags",
            });
        }

        if (self.feature_incompat.0 & !Ext4IncompatFeatures::ALLOWED_V1.0) != 0 {
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
    #[must_use]
    pub fn group_desc_offset(&self, group: ffs_types::GroupNumber) -> Option<u64> {
        let gdt_start_block = if self.block_size == 1024 {
            2_u64
        } else {
            1_u64
        };
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
    pub fn inode_table_offset(
        &self,
        ino: ffs_types::InodeNumber,
    ) -> (ffs_types::GroupNumber, u32, u64) {
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

// ── Checksum verification helpers ────────────────────────────────────────────

/// Offset of `bg_checksum` within a group descriptor (2 bytes).
const GD_CHECKSUM_OFFSET: usize = 0x1E;

/// Verify a group descriptor's CRC32C checksum (metadata_csum mode).
///
/// `raw_gd` is the raw on-disk group descriptor bytes (32 or 64 bytes).
/// `csum_seed` comes from `Ext4Superblock::csum_seed()`.
/// `group_number` is the block group index.
/// `desc_size` is from `Ext4Superblock::group_desc_size()`.
pub fn verify_group_desc_checksum(
    raw_gd: &[u8],
    csum_seed: u32,
    group_number: u32,
    desc_size: u16,
) -> Result<(), ParseError> {
    let ds = usize::from(desc_size);
    if raw_gd.len() < ds {
        return Err(ParseError::InsufficientData {
            needed: ds,
            offset: 0,
            actual: raw_gd.len(),
        });
    }

    let le_group = group_number.to_le_bytes();

    // kernel: csum = ext4_chksum(csum_seed, &le_group, 4)
    let mut csum = crc32c::crc32c_append(csum_seed, &le_group);
    // kernel: csum = ext4_chksum(csum, gd[0..bg_checksum_offset], offset)
    csum = crc32c::crc32c_append(csum, &raw_gd[..GD_CHECKSUM_OFFSET]);
    // kernel: csum = ext4_chksum(csum, &dummy_csum, 2)  (zero out checksum field)
    csum = crc32c::crc32c_append(csum, &[0, 0]);
    // kernel: if offset+2 < desc_size, csum rest
    let after_csum = GD_CHECKSUM_OFFSET + 2;
    if after_csum < ds {
        csum = crc32c::crc32c_append(csum, &raw_gd[after_csum..ds]);
    }

    let expected = (csum & 0xFFFF) as u16;
    let stored = read_le_u16(raw_gd, GD_CHECKSUM_OFFSET)?;

    if expected != stored {
        return Err(ParseError::InvalidField {
            field: "bg_checksum",
            reason: "group descriptor CRC32C mismatch",
        });
    }
    Ok(())
}

/// Offset of `i_checksum_lo` within an ext4 inode (osd2 area, 2 bytes).
const INODE_CHECKSUM_LO_OFFSET: usize = 0x7C;
/// Offset of `i_checksum_hi` within an ext4 inode (extended area, 2 bytes).
const INODE_CHECKSUM_HI_OFFSET: usize = 0x82;

/// Verify an inode's CRC32C checksum (metadata_csum mode).
///
/// `raw_inode` is the raw on-disk inode bytes (inode_size bytes).
/// `csum_seed` comes from `Ext4Superblock::csum_seed()`.
/// `ino` is the inode number.
/// `inode_size` is from the superblock.
#[allow(clippy::cast_possible_truncation)] // checksum is 32-bit
pub fn verify_inode_checksum(
    raw_inode: &[u8],
    csum_seed: u32,
    ino: u32,
    inode_size: u16,
) -> Result<(), ParseError> {
    let is = usize::from(inode_size);
    if raw_inode.len() < is || is < 128 {
        return Err(ParseError::InsufficientData {
            needed: is.max(128),
            offset: 0,
            actual: raw_inode.len(),
        });
    }

    // Per-inode seed: ext4_chksum(csum_seed, &le_ino, 4)
    //   then:        ext4_chksum(ino_seed, &le_gen, 4)
    let le_ino = ino.to_le_bytes();
    let ino_seed = crc32c::crc32c_append(csum_seed, &le_ino);
    let generation = read_le_u32(raw_inode, 0x64)?;
    let le_gen = generation.to_le_bytes();
    let ino_seed = crc32c::crc32c_append(ino_seed, &le_gen);

    // CRC base inode (128 bytes), skipping i_checksum_lo at 0x7C (2 bytes)
    let mut csum = crc32c::crc32c_append(ino_seed, &raw_inode[..INODE_CHECKSUM_LO_OFFSET]);
    csum = crc32c::crc32c_append(csum, &[0, 0]); // zero out checksum_lo
    let after_csum_lo = INODE_CHECKSUM_LO_OFFSET + 2;
    csum = crc32c::crc32c_append(csum, &raw_inode[after_csum_lo..128]);

    // Extended area (when inode_size > 128)
    if is > 128 {
        // CRC bytes from 128 up to i_checksum_hi (0x82), but don't exceed inode_size
        let hi_bound = INODE_CHECKSUM_HI_OFFSET.min(is);
        csum = crc32c::crc32c_append(csum, &raw_inode[128..hi_bound]);

        // Only handle checksum_hi if the inode is large enough to contain it
        if is >= INODE_CHECKSUM_HI_OFFSET + 2 {
            // Check if i_checksum_hi fits per i_extra_isize
            let extra_isize = read_le_u16(raw_inode, 0x80)?;
            let extra_end = 128 + usize::from(extra_isize);
            if extra_end >= INODE_CHECKSUM_HI_OFFSET + 2 {
                // Zero out checksum_hi
                csum = crc32c::crc32c_append(csum, &[0, 0]);
                let after_csum_hi = INODE_CHECKSUM_HI_OFFSET + 2;
                if after_csum_hi < is {
                    csum = crc32c::crc32c_append(csum, &raw_inode[after_csum_hi..is]);
                }
            } else {
                // No checksum_hi field per extra_isize, CRC the rest
                csum = crc32c::crc32c_append(csum, &raw_inode[INODE_CHECKSUM_HI_OFFSET..is]);
            }
        } else if hi_bound < is {
            // inode_size < 132: no room for checksum_hi, CRC remaining bytes
            csum = crc32c::crc32c_append(csum, &raw_inode[hi_bound..is]);
        }
    }

    // Extract stored checksum (lo + hi)
    let stored_lo = u32::from(read_le_u16(raw_inode, INODE_CHECKSUM_LO_OFFSET)?);
    let stored_hi = if is >= INODE_CHECKSUM_HI_OFFSET + 2 {
        // Need at least 130 bytes to read extra_isize at 0x80
        let extra_isize = read_le_u16(raw_inode, 0x80)?;
        let extra_end = 128 + usize::from(extra_isize);
        if extra_end >= INODE_CHECKSUM_HI_OFFSET + 2 {
            u32::from(read_le_u16(raw_inode, INODE_CHECKSUM_HI_OFFSET)?)
        } else {
            0
        }
    } else {
        0
    };
    let stored = stored_lo | (stored_hi << 16);

    if csum != stored {
        return Err(ParseError::InvalidField {
            field: "i_checksum",
            reason: "inode CRC32C mismatch",
        });
    }
    Ok(())
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
    /// Requires at least 128 bytes. Extended fields (timestamps, checksum,
    /// projid) are read when the buffer is large enough and `i_extra_isize`
    /// indicates they are present.
    #[allow(clippy::too_many_lines, clippy::similar_names)]
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
        let (
            extra_isize,
            checksum_hi,
            atime_extra,
            ctime_extra,
            mtime_extra,
            crtime,
            crtime_extra,
            projid,
        ) = if bytes.len() > 0x82 {
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
            (
                extra_isize,
                checksum_hi,
                atime_extra,
                ctime_extra,
                mtime_extra,
                crtime,
                crtime_extra,
                projid,
            )
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
        (self.flags & EXT4_EXTENTS_FL) != 0
    }

    /// Whether this inode has the htree index flag (hash-indexed directory).
    #[must_use]
    pub fn has_htree_index(&self) -> bool {
        (self.flags & EXT4_INDEX_FL) != 0
    }

    // ── File type detection ─────────────────────────────────────────────

    /// Extract the file type bits from the mode field.
    #[must_use]
    pub fn file_type_mode(&self) -> u16 {
        self.mode & S_IFMT
    }

    /// Whether this inode is a regular file.
    #[must_use]
    pub fn is_regular(&self) -> bool {
        self.file_type_mode() == S_IFREG
    }

    /// Whether this inode is a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.file_type_mode() == S_IFDIR
    }

    /// Whether this inode is a symbolic link.
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.file_type_mode() == S_IFLNK
    }

    /// Whether this inode is a character device.
    #[must_use]
    pub fn is_chrdev(&self) -> bool {
        self.file_type_mode() == S_IFCHR
    }

    /// Whether this inode is a block device.
    #[must_use]
    pub fn is_blkdev(&self) -> bool {
        self.file_type_mode() == S_IFBLK
    }

    /// Whether this inode is a FIFO (named pipe).
    #[must_use]
    pub fn is_fifo(&self) -> bool {
        self.file_type_mode() == S_IFIFO
    }

    /// Whether this inode is a socket.
    #[must_use]
    pub fn is_socket(&self) -> bool {
        self.file_type_mode() == S_IFSOCK
    }

    /// Permission bits (lower 12 bits of mode).
    #[must_use]
    pub fn permission_bits(&self) -> u16 {
        self.mode & 0o7777
    }

    // ── Symlink helpers ─────────────────────────────────────────────────

    /// Whether this is a "fast" (inline) symlink stored in the inode's i_block area.
    ///
    /// ext4 stores short symlink targets (up to 60 bytes) directly in the
    /// `i_block` field of the inode rather than in separate data blocks.
    /// This is detected by: symlink type + no extents flag + size <= 60.
    #[must_use]
    pub fn is_fast_symlink(&self) -> bool {
        self.is_symlink() && !self.uses_extents() && (self.size as usize) <= EXT4_FAST_SYMLINK_MAX
    }

    /// Read the target of a fast (inline) symlink from the inode's extent_bytes.
    ///
    /// Returns `None` if this is not a fast symlink.
    #[must_use]
    pub fn fast_symlink_target(&self) -> Option<&[u8]> {
        if !self.is_fast_symlink() {
            return None;
        }
        let len = self.size as usize;
        if len <= self.extent_bytes.len() {
            Some(&self.extent_bytes[..len])
        } else {
            None
        }
    }

    // ── Xattr helpers ───────────────────────────────────────────────────

    /// The raw bytes of the inode body area available for inline xattrs.
    ///
    /// Returns the portion of the inode between `128 + extra_isize` and
    /// the end of the inode. If `extra_isize` is 0 (no extended area),
    /// returns an empty slice.
    #[must_use]
    pub fn xattr_ibody_region(&self) -> &[u8] {
        // Inline xattrs live in the inode body after the fixed fields (128 bytes)
        // plus extra_isize bytes. We stored extent_bytes as bytes [0x28..0x28+60],
        // but the full raw inode is not kept. We'll need to handle this at the
        // ImageReader level where we have access to the full raw inode bytes.
        // This method is a placeholder indicating the concept.
        &[]
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

    /// Reconstruct a full 34-bit timestamp from base u32 + extra epoch bits.
    ///
    /// The kernel sign-extends the base u32 via `(signed)le32_to_cpu(raw->xtime)`
    /// then adds `(epoch_bits << 32)`.  We must do the same — `as i32` reinterprets
    /// the bits as signed, and `i64::from` sign-extends to 64 bits.
    #[allow(clippy::cast_possible_wrap)] // intentional: kernel reinterprets u32 as signed
    fn timestamp_full(base: u32, extra: u32) -> (i64, u32) {
        let signed_base = i64::from(base as i32); // sign-extend, matching kernel
        let epoch = i64::from(Self::extra_epoch(extra)) << 32;
        (signed_base + epoch, Self::extra_nsec(extra))
    }

    /// Full access time as (seconds_since_epoch, nanoseconds).
    #[must_use]
    pub fn atime_full(&self) -> (i64, u32) {
        Self::timestamp_full(self.atime, self.atime_extra)
    }

    /// Full modification time as (seconds_since_epoch, nanoseconds).
    #[must_use]
    pub fn mtime_full(&self) -> (i64, u32) {
        Self::timestamp_full(self.mtime, self.mtime_extra)
    }

    /// Full inode change time as (seconds_since_epoch, nanoseconds).
    #[must_use]
    pub fn ctime_full(&self) -> (i64, u32) {
        Self::timestamp_full(self.ctime, self.ctime_extra)
    }

    /// Full creation time as (seconds_since_epoch, nanoseconds).
    #[must_use]
    pub fn crtime_full(&self) -> (i64, u32) {
        Self::timestamp_full(self.crtime, self.crtime_extra)
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

// ── Directory entry parsing ─────────────────────────────────────────────────

/// ext4 file type constants from directory entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Ext4FileType {
    Unknown = 0,
    RegFile = 1,
    Dir = 2,
    Chrdev = 3,
    Blkdev = 4,
    Fifo = 5,
    Sock = 6,
    Symlink = 7,
}

impl Ext4FileType {
    #[must_use]
    pub fn from_raw(val: u8) -> Self {
        match val {
            1 => Self::RegFile,
            2 => Self::Dir,
            3 => Self::Chrdev,
            4 => Self::Blkdev,
            5 => Self::Fifo,
            6 => Self::Sock,
            7 => Self::Symlink,
            _ => Self::Unknown,
        }
    }
}

/// Sentinel file_type value for directory entry checksum tails.
const EXT4_FT_DIR_CSUM: u8 = 0xDE;

/// A parsed ext4 directory entry (`ext4_dir_entry_2`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4DirEntry {
    pub inode: u32,
    pub rec_len: u16,
    pub name_len: u8,
    pub file_type: Ext4FileType,
    pub name: Vec<u8>,
}

impl Ext4DirEntry {
    /// The actual on-disk size consumed by this entry (padded to 4 bytes).
    #[must_use]
    pub fn actual_size(&self) -> usize {
        // 8 bytes header + name_len, rounded up to 4-byte boundary
        (8 + usize::from(self.name_len) + 3) & !3
    }

    /// Return the name as a UTF-8 string (lossy).
    #[must_use]
    pub fn name_str(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }

    /// Whether this is the `.` entry.
    #[must_use]
    pub fn is_dot(&self) -> bool {
        self.name == b"."
    }

    /// Whether this is the `..` entry.
    #[must_use]
    pub fn is_dotdot(&self) -> bool {
        self.name == b".."
    }
}

/// A checksum tail at the end of a directory block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ext4DirEntryTail {
    pub checksum: u32,
}

/// Decode `rec_len` from its on-disk representation.
///
/// For blocks > 64K the kernel encodes large values by stealing the low 2 bits:
/// `decoded = (raw & 0xFFFC) | ((raw & 0x3) << 16)`.
///
/// For standard 1K-4K blocks (FrankenFS v1 scope), rec_len is always 4-byte
/// aligned so the low 2 bits are 0 and the formula is a no-op.
#[must_use]
fn rec_len_from_disk(raw: u16, _block_size: u32) -> u32 {
    let len = u32::from(raw);
    (len & 0xFFFC) | ((len & 0x3) << 16)
}

/// Parse all directory entries from a single directory data block.
///
/// Returns the entries (excluding checksum tails) and an optional
/// checksum tail if one was found at the end.
pub fn parse_dir_block(
    block: &[u8],
    block_size: u32,
) -> Result<(Vec<Ext4DirEntry>, Option<Ext4DirEntryTail>), ParseError> {
    let mut entries = Vec::new();
    let mut tail = None;
    let mut offset = 0_usize;

    while offset + 8 <= block.len() {
        let inode = read_le_u32(block, offset)?;
        let rec_len_raw = read_le_u16(block, offset + 4)?;
        let name_len = ensure_slice(block, offset + 6, 1)?[0];
        let file_type_raw = ensure_slice(block, offset + 7, 1)?[0];

        let rec_len = rec_len_from_disk(rec_len_raw, block_size);

        // Sanity: rec_len must be >= 8 and must not go past end of block
        if rec_len < 8 {
            return Err(ParseError::InvalidField {
                field: "de_rec_len",
                reason: "directory entry rec_len < 8",
            });
        }
        let entry_end = offset
            .checked_add(rec_len as usize)
            .ok_or(ParseError::InvalidField {
                field: "de_rec_len",
                reason: "overflow",
            })?;
        if entry_end > block.len() {
            return Err(ParseError::InvalidField {
                field: "de_rec_len",
                reason: "directory entry extends past block boundary",
            });
        }

        // Detect checksum tail: inode=0, name_len=0, file_type=0xDE, rec_len=12
        if inode == 0 && name_len == 0 && file_type_raw == EXT4_FT_DIR_CSUM && rec_len == 12 {
            if offset + 12 <= block.len() {
                tail = Some(Ext4DirEntryTail {
                    checksum: read_le_u32(block, offset + 8)?,
                });
            }
            break;
        }

        // Skip deleted entries (inode == 0)
        if inode == 0 {
            offset = entry_end;
            continue;
        }

        // Read name bytes
        let name_end = offset + 8 + usize::from(name_len);
        if name_end > entry_end {
            return Err(ParseError::InvalidField {
                field: "de_name_len",
                reason: "name extends past rec_len",
            });
        }
        let name = block[offset + 8..name_end].to_vec();

        entries.push(Ext4DirEntry {
            inode,
            rec_len: rec_len_raw,
            name_len,
            file_type: Ext4FileType::from_raw(file_type_raw),
            name,
        });

        offset = entry_end;
    }

    Ok((entries, tail))
}

/// Look up a single name in a directory data block.
///
/// Returns the matching entry if found.
#[must_use]
pub fn lookup_in_dir_block(block: &[u8], block_size: u32, target: &[u8]) -> Option<Ext4DirEntry> {
    let (entries, _) = parse_dir_block(block, block_size).ok()?;
    entries.into_iter().find(|e| e.name == target)
}

// ── High-level image readers ────────────────────────────────────────────────

/// Parsed context for reading ext4 structures from an image.
///
/// Caches the superblock so that multiple lookups avoid re-parsing it.
#[derive(Debug, Clone)]
pub struct Ext4ImageReader {
    pub sb: Ext4Superblock,
}

impl Ext4ImageReader {
    /// Create a reader by parsing the superblock from `image`.
    pub fn new(image: &[u8]) -> Result<Self, ParseError> {
        let sb = Ext4Superblock::parse_from_image(image)?;
        Ok(Self { sb })
    }

    /// Read a group descriptor by group number.
    pub fn read_group_desc(
        &self,
        image: &[u8],
        group: ffs_types::GroupNumber,
    ) -> Result<Ext4GroupDesc, ParseError> {
        let offset = self
            .sb
            .group_desc_offset(group)
            .ok_or(ParseError::InvalidField {
                field: "group_desc_offset",
                reason: "overflow computing group descriptor offset",
            })?;
        let offset_usize = usize::try_from(offset).map_err(|_| ParseError::InvalidField {
            field: "group_desc_offset",
            reason: "offset exceeds addressable range",
        })?;
        let desc_size = self.sb.group_desc_size();
        let slice = ensure_slice(image, offset_usize, usize::from(desc_size))?;
        Ext4GroupDesc::parse_from_bytes(slice, desc_size)
    }

    /// Read an inode by inode number from a raw disk image.
    pub fn read_inode(
        &self,
        image: &[u8],
        ino: ffs_types::InodeNumber,
    ) -> Result<Ext4Inode, ParseError> {
        if ino.0 == 0 {
            return Err(ParseError::InvalidField {
                field: "inode_number",
                reason: "inode 0 is invalid in ext4",
            });
        }

        let (group, _index, byte_offset_in_table) = self.sb.inode_table_offset(ino);

        // Read the group descriptor to find the inode table's start block
        let gd = self.read_group_desc(image, group)?;

        // Compute absolute byte offset of the inode
        let table_start_byte = gd
            .inode_table
            .checked_mul(u64::from(self.sb.block_size))
            .ok_or(ParseError::InvalidField {
                field: "bg_inode_table",
                reason: "overflow computing inode table byte offset",
            })?;
        let inode_byte =
            table_start_byte
                .checked_add(byte_offset_in_table)
                .ok_or(ParseError::InvalidField {
                    field: "inode_offset",
                    reason: "overflow computing inode byte offset",
                })?;

        let inode_offset = usize::try_from(inode_byte).map_err(|_| ParseError::InvalidField {
            field: "inode_offset",
            reason: "inode offset exceeds addressable range",
        })?;

        let inode_size = usize::from(self.sb.inode_size);
        let slice = ensure_slice(image, inode_offset, inode_size)?;
        Ext4Inode::parse_from_bytes(slice)
    }

    /// Read a data block by block number, returning a slice.
    pub fn read_block<'a>(
        &self,
        image: &'a [u8],
        block: ffs_types::BlockNumber,
    ) -> Result<&'a [u8], ParseError> {
        let byte =
            block
                .0
                .checked_mul(u64::from(self.sb.block_size))
                .ok_or(ParseError::InvalidField {
                    field: "block_offset",
                    reason: "overflow computing block byte offset",
                })?;
        let offset = usize::try_from(byte).map_err(|_| ParseError::InvalidField {
            field: "block_offset",
            reason: "block offset exceeds addressable range",
        })?;
        ensure_slice(image, offset, self.sb.block_size as usize)
    }

    // ── Extent mapping ───────────────────────────────────────────────────

    /// Maximum extent tree depth we'll follow (ext4 kernel limit is 5).
    const MAX_EXTENT_DEPTH: u16 = 5;

    /// Resolve a logical block number to a physical block number for an inode.
    ///
    /// Walks the inode's extent tree.  For depth-0 (leaf) trees this is a
    /// simple scan.  For deeper trees, the appropriate extent index blocks
    /// are read from disk and the tree is traversed down to the leaf level.
    ///
    /// Returns `Ok(None)` if the logical block falls in a hole (no mapping).
    pub fn resolve_extent(
        &self,
        image: &[u8],
        inode: &Ext4Inode,
        logical_block: u32,
    ) -> Result<Option<u64>, ParseError> {
        let (header, tree) = parse_inode_extent_tree(inode)?;
        self.walk_extent_tree(image, &header, &tree, logical_block, header.depth)
    }

    /// Recursive extent tree walker with depth tracking.
    fn walk_extent_tree(
        &self,
        image: &[u8],
        _header: &Ext4ExtentHeader,
        tree: &ExtentTree,
        logical_block: u32,
        remaining_depth: u16,
    ) -> Result<Option<u64>, ParseError> {
        if remaining_depth > Self::MAX_EXTENT_DEPTH {
            return Err(ParseError::InvalidField {
                field: "eh_depth",
                reason: "extent tree depth exceeds maximum",
            });
        }

        match tree {
            ExtentTree::Leaf(extents) => {
                // Scan extents for the target logical block
                for ext in extents {
                    let start = ext.logical_block;
                    let len = u32::from(ext.actual_len());
                    if logical_block >= start && logical_block < start.saturating_add(len) {
                        let offset_within = u64::from(logical_block - start);
                        return Ok(Some(ext.physical_start + offset_within));
                    }
                }
                // Hole — no extent covers this logical block
                Ok(None)
            }
            ExtentTree::Index(indexes) => {
                if remaining_depth == 0 {
                    return Err(ParseError::InvalidField {
                        field: "eh_depth",
                        reason: "extent index at depth 0",
                    });
                }
                // Find the index entry whose logical_block <= target.
                // Entries are sorted; we want the last entry where logical_block <= target.
                let mut chosen: Option<&Ext4ExtentIndex> = None;
                for idx in indexes {
                    if idx.logical_block <= logical_block {
                        chosen = Some(idx);
                    } else {
                        break;
                    }
                }
                let Some(idx) = chosen else {
                    return Ok(None); // target is before all index entries — hole
                };

                // Read the child extent block from disk
                let child_block = self.read_block(image, ffs_types::BlockNumber(idx.leaf_block))?;
                let (child_header, child_tree) = parse_extent_tree(child_block)?;

                // Validate depth consistency: child depth should be one less
                if child_header.depth + 1 != remaining_depth {
                    return Err(ParseError::InvalidField {
                        field: "eh_depth",
                        reason: "child extent tree depth inconsistency",
                    });
                }

                self.walk_extent_tree(
                    image,
                    &child_header,
                    &child_tree,
                    logical_block,
                    remaining_depth - 1,
                )
            }
        }
    }

    /// Collect all leaf extents for an inode, flattening multi-level trees.
    ///
    /// Returns extents sorted by logical block number.
    pub fn collect_extents(
        &self,
        image: &[u8],
        inode: &Ext4Inode,
    ) -> Result<Vec<Ext4Extent>, ParseError> {
        let (header, tree) = parse_inode_extent_tree(inode)?;
        let mut result = Vec::new();
        self.collect_extents_recursive(image, &tree, header.depth, &mut result)?;
        Ok(result)
    }

    fn collect_extents_recursive(
        &self,
        image: &[u8],
        tree: &ExtentTree,
        remaining_depth: u16,
        result: &mut Vec<Ext4Extent>,
    ) -> Result<(), ParseError> {
        if remaining_depth > Self::MAX_EXTENT_DEPTH {
            return Err(ParseError::InvalidField {
                field: "eh_depth",
                reason: "extent tree depth exceeds maximum",
            });
        }

        match tree {
            ExtentTree::Leaf(extents) => {
                result.extend_from_slice(extents);
                Ok(())
            }
            ExtentTree::Index(indexes) => {
                if remaining_depth == 0 {
                    return Err(ParseError::InvalidField {
                        field: "eh_depth",
                        reason: "extent index at depth 0",
                    });
                }
                for idx in indexes {
                    let child_block =
                        self.read_block(image, ffs_types::BlockNumber(idx.leaf_block))?;
                    let (child_header, child_tree) = parse_extent_tree(child_block)?;
                    if child_header.depth + 1 != remaining_depth {
                        return Err(ParseError::InvalidField {
                            field: "eh_depth",
                            reason: "child extent tree depth inconsistency",
                        });
                    }
                    self.collect_extents_recursive(
                        image,
                        &child_tree,
                        remaining_depth - 1,
                        result,
                    )?;
                }
                Ok(())
            }
        }
    }

    // ── File data reading ───────────────────────────────────────────────

    /// Read file data from an inode starting at `offset` into `buf`.
    ///
    /// Returns the number of bytes actually read (may be less than `buf.len()`
    /// if the file is shorter or if the read extends past EOF).
    /// Holes in the extent mapping are filled with zeroes.
    pub fn read_inode_data(
        &self,
        image: &[u8],
        inode: &Ext4Inode,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, ParseError> {
        let file_size = inode.size;
        if offset >= file_size {
            return Ok(0);
        }

        let available = file_size - offset;
        let to_read = usize::try_from(available.min(buf.len() as u64)).unwrap_or(buf.len());

        let bs = u64::from(self.sb.block_size);
        let bs_usize = self.sb.block_size as usize; // block_size ≤ 65536, always fits usize
        let mut bytes_read = 0_usize;

        while bytes_read < to_read {
            let current_offset = offset + bytes_read as u64;
            let logical_block =
                u32::try_from(current_offset / bs).map_err(|_| ParseError::IntegerConversion {
                    field: "logical_block",
                })?;
            // SAFETY: block_size ≤ 65536 so modulus always fits in usize
            #[allow(clippy::cast_possible_truncation)]
            let offset_in_block = (current_offset % bs) as usize;
            let remaining_in_block = bs_usize - offset_in_block;
            let chunk_size = remaining_in_block.min(to_read - bytes_read);

            match self.resolve_extent(image, inode, logical_block)? {
                Some(phys_block) => {
                    let block_data = self.read_block(image, ffs_types::BlockNumber(phys_block))?;
                    buf[bytes_read..bytes_read + chunk_size].copy_from_slice(
                        &block_data[offset_in_block..offset_in_block + chunk_size],
                    );
                }
                None => {
                    // Hole — fill with zeroes
                    buf[bytes_read..bytes_read + chunk_size].fill(0);
                }
            }

            bytes_read += chunk_size;
        }

        Ok(bytes_read)
    }

    // ── Directory operations ────────────────────────────────────────────

    /// Read all directory entries from a directory inode.
    ///
    /// Iterates over the inode's data blocks via extent mapping, parsing
    /// each block for directory entries.  Returns all non-deleted entries
    /// (excluding checksum tails).
    pub fn read_dir(
        &self,
        image: &[u8],
        inode: &Ext4Inode,
    ) -> Result<Vec<Ext4DirEntry>, ParseError> {
        let bs = u64::from(self.sb.block_size);
        let num_blocks = Self::dir_logical_block_count(inode.size, bs)?;

        let mut all_entries = Vec::new();

        for lb in 0..num_blocks {
            if let Some(phys) = self.resolve_extent(image, inode, lb)? {
                let block_data = self.read_block(image, ffs_types::BlockNumber(phys))?;
                let (entries, _tail) = parse_dir_block(block_data, self.sb.block_size)?;
                all_entries.extend(entries);
            }
            // Holes in directory data are skipped (shouldn't happen in practice)
        }

        Ok(all_entries)
    }

    /// Look up a single name in a directory inode.
    ///
    /// Returns the matching `Ext4DirEntry` if found.
    pub fn lookup(
        &self,
        image: &[u8],
        dir_inode: &Ext4Inode,
        name: &[u8],
    ) -> Result<Option<Ext4DirEntry>, ParseError> {
        let bs = u64::from(self.sb.block_size);
        let num_blocks = Self::dir_logical_block_count(dir_inode.size, bs)?;

        for lb in 0..num_blocks {
            if let Some(phys) = self.resolve_extent(image, dir_inode, lb)? {
                let block_data = self.read_block(image, ffs_types::BlockNumber(phys))?;
                if let Some(entry) = lookup_in_dir_block(block_data, self.sb.block_size, name) {
                    return Ok(Some(entry));
                }
            }
        }

        Ok(None)
    }

    /// Compute the number of logical blocks in a directory, as a u32.
    fn dir_logical_block_count(file_size: u64, block_size: u64) -> Result<u32, ParseError> {
        let num = file_size.div_ceil(block_size);
        u32::try_from(num).map_err(|_| ParseError::IntegerConversion {
            field: "dir_block_count",
        })
    }

    // ── Path resolution ─────────────────────────────────────────────────

    /// Resolve an absolute path to an inode number and parsed inode.
    ///
    /// The path must start with `/`.  Each component is looked up in the
    /// current directory.  Returns the final inode.
    ///
    /// Does not follow symlinks (yet).
    pub fn resolve_path(
        &self,
        image: &[u8],
        path: &str,
    ) -> Result<(ffs_types::InodeNumber, Ext4Inode), ParseError> {
        if !path.starts_with('/') {
            return Err(ParseError::InvalidField {
                field: "path",
                reason: "path must be absolute (start with /)",
            });
        }

        let mut current_ino = ffs_types::InodeNumber::ROOT;
        let mut current_inode = self.read_inode(image, current_ino)?;

        // Split path and process each non-empty component
        for component in path.split('/').filter(|c| !c.is_empty()) {
            // Current inode must be a directory
            if (current_inode.mode & 0xF000) != 0x4000 {
                return Err(ParseError::InvalidField {
                    field: "path",
                    reason: "component is not a directory",
                });
            }

            let entry = self
                .lookup(image, &current_inode, component.as_bytes())?
                .ok_or(ParseError::InvalidField {
                    field: "path",
                    reason: "component not found",
                })?;

            current_ino = ffs_types::InodeNumber(u64::from(entry.inode));
            current_inode = self.read_inode(image, current_ino)?;
        }

        Ok((current_ino, current_inode))
    }

    /// Read a directory block and parse its entries.
    pub fn read_dir_block(
        &self,
        image: &[u8],
        block: ffs_types::BlockNumber,
    ) -> Result<(Vec<Ext4DirEntry>, Option<Ext4DirEntryTail>), ParseError> {
        let data = self.read_block(image, block)?;
        parse_dir_block(data, self.sb.block_size)
    }
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

    #[test]
    fn parse_ext4_superblock_region_rejects_unsupported_block_size() {
        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
        sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&3_u32.to_le_bytes()); // log_block_size=3 -> 8K

        let err = Ext4Superblock::parse_superblock_region(&sb).expect_err("reject");
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "s_log_block_size",
                reason: "unsupported block size"
            }
        ));
    }

    /// Helper: build a minimal valid superblock buffer with required geometry.
    fn make_valid_sb() -> [u8; EXT4_SUPERBLOCK_SIZE] {
        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
        sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes()); // log_block_size=2 -> 4K
        sb[0x1C..0x20].copy_from_slice(&2_u32.to_le_bytes()); // log_cluster_size=2 -> 4K
        sb[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_count
        sb[0x04..0x08].copy_from_slice(&32768_u32.to_le_bytes()); // blocks_count_lo
        sb[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes()); // first_data_block
        sb[0x20..0x24].copy_from_slice(&32768_u32.to_le_bytes()); // blocks_per_group
        sb[0x24..0x28].copy_from_slice(&32768_u32.to_le_bytes()); // clusters_per_group
        sb[0x28..0x2C].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_per_group
        sb[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size
        sb
    }

    #[test]
    fn validate_superblock_features_v1() {
        let mut sb = make_valid_sb();

        // required incompat bits: FILETYPE + EXTENTS
        let incompat =
            (Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0).to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);

        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        parsed.validate_v1().expect("validate");

        let mut sb2 = sb;
        // add an unknown incompat bit
        let unknown =
            (Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0 | (1_u32 << 31))
                .to_le_bytes();
        sb2[0x60..0x64].copy_from_slice(&unknown);
        let parsed2 = Ext4Superblock::parse_superblock_region(&sb2).expect("parse2");
        assert!(parsed2.validate_v1().is_err());
    }

    #[test]
    fn validate_geometry_catches_bad_values() {
        let mut sb = make_valid_sb();
        let incompat =
            (Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0).to_le_bytes();
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
        sb[0x2C..0x30].copy_from_slice(&1_700_000_000_u32.to_le_bytes()); // mtime
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
    #[allow(clippy::similar_names)]
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
        let (ctime_sec, ctime_nsec) = inode.ctime_full();
        assert_eq!(ctime_sec, 1_700_000_100);
        assert_eq!(ctime_nsec, 500_000_000);

        let (mtime_sec, mtime_nsec) = inode.mtime_full();
        assert_eq!(mtime_sec, 1_700_000_200);
        assert_eq!(mtime_nsec, 250_000_000);

        // Creation time
        assert_eq!(inode.crtime, 1_600_000_000);

        // Extended inode area
        assert_eq!(inode.extra_isize, 32);
    }

    /// Verify timestamp sign-extension matches the kernel's behavior.
    ///
    /// The kernel does `(signed)le32_to_cpu(raw->atime)` which sign-extends,
    /// then adds `(epoch_bits << 32)`. A timestamp of 0xFFFF_FFFF should be
    /// -1 (pre-1970), not 4_294_967_295.
    #[test]
    fn timestamp_sign_extension() {
        let mut raw = [0_u8; 256];
        // Set atime to 0xFFFF_FFFF (= -1 as signed i32 = 1 second before epoch)
        raw[0x08..0x0C].copy_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
        // extra_isize = 32 (need extended area for atime_extra)
        raw[0x80..0x82].copy_from_slice(&32_u16.to_le_bytes());
        // atime_extra: epoch=0, nsec=0
        raw[0x8C..0x90].copy_from_slice(&0_u32.to_le_bytes());

        let inode = Ext4Inode::parse_from_bytes(&raw).unwrap();
        let (sec, nsec) = inode.atime_full();
        // Must be -1 (kernel: (signed)0xFFFFFFFF = -1), NOT 4294967295
        assert_eq!(sec, -1);
        assert_eq!(nsec, 0);

        // With epoch=1: kernel does -1 + (1 << 32) = 4294967295
        raw[0x8C..0x90].copy_from_slice(&1_u32.to_le_bytes()); // epoch=1, nsec=0
        let inode = Ext4Inode::parse_from_bytes(&raw).unwrap();
        let (sec, _) = inode.atime_full();
        assert_eq!(sec, 4_294_967_295_i64); // -1 + 2^32
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

    // ── Directory entry tests ───────────────────────────────────────────

    /// Build a directory entry in a buffer at `offset`.
    #[allow(clippy::cast_possible_truncation)]
    fn write_dir_entry(
        buf: &mut [u8],
        offset: usize,
        inode: u32,
        ft: u8,
        name: &[u8],
        rec_len: u16,
    ) {
        buf[offset..offset + 4].copy_from_slice(&inode.to_le_bytes());
        buf[offset + 4..offset + 6].copy_from_slice(&rec_len.to_le_bytes());
        buf[offset + 6] = name.len() as u8;
        buf[offset + 7] = ft;
        buf[offset + 8..offset + 8 + name.len()].copy_from_slice(name);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn parse_dir_block_basic() {
        let block_size = 4096_u32;
        let mut block = vec![0_u8; block_size as usize];

        // Entry 1: "." → inode 2, type=dir, rec_len=12
        write_dir_entry(&mut block, 0, 2, 2, b".", 12);
        // Entry 2: ".." → inode 2, type=dir, rec_len=12
        write_dir_entry(&mut block, 12, 2, 2, b"..", 12);
        // Entry 3: "hello.txt" → inode 12, type=regular, rec_len fills rest of block
        let remaining = block_size as u16 - 24;
        write_dir_entry(&mut block, 24, 12, 1, b"hello.txt", remaining);

        let (entries, tail) = parse_dir_block(&block, block_size).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(tail.is_none());

        assert!(entries[0].is_dot());
        assert_eq!(entries[0].inode, 2);
        assert_eq!(entries[0].file_type, Ext4FileType::Dir);

        assert!(entries[1].is_dotdot());
        assert_eq!(entries[1].inode, 2);

        assert_eq!(entries[2].name_str(), "hello.txt");
        assert_eq!(entries[2].inode, 12);
        assert_eq!(entries[2].file_type, Ext4FileType::RegFile);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn parse_dir_block_with_checksum_tail() {
        let block_size = 4096_u32;
        let mut block = vec![0_u8; block_size as usize];

        // Single entry: "." that spans almost the whole block, leaving 12 bytes for tail
        let entry_rec_len = block_size as u16 - 12;
        write_dir_entry(&mut block, 0, 2, 2, b".", entry_rec_len);

        // Checksum tail at end of block (last 12 bytes)
        let tail_off = (block_size - 12) as usize;
        block[tail_off..tail_off + 4].copy_from_slice(&0_u32.to_le_bytes()); // inode=0
        block[tail_off + 4..tail_off + 6].copy_from_slice(&12_u16.to_le_bytes()); // rec_len=12
        block[tail_off + 6] = 0; // name_len=0
        block[tail_off + 7] = EXT4_FT_DIR_CSUM; // file_type=0xDE
        block[tail_off + 8..tail_off + 12].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());

        let (entries, tail) = parse_dir_block(&block, block_size).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_dot());

        let tail = tail.expect("should have checksum tail");
        assert_eq!(tail.checksum, 0xDEAD_BEEF);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn parse_dir_block_skips_deleted_entries() {
        let block_size = 1024_u32;
        let mut block = vec![0_u8; block_size as usize];

        // Entry 1: "a" → inode 5, rec_len=12
        write_dir_entry(&mut block, 0, 5, 1, b"a", 12);
        // Entry 2: deleted (inode=0), rec_len=12
        write_dir_entry(&mut block, 12, 0, 0, b"", 12);
        // Entry 3: "b" → inode 6, rec_len fills rest
        let remaining = block_size as u16 - 24;
        write_dir_entry(&mut block, 24, 6, 1, b"b", remaining);

        let (entries, _) = parse_dir_block(&block, block_size).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, b"a");
        assert_eq!(entries[1].name, b"b");
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn lookup_in_dir_block_finds_entry() {
        let block_size = 4096_u32;
        let mut block = vec![0_u8; block_size as usize];

        write_dir_entry(&mut block, 0, 2, 2, b".", 12);
        write_dir_entry(&mut block, 12, 2, 2, b"..", 12);
        let remaining = block_size as u16 - 24;
        write_dir_entry(&mut block, 24, 42, 1, b"myfile", remaining);

        let found = lookup_in_dir_block(&block, block_size, b"myfile");
        assert!(found.is_some());
        assert_eq!(found.unwrap().inode, 42);

        let not_found = lookup_in_dir_block(&block, block_size, b"missing");
        assert!(not_found.is_none());
    }

    #[test]
    fn dir_entry_file_types() {
        assert_eq!(Ext4FileType::from_raw(0), Ext4FileType::Unknown);
        assert_eq!(Ext4FileType::from_raw(1), Ext4FileType::RegFile);
        assert_eq!(Ext4FileType::from_raw(2), Ext4FileType::Dir);
        assert_eq!(Ext4FileType::from_raw(7), Ext4FileType::Symlink);
        assert_eq!(Ext4FileType::from_raw(255), Ext4FileType::Unknown);
    }

    // ── Ext4ImageReader integration test ────────────────────────────────

    /// Build a minimal synthetic ext4 image with superblock, GDT, and inode table.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn image_reader_reads_inode() {
        // Layout: 4K blocks, 1 group
        //   Block 0: boot + superblock (offset 1024..2048)
        //   Block 1: group descriptor table
        //   Block 2: inode table (8192 inodes * 256 bytes, but we only populate a few)
        let block_size = 4096_usize;
        let image_blocks = 32; // 128K image
        let mut image = vec![0_u8; block_size * image_blocks];

        // Write superblock at offset 1024
        let sb_off = EXT4_SUPERBLOCK_OFFSET;
        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
        sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes()); // log_block_size=2 → 4K
        sb[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_count
        sb[0x04..0x08].copy_from_slice(&(image_blocks as u32).to_le_bytes()); // blocks_count_lo
        sb[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes()); // first_data_block=0
        sb[0x20..0x24].copy_from_slice(&(image_blocks as u32).to_le_bytes()); // blocks_per_group
        sb[0x28..0x2C].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_per_group
        sb[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size=256
        image[sb_off..sb_off + EXT4_SUPERBLOCK_SIZE].copy_from_slice(&sb);

        // Write group descriptor at block 1 (offset 4096)
        // bg_inode_table_lo = block 2 (offset 8192)
        let gdt_off = block_size; // block 1
        let mut gd = [0_u8; 32];
        gd[0x08..0x0C].copy_from_slice(&2_u32.to_le_bytes()); // inode_table_lo = block 2
        image[gdt_off..gdt_off + 32].copy_from_slice(&gd);

        // Write inode 2 (root) at inode table block 2, index 1 (offset = 256)
        // Inode table starts at block 2 = byte 8192
        // Inode 2 is at index 1 → byte 8192 + 256 = 8448
        let inode_table_off = 2 * block_size; // block 2
        let inode2_off = inode_table_off + 256; // index 1 * 256
        image[inode2_off..inode2_off + 2].copy_from_slice(&0o040_755_u16.to_le_bytes()); // mode: directory
        image[inode2_off + 0x02..inode2_off + 0x04].copy_from_slice(&0_u16.to_le_bytes()); // uid_lo=0 (root)
        image[inode2_off + 0x04..inode2_off + 0x08].copy_from_slice(&4096_u32.to_le_bytes()); // size_lo
        image[inode2_off + 0x1A..inode2_off + 0x1C].copy_from_slice(&2_u16.to_le_bytes()); // links=2
        image[inode2_off + 0x64..inode2_off + 0x68].copy_from_slice(&1_u32.to_le_bytes()); // generation=1

        // Read it back via Ext4ImageReader
        let reader = Ext4ImageReader::new(&image).expect("parse image");
        assert_eq!(reader.sb.block_size, 4096);
        assert_eq!(reader.sb.inodes_per_group, 8192);

        let inode = reader
            .read_inode(&image, ffs_types::InodeNumber(2))
            .expect("read inode 2");
        assert_eq!(inode.mode, 0o040_755);
        assert_eq!(inode.uid, 0);
        assert_eq!(inode.size, 4096);
        assert_eq!(inode.links_count, 2);
        assert_eq!(inode.generation, 1);

        // Inode 0 should be rejected
        assert!(
            reader
                .read_inode(&image, ffs_types::InodeNumber(0))
                .is_err()
        );

        // Read a block
        let block_data = reader
            .read_block(&image, ffs_types::BlockNumber(0))
            .expect("read block 0");
        assert_eq!(block_data.len(), 4096);
    }

    // ── Checksum verification tests ─────────────────────────────────────

    /// Helper: compute group descriptor checksum the same way the kernel does,
    /// then store it, and verify our verification function accepts it.
    #[test]
    fn group_desc_checksum_round_trip() {
        let uuid = [1_u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        // Compute csum_seed = ext4_chksum(~0, uuid, 16) = crc32c_append(!0, uuid)
        let csum_seed = crc32c::crc32c_append(!0u32, &uuid);

        let group_number: u32 = 0;
        let desc_size: u16 = 32;

        // Build a group descriptor with known fields
        let mut gd = [0_u8; 32];
        gd[0x00..0x04].copy_from_slice(&100_u32.to_le_bytes()); // block_bitmap
        gd[0x04..0x08].copy_from_slice(&200_u32.to_le_bytes()); // inode_bitmap
        gd[0x08..0x0C].copy_from_slice(&300_u32.to_le_bytes()); // inode_table
        gd[0x0C..0x0E].copy_from_slice(&50_u16.to_le_bytes()); // free_blocks_lo

        // Compute the checksum the same way the kernel does
        let le_group = group_number.to_le_bytes();
        let mut csum = crc32c::crc32c_append(csum_seed, &le_group);
        csum = crc32c::crc32c_append(csum, &gd[..GD_CHECKSUM_OFFSET]);
        csum = crc32c::crc32c_append(csum, &[0, 0]);
        let after = GD_CHECKSUM_OFFSET + 2;
        if after < 32 {
            csum = crc32c::crc32c_append(csum, &gd[after..32]);
        }
        let checksum = (csum & 0xFFFF) as u16;

        // Store it
        gd[GD_CHECKSUM_OFFSET..GD_CHECKSUM_OFFSET + 2].copy_from_slice(&checksum.to_le_bytes());

        // Verify it passes
        verify_group_desc_checksum(&gd, csum_seed, group_number, desc_size)
            .expect("checksum should match");

        // Corrupt one byte and verify it fails
        gd[0] ^= 0xFF;
        assert!(verify_group_desc_checksum(&gd, csum_seed, group_number, desc_size).is_err());
    }

    /// Helper: compute inode checksum the same way the kernel does,
    /// then store it, and verify our verification function accepts it.
    #[test]
    fn inode_checksum_round_trip() {
        let uuid = [0xAA_u8; 16];
        let csum_seed = crc32c::crc32c_append(!0u32, &uuid);
        let ino: u32 = 2;
        let inode_size: u16 = 256;

        let mut raw = [0_u8; 256];
        // mode = directory
        raw[0x00..0x02].copy_from_slice(&0o040_755_u16.to_le_bytes());
        // uid_lo
        raw[0x02..0x04].copy_from_slice(&1000_u16.to_le_bytes());
        // generation
        raw[0x64..0x68].copy_from_slice(&42_u32.to_le_bytes());
        // extra_isize = 32 (covers checksum_hi and more)
        raw[0x80..0x82].copy_from_slice(&32_u16.to_le_bytes());

        // Compute checksum:
        // ino_seed = crc32c_append(csum_seed, le_ino)
        // ino_seed = crc32c_append(ino_seed, le_gen)
        let ino_seed = crc32c::crc32c_append(csum_seed, &ino.to_le_bytes());
        let ino_seed = crc32c::crc32c_append(ino_seed, &42_u32.to_le_bytes());

        // CRC base inode, zeroing i_checksum_lo at 0x7C
        let mut csum = crc32c::crc32c_append(ino_seed, &raw[..INODE_CHECKSUM_LO_OFFSET]);
        csum = crc32c::crc32c_append(csum, &[0, 0]);
        csum = crc32c::crc32c_append(csum, &raw[INODE_CHECKSUM_LO_OFFSET + 2..128]);

        // Extended area, zeroing i_checksum_hi at 0x82
        csum = crc32c::crc32c_append(csum, &raw[128..INODE_CHECKSUM_HI_OFFSET]);
        csum = crc32c::crc32c_append(csum, &[0, 0]);
        csum = crc32c::crc32c_append(csum, &raw[INODE_CHECKSUM_HI_OFFSET + 2..256]);

        // Store lo and hi
        let csum_lo = (csum & 0xFFFF) as u16;
        let csum_hi = ((csum >> 16) & 0xFFFF) as u16;
        raw[INODE_CHECKSUM_LO_OFFSET..INODE_CHECKSUM_LO_OFFSET + 2]
            .copy_from_slice(&csum_lo.to_le_bytes());
        raw[INODE_CHECKSUM_HI_OFFSET..INODE_CHECKSUM_HI_OFFSET + 2]
            .copy_from_slice(&csum_hi.to_le_bytes());

        // Verify it passes
        verify_inode_checksum(&raw, csum_seed, ino, inode_size)
            .expect("inode checksum should match");

        // Corrupt one byte and verify it fails
        raw[0x10] ^= 0x01;
        assert!(verify_inode_checksum(&raw, csum_seed, ino, inode_size).is_err());
    }

    // ── Extent mapping / file reading / path resolution tests ───────────

    /// Build a complete synthetic ext4 image for integration testing.
    ///
    /// Layout (4K blocks, 1 group):
    ///   Block 0: boot sector + superblock (at byte 1024)
    ///   Block 1: group descriptor table
    ///   Block 2: inode table (inodes 1-8192, 256 bytes each)
    ///   Blocks 3+: data blocks for files/directories
    ///
    /// Directory structure:
    ///   / (inode 2) → ".", "..", "subdir", "hello.txt"
    ///   /subdir (inode 12) → ".", "..", "deep.txt"
    ///   /hello.txt (inode 11) → "Hello, FrankenFS!\n" (18 bytes)
    ///   /subdir/deep.txt (inode 13) → 8192 bytes of 'A' (spans 2 blocks)
    #[allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
    fn build_test_image() -> Vec<u8> {
        let block_size = 4096_usize;
        let image_blocks = 64;
        let mut image = vec![0_u8; block_size * image_blocks];

        // ── Superblock at byte offset 1024 ──────────────────────────────
        let sb_off = EXT4_SUPERBLOCK_OFFSET;
        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
        sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes()); // log_block_size=2 → 4K
        sb[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_count
        sb[0x04..0x08].copy_from_slice(&(image_blocks as u32).to_le_bytes());
        sb[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes()); // first_data_block=0
        sb[0x20..0x24].copy_from_slice(&(image_blocks as u32).to_le_bytes());
        sb[0x28..0x2C].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_per_group
        sb[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size=256
        sb[0x54..0x58].copy_from_slice(&11_u32.to_le_bytes()); // first_ino=11
        image[sb_off..sb_off + EXT4_SUPERBLOCK_SIZE].copy_from_slice(&sb);

        // ── Group descriptor at block 1 ─────────────────────────────────
        let gdt_off = block_size;
        let mut gd = [0_u8; 32];
        gd[0x08..0x0C].copy_from_slice(&2_u32.to_le_bytes()); // inode_table at block 2
        image[gdt_off..gdt_off + 32].copy_from_slice(&gd);

        // ── Inode table at block 2 ──────────────────────────────────────
        let itable_off = 2 * block_size;
        let inode_size = 256_usize;

        // Helper: write an inode at the given inode number
        let write_inode = |img: &mut Vec<u8>,
                           ino: u32,
                           mode: u16,
                           size: u64,
                           links: u16,
                           extent_block: u32,
                           extent_len: u16| {
            let off = itable_off + (ino as usize - 1) * inode_size;
            // mode
            img[off..off + 2].copy_from_slice(&mode.to_le_bytes());
            // size_lo
            img[off + 0x04..off + 0x08].copy_from_slice(&(size as u32).to_le_bytes());
            // size_hi
            img[off + 0x6C..off + 0x70].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
            // links_count
            img[off + 0x1A..off + 0x1C].copy_from_slice(&links.to_le_bytes());
            // flags: EXTENTS
            img[off + 0x20..off + 0x24].copy_from_slice(&0x0008_0000_u32.to_le_bytes());
            // generation
            img[off + 0x64..off + 0x68].copy_from_slice(&1_u32.to_le_bytes());

            // Extent header at i_block (offset 0x28)
            let eh = off + 0x28;
            img[eh..eh + 2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes()); // magic
            img[eh + 2..eh + 4].copy_from_slice(&1_u16.to_le_bytes()); // entries=1
            img[eh + 4..eh + 6].copy_from_slice(&4_u16.to_le_bytes()); // max_entries
            img[eh + 6..eh + 8].copy_from_slice(&0_u16.to_le_bytes()); // depth=0

            // Single extent entry: logical=0, len, physical=extent_block
            let ee = eh + 12;
            img[ee..ee + 4].copy_from_slice(&0_u32.to_le_bytes()); // logical_block=0
            img[ee + 4..ee + 6].copy_from_slice(&extent_len.to_le_bytes());
            img[ee + 6..ee + 8].copy_from_slice(&0_u16.to_le_bytes()); // start_hi=0
            img[ee + 8..ee + 12].copy_from_slice(&extent_block.to_le_bytes()); // start_lo
        };

        // Root directory (inode 2): mode=dir, 1 block of dir data at block 10
        write_inode(&mut image, 2, 0o040_755, 4096, 3, 10, 1);

        // hello.txt (inode 11): regular file, 18 bytes, data at block 20
        write_inode(&mut image, 11, 0o100_644, 18, 1, 20, 1);

        // subdir (inode 12): directory, 1 block of dir data at block 30
        write_inode(&mut image, 12, 0o040_755, 4096, 2, 30, 1);

        // deep.txt (inode 13): regular file, 8192 bytes, data at blocks 40-41
        write_inode(&mut image, 13, 0o100_644, 8192, 1, 40, 2);

        // ── Root directory data at block 10 ─────────────────────────────
        let root_blk = 10 * block_size;
        // "." → inode 2, dir
        write_dir_entry(&mut image, root_blk, 2, 2, b".", 12);
        // ".." → inode 2, dir
        write_dir_entry(&mut image, root_blk + 12, 2, 2, b"..", 12);
        // "hello.txt" → inode 11, regular
        write_dir_entry(&mut image, root_blk + 24, 11, 1, b"hello.txt", 24);
        // "subdir" → inode 12, dir (rec_len fills to end of block)
        let remaining: u16 = 4096 - 12 - 12 - 24;
        write_dir_entry(&mut image, root_blk + 48, 12, 2, b"subdir", remaining);

        // ── hello.txt data at block 20 ──────────────────────────────────
        let hello_blk = 20 * block_size;
        image[hello_blk..hello_blk + 18].copy_from_slice(b"Hello, FrankenFS!\n");

        // ── subdir directory data at block 30 ───────────────────────────
        let sub_blk = 30 * block_size;
        write_dir_entry(&mut image, sub_blk, 12, 2, b".", 12);
        write_dir_entry(&mut image, sub_blk + 12, 2, 2, b"..", 12);
        let remaining: u16 = 4096 - 12 - 12;
        write_dir_entry(&mut image, sub_blk + 24, 13, 1, b"deep.txt", remaining);

        // ── deep.txt data at blocks 40-41 ───────────────────────────────
        let deep_blk = 40 * block_size;
        image[deep_blk..deep_blk + 8192].fill(b'A');

        image
    }

    #[test]
    fn extent_mapping_depth_zero() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        // Read root inode and resolve extent for logical block 0
        let root_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(2))
            .unwrap();

        let phys = reader.resolve_extent(&image, &root_inode, 0).unwrap();
        assert_eq!(phys, Some(10)); // root dir data at block 10

        // Non-existent logical block should be None (hole)
        let hole = reader.resolve_extent(&image, &root_inode, 999).unwrap();
        assert_eq!(hole, None);
    }

    #[test]
    fn extent_mapping_multi_block_file() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        // deep.txt (inode 13) has 2 blocks starting at physical block 40
        let deep_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(13))
            .unwrap();

        let b0 = reader.resolve_extent(&image, &deep_inode, 0).unwrap();
        assert_eq!(b0, Some(40));

        let b1 = reader.resolve_extent(&image, &deep_inode, 1).unwrap();
        assert_eq!(b1, Some(41));

        let b2 = reader.resolve_extent(&image, &deep_inode, 2).unwrap();
        assert_eq!(b2, None); // past the extent
    }

    #[test]
    fn collect_extents_leaf() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let deep_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(13))
            .unwrap();

        let extents = reader.collect_extents(&image, &deep_inode).unwrap();
        assert_eq!(extents.len(), 1);
        assert_eq!(extents[0].logical_block, 0);
        assert_eq!(extents[0].actual_len(), 2);
        assert_eq!(extents[0].physical_start, 40);
    }

    #[test]
    fn read_inode_data_small_file() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let hello_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(11))
            .unwrap();
        assert_eq!(hello_inode.size, 18);

        let mut buf = [0_u8; 64];
        let n = reader
            .read_inode_data(&image, &hello_inode, 0, &mut buf)
            .unwrap();
        assert_eq!(n, 18);
        assert_eq!(&buf[..18], b"Hello, FrankenFS!\n");
    }

    #[test]
    fn read_inode_data_partial_read() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let hello_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(11))
            .unwrap();

        // Read from offset 7, requesting 5 bytes
        let mut buf = [0_u8; 5];
        let n = reader
            .read_inode_data(&image, &hello_inode, 7, &mut buf)
            .unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"Frank");
    }

    #[test]
    fn read_inode_data_past_eof() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let hello_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(11))
            .unwrap();

        // Read past EOF
        let mut buf = [0_u8; 10];
        let n = reader
            .read_inode_data(&image, &hello_inode, 100, &mut buf)
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_inode_data_multi_block() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let deep_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(13))
            .unwrap();
        assert_eq!(deep_inode.size, 8192);

        let mut buf = vec![0_u8; 8192];
        let n = reader
            .read_inode_data(&image, &deep_inode, 0, &mut buf)
            .unwrap();
        assert_eq!(n, 8192);
        assert!(buf.iter().all(|&b| b == b'A'));
    }

    #[test]
    fn read_inode_data_cross_block_boundary() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let deep_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(13))
            .unwrap();

        // Read 100 bytes straddling the block boundary (4090..4190)
        let mut buf = [0_u8; 100];
        let n = reader
            .read_inode_data(&image, &deep_inode, 4090, &mut buf)
            .unwrap();
        assert_eq!(n, 100);
        assert!(buf.iter().all(|&b| b == b'A'));
    }

    #[test]
    fn read_dir_lists_entries() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let root_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(2))
            .unwrap();

        let entries = reader.read_dir(&image, &root_inode).unwrap();
        assert_eq!(entries.len(), 4); // ., .., hello.txt, subdir

        let has_name = |n: &[u8]| entries.iter().any(|e| e.name == n);
        assert!(has_name(b"."));
        assert!(has_name(b".."));
        assert!(has_name(b"hello.txt"));
        assert!(has_name(b"subdir"));
    }

    #[test]
    fn read_dir_subdir() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let subdir_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(12))
            .unwrap();

        let entries = reader.read_dir(&image, &subdir_inode).unwrap();
        assert_eq!(entries.len(), 3); // ., .., deep.txt

        assert!(entries.iter().any(|e| e.name == b"deep.txt"));
    }

    #[test]
    fn lookup_finds_entry() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let root_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(2))
            .unwrap();

        let entry = reader.lookup(&image, &root_inode, b"hello.txt").unwrap();
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().inode, 11);

        let missing = reader.lookup(&image, &root_inode, b"nonexistent").unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn resolve_path_root() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let (ino, inode) = reader.resolve_path(&image, "/").unwrap();
        assert_eq!(ino, ffs_types::InodeNumber(2));
        assert_eq!(inode.mode, 0o040_755);
    }

    #[test]
    fn resolve_path_single_component() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let (ino, inode) = reader.resolve_path(&image, "/hello.txt").unwrap();
        assert_eq!(ino, ffs_types::InodeNumber(11));
        assert_eq!(inode.mode, 0o100_644);
        assert_eq!(inode.size, 18);
    }

    #[test]
    fn resolve_path_multi_component() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let (ino, inode) = reader.resolve_path(&image, "/subdir/deep.txt").unwrap();
        assert_eq!(ino, ffs_types::InodeNumber(13));
        assert_eq!(inode.mode, 0o100_644);
        assert_eq!(inode.size, 8192);
    }

    #[test]
    fn resolve_path_with_trailing_slash() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let (ino, _) = reader.resolve_path(&image, "/subdir/").unwrap();
        assert_eq!(ino, ffs_types::InodeNumber(12));
    }

    #[test]
    fn resolve_path_not_found() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let err = reader
            .resolve_path(&image, "/nonexistent")
            .expect_err("should fail");
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "path",
                reason: "component not found"
            }
        ));
    }

    #[test]
    fn resolve_path_not_directory() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        // Trying to traverse through a file
        let err = reader
            .resolve_path(&image, "/hello.txt/something")
            .expect_err("should fail");
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "path",
                reason: "component is not a directory"
            }
        ));
    }

    #[test]
    fn resolve_path_relative_rejected() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let err = reader
            .resolve_path(&image, "relative/path")
            .expect_err("should fail");
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "path",
                reason: "path must be absolute (start with /)"
            }
        ));
    }

    /// End-to-end: resolve path, then read file data.
    #[test]
    fn resolve_path_and_read_file_data() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let (_, inode) = reader.resolve_path(&image, "/subdir/deep.txt").unwrap();

        let mut buf = vec![0_u8; 8192];
        let n = reader.read_inode_data(&image, &inode, 0, &mut buf).unwrap();
        assert_eq!(n, 8192);
        assert!(buf.iter().all(|&b| b == b'A'));
    }
}
