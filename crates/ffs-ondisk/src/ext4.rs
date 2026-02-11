#![forbid(unsafe_code)]

use ffs_types::{
    EXT4_EXTENTS_FL, EXT4_FAST_SYMLINK_MAX, EXT4_HUGE_FILE_FL, EXT4_INDEX_FL, EXT4_SUPER_MAGIC,
    EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE, EXT4_XATTR_MAGIC, GroupNumber, InodeNumber,
    ParseError, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK,
    ensure_slice, ext4_block_size_from_log, read_fixed, read_le_u16, read_le_u32, trim_nul_padded,
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

    /// All known compat flags for iteration.
    const KNOWN: &[(u32, &'static str)] = &[
        (0x0001, "DIR_PREALLOC"),
        (0x0002, "IMAGIC_INODES"),
        (0x0004, "HAS_JOURNAL"),
        (0x0008, "EXT_ATTR"),
        (0x0010, "RESIZE_INODE"),
        (0x0020, "DIR_INDEX"),
        (0x0200, "SPARSE_SUPER2"),
        (0x0400, "FAST_COMMIT"),
        (0x0800, "STABLE_INODES"),
        (0x1000, "ORPHAN_FILE"),
    ];

    #[must_use]
    pub fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }

    /// Return names of all set flags. Unknown bits are included as hex.
    #[must_use]
    pub fn describe(self) -> Vec<&'static str> {
        describe_flags(self.0, Self::KNOWN)
    }

    /// Return the raw unknown bits (not covered by any named constant).
    #[must_use]
    pub fn unknown_bits(self) -> u32 {
        let known_mask: u32 = Self::KNOWN.iter().map(|(bit, _)| bit).fold(0, |a, b| a | b);
        self.0 & !known_mask
    }
}

impl std::fmt::Display for Ext4CompatFeatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format_flags(f, self.0, Self::KNOWN)
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

    /// All known incompat flags for iteration.
    const KNOWN: &[(u32, &'static str)] = &[
        (0x0001, "COMPRESSION"),
        (0x0002, "FILETYPE"),
        (0x0004, "RECOVER"),
        (0x0008, "JOURNAL_DEV"),
        (0x0010, "META_BG"),
        (0x0040, "EXTENTS"),
        (0x0080, "64BIT"),
        (0x0100, "MMP"),
        (0x0200, "FLEX_BG"),
        (0x0400, "EA_INODE"),
        (0x1000, "DIRDATA"),
        (0x2000, "CSUM_SEED"),
        (0x4000, "LARGEDIR"),
        (0x8000, "INLINE_DATA"),
        (0x1_0000, "ENCRYPT"),
        (0x2_0000, "CASEFOLD"),
    ];

    #[must_use]
    pub fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }

    /// Return names of all set flags. Unknown bits are included as hex.
    #[must_use]
    pub fn describe(self) -> Vec<&'static str> {
        describe_flags(self.0, Self::KNOWN)
    }

    /// Return the raw unknown bits (not covered by any named constant).
    #[must_use]
    pub fn unknown_bits(self) -> u32 {
        let known_mask: u32 = Self::KNOWN.iter().map(|(bit, _)| bit).fold(0, |a, b| a | b);
        self.0 & !known_mask
    }

    /// Describe which REJECTED_V1 flags are present in this value.
    #[must_use]
    pub fn describe_rejected_v1(self) -> Vec<&'static str> {
        describe_flags(self.0 & Self::REJECTED_V1.0, Self::KNOWN)
    }

    /// Describe which REQUIRED_V1 flags are missing from this value.
    #[must_use]
    pub fn describe_missing_required_v1(self) -> Vec<&'static str> {
        let missing = Self::REQUIRED_V1.0 & !self.0;
        describe_flags(missing, Self::KNOWN)
    }
}

impl std::fmt::Display for Ext4IncompatFeatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format_flags(f, self.0, Self::KNOWN)
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

    /// All known ro_compat flags for iteration.
    const KNOWN: &[(u32, &'static str)] = &[
        (0x0001, "SPARSE_SUPER"),
        (0x0002, "LARGE_FILE"),
        (0x0004, "BTREE_DIR"),
        (0x0008, "HUGE_FILE"),
        (0x0010, "GDT_CSUM"),
        (0x0020, "DIR_NLINK"),
        (0x0040, "EXTRA_ISIZE"),
        (0x0100, "QUOTA"),
        (0x0200, "BIGALLOC"),
        (0x0400, "METADATA_CSUM"),
        (0x1000, "READONLY"),
        (0x2000, "PROJECT"),
        (0x8000, "VERITY"),
        (0x1_0000, "ORPHAN_PRESENT"),
    ];

    #[must_use]
    pub fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }

    /// Return names of all set flags. Unknown bits are included as hex.
    #[must_use]
    pub fn describe(self) -> Vec<&'static str> {
        describe_flags(self.0, Self::KNOWN)
    }

    /// Return the raw unknown bits (not covered by any named constant).
    #[must_use]
    pub fn unknown_bits(self) -> u32 {
        let known_mask: u32 = Self::KNOWN.iter().map(|(bit, _)| bit).fold(0, |a, b| a | b);
        self.0 & !known_mask
    }
}

impl std::fmt::Display for Ext4RoCompatFeatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format_flags(f, self.0, Self::KNOWN)
    }
}

// ── Feature diagnostics ─────────────────────────────────────────────────────

/// Structured report of feature flag compatibility for v1 mount validation.
///
/// Produced by [`Ext4Superblock::feature_diagnostics_v1()`]. Callers use this
/// to enrich error messages or produce UX output.
#[derive(Debug, Clone)]
pub struct FeatureDiagnostics {
    /// Required incompat features that are missing (e.g., `["FILETYPE"]`).
    pub missing_required: Vec<&'static str>,
    /// Rejected incompat features that are present (e.g., `["ENCRYPT"]`).
    pub rejected_present: Vec<&'static str>,
    /// Raw bitmask of unknown incompat bits (not in any named constant).
    pub unknown_incompat_bits: u32,
    /// Raw bitmask of unknown ro_compat bits.
    pub unknown_ro_compat_bits: u32,
    /// Human-readable display of all incompat flags.
    pub incompat_display: String,
    /// Human-readable display of all ro_compat flags.
    pub ro_compat_display: String,
    /// Human-readable display of all compat flags.
    pub compat_display: String,
}

impl FeatureDiagnostics {
    /// True when all checks pass and the image can be mounted.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.missing_required.is_empty()
            && self.rejected_present.is_empty()
            && self.unknown_incompat_bits == 0
    }
}

impl std::fmt::Display for FeatureDiagnostics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "compat={}, incompat={}, ro_compat={}",
            self.compat_display, self.incompat_display, self.ro_compat_display
        )?;
        if !self.missing_required.is_empty() {
            write!(
                f,
                "; missing required: {}",
                self.missing_required.join(", ")
            )?;
        }
        if !self.rejected_present.is_empty() {
            write!(f, "; rejected: {}", self.rejected_present.join(", "))?;
        }
        if self.unknown_incompat_bits != 0 {
            write!(f, "; unknown incompat: 0x{:X}", self.unknown_incompat_bits)?;
        }
        if self.unknown_ro_compat_bits != 0 {
            write!(
                f,
                "; unknown ro_compat: 0x{:X}",
                self.unknown_ro_compat_bits
            )?;
        }
        Ok(())
    }
}

// ── Shared flag helpers ─────────────────────────────────────────────────────

/// Collect names of all set bits from a `(bit, name)` table.
///
/// Bits not present in `known` are silently omitted (callers that care
/// about unknown bits should use `unknown_bits()` separately).
fn describe_flags(bits: u32, known: &[(u32, &'static str)]) -> Vec<&'static str> {
    known
        .iter()
        .filter(|(bit, _)| bits & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// Format a bitmask as a pipe-separated list of flag names.
///
/// Example output: `FILETYPE|EXTENTS|FLEX_BG` or `(none)` when zero.
/// Unknown bits are appended as hex, e.g. `FILETYPE|0x80000000`.
fn format_flags(
    f: &mut std::fmt::Formatter<'_>,
    bits: u32,
    known: &[(u32, &'static str)],
) -> std::fmt::Result {
    if bits == 0 {
        return f.write_str("(none)");
    }
    let mut first = true;
    let mut remaining = bits;
    for &(bit, name) in known {
        if remaining & bit != 0 {
            if !first {
                f.write_str("|")?;
            }
            f.write_str(name)?;
            remaining &= !bit;
            first = false;
        }
    }
    // Append any unknown bits as hex.
    if remaining != 0 {
        if !first {
            f.write_str("|")?;
        }
        write!(f, "0x{remaining:X}")?;
    }
    Ok(())
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
        self.validate_geometry_fields()?;
        self.validate_geometry_layout()
    }

    /// Validate individual superblock field values (sizes, bounds, consistency).
    fn validate_geometry_fields(&self) -> Result<(), ParseError> {
        // ── blocks_per_group ────────────────────────────────────────────
        if self.blocks_per_group == 0 {
            return Err(ParseError::InvalidField {
                field: "s_blocks_per_group",
                reason: "cannot be zero",
            });
        }
        let max_blocks_per_group = self.block_size.saturating_mul(8);
        if max_blocks_per_group > 0 && self.blocks_per_group > max_blocks_per_group {
            return Err(ParseError::InvalidField {
                field: "s_blocks_per_group",
                reason: "exceeds block_size * 8 (block bitmap capacity)",
            });
        }

        // ── inodes_per_group ────────────────────────────────────────────
        if self.inodes_per_group == 0 {
            return Err(ParseError::InvalidField {
                field: "s_inodes_per_group",
                reason: "cannot be zero",
            });
        }
        let max_inodes_per_group = self.block_size.saturating_mul(8);
        if max_inodes_per_group > 0 && self.inodes_per_group > max_inodes_per_group {
            return Err(ParseError::InvalidField {
                field: "s_inodes_per_group",
                reason: "exceeds block_size * 8 (inode bitmap capacity)",
            });
        }

        // ── inode_size ──────────────────────────────────────────────────
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
        if u32::from(self.inode_size) > self.block_size {
            return Err(ParseError::InvalidField {
                field: "s_inode_size",
                reason: "inode_size exceeds block_size",
            });
        }

        // ── desc_size ───────────────────────────────────────────────────
        if self.desc_size != 0 {
            if self.desc_size < 32 {
                return Err(ParseError::InvalidField {
                    field: "s_desc_size",
                    reason: "must be >= 32 when non-zero",
                });
            }
            if u32::from(self.desc_size) > self.block_size {
                return Err(ParseError::InvalidField {
                    field: "s_desc_size",
                    reason: "desc_size exceeds block_size",
                });
            }
        }
        // Check the raw field — group_desc_size() clamps to 64 for 64BIT,
        // but the on-disk value should actually be >= 64.
        if self.is_64bit() && self.desc_size < 64 {
            return Err(ParseError::InvalidField {
                field: "s_desc_size",
                reason: "64BIT feature set but desc_size < 64",
            });
        }

        Ok(())
    }

    /// Validate cross-field layout: first_data_block, group count, GDT bounds,
    /// and inodes_count vs group geometry.
    fn validate_geometry_layout(&self) -> Result<(), ParseError> {
        // ── first_data_block ────────────────────────────────────────────
        if u64::from(self.first_data_block) >= self.blocks_count {
            return Err(ParseError::InvalidField {
                field: "s_first_data_block",
                reason: "first_data_block >= blocks_count",
            });
        }
        if self.block_size == 1024 && self.first_data_block != 1 {
            return Err(ParseError::InvalidField {
                field: "s_first_data_block",
                reason: "must be 1 for 1K block size",
            });
        }
        if self.block_size > 1024 && self.first_data_block != 0 {
            return Err(ParseError::InvalidField {
                field: "s_first_data_block",
                reason: "must be 0 for block sizes > 1K",
            });
        }

        // ── group count & GDT bounds ────────────────────────────────────
        let group_count = self.groups_count();
        if group_count == 0 {
            return Err(ParseError::InvalidField {
                field: "s_blocks_count",
                reason: "zero block groups (blocks_count too small)",
            });
        }
        let gdt_bytes = u64::from(group_count).saturating_mul(u64::from(self.group_desc_size()));
        let device_bytes = self.blocks_count.saturating_mul(u64::from(self.block_size));
        let gdt_start = self
            .group_desc_offset(ffs_types::GroupNumber(0))
            .unwrap_or(u64::MAX);
        if gdt_start.saturating_add(gdt_bytes) > device_bytes {
            return Err(ParseError::InvalidField {
                field: "s_blocks_count",
                reason: "group descriptor table extends beyond device",
            });
        }

        // ── inodes_count vs group geometry ──────────────────────────────
        let max_inodes = u64::from(group_count).saturating_mul(u64::from(self.inodes_per_group));
        if u64::from(self.inodes_count) > max_inodes {
            return Err(ParseError::InvalidField {
                field: "s_inodes_count",
                reason: "inodes_count exceeds groups * inodes_per_group",
            });
        }

        Ok(())
    }

    /// Run v1 mount-time validation.
    ///
    /// Checks geometry, block size, and feature flags. Returns `ParseError`
    /// with a static `field` + `reason` pair. Callers needing the specific
    /// flag names for UX should also call [`feature_diagnostics_v1()`] on
    /// failure to enrich the error message.
    pub fn validate_v1(&self) -> Result<(), ParseError> {
        self.validate_geometry()?;

        if !matches!(self.block_size, 1024 | 2048 | 4096) {
            return Err(ParseError::InvalidField {
                field: "block_size",
                reason: "unsupported (FrankenFS v1 supports 1K/2K/4K ext4 only)",
            });
        }

        // Check incompat features: required → rejected → unknown.
        if (self.feature_incompat.0 & Ext4IncompatFeatures::REQUIRED_V1.0)
            != Ext4IncompatFeatures::REQUIRED_V1.0
        {
            return Err(ParseError::InvalidField {
                field: "feature_incompat",
                reason: "missing required features (need FILETYPE+EXTENTS)",
            });
        }

        if (self.feature_incompat.0 & Ext4IncompatFeatures::REJECTED_V1.0) != 0 {
            return Err(ParseError::InvalidField {
                field: "feature_incompat",
                reason: "unsupported features present (COMPRESSION/JOURNAL_DEV/INLINE_DATA/ENCRYPT/CASEFOLD rejected)",
            });
        }

        if (self.feature_incompat.0 & !Ext4IncompatFeatures::ALLOWED_V1.0) != 0 {
            return Err(ParseError::InvalidField {
                field: "feature_incompat",
                reason: "unknown incompatible feature flags present",
            });
        }

        Ok(())
    }

    /// Produce structured diagnostics about feature flag compatibility.
    ///
    /// This does NOT fail on its own — it returns a summary that callers
    /// can use for logging, error enrichment, or UX display.
    #[must_use]
    pub fn feature_diagnostics_v1(&self) -> FeatureDiagnostics {
        let missing_required = self.feature_incompat.describe_missing_required_v1();
        let rejected_present = self.feature_incompat.describe_rejected_v1();
        let unknown_incompat = self.feature_incompat.unknown_bits();
        let unknown_ro_compat = self.feature_ro_compat.unknown_bits();

        FeatureDiagnostics {
            missing_required,
            rejected_present,
            unknown_incompat_bits: unknown_incompat,
            unknown_ro_compat_bits: unknown_ro_compat,
            incompat_display: format!("{}", self.feature_incompat),
            ro_compat_display: format!("{}", self.feature_ro_compat),
            compat_display: format!("{}", self.feature_compat),
        }
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

    /// Validated inode location: returns group, index, and byte offset within
    /// the group's inode table.
    ///
    /// Unlike [`inode_table_offset`](Self::inode_table_offset), this checks
    /// that `ino` is valid (non-zero, within `inodes_count`).
    pub fn locate_inode(&self, ino: InodeNumber) -> Result<InodeLocation, ParseError> {
        if ino.0 == 0 {
            return Err(ParseError::InvalidField {
                field: "inode_number",
                reason: "inode 0 is invalid in ext4",
            });
        }
        if ino.0 > u64::from(self.inodes_count) {
            return Err(ParseError::InvalidField {
                field: "inode_number",
                reason: "inode number exceeds inodes_count",
            });
        }
        let group = ffs_types::inode_to_group(ino, self.inodes_per_group);
        let index = ffs_types::inode_index_in_group(ino, self.inodes_per_group);
        let offset_in_table = u64::from(index)
            .checked_mul(u64::from(self.inode_size))
            .ok_or(ParseError::InvalidField {
                field: "inode_offset",
                reason: "overflow computing inode offset in table",
            })?;
        Ok(InodeLocation {
            group,
            index,
            offset_in_table,
        })
    }

    /// Compute the absolute device byte offset of an inode, given the group
    /// descriptor's `inode_table` block pointer.
    ///
    /// This is a pure helper — no I/O required. Use [`locate_inode`](Self::locate_inode)
    /// first to get the [`InodeLocation`], then pass the group descriptor's
    /// `inode_table` field here.
    pub fn inode_device_offset(
        &self,
        loc: &InodeLocation,
        inode_table_block: u64,
    ) -> Result<u64, ParseError> {
        let table_start_byte = inode_table_block
            .checked_mul(u64::from(self.block_size))
            .ok_or(ParseError::InvalidField {
                field: "bg_inode_table",
                reason: "overflow computing inode table byte offset",
            })?;
        table_start_byte
            .checked_add(loc.offset_in_table)
            .ok_or(ParseError::InvalidField {
                field: "inode_offset",
                reason: "overflow computing absolute inode offset",
            })
    }
}

/// Result of [`Ext4Superblock::locate_inode`]: which block group and where
/// within the inode table an inode resides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeLocation {
    /// Block group containing this inode.
    pub group: GroupNumber,
    /// Zero-based index within the group's inode table.
    pub index: u32,
    /// Byte offset from the start of the group's inode table.
    pub offset_in_table: u64,
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

/// Verify the CRC32C checksum of a directory block's tail entry.
///
/// The ext4 directory block checksum covers the directory entries up to
/// (but NOT including) the 12-byte `ext4_dir_entry_tail` structure at the
/// end of the block. The stored checksum is within that tail at offset +8.
///
/// ```text
/// tail_struct = block[block_size - 12 ..]   // 12-byte ext4_dir_entry_tail
/// stored_csum = tail_struct[8..12]          // det_checksum field
///
/// seed = ext4_chksum(csum_seed, &le_ino, 4)
/// seed = ext4_chksum(seed, &le_gen, 4)
/// csum = ext4_chksum(seed, dir_block[..block_size - 12])
/// ```
///
/// Returns `Ok(())` if the checksum matches, `Err` on mismatch.
pub fn verify_dir_block_checksum(
    dir_block: &[u8],
    csum_seed: u32,
    ino: u32,
    generation: u32,
) -> Result<(), ParseError> {
    let bs = dir_block.len();
    if bs < 12 {
        return Err(ParseError::InsufficientData {
            needed: 12,
            offset: 0,
            actual: bs,
        });
    }

    // The 12-byte tail structure at the end of the block:
    //   [0..4]  det_reserved_zero1 (inode=0)
    //   [4..6]  det_rec_len (12)
    //   [6]     det_reserved_zero2 (name_len=0)
    //   [7]     det_reserved_ft (0xDE)
    //   [8..12] det_checksum
    // Stored checksum is at block_size - 4.
    let stored = read_le_u32(dir_block, bs - 4)?;

    // Per-inode seed: i_csum_seed = crc32c(crc32c(csum_seed, le_ino), le_gen)
    let seed = crc32c::crc32c_append(csum_seed, &ino.to_le_bytes());
    let seed = crc32c::crc32c_append(seed, &generation.to_le_bytes());

    // Kernel checksums block[0..block_size - 12]: the dir entry data before
    // the 12-byte tail. The entire tail struct is excluded from coverage.
    let coverage_end = bs - 12;
    let computed = crc32c::crc32c_append(seed, &dir_block[..coverage_end]);

    if computed != stored {
        return Err(ParseError::InvalidField {
            field: "dir_checksum",
            reason: "directory block CRC32C mismatch",
        });
    }
    Ok(())
}

/// Verify the CRC32C checksum of an extent tree block.
///
/// Extent tree blocks (non-root, stored in separate blocks) have a 4-byte
/// checksum tail immediately after the extent entry slots. The kernel
/// defines `EXT4_EXTENT_TAIL_OFFSET(hdr) = 12 + 12 * eh_max`, so the
/// CRC covers `extent_block[0..12 + 12*eh_max]` and the stored checksum
/// lives at that same offset.
///
/// ```text
/// tail_off = sizeof(ext4_extent_header) + sizeof(ext4_extent) * eh_max
///          = 12 + 12 * eh_max
/// seed = ext4_chksum(csum_seed, &le_ino, 4)
/// seed = ext4_chksum(seed, &le_gen, 4)
/// csum = ext4_chksum(seed, extent_block[..tail_off])
/// stored = le32(extent_block[tail_off..tail_off+4])
/// ```
pub fn verify_extent_block_checksum(
    extent_block: &[u8],
    csum_seed: u32,
    ino: u32,
    generation: u32,
) -> Result<(), ParseError> {
    let bs = extent_block.len();
    if bs < 16 {
        return Err(ParseError::InsufficientData {
            needed: 16,
            offset: 0,
            actual: bs,
        });
    }

    // eh_max is at offset 4 in the 12-byte extent header
    let eh_max = usize::from(read_le_u16(extent_block, 4)?);
    let tail_off = 12 + 12 * eh_max;
    if tail_off + 4 > bs {
        return Err(ParseError::InsufficientData {
            needed: tail_off + 4,
            offset: 0,
            actual: bs,
        });
    }

    let stored = read_le_u32(extent_block, tail_off)?;

    let seed = crc32c::crc32c_append(csum_seed, &ino.to_le_bytes());
    let seed = crc32c::crc32c_append(seed, &generation.to_le_bytes());
    let computed = crc32c::crc32c_append(seed, &extent_block[..tail_off]);

    if computed != stored {
        return Err(ParseError::InvalidField {
            field: "extent_checksum",
            reason: "extent block CRC32C mismatch",
        });
    }
    Ok(())
}

// EXT4_HUGE_FILE_FL imported from ffs_types

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

    // ── Inline xattr area ───────────────────────────────────────────────
    /// Raw bytes from the inode body area available for inline xattrs.
    /// This is the region `[128 + extra_isize .. inode_size]`.
    pub xattr_ibody: Vec<u8>,
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

            xattr_ibody: if extra_isize > 0 {
                let xattr_start = 128 + usize::from(extra_isize);
                if xattr_start < bytes.len() {
                    bytes[xattr_start..].to_vec()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            },
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

    // ── Device number helpers ───────────────────────────────────────────

    /// For block/char device inodes, extract the device number from the i_block area.
    ///
    /// Returns the device number in Linux `new_encode_dev` format (suitable for
    /// FUSE `rdev` / `st_rdev`). For non-device inodes, returns 0.
    ///
    /// ext4 stores device numbers in `i_block[0]` (old 16-bit format) or
    /// `i_block[1]` (new 32-bit format). If `i_block[0]` is non-zero, it holds
    /// the old encoding; otherwise `i_block[1]` holds the new encoding.
    #[must_use]
    pub fn device_number(&self) -> u32 {
        if !self.is_blkdev() && !self.is_chrdev() {
            return 0;
        }
        if self.extent_bytes.len() < 8 {
            return 0;
        }

        let block0 = u32::from_le_bytes([
            self.extent_bytes[0],
            self.extent_bytes[1],
            self.extent_bytes[2],
            self.extent_bytes[3],
        ]);

        if block0 != 0 {
            // Old-format: 8-bit major in bits[15:8], 8-bit minor in bits[7:0].
            // This is already compatible with new_encode_dev for ≤8-bit values.
            block0 & 0xFFFF
        } else {
            // New-format in i_block[1]: 12-bit major, 20-bit minor.
            u32::from_le_bytes([
                self.extent_bytes[4],
                self.extent_bytes[5],
                self.extent_bytes[6],
                self.extent_bytes[7],
            ])
        }
    }

    /// Extract the major device number for block/char device inodes.
    ///
    /// Uses the Linux `new_decode_dev` convention: `major = (rdev >> 8) & 0xFFF`.
    #[must_use]
    pub fn device_major(&self) -> u32 {
        (self.device_number() >> 8) & 0xFFF
    }

    /// Extract the minor device number for block/char device inodes.
    ///
    /// Uses the Linux `new_decode_dev` convention:
    /// `minor = (rdev & 0xFF) | ((rdev >> 12) & 0xFFF00)`.
    #[must_use]
    pub fn device_minor(&self) -> u32 {
        let rdev = self.device_number();
        (rdev & 0xFF) | ((rdev >> 12) & 0xFFF00)
    }

    // ── Symlink helpers ─────────────────────────────────────────────────

    /// Whether this is a "fast" (inline) symlink stored in the inode's i_block area.
    ///
    /// ext4 stores short symlink targets (up to 60 bytes) directly in the
    /// `i_block` field of the inode rather than in separate data blocks.
    /// This is detected by: symlink type + no extents flag + size <= 60.
    #[must_use]
    pub fn is_fast_symlink(&self) -> bool {
        self.is_symlink() && !self.uses_extents() && self.size <= EXT4_FAST_SYMLINK_MAX as u64
    }

    /// Read the target of a fast (inline) symlink from the inode's extent_bytes.
    ///
    /// Returns `None` if this is not a fast symlink.
    #[must_use]
    pub fn fast_symlink_target(&self) -> Option<&[u8]> {
        if !self.is_fast_symlink() {
            return None;
        }
        // is_fast_symlink guarantees size <= 60, so this cast is safe
        let len = usize::try_from(self.size).ok()?;
        if len <= self.extent_bytes.len() {
            Some(&self.extent_bytes[..len])
        } else {
            None
        }
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

    /// Convert a (seconds, nanoseconds) pair to `SystemTime`.
    ///
    /// Negative seconds produce times before `UNIX_EPOCH` (pre-1970).
    /// Returns `None` for timestamps that overflow `SystemTime`'s range.
    #[must_use]
    pub fn to_system_time(secs: i64, nsec: u32) -> Option<std::time::SystemTime> {
        use std::time::{Duration, UNIX_EPOCH};
        if secs >= 0 {
            let secs = u64::try_from(secs).ok()?;
            UNIX_EPOCH.checked_add(Duration::new(secs, nsec))
        } else {
            let abs = u64::try_from(secs.checked_neg()?).ok()?;
            UNIX_EPOCH
                .checked_sub(Duration::new(abs, 0))?
                .checked_add(Duration::new(0, nsec))
        }
    }

    /// Access time as `SystemTime`. Falls back to `UNIX_EPOCH` on overflow.
    #[must_use]
    pub fn atime_system_time(&self) -> std::time::SystemTime {
        let (s, ns) = self.atime_full();
        Self::to_system_time(s, ns).unwrap_or(std::time::UNIX_EPOCH)
    }

    /// Modification time as `SystemTime`. Falls back to `UNIX_EPOCH` on overflow.
    #[must_use]
    pub fn mtime_system_time(&self) -> std::time::SystemTime {
        let (s, ns) = self.mtime_full();
        Self::to_system_time(s, ns).unwrap_or(std::time::UNIX_EPOCH)
    }

    /// Inode change time as `SystemTime`. Falls back to `UNIX_EPOCH` on overflow.
    #[must_use]
    pub fn ctime_system_time(&self) -> std::time::SystemTime {
        let (s, ns) = self.ctime_full();
        Self::to_system_time(s, ns).unwrap_or(std::time::UNIX_EPOCH)
    }

    /// Creation time as `SystemTime`. Falls back to `UNIX_EPOCH` on overflow.
    #[must_use]
    pub fn crtime_system_time(&self) -> std::time::SystemTime {
        let (s, ns) = self.crtime_full();
        Self::to_system_time(s, ns).unwrap_or(std::time::UNIX_EPOCH)
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

// ── Zero-allocation directory block iterator ────────────────────────────────

/// A borrowed directory entry (zero-copy reference into the block buffer).
///
/// Unlike [`Ext4DirEntry`] which owns its name bytes via `Vec<u8>`,
/// `Ext4DirEntryRef` borrows the name slice from the block buffer. This
/// avoids per-entry heap allocation when iterating directory blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ext4DirEntryRef<'a> {
    pub inode: u32,
    pub rec_len: u32,
    pub name_len: u8,
    pub file_type: Ext4FileType,
    pub name: &'a [u8],
}

impl Ext4DirEntryRef<'_> {
    /// Convert to an owned [`Ext4DirEntry`] (allocates name bytes).
    #[must_use]
    pub fn to_owned(&self) -> Ext4DirEntry {
        Ext4DirEntry {
            inode: self.inode,
            rec_len: u16::try_from(self.rec_len).unwrap_or(u16::MAX),
            name_len: self.name_len,
            file_type: self.file_type,
            name: self.name.to_vec(),
        }
    }

    /// Return the name as a UTF-8 string (lossy).
    #[must_use]
    pub fn name_str(&self) -> String {
        String::from_utf8_lossy(self.name).into_owned()
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

/// A zero-allocation iterator over ext4 directory entries in a block buffer.
///
/// Yields `Result<Ext4DirEntryRef<'a>, ParseError>` for each live entry
/// (inode != 0), skipping deleted entries and the checksum tail. After
/// exhausting the iterator, call [`checksum_tail()`](DirBlockIter::checksum_tail)
/// to retrieve the tail if one was present.
///
/// # Example
///
/// ```ignore
/// let iter = DirBlockIter::new(block_data, block_size);
/// for result in iter {
///     let entry = result?;
///     println!("{} -> inode {}", entry.name_str(), entry.inode);
/// }
/// ```
pub struct DirBlockIter<'a> {
    block: &'a [u8],
    block_size: u32,
    offset: usize,
    tail: Option<Ext4DirEntryTail>,
    done: bool,
}

impl<'a> DirBlockIter<'a> {
    /// Create a new iterator over directory entries in `block`.
    #[must_use]
    pub fn new(block: &'a [u8], block_size: u32) -> Self {
        Self {
            block,
            block_size,
            offset: 0,
            tail: None,
            done: false,
        }
    }

    /// Return the checksum tail, if one was found during iteration.
    ///
    /// Only valid after the iterator has been fully consumed.
    #[must_use]
    pub fn checksum_tail(&self) -> Option<Ext4DirEntryTail> {
        self.tail
    }
}

impl<'a> Iterator for DirBlockIter<'a> {
    type Item = Result<Ext4DirEntryRef<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done || self.offset + 8 > self.block.len() {
                return None;
            }

            let inode = match read_le_u32(self.block, self.offset) {
                Ok(v) => v,
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            };
            let rec_len_raw = match read_le_u16(self.block, self.offset + 4) {
                Ok(v) => v,
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            };
            let name_len = match ensure_slice(self.block, self.offset + 6, 1) {
                Ok(s) => s[0],
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            };
            let file_type_raw = match ensure_slice(self.block, self.offset + 7, 1) {
                Ok(s) => s[0],
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            };

            let rec_len = rec_len_from_disk(rec_len_raw, self.block_size);

            // rec_len must be >= 8 (header size)
            if rec_len < 8 {
                self.done = true;
                return Some(Err(ParseError::InvalidField {
                    field: "de_rec_len",
                    reason: "directory entry rec_len < 8",
                }));
            }

            // rec_len must not overflow or exceed block
            let entry_end = match self.offset.checked_add(rec_len as usize) {
                Some(end) if end <= self.block.len() => end,
                Some(_) => {
                    self.done = true;
                    return Some(Err(ParseError::InvalidField {
                        field: "de_rec_len",
                        reason: "directory entry extends past block boundary",
                    }));
                }
                None => {
                    self.done = true;
                    return Some(Err(ParseError::InvalidField {
                        field: "de_rec_len",
                        reason: "overflow",
                    }));
                }
            };

            // Detect checksum tail sentinel
            if inode == 0 && name_len == 0 && file_type_raw == EXT4_FT_DIR_CSUM && rec_len == 12 {
                if self.offset + 12 <= self.block.len() {
                    if let Ok(csum) = read_le_u32(self.block, self.offset + 8) {
                        self.tail = Some(Ext4DirEntryTail { checksum: csum });
                    }
                }
                self.done = true;
                return None;
            }

            // Skip deleted entries (inode == 0)
            if inode == 0 {
                self.offset = entry_end;
                continue;
            }

            // Validate name_len fits within rec_len
            let name_end = self.offset + 8 + usize::from(name_len);
            if name_end > entry_end {
                self.done = true;
                return Some(Err(ParseError::InvalidField {
                    field: "de_name_len",
                    reason: "name extends past rec_len",
                }));
            }

            let name = &self.block[self.offset + 8..name_end];
            self.offset = entry_end;

            return Some(Ok(Ext4DirEntryRef {
                inode,
                rec_len,
                name_len,
                file_type: Ext4FileType::from_raw(file_type_raw),
                name,
            }));
        }
    }
}

/// Create an iterator over directory entries in a block buffer.
///
/// This is a convenience wrapper around [`DirBlockIter::new`].
#[must_use]
pub fn iter_dir_block(block: &[u8], block_size: u32) -> DirBlockIter<'_> {
    DirBlockIter::new(block, block_size)
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
            if !current_inode.is_dir() {
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

    // ── Symlink operations ────────────────────────────────────────────

    /// Read the target of a symbolic link.
    ///
    /// For "fast" symlinks (target <= 60 bytes, stored inline in the inode's
    /// i_block area), the target is read directly from the inode.
    /// For longer symlinks, the target is read from extent-mapped data blocks.
    pub fn read_symlink(&self, image: &[u8], inode: &Ext4Inode) -> Result<Vec<u8>, ParseError> {
        if !inode.is_symlink() {
            return Err(ParseError::InvalidField {
                field: "i_mode",
                reason: "inode is not a symlink",
            });
        }

        // Fast symlink: target stored in i_block area
        if let Some(target) = inode.fast_symlink_target() {
            return Ok(target.to_vec());
        }

        // Extent-mapped symlink: read via normal file data path
        let size = usize::try_from(inode.size)
            .map_err(|_| ParseError::IntegerConversion { field: "i_size" })?;
        let mut buf = vec![0_u8; size];
        let n = self.read_inode_data(image, inode, 0, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Maximum number of symlink resolutions in a single path traversal.
    ///
    /// Matches the Linux kernel's MAXSYMLINKS (40) to prevent infinite loops.
    const MAX_SYMLINKS: u32 = 40;

    /// Resolve an absolute path, following symbolic links.
    ///
    /// Like `resolve_path`, but when a path component resolves to a symlink,
    /// the symlink target is read and the remaining path is adjusted.
    /// Detects symlink loops via a resolution counter (max 40, matching the kernel).
    ///
    /// Does not support relative symlinks that escape the root (they are
    /// resolved relative to the filesystem root).
    pub fn resolve_path_follow(
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

        let mut symlink_count = 0_u32;
        // Build the full component queue from the initial path
        let mut components: Vec<String> = path
            .split('/')
            .filter(|c| !c.is_empty())
            .map(String::from)
            .collect();
        components.reverse(); // process from the back as a stack

        let mut current_ino = ffs_types::InodeNumber::ROOT;
        let mut current_inode = self.read_inode(image, current_ino)?;

        while let Some(component) = components.pop() {
            // Current must be a directory to traverse into
            if !current_inode.is_dir() {
                return Err(ParseError::InvalidField {
                    field: "path",
                    reason: "component is not a directory",
                });
            }

            // Save parent directory for relative symlink resolution
            let parent_ino = current_ino;
            let parent_inode = current_inode.clone();

            let entry = self
                .lookup(image, &parent_inode, component.as_bytes())?
                .ok_or(ParseError::InvalidField {
                    field: "path",
                    reason: "component not found",
                })?;

            current_ino = ffs_types::InodeNumber(u64::from(entry.inode));
            current_inode = self.read_inode(image, current_ino)?;

            // If we landed on a symlink, resolve it
            if current_inode.is_symlink() {
                symlink_count += 1;
                if symlink_count > Self::MAX_SYMLINKS {
                    return Err(ParseError::InvalidField {
                        field: "path",
                        reason: "too many levels of symbolic links",
                    });
                }

                let target = self.read_symlink(image, &current_inode)?;
                let target_str =
                    std::str::from_utf8(&target).map_err(|_| ParseError::InvalidField {
                        field: "symlink_target",
                        reason: "symlink target is not valid UTF-8",
                    })?;

                if target_str.starts_with('/') {
                    // Absolute symlink: restart from root
                    current_ino = ffs_types::InodeNumber::ROOT;
                    current_inode = self.read_inode(image, current_ino)?;
                } else {
                    // Relative symlink: resolve from parent directory
                    current_ino = parent_ino;
                    current_inode = parent_inode;
                }

                // Push target components onto the stack (reversed)
                for comp in target_str
                    .split('/')
                    .filter(|c| !c.is_empty())
                    .map(String::from)
                    .rev()
                {
                    components.push(comp);
                }
            }
        }

        Ok((current_ino, current_inode))
    }

    // ── Extended attributes ─────────────────────────────────────────────

    /// Read inline xattrs from the inode body (ibody region).
    ///
    /// The inline xattr area starts after `128 + extra_isize` and contains
    /// entries prefixed with a 4-byte magic header.
    pub fn read_xattrs_ibody(&self, inode: &Ext4Inode) -> Result<Vec<Ext4Xattr>, ParseError> {
        if inode.xattr_ibody.len() < 4 {
            return Ok(Vec::new());
        }
        // The ibody xattr region starts with a 4-byte header (just the magic)
        let magic = read_le_u32(&inode.xattr_ibody, 0)?;
        if magic != EXT4_XATTR_MAGIC {
            // No inline xattrs present (or corrupted)
            return Ok(Vec::new());
        }
        parse_xattr_entries(&inode.xattr_ibody[4..])
    }

    /// Read xattrs from an external xattr block (pointed to by `i_file_acl`).
    pub fn read_xattrs_block(
        &self,
        image: &[u8],
        inode: &Ext4Inode,
    ) -> Result<Vec<Ext4Xattr>, ParseError> {
        if inode.file_acl == 0 {
            return Ok(Vec::new());
        }
        let block_data = self.read_block(image, ffs_types::BlockNumber(inode.file_acl))?;

        // External xattr block starts with a 32-byte header
        if block_data.len() < 32 {
            return Err(ParseError::InsufficientData {
                needed: 32,
                offset: 0,
                actual: block_data.len(),
            });
        }
        let magic = read_le_u32(block_data, 0)?;
        if magic != EXT4_XATTR_MAGIC {
            return Err(ParseError::InvalidMagic {
                expected: u64::from(EXT4_XATTR_MAGIC),
                actual: u64::from(magic),
            });
        }
        // Entries start at byte 32 of the xattr block
        parse_xattr_entries(&block_data[32..])
    }

    /// Read all xattrs for an inode (inline + external block).
    pub fn list_xattrs(
        &self,
        image: &[u8],
        inode: &Ext4Inode,
    ) -> Result<Vec<Ext4Xattr>, ParseError> {
        let mut result = self.read_xattrs_ibody(inode)?;
        let block_xattrs = self.read_xattrs_block(image, inode)?;
        result.extend(block_xattrs);
        Ok(result)
    }

    /// Get a specific xattr by name index and name.
    pub fn get_xattr(
        &self,
        image: &[u8],
        inode: &Ext4Inode,
        name_index: u8,
        name: &[u8],
    ) -> Result<Option<Vec<u8>>, ParseError> {
        let all = self.list_xattrs(image, inode)?;
        Ok(all
            .into_iter()
            .find(|x| x.name_index == name_index && x.name == name)
            .map(|x| x.value))
    }

    // ── Hash-tree (htree/DX) directory lookup ───────────────────────────

    /// Look up a name in a hash-indexed directory using the htree/DX index.
    ///
    /// If the directory has the `EXT4_INDEX_FL` flag set and block 0 contains
    /// a valid DX root, this performs an O(log n) lookup by hashing the name,
    /// binary-searching the DX entries to find the target leaf block, then
    /// doing a linear scan of that leaf block.
    ///
    /// Falls back to linear scan if the htree is not present or valid.
    pub fn htree_lookup(
        &self,
        image: &[u8],
        dir_inode: &Ext4Inode,
        name: &[u8],
    ) -> Result<Option<Ext4DirEntry>, ParseError> {
        // Only attempt htree if the INDEX flag is set
        if !dir_inode.has_htree_index() {
            return self.lookup(image, dir_inode, name);
        }

        // Read block 0 of the directory — it contains the DX root
        let Some(phys0) = self.resolve_extent(image, dir_inode, 0)? else {
            return self.lookup(image, dir_inode, name);
        };
        let block0 = self.read_block(image, ffs_types::BlockNumber(phys0))?;

        // Parse the DX root from block 0
        let Ok(dx_root) = parse_dx_root(block0) else {
            return self.lookup(image, dir_inode, name);
        };

        // Hash the name using the hash version from the DX root
        let (hash, _minor) = dx_hash(dx_root.hash_version, name, &self.sb.hash_seed);

        // Binary search the DX entries for the target hash
        let target_block = dx_find_leaf(&dx_root.entries, hash);

        // If there's an indirect level, we need to read the inner index block
        let leaf_block = if dx_root.indirect_levels > 0 {
            let Some(inner_phys) = self.resolve_extent(image, dir_inode, target_block)? else {
                return Ok(None);
            };
            let inner_data = self.read_block(image, ffs_types::BlockNumber(inner_phys))?;
            let inner_entries = parse_dx_entries(inner_data, 8)?;

            dx_find_leaf(&inner_entries, hash)
        } else {
            target_block
        };

        // Read the leaf directory block and do a linear scan
        let Some(leaf_phys) = self.resolve_extent(image, dir_inode, leaf_block)? else {
            return Ok(None);
        };
        let leaf_data = self.read_block(image, ffs_types::BlockNumber(leaf_phys))?;
        Ok(lookup_in_dir_block(leaf_data, self.sb.block_size, name))
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

// ── Extended attribute types and parsing ─────────────────────────────────────

/// A parsed extended attribute (name + value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4Xattr {
    /// Name index (namespace): 1=user, 2=posix_acl_access, 4=trusted, 6=security, etc.
    pub name_index: u8,
    /// Attribute name (without the namespace prefix).
    pub name: Vec<u8>,
    /// Attribute value.
    pub value: Vec<u8>,
}

impl Ext4Xattr {
    /// Return the full attribute name including the namespace prefix.
    #[must_use]
    pub fn full_name(&self) -> String {
        let prefix = match self.name_index {
            ffs_types::EXT4_XATTR_INDEX_USER => "user.",
            ffs_types::EXT4_XATTR_INDEX_POSIX_ACL_ACCESS => "system.posix_acl_access",
            ffs_types::EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT => "system.posix_acl_default",
            ffs_types::EXT4_XATTR_INDEX_TRUSTED => "trusted.",
            ffs_types::EXT4_XATTR_INDEX_SECURITY => "security.",
            ffs_types::EXT4_XATTR_INDEX_SYSTEM => "system.",
            _ => "unknown.",
        };
        format!("{prefix}{}", String::from_utf8_lossy(&self.name))
    }
}

/// Parse xattr entries from a byte slice (after the header/magic).
///
/// Each entry is:
///   - u8 name_len
///   - u8 name_index
///   - u16 value_offs (offset from start of the value area, which is the end of the block/ibody)
///   - u32 value_size
///   - u32 hash (we ignore this)
///   - [u8; name_len] name
///   - padding to 4-byte boundary
///
/// Entry list is terminated by a zero name_len + zero name_index.
fn parse_xattr_entries(data: &[u8]) -> Result<Vec<Ext4Xattr>, ParseError> {
    let mut entries = Vec::new();
    let mut offset = 0_usize;

    loop {
        // Need at least 4 bytes to check terminator and read entry header
        if offset + 4 > data.len() {
            break;
        }

        let name_len = data[offset];
        let name_index = data[offset + 1];

        // Terminator: name_len=0, name_index=0
        if name_len == 0 && name_index == 0 {
            break;
        }

        // Full entry header is 16 bytes
        if offset + 16 > data.len() {
            break;
        }

        let value_offs = read_le_u16(data, offset + 2)?;
        let value_size = read_le_u32(data, offset + 4)?;
        // skip hash at offset + 8..12

        let name_start = offset + 16;
        let name_end = name_start + usize::from(name_len);
        if name_end > data.len() {
            return Err(ParseError::InvalidField {
                field: "xattr_name",
                reason: "name extends past data boundary",
            });
        }
        let name = data[name_start..name_end].to_vec();

        // Read value from value area (offsets are from end of data working backwards)
        let value = if value_size > 0 {
            let v_off = usize::from(value_offs);
            let v_size =
                usize::try_from(value_size).map_err(|_| ParseError::IntegerConversion {
                    field: "xattr_value_size",
                })?;
            if v_off + v_size > data.len() {
                return Err(ParseError::InvalidField {
                    field: "xattr_value",
                    reason: "value extends past data boundary",
                });
            }
            data[v_off..v_off + v_size].to_vec()
        } else {
            Vec::new()
        };

        entries.push(Ext4Xattr {
            name_index,
            name,
            value,
        });

        // Advance past the entry: header (16) + name_len, padded to 4 bytes
        offset = (name_end + 3) & !3;
    }

    Ok(entries)
}

/// Parse inline (ibody) xattrs from an `Ext4Inode`.
///
/// This is a standalone version of `Ext4ImageReader::read_xattrs_ibody` that
/// does not require an image reader — useful for device-based backends.
pub fn parse_ibody_xattrs(inode: &Ext4Inode) -> Result<Vec<Ext4Xattr>, ParseError> {
    if inode.xattr_ibody.len() < 4 {
        return Ok(Vec::new());
    }
    let magic = read_le_u32(&inode.xattr_ibody, 0)?;
    if magic != EXT4_XATTR_MAGIC {
        return Ok(Vec::new());
    }
    parse_xattr_entries(&inode.xattr_ibody[4..])
}

/// Parse xattrs from an external xattr block (raw block data).
///
/// The block starts with a 32-byte header containing the xattr magic.
pub fn parse_xattr_block(block_data: &[u8]) -> Result<Vec<Ext4Xattr>, ParseError> {
    if block_data.len() < 32 {
        return Err(ParseError::InsufficientData {
            needed: 32,
            offset: 0,
            actual: block_data.len(),
        });
    }
    let magic = read_le_u32(block_data, 0)?;
    if magic != EXT4_XATTR_MAGIC {
        return Err(ParseError::InvalidMagic {
            expected: u64::from(EXT4_XATTR_MAGIC),
            actual: u64::from(magic),
        });
    }
    parse_xattr_entries(&block_data[32..])
}

// ── Hash-tree (htree/DX) structures and algorithms ──────────────────────────

/// Parsed DX root (block 0 of an htree directory).
#[derive(Debug, Clone)]
pub struct Ext4DxRoot {
    /// Hash version (0=legacy, 1=half_md4, 2=tea, 3=legacy_unsigned, 4=half_md4_unsigned, 5=tea_unsigned).
    pub hash_version: u8,
    /// Indirect levels (0 = single level, 1 = two levels).
    pub indirect_levels: u8,
    /// DX entries (hash → block pairs).
    pub entries: Vec<Ext4DxEntry>,
}

/// A single DX index entry: hash value → directory block number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ext4DxEntry {
    pub hash: u32,
    pub block: u32,
}

/// Parse the DX root from the first block of a hash-indexed directory.
///
/// Layout of the DX root (after the fake "." and ".." dir entries):
///   Byte 0x18: reserved (u32)
///   Byte 0x1C: hash_version (u8)
///   Byte 0x1D: info_length (u8)
///   Byte 0x1E: indirect_levels (u8)
///   Byte 0x1F: unused_flags (u8)
///   Byte 0x20: count/limit (u16, u16)
///   Byte 0x24+: DX entries (8 bytes each: hash(4) + block(4))
pub fn parse_dx_root(block: &[u8]) -> Result<Ext4DxRoot, ParseError> {
    // The DX root info starts at byte 0x1C in the directory block
    // (after the fake "." entry at 0x00 and ".." entry at 0x0C)
    if block.len() < 0x28 {
        return Err(ParseError::InsufficientData {
            needed: 0x28,
            offset: 0,
            actual: block.len(),
        });
    }

    let hash_version = block[0x1C];
    let info_length = block[0x1D];
    let indirect_levels = block[0x1E];

    // Validate
    if info_length != 8 {
        return Err(ParseError::InvalidField {
            field: "dx_root_info_length",
            reason: "expected 8",
        });
    }
    if indirect_levels > 2 {
        return Err(ParseError::InvalidField {
            field: "dx_indirect_levels",
            reason: "exceeds maximum (2)",
        });
    }

    // Count/limit at 0x20
    let count = read_le_u16(block, 0x20)?;
    let _limit = read_le_u16(block, 0x22)?;

    // Entries start at 0x24 (first is the zero-hash sentinel entry)
    let entries = parse_dx_entries(block, 0x24)?;

    // Sanity: should have `count` entries total (including sentinel)
    if entries.len() != usize::from(count) {
        // Parse what we can, but if count is wildly off, report as many as fit
    }

    Ok(Ext4DxRoot {
        hash_version,
        indirect_levels,
        entries,
    })
}

/// Parse DX entries starting at `offset` in a block.
///
/// Each entry is 8 bytes: hash(4) + block(4). The list continues
/// until we run out of space in the block.
fn parse_dx_entries(data: &[u8], start: usize) -> Result<Vec<Ext4DxEntry>, ParseError> {
    let mut entries = Vec::new();
    let mut off = start;

    // First, read count at start - 4 (the count/limit pair is 4 bytes before entries)
    let count = if start >= 4 {
        usize::from(read_le_u16(data, start - 4)?)
    } else {
        // Estimate: fill remaining space
        (data.len() - start) / 8
    };

    for _ in 0..count {
        if off + 8 > data.len() {
            break;
        }
        let hash = read_le_u32(data, off)?;
        let block = read_le_u32(data, off + 4)?;
        entries.push(Ext4DxEntry { hash, block });
        off += 8;
    }

    Ok(entries)
}

/// Find the leaf block for a given hash in a sorted DX entry list.
///
/// The entries are sorted by hash. We find the last entry whose hash <= target.
/// Entry 0 is the sentinel (hash=0, points to the first data block), so
/// for any hash, we always have at least one candidate.
fn dx_find_leaf(entries: &[Ext4DxEntry], hash: u32) -> u32 {
    // Binary search: find rightmost entry where entry.hash <= hash
    let mut lo = 0_usize;
    let mut hi = entries.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if entries[mid].hash <= hash {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    // lo-1 is the rightmost entry with hash <= target (lo >= 1 due to sentinel)
    if lo > 0 {
        entries[lo - 1].block
    } else {
        entries[0].block
    }
}

// ── ext4 directory hash functions ───────────────────────────────────────────

/// Hash version constants from the ext4 DX root.
const DX_HASH_LEGACY: u8 = 0;
const DX_HASH_HALF_MD4: u8 = 1;
const DX_HASH_TEA: u8 = 2;
const DX_HASH_LEGACY_UNSIGNED: u8 = 3;
const _DX_HASH_HALF_MD4_UNSIGNED: u8 = 4;
const DX_HASH_TEA_UNSIGNED: u8 = 5;
const _DX_HASH_SIPHASH: u8 = 6;

/// Compute the ext4 directory hash for a filename.
///
/// Returns (major_hash, minor_hash). The `hash_version` selects the algorithm
/// and whether characters are treated as signed or unsigned.
#[must_use]
pub fn dx_hash(hash_version: u8, name: &[u8], seed: &[u32; 4]) -> (u32, u32) {
    match hash_version {
        DX_HASH_LEGACY => dx_hash_legacy(name, true),
        DX_HASH_LEGACY_UNSIGNED => dx_hash_legacy(name, false),
        DX_HASH_HALF_MD4 => dx_hash_half_md4(name, seed, true),
        DX_HASH_TEA => dx_hash_tea(name, seed, true),
        DX_HASH_TEA_UNSIGNED => dx_hash_tea(name, seed, false),
        // DX_HASH_HALF_MD4_UNSIGNED and any unknown versions default to half_md4 unsigned
        _ => dx_hash_half_md4(name, seed, false),
    }
}

/// Legacy (r5) hash function — simple polynomial hash.
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)] // intentional signed char semantics
fn dx_hash_legacy(name: &[u8], signed: bool) -> (u32, u32) {
    let mut h0: u32 = 0x12a3_fe2d;
    let mut h1: u32 = 0x37ab_e8f9;

    for &b in name {
        let val = if signed {
            i32::from(b as i8) as u32
        } else {
            u32::from(b)
        };
        h0 = h0.wrapping_mul(16).wrapping_add(val);
        h1 = h1.wrapping_mul(16).wrapping_add(val);
    }

    // Fold to produce major/minor
    (h0 & !1, h1) // clear low bit of major (reserved by ext4)
}

/// Half-MD4 hash function — used by most ext4 filesystems.
///
/// This implements the str2hashbuf + half-MD4 transform from the kernel.
#[allow(clippy::cast_possible_wrap)] // intentional signed char semantics
fn dx_hash_half_md4(name: &[u8], seed: &[u32; 4], signed: bool) -> (u32, u32) {
    let buf = str2hashbuf(name, 8, signed);
    let mut a = seed[0];
    let mut b = seed[1];
    let mut c = seed[2];
    let mut d = seed[3];

    half_md4_transform(&mut a, &mut b, &mut c, &mut d, &buf);

    (a & !1, b) // clear low bit of major
}

/// TEA (Tiny Encryption Algorithm) hash — an alternative ext4 hash.
#[allow(clippy::cast_possible_wrap)]
fn dx_hash_tea(name: &[u8], seed: &[u32; 4], signed: bool) -> (u32, u32) {
    let buf = str2hashbuf(name, 4, signed);
    let mut a = seed[0];
    let mut b = seed[1];
    let mut c = seed[2];
    let mut d = seed[3];

    tea_transform(&mut a, &mut b, &mut c, &mut d, &buf);

    (a & !1, b)
}

/// Convert a filename to a u32 buffer for hashing.
///
/// The kernel's `str2hashbuf` packs characters into u32 words (little-endian),
/// with optional signed character semantics.
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
fn str2hashbuf(name: &[u8], buf_size: usize, signed: bool) -> Vec<u32> {
    let mut buf = vec![0_u32; buf_size];
    let mut idx = 0_usize;
    let mut shift = 0_u32;

    for &b in name {
        let val = if signed {
            (b as i8) as u32
        } else {
            u32::from(b)
        };
        buf[idx] |= val << shift;
        shift += 8;
        if shift >= 32 {
            shift = 0;
            idx += 1;
            if idx >= buf_size {
                break;
            }
        }
    }

    // Pad with 0x80 terminator like the kernel does
    if idx < buf_size {
        buf[idx] |= 0x80 << shift;
    }

    buf
}

/// Half-MD4 transform — the core of the half-MD4 hash.
///
/// This is a simplified version of MD4 that operates on a single 32-byte
/// block (8 u32 words) and produces a 128-bit intermediate state.
fn half_md4_transform(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, buf: &[u32]) {
    const K2: u32 = 0x5A82_7999; // Round 2 constant
    const K3: u32 = 0x6ED9_EBA1; // Round 3 constant

    // Ensure we have 8 words; pad with zero if shorter
    let get = |i: usize| -> u32 { buf.get(i).copied().unwrap_or(0) };

    // Round 1: F(x,y,z) = (x & y) | (!x & z)
    macro_rules! ff {
        ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
            $a = $a
                .wrapping_add(($b & $c) | (!$b & $d))
                .wrapping_add(get($k));
            $a = $a.rotate_left($s);
        };
    }

    ff!(*a, *b, *c, *d, 0, 3);
    ff!(*d, *a, *b, *c, 1, 7);
    ff!(*c, *d, *a, *b, 2, 11);
    ff!(*b, *c, *d, *a, 3, 19);
    ff!(*a, *b, *c, *d, 4, 3);
    ff!(*d, *a, *b, *c, 5, 7);
    ff!(*c, *d, *a, *b, 6, 11);
    ff!(*b, *c, *d, *a, 7, 19);

    // Round 2: G(x,y,z) = (x & y) | (x & z) | (y & z)
    macro_rules! gg {
        ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
            $a = $a
                .wrapping_add(($b & $c) | ($b & $d) | ($c & $d))
                .wrapping_add(get($k))
                .wrapping_add(K2);
            $a = $a.rotate_left($s);
        };
    }

    gg!(*a, *b, *c, *d, 1, 3);
    gg!(*d, *a, *b, *c, 3, 5);
    gg!(*c, *d, *a, *b, 5, 9);
    gg!(*b, *c, *d, *a, 7, 13);
    gg!(*a, *b, *c, *d, 0, 3);
    gg!(*d, *a, *b, *c, 2, 5);
    gg!(*c, *d, *a, *b, 4, 9);
    gg!(*b, *c, *d, *a, 6, 13);

    // Round 3: H(x,y,z) = x ^ y ^ z
    macro_rules! hh {
        ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
            $a = $a
                .wrapping_add($b ^ $c ^ $d)
                .wrapping_add(get($k))
                .wrapping_add(K3);
            $a = $a.rotate_left($s);
        };
    }

    hh!(*a, *b, *c, *d, 0, 3);
    hh!(*d, *a, *b, *c, 4, 9);
    hh!(*c, *d, *a, *b, 7, 11);
    hh!(*b, *c, *d, *a, 2, 15);
    hh!(*a, *b, *c, *d, 6, 3);
    hh!(*d, *a, *b, *c, 1, 9);
    hh!(*c, *d, *a, *b, 3, 11);
    hh!(*b, *c, *d, *a, 5, 15);
}

/// TEA (Tiny Encryption Algorithm) transform.
///
/// Operates on 4 u32 words of input, modifying the state (a, b, c, d).
fn tea_transform(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, buf: &[u32]) {
    let get = |i: usize| -> u32 { buf.get(i).copied().unwrap_or(0) };

    let mut sum: u32 = 0;
    let delta: u32 = 0x9E37_79B9;

    // TEA uses the buf as "key" and the state as "data"
    let k0 = get(0);
    let k1 = get(1);
    let k2 = get(2);
    let k3 = get(3);

    // 16 rounds of TEA on (a, b) pair
    for _ in 0..16 {
        sum = sum.wrapping_add(delta);
        *a = a.wrapping_add(
            (b.wrapping_shl(4).wrapping_add(k0))
                ^ b.wrapping_add(sum)
                ^ (b.wrapping_shr(5).wrapping_add(k1)),
        );
        *b = b.wrapping_add(
            (a.wrapping_shl(4).wrapping_add(k2))
                ^ a.wrapping_add(sum)
                ^ (a.wrapping_shr(5).wrapping_add(k3)),
        );
    }

    // 16 rounds on (c, d) pair
    sum = 0;
    for _ in 0..16 {
        sum = sum.wrapping_add(delta);
        *c = c.wrapping_add(
            (d.wrapping_shl(4).wrapping_add(k0))
                ^ d.wrapping_add(sum)
                ^ (d.wrapping_shr(5).wrapping_add(k1)),
        );
        *d = d.wrapping_add(
            (c.wrapping_shl(4).wrapping_add(k2))
                ^ c.wrapping_add(sum)
                ^ (c.wrapping_shr(5).wrapping_add(k3)),
        );
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
    fn geometry_blocks_per_group_exceeds_bitmap() {
        let mut sb = make_valid_sb();
        // blocks_per_group = 4096*8+1 = 32769, exceeds bitmap capacity for 4K blocks
        sb[0x20..0x24].copy_from_slice(&32769_u32.to_le_bytes());
        sb[0x24..0x28].copy_from_slice(&32769_u32.to_le_bytes()); // clusters too
        let p = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        let err = p.validate_geometry().unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "s_blocks_per_group",
                    ..
                }
            ),
            "expected blocks_per_group bitmap error, got: {err}",
        );
    }

    #[test]
    fn geometry_inodes_per_group_exceeds_bitmap() {
        let mut sb = make_valid_sb();
        // inodes_per_group = 4096*8+1 = 32769
        sb[0x28..0x2C].copy_from_slice(&32769_u32.to_le_bytes());
        let p = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        let err = p.validate_geometry().unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "s_inodes_per_group",
                    ..
                }
            ),
            "expected inodes_per_group bitmap error, got: {err}",
        );
    }

    #[test]
    fn geometry_inode_size_exceeds_block_size() {
        let mut sb = make_valid_sb();
        // inode_size = 8192 (power of two, but > 4K block_size)
        sb[0x58..0x5A].copy_from_slice(&8192_u16.to_le_bytes());
        let p = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        let err = p.validate_geometry().unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "s_inode_size",
                    reason: "inode_size exceeds block_size"
                }
            ),
            "expected inode > block error, got: {err}",
        );
    }

    #[test]
    fn geometry_desc_size_too_small() {
        let mut sb = make_valid_sb();
        // desc_size = 16 (non-zero but < 32)
        sb[0xFE..0x100].copy_from_slice(&16_u16.to_le_bytes());
        let p = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        let err = p.validate_geometry().unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "s_desc_size",
                    ..
                }
            ),
            "expected desc_size error, got: {err}",
        );
    }

    #[test]
    fn geometry_desc_size_exceeds_block_size() {
        let mut sb = make_valid_sb();
        // desc_size = 8192 (> 4K block size)
        sb[0xFE..0x100].copy_from_slice(&8192_u16.to_le_bytes());
        let p = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        let err = p.validate_geometry().unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "s_desc_size",
                    ..
                }
            ),
            "expected desc_size > block error, got: {err}",
        );
    }

    #[test]
    fn geometry_64bit_needs_desc_size_64() {
        let mut sb = make_valid_sb();
        // Set 64BIT feature but leave desc_size = 0 (effective 32).
        let incompat = (Ext4IncompatFeatures::FILETYPE.0
            | Ext4IncompatFeatures::EXTENTS.0
            | Ext4IncompatFeatures::BIT64.0)
            .to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);
        let p = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        let err = p.validate_geometry().unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "s_desc_size",
                    reason: "64BIT feature set but desc_size < 64"
                }
            ),
            "expected 64bit/desc_size mismatch, got: {err}",
        );
    }

    #[test]
    fn geometry_64bit_with_desc_size_64_ok() {
        let mut sb = make_valid_sb();
        let incompat = (Ext4IncompatFeatures::FILETYPE.0
            | Ext4IncompatFeatures::EXTENTS.0
            | Ext4IncompatFeatures::BIT64.0)
            .to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);
        sb[0xFE..0x100].copy_from_slice(&64_u16.to_le_bytes());
        let p = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        assert!(p.validate_geometry().is_ok());
    }

    #[test]
    fn geometry_first_data_block_1k() {
        // 1K block size requires first_data_block = 1.
        let mut sb = make_valid_sb();
        sb[0x18..0x1C].copy_from_slice(&0_u32.to_le_bytes()); // log_block_size=0 -> 1K
        sb[0x1C..0x20].copy_from_slice(&0_u32.to_le_bytes()); // log_cluster_size=0
        sb[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes()); // first_data_block = 0 (wrong)
        // Adjust blocks_per_group and inodes_per_group for 1K blocks.
        // 1K * 8 = 8192 max blocks per group.
        sb[0x20..0x24].copy_from_slice(&8192_u32.to_le_bytes());
        sb[0x24..0x28].copy_from_slice(&8192_u32.to_le_bytes());
        sb[0x28..0x2C].copy_from_slice(&2048_u32.to_le_bytes()); // inodes_per_group
        sb[0x00..0x04].copy_from_slice(&2048_u32.to_le_bytes()); // inodes_count
        let p = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        let err = p.validate_geometry().unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "s_first_data_block",
                    reason: "must be 1 for 1K block size"
                }
            ),
            "expected 1K first_data_block error, got: {err}",
        );

        // Fix: first_data_block = 1 → should pass.
        sb[0x14..0x18].copy_from_slice(&1_u32.to_le_bytes());
        let p = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        assert!(p.validate_geometry().is_ok());
    }

    #[test]
    fn geometry_first_data_block_4k_must_be_zero() {
        let mut sb = make_valid_sb();
        // 4K blocks, set first_data_block = 1 (wrong for >= 2K)
        sb[0x14..0x18].copy_from_slice(&1_u32.to_le_bytes());
        let p = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        let err = p.validate_geometry().unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "s_first_data_block",
                    reason: "must be 0 for block sizes > 1K"
                }
            ),
            "expected 4K first_data_block error, got: {err}",
        );
    }

    #[test]
    fn geometry_gdt_exceeds_device() {
        let mut sb = make_valid_sb();
        // Tiny device: 4 blocks × 4K = 16K. With blocks_per_group=4,
        // groups = 4/4 = 1 group → GDT needs 32 bytes at offset 4096.
        // But give it blocks_per_group=1, so groups = 4 → GDT = 4×32 = 128 bytes.
        // GDT at block 1 (byte 4096) + 128 = 4224, device = 4*4096 = 16384 → OK.
        // Instead: make blocks_count very small (2 blocks).
        // groups = 2 / blocks_per_group... Let's keep it simpler:
        // blocks_count = 2, blocks_per_group = 1, so groups = 2.
        // GDT = 2 * 32 = 64 bytes starting at block 1 = byte 4096.
        // Device = 2 * 4096 = 8192. GDT at 4096 + 64 = 4160 < 8192 → still fits.
        // Make it tighter: blocks_count = 1. But first_data_block=0 < 1 → passes.
        // groups = 1 / 1 = 1. GDT = 32 at byte 4096. Device = 4096. 4096+32 > 4096 → FAIL!
        sb[0x04..0x08].copy_from_slice(&1_u32.to_le_bytes()); // blocks_count_lo = 1
        sb[0x20..0x24].copy_from_slice(&1_u32.to_le_bytes()); // blocks_per_group = 1
        sb[0x24..0x28].copy_from_slice(&1_u32.to_le_bytes()); // clusters_per_group
        sb[0x28..0x2C].copy_from_slice(&1_u32.to_le_bytes()); // inodes_per_group
        sb[0x00..0x04].copy_from_slice(&1_u32.to_le_bytes()); // inodes_count
        let p = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        let err = p.validate_geometry().unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "s_blocks_count",
                    reason: "group descriptor table extends beyond device"
                }
            ),
            "expected GDT overflow, got: {err}",
        );
    }

    #[test]
    fn geometry_inodes_count_exceeds_groups() {
        let mut sb = make_valid_sb();
        // 1 group (blocks_per_group=32768 >= blocks_count=32768), inodes_per_group=8192.
        // Set inodes_count > 1 * 8192 = 8193.
        sb[0x00..0x04].copy_from_slice(&8193_u32.to_le_bytes());
        let p = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        let err = p.validate_geometry().unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "s_inodes_count",
                    ..
                }
            ),
            "expected inodes > groups*ipg, got: {err}",
        );
    }

    #[test]
    fn geometry_valid_sb_passes() {
        // The default make_valid_sb should pass geometry checks.
        let sb = make_valid_sb();
        let p = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        assert!(p.validate_geometry().is_ok());
    }

    // ── Inode location math tests ───────────────────────────────────────

    #[test]
    fn locate_inode_zero_is_invalid() {
        let sb = Ext4Superblock::parse_superblock_region(&make_valid_sb()).unwrap();
        let err = sb.locate_inode(InodeNumber(0)).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "inode_number",
                    reason: "inode 0 is invalid in ext4"
                }
            ),
            "expected inode 0 error, got: {err}",
        );
    }

    #[test]
    fn locate_inode_exceeds_count() {
        let sb = Ext4Superblock::parse_superblock_region(&make_valid_sb()).unwrap();
        // make_valid_sb has inodes_count = 8192
        let err = sb.locate_inode(InodeNumber(8193)).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "inode_number",
                    reason: "inode number exceeds inodes_count"
                }
            ),
            "expected out-of-range error, got: {err}",
        );
    }

    #[test]
    fn locate_inode_first() {
        let sb = Ext4Superblock::parse_superblock_region(&make_valid_sb()).unwrap();
        let loc = sb.locate_inode(InodeNumber(1)).unwrap();
        assert_eq!(loc.group, GroupNumber(0));
        assert_eq!(loc.index, 0);
        assert_eq!(loc.offset_in_table, 0);
    }

    #[test]
    fn locate_inode_last_in_group() {
        let sb = Ext4Superblock::parse_superblock_region(&make_valid_sb()).unwrap();
        // inodes_per_group = 8192, inode_size = 256
        // Inode 8192 is the last inode in group 0.
        let loc = sb.locate_inode(InodeNumber(8192)).unwrap();
        assert_eq!(loc.group, GroupNumber(0));
        assert_eq!(loc.index, 8191);
        assert_eq!(loc.offset_in_table, u64::from(8191_u32) * 256);
    }

    #[test]
    fn locate_inode_boundary() {
        // Make a 2-group filesystem: 2 * 8192 = 16384 inodes, 2 * 32768 = 65536 blocks.
        let mut sb_buf = make_valid_sb();
        sb_buf[0x00..0x04].copy_from_slice(&16384_u32.to_le_bytes()); // inodes_count
        sb_buf[0x04..0x08].copy_from_slice(&65536_u32.to_le_bytes()); // blocks_count_lo
        let sb = Ext4Superblock::parse_superblock_region(&sb_buf).unwrap();

        // First inode of second group.
        let loc = sb.locate_inode(InodeNumber(8193)).unwrap();
        assert_eq!(loc.group, GroupNumber(1));
        assert_eq!(loc.index, 0);
        assert_eq!(loc.offset_in_table, 0);

        // Last valid inode.
        let loc = sb.locate_inode(InodeNumber(16384)).unwrap();
        assert_eq!(loc.group, GroupNumber(1));
        assert_eq!(loc.index, 8191);
    }

    #[test]
    fn inode_device_offset_basic() {
        let sb = Ext4Superblock::parse_superblock_region(&make_valid_sb()).unwrap();
        let loc = sb.locate_inode(InodeNumber(1)).unwrap();
        // Suppose inode table starts at block 100.
        let abs = sb.inode_device_offset(&loc, 100).unwrap();
        assert_eq!(abs, 100 * 4096); // block 100 * 4K
    }

    #[test]
    fn inode_device_offset_with_index() {
        let sb = Ext4Superblock::parse_superblock_region(&make_valid_sb()).unwrap();
        let loc = sb.locate_inode(InodeNumber(3)).unwrap();
        // Inode 3 → index 2, offset = 2 * 256 = 512
        assert_eq!(loc.index, 2);
        assert_eq!(loc.offset_in_table, 512);
        let abs = sb.inode_device_offset(&loc, 50).unwrap();
        assert_eq!(abs, 50 * 4096 + 512);
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

    // ── DirBlockIter tests ──────────────────────────────────────────────

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn dir_iter_basic() {
        let block_size = 4096_u32;
        let mut block = vec![0_u8; block_size as usize];

        write_dir_entry(&mut block, 0, 2, 2, b".", 12);
        write_dir_entry(&mut block, 12, 2, 2, b"..", 12);
        let remaining = block_size as u16 - 24;
        write_dir_entry(&mut block, 24, 12, 1, b"hello.txt", remaining);

        let mut iter = iter_dir_block(&block, block_size);
        let e0 = iter.next().unwrap().unwrap();
        assert!(e0.is_dot());
        assert_eq!(e0.inode, 2);

        let e1 = iter.next().unwrap().unwrap();
        assert!(e1.is_dotdot());

        let e2 = iter.next().unwrap().unwrap();
        assert_eq!(e2.name_str(), "hello.txt");
        assert_eq!(e2.inode, 12);
        assert_eq!(e2.file_type, Ext4FileType::RegFile);

        assert!(iter.next().is_none());
        assert!(iter.checksum_tail().is_none());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn dir_iter_with_checksum_tail() {
        let block_size = 4096_u32;
        let mut block = vec![0_u8; block_size as usize];

        let entry_rec_len = block_size as u16 - 12;
        write_dir_entry(&mut block, 0, 2, 2, b".", entry_rec_len);

        // Checksum tail
        let tail_off = (block_size - 12) as usize;
        block[tail_off..tail_off + 4].copy_from_slice(&0_u32.to_le_bytes());
        block[tail_off + 4..tail_off + 6].copy_from_slice(&12_u16.to_le_bytes());
        block[tail_off + 6] = 0;
        block[tail_off + 7] = EXT4_FT_DIR_CSUM;
        block[tail_off + 8..tail_off + 12].copy_from_slice(&0xCAFE_BABE_u32.to_le_bytes());

        let mut iter = iter_dir_block(&block, block_size);
        let e0 = iter.next().unwrap().unwrap();
        assert!(e0.is_dot());
        assert!(iter.next().is_none());
        assert_eq!(iter.checksum_tail().unwrap().checksum, 0xCAFE_BABE);
    }

    #[test]
    fn dir_iter_empty_block() {
        // All-zero block: every entry has inode=0, rec_len=0 → rec_len < 8 error
        let block = vec![0_u8; 4096];
        let mut iter = iter_dir_block(&block, 4096);
        let result = iter.next().unwrap();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "de_rec_len",
                    ..
                }
            ),
            "expected rec_len error, got {err:?}",
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn dir_iter_rec_len_zero() {
        let mut block = vec![0_u8; 1024];
        // Entry with inode=5 but rec_len=0
        block[0..4].copy_from_slice(&5_u32.to_le_bytes());
        block[4..6].copy_from_slice(&0_u16.to_le_bytes());
        block[6] = 1;
        block[7] = 1;
        block[8] = b'x';

        let mut iter = iter_dir_block(&block, 1024);
        let result = iter.next().unwrap();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "de_rec_len",
                    reason,
                } if reason.contains("< 8")
            ),
            "expected rec_len < 8 error, got {err:?}",
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn dir_iter_rec_len_overflow() {
        let block_size = 1024_u32;
        let mut block = vec![0_u8; block_size as usize];

        block[0..4].copy_from_slice(&5_u32.to_le_bytes());
        block[4..6].copy_from_slice(&2048_u16.to_le_bytes());
        block[6] = 1;
        block[7] = 1;
        block[8] = b'x';

        let mut iter = iter_dir_block(&block, block_size);
        let result = iter.next().unwrap();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "de_rec_len",
                    reason,
                } if reason.contains("past block")
            ),
            "expected past-block error, got {err:?}",
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn dir_iter_name_len_exceeds_rec_len() {
        let block_size = 1024_u32;
        let mut block = vec![0_u8; block_size as usize];

        // rec_len=12 but name_len=10 → 8 + 10 = 18 > 12
        block[0..4].copy_from_slice(&5_u32.to_le_bytes());
        block[4..6].copy_from_slice(&12_u16.to_le_bytes());
        block[6] = 10;
        block[7] = 1;

        let mut iter = iter_dir_block(&block, block_size);
        let result = iter.next().unwrap();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "de_name_len",
                    ..
                }
            ),
            "expected name_len error, got {err:?}",
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn dir_iter_skips_deleted() {
        let block_size = 1024_u32;
        let mut block = vec![0_u8; block_size as usize];

        write_dir_entry(&mut block, 0, 5, 1, b"a", 12);
        write_dir_entry(&mut block, 12, 0, 0, b"", 12);
        let remaining = block_size as u16 - 24;
        write_dir_entry(&mut block, 24, 6, 1, b"b", remaining);

        let entries: Vec<_> = iter_dir_block(&block, block_size)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, b"a");
        assert_eq!(entries[1].name, b"b");
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn dir_iter_to_owned_roundtrip() {
        let block_size = 4096_u32;
        let mut block = vec![0_u8; block_size as usize];

        let remaining = block_size as u16;
        write_dir_entry(&mut block, 0, 42, 1, b"testfile", remaining);

        let entry_ref = iter_dir_block(&block, block_size).next().unwrap().unwrap();
        let owned = entry_ref.to_owned();
        assert_eq!(owned.inode, 42);
        assert_eq!(owned.name, b"testfile");
        assert_eq!(owned.file_type, Ext4FileType::RegFile);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn dir_iter_last_entry_fills_block() {
        let block_size = 1024_u32;
        let mut block = vec![0_u8; block_size as usize];

        write_dir_entry(&mut block, 0, 11, 2, b"only_entry", block_size as u16);

        let entries: Vec<_> = iter_dir_block(&block, block_size)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, b"only_entry");
        assert_eq!(entries[0].file_type, Ext4FileType::Dir);
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

    // ── Inode type helper tests ─────────────────────────────────────────

    #[test]
    fn inode_type_helpers() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let root = reader
            .read_inode(&image, ffs_types::InodeNumber(2))
            .unwrap();
        assert!(root.is_dir());
        assert!(!root.is_regular());
        assert!(!root.is_symlink());
        assert_eq!(root.file_type_mode(), ffs_types::S_IFDIR);
        assert_eq!(root.permission_bits(), 0o755);

        let hello = reader
            .read_inode(&image, ffs_types::InodeNumber(11))
            .unwrap();
        assert!(hello.is_regular());
        assert!(!hello.is_dir());
        assert!(!hello.is_symlink());
        assert_eq!(hello.file_type_mode(), ffs_types::S_IFREG);
        assert_eq!(hello.permission_bits(), 0o644);
    }

    // ── Symlink tests ───────────────────────────────────────────────────

    /// Build a test image with symlinks added.
    ///
    /// Extends build_test_image with:
    ///   /link (inode 14): fast symlink → "hello.txt" (9 bytes, stored inline)
    ///   /longlink (inode 15): extent-mapped symlink → long target at block 50
    ///   Root dir updated with "link" and "longlink" entries.
    #[allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
    fn build_symlink_test_image() -> Vec<u8> {
        let block_size = 4096_usize;
        let image_blocks = 64;
        let mut image = vec![0_u8; block_size * image_blocks];

        // ── Superblock ──────────────────────────────────────────────────
        let sb_off = EXT4_SUPERBLOCK_OFFSET;
        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
        sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes());
        sb[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes());
        sb[0x04..0x08].copy_from_slice(&(image_blocks as u32).to_le_bytes());
        sb[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes());
        sb[0x20..0x24].copy_from_slice(&(image_blocks as u32).to_le_bytes());
        sb[0x28..0x2C].copy_from_slice(&8192_u32.to_le_bytes());
        sb[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes());
        sb[0x54..0x58].copy_from_slice(&11_u32.to_le_bytes());
        image[sb_off..sb_off + EXT4_SUPERBLOCK_SIZE].copy_from_slice(&sb);

        // ── Group descriptor ────────────────────────────────────────────
        let gdt_off = block_size;
        let mut gd = [0_u8; 32];
        gd[0x08..0x0C].copy_from_slice(&2_u32.to_le_bytes());
        image[gdt_off..gdt_off + 32].copy_from_slice(&gd);

        let itable_off = 2 * block_size;
        let inode_size = 256_usize;

        // Write an inode with extent mapping
        let write_ext_inode = |img: &mut Vec<u8>,
                               ino: u32,
                               mode: u16,
                               size: u64,
                               links: u16,
                               flags: u32,
                               extent_block: u32,
                               extent_len: u16| {
            let off = itable_off + (ino as usize - 1) * inode_size;
            img[off..off + 2].copy_from_slice(&mode.to_le_bytes());
            img[off + 0x04..off + 0x08].copy_from_slice(&(size as u32).to_le_bytes());
            img[off + 0x6C..off + 0x70].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
            img[off + 0x1A..off + 0x1C].copy_from_slice(&links.to_le_bytes());
            img[off + 0x20..off + 0x24].copy_from_slice(&flags.to_le_bytes());
            img[off + 0x64..off + 0x68].copy_from_slice(&1_u32.to_le_bytes());

            let eh = off + 0x28;
            img[eh..eh + 2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
            img[eh + 2..eh + 4].copy_from_slice(&1_u16.to_le_bytes());
            img[eh + 4..eh + 6].copy_from_slice(&4_u16.to_le_bytes());
            img[eh + 6..eh + 8].copy_from_slice(&0_u16.to_le_bytes());
            let ee = eh + 12;
            img[ee..ee + 4].copy_from_slice(&0_u32.to_le_bytes());
            img[ee + 4..ee + 6].copy_from_slice(&extent_len.to_le_bytes());
            img[ee + 6..ee + 8].copy_from_slice(&0_u16.to_le_bytes());
            img[ee + 8..ee + 12].copy_from_slice(&extent_block.to_le_bytes());
        };

        // Write a fast symlink inode (target stored in i_block area, NO extents flag)
        let write_fast_symlink = |img: &mut Vec<u8>, ino: u32, target: &[u8]| {
            let off = itable_off + (ino as usize - 1) * inode_size;
            img[off..off + 2].copy_from_slice(&0o120_777_u16.to_le_bytes()); // symlink mode
            img[off + 0x04..off + 0x08].copy_from_slice(&(target.len() as u32).to_le_bytes());
            img[off + 0x6C..off + 0x70].copy_from_slice(&0_u32.to_le_bytes()); // size_hi=0
            img[off + 0x1A..off + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
            img[off + 0x20..off + 0x24].copy_from_slice(&0_u32.to_le_bytes()); // NO extents flag
            img[off + 0x64..off + 0x68].copy_from_slice(&1_u32.to_le_bytes());
            // Write target into i_block area (offset 0x28, 60 bytes)
            let ib = off + 0x28;
            img[ib..ib + target.len()].copy_from_slice(target);
        };

        // Root dir (inode 2)
        write_ext_inode(&mut image, 2, 0o040_755, 4096, 4, 0x0008_0000, 10, 1);

        // hello.txt (inode 11)
        write_ext_inode(&mut image, 11, 0o100_644, 18, 1, 0x0008_0000, 20, 1);

        // subdir (inode 12)
        write_ext_inode(&mut image, 12, 0o040_755, 4096, 2, 0x0008_0000, 30, 1);

        // deep.txt (inode 13)
        write_ext_inode(&mut image, 13, 0o100_644, 8192, 1, 0x0008_0000, 40, 2);

        // Fast symlink (inode 14): target = "hello.txt" (9 bytes, fits in i_block)
        write_fast_symlink(&mut image, 14, b"hello.txt");

        // Extent-mapped symlink (inode 15): long target at block 50
        let long_target = b"/subdir/deep.txt";
        write_ext_inode(
            &mut image,
            15,
            0o120_777,
            long_target.len() as u64,
            1,
            0x0008_0000,
            50,
            1,
        );

        // ── Root directory data (block 10) ──────────────────────────────
        let root_blk = 10 * block_size;
        write_dir_entry(&mut image, root_blk, 2, 2, b".", 12);
        write_dir_entry(&mut image, root_blk + 12, 2, 2, b"..", 12);
        write_dir_entry(&mut image, root_blk + 24, 11, 1, b"hello.txt", 24);
        write_dir_entry(&mut image, root_blk + 48, 12, 2, b"subdir", 20);
        write_dir_entry(&mut image, root_blk + 68, 14, 7, b"link", 16);
        let remaining: u16 = 4096 - 12 - 12 - 24 - 20 - 16;
        write_dir_entry(&mut image, root_blk + 84, 15, 7, b"longlink", remaining);

        // ── File data ───────────────────────────────────────────────────
        let hello_blk = 20 * block_size;
        image[hello_blk..hello_blk + 18].copy_from_slice(b"Hello, FrankenFS!\n");

        let sub_blk = 30 * block_size;
        write_dir_entry(&mut image, sub_blk, 12, 2, b".", 12);
        write_dir_entry(&mut image, sub_blk + 12, 2, 2, b"..", 12);
        let remaining: u16 = 4096 - 12 - 12;
        write_dir_entry(&mut image, sub_blk + 24, 13, 1, b"deep.txt", remaining);

        let deep_blk = 40 * block_size;
        image[deep_blk..deep_blk + 8192].fill(b'A');

        // Long symlink target data at block 50
        let link_blk = 50 * block_size;
        image[link_blk..link_blk + long_target.len()].copy_from_slice(long_target);

        image
    }

    #[test]
    fn fast_symlink_detection_and_reading() {
        let image = build_symlink_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let link_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(14))
            .unwrap();

        assert!(link_inode.is_symlink());
        assert!(link_inode.is_fast_symlink());
        assert!(!link_inode.uses_extents());

        let target = link_inode.fast_symlink_target().unwrap();
        assert_eq!(target, b"hello.txt");

        let target_via_reader = reader.read_symlink(&image, &link_inode).unwrap();
        assert_eq!(target_via_reader, b"hello.txt");
    }

    #[test]
    fn extent_mapped_symlink_reading() {
        let image = build_symlink_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let link_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(15))
            .unwrap();

        assert!(link_inode.is_symlink());
        assert!(!link_inode.is_fast_symlink()); // has extents flag
        assert!(link_inode.uses_extents());

        let target = reader.read_symlink(&image, &link_inode).unwrap();
        assert_eq!(target, b"/subdir/deep.txt");
    }

    #[test]
    fn read_symlink_rejects_non_symlink() {
        let image = build_symlink_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let hello = reader
            .read_inode(&image, ffs_types::InodeNumber(11))
            .unwrap();
        assert!(reader.read_symlink(&image, &hello).is_err());
    }

    #[test]
    fn resolve_path_follow_through_fast_symlink() {
        let image = build_symlink_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        // /link → "hello.txt" (relative symlink, resolves to /hello.txt)
        let (ino, inode) = reader.resolve_path_follow(&image, "/link").unwrap();
        assert_eq!(ino, ffs_types::InodeNumber(11));
        assert!(inode.is_regular());
        assert_eq!(inode.size, 18);
    }

    #[test]
    fn resolve_path_follow_through_absolute_symlink() {
        let image = build_symlink_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        // /longlink → "/subdir/deep.txt" (absolute symlink)
        let (ino, inode) = reader.resolve_path_follow(&image, "/longlink").unwrap();
        assert_eq!(ino, ffs_types::InodeNumber(13));
        assert!(inode.is_regular());
        assert_eq!(inode.size, 8192);
    }

    #[test]
    fn resolve_path_follow_non_symlink_unchanged() {
        let image = build_symlink_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        let (ino, _) = reader.resolve_path_follow(&image, "/hello.txt").unwrap();
        assert_eq!(ino, ffs_types::InodeNumber(11));

        let (ino, _) = reader
            .resolve_path_follow(&image, "/subdir/deep.txt")
            .unwrap();
        assert_eq!(ino, ffs_types::InodeNumber(13));
    }

    // ── Xattr parsing tests ─────────────────────────────────────────────

    #[test]
    fn parse_xattr_entries_basic() {
        // Build a minimal xattr entry: name_index=1 (user), name="test", value="val"
        let mut data = vec![0_u8; 256];

        // Entry header (16 bytes):
        data[0] = 4; // name_len=4
        data[1] = 1; // name_index=1 (user)
        data[2..4].copy_from_slice(&128_u16.to_le_bytes()); // value_offs=128
        data[4..8].copy_from_slice(&3_u32.to_le_bytes()); // value_size=3
        data[8..12].copy_from_slice(&0_u32.to_le_bytes()); // hash (unused)
        // 12..16 reserved
        // Name: "test" at byte 16
        data[16..20].copy_from_slice(b"test");

        // Value at offset 128: "val"
        data[128..131].copy_from_slice(b"val");

        // Terminator at byte 20 (padded: 16 + 4 = 20, already 4-byte aligned)
        data[20] = 0; // name_len=0
        data[21] = 0; // name_index=0

        let entries = super::parse_xattr_entries(&data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name_index, 1);
        assert_eq!(entries[0].name, b"test");
        assert_eq!(entries[0].value, b"val");
        assert_eq!(entries[0].full_name(), "user.test");
    }

    #[test]
    fn parse_xattr_entries_multiple() {
        let mut data = vec![0_u8; 512];

        // Entry 1: security.selinux = "context"
        data[0] = 7; // name_len
        data[1] = ffs_types::EXT4_XATTR_INDEX_SECURITY;
        data[2..4].copy_from_slice(&200_u16.to_le_bytes());
        data[4..8].copy_from_slice(&7_u32.to_le_bytes());
        data[16..23].copy_from_slice(b"selinux");
        data[200..207].copy_from_slice(b"context");

        // Entry 2 at byte 24 (16 + 7 rounded up to 24): user.mime = "text"
        data[24] = 4;
        data[25] = ffs_types::EXT4_XATTR_INDEX_USER;
        data[26..28].copy_from_slice(&250_u16.to_le_bytes());
        data[28..32].copy_from_slice(&4_u32.to_le_bytes());
        data[40..44].copy_from_slice(b"mime");
        data[250..254].copy_from_slice(b"text");

        // Terminator at byte 44 (24 + 16 + 4 = 44)
        data[44] = 0;
        data[45] = 0;

        let entries = super::parse_xattr_entries(&data).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].full_name(), "security.selinux");
        assert_eq!(entries[0].value, b"context");
        assert_eq!(entries[1].full_name(), "user.mime");
        assert_eq!(entries[1].value, b"text");
    }

    #[test]
    fn parse_xattr_entries_empty() {
        // Just a terminator
        let data = [0_u8; 4];
        let entries = super::parse_xattr_entries(&data).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn xattr_ibody_magic_check() {
        let image = build_test_image();
        let reader = Ext4ImageReader::new(&image).unwrap();

        // The test image inodes don't have xattr magic, so should return empty
        let inode = reader
            .read_inode(&image, ffs_types::InodeNumber(2))
            .unwrap();
        let xattrs = reader.read_xattrs_ibody(&inode).unwrap();
        assert!(xattrs.is_empty());
    }

    #[test]
    fn parse_ibody_xattrs_with_data() {
        // Build a 256-byte inode with xattr ibody containing one attribute
        let mut buf = vec![0_u8; 256];
        // mode = regular file
        buf[0x00..0x02].copy_from_slice(&(S_IFREG | 0o644).to_le_bytes());
        // extra_isize = 32 (0x20) at offset 0x80
        buf[0x80..0x82].copy_from_slice(&32_u16.to_le_bytes());

        // The inode parser sets xattr_ibody = bytes[128 + extra_isize .. inode_size]
        // = bytes[160..256] = 96 bytes of xattr ibody region
        // First 4 bytes of ibody region: magic
        let ibody_start = 128 + 32; // = 160
        buf[ibody_start..ibody_start + 4]
            .copy_from_slice(&ffs_types::EXT4_XATTR_MAGIC.to_le_bytes());

        // Xattr entry at ibody_start + 4 (relative offset 0 in parse_xattr_entries)
        let entry_start = ibody_start + 4;
        buf[entry_start] = 4; // name_len=4
        buf[entry_start + 1] = ffs_types::EXT4_XATTR_INDEX_USER;
        buf[entry_start + 2..entry_start + 4].copy_from_slice(&80_u16.to_le_bytes()); // value_offs=80 (relative to ibody+4)
        buf[entry_start + 4..entry_start + 8].copy_from_slice(&5_u32.to_le_bytes()); // value_size=5
        buf[entry_start + 16..entry_start + 20].copy_from_slice(b"mime");

        // Value at ibody+4+80 = entry data area offset 80
        let value_off = ibody_start + 4 + 80;
        buf[value_off..value_off + 5].copy_from_slice(b"image");

        // Terminator
        buf[entry_start + 20] = 0;
        buf[entry_start + 21] = 0;

        let inode = Ext4Inode::parse_from_bytes(&buf).expect("parse inode");
        let xattrs = super::parse_ibody_xattrs(&inode).expect("parse ibody xattrs");
        assert_eq!(xattrs.len(), 1);
        assert_eq!(xattrs[0].full_name(), "user.mime");
        assert_eq!(xattrs[0].value, b"image");
    }

    #[test]
    fn parse_ibody_xattrs_no_magic() {
        // Inode with empty xattr ibody (no magic)
        let buf = [0_u8; 128];
        let inode = Ext4Inode::parse_from_bytes(&buf).expect("parse inode");
        let xattrs = super::parse_ibody_xattrs(&inode).expect("parse ibody xattrs");
        assert!(xattrs.is_empty());
    }

    #[test]
    fn parse_xattr_block_smoke() {
        let mut block = vec![0_u8; 4096];
        // 32-byte header with magic
        block[0..4].copy_from_slice(&ffs_types::EXT4_XATTR_MAGIC.to_le_bytes());

        // Entry at offset 32 (after header)
        block[32] = 3; // name_len=3
        block[33] = ffs_types::EXT4_XATTR_INDEX_SECURITY;
        block[34..36].copy_from_slice(&200_u16.to_le_bytes());
        block[36..40].copy_from_slice(&4_u32.to_le_bytes());
        block[48..51].copy_from_slice(b"cap");
        block[32 + 200..32 + 204].copy_from_slice(b"data");

        // Terminator
        // Entry header is 16 bytes + 3 name = 19, rounded to 20
        block[52] = 0;
        block[53] = 0;

        let xattrs = super::parse_xattr_block(&block).expect("parse xattr block");
        assert_eq!(xattrs.len(), 1);
        assert_eq!(xattrs[0].full_name(), "security.cap");
        assert_eq!(xattrs[0].value, b"data");
    }

    #[test]
    fn parse_xattr_block_bad_magic() {
        let block = vec![0_u8; 4096];
        let err = super::parse_xattr_block(&block).unwrap_err();
        assert!(matches!(err, ParseError::InvalidMagic { .. }));
    }

    // ── DX hash function tests ──────────────────────────────────────────

    #[test]
    fn dx_hash_legacy_basic() {
        let (h, _) = super::dx_hash_legacy(b"hello", false);
        assert_ne!(h, 0);

        // Same input produces same hash
        let (h2, _) = super::dx_hash_legacy(b"hello", false);
        assert_eq!(h, h2);

        // Different input produces different hash
        let (h3, _) = super::dx_hash_legacy(b"world", false);
        assert_ne!(h, h3);

        // Low bit should be cleared (ext4 convention)
        assert_eq!(h & 1, 0);
    }

    #[test]
    fn dx_hash_half_md4_basic() {
        let seed = [0x1234_5678, 0x9abc_def0, 0xfedc_ba98, 0x7654_3210];

        let (h, _) = super::dx_hash_half_md4(b"testfile.txt", &seed, false);
        assert_ne!(h, 0);
        assert_eq!(h & 1, 0); // low bit cleared

        // Deterministic
        let (h2, _) = super::dx_hash_half_md4(b"testfile.txt", &seed, false);
        assert_eq!(h, h2);

        // Different name gives different hash
        let (h3, _) = super::dx_hash_half_md4(b"otherfile.txt", &seed, false);
        assert_ne!(h, h3);
    }

    #[test]
    fn dx_hash_tea_basic() {
        let seed = [0xAAAA_BBBB, 0xCCCC_DDDD, 0xEEEE_FFFF, 0x1111_2222];

        let (h, _) = super::dx_hash_tea(b"example", &seed, false);
        assert_ne!(h, 0);
        assert_eq!(h & 1, 0);

        let (h2, _) = super::dx_hash_tea(b"example", &seed, false);
        assert_eq!(h, h2);
    }

    #[test]
    fn dx_hash_signed_vs_unsigned() {
        let seed = [0, 0, 0, 0];
        // Filename with high-bit bytes (like UTF-8 encoded chars)
        let name = b"\xc3\xa9"; // é in UTF-8

        let (h_signed, _) = super::dx_hash_half_md4(name, &seed, true);
        let (h_unsigned, _) = super::dx_hash_half_md4(name, &seed, false);

        // Signed vs unsigned should produce different hashes for high-bit bytes
        assert_ne!(h_signed, h_unsigned);
    }

    #[test]
    fn dx_hash_dispatcher() {
        let seed = [1, 2, 3, 4];
        let name = b"test";

        // The dispatcher should route to the correct function
        let (h_legacy, _) = super::dx_hash(0, name, &seed);
        let (h_legacy_direct, _) = super::dx_hash_legacy(name, true);
        assert_eq!(h_legacy, h_legacy_direct);

        let (h_hmd4, _) = super::dx_hash(1, name, &seed);
        let (h_hmd4_direct, _) = super::dx_hash_half_md4(name, &seed, true);
        assert_eq!(h_hmd4, h_hmd4_direct);

        let (h_tea, _) = super::dx_hash(2, name, &seed);
        let (h_tea_direct, _) = super::dx_hash_tea(name, &seed, true);
        assert_eq!(h_tea, h_tea_direct);
    }

    // ── DX root parsing tests ───────────────────────────────────────────

    #[test]
    fn parse_dx_root_basic() {
        let mut block = vec![0_u8; 4096];

        // Fake "." dir entry at 0x00 (12 bytes)
        write_dir_entry(&mut block, 0, 2, 2, b".", 12);
        // Fake ".." dir entry at 0x0C (12 bytes, but rec_len covers to 0x1C)
        write_dir_entry(&mut block, 12, 2, 2, b"..", 12);

        // DX root info at 0x18 (after ".." dir entry header)
        // Actually, the root info is at fixed offset 0x1C
        block[0x1C] = 1; // hash_version = half_md4
        block[0x1D] = 8; // info_length = 8
        block[0x1E] = 0; // indirect_levels = 0
        block[0x1F] = 0; // unused_flags

        // count/limit at 0x20
        block[0x20..0x22].copy_from_slice(&3_u16.to_le_bytes()); // count=3
        block[0x22..0x24].copy_from_slice(&100_u16.to_le_bytes()); // limit=100

        // Entry 0 (sentinel): hash=0, block=1
        block[0x24..0x28].copy_from_slice(&0_u32.to_le_bytes());
        block[0x28..0x2C].copy_from_slice(&1_u32.to_le_bytes());

        // Entry 1: hash=0x1000, block=2
        block[0x2C..0x30].copy_from_slice(&0x1000_u32.to_le_bytes());
        block[0x30..0x34].copy_from_slice(&2_u32.to_le_bytes());

        // Entry 2: hash=0x8000, block=3
        block[0x34..0x38].copy_from_slice(&0x8000_u32.to_le_bytes());
        block[0x38..0x3C].copy_from_slice(&3_u32.to_le_bytes());

        let root = parse_dx_root(&block).unwrap();
        assert_eq!(root.hash_version, 1);
        assert_eq!(root.indirect_levels, 0);
        assert_eq!(root.entries.len(), 3);
        assert_eq!(root.entries[0].hash, 0);
        assert_eq!(root.entries[0].block, 1);
        assert_eq!(root.entries[1].hash, 0x1000);
        assert_eq!(root.entries[2].hash, 0x8000);
    }

    #[test]
    fn dx_find_leaf_basic() {
        let entries = vec![
            Ext4DxEntry { hash: 0, block: 1 }, // sentinel
            Ext4DxEntry {
                hash: 0x1000,
                block: 2,
            },
            Ext4DxEntry {
                hash: 0x8000,
                block: 3,
            },
        ];

        // Hash 0x500: between sentinel(0) and entry(0x1000) → block 1
        assert_eq!(super::dx_find_leaf(&entries, 0x500), 1);

        // Hash 0x1000: exact match → block 2
        assert_eq!(super::dx_find_leaf(&entries, 0x1000), 2);

        // Hash 0x5000: between 0x1000 and 0x8000 → block 2
        assert_eq!(super::dx_find_leaf(&entries, 0x5000), 2);

        // Hash 0x8000: exact match → block 3
        assert_eq!(super::dx_find_leaf(&entries, 0x8000), 3);

        // Hash 0xFFFF: past all entries → block 3
        assert_eq!(super::dx_find_leaf(&entries, 0xFFFF), 3);

        // Hash 0: match sentinel → block 1
        assert_eq!(super::dx_find_leaf(&entries, 0), 1);
    }

    #[test]
    fn str2hashbuf_basic() {
        let buf = super::str2hashbuf(b"abc", 4, false);
        assert_eq!(buf.len(), 4);
        // "abc" packs into first word: 'a'=0x61, 'b'=0x62, 'c'=0x63
        // plus 0x80 terminator in byte 3
        let expected = 0x61_u32 | (0x62 << 8) | (0x63 << 16) | (0x80 << 24);
        assert_eq!(buf[0], expected);
        assert_eq!(buf[1], 0); // remaining words are 0
    }

    #[test]
    fn str2hashbuf_signed_chars() {
        // 0xC3 as signed i8 is -61 (0xFFFFFFC3 as u32)
        let buf_signed = super::str2hashbuf(b"\xC3", 4, true);
        let buf_unsigned = super::str2hashbuf(b"\xC3", 4, false);

        // Signed: 0xC3 sign-extended + 0x80 terminator at byte 1
        // Unsigned: 0xC3 zero-extended + 0x80 terminator at byte 1
        assert_ne!(buf_signed[0], buf_unsigned[0]);
    }

    // ── Feature flag decode + validation tests ──────────────────────────

    #[test]
    fn incompat_describe_lists_set_flags() {
        let flags = Ext4IncompatFeatures(
            Ext4IncompatFeatures::FILETYPE.0
                | Ext4IncompatFeatures::EXTENTS.0
                | Ext4IncompatFeatures::FLEX_BG.0,
        );
        let names = flags.describe();
        assert_eq!(names, vec!["FILETYPE", "EXTENTS", "FLEX_BG"]);
    }

    #[test]
    fn incompat_describe_empty_for_zero() {
        let flags = Ext4IncompatFeatures(0);
        assert!(flags.describe().is_empty());
    }

    #[test]
    fn incompat_unknown_bits_detects_unnamed() {
        let flags = Ext4IncompatFeatures(Ext4IncompatFeatures::FILETYPE.0 | (1 << 30));
        assert_eq!(flags.unknown_bits(), 1 << 30);
    }

    #[test]
    fn incompat_describe_missing_required() {
        // Only EXTENTS set, FILETYPE missing.
        let flags = Ext4IncompatFeatures(Ext4IncompatFeatures::EXTENTS.0);
        let missing = flags.describe_missing_required_v1();
        assert_eq!(missing, vec!["FILETYPE"]);
    }

    #[test]
    fn incompat_describe_rejected_v1() {
        let flags = Ext4IncompatFeatures(
            Ext4IncompatFeatures::FILETYPE.0
                | Ext4IncompatFeatures::EXTENTS.0
                | Ext4IncompatFeatures::ENCRYPT.0,
        );
        let rejected = flags.describe_rejected_v1();
        assert_eq!(rejected, vec!["ENCRYPT"]);
    }

    #[test]
    fn compat_display_format() {
        let flags =
            Ext4CompatFeatures(Ext4CompatFeatures::HAS_JOURNAL.0 | Ext4CompatFeatures::DIR_INDEX.0);
        assert_eq!(format!("{flags}"), "HAS_JOURNAL|DIR_INDEX");
    }

    #[test]
    fn incompat_display_with_unknown_bits() {
        let flags = Ext4IncompatFeatures(Ext4IncompatFeatures::FILETYPE.0 | (1 << 28));
        assert_eq!(format!("{flags}"), "FILETYPE|0x10000000");
    }

    #[test]
    fn ro_compat_describe_all_known() {
        let flags = Ext4RoCompatFeatures(
            Ext4RoCompatFeatures::SPARSE_SUPER.0
                | Ext4RoCompatFeatures::HUGE_FILE.0
                | Ext4RoCompatFeatures::METADATA_CSUM.0,
        );
        let names = flags.describe();
        assert_eq!(names, vec!["SPARSE_SUPER", "HUGE_FILE", "METADATA_CSUM"]);
    }

    #[test]
    fn display_none_for_zero_flags() {
        let flags = Ext4IncompatFeatures(0);
        assert_eq!(format!("{flags}"), "(none)");
    }

    #[test]
    fn feature_diagnostics_ok_for_valid_image() {
        let mut sb = make_valid_sb();
        let incompat =
            (Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0).to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);

        let parsed = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        let diag = parsed.feature_diagnostics_v1();
        assert!(diag.is_ok());
        assert!(diag.missing_required.is_empty());
        assert!(diag.rejected_present.is_empty());
        assert_eq!(diag.unknown_incompat_bits, 0);
    }

    #[test]
    fn feature_diagnostics_detects_missing_and_rejected() {
        let mut sb = make_valid_sb();
        // Only EXTENTS (missing FILETYPE) + ENCRYPT (rejected).
        let incompat =
            (Ext4IncompatFeatures::EXTENTS.0 | Ext4IncompatFeatures::ENCRYPT.0).to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);

        let parsed = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        let diag = parsed.feature_diagnostics_v1();
        assert!(!diag.is_ok());
        assert_eq!(diag.missing_required, vec!["FILETYPE"]);
        assert_eq!(diag.rejected_present, vec!["ENCRYPT"]);
    }

    #[test]
    fn feature_diagnostics_display_is_informative() {
        let mut sb = make_valid_sb();
        let incompat =
            (Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0).to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);

        let parsed = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        let diag = parsed.feature_diagnostics_v1();
        let display = format!("{diag}");
        assert!(display.contains("FILETYPE"));
        assert!(display.contains("EXTENTS"));
    }

    #[test]
    fn validate_v1_rejects_encrypt_with_actionable_reason() {
        let mut sb = make_valid_sb();
        let incompat = (Ext4IncompatFeatures::FILETYPE.0
            | Ext4IncompatFeatures::EXTENTS.0
            | Ext4IncompatFeatures::ENCRYPT.0)
            .to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);

        let parsed = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        let err = parsed.validate_v1().unwrap_err();
        // Verify the error reason names the rejected features.
        let reason = format!("{err}");
        assert!(
            reason.contains("ENCRYPT") || reason.contains("unsupported"),
            "expected actionable error, got: {reason}",
        );
    }

    // ── Inode parsing edge-case tests ───────────────────────────────────

    /// Build a minimal 128-byte inode buffer (no extended area).
    fn make_inode_128() -> [u8; 128] {
        let mut buf = [0_u8; 128];
        // mode = 0o100644 (regular file)
        buf[0x00..0x02].copy_from_slice(&0o100_644_u16.to_le_bytes());
        // uid_lo = 1000
        buf[0x02..0x04].copy_from_slice(&1000_u16.to_le_bytes());
        // size_lo = 42
        buf[0x04..0x08].copy_from_slice(&42_u32.to_le_bytes());
        // atime = 1_700_000_000 (2023-11-14)
        buf[0x08..0x0C].copy_from_slice(&1_700_000_000_u32.to_le_bytes());
        // ctime = 1_700_000_001
        buf[0x0C..0x10].copy_from_slice(&1_700_000_001_u32.to_le_bytes());
        // mtime = 1_700_000_002
        buf[0x10..0x14].copy_from_slice(&1_700_000_002_u32.to_le_bytes());
        // gid_lo = 1000
        buf[0x18..0x1A].copy_from_slice(&1000_u16.to_le_bytes());
        // links_count = 1
        buf[0x1A..0x1C].copy_from_slice(&1_u16.to_le_bytes());
        // blocks_lo = 8
        buf[0x1C..0x20].copy_from_slice(&8_u32.to_le_bytes());
        // flags = EXTENTS
        buf[0x20..0x24].copy_from_slice(&EXT4_EXTENTS_FL.to_le_bytes());
        // generation = 7
        buf[0x64..0x68].copy_from_slice(&7_u32.to_le_bytes());
        buf
    }

    #[test]
    fn inode_parse_128_byte_base() {
        let buf = make_inode_128();
        let inode = Ext4Inode::parse_from_bytes(&buf).unwrap();
        assert_eq!(inode.mode, 0o100_644);
        assert_eq!(inode.uid, 1000);
        assert_eq!(inode.gid, 1000);
        assert_eq!(inode.size, 42);
        assert_eq!(inode.links_count, 1);
        assert_eq!(inode.blocks, 8);
        assert_eq!(inode.generation, 7);
        assert!(inode.is_regular());
        assert!(!inode.is_dir());
        assert_eq!(inode.permission_bits(), 0o644);
    }

    #[test]
    fn inode_parse_insufficient_data() {
        // Less than 128 bytes should produce InsufficientData.
        let buf = [0_u8; 64];
        let err = Ext4Inode::parse_from_bytes(&buf).unwrap_err();
        assert!(
            matches!(err, ParseError::InsufficientData { .. }),
            "expected InsufficientData, got {err:?}",
        );
    }

    #[test]
    fn inode_parse_empty_slice() {
        let err = Ext4Inode::parse_from_bytes(&[]).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn inode_128_byte_has_zero_extra_fields() {
        let buf = make_inode_128();
        let inode = Ext4Inode::parse_from_bytes(&buf).unwrap();
        // No extended area: extra fields should be zero.
        assert_eq!(inode.extra_isize, 0);
        assert_eq!(inode.atime_extra, 0);
        assert_eq!(inode.ctime_extra, 0);
        assert_eq!(inode.mtime_extra, 0);
        assert_eq!(inode.crtime, 0);
        assert_eq!(inode.crtime_extra, 0);
        assert_eq!(inode.projid, 0);
    }

    #[test]
    fn inode_256_byte_with_extended_timestamps() {
        let mut buf = [0_u8; 256];
        buf[..128].copy_from_slice(&make_inode_128());
        // extra_isize = 32 (standard for modern ext4)
        buf[0x80..0x82].copy_from_slice(&32_u16.to_le_bytes());
        // ctime_extra: epoch=0, nsec=500_000_000 (0.5s) -> (500_000_000 << 2) | 0
        let ctime_extra = 500_000_000_u32 << 2;
        buf[0x84..0x88].copy_from_slice(&ctime_extra.to_le_bytes());
        // mtime_extra: epoch=0, nsec=250_000_000
        let mtime_extra = 250_000_000_u32 << 2;
        buf[0x88..0x8C].copy_from_slice(&mtime_extra.to_le_bytes());
        // atime_extra: epoch=0, nsec=100_000_000
        let atime_extra = 100_000_000_u32 << 2;
        buf[0x8C..0x90].copy_from_slice(&atime_extra.to_le_bytes());
        // crtime = 1_600_000_000
        buf[0x90..0x94].copy_from_slice(&1_600_000_000_u32.to_le_bytes());

        let inode = Ext4Inode::parse_from_bytes(&buf).unwrap();
        assert_eq!(inode.extra_isize, 32);

        // Verify full timestamps.
        let atime = inode.atime_full();
        assert_eq!(atime.0, 1_700_000_000);
        assert_eq!(atime.1, 100_000_000);

        let mtime = inode.mtime_full();
        assert_eq!(mtime.0, 1_700_000_002);
        assert_eq!(mtime.1, 250_000_000);

        let ctime = inode.ctime_full();
        assert_eq!(ctime.0, 1_700_000_001);
        assert_eq!(ctime.1, 500_000_000);
    }

    #[test]
    fn inode_system_time_conversion() {
        use std::time::{Duration, UNIX_EPOCH};

        // Positive timestamp.
        let st = Ext4Inode::to_system_time(1_700_000_000, 500_000_000).unwrap();
        let expected = UNIX_EPOCH + Duration::new(1_700_000_000, 500_000_000);
        assert_eq!(st, expected);

        // Zero timestamp.
        let st = Ext4Inode::to_system_time(0, 0).unwrap();
        assert_eq!(st, UNIX_EPOCH);
    }

    #[test]
    fn inode_system_time_convenience_methods() {
        let mut buf = [0_u8; 256];
        buf[..128].copy_from_slice(&make_inode_128());
        buf[0x80..0x82].copy_from_slice(&32_u16.to_le_bytes());

        let inode = Ext4Inode::parse_from_bytes(&buf).unwrap();
        // atime_system_time should produce a valid time (no extra → no nanoseconds).
        let st = inode.atime_system_time();
        let epoch_secs = st.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(epoch_secs, 1_700_000_000);
    }

    #[test]
    fn inode_uid_gid_high_bits() {
        let mut buf = [0_u8; 256];
        buf[..128].copy_from_slice(&make_inode_128());
        // Set uid_hi = 1 (at offset 0x78 in Linux osd2)
        buf[0x78..0x7A].copy_from_slice(&1_u16.to_le_bytes());
        // Set gid_hi = 2 (at offset 0x7A)
        buf[0x7A..0x7C].copy_from_slice(&2_u16.to_le_bytes());

        let inode = Ext4Inode::parse_from_bytes(&buf).unwrap();
        assert_eq!(inode.uid, (1_u32 << 16) | 0x03e8);
        assert_eq!(inode.gid, (2_u32 << 16) | 0x03e8);
    }

    #[test]
    fn inode_file_type_detection() {
        let mut buf = make_inode_128();
        // directory
        buf[0x00..0x02].copy_from_slice(&(S_IFDIR | 0o755).to_le_bytes());
        let inode = Ext4Inode::parse_from_bytes(&buf).unwrap();
        assert!(inode.is_dir());
        assert!(!inode.is_regular());
        assert_eq!(inode.permission_bits(), 0o755);

        // symlink
        buf[0x00..0x02].copy_from_slice(&(S_IFLNK | 0o777).to_le_bytes());
        let inode = Ext4Inode::parse_from_bytes(&buf).unwrap();
        assert!(inode.is_symlink());

        // block device
        buf[0x00..0x02].copy_from_slice(&(S_IFBLK | 0o660).to_le_bytes());
        let inode = Ext4Inode::parse_from_bytes(&buf).unwrap();
        assert!(inode.is_blkdev());

        // char device
        buf[0x00..0x02].copy_from_slice(&(S_IFCHR | 0o666).to_le_bytes());
        let inode = Ext4Inode::parse_from_bytes(&buf).unwrap();
        assert!(inode.is_chrdev());

        // FIFO
        buf[0x00..0x02].copy_from_slice(&(S_IFIFO | 0o644).to_le_bytes());
        let inode = Ext4Inode::parse_from_bytes(&buf).unwrap();
        assert!(inode.is_fifo());

        // socket
        buf[0x00..0x02].copy_from_slice(&(S_IFSOCK | 0o755).to_le_bytes());
        let inode = Ext4Inode::parse_from_bytes(&buf).unwrap();
        assert!(inode.is_socket());
    }

    #[test]
    fn inode_extent_bytes_available() {
        let buf = make_inode_128();
        let inode = Ext4Inode::parse_from_bytes(&buf).unwrap();
        // 60 bytes of i_block area should be present.
        assert_eq!(inode.extent_bytes.len(), 60);
    }

    // ── Directory block checksum verification ────────────────────────────

    #[test]
    fn dir_block_checksum_round_trip() {
        let csum_seed = 0xDEAD_BEEF_u32;
        let ino: u32 = 2;
        let generation: u32 = 42;
        let block_size = 4096_usize;

        // Build a synthetic dir block: one entry + checksum tail
        let mut block = vec![0_u8; block_size];
        // Write a single dir entry "." spanning block minus 12 bytes for tail
        let entry_rec_len = u16::try_from(block_size - 12).unwrap();
        write_dir_entry(&mut block, 0, 2, 2, b".", entry_rec_len);

        // Write checksum tail sentinel at block_size - 12
        let tail_off = block_size - 12;
        block[tail_off..tail_off + 4].copy_from_slice(&0_u32.to_le_bytes()); // inode=0
        block[tail_off + 4..tail_off + 6].copy_from_slice(&12_u16.to_le_bytes());
        block[tail_off + 6] = 0; // name_len=0
        block[tail_off + 7] = EXT4_FT_DIR_CSUM; // 0xDE

        // Compute expected checksum: coverage excludes the entire 12-byte tail
        let seed = crc32c::crc32c_append(csum_seed, &ino.to_le_bytes());
        let seed = crc32c::crc32c_append(seed, &generation.to_le_bytes());
        let checksum = crc32c::crc32c_append(seed, &block[..block_size - 12]);

        // Store checksum in tail (last 4 bytes)
        block[block_size - 4..].copy_from_slice(&checksum.to_le_bytes());

        // Verify: should pass
        verify_dir_block_checksum(&block, csum_seed, ino, generation)
            .expect("valid dir block checksum");

        // Corrupt one byte in the block → should fail
        block[10] ^= 0xFF;
        assert!(verify_dir_block_checksum(&block, csum_seed, ino, generation).is_err());
    }

    #[test]
    fn dir_block_checksum_rejects_too_small() {
        let small = [0_u8; 8];
        let err = verify_dir_block_checksum(&small, 0, 1, 1).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    // ── Extent block checksum verification ───────────────────────────────

    #[test]
    fn extent_block_checksum_round_trip() {
        let csum_seed = 0xCAFE_BABE_u32;
        let ino: u32 = 11;
        let generation: u32 = 7;
        let block_size = 4096_usize;

        // Build a synthetic extent block
        let mut block = vec![0_u8; block_size];
        // Write an extent header at offset 0
        block[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes()); // magic
        block[2..4].copy_from_slice(&0_u16.to_le_bytes()); // entries=0
        block[4..6].copy_from_slice(&4_u16.to_le_bytes()); // max=4
        block[6..8].copy_from_slice(&0_u16.to_le_bytes()); // depth=0
        block[8..12].copy_from_slice(&0_u32.to_le_bytes()); // generation

        // Compute checksum: tail is at 12 + 12 * eh_max = 12 + 12 * 4 = 60
        let eh_max = 4_usize;
        let tail_off = 12 + 12 * eh_max;
        let seed = crc32c::crc32c_append(csum_seed, &ino.to_le_bytes());
        let seed = crc32c::crc32c_append(seed, &generation.to_le_bytes());
        let checksum = crc32c::crc32c_append(seed, &block[..tail_off]);

        // Store at tail (right after the extent entry slots)
        block[tail_off..tail_off + 4].copy_from_slice(&checksum.to_le_bytes());

        // Verify: should pass
        verify_extent_block_checksum(&block, csum_seed, ino, generation)
            .expect("valid extent block checksum");

        // Corrupt → should fail
        block[5] ^= 0x01;
        assert!(verify_extent_block_checksum(&block, csum_seed, ino, generation).is_err());
    }

    #[test]
    fn extent_block_checksum_rejects_too_small() {
        let small = [0_u8; 12];
        let err = verify_extent_block_checksum(&small, 0, 1, 1).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    // ── Device number tests ──────────────────────────────────────────

    /// Build a minimal 128-byte block device inode with i_block device encoding.
    fn make_device_inode(mode: u16, block0: u32, block1: u32) -> Ext4Inode {
        let mut buf = [0_u8; 128];
        // mode at offset 0x00
        buf[0x00..0x02].copy_from_slice(&mode.to_le_bytes());
        // i_block area at 0x28 (60 bytes)
        buf[0x28..0x2C].copy_from_slice(&block0.to_le_bytes());
        buf[0x2C..0x30].copy_from_slice(&block1.to_le_bytes());
        Ext4Inode::parse_from_bytes(&buf).expect("device inode parse")
    }

    #[test]
    fn device_number_old_format_block_device() {
        // Old format: major=8, minor=0 → /dev/sda = 0x0800
        let inode = make_device_inode(S_IFBLK | 0o660, 0x0800, 0);
        assert!(inode.is_blkdev());
        assert_eq!(inode.device_number(), 0x0800);
        assert_eq!(inode.device_major(), 8);
        assert_eq!(inode.device_minor(), 0);
    }

    #[test]
    fn device_number_old_format_char_device() {
        // Old format: major=1, minor=3 → /dev/null = 0x0103
        let inode = make_device_inode(S_IFCHR | 0o666, 0x0103, 0);
        assert!(inode.is_chrdev());
        assert_eq!(inode.device_number(), 0x0103);
        assert_eq!(inode.device_major(), 1);
        assert_eq!(inode.device_minor(), 3);
    }

    #[test]
    fn device_number_new_format() {
        // New format in i_block[1]: major=8, minor=1 → /dev/sda1
        // new_encode_dev: (minor & 0xFF) | (major << 8) | ((minor & ~0xFF) << 12)
        // = (1 & 0xFF) | (8 << 8) | 0 = 0x0801
        let inode = make_device_inode(S_IFBLK | 0o660, 0, 0x0801);
        assert!(inode.is_blkdev());
        assert_eq!(inode.device_number(), 0x0801);
        assert_eq!(inode.device_major(), 8);
        assert_eq!(inode.device_minor(), 1);
    }

    #[test]
    fn device_number_new_format_large_minor() {
        // New format with large minor: major=8, minor=256
        // new_encode_dev: (256 & 0xFF) | (8 << 8) | ((256 & ~0xFF) << 12)
        // = 0 | 0x0800 | (0x100 << 12) = 0x0800 | 0x100000 = 0x100800
        let inode = make_device_inode(S_IFBLK | 0o660, 0, 0x10_0800);
        assert!(inode.is_blkdev());
        assert_eq!(inode.device_number(), 0x10_0800);
        assert_eq!(inode.device_major(), 8);
        assert_eq!(inode.device_minor(), 256);
    }

    #[test]
    fn device_number_returns_zero_for_regular_file() {
        let inode = make_device_inode(S_IFREG | 0o644, 0x0800, 0);
        assert!(inode.is_regular());
        assert_eq!(inode.device_number(), 0);
        assert_eq!(inode.device_major(), 0);
        assert_eq!(inode.device_minor(), 0);
    }

    #[test]
    fn device_number_returns_zero_for_directory() {
        let inode = make_device_inode(S_IFDIR | 0o755, 0, 0);
        assert!(inode.is_dir());
        assert_eq!(inode.device_number(), 0);
    }
}
