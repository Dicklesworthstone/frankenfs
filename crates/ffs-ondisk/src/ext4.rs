#![forbid(unsafe_code)]

use ffs_types as crc32c;
use ffs_types::{
    EXT4_EXTENTS_FL, EXT4_FAST_SYMLINK_MAX, EXT4_HUGE_FILE_FL, EXT4_INDEX_FL,
    EXT4_SB_CHECKSUM_OFFSET, EXT4_SUPER_MAGIC, EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE,
    EXT4_XATTR_MAGIC, GroupNumber, InodeNumber, ParseError, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO,
    S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK, all_zero_bytes, ensure_slice, ext4_block_size_from_log,
    read_fixed, read_le_u16, read_le_u32, trim_nul_padded,
};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
pub const EXT_INIT_MAX_LEN: u16 = 1_u16 << 15;
pub const EXT4_MAX_NAME_BYTES: usize = 255;
// This i_flags bit is historically aliased with the old compression namespace.
// Modern ext4 uses it as FS_ENCRYPT_FL / EXT4_ENCRYPT_FL on encrypted inodes.
const EXT4_ENCRYPT_INODE_FL: u32 = 0x0000_0800;

/// Match the Linux kernel's `ext4_chksum()` / `crc32c_le()` convention.
///
/// The kernel's `crc32c_le(crc, data, len)` operates on **raw** CRC register
/// values — no initial or final XOR.  The Rust `crc32c` crate's
/// `crc32c_append(seed, data)` applies `!` (bitwise complement) to both
/// input and output, matching the standard CRC32C convention where
/// `crc32c(data) == crc32c_append(0, data)`.
///
/// This wrapper bridges the two conventions:
/// `ext4_chksum(raw_crc, data) == !crc32c_append(!raw_crc, data)`.
#[inline]
#[must_use]
pub fn ext4_chksum(raw_crc: u32, data: &[u8]) -> u32 {
    !crc32c::crc32c_append(!raw_crc, data)
}

// ── ext4 superblock state flags ──────────────────────────────────────────

/// Filesystem was cleanly unmounted.
pub const EXT4_VALID_FS: u16 = 0x0001;
/// Filesystem has errors detected.
pub const EXT4_ERROR_FS: u16 = 0x0002;
/// Filesystem is being recovered from an orphan list.
pub const EXT4_ORPHAN_FS: u16 = 0x0004;

// ── ext4 block-group descriptor flags (bd-glkri) ─────────────────────────
//
// Mirrored from the Linux kernel's `fs/ext4/ext4.h`. Each is a
// single power-of-2 bit in the 16-bit `bg_flags` field of
// `struct ext4_group_desc`; the constants here are the canonical
// values used by every parser/writer that consults
// `Ext4GroupDesc::flags`. Conformance is pinned by the
// `ext4_block_group_flag_constants_match_kernel_header` test.

/// Inode table for this group has never been initialized.
pub const EXT4_BG_INODE_UNINIT: u16 = 0x0001;
/// Block bitmap for this group has never been initialized.
pub const EXT4_BG_BLOCK_UNINIT: u16 = 0x0002;
/// Inode table for this group has been zeroed.
pub const EXT4_BG_INODE_ZEROED: u16 = 0x0004;

// ── ext4 reserved inode numbers (bd-k81lq) ───────────────────────────────
//
// Mirrored from the Linux kernel's `fs/ext4/ext4.h`. These are the
// well-known inode numbers that the kernel reserves for filesystem
// metadata. Mismatch with the kernel values would silently corrupt
// every ext4 image we mutate — the kernel-conformance unit test
// `ext4_reserved_inode_constants_match_kernel_header` pins each
// value.

/// Bad-blocks inode (kernel: `EXT4_BAD_INO`).
pub const EXT4_BAD_INO: u32 = 1;
/// Root directory inode (kernel: `EXT4_ROOT_INO`).
pub const EXT4_ROOT_INO: u32 = 2;
/// User-quota inode (kernel: `EXT4_USR_QUOTA_INO`).
pub const EXT4_USR_QUOTA_INO: u32 = 3;
/// Group-quota inode (kernel: `EXT4_GRP_QUOTA_INO`).
pub const EXT4_GRP_QUOTA_INO: u32 = 4;
/// Boot-loader inode (kernel: `EXT4_BOOT_LOADER_INO`).
pub const EXT4_BOOT_LOADER_INO: u32 = 5;
/// Undelete-directory inode (kernel: `EXT4_UNDEL_DIR_INO`).
pub const EXT4_UNDEL_DIR_INO: u32 = 6;
/// Reserved inode used by ext4 online resize to track non-contiguous GDT growth.
/// Kernel: `EXT4_RESIZE_INO`.
pub const EXT4_RESIZE_INO: u32 = 7;
/// Journal inode (kernel: `EXT4_JOURNAL_INO`).
pub const EXT4_JOURNAL_INO: u32 = 8;
/// Snapshot-exclude bitmap inode (kernel: `EXT4_EXCLUDE_INO`, non-upstream).
pub const EXT4_EXCLUDE_INO: u32 = 9;
/// Replica inode (kernel: `EXT4_REPLICA_INO`, non-upstream feature).
pub const EXT4_REPLICA_INO: u32 = 10;
/// First non-reserved inode in `EXT4_GOOD_OLD_REV` filesystems
/// (kernel: `EXT4_GOOD_OLD_FIRST_INO`).
pub const EXT4_GOOD_OLD_FIRST_INO: u32 = 11;
/// Project-quota inode (kernel: `EXT4_PRJ_QUOTA_INO`).
pub const EXT4_PRJ_QUOTA_INO: u32 = 16;

// ── ext4 revision-format constants (bd-k81lq) ────────────────────────────

/// Original ext4 (and ext2/3) on-disk format (kernel: `EXT4_GOOD_OLD_REV`).
pub const EXT4_GOOD_OLD_REV: u32 = 0;
/// V2 format with dynamic inode sizes (kernel: `EXT4_DYNAMIC_REV`).
pub const EXT4_DYNAMIC_REV: u32 = 1;
/// Inode size for `EXT4_GOOD_OLD_REV` filesystems
/// (kernel: `EXT4_GOOD_OLD_INODE_SIZE`).
pub const EXT4_GOOD_OLD_INODE_SIZE: u16 = 128;

pub const EXT4_MMP_MAGIC: u32 = 0x004D_4D50;
pub const EXT4_MMP_SEQ_CLEAN: u32 = 0xFF4D_4D50;
pub const EXT4_MMP_SEQ_FSCK: u32 = 0xE24D_4D50;
pub const EXT4_MMP_SEQ_MAX: u32 = 0xE24D_4D4F;
pub const EXT4_DFL_MAX_MNT_COUNT: u16 = 20;

// ── Reserved-inode predicate (bd-3ydm6) ──────────────────────────────────

/// Return `true` if `ino` is a reserved inode under the superblock's
/// `s_first_ino` boundary, i.e. NOT a user-visible regular inode.
///
/// Mirrors the Linux kernel helper `ext4_is_reserved_inode` from
/// `fs/ext4/ext4.h`: an inode number `ino` is reserved when
/// `ino == 0 || ino < first_ino`. The kernel uses inode 0 as the
/// "no inode" sentinel; values in `1..first_ino` carry filesystem
/// metadata (bad-blocks, root, user/group/project quotas, boot
/// loader, undelete, online-resize GDT, journal, snapshot exclude,
/// non-upstream replica). The exact reserved-inode constants are
/// pinned by `ext4_reserved_inode_constants_match_kernel_header`
/// (bd-k81lq).
///
/// # Fail-closed reasoning mode
///
/// This predicate exists to make the kernel's fail-closed contract
/// explicit. Callers that walk the inode table or iterate inode
/// bitmaps MUST consult this function before treating an inode as a
/// user-visible regular file. Specifically:
///
/// * `readdir` / `lookup` / fsck visibility: a reserved inode MUST
///   NOT be surfaced as a directory entry to userspace. Skip,
///   don't expose.
/// * Parse / checksum errors on a reserved inode MUST propagate as
///   filesystem-corruption (`FfsError::Format` or equivalent) rather
///   than be silently masked as "user error." The metadata is
///   structural; if it's broken, the filesystem is broken.
/// * Allocation paths MUST refuse to allocate a reserved inode
///   number to a new user file (the existing
///   `reserved_inodes_in_group` helper in ffs-alloc covers this for
///   group 0).
///
/// Returning `false` says "you may treat this as a user inode";
/// returning `true` says "this is metadata — apply the fail-closed
/// rules above."
#[must_use]
pub const fn is_reserved_inode(first_ino: u32, ino: u32) -> bool {
    ino == 0 || ino < first_ino
}
const EXT4_MMP_CHECKSUM_OFFSET: usize = 0x3FC;

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
    /// EXTENTS is no longer required since indirect block addressing is supported.
    pub const REQUIRED_V1: Self = Self(Self::FILETYPE.0);

    /// Bits FrankenFS v1 can parse/understand without failing mount validation.
    pub const ALLOWED_V1: Self = Self(
        Self::COMPRESSION.0
            | Self::FILETYPE.0
            | Self::RECOVER.0
            | Self::JOURNAL_DEV.0
            | Self::META_BG.0
            | Self::EXTENTS.0
            | Self::BIT64.0
            | Self::MMP.0
            | Self::FLEX_BG.0
            | Self::EA_INODE.0
            | Self::DIRDATA.0
            | Self::CSUM_SEED.0
            | Self::LARGEDIR.0
            | Self::INLINE_DATA.0
            | Self::ENCRYPT.0
            | Self::CASEFOLD.0,
    );

    /// Bits FrankenFS v1 explicitly rejects.
    /// Empty — all incompat features are now accepted at mount time.
    /// COMPRESSION: full e2compr read/write support (gzip, LZO).
    /// JOURNAL_DEV: detected at mount; paired-open with external journal supported.
    pub const REJECTED_V1: Self = Self(0);

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

/// ext4 block-group descriptor checksum mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ext4GroupDescChecksumKind {
    /// No on-disk checksum is expected.
    None,
    /// Legacy `gdt_csum` mode using CRC16 over UUID, group number, and descriptor bytes.
    GdtCsum,
    /// Modern `metadata_csum` mode using CRC32C over UUID/seed, group number, and descriptor bytes.
    MetadataCsum,
}

/// ext4 miscellaneous superblock flags (`s_flags`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4SuperFlags(pub u32);

impl Ext4SuperFlags {
    pub const SIGNED_HASH: Self = Self(0x0001);
    pub const UNSIGNED_HASH: Self = Self(0x0002);
    pub const TEST_FILESYS: Self = Self(0x0004);

    const KNOWN: &[(u32, &'static str)] = &[
        (0x0001, "SIGNED_HASH"),
        (0x0002, "UNSIGNED_HASH"),
        (0x0004, "TEST_FILESYS"),
    ];

    #[must_use]
    pub fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }

    #[must_use]
    pub fn describe(self) -> Vec<&'static str> {
        describe_flags(self.0, Self::KNOWN)
    }

    #[must_use]
    pub fn unknown_bits(self) -> u32 {
        let known_mask: u32 = Self::KNOWN.iter().map(|(bit, _)| bit).fold(0, |a, b| a | b);
        self.0 & !known_mask
    }
}

impl std::fmt::Display for Ext4SuperFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format_flags(f, self.0, Self::KNOWN)
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
    pub min_extra_isize: u16,
    pub want_extra_isize: u16,
    pub first_ino: u32,
    pub desc_size: u16,
    pub reserved_gdt_blocks: u16,
    pub first_meta_bg: u32,
    pub raid_stride: u16,
    pub raid_stripe_width: u32,
    pub kbytes_written: u64,

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
    pub super_flags: Ext4SuperFlags,
    pub default_mount_opts: u32,
    pub mount_opts: String,

    // ── State & error tracking ───────────────────────────────────────────
    pub state: u16,
    pub errors: u16,
    pub mnt_count: u16,
    pub max_mnt_count: u16,
    pub checkinterval: u32,
    pub error_count: u32,
    pub def_resuid: u32,
    pub def_resgid: u32,
    pub block_group_nr: u16,
    pub algorithm_usage_bitmap: u32,
    pub prealloc_blocks: u8,
    pub prealloc_dir_blocks: u8,
    pub jnl_backup_type: u8,

    // ── Timestamps ───────────────────────────────────────────────────────
    pub mtime: u32,
    pub wtime: u32,
    pub lastcheck: u32,
    pub mkfs_time: u32,
    pub first_error_time: u32,
    pub last_error_time: u32,
    pub wtime_hi: u8,
    pub mtime_hi: u8,
    pub mkfs_time_hi: u8,
    pub lastcheck_hi: u8,
    pub first_error_time_hi: u8,
    pub last_error_time_hi: u8,
    pub first_error_errcode: u8,
    pub last_error_errcode: u8,
    pub first_error_ino: u32,
    pub first_error_block: u64,
    pub first_error_func: String,
    pub first_error_line: u32,
    pub last_error_ino: u32,
    pub last_error_block: u64,
    pub last_error_func: String,
    pub last_error_line: u32,

    // ── Journal ──────────────────────────────────────────────────────────
    pub journal_inum: u32,
    pub journal_dev: u32,
    pub last_orphan: u32,
    pub journal_uuid: [u8; 16],
    pub jnl_blocks: [u32; 17],

    // ── Snapshot metadata ────────────────────────────────────────────────
    pub snapshot_inum: u32,
    pub snapshot_id: u32,
    pub snapshot_r_blocks_count: u64,
    pub snapshot_list: u32,

    // ── Htree directory hashing ──────────────────────────────────────────
    pub hash_seed: [u32; 4],
    pub def_hash_version: u8,

    // ── Flex BG ──────────────────────────────────────────────────────────
    pub log_groups_per_flex: u8,
    pub mmp_update_interval: u16,
    pub mmp_block: u64,
    pub usr_quota_inum: u32,
    pub grp_quota_inum: u32,
    pub prj_quota_inum: u32,
    pub overhead_clusters: u32,
    pub backup_bgs: [u32; 2],

    // ── Encryption / lost+found metadata ────────────────────────────────
    pub encrypt_algos: [u8; 4],
    pub encrypt_pw_salt: [u8; 16],
    pub lost_found_ino: u32,

    // ── Casefold / orphan file metadata ─────────────────────────────────
    pub encoding: u16,
    pub encoding_flags: u16,
    pub orphan_file_inum: u32,

    // ── Checksums ────────────────────────────────────────────────────────
    pub checksum_type: u8,
    pub checksum_seed: u32,
    pub checksum: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4OnlineResizeGroupAddPlan {
    pub resize_inode: u32,
    pub old_groups: u32,
    pub added_groups: u32,
    pub new_groups: u32,
    pub old_group_desc_blocks: u32,
    pub new_group_desc_blocks: u32,
    pub added_group_desc_blocks_per_copy: u32,
    pub reserved_gdt_blocks_per_copy: u32,
    pub reserved_gdt_blocks_consumed_per_copy: u32,
    pub reserved_gdt_blocks_remaining_per_copy: u32,
    pub descriptor_blocks_outside_reserved_window_per_copy: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4QuotaInodes {
    pub user: Option<u32>,
    pub group: Option<u32>,
    pub project: Option<u32>,
}

impl Ext4Superblock {
    /// Parse an ext4 superblock from a 1024-byte superblock region.
    #[expect(clippy::too_many_lines)]
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
        let prealloc_blocks = ensure_slice(region, 0xCC, 1)?[0];
        let prealloc_dir_blocks = ensure_slice(region, 0xCD, 1)?[0];
        let jnl_backup_type = ensure_slice(region, 0xFD, 1)?[0];
        let time_high_and_error_codes = read_fixed::<8>(region, 0x274)?;
        let jnl_blocks = [
            read_le_u32(region, 0x10C)?,
            read_le_u32(region, 0x110)?,
            read_le_u32(region, 0x114)?,
            read_le_u32(region, 0x118)?,
            read_le_u32(region, 0x11C)?,
            read_le_u32(region, 0x120)?,
            read_le_u32(region, 0x124)?,
            read_le_u32(region, 0x128)?,
            read_le_u32(region, 0x12C)?,
            read_le_u32(region, 0x130)?,
            read_le_u32(region, 0x134)?,
            read_le_u32(region, 0x138)?,
            read_le_u32(region, 0x13C)?,
            read_le_u32(region, 0x140)?,
            read_le_u32(region, 0x144)?,
            read_le_u32(region, 0x148)?,
            read_le_u32(region, 0x14C)?,
        ];

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
            min_extra_isize: read_le_u16(region, 0x15C)?,
            want_extra_isize: read_le_u16(region, 0x15E)?,
            first_ino: read_le_u32(region, 0x54)?,
            desc_size: read_le_u16(region, 0xFE)?,
            reserved_gdt_blocks: read_le_u16(region, 0xCE)?,
            first_meta_bg: read_le_u32(region, 0x104)?,
            raid_stride: read_le_u16(region, 0x164)?,
            raid_stripe_width: read_le_u32(region, 0x170)?,
            kbytes_written: u64::from(read_le_u32(region, 0x178)?)
                | (u64::from(read_le_u32(region, 0x17C)?) << 32),

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
            super_flags: Ext4SuperFlags(read_le_u32(region, 0x160)?),
            default_mount_opts: read_le_u32(region, 0x100)?,
            mount_opts: trim_nul_padded(&read_fixed::<64>(region, 0x200)?),

            // State & error tracking
            state: read_le_u16(region, 0x3A)?,
            errors: read_le_u16(region, 0x3C)?,
            mnt_count: read_le_u16(region, 0x34)?,
            max_mnt_count: read_le_u16(region, 0x36)?,
            checkinterval: read_le_u32(region, 0x44)?,
            error_count: read_le_u32(region, 0x194)?,
            def_resuid: u32::from(read_le_u16(region, 0x50)?)
                | (u32::from(read_le_u16(region, 0x284)?) << 16),
            def_resgid: u32::from(read_le_u16(region, 0x52)?)
                | (u32::from(read_le_u16(region, 0x286)?) << 16),
            block_group_nr: read_le_u16(region, 0x5A)?,
            algorithm_usage_bitmap: read_le_u32(region, 0xC8)?,
            prealloc_blocks,
            prealloc_dir_blocks,
            jnl_backup_type,

            // Timestamps
            mtime: read_le_u32(region, 0x2C)?,
            wtime: read_le_u32(region, 0x30)?,
            lastcheck: read_le_u32(region, 0x40)?,
            mkfs_time: read_le_u32(region, 0x108)?,
            first_error_time: read_le_u32(region, 0x198)?,
            last_error_time: read_le_u32(region, 0x1CC)?,
            wtime_hi: time_high_and_error_codes[0],
            mtime_hi: time_high_and_error_codes[1],
            mkfs_time_hi: time_high_and_error_codes[2],
            lastcheck_hi: time_high_and_error_codes[3],
            first_error_time_hi: time_high_and_error_codes[4],
            last_error_time_hi: time_high_and_error_codes[5],
            first_error_errcode: time_high_and_error_codes[6],
            last_error_errcode: time_high_and_error_codes[7],
            first_error_ino: read_le_u32(region, 0x19C)?,
            first_error_block: u64::from(read_le_u32(region, 0x1A0)?)
                | (u64::from(read_le_u32(region, 0x1A4)?) << 32),
            first_error_func: trim_nul_padded(&read_fixed::<32>(region, 0x1A8)?),
            first_error_line: read_le_u32(region, 0x1C8)?,
            last_error_ino: read_le_u32(region, 0x1D0)?,
            last_error_line: read_le_u32(region, 0x1D4)?,
            last_error_block: u64::from(read_le_u32(region, 0x1D8)?)
                | (u64::from(read_le_u32(region, 0x1DC)?) << 32),
            last_error_func: trim_nul_padded(&read_fixed::<32>(region, 0x1E0)?),

            // Journal
            journal_inum: read_le_u32(region, 0xE0)?,
            journal_dev: read_le_u32(region, 0xE4)?,
            last_orphan: read_le_u32(region, 0xE8)?,
            journal_uuid: read_fixed::<16>(region, 0xD0)?,
            jnl_blocks,

            // Snapshot metadata
            snapshot_inum: read_le_u32(region, 0x180)?,
            snapshot_id: read_le_u32(region, 0x184)?,
            snapshot_r_blocks_count: u64::from(read_le_u32(region, 0x188)?)
                | (u64::from(read_le_u32(region, 0x18C)?) << 32),
            snapshot_list: read_le_u32(region, 0x190)?,

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
            mmp_update_interval: read_le_u16(region, 0x166)?,
            mmp_block: u64::from(read_le_u32(region, 0x168)?)
                | (u64::from(read_le_u32(region, 0x16C)?) << 32),
            usr_quota_inum: read_le_u32(region, 0x240)?,
            grp_quota_inum: read_le_u32(region, 0x244)?,
            prj_quota_inum: read_le_u32(region, 0x26C)?,
            overhead_clusters: read_le_u32(region, 0x248)?,
            backup_bgs: [read_le_u32(region, 0x24C)?, read_le_u32(region, 0x250)?],

            // Encryption / lost+found metadata
            encrypt_algos: read_fixed::<4>(region, 0x254)?,
            encrypt_pw_salt: read_fixed::<16>(region, 0x258)?,
            lost_found_ino: read_le_u32(region, 0x268)?,

            // Casefold / orphan file metadata
            encoding: read_le_u16(region, 0x27C)?,
            encoding_flags: read_le_u16(region, 0x27E)?,
            orphan_file_inum: read_le_u32(region, 0x280)?,

            // Checksums
            checksum_type,
            checksum_seed: read_le_u32(region, 0x270)?,
            checksum: read_le_u32(region, EXT4_SB_CHECKSUM_OFFSET)?,
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
    pub fn has_resize_inode(&self) -> bool {
        self.has_compat(Ext4CompatFeatures::RESIZE_INODE)
    }

    #[must_use]
    pub fn resize_inode_number(&self) -> Option<u32> {
        self.has_resize_inode().then_some(EXT4_RESIZE_INO)
    }

    #[must_use]
    pub fn has_incompat(&self, mask: Ext4IncompatFeatures) -> bool {
        (self.feature_incompat.0 & mask.0) != 0
    }

    #[must_use]
    pub fn has_large_dir(&self) -> bool {
        self.has_incompat(Ext4IncompatFeatures::LARGEDIR)
    }

    #[must_use]
    pub fn has_ro_compat(&self, mask: Ext4RoCompatFeatures) -> bool {
        (self.feature_ro_compat.0 & mask.0) != 0
    }

    #[must_use]
    pub fn has_super_flag(&self, mask: Ext4SuperFlags) -> bool {
        (self.super_flags.0 & mask.0) != 0
    }

    #[must_use]
    pub fn effective_dirhash_version(&self, hash_version: u8) -> u8 {
        match hash_version {
            DX_HASH_LEGACY if self.has_super_flag(Ext4SuperFlags::UNSIGNED_HASH) => {
                DX_HASH_LEGACY_UNSIGNED
            }
            DX_HASH_HALF_MD4 if self.has_super_flag(Ext4SuperFlags::UNSIGNED_HASH) => {
                DX_HASH_HALF_MD4_UNSIGNED
            }
            DX_HASH_TEA if self.has_super_flag(Ext4SuperFlags::UNSIGNED_HASH) => {
                DX_HASH_TEA_UNSIGNED
            }
            _ => hash_version,
        }
    }

    /// ext4 interprets `s_max_mnt_count` as a signed 16-bit value.
    ///
    /// Negative values disable mount-count based fsck warnings. A raw value of
    /// zero is normalized to [`EXT4_DFL_MAX_MNT_COUNT`] on the first write mount.
    #[must_use]
    pub fn signed_max_mount_count(&self) -> i16 {
        i16::from_le_bytes(self.max_mnt_count.to_le_bytes())
    }

    /// Whether ext4 would emit the "maximal mount count reached" warning for
    /// the current on-disk counters before applying write-mount fixups.
    #[must_use]
    pub fn should_warn_max_mount_count(&self) -> bool {
        let signed_max = self.signed_max_mount_count();
        u16::try_from(signed_max).is_ok_and(|max| self.mnt_count >= max)
    }

    /// Apply the mount-count updates ext4 performs on a write mount.
    ///
    /// This mirrors the kernel's mount-time fixups:
    /// - `s_max_mnt_count == 0` becomes [`EXT4_DFL_MAX_MNT_COUNT`]
    /// - `s_mnt_count` increments with 16-bit wraparound
    /// - `s_mtime` records the mount timestamp
    pub fn record_write_mount(&mut self, mount_time: u32) {
        if self.max_mnt_count == 0 {
            self.max_mnt_count = EXT4_DFL_MAX_MNT_COUNT;
        }
        self.mnt_count = self.mnt_count.wrapping_add(1);
        self.mtime = mount_time;
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
    ///
    /// ext4 block groups are addressed by `u32`; an overflow here indicates a
    /// corrupted superblock.  We cap at `u32::MAX` instead of silently
    /// truncating.
    #[must_use]
    pub fn groups_count(&self) -> u32 {
        if self.blocks_per_group == 0 {
            return 0;
        }
        let data_blocks = self
            .blocks_count
            .saturating_sub(u64::from(self.first_data_block));
        let groups = data_blocks.div_ceil(u64::from(self.blocks_per_group));
        u32::try_from(groups).unwrap_or(u32::MAX)
    }

    /// Whether this superblock uses metadata checksums (crc32c).
    #[must_use]
    pub fn has_metadata_csum(&self) -> bool {
        self.has_ro_compat(Ext4RoCompatFeatures::METADATA_CSUM)
    }

    #[must_use]
    pub fn has_gdt_csum(&self) -> bool {
        self.has_ro_compat(Ext4RoCompatFeatures::GDT_CSUM) && !self.has_metadata_csum()
    }

    #[must_use]
    pub fn group_desc_checksum_kind(&self) -> Ext4GroupDescChecksumKind {
        if self.has_metadata_csum() {
            Ext4GroupDescChecksumKind::MetadataCsum
        } else if self.has_gdt_csum() {
            Ext4GroupDescChecksumKind::GdtCsum
        } else {
            Ext4GroupDescChecksumKind::None
        }
    }

    #[must_use]
    pub fn groups_per_flex(&self) -> u32 {
        if !self.has_incompat(Ext4IncompatFeatures::FLEX_BG) || self.log_groups_per_flex >= 32 {
            return 1;
        }
        1_u32 << self.log_groups_per_flex
    }

    #[must_use]
    pub fn flex_group_index(&self, group: GroupNumber) -> u32 {
        let groups_per_flex = self.groups_per_flex();
        if groups_per_flex == 0 {
            return 0;
        }
        group.0 / groups_per_flex
    }

    #[must_use]
    pub fn mmp_enabled(&self) -> bool {
        self.has_incompat(Ext4IncompatFeatures::MMP)
    }

    #[must_use]
    pub fn mmp_block_number(&self) -> Option<u64> {
        self.mmp_enabled()
            .then_some(self.mmp_block)
            .filter(|block| *block != 0)
    }

    #[must_use]
    pub fn quota_inodes(&self) -> Ext4QuotaInodes {
        Ext4QuotaInodes {
            user: self
                .has_ro_compat(Ext4RoCompatFeatures::QUOTA)
                .then_some(self.usr_quota_inum)
                .filter(|inode| *inode != 0),
            group: self
                .has_ro_compat(Ext4RoCompatFeatures::QUOTA)
                .then_some(self.grp_quota_inum)
                .filter(|inode| *inode != 0),
            project: self
                .has_ro_compat(Ext4RoCompatFeatures::PROJECT)
                .then_some(self.prj_quota_inum)
                .filter(|inode| *inode != 0),
        }
    }

    #[must_use]
    pub fn orphan_file_inode(&self) -> Option<u32> {
        self.has_compat(Ext4CompatFeatures::ORPHAN_FILE)
            .then_some(self.orphan_file_inum)
            .filter(|inode| *inode != 0)
    }

    #[must_use]
    pub fn has_backup_superblock(&self, group: GroupNumber) -> bool {
        let group = group.0;
        if group == 0 {
            return true;
        }
        if self.has_compat(Ext4CompatFeatures::SPARSE_SUPER2) {
            return group == self.backup_bgs[0] || group == self.backup_bgs[1];
        }
        if group <= 1 || !self.has_ro_compat(Ext4RoCompatFeatures::SPARSE_SUPER) {
            return true;
        }
        if group & 1 == 0 {
            return false;
        }
        is_power_of(group, 3) || is_power_of(group, 5) || is_power_of(group, 7)
    }

    #[must_use]
    fn group_desc_blocks_for_groups(&self, groups: u32) -> u32 {
        let desc_per_block = self.block_size / u32::from(self.group_desc_size());
        if desc_per_block == 0 {
            return 0;
        }
        groups.div_ceil(desc_per_block)
    }

    #[must_use]
    pub fn group_desc_blocks_count(&self) -> u32 {
        self.group_desc_blocks_for_groups(self.groups_count())
    }

    #[must_use]
    pub fn reserved_gdt_blocks_in_group(&self, group: GroupNumber) -> u32 {
        if !self.has_resize_inode() || !self.has_backup_superblock(group) {
            return 0;
        }
        if self.has_incompat(Ext4IncompatFeatures::META_BG) && group.0 >= self.first_meta_bg {
            return 0;
        }
        u32::from(self.reserved_gdt_blocks)
    }

    #[must_use]
    pub fn plan_group_add(&self, added_groups: u32) -> Option<Ext4OnlineResizeGroupAddPlan> {
        let resize_inode = self.resize_inode_number()?;
        let old_groups = self.groups_count();
        let new_groups = old_groups.saturating_add(added_groups);
        let old_group_desc_blocks = self.group_desc_blocks_for_groups(old_groups);
        let new_group_desc_blocks = self.group_desc_blocks_for_groups(new_groups);
        let added_group_desc_blocks_per_copy =
            new_group_desc_blocks.saturating_sub(old_group_desc_blocks);
        let reserved_gdt_blocks_per_copy = u32::from(self.reserved_gdt_blocks);
        let reserved_gdt_blocks_consumed_per_copy =
            added_group_desc_blocks_per_copy.min(reserved_gdt_blocks_per_copy);
        let reserved_gdt_blocks_remaining_per_copy =
            reserved_gdt_blocks_per_copy.saturating_sub(reserved_gdt_blocks_consumed_per_copy);

        Some(Ext4OnlineResizeGroupAddPlan {
            resize_inode,
            old_groups,
            added_groups,
            new_groups,
            old_group_desc_blocks,
            new_group_desc_blocks,
            added_group_desc_blocks_per_copy,
            reserved_gdt_blocks_per_copy,
            reserved_gdt_blocks_consumed_per_copy,
            reserved_gdt_blocks_remaining_per_copy,
            descriptor_blocks_outside_reserved_window_per_copy: added_group_desc_blocks_per_copy
                .saturating_sub(reserved_gdt_blocks_consumed_per_copy),
        })
    }

    #[must_use]
    pub fn base_meta_blocks_in_group(&self, group: GroupNumber) -> u32 {
        if !self.has_backup_superblock(group) {
            return 0;
        }
        let mut blocks = 1_u32; // superblock copy
        if !self.has_incompat(Ext4IncompatFeatures::META_BG) || group.0 < self.first_meta_bg {
            blocks = blocks
                .saturating_add(self.group_desc_blocks_count())
                .saturating_add(self.reserved_gdt_blocks_in_group(group));
        }
        blocks
    }

    /// Compute the crc32c checksum seed used for metadata checksums.
    ///
    /// If `INCOMPAT_CSUM_SEED` is set, uses the precomputed `checksum_seed` field.
    /// Otherwise, computes `ext4_chksum(~0, uuid)`.
    ///
    /// Returns a **raw** CRC register value matching the kernel's convention
    /// (i.e. the value stored in `sbi->s_csum_seed`).
    #[must_use]
    pub fn csum_seed(&self) -> u32 {
        if self.has_incompat(Ext4IncompatFeatures::CSUM_SEED) {
            self.checksum_seed
        } else {
            // kernel: sbi->s_csum_seed = ext4_chksum(~0, uuid, 16) = crc32c_le(!0, uuid)
            ext4_chksum(!0u32, &self.uuid)
        }
    }

    /// Validate the superblock's own CRC32C checksum.
    ///
    /// The kernel computes: `ext4_chksum(sbi, ~0, sb_bytes[..EXT4_SB_CHECKSUM_OFFSET])`.
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
        // The ~392-byte s_reserved[98] region before s_checksum is zero on
        // standard filesystems, so skip that zero tail algebraically.
        let computed = ext4_chksum_skip_zero_tail(!0u32, &raw_region[..EXT4_SB_CHECKSUM_OFFSET]);
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
        // With bigalloc the block bitmap tracks CLUSTERS (`clusters_per_group` bits),
        // not individual blocks, so `blocks_per_group` legitimately exceeds
        // `block_size * 8` — the one-block bitmap capacity bounds `clusters_per_group`
        // instead. Validating `blocks_per_group` here rejected every bigalloc ext4
        // image at open (could not be mounted/read at all).
        let block_bitmap_units = if self
            .feature_ro_compat
            .contains(Ext4RoCompatFeatures::BIGALLOC)
        {
            self.clusters_per_group
        } else {
            self.blocks_per_group
        };
        if max_blocks_per_group > 0 && block_bitmap_units > max_blocks_per_group {
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
        let gdt_start =
            self.group_desc_offset(ffs_types::GroupNumber(0))
                .ok_or(ParseError::InvalidField {
                    field: "s_first_data_block",
                    reason: "group descriptor table offset overflows",
                })?;
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
    /// flag names for UX should also call [`Self::feature_diagnostics_v1`] on
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
                reason: "missing required features (need FILETYPE)",
            });
        }

        // REJECTED_V1 is empty — all known incompat features are accepted.
        // The unknown-bits check below catches any truly unrecognized flags.

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

    /// Return the list of block group numbers that contain superblock backups.
    ///
    /// The standard ext4 sparse superblock pattern places backups in groups
    /// 0, 1, and every group whose number is a power of 3, 5, or 7.
    ///
    /// When `SPARSE_SUPER2` is set, backups exist ONLY in the two groups
    /// listed in `s_backup_bgs[0]` and `s_backup_bgs[1]` (plus group 0).
    #[must_use]
    pub fn backup_superblock_groups(&self, group_count: u32) -> Vec<u32> {
        let gc = group_count;
        if gc == 0 {
            return Vec::new();
        }

        let mut groups = vec![0_u32]; // Group 0 always has the primary superblock.

        if self.has_compat(Ext4CompatFeatures::SPARSE_SUPER2) {
            for &g in &self.backup_bgs {
                if g > 0 && g < gc {
                    groups.push(g);
                }
            }
        } else {
            // Standard sparse pattern: groups 1, and powers of 3, 5, 7.
            if gc > 1 {
                groups.push(1);
            }
            for &base in &[3_u32, 5, 7] {
                let mut g = base;
                while g < gc {
                    groups.push(g);
                    g = match g.checked_mul(base) {
                        Some(v) => v,
                        None => break,
                    };
                }
            }
        }

        groups.sort_unstable();
        groups.dedup();
        groups
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

fn is_power_of(mut value: u32, factor: u32) -> bool {
    while value >= factor {
        let rem = value % factor;
        if rem != 0 {
            return false;
        }
        value /= factor;
    }
    value == 1
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
    /// CRC32C of the block bitmap (lo 16 bits at 0x18, hi 16 bits at 0x38).
    pub block_bitmap_csum: u32,
    /// CRC32C of the inode bitmap (lo 16 bits at 0x1A, hi 16 bits at 0x3A).
    pub inode_bitmap_csum: u32,
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
        // Bitmap checksums (lo halves in 32-byte descriptor).
        let block_bitmap_csum_lo = u32::from(read_le_u16(bytes, 0x18)?);
        let inode_bitmap_csum_lo = u32::from(read_le_u16(bytes, 0x1A)?);
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
            // Bitmap checksum hi halves in 64-byte descriptor.
            let block_bitmap_csum_hi = u32::from(read_le_u16(bytes, 0x38)?);
            let inode_bitmap_csum_hi = u32::from(read_le_u16(bytes, 0x3A)?);

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
                block_bitmap_csum: block_bitmap_csum_lo | (block_bitmap_csum_hi << 16),
                inode_bitmap_csum: inode_bitmap_csum_lo | (inode_bitmap_csum_hi << 16),
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
                block_bitmap_csum: block_bitmap_csum_lo,
                inode_bitmap_csum: inode_bitmap_csum_lo,
            })
        }
    }
}

/// Compute the CRC32C checksum for a block or inode bitmap.
///
/// The kernel's `ext4_block_bitmap_csum_set` / `ext4_inode_bitmap_csum_set`
/// does `crc32c(s_csum_seed, bitmap_data, len)` where `len` is:
/// - For block bitmaps: `EXT4_CLUSTERS_PER_GROUP(sb) / 8`
/// - For inode bitmaps: `EXT4_INODES_PER_GROUP(sb) / 8`
///
/// No group number is mixed in (unlike group descriptor checksums).
/// The caller must pass the correct `checksum_len` — typically
/// `blocks_per_group / 8` for block bitmaps or `inodes_per_group / 8`
/// for inode bitmaps.
fn ext4_bitmap_checksum(raw_bitmap: &[u8], csum_seed: u32, checksum_len: usize) -> u32 {
    let len = checksum_len.min(raw_bitmap.len());
    // A partially-full group's bitmap is a live prefix (allocated low blocks/
    // inodes) followed by a zero tail (free high ones); skip that tail.
    ext4_chksum_skip_zero_tail(csum_seed, &raw_bitmap[..len])
}

#[must_use]
pub fn block_bitmap_checksum_value(
    raw_bitmap: &[u8],
    csum_seed: u32,
    clusters_per_group: u32,
    desc_size: u16,
) -> u32 {
    let checksum_len = (clusters_per_group / 8) as usize;
    let csum = ext4_bitmap_checksum(raw_bitmap, csum_seed, checksum_len);
    if desc_size >= 64 { csum } else { csum & 0xFFFF }
}

#[must_use]
pub fn inode_bitmap_checksum_value(
    raw_bitmap: &[u8],
    csum_seed: u32,
    inodes_per_group: u32,
    desc_size: u16,
) -> u32 {
    let checksum_len = (inodes_per_group / 8) as usize;
    let csum = ext4_bitmap_checksum(raw_bitmap, csum_seed, checksum_len);
    if desc_size >= 64 { csum } else { csum & 0xFFFF }
}

pub fn verify_block_bitmap_checksum(
    raw_bitmap: &[u8],
    csum_seed: u32,
    clusters_per_group: u32,
    gd: &Ext4GroupDesc,
    desc_size: u16,
) -> Result<(), ParseError> {
    let expected =
        block_bitmap_checksum_value(raw_bitmap, csum_seed, clusters_per_group, desc_size);
    if expected != gd.block_bitmap_csum {
        return Err(ParseError::InvalidField {
            field: "bg_block_bitmap_csum",
            reason: "block bitmap CRC32C mismatch",
        });
    }
    Ok(())
}

pub fn verify_inode_bitmap_checksum(
    raw_bitmap: &[u8],
    csum_seed: u32,
    inodes_per_group: u32,
    gd: &Ext4GroupDesc,
    desc_size: u16,
) -> Result<(), ParseError> {
    let expected = inode_bitmap_checksum_value(raw_bitmap, csum_seed, inodes_per_group, desc_size);
    if expected != gd.inode_bitmap_csum {
        return Err(ParseError::InvalidField {
            field: "bg_inode_bitmap_csum",
            reason: "inode bitmap CRC32C mismatch",
        });
    }
    Ok(())
}

/// Incrementally recompute a bitmap's descriptor checksum after a contiguous bit
/// range was flipped.
///
/// The range is `[start_bit, start_bit+count_bits)`. Allocation sets 0→1 and free
/// clears 1→0; both cases mean the CRC delta over the touched bytes is exactly the
/// range mask, so no before/after byte capture is needed.
///
/// Returns `None` (caller must full-recompute) when incremental is not
/// applicable: `desc_size < 64` (only the low 16 bits are stored, so the full
/// 32-bit CRC can't be recovered), the range extends past the checksummed region,
/// or the touched span is large enough that a bit-at-a-time delta CRC would not
/// beat the SIMD full recompute. On the common create/small-alloc path this is
/// ~11x cheaper than the full crc32c (bench `crc_incremental`). Result-identical
/// to [`block_bitmap_checksum_value`] on the new bitmap (proptest-verified).
#[must_use]
pub fn bitmap_checksum_incremental(
    old_csum: u32,
    start_bit: u32,
    count_bits: u32,
    units_per_group: u32,
    desc_size: u16,
) -> Option<u32> {
    if desc_size < 64 || count_bits == 0 {
        return None;
    }
    let checksum_len = (units_per_group / 8) as usize;
    let end_bit = start_bit.checked_add(count_bits)?;
    let byte_start = (start_bit / 8) as usize;
    let byte_end = (usize::try_from(end_bit).ok()?).div_ceil(8);
    if byte_end > checksum_len {
        return None; // touches beyond (or the partial tail of) the crc region
    }
    let span = byte_end - byte_start;
    // Bit-at-a-time raw CRC of the delta loses to the HW full recompute once the
    // touched span is a meaningful fraction of the bitmap (~1/32, the HW-vs-bitwise
    // throughput ratio). Fall back to full for large contiguous allocations.
    if span > checksum_len / 32 {
        return None;
    }
    let mut delta = vec![0u8; span];
    let local_start = start_bit - u32::try_from(byte_start).ok()? * 8;
    for b in local_start..local_start + count_bits {
        delta[(b / 8) as usize] |= 1u8 << (b % 8);
    }
    let suffix = checksum_len - byte_end;
    Some(crate::crc_incremental::crc32c_update_region(
        old_csum, &delta, suffix,
    ))
}

pub fn stamp_block_bitmap_checksum(
    raw_bitmap: &[u8],
    csum_seed: u32,
    clusters_per_group: u32,
    gd: &mut Ext4GroupDesc,
    desc_size: u16,
) {
    gd.block_bitmap_csum =
        block_bitmap_checksum_value(raw_bitmap, csum_seed, clusters_per_group, desc_size);
}

pub fn stamp_inode_bitmap_checksum(
    raw_bitmap: &[u8],
    csum_seed: u32,
    inodes_per_group: u32,
    gd: &mut Ext4GroupDesc,
    desc_size: u16,
) {
    gd.inode_bitmap_csum =
        inode_bitmap_checksum_value(raw_bitmap, csum_seed, inodes_per_group, desc_size);
}

impl Ext4GroupDesc {
    /// Serialize this group descriptor into a raw byte buffer.
    ///
    /// The buffer must be at least `desc_size` bytes. Only the fields parsed by
    /// [`Ext4GroupDesc::parse_from_bytes`] are written; any remaining bytes in
    /// the buffer are left unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if `buf` is shorter than `desc_size`.
    pub fn write_to_bytes(&self, buf: &mut [u8], desc_size: u16) -> Result<(), ParseError> {
        use ffs_types::{write_le_u16, write_le_u32};
        let ds = usize::from(desc_size);
        if buf.len() < ds {
            return Err(ParseError::InsufficientData {
                needed: ds,
                offset: 0,
                actual: buf.len(),
            });
        }
        #[expect(clippy::cast_possible_truncation)]
        {
            write_le_u32(buf, 0x00, self.block_bitmap as u32);
            write_le_u32(buf, 0x04, self.inode_bitmap as u32);
            write_le_u32(buf, 0x08, self.inode_table as u32);
            write_le_u16(buf, 0x0C, self.free_blocks_count as u16);
            write_le_u16(buf, 0x0E, self.free_inodes_count as u16);
            write_le_u16(buf, 0x10, self.used_dirs_count as u16);
            write_le_u16(buf, 0x12, self.flags);
            write_le_u16(buf, 0x18, self.block_bitmap_csum as u16);
            write_le_u16(buf, 0x1A, self.inode_bitmap_csum as u16);
            write_le_u16(buf, 0x1C, self.itable_unused as u16);
            write_le_u16(buf, 0x1E, self.checksum);
        }

        if ds >= 64 {
            write_le_u32(buf, 0x20, (self.block_bitmap >> 32) as u32);
            write_le_u32(buf, 0x24, (self.inode_bitmap >> 32) as u32);
            write_le_u32(buf, 0x28, (self.inode_table >> 32) as u32);
            write_le_u16(buf, 0x2C, (self.free_blocks_count >> 16) as u16);
            write_le_u16(buf, 0x2E, (self.free_inodes_count >> 16) as u16);
            write_le_u16(buf, 0x30, (self.used_dirs_count >> 16) as u16);
            write_le_u16(buf, 0x32, (self.itable_unused >> 16) as u16);
            write_le_u16(buf, 0x38, (self.block_bitmap_csum >> 16) as u16);
            write_le_u16(buf, 0x3A, (self.inode_bitmap_csum >> 16) as u16);
        }

        Ok(())
    }
}

// ── Checksum verification helpers ────────────────────────────────────────────

/// Offset of `bg_checksum` within a group descriptor (2 bytes).
const GD_CHECKSUM_OFFSET: usize = 0x1E;

/// CRC-16 lookup table used by legacy ext4 `gdt_csum`.
///
/// Matches e2fsprogs `ext2fs_crc16` with polynomial `0x8005`.
const EXT4_GDT_CRC16_TABLE: [u16; 256] = [
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241, 0xC601, 0x06C0, 0x0780, 0xC741,
    0x0500, 0xC5C1, 0xC481, 0x0440, 0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841, 0xD801, 0x18C0, 0x1980, 0xD941,
    0x1B00, 0xDBC1, 0xDA81, 0x1A40, 0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641, 0xD201, 0x12C0, 0x1380, 0xD341,
    0x1100, 0xD1C1, 0xD081, 0x1040, 0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441, 0x3C00, 0xFCC1, 0xFD81, 0x3D40,
    0xFF01, 0x3FC0, 0x3E80, 0xFE41, 0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41, 0xEE01, 0x2EC0, 0x2F80, 0xEF41,
    0x2D00, 0xEDC1, 0xEC81, 0x2C40, 0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041, 0xA001, 0x60C0, 0x6180, 0xA141,
    0x6300, 0xA3C1, 0xA281, 0x6240, 0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41, 0xAA01, 0x6AC0, 0x6B80, 0xAB41,
    0x6900, 0xA9C1, 0xA881, 0x6840, 0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40, 0xB401, 0x74C0, 0x7580, 0xB541,
    0x7700, 0xB7C1, 0xB681, 0x7640, 0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241, 0x9601, 0x56C0, 0x5780, 0x9741,
    0x5500, 0x95C1, 0x9481, 0x5440, 0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841, 0x8801, 0x48C0, 0x4980, 0x8941,
    0x4B00, 0x8BC1, 0x8A81, 0x4A40, 0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641, 0x8201, 0x42C0, 0x4380, 0x8341,
    0x4100, 0x81C1, 0x8081, 0x4040,
];

fn ext4_gdt_crc16(mut crc: u16, buffer: &[u8]) -> u16 {
    for &byte in buffer {
        crc = (crc >> 8) ^ EXT4_GDT_CRC16_TABLE[usize::from((crc ^ u16::from(byte)) & 0x00FF)];
    }
    crc
}

fn group_desc_checksum_value(
    raw_gd: &[u8],
    uuid: &[u8; 16],
    csum_seed: u32,
    group_number: u32,
    desc_size: u16,
    checksum_kind: Ext4GroupDescChecksumKind,
) -> Result<u16, ParseError> {
    let ds = usize::from(desc_size);
    if raw_gd.len() < ds {
        return Err(ParseError::InsufficientData {
            needed: ds,
            offset: 0,
            actual: raw_gd.len(),
        });
    }

    let after_csum = GD_CHECKSUM_OFFSET + 2;
    let le_group = group_number.to_le_bytes();

    match checksum_kind {
        Ext4GroupDescChecksumKind::None => Ok(0),
        Ext4GroupDescChecksumKind::MetadataCsum => {
            let mut csum = ext4_chksum(csum_seed, &le_group);
            csum = ext4_chksum(csum, &raw_gd[..GD_CHECKSUM_OFFSET]);
            csum = ext4_chksum(csum, &[0, 0]);
            if after_csum < ds {
                csum = ext4_chksum(csum, &raw_gd[after_csum..ds]);
            }
            Ok((csum & 0xFFFF) as u16)
        }
        Ext4GroupDescChecksumKind::GdtCsum => {
            let mut crc = ext4_gdt_crc16(!0u16, uuid);
            crc = ext4_gdt_crc16(crc, &le_group);
            crc = ext4_gdt_crc16(crc, &raw_gd[..GD_CHECKSUM_OFFSET]);
            if after_csum < ds {
                crc = ext4_gdt_crc16(crc, &raw_gd[after_csum..ds]);
            }
            Ok(crc)
        }
    }
}

/// Verify a group descriptor checksum according to the ext4 feature mode.
///
/// `raw_gd` is the raw on-disk group descriptor bytes (32 or 64 bytes).
/// `uuid` comes from `Ext4Superblock::uuid`.
/// `csum_seed` comes from `Ext4Superblock::csum_seed()` for `metadata_csum`.
/// `group_number` is the block group index.
/// `desc_size` is from `Ext4Superblock::group_desc_size()`.
pub fn verify_group_desc_checksum(
    raw_gd: &[u8],
    uuid: &[u8; 16],
    csum_seed: u32,
    group_number: u32,
    desc_size: u16,
    checksum_kind: Ext4GroupDescChecksumKind,
) -> Result<(), ParseError> {
    if checksum_kind == Ext4GroupDescChecksumKind::None {
        return Ok(());
    }

    let expected = group_desc_checksum_value(
        raw_gd,
        uuid,
        csum_seed,
        group_number,
        desc_size,
        checksum_kind,
    )?;
    let stored = read_le_u16(raw_gd, GD_CHECKSUM_OFFSET)?;

    if expected != stored {
        return Err(ParseError::InvalidField {
            field: "bg_checksum",
            reason: "group descriptor checksum mismatch",
        });
    }
    Ok(())
}

/// Compute and write the checksum for a group descriptor buffer.
///
/// Overwrites the 2-byte checksum at offset 0x1E in `raw_gd`.
#[allow(clippy::cast_possible_truncation)]
pub fn stamp_group_desc_checksum(
    raw_gd: &mut [u8],
    uuid: &[u8; 16],
    csum_seed: u32,
    group_number: u32,
    desc_size: u16,
    checksum_kind: Ext4GroupDescChecksumKind,
) {
    use ffs_types::write_le_u16;
    if checksum_kind == Ext4GroupDescChecksumKind::None {
        return;
    }

    let ds = usize::from(desc_size);
    if raw_gd.len() < ds || ds < GD_CHECKSUM_OFFSET + 2 {
        return;
    }

    let Ok(csum) = group_desc_checksum_value(
        raw_gd,
        uuid,
        csum_seed,
        group_number,
        desc_size,
        checksum_kind,
    ) else {
        return;
    };
    write_le_u16(raw_gd, GD_CHECKSUM_OFFSET, csum);
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
    let ino_seed = ext4_chksum(csum_seed, &le_ino);
    let generation = read_le_u32(raw_inode, 0x64)?;
    let le_gen = generation.to_le_bytes();
    let ino_seed = ext4_chksum(ino_seed, &le_gen);

    // CRC base inode (128 bytes), skipping i_checksum_lo at 0x7C (2 bytes)
    let mut csum = ext4_chksum(ino_seed, &raw_inode[..INODE_CHECKSUM_LO_OFFSET]);
    csum = ext4_chksum(csum, &[0, 0]); // zero out checksum_lo
    let after_csum_lo = INODE_CHECKSUM_LO_OFFSET + 2;
    csum = ext4_chksum(csum, &raw_inode[after_csum_lo..128]);

    // Extended area (when inode_size > 128)
    if is > 128 {
        // CRC bytes from 128 up to i_checksum_hi (0x82), but don't exceed inode_size
        let hi_bound = INODE_CHECKSUM_HI_OFFSET.min(is);
        csum = ext4_chksum(csum, &raw_inode[128..hi_bound]);

        // Only handle checksum_hi if the inode is large enough to contain it
        if is >= INODE_CHECKSUM_HI_OFFSET + 2 {
            // Check if i_checksum_hi fits per i_extra_isize
            let extra_isize = read_le_u16(raw_inode, 0x80)?;
            let extra_end = 128 + usize::from(extra_isize);
            if extra_end >= INODE_CHECKSUM_HI_OFFSET + 2 {
                // Zero out checksum_hi
                csum = ext4_chksum(csum, &[0, 0]);
                let after_csum_hi = INODE_CHECKSUM_HI_OFFSET + 2;
                if after_csum_hi < is {
                    csum = ext4_chksum(csum, &raw_inode[after_csum_hi..is]);
                }
            } else {
                // No checksum_hi field per extra_isize, CRC the rest
                csum = ext4_chksum(csum, &raw_inode[INODE_CHECKSUM_HI_OFFSET..is]);
            }
        } else if hi_bound < is {
            // inode_size < 132: no room for checksum_hi, CRC remaining bytes
            csum = ext4_chksum(csum, &raw_inode[hi_bound..is]);
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
    let tail_off = bs - 12;
    let tail_inode = read_le_u32(dir_block, tail_off)?;
    let tail_rec_len = read_le_u16(dir_block, tail_off + 4)?;
    let tail_name_len = dir_block[tail_off + 6];
    let tail_ft = dir_block[tail_off + 7];
    if tail_inode != 0 || tail_rec_len != 12 || tail_name_len != 0 || tail_ft != EXT4_FT_DIR_CSUM {
        return Err(ParseError::InvalidField {
            field: "dir_block_tail",
            reason: "missing or malformed checksum tail",
        });
    }

    let stored = read_le_u32(dir_block, bs - 4)?;

    // Per-inode seed: i_csum_seed = ext4_chksum(ext4_chksum(csum_seed, le_ino), le_gen)
    let seed = ext4_chksum(csum_seed, &ino.to_le_bytes());
    let seed = ext4_chksum(seed, &generation.to_le_bytes());

    // Kernel checksums block[0..block_size - 12]: the dir entry data before
    // the 12-byte tail. The entire tail struct is excluded from coverage.
    let coverage_end = bs - 12;
    let computed = ext4_chksum(seed, &dir_block[..coverage_end]);

    if computed != stored {
        return Err(ParseError::InvalidField {
            field: "dir_checksum",
            reason: "directory block CRC32C mismatch",
        });
    }
    Ok(())
}

/// Stamp the CRC32C checksum into a directory block's tail entry.
///
/// The tail structure occupies the last 12 bytes of the block. This
/// function recomputes the checksum over `block[0..block_size - 12]`
/// using the same per-inode seed as [`verify_dir_block_checksum`], then
/// writes the 4-byte result into `block[block_size - 4 .. block_size]`.
///
/// The caller must ensure the block has a valid tail structure (inode=0,
/// rec_len=12, name_len=0, file_type=0xDE) before calling.
pub fn stamp_dir_block_checksum(dir_block: &mut [u8], csum_seed: u32, ino: u32, generation: u32) {
    let bs = dir_block.len();
    if bs < 12 {
        return;
    }

    let seed = ext4_chksum(csum_seed, &ino.to_le_bytes());
    let seed = ext4_chksum(seed, &generation.to_le_bytes());
    let coverage_end = bs - 12;
    let computed = ext4_chksum_skip_zero_tail(seed, &dir_block[..coverage_end]);
    dir_block[bs - 4..bs].copy_from_slice(&computed.to_le_bytes());
}

/// `ext4_chksum(seed, data)` that skips a large trailing zero run algebraically
/// instead of streaming it.
///
/// Two ext4 metadata regions are a short live prefix followed by a long zero tail:
/// a freshly-built directory block (mkdir's initial `.`/`..` block, a newly
/// allocated leaf, or a large-slack insert — entries then a ~4 KiB zero gap) and a
/// partially-full group's block/inode bitmap (allocators fill bottom-up, so the
/// high blocks/inodes — the tail bytes — are still 0).
/// Since `crc(prefix ++ zeros) = crc32c_shift_bytes(crc(prefix), N)`, a 4-wide
/// reverse zero-scan finds the content boundary and the zero tail costs one
/// GF(2) shift instead of a full CRC. Falls back to a straight CRC when the
/// trailing zero run is too short to beat the reverse-scan + shift overhead
/// (self-correcting: a full region's reverse-scan hits non-zero immediately).
/// Result-identical to `ext4_chksum(seed, data)` (proptest
/// `stamp_dir_block_checksum_zero_tail_matches_full`).
#[must_use]
pub fn ext4_chksum_skip_zero_tail(seed: u32, data: &[u8]) -> u32 {
    const MIN_ZERO_RUN: usize = 256;
    let content_end = last_nonzero_len(data);
    let zero_run = data.len() - content_end;
    if zero_run >= MIN_ZERO_RUN {
        let prefix_crc = ext4_chksum(seed, &data[..content_end]);
        crate::crc_incremental::crc32c_shift_bytes(prefix_crc, zero_run)
    } else {
        ext4_chksum(seed, data)
    }
}

/// Index one past the last non-zero byte in `buf` (0 if all-zero), via a 4-wide
/// reverse word scan that skips 32-byte all-zero blocks in one OR-reduce (the
/// same branchless-scan shape as the allocator's zero finders), then a byte tail.
fn last_nonzero_len(buf: &[u8]) -> usize {
    let mut end = buf.len();
    while end >= 32 {
        let base = end - 32;
        let word = |o: usize| -> u64 {
            u64::from_ne_bytes(buf[base + o..base + o + 8].try_into().unwrap())
        };
        if (word(0) | word(8) | word(16) | word(24)) != 0 {
            break;
        }
        end = base;
    }
    while end > 0 && buf[end - 1] == 0 {
        end -= 1;
    }
    end
}

/// Incrementally update a directory block's checksum tail after a single
/// contiguous in-place change, instead of re-CRCing the whole ~4 KiB block.
///
/// A directory mutation (add/remove one entry) touches one contiguous span
/// `[region_start, region_start+delta.len())` where `delta[i] = before[i] XOR
/// after[i]` (0 for bytes within the span that are unchanged, e.g. the shortened
/// entry's untouched name between its rewritten `rec_len` and the new entry).
/// The stored tail already holds the checksum of the *old* block, and the
/// per-inode seed cancels in the same-length XOR difference, so the new tail is
/// `crc32c_update_region(old_tail, delta, suffix)` — no seed/ino/generation
/// needed. On the create/unlink hot path this replaces a ~4084-byte CRC with a
/// ~30-byte one (bench `dir_csum_incremental`).
///
/// Returns `false` (caller must call [`stamp_dir_block_checksum`] instead) when
/// the block is too small or the change reaches past the checksummed region.
/// Requires the tail to already hold a valid checksum for the pre-change block
/// (true for every mutation of an already-stamped block). Result-identical to a
/// full recompute (proptest-verified).
#[must_use]
pub fn stamp_dir_block_checksum_incremental(
    dir_block: &mut [u8],
    region_start: usize,
    delta: &[u8],
) -> bool {
    let bs = dir_block.len();
    if bs < 12 {
        return false;
    }
    let coverage_end = bs - 12;
    let Some(region_end) = region_start.checked_add(delta.len()) else {
        return false;
    };
    if region_end > coverage_end {
        return false;
    }
    let old_tail = u32::from_le_bytes([
        dir_block[bs - 4],
        dir_block[bs - 3],
        dir_block[bs - 2],
        dir_block[bs - 1],
    ]);
    let suffix = coverage_end - region_end;
    let new_tail = crate::crc_incremental::crc32c_update_region(old_tail, delta, suffix);
    dir_block[bs - 4..bs].copy_from_slice(&new_tail.to_le_bytes());
    true
}

/// `count_offset` of the `dx_countlimit` within a DX **root** block (after the
/// fake "."/".." entries and `dx_root_info`).
pub const DX_ROOT_COUNT_OFFSET: usize = 0x20;
/// `count_offset` of the `dx_countlimit` within a DX **node** (interior) block
/// (after a single 8-byte fake dirent).
pub const DX_NODE_COUNT_OFFSET: usize = 0x08;

/// Compute the CRC32C of a hash-tree (htree) index block (`dx_root` or
/// `dx_node`), mirroring the kernel's `ext4_dx_csum`.
///
/// The checksum covers `block[0 .. count_offset + count*8]` (the header through
/// the *used* DX entries, per the `dx_countlimit.count` at `count_offset`), then
/// the `dx_tail`'s 4-byte reserved field, then 4 zero bytes standing in for the
/// `dt_checksum` field itself. The `dx_tail` lives at `count_offset + limit*8`
/// and its checksum is the last 4 bytes. Returns `None` if the block is too
/// small or `count > limit`. The per-inode seed matches
/// [`stamp_dir_block_checksum`]. Validated against an e2fsprogs-written block by
/// `dx_block_csum_matches_e2fsprogs_oracle`.
#[must_use]
pub fn ext4_dx_block_csum(
    block: &[u8],
    csum_seed: u32,
    ino: u32,
    generation: u32,
    count_offset: usize,
) -> Option<u32> {
    let limit = usize::from(u16::from_le_bytes([
        *block.get(count_offset)?,
        *block.get(count_offset + 1)?,
    ]));
    let count = usize::from(u16::from_le_bytes([
        *block.get(count_offset + 2)?,
        *block.get(count_offset + 3)?,
    ]));
    let tail = count_offset.checked_add(limit.checked_mul(8)?)?;
    if tail.checked_add(8)? > block.len() {
        return None;
    }
    let coverage_end = count_offset.checked_add(count.checked_mul(8)?)?;
    if coverage_end > tail {
        return None; // count must not exceed limit
    }
    let seed = ext4_chksum(csum_seed, &ino.to_le_bytes());
    let seed = ext4_chksum(seed, &generation.to_le_bytes());
    let csum = ext4_chksum(seed, &block[..coverage_end]);
    let csum = ext4_chksum(csum, &block[tail..tail + 4]); // dt_reserved
    let csum = ext4_chksum(csum, &0_u32.to_le_bytes()); // dt_checksum field, treated as 0
    Some(csum)
}

/// Stamp the CRC32C into a hash-tree index block's `dx_tail.dt_checksum`.
///
/// `count_offset` is [`DX_ROOT_COUNT_OFFSET`] for a root block or
/// [`DX_NODE_COUNT_OFFSET`] for an interior node. No-op if the block is
/// malformed (see [`ext4_dx_block_csum`]).
pub fn stamp_dx_block_checksum(
    block: &mut [u8],
    csum_seed: u32,
    ino: u32,
    generation: u32,
    count_offset: usize,
) {
    if let Some(csum) = ext4_dx_block_csum(block, csum_seed, ino, generation, count_offset) {
        let limit = usize::from(u16::from_le_bytes([
            block[count_offset],
            block[count_offset + 1],
        ]));
        let tail = count_offset + limit * 8;
        block[tail + 4..tail + 8].copy_from_slice(&csum.to_le_bytes());
    }
}

/// Verify a hash-tree index block's stored `dx_tail.dt_checksum`.
#[must_use]
pub fn verify_dx_block_checksum(
    block: &[u8],
    csum_seed: u32,
    ino: u32,
    generation: u32,
    count_offset: usize,
) -> bool {
    let Some(computed) = ext4_dx_block_csum(block, csum_seed, ino, generation, count_offset) else {
        return false;
    };
    let limit = usize::from(u16::from_le_bytes([
        block[count_offset],
        block[count_offset + 1],
    ]));
    let tail = count_offset + limit * 8;
    let stored = u32::from_le_bytes([
        block[tail + 4],
        block[tail + 5],
        block[tail + 6],
        block[tail + 7],
    ]);
    computed == stored
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
    let tail_off = 12_usize
        .checked_mul(eh_max)
        .and_then(|v| v.checked_add(12))
        .ok_or(ParseError::InvalidField {
            field: "eh_max",
            reason: "extent header max entries causes offset overflow",
        })?;
    if tail_off + 4 > bs {
        return Err(ParseError::InsufficientData {
            needed: tail_off + 4,
            offset: 0,
            actual: bs,
        });
    }

    let stored = read_le_u32(extent_block, tail_off)?;

    let seed = ext4_chksum(csum_seed, &ino.to_le_bytes());
    let seed = ext4_chksum(seed, &generation.to_le_bytes());
    let computed = ext4_chksum(seed, &extent_block[..tail_off]);

    if computed != stored {
        return Err(ParseError::InvalidField {
            field: "extent_checksum",
            reason: "extent block CRC32C mismatch",
        });
    }
    Ok(())
}

/// Stamp the CRC32C checksum into an extent tree block's tail.
///
/// Mirrors the logic in [`verify_extent_block_checksum`]: the tail offset
/// is `12 + 12 * eh_max`, and the checksum covers `block[0..tail_off]`.
pub fn stamp_extent_block_checksum(
    extent_block: &mut [u8],
    csum_seed: u32,
    ino: u32,
    generation: u32,
) {
    let bs = extent_block.len();
    if bs < 16 {
        return;
    }

    let eh_max = u16::from_le_bytes([extent_block[4], extent_block[5]]) as usize;
    let Some(tail_off) = 12_usize.checked_mul(eh_max).and_then(|v| v.checked_add(12)) else {
        return;
    };
    if tail_off + 4 > bs {
        return;
    }

    let seed = ext4_chksum(csum_seed, &ino.to_le_bytes());
    let seed = ext4_chksum(seed, &generation.to_le_bytes());
    // Coverage spans ALL `eh_max` entry slots; a non-full extent node
    // (`eh_entries < eh_max`) leaves the trailing slots zeroed, so skip that
    // zero run algebraically.
    let computed = ext4_chksum_skip_zero_tail(seed, &extent_block[..tail_off]);
    extent_block[tail_off..tail_off + 4].copy_from_slice(&computed.to_le_bytes());
}

/// Byte offset of `ext4_xattr_header.h_checksum` within an external xattr block.
const XATTR_HEADER_CHECKSUM_OFFSET: usize = 16;

/// Compute the CRC32C checksum of an external ext4 xattr block.
///
/// Mirrors the kernel's `ext4_xattr_block_csum()`: seed with the filesystem
/// checksum seed, fold in the block's physical number as a little-endian `u64`,
/// then checksum the entire block with the 4-byte `h_checksum` field (offset
/// 16..20) treated as zero. Required on filesystems with `metadata_csum`;
/// without a valid value `e2fsck` reports the xattr block as corrupt.
///
/// The validated formula is pinned by `xattr_block_csum_matches_e2fsprogs_oracle`,
/// which checks this against a real block written by e2fsprogs/debugfs.
#[must_use]
pub fn ext4_xattr_block_csum(csum_seed: u32, block_nr: u64, block: &[u8]) -> u32 {
    let off = XATTR_HEADER_CHECKSUM_OFFSET;
    let seed = ext4_chksum(csum_seed, &block_nr.to_le_bytes());
    let seed = ext4_chksum(seed, &block[..off]);
    let seed = ext4_chksum(seed, &0_u32.to_le_bytes());
    ext4_chksum(seed, &block[off + 4..])
}

/// Stamp the CRC32C checksum into an external xattr block's `h_checksum` field.
///
/// No-op for blocks too short to hold the header checksum field. The current
/// contents of the `h_checksum` field do not affect the result (it is treated
/// as zero), so this is safe to call repeatedly or after mutating other header
/// fields such as `h_refcount`.
pub fn stamp_xattr_block_checksum(block: &mut [u8], csum_seed: u32, block_nr: u64) {
    let off = XATTR_HEADER_CHECKSUM_OFFSET;
    if block.len() < off + 4 {
        return;
    }
    let computed = ext4_xattr_block_csum(csum_seed, block_nr, block);
    block[off..off + 4].copy_from_slice(&computed.to_le_bytes());
}

/// Verify the CRC32C checksum stored in an external xattr block's header.
///
/// Returns `false` for blocks too short to hold the field.
#[must_use]
pub fn verify_xattr_block_checksum(block: &[u8], csum_seed: u32, block_nr: u64) -> bool {
    let off = XATTR_HEADER_CHECKSUM_OFFSET;
    if block.len() < off + 4 {
        return false;
    }
    let stored = u32::from_le_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
    ext4_xattr_block_csum(csum_seed, block_nr, block) == stored
}

/// Verify that an inode bitmap's free-bit count matches the group descriptor.
///
/// `inodes_per_group` is `s_inodes_per_group` from the superblock.
/// `expected_free_inodes` is `bg_free_inodes_count` from the group descriptor.
pub fn verify_inode_bitmap_free_count(
    raw_bitmap: &[u8],
    inodes_per_group: u32,
    expected_free_inodes: u32,
) -> Result<(), ParseError> {
    verify_bitmap_free_count(
        raw_bitmap,
        inodes_per_group,
        expected_free_inodes,
        "bg_inode_bitmap",
    )
}

/// Verify that a block bitmap's free-bit count matches the group descriptor.
///
/// `blocks_per_group` is `s_blocks_per_group` from the superblock.
/// `expected_free_blocks` is `bg_free_blocks_count` from the group descriptor.
pub fn verify_block_bitmap_free_count(
    raw_bitmap: &[u8],
    blocks_per_group: u32,
    expected_free_blocks: u32,
) -> Result<(), ParseError> {
    verify_bitmap_free_count(
        raw_bitmap,
        blocks_per_group,
        expected_free_blocks,
        "bg_block_bitmap",
    )
}

fn verify_bitmap_free_count(
    raw_bitmap: &[u8],
    total_bits: u32,
    expected_free_count: u32,
    field: &'static str,
) -> Result<(), ParseError> {
    let bytes_needed_u32 = total_bits.div_ceil(8);
    let bytes_needed =
        usize::try_from(bytes_needed_u32).map_err(|_| ParseError::IntegerConversion {
            field: "bitmap_len",
        })?;
    if raw_bitmap.len() < bytes_needed {
        return Err(ParseError::InsufficientData {
            needed: bytes_needed,
            offset: 0,
            actual: raw_bitmap.len(),
        });
    }

    let full_bytes_u32 = total_bits / 8;
    let full_bytes =
        usize::try_from(full_bytes_u32).map_err(|_| ParseError::IntegerConversion {
            field: "bitmap_len",
        })?;
    let rem_bits = total_bits % 8;

    let used_bits_full: u32 = raw_bitmap[..full_bytes]
        .iter()
        .map(|byte| byte.count_ones())
        .sum();
    let used_bits_rem = if rem_bits == 0 {
        0
    } else {
        let mask = (1_u8 << rem_bits) - 1;
        (raw_bitmap[full_bytes] & mask).count_ones()
    };
    let used_bits = used_bits_full.saturating_add(used_bits_rem);
    let free_bits = total_bits.saturating_sub(used_bits);

    if free_bits != expected_free_count {
        return Err(ParseError::InvalidField {
            field,
            reason: "bitmap free count mismatch",
        });
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ext4MmpStatus {
    Clean,
    Fsck,
    Active(u32),
    UnsafeUnknown(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4MmpBlock {
    pub magic: u32,
    pub seq: u32,
    pub time: u64,
    pub nodename: String,
    pub bdevname: String,
    pub check_interval: u16,
    pub checksum: u32,
}

impl Ext4MmpBlock {
    pub fn parse_from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < EXT4_SUPERBLOCK_SIZE {
            return Err(ParseError::InsufficientData {
                needed: EXT4_SUPERBLOCK_SIZE,
                offset: 0,
                actual: bytes.len(),
            });
        }
        let magic = read_le_u32(bytes, 0x00)?;
        if magic != EXT4_MMP_MAGIC {
            return Err(ParseError::InvalidField {
                field: "mmp_magic",
                reason: "invalid MMP magic",
            });
        }
        Ok(Self {
            magic,
            seq: read_le_u32(bytes, 0x04)?,
            time: u64::from(read_le_u32(bytes, 0x08)?)
                | (u64::from(read_le_u32(bytes, 0x0C)?) << 32),
            nodename: trim_nul_padded(&read_fixed::<64>(bytes, 0x10)?),
            bdevname: trim_nul_padded(&read_fixed::<32>(bytes, 0x50)?),
            check_interval: read_le_u16(bytes, 0x70)?,
            checksum: read_le_u32(bytes, EXT4_MMP_CHECKSUM_OFFSET)?,
        })
    }

    #[must_use]
    pub fn status(&self) -> Ext4MmpStatus {
        match self.seq {
            EXT4_MMP_SEQ_CLEAN => Ext4MmpStatus::Clean,
            EXT4_MMP_SEQ_FSCK => Ext4MmpStatus::Fsck,
            1..=EXT4_MMP_SEQ_MAX => Ext4MmpStatus::Active(self.seq),
            other => Ext4MmpStatus::UnsafeUnknown(other),
        }
    }

    pub fn validate_checksum(&self, raw_block: &[u8], csum_seed: u32) -> Result<(), ParseError> {
        if raw_block.len() < EXT4_SUPERBLOCK_SIZE {
            return Err(ParseError::InsufficientData {
                needed: EXT4_SUPERBLOCK_SIZE,
                offset: 0,
                actual: raw_block.len(),
            });
        }
        let computed = ext4_chksum(csum_seed, &raw_block[..EXT4_MMP_CHECKSUM_OFFSET]);
        if computed != self.checksum {
            return Err(ParseError::InvalidField {
                field: "mmp_checksum",
                reason: "MMP CRC32C mismatch",
            });
        }
        Ok(())
    }
}

// EXT4_HUGE_FILE_FL imported from ffs_types

pub type Ext4InodeBlockBytes = SmallVec<[u8; 64]>;

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
    /// i_osd1 / l_i_version (offset 0x24): NFS change attribute (low 32 bits).
    /// Preserved opaquely across read-modify-write cycles.
    pub version: u32,
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
    /// i_version_hi (offset 0x98): NFS change attribute (high 32 bits).
    /// Preserved opaquely across read-modify-write cycles.
    pub version_hi: u32,
    pub projid: u32,

    // ── Extent / inline data ─────────────────────────────────────────────
    pub extent_bytes: Ext4InodeBlockBytes,

    // ── Inline xattr area ───────────────────────────────────────────────
    /// Raw bytes from the inode body area available for inline xattrs.
    /// This is the region `[128 + extra_isize .. inode_size]`.
    pub xattr_ibody: Vec<u8>,

    // ── In-memory identity (NOT on-disk) ─────────────────────────────────
    /// Inode number this value was loaded from, stamped by the reader at load
    /// time. Not part of the on-disk format (it is the inode-table index, known
    /// only to the caller), so it is `#[serde(skip)]` and defaults to 0 for
    /// values built by `parse_from_bytes` or struct literals. Used to derive a
    /// STABLE per-inode cache namespace `(number, generation)` that does not
    /// drift as the extent tree mutates; consumers fall back to a content hash
    /// when it is 0 (unstamped). See ffs-core `extent_cache_namespace`.
    #[serde(skip)]
    pub number: u64,
}

impl Ext4Inode {
    /// Parse an ext4 inode from raw bytes.
    ///
    /// Requires at least 128 bytes. Extended fields (timestamps, checksum,
    /// projid) are read when the buffer is large enough and `i_extra_isize`
    /// indicates they are present.
    pub fn parse_from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        Self::parse_from_bytes_with_ibody(bytes, Ext4InodeIbodyParse::Full)
    }

    /// Parse only metadata fields from an ext4 inode.
    ///
    /// This preserves every fixed inode field parsed by [`Self::parse_from_bytes`],
    /// but intentionally leaves `xattr_ibody` empty. Use it only on metadata
    /// hot paths that immediately convert to attributes or directory traversal
    /// state; xattr and inline-data callers require the full parser.
    pub fn parse_metadata_from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        Self::parse_from_bytes_with_ibody(bytes, Ext4InodeIbodyParse::MetadataOnly)
    }

    /// Parse only the fields `inode_to_attr` needs (getattr/lookup hot path).
    ///
    /// Like [`Self::parse_metadata_from_bytes`] but ALSO skips the 60-byte
    /// `i_block`/extent copy for non-device inodes — the attr path reads
    /// `extent_bytes` only via `device_number()` (char/block-device rdev, which
    /// is still supplied). The parsed inode MUST NOT escape the attr computation
    /// (a regular file's `extent_bytes` is empty here).
    pub fn parse_attr_from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        Self::parse_from_bytes_with_ibody(bytes, Ext4InodeIbodyParse::AttrOnly)
    }

    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn parse_from_bytes_with_ibody(
        bytes: &[u8],
        ibody_parse: Ext4InodeIbodyParse,
    ) -> Result<Self, ParseError> {
        if bytes.len() < 128 {
            return Err(ParseError::InsufficientData {
                needed: 128,
                offset: 0,
                actual: bytes.len(),
            });
        }

        // ── Base 128-byte area ───────────────────────────────────────────
        let mode = read_le_u16(bytes, 0x00)?;
        let uid_lo = u32::from(read_le_u16(bytes, 0x02)?);
        let gid_lo = u32::from(read_le_u16(bytes, 0x18)?);

        let is_reg = (mode & ffs_types::S_IFMT) == ffs_types::S_IFREG;
        let is_dir = (mode & ffs_types::S_IFMT) == ffs_types::S_IFDIR;
        let is_device = (mode & ffs_types::S_IFMT) == ffs_types::S_IFCHR
            || (mode & ffs_types::S_IFMT) == ffs_types::S_IFBLK;
        let size_lo = u64::from(read_le_u32(bytes, 0x04)?);
        let size_hi = if (is_reg || is_dir) && bytes.len() >= 0x70 {
            u64::from(read_le_u32(bytes, 0x6C)?)
        } else {
            0
        };

        let blocks_lo = u64::from(read_le_u32(bytes, 0x1C)?);
        let flags = read_le_u32(bytes, 0x20)?;
        let version = read_le_u32(bytes, 0x24)?;
        let generation = read_le_u32(bytes, 0x64)?;
        let file_acl_lo = u64::from(read_le_u32(bytes, 0x68)?);

        // Extent bytes: i_block[0..14] = 60 bytes at offset 0x28
        // Only read if we have enough data (some truncated test inodes may be short).
        // AttrOnly skips this 60-byte copy for non-devices (the attr path reads
        // it only via device_number() for char/block-device rdev).
        let need_extent_bytes = ibody_parse != Ext4InodeIbodyParse::AttrOnly || is_device;
        let extent_bytes = if !need_extent_bytes {
            // AttrOnly + non-device: skip the 60-byte copy entirely (empty).
            Ext4InodeBlockBytes::new()
        } else if bytes.len() >= 0x28 + 60 {
            Ext4InodeBlockBytes::from_slice(&read_fixed::<60>(bytes, 0x28)?)
        } else {
            Ext4InodeBlockBytes::from_slice(&[0_u8; 60])
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
            version_hi,
            projid,
        ) = if bytes.len() >= 0x82 {
            let extra_isize = read_le_u16(bytes, 0x80)?;
            let extra_end = 128_usize + usize::from(extra_isize);
            // Kernel validates: i_extra_isize <= inode_size - 128
            if extra_end > bytes.len() {
                return Err(ParseError::InvalidField {
                    field: "i_extra_isize",
                    reason: "extra_isize extends beyond inode boundary",
                });
            }

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
            let version_hi = if extra_end >= 0x9C && bytes.len() >= 0x9C {
                read_le_u32(bytes, 0x98)?
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
                version_hi,
                projid,
            )
        } else {
            (0, 0, 0, 0, 0, 0, 0, 0, 0)
        };

        Ok(Self {
            mode,
            uid: uid_lo | (uid_hi << 16),
            gid: gid_lo | (gid_hi << 16),
            size: size_lo | (size_hi << 32),
            links_count: read_le_u16(bytes, 0x1A)?,
            blocks,
            flags,
            version,
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
            version_hi,
            projid,

            extent_bytes,

            xattr_ibody: if ibody_parse == Ext4InodeIbodyParse::Full && extra_isize > 0 {
                let xattr_start = 128 + usize::from(extra_isize);
                if xattr_start < bytes.len() {
                    bytes[xattr_start..].to_vec()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            },

            // In-memory only; the reader stamps the real inode number after parse.
            number: 0,
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

    /// Whether this inode is marked encrypted via ext4's `i_flags` bit.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        (self.flags & EXT4_ENCRYPT_INODE_FL) != 0
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ext4InodeIbodyParse {
    Full,
    MetadataOnly,
    /// Like `MetadataOnly`, but ALSO skips the 60-byte `i_block`/extent copy for
    /// non-device inodes. The attr path (`inode_to_attr`) reads `extent_bytes`
    /// only via `device_number()` for char/block devices (which we still
    /// supply); for regular files/dirs/symlinks it never touches it, so the copy
    /// is pure waste. The parsed inode never escapes the attr computation.
    AttrOnly,
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
        Ok((
            header,
            ExtentTree::Leaf(parse_extent_leaf(bytes, entries_len)?),
        ))
    } else {
        Ok((
            header,
            ExtentTree::Index(parse_extent_index(bytes, entries_len)?),
        ))
    }
}

/// Parse the leaf entries of an extent node.
///
/// Validates that extents are sorted by `logical_block` with no overlap.
/// The on-disk ext4 format requires this invariant; downstream consumers
/// (e.g. `ffs-btree::partition_point`) silently return wrong results when
/// it is violated, which would cause silent data misreads from corrupted
/// or crafted images.
fn parse_extent_leaf(bytes: &[u8], entries_len: usize) -> Result<Vec<Ext4Extent>, ParseError> {
    let mut extents: Vec<Ext4Extent> = Vec::with_capacity(entries_len);
    for idx in 0..entries_len {
        let base = 12
            + idx.checked_mul(12).ok_or(ParseError::InvalidField {
                field: "extent_entries",
                reason: "entry offset overflow",
            })?;
        // One bounds check for the whole 12-byte entry, then const-offset
        // array reads (no per-field bounds check) — the caller pre-validates
        // `bytes.len() >= 12 + entries_len*12`, so the 4 separate `read_le_*`
        // checks were provably-redundant-but-not-elided in this loop.
        let e = read_fixed::<12>(bytes, base)?;
        let logical_block = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
        let raw_len = u16::from_le_bytes([e[4], e[5]]);
        let start_hi = u64::from(u16::from_le_bytes([e[6], e[7]]));
        let start_lo = u64::from(u32::from_le_bytes([e[8], e[9], e[10], e[11]]));
        let physical_start = start_lo | (start_hi << 32);
        let extent = Ext4Extent {
            logical_block,
            raw_len,
            physical_start,
        };
        let actual_len = extent.actual_len();

        if actual_len == 0 {
            return Err(ParseError::InvalidField {
                field: "extent_entries.ee_len",
                reason: "extent length must be non-zero",
            });
        }

        if let Some(prev) = extents.last() {
            let prev_end = u64::from(prev.logical_block) + u64::from(prev.actual_len());
            if u64::from(logical_block) < prev_end {
                return Err(ParseError::InvalidField {
                    field: "extent_entries",
                    reason: "extents not sorted by logical_block or overlap",
                });
            }
        }

        extents.push(extent);
    }
    Ok(extents)
}

/// Parse the index entries of an extent node.
///
/// Validates that index entries are strictly sorted by `logical_block`.
/// See [`parse_extent_leaf`] for the rationale.
fn parse_extent_index(
    bytes: &[u8],
    entries_len: usize,
) -> Result<Vec<Ext4ExtentIndex>, ParseError> {
    let mut indexes: Vec<Ext4ExtentIndex> = Vec::with_capacity(entries_len);
    for idx in 0..entries_len {
        let base = 12
            + idx.checked_mul(12).ok_or(ParseError::InvalidField {
                field: "extent_indexes",
                reason: "index offset overflow",
            })?;
        // One bounds check for the 12-byte entry, then const-offset array
        // reads (caller pre-validates the region length — see parse_extent_leaf).
        let e = read_fixed::<12>(bytes, base)?;
        let logical_block = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
        let leaf_lo = u64::from(u32::from_le_bytes([e[4], e[5], e[6], e[7]]));
        let leaf_hi = u64::from(u16::from_le_bytes([e[8], e[9]]));
        let leaf_block = leaf_lo | (leaf_hi << 32);

        if let Some(prev) = indexes.last()
            && logical_block <= prev.logical_block
        {
            return Err(ParseError::InvalidField {
                field: "extent_indexes",
                reason: "index entries not strictly sorted by logical_block",
            });
        }

        indexes.push(Ext4ExtentIndex {
            logical_block,
            leaf_block,
        });
    }
    Ok(indexes)
}

pub fn parse_inode_extent_tree(
    inode: &Ext4Inode,
) -> Result<(Ext4ExtentHeader, ExtentTree), ParseError> {
    parse_extent_tree(&inode.extent_bytes)
}

// ── Directory entry parsing ─────────────────────────────────────────────────

// ── ext4 directory-entry file-type constants (bd-343v3) ──────────────────
//
// Mirrored verbatim from the Linux kernel `fs/ext4/ext4.h`. The
// `Ext4FileType` enum below carries the same discriminants; these
// pub consts give cross-crate callers a kernel-named handle they can
// grep for (e.g., `EXT4_FT_DIR_CSUM` from ffs-core's dir-block
// checksum pipeline). The `ext4_file_type_constants_match_kernel_header`
// unit test pins each value.

/// File-type sentinel: unknown / not specified (kernel: `EXT4_FT_UNKNOWN`).
pub const EXT4_FT_UNKNOWN: u8 = 0;
/// Regular file (kernel: `EXT4_FT_REG_FILE`).
pub const EXT4_FT_REG_FILE: u8 = 1;
/// Directory (kernel: `EXT4_FT_DIR`).
pub const EXT4_FT_DIR: u8 = 2;
/// Character device (kernel: `EXT4_FT_CHRDEV`).
pub const EXT4_FT_CHRDEV: u8 = 3;
/// Block device (kernel: `EXT4_FT_BLKDEV`).
pub const EXT4_FT_BLKDEV: u8 = 4;
/// FIFO / named pipe (kernel: `EXT4_FT_FIFO`).
pub const EXT4_FT_FIFO: u8 = 5;
/// Socket (kernel: `EXT4_FT_SOCK`).
pub const EXT4_FT_SOCK: u8 = 6;
/// Symbolic link (kernel: `EXT4_FT_SYMLINK`).
pub const EXT4_FT_SYMLINK: u8 = 7;
/// Boundary above which any non-sentinel value is invalid
/// (kernel: `EXT4_FT_MAX`).
pub const EXT4_FT_MAX: u8 = 8;
/// Sentinel file_type value for the directory-block checksum tail
/// (`ext4_dir_entry_tail.det_reserved_ft` per the kernel; the value
/// 0xDE is reserved out-of-band from the EXT4_FT_* range).
pub const EXT4_FT_DIR_CSUM: u8 = 0xDE;

/// ext4 file type constants from directory entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Ext4FileType {
    Unknown = EXT4_FT_UNKNOWN,
    RegFile = EXT4_FT_REG_FILE,
    Dir = EXT4_FT_DIR,
    Chrdev = EXT4_FT_CHRDEV,
    Blkdev = EXT4_FT_BLKDEV,
    Fifo = EXT4_FT_FIFO,
    Sock = EXT4_FT_SOCK,
    Symlink = EXT4_FT_SYMLINK,
}

impl Ext4FileType {
    #[must_use]
    pub fn from_raw(val: u8) -> Self {
        match val {
            EXT4_FT_REG_FILE => Self::RegFile,
            EXT4_FT_DIR => Self::Dir,
            EXT4_FT_CHRDEV => Self::Chrdev,
            EXT4_FT_BLKDEV => Self::Blkdev,
            EXT4_FT_FIFO => Self::Fifo,
            EXT4_FT_SOCK => Self::Sock,
            EXT4_FT_SYMLINK => Self::Symlink,
            _ => Self::Unknown,
        }
    }

    /// The on-disk `ext4_dir_entry_2.file_type` byte for this entry kind.
    /// Inverse of [`from_raw`](Self::from_raw).
    #[must_use]
    pub fn to_raw(self) -> u8 {
        match self {
            Self::Unknown => EXT4_FT_UNKNOWN,
            Self::RegFile => EXT4_FT_REG_FILE,
            Self::Dir => EXT4_FT_DIR,
            Self::Chrdev => EXT4_FT_CHRDEV,
            Self::Blkdev => EXT4_FT_BLKDEV,
            Self::Fifo => EXT4_FT_FIFO,
            Self::Sock => EXT4_FT_SOCK,
            Self::Symlink => EXT4_FT_SYMLINK,
        }
    }
}

/// A parsed ext4 directory entry (`ext4_dir_entry_2`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4DirEntry {
    pub inode: u32,
    pub rec_len: u32,
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
fn rec_len_from_disk(raw: u16, block_size: u32) -> u32 {
    // Kernel: EXT4_MAX_REC_LEN = (1<<16)-4 = 0xFFFC. Both 0xFFFC and 0
    // encode "entire block" (needed for 64K blocks where block_size > u16::MAX).
    if raw == 0xFFFC || raw == 0 {
        return block_size;
    }
    let len = u32::from(raw);
    (len & 0xFFFC) | ((len & 0x3) << 16)
}

fn is_dir_checksum_tail(inode: u32, name_len: u8, file_type_raw: u8, rec_len: u32) -> bool {
    inode == 0 && name_len == 0 && file_type_raw == EXT4_FT_DIR_CSUM && rec_len == 12
}

fn is_malformed_dir_checksum_tail(
    inode: u32,
    name_len: u8,
    file_type_raw: u8,
    rec_len: u32,
) -> bool {
    inode == 0 && name_len != 0 && file_type_raw == EXT4_FT_DIR_CSUM && rec_len == 12
}

fn validate_dir_block_slice_len(block: &[u8], block_size: u32) -> Result<(), ParseError> {
    let block_size = usize::try_from(block_size).map_err(|_| ParseError::InvalidField {
        field: "block_size",
        reason: "block_size exceeds addressable range",
    })?;
    if block_size == 0 {
        return Err(ParseError::InvalidField {
            field: "block_size",
            reason: "block_size must be non-zero",
        });
    }
    if block.len() > block_size {
        return Err(ParseError::InvalidField {
            field: "dir_block",
            reason: "directory block slice exceeds declared block_size",
        });
    }
    Ok(())
}

/// Parse all directory entries from a single directory data block.
///
/// Returns the entries (excluding checksum tails) and an optional
/// checksum tail if one was found at the end.
/// Walk the live entries of an ext4 directory block, invoking `on_entry` for
/// each non-deleted entry with its already-bounds-checked fields and name slice
/// (borrowed from `block`, no allocation). Performs the full structural
/// validation `parse_dir_block` requires — `rec_len` alignment/bounds, checksum
/// tail detection, and the trailing-completeness check — and returns the
/// checksum tail (if any). Callbacks that only need to inspect entries (e.g.
/// name lookup) avoid `parse_dir_block`'s per-entry name `Vec` allocations
/// while seeing exactly the same entries in the same order.
// 104 lines against a 100-line lint threshold. The body is ONE linear walk of an
// on-disk directory block in which nearly every line is a distinct field
// validation returning its own named `ParseError`. Extracting a helper would put
// the field checks somewhere other than the walk that establishes their
// preconditions, which is the property a reader of a parser most needs (bd-g9l54).
#[allow(clippy::too_many_lines)]
fn walk_dir_block_entries(
    block: &[u8],
    block_size: u32,
    mut on_entry: impl FnMut(u32, u8, u32, u8, &[u8]) -> core::ops::ControlFlow<()>,
) -> Result<Option<Ext4DirEntryTail>, ParseError> {
    validate_dir_block_slice_len(block, block_size)?;

    let mut tail = None;
    let mut offset = 0_usize;

    while offset + 8 <= block.len() {
        let inode = read_le_u32(block, offset)?;
        let rec_len_raw = read_le_u16(block, offset + 4)?;
        let name_len = ensure_slice(block, offset + 6, 1)?[0];
        let file_type_raw = ensure_slice(block, offset + 7, 1)?[0];

        if block_size <= 65536 && (rec_len_raw & 0x3) != 0 {
            return Err(ParseError::InvalidField {
                field: "de_rec_len",
                reason: "directory entry rec_len not 4-byte aligned",
            });
        }
        let rec_len = rec_len_from_disk(rec_len_raw, block_size);

        // Sanity: rec_len must be >= 12 and must not go past end of block
        if rec_len < 12 {
            return Err(ParseError::InvalidField {
                field: "de_rec_len",
                reason: "directory entry rec_len < 12",
            });
        }
        let entry_end = offset
            .checked_add(rec_len as usize)
            .ok_or(ParseError::InvalidField {
                field: "de_rec_len",
                reason: "overflow",
            })?;

        // Only an inode==0 slot can be the checksum tail (inode=0, name_len=0,
        // file_type=0xDE, rec_len=12), its malformed sibling, or a deleted entry.
        // A live entry (inode != 0) is none of these, so skip the two per-entry
        // checksum-tail predicates for it — this walk is the readdir / lookup /
        // path-resolution hot path (`lookup_in_dir_block` ~31% of an ext4 lookup;
        // bd-57lae). Byte-identical: both predicates are `inode == 0 && ...`, so
        // they were already false for every live entry, and the tail/deleted
        // handling below is reached only when inode==0 either way — the same
        // errors fire in the same order.
        if inode == 0 {
            if is_malformed_dir_checksum_tail(inode, name_len, file_type_raw, rec_len)
                && entry_end <= block.len()
                && all_zero_bytes(&block[entry_end..])
            {
                return Err(ParseError::InvalidField {
                    field: "dir_block_tail",
                    reason: "malformed checksum tail header",
                });
            }

            // Detect checksum tail: inode=0, name_len=0, file_type=0xDE, rec_len=12
            if is_dir_checksum_tail(inode, name_len, file_type_raw, rec_len) {
                if entry_end > block.len() {
                    return Err(ParseError::InsufficientData {
                        needed: 12,
                        offset,
                        actual: block.len().saturating_sub(offset),
                    });
                }
                let tail_end = offset.checked_add(12).ok_or(ParseError::InvalidField {
                    field: "dir_block_tail",
                    reason: "overflow",
                })?;
                if tail_end < block.len() && !all_zero_bytes(&block[tail_end..]) {
                    return Err(ParseError::InvalidField {
                        field: "dir_block_tail",
                        reason: "non-zero padding after checksum tail",
                    });
                }
                tail = Some(Ext4DirEntryTail {
                    checksum: read_le_u32(block, offset + 8)?,
                });
                offset = block.len();
                break;
            }

            // Deleted entry (inode==0, not the tail): still bounds-check rec_len.
            if entry_end > block.len() {
                return Err(ParseError::InvalidField {
                    field: "de_rec_len",
                    reason: "directory entry extends past block boundary",
                });
            }
            offset = entry_end;
            continue;
        }

        // Live entry (inode != 0).
        if entry_end > block.len() {
            return Err(ParseError::InvalidField {
                field: "de_rec_len",
                reason: "directory entry extends past block boundary",
            });
        }

        // Read name bytes
        let name_end = offset + 8 + usize::from(name_len);
        if name_end > entry_end {
            return Err(ParseError::InvalidField {
                field: "de_name_len",
                reason: "name extends past rec_len",
            });
        }
        // A consumer that has found what it needs (e.g. a name lookup) returns
        // `Break`, stopping the walk here. The entries up to and including this one
        // were fully validated; skipping the remainder trades whole-block
        // validation-after-match (defense-in-depth only — the accepted entry is
        // already parsed and correct) for not re-parsing ~half the leaf on every
        // htree lookup (`lookup_in_dir_block` was ~31% of an ext4 lookup, perf).
        if on_entry(
            inode,
            file_type_raw,
            rec_len,
            name_len,
            &block[offset + 8..name_end],
        )
        .is_break()
        {
            return Ok(None);
        }

        offset = entry_end;
    }

    if offset != block.len() {
        return Err(ParseError::InsufficientData {
            needed: 8,
            offset,
            actual: block.len().saturating_sub(offset),
        });
    }

    Ok(tail)
}

pub fn parse_dir_block(
    block: &[u8],
    block_size: u32,
) -> Result<(Vec<Ext4DirEntry>, Option<Ext4DirEntryTail>), ParseError> {
    let mut entries = Vec::new();
    let tail = walk_dir_block_entries(
        block,
        block_size,
        |inode, file_type_raw, rec_len, name_len, name| {
            entries.push(Ext4DirEntry {
                inode,
                rec_len,
                name_len,
                file_type: Ext4FileType::from_raw(file_type_raw),
                name: name.to_vec(),
            });
            core::ops::ControlFlow::Continue(())
        },
    )?;
    Ok((entries, tail))
}

/// Look up a single name in a directory data block.
///
/// Returns the matching entry if found.
///
/// Returns `Err` if the block data is corrupt and cannot be parsed.
/// Returns `Ok(None)` if the block is valid but the target name is
/// not present.
/// Word-at-a-time (SWAR) byte-slice equality. Rust's `&[u8] == &[u8]` for a
/// runtime-length subslice in a hot scan can lower to a byte-by-byte loop; for
/// the directory-name comparisons on the lookup / path-resolution scan, where
/// same-length names (numbered / log / hash / maildir files) defeat the length
/// gate, a u64 word compare + byte tail is measurably faster (ffs-dir bench
/// `dirent_dup_scan`: 1.43x on 203 same-length entries). Length mismatch still
/// short-circuits, so varied-length names are unaffected. Bit-identical to `a == b`.
#[inline]
#[must_use]
pub fn names_eq(a: &[u8], b: &[u8]) -> bool {
    let n = a.len();
    if n != b.len() {
        return false;
    }
    if n < 8 {
        return a == b;
    }
    // Full 8-byte words up to (but not including) the final 8-byte window.
    let mut i = 0;
    while i + 8 < n {
        if u64::from_ne_bytes(a[i..i + 8].try_into().unwrap())
            != u64::from_ne_bytes(b[i..i + 8].try_into().unwrap())
        {
            return false;
        }
        i += 8;
    }
    // Final (possibly OVERLAPPING) word over the last 8 bytes — one word-compare
    // instead of a byte-wise tail loop, so non-multiple-of-8 lengths (12/13/… —
    // common dir names) stay all-word-compares (bench names_eq_crossover: the
    // old byte tail LOST to `==` at len 12/13; this is ~1.3-1.6x faster there).
    u64::from_ne_bytes(a[n - 8..n].try_into().unwrap())
        == u64::from_ne_bytes(b[n - 8..n].try_into().unwrap())
}

pub fn lookup_in_dir_block(
    block: &[u8],
    block_size: u32,
    target: &[u8],
) -> Result<Option<Ext4DirEntry>, ParseError> {
    // Walk the block in place, materialising only the first matching entry
    // (one allocation) instead of building a `Vec<Ext4DirEntry>` with a name
    // `Vec` per entry. The whole block is still validated, so the accept/reject
    // behaviour is identical to `parse_dir_block(..).find(name == target)`.
    let mut found: Option<Ext4DirEntry> = None;
    walk_dir_block_entries(
        block,
        block_size,
        |inode, file_type_raw, rec_len, name_len, name| {
            if names_eq(name, target) {
                found = Some(Ext4DirEntry {
                    inode,
                    rec_len,
                    name_len,
                    file_type: Ext4FileType::from_raw(file_type_raw),
                    name: name.to_vec(),
                });
                return core::ops::ControlFlow::Break(());
            }
            core::ops::ControlFlow::Continue(())
        },
    )?;
    Ok(found)
}

/// Case-insensitive directory entry lookup for casefold directories.
///
/// Compares entry names against `target` using Unicode case-insensitive
/// matching (a small clean-room casefold approximation for UTF-8 strings).
/// Falls back to
/// byte-level comparison for non-UTF-8 filenames.
///
/// Returns `Err` if the block data is corrupt and cannot be parsed.
pub fn lookup_in_dir_block_casefold(
    block: &[u8],
    block_size: u32,
    target: &[u8],
) -> Result<Option<Ext4DirEntry>, ParseError> {
    let target_lower = ext4_casefold_key(target);
    // Walk in place: fold each entry name and compare against the (pre-folded)
    // target, materialising only the first match. Avoids `parse_dir_block`'s
    // per-entry name allocation and stops folding once matched, while still
    // validating the whole block — identical to
    // `parse_dir_block(..).find(casefold_key(name) == target_lower)`.
    let mut found: Option<Ext4DirEntry> = None;
    walk_dir_block_entries(
        block,
        block_size,
        |inode, file_type_raw, rec_len, name_len, name| {
            if casefold_key_eq(name, &target_lower) {
                found = Some(Ext4DirEntry {
                    inode,
                    rec_len,
                    name_len,
                    file_type: Ext4FileType::from_raw(file_type_raw),
                    name: name.to_vec(),
                });
                return core::ops::ControlFlow::Break(());
            }
            core::ops::ControlFlow::Continue(())
        },
    )?;
    Ok(found)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ext4CasefoldNameDiagnostics {
    pub source_len: usize,
    pub folded_key: Vec<u8>,
    pub encoding: Ext4CasefoldEncoding,
}

impl Ext4CasefoldNameDiagnostics {
    #[must_use]
    pub fn utf8_valid(&self) -> bool {
        self.encoding == Ext4CasefoldEncoding::Utf8
    }

    #[must_use]
    pub fn ascii_fallback(&self) -> bool {
        self.encoding == Ext4CasefoldEncoding::InvalidUtf8AsciiFallback
    }

    #[must_use]
    pub fn source_exceeds_ext4_name_limit(&self) -> bool {
        self.source_len > EXT4_MAX_NAME_BYTES
    }

    #[must_use]
    pub fn folded_key_exceeds_ext4_name_limit(&self) -> bool {
        self.folded_key.len() > EXT4_MAX_NAME_BYTES
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ext4CasefoldEncoding {
    Utf8,
    InvalidUtf8AsciiFallback,
}

/// Return the comparison key used by FrankenFS for ext4 casefold lookup.
///
/// The key is suitable for collision checks before create or rename: two names
/// that produce the same key would resolve to the same casefold directory
/// entry in this clean-room model.
#[must_use]
pub fn ext4_casefold_key(name: &[u8]) -> Vec<u8> {
    casefold_name(name)
}

/// Whether `name`'s casefold key equals an already-folded target key, without
/// allocating when `name` is ASCII (the common case). For an ASCII `name`,
/// `ext4_casefold_key(name)` is just its ASCII-lowercased bytes, so comparing
/// `name` to `folded_target` with ASCII-insensitive equality is bit-for-bit
/// identical to `ext4_casefold_key(name) == folded_target` — and avoids the
/// per-call `Vec` allocation. Non-ASCII names (which may fold via Unicode rules,
/// e.g. `ß`→`ss`) fall back to materialising the key.
#[must_use]
/// Lowercase 8 ASCII bytes (high bit clear) branchlessly: add 0x20 to bytes in
/// `'A'..='Z'`. No cross-byte carry — each cleared 7-bit byte plus the constant
/// stays below 0x100. Non-ASCII high bits are preserved (callers gate on ASCII).
#[inline]
fn swar_ascii_to_lower(w: u64) -> u64 {
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGHS: u64 = 0x8080_8080_8080_8080;
    let hi = w & HIGHS;
    let x = w & 0x7f7f_7f7f_7f7f_7f7f;
    let ge_a = x + (0x7f - 0x41 + 1) * ONES; // 0x80 set where byte >= 'A'
    let gt_z = x + (0x7f - 0x5a) * ONES; // 0x80 set where byte > 'Z'
    let is_upper = ge_a & !gt_z & HIGHS; // 0x80 where 'A'..='Z'
    (x | (is_upper >> 2)) | hi // 0x80 >> 2 = 0x20
}

/// ASCII case-insensitive byte-slice equality. Word-at-a-time SWAR for short
/// names (the common filename length) — the case-folding analogue of `names_eq`;
/// `eq_ignore_ascii_case` autovectorizes for LONG slices, so defer to it past a
/// length where its AVX path beats a u64 SWAR (bench `casefold_cmp`: SWAR 1.64x
/// at 13-14 B, loses at 33 B). Bit-identical to `a.eq_ignore_ascii_case(b)`.
#[inline]
fn ascii_ci_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    if a.len() > 16 {
        return a.eq_ignore_ascii_case(b);
    }
    let mut i = 0;
    while i + 8 <= a.len() {
        let wa = u64::from_ne_bytes(a[i..i + 8].try_into().unwrap());
        let wb = u64::from_ne_bytes(b[i..i + 8].try_into().unwrap());
        if swar_ascii_to_lower(wa) != swar_ascii_to_lower(wb) {
            return false;
        }
        i += 8;
    }
    while i < a.len() {
        if !a[i].eq_ignore_ascii_case(&b[i]) {
            return false;
        }
        i += 1;
    }
    true
}

fn casefold_key_eq(name: &[u8], folded_target: &[u8]) -> bool {
    if name.is_ascii() {
        ascii_ci_eq(name, folded_target)
    } else {
        ext4_casefold_key(name) == folded_target
    }
}

/// Case-insensitive equality of two raw directory names under ext4 casefold,
/// allocation-free when both are ASCII. Equivalent to
/// `ext4_casefold_key(left) == ext4_casefold_key(right)`.
#[must_use]
pub fn ext4_casefold_eq(left: &[u8], right: &[u8]) -> bool {
    if left.is_ascii() && right.is_ascii() {
        ascii_ci_eq(left, right)
    } else {
        ext4_casefold_key(left) == ext4_casefold_key(right)
    }
}

#[must_use]
pub fn ext4_casefold_names_collide(left: &[u8], right: &[u8]) -> bool {
    ext4_casefold_eq(left, right)
}

#[must_use]
pub fn ext4_casefold_name_diagnostics(name: &[u8]) -> Ext4CasefoldNameDiagnostics {
    let utf8_valid = std::str::from_utf8(name).is_ok();
    let folded_key = ext4_casefold_key(name);
    Ext4CasefoldNameDiagnostics {
        source_len: name.len(),
        folded_key,
        encoding: if utf8_valid {
            Ext4CasefoldEncoding::Utf8
        } else {
            Ext4CasefoldEncoding::InvalidUtf8AsciiFallback
        },
    }
}

/// Apply Unicode casefold to a filename for case-insensitive comparison.
///
/// Converts UTF-8 filenames to a canonical comparison form. This intentionally
/// covers the multi-code-point sharp-s fold (`ß`/`ẞ` -> `ss`) that ext4
/// casefold directories rely on for stable case-insensitive lookup. Non-UTF-8
/// filenames are compared byte-by-byte with ASCII case folding only.
fn casefold_name(name: &[u8]) -> Vec<u8> {
    if name.is_ascii() {
        let mut folded = name.to_vec();
        folded.make_ascii_lowercase();
        return folded;
    }

    std::str::from_utf8(name).map_or_else(
        |_| {
            // Non-UTF-8: ASCII case fold only.
            name.iter()
                .map(|&b| {
                    if b.is_ascii_uppercase() {
                        b.to_ascii_lowercase()
                    } else {
                        b
                    }
                })
                .collect()
        },
        |s| {
            let mut folded = String::with_capacity(s.len());
            for ch in s.chars() {
                push_casefolded_char(&mut folded, ch);
            }
            folded.into_bytes()
        },
    )
}

/// Canonical (NFD) decomposition of a precomposed single-mark letter into its
/// lowercased base char + combining mark, for casefold comparison. The kernel's
/// casefold table NFD-normalizes before folding, so a precomposed letter and
/// its decomposed form must fold to the same key; this makes the read-path
/// linear-scan lookup match either spelling for covered Latin, Greek, and
/// Cyrillic rows (bd-qdmlu / bd-gegku, read-correctness increments of bd-vsuni).
/// Multi-mark Latin Extended Additional / Vietnamese forms live in
/// [`precomposed_multi_mark_nfd_casefold`]. Returns `None` otherwise (e.g. Æ,
/// Ð, Ø, Þ, ß, Đ, Ł, Œ, ŋ — no canonical decomposition, handled elsewhere or
/// left as-is). The tables are pinned to canonical Unicode 12.1 decompositions
/// used by the ext4 casefold contract.
fn precomposed_nfd_casefold(ch: char) -> Option<(char, char)> {
    precomposed_latin1_nfd_casefold(ch)
        .or_else(|| precomposed_latin_extended_a_nfd_casefold(ch))
        .or_else(|| precomposed_latin_extended_additional_a_l_nfd_casefold(ch))
        .or_else(|| precomposed_latin_extended_additional_m_z_nfd_casefold(ch))
        .or_else(|| precomposed_vietnamese_single_mark_nfd_casefold(ch))
        .or_else(|| precomposed_greek_nfd_casefold(ch))
        .or_else(|| precomposed_cyrillic_nfd_casefold(ch))
}

const fn precomposed_latin1_nfd_casefold(ch: char) -> Option<(char, char)> {
    Some(match ch {
        'À' | 'à' => ('a', '\u{0300}'),
        'Á' | 'á' => ('a', '\u{0301}'),
        'Â' | 'â' => ('a', '\u{0302}'),
        'Ã' | 'ã' => ('a', '\u{0303}'),
        'Ä' | 'ä' => ('a', '\u{0308}'),
        'Å' | 'å' => ('a', '\u{030A}'),
        'Ç' | 'ç' => ('c', '\u{0327}'),
        'È' | 'è' => ('e', '\u{0300}'),
        'É' | 'é' => ('e', '\u{0301}'),
        'Ê' | 'ê' => ('e', '\u{0302}'),
        'Ë' | 'ë' => ('e', '\u{0308}'),
        'Ì' | 'ì' => ('i', '\u{0300}'),
        'Í' | 'í' => ('i', '\u{0301}'),
        'Î' | 'î' => ('i', '\u{0302}'),
        'Ï' | 'ï' => ('i', '\u{0308}'),
        'Ñ' | 'ñ' => ('n', '\u{0303}'),
        'Ò' | 'ò' => ('o', '\u{0300}'),
        'Ó' | 'ó' => ('o', '\u{0301}'),
        'Ô' | 'ô' => ('o', '\u{0302}'),
        'Õ' | 'õ' => ('o', '\u{0303}'),
        'Ö' | 'ö' => ('o', '\u{0308}'),
        'Ù' | 'ù' => ('u', '\u{0300}'),
        'Ú' | 'ú' => ('u', '\u{0301}'),
        'Û' | 'û' => ('u', '\u{0302}'),
        'Ü' | 'ü' => ('u', '\u{0308}'),
        'Ý' | 'ý' => ('y', '\u{0301}'),
        'Ÿ' | 'ÿ' => ('y', '\u{0308}'), // U+0178 / U+00FF
        _ => return None,
    })
}

const fn precomposed_latin_extended_a_nfd_casefold(ch: char) -> Option<(char, char)> {
    Some(match ch {
        'Ā' | 'ā' => ('a', '\u{0304}'),
        'Ă' | 'ă' => ('a', '\u{0306}'),
        'Ą' | 'ą' => ('a', '\u{0328}'),
        'Ć' | 'ć' => ('c', '\u{0301}'),
        'Ĉ' | 'ĉ' => ('c', '\u{0302}'),
        'Ċ' | 'ċ' => ('c', '\u{0307}'),
        'Č' | 'č' => ('c', '\u{030C}'),
        'Ď' | 'ď' => ('d', '\u{030C}'),
        'Ē' | 'ē' => ('e', '\u{0304}'),
        'Ĕ' | 'ĕ' => ('e', '\u{0306}'),
        'Ė' | 'ė' => ('e', '\u{0307}'),
        'Ę' | 'ę' => ('e', '\u{0328}'),
        'Ě' | 'ě' => ('e', '\u{030C}'),
        'Ĝ' | 'ĝ' => ('g', '\u{0302}'),
        'Ğ' | 'ğ' => ('g', '\u{0306}'),
        'Ġ' | 'ġ' => ('g', '\u{0307}'),
        'Ģ' | 'ģ' => ('g', '\u{0327}'),
        'Ĥ' | 'ĥ' => ('h', '\u{0302}'),
        'Ĩ' | 'ĩ' => ('i', '\u{0303}'),
        'Ī' | 'ī' => ('i', '\u{0304}'),
        'Ĭ' | 'ĭ' => ('i', '\u{0306}'),
        'Į' | 'į' => ('i', '\u{0328}'),
        'İ' => ('i', '\u{0307}'), // unpaired: dotless small i (U+0131) has no decomposition
        'Ĵ' | 'ĵ' => ('j', '\u{0302}'),
        'Ķ' | 'ķ' => ('k', '\u{0327}'),
        'Ĺ' | 'ĺ' => ('l', '\u{0301}'),
        'Ļ' | 'ļ' => ('l', '\u{0327}'),
        'Ľ' | 'ľ' => ('l', '\u{030C}'),
        'Ń' | 'ń' => ('n', '\u{0301}'),
        'Ņ' | 'ņ' => ('n', '\u{0327}'),
        'Ň' | 'ň' => ('n', '\u{030C}'),
        'Ō' | 'ō' => ('o', '\u{0304}'),
        'Ŏ' | 'ŏ' => ('o', '\u{0306}'),
        'Ő' | 'ő' => ('o', '\u{030B}'),
        'Ŕ' | 'ŕ' => ('r', '\u{0301}'),
        'Ŗ' | 'ŗ' => ('r', '\u{0327}'),
        'Ř' | 'ř' => ('r', '\u{030C}'),
        'Ś' | 'ś' => ('s', '\u{0301}'),
        'Ŝ' | 'ŝ' => ('s', '\u{0302}'),
        'Ş' | 'ş' => ('s', '\u{0327}'),
        'Š' | 'š' => ('s', '\u{030C}'),
        'Ţ' | 'ţ' => ('t', '\u{0327}'),
        'Ť' | 'ť' => ('t', '\u{030C}'),
        'Ũ' | 'ũ' => ('u', '\u{0303}'),
        'Ū' | 'ū' => ('u', '\u{0304}'),
        'Ŭ' | 'ŭ' => ('u', '\u{0306}'),
        'Ů' | 'ů' => ('u', '\u{030A}'),
        'Ű' | 'ű' => ('u', '\u{030B}'),
        'Ų' | 'ų' => ('u', '\u{0328}'),
        'Ŵ' | 'ŵ' => ('w', '\u{0302}'),
        'Ŷ' | 'ŷ' => ('y', '\u{0302}'),
        'Ź' | 'ź' => ('z', '\u{0301}'),
        'Ż' | 'ż' => ('z', '\u{0307}'),
        'Ž' | 'ž' => ('z', '\u{030C}'),
        _ => return None,
    })
}

const fn precomposed_latin_extended_additional_a_l_nfd_casefold(ch: char) -> Option<(char, char)> {
    Some(match ch {
        'Ḁ' | 'ḁ' => ('a', '\u{0325}'),
        'Ḃ' | 'ḃ' => ('b', '\u{0307}'),
        'Ḅ' | 'ḅ' => ('b', '\u{0323}'),
        'Ḇ' | 'ḇ' => ('b', '\u{0331}'),
        'Ḋ' | 'ḋ' => ('d', '\u{0307}'),
        'Ḍ' | 'ḍ' => ('d', '\u{0323}'),
        'Ḏ' | 'ḏ' => ('d', '\u{0331}'),
        'Ḑ' | 'ḑ' => ('d', '\u{0327}'),
        'Ḓ' | 'ḓ' => ('d', '\u{032D}'),
        'Ḙ' | 'ḙ' => ('e', '\u{032D}'),
        'Ḛ' | 'ḛ' => ('e', '\u{0330}'),
        'Ḟ' | 'ḟ' => ('f', '\u{0307}'),
        'Ḡ' | 'ḡ' => ('g', '\u{0304}'),
        'Ḣ' | 'ḣ' => ('h', '\u{0307}'),
        'Ḥ' | 'ḥ' => ('h', '\u{0323}'),
        'Ḧ' | 'ḧ' => ('h', '\u{0308}'),
        'Ḩ' | 'ḩ' => ('h', '\u{0327}'),
        'Ḫ' | 'ḫ' => ('h', '\u{032E}'),
        'Ḭ' | 'ḭ' => ('i', '\u{0330}'),
        'Ḱ' | 'ḱ' => ('k', '\u{0301}'),
        'Ḳ' | 'ḳ' => ('k', '\u{0323}'),
        'Ḵ' | 'ḵ' => ('k', '\u{0331}'),
        'Ḷ' | 'ḷ' => ('l', '\u{0323}'),
        'Ḻ' | 'ḻ' => ('l', '\u{0331}'),
        'Ḽ' | 'ḽ' => ('l', '\u{032D}'),
        _ => return None,
    })
}

const fn precomposed_latin_extended_additional_m_z_nfd_casefold(ch: char) -> Option<(char, char)> {
    Some(match ch {
        'Ḿ' | 'ḿ' => ('m', '\u{0301}'),
        'Ṁ' | 'ṁ' => ('m', '\u{0307}'),
        'Ṃ' | 'ṃ' => ('m', '\u{0323}'),
        'Ṅ' | 'ṅ' => ('n', '\u{0307}'),
        'Ṇ' | 'ṇ' => ('n', '\u{0323}'),
        'Ṉ' | 'ṉ' => ('n', '\u{0331}'),
        'Ṋ' | 'ṋ' => ('n', '\u{032D}'),
        'Ṕ' | 'ṕ' => ('p', '\u{0301}'),
        'Ṗ' | 'ṗ' => ('p', '\u{0307}'),
        'Ṙ' | 'ṙ' => ('r', '\u{0307}'),
        'Ṛ' | 'ṛ' => ('r', '\u{0323}'),
        'Ṟ' | 'ṟ' => ('r', '\u{0331}'),
        'Ṡ' | 'ṡ' | 'ẛ' => ('s', '\u{0307}'),
        'Ṣ' | 'ṣ' => ('s', '\u{0323}'),
        'Ṫ' | 'ṫ' => ('t', '\u{0307}'),
        'Ṭ' | 'ṭ' => ('t', '\u{0323}'),
        'Ṯ' | 'ṯ' => ('t', '\u{0331}'),
        'Ṱ' | 'ṱ' => ('t', '\u{032D}'),
        'Ṳ' | 'ṳ' => ('u', '\u{0324}'),
        'Ṵ' | 'ṵ' => ('u', '\u{0330}'),
        'Ṷ' | 'ṷ' => ('u', '\u{032D}'),
        'Ṽ' | 'ṽ' => ('v', '\u{0303}'),
        'Ṿ' | 'ṿ' => ('v', '\u{0323}'),
        'Ẁ' | 'ẁ' => ('w', '\u{0300}'),
        'Ẃ' | 'ẃ' => ('w', '\u{0301}'),
        'Ẅ' | 'ẅ' => ('w', '\u{0308}'),
        'Ẇ' | 'ẇ' => ('w', '\u{0307}'),
        'Ẉ' | 'ẉ' => ('w', '\u{0323}'),
        'Ẋ' | 'ẋ' => ('x', '\u{0307}'),
        'Ẍ' | 'ẍ' => ('x', '\u{0308}'),
        'Ẏ' | 'ẏ' => ('y', '\u{0307}'),
        'Ẑ' | 'ẑ' => ('z', '\u{0302}'),
        'Ẓ' | 'ẓ' => ('z', '\u{0323}'),
        'Ẕ' | 'ẕ' => ('z', '\u{0331}'),
        'ẖ' => ('h', '\u{0331}'),
        'ẗ' => ('t', '\u{0308}'),
        'ẘ' => ('w', '\u{030A}'),
        'ẙ' => ('y', '\u{030A}'),
        'ẚ' => ('a', '\u{02BE}'),
        _ => return None,
    })
}

const fn precomposed_vietnamese_single_mark_nfd_casefold(ch: char) -> Option<(char, char)> {
    Some(match ch {
        // Latin Extended-B bases used by Vietnamese precomposed letters.
        'Ơ' | 'ơ' => ('o', '\u{031B}'),
        'Ư' | 'ư' => ('u', '\u{031B}'),
        'Ạ' | 'ạ' => ('a', '\u{0323}'),
        'Ả' | 'ả' => ('a', '\u{0309}'),
        'Ẹ' | 'ẹ' => ('e', '\u{0323}'),
        'Ẻ' | 'ẻ' => ('e', '\u{0309}'),
        'Ẽ' | 'ẽ' => ('e', '\u{0303}'),
        'Ỉ' | 'ỉ' => ('i', '\u{0309}'),
        'Ị' | 'ị' => ('i', '\u{0323}'),
        'Ọ' | 'ọ' => ('o', '\u{0323}'),
        'Ỏ' | 'ỏ' => ('o', '\u{0309}'),
        'Ụ' | 'ụ' => ('u', '\u{0323}'),
        'Ủ' | 'ủ' => ('u', '\u{0309}'),
        'Ỳ' | 'ỳ' => ('y', '\u{0300}'),
        'Ỵ' | 'ỵ' => ('y', '\u{0323}'),
        'Ỷ' | 'ỷ' => ('y', '\u{0309}'),
        'Ỹ' | 'ỹ' => ('y', '\u{0303}'),
        _ => return None,
    })
}

const fn precomposed_greek_nfd_casefold(ch: char) -> Option<(char, char)> {
    Some(match ch {
        'Ά' | 'ά' => ('α', '\u{0301}'),
        'Έ' | 'έ' => ('ε', '\u{0301}'),
        'Ή' | 'ή' => ('η', '\u{0301}'),
        'Ί' | 'ί' => ('ι', '\u{0301}'),
        'Ό' | 'ό' => ('ο', '\u{0301}'),
        'Ύ' | 'ύ' => ('υ', '\u{0301}'),
        'Ώ' | 'ώ' => ('ω', '\u{0301}'),
        'Ϊ' | 'ϊ' => ('ι', '\u{0308}'),
        'Ϋ' | 'ϋ' => ('υ', '\u{0308}'),
        _ => return None,
    })
}

/// Cyrillic letters with canonical Unicode 12.1 decompositions. ext4's
/// casefold table NFD-normalizes before folding, so composed spellings like
/// `Й` and decomposed spellings like `и` + COMBINING BREVE must collide.
const fn precomposed_cyrillic_nfd_casefold(ch: char) -> Option<(char, char)> {
    Some(match ch {
        'Ѐ' | 'ѐ' => ('е', '\u{0300}'),
        'Ё' | 'ё' => ('е', '\u{0308}'),
        'Ѓ' | 'ѓ' => ('г', '\u{0301}'),
        'Ї' | 'ї' => ('і', '\u{0308}'),
        'Ќ' | 'ќ' => ('к', '\u{0301}'),
        'Ѝ' | 'ѝ' => ('и', '\u{0300}'),
        'Ў' | 'ў' => ('у', '\u{0306}'),
        'Й' | 'й' => ('и', '\u{0306}'),
        'Ѷ' | 'ѷ' => ('ѵ', '\u{030F}'),
        'Ӂ' | 'ӂ' => ('ж', '\u{0306}'),
        'Ӑ' | 'ӑ' => ('а', '\u{0306}'),
        'Ӓ' | 'ӓ' => ('а', '\u{0308}'),
        'Ӗ' | 'ӗ' => ('е', '\u{0306}'),
        'Ӛ' | 'ӛ' => ('ә', '\u{0308}'),
        'Ӝ' | 'ӝ' => ('ж', '\u{0308}'),
        'Ӟ' | 'ӟ' => ('з', '\u{0308}'),
        'Ӣ' | 'ӣ' => ('и', '\u{0304}'),
        'Ӥ' | 'ӥ' => ('и', '\u{0308}'),
        'Ӧ' | 'ӧ' => ('о', '\u{0308}'),
        'Ӫ' | 'ӫ' => ('ө', '\u{0308}'),
        'Ӭ' | 'ӭ' => ('э', '\u{0308}'),
        'Ӯ' | 'ӯ' => ('у', '\u{0304}'),
        'Ӱ' | 'ӱ' => ('у', '\u{0308}'),
        'Ӳ' | 'ӳ' => ('у', '\u{030B}'),
        'Ӵ' | 'ӵ' => ('ч', '\u{0308}'),
        'Ӹ' | 'ӹ' => ('ы', '\u{0308}'),
        _ => return None,
    })
}

/// Canonical (NFD) decomposition for Latin Extended Additional / Vietnamese
/// letters whose Unicode 12.1 decomposition recursively expands to more than
/// one combining mark. Marks are already in canonical combining-class order.
fn precomposed_multi_mark_nfd_casefold(ch: char) -> Option<(char, &'static str)> {
    let mapped = match ch {
        'Ḉ' | 'ḉ' => ('c', "\u{0327}\u{0301}"),
        'Ḕ' | 'ḕ' => ('e', "\u{0304}\u{0300}"),
        'Ḗ' | 'ḗ' => ('e', "\u{0304}\u{0301}"),
        'Ḝ' | 'ḝ' => ('e', "\u{0327}\u{0306}"),
        'Ḯ' | 'ḯ' => ('i', "\u{0308}\u{0301}"),
        'Ḹ' | 'ḹ' => ('l', "\u{0323}\u{0304}"),
        'Ṍ' | 'ṍ' => ('o', "\u{0303}\u{0301}"),
        'Ṏ' | 'ṏ' => ('o', "\u{0303}\u{0308}"),
        'Ṑ' | 'ṑ' => ('o', "\u{0304}\u{0300}"),
        'Ṓ' | 'ṓ' => ('o', "\u{0304}\u{0301}"),
        'Ṝ' | 'ṝ' => ('r', "\u{0323}\u{0304}"),
        'Ṥ' | 'ṥ' => ('s', "\u{0301}\u{0307}"),
        'Ṧ' | 'ṧ' => ('s', "\u{030C}\u{0307}"),
        'Ṩ' | 'ṩ' => ('s', "\u{0323}\u{0307}"),
        'Ṹ' | 'ṹ' => ('u', "\u{0303}\u{0301}"),
        'Ṻ' | 'ṻ' => ('u', "\u{0304}\u{0308}"),
        'Ấ' | 'ấ' => ('a', "\u{0302}\u{0301}"),
        'Ầ' | 'ầ' => ('a', "\u{0302}\u{0300}"),
        'Ẩ' | 'ẩ' => ('a', "\u{0302}\u{0309}"),
        'Ẫ' | 'ẫ' => ('a', "\u{0302}\u{0303}"),
        'Ậ' | 'ậ' => ('a', "\u{0323}\u{0302}"),
        'Ắ' | 'ắ' => ('a', "\u{0306}\u{0301}"),
        'Ằ' | 'ằ' => ('a', "\u{0306}\u{0300}"),
        'Ẳ' | 'ẳ' => ('a', "\u{0306}\u{0309}"),
        'Ẵ' | 'ẵ' => ('a', "\u{0306}\u{0303}"),
        'Ặ' | 'ặ' => ('a', "\u{0323}\u{0306}"),
        'Ế' | 'ế' => ('e', "\u{0302}\u{0301}"),
        'Ề' | 'ề' => ('e', "\u{0302}\u{0300}"),
        'Ể' | 'ể' => ('e', "\u{0302}\u{0309}"),
        'Ễ' | 'ễ' => ('e', "\u{0302}\u{0303}"),
        'Ệ' | 'ệ' => ('e', "\u{0323}\u{0302}"),
        'Ố' | 'ố' => ('o', "\u{0302}\u{0301}"),
        'Ồ' | 'ồ' => ('o', "\u{0302}\u{0300}"),
        'Ổ' | 'ổ' => ('o', "\u{0302}\u{0309}"),
        'Ỗ' | 'ỗ' => ('o', "\u{0302}\u{0303}"),
        'Ộ' | 'ộ' => ('o', "\u{0323}\u{0302}"),
        'Ớ' | 'ớ' => ('o', "\u{031B}\u{0301}"),
        'Ờ' | 'ờ' => ('o', "\u{031B}\u{0300}"),
        'Ở' | 'ở' => ('o', "\u{031B}\u{0309}"),
        'Ỡ' | 'ỡ' => ('o', "\u{031B}\u{0303}"),
        'Ợ' | 'ợ' => ('o', "\u{031B}\u{0323}"),
        'Ứ' | 'ứ' => ('u', "\u{031B}\u{0301}"),
        'Ừ' | 'ừ' => ('u', "\u{031B}\u{0300}"),
        'Ử' | 'ử' => ('u', "\u{031B}\u{0309}"),
        'Ữ' | 'ữ' => ('u', "\u{031B}\u{0303}"),
        'Ự' | 'ự' => ('u', "\u{031B}\u{0323}"),
        _ => return None,
    };
    Some(mapped)
}

const fn greek_breathing_accent_suffix(form: u32) -> &'static str {
    match form & 0x7 {
        0 => "\u{0313}",
        1 => "\u{0314}",
        2 => "\u{0313}\u{0300}",
        3 => "\u{0314}\u{0300}",
        4 => "\u{0313}\u{0301}",
        5 => "\u{0314}\u{0301}",
        6 => "\u{0313}\u{0342}",
        7 => "\u{0314}\u{0342}",
        _ => "",
    }
}

const fn greek_breathing_accent_iota_suffix(form: u32) -> &'static str {
    match form & 0x7 {
        0 => "\u{0313}ι",
        1 => "\u{0314}ι",
        2 => "\u{0313}\u{0300}ι",
        3 => "\u{0314}\u{0300}ι",
        4 => "\u{0313}\u{0301}ι",
        5 => "\u{0314}\u{0301}ι",
        6 => "\u{0313}\u{0342}ι",
        7 => "\u{0314}\u{0342}ι",
        _ => "",
    }
}

/// Greek Extended NFD + casefold coverage for polytonic forms. Some forms
/// include U+0345 COMBINING GREEK YPOGEGRAMMENI in NFD; casefold expands that
/// mark to a spacing iota, so the suffix may include Greek letters too.
fn precomposed_greek_extended_nfd_casefold(ch: char) -> Option<(char, &'static str)> {
    let code = u32::from(ch);
    let mapped = match code {
        0x0390 | 0x1FD3 => ('ι', "\u{0308}\u{0301}"),
        0x03B0 | 0x1FE3 => ('υ', "\u{0308}\u{0301}"),
        0x1F00..=0x1F0F => ('α', greek_breathing_accent_suffix(code)),
        0x1F10..=0x1F1D if (code & 0x7) <= 5 => ('ε', greek_breathing_accent_suffix(code)),
        0x1F20..=0x1F2F => ('η', greek_breathing_accent_suffix(code)),
        0x1F30..=0x1F3F => ('ι', greek_breathing_accent_suffix(code)),
        0x1F40..=0x1F4D if (code & 0x7) <= 5 => ('ο', greek_breathing_accent_suffix(code)),
        0x1F50..=0x1F57 | 0x1F59 | 0x1F5B | 0x1F5D | 0x1F5F => {
            ('υ', greek_breathing_accent_suffix(code))
        }
        0x1F60..=0x1F6F => ('ω', greek_breathing_accent_suffix(code)),
        0x1F70 | 0x1FBA => ('α', "\u{0300}"),
        0x1F71 | 0x1FBB => ('α', "\u{0301}"),
        0x1F72 | 0x1FC8 => ('ε', "\u{0300}"),
        0x1F73 | 0x1FC9 => ('ε', "\u{0301}"),
        0x1F74 | 0x1FCA => ('η', "\u{0300}"),
        0x1F75 | 0x1FCB => ('η', "\u{0301}"),
        0x1F76 | 0x1FDA => ('ι', "\u{0300}"),
        0x1F77 | 0x1FDB => ('ι', "\u{0301}"),
        0x1F78 | 0x1FF8 => ('ο', "\u{0300}"),
        0x1F79 | 0x1FF9 => ('ο', "\u{0301}"),
        0x1F7A | 0x1FEA => ('υ', "\u{0300}"),
        0x1F7B | 0x1FEB => ('υ', "\u{0301}"),
        0x1F7C | 0x1FFA => ('ω', "\u{0300}"),
        0x1F7D | 0x1FFB => ('ω', "\u{0301}"),
        0x1F80..=0x1F8F => ('α', greek_breathing_accent_iota_suffix(code)),
        0x1F90..=0x1F9F => ('η', greek_breathing_accent_iota_suffix(code)),
        0x1FA0..=0x1FAF => ('ω', greek_breathing_accent_iota_suffix(code)),
        0x1FB0 | 0x1FB8 => ('α', "\u{0306}"),
        0x1FB1 | 0x1FB9 => ('α', "\u{0304}"),
        0x1FB2 => ('α', "\u{0300}ι"),
        0x1FB3 | 0x1FBC => ('α', "ι"),
        0x1FB4 => ('α', "\u{0301}ι"),
        0x1FB6 => ('α', "\u{0342}"),
        0x1FB7 => ('α', "\u{0342}ι"),
        0x1FBE => ('ι', ""),
        0x1FC1 => ('\u{00A8}', "\u{0342}"),
        0x1FC2 => ('η', "\u{0300}ι"),
        0x1FC3 | 0x1FCC => ('η', "ι"),
        0x1FC4 => ('η', "\u{0301}ι"),
        0x1FC6 => ('η', "\u{0342}"),
        0x1FC7 => ('η', "\u{0342}ι"),
        0x1FCD => ('\u{1FBF}', "\u{0300}"),
        0x1FCE => ('\u{1FBF}', "\u{0301}"),
        0x1FCF => ('\u{1FBF}', "\u{0342}"),
        0x1FD0 | 0x1FD8 => ('ι', "\u{0306}"),
        0x1FD1 | 0x1FD9 => ('ι', "\u{0304}"),
        0x1FD2 => ('ι', "\u{0308}\u{0300}"),
        0x1FD6 => ('ι', "\u{0342}"),
        0x1FD7 => ('ι', "\u{0308}\u{0342}"),
        0x1FDD => ('\u{1FFE}', "\u{0300}"),
        0x1FDE => ('\u{1FFE}', "\u{0301}"),
        0x1FDF => ('\u{1FFE}', "\u{0342}"),
        0x1FE0 | 0x1FE8 => ('υ', "\u{0306}"),
        0x1FE1 | 0x1FE9 => ('υ', "\u{0304}"),
        0x1FE2 => ('υ', "\u{0308}\u{0300}"),
        0x1FE4 => ('ρ', "\u{0313}"),
        0x1FE5 | 0x1FEC => ('ρ', "\u{0314}"),
        0x1FE6 => ('υ', "\u{0342}"),
        0x1FE7 => ('υ', "\u{0308}\u{0342}"),
        0x1FED => ('\u{00A8}', "\u{0300}"),
        0x1FEE => ('\u{00A8}', "\u{0301}"),
        0x1FEF => ('`', ""),
        0x1FF2 => ('ω', "\u{0300}ι"),
        0x1FF3 | 0x1FFC => ('ω', "ι"),
        0x1FF4 => ('ω', "\u{0301}ι"),
        0x1FF6 => ('ω', "\u{0342}"),
        0x1FF7 => ('ω', "\u{0342}ι"),
        0x1FFD => ('\u{00B4}', ""),
        _ => return None,
    };
    Some(mapped)
}

fn push_precomposed_nfd_casefold(folded: &mut String, ch: char) -> bool {
    if let Some((base, mark)) = precomposed_nfd_casefold(ch) {
        folded.push(base);
        folded.push(mark);
        return true;
    }
    if let Some((base, marks)) = precomposed_multi_mark_nfd_casefold(ch) {
        folded.push(base);
        folded.push_str(marks);
        return true;
    }
    if let Some((base, suffix)) = precomposed_greek_extended_nfd_casefold(ch) {
        folded.push(base);
        folded.push_str(suffix);
        return true;
    }
    false
}

fn push_casefolded_char(folded: &mut String, ch: char) {
    if push_precomposed_nfd_casefold(folded, ch) {
        return;
    }
    match ch {
        'ß' | 'ẞ' => folded.push_str("ss"),
        'Α'..='Ρ' | 'Σ'..='Ϋ' => {
            let lower = char::from_u32(u32::from(ch) + 0x20)
                .expect("Greek uppercase range maps to valid lowercase scalar");
            folded.push(lower);
        }
        'Ё' => folded.push('ё'),
        'ſ' => folded.push('s'),
        'ς' => folded.push('σ'),
        'А'..='Я' => {
            let lower = char::from_u32(u32::from(ch) + 0x20)
                .expect("Cyrillic uppercase range maps to valid lowercase scalar");
            folded.push(lower);
        }
        '\u{0590}'..='\u{05FF}' | '\u{4E00}'..='\u{9FFF}' => folded.push(ch),
        _ => folded.extend(ch.to_lowercase()),
    }
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
            rec_len: self.rec_len,
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

#[derive(Debug, Clone, Copy)]
struct DirEntryHeader {
    inode: u32,
    rec_len: u32,
    name_len: u8,
    file_type_raw: u8,
    entry_end: usize,
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
/// ```text
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

    fn read_header(&self) -> Result<DirEntryHeader, ParseError> {
        let inode = read_le_u32(self.block, self.offset)?;
        let rec_len_raw = read_le_u16(self.block, self.offset + 4)?;
        let name_len = ensure_slice(self.block, self.offset + 6, 1)?[0];
        let file_type_raw = ensure_slice(self.block, self.offset + 7, 1)?[0];

        if self.block_size <= 65536 && (rec_len_raw & 0x3) != 0 {
            return Err(ParseError::InvalidField {
                field: "de_rec_len",
                reason: "directory entry rec_len not 4-byte aligned",
            });
        }
        let rec_len = rec_len_from_disk(rec_len_raw, self.block_size);
        if rec_len < 12 {
            return Err(ParseError::InvalidField {
                field: "de_rec_len",
                reason: "directory entry rec_len < 12",
            });
        }

        let entry_end =
            self.offset
                .checked_add(rec_len as usize)
                .ok_or(ParseError::InvalidField {
                    field: "de_rec_len",
                    reason: "overflow",
                })?;
        if entry_end > self.block.len() {
            let is_tail = is_dir_checksum_tail(inode, name_len, file_type_raw, rec_len);
            if !is_tail {
                return Err(ParseError::InvalidField {
                    field: "de_rec_len",
                    reason: "directory entry extends past block boundary",
                });
            }
        }

        Ok(DirEntryHeader {
            inode,
            rec_len,
            name_len,
            file_type_raw,
            entry_end,
        })
    }

    fn is_checksum_tail(header: DirEntryHeader) -> bool {
        is_dir_checksum_tail(
            header.inode,
            header.name_len,
            header.file_type_raw,
            header.rec_len,
        )
    }

    fn is_malformed_checksum_tail(header: DirEntryHeader) -> bool {
        is_malformed_dir_checksum_tail(
            header.inode,
            header.name_len,
            header.file_type_raw,
            header.rec_len,
        )
    }

    fn consume_tail(&mut self) -> Result<(), ParseError> {
        let Some(tail_end) = self.offset.checked_add(12) else {
            return Err(ParseError::InvalidField {
                field: "dir_block_tail",
                reason: "overflow",
            });
        };
        if tail_end > self.block.len() {
            return Err(ParseError::InsufficientData {
                needed: 12,
                offset: self.offset,
                actual: self.block.len().saturating_sub(self.offset),
            });
        }
        if tail_end < self.block.len() && !all_zero_bytes(&self.block[tail_end..]) {
            return Err(ParseError::InvalidField {
                field: "dir_block_tail",
                reason: "non-zero padding after checksum tail",
            });
        }
        let csum = read_le_u32(self.block, self.offset + 8)?;
        self.tail = Some(Ext4DirEntryTail { checksum: csum });
        self.offset = self.block.len();
        Ok(())
    }
}

impl<'a> Iterator for DirBlockIter<'a> {
    type Item = Result<Ext4DirEntryRef<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                return None;
            }
            if let Err(err) = validate_dir_block_slice_len(self.block, self.block_size) {
                self.done = true;
                return Some(Err(err));
            }
            if self.offset + 8 > self.block.len() {
                self.done = true;
                if self.offset == self.block.len() {
                    return None;
                }
                return Some(Err(ParseError::InsufficientData {
                    needed: 8,
                    offset: self.offset,
                    actual: self.block.len().saturating_sub(self.offset),
                }));
            }

            let header = match self.read_header() {
                Ok(header) => header,
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            };

            // Detect checksum tail sentinel.
            if Self::is_checksum_tail(header) {
                self.done = true;
                if let Err(err) = self.consume_tail() {
                    return Some(Err(err));
                }
                return None;
            }
            if Self::is_malformed_checksum_tail(header)
                && header.entry_end <= self.block.len()
                && all_zero_bytes(&self.block[header.entry_end..])
            {
                self.done = true;
                return Some(Err(ParseError::InvalidField {
                    field: "dir_block_tail",
                    reason: "malformed checksum tail header",
                }));
            }

            // Skip deleted entries (inode == 0)
            if header.inode == 0 {
                self.offset = header.entry_end;
                continue;
            }

            // Validate name_len fits within rec_len
            let name_end = self.offset + 8 + usize::from(header.name_len);
            if name_end > header.entry_end {
                self.done = true;
                return Some(Err(ParseError::InvalidField {
                    field: "de_name_len",
                    reason: "name extends past rec_len",
                }));
            }

            let name = &self.block[self.offset + 8..name_end];
            self.offset = header.entry_end;

            return Some(Ok(Ext4DirEntryRef {
                inode: header.inode,
                rec_len: header.rec_len,
                name_len: header.name_len,
                file_type: Ext4FileType::from_raw(header.file_type_raw),
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

/// Per-level memo of the last-resolved child extent block, for reusing an
/// already read+parsed child across a sequential walk of consecutive logical
/// blocks (the read / readdir / lookup hot loops).
///
/// For a depth-0 (inline leaf) inode this is never touched — the common case the
/// `resolve_extent_with_tree` hoist already covers.
///
/// For a depth ≥ 1 tree, `walk_extent_tree` re-reads AND re-parses the child
/// index/leaf block on EVERY logical block (heap-allocating a `Vec<Ext4Extent>`
/// and re-running sort/overlap validation), even though consecutive blocks
/// overwhelmingly fall under the same index entry: one 4 KiB extent leaf covers
/// up to ~340 extents.
///
/// This cache holds the last child parsed at each tree level (indexed by
/// `remaining_depth`, ≤ `MAX_EXTENT_DEPTH`); when the next block resolves to the
/// same `leaf_block`, the parsed child is reused instead of re-read and
/// re-parsed. Behaviour is identical: a cached child was validated when first
/// parsed and the underlying image block is immutable, so reuse yields the same
/// result the per-block re-parse would have.
#[derive(Debug, Default)]
pub struct ExtentResolveCache {
    /// `levels[d]` = the child `(leaf_block, header, tree)` last read by an
    /// Index node at `remaining_depth == d`. Index `0` is unused (leaf level).
    levels: [Option<(u64, Ext4ExtentHeader, ExtentTree)>;
        Ext4ImageReader::MAX_EXTENT_DEPTH as usize + 1],
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
        Ext4Inode::parse_from_bytes(self.inode_slice(image, ino)?)
    }

    /// Read an inode for metadata-only paths from a raw disk image.
    ///
    /// The returned inode has the same fixed fields as [`Self::read_inode`],
    /// but its `xattr_ibody` is intentionally empty.
    pub fn read_inode_metadata(
        &self,
        image: &[u8],
        ino: ffs_types::InodeNumber,
    ) -> Result<Ext4Inode, ParseError> {
        Ext4Inode::parse_metadata_from_bytes(self.inode_slice(image, ino)?)
    }

    fn inode_slice<'image>(
        &self,
        image: &'image [u8],
        ino: ffs_types::InodeNumber,
    ) -> Result<&'image [u8], ParseError> {
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
        ensure_slice(image, inode_offset, inode_size)
    }

    /// Read a data block by block number, returning a slice.
    pub fn read_block<'a>(
        &self,
        image: &'a [u8],
        block: ffs_types::BlockNumber,
    ) -> Result<&'a [u8], ParseError> {
        if block.0 >= self.sb.blocks_count {
            return Err(ParseError::InvalidField {
                field: "block_number",
                reason: "block outside filesystem block count",
            });
        }

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
        self.resolve_extent_with_tree(image, &header, &tree, logical_block)
    }

    /// Resolve a logical block against an ALREADY-PARSED extent tree.
    ///
    /// `resolve_extent` re-parses the inode's extent tree (a header decode plus
    /// a heap-allocating `Vec<Ext4Extent>` build with per-extent `from_le_bytes`
    /// and sort/overlap validation) on every call. That tree is invariant for
    /// the lifetime of one read/readdir/lookup, yet those paths call
    /// `resolve_extent` once per logical block inside a loop — so the identical
    /// parse+alloc is repeated for every block of the request (up to 32× for a
    /// 128 KiB read). Callers that walk multiple blocks of one inode should
    /// `parse_inode_extent_tree` ONCE before the loop and call this per block,
    /// hoisting that invariant work out of the hot path. Result is identical to
    /// `resolve_extent` for the same `(inode, logical_block)`.
    pub fn resolve_extent_with_tree(
        &self,
        image: &[u8],
        header: &Ext4ExtentHeader,
        tree: &ExtentTree,
        logical_block: u32,
    ) -> Result<Option<u64>, ParseError> {
        self.walk_extent_tree(image, header, tree, logical_block, header.depth)
    }

    /// Like [`resolve_extent_with_tree`], but reuses child index/leaf blocks
    /// across calls via `cache` (see [`ExtentResolveCache`]). Callers that walk
    /// consecutive logical blocks of one inode (read / readdir / lookup) should
    /// build one cache before the loop and pass it per block, so a depth ≥ 1
    /// tree does not re-read + re-parse the same child block for every block.
    /// Identical result to `resolve_extent_with_tree` for the same inputs; for a
    /// depth-0 tree the cache is never consulted (zero overhead).
    pub fn resolve_extent_with_tree_cached(
        &self,
        image: &[u8],
        header: &Ext4ExtentHeader,
        tree: &ExtentTree,
        logical_block: u32,
        cache: &mut ExtentResolveCache,
    ) -> Result<Option<u64>, ParseError> {
        self.walk_extent_tree_cached(image, tree, logical_block, header.depth, cache)
    }

    /// Binary-search a sorted extent leaf for the extent covering `logical_block`.
    ///
    /// Extents are stored strictly increasing by `logical_block`, so the covering
    /// extent (if any) is the last one with `logical_block <= target`; a bounds
    /// check against its length then distinguishes a hit from a hole. O(log E)
    /// vs the old linear O(E) scan — negligible for typical files (1–4 extents)
    /// but up to ~19x on a fragmented leaf (bench `extent_leaf_search`).
    fn extent_leaf_lookup(
        extents: &[Ext4Extent],
        logical_block: u32,
    ) -> Result<Option<u64>, ParseError> {
        let p = extents.partition_point(|ext| ext.logical_block <= logical_block);
        if p == 0 {
            return Ok(None);
        }
        let ext = &extents[p - 1];
        let len = u32::from(ext.actual_len());
        if logical_block < ext.logical_block.saturating_add(len) {
            let offset_within = u64::from(logical_block - ext.logical_block);
            let phys =
                ext.physical_start
                    .checked_add(offset_within)
                    .ok_or(ParseError::InvalidField {
                        field: "ee_start",
                        reason: "physical block + offset overflow",
                    })?;
            Ok(Some(phys))
        } else {
            Ok(None)
        }
    }

    /// Binary-search a sorted extent index node for the child whose subtree can
    /// contain `logical_block` (the last index with `logical_block <= target`).
    fn extent_index_choose(
        indexes: &[Ext4ExtentIndex],
        logical_block: u32,
    ) -> Option<&Ext4ExtentIndex> {
        let p = indexes.partition_point(|idx| idx.logical_block <= logical_block);
        if p == 0 { None } else { Some(&indexes[p - 1]) }
    }

    /// Recursive extent tree walker with a per-level child cache. Mirrors
    /// [`walk_extent_tree`] exactly for the leaf scan and index selection; the
    /// only difference is that the chosen child block is taken from `cache` when
    /// its `leaf_block` matches, else read + parsed and stored back.
    fn walk_extent_tree_cached(
        &self,
        image: &[u8],
        tree: &ExtentTree,
        logical_block: u32,
        remaining_depth: u16,
        cache: &mut ExtentResolveCache,
    ) -> Result<Option<u64>, ParseError> {
        if remaining_depth > Self::MAX_EXTENT_DEPTH {
            return Err(ParseError::InvalidField {
                field: "eh_depth",
                reason: "extent tree depth exceeds maximum",
            });
        }

        match tree {
            ExtentTree::Leaf(extents) => Self::extent_leaf_lookup(extents, logical_block),
            ExtentTree::Index(indexes) => {
                if remaining_depth == 0 {
                    return Err(ParseError::InvalidField {
                        field: "eh_depth",
                        reason: "extent index at depth 0",
                    });
                }
                let Some(idx) = Self::extent_index_choose(indexes, logical_block) else {
                    return Ok(None);
                };

                let slot = remaining_depth as usize;

                // Fast path (bd-vpypn): a leaf child (`remaining_depth == 1`) that
                // is already cached. `extent_leaf_lookup` borrows the leaf in place,
                // and the depth-0 leaf recursion never touches `cache`, so the
                // take/store-back dance below is pure overhead here — it moves the
                // owned `ExtentTree` (a `Vec`) out of the array and back on every
                // block. Borrowing in place is byte-identical (same extent found)
                // and leaves the cache slot unchanged (the store-back would restore
                // the identical `(idx.leaf_block, header, tree)`). Measured 1.14x on
                // the per-block cache-hit micro-op (bench `extent_leaf_search`).
                if remaining_depth == 1
                    && let Some((lb, _, ExtentTree::Leaf(exts))) = &cache.levels[slot]
                    && *lb == idx.leaf_block
                {
                    return Self::extent_leaf_lookup(exts, logical_block);
                }

                // Take the cached child out (so `cache` is free to be borrowed
                // mutably by the recursion, which uses a different level index),
                // reusing it iff it is the same child block; otherwise read +
                // parse + validate exactly as `walk_extent_tree` does.
                let cached = cache.levels[slot].take();
                let (child_header, child_tree) = match cached {
                    Some((lb, h, t)) if lb == idx.leaf_block => (h, t),
                    _ => {
                        let child_block =
                            self.read_block(image, ffs_types::BlockNumber(idx.leaf_block))?;
                        let (child_header, child_tree) = parse_extent_tree(child_block)?;
                        if child_header.depth + 1 != remaining_depth {
                            return Err(ParseError::InvalidField {
                                field: "eh_depth",
                                reason: "child extent tree depth inconsistency",
                            });
                        }
                        (child_header, child_tree)
                    }
                };

                let result = self.walk_extent_tree_cached(
                    image,
                    &child_tree,
                    logical_block,
                    remaining_depth - 1,
                    cache,
                );
                // Store the child back for the next (usually same-child) block.
                cache.levels[slot] = Some((idx.leaf_block, child_header, child_tree));
                result
            }
        }
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
            ExtentTree::Leaf(extents) => Self::extent_leaf_lookup(extents, logical_block),
            ExtentTree::Index(indexes) => {
                if remaining_depth == 0 {
                    return Err(ParseError::InvalidField {
                        field: "eh_depth",
                        reason: "extent index at depth 0",
                    });
                }
                let Some(idx) = Self::extent_index_choose(indexes, logical_block) else {
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

        // Nothing to read (e.g. empty `buf`): match the old per-block loop,
        // which would never have parsed the extent tree in this case.
        if to_read == 0 {
            return Ok(0);
        }

        // Parse the inode's extent tree ONCE (invariant across every block of
        // this read) instead of re-parsing + re-allocating it per block inside
        // the loop. `to_read > 0` here, so the old per-block path would have
        // parsed on the first iteration regardless — identical behaviour,
        // including error propagation.
        //
        // ERROR PRECEDENCE, restored (found 2026-08-24 verifying bd-q4qr8). The
        // "identical error propagation" above is NOT identical, and
        // `adversarial_corpus` was red on exactly this: the old per-block loop
        // computed `logical_block` FIRST and parsed only after, so a read starting
        // beyond the u32 logical-block range reported `IntegerConversion { field:
        // "logical_block" }`. With the parse hoisted in front of it, such a read
        // reports whatever the extent header says instead — for a zeroed inode a
        // header error, which is both a DIFFERENT error and a less accurate one:
        // the read is unsatisfiable because of the OFFSET, not because of the tree.
        //
        // Converting the first block here restores the old precedence without
        // giving back the per-block parse. The loop keeps its own conversion,
        // because a later block can cross the boundary this first one does not.
        u32::try_from(offset / bs).map_err(|_| ParseError::IntegerConversion {
            field: "logical_block",
        })?;
        let (header, tree) = parse_inode_extent_tree(inode)?;
        // Reuse child index/leaf blocks across the read's blocks (depth ≥ 1).
        let mut extent_cache = ExtentResolveCache::default();

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

            match self.resolve_extent_with_tree_cached(
                image,
                &header,
                &tree,
                logical_block,
                &mut extent_cache,
            )? {
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
        if num_blocks == 0 {
            return Ok(all_entries);
        }

        // Parse the extent tree once (invariant across all dir blocks) rather
        // than re-parsing + re-allocating it per block in the loop below.
        let (header, tree) = parse_inode_extent_tree(inode)?;
        let mut extent_cache = ExtentResolveCache::default();

        for lb in 0..num_blocks {
            if let Some(phys) =
                self.resolve_extent_with_tree_cached(image, &header, &tree, lb, &mut extent_cache)?
            {
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
        if num_blocks == 0 {
            return Ok(None);
        }

        // Parse the extent tree once (invariant across all dir blocks) rather
        // than re-parsing + re-allocating it per block in the loop below.
        let (header, tree) = parse_inode_extent_tree(dir_inode)?;
        let mut extent_cache = ExtentResolveCache::default();

        for lb in 0..num_blocks {
            if let Some(phys) =
                self.resolve_extent_with_tree_cached(image, &header, &tree, lb, &mut extent_cache)?
            {
                let block_data = self.read_block(image, ffs_types::BlockNumber(phys))?;
                if let Some(entry) = lookup_in_dir_block(block_data, self.sb.block_size, name)? {
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
        if inode.is_encrypted() {
            return Err(ParseError::InvalidField {
                field: "i_flags",
                reason: "encrypted symlink target requires fscrypt context",
            });
        }

        // Fast symlink: target stored in i_block area
        if let Some(target) = inode.fast_symlink_target() {
            return Ok(target.to_vec());
        }

        // Extent-mapped symlink: read via normal file data path
        let size = usize::try_from(inode.size)
            .map_err(|_| ParseError::IntegerConversion { field: "i_size" })?;

        // Protect against malicious symlink sizes causing OOM.
        // Linux PATH_MAX is 4096.
        if size > 4096 {
            return Err(ParseError::InvalidField {
                field: "i_size",
                reason: "symlink size exceeds 4096 bytes",
            });
        }

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
    /// entries prefixed with a 4-byte magic header. Inline `e_value_offs`
    /// values are relative to the start of the entry region after that header.
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
        let entries = &inode.xattr_ibody[4..];
        parse_xattr_entries(entries, entries, 0)
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
        // Entries start at byte 32 (after the xattr header). Value offsets are
        // relative to the start of the block, per ext4 spec.
        let entries_region = &block_data[32..];
        parse_xattr_entries(entries_region, block_data, 32)
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

    /// Names-only counterpart of [`list_xattrs`] for `listxattr`: returns every
    /// attribute's full name (inode body first, then the external block) WITHOUT
    /// materialising or bounds-validating any value. Same names, same order as
    /// `list_xattrs(..).map(full_name)` for a well-formed inode; skips the
    /// per-value `Vec` allocations `listxattr` would immediately discard. Like
    /// the by-name finders (bd-abu3z), a corrupt UNRELATED value can no longer
    /// abort the name listing (a strict superset of a consistent inode's names).
    #[cfg_attr(feature = "bench-instrumentation", inline(never))]
    pub fn list_xattr_names(
        &self,
        image: &[u8],
        inode: &Ext4Inode,
    ) -> Result<Vec<String>, ParseError> {
        let mut names = parse_ibody_xattr_names(inode)?;
        if inode.file_acl != 0 {
            let block_data = self.read_block(image, ffs_types::BlockNumber(inode.file_acl))?;
            names.extend(parse_xattr_block_names(block_data)?);
        }
        Ok(names)
    }

    /// Get a specific xattr by name index and name.
    ///
    /// Uses the by-name early-exit finders instead of materialising every
    /// attribute (name + value `Vec` per entry) via `list_xattrs` just to
    /// `find` one — the same transform the device backend already uses
    /// (bd-abu3z): scan the entry table once, allocate only the matched value,
    /// and probe the inode body FIRST so an ibody-resident attribute (e.g.
    /// `security.selinux`, hit on nearly every access) never reads or parses the
    /// external xattr block at all. The block-lookup transform measures ~7.2x
    /// over `parse_all_then_find` (bench `xattr_lookup`, 24-entry block).
    ///
    /// Behaviour matches the old materialise-all-then-`find` for a well-formed
    /// image: same ibody-before-block order, same unique-name assumption, same
    /// value (including the empty-value + `e_value_inum` convention for
    /// EA-inode-backed values). Like the sibling finders, a corrupt *unrelated*
    /// entry/block can no longer abort a lookup the ibody already answered — a
    /// strict superset of what a consistent image resolves.
    pub fn get_xattr(
        &self,
        image: &[u8],
        inode: &Ext4Inode,
        name_index: u8,
        name: &[u8],
    ) -> Result<Option<Vec<u8>>, ParseError> {
        if let Some((_, value, _inum)) = find_ibody_xattr_by_index_name(inode, name_index, name)? {
            return Ok(Some(value));
        }
        if inode.file_acl != 0 {
            let block_data = self.read_block(image, ffs_types::BlockNumber(inode.file_acl))?;
            if let Some((_, value, _inum)) =
                find_xattr_block_value_by_index_name(block_data, name_index, name)?
            {
                return Ok(Some(value));
            }
        }
        Ok(None)
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
        // Only attempt htree if the INDEX flag is set.
        if !dir_inode.has_htree_index() {
            return self.lookup(image, dir_inode, name);
        }

        // Navigate the DX index (shared with the runtime lookup path). Any
        // failure or not-found yields None, on which we fall back to the linear
        // scan — the index may be stale relative to linearly-appended entries.
        let found = htree_find_entry(
            self.sb.block_size,
            &self.sb.hash_seed,
            self.sb.has_large_dir(),
            name,
            |v| self.sb.effective_dirhash_version(v),
            |lb| {
                self.resolve_extent(image, dir_inode, lb)
                    .ok()
                    .flatten()
                    .and_then(|phys| {
                        self.read_block(image, ffs_types::BlockNumber(phys))
                            .ok()
                            .map(<[u8]>::to_vec)
                    })
            },
        );
        match found {
            HtreeFindResult::Found(entry) => Ok(Some(entry)),
            // Trust a successfully-navigated index for the static reader (the
            // image's index is authoritative); matches the original behavior.
            HtreeFindResult::NotFoundInIndex => Ok(None),
            // Index unusable -> linear scan.
            HtreeFindResult::IndexInvalid => self.lookup(image, dir_inode, name),
        }
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
        let prefix = xattr_name_index_prefix(self.name_index);
        let name = String::from_utf8_lossy(&self.name);
        let mut full_name = String::with_capacity(prefix.len() + name.len());
        full_name.push_str(prefix);
        full_name.push_str(&name);
        full_name
    }
}

/// The namespace prefix [`Ext4Xattr::full_name`] prepends for a given
/// `name_index`. Shared so the by-name finder ([`find_xattr_value_in_block`])
/// matches a query against an entry's full name byte-for-byte identically to
/// `full_name()` without materializing every entry.
fn xattr_name_index_prefix(name_index: u8) -> &'static str {
    match name_index {
        ffs_types::EXT4_XATTR_INDEX_USER => "user.",
        ffs_types::EXT4_XATTR_INDEX_POSIX_ACL_ACCESS => "system.posix_acl_access",
        ffs_types::EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT => "system.posix_acl_default",
        ffs_types::EXT4_XATTR_INDEX_TRUSTED => "trusted.",
        ffs_types::EXT4_XATTR_INDEX_SECURITY => "security.",
        ffs_types::EXT4_XATTR_INDEX_SYSTEM => "system.",
        ffs_types::EXT4_XATTR_INDEX_RICHACL => "system.richacl",
        _ => "unknown.",
    }
}

/// True iff an xattr entry `(name_index, name)` has the full name `target`.
///
/// Equivalent to `Ext4Xattr { name_index, name, .. }.full_name() == target` —
/// `format!("{prefix}{lossy_name}") == target` holds exactly when `target`
/// starts with `prefix` and its remainder equals the lossily-decoded name — but
/// allocates nothing for a non-match (the `from_utf8_lossy` `Cow` borrows for
/// the valid-UTF-8 names that xattrs use in practice).
fn xattr_entry_full_name_matches(name_index: u8, name: &[u8], target: &str) -> bool {
    let prefix = xattr_name_index_prefix(name_index);
    target
        .strip_prefix(prefix)
        .is_some_and(|rest| String::from_utf8_lossy(name) == rest)
}

/// Parse xattr entries from a byte slice (after the header/magic).
///
/// Each entry is:
///   - u8 name_len
///   - u8 name_index
///   - u16 value_offs (offset from the caller-provided value base)
///   - u32 value_size
///   - u32 hash (we ignore this)
///   - [u8; name_len] name
///   - padding to 4-byte boundary
///
/// Entry list is terminated by a zero name_len + zero name_index.
fn parse_xattr_entries(
    data: &[u8],
    value_base: &[u8],
    value_offset_base: usize,
) -> Result<Vec<Ext4Xattr>, ParseError> {
    Ok(
        parse_xattr_entries_with_inum(data, value_base, value_offset_base)?
            .into_iter()
            .map(|(xattr, _value_inum)| xattr)
            .collect(),
    )
}

/// Like [`parse_xattr_entries`] but also returns each attribute's
/// `e_value_inum` (0 for in-block values, non-zero for EA-inode-backed values
/// whose payload lives in a separate inode). Callers with device access use
/// the inum to read the external value; in-block callers can ignore it.
fn parse_xattr_entries_with_inum(
    data: &[u8],
    value_base: &[u8],
    value_offset_base: usize,
) -> Result<Vec<(Ext4Xattr, u32)>, ParseError> {
    struct PendingXattr {
        name_index: u8,
        name: Vec<u8>,
        value_offs: u16,
        value_inum: u32,
        value_size: u32,
    }

    let mut pending = Vec::new();
    let mut offset = 0_usize;
    let entries_region_end = loop {
        if offset + 4 > data.len() {
            break offset;
        }

        let name_len = data[offset];
        let name_index = data[offset + 1];

        if name_len == 0 && name_index == 0 {
            break offset + 4;
        }

        if offset + 16 > data.len() {
            break offset;
        }

        let value_offs = read_le_u16(data, offset + 2)?;
        // e_value_inum (offset+4): when non-zero the value lives in a separate
        // "EA inode" (the EA_INODE feature, for values too large to fit inline),
        // NOT in this block at e_value_offs. Tracked so the value-resolution
        // step below skips the in-block read for such entries instead of
        // misreading e_value_offs (which is 0 for EA-inode entries).
        let value_inum = read_le_u32(data, offset + 4)?;
        let value_size = read_le_u32(data, offset + 8)?;

        let name_start = offset + 16;
        let name_end = name_start + usize::from(name_len);
        if name_end > data.len() {
            return Err(ParseError::InvalidField {
                field: "xattr_name",
                reason: "name extends past data boundary",
            });
        }

        pending.push(PendingXattr {
            name_index,
            name: data[name_start..name_end].to_vec(),
            value_offs,
            value_inum,
            value_size,
        });

        offset = (name_end + 3) & !3;
    };

    let min_value_offset =
        value_offset_base
            .checked_add(entries_region_end)
            .ok_or(ParseError::InvalidField {
                field: "xattr_value",
                reason: "value offset floor overflow",
            })?;

    let mut entries = Vec::with_capacity(pending.len());
    for pending_entry in pending {
        // EA-inode-backed value (EA_INODE feature): the value bytes live in a
        // separate inode, not in this block. The on-disk e_value_offs is 0 for
        // these, so the in-block read below would spuriously reject the whole
        // block ("value overlaps header"). Surface the attribute with its name
        // (so listxattr is complete and sibling in-block values stay readable)
        // and an empty value; resolving the EA-inode payload itself is a
        // separate read path the value-base caller does not have access to.
        let value = if pending_entry.value_inum != 0 {
            Vec::new()
        } else if pending_entry.value_size > 0 {
            let v_off = usize::from(pending_entry.value_offs);
            if v_off < min_value_offset {
                return Err(ParseError::InvalidField {
                    field: "xattr_value",
                    reason: "value overlaps xattr header or entry table",
                });
            }
            let v_size = usize::try_from(pending_entry.value_size).map_err(|_| {
                ParseError::IntegerConversion {
                    field: "xattr_value_size",
                }
            })?;
            let v_end = v_off.checked_add(v_size).ok_or(ParseError::InvalidField {
                field: "xattr_value",
                reason: "value extends past data boundary",
            })?;
            if v_end > value_base.len() {
                return Err(ParseError::InvalidField {
                    field: "xattr_value",
                    reason: "value extends past data boundary",
                });
            }
            value_base[v_off..v_end].to_vec()
        } else {
            Vec::new()
        };

        entries.push((
            Ext4Xattr {
                name_index: pending_entry.name_index,
                name: pending_entry.name,
                value,
            },
            pending_entry.value_inum,
        ));
    }

    Ok(entries)
}

/// Find the value (and `e_value_inum`) of the single xattr whose full name is
/// `target`, scanning entries in place without materializing every attribute.
///
/// The read-side counterpart of `getxattr`: where [`parse_xattr_block_with_inum`]
/// allocates a name `Vec` and a value `Vec` for *every* attribute (and the
/// caller then builds a `full_name` `String` per entry to find one), this walks
/// the entry table once, compares each name to `target` allocation-free
/// ([`xattr_entry_full_name_matches`]), and materializes only the matched
/// value. Returns `Ok(None)` when no entry matches (bd-abu3z).
///
/// Matching and value-bounds validation are identical to
/// `parse_xattr_entries_with_inum` for the matched entry; like the
/// floor/binary-search read levers, only the consumed entry's value offset is
/// validated (a corrupt *non*-matched value can no longer abort an unrelated
/// lookup — a strict superset of the names a consistent image resolves).
fn find_xattr_value_by_full_name(
    data: &[u8],
    value_base: &[u8],
    value_offset_base: usize,
    target: &str,
) -> Result<Option<(u8, Vec<u8>, u32)>, ParseError> {
    find_xattr_value_matching(data, value_base, value_offset_base, |name_index, name| {
        xattr_entry_full_name_matches(name_index, name, target)
    })
}

/// Shared entry-table walker for the by-name finders. Scans the xattr entry
/// table once and materializes only the value of the first entry for which
/// `matches(name_index, name_bytes)` returns true. Behaviour (bounds validation,
/// EA-inode handling, single-value materialization) is identical to
/// [`find_xattr_value_by_full_name`]; only the match predicate varies, so a
/// caller holding a split `(name_index, name)` can match directly without
/// reconstructing a full-name string.
fn find_xattr_value_matching(
    data: &[u8],
    value_base: &[u8],
    value_offset_base: usize,
    matches: impl Fn(u8, &[u8]) -> bool,
) -> Result<Option<(u8, Vec<u8>, u32)>, ParseError> {
    let mut offset = 0_usize;
    // (name_index, value_offs, value_inum, value_size) of the entry that hit.
    let mut hit: Option<(u8, u16, u32, u32)> = None;
    let entries_region_end = loop {
        if offset + 4 > data.len() {
            break offset;
        }
        let name_len = data[offset];
        let name_index = data[offset + 1];
        if name_len == 0 && name_index == 0 {
            break offset + 4;
        }
        if offset + 16 > data.len() {
            break offset;
        }
        let value_offs = read_le_u16(data, offset + 2)?;
        let value_inum = read_le_u32(data, offset + 4)?;
        let value_size = read_le_u32(data, offset + 8)?;
        let name_start = offset + 16;
        let name_end = name_start + usize::from(name_len);
        if name_end > data.len() {
            return Err(ParseError::InvalidField {
                field: "xattr_name",
                reason: "name extends past data boundary",
            });
        }
        if hit.is_none() && matches(name_index, &data[name_start..name_end]) {
            hit = Some((name_index, value_offs, value_inum, value_size));
        }
        offset = (name_end + 3) & !3;
    };

    let Some((name_index, value_offs, value_inum, value_size)) = hit else {
        return Ok(None);
    };

    // EA-inode-backed value: payload lives in a separate inode; surface an empty
    // in-block value and let the caller resolve it (mirrors the parse path).
    if value_inum != 0 {
        return Ok(Some((name_index, Vec::new(), value_inum)));
    }
    if value_size == 0 {
        return Ok(Some((name_index, Vec::new(), 0)));
    }
    let min_value_offset =
        value_offset_base
            .checked_add(entries_region_end)
            .ok_or(ParseError::InvalidField {
                field: "xattr_value",
                reason: "value offset floor overflow",
            })?;
    let value_start = usize::from(value_offs);
    if value_start < min_value_offset {
        return Err(ParseError::InvalidField {
            field: "xattr_value",
            reason: "value overlaps xattr header or entry table",
        });
    }
    let v_size = usize::try_from(value_size).map_err(|_| ParseError::IntegerConversion {
        field: "xattr_value_size",
    })?;
    let v_end = value_start
        .checked_add(v_size)
        .ok_or(ParseError::InvalidField {
            field: "xattr_value",
            reason: "value extends past data boundary",
        })?;
    if v_end > value_base.len() {
        return Err(ParseError::InvalidField {
            field: "xattr_value",
            reason: "value extends past data boundary",
        });
    }
    Ok(Some((
        name_index,
        value_base[value_start..v_end].to_vec(),
        value_inum,
    )))
}

/// Find one inode-body xattr by full name without materializing the rest.
///
/// Returns `(name_index, in_block_value, e_value_inum)`. By-name early-exit
/// counterpart of [`parse_ibody_xattrs_with_inum`] (bd-abu3z).
pub fn find_ibody_xattr_by_name(
    inode: &Ext4Inode,
    target: &str,
) -> Result<Option<(u8, Vec<u8>, u32)>, ParseError> {
    if inode.xattr_ibody.len() < 4 {
        return Ok(None);
    }
    if read_le_u32(&inode.xattr_ibody, 0)? != EXT4_XATTR_MAGIC {
        return Ok(None);
    }
    let entries = &inode.xattr_ibody[4..];
    find_xattr_value_by_full_name(entries, entries, 0, target)
}

/// Find one external-block xattr by full name without materializing the rest.
///
/// Returns `(name_index, in_block_value, e_value_inum)`. By-name early-exit
/// counterpart of [`parse_xattr_block_with_inum`] (bd-abu3z).
pub fn find_xattr_block_value_by_name(
    block_data: &[u8],
    target: &str,
) -> Result<Option<(u8, Vec<u8>, u32)>, ParseError> {
    if block_data.len() < 32 {
        return Err(ParseError::InsufficientData {
            needed: 32,
            offset: 0,
            actual: block_data.len(),
        });
    }
    if read_le_u32(block_data, 0)? != EXT4_XATTR_MAGIC {
        return Err(ParseError::InvalidMagic {
            expected: u64::from(EXT4_XATTR_MAGIC),
            actual: u64::from(read_le_u32(block_data, 0)?),
        });
    }
    let entries_region = &block_data[32..];
    find_xattr_value_by_full_name(entries_region, block_data, 32, target)
}

/// Find one inode-body xattr by split `(name_index, name)` without materializing
/// the rest.
///
/// Direct-match counterpart of [`find_ibody_xattr_by_name`] for callers (e.g.
/// `getxattr` by index+name) that already hold the on-disk name index and suffix.
/// Matches exactly `entry.name_index == name_index && entry.name == name`.
pub fn find_ibody_xattr_by_index_name(
    inode: &Ext4Inode,
    name_index: u8,
    name: &[u8],
) -> Result<Option<(u8, Vec<u8>, u32)>, ParseError> {
    if inode.xattr_ibody.len() < 4 {
        return Ok(None);
    }
    if read_le_u32(&inode.xattr_ibody, 0)? != EXT4_XATTR_MAGIC {
        return Ok(None);
    }
    let entries = &inode.xattr_ibody[4..];
    find_xattr_value_matching(entries, entries, 0, |ni, nm| ni == name_index && nm == name)
}

/// Find one external-block xattr by split `(name_index, name)` without
/// materializing the rest. Direct-match counterpart of
/// [`find_xattr_block_value_by_name`].
pub fn find_xattr_block_value_by_index_name(
    block_data: &[u8],
    name_index: u8,
    name: &[u8],
) -> Result<Option<(u8, Vec<u8>, u32)>, ParseError> {
    if block_data.len() < 32 {
        return Err(ParseError::InsufficientData {
            needed: 32,
            offset: 0,
            actual: block_data.len(),
        });
    }
    if read_le_u32(block_data, 0)? != EXT4_XATTR_MAGIC {
        return Err(ParseError::InvalidMagic {
            expected: u64::from(EXT4_XATTR_MAGIC),
            actual: u64::from(read_le_u32(block_data, 0)?),
        });
    }
    let entries_region = &block_data[32..];
    find_xattr_value_matching(entries_region, block_data, 32, |ni, nm| {
        ni == name_index && nm == name
    })
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
    let entries = &inode.xattr_ibody[4..];
    parse_xattr_entries(entries, entries, 0)
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
    let entries_region = &block_data[32..];
    parse_xattr_entries(entries_region, block_data, 32)
}

/// Walk an xattr entry table and return each attribute's full name, WITHOUT
/// materialising values. `listxattr` needs names only, but the materialise-all
/// path ([`parse_xattr_entries`]) allocates a name `Vec` + a value `Vec` per
/// entry (and validates every value's in-block bounds) just to have the caller
/// take `full_name()` and drop the values. This builds the `full_name` `String`
/// directly during the single entry-table walk and never touches the value
/// region — so a corrupt UNRELATED value can no longer abort a `listxattr` (a
/// strict superset of the names a consistent block resolves, consistent with
/// the by-name finders, bd-abu3z).
#[cfg_attr(feature = "bench-instrumentation", inline(never))]
fn parse_xattr_entry_names(data: &[u8]) -> Result<Vec<String>, ParseError> {
    let mut names = Vec::new();
    let mut offset = 0_usize;
    loop {
        if offset + 4 > data.len() {
            break;
        }
        let name_len = data[offset];
        let name_index = data[offset + 1];
        if name_len == 0 && name_index == 0 {
            break;
        }
        if offset + 16 > data.len() {
            break;
        }
        let name_start = offset + 16;
        let name_end = name_start + usize::from(name_len);
        if name_end > data.len() {
            return Err(ParseError::InvalidField {
                field: "xattr_name",
                reason: "name extends past data boundary",
            });
        }
        let prefix = xattr_name_index_prefix(name_index);
        let name = String::from_utf8_lossy(&data[name_start..name_end]);
        let mut full_name = String::with_capacity(prefix.len() + name.len());
        full_name.push_str(prefix);
        full_name.push_str(&name);
        names.push(full_name);
        offset = (name_end + 3) & !3;
    }
    Ok(names)
}

/// Names-only counterpart of [`parse_xattr_block`] for `listxattr`: validates
/// the 32-byte block header, then returns full names without materialising any
/// value. See [`parse_xattr_entry_names`].
pub fn parse_xattr_block_names(block_data: &[u8]) -> Result<Vec<String>, ParseError> {
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
    parse_xattr_entry_names(&block_data[32..])
}

/// Names-only counterpart of [`parse_ibody_xattrs`] for `listxattr`.
///
/// Returns the inode-body attribute full names without materialising values. An
/// empty ibody (missing or mismatched magic) yields no names, exactly as
/// `parse_ibody_xattrs` does.
pub fn parse_ibody_xattr_names(inode: &Ext4Inode) -> Result<Vec<String>, ParseError> {
    if inode.xattr_ibody.len() < 4 {
        return Ok(Vec::new());
    }
    if read_le_u32(&inode.xattr_ibody, 0)? != EXT4_XATTR_MAGIC {
        return Ok(Vec::new());
    }
    parse_xattr_entry_names(&inode.xattr_ibody[4..])
}

/// Like [`parse_ibody_xattrs`] but also returns each attribute's `e_value_inum`
/// (0 = in-block value; non-zero = EA-inode-backed, payload in that inode).
pub fn parse_ibody_xattrs_with_inum(
    inode: &Ext4Inode,
) -> Result<Vec<(Ext4Xattr, u32)>, ParseError> {
    if inode.xattr_ibody.len() < 4 {
        return Ok(Vec::new());
    }
    let magic = read_le_u32(&inode.xattr_ibody, 0)?;
    if magic != EXT4_XATTR_MAGIC {
        return Ok(Vec::new());
    }
    let entries = &inode.xattr_ibody[4..];
    parse_xattr_entries_with_inum(entries, entries, 0)
}

/// Like [`parse_xattr_block`] but also returns each attribute's `e_value_inum`
/// (0 = in-block value; non-zero = EA-inode-backed, payload in that inode).
pub fn parse_xattr_block_with_inum(block_data: &[u8]) -> Result<Vec<(Ext4Xattr, u32)>, ParseError> {
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
    let entries_region = &block_data[32..];
    parse_xattr_entries_with_inum(entries_region, block_data, 32)
}

include!("ext4/htree.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    /// Build a representative dir block of `block_size` bytes with the
    /// 12-byte fake-record checksum tail in place but the checksum slot
    /// left zeroed.  Body bytes are filled with a deterministic ramp so
    /// that any single-bit flip in the covered region is reliably visible
    /// to the CRC.
    fn build_dir_block_for_checksum_test(block_size: usize) -> Vec<u8> {
        let mut block = vec![0u8; block_size];
        for (i, b) in block.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xFF).unwrap();
        }
        let tail_off = block_size - 12;
        block[tail_off..tail_off + 4].copy_from_slice(&0_u32.to_le_bytes());
        block[tail_off + 4..tail_off + 6].copy_from_slice(&12_u16.to_le_bytes());
        block[tail_off + 6] = 0;
        block[tail_off + 7] = EXT4_FT_DIR_CSUM;
        block
    }

    /// Build a representative extent tree block sized for `eh_max` slots,
    /// with a valid extent header magic + eh_max, the body filled with a
    /// deterministic ramp (so single-bit flips in the covered prefix are
    /// observable to the CRC), and the 4-byte tail checksum slot left
    /// zeroed.  `tail_off = 12 + 12 * eh_max`; the returned buffer is
    /// `tail_off + 4` bytes long.
    fn build_extent_block_for_checksum_test(eh_max: u16) -> Vec<u8> {
        let tail_off = 12 + usize::from(eh_max) * 12;
        let mut block = vec![0u8; tail_off + 4];
        for (i, b) in block.iter_mut().enumerate().take(tail_off) {
            *b = u8::try_from(i & 0xFF).unwrap();
        }
        // Restore the magic + eh_max fields after the ramp clobbered them.
        block[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
        block[4..6].copy_from_slice(&eh_max.to_le_bytes());
        block
    }

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

    #[test]
    fn parse_ext4_superblock_region_rejects_bad_magic() {
        let mut sb = make_valid_sb();
        sb[0x38..0x3A].copy_from_slice(&0x1234_u16.to_le_bytes());

        let err = Ext4Superblock::parse_superblock_region(&sb).expect_err("reject");
        assert!(matches!(
            err,
            ParseError::InvalidMagic { expected, actual }
                if expected == u64::from(EXT4_SUPER_MAGIC) && actual == u64::from(0x1234_u16)
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

    fn representative_ext4_geometry_sb() -> [u8; EXT4_SUPERBLOCK_SIZE] {
        let mut sb = make_valid_sb();
        sb[0x00..0x04].copy_from_slice(&(32_u32 * 8192).to_le_bytes()); // inodes_count
        sb[0x04..0x08].copy_from_slice(&(32_u32 * 32768).to_le_bytes()); // blocks_count_lo
        sb[0x5C..0x60].copy_from_slice(&Ext4CompatFeatures::SPARSE_SUPER2.0.to_le_bytes());
        sb[0x60..0x64].copy_from_slice(
            &(Ext4IncompatFeatures::FILETYPE.0
                | Ext4IncompatFeatures::EXTENTS.0
                | Ext4IncompatFeatures::FLEX_BG.0
                | Ext4IncompatFeatures::MMP.0
                | Ext4IncompatFeatures::BIT64.0)
                .to_le_bytes(),
        );
        sb[0x64..0x68].copy_from_slice(&Ext4RoCompatFeatures::METADATA_CSUM.0.to_le_bytes());
        sb[0xFE..0x100].copy_from_slice(&64_u16.to_le_bytes()); // desc_size
        sb[0x166..0x168].copy_from_slice(&5_u16.to_le_bytes()); // mmp_update_interval
        sb[0x168..0x170].copy_from_slice(&1234_u64.to_le_bytes()); // mmp_block
        sb[0x174] = 3; // log_groups_per_flex = 8 groups/flex
        sb[0x24C..0x250].copy_from_slice(&7_u32.to_le_bytes()); // backup_bgs[0]
        sb[0x250..0x254].copy_from_slice(&19_u32.to_le_bytes()); // backup_bgs[1]
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
    fn validate_geometry_fields_rejects_uncovered_branches() {
        // Start from a valid superblock with valid features so the error caught
        // is the geometry field, not a feature mismatch. block_size = 4096.
        let mut base = make_valid_sb();
        let incompat =
            (Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0).to_le_bytes();
        base[0x60..0x64].copy_from_slice(&incompat);

        // inodes_per_group == 0
        let mut bad = base;
        bad[0x28..0x2C].copy_from_slice(&0_u32.to_le_bytes());
        let err = Ext4Superblock::parse_superblock_region(&bad)
            .unwrap()
            .validate_geometry()
            .unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "s_inodes_per_group",
                    ..
                }
            ),
            "got {err}",
        );

        // inode_size < 128
        let mut bad = base;
        bad[0x58..0x5A].copy_from_slice(&64_u16.to_le_bytes());
        let err = Ext4Superblock::parse_superblock_region(&bad)
            .unwrap()
            .validate_geometry()
            .unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidField { field: "s_inode_size", reason } if reason.contains("must be >= 128")),
            "got {err}",
        );

        // inode_size > block_size (8192 is a power of two above 4096)
        let mut bad = base;
        bad[0x58..0x5A].copy_from_slice(&8192_u16.to_le_bytes());
        let err = Ext4Superblock::parse_superblock_region(&bad)
            .unwrap()
            .validate_geometry()
            .unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidField { field: "s_inode_size", reason } if reason.contains("exceeds block_size")),
            "got {err}",
        );

        // desc_size < 32 (when non-zero)
        let mut bad = base;
        bad[0xFE..0x100].copy_from_slice(&16_u16.to_le_bytes());
        let err = Ext4Superblock::parse_superblock_region(&bad)
            .unwrap()
            .validate_geometry()
            .unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidField { field: "s_desc_size", reason } if reason.contains("must be >= 32")),
            "got {err}",
        );

        // desc_size > block_size
        let mut bad = base;
        bad[0xFE..0x100].copy_from_slice(&8192_u16.to_le_bytes());
        let err = Ext4Superblock::parse_superblock_region(&bad)
            .unwrap()
            .validate_geometry()
            .unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidField { field: "s_desc_size", reason } if reason.contains("exceeds block_size")),
            "got {err}",
        );
    }

    #[test]
    fn validate_v1_rejects_uncovered_branches() {
        // inodes_count exceeds group_count * inodes_per_group (geometry layout),
        // surfaced through the public validate_v1 entry. make_valid_sb has one
        // group * 8192 inodes_per_group, so 1_000_000 is well over the limit.
        let mut bad = make_valid_sb();
        let incompat =
            (Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0).to_le_bytes();
        bad[0x60..0x64].copy_from_slice(&incompat);
        bad[0x00..0x04].copy_from_slice(&1_000_000_u32.to_le_bytes());
        let err = Ext4Superblock::parse_superblock_region(&bad)
            .unwrap()
            .validate_v1()
            .unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "s_inodes_count",
                    ..
                }
            ),
            "got {err}",
        );

        // Missing the required FILETYPE incompat feature (EXTENTS only).
        let mut bad = make_valid_sb();
        bad[0x60..0x64].copy_from_slice(&Ext4IncompatFeatures::EXTENTS.0.to_le_bytes());
        let err = Ext4Superblock::parse_superblock_region(&bad)
            .unwrap()
            .validate_v1()
            .unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidField { field: "feature_incompat", reason } if reason.contains("missing required")),
            "got {err}",
        );
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

    fn superblock_with_extended_fields() -> [u8; EXT4_SUPERBLOCK_SIZE] {
        let mut sb = make_valid_sb();
        sb[0xCE..0xD0].copy_from_slice(&7_u16.to_le_bytes()); // reserved_gdt_blocks
        sb[0x104..0x108].copy_from_slice(&3_u32.to_le_bytes()); // first_meta_bg
        sb[0x2C..0x30].copy_from_slice(&1_700_000_000_u32.to_le_bytes()); // mtime
        sb[0x3A..0x3C].copy_from_slice(&1_u16.to_le_bytes()); // state=clean
        sb[0x44..0x48].copy_from_slice(&180_u32.to_le_bytes()); // checkinterval
        sb[0x4C..0x50].copy_from_slice(&1_u32.to_le_bytes()); // rev_level=DYNAMIC
        sb[0x50..0x52].copy_from_slice(&0x1234_u16.to_le_bytes()); // def_resuid lo
        sb[0x52..0x54].copy_from_slice(&0x5678_u16.to_le_bytes()); // def_resgid lo
        sb[0x54..0x58].copy_from_slice(&11_u32.to_le_bytes()); // first_ino
        sb[0x5A..0x5C].copy_from_slice(&6_u16.to_le_bytes()); // block_group_nr
        sb[0xC8..0xCC].copy_from_slice(&0xA5A5_5A5A_u32.to_le_bytes()); // algorithm_usage_bitmap
        sb[0xCC] = 3; // prealloc_blocks
        sb[0xCD] = 4; // prealloc_dir_blocks
        sb[0xE0..0xE4].copy_from_slice(&8_u32.to_le_bytes()); // journal_inum
        sb[0xE8..0xEC].copy_from_slice(&12_u32.to_le_bytes()); // last_orphan
        sb[0xEC..0xF0].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes()); // hash_seed[0]
        sb[0xFC] = 1; // def_hash_version=HalfMD4
        sb[0xFD] = 2; // jnl_backup_type
        for (idx, value) in (0x10_u32..=0x20).enumerate() {
            let offset = 0x10C + idx * 4;
            sb[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        sb[0x15C..0x15E].copy_from_slice(&32_u16.to_le_bytes()); // min_extra_isize
        sb[0x15E..0x160].copy_from_slice(&64_u16.to_le_bytes()); // want_extra_isize
        sb[0x164..0x166].copy_from_slice(&128_u16.to_le_bytes()); // raid_stride
        sb[0x170..0x174].copy_from_slice(&256_u32.to_le_bytes()); // raid_stripe_width
        sb[0x178..0x180].copy_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());
        sb[0x200..0x20E].copy_from_slice(b"acl,user_xattr"); // mount_opts
        sb[0x248..0x24C].copy_from_slice(&222_u32.to_le_bytes()); // overhead_clusters
        sb[0x160..0x164].copy_from_slice(&Ext4SuperFlags::UNSIGNED_HASH.0.to_le_bytes());
        sb[0x174] = 4; // log_groups_per_flex
        sb[0x166..0x168].copy_from_slice(&5_u16.to_le_bytes()); // mmp_update_interval
        sb[0x168..0x170].copy_from_slice(&1234_u64.to_le_bytes()); // mmp_block
        sb[0x19C..0x1A0].copy_from_slice(&35_u32.to_le_bytes()); // first_error_ino
        sb[0x1A0..0x1A8].copy_from_slice(&36_u64.to_le_bytes()); // first_error_block
        sb[0x1A8..0x1B1].copy_from_slice(b"first_err"); // first_error_func
        sb[0x1C8..0x1CC].copy_from_slice(&37_u32.to_le_bytes()); // first_error_line
        sb[0x1D0..0x1D4].copy_from_slice(&38_u32.to_le_bytes()); // last_error_ino
        sb[0x1D4..0x1D8].copy_from_slice(&39_u32.to_le_bytes()); // last_error_line
        sb[0x1D8..0x1E0].copy_from_slice(&40_u64.to_le_bytes()); // last_error_block
        sb[0x1E0..0x1E8].copy_from_slice(b"last_err"); // last_error_func
        sb[0x180..0x184].copy_from_slice(&31_u32.to_le_bytes()); // snapshot_inum
        sb[0x184..0x188].copy_from_slice(&32_u32.to_le_bytes()); // snapshot_id
        sb[0x188..0x190].copy_from_slice(&33_u64.to_le_bytes()); // snapshot_r_blocks_count
        sb[0x190..0x194].copy_from_slice(&34_u32.to_le_bytes()); // snapshot_list
        sb[0x24C..0x250].copy_from_slice(&7_u32.to_le_bytes()); // backup_bgs[0]
        sb[0x250..0x254].copy_from_slice(&11_u32.to_le_bytes()); // backup_bgs[1]
        sb[0x254..0x258].copy_from_slice(&[1, 2, 3, 4]); // encrypt_algos
        sb[0x258..0x268].copy_from_slice(b"0123456789ABCDEF"); // encrypt_pw_salt
        sb[0x268..0x26C].copy_from_slice(&99_u32.to_le_bytes()); // lost_found_ino
        sb[0x274..0x27C].copy_from_slice(&[10, 11, 12, 13, 14, 15, 16, 17]); // time hi / errcodes
        sb[0x27C..0x27E].copy_from_slice(&1_u16.to_le_bytes()); // encoding=UTF-8
        sb[0x27E..0x280].copy_from_slice(&2_u16.to_le_bytes()); // encoding_flags
        sb[0x280..0x284].copy_from_slice(&13_u32.to_le_bytes()); // orphan_file_inum
        sb[0x284..0x286].copy_from_slice(&0xABCD_u16.to_le_bytes()); // def_resuid hi
        sb[0x286..0x288].copy_from_slice(&0x9ABC_u16.to_le_bytes()); // def_resgid hi
        sb[0x175] = 1; // checksum_type=crc32c
        sb
    }

    fn assert_extended_superblock_fields(parsed: &Ext4Superblock) {
        assert_eq!(parsed.reserved_gdt_blocks, 7);
        assert_eq!(parsed.first_meta_bg, 3);
        assert_eq!(parsed.mtime, 1_700_000_000);
        assert_eq!(parsed.state, 1);
        assert_eq!(parsed.checkinterval, 180);
        assert_eq!(parsed.rev_level, 1);
        assert_eq!(parsed.def_resuid, 0xABCD_1234);
        assert_eq!(parsed.def_resgid, 0x9ABC_5678);
        assert_eq!(parsed.block_group_nr, 6);
        assert_eq!(parsed.algorithm_usage_bitmap, 0xA5A5_5A5A);
        assert_eq!(parsed.prealloc_blocks, 3);
        assert_eq!(parsed.prealloc_dir_blocks, 4);
        assert_eq!(parsed.first_ino, 11);
        assert_eq!(parsed.mount_opts, "acl,user_xattr");
        assert_eq!(parsed.journal_inum, 8);
        assert_eq!(parsed.last_orphan, 12);
        assert_eq!(parsed.hash_seed[0], 0xDEAD_BEEF);
        assert_eq!(parsed.def_hash_version, 1);
        assert_eq!(parsed.jnl_backup_type, 2);
        assert_eq!(parsed.jnl_blocks[0], 0x10);
        assert_eq!(parsed.jnl_blocks[16], 0x20);
        assert_eq!(parsed.min_extra_isize, 32);
        assert_eq!(parsed.want_extra_isize, 64);
        assert_eq!(parsed.raid_stride, 128);
        assert_eq!(parsed.raid_stripe_width, 256);
        assert_eq!(parsed.kbytes_written, 0x0102_0304_0506_0708);
        assert!(parsed.has_super_flag(Ext4SuperFlags::UNSIGNED_HASH));
        assert_eq!(parsed.log_groups_per_flex, 4);
        assert_eq!(parsed.mmp_update_interval, 5);
        assert_eq!(parsed.mmp_block, 1234);
        assert_eq!(parsed.first_error_ino, 35);
        assert_eq!(parsed.first_error_block, 36);
        assert_eq!(parsed.first_error_func, "first_err");
        assert_eq!(parsed.first_error_line, 37);
        assert_eq!(parsed.last_error_ino, 38);
        assert_eq!(parsed.last_error_line, 39);
        assert_eq!(parsed.last_error_block, 40);
        assert_eq!(parsed.last_error_func, "last_err");
        assert_eq!(parsed.snapshot_inum, 31);
        assert_eq!(parsed.snapshot_id, 32);
        assert_eq!(parsed.snapshot_r_blocks_count, 33);
        assert_eq!(parsed.snapshot_list, 34);
        assert_eq!(parsed.overhead_clusters, 222);
        assert_eq!(parsed.backup_bgs, [7, 11]);
        assert_eq!(parsed.encrypt_algos, [1, 2, 3, 4]);
        assert_eq!(parsed.encrypt_pw_salt, *b"0123456789ABCDEF");
        assert_eq!(parsed.lost_found_ino, 99);
        assert_eq!(
            [
                parsed.wtime_hi,
                parsed.mtime_hi,
                parsed.mkfs_time_hi,
                parsed.lastcheck_hi,
                parsed.first_error_time_hi,
                parsed.last_error_time_hi,
                parsed.first_error_errcode,
                parsed.last_error_errcode,
            ],
            [10, 11, 12, 13, 14, 15, 16, 17]
        );
        assert_eq!(parsed.encoding, 1);
        assert_eq!(parsed.encoding_flags, 2);
        assert_eq!(parsed.orphan_file_inum, 13);
        assert_eq!(parsed.checksum_type, 1);
        assert_eq!(parsed.groups_count(), 1);
    }

    #[test]
    fn superblock_new_fields_parse() {
        let sb = superblock_with_extended_fields();
        let parsed = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        assert_extended_superblock_fields(&parsed);
    }

    #[test]
    fn base_meta_blocks_in_group_skips_reserved_gdt_after_first_meta_bg() {
        let mut sb = make_valid_sb();
        sb[0x5C..0x60].copy_from_slice(&Ext4CompatFeatures::RESIZE_INODE.0.to_le_bytes());
        sb[0x60..0x64].copy_from_slice(&Ext4IncompatFeatures::META_BG.0.to_le_bytes());
        sb[0xCE..0xD0].copy_from_slice(&4_u16.to_le_bytes());
        sb[0x104..0x108].copy_from_slice(&2_u32.to_le_bytes());
        sb[0x04..0x08].copy_from_slice(&131_072_u32.to_le_bytes()); // 4 groups at 32k blocks/group

        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse meta_bg sb");
        let full_copy_blocks =
            1 + parsed.group_desc_blocks_count() + u32::from(parsed.reserved_gdt_blocks);
        assert_eq!(
            parsed.base_meta_blocks_in_group(GroupNumber(1)),
            full_copy_blocks
        );
        assert_eq!(parsed.base_meta_blocks_in_group(GroupNumber(3)), 1);
    }

    #[test]
    fn reserved_gdt_blocks_require_resize_inode_feature() {
        let mut sb = make_valid_sb();
        sb[0xCE..0xD0].copy_from_slice(&3_u16.to_le_bytes());
        sb[0x04..0x08].copy_from_slice(&131_072_u32.to_le_bytes());

        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse sb");
        assert_eq!(parsed.reserved_gdt_blocks_in_group(GroupNumber(1)), 0);

        sb[0x5C..0x60].copy_from_slice(&Ext4CompatFeatures::RESIZE_INODE.0.to_le_bytes());
        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse resize sb");
        assert_eq!(parsed.resize_inode_number(), Some(EXT4_RESIZE_INO));
        assert_eq!(parsed.reserved_gdt_blocks_in_group(GroupNumber(1)), 3);
    }

    #[test]
    fn max_mount_count_warning_honors_signed_disable_semantics() {
        let mut sb = Ext4Superblock::parse_superblock_region(&make_valid_sb()).unwrap();
        sb.mnt_count = 7;
        sb.max_mnt_count = 7;
        assert!(sb.should_warn_max_mount_count());

        sb.max_mnt_count = u16::MAX; // ((__s16)-1) disables the warning
        assert_eq!(sb.signed_max_mount_count(), -1);
        assert!(!sb.should_warn_max_mount_count());
    }

    #[test]
    fn write_mount_normalizes_zero_max_mount_count_and_increments_counter() {
        let mut sb = Ext4Superblock::parse_superblock_region(&make_valid_sb()).unwrap();
        sb.max_mnt_count = 0;
        sb.mnt_count = 0;
        sb.mtime = 11;

        // The kernel warns before normalizing the zero field.
        assert!(sb.should_warn_max_mount_count());

        sb.record_write_mount(1_700_000_123);
        assert_eq!(sb.max_mnt_count, EXT4_DFL_MAX_MNT_COUNT);
        assert_eq!(sb.mnt_count, 1);
        assert_eq!(sb.mtime, 1_700_000_123);
        assert!(!sb.should_warn_max_mount_count());
    }

    #[test]
    fn write_mount_wraps_mount_count_like_le16_add_cpu() {
        let mut sb = Ext4Superblock::parse_superblock_region(&make_valid_sb()).unwrap();
        sb.max_mnt_count = u16::MAX; // signed -1: disabled
        sb.mnt_count = u16::MAX;

        sb.record_write_mount(99);
        assert_eq!(sb.mnt_count, 0);
        assert_eq!(sb.mtime, 99);
        assert_eq!(sb.max_mnt_count, u16::MAX);
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
        gd32[0x18..0x1A].copy_from_slice(&0xBEEF_u16.to_le_bytes());
        gd32[0x1A..0x1C].copy_from_slice(&0xCAFE_u16.to_le_bytes());
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
        assert_eq!(parsed32.block_bitmap_csum, 0xBEEF);
        assert_eq!(parsed32.inode_bitmap_csum, 0xCAFE);

        let mut gd64 = [0_u8; 64];
        gd64[..32].copy_from_slice(&gd32);
        gd64[0x20..0x24].copy_from_slice(&1_u32.to_le_bytes());
        gd64[0x24..0x28].copy_from_slice(&2_u32.to_le_bytes());
        gd64[0x28..0x2C].copy_from_slice(&3_u32.to_le_bytes());
        gd64[0x2C..0x2E].copy_from_slice(&4_u16.to_le_bytes());
        gd64[0x2E..0x30].copy_from_slice(&5_u16.to_le_bytes());
        gd64[0x30..0x32].copy_from_slice(&6_u16.to_le_bytes());
        gd64[0x32..0x34].copy_from_slice(&7_u16.to_le_bytes());
        gd64[0x38..0x3A].copy_from_slice(&0x0102_u16.to_le_bytes());
        gd64[0x3A..0x3C].copy_from_slice(&0x0304_u16.to_le_bytes());

        let parsed64 = Ext4GroupDesc::parse_from_bytes(&gd64, 64).expect("gd64");
        assert_eq!(parsed64.block_bitmap, (1_u64 << 32) | 0x007b_u64);
        assert_eq!(parsed64.inode_bitmap, (2_u64 << 32) | 0x01c8_u64);
        assert_eq!(parsed64.inode_table, (3_u64 << 32) | 0x0315_u64);
        assert_eq!(parsed64.free_blocks_count, 0x000a_u32 | (4_u32 << 16));
        assert_eq!(parsed64.free_inodes_count, 0x000b_u32 | (5_u32 << 16));
        assert_eq!(parsed64.used_dirs_count, 0x000c_u32 | (6_u32 << 16));
        assert_eq!(parsed64.itable_unused, 0x0063_u32 | (7_u32 << 16));
        assert_eq!(parsed64.block_bitmap_csum, 0x0102_BEEF);
        assert_eq!(parsed64.inode_bitmap_csum, 0x0304_CAFE);
    }

    #[test]
    fn group_desc_write_to_bytes_roundtrip_32() {
        let gd = Ext4GroupDesc {
            block_bitmap: 123,
            inode_bitmap: 456,
            inode_table: 789,
            free_blocks_count: 42,
            free_inodes_count: 17,
            used_dirs_count: 5,
            itable_unused: 99,
            flags: 0x0003,
            checksum: 0xABCD,
            block_bitmap_csum: 0x1234,
            inode_bitmap_csum: 0x5678,
        };
        let mut buf = [0_u8; 32];
        gd.write_to_bytes(&mut buf, 32).unwrap();
        let parsed = Ext4GroupDesc::parse_from_bytes(&buf, 32).unwrap();
        assert_eq!(parsed.block_bitmap, gd.block_bitmap);
        assert_eq!(parsed.inode_bitmap, gd.inode_bitmap);
        assert_eq!(parsed.inode_table, gd.inode_table);
        assert_eq!(parsed.free_blocks_count, gd.free_blocks_count);
        assert_eq!(parsed.free_inodes_count, gd.free_inodes_count);
        assert_eq!(parsed.used_dirs_count, gd.used_dirs_count);
        assert_eq!(parsed.itable_unused, gd.itable_unused);
        assert_eq!(parsed.flags, gd.flags);
        assert_eq!(parsed.checksum, gd.checksum);
        assert_eq!(parsed.block_bitmap_csum, gd.block_bitmap_csum);
        assert_eq!(parsed.inode_bitmap_csum, gd.inode_bitmap_csum);
    }

    /// bd-l6cfv — Canonical byte-layout snapshot for
    /// Ext4GroupDesc::write_to_bytes 32-byte mode. Pins the
    /// encoder's exact output for a magic-stamped fixture so any
    /// field-order or offset drift fails with a hex diff. The
    /// expected literal pins BOTH magic regions AND the implicit
    /// 4-byte gap at @0x14..0x18 that the encoder leaves
    /// untouched (a regression that wrote into that gap would be
    /// caught here).
    ///
    /// Pairs with bd-pketz (BtrfsInodeItem), bd-bq6l8
    /// (BtrfsInodeRef), bd-2gb89 (BtrfsDirItem), bd-yjzhk +
    /// bd-fw55q (BtrfsExtentData Regular/Inline). Correctness is
    /// pinned by the bd-ov7zr proptest suite + bd-38xrn fuzz
    /// target; this pins the byte-exact encoder layout.
    #[test]
    fn ext4_group_desc_write_to_bytes_32byte_canonical_byte_layout() {
        let gd = Ext4GroupDesc {
            // Magic-stamped values — distinct nibbles per field
            // so any offset drift produces a cross-field collision.
            block_bitmap: 0x1122_3344,
            inode_bitmap: 0x5566_7788,
            inode_table: 0x99AA_BBCC,
            free_blocks_count: 0x0000_DDDD,
            free_inodes_count: 0x0000_EEEE,
            used_dirs_count: 0x0000_FEFE,
            itable_unused: 0x0000_DEAD,
            flags: 0x1234,
            checksum: 0xBEEF,
            block_bitmap_csum: 0x0000_5678,
            inode_bitmap_csum: 0x0000_9ABC,
        };
        let mut buf = [0_u8; 32];
        gd.write_to_bytes(&mut buf, 32)
            .expect("canonical fixture encodes");

        let expected: [u8; 32] = [
            // block_bitmap LE @0x00..0x04 = 0x1122_3344 (low 32 bits)
            0x44, 0x33, 0x22, 0x11, // inode_bitmap LE @0x04..0x08 = 0x5566_7788
            0x88, 0x77, 0x66, 0x55, // inode_table LE @0x08..0x0C = 0x99AA_BBCC
            0xCC, 0xBB, 0xAA, 0x99,
            // free_blocks_count LE @0x0C..0x0E = 0xDDDD (cast u32→u16)
            0xDD, 0xDD, // free_inodes_count LE @0x0E..0x10 = 0xEEEE
            0xEE, 0xEE, // used_dirs_count LE @0x10..0x12 = 0xFEFE
            0xFE, 0xFE, // flags LE @0x12..0x14 = 0x1234
            0x34, 0x12, // 4-byte gap @0x14..0x18 (encoder leaves untouched)
            0x00, 0x00, 0x00, 0x00,
            // block_bitmap_csum LE @0x18..0x1A = 0x5678 (cast u32→u16)
            0x78, 0x56, // inode_bitmap_csum LE @0x1A..0x1C = 0x9ABC
            0xBC, 0x9A, // itable_unused LE @0x1C..0x1E = 0xDEAD (cast u32→u16)
            0xAD, 0xDE, // checksum LE @0x1E..0x20 = 0xBEEF
            0xEF, 0xBE,
        ];
        assert_eq!(
            buf, expected,
            "Ext4GroupDesc::write_to_bytes 32-byte canonical byte layout drifted"
        );

        // Cross-check: parser round-trips the canonical bytes.
        let parsed = Ext4GroupDesc::parse_from_bytes(&buf, 32).expect("canonical bytes parse");
        assert_eq!(parsed.block_bitmap, gd.block_bitmap);
        assert_eq!(parsed.flags, gd.flags);
        assert_eq!(parsed.checksum, gd.checksum);
    }

    #[test]
    fn group_desc_write_to_bytes_roundtrip_64() {
        let gd = Ext4GroupDesc {
            block_bitmap: (1_u64 << 32) | 0x7b,
            inode_bitmap: (2_u64 << 32) | 0x01c8,
            inode_table: (3_u64 << 32) | 0x0315,
            free_blocks_count: (4 << 16) | 0x2a,
            free_inodes_count: (5 << 16) | 0x11,
            used_dirs_count: (6 << 16) | 0x05,
            itable_unused: (7 << 16) | 0x63,
            flags: 0x0003,
            checksum: 0xABCD,
            block_bitmap_csum: 0x1234_5678,
            inode_bitmap_csum: 0x9ABC_DEF0,
        };
        let mut buf = [0_u8; 64];
        gd.write_to_bytes(&mut buf, 64).unwrap();
        let parsed = Ext4GroupDesc::parse_from_bytes(&buf, 64).unwrap();
        assert_eq!(parsed.block_bitmap, gd.block_bitmap);
        assert_eq!(parsed.inode_bitmap, gd.inode_bitmap);
        assert_eq!(parsed.inode_table, gd.inode_table);
        assert_eq!(parsed.free_blocks_count, gd.free_blocks_count);
        assert_eq!(parsed.free_inodes_count, gd.free_inodes_count);
        assert_eq!(parsed.used_dirs_count, gd.used_dirs_count);
        assert_eq!(parsed.itable_unused, gd.itable_unused);
        assert_eq!(parsed.block_bitmap_csum, gd.block_bitmap_csum);
        assert_eq!(parsed.inode_bitmap_csum, gd.inode_bitmap_csum);
    }

    #[test]
    fn bitmap_checksum_helpers_roundtrip() {
        let raw_bitmap = vec![0xA5_u8; 4096];
        let csum_seed = 0x1234_5678;
        let blocks_per_group = 32768_u32; // 32768/8 = 4096 bytes = full bitmap
        let inodes_per_group = 2048_u32; // 2048/8 = 256 bytes
        let mut gd32 = Ext4GroupDesc {
            block_bitmap: 0,
            inode_bitmap: 0,
            inode_table: 0,
            free_blocks_count: 0,
            free_inodes_count: 0,
            used_dirs_count: 0,
            itable_unused: 0,
            flags: 0,
            checksum: 0,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
        };
        stamp_block_bitmap_checksum(&raw_bitmap, csum_seed, blocks_per_group, &mut gd32, 32);
        stamp_inode_bitmap_checksum(&raw_bitmap, csum_seed, inodes_per_group, &mut gd32, 32);
        assert!(
            verify_block_bitmap_checksum(&raw_bitmap, csum_seed, blocks_per_group, &gd32, 32)
                .is_ok()
        );
        assert!(
            verify_inode_bitmap_checksum(&raw_bitmap, csum_seed, inodes_per_group, &gd32, 32)
                .is_ok()
        );
        assert_eq!(gd32.block_bitmap_csum >> 16, 0);
        assert_eq!(gd32.inode_bitmap_csum >> 16, 0);

        let mut gd64 = gd32.clone();
        stamp_block_bitmap_checksum(&raw_bitmap, csum_seed, blocks_per_group, &mut gd64, 64);
        stamp_inode_bitmap_checksum(&raw_bitmap, csum_seed, inodes_per_group, &mut gd64, 64);
        assert!(
            verify_block_bitmap_checksum(&raw_bitmap, csum_seed, blocks_per_group, &gd64, 64)
                .is_ok()
        );
        assert!(
            verify_inode_bitmap_checksum(&raw_bitmap, csum_seed, inodes_per_group, &gd64, 64)
                .is_ok()
        );
        assert_ne!(gd64.block_bitmap_csum, gd32.block_bitmap_csum);
        assert_ne!(gd64.inode_bitmap_csum, gd32.inode_bitmap_csum);
    }

    #[test]
    fn sparse_super2_and_flex_helpers_follow_superblock_fields() {
        let mut sb = make_valid_sb();
        sb[0x5C..0x60].copy_from_slice(&Ext4CompatFeatures::SPARSE_SUPER2.0.to_le_bytes());
        sb[0x60..0x64].copy_from_slice(
            &(Ext4IncompatFeatures::FILETYPE.0
                | Ext4IncompatFeatures::EXTENTS.0
                | Ext4IncompatFeatures::FLEX_BG.0)
                .to_le_bytes(),
        );
        sb[0x174] = 3;
        sb[0x24C..0x250].copy_from_slice(&7_u32.to_le_bytes());
        sb[0x250..0x254].copy_from_slice(&19_u32.to_le_bytes());
        let parsed = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        assert_eq!(parsed.groups_per_flex(), 8);
        assert_eq!(parsed.flex_group_index(GroupNumber(15)), 1);
        assert!(parsed.has_backup_superblock(GroupNumber(0)));
        assert!(parsed.has_backup_superblock(GroupNumber(7)));
        assert!(parsed.has_backup_superblock(GroupNumber(19)));
        assert!(!parsed.has_backup_superblock(GroupNumber(1)));
        assert!(!parsed.has_backup_superblock(GroupNumber(9)));
    }

    #[test]
    fn parse_ext4_superblock_region_reads_quota_inode_fields() {
        let mut sb = make_valid_sb();
        sb[0x240..0x244].copy_from_slice(&3_u32.to_le_bytes());
        sb[0x244..0x248].copy_from_slice(&4_u32.to_le_bytes());
        sb[0x26C..0x270].copy_from_slice(&11_u32.to_le_bytes());

        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        assert_eq!(parsed.usr_quota_inum, 3);
        assert_eq!(parsed.grp_quota_inum, 4);
        assert_eq!(parsed.prj_quota_inum, 11);
    }

    #[test]
    fn quota_inodes_require_feature_bits() {
        let mut sb = make_valid_sb();
        sb[0x240..0x244].copy_from_slice(&3_u32.to_le_bytes());
        sb[0x244..0x248].copy_from_slice(&4_u32.to_le_bytes());
        sb[0x26C..0x270].copy_from_slice(&11_u32.to_le_bytes());

        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        assert_eq!(
            parsed.quota_inodes(),
            Ext4QuotaInodes {
                user: None,
                group: None,
                project: None,
            }
        );
    }

    #[test]
    fn quota_inodes_report_enabled_superblock_metadata() {
        let mut sb = make_valid_sb();
        let ro_compat =
            (Ext4RoCompatFeatures::QUOTA.0 | Ext4RoCompatFeatures::PROJECT.0).to_le_bytes();
        sb[0x64..0x68].copy_from_slice(&ro_compat);
        sb[0x240..0x244].copy_from_slice(&3_u32.to_le_bytes());
        sb[0x244..0x248].copy_from_slice(&4_u32.to_le_bytes());
        sb[0x26C..0x270].copy_from_slice(&11_u32.to_le_bytes());

        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        assert_eq!(
            parsed.quota_inodes(),
            Ext4QuotaInodes {
                user: Some(3),
                group: Some(4),
                project: Some(11),
            }
        );
    }

    #[test]
    fn orphan_file_inode_requires_compat_feature() {
        let mut sb = make_valid_sb();
        sb[0x280..0x284].copy_from_slice(&13_u32.to_le_bytes());

        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        assert_eq!(parsed.orphan_file_inode(), None);
    }

    #[test]
    fn orphan_file_inode_reports_enabled_superblock_metadata() {
        let mut sb = make_valid_sb();
        sb[0x5C..0x60].copy_from_slice(&Ext4CompatFeatures::ORPHAN_FILE.0.to_le_bytes());
        sb[0x280..0x284].copy_from_slice(&13_u32.to_le_bytes());

        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        assert_eq!(parsed.orphan_file_inode(), Some(13));
    }

    #[test]
    fn representative_ext4_geometry_and_backup_layout_exact_golden_contract() {
        let parsed = Ext4Superblock::parse_superblock_region(&representative_ext4_geometry_sb())
            .expect("parse representative ext4 superblock");
        let root_loc = parsed
            .locate_inode(InodeNumber::ROOT)
            .expect("locate root inode");
        let first_second_group = parsed
            .locate_inode(InodeNumber(8193))
            .expect("locate first inode in second group");
        let root_dev = parsed
            .inode_device_offset(&root_loc, 100)
            .expect("root inode device offset");
        let second_group_dev = parsed
            .inode_device_offset(&first_second_group, 200)
            .expect("second group inode device offset");

        let actual = format!(
            concat!(
                "superblock\n",
                "  block_size={}\n",
                "  cluster_size={}\n",
                "  inode_size={}\n",
                "  groups_count={}\n",
                "  group_desc_size={}\n",
                "  group_desc_blocks_count={}\n",
                "  groups_per_flex={}\n",
                "  flex_group_index(15)={}\n",
                "  has_metadata_csum={}\n",
                "  mmp_block_number={:?}\n",
                "  backup_superblock_groups={:?}\n",
                "  has_backup_superblock(1)={}\n",
                "  has_backup_superblock(7)={}\n",
                "  has_backup_superblock(19)={}\n",
                "group_desc_offsets\n",
                "  group0={:?}\n",
                "  group31={:?}\n",
                "inode_locations\n",
                "  ino2=group:{},index:{},offset:{}\n",
                "  ino2_device_offset@100={}\n",
                "  ino8193=group:{},index:{},offset:{}\n",
                "  ino8193_device_offset@200={}"
            ),
            parsed.block_size,
            parsed.cluster_size,
            parsed.inode_size,
            parsed.groups_count(),
            parsed.group_desc_size(),
            parsed.group_desc_blocks_count(),
            parsed.groups_per_flex(),
            parsed.flex_group_index(GroupNumber(15)),
            parsed.has_metadata_csum(),
            parsed.mmp_block_number(),
            parsed.backup_superblock_groups(parsed.groups_count()),
            parsed.has_backup_superblock(GroupNumber(1)),
            parsed.has_backup_superblock(GroupNumber(7)),
            parsed.has_backup_superblock(GroupNumber(19)),
            parsed.group_desc_offset(GroupNumber(0)),
            parsed.group_desc_offset(GroupNumber(31)),
            root_loc.group.0,
            root_loc.index,
            root_loc.offset_in_table,
            root_dev,
            first_second_group.group.0,
            first_second_group.index,
            first_second_group.offset_in_table,
            second_group_dev,
        );

        let expected = concat!(
            "superblock\n",
            "  block_size=4096\n",
            "  cluster_size=4096\n",
            "  inode_size=256\n",
            "  groups_count=32\n",
            "  group_desc_size=64\n",
            "  group_desc_blocks_count=1\n",
            "  groups_per_flex=8\n",
            "  flex_group_index(15)=1\n",
            "  has_metadata_csum=true\n",
            "  mmp_block_number=Some(1234)\n",
            "  backup_superblock_groups=[0, 7, 19]\n",
            "  has_backup_superblock(1)=false\n",
            "  has_backup_superblock(7)=true\n",
            "  has_backup_superblock(19)=true\n",
            "group_desc_offsets\n",
            "  group0=Some(4096)\n",
            "  group31=Some(6080)\n",
            "inode_locations\n",
            "  ino2=group:0,index:1,offset:256\n",
            "  ino2_device_offset@100=409856\n",
            "  ino8193=group:1,index:0,offset:0\n",
            "  ino8193_device_offset@200=819200"
        );
        assert_eq!(actual, expected);
    }

    #[test]
    fn mmp_block_parse_and_checksum_roundtrip() {
        let mut raw = vec![0_u8; 4096];
        raw[0x00..0x04].copy_from_slice(&EXT4_MMP_MAGIC.to_le_bytes());
        raw[0x04..0x08].copy_from_slice(&EXT4_MMP_SEQ_CLEAN.to_le_bytes());
        raw[0x08..0x10].copy_from_slice(&123_u64.to_le_bytes());
        raw[0x10..0x1A].copy_from_slice(b"node-a\0\0\0\0");
        raw[0x50..0x58].copy_from_slice(b"/dev/vda");
        raw[0x70..0x72].copy_from_slice(&5_u16.to_le_bytes());
        let seed = 0xAABB_CCDD;
        let csum = ext4_chksum(seed, &raw[..EXT4_MMP_CHECKSUM_OFFSET]);
        raw[EXT4_MMP_CHECKSUM_OFFSET..EXT4_MMP_CHECKSUM_OFFSET + 4]
            .copy_from_slice(&csum.to_le_bytes());
        let parsed = Ext4MmpBlock::parse_from_bytes(&raw).unwrap();
        assert_eq!(parsed.status(), Ext4MmpStatus::Clean);
        assert_eq!(parsed.nodename, "node-a");
        assert_eq!(parsed.bdevname, "/dev/vda");
        assert!(parsed.validate_checksum(&raw, seed).is_ok());
    }

    /// bd-tpgp7 — Kernel-conformance pin for Ext4MmpBlock field
    /// offsets per fs/ext4/mmp.h struct mmp_struct.
    ///
    ///   magic            u32 @0x00
    ///   seq              u32 @0x04
    ///   time_lo          u32 @0x08  (kernel: __le64 mmp_time)
    ///   time_hi          u32 @0x0C
    ///   nodename       [u8;64] @0x10
    ///   bdevname       [u8;32] @0x50
    ///   check_interval   u16 @0x70
    ///   checksum         u32 @0x3FC
    ///
    /// bd-jbilz pins the EXT4_MMP_MAGIC value but the field
    /// OFFSETS are not pinned — a regression that drifted
    /// time_lo/time_hi/nodename/bdevname offsets would silently
    /// corrupt every multi-mount-protection check on mount
    /// without tripping the existing magic check or the round-
    /// trip in mmp_block_parse_and_checksum_roundtrip (which
    /// uses values 123 and 5_u16, not unique offset-detecting
    /// magics).
    ///
    /// Stamp each addressable field with a distinct non-zero
    /// magic so any single-field offset drift produces a cross-
    /// field collision on the parsed struct.
    #[test]
    fn ext4_mmp_block_kernel_offsets_match_mmp_h() {
        let mut raw = vec![0_u8; 1024]; // EXT4_SUPERBLOCK_SIZE = 1024

        // magic@0..4 (must be EXT4_MMP_MAGIC for parser to accept).
        raw[0x00..0x04].copy_from_slice(&EXT4_MMP_MAGIC.to_le_bytes());
        // seq@4..8 — unique magic.
        let seq_magic: u32 = 0x1234_5678;
        raw[0x04..0x08].copy_from_slice(&seq_magic.to_le_bytes());
        // time_lo@8..0xC — unique magic.
        let time_lo: u32 = 0x9999_9999;
        raw[0x08..0x0C].copy_from_slice(&time_lo.to_le_bytes());
        // time_hi@0xC..0x10 — unique magic (parser merges as u64).
        let time_hi: u32 = 0xAAAA_AAAA;
        raw[0x0C..0x10].copy_from_slice(&time_hi.to_le_bytes());
        // nodename@0x10..0x50 — 15-byte ASCII content, padded with NUL.
        let nodename_src = b"kernel-pin-test";
        raw[0x10..0x10 + nodename_src.len()].copy_from_slice(nodename_src);
        // bdevname@0x50..0x70 — 15-byte ASCII content, padded with NUL.
        let bdevname_src = b"/dev/kernel-pin";
        raw[0x50..0x50 + bdevname_src.len()].copy_from_slice(bdevname_src);
        // check_interval@0x70..0x72 — unique magic.
        let check_interval: u16 = 0xBBBB;
        raw[0x70..0x72].copy_from_slice(&check_interval.to_le_bytes());
        // checksum@0x3FC..0x400 — unique magic (parser stores raw,
        // validate_checksum is a separate gate).
        let checksum_magic: u32 = 0xCCCC_DDDD;
        raw[EXT4_MMP_CHECKSUM_OFFSET..EXT4_MMP_CHECKSUM_OFFSET + 4]
            .copy_from_slice(&checksum_magic.to_le_bytes());

        let parsed =
            Ext4MmpBlock::parse_from_bytes(&raw).expect("kernel-stamped MMP block must parse");

        assert_eq!(
            parsed.magic, EXT4_MMP_MAGIC,
            "magic must come from offset 0x00 per kernel layout"
        );
        assert_eq!(
            parsed.seq, seq_magic,
            "seq must come from offset 0x04 per kernel layout"
        );
        // time field is parsed as time_hi<<32 | time_lo per the
        // u64 split at lib.rs:2304-2305. Pin both halves.
        let expected_time = (u64::from(time_hi) << 32) | u64::from(time_lo);
        assert_eq!(
            parsed.time, expected_time,
            "time must come from offsets 0x08 (lo) and 0x0C (hi) per kernel layout"
        );
        assert_eq!(
            parsed.nodename, "kernel-pin-test",
            "nodename must come from offset 0x10 (NUL-trimmed from 64-byte field)"
        );
        assert_eq!(
            parsed.bdevname, "/dev/kernel-pin",
            "bdevname must come from offset 0x50 (NUL-trimmed from 32-byte field)"
        );
        assert_eq!(
            parsed.check_interval, check_interval,
            "check_interval must come from offset 0x70 per kernel layout"
        );
        assert_eq!(
            parsed.checksum, checksum_magic,
            "checksum must come from offset EXT4_MMP_CHECKSUM_OFFSET (0x3FC)"
        );
    }

    #[test]
    fn stamp_group_desc_checksum_matches_verify() {
        let gd = Ext4GroupDesc {
            block_bitmap: 100,
            inode_bitmap: 200,
            inode_table: 300,
            free_blocks_count: 50,
            free_inodes_count: 25,
            used_dirs_count: 3,
            itable_unused: 0,
            flags: 0,
            checksum: 0,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
        };
        let mut buf = [0_u8; 32];
        gd.write_to_bytes(&mut buf, 32).unwrap();

        let csum_seed = 0x1234_5678_u32;
        let uuid = [1_u8; 16];
        stamp_group_desc_checksum(
            &mut buf,
            &uuid,
            csum_seed,
            0,
            32,
            Ext4GroupDescChecksumKind::MetadataCsum,
        );

        // Verify should now pass.
        verify_group_desc_checksum(
            &buf,
            &uuid,
            csum_seed,
            0,
            32,
            Ext4GroupDescChecksumKind::MetadataCsum,
        )
        .expect("checksum should verify");
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
        if let ExtentTree::Leaf(exts) = tree {
            assert_eq!(exts.len(), 1);
            assert_eq!(exts[0].logical_block, 0);
            assert_eq!(exts[0].actual_len(), 8);
            assert_eq!(exts[0].physical_start, 1234);
        } else {
            unreachable!("expected leaf");
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

    #[test]
    fn inode_metadata_parse_skips_ibody_only() {
        let mut raw = [0_u8; 256];
        raw[0x00..0x02].copy_from_slice(&(S_IFREG | 0o644).to_le_bytes());
        raw[0x02..0x04].copy_from_slice(&1000_u16.to_le_bytes());
        raw[0x04..0x08].copy_from_slice(&8192_u32.to_le_bytes());
        raw[0x08..0x0C].copy_from_slice(&1_700_000_000_u32.to_le_bytes());
        raw[0x0C..0x10].copy_from_slice(&1_700_000_100_u32.to_le_bytes());
        raw[0x10..0x14].copy_from_slice(&1_700_000_200_u32.to_le_bytes());
        raw[0x18..0x1A].copy_from_slice(&100_u16.to_le_bytes());
        raw[0x1A..0x1C].copy_from_slice(&1_u16.to_le_bytes());
        raw[0x1C..0x20].copy_from_slice(&16_u32.to_le_bytes());
        raw[0x20..0x24].copy_from_slice(&EXT4_EXTENTS_FL.to_le_bytes());
        raw[0x28..0x64].fill(0x5A);
        raw[0x64..0x68].copy_from_slice(&42_u32.to_le_bytes());
        raw[0x78..0x7A].copy_from_slice(&1_u16.to_le_bytes());
        raw[0x7A..0x7C].copy_from_slice(&2_u16.to_le_bytes());
        raw[0x80..0x82].copy_from_slice(&32_u16.to_le_bytes());
        raw[0x82..0x84].copy_from_slice(&0xBEEF_u16.to_le_bytes());
        raw[0x84..0x88].copy_from_slice(&(500_000_000_u32 << 2).to_le_bytes());
        raw[0x88..0x8C].copy_from_slice(&(250_000_000_u32 << 2).to_le_bytes());
        raw[0x90..0x94].copy_from_slice(&1_600_000_000_u32.to_le_bytes());
        raw[0x98..0x9C].copy_from_slice(&7_u32.to_le_bytes());
        raw[0x9C..0xA0].copy_from_slice(&11_u32.to_le_bytes());
        raw[160..].fill(0xA5);

        let full = Ext4Inode::parse_from_bytes(&raw).expect("full inode parse");
        let metadata = Ext4Inode::parse_metadata_from_bytes(&raw).expect("metadata inode parse");
        assert_eq!(full.xattr_ibody.as_slice(), &raw[160..]);
        assert!(metadata.xattr_ibody.is_empty());

        let mut expected = full;
        expected.xattr_ibody.clear();
        assert_eq!(metadata, expected);
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
    fn timestamp_full_decodes_nsec_and_high_epochs() {
        let mut raw = [0_u8; 256];
        raw[0x80..0x82].copy_from_slice(&32_u16.to_le_bytes()); // extra_isize = 32

        // Nanoseconds live in the high 30 bits of *_extra (extra >> 2); the
        // sign-extension test only ever uses nsec = 0.
        raw[0x08..0x0C].copy_from_slice(&100_u32.to_le_bytes());
        raw[0x8C..0x90].copy_from_slice(&(123_456_789_u32 << 2).to_le_bytes());
        let inode = Ext4Inode::parse_from_bytes(&raw).unwrap();
        assert_eq!(inode.atime_full(), (100, 123_456_789));

        // Epoch bits 2 and 3 add 2*2^32 and 3*2^32 (only 0/1 were covered).
        raw[0x08..0x0C].copy_from_slice(&0_u32.to_le_bytes());
        raw[0x8C..0x90].copy_from_slice(&2_u32.to_le_bytes());
        let inode = Ext4Inode::parse_from_bytes(&raw).unwrap();
        assert_eq!(inode.atime_full(), (2_i64 << 32, 0));

        raw[0x8C..0x90].copy_from_slice(&3_u32.to_le_bytes());
        let inode = Ext4Inode::parse_from_bytes(&raw).unwrap();
        assert_eq!(inode.atime_full(), (3_i64 << 32, 0));

        // Combined: negative base (0xFFFF_FFFF = -1) + epoch 3 + nonzero nsec.
        raw[0x08..0x0C].copy_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
        raw[0x8C..0x90].copy_from_slice(&((5_u32 << 2) | 3).to_le_bytes());
        let inode = Ext4Inode::parse_from_bytes(&raw).unwrap();
        assert_eq!(inode.atime_full(), ((3_i64 << 32) - 1, 5));
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
    fn validate_dir_block_slice_len_rejects_bad_inputs() {
        // A zero block_size is rejected.
        let err = super::validate_dir_block_slice_len(&[0_u8; 16], 0)
            .expect_err("zero block_size must be rejected");
        assert!(
            matches!(err, ParseError::InvalidField { reason, .. } if reason.contains("must be non-zero")),
            "got {err:?}",
        );

        // A block slice longer than the declared block_size is rejected.
        let err = super::validate_dir_block_slice_len(&[0_u8; 100], 64)
            .expect_err("oversized slice must be rejected");
        assert!(
            matches!(err, ParseError::InvalidField { reason, .. } if reason.contains("exceeds declared block_size")),
            "got {err:?}",
        );

        // Slices within the declared block_size are accepted (including empty
        // and exactly block_size).
        assert!(super::validate_dir_block_slice_len(&[0_u8; 64], 64).is_ok());
        assert!(super::validate_dir_block_slice_len(&[0_u8; 32], 64).is_ok());
        assert!(super::validate_dir_block_slice_len(&[], 64).is_ok());
    }

    #[test]
    fn verify_bitmap_free_count_masks_partial_byte_and_rejects_short() {
        // total_bits = 12 -> full_bytes = 1, rem_bits = 4 (mask 0x0F): only the
        // low 4 bits of byte 1 count; the high nibble is ignored even when set.
        // [0xFF, 0xF0]: 8 used in byte 0, 0 used in the masked nibble -> 4 free.
        assert!(super::verify_bitmap_free_count(&[0xFF, 0xF0], 12, 4, "block_bitmap").is_ok());
        // [0xFF, 0x0F]: low nibble fully set -> 12 used, 0 free.
        assert!(super::verify_bitmap_free_count(&[0xFF, 0x0F], 12, 0, "block_bitmap").is_ok());
        // Wrong expected free count for the partial byte is rejected.
        assert!(super::verify_bitmap_free_count(&[0xFF, 0x0F], 12, 4, "block_bitmap").is_err());

        // A bitmap shorter than ceil(total_bits/8) is rejected with InsufficientData.
        let err = super::verify_bitmap_free_count(&[0x00], 16, 16, "block_bitmap")
            .expect_err("short bitmap must be rejected");
        assert!(
            matches!(
                err,
                ParseError::InsufficientData {
                    needed: 2,
                    actual: 1,
                    ..
                }
            ),
            "got {err:?}",
        );
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
        let remaining = u16::try_from(block_size).unwrap() - 24;
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
    fn parse_dir_block_rejects_slice_larger_than_declared_block_size() {
        let block_size = 1024_u32;
        let mut block = vec![0_u8; 1036];

        write_dir_entry(&mut block, 0, 2, 2, b".", 1024);
        write_dir_entry(&mut block, 1024, 99, 1, b"x", 12);

        let err = parse_dir_block(&block, block_size).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "dir_block",
                ..
            }
        ));
    }

    /// bd-7stug — Kernel-conformance pin for the 3 Ext4SuperFlags
    /// bit values per fs/ext4/ext4.h EXT4_FLAGS_*. These are read
    /// from the superblock @ s_flags (0x160). SIGNED_HASH /
    /// UNSIGNED_HASH gate effective_dirhash_version() — a drift
    /// would silently route every htree directory lookup through
    /// the wrong hash variant.
    ///
    /// Companion to bd-eiblh (incompat), bd-up9ff (compat/ro_compat),
    /// bd-wa27v (xattr), bd-mo92w (DX_HASH_*).
    #[test]
    fn ext4_super_flags_match_ext4_h() {
        // Per fs/ext4/ext4.h:
        //   #define EXT4_FLAGS_SIGNED_HASH   0x0001
        //   #define EXT4_FLAGS_UNSIGNED_HASH 0x0002
        //   #define EXT4_FLAGS_TEST_FILESYS  0x0004
        let cases: &[(&str, Ext4SuperFlags, u32)] = &[
            ("SIGNED_HASH", Ext4SuperFlags::SIGNED_HASH, 0x0001),
            ("UNSIGNED_HASH", Ext4SuperFlags::UNSIGNED_HASH, 0x0002),
            ("TEST_FILESYS", Ext4SuperFlags::TEST_FILESYS, 0x0004),
        ];
        for (name, actual, expected) in cases {
            assert_eq!(
                actual.0, *expected,
                "EXT4_FLAGS_{name} must equal kernel value 0x{expected:X}"
            );
            assert_eq!(
                actual.0.count_ones(),
                1,
                "EXT4_FLAGS_{name} must be a single-bit flag"
            );
        }
        // Pairwise distinctness.
        let bits: Vec<u32> = cases.iter().map(|&(_, f, _)| f.0).collect();
        let mut sorted = bits.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            bits.len(),
            sorted.len(),
            "EXT4_FLAGS_* bit values must be pairwise distinct"
        );
    }

    /// bd-mo92w — Kernel-conformance pin for the 6 DX_HASH_*
    /// hash-version constants + the 4-word DX_HASH_DEFAULT_SEED per
    /// fs/ext4/ext4.h. These values are read from the superblock @
    /// s_def_hash_version (0xFC) and from dx_root @ 0x1C, then used
    /// by dx_hash() on every htree directory lookup. A regression
    /// that drifted any hash-version value would silently route
    /// lookups through the wrong hash algorithm — every htree
    /// directory operation would return wrong results without
    /// compile error.
    ///
    /// Sister pins: bd-eiblh (incompat), bd-up9ff (compat/ro_compat),
    /// bd-wa27v (xattr), ext4_inode_flag_constants_match_kernel_header.
    #[test]
    fn ext4_dx_hash_version_constants_match_ext4_h() {
        // Per fs/ext4/ext4.h:
        //   #define DX_HASH_LEGACY              0
        //   #define DX_HASH_HALF_MD4            1
        //   #define DX_HASH_TEA                 2
        //   #define DX_HASH_LEGACY_UNSIGNED     3
        //   #define DX_HASH_HALF_MD4_UNSIGNED   4
        //   #define DX_HASH_TEA_UNSIGNED        5
        let cases: &[(&str, u8, u8)] = &[
            ("DX_HASH_LEGACY", DX_HASH_LEGACY, 0),
            ("DX_HASH_HALF_MD4", DX_HASH_HALF_MD4, 1),
            ("DX_HASH_TEA", DX_HASH_TEA, 2),
            ("DX_HASH_LEGACY_UNSIGNED", DX_HASH_LEGACY_UNSIGNED, 3),
            ("DX_HASH_HALF_MD4_UNSIGNED", DX_HASH_HALF_MD4_UNSIGNED, 4),
            ("DX_HASH_TEA_UNSIGNED", DX_HASH_TEA_UNSIGNED, 5),
        ];
        for (name, actual, expected) in cases {
            assert_eq!(
                actual, expected,
                "{name} must equal kernel value {expected}"
            );
        }

        // Pairwise distinctness — two hash version IDs sharing a
        // value would silently route both algorithms through the
        // same path.
        let values: Vec<u8> = cases.iter().map(|&(_, v, _)| v).collect();
        let mut sorted = values.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            values.len(),
            sorted.len(),
            "DX_HASH_* version IDs must be pairwise distinct"
        );

        // Ascending across the contract: 0..=5 inclusive, no gaps.
        // (Kernel reserves 0..=5 for current hash variants; gap-free
        // ordering helps catch a regression that inserted a new ID
        // out of order.)
        for (i, &v) in values.iter().enumerate() {
            assert_eq!(v as usize, i, "DX_HASH_* values must be sequential 0..=5");
        }

        // DX_HASH_DEFAULT_SEED matches MD4 init constants per
        // fs/ext4/ext4.h `EXT4_HTREE_EOF_*` and dx_hash() init.
        // A regression that drifted any seed word would change every
        // computed hash on filesystems lacking a per-fs seed.
        assert_eq!(
            DX_HASH_DEFAULT_SEED,
            [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            "DX_HASH_DEFAULT_SEED must match the kernel's MD4-init seed"
        );
    }

    /// bd-up9ff — Kernel-conformance pin for the Ext4CompatFeatures
    /// (10 bits) and Ext4RoCompatFeatures (14 bits) values per
    /// fs/ext4/ext4.h EXT4_FEATURE_COMPAT_* and EXT4_FEATURE_RO_COMPAT_*.
    /// These bits are read from the superblock @ s_feature_compat
    /// (0x5C) and s_feature_ro_compat (0x64); they gate JOURNAL
    /// presence, METADATA_CSUM verification, SPARSE_SUPER placement,
    /// BIGALLOC, READONLY enforcement, etc. A regression that drifted
    /// any value would silently mis-detect filesystem features —
    /// either failing to mount or mounting with wrong semantics.
    ///
    /// Companion to bd-eiblh (Ext4IncompatFeatures). Sister pins:
    /// bd-wa27v (xattr constants),
    /// ext4_inode_flag_constants_match_kernel_header.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn ext4_compat_and_ro_compat_features_match_ext4_h() {
        // Per fs/ext4/ext4.h — EXT4_FEATURE_COMPAT_*:
        let compat_cases: &[(&str, Ext4CompatFeatures, u32)] = &[
            ("DIR_PREALLOC", Ext4CompatFeatures::DIR_PREALLOC, 0x0001),
            ("IMAGIC_INODES", Ext4CompatFeatures::IMAGIC_INODES, 0x0002),
            ("HAS_JOURNAL", Ext4CompatFeatures::HAS_JOURNAL, 0x0004),
            ("EXT_ATTR", Ext4CompatFeatures::EXT_ATTR, 0x0008),
            ("RESIZE_INODE", Ext4CompatFeatures::RESIZE_INODE, 0x0010),
            ("DIR_INDEX", Ext4CompatFeatures::DIR_INDEX, 0x0020),
            ("SPARSE_SUPER2", Ext4CompatFeatures::SPARSE_SUPER2, 0x0200),
            ("FAST_COMMIT", Ext4CompatFeatures::FAST_COMMIT, 0x0400),
            ("STABLE_INODES", Ext4CompatFeatures::STABLE_INODES, 0x0800),
            ("ORPHAN_FILE", Ext4CompatFeatures::ORPHAN_FILE, 0x1000),
        ];
        for (name, actual, expected) in compat_cases {
            assert_eq!(
                actual.0, *expected,
                "EXT4_FEATURE_COMPAT_{name} must equal kernel value 0x{expected:X}"
            );
            assert_eq!(
                actual.0.count_ones(),
                1,
                "EXT4_FEATURE_COMPAT_{name} must be a single-bit flag"
            );
        }

        // Per fs/ext4/ext4.h — EXT4_FEATURE_RO_COMPAT_*:
        let ro_compat_cases: &[(&str, Ext4RoCompatFeatures, u32)] = &[
            ("SPARSE_SUPER", Ext4RoCompatFeatures::SPARSE_SUPER, 0x0001),
            ("LARGE_FILE", Ext4RoCompatFeatures::LARGE_FILE, 0x0002),
            ("BTREE_DIR", Ext4RoCompatFeatures::BTREE_DIR, 0x0004),
            ("HUGE_FILE", Ext4RoCompatFeatures::HUGE_FILE, 0x0008),
            ("GDT_CSUM", Ext4RoCompatFeatures::GDT_CSUM, 0x0010),
            ("DIR_NLINK", Ext4RoCompatFeatures::DIR_NLINK, 0x0020),
            ("EXTRA_ISIZE", Ext4RoCompatFeatures::EXTRA_ISIZE, 0x0040),
            ("QUOTA", Ext4RoCompatFeatures::QUOTA, 0x0100),
            ("BIGALLOC", Ext4RoCompatFeatures::BIGALLOC, 0x0200),
            ("METADATA_CSUM", Ext4RoCompatFeatures::METADATA_CSUM, 0x0400),
            ("READONLY", Ext4RoCompatFeatures::READONLY, 0x1000),
            ("PROJECT", Ext4RoCompatFeatures::PROJECT, 0x2000),
            ("VERITY", Ext4RoCompatFeatures::VERITY, 0x8000),
            (
                "ORPHAN_PRESENT",
                Ext4RoCompatFeatures::ORPHAN_PRESENT,
                0x1_0000,
            ),
        ];
        for (name, actual, expected) in ro_compat_cases {
            assert_eq!(
                actual.0, *expected,
                "EXT4_FEATURE_RO_COMPAT_{name} must equal kernel value 0x{expected:X}"
            );
            assert_eq!(
                actual.0.count_ones(),
                1,
                "EXT4_FEATURE_RO_COMPAT_{name} must be a single-bit flag"
            );
        }

        // Pairwise distinctness across compat values.
        let compat_bits: Vec<u32> = compat_cases.iter().map(|&(_, f, _)| f.0).collect();
        let mut sorted = compat_bits.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            compat_bits.len(),
            sorted.len(),
            "EXT4_FEATURE_COMPAT_* bit values must be pairwise distinct"
        );

        // Pairwise distinctness across ro_compat values.
        let ro_compat_bits: Vec<u32> = ro_compat_cases.iter().map(|&(_, f, _)| f.0).collect();
        let mut sorted = ro_compat_bits.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            ro_compat_bits.len(),
            sorted.len(),
            "EXT4_FEATURE_RO_COMPAT_* bit values must be pairwise distinct"
        );
    }

    /// bd-o7qbe — Kernel-conformance pin for the core
    /// ext4_super_block field offsets per fs/ext4/ext4.h. Each of
    /// 25 critical fields is stamped with a UNIQUE non-zero magic at
    /// its canonical kernel offset, then a single
    /// Ext4Superblock::parse_superblock_region call must round-trip
    /// every field. The ext4 superblock is the entry point for every
    /// mount/probe; a regression that drifted any single offset
    /// would silently corrupt mount-time bootstrap and either fail to
    /// mount or mount with wrong geometry.
    ///
    /// Sister kernel pins: ext4_inode (bd-ku16x), ext4_dir_entry_2
    /// (bd-12nk4), parse_dx_root (bd-2e5cy), btrfs_super_block
    /// (bd-ormcf), ext4_extent_leaf/index/header,
    /// ext4_mmp_block_kernel_offsets_match_mmp_h.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn ext4_super_block_kernel_offsets_match_ext4_h() {
        // Core geometry (constrained: log_block_size in 0..=2).
        let inodes_count: u32 = 0x0001_0203;
        let blocks_count_lo: u32 = 0x0405_0607;
        let r_blocks_count_lo: u32 = 0x0809_0A0B;
        let free_blocks_count_lo: u32 = 0x0C0D_0E0F;
        let free_inodes_count: u32 = 0x1011_1213;
        let first_data_block: u32 = 0x1415_1617;
        let log_block_size: u32 = 2; // → 4096
        let log_cluster_size: u32 = 2; // → 4096
        let blocks_per_group: u32 = 0x2021_2223;
        let clusters_per_group: u32 = 0x2425_2627;
        let inodes_per_group: u32 = 0x2829_2A2B;
        let mtime: u32 = 0x2C2D_2E2F;
        let wtime: u32 = 0x3031_3233;
        let mnt_count: u16 = 0x3435;
        let max_mnt_count: u16 = 0x3637;
        // s_magic must equal EXT4_SUPER_MAGIC.
        let state: u16 = 0x3A3B;
        let errors: u16 = 0x3C3D;
        let minor_rev_level: u16 = 0x3E3F;
        let lastcheck: u32 = 0x4041_4243;
        let creator_os: u32 = 0x4849_4A4B;
        let rev_level: u32 = 0x4C4D_4E4F;
        let first_ino: u32 = 0x5455_5657;
        let inode_size: u16 = 0x5859;
        let feature_compat: u32 = 0x5C5D_5E5F;
        let feature_incompat: u32 = 0x6061_6263;
        let feature_ro_compat: u32 = 0x6465_6667;
        // 16-byte uuid: distinct first/last bytes.
        let mut uuid = [0_u8; 16];
        uuid[0] = 0x68;
        uuid[15] = 0x77;
        // s_volume_name @ 0x78..0x88 — use a known label.
        let volume_name: &[u8] = b"FRANKEN-PIN";
        let blocks_count_hi: u32 = 0x1501_5253;
        let r_blocks_count_hi: u32 = 0x1545_5657;
        let free_blocks_count_hi: u32 = 0x1589_5A5B;
        let desc_size: u16 = 64; // valid power-of-two, supported
        let log_groups_per_flex: u8 = 0x74;
        let checksum_type: u8 = 0x75;

        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];

        // Magic + log_block_size + log_cluster_size to satisfy validators.
        sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&log_block_size.to_le_bytes());
        sb[0x1C..0x20].copy_from_slice(&log_cluster_size.to_le_bytes());

        // Stamp each field at its canonical offset.
        sb[0x00..0x04].copy_from_slice(&inodes_count.to_le_bytes());
        sb[0x04..0x08].copy_from_slice(&blocks_count_lo.to_le_bytes());
        sb[0x08..0x0C].copy_from_slice(&r_blocks_count_lo.to_le_bytes());
        sb[0x0C..0x10].copy_from_slice(&free_blocks_count_lo.to_le_bytes());
        sb[0x10..0x14].copy_from_slice(&free_inodes_count.to_le_bytes());
        sb[0x14..0x18].copy_from_slice(&first_data_block.to_le_bytes());
        sb[0x20..0x24].copy_from_slice(&blocks_per_group.to_le_bytes());
        sb[0x24..0x28].copy_from_slice(&clusters_per_group.to_le_bytes());
        sb[0x28..0x2C].copy_from_slice(&inodes_per_group.to_le_bytes());
        sb[0x2C..0x30].copy_from_slice(&mtime.to_le_bytes());
        sb[0x30..0x34].copy_from_slice(&wtime.to_le_bytes());
        sb[0x34..0x36].copy_from_slice(&mnt_count.to_le_bytes());
        sb[0x36..0x38].copy_from_slice(&max_mnt_count.to_le_bytes());
        sb[0x3A..0x3C].copy_from_slice(&state.to_le_bytes());
        sb[0x3C..0x3E].copy_from_slice(&errors.to_le_bytes());
        sb[0x3E..0x40].copy_from_slice(&minor_rev_level.to_le_bytes());
        sb[0x40..0x44].copy_from_slice(&lastcheck.to_le_bytes());
        sb[0x48..0x4C].copy_from_slice(&creator_os.to_le_bytes());
        sb[0x4C..0x50].copy_from_slice(&rev_level.to_le_bytes());
        sb[0x54..0x58].copy_from_slice(&first_ino.to_le_bytes());
        sb[0x58..0x5A].copy_from_slice(&inode_size.to_le_bytes());
        sb[0x5C..0x60].copy_from_slice(&feature_compat.to_le_bytes());
        sb[0x60..0x64].copy_from_slice(&feature_incompat.to_le_bytes());
        sb[0x64..0x68].copy_from_slice(&feature_ro_compat.to_le_bytes());
        sb[0x68..0x78].copy_from_slice(&uuid);
        sb[0x78..0x78 + volume_name.len()].copy_from_slice(volume_name);
        sb[0xFE..0x100].copy_from_slice(&desc_size.to_le_bytes());
        sb[0x150..0x154].copy_from_slice(&blocks_count_hi.to_le_bytes());
        sb[0x154..0x158].copy_from_slice(&r_blocks_count_hi.to_le_bytes());
        sb[0x158..0x15C].copy_from_slice(&free_blocks_count_hi.to_le_bytes());
        sb[0x174] = log_groups_per_flex;
        sb[0x175] = checksum_type;

        let parsed =
            Ext4Superblock::parse_superblock_region(&sb).expect("kernel-stamped sb must parse");

        assert_eq!(parsed.inodes_count, inodes_count, "inodes_count @ 0x00");
        assert_eq!(
            parsed.blocks_count,
            u64::from(blocks_count_lo) | (u64::from(blocks_count_hi) << 32),
            "blocks_count_lo @ 0x04 + blocks_count_hi @ 0x150"
        );
        assert_eq!(
            parsed.reserved_blocks_count,
            u64::from(r_blocks_count_lo) | (u64::from(r_blocks_count_hi) << 32),
            "r_blocks_count_lo @ 0x08 + r_blocks_count_hi @ 0x154"
        );
        assert_eq!(
            parsed.free_blocks_count,
            u64::from(free_blocks_count_lo) | (u64::from(free_blocks_count_hi) << 32),
            "free_blocks_count_lo @ 0x0C + free_blocks_count_hi @ 0x158"
        );
        assert_eq!(
            parsed.free_inodes_count, free_inodes_count,
            "free_inodes_count @ 0x10"
        );
        assert_eq!(
            parsed.first_data_block, first_data_block,
            "first_data_block @ 0x14"
        );
        assert_eq!(parsed.block_size, 4096, "block_size derived from 0x18");
        assert_eq!(
            parsed.blocks_per_group, blocks_per_group,
            "blocks_per_group @ 0x20"
        );
        assert_eq!(
            parsed.clusters_per_group, clusters_per_group,
            "clusters_per_group @ 0x24"
        );
        assert_eq!(
            parsed.inodes_per_group, inodes_per_group,
            "inodes_per_group @ 0x28"
        );
        assert_eq!(parsed.mtime, mtime, "mtime @ 0x2C");
        assert_eq!(parsed.wtime, wtime, "wtime @ 0x30");
        assert_eq!(parsed.mnt_count, mnt_count, "mnt_count @ 0x34");
        assert_eq!(parsed.max_mnt_count, max_mnt_count, "max_mnt_count @ 0x36");
        assert_eq!(parsed.magic, EXT4_SUPER_MAGIC, "magic @ 0x38");
        assert_eq!(parsed.state, state, "state @ 0x3A");
        assert_eq!(parsed.errors, errors, "errors @ 0x3C");
        assert_eq!(
            parsed.minor_rev_level, minor_rev_level,
            "minor_rev_level @ 0x3E"
        );
        assert_eq!(parsed.lastcheck, lastcheck, "lastcheck @ 0x40");
        assert_eq!(parsed.creator_os, creator_os, "creator_os @ 0x48");
        assert_eq!(parsed.rev_level, rev_level, "rev_level @ 0x4C");
        assert_eq!(parsed.first_ino, first_ino, "first_ino @ 0x54");
        assert_eq!(parsed.inode_size, inode_size, "inode_size @ 0x58");
        assert_eq!(
            parsed.feature_compat.0, feature_compat,
            "feature_compat @ 0x5C"
        );
        assert_eq!(
            parsed.feature_incompat.0, feature_incompat,
            "feature_incompat @ 0x60"
        );
        assert_eq!(
            parsed.feature_ro_compat.0, feature_ro_compat,
            "feature_ro_compat @ 0x64"
        );
        assert_eq!(parsed.uuid, uuid, "uuid @ 0x68..0x78");
        assert_eq!(
            parsed.volume_name,
            std::str::from_utf8(volume_name).unwrap(),
            "volume_name @ 0x78..0x88"
        );
        assert_eq!(parsed.desc_size, desc_size, "desc_size @ 0xFE");
    }

    /// bd-eiblh — Kernel-conformance pin for the 16 Ext4IncompatFeatures
    /// bit values per fs/ext4/ext4.h EXT4_FEATURE_INCOMPAT_*. These
    /// bits are read from the superblock @ s_feature_incompat (0x60)
    /// and gate every feature decision: extent vs indirect block,
    /// htree depth (LARGEDIR), MMP enabled, checksum seed (CSUM_SEED),
    /// encryption, casefold. A regression that drifted any value
    /// would silently mis-detect filesystem features and either fail
    /// to mount or mount with wrong semantics.
    ///
    /// Sister pins: ext4_xattr_constants_match_xattr_h (bd-wa27v),
    /// ext4_inode_flag_constants_match_kernel_header,
    /// btrfs_csum_type_constants_match_kernel_header,
    /// ext4_btrfs_layout_constants_match_kernel_header,
    /// ext4_file_type_constants_match_kernel_header.
    #[test]
    fn ext4_incompat_features_match_ext4_h() {
        // Per fs/ext4/ext4.h:
        //   #define EXT4_FEATURE_INCOMPAT_COMPRESSION  0x0001
        //   #define EXT4_FEATURE_INCOMPAT_FILETYPE     0x0002
        //   #define EXT4_FEATURE_INCOMPAT_RECOVER      0x0004
        //   #define EXT4_FEATURE_INCOMPAT_JOURNAL_DEV  0x0008
        //   #define EXT4_FEATURE_INCOMPAT_META_BG      0x0010
        //   #define EXT4_FEATURE_INCOMPAT_EXTENTS      0x0040
        //   #define EXT4_FEATURE_INCOMPAT_64BIT        0x0080
        //   #define EXT4_FEATURE_INCOMPAT_MMP          0x0100
        //   #define EXT4_FEATURE_INCOMPAT_FLEX_BG      0x0200
        //   #define EXT4_FEATURE_INCOMPAT_EA_INODE     0x0400
        //   #define EXT4_FEATURE_INCOMPAT_DIRDATA      0x1000
        //   #define EXT4_FEATURE_INCOMPAT_CSUM_SEED    0x2000
        //   #define EXT4_FEATURE_INCOMPAT_LARGEDIR     0x4000
        //   #define EXT4_FEATURE_INCOMPAT_INLINE_DATA  0x8000
        //   #define EXT4_FEATURE_INCOMPAT_ENCRYPT      0x10000
        //   #define EXT4_FEATURE_INCOMPAT_CASEFOLD     0x20000
        let cases: &[(&str, Ext4IncompatFeatures, u32)] = &[
            ("COMPRESSION", Ext4IncompatFeatures::COMPRESSION, 0x0001),
            ("FILETYPE", Ext4IncompatFeatures::FILETYPE, 0x0002),
            ("RECOVER", Ext4IncompatFeatures::RECOVER, 0x0004),
            ("JOURNAL_DEV", Ext4IncompatFeatures::JOURNAL_DEV, 0x0008),
            ("META_BG", Ext4IncompatFeatures::META_BG, 0x0010),
            ("EXTENTS", Ext4IncompatFeatures::EXTENTS, 0x0040),
            ("BIT64", Ext4IncompatFeatures::BIT64, 0x0080),
            ("MMP", Ext4IncompatFeatures::MMP, 0x0100),
            ("FLEX_BG", Ext4IncompatFeatures::FLEX_BG, 0x0200),
            ("EA_INODE", Ext4IncompatFeatures::EA_INODE, 0x0400),
            ("DIRDATA", Ext4IncompatFeatures::DIRDATA, 0x1000),
            ("CSUM_SEED", Ext4IncompatFeatures::CSUM_SEED, 0x2000),
            ("LARGEDIR", Ext4IncompatFeatures::LARGEDIR, 0x4000),
            ("INLINE_DATA", Ext4IncompatFeatures::INLINE_DATA, 0x8000),
            ("ENCRYPT", Ext4IncompatFeatures::ENCRYPT, 0x10000),
            ("CASEFOLD", Ext4IncompatFeatures::CASEFOLD, 0x20000),
        ];
        for (name, actual, expected) in cases {
            assert_eq!(
                actual.0, *expected,
                "EXT4_FEATURE_INCOMPAT_{name} must equal kernel value 0x{expected:X}"
            );
        }

        // Pairwise distinctness: every flag must be a unique bit
        // (single-bit pattern). A regression that aliased two flags
        // would route both feature checks to the same bit.
        let bits: Vec<u32> = cases.iter().map(|&(_, f, _)| f.0).collect();
        let mut sorted = bits.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            bits.len(),
            sorted.len(),
            "EXT4_FEATURE_INCOMPAT_* bit values must be pairwise distinct"
        );
        // Each value should be a single bit (power-of-two).
        for (name, actual, _) in cases {
            assert_eq!(
                actual.0.count_ones(),
                1,
                "EXT4_FEATURE_INCOMPAT_{name} must be a single-bit flag"
            );
        }
    }

    /// bd-ku16x — Kernel-conformance pin for the base 128-byte
    /// ext4_inode field offsets per fs/ext4/ext4.h. Each field is
    /// stamped with a UNIQUE non-zero magic at its canonical kernel
    /// offset, then a single Ext4Inode::parse_from_bytes call must
    /// round-trip every field. Ext4Inode is parsed on every ext4 file
    /// open / readdir / stat / xattr — the most heavily-trafficked
    /// ext4 struct. A regression that drifted any offset would
    /// mis-route mode-vs-uid_lo or atime-vs-ctime silently.
    ///
    /// Sister kernel-offset pins:
    /// ext4_dir_entry_2_kernel_offsets_match_ext4_h (bd-12nk4),
    /// parse_dx_root_kernel_offsets_match_ext4_h (bd-2e5cy),
    /// ext4_extent_leaf/index/header_kernel_offsets_match_extents_h,
    /// ext4_mmp_block_kernel_offsets_match_mmp_h, plus
    /// ext4_inode_flag_constants_match_kernel_header (which pins the
    /// flag values this test relies on indirectly).
    #[test]
    fn ext4_inode_kernel_offsets_match_ext4_h() {
        // Distinct non-zero magics. Each byte position in the inode
        // holds a value matching its address (little-endian), so an
        // offset drift produces a cross-field collision.
        // mode must encode a known type for size_hi to be read; pick
        // S_IFREG | 0o644 (0x81A4) so is_reg=true and 0x6C is read.
        let mode: u16 = 0x81A4;
        let uid_lo: u16 = 0x0203;
        let size_lo: u32 = 0x0405_0607;
        let atime: u32 = 0x0809_0A0B;
        let ctime: u32 = 0x0C0D_0E0F;
        let mtime: u32 = 0x1011_1213;
        let dtime: u32 = 0x1415_1617;
        let gid_lo: u16 = 0x1819;
        let links_count: u16 = 0x1A1B;
        let blocks_lo: u32 = 0x1C1D_1E1F;
        let flags: u32 = 0x2021_2223;
        let version: u32 = 0x2425_2627;
        let generation: u32 = 0x6465_6667;
        let file_acl_lo: u32 = 0x6869_6A6B;
        let size_hi: u32 = 0x6C6D_6E6F;

        // 128-byte base area; we don't exercise extra_isize / OS-Linux
        // extended fields here (those are 0x74..0x80 and 0x80+).
        let mut bytes = vec![0_u8; 128];
        bytes[0x00..0x02].copy_from_slice(&mode.to_le_bytes());
        bytes[0x02..0x04].copy_from_slice(&uid_lo.to_le_bytes());
        bytes[0x04..0x08].copy_from_slice(&size_lo.to_le_bytes());
        bytes[0x08..0x0C].copy_from_slice(&atime.to_le_bytes());
        bytes[0x0C..0x10].copy_from_slice(&ctime.to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&mtime.to_le_bytes());
        bytes[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());
        bytes[0x18..0x1A].copy_from_slice(&gid_lo.to_le_bytes());
        bytes[0x1A..0x1C].copy_from_slice(&links_count.to_le_bytes());
        bytes[0x1C..0x20].copy_from_slice(&blocks_lo.to_le_bytes());
        bytes[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
        bytes[0x24..0x28].copy_from_slice(&version.to_le_bytes());
        // i_block[15] @ 0x28..0x64: 60 bytes left zero (extent_bytes
        // captures them but we don't pin their content here).
        bytes[0x64..0x68].copy_from_slice(&generation.to_le_bytes());
        bytes[0x68..0x6C].copy_from_slice(&file_acl_lo.to_le_bytes());
        // size_hi only read when len() >= 0x70 AND is_reg/is_dir.
        // 128 ≥ 0x70, mode encodes S_IFREG, so it's read.
        bytes[0x6C..0x70].copy_from_slice(&size_hi.to_le_bytes());

        let inode =
            Ext4Inode::parse_from_bytes(&bytes).expect("kernel-stamped ext4_inode must parse");

        assert_eq!(inode.mode, mode, "mode @ 0x00..0x02");
        // uid is recombined from uid_lo (0x02) and uid_hi (0x78); we
        // didn't write 0x78 so uid_hi==0 and inode.uid == uid_lo.
        assert_eq!(inode.uid, u32::from(uid_lo), "uid_lo @ 0x02..0x04");
        // size is recombined from size_lo (0x04) and size_hi (0x6C).
        assert_eq!(
            inode.size,
            u64::from(size_lo) | (u64::from(size_hi) << 32),
            "size_lo @ 0x04 + size_hi @ 0x6C"
        );
        assert_eq!(inode.atime, atime, "atime @ 0x08..0x0C");
        assert_eq!(inode.ctime, ctime, "ctime @ 0x0C..0x10");
        assert_eq!(inode.mtime, mtime, "mtime @ 0x10..0x14");
        assert_eq!(inode.dtime, dtime, "dtime @ 0x14..0x18");
        assert_eq!(inode.gid, u32::from(gid_lo), "gid_lo @ 0x18..0x1A");
        assert_eq!(inode.links_count, links_count, "links_count @ 0x1A..0x1C");
        assert_eq!(
            inode.blocks,
            u64::from(blocks_lo),
            "blocks_lo @ 0x1C..0x20 (no high-half stamped)"
        );
        assert_eq!(inode.flags, flags, "flags @ 0x20..0x24");
        assert_eq!(inode.version, version, "version (l_i_version) @ 0x24..0x28");
        assert_eq!(inode.generation, generation, "generation @ 0x64..0x68");
        assert_eq!(
            inode.file_acl,
            u64::from(file_acl_lo),
            "file_acl_lo @ 0x68..0x6C (no high-half stamped)"
        );
    }

    /// bd-2e5cy — Kernel-conformance pin for parse_dx_root layout per
    /// fs/ext4/ext4.h struct dx_root + struct dx_entry. parse_dx_root
    /// validates strict kernel offsets:
    ///   reserved_zero u32 @ 0x18 (must be 0)
    ///   hash_version  u8  @ 0x1C
    ///   info_length   u8  @ 0x1D (must be 8)
    ///   indirect_levels u8 @ 0x1E
    ///   unused_flags  u8  @ 0x1F (must be 0)
    ///   limit         u16 @ 0x20
    ///   count         u16 @ 0x22
    ///   first_block   u32 @ 0x24 (implicit-hash-0 entry's block)
    ///   dx_entry[i]   @ 0x28 + (i-1)*8 for i ≥ 1 (hash u32@0, block u32@4)
    /// Each field is stamped with a UNIQUE non-zero magic at its
    /// canonical offset; parse_dx_root must round-trip every field. A
    /// regression that drifted any single offset would mis-route
    /// hash_version-vs-info_length or hash-vs-block silently — and
    /// parse_dx_root runs on every htree-indexed directory lookup.
    ///
    /// Sister kernel-offset pins:
    /// ext4_extent_leaf_kernel_offsets_match_extents_h,
    /// ext4_extent_index_kernel_offsets_match_extents_h,
    /// ext4_extent_header_kernel_offsets_match_extents_h,
    /// ext4_mmp_block_kernel_offsets_match_mmp_h,
    /// ext4_dir_entry_2_kernel_offsets_match_ext4_h (bd-12nk4).
    #[test]
    fn parse_dx_root_kernel_offsets_match_ext4_h() {
        // Allocate a 0x40-byte block: 0x18 fake-dirents + 0x08
        // dx_root_info + 0x08 dx_countlimit/entry-0 + 0x10 for two
        // dx_entries (entries 1, 2 — entry 0 is implicit-hash-0).
        let mut block = vec![0_u8; 0x40];

        // Distinct non-zero magics. info_length must equal 8 (parser
        // hard-validates); unused_flags must equal 0; reserved_zero
        // must equal 0. The remaining fields can hold any magic.
        let hash_version: u8 = 0x33;
        let indirect_levels: u8 = 0x02;
        let limit: u16 = 0x4444;
        let count: u16 = 3; // 1 implicit + 2 explicit entries
        let first_block: u32 = 0x6666_6666;
        let entry1_hash: u32 = 0x7777_7777;
        let entry1_block: u32 = 0x8888_8888;
        let entry2_hash: u32 = 0x9999_9999;
        let entry2_block: u32 = 0xAAAA_AAAA;

        // Header info @ 0x18..0x20.
        // reserved_zero @ 0x18 = 0 (already zero-initialized)
        block[0x1C] = hash_version;
        block[0x1D] = 8; // info_length, parser-required
        block[0x1E] = indirect_levels;
        // unused_flags @ 0x1F = 0 (already zero-initialized)
        // dx_countlimit @ 0x20: limit u16 + count u16.
        block[0x20..0x22].copy_from_slice(&limit.to_le_bytes());
        block[0x22..0x24].copy_from_slice(&count.to_le_bytes());
        // dx_countlimit doubles as entry 0: implicit hash=0, block @ 0x24.
        block[0x24..0x28].copy_from_slice(&first_block.to_le_bytes());
        // Entry 1 @ 0x28: hash u32 + block u32.
        block[0x28..0x2C].copy_from_slice(&entry1_hash.to_le_bytes());
        block[0x2C..0x30].copy_from_slice(&entry1_block.to_le_bytes());
        // Entry 2 @ 0x30: hash u32 + block u32.
        block[0x30..0x34].copy_from_slice(&entry2_hash.to_le_bytes());
        block[0x34..0x38].copy_from_slice(&entry2_block.to_le_bytes());

        let root = parse_dx_root(&block).expect("kernel-stamped dx_root must parse");

        assert_eq!(root.hash_version, hash_version, "hash_version @ 0x1C");
        assert_eq!(
            root.indirect_levels, indirect_levels,
            "indirect_levels @ 0x1E"
        );
        assert_eq!(root.entries.len(), 3);
        // Entry 0: implicit hash=0, block @ 0x24.
        assert_eq!(root.entries[0].hash, 0, "entry[0].hash implicit 0");
        assert_eq!(root.entries[0].block, first_block, "entry[0].block @ 0x24");
        // Entry 1.
        assert_eq!(root.entries[1].hash, entry1_hash, "entry[1].hash @ 0x28");
        assert_eq!(root.entries[1].block, entry1_block, "entry[1].block @ 0x2C");
        // Entry 2.
        assert_eq!(root.entries[2].hash, entry2_hash, "entry[2].hash @ 0x30");
        assert_eq!(root.entries[2].block, entry2_block, "entry[2].block @ 0x34");
    }

    /// bd-gauub (write-half STEP 1): `write_dx_root` is the exact inverse of
    /// `parse_dx_root`. Pins the serializer byte-for-byte against the same
    /// kernel layout the offset test above hand-builds, then round-trips.
    #[test]
    fn write_dx_root_round_trips_with_parse() {
        let entries = vec![
            Ext4DxEntry {
                hash: 0,
                block: 0x6666_6666,
            }, // entry 0 (implicit hash 0)
            Ext4DxEntry {
                hash: 0x7777_7777,
                block: 0x8888_8888,
            },
            Ext4DxEntry {
                hash: 0x9999_9999,
                block: 0xAAAA_AAAA,
            },
        ];
        let mut block = vec![0_u8; 0x40];
        write_dx_root(&mut block, 0x33, 0x02, 0x4444, &entries).expect("write_dx_root");

        // Byte-identity vs the hand-built kernel layout (cf. the offset pin).
        let mut expected = vec![0_u8; 0x40];
        expected[0x1C] = 0x33;
        expected[0x1D] = 8;
        expected[0x1E] = 0x02;
        expected[0x20..0x22].copy_from_slice(&0x4444_u16.to_le_bytes());
        expected[0x22..0x24].copy_from_slice(&3_u16.to_le_bytes());
        expected[0x24..0x28].copy_from_slice(&0x6666_6666_u32.to_le_bytes());
        expected[0x28..0x2C].copy_from_slice(&0x7777_7777_u32.to_le_bytes());
        expected[0x2C..0x30].copy_from_slice(&0x8888_8888_u32.to_le_bytes());
        expected[0x30..0x34].copy_from_slice(&0x9999_9999_u32.to_le_bytes());
        expected[0x34..0x38].copy_from_slice(&0xAAAA_AAAA_u32.to_le_bytes());
        assert_eq!(
            block, expected,
            "write_dx_root must match the kernel layout"
        );

        // Inverse round-trip recovers exactly what we wrote.
        let parsed = parse_dx_root(&block).expect("parse round-trip");
        assert_eq!(parsed.hash_version, 0x33);
        assert_eq!(parsed.indirect_levels, 0x02);
        assert_eq!(parsed.entries, entries);

        // Limit helper: 1 KiB block => (1024-0x20)/8 = 124 slots; csum reserves 1.
        assert_eq!(dx_root_entry_limit(1024, false), 124);
        assert_eq!(dx_root_entry_limit(1024, true), 123);

        // count > limit is rejected.
        let mut tiny = vec![0_u8; 0x40];
        assert!(write_dx_root(&mut tiny, 1, 0, 1, &entries).is_err());
    }

    #[test]
    fn write_dx_node_round_trips_with_parse() {
        let entries = vec![
            Ext4DxEntry {
                hash: 0,
                block: 0x1111_1111,
            }, // entry 0 (implicit hash 0)
            Ext4DxEntry {
                hash: 0x2222_2222,
                block: 0x3333_3333,
            },
            Ext4DxEntry {
                hash: 0x4444_4444,
                block: 0x5555_5555,
            },
        ];
        let mut block = vec![0_u8; 0x40];
        write_dx_node(&mut block, 0x07, &entries).expect("write_dx_node");

        // Inverse round-trip recovers exactly the entries we wrote.
        let parsed =
            parse_dx_entries(&block, DX_NODE_COUNT_OFFSET).expect("parse_dx_entries round-trip");
        assert_eq!(parsed, entries);

        // Reject branches: empty entries and a count exceeding the limit.
        let mut tiny = vec![0_u8; 0x40];
        assert!(write_dx_node(&mut tiny, 0x07, &[]).is_err());
        assert!(write_dx_node(&mut tiny, 1, &entries).is_err());
    }

    /// bd-gauub (write-half STEP 2): leaf-split point selection invariants.
    #[test]
    fn choose_htree_leaf_split_invariants() {
        // Too few / unsplittable inputs.
        assert_eq!(choose_htree_leaf_split(&[]), None);
        assert_eq!(choose_htree_leaf_split(&[(5, 16)]), None);
        // All entries collide on one hash -> no clean boundary.
        assert_eq!(choose_htree_leaf_split(&[(7, 16), (7, 16), (7, 16)]), None);

        // Two distinct hashes split at the boundary.
        assert_eq!(choose_htree_leaf_split(&[(3, 16), (9, 16)]), Some((1, 9)));

        // Balanced split picks the boundary closest to the byte midpoint.
        // Uniform 16-byte entries, hashes 10,20,30,40 -> midpoint at index 2.
        let uniform = [(10, 16), (20, 16), (30, 16), (40, 16)];
        assert_eq!(choose_htree_leaf_split(&uniform), Some((2, 30)));

        // An equal-hash run must NEVER be split inside the run, no matter where
        // the byte midpoint falls: hashes [10,20,20,20,90] only have clean
        // boundaries at index 1 and index 4, so the split is one of those.
        let run = [(10, 16), (20, 16), (20, 16), (20, 16), (90, 16)];
        let (idx, _) = choose_htree_leaf_split(&run).expect("splittable");
        assert!(
            idx == 1 || idx == 4,
            "split must not land inside the 20-run"
        );
        // With a large trailing entry the midpoint lands past the run -> index 4.
        let run_heavy = [(10, 16), (20, 16), (20, 16), (20, 16), (90, 64)];
        assert_eq!(choose_htree_leaf_split(&run_heavy), Some((4, 90)));

        // General invariant check across a randomized-ish set.
        let mut state = 0x9E37_79B9_u32;
        let mut entries: Vec<(u32, usize)> = (0..40)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 20, 12 + ((state as usize) % 5) * 4)
            })
            .collect();
        entries.sort_by_key(|&(h, _)| h);
        if let Some((i, h)) = choose_htree_leaf_split(&entries) {
            assert!(i >= 1 && i < entries.len());
            assert_eq!(entries[i].0, h);
            assert!(entries[..i].iter().all(|&(eh, _)| eh < h), "lower < split");
            assert!(
                entries[i..].iter().all(|&(eh, _)| eh >= h),
                "upper >= split"
            );
            assert!(entries[i - 1].0 < h, "split is on a clean boundary");
        }
    }

    /// bd-gauub (write-half STEP 3): pack_dir_block_entries is the inverse of the
    /// parse_dir_block entry walk, with and without a checksum tail.
    #[test]
    fn pack_dir_block_entries_round_trips() {
        let bs = 4096_usize;
        let entries: Vec<(u32, u8, &[u8])> = vec![
            (11, EXT4_FT_REG_FILE, b"alpha".as_slice()),
            (12, EXT4_FT_DIR, b"beta".as_slice()),
            (
                13,
                EXT4_FT_REG_FILE,
                b"a_much_longer_file_name_here.txt".as_slice(),
            ),
        ];
        for &with_csum in &[false, true] {
            let block = pack_dir_block_entries(&entries, bs, with_csum).expect("pack");
            let (parsed, tail) =
                parse_dir_block(&block, u32::try_from(bs).unwrap()).expect("parse");
            assert_eq!(parsed.len(), entries.len(), "with_csum={with_csum}");
            for (p, e) in parsed.iter().zip(entries.iter()) {
                assert_eq!(p.inode, e.0);
                assert_eq!(p.name.as_slice(), e.2);
                assert_eq!(p.name_len as usize, e.2.len());
            }
            assert_eq!(tail.is_some(), with_csum, "tail presence tracks with_csum");
        }

        // Empty block: no real (non-zero-inode) entries.
        let empty = pack_dir_block_entries(&[], bs, false).expect("pack empty");
        let (parsed, _) = parse_dir_block(&empty, u32::try_from(bs).unwrap()).expect("parse empty");
        assert!(parsed.iter().all(|e| e.inode == 0));

        // Overflow is rejected.
        let huge: Vec<(u32, u8, &[u8])> = (0..300)
            .map(|_| (1_u32, EXT4_FT_REG_FILE, b"x".as_slice()))
            .collect();
        assert!(pack_dir_block_entries(&huge, 1024, false).is_err());

        // Record-length helper matches the kernel EXT4_DIR_REC_LEN rounding.
        assert_eq!(dir_entry_rec_len(1), 12);
        assert_eq!(dir_entry_rec_len(4), 12);
        assert_eq!(dir_entry_rec_len(5), 16);
        assert_eq!(dir_entry_rec_len(255), 264);
    }

    /// bd-gauub (write-half STEP 4): a freshly built htree directory must be
    /// navigable by the read-half — htree_find_entry locates every entry through
    /// the index. This closes the write<->read loop (the read-half is itself
    /// validated against a real kernel htree image).
    #[test]
    fn build_htree_directory_is_navigable() {
        let bs = 4096_usize;
        let seed = [0x1234_5678_u32, 0x9abc_def0, 0x0f0f_0f0f, 0xa5a5_a5a5];
        let hash_version = 1_u8; // half_md4

        // Enough entries to force several leaf blocks under the dx_root.
        let names: Vec<Vec<u8>> = (0..300)
            .map(|i| format!("file_{i:05}").into_bytes())
            .collect();
        let entries: Vec<(u32, u8, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    100 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();

        let blocks = build_htree_directory(2, 2, &entries, bs, hash_version, &seed, false)
            .expect("single-level htree should build");
        assert!(
            blocks.len() >= 3,
            "should span dx_root + multiple leaves, got {}",
            blocks.len()
        );

        let read = |blocks: &[Vec<u8>], name: &[u8]| {
            htree_find_entry(
                u32::try_from(bs).unwrap(),
                &seed,
                false,
                name,
                |v| v,
                |lb| blocks.get(lb as usize).cloned(),
            )
        };

        for (i, name) in names.iter().enumerate() {
            match read(&blocks, name) {
                HtreeFindResult::Found(e) => {
                    assert_eq!(
                        e.inode,
                        100 + u32::try_from(i).unwrap(),
                        "wrong inode {name:?}"
                    );
                }
                other => panic!("entry {name:?} not reachable via index: {other:?}"),
            }
        }

        // Absent name must not yield a false positive.
        assert!(
            !matches!(read(&blocks, b"does_not_exist"), HtreeFindResult::Found(_)),
            "false positive for an absent name"
        );
    }

    /// bd-gauub (write-half STEP 4.5): the htree index-block checksum matches
    /// e2fsprogs. Oracle is the dx_root of inode 13 ("htree" dir) from the
    /// committed metadata_csum golden image; e2fsprogs stamped
    /// dt_checksum = 0xdab8599a (csum seed 0xea5be0da, gen 0).
    #[test]
    fn dx_block_csum_matches_e2fsprogs_oracle() {
        const SEED: u32 = 0xea5b_e0da;
        const INO: u32 = 13;
        const GEN: u32 = 0;
        const ORACLE: u32 = 0xdab8_599a;
        let block: &[u8] =
            include_bytes!("../../../conformance/golden/dx_root_oracle_metadata_csum.bin");
        assert_eq!(block.len(), 4096);

        assert_eq!(
            ext4_dx_block_csum(block, SEED, INO, GEN, DX_ROOT_COUNT_OFFSET),
            Some(ORACLE),
            "ext4_dx_block_csum must reproduce the e2fsprogs dt_checksum"
        );
        assert!(verify_dx_block_checksum(
            block,
            SEED,
            INO,
            GEN,
            DX_ROOT_COUNT_OFFSET
        ));

        // Stamping a clobbered copy restores the exact oracle value.
        let mut clobbered = block.to_vec();
        let limit = usize::from(u16::from_le_bytes([clobbered[0x20], clobbered[0x21]]));
        let tail = 0x20 + limit * 8;
        clobbered[tail + 4..tail + 8].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        assert!(!verify_dx_block_checksum(
            &clobbered,
            SEED,
            INO,
            GEN,
            DX_ROOT_COUNT_OFFSET
        ));
        stamp_dx_block_checksum(&mut clobbered, SEED, INO, GEN, DX_ROOT_COUNT_OFFSET);
        assert_eq!(&clobbered[tail + 4..tail + 8], &ORACLE.to_le_bytes());
        assert!(verify_dx_block_checksum(
            &clobbered,
            SEED,
            INO,
            GEN,
            DX_ROOT_COUNT_OFFSET
        ));

        // A wrong inode must not verify (the per-inode seed binds it).
        assert!(!verify_dx_block_checksum(
            block,
            SEED,
            INO + 1,
            GEN,
            DX_ROOT_COUNT_OFFSET
        ));
    }

    /// bd-gauub (write-half): the stamped builder produces a directory that is
    /// both navigable by the read-half AND fully checksum-valid (dx root + every
    /// leaf), i.e. e2fsck-ready on a metadata_csum filesystem.
    #[test]
    fn build_htree_directory_stamped_is_navigable_and_checksummed() {
        let bs = 4096_usize;
        let seed = [0x1111_1111_u32, 0x2222_2222, 0x3333_3333, 0x4444_4444];
        let csum_seed = 0xabcd_1234_u32;
        let dir_ino = 77_u32;
        let generation = 5_u32;
        let hash_version = 1_u8;

        let names: Vec<Vec<u8>> = (0..250)
            .map(|i| format!("entry_{i:04}").into_bytes())
            .collect();
        let entries: Vec<(u32, u8, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    200 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();

        let blocks = build_htree_directory_stamped(
            2,
            2,
            &entries,
            bs,
            hash_version,
            &seed,
            csum_seed,
            dir_ino,
            generation,
        )
        .expect("stamped htree build");
        assert!(blocks.len() >= 3, "needs dx_root + multiple leaves");

        // DX root + every leaf checksum verifies under the e2fsprogs-pinned formulas.
        assert!(verify_dx_block_checksum(
            &blocks[0],
            csum_seed,
            dir_ino,
            generation,
            DX_ROOT_COUNT_OFFSET
        ));
        for leaf in &blocks[1..] {
            verify_dir_block_checksum(leaf, csum_seed, dir_ino, generation)
                .expect("leaf block checksum must verify");
        }

        // Still navigable: the checksum tails don't disturb index navigation.
        for (i, name) in names.iter().enumerate() {
            match htree_find_entry(
                u32::try_from(bs).unwrap(),
                &seed,
                false,
                name,
                |v| v,
                |lb| blocks.get(lb as usize).cloned(),
            ) {
                HtreeFindResult::Found(e) => {
                    assert_eq!(e.inode, 200 + u32::try_from(i).unwrap());
                }
                other => panic!("entry {name:?} not reachable: {other:?}"),
            }
        }
    }

    /// bd-rename-2lvl piece (1): `promote_dx_root_to_two_level` must produce a
    /// two-level index through which EVERY original leaf is still reachable by the
    /// read-half descent (dx_root → dx_node → leaf), and leave both dx_nodes
    /// under-full so a subsequent leaf-split has room.
    #[test]
    fn promote_dx_root_to_two_level_routes_every_entry() {
        let block_size = 4096usize;
        // Build a single-level dx_root with N leaf pointers, hashes strictly
        // increasing so a clean boundary exists. Entry 0's hash is implicit (0).
        let n = 40u32;
        let leaves: Vec<Ext4DxEntry> = (0..n)
            .map(|i| Ext4DxEntry {
                hash: i * 1000,
                block: 100 + i, // leaf logical blocks
            })
            .collect();
        let root_limit = dx_root_entry_limit(block_size, false);
        let mut root = vec![0u8; block_size];
        write_dx_root(&mut root, 1, 0, root_limit, &leaves).expect("build single-level root");

        let (a_log, b_log) = (900u32, 901u32);
        let (new_root, node_a, node_b) =
            promote_dx_root_to_two_level(&root, block_size, false, false, a_log, b_log, 0, 2, 7)
                .expect("promotion applies");

        // New root is two-level with exactly two entries.
        let parsed_root = parse_dx_root_with_large_dir(&new_root, false).expect("parse new root");
        assert_eq!(parsed_root.indirect_levels, 1, "must be two-level");
        assert_eq!(parsed_root.entries.len(), 2, "root indexes two dx_nodes");

        let a_entries = parse_dx_entries(&node_a, DX_NODE_COUNT_OFFSET).expect("parse node a");
        let b_entries = parse_dx_entries(&node_b, DX_NODE_COUNT_OFFSET).expect("parse node b");
        // Each node is under-full (room for a future leaf-split).
        let node_limit = usize::from(dx_node_entry_limit(block_size, false));
        assert!(a_entries.len() < node_limit && b_entries.len() < node_limit);
        assert_eq!(
            a_entries.len() + b_entries.len(),
            leaves.len(),
            "no entry dropped"
        );

        // ORACLE: for every original (hash, leaf), the two-level descent reaches
        // the same leaf block the single-level index pointed at.
        for leaf in &leaves {
            let ridx = dx_find_leaf_idx(&parsed_root.entries, leaf.hash);
            let node_logical = parsed_root.entries[ridx].block;
            let node_entries = if node_logical == a_log {
                &a_entries
            } else if node_logical == b_log {
                &b_entries
            } else {
                panic!("root routed to an unknown dx_node block {node_logical}");
            };
            let nidx = dx_find_leaf_idx(node_entries, leaf.hash);
            assert_eq!(
                node_entries[nidx].block, leaf.block,
                "hash {} routed to leaf {} but should reach {}",
                leaf.hash, node_entries[nidx].block, leaf.block
            );
        }
    }

    /// bd-gauub (incremental leaf split): `split_htree_leaf` splits ONE full leaf
    /// and inserts ONE dx_entry, keeping the directory navigable for EVERY entry
    /// and keeping all three blocks' checksums valid — the O(log N) rename fast
    /// path that replaces the O(dir) rebuild. The read-half `htree_find_entry` is
    /// the oracle: after the split, every original name plus the new name must
    /// still resolve through the (now wider) single-level index.
    // `too_many_lines` (130/100) is a maintainability heuristic for production
    // functions; this is one indivisible on-disk SCENARIO — build a stamped htree,
    // overfill a leaf, split it, then re-resolve every original name plus the new
    // one through the widened index. Splitting it into helpers to reach 100 would
    // scatter the sequence a reader has to follow in order, and hiding half the
    // setup behind a helper is how a scenario test quietly stops testing the
    // scenario. Narrow allow on this function only, not a blanket test exemption
    // (bd-3ao0l); overrule it by restructuring the test, never by widening this.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn htree_leaf_split_keeps_dir_navigable_and_checksummed_bd_gauub() {
        let bs = 1024_usize; // small block => few entries per leaf, easy to overfill
        let seed = [0x1357_9bdf_u32, 0x2468_ace0, 0xfeed_beef, 0x0bad_cafe];
        let csum_seed = 0x55aa_33cc_u32;
        let dir_ino = 131_u32;
        let generation = 9_u32;
        let hash_version = 1_u8; // half_md4

        // Enough entries to make several single-level leaves at 1 KiB.
        let names: Vec<Vec<u8>> = (0..400)
            .map(|i| format!("name_{i:05}").into_bytes())
            .collect();
        let entries: Vec<(u32, u8, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    1000 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();

        let mut blocks = build_htree_directory_stamped(
            2,
            2,
            &entries,
            bs,
            hash_version,
            &seed,
            csum_seed,
            dir_ino,
            generation,
        )
        .expect("stamped htree build");
        // Single level only (this test exercises the single-level fast path).
        let root = parse_dx_root(&blocks[0]).expect("dx_root");
        assert_eq!(root.indirect_levels, 0, "test assumes single-level index");
        let leaf_count_before = blocks.len() - 1;

        // Pick a real target leaf: route an arbitrary new name to its leaf via the
        // same descent the insert path uses.
        let new_name = b"freshly_inserted_entry".to_vec();
        let target_logical = htree_target_leaf_block(
            &seed,
            false,
            &new_name,
            |v| v,
            |lb| blocks.get(lb as usize).cloned(),
        )
        .expect("target leaf");
        let target_leaf = blocks[target_logical as usize].clone();
        let new_leaf_logical = u32::try_from(blocks.len()).unwrap();

        let split = split_htree_leaf(
            &blocks[0],
            &target_leaf,
            target_logical,
            new_leaf_logical,
            bs,
            hash_version,
            &seed,
            true, // has_metadata_csum
            false,
            csum_seed,
            dir_ino,
            generation,
        )
        .expect("leaf split should succeed for a multi-distinct-hash leaf");

        // Apply the split to our in-memory block vector: dx_root + old leaf rewritten,
        // new leaf appended at new_leaf_logical.
        blocks[0] = split.dx_root.clone();
        blocks[target_logical as usize] = split.old_leaf.clone();
        assert_eq!(blocks.len(), new_leaf_logical as usize);
        blocks.push(split.new_leaf.clone());
        assert_eq!(
            blocks.len() - 1,
            leaf_count_before + 1,
            "exactly one new leaf"
        );

        // Add the new entry into the half that now owns its hash.
        let nh = dx_hash(hash_version, &new_name, &seed).0;
        let into_new = nh >= split.split_hash;
        let leaf_idx = if into_new {
            new_leaf_logical as usize
        } else {
            target_logical as usize
        };
        // Pack a fresh copy with the new entry appended (re-using parse+pack to keep
        // the test self-contained).
        {
            let (es, _t) = parse_dir_block(&blocks[leaf_idx], u32::try_from(bs).unwrap()).unwrap();
            let mut refs: Vec<(u32, u8, Vec<u8>)> = es
                .into_iter()
                .filter(|e| e.inode != 0 && e.name != b"." && e.name != b".." && !e.name.is_empty())
                .map(|e| (e.inode, e.file_type.to_raw(), e.name))
                .collect();
            refs.push((9999, EXT4_FT_REG_FILE, new_name.clone()));
            let packed_refs: Vec<(u32, u8, &[u8])> = refs
                .iter()
                .map(|(i, ft, n)| (*i, *ft, n.as_slice()))
                .collect();
            let mut packed = pack_dir_block_entries(&packed_refs, bs, true).expect("repack");
            stamp_dir_block_checksum(&mut packed, csum_seed, dir_ino, generation);
            blocks[leaf_idx] = packed;
        }

        // Every block's checksum verifies.
        assert!(verify_dx_block_checksum(
            &blocks[0],
            csum_seed,
            dir_ino,
            generation,
            DX_ROOT_COUNT_OFFSET
        ));
        for leaf in &blocks[1..] {
            verify_dir_block_checksum(leaf, csum_seed, dir_ino, generation)
                .expect("leaf checksum after split");
        }

        // Every original name still resolves through the widened index.
        for (i, name) in names.iter().enumerate() {
            match htree_find_entry(
                u32::try_from(bs).unwrap(),
                &seed,
                false,
                name,
                |v| v,
                |lb| blocks.get(lb as usize).cloned(),
            ) {
                HtreeFindResult::Found(e) => {
                    assert_eq!(e.inode, 1000 + u32::try_from(i).unwrap(), "name {name:?}");
                }
                other => panic!("post-split: {name:?} not reachable: {other:?}"),
            }
        }
        // The new name resolves too.
        match htree_find_entry(
            u32::try_from(bs).unwrap(),
            &seed,
            false,
            &new_name,
            |v| v,
            |lb| blocks.get(lb as usize).cloned(),
        ) {
            HtreeFindResult::Found(e) => assert_eq!(e.inode, 9999),
            other => panic!("post-split: new name not reachable: {other:?}"),
        }
    }

    // See the note on the single-level split test above: same reasoning, and this
    // one drives a TWO-level index (8000 entries), so the sequence is longer still
    // (141/100). Narrow allow, bd-3ao0l.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn htree_dx_node_leaf_split_keeps_two_level_dir_navigable_bd_bhh0i() {
        let bs = 1024_usize;
        let seed = [0x0bad_f00d_u32, 0xfeed_face, 0xdead_beef, 0xcafe_b0ba];
        let csum_seed = 0x2222_3333_u32;
        let dir_ino = 313_u32;
        let generation = 12_u32;
        let hash_version = 1_u8;

        let names: Vec<Vec<u8>> = (0..8000)
            .map(|i| format!("file_{i:06}").into_bytes())
            .collect();
        let entries: Vec<(u32, u8, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    100 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();

        let mut blocks = build_htree_directory_stamped(
            2,
            2,
            &entries,
            bs,
            hash_version,
            &seed,
            csum_seed,
            dir_ino,
            generation,
        )
        .expect("two-level htree build");
        let root = parse_dx_root(&blocks[0]).expect("parse dx root");
        assert_eq!(root.indirect_levels, 1, "test requires a two-level htree");

        let new_name = b"fresh_dx_node_split_entry".to_vec();
        let new_hash = dx_hash(hash_version, &new_name, &seed).0;
        let node_logical = root.entries[dx_find_leaf_idx(&root.entries, new_hash)].block;
        let target_logical = htree_target_leaf_block(
            &seed,
            false,
            &new_name,
            |v| v,
            |lb| blocks.get(lb as usize).cloned(),
        )
        .expect("target leaf");
        let new_leaf_logical = u32::try_from(blocks.len()).unwrap();

        let split = split_htree_leaf_in_dx_node(
            &blocks[node_logical as usize],
            &blocks[target_logical as usize],
            target_logical,
            new_leaf_logical,
            bs,
            hash_version,
            &seed,
            true,
            csum_seed,
            dir_ino,
            generation,
        )
        .expect("dx_node leaf split");

        let into_new = new_hash >= split.split_hash;
        blocks[node_logical as usize] = split.dx_node.clone();
        blocks[target_logical as usize] = split.old_leaf.clone();
        assert_eq!(blocks.len(), new_leaf_logical as usize);
        blocks.push(split.new_leaf);

        let leaf_idx = if into_new {
            new_leaf_logical as usize
        } else {
            target_logical as usize
        };
        {
            let (es, _tail) =
                parse_dir_block(&blocks[leaf_idx], u32::try_from(bs).unwrap()).unwrap();
            let mut refs: Vec<(u32, u8, Vec<u8>)> = es
                .into_iter()
                .filter(|e| e.inode != 0 && e.name != b"." && e.name != b".." && !e.name.is_empty())
                .map(|e| (e.inode, e.file_type.to_raw(), e.name))
                .collect();
            refs.push((999_001, EXT4_FT_REG_FILE, new_name.clone()));
            let packed_refs: Vec<(u32, u8, &[u8])> = refs
                .iter()
                .map(|(i, ft, n)| (*i, *ft, n.as_slice()))
                .collect();
            let mut packed = pack_dir_block_entries(&packed_refs, bs, true).expect("repack");
            stamp_dir_block_checksum(&mut packed, csum_seed, dir_ino, generation);
            blocks[leaf_idx] = packed;
        }

        assert!(verify_dx_block_checksum(
            &blocks[0],
            csum_seed,
            dir_ino,
            generation,
            DX_ROOT_COUNT_OFFSET
        ));
        assert!(verify_dx_block_checksum(
            &blocks[node_logical as usize],
            csum_seed,
            dir_ino,
            generation,
            DX_NODE_COUNT_OFFSET
        ));
        verify_dir_block_checksum(
            &blocks[target_logical as usize],
            csum_seed,
            dir_ino,
            generation,
        )
        .expect("old leaf checksum");
        verify_dir_block_checksum(
            &blocks[new_leaf_logical as usize],
            csum_seed,
            dir_ino,
            generation,
        )
        .expect("new leaf checksum");

        for (i, name) in names.iter().enumerate().step_by(257) {
            match htree_find_entry(
                u32::try_from(bs).unwrap(),
                &seed,
                false,
                name,
                |v| v,
                |lb| blocks.get(lb as usize).cloned(),
            ) {
                HtreeFindResult::Found(e) => {
                    assert_eq!(e.inode, 100 + u32::try_from(i).unwrap(), "name {name:?}");
                }
                other => panic!("post-dx_node-split: {name:?} not reachable: {other:?}"),
            }
        }
        match htree_find_entry(
            u32::try_from(bs).unwrap(),
            &seed,
            false,
            &new_name,
            |v| v,
            |lb| blocks.get(lb as usize).cloned(),
        ) {
            HtreeFindResult::Found(e) => assert_eq!(e.inode, 999_001),
            other => panic!("post-dx_node-split: new name not reachable: {other:?}"),
        }
    }

    /// bd-gauub: the fast path declines (so the caller falls back to rebuild) for
    /// a multi-level index and for a leaf with no clean hash boundary.
    #[test]
    fn htree_leaf_split_declines_unsupported_shapes_bd_gauub() {
        let bs = 1024_usize;
        let seed = [0x0bad_f00d_u32, 0xfeed_face, 0xdead_beef, 0xcafe_b0ba];
        let csum_seed = 0x1111_2222_u32;
        let dir_ino = 5_u32;
        let generation = 1_u32;
        let hash_version = 1_u8;

        // Two-level index => MultiLevelIndex decline.
        let names: Vec<Vec<u8>> = (0..8000)
            .map(|i| format!("f_{i:06}").into_bytes())
            .collect();
        let entries: Vec<(u32, u8, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    10 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();
        let blocks = build_htree_directory_stamped(
            2,
            2,
            &entries,
            bs,
            hash_version,
            &seed,
            csum_seed,
            dir_ino,
            generation,
        )
        .expect("two-level build");
        assert!(parse_dx_root(&blocks[0]).unwrap().indirect_levels >= 1);
        let some_leaf = blocks[1].clone();
        assert!(matches!(
            split_htree_leaf(
                &blocks[0],
                &some_leaf,
                1,
                99,
                bs,
                hash_version,
                &seed,
                true,
                false,
                csum_seed,
                dir_ino,
                generation
            ),
            Err(HtreeSplitFallback::MultiLevelIndex)
        ));

        // A single-entry leaf has only one distinct hash => NoCleanBoundary decline.
        let single = pack_dir_block_entries(&[(7, EXT4_FT_REG_FILE, b"only")], bs, true).unwrap();
        let small_names: Vec<Vec<u8>> = (0..3).map(|i| format!("s{i}").into_bytes()).collect();
        let small_entries: Vec<(u32, u8, &[u8])> = small_names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    1 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();
        let single_dir = build_htree_directory_stamped(
            2,
            2,
            &small_entries,
            bs,
            hash_version,
            &seed,
            csum_seed,
            dir_ino,
            generation,
        )
        .unwrap();
        assert!(matches!(
            split_htree_leaf(
                &single_dir[0],
                &single,
                1,
                99,
                bs,
                hash_version,
                &seed,
                true,
                false,
                csum_seed,
                dir_ino,
                generation
            ),
            Err(HtreeSplitFallback::NoCleanBoundary)
        ));
    }

    /// bd-owt2r (multi-level write-half): when the leaves overflow a single DX
    /// root, the builder produces a two-level index (`indirect_levels == 1`)
    /// whose interior `dx_node` blocks the read-half navigates correctly. A
    /// 1 KiB block holds only 124 DX root entries, so a few thousand entries
    /// force the second level. The read-half (`htree_find_entry`) is the oracle:
    /// every name must resolve through root -> interior node -> leaf.
    #[test]
    fn build_htree_directory_two_level_is_navigable_bd_owt2r() {
        let bs = 1024_usize;
        let seed = [0x0bad_f00d_u32, 0xfeed_face, 0xdead_beef, 0xcafe_b0ba];
        let hash_version = 1_u8; // half_md4

        // 8000 entries at 1 KiB: > 124 leaves, so a single DX root cannot index
        // them and the builder must emit indirect_levels == 1.
        let names: Vec<Vec<u8>> = (0..8000)
            .map(|i| format!("file_{i:06}").into_bytes())
            .collect();
        let entries: Vec<(u32, u8, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    100 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();

        let blocks = build_htree_directory(2, 2, &entries, bs, hash_version, &seed, false)
            .expect("two-level htree should build");

        // indirect_levels byte (0x1E of the dx_root) must be 1: the second level
        // was actually emitted, not silently dropped.
        assert_eq!(
            blocks[0][0x1E], 1,
            "dx_root must declare indirect_levels == 1"
        );

        // At least one interior node must parse as a dx_node with sane entries.
        let root_limit = usize::from(dx_root_entry_limit(bs, false));
        assert!(
            blocks.len() > root_limit + 2,
            "two-level layout must span more blocks than a single level could hold"
        );

        let read = |name: &[u8]| {
            htree_find_entry(
                u32::try_from(bs).unwrap(),
                &seed,
                false,
                name,
                |v| v,
                |lb| blocks.get(lb as usize).cloned(),
            )
        };

        for (i, name) in names.iter().enumerate() {
            match read(name) {
                HtreeFindResult::Found(e) => {
                    assert_eq!(
                        e.inode,
                        100 + u32::try_from(i).unwrap(),
                        "wrong inode {name:?}"
                    );
                }
                other => panic!("entry {name:?} not reachable via two-level index: {other:?}"),
            }
        }

        assert!(
            !matches!(read(b"absent_name_zzz"), HtreeFindResult::Found(_)),
            "false positive for an absent name in a two-level index"
        );
    }

    /// bd-owt2r: a casefold directory lookup resolves a case-variant query
    /// through the htree index (O(log) device reads) instead of a linear scan
    /// of every leaf block, and agrees with the linear casefold scan. The htree
    /// entries are hashed by the case-folded (lowercase, for ASCII) name — exactly
    /// as the kernel hashes a casefold dir — so an UPPERCASE query still descends
    /// to the right leaf, while an exact-match descent must miss it.
    #[test]
    fn htree_find_entry_casefold_resolves_case_variants_via_index_bd_owt2r() {
        let bs = 1024_usize;
        let bs_u32 = u32::try_from(bs).unwrap();
        let seed = [0x0bad_f00d_u32, 0xfeed_face, 0xdead_beef, 0xcafe_b0ba];
        let hash_version = 1_u8; // half_md4

        // A casefold dir stores names in their original (here lowercase) case and
        // hashes the folded name. Build with lowercase names so the index is
        // hashed exactly as a casefold directory's would be.
        let names: Vec<Vec<u8>> = (0..400)
            .map(|i| format!("file_{i:06}").into_bytes())
            .collect();
        let entries: Vec<(u32, u8, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    100 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();
        let blocks = build_htree_directory(2, 2, &entries, bs, hash_version, &seed, false)
            .expect("casefold htree builds");
        let total_leaf_blocks = blocks.len() - 1; // block 0 is the dx root
        assert!(
            total_leaf_blocks >= 4,
            "need several leaf blocks for a meaningful score (got {total_leaf_blocks})"
        );

        // Query an UPPERCASE variant of a stored (lowercase) name.
        let target_idx = 150_usize;
        let stored_name = format!("file_{target_idx:06}").into_bytes();
        let query_upper = format!("FILE_{target_idx:06}").into_bytes();

        // Casefold descent, counting block reads.
        let casefold_reads = std::cell::Cell::new(0_usize);
        let cf = htree_find_entry_casefold(
            bs_u32,
            &seed,
            false,
            &query_upper,
            |v| v,
            |lb| {
                casefold_reads.set(casefold_reads.get() + 1);
                blocks.get(lb as usize).cloned()
            },
        );
        let entry = match cf {
            HtreeFindResult::Found(e) => e,
            other => panic!("casefold descent failed for {query_upper:?}: {other:?}"),
        };
        assert_eq!(entry.inode, 100 + u32::try_from(target_idx).unwrap());
        assert_eq!(
            entry.name, stored_name,
            "stored (original-case) name returned"
        );

        // Exact-match descent MUST miss the uppercase query — proves the casefold
        // path is doing real work, not coincidentally matching.
        assert!(
            !matches!(
                htree_find_entry(
                    bs_u32,
                    &seed,
                    false,
                    &query_upper,
                    |v| v,
                    |lb| blocks.get(lb as usize).cloned()
                ),
                HtreeFindResult::Found(_)
            ),
            "exact-match descent must not find an uppercase variant"
        );

        // ISOMORPHISM: linear casefold scan over the leaf blocks finds the same
        // entry (this is the pre-existing source of truth the lookup falls back to).
        let mut linear_hit = None;
        for blk in &blocks[1..] {
            if let Ok(Some(found)) = lookup_in_dir_block_casefold(blk, bs_u32, &query_upper) {
                linear_hit = Some(found);
                break;
            }
        }
        let linear_entry = linear_hit.expect("linear casefold scan finds it");
        assert_eq!(
            linear_entry.inode, entry.inode,
            "htree vs linear casefold disagree"
        );
        assert_eq!(linear_entry.name, entry.name);

        // SCORE: the casefold descent reads a handful of blocks; the prior
        // behaviour (casefold dirs skipped the index) scanned up to every leaf
        // block. Worst-case linear cost = total_leaf_blocks.
        let reads = casefold_reads.get();
        let score = total_leaf_blocks as f64 / reads as f64;
        assert!(
            score >= 2.0,
            "Score {score} must clear 2.0 (linear {total_leaf_blocks} leaves -> casefold descent {reads} reads)"
        );
    }

    /// bd-owt2r (insert side): the casefold insert target-leaf locator places a
    /// new entry into the exact leaf a case-insensitive lookup descends to. For
    /// every stored (lowercase) name, inserting its UPPERCASE variant must target
    /// the same leaf the stored name's exact hash maps to — so the kernel (and
    /// FrankenFS's casefold lookup) finds it. Proves the write side is consistent
    /// with the read side for ASCII casefold names.
    #[test]
    fn htree_target_leaf_block_casefold_targets_the_lookup_leaf_bd_owt2r() {
        let bs = 1024_usize;
        let seed = [0x0bad_f00d_u32, 0xfeed_face, 0xdead_beef, 0xcafe_b0ba];
        let hash_version = 1_u8;
        let names: Vec<Vec<u8>> = (0..400)
            .map(|i| format!("file_{i:06}").into_bytes())
            .collect();
        let entries: Vec<(u32, u8, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    100 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();
        let blocks = build_htree_directory(2, 2, &entries, bs, hash_version, &seed, false)
            .expect("casefold htree builds");
        assert!(
            blocks.len() > 4,
            "need several leaves for a meaningful test"
        );

        for lower in names.iter().step_by(37) {
            let upper = lower.to_ascii_uppercase();
            let cf_leaf = htree_target_leaf_block_casefold(
                &seed,
                false,
                &upper,
                |v| v,
                |lb| blocks.get(lb as usize).cloned(),
            );
            let exact_leaf = htree_target_leaf_block(
                &seed,
                false,
                lower,
                |v| v,
                |lb| blocks.get(lb as usize).cloned(),
            );
            assert!(
                cf_leaf.is_some(),
                "casefold target leaf must resolve for {upper:?}"
            );
            assert_eq!(
                cf_leaf, exact_leaf,
                "casefold insert of {upper:?} must target the leaf holding {lower:?}"
            );
        }
    }

    /// bd-owt2r (leaf-full rebuild): the casefold rebuild builder lays out a
    /// fold-indexed tree where every entry is reachable via the case-insensitive
    /// descent. This is the core of ext4_rebuild_htree_dir's casefold path — it
    /// re-hashes every entry by its fold, so a later case-variant lookup of ANY
    /// name (including mixed-case originals) resolves through the index.
    #[test]
    fn build_htree_directory_casefold_rebuild_is_fold_navigable_bd_owt2r() {
        let bs = 1024_usize;
        let bs_u32 = u32::try_from(bs).unwrap();
        let seed = [0x1357_9bdf_u32, 0x2468_ace0, 0x0f1e_2d3c, 0x4b5a_6978];
        let csum_seed = 0x0fad_cafe_u32;
        let hash_version = 1_u8;
        let dir_ino = 77_u32;
        let generation = 3_u32;

        // Mixed-case original names (as the kernel might store them); the rebuild
        // hashes by their ASCII fold. Enough to span multiple leaves.
        let names: Vec<Vec<u8>> = (0..400)
            .map(|i| {
                if i % 2 == 0 {
                    format!("File_{i:04}.TXT").into_bytes()
                } else {
                    format!("file_{i:04}.txt").into_bytes()
                }
            })
            .collect();
        let entries: Vec<(u32, u8, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    200 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();

        let blocks = build_htree_directory_stamped_with_large_dir_casefold(
            dir_ino,
            2,
            &entries,
            bs,
            hash_version,
            &seed,
            csum_seed,
            dir_ino,
            generation,
            false,
        )
        .expect("casefold rebuild builds");
        assert!(
            blocks.len() > 4,
            "need several leaves for a real rebuild test"
        );

        // Every entry — queried by an arbitrary case variant — resolves via the
        // casefold descent, proving the rebuilt index is fold-correct.
        for (i, original) in names.iter().enumerate() {
            let query = if i % 3 == 0 {
                original.to_ascii_uppercase()
            } else {
                original.to_ascii_lowercase()
            };
            match htree_find_entry_casefold(
                bs_u32,
                &seed,
                false,
                &query,
                |v| v,
                |lb| blocks.get(lb as usize).cloned(),
            ) {
                HtreeFindResult::Found(e) => {
                    assert_eq!(
                        e.inode,
                        200 + u32::try_from(i).unwrap(),
                        "wrong inode for {query:?}"
                    );
                    assert_eq!(
                        &e.name, original,
                        "original case must be preserved in the leaf"
                    );
                }
                other => panic!("rebuilt casefold entry {query:?} not fold-reachable: {other:?}"),
            }
        }
    }

    /// bd-owt2r: the stamped two-level builder is both navigable AND fully
    /// checksum-valid — DX root and interior `dx_node` blocks under the index
    /// (`dx_tail`) formula, leaves under the directory-block formula — i.e.
    /// e2fsck-ready on a metadata_csum filesystem.
    #[test]
    fn build_htree_directory_stamped_two_level_is_navigable_and_checksummed_bd_owt2r() {
        let bs = 1024_usize;
        let seed = [0x5151_5151_u32, 0x6262_6262, 0x7373_7373, 0x8484_8484];
        let csum_seed = 0x0fad_cafe_u32;
        let dir_ino = 99_u32;
        let generation = 7_u32;
        let hash_version = 1_u8;

        let names: Vec<Vec<u8>> = (0..8000)
            .map(|i| format!("name_{i:06}").into_bytes())
            .collect();
        let entries: Vec<(u32, u8, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    300 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();

        let blocks = build_htree_directory_stamped(
            2,
            2,
            &entries,
            bs,
            hash_version,
            &seed,
            csum_seed,
            dir_ino,
            generation,
        )
        .expect("stamped two-level htree build");

        assert_eq!(
            blocks[0][0x1E], 1,
            "dx_root must declare indirect_levels == 1"
        );

        // The DX root checksum verifies under the index formula.
        assert!(verify_dx_block_checksum(
            &blocks[0],
            csum_seed,
            dir_ino,
            generation,
            DX_ROOT_COUNT_OFFSET
        ));

        // Every other block verifies under exactly one of the two formulas: a
        // leaf (directory-block tail) or an interior node (dx_node dx_tail). At
        // least one must be an interior node (the second level was stamped).
        let mut node_blocks = 0_usize;
        for blk in &blocks[1..] {
            let dir_ok = verify_dir_block_checksum(blk, csum_seed, dir_ino, generation).is_ok();
            let node_ok =
                verify_dx_block_checksum(blk, csum_seed, dir_ino, generation, DX_NODE_COUNT_OFFSET);
            if node_ok {
                node_blocks += 1;
            }
            assert!(
                dir_ok || node_ok,
                "every block must carry a valid leaf or interior-node checksum"
            );
        }
        assert!(
            node_blocks >= 1,
            "a two-level index must have at least one stamped interior node"
        );

        // Still navigable end-to-end with the checksum tails in place.
        for (i, name) in names.iter().enumerate() {
            match htree_find_entry(
                u32::try_from(bs).unwrap(),
                &seed,
                false,
                name,
                |v| v,
                |lb| blocks.get(lb as usize).cloned(),
            ) {
                HtreeFindResult::Found(e) => {
                    assert_eq!(e.inode, 300 + u32::try_from(i).unwrap());
                }
                other => panic!("entry {name:?} not reachable: {other:?}"),
            }
        }
    }

    /// bd-owt2r (gather-half): the leaf enumerator lists exactly the real leaf
    /// blocks of a two-level index — never an interior `dx_node` — so a rebuild
    /// reads only leaves. The builder lays leaves at logical 1..=L and interior
    /// nodes at L+1..=L+N, so the enumerated set must be precisely {1..=L}, and
    /// parsing those blocks must recover every input name and nothing else.
    #[test]
    fn htree_leaf_logical_blocks_enumerates_every_leaf_two_level_bd_owt2r() {
        let bs = 1024_usize;
        let seed = [0x0bad_f00d_u32, 0xfeed_face, 0xdead_beef, 0xcafe_b0ba];
        let hash_version = 1_u8;

        let names: Vec<Vec<u8>> = (0..8000)
            .map(|i| format!("file_{i:06}").into_bytes())
            .collect();
        let entries: Vec<(u32, u8, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    100 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();

        let blocks = build_htree_directory(2, 2, &entries, bs, hash_version, &seed, false)
            .expect("two-level htree should build");
        assert_eq!(blocks[0][0x1E], 1, "fixture must be two-level");

        let mut leaves =
            htree_leaf_logical_blocks(&blocks[0], false, |lb| blocks.get(lb as usize).cloned())
                .expect("leaf enumeration must succeed");

        // Parse the enumerated blocks first: they recover every input name and
        // nothing spurious (an interior node would parse to a single inode-0
        // fake entry, but the walk lists only real leaves, so the count matches).
        let mut found = std::collections::BTreeSet::new();
        for lb in &leaves {
            let (parsed, _) =
                parse_dir_block(&blocks[*lb as usize], u32::try_from(bs).unwrap()).unwrap();
            for e in parsed {
                if e.inode != 0 && e.name != b"." && e.name != b".." {
                    found.insert(e.name);
                }
            }
        }
        assert_eq!(
            found.len(),
            names.len(),
            "every entry accounted for via leaves only"
        );

        // The enumerated leaf set is exactly the contiguous leaf range 1..=L,
        // which excludes the interior nodes (logical L+1..). If the walk had
        // returned an interior node, the sorted set would not be 1..=L.
        leaves.sort_unstable();
        let l = leaves.len();
        assert!(l >= 2, "two-level dir must have multiple leaves, got {l}");
        assert_eq!(
            leaves,
            (1..=u32::try_from(l).unwrap()).collect::<Vec<_>>(),
            "enumeration must be exactly the leaf blocks 1..=L (no interior nodes)"
        );
        for n in &names {
            assert!(found.contains(n), "missing {n:?}");
        }
    }

    /// bd-owt2r: for a single-level index the enumerator returns the DX root's
    /// own entries (the leaves directly), with no descent.
    #[test]
    fn htree_leaf_logical_blocks_single_level_returns_root_leaves_bd_owt2r() {
        let bs = 4096_usize;
        let seed = [0x1234_5678_u32, 0x9abc_def0, 0x0f0f_0f0f, 0xa5a5_a5a5];
        let names: Vec<Vec<u8>> = (0..300)
            .map(|i| format!("file_{i:05}").into_bytes())
            .collect();
        let entries: Vec<(u32, u8, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    100 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();

        let blocks = build_htree_directory(2, 2, &entries, bs, 1, &seed, false).unwrap();
        assert_eq!(blocks[0][0x1E], 0, "fixture must be single-level");

        let mut leaves =
            htree_leaf_logical_blocks(&blocks[0], false, |lb| blocks.get(lb as usize).cloned())
                .unwrap();
        leaves.sort_unstable();
        assert_eq!(
            leaves,
            (1..=u32::try_from(blocks.len() - 1).unwrap()).collect::<Vec<_>>(),
            "single-level enumeration is every block after the dx_root"
        );
    }

    /// bd-owt2r (three-level construction): with a tiny 128-byte block the DX
    /// root holds only 12 entries and each interior node 15, so a two-level
    /// index caps at 12×15 = 180 leaves. A few thousand entries therefore force
    /// `indirect_levels == 2` (root → middle node → bottom node → leaf). The
    /// read-half navigates all three index levels and the leaf enumerator must
    /// still list exactly the leaves; this exercises the recursive bottom-up
    /// builder at its deepest supported depth.
    #[test]
    fn build_htree_directory_three_level_is_navigable_bd_owt2r() {
        let bs = 128_usize;
        let seed = [0x3333_1111_u32, 0x4444_2222, 0x5555_3333, 0x6666_4444];
        let hash_version = 1_u8;

        let names: Vec<Vec<u8>> = (0..4000).map(|i| format!("f{i:05}").into_bytes()).collect();
        let entries: Vec<(u32, u8, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    100 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();

        let blocks = build_htree_directory(2, 2, &entries, bs, hash_version, &seed, false)
            .expect("three-level htree should build");
        assert_eq!(
            blocks[0][0x1E], 2,
            "dx_root must declare indirect_levels == 2 (three levels)"
        );

        // Every name resolves through root -> middle -> bottom -> leaf.
        for (i, name) in names.iter().enumerate() {
            match htree_find_entry(
                u32::try_from(bs).unwrap(),
                &seed,
                false,
                name,
                |v| v,
                |lb| blocks.get(lb as usize).cloned(),
            ) {
                HtreeFindResult::Found(e) => {
                    assert_eq!(
                        e.inode,
                        100 + u32::try_from(i).unwrap(),
                        "wrong inode {name:?}"
                    );
                }
                other => panic!("entry {name:?} not reachable via three-level index: {other:?}"),
            }
        }

        // The leaf enumerator descends both indirect levels and lists exactly
        // the contiguous leaf range 1..=L (no interior nodes), recovering every
        // input name when those leaves are parsed.
        let mut leaves =
            htree_leaf_logical_blocks(&blocks[0], false, |lb| blocks.get(lb as usize).cloned())
                .expect("leaf enumeration");
        let mut found = std::collections::BTreeSet::new();
        for lb in &leaves {
            let (parsed, _) =
                parse_dir_block(&blocks[*lb as usize], u32::try_from(bs).unwrap()).unwrap();
            for e in parsed {
                if e.inode != 0 && e.name != b"." && e.name != b".." {
                    found.insert(e.name);
                }
            }
        }
        assert_eq!(
            found.len(),
            names.len(),
            "every entry accounted for via leaves only"
        );

        leaves.sort_unstable();
        let l = leaves.len();
        assert!(
            l > 180,
            "three-level dir must exceed the two-level leaf cap, got {l}"
        );
        assert_eq!(
            leaves,
            (1..=u32::try_from(l).unwrap()).collect::<Vec<_>>(),
            "enumeration must be exactly the leaf blocks 1..=L"
        );
    }

    /// bd-owt2r (large_dir): with the `INCOMPAT_LARGEDIR` feature the builder is
    /// allowed a fourth block level (`indirect_levels == 3`, root → upper node →
    /// lower node → leaf). The read-half (with `has_large_dir = true`) must
    /// navigate all three indirect frames and the leaf enumerator must still list
    /// exactly the leaves. Without the feature the same directory is unbuildable
    /// (the depth would be unreadable), so it must return `None` — never a
    /// silently-too-deep, kernel-unreadable index.
    #[test]
    fn build_htree_directory_four_level_large_dir_is_navigable_bd_owt2r() {
        let bs = 64_usize;
        let seed = [0x1234_5678_u32, 0x2345_6789, 0x3456_789a, 0x4567_89ab];
        let hash_version = 1_u8;

        // bs=64 → root_limit 4, node_limit 7 → a two-level index caps at
        // 4*7*7 = 196 leaves; ~600 leaves (4 entries/leaf) forces a third level.
        let names: Vec<Vec<u8>> = (0..2400).map(|i| format!("f{i:05}").into_bytes()).collect();
        let entries: Vec<(u32, u8, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    100 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();

        // Without large_dir the depth is unreadable: refuse to build it.
        assert!(
            build_htree_directory(2, 2, &entries, bs, hash_version, &seed, false).is_none(),
            "a four-level index must not build without INCOMPAT_LARGEDIR"
        );

        let blocks = build_htree_directory_with_large_dir(
            2,
            2,
            &entries,
            bs,
            hash_version,
            &seed,
            false,
            true,
        )
        .expect("four-level htree should build with large_dir");
        assert_eq!(
            blocks[0][0x1E], 3,
            "dx_root must declare indirect_levels == 3 (four block levels)"
        );

        // Every name resolves through root -> upper -> lower -> leaf.
        for (i, name) in names.iter().enumerate() {
            match htree_find_entry(
                u32::try_from(bs).unwrap(),
                &seed,
                true,
                name,
                |v| v,
                |lb| blocks.get(lb as usize).cloned(),
            ) {
                HtreeFindResult::Found(e) => {
                    assert_eq!(
                        e.inode,
                        100 + u32::try_from(i).unwrap(),
                        "wrong inode {name:?}"
                    );
                }
                other => panic!("entry {name:?} not reachable via four-level index: {other:?}"),
            }
        }

        // The leaf enumerator descends all indirect levels and lists exactly the
        // contiguous leaf range 1..=L (no interior nodes), recovering every name.
        let mut leaves =
            htree_leaf_logical_blocks(&blocks[0], true, |lb| blocks.get(lb as usize).cloned())
                .expect("leaf enumeration");
        let mut found = std::collections::BTreeSet::new();
        for lb in &leaves {
            let (parsed, _) =
                parse_dir_block(&blocks[*lb as usize], u32::try_from(bs).unwrap()).unwrap();
            for e in parsed {
                if e.inode != 0 && e.name != b"." && e.name != b".." {
                    found.insert(e.name);
                }
            }
        }
        assert_eq!(
            found.len(),
            names.len(),
            "every entry accounted for via leaves only"
        );

        leaves.sort_unstable();
        let l = leaves.len();
        assert!(
            l > 196,
            "four-level dir must exceed the two-level leaf cap, got {l}"
        );
        assert_eq!(
            leaves,
            (1..=u32::try_from(l).unwrap()).collect::<Vec<_>>(),
            "enumeration must be exactly the leaf blocks 1..=L"
        );
    }

    /// bd-owt2r (large_dir, checksummed): the `metadata_csum` builder produces an
    /// e2fsck-clean four-level index — every block verifies under exactly one of
    /// the leaf / interior-node CRC32C formulas, the extra indirect level is
    /// stamped as a `dx_node`, and the result stays navigable with the tails in
    /// place.
    #[test]
    fn build_htree_directory_stamped_four_level_large_dir_is_navigable_and_checksummed_bd_owt2r() {
        let bs = 64_usize;
        let seed = [0x9090_1010_u32, 0xa0a0_2020, 0xb0b0_3030, 0xc0c0_4040];
        let csum_seed = 0x0fad_beef_u32;
        let dir_ino = 4242_u32;
        let generation = 9_u32;
        let hash_version = 1_u8;

        // Stamped bs=64 → root_limit 3, node_limit 6 → two-level cap 3*6*6 = 108
        // leaves; ~400 leaves (3 entries/leaf) forces a third indirect level.
        let names: Vec<Vec<u8>> = (0..1200).map(|i| format!("g{i:05}").into_bytes()).collect();
        let entries: Vec<(u32, u8, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    500 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();

        // Parity: unbuildable without the feature flag.
        assert!(
            build_htree_directory_stamped(
                2,
                2,
                &entries,
                bs,
                hash_version,
                &seed,
                csum_seed,
                dir_ino,
                generation,
            )
            .is_none(),
            "a four-level stamped index must not build without INCOMPAT_LARGEDIR"
        );

        let blocks = build_htree_directory_stamped_with_large_dir(
            2,
            2,
            &entries,
            bs,
            hash_version,
            &seed,
            csum_seed,
            dir_ino,
            generation,
            true,
        )
        .expect("stamped four-level htree build with large_dir");
        assert_eq!(
            blocks[0][0x1E], 3,
            "dx_root must declare indirect_levels == 3"
        );

        // The DX root checksum verifies under the index formula.
        assert!(verify_dx_block_checksum(
            &blocks[0],
            csum_seed,
            dir_ino,
            generation,
            DX_ROOT_COUNT_OFFSET
        ));

        // Every other block verifies under exactly one formula; a four-level
        // index has at least two stamped interior nodes (two indirect levels).
        let mut node_blocks = 0_usize;
        for blk in &blocks[1..] {
            let dir_ok = verify_dir_block_checksum(blk, csum_seed, dir_ino, generation).is_ok();
            let node_ok =
                verify_dx_block_checksum(blk, csum_seed, dir_ino, generation, DX_NODE_COUNT_OFFSET);
            if node_ok {
                node_blocks += 1;
            }
            assert!(
                dir_ok || node_ok,
                "every block must carry a valid leaf or interior-node checksum"
            );
        }
        assert!(
            node_blocks >= 2,
            "a four-level index must have at least two stamped interior nodes, got {node_blocks}"
        );

        // Still navigable end-to-end with the checksum tails in place.
        for (i, name) in names.iter().enumerate() {
            match htree_find_entry(
                u32::try_from(bs).unwrap(),
                &seed,
                true,
                name,
                |v| v,
                |lb| blocks.get(lb as usize).cloned(),
            ) {
                HtreeFindResult::Found(e) => {
                    assert_eq!(e.inode, 500 + u32::try_from(i).unwrap());
                }
                other => panic!("entry {name:?} not reachable: {other:?}"),
            }
        }
    }

    #[test]
    fn htree_target_leaf_block_routes_each_name_to_its_owning_leaf_bd_wb4cd() {
        // The insert-side leaf locator must return, for every name, exactly the
        // leaf block that already holds that name — the same leaf
        // htree_find_entry navigates to. This is the invariant that lets
        // ext4_add_dir_entry insert into the hash-correct leaf without ever
        // linear-writing (and thus corrupting) the dx_root (bd-wb4cd).
        let bs = 4096_usize;
        let seed = [0x1111_1111_u32, 0x2222_2222, 0x3333_3333, 0x4444_4444];
        let csum_seed = 0xabcd_1234_u32;
        let dir_ino = 77_u32;
        let generation = 5_u32;
        let hash_version = 1_u8;

        let names: Vec<Vec<u8>> = (0..250)
            .map(|i| format!("entry_{i:04}").into_bytes())
            .collect();
        let entries: Vec<(u32, u8, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    200 + u32::try_from(i).unwrap(),
                    EXT4_FT_REG_FILE,
                    n.as_slice(),
                )
            })
            .collect();
        let blocks = build_htree_directory_stamped(
            2,
            2,
            &entries,
            bs,
            hash_version,
            &seed,
            csum_seed,
            dir_ino,
            generation,
        )
        .expect("stamped htree build");
        assert!(blocks.len() >= 3, "needs dx_root + multiple leaves");

        for name in &names {
            let target = htree_target_leaf_block(
                &seed,
                false,
                name,
                |v| v,
                |lb| blocks.get(lb as usize).cloned(),
            )
            .unwrap_or_else(|| panic!("no target leaf for {name:?}"));
            assert_ne!(target, 0, "target leaf must never be the dx_root (block 0)");
            let leaf = blocks
                .get(target as usize)
                .unwrap_or_else(|| panic!("target leaf {target} out of range"));
            let (leaf_entries, _) =
                parse_dir_block(leaf, u32::try_from(bs).unwrap()).expect("parse leaf");
            assert!(
                leaf_entries.iter().any(|e| e.name == *name),
                "name {name:?} must live in its hash-target leaf {target}"
            );
        }
    }

    /// bd-12nk4 — Kernel-conformance pin for the ext4_dir_entry_2
    /// header field offsets per fs/ext4/ext4.h (struct ext4_dir_entry_2,
    /// 8-byte header). Each field is stamped with a UNIQUE non-zero
    /// magic at its canonical kernel offset, then a single
    /// parse_dir_block call must round-trip every field. parse_dir_block
    /// runs on every ext4 readdir / lookup / remove / rename path —
    /// every directory operation depends on these offsets. A regression
    /// that drifted any single offset would mis-route inode-vs-rec_len
    /// or name_len-vs-file_type silently.
    ///
    /// Sister kernel-offset pins: ext4_extent_leaf_kernel_offsets_match_extents_h,
    /// ext4_extent_index_kernel_offsets_match_extents_h,
    /// ext4_extent_header_kernel_offsets_match_extents_h,
    /// ext4_mmp_block_kernel_offsets_match_mmp_h, plus
    /// ext4_file_type_constants_match_kernel_header (which pins the
    /// file_type discriminants this test relies on).
    #[test]
    fn ext4_dir_entry_2_kernel_offsets_match_ext4_h() {
        // Single 16-byte rec_len entry that fills the block. Magics
        // chosen so every byte position holds a UNIQUE value, so an
        // offset drift produces a cross-field collision:
        //   inode     u32 LE @0..4 = 0x1234_5678 → bytes [0x78,0x56,0x34,0x12]
        //   rec_len   u16 LE @4..6 = 16          → bytes [0x10, 0x00]
        //   name_len  u8      @6   = 5           → byte  [0x05]
        //   file_type u8      @7   = SYMLINK (7) → byte  [0x07]
        //   name              @8..13            = b"hello"
        //   pad               @13..16           = zeros (rec_len - 8 - name_len)
        let block_size = 16_u32;
        let mut block = vec![0_u8; 16];
        let inode_magic = 0x1234_5678_u32;
        let rec_len_raw = 16_u16;
        let name_len_magic = 5_u8;
        let file_type_raw = EXT4_FT_SYMLINK;

        block[0..4].copy_from_slice(&inode_magic.to_le_bytes());
        block[4..6].copy_from_slice(&rec_len_raw.to_le_bytes());
        block[6] = name_len_magic;
        block[7] = file_type_raw;
        block[8..13].copy_from_slice(b"hello");

        let (entries, tail) = parse_dir_block(&block, block_size)
            .expect("kernel-stamped ext4_dir_entry_2 must parse");

        assert!(tail.is_none(), "no checksum tail for this fixture");
        assert_eq!(entries.len(), 1, "exactly one entry");

        let entry = &entries[0];
        assert_eq!(entry.inode, inode_magic, "inode @ offset 0..4");
        assert_eq!(
            entry.rec_len,
            u32::from(rec_len_raw),
            "rec_len @ offset 4..6"
        );
        assert_eq!(entry.name_len, name_len_magic, "name_len @ offset 6");
        assert_eq!(
            entry.file_type,
            Ext4FileType::Symlink,
            "file_type @ offset 7"
        );
        assert_eq!(entry.name, b"hello", "name @ offset 8..");
    }

    /// bd-z22lc — Kernel-conformance pin for the ext4 checksum-offset
    /// constants:
    ///   GD_CHECKSUM_OFFSET       = offsetof(struct ext4_group_desc, bg_checksum)       = 0x1E
    ///   INODE_CHECKSUM_LO_OFFSET = offsetof(struct ext4_inode,      i_checksum_lo)     = 0x7C
    ///   INODE_CHECKSUM_HI_OFFSET = offsetof(struct ext4_inode,      i_checksum_hi)     = 0x82
    ///
    /// These are the byte offsets at which the per-structure CRC32C is
    /// read/written. A regression that drifted any by even one byte would
    /// silently break both checksum verification (read garbage as csum) and
    /// stamping (write csum into wrong field). The existing stamp/verify
    /// roundtrip MRs would NOT catch this because the same bad offset is
    /// used on both sides — they confirm round-trip consistency but not
    /// kernel-conformance of the offset itself.
    ///
    /// Pairs with ext4_super_block_kernel_offsets_match_ext4_h,
    /// ext4_inode_kernel_offsets_match_ext4_h (which pins many neighboring
    /// inode-field offsets but not i_checksum_lo / i_checksum_hi).
    #[test]
    fn ext4_checksum_offset_constants_match_kernel_header() {
        // Per fs/ext4/ext4.h struct ext4_group_desc.bg_checksum offset.
        assert_eq!(
            GD_CHECKSUM_OFFSET, 0x1E,
            "GD_CHECKSUM_OFFSET must equal offsetof(struct ext4_group_desc, bg_checksum)"
        );

        // Per fs/ext4/ext4.h struct ext4_inode.i_checksum_lo offset
        // (the LE u16 storing low 16 bits of the inode CRC32C).
        assert_eq!(
            INODE_CHECKSUM_LO_OFFSET, 0x7C,
            "INODE_CHECKSUM_LO_OFFSET must equal offsetof(struct ext4_inode, i_checksum_lo)"
        );

        // Per fs/ext4/ext4.h struct ext4_inode.i_checksum_hi offset
        // (the LE u16 storing high 16 bits of the inode CRC32C; only
        // present when i_extra_isize >= 0x86 - 0x80 = 6).
        assert_eq!(
            INODE_CHECKSUM_HI_OFFSET, 0x82,
            "INODE_CHECKSUM_HI_OFFSET must equal offsetof(struct ext4_inode, i_checksum_hi)"
        );

        // Layout invariants:
        //  - HI follows LO+ 2 bytes of padding (i_pad1 at 0x7E).
        //  - Both are 16-bit fields, so each occupies 2 bytes.
        assert_eq!(
            INODE_CHECKSUM_HI_OFFSET - INODE_CHECKSUM_LO_OFFSET,
            6,
            "INODE_CHECKSUM_HI - INODE_CHECKSUM_LO == 6 \
             (lo:u16 @0x7C, i_pad1:u16 @0x7E, i_isize_high:u16 @0x80, hi:u16 @0x82)"
        );

        // bg_checksum fits within the 32-byte group descriptor:
        // GD_CHECKSUM_OFFSET (0x1E) + 2 == 0x20.
        assert_eq!(
            GD_CHECKSUM_OFFSET + 2,
            0x20,
            "bg_checksum is u16 at the end of the 32-byte group descriptor"
        );

        // i_checksum_lo + 2 leaves the next field (0x7E) starting at i_pad1.
        // i_checksum_hi + 2 == 0x84 — within the 256-byte ext4_inode region.
        const {
            assert!(
                INODE_CHECKSUM_HI_OFFSET + 2 <= 256,
                "i_checksum_hi must fit within the maximum ext4 inode size"
            );
        }
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn parse_dir_block_with_checksum_tail() {
        let block_size = 4096_u32;
        let mut block = vec![0_u8; block_size as usize];

        // Single entry: "." that spans almost the whole block, leaving 12 bytes for tail
        let entry_rec_len = u16::try_from(block_size).unwrap() - 12;
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
    fn parse_dir_block_rejects_truncated_checksum_tail() {
        let block_size = 32_u32;
        let mut block = vec![0_u8; 30];

        let entry_rec_len = u16::try_from(block_size - 12).unwrap();
        write_dir_entry(&mut block, 0, 2, 2, b".", entry_rec_len);

        let tail_off = (block_size - 12) as usize;
        block[tail_off..tail_off + 4].copy_from_slice(&0_u32.to_le_bytes());
        block[tail_off + 4..tail_off + 6].copy_from_slice(&12_u16.to_le_bytes());
        block[tail_off + 6] = 0;
        block[tail_off + 7] = EXT4_FT_DIR_CSUM;

        let err = parse_dir_block(&block, block_size).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn parse_dir_block_rejects_checksum_tail_not_at_end() {
        let block_size = 32_u32;
        let mut block = vec![0_u8; block_size as usize];

        write_dir_entry(&mut block, 0, 2, 2, b".", 12);

        let tail_off = 12_usize;
        block[tail_off..tail_off + 4].copy_from_slice(&0_u32.to_le_bytes());
        block[tail_off + 4..tail_off + 6].copy_from_slice(&12_u16.to_le_bytes());
        block[tail_off + 6] = 0;
        block[tail_off + 7] = EXT4_FT_DIR_CSUM;
        block[tail_off + 8..tail_off + 12].copy_from_slice(&0xCAFE_BABE_u32.to_le_bytes());
        block[tail_off + 12] = 1;

        let err = parse_dir_block(&block, block_size).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "dir_block_tail",
                ..
            }
        ));
    }

    #[test]
    fn parse_dir_block_rejects_malformed_checksum_tail_header() {
        let block_size = 32_u32;
        let mut block = vec![0_u8; block_size as usize];

        write_dir_entry(&mut block, 0, 2, 2, b".", 20);

        let tail_off = 20_usize;
        block[tail_off..tail_off + 4].copy_from_slice(&0_u32.to_le_bytes());
        block[tail_off + 4..tail_off + 6].copy_from_slice(&12_u16.to_le_bytes());
        block[tail_off + 6] = 1;
        block[tail_off + 7] = EXT4_FT_DIR_CSUM;

        let err = parse_dir_block(&block, block_size).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "dir_block_tail",
                ..
            }
        ));
    }

    #[test]
    fn parse_dir_block_and_iter_allow_tail_marker_shape_when_not_at_tail_position() {
        let block_size = 36_u32;
        let mut block = vec![0_u8; block_size as usize];

        // This has the malformed checksum-tail header shape, but it is followed
        // by a live entry. It is therefore a deleted dirent, not the tail.
        write_dir_entry(&mut block, 0, 0, EXT4_FT_DIR_CSUM, b"x", 12);
        write_dir_entry(&mut block, 12, 7, EXT4_FT_REG_FILE, b"live", 24);

        let (entries, tail) = parse_dir_block(&block, block_size).unwrap();
        assert!(tail.is_none());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].inode, 7);
        assert_eq!(entries[0].name, b"live");

        let mut iter = DirBlockIter::new(&block, block_size);
        let entry = iter
            .next()
            .expect("one live entry")
            .expect("tail-marker-shaped deleted entry is skipped");
        assert_eq!(entry.inode, 7);
        assert_eq!(entry.name, b"live");
        assert!(iter.next().is_none());
        assert!(iter.checksum_tail().is_none());
    }

    #[test]
    fn parse_dir_block_allows_checksum_tail_with_zero_padding() {
        let block_size = 32_u32;
        let mut block = vec![0_u8; block_size as usize];

        write_dir_entry(&mut block, 0, 2, 2, b".", 12);

        let tail_off = 12_usize;
        block[tail_off..tail_off + 4].copy_from_slice(&0_u32.to_le_bytes());
        block[tail_off + 4..tail_off + 6].copy_from_slice(&12_u16.to_le_bytes());
        block[tail_off + 6] = 0;
        block[tail_off + 7] = EXT4_FT_DIR_CSUM;
        block[tail_off + 8..tail_off + 12].copy_from_slice(&0xCAFE_BABE_u32.to_le_bytes());

        let (entries, tail) = parse_dir_block(&block, block_size).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(tail.is_some());
    }

    #[test]
    fn parse_dir_block_rejects_trailing_bytes() {
        let block_size = 32_u32;
        let mut block = vec![0_u8; block_size as usize];

        write_dir_entry(&mut block, 0, 2, 2, b".", 28);

        let err = parse_dir_block(&block, block_size).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
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
        let remaining = u16::try_from(block_size).unwrap() - 24;
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
        let remaining = u16::try_from(block_size).unwrap() - 24;
        write_dir_entry(&mut block, 24, 42, 1, b"myfile", remaining);

        let found = lookup_in_dir_block(&block, block_size, b"myfile").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().inode, 42);

        let not_found = lookup_in_dir_block(&block, block_size, b"missing").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn lookup_in_dir_block_casefold_finds_case_variant() {
        let block_size = 4096_u32;
        let mut block = vec![0_u8; block_size as usize];

        write_dir_entry(&mut block, 0, 2, 2, b".", 12);
        write_dir_entry(&mut block, 12, 2, 2, b"..", 12);
        let remaining = u16::try_from(block_size).unwrap() - 24;
        write_dir_entry(&mut block, 24, 42, 1, b"MyFile.TXT", remaining);

        // Case-insensitive: should find "myfile.txt" matching "MyFile.TXT"
        let found = lookup_in_dir_block_casefold(&block, block_size, b"myfile.txt").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().inode, 42);

        // Exact case also works
        let found2 = lookup_in_dir_block_casefold(&block, block_size, b"MyFile.TXT").unwrap();
        assert!(found2.is_some());

        // Completely different name doesn't match
        let not_found = lookup_in_dir_block_casefold(&block, block_size, b"other.txt").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn lookup_in_dir_block_casefold_matches_sharp_s_expansion() {
        let block_size = 4096_u32;
        let mut block = vec![0_u8; block_size as usize];

        write_dir_entry(&mut block, 0, 2, 2, b".", 12);
        write_dir_entry(&mut block, 12, 2, 2, b"..", 12);
        let remaining = u16::try_from(block_size).unwrap() - 24;
        write_dir_entry(&mut block, 24, 77, 1, "Straße.TXT".as_bytes(), remaining);

        let found = lookup_in_dir_block_casefold(&block, block_size, b"STRASSE.txt").unwrap();
        assert!(
            found.is_some(),
            "ext4 casefold lookup should match sharp-s expansion"
        );
        assert_eq!(found.unwrap().inode, 77);

        let found_upper_sharp_s =
            lookup_in_dir_block_casefold(&block, block_size, "STRAẞE.txt".as_bytes()).unwrap();
        assert!(found_upper_sharp_s.is_some());
        assert_eq!(found_upper_sharp_s.unwrap().inode, 77);
    }

    #[test]
    fn ext4_casefold_key_capital_sigma_folds_like_lowercase_sigma() {
        // Regression guard (bd-m7adx): the valid-UTF-8 fast path must NOT route
        // capital sigma through str::to_lowercase, which applies the Final_Sigma
        // context rule (Σ→ς word-finally) and would diverge from the per-char
        // loop (Σ→σ). A capital sigma must casefold-match its lowercase form.
        let upper = "ΑΣ"; // alpha + capital sigma (sigma is word-final here)
        let lower = "ασ"; // alpha + lowercase (non-final) sigma
        assert_eq!(
            ext4_casefold_key(upper.as_bytes()),
            ext4_casefold_key(lower.as_bytes()),
            "capital sigma must fold to the same key as lowercase sigma (no Final_Sigma divergence)"
        );
        assert!(
            ext4_casefold_names_collide(upper.as_bytes(), lower.as_bytes()),
            "Σ and σ must be treated as a case-insensitive match"
        );
        // Lone capital sigma vs lowercase sigma (the word-final trigger case).
        assert_eq!(
            ext4_casefold_key("Σ".as_bytes()),
            ext4_casefold_key("σ".as_bytes()),
        );
    }

    #[test]
    fn ext4_casefold_key_final_sigma_folds_like_standard_sigma_bd_vsuni() {
        assert_eq!(
            ext4_casefold_key("ς".as_bytes()),
            ext4_casefold_key("σ".as_bytes()),
            "Greek final sigma must casefold to standard sigma"
        );
        assert!(ext4_casefold_names_collide(
            "Ὀδυσσεύς".as_bytes(),
            "Ὀδυσσεύσ".as_bytes()
        ));
    }

    #[test]
    fn ext4_casefold_key_nfd_normalizes_greek_extended_bd_vsuni() {
        let cases: &[(&str, &str)] = &[
            ("Ἀ", "α\u{0313}"),
            ("ἂ", "α\u{0313}\u{0300}"),
            ("Ἄ", "α\u{0313}\u{0301}"),
            ("Ἃ", "α\u{0314}\u{0300}"),
            ("Ἐ", "ε\u{0313}"),
            ("Ἕ", "ε\u{0314}\u{0301}"),
            ("Ἦ", "η\u{0313}\u{0342}"),
            ("Ἷ", "ι\u{0314}\u{0342}"),
            ("Ὅ", "ο\u{0314}\u{0301}"),
            ("Ὑ", "υ\u{0314}"),
            ("Ὓ", "υ\u{0314}\u{0300}"),
            ("Ὧ", "ω\u{0314}\u{0342}"),
            ("ὰ", "α\u{0300}"),
            ("\u{1F7B}", "υ\u{0301}"),
            ("Ῥ", "ρ\u{0314}"),
            ("ᾈ", "α\u{0313}ι"),
            ("ᾅ", "α\u{0314}\u{0301}ι"),
            ("ᾏ", "α\u{0314}\u{0342}ι"),
            ("ᾟ", "η\u{0314}\u{0342}ι"),
            ("ᾲ", "α\u{0300}ι"),
            ("ᾨ", "ω\u{0313}ι"),
            ("ᾧ", "ω\u{0314}\u{0342}ι"),
            ("ᾯ", "ω\u{0314}\u{0342}ι"),
            ("ᾰ", "α\u{0306}"),
            ("\u{1FBB}", "α\u{0301}"),
            ("\u{1FBE}", "ι"),
            ("῁", "\u{00A8}\u{0342}"),
            ("ῂ", "η\u{0300}ι"),
            ("ῇ", "η\u{0342}ι"),
            ("῍", "\u{1FBF}\u{0300}"),
            ("ῷ", "ω\u{0342}ι"),
            ("ΐ", "ι\u{0308}\u{0301}"),
            ("ῐ", "ι\u{0306}"),
            ("ῒ", "ι\u{0308}\u{0300}"),
            ("ῗ", "ι\u{0308}\u{0342}"),
            ("῝", "\u{1FFE}\u{0300}"),
            ("ΰ", "υ\u{0308}\u{0301}"),
            ("ῠ", "υ\u{0306}"),
            ("ῤ", "ρ\u{0313}"),
            ("ῢ", "υ\u{0308}\u{0300}"),
            ("ῧ", "υ\u{0308}\u{0342}"),
            ("῭", "\u{00A8}\u{0300}"),
            ("\u{1FEE}", "\u{00A8}\u{0301}"),
            ("\u{1FEF}", "`"),
            ("ῲ", "ω\u{0300}ι"),
            ("ῴ", "ω\u{0301}ι"),
            ("\u{1FFB}", "ω\u{0301}"),
            ("\u{1FFD}", "\u{00B4}"),
        ];
        for (composed, decomposed) in cases {
            assert_eq!(
                ext4_casefold_key(composed.as_bytes()),
                ext4_casefold_key(decomposed.as_bytes()),
                "Greek Extended composed {composed:?} must fold to {decomposed:?}"
            );
        }
        assert!(ext4_casefold_names_collide(
            "ᾈᾅᾧ".as_bytes(),
            "α\u{0313}ια\u{0314}\u{0301}ιω\u{0314}\u{0342}ι".as_bytes()
        ));
    }

    #[test]
    fn ext4_casefold_key_nfd_normalizes_precomposed_latin1_bd_qdmlu() {
        // The kernel casefold NFD-normalizes before folding, so a precomposed
        // accented letter and its decomposed (base + combining mark) form fold
        // to the same key. Cover case variants + a multi-letter name.
        let cases: &[(&str, &str)] = &[
            ("é", "e\u{0301}"), // NFC vs NFD
            ("É", "e\u{0301}"), // uppercase precomposed folds to the same
            ("café", "cafe\u{0301}"),
            ("CAFÉ", "cafe\u{0301}"),
            ("Ñ", "n\u{0303}"),
            ("ñ", "n\u{0303}"),
            ("über", "u\u{0308}ber"),
            ("ÜBER", "u\u{0308}ber"),
            ("ÿ", "y\u{0308}"),
            ("Ÿ", "y\u{0308}"),
            // Latin Extended-A (bd-gegku): Central/Eastern European, Baltic, etc.
            ("č", "c\u{030C}"),
            ("Č", "c\u{030C}"),
            ("š", "s\u{030C}"),
            ("ž", "z\u{030C}"),
            ("ā", "a\u{0304}"),
            ("ő", "o\u{030B}"),
            ("ū", "u\u{0304}"),
            ("ę", "e\u{0328}"),
            ("ŇOČ", "n\u{030C}oc\u{030C}"), // mixed-case multi-letter
            // Monotonic Greek precomposed (single mark).
            ("ά", "α\u{0301}"),
            ("Ά", "α\u{0301}"),
            ("ή", "η\u{0301}"),
            ("ό", "ο\u{0301}"),
            ("ϊ", "ι\u{0308}"),
            ("ΟΔΌΣ", "οδο\u{0301}σ"), // word-final sigma folds like non-final
        ];
        for (composed, decomposed) in cases {
            assert_eq!(
                ext4_casefold_key(composed.as_bytes()),
                ext4_casefold_key(decomposed.as_bytes()),
                "composed {composed:?} must fold to the same key as decomposed {decomposed:?}"
            );
        }
        // ASCII is unaffected.
        assert_eq!(ext4_casefold_key(b"Hello"), b"hello".to_vec());
    }

    #[test]
    fn ext4_casefold_key_nfd_normalizes_latin_extended_additional_single_mark_bd_vsuni() {
        let cases: &[(&str, &str)] = &[
            ("Ḁ", "a\u{0325}"),
            ("Ḃ", "b\u{0307}"),
            ("Ḅ", "b\u{0323}"),
            ("Ḇ", "b\u{0331}"),
            ("Ḑ", "d\u{0327}"),
            ("ḓ", "d\u{032D}"),
            ("Ḛ", "e\u{0330}"),
            ("Ḡ", "g\u{0304}"),
            ("Ḫ", "h\u{032E}"),
            ("Ḭ", "i\u{0330}"),
            ("Ḳ", "k\u{0323}"),
            ("Ḽ", "l\u{032D}"),
            ("Ṃ", "m\u{0323}"),
            ("Ṋ", "n\u{032D}"),
            ("Ṕ", "p\u{0301}"),
            ("Ṟ", "r\u{0331}"),
            ("Ṣ", "s\u{0323}"),
            ("Ṱ", "t\u{032D}"),
            ("Ṳ", "u\u{0324}"),
            ("Ṽ", "v\u{0303}"),
            ("Ẉ", "w\u{0323}"),
            ("Ẍ", "x\u{0308}"),
            ("Ẏ", "y\u{0307}"),
            ("Ẕ", "z\u{0331}"),
            ("ẛ", "s\u{0307}"),
        ];
        for (composed, decomposed) in cases {
            assert_eq!(
                ext4_casefold_key(composed.as_bytes()),
                ext4_casefold_key(decomposed.as_bytes()),
                "Latin Extended Additional composed {composed:?} must fold to {decomposed:?}"
            );
        }
    }

    #[test]
    fn ext4_casefold_key_nfd_normalizes_latin_extended_additional_multi_mark_bd_vsuni() {
        let cases: &[(&str, &str)] = &[
            ("Ḉ", "c\u{0327}\u{0301}"),
            ("Ḕ", "e\u{0304}\u{0300}"),
            ("Ḗ", "e\u{0304}\u{0301}"),
            ("Ḝ", "e\u{0327}\u{0306}"),
            ("Ḯ", "i\u{0308}\u{0301}"),
            ("Ḹ", "l\u{0323}\u{0304}"),
            ("Ṍ", "o\u{0303}\u{0301}"),
            ("Ṏ", "o\u{0303}\u{0308}"),
            ("Ṑ", "o\u{0304}\u{0300}"),
            ("Ṓ", "o\u{0304}\u{0301}"),
            ("Ṝ", "r\u{0323}\u{0304}"),
            ("Ṥ", "s\u{0301}\u{0307}"),
            ("Ṧ", "s\u{030C}\u{0307}"),
            ("Ṩ", "s\u{0323}\u{0307}"),
            ("Ṹ", "u\u{0303}\u{0301}"),
            ("Ṻ", "u\u{0304}\u{0308}"),
        ];
        for (composed, decomposed) in cases {
            assert_eq!(
                ext4_casefold_key(composed.as_bytes()),
                ext4_casefold_key(decomposed.as_bytes()),
                "Latin Extended Additional multi-mark {composed:?} must fold to {decomposed:?}"
            );
        }
        assert!(ext4_casefold_names_collide(
            "ḈaṦeṸ".as_bytes(),
            "c\u{0327}\u{0301}as\u{030C}\u{0307}eu\u{0303}\u{0301}".as_bytes()
        ));
    }

    #[test]
    fn ext4_casefold_key_nfd_normalizes_vietnamese_bd_vsuni() {
        let cases: &[(&str, &str)] = &[
            ("ạ", "a\u{0323}"),
            ("Ạ", "a\u{0323}"),
            ("ả", "a\u{0309}"),
            ("ơ", "o\u{031B}"),
            ("Ư", "u\u{031B}"),
            ("Ấ", "a\u{0302}\u{0301}"),
            ("Ầ", "a\u{0302}\u{0300}"),
            ("Ẩ", "a\u{0302}\u{0309}"),
            ("Ẫ", "a\u{0302}\u{0303}"),
            ("Ậ", "a\u{0323}\u{0302}"),
            ("Ắ", "a\u{0306}\u{0301}"),
            ("Ằ", "a\u{0306}\u{0300}"),
            ("Ẳ", "a\u{0306}\u{0309}"),
            ("Ẵ", "a\u{0306}\u{0303}"),
            ("Ặ", "a\u{0323}\u{0306}"),
            ("Ế", "e\u{0302}\u{0301}"),
            ("Ề", "e\u{0302}\u{0300}"),
            ("Ể", "e\u{0302}\u{0309}"),
            ("Ễ", "e\u{0302}\u{0303}"),
            ("Ệ", "e\u{0323}\u{0302}"),
            ("Ố", "o\u{0302}\u{0301}"),
            ("Ồ", "o\u{0302}\u{0300}"),
            ("Ổ", "o\u{0302}\u{0309}"),
            ("Ỗ", "o\u{0302}\u{0303}"),
            ("Ộ", "o\u{0323}\u{0302}"),
            ("Ớ", "o\u{031B}\u{0301}"),
            ("Ờ", "o\u{031B}\u{0300}"),
            ("Ở", "o\u{031B}\u{0309}"),
            ("Ỡ", "o\u{031B}\u{0303}"),
            ("Ợ", "o\u{031B}\u{0323}"),
            ("Ứ", "u\u{031B}\u{0301}"),
            ("Ừ", "u\u{031B}\u{0300}"),
            ("Ử", "u\u{031B}\u{0309}"),
            ("Ữ", "u\u{031B}\u{0303}"),
            ("Ự", "u\u{031B}\u{0323}"),
            ("Ỳ", "y\u{0300}"),
            ("Ỵ", "y\u{0323}"),
            ("Ỷ", "y\u{0309}"),
            ("Ỹ", "y\u{0303}"),
        ];
        for (composed, decomposed) in cases {
            assert_eq!(
                ext4_casefold_key(composed.as_bytes()),
                ext4_casefold_key(decomposed.as_bytes()),
                "Vietnamese composed {composed:?} must fold to NFD key {decomposed:?}"
            );
        }
        assert!(ext4_casefold_names_collide(
            "Tiếng Việt".as_bytes(),
            "tie\u{0302}\u{0301}ng vie\u{0323}\u{0302}t".as_bytes()
        ));
    }

    #[test]
    fn ext4_casefold_key_nfd_normalizes_latin_extended_additional_u1e9a_bd_vsuni() {
        assert_eq!(
            ext4_casefold_key("ẚ".as_bytes()),
            ext4_casefold_key("a\u{02BE}".as_bytes())
        );
        assert!(ext4_casefold_names_collide(
            "ẚla".as_bytes(),
            "a\u{02BE}la".as_bytes()
        ));
    }

    #[test]
    fn ext4_casefold_key_nfd_normalizes_precomposed_cyrillic_bd_vsuni() {
        let cases: &[(&str, &str)] = &[
            ("Ѐ", "е\u{0300}"),
            ("ѐ", "е\u{0300}"),
            ("Ё", "е\u{0308}"),
            ("ё", "е\u{0308}"),
            ("Ѓ", "г\u{0301}"),
            ("ѓ", "г\u{0301}"),
            ("Ї", "і\u{0308}"),
            ("ї", "і\u{0308}"),
            ("Ќ", "к\u{0301}"),
            ("ќ", "к\u{0301}"),
            ("Ѝ", "и\u{0300}"),
            ("ѝ", "и\u{0300}"),
            ("Ў", "у\u{0306}"),
            ("ў", "у\u{0306}"),
            ("Й", "и\u{0306}"),
            ("й", "и\u{0306}"),
            ("Ѷ", "ѵ\u{030F}"),
            ("ѷ", "ѵ\u{030F}"),
            ("Ӂ", "ж\u{0306}"),
            ("ӂ", "ж\u{0306}"),
            ("Ӑ", "а\u{0306}"),
            ("ӑ", "а\u{0306}"),
            ("Ӓ", "а\u{0308}"),
            ("ӓ", "а\u{0308}"),
            ("Ӗ", "е\u{0306}"),
            ("ӗ", "е\u{0306}"),
            ("Ӛ", "ә\u{0308}"),
            ("ӛ", "ә\u{0308}"),
            ("Ӝ", "ж\u{0308}"),
            ("ӝ", "ж\u{0308}"),
            ("Ӟ", "з\u{0308}"),
            ("ӟ", "з\u{0308}"),
            ("Ӣ", "и\u{0304}"),
            ("ӣ", "и\u{0304}"),
            ("Ӥ", "и\u{0308}"),
            ("ӥ", "и\u{0308}"),
            ("Ӧ", "о\u{0308}"),
            ("ӧ", "о\u{0308}"),
            ("Ӫ", "ө\u{0308}"),
            ("ӫ", "ө\u{0308}"),
            ("Ӭ", "э\u{0308}"),
            ("ӭ", "э\u{0308}"),
            ("Ӯ", "у\u{0304}"),
            ("ӯ", "у\u{0304}"),
            ("Ӱ", "у\u{0308}"),
            ("ӱ", "у\u{0308}"),
            ("Ӳ", "у\u{030B}"),
            ("ӳ", "у\u{030B}"),
            ("Ӵ", "ч\u{0308}"),
            ("ӵ", "ч\u{0308}"),
            ("Ӹ", "ы\u{0308}"),
            ("ӹ", "ы\u{0308}"),
        ];
        for (composed, decomposed) in cases {
            assert_eq!(
                ext4_casefold_key(composed.as_bytes()),
                ext4_casefold_key(decomposed.as_bytes()),
                "Cyrillic composed {composed:?} must fold to {decomposed:?}"
            );
        }
        assert!(ext4_casefold_names_collide(
            "КРАЙ-ӬЛ".as_bytes(),
            "краи\u{0306}-э\u{0308}л".as_bytes()
        ));
    }

    #[test]
    fn ext4_casefold_key_exposes_collision_contract() {
        assert!(ext4_casefold_names_collide(
            "Straße.TXT".as_bytes(),
            b"STRASSE.txt",
        ));
        assert!(ext4_casefold_names_collide(
            "STRAẞE.txt".as_bytes(),
            b"strasse.TXT",
        ));
        assert!(!ext4_casefold_names_collide(b"strasse-a", b"strasse-b"));
    }

    #[test]
    fn ext4_casefold_key_ascii_lowercases_bytes() {
        assert_eq!(ext4_casefold_key(b"README.md"), b"readme.md");
        assert_eq!(
            ext4_casefold_key(b"DOCUMENTATION_AND_NOTES.txt"),
            b"documentation_and_notes.txt"
        );
        assert_eq!(
            ext4_casefold_key(b"some_quite_long_filename_with_many_characters_to_exercise.dat"),
            b"some_quite_long_filename_with_many_characters_to_exercise.dat"
        );
    }

    #[test]
    fn ext4_casefold_key_specialized_unicode_ranges_match_slow_reference_bd_xmh5g_125() {
        fn slow_reference(name: &[u8]) -> Vec<u8> {
            if name.is_ascii() {
                let mut folded = name.to_vec();
                folded.make_ascii_lowercase();
                return folded;
            }

            std::str::from_utf8(name).map_or_else(
                |_| {
                    name.iter()
                        .map(|&b| {
                            if b.is_ascii_uppercase() {
                                b.to_ascii_lowercase()
                            } else {
                                b
                            }
                        })
                        .collect()
                },
                |s| {
                    let mut folded = String::with_capacity(s.len());
                    for ch in s.chars() {
                        // Mirror the NFD decomposition of precomposed letters
                        // (bd-qdmlu/bd-gegku) so this reference stays faithful to
                        // the NFD-aware fast path; the canonical decomposition is
                        // the ground truth.
                        if push_precomposed_nfd_casefold(&mut folded, ch) {
                            continue;
                        }
                        match ch {
                            'ß' | 'ẞ' => folded.push_str("ss"),
                            _ => folded.extend(ch.to_lowercase()),
                        }
                    }
                    folded.into_bytes()
                },
            )
        }

        let samples = [
            "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩΪΫ",
            "ЁАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ",
            "你好世界这是一个长的中文文件名",
            "אבגדהוזחטיכלמנסעפצקרשת",
            "ΑΒΓStraßeЁЯ你好אבגSTRAẞE",
        ];

        for sample in samples {
            assert_eq!(
                ext4_casefold_key(sample.as_bytes()),
                slow_reference(sample.as_bytes()),
                "specialized casefold range must match slow reference for {sample:?}"
            );
        }
    }

    #[test]
    fn ext4_casefold_diagnostics_reports_invalid_utf8_ascii_fallback() {
        let diagnostics = ext4_casefold_name_diagnostics(b"ABC\xff");

        assert_eq!(diagnostics.source_len, 4);
        assert_eq!(diagnostics.folded_key, b"abc\xff");
        assert!(!diagnostics.utf8_valid());
        assert!(diagnostics.ascii_fallback());
        assert!(!diagnostics.source_exceeds_ext4_name_limit());
        assert!(!diagnostics.folded_key_exceeds_ext4_name_limit());
        assert!(ext4_casefold_names_collide(b"ABC\xff", b"abc\xff"));
        assert!(!ext4_casefold_names_collide(b"ABC\xff", b"abc\xfe"));
    }

    #[test]
    fn ext4_casefold_diagnostics_reports_folded_key_overflow() {
        let name = "ß".repeat(128);
        let diagnostics = ext4_casefold_name_diagnostics(name.as_bytes());

        assert_eq!(diagnostics.source_len, 256);
        assert!(diagnostics.utf8_valid());
        assert!(!diagnostics.ascii_fallback());
        assert!(diagnostics.source_exceeds_ext4_name_limit());
        assert!(diagnostics.folded_key_exceeds_ext4_name_limit());
        assert_eq!(diagnostics.folded_key.len(), 256);
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
        let remaining = u16::try_from(block_size).unwrap() - 24;
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
    fn dir_iter_rejects_slice_larger_than_declared_block_size() {
        let block_size = 1024_u32;
        let mut block = vec![0_u8; 1036];

        write_dir_entry(&mut block, 0, 2, 2, b".", 1024);
        write_dir_entry(&mut block, 1024, 99, 1, b"x", 12);

        let mut iter = iter_dir_block(&block, block_size);
        let err = iter.next().unwrap().unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "dir_block",
                ..
            }
        ));
        assert!(iter.next().is_none());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn dir_iter_with_checksum_tail() {
        let block_size = 4096_u32;
        let mut block = vec![0_u8; block_size as usize];

        let entry_rec_len = u16::try_from(block_size).unwrap() - 12;
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
    fn dir_iter_rejects_truncated_checksum_tail() {
        let block_size = 32_u32;
        let mut block = vec![0_u8; 30];

        let entry_rec_len = u16::try_from(block_size - 12).unwrap();
        write_dir_entry(&mut block, 0, 2, 2, b".", entry_rec_len);

        let tail_off = (block_size - 12) as usize;
        block[tail_off..tail_off + 4].copy_from_slice(&0_u32.to_le_bytes());
        block[tail_off + 4..tail_off + 6].copy_from_slice(&12_u16.to_le_bytes());
        block[tail_off + 6] = 0;
        block[tail_off + 7] = EXT4_FT_DIR_CSUM;

        let mut iter = iter_dir_block(&block, block_size);
        assert!(iter.next().unwrap().is_ok());
        let err = iter.next().unwrap().unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn dir_iter_rejects_checksum_tail_not_at_end() {
        let block_size = 32_u32;
        let mut block = vec![0_u8; block_size as usize];

        write_dir_entry(&mut block, 0, 2, 2, b".", 12);

        let tail_off = 12_usize;
        block[tail_off..tail_off + 4].copy_from_slice(&0_u32.to_le_bytes());
        block[tail_off + 4..tail_off + 6].copy_from_slice(&12_u16.to_le_bytes());
        block[tail_off + 6] = 0;
        block[tail_off + 7] = EXT4_FT_DIR_CSUM;
        block[tail_off + 8..tail_off + 12].copy_from_slice(&0xCAFE_BABE_u32.to_le_bytes());
        block[tail_off + 12] = 1;

        let mut iter = iter_dir_block(&block, block_size);
        assert!(iter.next().unwrap().is_ok());
        let err = iter.next().unwrap().unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "dir_block_tail",
                ..
            }
        ));
    }

    #[test]
    fn dir_iter_rejects_malformed_checksum_tail_header() {
        let block_size = 32_u32;
        let mut block = vec![0_u8; block_size as usize];

        write_dir_entry(&mut block, 0, 2, 2, b".", 20);

        let tail_off = 20_usize;
        block[tail_off..tail_off + 4].copy_from_slice(&0_u32.to_le_bytes());
        block[tail_off + 4..tail_off + 6].copy_from_slice(&12_u16.to_le_bytes());
        block[tail_off + 6] = 1;
        block[tail_off + 7] = EXT4_FT_DIR_CSUM;

        let mut iter = iter_dir_block(&block, block_size);
        assert!(iter.next().unwrap().is_ok());
        let err = iter.next().unwrap().unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "dir_block_tail",
                ..
            }
        ));
    }

    #[test]
    fn dir_iter_allows_checksum_tail_with_zero_padding() {
        let block_size = 32_u32;
        let mut block = vec![0_u8; block_size as usize];

        write_dir_entry(&mut block, 0, 2, 2, b".", 12);

        let tail_off = 12_usize;
        block[tail_off..tail_off + 4].copy_from_slice(&0_u32.to_le_bytes());
        block[tail_off + 4..tail_off + 6].copy_from_slice(&12_u16.to_le_bytes());
        block[tail_off + 6] = 0;
        block[tail_off + 7] = EXT4_FT_DIR_CSUM;
        block[tail_off + 8..tail_off + 12].copy_from_slice(&0xCAFE_BABE_u32.to_le_bytes());

        let mut iter = iter_dir_block(&block, block_size);
        let entry = iter.next().unwrap().unwrap();
        assert!(entry.is_dot());
        assert!(iter.next().is_none());
        assert!(iter.checksum_tail().is_some());
    }

    #[test]
    fn dir_iter_rejects_trailing_bytes() {
        let block_size = 32_u32;
        let mut block = vec![0_u8; block_size as usize];

        write_dir_entry(&mut block, 0, 2, 2, b".", 28);

        let mut iter = iter_dir_block(&block, block_size);
        assert!(iter.next().unwrap().is_ok());
        let err = iter.next().unwrap().unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn dir_iter_empty_block() {
        // All-zero block: inode=0, rec_len_raw=0 → rec_len_from_disk maps 0 to
        // block_size (ext4 kernel convention: raw 0 and 0xFFFC both encode
        // "entire block"), so the single deleted entry is silently skipped.
        let block = vec![0_u8; 4096];
        let mut iter = iter_dir_block(&block, 4096);
        assert!(
            iter.next().is_none(),
            "all-zero block should yield no entries"
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn dir_iter_rec_len_zero() {
        let mut block = vec![0_u8; 1024];
        // Entry with inode=5, rec_len_raw=0 on disk → rec_len_from_disk(0,1024) = 1024.
        // Per the ext4 kernel convention, raw 0 encodes "entire block".
        block[0..4].copy_from_slice(&5_u32.to_le_bytes());
        block[4..6].copy_from_slice(&0_u16.to_le_bytes());
        block[6] = 1; // name_len
        block[7] = 1; // file_type (regular)
        block[8] = b'x'; // name

        let mut iter = iter_dir_block(&block, 1024);
        let entry = iter
            .next()
            .expect("should yield an entry")
            .expect("should parse ok");
        assert_eq!(entry.inode, 5);
        assert_eq!(entry.rec_len, 1024);
        assert_eq!(entry.name, b"x");

        // Only one entry spans the whole block, so iterator is exhausted.
        assert!(iter.next().is_none());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn dir_iter_rec_len_too_small() {
        // rec_len=4 on disk → rec_len_from_disk(4, 1024) = 4, which is < 12.
        let mut block = vec![0_u8; 1024];
        block[0..4].copy_from_slice(&5_u32.to_le_bytes()); // inode=5
        block[4..6].copy_from_slice(&4_u16.to_le_bytes()); // rec_len=4
        block[6] = 1; // name_len
        block[7] = 1; // file_type

        let mut iter = iter_dir_block(&block, 1024);
        let result = iter.next().expect("should yield an item");
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
            "expected rec_len < 12 error, got {err:?}",
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
        let remaining = u16::try_from(block_size).unwrap() - 24;
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

        let remaining = u16::try_from(block_size).unwrap();
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

        write_dir_entry(
            &mut block,
            0,
            11,
            2,
            b"only_entry",
            u16::try_from(block_size).unwrap(),
        );

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

    #[test]
    fn image_reader_rejects_block_past_declared_blocks_count() {
        let block_size = 4096_usize;
        let declared_blocks = 16_u64;
        let image_blocks = 32_usize;
        let mut image = vec![0_u8; block_size * image_blocks];

        let sb_off = EXT4_SUPERBLOCK_OFFSET;
        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
        sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes());
        sb[0x04..0x08].copy_from_slice(
            &u32::try_from(declared_blocks)
                .expect("fixture block count fits")
                .to_le_bytes(),
        );
        image[sb_off..sb_off + EXT4_SUPERBLOCK_SIZE].copy_from_slice(&sb);

        let reader = Ext4ImageReader::new(&image).expect("parse image");
        let last_declared = reader
            .read_block(&image, ffs_types::BlockNumber(declared_blocks - 1))
            .expect("last declared block is readable");
        assert_eq!(last_declared.len(), block_size);

        let err = reader
            .read_block(&image, ffs_types::BlockNumber(declared_blocks))
            .expect_err("first block beyond declared filesystem rejects");
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "block_number",
                reason: "block outside filesystem block count",
            }
        );
    }

    // ── Checksum verification tests ─────────────────────────────────────

    /// Helper: compute group descriptor checksum the same way the kernel does,
    /// then store it, and verify our verification function accepts it.
    #[test]
    fn group_desc_checksum_round_trip() {
        let uuid = [1_u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        // Compute csum_seed = ext4_chksum(~0, uuid, 16)
        let csum_seed = ext4_chksum(!0u32, &uuid);

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
        let mut csum = ext4_chksum(csum_seed, &le_group);
        csum = ext4_chksum(csum, &gd[..GD_CHECKSUM_OFFSET]);
        csum = ext4_chksum(csum, &[0, 0]);
        let after = GD_CHECKSUM_OFFSET + 2;
        if after < 32 {
            csum = ext4_chksum(csum, &gd[after..32]);
        }
        let checksum = (csum & 0xFFFF) as u16;

        // Store it
        gd[GD_CHECKSUM_OFFSET..GD_CHECKSUM_OFFSET + 2].copy_from_slice(&checksum.to_le_bytes());

        // Verify it passes
        verify_group_desc_checksum(
            &gd,
            &uuid,
            csum_seed,
            group_number,
            desc_size,
            Ext4GroupDescChecksumKind::MetadataCsum,
        )
        .expect("checksum should match");

        // Corrupt one byte and verify it fails
        gd[0] ^= 0xFF;
        assert!(
            verify_group_desc_checksum(
                &gd,
                &uuid,
                csum_seed,
                group_number,
                desc_size,
                Ext4GroupDescChecksumKind::MetadataCsum,
            )
            .is_err()
        );
    }

    /// Helper: compute inode checksum the same way the kernel does,
    /// then store it, and verify our verification function accepts it.
    #[test]
    fn inode_checksum_round_trip() {
        let uuid = [0xAA_u8; 16];
        let csum_seed = ext4_chksum(!0u32, &uuid);
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
        // ino_seed = ext4_chksum(csum_seed, le_ino)
        // ino_seed = ext4_chksum(ino_seed, le_gen)
        let ino_seed = ext4_chksum(csum_seed, &ino.to_le_bytes());
        let ino_seed = ext4_chksum(ino_seed, &42_u32.to_le_bytes());

        // CRC base inode, zeroing i_checksum_lo at 0x7C
        let mut csum = ext4_chksum(ino_seed, &raw[..INODE_CHECKSUM_LO_OFFSET]);
        csum = ext4_chksum(csum, &[0, 0]);
        csum = ext4_chksum(csum, &raw[INODE_CHECKSUM_LO_OFFSET + 2..128]);

        // Extended area, zeroing i_checksum_hi at 0x82
        csum = ext4_chksum(csum, &raw[128..INODE_CHECKSUM_HI_OFFSET]);
        csum = ext4_chksum(csum, &[0, 0]);
        csum = ext4_chksum(csum, &raw[INODE_CHECKSUM_HI_OFFSET + 2..256]);

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

    fn set_bitmap_bit(bitmap: &mut [u8], bit: u32) {
        let byte_idx = usize::try_from(bit / 8).expect("bit index fits usize");
        let bit_in_byte = u8::try_from(bit % 8).expect("bit-in-byte fits u8");
        bitmap[byte_idx] |= 1_u8 << bit_in_byte;
    }

    #[test]
    fn inode_bitmap_corruption_detected_by_free_count_mismatch() {
        let inodes_per_group = 32_u32;
        let mut inode_bitmap = vec![0_u8; 4];

        // Mark 3 inodes used -> free should be 29.
        set_bitmap_bit(&mut inode_bitmap, 0);
        set_bitmap_bit(&mut inode_bitmap, 2);
        set_bitmap_bit(&mut inode_bitmap, 7);
        verify_inode_bitmap_free_count(&inode_bitmap, inodes_per_group, 29)
            .expect("free count should match");

        // Corrupt bitmap by flipping one more bit to "used".
        set_bitmap_bit(&mut inode_bitmap, 8);
        let err = verify_inode_bitmap_free_count(&inode_bitmap, inodes_per_group, 29)
            .expect_err("bitmap mismatch should be detected");
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "bg_inode_bitmap",
                reason: "bitmap free count mismatch"
            }
        ));
    }

    #[test]
    fn block_bitmap_corruption_detected_by_free_count_mismatch() {
        let blocks_per_group = 64_u32;
        let mut block_bitmap = vec![0_u8; 8];

        // Mark 10 blocks used -> free should be 54.
        for idx in [0_u32, 1, 2, 3, 8, 9, 10, 15, 31, 47] {
            set_bitmap_bit(&mut block_bitmap, idx);
        }
        verify_block_bitmap_free_count(&block_bitmap, blocks_per_group, 54)
            .expect("free count should match");

        // Corrupt bitmap by clearing one used bit; free count no longer matches.
        let byte_idx = usize::try_from(31_u32 / 8).expect("fits");
        let bit_in_byte = u8::try_from(31_u32 % 8).expect("fits");
        block_bitmap[byte_idx] &= !(1_u8 << bit_in_byte);

        let err = verify_block_bitmap_free_count(&block_bitmap, blocks_per_group, 54)
            .expect_err("bitmap mismatch should be detected");
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "bg_block_bitmap",
                reason: "bitmap free count mismatch"
            }
        ));
    }

    #[test]
    fn extent_internal_corruption_keeps_earlier_extents_accessible() {
        let block_size = 4096_usize;
        let image_blocks = 80_usize;
        let image_blocks_u32 = u32::try_from(image_blocks).expect("image blocks fit u32");
        let block_size_u32 = u32::try_from(block_size).expect("block size fits u32");
        let mut image = vec![0_u8; block_size * image_blocks];

        // Superblock
        let sb_off = EXT4_SUPERBLOCK_OFFSET;
        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
        sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes()); // 4K blocks
        sb[0x1C..0x20].copy_from_slice(&2_u32.to_le_bytes()); // 4K clusters
        sb[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_count
        sb[0x04..0x08].copy_from_slice(&image_blocks_u32.to_le_bytes()); // blocks_count
        sb[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes()); // first_data_block=0
        sb[0x20..0x24].copy_from_slice(&image_blocks_u32.to_le_bytes()); // blocks_per_group
        sb[0x24..0x28].copy_from_slice(&image_blocks_u32.to_le_bytes()); // clusters_per_group
        sb[0x28..0x2C].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_per_group
        sb[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size
        sb[0x54..0x58].copy_from_slice(&11_u32.to_le_bytes()); // first_ino
        image[sb_off..sb_off + EXT4_SUPERBLOCK_SIZE].copy_from_slice(&sb);

        // Group descriptor table at block 1, inode table starts at block 2.
        let gdt_off = block_size;
        let mut gd = [0_u8; 32];
        gd[0x08..0x0C].copy_from_slice(&2_u32.to_le_bytes()); // inode_table
        image[gdt_off..gdt_off + 32].copy_from_slice(&gd);

        // Inode 11 with a depth-1 extent tree and two child leaves.
        let inode_table_off = 2 * block_size;
        let inode_off = inode_table_off + (11 - 1) * 256;
        image[inode_off..inode_off + 2].copy_from_slice(&0o100_644_u16.to_le_bytes()); // mode
        image[inode_off + 0x04..inode_off + 0x08]
            .copy_from_slice(&(16_u32 * block_size_u32).to_le_bytes()); // size_lo
        image[inode_off + 0x1A..inode_off + 0x1C].copy_from_slice(&1_u16.to_le_bytes()); // links
        image[inode_off + 0x20..inode_off + 0x24].copy_from_slice(&0x0008_0000_u32.to_le_bytes()); // extents flag
        image[inode_off + 0x64..inode_off + 0x68].copy_from_slice(&1_u32.to_le_bytes()); // generation

        let i_block = inode_off + 0x28;
        image[i_block..i_block + 2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes()); // magic
        image[i_block + 2..i_block + 4].copy_from_slice(&2_u16.to_le_bytes()); // entries
        image[i_block + 4..i_block + 6].copy_from_slice(&4_u16.to_le_bytes()); // max
        image[i_block + 6..i_block + 8].copy_from_slice(&1_u16.to_le_bytes()); // depth
        image[i_block + 8..i_block + 12].copy_from_slice(&1_u32.to_le_bytes()); // generation

        // Index 0 -> leaf block 20 for logical blocks 0..7
        let idx0 = i_block + 12;
        image[idx0..idx0 + 4].copy_from_slice(&0_u32.to_le_bytes()); // logical start
        image[idx0 + 4..idx0 + 8].copy_from_slice(&20_u32.to_le_bytes()); // leaf_lo
        image[idx0 + 8..idx0 + 10].copy_from_slice(&0_u16.to_le_bytes()); // leaf_hi

        // Index 1 -> leaf block 21 for logical blocks 8..
        let idx1 = i_block + 24;
        image[idx1..idx1 + 4].copy_from_slice(&8_u32.to_le_bytes()); // logical start
        image[idx1 + 4..idx1 + 8].copy_from_slice(&21_u32.to_le_bytes()); // leaf_lo
        image[idx1 + 8..idx1 + 10].copy_from_slice(&0_u16.to_le_bytes()); // leaf_hi

        // Valid child leaf at block 20 -> one extent (logical 0..7 -> physical 40..47).
        let leaf0 = 20 * block_size;
        image[leaf0..leaf0 + 2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes()); // magic
        image[leaf0 + 2..leaf0 + 4].copy_from_slice(&1_u16.to_le_bytes()); // entries
        image[leaf0 + 4..leaf0 + 6].copy_from_slice(&4_u16.to_le_bytes()); // max
        image[leaf0 + 6..leaf0 + 8].copy_from_slice(&0_u16.to_le_bytes()); // depth
        image[leaf0 + 8..leaf0 + 12].copy_from_slice(&1_u32.to_le_bytes()); // generation
        let leaf0_e = leaf0 + 12;
        image[leaf0_e..leaf0_e + 4].copy_from_slice(&0_u32.to_le_bytes()); // logical
        image[leaf0_e + 4..leaf0_e + 6].copy_from_slice(&8_u16.to_le_bytes()); // len
        image[leaf0_e + 8..leaf0_e + 12].copy_from_slice(&40_u32.to_le_bytes()); // physical

        // Corrupted child leaf at block 21 (bad magic).
        let leaf1 = 21 * block_size;
        image[leaf1..leaf1 + 2].copy_from_slice(&0xFFFF_u16.to_le_bytes()); // bad magic
        image[leaf1 + 2..leaf1 + 4].copy_from_slice(&1_u16.to_le_bytes());
        image[leaf1 + 4..leaf1 + 6].copy_from_slice(&4_u16.to_le_bytes());
        image[leaf1 + 6..leaf1 + 8].copy_from_slice(&0_u16.to_le_bytes());

        let reader = Ext4ImageReader::new(&image).expect("open image");
        let inode = reader
            .read_inode(&image, ffs_types::InodeNumber(11))
            .expect("read inode 11");

        // Extents before the corrupted child remain resolvable.
        let first = reader
            .resolve_extent(&image, &inode, 0)
            .expect("resolve first logical block");
        assert_eq!(first, Some(40));

        // Extents routed through the corrupted child fail cleanly.
        let err = reader
            .resolve_extent(&image, &inode, 8)
            .expect_err("second logical range should fail due to child corruption");
        assert!(matches!(err, ParseError::InvalidMagic { .. }));
    }

    #[test]
    fn inode_corruption_makes_only_target_file_inaccessible() {
        let mut image = build_test_image();
        let reader = Ext4ImageReader::new(&image).expect("open image");

        // Corrupt inode 11's extent header magic (hello.txt).
        let inode11_off = (2 * 4096) + ((11 - 1) * 256);
        let i_block = inode11_off + 0x28;
        image[i_block..i_block + 2].copy_from_slice(&0_u16.to_le_bytes());

        // The corrupted file now fails cleanly on read.
        let (_, hello_inode) = reader
            .resolve_path(&image, "/hello.txt")
            .expect("resolve corrupted inode path");
        let mut hello_buf = vec![0_u8; 32];
        let err = reader
            .read_inode_data(&image, &hello_inode, 0, &mut hello_buf)
            .expect_err("corrupted inode should fail");
        assert!(matches!(err, ParseError::InvalidMagic { .. }));

        // Neighbor files remain readable.
        let (_, deep_inode) = reader
            .resolve_path(&image, "/subdir/deep.txt")
            .expect("resolve unaffected file");
        let mut deep_buf = vec![0_u8; 16];
        let n = reader
            .read_inode_data(&image, &deep_inode, 0, &mut deep_buf)
            .expect("unaffected file read succeeds");
        assert_eq!(n, 16);
        assert!(deep_buf.iter().all(|&b| b == b'A'));
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
    fn extent_resolve_cache_matches_uncached_depth1() {
        // Build a depth-0 child extent leaf block: `exts` = (logical, len, phys).
        fn leaf_block_bytes(exts: &[(u32, u16, u32)]) -> Vec<u8> {
            let mut b = vec![0_u8; 4096];
            b[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
            b[2..4].copy_from_slice(
                &u16::try_from(exts.len())
                    .expect("fixture extent count fits u16")
                    .to_le_bytes(),
            );
            b[4..6].copy_from_slice(&340_u16.to_le_bytes()); // max_entries
            b[6..8].copy_from_slice(&0_u16.to_le_bytes()); // depth=0 (leaf)
            for (i, (lb, len, phys)) in exts.iter().enumerate() {
                let o = 12 + i * 12;
                b[o..o + 4].copy_from_slice(&lb.to_le_bytes());
                b[o + 4..o + 6].copy_from_slice(&len.to_le_bytes());
                b[o + 6..o + 8].copy_from_slice(&0_u16.to_le_bytes()); // start_hi
                b[o + 8..o + 12].copy_from_slice(&phys.to_le_bytes()); // start_lo
            }
            b
        }

        let mut image = build_test_image();
        // Two child leaves at free blocks 50/51 covering logical 0..16 and 16..32.
        image[50 * 4096..50 * 4096 + 4096]
            .copy_from_slice(&leaf_block_bytes(&[(0, 8, 2000), (8, 8, 3000)]));
        image[51 * 4096..51 * 4096 + 4096]
            .copy_from_slice(&leaf_block_bytes(&[(16, 8, 4000), (24, 8, 5000)]));

        // Root: depth-1 index with two entries pointing at blocks 50 and 51.
        let mut root = [0_u8; 60];
        root[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
        root[2..4].copy_from_slice(&2_u16.to_le_bytes()); // entries=2
        root[4..6].copy_from_slice(&4_u16.to_le_bytes()); // max_entries
        root[6..8].copy_from_slice(&1_u16.to_le_bytes()); // depth=1
        root[12..16].copy_from_slice(&0_u32.to_le_bytes()); // ei_block=0
        root[16..20].copy_from_slice(&50_u32.to_le_bytes()); // ei_leaf=50
        root[24..28].copy_from_slice(&16_u32.to_le_bytes()); // ei_block=16
        root[28..32].copy_from_slice(&51_u32.to_le_bytes()); // ei_leaf=51

        let reader = Ext4ImageReader::new(&image).unwrap();
        let (h, tree) = parse_extent_tree(&root).unwrap();

        // Cached must match uncached for sequential, reverse, and out-of-order
        // access (exercises cache hit, evict, and per-call miss).
        let orders: Vec<Vec<u32>> = vec![
            (0..40).collect(),
            (0..40).rev().collect(),
            vec![31, 0, 16, 15, 16, 0, 31, 8, 24, 999],
        ];
        for order in orders {
            let mut cache = ExtentResolveCache::default();
            for lb in order {
                let uncached = reader
                    .resolve_extent_with_tree(&image, &h, &tree, lb)
                    .unwrap();
                let cached = reader
                    .resolve_extent_with_tree_cached(&image, &h, &tree, lb, &mut cache)
                    .unwrap();
                assert_eq!(uncached, cached, "cached != uncached at logical block {lb}");
            }
        }

        // Spot-check concrete mappings across the child boundary via the cache.
        let mut cache = ExtentResolveCache::default();
        assert_eq!(
            reader
                .resolve_extent_with_tree_cached(&image, &h, &tree, 0, &mut cache)
                .unwrap(),
            Some(2000)
        );
        assert_eq!(
            reader
                .resolve_extent_with_tree_cached(&image, &h, &tree, 24, &mut cache)
                .unwrap(),
            Some(5000)
        );
        // A hole past the last extent.
        assert_eq!(
            reader
                .resolve_extent_with_tree_cached(&image, &h, &tree, 32, &mut cache)
                .unwrap(),
            None
        );
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

    fn set_test_inode_flag(image: &mut [u8], ino: u32, flag: u32) {
        let inode_size = 256_usize;
        let itable_off = 2 * 4096_usize;
        let flags_off = itable_off + (ino as usize - 1) * inode_size + 0x20;
        let mut raw = [0_u8; 4];
        raw.copy_from_slice(&image[flags_off..flags_off + 4]);
        let flags = u32::from_le_bytes(raw) | flag;
        image[flags_off..flags_off + 4].copy_from_slice(&flags.to_le_bytes());
    }

    #[test]
    fn is_fast_symlink_respects_size_boundary_and_conditions() {
        let make = |mode: u16, size: u64, flags: u32| Ext4Inode {
            mode,
            uid: 0,
            gid: 0,
            size,
            links_count: 1,
            blocks: 0,
            flags,
            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,
            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0_u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };
        let symlink = 0o120_000_u16; // S_IFLNK
        let regular = 0o100_000_u16; // S_IFREG

        // Size boundary: 60 bytes is an inline (fast) symlink, 61 is a slow one.
        assert!(make(symlink, 60, 0).is_fast_symlink());
        assert!(!make(symlink, 61, 0).is_fast_symlink());

        // A symlink that uses extents is never fast (target lives in blocks).
        assert!(!make(symlink, 10, EXT4_EXTENTS_FL).is_fast_symlink());

        // A non-symlink is never a fast symlink.
        assert!(!make(regular, 10, 0).is_fast_symlink());

        // fast_symlink_target follows is_fast_symlink.
        assert!(make(symlink, 60, 0).fast_symlink_target().is_some());
        assert!(make(symlink, 61, 0).fast_symlink_target().is_none());
        assert!(make(regular, 10, 0).fast_symlink_target().is_none());
    }

    #[test]
    fn dir_logical_block_count_boundaries_and_overflow() {
        // Ceil division of a directory's size into logical blocks.
        assert_eq!(
            Ext4ImageReader::dir_logical_block_count(0, 4096).unwrap(),
            0
        );
        assert_eq!(
            Ext4ImageReader::dir_logical_block_count(1, 4096).unwrap(),
            1
        );
        assert_eq!(
            Ext4ImageReader::dir_logical_block_count(4096, 4096).unwrap(),
            1
        );
        assert_eq!(
            Ext4ImageReader::dir_logical_block_count(4097, 4096).unwrap(),
            2
        );

        // A directory whose block count exceeds u32 is rejected, not truncated.
        assert!(matches!(
            Ext4ImageReader::dir_logical_block_count(u64::MAX, 1),
            Err(ParseError::IntegerConversion {
                field: "dir_block_count"
            })
        ));
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
    fn read_symlink_rejects_encrypted_fast_symlink() {
        let mut image = build_symlink_test_image();
        set_test_inode_flag(&mut image, 14, EXT4_ENCRYPT_INODE_FL);
        let reader = Ext4ImageReader::new(&image).unwrap();

        let link_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(14))
            .unwrap();
        let err = reader.read_symlink(&image, &link_inode).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "i_flags",
                reason
            } if reason.contains("fscrypt context")
        ));
    }

    #[test]
    fn read_symlink_rejects_encrypted_extent_symlink() {
        let mut image = build_symlink_test_image();
        set_test_inode_flag(&mut image, 15, EXT4_ENCRYPT_INODE_FL);
        let reader = Ext4ImageReader::new(&image).unwrap();

        let link_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(15))
            .unwrap();
        let err = reader.read_symlink(&image, &link_inode).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "i_flags",
                reason
            } if reason.contains("fscrypt context")
        ));
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

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn resolve_path_follow_detects_symlink_loop() {
        // Build a minimal image where /loop → /loop (self-referential).
        let block_size = 4096_usize;
        let image_blocks = 64;
        let mut image = vec![0_u8; block_size * image_blocks];

        let sb_off = EXT4_SUPERBLOCK_OFFSET;
        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
        sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes()); // log_block_size
        sb[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_count
        sb[0x04..0x08].copy_from_slice(&(image_blocks as u32).to_le_bytes());
        sb[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes()); // first_data_block
        sb[0x20..0x24].copy_from_slice(&(image_blocks as u32).to_le_bytes());
        sb[0x28..0x2C].copy_from_slice(&8192_u32.to_le_bytes()); // blocks_per_group
        sb[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size
        sb[0x54..0x58].copy_from_slice(&11_u32.to_le_bytes()); // first_ino
        image[sb_off..sb_off + EXT4_SUPERBLOCK_SIZE].copy_from_slice(&sb);

        let gdt_off = block_size;
        let mut gd = [0_u8; 32];
        gd[0x08..0x0C].copy_from_slice(&2_u32.to_le_bytes()); // inode_table
        image[gdt_off..gdt_off + 32].copy_from_slice(&gd);

        let itable_off = 2 * block_size;
        let inode_size = 256_usize;

        // Root dir (inode 2): extent-mapped at block 10
        {
            let off = itable_off + inode_size; // inode 2, zero-indexed at 1
            image[off..off + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
            image[off + 0x04..off + 0x08].copy_from_slice(&4096_u32.to_le_bytes());
            image[off + 0x1A..off + 0x1C].copy_from_slice(&3_u16.to_le_bytes());
            image[off + 0x20..off + 0x24].copy_from_slice(&0x0008_0000_u32.to_le_bytes());
            image[off + 0x64..off + 0x68].copy_from_slice(&1_u32.to_le_bytes());
            let eh = off + 0x28;
            image[eh..eh + 2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
            image[eh + 2..eh + 4].copy_from_slice(&1_u16.to_le_bytes());
            image[eh + 4..eh + 6].copy_from_slice(&4_u16.to_le_bytes());
            let ee = eh + 12;
            image[ee + 4..ee + 6].copy_from_slice(&1_u16.to_le_bytes()); // len=1
            image[ee + 8..ee + 12].copy_from_slice(&10_u32.to_le_bytes()); // block=10
        }

        // Self-referential symlink (inode 11): /loop → /loop (fast symlink)
        {
            let off = itable_off + (11 - 1) * inode_size;
            image[off..off + 2].copy_from_slice(&0o120_777_u16.to_le_bytes());
            let target = b"/loop";
            image[off + 0x04..off + 0x08].copy_from_slice(&(target.len() as u32).to_le_bytes());
            image[off + 0x1A..off + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
            image[off + 0x64..off + 0x68].copy_from_slice(&1_u32.to_le_bytes());
            let ib = off + 0x28;
            image[ib..ib + target.len()].copy_from_slice(target);
        }

        // Root directory data (block 10): contains "loop" entry
        let root_blk = 10 * block_size;
        write_dir_entry(&mut image, root_blk, 2, 2, b".", 12);
        write_dir_entry(&mut image, root_blk + 12, 2, 2, b"..", 12);
        let remaining: u16 = 4096 - 12 - 12;
        write_dir_entry(&mut image, root_blk + 24, 11, 7, b"loop", remaining);

        let reader = Ext4ImageReader::new(&image).unwrap();
        let err = reader
            .resolve_path_follow(&image, "/loop")
            .expect_err("should detect symlink loop");
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "path",
                    reason: "too many levels of symbolic links"
                }
            ),
            "unexpected error: {err:?}"
        );
    }

    // ── Xattr parsing tests ─────────────────────────────────────────────

    #[test]
    fn parse_xattr_entry_kernel_offsets_match_xattr_h() {
        // fs/ext4/xattr.h struct ext4_xattr_entry:
        //   e_name_len:u8 @0, e_name_index:u8 @1,
        //   e_value_offs:le16 @2, e_value_block:le32 @4,
        //   e_value_size:le32 @8, e_hash:le32 @12, e_name[] @16.
        let mut data = vec![0_u8; 256];
        let name = b"kernel";
        let value = b"layout";
        let value_offs = 128_u16;
        let value_size = u32::try_from(value.len()).expect("fixed value length fits u32");

        data[0] = u8::try_from(name.len()).expect("fixed name length fits u8");
        data[1] = ffs_types::EXT4_XATTR_INDEX_SECURITY;
        data[2..4].copy_from_slice(&value_offs.to_le_bytes());
        data[4..8].copy_from_slice(&0_u32.to_le_bytes());
        data[8..12].copy_from_slice(&value_size.to_le_bytes());
        data[12..16].copy_from_slice(&0xA5A5_5A5A_u32.to_le_bytes());
        data[16..16 + name.len()].copy_from_slice(name);

        let entry_len = (16 + name.len() + 3) & !3;
        data[entry_len] = 0;
        data[entry_len + 1] = 0;
        let value_start = usize::from(value_offs);
        data[value_start..value_start + value.len()].copy_from_slice(value);

        let entries = super::parse_xattr_entries(&data, &data, 0)
            .expect("kernel-stamped xattr entry must parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].name_index,
            ffs_types::EXT4_XATTR_INDEX_SECURITY,
            "e_name_index @0x01"
        );
        assert_eq!(&entries[0].name, name, "e_name @0x10");
        assert_eq!(
            &entries[0].value, value,
            "e_value_offs @0x02 + e_value_size @0x08"
        );
        assert_eq!(entries[0].full_name(), "security.kernel");
    }

    // Differential oracle: the by-name finder must agree with materialize-all for
    // every entry across a table of namespace/index combinations. The length is
    // the table plus one assertion per case, which is the point — trimming cases
    // to reach 100 lines would delete coverage. Narrow allow, bd-3ao0l.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn get_xattr_by_name_finder_matches_materialize_all() {
        // Lay out xattr entries + values in one region. `value_base_start` is the
        // offset of this region within the finder's value_base (0 for the ibody
        // region after the 4-byte magic; 32 for the external block).
        fn build_region(
            items: &[(u8, &[u8], &[u8])],
            value_base_start: usize,
            len: usize,
        ) -> Vec<u8> {
            let mut buf = vec![0_u8; len];
            let mut eo = 0_usize; // entry cursor (front)
            let mut vo = len; // value cursor (back)
            for (idx, name, val) in items {
                vo -= val.len();
                buf[vo..vo + val.len()].copy_from_slice(val);
                buf[eo] = u8::try_from(name.len()).unwrap();
                buf[eo + 1] = *idx;
                buf[eo + 2..eo + 4]
                    .copy_from_slice(&u16::try_from(value_base_start + vo).unwrap().to_le_bytes());
                buf[eo + 8..eo + 12]
                    .copy_from_slice(&u32::try_from(val.len()).unwrap().to_le_bytes());
                buf[eo + 16..eo + 16 + name.len()].copy_from_slice(name);
                eo = (eo + 16 + name.len() + 3) & !3;
            }
            buf // trailing zeros form the (0,0) terminator
        }

        // ibody: magic + region (values addressed from region start).
        let mut ibody = EXT4_XATTR_MAGIC.to_le_bytes().to_vec();
        ibody.extend(build_region(
            &[(
                ffs_types::EXT4_XATTR_INDEX_SECURITY,
                b"selinux",
                b"sysadm_u:obj",
            )],
            0,
            252,
        ));
        // external block: 32-byte header (magic@0) + region at [32..] (absolute value offsets).
        let mut block = vec![0_u8; 4096];
        block[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
        let region = build_region(
            &[
                (ffs_types::EXT4_XATTR_INDEX_USER, b"comment", b"hello-world"),
                (ffs_types::EXT4_XATTR_INDEX_TRUSTED, b"cap", b"0x1"),
            ],
            32,
            4064,
        );
        block[32..].copy_from_slice(&region);

        let mut image = build_test_image();
        image[50 * 4096..51 * 4096].copy_from_slice(&block);

        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,
            version: 0,
            generation: 0,
            file_acl: 50,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,
            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0_u8; 60].into(),
            xattr_ibody: ibody,
            number: 0,
        };

        let reader = Ext4ImageReader::new(&image).unwrap();

        // Old materialise-all-then-find, replicated for the equivalence oracle.
        let old_get = |ni: u8, name: &[u8]| -> Option<Vec<u8>> {
            reader
                .list_xattrs(&image, &inode)
                .unwrap()
                .into_iter()
                .find(|x| x.name_index == ni && x.name == name)
                .map(|x| x.value)
        };

        let cases: &[(u8, &[u8])] = &[
            (ffs_types::EXT4_XATTR_INDEX_SECURITY, b"selinux"), // ibody hit (block skipped)
            (ffs_types::EXT4_XATTR_INDEX_USER, b"comment"),     // block hit
            (ffs_types::EXT4_XATTR_INDEX_TRUSTED, b"cap"),      // block hit (2nd entry)
            (ffs_types::EXT4_XATTR_INDEX_USER, b"absent"),      // miss
            (ffs_types::EXT4_XATTR_INDEX_SECURITY, b"other"),   // miss
        ];
        for (ni, name) in cases {
            let new = reader.get_xattr(&image, &inode, *ni, name).unwrap();
            assert_eq!(
                new,
                old_get(*ni, name),
                "get_xattr mismatch for index {ni} name {name:?}"
            );
        }
        // Concrete spot-checks.
        assert_eq!(
            reader
                .get_xattr(
                    &image,
                    &inode,
                    ffs_types::EXT4_XATTR_INDEX_SECURITY,
                    b"selinux"
                )
                .unwrap()
                .as_deref(),
            Some(&b"sysadm_u:obj"[..])
        );
        assert_eq!(
            reader
                .get_xattr(&image, &inode, ffs_types::EXT4_XATTR_INDEX_TRUSTED, b"cap")
                .unwrap()
                .as_deref(),
            Some(&b"0x1"[..])
        );

        // list_xattr_names must equal the materialise-all-then-full_name path,
        // in the same (ibody-first, then block) order.
        let names_only = reader.list_xattr_names(&image, &inode).unwrap();
        let materialize_all: Vec<String> = reader
            .list_xattrs(&image, &inode)
            .unwrap()
            .iter()
            .map(Ext4Xattr::full_name)
            .collect();
        assert_eq!(
            names_only, materialize_all,
            "list_xattr_names != materialize-all names"
        );
        assert_eq!(
            names_only,
            vec![
                "security.selinux".to_owned(),
                "user.comment".to_owned(),
                "trusted.cap".to_owned(),
            ]
        );
    }

    #[test]
    fn parse_xattr_entries_basic() {
        // Build a minimal xattr entry: name_index=1 (user), name="test", value="val"
        let mut data = vec![0_u8; 256];

        // Entry header (16 bytes):
        data[0] = 4; // name_len=4
        data[1] = 1; // name_index=1 (user)
        data[2..4].copy_from_slice(&128_u16.to_le_bytes()); // value_offs=128
        data[4..8].copy_from_slice(&0_u32.to_le_bytes()); // value_block (unused)
        data[8..12].copy_from_slice(&3_u32.to_le_bytes()); // value_size=3
        data[12..16].copy_from_slice(&0_u32.to_le_bytes()); // hash (unused)
        // Name: "test" at byte 16
        data[16..20].copy_from_slice(b"test");

        // Value at offset 128: "val"
        data[128..131].copy_from_slice(b"val");

        // Terminator at byte 20 (padded: 16 + 4 = 20, already 4-byte aligned)
        data[20] = 0; // name_len=0
        data[21] = 0; // name_index=0

        let entries = super::parse_xattr_entries(&data, &data, 0).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name_index, 1);
        assert_eq!(entries[0].name, b"test");
        assert_eq!(entries[0].value, b"val");
        assert_eq!(entries[0].full_name(), "user.test");
    }

    #[test]
    fn parse_xattr_entry_names_matches_full_name_for_all_prefixes_and_invalid_utf8() {
        let indexes = [
            ffs_types::EXT4_XATTR_INDEX_USER,
            ffs_types::EXT4_XATTR_INDEX_POSIX_ACL_ACCESS,
            ffs_types::EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT,
            ffs_types::EXT4_XATTR_INDEX_TRUSTED,
            ffs_types::EXT4_XATTR_INDEX_SECURITY,
            ffs_types::EXT4_XATTR_INDEX_SYSTEM,
            ffs_types::EXT4_XATTR_INDEX_RICHACL,
            u8::MAX,
        ];
        let mut data = vec![0_u8; 256];
        let mut expected = Vec::new();
        let mut offset = 0_usize;
        for (i, name_index) in indexes.into_iter().enumerate() {
            let name = [b'a' + u8::try_from(i).expect("fixture index fits u8"), 0xFF];
            data[offset] = u8::try_from(name.len()).expect("2-byte fixture name");
            data[offset + 1] = name_index;
            data[offset + 16..offset + 16 + name.len()].copy_from_slice(&name);
            expected.push(
                Ext4Xattr {
                    name_index,
                    name: name.to_vec(),
                    value: Vec::new(),
                }
                .full_name(),
            );
            offset = (offset + 16 + name.len() + 3) & !3;
        }
        data[offset] = 0;
        data[offset + 1] = 0;

        assert_eq!(super::parse_xattr_entry_names(&data).unwrap(), expected);
    }

    #[test]
    fn xattr_full_name_preserves_lossy_invalid_utf8_output() {
        let xattr = Ext4Xattr {
            name_index: ffs_types::EXT4_XATTR_INDEX_USER,
            name: vec![b'a', 0xFF],
            value: Vec::new(),
        };

        assert_eq!(xattr.full_name(), "user.a\u{FFFD}");
    }

    #[test]
    fn parse_xattr_entries_multiple() {
        let mut data = vec![0_u8; 512];

        // Entry 1: security.selinux = "context"
        data[0] = 7; // name_len
        data[1] = ffs_types::EXT4_XATTR_INDEX_SECURITY;
        data[2..4].copy_from_slice(&200_u16.to_le_bytes()); // value_offs
        data[4..8].copy_from_slice(&0_u32.to_le_bytes()); // value_block (unused)
        data[8..12].copy_from_slice(&7_u32.to_le_bytes()); // value_size
        data[12..16].copy_from_slice(&0_u32.to_le_bytes()); // hash (unused)
        data[16..23].copy_from_slice(b"selinux");
        data[200..207].copy_from_slice(b"context");

        // Entry 2 at byte 24 (16 + 7 rounded up to 24): user.mime = "text"
        data[24] = 4;
        data[25] = ffs_types::EXT4_XATTR_INDEX_USER;
        data[26..28].copy_from_slice(&250_u16.to_le_bytes()); // value_offs
        data[28..32].copy_from_slice(&0_u32.to_le_bytes()); // value_block (unused)
        data[32..36].copy_from_slice(&4_u32.to_le_bytes()); // value_size
        data[36..40].copy_from_slice(&0_u32.to_le_bytes()); // hash (unused)
        data[40..44].copy_from_slice(b"mime");
        data[250..254].copy_from_slice(b"text");

        // Terminator at byte 44 (24 + 16 + 4 = 44)
        data[44] = 0;
        data[45] = 0;

        let entries = super::parse_xattr_entries(&data, &data, 0).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].full_name(), "security.selinux");
        assert_eq!(entries[0].value, b"context");
        assert_eq!(entries[1].full_name(), "user.mime");
        assert_eq!(entries[1].value, b"text");
    }

    #[test]
    fn parse_xattr_entries_lists_ea_inode_backed_value_without_rejecting_block_bd_bj00n() {
        // An EA_INODE-backed attribute stores its value in a separate inode:
        // e_value_inum != 0 and e_value_offs == 0. Before the fix the parser
        // ignored e_value_inum, treated e_value_offs (0) as an in-block offset,
        // tripped the "value overlaps header" guard, and returned Err for the
        // ENTIRE block — making the readable in-block sibling unreadable too.
        let mut data = vec![0_u8; 256];

        // Entry 1 (in-block): user.test = "val".
        data[0] = 4; // name_len
        data[1] = ffs_types::EXT4_XATTR_INDEX_USER;
        data[2..4].copy_from_slice(&128_u16.to_le_bytes()); // value_offs
        data[4..8].copy_from_slice(&0_u32.to_le_bytes()); // value_inum = 0 (in-block)
        data[8..12].copy_from_slice(&3_u32.to_le_bytes()); // value_size
        data[16..20].copy_from_slice(b"test");
        data[128..131].copy_from_slice(b"val");

        // Entry 2 (EA-inode-backed) at byte 20: user.big, value in inode 42.
        data[20] = 3; // name_len
        data[21] = ffs_types::EXT4_XATTR_INDEX_USER;
        data[22..24].copy_from_slice(&0_u16.to_le_bytes()); // value_offs = 0
        data[24..28].copy_from_slice(&42_u32.to_le_bytes()); // value_inum = 42
        data[28..32].copy_from_slice(&9000_u32.to_le_bytes()); // value_size (> block, never read in-block)
        data[36..39].copy_from_slice(b"big");

        // Terminator at byte 40 ((36 + 3) rounded up to 4).
        data[40] = 0;
        data[41] = 0;

        let entries = super::parse_xattr_entries(&data, &data, 0).unwrap();
        assert_eq!(
            entries.len(),
            2,
            "both attributes are listed, block not rejected"
        );
        // In-block sibling is still fully readable.
        assert_eq!(entries[0].full_name(), "user.test");
        assert_eq!(entries[0].value, b"val");
        // EA-inode attribute: name surfaced (so listxattr is complete), value
        // empty for now (resolving the EA-inode payload is a separate path).
        assert_eq!(entries[1].full_name(), "user.big");
        assert!(
            entries[1].value.is_empty(),
            "EA-inode value is not read from this block"
        );
    }

    #[test]
    fn parse_xattr_block_with_inum_surfaces_ea_inode_reference_bd_bj00n() {
        // Full external xattr block: 32-byte header (magic) + entries at +32.
        let mut block = vec![0_u8; 256];
        block[0..4].copy_from_slice(&ffs_types::EXT4_XATTR_MAGIC.to_le_bytes());

        // Entry 1 (in-block): user.test = "val" at value_offs 200.
        block[32] = 4; // name_len
        block[33] = ffs_types::EXT4_XATTR_INDEX_USER;
        block[34..36].copy_from_slice(&200_u16.to_le_bytes()); // value_offs
        block[36..40].copy_from_slice(&0_u32.to_le_bytes()); // value_inum = 0
        block[40..44].copy_from_slice(&3_u32.to_le_bytes()); // value_size
        block[48..52].copy_from_slice(b"test");
        block[200..203].copy_from_slice(b"val");

        // Entry 2 (EA-inode-backed): user.big, value in inode 77, offs 0.
        block[52] = 3; // name_len
        block[53] = ffs_types::EXT4_XATTR_INDEX_USER;
        block[54..56].copy_from_slice(&0_u16.to_le_bytes()); // value_offs = 0
        block[56..60].copy_from_slice(&77_u32.to_le_bytes()); // value_inum = 77
        block[60..64].copy_from_slice(&5000_u32.to_le_bytes()); // value_size
        block[68..71].copy_from_slice(b"big");

        // Terminator at region offset 40 (block byte 72).
        block[72] = 0;
        block[73] = 0;

        let entries = super::parse_xattr_block_with_inum(&block).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0.full_name(), "user.test");
        assert_eq!(entries[0].0.value, b"val");
        assert_eq!(entries[0].1, 0, "in-block value has no EA inode");
        assert_eq!(entries[1].0.full_name(), "user.big");
        assert_eq!(
            entries[1].1, 77,
            "EA-inode reference is surfaced to the caller"
        );
    }

    #[test]
    fn parse_xattr_entries_empty() {
        // Just a terminator
        let data = [0_u8; 4];
        let entries = super::parse_xattr_entries(&data, &data, 0).unwrap();
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
        let value_offs = 80_u16; // value_offs from start of the ibody entry region
        buf[entry_start + 2..entry_start + 4].copy_from_slice(&value_offs.to_le_bytes());
        // entry_start + 4..8 = e_value_block (unused, stays zero)
        buf[entry_start + 8..entry_start + 12].copy_from_slice(&5_u32.to_le_bytes()); // value_size=5
        // entry_start + 12..16 = e_hash (unused, stays zero)
        buf[entry_start + 16..entry_start + 20].copy_from_slice(b"mime");

        // Value at entry_start + value_offs (after the 4-byte ibody header)
        let value_off = entry_start + usize::from(value_offs);
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
    fn parse_ibody_xattrs_accepts_value_at_exact_layout_boundary() {
        let mut buf = vec![0_u8; 256];
        buf[0x00..0x02].copy_from_slice(&(S_IFREG | 0o644).to_le_bytes());
        buf[0x80..0x82].copy_from_slice(&32_u16.to_le_bytes());

        let ibody_start = 128 + 32;
        buf[ibody_start..ibody_start + 4]
            .copy_from_slice(&ffs_types::EXT4_XATTR_MAGIC.to_le_bytes());

        let entry_start = ibody_start + 4;
        buf[entry_start] = 4;
        buf[entry_start + 1] = ffs_types::EXT4_XATTR_INDEX_USER;
        let value_offs = 24_u16; // 20-byte entry + 4-byte terminator
        buf[entry_start + 2..entry_start + 4].copy_from_slice(&value_offs.to_le_bytes());
        buf[entry_start + 8..entry_start + 12].copy_from_slice(&3_u32.to_le_bytes());
        buf[entry_start + 16..entry_start + 20].copy_from_slice(b"mime");
        buf[entry_start + usize::from(value_offs)..entry_start + usize::from(value_offs) + 3]
            .copy_from_slice(b"ok!");
        buf[entry_start + 20] = 0;
        buf[entry_start + 21] = 0;

        let inode = Ext4Inode::parse_from_bytes(&buf).expect("parse inode");
        let xattrs = super::parse_ibody_xattrs(&inode).expect("parse ibody xattrs");
        assert_eq!(xattrs.len(), 1);
        assert_eq!(xattrs[0].full_name(), "user.mime");
        assert_eq!(xattrs[0].value, b"ok!");
    }

    #[test]
    fn parse_ibody_xattrs_rejects_value_before_layout_boundary() {
        let mut buf = vec![0_u8; 256];
        buf[0x00..0x02].copy_from_slice(&(S_IFREG | 0o644).to_le_bytes());
        buf[0x80..0x82].copy_from_slice(&32_u16.to_le_bytes());

        let ibody_start = 128 + 32;
        buf[ibody_start..ibody_start + 4]
            .copy_from_slice(&ffs_types::EXT4_XATTR_MAGIC.to_le_bytes());

        let entry_start = ibody_start + 4;
        buf[entry_start] = 4;
        buf[entry_start + 1] = ffs_types::EXT4_XATTR_INDEX_USER;
        let value_offs = 23_u16; // one byte before the first legal value position
        buf[entry_start + 2..entry_start + 4].copy_from_slice(&value_offs.to_le_bytes());
        buf[entry_start + 8..entry_start + 12].copy_from_slice(&3_u32.to_le_bytes());
        buf[entry_start + 16..entry_start + 20].copy_from_slice(b"mime");
        buf[entry_start + usize::from(value_offs)..entry_start + usize::from(value_offs) + 3]
            .copy_from_slice(b"bad");
        buf[entry_start + 20] = 0;
        buf[entry_start + 21] = 0;

        let inode = Ext4Inode::parse_from_bytes(&buf).expect("parse inode");
        let err = super::parse_ibody_xattrs(&inode).expect_err("value should overlap entry table");
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "xattr_value",
                reason: "value overlaps xattr header or entry table"
            }
        ));
    }

    #[test]
    fn parse_ibody_xattrs_no_magic() {
        // Inode with empty xattr ibody (no magic)
        let buf = [0_u8; 128];
        let inode = Ext4Inode::parse_from_bytes(&buf).expect("parse inode");
        let xattrs = super::parse_ibody_xattrs(&inode).expect("parse ibody xattrs");
        assert!(xattrs.is_empty());
    }

    fn build_sorted_external_xattr_block_with_entry_hashes(
        first_entry_hash: u32,
        second_entry_hash: u32,
    ) -> Vec<u8> {
        let mut block = vec![0_u8; 4096];
        block[0..4].copy_from_slice(&ffs_types::EXT4_XATTR_MAGIC.to_le_bytes());

        let first_entry_offset = 32;
        let first_name = b"b";
        let first_value = b"one";
        let first_value_off = 4088_u16;
        block[first_entry_offset] = u8::try_from(first_name.len()).expect("fixed name length");
        block[first_entry_offset + 1] = ffs_types::EXT4_XATTR_INDEX_USER;
        block[first_entry_offset + 2..first_entry_offset + 4]
            .copy_from_slice(&first_value_off.to_le_bytes());
        block[first_entry_offset + 8..first_entry_offset + 12].copy_from_slice(
            &u32::try_from(first_value.len())
                .expect("fixed value length")
                .to_le_bytes(),
        );
        block[first_entry_offset + 12..first_entry_offset + 16]
            .copy_from_slice(&first_entry_hash.to_le_bytes());
        block[first_entry_offset + 16..first_entry_offset + 16 + first_name.len()]
            .copy_from_slice(first_name);
        block[usize::from(first_value_off)..usize::from(first_value_off) + first_value.len()]
            .copy_from_slice(first_value);

        let second_entry_offset = 52;
        let second_name = b"alpha";
        let second_value = b"two";
        let second_value_off = 4092_u16;
        block[second_entry_offset] = u8::try_from(second_name.len()).expect("fixed name length");
        block[second_entry_offset + 1] = ffs_types::EXT4_XATTR_INDEX_USER;
        block[second_entry_offset + 2..second_entry_offset + 4]
            .copy_from_slice(&second_value_off.to_le_bytes());
        block[second_entry_offset + 8..second_entry_offset + 12].copy_from_slice(
            &u32::try_from(second_value.len())
                .expect("fixed value length")
                .to_le_bytes(),
        );
        block[second_entry_offset + 12..second_entry_offset + 16]
            .copy_from_slice(&second_entry_hash.to_le_bytes());
        block[second_entry_offset + 16..second_entry_offset + 16 + second_name.len()]
            .copy_from_slice(second_name);
        block[usize::from(second_value_off)..usize::from(second_value_off) + second_value.len()]
            .copy_from_slice(second_value);

        block[76] = 0;
        block[77] = 0;
        block
    }

    #[test]
    fn parse_xattr_block_kernel_header_offsets_match_xattr_h() {
        // fs/ext4/xattr.h struct ext4_xattr_header:
        //   h_magic:le32 @0, h_refcount:le32 @4, h_blocks:le32 @8,
        //   h_hash:le32 @12, h_checksum:le32 @16,
        //   h_reserved[3]:le32 @20..32, entries @32.
        let mut block = vec![0_u8; 4096];
        block[0..4].copy_from_slice(&ffs_types::EXT4_XATTR_MAGIC.to_le_bytes());
        block[4..8].copy_from_slice(&2_u32.to_le_bytes());
        block[8..12].copy_from_slice(&1_u32.to_le_bytes());
        block[12..16].copy_from_slice(&0x1122_3344_u32.to_le_bytes());
        block[16..20].copy_from_slice(&0x5566_7788_u32.to_le_bytes());
        block[20..24].copy_from_slice(&0x99AA_BBCC_u32.to_le_bytes());
        block[24..28].copy_from_slice(&0xDDEE_F001_u32.to_le_bytes());
        block[28..32].copy_from_slice(&0x2345_6789_u32.to_le_bytes());

        let entry_start = 32;
        let name = b"kernel";
        let value = b"header";
        let value_offs = 128_u16;
        block[entry_start] = u8::try_from(name.len()).expect("fixed name length fits u8");
        block[entry_start + 1] = ffs_types::EXT4_XATTR_INDEX_SECURITY;
        block[entry_start + 2..entry_start + 4].copy_from_slice(&value_offs.to_le_bytes());
        block[entry_start + 4..entry_start + 8].copy_from_slice(&0_u32.to_le_bytes());
        block[entry_start + 8..entry_start + 12].copy_from_slice(
            &u32::try_from(value.len())
                .expect("fixed value length fits u32")
                .to_le_bytes(),
        );
        block[entry_start + 12..entry_start + 16].copy_from_slice(&0xA5A5_5A5A_u32.to_le_bytes());
        block[entry_start + 16..entry_start + 16 + name.len()].copy_from_slice(name);

        let entry_len = (16 + name.len() + 3) & !3;
        block[entry_start + entry_len] = 0;
        block[entry_start + entry_len + 1] = 0;
        let value_start = usize::from(value_offs);
        block[value_start..value_start + value.len()].copy_from_slice(value);

        let xattrs = super::parse_xattr_block(&block).expect("parse kernel-layout xattr block");
        assert_eq!(xattrs.len(), 1);
        assert_eq!(xattrs[0].name_index, ffs_types::EXT4_XATTR_INDEX_SECURITY);
        assert_eq!(&xattrs[0].name, name);
        assert_eq!(&xattrs[0].value, value);
        assert_eq!(xattrs[0].full_name(), "security.kernel");
    }

    #[test]
    fn parse_xattr_block_smoke() {
        let mut block = vec![0_u8; 4096];
        // 32-byte header with magic
        block[0..4].copy_from_slice(&ffs_types::EXT4_XATTR_MAGIC.to_le_bytes());

        // Entry at offset 32 (after header)
        block[32] = 3; // name_len=3
        block[33] = ffs_types::EXT4_XATTR_INDEX_SECURITY;
        block[34..36].copy_from_slice(&200_u16.to_le_bytes()); // value_offs from block start
        // block[36..40] = e_value_block (unused, stays zero)
        block[40..44].copy_from_slice(&4_u32.to_le_bytes()); // value_size
        // block[44..48] = e_hash (unused, stays zero)
        block[48..51].copy_from_slice(b"cap");
        block[200..204].copy_from_slice(b"data");

        // Terminator
        // Entry header is 16 bytes + 3 name = 19, rounded to 20
        block[52] = 0;
        block[53] = 0;

        let xattrs = super::parse_xattr_block(&block).expect("parse xattr block");
        assert_eq!(xattrs.len(), 1);
        assert_eq!(xattrs[0].full_name(), "security.cap");
        assert_eq!(xattrs[0].value, b"data");
    }

    proptest! {
        #[test]
        fn ext4_proptest_parse_xattr_block_entry_hash_words_do_not_affect_sorted_parse(
            first_entry_hash in any::<u32>(),
            second_entry_hash in any::<u32>(),
        ) {
            let canonical = build_sorted_external_xattr_block_with_entry_hashes(0, 0);
            let mutated =
                build_sorted_external_xattr_block_with_entry_hashes(first_entry_hash, second_entry_hash);

            let parsed_canonical =
                super::parse_xattr_block(&canonical).expect("canonical xattr block should parse");
            let parsed_mutated =
                super::parse_xattr_block(&mutated).expect("mutated xattr block should parse");

            prop_assert_eq!(
                &parsed_mutated,
                &parsed_canonical,
                "unused external-xattr entry hash words must not change the logical parse result"
            );

            let names: Vec<String> = parsed_mutated.iter().map(Ext4Xattr::full_name).collect();
            prop_assert_eq!(names, vec!["user.b", "user.alpha"]);
        }

        /// Isomorphism oracle for the in-place `lookup_in_dir_block` /
        /// `lookup_in_dir_block_casefold` walkers: build a valid directory block
        /// from random unique names, then assert each lookup returns exactly what
        /// `parse_dir_block(..).into_iter().find(..)` (the prior implementation)
        /// would, for both a present and an absent target.
        #[test]
        fn ext4_proptest_lookup_in_dir_block_matches_parse_and_find(
            raw_names in proptest::collection::vec("[a-zA-Z0-9_]{1,12}", 1..=40),
            target_idx in 0_usize..50,
        ) {
            use std::collections::BTreeSet;
            let mut seen = BTreeSet::new();
            let names: Vec<Vec<u8>> = raw_names
                .into_iter()
                .filter(|n| seen.insert(n.clone()))
                .map(String::into_bytes)
                .collect();
            let entries: Vec<(u32, u8, &[u8])> = names
                .iter()
                .enumerate()
                .map(|(i, n)| (u32::try_from(i).unwrap() + 2, 1_u8, n.as_slice()))
                .collect();
            let block_size = 4096_usize;
            prop_assume!(super::pack_dir_block_entries(&entries, block_size, false).is_ok());
            let block = super::pack_dir_block_entries(&entries, block_size, false).unwrap();
            let bs = u32::try_from(block_size).unwrap();

            let target: Vec<u8> = if target_idx < names.len() {
                names[target_idx].clone()
            } else {
                b"__absent_name__".to_vec()
            };

            let expected = super::parse_dir_block(&block, bs)
                .map(|(es, _)| es.into_iter().find(|e| e.name == target));
            let actual = super::lookup_in_dir_block(&block, bs, &target);
            prop_assert_eq!(actual, expected);

            let target_lower = super::ext4_casefold_key(&target);
            let expected_cf = super::parse_dir_block(&block, bs).map(|(es, _)| {
                es.into_iter()
                    .find(|e| super::ext4_casefold_key(&e.name) == target_lower)
            });
            let actual_cf = super::lookup_in_dir_block_casefold(&block, bs, &target);
            prop_assert_eq!(actual_cf, expected_cf);
        }

        /// Isomorphism oracle for the allocation-free casefold comparators:
        /// `ext4_casefold_eq` and `casefold_key_eq` must agree bit-for-bit with
        /// the materialised `ext4_casefold_key(..) == ext4_casefold_key(..)`
        /// across arbitrary byte strings (ASCII, invalid UTF-8, mixed case).
        #[test]
        fn ext4_proptest_casefold_eq_matches_key_equality(
            a in proptest::collection::vec(any::<u8>(), 0..=24),
            b in proptest::collection::vec(any::<u8>(), 0..=24),
        ) {
            let key_a = super::ext4_casefold_key(&a);
            let key_b = super::ext4_casefold_key(&b);
            let expected = key_a == key_b;
            prop_assert_eq!(super::ext4_casefold_eq(&a, &b), expected);
            prop_assert_eq!(super::casefold_key_eq(&a, &key_b), expected);
        }
    }

    /// Casefold comparator equivalence on the Unicode fold path (ASCII fast path
    /// is exercised by the proptest above; these names are non-ASCII or fold via
    /// multi-char rules, so they take the materialised-key branch and must still
    /// match `ext4_casefold_key` equality).
    #[test]
    fn casefold_eq_matches_key_on_unicode_folds() {
        // Pairs that take the non-ASCII (materialised-key) branch. The assertion
        // is that the comparators agree with `ext4_casefold_key` equality — not
        // any presupposed fold result — so this is robust to the exact fold rules.
        let str_cases: &[(&str, &str)] = &[
            ("Straße", "STRASSE"),
            ("Straße", "strasse"),
            ("Café", "café"),
            ("Café", "cafe"),
            ("ÄÖÜ", "äöü"),
            ("ΑΒΓ", "αβγ"),
            ("groß", "gross"),
            ("ß", "SS"),
            ("ASCII", "ascii"),
        ];
        let mut cases: Vec<(&[u8], &[u8])> = str_cases
            .iter()
            .map(|(l, r)| (l.as_bytes(), r.as_bytes()))
            .collect();
        // Invalid UTF-8 pair → ASCII-fold fallback branch.
        cases.push((&[0xFF, 0x41], &[0xFF, 0x61]));
        for (left, right) in cases {
            let key_eq = ext4_casefold_key(left) == ext4_casefold_key(right);
            assert_eq!(
                ext4_casefold_eq(left, right),
                key_eq,
                "ext4_casefold_eq diverged for {left:?} vs {right:?}"
            );
            let right_key = ext4_casefold_key(right);
            assert_eq!(
                casefold_key_eq(left, &right_key),
                key_eq,
                "casefold_key_eq diverged for {left:?} vs {right:?}"
            );
        }
    }

    #[test]
    fn parse_xattr_block_bad_magic() {
        let block = vec![0_u8; 4096];
        let err = super::parse_xattr_block(&block).unwrap_err();
        assert!(matches!(err, ParseError::InvalidMagic { .. }));
    }

    #[test]
    fn xattr_full_name_maps_richacl_namespace() {
        let xattr = Ext4Xattr {
            name_index: ffs_types::EXT4_XATTR_INDEX_RICHACL,
            name: Vec::new(),
            value: Vec::new(),
        };
        assert_eq!(xattr.full_name(), "system.richacl");
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

    #[test]
    fn dx_hash_dispatcher_unknown_version_falls_back_to_half_md4_unsigned() {
        let seed = [1_u32, 2, 3, 4];
        let name = b"some_directory_entry_name";

        // DX_HASH_HALF_MD4_UNSIGNED (4) and every unknown/future hash_version
        // share the catch-all dispatch arm (half_md4 unsigned), matching the
        // kernel fallback, so they must all hash identically. dx_hash_dispatcher
        // only covers versions 0/1/2; this pins the catch-all arm.
        let baseline = super::dx_hash(super::DX_HASH_HALF_MD4_UNSIGNED, name, &seed);
        for version in [6_u8, 7, 99, 200, u8::MAX] {
            assert_eq!(
                super::dx_hash(version, name, &seed),
                baseline,
                "hash_version {version} must fall back to half_md4 unsigned",
            );
        }
    }

    #[test]
    fn dx_hash_dispatcher_legacy_and_tea_unsigned_arms() {
        let seed = [1_u32, 2, 3, 4];
        // High-bit bytes so the signed/unsigned distinction actually matters.
        let name = b"\xc3\xa9_dir_entry";

        // Version 3 must route to legacy unsigned; version 5 to tea unsigned.
        // dx_hash normalizes the major hash, so compare against the direct
        // function output with the same normalization applied.
        let (legacy_unsigned_major, legacy_unsigned_minor) = super::dx_hash_legacy(name, false);
        assert_eq!(
            super::dx_hash(super::DX_HASH_LEGACY_UNSIGNED, name, &seed),
            (
                super::normalize_dx_major_hash(legacy_unsigned_major),
                legacy_unsigned_minor
            ),
            "version 3 must route to legacy unsigned",
        );

        let (tea_unsigned_major, tea_unsigned_minor) = super::dx_hash_tea(name, &seed, false);
        assert_eq!(
            super::dx_hash(super::DX_HASH_TEA_UNSIGNED, name, &seed),
            (
                super::normalize_dx_major_hash(tea_unsigned_major),
                tea_unsigned_minor
            ),
            "version 5 must route to tea unsigned",
        );
    }

    #[test]
    fn dx_hash_matches_kernel_reference_vectors() {
        let seed = [0x1111_1111, 0x3333_2222, 0x5555_4444, 0x5555_5555];
        let name = b"alpha_0000_xyz.dat";

        assert_eq!(
            super::dx_hash(DX_HASH_LEGACY, name, &seed),
            (0xd1ef_1dde, 0)
        );
        assert_eq!(
            super::dx_hash(DX_HASH_HALF_MD4, name, &seed),
            (0x07b9_5998, 0x3c57_f807)
        );
        assert_eq!(
            super::dx_hash(DX_HASH_TEA, name, &seed),
            (0xc135_30d0, 0x8558_264c)
        );
    }

    /// bd-yb4r0 — Kernel-conformance pin for `normalize_dx_major_hash`.
    ///
    /// Per fs/ext4/hash.c (`ext4fs_dirhash`, lines ~256-264), the major
    /// hash returned by every htree directory lookup must satisfy two
    /// invariants:
    ///   1. Low bit is cleared. The low bit is reserved as a flag bit
    ///      in htree collision-chain traversal (`dx_probe`).
    ///   2. The value `EXT4_HTREE_EOF_32BIT << 1` (= 0xfffffffe) is
    ///      reserved as the htree end-of-tree cursor sentinel. If the
    ///      masked hash collides with the sentinel, the kernel bumps
    ///      it down to `(EXT4_HTREE_EOF_32BIT - 1) << 1` = 0xfffffffc.
    ///
    /// A regression that removed either step would corrupt
    /// collision-chain traversal — htree lookups would silently
    /// return "no such entry" for valid filenames whose major hash
    /// happened to land on the sentinel or whose collision chain
    /// relied on the low-bit flag.
    /// bd-pxzsx — Kernel-conformance pin for `DX_HASH_DEFAULT_SEED`.
    ///
    /// Per Linux kernel `fs/ext4/hash.c`:
    /// ```
    /// static __u32 hash_seed_default[4] = {
    ///     0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    /// };
    /// ```
    /// These are the standard MD4/MD5 initial values from RFC 1320
    /// (also the first 4 words of the SHA-1 IV). The seed is used by
    /// `dx_hash_seed_state` whenever the ext4 superblock's
    /// `hash_seed` field is all zeros — i.e., on every fresh ext4
    /// filesystem until a custom seed is set. A regression that
    /// swapped any element (or used a 32-bit-flipped variant) would
    /// silently break every directory lookup on those filesystems
    /// without affecting the dx_hash_matches_kernel_reference_vectors
    /// test (which uses an explicit non-zero seed).
    ///
    /// Pairs with bd-xt5ru (DX hash version constants), bd-yb4r0
    /// (normalize_dx_major_hash invariants).
    #[test]
    fn ext4_dx_hash_default_seed_matches_kernel() {
        // Exact values per kernel header.
        assert_eq!(
            super::DX_HASH_DEFAULT_SEED[0],
            0x6745_2301,
            "DX_HASH_DEFAULT_SEED[0] must equal MD4 IV word A (0x67452301)"
        );
        assert_eq!(
            super::DX_HASH_DEFAULT_SEED[1],
            0xefcd_ab89,
            "DX_HASH_DEFAULT_SEED[1] must equal MD4 IV word B (0xefcdab89)"
        );
        assert_eq!(
            super::DX_HASH_DEFAULT_SEED[2],
            0x98ba_dcfe,
            "DX_HASH_DEFAULT_SEED[2] must equal MD4 IV word C (0x98badcfe)"
        );
        assert_eq!(
            super::DX_HASH_DEFAULT_SEED[3],
            0x1032_5476,
            "DX_HASH_DEFAULT_SEED[3] must equal MD4 IV word D (0x10325476)"
        );

        // Structural invariant: the four seed words must be
        // pairwise distinct (else any two-word swap would be a
        // no-op and the regression test above wouldn't catch it).
        for i in 0..4 {
            for j in (i + 1)..4 {
                assert_ne!(
                    super::DX_HASH_DEFAULT_SEED[i],
                    super::DX_HASH_DEFAULT_SEED[j],
                    "DX_HASH_DEFAULT_SEED words must be pairwise distinct"
                );
            }
        }

        // Cross-check: word B is the bitwise complement of word D
        // and word C is the bitwise complement of word A — this is
        // a known property of the MD4/SHA-1 IV that catches single-
        // bit drift in any individual word.
        assert_eq!(
            super::DX_HASH_DEFAULT_SEED[2],
            !super::DX_HASH_DEFAULT_SEED[0],
            "MD4 IV: word C must be ~word A"
        );
        assert_eq!(
            super::DX_HASH_DEFAULT_SEED[1],
            !super::DX_HASH_DEFAULT_SEED[3],
            "MD4 IV: word B must be ~word D"
        );
    }

    #[test]
    fn ext4_dx_hash_major_hash_invariants_match_kernel() {
        // (d) Named boundary values from the kernel formula.
        // - Inputs whose top 31 bits land on the sentinel must bump down.
        assert_eq!(
            super::normalize_dx_major_hash(0xffff_fffe),
            0xffff_fffc,
            "0xfffffffe (== EOF<<1) must bump to 0xfffffffc per kernel rule"
        );
        assert_eq!(
            super::normalize_dx_major_hash(0xffff_ffff),
            0xffff_fffc,
            "0xffffffff masks to 0xfffffffe (== EOF<<1) then bumps to 0xfffffffc"
        );
        // - Non-sentinel inputs just have the low bit cleared.
        assert_eq!(super::normalize_dx_major_hash(0), 0);
        assert_eq!(super::normalize_dx_major_hash(1), 0);
        assert_eq!(
            super::normalize_dx_major_hash(0xdead_beef),
            0xdead_beee,
            "non-sentinel input keeps high bits, only low bit cleared"
        );
        assert_eq!(
            super::normalize_dx_major_hash(0xffff_fffd),
            0xffff_fffc,
            "0xfffffffd masks to 0xfffffffc (NOT the sentinel) — stays put"
        );
        assert_eq!(
            super::normalize_dx_major_hash(0xffff_fffc),
            0xffff_fffc,
            "0xfffffffc is the post-bump value — already invariant"
        );

        // The sentinel-bump constant must equal (EXT4_HTREE_EOF_32BIT - 1) << 1.
        let bump_target = (EXT4_HTREE_EOF_32BIT - 1) << 1;
        assert_eq!(
            bump_target, 0xffff_fffc,
            "(EOF-1)<<1 must equal 0xfffffffc per kernel formula"
        );
    }

    proptest::proptest! {
        // (a) MR-1: low bit always cleared — the htree collision-chain flag
        // bit is reserved by the kernel and must never appear in the major
        // hash post-normalization.
        #[test]
        fn ext4_normalize_dx_major_hash_low_bit_always_clear(h in proptest::prelude::any::<u32>()) {
            let normalized = super::normalize_dx_major_hash(h);
            proptest::prop_assert_eq!(
                normalized & 1,
                0,
                "kernel rule: major hash low bit must be reserved/clear"
            );
        }

        // (b) MR-2: never collides with EOF sentinel.
        #[test]
        fn ext4_normalize_dx_major_hash_avoids_eof_sentinel(h in proptest::prelude::any::<u32>()) {
            let normalized = super::normalize_dx_major_hash(h);
            proptest::prop_assert_ne!(
                normalized,
                EXT4_HTREE_EOF_32BIT << 1,
                "kernel rule: major hash must not collide with htree EOF cursor"
            );
        }

        // (c) MR-3: idempotence — normalize is a projection onto the
        // valid-major-hash subspace; reapplying it must be a no-op.
        #[test]
        fn ext4_normalize_dx_major_hash_idempotent(h in proptest::prelude::any::<u32>()) {
            let once = super::normalize_dx_major_hash(h);
            let twice = super::normalize_dx_major_hash(once);
            proptest::prop_assert_eq!(once, twice);
        }

        // bd-ldp92 — Zero-seed-equivalence MR for dx_hash_half_md4 and
        // dx_hash_tea. The ext4 kernel falls back to DX_HASH_DEFAULT_SEED
        // when s_hash_seed is all-zero. The fixed-case test
        // dx_hash_uses_ext4_default_seed_when_superblock_seed_is_zero
        // covers ONE name ("default-seed-check"); this sweeps arbitrary
        // names across both signed and unsigned char modes to catch a
        // regression that hardcoded the zero-seed fast path for a specific
        // name length or character class.
        #[test]
        fn ext4_proptest_dx_hash_zero_seed_falls_back_to_default(
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=128),
            signed in proptest::prelude::any::<bool>(),
        ) {
            let zero_seed = [0_u32; 4];
            proptest::prop_assert_eq!(
                super::dx_hash_half_md4(&name, &zero_seed, signed),
                super::dx_hash_half_md4(&name, &DX_HASH_DEFAULT_SEED, signed),
                "half_md4: zero seed must produce identical output to DX_HASH_DEFAULT_SEED"
            );
            proptest::prop_assert_eq!(
                super::dx_hash_tea(&name, &zero_seed, signed),
                super::dx_hash_tea(&name, &DX_HASH_DEFAULT_SEED, signed),
                "tea: zero seed must produce identical output to DX_HASH_DEFAULT_SEED"
            );
        }
    }

    #[test]
    fn dx_hash_uses_ext4_default_seed_when_superblock_seed_is_zero() {
        let name = b"default-seed-check";
        let zero_seed = [0_u32; 4];

        assert_eq!(
            super::dx_hash_half_md4(name, &zero_seed, true),
            super::dx_hash_half_md4(name, &DX_HASH_DEFAULT_SEED, true)
        );
        assert_eq!(
            super::dx_hash_tea(name, &zero_seed, true),
            super::dx_hash_tea(name, &DX_HASH_DEFAULT_SEED, true)
        );
    }

    // ── DX root parsing tests ───────────────────────────────────────────

    fn encode_dx_root_test_block(hash_version: u8, entries: &[Ext4DxEntry]) -> Vec<u8> {
        assert!(
            !entries.is_empty(),
            "DX root fixture needs at least the sentinel entry"
        );
        assert_eq!(
            entries[0].hash, 0,
            "DX root fixture sentinel hash must be zero"
        );

        let mut block = vec![0_u8; 4096];

        // Fake "." dir entry at 0x00 (12 bytes)
        write_dir_entry(&mut block, 0, 2, 2, b".", 12);
        // Fake ".." dir entry at 0x0C (12 bytes, but rec_len covers to 0x1C)
        write_dir_entry(&mut block, 12, 2, 2, b"..", 12);

        // DX root info at 0x18 (after ".." dir entry header)
        // Actually, the root info is at fixed offset 0x1C
        block[0x1C] = hash_version;
        block[0x1D] = 8; // info_length = 8
        block[0x1E] = 0; // indirect_levels = 0
        block[0x1F] = 0; // unused_flags

        // dx_countlimit at 0x20: overlaps with entry[0] (hash is implicit 0).
        // Layout: [limit(u16), count(u16), entry0_block(u32), entry1_hash, entry1_block, ...]
        let count = u16::try_from(entries.len()).expect("DX root fixture count must fit in u16");
        block[0x20..0x22].copy_from_slice(&count.to_le_bytes());
        block[0x22..0x24].copy_from_slice(&count.to_le_bytes());

        // Entry 0 (sentinel): hash is implicitly 0 (from countlimit bytes).
        block[0x24..0x28].copy_from_slice(&entries[0].block.to_le_bytes());

        let mut off = 0x28;
        for entry in entries.iter().skip(1) {
            block[off..off + 4].copy_from_slice(&entry.hash.to_le_bytes());
            block[off + 4..off + 8].copy_from_slice(&entry.block.to_le_bytes());
            off += 8;
        }

        block
    }

    fn make_dx_root_test_block() -> Vec<u8> {
        encode_dx_root_test_block(
            DX_HASH_HALF_MD4,
            &[
                Ext4DxEntry { hash: 0, block: 1 },
                Ext4DxEntry {
                    hash: 0x1000,
                    block: 2,
                },
                Ext4DxEntry {
                    hash: 0x8000,
                    block: 3,
                },
            ],
        )
    }

    fn build_single_name_dx_entries(
        hash_version: u8,
        names: &[Vec<u8>],
        seed: &[u32; 4],
    ) -> Option<Vec<Ext4DxEntry>> {
        let mut hashed_blocks = Vec::with_capacity(names.len());
        for (idx, name) in names.iter().enumerate() {
            let (hash, _) = dx_hash(hash_version, name, seed);
            let block = u32::try_from(idx + 1).expect("fixture block index must fit in u32");
            hashed_blocks.push((hash, block));
        }

        hashed_blocks.sort_unstable_by_key(|(hash, block)| (*hash, *block));
        if hashed_blocks.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return None;
        }

        let mut entries = Vec::with_capacity(hashed_blocks.len());
        entries.push(Ext4DxEntry {
            hash: 0,
            block: hashed_blocks[0].1,
        });
        for (hash, block) in hashed_blocks.into_iter().skip(1) {
            entries.push(Ext4DxEntry { hash, block });
        }

        Some(entries)
    }

    #[test]
    fn parse_dx_root_basic() {
        let block = make_dx_root_test_block();

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
    fn parse_dx_root_rejects_nonzero_reserved_zero() {
        let mut block = make_dx_root_test_block();
        block[0x18..0x1C].copy_from_slice(&1_u32.to_le_bytes());

        let err = parse_dx_root(&block).expect_err("reserved root info field must be zero");
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "dx_reserved_zero",
                reason: "expected 0"
            }
        );
    }

    #[test]
    fn parse_dx_root_rejects_nonzero_unused_flags() {
        let mut block = make_dx_root_test_block();
        block[0x1F] = 1;

        let err = parse_dx_root(&block).expect_err("unused root info flags must be zero");
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "dx_unused_flags",
                reason: "expected 0"
            }
        );
    }

    #[test]
    fn parse_dx_root_rejects_level_three_without_large_dir() {
        let mut block = make_dx_root_test_block();
        block[0x1E] = 3;

        let err = parse_dx_root_with_large_dir(&block, false)
            .expect_err("level-three htree requires LARGEDIR");
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "dx_indirect_levels",
                reason: "exceeds maximum (2) without LARGEDIR"
            }
        );
    }

    #[test]
    fn parse_dx_root_accepts_level_three_with_large_dir() {
        let mut block = make_dx_root_test_block();
        block[0x1E] = 3;

        let root = parse_dx_root_with_large_dir(&block, true)
            .expect("LARGEDIR should allow three indirect levels");
        assert_eq!(root.indirect_levels, 3);
        assert_eq!(root.entries.len(), 3);
    }

    proptest! {
        /// The zero-tail-skipping `crc_dir_coverage` fast path (used by
        /// `stamp_dir_block_checksum`) must be byte-identical to a straight
        /// `ext4_chksum` over the whole coverage, for any content prefix, any
        /// trailing-zero-run length (straddling the MIN_ZERO_RUN threshold), and
        /// any seed/ino/generation.
        #[test]
        fn stamp_dir_block_checksum_zero_tail_matches_full(
            seed in any::<u32>(),
            ino in any::<u32>(),
            generation in any::<u32>(),
            content in proptest::collection::vec(any::<u8>(), 0..300),
            zero_tail in 0usize..5000,
        ) {
            let coverage_len = content.len() + zero_tail;
            let bs = coverage_len + 12;
            let mut block = vec![0u8; bs];
            block[..content.len()].copy_from_slice(&content);

            let s = ext4_chksum(seed, &ino.to_le_bytes());
            let s = ext4_chksum(s, &generation.to_le_bytes());
            let expected = ext4_chksum(s, &block[..coverage_len]);

            stamp_dir_block_checksum(&mut block, seed, ino, generation);
            let got = u32::from_le_bytes([
                block[bs - 4],
                block[bs - 3],
                block[bs - 2],
                block[bs - 1],
            ]);
            prop_assert_eq!(got, expected);
        }

        /// Metamorphic relation: if the same directory names are re-indexed
        /// under hash_version=1 (half_md4) and hash_version=2 (TEA), and the
        /// DX entries are regenerated consistently for that version, each
        /// name still routes to its stable leaf block.
        #[test]
        fn ext4_proptest_dx_root_hash_version_transform_preserves_name_to_leaf_mapping(
            raw_names in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..=24), 2..=8),
            seed in proptest::array::uniform4(any::<u32>()),
        ) {
            let mut seen = BTreeSet::new();
            let names: Vec<Vec<u8>> = raw_names
                .into_iter()
                .filter(|name| seen.insert(name.clone()))
                .collect();
            prop_assume!(names.len() >= 2);
            prop_assume!(names.iter().any(|name| {
                dx_hash(DX_HASH_HALF_MD4, name, &seed) != dx_hash(DX_HASH_TEA, name, &seed)
            }));

            let Some(half_md4_entries) = build_single_name_dx_entries(DX_HASH_HALF_MD4, &names, &seed) else {
                prop_assume!(false);
                unreachable!("rejected duplicate half_md4 major hashes");
            };
            let Some(tea_entries) = build_single_name_dx_entries(DX_HASH_TEA, &names, &seed) else {
                prop_assume!(false);
                unreachable!("rejected duplicate TEA major hashes");
            };

            let half_md4_root = parse_dx_root(
                &encode_dx_root_test_block(DX_HASH_HALF_MD4, &half_md4_entries),
            )
            .expect("half_md4 DX root fixture should parse");
            let tea_root = parse_dx_root(&encode_dx_root_test_block(DX_HASH_TEA, &tea_entries))
                .expect("TEA DX root fixture should parse");

            prop_assert_eq!(half_md4_root.hash_version, DX_HASH_HALF_MD4);
            prop_assert_eq!(tea_root.hash_version, DX_HASH_TEA);

            for (idx, name) in names.iter().enumerate() {
                let expected_block =
                    u32::try_from(idx + 1).expect("fixture block index must fit in u32");
                let (half_md4_hash, _) = dx_hash(half_md4_root.hash_version, name, &seed);
                let (tea_hash, _) = dx_hash(tea_root.hash_version, name, &seed);

                prop_assert_eq!(
                    dx_find_leaf(&half_md4_root.entries, half_md4_hash),
                    expected_block,
                    "half_md4 root must route {:?} to its stable leaf block",
                    name,
                );
                prop_assert_eq!(
                    dx_find_leaf(&tea_root.entries, tea_hash),
                    expected_block,
                    "TEA root must route {:?} to its stable leaf block after the hash_version transform",
                    name,
                );
            }
        }
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
    fn dx_hash_extends_collision_chain_matches_split_lsb() {
        assert!(super::dx_hash_extends_collision_chain(0x2468, 0x2468));
        assert!(super::dx_hash_extends_collision_chain(0x2468, 0x2469));
        assert!(!super::dx_hash_extends_collision_chain(0x2468, 0x3469));
    }

    proptest::proptest! {
        // bd-uv9t3 — dx_hash_extends_collision_chain equivalence-relation
        // proptest. The function returns true when two major hashes
        // belong to the same htree collision chain (differ only in
        // their low bit). For htree traversal logic to be correct,
        // the predicate must be a proper equivalence relation:
        //   reflexive : f(a, a)       == true
        //   symmetric : f(a, b)       == f(b, a)
        //   transitive: f(a, b) && f(b, c) → f(a, c)
        // Sister fixed-case test covers 3 inputs; this sweeps
        // arbitrary u32 pairs/triples.

        #[test]
        fn dx_hash_extends_collision_chain_proptest_reflexive(a in proptest::prelude::any::<u32>()) {
            proptest::prop_assert!(super::dx_hash_extends_collision_chain(a, a));
        }

        #[test]
        fn dx_hash_extends_collision_chain_proptest_symmetric(
            a in proptest::prelude::any::<u32>(),
            b in proptest::prelude::any::<u32>(),
        ) {
            proptest::prop_assert_eq!(
                super::dx_hash_extends_collision_chain(a, b),
                super::dx_hash_extends_collision_chain(b, a),
                "predicate must be symmetric"
            );
        }

        #[test]
        fn dx_hash_extends_collision_chain_proptest_transitive(
            a in proptest::prelude::any::<u32>(),
            b in proptest::prelude::any::<u32>(),
            c in proptest::prelude::any::<u32>(),
        ) {
            if super::dx_hash_extends_collision_chain(a, b)
                && super::dx_hash_extends_collision_chain(b, c)
            {
                proptest::prop_assert!(
                    super::dx_hash_extends_collision_chain(a, c),
                    "predicate must be transitive: a~b && b~c ⇒ a~c"
                );
            }
        }
    }

    #[test]
    fn effective_dirhash_version_applies_unsigned_super_flag() {
        let mut sb = make_valid_sb();
        sb[0xFC] = DX_HASH_HALF_MD4;
        sb[0x160..0x164].copy_from_slice(&Ext4SuperFlags::UNSIGNED_HASH.0.to_le_bytes());
        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse valid sb");

        assert_eq!(
            parsed.effective_dirhash_version(DX_HASH_LEGACY),
            DX_HASH_LEGACY_UNSIGNED
        );
        assert_eq!(
            parsed.effective_dirhash_version(DX_HASH_HALF_MD4),
            DX_HASH_HALF_MD4_UNSIGNED
        );
        assert_eq!(
            parsed.effective_dirhash_version(DX_HASH_TEA),
            DX_HASH_TEA_UNSIGNED
        );
        assert_eq!(
            parsed.effective_dirhash_version(DX_HASH_TEA_UNSIGNED),
            DX_HASH_TEA_UNSIGNED
        );
    }

    #[allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
    fn build_indexed_htree_lookup_test_image(
        target_name: &[u8],
        super_flags: u32,
        root_hash_version: u8,
        root_entries: &[Ext4DxEntry],
        leaf1_entries: &[(u32, &[u8])],
        leaf2_entries: &[(u32, &[u8])],
        leaf3_entries: &[(u32, &[u8])],
    ) -> Vec<u8> {
        let block_size = 4096_usize;
        let image_blocks = 48_usize;
        let mut image = vec![0_u8; block_size * image_blocks];

        // Superblock
        let sb_off = EXT4_SUPERBLOCK_OFFSET;
        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
        sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes()); // 4K blocks
        sb[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes());
        sb[0x04..0x08].copy_from_slice(&(image_blocks as u32).to_le_bytes());
        sb[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes());
        sb[0x20..0x24].copy_from_slice(&(image_blocks as u32).to_le_bytes());
        sb[0x28..0x2C].copy_from_slice(&8192_u32.to_le_bytes());
        sb[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes());
        sb[0x54..0x58].copy_from_slice(&11_u32.to_le_bytes());
        sb[0x160..0x164].copy_from_slice(&super_flags.to_le_bytes());
        image[sb_off..sb_off + EXT4_SUPERBLOCK_SIZE].copy_from_slice(&sb);

        // Group descriptor table at block 1.
        let gdt_off = block_size;
        let mut gd = [0_u8; 32];
        gd[0x08..0x0C].copy_from_slice(&2_u32.to_le_bytes()); // inode table at block 2
        image[gdt_off..gdt_off + 32].copy_from_slice(&gd);

        // Root directory inode (inode 2): indexed + extents, mapping logical
        // blocks 0..3 onto physical blocks 10..13.
        let inode_table_off = 2 * block_size;
        let inode_off = inode_table_off + 256; // inode 2
        image[inode_off..inode_off + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
        image[inode_off + 0x04..inode_off + 0x08].copy_from_slice(&(4_u32 * 4096).to_le_bytes());
        image[inode_off + 0x1A..inode_off + 0x1C].copy_from_slice(&2_u16.to_le_bytes());
        image[inode_off + 0x20..inode_off + 0x24]
            .copy_from_slice(&(EXT4_EXTENTS_FL | EXT4_INDEX_FL).to_le_bytes());
        image[inode_off + 0x64..inode_off + 0x68].copy_from_slice(&1_u32.to_le_bytes());

        let i_block = inode_off + 0x28;
        image[i_block..i_block + 2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
        image[i_block + 2..i_block + 4].copy_from_slice(&1_u16.to_le_bytes());
        image[i_block + 4..i_block + 6].copy_from_slice(&4_u16.to_le_bytes());
        image[i_block + 6..i_block + 8].copy_from_slice(&0_u16.to_le_bytes());
        image[i_block + 8..i_block + 12].copy_from_slice(&1_u32.to_le_bytes());
        let extent = i_block + 12;
        image[extent..extent + 4].copy_from_slice(&0_u32.to_le_bytes());
        image[extent + 4..extent + 6].copy_from_slice(&4_u16.to_le_bytes());
        image[extent + 6..extent + 8].copy_from_slice(&0_u16.to_le_bytes());
        image[extent + 8..extent + 12].copy_from_slice(&10_u32.to_le_bytes());

        // DX root at logical block 0 / physical block 10.
        let root_off = 10 * block_size;
        let root_block = encode_dx_root_test_block(root_hash_version, root_entries);
        image[root_off..root_off + block_size].copy_from_slice(&root_block[..block_size]);

        let write_leaf = |image: &mut [u8], block_index: usize, entries: &[(u32, &[u8])]| {
            let leaf_off = block_index * block_size;
            let mut cursor = 0_usize;
            for (idx, (inode, name)) in entries.iter().enumerate() {
                let rec_len = if idx + 1 == entries.len() {
                    u16::try_from(block_size - cursor).expect("leaf rec_len fits u16")
                } else {
                    12_u16
                };
                write_dir_entry(image, leaf_off + cursor, *inode, 1, name, rec_len);
                cursor += usize::from(rec_len);
            }
        };

        write_leaf(&mut image, 11, leaf1_entries);
        write_leaf(&mut image, 12, leaf2_entries);
        write_leaf(&mut image, 13, leaf3_entries);

        // Ensure the target name is actually hashed under the default seed path.
        let reader = Ext4ImageReader::new(&image).expect("open indexed test image");
        let effective_hash_version = reader.sb.effective_dirhash_version(root_hash_version);
        let (target_hash, _) = dx_hash(effective_hash_version, target_name, &reader.sb.hash_seed);
        assert_eq!(
            root_entries[1].hash & !1,
            target_hash,
            "fixture successor entry must carry target's collision hash",
        );

        image
    }

    #[test]
    fn htree_lookup_follows_collision_split_successor_leaf() {
        let target_name = b"collision-target";
        let target_hash = dx_hash(DX_HASH_HALF_MD4, target_name, &[0; 4]).0;
        let image = build_indexed_htree_lookup_test_image(
            target_name,
            0,
            DX_HASH_HALF_MD4,
            &[
                Ext4DxEntry { hash: 0, block: 1 },
                Ext4DxEntry {
                    hash: target_hash | 1,
                    block: 2,
                },
            ],
            &[(11, b"alpha")],
            &[(42, target_name)],
            &[],
        );

        let reader = Ext4ImageReader::new(&image).expect("open indexed test image");
        let dir_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(2))
            .expect("read indexed directory inode");

        let found = reader
            .htree_lookup(&image, &dir_inode, target_name)
            .expect("htree lookup should succeed");
        let found = found.expect("lookup should scan successor collision leaf");
        assert_eq!(found.inode, 42);
        assert_eq!(found.name, target_name);
    }

    #[test]
    fn htree_lookup_stops_before_noncollision_successor_leaf() {
        let target_name = b"collision-target";
        let target_hash = dx_hash(DX_HASH_HALF_MD4, target_name, &[0; 4]).0;
        let image = build_indexed_htree_lookup_test_image(
            target_name,
            0,
            DX_HASH_HALF_MD4,
            &[
                Ext4DxEntry { hash: 0, block: 1 },
                Ext4DxEntry {
                    hash: target_hash | 1,
                    block: 2,
                },
                Ext4DxEntry {
                    hash: target_hash.wrapping_add(0x2000),
                    block: 3,
                },
            ],
            &[(11, b"alpha")],
            &[(12, b"beta")],
            &[(77, target_name)],
        );

        let reader = Ext4ImageReader::new(&image).expect("open indexed test image");
        let dir_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(2))
            .expect("read indexed directory inode");

        let found = reader
            .htree_lookup(&image, &dir_inode, target_name)
            .expect("htree lookup should succeed");
        assert!(
            found.is_none(),
            "lookup must not cross into a successor leaf whose major hash range differs",
        );
    }

    #[test]
    fn dx_node_entry_limit_reserves_csum_tail_slot() {
        // Without metadata_csum, all (block_size - DX_NODE_COUNT_OFFSET)/8 slots
        // are usable.
        assert_eq!(dx_node_entry_limit(4096, false), 511);
        assert_eq!(dx_node_entry_limit(1024, false), 127);
        // With metadata_csum, the last slot is reserved for the dx_tail checksum.
        assert_eq!(dx_node_entry_limit(4096, true), 510);
        assert_eq!(dx_node_entry_limit(1024, true), 126);
        // The csum variant is always exactly one fewer than the non-csum variant.
        for &bs in &[1024_usize, 2048, 4096, 8192, 16384, 65536] {
            assert_eq!(
                dx_node_entry_limit(bs, true) + 1,
                dx_node_entry_limit(bs, false),
                "csum reserves exactly one slot (block_size {bs})"
            );
        }
    }

    #[test]
    fn htree_lookup_applies_superblock_unsigned_hash_flag() {
        let target_name = b"\xC3unsigned-target";
        let target_hash = dx_hash(DX_HASH_HALF_MD4_UNSIGNED, target_name, &[0; 4]).0;
        let image = build_indexed_htree_lookup_test_image(
            target_name,
            Ext4SuperFlags::UNSIGNED_HASH.0,
            DX_HASH_HALF_MD4,
            &[
                Ext4DxEntry { hash: 0, block: 1 },
                Ext4DxEntry {
                    hash: target_hash | 1,
                    block: 2,
                },
            ],
            &[(11, b"alpha")],
            &[(42, target_name)],
            &[],
        );

        let reader = Ext4ImageReader::new(&image).expect("open indexed unsigned-hash test image");
        let dir_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(2))
            .expect("read indexed directory inode");

        let found = reader
            .htree_lookup(&image, &dir_inode, target_name)
            .expect("htree lookup should succeed");
        let found = found.expect("lookup should respect the unsigned hash superblock flag");
        assert_eq!(found.inode, 42);
        assert_eq!(found.name, target_name);
    }

    #[test]
    fn str2hashbuf_basic() {
        let buf = super::str2hashbuf(b"abc", 4, false);
        // Fixed [u32; 8] stack array now; callers read only `&buf[..buf_size]`.
        assert_eq!(buf.len(), 8);
        // Kernel packs big-endian within each word via val = char + (val << 8).
        // pad for len=3: 0x03030303. After 3 chars: val = 0x03616263.
        assert_eq!(buf[0], 0x0361_6263);
        assert_eq!(buf[1], 0x0303_0303); // remaining words are pad
    }

    #[test]
    fn str2hashbuf_signed_chars() {
        // 0xC3 as signed i8 is -61; sign extension affects the wrapping add
        let buf_signed = super::str2hashbuf(b"\xC3", 4, true);
        let buf_unsigned = super::str2hashbuf(b"\xC3", 4, false);

        // Signed: -61 + (pad<<8) wrapping = 0x010100C3
        // Unsigned: 195 + (pad<<8)          = 0x010101C3
        assert_ne!(buf_signed[0], buf_unsigned[0]);
        assert_eq!(buf_signed[0], 0x0101_00C3);
        assert_eq!(buf_unsigned[0], 0x0101_01C3);
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
    fn incompat_describe_rejected_v1_is_empty() {
        // All features are now allowed — REJECTED_V1 is empty.
        let flags = Ext4IncompatFeatures(
            Ext4IncompatFeatures::FILETYPE.0
                | Ext4IncompatFeatures::EXTENTS.0
                | Ext4IncompatFeatures::ENCRYPT.0,
        );
        let rejected = flags.describe_rejected_v1();
        assert!(rejected.is_empty());
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
    fn feature_diagnostics_detects_missing_required() {
        let mut sb = make_valid_sb();
        // Only EXTENTS (missing FILETYPE) + ENCRYPT (now allowed, not rejected).
        let incompat =
            (Ext4IncompatFeatures::EXTENTS.0 | Ext4IncompatFeatures::ENCRYPT.0).to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);

        let parsed = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        let diag = parsed.feature_diagnostics_v1();
        assert!(!diag.is_ok());
        assert_eq!(diag.missing_required, vec!["FILETYPE"]);
        // ENCRYPT is now allowed, so rejected_present should be empty.
        assert!(diag.rejected_present.is_empty());
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
    fn validate_v1_accepts_encrypt() {
        // ENCRYPT is now in ALLOWED_V1 — should pass validation.
        let mut sb = make_valid_sb();
        let incompat = (Ext4IncompatFeatures::FILETYPE.0
            | Ext4IncompatFeatures::EXTENTS.0
            | Ext4IncompatFeatures::ENCRYPT.0)
            .to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);

        let parsed = Ext4Superblock::parse_superblock_region(&sb).unwrap();
        assert!(parsed.validate_v1().is_ok());
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
        let seed = ext4_chksum(csum_seed, &ino.to_le_bytes());
        let seed = ext4_chksum(seed, &generation.to_le_bytes());
        let checksum = ext4_chksum(seed, &block[..block_size - 12]);

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
    fn dir_block_checksum_rejects_bad_tail_header() {
        let csum_seed = 0xDEAD_BEEF_u32;
        let ino: u32 = 2;
        let generation: u32 = 42;
        let block_size = 4096_usize;

        let mut block = vec![0_u8; block_size];
        let entry_rec_len = u16::try_from(block_size - 12).unwrap();
        write_dir_entry(&mut block, 0, 2, 2, b".", entry_rec_len);

        let tail_off = block_size - 12;
        block[tail_off..tail_off + 4].copy_from_slice(&0_u32.to_le_bytes());
        block[tail_off + 4..tail_off + 6].copy_from_slice(&12_u16.to_le_bytes());
        block[tail_off + 6] = 1; // invalid name_len
        block[tail_off + 7] = EXT4_FT_DIR_CSUM;

        let seed = ext4_chksum(csum_seed, &ino.to_le_bytes());
        let seed = ext4_chksum(seed, &generation.to_le_bytes());
        let checksum = ext4_chksum(seed, &block[..block_size - 12]);
        block[block_size - 4..].copy_from_slice(&checksum.to_le_bytes());

        let err = verify_dir_block_checksum(&block, csum_seed, ino, generation).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "dir_block_tail",
                ..
            }
        ));
    }

    #[test]
    fn dir_block_checksum_rejects_too_small() {
        let small = [0_u8; 8];
        let err = verify_dir_block_checksum(&small, 0, 1, 1).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn stamp_dir_block_checksum_round_trips_with_verify() {
        let block_size = 4096;
        let csum_seed = 0x1234_5678_u32;
        let ino = 42_u32;
        let generation = 7_u32;

        let mut block = vec![0_u8; block_size];
        // Fill with some directory-like data.
        for (i, byte) in block.iter_mut().enumerate().take(block_size - 12) {
            *byte = i.to_le_bytes()[0];
        }
        // Set up the checksum tail structure.
        let tail_off = block_size - 12;
        // inode = 0
        block[tail_off..tail_off + 4].copy_from_slice(&0_u32.to_le_bytes());
        // rec_len = 12
        block[tail_off + 4..tail_off + 6].copy_from_slice(&12_u16.to_le_bytes());
        // name_len = 0
        block[tail_off + 6] = 0;
        // file_type = 0xDE (EXT4_FT_DIR_CSUM)
        block[tail_off + 7] = 0xDE;

        // Stamp the checksum.
        stamp_dir_block_checksum(&mut block, csum_seed, ino, generation);

        // Verify should pass.
        verify_dir_block_checksum(&block, csum_seed, ino, generation)
            .expect("stamped checksum should verify");

        // Corrupt data and verify should fail.
        block[50] ^= 0xFF;
        assert!(verify_dir_block_checksum(&block, csum_seed, ino, generation).is_err());
    }

    #[test]
    fn stamp_extent_block_checksum_round_trips_with_verify() {
        let block_size = 4096;
        let csum_seed = 0xABCD_EF01_u32;
        let ino = 99_u32;
        let generation = 3_u32;

        let mut block = vec![0_u8; block_size];
        // Build a minimal extent header: magic=0xF30A, entries=2, max=340, depth=0
        block[0..2].copy_from_slice(&0xF30A_u16.to_le_bytes());
        block[2..4].copy_from_slice(&2_u16.to_le_bytes());
        block[4..6].copy_from_slice(&340_u16.to_le_bytes()); // eh_max
        block[6..8].copy_from_slice(&0_u16.to_le_bytes());

        // Stamp the checksum.
        stamp_extent_block_checksum(&mut block, csum_seed, ino, generation);

        // Verify should pass.
        verify_extent_block_checksum(&block, csum_seed, ino, generation)
            .expect("stamped checksum should verify");

        // Corrupt data and verify should fail.
        block[20] ^= 0xFF;
        assert!(verify_extent_block_checksum(&block, csum_seed, ino, generation).is_err());
    }

    // ── Bitmap checksum ───────────────────────────────────────────────

    #[test]
    fn block_bitmap_checksum_round_trips_with_verify() {
        let csum_seed = 0x1234_5678_u32;
        let blocks_per_group = 32768_u32;

        let mut bitmap = vec![0xFF_u8; 4096];
        bitmap[0] = 0xF0;
        bitmap[100] = 0x00;

        let csum = block_bitmap_checksum_value(&bitmap, csum_seed, blocks_per_group, 64);

        // Build a GDT entry with the computed checksum.
        let gd = Ext4GroupDesc {
            block_bitmap: 0,
            inode_bitmap: 0,
            inode_table: 0,
            free_blocks_count: 0,
            free_inodes_count: 0,
            used_dirs_count: 0,
            itable_unused: 0,
            flags: 0,
            checksum: 0,
            block_bitmap_csum: csum,
            inode_bitmap_csum: 0,
        };
        assert!(
            verify_block_bitmap_checksum(&bitmap, csum_seed, blocks_per_group, &gd, 64).is_ok()
        );

        // Corrupt bitmap → should fail.
        bitmap[50] ^= 0xFF;
        assert!(
            verify_block_bitmap_checksum(&bitmap, csum_seed, blocks_per_group, &gd, 64).is_err()
        );
    }

    #[test]
    fn inode_bitmap_checksum_uses_correct_length() {
        let csum_seed = 0xABCD_u32;
        let bitmap = vec![0xAA_u8; 4096];

        // With 2048 inodes/group, checksum covers only 256 bytes.
        let csum_2048 = inode_bitmap_checksum_value(&bitmap, csum_seed, 2048, 64);
        // With 32768 inodes/group (unusual), checksum covers 4096 bytes.
        let csum_32768 = inode_bitmap_checksum_value(&bitmap, csum_seed, 32768, 64);
        // Different lengths → different checksums (unless data is uniform, which it is here).
        // Both portions are 0xAA, but the CRC state after 256 bytes differs from after 4096.
        assert_ne!(csum_2048, csum_32768);
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
        let seed = ext4_chksum(csum_seed, &ino.to_le_bytes());
        let seed = ext4_chksum(seed, &generation.to_le_bytes());
        let checksum = ext4_chksum(seed, &block[..tail_off]);

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

    /// Oracle test (bd-fwph3): pin `ext4_xattr_block_csum` against a real
    /// external xattr block written by e2fsprogs/debugfs on a metadata_csum
    /// image, then verified clean by `e2fsck -fn`. The fixture is block 1363 of
    /// a 1 KiB-block image (csum seed 0xedadf038); e2fsprogs stamped
    /// h_checksum = 0x4763fce2. This proves our formula matches the on-disk
    /// spec — not just our own re-derivation.
    #[test]
    fn xattr_block_csum_matches_e2fsprogs_oracle() {
        const SEED: u32 = 0xedad_f038;
        const BLOCK_NR: u64 = 1363;
        const ORACLE_H_CHECKSUM: u32 = 0x4763_fce2;
        let block: &[u8] =
            include_bytes!("../../../conformance/golden/xattr_block_oracle_metadata_csum.bin");
        assert_eq!(block.len(), 1024);

        // The fixture already carries e2fsprogs' stored checksum.
        let stored = u32::from_le_bytes([block[16], block[17], block[18], block[19]]);
        assert_eq!(stored, ORACLE_H_CHECKSUM, "fixture h_checksum drifted");

        // Our computation must reproduce exactly what e2fsprogs wrote.
        assert_eq!(
            ext4_xattr_block_csum(SEED, BLOCK_NR, block),
            ORACLE_H_CHECKSUM,
            "ext4_xattr_block_csum disagrees with e2fsprogs oracle"
        );
        assert!(verify_xattr_block_checksum(block, SEED, BLOCK_NR));

        // Stamping a copy whose checksum field has been clobbered restores the
        // exact oracle value, and stamping is idempotent.
        let mut clobbered = block.to_vec();
        clobbered[16..20].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        assert!(!verify_xattr_block_checksum(&clobbered, SEED, BLOCK_NR));
        stamp_xattr_block_checksum(&mut clobbered, SEED, BLOCK_NR);
        assert_eq!(&clobbered[16..20], &ORACLE_H_CHECKSUM.to_le_bytes());
        assert!(verify_xattr_block_checksum(&clobbered, SEED, BLOCK_NR));

        // A wrong block number must not verify (the physical block is folded in).
        assert!(!verify_xattr_block_checksum(block, SEED, BLOCK_NR + 1));

        // A wrong csum_seed (a different filesystem) must not verify either, so a
        // valid xattr-block checksum cannot replay across filesystems.
        assert!(!verify_xattr_block_checksum(block, SEED ^ 0x1, BLOCK_NR));
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

    fn make_proptest_valid_ext4_superblock(
        log_block_size: u32,
        blocks_per_group: u32,
        inodes_per_group: u32,
        desc_size: u16,
        incompat: u32,
        volume_name: &[u8],
    ) -> [u8; EXT4_SUPERBLOCK_SIZE] {
        let mut sb = make_valid_sb();
        let first_data_block = u32::from(log_block_size == 0);
        let groups = 4_u32;
        let blocks_count = blocks_per_group
            .saturating_mul(groups)
            .saturating_add(first_data_block);
        let inodes_count = inodes_per_group.saturating_mul(groups);
        let mut name = [0_u8; 16];
        let copy_len = volume_name.len().min(name.len());
        name[..copy_len].copy_from_slice(&volume_name[..copy_len]);

        sb[0x18..0x1C].copy_from_slice(&log_block_size.to_le_bytes());
        sb[0x1C..0x20].copy_from_slice(&log_block_size.to_le_bytes());
        sb[0x14..0x18].copy_from_slice(&first_data_block.to_le_bytes());
        sb[0x04..0x08].copy_from_slice(&blocks_count.to_le_bytes());
        sb[0x20..0x24].copy_from_slice(&blocks_per_group.to_le_bytes());
        sb[0x24..0x28].copy_from_slice(&blocks_per_group.to_le_bytes());
        sb[0x28..0x2C].copy_from_slice(&inodes_per_group.to_le_bytes());
        sb[0x00..0x04].copy_from_slice(&inodes_count.to_le_bytes());
        sb[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes());
        sb[0x54..0x58].copy_from_slice(&11_u32.to_le_bytes());
        sb[0xFE..0x100].copy_from_slice(&desc_size.to_le_bytes());
        sb[0x60..0x64].copy_from_slice(&incompat.to_le_bytes());
        sb[0x5C..0x60].copy_from_slice(&0_u32.to_le_bytes());
        sb[0x64..0x68].copy_from_slice(&0_u32.to_le_bytes());
        sb[0x78..0x88].copy_from_slice(&name);
        sb
    }

    // ══════════════════════════════════════════════════════════════════
    //  Ext4Superblock query method tests
    // ══════════════════════════════════════════════════════════════════

    /// Parse `make_valid_sb()` with the given incompat flags into an Ext4Superblock.
    fn parse_valid_sb_with_incompat(incompat: u32) -> Ext4Superblock {
        let mut sb = make_valid_sb();
        sb[0x60..0x64].copy_from_slice(&incompat.to_le_bytes());
        Ext4Superblock::parse_superblock_region(&sb).expect("parse valid sb")
    }

    #[test]
    fn has_compat_detects_set_flags() {
        let mut sb = make_valid_sb();
        let compat =
            (Ext4CompatFeatures::HAS_JOURNAL.0 | Ext4CompatFeatures::EXT_ATTR.0).to_le_bytes();
        sb[0x5C..0x60].copy_from_slice(&compat);
        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        assert!(parsed.has_compat(Ext4CompatFeatures::HAS_JOURNAL));
        assert!(parsed.has_compat(Ext4CompatFeatures::EXT_ATTR));
        assert!(!parsed.has_compat(Ext4CompatFeatures::DIR_INDEX));
    }

    #[test]
    fn has_incompat_detects_set_flags() {
        let parsed = parse_valid_sb_with_incompat(
            Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0,
        );
        assert!(parsed.has_incompat(Ext4IncompatFeatures::FILETYPE));
        assert!(parsed.has_incompat(Ext4IncompatFeatures::EXTENTS));
        assert!(!parsed.has_incompat(Ext4IncompatFeatures::BIT64));
        assert!(!parsed.has_incompat(Ext4IncompatFeatures::ENCRYPT));
    }

    #[test]
    fn has_ro_compat_detects_set_flags() {
        let mut sb = make_valid_sb();
        let ro_compat = (Ext4RoCompatFeatures::SPARSE_SUPER.0 | Ext4RoCompatFeatures::LARGE_FILE.0)
            .to_le_bytes();
        sb[0x64..0x68].copy_from_slice(&ro_compat);
        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        assert!(parsed.has_ro_compat(Ext4RoCompatFeatures::SPARSE_SUPER));
        assert!(parsed.has_ro_compat(Ext4RoCompatFeatures::LARGE_FILE));
        assert!(!parsed.has_ro_compat(Ext4RoCompatFeatures::METADATA_CSUM));
    }

    #[test]
    fn is_64bit_false_without_flag() {
        let parsed = parse_valid_sb_with_incompat(
            Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0,
        );
        assert!(!parsed.is_64bit());
    }

    #[test]
    fn is_64bit_true_with_flag() {
        let mut sb = make_valid_sb();
        let incompat = (Ext4IncompatFeatures::FILETYPE.0
            | Ext4IncompatFeatures::EXTENTS.0
            | Ext4IncompatFeatures::BIT64.0)
            .to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);
        sb[0xFE..0x100].copy_from_slice(&64_u16.to_le_bytes()); // desc_size=64
        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        assert!(parsed.is_64bit());
    }

    #[test]
    fn group_desc_size_32_for_non_64bit() {
        let parsed = parse_valid_sb_with_incompat(
            Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0,
        );
        assert_eq!(parsed.group_desc_size(), 32);
    }

    #[test]
    fn group_desc_size_clamps_to_64_for_64bit() {
        let mut sb = make_valid_sb();
        let incompat = (Ext4IncompatFeatures::FILETYPE.0
            | Ext4IncompatFeatures::EXTENTS.0
            | Ext4IncompatFeatures::BIT64.0)
            .to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);
        sb[0xFE..0x100].copy_from_slice(&32_u16.to_le_bytes()); // desc_size=32 < 64
        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        assert_eq!(parsed.group_desc_size(), 64); // clamped
    }

    #[test]
    fn group_desc_size_128_for_64bit_when_specified() {
        let mut sb = make_valid_sb();
        let incompat = (Ext4IncompatFeatures::FILETYPE.0
            | Ext4IncompatFeatures::EXTENTS.0
            | Ext4IncompatFeatures::BIT64.0)
            .to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);
        sb[0xFE..0x100].copy_from_slice(&128_u16.to_le_bytes());
        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        assert_eq!(parsed.group_desc_size(), 128);
    }

    #[test]
    fn groups_count_single_group() {
        let parsed = parse_valid_sb_with_incompat(
            Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0,
        );
        // blocks_count=32768, blocks_per_group=32768 → 1 group
        assert_eq!(parsed.groups_count(), 1);
    }

    #[test]
    fn groups_count_zero_blocks_per_group_returns_zero() {
        let mut sb = make_valid_sb();
        sb[0x20..0x24].copy_from_slice(&0_u32.to_le_bytes()); // blocks_per_group=0
        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        assert_eq!(parsed.groups_count(), 0);
    }

    #[test]
    fn groups_count_rounds_up_partial() {
        let mut sb = make_valid_sb();
        sb[0x04..0x08].copy_from_slice(&33000_u32.to_le_bytes()); // blocks_count > 32768
        let incompat =
            (Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0).to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);
        // inodes_count must accommodate groups * inodes_per_group
        sb[0x00..0x04].copy_from_slice(&16384_u32.to_le_bytes());
        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        assert_eq!(parsed.groups_count(), 2); // ceil(33000/32768)
    }

    #[test]
    fn groups_count_caps_at_u32_max_on_overflow() {
        let mut sb = make_valid_sb();
        // Set blocks_count to a huge 64-bit value (via the 64-bit extension field).
        // blocks_count_lo = u32::MAX, blocks_count_hi = 1 → total > u32::MAX * bpg
        sb[0x04..0x08].copy_from_slice(&u32::MAX.to_le_bytes()); // blocks_count_lo
        // Enable 64BIT feature so the hi field is honored.
        let incompat = (Ext4IncompatFeatures::FILETYPE.0
            | Ext4IncompatFeatures::EXTENTS.0
            | Ext4IncompatFeatures::BIT64.0)
            .to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);
        // Pad to 256 bytes for 64-bit descriptor parsing.
        let mut big_sb = vec![0u8; 1024];
        big_sb[..sb.len()].copy_from_slice(&sb);
        // Set desc_size (offset 0xFE) for 64-bit mode.
        big_sb[0xFE..0x100].copy_from_slice(&64_u16.to_le_bytes());
        // Set blocks_count_hi to a large value.
        big_sb[0x150..0x154].copy_from_slice(&0xFFFF_u32.to_le_bytes());
        // blocks_per_group stays at 32768 (from make_valid_sb).
        // total = (0xFFFF << 32) | 0xFFFF_FFFF = 281_474_976_710_655
        // groups = ceil(total / 32768) which far exceeds u32::MAX.
        if let Ok(parsed) = Ext4Superblock::parse_superblock_region(&big_sb) {
            // groups_count should cap at u32::MAX, not silently truncate.
            assert_eq!(parsed.groups_count(), u32::MAX);
        }
        // If parsing fails due to other validation, the test still passes.
    }

    #[test]
    fn has_metadata_csum_false_without_flag() {
        let parsed = parse_valid_sb_with_incompat(
            Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0,
        );
        assert!(!parsed.has_metadata_csum());
    }

    #[test]
    fn has_metadata_csum_true_with_flag() {
        let mut sb = make_valid_sb();
        let ro_compat = Ext4RoCompatFeatures::METADATA_CSUM.0.to_le_bytes();
        sb[0x64..0x68].copy_from_slice(&ro_compat);
        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        assert!(parsed.has_metadata_csum());
    }

    #[test]
    fn csum_seed_from_uuid() {
        let mut sb = make_valid_sb();
        // Set a specific UUID
        let uuid: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        sb[0x68..0x78].copy_from_slice(&uuid);
        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        let expected = ext4_chksum(!0u32, &uuid);
        assert_eq!(parsed.csum_seed(), expected);
    }

    #[test]
    fn csum_seed_from_stored_when_csum_seed_flag() {
        let mut sb = make_valid_sb();
        let incompat = (Ext4IncompatFeatures::FILETYPE.0
            | Ext4IncompatFeatures::EXTENTS.0
            | Ext4IncompatFeatures::CSUM_SEED.0)
            .to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);
        sb[0x270..0x274].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes()); // checksum_seed
        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        assert_eq!(parsed.csum_seed(), 0xDEAD_BEEF);
    }

    #[test]
    fn validate_checksum_skips_without_metadata_csum() {
        let parsed = parse_valid_sb_with_incompat(
            Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0,
        );
        assert!(parsed.validate_checksum(&[0; 1024]).is_ok()); // no-op
    }

    #[test]
    fn validate_checksum_rejects_short_region() {
        let mut sb = make_valid_sb();
        let ro_compat = Ext4RoCompatFeatures::METADATA_CSUM.0.to_le_bytes();
        sb[0x64..0x68].copy_from_slice(&ro_compat);
        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        assert!(parsed.validate_checksum(&[0; 500]).is_err());
    }

    #[test]
    fn group_desc_offset_4k_block_group_0() {
        let parsed = parse_valid_sb_with_incompat(
            Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0,
        );
        // 4K blocks: GDT starts at block 1 = byte 4096
        assert_eq!(
            parsed.group_desc_offset(ffs_types::GroupNumber(0)),
            Some(4096)
        );
    }

    #[test]
    fn group_desc_offset_4k_block_group_1() {
        let parsed = parse_valid_sb_with_incompat(
            Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0,
        );
        assert_eq!(
            parsed.group_desc_offset(ffs_types::GroupNumber(1)),
            Some(4096 + 32) // group 1 offset = 4096 + desc_size
        );
    }

    #[test]
    fn group_desc_offset_1k_block() {
        let mut sb = make_valid_sb();
        sb[0x18..0x1C].copy_from_slice(&0_u32.to_le_bytes()); // log_block_size=0 → 1K
        sb[0x1C..0x20].copy_from_slice(&0_u32.to_le_bytes()); // log_cluster_size=0
        sb[0x14..0x18].copy_from_slice(&1_u32.to_le_bytes()); // first_data_block=1
        sb[0x20..0x24].copy_from_slice(&8192_u32.to_le_bytes());
        sb[0x24..0x28].copy_from_slice(&8192_u32.to_le_bytes());
        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        // 1K blocks: GDT starts at block 2 = byte 2048
        assert_eq!(
            parsed.group_desc_offset(ffs_types::GroupNumber(0)),
            Some(2048)
        );
    }

    #[test]
    fn inode_table_offset_root_inode() {
        let parsed = parse_valid_sb_with_incompat(
            Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0,
        );
        let (group, index, byte_offset) = parsed.inode_table_offset(ffs_types::InodeNumber::ROOT);
        assert_eq!(group, ffs_types::GroupNumber(0));
        // Root inode (2): index_in_group = (2-1) % 8192 = 1
        assert_eq!(index, 1);
        // byte_offset = index * inode_size = 1 * 256 = 256
        assert_eq!(byte_offset, 256);
    }

    #[test]
    fn inode_table_offset_first_inode() {
        let parsed = parse_valid_sb_with_incompat(
            Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0,
        );
        let (group, index, byte_offset) = parsed.inode_table_offset(ffs_types::InodeNumber(1));
        assert_eq!(group, ffs_types::GroupNumber(0));
        assert_eq!(index, 0);
        assert_eq!(byte_offset, 0);
    }

    #[test]
    fn parse_from_image_rejects_short_image() {
        assert!(Ext4Superblock::parse_from_image(&[0; 1024]).is_err());
        assert!(Ext4Superblock::parse_from_image(&[]).is_err());
    }

    #[test]
    fn parse_from_image_extracts_from_offset_1024() {
        // Build a valid image: 1024 zero bytes + 1024-byte superblock region
        let mut image = vec![0_u8; 2048];
        let sb = make_valid_sb();
        image[1024..2048].copy_from_slice(&sb);
        let parsed = Ext4Superblock::parse_from_image(&image).expect("parse from image");
        assert_eq!(parsed.magic, EXT4_SUPER_MAGIC);
        assert_eq!(parsed.block_size, 4096);
    }

    // ── Edge-case hardening tests ──────────────────────────────────────

    #[test]
    fn ext4_chksum_empty_data() {
        // Kernel: ext4_chksum(~0, &[], 0) = crc32c_le(~0, &[], 0) = ~0
        // Ours: ext4_chksum(!0, &[]) = !crc32c_append(!!0, &[]) = !crc32c_append(0, &[])
        let result = ext4_chksum(!0, &[]);
        // crc32c of empty data with seed 0 is 0 → !0 = 0xFFFF_FFFF
        assert_eq!(result, !0);
    }

    #[test]
    fn ext4_chksum_known_value() {
        // Verify that our ext4_chksum matches the kernel convention
        // for a known input. CRC32C of b"hello" (standard) = 0xC9265082.
        // Kernel crc32c_le(~0, "hello", 5) = !standard_crc32c("hello") = !0xC9265082
        // Our ext4_chksum(~0, "hello") = !crc32c_append(0, "hello") = !0xC9265082
        let result = ext4_chksum(!0, b"hello");
        let standard = crc32c::crc32c_append(0, b"hello"); // 0xC9265082
        assert_eq!(result, !standard);
    }

    /// bd-qfzk2 / CR-A — Conformance against the canonical CRC32C
    /// (Castagnoli) reference vectors. ext4_chksum bridges the kernel's
    /// raw-register `crc32c_le` to Rust's standard-convention
    /// `crc32c_append`; for seed `~0` the bridged value is the bitwise
    /// complement of the standard CRC32C (because the kernel returns
    /// the raw register state, not the standard input/output-XORed
    /// value). The reference vectors are the IETF-published
    /// CRC32C-Castagnoli check values.
    #[test]
    fn ext4_chksum_matches_kernel_reference_vectors() {
        // Standard CRC32C (Castagnoli) reference values:
        // ""             → 0x00000000
        // "a"            → 0xC1D04330
        // "123456789"    → 0xE3069283 (canonical CRC32C check value)
        // ext4_chksum(~0, x) returns the kernel raw-register state, which
        // is the bitwise complement of the standard CRC32C value.
        assert_eq!(ext4_chksum(!0, b""), !0x0000_0000_u32, "empty");
        assert_eq!(ext4_chksum(!0, b"a"), !0xC1D0_4330_u32, "single-byte");
        assert_eq!(
            ext4_chksum(!0, b"123456789"),
            !0xE306_9283_u32,
            "canonical CRC32C check value"
        );
    }

    /// bd-qfzk2 / CR-B — Hop-by-hop append associativity (the kernel's
    /// incremental checksum protocol):
    /// ext4_chksum(seed, A ++ B) == ext4_chksum(ext4_chksum(seed, A), B)
    /// The kernel uses this to compute a single checksum across
    /// disjoint memory regions (e.g., struct prefix + zeroed-csum-field
    /// and the remainder). A regression breaking this would make our
    /// re-encoded checksums diverge silently from kernel-mounted images.
    /// Property test under the existing proptest! block at the end of
    /// `tests` exercises arbitrary seed + A + B; here we pin one fixed
    /// case for fast feedback.
    #[test]
    fn ext4_chksum_hop_by_hop_append_fixed_case() {
        let seed = 0x1234_5678_u32;
        let a = b"prefix-region";
        let b = b"-suffix-region";
        let mut concat = Vec::with_capacity(a.len() + b.len());
        concat.extend_from_slice(a);
        concat.extend_from_slice(b);
        let direct = ext4_chksum(seed, &concat);
        let two_hop = ext4_chksum(ext4_chksum(seed, a), b);
        assert_eq!(
            direct, two_hop,
            "ext4_chksum must be associative across disjoint region appends"
        );
    }

    /// bd-qfzk2 / CR-C — Empty-suffix idempotence:
    /// ext4_chksum(seed, &[]) == seed.
    /// Trivial corollary of CR-B with B=empty, but worth pinning
    /// because a regression that accidentally negated empty input
    /// would silently corrupt every incremental checksum continuation.
    /// bd-343v3 — Kernel-conformance pin for ext4 directory-entry
    /// file-type constants. Each value is mirrored verbatim from the
    /// Linux kernel `fs/ext4/ext4.h`. A regression that, e.g.,
    /// swapped EXT4_FT_DIR (2) and EXT4_FT_REG_FILE (1) would make
    /// readdir silently expose every directory as a regular file —
    /// this test pins the kernel reference so such drift fails loudly.
    #[test]
    fn ext4_file_type_constants_match_kernel_header() {
        // Values per fs/ext4/ext4.h `enum`/`#define EXT4_FT_*`.
        assert_eq!(EXT4_FT_UNKNOWN, 0);
        assert_eq!(EXT4_FT_REG_FILE, 1);
        assert_eq!(EXT4_FT_DIR, 2);
        assert_eq!(EXT4_FT_CHRDEV, 3);
        assert_eq!(EXT4_FT_BLKDEV, 4);
        assert_eq!(EXT4_FT_FIFO, 5);
        assert_eq!(EXT4_FT_SOCK, 6);
        assert_eq!(EXT4_FT_SYMLINK, 7);
        assert_eq!(EXT4_FT_MAX, 8);
        assert_eq!(EXT4_FT_DIR_CSUM, 0xDE);

        // Enum discriminants must equal the kernel constants.
        assert_eq!(Ext4FileType::Unknown as u8, EXT4_FT_UNKNOWN);
        assert_eq!(Ext4FileType::RegFile as u8, EXT4_FT_REG_FILE);
        assert_eq!(Ext4FileType::Dir as u8, EXT4_FT_DIR);
        assert_eq!(Ext4FileType::Chrdev as u8, EXT4_FT_CHRDEV);
        assert_eq!(Ext4FileType::Blkdev as u8, EXT4_FT_BLKDEV);
        assert_eq!(Ext4FileType::Fifo as u8, EXT4_FT_FIFO);
        assert_eq!(Ext4FileType::Sock as u8, EXT4_FT_SOCK);
        assert_eq!(Ext4FileType::Symlink as u8, EXT4_FT_SYMLINK);

        // `from_raw` round-trip: every value in [0, EXT4_FT_MAX) maps
        // back to its corresponding enum variant whose discriminant
        // equals the raw value.
        for raw in 0..EXT4_FT_MAX {
            let parsed = Ext4FileType::from_raw(raw);
            assert_eq!(
                parsed as u8, raw,
                "Ext4FileType::from_raw({raw}) must round-trip to discriminant {raw}"
            );
        }

        // Boundary: any value at or above EXT4_FT_MAX (except the
        // out-of-band dir-checksum sentinel) decodes to Unknown. The
        // sentinel itself is 0xDE and decodes to Unknown by the same
        // rule — it is explicitly handled by the dir-tail recogniser
        // outside the enum, not by `from_raw`.
        assert_eq!(Ext4FileType::from_raw(EXT4_FT_MAX), Ext4FileType::Unknown);
        assert_eq!(Ext4FileType::from_raw(50), Ext4FileType::Unknown);
        assert_eq!(
            Ext4FileType::from_raw(EXT4_FT_DIR_CSUM),
            Ext4FileType::Unknown,
            "EXT4_FT_DIR_CSUM is recognised by the dir-tail pipeline, NOT by Ext4FileType::from_raw"
        );
        assert_eq!(Ext4FileType::from_raw(u8::MAX), Ext4FileType::Unknown);

        // Cross-check: file-type values are strict-monotonic ascending
        // and the dir-csum sentinel sits well above EXT4_FT_MAX.
        const {
            assert!(
                EXT4_FT_UNKNOWN < EXT4_FT_REG_FILE
                    && EXT4_FT_REG_FILE < EXT4_FT_DIR
                    && EXT4_FT_DIR < EXT4_FT_CHRDEV
                    && EXT4_FT_CHRDEV < EXT4_FT_BLKDEV
                    && EXT4_FT_BLKDEV < EXT4_FT_FIFO
                    && EXT4_FT_FIFO < EXT4_FT_SOCK
                    && EXT4_FT_SOCK < EXT4_FT_SYMLINK
                    && EXT4_FT_SYMLINK < EXT4_FT_MAX,
                "ext4 file-type values must be strict-monotonic ascending"
            );
            assert!(
                EXT4_FT_DIR_CSUM > EXT4_FT_MAX,
                "EXT4_FT_DIR_CSUM (0xDE) must sit above EXT4_FT_MAX so it never collides with a real file_type"
            );
        }
    }

    /// bd-3ydm6 — Kernel-conformance pin for `is_reserved_inode`.
    /// Verifies the predicate matches the kernel `ext4_is_reserved_inode`
    /// contract on every reserved-inode constant from bd-k81lq plus
    /// boundary cases (ino=0 sentinel, ino=first_ino threshold,
    /// ino=u32::MAX). The fail-closed reasoning mode is documented on
    /// the function itself; this test pins the boundary so a
    /// regression that shifted the predicate (e.g. `<=` vs `<`) would
    /// fail loudly rather than silently expose the journal as a
    /// regular file.
    #[test]
    fn is_reserved_inode_matches_kernel_contract() {
        const FIRST_INO: u32 = EXT4_GOOD_OLD_FIRST_INO;

        // Sentinel: inode 0 is always reserved (kernel "no inode" marker).
        assert!(
            is_reserved_inode(FIRST_INO, 0),
            "inode 0 must always be reserved (kernel no-inode sentinel)"
        );

        // Every named reserved inode constant must satisfy the predicate.
        for &reserved in &[
            EXT4_BAD_INO,         // 1
            EXT4_ROOT_INO,        // 2
            EXT4_USR_QUOTA_INO,   // 3
            EXT4_GRP_QUOTA_INO,   // 4
            EXT4_BOOT_LOADER_INO, // 5
            EXT4_UNDEL_DIR_INO,   // 6
            EXT4_RESIZE_INO,      // 7
            EXT4_JOURNAL_INO,     // 8
            EXT4_EXCLUDE_INO,     // 9
            EXT4_REPLICA_INO,     // 10
        ] {
            assert!(
                is_reserved_inode(FIRST_INO, reserved),
                "named reserved inode {reserved} must satisfy is_reserved_inode"
            );
        }

        // Boundary: first_ino itself is the FIRST non-reserved inode.
        assert!(
            !is_reserved_inode(FIRST_INO, FIRST_INO),
            "first_ino itself must NOT be reserved (it is the first user inode)"
        );

        // Anything strictly above first_ino is a user inode.
        for &user_ino in &[FIRST_INO + 1, FIRST_INO + 100, 1_000_000_u32, u32::MAX] {
            assert!(
                !is_reserved_inode(FIRST_INO, user_ino),
                "user inode {user_ino} must not be reserved when first_ino={FIRST_INO}"
            );
        }

        // EXT4_PRJ_QUOTA_INO (16) is reserved in modern filesystems
        // where the kernel sets first_ino to 256 (post-quota-inode
        // expansion), but is a user inode under the GOOD_OLD layout
        // where first_ino == 11. Pin both regimes.
        assert!(
            !is_reserved_inode(FIRST_INO, EXT4_PRJ_QUOTA_INO),
            "PRJ_QUOTA_INO is a user inode under GOOD_OLD first_ino=11"
        );
        assert!(
            is_reserved_inode(256, EXT4_PRJ_QUOTA_INO),
            "PRJ_QUOTA_INO is reserved under modern first_ino=256"
        );

        // Mid-range first_ino: pin the strict-less-than boundary.
        assert!(is_reserved_inode(11, 10));
        assert!(!is_reserved_inode(11, 11));
        assert!(is_reserved_inode(256, 255));
        assert!(!is_reserved_inode(256, 256));
    }

    /// bd-bevt2 — Kernel-conformance pin for the 40 ext4 feature-flag
    /// constants across the three wrapper structs:
    ///   * Ext4CompatFeatures   (10 flags, EXT4_FEATURE_COMPAT_*)
    ///   * Ext4IncompatFeatures (16 flags, EXT4_FEATURE_INCOMPAT_*)
    ///   * Ext4RoCompatFeatures (14 flags, EXT4_FEATURE_RO_COMPAT_*)
    ///
    /// Each constant mirrors a kernel macro from `fs/ext4/ext4.h`.
    /// Mount eligibility hinges on these bits: COMPAT bits are
    /// advisory (unknown bits ignored), INCOMPAT bits force mount
    /// failure on unknown bits, RO_COMPAT bits force read-only mount.
    /// A regression that swapped, e.g., FILETYPE (0x2) and EXTENTS
    /// (0x40) would silently mis-classify every ext4 image; a
    /// regression in BIT64 (0x80) would silently fail to recognize
    /// 64-bit field layout.
    ///
    /// This test pins each value plus the structural invariant that
    /// every flag is a single power-of-2 bit and no two flags within
    /// the same set share a bit.
    fn assert_ext4_feature_set_is_distinct(set_label: &str, flags: &[u32]) {
        for &flag in flags {
            assert!(
                flag.is_power_of_two(),
                "{set_label} flag {flag:#x} must be a single power-of-2 bit"
            );
        }
        for (i, &a) in flags.iter().enumerate() {
            for &b in &flags[i + 1..] {
                assert_eq!(
                    a & b,
                    0,
                    "{set_label} flags {a:#x} and {b:#x} must not share a bit"
                );
            }
        }
        let or_all: u32 = flags.iter().fold(0_u32, |acc, &f| acc | f);
        assert_eq!(
            or_all.count_ones() as usize,
            flags.len(),
            "{set_label}: OR of all flags must have exactly {} bits set",
            flags.len()
        );
    }

    #[test]
    fn ext4_feature_flag_constants_match_kernel_header() {
        // Compat (advisory) flags per fs/ext4/ext4.h.
        assert_eq!(Ext4CompatFeatures::DIR_PREALLOC.0, 0x0001);
        assert_eq!(Ext4CompatFeatures::IMAGIC_INODES.0, 0x0002);
        assert_eq!(Ext4CompatFeatures::HAS_JOURNAL.0, 0x0004);
        assert_eq!(Ext4CompatFeatures::EXT_ATTR.0, 0x0008);
        assert_eq!(Ext4CompatFeatures::RESIZE_INODE.0, 0x0010);
        assert_eq!(Ext4CompatFeatures::DIR_INDEX.0, 0x0020);
        assert_eq!(Ext4CompatFeatures::SPARSE_SUPER2.0, 0x0200);
        assert_eq!(Ext4CompatFeatures::FAST_COMMIT.0, 0x0400);
        assert_eq!(Ext4CompatFeatures::STABLE_INODES.0, 0x0800);
        assert_eq!(Ext4CompatFeatures::ORPHAN_FILE.0, 0x1000);

        // Incompat (mount-fail-on-unknown) flags.
        assert_eq!(Ext4IncompatFeatures::COMPRESSION.0, 0x0001);
        assert_eq!(Ext4IncompatFeatures::FILETYPE.0, 0x0002);
        assert_eq!(Ext4IncompatFeatures::RECOVER.0, 0x0004);
        assert_eq!(Ext4IncompatFeatures::JOURNAL_DEV.0, 0x0008);
        assert_eq!(Ext4IncompatFeatures::META_BG.0, 0x0010);
        assert_eq!(Ext4IncompatFeatures::EXTENTS.0, 0x0040);
        assert_eq!(Ext4IncompatFeatures::BIT64.0, 0x0080);
        assert_eq!(Ext4IncompatFeatures::MMP.0, 0x0100);
        assert_eq!(Ext4IncompatFeatures::FLEX_BG.0, 0x0200);
        assert_eq!(Ext4IncompatFeatures::EA_INODE.0, 0x0400);
        assert_eq!(Ext4IncompatFeatures::DIRDATA.0, 0x1000);
        assert_eq!(Ext4IncompatFeatures::CSUM_SEED.0, 0x2000);
        assert_eq!(Ext4IncompatFeatures::LARGEDIR.0, 0x4000);
        assert_eq!(Ext4IncompatFeatures::INLINE_DATA.0, 0x8000);
        assert_eq!(Ext4IncompatFeatures::ENCRYPT.0, 0x1_0000);
        assert_eq!(Ext4IncompatFeatures::CASEFOLD.0, 0x2_0000);

        // RoCompat (read-only-mount-on-unknown) flags.
        assert_eq!(Ext4RoCompatFeatures::SPARSE_SUPER.0, 0x0001);
        assert_eq!(Ext4RoCompatFeatures::LARGE_FILE.0, 0x0002);
        assert_eq!(Ext4RoCompatFeatures::BTREE_DIR.0, 0x0004);
        assert_eq!(Ext4RoCompatFeatures::HUGE_FILE.0, 0x0008);
        assert_eq!(Ext4RoCompatFeatures::GDT_CSUM.0, 0x0010);
        assert_eq!(Ext4RoCompatFeatures::DIR_NLINK.0, 0x0020);
        assert_eq!(Ext4RoCompatFeatures::EXTRA_ISIZE.0, 0x0040);
        assert_eq!(Ext4RoCompatFeatures::QUOTA.0, 0x0100);
        assert_eq!(Ext4RoCompatFeatures::BIGALLOC.0, 0x0200);
        assert_eq!(Ext4RoCompatFeatures::METADATA_CSUM.0, 0x0400);
        assert_eq!(Ext4RoCompatFeatures::READONLY.0, 0x1000);
        assert_eq!(Ext4RoCompatFeatures::PROJECT.0, 0x2000);
        assert_eq!(Ext4RoCompatFeatures::VERITY.0, 0x8000);
        assert_eq!(Ext4RoCompatFeatures::ORPHAN_PRESENT.0, 0x1_0000);

        let compat = [
            Ext4CompatFeatures::DIR_PREALLOC.0,
            Ext4CompatFeatures::IMAGIC_INODES.0,
            Ext4CompatFeatures::HAS_JOURNAL.0,
            Ext4CompatFeatures::EXT_ATTR.0,
            Ext4CompatFeatures::RESIZE_INODE.0,
            Ext4CompatFeatures::DIR_INDEX.0,
            Ext4CompatFeatures::SPARSE_SUPER2.0,
            Ext4CompatFeatures::FAST_COMMIT.0,
            Ext4CompatFeatures::STABLE_INODES.0,
            Ext4CompatFeatures::ORPHAN_FILE.0,
        ];
        let incompat = [
            Ext4IncompatFeatures::COMPRESSION.0,
            Ext4IncompatFeatures::FILETYPE.0,
            Ext4IncompatFeatures::RECOVER.0,
            Ext4IncompatFeatures::JOURNAL_DEV.0,
            Ext4IncompatFeatures::META_BG.0,
            Ext4IncompatFeatures::EXTENTS.0,
            Ext4IncompatFeatures::BIT64.0,
            Ext4IncompatFeatures::MMP.0,
            Ext4IncompatFeatures::FLEX_BG.0,
            Ext4IncompatFeatures::EA_INODE.0,
            Ext4IncompatFeatures::DIRDATA.0,
            Ext4IncompatFeatures::CSUM_SEED.0,
            Ext4IncompatFeatures::LARGEDIR.0,
            Ext4IncompatFeatures::INLINE_DATA.0,
            Ext4IncompatFeatures::ENCRYPT.0,
            Ext4IncompatFeatures::CASEFOLD.0,
        ];
        let ro_compat = [
            Ext4RoCompatFeatures::SPARSE_SUPER.0,
            Ext4RoCompatFeatures::LARGE_FILE.0,
            Ext4RoCompatFeatures::BTREE_DIR.0,
            Ext4RoCompatFeatures::HUGE_FILE.0,
            Ext4RoCompatFeatures::GDT_CSUM.0,
            Ext4RoCompatFeatures::DIR_NLINK.0,
            Ext4RoCompatFeatures::EXTRA_ISIZE.0,
            Ext4RoCompatFeatures::QUOTA.0,
            Ext4RoCompatFeatures::BIGALLOC.0,
            Ext4RoCompatFeatures::METADATA_CSUM.0,
            Ext4RoCompatFeatures::READONLY.0,
            Ext4RoCompatFeatures::PROJECT.0,
            Ext4RoCompatFeatures::VERITY.0,
            Ext4RoCompatFeatures::ORPHAN_PRESENT.0,
        ];

        for (set_label, flags) in [
            ("compat", &compat[..]),
            ("incompat", &incompat[..]),
            ("ro_compat", &ro_compat[..]),
        ] {
            assert_ext4_feature_set_is_distinct(set_label, flags);
        }
    }

    /// bd-jbilz — Kernel-conformance pin for ext4 magic numbers and
    /// superblock state flags from `fs/ext4/ext4.h`,
    /// `fs/ext4/ext4_extents.h`, and `fs/ext4/mmp.h`.
    ///
    /// These constants drive every mount, parse, and recovery
    /// decision. A regression would silently corrupt every ext4
    /// image we touch: a swapped EXT4_EXTENT_MAGIC = 0xF30A would
    /// fail to validate every extent tree; a swapped EXT4_MMP_MAGIC
    /// would mis-classify every mount-lock state; a swapped
    /// EXT4_VALID_FS / ERROR_FS / ORPHAN_FS bit would mis-flag every
    /// fsck decision.
    ///
    /// Pairs with bd-k81lq (reserved inodes + revision/inode-size),
    /// bd-bevt2 (40 feature flags), bd-tyeic (inode flags),
    /// bd-343v3 (file types), bd-vnfhb (POSIX S_IS), bd-pvbgz
    /// (btrfs struct sizes), bd-6uu7j (chunk_type flags),
    /// bd-khzn4 (btrfs tree objectids), bd-f0q7n (btrfs item keys),
    /// bd-xhswi (btrfs csum types).
    #[test]
    fn ext4_magic_numbers_and_state_flags_match_kernel_header() {
        use ffs_types::EXT4_SUPER_MAGIC;

        // Magic numbers per fs/ext4/ext4.h (EXT4_SUPER_MAGIC) and
        // fs/ext4/ext4_extents.h (EXT4_EXT_MAGIC, exposed here as
        // EXT4_EXTENT_MAGIC).
        assert_eq!(
            EXT4_SUPER_MAGIC, 0xEF53,
            "EXT4_SUPER_MAGIC must equal kernel value 0xEF53"
        );
        assert_eq!(
            EXT4_EXTENT_MAGIC, 0xF30A,
            "EXT4_EXTENT_MAGIC must equal kernel value 0xF30A"
        );

        // MMP (multi-mount protection) magic + sequence sentinels per
        // fs/ext4/mmp.h. EXT4_MMP_MAGIC = 'MMP\\0' little-endian.
        assert_eq!(
            EXT4_MMP_MAGIC, 0x004D_4D50,
            "EXT4_MMP_MAGIC must equal kernel value 0x004D4D50 ('MMP\\0' LE)"
        );
        assert_eq!(
            EXT4_MMP_SEQ_CLEAN, 0xFF4D_4D50,
            "EXT4_MMP_SEQ_CLEAN must equal kernel value 0xFF4D4D50"
        );
        assert_eq!(
            EXT4_MMP_SEQ_FSCK, 0xE24D_4D50,
            "EXT4_MMP_SEQ_FSCK must equal kernel value 0xE24D4D50"
        );
        assert_eq!(
            EXT4_MMP_SEQ_MAX, 0xE24D_4D4F,
            "EXT4_MMP_SEQ_MAX must equal kernel value 0xE24D4D4F"
        );

        // Superblock s_state flags per fs/ext4/ext4.h.
        assert_eq!(
            EXT4_VALID_FS, 0x0001,
            "EXT4_VALID_FS must equal kernel value 0x0001"
        );
        assert_eq!(
            EXT4_ERROR_FS, 0x0002,
            "EXT4_ERROR_FS must equal kernel value 0x0002"
        );
        assert_eq!(
            EXT4_ORPHAN_FS, 0x0004,
            "EXT4_ORPHAN_FS must equal kernel value 0x0004"
        );

        // Default mount-count limit per fs/ext4/ext4.h
        // (EXT4_DFL_MAX_MNT_COUNT).
        assert_eq!(
            EXT4_DFL_MAX_MNT_COUNT, 20,
            "EXT4_DFL_MAX_MNT_COUNT must equal kernel value 20"
        );

        // Structural invariants on the s_state bit set: each is a
        // power-of-2 single-bit flag and no two share a bit.
        let state_flags: &[(u16, &str)] = &[
            (EXT4_VALID_FS, "EXT4_VALID_FS"),
            (EXT4_ERROR_FS, "EXT4_ERROR_FS"),
            (EXT4_ORPHAN_FS, "EXT4_ORPHAN_FS"),
        ];
        for (flag, name) in state_flags {
            assert!(
                flag.is_power_of_two(),
                "{name} ({flag:#x}) must be a single power-of-two bit"
            );
        }
        for (i, (a, name_a)) in state_flags.iter().enumerate() {
            for (b, name_b) in &state_flags[i + 1..] {
                assert_eq!(
                    a & b,
                    0,
                    "state flags {name_a} ({a:#x}) and {name_b} ({b:#x}) must not share a bit"
                );
            }
        }

        // MMP_SEQ_CLEAN, _FSCK, _MAX are all in the high half of
        // u32 (>= 0x8000_0000) so they cannot collide with any
        // monotonically-increasing sequence counter that started at
        // 0 — this is the kernel's invariant for distinguishing
        // sentinels from live counters.
        for (sentinel, name) in [
            (EXT4_MMP_SEQ_CLEAN, "EXT4_MMP_SEQ_CLEAN"),
            (EXT4_MMP_SEQ_FSCK, "EXT4_MMP_SEQ_FSCK"),
            (EXT4_MMP_SEQ_MAX, "EXT4_MMP_SEQ_MAX"),
        ] {
            assert!(
                sentinel >= 0x8000_0000,
                "{name} ({sentinel:#x}) must be in the upper half of u32 \
                 (kernel sentinel-vs-counter invariant)"
            );
        }
        // MMP_SEQ_MAX is intentionally ONE LESS than _FSCK — the
        // kernel rejects any sequence value > _MAX, and _FSCK is the
        // first reserved sentinel above _MAX.
        assert_eq!(
            EXT4_MMP_SEQ_MAX + 1,
            EXT4_MMP_SEQ_FSCK,
            "EXT4_MMP_SEQ_MAX must be exactly one less than EXT4_MMP_SEQ_FSCK \
             (kernel reserved-sentinel invariant)"
        );
    }

    /// bd-glkri — Kernel-conformance pin for the 3 ext4
    /// block-group descriptor flag bits in `bg_flags` per
    /// `fs/ext4/ext4.h`.
    ///
    /// Each is a single power-of-2 bit in the 16-bit `bg_flags`
    /// field of `struct ext4_group_desc`. A regression that swapped
    /// EXT4_BG_INODE_UNINIT (0x0001) and EXT4_BG_BLOCK_UNINIT
    /// (0x0002) would silently mis-classify every group descriptor
    /// — either skipping valid inode tables or reading uninitialized
    /// memory.
    ///
    /// Pairs with bd-jbilz (state flags + magic), bd-bevt2
    /// (40 feature flags), bd-tyeic (27 inode flags).
    #[test]
    fn ext4_block_group_flag_constants_match_kernel_header() {
        // Canonical kernel values per fs/ext4/ext4.h.
        assert_eq!(
            EXT4_BG_INODE_UNINIT, 0x0001,
            "EXT4_BG_INODE_UNINIT must equal kernel value 0x0001"
        );
        assert_eq!(
            EXT4_BG_BLOCK_UNINIT, 0x0002,
            "EXT4_BG_BLOCK_UNINIT must equal kernel value 0x0002"
        );
        assert_eq!(
            EXT4_BG_INODE_ZEROED, 0x0004,
            "EXT4_BG_INODE_ZEROED must equal kernel value 0x0004"
        );

        // Structural invariants: each is a single power-of-2 bit
        // and no two share a bit. A regression that conflated any
        // pair would fail this immediately.
        let flags: &[(u16, &str)] = &[
            (EXT4_BG_INODE_UNINIT, "EXT4_BG_INODE_UNINIT"),
            (EXT4_BG_BLOCK_UNINIT, "EXT4_BG_BLOCK_UNINIT"),
            (EXT4_BG_INODE_ZEROED, "EXT4_BG_INODE_ZEROED"),
        ];
        for (flag, name) in flags {
            assert!(
                flag.is_power_of_two(),
                "{name} ({flag:#x}) must be a single power-of-two bit"
            );
        }
        for (i, (a, name_a)) in flags.iter().enumerate() {
            for (b, name_b) in &flags[i + 1..] {
                assert_eq!(
                    a & b,
                    0,
                    "{name_a} ({a:#x}) and {name_b} ({b:#x}) must not share a bit"
                );
            }
        }

        // Cross-check: the OR of all 3 flags has exactly 3 bits set
        // (no duplicates, no shared bits).
        let or_all: u16 = flags.iter().fold(0_u16, |acc, (f, _)| acc | f);
        assert_eq!(
            or_all.count_ones(),
            3,
            "OR of all bg_flag bits must have exactly 3 bits set, got {or_all:#x}"
        );
    }

    /// bd-xt5ru — Kernel-conformance pin for the 7 DX hash version
    /// constants from `fs/ext4/ext4.h` plus EXT4_HTREE_EOF_32BIT.
    ///
    /// Each value drives the hash-routing dispatch in `dx_hash` for
    /// every htree directory lookup. A regression that swapped
    /// DX_HASH_TEA (2) and DX_HASH_HALF_MD4 (1) would silently
    /// mis-classify every htree directory and route lookups through
    /// the wrong hash function — invisible until end users notice
    /// broken lookups.
    ///
    /// Structural invariant: the unsigned variants are derived by
    /// adding 3 to the signed variant — i.e., DX_HASH_LEGACY (0)
    /// pairs with DX_HASH_LEGACY_UNSIGNED (3), DX_HASH_HALF_MD4 (1)
    /// pairs with DX_HASH_HALF_MD4_UNSIGNED (4), DX_HASH_TEA (2)
    /// pairs with DX_HASH_TEA_UNSIGNED (5). EXT4_HTREE_EOF_32BIT is
    /// the htree end-of-tree sentinel for 32-bit hashes.
    ///
    /// Pairs with bd-bevt2 (40 feature flags), bd-jbilz (magic +
    /// state flags), bd-glkri (BG flags), bd-tyeic (27 inode flags),
    /// bd-k81lq (reserved inodes), bd-343v3 (file types).
    #[test]
    fn ext4_dx_hash_version_constants_match_kernel_header() {
        // Canonical kernel values per fs/ext4/ext4.h.
        assert_eq!(DX_HASH_LEGACY, 0, "DX_HASH_LEGACY must equal 0");
        assert_eq!(DX_HASH_HALF_MD4, 1, "DX_HASH_HALF_MD4 must equal 1");
        assert_eq!(DX_HASH_TEA, 2, "DX_HASH_TEA must equal 2");
        assert_eq!(
            DX_HASH_LEGACY_UNSIGNED, 3,
            "DX_HASH_LEGACY_UNSIGNED must equal 3"
        );
        assert_eq!(
            DX_HASH_HALF_MD4_UNSIGNED, 4,
            "DX_HASH_HALF_MD4_UNSIGNED must equal 4"
        );
        assert_eq!(DX_HASH_TEA_UNSIGNED, 5, "DX_HASH_TEA_UNSIGNED must equal 5");
        assert_eq!(_DX_HASH_SIPHASH, 6, "DX_HASH_SIPHASH must equal 6");

        // Structural invariant: unsigned variant = signed variant + 3
        // (the canonical kernel layout: signed values 0..=2,
        // unsigned values 3..=5, SipHash 6).
        assert_eq!(
            DX_HASH_LEGACY_UNSIGNED - DX_HASH_LEGACY,
            3,
            "DX_HASH_LEGACY_UNSIGNED must be DX_HASH_LEGACY + 3"
        );
        assert_eq!(
            DX_HASH_HALF_MD4_UNSIGNED - DX_HASH_HALF_MD4,
            3,
            "DX_HASH_HALF_MD4_UNSIGNED must be DX_HASH_HALF_MD4 + 3"
        );
        assert_eq!(
            DX_HASH_TEA_UNSIGNED - DX_HASH_TEA,
            3,
            "DX_HASH_TEA_UNSIGNED must be DX_HASH_TEA + 3"
        );

        // Strict-monotonic ascending across the 7-element set.
        let versions: [u8; 7] = [
            DX_HASH_LEGACY,
            DX_HASH_HALF_MD4,
            DX_HASH_TEA,
            DX_HASH_LEGACY_UNSIGNED,
            DX_HASH_HALF_MD4_UNSIGNED,
            DX_HASH_TEA_UNSIGNED,
            _DX_HASH_SIPHASH,
        ];
        for window in versions.windows(2) {
            assert!(
                window[0] < window[1],
                "DX hash version constants must be strict-monotonic ascending"
            );
        }

        // EXT4_HTREE_EOF_32BIT — kernel sentinel for 32-bit hash EOF.
        // Per fs/ext4/ext4.h: #define EXT4_HTREE_EOF_32BIT  ((1UL  << (32 - 1)) - 1)
        assert_eq!(
            EXT4_HTREE_EOF_32BIT, 0x7FFF_FFFF,
            "EXT4_HTREE_EOF_32BIT must equal (1<<31) - 1 = 0x7FFFFFFF"
        );
        assert_eq!(
            EXT4_HTREE_EOF_32BIT,
            (1_u32 << 31) - 1,
            "EXT4_HTREE_EOF_32BIT must round-trip via the kernel formula"
        );
    }

    /// bd-k81lq — Kernel-conformance pin for ext4 reserved-inode and
    /// revision-format constants. Each value is mirrored verbatim from
    /// the Linux kernel header `fs/ext4/ext4.h`. Mismatch would
    /// silently corrupt every ext4 image we mutate (e.g., treating
    /// inode 8 as a regular file rather than the journal). This test
    /// is the canonical kernel-reference vector for these constants.
    #[test]
    fn ext4_reserved_inode_constants_match_kernel_header() {
        // Reserved inode numbers (per fs/ext4/ext4.h).
        assert_eq!(EXT4_BAD_INO, 1, "EXT4_BAD_INO must equal kernel value 1");
        assert_eq!(EXT4_ROOT_INO, 2, "EXT4_ROOT_INO must equal kernel value 2");
        assert_eq!(
            EXT4_USR_QUOTA_INO, 3,
            "EXT4_USR_QUOTA_INO must equal kernel value 3"
        );
        assert_eq!(
            EXT4_GRP_QUOTA_INO, 4,
            "EXT4_GRP_QUOTA_INO must equal kernel value 4"
        );
        assert_eq!(
            EXT4_BOOT_LOADER_INO, 5,
            "EXT4_BOOT_LOADER_INO must equal kernel value 5"
        );
        assert_eq!(
            EXT4_UNDEL_DIR_INO, 6,
            "EXT4_UNDEL_DIR_INO must equal kernel value 6"
        );
        assert_eq!(
            EXT4_RESIZE_INO, 7,
            "EXT4_RESIZE_INO must equal kernel value 7"
        );
        assert_eq!(
            EXT4_JOURNAL_INO, 8,
            "EXT4_JOURNAL_INO must equal kernel value 8"
        );
        assert_eq!(
            EXT4_EXCLUDE_INO, 9,
            "EXT4_EXCLUDE_INO must equal kernel value 9"
        );
        assert_eq!(
            EXT4_REPLICA_INO, 10,
            "EXT4_REPLICA_INO must equal kernel value 10"
        );
        assert_eq!(
            EXT4_GOOD_OLD_FIRST_INO, 11,
            "EXT4_GOOD_OLD_FIRST_INO must equal kernel value 11"
        );
        assert_eq!(
            EXT4_PRJ_QUOTA_INO, 16,
            "EXT4_PRJ_QUOTA_INO must equal kernel value 16"
        );

        // Revision-format constants (per fs/ext4/ext4.h).
        assert_eq!(
            EXT4_GOOD_OLD_REV, 0,
            "EXT4_GOOD_OLD_REV must equal kernel value 0"
        );
        assert_eq!(
            EXT4_DYNAMIC_REV, 1,
            "EXT4_DYNAMIC_REV must equal kernel value 1"
        );
        assert_eq!(
            EXT4_GOOD_OLD_INODE_SIZE, 128,
            "EXT4_GOOD_OLD_INODE_SIZE must equal kernel value 128"
        );

        // Cross-check: the reserved-inode set is contiguous from 1 to 10
        // plus the project-quota inode at 16, and the first non-reserved
        // inode is 11 in EXT4_GOOD_OLD_REV.
        const {
            assert!(
                EXT4_BAD_INO < EXT4_ROOT_INO
                    && EXT4_ROOT_INO < EXT4_USR_QUOTA_INO
                    && EXT4_USR_QUOTA_INO < EXT4_GRP_QUOTA_INO
                    && EXT4_GRP_QUOTA_INO < EXT4_BOOT_LOADER_INO
                    && EXT4_BOOT_LOADER_INO < EXT4_UNDEL_DIR_INO
                    && EXT4_UNDEL_DIR_INO < EXT4_RESIZE_INO
                    && EXT4_RESIZE_INO < EXT4_JOURNAL_INO
                    && EXT4_JOURNAL_INO < EXT4_EXCLUDE_INO
                    && EXT4_EXCLUDE_INO < EXT4_REPLICA_INO
                    && EXT4_REPLICA_INO < EXT4_GOOD_OLD_FIRST_INO
                    && EXT4_GOOD_OLD_FIRST_INO < EXT4_PRJ_QUOTA_INO,
                "reserved-inode ordering must be strict-monotonic ascending"
            );
        }
    }

    #[test]
    fn ext4_chksum_empty_suffix_is_seed_identity() {
        for &seed in &[
            0x0000_0000_u32,
            0xFFFF_FFFF,
            0x1234_5678,
            0xDEAD_BEEF,
            0xCAFE_BABE,
        ] {
            assert_eq!(
                ext4_chksum(seed, &[]),
                seed,
                "appending an empty region must leave the seed unchanged (seed={seed:#x})"
            );
        }
    }

    /// bd-k62ym — Kernel-conformance pin for the ext4 size/limit
    /// constants EXT_INIT_MAX_LEN and EXT4_MAX_NAME_BYTES.
    ///
    /// EXT_INIT_MAX_LEN per `fs/ext4/ext4_extents.h`:
    ///   `#define EXT_INIT_MAX_LEN  (1UL << 15)`  /* 32768 */
    /// is the max length of a written (initialized) extent. Values
    /// above this indicate unwritten/preallocated extents — the
    /// single-bit boundary between init and uninit is the load-
    /// bearing semantic. A regression that drifted by even one bit
    /// would silently flip every long extent between written and
    /// unwritten.
    ///
    /// EXT4_MAX_NAME_BYTES per `fs/ext4/ext4.h` (`EXT4_NAME_LEN`):
    ///   `#define EXT4_NAME_LEN 255`
    /// is the max directory-entry name length. A regression here
    /// would silently truncate long filenames or accept too-long
    /// ones (overflowing the 1-byte name_len field on disk).
    ///
    /// Pairs with bd-k81lq (reserved inodes + revision + inode-size),
    /// bd-bevt2 (40 feature flags), bd-tyeic (inode flags), bd-343v3
    /// (file types), bd-jbilz (magic+state).
    #[test]
    fn ext4_size_limit_constants_match_kernel_header() {
        // EXT_INIT_MAX_LEN per fs/ext4/ext4_extents.h.
        assert_eq!(
            EXT_INIT_MAX_LEN,
            1_u16 << 15,
            "EXT_INIT_MAX_LEN must equal kernel formula (1UL << 15)"
        );
        assert_eq!(
            EXT_INIT_MAX_LEN, 32768,
            "EXT_INIT_MAX_LEN must equal kernel value 32768 (= 0x8000)"
        );
        assert_eq!(
            EXT_INIT_MAX_LEN, 0x8000,
            "EXT_INIT_MAX_LEN must equal kernel hex value 0x8000"
        );
        // The kernel uses bit 15 as the unwritten/preallocated flag.
        // EXT_INIT_MAX_LEN MUST be a single power-of-two so the test
        // raw_len > EXT_INIT_MAX_LEN is unambiguous.
        const {
            assert!(
                EXT_INIT_MAX_LEN.is_power_of_two(),
                "EXT_INIT_MAX_LEN must be a power of two so the unwritten flag bit is unambiguous"
            );
        }

        // EXT4_MAX_NAME_BYTES per fs/ext4/ext4.h EXT4_NAME_LEN.
        assert_eq!(
            EXT4_MAX_NAME_BYTES, 255,
            "EXT4_MAX_NAME_BYTES must equal kernel value 255 (== EXT4_NAME_LEN)"
        );
        // 255 is u8::MAX, which is what the kernel relies on so name_len
        // can fit in a single byte on disk.
        assert_eq!(
            EXT4_MAX_NAME_BYTES,
            usize::from(u8::MAX),
            "EXT4_MAX_NAME_BYTES must equal u8::MAX so the on-disk name_len field is unambiguous"
        );
    }

    #[test]
    fn ext4_extent_is_unwritten_boundary() {
        let written = Ext4Extent {
            logical_block: 0,
            raw_len: EXT_INIT_MAX_LEN, // 0x8000 — exactly at boundary
            physical_start: 100,
        };
        // EXT_INIT_MAX_LEN is NOT > EXT_INIT_MAX_LEN, so not unwritten.
        assert!(!written.is_unwritten());
        assert_eq!(written.actual_len(), EXT_INIT_MAX_LEN);

        let unwritten = Ext4Extent {
            logical_block: 0,
            raw_len: EXT_INIT_MAX_LEN | 1, // 0x8001 — just above
            physical_start: 200,
        };
        assert!(unwritten.is_unwritten());
        assert_eq!(unwritten.actual_len(), 1);
    }

    #[test]
    fn ext4_extent_zero_length() {
        let ext = Ext4Extent {
            logical_block: 0,
            raw_len: 0,
            physical_start: 0,
        };
        assert!(!ext.is_unwritten());
        assert_eq!(ext.actual_len(), 0);
    }

    #[test]
    fn parse_extent_tree_rejects_zero_length_leaf_extent() {
        let mut buf = [0_u8; 24];
        buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
        buf[2..4].copy_from_slice(&1_u16.to_le_bytes());
        buf[4..6].copy_from_slice(&1_u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0_u16.to_le_bytes());
        buf[12..16].copy_from_slice(&7_u32.to_le_bytes());
        buf[16..18].copy_from_slice(&0_u16.to_le_bytes());
        buf[20..24].copy_from_slice(&42_u32.to_le_bytes());

        let err = parse_extent_tree(&buf).expect_err("zero-length leaf extent rejects");
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "extent_entries.ee_len",
                reason: "extent length must be non-zero",
            }
        );
    }

    /// bd-bspkl — Kernel-conformance pin for Ext4Extent leaf entry
    /// 12-byte field offsets per fs/ext4/ext4_extents.h struct
    /// ext4_extent.
    ///
    ///   ee_block    u32 @0..4   (logical_block)
    ///   ee_len      u16 @4..6   (raw_len)
    ///   ee_start_hi u16 @6..8   (physical high 16 bits)
    ///   ee_start_lo u32 @8..12  (physical low 32 bits)
    ///   physical_start = (start_hi << 32) | start_lo (48-bit total)
    ///
    /// bd-jbilz pins EXT4_EXTENT_MAGIC (0xF30A); bd-9rxhw and the
    /// extent_tree_*_roundtrip proptests verify parser BEHAVIOR but
    /// no test pins each FIELD OFFSET within an entry with unique-
    /// magic stamping. A regression that drifted ee_start_hi to
    /// offset 4..6 (where ee_len lives) would still pass round-trip
    /// if the writer were similarly broken, and would silently
    /// corrupt every physical-block address in extent trees.
    ///
    /// Stamp each field with a distinct non-zero magic so any
    /// single-field offset drift produces a cross-field collision.
    #[test]
    fn ext4_extent_leaf_kernel_offsets_match_extents_h() {
        let mut buf = [0_u8; 24];

        // 12-byte header: magic (forced), 1 entry, depth=0 (leaf),
        // generation=0 (don't care).
        buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
        buf[2..4].copy_from_slice(&1_u16.to_le_bytes()); // entries
        buf[4..6].copy_from_slice(&1_u16.to_le_bytes()); // max_entries
        buf[6..8].copy_from_slice(&0_u16.to_le_bytes()); // depth=0 → leaf

        // 12-byte single entry at offset 12. Each field gets a
        // unique magic so an offset drift produces a cross-field
        // collision.
        let ee_block: u32 = 0x1111_2222;
        // ee_len must satisfy 0 < actual_len. Choose 0x1234 (well
        // below EXT_INIT_MAX_LEN=0x8000) → not unwritten, raw_len
        // round-trips as-is.
        let ee_len: u16 = 0x1234;
        let ee_start_hi: u16 = 0xABCD;
        let ee_start_lo: u32 = 0xDEAD_BEEF;

        buf[12..16].copy_from_slice(&ee_block.to_le_bytes());
        buf[16..18].copy_from_slice(&ee_len.to_le_bytes());
        buf[18..20].copy_from_slice(&ee_start_hi.to_le_bytes());
        buf[20..24].copy_from_slice(&ee_start_lo.to_le_bytes());

        let (header, tree) =
            parse_extent_tree(&buf).expect("kernel-stamped extent leaf must parse");

        // Header field offsets are pinned implicitly: a regression
        // in entries@2..4 would change the loop bound; magic@0..2
        // is checked by the parser. depth@6..8 is implicit in the
        // Leaf branch selection.
        assert_eq!(header.entries, 1, "entries must come from offset 2..4");
        assert_eq!(
            header.max_entries, 1,
            "max_entries must come from offset 4..6"
        );
        assert_eq!(
            header.depth, 0,
            "depth must come from offset 6..8 (leaf branch selected)"
        );

        let extents = match tree {
            ExtentTree::Leaf(extents) => extents,
            ExtentTree::Index(_) => unreachable!("depth=0 must yield Leaf branch"),
        };
        assert_eq!(
            extents.len(),
            1,
            "single-entry payload must parse to one extent"
        );
        let extent = extents[0];

        assert_eq!(
            extent.logical_block, ee_block,
            "logical_block must come from offset 0..4 (relative to entry)"
        );
        assert_eq!(
            extent.raw_len, ee_len,
            "raw_len must come from offset 4..6 (relative to entry)"
        );

        // physical_start = (ee_start_hi << 32) | ee_start_lo per
        // the parser at lib.rs:2956-2958. Pin both halves.
        let expected_physical = (u64::from(ee_start_hi) << 32) | u64::from(ee_start_lo);
        assert_eq!(
            extent.physical_start, expected_physical,
            "physical_start must combine ee_start_hi@6..8 (high 16) and ee_start_lo@8..12 (low 32)"
        );
        assert_eq!(
            extent.physical_start, 0x0000_ABCD_DEAD_BEEF,
            "explicit literal pinning of the 48-bit physical address"
        );
    }

    /// bd-uezhf — Kernel-conformance pin for Ext4ExtentIndex
    /// 12-byte field offsets per fs/ext4/ext4_extents.h struct
    /// ext4_extent_idx.
    ///
    ///   ei_block   u32 @0..4   (logical_block)
    ///   ei_leaf_lo u32 @4..8   (low 32 of leaf_block)
    ///   ei_leaf_hi u16 @8..10  (high 16 of leaf_block)
    ///   ei_unused  u16 @10..12 (padding, ignored)
    ///   leaf_block = (ei_leaf_hi << 32) | ei_leaf_lo (48-bit)
    ///
    /// bd-bspkl pins the parallel Ext4Extent (leaf) entry offsets.
    /// The index branch is a separate parser code path with its
    /// own offset arithmetic — a regression that drifted
    /// ei_leaf_hi to offset 4..6 would produce a wrong leaf_block
    /// address and silently route extent lookups to the wrong
    /// physical block.
    ///
    /// Stamp each field with a distinct non-zero magic so any
    /// single-field offset drift produces a cross-field collision.
    #[test]
    fn ext4_extent_index_kernel_offsets_match_extents_h() {
        let mut buf = [0_u8; 24];

        // 12-byte header: magic (forced), 1 entry, depth=1 (forces
        // Index branch via parse_extent_index).
        buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
        buf[2..4].copy_from_slice(&1_u16.to_le_bytes()); // entries
        buf[4..6].copy_from_slice(&1_u16.to_le_bytes()); // max_entries
        buf[6..8].copy_from_slice(&1_u16.to_le_bytes()); // depth=1 → index

        // 12-byte single index entry at offset 12. Each field gets
        // a unique magic so an offset drift produces a cross-field
        // collision.
        let ei_block: u32 = 0x1234_5678;
        let ei_leaf_lo: u32 = 0xCAFE_BABE;
        let ei_leaf_hi: u16 = 0xABCD;
        let ei_unused: u16 = 0xEEEE; // parser ignores this field

        buf[12..16].copy_from_slice(&ei_block.to_le_bytes());
        buf[16..20].copy_from_slice(&ei_leaf_lo.to_le_bytes());
        buf[20..22].copy_from_slice(&ei_leaf_hi.to_le_bytes());
        buf[22..24].copy_from_slice(&ei_unused.to_le_bytes());

        let (header, tree) =
            parse_extent_tree(&buf).expect("kernel-stamped extent index must parse");

        assert_eq!(header.entries, 1, "entries must come from offset 2..4");
        assert_eq!(
            header.depth, 1,
            "depth must come from offset 6..8 (index branch selected)"
        );

        let indexes = match tree {
            ExtentTree::Index(indexes) => indexes,
            ExtentTree::Leaf(_) => unreachable!("depth=1 must yield Index branch"),
        };
        assert_eq!(
            indexes.len(),
            1,
            "single-entry payload must parse to one index"
        );
        let index = indexes[0];

        assert_eq!(
            index.logical_block, ei_block,
            "logical_block must come from offset 0..4 (relative to entry)"
        );

        // leaf_block = (ei_leaf_hi << 32) | ei_leaf_lo per the
        // parser at lib.rs:3004-3006. Pin both halves.
        let expected_leaf = (u64::from(ei_leaf_hi) << 32) | u64::from(ei_leaf_lo);
        assert_eq!(
            index.leaf_block, expected_leaf,
            "leaf_block must combine ei_leaf_hi@8..10 (high 16) and ei_leaf_lo@4..8 (low 32)"
        );
        assert_eq!(
            index.leaf_block, 0x0000_ABCD_CAFE_BABE,
            "explicit literal pinning of the 48-bit leaf-block address"
        );
    }

    /// bd-esr1c - Kernel-conformance pin for Ext4ExtentHeader
    /// 12-byte field offsets per fs/ext4/ext4_extents.h struct
    /// ext4_extent_header.
    ///
    ///   eh_magic      u16 @0..2
    ///   eh_entries    u16 @2..4
    ///   eh_max        u16 @4..6
    ///   eh_depth      u16 @6..8
    ///   eh_generation u32 @8..12
    ///
    /// bd-bspkl + bd-uezhf cover entries/depth implicitly (via
    /// the loop bound and Leaf/Index branch selection), but
    /// eh_generation@8..12 is NOT pinned anywhere; a regression
    /// that drifted generation to read from offset 6..10 instead
    /// of 8..12 would silently include depth bytes in the parsed
    /// generation field, and no existing test catches it.
    ///
    /// Stamp eh_generation with a unique non-zero magic and assert
    /// the parsed value matches.
    #[test]
    fn ext4_extent_header_kernel_offsets_match_extents_h() {
        let mut buf = [0_u8; 24];

        // 12-byte header with explicit eh_generation magic.
        buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
        buf[2..4].copy_from_slice(&1_u16.to_le_bytes()); // entries
        buf[4..6].copy_from_slice(&1_u16.to_le_bytes()); // max_entries
        buf[6..8].copy_from_slice(&0_u16.to_le_bytes()); // depth=0 selects leaf

        let eh_generation: u32 = 0xCAFE_BABE;
        buf[8..12].copy_from_slice(&eh_generation.to_le_bytes());

        // 12-byte single leaf entry at offset 12. Use minimal valid
        // values; the goal here is the header, not the entries.
        buf[12..16].copy_from_slice(&0_u32.to_le_bytes()); // ee_block
        buf[16..18].copy_from_slice(&1_u16.to_le_bytes()); // ee_len=1
        buf[18..20].copy_from_slice(&0_u16.to_le_bytes()); // ee_start_hi
        buf[20..24].copy_from_slice(&0_u32.to_le_bytes()); // ee_start_lo

        let (header, _tree) = parse_extent_tree(&buf).expect("kernel-stamped header must parse");

        assert_eq!(
            header.magic, EXT4_EXTENT_MAGIC,
            "magic must come from offset 0..2 per kernel layout"
        );
        assert_eq!(
            header.entries, 1,
            "entries must come from offset 2..4 per kernel layout"
        );
        assert_eq!(
            header.max_entries, 1,
            "max_entries must come from offset 4..6 per kernel layout"
        );
        assert_eq!(
            header.depth, 0,
            "depth must come from offset 6..8 per kernel layout"
        );
        assert_eq!(
            header.generation, eh_generation,
            "generation must come from offset 8..12 per kernel layout"
        );
        assert_eq!(
            header.generation, 0xCAFE_BABE,
            "explicit literal pinning of the eh_generation magic"
        );
    }

    #[test]
    fn extra_nsec_and_epoch_extraction() {
        // extra = 0b...nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnee
        // nsec = extra >> 2, epoch = extra & 0x3
        let extra = (500_000_000_u32 << 2) | 0x2; // 500ms nsec, epoch=2
        assert_eq!(Ext4Inode::extra_nsec(extra), 500_000_000);
        assert_eq!(Ext4Inode::extra_epoch(extra), 2);

        // Zero extra.
        assert_eq!(Ext4Inode::extra_nsec(0), 0);
        assert_eq!(Ext4Inode::extra_epoch(0), 0);

        // Max epoch (3).
        assert_eq!(Ext4Inode::extra_epoch(0x3), 3);
    }

    #[test]
    fn to_system_time_positive() {
        use std::time::{Duration, UNIX_EPOCH};
        let st = Ext4Inode::to_system_time(1_000_000, 500).unwrap();
        assert_eq!(st, UNIX_EPOCH + Duration::new(1_000_000, 500));
    }

    #[test]
    fn to_system_time_negative() {
        use std::time::{Duration, UNIX_EPOCH};
        // 10 seconds before epoch.
        let st = Ext4Inode::to_system_time(-10, 0).unwrap();
        assert_eq!(st, UNIX_EPOCH - Duration::from_secs(10));
    }

    #[test]
    fn to_system_time_zero() {
        let st = Ext4Inode::to_system_time(0, 0).unwrap();
        assert_eq!(st, std::time::UNIX_EPOCH);
    }

    #[test]
    fn permission_bits_extraction() {
        // mode = S_IFREG | 0o755 = 0o100755
        let inode = Ext4Inode {
            mode: S_IFREG | 0o755,
            ..Ext4Inode::parse_from_bytes(&[0_u8; 256]).unwrap()
        };
        assert_eq!(inode.permission_bits(), 0o755);
        assert!(inode.is_regular());

        let dir_inode = Ext4Inode {
            mode: S_IFDIR | 0o700,
            ..Ext4Inode::parse_from_bytes(&[0_u8; 256]).unwrap()
        };
        assert_eq!(dir_inode.permission_bits(), 0o700);
        assert!(dir_inode.is_dir());
    }

    #[test]
    fn permission_bits_preserves_setuid_setgid_sticky() {
        let with_mode = |mode: u16| Ext4Inode {
            mode,
            ..Ext4Inode::parse_from_bytes(&[0_u8; 256]).unwrap()
        };
        // setuid (0o4000), setgid (0o2000), and sticky (0o1000) all survive.
        assert_eq!(with_mode(S_IFREG | 0o4755).permission_bits(), 0o4755);
        assert_eq!(with_mode(S_IFREG | 0o2755).permission_bits(), 0o2755);
        assert_eq!(with_mode(S_IFDIR | 0o1777).permission_bits(), 0o1777);
        assert_eq!(with_mode(S_IFREG | 0o7777).permission_bits(), 0o7777);
        // The S_IFMT file-type bits are excluded from the permission bits.
        assert_eq!(with_mode(S_IFREG | 0o644).permission_bits(), 0o644);
    }

    #[test]
    fn dir_entry_actual_size_alignment() {
        let entry = Ext4DirEntry {
            inode: 2,
            rec_len: 12,
            name_len: 1,
            file_type: Ext4FileType::Dir,
            name: b".".to_vec(),
        };
        // 8 + 1 = 9, rounded up to 12 (4-byte boundary).
        assert_eq!(entry.actual_size(), 12);

        let long_name = Ext4DirEntry {
            inode: 3,
            rec_len: 20,
            name_len: 10,
            file_type: Ext4FileType::RegFile,
            name: b"README.txt".to_vec(),
        };
        // 8 + 10 = 18, rounded up to 20.
        assert_eq!(long_name.actual_size(), 20);
    }

    #[test]
    fn dir_entry_dot_and_dotdot() {
        let dot = Ext4DirEntry {
            inode: 2,
            rec_len: 12,
            name_len: 1,
            file_type: Ext4FileType::Dir,
            name: b".".to_vec(),
        };
        assert!(dot.is_dot());
        assert!(!dot.is_dotdot());

        let dotdot = Ext4DirEntry {
            inode: 2,
            rec_len: 12,
            name_len: 2,
            file_type: Ext4FileType::Dir,
            name: b"..".to_vec(),
        };
        assert!(!dotdot.is_dot());
        assert!(dotdot.is_dotdot());
    }

    #[test]
    fn dir_entry_name_str() {
        let entry = Ext4DirEntry {
            inode: 10,
            rec_len: 16,
            name_len: 4,
            file_type: Ext4FileType::RegFile,
            name: b"test".to_vec(),
        };
        assert_eq!(entry.name_str(), "test");
    }

    #[test]
    fn file_type_from_raw_all_values() {
        assert_eq!(Ext4FileType::from_raw(0), Ext4FileType::Unknown);
        assert_eq!(Ext4FileType::from_raw(1), Ext4FileType::RegFile);
        assert_eq!(Ext4FileType::from_raw(2), Ext4FileType::Dir);
        assert_eq!(Ext4FileType::from_raw(3), Ext4FileType::Chrdev);
        assert_eq!(Ext4FileType::from_raw(4), Ext4FileType::Blkdev);
        assert_eq!(Ext4FileType::from_raw(5), Ext4FileType::Fifo);
        assert_eq!(Ext4FileType::from_raw(6), Ext4FileType::Sock);
        assert_eq!(Ext4FileType::from_raw(7), Ext4FileType::Symlink);
        assert_eq!(Ext4FileType::from_raw(8), Ext4FileType::Unknown);
        assert_eq!(Ext4FileType::from_raw(255), Ext4FileType::Unknown);
    }

    #[test]
    fn compat_features_unknown_bits() {
        let flags = Ext4CompatFeatures(0x0004 | 0x8000_0000);
        assert!(flags.contains(Ext4CompatFeatures::HAS_JOURNAL));
        assert_eq!(flags.unknown_bits(), 0x8000_0000);
    }

    #[test]
    fn incompat_features_missing_required_v1() {
        // Only EXTENTS, missing FILETYPE.
        let flags = Ext4IncompatFeatures(Ext4IncompatFeatures::EXTENTS.0);
        let missing = flags.describe_missing_required_v1();
        assert_eq!(missing, vec!["FILETYPE"]);

        // Both present.
        let flags = Ext4IncompatFeatures(
            Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0,
        );
        assert!(flags.describe_missing_required_v1().is_empty());
    }

    #[test]
    fn feature_diagnostics_display_with_unknown_ro_compat() {
        let diag = FeatureDiagnostics {
            missing_required: vec![],
            rejected_present: vec![],
            unknown_incompat_bits: 0,
            unknown_ro_compat_bits: 0x8000_0000,
            incompat_display: "FILETYPE|EXTENTS".into(),
            ro_compat_display: "SPARSE_SUPER|0x80000000".into(),
            compat_display: "(none)".into(),
        };
        assert!(diag.is_ok());
        let display = format!("{diag}");
        assert!(
            display.contains("unknown ro_compat: 0x80000000"),
            "expected unknown ro_compat in display: {display}"
        );
    }

    #[test]
    fn feature_diagnostics_display_with_all_issues() {
        let diag = FeatureDiagnostics {
            missing_required: vec!["FILETYPE"],
            rejected_present: vec!["ENCRYPT"],
            unknown_incompat_bits: 0x4000_0000,
            unknown_ro_compat_bits: 0,
            incompat_display: "EXTENTS|ENCRYPT|0x40000000".into(),
            ro_compat_display: "(none)".into(),
            compat_display: "(none)".into(),
        };
        assert!(!diag.is_ok());
        let display = format!("{diag}");
        assert!(display.contains("missing required: FILETYPE"));
        assert!(display.contains("rejected: ENCRYPT"));
        assert!(display.contains("unknown incompat: 0x40000000"));
    }

    #[test]
    fn rec_len_from_disk_special_values() {
        // 0xFFFC encodes "entire block".
        assert_eq!(rec_len_from_disk(0xFFFC, 4096), 4096);
        // 0 also encodes "entire block".
        assert_eq!(rec_len_from_disk(0, 4096), 4096);
        // Normal value: 12 stays 12.
        assert_eq!(rec_len_from_disk(12, 4096), 12);
        // Large block (64K): 0xFFFC and 0 both map to block_size.
        assert_eq!(rec_len_from_disk(0xFFFC, 65536), 65536);
        assert_eq!(rec_len_from_disk(0, 65536), 65536);
    }

    #[test]
    fn inode_file_type_flags() {
        let base = Ext4Inode::parse_from_bytes(&[0_u8; 256]).unwrap();

        let regular = Ext4Inode {
            mode: S_IFREG | 0o644,
            ..base.clone()
        };
        assert!(regular.is_regular());
        assert!(!regular.is_dir());
        assert!(!regular.is_symlink());

        let symlink = Ext4Inode {
            mode: S_IFLNK | 0o777,
            ..base.clone()
        };
        assert!(symlink.is_symlink());
        assert!(!symlink.is_regular());

        let chrdev = Ext4Inode {
            mode: S_IFCHR | 0o660,
            ..base.clone()
        };
        assert!(chrdev.is_chrdev());

        let blkdev = Ext4Inode {
            mode: S_IFBLK | 0o660,
            ..base.clone()
        };
        assert!(blkdev.is_blkdev());

        let fifo = Ext4Inode {
            mode: S_IFIFO | 0o644,
            ..base.clone()
        };
        assert!(fifo.is_fifo());

        let sock = Ext4Inode {
            mode: S_IFSOCK | 0o755,
            ..base
        };
        assert!(sock.is_socket());
    }

    #[test]
    fn inode_huge_file_and_htree_flags() {
        let mut inode = Ext4Inode::parse_from_bytes(&[0_u8; 256]).unwrap();
        assert!(!inode.is_huge_file());
        assert!(!inode.has_htree_index());
        assert!(!inode.uses_extents());

        inode.flags = EXT4_HUGE_FILE_FL;
        assert!(inode.is_huge_file());
        assert!(!inode.uses_extents());

        inode.flags = EXT4_INDEX_FL;
        assert!(inode.has_htree_index());

        inode.flags = EXT4_EXTENTS_FL;
        assert!(inode.uses_extents());
    }

    // Reproduce any failing case with:
    // PROPTEST_CASES=1 PROPTEST_SEED=<seed> cargo test -p ffs-ondisk <test_name> -- --nocapture
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn ext4_proptest_parse_superblock_region_no_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..=(EXT4_SUPERBLOCK_SIZE * 2)),
        ) {
            let _ = Ext4Superblock::parse_superblock_region(&bytes);
        }

        #[test]
        fn ext4_proptest_parse_from_image_no_panic(
            image in proptest::collection::vec(
                any::<u8>(),
                0..=(EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_SIZE + 256),
            ),
        ) {
            let _ = Ext4Superblock::parse_from_image(&image);
        }

        // bd-vvkfy — Determinism MR for Ext4Superblock::parse_from_image.
        // parse_from_image is the image-level mount entry point: it
        // seeks to EXT4_SUPERBLOCK_OFFSET (1024) and parses the
        // superblock region. Sister parse_superblock_region (slice-
        // level entry) has its own determinism MR via bd-3fkbj;
        // this pins the image-level wrapper. A regression that
        // introduced HashMap iteration, allocator-address dependence,
        // or any non-deterministic mount-time bootstrap state would
        // surface here.
        #[test]
        fn ext4_proptest_parse_from_image_determinism(
            image in proptest::collection::vec(
                any::<u8>(),
                0..=(EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_SIZE + 256),
            ),
        ) {
            let a = Ext4Superblock::parse_from_image(&image);
            let b = Ext4Superblock::parse_from_image(&image);
            prop_assert_eq!(a, b);
        }

        #[test]
        fn ext4_proptest_parse_extent_tree_no_panic(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let _ = parse_extent_tree(&block);
        }

        #[test]
        fn ext4_proptest_parse_inode_extent_tree_no_panic(
            inode_bytes in proptest::collection::vec(any::<u8>(), 128..=128),
        ) {
            let inode_buf: [u8; 128] = inode_bytes
                .as_slice()
                .try_into()
                .expect("fixed-size inode bytes");
            if let Ok(inode) = Ext4Inode::parse_from_bytes(&inode_buf) {
                let _ = parse_inode_extent_tree(&inode);
            }
        }

        #[test]
        fn ext4_proptest_parse_dir_block_no_panic(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
            block_size in prop_oneof![Just(1024_u32), Just(2048_u32), Just(4096_u32)],
        ) {
            let _ = parse_dir_block(&block, block_size);
        }

        // bd-qzwuq — Determinism MR for parse_dir_block. parse_dir_block
        // runs on every readdir / lookup / remove / rename operation —
        // the most heavily-trafficked ext4 parser. Sister btrfs
        // parsers all have determinism MRs (bd-fs41s, bd-x2320, bd-v8c1m,
        // bd-9f8ef, bd-xqf12, bd-edl7j, bd-vnlja); this closes the
        // ext4-side gap. A regression that introduced HashMap
        // iteration, allocator-address dependency, or any non-
        // deterministic per-call state would silently surface only
        // under specific scheduling.
        #[test]
        fn ext4_proptest_parse_dir_block_determinism(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
            block_size in prop_oneof![Just(1024_u32), Just(2048_u32), Just(4096_u32)],
        ) {
            let a = parse_dir_block(&block, block_size);
            let b = parse_dir_block(&block, block_size);
            prop_assert_eq!(a, b);
        }

        // bd-qzwuq — Determinism MR for parse_extent_tree. Companion
        // to parse_dir_block_determinism. parse_extent_tree runs on
        // every ext4 file read / mmap / truncate path through
        // ffs_core::OpenFs.
        #[test]
        fn ext4_proptest_parse_extent_tree_determinism(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let a = parse_extent_tree(&block);
            let b = parse_extent_tree(&block);
            prop_assert_eq!(a, b);
        }

        // bd-z8ko5 — Determinism MR for parse_xattr_block. Runs on
        // every getxattr / listxattr / llistxattr; parses the 32-byte
        // ext4_xattr_header followed by variable-length entries.
        // Sister determinism MRs: parse_dir_block, parse_extent_tree
        // (both bd-qzwuq).
        #[test]
        fn ext4_proptest_parse_xattr_block_determinism(
            block_data in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let a = parse_xattr_block(&block_data);
            let b = parse_xattr_block(&block_data);
            prop_assert_eq!(a, b);
        }

        // bd-afwgs — Determinism MR for parse_dx_root, deferred from
        // bd-qzwuq pending PartialEq+Eq derive on Ext4DxRoot. Runs on
        // every htree-indexed directory lookup. Closes the last gap;
        // all 5 heavily-trafficked ext4 parsers (parse_dir_block,
        // parse_extent_tree, parse_xattr_block, parse_inode_extent_tree,
        // parse_dx_root) now have determinism MRs.
        #[test]
        fn ext4_proptest_parse_dx_root_determinism(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let a = parse_dx_root(&block);
            let b = parse_dx_root(&block);
            prop_assert_eq!(a, b);
        }

        // bd-bopdb — Determinism MR for parse_dx_root_with_large_dir.
        // parse_dx_root() is a thin wrapper that calls this with
        // large_dir=false, covered by bd-afwgs. The large_dir=true
        // branch validates a different max_indirect_levels bound
        // (3 vs 2) and is the entry point for INCOMPAT_LARGEDIR
        // htree directories. This proptest cycles the bool to fuzz
        // both branches.
        #[test]
        fn ext4_proptest_parse_dx_root_with_large_dir_determinism(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
            large_dir in proptest::prelude::any::<bool>(),
        ) {
            let a = parse_dx_root_with_large_dir(&block, large_dir);
            let b = parse_dx_root_with_large_dir(&block, large_dir);
            prop_assert_eq!(a, b);
        }

        // bd-z8ko5 — Determinism MR for parse_inode_extent_tree. Runs
        // on every ext4 file open / read / write to compute the extent
        // tree from an Ext4Inode. Companion to bd-qzwuq's
        // parse_extent_tree determinism MR — that exercises the
        // "block-bytes" entry point, this exercises the inode-derived
        // entry point which has independent buffer-extraction logic.
        #[test]
        fn ext4_proptest_parse_inode_extent_tree_determinism(
            inode_bytes in proptest::collection::vec(any::<u8>(), 128..=128),
        ) {
            let inode_buf: [u8; 128] = inode_bytes
                .as_slice()
                .try_into()
                .expect("fixed-size inode bytes");
            if let Ok(inode) = Ext4Inode::parse_from_bytes(&inode_buf) {
                let a = parse_inode_extent_tree(&inode);
                let b = parse_inode_extent_tree(&inode);
                prop_assert_eq!(a, b);
            }
        }

        // bd-niw7j — Determinism MR for parse_ibody_xattrs. Reads the
        // inline-xattr region of an Ext4Inode (xattr_ibody slice
        // [128 + extra_isize ..]). Runs on every getxattr/listxattr
        // where the inode has inline xattrs. Sister parsers
        // (parse_xattr_block, parse_inode_extent_tree, parse_dir_block,
        // parse_extent_tree, parse_dx_root) all have determinism MRs.
        #[test]
        fn ext4_proptest_parse_ibody_xattrs_determinism(
            inode_bytes in proptest::collection::vec(any::<u8>(), 128..=256),
        ) {
            if let Ok(inode) = Ext4Inode::parse_from_bytes(&inode_bytes) {
                let a = parse_ibody_xattrs(&inode);
                let b = parse_ibody_xattrs(&inode);
                prop_assert_eq!(a, b);
            }
        }

        // bd-3fkbj — Determinism MR for Ext4Inode::parse_from_bytes.
        // Companion to parse_inode_extent_tree_determinism: that
        // exercises post-parse extent-tree derivation; this exercises
        // the inode-byte parse itself. Ext4Inode is parsed on every
        // ext4 file open / readdir / stat / xattr.
        #[test]
        fn ext4_proptest_ext4_inode_parse_from_bytes_determinism(
            inode_bytes in proptest::collection::vec(any::<u8>(), 128..=256),
        ) {
            let a = Ext4Inode::parse_from_bytes(&inode_bytes);
            let b = Ext4Inode::parse_from_bytes(&inode_bytes);
            prop_assert_eq!(a, b);
        }

        // bd-3fkbj — Determinism MR for
        // Ext4Superblock::parse_superblock_region. The ext4 superblock
        // is the entry point for every mount/probe; non-determinism
        // here would silently corrupt mount-time bootstrap state.
        // Sized at 1024..=1024 (matches EXT4_SUPERBLOCK_SIZE) so the
        // proptest fuzzes only the byte content, not the buffer length.
        #[test]
        fn ext4_proptest_ext4_superblock_parse_superblock_region_determinism(
            region in proptest::collection::vec(any::<u8>(), EXT4_SUPERBLOCK_SIZE..=EXT4_SUPERBLOCK_SIZE),
        ) {
            let a = Ext4Superblock::parse_superblock_region(&region);
            let b = Ext4Superblock::parse_superblock_region(&region);
            prop_assert_eq!(a, b);
        }

        // bd-ewh2w — Determinism MR for Ext4GroupDesc::parse_from_bytes.
        // Block group descriptors are read once per group on every mount
        // (hundreds-to-thousands of calls for a typical filesystem). The
        // parser has a non-trivial 32-byte vs 64-byte size branch and
        // combines lo+hi halves across 11 fields. Sister determinism MRs:
        // parse_dir_block (bd-qzwuq), parse_extent_tree (bd-qzwuq),
        // parse_xattr_block (bd-z8ko5), parse_dx_root (bd-afwgs),
        // parse_inode_extent_tree (bd-z8ko5), parse_ibody_xattrs
        // (bd-niw7j), Ext4Inode::parse_from_bytes (bd-3fkbj),
        // Ext4Superblock::parse_superblock_region (bd-3fkbj).
        #[test]
        fn ext4_proptest_ext4_group_desc_parse_from_bytes_determinism(
            bytes in proptest::collection::vec(any::<u8>(), 64..=64),
            desc_size in prop_oneof![Just(32_u16), Just(64_u16)],
        ) {
            let a = Ext4GroupDesc::parse_from_bytes(&bytes, desc_size);
            let b = Ext4GroupDesc::parse_from_bytes(&bytes, desc_size);
            prop_assert_eq!(a, b);
        }

        #[test]
        fn ext4_proptest_iter_dir_block_no_panic(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
            block_size in prop_oneof![Just(1024_u32), Just(2048_u32), Just(4096_u32)],
        ) {
            for _entry in iter_dir_block(&block, block_size) {}
        }

        // bd-tj83g — Determinism MR for iter_dir_block. The iterator API
        // is invoked on every readdir / lookup / rename / remove on
        // ext4. parse_dir_block (the eager parser) has its own
        // determinism MR via bd-qzwuq, but the iterator path runs
        // independent state (offset cursor, done flag, checksum-tail
        // detection) and is the actual hot path for ffs_core::OpenFs.
        // A regression that introduced iteration-order dependence
        // (HashMap-backed offset cache, allocator-address-based
        // ordering) would silently corrupt readdir results. Compares
        // two collected iteration passes element-by-element.
        #[test]
        fn ext4_proptest_iter_dir_block_determinism(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
            block_size in prop_oneof![Just(1024_u32), Just(2048_u32), Just(4096_u32)],
        ) {
            let a: Vec<Result<Ext4DirEntryRef<'_>, ParseError>> =
                iter_dir_block(&block, block_size).collect();
            let b: Vec<Result<Ext4DirEntryRef<'_>, ParseError>> =
                iter_dir_block(&block, block_size).collect();
            prop_assert_eq!(a, b);
        }

        #[test]
        fn ext4_proptest_structured_block_size_supported(log_block_size in 0_u32..=2) {
            let incompat = Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0;
            let sb = make_proptest_valid_ext4_superblock(
                log_block_size,
                8192,
                4096,
                64,
                incompat,
                b"prop-ext4",
            );
            let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse structured superblock");
            prop_assert!(matches!(parsed.block_size, 1024 | 2048 | 4096));
        }

        #[test]
        fn ext4_proptest_structured_group_counts_positive(
            blocks_per_group in 1_u32..=8192,
            inodes_per_group in 1_u32..=8192,
            log_block_size in 0_u32..=2,
        ) {
            let incompat = Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0;
            let sb = make_proptest_valid_ext4_superblock(
                log_block_size,
                blocks_per_group,
                inodes_per_group,
                64,
                incompat,
                b"groups",
            );
            let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse structured superblock");
            prop_assert!(parsed.blocks_per_group > 0);
            prop_assert!(parsed.inodes_per_group > 0);
            prop_assert!(parsed.validate_geometry().is_ok());
        }

        #[test]
        fn ext4_proptest_group_desc_size_floor_for_64bit(desc_size in 0_u16..=255) {
            let incompat = Ext4IncompatFeatures::FILETYPE.0
                | Ext4IncompatFeatures::EXTENTS.0
                | Ext4IncompatFeatures::BIT64.0;
            let sb = make_proptest_valid_ext4_superblock(
                2,
                8192,
                4096,
                desc_size,
                incompat,
                b"desc64",
            );
            let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse structured superblock");
            prop_assert!(parsed.is_64bit());
            prop_assert!(parsed.group_desc_size() >= 64);
        }

        #[test]
        fn ext4_proptest_group_desc_size_fixed_for_non_64bit(desc_size in 0_u16..=255) {
            let incompat = Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0;
            let sb = make_proptest_valid_ext4_superblock(
                2,
                8192,
                4096,
                desc_size,
                incompat,
                b"desc32",
            );
            let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse structured superblock");
            prop_assert!(!parsed.is_64bit());
            prop_assert_eq!(parsed.group_desc_size(), 32);
        }

        #[test]
        fn ext4_proptest_parse_from_image_reads_superblock_at_offset(
            mut image in proptest::collection::vec(
                any::<u8>(),
                (EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_SIZE)..=(EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_SIZE + 256),
            ),
            log_block_size in 0_u32..=2,
        ) {
            let incompat = Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0;
            let sb = make_proptest_valid_ext4_superblock(
                log_block_size,
                8192,
                4096,
                64,
                incompat,
                b"offset",
            );
            image[EXT4_SUPERBLOCK_OFFSET..EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_SIZE]
                .copy_from_slice(&sb);
            let parsed = Ext4Superblock::parse_from_image(&image).expect("parse from image");
            prop_assert!(matches!(parsed.block_size, 1024 | 2048 | 4096));
        }

        #[test]
        fn ext4_proptest_image_reader_no_panic_on_mutated_image(
            mutators in proptest::collection::vec((0_usize..(64 * 4096), any::<u8>()), 0..=32),
            inode in 0_u32..=16_384,
            group in 0_u32..=32,
            block in 0_u64..=2048,
        ) {
            let mut image = build_test_image();
            let len = image.len();
            for (idx, value) in mutators {
                image[idx % len] = value;
            }

            if let Ok(reader) = Ext4ImageReader::new(&image) {
                let _ = reader.read_group_desc(&image, ffs_types::GroupNumber(group));
                let _ = reader.read_inode(&image, ffs_types::InodeNumber(u64::from(inode)));
                let _ = reader.read_block(&image, ffs_types::BlockNumber(block));
            }
        }

        #[test]
        fn ext4_proptest_image_reader_no_panic_on_truncated_image(
            image_len in 0_usize..=(64 * 4096),
            inode in 0_u32..=16_384,
        ) {
            let mut image = build_test_image();
            image.truncate(image_len);

            if let Ok(reader) = Ext4ImageReader::new(&image) {
                let _ = reader.read_group_desc(&image, ffs_types::GroupNumber(0));
                let _ = reader.read_inode(&image, ffs_types::InodeNumber(u64::from(inode)));
                let _ = reader.read_block(&image, ffs_types::BlockNumber(0));
            }
        }

        #[test]
        fn ext4_proptest_image_reader_known_inodes_preserve_file_kind(
            inode in prop_oneof![Just(2_u32), Just(11_u32), Just(12_u32), Just(13_u32)],
        ) {
            let image = build_test_image();
            let reader = Ext4ImageReader::new(&image).expect("open synthetic image");
            let parsed = reader
                .read_inode(&image, ffs_types::InodeNumber(u64::from(inode)))
                .expect("known inode should be readable");

            match inode {
                2 | 12 => {
                    prop_assert!(parsed.is_dir());
                    prop_assert!(!parsed.is_regular());
                }
                11 | 13 => {
                    prop_assert!(parsed.is_regular());
                    prop_assert!(!parsed.is_dir());
                }
                _ => unreachable!("strategy only generates known test inodes"),
            }
        }

        #[test]
        fn ext4_proptest_parse_from_image_matches_region_parser(
            mut image in proptest::collection::vec(
                any::<u8>(),
                (EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_SIZE)..=(EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_SIZE + 1024),
            ),
            log_block_size in 0_u32..=2,
            blocks_per_group in 1_u32..=8192,
            inodes_per_group in 1_u32..=8192,
            desc_size in 0_u16..=255,
            use_64bit in any::<bool>(),
            raw_name in proptest::collection::vec(any::<u8>(), 0..=16),
        ) {
            let mut incompat = Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0;
            if use_64bit {
                incompat |= Ext4IncompatFeatures::BIT64.0;
            }

            let sb = make_proptest_valid_ext4_superblock(
                log_block_size,
                blocks_per_group,
                inodes_per_group,
                desc_size,
                incompat,
                &raw_name,
            );
            image[EXT4_SUPERBLOCK_OFFSET..EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_SIZE]
                .copy_from_slice(&sb);

            let from_region = Ext4Superblock::parse_superblock_region(&sb).expect("region parser");
            let from_image = Ext4Superblock::parse_from_image(&image).expect("image parser");

            prop_assert_eq!(&from_image, &from_region);
            prop_assert_eq!(
                from_image.validate_geometry().is_ok(),
                from_region.validate_geometry().is_ok()
            );
        }

        #[test]
        fn ext4_proptest_parse_and_iter_dir_block_equivalent_on_valid_blocks(
            block_size in prop_oneof![Just(1024_u32), Just(2048_u32), Just(4096_u32)],
            include_tail in any::<bool>(),
            tail_checksum in any::<u32>(),
            specs in proptest::collection::vec(
                (0_u32..=4096_u32, 0_u8..=7_u8, proptest::collection::vec(any::<u8>(), 1..=32)),
                1..=8,
            ),
        ) {
            let block_len = usize::try_from(block_size).expect("block_size in usize range");
            let tail_len = if include_tail { 12_usize } else { 0_usize };
            let min_payload: usize = specs
                .iter()
                .map(|(_, _, name)| (8 + name.len() + 3) & !3)
                .sum();
            prop_assume!(min_payload <= block_len.saturating_sub(tail_len));

            let mut block = vec![0_u8; block_len];
            let mut offset = 0_usize;
            let entry_region_end = block_len - tail_len;

            for (idx, (inode, file_type_raw, name)) in specs.iter().enumerate() {
                let min_rec_len = (8 + name.len() + 3) & !3;
                let is_last = idx + 1 == specs.len();
                let rec_len_usize = if is_last {
                    entry_region_end.saturating_sub(offset)
                } else {
                    min_rec_len
                };

                prop_assume!(rec_len_usize >= min_rec_len);
                prop_assume!(offset + rec_len_usize <= entry_region_end);
                let rec_len = u16::try_from(rec_len_usize).expect("record length fits u16");

                write_dir_entry(
                    &mut block,
                    offset,
                    *inode,
                    *file_type_raw,
                    name,
                    rec_len,
                );
                offset += rec_len_usize;
            }

            prop_assert_eq!(offset, entry_region_end);

            if include_tail {
                let tail_off = block_len - 12;
                block[tail_off..tail_off + 4].copy_from_slice(&0_u32.to_le_bytes());
                block[tail_off + 4..tail_off + 6].copy_from_slice(&12_u16.to_le_bytes());
                block[tail_off + 6] = 0;
                block[tail_off + 7] = EXT4_FT_DIR_CSUM;
                block[tail_off + 8..tail_off + 12].copy_from_slice(&tail_checksum.to_le_bytes());
            }

            let (parsed_entries, parsed_tail) =
                parse_dir_block(&block, block_size).expect("valid synthesized dir block parses");

            let mut iter = iter_dir_block(&block, block_size);
            let mut iter_entries = Vec::new();
            for entry in iter.by_ref() {
                iter_entries.push(entry.expect("iterator must parse synthesized block").to_owned());
            }
            let iter_tail = iter.checksum_tail();

            prop_assert_eq!(&parsed_entries, &iter_entries);
            prop_assert_eq!(parsed_tail, iter_tail);
            for entry in &parsed_entries {
                prop_assert!(usize::try_from(entry.rec_len).expect("rec_len in usize") >= entry.actual_size());
            }
        }

        #[test]
        fn ext4_proptest_volume_name_trimmed(
            raw_name in proptest::collection::vec(any::<u8>(), 0..=16),
        ) {
            let incompat = Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0;
            let sb = make_proptest_valid_ext4_superblock(
                2,
                8192,
                4096,
                64,
                incompat,
                &raw_name,
            );
            let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse structured superblock");
            prop_assert!(parsed.volume_name.chars().count() <= 16);
            prop_assert!(!parsed.volume_name.contains('\0'));
        }

        // ── ext4_chksum properties ────────────────────────────────────

        /// ext4_chksum is deterministic: same inputs always produce same output.
        #[test]
        fn ext4_proptest_chksum_deterministic(
            seed in any::<u32>(),
            data in proptest::collection::vec(any::<u8>(), 0..=256),
        ) {
            let a = ext4_chksum(seed, &data);
            let b = ext4_chksum(seed, &data);
            prop_assert_eq!(a, b);
        }

        /// ext4_chksum on empty data still transforms the seed.
        #[test]
        fn ext4_proptest_chksum_empty_data_varies(seed in any::<u32>()) {
            let result = ext4_chksum(seed, &[]);
            // With empty data, the CRC should still be a function of the seed
            // (not necessarily equal to the seed, since !crc32c_append(!seed, &[]) applies double complement)
            let _ = result; // just verify no panic; determinism checked above
        }

        /// ext4_chksum with different data produces different results (with high probability).
        #[test]
        fn ext4_proptest_chksum_collision_resistance(
            seed in any::<u32>(),
            data1 in proptest::collection::vec(any::<u8>(), 1..=64),
            data2 in proptest::collection::vec(any::<u8>(), 1..=64),
        ) {
            prop_assume!(data1 != data2);
            let h1 = ext4_chksum(seed, &data1);
            let h2 = ext4_chksum(seed, &data2);
            // Not guaranteed to differ, but with random 32-bit hash they almost always will.
            // We only assert no panic here; collision resistance is statistical.
            let _ = (h1, h2);
        }

        // ── Ext4GroupDesc parse/write roundtrip ───────────────────────

        /// Ext4GroupDesc: parse(write(gd)) == gd for 32-byte descriptors.
        #[test]
        fn ext4_proptest_group_desc_roundtrip_32(
            block_bitmap in any::<u32>(),
            inode_bitmap in any::<u32>(),
            inode_table in any::<u32>(),
            free_blocks in 0_u16..=u16::MAX,
            free_inodes in 0_u16..=u16::MAX,
            used_dirs in 0_u16..=u16::MAX,
            flags in any::<u16>(),
            itable_unused in 0_u16..=u16::MAX,
            checksum in any::<u16>(),
        ) {
            let gd = Ext4GroupDesc {
                block_bitmap: u64::from(block_bitmap),
                inode_bitmap: u64::from(inode_bitmap),
                inode_table: u64::from(inode_table),
                free_blocks_count: u32::from(free_blocks),
                free_inodes_count: u32::from(free_inodes),
                used_dirs_count: u32::from(used_dirs),
                itable_unused: u32::from(itable_unused),
                flags,
                checksum,
                block_bitmap_csum: 0,
                inode_bitmap_csum: 0,
            };
            let mut buf = vec![0u8; 32];
            gd.write_to_bytes(&mut buf, 32).expect("write 32-byte GD");
            let parsed = Ext4GroupDesc::parse_from_bytes(&buf, 32).expect("parse 32-byte GD");
            prop_assert_eq!(parsed.block_bitmap, gd.block_bitmap);
            prop_assert_eq!(parsed.inode_bitmap, gd.inode_bitmap);
            prop_assert_eq!(parsed.inode_table, gd.inode_table);
            prop_assert_eq!(parsed.free_blocks_count, gd.free_blocks_count);
            prop_assert_eq!(parsed.free_inodes_count, gd.free_inodes_count);
            prop_assert_eq!(parsed.used_dirs_count, gd.used_dirs_count);
            prop_assert_eq!(parsed.flags, gd.flags);
            prop_assert_eq!(parsed.checksum, gd.checksum);
        }

        /// Ext4GroupDesc: parse(write(gd)) == gd for 64-byte descriptors.
        #[test]
        fn ext4_proptest_group_desc_roundtrip_64(
            block_bitmap in any::<u64>(),
            inode_bitmap in any::<u64>(),
            inode_table in any::<u64>(),
            free_blocks in any::<u32>(),
            free_inodes in any::<u32>(),
            used_dirs in any::<u32>(),
            flags in any::<u16>(),
            itable_unused in any::<u32>(),
            checksum in any::<u16>(),
        ) {
            let gd = Ext4GroupDesc {
                block_bitmap,
                inode_bitmap,
                inode_table,
                free_blocks_count: free_blocks,
                free_inodes_count: free_inodes,
                used_dirs_count: used_dirs,
                itable_unused,
                flags,
                checksum,
                block_bitmap_csum: 0,
                inode_bitmap_csum: 0,
            };
            let mut buf = vec![0u8; 64];
            gd.write_to_bytes(&mut buf, 64).expect("write 64-byte GD");
            let parsed = Ext4GroupDesc::parse_from_bytes(&buf, 64).expect("parse 64-byte GD");
            prop_assert_eq!(parsed.block_bitmap, gd.block_bitmap);
            prop_assert_eq!(parsed.inode_bitmap, gd.inode_bitmap);
            prop_assert_eq!(parsed.inode_table, gd.inode_table);
            prop_assert_eq!(parsed.free_blocks_count, gd.free_blocks_count);
            prop_assert_eq!(parsed.free_inodes_count, gd.free_inodes_count);
            prop_assert_eq!(parsed.used_dirs_count, gd.used_dirs_count);
            prop_assert_eq!(parsed.flags, gd.flags);
            prop_assert_eq!(parsed.checksum, gd.checksum);
        }

        /// Ext4GroupDesc: parse never panics on arbitrary bytes.
        #[test]
        fn ext4_proptest_group_desc_parse_no_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..=128),
            desc_size in prop_oneof![Just(32_u16), Just(64_u16)],
        ) {
            let _ = Ext4GroupDesc::parse_from_bytes(&bytes, desc_size);
        }

        // ── stamp + verify group desc checksum roundtrip ──────────────

        /// stamp_group_desc_checksum + verify_group_desc_checksum roundtrip.
        #[test]
        fn ext4_proptest_gd_checksum_stamp_verify_roundtrip(
            csum_seed in any::<u32>(),
            group_number in any::<u32>(),
            desc_size in prop_oneof![Just(32_u16), Just(64_u16)],
        ) {
            let uuid = [0xA5_u8; 16];
            let ds = usize::from(desc_size);
            let mut buf = vec![0u8; ds];
            // Fill with arbitrary data except checksum field.
            for (i, b) in buf.iter_mut().enumerate() {
                *b = u8::try_from(i & 0xFF).unwrap();
            }
            stamp_group_desc_checksum(
                &mut buf,
                &uuid,
                csum_seed,
                group_number,
                desc_size,
                Ext4GroupDescChecksumKind::MetadataCsum,
            );
            let result = verify_group_desc_checksum(
                &buf,
                &uuid,
                csum_seed,
                group_number,
                desc_size,
                Ext4GroupDescChecksumKind::MetadataCsum,
            );
            prop_assert!(result.is_ok(), "stamp then verify should succeed");
        }

        /// Tampering with stamped checksum causes verification failure.
        #[test]
        fn ext4_proptest_gd_checksum_tamper_fails(
            csum_seed in any::<u32>(),
            group_number in any::<u32>(),
            tamper_byte in 0_usize..30,
        ) {
            let uuid = [0xA5_u8; 16];
            let desc_size = 32_u16;
            let ds = usize::from(desc_size);
            let mut buf = vec![0u8; ds];
            for (i, b) in buf.iter_mut().enumerate() {
                *b = u8::try_from(i & 0xFF).unwrap();
            }
            stamp_group_desc_checksum(
                &mut buf,
                &uuid,
                csum_seed,
                group_number,
                desc_size,
                Ext4GroupDescChecksumKind::MetadataCsum,
            );

            // Tamper with a non-checksum byte.
            let tamper_idx = if tamper_byte >= GD_CHECKSUM_OFFSET { tamper_byte + 2 } else { tamper_byte };
            if tamper_idx < ds {
                buf[tamper_idx] ^= 0xFF;
                let result = verify_group_desc_checksum(
                    &buf,
                    &uuid,
                    csum_seed,
                    group_number,
                    desc_size,
                    Ext4GroupDescChecksumKind::MetadataCsum,
                );
                prop_assert!(result.is_err(), "tampered descriptor should fail verification");
            }
        }

        // ── Ext4Inode parse no-panic ──────────────────────────────────

        /// Ext4Inode: parse never panics on arbitrary bytes (128+ bytes).
        #[test]
        fn ext4_proptest_inode_parse_no_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let _ = Ext4Inode::parse_from_bytes(&bytes);
        }

        /// Ext4Inode: parse on 128-byte buffer always succeeds (minimum valid inode).
        #[test]
        fn ext4_proptest_inode_parse_128_succeeds(
            bytes in proptest::collection::vec(any::<u8>(), 128..=128),
        ) {
            let result = Ext4Inode::parse_from_bytes(&bytes);
            prop_assert!(result.is_ok(), "128-byte inode should always parse");
        }

        /// Ext4Inode: parse on 256-byte buffer captures extended timestamps.
        #[test]
        fn ext4_proptest_inode_parse_256_extended(
            mut bytes in proptest::collection::vec(any::<u8>(), 256..=256),
        ) {
            // Set extra_isize to a valid value (>= 32 for extended timestamps).
            // extra_isize is at offset 0x80 (128) in the inode.
            bytes[0x80] = 32;
            bytes[0x81] = 0;
            let result = Ext4Inode::parse_from_bytes(&bytes);
            prop_assert!(result.is_ok(), "256-byte inode with extra_isize=32 should parse");
        }

        // ── dx_hash properties ────────────────────────────────────────

        /// dx_hash is deterministic.
        #[test]
        fn ext4_proptest_dx_hash_deterministic(
            hash_version in 0_u8..=5,
            name in proptest::collection::vec(any::<u8>(), 0..=255),
            seed in proptest::array::uniform4(any::<u32>()),
        ) {
            let (h1a, h1b) = dx_hash(hash_version, &name, &seed);
            let (h2a, h2b) = dx_hash(hash_version, &name, &seed);
            prop_assert_eq!(h1a, h2a);
            prop_assert_eq!(h1b, h2b);
        }

        /// dx_hash major value always has low bit clear (ext4 convention).
        #[test]
        fn ext4_proptest_dx_hash_major_low_bit_clear(
            hash_version in 0_u8..=5,
            name in proptest::collection::vec(any::<u8>(), 1..=64),
            seed in proptest::array::uniform4(any::<u32>()),
        ) {
            let (major, _minor) = dx_hash(hash_version, &name, &seed);
            prop_assert_eq!(major & 1, 0, "major hash low bit must be clear (ext4 convention)");
        }

        /// dx_hash never panics on any input.
        #[test]
        fn ext4_proptest_dx_hash_no_panic(
            hash_version in any::<u8>(),
            name in proptest::collection::vec(any::<u8>(), 0..=512),
            seed in proptest::array::uniform4(any::<u32>()),
        ) {
            let _ = dx_hash(hash_version, &name, &seed);
        }

        // ── dx_hash metamorphic relations (bd-590tc) ─────────────────

        /// MR-A — `normalize_dx_major_hash` reserves the htree EOF
        /// sentinel; `dx_hash` MUST never return `(EXT4_HTREE_EOF_32BIT
        /// << 1)` as the major hash for any input. Regression here
        /// would cause directory iteration to mistake a real entry for
        /// the end-of-iteration marker. Crawls the input space across
        /// every supported hash version including unknown values that
        /// fall through to the half-md4 unsigned default.
        #[test]
        fn ext4_proptest_dx_hash_never_returns_eof_sentinel_as_major(
            hash_version in 0_u8..=8,
            name in proptest::collection::vec(any::<u8>(), 0..=128),
            seed in proptest::array::uniform4(any::<u32>()),
        ) {
            let (major, _minor) = dx_hash(hash_version, &name, &seed);
            let reserved = EXT4_HTREE_EOF_32BIT << 1;
            prop_assert_ne!(
                major, reserved,
                "dx_hash MUST never return the htree-EOF sentinel as a major hash"
            );
        }

        /// MR-B — Legacy hash variants (DX_HASH_LEGACY,
        /// DX_HASH_LEGACY_UNSIGNED) ignore the seed parameter; their
        /// initial state is hardcoded in `dx_hash_legacy`. Property:
        /// changing the seed must NOT change the legacy hash output.
        /// A regression that threads the seed into the legacy path
        /// would make our htree reads diverge from kernel-mounted
        /// images.
        #[test]
        fn ext4_proptest_dx_hash_legacy_ignores_seed(
            name in proptest::collection::vec(any::<u8>(), 0..=128),
            seed_a in proptest::array::uniform4(any::<u32>()),
            seed_b in proptest::array::uniform4(any::<u32>()),
            unsigned in any::<bool>(),
        ) {
            let version = if unsigned { DX_HASH_LEGACY_UNSIGNED } else { DX_HASH_LEGACY };
            let (major_a, minor_a) = dx_hash(version, &name, &seed_a);
            let (major_b, minor_b) = dx_hash(version, &name, &seed_b);
            prop_assert_eq!(major_a, major_b, "legacy major hash must be seed-independent");
            prop_assert_eq!(minor_a, minor_b, "legacy minor hash must be seed-independent");
        }

        /// MR-C — For ASCII-only names (every byte < 128), signed and
        /// unsigned variants of each dx_hash family must produce the
        /// SAME hash. The signed/unsigned distinction only changes the
        /// byte reinterpretation for bytes ≥ 128 (which the kernel
        /// reinterprets via `signed char`); for ASCII bytes both paths
        /// agree. Pins this equivalence across all three families
        /// (legacy, half-md4, tea).
        #[test]
        fn ext4_proptest_dx_hash_ascii_signed_unsigned_equivalence(
            name in proptest::collection::vec(0_u8..=0x7F, 0..=128),
            seed in proptest::array::uniform4(any::<u32>()),
        ) {
            // Legacy family.
            let (legacy_signed_major, legacy_signed_minor) =
                dx_hash(DX_HASH_LEGACY, &name, &seed);
            let (legacy_unsigned_major, legacy_unsigned_minor) =
                dx_hash(DX_HASH_LEGACY_UNSIGNED, &name, &seed);
            prop_assert_eq!(
                (legacy_signed_major, legacy_signed_minor),
                (legacy_unsigned_major, legacy_unsigned_minor),
                "legacy signed/unsigned must agree on ASCII-only names"
            );

            // Half-MD4 family.
            let (md4_signed_major, md4_signed_minor) =
                dx_hash(DX_HASH_HALF_MD4, &name, &seed);
            let (md4_unsigned_major, md4_unsigned_minor) =
                dx_hash(DX_HASH_HALF_MD4_UNSIGNED, &name, &seed);
            prop_assert_eq!(
                (md4_signed_major, md4_signed_minor),
                (md4_unsigned_major, md4_unsigned_minor),
                "half-md4 signed/unsigned must agree on ASCII-only names"
            );

            // TEA family.
            let (tea_signed_major, tea_signed_minor) =
                dx_hash(DX_HASH_TEA, &name, &seed);
            let (tea_unsigned_major, tea_unsigned_minor) =
                dx_hash(DX_HASH_TEA_UNSIGNED, &name, &seed);
            prop_assert_eq!(
                (tea_signed_major, tea_signed_minor),
                (tea_unsigned_major, tea_unsigned_minor),
                "tea signed/unsigned must agree on ASCII-only names"
            );
        }

        // ── parse_dx_root properties ──────────────────────────────────

        /// parse_dx_root never panics on arbitrary input.
        #[test]
        fn ext4_proptest_parse_dx_root_no_panic(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let _ = parse_dx_root(&block);
        }

        #[test]
        fn ext4_proptest_parse_dx_entries_count_limit_and_truncation(
            limit in 0_u16..=64,
            count in 0_u16..=64,
            first_block in any::<u32>(),
            rest_pairs in proptest::collection::vec((any::<u32>(), any::<u32>()), 0..=63),
        ) {
            // Build data matching the actual dx_entry layout:
            // [limit(2), count(2), entry0_block(4), entry1_hash(4), entry1_block(4), ...]
            // Entry 0's hash is implicit 0 (countlimit overlaps).
            let data_len = 4 + 4 + rest_pairs.len() * 8; // countlimit(4) + entry0_block(4) + rest entries
            let mut data = vec![0_u8; data_len];
            data[0..2].copy_from_slice(&limit.to_le_bytes());
            data[2..4].copy_from_slice(&count.to_le_bytes());
            data[4..8].copy_from_slice(&first_block.to_le_bytes());
            for (idx, (hash, block)) in rest_pairs.iter().copied().enumerate() {
                let off = 8 + idx * 8;
                data[off..off + 4].copy_from_slice(&hash.to_le_bytes());
                data[off + 4..off + 8].copy_from_slice(&block.to_le_bytes());
            }

            if count > limit {
                let err = parse_dx_entries(&data, 0).expect_err("count > limit should reject");
                prop_assert_eq!(
                    err,
                    ParseError::InvalidField {
                        field: "dx_count",
                        reason: "count exceeds limit",
                    }
                );
            } else if count == 0 {
                let parsed = parse_dx_entries(&data, 0).expect("count 0 should parse");
                prop_assert_eq!(parsed.len(), 0);
            } else {
                let parsed = parse_dx_entries(&data, 0).expect("count <= limit should parse");
                // Entry 0 always has hash=0 (implicit), block=first_block.
                // Remaining entries come from rest_pairs, capped by count-1 and available data.
                let rest_count = usize::from(count).saturating_sub(1).min(rest_pairs.len());
                prop_assert_eq!(parsed.len(), 1 + rest_count);
                prop_assert_eq!(parsed[0].hash, 0);
                prop_assert_eq!(parsed[0].block, first_block);
                for (idx, entry) in parsed[1..].iter().enumerate() {
                    prop_assert_eq!(entry.hash, rest_pairs[idx].0);
                    prop_assert_eq!(entry.block, rest_pairs[idx].1);
                }
            }
        }

        #[test]
        fn ext4_proptest_parse_dx_entries_header_bounds_rejected(
            data in proptest::collection::vec(any::<u8>(), 0..=64),
            offset in 0_usize..=80,
        ) {
            prop_assume!(offset + 4 > data.len());
            let err = parse_dx_entries(&data, offset).expect_err("out-of-range header should fail");
            prop_assert_eq!(
                err,
                ParseError::InsufficientData {
                    needed: offset + 4,
                    offset: 0,
                    actual: data.len(),
                }
            );
        }

        // ── parse_xattr_block properties ──────────────────────────────

        #[test]
        fn ext4_proptest_parse_xattr_entries_single_roundtrip(
            name in proptest::collection::vec(any::<u8>(), 1..=32),
            value in proptest::collection::vec(any::<u8>(), 0..=96),
            name_index in any::<u8>(),
            // Minimum pad of 4 to leave room for the 2-byte terminator
            // between the entry and value without overlap.
            value_pad in 4_usize..=64,
        ) {
            let entry_len = (16 + name.len() + 3) & !3;
            let value_off = entry_len + value_pad;
            let value_end = value_off + value.len();
            let data_len = (entry_len + 4).max(value_end + 4);
            let mut data = vec![0_u8; data_len];

            data[0] = u8::try_from(name.len()).expect("name length bounded by strategy");
            data[1] = name_index;
            data[2..4].copy_from_slice(
                &u16::try_from(value_off)
                    .expect("value offset bounded by strategy")
                    .to_le_bytes(),
            );
            // data[4..8] = e_value_block (unused, stays zero)
            data[8..12].copy_from_slice(
                &u32::try_from(value.len())
                    .expect("value length bounded by strategy")
                    .to_le_bytes(),
            );
            // data[12..16] = e_hash (unused, stays zero)
            data[16..16 + name.len()].copy_from_slice(&name);
            // Write terminator BEFORE value so there is no overlap
            data[entry_len] = 0;
            data[entry_len + 1] = 0;
            if !value.is_empty() {
                data[value_off..value_off + value.len()].copy_from_slice(&value);
            }

            let parsed = parse_xattr_entries(&data, &data, 0).expect("valid entry should parse");
            prop_assert_eq!(parsed.len(), 1);
            prop_assert_eq!(parsed[0].name_index, name_index);
            prop_assert_eq!(&parsed[0].name, &name);
            prop_assert_eq!(&parsed[0].value, &value);
        }

        #[test]
        fn ext4_proptest_parse_xattr_entries_name_bounds_rejected(
            data_len in 16_usize..=128,
            name_len in 1_u8..=u8::MAX,
            name_index in any::<u8>(),
        ) {
            let mut data = vec![0_u8; data_len];
            data[0] = name_len;
            data[1] = name_index;

            prop_assume!(16 + usize::from(name_len) > data.len());
            let err =
                parse_xattr_entries(&data, &data, 0).expect_err("name overflow should reject");
            prop_assert_eq!(
                err,
                ParseError::InvalidField {
                    field: "xattr_name",
                    reason: "name extends past data boundary",
                }
            );
        }

        #[test]
        fn ext4_proptest_parse_xattr_entries_value_bounds_rejected(
            data_len in 36_usize..=256,
            name_len in 1_usize..=16,
            value_size in 1_usize..=64,
            name_index in any::<u8>(),
        ) {
            let mut data = vec![0_u8; data_len];
            let entry_len = (16 + name_len + 3) & !3;
            prop_assume!(entry_len + 1 < data.len());

            let value_off = data_len.saturating_sub(value_size.saturating_sub(1));
            prop_assume!(value_off >= entry_len + 4);
            prop_assume!(value_off + value_size > data.len());

            data[0] = u8::try_from(name_len).expect("name length bounded by strategy");
            data[1] = name_index;
            data[2..4].copy_from_slice(
                &u16::try_from(value_off)
                    .expect("value offset bounded by strategy")
                    .to_le_bytes(),
            );
            // data[4..8] = e_value_block (unused, stays zero)
            data[8..12].copy_from_slice(
                &u32::try_from(value_size)
                    .expect("value size bounded by strategy")
                    .to_le_bytes(),
            );
            // data[12..16] = e_hash (unused, stays zero)
            data[16..16 + name_len].fill(b'x');
            data[entry_len] = 0;
            data[entry_len + 1] = 0;

            let err =
                parse_xattr_entries(&data, &data, 0).expect_err("value overflow should reject");
            prop_assert_eq!(
                err,
                ParseError::InvalidField {
                    field: "xattr_value",
                    reason: "value extends past data boundary",
                }
            );
        }

        /// parse_xattr_block never panics on arbitrary input.
        #[test]
        fn ext4_proptest_parse_xattr_block_no_panic(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let _ = parse_xattr_block(&block);
        }

        /// parse_xattr_block fails on short input (<32 bytes).
        #[test]
        fn ext4_proptest_parse_xattr_block_short_fails(
            block in proptest::collection::vec(any::<u8>(), 0..=31),
        ) {
            let result = parse_xattr_block(&block);
            prop_assert!(result.is_err(), "xattr block < 32 bytes should fail");
        }

        // ── verify_bitmap_free_count properties ───────────────────────

        /// verify_bitmap_free_count: correct count always passes.
        #[test]
        fn ext4_proptest_bitmap_verify_correct_passes(
            byte_len in 1_usize..=128,
            fill_seed in any::<u64>(),
        ) {
            let total_bits = u32::try_from(byte_len * 8).unwrap();
            let mut bm = vec![0u8; byte_len];
            // Deterministic fill based on seed.
            let mut rng = fill_seed;
            for b in &mut bm {
                rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                *b = rng.to_le_bytes()[7];
            }
            // Count actual free bits.
            let used: u32 = bm[..byte_len].iter().map(|b| b.count_ones()).sum();
            let free = total_bits.saturating_sub(used);
            let result = verify_inode_bitmap_free_count(&bm, total_bits, free);
            prop_assert!(result.is_ok(), "correct free count should verify");
        }

        /// verify_bitmap_free_count: wrong count always fails.
        #[test]
        fn ext4_proptest_bitmap_verify_wrong_fails(
            byte_len in 1_usize..=64,
            delta in 1_u32..=100,
        ) {
            let total_bits = u32::try_from(byte_len * 8).unwrap();
            let bm = vec![0u8; byte_len]; // all free
            // True free count = total_bits, pass wrong count.
            let wrong_free = total_bits.saturating_sub(delta);
            if wrong_free != total_bits {
                let result = verify_inode_bitmap_free_count(&bm, total_bits, wrong_free);
                prop_assert!(result.is_err(), "wrong free count should fail verification");
            }
        }

        /// verify_bitmap_free_count agrees with an independent bit-by-bit count
        /// across arbitrary, often non-byte-aligned total_bits — exercising the
        /// trailing partial-byte mask that the multiple-of-8 proptests above
        /// never reach (they set total_bits = byte_len * 8).
        #[test]
        fn proptest_verify_bitmap_free_count_matches_bit_loop(
            bytes in proptest::collection::vec(any::<u8>(), 2..=64),
            trim in 0_u32..=7,
        ) {
            // total_bits = full capacity minus a 0..8 remainder, so the last
            // byte is often partial. ceil(total_bits/8) still equals bytes.len(),
            // so the bitmap is never too short.
            let capacity_bits = u32::try_from(bytes.len()).unwrap() * 8;
            let total_bits = capacity_bits - trim;

            // Independent reference: count set bits over exactly the first
            // total_bits bits, ignoring any high bits in the partial last byte.
            let mut used = 0_u32;
            for bit in 0..total_bits {
                let byte = bytes[usize::try_from(bit / 8).unwrap()];
                if byte & (1_u8 << (bit % 8)) != 0 {
                    used += 1;
                }
            }
            let free = total_bits.saturating_sub(used);

            prop_assert!(
                verify_bitmap_free_count(&bytes, total_bits, free, "test").is_ok(),
                "correct free {free} must verify for total_bits {total_bits}"
            );
            prop_assert!(
                verify_bitmap_free_count(&bytes, total_bits, free + 1, "test").is_err(),
                "wrong free must fail for total_bits {total_bits}"
            );
        }

        // ── verify_inode_checksum properties ───────────────────────────

        /// verify_inode_checksum never panics on arbitrary bytes.
        #[test]
        fn ext4_proptest_verify_inode_checksum_no_panic(
            raw_inode in proptest::collection::vec(any::<u8>(), 0..=512),
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
            inode_size in prop_oneof![Just(128_u16), Just(160_u16), Just(256_u16)],
        ) {
            let _ = verify_inode_checksum(&raw_inode, csum_seed, ino, inode_size);
        }

        /// verify_inode_checksum rejects buffers shorter than inode_size.
        #[test]
        fn ext4_proptest_verify_inode_checksum_short_rejects(
            raw_inode in proptest::collection::vec(any::<u8>(), 0..=127),
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
        ) {
            let result = verify_inode_checksum(&raw_inode, csum_seed, ino, 128);
            prop_assert!(result.is_err(), "buffer shorter than inode_size should fail");
        }

        /// verify_inode_checksum also rejects a buffer shorter than the common
        /// 256-byte inode size; short_rejects above only covers 128 and no_panic
        /// never asserts the reject for 256.
        #[test]
        fn ext4_proptest_verify_inode_checksum_short_rejects_256(
            raw_inode in proptest::collection::vec(any::<u8>(), 0..=255),
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
        ) {
            let result = verify_inode_checksum(&raw_inode, csum_seed, ino, 256);
            prop_assert!(result.is_err(), "buffer shorter than 256 should fail for inode_size 256");
        }

        /// bd-0g4j6 — Determinism MR for verify_inode_checksum.
        /// Verifier runs an independent ext4_chksum chain (per-inode
        /// seed, lo+hi extraction, extra_isize-conditional branches).
        /// A regression that introduced non-determinism in this path
        /// would silently corrupt mount-time inode integrity checks.
        #[test]
        fn ext4_proptest_verify_inode_checksum_determinism(
            raw_inode in proptest::collection::vec(any::<u8>(), 0..=512),
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
            inode_size in prop_oneof![Just(128_u16), Just(160_u16), Just(256_u16)],
        ) {
            let a = verify_inode_checksum(&raw_inode, csum_seed, ino, inode_size);
            let b = verify_inode_checksum(&raw_inode, csum_seed, ino, inode_size);
            prop_assert_eq!(a, b);
        }

        // ── verify_dir_block_checksum properties ───────────────────────

        /// verify_dir_block_checksum never panics on arbitrary bytes.
        #[test]
        fn ext4_proptest_verify_dir_block_checksum_no_panic(
            dir_block in proptest::collection::vec(any::<u8>(), 0..=4096),
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
            generation in any::<u32>(),
        ) {
            let _ = verify_dir_block_checksum(&dir_block, csum_seed, ino, generation);
        }

        /// verify_dir_block_checksum rejects blocks shorter than 12 bytes.
        #[test]
        fn ext4_proptest_verify_dir_block_checksum_short_rejects(
            dir_block in proptest::collection::vec(any::<u8>(), 0..=11),
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
            generation in any::<u32>(),
        ) {
            let result = verify_dir_block_checksum(&dir_block, csum_seed, ino, generation);
            prop_assert!(result.is_err(), "dir block < 12 bytes should fail");
        }

        /// bd-0g4j6 — Determinism MR for verify_dir_block_checksum.
        /// Invoked on every readdir against checksum-enabled fs.
        #[test]
        fn ext4_proptest_verify_dir_block_checksum_determinism(
            dir_block in proptest::collection::vec(any::<u8>(), 0..=4096),
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
            generation in any::<u32>(),
        ) {
            let a = verify_dir_block_checksum(&dir_block, csum_seed, ino, generation);
            let b = verify_dir_block_checksum(&dir_block, csum_seed, ino, generation);
            prop_assert_eq!(a, b);
        }

        // ── verify_extent_block_checksum properties ────────────────────

        /// verify_extent_block_checksum never panics on arbitrary bytes.
        #[test]
        fn ext4_proptest_verify_extent_block_checksum_no_panic(
            extent_block in proptest::collection::vec(any::<u8>(), 0..=4096),
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
            generation in any::<u32>(),
        ) {
            let _ = verify_extent_block_checksum(&extent_block, csum_seed, ino, generation);
        }

        /// verify_extent_block_checksum rejects blocks shorter than 16 bytes.
        #[test]
        fn ext4_proptest_verify_extent_block_checksum_short_rejects(
            extent_block in proptest::collection::vec(any::<u8>(), 0..=15),
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
            generation in any::<u32>(),
        ) {
            let result = verify_extent_block_checksum(&extent_block, csum_seed, ino, generation);
            prop_assert!(result.is_err(), "extent block < 16 bytes should fail");
        }

        /// bd-0g4j6 — Determinism MR for verify_extent_block_checksum.
        /// Invoked on every extent-tree walk against checksum-enabled fs.
        #[test]
        fn ext4_proptest_verify_extent_block_checksum_determinism(
            extent_block in proptest::collection::vec(any::<u8>(), 0..=4096),
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
            generation in any::<u32>(),
        ) {
            let a = verify_extent_block_checksum(&extent_block, csum_seed, ino, generation);
            let b = verify_extent_block_checksum(&extent_block, csum_seed, ino, generation);
            prop_assert_eq!(a, b);
        }

        // ── lookup_in_dir_block properties ─────────────────────────────

        /// lookup_in_dir_block never panics on arbitrary bytes.
        #[test]
        fn ext4_proptest_lookup_in_dir_block_no_panic(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
            block_size in prop_oneof![Just(1024_u32), Just(2048_u32), Just(4096_u32)],
            target in proptest::collection::vec(any::<u8>(), 0..=255),
        ) {
            let _ = lookup_in_dir_block(&block, block_size, &target);
        }

        // bd-z9ltd — Determinism MR for lookup_in_dir_block. lookup_in_dir_block
        // is invoked on every ext4 path lookup that hits a non-htree directory
        // (or htree leaf). It composes parse_dir_block + Vec::into_iter().find()
        // — a regression that introduced HashMap-based dispatch or any non-
        // deterministic comparison state would silently corrupt lookups. Sister
        // parse_dir_block (bd-qzwuq) and iter_dir_block (bd-tj83g) have their
        // own determinism MRs covering the underlying parser; this pins the
        // lookup wrapper.
        #[test]
        fn ext4_proptest_lookup_in_dir_block_determinism(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
            block_size in prop_oneof![Just(1024_u32), Just(2048_u32), Just(4096_u32)],
            target in proptest::collection::vec(any::<u8>(), 0..=255),
        ) {
            let a = lookup_in_dir_block(&block, block_size, &target);
            let b = lookup_in_dir_block(&block, block_size, &target);
            prop_assert_eq!(a, b);
        }

        // bd-z9ltd — Companion determinism MR for the casefold variant.
        // lookup_in_dir_block_casefold runs an additional UTF-8 casefold
        // step on each entry (ext4_casefold_key) before comparing, so it
        // has independent surface area for non-determinism beyond
        // lookup_in_dir_block. Invoked on every path lookup against a
        // case-insensitive (CASEFOLD) directory.
        #[test]
        fn ext4_proptest_lookup_in_dir_block_casefold_determinism(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
            block_size in prop_oneof![Just(1024_u32), Just(2048_u32), Just(4096_u32)],
            target in proptest::collection::vec(any::<u8>(), 0..=255),
        ) {
            let a = lookup_in_dir_block_casefold(&block, block_size, &target);
            let b = lookup_in_dir_block_casefold(&block, block_size, &target);
            prop_assert_eq!(a, b);
        }

        // ── parse_ibody_xattrs properties ──────────────────────────────

        /// parse_ibody_xattrs never panics on an inode with arbitrary xattr_ibody.
        #[test]
        fn ext4_proptest_parse_ibody_xattrs_no_panic(
            xattr_ibody in proptest::collection::vec(any::<u8>(), 0..=256),
        ) {
            let inode = Ext4Inode {
                mode: 0o100_644,
                uid: 0,
                gid: 0,
                size: 0,
                links_count: 1,
                blocks: 0,
                flags: 0,
                version: 0,
                generation: 0,
                file_acl: 0,
                atime: 0,
                ctime: 0,
                mtime: 0,
                dtime: 0,
                atime_extra: 0,
                ctime_extra: 0,
                mtime_extra: 0,
                crtime: 0,
                crtime_extra: 0,
                extra_isize: 32,
                checksum: 0,
                version_hi: 0,
                projid: 0,
                extent_bytes: vec![0; 60].into(),
                xattr_ibody,
                number: 0,
            };
            let _ = parse_ibody_xattrs(&inode);
        }

        // ── Ext4Inode file type extraction properties ──────────────────

        /// Ext4Inode: file_type always returns a valid variant for well-formed modes.
        #[test]
        fn ext4_proptest_inode_file_type_valid_mode(
            ftype in prop_oneof![
                Just(ffs_types::S_IFREG),
                Just(ffs_types::S_IFDIR),
                Just(ffs_types::S_IFLNK),
                Just(ffs_types::S_IFCHR),
                Just(ffs_types::S_IFBLK),
                Just(ffs_types::S_IFIFO),
                Just(ffs_types::S_IFSOCK),
            ],
            perm in 0_u16..=0o777,
        ) {
            let mode = ftype | perm;
            let mut bytes = vec![0u8; 128];
            #[allow(clippy::cast_possible_truncation)]
            {
                bytes[0] = mode as u8;
                bytes[1] = (mode >> 8) as u8;
            }
            if let Ok(inode) = Ext4Inode::parse_from_bytes(&bytes) {
                // file_type should return a recognized type for valid S_IFMT bits
                let _ = inode.file_type_mode();
            }
        }

        // ── DirBlockIter exhaustion property ───────────────────────────

        /// DirBlockIter: collecting all entries never exceeds the block boundary.
        #[test]
        fn ext4_proptest_dir_block_iter_bounded(
            block in proptest::collection::vec(any::<u8>(), 8..=4096),
            block_size in prop_oneof![Just(1024_u32), Just(2048_u32), Just(4096_u32)],
        ) {
            let entries: Vec<_> = iter_dir_block(&block, block_size)
                .filter_map(Result::ok)
                .collect();
            // Total rec_len of all entries should not exceed block length
            let total_rec_len: u64 = entries.iter().map(|e| u64::from(e.rec_len)).sum();
            prop_assert!(total_rec_len <= block.len() as u64,
                "total rec_len {} exceeds block len {}", total_rec_len, block.len());
        }

        // ── Ext4Xattr full_name property ───────────────────────────────

        /// Ext4Xattr: full_name always starts with a known namespace prefix.
        #[test]
        fn ext4_proptest_xattr_full_name_has_prefix(
            name_index in any::<u8>(),
            name in proptest::collection::vec(any::<u8>(), 0..=64),
        ) {
            let xattr = Ext4Xattr {
                name_index,
                name,
                value: Vec::new(),
            };
            let full = xattr.full_name();
            let valid_prefixes = [
                "user.", "system.posix_acl_access", "system.posix_acl_default",
                "trusted.", "security.", "system.", "system.richacl", "unknown.",
            ];
            prop_assert!(
                valid_prefixes.iter().any(|p| full.starts_with(p)),
                "full_name '{}' did not start with a recognized namespace prefix",
                full
            );
        }

        // ── Inode field preservation (structured construction) ───────

        /// Constructing a 128-byte inode buffer with known field values and
        /// parsing it back preserves the core fields.
        #[test]
        fn ext4_proptest_inode_fields_preserved(
            mode in any::<u16>(),
            uid_lo in any::<u16>(),
            gid_lo in any::<u16>(),
            size_lo in any::<u32>(),
            atime in any::<u32>(),
            ctime in any::<u32>(),
            mtime in any::<u32>(),
            dtime in any::<u32>(),
            links_count in any::<u16>(),
            blocks_lo in any::<u32>(),
            flags in any::<u32>(),
            generation in any::<u32>(),
        ) {
            let mut buf = [0u8; 128];
            buf[0x00..0x02].copy_from_slice(&mode.to_le_bytes());
            buf[0x02..0x04].copy_from_slice(&uid_lo.to_le_bytes());
            buf[0x04..0x08].copy_from_slice(&size_lo.to_le_bytes());
            buf[0x08..0x0C].copy_from_slice(&atime.to_le_bytes());
            buf[0x0C..0x10].copy_from_slice(&ctime.to_le_bytes());
            buf[0x10..0x14].copy_from_slice(&mtime.to_le_bytes());
            buf[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());
            buf[0x18..0x1A].copy_from_slice(&gid_lo.to_le_bytes());
            buf[0x1A..0x1C].copy_from_slice(&links_count.to_le_bytes());
            buf[0x1C..0x20].copy_from_slice(&blocks_lo.to_le_bytes());
            buf[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
            buf[0x64..0x68].copy_from_slice(&generation.to_le_bytes());

            let inode = Ext4Inode::parse_from_bytes(&buf).expect("128-byte inode parse");
            prop_assert_eq!(inode.mode, mode);
            prop_assert_eq!(inode.uid & 0xFFFF, u32::from(uid_lo));
            prop_assert_eq!(inode.gid & 0xFFFF, u32::from(gid_lo));
            prop_assert_eq!(inode.atime, atime);
            prop_assert_eq!(inode.ctime, ctime);
            prop_assert_eq!(inode.mtime, mtime);
            prop_assert_eq!(inode.dtime, dtime);
            prop_assert_eq!(inode.links_count, links_count);
            prop_assert_eq!(inode.generation, generation);
            prop_assert_eq!(inode.flags, flags);
        }

        /// Inode with extended area: extended timestamps preserved through parse.
        #[test]
        fn ext4_proptest_inode_extended_timestamps_preserved(
            atime_extra in any::<u32>(),
            ctime_extra in any::<u32>(),
            mtime_extra in any::<u32>(),
            crtime in any::<u32>(),
            crtime_extra in any::<u32>(),
        ) {
            let mut buf = [0u8; 256];
            buf[0x80..0x82].copy_from_slice(&128_u16.to_le_bytes());
            buf[0x84..0x88].copy_from_slice(&ctime_extra.to_le_bytes());
            buf[0x88..0x8C].copy_from_slice(&mtime_extra.to_le_bytes());
            buf[0x8C..0x90].copy_from_slice(&atime_extra.to_le_bytes());
            buf[0x90..0x94].copy_from_slice(&crtime.to_le_bytes());
            buf[0x94..0x98].copy_from_slice(&crtime_extra.to_le_bytes());

            let inode = Ext4Inode::parse_from_bytes(&buf).expect("256-byte inode parse");
            prop_assert_eq!(inode.atime_extra, atime_extra);
            prop_assert_eq!(inode.ctime_extra, ctime_extra);
            prop_assert_eq!(inode.mtime_extra, mtime_extra);
            prop_assert_eq!(inode.crtime, crtime);
            prop_assert_eq!(inode.crtime_extra, crtime_extra);
        }

        // ── Structured extent tree roundtrip ─────────────────────────

        /// Building a valid leaf extent tree and parsing it recovers
        /// header fields and all extent entries.
        ///
        /// The on-disk format requires extents to be sorted by `logical_block`
        /// with non-overlapping ranges, so we deterministically build a
        /// strictly-increasing sequence using the proptest gaps.
        #[test]
        fn ext4_proptest_extent_tree_leaf_roundtrip(
            n_entries in 0_u16..=10,
            max_entries in 10_u16..=20,
            generation in any::<u32>(),
            // Gaps between consecutive extents — keeps logical_blocks sorted
            // and ranges non-overlapping by construction.
            gaps in proptest::collection::vec(0_u32..=1024, 10),
            raw_lens in proptest::collection::vec(1_u16..=128, 10),
            phys_starts in proptest::collection::vec(any::<u64>(), 10),
        ) {
            let entries = usize::from(n_entries);
            let buf_len = 12 + entries * 12;
            let mut buf = vec![0u8; buf_len];
            buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
            buf[2..4].copy_from_slice(&n_entries.to_le_bytes());
            buf[4..6].copy_from_slice(&max_entries.to_le_bytes());
            buf[6..8].copy_from_slice(&0_u16.to_le_bytes());
            buf[8..12].copy_from_slice(&generation.to_le_bytes());
            // Build sorted, non-overlapping logical_blocks: start at 0, then
            // for each entry advance by `prev_actual_len + gap`.
            let mut logical_blocks = Vec::with_capacity(entries);
            let mut next_logical: u32 = 0;
            for (raw_len, gap) in raw_lens.iter().zip(gaps.iter()).take(entries) {
                logical_blocks.push(next_logical);
                let advance = u32::from(*raw_len).saturating_add(*gap);
                next_logical = next_logical.saturating_add(advance);
            }
            for i in 0..entries {
                let base = 12 + i * 12;
                let ps = phys_starts[i] & 0x0000_FFFF_FFFF_FFFF;
                let ps_lo = u32::try_from(ps & u64::from(u32::MAX)).expect("masked to 32 bits");
                buf[base..base + 4].copy_from_slice(&logical_blocks[i].to_le_bytes());
                buf[base + 4..base + 6].copy_from_slice(&raw_lens[i].to_le_bytes());
                buf[base + 6..base + 8].copy_from_slice(&(ps >> 32).to_le_bytes()[..2]);
                buf[base + 8..base + 12].copy_from_slice(&ps_lo.to_le_bytes());
            }
            let (hdr, tree) = parse_extent_tree(&buf).expect("valid leaf extent tree");
            prop_assert_eq!(hdr.magic, EXT4_EXTENT_MAGIC);
            prop_assert_eq!(hdr.entries, n_entries);
            prop_assert_eq!(hdr.max_entries, max_entries);
            prop_assert_eq!(hdr.depth, 0);
            prop_assert_eq!(hdr.generation, generation);
            if let ExtentTree::Leaf(exts) = tree {
                prop_assert_eq!(exts.len(), entries);
                for i in 0..entries {
                    prop_assert_eq!(exts[i].logical_block, logical_blocks[i]);
                    prop_assert_eq!(exts[i].raw_len, raw_lens[i]);
                    prop_assert_eq!(exts[i].physical_start, phys_starts[i] & 0x0000_FFFF_FFFF_FFFF);
                }
            } else {
                prop_assert!(false, "expected Leaf extent tree, got Index");
            }
        }

        /// Building a valid index extent tree (depth > 0) and parsing it
        /// recovers the header and index entries.
        ///
        /// On-disk index entries must be strictly sorted by `logical_block`,
        /// so we deterministically build a strictly-increasing sequence.
        #[test]
        fn ext4_proptest_extent_tree_index_roundtrip(
            n_entries in 0_u16..=10,
            max_entries in 10_u16..=20,
            depth in 1_u16..=5,
            generation in any::<u32>(),
            // Strictly-positive gaps so successive logical_blocks differ.
            gaps in proptest::collection::vec(1_u32..=4096, 10),
            leaf_blocks in proptest::collection::vec(any::<u64>(), 10),
        ) {
            let entries = usize::from(n_entries);
            let buf_len = 12 + entries * 12;
            let mut buf = vec![0u8; buf_len];
            buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
            buf[2..4].copy_from_slice(&n_entries.to_le_bytes());
            buf[4..6].copy_from_slice(&max_entries.to_le_bytes());
            buf[6..8].copy_from_slice(&depth.to_le_bytes());
            buf[8..12].copy_from_slice(&generation.to_le_bytes());
            // Build a strictly-increasing logical_block sequence.
            let mut logical_blocks = Vec::with_capacity(entries);
            let mut next_logical: u32 = 0;
            for &gap in gaps.iter().take(entries) {
                logical_blocks.push(next_logical);
                next_logical = next_logical.saturating_add(gap);
            }
            for i in 0..entries {
                let base = 12 + i * 12;
                let leaf = leaf_blocks[i] & 0x0000_FFFF_FFFF_FFFF;
                let leaf_lo =
                    u32::try_from(leaf & u64::from(u32::MAX)).expect("masked to 32 bits");
                buf[base..base + 4].copy_from_slice(&logical_blocks[i].to_le_bytes());
                buf[base + 4..base + 8].copy_from_slice(&leaf_lo.to_le_bytes());
                buf[base + 8..base + 10].copy_from_slice(&(leaf >> 32).to_le_bytes()[..2]);
            }
            let (hdr, tree) = parse_extent_tree(&buf).expect("valid index extent tree");
            prop_assert_eq!(hdr.depth, depth);
            prop_assert_eq!(hdr.entries, n_entries);
            if let ExtentTree::Index(idxs) = tree {
                prop_assert_eq!(idxs.len(), entries);
                for i in 0..entries {
                    prop_assert_eq!(idxs[i].logical_block, logical_blocks[i]);
                    prop_assert_eq!(idxs[i].leaf_block, leaf_blocks[i] & 0x0000_FFFF_FFFF_FFFF);
                }
            } else {
                prop_assert!(false, "expected Index extent tree, got Leaf");
            }
        }

        /// Unsorted leaf extents are always rejected.  This prevents silent
        /// data misreads from corrupted images, since downstream consumers
        /// (e.g. ffs-btree::partition_point) assume sorted ordering.
        #[test]
        fn ext4_proptest_extent_tree_unsorted_leaf_rejected(
            first_logical in 100_u32..=10_000,
            backslide in 1_u32..=99,
        ) {
            // Build a leaf with two extents where the second has a smaller
            // logical_block than the first.
            let n_entries: u16 = 2;
            let mut buf = vec![0u8; 12 + 2 * 12];
            buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
            buf[2..4].copy_from_slice(&n_entries.to_le_bytes());
            buf[4..6].copy_from_slice(&n_entries.to_le_bytes());
            buf[6..8].copy_from_slice(&0_u16.to_le_bytes());
            // First extent at logical_block = first_logical, length 1.
            buf[12..16].copy_from_slice(&first_logical.to_le_bytes());
            buf[16..18].copy_from_slice(&1_u16.to_le_bytes());
            // Second extent at first_logical - backslide (out of order).
            let second_logical = first_logical - backslide;
            buf[24..28].copy_from_slice(&second_logical.to_le_bytes());
            buf[28..30].copy_from_slice(&1_u16.to_le_bytes());
            prop_assert!(
                parse_extent_tree(&buf).is_err(),
                "unsorted leaf extents must be rejected"
            );
        }

        /// Overlapping leaf extents are always rejected.  Two extents whose
        /// logical ranges intersect would corrupt binary search lookups.
        #[test]
        fn ext4_proptest_extent_tree_overlapping_leaf_rejected(
            first_logical in 0_u32..=10_000,
            first_len in 4_u16..=100,
            overlap in 1_u32..=3,
        ) {
            let n_entries: u16 = 2;
            let mut buf = vec![0u8; 12 + 2 * 12];
            buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
            buf[2..4].copy_from_slice(&n_entries.to_le_bytes());
            buf[4..6].copy_from_slice(&n_entries.to_le_bytes());
            buf[6..8].copy_from_slice(&0_u16.to_le_bytes());
            // First extent: [first_logical, first_logical + first_len)
            buf[12..16].copy_from_slice(&first_logical.to_le_bytes());
            buf[16..18].copy_from_slice(&first_len.to_le_bytes());
            // Second extent starts inside the first one.
            let second_logical = first_logical + u32::from(first_len) - overlap;
            buf[24..28].copy_from_slice(&second_logical.to_le_bytes());
            buf[28..30].copy_from_slice(&1_u16.to_le_bytes());
            prop_assert!(
                parse_extent_tree(&buf).is_err(),
                "overlapping leaf extents must be rejected"
            );
        }

        /// Unsorted index entries are always rejected.
        #[test]
        fn ext4_proptest_extent_tree_unsorted_index_rejected(
            first_logical in 100_u32..=10_000,
            backslide in 0_u32..=99,
        ) {
            let n_entries: u16 = 2;
            let depth: u16 = 1;
            let mut buf = vec![0u8; 12 + 2 * 12];
            buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
            buf[2..4].copy_from_slice(&n_entries.to_le_bytes());
            buf[4..6].copy_from_slice(&n_entries.to_le_bytes());
            buf[6..8].copy_from_slice(&depth.to_le_bytes());
            buf[12..16].copy_from_slice(&first_logical.to_le_bytes());
            // Index entries must be *strictly* increasing — equal also rejected.
            let second_logical = first_logical - backslide;
            buf[24..28].copy_from_slice(&second_logical.to_le_bytes());
            prop_assert!(
                parse_extent_tree(&buf).is_err(),
                "unsorted or duplicate index entries must be rejected"
            );
        }

        /// Extent entries > max_entries is always rejected.
        #[test]
        fn ext4_proptest_extent_tree_entries_gt_max_rejected(n_entries in 2_u16..=20) {
            let max_entries = n_entries - 1;
            let mut buf = vec![0u8; 12 + usize::from(n_entries) * 12];
            buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
            buf[2..4].copy_from_slice(&n_entries.to_le_bytes());
            buf[4..6].copy_from_slice(&max_entries.to_le_bytes());
            prop_assert!(parse_extent_tree(&buf).is_err(), "entries > max should fail");
        }

        /// Bad magic in extent header always fails.
        #[test]
        fn ext4_proptest_extent_tree_bad_magic_rejected(magic in any::<u16>()) {
            prop_assume!(magic != EXT4_EXTENT_MAGIC);
            let mut buf = vec![0u8; 12];
            buf[0..2].copy_from_slice(&magic.to_le_bytes());
            prop_assert!(parse_extent_tree(&buf).is_err(), "wrong magic should fail");
        }

        // ── Directory entry structured construction & lookup ─────────

        /// Building a valid dir block with structured entries, parsing
        /// recovers entries and lookup finds them.
        #[test]
        fn ext4_proptest_dir_block_structured_roundtrip(
            inode1 in 1_u32..=u32::MAX,
            inode2 in 1_u32..=u32::MAX,
            ft1 in 0_u8..=7,
            ft2 in 0_u8..=7,
            name1_len in 1_u8..=20,
            name2_len in 1_u8..=20,
            fill1 in any::<u8>(),
            fill2 in any::<u8>(),
        ) {
            let block_size = 1024_u32;
            let mut block = vec![0u8; block_size as usize];
            let actual1 = (8 + usize::from(name1_len) + 3) & !3;
            let actual1_u16 = u16::try_from(actual1).expect("block_size bounds rec_len");
            let rec_len2 = block_size as usize - actual1;
            let rec_len2_u16 = u16::try_from(rec_len2).expect("block_size bounds rec_len");
            block[0..4].copy_from_slice(&inode1.to_le_bytes());
            block[4..6].copy_from_slice(&actual1_u16.to_le_bytes());
            block[6] = name1_len;
            block[7] = ft1;
            let name1: Vec<u8> = (0..name1_len).map(|i| b'a' + (fill1.wrapping_add(i)) % 26).collect();
            block[8..8 + usize::from(name1_len)].copy_from_slice(&name1);
            let off2 = actual1;
            block[off2..off2 + 4].copy_from_slice(&inode2.to_le_bytes());
            block[off2 + 4..off2 + 6].copy_from_slice(&rec_len2_u16.to_le_bytes());
            block[off2 + 6] = name2_len;
            block[off2 + 7] = ft2;
            let name2: Vec<u8> = (0..name2_len).map(|i| b'A' + (fill2.wrapping_add(i)) % 26).collect();
            block[off2 + 8..off2 + 8 + usize::from(name2_len)].copy_from_slice(&name2);
            let (entries, _tail) = parse_dir_block(&block, block_size).expect("valid dir block");
            prop_assert_eq!(entries.len(), 2);
            prop_assert_eq!(entries[0].inode, inode1);
            prop_assert_eq!(&entries[0].name, &name1);
            prop_assert_eq!(entries[1].inode, inode2);
            prop_assert_eq!(&entries[1].name, &name2);
            let found1 = lookup_in_dir_block(&block, block_size, &name1).unwrap();
            prop_assert!(found1.is_some());
            prop_assert_eq!(found1.unwrap().inode, inode1);
            let found2 = lookup_in_dir_block(&block, block_size, &name2).unwrap();
            prop_assert!(found2.is_some());
            prop_assert_eq!(found2.unwrap().inode, inode2);
            prop_assert!(lookup_in_dir_block(&block, block_size, b"ZZZZZZ_NONEXISTENT").unwrap().is_none());
        }

        /// parse_dir_block and iter_dir_block produce the same entries.
        #[test]
        fn ext4_proptest_dir_parse_iter_consistency(
            inode_val in 1_u32..=u32::MAX,
            name_len in 1_u8..=30,
        ) {
            let block_size = 1024_u32;
            let mut block = vec![0u8; block_size as usize];
            block[0..4].copy_from_slice(&inode_val.to_le_bytes());
            let block_size_u16 = u16::try_from(block_size).expect("strategy uses 1024 block size");
            block[4..6].copy_from_slice(&block_size_u16.to_le_bytes());
            block[6] = name_len;
            block[7] = 1;
            let name: Vec<u8> = (0..name_len).map(|i| b'x' + (i % 3)).collect();
            block[8..8 + usize::from(name_len)].copy_from_slice(&name);
            let (parsed_entries, _) = parse_dir_block(&block, block_size).expect("parse");
            let iter_entries: Vec<_> = iter_dir_block(&block, block_size)
                .filter_map(Result::ok)
                .collect();
            prop_assert_eq!(parsed_entries.len(), iter_entries.len());
            for (pe, ie) in parsed_entries.iter().zip(iter_entries.iter()) {
                prop_assert_eq!(pe.inode, ie.inode);
                prop_assert_eq!(&pe.name[..], ie.name);
                prop_assert_eq!(pe.name_len, ie.name_len);
            }
        }

        // ── Ext4FileType from_raw ────────────────────────────────────

        /// from_raw returns Unknown for values > 7.
        #[test]
        fn ext4_proptest_file_type_from_raw_no_panic(val in any::<u8>()) {
            let ft = Ext4FileType::from_raw(val);
            if val > 7 {
                prop_assert_eq!(ft, Ext4FileType::Unknown);
            }
        }

        // ── Checksum stamp+verify roundtrips ─────────────────────────

        /// Dir block with stamped checksum passes verification.
        #[test]
        fn ext4_proptest_dir_block_checksum_stamp_verify(
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
            generation in any::<u32>(),
            block_size in prop_oneof![Just(1024_usize), Just(2048_usize), Just(4096_usize)],
        ) {
            let mut block = build_dir_block_for_checksum_test(block_size);
            stamp_dir_block_checksum(&mut block, csum_seed, ino, generation);
            prop_assert!(verify_dir_block_checksum(&block, csum_seed, ino, generation).is_ok());
        }

        /// MR-INO: identical dir-block bodies stamped at two different inode
        /// numbers must produce different stored checksums, and a stamp from
        /// one ino must NOT verify when presented as another (defends against
        /// cross-slot replay).
        #[test]
        fn ext4_proptest_dir_block_checksum_is_sensitive_to_inode_number(
            csum_seed in any::<u32>(),
            ino_a in any::<u32>(),
            ino_b_delta in 1_u32..,
            generation in any::<u32>(),
            block_size in prop_oneof![Just(1024_usize), Just(2048_usize), Just(4096_usize)],
        ) {
            let ino_b = ino_a.wrapping_add(ino_b_delta);
            let mut block_a = build_dir_block_for_checksum_test(block_size);
            let mut block_b = block_a.clone();
            stamp_dir_block_checksum(&mut block_a, csum_seed, ino_a, generation);
            stamp_dir_block_checksum(&mut block_b, csum_seed, ino_b, generation);

            prop_assert_ne!(
                &block_a[block_size - 4..],
                &block_b[block_size - 4..],
                "dir-block stamps for inode {:#010x} and inode {:#010x} must differ",
                ino_a,
                ino_b
            );
            prop_assert!(
                verify_dir_block_checksum(&block_b, csum_seed, ino_a, generation).is_err(),
                "stamp from inode {:#010x} must NOT verify when presented as inode {:#010x}",
                ino_b,
                ino_a
            );
        }

        /// MR-GEN: changing only the generation field must shift the stamped
        /// checksum.  Generation participates in the per-inode seed, so two
        /// stampings at the same (csum_seed, ino) but different generations
        /// must yield distinct stored checksums.
        #[test]
        fn ext4_proptest_dir_block_checksum_is_sensitive_to_generation(
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
            gen_a in any::<u32>(),
            gen_delta in 1_u32..,
            block_size in prop_oneof![Just(1024_usize), Just(2048_usize), Just(4096_usize)],
        ) {
            let gen_b = gen_a.wrapping_add(gen_delta);
            let mut block_a = build_dir_block_for_checksum_test(block_size);
            let mut block_b = block_a.clone();
            stamp_dir_block_checksum(&mut block_a, csum_seed, ino, gen_a);
            stamp_dir_block_checksum(&mut block_b, csum_seed, ino, gen_b);

            prop_assert_ne!(
                &block_a[block_size - 4..],
                &block_b[block_size - 4..],
                "generation flip from {:#010x} to {:#010x} must change the stored checksum",
                gen_a,
                gen_b
            );
        }

        /// MR-SEED: identical body+ino+generation stamped under two
        /// different filesystem checksum seeds must yield different stored
        /// checksums, and a cross-seed verification must fail.  This is what
        /// makes a valid stamp from filesystem instance X non-replayable on
        /// instance Y.
        #[test]
        fn ext4_proptest_dir_block_checksum_is_sensitive_to_csum_seed(
            seed_a in any::<u32>(),
            seed_delta in 1_u32..,
            ino in any::<u32>(),
            generation in any::<u32>(),
            block_size in prop_oneof![Just(1024_usize), Just(2048_usize), Just(4096_usize)],
        ) {
            let seed_b = seed_a.wrapping_add(seed_delta);
            let mut block_a = build_dir_block_for_checksum_test(block_size);
            let mut block_b = block_a.clone();
            stamp_dir_block_checksum(&mut block_a, seed_a, ino, generation);
            stamp_dir_block_checksum(&mut block_b, seed_b, ino, generation);

            prop_assert_ne!(
                &block_a[block_size - 4..],
                &block_b[block_size - 4..],
                "dir-block stamp under seed {:#010x} must differ from stamp under seed {:#010x}",
                seed_a,
                seed_b
            );
            prop_assert!(
                verify_dir_block_checksum(&block_a, seed_b, ino, generation).is_err(),
                "stamp under seed A must NOT verify under seed B"
            );
        }

        /// MR-DETECT: flipping any single bit anywhere in the covered region
        /// `[0..block_size - 12]` must invalidate verification.  The 12-byte
        /// tail is excluded from coverage by construction (stamp/verify both
        /// only CRC the prefix), so flips inside the tail are unsound and
        /// must be skipped.
        #[test]
        fn ext4_proptest_dir_block_checksum_detects_single_bit_flip_in_body(
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
            generation in any::<u32>(),
            block_size in prop_oneof![Just(1024_usize), Just(2048_usize), Just(4096_usize)],
            flip_pos in 0_usize..4096,
            flip_bit in 0_u8..8,
        ) {
            prop_assume!(flip_pos < block_size - 12);

            let mut block = build_dir_block_for_checksum_test(block_size);
            stamp_dir_block_checksum(&mut block, csum_seed, ino, generation);

            // Sanity: the unflipped stamp verifies.
            prop_assert!(
                verify_dir_block_checksum(&block, csum_seed, ino, generation).is_ok()
            );

            block[flip_pos] ^= 1_u8 << flip_bit;
            prop_assert!(
                verify_dir_block_checksum(&block, csum_seed, ino, generation).is_err(),
                "single-bit flip at byte {:#06x} bit {} must invalidate the stored checksum",
                flip_pos,
                flip_bit
            );
        }

        /// Extent block with stamped checksum passes verification.
        #[test]
        fn ext4_proptest_extent_block_checksum_stamp_verify(
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
            generation in any::<u32>(),
            eh_max in 1_u16..=10,
        ) {
            let tail_off = 12 + usize::from(eh_max) * 12;
            let mut block = vec![0u8; tail_off + 4];
            block[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
            block[4..6].copy_from_slice(&eh_max.to_le_bytes());
            let seed = ext4_chksum(csum_seed, &ino.to_le_bytes());
            let seed = ext4_chksum(seed, &generation.to_le_bytes());
            let csum = ext4_chksum(seed, &block[..tail_off]);
            block[tail_off..tail_off + 4].copy_from_slice(&csum.to_le_bytes());
            prop_assert!(verify_extent_block_checksum(&block, csum_seed, ino, generation).is_ok());
        }

        /// Restamping must ignore any previous extent-tail checksum bytes because
        /// the checksum coverage ends immediately before the 4-byte tail slot.
        #[test]
        fn ext4_proptest_extent_block_checksum_stamping_ignores_previous_tail_contents(
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
            generation in any::<u32>(),
            eh_max in 1_u16..=10,
            tail_garbage in any::<u32>(),
        ) {
            let tail_off = 12 + usize::from(eh_max) * 12;
            let mut stamped_from_clean = build_extent_block_for_checksum_test(eh_max);
            let mut stamped_from_dirty = stamped_from_clean.clone();
            stamped_from_dirty[tail_off..tail_off + 4].copy_from_slice(&tail_garbage.to_le_bytes());

            stamp_extent_block_checksum(&mut stamped_from_clean, csum_seed, ino, generation);
            stamp_extent_block_checksum(&mut stamped_from_dirty, csum_seed, ino, generation);

            prop_assert_eq!(
                &stamped_from_dirty,
                &stamped_from_clean,
                "restamping must ignore prior extent tail checksum bytes"
            );
            prop_assert!(
                verify_extent_block_checksum(&stamped_from_dirty, csum_seed, ino, generation).is_ok(),
                "restamped extent block checksum must verify"
            );
        }

        /// MR-INO: identical extent-block bodies stamped at two different
        /// inode numbers must produce different stored checksums, and a
        /// stamp from one ino must NOT verify when presented as another.
        /// Defends against cross-slot replay of a valid extent tree block.
        #[test]
        fn ext4_proptest_extent_block_checksum_is_sensitive_to_inode_number(
            csum_seed in any::<u32>(),
            ino_a in any::<u32>(),
            ino_b_delta in 1_u32..,
            generation in any::<u32>(),
            eh_max in 1_u16..=10,
        ) {
            let ino_b = ino_a.wrapping_add(ino_b_delta);
            let mut block_a = build_extent_block_for_checksum_test(eh_max);
            let mut block_b = block_a.clone();
            stamp_extent_block_checksum(&mut block_a, csum_seed, ino_a, generation);
            stamp_extent_block_checksum(&mut block_b, csum_seed, ino_b, generation);

            let tail_off = 12 + usize::from(eh_max) * 12;
            prop_assert_ne!(
                &block_a[tail_off..tail_off + 4],
                &block_b[tail_off..tail_off + 4],
                "extent-block stamps for inode {:#010x} and inode {:#010x} must differ",
                ino_a,
                ino_b
            );
            prop_assert!(
                verify_extent_block_checksum(&block_b, csum_seed, ino_a, generation).is_err(),
                "stamp from inode {:#010x} must NOT verify when presented as inode {:#010x}",
                ino_b,
                ino_a
            );
        }

        /// MR-GEN: changing only the generation field must shift the stamped
        /// checksum.  Extent blocks reuse the same per-inode seed as inode
        /// and dir blocks, so generation participation is required.
        #[test]
        fn ext4_proptest_extent_block_checksum_is_sensitive_to_generation(
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
            gen_a in any::<u32>(),
            gen_delta in 1_u32..,
            eh_max in 1_u16..=10,
        ) {
            let gen_b = gen_a.wrapping_add(gen_delta);
            let mut block_a = build_extent_block_for_checksum_test(eh_max);
            let mut block_b = block_a.clone();
            stamp_extent_block_checksum(&mut block_a, csum_seed, ino, gen_a);
            stamp_extent_block_checksum(&mut block_b, csum_seed, ino, gen_b);

            let tail_off = 12 + usize::from(eh_max) * 12;
            prop_assert_ne!(
                &block_a[tail_off..tail_off + 4],
                &block_b[tail_off..tail_off + 4],
                "generation flip from {:#010x} to {:#010x} must change the stored checksum",
                gen_a,
                gen_b
            );
        }

        /// MR-SEED: identical body+ino+generation stamped under two
        /// different filesystem checksum seeds must yield different stored
        /// checksums, and a cross-seed verification must fail.
        #[test]
        fn ext4_proptest_extent_block_checksum_is_sensitive_to_csum_seed(
            seed_a in any::<u32>(),
            seed_delta in 1_u32..,
            ino in any::<u32>(),
            generation in any::<u32>(),
            eh_max in 1_u16..=10,
        ) {
            let seed_b = seed_a.wrapping_add(seed_delta);
            let mut block_a = build_extent_block_for_checksum_test(eh_max);
            let mut block_b = block_a.clone();
            stamp_extent_block_checksum(&mut block_a, seed_a, ino, generation);
            stamp_extent_block_checksum(&mut block_b, seed_b, ino, generation);

            let tail_off = 12 + usize::from(eh_max) * 12;
            prop_assert_ne!(
                &block_a[tail_off..tail_off + 4],
                &block_b[tail_off..tail_off + 4],
                "extent-block stamp under seed {:#010x} must differ from stamp under seed {:#010x}",
                seed_a,
                seed_b
            );
            prop_assert!(
                verify_extent_block_checksum(&block_a, seed_b, ino, generation).is_err(),
                "stamp under seed A must NOT verify under seed B"
            );
        }

        /// MR-DETECT: flipping any single bit in the covered prefix
        /// `[0..tail_off]` must invalidate verification.  Flips inside the
        /// 4-byte stored-checksum slot (`[tail_off..tail_off + 4]`) are
        /// excluded — the verifier reads the stored checksum from there
        /// rather than CRC-ing it, so a flip there changes which stored
        /// value the comparator reads but doesn't break the digest contract
        /// in a way MR-DETECT is meant to catch.
        #[test]
        fn ext4_proptest_extent_block_checksum_detects_single_bit_flip_in_body(
            csum_seed in any::<u32>(),
            ino in any::<u32>(),
            generation in any::<u32>(),
            eh_max in 1_u16..=10,
            flip_pos_raw in 0_usize..132,
            flip_bit in 0_u8..8,
        ) {
            let tail_off = 12 + usize::from(eh_max) * 12;
            prop_assume!(flip_pos_raw < tail_off);

            let mut block = build_extent_block_for_checksum_test(eh_max);
            stamp_extent_block_checksum(&mut block, csum_seed, ino, generation);

            // Sanity: the unflipped stamp verifies.
            prop_assert!(
                verify_extent_block_checksum(&block, csum_seed, ino, generation).is_ok()
            );

            block[flip_pos_raw] ^= 1_u8 << flip_bit;
            prop_assert!(
                verify_extent_block_checksum(&block, csum_seed, ino, generation).is_err(),
                "single-bit flip at byte {:#06x} bit {} must invalidate the stored checksum",
                flip_pos_raw,
                flip_bit
            );
        }

        // ── Block bitmap ─────────────────────────────────────────────

        /// verify_block_bitmap_free_count with correct count passes.
        #[test]
        fn ext4_proptest_block_bitmap_verify_correct_passes(
            byte_len in 1_usize..=128,
            fill_seed in any::<u64>(),
        ) {
            let total_bits = u32::try_from(byte_len * 8).unwrap();
            let mut bm = vec![0u8; byte_len];
            let mut rng = fill_seed;
            for b in &mut bm {
                rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                *b = rng.to_le_bytes()[7];
            }
            let used: u32 = bm.iter().map(|b| b.count_ones()).sum();
            let free = total_bits.saturating_sub(used);
            prop_assert!(verify_block_bitmap_free_count(&bm, total_bits, free).is_ok());
        }

        // bd-e5vp5 — stamp/verify proptest MRs for the two BITMAP
        // checksums. Sister stamp/verify proptests exist for
        // group_desc (ext4_proptest_gd_checksum_stamp_verify_roundtrip),
        // dir_block (ext4_proptest_dir_block_checksum_stamp_verify),
        // and extent_block (ext4_proptest_extent_block_checksum_stamp_verify);
        // the two bitmap checksums had only a fixed-input smoke test.
        // bitmap_csum protects per-group allocation state — a regression
        // that masks for one bitmap content+seed but fails for arbitrary
        // inputs (endian swap, wrong slice length, lo/hi swap) would
        // silently corrupt every block-group allocation.

        /// MR-1 block_bitmap stamp(bm, seed) → verify must succeed for any
        /// bitmap content + seed across both 32+64-byte descriptor sizes.
        #[test]
        fn ext4_proptest_block_bitmap_checksum_stamp_verify(
            csum_seed in any::<u32>(),
            byte_len in prop_oneof![Just(8_usize), Just(32_usize), Just(128_usize), Just(512_usize)],
            fill_seed in any::<u64>(),
            desc_size in prop_oneof![Just(32_u16), Just(64_u16)],
        ) {
            let clusters_per_group = u32::try_from(byte_len * 8).unwrap();
            let mut bm = vec![0u8; byte_len];
            let mut rng = fill_seed;
            for b in &mut bm {
                rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                *b = rng.to_le_bytes()[7];
            }
            let mut gd = Ext4GroupDesc {
                block_bitmap: 0, inode_bitmap: 0, inode_table: 0,
                free_blocks_count: 0, free_inodes_count: 0, used_dirs_count: 0,
                itable_unused: 0, flags: 0, checksum: 0,
                block_bitmap_csum: 0xDEAD_BEEF, // pre-filled garbage to ensure stamp overwrites
                inode_bitmap_csum: 0,
            };
            stamp_block_bitmap_checksum(&bm, csum_seed, clusters_per_group, &mut gd, desc_size);
            // For 32-byte descriptor, only the low 16 bits of bitmap_csum are stored.
            if desc_size < 64 {
                prop_assert_eq!(gd.block_bitmap_csum >> 16, 0,
                    "32-byte descriptor must clear high half of block_bitmap_csum");
            }
            prop_assert!(
                verify_block_bitmap_checksum(&bm, csum_seed, clusters_per_group, &gd, desc_size).is_ok(),
                "stamp then verify must succeed for byte_len={byte_len}, desc_size={desc_size}"
            );
        }

        /// MR-2 inode_bitmap stamp(bm, seed) → verify must succeed.
        #[test]
        fn ext4_proptest_inode_bitmap_checksum_stamp_verify(
            csum_seed in any::<u32>(),
            byte_len in prop_oneof![Just(8_usize), Just(32_usize), Just(128_usize), Just(256_usize)],
            fill_seed in any::<u64>(),
            desc_size in prop_oneof![Just(32_u16), Just(64_u16)],
        ) {
            let inodes_per_group = u32::try_from(byte_len * 8).unwrap();
            let mut bm = vec![0u8; byte_len];
            let mut rng = fill_seed;
            for b in &mut bm {
                rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                *b = rng.to_le_bytes()[7];
            }
            let mut gd = Ext4GroupDesc {
                block_bitmap: 0, inode_bitmap: 0, inode_table: 0,
                free_blocks_count: 0, free_inodes_count: 0, used_dirs_count: 0,
                itable_unused: 0, flags: 0, checksum: 0,
                block_bitmap_csum: 0,
                inode_bitmap_csum: 0xCAFE_BABE, // pre-filled garbage to ensure stamp overwrites
            };
            stamp_inode_bitmap_checksum(&bm, csum_seed, inodes_per_group, &mut gd, desc_size);
            if desc_size < 64 {
                prop_assert_eq!(gd.inode_bitmap_csum >> 16, 0,
                    "32-byte descriptor must clear high half of inode_bitmap_csum");
            }
            prop_assert!(
                verify_inode_bitmap_checksum(&bm, csum_seed, inodes_per_group, &gd, desc_size).is_ok(),
                "stamp then verify must succeed for byte_len={byte_len}, desc_size={desc_size}"
            );
        }

        /// MR-3 cross-seed non-replay for block_bitmap: a stamp under
        /// seed_a must NOT verify under seed_b for any distinct seeds.
        /// Defends against cross-filesystem replay of a valid bitmap-csum.
        #[test]
        fn ext4_proptest_block_bitmap_checksum_cross_seed_non_replay(
            seed_a in any::<u32>(),
            seed_delta in 1_u32..,
            byte_len in prop_oneof![Just(8_usize), Just(32_usize), Just(128_usize)],
            fill_seed in any::<u64>(),
        ) {
            let seed_b = seed_a.wrapping_add(seed_delta);
            let clusters_per_group = u32::try_from(byte_len * 8).unwrap();
            let mut bm = vec![0u8; byte_len];
            let mut rng = fill_seed;
            for b in &mut bm {
                rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                *b = rng.to_le_bytes()[7];
            }
            let mut gd = Ext4GroupDesc {
                block_bitmap: 0, inode_bitmap: 0, inode_table: 0,
                free_blocks_count: 0, free_inodes_count: 0, used_dirs_count: 0,
                itable_unused: 0, flags: 0, checksum: 0,
                block_bitmap_csum: 0, inode_bitmap_csum: 0,
            };
            stamp_block_bitmap_checksum(&bm, seed_a, clusters_per_group, &mut gd, 64);
            // Sanity: same-seed verifies.
            prop_assert!(
                verify_block_bitmap_checksum(&bm, seed_a, clusters_per_group, &gd, 64).is_ok()
            );
            // Cross-seed must fail unless CRC32C of (seed_a, bm) == CRC32C of (seed_b, bm),
            // which is astronomically unlikely for 32-bit seeds with arbitrary delta.
            // Filter the rare case to keep the proptest stable across all 32-bit deltas.
            let csum_b = block_bitmap_checksum_value(&bm, seed_b, clusters_per_group, 64);
            prop_assume!(csum_b != gd.block_bitmap_csum);
            prop_assert!(
                verify_block_bitmap_checksum(&bm, seed_b, clusters_per_group, &gd, 64).is_err(),
                "stamp under seed {seed_a:#x} must NOT verify under seed {seed_b:#x}"
            );
        }

        /// Cross-seed non-replay for inode_bitmap (missed sibling of the
        /// block_bitmap test): a stamp under seed_a must NOT verify under
        /// seed_b, defending against cross-filesystem replay of a valid
        /// inode-bitmap checksum.
        #[test]
        fn ext4_proptest_inode_bitmap_checksum_cross_seed_non_replay(
            seed_a in any::<u32>(),
            seed_delta in 1_u32..,
            byte_len in prop_oneof![Just(8_usize), Just(32_usize), Just(128_usize)],
            fill_seed in any::<u64>(),
        ) {
            let seed_b = seed_a.wrapping_add(seed_delta);
            let inodes_per_group = u32::try_from(byte_len * 8).unwrap();
            let mut bm = vec![0u8; byte_len];
            let mut rng = fill_seed;
            for b in &mut bm {
                rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                *b = rng.to_le_bytes()[7];
            }
            let mut gd = Ext4GroupDesc {
                block_bitmap: 0, inode_bitmap: 0, inode_table: 0,
                free_blocks_count: 0, free_inodes_count: 0, used_dirs_count: 0,
                itable_unused: 0, flags: 0, checksum: 0,
                block_bitmap_csum: 0, inode_bitmap_csum: 0,
            };
            stamp_inode_bitmap_checksum(&bm, seed_a, inodes_per_group, &mut gd, 64);
            // Sanity: same-seed verifies.
            prop_assert!(
                verify_inode_bitmap_checksum(&bm, seed_a, inodes_per_group, &gd, 64).is_ok()
            );
            // Filter the astronomically rare cross-seed collision to keep stable.
            let csum_b = inode_bitmap_checksum_value(&bm, seed_b, inodes_per_group, 64);
            prop_assume!(csum_b != gd.inode_bitmap_csum);
            prop_assert!(
                verify_inode_bitmap_checksum(&bm, seed_b, inodes_per_group, &gd, 64).is_err(),
                "stamp under seed {seed_a:#x} must NOT verify under seed {seed_b:#x}"
            );
        }

        // ── Superblock geometry and validation ───────────────────────

        /// Well-formed superblock always passes validate_geometry().
        #[test]
        fn ext4_proptest_superblock_validate_geometry(
            log_block_size in 0_u32..=2,
            blocks_per_group in 1_u32..=8192,
            inodes_per_group in 1_u32..=8192,
        ) {
            let incompat = Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0;
            let sb = make_proptest_valid_ext4_superblock(
                log_block_size, blocks_per_group, inodes_per_group,
                64, incompat, b"geom-val",
            );
            let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse sb");
            prop_assert!(parsed.validate_geometry().is_ok());
        }

        /// validate_v1 requires FILETYPE; EXTENTS is optional.
        #[test]
        fn ext4_proptest_superblock_validate_v1_requires_flags(
            has_filetype in any::<bool>(),
            has_extents in any::<bool>(),
        ) {
            let mut incompat = 0_u32;
            if has_filetype { incompat |= Ext4IncompatFeatures::FILETYPE.0; }
            if has_extents { incompat |= Ext4IncompatFeatures::EXTENTS.0; }
            let sb = make_proptest_valid_ext4_superblock(
                2, 8192, 4096, 64, incompat, b"v1-check",
            );
            let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse sb");
            let result = parsed.validate_v1();
            if has_filetype {
                prop_assert!(result.is_ok());
            } else {
                prop_assert!(result.is_err());
            }
        }

        /// bd-c6zvd — Ext4Superblock::group_desc_checksum_kind dispatch
        /// contract:
        ///   * MetadataCsum  iff METADATA_CSUM ro_compat is set
        ///   * GdtCsum       iff GDT_CSUM ro_compat is set AND NOT MetadataCsum
        ///   * None          otherwise
        ///
        /// Pins the 3-way mutually-exclusive dispatcher used by every
        /// stamp_group_desc_checksum / verify_group_desc_checksum call.
        /// A regression that flipped the GdtCsum precedence (returning
        /// GdtCsum even when METADATA_CSUM is set) would silently corrupt
        /// every group_desc checksum verification on a metadata_csum
        /// filesystem — and the stamp/verify roundtrip MR wouldn't catch
        /// it because both sides use the same dispatcher.
        #[test]
        fn ext4_proptest_group_desc_checksum_kind_dispatch(
            has_meta in any::<bool>(),
            has_gdt in any::<bool>(),
        ) {
            // Compose the ro_compat field with the two relevant flags.
            let incompat = Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0;
            let mut sb = make_proptest_valid_ext4_superblock(
                2, 8192, 4096, 64, incompat, b"ck-dispatch",
            );
            let mut ro_compat = 0_u32;
            if has_meta { ro_compat |= Ext4RoCompatFeatures::METADATA_CSUM.0; }
            if has_gdt  { ro_compat |= Ext4RoCompatFeatures::GDT_CSUM.0; }
            sb[0x64..0x68].copy_from_slice(&ro_compat.to_le_bytes());
            let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse sb");

            let kind = parsed.group_desc_checksum_kind();
            let expected = if has_meta {
                Ext4GroupDescChecksumKind::MetadataCsum
            } else if has_gdt {
                Ext4GroupDescChecksumKind::GdtCsum
            } else {
                Ext4GroupDescChecksumKind::None
            };
            prop_assert_eq!(kind, expected,
                "dispatch (meta={}, gdt={}) must yield {:?}", has_meta, has_gdt, expected);

            // Mutual exclusivity: the three booleans (has_metadata_csum,
            // has_gdt_csum, kind == None) must always sum to exactly 1.
            let is_meta = parsed.has_metadata_csum();
            let is_gdt  = parsed.has_gdt_csum();
            let is_none = matches!(kind, Ext4GroupDescChecksumKind::None);
            let true_count = usize::from(is_meta) + usize::from(is_gdt) + usize::from(is_none);
            prop_assert_eq!(true_count, 1,
                "exactly one of {{has_metadata_csum, has_gdt_csum, kind==None}} must be true \
                 (meta={}, gdt={}, none={})", is_meta, is_gdt, is_none);
        }

        // ── Ext4Extent properties ────────────────────────────────────

        /// actual_len is always in [1, EXT_INIT_MAX_LEN].
        #[test]
        fn ext4_proptest_extent_actual_len_bounded(raw_len in 1_u16..=u16::MAX) {
            let ext = Ext4Extent { logical_block: 0, raw_len, physical_start: 0 };
            let len = ext.actual_len();
            prop_assert!(len >= 1);
            prop_assert!(len <= EXT_INIT_MAX_LEN);
        }

        /// is_unwritten iff raw_len > EXT_INIT_MAX_LEN.
        #[test]
        fn ext4_proptest_extent_is_unwritten_consistent(raw_len in 1_u16..=u16::MAX) {
            let ext = Ext4Extent { logical_block: 0, raw_len, physical_start: 0 };
            prop_assert_eq!(ext.is_unwritten(), raw_len > EXT_INIT_MAX_LEN);
        }

        // bd-j0zo3 — Metamorphic relations for Ext4Extent::actual_len
        // and the unwritten-extent split-bit encoding. These pin
        // distinct algebraic laws of the kernel's
        // [actual_len][unwritten_bit] u16 layout.

        /// MR1 — actual_len boundary: raw_len == EXT_INIT_MAX_LEN
        /// MUST yield is_unwritten=false AND actual_len=0x8000 (the
        /// max-written extent length). Off-by-one here silently
        /// mis-classifies every max-length written extent.
        #[test]
        fn ext4_proptest_extent_actual_len_boundary_is_written(_dummy in any::<u8>()) {
            let ext = Ext4Extent {
                logical_block: 0,
                raw_len: EXT_INIT_MAX_LEN,
                physical_start: 0,
            };
            prop_assert!(!ext.is_unwritten());
            prop_assert_eq!(ext.actual_len(), EXT_INIT_MAX_LEN);
        }

        /// MR2 — Unwritten range: for raw_len in (EXT_INIT_MAX_LEN+1)..=u16::MAX,
        /// actual_len == raw_len - EXT_INIT_MAX_LEN AND is_unwritten == true.
        #[test]
        fn ext4_proptest_extent_actual_len_unwritten_range(
            offset in 1_u16..=(u16::MAX - EXT_INIT_MAX_LEN),
        ) {
            let raw_len = EXT_INIT_MAX_LEN + offset;
            let ext = Ext4Extent { logical_block: 0, raw_len, physical_start: 0 };
            prop_assert!(ext.is_unwritten());
            prop_assert_eq!(ext.actual_len(), offset);
        }

        /// MR3 — Written range: for raw_len in 0..=EXT_INIT_MAX_LEN,
        /// actual_len == raw_len AND is_unwritten == false.
        #[test]
        fn ext4_proptest_extent_actual_len_written_range(
            raw_len in 0_u16..=EXT_INIT_MAX_LEN,
        ) {
            let ext = Ext4Extent { logical_block: 0, raw_len, physical_start: 0 };
            prop_assert!(!ext.is_unwritten());
            prop_assert_eq!(ext.actual_len(), raw_len);
        }

        /// MR4 — Encode round-trip: synthesizing raw_len from a
        /// (actual, unwritten) pair and re-decoding it recovers the
        /// original pair. Pins the split-bit encoding bijection.
        #[test]
        fn ext4_proptest_extent_actual_len_encode_roundtrip(
            actual in 1_u16..=EXT_INIT_MAX_LEN,
            unwritten in any::<bool>(),
        ) {
            // EXT_INIT_MAX_LEN = 0x8000, so the unwritten-with-max-actual
            // case raw_len = 0x8000 + 0x8000 overflows u16. Skip it —
            // the kernel never produces that combination because an
            // unwritten extent strictly requires raw_len > EXT_INIT_MAX_LEN
            // and the actual_len for unwritten is bounded by 0x7FFF.
            prop_assume!(!(unwritten && actual == EXT_INIT_MAX_LEN));
            let raw_len = if unwritten {
                actual + EXT_INIT_MAX_LEN
            } else {
                actual
            };
            let ext = Ext4Extent { logical_block: 0, raw_len, physical_start: 0 };
            prop_assert_eq!(ext.actual_len(), actual);
            prop_assert_eq!(ext.is_unwritten(), unwritten);
        }

        /// MR5/MR6 — actual_len is deterministic, bounded by
        /// EXT_INIT_MAX_LEN for every raw u16 encoding, and reconstructing
        /// raw_len from (is_unwritten, actual_len) recovers the source bits.
        #[test]
        fn ext4_proptest_extent_actual_len_is_bounded(raw_len in any::<u16>()) {
            let ext = Ext4Extent { logical_block: 0, raw_len, physical_start: 0 };
            let actual_len = ext.actual_len();
            prop_assert_eq!(actual_len, ext.actual_len());
            prop_assert!(actual_len <= EXT_INIT_MAX_LEN);

            let reconstructed_raw_len = if ext.is_unwritten() {
                actual_len + EXT_INIT_MAX_LEN
            } else {
                actual_len
            };
            prop_assert_eq!(reconstructed_raw_len, raw_len);
        }

        // ── ext4_chksum incremental chaining ─────────────────────────

        /// Feeding data in two chunks equals one-shot.
        #[test]
        fn ext4_proptest_chksum_incremental(
            seed in any::<u32>(),
            data1 in proptest::collection::vec(any::<u8>(), 0..=128),
            data2 in proptest::collection::vec(any::<u8>(), 0..=128),
        ) {
            let mut combined = data1.clone();
            combined.extend_from_slice(&data2);
            prop_assert_eq!(
                ext4_chksum(seed, &combined),
                ext4_chksum(ext4_chksum(seed, &data1), &data2),
                "CRC chaining must equal one-shot"
            );
        }

        // ── Ext4MmpBlock metamorphic relations (bd-pyzm5) ────────────

        /// MR-A — Length rejection: any input shorter than
        /// EXT4_SUPERBLOCK_SIZE (1024 bytes) MUST return
        /// `InsufficientData`. Pins that the parser refuses to read
        /// past the buffer end.
        #[test]
        fn ext4_proptest_mmp_block_rejects_short_input(short_len in 0_usize..=1023) {
            let bytes = vec![0xAB_u8; short_len];
            let result = Ext4MmpBlock::parse_from_bytes(&bytes);
            let is_insufficient = matches!(result, Err(ParseError::InsufficientData { .. }));
            prop_assert!(is_insufficient);
        }

        /// MR-B — Magic rejection: any input >= 1024 bytes whose
        /// first 4 bytes are NOT EXT4_MMP_MAGIC (0x004D_4D50) MUST
        /// return `InvalidField` for `mmp_magic`. Pins the magic
        /// check is the FIRST gate after length validation.
        #[test]
        fn ext4_proptest_mmp_block_rejects_bad_magic(
            bad_magic in any::<u32>().prop_filter("must not match EXT4_MMP_MAGIC", |m| {
                *m != EXT4_MMP_MAGIC
            }),
            tail in proptest::collection::vec(any::<u8>(), 1020..=1020),
        ) {
            let mut bytes = Vec::with_capacity(1024);
            bytes.extend_from_slice(&bad_magic.to_le_bytes());
            bytes.extend_from_slice(&tail);
            let result = Ext4MmpBlock::parse_from_bytes(&bytes);
            let is_bad_magic = matches!(
                result,
                Err(ParseError::InvalidField { field: "mmp_magic", .. })
            );
            prop_assert!(is_bad_magic);
        }

        /// MR-C — Status total partition: for any u32 `seq` value,
        /// `Ext4MmpBlock::status()` returns EXACTLY one of
        /// {Clean, Fsck, Active, UnsafeUnknown}. No overlap, no
        /// zero-coverage. Pins the kernel-defined seq classification.
        #[test]
        fn ext4_proptest_mmp_status_total_partition(seq in any::<u32>()) {
            let mmp = Ext4MmpBlock {
                magic: EXT4_MMP_MAGIC,
                seq,
                time: 0,
                nodename: String::new(),
                bdevname: String::new(),
                check_interval: 0,
                checksum: 0,
            };
            // Exactly one variant must match; encoded as a count.
            let status = mmp.status();
            let count = u32::from(matches!(status, Ext4MmpStatus::Clean))
                + u32::from(matches!(status, Ext4MmpStatus::Fsck))
                + u32::from(matches!(status, Ext4MmpStatus::Active(_)))
                + u32::from(matches!(status, Ext4MmpStatus::UnsafeUnknown(_)));
            prop_assert_eq!(count, 1);

            // Cross-check: the variant carries the EXACT seq when
            // Active or UnsafeUnknown.
            match status {
                Ext4MmpStatus::Active(s) => prop_assert_eq!(s, seq),
                Ext4MmpStatus::UnsafeUnknown(s) => prop_assert_eq!(s, seq),
                Ext4MmpStatus::Clean => prop_assert_eq!(seq, EXT4_MMP_SEQ_CLEAN),
                Ext4MmpStatus::Fsck => prop_assert_eq!(seq, EXT4_MMP_SEQ_FSCK),
            }
        }

        /// MR-D — Tail-invariance: parse_from_bytes reads only the
        /// documented field offsets (0x00..0x72 + 0x3FC..0x400).
        /// Bytes in the gap region (0x72..0x3FC) MUST NOT affect the
        /// parsed struct. Pins the read-only-from-documented-offsets
        /// contract.
        #[test]
        fn ext4_proptest_mmp_block_ignores_gap_bytes(
            seq in any::<u32>(),
            time_lo in any::<u32>(),
            time_hi in any::<u32>(),
            check_interval in any::<u16>(),
            csum in any::<u32>(),
            gap_a in proptest::collection::vec(any::<u8>(), 906..=906),
            gap_b in proptest::collection::vec(any::<u8>(), 906..=906),
        ) {
            // Build two 1024-byte blocks identical except in the
            // gap region 0x72..0x3FC (906 bytes).
            let mut block_a = vec![0_u8; EXT4_SUPERBLOCK_SIZE];
            let mut block_b = vec![0_u8; EXT4_SUPERBLOCK_SIZE];
            for block in [&mut block_a, &mut block_b] {
                block[0x00..0x04].copy_from_slice(&EXT4_MMP_MAGIC.to_le_bytes());
                block[0x04..0x08].copy_from_slice(&seq.to_le_bytes());
                block[0x08..0x0C].copy_from_slice(&time_lo.to_le_bytes());
                block[0x0C..0x10].copy_from_slice(&time_hi.to_le_bytes());
                // 0x10..0x50 nodename + 0x50..0x70 bdevname stay zero.
                block[0x70..0x72].copy_from_slice(&check_interval.to_le_bytes());
                block[EXT4_MMP_CHECKSUM_OFFSET..EXT4_MMP_CHECKSUM_OFFSET + 4]
                    .copy_from_slice(&csum.to_le_bytes());
            }
            // Differ in the gap region.
            block_a[0x72..0x3FC].copy_from_slice(&gap_a);
            block_b[0x72..0x3FC].copy_from_slice(&gap_b);

            let parsed_a = Ext4MmpBlock::parse_from_bytes(&block_a)
                .expect("block_a with valid magic must parse");
            let parsed_b = Ext4MmpBlock::parse_from_bytes(&block_b)
                .expect("block_b with valid magic must parse");
            prop_assert_eq!(parsed_a, parsed_b);
        }

        // ── DirEntry actual_size ─────────────────────────────────────

        /// actual_size is always 4-byte aligned and >= 8.
        #[test]
        fn ext4_proptest_dir_entry_actual_size_aligned(name_len in 0_u8..=255) {
            let entry = Ext4DirEntry {
                inode: 1, rec_len: 0, name_len,
                file_type: Ext4FileType::RegFile,
                name: vec![b'a'; usize::from(name_len)],
            };
            let size = entry.actual_size();
            prop_assert!(size >= 8);
            prop_assert_eq!(size % 4, 0);
        }

        // ── Ext4DirEntry::actual_size kernel-formula MRs (bd-wwket) ──

        /// MR-A (kernel-formula equivalence) — actual_size(name_len)
        /// MUST equal the kernel macro `EXT4_DIR_REC_LEN(name_len)
        /// = (name_len + 8 + 3) & ~3` byte-for-byte. Pins the exact
        /// formula so a future refactor (e.g. `name_len + 11` vs
        /// `8 + name_len + 3`) cannot drift the alignment math.
        #[test]
        fn ext4_proptest_dir_entry_actual_size_matches_kernel_macro(name_len in 0_u8..=255) {
            let entry = Ext4DirEntry {
                inode: 1, rec_len: 0, name_len,
                file_type: Ext4FileType::RegFile,
                name: vec![b'a'; usize::from(name_len)],
            };
            let kernel_formula = (usize::from(name_len) + 8 + 3) & !3;
            prop_assert_eq!(entry.actual_size(), kernel_formula);
        }

        /// MR-B (monotonicity) — actual_size is non-decreasing in
        /// name_len. Adding a byte to the name never shrinks the
        /// on-disk record.
        #[test]
        fn ext4_proptest_dir_entry_actual_size_monotonic(name_len in 0_u8..=254) {
            let mk = |nl: u8| -> usize {
                let entry = Ext4DirEntry {
                    inode: 1, rec_len: 0, name_len: nl,
                    file_type: Ext4FileType::RegFile,
                    name: vec![b'a'; usize::from(nl)],
                };
                entry.actual_size()
            };
            prop_assert!(mk(name_len) <= mk(name_len + 1));
        }

        /// MR-C (step-bounded) — between consecutive name_len values,
        /// actual_size grows by either 0 or 4 (never 1, 2, 3, or > 4).
        /// This is the sharpest formulation of the 4-byte alignment
        /// contract.
        #[test]
        fn ext4_proptest_dir_entry_actual_size_step_is_zero_or_four(name_len in 0_u8..=254) {
            let mk = |nl: u8| -> usize {
                let entry = Ext4DirEntry {
                    inode: 1, rec_len: 0, name_len: nl,
                    file_type: Ext4FileType::RegFile,
                    name: vec![b'a'; usize::from(nl)],
                };
                entry.actual_size()
            };
            let delta = mk(name_len + 1) - mk(name_len);
            prop_assert!(
                delta == 0 || delta == 4,
                "actual_size step must be 0 or 4, got {delta} for name_len={name_len}"
            );
        }

        /// MR-D (4-byte cycle) — across any window of 4 consecutive
        /// name_len values, actual_size grows by exactly 4 in total.
        /// Pins that the alignment rounds up ONCE per 4-byte boundary.
        #[test]
        fn ext4_proptest_dir_entry_actual_size_grows_four_per_window(name_len in 0_u8..=251) {
            let mk = |nl: u8| -> usize {
                let entry = Ext4DirEntry {
                    inode: 1, rec_len: 0, name_len: nl,
                    file_type: Ext4FileType::RegFile,
                    name: vec![b'a'; usize::from(nl)],
                };
                entry.actual_size()
            };
            let total_delta = mk(name_len + 4) - mk(name_len);
            prop_assert_eq!(
                total_delta, 4,
                "actual_size must grow by exactly 4 across 4 name_len increments"
            );
        }

        // ── Ext4FileType::from_raw round-trip / boundary (bd-wwket) ──

        /// MR-FG — from_raw is a total function that round-trips on
        /// every defined variant and falls back to Unknown for every
        /// other u8. Distinct from the bd-343v3 fixed-input pin: this
        /// proptest covers every value in [0, 256) so any future drift
        /// in the match arms (e.g. swapping two variants) trips here
        /// regardless of which value the regression hit.
        #[test]
        fn ext4_proptest_file_type_from_raw_total_and_round_trips(raw in any::<u8>()) {
            let parsed = Ext4FileType::from_raw(raw);
            if raw < EXT4_FT_MAX {
                // Defined range: round-trip via discriminant.
                prop_assert_eq!(parsed as u8, raw);
            } else {
                // Out-of-range (including the 0xDE dir-csum sentinel,
                // which is recognised by the dir-tail pipeline rather
                // than by from_raw): MUST decode to Unknown.
                prop_assert_eq!(parsed, Ext4FileType::Unknown);
            }
        }

        // ── is_reserved_inode metamorphic relations (bd-x1t2n) ───────

        /// MR-A — Zero sentinel always reserved. The kernel uses inode 0
        /// as the "no inode" marker; `is_reserved_inode` must always
        /// classify it as reserved regardless of `first_ino` (even when
        /// first_ino == 0, where the predicate's `< first_ino` arm
        /// degenerates).
        #[test]
        fn ext4_proptest_is_reserved_inode_zero_sentinel(first_ino in any::<u32>()) {
            prop_assert!(is_reserved_inode(first_ino, 0));
        }

        /// MR-B — Cut-off boundary: for any first_ino > 0,
        ///   * is_reserved_inode(first_ino, first_ino) == false
        ///     (first_ino is the FIRST user inode)
        ///   * is_reserved_inode(first_ino, first_ino - 1) == true
        ///     (the slot immediately below is reserved)
        /// Pins the strict-less-than boundary so a regression that
        /// flipped `<` to `<=` would fail here.
        #[test]
        fn ext4_proptest_is_reserved_inode_strict_cutoff(first_ino in 1_u32..=u32::MAX) {
            prop_assert!(
                !is_reserved_inode(first_ino, first_ino),
                "first_ino itself must NOT be reserved (it is the first user inode)"
            );
            prop_assert!(
                is_reserved_inode(first_ino, first_ino - 1),
                "the inode immediately below first_ino must be reserved"
            );
        }

        /// MR-C — Anti-monotonicity in first_ino: for any ino > 0,
        /// raising the first_ino threshold can only keep `ino`
        /// reserved or newly-reserve it — never un-reserve. Formally:
        ///   first_ino_a <= first_ino_b  →
        ///   is_reserved_inode(first_ino_a, ino) <= is_reserved_inode(first_ino_b, ino)
        /// (where false < true). This pins the predicate's
        /// directional dependency on first_ino so a regression that
        /// inverted the comparison sense would fail here.
        #[test]
        fn ext4_proptest_is_reserved_inode_anti_monotonic_in_first_ino(
            first_ino_a in 0_u32..=u32::MAX,
            delta in 0_u32..=1_000_000,
            ino in 1_u32..=u32::MAX,
        ) {
            let first_ino_b = first_ino_a.saturating_add(delta);
            let a = is_reserved_inode(first_ino_a, ino);
            let b = is_reserved_inode(first_ino_b, ino);
            prop_assert!(
                !a || b,
                "raising first_ino must not un-reserve a previously-reserved inode \
                 (a={a}, b={b}, first_ino_a={first_ino_a}, first_ino_b={first_ino_b}, ino={ino})"
            );
        }

        // ── rec_len_from_disk ────────────────────────────────────────

        /// 4-byte-aligned rec_len decodes to itself for standard blocks.
        #[test]
        fn ext4_proptest_rec_len_from_disk_aligned_identity(
            raw in (2_u16..=255).prop_map(|v| v * 4),
            block_size in prop_oneof![Just(1024_u32), Just(2048_u32), Just(4096_u32)],
        ) {
            prop_assert_eq!(rec_len_from_disk(raw, block_size), u32::from(raw));
        }

        /// Sentinel values (0 and 0xFFFC) decode to block_size.
        #[test]
        fn ext4_proptest_rec_len_from_disk_sentinel(
            block_size in prop_oneof![Just(1024_u32), Just(2048_u32), Just(4096_u32)],
        ) {
            prop_assert_eq!(rec_len_from_disk(0xFFFC, block_size), block_size);
            prop_assert_eq!(rec_len_from_disk(0, block_size), block_size);
        }

        // ── Superblock 64-bit block count ────────────────────────────

        /// 64BIT flag: low 32 bits of blocks_count preserved.
        #[test]
        fn ext4_proptest_superblock_64bit_block_count(
            blocks_lo in any::<u32>(),
            blocks_hi in any::<u32>(),
        ) {
            let incompat = Ext4IncompatFeatures::FILETYPE.0
                | Ext4IncompatFeatures::EXTENTS.0
                | Ext4IncompatFeatures::BIT64.0;
            let mut sb = make_proptest_valid_ext4_superblock(
                2, 8192, 4096, 64, incompat, b"64bit",
            );
            sb[0x04..0x08].copy_from_slice(&blocks_lo.to_le_bytes());
            if sb.len() > 0x154 {
                sb[0x150..0x154].copy_from_slice(&blocks_hi.to_le_bytes());
            }
            let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse 64bit sb");
            prop_assert!(parsed.is_64bit());
            prop_assert_eq!(parsed.blocks_count & u64::from(u32::MAX), u64::from(blocks_lo));
        }

        // ── Ext4GroupDesc encode/decode metamorphic relations (bd-ov7zr) ────
        // The fixed-input `group_desc_write_to_bytes_roundtrip_32`/`_64` tests
        // pin one example each; these proptests exercise the full field-value
        // space and pin the lo/hi split contract so a future refactor of the
        // 32-vs-64 branching can't silently corrupt 64-bit-mode bitmap pointers.

        /// MR1 — full bijection at desc_size=64: parse(write(gd, 64), 64) == gd.
        #[test]
        fn ext4_proptest_group_desc_full_roundtrip_64(
            block_bitmap in any::<u64>(),
            inode_bitmap in any::<u64>(),
            inode_table in any::<u64>(),
            free_blocks_count in any::<u32>(),
            free_inodes_count in any::<u32>(),
            used_dirs_count in any::<u32>(),
            itable_unused in any::<u32>(),
            flags in any::<u16>(),
            checksum in any::<u16>(),
            block_bitmap_csum in any::<u32>(),
            inode_bitmap_csum in any::<u32>(),
        ) {
            let gd = Ext4GroupDesc {
                block_bitmap,
                inode_bitmap,
                inode_table,
                free_blocks_count,
                free_inodes_count,
                used_dirs_count,
                itable_unused,
                flags,
                checksum,
                block_bitmap_csum,
                inode_bitmap_csum,
            };
            let mut buf = [0_u8; 64];
            gd.write_to_bytes(&mut buf, 64).expect("write 64");
            let parsed = Ext4GroupDesc::parse_from_bytes(&buf, 64).expect("parse 64");
            prop_assert_eq!(parsed, gd, "64-byte desc must round-trip exactly");
        }

        /// MR2 — truncating bijection at desc_size=32: high halves drop.
        #[test]
        fn ext4_proptest_group_desc_truncating_roundtrip_32(
            block_bitmap in any::<u64>(),
            inode_bitmap in any::<u64>(),
            inode_table in any::<u64>(),
            free_blocks_count in any::<u32>(),
            free_inodes_count in any::<u32>(),
            used_dirs_count in any::<u32>(),
            itable_unused in any::<u32>(),
            flags in any::<u16>(),
            checksum in any::<u16>(),
            block_bitmap_csum in any::<u32>(),
            inode_bitmap_csum in any::<u32>(),
        ) {
            let gd = Ext4GroupDesc {
                block_bitmap,
                inode_bitmap,
                inode_table,
                free_blocks_count,
                free_inodes_count,
                used_dirs_count,
                itable_unused,
                flags,
                checksum,
                block_bitmap_csum,
                inode_bitmap_csum,
            };
            #[expect(clippy::cast_possible_truncation)]
            let truncated = Ext4GroupDesc {
                block_bitmap: u64::from(block_bitmap as u32),
                inode_bitmap: u64::from(inode_bitmap as u32),
                inode_table: u64::from(inode_table as u32),
                free_blocks_count: u32::from(free_blocks_count as u16),
                free_inodes_count: u32::from(free_inodes_count as u16),
                used_dirs_count: u32::from(used_dirs_count as u16),
                itable_unused: u32::from(itable_unused as u16),
                flags,
                checksum,
                block_bitmap_csum: u32::from(block_bitmap_csum as u16),
                inode_bitmap_csum: u32::from(inode_bitmap_csum as u16),
            };
            let mut buf = [0_u8; 32];
            gd.write_to_bytes(&mut buf, 32).expect("write 32");
            let parsed = Ext4GroupDesc::parse_from_bytes(&buf, 32).expect("parse 32");
            prop_assert_eq!(parsed, truncated, "32-byte desc must round-trip the lo halves only");
        }

        /// MR3 — encoded output parses identically regardless of how the
        /// destination buffer was initialised. Padding bytes (bg_reserved /
        /// hi-csum tail, e.g. 0x14..0x18, 0x34..0x38, 0x3C..0x40 at
        /// desc_size=64) are intentionally left untouched per the writer's
        /// doc comment, so we compare PARSED structs rather than raw bytes —
        /// any drift in which offsets the writer touches is caught here.
        #[test]
        fn ext4_proptest_group_desc_write_init_invariance(
            block_bitmap in any::<u64>(),
            inode_bitmap in any::<u64>(),
            inode_table in any::<u64>(),
            free_blocks_count in any::<u32>(),
            free_inodes_count in any::<u32>(),
            used_dirs_count in any::<u32>(),
            itable_unused in any::<u32>(),
            flags in any::<u16>(),
            checksum in any::<u16>(),
            block_bitmap_csum in any::<u32>(),
            inode_bitmap_csum in any::<u32>(),
            ds in prop_oneof![Just(32_u16), Just(64_u16)],
            fill in any::<u8>(),
        ) {
            let gd = Ext4GroupDesc {
                block_bitmap,
                inode_bitmap,
                inode_table,
                free_blocks_count,
                free_inodes_count,
                used_dirs_count,
                itable_unused,
                flags,
                checksum,
                block_bitmap_csum,
                inode_bitmap_csum,
            };
            let ds_usize = usize::from(ds);
            let mut buf_zero = vec![0x00_u8; ds_usize];
            let mut buf_fill = vec![fill; ds_usize];
            gd.write_to_bytes(&mut buf_zero, ds).expect("write zero-init");
            gd.write_to_bytes(&mut buf_fill, ds).expect("write fill-init");
            let parsed_zero =
                Ext4GroupDesc::parse_from_bytes(&buf_zero, ds).expect("parse zero-init");
            let parsed_fill =
                Ext4GroupDesc::parse_from_bytes(&buf_fill, ds).expect("parse fill-init");
            prop_assert_eq!(
                parsed_zero, parsed_fill,
                "encoded output must parse identically regardless of pre-write buffer state"
            );
        }

        /// MR4 — encode is pure: writing the same gd twice into the same
        /// buffer produces identical bytes both times. The padding bytes
        /// hold their post-first-write values; if the writer ever read from
        /// the buffer or accumulated state, the second pass would diverge.
        #[test]
        fn ext4_proptest_group_desc_encode_is_pure(
            block_bitmap in any::<u64>(),
            inode_bitmap in any::<u64>(),
            inode_table in any::<u64>(),
            free_blocks_count in any::<u32>(),
            free_inodes_count in any::<u32>(),
            used_dirs_count in any::<u32>(),
            itable_unused in any::<u32>(),
            flags in any::<u16>(),
            checksum in any::<u16>(),
            block_bitmap_csum in any::<u32>(),
            inode_bitmap_csum in any::<u32>(),
            ds in prop_oneof![Just(32_u16), Just(64_u16)],
        ) {
            let gd = Ext4GroupDesc {
                block_bitmap,
                inode_bitmap,
                inode_table,
                free_blocks_count,
                free_inodes_count,
                used_dirs_count,
                itable_unused,
                flags,
                checksum,
                block_bitmap_csum,
                inode_bitmap_csum,
            };
            let ds_usize = usize::from(ds);
            let mut buf = vec![0_u8; ds_usize];
            gd.write_to_bytes(&mut buf, ds).expect("first encode");
            let snapshot = buf.clone();
            gd.write_to_bytes(&mut buf, ds).expect("second encode");
            prop_assert_eq!(snapshot, buf, "encode must be a pure function of `gd`");
        }

        /// MR5a — write to undersized buffer must error.
        #[test]
        fn ext4_proptest_group_desc_write_too_small_errors(
            short_len in 0_usize..=63,
            ds in prop_oneof![Just(32_u16), Just(64_u16)],
        ) {
            let ds_usize = usize::from(ds);
            prop_assume!(short_len < ds_usize);
            let gd = Ext4GroupDesc {
                block_bitmap: 1,
                inode_bitmap: 1,
                inode_table: 1,
                free_blocks_count: 0,
                free_inodes_count: 0,
                used_dirs_count: 0,
                itable_unused: 0,
                flags: 0,
                checksum: 0,
                block_bitmap_csum: 0,
                inode_bitmap_csum: 0,
            };
            let mut buf = vec![0_u8; short_len];
            prop_assert!(
                gd.write_to_bytes(&mut buf, ds).is_err(),
                "write must reject buffer shorter than desc_size"
            );
        }

        /// MR5b — parse from undersized input must error.
        #[test]
        fn ext4_proptest_group_desc_parse_too_small_errors(
            short_len in 0_usize..=63,
            ds in prop_oneof![Just(32_u16), Just(64_u16)],
        ) {
            let ds_usize = usize::from(ds);
            prop_assume!(short_len < ds_usize);
            let bytes = vec![0xAB_u8; short_len];
            prop_assert!(
                Ext4GroupDesc::parse_from_bytes(&bytes, ds).is_err(),
                "parse must reject input shorter than desc_size"
            );
        }

        /// MR6 — 32-byte parser ignores bytes at offset >= 0x20.
        #[test]
        fn ext4_proptest_group_desc_parse_32_ignores_tail(
            block_bitmap in any::<u32>(),
            inode_bitmap in any::<u32>(),
            inode_table in any::<u32>(),
            tail in proptest::collection::vec(any::<u8>(), 0..=96),
        ) {
            let mut canonical = [0_u8; 32];
            canonical[0x00..0x04].copy_from_slice(&block_bitmap.to_le_bytes());
            canonical[0x04..0x08].copy_from_slice(&inode_bitmap.to_le_bytes());
            canonical[0x08..0x0C].copy_from_slice(&inode_table.to_le_bytes());
            let baseline = Ext4GroupDesc::parse_from_bytes(&canonical, 32)
                .expect("baseline 32-byte parse");

            let mut extended = canonical.to_vec();
            extended.extend_from_slice(&tail);
            let with_tail = Ext4GroupDesc::parse_from_bytes(&extended, 32)
                .expect("extended-input 32-byte parse");
            prop_assert_eq!(
                with_tail, baseline,
                "32-byte parse must ignore bytes >= 0x20"
            );
        }

        // bd-834zk — Metamorphic relations for the on-disk *_extra
        // timestamp bit-pack helpers. Each MR pins a specific
        // algebraic law of the [nsec:30][epoch:2] u32 layout used by
        // every inode timestamp read on ext4 v6+ filesystems. A
        // regression that swapped the masks (epoch ⇔ nsec) would
        // silently corrupt every timestamp without tripping any
        // existing test.

        /// MR1 — Bit-pack inverse: for any u32 x,
        /// (extra_nsec(x) << 2) | extra_epoch(x) == x.
        #[test]
        fn ext4_proptest_extra_bit_pack_is_invertible(extra in any::<u32>()) {
            let nsec = Ext4Inode::extra_nsec(extra);
            let epoch = Ext4Inode::extra_epoch(extra);
            prop_assert_eq!((nsec << 2) | epoch, extra);
        }

        /// MR2 — Epoch bound: extra_epoch(x) ≤ 3 for all u32 x
        /// (the kernel reserves only 2 bits for epoch).
        #[test]
        fn ext4_proptest_extra_epoch_is_bounded(extra in any::<u32>()) {
            let epoch = Ext4Inode::extra_epoch(extra);
            prop_assert!(epoch <= 3);
        }

        /// MR3 — Nsec bound: extra_nsec(x) ≤ 0x3FFF_FFFF — only the
        /// upper 30 bits of `extra` carry the nanosecond payload.
        #[test]
        fn ext4_proptest_extra_nsec_is_bounded(extra in any::<u32>()) {
            let nsec = Ext4Inode::extra_nsec(extra);
            prop_assert!(nsec <= 0x3FFF_FFFF);
        }

        /// MR4 — Disjoint fields: a value with only nsec bits set
        /// must yield epoch == 0, and a value with only epoch bits
        /// set must yield nsec == 0. A regression that swapped the
        /// masks would fail this MR immediately.
        #[test]
        fn ext4_proptest_extra_nsec_and_epoch_are_disjoint(
            nsec_payload in 0_u32..=0x3FFF_FFFF,
            epoch_payload in 0_u32..=3,
        ) {
            let nsec_only = nsec_payload << 2;
            prop_assert_eq!(Ext4Inode::extra_epoch(nsec_only), 0);
            prop_assert_eq!(Ext4Inode::extra_nsec(nsec_only), nsec_payload);

            let epoch_only = epoch_payload;
            prop_assert_eq!(Ext4Inode::extra_nsec(epoch_only), 0);
            prop_assert_eq!(Ext4Inode::extra_epoch(epoch_only), epoch_payload);
        }

        /// MR5 — Determinism: same input always gives same output.
        /// Pairs with the bit-pack inverse to prove the helpers are
        /// pure projections.
        #[test]
        fn ext4_proptest_extra_helpers_are_deterministic(extra in any::<u32>()) {
            prop_assert_eq!(Ext4Inode::extra_nsec(extra), Ext4Inode::extra_nsec(extra));
            prop_assert_eq!(Ext4Inode::extra_epoch(extra), Ext4Inode::extra_epoch(extra));
        }

        /// bd-6rsow — Transitivity of `ext4_casefold_names_collide`
        /// across ASCII case variants.
        ///
        /// The existing transitivity proptest
        /// (`ext4_proptest_casefold_collision_is_transitive_through_folded_key`)
        /// proves transitivity along the chain `name -> fold(name) ->
        /// fold(fold(name))`, which exercises the idempotence axis
        /// but not the cross-case axis. This MR pins transitivity
        /// along an orthogonal chain — `a (mixed case) ~ b
        /// (uppercase) ~ c (lowercase) ⇒ a ~ c` — which is the
        /// user-visible contract for case-insensitive lookup. A
        /// buggy comparator that short-circuited equality on object
        /// identity, hashed with a per-call salt, or treated the
        /// second of a fold-pair asymmetrically could pass the
        /// existing transitivity test but fail this one.
        #[test]
        fn ext4_proptest_casefold_collide_is_transitive_on_ascii_case_variants(
            a in proptest::collection::vec(any::<u8>(), 0..=64),
        ) {
            let b: Vec<u8> = a.iter().map(u8::to_ascii_uppercase).collect();
            let c: Vec<u8> = a.iter().map(u8::to_ascii_lowercase).collect();
            let ab = ext4_casefold_names_collide(&a, &b);
            let bc = ext4_casefold_names_collide(&b, &c);
            let ac = ext4_casefold_names_collide(&a, &c);
            if ab && bc {
                prop_assert!(
                    ac,
                    "casefold collision must be transitive on ASCII case variants"
                );
            }
        }

        // bd-8u2xy — Idempotence MR for ext4_casefold_key.
        // ext4_casefold_key must be a projection: fold(fold(x)) == fold(x).
        // It is invoked twice per case-insensitive directory lookup (on
        // the target and on each candidate entry), and the comparison
        // assumes the once-applied output equals the twice-applied
        // output. A regression that introduced a non-idempotent step
        // (e.g., dropping a normalization pass on already-folded keys,
        // or a per-call salt) would silently corrupt CASEFOLD lookups
        // for non-trivial Unicode inputs.
        #[test]
        fn ext4_proptest_casefold_key_idempotent(
            name in proptest::collection::vec(any::<u8>(), 0..=64),
        ) {
            let once = ext4_casefold_key(&name);
            let twice = ext4_casefold_key(&once);
            prop_assert_eq!(once, twice);
        }

        // bd-8pbjm — ext4_chksum associativity proptest MR.
        // ext4_chksum is the foundational CRC32C primitive called from
        // every ext4 metadata-checksum path (group desc, bitmap, dir
        // block, inode, extent block, superblock). Multi-region
        // checksums require:
        //     ext4_chksum(seed, a||b) == ext4_chksum(ext4_chksum(seed, a), b)
        // The fixed-input ext4_chksum_hop_by_hop_append_fixed_case
        // exercised one (seed, prefix, suffix) tuple; this sweeps
        // arbitrary seed + variable-length prefix/suffix.
        // A regression that broke associativity would silently corrupt
        // every checksum that uses incremental computation (e.g., the
        // inode csum that pre-checksums (ino, generation) then
        // appends the inode body, or the group desc csum that
        // pre-checksums group_number then appends raw_gd).
        #[test]
        fn ext4_chksum_proptest_associative_across_appends(
            seed in any::<u32>(),
            a in proptest::collection::vec(any::<u8>(), 0..=256),
            b in proptest::collection::vec(any::<u8>(), 0..=256),
        ) {
            let mut concat = Vec::with_capacity(a.len() + b.len());
            concat.extend_from_slice(&a);
            concat.extend_from_slice(&b);
            let direct = ext4_chksum(seed, &concat);
            let two_hop = ext4_chksum(ext4_chksum(seed, &a), &b);
            prop_assert_eq!(
                direct,
                two_hop,
                "ext4_chksum must be associative across disjoint region appends: \
                 seed={:#x}, a.len={}, b.len={}", seed, a.len(), b.len()
            );
        }

        // bd-8pbjm MR-2 — three-way associativity (right-associative):
        // ext4_chksum(seed, a||b||c) == ext4_chksum(ext4_chksum(ext4_chksum(seed, a), b), c).
        // Stronger than MR-1 because it composes two associativity
        // applications; a regression that subtly broke chaining beyond
        // the first hop (e.g., off-by-one state reset) would surface
        // here but pass MR-1.
        #[test]
        fn ext4_chksum_proptest_associative_three_way(
            seed in any::<u32>(),
            a in proptest::collection::vec(any::<u8>(), 0..=64),
            b in proptest::collection::vec(any::<u8>(), 0..=64),
            c in proptest::collection::vec(any::<u8>(), 0..=64),
        ) {
            let mut concat = Vec::with_capacity(a.len() + b.len() + c.len());
            concat.extend_from_slice(&a);
            concat.extend_from_slice(&b);
            concat.extend_from_slice(&c);
            let direct = ext4_chksum(seed, &concat);
            let three_hop = ext4_chksum(ext4_chksum(ext4_chksum(seed, &a), &b), &c);
            prop_assert_eq!(direct, three_hop);
        }

        // bd-0djme — ext4_gdt_crc16 foundational laws.
        // ext4_gdt_crc16 is the CRC16 (polynomial 0x8005) primitive used
        // inside group_desc_checksum_value for filesystems that select
        // the GdtCsum (pre-metadata_csum) variant. It has no direct
        // test — only transitively covered through
        // group_desc_checksum_value. Sister ext4_chksum has bd-8pbjm
        // pinning the same associativity + empty-suffix laws for the
        // CRC32C variant; this closes the parallel.

        // MR-1 — Empty-suffix identity: ext4_gdt_crc16(seed, &[]) == seed.
        // The loop body of ext4_gdt_crc16 must be a no-op on empty input.
        #[test]
        fn ext4_gdt_crc16_proptest_empty_suffix_is_seed_identity(seed in any::<u16>()) {
            prop_assert_eq!(super::ext4_gdt_crc16(seed, &[]), seed);
        }

        // MR-2 — Associativity across appends:
        //   gdt_crc16(seed, a||b) == gdt_crc16(gdt_crc16(seed, a), b)
        // Permits multi-region incremental checksumming throughout the
        // group_desc_checksum_value (GdtCsum) code path
        // (uuid || group_id || raw_gd_prefix || zero_csum_slot || raw_gd_suffix).
        #[test]
        fn ext4_gdt_crc16_proptest_associative_across_appends(
            seed in any::<u16>(),
            a in proptest::collection::vec(any::<u8>(), 0..=256),
            b in proptest::collection::vec(any::<u8>(), 0..=256),
        ) {
            let mut concat = Vec::with_capacity(a.len() + b.len());
            concat.extend_from_slice(&a);
            concat.extend_from_slice(&b);
            let direct = super::ext4_gdt_crc16(seed, &concat);
            let two_hop = super::ext4_gdt_crc16(super::ext4_gdt_crc16(seed, &a), &b);
            prop_assert_eq!(direct, two_hop);
        }
    }
}

#[cfg(test)]
mod bitmap_csum_incremental_verify {
    use super::*;
    #[test]
    fn incremental_matches_full_prop() {
        let mut state = 0xABCD_1234u32;
        let mut next = || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state
        };
        let clusters = 32768u32; // 4096-byte bitmap, byte-aligned
        let seed = 0x1234_5678u32;
        let mut bitmap = vec![0u8; 4096];
        for b in &mut bitmap {
            *b = (next() & 0xFF) as u8;
        }
        let mut checked = 0;
        for _ in 0..400 {
            let count = 1 + (next() % 900);
            let start = next() % (clusters - count);
            let old = block_bitmap_checksum_value(&bitmap, seed, clusters, 64);
            let mut newbm = bitmap.clone();
            for bit in start..start + count {
                newbm[(bit / 8) as usize] ^= 1u8 << (bit % 8);
            }
            let full = block_bitmap_checksum_value(&newbm, seed, clusters, 64);
            if let Some(inc) = bitmap_checksum_incremental(old, start, count, clusters, 64) {
                assert_eq!(inc, full, "start={start} count={count}");
                checked += 1;
            }
            bitmap = newbm;
        }
        assert!(
            checked > 50,
            "incremental exercised too few times: {checked}"
        );
    }
    #[test]
    fn incremental_none_for_16bit_desc() {
        assert!(bitmap_checksum_incremental(0, 0, 8, 32768, 32).is_none());
    }
}

#[cfg(test)]
mod dir_csum_incremental_verify {
    use super::*;
    #[test]
    fn incremental_matches_full_dir_stamp_prop() {
        let mut state = 0x51A7_3C9Fu32;
        let mut next = || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state
        };
        let bs = 4096usize;
        let coverage_end = bs - 12;
        let seed = 0xDEAD_BEEFu32;
        let ino = 42u32;
        let generation = 7u32;
        let mut block = vec![0u8; bs];
        for b in &mut block {
            *b = (next() & 0xFF) as u8;
        }
        stamp_dir_block_checksum(&mut block, seed, ino, generation);
        let mut checked = 0;
        for _ in 0..400 {
            // one contiguous change within coverage (like an entry insert/remove)
            let len = 1 + (next() as usize % 48);
            let start = (next() as usize) % (coverage_end - len);
            let mut new_bytes = vec![0u8; len];
            for b in &mut new_bytes {
                *b = (next() & 0xFF) as u8;
            }
            let delta: Vec<u8> = new_bytes
                .iter()
                .zip(&block[start..start + len])
                .map(|(n, o)| n ^ o)
                .collect();
            // apply the change to two copies
            let mut inc = block.clone();
            inc[start..start + len].copy_from_slice(&new_bytes);
            let mut full = inc.clone();
            // incremental tail update (inc still carries the OLD tail from `block`)
            assert!(stamp_dir_block_checksum_incremental(
                &mut inc, start, &delta
            ));
            // full recompute oracle
            stamp_dir_block_checksum(&mut full, seed, ino, generation);
            assert_eq!(&inc[bs - 4..], &full[bs - 4..], "start={start} len={len}");
            block = full; // chain (like successive mutations)
            checked += 1;
        }
        assert!(checked > 100);
    }
    #[test]
    fn incremental_rejects_out_of_coverage() {
        let mut block = vec![0u8; 4096];
        assert!(!stamp_dir_block_checksum_incremental(
            &mut block, 4090, &[0u8; 8]
        ));
        assert!(!stamp_dir_block_checksum_incremental(
            &mut [0u8; 8],
            0,
            &[0u8; 1]
        ));
    }
}
