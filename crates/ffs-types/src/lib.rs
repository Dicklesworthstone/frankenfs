#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

pub const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
pub const EXT4_SUPERBLOCK_SIZE: usize = 1024;
pub const EXT4_SUPER_MAGIC: u16 = 0xEF53;

pub const BTRFS_SUPER_INFO_OFFSET: usize = 64 * 1024;
pub const BTRFS_SUPER_INFO_SIZE: usize = 4096;
pub const BTRFS_MAGIC: u64 = 0x4D5F_5366_5248_425F;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockNumber(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InodeNumber(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TxnId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CommitSeq(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub high: CommitSeq,
}

/// Validated block size (must be a power of two in 1024..=65536).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockSize(u32);

impl BlockSize {
    /// Create a `BlockSize` if `value` is a power of two in [1024, 65536].
    pub fn new(value: u32) -> Result<Self, ParseError> {
        if !value.is_power_of_two() || !(1024..=65536).contains(&value) {
            return Err(ParseError::InvalidField {
                field: "block_size",
                reason: "must be power of two in 1024..=65536",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }

    /// Number of bits to shift to convert between bytes and blocks.
    #[must_use]
    pub fn shift(self) -> u32 {
        self.0.trailing_zeros()
    }

    /// Convert a byte offset to a block number (truncating).
    #[must_use]
    pub fn byte_to_block(self, byte_offset: u64) -> BlockNumber {
        BlockNumber(byte_offset >> u64::from(self.shift()))
    }

    /// Convert a block number to a byte offset.
    #[must_use]
    pub fn block_to_byte(self, block: BlockNumber) -> Option<u64> {
        block.0.checked_mul(u64::from(self.0))
    }
}

/// Block group index (ext4: u32 group number).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GroupNumber(pub u32);

/// Byte offset on a `ByteDevice` (pread/pwrite semantics).
///
/// This is a unit-carrying wrapper to prevent mixing bytes and blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ByteOffset(pub u64);

impl ByteOffset {
    pub const ZERO: Self = Self(0);

    /// Add a byte count, returning `None` on overflow.
    #[must_use]
    pub fn checked_add(self, bytes: u64) -> Option<Self> {
        self.0.checked_add(bytes).map(Self)
    }

    /// Subtract a byte count, returning `None` on underflow.
    #[must_use]
    pub fn checked_sub(self, bytes: u64) -> Option<Self> {
        self.0.checked_sub(bytes).map(Self)
    }

    /// Multiply by a scalar, returning `None` on overflow.
    #[must_use]
    pub fn checked_mul(self, factor: u64) -> Option<Self> {
        self.0.checked_mul(factor).map(Self)
    }
}

/// Stable device identifier (future-proofing for multi-device support).
///
/// For now, this is typically derived from the on-disk UUID fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub u128);

impl DeviceId {
    #[must_use]
    pub fn from_uuid_bytes_be(bytes: [u8; 16]) -> Self {
        Self(u128::from_be_bytes(bytes))
    }

    #[must_use]
    pub fn to_uuid_bytes_be(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }
}

/// Inode or filesystem generation counter (ext4: u32, btrfs: u64).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Generation(pub u64);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParseError {
    #[error("insufficient data: need {needed} bytes at offset {offset}, got {actual}")]
    InsufficientData {
        needed: usize,
        offset: usize,
        actual: usize,
    },
    #[error("invalid magic: expected {expected:#x}, got {actual:#x}")]
    InvalidMagic { expected: u64, actual: u64 },
    #[error("invalid field: {field} ({reason})")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("integer conversion failed: {field}")]
    IntegerConversion { field: &'static str },
}

#[inline]
pub fn ensure_slice(data: &[u8], offset: usize, len: usize) -> Result<&[u8], ParseError> {
    let Some(end) = offset.checked_add(len) else {
        return Err(ParseError::InvalidField {
            field: "offset",
            reason: "overflow",
        });
    };

    if end > data.len() {
        return Err(ParseError::InsufficientData {
            needed: len,
            offset,
            actual: data.len().saturating_sub(offset),
        });
    }

    Ok(&data[offset..end])
}

#[inline]
pub fn read_le_u16(data: &[u8], offset: usize) -> Result<u16, ParseError> {
    let bytes = ensure_slice(data, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

#[inline]
pub fn read_le_u32(data: &[u8], offset: usize) -> Result<u32, ParseError> {
    let bytes = ensure_slice(data, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[inline]
pub fn read_le_u64(data: &[u8], offset: usize) -> Result<u64, ParseError> {
    let bytes = ensure_slice(data, offset, 8)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[inline]
pub fn read_fixed<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], ParseError> {
    let bytes = ensure_slice(data, offset, N)?;
    let mut out = [0_u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[must_use]
pub fn trim_nul_padded(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_owned()
}

#[must_use]
pub fn is_power_of_two_u32(value: u32) -> bool {
    value.is_power_of_two()
}

#[must_use]
pub fn ext4_block_size_from_log(log_block_size: u32) -> Option<u32> {
    let shift = 10_u32.checked_add(log_block_size)?;
    1_u32.checked_shl(shift)
}

impl fmt::Display for BlockNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for InodeNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for BlockSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for GroupNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for ByteOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

impl fmt::Display for Generation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl InodeNumber {
    pub const ROOT: Self = Self(2);
    pub const JOURNAL: Self = Self(8);

    /// Narrow to an ext4 inode number (u32).
    ///
    /// Returns `ParseError::IntegerConversion` if the value exceeds `u32::MAX`,
    /// which would indicate a btrfs objectid was mistakenly treated as ext4.
    pub fn to_ext4(self) -> Result<Ext4InodeNumber, ParseError> {
        u32::try_from(self.0)
            .map(Ext4InodeNumber)
            .map_err(|_| ParseError::IntegerConversion {
                field: "inode_number",
            })
    }

    /// Convert to a btrfs object ID (infallible — same width).
    #[must_use]
    pub fn to_btrfs(self) -> BtrfsObjectId {
        BtrfsObjectId(self.0)
    }
}

// ── Format-specific inode/objectid types ────────────────────────────────────
//
// These types are used at parsing boundaries to prevent mixing ext4 inode
// numbers (u32) with btrfs object IDs (u64). The canonical `InodeNumber(u64)`
// is used throughout the codebase; these wrappers provide safe entry points.

/// ext4 inode number (u32, 1-indexed).
///
/// ext4 stores inode numbers as 32-bit values. This wrapper ensures that
/// parsing code uses the correct width and that conversion to the canonical
/// `InodeNumber(u64)` is explicit and lossless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Ext4InodeNumber(pub u32);

impl Ext4InodeNumber {
    pub const ROOT: Self = Self(2);
    pub const JOURNAL: Self = Self(8);

    /// Promote to the canonical `InodeNumber(u64)` (infallible, lossless).
    #[must_use]
    pub fn to_canonical(self) -> InodeNumber {
        InodeNumber(u64::from(self.0))
    }
}

impl From<Ext4InodeNumber> for InodeNumber {
    fn from(ext4: Ext4InodeNumber) -> Self {
        ext4.to_canonical()
    }
}

impl fmt::Display for Ext4InodeNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// btrfs object ID (u64).
///
/// btrfs uses 64-bit object IDs as B-tree keys. This wrapper distinguishes
/// btrfs-specific IDs from the canonical `InodeNumber` at parsing boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BtrfsObjectId(pub u64);

impl BtrfsObjectId {
    /// Promote to the canonical `InodeNumber(u64)` (infallible, same width).
    #[must_use]
    pub fn to_canonical(self) -> InodeNumber {
        InodeNumber(self.0)
    }
}

impl From<BtrfsObjectId> for InodeNumber {
    fn from(btrfs: BtrfsObjectId) -> Self {
        btrfs.to_canonical()
    }
}

impl fmt::Display for BtrfsObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── POSIX file mode constants ────────────────────────────────────────────────

/// File type mask (upper 4 bits of mode).
pub const S_IFMT: u16 = 0o170000;
/// Named pipe (FIFO).
pub const S_IFIFO: u16 = 0o010000;
/// Character device.
pub const S_IFCHR: u16 = 0o020000;
/// Directory.
pub const S_IFDIR: u16 = 0o040000;
/// Block device.
pub const S_IFBLK: u16 = 0o060000;
/// Regular file.
pub const S_IFREG: u16 = 0o100000;
/// Symbolic link.
pub const S_IFLNK: u16 = 0o120000;
/// Socket.
pub const S_IFSOCK: u16 = 0o140000;

// ── ext4 inode flags (i_flags) ──────────────────────────────────────────────

/// Secure deletion (not actually implemented in ext4).
pub const EXT4_SECRM_FL: u32 = 0x0000_0001;
/// Undelete (not implemented).
pub const EXT4_UNRM_FL: u32 = 0x0000_0002;
/// Compressed file.
pub const EXT4_COMPR_FL: u32 = 0x0000_0004;
/// Synchronous updates.
pub const EXT4_SYNC_FL: u32 = 0x0000_0008;
/// Immutable file.
pub const EXT4_IMMUTABLE_FL: u32 = 0x0000_0010;
/// Append-only file.
pub const EXT4_APPEND_FL: u32 = 0x0000_0020;
/// Do not dump/undelete.
pub const EXT4_NODUMP_FL: u32 = 0x0000_0040;
/// Do not update access time.
pub const EXT4_NOATIME_FL: u32 = 0x0000_0080;
/// Hash-indexed directory (htree/DX).
pub const EXT4_INDEX_FL: u32 = 0x0000_1000;
/// AFS directory.
pub const EXT4_IMAGIC_FL: u32 = 0x0000_2000;
/// File data should be journaled.
pub const EXT4_JOURNAL_DATA_FL: u32 = 0x0000_4000;
/// File tail should not be merged.
pub const EXT4_NOTAIL_FL: u32 = 0x0000_8000;
/// Dirsync behaviour (directories only).
pub const EXT4_DIRSYNC_FL: u32 = 0x0001_0000;
/// Top of directory hierarchies.
pub const EXT4_TOPDIR_FL: u32 = 0x0002_0000;
/// Set to each huge file.
pub const EXT4_HUGE_FILE_FL: u32 = 0x0004_0000;
/// Inode uses extents.
pub const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
/// Inode used for large EA.
pub const EXT4_EA_INODE_FL: u32 = 0x0020_0000;
/// Blocks allocated beyond EOF (pre-allocation).
pub const EXT4_EOFBLOCKS_FL: u32 = 0x0040_0000;
/// Inode is a snapshot.
pub const EXT4_SNAPFILE_FL: u32 = 0x0100_0000;
/// Snapshot is being deleted.
pub const EXT4_SNAPFILE_DELETED_FL: u32 = 0x0400_0000;
/// Snapshot shrink has completed.
pub const EXT4_SNAPFILE_SHRUNK_FL: u32 = 0x0800_0000;
/// Inode has inline data.
pub const EXT4_INLINE_DATA_FL: u32 = 0x1000_0000;
/// Create with parents projid.
pub const EXT4_PROJINHERIT_FL: u32 = 0x2000_0000;
/// Casefolded directory.
pub const EXT4_CASEFOLD_FL: u32 = 0x4000_0000;

/// Maximum ext4 fast symlink target size (stored in the inode's i_block area).
pub const EXT4_FAST_SYMLINK_MAX: usize = 60;

// ── ext4 xattr name indices ─────────────────────────────────────────────────

/// User extended attributes (user.*)
pub const EXT4_XATTR_INDEX_USER: u8 = 1;
/// POSIX ACL access.
pub const EXT4_XATTR_INDEX_POSIX_ACL_ACCESS: u8 = 2;
/// POSIX ACL default.
pub const EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT: u8 = 3;
/// Trusted extended attributes (trusted.*)
pub const EXT4_XATTR_INDEX_TRUSTED: u8 = 4;
/// Lustre (reserved).
pub const EXT4_XATTR_INDEX_LUSTRE: u8 = 5;
/// Security extended attributes (security.*)
pub const EXT4_XATTR_INDEX_SECURITY: u8 = 6;
/// System extended attributes (system.*)
pub const EXT4_XATTR_INDEX_SYSTEM: u8 = 7;
/// System richacl.
pub const EXT4_XATTR_INDEX_RICHACL: u8 = 8;
/// Encryption.
pub const EXT4_XATTR_INDEX_ENCRYPTION: u8 = 9;
/// Hurd.
pub const EXT4_XATTR_INDEX_HURD: u8 = 10;

/// Magic number for ext4 xattr blocks.
pub const EXT4_XATTR_MAGIC: u32 = 0xEA02_0000;

// ── Checked arithmetic helpers ──────────────────────────────────────────────

impl BlockNumber {
    /// Add a block count, returning `None` on overflow.
    #[must_use]
    pub fn checked_add(self, count: u64) -> Option<Self> {
        self.0.checked_add(count).map(Self)
    }

    /// Subtract a block count, returning `None` on underflow.
    #[must_use]
    pub fn checked_sub(self, count: u64) -> Option<Self> {
        self.0.checked_sub(count).map(Self)
    }

    /// Convert this block number to its byte offset using the given block size.
    ///
    /// Returns `None` on overflow.
    #[must_use]
    pub fn to_byte_offset(self, block_size: BlockSize) -> Option<ByteOffset> {
        checked_mul_block(self, block_size)
    }

    /// Narrow to `u32`, returning `ParseError::IntegerConversion` on overflow.
    pub fn to_u32(self) -> Result<u32, ParseError> {
        u32::try_from(self.0).map_err(|_| ParseError::IntegerConversion {
            field: "block_number",
        })
    }
}

impl ByteOffset {
    /// Round down to the nearest multiple of `alignment` (must be a non-zero power of two).
    ///
    /// Returns `None` if `alignment` is zero or not a power of two.
    #[must_use]
    pub fn align_down(self, alignment: u64) -> Option<Self> {
        align_down(self.0, alignment).map(Self)
    }

    /// Round up to the nearest multiple of `alignment` (must be a non-zero power of two).
    ///
    /// Returns `None` on overflow or if `alignment` is invalid.
    #[must_use]
    pub fn align_up(self, alignment: u64) -> Option<Self> {
        align_up(self.0, alignment).map(Self)
    }

    /// Narrow to `usize`, returning `ParseError::IntegerConversion` on overflow.
    pub fn to_usize(self) -> Result<usize, ParseError> {
        usize::try_from(self.0).map_err(|_| ParseError::IntegerConversion {
            field: "byte_offset",
        })
    }
}

// ── Free-standing checked arithmetic functions ──────────────────────────────

/// Add a byte length to a byte offset, returning the end position.
///
/// Returns `None` on overflow. Equivalent to `offset.checked_add(len)` but
/// named for clarity at call sites that compute "offset + length = end".
#[must_use]
pub fn checked_add_bytes(offset: ByteOffset, len: u64) -> Option<ByteOffset> {
    offset.checked_add(len)
}

/// Compute the byte offset of a block number given a block size.
///
/// Returns `None` on overflow.
#[must_use]
pub fn checked_mul_block(block: BlockNumber, block_size: BlockSize) -> Option<ByteOffset> {
    block
        .0
        .checked_mul(u64::from(block_size.get()))
        .map(ByteOffset)
}

/// Round `value` down to the nearest multiple of `alignment`.
///
/// `alignment` must be a non-zero power of two; returns `None` otherwise.
#[must_use]
pub fn align_down(value: u64, alignment: u64) -> Option<u64> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return None;
    }
    Some(value & !(alignment - 1))
}

/// Round `value` up to the nearest multiple of `alignment`.
///
/// `alignment` must be a non-zero power of two; returns `None` on overflow
/// or if `alignment` is invalid.
#[must_use]
pub fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return None;
    }
    let mask = alignment - 1;
    value.checked_add(mask).map(|v| v & !mask)
}

/// Narrow a `u64` to `usize` with an explicit error path.
///
/// On 64-bit platforms this is infallible; on 32-bit it can fail.
/// The `field` label is included in the error for diagnostics.
pub fn u64_to_usize(value: u64, field: &'static str) -> Result<usize, ParseError> {
    usize::try_from(value).map_err(|_| ParseError::IntegerConversion { field })
}

/// Narrow a `u64` to `u32` with an explicit error path.
pub fn u64_to_u32(value: u64, field: &'static str) -> Result<u32, ParseError> {
    u32::try_from(value).map_err(|_| ParseError::IntegerConversion { field })
}

/// Compute the block group that contains a given block.
///
/// `first_data_block` is typically 0 for 4K blocks and 1 for 1K blocks.
#[must_use]
#[allow(clippy::cast_possible_truncation)] // ext4 group count is u32
pub fn block_to_group(
    block: BlockNumber,
    blocks_per_group: u32,
    first_data_block: u32,
) -> GroupNumber {
    let adjusted = block.0.saturating_sub(u64::from(first_data_block));
    GroupNumber((adjusted / u64::from(blocks_per_group)) as u32)
}

/// Compute the first block of a given block group.
pub fn group_first_block(
    group: GroupNumber,
    blocks_per_group: u32,
    first_data_block: u32,
) -> Option<BlockNumber> {
    let offset = u64::from(group.0).checked_mul(u64::from(blocks_per_group))?;
    offset
        .checked_add(u64::from(first_data_block))
        .map(BlockNumber)
}

/// Compute the inode's block group from its inode number.
///
/// Inode numbers are 1-indexed; group assignment uses `(ino - 1) / inodes_per_group`.
#[must_use]
#[allow(clippy::cast_possible_truncation)] // ext4 group count is u32
pub fn inode_to_group(ino: InodeNumber, inodes_per_group: u32) -> GroupNumber {
    GroupNumber(((ino.0.saturating_sub(1)) / u64::from(inodes_per_group)) as u32)
}

/// Compute the index of an inode within its block group.
#[must_use]
#[allow(clippy::cast_possible_truncation)] // modulo by u32 always fits in u32
pub fn inode_index_in_group(ino: InodeNumber, inodes_per_group: u32) -> u32 {
    ((ino.0.saturating_sub(1)) % u64::from(inodes_per_group)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_helpers() {
        let bytes = [0x34_u8, 0x12, 0x78, 0x56, 0xEF, 0xCD, 0xAB, 0x90];
        assert_eq!(read_le_u16(&bytes, 0).expect("u16"), 0x1234);
        assert_eq!(read_le_u32(&bytes, 0).expect("u32"), 0x5678_1234);
        assert_eq!(read_le_u32(&bytes, 4).expect("u32"), 0x90AB_CDEF);
    }

    #[test]
    fn test_trim_nul_padded() {
        let raw = b"ffs\0\0\0\0";
        assert_eq!(trim_nul_padded(raw), "ffs");
    }

    #[test]
    fn test_ext4_block_size_from_log() {
        assert_eq!(ext4_block_size_from_log(0), Some(1024));
        assert_eq!(ext4_block_size_from_log(1), Some(2048));
        assert_eq!(ext4_block_size_from_log(2), Some(4096));
    }

    #[test]
    fn test_block_size_validation() {
        assert!(BlockSize::new(4096).is_ok());
        assert!(BlockSize::new(1024).is_ok());
        assert!(BlockSize::new(65536).is_ok());
        assert_eq!(BlockSize::new(4096).unwrap().get(), 4096);
        assert_eq!(BlockSize::new(4096).unwrap().shift(), 12);

        // Invalid: not power of two
        assert!(BlockSize::new(3000).is_err());
        // Invalid: too small
        assert!(BlockSize::new(512).is_err());
        // Invalid: too large
        assert!(BlockSize::new(131_072).is_err());
        // Invalid: zero
        assert!(BlockSize::new(0).is_err());
    }

    #[test]
    fn test_block_size_conversions() {
        let bs = BlockSize::new(4096).unwrap();
        assert_eq!(bs.byte_to_block(0), BlockNumber(0));
        assert_eq!(bs.byte_to_block(4096), BlockNumber(1));
        assert_eq!(bs.byte_to_block(8192), BlockNumber(2));
        assert_eq!(bs.byte_to_block(4095), BlockNumber(0)); // truncates

        assert_eq!(bs.block_to_byte(BlockNumber(0)), Some(0));
        assert_eq!(bs.block_to_byte(BlockNumber(1)), Some(4096));
        assert_eq!(bs.block_to_byte(BlockNumber(100)), Some(409_600));
    }

    #[test]
    fn test_inode_group_math() {
        // Standard: 8192 inodes per group
        assert_eq!(inode_to_group(InodeNumber(1), 8192), GroupNumber(0));
        assert_eq!(inode_to_group(InodeNumber(8192), 8192), GroupNumber(0));
        assert_eq!(inode_to_group(InodeNumber(8193), 8192), GroupNumber(1));

        assert_eq!(inode_index_in_group(InodeNumber(1), 8192), 0);
        assert_eq!(inode_index_in_group(InodeNumber(2), 8192), 1);
        assert_eq!(inode_index_in_group(InodeNumber(8193), 8192), 0);
    }

    #[test]
    fn test_block_group_math() {
        // 4K blocks, first_data_block = 0, 32768 blocks per group
        assert_eq!(block_to_group(BlockNumber(0), 32768, 0), GroupNumber(0));
        assert_eq!(block_to_group(BlockNumber(32767), 32768, 0), GroupNumber(0));
        assert_eq!(block_to_group(BlockNumber(32768), 32768, 0), GroupNumber(1));

        assert_eq!(
            group_first_block(GroupNumber(0), 32768, 0),
            Some(BlockNumber(0))
        );
        assert_eq!(
            group_first_block(GroupNumber(1), 32768, 0),
            Some(BlockNumber(32768))
        );

        // 1K blocks, first_data_block = 1, 8192 blocks per group
        assert_eq!(block_to_group(BlockNumber(1), 8192, 1), GroupNumber(0));
        assert_eq!(block_to_group(BlockNumber(8193), 8192, 1), GroupNumber(1));
        assert_eq!(
            group_first_block(GroupNumber(0), 8192, 1),
            Some(BlockNumber(1))
        );
        assert_eq!(
            group_first_block(GroupNumber(1), 8192, 1),
            Some(BlockNumber(8193))
        );
    }

    #[test]
    fn test_block_number_checked_ops() {
        assert_eq!(BlockNumber(10).checked_add(5), Some(BlockNumber(15)));
        assert_eq!(BlockNumber(u64::MAX).checked_add(1), None);
        assert_eq!(BlockNumber(10).checked_sub(3), Some(BlockNumber(7)));
        assert_eq!(BlockNumber(0).checked_sub(1), None);
    }

    #[test]
    fn test_byte_offset_checked_ops() {
        assert_eq!(ByteOffset(10).checked_add(5), Some(ByteOffset(15)));
        assert_eq!(ByteOffset(u64::MAX).checked_add(1), None);
        assert_eq!(ByteOffset(10).checked_sub(3), Some(ByteOffset(7)));
        assert_eq!(ByteOffset(0).checked_sub(1), None);
        assert_eq!(ByteOffset(3).checked_mul(7), Some(ByteOffset(21)));
        assert_eq!(ByteOffset(u64::MAX).checked_mul(2), None);
    }

    #[test]
    fn test_inode_constants() {
        assert_eq!(InodeNumber::ROOT, InodeNumber(2));
        assert_eq!(InodeNumber::JOURNAL, InodeNumber(8));
    }

    // ── bd-1ds: format-specific inode/objectid tests ────────────────────

    #[test]
    fn ext4_inode_number_round_trip() {
        let ext4 = Ext4InodeNumber(42);
        let canonical: InodeNumber = ext4.into();
        assert_eq!(canonical, InodeNumber(42));
        assert_eq!(canonical.to_ext4(), Ok(Ext4InodeNumber(42)));
    }

    #[test]
    fn ext4_inode_number_max_u32() {
        let ext4 = Ext4InodeNumber(u32::MAX);
        let canonical: InodeNumber = ext4.into();
        assert_eq!(canonical.0, u64::from(u32::MAX));
        assert_eq!(canonical.to_ext4(), Ok(Ext4InodeNumber(u32::MAX)));
    }

    #[test]
    fn ext4_inode_number_overflow() {
        // A btrfs-sized inode number cannot be narrowed to ext4
        let large = InodeNumber(u64::from(u32::MAX) + 1);
        assert!(large.to_ext4().is_err());
        assert_eq!(
            InodeNumber(u64::MAX).to_ext4().unwrap_err(),
            ParseError::IntegerConversion {
                field: "inode_number"
            }
        );
    }

    #[test]
    fn btrfs_object_id_round_trip() {
        let btrfs = BtrfsObjectId(0xDEAD_BEEF_CAFE_BABE);
        let canonical: InodeNumber = btrfs.into();
        assert_eq!(canonical.0, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(canonical.to_btrfs(), BtrfsObjectId(0xDEAD_BEEF_CAFE_BABE));
    }

    #[test]
    fn ext4_inode_constants_match_canonical() {
        assert_eq!(Ext4InodeNumber::ROOT.to_canonical(), InodeNumber::ROOT);
        assert_eq!(
            Ext4InodeNumber::JOURNAL.to_canonical(),
            InodeNumber::JOURNAL
        );
    }

    #[test]
    fn display_format_specific_types() {
        assert_eq!(Ext4InodeNumber(42).to_string(), "42");
        assert_eq!(BtrfsObjectId(256).to_string(), "256");
    }

    // ── bd-sik: checked arithmetic + alignment tests ────────────────────

    #[test]
    fn test_checked_add_bytes() {
        let base = ByteOffset(1024);
        assert_eq!(checked_add_bytes(base, 512), Some(ByteOffset(1536)));
        assert_eq!(checked_add_bytes(base, 0), Some(ByteOffset(1024)));
        assert_eq!(checked_add_bytes(ByteOffset(u64::MAX), 1), None);
        assert_eq!(checked_add_bytes(ByteOffset(u64::MAX - 10), 11), None);
        assert_eq!(
            checked_add_bytes(ByteOffset(u64::MAX - 10), 10),
            Some(ByteOffset(u64::MAX))
        );
    }

    #[test]
    fn test_checked_mul_block() {
        let bs = BlockSize::new(4096).unwrap();
        assert_eq!(checked_mul_block(BlockNumber(0), bs), Some(ByteOffset(0)));
        assert_eq!(
            checked_mul_block(BlockNumber(1), bs),
            Some(ByteOffset(4096))
        );
        assert_eq!(
            checked_mul_block(BlockNumber(256), bs),
            Some(ByteOffset(1_048_576))
        );
        // Overflow: huge block number * block size
        assert_eq!(checked_mul_block(BlockNumber(u64::MAX), bs), None);
        // Large but valid
        let large_block = u64::MAX / 4096;
        assert!(checked_mul_block(BlockNumber(large_block), bs).is_some());
        assert_eq!(checked_mul_block(BlockNumber(large_block + 1), bs), None);
    }

    #[test]
    fn test_block_number_to_byte_offset() {
        let bs = BlockSize::new(4096).unwrap();
        assert_eq!(BlockNumber(10).to_byte_offset(bs), Some(ByteOffset(40960)));
        assert_eq!(BlockNumber(u64::MAX).to_byte_offset(bs), None);
    }

    #[test]
    fn test_block_number_to_u32() {
        assert_eq!(BlockNumber(0).to_u32(), Ok(0));
        assert_eq!(BlockNumber(u64::from(u32::MAX)).to_u32(), Ok(u32::MAX));
        assert!(BlockNumber(u64::from(u32::MAX) + 1).to_u32().is_err());
    }

    #[test]
    fn test_align_down() {
        // 4K alignment
        assert_eq!(align_down(4096, 4096), Some(4096));
        assert_eq!(align_down(4097, 4096), Some(4096));
        assert_eq!(align_down(8191, 4096), Some(4096));
        assert_eq!(align_down(8192, 4096), Some(8192));
        assert_eq!(align_down(0, 4096), Some(0));
        // 1-byte alignment (trivial)
        assert_eq!(align_down(12345, 1), Some(12345));
        // Large values
        assert_eq!(align_down(u64::MAX, 4096), Some(u64::MAX - 4095));
        // Invalid: zero alignment
        assert_eq!(align_down(100, 0), None);
        // Invalid: non-power-of-two
        assert_eq!(align_down(100, 3), None);
        assert_eq!(align_down(100, 6), None);
    }

    #[test]
    fn test_align_up() {
        // 4K alignment
        assert_eq!(align_up(4096, 4096), Some(4096));
        assert_eq!(align_up(4097, 4096), Some(8192));
        assert_eq!(align_up(1, 4096), Some(4096));
        assert_eq!(align_up(0, 4096), Some(0));
        // 1-byte alignment (trivial)
        assert_eq!(align_up(12345, 1), Some(12345));
        // Overflow: aligning MAX up
        assert_eq!(align_up(u64::MAX, 4096), None);
        assert_eq!(align_up(u64::MAX - 4094, 4096), None);
        // Edge: just fits
        assert_eq!(align_up(u64::MAX - 4095, 4096), Some(u64::MAX - 4095));
        // Invalid: zero alignment
        assert_eq!(align_up(100, 0), None);
        // Invalid: non-power-of-two
        assert_eq!(align_up(100, 3), None);
    }

    #[test]
    fn test_byte_offset_align_methods() {
        let off = ByteOffset(5000);
        assert_eq!(off.align_down(4096), Some(ByteOffset(4096)));
        assert_eq!(off.align_up(4096), Some(ByteOffset(8192)));

        let aligned = ByteOffset(8192);
        assert_eq!(aligned.align_down(4096), Some(ByteOffset(8192)));
        assert_eq!(aligned.align_up(4096), Some(ByteOffset(8192)));

        // Invalid alignment
        assert_eq!(off.align_down(0), None);
        assert_eq!(off.align_up(0), None);
    }

    #[test]
    fn test_byte_offset_to_usize() {
        assert_eq!(ByteOffset(0).to_usize(), Ok(0));
        assert_eq!(ByteOffset(1024).to_usize(), Ok(1024));
        // On 64-bit platforms, u64::MAX should fit in usize.
        // On 32-bit platforms it wouldn't, but we test the error path
        // with a value that won't fit in u32.
        #[cfg(target_pointer_width = "64")]
        assert!(ByteOffset(u64::MAX).to_usize().is_ok());
    }

    #[test]
    fn test_u64_to_usize() {
        assert_eq!(u64_to_usize(42, "test"), Ok(42));
        assert_eq!(u64_to_usize(0, "test"), Ok(0));
    }

    #[test]
    fn test_u64_to_u32() {
        assert_eq!(u64_to_u32(0, "test"), Ok(0));
        assert_eq!(u64_to_u32(u64::from(u32::MAX), "test"), Ok(u32::MAX));
        assert!(u64_to_u32(u64::from(u32::MAX) + 1, "test").is_err());
        assert!(u64_to_u32(u64::MAX, "test").is_err());
    }

    #[test]
    fn test_align_power_of_two_boundaries() {
        // Exhaustive check for small powers of two
        for shift in 0..16 {
            let alignment = 1_u64 << shift;
            // Zero always aligns
            assert_eq!(align_down(0, alignment), Some(0));
            assert_eq!(align_up(0, alignment), Some(0));
            // alignment itself always aligns
            assert_eq!(align_down(alignment, alignment), Some(alignment));
            assert_eq!(align_up(alignment, alignment), Some(alignment));
            // alignment - 1 rounds down to 0, up to alignment
            if alignment > 1 {
                assert_eq!(align_down(alignment - 1, alignment), Some(0));
                assert_eq!(align_up(alignment - 1, alignment), Some(alignment));
            }
        }
    }
}
