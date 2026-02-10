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
        if !value.is_power_of_two() || value < 1024 || value > 65536 {
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
    pub fn block_to_byte(self, block: BlockNumber) -> Option<u64> {
        block.0.checked_mul(u64::from(self.0))
    }
}

/// Block group index (ext4: u32 group number).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GroupNumber(pub u32);

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

impl fmt::Display for Generation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl InodeNumber {
    pub const ROOT: Self = Self(2);
    pub const JOURNAL: Self = Self(8);
}

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
}

/// Compute the block group that contains a given block.
///
/// `first_data_block` is typically 0 for 4K blocks and 1 for 1K blocks.
#[must_use]
pub fn block_to_group(block: BlockNumber, blocks_per_group: u32, first_data_block: u32) -> GroupNumber {
    let adjusted = block.0.saturating_sub(u64::from(first_data_block));
    GroupNumber((adjusted / u64::from(blocks_per_group)) as u32)
}

/// Compute the first block of a given block group.
pub fn group_first_block(group: GroupNumber, blocks_per_group: u32, first_data_block: u32) -> Option<BlockNumber> {
    let offset = u64::from(group.0).checked_mul(u64::from(blocks_per_group))?;
    offset.checked_add(u64::from(first_data_block)).map(BlockNumber)
}

/// Compute the inode's block group from its inode number.
///
/// Inode numbers are 1-indexed; group assignment uses `(ino - 1) / inodes_per_group`.
#[must_use]
pub fn inode_to_group(ino: InodeNumber, inodes_per_group: u32) -> GroupNumber {
    GroupNumber(((ino.0.saturating_sub(1)) / u64::from(inodes_per_group)) as u32)
}

/// Compute the index of an inode within its block group.
#[must_use]
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

        assert_eq!(group_first_block(GroupNumber(0), 32768, 0), Some(BlockNumber(0)));
        assert_eq!(group_first_block(GroupNumber(1), 32768, 0), Some(BlockNumber(32768)));

        // 1K blocks, first_data_block = 1, 8192 blocks per group
        assert_eq!(block_to_group(BlockNumber(1), 8192, 1), GroupNumber(0));
        assert_eq!(block_to_group(BlockNumber(8193), 8192, 1), GroupNumber(1));
        assert_eq!(group_first_block(GroupNumber(0), 8192, 1), Some(BlockNumber(1)));
        assert_eq!(group_first_block(GroupNumber(1), 8192, 1), Some(BlockNumber(8193)));
    }

    #[test]
    fn test_block_number_checked_ops() {
        assert_eq!(BlockNumber(10).checked_add(5), Some(BlockNumber(15)));
        assert_eq!(BlockNumber(u64::MAX).checked_add(1), None);
        assert_eq!(BlockNumber(10).checked_sub(3), Some(BlockNumber(7)));
        assert_eq!(BlockNumber(0).checked_sub(1), None);
    }

    #[test]
    fn test_inode_constants() {
        assert_eq!(InodeNumber::ROOT, InodeNumber(2));
        assert_eq!(InodeNumber::JOURNAL, InodeNumber(8));
    }
}
