#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::OnceLock;
use thiserror::Error;

pub const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
pub const EXT4_SUPERBLOCK_SIZE: usize = 1024;
pub const EXT4_SUPER_MAGIC: u16 = 0xEF53;

/// Sector size for ext4 `i_blocks` accounting.
///
/// The `i_blocks` field counts in 512-byte units regardless of fs block size
/// (unless the `huge_file` flag promotes to fs-block units).
pub const EXT4_SECTOR_SIZE: u32 = 512;

/// Byte offset of `s_checksum` within the ext4 superblock.
///
/// The kernel CRC32C-checksums `sb[..0x3FC]` and stores the result at
/// `sb[0x3FC..0x400]`.
pub const EXT4_SB_CHECKSUM_OFFSET: usize = 0x3FC;

pub const BTRFS_SUPER_INFO_OFFSET: usize = 64 * 1024;
pub const BTRFS_SUPER_INFO_SIZE: usize = 4096;
pub const BTRFS_MAGIC: u64 = 0x4D5F_5366_5248_425F;

/// btrfs checksum algorithm types (stored in superblock `csum_type` field).
pub const BTRFS_CSUM_TYPE_CRC32C: u16 = 0;
pub const BTRFS_CSUM_TYPE_XXHASH64: u16 = 1;
pub const BTRFS_CSUM_TYPE_SHA256: u16 = 2;
pub const BTRFS_CSUM_TYPE_BLAKE2B: u16 = 3;

/// Runtime SIMD capabilities relevant to checksum acceleration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SimdCapabilities {
    bits: u8,
}

impl SimdCapabilities {
    const X86_SSE42: u8 = 1 << 0;
    const X86_AVX2: u8 = 1 << 1;
    const AARCH64_CRC: u8 = 1 << 2;
    const AARCH64_NEON: u8 = 1 << 3;

    const fn set(&mut self, flag: u8, enabled: bool) {
        if enabled {
            self.bits |= flag;
        }
    }

    #[must_use]
    pub const fn has_x86_sse42(self) -> bool {
        (self.bits & Self::X86_SSE42) != 0
    }

    #[must_use]
    pub const fn has_x86_avx2(self) -> bool {
        (self.bits & Self::X86_AVX2) != 0
    }

    #[must_use]
    pub const fn has_aarch64_crc(self) -> bool {
        (self.bits & Self::AARCH64_CRC) != 0
    }

    #[must_use]
    pub const fn has_aarch64_neon(self) -> bool {
        (self.bits & Self::AARCH64_NEON) != 0
    }
}

/// Batch checksum algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumAlgo {
    /// CRC32C with a caller-provided seed.
    Crc32c { seed: u32 },
    /// Lower 32 bits of the BLAKE3 digest.
    Blake3Truncated32,
}

static SIMD_CAPABILITIES: OnceLock<SimdCapabilities> = OnceLock::new();

fn detect_simd_capabilities() -> SimdCapabilities {
    let mut caps = SimdCapabilities::default();
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        caps.set(
            SimdCapabilities::X86_SSE42,
            std::arch::is_x86_feature_detected!("sse4.2"),
        );
        caps.set(
            SimdCapabilities::X86_AVX2,
            std::arch::is_x86_feature_detected!("avx2"),
        );
    }
    #[cfg(target_arch = "aarch64")]
    {
        caps.set(
            SimdCapabilities::AARCH64_CRC,
            std::arch::is_aarch64_feature_detected!("crc"),
        );
        caps.set(
            SimdCapabilities::AARCH64_NEON,
            std::arch::is_aarch64_feature_detected!("neon"),
        );
    }
    caps
}

/// Detect and cache checksum-relevant SIMD capabilities.
///
/// This logs the detected capability matrix once on first use.
#[must_use]
pub fn simd_capabilities() -> SimdCapabilities {
    *SIMD_CAPABILITIES.get_or_init(|| {
        let caps = detect_simd_capabilities();
        tracing::info!(
            target: "ffs::checksum",
            x86_sse42 = caps.has_x86_sse42(),
            x86_avx2 = caps.has_x86_avx2(),
            aarch64_crc = caps.has_aarch64_crc(),
            aarch64_neon = caps.has_aarch64_neon(),
            "detected checksum SIMD capabilities"
        );
        caps
    })
}

/// Compute CRC32C over `data`.
#[inline]
#[must_use]
pub fn crc32c(data: &[u8]) -> u32 {
    let _ = simd_capabilities();
    crc32c::crc32c(data)
}

/// Compute seeded CRC32C over `data`.
#[inline]
#[must_use]
pub fn crc32c_append(seed: u32, data: &[u8]) -> u32 {
    let _ = simd_capabilities();
    crc32c::crc32c_append(seed, data)
}

/// Compute BLAKE3 digest over `data`.
#[inline]
#[must_use]
pub fn blake3_hash(data: &[u8]) -> blake3::Hash {
    let _ = simd_capabilities();
    blake3::hash(data)
}

#[inline]
fn blake3_truncated32(data: &[u8]) -> u32 {
    let hash = blake3_hash(data);
    let bytes = hash.as_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Compute checksums for multiple blocks in parallel.
#[must_use]
pub fn batch_checksum(blocks: &[&[u8]], algo: ChecksumAlgo) -> Vec<u32> {
    use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

    match algo {
        ChecksumAlgo::Crc32c { seed } => blocks
            .par_iter()
            .map(|block| crc32c_append(seed, block))
            .collect(),
        ChecksumAlgo::Blake3Truncated32 => blocks
            .par_iter()
            .map(|block| blake3_truncated32(block))
            .collect(),
    }
}

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
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Number of bits to shift to convert between bytes and blocks.
    #[must_use]
    pub const fn shift(self) -> u32 {
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
    pub const fn from_uuid_bytes_be(bytes: [u8; 16]) -> Self {
        Self(u128::from_be_bytes(bytes))
    }

    #[must_use]
    pub const fn to_uuid_bytes_be(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }
}

/// Filesystem mount mode controlling which on-disk mutations are permitted.
///
/// `FrankenFS` operates in one of two modes:
///
/// - **Compat** (default): Only standard ext4/btrfs on-disk structures are read
///   and written. The resulting image remains mountable by the Linux kernel
///   driver. All checksums use CRC32C. Journal uses JBD2 physical journaling.
///
/// - **Native**: In addition to standard structures, `FrankenFS` may write
///   MVCC version chains (to a dedicated version-store inode), `RaptorQ` repair
///   symbols (to reserved tail blocks in each block group), and BLAKE3
///   checksums for native metadata. Journal uses COW semantics.
///
/// The mode is set at mount time via [`MountMode`] in `OpenOptions`. Switching
/// from Compat to Native requires explicit opt-in; Native images can be opened
/// in Compat mode (read-only for native-only metadata).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum MountMode {
    /// Compatibility mode: only standard ext4/btrfs mutations allowed.
    #[default]
    Compat,
    /// Native MVCC mode: repair symbols, version store, and BLAKE3 permitted.
    Native,
}

impl MountMode {
    /// Returns `true` if this is native MVCC mode.
    #[must_use]
    pub const fn is_native(self) -> bool {
        matches!(self, Self::Native)
    }

    /// Returns `true` if this is compatibility mode.
    #[must_use]
    pub const fn is_compat(self) -> bool {
        matches!(self, Self::Compat)
    }
}

impl fmt::Display for MountMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compat => f.write_str("compat"),
            Self::Native => f.write_str("native"),
        }
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

/// Write a little-endian u16 at `offset` in `data`.
///
/// # Panics
///
/// Panics if `offset + 2 > data.len()`.
#[inline]
pub fn write_le_u16(data: &mut [u8], offset: usize, val: u16) {
    data[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
}

/// Write a little-endian u32 at `offset` in `data`.
///
/// # Panics
///
/// Panics if `offset + 4 > data.len()`.
#[inline]
pub fn write_le_u32(data: &mut [u8], offset: usize, val: u32) {
    data[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
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
pub fn all_zero_bytes(bytes: &[u8]) -> bool {
    // `as_chunks::<N>()` instead of `chunks_exact(N)` (bd-wc78p): with a CONST
    // chunk size it hands back `&[[u8; N]]`, so the length is in the type and the
    // per-chunk `try_into().expect(..)` disappears. `chunks_exact(N)` is also a
    // denied pedantic lint here, which was breaking the workspace clippy gate.
    //
    // ISOMORPHISM (this is a banked perf lever, b77c7e8a / bd-a2x93 — the 4-lane
    // unrolled zero scan — so the shape is preserved deliberately):
    //   * split point: `as_chunks::<64>()` returns the same `len/64*64` prefix and
    //     the same trailing remainder that `chunks_exact(64)` + `.remainder()` did.
    //   * traversal order: unchanged, front to back.
    //   * the four-lane unroll is character-for-character the same four
    //     `u128::from_ne_bytes` loads OR-ed in the same order, so the instruction
    //     mix the lever was measured on is preserved.
    //   * early return: still on the first non-zero 64-byte line, then the first
    //     non-zero 16-byte lane, so the number of bytes touched before a `false`
    //     is identical for every input.
    //   * endianness: still `from_ne_bytes`; the value is compared against 0, for
    //     which byte order is irrelevant.
    // Result equality is total, not just structural: the function is a pure
    // predicate over "is every byte zero", and both forms visit every byte until
    // the first non-zero one.
    let (cache_lines, tail) = bytes.as_chunks::<64>();
    for cache_line in cache_lines {
        let word0 = u128::from_ne_bytes(cache_line[0..16].try_into().expect("first 16-byte lane"));
        let word1 =
            u128::from_ne_bytes(cache_line[16..32].try_into().expect("second 16-byte lane"));
        let word2 = u128::from_ne_bytes(cache_line[32..48].try_into().expect("third 16-byte lane"));
        let word3 =
            u128::from_ne_bytes(cache_line[48..64].try_into().expect("fourth 16-byte lane"));
        if (word0 | word1 | word2 | word3) != 0 {
            return false;
        }
    }

    let (lanes, rest) = tail.as_chunks::<16>();
    for lane in lanes {
        if u128::from_ne_bytes(*lane) != 0 {
            return false;
        }
    }
    rest.iter().all(|&byte| byte == 0)
}

#[must_use]
pub const fn is_power_of_two_u32(value: u32) -> bool {
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
    pub const fn to_btrfs(self) -> BtrfsObjectId {
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
    #[allow(clippy::missing_const_for_fn)]
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
    pub const fn to_canonical(self) -> InodeNumber {
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
pub const S_IFMT: u16 = 0o170_000;
/// Named pipe (FIFO).
pub const S_IFIFO: u16 = 0o010_000;
/// Character device.
pub const S_IFCHR: u16 = 0o020_000;
/// Directory.
pub const S_IFDIR: u16 = 0o040_000;
/// Block device.
pub const S_IFBLK: u16 = 0o060_000;
/// Regular file.
pub const S_IFREG: u16 = 0o100_000;
/// Symbolic link.
pub const S_IFLNK: u16 = 0o120_000;
/// Socket.
pub const S_IFSOCK: u16 = 0o140_000;

// ── POSIX file-mode predicates (bd-vnfhb) ────────────────────────────────
//
// Mirrored from `<sys/stat.h>`. Each predicate masks `mode & S_IFMT`
// and compares to the corresponding S_IF* constant. A regression in
// the mask or the comparison sense would silently misclassify file
// kinds at every callsite that uses the predicate. Pinned by
// `posix_file_mode_predicates_match_kernel_macros`.

/// Predicate for "is regular file" (kernel: `S_ISREG(m)`).
#[must_use]
pub const fn is_regular_file(mode: u16) -> bool {
    (mode & S_IFMT) == S_IFREG
}

/// Predicate for "is directory" (kernel: `S_ISDIR(m)`).
#[must_use]
pub const fn is_directory(mode: u16) -> bool {
    (mode & S_IFMT) == S_IFDIR
}

/// Predicate for "is symbolic link" (kernel: `S_ISLNK(m)`).
#[must_use]
pub const fn is_symlink(mode: u16) -> bool {
    (mode & S_IFMT) == S_IFLNK
}

/// Predicate for "is character device" (kernel: `S_ISCHR(m)`).
#[must_use]
pub const fn is_character_device(mode: u16) -> bool {
    (mode & S_IFMT) == S_IFCHR
}

/// Predicate for "is block device" (kernel: `S_ISBLK(m)`).
#[must_use]
pub const fn is_block_device(mode: u16) -> bool {
    (mode & S_IFMT) == S_IFBLK
}

/// Predicate for "is FIFO / named pipe" (kernel: `S_ISFIFO(m)`).
#[must_use]
pub const fn is_fifo(mode: u16) -> bool {
    (mode & S_IFMT) == S_IFIFO
}

/// Predicate for "is socket" (kernel: `S_ISSOCK(m)`).
#[must_use]
pub const fn is_socket(mode: u16) -> bool {
    (mode & S_IFMT) == S_IFSOCK
}

// ── ext4 inode flags (i_flags) ──────────────────────────────────────────────

/// Legacy secure-deletion advisory flag retained for on-disk compatibility.
pub const EXT4_SECRM_FL: u32 = 0x0000_0001;
/// Legacy undelete advisory flag retained for on-disk compatibility.
pub const EXT4_UNRM_FL: u32 = 0x0000_0002;
/// Compressed file (e2compr: may be set on new writes).
pub const EXT4_COMPR_FL: u32 = 0x0000_0004;
/// One or more compressed clusters (e2compr: file contains compressed data).
pub const EXT4_COMPRBLK_FL: u32 = 0x0000_0200;
/// Access raw compressed data (e2compr: bypass decompression).
pub const EXT4_NOCOMPR_FL: u32 = 0x0000_0400;
/// Compression error (e2compr: file became read-only due to error).
pub const EXT4_ECOMPR_FL: u32 = 0x0000_0800;
/// Sentinel block address marking compressed cluster tail.
pub const EXT2_COMPRESSED_BLKADDR: u64 = 0xFFFF_FFFF;
/// Magic number at the start of a compressed cluster header.
pub const EXT2_COMPRESS_MAGIC: u16 = 0x8EC7;
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
/// Inode has fs-verity protection (read-only, Merkle-tree-verified).
pub const EXT4_VERITY_FL: u32 = 0x0010_0000;
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

// ── btrfs-specific FS flags ─────────────────────────────────────────────────

/// No copy-on-write for data (btrfs-specific, implies NODATASUM).
/// Used in `FS_IOC_GETFLAGS`/`FS_IOC_SETFLAGS` for btrfs inodes.
pub const FS_NOCOW_FL: u32 = 0x0080_0000;

/// Maximum ext4 fast symlink target size (stored in the inode's `i_block` area).
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
pub const fn align_down(value: u64, alignment: u64) -> Option<u64> {
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
    if blocks_per_group == 0 {
        return GroupNumber(0);
    }
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
    if inodes_per_group == 0 {
        return GroupNumber(0);
    }
    GroupNumber(((ino.0.saturating_sub(1)) / u64::from(inodes_per_group)) as u32)
}

/// Compute the index of an inode within its block group.
#[must_use]
#[allow(clippy::cast_possible_truncation)] // modulo by u32 always fits in u32
pub fn inode_index_in_group(ino: InodeNumber, inodes_per_group: u32) -> u32 {
    if inodes_per_group == 0 {
        return 0;
    }
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

    /// Differential oracle for the unrolled zero scan.
    ///
    /// Extended to 258 for the `as_chunks` conversion (bd-wc78p): 160 only reached
    /// two 64-byte cache lines, so it could not distinguish a bug in the
    /// prefix/remainder split from one in the lane loop. 258 covers four full cache
    /// lines plus every remainder shape (0..64), and walking a single non-zero byte
    /// across every position pins the EARLY-RETURN boundary at each of the three
    /// stages — 64-byte line, 16-byte lane, trailing bytes.
    #[test]
    fn all_zero_bytes_matches_scalar_scan() {
        for len in 0_usize..=258 {
            let mut bytes = vec![0_u8; len];
            assert!(all_zero_bytes(&bytes), "all-zero len {len}");
            for pos in 0..len {
                bytes[pos] = 1;
                assert!(
                    !all_zero_bytes(&bytes),
                    "nonzero byte at {pos} in len {len}"
                );
                bytes[pos] = 0;
            }
        }
    }

    /// The bit position within a byte must not matter, and neither must the byte
    /// position within its 16-byte lane. A `from_ne_bytes` load that dropped or
    /// mis-ordered a lane would still pass a test that only ever sets `1` in the
    /// first lane, so set every single-bit pattern at every offset of one full
    /// cache line plus a partial one.
    #[test]
    fn all_zero_bytes_detects_every_single_bit_at_every_offset() {
        let len = 64 + 16 + 7;
        for pos in 0..len {
            for bit in 0..8 {
                let mut bytes = vec![0_u8; len];
                bytes[pos] = 1_u8 << bit;
                assert!(
                    !all_zero_bytes(&bytes),
                    "bit {bit} at byte {pos} of {len} must be detected"
                );
            }
        }
    }

    /// The remainder path must not be skipped when the prefix is clean. A split
    /// that dropped the tail would report an all-zero verdict for a buffer whose
    /// ONLY non-zero byte is past the last full 64-byte line.
    #[test]
    fn all_zero_bytes_checks_the_tail_after_a_clean_prefix() {
        for tail_len in 1_usize..64 {
            let len = 128 + tail_len;
            let mut bytes = vec![0_u8; len];
            bytes[len - 1] = 0x80;
            assert!(
                !all_zero_bytes(&bytes),
                "final byte of a {tail_len}-byte tail after two clean cache lines"
            );
        }
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
    fn checksum_wrappers_match_backend() {
        let data = b"frankenfs-checksum-wrapper";
        let seed = 0xA11C_E551;
        assert_eq!(crc32c(data), ::crc32c::crc32c(data));
        assert_eq!(
            crc32c_append(seed, data),
            ::crc32c::crc32c_append(seed, data)
        );
        assert_eq!(blake3_hash(data), ::blake3::hash(data));
    }

    #[test]
    fn batch_checksum_crc32c_matches_scalar() {
        let blocks: [&[u8]; 4] = [
            b"alpha".as_slice(),
            b"beta".as_slice(),
            b"gamma".as_slice(),
            b"delta".as_slice(),
        ];
        let seed = 0x1234_5678;
        let expected: Vec<u32> = blocks
            .iter()
            .map(|block| crc32c_append(seed, block))
            .collect();
        let actual = batch_checksum(&blocks, ChecksumAlgo::Crc32c { seed });
        assert_eq!(actual, expected);
    }

    #[test]
    fn batch_checksum_blake3_matches_scalar_truncation() {
        let blocks: [&[u8]; 3] = [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()];
        let expected: Vec<u32> = blocks
            .iter()
            .map(|block| {
                let hash = blake3_hash(block);
                let bytes = hash.as_bytes();
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            })
            .collect();
        let actual = batch_checksum(&blocks, ChecksumAlgo::Blake3Truncated32);
        assert_eq!(actual, expected);
    }

    #[test]
    fn simd_capabilities_cached() {
        let first = simd_capabilities();
        let second = simd_capabilities();
        assert_eq!(first, second);
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

    // ── Edge-case and boundary tests (bd-2s9u) ────────────────────────

    #[test]
    fn read_le_u64_basic() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_le_u64(&bytes, 0).unwrap(), 0x0807_0605_0403_0201);
    }

    #[test]
    fn read_le_u64_insufficient_data() {
        let bytes = [0x01, 0x02, 0x03];
        assert!(read_le_u64(&bytes, 0).is_err());
    }

    #[test]
    fn read_fixed_basic() {
        let data = [10, 20, 30, 40, 50];
        let result: [u8; 3] = read_fixed(&data, 1).unwrap();
        assert_eq!(result, [20, 30, 40]);
    }

    #[test]
    fn read_fixed_out_of_bounds() {
        let data = [1, 2, 3];
        let result: Result<[u8; 4], _> = read_fixed(&data, 0);
        assert!(result.is_err());
    }

    #[test]
    fn ensure_slice_offset_overflow() {
        let data = [0u8; 10];
        let result = ensure_slice(&data, usize::MAX, 1);
        assert!(matches!(
            result,
            Err(ParseError::InvalidField {
                field: "offset",
                ..
            })
        ));
    }

    #[test]
    fn trim_nul_padded_all_nul() {
        let bytes = [0u8; 8];
        assert_eq!(trim_nul_padded(&bytes), "");
    }

    #[test]
    fn trim_nul_padded_empty() {
        assert_eq!(trim_nul_padded(&[]), "");
    }

    #[test]
    fn trim_nul_padded_no_nul() {
        let bytes = b"hello";
        assert_eq!(trim_nul_padded(bytes), "hello");
    }

    #[test]
    fn trim_nul_padded_interior_nul() {
        let bytes = b"ab\0cd";
        assert_eq!(trim_nul_padded(bytes), "ab");
    }

    #[test]
    fn ext4_block_size_from_log_overflow() {
        // log = 22 → shift = 32 → overflow for u32
        assert_eq!(ext4_block_size_from_log(22), None);
        // log = u32::MAX → addition overflow
        assert_eq!(ext4_block_size_from_log(u32::MAX), None);
    }

    #[test]
    fn inode_to_group_inode_zero() {
        // Inode 0 is not valid in ext4, but should not panic.
        // saturating_sub(1) on 0 gives 0, so group = 0/8192 = 0.
        assert_eq!(inode_to_group(InodeNumber(0), 8192), GroupNumber(0));
        assert_eq!(inode_index_in_group(InodeNumber(0), 8192), 0);
    }

    #[test]
    fn batch_checksum_empty_blocks() {
        let blocks: [&[u8]; 0] = [];
        let result = batch_checksum(&blocks, ChecksumAlgo::Crc32c { seed: 0 });
        assert!(result.is_empty());
        let result = batch_checksum(&blocks, ChecksumAlgo::Blake3Truncated32);
        assert!(result.is_empty());
    }

    #[test]
    fn group_first_block_add_overflow() {
        // u32::MAX * u32::MAX fits in u64, but adding first_data_block=u32::MAX
        // can push the result over the edge if the multiplication is already near u64::MAX.
        // Use a case where multiplication just fits but adding overflows.
        let result = group_first_block(GroupNumber(u32::MAX), u32::MAX, u32::MAX);
        // u32::MAX * u32::MAX = 2^64 - 2^33 + 1, plus u32::MAX = 2^64 - 2^32.
        // That's still < u64::MAX, so this succeeds. Let's verify it returns Some.
        assert!(result.is_some(), "should not overflow for u32::MAX inputs");
        // Verify the function handles zero correctly.
        assert_eq!(
            group_first_block(GroupNumber(0), 32768, 0),
            Some(BlockNumber(0))
        );
    }

    #[test]
    fn display_and_debug_coverage() {
        assert_eq!(Generation(7).to_string(), "7");
        // TxnId and CommitSeq only have Debug, not Display.
        let _ = format!("{:?}", TxnId(42));
        let _ = format!("{:?}", CommitSeq(99));
    }

    #[test]
    fn parse_error_display() {
        let e = ParseError::InsufficientData {
            needed: 8,
            offset: 4,
            actual: 2,
        };
        let msg = format!("{e}");
        assert_eq!(msg, "insufficient data: need 8 bytes at offset 4, got 2");

        let e = ParseError::InvalidMagic {
            expected: 0xEF53,
            actual: 0xBEEF,
        };
        let msg = format!("{e}");
        assert_eq!(msg, "invalid magic: expected 0xef53, got 0xbeef");

        let e = ParseError::InvalidField {
            field: "test_field",
            reason: "bad value",
        };
        let msg = format!("{e}");
        assert_eq!(msg, "invalid field: test_field (bad value)");

        let e = ParseError::IntegerConversion {
            field: "test_field",
        };
        let msg = format!("{e}");
        assert_eq!(msg, "integer conversion failed: test_field");
    }

    #[test]
    fn is_power_of_two_u32_edge_cases() {
        assert!(!is_power_of_two_u32(0));
        assert!(is_power_of_two_u32(1));
        assert!(is_power_of_two_u32(2));
        assert!(!is_power_of_two_u32(3));
        assert!(is_power_of_two_u32(0x8000_0000)); // 2^31
        assert!(!is_power_of_two_u32(u32::MAX));
    }

    #[test]
    fn block_to_group_block_before_first_data() {
        // Block 0 with first_data_block=1: saturating_sub gives 0.
        assert_eq!(block_to_group(BlockNumber(0), 8192, 1), GroupNumber(0));
    }

    #[test]
    fn snapshot_fields() {
        let snap = Snapshot {
            high: CommitSeq(100),
        };
        assert_eq!(snap.high, CommitSeq(100));
        let _ = format!("{snap:?}");
    }

    #[test]
    fn checksum_algo_debug_clone_eq() {
        let a = ChecksumAlgo::Crc32c { seed: 42 };
        let b = a;
        assert_eq!(a, b);
        let _ = format!("{a:?}");

        let c = ChecksumAlgo::Blake3Truncated32;
        assert_ne!(a, c);
    }

    #[test]
    fn simd_capabilities_default_is_empty() {
        let caps = SimdCapabilities::default();
        assert!(!caps.has_x86_sse42());
        assert!(!caps.has_x86_avx2());
        assert!(!caps.has_aarch64_crc());
        assert!(!caps.has_aarch64_neon());
    }

    #[test]
    fn posix_file_type_constants() {
        // Verify file type constants don't overlap.
        let types = [
            S_IFIFO, S_IFCHR, S_IFDIR, S_IFBLK, S_IFREG, S_IFLNK, S_IFSOCK,
        ];
        for (i, a) in types.iter().enumerate() {
            for b in &types[i + 1..] {
                assert_ne!(a, b, "file type constants must not overlap");
            }
        }
        // Verify mask extracts file type.
        assert_eq!(0o100_644 & S_IFMT, S_IFREG);
        assert_eq!(0o040_755 & S_IFMT, S_IFDIR);
        assert_eq!(0o120_777 & S_IFMT, S_IFLNK);
    }

    #[test]
    fn ext4_xattr_constants() {
        // xattr indices should be distinct and sequential.
        let indices = [
            EXT4_XATTR_INDEX_USER,
            EXT4_XATTR_INDEX_POSIX_ACL_ACCESS,
            EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT,
            EXT4_XATTR_INDEX_TRUSTED,
            EXT4_XATTR_INDEX_LUSTRE,
            EXT4_XATTR_INDEX_SECURITY,
            EXT4_XATTR_INDEX_SYSTEM,
            EXT4_XATTR_INDEX_RICHACL,
            EXT4_XATTR_INDEX_ENCRYPTION,
            EXT4_XATTR_INDEX_HURD,
        ];
        for (i, idx) in indices.iter().enumerate() {
            assert_eq!(
                *idx,
                u8::try_from(i + 1).unwrap(),
                "xattr index {i} mismatch"
            );
        }
    }

    #[test]
    fn write_le_u16_u32_boundary() {
        let mut buf = [0u8; 4];
        write_le_u16(&mut buf, 2, 0xABCD);
        assert_eq!(buf, [0, 0, 0xCD, 0xAB]);

        let mut buf = [0u8; 8];
        write_le_u32(&mut buf, 4, 0x1234_5678);
        assert_eq!(buf[4..8], [0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn device_id_display_zero_padded() {
        let id = DeviceId(0x1);
        assert_eq!(id.to_string(), "00000000000000000000000000000001");
    }

    // ── Edge-case hardening tests ──────────────────────────────────────

    #[test]
    fn device_id_uuid_roundtrip_explicit() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let id = DeviceId::from_uuid_bytes_be(bytes);
        assert_eq!(id.to_uuid_bytes_be(), bytes);
    }

    #[test]
    fn device_id_zero() {
        let id = DeviceId(0);
        assert_eq!(id.to_string(), "00000000000000000000000000000000");
        assert_eq!(id.to_uuid_bytes_be(), [0u8; 16]);
    }

    #[test]
    fn simd_capabilities_set_flag() {
        let mut caps = SimdCapabilities::default();
        caps.set(SimdCapabilities::X86_SSE42, true);
        assert!(caps.has_x86_sse42());
        assert!(!caps.has_x86_avx2());

        caps.set(SimdCapabilities::X86_AVX2, true);
        assert!(caps.has_x86_avx2());

        // set(false) is a no-op (does not clear), so SSE4.2 remains set.
        caps.set(SimdCapabilities::X86_SSE42, false);
        assert!(caps.has_x86_sse42());
    }

    #[test]
    fn display_newtypes() {
        assert_eq!(BlockNumber(42).to_string(), "42");
        assert_eq!(InodeNumber(100).to_string(), "100");
        assert_eq!(BlockSize::new(4096).unwrap().to_string(), "4096");
        assert_eq!(GroupNumber(3).to_string(), "3");
        assert_eq!(ByteOffset(8192).to_string(), "8192");
        assert_eq!(Generation(7).to_string(), "7");
    }

    #[test]
    fn representative_scalar_and_parse_error_exact_golden_contract() {
        let device_id = DeviceId::from_uuid_bytes_be([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]);
        let actual = [
            format!("mount_mode.compat={}", MountMode::Compat),
            format!("mount_mode.native={}", MountMode::Native),
            format!("block_number.answer={}", BlockNumber(42)),
            format!("inode_number.root={}", InodeNumber::ROOT),
            format!("block_size.4k={}", BlockSize::new(4096).unwrap()),
            format!("group_number.sample={}", GroupNumber(7)),
            format!("byte_offset.sample={}", ByteOffset(8192)),
            format!("generation.sample={}", Generation(42)),
            format!("device_id.sample={device_id}"),
            format!("ext4_inode.root={}", Ext4InodeNumber::ROOT),
            format!("btrfs_object.sample={}", BtrfsObjectId(256)),
            format!(
                "parse.insufficient_data={}",
                ParseError::InsufficientData {
                    needed: 8,
                    offset: 1024,
                    actual: 3,
                }
            ),
            format!(
                "parse.invalid_magic={}",
                ParseError::InvalidMagic {
                    expected: u64::from(EXT4_SUPER_MAGIC),
                    actual: 0,
                }
            ),
            format!(
                "parse.invalid_field={}",
                ParseError::InvalidField {
                    field: "block_size",
                    reason: "must be power of two in 1024..=65536",
                }
            ),
            format!(
                "parse.integer_conversion={}",
                ParseError::IntegerConversion {
                    field: "block_number",
                }
            ),
        ]
        .join("\n");

        let expected = concat!(
            "mount_mode.compat=compat\n",
            "mount_mode.native=native\n",
            "block_number.answer=42\n",
            "inode_number.root=2\n",
            "block_size.4k=4096\n",
            "group_number.sample=7\n",
            "byte_offset.sample=8192\n",
            "generation.sample=42\n",
            "device_id.sample=0123456789abcdeffedcba9876543210\n",
            "ext4_inode.root=2\n",
            "btrfs_object.sample=256\n",
            "parse.insufficient_data=insufficient data: need 8 bytes at offset 1024, got 3\n",
            "parse.invalid_magic=invalid magic: expected 0xef53, got 0x0\n",
            "parse.invalid_field=invalid field: block_size (must be power of two in 1024..=65536)\n",
            "parse.integer_conversion=integer conversion failed: block_number",
        );
        assert_eq!(actual, expected);
    }

    const REPRESENTATIVE_SCALAR_JSON_GOLDEN: &str = r#"{
  "mount_mode": "Native",
  "block_number": 42,
  "inode_number": 2,
  "txn_id": 7,
  "commit_seq": 17,
  "snapshot": {
    "high": 17
  },
  "block_size": 4096,
  "group_number": 3,
  "byte_offset": 8192,
  "generation": 21,
  "ext4_inode": 2,
  "btrfs_object_id": 256
}"#;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct RepresentativeScalarJsonContract {
        mount_mode: MountMode,
        block_number: BlockNumber,
        inode_number: InodeNumber,
        txn_id: TxnId,
        commit_seq: CommitSeq,
        snapshot: Snapshot,
        block_size: BlockSize,
        group_number: GroupNumber,
        byte_offset: ByteOffset,
        generation: Generation,
        ext4_inode: Ext4InodeNumber,
        btrfs_object_id: BtrfsObjectId,
    }

    #[test]
    fn representative_scalar_json_exact_golden_contract() {
        let actual = RepresentativeScalarJsonContract {
            mount_mode: MountMode::Native,
            block_number: BlockNumber(42),
            inode_number: InodeNumber::ROOT,
            txn_id: TxnId(7),
            commit_seq: CommitSeq(17),
            snapshot: Snapshot {
                high: CommitSeq(17),
            },
            block_size: BlockSize::new(4096).unwrap(),
            group_number: GroupNumber(3),
            byte_offset: ByteOffset(8192),
            generation: Generation(21),
            ext4_inode: Ext4InodeNumber::ROOT,
            btrfs_object_id: BtrfsObjectId(256),
        };

        let json = serde_json::to_string_pretty(&actual).expect("serialize representative JSON");
        assert_eq!(json, REPRESENTATIVE_SCALAR_JSON_GOLDEN);

        let parsed: RepresentativeScalarJsonContract =
            serde_json::from_str(&json).expect("deserialize representative JSON");
        assert_eq!(parsed, actual);
    }

    #[test]
    fn newtype_ordering() {
        assert!(BlockNumber(1) < BlockNumber(2));
        assert!(InodeNumber(10) > InodeNumber(5));
        assert!(ByteOffset(100) >= ByteOffset(100));
        assert!(GroupNumber(0) <= GroupNumber(1));
        assert!(CommitSeq(3) < CommitSeq(4));
        assert!(TxnId(1) < TxnId(2));
        assert!(BlockSize::new(1024).unwrap() < BlockSize::new(4096).unwrap());
    }

    #[test]
    fn byte_offset_zero_constant() {
        assert_eq!(ByteOffset::ZERO, ByteOffset(0));
        assert_eq!(ByteOffset::ZERO.0, 0);
    }

    #[test]
    fn parse_error_equality() {
        let a = ParseError::InsufficientData {
            needed: 8,
            offset: 0,
            actual: 4,
        };
        let b = a.clone();
        assert_eq!(a, b);

        let c = ParseError::InvalidMagic {
            expected: 0xEF53,
            actual: 0,
        };
        assert_ne!(a, c);
    }

    #[test]
    fn block_size_shift_values() {
        assert_eq!(BlockSize::new(1024).unwrap().shift(), 10);
        assert_eq!(BlockSize::new(2048).unwrap().shift(), 11);
        assert_eq!(BlockSize::new(4096).unwrap().shift(), 12);
        assert_eq!(BlockSize::new(8192).unwrap().shift(), 13);
        assert_eq!(BlockSize::new(16384).unwrap().shift(), 14);
        assert_eq!(BlockSize::new(32768).unwrap().shift(), 15);
        assert_eq!(BlockSize::new(65536).unwrap().shift(), 16);
    }

    #[test]
    fn block_to_byte_overflow() {
        let bs = BlockSize::new(4096).unwrap();
        // Very large block number should overflow when multiplied.
        assert_eq!(bs.block_to_byte(BlockNumber(u64::MAX)), None);
        // Just under overflow boundary should succeed.
        let max_block = u64::MAX / 4096;
        assert!(bs.block_to_byte(BlockNumber(max_block)).is_some());
    }

    // ── Property-based tests (proptest) ────────────────────────────────

    use proptest::prelude::*;

    fn valid_block_size_strategy() -> impl Strategy<Value = u32> {
        prop::sample::select(vec![1024_u32, 2048, 4096, 8192, 16384, 32768, 65536])
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn proptest_block_size_byte_block_roundtrip(
            raw_bs in valid_block_size_strategy(),
            byte_offset in 0_u64..=(u64::MAX / 65536),
        ) {
            let bs = BlockSize::new(raw_bs).unwrap();
            let block = bs.byte_to_block(byte_offset);
            let round_tripped = bs.block_to_byte(block).unwrap();
            // block_to_byte(byte_to_block(x)) == align_down(x, bs)
            prop_assert_eq!(round_tripped, byte_offset & !(u64::from(raw_bs) - 1));
        }

        #[test]
        fn proptest_block_size_rejects_invalid(value in 0_u32..=200_000) {
            let valid = value.is_power_of_two() && (1024..=65536).contains(&value);
            prop_assert_eq!(BlockSize::new(value).is_ok(), valid);
        }

        #[test]
        fn proptest_align_down_le_input(
            value in 0_u64..=u64::MAX,
            shift in 0_u32..32,
        ) {
            let alignment = 1_u64 << shift;
            let result = align_down(value, alignment).unwrap();
            prop_assert!(result <= value);
            prop_assert!(value - result < alignment);
            prop_assert_eq!(result % alignment, 0);
        }

        #[test]
        fn proptest_align_up_ge_input(
            value in 0_u64..=(u64::MAX - (1_u64 << 31)),
            shift in 0_u32..32,
        ) {
            let alignment = 1_u64 << shift;
            if let Some(result) = align_up(value, alignment) {
                prop_assert!(result >= value);
                prop_assert!(result - value < alignment);
                prop_assert_eq!(result % alignment, 0);
            }
        }

        #[test]
        fn proptest_align_down_up_bracket(
            value in 0_u64..=(u64::MAX - (1_u64 << 31)),
            shift in 0_u32..32,
        ) {
            let alignment = 1_u64 << shift;
            let down = align_down(value, alignment).unwrap();
            if let Some(up) = align_up(value, alignment) {
                prop_assert!(down <= value);
                prop_assert!(up >= value);
                prop_assert!(up - down <= alignment);
                if value % alignment == 0 {
                    prop_assert_eq!(down, up);
                } else {
                    prop_assert_eq!(up - down, alignment);
                }
            }
        }

        #[test]
        fn proptest_block_to_group_first_block_inverse(
            group_idx in 0_u32..1000,
            bpg in prop::sample::select(vec![8192_u32, 16384, 32768]),
            first_data in prop::sample::select(vec![0_u32, 1]),
        ) {
            let first_block = group_first_block(GroupNumber(group_idx), bpg, first_data).unwrap();
            let computed_group = block_to_group(first_block, bpg, first_data);
            prop_assert_eq!(computed_group, GroupNumber(group_idx));
        }

        #[test]
        fn proptest_inode_group_index_partition(
            ino in 1_u64..=100_000,
            ipg in prop::sample::select(vec![256_u32, 512, 1024, 2048, 8192]),
        ) {
            let group = inode_to_group(InodeNumber(ino), ipg);
            let index = inode_index_in_group(InodeNumber(ino), ipg);
            // Reconstruct: (group * ipg) + index + 1 == ino
            let reconstructed = u64::from(group.0) * u64::from(ipg) + u64::from(index) + 1;
            prop_assert_eq!(reconstructed, ino);
            prop_assert!(index < ipg);
        }

        // bd-vbrhh — BlockSize byte_to_block / block_to_byte roundtrip MR.
        // BlockSize unit converters are used throughout ffs_core / ffs_ondisk
        // for every read seek and write seek. The contract:
        //   byte_to_block(block_to_byte(block)) == block (when not overflowing)
        // A regression that swapped shift direction or used the wrong block-size
        // field would silently corrupt every byte↔block translation.
        #[test]
        fn proptest_block_size_block_byte_roundtrip(
            bs_log in 10_u32..=16,  // 1024..=65536 — valid BlockSize values
            block in 0_u64..=u64::from(u32::MAX),
        ) {
            let bs = BlockSize::new(1_u32 << bs_log).expect("valid block size");
            if let Some(byte_offset) = bs.block_to_byte(BlockNumber(block)) {
                let recovered = bs.byte_to_block(byte_offset);
                prop_assert_eq!(recovered, BlockNumber(block),
                    "block→byte→block roundtrip must recover original block");
            }
        }

        // bd-vbrhh — Truncation MR: for any byte offset, byte_to_block
        // truncates toward zero such that
        //   block_to_byte(byte_to_block(b)) <= b < block_to_byte(byte_to_block(b) + 1)
        // (when both sides don't overflow). Pins the truncation semantics
        // documented on byte_to_block.
        #[test]
        fn proptest_block_size_byte_to_block_truncation(
            bs_log in 10_u32..=16,
            byte_offset in 0_u64..=(1_u64 << 48),  // bounded so block_to_byte doesn't overflow
        ) {
            let bs = BlockSize::new(1_u32 << bs_log).expect("valid block size");
            let block = bs.byte_to_block(byte_offset);
            let block_byte_start = bs.block_to_byte(block).expect("no overflow under bound");
            prop_assert!(block_byte_start <= byte_offset);
            let next_byte_start = bs.block_to_byte(BlockNumber(block.0 + 1));
            if let Some(next) = next_byte_start {
                prop_assert!(byte_offset < next, "byte_offset must be strictly less than next block start");
            }
        }

        #[test]
        fn proptest_crc32c_seed_zero_equiv(data in prop::collection::vec(any::<u8>(), 0..256)) {
            let unseeded = crc32c(&data);
            let seeded = crc32c_append(0, &data);
            prop_assert_eq!(unseeded, seeded);
        }

        // bd-oviw2 — crc32c_append associativity proptest MR.
        // crc32c_append is the btrfs-side foundational CRC32C primitive
        // used by btrfs superblock checksum, tree block checksums, send
        // stream commands. Multi-region checksumming requires:
        //     crc32c_append(seed, a||b) == crc32c_append(crc32c_append(seed, a), b)
        // Sister ext4_chksum has bd-8pbjm pinning this property. A
        // regression that swapped crc32c_append for a non-associative
        // fold would silently corrupt every multi-region btrfs checksum.
        #[test]
        fn proptest_crc32c_append_associative_across_appends(
            seed in any::<u32>(),
            a in prop::collection::vec(any::<u8>(), 0..=256),
            b in prop::collection::vec(any::<u8>(), 0..=256),
        ) {
            let mut concat = Vec::with_capacity(a.len() + b.len());
            concat.extend_from_slice(&a);
            concat.extend_from_slice(&b);
            let direct = crc32c_append(seed, &concat);
            let two_hop = crc32c_append(crc32c_append(seed, &a), &b);
            prop_assert_eq!(direct, two_hop);
        }

        /// bd-oviw2 — Three-way associativity: catches regressions
        /// that subtly break chaining beyond the first hop.
        #[test]
        fn proptest_crc32c_append_associative_three_way(
            seed in any::<u32>(),
            a in prop::collection::vec(any::<u8>(), 0..=64),
            b in prop::collection::vec(any::<u8>(), 0..=64),
            c in prop::collection::vec(any::<u8>(), 0..=64),
        ) {
            let mut concat = Vec::with_capacity(a.len() + b.len() + c.len());
            concat.extend_from_slice(&a);
            concat.extend_from_slice(&b);
            concat.extend_from_slice(&c);
            let direct = crc32c_append(seed, &concat);
            let three_hop = crc32c_append(crc32c_append(crc32c_append(seed, &a), &b), &c);
            prop_assert_eq!(direct, three_hop);
        }

        #[test]
        fn proptest_device_id_uuid_roundtrip(raw in any::<[u8; 16]>()) {
            let id = DeviceId::from_uuid_bytes_be(raw);
            let back = id.to_uuid_bytes_be();
            prop_assert_eq!(raw, back);
        }

        #[test]
        fn proptest_ext4_inode_number_roundtrip(val in 0_u32..=u32::MAX) {
            let ext4 = Ext4InodeNumber(val);
            let canonical: InodeNumber = ext4.into();
            prop_assert_eq!(canonical.to_ext4().unwrap(), ext4);
        }

        #[test]
        fn proptest_ensure_slice_bounds(
            buf_len in 0_usize..=512,
            offset in 0_usize..=512,
            len in 0_usize..=512,
        ) {
            let buf = vec![0_u8; buf_len];
            let result = ensure_slice(&buf, offset, len);
            match offset.checked_add(len) {
                Some(end) if end <= buf_len => {
                    prop_assert!(result.is_ok());
                    prop_assert_eq!(result.unwrap().len(), len);
                }
                _ => {
                    prop_assert!(result.is_err());
                }
            }
        }

        /// ByteOffset::checked_add returns None on overflow, Some otherwise.
        #[test]
        fn proptest_byte_offset_checked_add(a in any::<u64>(), b in any::<u64>()) {
            let result = ByteOffset(a).checked_add(b);
            if let Some(sum) = a.checked_add(b) {
                prop_assert_eq!(result, Some(ByteOffset(sum)));
            } else {
                prop_assert_eq!(result, None);
            }
        }

        /// ByteOffset::checked_sub returns None on underflow, Some otherwise.
        #[test]
        fn proptest_byte_offset_checked_sub(a in any::<u64>(), b in any::<u64>()) {
            let result = ByteOffset(a).checked_sub(b);
            if let Some(diff) = a.checked_sub(b) {
                prop_assert_eq!(result, Some(ByteOffset(diff)));
            } else {
                prop_assert_eq!(result, None);
            }
        }

        /// BlockNumber::checked_add/sub roundtrip: add then sub returns original.
        #[test]
        fn proptest_block_number_add_sub_roundtrip(
            base in 0_u64..=(u64::MAX / 2),
            delta in 0_u64..=(u64::MAX / 2),
        ) {
            if let Some(sum) = BlockNumber(base).checked_add(delta) {
                let back = sum.checked_sub(delta);
                prop_assert_eq!(back, Some(BlockNumber(base)));
            }
        }

        /// BtrfsObjectId → InodeNumber → BtrfsObjectId roundtrip.
        #[test]
        fn proptest_btrfs_object_id_roundtrip(val in any::<u64>()) {
            let btrfs = BtrfsObjectId(val);
            let canonical: InodeNumber = btrfs.into();
            prop_assert_eq!(canonical.to_btrfs(), btrfs);
        }

        /// write_le_u16 → read_le_u16 roundtrip.
        #[test]
        fn proptest_read_write_le_u16_roundtrip(val in any::<u16>(), offset in 0_usize..100) {
            let mut buf = vec![0_u8; offset + 2];
            write_le_u16(&mut buf, offset, val);
            let read_back = read_le_u16(&buf, offset).unwrap();
            prop_assert_eq!(read_back, val);
        }

        /// write_le_u32 → read_le_u32 roundtrip.
        #[test]
        fn proptest_read_write_le_u32_roundtrip(val in any::<u32>(), offset in 0_usize..100) {
            let mut buf = vec![0_u8; offset + 4];
            write_le_u32(&mut buf, offset, val);
            let read_back = read_le_u32(&buf, offset).unwrap();
            prop_assert_eq!(read_back, val);
        }

        /// val.to_le_bytes() stamped at offset reads back equal via
        /// read_le_u64. Fills the u16/u32 → u64 asymmetry in this
        /// crate's proptest coverage (the project has no
        /// write_le_u64 helper, so the test stamps the bytes
        /// directly with the standard library).
        #[test]
        fn proptest_read_le_u64_roundtrip(val in any::<u64>(), offset in 0_usize..100) {
            let mut buf = vec![0_u8; offset + 8];
            buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
            let read_back = read_le_u64(&buf, offset).unwrap();
            prop_assert_eq!(read_back, val);
        }

        /// read_le_u64 is deterministic: same (data, offset) yields
        /// the same Result.
        #[test]
        fn proptest_read_le_u64_is_deterministic(
            data in prop::collection::vec(any::<u8>(), 0..256),
            offset in 0_usize..256,
        ) {
            let a = read_le_u64(&data, offset).map_err(|e| e.to_string());
            let b = read_le_u64(&data, offset).map_err(|e| e.to_string());
            prop_assert_eq!(a, b);
        }

        /// Any 8-byte read whose end exceeds the slice length is
        /// rejected with InsufficientData carrying needed=8.
        #[test]
        fn proptest_read_le_u64_rejects_short(
            data in prop::collection::vec(any::<u8>(), 0..16),
            extra in 0_usize..8,
        ) {
            // Pick the smallest offset that places offset+8 just past
            // the end of the slice: short = data.len()-7..data.len()
            // are all out-of-range. Skip when data is too small to
            // form a non-degenerate test.
            prop_assume!(data.len() < 8 || extra > 0);
            let offset = data.len().saturating_sub(7).saturating_add(extra);
            let err = read_le_u64(&data, offset)
                .expect_err("short read must be rejected");
            prop_assert!(
                matches!(err, ParseError::InsufficientData { needed: 8, .. }),
                "expected InsufficientData {{ needed: 8 }}, got {:?}", err
            );
        }

        /// Reading at offset == usize::MAX overflows offset+8 and must
        /// be rejected with InvalidField (overflow), not panic.
        #[test]
        fn proptest_read_le_u64_offset_overflow_rejected(
            data in prop::collection::vec(any::<u8>(), 0..16),
        ) {
            let offset = usize::MAX - 4; // offset + 8 overflows usize
            let err = read_le_u64(&data, offset)
                .expect_err("offset overflow must be rejected");
            prop_assert!(
                matches!(err, ParseError::InvalidField { field: "offset", reason: "overflow" }),
                "expected InvalidField overflow, got {:?}", err
            );
        }

        /// ext4_block_size_from_log produces valid block sizes for log values 0..=6.
        #[test]
        fn proptest_ext4_block_size_from_log_valid(log_val in 0_u32..=6) {
            let bs = ext4_block_size_from_log(log_val);
            prop_assert!(bs.is_some());
            let size = bs.unwrap();
            prop_assert!(size.is_power_of_two());
            prop_assert_eq!(size, 1_u32 << (10 + log_val));
        }

        /// batch_checksum CRC32C matches individual crc32c_append results.
        #[test]
        fn proptest_batch_checksum_matches_scalar(
            seed in any::<u32>(),
            n_blocks in 1_usize..8,
            fill_byte in any::<u8>(),
        ) {
            let block_data: Vec<Vec<u8>> = (0..n_blocks)
                .map(|i| vec![fill_byte.wrapping_add(u8::try_from(i % 256).unwrap()); 64])
                .collect();
            let block_refs: Vec<&[u8]> = block_data.iter().map(Vec::as_slice).collect();
            let batch_result = batch_checksum(&block_refs, ChecksumAlgo::Crc32c { seed });
            let scalar_result: Vec<u32> = block_refs.iter().map(|b| crc32c_append(seed, b)).collect();
            prop_assert_eq!(batch_result, scalar_result);
        }

        /// bd-2ihe1 — batch_checksum Blake3 variant matches the public
        /// blake3_hash truncated-to-32 helper. The CRC32c branch above
        /// was the only proptest-covered variant; this closes the gap
        /// on the Blake3Truncated32 dispatch arm. A regression that
        /// dropped the explicit-le truncation step (e.g., switched to
        /// big-endian bytes or used the wrong 4-byte window) would
        /// silently corrupt every Blake3-mode batch checksum.
        #[test]
        fn proptest_batch_checksum_blake3_matches_scalar(
            n_blocks in 1_usize..8,
            fill_byte in any::<u8>(),
            block_len in 1_usize..=128,
        ) {
            let block_data: Vec<Vec<u8>> = (0..n_blocks)
                .map(|i| vec![fill_byte.wrapping_add(u8::try_from(i % 256).unwrap()); block_len])
                .collect();
            let block_refs: Vec<&[u8]> = block_data.iter().map(Vec::as_slice).collect();
            let batch_result = batch_checksum(&block_refs, ChecksumAlgo::Blake3Truncated32);
            let scalar_result: Vec<u32> = block_refs
                .iter()
                .map(|b| {
                    let hash = blake3_hash(b);
                    let bytes = hash.as_bytes();
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                })
                .collect();
            prop_assert_eq!(batch_result, scalar_result);
        }

        /// trim_nul_padded on a string without NUL bytes preserves the string.
        #[test]
        fn proptest_trim_nul_padded_no_nul(
            s in "[a-zA-Z0-9]{0,32}",
        ) {
            let bytes = s.as_bytes();
            let result = trim_nul_padded(bytes);
            prop_assert_eq!(result, s.trim());
        }

        // ── S_IS* predicate metamorphic relations (bd-0636l) ─────────

        /// MR-A — Mask isolation: every S_IS* predicate ignores the
        /// lower 12 bits (permissions / sticky / setuid / setgid).
        /// `predicate(mode) == predicate(mode & S_IFMT)` for any u16.
        /// Pins that the mask is correctly applied at every callsite.
        #[test]
        fn proptest_s_is_predicates_mask_isolation(mode in any::<u16>()) {
            let mode_masked = mode & S_IFMT;
            prop_assert_eq!(is_regular_file(mode), is_regular_file(mode_masked));
            prop_assert_eq!(is_directory(mode), is_directory(mode_masked));
            prop_assert_eq!(is_symlink(mode), is_symlink(mode_masked));
            prop_assert_eq!(is_character_device(mode), is_character_device(mode_masked));
            prop_assert_eq!(is_block_device(mode), is_block_device(mode_masked));
            prop_assert_eq!(is_fifo(mode), is_fifo(mode_masked));
            prop_assert_eq!(is_socket(mode), is_socket(mode_masked));
        }

        /// MR-B — Mutual exclusivity: for any u16, AT MOST ONE
        /// predicate returns true. A regression that changed `==`
        /// to `&` or `|` in any predicate would fail this MR.
        #[test]
        fn proptest_s_is_predicates_mutually_exclusive(mode in any::<u16>()) {
            let count = u32::from(is_regular_file(mode))
                + u32::from(is_directory(mode))
                + u32::from(is_symlink(mode))
                + u32::from(is_character_device(mode))
                + u32::from(is_block_device(mode))
                + u32::from(is_fifo(mode))
                + u32::from(is_socket(mode));
            prop_assert!(count <= 1, "at most one S_IS* predicate may return true");
        }

        /// MR-C — Total coverage on canonical S_IF* values: any mode
        /// whose top 4 bits match a defined S_IF* constant satisfies
        /// EXACTLY ONE predicate; any other mode satisfies NONE.
        /// Sentinel test: the kernel reserves only the 7 listed type
        /// fields (010..0140 in octal); other patterns in the upper
        /// nibble (e.g. S_IFMT itself = 0o170_000) must NOT classify.
        #[test]
        fn proptest_s_is_predicates_total_coverage(mode in any::<u16>()) {
            let masked = mode & S_IFMT;
            let count = u32::from(is_regular_file(mode))
                + u32::from(is_directory(mode))
                + u32::from(is_symlink(mode))
                + u32::from(is_character_device(mode))
                + u32::from(is_block_device(mode))
                + u32::from(is_fifo(mode))
                + u32::from(is_socket(mode));
            // Mode is in the canonical S_IF* set if and only if
            // exactly one predicate returns true.
            let in_canonical = matches!(
                masked,
                S_IFREG | S_IFDIR | S_IFLNK | S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK
            );
            if in_canonical {
                prop_assert_eq!(count, 1);
            } else {
                prop_assert_eq!(count, 0);
            }
        }

        // bd-jk3wp — Metamorphic relations for ext4_block_size_from_log,
        // the log->size mapping used by every parser that reads or
        // writes ext4 blocks. The function computes 1 << (10 + log).

        /// MR1 — Determinism: same input always yields the same Some/None.
        #[test]
        fn proptest_ext4_block_size_from_log_is_deterministic(log in any::<u32>()) {
            prop_assert_eq!(
                ext4_block_size_from_log(log),
                ext4_block_size_from_log(log)
            );
        }

        /// MR2 — Result is power-of-2: every Some(s) value satisfies
        /// s.is_power_of_two().
        #[test]
        fn proptest_ext4_block_size_from_log_is_power_of_two(log in any::<u32>()) {
            if let Some(size) = ext4_block_size_from_log(log) {
                prop_assert!(
                    size.is_power_of_two(),
                    "block size {size} for log={log} must be a power of 2"
                );
            }
        }

        /// MR3 — Lower bound: the smallest valid result is 1024 (log=0)
        /// — this is EXT4_MIN_BLOCK_SIZE per the kernel.
        #[test]
        fn proptest_ext4_block_size_from_log_minimum_is_1024(log in 0_u32..=21) {
            let size = ext4_block_size_from_log(log).expect("log <= 21 must produce Some");
            prop_assert!(
                size >= 1024,
                "block size {size} for log={log} must be >= 1024"
            );
        }

        /// MR4 — Doubling: from_log(log+1) == 2 * from_log(log) when both
        /// fit in u32. A regression that swapped left-shift for right-shift
        /// or biased the shift constant breaks this.
        #[test]
        fn proptest_ext4_block_size_from_log_doubles(log in 0_u32..=20) {
            let size = ext4_block_size_from_log(log).expect("log <= 20 must produce Some");
            let next = ext4_block_size_from_log(log + 1).expect("log <= 20 doubles cleanly");
            prop_assert_eq!(
                next,
                size.checked_mul(2).expect("doubling must not overflow"),
                "from_log(log+1) must equal 2 * from_log(log)"
            );
        }

        /// MR5 — Overflow boundary: log == 22 produces None because
        /// 1 << (10 + 22) overflows u32. Pin the exact boundary so an
        /// off-by-one in the overflow check fails immediately.
        #[test]
        fn proptest_ext4_block_size_from_log_overflows_at_22(log in 22_u32..=u32::MAX) {
            prop_assert_eq!(
                ext4_block_size_from_log(log),
                None,
                "log >= 22 must overflow and return None"
            );
        }

        /// MR6 — Inverse round-trip: for a Some(s) result, the log of
        /// the block size in bits, minus 10, recovers the original log.
        /// A shift bias regression (e.g., 9 instead of 10) breaks this.
        #[test]
        fn proptest_ext4_block_size_from_log_inverse_roundtrip(log in 0_u32..=21) {
            let size = ext4_block_size_from_log(log).expect("log <= 21 must produce Some");
            let recovered = size.trailing_zeros() - 10;
            prop_assert_eq!(recovered, log, "log recovery must round-trip");
        }
    }

    #[test]
    fn mount_mode_default_is_compat() {
        assert_eq!(MountMode::default(), MountMode::Compat);
    }

    #[test]
    fn mount_mode_predicates() {
        assert!(MountMode::Compat.is_compat());
        assert!(!MountMode::Compat.is_native());
        assert!(MountMode::Native.is_native());
        assert!(!MountMode::Native.is_compat());
    }

    #[test]
    fn mount_mode_display() {
        assert_eq!(format!("{}", MountMode::Compat), "compat");
        assert_eq!(format!("{}", MountMode::Native), "native");
    }

    // ── TxnId and CommitSeq coverage ────────────────────────────────────

    #[test]
    fn txn_id_ordering() {
        assert!(TxnId(1) < TxnId(2));
        assert_eq!(TxnId(42), TxnId(42));
        assert_ne!(TxnId(1), TxnId(2));
    }

    #[test]
    fn txn_id_zero_and_max() {
        let zero = TxnId(0);
        let max = TxnId(u64::MAX);
        assert!(zero < max);
        assert_eq!(zero.0, 0);
        assert_eq!(max.0, u64::MAX);
    }

    #[test]
    fn txn_id_hash_and_debug() {
        const TXN_ID_DEBUG_GOLDEN: &str = "TxnId(42)";

        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(TxnId(1));
        set.insert(TxnId(2));
        set.insert(TxnId(1));
        assert_eq!(set.len(), 2);
        assert_eq!(format!("{:?}", TxnId(42)), TXN_ID_DEBUG_GOLDEN);
    }

    #[test]
    fn commit_seq_ordering() {
        assert!(CommitSeq(0) < CommitSeq(1));
        assert_eq!(CommitSeq(100), CommitSeq(100));
    }

    #[test]
    fn commit_seq_zero_and_max() {
        let zero = CommitSeq(0);
        let max = CommitSeq(u64::MAX);
        assert!(zero < max);
        assert_eq!(max.0, u64::MAX);
    }

    #[test]
    fn commit_seq_hash_and_debug() {
        const COMMIT_SEQ_DEBUG_GOLDEN: &str = "CommitSeq(99)";

        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(CommitSeq(10));
        set.insert(CommitSeq(20));
        assert_eq!(set.len(), 2);
        assert_eq!(format!("{:?}", CommitSeq(99)), COMMIT_SEQ_DEBUG_GOLDEN);
    }

    #[test]
    fn snapshot_with_commit_seq() {
        let snap = Snapshot {
            high: CommitSeq(42),
        };
        assert_eq!(snap.high, CommitSeq(42));
        let snap2 = snap;
        assert_eq!(snap, snap2);
    }

    // ── Generation newtype ──────────────────────────────────────────────

    #[test]
    fn generation_ordering_and_display() {
        assert!(Generation(1) < Generation(2));
        assert_eq!(format!("{}", Generation(42)), "42");
    }

    // ── GroupNumber coverage ────────────────────────────────────────────

    #[test]
    fn group_number_ordering_and_display() {
        assert!(GroupNumber(0) < GroupNumber(1));
        assert_eq!(format!("{}", GroupNumber(7)), "7");
    }

    #[test]
    fn group_number_max_value() {
        let g = GroupNumber(u32::MAX);
        assert_eq!(g.0, u32::MAX);
    }

    // ── BlockNumber additional coverage ─────────────────────────────────

    #[test]
    fn block_number_to_u32_max() {
        let bn = BlockNumber(u64::from(u32::MAX));
        assert_eq!(bn.to_u32().unwrap(), u32::MAX);
    }

    #[test]
    fn block_number_to_u32_overflow() {
        let bn = BlockNumber(u64::from(u32::MAX) + 1);
        assert!(bn.to_u32().is_err());
    }

    #[test]
    fn block_number_display() {
        assert_eq!(format!("{}", BlockNumber(123)), "123");
    }

    // ── ByteOffset additional coverage ──────────────────────────────────

    #[test]
    fn byte_offset_checked_mul_overflow() {
        let big = ByteOffset(u64::MAX);
        assert_eq!(big.checked_mul(2), None);
    }

    #[test]
    fn byte_offset_align_down_zero_alignment() {
        let off = ByteOffset(100);
        assert_eq!(off.align_down(0), None);
    }

    #[test]
    fn byte_offset_align_up_zero_alignment() {
        let off = ByteOffset(100);
        assert_eq!(off.align_up(0), None);
    }

    #[test]
    fn byte_offset_align_already_aligned() {
        let off = ByteOffset(4096);
        assert_eq!(off.align_down(4096), Some(ByteOffset(4096)));
        assert_eq!(off.align_up(4096), Some(ByteOffset(4096)));
    }

    // ── Ext4InodeNumber / BtrfsObjectId ─────────────────────────────────

    #[test]
    fn ext4_inode_number_display() {
        assert_eq!(format!("{}", Ext4InodeNumber(2)), "2");
    }

    #[test]
    fn btrfs_object_id_display() {
        assert_eq!(format!("{}", BtrfsObjectId(256)), "256");
    }

    #[test]
    fn btrfs_object_id_to_canonical_preserves_value() {
        let oid = BtrfsObjectId(999);
        let canonical = oid.to_canonical();
        assert_eq!(canonical, InodeNumber(999));
    }

    // ── DeviceId additional coverage ────────────────────────────────────

    #[test]
    fn device_id_max_value() {
        let d = DeviceId(u128::MAX);
        let bytes = d.to_uuid_bytes_be();
        let roundtrip = DeviceId::from_uuid_bytes_be(bytes);
        assert_eq!(d, roundtrip);
    }

    // ── ChecksumAlgo coverage ───────────────────────────────────────────

    #[test]
    fn checksum_algo_crc32c_seed_varies() {
        let a1 = ChecksumAlgo::Crc32c { seed: 0 };
        let a2 = ChecksumAlgo::Crc32c { seed: 42 };
        assert_ne!(a1, a2);
    }

    #[test]
    fn checksum_algo_blake3_eq() {
        let b1 = ChecksumAlgo::Blake3Truncated32;
        let b2 = ChecksumAlgo::Blake3Truncated32;
        assert_eq!(b1, b2);
    }

    // ── inode_index_in_group edge case ──────────────────────────────────

    #[test]
    fn inode_index_in_group_first_inode() {
        // Inode 1 in group with 128 inodes_per_group
        let idx = inode_index_in_group(InodeNumber(1), 128);
        assert_eq!(idx, 0);
    }

    #[test]
    fn inode_index_in_group_last_in_group() {
        let idx = inode_index_in_group(InodeNumber(128), 128);
        assert_eq!(idx, 127);
    }
    #[test]
    fn inode_index_in_group_first_of_next_group() {
        let idx = inode_index_in_group(InodeNumber(129), 128);
        assert_eq!(idx, 0);
    }

    /// bd-tyeic — Kernel-conformance pin for the 27 ext4 inode-flag
    /// constants (EXT4_*_FL) declared in `fs/ext4/ext4.h`. Each flag
    /// is a single-bit value in `inode.i_flags`; the parser reads
    /// these to determine inode behaviour (immutable, append-only,
    /// extents-on, htree-index, casefold, etc.).
    ///
    /// A regression that swapped, e.g., EXT4_INDEX_FL (0x1000) and
    /// EXT4_EXTENTS_FL (0x80000) would silently treat htree-indexed
    /// directories as extent-tree-using files and vice versa — both
    /// fatal misclassifications. This test pins each value AND two
    /// structural invariants: (1) every flag is a single power-of-2
    /// bit, (2) no two flags share a bit (pairwise AND is zero).
    #[test]
    fn ext4_inode_flag_constants_match_kernel_header() {
        // Values per fs/ext4/ext4.h (bits in `i_flags`).
        assert_eq!(EXT4_SECRM_FL, 0x0000_0001);
        assert_eq!(EXT4_UNRM_FL, 0x0000_0002);
        assert_eq!(EXT4_COMPR_FL, 0x0000_0004);
        assert_eq!(EXT4_SYNC_FL, 0x0000_0008);
        assert_eq!(EXT4_IMMUTABLE_FL, 0x0000_0010);
        assert_eq!(EXT4_APPEND_FL, 0x0000_0020);
        assert_eq!(EXT4_NODUMP_FL, 0x0000_0040);
        assert_eq!(EXT4_NOATIME_FL, 0x0000_0080);
        assert_eq!(EXT4_COMPRBLK_FL, 0x0000_0200);
        assert_eq!(EXT4_NOCOMPR_FL, 0x0000_0400);
        assert_eq!(EXT4_ECOMPR_FL, 0x0000_0800);
        assert_eq!(EXT4_INDEX_FL, 0x0000_1000);
        assert_eq!(EXT4_IMAGIC_FL, 0x0000_2000);
        assert_eq!(EXT4_JOURNAL_DATA_FL, 0x0000_4000);
        assert_eq!(EXT4_NOTAIL_FL, 0x0000_8000);
        assert_eq!(EXT4_DIRSYNC_FL, 0x0001_0000);
        assert_eq!(EXT4_TOPDIR_FL, 0x0002_0000);
        assert_eq!(EXT4_HUGE_FILE_FL, 0x0004_0000);
        assert_eq!(EXT4_EXTENTS_FL, 0x0008_0000);
        assert_eq!(EXT4_EA_INODE_FL, 0x0020_0000);
        assert_eq!(EXT4_EOFBLOCKS_FL, 0x0040_0000);
        assert_eq!(EXT4_SNAPFILE_FL, 0x0100_0000);
        assert_eq!(EXT4_SNAPFILE_DELETED_FL, 0x0400_0000);
        assert_eq!(EXT4_SNAPFILE_SHRUNK_FL, 0x0800_0000);
        assert_eq!(EXT4_INLINE_DATA_FL, 0x1000_0000);
        assert_eq!(EXT4_PROJINHERIT_FL, 0x2000_0000);
        assert_eq!(EXT4_CASEFOLD_FL, 0x4000_0000);

        // Invariant 1: every flag is a single power-of-2 bit.
        let flags = [
            EXT4_SECRM_FL,
            EXT4_UNRM_FL,
            EXT4_COMPR_FL,
            EXT4_SYNC_FL,
            EXT4_IMMUTABLE_FL,
            EXT4_APPEND_FL,
            EXT4_NODUMP_FL,
            EXT4_NOATIME_FL,
            EXT4_COMPRBLK_FL,
            EXT4_NOCOMPR_FL,
            EXT4_ECOMPR_FL,
            EXT4_INDEX_FL,
            EXT4_IMAGIC_FL,
            EXT4_JOURNAL_DATA_FL,
            EXT4_NOTAIL_FL,
            EXT4_DIRSYNC_FL,
            EXT4_TOPDIR_FL,
            EXT4_HUGE_FILE_FL,
            EXT4_EXTENTS_FL,
            EXT4_EA_INODE_FL,
            EXT4_EOFBLOCKS_FL,
            EXT4_SNAPFILE_FL,
            EXT4_SNAPFILE_DELETED_FL,
            EXT4_SNAPFILE_SHRUNK_FL,
            EXT4_INLINE_DATA_FL,
            EXT4_PROJINHERIT_FL,
            EXT4_CASEFOLD_FL,
        ];
        for &flag in &flags {
            assert!(
                flag.is_power_of_two(),
                "EXT4_*_FL value {flag:#x} must be a single power-of-2 bit"
            );
        }

        // Invariant 2: no two flags share a bit (pairwise AND zero).
        // Total bits: 27 distinct powers of 2.
        for (i, &a) in flags.iter().enumerate() {
            for &b in &flags[i + 1..] {
                assert_eq!(
                    a & b,
                    0,
                    "EXT4_*_FL constants {a:#x} and {b:#x} must not share a bit"
                );
            }
        }

        // Cross-check: OR of all 27 flags has exactly 27 bits set.
        let or_all: u32 = flags.iter().fold(0_u32, |acc, &f| acc | f);
        assert_eq!(
            or_all.count_ones() as usize,
            flags.len(),
            "OR of all EXT4_*_FL constants must have exactly {} bits set",
            flags.len()
        );
    }

    /// bd-2ktji — Kernel-conformance pin for the POSIX S_IF*
    /// file-mode constant **integer values** per `<sys/stat.h>`.
    ///
    /// bd-vnfhb verifies the PREDICATE behavior but not the
    /// underlying integer values — the predicates are defined as
    /// `mode & S_IFMT == S_IFREG` (tautological), so a regression
    /// that changed S_IFREG from 0o100_000 to 0o050_000 would
    /// still pass bd-vnfhb and would silently misclassify every
    /// file across the FUSE / ext4 / btrfs layers. Pin each value
    /// AND the S_IFMT mask invariants directly.
    #[test]
    fn posix_s_if_constant_values_match_sys_stat_h() {
        // Per <sys/stat.h>:
        //   #define S_IFMT  0170000
        //   #define S_IFIFO 0010000  (named pipe)
        //   #define S_IFCHR 0020000  (character device)
        //   #define S_IFDIR 0040000  (directory)
        //   #define S_IFBLK 0060000  (block device)
        //   #define S_IFREG 0100000  (regular file)
        //   #define S_IFLNK 0120000  (symbolic link)
        //   #define S_IFSOCK 0140000 (socket)
        assert_eq!(S_IFMT, 0o170_000, "S_IFMT must equal 0o170_000");
        assert_eq!(S_IFIFO, 0o010_000, "S_IFIFO must equal 0o010_000");
        assert_eq!(S_IFCHR, 0o020_000, "S_IFCHR must equal 0o020_000");
        assert_eq!(S_IFDIR, 0o040_000, "S_IFDIR must equal 0o040_000");
        assert_eq!(S_IFBLK, 0o060_000, "S_IFBLK must equal 0o060_000");
        assert_eq!(S_IFREG, 0o100_000, "S_IFREG must equal 0o100_000");
        assert_eq!(S_IFLNK, 0o120_000, "S_IFLNK must equal 0o120_000");
        assert_eq!(S_IFSOCK, 0o140_000, "S_IFSOCK must equal 0o140_000");

        // Mask invariants: every S_IF* value is a subset of S_IFMT,
        // and the lower 12 bits (permissions) are zero in each S_IF*
        // constant.
        for (name, value) in [
            ("S_IFIFO", S_IFIFO),
            ("S_IFCHR", S_IFCHR),
            ("S_IFDIR", S_IFDIR),
            ("S_IFBLK", S_IFBLK),
            ("S_IFREG", S_IFREG),
            ("S_IFLNK", S_IFLNK),
            ("S_IFSOCK", S_IFSOCK),
        ] {
            assert_eq!(
                value & !S_IFMT,
                0,
                "{name} ({value:#o}) must have no bits outside S_IFMT mask"
            );
            assert_ne!(value, 0, "{name} must be non-zero");
        }

        // Pairwise distinct under the mask: no two S_IF* values
        // collide. (They occupy distinct nibbles in the 0o0X0_000
        // position; this assertion catches any future renumbering.)
        let values: [(u16, &str); 7] = [
            (S_IFIFO, "S_IFIFO"),
            (S_IFCHR, "S_IFCHR"),
            (S_IFDIR, "S_IFDIR"),
            (S_IFBLK, "S_IFBLK"),
            (S_IFREG, "S_IFREG"),
            (S_IFLNK, "S_IFLNK"),
            (S_IFSOCK, "S_IFSOCK"),
        ];
        for i in 0..values.len() {
            for j in (i + 1)..values.len() {
                assert_ne!(
                    values[i].0, values[j].0,
                    "{} and {} must not collide",
                    values[i].1, values[j].1
                );
            }
        }
    }

    /// bd-vnfhb — Kernel-conformance pin for the seven POSIX file-mode
    /// predicates that mirror `<sys/stat.h>`'s S_ISREG / S_ISDIR /
    /// S_ISLNK / S_ISCHR / S_ISBLK / S_ISFIFO / S_ISSOCK macros.
    ///
    /// A regression that flipped the mask sense (e.g., `&` to `|`) or
    /// dropped the `& S_IFMT` would silently misclassify every file
    /// kind. Each predicate is exercised against the corresponding
    /// S_IF* constant AND every other constant — to verify mutually-
    /// exclusive classification, every mode must satisfy EXACTLY ONE
    /// S_IS* predicate, not zero, not two.
    #[test]
    fn posix_file_mode_predicates_match_kernel_macros() {
        // Each constant must satisfy its corresponding predicate.
        assert!(is_regular_file(S_IFREG));
        assert!(is_directory(S_IFDIR));
        assert!(is_symlink(S_IFLNK));
        assert!(is_character_device(S_IFCHR));
        assert!(is_block_device(S_IFBLK));
        assert!(is_fifo(S_IFIFO));
        assert!(is_socket(S_IFSOCK));

        // Predicates honor the S_IFMT mask: lower 12 bits (permissions
        // and sticky/setuid/setgid) must NOT influence classification.
        // Use 0o7777 to set every permission/sticky bit.
        assert!(is_regular_file(S_IFREG | 0o7777));
        assert!(is_directory(S_IFDIR | 0o7777));
        assert!(is_symlink(S_IFLNK | 0o7777));
        assert!(is_character_device(S_IFCHR | 0o7777));
        assert!(is_block_device(S_IFBLK | 0o7777));
        assert!(is_fifo(S_IFIFO | 0o7777));
        assert!(is_socket(S_IFSOCK | 0o7777));

        // Mutually-exclusive classification: every S_IF* constant
        // satisfies EXACTLY ONE predicate.
        let preds: [(u16, [bool; 7]); 7] = [
            // (mode, [is_reg, is_dir, is_sym, is_chr, is_blk, is_fifo, is_sock])
            (S_IFREG, [true, false, false, false, false, false, false]),
            (S_IFDIR, [false, true, false, false, false, false, false]),
            (S_IFLNK, [false, false, true, false, false, false, false]),
            (S_IFCHR, [false, false, false, true, false, false, false]),
            (S_IFBLK, [false, false, false, false, true, false, false]),
            (S_IFIFO, [false, false, false, false, false, true, false]),
            (S_IFSOCK, [false, false, false, false, false, false, true]),
        ];
        for (mode, expected) in preds {
            assert_eq!(
                [
                    is_regular_file(mode),
                    is_directory(mode),
                    is_symlink(mode),
                    is_character_device(mode),
                    is_block_device(mode),
                    is_fifo(mode),
                    is_socket(mode),
                ],
                expected,
                "mode {mode:#o} must satisfy exactly one S_IS* predicate"
            );
            // Sanity: exactly one true in the expected vector.
            assert_eq!(
                expected.iter().filter(|x| **x).count(),
                1,
                "test setup error: expected vector for mode {mode:#o} must have exactly one true"
            );
        }

        // The S_IFMT mask itself (a synthesised mode with no file-type
        // bits set after masking) must NOT match any predicate.
        // mode=0 → 0 & S_IFMT == 0 ≠ any S_IF* constant.
        let zero = 0_u16;
        assert!(!is_regular_file(zero));
        assert!(!is_directory(zero));
        assert!(!is_symlink(zero));
        assert!(!is_character_device(zero));
        assert!(!is_block_device(zero));
        assert!(!is_fifo(zero));
        assert!(!is_socket(zero));
    }

    /// bd-xhswi — Kernel-conformance pin for the btrfs checksum-type
    /// constants declared in `fs/btrfs/btrfs_tree.h`. The btrfs
    /// superblock parser uses these for checksum dispatch via
    /// `validate_supported_csum_type` (crates/ffs-ondisk/src/btrfs.rs).
    /// A regression that swapped, e.g., BTRFS_CSUM_TYPE_CRC32C (0) and
    /// BTRFS_CSUM_TYPE_XXHASH64 (1) would make the parser silently
    /// reject every CRC32C image and masquerade-accept every xxhash64
    /// image — both fatal contracts. This test pins each value plus
    /// the contiguous strict-monotonic ordering 0..=3.
    #[test]
    fn btrfs_csum_type_constants_match_kernel_header() {
        // Values per fs/btrfs/btrfs_tree.h:
        //   #define BTRFS_CSUM_TYPE_CRC32      0
        //   #define BTRFS_CSUM_TYPE_XXHASH     1
        //   #define BTRFS_CSUM_TYPE_SHA256     2
        //   #define BTRFS_CSUM_TYPE_BLAKE2     3
        assert_eq!(BTRFS_CSUM_TYPE_CRC32C, 0);
        assert_eq!(BTRFS_CSUM_TYPE_XXHASH64, 1);
        assert_eq!(BTRFS_CSUM_TYPE_SHA256, 2);
        assert_eq!(BTRFS_CSUM_TYPE_BLAKE2B, 3);

        // Strict-monotonic ascending across the 4-element set —
        // catches any future renumbering that would silently misroute
        // checksum dispatch.
        let csum_type_order = [
            BTRFS_CSUM_TYPE_CRC32C,
            BTRFS_CSUM_TYPE_XXHASH64,
            BTRFS_CSUM_TYPE_SHA256,
            BTRFS_CSUM_TYPE_BLAKE2B,
        ];
        assert!(
            csum_type_order.windows(2).all(|pair| pair[0] < pair[1]),
            "btrfs csum-type constants must be strict-monotonic ascending"
        );

        // Contiguous range invariant: max - min == 3 (no gaps).
        assert_eq!(
            BTRFS_CSUM_TYPE_BLAKE2B - BTRFS_CSUM_TYPE_CRC32C,
            3,
            "the btrfs csum-type range must be contiguous 0..=3"
        );
    }

    /// bd-63e4e — Kernel-conformance pin for the ext4 + btrfs
    /// superblock layout constants. Each value determines where on
    /// disk the parser looks for the superblock and what byte-level
    /// magic it must find. Drift in any value would silently fail
    /// every mount of every image — yet each constant has NO test
    /// pinning it to a canonical kernel value.
    ///
    /// Pairs with bd-jbilz (EXT4_SUPER_MAGIC + ext4 state flags),
    /// bd-xhswi (BTRFS_CSUM_TYPE_*), bd-pvbgz (btrfs struct sizes),
    /// bd-6uu7j (chunk_type flags) — those pin scalar / struct
    /// constants; this pins the **layout offsets** that determine
    /// the byte address of every superblock and checksum field.
    #[test]
    fn ext4_btrfs_layout_constants_match_kernel_header() {
        // ext4 layout per fs/ext4/ext4.h:
        //   #define EXT4_MIN_BLOCK_SIZE  1024
        //   the ext4 superblock starts 1024 bytes from device start
        //   regardless of block size, sized at sizeof(struct
        //   ext4_super_block) = 1024 bytes.
        assert_eq!(
            EXT4_SUPERBLOCK_OFFSET, 1024,
            "EXT4_SUPERBLOCK_OFFSET must equal kernel value 1024"
        );
        assert_eq!(
            EXT4_SUPERBLOCK_SIZE, 1024,
            "EXT4_SUPERBLOCK_SIZE must equal sizeof(struct ext4_super_block) = 1024"
        );
        assert_eq!(
            EXT4_SECTOR_SIZE, 512,
            "EXT4_SECTOR_SIZE must equal kernel logical sector size 512"
        );
        // Kernel: u32 s_checksum is at offset 0x3FC (1020 decimal),
        // the LAST 4 bytes of the 1024-byte superblock.
        assert_eq!(
            EXT4_SB_CHECKSUM_OFFSET, 0x3FC,
            "EXT4_SB_CHECKSUM_OFFSET must equal kernel offset 0x3FC"
        );
        assert_eq!(
            EXT4_SB_CHECKSUM_OFFSET,
            EXT4_SUPERBLOCK_SIZE - 4,
            "EXT4_SB_CHECKSUM_OFFSET must be the last 4 bytes of the superblock"
        );

        // btrfs layout per fs/btrfs/disk-io.h:
        //   #define BTRFS_SUPER_INFO_OFFSET    SZ_64K
        //   #define BTRFS_SUPER_INFO_SIZE      4096
        //   #define BTRFS_MAGIC                0x4D5F53665248425FULL
        assert_eq!(
            BTRFS_SUPER_INFO_OFFSET,
            64 * 1024,
            "BTRFS_SUPER_INFO_OFFSET must equal kernel value SZ_64K (65536)"
        );
        assert_eq!(
            BTRFS_SUPER_INFO_SIZE, 4096,
            "BTRFS_SUPER_INFO_SIZE must equal sizeof(struct btrfs_super_block) = 4096"
        );
        assert_eq!(
            BTRFS_MAGIC, 0x4D5F_5366_5248_425F,
            "BTRFS_MAGIC must equal kernel value 0x4D5F53665248425F"
        );
        // Byte decomposition: BTRFS_MAGIC stored little-endian
        // gives the ASCII byte sequence "_BHRfS_M" — pin both the
        // bytes and the round-trip so a swapped-endian regression
        // fails immediately rather than at first mount.
        let magic_bytes: [u8; 8] = BTRFS_MAGIC.to_le_bytes();
        assert_eq!(
            &magic_bytes, b"_BHRfS_M",
            "BTRFS_MAGIC LE byte sequence must be \"_BHRfS_M\""
        );
        assert_eq!(
            u64::from_le_bytes(*b"_BHRfS_M"),
            BTRFS_MAGIC,
            "round-trip: from_le_bytes(\"_BHRfS_M\") must reproduce BTRFS_MAGIC"
        );
    }

    /// bd-wa27v — Kernel-conformance pin for EXT4_XATTR_MAGIC + the 10
    /// EXT4_XATTR_INDEX_* constants per fs/ext4/xattr.h. The index byte
    /// is the high-byte of e_name_index in every ext4 xattr entry and
    /// determines the namespace prefix (user. / trusted. / security. /
    /// system. / lustre.) prepended on getxattr/listxattr. A regression
    /// that drifted any index by ±1 would silently mis-route trusted
    /// attributes as security attributes (or vice versa), corrupting
    /// every xattr round-trip. EXT4_XATTR_MAGIC is the first 4 bytes
    /// of every ext4 xattr block — a magic drift breaks every parse.
    ///
    /// Sister kernel-pin tests: ext4_btrfs_layout_constants_match_kernel_header,
    /// btrfs_csum_type_constants_match_kernel_header,
    /// ext4_inode_flag_constants_match_kernel_header,
    /// posix_s_if_constant_values_match_sys_stat_h.
    #[test]
    fn ext4_xattr_constants_match_xattr_h() {
        // Per fs/ext4/xattr.h:
        //   #define EXT4_XATTR_MAGIC          0xEA020000
        //   #define EXT4_XATTR_INDEX_USER     1
        //   #define EXT4_XATTR_INDEX_POSIX_ACL_ACCESS  2
        //   #define EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT 3
        //   #define EXT4_XATTR_INDEX_TRUSTED  4
        //   #define EXT4_XATTR_INDEX_LUSTRE   5
        //   #define EXT4_XATTR_INDEX_SECURITY 6
        //   #define EXT4_XATTR_INDEX_SYSTEM   7
        //   #define EXT4_XATTR_INDEX_RICHACL  8
        //   #define EXT4_XATTR_INDEX_ENCRYPTION 9
        //   #define EXT4_XATTR_INDEX_HURD     10
        assert_eq!(
            EXT4_XATTR_MAGIC, 0xEA02_0000,
            "EXT4_XATTR_MAGIC must equal kernel value 0xEA020000"
        );
        // LE byte sequence: 00 00 02 EA — pin the byte order so an
        // endian-flip regression fails immediately rather than at
        // first xattr block parse.
        let magic_bytes: [u8; 4] = EXT4_XATTR_MAGIC.to_le_bytes();
        assert_eq!(
            magic_bytes,
            [0x00, 0x00, 0x02, 0xEA],
            "EXT4_XATTR_MAGIC LE byte sequence must be [00, 00, 02, EA]"
        );

        // Index values: each constant pinned to its kernel integer.
        let indices: &[(&str, u8, u8)] = &[
            ("EXT4_XATTR_INDEX_USER", EXT4_XATTR_INDEX_USER, 1),
            (
                "EXT4_XATTR_INDEX_POSIX_ACL_ACCESS",
                EXT4_XATTR_INDEX_POSIX_ACL_ACCESS,
                2,
            ),
            (
                "EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT",
                EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT,
                3,
            ),
            ("EXT4_XATTR_INDEX_TRUSTED", EXT4_XATTR_INDEX_TRUSTED, 4),
            ("EXT4_XATTR_INDEX_LUSTRE", EXT4_XATTR_INDEX_LUSTRE, 5),
            ("EXT4_XATTR_INDEX_SECURITY", EXT4_XATTR_INDEX_SECURITY, 6),
            ("EXT4_XATTR_INDEX_SYSTEM", EXT4_XATTR_INDEX_SYSTEM, 7),
            ("EXT4_XATTR_INDEX_RICHACL", EXT4_XATTR_INDEX_RICHACL, 8),
            (
                "EXT4_XATTR_INDEX_ENCRYPTION",
                EXT4_XATTR_INDEX_ENCRYPTION,
                9,
            ),
            ("EXT4_XATTR_INDEX_HURD", EXT4_XATTR_INDEX_HURD, 10),
        ];
        for (name, actual, expected) in indices {
            assert_eq!(
                actual, expected,
                "{name} must equal kernel value {expected}"
            );
        }

        // Pairwise distinctness: every namespace must map to a unique
        // index byte. A future regression that aliased two namespaces
        // would route both to the same prefix string.
        let values: Vec<u8> = indices.iter().map(|&(_, v, _)| v).collect();
        let mut sorted = values.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            values.len(),
            sorted.len(),
            "EXT4_XATTR_INDEX_* values must be pairwise distinct"
        );
    }
}
