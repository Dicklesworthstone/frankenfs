//! Repair symbol format and storage types.
//!
//! Defines the on-disk layout for RaptorQ repair symbols stored at the end of
//! each block group. The format follows the design in
//! `COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md` §3.7 (Repair Symbol Storage) and
//! §3.4 (Object Transmission Information).
//!
//! # Layout
//!
//! Within each block group, repair blocks occupy a reserved range at the end:
//!
//! ```text
//! ┌────────────────────────┬──────────────────┬─────────────────────┐
//! │  data blocks (K)       │ validation blocks│  repair blocks (R)  │
//! │  (file data + metadata)│ (BLAKE3 digests) │  (RaptorQ symbols)  │
//! └────────────────────────┴──────────────────┴─────────────────────┘
//! ```
//!
//! Each repair block starts with a [`RepairBlockHeader`] followed by symbol
//! payload data. The group descriptor extension ([`RepairGroupDescExt`])
//! records the OTI and block range for the repair region.

use ffs_types::{BlockNumber, GroupNumber};

// ── Magic constants ─────────────────────────────────────────────────────────

/// Magic bytes for `RepairBlockHeader` — "RQSB" (RaptorQ Symbol Block).
pub const REPAIR_BLOCK_MAGIC: u32 = 0x5251_5342;

/// Magic bytes for `RepairGroupDescExt` — "RQRF" (RaptorQ Repair Format).
pub const REPAIR_GROUP_DESC_MAGIC: u32 = 0x5251_5246;

// ── RepairBlockHeader ───────────────────────────────────────────────────────

/// On-disk header for a repair symbol block.
///
/// Each repair block within a block group starts with this 32-byte header
/// followed by `symbol_count * symbol_size` bytes of encoded symbol payload.
///
/// ```text
/// Offset  Size  Field
/// 0       4     magic (0x52515342 = "RQSB")
/// 4       4     first_esi — encoding symbol ID of the first symbol in this block
/// 8       2     symbol_count — number of symbols packed in this block
/// 10      2     symbol_size — bytes per symbol (matches OTI T)
/// 12      4     block_group — which group this block belongs to
/// 16      8     repair_generation — monotonic generation counter
/// 24      4     checksum — CRC32C of bytes [0..24]
/// 28      4     reserved (zero)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairBlockHeader {
    /// Encoding symbol ID of the first symbol in this block.
    pub first_esi: u32,
    /// Number of symbols packed in this block.
    pub symbol_count: u16,
    /// Bytes per symbol (matches OTI T field).
    pub symbol_size: u16,
    /// Block group this repair block belongs to.
    pub block_group: GroupNumber,
    /// Monotonic generation counter. Increments only after a full symbol
    /// refresh completes for this group.
    pub repair_generation: u64,
    /// CRC32C checksum of the header bytes [0..24].
    pub checksum: u32,
}

impl RepairBlockHeader {
    /// Serialized size of the header in bytes.
    pub const SIZE: usize = 32;

    /// Serialize the header to a 32-byte buffer.
    ///
    /// Computes the CRC32C checksum over the first 24 bytes and writes it
    /// at offset 24.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0_u8; Self::SIZE];
        buf[0..4].copy_from_slice(&REPAIR_BLOCK_MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&self.first_esi.to_le_bytes());
        buf[8..10].copy_from_slice(&self.symbol_count.to_le_bytes());
        buf[10..12].copy_from_slice(&self.symbol_size.to_le_bytes());
        buf[12..16].copy_from_slice(&self.block_group.0.to_le_bytes());
        buf[16..24].copy_from_slice(&self.repair_generation.to_le_bytes());
        let crc = crc32c::crc32c(&buf[..24]);
        buf[24..28].copy_from_slice(&crc.to_le_bytes());
        // buf[28..32] remains zero (reserved)
        buf
    }

    /// Parse a header from a 32-byte slice.
    ///
    /// Validates magic number and CRC32C checksum.
    pub fn parse(data: &[u8]) -> Result<Self, RepairParseError> {
        if data.len() < Self::SIZE {
            return Err(RepairParseError::InsufficientData {
                needed: Self::SIZE,
                actual: data.len(),
            });
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != REPAIR_BLOCK_MAGIC {
            return Err(RepairParseError::BadMagic {
                expected: REPAIR_BLOCK_MAGIC,
                actual: magic,
            });
        }

        let first_esi = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let symbol_count = u16::from_le_bytes([data[8], data[9]]);
        let symbol_size = u16::from_le_bytes([data[10], data[11]]);
        let block_group = GroupNumber(u32::from_le_bytes([data[12], data[13], data[14], data[15]]));
        let repair_generation = u64::from_le_bytes([
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]);
        let stored_checksum = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);

        let computed_checksum = crc32c::crc32c(&data[..24]);
        if stored_checksum != computed_checksum {
            return Err(RepairParseError::ChecksumMismatch {
                stored: stored_checksum,
                computed: computed_checksum,
            });
        }

        Ok(Self {
            first_esi,
            symbol_count,
            symbol_size,
            block_group,
            repair_generation,
            checksum: stored_checksum,
        })
    }

    /// Total payload size: `symbol_count * symbol_size` bytes.
    #[must_use]
    pub fn payload_size(&self) -> usize {
        usize::from(self.symbol_count) * usize::from(self.symbol_size)
    }
}

// ── RepairGroupDescExt ──────────────────────────────────────────────────────

/// Extension to the group descriptor that records repair metadata for a group.
///
/// This is stored alongside the standard ext4 group descriptor (or in a
/// FrankenFS-native metadata area) and provides the Object Transmission
/// Information (OTI) plus repair block locations.
///
/// ```text
/// Offset  Size  Field
/// 0       4     magic (0x52515246 = "RQRF")
/// 4       8     transfer_length (F) — total source bytes
/// 12      2     symbol_size (T) — bytes per encoding symbol
/// 14      2     source_block_count_z (Z) — number of source blocks
/// 16      2     sub_blocks (N) — sub-block partitioning count
/// 18      2     symbol_alignment (Al) — alignment in bytes (typically 4)
/// 20      8     repair_start_block — first repair block in the group
/// 28      4     repair_block_count — number of repair blocks
/// 32      8     repair_generation — current generation counter
/// 40      4     checksum — CRC32C of bytes [0..40]
/// 44      4     reserved (zero)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairGroupDescExt {
    /// Total source data length in bytes (OTI F field).
    pub transfer_length: u64,
    /// Symbol size in bytes (OTI T field).
    pub symbol_size: u16,
    /// Number of source blocks (OTI Z field).
    pub source_block_count: u16,
    /// Sub-block partitioning count (OTI N field).
    pub sub_blocks: u16,
    /// Symbol alignment in bytes (OTI Al field, typically 4).
    pub symbol_alignment: u16,
    /// First repair block within this group (absolute block number).
    pub repair_start_block: BlockNumber,
    /// Number of repair blocks in this group.
    pub repair_block_count: u32,
    /// Monotonic generation counter for this group's repair symbols.
    pub repair_generation: u64,
    /// CRC32C checksum of the descriptor extension.
    pub checksum: u32,
}

impl RepairGroupDescExt {
    /// Serialized size of the descriptor extension in bytes.
    pub const SIZE: usize = 48;

    /// Serialize to a 48-byte buffer.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0_u8; Self::SIZE];
        buf[0..4].copy_from_slice(&REPAIR_GROUP_DESC_MAGIC.to_le_bytes());
        buf[4..12].copy_from_slice(&self.transfer_length.to_le_bytes());
        buf[12..14].copy_from_slice(&self.symbol_size.to_le_bytes());
        buf[14..16].copy_from_slice(&self.source_block_count.to_le_bytes());
        buf[16..18].copy_from_slice(&self.sub_blocks.to_le_bytes());
        buf[18..20].copy_from_slice(&self.symbol_alignment.to_le_bytes());
        buf[20..28].copy_from_slice(&self.repair_start_block.0.to_le_bytes());
        buf[28..32].copy_from_slice(&self.repair_block_count.to_le_bytes());
        buf[32..40].copy_from_slice(&self.repair_generation.to_le_bytes());
        let crc = crc32c::crc32c(&buf[..40]);
        buf[40..44].copy_from_slice(&crc.to_le_bytes());
        // buf[44..48] remains zero (reserved)
        buf
    }

    /// Parse from a 48-byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, RepairParseError> {
        if data.len() < Self::SIZE {
            return Err(RepairParseError::InsufficientData {
                needed: Self::SIZE,
                actual: data.len(),
            });
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != REPAIR_GROUP_DESC_MAGIC {
            return Err(RepairParseError::BadMagic {
                expected: REPAIR_GROUP_DESC_MAGIC,
                actual: magic,
            });
        }

        let transfer_length = u64::from_le_bytes([
            data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
        ]);
        let symbol_size = u16::from_le_bytes([data[12], data[13]]);
        let source_block_count = u16::from_le_bytes([data[14], data[15]]);
        let sub_blocks = u16::from_le_bytes([data[16], data[17]]);
        let symbol_alignment = u16::from_le_bytes([data[18], data[19]]);
        let repair_start_block = BlockNumber(u64::from_le_bytes([
            data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27],
        ]));
        let repair_block_count = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
        let repair_generation = u64::from_le_bytes([
            data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
        ]);
        let stored_checksum = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);

        let computed_checksum = crc32c::crc32c(&data[..40]);
        if stored_checksum != computed_checksum {
            return Err(RepairParseError::ChecksumMismatch {
                stored: stored_checksum,
                computed: computed_checksum,
            });
        }

        Ok(Self {
            transfer_length,
            symbol_size,
            source_block_count,
            sub_blocks,
            symbol_alignment,
            repair_start_block,
            repair_block_count,
            repair_generation,
            checksum: stored_checksum,
        })
    }

    /// Compute the repair block count for a given source block count and
    /// overhead ratio.
    ///
    /// `overhead_ratio` must be >= 1.0; the repair block count is
    /// `ceil(source_blocks * (overhead_ratio - 1.0))`.
    #[must_use]
    pub fn compute_repair_block_count(source_blocks: u32, overhead_ratio: f64) -> u32 {
        let extra = f64::from(source_blocks) * (overhead_ratio - 1.0);
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "extra is clamped to [0, u32::MAX] range"
        )]
        {
            extra.ceil().max(0.0).min(f64::from(u32::MAX)) as u32
        }
    }
}

// ── SymbolDigest ────────────────────────────────────────────────────────────

/// Per-symbol integrity digest used in decode proofs.
///
/// Associates an encoding symbol ID (ESI) with its BLAKE3 hash for
/// auditable repair verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolDigest {
    /// Encoding Symbol Identifier.
    pub esi: u32,
    /// BLAKE3 hash of the symbol payload.
    pub digest: [u8; 32],
}

impl SymbolDigest {
    /// Serialized size: 4 (ESI) + 32 (BLAKE3) = 36 bytes.
    pub const SIZE: usize = 36;

    /// Serialize to a 36-byte buffer.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0_u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.esi.to_le_bytes());
        buf[4..36].copy_from_slice(&self.digest);
        buf
    }

    /// Parse from a 36-byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, RepairParseError> {
        if data.len() < Self::SIZE {
            return Err(RepairParseError::InsufficientData {
                needed: Self::SIZE,
                actual: data.len(),
            });
        }
        let esi = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&data[4..36]);
        Ok(Self { esi, digest })
    }
}

// ── Seed derivation ─────────────────────────────────────────────────────────

/// Derive the deterministic repair seed for a given filesystem UUID and group.
///
/// Ensures that independent agents (scrub daemon, manual repair) generate
/// identical symbols for the same group.
///
/// Formula: `blake3("ffs:repair:seed:v1" || fs_uuid || group.to_le_bytes())[0..8]`
#[must_use]
pub fn repair_seed(fs_uuid: &[u8; 16], group: GroupNumber) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ffs:repair:seed:v1");
    hasher.update(fs_uuid);
    hasher.update(&group.0.to_le_bytes());
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors from parsing repair symbol structures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairParseError {
    /// Not enough data to parse the structure.
    InsufficientData { needed: usize, actual: usize },
    /// Magic number does not match expected value.
    BadMagic { expected: u32, actual: u32 },
    /// CRC32C checksum mismatch.
    ChecksumMismatch { stored: u32, computed: u32 },
}

impl std::fmt::Display for RepairParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientData { needed, actual } => {
                write!(f, "insufficient data: need {needed} bytes, got {actual}")
            }
            Self::BadMagic { expected, actual } => {
                write!(
                    f,
                    "bad magic: expected {expected:#010x}, got {actual:#010x}"
                )
            }
            Self::ChecksumMismatch { stored, computed } => {
                write!(
                    f,
                    "checksum mismatch: stored {stored:#010x}, computed {computed:#010x}"
                )
            }
        }
    }
}

impl std::error::Error for RepairParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_block_header_round_trip() {
        let header = RepairBlockHeader {
            first_esi: 100,
            symbol_count: 50,
            symbol_size: 256,
            block_group: GroupNumber(3),
            repair_generation: 42,
            checksum: 0, // will be computed
        };
        let bytes = header.to_bytes();
        let parsed = RepairBlockHeader::parse(&bytes).expect("parse");
        assert_eq!(parsed.first_esi, 100);
        assert_eq!(parsed.symbol_count, 50);
        assert_eq!(parsed.symbol_size, 256);
        assert_eq!(parsed.block_group, GroupNumber(3));
        assert_eq!(parsed.repair_generation, 42);
    }

    #[test]
    fn repair_block_header_bad_magic() {
        let mut bytes = [0_u8; RepairBlockHeader::SIZE];
        bytes[0..4].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        let err = RepairBlockHeader::parse(&bytes).unwrap_err();
        assert!(matches!(err, RepairParseError::BadMagic { .. }));
    }

    #[test]
    fn repair_block_header_checksum_mismatch() {
        let header = RepairBlockHeader {
            first_esi: 0,
            symbol_count: 10,
            symbol_size: 128,
            block_group: GroupNumber(0),
            repair_generation: 1,
            checksum: 0,
        };
        let mut bytes = header.to_bytes();
        // Corrupt a payload byte
        bytes[5] ^= 0xFF;
        let err = RepairBlockHeader::parse(&bytes).unwrap_err();
        assert!(matches!(err, RepairParseError::ChecksumMismatch { .. }));
    }

    #[test]
    fn repair_block_header_insufficient_data() {
        let err = RepairBlockHeader::parse(&[0; 16]).unwrap_err();
        assert!(matches!(
            err,
            RepairParseError::InsufficientData {
                needed: 32,
                actual: 16
            }
        ));
    }

    #[test]
    fn repair_group_desc_ext_round_trip() {
        let desc = RepairGroupDescExt {
            transfer_length: 128 * 1024 * 1024,
            symbol_size: 256,
            source_block_count: 32768,
            sub_blocks: 1,
            symbol_alignment: 4,
            repair_start_block: BlockNumber(31000),
            repair_block_count: 1639,
            repair_generation: 7,
            checksum: 0,
        };
        let bytes = desc.to_bytes();
        let parsed = RepairGroupDescExt::parse(&bytes).expect("parse");
        assert_eq!(parsed.transfer_length, 128 * 1024 * 1024);
        assert_eq!(parsed.symbol_size, 256);
        assert_eq!(parsed.source_block_count, 32768);
        assert_eq!(parsed.sub_blocks, 1);
        assert_eq!(parsed.symbol_alignment, 4);
        assert_eq!(parsed.repair_start_block, BlockNumber(31000));
        assert_eq!(parsed.repair_block_count, 1639);
        assert_eq!(parsed.repair_generation, 7);
    }

    #[test]
    fn repair_group_desc_ext_bad_magic() {
        let mut bytes = [0_u8; RepairGroupDescExt::SIZE];
        bytes[0..4].copy_from_slice(&0xBAD0_CAFE_u32.to_le_bytes());
        let err = RepairGroupDescExt::parse(&bytes).unwrap_err();
        assert!(matches!(err, RepairParseError::BadMagic { .. }));
    }

    #[test]
    fn symbol_digest_round_trip() {
        let digest = SymbolDigest {
            esi: 42,
            digest: [0xAB; 32],
        };
        let bytes = digest.to_bytes();
        let parsed = SymbolDigest::parse(&bytes).expect("parse");
        assert_eq!(parsed.esi, 42);
        assert_eq!(parsed.digest, [0xAB; 32]);
    }

    #[test]
    fn compute_repair_block_count_standard() {
        // 5% overhead on 32K source blocks = ceil(32768 * 0.05) = 1639
        assert_eq!(
            RepairGroupDescExt::compute_repair_block_count(32768, 1.05),
            1639
        );
        // 1% overhead on 32K = ceil(32768 * 0.01) = 328
        assert_eq!(
            RepairGroupDescExt::compute_repair_block_count(32768, 1.01),
            328
        );
        // 10% overhead on 32K = ceil(32768 * 0.10) = 3277
        assert_eq!(
            RepairGroupDescExt::compute_repair_block_count(32768, 1.10),
            3277
        );
    }

    #[test]
    fn compute_repair_block_count_small_group() {
        // Tail group with 100 blocks at 5%: f64 rounding gives ceil(5.00..004) = 6
        assert_eq!(RepairGroupDescExt::compute_repair_block_count(100, 1.05), 6);
        // Very small: 4 blocks at 5% = ceil(0.2) = 1
        assert_eq!(RepairGroupDescExt::compute_repair_block_count(4, 1.05), 1);
    }

    #[test]
    fn repair_seed_deterministic() {
        let uuid = [1_u8; 16];
        let seed1 = repair_seed(&uuid, GroupNumber(0));
        let seed2 = repair_seed(&uuid, GroupNumber(0));
        assert_eq!(seed1, seed2, "same inputs must produce same seed");

        let seed_other_group = repair_seed(&uuid, GroupNumber(1));
        assert_ne!(
            seed1, seed_other_group,
            "different groups should produce different seeds"
        );

        let other_uuid = [2_u8; 16];
        let seed_other_uuid = repair_seed(&other_uuid, GroupNumber(0));
        assert_ne!(
            seed1, seed_other_uuid,
            "different UUIDs should produce different seeds"
        );
    }

    #[test]
    fn repair_block_header_payload_size() {
        let header = RepairBlockHeader {
            first_esi: 0,
            symbol_count: 16,
            symbol_size: 256,
            block_group: GroupNumber(0),
            repair_generation: 0,
            checksum: 0,
        };
        assert_eq!(header.payload_size(), 16 * 256);
    }

    #[test]
    fn magic_constants_are_correct() {
        // "RQSB" in ASCII
        assert_eq!(
            &REPAIR_BLOCK_MAGIC.to_le_bytes(),
            b"BSQR", // LE representation of 0x52515342
        );
        // "RQRF" in ASCII
        assert_eq!(
            &REPAIR_GROUP_DESC_MAGIC.to_le_bytes(),
            b"FRQR", // LE representation of 0x52515246
        );
    }
}
