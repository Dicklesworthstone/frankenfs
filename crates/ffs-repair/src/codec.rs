//! RaptorQ encode/decode workflow for filesystem block groups.
//!
//! Bridges the `asupersync` RaptorQ codec (systematic encoder + inactivation
//! decoder) with the FrankenFS block layer. Each block group's data blocks are
//! treated as source symbols; repair symbols are generated deterministically
//! and can reconstruct any missing/corrupt blocks given sufficient redundancy.
//!
//! # Encode flow
//!
//! ```text
//! source blocks ──► SystematicEncoder ──► repair symbols + metadata
//! ```
//!
//! # Decode flow
//!
//! ```text
//! available blocks + repair symbols ──► InactivationDecoder ──► recovered blocks + proof
//! ```

use asupersync::Cx;
use asupersync::raptorq::decoder::{
    DecodeError, DecodeResult, InactivationDecoder, ReceivedSymbol,
};
use asupersync::raptorq::systematic::{EmittedSymbol, SystematicEncoder};
use ffs_block::BlockDevice;
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, GroupNumber};

use crate::symbol::repair_seed;

const RQ_DECODE_WAVEFRONT_BATCH: usize = 4;

// ── Encode ──────────────────────────────────────────────────────────────────

/// Result of encoding repair symbols for a block group.
#[derive(Debug)]
pub struct EncodedGroup {
    /// Group number this encoding covers.
    pub group: GroupNumber,
    /// Number of source blocks (K).
    pub source_block_count: u32,
    /// Block size (symbol size) in bytes.
    pub symbol_size: u32,
    /// Seed used for deterministic encoding.
    pub seed: u64,
    /// Emitted repair symbols (ESI >= K).
    pub repair_symbols: Vec<EmittedSymbol>,
}

/// Encode repair symbols for a contiguous range of source blocks.
///
/// Reads `source_block_count` blocks starting at `first_block` from the device,
/// then generates `repair_count` repair symbols using the RaptorQ systematic
/// encoder. The seed is derived deterministically from `fs_uuid` and `group`.
///
/// # Errors
///
/// Returns `FfsError::Io` if block reads fail, or `FfsError::Corruption` if
/// the constraint matrix is singular (extremely unlikely for well-formed input).
pub fn encode_group(
    cx: &Cx,
    device: &dyn BlockDevice,
    fs_uuid: &[u8; 16],
    group: GroupNumber,
    first_block: BlockNumber,
    source_block_count: u32,
    repair_count: u32,
) -> Result<EncodedGroup> {
    let block_size = device.block_size();
    let seed = repair_seed(fs_uuid, group);

    // Read source blocks into symbol buffers.
    let mut source_symbols: Vec<Vec<u8>> = Vec::with_capacity(source_block_count as usize);
    for i in 0..u64::from(source_block_count) {
        let block_num = BlockNumber(first_block.0.checked_add(i).ok_or_else(|| {
            FfsError::RepairFailed(format!(
                "encode_group: block address overflow at first_block={} + offset={i}",
                first_block.0
            ))
        })?);
        let buf = device.read_block(cx, block_num)?;
        source_symbols.push(buf.into_inner());
    }

    // Create systematic encoder.
    let mut encoder = SystematicEncoder::new(&source_symbols, block_size as usize, seed)
        .ok_or_else(|| {
            FfsError::RepairFailed(format!(
                "constraint matrix singular for group {} (K={source_block_count})",
                group.0
            ))
        })?;

    // Generate repair symbols.
    let repair_symbols = encoder.emit_repair(repair_count as usize);

    Ok(EncodedGroup {
        group,
        source_block_count,
        symbol_size: block_size,
        seed,
        repair_symbols,
    })
}

// ── Decode ──────────────────────────────────────────────────────────────────

/// A recovered block from the decode process.
#[derive(Debug, Clone)]
pub struct RecoveredBlock {
    /// The block number that was recovered.
    pub block: BlockNumber,
    /// The recovered data.
    pub data: Vec<u8>,
}

/// Result of attempting to decode/reconstruct corrupt blocks.
#[derive(Debug)]
pub struct DecodeOutcome {
    /// Successfully recovered blocks.
    pub recovered: Vec<RecoveredBlock>,
    /// Decode statistics from the RaptorQ decoder.
    pub stats: asupersync::raptorq::decoder::DecodeStats,
    /// Whether all requested corrupt blocks were recovered.
    pub complete: bool,
}

#[derive(Debug)]
struct CorruptIndexSet {
    unique: Vec<u32>,
}

impl CorruptIndexSet {
    fn new(indices: &[u32], source_block_count: u32, group: GroupNumber) -> Result<Self> {
        let mut unique = Vec::with_capacity(indices.len());
        for &idx in indices {
            if idx >= source_block_count {
                return Err(FfsError::RepairFailed(format!(
                    "decode_group: corrupt index {idx} out of range for group {} with {source_block_count} source blocks",
                    group.0
                )));
            }
            unique.push(idx);
        }
        unique.sort_unstable();
        unique.dedup();
        Ok(Self { unique })
    }

    fn len(&self) -> usize {
        self.unique.len()
    }

    fn contains(&self, index: u32) -> bool {
        self.unique.binary_search(&index).is_ok()
    }
}

enum RepairSymbolInput<'a> {
    Borrowed(&'a [(u32, Vec<u8>)]),
    Owned(Vec<(u32, Vec<u8>)>),
}

impl RepairSymbolInput<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Borrowed(symbols) => symbols.len(),
            Self::Owned(symbols) => symbols.len(),
        }
    }

    fn validate_lengths(&self, block_size: usize, group: GroupNumber) -> Result<()> {
        match self {
            Self::Borrowed(symbols) => {
                validate_repair_symbol_lengths(symbols.iter(), block_size, group)
            }
            Self::Owned(symbols) => {
                validate_repair_symbol_lengths(symbols.iter(), block_size, group)
            }
        }
    }
}

fn validate_repair_symbol_lengths<'a>(
    symbols: impl Iterator<Item = &'a (u32, Vec<u8>)>,
    block_size: usize,
    group: GroupNumber,
) -> Result<()> {
    for (esi, data) in symbols {
        if data.len() != block_size {
            return Err(FfsError::RepairFailed(format!(
                "decode_group: repair symbol esi={esi} for group {} has payload length {} \
                 but device block_size is {block_size}; refusing to decode malformed symbol",
                group.0,
                data.len(),
            )));
        }
    }
    Ok(())
}

/// Attempt to reconstruct corrupt blocks using available source blocks and
/// repair symbols.
///
/// Reads all non-corrupt blocks from the device as source symbols, combines
/// them with the provided repair symbols, and feeds them to the inactivation
/// decoder. On success, returns the recovered data for each corrupt block.
///
/// # Arguments
///
/// * `cx` - Cancellation context.
/// * `device` - Block device to read non-corrupt blocks from.
/// * `fs_uuid` - Filesystem UUID for seed derivation.
/// * `group` - Block group number.
/// * `first_block` - First block number of the source range.
/// * `source_block_count` - Number of source blocks (K).
/// * `corrupt_indices` - Indices within the source range that are corrupt
///   (0-indexed relative to `first_block`). These blocks will NOT be read.
/// * `repair_symbols` - Available repair symbols as `(ESI, data)` pairs.
///
/// # Errors
///
/// Returns `FfsError::RepairFailed` if the decoder cannot recover all blocks
/// (insufficient redundancy). Returns `FfsError::Io` if non-corrupt block
/// reads fail.
#[allow(clippy::too_many_arguments)]
pub fn decode_group(
    cx: &Cx,
    device: &dyn BlockDevice,
    fs_uuid: &[u8; 16],
    group: GroupNumber,
    first_block: BlockNumber,
    source_block_count: u32,
    corrupt_indices: &[u32],
    repair_symbols: &[(u32, Vec<u8>)],
) -> Result<DecodeOutcome> {
    decode_group_impl(
        cx,
        device,
        fs_uuid,
        group,
        first_block,
        source_block_count,
        corrupt_indices,
        RepairSymbolInput::Borrowed(repair_symbols),
    )
}

/// Attempt to reconstruct corrupt blocks while taking ownership of loaded
/// repair-symbol payloads.
///
/// This is equivalent to [`decode_group`] but avoids cloning each repair symbol
/// into decoder inputs. Use it on recovery paths that read a fresh symbol batch
/// and do not need to retain that batch after decode.
///
/// # Errors
///
/// Returns the same errors as [`decode_group`].
#[allow(clippy::too_many_arguments)]
pub fn decode_group_with_owned_repair_symbols(
    cx: &Cx,
    device: &dyn BlockDevice,
    fs_uuid: &[u8; 16],
    group: GroupNumber,
    first_block: BlockNumber,
    source_block_count: u32,
    corrupt_indices: &[u32],
    repair_symbols: Vec<(u32, Vec<u8>)>,
) -> Result<DecodeOutcome> {
    decode_group_impl(
        cx,
        device,
        fs_uuid,
        group,
        first_block,
        source_block_count,
        corrupt_indices,
        RepairSymbolInput::Owned(repair_symbols),
    )
}

#[allow(clippy::too_many_arguments)]
fn decode_group_impl(
    cx: &Cx,
    device: &dyn BlockDevice,
    fs_uuid: &[u8; 16],
    group: GroupNumber,
    first_block: BlockNumber,
    source_block_count: u32,
    corrupt_indices: &[u32],
    repair_symbols: RepairSymbolInput<'_>,
) -> Result<DecodeOutcome> {
    let block_size = device.block_size() as usize;
    let k = source_block_count as usize;
    let seed = repair_seed(fs_uuid, group);

    if corrupt_indices.is_empty() {
        return Ok(DecodeOutcome {
            recovered: Vec::new(),
            stats: asupersync::raptorq::decoder::DecodeStats::default(),
            complete: true,
        });
    }

    let corrupt_set = CorruptIndexSet::new(corrupt_indices, source_block_count, group)?;
    if corrupt_set.len() >= source_block_count as usize && source_block_count > 0 {
        return Err(FfsError::RepairFailed(format!(
            "decode_group: group {} has no intact source blocks; refusing full reconstruction from repair symbols alone",
            group.0
        )));
    }
    // Feasibility check: a corrupt block can only be reconstructed if at
    // least one repair symbol contributes erasure-correcting information
    // for the missing slots. With more corrupt blocks than available repair
    // symbols, decode is mathematically hopeless and pushing the
    // InactivationDecoder through a guaranteed-failure case wastes 60+s
    // of CPU on inputs where libFuzzer mutated the symbol list down to
    // zero. Surface a fast, named error instead. (The decoder still does
    // its full constraint solve on the borderline case where the count
    // matches exactly; only the strictly-impossible case is short-circuited.)
    let repair_symbol_count = repair_symbols.len();
    if corrupt_set.len() > repair_symbol_count {
        return Err(FfsError::RepairFailed(format!(
            "decode_group: group {} has {} corrupt blocks but only {} repair symbols available; \
             insufficient redundancy",
            group.0,
            corrupt_set.len(),
            repair_symbol_count,
        )));
    }

    // Every repair symbol payload MUST be exactly block_size bytes — that is
    // the encode-side contract. Validate before reading intact source blocks so
    // malformed symbol bundles fail without wasting I/O or decoder setup.
    repair_symbols.validate_lengths(block_size, group)?;

    let decoder = InactivationDecoder::new(k, block_size, seed);

    // Start with constraint symbols (LDPC + HDPC with zero data).
    let mut received: Vec<ReceivedSymbol> = decoder.constraint_symbols();
    received.reserve(k.saturating_sub(corrupt_set.len()) + repair_symbol_count);

    // Add available (non-corrupt) source blocks.
    for i in 0..source_block_count {
        if corrupt_set.contains(i) {
            continue;
        }
        let block_num = BlockNumber(first_block.0.checked_add(u64::from(i)).ok_or_else(|| {
            FfsError::RepairFailed(format!(
                "decode_group: block address overflow at first_block={} + offset={i}",
                first_block.0
            ))
        })?);
        let buf = device.read_block(cx, block_num)?;
        received.push(ReceivedSymbol::source(i, buf.into_inner()));
    }

    // Add repair symbols with their equations.
    match repair_symbols {
        RepairSymbolInput::Borrowed(symbols) => {
            for (esi, data) in symbols {
                let (cols, coefs) = decoder.repair_equation(*esi).map_err(|error| {
                    FfsError::RepairFailed(format!(
                        "repair_equation failed for esi {} in group {}: {error:?}",
                        *esi, group.0
                    ))
                })?;
                received.push(ReceivedSymbol::repair(*esi, cols, coefs, data.clone()));
            }
        }
        RepairSymbolInput::Owned(symbols) => {
            for (esi, data) in symbols {
                let (cols, coefs) = decoder.repair_equation(esi).map_err(|error| {
                    FfsError::RepairFailed(format!(
                        "repair_equation failed for esi {esi} in group {}: {error:?}",
                        group.0
                    ))
                })?;
                received.push(ReceivedSymbol::repair(esi, cols, coefs, data));
            }
        }
    }

    // Attempt decode.
    let result: DecodeResult = decoder
        .decode_wavefront(&received, RQ_DECODE_WAVEFRONT_BATCH)
        .map_err(|error| match error {
            DecodeError::InsufficientSymbols { received, required } => {
                FfsError::RepairFailed(format!(
                    "insufficient symbols for group {}: have {received}, need {required}",
                    group.0
                ))
            }
            other => {
                FfsError::RepairFailed(format!("decode failed for group {}: {other:?}", group.0))
            }
        })?;

    // Extract recovered blocks for the corrupt indices.
    let mut recovered = Vec::with_capacity(corrupt_indices.len());
    for &idx in corrupt_indices {
        let block_num =
            BlockNumber(first_block.0.checked_add(u64::from(idx)).ok_or_else(|| {
                FfsError::RepairFailed(format!(
                    "decode_group: block address overflow at first_block={} + corrupt_idx={idx}",
                    first_block.0
                ))
            })?);
        if idx as usize >= result.source.len() {
            return Err(FfsError::RepairFailed(format!(
                "decode_group: corrupt index {idx} out of range (source has {} blocks)",
                result.source.len()
            )));
        }
        let data = result.source[idx as usize].clone();
        recovered.push(RecoveredBlock {
            block: block_num,
            data,
        });
    }

    Ok(DecodeOutcome {
        complete: recovered.len() == corrupt_indices.len(),
        recovered,
        stats: result.stats,
    })
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_block::BlockBuf;
    use ffs_types::BlockNumber;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// In-memory block device for testing.
    struct MemBlockDevice {
        blocks: Mutex<HashMap<u64, Vec<u8>>>,
        block_size: u32,
        block_count: u64,
        read_count: AtomicUsize,
    }

    impl MemBlockDevice {
        fn new(block_size: u32, block_count: u64) -> Self {
            Self {
                blocks: Mutex::new(HashMap::new()),
                block_size,
                block_count,
                read_count: AtomicUsize::new(0),
            }
        }

        fn write(&self, block: BlockNumber, data: Vec<u8>) {
            assert_eq!(data.len(), self.block_size as usize);
            self.blocks.lock().insert(block.0, data);
        }

        fn read_count(&self) -> usize {
            self.read_count.load(Ordering::Relaxed)
        }
    }

    impl BlockDevice for MemBlockDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            self.read_count.fetch_add(1, Ordering::Relaxed);
            let data = self
                .blocks
                .lock()
                .get(&block.0)
                .cloned()
                .unwrap_or_else(|| vec![0u8; self.block_size as usize]);
            Ok(BlockBuf::new(data))
        }

        fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            assert_eq!(data.len(), self.block_size as usize);
            self.blocks.lock().insert(block.0, data.to_vec());
            Ok(())
        }

        fn block_size(&self) -> u32 {
            self.block_size
        }

        fn block_count(&self) -> u64 {
            self.block_count
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    fn test_uuid() -> [u8; 16] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]
    }

    fn make_deterministic_block(index: u64, block_size: u32) -> Vec<u8> {
        (0..block_size as usize)
            .map(|j| {
                #[allow(clippy::cast_possible_truncation)]
                let byte = (index
                    .wrapping_mul(37)
                    .wrapping_add(j as u64)
                    .wrapping_mul(13)
                    .wrapping_add(7)
                    % 256) as u8;
                byte
            })
            .collect()
    }

    fn setup_device(k: u32, block_size: u32) -> MemBlockDevice {
        let device = MemBlockDevice::new(block_size, u64::from(k) * 2);
        for i in 0..u64::from(k) {
            device.write(BlockNumber(i), make_deterministic_block(i, block_size));
        }
        device
    }

    #[test]
    fn encode_produces_repair_symbols() {
        let cx = Cx::for_testing();
        let k = 8;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(0);

        let encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, 4)
            .expect("encode should succeed");

        assert_eq!(encoded.source_block_count, k);
        assert_eq!(encoded.symbol_size, block_size);
        assert_eq!(encoded.repair_symbols.len(), 4);
        for sym in &encoded.repair_symbols {
            assert!(!sym.is_source);
            assert_eq!(sym.data.len(), block_size as usize);
        }
    }

    #[test]
    fn encode_deterministic() {
        let cx = Cx::for_testing();
        let k = 8;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(0);

        let enc1 = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, 4).unwrap();
        let enc2 = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, 4).unwrap();

        for (s1, s2) in enc1.repair_symbols.iter().zip(enc2.repair_symbols.iter()) {
            assert_eq!(s1.esi, s2.esi);
            assert_eq!(s1.data, s2.data);
        }
    }

    #[test]
    fn decode_recovers_single_corrupt_block() {
        let cx = Cx::for_testing();
        let k = 8;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(0);

        // Encode to get repair symbols.
        let encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, k)
            .expect("encode should succeed");

        let repair_data: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .iter()
            .map(|s| (s.esi, s.data.clone()))
            .collect();

        // Corrupt block 3.
        let original = make_deterministic_block(3, block_size);

        // Decode — block 3 is marked corrupt and NOT read from device.
        let outcome = decode_group(
            &cx,
            &device,
            &uuid,
            group,
            BlockNumber(0),
            k,
            &[3],
            &repair_data,
        )
        .expect("decode should succeed");

        assert!(outcome.complete);
        assert_eq!(outcome.recovered.len(), 1);
        assert_eq!(outcome.recovered[0].block, BlockNumber(3));
        assert_eq!(outcome.recovered[0].data, original);
    }

    #[test]
    fn decode_owned_repair_symbols_recovers_single_corrupt_block() {
        let cx = Cx::for_testing();
        let k = 8;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(0);

        let encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, k)
            .expect("encode should succeed");
        let repair_data: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .into_iter()
            .map(|symbol| (symbol.esi, symbol.data))
            .collect();

        let original = make_deterministic_block(3, block_size);
        let outcome = decode_group_with_owned_repair_symbols(
            &cx,
            &device,
            &uuid,
            group,
            BlockNumber(0),
            k,
            &[3],
            repair_data,
        )
        .expect("decode should succeed");

        assert!(outcome.complete);
        assert_eq!(outcome.recovered.len(), 1);
        assert_eq!(outcome.recovered[0].block, BlockNumber(3));
        assert_eq!(outcome.recovered[0].data, original);
    }

    #[test]
    fn decode_duplicate_corrupt_indices_duplicate_recovered_output() {
        let cx = Cx::for_testing();
        let k = 8;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(0);

        let encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, k)
            .expect("encode should succeed");
        let repair_data: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .iter()
            .map(|s| (s.esi, s.data.clone()))
            .collect();

        let original = make_deterministic_block(3, block_size);
        let outcome = decode_group(
            &cx,
            &device,
            &uuid,
            group,
            BlockNumber(0),
            k,
            &[3, 3],
            &repair_data,
        )
        .expect("decode should succeed");

        assert!(outcome.complete);
        assert_eq!(outcome.recovered.len(), 2);
        assert_eq!(outcome.recovered[0].block, BlockNumber(3));
        assert_eq!(outcome.recovered[1].block, BlockNumber(3));
        assert_eq!(outcome.recovered[0].data, original);
        assert_eq!(outcome.recovered[1].data, outcome.recovered[0].data);
    }

    #[test]
    fn decode_recovers_multiple_corrupt_blocks() {
        let cx = Cx::for_testing();
        let k = 16;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(0);

        // Generate more repair symbols than corrupt blocks.
        let encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, k)
            .expect("encode should succeed");

        let repair_data: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .iter()
            .map(|s| (s.esi, s.data.clone()))
            .collect();

        // Corrupt blocks 0, 5, 10.
        let corrupt = [0, 5, 10];
        let originals: Vec<Vec<u8>> = corrupt
            .iter()
            .map(|&i| make_deterministic_block(u64::from(i), block_size))
            .collect();

        let outcome = decode_group(
            &cx,
            &device,
            &uuid,
            group,
            BlockNumber(0),
            k,
            &corrupt,
            &repair_data,
        )
        .expect("decode should succeed");

        assert!(outcome.complete);
        assert_eq!(outcome.recovered.len(), 3);
        for (i, recovered) in outcome.recovered.iter().enumerate() {
            assert_eq!(recovered.block, BlockNumber(u64::from(corrupt[i])));
            assert_eq!(
                recovered.data, originals[i],
                "block {} mismatch",
                corrupt[i]
            );
        }
    }

    #[test]
    fn decode_fails_with_insufficient_repair() {
        let cx = Cx::for_testing();
        let k = 8;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(0);

        // Only 1 repair symbol, but 4 corrupt blocks — not enough.
        let encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, 1)
            .expect("encode should succeed");

        let repair_data: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .iter()
            .map(|s| (s.esi, s.data.clone()))
            .collect();

        // Corrupt 4 blocks with only 1 repair symbol.
        let corrupt = [0, 1, 2, 3];
        let result = decode_group(
            &cx,
            &device,
            &uuid,
            group,
            BlockNumber(0),
            k,
            &corrupt,
            &repair_data,
        );

        let error = result.expect_err("decode must reject infeasible recovery");
        assert!(
            matches!(
                &error,
                FfsError::RepairFailed(msg)
                    if msg.contains("insufficient") || msg.contains("singular")
            ),
            "expected RepairFailed with insufficient/singular detail, got: {error:?}"
        );
    }

    /// Pin the upfront repair-symbol length-validation guard added in the
    /// fab3ff1 fix: a malformed repair symbol whose payload differs from
    /// device.block_size must surface a fast RepairFailed error rather than
    /// pushing the InactivationDecoder through pathological work.
    #[test]
    fn decode_rejects_malformed_repair_symbol_length() {
        let cx = Cx::for_testing();
        let k = 4;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(0);

        let encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, 2)
            .expect("encode should succeed");

        // Truncate the first repair symbol's payload to a wrong length.
        let mut repair_data: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .iter()
            .map(|s| (s.esi, s.data.clone()))
            .collect();
        repair_data[0].1.truncate(8); // 8 bytes instead of block_size=64

        let corrupt = [0_u32];
        let reads_before_decode = device.read_count();
        let result = decode_group(
            &cx,
            &device,
            &uuid,
            group,
            BlockNumber(0),
            k,
            &corrupt,
            &repair_data,
        );

        let error = result.expect_err("decode must reject malformed repair symbol length");
        assert!(
            matches!(
                &error,
                FfsError::RepairFailed(msg)
                    if msg.contains("malformed") || msg.contains("payload length")
            ),
            "expected RepairFailed about malformed payload, got: {error:?}"
        );
        assert_eq!(
            device.read_count(),
            reads_before_decode,
            "malformed repair symbol decode must fail before reading source blocks"
        );
    }

    #[test]
    fn decode_rejects_out_of_range_corrupt_index_without_reads() {
        let cx = Cx::for_testing();
        let k = 4;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(0);

        let reads_before_decode = device.read_count();
        let result = decode_group(&cx, &device, &uuid, group, BlockNumber(0), k, &[k], &[]);

        let error = result.expect_err("decode must reject out-of-range corrupt index");
        assert!(
            matches!(
                &error,
                FfsError::RepairFailed(msg)
                    if msg.contains("corrupt index") && msg.contains("out of range")
            ),
            "expected RepairFailed about corrupt index bounds, got: {error:?}"
        );
        assert_eq!(
            device.read_count(),
            reads_before_decode,
            "out-of-range corrupt index must fail before reading source blocks"
        );
    }

    #[test]
    fn encode_different_groups_produce_different_symbols() {
        let cx = Cx::for_testing();
        let k = 8;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();

        let enc_g0 =
            encode_group(&cx, &device, &uuid, GroupNumber(0), BlockNumber(0), k, 2).unwrap();
        let enc_g1 =
            encode_group(&cx, &device, &uuid, GroupNumber(1), BlockNumber(0), k, 2).unwrap();

        // Different groups must derive different seeds, even if emitted
        // symbols happen to coincide for identical source payloads.
        assert_ne!(
            enc_g0.seed, enc_g1.seed,
            "different groups should derive different RaptorQ seeds"
        );
    }

    #[test]
    fn decode_recovers_first_and_last_blocks() {
        let cx = Cx::for_testing();
        let k = 8;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(0);

        let encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, k).unwrap();
        let repair_data: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .iter()
            .map(|s| (s.esi, s.data.clone()))
            .collect();

        // Corrupt first and last blocks.
        let corrupt = [0, k - 1];
        let orig_first = make_deterministic_block(0, block_size);
        let orig_last = make_deterministic_block(u64::from(k - 1), block_size);

        let outcome = decode_group(
            &cx,
            &device,
            &uuid,
            group,
            BlockNumber(0),
            k,
            &corrupt,
            &repair_data,
        )
        .unwrap();

        assert!(outcome.complete);
        assert_eq!(outcome.recovered[0].data, orig_first);
        assert_eq!(outcome.recovered[1].data, orig_last);
    }

    #[test]
    fn decode_with_nonzero_first_block() {
        let cx = Cx::for_testing();
        let k = 8;
        let block_size = 64;
        // Place blocks starting at offset 100.
        let device = MemBlockDevice::new(block_size, 200);
        let first = BlockNumber(100);
        for i in 0..u64::from(k) {
            device.write(
                BlockNumber(first.0 + i),
                make_deterministic_block(i, block_size),
            );
        }

        let uuid = test_uuid();
        let group = GroupNumber(5);

        let encoded = encode_group(&cx, &device, &uuid, group, first, k, k).unwrap();
        let repair_data: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .iter()
            .map(|s| (s.esi, s.data.clone()))
            .collect();

        // Corrupt block at index 2 (absolute: BlockNumber(102)).
        let original = make_deterministic_block(2, block_size);
        let outcome =
            decode_group(&cx, &device, &uuid, group, first, k, &[2], &repair_data).unwrap();

        assert!(outcome.complete);
        assert_eq!(outcome.recovered[0].block, BlockNumber(102));
        assert_eq!(outcome.recovered[0].data, original);
    }

    #[test]
    fn decode_stats_populated() {
        let cx = Cx::for_testing();
        let k = 8;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(0);

        let encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, k).unwrap();
        let repair_data: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .iter()
            .map(|s| (s.esi, s.data.clone()))
            .collect();

        let outcome = decode_group(
            &cx,
            &device,
            &uuid,
            group,
            BlockNumber(0),
            k,
            &[1],
            &repair_data,
        )
        .unwrap();

        // At least some peeling or inactivation should occur.
        assert!(
            outcome.stats.peeled > 0 || outcome.stats.inactivated > 0,
            "decoder should perform some work"
        );
    }

    #[test]
    fn encode_zero_repair_symbols() {
        let cx = Cx::for_testing();
        let k = 4;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(0);

        let encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, 0).unwrap();
        assert!(encoded.repair_symbols.is_empty());
    }

    #[test]
    fn decode_no_corruption_succeeds() {
        let cx = Cx::for_testing();
        let k = 8;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(0);

        let encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, 4).unwrap();
        let repair_data: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .iter()
            .map(|s| (s.esi, s.data.clone()))
            .collect();

        // No corrupt blocks — trivially succeeds.
        let reads_before_decode = device.read_count();
        let outcome = decode_group(
            &cx,
            &device,
            &uuid,
            group,
            BlockNumber(0),
            k,
            &[],
            &repair_data,
        )
        .unwrap();

        assert!(outcome.complete);
        assert!(outcome.recovered.is_empty());
        assert_eq!(
            outcome.stats.peeled + outcome.stats.inactivated + outcome.stats.gauss_ops,
            0,
            "empty corruption decode must not enter the solver"
        );
        assert_eq!(
            device.read_count(),
            reads_before_decode,
            "empty corruption decode must not reread source blocks"
        );
    }

    // ── Property-based tests (proptest) ────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Encode → decode roundtrip: for any random source data with
        /// corruption_count ≤ repair_count, all corrupt blocks are recovered
        /// exactly.
        #[test]
        fn proptest_encode_decode_roundtrip(
            k in 4_u32..20,
            repair_extra in 0_u32..4,
            corrupt_count in 1_u32..4,
            fill_byte in any::<u8>(),
        ) {
            let cx = Cx::for_testing();
            let block_size = 64_u32;
            let repair_count = corrupt_count + repair_extra + 8;
            let actual_corrupt = corrupt_count.min(k);

            let device = MemBlockDevice::new(block_size, u64::from(k) * 2);
            for i in 0..u64::from(k) {
                let data: Vec<u8> = (0..block_size as usize)
                    .map(|j| fill_byte.wrapping_add(u8::try_from(i % 256).unwrap()).wrapping_add(u8::try_from(j % 256).unwrap()))
                    .collect();
                device.write(BlockNumber(i), data);
            }

            let uuid = test_uuid();
            let group = GroupNumber(0);

            let encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, repair_count)
                .expect("encode should succeed");

            let repair_data: Vec<(u32, Vec<u8>)> = encoded
                .repair_symbols
                .iter()
                .map(|s| (s.esi, s.data.clone()))
                .collect();

            // Corrupt the first `actual_corrupt` blocks.
            let corrupt_indices: Vec<u32> = (0..actual_corrupt).collect();
            let originals: Vec<Vec<u8>> = corrupt_indices
                .iter()
                .map(|&i| {
                    (0..block_size as usize)
                        .map(|j| fill_byte.wrapping_add(u8::try_from(u64::from(i) % 256).unwrap()).wrapping_add(u8::try_from(j % 256).unwrap()))
                        .collect()
                })
                .collect();

            let outcome = decode_group(
                &cx,
                &device,
                &uuid,
                group,
                BlockNumber(0),
                k,
                &corrupt_indices,
                &repair_data,
            )
            .expect("decode should succeed with sufficient repair symbols");

            prop_assert!(outcome.complete);
            prop_assert_eq!(outcome.recovered.len(), actual_corrupt as usize);
            for (i, recovered) in outcome.recovered.iter().enumerate() {
                prop_assert_eq!(
                    &recovered.data, &originals[i],
                    "block {} data mismatch", corrupt_indices[i]
                );
            }
        }

        /// Encoding is deterministic: same inputs always produce same repair
        /// symbols.
        #[test]
        fn proptest_encode_deterministic(
            k in 4_u32..16,
            repair_count in 1_u32..8,
            fill_byte in any::<u8>(),
            group_idx in 0_u32..100,
        ) {
            let cx = Cx::for_testing();
            let block_size = 64_u32;
            let device = MemBlockDevice::new(block_size, u64::from(k) * 2);
            for i in 0..u64::from(k) {
                let data: Vec<u8> = vec![fill_byte.wrapping_add(u8::try_from(i % 256).unwrap()); block_size as usize];
                device.write(BlockNumber(i), data);
            }

            let uuid = test_uuid();
            let group = GroupNumber(group_idx);

            let enc1 = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, repair_count)
                .expect("first encode should succeed");
            let enc2 = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, repair_count)
                .expect("second encode should succeed");

            prop_assert_eq!(enc1.repair_symbols.len(), enc2.repair_symbols.len());
            for (s1, s2) in enc1.repair_symbols.iter().zip(enc2.repair_symbols.iter()) {
                prop_assert_eq!(s1.esi, s2.esi);
                prop_assert_eq!(&s1.data, &s2.data);
            }
        }

        /// Different groups produce different seeds (and therefore different
        /// repair symbols) even with identical source data.
        #[test]
        fn proptest_different_groups_different_seeds(
            k in 4_u32..12,
            group_a in 0_u32..1000,
            group_b in 0_u32..1000,
            fill_byte in any::<u8>(),
        ) {
            prop_assume!(group_a != group_b);
            let cx = Cx::for_testing();
            let block_size = 64_u32;
            let device = MemBlockDevice::new(block_size, u64::from(k) * 2);
            for i in 0..u64::from(k) {
                device.write(BlockNumber(i), vec![fill_byte; block_size as usize]);
            }

            let uuid = test_uuid();
            let enc_a = encode_group(&cx, &device, &uuid, GroupNumber(group_a), BlockNumber(0), k, 2)
                .expect("encode group_a");
            let enc_b = encode_group(&cx, &device, &uuid, GroupNumber(group_b), BlockNumber(0), k, 2)
                .expect("encode group_b");

            prop_assert_ne!(enc_a.seed, enc_b.seed);
        }

        /// Repair symbol count matches requested count.
        #[test]
        fn proptest_repair_count_matches_request(
            k in 4_u32..16,
            repair_count in 0_u32..16,
        ) {
            let cx = Cx::for_testing();
            let block_size = 64_u32;
            let device = setup_device(k, block_size);
            let uuid = test_uuid();
            let group = GroupNumber(0);

            let encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, repair_count)
                .expect("encode");

            prop_assert_eq!(
                encoded.repair_symbols.len(),
                repair_count as usize
            );
            prop_assert_eq!(encoded.source_block_count, k);
            prop_assert_eq!(encoded.symbol_size, block_size);
        }
    }

    #[test]
    fn fault_injection_progressive_corruption() {
        // Verify that decode succeeds with sufficient redundancy and fails
        // when corruption exceeds available repair symbols.
        //
        // The decoder needs L = K + S + H total received symbols (constraint +
        // source + repair). With K=16, S~7, H~4, L~27. The S+H=11 constraint
        // symbols are always provided, so we need (K - corrupt) + repair >= L,
        // i.e., repair >= corrupt + S + H. Use K repair symbols to be safe.
        let cx = Cx::for_testing();
        let k = 16;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(0);

        let encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, k).unwrap();
        let repair_data: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .iter()
            .map(|s| (s.esi, s.data.clone()))
            .collect();

        // 1 corrupt block with K repair symbols — should succeed.
        let result = decode_group(
            &cx,
            &device,
            &uuid,
            group,
            BlockNumber(0),
            k,
            &[0],
            &repair_data,
        );
        assert!(result.is_ok(), "1 corrupt with K repairs should work");

        // 3 corrupt blocks — should succeed.
        let result = decode_group(
            &cx,
            &device,
            &uuid,
            group,
            BlockNumber(0),
            k,
            &[0, 1, 2],
            &repair_data,
        );
        assert!(result.is_ok(), "3 corrupt with K repairs should work");

        // All blocks corrupt with only K repair symbols — should fail because
        // total received = (S+H constraints) + K repairs < L + K needed.
        let too_many: Vec<u32> = (0..k).collect();
        let result = decode_group(
            &cx,
            &device,
            &uuid,
            group,
            BlockNumber(0),
            k,
            &too_many,
            &repair_data,
        );
        assert!(result.is_err(), "all blocks corrupt should fail");

        // Verify few repair symbols with few corruptions also fails:
        // only 1 repair symbol, 4 corrupt blocks.
        let small_encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, 1).unwrap();
        let small_repair: Vec<(u32, Vec<u8>)> = small_encoded
            .repair_symbols
            .iter()
            .map(|s| (s.esi, s.data.clone()))
            .collect();
        let result = decode_group(
            &cx,
            &device,
            &uuid,
            group,
            BlockNumber(0),
            k,
            &[0, 1, 2, 3],
            &small_repair,
        );
        assert!(result.is_err(), "4 corrupt with 1 repair should fail");
    }
}
