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
use asupersync::raptorq::gf256::{Gf256, gf256_add_slice, gf256_addmul_slice, gf256_mul_slice};
use asupersync::raptorq::rfc6330::{next_prime_ge, try_tuple};
use asupersync::raptorq::systematic::{EmittedSymbol, SystematicEncoder, SystematicParams};
#[cfg(any(test, feature = "bench-instrumentation"))]
use ffs_block::BlockBuf;
use ffs_block::BlockDevice;
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, GroupNumber};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};

use crate::symbol::repair_seed;

const RQ_DECODE_WAVEFRONT_BATCH: usize = 4;
const DIRECT_SMALL_ERASURE_MAX_CORRUPT: usize = 2;
const DIRECT_SMALL_ERASURE_MAX_SOURCE_BLOCKS: usize = 64;
const SOURCE_COEFFICIENT_ENCODER_CACHE_CAPACITY: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceCoefficientEncoderKey {
    source_count: usize,
    seed: u64,
}

#[derive(Debug)]
struct SourceCoefficientEncoderCacheEntry {
    key: SourceCoefficientEncoderKey,
    encoder: Arc<SystematicEncoder>,
}

static SOURCE_COEFFICIENT_ENCODER_CACHE: OnceLock<
    Mutex<VecDeque<SourceCoefficientEncoderCacheEntry>>,
> = OnceLock::new();

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
    let source_symbols = read_source_symbols_serial(cx, device, first_block, source_block_count)?;

    finish_encode_group(
        &source_symbols,
        block_size,
        seed,
        repair_count,
        group,
        source_block_count,
    )
}

fn read_source_symbols_serial(
    cx: &Cx,
    device: &dyn BlockDevice,
    first_block: BlockNumber,
    source_block_count: u32,
) -> Result<Vec<Vec<u8>>> {
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
    Ok(source_symbols)
}

#[cfg(any(test, feature = "bench-instrumentation"))]
fn read_source_symbols_batched_candidate(
    cx: &Cx,
    device: &dyn BlockDevice,
    first_block: BlockNumber,
    source_block_count: u32,
) -> Result<Vec<Vec<u8>>> {
    let count = u64::from(source_block_count);

    // Keep the scalar path for zero/one-block groups, devices without a
    // contiguous-read implementation, and ranges that would fail address/device
    // bounds validation. The fallback deliberately retains the old per-block
    // check/read ordering and error text.
    let Some(last_block) = first_block.0.checked_add(count.saturating_sub(1)) else {
        return read_source_symbols_serial(cx, device, first_block, source_block_count);
    };
    if count <= 1
        || !device.supports_contiguous_reads()
        || last_block >= device.block_count()
        || device.block_size() == 0
    {
        return read_source_symbols_serial(cx, device, first_block, source_block_count);
    }

    // File-backed devices collapse this into one positioned vectored read.
    // BlockBuf order is identical to scalar block order, and unsupported
    // devices never pay setup/allocation overhead for this path.
    let block_size = usize::try_from(device.block_size())
        .map_err(|_| FfsError::Format("encode_group: block size does not fit usize".to_owned()))?;
    let source_count = usize::try_from(source_block_count).map_err(|_| {
        FfsError::Format("encode_group: source count does not fit usize".to_owned())
    })?;
    let mut blocks = (0..source_count)
        .map(|_| BlockBuf::zeroed(block_size))
        .collect::<Vec<_>>();
    device.read_contiguous_blocks(cx, first_block, &mut blocks)?;
    Ok(blocks.into_iter().map(BlockBuf::into_inner).collect())
}

fn finish_encode_group(
    source_symbols: &[Vec<u8>],
    block_size: u32,
    seed: u64,
    repair_count: u32,
    group: GroupNumber,
    source_block_count: u32,
) -> Result<EncodedGroup> {
    let repair_symbols = emit_projected_repair_symbols(
        source_symbols,
        block_size as usize,
        seed,
        repair_count as usize,
        group,
    )?;

    Ok(EncodedGroup {
        group,
        source_block_count,
        symbol_size: block_size,
        seed,
        repair_symbols,
    })
}

/// Rejected contiguous-read candidate retained for same-ELF benchmark controls.
///
/// This is compiled only when the explicit benchmark-instrumentation feature is
/// enabled; production [`encode_group`] retains serial source reads.
#[cfg(feature = "bench-instrumentation")]
#[doc(hidden)]
pub fn encode_group_batched_read_candidate(
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
    let source_symbols =
        read_source_symbols_batched_candidate(cx, device, first_block, source_block_count)?;
    finish_encode_group(
        &source_symbols,
        block_size,
        seed,
        repair_count,
        group,
        source_block_count,
    )
}

fn emit_projected_repair_symbols(
    source_symbols: &[Vec<u8>],
    block_size: usize,
    seed: u64,
    repair_count: usize,
    group: GroupNumber,
) -> Result<Vec<EmittedSymbol>> {
    let source_count = source_symbols.len();
    let coefficient_encoder =
        build_source_coefficient_encoder(source_count, seed).ok_or_else(|| {
            FfsError::RepairFailed(format!(
                "constraint matrix singular for group {} (K={source_count})",
                group.0
            ))
        })?;

    let start_esi = coefficient_encoder.next_repair_esi();
    let params = coefficient_encoder.params();

    // Each repair symbol is an independent GF256 linear combination of the K
    // source symbols (own coefficients + data buffers; the encoder is shared
    // read-only via the Arc), so compute the R of them in parallel across cores
    // — mirroring the already-parallel LRC global-parity loop (lrc.rs) (bd-blr6r).
    //
    // The serial version `break`s on the first esi that would overflow u32; since
    // esi = start_esi + i is monotonic, that valid set is a prefix, so cap the
    // index range at `valid_count` and let rayon's ordered `collect` reproduce
    // the exact emission order and symbols.
    let valid_count = repair_count.min(
        usize::try_from(u32::MAX - start_esi)
            .unwrap_or(usize::MAX)
            .saturating_add(1),
    );
    let repair_symbols: Vec<EmittedSymbol> = (0..valid_count)
        .into_par_iter()
        .map(|i| {
            // i < valid_count guarantees i fits u32 and start_esi + i ≤ u32::MAX.
            let esi = start_esi + u32::try_from(i).unwrap_or(u32::MAX);
            let mut coefficients = vec![0_u8; source_count];
            coefficient_encoder.repair_symbol_into(esi, &mut coefficients);

            let mut data = vec![0_u8; block_size];
            for (&coefficient, source_symbol) in coefficients.iter().zip(source_symbols) {
                let coefficient = Gf256::new(coefficient);
                if coefficient.is_zero() {
                    continue;
                }
                if coefficient == Gf256::ONE {
                    gf256_add_slice(&mut data, source_symbol);
                } else {
                    gf256_addmul_slice(&mut data, source_symbol, coefficient);
                }
            }

            EmittedSymbol {
                esi,
                data,
                is_source: false,
                degree: raptorq_repair_symbol_degree(params, esi),
            }
        })
        .collect();

    Ok(repair_symbols)
}

fn raptorq_repair_symbol_degree(params: &SystematicParams, esi: u32) -> usize {
    let Some(padding_delta) = params
        .k_prime
        .checked_sub(params.k)
        .and_then(|delta| u32::try_from(delta).ok())
    else {
        return 0;
    };
    let Some(repair_isi) = esi.checked_add(padding_delta) else {
        return 0;
    };
    let Some(pi_modulus) = next_prime_ge(params.p) else {
        return 0;
    };
    let Some(lt_tuple) = try_tuple(params.j, params.w, params.p, pi_modulus, repair_isi) else {
        return 0;
    };
    lt_tuple.d + lt_tuple.d1
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
#[allow(clippy::too_many_lines)]
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
    if corrupt_indices.is_empty() {
        return Ok(DecodeOutcome {
            recovered: Vec::new(),
            stats: asupersync::raptorq::decoder::DecodeStats::default(),
            complete: true,
        });
    }

    let block_size = device.block_size() as usize;
    let k = source_block_count as usize;
    let seed = repair_seed(fs_uuid, group);

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
    let repair_symbols = match repair_symbols {
        RepairSymbolInput::Borrowed(symbols) => {
            if let Some(outcome) = try_direct_small_erasure_decode(
                cx,
                device,
                &decoder,
                first_block,
                source_block_count,
                corrupt_indices,
                &corrupt_set,
                symbols,
                seed,
                block_size,
            )? {
                return Ok(outcome);
            }
            RepairSymbolInput::Borrowed(symbols)
        }
        RepairSymbolInput::Owned(symbols) => {
            let attempt = try_direct_small_erasure_decode_owned(
                cx,
                device,
                &decoder,
                first_block,
                source_block_count,
                corrupt_indices,
                &corrupt_set,
                symbols,
                seed,
                block_size,
            )?;
            if let Some(outcome) = attempt.outcome {
                return Ok(outcome);
            }
            RepairSymbolInput::Owned(attempt.fallback)
        }
    };

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

struct DirectRepairRow {
    esi: u32,
    coefficients: [Gf256; DIRECT_SMALL_ERASURE_MAX_CORRUPT],
    source_coefficients: [u8; DIRECT_SMALL_ERASURE_MAX_SOURCE_BLOCKS],
    source_count: usize,
    residual: Vec<u8>,
}

struct KnownSourceSymbol {
    source_index: usize,
    data: Vec<u8>,
}

struct DirectRepairPlan {
    rows: Vec<DirectRepairRow>,
    selection: DirectRepairSelection,
}

#[derive(Clone, Copy)]
enum DirectRepairSelection {
    One(usize),
    Two(usize, usize),
}

struct OwnedDirectDecodeAttempt {
    outcome: Option<DecodeOutcome>,
    fallback: Vec<(u32, Vec<u8>)>,
}

enum OwnedDirectRows {
    Rows(Vec<DirectRepairRow>),
    Fallback(Vec<(u32, Vec<u8>)>),
}

#[allow(clippy::too_many_arguments)]
fn try_direct_small_erasure_decode(
    cx: &Cx,
    device: &dyn BlockDevice,
    decoder: &InactivationDecoder,
    first_block: BlockNumber,
    source_block_count: u32,
    corrupt_indices: &[u32],
    corrupt_set: &CorruptIndexSet,
    repair_symbols: &[(u32, Vec<u8>)],
    seed: u64,
    block_size: usize,
) -> Result<Option<DecodeOutcome>> {
    let missing_count = corrupt_set.len();
    let source_count =
        usize::try_from(source_block_count).expect("u32 source block count fits usize");
    if !(1..=DIRECT_SMALL_ERASURE_MAX_CORRUPT).contains(&missing_count)
        || source_count > DIRECT_SMALL_ERASURE_MAX_SOURCE_BLOCKS
    {
        return Ok(None);
    }

    let Some(source_coefficient_encoder) = build_source_coefficient_encoder(source_count, seed)
    else {
        return Ok(None);
    };

    let Some(mut plan) = select_direct_repair_plan_without_projection(
        decoder,
        &corrupt_set.unique,
        repair_symbols,
        source_count,
        &source_coefficient_encoder,
    ) else {
        return Ok(None);
    };

    let known_source = read_known_source_symbols(
        cx,
        device,
        first_block,
        source_block_count,
        corrupt_set,
        block_size,
    )?;
    project_known_source_contributions_source_major(&mut plan.rows, &known_source, block_size)
        .expect("known source symbols were read at the device block size");

    let Some(solved) = solve_direct_repair_rows(&plan.rows, plan.selection)? else {
        return Ok(None);
    };

    let recovered =
        recover_from_direct_solution(first_block, corrupt_indices, &corrupt_set.unique, &solved)?;

    Ok(Some(DecodeOutcome {
        complete: recovered.len() == corrupt_indices.len(),
        recovered,
        stats: direct_decode_stats(missing_count),
    }))
}

#[allow(clippy::too_many_arguments)]
fn try_direct_small_erasure_decode_owned(
    cx: &Cx,
    device: &dyn BlockDevice,
    decoder: &InactivationDecoder,
    first_block: BlockNumber,
    source_block_count: u32,
    corrupt_indices: &[u32],
    corrupt_set: &CorruptIndexSet,
    repair_symbols: Vec<(u32, Vec<u8>)>,
    seed: u64,
    block_size: usize,
) -> Result<OwnedDirectDecodeAttempt> {
    let missing_count = corrupt_set.len();
    let source_count =
        usize::try_from(source_block_count).expect("u32 source block count fits usize");
    if !(1..=DIRECT_SMALL_ERASURE_MAX_CORRUPT).contains(&missing_count)
        || source_count > DIRECT_SMALL_ERASURE_MAX_SOURCE_BLOCKS
    {
        return Ok(OwnedDirectDecodeAttempt {
            outcome: None,
            fallback: repair_symbols,
        });
    }

    let Some(source_coefficient_encoder) = build_source_coefficient_encoder(source_count, seed)
    else {
        return Ok(OwnedDirectDecodeAttempt {
            outcome: None,
            fallback: repair_symbols,
        });
    };

    let mut rows = match build_owned_direct_repair_rows(
        decoder,
        &corrupt_set.unique,
        repair_symbols,
        &source_coefficient_encoder,
        source_count,
    ) {
        OwnedDirectRows::Rows(rows) => rows,
        OwnedDirectRows::Fallback(symbols) => {
            return Ok(OwnedDirectDecodeAttempt {
                outcome: None,
                fallback: symbols,
            });
        }
    };

    let Some(selection) = select_direct_repair_rows(&rows, missing_count) else {
        return Ok(OwnedDirectDecodeAttempt {
            outcome: None,
            fallback: repair_symbols_from_direct_rows(rows),
        });
    };

    let known_source = read_known_source_symbols(
        cx,
        device,
        first_block,
        source_block_count,
        corrupt_set,
        block_size,
    )?;
    project_known_source_contributions_source_major(&mut rows, &known_source, block_size)
        .expect("known source symbols were read at the device block size");

    let Some(solved) = solve_direct_repair_rows(&rows, selection)? else {
        restore_known_source_contributions_source_major(&mut rows, &known_source, block_size)
            .expect("known source projection should be reversible");
        return Ok(OwnedDirectDecodeAttempt {
            outcome: None,
            fallback: repair_symbols_from_direct_rows(rows),
        });
    };

    let recovered =
        recover_from_direct_solution(first_block, corrupt_indices, &corrupt_set.unique, &solved)?;

    Ok(OwnedDirectDecodeAttempt {
        outcome: Some(DecodeOutcome {
            complete: recovered.len() == corrupt_indices.len(),
            recovered,
            stats: direct_decode_stats(missing_count),
        }),
        fallback: Vec::new(),
    })
}

fn read_known_source_symbols(
    cx: &Cx,
    device: &dyn BlockDevice,
    first_block: BlockNumber,
    source_block_count: u32,
    corrupt_set: &CorruptIndexSet,
    _block_size: usize,
) -> Result<Vec<KnownSourceSymbol>> {
    let source_count =
        usize::try_from(source_block_count).expect("u32 source block count fits usize");
    let mut source = Vec::with_capacity(source_count.saturating_sub(corrupt_set.len()));
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
        source.push(KnownSourceSymbol {
            source_index: usize::try_from(i).expect("u32 source index fits usize"),
            data: device.read_block(cx, block_num)?.into_inner(),
        });
    }
    Ok(source)
}

fn build_source_coefficient_encoder(
    source_count: usize,
    seed: u64,
) -> Option<Arc<SystematicEncoder>> {
    let key = SourceCoefficientEncoderKey { source_count, seed };
    if let Some(encoder) = cached_source_coefficient_encoder(key) {
        return Some(encoder);
    }

    let encoder = Arc::new(build_uncached_source_coefficient_encoder(
        source_count,
        seed,
    )?);
    Some(cache_source_coefficient_encoder(key, encoder))
}

fn build_uncached_source_coefficient_encoder(
    source_count: usize,
    seed: u64,
) -> Option<SystematicEncoder> {
    let mut source_coefficients = vec![vec![0_u8; source_count]; source_count];
    for (source_index, symbol) in source_coefficients.iter_mut().enumerate() {
        symbol[source_index] = 1;
    }
    SystematicEncoder::new(&source_coefficients, source_count, seed)
}

fn source_coefficient_encoder_cache() -> &'static Mutex<VecDeque<SourceCoefficientEncoderCacheEntry>>
{
    SOURCE_COEFFICIENT_ENCODER_CACHE.get_or_init(|| {
        Mutex::new(VecDeque::with_capacity(
            SOURCE_COEFFICIENT_ENCODER_CACHE_CAPACITY,
        ))
    })
}

fn cached_source_coefficient_encoder(
    key: SourceCoefficientEncoderKey,
) -> Option<Arc<SystematicEncoder>> {
    let Ok(mut entries) = source_coefficient_encoder_cache().lock() else {
        return None;
    };
    let entry_index = entries.iter().position(|entry| entry.key == key)?;
    let entry = entries.remove(entry_index)?;
    let encoder = Arc::clone(&entry.encoder);
    entries.push_back(entry);
    Some(encoder)
}

fn cache_source_coefficient_encoder(
    key: SourceCoefficientEncoderKey,
    encoder: Arc<SystematicEncoder>,
) -> Arc<SystematicEncoder> {
    let Ok(mut entries) = source_coefficient_encoder_cache().lock() else {
        return encoder;
    };
    if let Some(entry_index) = entries.iter().position(|entry| entry.key == key)
        && let Some(entry) = entries.remove(entry_index)
    {
        let cached = Arc::clone(&entry.encoder);
        entries.push_back(entry);
        return cached;
    }
    if entries.len() == SOURCE_COEFFICIENT_ENCODER_CACHE_CAPACITY {
        entries.pop_front();
    }
    entries.push_back(SourceCoefficientEncoderCacheEntry {
        key,
        encoder: Arc::clone(&encoder),
    });
    encoder
}

#[cfg(test)]
fn build_known_basis_encoder(
    mut source: Vec<Vec<u8>>,
    missing: &[u32],
    block_size: usize,
    seed: u64,
) -> Option<SystematicEncoder> {
    let symbol_size = block_size.checked_add(missing.len())?;
    for symbol in &mut source {
        if symbol.len() != block_size {
            return None;
        }
        symbol.resize(symbol_size, 0);
    }

    for (slot, &missing_index) in missing.iter().enumerate() {
        let source_index = usize::try_from(missing_index).ok()?;
        let symbol = source.get_mut(source_index)?;
        symbol[block_size + slot] = 1;
    }

    SystematicEncoder::new(&source, symbol_size, seed)
}

#[cfg(test)]
fn select_direct_repair_plan(
    decoder: &InactivationDecoder,
    missing: &[u32],
    repair_symbols: &[(u32, Vec<u8>)],
    source_count: usize,
    known_source: &[KnownSourceSymbol],
    source_coefficient_encoder: &SystematicEncoder,
    block_size: usize,
) -> Option<DirectRepairPlan> {
    let mut plan = select_direct_repair_plan_without_projection(
        decoder,
        missing,
        repair_symbols,
        source_count,
        source_coefficient_encoder,
    )?;
    project_known_source_contributions_source_major(&mut plan.rows, known_source, block_size)?;
    Some(plan)
}

fn select_direct_repair_plan_without_projection(
    decoder: &InactivationDecoder,
    missing: &[u32],
    repair_symbols: &[(u32, Vec<u8>)],
    source_count: usize,
    source_coefficient_encoder: &SystematicEncoder,
) -> Option<DirectRepairPlan> {
    if source_count > DIRECT_SMALL_ERASURE_MAX_SOURCE_BLOCKS {
        return None;
    }

    let mut rows = Vec::with_capacity(repair_symbols.len());
    for (esi, actual) in repair_symbols {
        if decoder.repair_equation(*esi).is_err() {
            return None;
        }
        let mut source_coefficients = [0_u8; DIRECT_SMALL_ERASURE_MAX_SOURCE_BLOCKS];
        source_coefficient_encoder
            .repair_symbol_into(*esi, &mut source_coefficients[..source_count]);

        let mut coefficients = [Gf256::ZERO; DIRECT_SMALL_ERASURE_MAX_CORRUPT];
        for slot in 0..missing.len() {
            let source_index = usize::try_from(missing[slot]).ok()?;
            coefficients[slot] = Gf256::new(*source_coefficients.get(source_index)?);
        }

        rows.push(DirectRepairRow {
            esi: *esi,
            coefficients,
            source_coefficients,
            source_count,
            residual: actual.clone(),
        });
    }
    let selection = select_direct_repair_rows(&rows, missing.len())?;
    Some(DirectRepairPlan { rows, selection })
}

fn build_owned_direct_repair_rows(
    decoder: &InactivationDecoder,
    missing: &[u32],
    repair_symbols: Vec<(u32, Vec<u8>)>,
    source_coefficient_encoder: &SystematicEncoder,
    source_count: usize,
) -> OwnedDirectRows {
    let mut rows = Vec::with_capacity(repair_symbols.len());
    let mut symbols = repair_symbols.into_iter();
    while let Some((esi, actual)) = symbols.next() {
        if decoder.repair_equation(esi).is_err() {
            return OwnedDirectRows::Fallback(restore_direct_rows_with_tail(
                rows,
                Some((esi, actual)),
                symbols,
            ));
        }
        let mut source_coefficients = [0_u8; DIRECT_SMALL_ERASURE_MAX_SOURCE_BLOCKS];
        source_coefficient_encoder
            .repair_symbol_into(esi, &mut source_coefficients[..source_count]);

        let mut coefficients = [Gf256::ZERO; DIRECT_SMALL_ERASURE_MAX_CORRUPT];
        for slot in 0..missing.len() {
            let Ok(source_index) = usize::try_from(missing[slot]) else {
                return OwnedDirectRows::Fallback(restore_direct_rows_with_tail(
                    rows,
                    Some((esi, actual)),
                    symbols,
                ));
            };
            let Some(&coefficient) = source_coefficients.get(source_index) else {
                return OwnedDirectRows::Fallback(restore_direct_rows_with_tail(
                    rows,
                    Some((esi, actual)),
                    symbols,
                ));
            };
            coefficients[slot] = Gf256::new(coefficient);
        }

        rows.push(DirectRepairRow {
            esi,
            coefficients,
            source_coefficients,
            source_count,
            residual: actual,
        });
    }

    OwnedDirectRows::Rows(rows)
}

fn restore_direct_rows_with_tail(
    rows: Vec<DirectRepairRow>,
    current: Option<(u32, Vec<u8>)>,
    tail: std::vec::IntoIter<(u32, Vec<u8>)>,
) -> Vec<(u32, Vec<u8>)> {
    let mut symbols = repair_symbols_from_direct_rows(rows);
    if let Some(symbol) = current {
        symbols.push(symbol);
    }
    symbols.extend(tail);
    symbols
}

fn repair_symbols_from_direct_rows(rows: Vec<DirectRepairRow>) -> Vec<(u32, Vec<u8>)> {
    rows.into_iter()
        .map(|row| (row.esi, row.residual))
        .collect()
}

fn select_direct_repair_rows(
    rows: &[DirectRepairRow],
    missing_count: usize,
) -> Option<DirectRepairSelection> {
    match missing_count {
        1 => rows
            .iter()
            .position(|row| !row.coefficients[0].is_zero())
            .map(DirectRepairSelection::One),
        2 => select_full_rank_pair(rows)
            .map(|(row_a, row_b)| DirectRepairSelection::Two(row_a, row_b)),
        _ => None,
    }
}

fn project_known_source_contributions_source_major(
    rows: &mut [DirectRepairRow],
    known_source: &[KnownSourceSymbol],
    block_size: usize,
) -> Option<()> {
    if rows.is_empty() {
        return Some(());
    }

    let source_count = rows[0].source_count;
    if rows.iter().any(|row| row.source_count != source_count) {
        return None;
    }

    for source_symbol in known_source {
        if source_symbol.source_index >= source_count || source_symbol.data.len() != block_size {
            return None;
        }
        for row in rows.iter_mut() {
            let coefficient = Gf256::new(row.source_coefficients[source_symbol.source_index]);
            if !coefficient.is_zero() {
                gf256_addmul_slice(&mut row.residual, &source_symbol.data, coefficient);
            }
        }
    }
    Some(())
}

fn restore_known_source_contributions_source_major(
    rows: &mut [DirectRepairRow],
    known_source: &[KnownSourceSymbol],
    block_size: usize,
) -> Option<()> {
    project_known_source_contributions_source_major(rows, known_source, block_size)
}

fn select_full_rank_pair(rows: &[DirectRepairRow]) -> Option<(usize, usize)> {
    for first_index in 0..rows.len() {
        for second_index in first_index + 1..rows.len() {
            let row_a = &rows[first_index];
            let row_b = &rows[second_index];
            if !det2(row_a.coefficients, row_b.coefficients).is_zero() {
                return Some((first_index, second_index));
            }
        }
    }
    None
}

fn det2(
    row_a: [Gf256; DIRECT_SMALL_ERASURE_MAX_CORRUPT],
    row_b: [Gf256; DIRECT_SMALL_ERASURE_MAX_CORRUPT],
) -> Gf256 {
    row_a[0] * row_b[1] + row_a[1] * row_b[0]
}

fn solve_one_erasure(row: &DirectRepairRow) -> Option<Vec<Vec<u8>>> {
    let coefficient = row.coefficients[0];
    if coefficient.is_zero() {
        return None;
    }
    let mut recovered = row.residual.clone();
    gf256_mul_slice(&mut recovered, coefficient.inv());
    Some(vec![recovered])
}

fn solve_two_erasures(
    row_a: &DirectRepairRow,
    row_b: &DirectRepairRow,
) -> Result<Option<Vec<Vec<u8>>>> {
    let determinant = det2(row_a.coefficients, row_b.coefficients);
    if determinant.is_zero() {
        return Ok(None);
    }

    let residual_a = &row_a.residual;
    let residual_b = &row_b.residual;
    if residual_a.len() != residual_b.len() {
        return Err(FfsError::RepairFailed(format!(
            "decode_group: direct residual length mismatch: {} vs {}",
            residual_a.len(),
            residual_b.len(),
        )));
    }
    let mut first = vec![0; residual_a.len()];
    let mut second = vec![0; residual_a.len()];

    gf256_addmul_slice(&mut first, residual_a, row_b.coefficients[1]);
    gf256_addmul_slice(&mut first, residual_b, row_a.coefficients[1]);
    gf256_mul_slice(&mut first, determinant.inv());

    gf256_addmul_slice(&mut second, residual_a, row_b.coefficients[0]);
    gf256_addmul_slice(&mut second, residual_b, row_a.coefficients[0]);
    gf256_mul_slice(&mut second, determinant.inv());

    Ok(Some(vec![first, second]))
}

fn solve_direct_repair_rows(
    rows: &[DirectRepairRow],
    selection: DirectRepairSelection,
) -> Result<Option<Vec<Vec<u8>>>> {
    match selection {
        DirectRepairSelection::One(row_index) => {
            let row = &rows[row_index];
            let Some(solved) = solve_one_erasure(row) else {
                return Ok(None);
            };
            if !direct_solution_satisfies_all_repairs(rows, &solved) {
                return Ok(None);
            }
            Ok(Some(solved))
        }
        DirectRepairSelection::Two(pivot_index, companion_index) => {
            let row_a = &rows[pivot_index];
            let row_b = &rows[companion_index];
            let Some(solved) = solve_two_erasures(row_a, row_b)? else {
                return Ok(None);
            };
            if !direct_solution_satisfies_all_repairs(rows, &solved) {
                return Ok(None);
            }
            Ok(Some(solved))
        }
    }
}

fn direct_solution_satisfies_all_repairs(rows: &[DirectRepairRow], solved: &[Vec<u8>]) -> bool {
    let Some(first_row) = rows.first() else {
        return true;
    };
    let block_size = first_row.residual.len();
    if solved.iter().any(|recovered| recovered.len() != block_size)
        || rows.iter().any(|row| row.residual.len() != block_size)
    {
        return false;
    }

    let mut expected = vec![0; block_size];
    for row in rows {
        expected.fill(0);
        for (missing_position, recovered) in solved.iter().enumerate() {
            let coefficient = row.coefficients[missing_position];
            if !coefficient.is_zero() {
                gf256_addmul_slice(&mut expected, recovered, coefficient);
            }
        }
        if row.residual.as_slice() != expected.as_slice() {
            return false;
        }
    }
    true
}

fn recover_from_direct_solution(
    first_block: BlockNumber,
    corrupt_indices: &[u32],
    unique_corrupt_indices: &[u32],
    solved: &[Vec<u8>],
) -> Result<Vec<RecoveredBlock>> {
    let mut recovered = Vec::with_capacity(corrupt_indices.len());
    for &idx in corrupt_indices {
        let Some(unique_position) = unique_corrupt_indices
            .iter()
            .position(|&unique| unique == idx)
        else {
            return Err(FfsError::RepairFailed(format!(
                "decode_group: corrupt index {idx} missing from direct solution"
            )));
        };
        let block_num =
            BlockNumber(first_block.0.checked_add(u64::from(idx)).ok_or_else(|| {
                FfsError::RepairFailed(format!(
                    "decode_group: block address overflow at first_block={} + corrupt_idx={idx}",
                    first_block.0
                ))
            })?);
        recovered.push(RecoveredBlock {
            block: block_num,
            data: solved[unique_position].clone(),
        });
    }
    Ok(recovered)
}

#[allow(clippy::field_reassign_with_default)]
fn direct_decode_stats(missing_count: usize) -> asupersync::raptorq::decoder::DecodeStats {
    let mut stats = asupersync::raptorq::decoder::DecodeStats::default();
    stats.peeled = missing_count;
    stats.pivots_selected = missing_count;
    stats.gauss_ops = missing_count;
    stats.policy_mode = Some("small_erasure_direct");
    stats.policy_reason = Some("full_rank_source_domain_repair");
    stats
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

    struct FailingReadDevice {
        block_size: u32,
        fail_blocks: Vec<u64>,
        reads: Mutex<Vec<u64>>,
    }

    impl FailingReadDevice {
        fn new(block_size: u32, fail_blocks: Vec<u64>) -> Self {
            Self {
                block_size,
                fail_blocks,
                reads: Mutex::new(Vec::new()),
            }
        }
    }

    impl BlockDevice for FailingReadDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            self.reads.lock().push(block.0);
            if self.fail_blocks.contains(&block.0) {
                return Err(FfsError::Io(std::io::Error::other(format!(
                    "injected read failure at block {}",
                    block.0
                ))));
            }
            Ok(BlockBuf::new(vec![
                block.0.to_le_bytes()[0];
                self.block_size as usize
            ]))
        }

        fn supports_contiguous_reads(&self) -> bool {
            true
        }

        fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
            Err(FfsError::ReadOnly)
        }

        fn block_size(&self) -> u32 {
            self.block_size
        }

        fn block_count(&self) -> u64 {
            u64::MAX
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
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

        fn supports_contiguous_reads(&self) -> bool {
            true
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

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
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
    fn encode_source_read_batch_preserves_block_order_and_bytes() {
        let cx = Cx::for_testing();
        let source_count = 16;
        let device = setup_device(source_count, 64);

        let serial =
            read_source_symbols_serial(&cx, &device, BlockNumber(0), source_count).unwrap();
        let batched =
            read_source_symbols_batched_candidate(&cx, &device, BlockNumber(0), source_count)
                .unwrap();

        assert_eq!(serial, batched);
        assert_eq!(
            device.read_count(),
            usize::try_from(source_count).unwrap() * 2
        );
    }

    #[test]
    fn encode_source_read_batch_preserves_first_error_in_block_order() {
        let cx = Cx::for_testing();
        let device = FailingReadDevice::new(64, vec![2, 5]);

        let error = read_source_symbols_batched_candidate(&cx, &device, BlockNumber(0), 8)
            .expect_err("batched source reads must return the first indexed read error");

        assert_eq!(
            error.to_string(),
            "I/O error: injected read failure at block 2"
        );
    }

    #[test]
    fn encode_source_read_batch_preserves_error_before_later_address_overflow() {
        let cx = Cx::for_testing();
        let first = u64::MAX - 1;
        let device = FailingReadDevice::new(64, vec![first]);

        let error = read_source_symbols_batched_candidate(&cx, &device, BlockNumber(first), 3)
            .expect_err("earlier device error must precede later address overflow");

        assert_eq!(
            error.to_string(),
            format!("I/O error: injected read failure at block {first}")
        );
        assert_eq!(*device.reads.lock(), vec![first]);
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
    fn raptorq_encode_golden_report() {
        let cx = Cx::for_testing();
        let k = 8;
        let block_size = 96;
        let repair_count = 4;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(3);

        let encoded =
            encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, repair_count).unwrap();

        println!("RAPTORQ_ENCODE_GOLDEN_BEGIN");
        println!(
            "group={} source_block_count={} symbol_size={} seed={} repair_count={}",
            encoded.group.0,
            encoded.source_block_count,
            encoded.symbol_size,
            encoded.seed,
            encoded.repair_symbols.len()
        );
        for symbol in &encoded.repair_symbols {
            println!(
                "symbol esi={} is_source={} degree={} data={}",
                symbol.esi,
                symbol.is_source,
                symbol.degree,
                hex_encode(&symbol.data)
            );
        }
        println!("RAPTORQ_ENCODE_GOLDEN_END");
    }

    #[test]
    fn raptorq_reference_encode_golden_report() {
        let cx = Cx::for_testing();
        let k = 8_u32;
        let block_size = 96_u32;
        let repair_count = 4_u32;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(3);
        let seed = repair_seed(&uuid, group);

        let mut source_symbols = Vec::with_capacity(usize::try_from(k).expect("test K fits usize"));
        for block in 0..k {
            source_symbols.push(
                device
                    .read_block(&cx, BlockNumber(u64::from(block)))
                    .unwrap()
                    .into_inner(),
            );
        }
        let mut reference_encoder = SystematicEncoder::new(
            &source_symbols,
            usize::try_from(block_size).expect("test block size fits usize"),
            seed,
        )
        .unwrap();
        let repair_symbols = reference_encoder
            .emit_repair(usize::try_from(repair_count).expect("test repair count fits usize"));

        println!("RAPTORQ_ENCODE_GOLDEN_BEGIN");
        println!(
            "group={} source_block_count={} symbol_size={} seed={} repair_count={}",
            group.0,
            k,
            block_size,
            seed,
            repair_symbols.len()
        );
        for symbol in &repair_symbols {
            println!(
                "symbol esi={} is_source={} degree={} data={}",
                symbol.esi,
                symbol.is_source,
                symbol.degree,
                hex_encode(&symbol.data)
            );
        }
        println!("RAPTORQ_ENCODE_GOLDEN_END");
    }

    #[test]
    fn encode_group_projected_symbols_match_full_encoder_reference() {
        let cx = Cx::for_testing();
        let k = 16_u32;
        let block_size = 257_u32;
        let repair_count = 6_u32;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(5);
        let seed = repair_seed(&uuid, group);

        let mut source_symbols = Vec::with_capacity(usize::try_from(k).expect("test K fits usize"));
        for block in 0..k {
            source_symbols.push(
                device
                    .read_block(&cx, BlockNumber(u64::from(block)))
                    .unwrap()
                    .into_inner(),
            );
        }
        let mut reference_encoder = SystematicEncoder::new(
            &source_symbols,
            usize::try_from(block_size).expect("test block size fits usize"),
            seed,
        )
        .unwrap();
        let expected = reference_encoder
            .emit_repair(usize::try_from(repair_count).expect("test repair count fits usize"));

        let actual =
            encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, repair_count).unwrap();

        assert_eq!(actual.seed, seed);
        assert_eq!(actual.repair_symbols.len(), expected.len());
        for (actual, expected) in actual.repair_symbols.iter().zip(&expected) {
            assert_eq!(actual.esi, expected.esi);
            assert_eq!(actual.is_source, expected.is_source);
            assert_eq!(actual.degree, expected.degree);
            assert_eq!(actual.data, expected.data);
        }
    }

    #[test]
    fn cached_source_coefficient_encoder_matches_uncached_reference() {
        let k = 16_usize;
        let seed = repair_seed(&test_uuid(), GroupNumber(7));
        let cached = build_source_coefficient_encoder(k, seed).expect("cached encoder");
        let cached_again = build_source_coefficient_encoder(k, seed).expect("same cached encoder");
        let fresh = build_uncached_source_coefficient_encoder(k, seed).expect("fresh encoder");

        assert!(
            Arc::ptr_eq(&cached, &cached_again),
            "same source-count/seed plan should reuse the cached encoder"
        );
        assert_eq!(cached.next_repair_esi(), fresh.next_repair_esi());
        assert_eq!(cached.seed(), fresh.seed());
        assert_eq!(cached.params().k, fresh.params().k);
        assert_eq!(cached.params().k_prime, fresh.params().k_prime);
        assert_eq!(cached.params().s, fresh.params().s);
        assert_eq!(cached.params().h, fresh.params().h);
        assert_eq!(cached.params().l, fresh.params().l);
        assert_eq!(cached.params().w, fresh.params().w);
        assert_eq!(cached.params().p, fresh.params().p);
        assert_eq!(cached.params().b, fresh.params().b);
        assert_eq!(cached.params().symbol_size, fresh.params().symbol_size);

        let start_esi = cached.next_repair_esi();
        for offset in 0..8 {
            let esi = start_esi + offset;
            let mut cached_coefficients = vec![0_u8; k];
            let mut fresh_coefficients = vec![0_u8; k];
            cached.repair_symbol_into(esi, &mut cached_coefficients);
            fresh.repair_symbol_into(esi, &mut fresh_coefficients);
            assert_eq!(cached_coefficients, fresh_coefficients, "ESI {esi}");
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
    fn decode_invalid_direct_repair_row_reads_intact_sources_once() {
        let cx = Cx::for_testing();
        let k = 8;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(0);
        let seed = repair_seed(&uuid, group);
        let decoder = InactivationDecoder::new(k as usize, block_size as usize, seed);
        let invalid_esi = [u32::MAX, u32::MAX - 1, u32::MAX - 2]
            .into_iter()
            .find(|&esi| decoder.repair_equation(esi).is_err())
            .expect("test K must expose an overflow-invalid repair ESI");
        let repair_data = vec![(invalid_esi, vec![0_u8; block_size as usize])];
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

        let error = result.expect_err("invalid repair equation must fail closed");
        assert!(
            matches!(&error, FfsError::RepairFailed(msg) if msg.contains("repair_equation failed")),
            "expected RepairFailed about invalid repair equation, got: {error:?}"
        );
        assert_eq!(
            device.read_count() - reads_before_decode,
            (k as usize) - corrupt.len(),
            "direct-row rejection must not pre-read intact sources before fallback"
        );
    }

    #[test]
    fn validate_repair_symbol_lengths_rejects_wrong_length() {
        let group = GroupNumber(3);
        let block_size = 4096_usize;

        // All symbols matching block_size validate.
        let good: Vec<(u32, Vec<u8>)> = vec![(0, vec![0_u8; 4096]), (1, vec![0_u8; 4096])];
        assert!(validate_repair_symbol_lengths(good.iter(), block_size, group).is_ok());

        // No symbols is trivially valid.
        let empty: Vec<(u32, Vec<u8>)> = vec![];
        assert!(validate_repair_symbol_lengths(empty.iter(), block_size, group).is_ok());

        // A symbol whose payload length differs from block_size is refused.
        let bad: Vec<(u32, Vec<u8>)> = vec![(0, vec![0_u8; 4096]), (5, vec![0_u8; 100])];
        let err = validate_repair_symbol_lengths(bad.iter(), block_size, group).unwrap_err();
        assert!(matches!(err, FfsError::RepairFailed(_)), "got {err:?}");
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
    fn direct_source_coefficients_match_fused_known_basis_projection() {
        let k = 16_usize;
        let k_u32 = u32::try_from(k).expect("test K fits u32");
        let block_size = 64_usize;
        let block_size_u32 = 64_u32;
        let seed = 42_u64;
        let missing = [0_u32, 1];

        let source: Vec<Vec<u8>> = (0..k)
            .map(|index| {
                make_deterministic_block(
                    u64::try_from(index).expect("test source index fits u64"),
                    block_size_u32,
                )
            })
            .collect();
        let mut known_source = source;
        for &missing_index in &missing {
            let source_index = usize::try_from(missing_index).expect("missing index fits usize");
            known_source[source_index].fill(0);
        }

        let fused_encoder =
            build_known_basis_encoder(known_source.clone(), &missing, block_size, seed)
                .expect("fused known+basis encoder should build");
        let source_coefficient_encoder =
            build_source_coefficient_encoder(k, seed).expect("source coefficient encoder");

        for esi in k_u32..u32::try_from(k + 4).expect("test ESI range fits u32") {
            let fused = fused_encoder.repair_symbol(esi);
            assert_eq!(fused.len(), block_size + missing.len());
            let source_coefficients = source_coefficient_encoder.repair_symbol(esi);
            assert_eq!(source_coefficients.len(), k);

            let mut source_projected = vec![0_u8; block_size];
            for (source_index, source_symbol) in known_source.iter().enumerate() {
                let coefficient = Gf256::new(source_coefficients[source_index]);
                if !coefficient.is_zero() {
                    gf256_addmul_slice(&mut source_projected, source_symbol, coefficient);
                }
            }
            assert_eq!(
                source_projected.as_slice(),
                &fused[..block_size],
                "source-domain known projection must match fused prefix for esi={esi}"
            );
            for (slot, &missing_index) in missing.iter().enumerate() {
                let source_index =
                    usize::try_from(missing_index).expect("missing index fits usize");
                assert_eq!(
                    source_coefficients[source_index],
                    fused[block_size + slot],
                    "source-domain missing coefficient {slot} must match fused suffix for esi={esi}"
                );
            }
        }
    }

    fn reference_direct_rows_row_major(
        decoder: &InactivationDecoder,
        missing: &[u32],
        repair_symbols: &[(u32, Vec<u8>)],
        known_source: &[Vec<u8>],
        source_coefficient_encoder: &SystematicEncoder,
        block_size: usize,
    ) -> Vec<DirectRepairRow> {
        let mut rows = Vec::with_capacity(repair_symbols.len());
        for (esi, actual) in repair_symbols {
            assert!(
                decoder.repair_equation(*esi).is_ok(),
                "test ESI should be valid"
            );
            assert!(known_source.len() <= DIRECT_SMALL_ERASURE_MAX_SOURCE_BLOCKS);
            let mut source_coefficients = [0_u8; DIRECT_SMALL_ERASURE_MAX_SOURCE_BLOCKS];
            source_coefficient_encoder
                .repair_symbol_into(*esi, &mut source_coefficients[..known_source.len()]);

            let mut coefficients = [Gf256::ZERO; DIRECT_SMALL_ERASURE_MAX_CORRUPT];
            for slot in 0..missing.len() {
                let source_index = usize::try_from(missing[slot]).expect("missing index fits");
                coefficients[slot] = Gf256::new(source_coefficients[source_index]);
            }

            let mut residual = actual.clone();
            for (source_index, source_symbol) in known_source.iter().enumerate() {
                assert_eq!(source_symbol.len(), block_size);
                let source_index_u32 = u32::try_from(source_index).expect("source index fits u32");
                if missing.binary_search(&source_index_u32).is_ok() {
                    continue;
                }
                let coefficient = Gf256::new(source_coefficients[source_index]);
                if !coefficient.is_zero() {
                    gf256_addmul_slice(&mut residual, source_symbol, coefficient);
                }
            }

            rows.push(DirectRepairRow {
                esi: *esi,
                coefficients,
                source_coefficients,
                source_count: known_source.len(),
                residual,
            });
        }
        rows
    }

    fn direct_selection_signature(selection: &DirectRepairSelection) -> (usize, Option<usize>) {
        match *selection {
            DirectRepairSelection::One(row) => (row, None),
            DirectRepairSelection::Two(first, second) => (first, Some(second)),
        }
    }

    #[test]
    fn decode_direct_source_major_residuals_match_row_major_reference() {
        let cx = Cx::for_testing();
        let k = 16_u32;
        let block_size = 257_u32;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(7);
        let first = BlockNumber(0);
        let corrupt = [0_u32, 1];

        let encoded = encode_group(&cx, &device, &uuid, group, first, k, 4).unwrap();
        let repair_data: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .iter()
            .map(|symbol| (symbol.esi, symbol.data.clone()))
            .collect();
        let corrupt_set = CorruptIndexSet::new(&corrupt, k, group).unwrap();
        let known_source = read_known_source_symbols(
            &cx,
            &device,
            first,
            k,
            &corrupt_set,
            usize::try_from(block_size).expect("block size fits usize"),
        )
        .unwrap();
        let decoder = InactivationDecoder::new(
            usize::try_from(k).expect("K fits usize"),
            usize::try_from(block_size).expect("block size fits usize"),
            encoded.seed,
        );
        let source_coefficient_encoder = build_source_coefficient_encoder(
            usize::try_from(k).expect("K fits usize"),
            encoded.seed,
        )
        .expect("source coefficient encoder");
        let block_size_usize = usize::try_from(block_size).expect("block size fits usize");
        let mut reference_known_source =
            vec![vec![0_u8; block_size_usize]; usize::try_from(k).expect("K fits usize")];
        for symbol in &known_source {
            reference_known_source[symbol.source_index] = symbol.data.clone();
        }

        let actual = select_direct_repair_plan(
            &decoder,
            &corrupt_set.unique,
            &repair_data,
            usize::try_from(k).expect("K fits usize"),
            &known_source,
            &source_coefficient_encoder,
            block_size_usize,
        )
        .expect("source-major plan should be selected");
        let expected_rows = reference_direct_rows_row_major(
            &decoder,
            &corrupt_set.unique,
            &repair_data,
            &reference_known_source,
            &source_coefficient_encoder,
            block_size_usize,
        );
        let (first_row, second_row) = select_full_rank_pair(&expected_rows).expect("full rank");
        let expected_selection = DirectRepairSelection::Two(first_row, second_row);

        assert_eq!(
            direct_selection_signature(&actual.selection),
            direct_selection_signature(&expected_selection)
        );
        assert_eq!(actual.rows.len(), expected_rows.len());
        for (actual, expected) in actual.rows.iter().zip(&expected_rows) {
            assert_eq!(actual.coefficients, expected.coefficients);
            assert_eq!(actual.source_count, expected.source_count);
            assert_eq!(
                &actual.source_coefficients[..actual.source_count],
                &expected.source_coefficients[..expected.source_count]
            );
            assert_eq!(actual.residual, expected.residual);
        }
    }

    #[test]
    fn raptorq_decode_golden_report() {
        let cx = Cx::for_testing();
        let k = 16_u32;
        let block_size = 96_u32;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(3);
        let first = BlockNumber(0);
        let corrupt = [5_u32, 0, 5];

        let encoded = encode_group(&cx, &device, &uuid, group, first, k, 4).unwrap();
        let repair_data: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .iter()
            .map(|symbol| (symbol.esi, symbol.data.clone()))
            .collect();
        let outcome =
            decode_group(&cx, &device, &uuid, group, first, k, &corrupt, &repair_data).unwrap();

        println!("RAPTORQ_DECODE_GOLDEN_BEGIN");
        println!(
            "group={} source_block_count={} symbol_size={} seed={} corrupt={:?} complete={} policy_mode={:?} policy_reason={:?}",
            group.0,
            k,
            block_size,
            encoded.seed,
            corrupt,
            outcome.complete,
            outcome.stats.policy_mode,
            outcome.stats.policy_reason
        );
        for recovered in &outcome.recovered {
            println!(
                "recovered block={} data={}",
                recovered.block.0,
                hex_encode(&recovered.data)
            );
        }
        println!("RAPTORQ_DECODE_GOLDEN_END");
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
    fn decode_two_corrupt_blocks_uses_direct_small_erasure_path() {
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

        let corrupt = [0, 1];
        let original_first = make_deterministic_block(0, block_size);
        let original_second = make_deterministic_block(1, block_size);
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
        assert_eq!(outcome.stats.policy_mode, Some("small_erasure_direct"));
        assert_eq!(outcome.recovered[0].block, BlockNumber(0));
        assert_eq!(outcome.recovered[1].block, BlockNumber(1));
        assert_eq!(outcome.recovered[0].data, original_first);
        assert_eq!(outcome.recovered[1].data, original_second);
    }

    #[test]
    fn decode_direct_small_erasure_preserves_duplicate_output_order() {
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

        let corrupt = [5, 0, 5];
        let original_five = make_deterministic_block(5, block_size);
        let original_zero = make_deterministic_block(0, block_size);
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
        assert_eq!(outcome.stats.policy_mode, Some("small_erasure_direct"));
        assert_eq!(outcome.recovered.len(), corrupt.len());
        assert_eq!(outcome.recovered[0].block, BlockNumber(5));
        assert_eq!(outcome.recovered[1].block, BlockNumber(0));
        assert_eq!(outcome.recovered[2].block, BlockNumber(5));
        assert_eq!(outcome.recovered[0].data, original_five);
        assert_eq!(outcome.recovered[1].data, original_zero);
        assert_eq!(outcome.recovered[2].data, outcome.recovered[0].data);
    }

    #[test]
    fn decode_owned_direct_small_erasure_preserves_duplicate_output_order() {
        let cx = Cx::for_testing();
        let k = 16;
        let block_size = 64;
        let device = setup_device(k, block_size);
        let uuid = test_uuid();
        let group = GroupNumber(0);

        let encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, k).unwrap();
        let repair_data: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .into_iter()
            .map(|s| (s.esi, s.data))
            .collect();

        let corrupt = [5, 0, 5];
        let original_five = make_deterministic_block(5, block_size);
        let original_zero = make_deterministic_block(0, block_size);
        let outcome = decode_group_with_owned_repair_symbols(
            &cx,
            &device,
            &uuid,
            group,
            BlockNumber(0),
            k,
            &corrupt,
            repair_data,
        )
        .unwrap();

        assert!(outcome.complete);
        assert_eq!(outcome.stats.policy_mode, Some("small_erasure_direct"));
        assert_eq!(outcome.recovered.len(), corrupt.len());
        assert_eq!(outcome.recovered[0].block, BlockNumber(5));
        assert_eq!(outcome.recovered[1].block, BlockNumber(0));
        assert_eq!(outcome.recovered[2].block, BlockNumber(5));
        assert_eq!(outcome.recovered[0].data, original_five);
        assert_eq!(outcome.recovered[1].data, original_zero);
        assert_eq!(outcome.recovered[2].data, outcome.recovered[0].data);
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
