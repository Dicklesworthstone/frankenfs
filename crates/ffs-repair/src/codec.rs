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
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, GroupNumber};
use rayon::prelude::{IntoParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

use crate::symbol::repair_seed;

const RQ_DECODE_WAVEFRONT_BATCH: usize = 4;
const DIRECT_SMALL_ERASURE_MAX_CORRUPT: usize = 2;
const DIRECT_SMALL_ERASURE_MAX_SOURCE_BLOCKS: usize = 64;
const SOURCE_COEFFICIENT_ENCODER_CACHE_CAPACITY: usize = 8;
const PROJECTED_REPAIR_BATCH_SYMBOLS: usize = 8;
const PROJECTED_SOURCE_TILE_BLOCKS: usize = 8;

/// Default RFC 6330 §4.3 sub-block (stripe) source symbol count for large
/// (`128 MiB` = `32,768 × 4 KiB`) block groups.
///
/// Sizing each stripe at `64` blocks (`256 KiB`) keeps the entire stripe hot in
/// L2 cache during SIMD `GF(256)` projection AND ensures 1–2 erasures per
/// stripe hit [`try_direct_small_erasure_decode`] (`DIRECT_SMALL_ERASURE_MAX_SOURCE_BLOCKS = 64`).
pub const DEFAULT_MAX_STRIPE_SOURCE_BLOCKS: u32 = 64;

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

/// One bounded direct encoding operation over an admitted source range.
#[derive(Debug, Clone, Copy)]
pub struct DirectEncodeRequest {
    /// Group identity used for deterministic encoding.
    pub group: GroupNumber,
    /// First source block on the device.
    pub first_block: BlockNumber,
    /// Number of complete source blocks.
    pub source_block_count: u32,
    /// Number of repair symbols to produce.
    pub repair_count: u32,
    /// Maximum estimated encoder working allocation, including its margin.
    pub max_working_bytes: u64,
}

fn direct_encode_parameters(
    source_block_count: u32,
    block_size: u32,
    repair_count: u32,
) -> Result<SystematicParams> {
    if block_size == 0 || block_size > u32::from(u16::MAX) || repair_count == 0 {
        return Err(FfsError::RepairFailed(
            "direct encode requires a nonzero u16 symbol size and nonzero repair count".to_owned(),
        ));
    }
    let source_count = usize::try_from(source_block_count)
        .map_err(|_| FfsError::RepairFailed("direct source count exceeds usize".to_owned()))?;
    let symbol_size = usize::try_from(block_size)
        .map_err(|_| FfsError::RepairFailed("direct symbol size exceeds usize".to_owned()))?;
    let params = SystematicParams::try_for_source_block(source_count, symbol_size)
        .map_err(|error| FfsError::RepairFailed(format!("direct encode parameters: {error:?}")))?;
    let extended_count = u32::try_from(params.k_prime).map_err(|_| {
        FfsError::RepairFailed("direct extended source count exceeds u32".to_owned())
    })?;
    extended_count
        .checked_add(repair_count - 1)
        .ok_or_else(|| {
            FfsError::RepairFailed("direct repair ISI range overflows u32".to_owned())
        })?;
    usize::try_from(repair_count)
        .map_err(|_| FfsError::RepairFailed("direct repair count exceeds usize".to_owned()))?;
    Ok(params)
}

fn direct_workspace_sum(values: &[u64]) -> Result<u64> {
    values.iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or_else(|| FfsError::RepairFailed("direct workspace size overflow".to_owned()))
    })
}

fn direct_workspace_product(count: u64, bytes: u64) -> Result<u64> {
    count
        .checked_mul(bytes)
        .ok_or_else(|| FfsError::RepairFailed("direct workspace size overflow".to_owned()))
}

/// Estimate the peak allocation for the pinned direct systematic encoder.
///
/// This accounts for asupersync 0.5.0's dense matrix and solve copy, three
/// simultaneous RHS/result arrays, retained sources, HDPC scratch, vector
/// headers, pivots, and repair output. The maximum of construction, solving,
/// encoder retention, source reading, and one-at-a-time emission receives a
/// 25% margin plus 64 KiB for allocation bookkeeping and small temporaries.
/// Device-owned buffers, caller-owned validation records, allocator retention,
/// and unrelated tasks are outside this estimate: it is not a process-RSS cap.
/// Revisit this accounting when upgrading the encoder implementation.
///
/// # Errors
/// Rejects unsupported RFC parameters, unrepresentable symbol geometry or ESI
/// ranges, zero counts/sizes, and arithmetic overflow before any source I/O.
pub fn direct_encode_workspace_bytes(
    source_block_count: u32,
    block_size: u32,
    repair_count: u32,
) -> Result<u64> {
    let params = direct_encode_parameters(source_block_count, block_size, repair_count)?;
    let intermediate_count = u64::try_from(params.l)
        .map_err(|_| FfsError::RepairFailed("direct intermediate count exceeds u64".to_owned()))?;
    let hdpc_count = u64::try_from(params.h)
        .map_err(|_| FfsError::RepairFailed("direct HDPC count exceeds u64".to_owned()))?;
    let non_hdpc_count = intermediate_count.checked_sub(hdpc_count).ok_or_else(|| {
        FfsError::RepairFailed("direct HDPC geometry exceeds intermediate count".to_owned())
    })?;
    let symbol_size = u64::from(block_size);
    let vector_bytes = size_of::<Vec<u8>>() as u64;
    let index_bytes = size_of::<usize>() as u64;
    let emitted_bytes = size_of::<EmittedSymbol>() as u64;
    let row_bytes = direct_workspace_sum(&[symbol_size, vector_bytes])?;
    let source_rows = direct_workspace_product(u64::from(source_block_count), row_bytes)?;
    let intermediate_rows = direct_workspace_product(intermediate_count, row_bytes)?;
    let matrix = direct_workspace_product(intermediate_count, intermediate_count)?;

    // Gf256 is repr(transparent) over u8. Construction's HDPC buffer is
    // H*(K'+S); temporary LT indices cannot exceed the L-column domain.
    let construction = direct_workspace_sum(&[
        source_rows,
        matrix,
        direct_workspace_product(
            hdpc_count,
            direct_workspace_sum(&[non_hdpc_count, vector_bytes])?,
        )?,
        direct_workspace_product(intermediate_count, index_bytes)?,
    ])?;
    let solving = direct_workspace_sum(&[
        source_rows,
        direct_workspace_product(2, matrix)?,
        direct_workspace_product(3, intermediate_rows)?,
        direct_workspace_product(
            intermediate_count,
            direct_workspace_sum(&[index_bytes, 3 * size_of::<bool>() as u64])?,
        )?,
    ])?;
    // new() clones the caller's sources while its original matrix and RHS
    // still exist. The solve's working copy has already been released.
    let retention = direct_workspace_sum(&[
        direct_workspace_product(2, source_rows)?,
        matrix,
        direct_workspace_product(2, intermediate_rows)?,
    ])?;
    // Caller source rows are dropped before emitting. Allow an additional
    // single-symbol batch and its temporary buffer alongside the full output.
    let emission = direct_workspace_sum(&[
        source_rows,
        intermediate_rows,
        direct_workspace_product(
            u64::from(repair_count),
            direct_workspace_sum(&[symbol_size, emitted_bytes])?,
        )?,
        direct_workspace_product(2, direct_workspace_sum(&[symbol_size, emitted_bytes])?)?,
    ])?;
    let reading = direct_workspace_sum(&[source_rows, direct_workspace_product(2, symbol_size)?])?;
    let peak = construction
        .max(solving)
        .max(retention)
        .max(emission)
        .max(reading);
    direct_workspace_sum(&[peak, peak.div_ceil(4), 64 * 1024])
}

/// Encode directly from source data without the global coefficient cache.
///
/// Admits parameters, device bounds, and the working allocation estimate before
/// reading sources. Reads must return complete rows. Cancellation is checked
/// around each read, around the solve, and for each emitted symbol. The pinned
/// synchronous solve itself has no cancellation checkpoint.
///
/// This does not validate source digests or establish freshness; native callers
/// must provide that authority for the exact source bytes read by this device.
///
/// # Errors
/// Returns an error for invalid geometry, insufficient working budget, malformed
/// source rows, device failures, cancellation, or unsuccessful encoding.
pub fn encode_group_direct(
    cx: &Cx,
    device: &dyn BlockDevice,
    fs_uuid: &[u8; 16],
    request: DirectEncodeRequest,
) -> Result<EncodedGroup> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    let block_size = device.block_size();
    let required = direct_encode_workspace_bytes(
        request.source_block_count,
        block_size,
        request.repair_count,
    )?;
    if required > request.max_working_bytes {
        return Err(FfsError::RepairFailed(format!(
            "direct encode working budget exceeded: required={required} allowed={}",
            request.max_working_bytes
        )));
    }
    let end = request
        .first_block
        .0
        .checked_add(u64::from(request.source_block_count))
        .ok_or_else(|| FfsError::RepairFailed("direct source block range overflows".to_owned()))?;
    if end > device.block_count() || end.checked_mul(u64::from(block_size)).is_none() {
        return Err(FfsError::RepairFailed(
            "direct source range exceeds device or byte-address bounds".to_owned(),
        ));
    }
    let source_symbols = read_direct_source_symbols(cx, device, &request, block_size)?;
    let seed = repair_seed(fs_uuid, request.group);
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    let mut encoder = SystematicEncoder::new(&source_symbols, block_size as usize, seed)
        .ok_or_else(|| {
            FfsError::RepairFailed(format!(
                "direct encode constraint matrix singular for group {}",
                request.group.0
            ))
        })?;
    drop(source_symbols);
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    let mut repair_symbols = Vec::new();
    repair_symbols
        .try_reserve_exact(request.repair_count as usize)
        .map_err(|error| FfsError::RepairFailed(format!("direct repair allocation: {error}")))?;
    for index in 0..request.repair_count {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let mut batch = encoder.emit_repair(1);
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        if batch.len() != 1 {
            return Err(FfsError::RepairFailed(
                "direct encoder did not emit the requested symbol".to_owned(),
            ));
        }
        let symbol = batch.pop().expect("one emitted symbol");
        if symbol.esi != request.source_block_count + index
            || symbol.is_source
            || symbol.data.len() != block_size as usize
        {
            return Err(FfsError::RepairFailed(
                "direct encoder returned inconsistent symbol geometry".to_owned(),
            ));
        }
        repair_symbols.push(symbol);
    }
    Ok(EncodedGroup {
        group: request.group,
        source_block_count: request.source_block_count,
        symbol_size: block_size,
        seed,
        repair_symbols,
    })
}

fn read_direct_source_symbols(
    cx: &Cx,
    device: &dyn BlockDevice,
    request: &DirectEncodeRequest,
    block_size: u32,
) -> Result<Vec<Vec<u8>>> {
    let mut source_symbols = Vec::new();
    source_symbols
        .try_reserve_exact(request.source_block_count as usize)
        .map_err(|error| FfsError::RepairFailed(format!("direct source allocation: {error}")))?;
    for index in 0..u64::from(request.source_block_count) {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        // The complete block and byte ranges were checked before the first read.
        let block = BlockNumber(request.first_block.0 + index);
        let row = device.read_block(cx, block)?;
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        if row.len() != block_size as usize {
            return Err(FfsError::RepairFailed(format!(
                "direct source block {} has {} bytes, expected {block_size}",
                block.0,
                row.len()
            )));
        }
        // Do not inherit arbitrary spare capacity from a device-owned buffer.
        // The encoder's retained source allocation is bounded by these rows.
        source_symbols.push(row.as_slice().to_vec());
    }
    Ok(source_symbols)
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
    let refs: Vec<&[u8]> = source_symbols.iter().map(Vec::as_slice).collect();
    emit_projected_repair_symbols_refs(&refs, block_size, seed, repair_count, group, true)
}

fn emit_projected_repair_batch(
    source_symbols: &[&[u8]],
    block_size: usize,
    coefficient_encoder: &SystematicEncoder,
    params: &SystematicParams,
    start_esi: u32,
    batch_offset: usize,
    batch_len: usize,
) -> Vec<EmittedSymbol> {
    let source_count = source_symbols.len();
    let mut coeff_rows = vec![vec![0_u8; source_count]; batch_len];
    let mut esis = Vec::with_capacity(batch_len);
    for (slot, row) in coeff_rows.iter_mut().enumerate() {
        let esi = start_esi + u32::try_from(batch_offset + slot).unwrap_or(u32::MAX);
        coefficient_encoder.repair_symbol_into(esi, row);
        esis.push(esi);
    }

    let mut outputs = vec![vec![0_u8; block_size]; batch_len];
    for tile_start in (0..source_count).step_by(PROJECTED_SOURCE_TILE_BLOCKS) {
        let tile_end = (tile_start + PROJECTED_SOURCE_TILE_BLOCKS).min(source_count);
        for (src_idx, &source_symbol) in source_symbols[tile_start..tile_end]
            .iter()
            .enumerate()
            .map(|(off, sym)| (tile_start + off, sym))
        {
            for (out_idx, output) in outputs.iter_mut().enumerate() {
                let coefficient = Gf256::new(coeff_rows[out_idx][src_idx]);
                if coefficient.is_zero() {
                    continue;
                }
                if coefficient == Gf256::ONE {
                    gf256_add_slice(output, source_symbol);
                } else {
                    gf256_addmul_slice(output, source_symbol, coefficient);
                }
            }
        }
    }

    outputs
        .into_iter()
        .zip(esis)
        .map(|(data, esi)| EmittedSymbol {
            esi,
            data,
            is_source: false,
            degree: raptorq_repair_symbol_degree(params, esi),
        })
        .collect()
}

fn emit_projected_repair_symbols_refs(
    source_symbols: &[&[u8]],
    block_size: usize,
    seed: u64,
    repair_count: usize,
    group: GroupNumber,
    parallel_batches: bool,
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
    let valid_count = repair_count.min(
        usize::try_from(u32::MAX - start_esi)
            .unwrap_or(usize::MAX)
            .saturating_add(1),
    );
    if valid_count == 0 {
        return Ok(Vec::new());
    }

    let batch_count = valid_count.div_ceil(PROJECTED_REPAIR_BATCH_SYMBOLS);
    if parallel_batches && batch_count > 1 {
        let symbols = (0..batch_count)
            .into_par_iter()
            .flat_map_iter(|batch_idx| {
                let batch_offset = batch_idx * PROJECTED_REPAIR_BATCH_SYMBOLS;
                let batch_len = (valid_count - batch_offset).min(PROJECTED_REPAIR_BATCH_SYMBOLS);
                emit_projected_repair_batch(
                    source_symbols,
                    block_size,
                    &coefficient_encoder,
                    params,
                    start_esi,
                    batch_offset,
                    batch_len,
                )
            })
            .collect();
        Ok(symbols)
    } else {
        let mut symbols = Vec::with_capacity(valid_count);
        for batch_idx in 0..batch_count {
            let batch_offset = batch_idx * PROJECTED_REPAIR_BATCH_SYMBOLS;
            let batch_len = (valid_count - batch_offset).min(PROJECTED_REPAIR_BATCH_SYMBOLS);
            symbols.extend(emit_projected_repair_batch(
                source_symbols,
                block_size,
                &coefficient_encoder,
                params,
                start_esi,
                batch_offset,
                batch_len,
            ));
        }
        Ok(symbols)
    }
}

/// One modified source block for incremental `GF(256)` parity refresh.
#[derive(Debug, Clone, Copy)]
pub struct BlockDelta<'a> {
    /// Zero-based index of the modified source block within the encoded group.
    pub source_index: u32,
    /// Previous bytes of the source block before mutation.
    pub old_block: &'a [u8],
    /// Updated bytes of the source block after mutation.
    pub new_block: &'a [u8],
}

/// Incrementally update `encoded`'s repair symbols in place for sparse block
/// mutations using systematic RaptorQ's `GF(256)` linearity:
/// `R_new[esi] = R_old[esi] ^ sum_i G[esi, idx_i] * (old_i ^ new_i)`.
///
/// The resulting repair symbols are bit-for-bit identical to running a full
/// [`encode_group`] over the post-mutation block group, while doing `O(|deltas| * R)`
/// SIMD slice operations instead of `O(K * R)`.
///
/// # Errors
///
/// Returns [`FfsError::RepairFailed`] if any delta index is out of bounds, block
/// lengths do not match `encoded.symbol_size`, or the systematic coefficient
/// matrix cannot be constructed.
pub fn update_encoded_group_delta(
    encoded: &mut EncodedGroup,
    deltas: &[BlockDelta<'_>],
) -> Result<()> {
    let symbol_size = usize::try_from(encoded.symbol_size)
        .map_err(|_| FfsError::RepairFailed("encoded symbol_size exceeds usize".to_owned()))?;
    let source_count = usize::try_from(encoded.source_block_count)
        .map_err(|_| FfsError::RepairFailed("encoded source count exceeds usize".to_owned()))?;

    if deltas.is_empty() || encoded.repair_symbols.is_empty() {
        for delta in deltas {
            if delta.source_index >= encoded.source_block_count {
                return Err(FfsError::RepairFailed(format!(
                    "delta source_index {} out of range for K={}",
                    delta.source_index, encoded.source_block_count
                )));
            }
            if delta.old_block.len() != symbol_size || delta.new_block.len() != symbol_size {
                return Err(FfsError::RepairFailed(format!(
                    "delta block length mismatch: expected {symbol_size}, got old={} new={}",
                    delta.old_block.len(),
                    delta.new_block.len()
                )));
            }
        }
        return Ok(());
    }

    let mut coalesced: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
    for delta in deltas {
        if delta.source_index >= encoded.source_block_count {
            return Err(FfsError::RepairFailed(format!(
                "delta source_index {} out of range for K={}",
                delta.source_index, encoded.source_block_count
            )));
        }
        if delta.old_block.len() != symbol_size || delta.new_block.len() != symbol_size {
            return Err(FfsError::RepairFailed(format!(
                "delta block length mismatch: expected {symbol_size}, got old={} new={}",
                delta.old_block.len(),
                delta.new_block.len()
            )));
        }
        let idx = usize::try_from(delta.source_index)
            .map_err(|_| FfsError::RepairFailed("delta source_index exceeds usize".to_owned()))?;
        let acc = coalesced
            .entry(idx)
            .or_insert_with(|| vec![0_u8; symbol_size]);
        gf256_add_slice(acc, delta.old_block);
        gf256_add_slice(acc, delta.new_block);
    }

    let active_diffs: Vec<(usize, Vec<u8>)> = coalesced
        .into_iter()
        .filter(|(_, diff)| diff.iter().any(|&byte| byte != 0))
        .collect();
    if active_diffs.is_empty() {
        return Ok(());
    }

    let coefficient_encoder = build_source_coefficient_encoder(source_count, encoded.seed)
        .ok_or_else(|| {
            FfsError::RepairFailed(format!(
                "constraint matrix singular for group {} (K={source_count})",
                encoded.group.0
            ))
        })?;

    let apply_to_symbol = |symbol: &mut EmittedSymbol| {
        let mut coefficients = vec![0_u8; source_count];
        coefficient_encoder.repair_symbol_into(symbol.esi, &mut coefficients);
        for &(src_idx, ref diff) in &active_diffs {
            let coefficient = Gf256::new(coefficients[src_idx]);
            if coefficient.is_zero() {
                continue;
            }
            if coefficient == Gf256::ONE {
                gf256_add_slice(&mut symbol.data, diff);
            } else {
                gf256_addmul_slice(&mut symbol.data, diff, coefficient);
            }
        }
    };

    if encoded.repair_symbols.len() >= 16 {
        encoded
            .repair_symbols
            .par_iter_mut()
            .for_each(apply_to_symbol);
    } else {
        encoded.repair_symbols.iter_mut().for_each(apply_to_symbol);
    }
    Ok(())
}

/// Configuration for RFC 6330 §4.3 block-interleaved striped RaptorQ encoding of
/// full `128 MiB` (`32,768 × 4 KiB`) filesystem block groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StripedGroupConfig {
    /// Maximum source blocks per stripe (`K_stripe`, default `64`).
    pub max_stripe_blocks: u32,
    /// Number of repair symbols emitted per stripe (`R_stripe`, default `4`).
    pub repair_blocks_per_stripe: u32,
}

impl Default for StripedGroupConfig {
    fn default() -> Self {
        Self {
            max_stripe_blocks: DEFAULT_MAX_STRIPE_SOURCE_BLOCKS,
            repair_blocks_per_stripe: 4,
        }
    }
}

impl StripedGroupConfig {
    /// Build a striped configuration targeting at least `overhead_pct` percent
    /// parity redundancy per stripe.
    #[must_use]
    pub const fn for_overhead_pct(max_stripe_blocks: u32, overhead_pct: u32) -> Self {
        let numerator = (max_stripe_blocks as u64) * (overhead_pct as u64);
        let repair_u64 = numerator.div_ceil(100);
        let repair = if repair_u64 == 0 {
            1
        } else if repair_u64 > u32::MAX as u64 {
            u32::MAX
        } else {
            repair_u64 as u32
        };
        Self {
            max_stripe_blocks,
            repair_blocks_per_stripe: repair,
        }
    }
}

/// Encoded repair state for a single interleaved sub-block stripe.
#[derive(Debug, Clone)]
pub struct StripedRepairStripe {
    /// Stripe index `s` in `0..stripe_count` (owns offsets `s + slot * stripe_count`).
    pub stripe_index: u32,
    /// Number of source blocks mapped into this stripe (`K_s`).
    pub source_block_count: u32,
    /// Deterministic RaptorQ seed for this stripe.
    pub seed: u64,
    /// Emitted repair symbols for this stripe (`ESI >= K_s`).
    pub repair_symbols: Vec<EmittedSymbol>,
}

/// Encoded RFC 6330 §4.3 block-interleaved striped repair state for an entire
/// block group (such as a `128 MiB` = `32,768 × 4 KiB` ext4 block group).
#[derive(Debug, Clone)]
pub struct StripedEncodedGroup {
    /// Block group identifier.
    pub group: GroupNumber,
    /// First physical block covered by this group.
    pub first_block: BlockNumber,
    /// Total source blocks across all stripes (`K_total`).
    pub total_source_blocks: u32,
    /// Number of interleaved stripes (`Z`).
    pub stripe_count: u32,
    /// Block size in bytes.
    pub symbol_size: u32,
    /// Per-stripe repair symbol sets in `0..stripe_count` order.
    pub stripes: Vec<StripedRepairStripe>,
}

impl StripedEncodedGroup {
    /// Total repair symbols emitted across all stripes.
    #[must_use]
    pub fn total_repair_symbols(&self) -> usize {
        self.stripes.iter().map(|s| s.repair_symbols.len()).sum()
    }
}

enum GroupSourceStorage {
    Contiguous { bytes: Vec<u8>, block_size: usize },
    Blocks(Vec<BlockBuf>),
}

impl GroupSourceStorage {
    #[inline]
    fn block_slice(&self, index: usize) -> &[u8] {
        match self {
            Self::Contiguous { bytes, block_size } => {
                let start = index * *block_size;
                &bytes[start..start + *block_size]
            }
            Self::Blocks(blocks) => blocks[index].as_slice(),
        }
    }
}

fn read_group_blocks_fast(
    cx: &Cx,
    device: &dyn BlockDevice,
    first_block: BlockNumber,
    source_block_count: u32,
) -> Result<GroupSourceStorage> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    let count_u64 = u64::from(source_block_count);
    if count_u64 == 0 {
        return Ok(GroupSourceStorage::Blocks(Vec::new()));
    }
    let last_block = first_block.0.checked_add(count_u64 - 1).ok_or_else(|| {
        FfsError::RepairFailed(format!(
            "encode_group_striped: block address overflow at first_block={} + count={source_block_count}",
            first_block.0
        ))
    })?;
    let block_size = usize::try_from(device.block_size()).map_err(|_| {
        FfsError::Format("encode_group_striped: block size exceeds usize".to_owned())
    })?;
    let source_count = usize::try_from(source_block_count).map_err(|_| {
        FfsError::Format("encode_group_striped: source count exceeds usize".to_owned())
    })?;

    if count_u64 > 1
        && device.supports_contiguous_reads()
        && last_block < device.block_count()
        && block_size > 0
    {
        let total_bytes = source_count.checked_mul(block_size).ok_or_else(|| {
            FfsError::Format("encode_group_striped: group byte length overflows usize".to_owned())
        })?;
        let mut bytes = vec![0_u8; total_bytes];
        device.read_contiguous_into(cx, first_block, &mut bytes)?;
        return Ok(GroupSourceStorage::Contiguous { bytes, block_size });
    }

    let mut blocks = Vec::with_capacity(source_count);
    for idx in 0..count_u64 {
        if idx.trailing_zeros() >= 6 {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        }
        blocks.push(device.read_block(cx, BlockNumber(first_block.0 + idx))?);
    }
    Ok(GroupSourceStorage::Blocks(blocks))
}

/// Encode an entire block group (including full `128 MiB` = `32,768 × 4 KiB`
/// groups) using RFC 6330 §4.3 stride-interleaved sub-blocking.
///
/// Block offset `off` (`0..source_block_count`) maps to stripe `off % Z` at
/// intra-stripe slot `off / Z`, dispersing contiguous physical burst erasures
/// evenly across all `Z` stripes while sharing cached systematic generator
/// matrices across Rayon worker threads.
///
/// # Errors
///
/// Returns an error if `config` has zero counts, block reads fail, `cx` is
/// cancelled, or any stripe's systematic matrix is singular.
pub fn encode_group_striped(
    cx: &Cx,
    device: &dyn BlockDevice,
    fs_uuid: &[u8; 16],
    group: GroupNumber,
    first_block: BlockNumber,
    source_block_count: u32,
    config: StripedGroupConfig,
) -> Result<StripedEncodedGroup> {
    if source_block_count == 0
        || config.max_stripe_blocks == 0
        || config.repair_blocks_per_stripe == 0
    {
        return Err(FfsError::RepairFailed(
            "encode_group_striped requires nonzero source, stripe, and repair counts".to_owned(),
        ));
    }
    let block_size = device.block_size();
    let block_size_usize = usize::try_from(block_size)
        .map_err(|_| FfsError::RepairFailed("block_size exceeds usize".to_owned()))?;
    let repair_per_stripe = usize::try_from(config.repair_blocks_per_stripe)
        .map_err(|_| FfsError::RepairFailed("repair_blocks_per_stripe exceeds usize".to_owned()))?;

    let raw_blocks = read_group_blocks_fast(cx, device, first_block, source_block_count)?;
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;

    let stripe_count = source_block_count.div_ceil(config.max_stripe_blocks);
    let stripe_count_usize = usize::try_from(stripe_count)
        .map_err(|_| FfsError::RepairFailed("stripe_count exceeds usize".to_owned()))?;
    let base_k = usize::try_from(source_block_count / stripe_count)
        .map_err(|_| FfsError::RepairFailed("stripe base K exceeds usize".to_owned()))?;
    let remainder = source_block_count % stripe_count;
    let base_seed = repair_seed(fs_uuid, group);

    // Pre-warm the (at most two) distinct stripe matrix sizes once before
    // spawning parallel stripe tasks so worker threads hit the LRU cache.
    if base_k > 0 {
        let _ = build_source_coefficient_encoder(base_k, base_seed).ok_or_else(|| {
            FfsError::RepairFailed(format!(
                "striped constraint matrix singular for group {} (stripe_k={base_k})",
                group.0
            ))
        })?;
    }
    if remainder > 0 {
        let larger_k = base_k + 1;
        let _ = build_source_coefficient_encoder(larger_k, base_seed).ok_or_else(|| {
            FfsError::RepairFailed(format!(
                "striped constraint matrix singular for group {} (stripe_k={larger_k})",
                group.0
            ))
        })?;
    }

    let parallel_inner = stripe_count < 8;
    let stripes: Result<Vec<StripedRepairStripe>> = (0..stripe_count)
        .into_par_iter()
        .map(|stripe_idx| {
            let stripe_k_u32 =
                (source_block_count / stripe_count) + u32::from(stripe_idx < remainder);
            let stripe_k = usize::try_from(stripe_k_u32).expect("u32 fits usize");
            let stripe_usize = usize::try_from(stripe_idx).expect("u32 fits usize");
            let mut stripe_refs = Vec::with_capacity(stripe_k);
            for slot in 0..stripe_k {
                let offset = stripe_usize + slot * stripe_count_usize;
                stripe_refs.push(raw_blocks.block_slice(offset));
            }
            let repair_symbols = emit_projected_repair_symbols_refs(
                &stripe_refs,
                block_size_usize,
                base_seed,
                repair_per_stripe,
                group,
                parallel_inner,
            )?;
            Ok(StripedRepairStripe {
                stripe_index: stripe_idx,
                source_block_count: stripe_k_u32,
                seed: base_seed,
                repair_symbols,
            })
        })
        .collect();

    Ok(StripedEncodedGroup {
        group,
        first_block,
        total_source_blocks: source_block_count,
        stripe_count,
        symbol_size: block_size,
        stripes: stripes?,
    })
}

/// Incrementally update a [`StripedEncodedGroup`] in place for sparse 4 KiB
/// block mutations in `O(|deltas| * R_stripe)` time.
///
/// # Errors
///
/// Returns [`FfsError::RepairFailed`] if any delta index or block size is invalid.
pub fn update_striped_group_delta(
    encoded: &mut StripedEncodedGroup,
    deltas: &[BlockDelta<'_>],
) -> Result<()> {
    if encoded.stripe_count == 0 || encoded.stripes.len() != encoded.stripe_count as usize {
        return Err(FfsError::RepairFailed(
            "invalid striped group geometry".to_owned(),
        ));
    }
    let symbol_size = usize::try_from(encoded.symbol_size)
        .map_err(|_| FfsError::RepairFailed("encoded symbol_size exceeds usize".to_owned()))?;
    if deltas.is_empty() {
        return Ok(());
    }

    let mut per_stripe: BTreeMap<usize, Vec<BlockDelta<'_>>> = BTreeMap::new();
    for delta in deltas {
        if delta.source_index >= encoded.total_source_blocks {
            return Err(FfsError::RepairFailed(format!(
                "striped delta source_index {} out of range for total_source_blocks={}",
                delta.source_index, encoded.total_source_blocks
            )));
        }
        if delta.old_block.len() != symbol_size || delta.new_block.len() != symbol_size {
            return Err(FfsError::RepairFailed(format!(
                "striped delta block length mismatch: expected {symbol_size}, got old={} new={}",
                delta.old_block.len(),
                delta.new_block.len()
            )));
        }
        let stripe_idx = (delta.source_index % encoded.stripe_count) as usize;
        let slot = delta.source_index / encoded.stripe_count;
        per_stripe.entry(stripe_idx).or_default().push(BlockDelta {
            source_index: slot,
            old_block: delta.old_block,
            new_block: delta.new_block,
        });
    }

    for (stripe_idx, stripe_deltas) in per_stripe {
        let stripe = &mut encoded.stripes[stripe_idx];
        let mut temp = EncodedGroup {
            group: encoded.group,
            source_block_count: stripe.source_block_count,
            symbol_size: encoded.symbol_size,
            seed: stripe.seed,
            repair_symbols: std::mem::take(&mut stripe.repair_symbols),
        };
        let res = update_encoded_group_delta(&mut temp, &stripe_deltas);
        stripe.repair_symbols = temp.repair_symbols;
        res?;
    }
    Ok(())
}

struct StripeSliceDevice {
    blocks: Vec<BlockBuf>,
    block_size: u32,
}

impl BlockDevice for StripeSliceDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        let idx = usize::try_from(block.0)
            .map_err(|_| FfsError::RepairFailed("stripe block index exceeds usize".to_owned()))?;
        self.blocks
            .get(idx)
            .cloned()
            .ok_or_else(|| FfsError::RepairFailed(format!("stripe block index {idx} out of range")))
    }

    fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
        Err(FfsError::UnsupportedFeature(
            "StripeSliceDevice is read-only".to_owned(),
        ))
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        u64::try_from(self.blocks.len()).unwrap_or(u64::MAX)
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

/// Reconstruct corrupt blocks in a block-interleaved [`StripedEncodedGroup`].
///
/// Only stripes containing at least one corrupt block perform device reads or
/// erasure solving; stripes with 1–2 erasures and `K_s <= 64` automatically hit
/// the direct O(`K_s`) solver.
///
/// # Errors
///
/// Returns an error if `corrupt_offsets` contains an out-of-range index, device
/// reads fail, or any affected stripe has insufficient repair symbols.
pub fn decode_group_striped(
    cx: &Cx,
    device: &dyn BlockDevice,
    fs_uuid: &[u8; 16],
    encoded: &StripedEncodedGroup,
    corrupt_offsets: &[u32],
) -> Result<DecodeOutcome> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    if encoded.stripe_count == 0 || encoded.stripes.len() != encoded.stripe_count as usize {
        return Err(FfsError::RepairFailed(
            "decode_group_striped: invalid striped group geometry".to_owned(),
        ));
    }
    if corrupt_offsets.is_empty() {
        return Ok(DecodeOutcome {
            recovered: Vec::new(),
            stats: asupersync::raptorq::decoder::DecodeStats::default(),
            complete: true,
        });
    }

    let mut per_stripe: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for &offset in corrupt_offsets {
        if offset >= encoded.total_source_blocks {
            return Err(FfsError::RepairFailed(format!(
                "decode_group_striped: corrupt offset {offset} out of range for total_source_blocks={}",
                encoded.total_source_blocks
            )));
        }
        let stripe_idx = offset % encoded.stripe_count;
        let slot = offset / encoded.stripe_count;
        let slots = per_stripe.entry(stripe_idx).or_default();
        if !slots.contains(&slot) {
            slots.push(slot);
        }
    }

    let block_size_usize = usize::try_from(encoded.symbol_size)
        .map_err(|_| FfsError::RepairFailed("symbol_size exceeds usize".to_owned()))?;
    let mut recovered_by_offset: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut agg_stats = asupersync::raptorq::decoder::DecodeStats::default();

    for (stripe_idx, corrupt_slots) in per_stripe {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let stripe = &encoded.stripes[stripe_idx as usize];
        let stripe_k = stripe.source_block_count;
        let mut stripe_blocks = Vec::with_capacity(stripe_k as usize);
        for slot in 0..stripe_k {
            if corrupt_slots.contains(&slot) {
                stripe_blocks.push(BlockBuf::zeroed(block_size_usize));
            } else {
                let offset =
                    u64::from(stripe_idx) + u64::from(slot) * u64::from(encoded.stripe_count);
                let phys =
                    BlockNumber(encoded.first_block.0.checked_add(offset).ok_or_else(|| {
                        FfsError::RepairFailed(
                            "decode_group_striped: physical block overflow".to_owned(),
                        )
                    })?);
                stripe_blocks.push(device.read_block(cx, phys)?);
            }
        }
        let stripe_dev = StripeSliceDevice {
            blocks: stripe_blocks,
            block_size: encoded.symbol_size,
        };
        let repair_pairs: Vec<(u32, Vec<u8>)> = stripe
            .repair_symbols
            .iter()
            .map(|sym| (sym.esi, sym.data.clone()))
            .collect();
        let outcome = decode_group(
            cx,
            &stripe_dev,
            fs_uuid,
            encoded.group,
            BlockNumber(0),
            stripe_k,
            &corrupt_slots,
            &repair_pairs,
        )?;
        agg_stats.peeled += outcome.stats.peeled;
        agg_stats.inactivated += outcome.stats.inactivated;
        agg_stats.gauss_ops += outcome.stats.gauss_ops;
        for rec in outcome.recovered {
            let slot = u32::try_from(rec.block.0)
                .map_err(|_| FfsError::RepairFailed("recovered slot exceeds u32".to_owned()))?;
            let offset = stripe_idx + slot * encoded.stripe_count;
            recovered_by_offset.insert(offset, rec.data);
        }
    }

    let mut recovered = Vec::with_capacity(corrupt_offsets.len());
    for &offset in corrupt_offsets {
        let data = recovered_by_offset
            .get(&offset)
            .cloned()
            .ok_or_else(|| FfsError::RepairFailed(format!("missing recovered offset {offset}")))?;
        let phys = BlockNumber(
            encoded
                .first_block
                .0
                .checked_add(u64::from(offset))
                .ok_or_else(|| FfsError::RepairFailed("recovered block overflow".to_owned()))?,
        );
        recovered.push(RecoveredBlock { block: phys, data });
    }

    Ok(DecodeOutcome {
        complete: recovered.len() == corrupt_offsets.len(),
        recovered,
        stats: agg_stats,
    })
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
    fn encode_group_direct_matches_projected_symbols() {
        let cx = Cx::for_testing();
        let uuid = test_uuid();
        for (source_count, block_size, first, repair_count) in
            [(16, 257, 0, 6), (64, 1024, 0, 7), (16, 4096, 11, 4)]
        {
            let device = MemBlockDevice::new(block_size, first + u64::from(source_count));
            for block in first..first + u64::from(source_count) {
                device.write(
                    BlockNumber(block),
                    make_deterministic_block(block, block_size),
                );
            }
            let group = GroupNumber(7);
            let expected = encode_group(
                &cx,
                &device,
                &uuid,
                group,
                BlockNumber(first),
                source_count,
                repair_count,
            )
            .unwrap();
            let actual = encode_group_direct(
                &cx,
                &device,
                &uuid,
                DirectEncodeRequest {
                    group,
                    first_block: BlockNumber(first),
                    source_block_count: source_count,
                    repair_count,
                    max_working_bytes: direct_encode_workspace_bytes(
                        source_count,
                        block_size,
                        repair_count,
                    )
                    .unwrap(),
                },
            )
            .unwrap();
            assert_eq!(actual.group, expected.group);
            assert_eq!(actual.seed, expected.seed);
            assert_eq!(actual.source_block_count, expected.source_block_count);
            assert_eq!(actual.symbol_size, expected.symbol_size);
            assert_eq!(actual.repair_symbols.len(), repair_count as usize);
            assert_eq!(actual.repair_symbols.len(), expected.repair_symbols.len());
            for (actual, expected) in actual.repair_symbols.iter().zip(&expected.repair_symbols) {
                assert_eq!(actual.esi, expected.esi);
                assert_eq!(actual.is_source, expected.is_source);
                assert_eq!(actual.degree, expected.degree);
                assert_eq!(actual.data, expected.data);
            }
            assert_eq!(device.read_count(), 2 * source_count as usize);
        }
    }

    #[test]
    fn encode_group_direct_budget_refuses_before_source_io() {
        let cx = Cx::for_testing();
        let device = setup_device(16, 257);
        let required = direct_encode_workspace_bytes(16, 257, 6).unwrap();
        let request = DirectEncodeRequest {
            group: GroupNumber(3),
            first_block: BlockNumber(0),
            source_block_count: 16,
            repair_count: 6,
            max_working_bytes: required - 1,
        };
        let error = encode_group_direct(&cx, &device, &test_uuid(), request).unwrap_err();
        assert!(matches!(error, FfsError::RepairFailed(_)), "{error}");
        assert!(
            error.to_string().contains("working budget exceeded"),
            "{error}"
        );
        assert_eq!(device.read_count(), 0);

        let encoded = encode_group_direct(
            &cx,
            &device,
            &test_uuid(),
            DirectEncodeRequest {
                max_working_bytes: required,
                ..request
            },
        )
        .unwrap();
        assert_eq!(encoded.repair_symbols.len(), 6);
        assert_eq!(device.read_count(), 16);
    }

    #[test]
    fn encode_group_direct_rejects_invalid_geometry_before_source_io() {
        let cx = Cx::for_testing();
        for (source_count, block_size, repair_count, reason) in [
            (0, 64, 4, "parameters"),
            (56_404, 64, 4, "parameters"),
            (16, 0, 4, "nonzero u16 symbol size"),
            (16, 65_536, 4, "nonzero u16 symbol size"),
            (16, 64, 0, "nonzero repair count"),
            (16, 64, u32::MAX, "ISI range overflows"),
        ] {
            assert!(direct_encode_workspace_bytes(source_count, block_size, repair_count).is_err());
            let device = MemBlockDevice::new(block_size, 64);
            let error = encode_group_direct(
                &cx,
                &device,
                &test_uuid(),
                DirectEncodeRequest {
                    group: GroupNumber(0),
                    first_block: BlockNumber(0),
                    source_block_count: source_count,
                    repair_count,
                    max_working_bytes: u64::MAX,
                },
            )
            .unwrap_err();
            assert!(matches!(error, FfsError::RepairFailed(_)), "{error}");
            assert!(error.to_string().contains(reason), "{error}");
            assert_eq!(device.read_count(), 0);
        }
        for (first, blocks, reason) in [
            (u64::MAX, u64::MAX, "block range overflows"),
            (63, 64, "device or byte-address bounds"),
            (u64::MAX / 64, u64::MAX, "device or byte-address bounds"),
        ] {
            let device = MemBlockDevice::new(64, blocks);
            let error = encode_group_direct(
                &cx,
                &device,
                &test_uuid(),
                DirectEncodeRequest {
                    group: GroupNumber(0),
                    first_block: BlockNumber(first),
                    source_block_count: 16,
                    repair_count: 4,
                    max_working_bytes: u64::MAX,
                },
            )
            .unwrap_err();
            assert!(matches!(error, FfsError::RepairFailed(_)), "{error}");
            assert!(error.to_string().contains(reason), "{error}");
            assert_eq!(device.read_count(), 0);
        }
    }

    #[test]
    fn encode_group_direct_rejects_malformed_rows_and_preserves_io_errors() {
        let cx = Cx::for_testing();
        let request = DirectEncodeRequest {
            group: GroupNumber(0),
            first_block: BlockNumber(0),
            source_block_count: 16,
            repair_count: 4,
            max_working_bytes: u64::MAX,
        };
        for malformed_size in [63, 65] {
            let device = setup_device(16, 64);
            device.blocks.lock().insert(2, vec![0; malformed_size]);
            let error = encode_group_direct(&cx, &device, &test_uuid(), request).unwrap_err();
            assert!(matches!(error, FfsError::RepairFailed(_)), "{error}");
            assert!(
                error.to_string().contains(&format!(
                    "source block 2 has {malformed_size} bytes, expected 64"
                )),
                "{error}"
            );
            assert_eq!(device.read_count(), 3, "no reads after the malformed row");
        }
        let device = FailingReadDevice::new(64, vec![2]);
        let error = encode_group_direct(&cx, &device, &test_uuid(), request).unwrap_err();
        assert!(matches!(error, FfsError::Io(_)), "{error}");
        assert_eq!(
            error.to_string(),
            "I/O error: injected read failure at block 2"
        );
        assert_eq!(*device.reads.lock(), vec![0, 1, 2]);
    }

    #[test]
    fn encode_group_direct_observes_cancellation_before_and_during_reads() {
        struct CancelOnRead {
            device: MemBlockDevice,
            cancel_at: BlockNumber,
        }

        impl BlockDevice for CancelOnRead {
            fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
                let row = self.device.read_block(cx, block)?;
                if block == self.cancel_at {
                    cx.set_cancel_requested(true);
                }
                Ok(row)
            }

            fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
                Err(FfsError::ReadOnly)
            }

            fn block_size(&self) -> u32 {
                self.device.block_size()
            }

            fn block_count(&self) -> u64 {
                self.device.block_count()
            }

            fn sync(&self, _cx: &Cx) -> Result<()> {
                Err(FfsError::ReadOnly)
            }
        }

        let request = DirectEncodeRequest {
            group: GroupNumber(0),
            first_block: BlockNumber(0),
            source_block_count: 16,
            repair_count: 4,
            max_working_bytes: u64::MAX,
        };
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let device = setup_device(16, 64);
        assert!(matches!(
            encode_group_direct(&cx, &device, &test_uuid(), request),
            Err(FfsError::Cancelled)
        ));
        assert_eq!(device.read_count(), 0);
        for cancel_at in [0, 15] {
            let cx = Cx::for_testing();
            let device = CancelOnRead {
                device: setup_device(16, 64),
                cancel_at: BlockNumber(cancel_at),
            };
            assert!(matches!(
                encode_group_direct(&cx, &device, &test_uuid(), request),
                Err(FfsError::Cancelled)
            ));
            assert_eq!(device.device.read_count(), cancel_at as usize + 1);
        }
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

    #[test]
    fn tiled_projection_matches_direct_systematic_encoder_bit_for_bit() {
        let cx = Cx::for_testing();
        let uuid = test_uuid();
        let group = GroupNumber(3);
        for (k, r, block_size) in [(17_u32, 9_u32, 256_u32), (64_u32, 19_u32, 4096_u32)] {
            let device = setup_device(k, block_size);
            let tiled = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, r)
                .expect("tiled encode_group");
            let direct = encode_group_direct(
                &cx,
                &device,
                &uuid,
                DirectEncodeRequest {
                    group,
                    first_block: BlockNumber(0),
                    source_block_count: k,
                    repair_count: r,
                    max_working_bytes: 256 * 1024 * 1024,
                },
            )
            .expect("direct encode_group");
            assert_eq!(tiled.repair_symbols.len(), direct.repair_symbols.len());
            for (lhs, rhs) in tiled.repair_symbols.iter().zip(&direct.repair_symbols) {
                assert_eq!(lhs.esi, rhs.esi);
                assert_eq!(lhs.degree, rhs.degree);
                assert_eq!(lhs.data, rhs.data);
            }
        }
    }

    #[test]
    fn update_encoded_group_delta_matches_full_reencode_and_rejects_bad_bounds() {
        let cx = Cx::for_testing();
        let uuid = test_uuid();
        let group = GroupNumber(11);
        let k = 32_u32;
        let r = 8_u32;
        let block_size = 512_u32;
        let device = setup_device(k, block_size);
        let mut encoded =
            encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, r).expect("initial encode");

        let old_5 = device.read_block(&cx, BlockNumber(5)).unwrap().into_inner();
        let old_21 = device
            .read_block(&cx, BlockNumber(21))
            .unwrap()
            .into_inner();
        let mid_5: Vec<u8> = (0..block_size as usize)
            .map(|i| u8::try_from((i * 7 + 3) & 0xFF).unwrap())
            .collect();
        let new_5: Vec<u8> = (0..block_size as usize)
            .map(|i| u8::try_from((i * 13 + 91) & 0xFF).unwrap())
            .collect();
        let new_21: Vec<u8> = (0..block_size as usize)
            .map(|i| u8::try_from((i * 29 + 17) & 0xFF).unwrap())
            .collect();

        device.write_block(&cx, BlockNumber(5), &new_5).unwrap();
        device.write_block(&cx, BlockNumber(21), &new_21).unwrap();

        // Exercise chained updates on the same source_index (5: old -> mid -> new)
        // plus an independent update on source_index 21.
        update_encoded_group_delta(
            &mut encoded,
            &[
                BlockDelta {
                    source_index: 5,
                    old_block: &old_5,
                    new_block: &mid_5,
                },
                BlockDelta {
                    source_index: 5,
                    old_block: &mid_5,
                    new_block: &new_5,
                },
                BlockDelta {
                    source_index: 21,
                    old_block: &old_21,
                    new_block: &new_21,
                },
            ],
        )
        .expect("delta update must succeed");

        let fresh = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, r)
            .expect("fresh re-encode");
        for (inc, full) in encoded.repair_symbols.iter().zip(&fresh.repair_symbols) {
            assert_eq!(inc.esi, full.esi);
            assert_eq!(inc.data, full.data);
        }

        // Negative cases: out-of-range source_index and mismatched block size.
        assert!(
            update_encoded_group_delta(
                &mut encoded,
                &[BlockDelta {
                    source_index: k,
                    old_block: &old_5,
                    new_block: &new_5,
                }],
            )
            .is_err()
        );
        assert!(
            update_encoded_group_delta(
                &mut encoded,
                &[BlockDelta {
                    source_index: 0,
                    old_block: &old_5[..16],
                    new_block: &new_5,
                }],
            )
            .is_err()
        );
    }

    #[test]
    fn striped_group_recovers_contiguous_burst_erasure_and_incremental_delta() {
        let cx = Cx::for_testing();
        let uuid = test_uuid();
        let group = GroupNumber(2);
        let k_total = 520_u32; // intentionally non-multiple of 64 (9 stripes: 8x58 + 1x56)
        let block_size = 512_u32;
        let device = setup_device(k_total, block_size);
        let config = StripedGroupConfig {
            max_stripe_blocks: 64,
            repair_blocks_per_stripe: 4,
        };

        let mut striped =
            encode_group_striped(&cx, &device, &uuid, group, BlockNumber(0), k_total, config)
                .expect("striped encode");

        // Apply sparse delta on 3 blocks across different stripes and verify parity matches fresh encode.
        let mut deltas_owned = Vec::new();
        for &idx in &[0_u32, 259_u32, 519_u32] {
            let old_b = device
                .read_block(&cx, BlockNumber(u64::from(idx)))
                .unwrap()
                .into_inner();
            let new_b: Vec<u8> = old_b
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ u8::try_from((i + idx as usize + 1) & 0xFF).unwrap())
                .collect();
            device
                .write_block(&cx, BlockNumber(u64::from(idx)), &new_b)
                .unwrap();
            deltas_owned.push((idx, old_b, new_b));
        }
        let delta_refs: Vec<BlockDelta<'_>> = deltas_owned
            .iter()
            .map(|(idx, old_b, new_b)| BlockDelta {
                source_index: *idx,
                old_block: old_b,
                new_block: new_b,
            })
            .collect();
        update_striped_group_delta(&mut striped, &delta_refs).expect("striped delta update");

        let fresh_striped =
            encode_group_striped(&cx, &device, &uuid, group, BlockNumber(0), k_total, config)
                .expect("fresh striped encode");
        for (lhs_s, rhs_s) in striped.stripes.iter().zip(&fresh_striped.stripes) {
            for (lhs_sym, rhs_sym) in lhs_s.repair_symbols.iter().zip(&rhs_s.repair_symbols) {
                assert_eq!(lhs_sym.data, rhs_sym.data);
            }
        }

        // Wipe a contiguous 27-block burst (3 erasures in each of the 9 stripes)
        // and verify bit-identical recovery of all 27 blocks!
        let burst_start = 100_u32;
        let burst_len = 27_u32;
        let mut expected = Vec::new();
        let mut corrupt_offsets = Vec::new();
        let zeroes = vec![0_u8; block_size as usize];
        for off in burst_start..burst_start + burst_len {
            expected.push(
                device
                    .read_block(&cx, BlockNumber(u64::from(off)))
                    .unwrap()
                    .into_inner(),
            );
            device
                .write_block(&cx, BlockNumber(u64::from(off)), &zeroes)
                .unwrap();
            corrupt_offsets.push(off);
        }

        let decoded = decode_group_striped(&cx, &device, &uuid, &striped, &corrupt_offsets)
            .expect("striped burst decode must succeed");
        assert!(decoded.complete);
        assert_eq!(decoded.recovered.len(), burst_len as usize);
        for (rec, exp) in decoded.recovered.iter().zip(&expected) {
            assert_eq!(&rec.data, exp);
        }
    }

    mod delta_proptests {
        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(24))]

            #[test]
            fn prop_sparse_delta_parity_bit_identical_to_full_encode(
                k in 8_u32..=40,
                r in 1_u32..=8,
                mutations in prop::collection::vec((0_usize..40, any::<u8>()), 1..=6),
            ) {
                let cx = Cx::for_testing();
                let uuid = test_uuid();
                let group = GroupNumber(5);
                let block_size = 128_u32;
                let device = setup_device(k, block_size);
                let mut encoded = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, r)
                    .expect("encode_group");

                let mut owned = Vec::new();
                for (raw_idx, mask) in mutations {
                    let idx = u32::try_from(raw_idx % (k as usize)).unwrap();
                    let old_bytes = device
                        .read_block(&cx, BlockNumber(u64::from(idx)))
                        .unwrap()
                        .into_inner();
                    let new_bytes: Vec<u8> = old_bytes
                        .iter()
                        .enumerate()
                        .map(|(pos, &b)| b ^ mask.wrapping_add(u8::try_from(pos & 0xFF).unwrap()))
                        .collect();
                    device
                        .write_block(&cx, BlockNumber(u64::from(idx)), &new_bytes)
                        .unwrap();
                    owned.push((idx, old_bytes, new_bytes));
                }
                let refs: Vec<BlockDelta<'_>> = owned
                    .iter()
                    .map(|(idx, old_b, new_b)| BlockDelta {
                        source_index: *idx,
                        old_block: old_b,
                        new_block: new_b,
                    })
                    .collect();
                update_encoded_group_delta(&mut encoded, &refs).expect("delta update");

                let full = encode_group(&cx, &device, &uuid, group, BlockNumber(0), k, r)
                    .expect("full encode");
                for (lhs, rhs) in encoded.repair_symbols.iter().zip(&full.repair_symbols) {
                    prop_assert_eq!(lhs.esi, rhs.esi);
                    prop_assert_eq!(&lhs.data, &rhs.data);
                }
            }
        }
    }
}
