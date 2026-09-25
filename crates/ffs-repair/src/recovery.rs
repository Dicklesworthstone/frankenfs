//! Corruption recovery orchestration for one block group.
//!
//! This module wires together:
//! - symbol retrieval (`storage`)
//! - RaptorQ decode (`codec`)
//! - block writeback + verification
//! - structured evidence ledger emission
//!
//! V1 signal model: caller provides explicit corrupt block indices.
//! Full-block recovery loads one integrity-verified raw generation, including
//! surviving parity from degraded reads, and revalidates that generation after
//! decoding. Callers still establish source freshness and exclude concurrent
//! writers; integrity and observation checks are not an atomic storage fence.

mod erasure;

pub use erasure::ErasureRecoveryWritebackBlock;

use asupersync::Cx;
use asupersync::raptorq::decoder::DecodeStats;
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, GroupNumber};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::codec::{DecodeOutcome, decode_group_with_owned_repair_symbols};
use crate::scrub::{BlockValidator, BlockVerdict};
use crate::storage::{RepairGroupLayout, RepairGroupStorage};
use crate::symbol::RepairGroupDescExt;

/// Recovered block plus the bytes observed when repair planning began.
///
/// Mounted read-write repair uses `expected_current` as the compare side of a
/// compare-and-write gate. If the mounted view changed after scrub detected the
/// corrupt block, the writeback authority must fail closed instead of
/// overwriting newer client data.
#[derive(Debug, Clone, Copy)]
pub struct RecoveryWritebackBlock<'a> {
    pub block: BlockNumber,
    pub expected_current: &'a [u8],
    pub data: &'a [u8],
}

/// Authority used to make recovered blocks durable.
pub trait RecoveryWriteback: Send + Sync + std::fmt::Debug {
    fn writeback_recovered(
        &self,
        cx: &Cx,
        device: &dyn BlockDevice,
        recovered: &[RecoveryWritebackBlock<'_>],
    ) -> Result<()>;

    /// Opt in only when unreadability can be checked under this authority's
    /// exclusion contract. Existing mounted serializers remain opted out.
    fn supports_unreadable_targets(&self) -> bool {
        false
    }

    /// Recover targets with explicit readable or unreadable before-images.
    ///
    /// The default must not bypass an existing mounted compare-and-write gate.
    /// An implementation opting in must preflight the entire batch, preserve
    /// readable before-images, and reject a formerly unreadable target that has
    /// become readable before writing. Success requires sync and readback.
    fn writeback_recovered_erasures(
        &self,
        _cx: &Cx,
        _device: &dyn BlockDevice,
        _recovered: &[ErasureRecoveryWritebackBlock<'_>],
    ) -> Result<()> {
        Err(FfsError::RepairFailed(
            "writeback authority does not support unreadable repair targets".to_owned(),
        ))
    }

    fn authority_name(&self) -> &'static str;
}

/// Direct block-device writeback for offline repair or client read-only mounts.
#[derive(Debug, Default)]
pub struct DirectDeviceRecoveryWriteback;

impl RecoveryWriteback for DirectDeviceRecoveryWriteback {
    fn writeback_recovered(
        &self,
        cx: &Cx,
        device: &dyn BlockDevice,
        recovered: &[RecoveryWritebackBlock<'_>],
    ) -> Result<()> {
        use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let block_size = device.block_size() as usize;
        let mut seen = BTreeSet::new();
        // Validate the complete batch before any I/O, not merely at each
        // device write: a malformed later target must not partially apply an
        // otherwise valid earlier target.
        for block in recovered {
            if block_size == 0
                || block.block.0 >= device.block_count()
                || block.expected_current.len() != block_size
                || block.data.len() != block_size
                || !seen.insert(block.block)
            {
                return Err(FfsError::RepairFailed(
                    "invalid or duplicate recovery writeback target".to_owned(),
                ));
            }
        }

        // Pre-write compare-and-write gate: confirm each block still matches the
        // scrub-time bytes. The reads are independent, so overlap them across the
        // rayon pool (a blocking read parks its worker); consume the per-block
        // outcomes in index order so the first compare failure reported is
        // identical to the serial loop's (I/O-overlap, bd-307e4/bd-g5v1s family).
        let gate: Vec<Result<()>> = recovered
            .par_iter()
            .map(|block| {
                cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
                let observed = device.read_block(cx, block.block)?;
                if observed.as_slice() != block.expected_current {
                    return Err(FfsError::RepairFailed(format!(
                        "recovery writeback compare failed at block {}",
                        block.block.0
                    )));
                }
                Ok(())
            })
            .collect();
        for outcome in gate {
            outcome?;
        }
        // Writes stay serial: the gate has passed, and write ordering / durability
        // semantics are left untouched.
        for block in recovered {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            device.write_block(cx, block.block, block.data)?;
        }
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        device.sync(cx)?;
        // Post-repair verification: same independent-read overlap as the gate.
        let verify: Vec<Result<()>> = recovered
            .par_iter()
            .map(|block| {
                let observed = device.read_block(cx, block.block)?;
                if observed.as_slice() != block.data {
                    return Err(FfsError::RepairFailed(format!(
                        "post-repair verification failed at block {}",
                        block.block.0
                    )));
                }
                Ok(())
            })
            .collect();
        for outcome in verify {
            outcome?;
        }
        cx.checkpoint().map_err(|_| FfsError::Cancelled)
    }

    fn supports_unreadable_targets(&self) -> bool {
        true
    }

    fn writeback_recovered_erasures(
        &self,
        cx: &Cx,
        device: &dyn BlockDevice,
        recovered: &[ErasureRecoveryWritebackBlock<'_>],
    ) -> Result<()> {
        erasure::writeback_direct(cx, device, recovered)
    }

    fn authority_name(&self) -> &'static str {
        "direct_device"
    }
}

static DIRECT_DEVICE_RECOVERY_WRITEBACK: DirectDeviceRecoveryWriteback =
    DirectDeviceRecoveryWriteback;

/// Decode stats captured in the recovery evidence ledger.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryDecoderStats {
    pub peeled: usize,
    pub inactivated: usize,
    pub gauss_ops: usize,
    pub pivots_selected: usize,
}

impl From<&DecodeStats> for RecoveryDecoderStats {
    fn from(stats: &DecodeStats) -> Self {
        Self {
            peeled: stats.peeled,
            inactivated: stats.inactivated,
            gauss_ops: stats.gauss_ops,
            pivots_selected: stats.pivots_selected,
        }
    }
}

/// Recovery attempt outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOutcome {
    Recovered,
    Partial,
    Failed,
}

/// Structured recovery evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryEvidence {
    pub group: u32,
    pub generation: u64,
    pub corrupt_count: usize,
    pub symbols_available: usize,
    pub symbols_used: usize,
    pub decoder_stats: RecoveryDecoderStats,
    pub outcome: RecoveryOutcome,
    pub reason: Option<String>,
}

impl RecoveryEvidence {
    pub fn to_json(&self) -> std::result::Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Result of one recovery attempt.
#[derive(Debug, Clone)]
pub struct RecoveryAttemptResult {
    pub evidence: RecoveryEvidence,
    pub repaired_blocks: Vec<BlockNumber>,
}

impl RecoveryAttemptResult {
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.evidence.outcome == RecoveryOutcome::Recovered
    }
}

/// Recovery orchestrator bound to one group/source region.
pub struct GroupRecoveryOrchestrator<'a> {
    device: &'a dyn BlockDevice,
    writeback: &'a dyn RecoveryWriteback,
    storage: RepairGroupStorage<'a>,
    fs_uuid: [u8; 16],
    source_first_block: BlockNumber,
    source_block_count: u32,
    decoded_block_check: Option<DecodedBlockCheck<'a>>,
}

/// Builds a validator over a device view. Used for decoded-block checks, where
/// the view is the image as it would be after writeback.
pub type DecodedViewValidatorFactory<'a> =
    &'a (dyn Fn(&Cx, &dyn BlockDevice) -> Result<Box<dyn BlockValidator>> + Sync);

#[derive(Clone, Copy)]
enum DecodedBlockCheck<'a> {
    /// A validator whose verdict depends only on the block itself.
    Static(&'a dyn BlockValidator),
    /// A validator built over the post-writeback view, for checks that read
    /// other blocks (ext4 bitmap checksums live in the group descriptors).
    OverDecodedView(DecodedViewValidatorFactory<'a>),
}

/// Read-only view of `inner` with the decoded blocks substituted.
struct DecodedOverlay<'b> {
    inner: &'b dyn BlockDevice,
    decoded: std::collections::HashMap<u64, &'b [u8]>,
}

impl BlockDevice for DecodedOverlay<'_> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        self.decoded.get(&block.0).map_or_else(
            || self.inner.read_block(cx, block),
            |data| Ok(BlockBuf::new(data.to_vec())),
        )
    }

    fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
        Err(FfsError::RepairFailed(
            "decoded-block validation view is read-only".to_owned(),
        ))
    }

    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

impl<'a> GroupRecoveryOrchestrator<'a> {
    /// Check every decoded block with `validator` before any writeback
    /// (bd-jufod). A decode only proves agreement with the stored symbols;
    /// damaged or tampered parity can still decode to bytes that fail the
    /// block's own checksum, and those must never be written over the image.
    #[must_use]
    pub fn with_decoded_block_validator(mut self, validator: &'a dyn BlockValidator) -> Self {
        self.decoded_block_check = Some(DecodedBlockCheck::Static(validator));
        self
    }

    /// Like [`Self::with_decoded_block_validator`], for validators that read
    /// other blocks: `factory` is handed the image as it would be after this
    /// writeback, so a repaired descriptor block and the bitmap it describes
    /// are judged together rather than against the corrupt copy.
    #[must_use]
    pub fn with_decoded_view_validator(mut self, factory: DecodedViewValidatorFactory<'a>) -> Self {
        self.decoded_block_check = Some(DecodedBlockCheck::OverDecodedView(factory));
        self
    }

    /// First decoded block the validator rejects, as a repair failure.
    fn reject_invalid_decoded_blocks(&self, cx: &Cx, decode: &DecodeOutcome) -> Result<()> {
        let Some(check) = self.decoded_block_check else {
            return Ok(());
        };
        let built;
        let validator: &dyn BlockValidator = match check {
            DecodedBlockCheck::Static(validator) => validator,
            DecodedBlockCheck::OverDecodedView(factory) => {
                let overlay = DecodedOverlay {
                    inner: self.device,
                    decoded: decode
                        .recovered
                        .iter()
                        .map(|recovered| (recovered.block.0, recovered.data.as_slice()))
                        .collect(),
                };
                built = factory(cx, &overlay)?;
                &*built
            }
        };
        for recovered in &decode.recovered {
            let data = BlockBuf::new(recovered.data.clone());
            if let BlockVerdict::Corrupt(issues) = validator.validate(recovered.block, &data) {
                let detail = issues
                    .iter()
                    .map(|(kind, _, message)| format!("{kind:?}: {message}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(FfsError::RepairFailed(format!(
                    "decoded block {} fails validation ({detail}); nothing written back",
                    recovered.block.0
                )));
            }
        }
        Ok(())
    }

    /// Create a recovery orchestrator for one source region within a group.
    pub fn new(
        device: &'a dyn BlockDevice,
        fs_uuid: [u8; 16],
        layout: RepairGroupLayout,
        source_first_block: BlockNumber,
        source_block_count: u32,
    ) -> Result<Self> {
        Self::new_with_writeback(
            device,
            &DIRECT_DEVICE_RECOVERY_WRITEBACK,
            fs_uuid,
            layout,
            source_first_block,
            source_block_count,
        )
    }

    pub fn new_with_writeback(
        device: &'a dyn BlockDevice,
        writeback: &'a dyn RecoveryWriteback,
        fs_uuid: [u8; 16],
        layout: RepairGroupLayout,
        source_first_block: BlockNumber,
        source_block_count: u32,
    ) -> Result<Self> {
        if source_block_count == 0 {
            return Err(FfsError::RepairFailed(
                "source_block_count must be > 0".to_owned(),
            ));
        }

        let source_end = source_first_block
            .0
            .checked_add(u64::from(source_block_count))
            .ok_or_else(|| {
                FfsError::RepairFailed("source range overflow for recovery orchestrator".to_owned())
            })?;
        let group_data_end = layout.validation_start_block().0;

        if source_first_block.0 < layout.group_start.0 || source_end > group_data_end {
            return Err(FfsError::RepairFailed(format!(
                "source range [{}, {}) is outside group data region [{}, {}) for group {}",
                source_first_block.0,
                source_end,
                layout.group_start.0,
                group_data_end,
                layout.group.0
            )));
        }

        Ok(Self {
            device,
            writeback,
            storage: RepairGroupStorage::new(device, layout),
            fs_uuid,
            source_first_block,
            source_block_count,
            decoded_block_check: None,
        })
    }

    #[must_use]
    pub fn group(&self) -> GroupNumber {
        self.storage.layout().group
    }

    /// Convert absolute corrupt block numbers to source-relative indices.
    pub fn map_corrupt_blocks_to_indices(
        &self,
        corrupt_blocks: &[BlockNumber],
    ) -> Result<Vec<u32>> {
        let start = self.source_first_block.0;
        let end = start + u64::from(self.source_block_count);
        let mut out = Vec::with_capacity(corrupt_blocks.len());

        for block in corrupt_blocks {
            if block.0 < start || block.0 >= end {
                return Err(FfsError::RepairFailed(format!(
                    "corrupt block {} outside source range [{start}, {end})",
                    block.0
                )));
            }
            let idx = u32::try_from(block.0 - start).map_err(|_| {
                FfsError::RepairFailed(format!("corrupt block {} index does not fit u32", block.0))
            })?;
            out.push(idx);
        }

        Self::normalize_indices(&mut out, self.source_block_count)?;
        Ok(out)
    }

    /// Recover from explicit source-relative corrupt indices.
    #[must_use]
    pub fn recover_from_indices(&self, cx: &Cx, corrupt_indices: &[u32]) -> RecoveryAttemptResult {
        let mut normalized = corrupt_indices.to_vec();
        if let Err(err) = Self::normalize_indices(&mut normalized, self.source_block_count) {
            return self.failure_result(
                0,
                corrupt_indices.len(),
                0,
                0,
                RecoveryDecoderStats::default(),
                &err,
            );
        }

        self.recover_from_normalized_indices(cx, &normalized)
    }

    /// Continue recovery with owned indices that are already validated, sorted,
    /// and deduplicated for this session's source range.
    fn recover_from_normalized_indices(
        &self,
        cx: &Cx,
        normalized: &[u32],
    ) -> RecoveryAttemptResult {
        if cx.checkpoint().is_err() {
            return self.failure_result(
                0,
                normalized.len(),
                0,
                0,
                RecoveryDecoderStats::default(),
                &FfsError::Cancelled,
            );
        }
        if normalized.is_empty() {
            return self.success_result(0, 0, 0, RecoveryDecoderStats::default(), Vec::new());
        }

        let expected_current = match self.capture_expected_current_blocks(cx, normalized) {
            Ok(expected_current) => expected_current,
            Err(err)
                if self.writeback.supports_unreadable_targets()
                    && erasure::is_media_read_failure(&err) =>
            {
                return self.recover_unreadable_targets(cx, normalized);
            }
            Err(err) => {
                return self.failure_result(
                    0,
                    normalized.len(),
                    0,
                    0,
                    RecoveryDecoderStats::default(),
                    &err,
                );
            }
        };

        // Metadata and parity come from the SAME sealed generation. A media
        // failure in parity is useful erasure information even when every
        // source target remains readable but has a checksum mismatch.
        let (desc, symbols) = match self.storage.read_verified_raw_generation(cx, true) {
            Ok(generation) => generation,
            Err(err) => {
                return self.failure_result(
                    0,
                    normalized.len(),
                    0,
                    0,
                    RecoveryDecoderStats::default(),
                    &err,
                );
            }
        };
        let generation = desc.repair_generation;
        let symbols_available = symbols.len();
        if let Err(err) = self.validate_recovery_geometry(&desc) {
            return self.failure_result(
                generation,
                normalized.len(),
                symbols_available,
                0,
                RecoveryDecoderStats::default(),
                &err,
            );
        }
        let decode = match decode_group_with_owned_repair_symbols(
            cx,
            self.device,
            &self.fs_uuid,
            self.group(),
            self.source_first_block,
            self.source_block_count,
            normalized,
            symbols,
        ) {
            Ok(outcome) => outcome,
            Err(err) => {
                return self.failure_result(
                    generation,
                    normalized.len(),
                    symbols_available,
                    symbols_available,
                    RecoveryDecoderStats::default(),
                    &err,
                );
            }
        };

        // A refresh starting after symbol capture invalidates this plan, even
        // when decoding succeeds. Never hand its reconstructed bytes to a
        // writeback authority after observing a pending or newer generation.
        if let Err(err) = self.storage.ensure_verified_raw_generation(cx, &desc) {
            return self.failure_result(
                generation,
                normalized.len(),
                symbols_available,
                symbols_available,
                RecoveryDecoderStats::from(&decode.stats),
                &err,
            );
        }

        self.finish_decode(
            cx,
            generation,
            normalized.len(),
            symbols_available,
            &decode,
            &expected_current,
        )
    }

    fn validate_recovery_geometry(&self, desc: &RepairGroupDescExt) -> Result<()> {
        if u32::from(desc.source_block_count) != self.source_block_count
            || u32::from(desc.symbol_size) != self.device.block_size()
            || desc.transfer_length
                != u64::from(self.source_block_count) * u64::from(self.device.block_size())
            || desc.sub_blocks != 1
            || desc.symbol_alignment != 4
        {
            return Err(FfsError::RepairFailed(
                "repair descriptor does not match the source geometry".to_owned(),
            ));
        }
        Ok(())
    }

    /// Recover from absolute corrupt block numbers.
    #[must_use]
    pub fn recover_from_corrupt_blocks(
        &self,
        cx: &Cx,
        corrupt_blocks: &[BlockNumber],
    ) -> RecoveryAttemptResult {
        match self.map_corrupt_blocks_to_indices(corrupt_blocks) {
            Ok(indices) => self.recover_from_normalized_indices(cx, &indices),
            Err(err) => self.failure_result(
                0,
                corrupt_blocks.len(),
                0,
                0,
                RecoveryDecoderStats::default(),
                &err,
            ),
        }
    }

    fn finish_decode(
        &self,
        cx: &Cx,
        generation: u64,
        corrupt_count: usize,
        symbols_available: usize,
        decode: &DecodeOutcome,
        expected_current: &[(BlockNumber, Vec<u8>)],
    ) -> RecoveryAttemptResult {
        let stats = RecoveryDecoderStats::from(&decode.stats);
        if !decode.complete {
            return self.partial_result(
                generation,
                corrupt_count,
                symbols_available,
                symbols_available,
                stats,
                "decoder returned incomplete recovery".to_owned(),
            );
        }

        if let Err(err) = self.reject_invalid_decoded_blocks(cx, decode) {
            return self.failure_result(
                generation,
                corrupt_count,
                symbols_available,
                symbols_available,
                stats,
                &err,
            );
        }
        let recovered_blocks = decode.recovered.iter().map(|b| b.block).collect::<Vec<_>>();
        let writeback_blocks = match Self::build_writeback_blocks(decode, expected_current) {
            Ok(writeback_blocks) => writeback_blocks,
            Err(err) => {
                return self.failure_result(
                    generation,
                    corrupt_count,
                    symbols_available,
                    symbols_available,
                    stats,
                    &err,
                );
            }
        };
        if let Err(err) = self
            .writeback
            .writeback_recovered(cx, self.device, &writeback_blocks)
        {
            return self.failure_result(
                generation,
                corrupt_count,
                symbols_available,
                symbols_available,
                stats,
                &err,
            );
        }

        self.success_result(
            generation,
            corrupt_count,
            symbols_available,
            stats,
            recovered_blocks,
        )
    }

    fn capture_expected_current_blocks(
        &self,
        cx: &Cx,
        corrupt_indices: &[u32],
    ) -> Result<Vec<(BlockNumber, Vec<u8>)>> {
        use rayon::prelude::{IntoParallelIterator, ParallelIterator};

        // Plan the target blocks serially (cheap), honoring cancellation up
        // front exactly as the old loop did before any read.
        let mut blocks = Vec::with_capacity(corrupt_indices.len());
        for index in corrupt_indices {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            blocks.push(BlockNumber(self.source_first_block.0 + u64::from(*index)));
        }

        // The per-block reads are independent. Read them across the rayon pool:
        // a blocking device read parks its worker, so the per-read access
        // latencies overlap up to the pool size (the I/O-overlap lever shared
        // with the scrub/read-path levers bd-307e4/bd-tyym4). An indexed
        // `into_par_iter().collect()` preserves block order, and consuming the
        // results in index order with `?` reproduces the serial loop's
        // first-error-in-index-order behaviour byte-for-byte.
        let reads: Vec<Result<(BlockNumber, Vec<u8>)>> = blocks
            .into_par_iter()
            .map(|block| {
                let bytes = self.device.read_block(cx, block)?;
                if bytes.is_empty() || bytes.len() != self.device.block_size() as usize {
                    return Err(FfsError::RepairFailed(format!(
                        "short before-image at repair target {}",
                        block.0
                    )));
                }
                Ok((block, bytes.into_inner()))
            })
            .collect();
        let mut expected_current = Vec::with_capacity(reads.len());
        for read in reads {
            expected_current.push(read?);
        }
        Ok(expected_current)
    }

    fn build_writeback_blocks<'b>(
        decode: &'b DecodeOutcome,
        expected_current: &'b [(BlockNumber, Vec<u8>)],
    ) -> Result<Vec<RecoveryWritebackBlock<'b>>> {
        if decode.recovered.len() != expected_current.len() {
            return Err(FfsError::RepairFailed(
                "decoder output does not cover the exact recovery target set".to_owned(),
            ));
        }
        let mut writeback_blocks = Vec::with_capacity(decode.recovered.len());
        let mut seen = BTreeSet::new();
        // Both inputs preserve the normalized corrupt-index order. Pair the
        // common path by ordinal position and retain the binary search as a
        // behavior-preserving fallback for an unexpectedly reordered decode.
        for (position, recovered) in decode.recovered.iter().enumerate() {
            if !seen.insert(recovered.block) {
                return Err(FfsError::RepairFailed(
                    "decoder returned a duplicate recovery target".to_owned(),
                ));
            }
            let expected = if let Some((block, expected)) = expected_current.get(position)
                && *block == recovered.block
            {
                expected
            } else {
                let Ok(idx) =
                    expected_current.binary_search_by_key(&recovered.block, |(block, _)| *block)
                else {
                    return Err(FfsError::RepairFailed(format!(
                        "missing scrub-time bytes for recovered block {}",
                        recovered.block.0
                    )));
                };
                &expected_current[idx].1
            };
            if expected.is_empty() || recovered.data.len() != expected.len() {
                return Err(FfsError::RepairFailed(
                    "decoder returned an invalid recovered block length".to_owned(),
                ));
            }
            writeback_blocks.push(RecoveryWritebackBlock {
                block: recovered.block,
                expected_current: expected.as_slice(),
                data: recovered.data.as_slice(),
            });
        }
        Ok(writeback_blocks)
    }

    fn normalize_indices(indices: &mut Vec<u32>, source_block_count: u32) -> Result<()> {
        indices.sort_unstable();
        indices.dedup();
        for idx in indices {
            if *idx >= source_block_count {
                return Err(FfsError::RepairFailed(format!(
                    "corrupt index {idx} outside source range [0, {source_block_count})"
                )));
            }
        }
        Ok(())
    }

    fn success_result(
        &self,
        generation: u64,
        corrupt_count: usize,
        symbols_available: usize,
        stats: RecoveryDecoderStats,
        repaired_blocks: Vec<BlockNumber>,
    ) -> RecoveryAttemptResult {
        RecoveryAttemptResult {
            evidence: RecoveryEvidence {
                group: self.group().0,
                generation,
                corrupt_count,
                symbols_available,
                symbols_used: symbols_available,
                decoder_stats: stats,
                outcome: RecoveryOutcome::Recovered,
                reason: None,
            },
            repaired_blocks,
        }
    }

    fn partial_result(
        &self,
        generation: u64,
        corrupt_count: usize,
        symbols_available: usize,
        symbols_used: usize,
        stats: RecoveryDecoderStats,
        reason: String,
    ) -> RecoveryAttemptResult {
        RecoveryAttemptResult {
            evidence: RecoveryEvidence {
                group: self.group().0,
                generation,
                corrupt_count,
                symbols_available,
                symbols_used,
                decoder_stats: stats,
                outcome: RecoveryOutcome::Partial,
                reason: Some(reason),
            },
            repaired_blocks: Vec::new(),
        }
    }

    fn failure_result(
        &self,
        generation: u64,
        corrupt_count: usize,
        symbols_available: usize,
        symbols_used: usize,
        stats: RecoveryDecoderStats,
        err: &FfsError,
    ) -> RecoveryAttemptResult {
        RecoveryAttemptResult {
            evidence: RecoveryEvidence {
                group: self.group().0,
                generation,
                corrupt_count,
                symbols_available,
                symbols_used,
                decoder_stats: stats,
                outcome: RecoveryOutcome::Failed,
                reason: Some(err.to_string()),
            },
            repaired_blocks: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode_group;
    use crate::symbol::RepairGroupDescExt;
    use ffs_block::BlockBuf;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct MemBlockDevice {
        blocks: Mutex<HashMap<u64, Vec<u8>>>,
        block_size: u32,
        block_count: u64,
    }

    impl MemBlockDevice {
        fn new(block_size: u32, block_count: u64) -> Self {
            Self {
                blocks: Mutex::new(HashMap::new()),
                block_size,
                block_count,
            }
        }
    }

    impl BlockDevice for MemBlockDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            if block.0 >= self.block_count {
                return Err(FfsError::Format(format!(
                    "read out of range: block={} block_count={}",
                    block.0, self.block_count
                )));
            }
            let bytes = self
                .blocks
                .lock()
                .expect("mutex")
                .get(&block.0)
                .cloned()
                .unwrap_or_else(|| vec![0_u8; self.block_size as usize]);
            Ok(BlockBuf::new(bytes))
        }

        fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            if block.0 >= self.block_count {
                return Err(FfsError::Format(format!(
                    "write out of range: block={} block_count={}",
                    block.0, self.block_count
                )));
            }
            if data.len() != self.block_size as usize {
                return Err(FfsError::Format(format!(
                    "write size mismatch: got={} expected={}",
                    data.len(),
                    self.block_size
                )));
            }
            self.blocks
                .lock()
                .expect("mutex")
                .insert(block.0, data.to_vec());
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

    /// Block device wrapper that injects deterministic read I/O errors.
    struct FaultyBlockDevice {
        inner: MemBlockDevice,
        read_fail_blocks: HashSet<u64>,
    }

    impl FaultyBlockDevice {
        fn new(
            inner: MemBlockDevice,
            read_fail_blocks: impl IntoIterator<Item = BlockNumber>,
        ) -> Self {
            let read_fail_blocks = read_fail_blocks.into_iter().map(|block| block.0).collect();
            Self {
                inner,
                read_fail_blocks,
            }
        }
    }

    impl BlockDevice for FaultyBlockDevice {
        fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            if self.read_fail_blocks.contains(&block.0) {
                return Err(FfsError::Io(std::io::Error::other(format!(
                    "simulated symbol read i/o error at block {}",
                    block.0
                ))));
            }
            self.inner.read_block(cx, block)
        }

        fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            self.inner.write_block(cx, block, data)
        }

        fn block_size(&self) -> u32 {
            self.inner.block_size()
        }

        fn block_count(&self) -> u64 {
            self.inner.block_count()
        }

        fn sync(&self, cx: &Cx) -> Result<()> {
            self.inner.sync(cx)
        }
    }

    fn test_uuid() -> [u8; 16] {
        [0x11; 16]
    }

    fn deterministic_block(index: u64, block_size: u32) -> Vec<u8> {
        (0..block_size as usize)
            .map(|i| {
                let value = (index.wrapping_mul(31))
                    .wrapping_add(i as u64)
                    .wrapping_add(7)
                    % 251;
                u8::try_from(value).expect("value < 251")
            })
            .collect()
    }

    fn write_source_blocks(
        cx: &Cx,
        device: &MemBlockDevice,
        source_first_block: BlockNumber,
        source_block_count: u32,
        block_size: u32,
    ) -> Vec<Vec<u8>> {
        let mut originals = Vec::with_capacity(source_block_count as usize);
        for i in 0..u64::from(source_block_count) {
            let data = deterministic_block(i, block_size);
            let block = BlockNumber(source_first_block.0 + i);
            device
                .write_block(cx, block, &data)
                .expect("write source block");
            originals.push(data);
        }
        originals
    }

    fn bootstrap_storage(
        cx: &Cx,
        device: &MemBlockDevice,
        layout: RepairGroupLayout,
        source_first_block: BlockNumber,
        source_block_count: u32,
        repair_symbol_count: u32,
    ) -> usize {
        let encoded = encode_group(
            cx,
            device,
            &test_uuid(),
            layout.group,
            source_first_block,
            source_block_count,
            repair_symbol_count,
        )
        .expect("encode group");

        let storage = RepairGroupStorage::new(device, layout);
        let desc = RepairGroupDescExt {
            transfer_length: u64::from(encoded.source_block_count) * u64::from(encoded.symbol_size),
            symbol_size: u16::try_from(encoded.symbol_size).expect("symbol_size fits u16"),
            source_block_count: u16::try_from(encoded.source_block_count)
                .expect("source_block_count fits u16"),
            sub_blocks: 1,
            symbol_alignment: 4,
            repair_start_block: layout.repair_start_block(),
            repair_block_count: layout.repair_block_count,
            repair_generation: 0,
            checksum: 0,
        };
        storage
            .write_group_desc_ext(cx, &desc)
            .expect("write bootstrap desc");

        let symbols = encoded
            .repair_symbols
            .into_iter()
            .map(|s| (s.esi, s.data))
            .collect::<Vec<_>>();
        storage
            .write_repair_symbols(cx, &symbols, 1)
            .expect("write repair symbols");
        symbols.len()
    }

    #[test]
    fn direct_writeback_rejects_changed_current_block() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 8);
        let block = BlockNumber(3);
        let expected = vec![0x11; block_size as usize];
        let newer = vec![0x22; block_size as usize];
        let recovered = vec![0x33; block_size as usize];

        device
            .write_block(&cx, block, &expected)
            .expect("seed expected current bytes");
        device
            .write_block(&cx, block, &newer)
            .expect("simulate concurrent block update");

        let writeback = DirectDeviceRecoveryWriteback;
        let err = writeback
            .writeback_recovered(
                &cx,
                &device,
                &[RecoveryWritebackBlock {
                    block,
                    expected_current: &expected,
                    data: &recovered,
                }],
            )
            .expect_err("stale expected_current must fail closed");

        assert!(
            err.to_string().contains("compare failed"),
            "unexpected error: {err}"
        );
        let observed = device.read_block(&cx, block).expect("read current block");
        assert_eq!(observed.as_slice(), newer.as_slice());
    }

    #[test]
    fn recovery_restores_corrupted_blocks_when_redundancy_is_sufficient() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        let originals = write_source_blocks(&cx, &device, source_first, source_count, block_size);
        let symbols_available =
            bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        for idx in [1_u32, 5_u32] {
            let block = BlockNumber(source_first.0 + u64::from(idx));
            device
                .write_block(&cx, block, &vec![0xA5; block_size as usize])
                .expect("inject corruption");
        }

        let orchestrator = GroupRecoveryOrchestrator::new(
            &device,
            test_uuid(),
            layout,
            source_first,
            source_count,
        )
        .expect("orchestrator");
        let result = orchestrator.recover_from_indices(&cx, &[1, 5]);
        assert!(
            result.is_success(),
            "expected successful recovery: {:?}",
            result.evidence
        );
        assert_eq!(result.evidence.outcome, RecoveryOutcome::Recovered);
        assert_eq!(result.evidence.generation, 1);
        assert_eq!(result.evidence.symbols_available, symbols_available);

        for idx in [1_u32, 5_u32] {
            let block = BlockNumber(source_first.0 + u64::from(idx));
            let restored = device.read_block(&cx, block).expect("read restored");
            assert_eq!(
                restored.as_slice(),
                originals[idx as usize].as_slice(),
                "block {} was not restored exactly",
                block.0
            );
        }
    }

    /// Stands in for a block's own checksum: a block is valid only if it holds
    /// the bytes recorded for it.
    struct ExpectedBytesValidator(std::collections::HashMap<u64, Vec<u8>>);

    impl BlockValidator for ExpectedBytesValidator {
        fn validate(&self, block: BlockNumber, data: &BlockBuf) -> BlockVerdict {
            match self.0.get(&block.0) {
                Some(expected) if expected.as_slice() == data.as_slice() => BlockVerdict::Clean,
                Some(_) => BlockVerdict::Corrupt(vec![(
                    crate::scrub::CorruptionKind::ChecksumMismatch,
                    crate::scrub::Severity::Error,
                    "checksum mismatch".to_owned(),
                )]),
                None => BlockVerdict::Skip,
            }
        }
    }

    /// bd-jufod: symbols older than the block decode "successfully" to the old
    /// bytes (see recovery_detects_stale_symbol_restore_via_blake3_mismatch).
    /// With a decoded-block validator that knows the current checksum, the
    /// decode is rejected and nothing is written.
    #[test]
    fn decoded_block_failing_validation_is_never_written_back_bd_jufod() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(8), BlockNumber(0), 64, 0, 6).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;
        write_source_blocks(&cx, &device, source_first, source_count, block_size);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let target = BlockNumber(2);
        let latest = deterministic_block(10_000, block_size);
        device
            .write_block(&cx, target, &latest)
            .expect("update after symbol generation");
        let corrupt = vec![0xEE; block_size as usize];
        device
            .write_block(&cx, target, &corrupt)
            .expect("inject corruption");

        let validator = ExpectedBytesValidator(std::iter::once((target.0, latest)).collect());
        let result = GroupRecoveryOrchestrator::new(
            &device,
            test_uuid(),
            layout,
            source_first,
            source_count,
        )
        .expect("orchestrator")
        .with_decoded_block_validator(&validator)
        .recover_from_indices(&cx, &[2]);

        assert_eq!(result.evidence.outcome, RecoveryOutcome::Failed);
        assert!(
            result
                .evidence
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("fails validation")),
            "the refusal must say why: {:?}",
            result.evidence.reason
        );
        assert_eq!(result.repaired_blocks, Vec::<BlockNumber>::new());
        assert_eq!(
            device.read_block(&cx, target).expect("read").as_slice(),
            corrupt.as_slice(),
            "a rejected decode must leave the block untouched"
        );
    }

    /// bd-jufod: a view validator is built over the image as it would be after
    /// writeback — decoded bytes for the targets, the device for the rest — and
    /// a correct decode passes it and is written.
    #[test]
    fn decoded_view_validator_sees_the_post_writeback_image_bd_jufod() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;
        let originals = write_source_blocks(&cx, &device, source_first, source_count, block_size);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);
        for idx in [1_u64, 5] {
            device
                .write_block(&cx, BlockNumber(idx), &vec![0xA5; block_size as usize])
                .expect("inject corruption");
        }

        // The factory snapshots what the view shows for every source block;
        // validation then requires each decoded block to match that snapshot.
        let factory = |cx: &Cx, view: &dyn BlockDevice| -> Result<Box<dyn BlockValidator>> {
            let mut seen = std::collections::HashMap::new();
            for block in 0..u64::from(source_count) {
                seen.insert(
                    block,
                    view.read_block(cx, BlockNumber(block))?.as_slice().to_vec(),
                );
            }
            Ok(Box::new(ExpectedBytesValidator(seen)))
        };
        let observed = std::sync::Mutex::new(Vec::new());
        let recording = |cx: &Cx, view: &dyn BlockDevice| -> Result<Box<dyn BlockValidator>> {
            for block in 0..u64::from(source_count) {
                observed
                    .lock()
                    .expect("lock")
                    .push(view.read_block(cx, BlockNumber(block))?.as_slice().to_vec());
            }
            factory(cx, view)
        };
        let result = GroupRecoveryOrchestrator::new(
            &device,
            test_uuid(),
            layout,
            source_first,
            source_count,
        )
        .expect("orchestrator")
        .with_decoded_view_validator(&recording)
        .recover_from_indices(&cx, &[1, 5]);

        assert!(result.is_success(), "{:?}", result.evidence);
        let observed = observed.into_inner().expect("lock");
        for (index, original) in originals.iter().enumerate() {
            assert_eq!(
                observed[index].as_slice(),
                original.as_slice(),
                "view block {index} must be the post-writeback content"
            );
            assert_eq!(
                device
                    .read_block(&cx, BlockNumber(index as u64))
                    .expect("read")
                    .as_slice(),
                original.as_slice()
            );
        }
    }

    #[test]
    fn recovery_fails_loudly_when_redundancy_is_insufficient() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(1), BlockNumber(0), 64, 0, 2).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        let originals = write_source_blocks(&cx, &device, source_first, source_count, block_size);
        let _symbols_available =
            bootstrap_storage(&cx, &device, layout, source_first, source_count, 1);

        for idx in [0_u32, 1_u32] {
            let block = BlockNumber(source_first.0 + u64::from(idx));
            device
                .write_block(&cx, block, &vec![0xCC; block_size as usize])
                .expect("inject corruption");
        }

        let orchestrator = GroupRecoveryOrchestrator::new(
            &device,
            test_uuid(),
            layout,
            source_first,
            source_count,
        )
        .expect("orchestrator");
        let result = orchestrator.recover_from_indices(&cx, &[0, 1]);
        assert_eq!(result.evidence.outcome, RecoveryOutcome::Failed);
        let reason = result.evidence.reason.as_deref().unwrap_or_default();
        assert!(
            reason.contains("insufficient")
                && (reason.contains("symbol") || reason.contains("redundancy")),
            "expected insufficient-symbols reason, got {:?}",
            result.evidence.reason
        );

        let still_corrupt = device
            .read_block(&cx, BlockNumber(0))
            .expect("read block after failed recovery");
        assert_ne!(
            still_corrupt.as_slice(),
            originals[0].as_slice(),
            "block 0 unexpectedly restored despite insufficient redundancy"
        );
    }

    #[test]
    fn recovery_succeeds_with_partial_symbol_loss() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(7), BlockNumber(0), 64, 0, 8).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        let originals = write_source_blocks(&cx, &device, source_first, source_count, block_size);
        let symbols_available =
            bootstrap_storage(&cx, &device, layout, source_first, source_count, 6);

        // Simulate partial symbol loss by zeroing one raw symbol block.
        let damaged_symbol_block = BlockNumber(layout.repair_start_block().0 + 1);
        device
            .write_block(&cx, damaged_symbol_block, &vec![0_u8; block_size as usize])
            .expect("damage one symbol block");

        let corrupt_idx = 3_u32;
        let corrupt_block = BlockNumber(source_first.0 + u64::from(corrupt_idx));
        device
            .write_block(&cx, corrupt_block, &vec![0xAB; block_size as usize])
            .expect("inject corruption");

        let orchestrator = GroupRecoveryOrchestrator::new(
            &device,
            test_uuid(),
            layout,
            source_first,
            source_count,
        )
        .expect("orchestrator");
        let result = orchestrator.recover_from_indices(&cx, &[corrupt_idx]);
        assert!(
            result.is_success(),
            "expected recovery success despite partial symbol loss: {:?}",
            result.evidence
        );
        assert!(
            result.evidence.symbols_available < symbols_available,
            "expected fewer symbols after corruption: before={symbols_available} after={}",
            result.evidence.symbols_available
        );

        let restored = device
            .read_block(&cx, corrupt_block)
            .expect("read restored");
        assert_eq!(
            restored.as_slice(),
            originals[usize::try_from(corrupt_idx).expect("fits usize")].as_slice(),
            "corrupt block should be restored exactly with remaining symbols"
        );
    }

    #[test]
    fn recovery_detects_stale_symbol_restore_via_blake3_mismatch() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(8), BlockNumber(0), 64, 0, 6).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        let originals = write_source_blocks(&cx, &device, source_first, source_count, block_size);
        let _symbols_available =
            bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        // Update one source block after symbol generation; symbols are now stale.
        let target_idx = 2_u32;
        let target_block = BlockNumber(source_first.0 + u64::from(target_idx));
        let new_bytes = deterministic_block(10_000, block_size);
        let new_hash = blake3::hash(&new_bytes);
        device
            .write_block(&cx, target_block, &new_bytes)
            .expect("write updated source data");

        // Corrupt the updated block, then recover using stale symbols.
        device
            .write_block(&cx, target_block, &vec![0xEE; block_size as usize])
            .expect("inject corruption on updated block");

        let orchestrator = GroupRecoveryOrchestrator::new(
            &device,
            test_uuid(),
            layout,
            source_first,
            source_count,
        )
        .expect("orchestrator");
        let result = orchestrator.recover_from_indices(&cx, &[target_idx]);
        assert!(
            result.is_success(),
            "expected decode success even with stale symbols: {:?}",
            result.evidence
        );

        let restored = device.read_block(&cx, target_block).expect("read restored");
        // Stale symbols can restore a previous value; assert mismatch against latest bytes.
        let restored_hash = blake3::hash(restored.as_slice());
        assert_ne!(
            restored_hash, new_hash,
            "expected stale-symbol restore to mismatch latest payload hash"
        );
        assert_eq!(
            restored.as_slice(),
            originals[usize::try_from(target_idx).expect("fits usize")].as_slice(),
            "stale symbols should recover the pre-update payload"
        );
    }

    #[test]
    fn recovery_handles_symbol_read_io_errors_gracefully() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(9), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count, block_size);
        let _symbols_available =
            bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let corrupt_idx = 1_u32;
        let corrupt_block = BlockNumber(source_first.0 + u64::from(corrupt_idx));
        device
            .write_block(&cx, corrupt_block, &vec![0xCD; block_size as usize])
            .expect("inject corruption");

        let repair_symbol_block = layout.repair_start_block();
        let faulty = FaultyBlockDevice::new(device, [repair_symbol_block]);
        let orchestrator = GroupRecoveryOrchestrator::new(
            &faulty,
            test_uuid(),
            layout,
            source_first,
            source_count,
        )
        .expect("orchestrator");
        let result = orchestrator.recover_from_indices(&cx, &[corrupt_idx]);

        assert_eq!(result.evidence.outcome, RecoveryOutcome::Failed);
        let reason = result.evidence.reason.as_deref().unwrap_or_default();
        assert!(
            reason.contains("simulated symbol read i/o error")
                || reason.contains("no fully-valid repair generation"),
            "expected symbol-read failure context, got {:?}",
            result.evidence.reason,
        );
        assert!(
            result.repaired_blocks.is_empty(),
            "failed recovery must not report repaired blocks"
        );
    }

    #[test]
    fn evidence_ledger_is_json_parseable_and_complete() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 64);
        let layout =
            RepairGroupLayout::new(GroupNumber(2), BlockNumber(0), 32, 0, 2).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 4;

        let _originals = write_source_blocks(&cx, &device, source_first, source_count, block_size);
        let _symbols_available =
            bootstrap_storage(&cx, &device, layout, source_first, source_count, 2);

        let orchestrator = GroupRecoveryOrchestrator::new(
            &device,
            test_uuid(),
            layout,
            source_first,
            source_count,
        )
        .expect("orchestrator");
        let result = orchestrator.recover_from_indices(&cx, &[1]);

        let json = result.evidence.to_json().expect("serialize evidence");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse evidence json");
        for key in [
            "group",
            "generation",
            "corrupt_count",
            "symbols_available",
            "symbols_used",
            "decoder_stats",
            "outcome",
            "reason",
        ] {
            assert!(value.get(key).is_some(), "missing ledger field: {key}");
        }

        let parsed: RecoveryEvidence = serde_json::from_str(&json).expect("round-trip parse");
        assert_eq!(parsed.group, layout.group.0);
        assert_eq!(parsed.corrupt_count, 1);
    }

    #[test]
    fn recovery_noop_for_empty_corrupt_list() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count, block_size);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let orchestrator = GroupRecoveryOrchestrator::new(
            &device,
            test_uuid(),
            layout,
            source_first,
            source_count,
        )
        .expect("orchestrator");
        let result = orchestrator.recover_from_indices(&cx, &[]);
        assert!(result.is_success());
        assert_eq!(result.evidence.corrupt_count, 0);
        assert_eq!(result.repaired_blocks, [] as [BlockNumber; 0]);
    }

    #[test]
    fn recovery_deduplicates_corrupt_indices() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        let originals = write_source_blocks(&cx, &device, source_first, source_count, block_size);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let corrupt_idx = 3_u32;
        let corrupt_block = BlockNumber(source_first.0 + u64::from(corrupt_idx));
        device
            .write_block(&cx, corrupt_block, &vec![0xAA; block_size as usize])
            .expect("inject corruption");

        let orchestrator = GroupRecoveryOrchestrator::new(
            &device,
            test_uuid(),
            layout,
            source_first,
            source_count,
        )
        .expect("orchestrator");
        // Pass duplicates; should deduplicate to a single index.
        let result = orchestrator.recover_from_indices(&cx, &[3, 3, 3]);
        assert!(result.is_success(), "dedup recovery: {:?}", result.evidence);
        assert_eq!(result.evidence.corrupt_count, 1);

        let restored = device
            .read_block(&cx, corrupt_block)
            .expect("read restored");
        assert_eq!(restored.as_slice(), originals[3].as_slice());
    }

    #[test]
    fn recovery_rejects_out_of_range_index() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count, block_size);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let orchestrator = GroupRecoveryOrchestrator::new(
            &device,
            test_uuid(),
            layout,
            source_first,
            source_count,
        )
        .expect("orchestrator");
        let result = orchestrator.recover_from_indices(&cx, &[99]);
        assert_eq!(result.evidence.outcome, RecoveryOutcome::Failed);
        assert!(
            result
                .evidence
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("outside source range")
        );
    }

    #[test]
    fn recover_from_corrupt_blocks_maps_absolute_to_relative() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 256);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 128, 0, 8).expect("layout");
        let source_first = BlockNumber(10);
        let source_count = 8;

        let originals = write_source_blocks(&cx, &device, source_first, source_count, block_size);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        // Corrupt block at absolute position 12 (relative index 2).
        let corrupt_abs = BlockNumber(12);
        device
            .write_block(&cx, corrupt_abs, &vec![0xDD; block_size as usize])
            .expect("inject corruption");

        let orchestrator = GroupRecoveryOrchestrator::new(
            &device,
            test_uuid(),
            layout,
            source_first,
            source_count,
        )
        .expect("orchestrator");
        let result = orchestrator.recover_from_corrupt_blocks(&cx, &[corrupt_abs]);
        assert!(
            result.is_success(),
            "abs block recovery: {:?}",
            result.evidence
        );

        let restored = device.read_block(&cx, corrupt_abs).expect("read restored");
        assert_eq!(restored.as_slice(), originals[2].as_slice());
    }

    #[test]
    fn recover_from_corrupt_blocks_rejects_block_outside_source() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 256);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 128, 0, 8).expect("layout");
        let source_first = BlockNumber(10);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count, block_size);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let orchestrator = GroupRecoveryOrchestrator::new(
            &device,
            test_uuid(),
            layout,
            source_first,
            source_count,
        )
        .expect("orchestrator");

        // Block 5 is before source_first (10).
        let result = orchestrator.recover_from_corrupt_blocks(&cx, &[BlockNumber(5)]);
        assert_eq!(result.evidence.outcome, RecoveryOutcome::Failed);
        assert!(
            result
                .evidence
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("outside source range")
        );
    }

    #[test]
    fn orchestrator_rejects_zero_source_block_count() {
        let device = MemBlockDevice::new(256, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let result =
            GroupRecoveryOrchestrator::new(&device, test_uuid(), layout, BlockNumber(0), 0);
        assert!(
            matches!(result, Err(FfsError::RepairFailed(_))),
            "zero source_block_count should fail with RepairFailed"
        );
    }

    #[test]
    fn orchestrator_rejects_source_outside_group_data() {
        let device = MemBlockDevice::new(256, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 32, 2, 4).expect("layout");

        // Source range [20, 28) overlaps validation/repair tail starting at 24.
        let result =
            GroupRecoveryOrchestrator::new(&device, test_uuid(), layout, BlockNumber(20), 8);
        assert!(
            matches!(result, Err(FfsError::RepairFailed(_))),
            "source overlapping tail should fail with RepairFailed"
        );
    }

    #[test]
    fn evidence_round_trip_preserves_partial_outcome() {
        let evidence = RecoveryEvidence {
            group: 5,
            generation: 42,
            corrupt_count: 3,
            symbols_available: 10,
            symbols_used: 10,
            decoder_stats: RecoveryDecoderStats {
                peeled: 2,
                inactivated: 1,
                gauss_ops: 15,
                pivots_selected: 3,
            },
            outcome: RecoveryOutcome::Partial,
            reason: Some("decoder returned incomplete recovery".to_owned()),
        };

        let json = evidence.to_json().expect("serialize");
        let parsed: RecoveryEvidence = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed.outcome, RecoveryOutcome::Partial);
        assert_eq!(parsed.group, 5);
        assert_eq!(parsed.generation, 42);
        assert_eq!(parsed.decoder_stats.peeled, 2);
        assert_eq!(
            parsed.reason.as_deref(),
            Some("decoder returned incomplete recovery")
        );
    }

    // ── Edge-case hardening tests ──────────────────────────────────────

    #[test]
    fn recovery_decoder_stats_default_is_zeroed() {
        let s = RecoveryDecoderStats::default();
        assert_eq!(s.peeled, 0);
        assert_eq!(s.inactivated, 0);
        assert_eq!(s.gauss_ops, 0);
        assert_eq!(s.pivots_selected, 0);
    }

    #[test]
    fn recovery_outcome_serde_round_trip() {
        for outcome in [
            RecoveryOutcome::Recovered,
            RecoveryOutcome::Partial,
            RecoveryOutcome::Failed,
        ] {
            let json = serde_json::to_string(&outcome).expect("serialize");
            let parsed: RecoveryOutcome = serde_json::from_str(&json).expect("parse");
            assert_eq!(parsed, outcome);
        }
    }

    #[test]
    fn recovery_attempt_result_is_success_checks_outcome() {
        let evidence = RecoveryEvidence {
            group: 0,
            generation: 1,
            corrupt_count: 1,
            symbols_available: 4,
            symbols_used: 4,
            decoder_stats: RecoveryDecoderStats::default(),
            outcome: RecoveryOutcome::Recovered,
            reason: None,
        };
        let result = RecoveryAttemptResult {
            evidence,
            repaired_blocks: vec![BlockNumber(0)],
        };
        assert!(result.is_success());

        let failed_evidence = RecoveryEvidence {
            outcome: RecoveryOutcome::Failed,
            ..result.evidence
        };
        let failed_result = RecoveryAttemptResult {
            evidence: failed_evidence,
            repaired_blocks: Vec::new(),
        };
        assert!(!failed_result.is_success());
    }

    #[test]
    fn recovery_evidence_to_json_is_valid() {
        let evidence = RecoveryEvidence {
            group: 3,
            generation: 7,
            corrupt_count: 2,
            symbols_available: 8,
            symbols_used: 6,
            decoder_stats: RecoveryDecoderStats {
                peeled: 1,
                inactivated: 0,
                gauss_ops: 5,
                pivots_selected: 2,
            },
            outcome: RecoveryOutcome::Recovered,
            reason: None,
        };
        let json = evidence.to_json().expect("to_json");
        assert!(json.contains("\"recovered\""));
        assert!(json.contains("\"group\":3"));
    }

    #[test]
    fn map_corrupt_blocks_rejects_duplicate_indices() {
        let device = MemBlockDevice::new(256, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let orch = GroupRecoveryOrchestrator::new(&device, test_uuid(), layout, BlockNumber(0), 32)
            .expect("orch");

        // Duplicate block numbers should be deduplicated (not rejected).
        let indices = orch
            .map_corrupt_blocks_to_indices(&[BlockNumber(5), BlockNumber(5)])
            .expect("mapping");
        assert_eq!(indices.len(), 1, "duplicates should be deduplicated");
    }

    /// Faults are injected only after real encoding and sealed publication.
    /// A source read during decoding can invalidate the generation or cancel
    /// the caller, distinguishing symbol-capture checks from pre-write checks.
    struct RecoveryFaultDevice {
        inner: MemBlockDevice,
        layout: RepairGroupLayout,
        missing: HashSet<u64>,
        invalidate_on_decode: AtomicBool,
        cancel_on_decode: AtomicBool,
        short_target: bool,
        writes: AtomicUsize,
    }

    impl BlockDevice for RecoveryFaultDevice {
        fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            if self.missing.contains(&block.0) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "injected unreadable parity",
                )
                .into());
            }
            if block.0 == 0 {
                if self.invalidate_on_decode.swap(false, Ordering::Relaxed) {
                    for slot in self.layout.descriptor_blocks() {
                        let mut bytes = self.inner.read_block(cx, slot)?.into_inner();
                        let mut descriptor = RepairGroupDescExt::parse(&bytes).expect("descriptor");
                        descriptor.repair_generation += 1;
                        bytes[..RepairGroupDescExt::SIZE].copy_from_slice(&descriptor.to_bytes());
                        self.inner.write_block(cx, slot, &bytes)?;
                    }
                }
                if self.cancel_on_decode.swap(false, Ordering::Relaxed) {
                    cx.set_cancel_requested(true);
                }
            }
            if block.0 == 1 && self.short_target {
                return Ok(BlockBuf::new(vec![0xee; 255]));
            }
            self.inner.read_block(cx, block)
        }

        fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.inner.write_block(cx, block, data)
        }

        fn block_size(&self) -> u32 {
            self.inner.block_size()
        }

        fn block_count(&self) -> u64 {
            self.inner.block_count()
        }

        fn sync(&self, cx: &Cx) -> Result<()> {
            self.inner.sync(cx)
        }
    }

    fn verified_fixture(encoded_source_count: u32) -> (RecoveryFaultDevice, Vec<Vec<u8>>) {
        let cx = Cx::for_testing();
        let inner = MemBlockDevice::new(256, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let originals = write_source_blocks(&cx, &inner, BlockNumber(0), 8, 256);
        bootstrap_storage(&cx, &inner, layout, BlockNumber(0), encoded_source_count, 4);
        inner
            .write_block(&cx, BlockNumber(1), &[0xee; 256])
            .expect("damage source");
        (
            RecoveryFaultDevice {
                inner,
                layout,
                missing: HashSet::new(),
                invalidate_on_decode: AtomicBool::new(false),
                cancel_on_decode: AtomicBool::new(false),
                short_target: false,
                writes: AtomicUsize::new(0),
            },
            originals,
        )
    }

    fn verified_recovery(cx: &Cx, device: &RecoveryFaultDevice) -> RecoveryAttemptResult {
        GroupRecoveryOrchestrator::new(device, test_uuid(), device.layout, BlockNumber(0), 8)
            .expect("orchestrator")
            .recover_from_indices(cx, &[1])
    }

    #[test]
    fn readable_source_corruption_recovers_despite_unreadable_parity() {
        let cx = Cx::for_testing();
        let (mut device, originals) = verified_fixture(8);
        device.missing.insert(device.layout.repair_start_block().0);
        let result = verified_recovery(&cx, &device);
        assert!(result.is_success(), "{:?}", result.evidence);
        assert_eq!(result.evidence.generation, 1);
        assert_eq!(result.evidence.symbols_available, 3);
        assert_eq!(device.writes.load(Ordering::Relaxed), 1);
        for (index, original) in originals.iter().enumerate() {
            assert_eq!(
                device
                    .inner
                    .read_block(&cx, BlockNumber(index as u64))
                    .expect("source")
                    .as_slice(),
                original.as_slice()
            );
        }
    }

    #[test]
    fn readable_source_corruption_uses_only_checksum_verified_parity() {
        let cx = Cx::for_testing();
        let (device, originals) = verified_fixture(8);
        let parity = BlockNumber(device.layout.repair_start_block().0 + 1);
        let mut bytes = device
            .inner
            .read_block(&cx, parity)
            .expect("parity")
            .into_inner();
        bytes[19] ^= 0x80;
        device
            .inner
            .write_block(&cx, parity, &bytes)
            .expect("damage parity");
        let result = verified_recovery(&cx, &device);
        assert!(result.is_success(), "{:?}", result.evidence);
        assert_eq!(result.evidence.symbols_available, 3);
        assert_eq!(device.writes.load(Ordering::Relaxed), 1);
        assert_eq!(
            device
                .inner
                .read_block(&cx, BlockNumber(1))
                .expect("source")
                .as_slice(),
            originals[1]
        );
    }

    #[test]
    fn loss_of_every_parity_bucket_never_writes_source_data() {
        let cx = Cx::for_testing();
        let (mut device, _) = verified_fixture(8);
        let start = device.layout.repair_start_block().0;
        device.missing.extend(start..start + 4);
        let result = verified_recovery(&cx, &device);
        assert!(!result.is_success());
        assert_eq!(result.evidence.symbols_available, 0);
        assert_eq!(result.repaired_blocks, [] as [BlockNumber; 0]);
        assert_eq!(device.writes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn generation_change_during_decode_never_reaches_writeback() {
        let cx = Cx::for_testing();
        let (device, _) = verified_fixture(8);
        device.invalidate_on_decode.store(true, Ordering::Relaxed);
        let result = verified_recovery(&cx, &device);
        assert!(!result.is_success(), "{:?}", result.evidence);
        assert!(
            result
                .evidence
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("generation changed")
        );
        assert_eq!(device.writes.load(Ordering::Relaxed), 0);
        assert_eq!(
            device
                .inner
                .read_block(&cx, BlockNumber(1))
                .expect("source")
                .as_slice(),
            [0xee; 256]
        );
    }

    #[test]
    fn cancellation_during_decode_never_reaches_writeback() {
        let cx = Cx::for_testing();
        let (device, _) = verified_fixture(8);
        device.cancel_on_decode.store(true, Ordering::Relaxed);
        let result = verified_recovery(&cx, &device);
        assert!(!result.is_success());
        assert_eq!(device.writes.load(Ordering::Relaxed), 0);
        assert_eq!(result.repaired_blocks, [] as [BlockNumber; 0]);
        assert!(
            result
                .evidence
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("cancelled")
        );
    }

    #[test]
    fn sealed_descriptor_with_wrong_source_geometry_never_decodes_or_writes() {
        let cx = Cx::for_testing();
        let (device, _) = verified_fixture(7);
        let result = verified_recovery(&cx, &device);
        assert!(!result.is_success());
        assert_eq!(result.evidence.symbols_used, 0);
        assert_eq!(device.writes.load(Ordering::Relaxed), 0);
        assert!(
            result
                .evidence
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("source geometry")
        );
    }

    #[test]
    fn decoder_must_return_exact_unique_targets_with_full_length() {
        use crate::codec::RecoveredBlock;

        let expected = vec![
            (BlockNumber(1), vec![1; 256]),
            (BlockNumber(2), vec![2; 256]),
        ];
        let first = RecoveredBlock {
            block: BlockNumber(1),
            data: vec![3; 256],
        };
        let second = RecoveredBlock {
            block: BlockNumber(2),
            data: vec![4; 256],
        };
        for recovered in [
            vec![first.clone()],
            vec![first.clone(), first.clone()],
            vec![
                first.clone(),
                RecoveredBlock {
                    block: BlockNumber(2),
                    data: vec![4; 255],
                },
            ],
            vec![
                first.clone(),
                RecoveredBlock {
                    block: BlockNumber(3),
                    data: vec![4; 256],
                },
            ],
        ] {
            let outcome = DecodeOutcome {
                recovered,
                stats: DecodeStats::default(),
                complete: true,
            };
            assert!(
                GroupRecoveryOrchestrator::build_writeback_blocks(&outcome, &expected).is_err()
            );
        }
        // Reordering is valid if the exact set and before-images still match.
        let outcome = DecodeOutcome {
            recovered: vec![second, first],
            stats: DecodeStats::default(),
            complete: true,
        };
        let blocks = GroupRecoveryOrchestrator::build_writeback_blocks(&outcome, &expected)
            .expect("exact reordered set");
        assert_eq!(blocks[0].expected_current, [2; 256]);
        assert_eq!(blocks[1].expected_current, [1; 256]);
    }

    #[test]
    fn invalid_later_writeback_target_cannot_partially_apply_earlier_target() {
        let cx = Cx::for_testing();
        let device = MemBlockDevice::new(256, 8);
        let before = [0xaa; 256];
        let after = [0xbb; 256];
        for block in [BlockNumber(1), BlockNumber(2)] {
            device.write_block(&cx, block, &before).expect("seed");
        }
        let first = RecoveryWritebackBlock {
            block: BlockNumber(1),
            expected_current: &before,
            data: &after,
        };
        for invalid in [
            RecoveryWritebackBlock {
                block: BlockNumber(2),
                expected_current: &before,
                data: &[0; 3],
            },
            RecoveryWritebackBlock {
                block: BlockNumber(8),
                expected_current: &before,
                data: &after,
            },
            first,
        ] {
            assert!(
                DirectDeviceRecoveryWriteback
                    .writeback_recovered(&cx, &device, &[first, invalid])
                    .is_err()
            );
            assert_eq!(
                device
                    .read_block(&cx, BlockNumber(1))
                    .expect("unchanged")
                    .as_slice(),
                before
            );
            assert_eq!(
                device
                    .read_block(&cx, BlockNumber(2))
                    .expect("unchanged")
                    .as_slice(),
                before
            );
        }
        DirectDeviceRecoveryWriteback
            .writeback_recovered(&cx, &device, &[first])
            .expect("valid write");
        assert_eq!(
            device
                .read_block(&cx, BlockNumber(1))
                .expect("updated")
                .as_slice(),
            after
        );
    }

    #[test]
    fn successful_short_before_image_is_not_a_media_erasure() {
        let cx = Cx::for_testing();
        let (mut device, _) = verified_fixture(8);
        device.short_target = true;
        let result = verified_recovery(&cx, &device);
        assert!(!result.is_success());
        assert_eq!(device.writes.load(Ordering::Relaxed), 0);
        assert!(
            result
                .evidence
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("short before-image")
        );
    }

    #[test]
    fn cancelled_empty_recovery_is_not_reported_as_success() {
        let (device, _) = verified_fixture(8);
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let result =
            GroupRecoveryOrchestrator::new(&device, test_uuid(), device.layout, BlockNumber(0), 8)
                .expect("orchestrator")
                .recover_from_indices(&cx, &[]);
        assert!(!result.is_success());
        assert_eq!(device.writes.load(Ordering::Relaxed), 0);
    }
}
