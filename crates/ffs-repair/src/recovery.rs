//! Corruption recovery orchestration for one block group.
//!
//! This module wires together:
//! - symbol retrieval (`storage`)
//! - RaptorQ decode (`codec`)
//! - block writeback + verification
//! - structured evidence ledger emission
//!
//! V1 signal model: caller provides explicit corrupt block indices.

use asupersync::Cx;
use asupersync::raptorq::decoder::DecodeStats;
use ffs_block::BlockDevice;
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, GroupNumber};
use serde::{Deserialize, Serialize};

use crate::codec::{DecodeOutcome, decode_group_with_owned_repair_symbols};
use crate::storage::{RepairGroupLayout, RepairGroupStorage};

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

        // Pre-write compare-and-write gate: confirm each block still matches the
        // scrub-time bytes. The reads are independent, so overlap them across the
        // rayon pool (a blocking read parks its worker); consume the per-block
        // outcomes in index order so the first compare failure reported is
        // identical to the serial loop's (I/O-overlap, bd-307e4/bd-g5v1s family).
        let gate: Vec<Result<()>> = recovered
            .par_iter()
            .map(|block| {
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
            device.write_block(cx, block.block, block.data)?;
        }
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
        Ok(())
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
}

impl<'a> GroupRecoveryOrchestrator<'a> {
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
        if normalized.is_empty() {
            return self.success_result(0, 0, 0, RecoveryDecoderStats::default(), Vec::new());
        }

        let expected_current = match self.capture_expected_current_blocks(cx, normalized) {
            Ok(expected_current) => expected_current,
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

        let desc = match self.storage.read_group_desc_ext(cx) {
            Ok(desc) => desc,
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

        let symbols = match self.storage.read_repair_symbols(cx) {
            Ok(symbols) => symbols,
            Err(err) => {
                return self.failure_result(
                    generation,
                    normalized.len(),
                    0,
                    0,
                    RecoveryDecoderStats::default(),
                    &err,
                );
            }
        };

        let symbols_available = symbols.len();
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

        self.finish_decode(
            cx,
            generation,
            normalized.len(),
            symbols_available,
            &decode,
            &expected_current,
        )
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
                let bytes = self.device.read_block(cx, block)?.as_slice().to_vec();
                Ok((block, bytes))
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
        let mut writeback_blocks = Vec::with_capacity(decode.recovered.len());
        // Both inputs preserve the normalized corrupt-index order. Pair the
        // common path by ordinal position and retain the binary search as a
        // behavior-preserving fallback for an unexpectedly reordered decode.
        for (position, recovered) in decode.recovered.iter().enumerate() {
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
        assert!(result.repaired_blocks.is_empty());
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
}
