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

use crate::codec::{DecodeOutcome, decode_group};
use crate::storage::{RepairGroupLayout, RepairGroupStorage};

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

        if normalized.is_empty() {
            return self.success_result(0, 0, 0, RecoveryDecoderStats::default(), Vec::new());
        }

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
        let decode = match decode_group(
            cx,
            self.device,
            &self.fs_uuid,
            self.group(),
            self.source_first_block,
            self.source_block_count,
            &normalized,
            &symbols,
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

        self.finish_decode(cx, generation, normalized.len(), symbols_available, &decode)
    }

    /// Recover from absolute corrupt block numbers.
    #[must_use]
    pub fn recover_from_corrupt_blocks(
        &self,
        cx: &Cx,
        corrupt_blocks: &[BlockNumber],
    ) -> RecoveryAttemptResult {
        match self.map_corrupt_blocks_to_indices(corrupt_blocks) {
            Ok(indices) => self.recover_from_indices(cx, &indices),
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
        if let Err(err) = self.writeback_recovered(cx, decode) {
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

    fn writeback_recovered(&self, cx: &Cx, decode: &DecodeOutcome) -> Result<()> {
        for block in &decode.recovered {
            self.device.write_block(cx, block.block, &block.data)?;
        }
        self.device.sync(cx)?;
        for block in &decode.recovered {
            let observed = self.device.read_block(cx, block.block)?;
            if observed.as_slice() != block.data {
                return Err(FfsError::RepairFailed(format!(
                    "post-repair verification failed at block {}",
                    block.block.0
                )));
            }
        }
        Ok(())
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
    use std::collections::HashMap;
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
        assert!(
            result
                .evidence
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("insufficient symbols"),
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
}
