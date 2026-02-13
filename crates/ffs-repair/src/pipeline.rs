//! Automatic corruption recovery pipeline.
//!
//! [`ScrubWithRecovery`] connects the scrub engine ([`Scrubber`]) with the
//! recovery orchestrator ([`GroupRecoveryOrchestrator`]) and the evidence
//! ledger ([`EvidenceLedger`]).  When a scrub pass detects corruption, the
//! pipeline automatically attempts RaptorQ recovery, logs structured evidence
//! for every decision, and optionally refreshes repair symbols after a
//! successful recovery.
//!
//! # Flow
//!
//! ```text
//! scrub range → corrupt blocks → group recovery → evidence → symbol refresh
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use asupersync::Cx;
use ffs_block::BlockDevice;
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, GroupNumber};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, trace, warn};

use crate::autopilot::{DurabilityAutopilot, OverheadDecision};
use crate::codec::{EncodedGroup, encode_group};
use crate::evidence::{
    CorruptionDetail, EvidenceLedger, EvidenceRecord, PolicyDecisionDetail, SymbolRefreshDetail,
};
use crate::recovery::{
    GroupRecoveryOrchestrator, RecoveryAttemptResult, RecoveryDecoderStats, RecoveryOutcome,
};
use crate::scrub::{BlockValidator, ScrubReport, Scrubber, Severity};
use crate::storage::{RepairGroupLayout, RepairGroupStorage};
use crate::symbol::RepairGroupDescExt;

// ── Per-group configuration ───────────────────────────────────────────────

/// Configuration for one block group's recovery-capable scrub.
#[derive(Debug, Clone, Copy)]
pub struct GroupConfig {
    /// On-image tail layout for this group.
    pub layout: RepairGroupLayout,
    /// First source (data) block in this group.
    pub source_first_block: BlockNumber,
    /// Number of source (data) blocks in this group.
    pub source_block_count: u32,
}

// ── Recovery report ───────────────────────────────────────────────────────

/// Outcome for a single block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockOutcome {
    /// Block was clean — no corruption detected.
    Clean,
    /// Block was corrupt and successfully recovered.
    Recovered,
    /// Block was corrupt but recovery failed.
    Unrecoverable,
}

/// Per-group recovery summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRecoverySummary {
    /// Block group number.
    pub group: u32,
    /// Number of corrupt blocks detected in this group.
    pub corrupt_count: usize,
    /// Number of blocks successfully recovered.
    pub recovered_count: usize,
    /// Number of blocks that could not be recovered.
    pub unrecoverable_count: usize,
    /// Whether repair symbols were refreshed after recovery.
    pub symbols_refreshed: bool,
    /// Recovery decoder statistics (if recovery was attempted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoder_stats: Option<RecoveryDecoderStats>,
}

/// Aggregated report from a scrub-with-recovery pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryReport {
    /// Underlying scrub statistics.
    pub blocks_scanned: u64,
    /// Total corrupt blocks detected across all groups.
    pub total_corrupt: usize,
    /// Total blocks successfully recovered.
    pub total_recovered: usize,
    /// Total blocks that could not be recovered.
    pub total_unrecoverable: usize,
    /// Per-block outcomes (only for blocks that had findings).
    pub block_outcomes: BTreeMap<u64, BlockOutcome>,
    /// Per-group recovery summaries.
    pub group_summaries: Vec<GroupRecoverySummary>,
}

impl RecoveryReport {
    /// True if all corrupt blocks were recovered (or none were corrupt).
    #[must_use]
    pub fn is_fully_recovered(&self) -> bool {
        self.total_unrecoverable == 0
    }
}

// ── Pipeline ──────────────────────────────────────────────────────────────

/// Automatic corruption recovery pipeline.
///
/// Wraps a [`Scrubber`] and a set of per-group configurations to provide
/// end-to-end scrub → detect → recover → evidence → refresh.
pub struct ScrubWithRecovery<'a, W: Write> {
    device: &'a dyn BlockDevice,
    validator: &'a dyn BlockValidator,
    fs_uuid: [u8; 16],
    groups: Vec<GroupConfig>,
    ledger: EvidenceLedger<W>,
    /// Static fallback symbol count when adaptive policy is disabled.
    repair_symbol_count: u32,
    /// Optional adaptive overhead policy state.
    adaptive_overhead: Option<DurabilityAutopilot>,
    /// Groups treated as metadata-critical for policy multiplier.
    metadata_groups: BTreeSet<u32>,
    /// Latest adaptive decisions keyed by group number.
    policy_decisions: BTreeMap<u32, OverheadDecision>,
}

impl<'a, W: Write> ScrubWithRecovery<'a, W> {
    /// Create a new pipeline.
    ///
    /// - `device`: block device to scrub and recover on.
    /// - `validator`: pluggable block validation strategy.
    /// - `fs_uuid`: filesystem UUID for deterministic seed derivation.
    /// - `groups`: per-group layout and source range configurations.
    /// - `ledger_writer`: sink for JSONL evidence records.
    /// - `repair_symbol_count`: number of symbols to generate on refresh
    ///   (set to 0 to skip symbol refresh after recovery).
    pub fn new(
        device: &'a dyn BlockDevice,
        validator: &'a dyn BlockValidator,
        fs_uuid: [u8; 16],
        groups: Vec<GroupConfig>,
        ledger_writer: W,
        repair_symbol_count: u32,
    ) -> Self {
        Self {
            device,
            validator,
            fs_uuid,
            groups,
            ledger: EvidenceLedger::new(ledger_writer),
            repair_symbol_count,
            adaptive_overhead: None,
            metadata_groups: BTreeSet::from([0_u32]),
            policy_decisions: BTreeMap::new(),
        }
    }

    /// Enable adaptive Bayesian overhead policy.
    #[must_use]
    pub fn with_adaptive_overhead(mut self, autopilot: DurabilityAutopilot) -> Self {
        self.adaptive_overhead = Some(autopilot);
        self
    }

    /// Override metadata-critical group set for 2x overhead multiplier.
    #[must_use]
    pub fn with_metadata_groups<I>(mut self, groups: I) -> Self
    where
        I: IntoIterator<Item = GroupNumber>,
    {
        self.metadata_groups = groups.into_iter().map(|group| group.0).collect();
        self
    }

    /// Run the full scrub-and-recover pipeline.
    ///
    /// 1. Scrub the device (full or range-based, depending on group configs).
    /// 2. For each group with corruption, attempt RaptorQ recovery.
    /// 3. Log evidence for every detection, recovery attempt, and outcome.
    /// 4. Optionally refresh repair symbols after successful recovery.
    /// 5. Return a [`RecoveryReport`] with per-block outcomes.
    pub fn scrub_and_recover(&mut self, cx: &Cx) -> Result<RecoveryReport> {
        let scrubber = Scrubber::new(self.device, self.validator);

        // Scrub the entire device.
        info!("scrub_and_recover: starting full device scrub");
        let report = scrubber.scrub_all(cx)?;
        debug!(
            blocks_scanned = report.blocks_scanned,
            blocks_corrupt = report.blocks_corrupt,
            findings = report.findings.len(),
            "scrub complete"
        );
        self.update_adaptive_policy(&report)?;

        if report.is_clean() {
            info!("scrub_and_recover: no corruption found");
            return Ok(RecoveryReport {
                blocks_scanned: report.blocks_scanned,
                total_corrupt: 0,
                total_recovered: 0,
                total_unrecoverable: 0,
                block_outcomes: BTreeMap::new(),
                group_summaries: Vec::new(),
            });
        }

        // Group corrupt blocks by their owning group.
        let grouped_corrupt = self.group_corrupt_blocks(&report);

        let mut block_outcomes = BTreeMap::new();
        let mut group_summaries = Vec::new();
        let mut total_recovered: usize = 0;
        let mut total_unrecoverable: usize = 0;

        for (group_cfg, corrupt_blocks) in &grouped_corrupt {
            let summary = self.recover_group(
                cx,
                group_cfg,
                corrupt_blocks,
                &mut block_outcomes,
                &mut total_recovered,
                &mut total_unrecoverable,
            )?;
            group_summaries.push(summary);
        }

        Ok(RecoveryReport {
            blocks_scanned: report.blocks_scanned,
            total_corrupt: grouped_corrupt.iter().map(|(_, blocks)| blocks.len()).sum(),
            total_recovered,
            total_unrecoverable,
            block_outcomes,
            group_summaries,
        })
    }

    /// Consume the pipeline and return the underlying evidence writer.
    #[must_use]
    pub fn into_ledger(self) -> W {
        self.ledger.into_inner()
    }

    // ── Internal helpers ──────────────────────────────────────────────

    fn update_adaptive_policy(&mut self, report: &ScrubReport) -> Result<()> {
        self.policy_decisions.clear();

        let Some(autopilot) = self.adaptive_overhead.as_mut() else {
            return Ok(());
        };

        trace!(
            target: "ffs::repair::policy",
            checked_blocks = report.blocks_scanned,
            corrupted_blocks = report.blocks_corrupt,
            groups_total = self.groups.len(),
            "policy_scrub_observation"
        );
        autopilot.update_posterior(report.blocks_corrupt, report.blocks_scanned);
        let (posterior_alpha, posterior_beta) = autopilot.posterior_params();
        debug!(
            target: "ffs::repair::policy",
            posterior_alpha,
            posterior_beta,
            posterior_mean = autopilot.posterior_mean(),
            "policy_posterior_updated"
        );

        for group_cfg in &self.groups {
            let group = group_cfg.layout.group.0;
            let metadata_group = self.metadata_groups.contains(&group);
            let mut decision = autopilot.decision_for_group(group_cfg.source_block_count, metadata_group);

            if decision.symbols_selected > group_cfg.layout.repair_block_count {
                let effective_symbols = group_cfg.layout.repair_block_count;
                let source_count = group_cfg.source_block_count.max(1);
                let effective_overhead = f64::from(effective_symbols) / f64::from(source_count);
                decision.symbols_selected = effective_symbols;
                decision.overhead_ratio = effective_overhead;
                decision.risk_bound = autopilot.risk_bound(effective_overhead, group_cfg.source_block_count);
                decision.expected_loss =
                    autopilot.expected_loss(effective_overhead, group_cfg.source_block_count);
                warn!(
                    target: "ffs::repair::policy",
                    group,
                    selected_symbols = decision.symbols_selected,
                    layout_capacity = group_cfg.layout.repair_block_count,
                    effective_overhead,
                    "policy_symbol_count_clamped"
                );
            }

            info!(
                target: "ffs::repair::policy",
                group,
                metadata_group = decision.metadata_group,
                selected_overhead = decision.overhead_ratio,
                symbol_count = decision.symbols_selected,
                risk_bound = decision.risk_bound,
                expected_loss = decision.expected_loss,
                "policy_decision_selected"
            );

            let record = EvidenceRecord::policy_decision(
                group,
                PolicyDecisionDetail {
                    corruption_posterior: decision.corruption_posterior,
                    posterior_alpha: decision.posterior_alpha,
                    posterior_beta: decision.posterior_beta,
                    overhead_ratio: decision.overhead_ratio,
                    risk_bound: decision.risk_bound,
                    expected_loss: decision.expected_loss,
                    symbols_selected: decision.symbols_selected,
                    metadata_group: decision.metadata_group,
                    decision: "adaptive_overhead_expected_loss".to_owned(),
                },
            );
            self.ledger.append(&record).map_err(|e| {
                error!(
                    target: "ffs::repair::policy",
                    group,
                    error = %e,
                    "policy_evidence_append_failed"
                );
                FfsError::RepairFailed(format!("failed to write policy evidence: {e}"))
            })?;
            self.policy_decisions.insert(group, decision);
        }

        Ok(())
    }

    #[must_use]
    fn selected_refresh_symbol_count(&self, group_cfg: &GroupConfig) -> u32 {
        self.policy_decisions
            .get(&group_cfg.layout.group.0)
            .map_or(self.repair_symbol_count, |decision| decision.symbols_selected)
    }

    /// Recover a single group's corrupt blocks and return a summary.
    fn recover_group(
        &mut self,
        cx: &Cx,
        group_cfg: &GroupConfig,
        corrupt_blocks: &[BlockNumber],
        block_outcomes: &mut BTreeMap<u64, BlockOutcome>,
        total_recovered: &mut usize,
        total_unrecoverable: &mut usize,
    ) -> Result<GroupRecoverySummary> {
        let group_num = group_cfg.layout.group;

        // Log corruption detection evidence.
        self.log_corruption_detected(group_num, corrupt_blocks)?;

        info!(
            group = group_num.0,
            corrupt_count = corrupt_blocks.len(),
            "attempting recovery for group"
        );

        // Attempt recovery.
        let recovery_result = self.attempt_group_recovery(cx, group_cfg, corrupt_blocks);

        // Log recovery evidence.
        let evidence_record = EvidenceRecord::from_recovery(&recovery_result.evidence);
        self.ledger.append(&evidence_record).map_err(|e| {
            FfsError::RepairFailed(format!("failed to write recovery evidence: {e}"))
        })?;

        let mut symbols_refreshed = false;

        match recovery_result.evidence.outcome {
            RecoveryOutcome::Recovered => {
                info!(
                    group = group_num.0,
                    blocks_recovered = recovery_result.repaired_blocks.len(),
                    "recovery successful"
                );
                for block in &recovery_result.repaired_blocks {
                    block_outcomes.insert(block.0, BlockOutcome::Recovered);
                }
                *total_recovered += recovery_result.repaired_blocks.len();

                // Refresh symbols after successful recovery.
                let refresh_symbol_count = self.selected_refresh_symbol_count(group_cfg);
                if refresh_symbol_count > 0 {
                    match self.refresh_symbols(cx, group_cfg, refresh_symbol_count) {
                        Ok(()) => {
                            symbols_refreshed = true;
                            info!(group = group_num.0, "repair symbols refreshed");
                        }
                        Err(e) => {
                            error!(
                                group = group_num.0,
                                error = %e,
                                "failed to refresh repair symbols"
                            );
                        }
                    }
                }
            }
            RecoveryOutcome::Partial => {
                warn!(
                    group = group_num.0,
                    reason = recovery_result
                        .evidence
                        .reason
                        .as_deref()
                        .unwrap_or("unknown"),
                    "partial recovery"
                );
                for block in &recovery_result.repaired_blocks {
                    block_outcomes.insert(block.0, BlockOutcome::Recovered);
                }
                *total_recovered += recovery_result.repaired_blocks.len();

                // Mark remaining corrupt blocks as unrecoverable.
                let repaired_set: std::collections::BTreeSet<u64> = recovery_result
                    .repaired_blocks
                    .iter()
                    .map(|b| b.0)
                    .collect();
                for block in corrupt_blocks {
                    if !repaired_set.contains(&block.0) {
                        block_outcomes.insert(block.0, BlockOutcome::Unrecoverable);
                        *total_unrecoverable += 1;
                    }
                }
            }
            RecoveryOutcome::Failed => {
                error!(
                    group = group_num.0,
                    reason = recovery_result
                        .evidence
                        .reason
                        .as_deref()
                        .unwrap_or("unknown"),
                    "recovery failed"
                );
                for block in corrupt_blocks {
                    block_outcomes.insert(block.0, BlockOutcome::Unrecoverable);
                }
                *total_unrecoverable += corrupt_blocks.len();
            }
        }

        Ok(GroupRecoverySummary {
            group: group_num.0,
            corrupt_count: corrupt_blocks.len(),
            recovered_count: recovery_result.repaired_blocks.len(),
            unrecoverable_count: corrupt_blocks.len() - recovery_result.repaired_blocks.len(),
            symbols_refreshed,
            decoder_stats: Some(recovery_result.evidence.decoder_stats),
        })
    }

    /// Group corrupt block numbers by their owning group configuration.
    ///
    /// Blocks that don't fall into any configured group are logged and skipped.
    fn group_corrupt_blocks(&self, report: &ScrubReport) -> Vec<(GroupConfig, Vec<BlockNumber>)> {
        // Only consider Error-or-above severity findings.
        let corrupt_blocks: Vec<BlockNumber> = report
            .findings
            .iter()
            .filter(|f| f.severity >= Severity::Error)
            .map(|f| f.block)
            .collect();

        // Deduplicate block numbers (a block may have multiple findings).
        let mut unique_blocks = corrupt_blocks;
        unique_blocks.sort_unstable_by_key(|b| b.0);
        unique_blocks.dedup_by_key(|b| b.0);

        let mut result: Vec<(GroupConfig, Vec<BlockNumber>)> = Vec::new();

        for block in unique_blocks {
            let mut found = false;
            for group_cfg in &self.groups {
                let start = group_cfg.source_first_block.0;
                let end = start + u64::from(group_cfg.source_block_count);
                if block.0 >= start && block.0 < end {
                    // Find or create entry for this group.
                    if let Some(entry) = result
                        .iter_mut()
                        .find(|(g, _)| g.layout.group == group_cfg.layout.group)
                    {
                        entry.1.push(block);
                    } else {
                        result.push((*group_cfg, vec![block]));
                    }
                    found = true;
                    break;
                }
            }
            if !found {
                warn!(
                    block = block.0,
                    "corrupt block does not belong to any configured group"
                );
            }
        }

        result
    }

    /// Attempt recovery for one group.
    fn attempt_group_recovery(
        &self,
        cx: &Cx,
        group_cfg: &GroupConfig,
        corrupt_blocks: &[BlockNumber],
    ) -> RecoveryAttemptResult {
        let orchestrator = match GroupRecoveryOrchestrator::new(
            self.device,
            self.fs_uuid,
            group_cfg.layout,
            group_cfg.source_first_block,
            group_cfg.source_block_count,
        ) {
            Ok(o) => o,
            Err(e) => {
                error!(
                    group = group_cfg.layout.group.0,
                    error = %e,
                    "failed to create recovery orchestrator"
                );
                return RecoveryAttemptResult {
                    evidence: crate::recovery::RecoveryEvidence {
                        group: group_cfg.layout.group.0,
                        generation: 0,
                        corrupt_count: corrupt_blocks.len(),
                        symbols_available: 0,
                        symbols_used: 0,
                        decoder_stats: RecoveryDecoderStats::default(),
                        outcome: RecoveryOutcome::Failed,
                        reason: Some(format!("orchestrator creation failed: {e}")),
                    },
                    repaired_blocks: Vec::new(),
                };
            }
        };

        debug!(
            group = group_cfg.layout.group.0,
            corrupt_count = corrupt_blocks.len(),
            "calling recovery orchestrator"
        );
        orchestrator.recover_from_corrupt_blocks(cx, corrupt_blocks)
    }

    /// Re-encode repair symbols for a group after successful recovery.
    fn refresh_symbols(
        &mut self,
        cx: &Cx,
        group_cfg: &GroupConfig,
        repair_symbol_count: u32,
    ) -> Result<()> {
        let group_num = group_cfg.layout.group;
        let storage = RepairGroupStorage::new(self.device, group_cfg.layout);

        // Read current generation.
        let old_desc = storage.read_group_desc_ext(cx)?;
        let old_gen = old_desc.repair_generation;
        let effective_symbol_count = repair_symbol_count.min(group_cfg.layout.repair_block_count);
        if effective_symbol_count != repair_symbol_count {
            warn!(
                target: "ffs::repair::policy",
                group = group_num.0,
                selected_symbols = repair_symbol_count,
                layout_capacity = group_cfg.layout.repair_block_count,
                effective_overhead = f64::from(effective_symbol_count)
                    / f64::from(group_cfg.source_block_count.max(1)),
                "policy_symbol_count_clamped"
            );
        }

        debug!(
            group = group_num.0,
            previous_generation = old_gen,
            requested_symbols = repair_symbol_count,
            effective_symbols = effective_symbol_count,
            "refreshing repair symbols"
        );

        // Re-encode.
        let encoded: EncodedGroup = encode_group(
            cx,
            self.device,
            &self.fs_uuid,
            group_num,
            group_cfg.source_first_block,
            group_cfg.source_block_count,
            effective_symbol_count,
        )?;

        let new_gen = old_gen + 1;

        // Write symbols.
        let symbols: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .into_iter()
            .map(|s| (s.esi, s.data))
            .collect();
        let symbols_generated = u32::try_from(symbols.len()).unwrap_or(u32::MAX);

        storage.write_repair_symbols(cx, &symbols, new_gen)?;

        // Write updated descriptor.
        let new_desc = RepairGroupDescExt {
            repair_generation: new_gen,
            ..old_desc
        };
        storage.write_group_desc_ext(cx, &new_desc)?;

        trace!(
            group = group_num.0,
            new_generation = new_gen,
            symbols_generated,
            "symbol refresh complete"
        );

        // Log evidence.
        let evidence = EvidenceRecord::symbol_refresh(
            group_num.0,
            SymbolRefreshDetail {
                previous_generation: old_gen,
                new_generation: new_gen,
                symbols_generated,
            },
        );
        self.ledger.append(&evidence).map_err(|e| {
            FfsError::RepairFailed(format!("failed to write symbol refresh evidence: {e}"))
        })?;

        Ok(())
    }

    /// Log corruption detection events for a group.
    fn log_corruption_detected(
        &mut self,
        group: GroupNumber,
        corrupt_blocks: &[BlockNumber],
    ) -> Result<()> {
        warn!(
            group = group.0,
            corrupt_blocks = corrupt_blocks.len(),
            "corruption detected"
        );

        let detail = CorruptionDetail {
            blocks_affected: u32::try_from(corrupt_blocks.len()).unwrap_or(u32::MAX),
            corruption_kind: "checksum_mismatch".to_owned(),
            severity: "error".to_owned(),
            detail: format!(
                "blocks: {:?}",
                corrupt_blocks
                    .iter()
                    .take(16)
                    .map(|b| b.0)
                    .collect::<Vec<_>>()
            ),
        };
        let record = EvidenceRecord::corruption_detected(group.0, detail);
        self.ledger.append(&record).map_err(|e| {
            FfsError::RepairFailed(format!("failed to write corruption evidence: {e}"))
        })?;
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode_group;
    use crate::scrub::{BlockVerdict, CorruptionKind, Severity};
    use crate::symbol::RepairGroupDescExt;
    use ffs_block::BlockBuf;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // ── In-memory block device ────────────────────────────────────────

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

    // ── Helpers ───────────────────────────────────────────────────────

    fn test_uuid() -> [u8; 16] {
        [0x22; 16]
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
    ) -> Vec<Vec<u8>> {
        let block_size = device.block_size();
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

    /// Validator that flags specific block numbers as corrupt.
    struct CorruptBlockValidator {
        corrupt_blocks: Vec<u64>,
    }

    impl CorruptBlockValidator {
        fn new(corrupt_blocks: Vec<u64>) -> Self {
            Self { corrupt_blocks }
        }
    }

    impl BlockValidator for CorruptBlockValidator {
        fn validate(&self, block: BlockNumber, _data: &BlockBuf) -> BlockVerdict {
            if self.corrupt_blocks.contains(&block.0) {
                BlockVerdict::Corrupt(vec![(
                    CorruptionKind::ChecksumMismatch,
                    Severity::Error,
                    format!("injected corruption at block {}", block.0),
                )])
            } else {
                BlockVerdict::Clean
            }
        }
    }

    // ── Unit tests ────────────────────────────────────────────────────

    #[test]
    fn single_corrupt_block_automatic_recovery() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        let originals = write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        // Inject corruption at block 3.
        let corrupt_block = BlockNumber(3);
        device
            .write_block(&cx, corrupt_block, &vec![0xDE; block_size as usize])
            .expect("inject corruption");

        let validator = CorruptBlockValidator::new(vec![3]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert!(
            report.is_fully_recovered(),
            "expected full recovery: {report:?}"
        );
        assert_eq!(report.total_corrupt, 1);
        assert_eq!(report.total_recovered, 1);
        assert_eq!(report.total_unrecoverable, 0);
        assert_eq!(
            report.block_outcomes.get(&3),
            Some(&BlockOutcome::Recovered)
        );

        // Verify the block was actually restored.
        let restored = device.read_block(&cx, corrupt_block).expect("read");
        assert_eq!(restored.as_slice(), originals[3].as_slice());
    }

    #[test]
    fn multiple_corrupt_blocks_same_group_recovered() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        let originals = write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        // Corrupt blocks 1 and 5.
        for idx in [1_u64, 5] {
            device
                .write_block(&cx, BlockNumber(idx), &vec![0xAA; block_size as usize])
                .expect("inject corruption");
        }

        let validator = CorruptBlockValidator::new(vec![1, 5]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert!(report.is_fully_recovered());
        assert_eq!(report.total_corrupt, 2);
        assert_eq!(report.total_recovered, 2);

        for idx in [1_u64, 5] {
            let restored = device.read_block(&cx, BlockNumber(idx)).expect("read");
            assert_eq!(
                restored.as_slice(),
                originals[usize::try_from(idx).unwrap()].as_slice(),
                "block {idx} not restored"
            );
        }
    }

    #[test]
    fn too_many_corrupt_blocks_graceful_failure() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 2).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 1);

        // Corrupt 3 blocks but only 1 repair symbol available.
        for idx in [0_u64, 1, 2] {
            device
                .write_block(&cx, BlockNumber(idx), &vec![0xBB; block_size as usize])
                .expect("inject corruption");
        }

        let validator = CorruptBlockValidator::new(vec![0, 1, 2]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            0, // no refresh
        );

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert!(!report.is_fully_recovered());
        assert_eq!(report.total_corrupt, 3);
        assert_eq!(report.total_unrecoverable, 3);

        // All blocks marked unrecoverable.
        for idx in [0_u64, 1, 2] {
            assert_eq!(
                report.block_outcomes.get(&idx),
                Some(&BlockOutcome::Unrecoverable),
                "block {idx} should be unrecoverable"
            );
        }
    }

    #[test]
    fn clean_scrub_produces_empty_report() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 64);

        // Write non-zero data to all blocks so ZeroCheckValidator won't trigger.
        for i in 0..64 {
            let data = deterministic_block(i, block_size);
            device
                .write_block(&cx, BlockNumber(i), &data)
                .expect("write");
        }

        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 32, 0, 2).expect("layout");
        let group_cfg = GroupConfig {
            layout,
            source_first_block: BlockNumber(0),
            source_block_count: 8,
        };

        // Validator that always says clean.
        let validator = CorruptBlockValidator::new(vec![]);

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            0,
        );

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert!(report.is_fully_recovered());
        assert_eq!(report.total_corrupt, 0);
        assert_eq!(report.total_recovered, 0);
        assert_eq!(report.blocks_scanned, 64);
        assert!(report.group_summaries.is_empty());
    }

    #[test]
    fn evidence_ledger_captures_all_events() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        device
            .write_block(&cx, BlockNumber(2), &vec![0xCC; block_size as usize])
            .expect("inject corruption");

        let validator = CorruptBlockValidator::new(vec![2]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4, // enable refresh
        );

        let _report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        let ledger_data = pipeline.into_ledger();

        let records = crate::evidence::parse_evidence_ledger(ledger_data);
        assert!(
            records.len() >= 3,
            "expected at least 3 evidence records (corruption + repair + refresh), got {}",
            records.len()
        );

        // First record: corruption detected.
        assert_eq!(
            records[0].event_type,
            crate::evidence::EvidenceEventType::CorruptionDetected
        );
        // Second record: repair succeeded.
        assert_eq!(
            records[1].event_type,
            crate::evidence::EvidenceEventType::RepairSucceeded
        );
        // Third record: symbol refresh.
        assert_eq!(
            records[2].event_type,
            crate::evidence::EvidenceEventType::SymbolRefresh
        );
    }

    #[test]
    fn symbol_refresh_after_recovery() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        device
            .write_block(&cx, BlockNumber(1), &vec![0xDD; block_size as usize])
            .expect("inject corruption");

        let validator = CorruptBlockValidator::new(vec![1]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert!(report.is_fully_recovered());

        // Verify generation was bumped.
        let storage = RepairGroupStorage::new(&device, layout);
        let desc = storage.read_group_desc_ext(&cx).expect("read desc");
        assert!(
            desc.repair_generation >= 2,
            "expected generation >= 2 after refresh, got {}",
            desc.repair_generation
        );

        // Verify symbols_refreshed in group summary.
        assert_eq!(report.group_summaries.len(), 1);
        assert!(report.group_summaries[0].symbols_refreshed);
    }

    #[test]
    fn stress_random_corruption_patterns() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 8).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 16;

        let originals = write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 8);

        // Corrupt up to 4 blocks (within RaptorQ capacity of 8 symbols).
        let corrupt_indices: Vec<u64> = vec![2, 7, 11, 14];
        for &idx in &corrupt_indices {
            device
                .write_block(&cx, BlockNumber(idx), &vec![0xEE; block_size as usize])
                .expect("inject corruption");
        }

        let validator = CorruptBlockValidator::new(corrupt_indices.clone());
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            8,
        );

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert!(
            report.is_fully_recovered(),
            "expected full recovery: corrupt={} recovered={} unrecoverable={}",
            report.total_corrupt,
            report.total_recovered,
            report.total_unrecoverable,
        );
        assert_eq!(report.total_corrupt, 4);
        assert_eq!(report.total_recovered, 4);

        // Verify all blocks restored correctly.
        for &idx in &corrupt_indices {
            let restored = device.read_block(&cx, BlockNumber(idx)).expect("read");
            assert_eq!(
                restored.as_slice(),
                originals[usize::try_from(idx).unwrap()].as_slice(),
                "block {idx} not restored correctly"
            );
        }
    }
}
