use anyhow::{Context, Result, bail};
use ffs_block::CacheRuntimeMetricsSnapshot;
use ffs_fuse::MetricsSnapshot;
use ffs_repair::evidence::{EvidenceEventType, EvidenceRecord};
use ffs_repair::pipeline::RepairRuntimeMetricsSnapshot;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Instant;
use tracing::{info, info_span, warn};

// ── Preset definitions ─────────────────────────────────────────────────────

/// Operator-oriented preset query names and their constituent event types.
pub const PRESET_REPLAY_ANOMALIES: &str = "replay-anomalies";
pub const PRESET_REPAIR_FAILURES: &str = "repair-failures";
pub const PRESET_PRESSURE_TRANSITIONS: &str = "pressure-transitions";
pub const PRESET_CONTENTION: &str = "contention";
pub const PRESET_METRICS: &str = "metrics";
pub const PRESET_CACHE: &str = "cache";
pub const PRESET_MVCC: &str = "mvcc";
pub const PRESET_REPAIR_LIVE: &str = "repair-live";

/// Returns the event types included in a preset, or `None` if unknown.
pub fn preset_event_types(preset: &str) -> Option<&'static [EvidenceEventType]> {
    match preset {
        PRESET_REPLAY_ANOMALIES => Some(&[
            EvidenceEventType::WalRecovery,
            EvidenceEventType::TxnAborted,
            EvidenceEventType::SerializationConflict,
        ]),
        PRESET_REPAIR_FAILURES => Some(&[
            EvidenceEventType::CorruptionDetected,
            EvidenceEventType::RepairAttempted,
            EvidenceEventType::RepairSucceeded,
            EvidenceEventType::RepairFailed,
            EvidenceEventType::ScrubCycleComplete,
        ]),
        PRESET_PRESSURE_TRANSITIONS => Some(&[
            EvidenceEventType::BackpressureActivated,
            EvidenceEventType::FlushBatch,
            EvidenceEventType::DurabilityPolicyChanged,
            EvidenceEventType::RefreshPolicyChanged,
        ]),
        PRESET_CONTENTION => Some(&[
            EvidenceEventType::MergeProofChecked,
            EvidenceEventType::MergeApplied,
            EvidenceEventType::MergeRejected,
            EvidenceEventType::PolicySwitched,
            EvidenceEventType::ContentionSample,
        ]),
        PRESET_METRICS => Some(&[
            EvidenceEventType::VersionGc,
            EvidenceEventType::SnapshotAdvanced,
            EvidenceEventType::FlushBatch,
            EvidenceEventType::BackpressureActivated,
            EvidenceEventType::PolicyDecision,
            EvidenceEventType::ContentionSample,
        ]),
        PRESET_CACHE => Some(&[
            EvidenceEventType::FlushBatch,
            EvidenceEventType::BackpressureActivated,
            EvidenceEventType::DirtyBlockDiscarded,
        ]),
        PRESET_MVCC => Some(&[
            EvidenceEventType::TransactionCommit,
            EvidenceEventType::TxnAborted,
            EvidenceEventType::SerializationConflict,
            EvidenceEventType::VersionGc,
            EvidenceEventType::SnapshotAdvanced,
            EvidenceEventType::ContentionSample,
            EvidenceEventType::MergeApplied,
            EvidenceEventType::MergeRejected,
            EvidenceEventType::PolicySwitched,
        ]),
        PRESET_REPAIR_LIVE => Some(&[
            EvidenceEventType::CorruptionDetected,
            EvidenceEventType::RepairAttempted,
            EvidenceEventType::RepairSucceeded,
            EvidenceEventType::RepairFailed,
            EvidenceEventType::SymbolRefresh,
            EvidenceEventType::ScrubCycleComplete,
            EvidenceEventType::PolicyDecision,
        ]),
        _ => None,
    }
}

/// All known preset names.
pub const KNOWN_PRESETS: &[&str] = &[
    PRESET_REPLAY_ANOMALIES,
    PRESET_REPAIR_FAILURES,
    PRESET_PRESSURE_TRANSITIONS,
    PRESET_CONTENTION,
    PRESET_METRICS,
    PRESET_CACHE,
    PRESET_MVCC,
    PRESET_REPAIR_LIVE,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PresetMode {
    Ledger,
    Metrics,
}

fn preset_mode(preset: &str) -> Option<PresetMode> {
    match preset {
        PRESET_REPLAY_ANOMALIES
        | PRESET_REPAIR_FAILURES
        | PRESET_PRESSURE_TRANSITIONS
        | PRESET_CONTENTION => Some(PresetMode::Ledger),
        PRESET_METRICS | PRESET_CACHE | PRESET_MVCC | PRESET_REPAIR_LIVE => {
            Some(PresetMode::Metrics)
        }
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceMetricsBundle {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheRuntimeMetricsSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mvcc: Option<EvidenceMvccRuntimeMetricsSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repair_live: Option<RepairRuntimeMetricsSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MetricsAggregateAnalysis {
    pub request_error_rate: f64,
    pub throttled_ratio: f64,
    pub shed_ratio: f64,
    pub cache_miss_rate: Option<f64>,
    pub cache_dirty_pressure: Option<String>,
    pub mvcc_commit_success_rate: Option<f64>,
    pub mvcc_contention_level: Option<String>,
    pub repair_decode_success_rate: Option<f64>,
    pub repair_freshness: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MetricsAggregateReport {
    pub preset: String,
    pub analyses: MetricsAggregateAnalysis,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheRuntimeMetricsSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mvcc: Option<EvidenceMvccRuntimeMetricsSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repair_live: Option<RepairRuntimeMetricsSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CacheMetricsReport {
    pub preset: String,
    pub snapshot: CacheRuntimeMetricsSnapshot,
    pub total_accesses: u64,
    pub miss_rate: f64,
    pub dirty_pressure: String,
    pub writeback_pressure: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MvccMetricsReport {
    pub preset: String,
    pub snapshot: EvidenceMvccRuntimeMetricsSnapshot,
    pub commit_success_rate: f64,
    pub contention_level: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RepairLiveMetricsReport {
    pub preset: String,
    pub snapshot: RepairRuntimeMetricsSnapshot,
    pub decode_success_rate: f64,
    pub freshness: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum MetricsPresetReport {
    Aggregate(Box<MetricsAggregateReport>),
    Cache(CacheMetricsReport),
    Mvcc(MvccMetricsReport),
    RepairLive(RepairLiveMetricsReport),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceHistogramBucket {
    pub le: u64,
    pub count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceHistogramSnapshot {
    pub buckets: Vec<EvidenceHistogramBucket>,
    pub inf_count: u64,
    pub sum: u64,
    pub count: u64,
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EvidenceMvccRuntimeMetricsSnapshot {
    pub active_snapshots: usize,
    pub commit_rate: f64,
    pub conflict_rate: f64,
    pub abort_rate: f64,
    pub version_chain_max_length: usize,
    pub prune_throughput: f64,
    pub commit_attempts_total: u64,
    pub commit_successes_total: u64,
    pub conflicts_total: u64,
    pub aborts_total: u64,
    pub pruned_versions_total: u64,
    pub commit_latency_us: EvidenceHistogramSnapshot,
    pub conflict_resolution_latency_us: EvidenceHistogramSnapshot,
}

// ── Summary ────────────────────────────────────────────────────────────────

/// Aggregated summary of evidence records.
#[derive(Debug, serde::Serialize)]
pub struct EvidenceSummary {
    pub total_records: usize,
    pub event_type_counts: BTreeMap<String, usize>,
    pub time_span_ns: Option<(u64, u64)>,
    pub block_groups_seen: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_summary: Option<ReplaySummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repair_summary: Option<RepairSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pressure_summary: Option<PressureSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contention_summary: Option<ContentionSummary>,
}

#[derive(Debug, serde::Serialize)]
pub struct ReplaySummary {
    pub recovery_count: usize,
    pub total_commits_replayed: u64,
    pub total_records_discarded: u64,
    pub aborts: usize,
    pub conflicts: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct RepairSummary {
    pub corruptions_detected: usize,
    pub repairs_attempted: usize,
    pub repairs_succeeded: usize,
    pub repairs_failed: usize,
    pub scrub_cycles: usize,
    pub total_blocks_corrupt: u64,
}

#[derive(Debug, serde::Serialize)]
pub struct PressureSummary {
    pub backpressure_events: usize,
    pub flush_batches: usize,
    pub total_blocks_flushed: u64,
    pub policy_changes: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct ContentionSummary {
    pub merge_proofs_checked: usize,
    pub merge_proofs_valid: usize,
    pub merge_proofs_invalid: usize,
    pub merges_applied: usize,
    pub merges_rejected: usize,
    pub total_merged_blocks: u64,
    pub total_combined_write_set_bytes: u64,
    pub policy_switches: usize,
    pub contention_samples: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_conflict_rate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_merge_success_rate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_abort_rate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_total_commits: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_total_conflicts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_total_merges: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_total_aborts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_effective_policy: Option<String>,
}

/// Mutable accumulators for building an evidence summary.
#[derive(Default)]
struct SummaryAccumulator {
    event_type_counts: BTreeMap<String, usize>,
    min_ts: Option<u64>,
    max_ts: Option<u64>,
    groups: Vec<u32>,
    // Replay
    recovery_count: usize,
    total_commits_replayed: u64,
    total_records_discarded: u64,
    aborts: usize,
    conflicts: usize,
    // Repair
    corruptions_detected: usize,
    repairs_attempted: usize,
    repairs_succeeded: usize,
    repairs_failed: usize,
    scrub_cycles: usize,
    total_blocks_corrupt: u64,
    // Pressure
    backpressure_events: usize,
    flush_batches: usize,
    total_blocks_flushed: u64,
    policy_changes: usize,
    // Contention
    merge_proofs_checked: usize,
    merge_proofs_valid: usize,
    merge_proofs_invalid: usize,
    merges_applied: usize,
    merges_rejected: usize,
    total_merged_blocks: u64,
    total_combined_write_set_bytes: u64,
    policy_switches: usize,
    contention_samples: usize,
    latest_conflict_rate: Option<f64>,
    latest_merge_success_rate: Option<f64>,
    latest_abort_rate: Option<f64>,
    latest_total_commits: Option<u64>,
    latest_total_conflicts: Option<u64>,
    latest_total_merges: Option<u64>,
    latest_total_aborts: Option<u64>,
    latest_effective_policy: Option<String>,
}

impl SummaryAccumulator {
    fn ingest(&mut self, record: &EvidenceRecord) {
        let name = evidence_event_type_name(record.event_type);
        let event_count = self.event_type_counts.entry(name.to_owned()).or_insert(0);
        Self::increment_usize(event_count);

        let ts = record.timestamp_ns;
        self.min_ts = Some(self.min_ts.map_or(ts, |m: u64| m.min(ts)));
        self.max_ts = Some(self.max_ts.map_or(ts, |m: u64| m.max(ts)));

        if record.block_group != 0 && !self.groups.contains(&record.block_group) {
            self.groups.push(record.block_group);
        }

        match record.event_type {
            EvidenceEventType::WalRecovery => {
                Self::increment_usize(&mut self.recovery_count);
                if let Some(w) = record.wal_recovery.as_ref() {
                    Self::add_u64(&mut self.total_commits_replayed, w.commits_replayed);
                    Self::add_u64(&mut self.total_records_discarded, w.records_discarded);
                }
            }
            EvidenceEventType::TxnAborted => Self::increment_usize(&mut self.aborts),
            EvidenceEventType::SerializationConflict => Self::increment_usize(&mut self.conflicts),
            EvidenceEventType::CorruptionDetected => {
                Self::increment_usize(&mut self.corruptions_detected);
                if let Some(c) = record.corruption.as_ref() {
                    Self::add_u64(&mut self.total_blocks_corrupt, u64::from(c.blocks_affected));
                }
            }
            EvidenceEventType::RepairAttempted => {
                Self::increment_usize(&mut self.repairs_attempted);
            }
            EvidenceEventType::RepairSucceeded => {
                Self::increment_usize(&mut self.repairs_succeeded);
            }
            EvidenceEventType::RepairFailed => {
                Self::increment_usize(&mut self.repairs_failed);
            }
            EvidenceEventType::ScrubCycleComplete => Self::increment_usize(&mut self.scrub_cycles),
            EvidenceEventType::BackpressureActivated => {
                Self::increment_usize(&mut self.backpressure_events);
            }
            EvidenceEventType::FlushBatch => {
                Self::increment_usize(&mut self.flush_batches);
                if let Some(f) = record.flush_batch.as_ref() {
                    Self::add_u64(&mut self.total_blocks_flushed, f.blocks_flushed);
                }
            }
            EvidenceEventType::DurabilityPolicyChanged
            | EvidenceEventType::RefreshPolicyChanged => {
                Self::increment_usize(&mut self.policy_changes);
            }
            EvidenceEventType::MergeProofChecked => {
                Self::increment_usize(&mut self.merge_proofs_checked);
                if let Some(proof) = record.merge_proof_checked.as_ref() {
                    if proof.valid {
                        Self::increment_usize(&mut self.merge_proofs_valid);
                    } else {
                        Self::increment_usize(&mut self.merge_proofs_invalid);
                    }
                }
            }
            EvidenceEventType::MergeApplied => {
                Self::increment_usize(&mut self.merges_applied);
                if let Some(merge) = record.merge_applied.as_ref() {
                    Self::add_usize_as_u64(&mut self.total_merged_blocks, merge.merged_block_count);
                    Self::add_usize_as_u64(
                        &mut self.total_combined_write_set_bytes,
                        merge.combined_write_set_bytes,
                    );
                }
            }
            EvidenceEventType::MergeRejected => {
                Self::increment_usize(&mut self.merges_rejected);
            }
            EvidenceEventType::PolicySwitched => {
                Self::increment_usize(&mut self.policy_switches);
                if let Some(policy) = record.policy_switched.as_ref() {
                    self.latest_effective_policy = Some(policy.to_policy.clone());
                }
            }
            EvidenceEventType::ContentionSample => {
                Self::increment_usize(&mut self.contention_samples);
                if let Some(sample) = record.contention_sample.as_ref() {
                    self.latest_conflict_rate = Some(sample.conflict_rate);
                    self.latest_merge_success_rate = Some(sample.merge_success_rate);
                    self.latest_abort_rate = Some(sample.abort_rate);
                    self.latest_total_commits = Some(sample.total_commits);
                    self.latest_total_conflicts = Some(sample.total_conflicts);
                    self.latest_total_merges = Some(sample.total_merges);
                    self.latest_total_aborts = Some(sample.total_aborts);
                    self.latest_effective_policy = Some(sample.effective_policy.clone());
                }
            }
            _ => {}
        }
    }

    fn increment_usize(counter: &mut usize) {
        *counter = counter.saturating_add(1);
    }

    fn add_u64(total: &mut u64, delta: u64) {
        *total = total.saturating_add(delta);
    }

    fn add_usize_as_u64(total: &mut u64, delta: usize) {
        *total = total.saturating_add(u64::try_from(delta).unwrap_or(u64::MAX));
    }

    fn finalize(mut self, total: usize, preset: Option<&str>) -> EvidenceSummary {
        self.groups.sort_unstable();
        let has_replay = self.recovery_count > 0 || self.aborts > 0 || self.conflicts > 0;
        let has_repair = self.corruptions_detected > 0
            || self.repairs_attempted > 0
            || self.repairs_succeeded > 0
            || self.repairs_failed > 0
            || self.scrub_cycles > 0;
        let has_pressure =
            self.backpressure_events > 0 || self.flush_batches > 0 || self.policy_changes > 0;
        let has_contention = self.merge_proofs_checked > 0
            || self.merges_applied > 0
            || self.merges_rejected > 0
            || self.policy_switches > 0
            || self.contention_samples > 0;

        EvidenceSummary {
            total_records: total,
            event_type_counts: self.event_type_counts,
            time_span_ns: self.min_ts.zip(self.max_ts),
            block_groups_seen: self.groups,
            preset: preset.map(str::to_owned),
            replay_summary: if has_replay {
                Some(ReplaySummary {
                    recovery_count: self.recovery_count,
                    total_commits_replayed: self.total_commits_replayed,
                    total_records_discarded: self.total_records_discarded,
                    aborts: self.aborts,
                    conflicts: self.conflicts,
                })
            } else {
                None
            },
            repair_summary: if has_repair {
                Some(RepairSummary {
                    corruptions_detected: self.corruptions_detected,
                    repairs_attempted: self.repairs_attempted,
                    repairs_succeeded: self.repairs_succeeded,
                    repairs_failed: self.repairs_failed,
                    scrub_cycles: self.scrub_cycles,
                    total_blocks_corrupt: self.total_blocks_corrupt,
                })
            } else {
                None
            },
            pressure_summary: if has_pressure {
                Some(PressureSummary {
                    backpressure_events: self.backpressure_events,
                    flush_batches: self.flush_batches,
                    total_blocks_flushed: self.total_blocks_flushed,
                    policy_changes: self.policy_changes,
                })
            } else {
                None
            },
            contention_summary: if has_contention {
                Some(ContentionSummary {
                    merge_proofs_checked: self.merge_proofs_checked,
                    merge_proofs_valid: self.merge_proofs_valid,
                    merge_proofs_invalid: self.merge_proofs_invalid,
                    merges_applied: self.merges_applied,
                    merges_rejected: self.merges_rejected,
                    total_merged_blocks: self.total_merged_blocks,
                    total_combined_write_set_bytes: self.total_combined_write_set_bytes,
                    policy_switches: self.policy_switches,
                    contention_samples: self.contention_samples,
                    latest_conflict_rate: self.latest_conflict_rate,
                    latest_merge_success_rate: self.latest_merge_success_rate,
                    latest_abort_rate: self.latest_abort_rate,
                    latest_total_commits: self.latest_total_commits,
                    latest_total_conflicts: self.latest_total_conflicts,
                    latest_total_merges: self.latest_total_merges,
                    latest_total_aborts: self.latest_total_aborts,
                    latest_effective_policy: self.latest_effective_policy,
                })
            } else {
                None
            },
        }
    }
}

fn build_summary(records: &[EvidenceRecord], preset: Option<&str>) -> EvidenceSummary {
    let mut acc = SummaryAccumulator::default();
    for record in records {
        acc.ingest(record);
    }
    acc.finalize(records.len(), preset)
}

fn print_summary(summary: &EvidenceSummary) {
    println!("FrankenFS Evidence Summary");
    if let Some(preset) = summary.preset.as_ref() {
        println!("  Preset: {preset}");
    }
    println!("  Total records: {}", summary.total_records);
    if let Some((min_ts, max_ts)) = summary.time_span_ns {
        let min_s = min_ts / 1_000_000_000;
        let max_s = max_ts / 1_000_000_000;
        let span_s = max_s.saturating_sub(min_s);
        println!("  Time span: {span_s}s (earliest={min_s}, latest={max_s})");
    }
    if !summary.block_groups_seen.is_empty() {
        println!(
            "  Block groups: {} distinct",
            summary.block_groups_seen.len()
        );
    }

    println!();
    println!("  Event type breakdown:");
    for (name, count) in &summary.event_type_counts {
        println!("    {name:<32} {count}");
    }

    if let Some(replay) = summary.replay_summary.as_ref() {
        println!();
        println!("  Replay anomalies:");
        println!(
            "    WAL recoveries: {}  commits_replayed: {}  records_discarded: {}",
            replay.recovery_count, replay.total_commits_replayed, replay.total_records_discarded
        );
        println!(
            "    Aborts: {}  Serialization conflicts: {}",
            replay.aborts, replay.conflicts
        );
    }

    if let Some(repair) = summary.repair_summary.as_ref() {
        println!();
        println!("  Repair activity:");
        println!(
            "    Corruptions: {}  Blocks affected: {}",
            repair.corruptions_detected, repair.total_blocks_corrupt
        );
        println!(
            "    Repairs: {} attempted, {} succeeded, {} failed",
            repair.repairs_attempted, repair.repairs_succeeded, repair.repairs_failed
        );
        println!("    Scrub cycles: {}", repair.scrub_cycles);
    }

    if let Some(pressure) = summary.pressure_summary.as_ref() {
        println!();
        println!("  Pressure transitions:");
        println!(
            "    Backpressure activations: {}",
            pressure.backpressure_events
        );
        println!(
            "    Flush batches: {}  total blocks flushed: {}",
            pressure.flush_batches, pressure.total_blocks_flushed
        );
        println!("    Policy changes: {}", pressure.policy_changes);
    }

    if let Some(contention) = summary.contention_summary.as_ref() {
        println!();
        println!("  Contention:");
        println!(
            "    Merge proofs: {} checked, {} valid, {} invalid",
            contention.merge_proofs_checked,
            contention.merge_proofs_valid,
            contention.merge_proofs_invalid
        );
        println!(
            "    Merges: {} applied ({} blocks, {} bytes), {} rejected",
            contention.merges_applied,
            contention.total_merged_blocks,
            contention.total_combined_write_set_bytes,
            contention.merges_rejected
        );
        println!(
            "    Policy switches: {}  Samples: {}",
            contention.policy_switches, contention.contention_samples
        );
        if let (Some(conflict_rate), Some(merge_success_rate), Some(abort_rate), Some(commits)) = (
            contention.latest_conflict_rate,
            contention.latest_merge_success_rate,
            contention.latest_abort_rate,
            contention.latest_total_commits,
        ) {
            let policy = contention
                .latest_effective_policy
                .as_deref()
                .unwrap_or("unknown");
            println!(
                "    Latest sample: conflict_rate={conflict_rate:.4} \
merge_success={merge_success_rate:.4} abort_rate={abort_rate:.4} \
commits={commits} policy={policy}"
            );
        } else if let Some(policy) = contention.latest_effective_policy.as_ref() {
            println!("    Latest policy: {policy}");
        }
    }
}

fn safe_ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn cache_dirty_pressure(snapshot: &CacheRuntimeMetricsSnapshot) -> String {
    match snapshot.cache_dirty_count {
        0 => "clean".to_owned(),
        1..=32 => "elevated".to_owned(),
        33..=128 => "high".to_owned(),
        _ => "critical".to_owned(),
    }
}

fn writeback_pressure(snapshot: &CacheRuntimeMetricsSnapshot) -> String {
    match snapshot.writeback_queue_depth {
        0 => "idle".to_owned(),
        1..=8 => "active".to_owned(),
        9..=32 => "queued".to_owned(),
        _ => "saturated".to_owned(),
    }
}

fn mvcc_contention_level(snapshot: &EvidenceMvccRuntimeMetricsSnapshot) -> String {
    if snapshot.conflict_rate >= 0.25 || snapshot.abort_rate >= 0.30 {
        "critical".to_owned()
    } else if snapshot.conflict_rate >= 0.10 || snapshot.abort_rate >= 0.15 {
        "high".to_owned()
    } else if snapshot.conflict_rate > 0.0 || snapshot.abort_rate > 0.0 {
        "elevated".to_owned()
    } else {
        "nominal".to_owned()
    }
}

fn repair_freshness(snapshot: &RepairRuntimeMetricsSnapshot) -> String {
    if snapshot.symbol_staleness_max_seconds >= 300.0 {
        "stale".to_owned()
    } else if snapshot.symbol_staleness_max_seconds >= 60.0 {
        "aging".to_owned()
    } else {
        "fresh".to_owned()
    }
}

fn load_metrics_bundle(path: &PathBuf) -> Result<EvidenceMetricsBundle> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read metrics snapshot: {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse metrics snapshot JSON: {}", path.display()))
}

fn load_direct_metrics<T>(path: &PathBuf, label: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let raw = std::fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read {label} metrics snapshot: {}",
            path.display()
        )
    })?;
    serde_json::from_str(&raw).with_context(|| {
        format!(
            "failed to parse {label} metrics snapshot JSON: {}",
            path.display()
        )
    })
}

fn metrics_report_from_bundle(bundle: EvidenceMetricsBundle) -> MetricsPresetReport {
    let analyses = MetricsAggregateAnalysis {
        request_error_rate: bundle.metrics.map_or(0.0, |snapshot| {
            safe_ratio(snapshot.requests_err, snapshot.requests_total)
        }),
        throttled_ratio: bundle.metrics.map_or(0.0, |snapshot| {
            safe_ratio(snapshot.requests_throttled, snapshot.requests_total)
        }),
        shed_ratio: bundle.metrics.map_or(0.0, |snapshot| {
            safe_ratio(snapshot.requests_shed, snapshot.requests_total)
        }),
        cache_miss_rate: bundle.cache.map(|snapshot| {
            safe_ratio(
                snapshot.cache_misses,
                snapshot.cache_hits.saturating_add(snapshot.cache_misses),
            )
        }),
        cache_dirty_pressure: bundle.cache.map(|snapshot| cache_dirty_pressure(&snapshot)),
        mvcc_commit_success_rate: bundle.mvcc.as_ref().map(|snapshot| {
            safe_ratio(
                snapshot.commit_successes_total,
                snapshot.commit_attempts_total,
            )
        }),
        mvcc_contention_level: bundle.mvcc.as_ref().map(mvcc_contention_level),
        repair_decode_success_rate: bundle
            .repair_live
            .as_ref()
            .map(|snapshot| safe_ratio(snapshot.decode_successes, snapshot.decode_attempts)),
        repair_freshness: bundle.repair_live.as_ref().map(repair_freshness),
    };

    MetricsPresetReport::Aggregate(Box::new(MetricsAggregateReport {
        preset: PRESET_METRICS.to_owned(),
        analyses,
        metrics: bundle.metrics,
        cache: bundle.cache,
        mvcc: bundle.mvcc,
        repair_live: bundle.repair_live,
    }))
}

fn cache_report(snapshot: CacheRuntimeMetricsSnapshot) -> MetricsPresetReport {
    MetricsPresetReport::Cache(CacheMetricsReport {
        preset: PRESET_CACHE.to_owned(),
        total_accesses: snapshot.cache_hits.saturating_add(snapshot.cache_misses),
        miss_rate: safe_ratio(
            snapshot.cache_misses,
            snapshot.cache_hits.saturating_add(snapshot.cache_misses),
        ),
        dirty_pressure: cache_dirty_pressure(&snapshot),
        writeback_pressure: writeback_pressure(&snapshot),
        snapshot,
    })
}

fn mvcc_report(snapshot: EvidenceMvccRuntimeMetricsSnapshot) -> MetricsPresetReport {
    MetricsPresetReport::Mvcc(MvccMetricsReport {
        preset: PRESET_MVCC.to_owned(),
        commit_success_rate: safe_ratio(
            snapshot.commit_successes_total,
            snapshot.commit_attempts_total,
        ),
        contention_level: mvcc_contention_level(&snapshot),
        snapshot,
    })
}

fn repair_live_report(snapshot: RepairRuntimeMetricsSnapshot) -> MetricsPresetReport {
    MetricsPresetReport::RepairLive(RepairLiveMetricsReport {
        preset: PRESET_REPAIR_LIVE.to_owned(),
        decode_success_rate: safe_ratio(snapshot.decode_successes, snapshot.decode_attempts),
        freshness: repair_freshness(&snapshot),
        snapshot,
    })
}

fn load_metrics_report(path: &PathBuf, preset: &str) -> Result<MetricsPresetReport> {
    match preset {
        PRESET_METRICS => Ok(metrics_report_from_bundle(load_metrics_bundle(path)?)),
        PRESET_CACHE => load_metrics_bundle(path).map_or_else(
            |_| load_direct_metrics(path, "cache").map(cache_report),
            |bundle| {
                bundle
                    .cache
                    .map_or_else(|| load_direct_metrics(path, "cache"), Ok)
                    .map(cache_report)
            },
        ),
        PRESET_MVCC => load_metrics_bundle(path).map_or_else(
            |_| load_direct_metrics(path, "MVCC").map(mvcc_report),
            |bundle| {
                bundle
                    .mvcc
                    .map_or_else(|| load_direct_metrics(path, "MVCC"), Ok)
                    .map(mvcc_report)
            },
        ),
        PRESET_REPAIR_LIVE => load_metrics_bundle(path).map_or_else(
            |_| load_direct_metrics(path, "repair-live").map(repair_live_report),
            |bundle| {
                bundle
                    .repair_live
                    .map_or_else(|| load_direct_metrics(path, "repair-live"), Ok)
                    .map(repair_live_report)
            },
        ),
        _ => bail!("metrics report requested for unsupported preset '{preset}'"),
    }
}

fn print_metrics_header(preset: &str) {
    println!("FrankenFS Evidence Metrics");
    println!("  Preset: {preset}");
}

fn print_aggregate_metrics_report(report: &MetricsAggregateReport) {
    print_metrics_header(&report.preset);
    if let Some(snapshot) = report.metrics {
        println!("  FUSE request metrics:");
        println!(
            "    total={} ok={} err={} bytes_read={}",
            snapshot.requests_total,
            snapshot.requests_ok,
            snapshot.requests_err,
            snapshot.bytes_read
        );
        println!(
            "    throttled={} shed={} error_rate={:.3}",
            snapshot.requests_throttled, snapshot.requests_shed, report.analyses.request_error_rate
        );
    }
    if let Some(snapshot) = report.cache {
        println!("  Cache metrics:");
        println!(
            "    hits={} misses={} evictions={} hit_rate={:.3}",
            snapshot.cache_hits, snapshot.cache_misses, snapshot.cache_evictions, snapshot.hit_rate
        );
        println!(
            "    dirty_count={} writeback_depth={} pressure={}",
            snapshot.cache_dirty_count,
            snapshot.writeback_queue_depth,
            report
                .analyses
                .cache_dirty_pressure
                .as_deref()
                .unwrap_or("unknown")
        );
    }
    if let Some(snapshot) = report.mvcc.as_ref() {
        println!("  MVCC metrics:");
        println!(
            "    active_snapshots={} commits={} successes={} conflicts={} aborts={}",
            snapshot.active_snapshots,
            snapshot.commit_attempts_total,
            snapshot.commit_successes_total,
            snapshot.conflicts_total,
            snapshot.aborts_total
        );
        println!(
            "    contention={} prune_throughput={:.3}/s version_chain_max={}",
            report
                .analyses
                .mvcc_contention_level
                .as_deref()
                .unwrap_or("unknown"),
            snapshot.prune_throughput,
            snapshot.version_chain_max_length
        );
    }
    if let Some(snapshot) = report.repair_live.as_ref() {
        println!("  Repair-live metrics:");
        println!(
            "    groups_scrubbed={} corruption_detected={} decode_attempts={} decode_successes={}",
            snapshot.groups_scrubbed,
            snapshot.corruption_detected,
            snapshot.decode_attempts,
            snapshot.decode_successes
        );
        println!(
            "    symbol_refresh_count={} freshness={} max_staleness_s={:.3}",
            snapshot.symbol_refresh_count,
            report
                .analyses
                .repair_freshness
                .as_deref()
                .unwrap_or("unknown"),
            snapshot.symbol_staleness_max_seconds
        );
    }
}

fn print_cache_metrics_report(report: &CacheMetricsReport) {
    print_metrics_header(&report.preset);
    println!(
        "  hits={} misses={} total_accesses={} hit_rate={:.3} miss_rate={:.3}",
        report.snapshot.cache_hits,
        report.snapshot.cache_misses,
        report.total_accesses,
        report.snapshot.hit_rate,
        report.miss_rate
    );
    println!(
        "  evictions={} dirty_count={} dirty_pressure={} writeback_depth={} writeback_pressure={}",
        report.snapshot.cache_evictions,
        report.snapshot.cache_dirty_count,
        report.dirty_pressure,
        report.snapshot.writeback_queue_depth,
        report.writeback_pressure
    );
}

fn print_mvcc_metrics_report(report: &MvccMetricsReport) {
    print_metrics_header(&report.preset);
    println!(
        "  active_snapshots={} commits={} successes={} commit_success_rate={:.3}",
        report.snapshot.active_snapshots,
        report.snapshot.commit_attempts_total,
        report.snapshot.commit_successes_total,
        report.commit_success_rate
    );
    println!(
        "  conflicts={} aborts={} contention={} version_chain_max={}",
        report.snapshot.conflicts_total,
        report.snapshot.aborts_total,
        report.contention_level,
        report.snapshot.version_chain_max_length
    );
}

fn print_repair_live_metrics_report(report: &RepairLiveMetricsReport) {
    print_metrics_header(&report.preset);
    println!(
        "  groups_scrubbed={} corruption_detected={} decode_attempts={} decode_successes={}",
        report.snapshot.groups_scrubbed,
        report.snapshot.corruption_detected,
        report.snapshot.decode_attempts,
        report.snapshot.decode_successes
    );
    println!(
        "  decode_success_rate={:.3} freshness={} symbol_refresh_count={} max_staleness_s={:.3}",
        report.decode_success_rate,
        report.freshness,
        report.snapshot.symbol_refresh_count,
        report.snapshot.symbol_staleness_max_seconds
    );
}

fn print_metrics_report(report: &MetricsPresetReport) {
    match report {
        MetricsPresetReport::Aggregate(report) => print_aggregate_metrics_report(report),
        MetricsPresetReport::Cache(report) => print_cache_metrics_report(report),
        MetricsPresetReport::Mvcc(report) => print_mvcc_metrics_report(report),
        MetricsPresetReport::RepairLive(report) => print_repair_live_metrics_report(report),
    }
}

// ── Main command ───────────────────────────────────────────────────────────

fn validate_evidence_args(
    preset: Option<&str>,
    event_type_filter: Option<&str>,
    tail: Option<usize>,
    block_group_filter: Option<u32>,
    summary: bool,
) -> Result<Option<PresetMode>> {
    let preset_kind = if let Some(preset_name) = preset {
        let kind = preset_mode(preset_name);
        if kind.is_none() {
            warn!(
                target: "ffs::cli::evidence",
                preset = preset_name,
                outcome = "rejected",
                error_class = "invalid_preset",
                "evidence_preset_rejected"
            );
            bail!(
                "unknown preset '{preset_name}'. Valid presets: {}",
                KNOWN_PRESETS.join(", ")
            );
        }
        kind
    } else {
        None
    };

    if preset.is_some() && event_type_filter.is_some() {
        bail!("--preset and --event-type are mutually exclusive");
    }

    if matches!(preset_kind, Some(PresetMode::Metrics)) {
        if tail.is_some() {
            bail!("--tail is only supported for ledger-backed evidence presets");
        }
        if block_group_filter.is_some() {
            bail!("--block-group is only supported for ledger-backed evidence presets");
        }
        if summary {
            bail!("--summary is only supported for ledger-backed evidence presets");
        }
    }

    Ok(preset_kind)
}

fn run_metrics_evidence(path: &PathBuf, json: bool, preset_name: &str) -> Result<()> {
    let report = load_metrics_report(path, preset_name)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).context("serialize metrics report")?
        );
    } else {
        print_metrics_report(&report);
    }
    Ok(())
}

fn emit_ledger_output(
    records: &[EvidenceRecord],
    json: bool,
    preset: Option<&str>,
    summary: bool,
) -> Result<()> {
    if summary {
        let report = build_summary(records, preset);
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).context("serialize evidence summary")?
            );
        } else {
            print_summary(&report);
        }
    } else if json {
        println!(
            "{}",
            serde_json::to_string_pretty(records).context("serialize evidence records")?
        );
    } else if records.is_empty() {
        println!("No evidence records found.");
    } else {
        if let Some(preset_name) = preset {
            println!(
                "FrankenFS Evidence Ledger — preset: {preset_name} ({} records)",
                records.len()
            );
        } else {
            println!("FrankenFS Evidence Ledger ({} records)", records.len());
        }
        println!();
        for record in records {
            print_evidence_record(record);
        }
    }

    Ok(())
}

fn log_metrics_completion(started: Instant, preset_name: &str, summary: bool) {
    info!(
        target: "ffs::cli::evidence",
        preset = preset_name,
        summary = summary,
        outcome = "success",
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "evidence_metrics_complete"
    );
}

fn log_ledger_completion(
    started: Instant,
    records: &[EvidenceRecord],
    preset: Option<&str>,
    summary: bool,
) {
    info!(
        target: "ffs::cli::evidence",
        record_count = records.len(),
        preset = preset.unwrap_or(""),
        summary = summary,
        outcome = "success",
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "evidence_complete"
    );
}

pub fn evidence_cmd(
    path: &PathBuf,
    json: bool,
    event_type_filter: Option<&str>,
    tail: Option<usize>,
    preset: Option<&str>,
    block_group_filter: Option<u32>,
    summary: bool,
) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::evidence",
        "evidence",
        operation_id = %uuid_v4(),
        ledger = %path.display(),
        output_json = json,
        event_type_filter = event_type_filter.unwrap_or(""),
        tail = tail.unwrap_or(0),
        preset = preset.unwrap_or(""),
        block_group_filter = block_group_filter.unwrap_or(0),
        summary = summary,
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::evidence", "evidence_start");

    let preset_kind =
        validate_evidence_args(preset, event_type_filter, tail, block_group_filter, summary)?;
    if matches!(preset_kind, Some(PresetMode::Metrics)) {
        let preset_name =
            preset.ok_or_else(|| anyhow::anyhow!("metrics preset kind requires preset name"))?;
        run_metrics_evidence(path, json, preset_name)?;
        log_metrics_completion(started, preset_name, summary);
        return Ok(());
    }

    let records = load_evidence_records(path, event_type_filter, tail, preset, block_group_filter)?;
    emit_ledger_output(&records, json, preset, summary)?;
    log_ledger_completion(started, &records, preset, summary);
    Ok(())
}

// ── Record loading ─────────────────────────────────────────────────────────

pub fn load_evidence_records(
    path: &PathBuf,
    event_type_filter: Option<&str>,
    tail: Option<usize>,
    preset: Option<&str>,
    block_group_filter: Option<u32>,
) -> Result<Vec<EvidenceRecord>> {
    let preset_types = preset.and_then(preset_event_types);

    let file = File::open(path)
        .with_context(|| format!("failed to open evidence ledger: {}", path.display()))?;
    if matches!(tail, Some(0)) {
        return Ok(Vec::new());
    }
    let mut reader = BufReader::new(file);
    let mut records: Vec<EvidenceRecord> = Vec::new();
    let mut tail_records: VecDeque<EvidenceRecord> = VecDeque::new();
    let mut line_buf = Vec::new();

    loop {
        line_buf.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut line_buf)
            .with_context(|| format!("failed reading evidence ledger line: {}", path.display()))?;
        if bytes_read == 0 {
            break;
        }
        let Ok(line) = std::str::from_utf8(&line_buf) else {
            // Preserve torn-write behavior: skip malformed byte sequences.
            continue;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<EvidenceRecord>(line) else {
            // Preserve torn-write behavior: skip malformed lines.
            continue;
        };

        // Apply single event_type filter.
        if let Some(filter) = event_type_filter
            && evidence_event_type_name(record.event_type) != filter {
                continue;
            }

        // Apply preset multi-type filter.
        if let Some(types) = preset_types
            && !types.contains(&record.event_type) {
                continue;
            }

        if let Some(block_group) = block_group_filter
            && record.block_group != block_group {
                continue;
            }

        if let Some(limit) = tail {
            if limit == 0 {
                continue;
            }
            if tail_records.len() == limit {
                tail_records.pop_front();
            }
            tail_records.push_back(record);
        } else {
            records.push(record);
        }
    }

    if tail.is_some() {
        Ok(tail_records.into_iter().collect())
    } else {
        Ok(records)
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn uuid_v4() -> String {
    // Minimal v4-like UUID for operation_id correlation.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut h);
    std::process::id().hash(&mut h);
    let bits = h.finish();
    format!("{bits:016x}")
}

pub const fn evidence_event_type_name(event_type: EvidenceEventType) -> &'static str {
    match event_type {
        EvidenceEventType::CorruptionDetected => "corruption_detected",
        EvidenceEventType::RepairAttempted => "repair_attempted",
        EvidenceEventType::RepairSucceeded => "repair_succeeded",
        EvidenceEventType::RepairFailed => "repair_failed",
        EvidenceEventType::ScrubCycleComplete => "scrub_cycle_complete",
        EvidenceEventType::PolicyDecision => "policy_decision",
        EvidenceEventType::SymbolRefresh => "symbol_refresh",
        EvidenceEventType::WalRecovery => "wal_recovery",
        EvidenceEventType::TransactionCommit => "transaction_commit",
        EvidenceEventType::TxnAborted => "txn_aborted",
        EvidenceEventType::SerializationConflict => "serialization_conflict",
        EvidenceEventType::VersionGc => "version_gc",
        EvidenceEventType::SnapshotAdvanced => "snapshot_advanced",
        EvidenceEventType::FlushBatch => "flush_batch",
        EvidenceEventType::BackpressureActivated => "backpressure_activated",
        EvidenceEventType::DirtyBlockDiscarded => "dirty_block_discarded",
        EvidenceEventType::DurabilityPolicyChanged => "durability_policy_changed",
        EvidenceEventType::RefreshPolicyChanged => "refresh_policy_changed",
        EvidenceEventType::MergeProofChecked => "merge_proof_checked",
        EvidenceEventType::MergeApplied => "merge_applied",
        EvidenceEventType::MergeRejected => "merge_rejected",
        EvidenceEventType::PolicySwitched => "policy_switched",
        EvidenceEventType::ContentionSample => "contention_sample",
    }
}

#[cfg(test)]
pub fn build_summary_for_test(records: &[EvidenceRecord], preset: Option<&str>) -> EvidenceSummary {
    build_summary(records, preset)
}

#[cfg(test)]
pub fn load_metrics_report_for_test(path: &PathBuf, preset: &str) -> Result<MetricsPresetReport> {
    load_metrics_report(path, preset)
}

fn print_evidence_record(record: &EvidenceRecord) {
    let ts_secs = record.timestamp_ns / 1_000_000_000;
    let ts_nanos = record.timestamp_ns % 1_000_000_000;
    let event = evidence_event_type_name(record.event_type);

    print!(
        "  [{ts_secs}.{ts_nanos:09}] {event:<24} group={}",
        record.block_group
    );

    if let Some((start, end)) = record.block_range {
        print!(" blocks={start}..{end}");
    }

    print_evidence_record_event_payload(record);
    println!();
}

fn print_evidence_record_event_payload(record: &EvidenceRecord) {
    match record.event_type {
        EvidenceEventType::CorruptionDetected => print_corruption_payload(record),
        EvidenceEventType::RepairAttempted
        | EvidenceEventType::RepairSucceeded
        | EvidenceEventType::RepairFailed => print_repair_payload(record),
        EvidenceEventType::ScrubCycleComplete => print_scrub_cycle_payload(record),
        EvidenceEventType::PolicyDecision => print_policy_payload(record),
        EvidenceEventType::SymbolRefresh => print_symbol_refresh_payload(record),
        EvidenceEventType::WalRecovery => print_wal_recovery_payload(record),
        EvidenceEventType::TransactionCommit => print_transaction_commit_payload(record),
        EvidenceEventType::TxnAborted => print_txn_aborted_payload(record),
        EvidenceEventType::SerializationConflict => print_serialization_conflict_payload(record),
        EvidenceEventType::VersionGc => print_version_gc_payload(record),
        EvidenceEventType::SnapshotAdvanced => print_snapshot_advanced_payload(record),
        EvidenceEventType::FlushBatch => print_flush_batch_payload(record),
        EvidenceEventType::BackpressureActivated => print_backpressure_payload(record),
        EvidenceEventType::DirtyBlockDiscarded => print_dirty_block_discarded_payload(record),
        EvidenceEventType::DurabilityPolicyChanged => {
            print_durability_policy_changed_payload(record);
        }
        EvidenceEventType::RefreshPolicyChanged => print_refresh_policy_changed_payload(record),
        EvidenceEventType::MergeProofChecked => print_merge_proof_checked_payload(record),
        EvidenceEventType::MergeApplied => print_merge_applied_payload(record),
        EvidenceEventType::MergeRejected => print_merge_rejected_payload(record),
        EvidenceEventType::PolicySwitched => print_policy_switched_payload(record),
        EvidenceEventType::ContentionSample => print_contention_sample_payload(record),
    }
}

fn print_corruption_payload(record: &EvidenceRecord) {
    if let Some(c) = record.corruption.as_ref() {
        print!(
            " blocks_affected={} kind={} severity={}",
            c.blocks_affected, c.corruption_kind, c.severity
        );
    }
}

fn print_repair_payload(record: &EvidenceRecord) {
    if let Some(r) = record.repair.as_ref() {
        print!(
            " corrupt={} symbols={}/{} verify={}",
            r.corrupt_count, r.symbols_used, r.symbols_available, r.verify_pass
        );
        if let Some(reason) = r.reason.as_ref() {
            print!(" reason=\"{reason}\"");
        }
    }
}

fn print_scrub_cycle_payload(record: &EvidenceRecord) {
    if let Some(s) = record.scrub_cycle.as_ref() {
        print!(
            " scanned={} corrupt={} io_errors={} findings={}",
            s.blocks_scanned, s.blocks_corrupt, s.blocks_io_error, s.findings_count
        );
    }
}

fn print_policy_payload(record: &EvidenceRecord) {
    if let Some(p) = record.policy.as_ref() {
        print!(
            " posterior={:.4} overhead={:.3} risk_bound={:.1e} decision=\"{}\"",
            p.corruption_posterior, p.overhead_ratio, p.risk_bound, p.decision
        );
    }
}

fn print_symbol_refresh_payload(record: &EvidenceRecord) {
    if let Some(s) = record.symbol_refresh.as_ref() {
        print!(
            " gen={}→{} symbols={}",
            s.previous_generation, s.new_generation, s.symbols_generated
        );
    }
}

fn print_wal_recovery_payload(record: &EvidenceRecord) {
    if let Some(w) = record.wal_recovery.as_ref() {
        print!(
            " commits={} versions={} discarded={} valid={}/{}",
            w.commits_replayed,
            w.versions_replayed,
            w.records_discarded,
            w.wal_valid_bytes,
            w.wal_total_bytes
        );
        if w.used_checkpoint
            && let Some(seq) = w.checkpoint_commit_seq {
                print!(" checkpoint_seq={seq}");
            }
    }
}

fn print_transaction_commit_payload(record: &EvidenceRecord) {
    if let Some(t) = record.transaction_commit.as_ref() {
        print!(
            " txn_id={} commit_seq={} write_set_size={} duration_us={}",
            t.txn_id, t.commit_seq, t.write_set_size, t.duration_us
        );
    }
}

fn print_txn_aborted_payload(record: &EvidenceRecord) {
    if let Some(t) = record.txn_aborted.as_ref() {
        let reason = serde_json::to_value(t.reason)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("{:?}", t.reason));
        print!(
            " txn_id={} reason={reason} read_set_size={} write_set_size={}",
            t.txn_id, t.read_set_size, t.write_set_size
        );
        if let Some(detail) = t.detail.as_ref() {
            print!(" detail=\"{detail}\"");
        }
    }
}

fn print_serialization_conflict_payload(record: &EvidenceRecord) {
    if let Some(c) = record.serialization_conflict.as_ref() {
        print!(" txn_id={} conflict_type={}", c.txn_id, c.conflict_type);
        if let Some(conflicting_txn) = c.conflicting_txn {
            print!(" conflicting_txn={conflicting_txn}");
        }
    }
}

fn print_version_gc_payload(record: &EvidenceRecord) {
    if let Some(gc) = record.version_gc.as_ref() {
        print!(
            " block_id={} versions_freed={} oldest_retained_commit_seq={}",
            gc.block_id, gc.versions_freed, gc.oldest_retained_commit_seq
        );
    }
}

fn print_snapshot_advanced_payload(record: &EvidenceRecord) {
    if let Some(s) = record.snapshot_advanced.as_ref() {
        print!(
            " old_commit_seq={} new_commit_seq={} versions_eligible={}",
            s.old_commit_seq, s.new_commit_seq, s.versions_eligible
        );
    }
}

fn print_flush_batch_payload(record: &EvidenceRecord) {
    if let Some(f) = record.flush_batch.as_ref() {
        print!(
            " blocks_flushed={} bytes_written={} flush_duration_us={}",
            f.blocks_flushed, f.bytes_written, f.flush_duration_us
        );
    }
}

fn print_backpressure_payload(record: &EvidenceRecord) {
    if let Some(b) = record.backpressure_activated.as_ref() {
        print!(
            " dirty_ratio={:.4} threshold={:.4}",
            b.dirty_ratio, b.threshold
        );
    }
}

fn print_dirty_block_discarded_payload(record: &EvidenceRecord) {
    if let Some(d) = record.dirty_block_discarded.as_ref() {
        let reason = serde_json::to_value(d.reason)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("{:?}", d.reason));
        print!(
            " block_id={} txn_id={} reason={reason}",
            d.block_id, d.txn_id
        );
    }
}

fn print_durability_policy_changed_payload(record: &EvidenceRecord) {
    if let Some(d) = record.durability_policy_changed.as_ref() {
        print!(
            " old_overhead={:.4} new_overhead={:.4} posterior=({:.3},{:.3},{:.4})",
            d.old_overhead, d.new_overhead, d.posterior_alpha, d.posterior_beta, d.posterior_mean
        );
    }
}

fn print_refresh_policy_changed_payload(record: &EvidenceRecord) {
    if let Some(p) = record.refresh_policy_changed.as_ref() {
        print!(
            " policy=\"{}\"->\"{}\" policy_group={}",
            p.old_policy, p.new_policy, p.block_group
        );
    }
}

fn print_merge_proof_checked_payload(record: &EvidenceRecord) {
    if let Some(p) = record.merge_proof_checked.as_ref() {
        print!(
            " txn={} block={} proof={} valid={}",
            p.txn_id, p.block_id, p.proof_variant, p.valid
        );
        if let Some(reason) = p.rejection_reason.as_ref() {
            print!(" reason={reason}");
        }
    }
}

fn print_merge_applied_payload(record: &EvidenceRecord) {
    if let Some(p) = record.merge_applied.as_ref() {
        print!(
            " txn={} merged_blocks={} bytes={} proof={}",
            p.txn_id, p.merged_block_count, p.combined_write_set_bytes, p.proof_variant
        );
    }
}

fn print_merge_rejected_payload(record: &EvidenceRecord) {
    if let Some(p) = record.merge_rejected.as_ref() {
        print!(
            " txn={} block={} proof={} reason={}",
            p.txn_id, p.block_id, p.proof_variant, p.reason
        );
    }
}

fn print_policy_switched_payload(record: &EvidenceRecord) {
    if let Some(p) = record.policy_switched.as_ref() {
        print!(
            " from={} to={} delta={:.6} trigger={}",
            p.from_policy, p.to_policy, p.expected_loss_delta, p.trigger_reason
        );
    }
}

fn print_contention_sample_payload(record: &EvidenceRecord) {
    if let Some(p) = record.contention_sample.as_ref() {
        print!(
            " conflict_rate={:.4} merge_success={:.4} abort_rate={:.4} commits={} policy={}",
            p.conflict_rate,
            p.merge_success_rate,
            p.abort_rate,
            p.total_commits,
            p.effective_policy
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PRESET_CACHE, PRESET_CONTENTION, PRESET_METRICS, PRESET_MVCC, PRESET_PRESSURE_TRANSITIONS,
        PRESET_REPAIR_FAILURES, PRESET_REPAIR_LIVE, PRESET_REPLAY_ANOMALIES, PresetMode,
        SummaryAccumulator, evidence_event_type_name, validate_evidence_args,
    };
    use ffs_repair::evidence::{
        CorruptionDetail, EvidenceEventType, EvidenceRecord, FlushBatchDetail, WalRecoveryDetail,
    };
    use std::collections::BTreeMap;

    #[test]
    fn cache_dirty_pressure_and_writeback_pressure_classify_by_threshold() {
        use super::{CacheRuntimeMetricsSnapshot, cache_dirty_pressure, writeback_pressure};
        let snap = |dirty: u64, writeback: u64| CacheRuntimeMetricsSnapshot {
            cache_hits: 0,
            cache_misses: 0,
            cache_evictions: 0,
            cache_dirty_count: dirty,
            writeback_queue_depth: writeback,
            hit_rate: 0.0,
        };

        // dirty-count buckets: 0 / 1..=32 / 33..=128 / >128.
        assert_eq!(cache_dirty_pressure(&snap(0, 0)), "clean");
        assert_eq!(cache_dirty_pressure(&snap(1, 0)), "elevated");
        assert_eq!(cache_dirty_pressure(&snap(32, 0)), "elevated");
        assert_eq!(cache_dirty_pressure(&snap(33, 0)), "high");
        assert_eq!(cache_dirty_pressure(&snap(128, 0)), "high");
        assert_eq!(cache_dirty_pressure(&snap(129, 0)), "critical");

        // writeback-depth buckets: 0 / 1..=8 / 9..=32 / >32.
        assert_eq!(writeback_pressure(&snap(0, 0)), "idle");
        assert_eq!(writeback_pressure(&snap(0, 1)), "active");
        assert_eq!(writeback_pressure(&snap(0, 8)), "active");
        assert_eq!(writeback_pressure(&snap(0, 9)), "queued");
        assert_eq!(writeback_pressure(&snap(0, 32)), "queued");
        assert_eq!(writeback_pressure(&snap(0, 33)), "saturated");
    }

    #[test]
    fn repair_freshness_classifies_symbol_staleness_by_threshold() {
        use super::{RepairRuntimeMetricsSnapshot, repair_freshness};
        let snap = |staleness: f64| RepairRuntimeMetricsSnapshot {
            groups_scrubbed: 0,
            corruption_detected: 0,
            decode_attempts: 0,
            decode_successes: 0,
            symbol_refresh_count: 0,
            symbol_staleness_max_seconds: staleness,
        };
        assert_eq!(repair_freshness(&snap(0.0)), "fresh");
        assert_eq!(repair_freshness(&snap(59.9)), "fresh");
        assert_eq!(repair_freshness(&snap(60.0)), "aging"); // >= 60s boundary
        assert_eq!(repair_freshness(&snap(299.9)), "aging");
        assert_eq!(repair_freshness(&snap(300.0)), "stale"); // >= 300s boundary
        assert_eq!(repair_freshness(&snap(10_000.0)), "stale");
    }

    #[test]
    fn validate_evidence_args_rejects_unknown_preset() {
        let err = validate_evidence_args(Some("unknown-preset"), None, None, None, false)
            .expect_err("unknown preset should fail");
        let message = err.to_string();
        assert!(message.contains("unknown preset 'unknown-preset'"));
        assert!(message.contains(PRESET_METRICS));
        assert!(message.contains(PRESET_REPAIR_FAILURES));
    }

    #[test]
    fn validate_evidence_args_rejects_preset_and_event_type_together() {
        let err = validate_evidence_args(
            Some(PRESET_REPAIR_FAILURES),
            Some("repair_failed"),
            None,
            None,
            false,
        )
        .expect_err("preset and event type should be mutually exclusive");
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn validate_evidence_args_rejects_tail_for_metrics_presets() {
        let err = validate_evidence_args(Some(PRESET_METRICS), None, Some(5), None, false)
            .expect_err("metrics presets should reject tail");
        assert!(
            err.to_string()
                .contains("--tail is only supported for ledger-backed evidence presets")
        );
    }

    #[test]
    fn validate_evidence_args_rejects_summary_for_metrics_presets() {
        let err = validate_evidence_args(Some(PRESET_METRICS), None, None, None, true)
            .expect_err("metrics presets should reject summary");
        assert!(
            err.to_string()
                .contains("--summary is only supported for ledger-backed evidence presets")
        );
    }

    #[test]
    fn validate_evidence_args_rejects_block_group_for_metrics_presets() {
        let err = validate_evidence_args(Some(PRESET_METRICS), None, None, Some(7), false)
            .expect_err("metrics presets should reject block-group filters");
        assert!(
            err.to_string()
                .contains("--block-group is only supported for ledger-backed evidence presets")
        );
    }

    #[test]
    fn validate_evidence_args_accepts_block_group_for_ledger_presets() {
        let preset_kind =
            validate_evidence_args(Some(PRESET_REPAIR_FAILURES), None, None, Some(7), false);
        assert!(matches!(preset_kind, Ok(Some(PresetMode::Ledger))));
    }

    #[test]
    fn validate_evidence_args_accepts_block_group_without_preset() {
        let preset_kind = validate_evidence_args(None, None, None, Some(7), false);
        assert!(matches!(preset_kind, Ok(None)));
    }

    #[test]
    fn validate_evidence_args_rejects_block_group_for_all_metrics_presets() {
        for preset in [
            PRESET_METRICS,
            PRESET_CACHE,
            PRESET_MVCC,
            PRESET_REPAIR_LIVE,
        ] {
            let err = validate_evidence_args(Some(preset), None, None, Some(7), false).unwrap_err();
            assert!(
                err.to_string()
                    .contains("--block-group is only supported for ledger-backed evidence presets"),
                "preset {preset} should reject --block-group with the ledger-only message"
            );
        }
    }

    #[test]
    fn validate_evidence_args_accepts_block_group_for_all_ledger_presets() {
        for preset in [
            PRESET_REPLAY_ANOMALIES,
            PRESET_REPAIR_FAILURES,
            PRESET_PRESSURE_TRANSITIONS,
            PRESET_CONTENTION,
        ] {
            assert!(
                matches!(
                    validate_evidence_args(Some(preset), None, None, Some(7), false),
                    Ok(Some(PresetMode::Ledger))
                ),
                "ledger preset {preset} should accept --block-group"
            );
        }
    }

    #[test]
    fn validate_evidence_args_accepts_ledger_preset_with_tail_summary_and_block_group() {
        let preset_kind =
            validate_evidence_args(Some(PRESET_REPAIR_FAILURES), None, Some(3), Some(7), true);
        assert!(matches!(preset_kind, Ok(Some(PresetMode::Ledger))));
    }

    #[test]
    fn validate_evidence_args_accepts_raw_event_type_with_block_group() {
        assert!(
            matches!(
                validate_evidence_args(None, Some("repair_failed"), Some(4), Some(7), true),
                Ok(None)
            ),
            "raw event-type filters should compose with --block-group"
        );
    }

    #[test]
    fn validate_evidence_args_accepts_ledger_preset_with_tail_and_summary() {
        let preset_kind =
            validate_evidence_args(Some(PRESET_REPAIR_FAILURES), None, Some(3), None, true);
        assert!(matches!(preset_kind, Ok(Some(PresetMode::Ledger))));
    }

    #[test]
    fn validate_evidence_args_rejects_tail_and_summary_for_all_metrics_presets() {
        for preset in [
            PRESET_METRICS,
            PRESET_CACHE,
            PRESET_MVCC,
            PRESET_REPAIR_LIVE,
        ] {
            let tail_err =
                validate_evidence_args(Some(preset), None, Some(5), None, false).unwrap_err();
            assert!(
                tail_err
                    .to_string()
                    .contains("--tail is only supported for ledger-backed evidence presets"),
                "preset {preset} should reject --tail with the ledger-only message"
            );

            let summary_err =
                validate_evidence_args(Some(preset), None, None, None, true).unwrap_err();
            assert!(
                summary_err
                    .to_string()
                    .contains("--summary is only supported for ledger-backed evidence presets"),
                "preset {preset} should reject --summary with the ledger-only message"
            );
        }
    }

    #[test]
    fn validate_evidence_args_accepts_tail_and_summary_for_all_ledger_presets() {
        for preset in [
            PRESET_REPLAY_ANOMALIES,
            PRESET_REPAIR_FAILURES,
            PRESET_PRESSURE_TRANSITIONS,
            PRESET_CONTENTION,
        ] {
            assert!(
                matches!(
                    validate_evidence_args(Some(preset), None, Some(3), None, true),
                    Ok(Some(PresetMode::Ledger))
                ),
                "ledger preset {preset} should classify as ledger-backed"
            );
        }
    }

    #[test]
    fn validate_evidence_args_classifies_all_metrics_presets_as_metrics_mode() {
        for preset in [
            PRESET_METRICS,
            PRESET_CACHE,
            PRESET_MVCC,
            PRESET_REPAIR_LIVE,
        ] {
            assert!(
                matches!(
                    validate_evidence_args(Some(preset), None, None, None, false),
                    Ok(Some(PresetMode::Metrics))
                ),
                "metrics preset {preset} should classify as metrics-backed"
            );
        }
    }

    #[test]
    fn validate_evidence_args_accepts_raw_event_type_filter_without_preset() {
        assert!(
            matches!(
                validate_evidence_args(None, Some("repair_failed"), Some(4), None, true),
                Ok(None)
            ),
            "no-preset validation path should not classify as a preset mode"
        );
    }

    #[test]
    fn summary_accumulator_saturates_numeric_limits() {
        let maxed_events = [
            EvidenceEventType::WalRecovery,
            EvidenceEventType::TxnAborted,
            EvidenceEventType::SerializationConflict,
            EvidenceEventType::CorruptionDetected,
            EvidenceEventType::RepairAttempted,
            EvidenceEventType::RepairSucceeded,
            EvidenceEventType::RepairFailed,
            EvidenceEventType::ScrubCycleComplete,
            EvidenceEventType::BackpressureActivated,
            EvidenceEventType::FlushBatch,
            EvidenceEventType::DurabilityPolicyChanged,
            EvidenceEventType::RefreshPolicyChanged,
        ];
        let mut accumulator = SummaryAccumulator {
            event_type_counts: maxed_events
                .iter()
                .map(|event_type| (evidence_event_type_name(*event_type).to_owned(), usize::MAX))
                .collect::<BTreeMap<_, _>>(),
            recovery_count: usize::MAX,
            total_commits_replayed: u64::MAX,
            total_records_discarded: u64::MAX,
            aborts: usize::MAX,
            conflicts: usize::MAX,
            corruptions_detected: usize::MAX,
            repairs_attempted: usize::MAX,
            repairs_succeeded: usize::MAX,
            repairs_failed: usize::MAX,
            scrub_cycles: usize::MAX,
            total_blocks_corrupt: u64::MAX,
            backpressure_events: usize::MAX,
            flush_batches: usize::MAX,
            total_blocks_flushed: u64::MAX,
            policy_changes: usize::MAX,
            ..SummaryAccumulator::default()
        };

        let mut wal_recovery = bare_record(1, EvidenceEventType::WalRecovery, 0);
        wal_recovery.wal_recovery = Some(WalRecoveryDetail {
            commits_replayed: u64::MAX,
            versions_replayed: 0,
            records_discarded: u64::MAX,
            wal_valid_bytes: 0,
            wal_total_bytes: 0,
            used_checkpoint: false,
            checkpoint_commit_seq: None,
        });

        let mut corruption = bare_record(4, EvidenceEventType::CorruptionDetected, 7);
        corruption.corruption = Some(CorruptionDetail {
            blocks_affected: u32::MAX,
            corruption_kind: "crc".to_owned(),
            severity: "critical".to_owned(),
            detail: "bad crc".to_owned(),
        });

        let mut flush_batch = bare_record(10, EvidenceEventType::FlushBatch, 0);
        flush_batch.flush_batch = Some(FlushBatchDetail {
            blocks_flushed: u64::MAX,
            bytes_written: 0,
            flush_duration_us: 0,
        });

        let records = [
            wal_recovery,
            bare_record(2, EvidenceEventType::TxnAborted, 0),
            bare_record(3, EvidenceEventType::SerializationConflict, 0),
            corruption,
            bare_record(5, EvidenceEventType::RepairAttempted, 0),
            bare_record(6, EvidenceEventType::RepairSucceeded, 0),
            bare_record(7, EvidenceEventType::RepairFailed, 0),
            bare_record(8, EvidenceEventType::ScrubCycleComplete, 0),
            bare_record(9, EvidenceEventType::BackpressureActivated, 0),
            flush_batch,
            bare_record(11, EvidenceEventType::DurabilityPolicyChanged, 0),
            bare_record(12, EvidenceEventType::RefreshPolicyChanged, 0),
        ];
        for record in &records {
            accumulator.ingest(record);
        }

        for event_type in maxed_events {
            assert_eq!(
                accumulator.event_type_counts[evidence_event_type_name(event_type)],
                usize::MAX
            );
        }
        assert_eq!(accumulator.recovery_count, usize::MAX);
        assert_eq!(accumulator.total_commits_replayed, u64::MAX);
        assert_eq!(accumulator.total_records_discarded, u64::MAX);
        assert_eq!(accumulator.aborts, usize::MAX);
        assert_eq!(accumulator.conflicts, usize::MAX);
        assert_eq!(accumulator.corruptions_detected, usize::MAX);
        assert_eq!(accumulator.repairs_attempted, usize::MAX);
        assert_eq!(accumulator.repairs_succeeded, usize::MAX);
        assert_eq!(accumulator.repairs_failed, usize::MAX);
        assert_eq!(accumulator.scrub_cycles, usize::MAX);
        assert_eq!(accumulator.total_blocks_corrupt, u64::MAX);
        assert_eq!(accumulator.backpressure_events, usize::MAX);
        assert_eq!(accumulator.flush_batches, usize::MAX);
        assert_eq!(accumulator.total_blocks_flushed, u64::MAX);
        assert_eq!(accumulator.policy_changes, usize::MAX);
        assert_eq!(accumulator.min_ts, Some(1));
        assert_eq!(accumulator.max_ts, Some(12));
        assert_eq!(accumulator.groups, vec![7]);
    }

    fn bare_record(
        timestamp_ns: u64,
        event_type: EvidenceEventType,
        block_group: u32,
    ) -> EvidenceRecord {
        EvidenceRecord {
            timestamp_ns,
            event_type,
            block_group,
            block_range: None,
            corruption: None,
            repair: None,
            scrub_cycle: None,
            policy: None,
            symbol_refresh: None,
            wal_recovery: None,
            transaction_commit: None,
            txn_aborted: None,
            serialization_conflict: None,
            version_gc: None,
            snapshot_advanced: None,
            flush_batch: None,
            backpressure_activated: None,
            dirty_block_discarded: None,
            durability_policy_changed: None,
            refresh_policy_changed: None,
            merge_proof_checked: None,
            merge_applied: None,
            merge_rejected: None,
            policy_switched: None,
            contention_sample: None,
        }
    }
}
