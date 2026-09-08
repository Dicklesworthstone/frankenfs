//! Append-only JSONL evidence ledger for repair and scrub actions.
//!
//! Every repair action, corruption detection, policy decision, and scrub cycle
//! produces a durable, auditable [`EvidenceRecord`]. Records are persisted as
//! one-JSON-object-per-line (JSONL) for streaming reads and crash safety.
//!
//! # Format
//!
//! Each line is a self-contained [`EvidenceRecord`] serialized as JSON.
//! The [`EvidenceLedger`] writer flushes after every record to minimize
//! data loss on crash.
//!
//! # Usage
//!
//! ```no_run
//! # use ffs_repair::evidence::{EvidenceLedger, EvidenceRecord, CorruptionDetail};
//! # fn example() -> std::io::Result<()> {
//! let file = std::fs::File::create("/tmp/evidence.jsonl")?;
//! let mut ledger = EvidenceLedger::new(file);
//! let detail = CorruptionDetail {
//!     blocks_affected: 3,
//!     corruption_kind: "checksum_mismatch".into(),
//!     severity: "error".into(),
//!     detail: "block 42 CRC mismatch".into(),
//! };
//! ledger.append(&EvidenceRecord::corruption_detected(0, detail))?;
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::io::{self, Write};

use crate::recovery::{RecoveryDecoderStats, RecoveryEvidence, RecoveryOutcome};
use crate::scrub::ScrubReport;

// ── Timestamp ───────────────────────────────────────────────────────────────

/// Current wall-clock time as nanoseconds since the Unix epoch.
///
/// Returns 0 if the system clock is unavailable or before the epoch.
fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

// ── Event type ──────────────────────────────────────────────────────────────

/// Category of evidence event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceEventType {
    /// Corruption was detected during a scrub or read.
    CorruptionDetected,
    /// A repair attempt was initiated.
    RepairAttempted,
    /// A repair attempt completed successfully.
    RepairSucceeded,
    /// A repair attempt failed.
    RepairFailed,
    /// A full scrub cycle completed.
    ScrubCycleComplete,
    /// The Bayesian autopilot made an overhead adjustment decision.
    PolicyDecision,
    /// Repair symbols were regenerated for a block group.
    SymbolRefresh,
    /// WAL recovery completed (replay after crash or restart).
    WalRecovery,
    /// MVCC transaction committed successfully.
    TransactionCommit,
    /// MVCC transaction was aborted.
    TxnAborted,
    /// Serializable Snapshot Isolation conflict detected.
    SerializationConflict,
    /// MVCC version garbage collection reclaimed old versions.
    VersionGc,
    /// Active snapshot watermark advanced.
    SnapshotAdvanced,
    /// Write-back cache flush completed.
    FlushBatch,
    /// Write-back cache backpressure activated.
    BackpressureActivated,
    /// Dirty block discarded from an aborted transaction.
    DirtyBlockDiscarded,
    /// Durability policy overhead changed.
    DurabilityPolicyChanged,
    /// Symbol refresh policy mode changed.
    RefreshPolicyChanged,
    /// Merge proof was checked during conflict resolution.
    MergeProofChecked,
    /// Merge was successfully applied to resolve a conflict.
    MergeApplied,
    /// Merge was rejected (invalid proof, overlapping ranges, etc.).
    MergeRejected,
    /// Adaptive conflict policy switched between Strict and SafeMerge.
    PolicySwitched,
    /// Periodic contention metrics sample.
    ContentionSample,
}

// ── Detail structs ──────────────────────────────────────────────────────────

/// Detail payload for corruption detection events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorruptionDetail {
    /// Number of blocks affected by this corruption event.
    pub blocks_affected: u32,
    /// Category of corruption (e.g., "checksum_mismatch", "bad_magic").
    pub corruption_kind: String,
    /// Severity level (e.g., "error", "critical").
    pub severity: String,
    /// Human-readable description of the corruption.
    pub detail: String,
}

/// Detail payload for repair attempt/success/failure events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairDetail {
    /// Repair symbol generation used.
    pub generation: u64,
    /// Number of corrupt blocks targeted for recovery.
    pub corrupt_count: usize,
    /// Number of repair symbols consumed during decode.
    pub symbols_used: usize,
    /// Total repair symbols available for the group.
    pub symbols_available: usize,
    /// RaptorQ decoder statistics.
    pub decoder_stats: RecoveryDecoderStats,
    /// Whether post-repair block verification passed.
    pub verify_pass: bool,
    /// Human-readable reason for partial/failed outcomes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Detail payload for scrub cycle completion events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubCycleDetail {
    /// Total blocks scanned during the cycle.
    pub blocks_scanned: u64,
    /// Number of blocks with at least one corruption finding.
    pub blocks_corrupt: u64,
    /// Number of blocks that returned I/O errors.
    pub blocks_io_error: u64,
    /// Total number of individual findings.
    pub findings_count: usize,
}

/// Detail payload for Bayesian autopilot policy decisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecisionDetail {
    /// Posterior probability of corruption.
    pub corruption_posterior: f64,
    /// Beta posterior alpha parameter.
    #[serde(default)]
    pub posterior_alpha: f64,
    /// Beta posterior beta parameter.
    #[serde(default)]
    pub posterior_beta: f64,
    /// Current or proposed overhead ratio.
    pub overhead_ratio: f64,
    /// Risk bound threshold.
    pub risk_bound: f64,
    /// Expected loss at `overhead_ratio`.
    #[serde(default)]
    pub expected_loss: f64,
    /// Number of repair symbols selected for next refresh.
    #[serde(default)]
    pub symbols_selected: u32,
    /// Whether metadata-specific multiplier was applied.
    #[serde(default)]
    pub metadata_group: bool,
    /// Human-readable description of the policy decision.
    pub decision: String,
}

/// Detail payload for symbol refresh (re-encoding) events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolRefreshDetail {
    /// Previous repair symbol generation.
    pub previous_generation: u64,
    /// New repair symbol generation after refresh.
    pub new_generation: u64,
    /// Number of repair symbols generated.
    pub symbols_generated: u32,
}

/// Detail payload for WAL recovery events.
///
/// Emitted when a persistent MVCC store replays its WAL on startup.
/// Captures enough detail to audit crash recovery behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalRecoveryDetail {
    /// Number of commit records successfully replayed.
    pub commits_replayed: u64,
    /// Number of individual block versions restored.
    pub versions_replayed: u64,
    /// Number of WAL records discarded (corrupt CRC or truncated tail).
    pub records_discarded: u64,
    /// Byte offset where valid WAL data ends.
    pub wal_valid_bytes: u64,
    /// Total WAL file size in bytes.
    pub wal_total_bytes: u64,
    /// Whether a checkpoint was loaded before WAL replay.
    pub used_checkpoint: bool,
    /// Highest commit sequence restored from checkpoint, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_commit_seq: Option<u64>,
}

/// Detail payload for MVCC transaction commit events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionCommitDetail {
    /// Committed transaction identifier.
    pub txn_id: u64,
    /// Assigned commit sequence.
    pub commit_seq: u64,
    /// Number of logical blocks in the write set.
    pub write_set_size: usize,
    /// End-to-end commit duration in microseconds.
    pub duration_us: u64,
}

/// Abort reason classification for MVCC transaction aborts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxnAbortReason {
    /// First-committer-wins conflict with a newer committed writer.
    FcwConflict,
    /// SSI cycle detection aborted the transaction.
    SsiCycle,
    /// Deadline or timeout budget exceeded.
    Timeout,
    /// Durability layer failed while persisting a commit.
    DurabilityFailure,
    /// Explicit user-requested abort.
    UserAbort,
}

/// Detail payload for MVCC transaction-aborted events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxnAbortedDetail {
    /// Aborted transaction ID.
    pub txn_id: u64,
    /// Classified abort reason.
    pub reason: TxnAbortReason,
    /// Optional diagnostic message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Number of blocks in the read set at abort time.
    #[serde(default)]
    pub read_set_size: usize,
    /// Number of blocks in the write set at abort time.
    #[serde(default)]
    pub write_set_size: usize,
}

/// Detail payload for SSI serialization conflicts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationConflictDetail {
    /// Transaction rejected by SSI.
    pub txn_id: u64,
    /// Conflicting transaction identifier, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflicting_txn: Option<u64>,
    /// Conflict classification (for example, "rw_antidependency_cycle").
    pub conflict_type: String,
}

/// Detail payload for MVCC version-GC events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionGcDetail {
    /// Logical block whose version chain was pruned.
    pub block_id: u64,
    /// Number of versions freed by this GC action.
    pub versions_freed: u64,
    /// Oldest retained commit sequence for the block after pruning.
    pub oldest_retained_commit_seq: u64,
}

/// Detail payload for snapshot-watermark advance events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotAdvancedDetail {
    /// Previous oldest active snapshot sequence.
    pub old_commit_seq: u64,
    /// New oldest active snapshot sequence after advance.
    pub new_commit_seq: u64,
    /// Number of versions now eligible for GC.
    pub versions_eligible: u64,
}

/// Detail payload for write-back flush batch events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlushBatchDetail {
    /// Number of blocks flushed to durable storage.
    pub blocks_flushed: u64,
    /// Total bytes written in the flush batch.
    pub bytes_written: u64,
    /// Flush duration in microseconds.
    pub flush_duration_us: u64,
}

/// Detail payload for write-back backpressure events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackpressureActivatedDetail {
    /// Dirty block ratio at activation.
    pub dirty_ratio: f64,
    /// Threshold that triggered backpressure.
    pub threshold: f64,
}

/// Discard reason for dirty-block discard events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirtyDiscardReason {
    /// Dirty state discarded because owning transaction aborted.
    Abort,
}

/// Detail payload for dirty-block-discard events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirtyBlockDiscardedDetail {
    /// Logical block identifier.
    pub block_id: u64,
    /// Owning transaction identifier.
    pub txn_id: u64,
    /// Classified discard reason.
    pub reason: DirtyDiscardReason,
}

/// Detail payload for durability-overhead policy changes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DurabilityPolicyChangedDetail {
    /// Previous durability overhead ratio.
    pub old_overhead: f64,
    /// New durability overhead ratio.
    pub new_overhead: f64,
    /// Posterior alpha parameter used by policy update.
    pub posterior_alpha: f64,
    /// Posterior beta parameter used by policy update.
    pub posterior_beta: f64,
    /// Posterior mean probability used by policy update.
    pub posterior_mean: f64,
}

/// Detail payload for symbol refresh policy mode changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshPolicyChangedDetail {
    /// Block group whose refresh policy changed.
    pub block_group: u32,
    /// Previous policy name.
    pub old_policy: String,
    /// New policy name.
    pub new_policy: String,
}

/// Detail payload for merge-proof-checked events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeProofCheckedDetail {
    /// Transaction that attempted the merge.
    pub txn_id: u64,
    /// Block where the conflict occurred.
    pub block_id: u64,
    /// Merge proof variant name (e.g., "AppendOnly", "IndependentKeys").
    pub proof_variant: String,
    /// Whether the proof validated successfully.
    pub valid: bool,
    /// Rejection reason (only populated when `valid` is false).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

/// Detail payload for merge-applied events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeAppliedDetail {
    /// Transaction that committed with merged writes.
    pub txn_id: u64,
    /// Number of blocks that were merged (had conflicts resolved by proof).
    pub merged_block_count: usize,
    /// Total size in bytes of the combined write set after merge.
    pub combined_write_set_bytes: usize,
    /// Merge proof variant used (e.g., "AppendOnly").
    pub proof_variant: String,
}

/// Detail payload for merge-rejected events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeRejectedDetail {
    /// Transaction that was rejected.
    pub txn_id: u64,
    /// Block where the merge failed.
    pub block_id: u64,
    /// Merge proof variant attempted (e.g., "Unsafe").
    pub proof_variant: String,
    /// Reason for rejection.
    pub reason: String,
}

/// Detail payload for adaptive policy-switch events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicySwitchedDetail {
    /// Previous effective policy.
    pub from_policy: String,
    /// New effective policy.
    pub to_policy: String,
    /// Expected-loss delta (positive = new policy is cheaper).
    pub expected_loss_delta: f64,
    /// Trigger reason (e.g., "contention_rate_change").
    pub trigger_reason: String,
}

/// Detail payload for periodic contention sample events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentionSampleDetail {
    /// EMA conflict rate at sample time.
    pub conflict_rate: f64,
    /// EMA merge success rate at sample time.
    pub merge_success_rate: f64,
    /// EMA abort rate at sample time.
    pub abort_rate: f64,
    /// Total commits observed.
    pub total_commits: u64,
    /// Total conflicts observed.
    pub total_conflicts: u64,
    /// Total successful merges.
    pub total_merges: u64,
    /// Total aborts.
    pub total_aborts: u64,
    /// Currently effective policy.
    pub effective_policy: String,
}

// ── Evidence record ─────────────────────────────────────────────────────────

/// A single evidence record in the JSONL ledger.
///
/// Each record is self-contained: it includes a timestamp, event type,
/// block group, and event-specific detail. Only the detail field matching
/// `event_type` is populated; the rest are `None` (and omitted from JSON).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// Nanoseconds since the Unix epoch when this record was created.
    pub timestamp_ns: u64,
    /// Category of event.
    pub event_type: EvidenceEventType,
    /// Block group this event pertains to.
    pub block_group: u32,
    /// Optional affected block range `(start, end_exclusive)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_range: Option<(u64, u64)>,
    /// Corruption detail (present when `event_type` is `CorruptionDetected`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corruption: Option<CorruptionDetail>,
    /// Repair detail (present when `event_type` is `Repair*`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repair: Option<RepairDetail>,
    /// Scrub cycle summary (present when `event_type` is `ScrubCycleComplete`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scrub_cycle: Option<ScrubCycleDetail>,
    /// Policy decision detail (present when `event_type` is `PolicyDecision`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyDecisionDetail>,
    /// Symbol refresh detail (present when `event_type` is `SymbolRefresh`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol_refresh: Option<SymbolRefreshDetail>,
    /// WAL recovery detail (present when `event_type` is `WalRecovery`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wal_recovery: Option<WalRecoveryDetail>,
    /// Transaction-commit detail (present when `event_type` is `TransactionCommit`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_commit: Option<TransactionCommitDetail>,
    /// Transaction-aborted detail (present when `event_type` is `TxnAborted`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txn_aborted: Option<TxnAbortedDetail>,
    /// Serialization-conflict detail (present when `event_type` is `SerializationConflict`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serialization_conflict: Option<SerializationConflictDetail>,
    /// Version-GC detail (present when `event_type` is `VersionGc`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_gc: Option<VersionGcDetail>,
    /// Snapshot-advanced detail (present when `event_type` is `SnapshotAdvanced`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_advanced: Option<SnapshotAdvancedDetail>,
    /// Flush-batch detail (present when `event_type` is `FlushBatch`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flush_batch: Option<FlushBatchDetail>,
    /// Backpressure detail (present when `event_type` is `BackpressureActivated`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backpressure_activated: Option<BackpressureActivatedDetail>,
    /// Dirty-discard detail (present when `event_type` is `DirtyBlockDiscarded`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dirty_block_discarded: Option<DirtyBlockDiscardedDetail>,
    /// Durability-policy detail (present when `event_type` is `DurabilityPolicyChanged`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub durability_policy_changed: Option<DurabilityPolicyChangedDetail>,
    /// Refresh-policy detail (present when `event_type` is `RefreshPolicyChanged`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_policy_changed: Option<RefreshPolicyChangedDetail>,
    /// Merge-proof-checked detail (present when `event_type` is `MergeProofChecked`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merge_proof_checked: Option<MergeProofCheckedDetail>,
    /// Merge-applied detail (present when `event_type` is `MergeApplied`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merge_applied: Option<MergeAppliedDetail>,
    /// Merge-rejected detail (present when `event_type` is `MergeRejected`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merge_rejected: Option<MergeRejectedDetail>,
    /// Policy-switched detail (present when `event_type` is `PolicySwitched`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_switched: Option<PolicySwitchedDetail>,
    /// Contention-sample detail (present when `event_type` is `ContentionSample`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contention_sample: Option<ContentionSampleDetail>,
}

impl EvidenceRecord {
    fn base(event_type: EvidenceEventType, block_group: u32) -> Self {
        Self {
            timestamp_ns: now_ns(),
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

    /// Create a corruption-detected evidence record.
    #[must_use]
    pub fn corruption_detected(block_group: u32, detail: CorruptionDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::CorruptionDetected, block_group);
        r.corruption = Some(detail);
        r
    }

    /// Create a repair-attempted evidence record.
    #[must_use]
    pub fn repair_attempted(block_group: u32, detail: RepairDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::RepairAttempted, block_group);
        r.repair = Some(detail);
        r
    }

    /// Create a repair-succeeded evidence record.
    #[must_use]
    pub fn repair_succeeded(block_group: u32, detail: RepairDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::RepairSucceeded, block_group);
        r.repair = Some(detail);
        r
    }

    /// Create a repair-failed evidence record.
    #[must_use]
    pub fn repair_failed(block_group: u32, detail: RepairDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::RepairFailed, block_group);
        r.repair = Some(detail);
        r
    }

    /// Create a scrub-cycle-complete evidence record.
    #[must_use]
    pub fn scrub_cycle_complete(block_group: u32, detail: ScrubCycleDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::ScrubCycleComplete, block_group);
        r.scrub_cycle = Some(detail);
        r
    }

    /// Create a policy-decision evidence record.
    #[must_use]
    pub fn policy_decision(block_group: u32, detail: PolicyDecisionDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::PolicyDecision, block_group);
        r.policy = Some(detail);
        r
    }

    /// Create a symbol-refresh evidence record.
    #[must_use]
    pub fn symbol_refresh(block_group: u32, detail: SymbolRefreshDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::SymbolRefresh, block_group);
        r.symbol_refresh = Some(detail);
        r
    }

    /// Create a WAL-recovery evidence record.
    #[must_use]
    pub fn wal_recovery(detail: WalRecoveryDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::WalRecovery, 0);
        r.wal_recovery = Some(detail);
        r
    }

    /// Create a transaction-commit evidence record.
    #[must_use]
    pub fn transaction_commit(detail: TransactionCommitDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::TransactionCommit, 0);
        r.transaction_commit = Some(detail);
        r
    }

    /// Create a transaction-aborted evidence record.
    #[must_use]
    pub fn txn_aborted(detail: TxnAbortedDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::TxnAborted, 0);
        r.txn_aborted = Some(detail);
        r
    }

    /// Create a serialization-conflict evidence record.
    #[must_use]
    pub fn serialization_conflict(detail: SerializationConflictDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::SerializationConflict, 0);
        r.serialization_conflict = Some(detail);
        r
    }

    /// Create a version-GC evidence record.
    #[must_use]
    pub fn version_gc(detail: VersionGcDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::VersionGc, 0);
        r.version_gc = Some(detail);
        r
    }

    /// Create a snapshot-advanced evidence record.
    #[must_use]
    pub fn snapshot_advanced(detail: SnapshotAdvancedDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::SnapshotAdvanced, 0);
        r.snapshot_advanced = Some(detail);
        r
    }

    /// Create a flush-batch evidence record.
    #[must_use]
    pub fn flush_batch(detail: FlushBatchDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::FlushBatch, 0);
        r.flush_batch = Some(detail);
        r
    }

    /// Create a backpressure-activated evidence record.
    #[must_use]
    pub fn backpressure_activated(detail: BackpressureActivatedDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::BackpressureActivated, 0);
        r.backpressure_activated = Some(detail);
        r
    }

    /// Create a dirty-block-discarded evidence record.
    #[must_use]
    pub fn dirty_block_discarded(detail: DirtyBlockDiscardedDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::DirtyBlockDiscarded, 0);
        r.dirty_block_discarded = Some(detail);
        r
    }

    /// Create a durability-policy-changed evidence record.
    #[must_use]
    pub fn durability_policy_changed(detail: DurabilityPolicyChangedDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::DurabilityPolicyChanged, 0);
        r.durability_policy_changed = Some(detail);
        r
    }

    /// Create a refresh-policy-changed evidence record.
    #[must_use]
    pub fn refresh_policy_changed(detail: RefreshPolicyChangedDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::RefreshPolicyChanged, detail.block_group);
        r.refresh_policy_changed = Some(detail);
        r
    }

    /// Create a merge-proof-checked evidence record.
    #[must_use]
    pub fn merge_proof_checked(detail: MergeProofCheckedDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::MergeProofChecked, 0);
        r.merge_proof_checked = Some(detail);
        r
    }

    /// Create a merge-applied evidence record.
    #[must_use]
    pub fn merge_applied(detail: MergeAppliedDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::MergeApplied, 0);
        r.merge_applied = Some(detail);
        r
    }

    /// Create a merge-rejected evidence record.
    #[must_use]
    pub fn merge_rejected(detail: MergeRejectedDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::MergeRejected, 0);
        r.merge_rejected = Some(detail);
        r
    }

    /// Create a policy-switched evidence record.
    #[must_use]
    pub fn policy_switched(detail: PolicySwitchedDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::PolicySwitched, 0);
        r.policy_switched = Some(detail);
        r
    }

    /// Create a contention-sample evidence record.
    #[must_use]
    pub fn contention_sample(detail: ContentionSampleDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::ContentionSample, 0);
        r.contention_sample = Some(detail);
        r
    }

    /// Set the affected block range.
    #[must_use]
    pub fn with_block_range(mut self, start: u64, end: u64) -> Self {
        self.block_range = Some((start, end));
        self
    }

    /// Override the auto-generated timestamp.
    #[must_use]
    pub fn with_timestamp(mut self, timestamp_ns: u64) -> Self {
        self.timestamp_ns = timestamp_ns;
        self
    }

    /// Serialize this record to a single-line JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize a record from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or missing required fields.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Create an evidence record from a [`RecoveryEvidence`].
    ///
    /// Maps outcome to event type:
    /// - `Recovered` → `RepairSucceeded`
    /// - `Partial` / `Failed` → `RepairFailed`
    #[must_use]
    pub fn from_recovery(evidence: &RecoveryEvidence) -> Self {
        let event_type = match evidence.outcome {
            RecoveryOutcome::Recovered => EvidenceEventType::RepairSucceeded,
            RecoveryOutcome::Partial | RecoveryOutcome::Failed => EvidenceEventType::RepairFailed,
        };
        let detail = RepairDetail {
            generation: evidence.generation,
            corrupt_count: evidence.corrupt_count,
            symbols_used: evidence.symbols_used,
            symbols_available: evidence.symbols_available,
            decoder_stats: evidence.decoder_stats.clone(),
            verify_pass: evidence.outcome == RecoveryOutcome::Recovered,
            reason: evidence.reason.clone(),
        };
        let mut r = Self::base(event_type, evidence.group);
        r.repair = Some(detail);
        r
    }

    /// Create a scrub-cycle-complete evidence record from a [`ScrubReport`].
    #[must_use]
    pub fn from_scrub_report(block_group: u32, report: &ScrubReport) -> Self {
        Self::scrub_cycle_complete(
            block_group,
            ScrubCycleDetail {
                blocks_scanned: report.blocks_scanned,
                blocks_corrupt: report.blocks_corrupt,
                blocks_io_error: report.blocks_io_error,
                findings_count: report.findings.len(),
            },
        )
    }
}

// ── JSONL ledger ────────────────────────────────────────────────────────────

/// Append-only JSONL evidence writer.
///
/// Writes one JSON object per line. Each [`append`](Self::append) call
/// produces exactly one line and flushes the underlying writer to minimize
/// data loss on crash.
pub struct EvidenceLedger<W: Write> {
    writer: W,
    poisoned: bool,
}

impl<W: Write> EvidenceLedger<W> {
    /// Create a new evidence ledger writing to the given sink.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            poisoned: false,
        }
    }

    /// Append a record as a single JSONL line and flush.
    ///
    /// Serializes the record into an owned byte buffer (ending with `\n`)
    /// before issuing any I/O, avoiding the torn output that
    /// `serde_json::to_writer` can leave when serialization itself fails
    /// midway through streaming. A generic [`Write`] can still accept a
    /// partial prefix before reporting an I/O error; after any write or
    /// flush failure, the ledger is poisoned so later records cannot be
    /// concatenated onto a possibly incomplete JSONL line.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if serialization or writing fails.
    pub fn append(&mut self, record: &EvidenceRecord) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "evidence ledger append attempted after a failed write",
            ));
        }

        let mut line = serde_json::to_vec(record)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        line.push(b'\n');
        if let Err(err) = self.writer.write_all(&line) {
            self.poisoned = true;
            return Err(err);
        }
        if let Err(err) = self.writer.flush() {
            self.poisoned = true;
            return Err(err);
        }
        Ok(())
    }

    /// Consume the ledger, returning the underlying writer.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.writer
    }
}

/// Parse all evidence records from JSONL data.
///
/// Skips blank lines and lines that fail to parse (e.g., from torn writes).
/// Returns successfully parsed records in order.
#[must_use]
pub fn parse_evidence_ledger(data: &[u8]) -> Vec<EvidenceRecord> {
    data.split(|byte| *byte == b'\n')
        .filter_map(|raw_line| {
            let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
            if raw_line.iter().all(u8::is_ascii_whitespace) {
                return None;
            }
            let line = std::str::from_utf8(raw_line).ok()?;
            serde_json::from_str(line).ok()
        })
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_corruption_detail() -> CorruptionDetail {
        CorruptionDetail {
            blocks_affected: 3,
            corruption_kind: "checksum_mismatch".to_owned(),
            severity: "error".to_owned(),
            detail: "CRC32C expected 0x1234, got 0x5678".to_owned(),
        }
    }

    fn sample_repair_detail() -> RepairDetail {
        RepairDetail {
            generation: 7,
            corrupt_count: 2,
            symbols_used: 4,
            symbols_available: 8,
            decoder_stats: RecoveryDecoderStats {
                peeled: 10,
                inactivated: 2,
                gauss_ops: 50,
                pivots_selected: 3,
            },
            verify_pass: true,
            reason: None,
        }
    }

    fn sample_scrub_cycle_detail() -> ScrubCycleDetail {
        ScrubCycleDetail {
            blocks_scanned: 32768,
            blocks_corrupt: 5,
            blocks_io_error: 1,
            findings_count: 7,
        }
    }

    fn sample_policy_detail() -> PolicyDecisionDetail {
        PolicyDecisionDetail {
            corruption_posterior: 0.023,
            posterior_alpha: 23.0,
            posterior_beta: 977.0,
            overhead_ratio: 0.05,
            risk_bound: 1e-9,
            expected_loss: 0.051,
            symbols_selected: 5,
            metadata_group: false,
            decision: "maintain current overhead ratio".to_owned(),
        }
    }

    fn sample_symbol_refresh_detail() -> SymbolRefreshDetail {
        SymbolRefreshDetail {
            previous_generation: 6,
            new_generation: 7,
            symbols_generated: 1639,
        }
    }

    fn sample_txn_aborted_detail() -> TxnAbortedDetail {
        TxnAbortedDetail {
            txn_id: 77,
            reason: TxnAbortReason::SsiCycle,
            detail: Some("rw-antidependency cycle".to_owned()),
            read_set_size: 3,
            write_set_size: 2,
        }
    }

    fn sample_transaction_commit_detail() -> TransactionCommitDetail {
        TransactionCommitDetail {
            txn_id: 77,
            commit_seq: 19,
            write_set_size: 5,
            duration_us: 420,
        }
    }

    fn sample_serialization_conflict_detail() -> SerializationConflictDetail {
        SerializationConflictDetail {
            txn_id: 77,
            conflicting_txn: Some(76),
            conflict_type: "rw_antidependency_cycle".to_owned(),
        }
    }

    fn sample_version_gc_detail() -> VersionGcDetail {
        VersionGcDetail {
            block_id: 42,
            versions_freed: 3,
            oldest_retained_commit_seq: 11,
        }
    }

    fn sample_snapshot_advanced_detail() -> SnapshotAdvancedDetail {
        SnapshotAdvancedDetail {
            old_commit_seq: 100,
            new_commit_seq: 140,
            versions_eligible: 12,
        }
    }

    fn sample_flush_batch_detail() -> FlushBatchDetail {
        FlushBatchDetail {
            blocks_flushed: 64,
            bytes_written: 262_144,
            flush_duration_us: 9_500,
        }
    }

    fn sample_backpressure_detail() -> BackpressureActivatedDetail {
        BackpressureActivatedDetail {
            dirty_ratio: 0.83,
            threshold: 0.8,
        }
    }

    fn sample_dirty_block_discarded_detail() -> DirtyBlockDiscardedDetail {
        DirtyBlockDiscardedDetail {
            block_id: 17,
            txn_id: 99,
            reason: DirtyDiscardReason::Abort,
        }
    }

    fn sample_durability_policy_changed_detail() -> DurabilityPolicyChangedDetail {
        DurabilityPolicyChangedDetail {
            old_overhead: 0.05,
            new_overhead: 0.08,
            posterior_alpha: 20.0,
            posterior_beta: 980.0,
            posterior_mean: 0.02,
        }
    }

    fn sample_refresh_policy_changed_detail() -> RefreshPolicyChangedDetail {
        RefreshPolicyChangedDetail {
            block_group: 4,
            old_policy: "lazy".to_owned(),
            new_policy: "eager".to_owned(),
        }
    }

    #[test]
    fn corruption_detected_round_trip() {
        let record = EvidenceRecord::corruption_detected(0, sample_corruption_detail())
            .with_timestamp(1_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::CorruptionDetected);
        assert_eq!(parsed.block_group, 0);
        assert_eq!(parsed.timestamp_ns, 1_000_000);
        assert_eq!(parsed.corruption, Some(sample_corruption_detail()));
        assert!(parsed.repair.is_none());
        assert!(parsed.scrub_cycle.is_none());
        assert!(parsed.policy.is_none());
        assert!(parsed.symbol_refresh.is_none());
    }

    #[test]
    fn repair_attempted_round_trip() {
        let record =
            EvidenceRecord::repair_attempted(1, sample_repair_detail()).with_timestamp(7_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::RepairAttempted);
        assert_eq!(parsed.repair, Some(sample_repair_detail()));
    }

    #[test]
    fn repair_succeeded_round_trip() {
        let record = EvidenceRecord::repair_succeeded(5, sample_repair_detail())
            .with_timestamp(2_000_000)
            .with_block_range(100, 200);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::RepairSucceeded);
        assert_eq!(parsed.block_group, 5);
        assert_eq!(parsed.block_range, Some((100, 200)));
        assert_eq!(parsed.repair, Some(sample_repair_detail()));
    }

    #[test]
    fn repair_failed_round_trip() {
        let mut detail = sample_repair_detail();
        detail.verify_pass = false;
        detail.reason = Some("insufficient symbols".to_owned());
        let record = EvidenceRecord::repair_failed(3, detail).with_timestamp(3_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::RepairFailed);
        assert!(!parsed.repair.as_ref().expect("repair detail").verify_pass);
        assert_eq!(
            parsed
                .repair
                .as_ref()
                .expect("repair detail")
                .reason
                .as_deref(),
            Some("insufficient symbols")
        );
    }

    #[test]
    fn scrub_cycle_round_trip() {
        let record = EvidenceRecord::scrub_cycle_complete(10, sample_scrub_cycle_detail())
            .with_timestamp(4_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::ScrubCycleComplete);
        assert_eq!(parsed.scrub_cycle, Some(sample_scrub_cycle_detail()));
    }

    #[test]
    fn policy_decision_round_trip() {
        let record =
            EvidenceRecord::policy_decision(0, sample_policy_detail()).with_timestamp(5_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::PolicyDecision);
        let policy = parsed.policy.expect("policy detail present");
        assert!(
            (policy.corruption_posterior - 0.023).abs() < 1e-15,
            "corruption_posterior mismatch"
        );
        assert!(
            (policy.posterior_alpha - 23.0).abs() < 1e-15,
            "posterior_alpha mismatch"
        );
        assert!(
            (policy.posterior_beta - 977.0).abs() < 1e-15,
            "posterior_beta mismatch"
        );
        assert!(
            (policy.overhead_ratio - 0.05).abs() < 1e-15,
            "overhead_ratio mismatch"
        );
        assert!(
            (policy.risk_bound - 1e-9).abs() < 1e-20,
            "risk_bound mismatch"
        );
        assert!(
            (policy.expected_loss - 0.051).abs() < 1e-15,
            "expected_loss mismatch"
        );
        assert_eq!(policy.symbols_selected, 5);
        assert!(!policy.metadata_group);
        assert_eq!(policy.decision, "maintain current overhead ratio");
    }

    #[test]
    fn symbol_refresh_round_trip() {
        let record = EvidenceRecord::symbol_refresh(2, sample_symbol_refresh_detail())
            .with_timestamp(6_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::SymbolRefresh);
        assert_eq!(parsed.symbol_refresh, Some(sample_symbol_refresh_detail()));
    }

    #[test]
    fn txn_aborted_round_trip() {
        let record =
            EvidenceRecord::txn_aborted(sample_txn_aborted_detail()).with_timestamp(7_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::TxnAborted);
        assert_eq!(parsed.txn_aborted, Some(sample_txn_aborted_detail()));
    }

    #[test]
    fn transaction_commit_round_trip() {
        let record = EvidenceRecord::transaction_commit(sample_transaction_commit_detail())
            .with_timestamp(7_500_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::TransactionCommit);
        assert_eq!(
            parsed.transaction_commit,
            Some(sample_transaction_commit_detail())
        );
    }

    #[test]
    fn serialization_conflict_round_trip() {
        let record = EvidenceRecord::serialization_conflict(sample_serialization_conflict_detail())
            .with_timestamp(7_750_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::SerializationConflict);
        assert_eq!(
            parsed.serialization_conflict,
            Some(sample_serialization_conflict_detail())
        );
    }

    #[test]
    fn version_gc_round_trip() {
        let record =
            EvidenceRecord::version_gc(sample_version_gc_detail()).with_timestamp(8_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::VersionGc);
        assert_eq!(parsed.version_gc, Some(sample_version_gc_detail()));
    }

    #[test]
    fn snapshot_advanced_round_trip() {
        let record = EvidenceRecord::snapshot_advanced(sample_snapshot_advanced_detail())
            .with_timestamp(9_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::SnapshotAdvanced);
        assert_eq!(
            parsed.snapshot_advanced,
            Some(sample_snapshot_advanced_detail())
        );
    }

    #[test]
    fn flush_batch_round_trip() {
        let record =
            EvidenceRecord::flush_batch(sample_flush_batch_detail()).with_timestamp(10_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::FlushBatch);
        assert_eq!(parsed.flush_batch, Some(sample_flush_batch_detail()));
    }

    #[test]
    fn backpressure_activated_round_trip() {
        let record = EvidenceRecord::backpressure_activated(sample_backpressure_detail())
            .with_timestamp(11_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::BackpressureActivated);
        let detail = parsed
            .backpressure_activated
            .expect("backpressure detail present");
        assert!((detail.dirty_ratio - 0.83).abs() < 1e-15);
        assert!((detail.threshold - 0.8).abs() < 1e-15);
    }

    #[test]
    fn dirty_block_discarded_round_trip() {
        let record = EvidenceRecord::dirty_block_discarded(sample_dirty_block_discarded_detail())
            .with_timestamp(12_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::DirtyBlockDiscarded);
        assert_eq!(
            parsed.dirty_block_discarded,
            Some(sample_dirty_block_discarded_detail())
        );
    }

    #[test]
    fn durability_policy_changed_round_trip() {
        let record =
            EvidenceRecord::durability_policy_changed(sample_durability_policy_changed_detail())
                .with_timestamp(13_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(
            parsed.event_type,
            EvidenceEventType::DurabilityPolicyChanged
        );
        let detail = parsed
            .durability_policy_changed
            .expect("durability policy detail present");
        assert!((detail.old_overhead - 0.05).abs() < 1e-15);
        assert!((detail.new_overhead - 0.08).abs() < 1e-15);
        assert!((detail.posterior_alpha - 20.0).abs() < 1e-15);
        assert!((detail.posterior_beta - 980.0).abs() < 1e-15);
        assert!((detail.posterior_mean - 0.02).abs() < 1e-15);
    }

    #[test]
    fn refresh_policy_changed_round_trip() {
        let record = EvidenceRecord::refresh_policy_changed(sample_refresh_policy_changed_detail())
            .with_timestamp(14_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::RefreshPolicyChanged);
        assert_eq!(
            parsed.refresh_policy_changed,
            Some(sample_refresh_policy_changed_detail())
        );
        assert_eq!(parsed.block_group, 4);
    }

    #[test]
    fn from_recovery_evidence_recovered() {
        let ev = RecoveryEvidence {
            group: 4,
            generation: 3,
            corrupt_count: 2,
            symbols_available: 10,
            symbols_used: 10,
            decoder_stats: RecoveryDecoderStats {
                peeled: 5,
                inactivated: 1,
                gauss_ops: 20,
                pivots_selected: 2,
            },
            outcome: RecoveryOutcome::Recovered,
            reason: None,
        };
        let record = EvidenceRecord::from_recovery(&ev);
        assert_eq!(record.event_type, EvidenceEventType::RepairSucceeded);
        assert_eq!(record.block_group, 4);
        let repair = record.repair.expect("repair detail");
        assert!(repair.verify_pass);
        assert_eq!(repair.generation, 3);
        assert_eq!(repair.corrupt_count, 2);
    }

    #[test]
    fn from_recovery_evidence_failed() {
        let ev = RecoveryEvidence {
            group: 1,
            generation: 5,
            corrupt_count: 4,
            symbols_available: 2,
            symbols_used: 2,
            decoder_stats: RecoveryDecoderStats::default(),
            outcome: RecoveryOutcome::Failed,
            reason: Some("insufficient symbols".to_owned()),
        };
        let record = EvidenceRecord::from_recovery(&ev);
        assert_eq!(record.event_type, EvidenceEventType::RepairFailed);
        let repair = record.repair.expect("repair detail");
        assert!(!repair.verify_pass);
        assert_eq!(repair.reason.as_deref(), Some("insufficient symbols"));
    }

    #[test]
    fn from_scrub_report_conversion() {
        let report = ScrubReport {
            findings: vec![crate::scrub::ScrubFinding {
                block: ffs_types::BlockNumber(42),
                kind: crate::scrub::CorruptionKind::ChecksumMismatch,
                severity: crate::scrub::Severity::Error,
                detail: "bad crc".to_owned(),
            }],
            blocks_scanned: 1000,
            blocks_corrupt: 1,
            blocks_io_error: 0,
        };
        let record = EvidenceRecord::from_scrub_report(7, &report);
        assert_eq!(record.event_type, EvidenceEventType::ScrubCycleComplete);
        assert_eq!(record.block_group, 7);
        let cycle = record.scrub_cycle.expect("scrub cycle detail");
        assert_eq!(cycle.blocks_scanned, 1000);
        assert_eq!(cycle.blocks_corrupt, 1);
        assert_eq!(cycle.findings_count, 1);
    }

    #[test]
    fn ledger_append_and_parse() {
        let mut buf = Vec::new();
        {
            let mut ledger = EvidenceLedger::new(&mut buf);
            ledger
                .append(
                    &EvidenceRecord::corruption_detected(0, sample_corruption_detail())
                        .with_timestamp(100),
                )
                .expect("append 1");
            ledger
                .append(
                    &EvidenceRecord::repair_succeeded(0, sample_repair_detail())
                        .with_timestamp(200),
                )
                .expect("append 2");
            ledger
                .append(
                    &EvidenceRecord::scrub_cycle_complete(0, sample_scrub_cycle_detail())
                        .with_timestamp(300),
                )
                .expect("append 3");
        }

        let records = parse_evidence_ledger(&buf);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].event_type, EvidenceEventType::CorruptionDetected);
        assert_eq!(records[1].event_type, EvidenceEventType::RepairSucceeded);
        assert_eq!(records[2].event_type, EvidenceEventType::ScrubCycleComplete);
    }

    #[test]
    fn representative_evidence_ledger_jsonl_exact_golden_contract() {
        let mut buf = Vec::new();
        {
            let mut ledger = EvidenceLedger::new(&mut buf);
            ledger
                .append(
                    &EvidenceRecord::corruption_detected(0, sample_corruption_detail())
                        .with_block_range(10, 20)
                        .with_timestamp(42),
                )
                .expect("append corruption");
            ledger
                .append(
                    &EvidenceRecord::txn_aborted(sample_txn_aborted_detail())
                        .with_timestamp(7_000_000),
                )
                .expect("append txn aborted");
            ledger
                .append(
                    &EvidenceRecord::refresh_policy_changed(sample_refresh_policy_changed_detail())
                        .with_timestamp(11_000_000),
                )
                .expect("append refresh policy change");
        }

        let actual = String::from_utf8(buf).expect("utf8");
        let expected = concat!(
            "{\"timestamp_ns\":42,\"event_type\":\"corruption_detected\",\"block_group\":0,\"block_range\":[10,20],\"corruption\":{\"blocks_affected\":3,\"corruption_kind\":\"checksum_mismatch\",\"severity\":\"error\",\"detail\":\"CRC32C expected 0x1234, got 0x5678\"}}\n",
            "{\"timestamp_ns\":7000000,\"event_type\":\"txn_aborted\",\"block_group\":0,\"txn_aborted\":{\"txn_id\":77,\"reason\":\"ssi_cycle\",\"detail\":\"rw-antidependency cycle\",\"read_set_size\":3,\"write_set_size\":2}}\n",
            "{\"timestamp_ns\":11000000,\"event_type\":\"refresh_policy_changed\",\"block_group\":4,\"refresh_policy_changed\":{\"block_group\":4,\"old_policy\":\"lazy\",\"new_policy\":\"eager\"}}\n",
        );
        assert_eq!(actual, expected);
    }

    #[test]
    fn parse_skips_invalid_lines() {
        let mut data = Vec::new();
        // Valid record
        let record =
            EvidenceRecord::corruption_detected(0, sample_corruption_detail()).with_timestamp(100);
        serde_json::to_writer(&mut data, &record).expect("serialize");
        data.extend_from_slice(b"\n");
        // Invalid line
        data.extend_from_slice(b"not valid json\n");
        // Blank line
        data.extend_from_slice(b"\n");
        // Another valid record
        let second =
            EvidenceRecord::repair_succeeded(0, sample_repair_detail()).with_timestamp(200);
        serde_json::to_writer(&mut data, &second).expect("serialize");
        data.extend_from_slice(b"\n");

        let parsed = parse_evidence_ledger(&data);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].event_type, EvidenceEventType::CorruptionDetected);
        assert_eq!(parsed[1].event_type, EvidenceEventType::RepairSucceeded);
    }

    #[test]
    fn none_fields_omitted_from_json() {
        let record =
            EvidenceRecord::corruption_detected(0, sample_corruption_detail()).with_timestamp(100);
        let json = record.to_json().expect("serialize");
        assert!(json.contains("\"corruption\""));
        assert!(!json.contains("\"repair\""));
        assert!(!json.contains("\"scrub_cycle\""));
        assert!(!json.contains("\"policy\""));
        assert!(!json.contains("\"symbol_refresh\""));
        assert!(!json.contains("\"block_range\""));
        assert!(!json.contains("\"wal_recovery\""));
        assert!(!json.contains("\"transaction_commit\""));
        assert!(!json.contains("\"txn_aborted\""));
        assert!(!json.contains("\"serialization_conflict\""));
        assert!(!json.contains("\"version_gc\""));
        assert!(!json.contains("\"snapshot_advanced\""));
        assert!(!json.contains("\"flush_batch\""));
        assert!(!json.contains("\"backpressure_activated\""));
        assert!(!json.contains("\"dirty_block_discarded\""));
        assert!(!json.contains("\"durability_policy_changed\""));
        assert!(!json.contains("\"refresh_policy_changed\""));
    }

    #[test]
    fn wal_recovery_round_trip() {
        let detail = WalRecoveryDetail {
            commits_replayed: 42,
            versions_replayed: 128,
            records_discarded: 1,
            wal_valid_bytes: 65536,
            wal_total_bytes: 65600,
            used_checkpoint: true,
            checkpoint_commit_seq: Some(30),
        };
        let record = EvidenceRecord::wal_recovery(detail.clone()).with_timestamp(9_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::WalRecovery);
        assert_eq!(parsed.block_group, 0);
        assert_eq!(parsed.wal_recovery, Some(detail));
        assert!(parsed.corruption.is_none());
        assert!(parsed.repair.is_none());
    }

    #[test]
    fn wal_recovery_no_checkpoint() {
        let detail = WalRecoveryDetail {
            commits_replayed: 5,
            versions_replayed: 10,
            records_discarded: 0,
            wal_valid_bytes: 1024,
            wal_total_bytes: 1024,
            used_checkpoint: false,
            checkpoint_commit_seq: None,
        };
        let record = EvidenceRecord::wal_recovery(detail).with_timestamp(10_000_000);
        let json = record.to_json().expect("serialize");
        // checkpoint_commit_seq should be omitted from JSON
        assert!(!json.contains("checkpoint_commit_seq"));
    }

    // ── Edge-case hardening tests ──────────────────────────────────────

    #[test]
    fn evidence_event_type_serde_all_variants() {
        use EvidenceEventType::*;
        let variants = [
            CorruptionDetected,
            RepairAttempted,
            RepairSucceeded,
            RepairFailed,
            ScrubCycleComplete,
            PolicyDecision,
            SymbolRefresh,
            WalRecovery,
            TransactionCommit,
            TxnAborted,
            SerializationConflict,
            VersionGc,
            SnapshotAdvanced,
            FlushBatch,
            BackpressureActivated,
            DirtyBlockDiscarded,
            DurabilityPolicyChanged,
            RefreshPolicyChanged,
            MergeProofChecked,
            MergeApplied,
            MergeRejected,
            PolicySwitched,
            ContentionSample,
        ];
        for variant in variants {
            let json = serde_json::to_string(&variant).expect("serialize");
            let parsed: EvidenceEventType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(parsed, variant, "round-trip failed for {variant:?}");
        }
    }

    #[test]
    fn evidence_event_type_hash_consistent() {
        use std::collections::HashSet;
        let set: HashSet<EvidenceEventType> = [
            EvidenceEventType::CorruptionDetected,
            EvidenceEventType::CorruptionDetected,
            EvidenceEventType::RepairFailed,
        ]
        .into_iter()
        .collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn evidence_record_with_block_range_appears_in_json() {
        let record = EvidenceRecord::corruption_detected(0, sample_corruption_detail())
            .with_block_range(10, 20)
            .with_timestamp(42);
        let json = record.to_json().expect("serialize");
        assert!(json.contains("\"block_range\""));
        assert!(json.contains("10"));
        assert!(json.contains("20"));
    }

    #[test]
    fn evidence_record_with_timestamp_overrides_auto() {
        let record =
            EvidenceRecord::corruption_detected(0, sample_corruption_detail()).with_timestamp(999);
        assert_eq!(record.timestamp_ns, 999);
    }

    #[test]
    fn corruption_detail_clone_and_eq() {
        let d = sample_corruption_detail();
        let d2 = d.clone();
        assert_eq!(d, d2);
    }

    #[test]
    fn txn_abort_reason_serde_all_variants() {
        for variant in [
            TxnAbortReason::FcwConflict,
            TxnAbortReason::SsiCycle,
            TxnAbortReason::Timeout,
            TxnAbortReason::DurabilityFailure,
            TxnAbortReason::UserAbort,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            let parsed: TxnAbortReason = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn ledger_into_inner_returns_writer() {
        let buf: Vec<u8> = Vec::new();
        let ledger = EvidenceLedger::new(buf);
        let inner = ledger.into_inner();
        assert_eq!(inner, [] as [u8; 0]);
    }

    #[test]
    fn parse_evidence_ledger_empty_input() {
        let records = parse_evidence_ledger(b"");
        assert_eq!(records, [] as [EvidenceRecord; 0]);
    }

    #[test]
    fn parse_evidence_ledger_all_blank_lines() {
        let records = parse_evidence_ledger(b"\n\n\n");
        assert_eq!(records, [] as [EvidenceRecord; 0]);
    }

    #[test]
    fn parse_evidence_ledger_skips_invalid_utf8_lines_without_lossy_rewrite() {
        let invalid =
            EvidenceRecord::corruption_detected(0, sample_corruption_detail()).with_timestamp(100);
        let mut invalid_json = invalid.to_json().expect("serialize").into_bytes();
        let detail_pos = invalid_json
            .windows(b"checksum_mismatch".len())
            .position(|window| window == b"checksum_mismatch")
            .expect("detail string present");
        invalid_json[detail_pos] = 0xff;

        let valid = EvidenceRecord::repair_succeeded(0, sample_repair_detail()).with_timestamp(200);
        let mut data = invalid_json;
        data.push(b'\n');
        data.extend_from_slice(valid.to_json().expect("serialize").as_bytes());

        let records = parse_evidence_ledger(&data);
        assert_eq!(records, vec![valid]);
    }

    #[test]
    fn from_recovery_evidence_partial_maps_to_repair_failed() {
        let ev = RecoveryEvidence {
            group: 2,
            generation: 1,
            corrupt_count: 3,
            symbols_available: 2,
            symbols_used: 2,
            decoder_stats: RecoveryDecoderStats::default(),
            outcome: RecoveryOutcome::Partial,
            reason: Some("partial decode".to_owned()),
        };
        let record = EvidenceRecord::from_recovery(&ev);
        assert_eq!(record.event_type, EvidenceEventType::RepairFailed);
        assert!(!record.repair.as_ref().unwrap().verify_pass);
    }

    /// A writer that accepts at most N bytes before failing, including
    /// partial writes. This reproduces the generic `Write` failure mode
    /// where a sink returns `Ok(n)` for a prefix and then fails on the
    /// next `write_all` retry.
    struct FaultyWriter {
        inner: Vec<u8>,
        bytes_before_failure: usize,
        failed: bool,
    }

    impl FaultyWriter {
        fn new(bytes_before_failure: usize) -> Self {
            Self {
                inner: Vec::new(),
                bytes_before_failure,
                failed: false,
            }
        }
    }

    impl io::Write for FaultyWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.failed {
                return Err(io::Error::other("writer already failed"));
            }
            let remaining = self.bytes_before_failure.saturating_sub(self.inner.len());
            if remaining == 0 {
                self.failed = true;
                return Err(io::Error::other("writer failed"));
            }
            if buf.len() <= remaining {
                self.inner.extend_from_slice(buf);
                Ok(buf.len())
            } else {
                self.inner.extend_from_slice(&buf[..remaining]);
                self.failed = true;
                Ok(remaining)
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.failed {
                Err(io::Error::other("writer already failed"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn append_failed_partial_write_poisons_ledger_handle() {
        // Serialize-to-buffer prevents serde's own incremental output
        // from tearing a line. It cannot make arbitrary `Write` sinks
        // atomic, so a failed I/O append must poison the handle and
        // reject later appends instead of concatenating onto the partial
        // prefix.
        let mut ledger = EvidenceLedger::new(FaultyWriter::new(4)); // fail before any full record fits
        let record =
            EvidenceRecord::corruption_detected(7, sample_corruption_detail()).with_timestamp(1);

        let err = ledger.append(&record).expect_err("small buffer must fail");
        assert_eq!(err.kind(), io::ErrorKind::Other);

        let bytes_after_failure = ledger.writer.inner.clone();
        assert_ne!(bytes_after_failure, [] as [u8; 0]);
        assert!(
            !bytes_after_failure.ends_with(b"\n"),
            "test writer should leave a torn JSONL prefix; got {bytes_after_failure:?}"
        );

        let err = ledger
            .append(&record)
            .expect_err("poisoned ledger must reject future appends");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

        let bytes = ledger.into_inner().inner;
        assert_eq!(bytes, bytes_after_failure);
        assert_eq!(parse_evidence_ledger(&bytes), [] as [EvidenceRecord; 0]);
    }

    #[test]
    fn append_round_trip_via_ledger_parses_back() {
        // Full happy-path regression covering the in-memory ledger path
        // that downstream consumers rely on for JSONL parsing.
        let mut ledger = EvidenceLedger::new(Vec::new());
        let records = [
            EvidenceRecord::corruption_detected(1, sample_corruption_detail()).with_timestamp(10),
            EvidenceRecord::repair_succeeded(1, sample_repair_detail()).with_timestamp(20),
            EvidenceRecord::scrub_cycle_complete(
                2,
                ScrubCycleDetail {
                    blocks_scanned: 256,
                    blocks_corrupt: 0,
                    blocks_io_error: 0,
                    findings_count: 0,
                },
            )
            .with_timestamp(30),
        ];
        for record in &records {
            ledger.append(record).expect("append");
        }
        let parsed = parse_evidence_ledger(&ledger.into_inner());
        assert_eq!(parsed.len(), records.len());
        assert_eq!(parsed[0].timestamp_ns, 10);
        assert_eq!(parsed[1].event_type, EvidenceEventType::RepairSucceeded);
        assert_eq!(parsed[2].scrub_cycle.as_ref().unwrap().blocks_scanned, 256);
    }
}
