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

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::Write;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use asupersync::{Cx, SystemPressure};
use ffs_block::{BlockDevice, RepairFlushLifecycle};
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, GroupNumber};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, trace, warn};

use crate::autopilot::{DurabilityAutopilot, OverheadDecision};
use crate::codec::{EncodedGroup, encode_group};
use crate::evidence::{
    CorruptionDetail, EvidenceLedger, EvidenceRecord, PolicyDecisionDetail, RepairDetail,
    SymbolRefreshDetail,
};
use crate::recovery::{
    DirectDeviceRecoveryWriteback, GroupRecoveryOrchestrator, RecoveryAttemptResult,
    RecoveryDecoderStats, RecoveryOutcome, RecoveryWriteback,
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

/// Refresh policy for repair symbol regeneration after writes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RefreshPolicy {
    /// Refresh immediately on every write to the group.
    Eager,
    /// Refresh on scrub (or when staleness budget is exceeded).
    Lazy { max_staleness: Duration },
    /// Switch eager/lazy behavior based on corruption posterior.
    Adaptive {
        /// Posterior threshold above which eager refresh is used.
        risk_threshold: f64,
        /// Maximum allowed dirty age before forced refresh.
        max_staleness: Duration,
    },
    /// Refresh when EITHER age timeout OR block-count threshold is exceeded.
    ///
    /// This is the expected-loss-optimal policy identified by `RefreshLossModel`:
    /// it caps both the time-based staleness and the write-count-based staleness,
    /// using whichever trigger fires first.
    Hybrid {
        /// Maximum allowed dirty age before forced refresh.
        max_staleness: Duration,
        /// Maximum writes before forced refresh.
        block_count_threshold: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshMode {
    Recovery,
    EagerWrite,
    LazyScrub,
    AdaptiveEagerWrite,
    AdaptiveLazyScrub,
    StalenessTimeout,
    /// Triggered when block-count writes since last refresh exceeds threshold.
    BlockCountThreshold,
    /// Hybrid policy: age timeout fired first.
    HybridAge,
    /// Hybrid policy: block-count threshold fired first.
    HybridBlockCount,
    /// Hybrid policy: triggered on scrub cycle.
    HybridScrub,
}

impl RefreshMode {
    #[must_use]
    fn as_str(self) -> &'static str {
        match self {
            Self::Recovery => "recovery",
            Self::EagerWrite => "eager_write",
            Self::LazyScrub => "lazy_scrub",
            Self::AdaptiveEagerWrite => "adaptive_eager_write",
            Self::AdaptiveLazyScrub => "adaptive_lazy_scrub",
            Self::StalenessTimeout => "staleness_timeout",
            Self::BlockCountThreshold => "block_count_threshold",
            Self::HybridAge => "hybrid_age",
            Self::HybridBlockCount => "hybrid_block_count",
            Self::HybridScrub => "hybrid_scrub",
        }
    }
}

/// Per-group refresh state summary for telemetry/observability.
#[derive(Debug, Clone, Serialize)]
pub struct GroupRefreshSummary {
    /// Block group number.
    pub group: u32,
    /// Whether the group currently has dirty (not-yet-refreshed) symbols.
    pub dirty: bool,
    /// Milliseconds since the group was first marked dirty (0 if clean).
    pub dirty_age_ms: u64,
    /// Which refresh policy is assigned.
    pub policy: String,
    /// Milliseconds since the last successful symbol refresh.
    pub since_last_refresh_ms: u64,
    /// Number of block writes since the last symbol refresh.
    pub writes_since_refresh: u64,
    /// Block-count threshold (0 if disabled).
    pub block_count_threshold: u64,
}

/// Aggregate refresh-state telemetry for the entire pipeline.
#[derive(Debug, Clone, Serialize)]
pub struct RefreshTelemetry {
    /// Total groups with refresh tracking.
    pub tracked_groups: usize,
    /// Number of groups currently dirty.
    pub dirty_groups: usize,
    /// Maximum dirty age across all groups (ms).
    pub max_dirty_age_ms: u64,
    /// Per-group summaries.
    pub groups: Vec<GroupRefreshSummary>,
}

// ── Stale-window SLO ──────────────────────────────────────────────────────

/// Service-level objective for repair symbol freshness.
///
/// A stale-window SLO is breached when the configured percentile of groups
/// exceeds either the age or write-count threshold.  For example, with
/// `percentile = 0.95`, the SLO is met only if at least 95% of groups have
/// staleness below the thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct StaleWindowSlo {
    /// Maximum acceptable age (ms) since last refresh for p95 of groups.
    /// Default: 60_000ms (60 seconds).
    pub max_age_ms: u64,
    /// Maximum acceptable writes since last refresh for p95 of groups.
    /// Default: 5000 blocks.
    pub max_writes: u64,
    /// Percentile threshold for SLO evaluation (0.0–1.0).
    /// Default: 0.95 (p95).
    pub percentile: f64,
}

impl Default for StaleWindowSlo {
    fn default() -> Self {
        Self {
            max_age_ms: 60_000,
            max_writes: 5_000,
            percentile: 0.95,
        }
    }
}

/// Result of a stale-window SLO evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct SloEvaluation {
    /// Whether the SLO is currently breached.
    pub breached: bool,
    /// The age (ms) at the configured percentile across all groups.
    pub age_at_percentile_ms: u64,
    /// The write count at the configured percentile across all groups.
    pub writes_at_percentile: u64,
    /// Number of groups whose age exceeds the SLO age threshold.
    pub groups_age_breached: usize,
    /// Number of groups whose write count exceeds the SLO write threshold.
    pub groups_writes_breached: usize,
    /// Total tracked groups.
    pub total_groups: usize,
}

impl StaleWindowSlo {
    /// Evaluate the SLO against current pipeline state.
    ///
    /// Computes the percentile staleness across all tracked groups and checks
    /// whether it exceeds the configured thresholds.
    #[must_use]
    pub fn evaluate(&self, telemetry: &RefreshTelemetry) -> SloEvaluation {
        if telemetry.groups.is_empty() {
            return SloEvaluation {
                breached: false,
                age_at_percentile_ms: 0,
                writes_at_percentile: 0,
                groups_age_breached: 0,
                groups_writes_breached: 0,
                total_groups: 0,
            };
        }

        let mut ages: Vec<u64> = telemetry.groups.iter().map(|g| g.dirty_age_ms).collect();
        let mut writes: Vec<u64> = telemetry
            .groups
            .iter()
            .map(|g| g.writes_since_refresh)
            .collect();
        ages.sort_unstable();
        writes.sort_unstable();

        let idx = percentile_index(ages.len(), self.percentile);
        let age_pctl = ages[idx];
        let writes_pctl = writes[idx];

        let groups_age_breached = ages.iter().filter(|&&a| a > self.max_age_ms).count();
        let groups_writes_breached = writes.iter().filter(|&&w| w > self.max_writes).count();

        let breached = age_pctl > self.max_age_ms || writes_pctl > self.max_writes;

        SloEvaluation {
            breached,
            age_at_percentile_ms: age_pctl,
            writes_at_percentile: writes_pctl,
            groups_age_breached,
            groups_writes_breached,
            total_groups: telemetry.groups.len(),
        }
    }
}

/// Compute the index for a given percentile in a sorted array of `len` elements.
fn percentile_index(len: usize, percentile: f64) -> usize {
    if len == 0 {
        return 0;
    }
    let raw = (percentile.clamp(0.0, 1.0) * (len as f64 - 1.0)).round();
    // Safe conversion: raw is in [0, len-1] after clamp+round, always non-negative and fits usize.
    let idx = if raw.is_finite() && raw >= 0.0 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let i = raw as usize;
        i
    } else {
        0
    };
    idx.min(len - 1)
}

#[derive(Debug, Clone)]
struct GroupRefreshState {
    dirty: bool,
    dirty_since: Option<Instant>,
    policy: RefreshPolicy,
    last_refresh: Instant,
    /// Number of block writes to this group since the last symbol refresh.
    writes_since_refresh: u64,
    /// Block-count threshold: trigger eager refresh when exceeded.
    /// `None` disables block-count tracking.
    block_count_threshold: Option<u64>,
}

impl GroupRefreshState {
    #[must_use]
    fn new(policy: RefreshPolicy) -> Self {
        let now = Instant::now();
        Self {
            dirty: false,
            dirty_since: None,
            policy,
            last_refresh: now,
            writes_since_refresh: 0,
            block_count_threshold: None,
        }
    }

    #[must_use]
    #[allow(dead_code)]
    fn with_block_count_threshold(mut self, threshold: u64) -> Self {
        self.block_count_threshold = Some(threshold);
        self
    }

    /// Returns true if the block-count threshold has been exceeded.
    #[must_use]
    fn block_count_exceeded(&self) -> bool {
        self.block_count_threshold
            .is_some_and(|threshold| self.writes_since_refresh >= threshold)
    }
}

#[derive(Debug, Clone, Copy)]
struct GroupBlockRange {
    group: GroupNumber,
    start: u64,
    end: u64,
}

/// Flush-driven queue of block groups that require symbol refresh.
///
/// This adapter bridges write-back flush notifications from `ffs-block` into
/// the repair pipeline without coupling `ffs-block` to repair internals.
///
/// # Concurrency invariant (bd-scg17): drain + drop + process
///
/// `queued_groups` is acquired ONLY for the brief duration of an insert or a
/// drain — never held across a pipeline call. The two consumer paths follow
/// the same pattern:
///
/// * [`on_flush_committed`](Self::on_flush_committed) acquires the lock in a
///   scoped block, inserts the affected group ids, and drops the guard at
///   inner-scope close BEFORE iterating to log.
/// * [`apply_queued_refreshes`](Self::apply_queued_refreshes) calls
///   [`drain_queued_groups`](Self::drain_queued_groups) which acquires +
///   drains + drops the lock, THEN calls `pipeline.mark_group_dirty` and
///   `pipeline.on_group_flush` outside the lock.
///
/// This separation is critical: those pipeline calls can fire back into
/// `RepairFlushLifecycle::on_flush_committed` (the same trait this struct
/// implements), which reacquires `queued_groups`. Holding the lock during the
/// pipeline call would deadlock on the first re-entrant flush.
///
/// **Any future refactor that hoists the pipeline calls inside the locked
/// block (e.g., to keep "drain + process" atomic) MUST be rejected.** The
/// `queued_repair_refresh_drain_releases_lock_before_processing` regression
/// test exercises a callback that re-enters `on_flush_committed` during
/// processing and asserts no deadlock.
#[derive(Debug, Clone)]
pub struct QueuedRepairRefresh {
    group_ranges: Arc<Vec<GroupBlockRange>>,
    group_ranges_are_disjoint: bool,
    queued_groups: Arc<Mutex<HashSet<GroupNumber>>>,
}

impl QueuedRepairRefresh {
    /// Build a queue adapter from repair group configurations.
    #[must_use]
    pub fn from_group_configs(groups: &[GroupConfig]) -> Self {
        let ranges: Vec<GroupBlockRange> = groups
            .iter()
            .map(|cfg| GroupBlockRange {
                group: cfg.layout.group,
                start: cfg.source_first_block.0,
                end: cfg.source_first_block.0 + u64::from(cfg.source_block_count),
            })
            .collect();
        let mut indexed_ranges = ranges.clone();
        indexed_ranges.sort_by_key(|range| range.start);
        let group_ranges_are_disjoint = indexed_ranges
            .windows(2)
            .all(|pair| pair[0].end <= pair[1].start);
        let group_ranges = if group_ranges_are_disjoint {
            indexed_ranges
        } else {
            // Overlapping ranges are not a valid production layout, but the
            // public constructor historically accepted them and selected the
            // first matching input range. Preserve that tie-break exactly.
            ranges
        };
        Self {
            group_ranges: Arc::new(group_ranges),
            group_ranges_are_disjoint,
            queued_groups: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    fn groups_for_blocks(&self, blocks: &[BlockNumber]) -> Vec<GroupNumber> {
        let mut groups = Vec::with_capacity(blocks.len());
        for block in blocks {
            let range = if self.group_ranges_are_disjoint {
                self.group_ranges
                    .partition_point(|range| range.start <= block.0)
                    .checked_sub(1)
                    .and_then(|index| self.group_ranges.get(index))
                    .filter(|range| block.0 < range.end)
            } else {
                self.group_ranges
                    .iter()
                    .find(|range| block.0 >= range.start && block.0 < range.end)
            };
            if let Some(range) = range {
                groups.push(range.group);
            }
        }
        groups.sort_unstable();
        groups.dedup();
        groups
    }

    /// Drain queued dirty groups in deterministic order.
    pub fn drain_queued_groups(&self) -> Result<Vec<GroupNumber>> {
        let mut guard = self
            .queued_groups
            .lock()
            .map_err(|_| FfsError::RepairFailed("queued refresh mutex poisoned".to_owned()))?;
        let mut groups = guard.drain().collect::<Vec<_>>();
        drop(guard);
        groups.sort_unstable();
        Ok(groups)
    }

    /// Apply queued refresh notifications to a mutable repair pipeline.
    ///
    /// Returns the number of groups refreshed immediately (groups that remain
    /// dirty were queued but deferred by policy).
    pub fn apply_queued_refreshes<W: Write>(
        &self,
        cx: &Cx,
        pipeline: &mut ScrubWithRecovery<'_, W>,
    ) -> Result<usize> {
        let groups = self.drain_queued_groups()?;
        if groups.is_empty() {
            return Ok(0);
        }

        let mut refreshed_now = 0_usize;
        for group in groups {
            let started = Instant::now();
            pipeline.mark_group_dirty(group)?;
            pipeline.on_group_flush(cx, group)?;

            if pipeline.is_group_dirty(group) {
                debug!(
                    target: "ffs::repair::refresh",
                    group_id = group.0,
                    "symbol_refresh_deferred"
                );
            } else {
                let symbols = pipeline
                    .find_group_config(group)
                    .map_or(0, |cfg| pipeline.selected_refresh_symbol_count(&cfg));
                info!(
                    target: "ffs::repair::refresh",
                    group_id = group.0,
                    duration_ms = started.elapsed().as_millis(),
                    symbol_count = symbols,
                    "symbol_refresh_complete"
                );
                refreshed_now += 1;
            }
        }
        Ok(refreshed_now)
    }
}

impl RepairFlushLifecycle for QueuedRepairRefresh {
    fn on_flush_committed(&self, _cx: &Cx, blocks: &[BlockNumber]) -> Result<()> {
        let groups = self.groups_for_blocks(blocks);
        if groups.is_empty() {
            return Ok(());
        }

        let group_ids: Vec<u32> = groups.iter().map(|group| group.0).collect();
        debug!(
            target: "ffs::repair::refresh",
            group_ids = ?group_ids,
            block_count = blocks.len(),
            "flush_triggers_refresh"
        );

        {
            let mut queued = self
                .queued_groups
                .lock()
                .map_err(|_| FfsError::RepairFailed("queued refresh mutex poisoned".to_owned()))?;
            queued.reserve(groups.len());
            for group in &groups {
                queued.insert(*group);
            }
        }
        for group in groups {
            debug!(
                target: "ffs::repair::refresh",
                group_id = group.0,
                priority = "normal",
                "symbol_refresh_queued"
            );
        }
        Ok(())
    }
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

// ── Daemon scheduler ──────────────────────────────────────────────────────

/// Background scrub daemon configuration.
#[derive(Debug, Clone)]
pub struct ScrubDaemonConfig {
    /// Delay between daemon ticks.
    pub interval: Duration,
    /// Cancellation polling granularity while sleeping.
    pub cancel_check_interval: Duration,
    /// Poll quota threshold below which the daemon yields for budget pressure.
    pub budget_poll_quota_threshold: u32,
    /// Yield duration when budget pressure is active.
    pub budget_sleep: Duration,
    /// Headroom threshold below which the daemon yields for backpressure.
    pub backpressure_headroom_threshold: f32,
    /// Yield duration when backpressure is active.
    pub backpressure_sleep: Duration,
}

impl Default for ScrubDaemonConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            cancel_check_interval: Duration::from_millis(100),
            budget_poll_quota_threshold: 256,
            budget_sleep: Duration::from_millis(10),
            backpressure_headroom_threshold: 0.3,
            backpressure_sleep: Duration::from_millis(25),
        }
    }
}

/// Live scrub daemon counters exposed to callers/TUI layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubDaemonMetrics {
    pub blocks_scanned_total: u64,
    pub blocks_corrupt_found: u64,
    pub blocks_recovered: u64,
    pub blocks_unrecoverable: u64,
    pub scrub_rounds_completed: u64,
    pub current_group: u32,
    pub scrub_rate_blocks_per_sec: f64,
    pub backpressure_yields: u64,
}

impl Default for ScrubDaemonMetrics {
    fn default() -> Self {
        Self {
            blocks_scanned_total: 0,
            blocks_corrupt_found: 0,
            blocks_recovered: 0,
            blocks_unrecoverable: 0,
            scrub_rounds_completed: 0,
            current_group: 0,
            scrub_rate_blocks_per_sec: 0.0,
            backpressure_yields: 0,
        }
    }
}

/// Thread-safe atomic metrics for concurrent external repair observation.
#[derive(Debug, Clone)]
pub struct RepairPipelineMetrics {
    groups_scrubbed: Arc<AtomicU64>,
    corruption_detected: Arc<AtomicU64>,
    decode_attempts: Arc<AtomicU64>,
    decode_successes: Arc<AtomicU64>,
    symbol_refresh_count: Arc<AtomicU64>,
    symbol_staleness_max_seconds: Arc<AtomicI64>,
    blocks_scanned: Arc<AtomicU64>,
    blocks_recovered: Arc<AtomicU64>,
    blocks_unrecoverable: Arc<AtomicU64>,
    scrub_rounds_completed: Arc<AtomicU64>,
}

impl RepairPipelineMetrics {
    fn saturating_add_u64(counter: &AtomicU64, delta: u64) {
        while counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(delta))
            })
            .is_err()
        {
            std::hint::spin_loop();
        }
    }

    #[must_use]
    pub fn new() -> Self {
        Self {
            groups_scrubbed: Arc::new(AtomicU64::new(0)),
            corruption_detected: Arc::new(AtomicU64::new(0)),
            decode_attempts: Arc::new(AtomicU64::new(0)),
            decode_successes: Arc::new(AtomicU64::new(0)),
            symbol_refresh_count: Arc::new(AtomicU64::new(0)),
            symbol_staleness_max_seconds: Arc::new(AtomicI64::new(0)),
            blocks_scanned: Arc::new(AtomicU64::new(0)),
            blocks_recovered: Arc::new(AtomicU64::new(0)),
            blocks_unrecoverable: Arc::new(AtomicU64::new(0)),
            scrub_rounds_completed: Arc::new(AtomicU64::new(0)),
        }
    }

    fn add_groups_scrubbed(&self, delta: u64) {
        Self::saturating_add_u64(&self.groups_scrubbed, delta);
    }

    fn add_corruption_detected(&self, delta: u64) {
        Self::saturating_add_u64(&self.corruption_detected, delta);
    }

    fn add_decode_attempts(&self, delta: u64) {
        Self::saturating_add_u64(&self.decode_attempts, delta);
    }

    fn add_decode_successes(&self, delta: u64) {
        Self::saturating_add_u64(&self.decode_successes, delta);
    }

    fn add_symbol_refresh_count(&self, delta: u64) {
        Self::saturating_add_u64(&self.symbol_refresh_count, delta);
    }

    fn add_blocks_scanned(&self, delta: u64) {
        Self::saturating_add_u64(&self.blocks_scanned, delta);
    }

    fn add_blocks_recovered(&self, delta: u64) {
        Self::saturating_add_u64(&self.blocks_recovered, delta);
    }

    fn add_blocks_unrecoverable(&self, delta: u64) {
        Self::saturating_add_u64(&self.blocks_unrecoverable, delta);
    }

    fn add_scrub_rounds_completed(&self, delta: u64) {
        Self::saturating_add_u64(&self.scrub_rounds_completed, delta);
    }

    #[must_use]
    pub fn snapshot(&self) -> RepairMetricsSnapshot {
        RepairMetricsSnapshot {
            groups_scrubbed: self.groups_scrubbed.load(Ordering::Relaxed),
            corruption_detected: self.corruption_detected.load(Ordering::Relaxed),
            decode_attempts: self.decode_attempts.load(Ordering::Relaxed),
            decode_successes: self.decode_successes.load(Ordering::Relaxed),
            symbol_refresh_count: self.symbol_refresh_count.load(Ordering::Relaxed),
            symbol_staleness_max_seconds: self.symbol_staleness_max_seconds.load(Ordering::Relaxed),
            blocks_scanned: self.blocks_scanned.load(Ordering::Relaxed),
            blocks_recovered: self.blocks_recovered.load(Ordering::Relaxed),
            blocks_unrecoverable: self.blocks_unrecoverable.load(Ordering::Relaxed),
            scrub_rounds_completed: self.scrub_rounds_completed.load(Ordering::Relaxed),
        }
    }

    fn update_staleness_gauge(&self, telemetry: &RefreshTelemetry) {
        let max_staleness_ms = telemetry
            .groups
            .iter()
            .map(|group| group.since_last_refresh_ms)
            .max()
            .unwrap_or(0);
        let max_staleness_secs = i64::try_from(max_staleness_ms / 1000).unwrap_or(i64::MAX);
        self.symbol_staleness_max_seconds
            .store(max_staleness_secs, Ordering::Relaxed);
    }
}

impl Default for RepairPipelineMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable point-in-time snapshot of the atomic repair metrics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepairMetricsSnapshot {
    pub groups_scrubbed: u64,
    pub corruption_detected: u64,
    pub decode_attempts: u64,
    pub decode_successes: u64,
    pub symbol_refresh_count: u64,
    pub symbol_staleness_max_seconds: i64,
    pub blocks_scanned: u64,
    pub blocks_recovered: u64,
    pub blocks_unrecoverable: u64,
    pub scrub_rounds_completed: u64,
}

/// JSON-friendly runtime metrics export for repair pipeline health.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairRuntimeMetricsSnapshot {
    pub groups_scrubbed: u64,
    pub corruption_detected: u64,
    pub decode_attempts: u64,
    pub decode_successes: u64,
    pub symbol_refresh_count: u64,
    pub symbol_staleness_max_seconds: f64,
}

#[derive(Debug, Clone, Default)]
struct RepairRuntimeMetrics {
    groups_scrubbed: u64,
    corruption_detected: u64,
    decode_attempts: u64,
    decode_successes: u64,
    symbol_refresh_count: u64,
}

impl RepairRuntimeMetrics {
    fn snapshot(&self, telemetry: &RefreshTelemetry) -> RepairRuntimeMetricsSnapshot {
        let max_staleness_ms = telemetry
            .groups
            .iter()
            .map(|group| group.since_last_refresh_ms)
            .max()
            .unwrap_or(0);
        RepairRuntimeMetricsSnapshot {
            groups_scrubbed: self.groups_scrubbed,
            corruption_detected: self.corruption_detected,
            decode_attempts: self.decode_attempts,
            decode_successes: self.decode_successes,
            symbol_refresh_count: self.symbol_refresh_count,
            symbol_staleness_max_seconds: max_staleness_ms as f64 / 1000.0,
        }
    }
}

/// Summary for one daemon tick (one group scan attempt).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubDaemonStep {
    pub group: u32,
    pub blocks_scanned: u64,
    pub corrupt_count: usize,
    pub recovered_count: usize,
    pub unrecoverable_count: usize,
    pub duration_ms: u64,
}

/// Round-robin background scheduler over [`ScrubWithRecovery`] group configs.
pub struct ScrubDaemon<'a, W: Write> {
    pipeline: ScrubWithRecovery<'a, W>,
    queued_refresh: Option<QueuedRepairRefresh>,
    config: ScrubDaemonConfig,
    metrics: ScrubDaemonMetrics,
    next_group_index: usize,
    pressure: Option<Arc<SystemPressure>>,
    round_number: u64,
    round_started_at: Instant,
    round_groups_scanned: usize,
    round_corrupt: usize,
    round_recovered: usize,
    throttled: bool,
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
    /// Per-group refresh protocol state (dirty tracking + policy).
    refresh_states: BTreeMap<u32, GroupRefreshState>,
    /// Runtime metrics for scrub/decode/refresh activity.
    runtime_metrics: RepairRuntimeMetrics,
    /// Optional thread-safe atomic metrics for concurrent external observation.
    atomic_metrics: Option<RepairPipelineMetrics>,
    /// Authority that makes recovered source blocks durable.
    recovery_writeback: Arc<dyn RecoveryWriteback>,
    /// Whether this pipeline may mutate the device for recovery or symbol refresh.
    repair_writes_enabled: bool,
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
        // Default metadata-critical policy applies to the lowest configured
        // group id (typically the filesystem's primary metadata group).
        let metadata_groups = groups
            .iter()
            .map(|group_cfg| group_cfg.layout.group.0)
            .min()
            .map_or_else(BTreeSet::new, |group| BTreeSet::from([group]));
        let refresh_states = groups
            .iter()
            .map(|group_cfg| {
                let group = group_cfg.layout.group.0;
                let policy = if metadata_groups.contains(&group) {
                    RefreshPolicy::Eager
                } else {
                    RefreshPolicy::Lazy {
                        max_staleness: Duration::from_secs(30),
                    }
                };
                (group, GroupRefreshState::new(policy))
            })
            .collect();

        Self {
            device,
            validator,
            fs_uuid,
            groups,
            ledger: EvidenceLedger::new(ledger_writer),
            repair_symbol_count,
            adaptive_overhead: None,
            metadata_groups,
            policy_decisions: BTreeMap::new(),
            refresh_states,
            runtime_metrics: RepairRuntimeMetrics::default(),
            atomic_metrics: None,
            recovery_writeback: Arc::new(DirectDeviceRecoveryWriteback),
            repair_writes_enabled: true,
        }
    }

    /// Attach thread-safe atomic metrics for concurrent external observation.
    ///
    /// When attached, the pipeline updates these atomics alongside the internal
    /// `RepairRuntimeMetrics` at every instrumentation point. External consumers
    /// (TUI dashboard, monitoring thread) can read the returned clone at any time
    /// without blocking the scrub/recovery hot path.
    #[must_use]
    pub fn with_metrics(mut self, metrics: RepairPipelineMetrics) -> Self {
        self.atomic_metrics = Some(metrics);
        self
    }

    /// Enable or disable repair-side writes.
    ///
    /// Disabling this turns the pipeline into detection-only mode: scrub evidence
    /// and corruption records are still emitted, but recovery and repair-symbol
    /// refresh writes are skipped. This is used by read-only mount integration.
    #[must_use]
    pub fn with_repair_writes_enabled(mut self, enabled: bool) -> Self {
        self.repair_writes_enabled = enabled;
        self
    }

    /// Override the recovered-block writeback authority.
    ///
    /// The default authority writes directly to the supplied block device and
    /// is valid for offline repair and client read-only mount repair. Mounted
    /// read-write repair should provide an authority that stages recovered
    /// blocks through the mounted mutation path before symbol refresh.
    #[must_use]
    pub fn with_recovery_writeback(mut self, writeback: Arc<dyn RecoveryWriteback>) -> Self {
        self.recovery_writeback = writeback;
        self
    }

    /// Returns a clone of the attached atomic metrics, if any.
    #[must_use]
    pub fn atomic_metrics(&self) -> Option<&RepairPipelineMetrics> {
        self.atomic_metrics.as_ref()
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
        self.apply_default_refresh_policies();
        self
    }

    /// Override refresh policy for a single block group.
    #[must_use]
    pub fn with_group_refresh_policy(mut self, group: GroupNumber, policy: RefreshPolicy) -> Self {
        let threshold = match policy {
            RefreshPolicy::Hybrid {
                block_count_threshold,
                ..
            } => Some(block_count_threshold),
            _ => None,
        };
        self.refresh_states
            .entry(group.0)
            .and_modify(|state| {
                state.policy = policy;
                state.block_count_threshold = threshold;
            })
            .or_insert_with(|| {
                let mut s = GroupRefreshState::new(policy);
                s.block_count_threshold = threshold;
                s
            });
        self
    }

    /// Mark a group as dirty without immediately forcing refresh.
    ///
    /// This is used by write-path integrations that batch refresh work until
    /// an explicit flush/scrub boundary.
    pub fn mark_group_dirty(&mut self, group: GroupNumber) -> Result<()> {
        self.mark_group_dirty_with_cause(group, "manual")
    }

    /// Return whether a group is currently marked dirty.
    #[must_use]
    pub fn is_group_dirty(&self, group: GroupNumber) -> bool {
        self.refresh_states
            .get(&group.0)
            .is_some_and(|state| state.dirty)
    }

    /// Return all dirty groups in deterministic order.
    #[must_use]
    pub fn dirty_groups(&self) -> Vec<GroupNumber> {
        self.refresh_states
            .iter()
            .filter_map(|(group, state)| state.dirty.then_some(GroupNumber(*group)))
            .collect()
    }

    /// Build a telemetry snapshot of the refresh state for all tracked groups.
    #[must_use]
    pub fn refresh_telemetry(&self) -> RefreshTelemetry {
        let now = Instant::now();
        let mut groups = Vec::with_capacity(self.refresh_states.len());
        let mut max_dirty_age_ms = 0_u64;
        let mut dirty_count = 0_usize;

        for (&group_id, state) in &self.refresh_states {
            let dirty_age_ms = state
                .dirty_since
                .filter(|_| state.dirty)
                .map_or(0, |since| {
                    u64::try_from(now.saturating_duration_since(since).as_millis())
                        .unwrap_or(u64::MAX)
                });
            if state.dirty {
                dirty_count += 1;
                max_dirty_age_ms = max_dirty_age_ms.max(dirty_age_ms);
            }
            let policy_str = match state.policy {
                RefreshPolicy::Eager => "eager".to_owned(),
                RefreshPolicy::Lazy { max_staleness } => {
                    format!("lazy({}ms)", max_staleness.as_millis())
                }
                RefreshPolicy::Adaptive {
                    risk_threshold,
                    max_staleness,
                } => format!(
                    "adaptive(risk={risk_threshold:.3},max={}ms)",
                    max_staleness.as_millis()
                ),
                RefreshPolicy::Hybrid {
                    max_staleness,
                    block_count_threshold,
                } => format!(
                    "hybrid(age={}ms,blocks={block_count_threshold})",
                    max_staleness.as_millis()
                ),
            };
            groups.push(GroupRefreshSummary {
                group: group_id,
                dirty: state.dirty,
                dirty_age_ms,
                policy: policy_str,
                since_last_refresh_ms: u64::try_from(
                    now.saturating_duration_since(state.last_refresh)
                        .as_millis(),
                )
                .unwrap_or(u64::MAX),
                writes_since_refresh: state.writes_since_refresh,
                block_count_threshold: state.block_count_threshold.unwrap_or(0),
            });
        }

        groups.sort_by_key(|g| g.group);

        RefreshTelemetry {
            tracked_groups: self.refresh_states.len(),
            dirty_groups: dirty_count,
            max_dirty_age_ms,
            groups,
        }
    }

    /// Evaluate the stale-window SLO against current pipeline state.
    ///
    /// If the SLO is breached, emits a `repair_stale_window_slo_breach`
    /// structured log event with the evaluation details.
    #[must_use]
    pub fn evaluate_slo(&self, slo: &StaleWindowSlo) -> SloEvaluation {
        let telemetry = self.refresh_telemetry();
        let eval = slo.evaluate(&telemetry);
        if eval.breached {
            warn!(
                target: "ffs::repair::slo",
                event = "repair_stale_window_slo_breach",
                age_at_percentile_ms = eval.age_at_percentile_ms,
                writes_at_percentile = eval.writes_at_percentile,
                max_age_ms = slo.max_age_ms,
                max_writes = slo.max_writes,
                groups_age_breached = eval.groups_age_breached,
                groups_writes_breached = eval.groups_writes_breached,
                total_groups = eval.total_groups,
                percentile = slo.percentile,
                "stale-window SLO breached"
            );
        }
        eval
    }

    /// JSON-friendly runtime metrics export for repair health/performance.
    #[must_use]
    pub fn runtime_metrics(&self) -> RepairRuntimeMetricsSnapshot {
        self.runtime_metrics.snapshot(&self.refresh_telemetry())
    }

    /// Notify the refresh policy that a write dirtied `group`.
    ///
    /// Eager/adaptive-eager policies will immediately refresh symbols.
    pub fn on_group_write(&mut self, cx: &Cx, group: GroupNumber) -> Result<()> {
        // Increment per-group write counter for block-count staleness tracking.
        if let Some(state) = self.refresh_states.get_mut(&group.0) {
            state.writes_since_refresh = state.writes_since_refresh.saturating_add(1);
            if state.block_count_exceeded() {
                info!(
                    target: "ffs::repair::refresh",
                    group = group.0,
                    writes_since_refresh = state.writes_since_refresh,
                    threshold = state.block_count_threshold.unwrap_or(0),
                    "block_count_threshold_exceeded"
                );
            }
        }
        self.mark_group_dirty_with_cause(group, "write")?;
        if !self.repair_writes_enabled {
            return Ok(());
        }
        self.maybe_refresh_dirty_group(cx, group, true)?;
        Ok(())
    }

    /// Set the block-count threshold for a group.
    ///
    /// When the number of writes since the last refresh exceeds this threshold,
    /// an eager symbol refresh is triggered regardless of the group's time-based
    /// refresh policy.  Set to `None` to disable block-count tracking.
    pub fn set_block_count_threshold(&mut self, group: GroupNumber, threshold: Option<u64>) {
        if let Some(state) = self.refresh_states.get_mut(&group.0) {
            state.block_count_threshold = threshold;
        }
    }

    /// Returns the current write count since last refresh for a group, or `None`
    /// if the group is not tracked.
    #[must_use]
    pub fn writes_since_refresh(&self, group: GroupNumber) -> Option<u64> {
        self.refresh_states
            .get(&group.0)
            .map(|s| s.writes_since_refresh)
    }

    /// Notify the refresh policy that dirty data for `group` reached a flush boundary.
    ///
    /// This is intended for fsync/flush wiring from write-back layers.
    pub fn on_group_flush(&mut self, cx: &Cx, group: GroupNumber) -> Result<()> {
        if !self.repair_writes_enabled {
            return Ok(());
        }
        self.maybe_refresh_dirty_group(cx, group, true)
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
        let groups_count = u64::try_from(self.groups.len()).unwrap_or(u64::MAX);
        self.runtime_metrics.groups_scrubbed = self
            .runtime_metrics
            .groups_scrubbed
            .saturating_add(groups_count);
        if let Some(m) = &self.atomic_metrics {
            m.add_groups_scrubbed(groups_count);
            m.add_blocks_scanned(report.blocks_scanned);
        }
        debug!(
            blocks_scanned = report.blocks_scanned,
            blocks_corrupt = report.blocks_corrupt,
            findings = report.findings.len(),
            "scrub complete"
        );
        self.update_adaptive_policy(&report)?;
        if self.repair_writes_enabled {
            self.refresh_dirty_groups_now(cx)?;
        }
        self.sync_atomic_staleness_gauge();

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
            let summary = if self.repair_writes_enabled {
                self.recover_group(
                    cx,
                    group_cfg,
                    corrupt_blocks,
                    &mut block_outcomes,
                    &mut total_recovered,
                    &mut total_unrecoverable,
                )?
            } else {
                for block in corrupt_blocks {
                    block_outcomes.insert(block.0, BlockOutcome::Unrecoverable);
                }
                total_unrecoverable = total_unrecoverable.saturating_add(corrupt_blocks.len());
                self.observe_corrupt_group(group_cfg.layout.group, corrupt_blocks)?
            };
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

    fn corrupt_blocks_from_report(report: &ScrubReport) -> Vec<BlockNumber> {
        let mut blocks: Vec<BlockNumber> = report
            .findings
            .iter()
            .filter(|finding| finding.severity >= Severity::Error)
            .map(|finding| finding.block)
            .collect();
        blocks.sort_unstable_by_key(|block| block.0);
        blocks.dedup_by_key(|block| block.0);
        blocks
    }

    fn scrub_group_once(
        &mut self,
        cx: &Cx,
        group_cfg: GroupConfig,
    ) -> Result<(ScrubReport, Option<GroupRecoverySummary>)> {
        let group = group_cfg.layout.group;
        let scrubber = Scrubber::new(self.device, self.validator);
        let report = scrubber.scrub_range(
            cx,
            group_cfg.source_first_block,
            u64::from(group_cfg.source_block_count),
        )?;
        self.runtime_metrics.groups_scrubbed =
            self.runtime_metrics.groups_scrubbed.saturating_add(1);
        if let Some(m) = &self.atomic_metrics {
            m.add_groups_scrubbed(1);
            m.add_blocks_scanned(report.blocks_scanned);
        }

        let scrub_record = EvidenceRecord::from_scrub_report(group.0, &report);
        self.ledger.append(&scrub_record).map_err(|e| {
            FfsError::RepairFailed(format!("failed to write scrub-cycle evidence: {e}"))
        })?;

        self.update_adaptive_policy(&report)?;
        if self.repair_writes_enabled {
            self.maybe_refresh_dirty_group(cx, group, false)?;
        }

        let corrupt_blocks = Self::corrupt_blocks_from_report(&report);
        if corrupt_blocks.is_empty() {
            return Ok((report, None));
        }

        if !self.repair_writes_enabled {
            let summary = self.observe_corrupt_group(group, &corrupt_blocks)?;
            return Ok((report, Some(summary)));
        }

        let mut block_outcomes = BTreeMap::new();
        let mut total_recovered = 0_usize;
        let mut total_unrecoverable = 0_usize;
        let summary = self.recover_group(
            cx,
            &group_cfg,
            &corrupt_blocks,
            &mut block_outcomes,
            &mut total_recovered,
            &mut total_unrecoverable,
        )?;
        Ok((report, Some(summary)))
    }

    fn observe_corrupt_group(
        &mut self,
        group: GroupNumber,
        corrupt_blocks: &[BlockNumber],
    ) -> Result<GroupRecoverySummary> {
        self.log_corruption_detected(group, corrupt_blocks)?;
        Ok(GroupRecoverySummary {
            group: group.0,
            corrupt_count: corrupt_blocks.len(),
            recovered_count: 0,
            unrecoverable_count: corrupt_blocks.len(),
            symbols_refreshed: false,
            decoder_stats: None,
        })
    }

    fn apply_default_refresh_policies(&mut self) {
        for group_cfg in &self.groups {
            let group = group_cfg.layout.group.0;
            let policy = if self.metadata_groups.contains(&group) {
                RefreshPolicy::Eager
            } else {
                RefreshPolicy::Lazy {
                    max_staleness: Duration::from_secs(30),
                }
            };
            self.refresh_states
                .entry(group)
                .and_modify(|state| state.policy = policy)
                .or_insert_with(|| GroupRefreshState::new(policy));
        }
    }

    #[must_use]
    fn find_group_config(&self, group: GroupNumber) -> Option<GroupConfig> {
        self.groups
            .iter()
            .copied()
            .find(|cfg| cfg.layout.group == group)
    }

    fn mark_group_dirty_with_cause(
        &mut self,
        group: GroupNumber,
        cause: &'static str,
    ) -> Result<()> {
        let state = self
            .refresh_states
            .get_mut(&group.0)
            .ok_or_else(|| FfsError::Format(format!("group {} not configured", group.0)))?;
        if !state.dirty {
            state.dirty = true;
            state.dirty_since = Some(Instant::now());
        }
        trace!(
            target: "ffs::repair::refresh",
            group = group.0,
            cause,
            policy = ?state.policy,
            dirty = state.dirty,
            "refresh_group_marked_dirty"
        );
        self.sync_atomic_staleness_gauge();
        Ok(())
    }

    fn mark_group_refreshed(&mut self, group: GroupNumber) {
        if let Some(state) = self.refresh_states.get_mut(&group.0) {
            state.dirty = false;
            state.dirty_since = None;
            state.last_refresh = Instant::now();
            state.writes_since_refresh = 0;
        }
        self.sync_atomic_staleness_gauge();
    }

    fn sync_atomic_staleness_gauge(&self) {
        if let Some(metrics) = &self.atomic_metrics {
            let telemetry = self.refresh_telemetry();
            metrics.update_staleness_gauge(&telemetry);
        }
    }

    /// Refresh all currently dirty groups using scrub-trigger semantics.
    pub fn refresh_dirty_groups_now(&mut self, cx: &Cx) -> Result<()> {
        if !self.repair_writes_enabled {
            return Ok(());
        }
        let dirty_groups = self.dirty_groups();
        for group in dirty_groups {
            self.maybe_refresh_dirty_group(cx, group, false)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn maybe_refresh_dirty_group(
        &mut self,
        cx: &Cx,
        group: GroupNumber,
        write_trigger: bool,
    ) -> Result<()> {
        let group_cfg = self
            .find_group_config(group)
            .ok_or_else(|| FfsError::Format(format!("group {} not configured", group.0)))?;

        let Some(state) = self.refresh_states.get(&group.0) else {
            return Ok(());
        };
        if !state.dirty {
            return Ok(());
        }
        let dirty_since = state.dirty_since.unwrap_or_else(Instant::now);
        let policy = state.policy;
        let dirty_age = Instant::now().saturating_duration_since(dirty_since);
        let decision = self.policy_decisions.get(&group.0).copied();

        trace!(
            target: "ffs::repair::refresh",
            group = group.0,
            policy = ?policy,
            dirty = state.dirty,
            dirty_since_ms = dirty_age.as_millis(),
            dirty_age_ms = dirty_age.as_millis(),
            last_refresh_ms = Instant::now()
                .saturating_duration_since(state.last_refresh)
                .as_millis(),
            "refresh_policy_evaluated"
        );

        let refresh_mode = match policy {
            RefreshPolicy::Eager => Some(RefreshMode::EagerWrite),
            RefreshPolicy::Lazy { max_staleness } => {
                if write_trigger {
                    if dirty_age >= max_staleness {
                        warn!(
                            target: "ffs::repair::refresh",
                            group = group.0,
                            dirty_age_ms = dirty_age.as_millis(),
                            max_staleness_ms = max_staleness.as_millis(),
                            "refresh_staleness_timeout_triggered"
                        );
                        Some(RefreshMode::StalenessTimeout)
                    } else {
                        None
                    }
                } else {
                    Some(RefreshMode::LazyScrub)
                }
            }
            RefreshPolicy::Adaptive {
                risk_threshold,
                max_staleness,
            } => {
                let posterior = decision.map_or_else(
                    || {
                        self.adaptive_overhead
                            .map_or(0.0, |autopilot| autopilot.posterior_mean())
                    },
                    |d| d.corruption_posterior,
                );
                debug!(
                    target: "ffs::repair::refresh",
                    group = group.0,
                    policy = ?policy,
                    risk_threshold,
                    posterior_mean = posterior,
                    max_staleness_ms = max_staleness.as_millis(),
                    "adaptive_refresh_policy_resolved"
                );
                if posterior >= risk_threshold {
                    if write_trigger {
                        Some(RefreshMode::AdaptiveEagerWrite)
                    } else {
                        Some(RefreshMode::AdaptiveLazyScrub)
                    }
                } else if write_trigger {
                    if dirty_age >= max_staleness {
                        warn!(
                            target: "ffs::repair::refresh",
                            group = group.0,
                            dirty_age_ms = dirty_age.as_millis(),
                            max_staleness_ms = max_staleness.as_millis(),
                            "refresh_staleness_timeout_triggered"
                        );
                        Some(RefreshMode::StalenessTimeout)
                    } else {
                        None
                    }
                } else {
                    Some(RefreshMode::AdaptiveLazyScrub)
                }
            }
            RefreshPolicy::Hybrid {
                max_staleness,
                block_count_threshold,
            } => {
                if write_trigger {
                    let writes = self
                        .refresh_states
                        .get(&group.0)
                        .map_or(0, |s| s.writes_since_refresh);
                    let age_exceeded = dirty_age >= max_staleness;
                    let count_exceeded = writes >= block_count_threshold;
                    if count_exceeded {
                        debug!(
                            target: "ffs::repair::refresh",
                            group = group.0,
                            writes_since_refresh = writes,
                            block_count_threshold,
                            dirty_age_ms = dirty_age.as_millis(),
                            "hybrid_block_count_triggered"
                        );
                        Some(RefreshMode::HybridBlockCount)
                    } else if age_exceeded {
                        debug!(
                            target: "ffs::repair::refresh",
                            group = group.0,
                            dirty_age_ms = dirty_age.as_millis(),
                            max_staleness_ms = max_staleness.as_millis(),
                            writes_since_refresh = writes,
                            "hybrid_age_triggered"
                        );
                        Some(RefreshMode::HybridAge)
                    } else {
                        None
                    }
                } else {
                    // Scrub trigger always refreshes.
                    Some(RefreshMode::HybridScrub)
                }
            }
        };

        // If policy didn't trigger but block-count threshold is exceeded, force refresh.
        let refresh_mode = refresh_mode.or_else(|| {
            self.refresh_states
                .get(&group.0)
                .filter(|s| s.block_count_exceeded())
                .map(|_| RefreshMode::BlockCountThreshold)
        });

        if let Some(mode) = refresh_mode {
            let refresh_symbol_count = self.selected_refresh_symbol_count(&group_cfg);
            if refresh_symbol_count == 0 {
                return Ok(());
            }
            if let Err(error) = self.refresh_symbols(cx, &group_cfg, refresh_symbol_count, mode) {
                error!(
                    target: "ffs::repair::refresh",
                    group = group.0,
                    refresh_mode = mode.as_str(),
                    error = %error,
                    "refresh_symbols_failed"
                );
                return Err(error);
            }
            self.mark_group_refreshed(group);
        }
        Ok(())
    }

    fn update_adaptive_policy(&mut self, report: &ScrubReport) -> Result<()> {
        self.policy_decisions.clear();

        let Some(mut autopilot) = self.adaptive_overhead else {
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

        let mut decision_cache: BTreeMap<(u32, bool), OverheadDecision> = BTreeMap::new();

        for group_cfg in &self.groups {
            let group = group_cfg.layout.group.0;
            let metadata_group = self.metadata_groups.contains(&group);
            let mut decision = *decision_cache
                .entry((group_cfg.source_block_count, metadata_group))
                .or_insert_with(|| {
                    autopilot.decision_for_group(group_cfg.source_block_count, metadata_group)
                });

            if decision.symbols_selected > group_cfg.layout.repair_block_count {
                let effective_symbols = group_cfg.layout.repair_block_count;
                let source_count = group_cfg.source_block_count.max(1);
                let effective_overhead = f64::from(effective_symbols) / f64::from(source_count);
                decision.symbols_selected = effective_symbols;
                decision.overhead_ratio = effective_overhead;
                decision.risk_bound =
                    autopilot.risk_bound(effective_overhead, group_cfg.source_block_count);
                decision.expected_loss = autopilot.expected_loss_for_group(
                    effective_overhead,
                    group_cfg.source_block_count,
                    decision.metadata_group,
                );
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

        self.adaptive_overhead = Some(autopilot);
        Ok(())
    }

    #[must_use]
    fn selected_refresh_symbol_count(&self, group_cfg: &GroupConfig) -> u32 {
        self.policy_decisions
            .get(&group_cfg.layout.group.0)
            .map_or(self.repair_symbol_count, |decision| {
                decision.symbols_selected
            })
    }

    fn log_repair_attempt(
        &mut self,
        group_cfg: &GroupConfig,
        corrupt_blocks: &[BlockNumber],
    ) -> Result<()> {
        self.runtime_metrics.decode_attempts =
            self.runtime_metrics.decode_attempts.saturating_add(1);
        if let Some(m) = &self.atomic_metrics {
            m.add_decode_attempts(1);
        }
        let attempt_detail = RepairDetail {
            generation: 0,
            corrupt_count: corrupt_blocks.len(),
            symbols_used: 0,
            symbols_available: usize::try_from(group_cfg.layout.repair_block_count)
                .unwrap_or(usize::MAX),
            decoder_stats: RecoveryDecoderStats::default(),
            verify_pass: false,
            reason: None,
        };
        self.ledger
            .append(&EvidenceRecord::repair_attempted(
                group_cfg.layout.group.0,
                attempt_detail,
            ))
            .map_err(|e| FfsError::RepairFailed(format!("failed to write recovery evidence: {e}")))
    }

    fn log_recovery_evidence(&mut self, recovery_result: &RecoveryAttemptResult) -> Result<()> {
        let evidence_record = EvidenceRecord::from_recovery(&recovery_result.evidence);
        self.ledger
            .append(&evidence_record)
            .map_err(|e| FfsError::RepairFailed(format!("failed to write recovery evidence: {e}")))
    }

    fn mark_recovered_blocks(
        block_outcomes: &mut BTreeMap<u64, BlockOutcome>,
        repaired_blocks: &[BlockNumber],
    ) -> usize {
        for block in repaired_blocks {
            block_outcomes.insert(block.0, BlockOutcome::Recovered);
        }
        repaired_blocks.len()
    }

    fn mark_unrecoverable_blocks(
        block_outcomes: &mut BTreeMap<u64, BlockOutcome>,
        blocks: &[BlockNumber],
    ) -> usize {
        for block in blocks {
            block_outcomes.insert(block.0, BlockOutcome::Unrecoverable);
        }
        blocks.len()
    }

    fn mark_remaining_unrecoverable(
        block_outcomes: &mut BTreeMap<u64, BlockOutcome>,
        corrupt_blocks: &[BlockNumber],
        repaired_blocks: &[BlockNumber],
    ) -> usize {
        let repaired_set: BTreeSet<u64> = repaired_blocks.iter().map(|b| b.0).collect();
        let mut unrecoverable = 0;
        for block in corrupt_blocks {
            if !repaired_set.contains(&block.0) {
                block_outcomes.insert(block.0, BlockOutcome::Unrecoverable);
                unrecoverable += 1;
            }
        }
        unrecoverable
    }

    fn refresh_symbols_after_recovery(&mut self, cx: &Cx, group_cfg: &GroupConfig) -> bool {
        let group_num = group_cfg.layout.group;
        let refresh_symbol_count = self.selected_refresh_symbol_count(group_cfg);
        if refresh_symbol_count == 0 {
            return false;
        }

        match self.refresh_symbols(cx, group_cfg, refresh_symbol_count, RefreshMode::Recovery) {
            Ok(()) => {
                self.mark_group_refreshed(group_num);
                info!(
                    target: "ffs::repair::refresh",
                    group = group_num.0,
                    refresh_mode = RefreshMode::Recovery.as_str(),
                    "repair symbols refreshed"
                );
                true
            }
            Err(e) => {
                error!(
                    target: "ffs::repair::refresh",
                    group = group_num.0,
                    refresh_mode = RefreshMode::Recovery.as_str(),
                    error = %e,
                    "failed to refresh repair symbols"
                );
                false
            }
        }
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

        self.log_repair_attempt(group_cfg, corrupt_blocks)?;

        // Attempt recovery.
        let recovery_result = self.attempt_group_recovery(cx, group_cfg, corrupt_blocks);

        // Log recovery evidence.
        self.log_recovery_evidence(&recovery_result)?;

        let (recovered_count, unrecoverable_count, symbols_refreshed) = match recovery_result
            .evidence
            .outcome
        {
            RecoveryOutcome::Recovered => {
                self.runtime_metrics.decode_successes =
                    self.runtime_metrics.decode_successes.saturating_add(1);
                if let Some(m) = &self.atomic_metrics {
                    m.add_decode_successes(1);
                }
                info!(
                    group = group_num.0,
                    blocks_recovered = recovery_result.repaired_blocks.len(),
                    "recovery successful"
                );
                (
                    Self::mark_recovered_blocks(block_outcomes, &recovery_result.repaired_blocks),
                    0,
                    self.refresh_symbols_after_recovery(cx, group_cfg),
                )
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
                (
                    Self::mark_recovered_blocks(block_outcomes, &recovery_result.repaired_blocks),
                    Self::mark_remaining_unrecoverable(
                        block_outcomes,
                        corrupt_blocks,
                        &recovery_result.repaired_blocks,
                    ),
                    false,
                )
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
                (
                    0,
                    Self::mark_unrecoverable_blocks(block_outcomes, corrupt_blocks),
                    false,
                )
            }
        };
        if let Some(m) = &self.atomic_metrics {
            if recovered_count > 0 {
                m.add_blocks_recovered(u64::try_from(recovered_count).unwrap_or(u64::MAX));
            }
            if unrecoverable_count > 0 {
                m.add_blocks_unrecoverable(u64::try_from(unrecoverable_count).unwrap_or(u64::MAX));
            }
        }
        *total_recovered += recovered_count;
        *total_unrecoverable += unrecoverable_count;

        Ok(GroupRecoverySummary {
            group: group_num.0,
            corrupt_count: corrupt_blocks.len(),
            recovered_count,
            unrecoverable_count,
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
        let orchestrator = match GroupRecoveryOrchestrator::new_with_writeback(
            self.device,
            self.recovery_writeback.as_ref(),
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
        mode: RefreshMode,
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
            target: "ffs::repair::refresh",
            group = group_num.0,
            refresh_mode = mode.as_str(),
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

        info!(
            target: "ffs::repair::refresh",
            group = group_num.0,
            refresh_mode = mode.as_str(),
            symbols_generated,
            generation_before = old_gen,
            generation_after = new_gen,
            "refresh_symbols_applied"
        );
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
        self.runtime_metrics.symbol_refresh_count =
            self.runtime_metrics.symbol_refresh_count.saturating_add(1);
        if let Some(m) = &self.atomic_metrics {
            m.add_symbol_refresh_count(1);
        }

        Ok(())
    }

    /// Log corruption detection events for a group.
    fn log_corruption_detected(
        &mut self,
        group: GroupNumber,
        corrupt_blocks: &[BlockNumber],
    ) -> Result<()> {
        let corrupt_count = u64::try_from(corrupt_blocks.len()).unwrap_or(u64::MAX);
        self.runtime_metrics.corruption_detected = self
            .runtime_metrics
            .corruption_detected
            .saturating_add(corrupt_count);
        if let Some(m) = &self.atomic_metrics {
            m.add_corruption_detected(corrupt_count);
        }
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

impl<'a, W: Write> ScrubDaemon<'a, W> {
    /// Create a round-robin scrub daemon over an existing recovery pipeline.
    pub fn new(pipeline: ScrubWithRecovery<'a, W>, config: ScrubDaemonConfig) -> Self {
        Self {
            pipeline,
            queued_refresh: None,
            config,
            metrics: ScrubDaemonMetrics::default(),
            next_group_index: 0,
            pressure: None,
            round_number: 0,
            round_started_at: Instant::now(),
            round_groups_scanned: 0,
            round_corrupt: 0,
            round_recovered: 0,
            throttled: false,
        }
    }

    /// Attach queued flush lifecycle integration for daemon-driven refreshes.
    #[must_use]
    pub fn with_queued_refresh(mut self, queued_refresh: QueuedRepairRefresh) -> Self {
        self.queued_refresh = Some(queued_refresh);
        self
    }

    /// Attach shared system pressure for backpressure-aware yielding.
    #[must_use]
    pub fn with_pressure(mut self, pressure: Arc<SystemPressure>) -> Self {
        self.pressure = Some(pressure);
        self
    }

    /// Current daemon counters.
    #[must_use]
    pub fn metrics(&self) -> &ScrubDaemonMetrics {
        &self.metrics
    }

    /// Returns a reference to the attached atomic metrics, if any.
    #[must_use]
    pub fn atomic_metrics(&self) -> Option<&RepairPipelineMetrics> {
        self.pipeline.atomic_metrics()
    }

    /// JSON-friendly runtime metrics export for repair pipeline activity.
    #[must_use]
    pub fn runtime_metrics(&self) -> RepairRuntimeMetricsSnapshot {
        self.pipeline.runtime_metrics()
    }

    /// Consume the daemon and return the inner pipeline + final metrics.
    #[must_use]
    pub fn into_parts(self) -> (ScrubWithRecovery<'a, W>, ScrubDaemonMetrics) {
        (self.pipeline, self.metrics)
    }

    /// Consume the daemon and return only the inner pipeline.
    #[must_use]
    pub fn into_pipeline(self) -> ScrubWithRecovery<'a, W> {
        self.pipeline
    }

    /// Execute one daemon tick (apply queued refreshes, then scan one group).
    #[allow(clippy::too_many_lines)]
    pub fn run_once(&mut self, cx: &Cx) -> Result<ScrubDaemonStep> {
        if self.pipeline.groups.is_empty() {
            return Err(FfsError::RepairFailed(
                "scrub daemon requires at least one group".to_owned(),
            ));
        }

        if self.next_group_index == 0 {
            self.round_number = self.round_number.saturating_add(1);
            self.round_started_at = Instant::now();
            self.round_groups_scanned = 0;
            self.round_corrupt = 0;
            self.round_recovered = 0;
            debug!(
                target: "ffs::repair::daemon",
                round_number = self.round_number,
                starting_group = self.pipeline.groups[0].layout.group.0,
                "scrub_round_start"
            );
        }

        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;

        if let Some(queue) = &self.queued_refresh {
            let refreshed = queue.apply_queued_refreshes(cx, &mut self.pipeline)?;
            if refreshed > 0 {
                debug!(
                    target: "ffs::repair::daemon",
                    refreshed_groups = refreshed,
                    "scrub_daemon_applied_queued_refreshes"
                );
            }
        }

        let group_cfg = self.pipeline.groups[self.next_group_index];
        let group = group_cfg.layout.group;
        self.maybe_backpressure_yield(cx, group)?;
        trace!(
            target: "ffs::repair::daemon",
            group_id = group.0,
            "group_scan_start"
        );

        let started = Instant::now();
        let (report, summary) = self.pipeline.scrub_group_once(cx, group_cfg)?;
        let elapsed = started.elapsed();
        let duration_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);

        let corrupt_count = summary.as_ref().map_or(0, |s| s.corrupt_count);
        let recovered_count = summary.as_ref().map_or(0, |s| s.recovered_count);
        let unrecoverable_count = summary.as_ref().map_or(0, |s| s.unrecoverable_count);

        trace!(
            target: "ffs::repair::daemon",
            group_id = group.0,
            duration_ms,
            blocks_scanned = report.blocks_scanned,
            errors_found = report.findings.len(),
            "group_scan_complete"
        );

        self.metrics.current_group = group.0;
        self.metrics.blocks_scanned_total = self
            .metrics
            .blocks_scanned_total
            .saturating_add(report.blocks_scanned);
        self.metrics.blocks_corrupt_found = self
            .metrics
            .blocks_corrupt_found
            .saturating_add(u64::try_from(corrupt_count).unwrap_or(u64::MAX));
        self.metrics.blocks_recovered = self
            .metrics
            .blocks_recovered
            .saturating_add(u64::try_from(recovered_count).unwrap_or(u64::MAX));
        self.metrics.blocks_unrecoverable = self
            .metrics
            .blocks_unrecoverable
            .saturating_add(u64::try_from(unrecoverable_count).unwrap_or(u64::MAX));
        self.metrics.scrub_rate_blocks_per_sec = if elapsed.is_zero() {
            0.0
        } else {
            report.blocks_scanned as f64 / elapsed.as_secs_f64()
        };

        self.round_groups_scanned = self.round_groups_scanned.saturating_add(1);
        self.round_corrupt = self.round_corrupt.saturating_add(corrupt_count);
        self.round_recovered = self.round_recovered.saturating_add(recovered_count);

        self.next_group_index += 1;
        if self.next_group_index >= self.pipeline.groups.len() {
            self.next_group_index = 0;
            self.metrics.scrub_rounds_completed =
                self.metrics.scrub_rounds_completed.saturating_add(1);
            if let Some(m) = self.pipeline.atomic_metrics.as_ref() {
                m.add_scrub_rounds_completed(1);
                let telemetry = self.pipeline.refresh_telemetry();
                m.update_staleness_gauge(&telemetry);
            }
            info!(
                target: "ffs::repair::daemon",
                round_number = self.round_number,
                duration_secs = self.round_started_at.elapsed().as_secs_f64(),
                groups_scanned = self.round_groups_scanned,
                total_corrupt = self.round_corrupt,
                total_recovered = self.round_recovered,
                "scrub_round_complete"
            );
        }

        Ok(ScrubDaemonStep {
            group: group.0,
            blocks_scanned: report.blocks_scanned,
            corrupt_count,
            recovered_count,
            unrecoverable_count,
            duration_ms,
        })
    }

    /// Execute one full round (all configured groups exactly once).
    pub fn run_one_round(&mut self, cx: &Cx) -> Result<()> {
        let total_groups = self.pipeline.groups.len();
        for _ in 0..total_groups {
            self.run_once(cx)?;
        }
        Ok(())
    }

    /// Run continuously until cancellation is requested.
    pub fn run_until_cancelled(&mut self, cx: &Cx) -> Result<ScrubDaemonMetrics> {
        info!(
            target: "ffs::repair::daemon",
            total_groups = self.pipeline.groups.len(),
            interval_secs = self.config.interval.as_secs_f64(),
            budget_poll_quota_threshold = self.config.budget_poll_quota_threshold,
            backpressure_threshold = self.config.backpressure_headroom_threshold,
            "scrub_daemon_start"
        );

        loop {
            if cx.checkpoint().is_err() {
                info!(
                    target: "ffs::repair::daemon",
                    reason = "cancelled",
                    blocks_scanned_total = self.metrics.blocks_scanned_total,
                    blocks_corrupt_found = self.metrics.blocks_corrupt_found,
                    blocks_recovered = self.metrics.blocks_recovered,
                    blocks_unrecoverable = self.metrics.blocks_unrecoverable,
                    scrub_rounds_completed = self.metrics.scrub_rounds_completed,
                    "scrub_daemon_stop"
                );
                return Ok(self.metrics.clone());
            }

            let tick_started = Instant::now();
            match self.run_once(cx) {
                Ok(_) => {}
                Err(FfsError::Cancelled) => {
                    info!(
                        target: "ffs::repair::daemon",
                        reason = "cancelled",
                        blocks_scanned_total = self.metrics.blocks_scanned_total,
                        blocks_corrupt_found = self.metrics.blocks_corrupt_found,
                        blocks_recovered = self.metrics.blocks_recovered,
                        blocks_unrecoverable = self.metrics.blocks_unrecoverable,
                        scrub_rounds_completed = self.metrics.scrub_rounds_completed,
                        "scrub_daemon_stop"
                    );
                    return Ok(self.metrics.clone());
                }
                Err(err) => return Err(err),
            }

            let tick_elapsed = tick_started.elapsed();
            let idle = self.config.interval.saturating_sub(tick_elapsed);
            if let Err(err) = self.sleep_with_checkpoint(cx, idle) {
                if matches!(err, FfsError::Cancelled) {
                    info!(
                        target: "ffs::repair::daemon",
                        reason = "cancelled",
                        blocks_scanned_total = self.metrics.blocks_scanned_total,
                        blocks_corrupt_found = self.metrics.blocks_corrupt_found,
                        blocks_recovered = self.metrics.blocks_recovered,
                        blocks_unrecoverable = self.metrics.blocks_unrecoverable,
                        scrub_rounds_completed = self.metrics.scrub_rounds_completed,
                        "scrub_daemon_stop"
                    );
                    return Ok(self.metrics.clone());
                }
                return Err(err);
            }
        }
    }

    fn maybe_backpressure_yield(&mut self, cx: &Cx, group: GroupNumber) -> Result<()> {
        let budget = cx.budget();
        let budget_remaining = budget.poll_quota;
        if budget.is_exhausted() || budget_remaining <= self.config.budget_poll_quota_threshold {
            let yield_duration = self.config.budget_sleep;
            self.metrics.backpressure_yields = self.metrics.backpressure_yields.saturating_add(1);
            debug!(
                target: "ffs::repair::daemon",
                daemon_name = "scrub_daemon",
                current_group = group.0,
                budget_remaining,
                yield_duration_ms = yield_duration.as_millis(),
                pressure_level = "budget",
                "daemon_throttled"
            );
            self.throttled = true;
            return self.sleep_with_checkpoint(cx, yield_duration);
        }

        if let Some(pressure) = self.pressure.as_ref() {
            let headroom = pressure.headroom();
            if headroom < self.config.backpressure_headroom_threshold {
                let yield_duration = self.config.backpressure_sleep;
                self.metrics.backpressure_yields =
                    self.metrics.backpressure_yields.saturating_add(1);
                debug!(
                    target: "ffs::repair::daemon",
                    daemon_name = "scrub_daemon",
                    current_group = group.0,
                    pressure_source = pressure.level_label(),
                    headroom,
                    budget_remaining,
                    yield_duration_ms = yield_duration.as_millis(),
                    pressure_level = "system",
                    "daemon_throttled"
                );
                self.throttled = true;
                return self.sleep_with_checkpoint(cx, yield_duration);
            }
        }

        if self.throttled {
            debug!(
                target: "ffs::repair::daemon",
                daemon_name = "scrub_daemon",
                new_budget = budget_remaining,
                "daemon_resumed"
            );
            self.throttled = false;
        }
        Ok(())
    }

    fn sleep_with_checkpoint(&self, cx: &Cx, duration: Duration) -> Result<()> {
        if duration.is_zero() {
            return Ok(());
        }

        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let budget = cx.budget();
        let now = cx.now();
        if budget.is_past_deadline(now)
            || budget
                .remaining_time(now)
                .is_some_and(|remaining| remaining <= duration)
        {
            return Err(FfsError::Cancelled);
        }

        let mut remaining = duration;
        while !remaining.is_zero() {
            let slice = remaining.min(self.config.cancel_check_interval);
            let budget = cx.budget();
            let now = cx.now();
            if budget.is_past_deadline(now)
                || budget
                    .remaining_time(now)
                    .is_some_and(|remaining_time| remaining_time <= slice)
            {
                return Err(FfsError::Cancelled);
            }
            std::thread::sleep(slice);
            remaining = remaining.saturating_sub(slice);
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autopilot::DurabilityAutopilot;
    use crate::codec::encode_group;
    use crate::evidence::{EvidenceEventType, EvidenceRecord};
    use crate::scrub::{BlockVerdict, CorruptionKind, Ext4SuperblockValidator, Severity};
    use crate::symbol::RepairGroupDescExt;
    use ffs_block::{ArcCache, ArcWritePolicy, BlockBuf, RepairFlushLifecycle};
    use ffs_ondisk::{Ext4IncompatFeatures, Ext4RoCompatFeatures};
    use ffs_types::{
        EXT4_SB_CHECKSUM_OFFSET, EXT4_SUPER_MAGIC, EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE,
    };
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default)]
    struct RecordingRecoveryWriteback {
        blocks: Mutex<Vec<BlockNumber>>,
        expected_current: Mutex<Vec<(BlockNumber, Vec<u8>)>>,
    }

    impl RecoveryWriteback for RecordingRecoveryWriteback {
        fn writeback_recovered(
            &self,
            cx: &Cx,
            device: &dyn BlockDevice,
            recovered: &[crate::recovery::RecoveryWritebackBlock<'_>],
        ) -> Result<()> {
            for block in recovered {
                device.write_block(cx, block.block, block.data)?;
                self.blocks
                    .lock()
                    .map_err(|_| FfsError::RepairFailed("recording writeback lock".to_owned()))?
                    .push(block.block);
                self.expected_current
                    .lock()
                    .map_err(|_| {
                        FfsError::RepairFailed("recording expected-current lock".to_owned())
                    })?
                    .push((block.block, block.expected_current.to_vec()));
            }
            device.sync(cx)?;
            Ok(())
        }

        fn authority_name(&self) -> &'static str {
            "recording_mounted_mutation_path"
        }
    }

    #[derive(Debug)]
    struct RejectingRecoveryWriteback;

    impl RecoveryWriteback for RejectingRecoveryWriteback {
        fn writeback_recovered(
            &self,
            _cx: &Cx,
            _device: &dyn BlockDevice,
            _recovered: &[crate::recovery::RecoveryWritebackBlock<'_>],
        ) -> Result<()> {
            Err(FfsError::RepairFailed(
                "mounted mutation path rejected stale repair snapshot".to_owned(),
            ))
        }

        fn authority_name(&self) -> &'static str {
            "rejecting_mounted_mutation_path"
        }
    }

    const E2E_GROUP_COUNT: u32 = 20;
    const E2E_GROUP_BLOCK_COUNT: u32 = 64;
    const E2E_SOURCE_BLOCK_COUNT: u32 = 20;
    const E2E_REPAIR_SYMBOL_COUNT: u32 = 8;
    const E2E_CORRUPTION_PERCENT: u64 = 5;
    const E2E_SEED: u64 = 0x05ee_df00_dd15_ca11;

    struct RepairE2eFixture {
        device: MemBlockDevice,
        groups: Vec<GroupConfig>,
        source_blocks: Vec<u64>,
        corrupt_blocks: Vec<u64>,
        before_hashes: BTreeMap<u64, String>,
    }

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

    fn make_valid_ext4_superblock_region() -> [u8; EXT4_SUPERBLOCK_SIZE] {
        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
        sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes()); // magic
        sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes()); // 4KiB blocks
        sb[0x1C..0x20].copy_from_slice(&2_u32.to_le_bytes()); // 4KiB clusters
        sb[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_count
        sb[0x04..0x08].copy_from_slice(&32768_u32.to_le_bytes()); // blocks_count_lo
        sb[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes()); // first_data_block
        sb[0x20..0x24].copy_from_slice(&32768_u32.to_le_bytes()); // blocks_per_group
        sb[0x24..0x28].copy_from_slice(&32768_u32.to_le_bytes()); // clusters_per_group
        sb[0x28..0x2C].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_per_group
        sb[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size
        let incompat =
            (Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0).to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);
        sb[0x64..0x68].copy_from_slice(&Ext4RoCompatFeatures::METADATA_CSUM.0.to_le_bytes());
        sb[0x175] = 1; // checksum_type=crc32c

        let checksum = ffs_ondisk::ext4_chksum(!0_u32, &sb[..EXT4_SB_CHECKSUM_OFFSET]);
        sb[EXT4_SB_CHECKSUM_OFFSET..EXT4_SB_CHECKSUM_OFFSET + 4]
            .copy_from_slice(&checksum.to_le_bytes());
        sb
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
        bootstrap_storage_result(
            cx,
            device,
            layout,
            source_first_block,
            source_block_count,
            repair_symbol_count,
        )
        .expect("bootstrap storage")
    }

    fn bootstrap_storage_result(
        cx: &Cx,
        device: &MemBlockDevice,
        layout: RepairGroupLayout,
        source_first_block: BlockNumber,
        source_block_count: u32,
        repair_symbol_count: u32,
    ) -> Result<usize> {
        let encoded = encode_group(
            cx,
            device,
            &test_uuid(),
            layout.group,
            source_first_block,
            source_block_count,
            repair_symbol_count,
        )?;

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
        storage.write_group_desc_ext(cx, &desc)?;

        let symbols = encoded
            .repair_symbols
            .into_iter()
            .map(|s| (s.esi, s.data))
            .collect::<Vec<_>>();
        storage.write_repair_symbols(cx, &symbols, 1)?;
        Ok(symbols.len())
    }

    fn read_generation(cx: &Cx, device: &MemBlockDevice, layout: RepairGroupLayout) -> u64 {
        let storage = RepairGroupStorage::new(device, layout);
        storage
            .read_group_desc_ext(cx)
            .expect("read group desc")
            .repair_generation
    }

    fn policy_decision_fixture(
        symbols_selected: u32,
        corruption_posterior: f64,
    ) -> OverheadDecision {
        OverheadDecision {
            overhead_ratio: 0.05,
            corruption_posterior,
            posterior_alpha: 1.0,
            posterior_beta: 100.0,
            risk_bound: 1e-6,
            expected_loss: 10.0,
            symbols_selected,
            metadata_group: false,
        }
    }

    fn splitmix64(mut x: u64) -> u64 {
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        x ^ (x >> 31)
    }

    fn block_hashes(cx: &Cx, device: &MemBlockDevice, blocks: &[u64]) -> BTreeMap<u64, String> {
        let mut hashes = BTreeMap::new();
        for &block in blocks {
            let bytes = device.read_block(cx, BlockNumber(block)).expect("read");
            let digest = blake3::hash(bytes.as_slice()).to_hex().to_string();
            hashes.insert(block, digest);
        }
        hashes
    }

    fn maybe_write_repair_e2e_artifacts(
        before: &BTreeMap<u64, String>,
        after: &BTreeMap<u64, String>,
        corrupt_blocks: &[u64],
        ledger_data: &[u8],
        seed: u64,
        corruption_percent: u64,
    ) {
        let before_body = before
            .iter()
            .map(|(block, digest)| format!("{block} {digest}"))
            .collect::<Vec<_>>()
            .join("\n");
        let before_payload = format!("{before_body}\n");

        let after_body = after
            .iter()
            .map(|(block, digest)| format!("{block} {digest}"))
            .collect::<Vec<_>>()
            .join("\n");
        let after_payload = format!("{after_body}\n");

        let corruption_plan = serde_json::json!({
            "seed": seed,
            "corruption_percent": corruption_percent,
            "total_corrupted_blocks": corrupt_blocks.len(),
            "corrupted_blocks": corrupt_blocks,
        });
        let corruption_plan_payload =
            serde_json::to_string_pretty(&corruption_plan).expect("serialize corruption plan");
        let ledger_payload = String::from_utf8_lossy(ledger_data).into_owned();

        if std::env::var("FFS_REPAIR_E2E_ARTIFACT_STDOUT").as_deref() == Ok("1") {
            for (name, payload) in [
                ("before_checksums.txt", before_payload.as_str()),
                ("after_checksums.txt", after_payload.as_str()),
                ("corruption_plan.json", corruption_plan_payload.as_str()),
                ("recovery_evidence.jsonl", ledger_payload.as_str()),
            ] {
                println!(
                    "FFS_REPAIR_E2E_ARTIFACT|name={name}|json={}",
                    serde_json::to_string(payload).expect("serialize stdout artifact")
                );
            }
        }

        if let Ok(dir) = std::env::var("FFS_REPAIR_E2E_ARTIFACT_DIR") {
            let dir_path = std::path::Path::new(&dir);
            std::fs::create_dir_all(dir_path).expect("create artifact dir");

            std::fs::write(dir_path.join("before_checksums.txt"), &before_payload)
                .expect("write before checksums");
            std::fs::write(dir_path.join("after_checksums.txt"), &after_payload)
                .expect("write after checksums");
            std::fs::write(
                dir_path.join("corruption_plan.json"),
                &corruption_plan_payload,
            )
            .expect("write corruption plan");
            std::fs::write(dir_path.join("recovery_evidence.jsonl"), ledger_data)
                .expect("write recovery evidence");
        }
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

    fn inject_corruption_blocks(cx: &Cx, device: &MemBlockDevice, blocks: &[u64]) {
        for &block in blocks {
            let mut bytes = device
                .read_block(cx, BlockNumber(block))
                .expect("read source block")
                .as_slice()
                .to_vec();
            let last = bytes.len().saturating_sub(1);
            bytes[0] ^= 0xA5;
            bytes[last] ^= 0x5A;
            device
                .write_block(cx, BlockNumber(block), &bytes)
                .expect("inject corruption");
        }
    }

    fn build_repair_e2e_fixture(cx: &Cx) -> RepairE2eFixture {
        let total_blocks = u64::from(E2E_GROUP_COUNT) * u64::from(E2E_GROUP_BLOCK_COUNT);
        let device = MemBlockDevice::new(1024, total_blocks);

        let mut groups = Vec::new();
        let mut source_blocks = Vec::new();
        for group in 0..E2E_GROUP_COUNT {
            let group_first = u64::from(group) * u64::from(E2E_GROUP_BLOCK_COUNT);
            let layout = RepairGroupLayout::new(
                GroupNumber(group),
                BlockNumber(group_first),
                E2E_GROUP_BLOCK_COUNT,
                0,
                E2E_REPAIR_SYMBOL_COUNT,
            )
            .expect("layout");
            let source_first = BlockNumber(group_first);

            write_source_blocks(cx, &device, source_first, E2E_SOURCE_BLOCK_COUNT);
            bootstrap_storage(
                cx,
                &device,
                layout,
                source_first,
                E2E_SOURCE_BLOCK_COUNT,
                E2E_REPAIR_SYMBOL_COUNT,
            );

            groups.push(GroupConfig {
                layout,
                source_first_block: source_first,
                source_block_count: E2E_SOURCE_BLOCK_COUNT,
            });
            for idx in 0..u64::from(E2E_SOURCE_BLOCK_COUNT) {
                source_blocks.push(group_first + idx);
            }
        }

        let target_corrupt = (source_blocks.len()
            * usize::try_from(E2E_CORRUPTION_PERCENT).expect("percent fits"))
            / 100;
        assert_eq!(
            target_corrupt,
            usize::try_from(E2E_GROUP_COUNT).expect("group count fits")
        );

        let mut corrupt_blocks = Vec::with_capacity(target_corrupt);
        for group in 0..E2E_GROUP_COUNT {
            let group_first = u64::from(group) * u64::from(E2E_GROUP_BLOCK_COUNT);
            let offset =
                splitmix64(E2E_SEED ^ u64::from(group)) % u64::from(E2E_SOURCE_BLOCK_COUNT);
            corrupt_blocks.push(group_first + offset);
        }

        let before_hashes = block_hashes(cx, &device, &source_blocks);
        inject_corruption_blocks(cx, &device, &corrupt_blocks);

        RepairE2eFixture {
            device,
            groups,
            source_blocks,
            corrupt_blocks,
            before_hashes,
        }
    }

    fn assert_repair_e2e_evidence(ledger_data: &[u8], expected_repairs: usize) {
        let records = crate::evidence::parse_evidence_ledger(ledger_data);
        assert_ledger_self_consistency(&records);
        let corruption_detected = count_event(&records, EvidenceEventType::CorruptionDetected);
        let repair_attempted = count_event(&records, EvidenceEventType::RepairAttempted);
        let repair_succeeded = count_event(&records, EvidenceEventType::RepairSucceeded);
        let repair_failed = count_event(&records, EvidenceEventType::RepairFailed);
        let scrub_cycle_complete = count_event(&records, EvidenceEventType::ScrubCycleComplete);

        assert_eq!(corruption_detected, expected_repairs);
        assert_eq!(repair_attempted, expected_repairs);
        assert_eq!(repair_succeeded, expected_repairs);
        assert_eq!(repair_failed, 0);
        assert_eq!(scrub_cycle_complete, expected_repairs);

        let mut corrupt_by_group: HashMap<u32, u64> = HashMap::new();
        let mut scanned_by_group: HashMap<u32, u64> = HashMap::new();
        for record in &records {
            match record.event_type {
                EvidenceEventType::CorruptionDetected => {
                    let detail = record.corruption.as_ref().expect("corruption detail");
                    corrupt_by_group
                        .entry(record.block_group)
                        .and_modify(|count| *count += u64::from(detail.blocks_affected))
                        .or_insert_with(|| u64::from(detail.blocks_affected));
                }
                EvidenceEventType::ScrubCycleComplete => {
                    let detail = record.scrub_cycle.as_ref().expect("scrub-cycle detail");
                    scanned_by_group
                        .entry(record.block_group)
                        .and_modify(|count| *count += detail.blocks_scanned)
                        .or_insert(detail.blocks_scanned);
                }
                _ => {}
            }
        }

        for (group, corrupt_blocks) in &corrupt_by_group {
            let scanned = scanned_by_group.get(group).copied().unwrap_or_default();
            assert!(
                scanned >= *corrupt_blocks,
                "group {group}: scrub blocks_scanned ({scanned}) is less than corrupt blocks ({corrupt_blocks})"
            );
        }
    }

    fn count_event(records: &[EvidenceRecord], event_type: EvidenceEventType) -> usize {
        records
            .iter()
            .filter(|record| record.event_type == event_type)
            .count()
    }

    fn assert_ledger_self_consistency(records: &[EvidenceRecord]) {
        let mut seen = HashSet::new();
        let mut attempts_by_group: HashMap<u32, usize> = HashMap::new();
        let mut terminal_by_group: HashMap<u32, usize> = HashMap::new();
        let mut corruption_by_group: HashMap<u32, u64> = HashMap::new();
        let mut scrub_scanned_by_group: HashMap<u32, u64> = HashMap::new();

        for window in records.windows(2) {
            let previous = &window[0];
            let current = &window[1];
            assert!(
                previous.timestamp_ns <= current.timestamp_ns,
                "ledger timestamps are not monotonic: prev={} current={}",
                previous.timestamp_ns,
                current.timestamp_ns
            );
        }

        for record in records {
            let unique_key = (
                record.event_type,
                record.block_group,
                record.block_range,
                record.timestamp_ns,
            );
            assert!(
                seen.insert(unique_key),
                "duplicate ledger record key: event={:?} group={} range={:?} ts={}",
                record.event_type,
                record.block_group,
                record.block_range,
                record.timestamp_ns
            );

            match record.event_type {
                EvidenceEventType::CorruptionDetected => {
                    let detail = record.corruption.as_ref().expect("corruption detail");
                    corruption_by_group
                        .entry(record.block_group)
                        .and_modify(|count| *count += u64::from(detail.blocks_affected))
                        .or_insert_with(|| u64::from(detail.blocks_affected));
                }
                EvidenceEventType::RepairAttempted => {
                    attempts_by_group
                        .entry(record.block_group)
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                }
                EvidenceEventType::RepairSucceeded | EvidenceEventType::RepairFailed => {
                    terminal_by_group
                        .entry(record.block_group)
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                }
                EvidenceEventType::ScrubCycleComplete => {
                    let detail = record.scrub_cycle.as_ref().expect("scrub-cycle detail");
                    scrub_scanned_by_group
                        .entry(record.block_group)
                        .and_modify(|count| *count += detail.blocks_scanned)
                        .or_insert(detail.blocks_scanned);
                }
                _ => {}
            }
        }

        for (group, attempts) in &attempts_by_group {
            let terminal = terminal_by_group.get(group).copied().unwrap_or_default();
            assert!(
                terminal >= *attempts,
                "group {group}: repair attempts ({attempts}) exceed terminal outcomes ({terminal})"
            );
        }

        for (group, corrupt_blocks) in &corruption_by_group {
            let attempts = attempts_by_group.get(group).copied().unwrap_or_default();
            assert!(
                attempts > 0,
                "group {group}: corruption detected ({corrupt_blocks} blocks) but no repair attempt"
            );
            if let Some(scanned) = scrub_scanned_by_group.get(group).copied() {
                assert!(
                    scanned == 0 || scanned >= *corrupt_blocks,
                    "group {group}: scrub blocks_scanned ({scanned}) is less than corrupt blocks ({corrupt_blocks})"
                );
            }
        }
    }

    fn assert_group_event_coverage(records: &[EvidenceRecord], corrupt_blocks: &[u64]) {
        let expected_groups: HashSet<u32> = corrupt_blocks
            .iter()
            .map(|block| {
                u32::try_from(*block / u64::from(E2E_GROUP_BLOCK_COUNT)).expect("group fits u32")
            })
            .collect();
        for group in expected_groups {
            assert_eq!(
                records
                    .iter()
                    .filter(|record| {
                        record.block_group == group
                            && record.event_type == EvidenceEventType::CorruptionDetected
                    })
                    .count(),
                1,
                "group {group} expected one CorruptionDetected"
            );
            assert_eq!(
                records
                    .iter()
                    .filter(|record| {
                        record.block_group == group
                            && record.event_type == EvidenceEventType::RepairAttempted
                    })
                    .count(),
                1,
                "group {group} expected one RepairAttempted"
            );
            assert_eq!(
                records
                    .iter()
                    .filter(|record| {
                        record.block_group == group
                            && record.event_type == EvidenceEventType::RepairSucceeded
                    })
                    .count(),
                1,
                "group {group} expected one RepairSucceeded"
            );
            assert_eq!(
                records
                    .iter()
                    .filter(|record| {
                        record.block_group == group
                            && record.event_type == EvidenceEventType::ScrubCycleComplete
                    })
                    .count(),
                1,
                "group {group} expected one ScrubCycleComplete"
            );
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

        let records = crate::evidence::parse_evidence_ledger(pipeline.into_ledger());
        assert_ledger_self_consistency(&records);
        assert_eq!(
            count_event(&records, EvidenceEventType::CorruptionDetected),
            1
        );
        assert_eq!(count_event(&records, EvidenceEventType::RepairAttempted), 1);
        assert_eq!(count_event(&records, EvidenceEventType::RepairSucceeded), 1);
        assert_eq!(count_event(&records, EvidenceEventType::RepairFailed), 0);
    }

    #[test]
    fn ext4_superblock_corruption_recovered_and_logged() {
        let cx = Cx::for_testing();
        let block_size = 4096;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 8).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        let mut originals = write_source_blocks(&cx, &device, source_first, source_count);
        let mut block0 = originals[0].clone();
        let superblock = make_valid_ext4_superblock_region();
        block0[EXT4_SUPERBLOCK_OFFSET..EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_SIZE]
            .copy_from_slice(&superblock);
        device
            .write_block(&cx, source_first, &block0)
            .expect("write ext4 superblock block");
        originals[0] = block0.clone();

        bootstrap_storage(&cx, &device, layout, source_first, source_count, 8);

        let mut corrupted = block0;
        corrupted[EXT4_SUPERBLOCK_OFFSET + 0x50] ^= 0x01; // invalidate checksum
        device
            .write_block(&cx, source_first, &corrupted)
            .expect("inject superblock corruption");

        let validator = Ext4SuperblockValidator::new(block_size);
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
        assert!(report.is_fully_recovered(), "{report:?}");
        assert_eq!(report.total_corrupt, 1);
        assert_eq!(report.total_recovered, 1);
        assert_eq!(report.total_unrecoverable, 0);
        assert_eq!(
            report.block_outcomes.get(&0),
            Some(&BlockOutcome::Recovered)
        );

        let repaired_block = device
            .read_block(&cx, source_first)
            .expect("read repaired block");
        let repaired_region = &repaired_block.as_slice()
            [EXT4_SUPERBLOCK_OFFSET..EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_SIZE];
        assert_eq!(repaired_region, superblock.as_slice());
        assert_eq!(
            repaired_block.as_slice(),
            originals[0].as_slice(),
            "source block should be byte-identical after repair"
        );

        let records = crate::evidence::parse_evidence_ledger(pipeline.into_ledger());
        assert_ledger_self_consistency(&records);
        assert_eq!(
            count_event(&records, EvidenceEventType::CorruptionDetected),
            1
        );
        assert_eq!(count_event(&records, EvidenceEventType::RepairAttempted), 1);
        assert_eq!(count_event(&records, EvidenceEventType::RepairSucceeded), 1);
        assert_eq!(count_event(&records, EvidenceEventType::RepairFailed), 0);

        let corruption = records
            .iter()
            .find(|record| record.event_type == EvidenceEventType::CorruptionDetected)
            .and_then(|record| record.corruption.as_ref())
            .expect("corruption detail");
        assert_eq!(corruption.blocks_affected, 1);
        assert!(
            corruption.detail.contains('0'),
            "expected corruption detail to mention block 0, got: {}",
            corruption.detail
        );
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
    fn recovery_uses_configured_writeback_authority() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        let originals = write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);
        device
            .write_block(&cx, BlockNumber(3), &vec![0xAA; block_size as usize])
            .expect("inject corruption");

        let validator = CorruptBlockValidator::new(vec![3]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let writeback = Arc::new(RecordingRecoveryWriteback::default());
        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        )
        .with_recovery_writeback(writeback.clone());

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");

        assert!(report.is_fully_recovered());
        assert_eq!(
            writeback
                .blocks
                .lock()
                .expect("recording writeback lock")
                .as_slice(),
            &[BlockNumber(3)]
        );
        assert_eq!(
            writeback
                .expected_current
                .lock()
                .expect("recording expected-current lock")
                .as_slice(),
            &[(BlockNumber(3), vec![0xAA; block_size as usize])]
        );
        let restored = device.read_block(&cx, BlockNumber(3)).expect("read");
        assert_eq!(restored.as_slice(), originals[3].as_slice());
    }

    #[test]
    fn recovery_writeback_rejection_fails_closed_without_symbol_refresh() {
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
            .write_block(&cx, BlockNumber(3), &vec![0xAA; block_size as usize])
            .expect("inject corruption");

        let validator = CorruptBlockValidator::new(vec![3]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        )
        .with_recovery_writeback(Arc::new(RejectingRecoveryWriteback));
        let mut pipeline = pipeline;

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        let records = crate::evidence::parse_evidence_ledger(pipeline.into_ledger());

        assert!(!report.is_fully_recovered());
        assert_eq!(report.total_unrecoverable, 1);
        assert_eq!(count_event(&records, EvidenceEventType::RepairSucceeded), 0);
        assert_eq!(count_event(&records, EvidenceEventType::RepairFailed), 1);
        assert_eq!(count_event(&records, EvidenceEventType::SymbolRefresh), 0);
        let failed = records
            .iter()
            .find(|record| record.event_type == EvidenceEventType::RepairFailed)
            .expect("repair failed record");
        let reason = failed
            .repair
            .as_ref()
            .and_then(|detail| detail.reason.as_deref())
            .unwrap_or_default();
        assert!(
            reason.contains("stale repair snapshot"),
            "unexpected failure reason: {reason}"
        );
    }

    #[test]
    fn bootstrap_storage_rejects_symbols_beyond_layout_capacity() {
        let cx = Cx::for_testing();
        let device = MemBlockDevice::new(256, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);

        write_source_blocks(&cx, &device, source_first, 8);
        let err = bootstrap_storage_result(&cx, &device, layout, source_first, 8, 8)
            .expect_err("repair symbols should exceed reserved layout capacity");

        let message = match err {
            FfsError::RepairFailed(message) => message,
            other => {
                assert!(
                    matches!(other, FfsError::RepairFailed(_)),
                    "unexpected error variant: {other:?}"
                );
                return;
            }
        };
        assert!(
            message.contains("too many raw symbols for reserved region"),
            "unexpected repair error message: {message}"
        );
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

        let records = crate::evidence::parse_evidence_ledger(pipeline.into_ledger());
        assert_ledger_self_consistency(&records);
        assert_eq!(
            count_event(&records, EvidenceEventType::CorruptionDetected),
            1
        );
        assert_eq!(count_event(&records, EvidenceEventType::RepairAttempted), 1);
        assert_eq!(count_event(&records, EvidenceEventType::RepairSucceeded), 0);
        assert_eq!(count_event(&records, EvidenceEventType::RepairFailed), 1);

        let failed_record = records
            .iter()
            .find(|record| record.event_type == EvidenceEventType::RepairFailed)
            .expect("repair_failed record");
        let failure_reason = failed_record
            .repair
            .as_ref()
            .and_then(|detail| detail.reason.as_deref())
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert!(
            failure_reason.contains("insufficient")
                || failure_reason.contains("unrecoverable")
                || failure_reason.contains("recover"),
            "unexpected repair failure reason: {failure_reason}"
        );
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
            records.len() >= 4,
            "expected at least 4 evidence records (corruption + attempt + repair + refresh), got {}",
            records.len()
        );

        // First record: corruption detected.
        assert_eq!(
            records[0].event_type,
            crate::evidence::EvidenceEventType::CorruptionDetected
        );
        assert!(
            records
                .iter()
                .any(|r| { r.event_type == crate::evidence::EvidenceEventType::RepairAttempted })
        );
        assert!(
            records
                .iter()
                .any(|r| { r.event_type == crate::evidence::EvidenceEventType::RepairSucceeded })
        );
        assert!(
            records
                .iter()
                .any(|r| { r.event_type == crate::evidence::EvidenceEventType::SymbolRefresh })
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

    #[test]
    fn eager_policy_refreshes_symbols_on_write() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);
        let generation_before = read_generation(&cx, &device, layout);

        let validator = CorruptBlockValidator::new(vec![]);
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
        )
        .with_group_refresh_policy(GroupNumber(0), RefreshPolicy::Eager);

        pipeline
            .on_group_write(&cx, GroupNumber(0))
            .expect("eager refresh");

        let generation_after = read_generation(&cx, &device, layout);
        assert_eq!(generation_after, generation_before + 1);
    }

    #[test]
    fn dirty_group_tracking_api_reports_state() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
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

        assert!(pipeline.dirty_groups().is_empty());
        assert!(!pipeline.is_group_dirty(GroupNumber(0)));
        pipeline
            .mark_group_dirty(GroupNumber(0))
            .expect("mark dirty");
        assert_eq!(pipeline.dirty_groups(), vec![GroupNumber(0)]);
        assert!(pipeline.is_group_dirty(GroupNumber(0)));

        pipeline
            .refresh_dirty_groups_now(&cx)
            .expect("refresh dirty groups");
        assert!(pipeline.dirty_groups().is_empty());
        assert!(!pipeline.is_group_dirty(GroupNumber(0)));
    }

    #[test]
    fn group_flush_refreshes_eager_policy() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);
        let generation_before = read_generation(&cx, &device, layout);

        let validator = CorruptBlockValidator::new(vec![]);
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
        )
        .with_group_refresh_policy(GroupNumber(0), RefreshPolicy::Eager);

        pipeline
            .mark_group_dirty(GroupNumber(0))
            .expect("mark dirty");
        pipeline
            .on_group_flush(&cx, GroupNumber(0))
            .expect("flush refresh");

        assert_eq!(read_generation(&cx, &device, layout), generation_before + 1);
        assert!(!pipeline.is_group_dirty(GroupNumber(0)));
    }

    #[test]
    fn group_flush_keeps_fresh_lazy_group_dirty() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);
        let generation_before = read_generation(&cx, &device, layout);

        let validator = CorruptBlockValidator::new(vec![]);
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
        )
        .with_group_refresh_policy(
            GroupNumber(0),
            RefreshPolicy::Lazy {
                max_staleness: Duration::from_secs(30),
            },
        );

        pipeline
            .mark_group_dirty(GroupNumber(0))
            .expect("mark dirty");
        pipeline
            .on_group_flush(&cx, GroupNumber(0))
            .expect("flush check");

        assert_eq!(read_generation(&cx, &device, layout), generation_before);
        assert!(pipeline.is_group_dirty(GroupNumber(0)));
    }

    #[test]
    fn queued_refresh_lifecycle_receives_group_notifications() {
        let cx = Cx::for_testing();
        let groups = vec![
            GroupConfig {
                layout: RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4)
                    .expect("layout0"),
                source_first_block: BlockNumber(0),
                source_block_count: 16,
            },
            GroupConfig {
                layout: RepairGroupLayout::new(GroupNumber(1), BlockNumber(64), 64, 0, 4)
                    .expect("layout1"),
                source_first_block: BlockNumber(64),
                source_block_count: 16,
            },
        ];

        let queue = QueuedRepairRefresh::from_group_configs(&groups);
        queue
            .on_flush_committed(&cx, &[BlockNumber(3), BlockNumber(70), BlockNumber(71)])
            .expect("queue groups");
        let queued = queue.drain_queued_groups().expect("drain queue");
        assert_eq!(queued, vec![GroupNumber(0), GroupNumber(1)]);
    }

    #[test]
    fn writeback_flush_queue_triggers_symbol_refresh() {
        let cx = Cx::for_testing();
        let block_size = 256_u32;
        let source_count = 8_u32;
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let group_cfg = GroupConfig {
            layout,
            source_first_block: BlockNumber(0),
            source_block_count: source_count,
        };
        let queue = QueuedRepairRefresh::from_group_configs(&[group_cfg]);
        let repair_lifecycle: Arc<dyn RepairFlushLifecycle> = Arc::new(queue.clone());

        let cache = ArcCache::new_with_policy_and_repair_lifecycle(
            MemBlockDevice::new(block_size, 128),
            32,
            ArcWritePolicy::WriteBack,
            repair_lifecycle,
        )
        .expect("cache");

        write_source_blocks(&cx, cache.inner(), BlockNumber(0), source_count);
        bootstrap_storage(&cx, cache.inner(), layout, BlockNumber(0), source_count, 4);
        let generation_before = read_generation(&cx, cache.inner(), layout);

        let mut mutated = deterministic_block(99, block_size);
        mutated[0] ^= 0x5A;
        cache
            .write_block(&cx, BlockNumber(2), &mutated)
            .expect("stage write");
        cache.flush_dirty(&cx).expect("flush dirty");

        let validator = CorruptBlockValidator::new(vec![]);
        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            cache.inner(),
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );

        let refreshed = queue
            .apply_queued_refreshes(&cx, &mut pipeline)
            .expect("apply refresh queue");
        assert_eq!(refreshed, 1);
        assert_eq!(
            read_generation(&cx, cache.inner(), layout),
            generation_before + 1
        );
    }

    #[test]
    fn lazy_policy_refreshes_on_next_scrub_cycle() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);
        let generation_before = read_generation(&cx, &device, layout);

        let validator = CorruptBlockValidator::new(vec![]);
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
        )
        .with_group_refresh_policy(
            GroupNumber(0),
            RefreshPolicy::Lazy {
                max_staleness: Duration::from_secs(30),
            },
        );

        pipeline
            .on_group_write(&cx, GroupNumber(0))
            .expect("mark dirty");
        let generation_after_write = read_generation(&cx, &device, layout);
        assert_eq!(generation_after_write, generation_before);

        let _report = pipeline.scrub_and_recover(&cx).expect("scrub");
        let generation_after_scrub = read_generation(&cx, &device, layout);
        assert_eq!(generation_after_scrub, generation_before + 1);
    }

    #[test]
    fn adaptive_policy_switches_eager_based_on_posterior() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);
        let generation_before = read_generation(&cx, &device, layout);

        let validator = CorruptBlockValidator::new(vec![]);
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
        )
        .with_group_refresh_policy(
            GroupNumber(0),
            RefreshPolicy::Adaptive {
                risk_threshold: 0.05,
                max_staleness: Duration::from_secs(30),
            },
        );

        pipeline
            .policy_decisions
            .insert(0, policy_decision_fixture(4, 0.01));
        pipeline
            .on_group_write(&cx, GroupNumber(0))
            .expect("adaptive low-risk write");
        assert_eq!(read_generation(&cx, &device, layout), generation_before);
        assert!(
            pipeline
                .refresh_states
                .get(&0)
                .expect("refresh state")
                .dirty
        );

        pipeline
            .policy_decisions
            .insert(0, policy_decision_fixture(4, 0.2));
        pipeline
            .on_group_write(&cx, GroupNumber(0))
            .expect("adaptive high-risk write");
        assert_eq!(read_generation(&cx, &device, layout), generation_before + 1);
        assert!(
            !pipeline
                .refresh_states
                .get(&0)
                .expect("refresh state")
                .dirty
        );
    }

    #[test]
    fn staleness_timeout_forces_refresh() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);
        let generation_before = read_generation(&cx, &device, layout);

        let validator = CorruptBlockValidator::new(vec![]);
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
        )
        .with_group_refresh_policy(
            GroupNumber(0),
            RefreshPolicy::Lazy {
                max_staleness: Duration::from_millis(5),
            },
        );

        pipeline
            .on_group_write(&cx, GroupNumber(0))
            .expect("mark dirty");
        if let Some(state) = pipeline.refresh_states.get_mut(&0) {
            state.dirty = true;
            state.dirty_since = Instant::now().checked_sub(Duration::from_millis(25));
        }
        pipeline
            .on_group_write(&cx, GroupNumber(0))
            .expect("force stale refresh");

        assert_eq!(read_generation(&cx, &device, layout), generation_before + 1);
    }

    #[test]
    fn adaptive_policy_logs_decision_on_clean_scrub() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 64);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 32, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 16;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
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
        )
        .with_adaptive_overhead(DurabilityAutopilot::default())
        .with_metadata_groups([GroupNumber(0)]);

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert!(report.is_fully_recovered());

        let records = crate::evidence::parse_evidence_ledger(pipeline.into_ledger());
        assert_ledger_self_consistency(&records);
        let policy = records
            .iter()
            .find(|record| record.event_type == crate::evidence::EvidenceEventType::PolicyDecision)
            .expect("policy decision record");
        let detail = policy.policy.as_ref().expect("policy detail");
        assert!(detail.posterior_alpha >= 1.0);
        assert!(detail.posterior_beta >= 100.0);
        assert!(detail.overhead_ratio >= 0.03);
        assert!(detail.overhead_ratio <= 0.20);
    }

    #[test]
    fn adaptive_policy_controls_symbol_refresh_count() {
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
            .write_block(&cx, BlockNumber(2), &vec![0xAB; block_size as usize])
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
            4,
        )
        .with_adaptive_overhead(DurabilityAutopilot::default())
        .with_metadata_groups([GroupNumber(0)]);

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert!(report.is_fully_recovered());

        let records = crate::evidence::parse_evidence_ledger(pipeline.into_ledger());
        let policy_detail = records
            .iter()
            .filter_map(|record| {
                if record.event_type == crate::evidence::EvidenceEventType::PolicyDecision {
                    record.policy.as_ref()
                } else {
                    None
                }
            })
            .find(|detail| detail.symbols_selected > 0)
            .unwrap_or_else(|| {
                records
                    .iter()
                    .find_map(|record| record.policy.as_ref())
                    .expect("policy detail")
            });

        let refresh_detail = records
            .iter()
            .find_map(|record| {
                if record.event_type == crate::evidence::EvidenceEventType::SymbolRefresh {
                    record.symbol_refresh.as_ref()
                } else {
                    None
                }
            })
            .expect("symbol refresh detail");

        assert_eq!(
            refresh_detail.symbols_generated,
            policy_detail.symbols_selected
        );
    }

    #[test]
    fn adaptive_policy_clamp_preserves_metadata_expected_loss() {
        let device = MemBlockDevice::new(256, 128);
        let validator = CorruptBlockValidator::new(vec![]);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 1).expect("layout");
        let group_cfg = GroupConfig {
            layout,
            source_first_block: BlockNumber(0),
            source_block_count: 64,
        };
        let report = ScrubReport {
            findings: Vec::new(),
            blocks_scanned: 64,
            blocks_corrupt: 64,
            blocks_io_error: 0,
        };

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        )
        .with_adaptive_overhead(DurabilityAutopilot::default())
        .with_metadata_groups([GroupNumber(0)]);

        pipeline
            .update_adaptive_policy(&report)
            .expect("adaptive policy update");

        let decision = pipeline
            .policy_decisions
            .get(&0)
            .expect("group policy decision");
        assert_eq!(decision.symbols_selected, layout.repair_block_count);

        let mut expected_ap = DurabilityAutopilot::default();
        expected_ap.update_posterior(report.blocks_corrupt, report.blocks_scanned);
        let effective_overhead =
            f64::from(layout.repair_block_count) / f64::from(group_cfg.source_block_count);
        let metadata_loss = expected_ap.expected_loss_for_group(
            effective_overhead,
            group_cfg.source_block_count,
            true,
        );
        let base_loss = expected_ap.expected_loss_for_group(
            effective_overhead,
            group_cfg.source_block_count,
            false,
        );

        assert!(
            metadata_loss > base_loss,
            "test setup should expose metadata multiplier after clamping"
        );
        assert!(
            (decision.expected_loss - metadata_loss).abs() < 1e-12,
            "clamped metadata decision must preserve metadata expected-loss cost"
        );
    }

    #[test]
    fn default_metadata_group_uses_lowest_configured_group_id() {
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 256);
        let validator = CorruptBlockValidator::new(vec![]);

        let high_group = GroupConfig {
            layout: RepairGroupLayout::new(GroupNumber(9), BlockNumber(64), 64, 0, 4)
                .expect("high layout"),
            source_first_block: BlockNumber(64),
            source_block_count: 16,
        };
        let low_group = GroupConfig {
            layout: RepairGroupLayout::new(GroupNumber(7), BlockNumber(0), 64, 0, 4)
                .expect("low layout"),
            source_first_block: BlockNumber(0),
            source_block_count: 16,
        };

        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![high_group, low_group],
            &mut ledger_buf,
            4,
        );

        assert_eq!(pipeline.metadata_groups, BTreeSet::from([7_u32]));
        assert_eq!(
            pipeline.refresh_states.get(&7).map(|state| state.policy),
            Some(RefreshPolicy::Eager)
        );
        assert_eq!(
            pipeline.refresh_states.get(&9).map(|state| state.policy),
            Some(RefreshPolicy::Lazy {
                max_staleness: Duration::from_secs(30),
            })
        );
    }

    #[test]
    fn default_metadata_group_is_empty_when_no_groups_configured() {
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 64);
        let validator = CorruptBlockValidator::new(vec![]);
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            Vec::new(),
            &mut ledger_buf,
            4,
        );

        assert!(pipeline.metadata_groups.is_empty());
        assert!(pipeline.refresh_states.is_empty());
    }

    #[test]
    fn scrub_daemon_scans_at_least_one_group() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );
        let mut daemon = ScrubDaemon::new(
            pipeline,
            ScrubDaemonConfig {
                interval: Duration::ZERO,
                cancel_check_interval: Duration::from_millis(1),
                ..ScrubDaemonConfig::default()
            },
        );

        let step = daemon.run_once(&cx).expect("run once");
        assert_eq!(step.group, 0);
        assert!(step.blocks_scanned > 0);
        assert!(daemon.metrics().blocks_scanned_total >= u64::from(source_count));
        assert_eq!(daemon.metrics().scrub_rounds_completed, 1);
    }

    #[test]
    fn scrub_daemon_run_once_applies_queued_refreshes() {
        let cx = Cx::for_testing();
        let block_size = 256_u32;
        let source_count = 8_u32;
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let group_cfg = GroupConfig {
            layout,
            source_first_block: BlockNumber(0),
            source_block_count: source_count,
        };
        let queue = QueuedRepairRefresh::from_group_configs(&[group_cfg]);
        let repair_lifecycle: Arc<dyn RepairFlushLifecycle> = Arc::new(queue.clone());

        let cache = ArcCache::new_with_policy_and_repair_lifecycle(
            MemBlockDevice::new(block_size, 128),
            32,
            ArcWritePolicy::WriteBack,
            repair_lifecycle,
        )
        .expect("cache");

        write_source_blocks(&cx, cache.inner(), BlockNumber(0), source_count);
        bootstrap_storage(&cx, cache.inner(), layout, BlockNumber(0), source_count, 4);
        let generation_before = read_generation(&cx, cache.inner(), layout);

        let mut mutated = deterministic_block(77, block_size);
        mutated[0] ^= 0x33;
        cache
            .write_block(&cx, BlockNumber(2), &mutated)
            .expect("stage write");
        cache.flush_dirty(&cx).expect("flush dirty");

        let validator = CorruptBlockValidator::new(vec![]);
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            cache.inner(),
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );
        let mut daemon = ScrubDaemon::new(
            pipeline,
            ScrubDaemonConfig {
                interval: Duration::ZERO,
                cancel_check_interval: Duration::from_millis(1),
                ..ScrubDaemonConfig::default()
            },
        )
        .with_queued_refresh(queue.clone());

        let _step = daemon.run_once(&cx).expect("run once");

        assert_eq!(
            read_generation(&cx, cache.inner(), layout),
            generation_before + 1
        );
        assert!(
            queue
                .drain_queued_groups()
                .expect("drain queue after daemon run")
                .is_empty()
        );
    }

    #[test]
    fn scrub_daemon_detects_corruption_and_triggers_recovery() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        let originals = write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let corrupt_block = BlockNumber(3);
        device
            .write_block(&cx, corrupt_block, &vec![0xEF; block_size as usize])
            .expect("inject corruption");

        let validator = CorruptBlockValidator::new(vec![3]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );
        let mut daemon = ScrubDaemon::new(
            pipeline,
            ScrubDaemonConfig {
                interval: Duration::ZERO,
                cancel_check_interval: Duration::from_millis(1),
                ..ScrubDaemonConfig::default()
            },
        );

        let step = daemon.run_once(&cx).expect("run once");
        assert_eq!(step.corrupt_count, 1);
        assert_eq!(step.recovered_count, 1);
        assert_eq!(step.unrecoverable_count, 0);

        let restored = device
            .read_block(&cx, corrupt_block)
            .expect("read restored");
        assert_eq!(restored.as_slice(), originals[3].as_slice());

        let (pipeline, _metrics) = daemon.into_parts();
        let ledger = pipeline.into_ledger();
        let records = crate::evidence::parse_evidence_ledger(ledger);
        assert!(
            records.iter().any(|r| {
                r.event_type == crate::evidence::EvidenceEventType::ScrubCycleComplete
            })
        );
        assert!(
            records
                .iter()
                .any(|r| r.event_type == crate::evidence::EvidenceEventType::RepairSucceeded)
        );
    }

    #[test]
    fn scrub_daemon_detection_only_does_not_write_recovery_blocks() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        let originals = write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let corrupt_block = BlockNumber(3);
        let corrupt_payload = vec![0xEF; block_size as usize];
        device
            .write_block(&cx, corrupt_block, &corrupt_payload)
            .expect("inject corruption");

        let validator = CorruptBlockValidator::new(vec![3]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        )
        .with_repair_writes_enabled(false);
        let mut daemon = ScrubDaemon::new(
            pipeline,
            ScrubDaemonConfig {
                interval: Duration::ZERO,
                cancel_check_interval: Duration::from_millis(1),
                ..ScrubDaemonConfig::default()
            },
        );

        let step = daemon.run_once(&cx).expect("run once");
        assert_eq!(step.corrupt_count, 1);
        assert_eq!(step.recovered_count, 0);
        assert_eq!(step.unrecoverable_count, 1);

        let stored = device
            .read_block(&cx, corrupt_block)
            .expect("read stored block");
        assert_ne!(stored.as_slice(), originals[3].as_slice());
        assert_eq!(stored.as_slice(), corrupt_payload.as_slice());

        let (pipeline, _metrics) = daemon.into_parts();
        let records = crate::evidence::parse_evidence_ledger(pipeline.into_ledger());
        assert!(
            records.iter().any(|r| {
                r.event_type == crate::evidence::EvidenceEventType::CorruptionDetected
            })
        );
        assert!(!records.iter().any(|r| {
            matches!(
                r.event_type,
                crate::evidence::EvidenceEventType::RepairAttempted
                    | crate::evidence::EvidenceEventType::RepairSucceeded
                    | crate::evidence::EvidenceEventType::SymbolRefresh
            )
        }));
    }

    #[test]
    fn scrub_daemon_respects_cancellation_promptly() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );
        let mut daemon = ScrubDaemon::new(pipeline, ScrubDaemonConfig::default());

        let metrics = daemon.run_until_cancelled(&cx).expect("cancelled stop");
        assert_eq!(metrics.blocks_scanned_total, 0);
        assert_eq!(metrics.scrub_rounds_completed, 0);
    }

    #[test]
    fn scrub_daemon_yields_under_backpressure() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );
        let pressure = Arc::new(SystemPressure::with_headroom(0.1));
        let mut daemon = ScrubDaemon::new(
            pipeline,
            ScrubDaemonConfig {
                interval: Duration::ZERO,
                cancel_check_interval: Duration::from_millis(1),
                backpressure_headroom_threshold: 0.5,
                backpressure_sleep: Duration::from_millis(1),
                ..ScrubDaemonConfig::default()
            },
        )
        .with_pressure(pressure);

        let _step = daemon.run_once(&cx).expect("run once");
        assert_eq!(daemon.metrics().backpressure_yields, 1);
    }

    #[test]
    fn scrub_daemon_backpressure_yield_rejects_deadline_that_cannot_fit() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );
        let pressure = Arc::new(SystemPressure::with_headroom(0.1));
        let yield_sleep = Duration::from_millis(250);
        let mut daemon = ScrubDaemon::new(
            pipeline,
            ScrubDaemonConfig {
                interval: Duration::ZERO,
                cancel_check_interval: yield_sleep,
                backpressure_headroom_threshold: 0.5,
                backpressure_sleep: yield_sleep,
                ..ScrubDaemonConfig::default()
            },
        )
        .with_pressure(pressure);

        let tight_deadline = Cx::for_testing().now() + Duration::from_millis(20);
        let tight_cx =
            Cx::for_testing_with_budget(asupersync::Budget::new().with_deadline(tight_deadline));
        let started = Instant::now();
        let err = daemon
            .run_once(&tight_cx)
            .expect_err("too-tight deadline should reject throttle admission");
        let elapsed = started.elapsed();

        assert!(matches!(err, FfsError::Cancelled));
        assert!(
            elapsed < yield_sleep / 2,
            "too-tight Cx should skip scrub-daemon throttle sleep promptly, elapsed={elapsed:?}"
        );
        assert_eq!(daemon.metrics().backpressure_yields, 1);
        assert_eq!(daemon.metrics().blocks_scanned_total, 0);
    }

    #[test]
    fn scrub_daemon_backpressure_yield_observes_mid_sleep_cancellation() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );
        let pressure = Arc::new(SystemPressure::with_headroom(0.1));
        let yield_sleep = Duration::from_millis(250);
        let mut daemon = ScrubDaemon::new(
            pipeline,
            ScrubDaemonConfig {
                interval: Duration::ZERO,
                cancel_check_interval: Duration::from_millis(10),
                backpressure_headroom_threshold: 0.5,
                backpressure_sleep: yield_sleep,
                ..ScrubDaemonConfig::default()
            },
        )
        .with_pressure(pressure);

        let cancel_cx = cx.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(15));
            cancel_cx.set_cancel_requested(true);
        });

        let started = Instant::now();
        let err = daemon
            .run_once(&cx)
            .expect_err("mid-sleep cancellation should stop backpressure yield");
        let elapsed = started.elapsed();
        canceller.join().expect("canceller thread should finish");

        assert!(matches!(err, FfsError::Cancelled));
        assert!(
            elapsed < yield_sleep / 2,
            "cancelled Cx should interrupt scrub-daemon throttle sleep promptly, elapsed={elapsed:?}"
        );
        assert_eq!(daemon.metrics().backpressure_yields, 1);
        assert_eq!(daemon.metrics().blocks_scanned_total, 0);
    }

    #[test]
    fn scrub_daemon_yields_when_budget_is_low() {
        let cx = Cx::for_testing_with_budget(asupersync::Budget::new().with_poll_quota(8));
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );
        let mut daemon = ScrubDaemon::new(
            pipeline,
            ScrubDaemonConfig {
                interval: Duration::ZERO,
                cancel_check_interval: Duration::from_millis(1),
                budget_poll_quota_threshold: 16,
                budget_sleep: Duration::from_millis(1),
                ..ScrubDaemonConfig::default()
            },
        );

        let _step = daemon.run_once(&cx).expect("run once");
        assert_eq!(daemon.metrics().backpressure_yields, 1);
    }

    #[test]
    fn scrub_daemon_completes_full_round_without_error() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 256);

        let layout0 =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout0");
        let layout1 =
            RepairGroupLayout::new(GroupNumber(1), BlockNumber(64), 64, 0, 4).expect("layout1");

        let source_count = 8;
        write_source_blocks(&cx, &device, BlockNumber(0), source_count);
        write_source_blocks(&cx, &device, BlockNumber(64), source_count);
        bootstrap_storage(&cx, &device, layout0, BlockNumber(0), source_count, 4);
        bootstrap_storage(&cx, &device, layout1, BlockNumber(64), source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let groups = vec![
            GroupConfig {
                layout: layout0,
                source_first_block: BlockNumber(0),
                source_block_count: source_count,
            },
            GroupConfig {
                layout: layout1,
                source_first_block: BlockNumber(64),
                source_block_count: source_count,
            },
        ];

        let mut ledger_buf = Vec::new();
        let pipeline =
            ScrubWithRecovery::new(&device, &validator, test_uuid(), groups, &mut ledger_buf, 4);
        let mut daemon = ScrubDaemon::new(
            pipeline,
            ScrubDaemonConfig {
                interval: Duration::ZERO,
                cancel_check_interval: Duration::from_millis(1),
                ..ScrubDaemonConfig::default()
            },
        );

        daemon.run_one_round(&cx).expect("run one round");
        assert_eq!(daemon.metrics().scrub_rounds_completed, 1);
        assert!(daemon.metrics().blocks_scanned_total >= u64::from(source_count) * 2);
        assert_eq!(daemon.runtime_metrics().groups_scrubbed, 2);
    }

    #[test]
    fn e2e_survive_five_percent_random_block_corruption_with_daemon() {
        let cx = Cx::for_testing();
        let RepairE2eFixture {
            device,
            groups,
            source_blocks,
            corrupt_blocks,
            before_hashes,
        } = build_repair_e2e_fixture(&cx);

        let validator = CorruptBlockValidator::new(corrupt_blocks.clone());
        let mut ledger_buf = Vec::new();
        let expected_groups = u64::try_from(groups.len()).expect("groups len fits u64");
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            groups,
            &mut ledger_buf,
            E2E_REPAIR_SYMBOL_COUNT,
        );
        let mut daemon = ScrubDaemon::new(
            pipeline,
            ScrubDaemonConfig {
                interval: Duration::ZERO,
                cancel_check_interval: Duration::from_millis(1),
                ..ScrubDaemonConfig::default()
            },
        );

        let started = Instant::now();
        daemon.run_one_round(&cx).expect("daemon one round");
        let elapsed = started.elapsed();

        let expected_repairs = u64::try_from(corrupt_blocks.len()).expect("len fits u64");
        assert_eq!(daemon.metrics().blocks_corrupt_found, expected_repairs);
        assert_eq!(daemon.metrics().blocks_recovered, expected_repairs);
        assert_eq!(daemon.metrics().blocks_unrecoverable, 0);
        assert_eq!(daemon.metrics().scrub_rounds_completed, 1);
        let runtime_metrics = daemon.runtime_metrics();
        assert_eq!(runtime_metrics.groups_scrubbed, expected_groups);
        assert_eq!(runtime_metrics.corruption_detected, expected_repairs);
        assert_eq!(runtime_metrics.decode_attempts, expected_repairs);
        assert_eq!(runtime_metrics.decode_successes, expected_repairs);
        assert_eq!(runtime_metrics.symbol_refresh_count, expected_repairs);
        assert!(
            runtime_metrics.symbol_staleness_max_seconds >= 0.0,
            "staleness gauge must be non-negative"
        );

        let after_hashes = block_hashes(&cx, &device, &source_blocks);
        assert_eq!(before_hashes, after_hashes, "data mismatch after repair");

        let (pipeline, _metrics) = daemon.into_parts();
        let ledger_data = pipeline.into_ledger();
        assert_repair_e2e_evidence(ledger_data, corrupt_blocks.len());

        let records = crate::evidence::parse_evidence_ledger(ledger_data);
        assert_group_event_coverage(&records, &corrupt_blocks);

        assert!(
            elapsed <= Duration::from_secs(120),
            "repair e2e exceeded timeout: {elapsed:?}"
        );

        maybe_write_repair_e2e_artifacts(
            &before_hashes,
            &after_hashes,
            &corrupt_blocks,
            ledger_data,
            E2E_SEED,
            E2E_CORRUPTION_PERCENT,
        );
    }

    // ── Edge-case hardening tests ──────────────────────────────────────

    #[test]
    fn recovery_report_is_fully_recovered_when_no_corruption() {
        let report = RecoveryReport {
            blocks_scanned: 100,
            total_corrupt: 0,
            total_recovered: 0,
            total_unrecoverable: 0,
            block_outcomes: BTreeMap::new(),
            group_summaries: Vec::new(),
        };
        assert!(report.is_fully_recovered());
    }

    #[test]
    fn recovery_report_not_fully_recovered_with_unrecoverable() {
        let report = RecoveryReport {
            blocks_scanned: 100,
            total_corrupt: 2,
            total_recovered: 1,
            total_unrecoverable: 1,
            block_outcomes: BTreeMap::from([(42, BlockOutcome::Unrecoverable)]),
            group_summaries: Vec::new(),
        };
        assert!(!report.is_fully_recovered());
    }

    #[test]
    fn recovery_report_serde_round_trip() {
        let report = RecoveryReport {
            blocks_scanned: 50,
            total_corrupt: 1,
            total_recovered: 1,
            total_unrecoverable: 0,
            block_outcomes: BTreeMap::from([
                (10, BlockOutcome::Clean),
                (11, BlockOutcome::Recovered),
            ]),
            group_summaries: vec![GroupRecoverySummary {
                group: 0,
                corrupt_count: 1,
                recovered_count: 1,
                unrecoverable_count: 0,
                symbols_refreshed: true,
                decoder_stats: None,
            }],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: RecoveryReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.blocks_scanned, 50);
        assert_eq!(parsed.total_corrupt, 1);
        assert!(parsed.is_fully_recovered());
    }

    #[test]
    fn block_outcome_serde_round_trip() {
        for outcome in [
            BlockOutcome::Clean,
            BlockOutcome::Recovered,
            BlockOutcome::Unrecoverable,
        ] {
            let json = serde_json::to_string(&outcome).expect("serialize");
            let parsed: BlockOutcome = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(parsed, outcome);
        }
    }

    #[test]
    fn scrub_daemon_config_default_has_sensible_values() {
        let cfg = ScrubDaemonConfig::default();
        assert!(!cfg.interval.is_zero());
        assert!(!cfg.cancel_check_interval.is_zero());
        assert!(cfg.budget_poll_quota_threshold > 0);
        assert!(cfg.backpressure_headroom_threshold > 0.0);
    }

    #[test]
    fn scrub_daemon_metrics_default_is_zeroed() {
        let m = ScrubDaemonMetrics::default();
        assert_eq!(m.blocks_scanned_total, 0);
        assert_eq!(m.blocks_corrupt_found, 0);
        assert_eq!(m.blocks_recovered, 0);
        assert_eq!(m.blocks_unrecoverable, 0);
        assert_eq!(m.scrub_rounds_completed, 0);
        assert!(
            (m.scrub_rate_blocks_per_sec - 0.0).abs() < f64::EPSILON,
            "scrub_rate should be zero"
        );
        assert_eq!(m.backpressure_yields, 0);
    }

    #[test]
    fn scrub_daemon_metrics_serde_round_trip() {
        let m = ScrubDaemonMetrics {
            blocks_scanned_total: 1000,
            blocks_corrupt_found: 5,
            blocks_recovered: 4,
            blocks_unrecoverable: 1,
            scrub_rounds_completed: 3,
            current_group: 7,
            scrub_rate_blocks_per_sec: 123.45,
            backpressure_yields: 2,
        };
        let json = serde_json::to_string(&m).expect("serialize");
        let parsed: ScrubDaemonMetrics = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.blocks_scanned_total, 1000);
        assert_eq!(parsed.blocks_recovered, 4);
    }

    #[test]
    fn repair_runtime_metrics_default_is_zeroed() {
        let metrics = RepairRuntimeMetrics::default().snapshot(&RefreshTelemetry {
            tracked_groups: 0,
            dirty_groups: 0,
            max_dirty_age_ms: 0,
            groups: Vec::new(),
        });
        assert_eq!(metrics.groups_scrubbed, 0);
        assert_eq!(metrics.corruption_detected, 0);
        assert_eq!(metrics.decode_attempts, 0);
        assert_eq!(metrics.decode_successes, 0);
        assert_eq!(metrics.symbol_refresh_count, 0);
        assert!(
            (metrics.symbol_staleness_max_seconds - 0.0).abs() < f64::EPSILON,
            "staleness gauge should default to zero"
        );
    }

    #[test]
    fn repair_runtime_metrics_serde_round_trip() {
        let metrics = RepairRuntimeMetricsSnapshot {
            groups_scrubbed: 12,
            corruption_detected: 4,
            decode_attempts: 4,
            decode_successes: 3,
            symbol_refresh_count: 5,
            symbol_staleness_max_seconds: 7.25,
        };
        let json = serde_json::to_string(&metrics).expect("serialize");
        let parsed: RepairRuntimeMetricsSnapshot =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.groups_scrubbed, 12);
        assert_eq!(parsed.decode_successes, 3);
        assert!(
            (parsed.symbol_staleness_max_seconds - 7.25).abs() < f64::EPSILON,
            "staleness gauge must survive serde round-trip"
        );
    }

    #[test]
    fn repair_runtime_metrics_report_max_symbol_staleness() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout0 =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout0");
        let layout1 =
            RepairGroupLayout::new(GroupNumber(1), BlockNumber(64), 64, 0, 4).expect("layout1");
        let source_count = 8;

        write_source_blocks(&cx, &device, BlockNumber(0), source_count);
        write_source_blocks(&cx, &device, BlockNumber(64), source_count);
        bootstrap_storage(&cx, &device, layout0, BlockNumber(0), source_count, 4);
        bootstrap_storage(&cx, &device, layout1, BlockNumber(64), source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let groups = vec![
            GroupConfig {
                layout: layout0,
                source_first_block: BlockNumber(0),
                source_block_count: source_count,
            },
            GroupConfig {
                layout: layout1,
                source_first_block: BlockNumber(64),
                source_block_count: source_count,
            },
        ];

        let mut ledger_buf = Vec::new();
        let mut pipeline =
            ScrubWithRecovery::new(&device, &validator, test_uuid(), groups, &mut ledger_buf, 4);
        let now = Instant::now();
        pipeline
            .refresh_states
            .get_mut(&0)
            .expect("group 0 state")
            .last_refresh = now
            .checked_sub(Duration::from_secs(2))
            .expect("valid instant math");
        pipeline
            .refresh_states
            .get_mut(&1)
            .expect("group 1 state")
            .last_refresh = now
            .checked_sub(Duration::from_secs(5))
            .expect("valid instant math");

        let metrics = pipeline.runtime_metrics();
        assert!(
            metrics.symbol_staleness_max_seconds >= 5.0,
            "expected max staleness >= 5s, got {}",
            metrics.symbol_staleness_max_seconds
        );
        assert!(
            metrics.symbol_staleness_max_seconds < 6.0,
            "expected max staleness < 6s, got {}",
            metrics.symbol_staleness_max_seconds
        );
    }

    #[test]
    fn scrub_daemon_step_serde_round_trip() {
        let step = ScrubDaemonStep {
            group: 3,
            blocks_scanned: 64,
            corrupt_count: 2,
            recovered_count: 2,
            unrecoverable_count: 0,
            duration_ms: 150,
        };
        let json = serde_json::to_string(&step).expect("serialize");
        let parsed: ScrubDaemonStep = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.group, 3);
        assert_eq!(parsed.blocks_scanned, 64);
    }

    #[test]
    fn refresh_mode_as_str_covers_all_variants() {
        assert_eq!(RefreshMode::Recovery.as_str(), "recovery");
        assert_eq!(RefreshMode::EagerWrite.as_str(), "eager_write");
        assert_eq!(RefreshMode::LazyScrub.as_str(), "lazy_scrub");
        assert_eq!(
            RefreshMode::AdaptiveEagerWrite.as_str(),
            "adaptive_eager_write"
        );
        assert_eq!(
            RefreshMode::AdaptiveLazyScrub.as_str(),
            "adaptive_lazy_scrub"
        );
        assert_eq!(RefreshMode::StalenessTimeout.as_str(), "staleness_timeout");
    }

    #[test]
    fn queued_repair_refresh_empty_drain() {
        let queue = QueuedRepairRefresh::from_group_configs(&[]);
        let drained = queue.drain_queued_groups().expect("drain");
        assert!(drained.is_empty());
    }

    #[test]
    fn queued_repair_refresh_maps_blocks_to_groups() {
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let configs = vec![GroupConfig {
            layout,
            source_first_block: BlockNumber(0),
            source_block_count: 32,
        }];
        let queue = QueuedRepairRefresh::from_group_configs(&configs);

        // Repeated blocks in group 0's source range still queue it once.
        let cx = Cx::for_testing();
        queue
            .on_flush_committed(&cx, &[BlockNumber(10), BlockNumber(11), BlockNumber(10)])
            .expect("flush");
        let drained = queue.drain_queued_groups().expect("drain");
        assert_eq!(drained, vec![GroupNumber(0)]);

        // Second drain should be empty.
        let drained2 = queue.drain_queued_groups().expect("drain2");
        assert!(drained2.is_empty());
    }

    #[test]
    fn queued_repair_refresh_indexes_disjoint_unsorted_ranges() {
        let configs = [
            GroupConfig {
                layout: RepairGroupLayout::new(GroupNumber(2), BlockNumber(192), 64, 0, 4)
                    .expect("layout2"),
                source_first_block: BlockNumber(64),
                source_block_count: 16,
            },
            GroupConfig {
                layout: RepairGroupLayout::new(GroupNumber(0), BlockNumber(128), 64, 0, 4)
                    .expect("layout0"),
                source_first_block: BlockNumber(0),
                source_block_count: 16,
            },
            GroupConfig {
                layout: RepairGroupLayout::new(GroupNumber(1), BlockNumber(160), 64, 0, 4)
                    .expect("layout1"),
                source_first_block: BlockNumber(32),
                source_block_count: 16,
            },
        ];
        let queue = QueuedRepairRefresh::from_group_configs(&configs);
        assert!(queue.group_ranges_are_disjoint);

        let cx = Cx::for_testing();
        queue
            .on_flush_committed(&cx, &[BlockNumber(70), BlockNumber(1), BlockNumber(39)])
            .expect("flush");
        assert_eq!(
            queue.drain_queued_groups().expect("drain"),
            vec![GroupNumber(0), GroupNumber(1), GroupNumber(2)]
        );
    }

    #[test]
    fn queued_repair_refresh_preserves_first_match_for_overlapping_ranges() {
        let configs = [
            GroupConfig {
                layout: RepairGroupLayout::new(GroupNumber(7), BlockNumber(64), 64, 0, 4)
                    .expect("layout7"),
                source_first_block: BlockNumber(0),
                source_block_count: 16,
            },
            GroupConfig {
                layout: RepairGroupLayout::new(GroupNumber(3), BlockNumber(96), 64, 0, 4)
                    .expect("layout3"),
                source_first_block: BlockNumber(8),
                source_block_count: 16,
            },
        ];
        let queue = QueuedRepairRefresh::from_group_configs(&configs);
        assert!(!queue.group_ranges_are_disjoint);

        let cx = Cx::for_testing();
        queue
            .on_flush_committed(&cx, &[BlockNumber(10)])
            .expect("flush");
        assert_eq!(
            queue.drain_queued_groups().expect("drain"),
            vec![GroupNumber(7)]
        );
    }

    #[test]
    fn queued_repair_refresh_ignores_blocks_outside_any_group() {
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let configs = vec![GroupConfig {
            layout,
            source_first_block: BlockNumber(0),
            source_block_count: 8,
        }];
        let queue = QueuedRepairRefresh::from_group_configs(&configs);

        // Block 100 is outside all groups.
        let cx = Cx::for_testing();
        queue
            .on_flush_committed(&cx, &[BlockNumber(100)])
            .expect("flush");
        let drained = queue.drain_queued_groups().expect("drain");
        assert!(drained.is_empty());
    }

    /// bd-scg17 — Regression for the QueuedRepairRefresh
    /// "drain + drop + process" lock-order invariant.
    ///
    /// `apply_queued_refreshes` calls `drain_queued_groups` (which
    /// acquires + drains + drops the lock), THEN calls into
    /// `pipeline.mark_group_dirty` / `pipeline.on_group_flush`
    /// outside the lock. Those pipeline calls can fire back into
    /// `RepairFlushLifecycle::on_flush_committed`, which reacquires
    /// the same `queued_groups` mutex. If the lock were held during
    /// the pipeline call, the re-entrant flush would deadlock.
    ///
    /// This test simulates that re-entry pattern directly: spawn a
    /// thread that calls `drain_queued_groups` and `on_flush_committed`
    /// alternately. If a regression hoisted any pipeline-style work
    /// inside the locked block, the second `on_flush_committed` would
    /// block on the held mutex. We assert progress within a tight
    /// timeout to catch deadlock.
    #[test]
    fn queued_repair_refresh_drain_releases_lock_before_processing() {
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
        use std::thread;
        use std::time::Duration;

        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let configs = vec![GroupConfig {
            layout,
            source_first_block: BlockNumber(0),
            source_block_count: 32,
        }];
        let queue = StdArc::new(QueuedRepairRefresh::from_group_configs(&configs));
        let progress = StdArc::new(AtomicU64::new(0));

        // Producer thread — repeatedly calls on_flush_committed,
        // simulating a write-back path that fires re-entrantly.
        let producer = {
            let queue = StdArc::clone(&queue);
            let progress = StdArc::clone(&progress);
            thread::spawn(move || {
                let cx = Cx::for_testing();
                for _ in 0..256 {
                    queue
                        .on_flush_committed(&cx, &[BlockNumber(10)])
                        .expect("re-entrant flush must not deadlock");
                    progress.fetch_add(1, AtomicOrdering::Relaxed);
                }
            })
        };

        // Consumer thread — drains repeatedly. If drain held the
        // lock across iteration, the producer's lock acquisition
        // would block; the producer counter would not advance past
        // 1 within the timeout.
        let consumer = {
            let queue = StdArc::clone(&queue);
            thread::spawn(move || {
                for _ in 0..256 {
                    let _ = queue
                        .drain_queued_groups()
                        .expect("drain must not deadlock");
                }
            })
        };

        // Wait for both threads with a tight timeout. A held-lock
        // bug would manifest as one thread parked forever in the
        // futex; we'd see progress stuck.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        producer.join().expect("producer joined");
        consumer.join().expect("consumer joined");
        assert!(
            std::time::Instant::now() < deadline,
            "both threads must complete within 5s — a held-lock regression \
             would deadlock under the re-entrant flush pattern"
        );
        assert!(
            progress.load(AtomicOrdering::Relaxed) >= 256,
            "producer must complete all 256 re-entrant flush calls"
        );
    }

    #[test]
    fn group_recovery_summary_serde_omits_none_decoder_stats() {
        let summary = GroupRecoverySummary {
            group: 1,
            corrupt_count: 0,
            recovered_count: 0,
            unrecoverable_count: 0,
            symbols_refreshed: false,
            decoder_stats: None,
        };
        let json = serde_json::to_string(&summary).expect("serialize");
        assert!(
            !json.contains("decoder_stats"),
            "None decoder_stats should be omitted"
        );
    }

    // ── OQ3 closure: refresh policy and staleness telemetry tests ────────

    #[test]
    fn refresh_telemetry_reports_clean_state() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 64);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 32, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 16;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );

        let telemetry = pipeline.refresh_telemetry();
        assert_eq!(telemetry.tracked_groups, 1);
        assert_eq!(telemetry.dirty_groups, 0);
        assert_eq!(telemetry.max_dirty_age_ms, 0);
        assert_eq!(telemetry.groups.len(), 1);
        assert!(!telemetry.groups[0].dirty);
        assert_eq!(telemetry.groups[0].dirty_age_ms, 0);
    }

    #[test]
    fn refresh_telemetry_tracks_dirty_group() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
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
        )
        .with_group_refresh_policy(
            GroupNumber(0),
            RefreshPolicy::Lazy {
                max_staleness: Duration::from_secs(60),
            },
        );

        pipeline
            .mark_group_dirty(GroupNumber(0))
            .expect("mark dirty");

        let telemetry = pipeline.refresh_telemetry();
        assert_eq!(telemetry.dirty_groups, 1);
        assert!(telemetry.groups[0].dirty);
        assert!(telemetry.groups[0].policy.starts_with("lazy("));
    }

    #[test]
    fn refresh_telemetry_serializes_to_json() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 64);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 32, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 16;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );

        let telemetry = pipeline.refresh_telemetry();
        let json = serde_json::to_string_pretty(&telemetry).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["tracked_groups"], 1);
        assert_eq!(parsed["dirty_groups"], 0);
        assert_eq!(parsed["groups"].as_array().expect("groups array").len(), 1);
    }

    #[test]
    fn churn_writes_respect_staleness_budget() {
        // Under sustained rapid writes with Lazy policy, the staleness timeout
        // must trigger a refresh before the budget is exceeded by more than
        // one write interval.
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);
        let gen_before = read_generation(&cx, &device, layout);

        let validator = CorruptBlockValidator::new(vec![]);
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
        )
        .with_group_refresh_policy(
            GroupNumber(0),
            RefreshPolicy::Lazy {
                max_staleness: Duration::from_millis(10),
            },
        );

        // Simulate 20 rapid writes with artificial aging.
        // After the first write (which sets dirty), age the dirty_since so
        // subsequent writes trigger the staleness timeout.
        pipeline
            .on_group_write(&cx, GroupNumber(0))
            .expect("first write");

        // Artificially age the dirty_since to exceed max_staleness.
        if let Some(state) = pipeline.refresh_states.get_mut(&0) {
            state.dirty = true;
            state.dirty_since = Instant::now().checked_sub(Duration::from_millis(50));
        }

        // This write should trigger staleness timeout and refresh.
        pipeline
            .on_group_write(&cx, GroupNumber(0))
            .expect("stale write");

        let gen_after = read_generation(&cx, &device, layout);
        assert!(
            gen_after > gen_before,
            "staleness timeout must trigger refresh: gen_before={gen_before}, gen_after={gen_after}"
        );

        // After refresh, group should be clean.
        let telemetry = pipeline.refresh_telemetry();
        assert_eq!(
            telemetry.dirty_groups, 0,
            "group should be clean after staleness-triggered refresh"
        );
    }

    #[test]
    fn eager_policy_refreshes_on_every_write() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);
        let gen_before = read_generation(&cx, &device, layout);

        let validator = CorruptBlockValidator::new(vec![]);
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
        )
        .with_group_refresh_policy(GroupNumber(0), RefreshPolicy::Eager);

        // Each write should increment generation.
        for i in 1..=3_u64 {
            pipeline
                .on_group_write(&cx, GroupNumber(0))
                .expect("eager write");
            assert_eq!(
                read_generation(&cx, &device, layout),
                gen_before + i,
                "eager policy must refresh on every write (iteration {i})"
            );
        }

        // Group should always be clean after eager refresh.
        let telemetry = pipeline.refresh_telemetry();
        assert_eq!(telemetry.dirty_groups, 0);
    }

    #[test]
    fn lazy_policy_defers_refresh_until_scrub_or_timeout() {
        // Negative test: Lazy policy must NOT refresh on writes when under
        // the staleness budget. Refresh should only occur on scrub trigger
        // or staleness timeout.
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);
        let gen_before = read_generation(&cx, &device, layout);

        let validator = CorruptBlockValidator::new(vec![]);
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
        )
        .with_group_refresh_policy(
            GroupNumber(0),
            RefreshPolicy::Lazy {
                max_staleness: Duration::from_secs(3600),
            },
        );

        // Several writes within budget — generation must NOT change.
        for _ in 0..5 {
            pipeline
                .on_group_write(&cx, GroupNumber(0))
                .expect("lazy write");
        }
        assert_eq!(
            read_generation(&cx, &device, layout),
            gen_before,
            "lazy policy must NOT refresh within staleness budget"
        );

        // Group should be dirty (deferred).
        let telemetry = pipeline.refresh_telemetry();
        assert_eq!(telemetry.dirty_groups, 1);

        // A scrub trigger (non-write) should refresh.
        pipeline
            .refresh_dirty_groups_now(&cx)
            .expect("scrub trigger refresh");
        assert!(
            read_generation(&cx, &device, layout) > gen_before,
            "scrub trigger must refresh lazy dirty groups"
        );
    }

    #[test]
    fn refresh_telemetry_multiple_groups_sorted() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 256);

        let layout0 =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 32, 0, 4).expect("layout0");
        let layout1 =
            RepairGroupLayout::new(GroupNumber(1), BlockNumber(64), 32, 0, 4).expect("layout1");
        let source_count = 16;

        write_source_blocks(&cx, &device, BlockNumber(0), source_count);
        write_source_blocks(&cx, &device, BlockNumber(64), source_count);
        bootstrap_storage(&cx, &device, layout0, BlockNumber(0), source_count, 4);
        bootstrap_storage(&cx, &device, layout1, BlockNumber(64), source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let groups = vec![
            GroupConfig {
                layout: layout0,
                source_first_block: BlockNumber(0),
                source_block_count: source_count,
            },
            GroupConfig {
                layout: layout1,
                source_first_block: BlockNumber(64),
                source_block_count: source_count,
            },
        ];
        let mut ledger_buf = Vec::new();
        let mut pipeline =
            ScrubWithRecovery::new(&device, &validator, test_uuid(), groups, &mut ledger_buf, 4)
                .with_group_refresh_policy(GroupNumber(0), RefreshPolicy::Eager)
                .with_group_refresh_policy(
                    GroupNumber(1),
                    RefreshPolicy::Lazy {
                        max_staleness: Duration::from_secs(30),
                    },
                );

        // Dirty only group 1.
        pipeline
            .mark_group_dirty(GroupNumber(1))
            .expect("mark group 1 dirty");

        let telemetry = pipeline.refresh_telemetry();
        assert_eq!(telemetry.tracked_groups, 2);
        assert_eq!(telemetry.dirty_groups, 1);
        // Sorted by group number.
        assert_eq!(telemetry.groups[0].group, 0);
        assert_eq!(telemetry.groups[1].group, 1);
        assert!(!telemetry.groups[0].dirty);
        assert!(telemetry.groups[1].dirty);
        assert!(telemetry.groups[0].policy.starts_with("eager"));
        assert!(telemetry.groups[1].policy.starts_with("lazy("));
    }

    // ── Btrfs write-churn stress tests (bd-h6nz.3.4) ───────────────────

    #[test]
    fn scrub_detects_corruption_after_write_churn_dirties_symbols() {
        // Simulate write churn dirtying symbols, then scrub: corruption must
        // still be detected (no false "clean" outcome).
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        // Inject corruption at block 2.
        device
            .write_block(&cx, BlockNumber(2), &vec![0xDE; block_size as usize])
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
            4,
        )
        .with_group_refresh_policy(
            GroupNumber(0),
            RefreshPolicy::Lazy {
                max_staleness: Duration::from_secs(3600),
            },
        );

        // Simulate write churn: multiple writes dirtying the group.
        for _ in 0..10 {
            pipeline
                .on_group_write(&cx, GroupNumber(0))
                .expect("write churn");
        }

        // Symbols are now stale (dirty). Scrub must still detect corruption.
        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert_eq!(
            report.total_corrupt, 1,
            "corruption must be detected even after write churn"
        );
        assert!(
            !report.block_outcomes.is_empty(),
            "block outcomes must contain the corrupt block"
        );
    }

    #[test]
    fn recovery_succeeds_with_fresh_symbols_under_write_churn() {
        // If symbols are refreshed after writes (eager policy), recovery
        // should succeed even under write churn.
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        let originals = write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        // Simulate eager-policy write churn (symbols refreshed after each write).
        let validator = CorruptBlockValidator::new(vec![]);
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
        )
        .with_group_refresh_policy(GroupNumber(0), RefreshPolicy::Eager);

        // Simulate writes that refresh symbols.
        for _ in 0..3 {
            pipeline
                .on_group_write(&cx, GroupNumber(0))
                .expect("eager write");
        }

        // Now inject corruption and re-create pipeline with correct validator.
        drop(pipeline);
        device
            .write_block(&cx, BlockNumber(2), &vec![0xDE; block_size as usize])
            .expect("inject corruption");

        let validator_corrupt = CorruptBlockValidator::new(vec![2]);
        let mut ledger_buf2 = Vec::new();
        let mut pipeline2 = ScrubWithRecovery::new(
            &device,
            &validator_corrupt,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf2,
            4,
        );

        let report = pipeline2.scrub_and_recover(&cx).expect("pipeline2");
        assert_eq!(report.total_corrupt, 1);
        assert_eq!(
            report.total_recovered, 1,
            "recovery should succeed with fresh symbols"
        );
        let restored = device.read_block(&cx, BlockNumber(2)).expect("read");
        assert_eq!(
            restored.as_slice(),
            originals[2].as_slice(),
            "restored data must match original"
        );
    }

    #[test]
    fn evidence_ledger_captures_churn_context_in_repair_events() {
        // Under write churn, repair events in the evidence ledger must include
        // sufficient context for diagnosis.
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        // Inject corruption.
        device
            .write_block(&cx, BlockNumber(1), &vec![0xCC; block_size as usize])
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

        // Simulate some write churn before scrub.
        pipeline
            .mark_group_dirty(GroupNumber(0))
            .expect("mark dirty");

        let _report = pipeline.scrub_and_recover(&cx).expect("pipeline");

        // Parse evidence ledger and verify events are present.
        let records = crate::evidence::parse_evidence_ledger(pipeline.into_ledger());
        let corruption_events = records
            .iter()
            .filter(|r| r.event_type == EvidenceEventType::CorruptionDetected)
            .count();
        let repair_events = records
            .iter()
            .filter(|r| {
                r.event_type == EvidenceEventType::RepairAttempted
                    || r.event_type == EvidenceEventType::RepairSucceeded
                    || r.event_type == EvidenceEventType::RepairFailed
            })
            .count();

        assert!(
            corruption_events >= 1,
            "evidence must record corruption detection"
        );
        assert!(
            repair_events >= 1,
            "evidence must record repair attempt/outcome"
        );
    }

    #[test]
    fn no_false_clean_when_corruption_exists_under_heavy_churn() {
        // Invariant: scrub must NEVER report 0 corruption when blocks are
        // actually corrupt, regardless of write churn state.
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        // Corrupt multiple blocks.
        for block in [0, 3, 5] {
            device
                .write_block(&cx, BlockNumber(block), &vec![0xFF; block_size as usize])
                .expect("inject corruption");
        }

        let validator = CorruptBlockValidator::new(vec![0, 3, 5]);
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
        )
        .with_group_refresh_policy(
            GroupNumber(0),
            RefreshPolicy::Lazy {
                max_staleness: Duration::from_secs(3600),
            },
        );

        // Heavy write churn: 50 writes, all deferred (lazy within budget).
        for _ in 0..50 {
            pipeline
                .on_group_write(&cx, GroupNumber(0))
                .expect("churn write");
        }

        // Telemetry should show dirty state.
        let telemetry = pipeline.refresh_telemetry();
        assert_eq!(telemetry.dirty_groups, 1, "group must be dirty after churn");

        // Scrub must still find all 3 corrupt blocks.
        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert_eq!(
            report.total_corrupt, 3,
            "scrub must find all 3 corrupt blocks despite write churn (found {})",
            report.total_corrupt
        );
    }

    #[test]
    fn write_churn_with_staleness_timeout_still_recovers() {
        // Under write churn with staleness timeout, symbols get refreshed
        // but recovery must still work for newly-detected corruption.
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        let originals = write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
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
        )
        .with_group_refresh_policy(
            GroupNumber(0),
            RefreshPolicy::Lazy {
                max_staleness: Duration::from_millis(5),
            },
        );

        // First write sets dirty.
        pipeline
            .on_group_write(&cx, GroupNumber(0))
            .expect("first write");

        // Age it past staleness.
        if let Some(state) = pipeline.refresh_states.get_mut(&0) {
            state.dirty = true;
            state.dirty_since = Instant::now().checked_sub(Duration::from_millis(50));
        }
        // This triggers staleness refresh.
        pipeline
            .on_group_write(&cx, GroupNumber(0))
            .expect("stale write");

        // Group should be clean after refresh.
        assert!(!pipeline.is_group_dirty(GroupNumber(0)));

        // Now inject corruption after symbols are fresh.
        drop(pipeline);
        device
            .write_block(&cx, BlockNumber(4), &vec![0xAB; block_size as usize])
            .expect("inject corruption");

        let validator_corrupt = CorruptBlockValidator::new(vec![4]);
        let mut ledger_buf2 = Vec::new();
        let mut pipeline2 = ScrubWithRecovery::new(
            &device,
            &validator_corrupt,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf2,
            4,
        );

        let report = pipeline2.scrub_and_recover(&cx).expect("recovery");
        assert_eq!(report.total_corrupt, 1);
        assert_eq!(report.total_recovered, 1);
        let restored = device.read_block(&cx, BlockNumber(4)).expect("read");
        assert_eq!(
            restored.as_slice(),
            originals[4].as_slice(),
            "block 4 must be restored after staleness-refreshed symbols"
        );
    }

    // ── Stale-window SLO tests ────────────────────────────────────────────

    #[test]
    fn slo_no_breach_when_all_groups_fresh() {
        let slo = StaleWindowSlo::default();
        let telemetry = RefreshTelemetry {
            tracked_groups: 3,
            dirty_groups: 0,
            max_dirty_age_ms: 0,
            groups: vec![
                GroupRefreshSummary {
                    group: 0,
                    dirty: false,
                    dirty_age_ms: 0,
                    policy: "lazy(30000ms)".to_owned(),
                    since_last_refresh_ms: 1000,
                    writes_since_refresh: 0,
                    block_count_threshold: 0,
                },
                GroupRefreshSummary {
                    group: 1,
                    dirty: false,
                    dirty_age_ms: 0,
                    policy: "lazy(30000ms)".to_owned(),
                    since_last_refresh_ms: 2000,
                    writes_since_refresh: 10,
                    block_count_threshold: 0,
                },
                GroupRefreshSummary {
                    group: 2,
                    dirty: false,
                    dirty_age_ms: 0,
                    policy: "lazy(30000ms)".to_owned(),
                    since_last_refresh_ms: 500,
                    writes_since_refresh: 5,
                    block_count_threshold: 0,
                },
            ],
        };
        let eval = slo.evaluate(&telemetry);
        assert!(!eval.breached);
        assert_eq!(eval.groups_age_breached, 0);
        assert_eq!(eval.groups_writes_breached, 0);
    }

    #[test]
    fn slo_breach_when_age_exceeds_threshold() {
        let slo = StaleWindowSlo {
            max_age_ms: 60_000,
            max_writes: 5_000,
            percentile: 0.95,
        };
        let telemetry = RefreshTelemetry {
            tracked_groups: 2,
            dirty_groups: 2,
            max_dirty_age_ms: 120_000,
            groups: vec![
                GroupRefreshSummary {
                    group: 0,
                    dirty: true,
                    dirty_age_ms: 120_000, // 2 minutes — exceeds 60s SLO.
                    policy: "lazy(30000ms)".to_owned(),
                    since_last_refresh_ms: 120_000,
                    writes_since_refresh: 100,
                    block_count_threshold: 0,
                },
                GroupRefreshSummary {
                    group: 1,
                    dirty: true,
                    dirty_age_ms: 90_000, // 90s — also exceeds.
                    policy: "lazy(30000ms)".to_owned(),
                    since_last_refresh_ms: 90_000,
                    writes_since_refresh: 50,
                    block_count_threshold: 0,
                },
            ],
        };
        let eval = slo.evaluate(&telemetry);
        assert!(eval.breached);
        assert_eq!(eval.groups_age_breached, 2);
        assert!(eval.age_at_percentile_ms > 60_000);
    }

    #[test]
    fn slo_breach_when_writes_exceed_threshold() {
        let slo = StaleWindowSlo {
            max_age_ms: 60_000,
            max_writes: 5_000,
            percentile: 0.5, // p50 for 2-group test.
        };
        let telemetry = RefreshTelemetry {
            tracked_groups: 2,
            dirty_groups: 2,
            max_dirty_age_ms: 10_000,
            groups: vec![
                GroupRefreshSummary {
                    group: 0,
                    dirty: true,
                    dirty_age_ms: 5_000,
                    policy: "hybrid(age=30000ms,blocks=10000)".to_owned(),
                    since_last_refresh_ms: 5_000,
                    writes_since_refresh: 8_000, // Exceeds 5000.
                    block_count_threshold: 10_000,
                },
                GroupRefreshSummary {
                    group: 1,
                    dirty: true,
                    dirty_age_ms: 10_000,
                    policy: "hybrid(age=30000ms,blocks=10000)".to_owned(),
                    since_last_refresh_ms: 10_000,
                    writes_since_refresh: 6_000, // Also exceeds.
                    block_count_threshold: 10_000,
                },
            ],
        };
        let eval = slo.evaluate(&telemetry);
        assert!(eval.breached);
        assert_eq!(eval.groups_writes_breached, 2);
    }

    #[test]
    fn slo_breach_single_outlier_at_p95_boundary() {
        // 10 groups, 1 outlier (10% violation rate).  With p95, the p95 index
        // lands on the outlier: round(0.95 * 9) = round(8.55) = 9.
        let slo = StaleWindowSlo {
            max_age_ms: 60_000,
            max_writes: 5_000,
            percentile: 0.95,
        };
        let mut groups = Vec::new();
        for i in 0..10_u32 {
            groups.push(GroupRefreshSummary {
                group: i,
                dirty: i == 9,
                dirty_age_ms: if i == 9 { 100_000 } else { 1_000 },
                policy: "lazy(30000ms)".to_owned(),
                since_last_refresh_ms: if i == 9 { 100_000 } else { 1_000 },
                writes_since_refresh: if i == 9 { 10_000 } else { 10 },
                block_count_threshold: 0,
            });
        }
        let telemetry = RefreshTelemetry {
            tracked_groups: 10,
            dirty_groups: 1,
            max_dirty_age_ms: 100_000,
            groups,
        };
        let eval = slo.evaluate(&telemetry);
        // p95 index = 9 → outlier value → breach.
        assert!(eval.breached);
        assert_eq!(eval.groups_age_breached, 1);
    }

    #[test]
    fn slo_no_breach_when_outlier_below_percentile() {
        // 100 groups, 1 outlier (1% violation rate).  With p95, 99% are healthy
        // which exceeds the 95% requirement → no breach.
        let slo = StaleWindowSlo {
            max_age_ms: 60_000,
            max_writes: 5_000,
            percentile: 0.95,
        };
        let mut groups = Vec::new();
        for i in 0..100_u32 {
            groups.push(GroupRefreshSummary {
                group: i,
                dirty: i == 99,
                dirty_age_ms: if i == 99 { 100_000 } else { 1_000 },
                policy: "lazy(30000ms)".to_owned(),
                since_last_refresh_ms: if i == 99 { 100_000 } else { 1_000 },
                writes_since_refresh: if i == 99 { 10_000 } else { 10 },
                block_count_threshold: 0,
            });
        }
        let telemetry = RefreshTelemetry {
            tracked_groups: 100,
            dirty_groups: 1,
            max_dirty_age_ms: 100_000,
            groups,
        };
        let eval = slo.evaluate(&telemetry);
        // p95 index = round(0.95 * 99) = round(94.05) = 94. Ages[94] = 1000 < 60000.
        assert!(!eval.breached, "1% violation should not breach p95 SLO");
        // But individual group counts still reflect the 1 outlier.
        assert_eq!(eval.groups_age_breached, 1);
        assert_eq!(eval.groups_writes_breached, 1);
    }

    #[test]
    fn slo_empty_groups_no_breach() {
        let slo = StaleWindowSlo::default();
        let telemetry = RefreshTelemetry {
            tracked_groups: 0,
            dirty_groups: 0,
            max_dirty_age_ms: 0,
            groups: vec![],
        };
        let eval = slo.evaluate(&telemetry);
        assert!(!eval.breached);
        assert_eq!(eval.total_groups, 0);
    }

    #[test]
    fn percentile_index_boundary_cases() {
        assert_eq!(percentile_index(1, 0.0), 0);
        assert_eq!(percentile_index(1, 1.0), 0);
        assert_eq!(percentile_index(10, 0.0), 0);
        assert_eq!(percentile_index(10, 1.0), 9);
        assert_eq!(percentile_index(10, 0.5), 5); // round(0.5 * 9) = 5
        assert_eq!(percentile_index(100, 0.95), 94); // round(0.95 * 99) = 94
        assert_eq!(percentile_index(0, 0.95), 0);
    }

    // ── RepairPipelineMetrics tests ───────────────────────────────────────

    #[test]
    fn atomic_metrics_default_is_zeroed() {
        let metrics = RepairPipelineMetrics::new();
        let snap = metrics.snapshot();
        assert_eq!(snap.groups_scrubbed, 0);
        assert_eq!(snap.corruption_detected, 0);
        assert_eq!(snap.decode_attempts, 0);
        assert_eq!(snap.decode_successes, 0);
        assert_eq!(snap.symbol_refresh_count, 0);
        assert_eq!(snap.symbol_staleness_max_seconds, 0);
        assert_eq!(snap.blocks_scanned, 0);
        assert_eq!(snap.blocks_recovered, 0);
        assert_eq!(snap.blocks_unrecoverable, 0);
        assert_eq!(snap.scrub_rounds_completed, 0);
    }

    #[test]
    fn atomic_metrics_increment_and_snapshot() {
        let metrics = RepairPipelineMetrics::new();
        metrics.add_groups_scrubbed(5);
        metrics.add_corruption_detected(2);
        metrics.add_decode_attempts(3);
        metrics.add_decode_successes(1);
        metrics.add_symbol_refresh_count(4);
        metrics.add_blocks_scanned(1000);
        metrics.add_blocks_recovered(7);
        metrics.add_blocks_unrecoverable(2);
        metrics.add_scrub_rounds_completed(1);
        metrics
            .symbol_staleness_max_seconds
            .store(42, Ordering::Relaxed);

        let snap = metrics.snapshot();
        assert_eq!(snap.groups_scrubbed, 5);
        assert_eq!(snap.corruption_detected, 2);
        assert_eq!(snap.decode_attempts, 3);
        assert_eq!(snap.decode_successes, 1);
        assert_eq!(snap.symbol_refresh_count, 4);
        assert_eq!(snap.blocks_scanned, 1000);
        assert_eq!(snap.blocks_recovered, 7);
        assert_eq!(snap.blocks_unrecoverable, 2);
        assert_eq!(snap.scrub_rounds_completed, 1);
        assert_eq!(snap.symbol_staleness_max_seconds, 42);
    }

    #[test]
    fn atomic_metrics_saturate_at_numeric_limits() {
        let metrics = RepairPipelineMetrics::new();
        metrics
            .groups_scrubbed
            .store(u64::MAX - 1, Ordering::Relaxed);
        metrics
            .corruption_detected
            .store(u64::MAX - 1, Ordering::Relaxed);
        metrics
            .decode_attempts
            .store(u64::MAX - 1, Ordering::Relaxed);
        metrics
            .decode_successes
            .store(u64::MAX - 1, Ordering::Relaxed);
        metrics
            .symbol_refresh_count
            .store(u64::MAX - 1, Ordering::Relaxed);
        metrics
            .blocks_scanned
            .store(u64::MAX - 1, Ordering::Relaxed);
        metrics
            .blocks_recovered
            .store(u64::MAX - 1, Ordering::Relaxed);
        metrics
            .blocks_unrecoverable
            .store(u64::MAX - 1, Ordering::Relaxed);
        metrics
            .scrub_rounds_completed
            .store(u64::MAX - 1, Ordering::Relaxed);

        metrics.add_groups_scrubbed(5);
        metrics.add_corruption_detected(5);
        metrics.add_decode_attempts(5);
        metrics.add_decode_successes(5);
        metrics.add_symbol_refresh_count(5);
        metrics.add_blocks_scanned(5);
        metrics.add_blocks_recovered(5);
        metrics.add_blocks_unrecoverable(5);
        metrics.add_scrub_rounds_completed(5);

        let snap = metrics.snapshot();
        assert_eq!(snap.groups_scrubbed, u64::MAX);
        assert_eq!(snap.corruption_detected, u64::MAX);
        assert_eq!(snap.decode_attempts, u64::MAX);
        assert_eq!(snap.decode_successes, u64::MAX);
        assert_eq!(snap.symbol_refresh_count, u64::MAX);
        assert_eq!(snap.blocks_scanned, u64::MAX);
        assert_eq!(snap.blocks_recovered, u64::MAX);
        assert_eq!(snap.blocks_unrecoverable, u64::MAX);
        assert_eq!(snap.scrub_rounds_completed, u64::MAX);
    }

    #[test]
    fn atomic_metrics_serde_round_trip() {
        let metrics = RepairPipelineMetrics::new();
        metrics.add_groups_scrubbed(10);
        metrics.add_corruption_detected(3);
        metrics
            .symbol_staleness_max_seconds
            .store(15, Ordering::Relaxed);

        let snap = metrics.snapshot();
        let json = serde_json::to_string_pretty(&snap).expect("serialize");
        let parsed: RepairMetricsSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, snap);
    }

    #[test]
    fn atomic_metrics_concurrent_updates() {
        let metrics = Arc::new(RepairPipelineMetrics::new());
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let m = Arc::clone(&metrics);
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        m.add_groups_scrubbed(1);
                        m.add_blocks_scanned(10);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread join");
        }
        let snap = metrics.snapshot();
        assert_eq!(snap.groups_scrubbed, 400);
        assert_eq!(snap.blocks_scanned, 4000);
    }

    #[test]
    fn atomic_metrics_staleness_gauge_from_telemetry() {
        let metrics = RepairPipelineMetrics::new();
        let telemetry = RefreshTelemetry {
            tracked_groups: 2,
            dirty_groups: 1,
            max_dirty_age_ms: 7500,
            groups: vec![
                GroupRefreshSummary {
                    group: 0,
                    dirty: false,
                    dirty_age_ms: 0,
                    policy: "eager".to_owned(),
                    since_last_refresh_ms: 2000,
                    writes_since_refresh: 0,
                    block_count_threshold: 0,
                },
                GroupRefreshSummary {
                    group: 1,
                    dirty: true,
                    dirty_age_ms: 7500,
                    policy: "lazy(30000ms)".to_owned(),
                    since_last_refresh_ms: 7500,
                    writes_since_refresh: 100,
                    block_count_threshold: 0,
                },
            ],
        };
        metrics.update_staleness_gauge(&telemetry);
        assert_eq!(
            metrics.symbol_staleness_max_seconds.load(Ordering::Relaxed),
            7 // 7500ms / 1000 = 7 (integer division)
        );
    }

    #[test]
    fn atomic_metrics_wired_into_pipeline_scrub() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_count = 8;

        write_source_blocks(&cx, &device, BlockNumber(0), source_count);
        bootstrap_storage(&cx, &device, layout, BlockNumber(0), source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let groups = vec![GroupConfig {
            layout,
            source_first_block: BlockNumber(0),
            source_block_count: source_count,
        }];

        let atomic = RepairPipelineMetrics::new();
        let atomic_clone = atomic.clone();

        let mut ledger_buf = Vec::new();
        let mut pipeline =
            ScrubWithRecovery::new(&device, &validator, test_uuid(), groups, &mut ledger_buf, 4)
                .with_metrics(atomic);

        // Run scrub (no corruption)
        let report = pipeline.scrub_and_recover(&cx).expect("scrub");
        assert_eq!(report.total_corrupt, 0);

        // Verify atomic metrics were updated
        let snap = atomic_clone.snapshot();
        assert_eq!(snap.groups_scrubbed, 1);
        assert!(snap.blocks_scanned > 0);
        assert_eq!(snap.corruption_detected, 0);
        assert_eq!(snap.decode_attempts, 0);
    }

    #[test]
    fn recovery_refresh_resets_dirty_state_and_atomic_staleness() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_count = 8;

        write_source_blocks(&cx, &device, BlockNumber(0), source_count);
        bootstrap_storage(&cx, &device, layout, BlockNumber(0), source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: BlockNumber(0),
            source_block_count: source_count,
        };

        let atomic = RepairPipelineMetrics::new();
        let atomic_clone = atomic.clone();
        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        )
        .with_metrics(atomic);

        let now = Instant::now();
        let state = pipeline.refresh_states.get_mut(&0).expect("group 0 state");
        state.dirty = true;
        state.dirty_since = Some(
            now.checked_sub(Duration::from_secs(4))
                .expect("valid instant math"),
        );
        state.last_refresh = now
            .checked_sub(Duration::from_secs(7))
            .expect("valid instant math");
        state.writes_since_refresh = 3;
        pipeline.sync_atomic_staleness_gauge();

        assert_eq!(
            atomic_clone
                .symbol_staleness_max_seconds
                .load(Ordering::Relaxed),
            7
        );
        assert!(pipeline.refresh_symbols_after_recovery(&cx, &group_cfg));

        let refreshed = pipeline.refresh_states.get(&0).expect("group 0 state");
        assert!(
            !refreshed.dirty,
            "recovery refresh should clear dirty state"
        );
        assert_eq!(
            refreshed.dirty_since, None,
            "recovery refresh should clear dirty age"
        );
        assert_eq!(
            refreshed.writes_since_refresh, 0,
            "recovery refresh should reset write count"
        );
        assert!(
            refreshed.last_refresh >= now,
            "recovery refresh should advance last_refresh"
        );
        assert_eq!(
            atomic_clone
                .symbol_staleness_max_seconds
                .load(Ordering::Relaxed),
            0,
            "atomic staleness gauge should be refreshed after recovery symbol regeneration"
        );
    }

    #[test]
    fn atomic_metrics_wired_into_daemon() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_count = 8;

        write_source_blocks(&cx, &device, BlockNumber(0), source_count);
        bootstrap_storage(&cx, &device, layout, BlockNumber(0), source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let groups = vec![GroupConfig {
            layout,
            source_first_block: BlockNumber(0),
            source_block_count: source_count,
        }];

        let atomic = RepairPipelineMetrics::new();
        let atomic_clone = atomic.clone();

        let mut ledger_buf = Vec::new();
        let pipeline =
            ScrubWithRecovery::new(&device, &validator, test_uuid(), groups, &mut ledger_buf, 4)
                .with_metrics(atomic);

        let mut daemon = ScrubDaemon::new(pipeline, ScrubDaemonConfig::default());
        daemon.run_one_round(&cx).expect("daemon round");

        let snap = atomic_clone.snapshot();
        assert_eq!(snap.groups_scrubbed, 1, "daemon round should scrub 1 group");
        assert!(snap.blocks_scanned > 0, "should have scanned blocks");
        assert_eq!(snap.scrub_rounds_completed, 1, "1 round completed");
    }

    // ── End-to-end distributed repair pipeline ────────────────────────

    /// E2E test: detect corruption → encode symbols → exchange via TCP →
    /// decode → verify recovery. Exercises the full distributed repair
    /// pipeline across two simulated hosts using the exchange protocol.
    #[test]
    #[expect(clippy::too_many_lines)]
    fn distributed_repair_pipeline_e2e() {
        use crate::codec::{decode_group, encode_group};
        use crate::exchange::{self, InMemoryStore, LookupResult, Store};
        use std::sync::Arc;

        let cx = Cx::for_testing();
        let block_size = 4096_u32;
        let source_count = 16_u32;
        let repair_count = 8_u32; // Need enough symbols for RaptorQ overhead
        let fs_uuid = test_uuid();

        // ── Step 1: Create device with known data ─────────────────────
        let device = MemBlockDevice::new(block_size, u64::from(source_count + repair_count + 10));
        let group_first_block = BlockNumber(0);

        // Write known patterns to source blocks.
        for i in 0..source_count {
            let data = vec![(i & 0xFF) as u8; block_size as usize];
            device
                .write_block(&cx, BlockNumber(u64::from(i)), &data)
                .expect("write source block");
        }

        // ── Step 2: Encode repair symbols ─────────────────────────────
        let encoded = encode_group(
            &cx,
            &device,
            &fs_uuid,
            GroupNumber(0),
            group_first_block,
            source_count,
            repair_count,
        )
        .expect("encode repair symbols");

        assert!(!encoded.repair_symbols.is_empty(), "must produce symbols");

        // ── Step 3: Store symbols on "Host A" exchange server ─────────
        let store = Arc::new(InMemoryStore::new());
        let symbol_pairs: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .iter()
            .map(|s| (s.esi, s.data.clone()))
            .collect();

        // Put symbols into the store at generation 1 via the Store trait.
        store
            .put_symbols(&cx, 0, 1, &symbol_pairs)
            .expect("store symbols");

        // Start TCP exchange server on a random port.
        let server_config = exchange::Config::default();
        let server = exchange::Server::bind("127.0.0.1:0", Arc::clone(&store), server_config)
            .expect("bind server");
        let server_addr = server.local_addr().expect("server addr");

        // Run server in a background thread for one request.
        let server_handle = std::thread::spawn(move || {
            let cx = Cx::for_testing();
            let _ = server.serve_once(&cx);
        });

        // ── Step 4: Inject corruption ─────────────────────────────────
        let corrupt_indices = vec![3_u32, 7, 11]; // Corrupt 3 blocks.
        for &idx in &corrupt_indices {
            let corrupt_data = vec![0xFF_u8; block_size as usize];
            device
                .write_block(&cx, BlockNumber(u64::from(idx)), &corrupt_data)
                .expect("inject corruption");
        }

        // Verify corruption is injected.
        for &idx in &corrupt_indices {
            let data = device
                .read_block(&cx, BlockNumber(u64::from(idx)))
                .expect("read corrupt");
            assert_eq!(data.as_slice()[0], 0xFF, "block {idx} should be corrupted");
        }

        // ── Step 5: "Host B" retrieves symbols via exchange ───────────
        let client_config = exchange::Config::default();
        let client = exchange::Client::new(server_addr, client_config).expect("client connect");

        let lookup = client.get_symbols(&cx, 0, 1).expect("get symbols");
        let retrieved = match lookup {
            LookupResult::Found(stored) => {
                assert_eq!(stored.generation, 1);
                stored.symbols
            }
            other => {
                assert!(
                    matches!(other, LookupResult::Found(_)),
                    "expected Found, got {other:?}"
                );
                return;
            }
        };

        // Wait for server thread to finish.
        server_handle.join().expect("server thread");

        // ── Step 6: Decode and recover ────────────────────────────────
        let outcome = decode_group(
            &cx,
            &device,
            &fs_uuid,
            GroupNumber(0),
            group_first_block,
            source_count,
            &corrupt_indices,
            &retrieved,
        )
        .expect("decode group");

        assert!(
            outcome.complete,
            "decode must fully recover all corrupt blocks"
        );
        assert_eq!(
            outcome.recovered.len(),
            corrupt_indices.len(),
            "must recover exactly the corrupt blocks"
        );

        // ── Step 7: Write back recovered data and verify ──────────────
        for recovered in &outcome.recovered {
            device
                .write_block(&cx, recovered.block, &recovered.data)
                .expect("write recovered block");
        }

        // Verify all blocks match original patterns.
        for i in 0..source_count {
            let data = device
                .read_block(&cx, BlockNumber(u64::from(i)))
                .expect("read verified");
            let expected_byte = (i & 0xFF) as u8;
            assert!(
                data.as_slice().iter().all(|&b| b == expected_byte),
                "block {i} data mismatch after recovery"
            );
        }
    }

    /// Verify the full scrub → detect → recover pipeline with the
    /// orchestrator (no TCP exchange, purely local symbol recovery).
    #[test]
    fn local_scrub_detect_recover_pipeline() {
        use crate::codec::encode_group;

        let cx = Cx::for_testing();
        let block_size = 4096_u32;
        let source_count = 32_u32;
        let repair_count = 10_u32; // Need enough symbols for RaptorQ overhead
        let fs_uuid = test_uuid();

        let device = MemBlockDevice::new(block_size, u64::from(source_count + repair_count + 10));

        // Write unique patterns.
        for i in 0..source_count {
            let data = vec![(i & 0xFF) as u8; block_size as usize];
            device
                .write_block(&cx, BlockNumber(u64::from(i)), &data)
                .expect("write");
        }

        // Encode symbols.
        let encoded = encode_group(
            &cx,
            &device,
            &fs_uuid,
            GroupNumber(0),
            BlockNumber(0),
            source_count,
            repair_count,
        )
        .expect("encode");

        // Corrupt blocks.
        let corrupt_blocks = vec![5_u32, 15, 25];
        for &idx in &corrupt_blocks {
            device
                .write_block(
                    &cx,
                    BlockNumber(u64::from(idx)),
                    &vec![0xDE; block_size as usize],
                )
                .expect("corrupt");
        }

        // Recover using local symbols.
        let repair_pairs: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .iter()
            .map(|s| (s.esi, s.data.clone()))
            .collect();

        let outcome = crate::codec::decode_group(
            &cx,
            &device,
            &fs_uuid,
            GroupNumber(0),
            BlockNumber(0),
            source_count,
            &corrupt_blocks,
            &repair_pairs,
        )
        .expect("decode");

        assert!(outcome.complete, "recovery must be complete");
        assert_eq!(outcome.recovered.len(), 3);

        // Write back and verify.
        for rec in &outcome.recovered {
            device
                .write_block(&cx, rec.block, &rec.data)
                .expect("writeback");
        }

        for i in 0..source_count {
            let data = device
                .read_block(&cx, BlockNumber(u64::from(i)))
                .expect("verify");
            let expected = (i & 0xFF) as u8;
            assert!(
                data.as_slice().iter().all(|&b| b == expected),
                "block {i} not restored"
            );
        }
    }
}
