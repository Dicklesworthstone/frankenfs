//! Thread-per-core dispatch for FUSE (Seastar/Glommio model).
//!
//! Assigns each FUSE worker to a specific CPU core with core-local
//! caches and per-core metrics, eliminating cross-core synchronization
//! for the common read path.
//!
//! # Design
//!
//! - **Core-pinned workers**: each worker thread is bound to a specific
//!   CPU core via `sched_setaffinity`.
//! - **Per-core cache partition**: each core owns a private slice of the
//!   ARC cache (size = total_cache / num_cores), eliminating cache-line
//!   bouncing on the read path.
//! - **Request routing**: FUSE requests are routed to the core that
//!   "owns" the target inode (inode % num_cores), ensuring locality.
//! - **Cross-core fallback**: when a request must access data owned by
//!   another core, it uses a lock-free message channel.
//!
//! # Failure modes (from Alien CS Graveyard)
//!
//! 1. **Work imbalance**: hot inodes cause one core to saturate.
//!    Mitigation: steal-half work-stealing when queue depth > 2x average.
//! 2. **Cross-core joins**: directory operations may span multiple cores.
//!    Mitigation: directory ops use a shared path, not per-core dispatch.
//! 3. **Debugging difficulty**: per-core state harder to inspect.
//!    Mitigation: per-core metrics exported via unified stats endpoint.
//!
//! # `unsafe_code = "forbid"` Compliance
//!
//! CPU affinity requires `libc::sched_setaffinity` which is unsafe.
//! We use the safe `nix` crate wrapper instead... but since ffs-fuse
//! forbids unsafe, we use a **best-effort** approach: the prototype
//! uses standard threads with advisory core assignment via thread naming
//! and OS scheduler hints. True pinning requires a future `pin` feature.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

// ── Per-core metrics ───────────────────────────────────────────────────────

/// Metrics for a single core's dispatch lane.
#[derive(Debug)]
pub struct CoreMetrics {
    /// Requests processed by this core.
    pub requests: AtomicU64,
    /// Currently active/pending requests in this core's queue.
    pub pending_requests: AtomicI64,
    /// Cache hits on this core's local partition.
    pub cache_hits: AtomicU64,
    /// Cache misses requiring cross-core or backing store access.
    pub cache_misses: AtomicU64,
    /// Requests stolen from this core by another (work-stealing).
    pub stolen_from: AtomicU64,
    /// Requests this core stole from another.
    pub stolen_to: AtomicU64,
}

impl CoreMetrics {
    #[allow(
        deprecated,
        reason = "try_update requires Rust 1.95; workspace MSRV is 1.85"
    )]
    fn saturating_add_u64(counter: &AtomicU64, delta: u64) {
        while counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(delta))
            })
            .is_err()
        {
            std::hint::spin_loop();
        }
    }

    #[allow(
        deprecated,
        reason = "try_update requires Rust 1.95; workspace MSRV is 1.85"
    )]
    fn saturating_add_i64(counter: &AtomicI64, delta: i64) {
        while counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(delta))
            })
            .is_err()
        {
            std::hint::spin_loop();
        }
    }

    #[allow(
        deprecated,
        reason = "try_update requires Rust 1.95; workspace MSRV is 1.85"
    )]
    fn saturating_decrement_nonnegative_i64(counter: &AtomicI64) {
        while counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(1).max(0))
            })
            .is_err()
        {
            std::hint::spin_loop();
        }
    }

    /// Create zeroed metrics.
    #[must_use]
    pub fn new() -> Self {
        Self {
            requests: AtomicU64::new(0),
            pending_requests: std::sync::atomic::AtomicI64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            stolen_from: AtomicU64::new(0),
            stolen_to: AtomicU64::new(0),
        }
    }

    /// Record a request beginning processing.
    pub fn begin_request(&self) {
        Self::saturating_add_i64(&self.pending_requests, 1);
    }

    /// Record a request processed.
    pub fn record_request(&self) {
        Self::saturating_add_u64(&self.requests, 1);
        Self::saturating_decrement_nonnegative_i64(&self.pending_requests);
    }

    /// Record a cache hit.
    pub fn record_hit(&self) {
        Self::saturating_add_u64(&self.cache_hits, 1);
    }

    /// Record a cache miss.
    pub fn record_miss(&self) {
        Self::saturating_add_u64(&self.cache_misses, 1);
    }

    /// Snapshot the metrics for reporting.
    #[must_use]
    pub fn snapshot(&self) -> CoreMetricsSnapshot {
        CoreMetricsSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            pending_requests: self.pending_requests.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            stolen_from: self.stolen_from.load(Ordering::Relaxed),
            stolen_to: self.stolen_to.load(Ordering::Relaxed),
        }
    }
}

impl Default for CoreMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Immutable snapshot of per-core metrics for reporting.
#[derive(Debug, Clone, Copy)]
pub struct CoreMetricsSnapshot {
    pub requests: u64,
    pub pending_requests: i64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub stolen_from: u64,
    pub stolen_to: u64,
}

/// Advisory work-stealing plan for one receiving core.
///
/// The dispatcher does not own caller request queues, so applying this plan is
/// the caller's responsibility. `record_steal` records only metrics.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StealPlan {
    pub receiver_core: u32,
    pub donor_core: u32,
    pub receiver_pending: i64,
    pub donor_pending: i64,
    pub average_pending: f64,
    pub transfer_count: u64,
}

impl CoreMetricsSnapshot {
    /// Cache hit rate as a fraction [0.0, 1.0].
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        if self.cache_hits == 0 && self.cache_misses == 0 {
            return 0.0;
        }
        let total = self.cache_hits as f64 + self.cache_misses as f64;
        self.cache_hits as f64 / total
    }
}

// ── Core assignment ────────────────────────────────────────────────────────

/// Route an inode to a core.
///
/// Uses a mixed inode hash for locality and load distribution.
#[must_use]
#[inline]
fn mixed_inode_fold(ino: u64) -> u32 {
    // Mix the inode number to avoid pathological patterns.
    // FNV-1a-like mixing: multiply by a prime, XOR-fold.
    let mixed = ino.wrapping_mul(0x517c_c1b7_2722_0a95);
    #[expect(clippy::cast_possible_truncation)] // intentional 64→32 fold
    {
        (mixed ^ (mixed >> 32)) as u32
    }
}

/// Route an inode to a core.
///
/// Uses a mixed inode hash for locality and load distribution.
#[must_use]
#[inline]
pub fn inode_to_core(ino: u64, num_cores: u32) -> u32 {
    if num_cores == 0 {
        return 0;
    }
    let folded = mixed_inode_fold(ino);
    if num_cores.is_power_of_two() {
        folded & (num_cores - 1)
    } else {
        folded % num_cores
    }
}

/// Route a (parent, name) lookup to a core.
///
/// Directory lookups use the parent inode for routing so that
/// directory scans stay on one core.
#[must_use]
#[inline]
pub fn lookup_to_core(parent_ino: u64, num_cores: u32) -> u32 {
    inode_to_core(parent_ino, num_cores)
}

// ── Dispatch configuration ─────────────────────────────────────────────────

/// Thread-per-core dispatch configuration.
#[derive(Debug, Clone)]
pub struct PerCoreConfig {
    /// Number of cores to use (0 = auto-detect).
    pub num_cores: u32,
    /// Per-core cache size in blocks.
    pub cache_blocks_per_core: u32,
    /// Work-stealing threshold: steal when queue depth exceeds
    /// this multiple of the average across cores.
    /// Non-finite or non-positive values are sanitized to the default.
    pub steal_threshold: f64,
    /// Whether to use advisory CPU affinity (thread naming only,
    /// since true pinning requires unsafe).
    pub advisory_affinity: bool,
}

impl Default for PerCoreConfig {
    #[expect(clippy::cast_possible_truncation)] // .min(16) always fits u32
    fn default() -> Self {
        let num_cores = std::thread::available_parallelism().map_or(4, |n| n.get().min(16) as u32);
        Self {
            num_cores,
            cache_blocks_per_core: 4096,
            steal_threshold: Self::DEFAULT_STEAL_THRESHOLD,
            advisory_affinity: true,
        }
    }
}

impl PerCoreConfig {
    const DEFAULT_STEAL_THRESHOLD: f64 = 2.0;

    /// Resolved number of cores.
    #[must_use]
    #[expect(clippy::cast_possible_truncation)] // .min(16) always fits u32
    pub fn resolved_cores(&self) -> u32 {
        if self.num_cores == 0 {
            std::thread::available_parallelism().map_or(4, |n| n.get().min(16) as u32)
        } else {
            self.num_cores
        }
    }

    /// Normalized work-stealing threshold.
    ///
    /// Non-finite or non-positive values are treated as the default
    /// to avoid disabling stealing via NaN/negative division.
    #[must_use]
    pub fn normalized_steal_threshold(&self) -> f64 {
        if self.steal_threshold.is_finite() && self.steal_threshold > 0.0 {
            self.steal_threshold
        } else {
            Self::DEFAULT_STEAL_THRESHOLD
        }
    }

    /// Total cache size across all cores.
    #[must_use]
    pub fn total_cache_blocks(&self) -> u64 {
        u64::from(self.resolved_cores()) * u64::from(self.cache_blocks_per_core)
    }
}

// ── Dispatcher ─────────────────────────────────────────────────────────────

/// Thread-per-core dispatch coordinator.
///
/// Tracks per-core metrics and provides routing decisions.
/// The actual FUSE request handling is done by the caller;
/// this struct provides the routing and metrics infrastructure.
pub struct PerCoreDispatcher {
    config: PerCoreConfig,
    resolved_cores: u32,
    core_mask: Option<u32>,
    core_metrics: Vec<Arc<CoreMetrics>>,
}

impl PerCoreDispatcher {
    fn pending_depth(&self, core_idx: usize) -> i64 {
        self.core_metrics[core_idx]
            .pending_requests
            .load(Ordering::Relaxed)
            .max(0)
    }

    /// Create a new dispatcher with the given configuration.
    #[must_use]
    pub fn new(config: PerCoreConfig) -> Self {
        let resolved_cores = config.resolved_cores();
        let n = resolved_cores as usize;
        let core_mask = resolved_cores
            .is_power_of_two()
            .then_some(resolved_cores.saturating_sub(1));
        let core_metrics = (0..n).map(|_| Arc::new(CoreMetrics::new())).collect();
        Self {
            config,
            resolved_cores,
            core_mask,
            core_metrics,
        }
    }

    /// Number of cores.
    #[must_use]
    pub fn num_cores(&self) -> u32 {
        self.resolved_cores
    }

    /// Get metrics for a specific core.
    #[must_use]
    pub fn core_metrics(&self, core: u32) -> Option<&Arc<CoreMetrics>> {
        self.core_metrics.get(core as usize)
    }

    /// Route an inode-based request to a core.
    #[must_use]
    pub fn route_inode(&self, ino: u64) -> u32 {
        let folded = mixed_inode_fold(ino);
        self.core_mask
            .map_or_else(|| folded % self.resolved_cores, |mask| folded & mask)
    }

    /// Route a lookup request to a core.
    #[must_use]
    pub fn route_lookup(&self, parent_ino: u64) -> u32 {
        self.route_inode(parent_ino)
    }

    /// Check if work-stealing should be triggered for `core`.
    ///
    /// Returns `true` when `steal_plan_for(core)` can name a deterministic
    /// donor and bounded transfer count.
    #[must_use]
    pub fn should_steal(&self, core: u32) -> bool {
        let n = self.core_metrics.len();
        if n < 2 {
            return false;
        }
        let receiver_idx = core as usize;
        if receiver_idx >= n {
            return false;
        }

        let Ok(core_count) = i64::try_from(n) else {
            return false;
        };

        let mut total = 0_i64;
        let mut receiver_pending = 0_i64;
        let mut donor_pending = 0_i64;

        for idx in 0..n {
            let depth = self.pending_depth(idx);
            total = total.saturating_add(depth);
            if idx == receiver_idx {
                receiver_pending = depth;
            } else {
                donor_pending = donor_pending.max(depth);
            }
        }

        if total < core_count {
            return false;
        }

        let avg = total as f64 / n as f64;
        let mine = receiver_pending as f64;
        if mine >= avg / self.config.normalized_steal_threshold() {
            return false;
        }

        donor_pending > receiver_pending
    }

    /// Build an advisory plan for `receiver_core` to steal pending work.
    ///
    /// Donor selection is deterministic: choose the core with the highest
    /// pending depth, breaking ties by the lowest core index. The transfer
    /// count is half the pending-depth gap, rounded down and bounded to at
    /// least one when stealing is justified. Pending depths are snapshots, so
    /// callers should treat the plan as advisory and re-check their queues
    /// before moving work.
    #[must_use]
    pub fn steal_plan_for(&self, receiver_core: u32) -> Option<StealPlan> {
        let n = self.core_metrics.len();
        if n < 2 {
            return None;
        }
        let receiver_idx = receiver_core as usize;
        if receiver_idx >= n {
            return None;
        }

        let Ok(core_count) = i64::try_from(n) else {
            return None;
        };

        let mut total = 0_i64;
        let mut receiver_pending = 0_i64;
        let mut donor: Option<(usize, i64)> = None;

        for idx in 0..n {
            let depth = self.pending_depth(idx);
            total = total.saturating_add(depth);
            if idx == receiver_idx {
                receiver_pending = depth;
                continue;
            }

            match donor {
                Some((donor_idx, donor_pending))
                    if donor_pending > depth || (donor_pending == depth && donor_idx < idx) => {}
                _ => donor = Some((idx, depth)),
            }
        }

        // Do not steal if the system is essentially idle.
        // We need at least an average of 1 request per core to justify the
        // cross-core synchronization overhead of stealing.
        if total < core_count {
            return None;
        }

        let avg = total as f64 / n as f64;
        let mine = receiver_pending as f64;

        // This core is idle relative to average queue depth — try to steal work.
        if mine >= avg / self.config.normalized_steal_threshold() {
            return None;
        }

        let (donor_idx, donor_pending) = donor?;

        if donor_pending <= receiver_pending {
            return None;
        }

        let pending_gap = donor_pending.saturating_sub(receiver_pending);
        let transfer_count = u64::try_from((pending_gap / 2).max(1)).ok()?;
        let donor_core = u32::try_from(donor_idx).ok()?;

        Some(StealPlan {
            receiver_core,
            donor_core,
            receiver_pending,
            donor_pending,
            average_pending: avg,
            transfer_count,
        })
    }

    /// Record that a caller applied a previously computed steal plan.
    ///
    /// This only updates observability counters. It deliberately leaves
    /// pending-request depths unchanged because request queues are owned by the
    /// caller, not by this advisory dispatcher.
    pub fn record_steal(&self, plan: &StealPlan) {
        let Some(donor) = self.core_metrics(plan.donor_core) else {
            return;
        };
        let Some(receiver) = self.core_metrics(plan.receiver_core) else {
            return;
        };

        CoreMetrics::saturating_add_u64(&donor.stolen_from, plan.transfer_count);
        CoreMetrics::saturating_add_u64(&receiver.stolen_to, plan.transfer_count);
    }

    /// Aggregate metrics across all cores.
    #[must_use]
    pub fn aggregate_metrics(&self) -> AggregateMetrics {
        let mut total_requests = 0_u64;
        let mut total_pending_requests = 0_i64;
        let mut total_hits = 0_u64;
        let mut total_misses = 0_u64;
        let mut total_hits_for_rate = 0.0_f64;
        let mut total_misses_for_rate = 0.0_f64;
        let mut per_core = Vec::with_capacity(self.core_metrics.len());

        for metrics in &self.core_metrics {
            let snap = metrics.snapshot();
            total_requests = total_requests.saturating_add(snap.requests);
            total_pending_requests = total_pending_requests.saturating_add(snap.pending_requests);
            total_hits = total_hits.saturating_add(snap.cache_hits);
            total_misses = total_misses.saturating_add(snap.cache_misses);
            total_hits_for_rate += snap.cache_hits as f64;
            total_misses_for_rate += snap.cache_misses as f64;
            per_core.push(snap);
        }

        let total_io_for_rate = total_hits_for_rate + total_misses_for_rate;
        let hit_rate = if total_hits == 0 && total_misses == 0 {
            0.0
        } else {
            total_hits_for_rate / total_io_for_rate
        };

        AggregateMetrics {
            total_requests,
            total_pending_requests,
            total_cache_hits: total_hits,
            total_cache_misses: total_misses,
            aggregate_hit_rate: hit_rate,
            per_core,
        }
    }
}

impl std::fmt::Debug for PerCoreDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerCoreDispatcher")
            .field("num_cores", &self.num_cores())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Aggregated metrics across all cores.
#[derive(Debug, Clone)]
pub struct AggregateMetrics {
    pub total_requests: u64,
    pub total_pending_requests: i64,
    pub total_cache_hits: u64,
    pub total_cache_misses: u64,
    pub aggregate_hit_rate: f64,
    pub per_core: Vec<CoreMetricsSnapshot>,
}

impl AggregateMetrics {
    /// Find the most loaded core (by request count).
    #[must_use]
    pub fn hottest_core(&self) -> Option<(usize, u64)> {
        self.per_core
            .iter()
            .enumerate()
            .max_by_key(|(_, s)| s.requests)
            .map(|(i, s)| (i, s.requests))
    }

    /// Find the least loaded core.
    #[must_use]
    pub fn coldest_core(&self) -> Option<(usize, u64)> {
        self.per_core
            .iter()
            .enumerate()
            .min_by_key(|(_, s)| s.requests)
            .map(|(i, s)| (i, s.requests))
    }

    /// Load imbalance ratio: max/min request count.
    /// Returns 1.0 for perfectly balanced, higher for imbalanced.
    #[must_use]
    pub fn imbalance_ratio(&self) -> f64 {
        let max = self.hottest_core().map_or(0, |(_, r)| r);
        let min = self.coldest_core().map_or(0, |(_, r)| r);
        if min == 0 {
            return if max == 0 { 1.0 } else { f64::INFINITY };
        }
        max as f64 / min as f64
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    fn legacy_inode_to_core(ino: u64, num_cores: u32) -> u32 {
        if num_cores == 0 {
            return 0;
        }
        let mixed = ino.wrapping_mul(0x517c_c1b7_2722_0a95);
        #[expect(clippy::cast_possible_truncation)] // intentional 64→32 fold
        let folded = (mixed ^ (mixed >> 32)) as u32;
        folded % num_cores
    }

    #[test]
    fn inode_routing_deterministic() {
        for ino in 0..1000 {
            let core1 = inode_to_core(ino, 8);
            let core2 = inode_to_core(ino, 8);
            assert_eq!(core1, core2);
            assert!(core1 < 8);
        }
    }

    #[test]
    fn inode_routing_distribution() {
        // Check that routing is reasonably uniform.
        let num_cores = 8;
        let mut counts = vec![0_u32; num_cores as usize];
        for ino in 0..10_000_u64 {
            let core = inode_to_core(ino, num_cores);
            counts[core as usize] += 1;
        }
        // Each core should get roughly 10000/8 = 1250 ± 30%.
        for (core, &count) in counts.iter().enumerate() {
            assert!(
                count > 800 && count < 1700,
                "core {core} got {count} requests (expected ~1250)"
            );
        }
    }

    #[test]
    fn inode_routing_matches_legacy_modulo_reference() {
        for num_cores in [1, 2, 4, 8, 16, 32, 3, 5, 7, 10, 15] {
            let dispatcher = PerCoreDispatcher::new(PerCoreConfig {
                num_cores,
                ..Default::default()
            });
            for ino in 0..10_000_u64 {
                assert_eq!(
                    inode_to_core(ino, num_cores),
                    legacy_inode_to_core(ino, num_cores),
                    "ino={ino} num_cores={num_cores}"
                );
                assert_eq!(
                    dispatcher.route_inode(ino),
                    legacy_inode_to_core(ino, num_cores),
                    "dispatcher ino={ino} num_cores={num_cores}"
                );
                assert_eq!(
                    dispatcher.route_lookup(ino),
                    legacy_inode_to_core(ino, num_cores),
                    "lookup ino={ino} num_cores={num_cores}"
                );
            }
        }
    }

    #[test]
    fn should_steal_sanitizes_invalid_thresholds() {
        let config = PerCoreConfig {
            num_cores: 2,
            cache_blocks_per_core: 1,
            steal_threshold: -1.0,
            advisory_affinity: false,
        };
        let dispatcher = PerCoreDispatcher::new(config);
        dispatcher.core_metrics[0]
            .pending_requests
            .store(1, Ordering::Relaxed);
        dispatcher.core_metrics[1]
            .pending_requests
            .store(9, Ordering::Relaxed);

        assert!(dispatcher.should_steal(0));
    }

    #[test]
    fn inode_routing_zero_cores() {
        assert_eq!(inode_to_core(42, 0), 0);
    }

    #[test]
    fn lookup_routes_by_parent() {
        let core1 = lookup_to_core(100, 8);
        let core2 = lookup_to_core(100, 8);
        assert_eq!(core1, core2);

        // Different parent → likely different core.
        let core3 = lookup_to_core(200, 8);
        // Can't guarantee different core but routing is deterministic.
        let _ = core3;
    }

    #[test]
    fn config_defaults() {
        let cfg = PerCoreConfig::default();
        assert!(cfg.num_cores > 0);
        assert!(cfg.cache_blocks_per_core > 0);
        assert!(cfg.steal_threshold > 1.0);
    }

    #[test]
    fn config_total_cache() {
        let cfg = PerCoreConfig {
            num_cores: 4,
            cache_blocks_per_core: 1024,
            steal_threshold: 2.0,
            advisory_affinity: true,
        };
        assert_eq!(cfg.total_cache_blocks(), 4096);
    }

    #[test]
    fn dispatcher_creation() {
        let cfg = PerCoreConfig {
            num_cores: 4,
            ..Default::default()
        };
        let disp = PerCoreDispatcher::new(cfg);
        assert_eq!(disp.num_cores(), 4);
        assert!(disp.core_metrics(0).is_some());
        assert!(disp.core_metrics(3).is_some());
        assert!(disp.core_metrics(4).is_none());
    }

    #[test]
    fn dispatcher_routing_and_metrics() {
        let cfg = PerCoreConfig {
            num_cores: 4,
            ..Default::default()
        };
        let disp = PerCoreDispatcher::new(cfg);

        // Route some requests and record metrics.
        for ino in 0..100_u64 {
            let core = disp.route_inode(ino);
            let metrics = disp.core_metrics(core).unwrap();
            metrics.begin_request();
            metrics.record_request();
            if ino % 3 == 0 {
                metrics.record_hit();
            } else {
                metrics.record_miss();
            }
        }

        let agg = disp.aggregate_metrics();
        assert_eq!(agg.total_requests, 100);
        assert_eq!(agg.per_core.len(), 4);
        assert!(agg.aggregate_hit_rate > 0.2 && agg.aggregate_hit_rate < 0.5);
    }

    #[test]
    fn core_metrics_saturate_at_numeric_limits() {
        let m = CoreMetrics::new();
        m.requests.store(u64::MAX - 1, Ordering::Relaxed);
        m.pending_requests.store(i64::MAX, Ordering::Relaxed);
        m.cache_hits.store(u64::MAX - 1, Ordering::Relaxed);
        m.cache_misses.store(u64::MAX, Ordering::Relaxed);

        m.begin_request();
        m.record_hit();
        m.record_miss();
        let saturated_begin = m.snapshot();
        assert_eq!(saturated_begin.pending_requests, i64::MAX);
        assert_eq!(saturated_begin.cache_hits, u64::MAX);
        assert_eq!(saturated_begin.cache_misses, u64::MAX);

        m.pending_requests.store(0, Ordering::Relaxed);
        m.record_request();
        let completed = m.snapshot();
        assert_eq!(completed.requests, u64::MAX);
        assert_eq!(completed.pending_requests, 0);
    }

    #[test]
    fn core_metrics_hit_rate_handles_saturated_bounds() {
        let snap = CoreMetricsSnapshot {
            requests: 0,
            pending_requests: 0,
            cache_hits: u64::MAX,
            cache_misses: u64::MAX,
            stolen_from: 0,
            stolen_to: 0,
        };

        assert!((snap.hit_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_metrics_saturates_numeric_totals() {
        let cfg = PerCoreConfig {
            num_cores: 2,
            ..Default::default()
        };
        let disp = PerCoreDispatcher::new(cfg);

        let m0 = disp.core_metrics(0).unwrap();
        m0.requests.store(u64::MAX, Ordering::Relaxed);
        m0.pending_requests.store(i64::MAX, Ordering::Relaxed);
        m0.cache_hits.store(u64::MAX, Ordering::Relaxed);

        let m1 = disp.core_metrics(1).unwrap();
        m1.requests.store(u64::MAX, Ordering::Relaxed);
        m1.pending_requests.store(i64::MAX, Ordering::Relaxed);
        m1.cache_misses.store(u64::MAX, Ordering::Relaxed);

        let agg = disp.aggregate_metrics();
        assert_eq!(agg.total_requests, u64::MAX);
        assert_eq!(agg.total_pending_requests, i64::MAX);
        assert_eq!(agg.total_cache_hits, u64::MAX);
        assert_eq!(agg.total_cache_misses, u64::MAX);
        assert!((agg.aggregate_hit_rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_imbalance_ratio() {
        let cfg = PerCoreConfig {
            num_cores: 2,
            ..Default::default()
        };
        let disp = PerCoreDispatcher::new(cfg);

        // Give all requests to core 0.
        let m0 = disp.core_metrics(0).unwrap();
        for _ in 0..100 {
            m0.begin_request();
            m0.record_request();
        }
        let m1 = disp.core_metrics(1).unwrap();
        m1.begin_request(); // 1 request to core 1
        m1.record_request();

        let agg = disp.aggregate_metrics();
        assert_eq!(agg.total_requests, 101);
        assert!(agg.imbalance_ratio() > 50.0);
    }

    #[test]
    fn should_steal_when_idle() {
        let cfg = PerCoreConfig {
            num_cores: 2,
            steal_threshold: 2.0,
            ..Default::default()
        };
        let disp = PerCoreDispatcher::new(cfg);

        // Give 100 requests to core 0, 0 to core 1.
        let m0 = disp.core_metrics(0).unwrap();
        for _ in 0..100 {
            m0.begin_request();
        }

        // Core 1 is idle → should steal.
        assert!(disp.should_steal(1));
        // Core 0 is busy → should not steal.
        assert!(!disp.should_steal(0));
    }

    #[test]
    fn steal_plan_selects_busiest_donor_with_stable_tie_break() {
        let cfg = PerCoreConfig {
            num_cores: 4,
            steal_threshold: 2.0,
            ..Default::default()
        };
        let disp = PerCoreDispatcher::new(cfg);

        for (core, pending) in [(0, 0), (1, 9), (2, 4), (3, 9)] {
            disp.core_metrics(core)
                .unwrap()
                .pending_requests
                .store(pending, Ordering::Relaxed);
        }

        let plan = disp.steal_plan_for(0).expect("idle core can steal");
        assert_eq!(plan.receiver_core, 0);
        assert_eq!(plan.donor_core, 1);
        assert_eq!(plan.receiver_pending, 0);
        assert_eq!(plan.donor_pending, 9);
        assert_eq!(plan.transfer_count, 4);
        assert!((plan.average_pending - 5.5).abs() < f64::EPSILON);
    }

    #[test]
    fn record_steal_updates_counters_without_pending_mutation() {
        let cfg = PerCoreConfig {
            num_cores: 2,
            steal_threshold: 2.0,
            ..Default::default()
        };
        let disp = PerCoreDispatcher::new(cfg);
        disp.core_metrics(0)
            .unwrap()
            .pending_requests
            .store(0, Ordering::Relaxed);
        disp.core_metrics(1)
            .unwrap()
            .pending_requests
            .store(8, Ordering::Relaxed);

        let plan = disp.steal_plan_for(0).expect("receiver can steal");
        assert_eq!(plan.transfer_count, 4);
        disp.record_steal(&plan);

        let receiver = disp.core_metrics(0).unwrap().snapshot();
        let donor = disp.core_metrics(1).unwrap().snapshot();
        assert_eq!(receiver.stolen_to, 4);
        assert_eq!(donor.stolen_from, 4);
        assert_eq!(receiver.pending_requests, 0);
        assert_eq!(donor.pending_requests, 8);
    }

    #[test]
    fn steal_plan_rejects_balanced_and_low_total_queues() {
        let balanced = PerCoreDispatcher::new(PerCoreConfig {
            num_cores: 4,
            steal_threshold: 2.0,
            ..Default::default()
        });
        for core in 0..4 {
            balanced
                .core_metrics(core)
                .unwrap()
                .pending_requests
                .store(4, Ordering::Relaxed);
        }
        assert!(balanced.steal_plan_for(0).is_none());

        let low_total = PerCoreDispatcher::new(PerCoreConfig {
            num_cores: 4,
            steal_threshold: 2.0,
            ..Default::default()
        });
        low_total
            .core_metrics(1)
            .unwrap()
            .pending_requests
            .store(1, Ordering::Relaxed);
        assert!(low_total.steal_plan_for(0).is_none());
    }

    #[test]
    fn steal_plan_rejects_out_of_range_and_single_core_receivers() {
        let multi_core = PerCoreDispatcher::new(PerCoreConfig {
            num_cores: 2,
            steal_threshold: 2.0,
            ..Default::default()
        });
        assert!(multi_core.steal_plan_for(9).is_none());

        let single_core = PerCoreDispatcher::new(PerCoreConfig {
            num_cores: 1,
            steal_threshold: 2.0,
            ..Default::default()
        });
        assert!(single_core.steal_plan_for(0).is_none());
    }

    #[test]
    fn steal_plan_uses_sanitized_thresholds_and_saturating_totals() {
        let invalid_threshold = PerCoreDispatcher::new(PerCoreConfig {
            num_cores: 2,
            cache_blocks_per_core: 1,
            steal_threshold: f64::NAN,
            advisory_affinity: false,
        });
        invalid_threshold.core_metrics[0]
            .pending_requests
            .store(1, Ordering::Relaxed);
        invalid_threshold.core_metrics[1]
            .pending_requests
            .store(9, Ordering::Relaxed);
        assert_eq!(
            invalid_threshold
                .steal_plan_for(0)
                .expect("sanitized threshold permits stealing")
                .transfer_count,
            4
        );

        let saturated = PerCoreDispatcher::new(PerCoreConfig {
            num_cores: 2,
            steal_threshold: 2.0,
            ..Default::default()
        });
        saturated.core_metrics[0]
            .pending_requests
            .store(i64::MAX, Ordering::Relaxed);
        saturated.core_metrics[1]
            .pending_requests
            .store(i64::MAX, Ordering::Relaxed);
        assert!(saturated.steal_plan_for(0).is_none());
        assert!(saturated.steal_plan_for(1).is_none());
    }

    #[test]
    fn should_steal_saturates_pending_total() {
        let cfg = PerCoreConfig {
            num_cores: 2,
            steal_threshold: 2.0,
            ..Default::default()
        };
        let disp = PerCoreDispatcher::new(cfg);
        disp.core_metrics[0]
            .pending_requests
            .store(i64::MAX, Ordering::Relaxed);
        disp.core_metrics[1]
            .pending_requests
            .store(i64::MAX, Ordering::Relaxed);

        assert!(!disp.should_steal(0));
        assert!(!disp.should_steal(1));
    }

    #[test]
    fn should_steal_out_of_range_returns_false() {
        let cfg = PerCoreConfig {
            num_cores: 2,
            steal_threshold: 2.0,
            ..Default::default()
        };
        let disp = PerCoreDispatcher::new(cfg);
        assert!(!disp.should_steal(9));
    }

    #[test]
    fn should_steal_matches_plan_existence() {
        let thresholds = [2.0, 1.5, f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0];
        let cases: &[&[i64]] = &[
            &[0, 0],
            &[0, 1],
            &[0, 9],
            &[4, 4],
            &[9, 0],
            &[-5, 8],
            &[0, 9, 9, 4],
            &[1, 9, 0, 9],
            &[i64::MAX, i64::MAX],
        ];

        for &threshold in &thresholds {
            for pending in cases {
                let core_count = u32::try_from(pending.len()).expect("test core count fits u32");
                let disp = PerCoreDispatcher::new(PerCoreConfig {
                    num_cores: core_count,
                    steal_threshold: threshold,
                    ..Default::default()
                });
                for (core, &depth) in pending.iter().enumerate() {
                    let core_id = u32::try_from(core).expect("test core index fits u32");
                    disp.core_metrics(core_id)
                        .unwrap()
                        .pending_requests
                        .store(depth, Ordering::Relaxed);
                }

                for core in 0..=core_count {
                    assert_eq!(
                        disp.should_steal(core),
                        disp.steal_plan_for(core).is_some(),
                        "threshold={threshold:?} pending={pending:?} core={core}"
                    );
                }
            }
        }
    }

    fn steal_plan_reference_from_pending(
        num_cores: u32,
        steal_threshold: f64,
        pending_raw: &[i64],
        receiver_core: u32,
    ) -> Option<StealPlan> {
        let n = usize::try_from(num_cores).ok()?;
        if n < 2 || pending_raw.len() != n {
            return None;
        }
        let receiver_idx = receiver_core as usize;
        if receiver_idx >= n {
            return None;
        }

        let pending = pending_raw
            .iter()
            .copied()
            .map(|depth| depth.max(0))
            .collect::<Vec<_>>();
        let total = pending.iter().copied().fold(0, i64::saturating_add);
        let Ok(core_count) = i64::try_from(n) else {
            return None;
        };
        if total < core_count {
            return None;
        }

        let avg = total as f64 / n as f64;
        let receiver_pending = pending[receiver_idx];
        let threshold = if steal_threshold.is_finite() && steal_threshold > 0.0 {
            steal_threshold
        } else {
            PerCoreConfig::DEFAULT_STEAL_THRESHOLD
        };
        if receiver_pending as f64 >= avg / threshold {
            return None;
        }

        let (donor_idx, &donor_pending) = pending
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx != receiver_idx)
            .max_by_key(|(idx, depth)| (**depth, std::cmp::Reverse(*idx)))?;

        if donor_pending <= receiver_pending {
            return None;
        }

        let pending_gap = donor_pending.saturating_sub(receiver_pending);
        let transfer_count = u64::try_from((pending_gap / 2).max(1)).ok()?;
        let donor_core = u32::try_from(donor_idx).ok()?;

        Some(StealPlan {
            receiver_core,
            donor_core,
            receiver_pending,
            donor_pending,
            average_pending: avg,
            transfer_count,
        })
    }

    #[test]
    fn steal_plan_golden_report() {
        fn set_pending(dispatcher: &PerCoreDispatcher, pending: &[i64]) {
            for (core, depth) in pending.iter().copied().enumerate() {
                dispatcher
                    .core_metrics(u32::try_from(core).expect("core fits u32"))
                    .expect("core exists")
                    .pending_requests
                    .store(depth, Ordering::Relaxed);
            }
        }

        fn render_plan(plan: Option<StealPlan>) -> String {
            plan.map_or_else(
                || String::from("None"),
                |plan| {
                    format!(
                        "Some(receiver={},donor={},receiver_pending={},donor_pending={},avg={:.3},transfer={})",
                        plan.receiver_core,
                        plan.donor_core,
                        plan.receiver_pending,
                        plan.donor_pending,
                        plan.average_pending,
                        plan.transfer_count
                    )
                },
            )
        }

        let cases: [(&str, u32, f64, &[i64], u32); 6] = [
            ("idle_total", 4, 2.0, &[0, 1, 0, 0], 0),
            ("balanced", 4, 2.0, &[4, 4, 4, 4], 0),
            ("lowest_tie", 4, 2.0, &[0, 9, 4, 9], 0),
            ("receiver_busy", 4, 2.0, &[9, 0, 9, 9], 0),
            ("negative_depths", 4, 2.0, &[-7, 0, 8, 8], 1),
            ("invalid_threshold", 2, f64::NAN, &[1, 9], 0),
        ];

        let mut report = String::new();
        for (name, num_cores, steal_threshold, pending, receiver) in cases {
            let dispatcher = PerCoreDispatcher::new(PerCoreConfig {
                num_cores,
                cache_blocks_per_core: 1,
                steal_threshold,
                advisory_affinity: false,
            });
            set_pending(&dispatcher, pending);
            let rendered = render_plan(dispatcher.steal_plan_for(receiver));
            let expected = render_plan(steal_plan_reference_from_pending(
                num_cores,
                steal_threshold,
                pending,
                receiver,
            ));
            assert_eq!(rendered, expected, "{name}");
            writeln!(report, "STEAL_PLAN_GOLDEN\t{name}\t{rendered}")
                .expect("write golden report row");
        }

        let out_of_range = PerCoreDispatcher::new(PerCoreConfig {
            num_cores: 2,
            cache_blocks_per_core: 1,
            steal_threshold: 2.0,
            advisory_affinity: false,
        });
        assert_eq!(
            out_of_range.steal_plan_for(9),
            steal_plan_reference_from_pending(2, 2.0, &[0, 0], 9)
        );
        writeln!(
            report,
            "STEAL_PLAN_GOLDEN\tout_of_range\t{}",
            render_plan(out_of_range.steal_plan_for(9))
        )
        .expect("write golden report row");

        print!("{report}");
    }

    #[test]
    fn hottest_coldest_core() {
        let cfg = PerCoreConfig {
            num_cores: 3,
            ..Default::default()
        };
        let disp = PerCoreDispatcher::new(cfg);

        for (core, count) in [(0, 10), (1, 50), (2, 30)] {
            let m = disp.core_metrics(core).unwrap();
            for _ in 0..count {
                m.begin_request();
                m.record_request();
            }
        }

        let agg = disp.aggregate_metrics();
        assert_eq!(agg.hottest_core(), Some((1, 50)));
        assert_eq!(agg.coldest_core(), Some((0, 10)));
    }

    #[test]
    fn hit_rate_calculation() {
        let m = CoreMetrics::new();
        assert!(m.snapshot().hit_rate().abs() < f64::EPSILON); // no data

        for _ in 0..7 {
            m.record_hit();
        }
        for _ in 0..3 {
            m.record_miss();
        }

        let snap = m.snapshot();
        assert!((snap.hit_rate() - 0.7).abs() < 0.001);
    }

    #[test]
    fn benchmark_routing_throughput() {
        // Verify routing is fast: 10M routes should complete quickly.
        let num_cores = 8_u32;
        let mut sum = 0_u64;
        for ino in 0..10_000_000_u64 {
            sum += u64::from(inode_to_core(ino, num_cores));
        }
        // Just ensure it ran (prevent optimization).
        assert!(sum > 0);
    }

    // ── normalized_steal_threshold edge cases ───────────────────────────────

    #[test]
    fn normalized_steal_threshold_valid_value() {
        let cfg = PerCoreConfig {
            steal_threshold: 3.5,
            ..Default::default()
        };
        assert!((cfg.normalized_steal_threshold() - 3.5).abs() < f64::EPSILON);
    }

    #[test]
    #[expect(clippy::float_cmp)] // exact constant comparison
    fn normalized_steal_threshold_zero_returns_default() {
        let cfg = PerCoreConfig {
            steal_threshold: 0.0,
            ..Default::default()
        };
        assert_eq!(
            cfg.normalized_steal_threshold(),
            PerCoreConfig::DEFAULT_STEAL_THRESHOLD
        );
    }

    #[test]
    #[expect(clippy::float_cmp)] // exact constant comparison
    fn normalized_steal_threshold_negative_returns_default() {
        let cfg = PerCoreConfig {
            steal_threshold: -1.0,
            ..Default::default()
        };
        assert_eq!(
            cfg.normalized_steal_threshold(),
            PerCoreConfig::DEFAULT_STEAL_THRESHOLD
        );
    }

    #[test]
    #[expect(clippy::float_cmp)] // exact constant comparison
    fn normalized_steal_threshold_nan_returns_default() {
        let cfg = PerCoreConfig {
            steal_threshold: f64::NAN,
            ..Default::default()
        };
        assert_eq!(
            cfg.normalized_steal_threshold(),
            PerCoreConfig::DEFAULT_STEAL_THRESHOLD
        );
    }

    #[test]
    #[expect(clippy::float_cmp)] // exact constant comparison
    fn normalized_steal_threshold_infinity_returns_default() {
        let cfg = PerCoreConfig {
            steal_threshold: f64::INFINITY,
            ..Default::default()
        };
        assert_eq!(
            cfg.normalized_steal_threshold(),
            PerCoreConfig::DEFAULT_STEAL_THRESHOLD
        );
    }

    #[test]
    #[expect(clippy::float_cmp)] // exact constant comparison
    fn normalized_steal_threshold_neg_infinity_returns_default() {
        let cfg = PerCoreConfig {
            steal_threshold: f64::NEG_INFINITY,
            ..Default::default()
        };
        assert_eq!(
            cfg.normalized_steal_threshold(),
            PerCoreConfig::DEFAULT_STEAL_THRESHOLD
        );
    }

    // ── resolved_cores edge cases ───────────────────────────────────────────

    #[test]
    fn resolved_cores_explicit_value() {
        let cfg = PerCoreConfig {
            num_cores: 8,
            ..Default::default()
        };
        assert_eq!(cfg.resolved_cores(), 8);
    }

    #[test]
    fn resolved_cores_zero_uses_parallelism() {
        let cfg = PerCoreConfig {
            num_cores: 0,
            ..Default::default()
        };
        let resolved = cfg.resolved_cores();
        // When num_cores is 0, resolved_cores() uses available_parallelism
        // capped at 16, or falls back to 4.
        assert!((1..=16).contains(&resolved));
    }

    #[test]
    fn resolved_cores_one_is_valid() {
        let cfg = PerCoreConfig {
            num_cores: 1,
            ..Default::default()
        };
        assert_eq!(cfg.resolved_cores(), 1);
    }

    // ── AggregateMetrics edge cases ─────────────────────────────────────────

    #[test]
    fn aggregate_metrics_empty_per_core() {
        let agg = AggregateMetrics {
            total_requests: 0,
            total_pending_requests: 0,
            total_cache_hits: 0,
            total_cache_misses: 0,
            aggregate_hit_rate: 0.0,
            per_core: vec![],
        };
        assert_eq!(agg.hottest_core(), None);
        assert_eq!(agg.coldest_core(), None);
        assert!((agg.imbalance_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_metrics_single_core() {
        let agg = AggregateMetrics {
            total_requests: 100,
            total_pending_requests: 5,
            total_cache_hits: 70,
            total_cache_misses: 30,
            aggregate_hit_rate: 0.7,
            per_core: vec![CoreMetricsSnapshot {
                requests: 100,
                pending_requests: 5,
                cache_hits: 70,
                cache_misses: 30,
                stolen_from: 0,
                stolen_to: 0,
            }],
        };
        assert_eq!(agg.hottest_core(), Some((0, 100)));
        assert_eq!(agg.coldest_core(), Some((0, 100)));
        assert!((agg.imbalance_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_metrics_imbalance_infinity_when_min_zero() {
        let agg = AggregateMetrics {
            total_requests: 100,
            total_pending_requests: 0,
            total_cache_hits: 0,
            total_cache_misses: 0,
            aggregate_hit_rate: 0.0,
            per_core: vec![
                CoreMetricsSnapshot {
                    requests: 100,
                    pending_requests: 0,
                    cache_hits: 0,
                    cache_misses: 0,
                    stolen_from: 0,
                    stolen_to: 0,
                },
                CoreMetricsSnapshot {
                    requests: 0,
                    pending_requests: 0,
                    cache_hits: 0,
                    cache_misses: 0,
                    stolen_from: 0,
                    stolen_to: 0,
                },
            ],
        };
        assert!(agg.imbalance_ratio().is_infinite());
    }

    // ── CoreMetrics default and snapshot tests ──────────────────────────────

    #[test]
    fn core_metrics_default_snapshot_all_zero() {
        let m = CoreMetrics::default();
        let snap = m.snapshot();
        assert_eq!(snap.requests, 0);
        assert_eq!(snap.pending_requests, 0);
        assert_eq!(snap.cache_hits, 0);
        assert_eq!(snap.cache_misses, 0);
        assert_eq!(snap.stolen_from, 0);
        assert_eq!(snap.stolen_to, 0);
    }

    #[test]
    fn core_metrics_new_equals_default() {
        let from_new = CoreMetrics::new();
        let from_default = CoreMetrics::default();
        let snap_new = from_new.snapshot();
        let snap_default = from_default.snapshot();
        assert_eq!(snap_new.requests, snap_default.requests);
        assert_eq!(snap_new.pending_requests, snap_default.pending_requests);
        assert_eq!(snap_new.cache_hits, snap_default.cache_hits);
        assert_eq!(snap_new.cache_misses, snap_default.cache_misses);
    }

    // ── Property-based tests ────────────────────────────────────────────────

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn hit_rate_always_in_zero_one_range(
                hits in 0_u64..=u64::MAX / 2,
                misses in 0_u64..=u64::MAX / 2,
            ) {
                let snap = CoreMetricsSnapshot {
                    requests: 0,
                    pending_requests: 0,
                    cache_hits: hits,
                    cache_misses: misses,
                    stolen_from: 0,
                    stolen_to: 0,
                };
                let rate = snap.hit_rate();
                prop_assert!((0.0..=1.0).contains(&rate), "hit_rate {rate} out of [0,1]");
            }

            #[test]
            fn hit_rate_zero_when_no_accesses(hits in 0_u64..=0, misses in 0_u64..=0) {
                let snap = CoreMetricsSnapshot {
                    requests: 0,
                    pending_requests: 0,
                    cache_hits: hits,
                    cache_misses: misses,
                    stolen_from: 0,
                    stolen_to: 0,
                };
                prop_assert!((snap.hit_rate() - 0.0).abs() < f64::EPSILON);
            }

            #[test]
            fn normalized_steal_threshold_always_positive_finite(
                threshold in -100.0_f64..=100.0,
            ) {
                let cfg = PerCoreConfig {
                    num_cores: 4,
                    cache_blocks_per_core: 1024,
                    steal_threshold: threshold,
                    advisory_affinity: false,
                };
                let norm = cfg.normalized_steal_threshold();
                prop_assert!(norm > 0.0 && norm.is_finite(), "normalized {norm} not positive+finite");
            }

            #[test]
            fn resolved_cores_never_zero(
                cores in 0_u32..=256,
            ) {
                let cfg = PerCoreConfig {
                    num_cores: cores,
                    cache_blocks_per_core: 1024,
                    steal_threshold: 2.0,
                    advisory_affinity: false,
                };
                prop_assert!(cfg.resolved_cores() >= 1);
            }

            #[test]
            fn normalized_steal_threshold_handles_special_floats(
                bits in proptest::bits::u64::ANY,
            ) {
                let threshold = f64::from_bits(bits);
                let cfg = PerCoreConfig {
                    num_cores: 4,
                    cache_blocks_per_core: 1024,
                    steal_threshold: threshold,
                    advisory_affinity: false,
                };
                let norm = cfg.normalized_steal_threshold();
                prop_assert!(norm > 0.0 && norm.is_finite());
            }
        }
    }
}
