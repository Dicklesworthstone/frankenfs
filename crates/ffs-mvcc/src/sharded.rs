//! Sharded MVCC version store for concurrent multi-writer access.
//!
//! [`ShardedMvccStore`] partitions block versions across multiple shards,
//! each with its own [`parking_lot::RwLock`].  Writers to different block
//! ranges proceed without contention.  The commit sequence is a global
//! [`AtomicU64`], lock-free for the common case.
//!
//! Snapshot lifecycle is managed externally via [`SnapshotRegistry`].

use crate::SnapshotRegistry;
use crate::compression::{self, CompressionPolicy, VersionData};
use crate::{
    AdaptivePolicyConfig, BlockVersion, CommitError, CommittedTxnRecord, ConflictPolicy,
    ContentionMetrics, MergeProof, Transaction, detect_ssi_dangerous_structure,
    resolve_version_bytes_cow_at_or_before, validate_transaction_id,
};
use asupersync::Cx;
use ffs_block::BlockDevice;
use ffs_error::Result as FfsResult;
use ffs_types::{BlockNumber, CommitSeq, Snapshot, TxnId};
use parking_lot::{Condvar, Mutex, RwLock, RwLockWriteGuard};
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use tracing::{debug, info, trace};

/// Number of MVCC version-store shards to provision per available CPU.
pub const MVCC_SHARDS_PER_CORE: usize = 4;
/// Minimum shard count for host-sized sharded stores.
pub const MIN_MVCC_SHARDS: usize = 16;
/// Maximum shard count for host-sized sharded stores.
pub const MAX_MVCC_SHARDS: usize = 1024;

#[derive(Clone, Copy)]
enum CommitLockPhase {
    ShardWait,
    ShardHold,
    PublicationLockWait,
    PublicationLockHold,
    PublicationPrefixWait,
    PublicationTotal,
}

trait CommitLockProbe {
    type Stamp;

    fn start(&self) -> Self::Stamp;
    fn finish(&mut self, phase: CommitLockPhase, started: Self::Stamp);
}

struct NoopCommitLockProbe;

impl CommitLockProbe for NoopCommitLockProbe {
    type Stamp = ();

    #[inline(always)]
    fn start(&self) {}

    #[inline(always)]
    fn finish(&mut self, _phase: CommitLockPhase, _started: ()) {}
}

/// Log2 timing histogram used by the bench-only commit-lock probe.
///
/// Each worker owns its profile while committing, so recording introduces no
/// shared atomics or probe mutex that could manufacture contention. Normal
/// builds do not expose or instantiate this type.
#[cfg(feature = "bench-instrumentation")]
#[derive(Clone, Debug)]
pub struct LockTimingHistogram {
    buckets: [u64; 64],
    samples: u64,
    total_ns: u64,
    max_ns: u64,
}

#[cfg(feature = "bench-instrumentation")]
impl Default for LockTimingHistogram {
    fn default() -> Self {
        Self {
            buckets: [0; 64],
            samples: 0,
            total_ns: 0,
            max_ns: 0,
        }
    }
}

#[cfg(feature = "bench-instrumentation")]
impl LockTimingHistogram {
    fn record(&mut self, elapsed_ns: u64) {
        let bucket = usize::try_from(elapsed_ns.max(1).ilog2()).expect("ilog2 fits usize");
        self.buckets[bucket] = self.buckets[bucket].saturating_add(1);
        self.samples = self.samples.saturating_add(1);
        self.total_ns = self.total_ns.saturating_add(elapsed_ns);
        self.max_ns = self.max_ns.max(elapsed_ns);
    }

    fn merge(&mut self, other: &Self) {
        for (dst, src) in self.buckets.iter_mut().zip(&other.buckets) {
            *dst = dst.saturating_add(*src);
        }
        self.samples = self.samples.saturating_add(other.samples);
        self.total_ns = self.total_ns.saturating_add(other.total_ns);
        self.max_ns = self.max_ns.max(other.max_ns);
    }

    fn percentile_upper_ns(&self, percentile: u64) -> u64 {
        if self.samples == 0 {
            return 0;
        }
        let target = self.samples.saturating_mul(percentile).saturating_add(99) / 100;
        let mut cumulative = 0_u64;
        for (index, count) in self.buckets.iter().enumerate() {
            cumulative = cumulative.saturating_add(*count);
            if cumulative >= target {
                let shift = u32::try_from(index + 1).expect("histogram shift fits u32");
                return 1_u64
                    .checked_shl(shift)
                    .map_or(u64::MAX, |upper| upper.saturating_sub(1));
            }
        }
        u64::MAX
    }

    /// Return a compact summary. Percentiles are inclusive upper bounds of the
    /// matching power-of-two bucket rather than interpolated point estimates.
    #[must_use]
    pub fn summary(&self) -> LockTimingSummary {
        LockTimingSummary {
            samples: self.samples,
            mean_ns: self.total_ns.checked_div(self.samples).unwrap_or(0),
            p50_upper_ns: self.percentile_upper_ns(50),
            p95_upper_ns: self.percentile_upper_ns(95),
            p99_upper_ns: self.percentile_upper_ns(99),
            max_ns: self.max_ns,
        }
    }
}

/// Compact view of a bench-only commit-lock timing histogram.
#[cfg(feature = "bench-instrumentation")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockTimingSummary {
    /// Number of recorded lock events.
    pub samples: u64,
    /// Integer mean duration in nanoseconds.
    pub mean_ns: u64,
    /// Inclusive upper bound of the p50 log2 bucket, in nanoseconds.
    pub p50_upper_ns: u64,
    /// Inclusive upper bound of the p95 log2 bucket, in nanoseconds.
    pub p95_upper_ns: u64,
    /// Inclusive upper bound of the p99 log2 bucket, in nanoseconds.
    pub p99_upper_ns: u64,
    /// Largest observed duration in nanoseconds.
    pub max_ns: u64,
}

/// Worker-local timing profile for the real sharded MVCC commit path.
#[cfg(feature = "bench-instrumentation")]
#[derive(Clone, Debug, Default)]
pub struct CommitLockProfile {
    shard_wait: LockTimingHistogram,
    shard_hold: LockTimingHistogram,
    publication_lock_wait: LockTimingHistogram,
    publication_lock_hold: LockTimingHistogram,
    publication_prefix_wait: LockTimingHistogram,
    publication_total: LockTimingHistogram,
}

#[cfg(feature = "bench-instrumentation")]
impl CommitLockProfile {
    /// Merge another worker's counters after both workers have stopped.
    pub fn merge(&mut self, other: &Self) {
        self.shard_wait.merge(&other.shard_wait);
        self.shard_hold.merge(&other.shard_hold);
        self.publication_lock_wait
            .merge(&other.publication_lock_wait);
        self.publication_lock_hold
            .merge(&other.publication_lock_hold);
        self.publication_prefix_wait
            .merge(&other.publication_prefix_wait);
        self.publication_total.merge(&other.publication_total);
    }

    /// Shard write-lock acquisition wait histogram.
    #[must_use]
    pub fn shard_wait(&self) -> LockTimingSummary {
        self.shard_wait.summary()
    }

    /// Shard write-lock hold histogram.
    #[must_use]
    pub fn shard_hold(&self) -> LockTimingSummary {
        self.shard_hold.summary()
    }

    /// Initial publication-mutex acquisition wait histogram.
    #[must_use]
    pub fn publication_lock_wait(&self) -> LockTimingSummary {
        self.publication_lock_wait.summary()
    }

    /// Publication-mutex held-segment histogram. Condvar sleep is excluded.
    #[must_use]
    pub fn publication_lock_hold(&self) -> LockTimingSummary {
        self.publication_lock_hold.summary()
    }

    /// Ordered-prefix Condvar wait histogram. This includes sleep and reacquire.
    #[must_use]
    pub fn publication_prefix_wait(&self) -> LockTimingSummary {
        self.publication_prefix_wait.summary()
    }

    /// End-to-end ordered-publication call histogram.
    #[must_use]
    pub fn publication_total(&self) -> LockTimingSummary {
        self.publication_total.summary()
    }
}

#[cfg(feature = "bench-instrumentation")]
impl CommitLockProbe for CommitLockProfile {
    type Stamp = std::time::Instant;

    #[inline]
    fn start(&self) -> Self::Stamp {
        std::time::Instant::now()
    }

    #[inline]
    fn finish(&mut self, phase: CommitLockPhase, started: Self::Stamp) {
        let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        match phase {
            CommitLockPhase::ShardWait => self.shard_wait.record(elapsed_ns),
            CommitLockPhase::ShardHold => self.shard_hold.record(elapsed_ns),
            CommitLockPhase::PublicationLockWait => {
                self.publication_lock_wait.record(elapsed_ns);
            }
            CommitLockPhase::PublicationLockHold => {
                self.publication_lock_hold.record(elapsed_ns);
            }
            CommitLockPhase::PublicationPrefixWait => {
                self.publication_prefix_wait.record(elapsed_ns);
            }
            CommitLockPhase::PublicationTotal => self.publication_total.record(elapsed_ns),
        }
    }
}

/// Ordered-publication algorithm used by [`CommitPublicationGate`].
///
/// Both modes implement the SAME contract — `publish(seq)` returns only once
/// `completed >= seq`, and `completed` only ever advances over a contiguous
/// prefix — so they are indistinguishable to every reader, and the block bytes
/// a snapshot resolves are identical under either. They differ only in the
/// synchronization used to reach that state (bd-bhh0i publication convoy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PublicationMode {
    /// Compatibility fallback: one global `Mutex<BTreeSet>` plus a `Condvar`,
    /// taken on every commit that is not already covered by the watermark.
    Mutex,
    /// Production default: the committer stores its sequence into a slot of a
    /// power-of-two ring and CAS-walks the contiguous ready prefix forward. No
    /// mutex and no ordered-tree work on the common path; the `Condvar`
    /// survives only as the parking path for a committer whose predecessor has
    /// not published yet.
    #[default]
    WaitFree,
    /// [`Self::WaitFree`] with the pre-park spin disabled: a committer whose
    /// predecessor has not published parks immediately instead of re-draining
    /// `PUBLICATION_SPIN_ROUNDS` times.
    ///
    /// The spin trades CPU for wall time, and the trade is not obviously
    /// correct: profiling the wait-free gate at 8 writers put
    /// `publish_with_probe` at **16.33% self** against **5.85%** for the mutex
    /// gate, because a futex wait accrues no CPU samples while a spin does. This
    /// variant exists so the spin can be A/B'd against no-spin inside ONE binary
    /// rather than argued about.
    WaitFreeNoSpin,
}

impl PublicationMode {
    /// Mode selected by `FFS_MVCC_WAITFREE_PUBLISH`.
    ///
    /// The wait-free gate is the production default after the `bd-bhh0i`
    /// cutover. `0`/`false`/`off`/`no`/`mutex` restore the compatibility gate;
    /// `nospin` selects the diagnostic no-spin variant. An unrecognized or
    /// non-Unicode override fails closed to the compatibility gate.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var("FFS_MVCC_WAITFREE_PUBLISH") {
            Ok(value) => Self::from_env_value(Some(&value)),
            Err(std::env::VarError::NotPresent) => Self::from_env_value(None),
            Err(std::env::VarError::NotUnicode(_)) => Self::Mutex,
        }
    }

    fn from_env_value(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            None | Some("1" | "true" | "on" | "yes") => Self::WaitFree,
            Some("nospin" | "no-spin") => Self::WaitFreeNoSpin,
            Some("0" | "false" | "off" | "no" | "mutex") => Self::Mutex,
            Some(_) => Self::Mutex,
        }
    }
}

/// Ring slots for [`PublicationMode::WaitFree`]. A slot is reusable once the
/// watermark passes the sequence that previously occupied it, so the ring only
/// has to exceed the number of commit sequences that can be allocated but not
/// yet published — which is bounded by the number of threads inside `commit`.
const PUBLICATION_RING_SLOTS: u64 = 1024;
const PUBLICATION_RING_MASK: u64 = PUBLICATION_RING_SLOTS - 1;
/// Re-drain attempts before a committer parks on the `Condvar`. A predecessor
/// that has entered `commit` is only a few hundred nanoseconds from publishing,
/// so a short spin usually beats a futex round trip; the parking path bounds the
/// cost when it does not.
const PUBLICATION_SPIN_ROUNDS: u32 = 64;

struct CommitPublicationGate {
    completed_commit: AtomicU64,
    wait_lock: Mutex<PublicationState>,
    ready: Condvar,
    mode: PublicationMode,
    /// Ready-sequence ring for [`PublicationMode::WaitFree`]. Empty under
    /// [`PublicationMode::Mutex`], which allocates nothing extra.
    ring: Box<[AtomicU64]>,
    /// Committers parked on `ready` under [`PublicationMode::WaitFree`]. Read
    /// without the mutex so an advancing committer can skip the lock entirely
    /// when nobody is waiting.
    parked: AtomicUsize,
}

#[derive(Debug, Default)]
struct PublicationState {
    ready_commits: BTreeSet<u64>,
    waiters: usize,
}

impl CommitPublicationGate {
    /// Production always selects a mode explicitly (see
    /// [`ShardedMvccStore::with_compression_policy`]); the gate tests use this
    /// to build the default mutex gate directly.
    #[cfg(test)]
    fn new() -> Self {
        Self::with_mode(PublicationMode::Mutex)
    }

    fn with_mode(mode: PublicationMode) -> Self {
        let ring = match mode {
            PublicationMode::Mutex => Vec::new(),
            PublicationMode::WaitFree | PublicationMode::WaitFreeNoSpin => {
                (0..PUBLICATION_RING_SLOTS)
                    .map(|_| AtomicU64::new(0))
                    .collect()
            }
        };
        Self {
            completed_commit: AtomicU64::new(0),
            wait_lock: Mutex::new(PublicationState::default()),
            ready: Condvar::new(),
            mode,
            ring: ring.into_boxed_slice(),
            parked: AtomicUsize::new(0),
        }
    }

    fn completed(&self) -> u64 {
        self.completed_commit.load(Ordering::Acquire)
    }

    fn advance_ready_prefix(&self, state: &mut PublicationState) -> bool {
        let mut advanced = false;
        loop {
            let next = self.completed().saturating_add(1);
            if !state.ready_commits.remove(&next) {
                return advanced;
            }
            self.completed_commit.store(next, Ordering::Release);
            advanced = true;
        }
    }

    fn publish(&self, commit_seq: CommitSeq) {
        self.publish_with_probe(commit_seq, &mut NoopCommitLockProbe);
    }

    #[cfg_attr(feature = "bench-instrumentation", inline(never))]
    fn publish_with_probe<P: CommitLockProbe>(&self, commit_seq: CommitSeq, probe: &mut P) {
        let total_started = probe.start();
        match self.mode {
            PublicationMode::Mutex => self.publish_mutex(commit_seq, probe),
            PublicationMode::WaitFree => {
                self.publish_wait_free(commit_seq, probe, PUBLICATION_SPIN_ROUNDS);
            }
            PublicationMode::WaitFreeNoSpin => self.publish_wait_free(commit_seq, probe, 0),
        }
        probe.finish(CommitLockPhase::PublicationTotal, total_started);
    }

    fn publish_mutex<P: CommitLockProbe>(&self, commit_seq: CommitSeq, probe: &mut P) {
        if self.completed() >= commit_seq.0 {
            return;
        }

        let lock_wait_started = probe.start();
        let mut state = self.wait_lock.lock();
        probe.finish(CommitLockPhase::PublicationLockWait, lock_wait_started);
        let mut lock_hold_started = probe.start();
        if self.completed() >= commit_seq.0 {
            probe.finish(CommitLockPhase::PublicationLockHold, lock_hold_started);
            return;
        }

        state.ready_commits.insert(commit_seq.0);
        loop {
            let advanced = self.advance_ready_prefix(&mut state);
            if advanced && state.waiters > 0 {
                self.ready.notify_all();
            }
            if self.completed() >= commit_seq.0 {
                probe.finish(CommitLockPhase::PublicationLockHold, lock_hold_started);
                return;
            }

            state.waiters = state.waiters.saturating_add(1);
            probe.finish(CommitLockPhase::PublicationLockHold, lock_hold_started);
            let prefix_wait_started = probe.start();
            self.ready.wait(&mut state);
            probe.finish(CommitLockPhase::PublicationPrefixWait, prefix_wait_started);
            lock_hold_started = probe.start();
            state.waiters = state.waiters.saturating_sub(1);
        }
    }

    /// Advance `completed_commit` over every contiguous sequence already present
    /// in the ring. Any thread may run this; the CAS makes concurrent drains
    /// idempotent. Returns whether this call moved the watermark.
    ///
    /// `next` is never 0 (sequences start at 1) and the ring is zero-initialized,
    /// so an untouched slot can never be mistaken for a ready sequence. A slot is
    /// only written once the watermark has passed its previous occupant
    /// (`seq - PUBLICATION_RING_SLOTS`), so a stale value can never match `next`
    /// either — the ring is ABA-free without tagging.
    fn drain_ready_prefix(&self) -> bool {
        if self.ring.is_empty() {
            // `PublicationMode::Mutex` allocates no ring; the mutex path owns the
            // watermark there and never calls this.
            return false;
        }
        let mut advanced = false;
        loop {
            let current = self.completed_commit.load(Ordering::Acquire);
            let next = current.wrapping_add(1);
            let slot = usize::try_from(next & PUBLICATION_RING_MASK).unwrap_or(0);
            if self.ring[slot].load(Ordering::Acquire) != next {
                return advanced;
            }
            if self
                .completed_commit
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::Acquire)
                .is_ok()
            {
                advanced = true;
            }
        }
    }

    /// Wake any parked committers after the watermark moved.
    ///
    /// The `parked` load and the `completed_commit` CAS in [`Self::drain_ready_prefix`]
    /// are both `SeqCst`, as are the parking side's `parked` increment and its
    /// `completed_commit` re-check. That total order rules out a lost wakeup:
    /// either the parker's increment precedes this load (so it is notified), or
    /// this CAS precedes the parker's re-check (so it never sleeps).
    fn notify_parked(&self) {
        if self.parked.load(Ordering::SeqCst) > 0 {
            let _state = self.wait_lock.lock();
            self.ready.notify_all();
        }
    }

    fn publish_wait_free<P: CommitLockProbe>(
        &self,
        commit_seq: CommitSeq,
        probe: &mut P,
        spin_rounds: u32,
    ) {
        let seq = commit_seq.0;
        if self.completed() >= seq {
            return;
        }

        // Claim the ring slot. It last held `seq - PUBLICATION_RING_SLOTS`, which
        // is consumed once the watermark passes it. Sequences are allocated inside
        // `commit` and published before it returns, so the number of allocated-but
        // -unpublished sequences never exceeds the number of committing threads and
        // this loop does not spin below ~1024 concurrent committers.
        let lock_wait_started = probe.start();
        while seq.saturating_sub(self.completed()) >= PUBLICATION_RING_SLOTS {
            self.drain_ready_prefix();
            std::hint::spin_loop();
        }
        probe.finish(CommitLockPhase::PublicationLockWait, lock_wait_started);

        let hold_started = probe.start();
        let slot = usize::try_from(seq & PUBLICATION_RING_MASK).unwrap_or(0);
        self.ring[slot].store(seq, Ordering::Release);
        if self.drain_ready_prefix() {
            self.notify_parked();
        }
        probe.finish(CommitLockPhase::PublicationLockHold, hold_started);
        if self.completed() >= seq {
            return;
        }

        // A predecessor is still installing. Spin briefly, then park.
        let prefix_wait_started = probe.start();
        for _ in 0..spin_rounds {
            std::hint::spin_loop();
            if self.drain_ready_prefix() {
                self.notify_parked();
            }
            if self.completed() >= seq {
                probe.finish(CommitLockPhase::PublicationPrefixWait, prefix_wait_started);
                return;
            }
        }

        let mut state = self.wait_lock.lock();
        self.parked.fetch_add(1, Ordering::SeqCst);
        while self.completed_commit.load(Ordering::SeqCst) < seq {
            self.ready.wait(&mut state);
        }
        self.parked.fetch_sub(1, Ordering::SeqCst);
        drop(state);
        probe.finish(CommitLockPhase::PublicationPrefixWait, prefix_wait_started);
    }
}

impl std::fmt::Debug for CommitPublicationGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.wait_lock.lock();
        f.debug_struct("CommitPublicationGate")
            .field("completed_commit", &self.completed())
            .field("waiters", &state.waiters)
            .field("ready_commits", &state.ready_commits.len())
            .finish_non_exhaustive()
    }
}

/// A single shard of the version store.
#[derive(Debug, Default)]
struct MvccShard {
    versions: FxHashMap<BlockNumber, ShardVersionChain>,
    /// Per-shard SSI log.  Entries are kept here because SSI checks
    /// are per-block and shards are block-partitioned.
    ssi_log: Vec<CommittedTxnRecord>,
    /// Blocks in this shard whose version chain currently has >1 version — the
    /// only blocks `prune_versions_older_than` needs to visit. `install_committed_version_locked`
    /// (the sole version-add site) inserts a block here when its chain grows past
    /// 1, so this set is complete; prune drops a block once it collapses back to a
    /// single version. Lets prune skip the O(all-blocks) scan of single-version
    /// blocks (the common case under write-once/overwrite workloads, ~6% of a
    /// write-bench overwrite) and touch only O(changed) (bd-cc-prunecand).
    prune_candidates: FxHashSet<BlockNumber>,
}

type ShardVersionChain = SmallVec<[BlockVersion; 1]>;
type ShardWriteGuard<'a> = RwLockWriteGuard<'a, MvccShard>;
type ShardIndexVec = SmallVec<[usize; 4]>;
type ShardGuardVec<'a> = SmallVec<[(usize, ShardWriteGuard<'a>); 4]>;

#[derive(Debug, Clone, Copy)]
struct CommitInstallContext {
    snapshot: Snapshot,
    commit_seq: CommitSeq,
    txn_id: TxnId,
    dedup_enabled: bool,
}

/// Thread-safe, sharded MVCC version store.
///
/// Blocks are assigned to shards via `block_number.0 & shard_mask`.
/// `shard_count` is normalized to a power of two at construction, so this is
/// equivalent to modulo routing.
/// Each shard has its own `RwLock`, so writers to different block ranges
/// proceed without contention.
///
/// # Snapshot lifecycle
///
/// Use a [`SnapshotRegistry`] (from [`crate`]) alongside this store.
/// The registry tracks active snapshots; the store tracks version chains.
/// This separation avoids coupling snapshot lifecycle to the version-store
/// lock.
///
/// # Commit protocol
///
/// Transactions that touch multiple shards acquire shard locks in sorted
/// order to prevent deadlocks.
///
/// # Lock ordering invariant (bd-bky2f)
///
/// The struct holds four [`parking_lot::RwLock`]s plus a publication
/// gate `Mutex<()>`. Any code path that acquires more than one of
/// them MUST do so in this order to prevent AB-BA deadlock:
///
/// ```text
///     active_snapshots  ──→  shards  ──→  contention_metrics
///                           (per-shard,
///                            sorted index)
/// ```
///
/// `conflict_policy` is a leaf lock — only ever acquired alone, for
/// brief reads or a single write. `commit` and `commit_ssi` snapshot
/// the effective policy before acquiring shard locks, then use that
/// lock-free value during preflight. The publication gate's
/// `wait_lock` is internal to `CommitPublicationGate` and is acquired
/// after all shard locks are dropped.
///
/// Production callers comply:
///
/// | Caller             | conflict_policy | active_snapshots | shards     | contention_metrics |
/// |--------------------|-----------------|------------------|------------|---------------------|
/// | `commit`           | R (alone)       | -                | W (sorted) | R (alone, Adaptive); W (briefly) |
/// | `commit_ssi`       | R (alone)       | -                | W (sorted) | R (alone, Adaptive); W (briefly) |
/// | `prune_safe`       | -               | W                | W (per)    | -                   |
/// | `register_snapshot`| -               | W                | -          | -                   |
/// | `release_snapshot` | -               | W                | -          | -                   |
/// | `set_conflict_policy` / `effective_policy`: leaf only       |
///
/// Acquiring `contention_metrics.write()` BEFORE
/// `active_snapshots.write()` (e.g., a hypothetical `gc_with_metrics`)
/// would deadlock against `commit`+`prune_safe` running concurrently.
/// New methods on this struct must respect the order. The
/// `lock_ordering_under_concurrent_commit_prune_and_register` test
/// exercises it under concurrent load with a watchdog timeout.
#[derive(Debug)]
pub struct ShardedMvccStore {
    /// Per-shard version stores. **Lock-rank 1** — must only be
    /// acquired while no `contention_metrics` lock is held; may be
    /// acquired while `active_snapshots` is held. Multi-shard
    /// transactions must acquire in sorted shard-index order
    /// (enforced by `lock_shards`).
    shards: Vec<RwLock<MvccShard>>,
    shard_count: usize,
    // NOTE: `shard_mask` shares a cache line with the per-commit-written
    // next_txn/next_commit/publication_gate (report_hot_field_cache_line_layout),
    // but cache-line-isolating it is measurably NEUTRAL — a plain (non-atomic)
    // read-hot field is register-hoisted out of hot loops, so it is not re-read
    // from the invalidated line. False sharing only hurts ATOMIC reads. See the
    // 2026-07-13 negative-ledger row.
    shard_mask: u64,
    next_txn: AtomicU64,
    next_commit: AtomicU64,
    publication_gate: CommitPublicationGate,
    /// Set true the first time any commit installs a version, before that commit
    /// publishes. A read-only mount never writes, so this stays false and every
    /// `read_visible`/`read_visible_physical` returns `None` without hashing +
    /// read-locking a shard to probe an always-empty version map (bd-cc-mvccempty).
    /// Monotonic: once set it never clears (installed blocks retain their latest
    /// version). Ordering is carried by the existing publish/snapshot sync — a
    /// snapshot that can see a version was taken after that commit published, hence
    /// after this store, so a reader loading `false` provably has no visible version.
    any_version_installed: AtomicBool,
    /// Inline snapshot tracking. **Lock-rank 0** — must be acquired
    /// before `shards` and `contention_metrics`.
    active_snapshots: RwLock<BTreeMap<CommitSeq, u64>>,
    /// Compression policy for version chains.
    compression_policy: CompressionPolicy,
    /// Conflict resolution policy (Strict / SafeMerge / Adaptive).
    /// **Leaf lock** — always acquired alone, never nested under
    /// `shards`, `active_snapshots`, or `contention_metrics`.
    conflict_policy: RwLock<ConflictPolicy>,
    /// Configuration for the adaptive expected-loss decision model.
    adaptive_config: AdaptivePolicyConfig,
    /// Runtime contention metrics tracked via EMA. **Lock-rank 2** —
    /// must be acquired last (or alone). Never acquire `shards` or
    /// `active_snapshots` while holding `contention_metrics`.
    contention_metrics: RwLock<ContentionMetrics>,
    /// Bench/test-only: force per-commit contention-metrics recording even under
    /// a fixed policy, so a same-binary A/B can reproduce the pre-gate behavior
    /// (the global `contention_metrics.write()` on every commit). Production
    /// leaves this `false` — fixed policies never read the metrics, so recording
    /// them would just serialize otherwise-disjoint parallel commits.
    force_metrics_record: AtomicBool,
}

impl ShardedMvccStore {
    /// Create a new sharded store with the given shard count.
    ///
    /// A reasonable default is `min(num_cpus, 64)`.
    #[must_use]
    pub fn new(shard_count: usize) -> Self {
        Self::with_compression_policy(shard_count, CompressionPolicy::default())
    }

    /// Create a host-sized store (`available_parallelism * 4`, bounded).
    ///
    /// This is the default constructor to prefer for high-core deployments: it
    /// creates enough independent version-store locks for 64+ core writer
    /// bursts without allowing unbounded shard metadata growth.
    #[must_use]
    pub fn for_host_parallelism() -> Self {
        Self::new(Self::host_parallelism_shard_count())
    }

    /// Recommended shard count for this host.
    #[must_use]
    pub fn host_parallelism_shard_count() -> usize {
        let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        cores
            .saturating_mul(MVCC_SHARDS_PER_CORE)
            .clamp(MIN_MVCC_SHARDS, MAX_MVCC_SHARDS)
            .next_power_of_two()
    }

    /// Create a new sharded store with an explicit ordered-publication mode.
    ///
    /// Only the synchronization used to advance the publication watermark
    /// differs between modes; see [`PublicationMode`]. Benchmarks use this to
    /// run both arms from ONE binary so an A/B cannot be confounded by codegen.
    #[must_use]
    pub fn with_publication_mode(shard_count: usize, mode: PublicationMode) -> Self {
        let mut store = Self::with_compression_policy(shard_count, CompressionPolicy::default());
        store.publication_gate = CommitPublicationGate::with_mode(mode);
        store
    }

    /// Create a new sharded store with a custom compression policy.
    #[must_use]
    pub fn with_compression_policy(shard_count: usize, policy: CompressionPolicy) -> Self {
        let shard_count = shard_count.clamp(1, MAX_MVCC_SHARDS).next_power_of_two();
        info!(shard_count, "sharded_mvcc_store: initializing");
        let shards = (0..shard_count)
            .map(|_| RwLock::new(MvccShard::default()))
            .collect();
        Self {
            shards,
            shard_count,
            shard_mask: u64::try_from(shard_count - 1).expect("shard mask fits in u64"),
            next_txn: AtomicU64::new(1),
            next_commit: AtomicU64::new(1),
            publication_gate: CommitPublicationGate::with_mode(PublicationMode::from_env()),
            any_version_installed: AtomicBool::new(false),
            active_snapshots: RwLock::new(BTreeMap::new()),
            compression_policy: policy,
            conflict_policy: RwLock::new(ConflictPolicy::default()),
            adaptive_config: AdaptivePolicyConfig::default(),
            contention_metrics: RwLock::new(ContentionMetrics::default()),
            force_metrics_record: AtomicBool::new(false),
        }
    }

    /// Number of shards.
    #[must_use]
    pub fn shard_count(&self) -> usize {
        self.shard_count
    }

    /// Set the conflict resolution policy.
    pub fn set_conflict_policy(&self, policy: ConflictPolicy) {
        *self.conflict_policy.write() = policy;
    }

    /// Returns the current conflict policy.
    #[must_use]
    pub fn conflict_policy(&self) -> ConflictPolicy {
        *self.conflict_policy.read()
    }

    /// Returns a snapshot of current contention metrics.
    #[must_use]
    pub fn contention_metrics(&self) -> ContentionMetrics {
        *self.contention_metrics.read()
    }

    /// The effective policy for the next commit: resolves `Adaptive` to a
    /// concrete `Strict` or `SafeMerge` based on current contention metrics.
    #[must_use]
    pub fn effective_policy(&self) -> ConflictPolicy {
        let policy = *self.conflict_policy.read();
        match policy {
            ConflictPolicy::Adaptive => self
                .contention_metrics
                .read()
                .select_policy(&self.adaptive_config),
            other => other,
        }
    }

    /// The effective policy for the next commit AND whether its contention
    /// metrics must be maintained. Only [`ConflictPolicy::Adaptive`] consumes
    /// the metrics (`effective_policy` reads them to select a strategy; no
    /// production caller reads them otherwise), so under a fixed policy the
    /// per-commit `contention_metrics.write()` — a GLOBAL lock that serializes
    /// every otherwise-disjoint parallel commit across all shards — is pure
    /// unread telemetry and is skipped. One `conflict_policy` read answers both.
    fn commit_policy(&self) -> (ConflictPolicy, bool) {
        let configured = *self.conflict_policy.read();
        match configured {
            ConflictPolicy::Adaptive => (
                self.contention_metrics
                    .read()
                    .select_policy(&self.adaptive_config),
                true,
            ),
            other => (
                other,
                self.force_metrics_record
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
        }
    }

    /// Bench/test hook: force contention-metrics recording under a fixed policy,
    /// reproducing the pre-gate per-commit `contention_metrics.write()` so a
    /// same-binary A/B can measure the eliminated global-lock serialization.
    #[doc(hidden)]
    pub fn set_force_metrics_record(&self, on: bool) {
        self.force_metrics_record
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// Map a block number to its shard index.
    #[inline]
    fn shard_index(&self, block: BlockNumber) -> usize {
        usize::try_from(block.0 & self.shard_mask).expect("masked shard index fits in usize")
    }

    fn latest_payload_matches(versions: &[BlockVersion], bytes: &[u8]) -> bool {
        versions.len().checked_sub(1).is_some_and(|last_idx| {
            compression::resolve_data_with(versions, last_idx, |v| &v.data)
                .is_some_and(|existing| existing == bytes)
        })
    }

    fn build_version_data(
        existing_versions: Option<&ShardVersionChain>,
        bytes: Vec<u8>,
        dedup_enabled: bool,
        block: BlockNumber,
    ) -> VersionData {
        if dedup_enabled
            && existing_versions
                .is_some_and(|versions| Self::latest_payload_matches(versions, bytes.as_slice()))
        {
            trace!(
                block = block.0,
                bytes_saved = bytes.len(),
                "sharded_version_dedup"
            );
            VersionData::Identical
        } else {
            VersionData::full(bytes)
        }
    }

    fn make_chain_head_full(versions: &mut [BlockVersion], keep_from: usize) {
        if keep_from < versions.len() && versions[keep_from].data.is_identical() {
            if let Some(full_data) =
                compression::resolve_data_with(versions, keep_from, |v| &v.data)
            {
                // `resolve_data_with` returns `Cow::Owned` for any compressed
                // version; move that decompressed Vec out instead of cloning it
                // (matches the already-corrected twin in lib.rs make_chain_head_full).
                let full_data = full_data.into_owned();
                versions[keep_from].data = VersionData::full(full_data);
            }
        }
    }

    fn latest_commit_seq_in_shard(shard: &MvccShard, block: BlockNumber) -> CommitSeq {
        shard
            .versions
            .get(&block)
            .and_then(|versions| versions.last())
            .map_or(CommitSeq(0), |version| version.commit_seq)
    }

    fn latest_published_commit_seq_in_shard(
        shard: &MvccShard,
        block: BlockNumber,
        published_high: CommitSeq,
    ) -> CommitSeq {
        shard
            .versions
            .get(&block)
            .and_then(|versions| {
                crate::newest_visible_index(versions, published_high)
                    .map(|idx| versions[idx].commit_seq)
            })
            .unwrap_or(CommitSeq(0))
    }

    /// Preflight validity check for a same-block FCW conflict: may the staged
    /// write commit (no conflict, or a valid merge against the latest version)?
    /// Returns `Ok(())` to proceed, `Err(Conflict)` to abort.
    ///
    /// Unlike the install path (`merged_write_bytes_locked`) this does NOT build
    /// the merged block — the preflight only needs a yes/no answer, and building
    /// the merged buffer here (discarded, then rebuilt at install) wastes a
    /// block-sized allocation + copy per conflicting block under the shard lock.
    /// `merge_valid == merge_bytes(..).is_some()`, so the gate is unchanged.
    fn check_write_mergeable_locked(
        txn: &Transaction,
        block: BlockNumber,
        shard: &MvccShard,
    ) -> Result<(), CommitError> {
        let staged = txn
            .staged_write(block)
            .ok_or_else(|| CommitError::DurabilityFailure {
                detail: format!("write_set keys must have staged bytes: {block:?}"),
            })?;
        let observed = Self::latest_commit_seq_in_shard(shard, block);
        if observed <= txn.snapshot().high {
            return Ok(());
        }

        let proof = txn.merge_proof(block).cloned().unwrap_or_default();
        // A freshly-allocated block (two concurrent creates writing disjoint inode
        // slots / group descriptors) has NO version at the shared snapshot, so the
        // version chain yields an empty base and the range-overlay merge would
        // spuriously reject on a length mismatch. Fall back to the base bytes the
        // committing txn recorded during its RMW — the on-disk content both writers
        // patched from, i.e. the true common ancestor (bd-bhh0i; the single-store
        // path fixed the same way at `MvccStore::resolved_write_*`).
        let base = shard
            .versions
            .get(&block)
            .and_then(|versions| {
                resolve_version_bytes_cow_at_or_before(versions, txn.snapshot().high)
            })
            .or_else(|| txn.staged_base(block).map(std::borrow::Cow::Borrowed))
            .unwrap_or_default();
        let latest = shard
            .versions
            .get(&block)
            .and_then(|versions| resolve_version_bytes_cow_at_or_before(versions, observed))
            .unwrap_or_default();
        if proof.merge_valid(&base, &latest, staged) {
            Ok(())
        } else {
            Err(CommitError::Conflict {
                block,
                snapshot: txn.snapshot().high,
                observed,
            })
        }
    }

    fn lock_shards(&self, shard_indices: &[usize]) -> ShardGuardVec<'_> {
        shard_indices
            .iter()
            .map(|&idx| (idx, self.shards[idx].write()))
            .collect()
    }

    fn preflight_fcw_locked(
        &self,
        txn: &Transaction,
        shard_guards: &[(usize, ShardWriteGuard<'_>)],
        effective: ConflictPolicy,
        record_metrics: bool,
        merge_log_event: &'static str,
    ) -> Result<(), CommitError> {
        let mut had_conflict = false;
        let mut merge_succeeded = false;

        for &block in txn.write_set().keys() {
            let shard_idx = self.shard_index(block);
            let Some(shard) = shard_guards
                .binary_search_by_key(&shard_idx, |(idx, _)| *idx)
                .ok()
                .map(|pos| &shard_guards[pos].1)
            else {
                return Err(CommitError::DurabilityFailure {
                    detail: "shard guard missing".into(),
                });
            };
            let latest = Self::latest_commit_seq_in_shard(shard, block);
            if latest > txn.snapshot().high {
                had_conflict = true;

                // Under Strict policy, any conflict is an immediate abort.
                if effective == ConflictPolicy::Strict {
                    if record_metrics {
                        let mut cm = self.contention_metrics.write();
                        cm.record_commit(self.adaptive_config.ema_alpha, true, false, true);
                        cm.last_selected = Some(cm.select_policy(&self.adaptive_config));
                        drop(cm);
                    }
                    return Err(CommitError::Conflict {
                        block,
                        snapshot: txn.snapshot().high,
                        observed: latest,
                    });
                }

                // SafeMerge: attempt merge-proof resolution (validity only; the
                // merged block is (re)built at install by merged_write_bytes_locked).
                if Self::check_write_mergeable_locked(txn, block, shard).is_ok() {
                    merge_succeeded = true;
                    debug!(
                        block = block.0,
                        merge_proof = ?txn.merge_proof(block),
                        snapshot_commit_seq = txn.snapshot().high.0,
                        observed_commit_seq = latest.0,
                        policy = ?effective,
                        "{merge_log_event}"
                    );
                } else {
                    if record_metrics {
                        let mut cm = self.contention_metrics.write();
                        cm.record_commit(self.adaptive_config.ema_alpha, true, false, true);
                        cm.last_selected = Some(cm.select_policy(&self.adaptive_config));
                        drop(cm);
                    }
                    return Err(CommitError::Conflict {
                        block,
                        snapshot: txn.snapshot().high,
                        observed: latest,
                    });
                }
            }
        }

        // Record successful preflight (no abort). Under a fixed conflict policy
        // nothing reads these metrics (only Adaptive's `effective_policy` does),
        // so skip the global `contention_metrics` write lock entirely — it would
        // otherwise serialize every parallel commit across all shards on the hot
        // path even though its output (`last_selected`) is never consumed.
        if record_metrics {
            let mut cm = self.contention_metrics.write();
            cm.record_commit(
                self.adaptive_config.ema_alpha,
                had_conflict,
                merge_succeeded,
                false,
            );
            cm.last_selected = Some(cm.select_policy(&self.adaptive_config));
            drop(cm);
        }
        Ok(())
    }

    fn merged_write_bytes_locked(
        shard: &MvccShard,
        block: BlockNumber,
        snapshot: Snapshot,
        bytes: Vec<u8>,
        merge_proof: Option<&MergeProof>,
        staged_base: Option<&[u8]>,
    ) -> Vec<u8> {
        let observed = Self::latest_commit_seq_in_shard(shard, block);
        if observed <= snapshot.high {
            return bytes;
        }

        let proof = merge_proof.cloned().unwrap_or_default();
        // Same freshly-allocated-block base fallback as the preflight
        // (`check_write_mergeable_locked`): install must rebuild the merged block
        // from the SAME common ancestor the preflight validated against, or a
        // disjoint-slot merge that the gate accepted would install unmerged bytes
        // (clobbering the concurrent writer's slot) via the `merge_bytes` None
        // fallback below (bd-bhh0i).
        let base = shard
            .versions
            .get(&block)
            .and_then(|versions| resolve_version_bytes_cow_at_or_before(versions, snapshot.high))
            .or_else(|| staged_base.map(std::borrow::Cow::Borrowed))
            .unwrap_or_default();
        let latest = shard
            .versions
            .get(&block)
            .and_then(|versions| resolve_version_bytes_cow_at_or_before(versions, observed))
            .unwrap_or_default();
        proof
            .merge_bytes(&base, &latest, &bytes)
            .unwrap_or_else(|| {
                tracing::error!("preflight missed an unmergeable conflict on block {block:?}");
                bytes.clone()
            })
    }

    fn install_committed_version_locked(
        shard: &mut MvccShard,
        block: BlockNumber,
        bytes: Vec<u8>,
        merge_proof: Option<&MergeProof>,
        staged_base: Option<&[u8]>,
        ctx: CommitInstallContext,
    ) {
        let version_bytes = Self::merged_write_bytes_locked(
            shard,
            block,
            ctx.snapshot,
            bytes,
            merge_proof,
            staged_base,
        );
        let version_data = Self::build_version_data(
            shard.versions.get(&block),
            version_bytes,
            ctx.dedup_enabled,
            block,
        );
        let versions = shard.versions.entry(block).or_default();
        let pos = versions.partition_point(|v| v.commit_seq < ctx.commit_seq);
        versions.insert(
            pos,
            BlockVersion {
                block,
                commit_seq: ctx.commit_seq,
                writer: ctx.txn_id,
                data: version_data,
            },
        );
        // Record the block as a prune candidate the moment its chain FIRST crosses
        // to 2 versions. Installs add one version at a time, so every multi-version
        // chain passes through `len == 2` exactly once per episode — inserting only
        // then (not on every 2→3→… install to an already-tracked block) keeps this
        // near-free on the hot path while still catching every prunable block; prune
        // drops a block once it collapses back to 1 version (bd-cc-prunecand).
        if versions.len() == 2 {
            shard.prune_candidates.insert(block);
        }
    }

    fn ssi_shards_for_txn(&self, txn: &Transaction) -> ShardIndexVec {
        let mut shard_indices: ShardIndexVec = txn
            .write_set()
            .keys()
            .chain(txn.read_set().keys())
            .map(|block| self.shard_index(*block))
            .collect();
        shard_indices.sort_unstable();
        shard_indices.dedup();
        shard_indices
    }

    fn validate_ssi_read_set_locked(
        &self,
        txn: &Transaction,
        shard_guards: &[(usize, ShardWriteGuard<'_>)],
    ) -> Result<(), CommitError> {
        for block in txn.read_set().keys().chain(txn.write_set().keys()) {
            let shard_idx = self.shard_index(*block);
            if shard_guards
                .binary_search_by_key(&shard_idx, |(idx, _)| *idx)
                .is_err()
            {
                return Err(CommitError::DurabilityFailure {
                    detail: "shard guard missing".into(),
                });
            }
        }

        let mut records = BTreeMap::new();
        for (_, shard) in shard_guards {
            for record in shard.ssi_log.iter().rev() {
                if record.commit_seq <= txn.snapshot().high {
                    break;
                }
                records
                    .entry((record.commit_seq.0, record.txn_id.0))
                    .or_insert_with(|| record.clone());
            }
        }

        let (_checks_performed, dangerous_structure) =
            detect_ssi_dangerous_structure(txn, records.values());
        if let Some(dangerous_structure) = dangerous_structure {
            dangerous_structure.emit_logs(txn.id());
            return Err(dangerous_structure.to_commit_error());
        }

        Ok(())
    }

    fn append_ssi_record_locked(
        shard_guards: &mut [(usize, ShardWriteGuard<'_>)],
        record: &CommittedTxnRecord,
    ) {
        for (_, shard) in shard_guards {
            shard.ssi_log.push(record.clone());
        }
    }

    /// The current snapshot (latest committed version).
    #[must_use]
    pub fn current_snapshot(&self) -> Snapshot {
        let high = self.publication_gate.completed();
        Snapshot {
            high: CommitSeq(high),
        }
    }

    fn next_commit_seq(&self) -> Result<CommitSeq, CommitError> {
        // `fetch_update` (a checked CAS loop) is retained over a wait-free
        // `fetch_add`: the counter is BOUNDED (must error, not wrap, on
        // exhaustion — a wrapped commit seq breaks monotonicity), and a
        // conditional increment fundamentally needs compare-exchange. See the
        // 2026-07-13 negative-ledger row: the wait-free variant's isolated win is
        // real but end-to-end negligible (this atomic is <0.5% of a commit).
        match self
            .next_commit
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            }) {
            Ok(prev) => Ok(CommitSeq(prev)),
            Err(current) => Err(CommitError::DurabilityFailure {
                detail: format!("commit sequence exhausted at {current}"),
            }),
        }
    }

    fn next_txn_id(&self) -> Result<TxnId, CommitError> {
        match self
            .next_txn
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                if (1..u64::MAX).contains(&current) {
                    Some(current + 1)
                } else {
                    None
                }
            }) {
            Ok(prev) => Ok(TxnId(prev)),
            Err(current) => Err(CommitError::DurabilityFailure {
                detail: format!("transaction id exhausted at {current}"),
            }),
        }
    }

    /// Begin a new transaction at the current snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`CommitError::DurabilityFailure`] if the transaction ID
    /// allocator is exhausted or has reached an invalid sentinel state.
    pub fn try_begin(&self) -> Result<Transaction, CommitError> {
        let id = self.next_txn_id()?;
        let snapshot = self.current_snapshot();
        Ok(Transaction::new(id, snapshot))
    }

    /// Begin a new transaction at the current snapshot.
    ///
    /// If the transaction ID allocator is exhausted, this compatibility entry
    /// point returns a sentinel transaction that [`Self::commit`] rejects before
    /// any writes are installed. Use [`Self::try_begin`] when callers need to
    /// handle exhaustion explicitly at begin time.
    pub fn begin(&self) -> Transaction {
        self.try_begin()
            .unwrap_or_else(|_| Transaction::new(TxnId(u64::MAX), self.current_snapshot()))
    }

    /// The latest commit sequence for a block (per-shard query).
    #[must_use]
    pub fn latest_commit_seq(&self, block: BlockNumber) -> CommitSeq {
        let shard_idx = self.shard_index(block);
        let shard = self.shards[shard_idx].read();
        let published_high = CommitSeq(self.publication_gate.completed());
        Self::latest_published_commit_seq_in_shard(&shard, block, published_high)
    }

    /// Read the version of `block` visible at `snapshot`.
    #[must_use]
    pub fn read_visible(&self, block: BlockNumber, snapshot: Snapshot) -> Option<Vec<u8>> {
        // No version has ever been installed (read-only mount): skip the shard hash
        // + read-lock + empty-map probe entirely (bd-cc-mvccempty).
        if !self.any_version_installed.load(Ordering::Acquire) {
            return None;
        }
        let shard_idx = self.shard_index(block);
        let shard = self.shards[shard_idx].read();
        // Newest-first check then O(log n) binary search over the ascending
        // `commit_seq` chain (via `newest_visible_index`), instead of an O(n)
        // reverse linear scan — identical result for any ascending chain
        // (`newest_visible_index_by_matches_reverse_scan_iso`), but a reader
        // holding the GC watermark down no longer pays a per-read walk past
        // every newer version. Mirrors `read_visible_physical`.
        shard
            .versions
            .get(&block)
            .and_then(|versions| crate::resolve_version_bytes_at_or_before(versions, snapshot.high))
    }

    /// Read the visible version of `block` as a [`ffs_block::BlockBuf`]
    /// (bd-cc-shardread). Mirrors [`Self::read_visible`] but shares
    /// uncompressed `VersionData::Full` storage instead of cloning through an
    /// owned `Vec`, completing the read interface the OpenFs store needs.
    /// Byte-identical to `read_visible` wrapped in a `BlockBuf` (verified by
    /// `sharded_read_visible_block_buf_shares_full_version_storage`).
    #[must_use]
    pub fn read_visible_block_buf(
        &self,
        block: BlockNumber,
        snapshot: Snapshot,
    ) -> Option<ffs_block::BlockBuf> {
        // Mirror `read_visible`'s empty-store fast path (bd-cc-mvccempty): with no
        // version ever installed (read-only mount), skip the shard hash + read-lock
        // + empty-map probe — the result is `None` either way (no map holds `block`).
        if !self.any_version_installed.load(Ordering::Acquire) {
            return None;
        }
        let shard_idx = self.shard_index(block);
        let shard = self.shards[shard_idx].read();
        shard.versions.get(&block).and_then(|versions| {
            let idx = crate::newest_visible_index(versions, snapshot.high)?;
            compression::resolve_block_buf_with(versions, idx, |version| &version.data)
        })
    }

    /// Resolve the visible PHYSICAL block for a logical block (bd-cc-shardread).
    /// The sharded store backs the no-COW ext4 write path and does NOT track COW
    /// physical remapping, so a visible logical block maps to itself — exactly the
    /// behaviour of `MvccStore::read_visible_physical` when a block has no
    /// `physical_versions` chain (its documented fallback). A cheap existence
    /// check (no byte resolution) under the shard read lock.
    #[must_use]
    pub fn read_visible_physical(
        &self,
        logical: BlockNumber,
        snapshot: Snapshot,
    ) -> Option<BlockNumber> {
        if !self.any_version_installed.load(Ordering::Acquire) {
            return None;
        }
        let shard = self.shards[self.shard_index(logical)].read();
        shard
            .versions
            .get(&logical)
            .and_then(|versions| crate::newest_visible_index(versions, snapshot.high))
            .map(|_| logical)
    }

    /// Durable checkpoint (bd-cc-shardflush): write the visible-at-current-snapshot
    /// version of every block across all shards to `device`, coalescing contiguous
    /// runs into one ranged `write_contiguous_blocks` each (mirrors
    /// `MvccStore::flush_to_device` / bd-ryqep over the sharded layout — same
    /// bytes/locations). A CONSISTENT checkpoint up to `current_snapshot().high`:
    /// each shard is read under its own lock, and `snapshot.high` bounds visibility
    /// so the result is a coherent prefix; concurrent commits beyond `high` land in
    /// the next checkpoint (and the WAL). Completes the OpenFs store interface so the
    /// sharded store is wireable.
    pub fn flush_to_device<D: BlockDevice>(&self, cx: &Cx, device: &D) -> FfsResult<usize> {
        self.flush_to_device_after(cx, device, CommitSeq(0))
            .map(|(flushed, _)| flushed)
    }

    /// Flush versions committed after `flushed_through` and return the snapshot
    /// through which the device is durable.
    ///
    /// The caller must serialize calls and advance its watermark only after this
    /// method succeeds. Keeping that cursor at the filesystem/device boundary
    /// lets the public [`Self::flush_to_device`] retain its full-checkpoint
    /// semantics for callers that supply unrelated devices.
    pub fn flush_to_device_after<D: BlockDevice>(
        &self,
        cx: &Cx,
        device: &D,
        flushed_through: CommitSeq,
    ) -> FfsResult<(usize, CommitSeq)> {
        let snapshot = self.current_snapshot();
        if snapshot.high <= flushed_through {
            return Ok((0, snapshot.high));
        }
        // Collect visible (block, bytes) across all shards (each under its read lock,
        // briefly), then sort + coalesce + write holding no shard lock.
        let mut items: Vec<(BlockNumber, Vec<u8>)> = Vec::new();
        for shard in &self.shards {
            let shard = shard.read();
            for (block, versions) in &shard.versions {
                let Some(idx) = crate::newest_visible_index(versions, snapshot.high) else {
                    continue;
                };
                if versions[idx].commit_seq <= flushed_through {
                    continue;
                }
                if let Some(bytes) = compression::resolve_data_with(versions, idx, |v| &v.data)
                    .map(std::borrow::Cow::into_owned)
                {
                    items.push((*block, bytes));
                }
            }
        }
        items.sort_unstable_by_key(|(block, _)| block.0);

        let mut flushed = 0_usize;
        let mut run_start: Option<BlockNumber> = None;
        let mut run_next: u64 = 0;
        let mut run_buf: Vec<u8> = Vec::new();
        for (block, data) in &items {
            let continues = run_start.is_some() && block.0 == run_next;
            if !continues {
                if let Some(start) = run_start.take() {
                    device.write_contiguous_blocks(cx, start, &run_buf)?;
                    run_buf.clear();
                }
                run_start = Some(*block);
            }
            run_buf.extend_from_slice(data);
            run_next = block.0.saturating_add(1);
            flushed += 1;
        }
        if let Some(start) = run_start.take() {
            device.write_contiguous_blocks(cx, start, &run_buf)?;
        }
        if flushed > 0 {
            device.sync(cx)?;
        }
        Ok((flushed, snapshot.high))
    }

    /// Commit a transaction with first-committer-wins (FCW) conflict detection.
    ///
    /// Shard locks are acquired in sorted order to prevent deadlocks.
    #[allow(clippy::result_large_err)]
    pub fn commit(&self, txn: Transaction) -> Result<CommitSeq, (CommitError, Transaction)> {
        self.commit_with_probe(txn, &mut NoopCommitLockProbe)
    }

    /// Commit through the production algorithm while recording worker-local
    /// lock timings. This entry point exists only for the characterization
    /// binary and is absent from normal builds.
    #[cfg(feature = "bench-instrumentation")]
    #[allow(clippy::result_large_err)]
    pub fn commit_profiled(
        &self,
        txn: Transaction,
        profile: &mut CommitLockProfile,
    ) -> Result<CommitSeq, (CommitError, Transaction)> {
        self.commit_with_probe(txn, profile)
    }

    #[cfg_attr(feature = "bench-instrumentation", inline(never))]
    #[allow(clippy::result_large_err)]
    fn commit_with_probe<P: CommitLockProbe>(
        &self,
        txn: Transaction,
        probe: &mut P,
    ) -> Result<CommitSeq, (CommitError, Transaction)> {
        if let Err(error) = validate_transaction_id(txn.id()) {
            return Err((error, txn));
        }

        if txn.write_set().is_empty() {
            // Read-only transaction: nothing to commit.
            return Ok(self.current_snapshot().high);
        }

        let shard_indices = self.involved_shards(&txn);
        let (effective, record_metrics) = self.commit_policy();
        let shard_wait_started = probe.start();
        let mut shard_guards = self.lock_shards(&shard_indices);
        probe.finish(CommitLockPhase::ShardWait, shard_wait_started);
        let shard_hold_started = probe.start();

        if let Err(error) = self.preflight_fcw_locked(
            &txn,
            &shard_guards,
            effective,
            record_metrics,
            "sharded_fcw_conflict_merged",
        ) {
            drop(shard_guards);
            probe.finish(CommitLockPhase::ShardHold, shard_hold_started);
            return Err((error, txn));
        }

        let commit_seq = match self.next_commit_seq() {
            Ok(seq) => seq,
            Err(err) => {
                drop(shard_guards);
                probe.finish(CommitLockPhase::ShardHold, shard_hold_started);
                return Err((err, txn));
            }
        };
        trace!(
            commit_seq = commit_seq.0,
            shards_involved = shard_indices.len(),
            blocks_written = txn.write_set().len(),
            "sharded_commit"
        );

        let install_ctx = CommitInstallContext {
            snapshot: txn.snapshot(),
            commit_seq,
            txn_id: txn.id(),
            dedup_enabled: self.compression_policy.dedup_identical,
        };
        for (block, staged) in txn.into_staged_writes() {
            let shard_idx = self.shard_index(block);
            let Some(shard) = shard_guards
                .binary_search_by_key(&shard_idx, |(idx, _)| *idx)
                .ok()
                .map(|pos| &mut shard_guards[pos].1)
            else {
                tracing::error!("missing shard guard for block {block:?}");
                continue;
            };
            Self::install_committed_version_locked(
                shard,
                block,
                staged.bytes,
                Some(&staged.merge_proof),
                staged.base.as_deref(),
                install_ctx,
            );
        }
        // A version now exists; enable the version-aware read path. Set before
        // publish so any snapshot that can see this commit also sees the flag.
        // Monotonic (never clears), so a relaxed load guards the Release store:
        // after the first-ever install this is a no-op, avoiding a redundant
        // per-commit (previously per-BLOCK) store that dirties a cache line EVERY
        // read loads (any_version_installed at read fast paths) — committer↔reader
        // false sharing on the parallel path.
        if !self.any_version_installed.load(Ordering::Relaxed) {
            self.any_version_installed.store(true, Ordering::Release);
        }

        // Release shard locks before ordered publication. All version data is
        // already installed; the gate only preserves monotonic snapshot
        // visibility without burning CPU when commits finish out of order.
        drop(shard_guards);
        probe.finish(CommitLockPhase::ShardHold, shard_hold_started);
        self.publication_gate.publish_with_probe(commit_seq, probe);

        Ok(commit_seq)
    }

    /// Commit with Serializable Snapshot Isolation (SSI) enforcement.
    #[allow(clippy::result_large_err)]
    pub fn commit_ssi(&self, txn: Transaction) -> Result<CommitSeq, (CommitError, Transaction)> {
        if let Err(error) = validate_transaction_id(txn.id()) {
            return Err((error, txn));
        }

        if txn.write_set().is_empty() {
            return Ok(self.current_snapshot().high);
        }

        let shard_indices = self.ssi_shards_for_txn(&txn);
        let (effective, record_metrics) = self.commit_policy();
        let mut shard_guards = self.lock_shards(&shard_indices);

        if let Err(error) = self.preflight_fcw_locked(
            &txn,
            &shard_guards,
            effective,
            record_metrics,
            "sharded_ssi_fcw_conflict_merged",
        ) {
            return Err((error, txn));
        }

        if let Err(error) = self.validate_ssi_read_set_locked(&txn, &shard_guards) {
            return Err((error, txn));
        }

        let commit_seq = match self.next_commit_seq() {
            Ok(seq) => seq,
            Err(err) => return Err((err, txn)),
        };
        let install_ctx = CommitInstallContext {
            snapshot: txn.snapshot(),
            commit_seq,
            txn_id: txn.id(),
            dedup_enabled: self.compression_policy.dedup_identical,
        };
        let read_set = txn.read_set().clone();
        let write_keys: BTreeSet<BlockNumber> = txn.write_set().keys().copied().collect();

        for (block, staged) in txn.into_staged_writes() {
            let shard_idx = self.shard_index(block);
            let Some(shard) = shard_guards
                .binary_search_by_key(&shard_idx, |(idx, _)| *idx)
                .ok()
                .map(|pos| &mut shard_guards[pos].1)
            else {
                tracing::error!("missing shard guard for block {block:?}");
                continue;
            };
            Self::install_committed_version_locked(
                shard,
                block,
                staged.bytes,
                Some(&staged.merge_proof),
                staged.base.as_deref(),
                install_ctx,
            );
        }
        // Monotonic flag; relaxed-load guard skips the redundant Release store
        // (and its committer↔reader false sharing) after the first-ever install.
        if !write_keys.is_empty() && !self.any_version_installed.load(Ordering::Relaxed) {
            self.any_version_installed.store(true, Ordering::Release);
        }

        let ssi_record = CommittedTxnRecord {
            txn_id: install_ctx.txn_id,
            commit_seq,
            snapshot: install_ctx.snapshot,
            write_set: write_keys,
            read_set,
        };
        Self::append_ssi_record_locked(&mut shard_guards, &ssi_record);

        // Release shard locks before ordered publication. All version data and
        // SSI records are already installed; the gate only preserves monotonic
        // snapshot visibility without burning CPU when commits finish out of
        // order.
        drop(shard_guards);
        self.publication_gate.publish(commit_seq);

        Ok(commit_seq)
    }

    // ── Snapshot tracking (inline, for compatibility) ────────────────────

    /// Register a snapshot as active (inline tracking).
    pub fn register_snapshot(&self, snapshot: Snapshot) {
        let mut active = self.active_snapshots.write();
        active
            .entry(snapshot.high)
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
    }

    /// Release a previously registered snapshot.
    pub fn release_snapshot(&self, snapshot: Snapshot) -> bool {
        let mut active = self.active_snapshots.write();
        active.get(&snapshot.high).copied().is_some_and(|count| {
            if count <= 1 {
                active.remove(&snapshot.high);
            } else {
                active.insert(snapshot.high, count.saturating_sub(1));
            }
            true
        })
    }

    /// Oldest active snapshot, or `None`.
    #[must_use]
    pub fn watermark(&self) -> Option<CommitSeq> {
        self.active_snapshots.read().keys().next().copied()
    }

    /// Number of active snapshot references.
    #[must_use]
    pub fn active_snapshot_count(&self) -> usize {
        self.active_snapshots
            .read()
            .values()
            .fold(0_usize, |total, count| {
                total.saturating_add(usize::try_from(*count).unwrap_or(usize::MAX))
            })
    }

    // ── GC / pruning ────────────────────────────────────────────────────

    /// Prune versions older than `watermark` across all shards.
    pub fn prune_versions_older_than(&self, watermark: CommitSeq) {
        for (idx, shard_lock) in self.shards.iter().enumerate() {
            let mut shard = shard_lock.write();
            // Visit only blocks whose chain has grown past 1 version (the prune
            // candidates), instead of scanning every versioned block in the shard.
            // A block that collapses back to a single version is dropped from the
            // set; one that is still multi-version (watermark not yet past its 2nd
            // version) is retained for a later cycle (bd-cc-prunecand).
            let candidates = std::mem::take(&mut shard.prune_candidates);
            let mut still: FxHashSet<BlockNumber> = FxHashSet::default();
            for block in candidates {
                let Some(versions) = shard.versions.get_mut(&block) else {
                    continue;
                };
                if versions.len() <= 1 {
                    continue;
                }
                let mut keep_from = 0_usize;
                while keep_from + 1 < versions.len() {
                    if versions[keep_from + 1].commit_seq <= watermark {
                        keep_from += 1;
                    } else {
                        break;
                    }
                }
                if keep_from > 0 {
                    Self::make_chain_head_full(versions, keep_from);
                    versions.drain(0..keep_from);
                }
                if versions.len() > 1 {
                    still.insert(block);
                }
            }
            shard.prune_candidates = still;
            // Prune SSI log for this shard too.
            shard.ssi_log.retain(|r| r.commit_seq > watermark);
            drop(shard);
            trace!(shard_idx = idx, watermark = watermark.0, "shard_pruned");
        }
    }

    /// Safe prune: use watermark from active snapshots.
    ///
    /// Holds the `active_snapshots` write lock while pruning to prevent a
    /// TOCTOU race where a snapshot is registered between reading the
    /// watermark and pruning versions older than it.
    pub fn prune_safe(&self) -> CommitSeq {
        let active = self.active_snapshots.write();
        let wm = active
            .keys()
            .next()
            .copied()
            .unwrap_or_else(|| self.current_snapshot().high);
        // Hold the active_snapshots lock while pruning so no new snapshot
        // can be registered at a commit_seq that we're about to prune.
        self.prune_versions_older_than(wm);
        drop(active);
        debug!(watermark = wm.0, "prune_safe_sharded");
        wm
    }

    /// Safe prune using an external [`SnapshotRegistry`].
    ///
    /// Holds the registry's read lock while pruning to prevent a TOCTOU race
    /// where a snapshot is registered between reading the watermark and
    /// pruning versions older than it.
    pub fn prune_safe_with_registry(&self, registry: &SnapshotRegistry) -> CommitSeq {
        let wm = registry.watermark_under_guard(|wm_opt| {
            let wm = wm_opt.unwrap_or_else(|| self.current_snapshot().high);
            // Prune while the registry's internal lock is still held,
            // preventing concurrent snapshot registration below the watermark.
            self.prune_versions_older_than(wm);
            wm
        });
        debug!(watermark = wm.0, "prune_safe_registry");
        wm
    }

    /// Total number of block versions across all shards.
    #[must_use]
    pub fn version_count(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                s.read()
                    .versions
                    .values()
                    .map(|versions| versions.len())
                    .sum::<usize>()
            })
            .sum()
    }

    /// Number of distinct versioned blocks across all shards.
    #[must_use]
    pub fn block_count_versioned(&self) -> usize {
        self.shards.iter().map(|s| s.read().versions.len()).sum()
    }

    // ── Internals ───────────────────────────────────────────────────────

    /// Sorted, deduplicated shard indices touched by a transaction's writes.
    fn involved_shards(&self, txn: &Transaction) -> ShardIndexVec {
        // Avoid BTreeSet and heap allocation for the common short shard lists.
        let mut indices: ShardIndexVec = txn
            .write_set()
            .keys()
            .map(|block| self.shard_index(*block))
            .collect();
        indices.sort_unstable();
        indices.dedup();
        indices
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn publication_mode_cutover_defaults_to_wait_free_with_mutex_fallback() {
        assert_eq!(PublicationMode::default(), PublicationMode::WaitFree);
        assert_eq!(
            PublicationMode::from_env_value(None),
            PublicationMode::WaitFree
        );
        for enabled in ["1", "true", "on", "yes"] {
            assert_eq!(
                PublicationMode::from_env_value(Some(enabled)),
                PublicationMode::WaitFree
            );
        }
        for fallback in ["0", "false", "off", "no", "mutex", "invalid"] {
            assert_eq!(
                PublicationMode::from_env_value(Some(fallback)),
                PublicationMode::Mutex
            );
        }
        assert_eq!(
            PublicationMode::from_env_value(Some("nospin")),
            PublicationMode::WaitFreeNoSpin
        );
    }

    fn make_store(shards: usize) -> ShardedMvccStore {
        ShardedMvccStore::new(shards)
    }

    #[derive(Debug)]
    struct CheckpointDevice {
        blocks: RwLock<HashMap<BlockNumber, Vec<u8>>>,
        block_size: u32,
        block_count: u64,
    }

    impl CheckpointDevice {
        fn new(block_size: u32, block_count: u64) -> Self {
            Self {
                blocks: RwLock::new(HashMap::new()),
                block_size,
                block_count,
            }
        }
    }

    impl BlockDevice for CheckpointDevice {
        fn read_block(
            &self,
            _cx: &Cx,
            block: BlockNumber,
        ) -> ffs_error::Result<ffs_block::BlockBuf> {
            let data = self
                .blocks
                .read()
                .get(&block)
                .cloned()
                .unwrap_or_else(|| vec![0_u8; self.block_size as usize]);
            Ok(ffs_block::BlockBuf::new(data))
        }

        fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> ffs_error::Result<()> {
            self.blocks.write().insert(block, data.to_vec());
            Ok(())
        }

        fn block_size(&self) -> u32 {
            self.block_size
        }

        fn block_count(&self) -> u64 {
            self.block_count
        }

        fn sync(&self, _cx: &Cx) -> ffs_error::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn incremental_flush_writes_only_versions_after_watermark() {
        const BS: u32 = 4096;
        let cx = Cx::for_testing();
        let store = make_store(4);
        let dev = CheckpointDevice::new(BS, 64);

        let mut initial = store.begin();
        initial.stage_write(BlockNumber(10), vec![0x10; BS as usize]);
        initial.stage_write(BlockNumber(11), vec![0x11; BS as usize]);
        store.commit(initial).expect("initial commit");
        let (initial_flushed, initial_through) = store
            .flush_to_device_after(&cx, &dev, CommitSeq(0))
            .expect("initial checkpoint");
        assert_eq!(initial_flushed, 2);

        let mut changed = store.begin();
        changed.stage_write(BlockNumber(11), vec![0xBB; BS as usize]);
        changed.stage_write(BlockNumber(20), vec![0xCC; BS as usize]);
        store.commit(changed).expect("changed commit");
        let (incremental_flushed, incremental_through) = store
            .flush_to_device_after(&cx, &dev, initial_through)
            .expect("incremental checkpoint");
        assert_eq!(incremental_flushed, 2);
        assert!(incremental_through > initial_through);

        let blocks = dev.blocks.read();
        assert_eq!(
            blocks.get(&BlockNumber(10)).unwrap(),
            &vec![0x10; BS as usize],
            "unchanged durable block must remain byte-identical"
        );
        assert_eq!(
            blocks.get(&BlockNumber(11)).unwrap(),
            &vec![0xBB; BS as usize]
        );
        assert_eq!(
            blocks.get(&BlockNumber(20)).unwrap(),
            &vec![0xCC; BS as usize]
        );
        drop(blocks);

        let (repeat_flushed, repeat_through) = store
            .flush_to_device_after(&cx, &dev, incremental_through)
            .expect("idempotent checkpoint");
        assert_eq!(repeat_flushed, 0);
        assert_eq!(repeat_through, incremental_through);

        let unrelated = CheckpointDevice::new(BS, 64);
        assert_eq!(
            store.flush_to_device(&cx, &unrelated).unwrap(),
            3,
            "public full-checkpoint API must not inherit another device's cursor"
        );
    }

    #[test]
    fn report_hot_field_cache_line_layout() {
        use std::mem::{offset_of, size_of};
        let nt = offset_of!(ShardedMvccStore, next_txn);
        let nc = offset_of!(ShardedMvccStore, next_commit);
        let sm = offset_of!(ShardedMvccStore, shard_mask);
        let sc = offset_of!(ShardedMvccStore, shard_count);
        let av = offset_of!(ShardedMvccStore, any_version_installed);
        let pg = offset_of!(ShardedMvccStore, publication_gate);
        let asn = offset_of!(ShardedMvccStore, active_snapshots);
        // Read-hot: shard_mask/shard_count (every shard_index), any_version_installed
        // (every read). Write-hot: next_txn/next_commit (every commit).
        eprintln!(
            "FIELDLAYOUT size={} next_txn={nt} next_commit={nc} shard_mask={sm} \
             shard_count={sc} any_version_installed={av} publication_gate={pg} \
             active_snapshots={asn}",
            size_of::<ShardedMvccStore>()
        );
        eprintln!(
            "FIELDLAYOUT line64: shard_mask={} next_commit={} next_txn={} \
             any_version_installed={} publication_gate={}",
            sm / 64,
            nc / 64,
            nt / 64,
            av / 64,
            pg / 64
        );
        eprintln!(
            "FIELDLAYOUT collide shard_mask/next_commit={} shard_count/next_commit={} \
             any_version_installed/next_commit={} any_version_installed/publication_gate={}",
            sm / 64 == nc / 64,
            sc / 64 == nc / 64,
            av / 64 == nc / 64,
            av / 64 == pg / 64
        );
        let _ = (sc, asn, nt, pg);
        // Diagnostic only: `shard_mask` DOES share a cache line with next_commit
        // here, but cache-line-isolating it measured NEUTRAL (a plain read-hot
        // field is register-hoisted, so it is not re-read from the invalidated
        // line) — see the 2026-07-13 negative-ledger row. Left as documentation of
        // the layout; no isolation is enforced.
        assert_eq!(sm / 64, nc / 64);
    }

    #[test]
    fn prune_preserves_read_visible_data_after_chain_head_compaction() {
        // With dedup on, a repeated identical write becomes an `Identical`
        // version; pruning makes it the chain head, which `make_chain_head_full`
        // must MATERIALIZE to `Full` (the path bd-xmh5g.395 changed to move the
        // resolved Cow via `into_owned`). The invariant under test holds
        // regardless of that detail: pruning a version chain must never change
        // the bytes visible at any retained snapshot — the conformance guard the
        // GC compaction path previously lacked.
        let policy = CompressionPolicy {
            dedup_identical: true,
            max_chain_length: None,
            algo: compression::CompressionAlgo::None,
        };
        let store = ShardedMvccStore::with_compression_policy(8, policy);
        let block = BlockNumber(42);
        let d = vec![0xAB_u8; 100];
        let e = vec![0xCD_u8; 100];

        let mut t1 = store.begin();
        t1.stage_write(block, d.clone());
        store.commit(t1).expect("commit 1");

        let mut t2 = store.begin();
        t2.stage_write(block, d.clone()); // identical -> deduped to Identical
        let seq2 = store.commit(t2).expect("commit 2");

        let mut t3 = store.begin();
        t3.stage_write(block, e.clone());
        let seq3 = store.commit(t3).expect("commit 3");

        // Pre-prune visibility: D at seq2 (via the Identical), E at seq3.
        assert_eq!(
            store.read_visible(block, Snapshot { high: seq2 }),
            Some(d.clone())
        );
        assert_eq!(
            store.read_visible(block, Snapshot { high: seq3 }),
            Some(e.clone())
        );

        // Trim everything at or before seq2: the Identical@seq2 becomes the head
        // and is materialized by make_chain_head_full; the older Full is drained.
        store.prune_versions_older_than(seq2);

        // The visible bytes must be byte-identical after compaction.
        assert_eq!(
            store.read_visible(block, Snapshot { high: seq2 }),
            Some(d),
            "chain-head compaction must preserve the bytes visible at the retained snapshot"
        );
        assert_eq!(store.read_visible(block, Snapshot { high: seq3 }), Some(e));
    }

    #[test]
    fn sharded_store_rounds_and_bounds_shard_count() {
        assert_eq!(ShardedMvccStore::new(0).shard_count(), 1);
        assert_eq!(ShardedMvccStore::new(3).shard_count(), 4);
        assert_eq!(
            ShardedMvccStore::new(MAX_MVCC_SHARDS + 1).shard_count(),
            MAX_MVCC_SHARDS
        );

        let host_shards = ShardedMvccStore::host_parallelism_shard_count();
        assert!(host_shards.is_power_of_two());
        assert!((MIN_MVCC_SHARDS..=MAX_MVCC_SHARDS).contains(&host_shards));
        assert_eq!(
            ShardedMvccStore::for_host_parallelism().shard_count(),
            host_shards
        );
    }

    #[test]
    fn commit_publication_gate_preserves_order_without_busy_spin() {
        use std::sync::mpsc;
        use std::time::Duration;

        let gate = Arc::new(CommitPublicationGate::new());
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker_gate = Arc::clone(&gate);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).expect("send started");
            worker_gate.publish(CommitSeq(2));
            done_tx.send(()).expect("send done");
        });

        started_rx.recv().expect("worker started");
        assert!(
            done_rx.recv_timeout(Duration::from_millis(20)).is_err(),
            "commit 2 must not publish before commit 1"
        );
        assert_eq!(gate.completed(), 0);

        gate.publish(CommitSeq(1));
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("commit 2 published after predecessor");
        worker.join().expect("worker joined");
        assert_eq!(gate.completed(), 2);
    }

    #[test]
    fn commit_publication_gate_advances_ready_prefix_golden_report() {
        use std::sync::mpsc;
        use std::time::Duration;

        let gate = Arc::new(CommitPublicationGate::new());
        let (done_tx, done_rx) = mpsc::channel();
        let mut workers = Vec::new();
        for seq in [CommitSeq(3), CommitSeq(2)] {
            let worker_gate = Arc::clone(&gate);
            let done_tx = done_tx.clone();
            workers.push(std::thread::spawn(move || {
                worker_gate.publish(seq);
                done_tx.send(seq).expect("send completed seq");
            }));
        }
        drop(done_tx);

        let mut ready_count = 0_usize;
        for _ in 0..100 {
            ready_count = gate.wait_lock.lock().ready_commits.len();
            if ready_count == 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(ready_count, 2, "commits 2 and 3 should be ready");
        assert_eq!(gate.completed(), 0);
        assert!(
            done_rx.recv_timeout(Duration::from_millis(20)).is_err(),
            "out-of-order commits must not publish before commit 1"
        );

        gate.publish(CommitSeq(1));
        let mut completed = [
            done_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("first waiting commit published"),
            done_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("second waiting commit published"),
        ];
        completed.sort_by_key(|seq| seq.0);
        assert_eq!(completed, [CommitSeq(2), CommitSeq(3)]);
        for worker in workers {
            worker.join().expect("worker joined");
        }
        assert_eq!(gate.completed(), 3);
        println!(
            "SHARDED_PUBLISH_GOLDEN|ready_prefix=2,3|release=1|completed={}",
            gate.completed()
        );
    }

    /// Both publication modes must be indistinguishable: every publisher returns
    /// only once its own sequence is covered, and the watermark advances over a
    /// contiguous prefix, so no snapshot taken under one mode could observe a
    /// state the other cannot produce. Shuffled concurrent publication is the
    /// adversarial case — it forces out-of-order arrivals, which is exactly where
    /// the wait-free ring and the mutex/BTreeSet gate could diverge.
    #[test]
    fn commit_publication_gate_wait_free_matches_mutex_under_shuffled_publish() {
        const SEQS: u64 = 2000;
        const THREADS: u64 = 8;

        for mode in [
            PublicationMode::Mutex,
            PublicationMode::WaitFree,
            PublicationMode::WaitFreeNoSpin,
        ] {
            let gate = Arc::new(CommitPublicationGate::with_mode(mode));
            let mut handles = Vec::new();
            for thread in 0..THREADS {
                let gate = Arc::clone(&gate);
                handles.push(std::thread::spawn(move || {
                    // Strided: each thread owns a non-contiguous subset, so
                    // within every round the arrival order is whatever the
                    // scheduler picks — the out-of-order case the ring and the
                    // BTreeSet could diverge on. Ascending per thread keeps the
                    // set collectively publishable: a thread parked on seq `s`
                    // only waits on predecessors owned by threads that are not
                    // themselves waiting on `s`.
                    let mut seq = thread.saturating_add(1);
                    while seq <= SEQS {
                        gate.publish(CommitSeq(seq));
                        // Publishing returns only when the caller's own sequence
                        // is covered — the contract both modes share.
                        assert!(
                            gate.completed() >= seq,
                            "{mode:?}: publish returned before covering {seq}"
                        );
                        seq = seq.saturating_add(THREADS);
                    }
                }));
            }
            for handle in handles {
                handle.join().expect("publisher joined");
            }
            assert_eq!(gate.completed(), SEQS, "{mode:?}: final watermark");
            assert!(
                gate.wait_lock.lock().ready_commits.is_empty(),
                "{mode:?}: buffered remnants"
            );
            assert_eq!(gate.parked.load(Ordering::SeqCst), 0, "{mode:?}: leaked waiter");
        }
    }

    /// A wait-free publisher must never expose a gap: at every observation the
    /// watermark is a contiguous prefix, so a reader resolving at `completed`
    /// sees a state in which every earlier commit is installed.
    ///
    /// White-box on purpose. `publish` BLOCKS until the caller's own sequence is
    /// covered — that is the contract — so a single thread cannot drive an
    /// out-of-order case through it. Staging the ring directly and calling the
    /// drain is the only way to observe the prefix rule without a second thread.
    #[test]
    fn commit_publication_gate_wait_free_advances_only_over_contiguous_prefix() {
        let gate = CommitPublicationGate::with_mode(PublicationMode::WaitFree);
        let slot = |seq: u64| usize::try_from(seq & PUBLICATION_RING_MASK).expect("ring slot");

        gate.ring[slot(3)].store(3, Ordering::Release);
        assert!(!gate.drain_ready_prefix(), "3 must not publish ahead of 1, 2");
        assert_eq!(gate.completed(), 0);

        gate.ring[slot(2)].store(2, Ordering::Release);
        assert!(!gate.drain_ready_prefix(), "2 must not publish ahead of 1");
        assert_eq!(gate.completed(), 0);

        // 1 arrives: the whole contiguous 1..=3 prefix retires in one drain.
        gate.publish(CommitSeq(1));
        assert_eq!(gate.completed(), 3);
        assert_eq!(gate.parked.load(Ordering::SeqCst), 0);

        gate.publish(CommitSeq(1));
        assert_eq!(gate.completed(), 3, "duplicate publish is a no-op");
        gate.publish(CommitSeq(3));
        assert_eq!(gate.completed(), 3, "already-covered publish is a no-op");
    }

    #[test]
    fn commit_publication_gate_duplicate_publish_returns_promptly() {
        use std::sync::mpsc;
        use std::time::Duration;

        let gate = Arc::new(CommitPublicationGate::new());
        gate.publish(CommitSeq(1));
        assert_eq!(gate.completed(), 1);

        let (done_tx, done_rx) = mpsc::channel();
        let worker_gate = Arc::clone(&gate);
        let worker = std::thread::spawn(move || {
            worker_gate.publish(CommitSeq(1));
            done_tx.send(()).expect("send duplicate publish done");
        });

        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("duplicate publish should not wait for an impossible predecessor");
        worker.join().expect("worker joined");
        assert_eq!(gate.completed(), 1);
    }

    #[test]
    fn latest_commit_seq_hides_unpublished_versions() {
        use std::sync::mpsc;
        use std::time::Duration;

        let store = Arc::new(make_store(1));
        let block = BlockNumber(7);
        store.next_commit.store(2, Ordering::SeqCst);

        let (started_tx, started_rx) = mpsc::channel();
        let worker_store = Arc::clone(&store);
        let worker = std::thread::spawn(move || {
            let mut txn = worker_store.begin();
            txn.stage_write(block, vec![0xC2]);
            started_tx.send(()).expect("send started");
            worker_store.commit(txn).expect("commit 2");
        });

        started_rx.recv().expect("worker started");
        let mut installed = CommitSeq(0);
        for _ in 0..1_000 {
            {
                let shard = store.shards[store.shard_index(block)].read();
                installed = ShardedMvccStore::latest_commit_seq_in_shard(&shard, block);
            }
            if installed == CommitSeq(2) {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            installed,
            CommitSeq(2),
            "commit 2 should install before waiting on publication"
        );

        let visible_snapshot = store.current_snapshot();
        assert_eq!(visible_snapshot.high, CommitSeq(0));
        assert_eq!(store.latest_commit_seq(block), CommitSeq(0));
        assert_eq!(store.read_visible(block, visible_snapshot), None);

        store.publication_gate.publish(CommitSeq(1));
        worker.join().expect("worker joined");

        let latest = store.current_snapshot();
        assert_eq!(latest.high, CommitSeq(2));
        assert_eq!(store.latest_commit_seq(block), CommitSeq(2));
        assert_eq!(store.read_visible(block, latest), Some(vec![0xC2]));
    }

    #[test]
    fn basic_commit_and_read() {
        let store = make_store(4);
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(1), vec![0xAA; 8]);
        let seq = store.commit(txn).expect("commit");
        assert_eq!(seq, CommitSeq(1));

        let snap = store.current_snapshot();
        let data = store.read_visible(BlockNumber(1), snap).expect("visible");
        assert_eq!(data, vec![0xAA; 8]);
    }

    #[test]
    fn sharded_read_visible_block_buf_shares_full_version_storage() {
        let store = make_store(8);
        let block = BlockNumber(17);
        let bytes = vec![0xBC; 4096];
        let mut txn = store.begin();
        txn.stage_write(block, bytes.clone());
        store.commit(txn).expect("commit");

        let stored = {
            let shard = store.shards[store.shard_index(block)].read();
            let versions = shard.versions.get(&block).expect("version chain");
            let compression::VersionData::Full(shared) = &versions[0].data else {
                panic!("uncompressed staged write should remain full");
            };
            ffs_block::BlockBuf::from_shared_aligned(Arc::clone(shared))
        };

        let snap = store.current_snapshot();
        let read = store
            .read_visible_block_buf(block, snap)
            .expect("visible block buf");
        assert_eq!(read.as_slice(), bytes.as_slice());
        assert!(
            read.shares_storage_with(&stored),
            "sharded read_visible_block_buf should share uncompressed VersionData::Full storage"
        );
    }

    #[test]
    fn fcw_conflict_same_block() {
        let store = make_store(4);
        let mut t1 = store.begin();
        let mut t2 = store.begin();

        t1.stage_write(BlockNumber(7), vec![1]);
        t2.stage_write(BlockNumber(7), vec![2]);

        store.commit(t1).expect("t1");
        let err = store.commit(t2).expect_err("t2 should conflict");
        assert!(matches!(err, (CommitError::Conflict { .. }, _)));
    }

    #[test]
    fn fcw_append_only_merge_proof_allows_same_block_commit() {
        let store = make_store(4);
        let block = BlockNumber(9);

        let mut seed = store.begin();
        seed.stage_write(block, vec![0]);
        store.commit(seed).expect("seed");

        let mut t1 = store.begin();
        let mut t2 = store.begin();

        t1.stage_write_with_proof(
            block,
            vec![0, 1],
            crate::MergeProof::AppendOnly { base_len: 1 },
        );
        t2.stage_write_with_proof(
            block,
            vec![0, 2],
            crate::MergeProof::AppendOnly { base_len: 1 },
        );

        store.commit(t1).expect("first append");
        store
            .commit(t2)
            .expect("second append should merge instead of conflicting");

        let latest = store.current_snapshot();
        let visible = store.read_visible(block, latest).expect("visible");
        assert_eq!(visible, vec![0, 1, 2]);
    }

    #[test]
    fn disjoint_shards_no_conflict() {
        let store = make_store(4);
        let mut t1 = store.begin();
        let mut t2 = store.begin();

        // These go to different shards (0%4=0, 1%4=1).
        t1.stage_write(BlockNumber(0), vec![1]);
        t2.stage_write(BlockNumber(1), vec![2]);

        store.commit(t1).expect("t1");
        store
            .commit(t2)
            .expect("t2 should succeed (different shard)");
    }

    #[test]
    fn snapshot_isolation() {
        let store = make_store(4);

        let mut t1 = store.begin();
        t1.stage_write(BlockNumber(1), vec![1]);
        store.commit(t1).expect("commit v1");

        let snap = store.current_snapshot();

        let mut t2 = store.begin();
        t2.stage_write(BlockNumber(1), vec![2]);
        store.commit(t2).expect("commit v2");

        // Snap should still see v1.
        let data = store.read_visible(BlockNumber(1), snap).expect("visible");
        assert_eq!(data, vec![1]);

        // Latest should see v2.
        let latest = store.current_snapshot();
        let data2 = store.read_visible(BlockNumber(1), latest).expect("visible");
        assert_eq!(data2, vec![2]);
    }

    #[test]
    fn commit_sequence_advances_atomically() {
        let store = make_store(4);

        for i in 1_u64..=10 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(i), vec![u8::try_from(i).expect("i fits in u8")]);
            let seq = store.commit(txn).expect("commit");
            assert_eq!(seq, CommitSeq(i));
        }
    }

    #[test]
    fn commit_sequence_exhaustion_returns_error() {
        let store = make_store(1);
        store.next_commit.store(u64::MAX, Ordering::SeqCst);

        let mut txn = store.begin();
        txn.stage_write(BlockNumber(1), vec![0xAA]);

        let (err, _txn) = store
            .commit(txn)
            .expect_err("commit sequence should be exhausted");
        match err {
            CommitError::DurabilityFailure { detail } => {
                assert!(detail.contains("commit sequence exhausted"));
            }
            other => assert!(
                matches!(other, CommitError::DurabilityFailure { .. }),
                "unexpected error: {other:?}"
            ),
        }

        assert_eq!(store.current_snapshot().high, CommitSeq(0));
    }

    #[test]
    fn transaction_id_exhaustion_returns_error_without_wrap() {
        let store = make_store(1);
        store.next_txn.store(u64::MAX - 1, Ordering::SeqCst);

        let txn = store.try_begin().expect("last transaction id");
        assert_eq!(txn.id(), TxnId(u64::MAX - 1));
        assert_eq!(store.next_txn.load(Ordering::SeqCst), u64::MAX);

        let err = store
            .try_begin()
            .expect_err("transaction id allocator should be exhausted");
        match err {
            CommitError::DurabilityFailure { detail } => {
                assert!(detail.contains("transaction id exhausted"));
            }
            other => assert!(
                matches!(other, CommitError::DurabilityFailure { .. }),
                "unexpected error: {other:?}"
            ),
        }
        assert_eq!(store.next_txn.load(Ordering::SeqCst), u64::MAX);

        let mut sentinel = store.begin();
        assert_eq!(sentinel.id(), TxnId(u64::MAX));
        sentinel.stage_write(BlockNumber(7), vec![0xA5]);
        let (err, _) = store
            .commit(sentinel)
            .expect_err("sentinel transaction id should not commit");
        match err {
            CommitError::DurabilityFailure { detail } => {
                assert!(detail.contains("invalid transaction id"));
            }
            other => assert!(
                matches!(other, CommitError::DurabilityFailure { .. }),
                "unexpected error: {other:?}"
            ),
        }

        let mut ssi_sentinel = store.begin();
        assert_eq!(ssi_sentinel.id(), TxnId(u64::MAX));
        ssi_sentinel.stage_write(BlockNumber(8), vec![0x5A]);
        let (err, _) = store
            .commit_ssi(ssi_sentinel)
            .expect_err("SSI must reject sentinel transaction id");
        match err {
            CommitError::DurabilityFailure { detail } => {
                assert!(detail.contains("invalid transaction id"));
            }
            other => assert!(
                matches!(other, CommitError::DurabilityFailure { .. }),
                "unexpected error: {other:?}"
            ),
        }
        assert_eq!(store.current_snapshot().high, CommitSeq(0));

        store.next_txn.store(0, Ordering::SeqCst);
        let err = store
            .try_begin()
            .expect_err("zero transaction id state should fail closed");
        match err {
            CommitError::DurabilityFailure { detail } => {
                assert!(detail.contains("transaction id exhausted"));
            }
            other => assert!(
                matches!(other, CommitError::DurabilityFailure { .. }),
                "unexpected error: {other:?}"
            ),
        }
        assert_eq!(store.next_txn.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn sharded_snapshot_ref_count_saturates_at_numeric_limit() {
        let store = make_store(4);
        let snap = Snapshot {
            high: CommitSeq(42),
        };

        {
            let mut active = store.active_snapshots.write();
            active.insert(snap.high, u64::MAX);
        }

        store.register_snapshot(snap);
        assert_eq!(
            store.active_snapshots.read().get(&snap.high).copied(),
            Some(u64::MAX)
        );
        assert_eq!(store.active_snapshot_count(), usize::MAX);

        assert!(store.release_snapshot(snap));
        assert_eq!(
            store.active_snapshots.read().get(&snap.high).copied(),
            Some(u64::MAX - 1)
        );
        assert_eq!(store.watermark(), Some(snap.high));
    }

    #[test]
    fn adaptive_conflict_free_commit_sets_strict_incumbent() {
        let mut store = make_store(4);
        store.adaptive_config = AdaptivePolicyConfig {
            warmup_commits: 0,
            ..AdaptivePolicyConfig::default()
        };
        store.set_conflict_policy(ConflictPolicy::Adaptive);

        let mut txn = store.begin();
        txn.stage_write(BlockNumber(1), vec![0xAA; 8]);
        store.commit(txn).expect("commit");

        let metrics = store.contention_metrics();
        assert_eq!(metrics.last_selected, Some(ConflictPolicy::Strict));
        assert_eq!(store.effective_policy(), ConflictPolicy::Strict);
    }

    #[test]
    fn fixed_policy_skips_contention_metrics_but_force_records() {
        // Default (SafeMerge) fixed policy: the commit succeeds but the global
        // contention_metrics write lock is skipped, so counters stay at default.
        let store = make_store(4);
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(1), vec![0xAA; 8]);
        store.commit(txn).expect("commit");
        assert_eq!(
            store.contention_metrics().total_commits,
            0,
            "fixed policy must not record per-commit contention metrics"
        );

        // The bench/test force hook reproduces the pre-gate per-commit recording.
        let store = make_store(4);
        store.set_force_metrics_record(true);
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(1), vec![0xAA; 8]);
        store.commit(txn).expect("commit");
        assert_eq!(
            store.contention_metrics().total_commits,
            1,
            "force hook must reproduce per-commit recording"
        );
    }

    #[test]
    fn adaptive_hysteresis_blocks_non_convincing_flip_in_sharded_store() {
        let mut store = make_store(4);
        store.adaptive_config = AdaptivePolicyConfig {
            warmup_commits: 0,
            hysteresis_ratio: 1.5,
            ..AdaptivePolicyConfig::default()
        };
        store.set_conflict_policy(ConflictPolicy::Adaptive);
        *store.contention_metrics.write() = ContentionMetrics {
            conflict_rate: 0.0012,
            merge_success_rate: 0.95,
            abort_rate: 0.001,
            total_commits: 100,
            total_conflicts: 1,
            total_merges: 1,
            total_aborts: 0,
            last_selected: Some(ConflictPolicy::Strict),
        };

        assert_eq!(store.effective_policy(), ConflictPolicy::Strict);
    }

    #[test]
    fn adaptive_hysteresis_allows_convincing_flip_in_sharded_store() {
        let mut store = make_store(4);
        store.adaptive_config = AdaptivePolicyConfig {
            warmup_commits: 0,
            hysteresis_ratio: 1.5,
            ..AdaptivePolicyConfig::default()
        };
        store.set_conflict_policy(ConflictPolicy::Adaptive);
        *store.contention_metrics.write() = ContentionMetrics {
            conflict_rate: 0.001,
            merge_success_rate: 0.0,
            abort_rate: 0.001,
            total_commits: 100,
            total_conflicts: 1,
            total_merges: 0,
            total_aborts: 0,
            last_selected: Some(ConflictPolicy::SafeMerge),
        };

        assert_eq!(store.effective_policy(), ConflictPolicy::Strict);
    }

    #[test]
    fn adaptive_hysteresis_disabled_switches_on_any_improvement_in_sharded_store() {
        let mut store = make_store(4);
        store.adaptive_config = AdaptivePolicyConfig {
            warmup_commits: 0,
            hysteresis_ratio: 1.0,
            ..AdaptivePolicyConfig::default()
        };
        store.set_conflict_policy(ConflictPolicy::Adaptive);
        *store.contention_metrics.write() = ContentionMetrics {
            conflict_rate: 0.0012,
            merge_success_rate: 0.95,
            abort_rate: 0.001,
            total_commits: 100,
            total_conflicts: 1,
            total_merges: 1,
            total_aborts: 0,
            last_selected: Some(ConflictPolicy::Strict),
        };

        assert_eq!(store.effective_policy(), ConflictPolicy::SafeMerge);
    }

    #[test]
    fn ssi_detects_write_skew() {
        let store = make_store(4);
        let block_a = BlockNumber(100);
        let block_b = BlockNumber(200);

        // Seed.
        let mut seed = store.begin();
        seed.stage_write(block_a, vec![1]);
        seed.stage_write(block_b, vec![1]);
        store.commit_ssi(seed).expect("seed");

        // T1: reads A, writes B.
        let mut t1 = store.begin();
        let a_ver = store.latest_commit_seq(block_a);
        t1.record_read(block_a, a_ver);
        t1.stage_write(block_b, vec![2]);

        // T2: reads B, writes A.
        let mut t2 = store.begin();
        let b_ver = store.latest_commit_seq(block_b);
        t2.record_read(block_b, b_ver);
        t2.stage_write(block_a, vec![2]);

        store.commit_ssi(t1).expect("T1 succeeds");
        let result = store.commit_ssi(t2);
        assert!(
            matches!(result, Err((CommitError::SsiConflict { .. }, _))),
            "SSI should reject T2"
        );
    }

    #[test]
    fn prune_across_shards() {
        let store = make_store(4);

        // Write to 4 different shards.
        for i in 0_u64..4 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(i), vec![1]);
            store.commit(txn).expect("commit");
        }
        // Write second version to all.
        for i in 0_u64..4 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(i), vec![2]);
            store.commit(txn).expect("commit");
        }

        assert_eq!(store.version_count(), 8);

        store.prune_safe();

        // Should keep only latest version per block.
        assert!(store.version_count() <= 4);
    }

    #[test]
    fn concurrent_writes_different_shards() {
        let store = Arc::new(ShardedMvccStore::new(8));
        let num_threads = 8_usize;
        let barrier = Arc::new(std::sync::Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    // Each thread writes to its own block (different shard).
                    let block = BlockNumber(u64::try_from(i).unwrap());
                    let mut txn = store.begin();
                    let val = u8::try_from(i % 256).unwrap();
                    txn.stage_write(block, vec![val; 64]);
                    store.commit(txn).expect("commit should succeed");
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        let snap = store.current_snapshot();
        for i in 0..num_threads {
            let block = BlockNumber(u64::try_from(i).unwrap());
            let val = u8::try_from(i % 256).unwrap();
            let data = store.read_visible(block, snap).expect("visible");
            assert_eq!(data, vec![val; 64]);
        }
    }

    #[test]
    fn concurrent_writes_same_shard_serialize() {
        let store = Arc::new(ShardedMvccStore::new(1)); // Single shard forces serialization.
        let num_threads = 8_usize;
        let barrier = Arc::new(std::sync::Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    // All write to different blocks but same shard.
                    let block = BlockNumber(u64::try_from(i).unwrap());
                    let mut txn = store.begin();
                    let value = u8::try_from(i).expect("i fits in u8");
                    txn.stage_write(block, vec![value; 8]);
                    store
                        .commit(txn)
                        .expect("should succeed (different blocks)");
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        // All writes should be visible.
        let snap = store.current_snapshot();
        for i in 0..num_threads {
            let block = BlockNumber(u64::try_from(i).unwrap());
            let data = store.read_visible(block, snap).expect("visible");
            let value = u8::try_from(i).expect("i fits in u8");
            assert_eq!(data, vec![value; 8]);
        }
    }

    #[test]
    fn concurrent_disjoint_slot_writes_same_block_all_merge() {
        // bd-bhh0i slices 2b/4: the shared-metadata merge under REAL concurrency.
        // N threads each read-modify-write a DISJOINT fixed-size slot of the SAME
        // block — exactly what `FsMvccBlockDevice::rmw_block` does per sharded
        // create (an inode-table slot / a GDT descriptor): begin, read at the txn
        // snapshot, patch one slot, stage under a range-overlay proof, commit. A
        // barrier makes all N txns begin at the SAME (stale) snapshot, so every
        // commit but the first takes the concurrent MERGE path. All must commit
        // (disjoint ranges never truly conflict) and the final block must carry
        // EVERY thread's slot — a stale-base clobber (the bug the read-at-snapshot
        // RMW prevents) would leave some slot at its base value. Needs no mke2fs,
        // so it validates REMOTELY what the local cutover otherwise exercises.
        fn run_case(proof_of: fn(usize, usize) -> MergeProof) {
            let store = Arc::new(ShardedMvccStore::new(8));
            let block = BlockNumber(4242);
            let block_size = 4096_usize;
            let slot = 32_usize;
            let threads = 16_usize;
            assert!(threads * slot <= block_size);

            let mut seed = store.begin();
            seed.stage_write(block, vec![0_u8; block_size]);
            store.commit(seed).expect("seed base version");

            let barrier = Arc::new(std::sync::Barrier::new(threads));
            let handles: Vec<_> = (0..threads)
                .map(|i| {
                    let store = Arc::clone(&store);
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        let marker = u8::try_from(i + 1).expect("marker fits u8");
                        let off = i * slot;
                        // Begin + read at THIS txn's own snapshot BEFORE the barrier,
                        // so all txns share the pre-writes snapshot and every commit
                        // after the first hits the concurrent merge path.
                        let mut txn = store.begin();
                        let snap = txn.snapshot();
                        let mut data = store
                            .read_visible(block, snap)
                            .expect("base version visible at snapshot");
                        data[off..off + slot].fill(marker);
                        txn.stage_write_with_proof(block, data, proof_of(off, slot));
                        barrier.wait();
                        store
                            .commit(txn)
                            .expect("disjoint-slot write must merge, not FCW-conflict");
                    })
                })
                .collect();
            for h in handles {
                h.join().expect("worker thread panicked");
            }

            let final_block = store
                .read_visible(block, store.current_snapshot())
                .expect("committed version");
            assert_eq!(final_block.len(), block_size);
            for i in 0..threads {
                let marker = u8::try_from(i + 1).expect("marker fits u8");
                let off = i * slot;
                assert!(
                    final_block[off..off + slot].iter().all(|&b| b == marker),
                    "thread {i}'s slot was clobbered by a concurrent merge: {:?}",
                    &final_block[off..off + slot]
                );
            }
            for &b in &final_block[threads * slot..] {
                assert_eq!(b, 0, "bytes outside every written slot must stay at base");
            }
        }

        // Both range-overlay proof families the two slices emit.
        run_case(MergeProof::independent_key_range); // GDT descriptor (slice 4)
        run_case(MergeProof::timestamp_only_inode_range); // inode-table slot (slice 2b)
    }

    #[test]
    fn snapshot_reads_consistent_across_shards() {
        let store = ShardedMvccStore::new(4);

        // Write to 4 different shards in one commit.
        let mut txn = store.begin();
        for i in 0_u64..4 {
            txn.stage_write(BlockNumber(i), vec![1; 8]);
        }
        store.commit(txn).expect("commit");

        let snap = store.current_snapshot();

        // Write v2 to all.
        let mut txn2 = store.begin();
        for i in 0_u64..4 {
            txn2.stage_write(BlockNumber(i), vec![2; 8]);
        }
        store.commit(txn2).expect("commit");

        // Snap should see v1 across all shards.
        for i in 0_u64..4 {
            let data = store.read_visible(BlockNumber(i), snap).expect("visible");
            assert_eq!(data, vec![1; 8], "block {i} should see v1 at old snapshot");
        }
    }

    #[test]
    fn stress_16_threads_10000_ops() {
        let store = Arc::new(ShardedMvccStore::new(8));
        let num_threads = 16_usize;
        let ops_per_thread = 10_000_usize;
        let barrier = Arc::new(std::sync::Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|thread_id| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let mut committed = 0_usize;
                    for j in 0..ops_per_thread {
                        let block_num = u64::try_from(thread_id * ops_per_thread + j).unwrap() % 64;
                        let block = BlockNumber(block_num);
                        let mut txn = store.begin();
                        let value = u8::try_from(j % 256).expect("j % 256 always fits in u8");
                        txn.stage_write(block, vec![value; 8]);
                        match store.commit(txn) {
                            Ok(_) => committed += 1,
                            Err((err, _)) => assert!(
                                matches!(err, CommitError::Conflict { .. }),
                                "unexpected error: {err}"
                            ),
                        }
                    }
                    committed
                })
            })
            .collect();

        let mut total_committed = 0_usize;
        for handle in handles {
            total_committed += handle.join().expect("thread panicked");
        }

        // At least some should have committed.
        assert!(total_committed > 0, "at least some commits should succeed");

        // Version store should be consistent.
        let snap = store.current_snapshot();
        for b in 0_u64..64 {
            // Every block that has a version should be readable.
            if let Some(data) = store.read_visible(BlockNumber(b), snap) {
                assert_eq!(data.len(), 8);
            }
        }
    }

    #[test]
    fn prune_with_external_registry() {
        let store = ShardedMvccStore::new(4);
        let registry = Arc::new(SnapshotRegistry::new());

        // Write 3 versions to block 0.
        for v in 1_u8..=3 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(0), vec![v]);
            store.commit(txn).expect("commit");
        }

        // Register a snapshot at commit 2.
        let snap2 = Snapshot { high: CommitSeq(2) };
        let _handle = SnapshotRegistry::acquire(&registry, snap2);

        // Prune using registry watermark.
        let wm = store.prune_safe_with_registry(&registry);
        assert_eq!(wm, CommitSeq(2));

        // v2 should still be visible.
        let data = store.read_visible(BlockNumber(0), snap2).expect("visible");
        assert_eq!(data, vec![2]);
    }

    #[test]
    fn multi_shard_transaction() {
        let store = ShardedMvccStore::new(4);

        // Write to blocks that span all 4 shards in a single transaction.
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(0), vec![10]); // shard 0
        txn.stage_write(BlockNumber(1), vec![11]); // shard 1
        txn.stage_write(BlockNumber(2), vec![12]); // shard 2
        txn.stage_write(BlockNumber(3), vec![13]); // shard 3
        let seq = store.commit(txn).expect("multi-shard commit");

        let snap = store.current_snapshot();
        assert_eq!(store.read_visible(BlockNumber(0), snap).unwrap(), vec![10]);
        assert_eq!(store.read_visible(BlockNumber(3), snap).unwrap(), vec![13]);
        assert_eq!(seq, CommitSeq(1));
    }

    // ── Property-based tests (proptest) ────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Shard index is always in [0, shard_count).
        #[test]
        fn proptest_shard_index_in_range(
            shard_count in 1_usize..64,
            block_num in any::<u64>(),
        ) {
            let store = make_store(shard_count);
            let effective_shard_count = store.shard_count();
            let idx = store.shard_index(BlockNumber(block_num));
            let expected = usize::try_from(
                block_num % u64::try_from(effective_shard_count).expect("fits"),
            )
            .expect("modulo result fits");
            prop_assert!(
                idx < effective_shard_count,
                "shard_index {} >= effective shard count {}",
                idx,
                effective_shard_count
            );
            prop_assert_eq!(idx, expected);
        }

        /// Committed writes are visible in ShardedMvccStore.
        #[test]
        fn proptest_sharded_committed_writes_visible(
            shard_count in 1_usize..8,
            ops in proptest::collection::vec((0_u16..64, any::<u8>()), 1..16),
        ) {
            let store = make_store(shard_count);
            let mut expected = std::collections::BTreeMap::<u16, u8>::new();
            let mut txn = store.begin();
            for &(block, byte) in &ops {
                txn.stage_write(BlockNumber(u64::from(block)), vec![byte; 8]);
                expected.insert(block, byte);
            }
            store.commit(txn).expect("commit");

            let snap = store.current_snapshot();
            for (&block, &byte) in &expected {
                let data = store
                    .read_visible(BlockNumber(u64::from(block)), snap)
                    .expect("visible");
                prop_assert_eq!(data[0], byte, "block {} data mismatch", block);
            }
        }

        /// FCW conflict detection in ShardedMvccStore.
        #[test]
        fn proptest_sharded_fcw_conflict(
            shard_count in 1_usize..8,
            block_id in 0_u64..64,
            byte_a in any::<u8>(),
            byte_b in any::<u8>(),
        ) {
            let store = make_store(shard_count);
            let block = BlockNumber(block_id);
            let mut t1 = store.begin();
            let mut t2 = store.begin();
            t1.stage_write(block, vec![byte_a; 8]);
            t2.stage_write(block, vec![byte_b; 8]);
            store.commit(t1).expect("t1 first");
            let result = store.commit(t2);
            prop_assert!(result.is_err(), "FCW should reject t2 for block {}", block_id);
        }

        /// Snapshot isolation in ShardedMvccStore.
        #[test]
        fn proptest_sharded_snapshot_isolation(
            shard_count in 1_usize..8,
            block_id in 0_u64..32,
            byte_v1 in any::<u8>(),
            byte_v2 in any::<u8>(),
        ) {
            let store = make_store(shard_count);
            let block = BlockNumber(block_id);

            let mut t1 = store.begin();
            t1.stage_write(block, vec![byte_v1; 8]);
            store.commit(t1).expect("commit v1");

            let snap = store.current_snapshot();

            let mut t2 = store.begin();
            t2.stage_write(block, vec![byte_v2; 8]);
            store.commit(t2).expect("commit v2");

            // snap must still see v1
            let data = store.read_visible(block, snap).expect("visible");
            prop_assert_eq!(data[0], byte_v1);
        }

        /// Snapshot register/release ref-counting in ShardedMvccStore.
        #[test]
        fn proptest_sharded_snapshot_refcount(
            register_count in 1_usize..8,
        ) {
            let store = make_store(4);
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(0), vec![1]);
            store.commit(txn).expect("commit");

            let snap = store.current_snapshot();
            for _ in 0..register_count {
                store.register_snapshot(snap);
            }
            prop_assert_eq!(store.active_snapshot_count(), register_count);
            prop_assert_eq!(store.watermark(), Some(snap.high));

            for _ in 0..register_count {
                prop_assert!(store.release_snapshot(snap));
            }
            prop_assert_eq!(store.active_snapshot_count(), 0);
            prop_assert_eq!(store.watermark(), None);
        }

        /// Unwritten blocks return None in ShardedMvccStore.
        #[test]
        fn proptest_sharded_unwritten_returns_none(
            shard_count in 1_usize..8,
            block_id in 0_u64..1024,
        ) {
            let store = make_store(shard_count);
            let snap = store.current_snapshot();
            prop_assert!(store.read_visible(BlockNumber(block_id), snap).is_none());
        }
    }

    fn assert_policy_wait_does_not_pin_shard<F>(label: &'static str, commit: F)
    where
        F: FnOnce(Arc<ShardedMvccStore>, BlockNumber) + Send + 'static,
    {
        use std::sync::mpsc;
        use std::thread;
        use std::time::{Duration, Instant};

        let store = Arc::new(make_store(4));
        store.set_conflict_policy(ConflictPolicy::Adaptive);
        let block = BlockNumber(0);
        let shard_idx = store.shard_index(block);
        let policy_guard = store.conflict_policy.write();
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();

        let worker_store = Arc::clone(&store);
        let worker = thread::spawn(move || {
            started_tx.send(()).expect("send start");
            commit(worker_store, block);
            finished_tx.send(()).expect("send finish");
        });

        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker started");
        thread::sleep(Duration::from_millis(20));
        let finished_while_policy_held = finished_rx.try_recv().is_ok();

        let deadline = Instant::now() + Duration::from_secs(1);
        let mut shard_available = false;
        while Instant::now() < deadline {
            if let Some(shard_guard) = store.shards[shard_idx].try_write() {
                drop(shard_guard);
                shard_available = true;
                break;
            }
            thread::yield_now();
        }

        drop(policy_guard);
        if !finished_while_policy_held {
            finished_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("worker finished after policy lock released");
        }
        worker.join().expect("worker panicked");

        assert!(
            !finished_while_policy_held,
            "{label}: commit path did not wait on the held conflict_policy lock"
        );
        assert!(
            shard_available,
            "{label}: commit path held a shard write lock while waiting on conflict_policy"
        );
    }

    #[test]
    fn commit_snapshots_policy_before_shard_locks() {
        assert_policy_wait_does_not_pin_shard("commit", |store, block| {
            let mut txn = store.begin();
            txn.stage_write(block, vec![0xA5; 8]);
            store.commit(txn).expect("commit after policy unlock");
        });
    }

    #[test]
    fn commit_ssi_snapshots_policy_before_shard_locks() {
        assert_policy_wait_does_not_pin_shard("commit_ssi", |store, block| {
            let mut txn = store.begin();
            txn.stage_write(block, vec![0x5A; 8]);
            store
                .commit_ssi(txn)
                .expect("SSI commit after policy unlock");
        });
    }

    /// bd-bky2f / bd-c1yn6 — regression guard for the canonical
    /// lock-ordering invariant on `ShardedMvccStore`
    /// (active_snapshots → shards → contention_metrics, with
    /// conflict_policy as a leaf-only lock). Spawns concurrent workers
    /// that exercise the nested-lock and leaf-lock code paths
    /// simultaneously: commit (shards.W → contention_metrics.W),
    /// commit_ssi (shards.W → contention_metrics.W), prune_safe
    /// (active_snapshots.W → shards.W), register/release_snapshot
    /// (active_snapshots.W), and conflict-policy updates/effective
    /// reads (conflict_policy alone, then contention_metrics alone for
    /// Adaptive). A watchdog thread fails the test with a tagged panic
    /// if the workers do not finish within 15s; any future AB-BA
    /// introduced by a refactor surfaces as a clear failure rather than
    /// a silent stall.
    #[test]
    fn lock_ordering_under_concurrent_commit_prune_and_register() {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        use std::thread;
        use std::time::{Duration, Instant};

        const LOCK_ORDERING_WATCHDOG_POLL_INTERVAL: Duration = Duration::from_millis(10);

        let store = Arc::new(make_store(4));

        let done = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(15);

        // Watchdog: prove no worker is stuck after the timeout elapses.
        let watchdog_done = Arc::clone(&done);
        let watchdog = thread::spawn(move || {
            loop {
                if watchdog_done.load(AtomicOrdering::Acquire) {
                    return;
                }
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let remaining = deadline.saturating_duration_since(now);
                thread::sleep(LOCK_ORDERING_WATCHDOG_POLL_INTERVAL.min(remaining));
            }
            assert!(
                watchdog_done.load(AtomicOrdering::Acquire),
                "bd-bky2f: ShardedMvccStore lock-ordering watchdog tripped - \
                 commit/ssi/prune/register/policy workers did not finish within 15s, \
                 indicating a likely AB-BA deadlock",
            );
        });

        // Worker A: commit pipeline (conflict_policy.R alone, then
        // shards.W → contention_metrics.W).
        let store_a = Arc::clone(&store);
        let worker_a = thread::spawn(move || {
            for i in 0..64_u64 {
                let mut txn = store_a.begin();
                txn.stage_write(BlockNumber(i), vec![(i & 0xFF) as u8; 16]);
                let _ = store_a.commit(txn).expect("commit must not block");
            }
        });

        // Worker B: SSI commit pipeline (conflict_policy.R alone, then
        // shards.W → contention_metrics.W).
        let store_b = Arc::clone(&store);
        let worker_b = thread::spawn(move || {
            for i in 0..64_u64 {
                let block = BlockNumber(1024 + i);
                let mut txn = store_b.begin();
                txn.stage_write(block, vec![(i & 0xFF) as u8; 16]);
                let _ = store_b.commit_ssi(txn).expect("SSI commit must not block");
            }
        });

        // Worker C: prune_safe (active_snapshots.W → shards.W per shard).
        let store_c = Arc::clone(&store);
        let worker_c = thread::spawn(move || {
            for _ in 0..32 {
                let _ = store_c.prune_safe();
            }
        });

        // Worker D: register/release_snapshot (active_snapshots.W only).
        let store_d = Arc::clone(&store);
        let worker_d = thread::spawn(move || {
            for _ in 0..64 {
                let snap = store_d.current_snapshot();
                store_d.register_snapshot(snap);
                let _ = store_d.release_snapshot(snap);
            }
        });

        // Worker E: conflict_policy leaf updates and effective-policy reads.
        let store_e = Arc::clone(&store);
        let worker_e = thread::spawn(move || {
            let policies = [
                ConflictPolicy::Adaptive,
                ConflictPolicy::Strict,
                ConflictPolicy::SafeMerge,
            ];
            for i in 0..96 {
                store_e.set_conflict_policy(policies[i % policies.len()]);
                let _ = store_e.effective_policy();
            }
        });

        worker_a.join().expect("worker A panicked");
        worker_b.join().expect("worker B panicked");
        worker_c.join().expect("worker C panicked");
        worker_d.join().expect("worker D panicked");
        worker_e.join().expect("worker E panicked");
        let watchdog_join_started = Instant::now();
        done.store(true, AtomicOrdering::Release);
        watchdog.join().expect("watchdog panicked");
        assert!(
            watchdog_join_started.elapsed() <= LOCK_ORDERING_WATCHDOG_POLL_INTERVAL * 25,
            "watchdog should observe completion promptly after workers finish"
        );
    }
}
