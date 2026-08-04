//! Read-Copy-Update (RCU) primitives for lock-free metadata reads.
//!
//! This module provides RCU-style data structures backed by [`arc_swap::ArcSwap`]
//! for truly lock-free reader access with no atomic increments on the reader path.
//!
//! # Design
//!
//! - **Readers**: Call [`RcuCell::load`] to get a `Guard` — a zero-cost handle
//!   that borrows the current value without any atomic increment. Multiple
//!   concurrent readers never block each other or writers.
//!
//! - **Writers**: Call [`RcuCell::update`] to atomically publish a new value.
//!   Writers coordinate externally (e.g., via `Mutex`) if needed. The old
//!   value is freed through `Arc` reference counting once all readers finish.
//!
//! - **Reclamation (QSBR)**: Old values are reclaimed when the last `Guard`
//!   or `Arc` reference is dropped. The `arc-swap` crate internally uses a
//!   debt-based scheme that tracks quiescent states — once all reader guards
//!   from a given generation are dropped, the old `Arc` can be freed.
//!
//! # `unsafe_code = "forbid"` Compliance
//!
//! All RCU operations are safe Rust. The `arc-swap` crate encapsulates the
//! necessary atomics internally while exposing an entirely safe API.
//!
//! # Logging
//!
//! - **TRACE** `ffs::mvcc::rcu`: `rcu_cell_load` — reader load (guard created)
//! - **DEBUG** `ffs::mvcc::rcu`: `rcu_cell_update` — writer publishes new value
//! - **INFO**  `ffs::mvcc::rcu`: `rcu_map_update` — map entry updated or inserted
//! - **WARN**  `ffs::mvcc::rcu`: `rcu_map_high_churn` — map updates exceeding churn threshold
//! - **ERROR** `ffs::mvcc::rcu`: `rcu_map_inconsistency` — map invariant violation

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, trace, warn};

fn saturating_increment(counter: &AtomicU64) -> u64 {
    loop {
        match counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_add(1))
        }) {
            Ok(previous) => return previous.saturating_add(1),
            Err(_) => std::hint::spin_loop(),
        }
    }
}

// ─── RcuCell ────────────────────────────────────────────────────────────────

/// A single RCU-protected value.
///
/// Provides lock-free reads (no atomic increments on the fast path) and
/// atomic updates via [`ArcSwap`]. Multiple concurrent readers never block
/// each other or writers.
///
/// # Examples
///
/// ```
/// use ffs_mvcc::rcu::RcuCell;
///
/// let cell = RcuCell::new(42_u64);
///
/// // Reader path — no locks, no atomic increments
/// let value = cell.load();
/// assert_eq!(**value, 42);
///
/// // Writer path — atomic swap
/// cell.update(100);
/// assert_eq!(**cell.load(), 100);
/// ```
pub struct RcuCell<T> {
    inner: ArcSwap<T>,
    update_count: AtomicU64,
}

impl<T: fmt::Debug> fmt::Debug for RcuCell<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RcuCell")
            .field("value", &*self.load_arc())
            .field("update_count", &self.update_count())
            .finish()
    }
}

impl<T> RcuCell<T> {
    /// Create a new `RcuCell` with an initial value.
    pub fn new(value: T) -> Self {
        Self {
            inner: ArcSwap::from_pointee(value),
            update_count: AtomicU64::new(0),
        }
    }

    /// Create from an existing `Arc<T>`.
    pub fn from_arc(arc: Arc<T>) -> Self {
        Self {
            inner: ArcSwap::from(arc),
            update_count: AtomicU64::new(0),
        }
    }

    /// Load the current value without any atomic increment.
    ///
    /// Returns a [`arc_swap::Guard`] that borrows the current `Arc<T>`.
    /// The guard must not be held across yield points or long operations
    /// — prefer short-lived reads.
    ///
    /// This is the primary reader API and is completely lock-free.
    #[inline]
    pub fn load(&self) -> arc_swap::Guard<Arc<T>> {
        let guard = self.inner.load();
        trace!(
            target: "ffs::mvcc::rcu",
            update_count = self.update_count.load(Ordering::Relaxed),
            "rcu_cell_load"
        );
        guard
    }

    /// Load the current value as a full `Arc<T>`.
    ///
    /// Unlike [`load`](Self::load), this performs an atomic increment on the
    /// `Arc` reference count. Use when you need to hold the value beyond
    /// the scope of a guard (e.g., across async yield points).
    #[inline]
    pub fn load_arc(&self) -> Arc<T> {
        self.inner.load_full()
    }

    /// Atomically publish a new value.
    ///
    /// All subsequent reads see the new value. Readers that loaded the
    /// old value before this call continue to see it until they release
    /// their guard/arc. The old value is freed when the last reference
    /// drops (QSBR-like reclamation via `Arc` refcount).
    pub fn update(&self, new_value: T) {
        self.inner.store(Arc::new(new_value));
        let count = saturating_increment(&self.update_count);
        debug!(
            target: "ffs::mvcc::rcu",
            update_count = count,
            "rcu_cell_update"
        );
    }

    /// Atomically publish a new value from an existing `Arc<T>`.
    pub fn update_arc(&self, new_arc: Arc<T>) {
        self.inner.store(new_arc);
        let count = saturating_increment(&self.update_count);
        debug!(
            target: "ffs::mvcc::rcu",
            update_count = count,
            "rcu_cell_update"
        );
    }

    /// Swap the current value, returning the old one.
    ///
    /// The caller receives the old `Arc<T>`; if no other readers hold it,
    /// the value is freed when this `Arc` drops.
    pub fn swap(&self, new_value: T) -> Arc<T> {
        let old = self.inner.swap(Arc::new(new_value));
        saturating_increment(&self.update_count);
        old
    }

    /// Number of updates performed since creation.
    #[must_use]
    pub fn update_count(&self) -> u64 {
        self.update_count.load(Ordering::Relaxed)
    }
}

// ─── RcuMap ─────────────────────────────────────────────────────────────────

/// An RCU-protected immutable map for metadata caching.
///
/// The map is stored as `ArcSwap<BTreeMap<K, Arc<V>>>`. Readers get a
/// lock-free snapshot of the entire map. Writers produce a new map version
/// (copy-on-write) and publish it atomically.
///
/// This is designed for metadata caches where:
/// - Reads vastly outnumber writes (stat, readdir, lookup)
/// - The map is small-to-moderate (hundreds to thousands of entries)
/// - Writes are infrequent (inode creation, directory modification)
///
/// For large maps with frequent writes, consider [`ShardedMvccStore`](crate::sharded::ShardedMvccStore).
///
/// # Examples
///
/// ```
/// use ffs_mvcc::rcu::RcuMap;
///
/// let map: RcuMap<u64, String> = RcuMap::new();
///
/// // Writer: insert a new entry (copy-on-write)
/// map.insert(42, "hello".to_string());
///
/// // Reader: lock-free lookup
/// let snapshot = map.load();
/// assert_eq!(snapshot.get(&42).map(|v| v.as_str()), Some("hello"));
/// ```
pub struct RcuMap<K, V> {
    inner: ArcSwap<BTreeMap<K, Arc<V>>>,
    /// Write-side mutex: serializes COW updates to the map.
    /// Readers never acquire this — only writers.
    write_lock: Mutex<()>,
    update_count: AtomicU64,
    /// Churn threshold: log a warning if updates exceed this rate.
    churn_threshold: u64,
}

impl<K: fmt::Debug + Ord, V: fmt::Debug> fmt::Debug for RcuMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let snap = self.inner.load_full();
        f.debug_struct("RcuMap")
            .field("entry_count", &snap.len())
            .field("update_count", &self.update_count.load(Ordering::Relaxed))
            .field("churn_threshold", &self.churn_threshold)
            .finish_non_exhaustive()
    }
}

impl<K: Clone + Ord + Hash + fmt::Debug, V: Clone + fmt::Debug> RcuMap<K, V> {
    /// Create a new empty RCU-protected map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: ArcSwap::from_pointee(BTreeMap::new()),
            write_lock: Mutex::new(()),
            update_count: AtomicU64::new(0),
            churn_threshold: 10_000,
        }
    }

    /// Create with a custom churn warning threshold.
    #[must_use]
    pub fn with_churn_threshold(churn_threshold: u64) -> Self {
        Self {
            churn_threshold,
            ..Self::new()
        }
    }

    /// Load a lock-free snapshot of the map.
    ///
    /// Returns a guard that borrows the current map. No locks, no atomic
    /// increments on the reader fast path.
    #[inline]
    pub fn load(&self) -> arc_swap::Guard<Arc<BTreeMap<K, Arc<V>>>> {
        self.inner.load()
    }

    /// Load the current map as a full `Arc`.
    #[inline]
    pub fn load_arc(&self) -> Arc<BTreeMap<K, Arc<V>>> {
        self.inner.load_full()
    }

    /// Look up a key, returning a cloned `Arc<V>` if present.
    ///
    /// This is a convenience method that loads the map and looks up
    /// the key in a single operation.
    #[must_use]
    pub fn get(&self, key: &K) -> Option<Arc<V>> {
        let snap = self.inner.load();
        snap.get(key).cloned()
    }

    /// Insert or update a key-value pair (copy-on-write).
    ///
    /// Acquires the write-side mutex, clones the current map, inserts the
    /// entry, and publishes the new version atomically. Readers never block.
    pub fn insert(&self, key: K, value: V) {
        let guard = self.write_lock.lock();
        let old = self.inner.load_full();
        let mut new_map = (*old).clone();
        new_map.insert(key, Arc::new(value));
        self.inner.store(Arc::new(new_map));
        drop(guard);

        let count = saturating_increment(&self.update_count);
        info!(
            target: "ffs::mvcc::rcu",
            update_count = count,
            "rcu_map_update"
        );
        if self.churn_threshold != 0 && count % self.churn_threshold == 0 {
            warn!(
                target: "ffs::mvcc::rcu",
                update_count = count,
                churn_threshold = self.churn_threshold,
                "rcu_map_high_churn"
            );
        }
    }

    /// Remove a key (copy-on-write).
    ///
    /// Returns `true` if the key was present and removed.
    pub fn remove(&self, key: &K) -> bool {
        let guard = self.write_lock.lock();
        let old = self.inner.load_full();
        if !old.contains_key(key) {
            return false;
        }
        let mut new_map = (*old).clone();
        new_map.remove(key);
        self.inner.store(Arc::new(new_map));
        drop(guard);

        saturating_increment(&self.update_count);
        true
    }

    /// Number of entries in the current snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.load().len()
    }

    /// Whether the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.load().is_empty()
    }

    /// Total number of updates since creation.
    #[must_use]
    pub fn update_count(&self) -> u64 {
        self.update_count.load(Ordering::Relaxed)
    }

    /// Replace the entire map atomically.
    pub fn replace(&self, new_map: BTreeMap<K, Arc<V>>) {
        let _guard = self.write_lock.lock();
        self.inner.store(Arc::new(new_map));
        saturating_increment(&self.update_count);
    }

    /// Clear all entries (publish an empty map).
    pub fn clear(&self) {
        let _guard = self.write_lock.lock();
        self.inner.store(Arc::new(BTreeMap::new()));
        saturating_increment(&self.update_count);
    }
}

impl<K: Clone + Ord + Hash + fmt::Debug, V: Clone + fmt::Debug> Default for RcuMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

// ─── AtomicWatermark ────────────────────────────────────────────────────────

/// Lock-free watermark for snapshot GC.
///
/// Stores a `CommitSeq` (u64) that can be read atomically without any lock.
/// Writers update it when the set of active snapshots changes.
///
/// The sentinel value `u64::MAX` represents "no active snapshots" (empty).
#[derive(Debug)]
pub struct AtomicWatermark {
    value: AtomicU64,
}

const WATERMARK_EMPTY: u64 = u64::MAX;

impl AtomicWatermark {
    /// Create with no active snapshots.
    #[must_use]
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(WATERMARK_EMPTY),
        }
    }

    /// Create with an initial watermark value.
    #[must_use]
    pub fn with_value(commit_seq: u64) -> Self {
        Self {
            value: AtomicU64::new(commit_seq),
        }
    }

    /// Load the current watermark.
    ///
    /// Returns `None` if no active snapshots exist.
    /// Completely lock-free — just an atomic load.
    #[inline]
    #[must_use]
    pub fn load(&self) -> Option<u64> {
        let v = self.value.load(Ordering::Acquire);
        if v == WATERMARK_EMPTY { None } else { Some(v) }
    }

    /// Store a new watermark value.
    #[inline]
    pub fn store(&self, commit_seq: u64) {
        self.value.store(commit_seq, Ordering::Release);
    }

    /// Clear the watermark (no active snapshots).
    #[inline]
    pub fn clear(&self) {
        self.value.store(WATERMARK_EMPTY, Ordering::Release);
    }

    /// Load the raw u64 (including sentinel).
    #[inline]
    #[must_use]
    pub fn load_raw(&self) -> u64 {
        self.value.load(Ordering::Acquire)
    }
}

impl Default for AtomicWatermark {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Metadata Read-Path Proof Surface ──────────────────────────────────────

/// Invariants that must hold before an RCU/QSBR metadata read path can move
/// beyond design-only status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RcuQsbrInvariant {
    ReaderSnapshotVisibility,
    ReclamationEpochAdvancement,
    WriterPublicationOrdering,
    CancellationReleasesReader,
    RollbackRestoresPriorPublication,
    EpochSaturationFallsBack,
    MemoryBudgetPressureFallsBack,
}

/// Complete invariant set for the metadata read-path prototype.
pub const RCU_QSBR_METADATA_INVARIANTS: [RcuQsbrInvariant; 7] = [
    RcuQsbrInvariant::ReaderSnapshotVisibility,
    RcuQsbrInvariant::ReclamationEpochAdvancement,
    RcuQsbrInvariant::WriterPublicationOrdering,
    RcuQsbrInvariant::CancellationReleasesReader,
    RcuQsbrInvariant::RollbackRestoresPriorPublication,
    RcuQsbrInvariant::EpochSaturationFallsBack,
    RcuQsbrInvariant::MemoryBudgetPressureFallsBack,
];

impl RcuQsbrInvariant {
    /// Stable identifier for structured proof artifacts.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::ReaderSnapshotVisibility => "reader_snapshot_visibility",
            Self::ReclamationEpochAdvancement => "reclamation_epoch_advancement",
            Self::WriterPublicationOrdering => "writer_publication_ordering",
            Self::CancellationReleasesReader => "cancellation_releases_reader",
            Self::RollbackRestoresPriorPublication => "rollback_restores_prior_publication",
            Self::EpochSaturationFallsBack => "epoch_saturation_falls_back",
            Self::MemoryBudgetPressureFallsBack => "memory_budget_pressure_falls_back",
        }
    }
}

/// Reader lifecycle state used by the QSBR proof model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RcuReaderState {
    Active { snapshot_epoch: u64 },
    Cancelled { snapshot_epoch: u64 },
    Quiescent { snapshot_epoch: u64 },
}

impl RcuReaderState {
    #[must_use]
    pub const fn snapshot_epoch(self) -> u64 {
        match self {
            Self::Active { snapshot_epoch }
            | Self::Cancelled { snapshot_epoch }
            | Self::Quiescent { snapshot_epoch } => snapshot_epoch,
        }
    }

    /// A cancelled reader is a quiescent state: it can no longer dereference
    /// the snapshot it previously observed.
    #[must_use]
    pub const fn permits_reclamation_at(self, reclaim_epoch: u64) -> bool {
        match self {
            Self::Active { .. } => false,
            Self::Cancelled { snapshot_epoch } | Self::Quiescent { snapshot_epoch } => {
                snapshot_epoch <= reclaim_epoch
            }
        }
    }
}

/// Advance the publication epoch, refusing wraparound instead of reusing an id.
#[must_use]
pub const fn next_publication_epoch(current_epoch: u64) -> Option<u64> {
    current_epoch.checked_add(1)
}

/// Evidence gates that control whether the prototype can be selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RcuQsbrProofGate {
    ExecutableModelTests,
    RollbackPath,
    UnsafeCodeForbidden,
    AsupersyncOnly,
}

impl RcuQsbrProofGate {
    const fn bit(self) -> u8 {
        match self {
            Self::ExecutableModelTests => 1 << 0,
            Self::RollbackPath => 1 << 1,
            Self::UnsafeCodeForbidden => 1 << 2,
            Self::AsupersyncOnly => 1 << 3,
        }
    }
}

/// Compact gate mask for RCU/QSBR proof evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RcuQsbrProofEvidence {
    bits: u8,
}

impl RcuQsbrProofEvidence {
    /// Executable model and safety gates are present, but rollback evidence is
    /// intentionally missing, so the path remains design-only.
    #[must_use]
    pub const fn design_only() -> Self {
        Self {
            bits: RcuQsbrProofGate::ExecutableModelTests.bit()
                | RcuQsbrProofGate::UnsafeCodeForbidden.bit()
                | RcuQsbrProofGate::AsupersyncOnly.bit(),
        }
    }

    /// Every gate required for promotion is present.
    #[must_use]
    pub const fn complete() -> Self {
        Self {
            bits: RcuQsbrProofGate::ExecutableModelTests.bit()
                | RcuQsbrProofGate::RollbackPath.bit()
                | RcuQsbrProofGate::UnsafeCodeForbidden.bit()
                | RcuQsbrProofGate::AsupersyncOnly.bit(),
        }
    }

    /// Return true if this evidence contains `gate`.
    #[must_use]
    pub const fn contains(self, gate: RcuQsbrProofGate) -> bool {
        self.bits & gate.bit() != 0
    }

    /// Return a copy with `gate` removed.
    #[must_use]
    pub const fn without(self, gate: RcuQsbrProofGate) -> Self {
        Self {
            bits: self.bits & !gate.bit(),
        }
    }

    #[must_use]
    pub const fn safety_gates_pass(self) -> bool {
        self.contains(RcuQsbrProofGate::UnsafeCodeForbidden)
            && self.contains(RcuQsbrProofGate::AsupersyncOnly)
    }

    #[must_use]
    pub const fn promotion_gates_pass(self) -> bool {
        self.safety_gates_pass()
            && self.contains(RcuQsbrProofGate::ExecutableModelTests)
            && self.contains(RcuQsbrProofGate::RollbackPath)
    }
}

/// Measured input for comparing the existing lock path against the epoch path.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RcuReadPathMeasurements {
    pub read_ops: u64,
    pub contention_events: u64,
    pub tail_latency_micros: u64,
    pub memory_overhead_bytes: u64,
    pub stalled_reader_count: u64,
    pub complexity_risk: f64,
}

impl RcuReadPathMeasurements {
    #[must_use]
    pub fn contention_rate(self) -> f64 {
        if self.read_ops == 0 {
            0.0
        } else {
            self.contention_events as f64 / self.read_ops as f64
        }
    }
}

/// Weights for the expected-loss comparison.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RcuExpectedLossWeights {
    pub contention_weight: f64,
    pub tail_latency_weight: f64,
    pub memory_mib_weight: f64,
    pub stalled_reader_weight: f64,
    pub complexity_weight: f64,
}

impl Default for RcuExpectedLossWeights {
    fn default() -> Self {
        Self {
            contention_weight: 100.0,
            tail_latency_weight: 0.01,
            memory_mib_weight: 0.25,
            stalled_reader_weight: 50.0,
            complexity_weight: 25.0,
        }
    }
}

impl RcuExpectedLossWeights {
    #[must_use]
    pub fn expected_loss(self, measurements: RcuReadPathMeasurements) -> f64 {
        let memory_mib = measurements.memory_overhead_bytes as f64 / 1_048_576.0;
        let loss = self
            .tail_latency_weight
            .mul_add(measurements.tail_latency_micros as f64, 0.0);
        let loss = self
            .contention_weight
            .mul_add(measurements.contention_rate(), loss);
        let loss = self.memory_mib_weight.mul_add(memory_mib, loss);
        let loss = self
            .stalled_reader_weight
            .mul_add(measurements.stalled_reader_count as f64, loss);
        self.complexity_weight
            .mul_add(measurements.complexity_risk.clamp(0.0, 1.0), loss)
    }
}

/// Selected mode after evaluating proof evidence and expected loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RcuReadPathRecommendation {
    KeepExistingLocks,
    DesignOnlyPrototype,
    CandidateEpochPath,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RcuReadPathDecision {
    pub recommendation: RcuReadPathRecommendation,
    pub lock_path_loss: f64,
    pub epoch_path_loss: f64,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RcuReadPathDecisionInput {
    pub lock_path: RcuReadPathMeasurements,
    pub epoch_path: RcuReadPathMeasurements,
    pub weights: RcuExpectedLossWeights,
    pub memory_budget_bytes: u64,
    pub proof_evidence: RcuQsbrProofEvidence,
}

impl RcuReadPathDecisionInput {
    /// Evaluate the prototype without enabling it. The epoch path needs a 10%
    /// expected-loss margin plus proof evidence before it can become a candidate.
    #[must_use]
    pub fn evaluate(self) -> RcuReadPathDecision {
        const EPOCH_MARGIN: f64 = 0.90;

        let lock_path_loss = self.weights.expected_loss(self.lock_path);
        let epoch_path_loss = self.weights.expected_loss(self.epoch_path);
        let decision = |recommendation, reason| RcuReadPathDecision {
            recommendation,
            lock_path_loss,
            epoch_path_loss,
            reason,
        };

        if !self.proof_evidence.safety_gates_pass() {
            return decision(
                RcuReadPathRecommendation::KeepExistingLocks,
                "safety_gate_failed",
            );
        }
        if !self.proof_evidence.promotion_gates_pass() {
            return decision(
                RcuReadPathRecommendation::DesignOnlyPrototype,
                "missing_executable_evidence_or_rollback",
            );
        }
        if self.epoch_path.stalled_reader_count != 0 {
            return decision(
                RcuReadPathRecommendation::KeepExistingLocks,
                "stalled_reader_blocks_reclamation",
            );
        }
        if self.epoch_path.memory_overhead_bytes > self.memory_budget_bytes {
            return decision(
                RcuReadPathRecommendation::KeepExistingLocks,
                "memory_budget_exceeded",
            );
        }
        if epoch_path_loss < lock_path_loss * EPOCH_MARGIN {
            decision(
                RcuReadPathRecommendation::CandidateEpochPath,
                "epoch_path_lower_expected_loss",
            )
        } else {
            decision(
                RcuReadPathRecommendation::KeepExistingLocks,
                "expected_loss_margin_not_met",
            )
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    #[test]
    fn rcu_cell_basic_read_write() {
        let cell = RcuCell::new(42_u64);
        assert_eq!(**cell.load(), 42);

        cell.update(100);
        assert_eq!(**cell.load(), 100);
        assert_eq!(cell.update_count(), 1);
    }

    #[test]
    fn rcu_cell_arc_roundtrip() {
        let cell = RcuCell::from_arc(Arc::new("hello".to_string()));
        assert_eq!(&***cell.load(), "hello");

        cell.update("world".to_string());
        assert_eq!(&***cell.load(), "world");
    }

    #[test]
    fn rcu_cell_swap_returns_old() {
        let cell = RcuCell::new(1_u32);
        let old = cell.swap(2);
        assert_eq!(*old, 1);
        assert_eq!(**cell.load(), 2);
    }

    #[test]
    fn rcu_cell_concurrent_readers_no_block() {
        let cell = Arc::new(RcuCell::new(0_u64));
        let barrier = Arc::new(Barrier::new(8));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let cell = Arc::clone(&cell);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    let mut sum = 0_u64;
                    for _ in 0..10_000 {
                        sum = sum.wrapping_add(**cell.load());
                    }
                    sum
                })
            })
            .collect();

        for h in handles {
            let _ = h.join().unwrap();
        }
    }

    #[test]
    fn rcu_cell_readers_see_consistent_value() {
        let cell = Arc::new(RcuCell::new(0_u64));

        // Writer thread
        let writer_cell = Arc::clone(&cell);
        let writer = thread::spawn(move || {
            for i in 1..=1000 {
                writer_cell.update(i);
            }
        });

        // Reader threads
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let cell = Arc::clone(&cell);
                thread::spawn(move || {
                    let mut prev = 0_u64;
                    for _ in 0..10_000 {
                        let val = **cell.load();
                        // Values must be monotonically non-decreasing
                        // (single writer, sequential updates).
                        assert!(val >= prev, "non-monotonic: {val} < {prev}");
                        prev = val;
                    }
                })
            })
            .collect();

        writer.join().unwrap();
        for r in readers {
            r.join().unwrap();
        }
    }

    #[test]
    fn rcu_map_basic_operations() {
        let map: RcuMap<u64, String> = RcuMap::new();
        assert!(map.is_empty());

        map.insert(1, "one".to_string());
        assert_eq!(map.len(), 1);
        assert_eq!(
            map.get(&1).map(|v| v.as_str().to_owned()),
            Some("one".to_owned())
        );

        map.insert(2, "two".to_string());
        assert_eq!(map.len(), 2);

        assert!(map.remove(&1));
        assert_eq!(map.len(), 1);
        assert!(map.get(&1).is_none());

        assert!(!map.remove(&99));
    }

    #[test]
    fn rcu_map_concurrent_read_write() {
        let map = Arc::new(RcuMap::<u64, u64>::new());
        let barrier = Arc::new(Barrier::new(5));

        // Writer
        let writer_map = Arc::clone(&map);
        let writer_barrier = Arc::clone(&barrier);
        let writer = thread::spawn(move || {
            writer_barrier.wait();
            for i in 0..500 {
                writer_map.insert(i, i * 10);
            }
        });

        // Readers
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let map = Arc::clone(&map);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    let mut reads = 0_u64;
                    for _ in 0..5_000 {
                        let snap = map.load();
                        // Snapshot must be internally consistent
                        for (k, v) in snap.iter() {
                            assert_eq!(**v, *k * 10, "inconsistent: k={k}, v={v}");
                        }
                        reads += 1;
                    }
                    reads
                })
            })
            .collect();

        writer.join().unwrap();
        for r in readers {
            let reads = r.join().unwrap();
            assert!(reads > 0);
        }
    }

    #[test]
    fn rcu_map_snapshot_isolation() {
        let map: RcuMap<u64, String> = RcuMap::new();
        map.insert(1, "original".to_string());

        // Take a snapshot
        let snapshot = map.load_arc();
        assert_eq!(snapshot.get(&1).unwrap().as_str(), "original");

        // Update the map
        map.insert(1, "updated".to_string());

        // Old snapshot still sees original value
        assert_eq!(snapshot.get(&1).unwrap().as_str(), "original");

        // New load sees updated value
        assert_eq!(map.get(&1).unwrap().as_str(), "updated");
    }

    #[test]
    fn rcu_map_replace_and_clear() {
        let map: RcuMap<u64, u64> = RcuMap::new();
        map.insert(1, 10);
        map.insert(2, 20);

        let mut new = BTreeMap::new();
        new.insert(3, Arc::new(30));
        map.replace(new);

        assert_eq!(map.len(), 1);
        assert!(map.get(&1).is_none());
        assert_eq!(*map.get(&3).unwrap(), 30);

        map.clear();
        assert!(map.is_empty());
    }

    #[test]
    fn atomic_watermark_basic() {
        let wm = AtomicWatermark::new();
        assert_eq!(wm.load(), None);

        wm.store(42);
        assert_eq!(wm.load(), Some(42));

        wm.clear();
        assert_eq!(wm.load(), None);
    }

    #[test]
    fn atomic_watermark_concurrent_reads() {
        let wm = Arc::new(AtomicWatermark::with_value(100));
        let barrier = Arc::new(Barrier::new(8));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let wm = Arc::clone(&wm);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    let mut reads = 0_u64;
                    for _ in 0..100_000 {
                        if wm.load().is_some() {
                            reads += 1;
                        }
                    }
                    reads
                })
            })
            .collect();

        for h in handles {
            let reads = h.join().unwrap();
            assert_eq!(reads, 100_000);
        }
    }

    #[test]
    fn rcu_cell_update_arc_publishes_value() {
        let cell = RcuCell::new(10_u64);
        cell.update_arc(Arc::new(42));
        assert_eq!(**cell.load(), 42);
        assert_eq!(cell.update_count(), 1);
    }

    #[test]
    fn rcu_cell_update_count_saturates_at_numeric_limit() {
        let cell = RcuCell::new(0_u64);
        cell.update_count.store(u64::MAX - 1, Ordering::Relaxed);

        cell.update(1);
        assert_eq!(cell.update_count(), u64::MAX);

        cell.update_arc(Arc::new(2));
        assert_eq!(cell.update_count(), u64::MAX);

        let old = cell.swap(3);
        assert_eq!(*old, 2);
        assert_eq!(**cell.load(), 3);
        assert_eq!(cell.update_count(), u64::MAX);
    }

    #[test]
    fn rcu_cell_load_arc_returns_independent_arc() {
        let cell = RcuCell::new(99_u32);
        let arc1 = cell.load_arc();
        let arc2 = cell.load_arc();
        assert_eq!(*arc1, 99);
        assert_eq!(*arc2, 99);
        // update doesn't affect already-loaded arcs
        cell.update(200);
        assert_eq!(*arc1, 99);
        assert_eq!(**cell.load(), 200);
    }

    #[test]
    fn rcu_map_with_churn_threshold_sets_threshold() {
        let map: RcuMap<u64, u64> = RcuMap::with_churn_threshold(5);
        // Insert 5 entries — should hit the churn threshold
        for i in 0..5 {
            map.insert(i, i * 10);
        }
        assert_eq!(map.update_count(), 5);
        assert_eq!(map.len(), 5);
    }

    #[test]
    fn rcu_map_zero_churn_threshold_does_not_panic() {
        let map: RcuMap<u64, u64> = RcuMap::with_churn_threshold(0);
        map.insert(1, 10);
        assert_eq!(map.update_count(), 1);
        assert_eq!(map.get(&1).as_deref().copied(), Some(10));
    }

    #[test]
    fn rcu_map_update_count_saturates_at_numeric_limit() {
        let map: RcuMap<u64, u64> = RcuMap::new();
        map.update_count.store(u64::MAX - 1, Ordering::Relaxed);

        map.insert(1, 10);
        assert_eq!(map.update_count(), u64::MAX);

        map.insert(2, 20);
        assert_eq!(map.update_count(), u64::MAX);

        assert!(map.remove(&1));
        assert_eq!(map.update_count(), u64::MAX);

        let mut replacement = BTreeMap::new();
        replacement.insert(3, Arc::new(30));
        map.replace(replacement);
        assert_eq!(map.update_count(), u64::MAX);

        map.clear();
        assert_eq!(map.update_count(), u64::MAX);
    }

    #[test]
    fn rcu_map_default_is_empty() {
        let map: RcuMap<u64, u64> = RcuMap::default();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        assert_eq!(map.update_count(), 0);
    }

    #[test]
    fn atomic_watermark_with_value_constructor() {
        let wm = AtomicWatermark::with_value(42);
        assert_eq!(wm.load(), Some(42));
        assert_eq!(wm.load_raw(), 42);
    }

    #[test]
    fn atomic_watermark_max_sentinel_reads_as_none() {
        let wm = AtomicWatermark::new();
        assert_eq!(wm.load(), None);
        assert_eq!(wm.load_raw(), u64::MAX);
    }

    #[test]
    fn rcu_qsbr_metadata_proof_surface_declares_required_invariants() {
        let ids = RCU_QSBR_METADATA_INVARIANTS
            .iter()
            .map(|invariant| invariant.id())
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(ids.len(), RCU_QSBR_METADATA_INVARIANTS.len());
        assert!(ids.contains("reader_snapshot_visibility"));
        assert!(ids.contains("reclamation_epoch_advancement"));
        assert!(ids.contains("writer_publication_ordering"));
        assert!(ids.contains("cancellation_releases_reader"));
        assert!(ids.contains("rollback_restores_prior_publication"));
        assert!(ids.contains("epoch_saturation_falls_back"));
        assert!(ids.contains("memory_budget_pressure_falls_back"));
    }

    #[test]
    fn rcu_qsbr_reader_lifecycle_models_cancellation_as_quiescence() {
        let active = RcuReaderState::Active { snapshot_epoch: 7 };
        let cancelled = RcuReaderState::Cancelled { snapshot_epoch: 7 };
        let quiescent = RcuReaderState::Quiescent { snapshot_epoch: 7 };

        assert_eq!(active.snapshot_epoch(), 7);
        assert!(!active.permits_reclamation_at(7));
        assert!(cancelled.permits_reclamation_at(7));
        assert!(quiescent.permits_reclamation_at(8));
        assert!(!cancelled.permits_reclamation_at(6));
    }

    #[test]
    fn rcu_qsbr_publication_epoch_refuses_wraparound() {
        assert_eq!(next_publication_epoch(41), Some(42));
        assert_eq!(next_publication_epoch(u64::MAX), None);
    }

    #[test]
    fn rcu_cell_writer_publication_and_rollback_keep_reader_snapshot() {
        let cell = RcuCell::new("v1".to_string());
        let reader_snapshot = cell.load_arc();

        let prior_publication = cell.swap("v2".to_string());
        assert_eq!(&**reader_snapshot, "v1");
        assert_eq!(&**cell.load(), "v2");

        cell.update_arc(prior_publication);
        assert_eq!(&**reader_snapshot, "v1");
        assert_eq!(&**cell.load(), "v1");
    }

    fn read_path_measurements(
        read_ops: u64,
        contention_events: u64,
        tail_latency_micros: u64,
        memory_overhead_bytes: u64,
        stalled_reader_count: u64,
        complexity_risk: f64,
    ) -> RcuReadPathMeasurements {
        RcuReadPathMeasurements {
            read_ops,
            contention_events,
            tail_latency_micros,
            memory_overhead_bytes,
            stalled_reader_count,
            complexity_risk,
        }
    }

    #[test]
    fn rcu_qsbr_expected_loss_rule_keeps_epoch_path_design_only_without_rollback() {
        let decision = RcuReadPathDecisionInput {
            lock_path: read_path_measurements(10_000, 1_200, 2_000, 0, 0, 0.05),
            epoch_path: read_path_measurements(10_000, 5, 250, 512 * 1024, 0, 0.20),
            weights: RcuExpectedLossWeights::default(),
            memory_budget_bytes: 2 * 1024 * 1024,
            proof_evidence: RcuQsbrProofEvidence::design_only(),
        }
        .evaluate();

        assert_eq!(
            decision.recommendation,
            RcuReadPathRecommendation::DesignOnlyPrototype
        );
        assert_eq!(decision.reason, "missing_executable_evidence_or_rollback");
        assert!(decision.epoch_path_loss < decision.lock_path_loss);
    }

    #[test]
    fn rcu_qsbr_expected_loss_rule_rejects_stalled_readers_and_memory_pressure() {
        let common = RcuReadPathDecisionInput {
            lock_path: read_path_measurements(10_000, 2_000, 2_500, 0, 0, 0.05),
            epoch_path: read_path_measurements(10_000, 10, 200, 512 * 1024, 1, 0.10),
            weights: RcuExpectedLossWeights::default(),
            memory_budget_bytes: 2 * 1024 * 1024,
            proof_evidence: RcuQsbrProofEvidence::complete(),
        };

        let stalled = common.evaluate();
        assert_eq!(
            stalled.recommendation,
            RcuReadPathRecommendation::KeepExistingLocks
        );
        assert_eq!(stalled.reason, "stalled_reader_blocks_reclamation");

        let over_budget = RcuReadPathDecisionInput {
            epoch_path: read_path_measurements(10_000, 10, 200, 4 * 1024 * 1024, 0, 0.10),
            ..common
        }
        .evaluate();
        assert_eq!(
            over_budget.recommendation,
            RcuReadPathRecommendation::KeepExistingLocks
        );
        assert_eq!(over_budget.reason, "memory_budget_exceeded");
    }

    #[test]
    fn rcu_qsbr_expected_loss_rule_selects_epoch_only_with_margin_and_safety() {
        let candidate = RcuReadPathDecisionInput {
            lock_path: read_path_measurements(10_000, 2_000, 2_500, 0, 0, 0.05),
            epoch_path: read_path_measurements(10_000, 10, 200, 512 * 1024, 0, 0.10),
            weights: RcuExpectedLossWeights::default(),
            memory_budget_bytes: 2 * 1024 * 1024,
            proof_evidence: RcuQsbrProofEvidence::complete(),
        }
        .evaluate();
        assert_eq!(
            candidate.recommendation,
            RcuReadPathRecommendation::CandidateEpochPath
        );
        assert_eq!(candidate.reason, "epoch_path_lower_expected_loss");

        let safety_failure = RcuReadPathDecisionInput {
            proof_evidence: RcuQsbrProofEvidence::complete()
                .without(RcuQsbrProofGate::AsupersyncOnly),
            ..RcuReadPathDecisionInput {
                lock_path: read_path_measurements(10_000, 2_000, 2_500, 0, 0, 0.05),
                epoch_path: read_path_measurements(10_000, 10, 200, 512 * 1024, 0, 0.10),
                weights: RcuExpectedLossWeights::default(),
                memory_budget_bytes: 2 * 1024 * 1024,
                proof_evidence: RcuQsbrProofEvidence::complete(),
            }
        }
        .evaluate();
        assert_eq!(
            safety_failure.recommendation,
            RcuReadPathRecommendation::KeepExistingLocks
        );
        assert_eq!(safety_failure.reason, "safety_gate_failed");
    }

    #[test]
    fn rcu_cell_debug_format() {
        const RCU_CELL_DEBUG_GOLDEN: &str = "RcuCell { value: 42, update_count: 0 }";

        let cell = RcuCell::new(42_u64);
        let debug_str = format!("{cell:?}");
        assert_eq!(debug_str, RCU_CELL_DEBUG_GOLDEN);
    }

    #[test]
    fn rcu_map_debug_format() {
        const RCU_MAP_DEBUG_GOLDEN: &str =
            "RcuMap { entry_count: 1, update_count: 1, churn_threshold: 10000, .. }";

        let map: RcuMap<u64, u64> = RcuMap::new();
        map.insert(1, 10);
        let debug_str = format!("{map:?}");
        assert_eq!(debug_str, RCU_MAP_DEBUG_GOLDEN);
    }

    // ── Property-based tests (proptest) ────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// RcuCell: update then load always returns the latest value.
        #[test]
        fn proptest_rcu_cell_update_load_consistency(
            values in proptest::collection::vec(any::<u64>(), 1..16),
        ) {
            let cell = RcuCell::new(0_u64);
            for &v in &values {
                cell.update(v);
                prop_assert_eq!(**cell.load(), v);
            }
            prop_assert_eq!(cell.update_count(), values.len() as u64);
        }

        /// RcuCell: swap returns the previous value.
        #[test]
        fn proptest_rcu_cell_swap_returns_previous(
            initial in any::<u32>(),
            new_val in any::<u32>(),
        ) {
            let cell = RcuCell::new(initial);
            let old = cell.swap(new_val);
            prop_assert_eq!(*old, initial);
            prop_assert_eq!(**cell.load(), new_val);
        }

        /// RcuCell: from_arc roundtrip preserves value.
        #[test]
        fn proptest_rcu_cell_from_arc_roundtrip(value in any::<u64>()) {
            let cell = RcuCell::from_arc(Arc::new(value));
            prop_assert_eq!(**cell.load(), value);
            let arc = cell.load_arc();
            prop_assert_eq!(*arc, value);
        }

        /// RcuMap: insert/get roundtrip for arbitrary keys and values.
        #[test]
        fn proptest_rcu_map_insert_get_roundtrip(
            entries in proptest::collection::vec((1_u64..256, any::<u64>()), 1..16),
        ) {
            let map: RcuMap<u64, u64> = RcuMap::new();
            let mut expected = std::collections::BTreeMap::new();
            for &(k, v) in &entries {
                map.insert(k, v);
                expected.insert(k, v);
            }
            for (&k, &v) in &expected {
                let got = map.get(&k).expect("key must exist");
                prop_assert_eq!(*got, v, "mismatch for key {}", k);
            }
            prop_assert_eq!(map.len(), expected.len());
        }

        /// RcuMap: remove returns true for existing keys, false for missing.
        #[test]
        fn proptest_rcu_map_remove_semantics(
            key in 1_u64..100,
            value in any::<u64>(),
        ) {
            let map: RcuMap<u64, u64> = RcuMap::new();
            prop_assert!(!map.remove(&key));  // not yet inserted
            map.insert(key, value);
            prop_assert!(map.remove(&key));   // now present
            prop_assert!(map.get(&key).is_none());
        }

        /// RcuMap: snapshot isolation — old load_arc sees original state.
        #[test]
        fn proptest_rcu_map_snapshot_isolation(
            initial in any::<u64>(),
            updated in any::<u64>(),
        ) {
            let map: RcuMap<u64, u64> = RcuMap::new();
            map.insert(1, initial);
            let snapshot = map.load_arc();
            map.insert(1, updated);
            // Old snapshot sees original
            prop_assert_eq!(**snapshot.get(&1).unwrap(), initial);
            // New read sees updated
            prop_assert_eq!(*map.get(&1).unwrap(), updated);
        }

        /// AtomicWatermark: store/load roundtrip.
        #[test]
        fn proptest_atomic_watermark_store_load(value in any::<u64>()) {
            // Exclude u64::MAX since it's the sentinel for "empty"
            if value != u64::MAX {
                let wm = AtomicWatermark::new();
                wm.store(value);
                prop_assert_eq!(wm.load(), Some(value));
                prop_assert_eq!(wm.load_raw(), value);
            }
        }

        /// AtomicWatermark: clear sets load to None.
        #[test]
        fn proptest_atomic_watermark_clear(value in 0_u64..u64::MAX) {
            let wm = AtomicWatermark::with_value(value);
            prop_assert_eq!(wm.load(), Some(value));
            wm.clear();
            prop_assert_eq!(wm.load(), None);
        }
    }
}
