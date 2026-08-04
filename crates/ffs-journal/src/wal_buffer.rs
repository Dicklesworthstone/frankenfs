#![forbid(unsafe_code)]
//! Per-core WAL buffers for lock-free concurrent MVCC writes.
//!
//! Design (Silo/Aether style):
//! - Each thread gets its own WAL buffer via thread-local storage.
//! - Appending to the local buffer requires **no locks** — the hot path is contention-free.
//! - A global epoch counter (atomic) tags each entry for ordering across cores.
//! - When a buffer fills, or at explicit flush points, entries are drained and
//!   returned to the caller for durable persistence.
//!
//! This module provides the in-memory buffering layer only. The caller (typically
//! `ffs-mvcc`) is responsible for actually writing flushed entries to disk and
//! issuing `fsync`.

use ffs_error::FfsError;
use ffs_types::{BlockNumber, CommitSeq, TxnId};
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

// ---------------------------------------------------------------------------
// Epoch counter
// ---------------------------------------------------------------------------

/// Global monotonic epoch counter shared across all cores/threads.
///
/// Each WAL entry is stamped with the epoch at append time. Epochs provide a
/// total order across per-core buffers: entries within the same epoch are
/// commutative (order doesn't matter), while entries in different epochs must
/// be applied in epoch order.
pub struct EpochCounter {
    value: AtomicU64,
}

impl std::fmt::Debug for EpochCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochCounter")
            .field("value", &self.value.load(Ordering::Relaxed))
            .finish()
    }
}

impl EpochCounter {
    /// Create a new epoch counter starting at the given value.
    #[must_use]
    pub fn new(start: u64) -> Self {
        Self {
            value: AtomicU64::new(start),
        }
    }

    /// Read the current epoch without advancing it.
    #[must_use]
    pub fn current(&self) -> u64 {
        self.value.load(Ordering::Acquire)
    }

    /// Advance to the next epoch, returning the new epoch value.
    ///
    /// This is the only contention point in the per-core WAL design: a single
    /// atomic compare-and-update. Under typical workloads epoch advancement is
    /// infrequent (once per group commit), so contention is negligible.
    #[allow(deprecated)]
    pub fn advance(&self) -> u64 {
        match self
            .value
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            }) {
            Ok(prev) => prev + 1,
            Err(prev) => prev,
        }
    }
}

impl Default for EpochCounter {
    fn default() -> Self {
        Self::new(1)
    }
}

// ---------------------------------------------------------------------------
// WAL entry types
// ---------------------------------------------------------------------------

/// The type of operation recorded in a WAL entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalEntryType {
    /// A block write within a transaction.
    Write { block: BlockNumber, data: Vec<u8> },
    /// A commit marker — the transaction is durable after this entry is persisted.
    Commit,
    /// An abort marker — discard all writes for this transaction.
    Abort,
}

/// A single entry in the per-core WAL buffer.
///
/// Each entry is self-contained: it carries its epoch, transaction ID, and
/// a CRC32C checksum of the payload for integrity verification during recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalEntry {
    /// Global epoch at the time this entry was appended.
    pub epoch: u64,
    /// Transaction that produced this entry.
    pub txn_id: TxnId,
    /// Commit sequence (set on commit entries; 0 for writes/aborts).
    pub commit_seq: CommitSeq,
    /// The operation.
    pub entry_type: WalEntryType,
    /// CRC32C of the data payload (0 for non-write entries).
    pub crc32c: u32,
}

// ---------------------------------------------------------------------------
// Per-core buffer
// ---------------------------------------------------------------------------

/// Configuration for per-core WAL buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalBufferConfig {
    /// Maximum number of entries before the buffer auto-flushes.
    /// Default: 1024.
    pub max_entries: usize,
    /// Maximum total payload bytes before the buffer auto-flushes.
    /// Default: 4 MiB (4 * 1024 * 1024).
    pub max_bytes: usize,
}

impl Default for WalBufferConfig {
    fn default() -> Self {
        Self {
            max_entries: 1024,
            max_bytes: 4 * 1024 * 1024,
        }
    }
}

/// A single core's WAL buffer.
///
/// This is **not** shared between threads. Each thread owns exactly one
/// `CoreWalBuffer` (accessed via thread-local storage or explicit ownership).
/// All operations are `&mut self` — no interior mutability, no locks.
#[derive(Debug)]
pub struct CoreWalBuffer {
    /// Buffered entries awaiting flush.
    entries: Vec<WalEntry>,
    /// Running total of payload bytes in `entries`.
    payload_bytes: usize,
    /// Configuration thresholds.
    config: WalBufferConfig,
    /// Logical core/thread identifier for tracing.
    core_id: usize,
}

impl CoreWalBuffer {
    /// Create a new buffer for the given core/thread.
    #[must_use]
    pub fn new(core_id: usize, config: WalBufferConfig) -> Self {
        Self {
            entries: Vec::with_capacity(config.max_entries),
            payload_bytes: 0,
            config,
            core_id,
        }
    }

    /// Append a block write to this buffer.
    ///
    /// Returns `true` if the buffer should be flushed (capacity exceeded).
    /// The caller is responsible for calling [`drain`](Self::drain) when this
    /// returns `true`.
    pub fn append_write(
        &mut self,
        epoch: u64,
        txn_id: TxnId,
        block: BlockNumber,
        data: Vec<u8>,
    ) -> bool {
        let crc = crc32c::crc32c(&data);
        let data_len = data.len();
        self.entries.push(WalEntry {
            epoch,
            txn_id,
            commit_seq: CommitSeq(0),
            entry_type: WalEntryType::Write { block, data },
            crc32c: crc,
        });
        self.payload_bytes = self.payload_bytes.saturating_add(data_len);

        tracing::trace!(
            target: "ffs::wal_buffer",
            core_id = self.core_id,
            epoch,
            txn_id = txn_id.0,
            block = block.0,
            data_len,
            entries = self.entries.len(),
            payload_bytes = self.payload_bytes,
            "wal_buffer_append_write"
        );

        self.should_flush()
    }

    /// Append a commit marker to this buffer.
    ///
    /// Returns `true` if the buffer should be flushed.
    pub fn append_commit(&mut self, epoch: u64, txn_id: TxnId, commit_seq: CommitSeq) -> bool {
        self.entries.push(WalEntry {
            epoch,
            txn_id,
            commit_seq,
            entry_type: WalEntryType::Commit,
            crc32c: 0,
        });

        tracing::debug!(
            target: "ffs::wal_buffer",
            core_id = self.core_id,
            epoch,
            txn_id = txn_id.0,
            commit_seq = commit_seq.0,
            entries = self.entries.len(),
            "wal_buffer_append_commit"
        );

        self.should_flush()
    }

    /// Append an abort marker to this buffer.
    ///
    /// Returns `true` if the buffer should be flushed.
    pub fn append_abort(&mut self, epoch: u64, txn_id: TxnId) -> bool {
        self.entries.push(WalEntry {
            epoch,
            txn_id,
            commit_seq: CommitSeq(0),
            entry_type: WalEntryType::Abort,
            crc32c: 0,
        });

        tracing::debug!(
            target: "ffs::wal_buffer",
            core_id = self.core_id,
            epoch,
            txn_id = txn_id.0,
            entries = self.entries.len(),
            "wal_buffer_append_abort"
        );

        self.should_flush()
    }

    /// Drain all buffered entries, resetting the buffer to empty.
    ///
    /// The returned entries should be serialized and persisted by the caller.
    pub fn drain(&mut self) -> Vec<WalEntry> {
        let count = self.entries.len();
        let bytes = self.payload_bytes;
        self.payload_bytes = 0;
        let drained = std::mem::take(&mut self.entries);
        self.entries = Vec::with_capacity(self.config.max_entries);

        tracing::debug!(
            target: "ffs::wal_buffer",
            core_id = self.core_id,
            entries_flushed = count,
            payload_bytes_flushed = bytes,
            "wal_buffer_drain"
        );

        drained
    }

    /// Number of entries currently buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total payload bytes currently buffered.
    #[must_use]
    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    /// Core/thread identifier.
    #[must_use]
    pub fn core_id(&self) -> usize {
        self.core_id
    }

    fn should_flush(&self) -> bool {
        self.entries.len() >= self.config.max_entries || self.payload_bytes >= self.config.max_bytes
    }
}

// ---------------------------------------------------------------------------
// Per-core buffer pool (multi-threaded coordinator)
// ---------------------------------------------------------------------------

/// Flush result from draining one or more per-core buffers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FlushResult {
    /// Total entries drained across all buffers.
    pub entries_flushed: usize,
    /// Total payload bytes drained.
    pub payload_bytes_flushed: usize,
    /// Number of buffers that contributed entries.
    pub buffers_drained: usize,
}

thread_local! {
    static THREAD_WAL_BUFFER: RefCell<Option<CoreWalBuffer>> = const { RefCell::new(None) };
}

/// Next thread-local core ID (used for tracing, not for CPU affinity).
static NEXT_CORE_ID: AtomicU64 = AtomicU64::new(0);

#[allow(deprecated)]
fn allocate_core_id(counter: &AtomicU64) -> usize {
    let id = match counter.try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        current.checked_add(1)
    }) {
        Ok(previous) | Err(previous) => previous,
    };
    usize::try_from(id).unwrap_or(usize::MAX)
}

/// Initialize (or reinitialize) the current thread's WAL buffer.
///
/// Must be called before any `with_thread_buffer` calls on this thread.
/// Safe to call multiple times — replaces the previous buffer (any un-drained
/// entries are lost).
pub fn init_thread_buffer(config: WalBufferConfig) {
    let core_id = allocate_core_id(&NEXT_CORE_ID);
    THREAD_WAL_BUFFER.with(|cell| {
        *cell.borrow_mut() = Some(CoreWalBuffer::new(core_id, config));
    });
}

/// Access the current thread's WAL buffer.
///
/// # Panics
///
/// Panics if [`init_thread_buffer`] has not been called on this thread.
pub fn with_thread_buffer<F, R>(f: F) -> R
where
    F: FnOnce(&mut CoreWalBuffer) -> R,
{
    THREAD_WAL_BUFFER.with(|cell| {
        let mut borrow = cell.borrow_mut();
        let buf = borrow
            .as_mut()
            .expect("WAL buffer not initialized — call init_thread_buffer first");
        f(buf)
    })
}

/// Drain the current thread's WAL buffer, returning all buffered entries.
///
/// Returns an empty vec if the buffer hasn't been initialized or is already empty.
#[must_use]
pub fn drain_thread_buffer() -> Vec<WalEntry> {
    THREAD_WAL_BUFFER.with(|cell| {
        let mut borrow = cell.borrow_mut();
        borrow.as_mut().map_or_else(Vec::new, CoreWalBuffer::drain)
    })
}

// ---------------------------------------------------------------------------
// Standalone pool for explicit ownership (no thread-local magic)
// ---------------------------------------------------------------------------

/// An explicitly-managed pool of per-core WAL buffers.
///
/// Unlike the thread-local API above, `ExplicitWalPool` gives the caller full
/// ownership of each buffer. This is useful for testing and for architectures
/// where thread-local storage is undesirable.
#[derive(Debug)]
pub struct ExplicitWalPool {
    epoch: EpochCounter,
    config: WalBufferConfig,
}

impl ExplicitWalPool {
    /// Create a new pool with the given configuration.
    #[must_use]
    pub fn new(config: WalBufferConfig) -> Self {
        Self {
            epoch: EpochCounter::default(),
            config,
        }
    }

    /// Allocate a new per-core buffer.
    #[must_use]
    pub fn allocate_buffer(&self, core_id: usize) -> CoreWalBuffer {
        CoreWalBuffer::new(core_id, self.config)
    }

    /// Read the current epoch.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.epoch.current()
    }

    /// Advance to the next epoch, returning the new value.
    pub fn advance_epoch(&self) -> u64 {
        self.epoch.advance()
    }

    /// Drain all provided buffers, collecting entries sorted by epoch.
    ///
    /// Within the same epoch, entries retain their per-buffer append order
    /// (but inter-buffer ordering within an epoch is arbitrary — by design,
    /// same-epoch entries are commutative).
    pub fn drain_all(&self, buffers: &mut [CoreWalBuffer]) -> (Vec<WalEntry>, FlushResult) {
        let mut all_entries = Vec::new();
        let mut result = FlushResult::default();

        for buf in buffers.iter_mut() {
            let drained = buf.drain();
            if !drained.is_empty() {
                result.buffers_drained += 1;
                result.entries_flushed += drained.len();
                for entry in &drained {
                    if let WalEntryType::Write { data, .. } = &entry.entry_type {
                        result.payload_bytes_flushed =
                            result.payload_bytes_flushed.saturating_add(data.len());
                    }
                }
                all_entries.extend(drained);
            }
        }

        // Sort by epoch for correct ordering; within same epoch, order is arbitrary.
        all_entries.sort_unstable_by_key(|e| e.epoch);

        tracing::info!(
            target: "ffs::wal_buffer",
            entries_flushed = result.entries_flushed,
            payload_bytes = result.payload_bytes_flushed,
            buffers_drained = result.buffers_drained,
            "explicit_pool_drain_all"
        );

        (all_entries, result)
    }
}

// ---------------------------------------------------------------------------
// Epoch manager (time-based + count-based epoch advancement)
// ---------------------------------------------------------------------------

/// Configuration for the epoch manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochManagerConfig {
    /// Advance the epoch after this many commits within the current epoch.
    /// Default: 64.
    pub commit_threshold: u64,
    /// Advance the epoch after this duration has elapsed.
    /// Default: 10ms.
    pub epoch_interval: std::time::Duration,
}

impl Default for EpochManagerConfig {
    fn default() -> Self {
        Self {
            commit_threshold: 64,
            epoch_interval: std::time::Duration::from_millis(10),
        }
    }
}

/// Manages epoch advancement and tracks which epochs have been durably flushed.
///
/// The epoch manager provides the ordering backbone for per-core WAL buffers.
/// Epochs advance based on two triggers (whichever fires first):
/// 1. **Count-based**: after `commit_threshold` commits in the current epoch.
/// 2. **Time-based**: after `epoch_interval` has elapsed since the last advance.
///
/// After an epoch advances, all entries stamped with the old epoch become
/// eligible for group commit (a single `fsync` covers all entries in the epoch).
///
/// The durability contract:
/// - A transaction in epoch E is durable **only** after `mark_epoch_flushed(E)`.
/// - `is_durable(E)` returns `true` iff epoch E (and all prior) have been flushed.
#[derive(Debug)]
pub struct EpochManager {
    epoch: EpochCounter,
    config: EpochManagerConfig,
    /// Commits in the current epoch (reset on advance).
    commits_in_epoch: AtomicU64,
    /// Timestamp of the last epoch advance.
    last_advance: std::sync::Mutex<std::time::Instant>,
    /// Highest epoch that has been durably flushed to disk.
    flushed_epoch: AtomicU64,
}

impl EpochManager {
    /// Create a new epoch manager starting at epoch 1.
    #[must_use]
    pub fn new(config: EpochManagerConfig) -> Self {
        Self {
            epoch: EpochCounter::new(1),
            config,
            commits_in_epoch: AtomicU64::new(0),
            last_advance: std::sync::Mutex::new(std::time::Instant::now()),
            flushed_epoch: AtomicU64::new(0),
        }
    }

    /// The current epoch value.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.epoch.current()
    }

    /// Record a commit in the current epoch.
    ///
    /// Returns `Some(new_epoch)` if the epoch was advanced (commit threshold
    /// reached), or `None` if the epoch stays the same.
    pub fn record_commit(&self) -> Option<u64> {
        let commits = self.increment_commits_in_epoch();
        if commits >= self.config.commit_threshold {
            self.try_advance(false)
        } else {
            None
        }
    }

    #[allow(deprecated)]
    fn increment_commits_in_epoch(&self) -> u64 {
        match self
            .commits_in_epoch
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_add(1))
            }) {
            Ok(previous) => previous.saturating_add(1),
            Err(current) => current,
        }
    }

    /// Check whether the epoch should advance due to elapsed time.
    ///
    /// Returns `Some(new_epoch)` if the interval has elapsed and the epoch
    /// was advanced, or `None` if not yet time.
    pub fn maybe_advance_by_time(&self) -> Option<u64> {
        self.try_advance(false)
    }

    /// Check if the current epoch should advance (either trigger).
    ///
    /// Returns `Some(new_epoch)` if advanced, `None` otherwise.
    pub fn maybe_advance(&self) -> Option<u64> {
        self.try_advance(false)
    }

    /// Force an epoch advance regardless of triggers.
    pub fn force_advance(&self) -> u64 {
        self.try_advance(true)
            .unwrap_or_else(|| self.epoch.current())
    }

    #[allow(clippy::significant_drop_tightening)]
    fn try_advance(&self, force: bool) -> Option<u64> {
        let mut guard = self
            .last_advance
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let needs_advance = force
            || guard.elapsed() >= self.config.epoch_interval
            || self.commits_in_epoch.load(Ordering::Acquire) >= self.config.commit_threshold;

        if needs_advance {
            let new_epoch = self.epoch.advance();
            *guard = std::time::Instant::now();
            self.commits_in_epoch.store(0, Ordering::Release);
            tracing::debug!(
                target: "ffs::wal_buffer",
                new_epoch,
                "epoch_advanced"
            );
            Some(new_epoch)
        } else {
            None
        }
    }

    #[cfg(test)]
    fn rewind_last_advance_for_test(&self, elapsed: std::time::Duration) {
        let mut guard = self
            .last_advance
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = std::time::Instant::now()
            .checked_sub(elapsed)
            .unwrap_or_else(std::time::Instant::now);
    }

    /// Mark an epoch as durably flushed.
    ///
    /// After this call, `is_durable(epoch)` returns `true`.
    /// Epochs must be flushed in order — the caller must ensure epoch E-1
    /// is flushed before E.
    pub fn mark_epoch_flushed(&self, epoch: u64) {
        let mut current = self.flushed_epoch.load(Ordering::Acquire);
        loop {
            if epoch <= current {
                return; // Already flushed.
            }
            match self.flushed_epoch.compare_exchange_weak(
                current,
                epoch,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    tracing::info!(
                        target: "ffs::wal_buffer",
                        epoch,
                        "epoch_flushed"
                    );
                    return;
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// Check whether the given epoch has been durably flushed.
    #[must_use]
    pub fn is_durable(&self, epoch: u64) -> bool {
        epoch <= self.flushed_epoch.load(Ordering::Acquire)
    }

    /// The highest epoch that has been durably flushed.
    #[must_use]
    pub fn flushed_epoch(&self) -> u64 {
        self.flushed_epoch.load(Ordering::Acquire)
    }

    /// Stamp a WAL entry with the current epoch.
    ///
    /// Convenience method that reads the current epoch atomically.
    #[must_use]
    pub fn stamp(&self) -> u64 {
        self.epoch.current()
    }
}

// ---------------------------------------------------------------------------
// Group commit — WAL writer trait
// ---------------------------------------------------------------------------

/// Trait for writing WAL entries to durable storage.
///
/// Implementations handle the actual I/O: serializing entries to a file/device,
/// then issuing `fsync`. The group commit coordinator calls `write_entries`
/// once for all entries in an epoch, followed by a single `sync`.
pub trait WalWriter: Send + Sync {
    /// Write a batch of WAL entries to the underlying storage.
    ///
    /// The entries are guaranteed to be sorted by epoch. The implementation
    /// should append them atomically (or as close to atomic as possible).
    fn write_entries(&self, entries: &[WalEntry]) -> Result<(), FfsError>;

    /// Ensure all previously written entries are durable (fsync).
    fn sync(&self) -> Result<(), FfsError>;
}

// ---------------------------------------------------------------------------
// Group commit — durability notifier
// ---------------------------------------------------------------------------

/// Tracks durability state and wakes transactions awaiting epoch flush.
///
/// The protocol:
/// - Committing transactions call [`await_epoch`](Self::await_epoch) and block
///   until the epoch is durable (or has failed).
/// - The group commit coordinator calls [`notify_durable`](Self::notify_durable)
///   after a successful fsync, or [`notify_failed`](Self::notify_failed) on error.
/// - All waiters for the affected epoch (and earlier) are woken together.
///
/// # Concurrency invariants (bd-lebu5)
///
/// **Invariant 1 — notify outside the lock.** Both `notify_durable` and
/// `notify_failed` acquire `state`, mutate, drop the guard at the inner
/// block scope, THEN call `condvar.notify_all()`. Notifying *while*
/// holding `state` would force every woken waiter to re-block on the
/// same mutex on the very next instruction — a subtle perf regression
/// (every `notify_all` would serialize through the mutex twice). Future
/// refactors that hoist the `notify_all` inside the inner block must
/// be rejected.
///
/// **Invariant 2 — predicate-loop on every wake.** `await_epoch` and
/// `await_epoch_timeout` re-check the `durable_epoch` and `failed`
/// predicates on EVERY condvar wake — both spurious wakes (allowed by
/// the OS) and notify_all-induced wakes for unrelated lower epochs. A
/// regression that drops the surrounding `loop { ... }` — converting
/// the wait into single-shot — would silently let `notify_durable(2)`
/// wake a waiter awaiting epoch 5; that waiter would then read
/// `durable_epoch == 2`, return [`DurabilityOutcome::Durable`], and
/// the calling fsync path would *trust* an unrelated lower epoch as
/// durable. The
/// `durability_notifier_lower_epoch_notification_does_not_wake_higher_epoch_waiter`
/// regression test pins this contract.
#[derive(Debug)]
pub struct DurabilityNotifier {
    state: Mutex<DurabilityState>,
    condvar: Condvar,
}

#[derive(Debug)]
struct DurabilityState {
    /// Highest epoch that has been durably flushed.
    durable_epoch: u64,
    /// If set, the epoch that failed and a description of the error.
    failed: Option<(u64, String)>,
}

/// Outcome of awaiting epoch durability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurabilityOutcome {
    /// The epoch (and all prior) are durable on disk.
    Durable,
    /// The flush for this epoch failed.
    Failed(String),
}

impl DurabilityNotifier {
    /// Create a new notifier with no epochs durable.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(DurabilityState {
                durable_epoch: 0,
                failed: None,
            }),
            condvar: Condvar::new(),
        }
    }

    /// Block until `epoch` is durable or has failed.
    ///
    /// Returns immediately if the epoch is already durable.
    pub fn await_epoch(&self, epoch: u64) -> DurabilityOutcome {
        self.await_epoch_with_observer(epoch, || {})
    }

    fn await_epoch_with_observer<F>(&self, epoch: u64, mut before_wait: F) -> DurabilityOutcome
    where
        F: FnMut(),
    {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            // Check for failure first.
            if let Some((failed_epoch, ref msg)) = state.failed {
                if epoch >= failed_epoch {
                    return DurabilityOutcome::Failed(msg.clone());
                }
            }
            // Check for success.
            if epoch <= state.durable_epoch {
                return DurabilityOutcome::Durable;
            }
            before_wait();
            state = self
                .condvar
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// Block until `epoch` is durable or has failed, with a timeout.
    ///
    /// Returns `None` if the timeout elapsed before resolution.
    pub fn await_epoch_timeout(
        &self,
        epoch: u64,
        timeout: std::time::Duration,
    ) -> Option<DurabilityOutcome> {
        self.await_epoch_timeout_with_observer(epoch, timeout, || {})
    }

    fn await_epoch_timeout_with_observer<F>(
        &self,
        epoch: u64,
        timeout: std::time::Duration,
        mut before_wait: F,
    ) -> Option<DurabilityOutcome>
    where
        F: FnMut(),
    {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some((failed_epoch, ref msg)) = state.failed {
                if epoch >= failed_epoch {
                    return Some(DurabilityOutcome::Failed(msg.clone()));
                }
            }
            if epoch <= state.durable_epoch {
                return Some(DurabilityOutcome::Durable);
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            before_wait();
            let (new_state, timeout_result) = self
                .condvar
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = new_state;
            if timeout_result.timed_out() {
                // One more check before giving up.
                if let Some((failed_epoch, ref msg)) = state.failed {
                    if epoch >= failed_epoch {
                        return Some(DurabilityOutcome::Failed(msg.clone()));
                    }
                }
                if epoch <= state.durable_epoch {
                    return Some(DurabilityOutcome::Durable);
                }
                drop(state);
                return None;
            }
        }
    }

    /// Mark `epoch` (and all prior) as durably flushed. Wakes all waiters.
    pub fn notify_durable(&self, epoch: u64) {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if epoch > state.durable_epoch {
                state.durable_epoch = epoch;
            }
        }
        self.condvar.notify_all();
    }

    /// Mark `epoch` as failed. Wakes all waiters.
    pub fn notify_failed(&self, epoch: u64, error: String) {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Keep the lowest failed epoch.
            match &state.failed {
                Some((prev, _)) if *prev <= epoch => {}
                _ => state.failed = Some((epoch, error)),
            }
        }
        self.condvar.notify_all();
    }

    /// The highest epoch that has been durably flushed.
    #[must_use]
    pub fn durable_epoch(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .durable_epoch
    }
}

impl Default for DurabilityNotifier {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Group commit — coordinator
// ---------------------------------------------------------------------------

/// Configuration for the group commit coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupCommitConfig {
    /// Maximum retries for a failed fsync before giving up.
    /// Default: 3.
    pub max_retries: usize,
}

impl Default for GroupCommitConfig {
    fn default() -> Self {
        Self { max_retries: 3 }
    }
}

/// Result of a successful group commit flush.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupCommitResult {
    /// The epoch that was flushed.
    pub epoch: u64,
    /// Number of entries written.
    pub entries_written: usize,
    /// Total payload bytes written.
    pub payload_bytes: usize,
    /// Number of fsync calls issued (including retries).
    pub fsyncs_issued: usize,
}

/// Coordinates group commit: collects per-core WAL buffers for an epoch,
/// writes them via a [`WalWriter`], issues a single fsync, and notifies
/// waiting transactions.
///
/// The flush protocol:
/// 1. Collect entries from all per-core buffers (caller drains buffers and
///    passes the collected entries).
/// 2. Filter entries for the target epoch (and any earlier unflushed epochs).
/// 3. Write all entries to storage via [`WalWriter::write_entries`].
/// 4. Issue a single [`WalWriter::sync`] (with retries on failure).
/// 5. On success: update `EpochManager` and `DurabilityNotifier`.
/// 6. On failure: notify waiters of the failure.
pub struct GroupCommitCoordinator<W: WalWriter> {
    epoch_manager: Arc<EpochManager>,
    notifier: Arc<DurabilityNotifier>,
    writer: W,
    config: GroupCommitConfig,
}

impl<W: WalWriter> std::fmt::Debug for GroupCommitCoordinator<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupCommitCoordinator")
            .field("epoch_manager", &self.epoch_manager)
            .field("notifier", &self.notifier)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<W: WalWriter> GroupCommitCoordinator<W> {
    /// Create a new group commit coordinator.
    pub fn new(
        epoch_manager: Arc<EpochManager>,
        notifier: Arc<DurabilityNotifier>,
        writer: W,
        config: GroupCommitConfig,
    ) -> Self {
        Self {
            epoch_manager,
            notifier,
            writer,
            config,
        }
    }

    /// Flush all entries up to (and including) `epoch`.
    ///
    /// `entries` should be the collected drain from all per-core buffers.
    /// Only entries with epoch <= `epoch` are written. Entries with higher
    /// epochs are returned (they belong to a future flush).
    ///
    /// On success, the `EpochManager` and `DurabilityNotifier` are updated.
    /// On failure (after retries), waiters are notified of the failure.
    pub fn flush_epoch(
        &self,
        entries: Vec<WalEntry>,
        epoch: u64,
    ) -> Result<(GroupCommitResult, Vec<WalEntry>), FfsError> {
        // Retain the input allocation for the common, dominant flush set and
        // move only future entries into the returned tail.
        let mut to_flush = entries;
        let remaining = to_flush
            .extract_if(.., |entry| entry.epoch > epoch)
            .collect();

        if to_flush.is_empty() {
            // Nothing to flush — still mark the epoch as durable (it's vacuously true).
            self.epoch_manager.mark_epoch_flushed(epoch);
            self.notifier.notify_durable(epoch);

            tracing::debug!(
                target: "ffs::group_commit",
                epoch,
                "group_commit_empty_epoch"
            );

            return Ok((
                GroupCommitResult {
                    epoch,
                    entries_written: 0,
                    payload_bytes: 0,
                    fsyncs_issued: 0,
                },
                remaining,
            ));
        }

        // Compute payload bytes for the result.
        let payload_bytes: usize = to_flush
            .iter()
            .map(|e| match &e.entry_type {
                WalEntryType::Write { data, .. } => data.len(),
                _ => 0,
            })
            .sum();
        let entries_written = to_flush.len();

        tracing::info!(
            target: "ffs::group_commit",
            epoch,
            entries = entries_written,
            payload_bytes,
            "group_commit_write_start"
        );

        // Write entries to storage.
        if let Err(e) = self.writer.write_entries(&to_flush) {
            let msg = format!("write_entries failed: {e}");
            tracing::error!(
                target: "ffs::group_commit",
                epoch,
                error = %e,
                "group_commit_write_failed"
            );
            self.notifier.notify_failed(epoch, msg);
            return Err(e);
        }

        // Fsync with retries.
        let mut fsyncs_issued = 0_usize;
        let mut last_err = None;
        for attempt in 0..=self.config.max_retries {
            fsyncs_issued += 1;
            match self.writer.sync() {
                Ok(()) => {
                    // Success — update epoch manager and notifier.
                    self.epoch_manager.mark_epoch_flushed(epoch);
                    self.notifier.notify_durable(epoch);

                    tracing::info!(
                        target: "ffs::group_commit",
                        epoch,
                        entries = entries_written,
                        payload_bytes,
                        fsyncs_issued,
                        "group_commit_success"
                    );

                    return Ok((
                        GroupCommitResult {
                            epoch,
                            entries_written,
                            payload_bytes,
                            fsyncs_issued,
                        },
                        remaining,
                    ));
                }
                Err(e) => {
                    tracing::warn!(
                        target: "ffs::group_commit",
                        epoch,
                        attempt,
                        error = %e,
                        "group_commit_sync_retry"
                    );
                    last_err = Some(e);
                }
            }
        }

        // All retries exhausted.
        let err = last_err
            .unwrap_or_else(|| FfsError::Format("fsync loop failed to record an error".into()));
        let msg = format!("fsync failed after {fsyncs_issued} attempts: {err}");
        tracing::error!(
            target: "ffs::group_commit",
            epoch,
            fsyncs_issued,
            error = %err,
            "group_commit_sync_exhausted"
        );
        self.notifier.notify_failed(epoch, msg);
        Err(err)
    }

    /// Access the epoch manager.
    #[must_use]
    pub fn epoch_manager(&self) -> &Arc<EpochManager> {
        &self.epoch_manager
    }

    /// Access the durability notifier.
    #[must_use]
    pub fn notifier(&self) -> &Arc<DurabilityNotifier> {
        &self.notifier
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use std::sync::mpsc::{Receiver, sync_channel};
    use std::sync::{Arc, Barrier};
    use std::thread::JoinHandle;

    fn spawn_observed_epoch_waiter(
        notifier: &Arc<DurabilityNotifier>,
        epoch: u64,
    ) -> (Receiver<()>, JoinHandle<DurabilityOutcome>) {
        let (before_wait_tx, before_wait_rx) = sync_channel(1);
        let notifier = Arc::clone(notifier);
        let handle = std::thread::spawn(move || {
            notifier.await_epoch_with_observer(epoch, || {
                before_wait_tx
                    .send(())
                    .expect("test receiver should observe waiter parking");
            })
        });
        (before_wait_rx, handle)
    }

    fn spawn_observed_epoch_timeout_waiter(
        notifier: &Arc<DurabilityNotifier>,
        epoch: u64,
        timeout: std::time::Duration,
    ) -> (Receiver<()>, JoinHandle<Option<DurabilityOutcome>>) {
        let (before_wait_tx, before_wait_rx) = sync_channel(1);
        let notifier = Arc::clone(notifier);
        let handle = std::thread::spawn(move || {
            notifier.await_epoch_timeout_with_observer(epoch, timeout, || {
                before_wait_tx
                    .send(())
                    .expect("test receiver should observe waiter parking");
            })
        });
        (before_wait_rx, handle)
    }

    fn observe_waiter_parking(before_wait: &Receiver<()>) {
        before_wait
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("waiter should reach the condvar wait point");
    }

    fn make_config(max_entries: usize, max_bytes: usize) -> WalBufferConfig {
        WalBufferConfig {
            max_entries,
            max_bytes,
        }
    }

    // -- CoreWalBuffer unit tests --

    #[test]
    fn empty_buffer_is_empty() {
        let buf = CoreWalBuffer::new(0, WalBufferConfig::default());
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.payload_bytes(), 0);
        assert_eq!(buf.core_id(), 0);
    }

    #[test]
    fn append_write_tracks_entry_count_and_bytes() {
        let mut buf = CoreWalBuffer::new(1, WalBufferConfig::default());
        let data = vec![0xAB; 4096];
        let should_flush = buf.append_write(1, TxnId(10), BlockNumber(5), data);
        assert!(!should_flush);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.payload_bytes(), 4096);
    }

    #[test]
    fn append_commit_increments_entry_count() {
        let mut buf = CoreWalBuffer::new(2, WalBufferConfig::default());
        buf.append_commit(1, TxnId(20), CommitSeq(3));
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.payload_bytes(), 0); // Commit has no payload.
    }

    #[test]
    fn append_abort_increments_entry_count() {
        let mut buf = CoreWalBuffer::new(3, WalBufferConfig::default());
        buf.append_abort(1, TxnId(30));
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.payload_bytes(), 0);
    }

    #[test]
    fn core_id_allocator_saturates_without_wrapping() {
        let counter = AtomicU64::new(u64::MAX - 1);

        let penultimate = allocate_core_id(&counter);
        assert_eq!(
            penultimate,
            usize::try_from(u64::MAX - 1).unwrap_or(usize::MAX)
        );
        assert_eq!(counter.load(Ordering::Acquire), u64::MAX);

        let saturated = allocate_core_id(&counter);
        assert_eq!(saturated, usize::MAX);
        assert_eq!(counter.load(Ordering::Acquire), u64::MAX);

        let still_saturated = allocate_core_id(&counter);
        assert_eq!(still_saturated, usize::MAX);
        assert_eq!(counter.load(Ordering::Acquire), u64::MAX);
    }

    #[test]
    fn drain_returns_all_entries_and_resets() {
        let mut buf = CoreWalBuffer::new(0, WalBufferConfig::default());
        buf.append_write(1, TxnId(1), BlockNumber(1), vec![0x11; 100]);
        buf.append_write(1, TxnId(1), BlockNumber(2), vec![0x22; 200]);
        buf.append_commit(1, TxnId(1), CommitSeq(1));

        let entries = buf.drain();
        assert_eq!(entries.len(), 3);
        assert!(buf.is_empty());
        assert_eq!(buf.payload_bytes(), 0);

        // Verify entry contents.
        assert_eq!(entries[0].epoch, 1);
        assert_eq!(entries[0].txn_id, TxnId(1));
        assert!(matches!(
            &entries[0].entry_type,
            WalEntryType::Write { block, data }
            if *block == BlockNumber(1) && data.len() == 100
        ));
        assert_ne!(entries[0].crc32c, 0); // CRC computed for writes.

        assert!(matches!(entries[2].entry_type, WalEntryType::Commit));
        assert_eq!(entries[2].commit_seq, CommitSeq(1));
    }

    #[test]
    fn should_flush_on_max_entries() {
        let cfg = make_config(3, usize::MAX);
        let mut buf = CoreWalBuffer::new(0, cfg);
        assert!(!buf.append_write(1, TxnId(1), BlockNumber(1), vec![0; 10]));
        assert!(!buf.append_write(1, TxnId(1), BlockNumber(2), vec![0; 10]));
        assert!(buf.append_write(1, TxnId(1), BlockNumber(3), vec![0; 10]));
    }

    #[test]
    fn should_flush_on_max_bytes() {
        let cfg = make_config(1_000_000, 256);
        let mut buf = CoreWalBuffer::new(0, cfg);
        assert!(!buf.append_write(1, TxnId(1), BlockNumber(1), vec![0; 200]));
        assert!(buf.append_write(1, TxnId(1), BlockNumber(2), vec![0; 100]));
    }

    #[test]
    fn crc32c_matches_payload() {
        let mut buf = CoreWalBuffer::new(0, WalBufferConfig::default());
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let expected_crc = crc32c::crc32c(&data);
        buf.append_write(5, TxnId(42), BlockNumber(99), data);
        let entries = buf.drain();
        assert_eq!(entries[0].crc32c, expected_crc);
    }

    #[test]
    fn multiple_transactions_interleaved() {
        let mut buf = CoreWalBuffer::new(0, WalBufferConfig::default());
        // Transaction 1 writes.
        buf.append_write(1, TxnId(1), BlockNumber(10), vec![0x11; 50]);
        // Transaction 2 writes.
        buf.append_write(1, TxnId(2), BlockNumber(20), vec![0x22; 50]);
        // Transaction 1 commits.
        buf.append_commit(1, TxnId(1), CommitSeq(1));
        // Transaction 2 aborts.
        buf.append_abort(1, TxnId(2));

        let entries = buf.drain();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].txn_id, TxnId(1));
        assert_eq!(entries[1].txn_id, TxnId(2));
        assert!(matches!(entries[2].entry_type, WalEntryType::Commit));
        assert!(matches!(entries[3].entry_type, WalEntryType::Abort));
    }

    // -- EpochCounter tests --

    #[test]
    fn epoch_counter_starts_at_given_value() {
        let epoch = EpochCounter::new(42);
        assert_eq!(epoch.current(), 42);
    }

    #[test]
    fn epoch_counter_advances_monotonically() {
        let epoch = EpochCounter::new(1);
        assert_eq!(epoch.advance(), 2);
        assert_eq!(epoch.advance(), 3);
        assert_eq!(epoch.advance(), 4);
        assert_eq!(epoch.current(), 4);
    }

    #[test]
    fn epoch_counter_concurrent_advances_are_unique() {
        let epoch = Arc::new(EpochCounter::new(0));
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let epoch = Arc::clone(&epoch);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let mut values = Vec::new();
                for _ in 0..100 {
                    values.push(epoch.advance());
                }
                values
            }));
        }

        let mut all_values: Vec<u64> = Vec::new();
        for h in handles {
            all_values.extend(h.join().expect("no panic"));
        }

        // All 800 values should be unique (no duplicates from concurrent CAS).
        all_values.sort_unstable();
        all_values.dedup();
        assert_eq!(all_values.len(), 800);
    }

    #[test]
    fn epoch_counter_saturates_at_u64_max() {
        let epoch = EpochCounter::new(u64::MAX - 1);
        assert_eq!(epoch.advance(), u64::MAX);
        assert_eq!(epoch.current(), u64::MAX);
        assert_eq!(epoch.advance(), u64::MAX);
        assert_eq!(epoch.current(), u64::MAX);
    }

    // -- ExplicitWalPool tests --

    #[test]
    fn explicit_pool_allocates_independent_buffers() {
        let pool = ExplicitWalPool::new(WalBufferConfig::default());
        let mut buf0 = pool.allocate_buffer(0);
        let mut buf1 = pool.allocate_buffer(1);

        buf0.append_write(1, TxnId(1), BlockNumber(10), vec![0x11; 100]);
        buf1.append_write(1, TxnId(2), BlockNumber(20), vec![0x22; 200]);

        assert_eq!(buf0.len(), 1);
        assert_eq!(buf1.len(), 1);
        assert_eq!(buf0.payload_bytes(), 100);
        assert_eq!(buf1.payload_bytes(), 200);
    }

    #[test]
    fn explicit_pool_drain_all_sorts_by_epoch() {
        let pool = ExplicitWalPool::new(WalBufferConfig::default());
        let mut buf0 = pool.allocate_buffer(0);
        let mut buf1 = pool.allocate_buffer(1);

        // buf0 gets epoch 3 entries.
        buf0.append_write(3, TxnId(1), BlockNumber(10), vec![0x33; 10]);
        // buf1 gets epoch 1 entries.
        buf1.append_write(1, TxnId(2), BlockNumber(20), vec![0x11; 10]);
        // buf0 gets epoch 2 entries.
        buf0.append_write(2, TxnId(3), BlockNumber(30), vec![0x22; 10]);

        let (entries, result) = pool.drain_all(&mut [buf0, buf1]);

        assert_eq!(entries.len(), 3);
        assert_eq!(result.entries_flushed, 3);
        assert_eq!(result.buffers_drained, 2);
        assert_eq!(result.payload_bytes_flushed, 30);

        // Verify sorted by epoch.
        assert_eq!(entries[0].epoch, 1);
        assert_eq!(entries[1].epoch, 2);
        assert_eq!(entries[2].epoch, 3);
    }

    #[test]
    fn explicit_pool_epoch_advances() {
        let pool = ExplicitWalPool::new(WalBufferConfig::default());
        assert_eq!(pool.current_epoch(), 1);
        assert_eq!(pool.advance_epoch(), 2);
        assert_eq!(pool.advance_epoch(), 3);
        assert_eq!(pool.current_epoch(), 3);
    }

    #[test]
    fn explicit_pool_drain_empty_buffers() {
        let pool = ExplicitWalPool::new(WalBufferConfig::default());
        let buf0 = pool.allocate_buffer(0);
        let buf1 = pool.allocate_buffer(1);

        let (entries, result) = pool.drain_all(&mut [buf0, buf1]);
        assert!(entries.is_empty());
        assert_eq!(result.entries_flushed, 0);
        assert_eq!(result.buffers_drained, 0);
    }

    // -- Concurrent per-core buffer tests --

    #[test]
    fn concurrent_append_to_separate_buffers_no_contention() {
        let pool = Arc::new(ExplicitWalPool::new(WalBufferConfig::default()));
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for core_id in 0..4_usize {
            let pool = Arc::clone(&pool);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let mut buf = pool.allocate_buffer(core_id);
                barrier.wait();
                for i in 0..500_u64 {
                    let epoch = pool.current_epoch();
                    buf.append_write(
                        epoch,
                        TxnId(core_id as u64 * 1000 + i),
                        BlockNumber(i),
                        vec![core_id as u8; 64],
                    );
                }
                buf
            }));
        }

        let mut buffers: Vec<CoreWalBuffer> = handles
            .into_iter()
            .map(|h| h.join().expect("no panic"))
            .collect();

        // Each buffer should have exactly 500 entries.
        for buf in &buffers {
            assert_eq!(buf.len(), 500);
        }

        // Drain all and verify total.
        let (entries, result) = pool.drain_all(&mut buffers);
        assert_eq!(entries.len(), 2000);
        assert_eq!(result.entries_flushed, 2000);
        assert_eq!(result.buffers_drained, 4);
    }

    #[test]
    fn concurrent_epoch_stamping_preserves_order() {
        let pool = Arc::new(ExplicitWalPool::new(WalBufferConfig::default()));
        let barrier = Arc::new(Barrier::new(2));

        // Thread 0: writes at epoch 1, then epoch 3.
        let pool0 = Arc::clone(&pool);
        let barrier0 = Arc::clone(&barrier);
        let h0 = std::thread::spawn(move || {
            let mut buf = pool0.allocate_buffer(0);
            barrier0.wait();
            buf.append_write(1, TxnId(100), BlockNumber(10), vec![0x01; 32]);
            buf.append_commit(1, TxnId(100), CommitSeq(1));
            buf.append_write(3, TxnId(101), BlockNumber(11), vec![0x03; 32]);
            buf.append_commit(3, TxnId(101), CommitSeq(3));
            buf
        });

        // Thread 1: writes at epoch 2.
        let pool1 = Arc::clone(&pool);
        let barrier1 = Arc::clone(&barrier);
        let h1 = std::thread::spawn(move || {
            let mut buf = pool1.allocate_buffer(1);
            barrier1.wait();
            buf.append_write(2, TxnId(200), BlockNumber(20), vec![0x02; 32]);
            buf.append_commit(2, TxnId(200), CommitSeq(2));
            buf
        });

        let buf0 = h0.join().expect("no panic");
        let buf1 = h1.join().expect("no panic");

        let (entries, _) = pool.drain_all(&mut [buf0, buf1]);

        // After sorting by epoch, we should see epoch 1, 1, 2, 2, 3, 3.
        let epochs: Vec<u64> = entries.iter().map(|e| e.epoch).collect();
        assert_eq!(epochs, vec![1, 1, 2, 2, 3, 3]);
    }

    #[test]
    fn drain_after_multiple_flush_cycles() {
        let mut buf = CoreWalBuffer::new(0, make_config(2, usize::MAX));

        // First cycle.
        buf.append_write(1, TxnId(1), BlockNumber(1), vec![0x01; 10]);
        assert!(buf.append_write(1, TxnId(1), BlockNumber(2), vec![0x02; 10]));
        let first = buf.drain();
        assert_eq!(first.len(), 2);

        // Second cycle.
        buf.append_write(2, TxnId(2), BlockNumber(3), vec![0x03; 10]);
        assert!(buf.append_write(2, TxnId(2), BlockNumber(4), vec![0x04; 10]));
        let second = buf.drain();
        assert_eq!(second.len(), 2);

        // Epochs are distinct.
        assert!(first.iter().all(|e| e.epoch == 1));
        assert!(second.iter().all(|e| e.epoch == 2));
    }

    // -- Thread-local API tests --

    #[test]
    fn thread_local_init_and_access() {
        // Run in a dedicated thread to avoid polluting other tests' TLS.
        let handle = std::thread::spawn(|| {
            init_thread_buffer(WalBufferConfig::default());
            with_thread_buffer(|buf| {
                buf.append_write(1, TxnId(1), BlockNumber(1), vec![0xFF; 32]);
                assert_eq!(buf.len(), 1);
            });
            let drained = drain_thread_buffer();
            assert_eq!(drained.len(), 1);
        });
        handle.join().expect("no panic");
    }

    #[test]
    fn thread_local_drain_without_init_returns_empty() {
        let handle = std::thread::spawn(|| {
            let drained = drain_thread_buffer();
            assert!(drained.is_empty());
        });
        handle.join().expect("no panic");
    }

    #[test]
    fn thread_local_buffers_are_independent() {
        let barrier = Arc::new(Barrier::new(2));
        let b0 = Arc::clone(&barrier);
        let b1 = Arc::clone(&barrier);

        let h0 = std::thread::spawn(move || {
            init_thread_buffer(WalBufferConfig::default());
            b0.wait();
            with_thread_buffer(|buf| {
                buf.append_write(1, TxnId(1), BlockNumber(10), vec![0x01; 64]);
            });
            let drained = drain_thread_buffer();
            assert_eq!(drained.len(), 1);
            assert_eq!(drained[0].txn_id, TxnId(1));
        });

        let h1 = std::thread::spawn(move || {
            init_thread_buffer(WalBufferConfig::default());
            b1.wait();
            with_thread_buffer(|buf| {
                buf.append_write(1, TxnId(2), BlockNumber(20), vec![0x02; 64]);
                buf.append_write(1, TxnId(2), BlockNumber(21), vec![0x03; 64]);
            });
            let drained = drain_thread_buffer();
            assert_eq!(drained.len(), 2);
            assert!(drained.iter().all(|e| e.txn_id == TxnId(2)));
        });

        h0.join().expect("no panic");
        h1.join().expect("no panic");
    }

    // -- EpochManager tests --

    #[test]
    fn epoch_manager_starts_at_epoch_1() {
        let mgr = EpochManager::new(EpochManagerConfig::default());
        assert_eq!(mgr.current_epoch(), 1);
        assert_eq!(mgr.flushed_epoch(), 0);
        assert!(!mgr.is_durable(1));
    }

    #[test]
    fn epoch_manager_advances_on_commit_threshold() {
        let cfg = EpochManagerConfig {
            commit_threshold: 3,
            epoch_interval: std::time::Duration::from_secs(3600), // No time trigger
        };
        let mgr = EpochManager::new(cfg);

        assert!(mgr.record_commit().is_none()); // 1 commit
        assert!(mgr.record_commit().is_none()); // 2 commits
        let result = mgr.record_commit(); // 3 commits -> threshold
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 2); // Epoch advanced from 1 to 2
        assert_eq!(mgr.current_epoch(), 2);
    }

    #[test]
    fn epoch_manager_commit_count_saturates_at_numeric_limit() {
        let cfg = EpochManagerConfig {
            commit_threshold: u64::MAX,
            epoch_interval: std::time::Duration::from_secs(3600),
        };
        let mgr = EpochManager::new(cfg);
        mgr.commits_in_epoch.store(u64::MAX, Ordering::Release);

        let result = mgr.record_commit();

        assert_eq!(result, Some(2));
        assert_eq!(mgr.current_epoch(), 2);
        assert_eq!(mgr.commits_in_epoch.load(Ordering::Acquire), 0);
    }

    #[test]
    fn epoch_manager_advances_on_time() {
        let cfg = EpochManagerConfig {
            commit_threshold: 1_000_000, // No count trigger
            epoch_interval: std::time::Duration::from_millis(1),
        };
        let mgr = EpochManager::new(cfg);

        // Should not advance immediately.
        assert!(mgr.maybe_advance_by_time().is_none());

        mgr.rewind_last_advance_for_test(std::time::Duration::from_millis(5));
        let result = mgr.maybe_advance_by_time();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 2);
    }

    #[test]
    fn epoch_manager_maybe_advance_checks_count() {
        let cfg = EpochManagerConfig {
            commit_threshold: 3,
            epoch_interval: std::time::Duration::from_secs(3600),
        };
        let mgr = EpochManager::new(cfg);

        // 1 commit — not enough for threshold.
        mgr.record_commit();
        assert!(mgr.maybe_advance().is_none());

        // 2 commits — still not enough.
        mgr.record_commit();
        assert!(mgr.maybe_advance().is_none());

        // 3rd commit triggers threshold via record_commit itself.
        let result = mgr.record_commit();
        assert!(result.is_some());
        assert_eq!(mgr.current_epoch(), 2);
    }

    #[test]
    fn epoch_manager_maybe_advance_checks_time() {
        let cfg = EpochManagerConfig {
            commit_threshold: 1_000_000,
            epoch_interval: std::time::Duration::from_millis(1),
        };
        let mgr = EpochManager::new(cfg);

        // No time elapsed yet.
        assert!(mgr.maybe_advance().is_none());

        mgr.rewind_last_advance_for_test(std::time::Duration::from_millis(5));
        let result = mgr.maybe_advance();
        assert!(result.is_some());
        assert_eq!(mgr.current_epoch(), 2);
    }

    #[test]
    fn epoch_manager_force_advance() {
        let mgr = EpochManager::new(EpochManagerConfig::default());
        assert_eq!(mgr.current_epoch(), 1);
        assert_eq!(mgr.force_advance(), 2);
        assert_eq!(mgr.force_advance(), 3);
        assert_eq!(mgr.current_epoch(), 3);
    }

    #[test]
    fn epoch_manager_durability_tracking() {
        let mgr = EpochManager::new(EpochManagerConfig::default());

        // No epochs flushed yet.
        assert!(!mgr.is_durable(1));
        assert!(!mgr.is_durable(2));

        // Flush epoch 1.
        mgr.mark_epoch_flushed(1);
        assert!(mgr.is_durable(1));
        assert!(!mgr.is_durable(2));
        assert_eq!(mgr.flushed_epoch(), 1);

        // Flush epoch 3 (skipping 2 is allowed — max-wins semantics).
        mgr.mark_epoch_flushed(3);
        assert!(mgr.is_durable(1));
        assert!(mgr.is_durable(2));
        assert!(mgr.is_durable(3));
        assert!(!mgr.is_durable(4));
    }

    #[test]
    fn epoch_manager_flushed_epoch_never_decreases() {
        let mgr = EpochManager::new(EpochManagerConfig::default());
        mgr.mark_epoch_flushed(5);
        assert_eq!(mgr.flushed_epoch(), 5);

        // Flushing an earlier epoch should be a no-op.
        mgr.mark_epoch_flushed(3);
        assert_eq!(mgr.flushed_epoch(), 5);
    }

    #[test]
    fn epoch_manager_stamp_returns_current() {
        let mgr = EpochManager::new(EpochManagerConfig::default());
        assert_eq!(mgr.stamp(), 1);
        mgr.force_advance();
        assert_eq!(mgr.stamp(), 2);
    }

    #[test]
    fn epoch_manager_concurrent_record_commit() {
        let cfg = EpochManagerConfig {
            commit_threshold: 100,
            epoch_interval: std::time::Duration::from_secs(3600),
        };
        let mgr = Arc::new(EpochManager::new(cfg));
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let mgr = Arc::clone(&mgr);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let mut advances = 0_u64;
                for _ in 0..200 {
                    if mgr.record_commit().is_some() {
                        advances += 1;
                    }
                }
                advances
            }));
        }

        let total_advances: u64 = handles
            .into_iter()
            .map(|h| h.join().expect("no panic"))
            .sum();

        // 800 total commits at threshold 100 = at least 7 advances.
        // Due to races, might get more or fewer exact advances, but the
        // epoch should have advanced at least a few times.
        assert!(total_advances >= 1, "expected at least 1 advance");
        assert!(mgr.current_epoch() > 1);
    }

    #[test]
    fn epoch_manager_integration_with_buffers() {
        let cfg = EpochManagerConfig {
            commit_threshold: 3,
            epoch_interval: std::time::Duration::from_secs(3600),
        };
        let mgr = EpochManager::new(cfg);
        let pool = ExplicitWalPool::new(WalBufferConfig::default());
        let mut buf = pool.allocate_buffer(0);

        // Write 3 entries in epoch 1, then advance.
        for i in 0..3_u64 {
            let epoch = mgr.stamp();
            buf.append_write(epoch, TxnId(i), BlockNumber(i), vec![0xAA; 32]);
            mgr.record_commit();
        }

        // Epoch should have advanced after 3rd commit.
        assert_eq!(mgr.current_epoch(), 2);

        // Write 2 more in epoch 2.
        for i in 3..5_u64 {
            let epoch = mgr.stamp();
            buf.append_write(epoch, TxnId(i), BlockNumber(i), vec![0xBB; 32]);
        }

        let entries = buf.drain();
        assert_eq!(entries.len(), 5);

        // First 3 in epoch 1, last 2 in epoch 2.
        assert!(entries[..3].iter().all(|e| e.epoch == 1));
        assert!(entries[3..].iter().all(|e| e.epoch == 2));

        // Mark epoch 1 as flushed.
        mgr.mark_epoch_flushed(1);
        assert!(mgr.is_durable(1));
        assert!(!mgr.is_durable(2));
    }

    // -- DurabilityNotifier tests --

    #[test]
    fn durability_notifier_starts_with_no_durable_epochs() {
        let notifier = DurabilityNotifier::new();
        assert_eq!(notifier.durable_epoch(), 0);
    }

    #[test]
    fn durability_notifier_immediate_return_if_already_durable() {
        let notifier = DurabilityNotifier::new();
        notifier.notify_durable(5);
        assert_eq!(notifier.durable_epoch(), 5);
        // All epochs <= 5 should return immediately.
        assert_eq!(notifier.await_epoch(1), DurabilityOutcome::Durable);
        assert_eq!(notifier.await_epoch(5), DurabilityOutcome::Durable);
    }

    #[test]
    fn durability_notifier_waiter_woken_on_notify() {
        let notifier = Arc::new(DurabilityNotifier::new());
        let (before_wait, handle) = spawn_observed_epoch_waiter(&notifier, 1);
        observe_waiter_parking(&before_wait);
        notifier.notify_durable(1);
        let outcome = handle.join().expect("no panic");
        assert_eq!(outcome, DurabilityOutcome::Durable);
    }

    #[test]
    fn durability_notifier_failure_wakes_waiters() {
        let notifier = Arc::new(DurabilityNotifier::new());
        let (before_wait, handle) = spawn_observed_epoch_waiter(&notifier, 1);
        observe_waiter_parking(&before_wait);
        notifier.notify_failed(1, "disk on fire".to_string());
        let outcome = handle.join().expect("no panic");
        assert_eq!(
            outcome,
            DurabilityOutcome::Failed("disk on fire".to_string())
        );
    }

    #[test]
    fn durability_notifier_keeps_lowest_failed_epoch() {
        let notifier = DurabilityNotifier::new();
        notifier.notify_failed(5, "late".to_string());
        notifier.notify_failed(3, "early".to_string());

        let outcome = notifier.await_epoch_timeout(4, std::time::Duration::from_millis(10));
        assert_eq!(
            outcome,
            Some(DurabilityOutcome::Failed("early".to_string()))
        );

        let none = notifier.await_epoch_timeout(2, std::time::Duration::from_millis(10));
        assert!(none.is_none());
    }

    #[test]
    fn durability_notifier_timeout_returns_failure_for_later_epoch() {
        let notifier = Arc::new(DurabilityNotifier::new());
        let (before_wait, handle) =
            spawn_observed_epoch_timeout_waiter(&notifier, 5, std::time::Duration::from_secs(1));
        observe_waiter_parking(&before_wait);
        notifier.notify_failed(3, "disk on fire".to_string());
        let outcome = handle.join().expect("no panic");
        assert_eq!(
            outcome,
            Some(DurabilityOutcome::Failed("disk on fire".to_string()))
        );
    }

    #[test]
    fn durability_notifier_timeout_returns_none() {
        let notifier = DurabilityNotifier::new();
        let result = notifier.await_epoch_timeout(1, std::time::Duration::from_millis(10));
        assert!(result.is_none());
    }

    #[test]
    fn durability_notifier_timeout_returns_result_if_resolved_in_time() {
        let notifier = Arc::new(DurabilityNotifier::new());
        let (before_wait, handle) =
            spawn_observed_epoch_timeout_waiter(&notifier, 1, std::time::Duration::from_secs(5));
        observe_waiter_parking(&before_wait);
        notifier.notify_durable(1);
        let result = handle.join().expect("no panic");
        assert_eq!(result, Some(DurabilityOutcome::Durable));
    }

    #[test]
    fn durability_notifier_multiple_waiters() {
        let notifier = Arc::new(DurabilityNotifier::new());
        let mut handles = Vec::new();
        let mut before_waits = Vec::new();

        for epoch in 1..=3_u64 {
            let (before_wait, handle) = spawn_observed_epoch_waiter(&notifier, epoch);
            before_waits.push(before_wait);
            handles.push(handle);
        }

        for before_wait in &before_waits {
            observe_waiter_parking(before_wait);
        }
        // Flush epoch 3 — wakes all waiters (1, 2, 3).
        notifier.notify_durable(3);

        for h in handles {
            assert_eq!(h.join().expect("no panic"), DurabilityOutcome::Durable);
        }
    }

    /// bd-lebu5 — Regression for DurabilityNotifier Invariant 2
    /// (predicate-loop on every wake).
    ///
    /// `notify_durable` calls `condvar.notify_all`, which wakes EVERY
    /// waiter regardless of the epoch they're awaiting. A waiter
    /// awaiting epoch 5 must NOT exit when `notify_durable(2)` fires —
    /// it must re-check `durable_epoch`, see that it's still < 5, and
    /// re-wait. A regression that converts `await_epoch`'s `loop` into
    /// a single-shot wait would silently let the lower-epoch
    /// notification release the higher-epoch waiter, which would then
    /// mis-trust an unrelated lower epoch as durable.
    ///
    /// The test:
    ///   1. spawns a waiter for epoch 5
    ///   2. fires `notify_durable(2)` — the waiter must remain blocked
    ///      (we observe this by checking `is_finished()` after a brief
    ///      settle)
    ///   3. fires `notify_durable(7)` — the waiter MUST then unblock
    ///      with `Durable`
    #[test]
    fn durability_notifier_lower_epoch_notification_does_not_wake_higher_epoch_waiter() {
        let notifier = Arc::new(DurabilityNotifier::new());
        let (before_wait, handle) = spawn_observed_epoch_waiter(&notifier, 5);

        observe_waiter_parking(&before_wait);

        // Fire a lower-epoch notification. Predicate (5 <= durable_epoch=2)
        // is FALSE, so the loop must re-wait.
        notifier.notify_durable(2);

        observe_waiter_parking(&before_wait);
        assert!(
            !handle.is_finished(),
            "waiter for epoch 5 must NOT exit on notify_durable(2) — \
             a regression that dropped the predicate-loop would let the \
             waiter return Durable while durable_epoch is only 2"
        );

        // Now fire a sufficient notification. Predicate becomes TRUE.
        notifier.notify_durable(7);

        let outcome = handle.join().expect("waiter joined");
        assert_eq!(
            outcome,
            DurabilityOutcome::Durable,
            "waiter must wake with Durable after notify_durable(7)"
        );
        assert_eq!(notifier.durable_epoch(), 7);
    }

    // -- Test WalWriter fixture for group commit tests --

    struct TestWalWriter {
        entries_written: Mutex<Vec<WalEntry>>,
        sync_results: Mutex<Vec<Result<(), std::io::Error>>>,
        write_fail: Mutex<bool>,
    }

    impl TestWalWriter {
        fn new() -> Self {
            Self {
                entries_written: Mutex::new(Vec::new()),
                sync_results: Mutex::new(Vec::new()),
                write_fail: Mutex::new(false),
            }
        }

        fn with_sync_results(results: Vec<Result<(), std::io::Error>>) -> Self {
            Self {
                entries_written: Mutex::new(Vec::new()),
                sync_results: Mutex::new(results),
                write_fail: Mutex::new(false),
            }
        }

        fn set_write_fail(&self, fail: bool) {
            *self.write_fail.lock().unwrap() = fail;
        }
    }

    impl WalWriter for TestWalWriter {
        fn write_entries(&self, entries: &[WalEntry]) -> Result<(), FfsError> {
            if *self.write_fail.lock().unwrap() {
                return Err(FfsError::Io(std::io::Error::other(
                    "injected write failure",
                )));
            }
            self.entries_written
                .lock()
                .unwrap()
                .extend(entries.iter().cloned());
            Ok(())
        }

        fn sync(&self) -> Result<(), FfsError> {
            let mut results = self.sync_results.lock().unwrap();
            if results.is_empty() {
                Ok(())
            } else {
                results.remove(0).map_err(FfsError::Io)
            }
        }
    }

    // -- GroupCommitCoordinator tests --

    fn make_group_commit_setup() -> (Arc<EpochManager>, Arc<DurabilityNotifier>) {
        let epoch_mgr = Arc::new(EpochManager::new(EpochManagerConfig {
            commit_threshold: 1_000_000,
            epoch_interval: std::time::Duration::from_secs(3600),
        }));
        let notifier = Arc::new(DurabilityNotifier::new());
        (epoch_mgr, notifier)
    }

    fn make_entries(epoch: u64, count: usize) -> Vec<WalEntry> {
        (0..count)
            .map(|i| WalEntry {
                epoch,
                txn_id: TxnId(i as u64),
                commit_seq: CommitSeq(0),
                entry_type: WalEntryType::Write {
                    block: BlockNumber(i as u64),
                    data: vec![0xAA; 64],
                },
                crc32c: crc32c::crc32c(&[0xAA; 64]),
            })
            .collect()
    }

    #[test]
    fn group_commit_flushes_epoch_entries() {
        let (epoch_mgr, notifier) = make_group_commit_setup();
        let writer = TestWalWriter::new();
        let coord = GroupCommitCoordinator::new(
            Arc::clone(&epoch_mgr),
            Arc::clone(&notifier),
            writer,
            GroupCommitConfig::default(),
        );

        let entries = make_entries(1, 5);
        let (result, remaining) = coord.flush_epoch(entries, 1).expect("flush");
        assert_eq!(result.epoch, 1);
        assert_eq!(result.entries_written, 5);
        assert_eq!(result.payload_bytes, 5 * 64);
        assert_eq!(result.fsyncs_issued, 1);
        assert!(remaining.is_empty());

        // Epoch 1 should now be durable.
        assert!(epoch_mgr.is_durable(1));
        assert_eq!(notifier.durable_epoch(), 1);
    }

    #[test]
    fn group_commit_partitions_by_epoch() {
        let (epoch_mgr, notifier) = make_group_commit_setup();
        let writer = TestWalWriter::new();
        let coord = GroupCommitCoordinator::new(
            Arc::clone(&epoch_mgr),
            Arc::clone(&notifier),
            writer,
            GroupCommitConfig::default(),
        );

        let mut entries = make_entries(1, 3);
        entries.extend(make_entries(2, 2));
        entries.extend(make_entries(3, 1));

        // Flush only epoch 1.
        let (result, remaining) = coord.flush_epoch(entries, 1).expect("flush");
        assert_eq!(result.entries_written, 3);
        assert_eq!(remaining.len(), 3); // epoch 2 + epoch 3 entries remain.
        assert!(remaining.iter().all(|e| e.epoch > 1));
    }

    #[test]
    fn group_commit_flushes_up_to_epoch() {
        let (epoch_mgr, notifier) = make_group_commit_setup();
        let writer = TestWalWriter::new();
        let coord = GroupCommitCoordinator::new(
            Arc::clone(&epoch_mgr),
            Arc::clone(&notifier),
            writer,
            GroupCommitConfig::default(),
        );

        let mut entries = make_entries(1, 2);
        entries.extend(make_entries(2, 3));
        entries.extend(make_entries(3, 1));

        // Flush epochs 1 and 2.
        let (result, remaining) = coord.flush_epoch(entries, 2).expect("flush");
        assert_eq!(result.entries_written, 5); // 2 + 3
        assert_eq!(remaining.len(), 1); // epoch 3 remains.
        assert!(epoch_mgr.is_durable(2));
    }

    #[test]
    fn group_commit_empty_epoch_is_ok() {
        let (epoch_mgr, notifier) = make_group_commit_setup();
        let writer = TestWalWriter::new();
        let coord = GroupCommitCoordinator::new(
            Arc::clone(&epoch_mgr),
            Arc::clone(&notifier),
            writer,
            GroupCommitConfig::default(),
        );

        let entries = Vec::new();
        let (result, remaining) = coord.flush_epoch(entries, 1).expect("flush");
        assert_eq!(result.entries_written, 0);
        assert_eq!(result.fsyncs_issued, 0);
        assert!(remaining.is_empty());
        assert!(epoch_mgr.is_durable(1));
    }

    #[test]
    fn group_commit_write_failure_notifies_waiters() {
        let (epoch_mgr, notifier) = make_group_commit_setup();
        let writer = TestWalWriter::new();
        writer.set_write_fail(true);
        let coord = GroupCommitCoordinator::new(
            Arc::clone(&epoch_mgr),
            Arc::clone(&notifier),
            writer,
            GroupCommitConfig::default(),
        );

        let entries = make_entries(1, 3);
        let err = coord.flush_epoch(entries, 1);
        assert!(err.is_err());

        // Epoch 1 should NOT be durable.
        assert!(!epoch_mgr.is_durable(1));
    }

    #[test]
    fn group_commit_sync_retries_then_succeeds() {
        let (epoch_mgr, notifier) = make_group_commit_setup();
        let writer = TestWalWriter::with_sync_results(vec![
            Err(std::io::Error::other("retry 1")),
            Err(std::io::Error::other("retry 2")),
            Ok(()),
        ]);
        let coord = GroupCommitCoordinator::new(
            Arc::clone(&epoch_mgr),
            Arc::clone(&notifier),
            writer,
            GroupCommitConfig { max_retries: 3 },
        );

        let entries = make_entries(1, 2);
        let (result, _) = coord.flush_epoch(entries, 1).expect("flush");
        assert_eq!(result.fsyncs_issued, 3); // 2 failures + 1 success
        assert!(epoch_mgr.is_durable(1));
    }

    #[test]
    fn group_commit_sync_exhaustion_notifies_failure() {
        let (epoch_mgr, notifier) = make_group_commit_setup();
        let writer = TestWalWriter::with_sync_results(vec![
            Err(std::io::Error::other("fail 1")),
            Err(std::io::Error::other("fail 2")),
        ]);
        let coord = GroupCommitCoordinator::new(
            Arc::clone(&epoch_mgr),
            Arc::clone(&notifier),
            writer,
            GroupCommitConfig { max_retries: 1 },
        );

        let entries = make_entries(1, 2);
        let err = coord.flush_epoch(entries, 1);
        assert!(err.is_err());
        assert!(!epoch_mgr.is_durable(1));
    }

    #[test]
    fn group_commit_wakes_concurrent_waiters() {
        let (epoch_mgr, notifier) = make_group_commit_setup();
        let writer = TestWalWriter::new();
        let coord = Arc::new(GroupCommitCoordinator::new(
            Arc::clone(&epoch_mgr),
            Arc::clone(&notifier),
            writer,
            GroupCommitConfig::default(),
        ));

        // Spawn waiters for epoch 1.
        let mut handles = Vec::new();
        let mut before_waits = Vec::new();
        for _ in 0..4 {
            let (before_wait, handle) = spawn_observed_epoch_waiter(&notifier, 1);
            before_waits.push(before_wait);
            handles.push(handle);
        }

        for before_wait in &before_waits {
            observe_waiter_parking(before_wait);
        }

        // Flush epoch 1.
        let entries = make_entries(1, 3);
        coord.flush_epoch(entries, 1).expect("flush");

        // All waiters should get Durable.
        for h in handles {
            assert_eq!(h.join().expect("no panic"), DurabilityOutcome::Durable);
        }
    }

    #[test]
    fn group_commit_sequential_epochs() {
        let (epoch_mgr, notifier) = make_group_commit_setup();
        let writer = TestWalWriter::new();
        let coord = GroupCommitCoordinator::new(
            Arc::clone(&epoch_mgr),
            Arc::clone(&notifier),
            writer,
            GroupCommitConfig::default(),
        );

        // Flush epoch 1.
        let entries = make_entries(1, 3);
        coord.flush_epoch(entries, 1).expect("flush epoch 1");
        assert!(epoch_mgr.is_durable(1));
        assert_eq!(notifier.durable_epoch(), 1);

        // Flush epoch 2.
        let entries = make_entries(2, 2);
        coord.flush_epoch(entries, 2).expect("flush epoch 2");
        assert!(epoch_mgr.is_durable(2));
        assert_eq!(notifier.durable_epoch(), 2);
    }

    #[test]
    fn group_commit_full_integration() {
        // End-to-end: multiple cores write, epoch advances, group commit flushes.
        let epoch_cfg = EpochManagerConfig {
            commit_threshold: 4,
            epoch_interval: std::time::Duration::from_secs(3600),
        };
        let epoch_mgr = Arc::new(EpochManager::new(epoch_cfg));
        let notifier = Arc::new(DurabilityNotifier::new());
        let writer = TestWalWriter::new();
        let coord = GroupCommitCoordinator::new(
            Arc::clone(&epoch_mgr),
            Arc::clone(&notifier),
            writer,
            GroupCommitConfig::default(),
        );

        let pool = ExplicitWalPool::new(WalBufferConfig::default());
        let mut buf0 = pool.allocate_buffer(0);
        let mut buf1 = pool.allocate_buffer(1);

        // 4 commits across 2 buffers in epoch 1.
        for i in 0..2_u64 {
            let epoch = epoch_mgr.stamp();
            buf0.append_write(epoch, TxnId(i), BlockNumber(i), vec![0x01; 32]);
            buf0.append_commit(epoch, TxnId(i), CommitSeq(i));
            epoch_mgr.record_commit();
        }
        for i in 2..4_u64 {
            let epoch = epoch_mgr.stamp();
            buf1.append_write(epoch, TxnId(i), BlockNumber(i), vec![0x02; 32]);
            buf1.append_commit(epoch, TxnId(i), CommitSeq(i));
            epoch_mgr.record_commit();
        }

        // Epoch should have advanced (4 commits at threshold 4).
        assert_eq!(epoch_mgr.current_epoch(), 2);

        // Drain all buffers.
        let (all_entries, flush_result) = pool.drain_all(&mut [buf0, buf1]);
        assert_eq!(flush_result.entries_flushed, 8); // 4 writes + 4 commits
        assert_eq!(flush_result.buffers_drained, 2);

        // Group commit epoch 1.
        let (gc_result, remaining) = coord.flush_epoch(all_entries, 1).expect("flush");
        assert_eq!(gc_result.epoch, 1);
        assert_eq!(gc_result.entries_written, 8);
        assert_eq!(gc_result.fsyncs_issued, 1);
        assert!(remaining.is_empty()); // All entries were epoch 1.
        assert!(epoch_mgr.is_durable(1));
        assert_eq!(notifier.durable_epoch(), 1);
    }

    // -- bd-2oah.5: Additional unit test coverage --

    #[test]
    fn recovery_replay_entries_arrive_in_epoch_order() {
        // Simulate recovery: drain 3 buffers with interleaved epochs,
        // verify drain_all produces entries sorted by epoch.
        let pool = ExplicitWalPool::new(WalBufferConfig::default());
        let mut bufs: Vec<CoreWalBuffer> = (0..3).map(|id| pool.allocate_buffer(id)).collect();

        // Core 0: epoch 3, epoch 1
        bufs[0].append_write(3, TxnId(10), BlockNumber(10), vec![0x33; 16]);
        bufs[0].append_write(1, TxnId(11), BlockNumber(11), vec![0x11; 16]);

        // Core 1: epoch 2, epoch 2
        bufs[1].append_write(2, TxnId(20), BlockNumber(20), vec![0x22; 16]);
        bufs[1].append_commit(2, TxnId(20), CommitSeq(1));

        // Core 2: epoch 1, epoch 3
        bufs[2].append_write(1, TxnId(30), BlockNumber(30), vec![0x11; 16]);
        bufs[2].append_write(3, TxnId(31), BlockNumber(31), vec![0x33; 16]);

        let (entries, result) = pool.drain_all(&mut bufs);
        assert_eq!(result.entries_flushed, 6);
        assert_eq!(result.buffers_drained, 3);

        // Verify strict epoch ordering: 1, 1, 2, 2, 3, 3
        let epochs: Vec<u64> = entries.iter().map(|e| e.epoch).collect();
        assert_eq!(epochs, vec![1, 1, 2, 2, 3, 3]);

        // Entries in epoch 1 should be from TxnId(11) and TxnId(30) (in some order).
        let epoch1_txns: Vec<u64> = entries
            .iter()
            .filter(|e| e.epoch == 1)
            .map(|e| e.txn_id.0)
            .collect();
        assert!(epoch1_txns.contains(&11));
        assert!(epoch1_txns.contains(&30));
    }

    #[test]
    fn epoch_boundary_consistent_across_all_cores() {
        // Verify that when epoch advances, new entries get the new epoch
        // while entries before the advance keep the old epoch.
        let epoch_mgr = Arc::new(EpochManager::new(EpochManagerConfig {
            commit_threshold: 2,
            epoch_interval: std::time::Duration::from_secs(3600),
        }));
        let pool = ExplicitWalPool::new(WalBufferConfig::default());
        let mut bufs: Vec<CoreWalBuffer> = (0..4).map(|id| pool.allocate_buffer(id)).collect();

        // All 4 cores write in epoch 1.
        for (i, buf) in bufs.iter_mut().enumerate() {
            let epoch = epoch_mgr.stamp();
            assert_eq!(epoch, 1);
            buf.append_write(
                epoch,
                TxnId(i as u64),
                BlockNumber(i as u64),
                vec![0xAA; 16],
            );
        }

        // 2 commits trigger epoch advance.
        epoch_mgr.record_commit();
        let advance = epoch_mgr.record_commit();
        assert!(advance.is_some());
        assert_eq!(epoch_mgr.current_epoch(), 2);

        // Now all 4 cores write in epoch 2.
        for (i, buf) in bufs.iter_mut().enumerate() {
            let epoch = epoch_mgr.stamp();
            assert_eq!(epoch, 2);
            buf.append_write(
                epoch,
                TxnId(100 + i as u64),
                BlockNumber(100 + i as u64),
                vec![0xBB; 16],
            );
        }

        // Drain and verify: 4 entries in epoch 1, 4 in epoch 2.
        let (entries, _) = pool.drain_all(&mut bufs);
        assert_eq!(entries.len(), 8);
        assert_eq!(entries.iter().filter(|e| e.epoch == 1).count(), 4);
        assert_eq!(entries.iter().filter(|e| e.epoch == 2).count(), 4);
    }

    #[test]
    fn group_commit_timeout_partial_flush() {
        // Simulate: epoch 1 entries are ready, epoch 2 entries are not yet
        // complete. Flush only epoch 1 (partial flush due to "timeout").
        let (epoch_mgr, notifier) = make_group_commit_setup();
        let writer = TestWalWriter::new();
        let coord = GroupCommitCoordinator::new(
            Arc::clone(&epoch_mgr),
            Arc::clone(&notifier),
            writer,
            GroupCommitConfig::default(),
        );

        // Mix of epoch 1 and epoch 2 entries.
        let mut entries = make_entries(1, 4);
        entries.extend(make_entries(2, 3));

        // Partial flush: only epoch 1 (simulating timeout-triggered partial commit).
        let (result, remaining) = coord.flush_epoch(entries, 1).expect("partial flush");
        assert_eq!(result.epoch, 1);
        assert_eq!(result.entries_written, 4);
        assert_eq!(remaining.len(), 3);
        assert!(remaining.iter().all(|e| e.epoch == 2));

        // Epoch 1 durable, epoch 2 not yet.
        assert!(epoch_mgr.is_durable(1));
        assert!(!epoch_mgr.is_durable(2));
        assert_eq!(notifier.durable_epoch(), 1);

        // Later: flush epoch 2 with remaining entries.
        let (result2, remaining2) = coord.flush_epoch(remaining, 2).expect("flush rest");
        assert_eq!(result2.entries_written, 3);
        assert!(remaining2.is_empty());
        assert!(epoch_mgr.is_durable(2));
    }

    #[test]
    fn aborted_txn_excluded_from_committed_entries() {
        // Verify that abort markers are preserved in the WAL stream but
        // can be identified and filtered during recovery.
        let pool = ExplicitWalPool::new(WalBufferConfig::default());
        let mut buf = pool.allocate_buffer(0);

        // Transaction 1: write + commit.
        buf.append_write(1, TxnId(1), BlockNumber(10), vec![0x01; 32]);
        buf.append_commit(1, TxnId(1), CommitSeq(1));

        // Transaction 2: write + abort (should be excluded on recovery).
        buf.append_write(1, TxnId(2), BlockNumber(20), vec![0x02; 32]);
        buf.append_abort(1, TxnId(2));

        // Transaction 3: write + commit.
        buf.append_write(1, TxnId(3), BlockNumber(30), vec![0x03; 32]);
        buf.append_commit(1, TxnId(3), CommitSeq(2));

        let entries = buf.drain();
        assert_eq!(entries.len(), 6);

        // Simulate recovery filtering: only committed txns.
        let committed_txns: std::collections::HashSet<u64> = entries
            .iter()
            .filter(|e| matches!(e.entry_type, WalEntryType::Commit))
            .map(|e| e.txn_id.0)
            .collect();
        let aborted_txns: std::collections::HashSet<u64> = entries
            .iter()
            .filter(|e| matches!(e.entry_type, WalEntryType::Abort))
            .map(|e| e.txn_id.0)
            .collect();

        assert!(committed_txns.contains(&1));
        assert!(committed_txns.contains(&3));
        assert!(!committed_txns.contains(&2));
        assert!(aborted_txns.contains(&2));

        // Only writes from committed txns should be replayed.
        let replay_writes: Vec<&WalEntry> = entries
            .iter()
            .filter(|e| {
                matches!(e.entry_type, WalEntryType::Write { .. })
                    && committed_txns.contains(&e.txn_id.0)
            })
            .collect();
        assert_eq!(replay_writes.len(), 2);
        assert_eq!(replay_writes[0].txn_id, TxnId(1));
        assert_eq!(replay_writes[1].txn_id, TxnId(3));
    }

    #[test]
    fn group_commit_concurrent_multi_epoch_pipeline() {
        // Simulate pipelined group commits: while epoch 1 is being flushed,
        // new entries are accumulating in epoch 2.
        let epoch_cfg = EpochManagerConfig {
            commit_threshold: 3,
            epoch_interval: std::time::Duration::from_secs(3600),
        };
        let epoch_mgr = Arc::new(EpochManager::new(epoch_cfg));
        let notifier = Arc::new(DurabilityNotifier::new());
        let writer = TestWalWriter::new();
        let coord = GroupCommitCoordinator::new(
            Arc::clone(&epoch_mgr),
            Arc::clone(&notifier),
            writer,
            GroupCommitConfig::default(),
        );

        let pool = ExplicitWalPool::new(WalBufferConfig::default());
        let mut buf = pool.allocate_buffer(0);

        // Phase 1: 3 commits in epoch 1 -> triggers advance to epoch 2.
        for i in 0..3_u64 {
            let epoch = epoch_mgr.stamp();
            buf.append_write(epoch, TxnId(i), BlockNumber(i), vec![0x01; 16]);
            buf.append_commit(epoch, TxnId(i), CommitSeq(i));
            epoch_mgr.record_commit();
        }
        assert_eq!(epoch_mgr.current_epoch(), 2);

        // Phase 2: New writes accumulate in epoch 2 (before epoch 1 is flushed).
        for i in 10..13_u64 {
            let epoch = epoch_mgr.stamp();
            buf.append_write(epoch, TxnId(i), BlockNumber(i), vec![0x02; 16]);
            buf.append_commit(epoch, TxnId(i), CommitSeq(i));
            epoch_mgr.record_commit();
        }
        assert_eq!(epoch_mgr.current_epoch(), 3);

        // Drain everything.
        let all_entries = buf.drain();
        assert_eq!(all_entries.len(), 12); // 6 in epoch 1 + 6 in epoch 2

        // Flush epoch 1 first.
        let (result1, remaining) = coord.flush_epoch(all_entries, 1).expect("flush 1");
        assert_eq!(result1.entries_written, 6);
        assert_eq!(remaining.len(), 6);
        assert!(epoch_mgr.is_durable(1));

        // Flush epoch 2.
        let (result2, remaining2) = coord.flush_epoch(remaining, 2).expect("flush 2");
        assert_eq!(result2.entries_written, 6);
        assert!(remaining2.is_empty());
        assert!(epoch_mgr.is_durable(2));
    }

    #[test]
    fn durability_notifier_failure_blocks_later_epochs() {
        // Epoch 1 fails — waiters for epoch 2 must also get Failed, because
        // the WAL is strictly monotonic and a hole in the log is a fatal error.
        let notifier = DurabilityNotifier::new();

        // Epoch 1 fails.
        notifier.notify_failed(1, "disk error".to_string());

        // Waiter for epoch 2 gets Failed (propagated forward from epoch 1).
        assert_eq!(
            notifier.await_epoch(2),
            DurabilityOutcome::Failed("disk error".to_string())
        );

        // Waiter for epoch 1 gets failure.
        assert_eq!(
            notifier.await_epoch(1),
            DurabilityOutcome::Failed("disk error".to_string())
        );
    }
}
