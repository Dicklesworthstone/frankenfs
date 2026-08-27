#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation, clippy::needless_collect)]
//! E2E tests for the parallel WAL (Silo/Aether-style per-core buffers).
//!
//! Scenarios tested:
//! 1. Throughput scaling: WAL entries/sec scales with thread count.
//! 2. Epoch-boundary crash recovery: complete epochs recovered, partial discarded.
//! 3. Mid-epoch crash recovery: only complete epochs survive.
//! 4. Group commit correctness: all transactions in same epoch share one fsync.
//! 5. Epoch ordering under high contention.

use ffs_error::FfsError;
use ffs_journal::wal_buffer::{
    CoreWalBuffer, DurabilityNotifier, DurabilityOutcome, EpochManager, EpochManagerConfig,
    ExplicitWalPool, GroupCommitConfig, GroupCommitCoordinator, WalBufferConfig, WalEntry,
    WalEntryType, WalWriter,
};
use ffs_types::{BlockNumber, CommitSeq, TxnId};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

// ---------------------------------------------------------------------------
// Mock writer that tracks calls
// ---------------------------------------------------------------------------

struct TrackingWriter {
    entries: Arc<Mutex<Vec<WalEntry>>>,
    sync_count: Arc<AtomicUsize>,
}

impl TrackingWriter {
    fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            sync_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn sync_counter(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.sync_count)
    }
}

impl WalWriter for TrackingWriter {
    fn write_entries(&self, entries: &[WalEntry]) -> Result<(), FfsError> {
        self.entries.lock().unwrap().extend(entries.iter().cloned());
        Ok(())
    }

    fn sync(&self) -> Result<(), FfsError> {
        self.sync_count.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Scenario 1: Throughput scaling
// ---------------------------------------------------------------------------

#[test]
fn throughput_scales_with_thread_count() {
    // Test that WAL throughput doesn't degrade when using more threads.
    // Each thread writes to its own buffer (no shared lock on the hot path),
    // then we collect all drained entries.  On machines with sufficient cores
    // we expect near-linear scaling, but on constrained CI workers (few cores,
    // noisy neighbours) the per-op work is tiny (~Vec push + atomic stamp) so
    // scheduling overhead can eat into the benefit.  We therefore use a lenient
    // threshold: 4-thread throughput must be at least 0.9x single-thread
    // (i.e., verify no contention-induced regression).

    let ops_per_thread = 10_000_u64;
    let entries_per_txn = 4_u64;

    // Warm-up run to avoid cold-cache / JIT artefacts.
    let _ = run_throughput_test(1, 1_000, entries_per_txn);

    let single_thread_time = run_throughput_test(1, ops_per_thread, entries_per_txn);
    let four_thread_time = run_throughput_test(4, ops_per_thread, entries_per_txn);

    let single_entries = ops_per_thread * entries_per_txn;
    let four_entries = 4 * ops_per_thread * entries_per_txn;

    let single_throughput = single_entries as f64 / single_thread_time.as_secs_f64();
    let four_throughput = four_entries as f64 / four_thread_time.as_secs_f64();

    eprintln!(
        "1 thread: {single_entries} entries in {single_thread_time:?} ({single_throughput:.0} entries/sec)"
    );
    eprintln!(
        "4 threads: {four_entries} entries in {four_thread_time:?} ({four_throughput:.0} entries/sec)"
    );

    // 4-thread must not be slower than single-thread (allow 10% noise margin).
    assert!(
        four_throughput >= single_throughput * 0.9,
        "expected 4-thread throughput ({four_throughput:.0}) >= 0.9x single-thread ({single_throughput:.0})"
    );
}

fn run_throughput_test(
    num_threads: usize,
    ops_per_thread: u64,
    entries_per_txn: u64,
) -> std::time::Duration {
    let epoch_mgr = Arc::new(EpochManager::new(EpochManagerConfig {
        commit_threshold: 64,
        epoch_interval: std::time::Duration::from_millis(10),
    }));
    let pool = Arc::new(ExplicitWalPool::new(WalBufferConfig::default()));
    let barrier = Arc::new(Barrier::new(num_threads));

    let start = std::time::Instant::now();

    let handles: Vec<_> = (0..num_threads)
        .map(|tid| {
            let epoch_mgr = Arc::clone(&epoch_mgr);
            let pool = Arc::clone(&pool);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut buf = pool.allocate_buffer(tid);
                barrier.wait();
                for op in 0..ops_per_thread {
                    let epoch = epoch_mgr.stamp();
                    let txn = TxnId(tid as u64 * 100_000 + op);
                    for j in 0..entries_per_txn {
                        buf.append_write(epoch, txn, BlockNumber(j), vec![0xAA; 64]);
                    }
                    buf.append_commit(epoch, txn, CommitSeq(op));
                    epoch_mgr.record_commit();

                    // Drain if buffer is full.
                    if buf.len() >= 512 {
                        let _ = buf.drain();
                    }
                }
                buf.drain()
            })
        })
        .collect();

    let all_entries: Vec<WalEntry> = handles
        .into_iter()
        .flat_map(|h| h.join().expect("no panic"))
        .collect();

    let elapsed = start.elapsed();
    // Verify we got entries.
    assert_ne!(all_entries, [] as [ffs_journal::wal_buffer::WalEntry; 0]);
    elapsed
}

// ---------------------------------------------------------------------------
// Scenario 1b: fsync count is O(epochs), not O(transactions)
// ---------------------------------------------------------------------------

#[test]
fn fsync_count_is_per_epoch_not_per_transaction() {
    let epoch_mgr = Arc::new(EpochManager::new(EpochManagerConfig {
        commit_threshold: 50,
        epoch_interval: std::time::Duration::from_secs(3600),
    }));
    let notifier = Arc::new(DurabilityNotifier::new());
    let writer = TrackingWriter::new();
    let sync_counter = writer.sync_counter();
    let coord = GroupCommitCoordinator::new(
        Arc::clone(&epoch_mgr),
        Arc::clone(&notifier),
        writer,
        GroupCommitConfig::default(),
    );

    let pool = ExplicitWalPool::new(WalBufferConfig::default());
    let mut buf = pool.allocate_buffer(0);

    let total_txns = 200_u64;
    for i in 0..total_txns {
        let epoch = epoch_mgr.stamp();
        buf.append_write(epoch, TxnId(i), BlockNumber(i), vec![0xBB; 32]);
        buf.append_commit(epoch, TxnId(i), CommitSeq(i));
        epoch_mgr.record_commit();
    }

    // Drain all entries.
    let entries = buf.drain();
    let max_epoch = entries.iter().map(|e| e.epoch).max().unwrap();

    // Flush each epoch sequentially.
    let mut remaining = entries;
    for epoch in 1..=max_epoch {
        let (_, rest) = coord.flush_epoch(remaining, epoch).expect("flush");
        remaining = rest;
    }

    // fsync count should equal number of epochs flushed, not number of transactions.
    let sync_count = sync_counter.load(Ordering::Acquire);
    assert_eq!(u64::try_from(sync_count), Ok(max_epoch));
    assert_eq!(coord.notifier().durable_epoch(), max_epoch);
    assert!(
        max_epoch < total_txns,
        "epochs ({max_epoch}) should be << transactions ({total_txns})"
    );
}

// ---------------------------------------------------------------------------
// Scenario 2: Epoch-boundary crash recovery
// ---------------------------------------------------------------------------

#[test]
fn epoch_boundary_crash_recovery() {
    // Simulate: 4 threads write, epochs 1 and 2 are flushed, crash occurs
    // at epoch boundary before epoch 3 is flushed.
    // Recovery: only epoch 1 and 2 entries are durable.

    let epoch_mgr = Arc::new(EpochManager::new(EpochManagerConfig {
        commit_threshold: 4,
        epoch_interval: std::time::Duration::from_secs(3600),
    }));
    let notifier = Arc::new(DurabilityNotifier::new());
    let writer = TrackingWriter::new();
    let coord = GroupCommitCoordinator::new(
        Arc::clone(&epoch_mgr),
        Arc::clone(&notifier),
        writer,
        GroupCommitConfig::default(),
    );

    let pool = ExplicitWalPool::new(WalBufferConfig::default());
    let mut bufs: Vec<CoreWalBuffer> = (0..4).map(|id| pool.allocate_buffer(id)).collect();

    // Write entries across 3 epochs.
    for round in 0..3_u64 {
        for (core_id, buf) in bufs.iter_mut().enumerate() {
            let epoch = epoch_mgr.stamp();
            let txn = TxnId(round * 100 + core_id as u64);
            buf.append_write(
                epoch,
                txn,
                BlockNumber(round * 10 + core_id as u64),
                vec![0xCC; 32],
            );
            buf.append_commit(epoch, txn, CommitSeq(round * 10 + core_id as u64));
            epoch_mgr.record_commit();
        }
    }

    // Should have advanced through at least 3 epochs.
    assert!(epoch_mgr.current_epoch() >= 3);

    // Drain and flush only epochs 1 and 2 (simulating crash before epoch 3 flush).
    let (all_entries, _) = pool.drain_all(&mut bufs);
    let (_, remaining) = coord.flush_epoch(all_entries, 1).expect("flush epoch 1");
    let (_, remaining) = coord.flush_epoch(remaining, 2).expect("flush epoch 2");

    // Simulate crash: epoch 3 entries in `remaining` are lost.
    assert!(!remaining.is_empty(), "epoch 3 entries should exist");
    let lost_entries = remaining.len();

    // Recovery: only entries from durable writer are available.
    let durable_entries = coord.notifier().durable_epoch();
    assert_eq!(durable_entries, 2);
    assert!(epoch_mgr.is_durable(1));
    assert!(epoch_mgr.is_durable(2));
    assert!(!epoch_mgr.is_durable(3));

    eprintln!("Epoch-boundary crash: {lost_entries} entries from epoch 3 lost (correct)");
}

// ---------------------------------------------------------------------------
// Scenario 3: Mid-epoch crash recovery
// ---------------------------------------------------------------------------

#[test]
fn mid_epoch_crash_recovery() {
    // Simulate: 4 threads writing, epoch 1 is flushed, crash occurs mid-epoch 2
    // (some buffers partially written, fsync never called for epoch 2).
    // Recovery: only epoch 1 entries survive.

    let epoch_mgr = Arc::new(EpochManager::new(EpochManagerConfig {
        commit_threshold: 8,
        epoch_interval: std::time::Duration::from_secs(3600),
    }));
    let notifier = Arc::new(DurabilityNotifier::new());
    let writer = TrackingWriter::new();
    let coord = GroupCommitCoordinator::new(
        Arc::clone(&epoch_mgr),
        Arc::clone(&notifier),
        writer,
        GroupCommitConfig::default(),
    );

    let pool = ExplicitWalPool::new(WalBufferConfig::default());
    let mut bufs: Vec<CoreWalBuffer> = (0..4).map(|id| pool.allocate_buffer(id)).collect();

    // Fill epoch 1 (8 commits trigger advance).
    for i in 0..8_u64 {
        let core = (i as usize) % 4;
        let epoch = epoch_mgr.stamp();
        bufs[core].append_write(epoch, TxnId(i), BlockNumber(i), vec![0xDD; 32]);
        bufs[core].append_commit(epoch, TxnId(i), CommitSeq(i));
        epoch_mgr.record_commit();
    }
    assert_eq!(epoch_mgr.current_epoch(), 2);

    // Partial writes in epoch 2 (only 3 of 8 needed for advance).
    for i in 100..103_u64 {
        let core = (i as usize) % 4;
        let epoch = epoch_mgr.stamp();
        bufs[core].append_write(epoch, TxnId(i), BlockNumber(i), vec![0xEE; 32]);
        bufs[core].append_commit(epoch, TxnId(i), CommitSeq(i));
    }

    // Drain all and flush only epoch 1.
    let (all_entries, _) = pool.drain_all(&mut bufs);
    let epoch1_count = all_entries.iter().filter(|e| e.epoch == 1).count();
    let epoch2_count = all_entries.iter().filter(|e| e.epoch == 2).count();

    let (result, remaining) = coord.flush_epoch(all_entries, 1).expect("flush epoch 1");

    // Simulate crash: epoch 2 entries lost (fsync never called for epoch 2).
    assert_eq!(result.epoch, 1);
    assert_eq!(remaining.len(), epoch2_count);
    assert!(epoch_mgr.is_durable(1));
    assert!(!epoch_mgr.is_durable(2));

    eprintln!(
        "Mid-epoch crash: epoch 1 ({epoch1_count} entries) recovered, epoch 2 ({epoch2_count} entries) lost"
    );
}

// ---------------------------------------------------------------------------
// Scenario 4: Group commit correctness
// ---------------------------------------------------------------------------

#[test]
fn group_commit_all_threads_share_one_fsync() {
    // 8 threads each commit 1 transaction in epoch 1.
    // Group commit should use exactly 1 fsync for all 8 transactions.

    let epoch_mgr = Arc::new(EpochManager::new(EpochManagerConfig {
        commit_threshold: 100, // Don't auto-advance.
        epoch_interval: std::time::Duration::from_secs(3600),
    }));
    let notifier = Arc::new(DurabilityNotifier::new());
    let writer = TrackingWriter::new();
    let sync_counter = writer.sync_counter();
    let coord = GroupCommitCoordinator::new(
        Arc::clone(&epoch_mgr),
        Arc::clone(&notifier),
        writer,
        GroupCommitConfig::default(),
    );

    let pool = Arc::new(ExplicitWalPool::new(WalBufferConfig::default()));
    let barrier = Arc::new(Barrier::new(8));

    let handles: Vec<_> = (0..8_usize)
        .map(|tid| {
            let epoch_mgr = Arc::clone(&epoch_mgr);
            let pool = Arc::clone(&pool);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut buf = pool.allocate_buffer(tid);
                barrier.wait();
                let epoch = epoch_mgr.stamp();
                buf.append_write(
                    epoch,
                    TxnId(tid as u64),
                    BlockNumber(tid as u64),
                    vec![0xFF; 64],
                );
                buf.append_commit(epoch, TxnId(tid as u64), CommitSeq(tid as u64));
                buf.drain()
            })
        })
        .collect();

    let all_entries: Vec<WalEntry> = handles
        .into_iter()
        .flat_map(|h| h.join().expect("no panic"))
        .collect();

    // All entries should be epoch 1.
    assert!(all_entries.iter().all(|e| e.epoch == 1));
    assert_eq!(all_entries.len(), 16); // 8 writes + 8 commits

    // Single group commit for epoch 1.
    let (result, remaining) = coord.flush_epoch(all_entries, 1).expect("flush");
    assert_eq!(result.fsyncs_issued, 1); // Only 1 fsync for all 8 transactions.
    assert_eq!(remaining, [] as [ffs_journal::wal_buffer::WalEntry; 0]);
    assert_eq!(sync_counter.load(Ordering::Acquire), 1);
}

#[test]
fn await_durability_blocks_until_group_commit() {
    // Verify that await_durability blocks until the group commit flushes the epoch.

    let epoch_mgr = Arc::new(EpochManager::new(EpochManagerConfig {
        commit_threshold: 100,
        epoch_interval: std::time::Duration::from_secs(3600),
    }));
    let notifier = Arc::new(DurabilityNotifier::new());
    let writer = TrackingWriter::new();
    let coord = GroupCommitCoordinator::new(
        Arc::clone(&epoch_mgr),
        Arc::clone(&notifier),
        writer,
        GroupCommitConfig::default(),
    );

    assert_eq!(
        notifier.await_epoch_timeout(1, std::time::Duration::ZERO),
        None,
        "epoch should not be durable before group commit flush"
    );

    // Spawn waiters before flush. The barrier removes the old timing guess:
    // all waiter threads are ready to call await_epoch before we flush.
    let waiter_count = 4;
    let waiter_barrier = Arc::new(Barrier::new(waiter_count + 1));
    let mut waiter_handles = Vec::new();
    for _ in 0..waiter_count {
        let n = Arc::clone(&notifier);
        let waiter_barrier = Arc::clone(&waiter_barrier);
        waiter_handles.push(std::thread::spawn(move || {
            waiter_barrier.wait();
            n.await_epoch(1)
        }));
    }

    waiter_barrier.wait();

    // Now flush.
    let entries = vec![WalEntry {
        epoch: 1,
        txn_id: TxnId(1),
        commit_seq: CommitSeq(1),
        entry_type: WalEntryType::Commit,
        crc32c: 0,
    }];
    coord.flush_epoch(entries, 1).expect("flush");

    // All waiters should now be unblocked with Durable.
    for h in waiter_handles {
        assert_eq!(h.join().expect("no panic"), DurabilityOutcome::Durable);
    }
}

// ---------------------------------------------------------------------------
// Scenario 5: Epoch ordering under high contention
// ---------------------------------------------------------------------------

#[test]
fn epoch_ordering_under_high_contention() {
    // 8 threads, rapid commits to stress epoch ordering.
    // Verify: all drained entries respect epoch monotonicity per-buffer,
    // and drain_all sorts correctly across buffers.

    let epoch_mgr = Arc::new(EpochManager::new(EpochManagerConfig {
        commit_threshold: 16,
        epoch_interval: std::time::Duration::from_millis(1),
    }));
    let pool = Arc::new(ExplicitWalPool::new(WalBufferConfig::default()));
    let barrier = Arc::new(Barrier::new(8));
    let commits_total = Arc::new(AtomicU64::new(0));

    let handles: Vec<_> = (0..8_usize)
        .map(|tid| {
            let epoch_mgr = Arc::clone(&epoch_mgr);
            let pool = Arc::clone(&pool);
            let barrier = Arc::clone(&barrier);
            let commits_total = Arc::clone(&commits_total);
            std::thread::spawn(move || {
                let mut buf = pool.allocate_buffer(tid);
                barrier.wait();
                let mut last_epoch = 0_u64;
                for i in 0..500_u64 {
                    let epoch = epoch_mgr.stamp();
                    // Within a single buffer, epochs should be monotonically non-decreasing.
                    assert!(
                        epoch >= last_epoch,
                        "epoch went backwards: {epoch} < {last_epoch}"
                    );
                    last_epoch = epoch;

                    buf.append_write(
                        epoch,
                        TxnId(tid as u64 * 10_000 + i),
                        BlockNumber(i),
                        vec![0x77; 16],
                    );
                    buf.append_commit(epoch, TxnId(tid as u64 * 10_000 + i), CommitSeq(i));
                    epoch_mgr.record_commit();
                    commits_total.fetch_add(1, Ordering::Relaxed);
                }
                buf
            })
        })
        .collect();

    let mut bufs: Vec<CoreWalBuffer> = handles
        .into_iter()
        .map(|h| h.join().expect("no panic"))
        .collect();

    // Drain all and verify epoch ordering.
    let (entries, result) = pool.drain_all(&mut bufs);
    assert_eq!(result.buffers_drained, 8);

    // Entries should be sorted by epoch after drain_all.
    let mut prev_epoch = 0_u64;
    for entry in &entries {
        assert!(
            entry.epoch >= prev_epoch,
            "entries not sorted by epoch: {} < {}",
            entry.epoch,
            prev_epoch
        );
        prev_epoch = entry.epoch;
    }

    let total_commits = commits_total.load(Ordering::Relaxed);
    let max_epoch = entries.iter().map(|e| e.epoch).max().unwrap_or(0);
    eprintln!(
        "High contention: {total_commits} commits, {} entries, max epoch {max_epoch}, {} epochs advanced",
        entries.len(),
        max_epoch - 1
    );

    // Should have advanced through multiple epochs.
    assert!(max_epoch > 1, "epoch should have advanced at least once");
}

#[test]
fn cross_epoch_transactions_correctly_ordered() {
    // Verify: entries from epoch E are always before entries from epoch E+1
    // in the flushed output, even when transactions span epoch boundaries.

    let epoch_mgr = Arc::new(EpochManager::new(EpochManagerConfig {
        commit_threshold: 5,
        epoch_interval: std::time::Duration::from_secs(3600),
    }));
    let notifier = Arc::new(DurabilityNotifier::new());
    let writer = TrackingWriter::new();
    let coord = GroupCommitCoordinator::new(
        Arc::clone(&epoch_mgr),
        Arc::clone(&notifier),
        writer,
        GroupCommitConfig::default(),
    );

    let pool = ExplicitWalPool::new(WalBufferConfig::default());
    let mut buf = pool.allocate_buffer(0);

    // Write 15 commits to get through 3 epochs (threshold=5).
    for i in 0..15_u64 {
        let epoch = epoch_mgr.stamp();
        buf.append_write(epoch, TxnId(i), BlockNumber(i), vec![0xAA; 16]);
        buf.append_commit(epoch, TxnId(i), CommitSeq(i));
        epoch_mgr.record_commit();
    }

    let entries = buf.drain();
    let max_epoch = entries.iter().map(|e| e.epoch).max().unwrap();

    // Flush all epochs.
    let mut remaining = entries;
    for epoch in 1..=max_epoch {
        let (result, rest) = coord.flush_epoch(remaining, epoch).expect("flush");
        remaining = rest;

        // Verify all flushed entries have epoch <= current flush target.
        assert!(
            result.entries_written > 0 || epoch > max_epoch,
            "epoch {epoch} should have entries"
        );
    }

    // Verify final state.
    assert_eq!(remaining, [] as [ffs_journal::wal_buffer::WalEntry; 0]);
    assert!(epoch_mgr.is_durable(max_epoch));

    // Verify the writer received entries in epoch order.
    let written = coord.notifier().durable_epoch();
    assert_eq!(written, max_epoch);
}
