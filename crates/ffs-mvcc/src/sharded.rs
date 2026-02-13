//! Sharded MVCC version store for concurrent multi-writer access.
//!
//! [`ShardedMvccStore`] partitions block versions across multiple shards,
//! each with its own [`parking_lot::RwLock`].  Writers to different block
//! ranges proceed without contention.  The commit sequence is a global
//! [`AtomicU64`], lock-free for the common case.
//!
//! Snapshot lifecycle is managed externally via [`SnapshotRegistry`].

use crate::{BlockVersion, CommitError, CommittedTxnRecord, SnapshotRegistry, Transaction};
use ffs_types::{BlockNumber, CommitSeq, Snapshot, TxnId};
use parking_lot::RwLock;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, trace};

/// A single shard of the version store.
#[derive(Debug, Default)]
struct MvccShard {
    versions: BTreeMap<BlockNumber, Vec<BlockVersion>>,
    /// Per-shard SSI log.  Entries are kept here because SSI checks
    /// are per-block and shards are block-partitioned.
    ssi_log: Vec<CommittedTxnRecord>,
}

/// Thread-safe, sharded MVCC version store.
///
/// Blocks are assigned to shards via `block_number.0 as usize % shard_count`.
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
#[derive(Debug)]
pub struct ShardedMvccStore {
    shards: Vec<RwLock<MvccShard>>,
    shard_count: usize,
    next_txn: AtomicU64,
    next_commit: AtomicU64,
    /// Inline snapshot tracking (for callers who don't use SnapshotRegistry).
    active_snapshots: RwLock<BTreeMap<CommitSeq, u32>>,
}

impl ShardedMvccStore {
    /// Create a new sharded store with the given shard count.
    ///
    /// A reasonable default is `min(num_cpus, 64)`.
    #[must_use]
    pub fn new(shard_count: usize) -> Self {
        let shard_count = shard_count.max(1);
        info!(shard_count, "sharded_mvcc_store: initializing");
        let shards = (0..shard_count)
            .map(|_| RwLock::new(MvccShard::default()))
            .collect();
        Self {
            shards,
            shard_count,
            next_txn: AtomicU64::new(1),
            next_commit: AtomicU64::new(1),
            active_snapshots: RwLock::new(BTreeMap::new()),
        }
    }

    /// Number of shards.
    #[must_use]
    pub fn shard_count(&self) -> usize {
        self.shard_count
    }

    /// Map a block number to its shard index.
    #[inline]
    fn shard_index(&self, block: BlockNumber) -> usize {
        let shard_count_u64 = u64::try_from(self.shard_count).expect("shard_count must fit in u64");
        let rem = block.0 % shard_count_u64;
        usize::try_from(rem).expect("remainder must fit in usize")
    }

    /// The current snapshot (latest committed version).
    #[must_use]
    pub fn current_snapshot(&self) -> Snapshot {
        let high = self.next_commit.load(Ordering::SeqCst).saturating_sub(1);
        Snapshot {
            high: CommitSeq(high),
        }
    }

    /// Begin a new transaction at the current snapshot.
    pub fn begin(&self) -> Transaction {
        let id = TxnId(self.next_txn.fetch_add(1, Ordering::SeqCst));
        let snapshot = self.current_snapshot();
        Transaction::new(id, snapshot)
    }

    /// The latest commit sequence for a block (per-shard query).
    #[must_use]
    pub fn latest_commit_seq(&self, block: BlockNumber) -> CommitSeq {
        let shard_idx = self.shard_index(block);
        let shard = self.shards[shard_idx].read();
        shard
            .versions
            .get(&block)
            .and_then(|v| v.last())
            .map_or(CommitSeq(0), |v| v.commit_seq)
    }

    /// Read the version of `block` visible at `snapshot`.
    #[must_use]
    pub fn read_visible(&self, block: BlockNumber, snapshot: Snapshot) -> Option<Vec<u8>> {
        let shard_idx = self.shard_index(block);
        let shard = self.shards[shard_idx].read();
        shard.versions.get(&block).and_then(|versions| {
            versions
                .iter()
                .rev()
                .find(|v| v.commit_seq <= snapshot.high)
                .map(|v| v.bytes.clone())
        })
    }

    /// Commit a transaction with first-committer-wins (FCW) conflict detection.
    ///
    /// Shard locks are acquired in sorted order to prevent deadlocks.
    pub fn commit(&self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        if txn.write_set().is_empty() {
            // Read-only transaction: nothing to commit.
            return Ok(self.current_snapshot().high);
        }

        // Determine which shards are involved and sort for consistent ordering.
        let shard_indices = self.involved_shards(&txn);

        // Acquire write locks in sorted order.
        let mut shard_guards: Vec<(usize, parking_lot::RwLockWriteGuard<'_, MvccShard>)> =
            shard_indices
                .iter()
                .map(|&idx| (idx, self.shards[idx].write()))
                .collect();

        // FCW check across all shards.
        for &block in txn.write_set().keys() {
            let shard_idx = self.shard_index(block);
            let latest = shard_guards
                .iter()
                .find(|(idx, _)| *idx == shard_idx)
                .and_then(|(_, guard)| guard.versions.get(&block))
                .and_then(|v| v.last())
                .map_or(CommitSeq(0), |v| v.commit_seq);
            if latest > txn.snapshot().high {
                return Err(CommitError::Conflict {
                    block,
                    snapshot: txn.snapshot().high,
                    observed: latest,
                });
            }
        }

        // Allocate commit sequence (atomic, unique).
        let commit_seq = CommitSeq(self.next_commit.fetch_add(1, Ordering::SeqCst));

        trace!(
            commit_seq = commit_seq.0,
            shards_involved = shard_indices.len(),
            blocks_written = txn.write_set().len(),
            "sharded_commit"
        );

        // Write versions to shards.
        let txn_id = txn.id();
        for (block, bytes) in txn.into_writes() {
            let shard_idx = self.shard_index(block);
            let shard = shard_guards
                .iter_mut()
                .find(|(idx, _)| *idx == shard_idx)
                .map(|(_, guard)| guard)
                .expect("shard must be locked");
            shard.versions.entry(block).or_default().push(BlockVersion {
                block,
                commit_seq,
                writer: txn_id,
                bytes,
            });
        }

        Ok(commit_seq)
    }

    /// Commit with Serializable Snapshot Isolation (SSI) enforcement.
    pub fn commit_ssi(&self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        if txn.write_set().is_empty() {
            return Ok(self.current_snapshot().high);
        }

        // Determine all involved shards (writes + reads).
        let mut all_blocks: BTreeSet<usize> = BTreeSet::new();
        for block in txn.write_set().keys() {
            all_blocks.insert(self.shard_index(*block));
        }
        for block in txn.read_set().keys() {
            all_blocks.insert(self.shard_index(*block));
        }
        let shard_indices: Vec<usize> = all_blocks.into_iter().collect();

        let mut shard_guards: Vec<(usize, parking_lot::RwLockWriteGuard<'_, MvccShard>)> =
            shard_indices
                .iter()
                .map(|&idx| (idx, self.shards[idx].write()))
                .collect();

        // FCW check.
        for &block in txn.write_set().keys() {
            let shard_idx = self.shard_index(block);
            let latest = shard_guards
                .iter()
                .find(|(idx, _)| *idx == shard_idx)
                .and_then(|(_, guard)| guard.versions.get(&block))
                .and_then(|v| v.last())
                .map_or(CommitSeq(0), |v| v.commit_seq);
            if latest > txn.snapshot().high {
                return Err(CommitError::Conflict {
                    block,
                    snapshot: txn.snapshot().high,
                    observed: latest,
                });
            }
        }

        // SSI rw-antidependency check.
        for (&block, &read_version) in txn.read_set() {
            let shard_idx = self.shard_index(block);
            let shard = shard_guards
                .iter()
                .find(|(idx, _)| *idx == shard_idx)
                .map(|(_, guard)| guard)
                .expect("shard must be locked");
            for record in shard.ssi_log.iter().rev() {
                if record.commit_seq <= txn.snapshot().high {
                    break;
                }
                if record.write_set.contains(&block) {
                    return Err(CommitError::SsiConflict {
                        pivot_block: block,
                        read_version,
                        write_version: record.commit_seq,
                        concurrent_txn: record.txn_id,
                    });
                }
            }
        }

        // Allocate commit sequence.
        let commit_seq = CommitSeq(self.next_commit.fetch_add(1, Ordering::SeqCst));

        let txn_id = txn.id();
        let snapshot = txn.snapshot();
        let read_set = txn.read_set().clone();
        let write_keys: BTreeSet<BlockNumber> = txn.write_set().keys().copied().collect();

        // Write versions and SSI log entries per shard.
        for (block, bytes) in txn.into_writes() {
            let shard_idx = self.shard_index(block);
            let shard = shard_guards
                .iter_mut()
                .find(|(idx, _)| *idx == shard_idx)
                .map(|(_, guard)| guard)
                .expect("shard must be locked");
            shard.versions.entry(block).or_default().push(BlockVersion {
                block,
                commit_seq,
                writer: txn_id,
                bytes,
            });
        }

        // Add SSI log entry to all write-set shards.
        let ssi_record = CommittedTxnRecord {
            txn_id,
            commit_seq,
            snapshot,
            write_set: write_keys,
            read_set,
        };
        for (_, shard) in &mut shard_guards {
            shard.ssi_log.push(ssi_record.clone());
        }

        Ok(commit_seq)
    }

    // ── Snapshot tracking (inline, for compatibility) ────────────────────

    /// Register a snapshot as active (inline tracking).
    pub fn register_snapshot(&self, snapshot: Snapshot) {
        let mut active = self.active_snapshots.write();
        *active.entry(snapshot.high).or_insert(0) += 1;
    }

    /// Release a previously registered snapshot.
    pub fn release_snapshot(&self, snapshot: Snapshot) -> bool {
        let mut active = self.active_snapshots.write();
        active.get(&snapshot.high).copied().is_some_and(|count| {
            if count <= 1 {
                active.remove(&snapshot.high);
            } else {
                active.insert(snapshot.high, count - 1);
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
            .map(|c| *c as usize)
            .sum()
    }

    // ── GC / pruning ────────────────────────────────────────────────────

    /// Prune versions older than `watermark` across all shards.
    pub fn prune_versions_older_than(&self, watermark: CommitSeq) {
        for (idx, shard_lock) in self.shards.iter().enumerate() {
            let mut shard = shard_lock.write();
            for versions in shard.versions.values_mut() {
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
                    versions.drain(0..keep_from);
                }
            }
            // Prune SSI log for this shard too.
            shard.ssi_log.retain(|r| r.commit_seq > watermark);
            drop(shard);
            trace!(shard_idx = idx, watermark = watermark.0, "shard_pruned");
        }
    }

    /// Safe prune: use watermark from active snapshots.
    pub fn prune_safe(&self) -> CommitSeq {
        let wm = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        self.prune_versions_older_than(wm);
        debug!(watermark = wm.0, "prune_safe_sharded");
        wm
    }

    /// Safe prune using an external [`SnapshotRegistry`].
    pub fn prune_safe_with_registry(&self, registry: &SnapshotRegistry) -> CommitSeq {
        let wm = registry
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        self.prune_versions_older_than(wm);
        debug!(watermark = wm.0, "prune_safe_registry");
        wm
    }

    /// Total number of block versions across all shards.
    #[must_use]
    pub fn version_count(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.read().versions.values().map(Vec::len).sum::<usize>())
            .sum()
    }

    /// Number of distinct versioned blocks across all shards.
    #[must_use]
    pub fn block_count_versioned(&self) -> usize {
        self.shards.iter().map(|s| s.read().versions.len()).sum()
    }

    // ── Internals ───────────────────────────────────────────────────────

    /// Sorted, deduplicated shard indices touched by a transaction's writes.
    fn involved_shards(&self, txn: &Transaction) -> Vec<usize> {
        let mut indices: BTreeSet<usize> = BTreeSet::new();
        for block in txn.write_set().keys() {
            indices.insert(self.shard_index(*block));
        }
        indices.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_store(shards: usize) -> ShardedMvccStore {
        ShardedMvccStore::new(shards)
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
    fn fcw_conflict_same_block() {
        let store = make_store(4);
        let mut t1 = store.begin();
        let mut t2 = store.begin();

        t1.stage_write(BlockNumber(7), vec![1]);
        t2.stage_write(BlockNumber(7), vec![2]);

        store.commit(t1).expect("t1");
        let err = store.commit(t2).expect_err("t2 should conflict");
        assert!(matches!(err, CommitError::Conflict { .. }));
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
            matches!(result, Err(CommitError::SsiConflict { .. })),
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
                            Err(CommitError::Conflict { .. }) => {
                                // Expected under contention.
                            }
                            Err(e) => panic!("unexpected error: {e}"),
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
}
