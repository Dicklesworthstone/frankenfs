#![forbid(unsafe_code)]

use asupersync::Cx;
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::FfsError;
use ffs_types::{BlockNumber, CommitSeq, Snapshot, TxnId};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockVersion {
    pub block: BlockNumber,
    pub commit_seq: CommitSeq,
    pub writer: TxnId,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub id: TxnId,
    pub snapshot: Snapshot,
    writes: BTreeMap<BlockNumber, Vec<u8>>,
}

impl Transaction {
    pub fn stage_write(&mut self, block: BlockNumber, bytes: Vec<u8>) {
        self.writes.insert(block, bytes);
    }

    #[must_use]
    pub fn staged_write(&self, block: BlockNumber) -> Option<&[u8]> {
        self.writes.get(&block).map(Vec::as_slice)
    }

    #[must_use]
    pub fn pending_writes(&self) -> usize {
        self.writes.len()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommitError {
    #[error(
        "first-committer-wins conflict on block {block}: snapshot={snapshot:?}, observed={observed:?}"
    )]
    Conflict {
        block: BlockNumber,
        snapshot: CommitSeq,
        observed: CommitSeq,
    },
}

#[derive(Debug, Clone, Default)]
pub struct MvccStore {
    next_txn: u64,
    next_commit: u64,
    versions: BTreeMap<BlockNumber, Vec<BlockVersion>>,
}

impl MvccStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_txn: 1,
            next_commit: 1,
            versions: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn current_snapshot(&self) -> Snapshot {
        let high = self.next_commit.saturating_sub(1);
        Snapshot {
            high: CommitSeq(high),
        }
    }

    pub fn begin(&mut self) -> Transaction {
        let txn = Transaction {
            id: TxnId(self.next_txn),
            snapshot: self.current_snapshot(),
            writes: BTreeMap::new(),
        };
        self.next_txn = self.next_txn.saturating_add(1);
        txn
    }

    pub fn commit(&mut self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        for block in txn.writes.keys() {
            let latest = self.latest_commit_seq(*block);
            if latest > txn.snapshot.high {
                return Err(CommitError::Conflict {
                    block: *block,
                    snapshot: txn.snapshot.high,
                    observed: latest,
                });
            }
        }

        let commit_seq = CommitSeq(self.next_commit);
        self.next_commit = self.next_commit.saturating_add(1);

        for (block, bytes) in txn.writes {
            self.versions.entry(block).or_default().push(BlockVersion {
                block,
                commit_seq,
                writer: txn.id,
                bytes,
            });
        }

        Ok(commit_seq)
    }

    #[must_use]
    pub fn latest_commit_seq(&self, block: BlockNumber) -> CommitSeq {
        self.versions
            .get(&block)
            .and_then(|v| v.last())
            .map_or(CommitSeq(0), |v| v.commit_seq)
    }

    #[must_use]
    pub fn read_visible(&self, block: BlockNumber, snapshot: Snapshot) -> Option<&[u8]> {
        self.versions.get(&block).and_then(|versions| {
            versions
                .iter()
                .rev()
                .find(|v| v.commit_seq <= snapshot.high)
                .map(|v| v.bytes.as_slice())
        })
    }

    pub fn prune_versions_older_than(&mut self, watermark: CommitSeq) {
        for versions in self.versions.values_mut() {
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
    }
}

/// Snapshot-aware block device wrapper.
///
/// Reads check the `MvccStore` for a version visible at the configured
/// snapshot before falling back to the base device.  Writes stage data
/// into the version store immediately (write-through to the base device
/// is deferred to commit time).
///
/// # Concurrency
///
/// The `MvccStore` is behind a `parking_lot::RwLock`:
/// - **Reads** acquire a shared (`read`) lock — many concurrent readers.
/// - **Writes/commits** acquire an exclusive (`write`) lock.
/// - The base device read (fallback path) happens **outside** the lock.
#[derive(Debug)]
pub struct MvccBlockDevice<D: BlockDevice> {
    base: D,
    store: Arc<RwLock<MvccStore>>,
    snapshot: Snapshot,
}

impl<D: BlockDevice> MvccBlockDevice<D> {
    /// Create a new MVCC block device at a given snapshot.
    ///
    /// The `store` is shared across all devices/transactions that
    /// participate in the same MVCC group.
    pub fn new(base: D, store: Arc<RwLock<MvccStore>>, snapshot: Snapshot) -> Self {
        Self {
            base,
            store,
            snapshot,
        }
    }

    /// The snapshot this device reads at.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot
    }

    /// Shared reference to the MVCC store.
    #[must_use]
    pub fn store(&self) -> &Arc<RwLock<MvccStore>> {
        &self.store
    }

    /// Reference to the underlying base device.
    #[must_use]
    pub fn base(&self) -> &D {
        &self.base
    }
}

impl<D: BlockDevice> BlockDevice for MvccBlockDevice<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> ffs_error::Result<BlockBuf> {
        // Check version store first (shared lock, no I/O).
        {
            let guard = self.store.read();
            if let Some(bytes) = guard.read_visible(block, self.snapshot) {
                return Ok(BlockBuf::new(bytes.to_vec()));
            }
        }
        // Fall back to base device (no lock held).
        self.base.read_block(cx, block)
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> ffs_error::Result<()> {
        // Stage into a new single-block transaction and commit immediately.
        // For batched writes, callers should use the MvccStore API directly.
        let mut guard = self.store.write();
        let mut txn = guard.begin();
        txn.stage_write(block, data.to_vec());
        guard
            .commit(txn)
            .map_err(|e| FfsError::Format(e.to_string()))?;
        drop(guard);
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.base.block_size()
    }

    fn block_count(&self) -> u64 {
        self.base.block_count()
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        self.base.sync(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Simple in-memory block device for testing `MvccBlockDevice`.
    #[derive(Debug)]
    struct MemBlockDevice {
        blocks: parking_lot::RwLock<HashMap<BlockNumber, Vec<u8>>>,
        block_size: u32,
        block_count: u64,
    }

    impl MemBlockDevice {
        fn new(block_size: u32, block_count: u64) -> Self {
            Self {
                blocks: parking_lot::RwLock::new(HashMap::new()),
                block_size,
                block_count,
            }
        }
    }

    impl BlockDevice for MemBlockDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> ffs_error::Result<BlockBuf> {
            let bs = usize::try_from(self.block_size)
                .map_err(|_| FfsError::Format("block_size overflow".to_owned()))?;
            let data = self
                .blocks
                .read()
                .get(&block)
                .cloned()
                .unwrap_or_else(|| vec![0_u8; bs]);
            Ok(BlockBuf::new(data))
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

    fn test_cx() -> Cx {
        Cx::for_testing()
    }

    #[test]
    fn visibility_and_fcw_conflict() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        let mut t2 = store.begin();

        t1.stage_write(BlockNumber(7), vec![1, 2, 3]);
        t2.stage_write(BlockNumber(7), vec![9, 9, 9]);

        let c1 = store.commit(t1).expect("t1 commit");
        assert_eq!(c1, CommitSeq(1));

        let err = store.commit(t2).expect_err("t2 should conflict");
        match err {
            CommitError::Conflict { block, .. } => assert_eq!(block, BlockNumber(7)),
        }
    }

    #[test]
    fn read_snapshot_visibility() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        t1.stage_write(BlockNumber(1), vec![1]);
        let _ = store.commit(t1).expect("commit t1");

        let snap = store.current_snapshot();

        let mut t2 = store.begin();
        t2.stage_write(BlockNumber(1), vec![2]);
        let _ = store.commit(t2).expect("commit t2");

        let visible = store
            .read_visible(BlockNumber(1), snap)
            .expect("visible data at snap");
        assert_eq!(visible, &[1]);
    }

    // ── MvccBlockDevice tests ────────────────────────────────────────────

    #[test]
    fn mvcc_device_read_falls_back_to_base() {
        let cx = test_cx();
        let base = MemBlockDevice::new(512, 16);
        // Pre-populate block 3 in base device.
        base.write_block(&cx, BlockNumber(3), &[0xAB; 512])
            .expect("base write");

        let store = Arc::new(RwLock::new(MvccStore::new()));
        let snap = store.read().current_snapshot();
        let dev = MvccBlockDevice::new(base, store, snap);

        let buf = dev.read_block(&cx, BlockNumber(3)).expect("read block 3");
        assert_eq!(buf.as_slice(), &[0xAB; 512]);
    }

    #[test]
    fn mvcc_device_write_visible_to_reader_at_later_snapshot() {
        let cx = test_cx();
        let base = MemBlockDevice::new(512, 16);
        let store = Arc::new(RwLock::new(MvccStore::new()));

        let snap1 = store.read().current_snapshot();
        let dev = MvccBlockDevice::new(base, Arc::clone(&store), snap1);

        // Write via the MVCC device.
        dev.write_block(&cx, BlockNumber(5), &[0xFF; 512])
            .expect("mvcc write");

        // A new snapshot taken after the write should see it.
        let snap2 = store.read().current_snapshot();
        let base2 = MemBlockDevice::new(512, 16);
        let dev2 = MvccBlockDevice::new(base2, Arc::clone(&store), snap2);

        let buf = dev2.read_block(&cx, BlockNumber(5)).expect("read block 5");
        assert_eq!(buf.as_slice(), &[0xFF; 512]);
    }

    #[test]
    fn mvcc_device_snapshot_isolation() {
        let cx = test_cx();
        let store = Arc::new(RwLock::new(MvccStore::new()));

        // Commit a version via the store directly.
        {
            let mut guard = store.write();
            let mut txn = guard.begin();
            txn.stage_write(BlockNumber(1), vec![1; 512]);
            guard.commit(txn).expect("commit v1");
        }

        // Capture snapshot after v1.
        let snap_after_v1 = store.read().current_snapshot();

        // Commit a second version.
        {
            let mut guard = store.write();
            let mut txn = guard.begin();
            txn.stage_write(BlockNumber(1), vec![2; 512]);
            guard.commit(txn).expect("commit v2");
        }

        // Device at snap_after_v1 should see v1, not v2.
        let base = MemBlockDevice::new(512, 16);
        let dev = MvccBlockDevice::new(base, Arc::clone(&store), snap_after_v1);
        let buf = dev.read_block(&cx, BlockNumber(1)).expect("read");
        assert_eq!(buf.as_slice(), &[1; 512]);

        // Device at latest snapshot should see v2.
        let snap_after_v2 = store.read().current_snapshot();
        let base2 = MemBlockDevice::new(512, 16);
        let dev2 = MvccBlockDevice::new(base2, Arc::clone(&store), snap_after_v2);
        let buf2 = dev2.read_block(&cx, BlockNumber(1)).expect("read v2");
        assert_eq!(buf2.as_slice(), &[2; 512]);
    }

    #[test]
    fn mvcc_device_delegates_block_size_and_count() {
        let base = MemBlockDevice::new(4096, 128);
        let store = Arc::new(RwLock::new(MvccStore::new()));
        let snap = store.read().current_snapshot();
        let dev = MvccBlockDevice::new(base, store, snap);

        assert_eq!(dev.block_size(), 4096);
        assert_eq!(dev.block_count(), 128);
    }

    // ── Deterministic concurrency tests (bd-hrv) ─────────────────────────
    //
    // These tests encode MVCC invariants under controlled interleavings:
    //   1. Snapshot visibility — readers see only committed versions ≤ snap.
    //   2. First-committer-wins (FCW) — concurrent writers conflict correctly.
    //   3. No lost updates — every committed write is observable.
    //
    // The tests are deterministic: each constructs a specific interleaving
    // order rather than relying on thread scheduling, making them non-flaky.

    /// Invariant: snapshot visibility across a chain of commits.
    ///
    /// Commits v1..v5 to the same block, captures a snapshot after each.
    /// Each snapshot sees exactly the version committed at or before it.
    #[test]
    fn snapshot_visibility_chain() {
        let mut store = MvccStore::new();
        let mut snapshots = Vec::new();
        let block = BlockNumber(42);

        for version in 1_u8..=5 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![version; 4]);
            store.commit(txn).expect("commit");
            snapshots.push(store.current_snapshot());
        }

        // Each snapshot i should see version i+1 (1-indexed).
        for (i, snap) in snapshots.iter().enumerate() {
            let expected_version = u8::try_from(i + 1).expect("fits u8");
            let data = store.read_visible(block, *snap).expect("should be visible");
            assert_eq!(
                data, &[expected_version; 4],
                "snapshot {i} should see version {expected_version}"
            );
        }
    }

    /// Invariant: snapshot isolation prevents seeing future commits.
    ///
    /// Take a snapshot before any commits. Later commits must not be
    /// visible at that snapshot.
    #[test]
    fn snapshot_isolation_future_invisible() {
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        let early_snap = store.current_snapshot();

        // Commit 3 versions after the snapshot.
        for v in 1_u8..=3 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
        }

        // Early snapshot should see nothing.
        assert!(
            store.read_visible(block, early_snap).is_none(),
            "snapshot taken before any commits should see nothing"
        );
    }

    /// Invariant: FCW — interleaved writers to same block.
    ///
    /// Scenario: 3 transactions all begin at the same snapshot, all write
    /// the same block. Only the first to commit succeeds; the other two
    /// get Conflict errors.
    #[test]
    fn fcw_three_concurrent_writers() {
        let mut store = MvccStore::new();
        let block = BlockNumber(10);

        let mut t1 = store.begin();
        let mut t2 = store.begin();
        let mut t3 = store.begin();

        t1.stage_write(block, vec![1]);
        t2.stage_write(block, vec![2]);
        t3.stage_write(block, vec![3]);

        // T1 commits first — succeeds.
        let c1 = store.commit(t1).expect("t1 should succeed");
        assert_eq!(c1, CommitSeq(1));

        // T2 and T3 conflict because block was updated after their snapshot.
        let err2 = store.commit(t2).expect_err("t2 should conflict");
        assert!(matches!(err2, CommitError::Conflict { .. }));

        let err3 = store.commit(t3).expect_err("t3 should conflict");
        assert!(matches!(err3, CommitError::Conflict { .. }));
    }

    /// Invariant: FCW is per-block — disjoint writers don't conflict.
    ///
    /// Two concurrent transactions writing to different blocks both succeed.
    #[test]
    fn fcw_disjoint_blocks_no_conflict() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        let mut t2 = store.begin();

        t1.stage_write(BlockNumber(1), vec![0xAA]);
        t2.stage_write(BlockNumber(2), vec![0xBB]);

        store.commit(t1).expect("t1 should succeed");
        store
            .commit(t2)
            .expect("t2 should succeed (disjoint block)");

        let snap = store.current_snapshot();
        assert_eq!(store.read_visible(BlockNumber(1), snap).unwrap(), &[0xAA]);
        assert_eq!(store.read_visible(BlockNumber(2), snap).unwrap(), &[0xBB]);
    }

    /// Invariant: no lost updates — every committed write is observable.
    ///
    /// Serial commits to different blocks; all are visible at the final snapshot.
    #[test]
    fn no_lost_updates_serial() {
        let mut store = MvccStore::new();

        for i in 0_u64..20 {
            let block = BlockNumber(i);
            let mut txn = store.begin();
            let val = u8::try_from(i % 256).expect("fits u8");
            txn.stage_write(block, vec![val; 8]);
            store.commit(txn).expect("commit");
        }

        let snap = store.current_snapshot();
        for i in 0_u64..20 {
            let block = BlockNumber(i);
            let expected_val = u8::try_from(i % 256).expect("fits u8");
            let data = store.read_visible(block, snap).expect("must be visible");
            assert_eq!(data, &[expected_val; 8], "block {i} data mismatch");
        }
    }

    /// Invariant: no lost updates under interleaved begin/commit ordering.
    ///
    /// Interleave: begin(t1), begin(t2), commit(t1), commit(t2)
    /// where t1 and t2 write disjoint blocks. Both must persist.
    #[test]
    fn no_lost_updates_interleaved_disjoint() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        let mut t2 = store.begin();

        t1.stage_write(BlockNumber(100), vec![1; 16]);
        t2.stage_write(BlockNumber(200), vec![2; 16]);

        store.commit(t1).expect("commit t1");
        store.commit(t2).expect("commit t2");

        let snap = store.current_snapshot();
        assert_eq!(
            store.read_visible(BlockNumber(100), snap).unwrap(),
            &[1; 16]
        );
        assert_eq!(
            store.read_visible(BlockNumber(200), snap).unwrap(),
            &[2; 16]
        );
    }

    /// Invariant: prune does not break snapshot visibility.
    ///
    /// After pruning old versions, a snapshot that sees the latest
    /// version still returns the correct data.
    #[test]
    fn prune_preserves_latest_visibility() {
        let mut store = MvccStore::new();
        let block = BlockNumber(5);

        // Write 5 versions.
        for v in 1_u8..=5 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
        }

        let snap = store.current_snapshot();

        // Prune everything up to commit 4.
        store.prune_versions_older_than(CommitSeq(4));

        // Latest snapshot should still see version 5.
        let data = store.read_visible(block, snap).expect("still visible");
        assert_eq!(data, &[5]);
    }

    /// Multi-threaded stress: concurrent MvccBlockDevice writers on disjoint blocks.
    ///
    /// Multiple threads each write to their own block via the MvccBlockDevice.
    /// After all threads complete, all writes must be visible.
    #[test]
    fn concurrent_mvcc_device_disjoint_writers() {
        let store = Arc::new(RwLock::new(MvccStore::new()));
        let num_threads: usize = 8;
        let barrier = Arc::new(std::sync::Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                let block_num = u64::try_from(i).expect("thread index fits u64");
                std::thread::spawn(move || {
                    let cx = Cx::for_testing();
                    let snap = store.read().current_snapshot();
                    let base = MemBlockDevice::new(64, 256);
                    let dev = MvccBlockDevice::new(base, Arc::clone(&store), snap);

                    // Synchronize all threads to start at the same time.
                    barrier.wait();

                    let val = u8::try_from(i % 256).expect("fits u8");
                    dev.write_block(&cx, BlockNumber(block_num), &[val; 64])
                        .expect("write should succeed (disjoint blocks)");
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        // Verify all writes are visible at the latest snapshot.
        let guard = store.read();
        let snap = guard.current_snapshot();
        for i in 0..num_threads {
            let block_num = u64::try_from(i).expect("thread index fits u64");
            let expected_val = u8::try_from(i % 256).expect("fits u8");
            let data = guard
                .read_visible(BlockNumber(block_num), snap)
                .expect("block must be visible");
            assert_eq!(data, &[expected_val; 64], "thread {i} write lost");
        }
        drop(guard);
    }

    /// Multi-threaded stress: concurrent readers see stable snapshots.
    ///
    /// A writer thread commits versions while reader threads assert that
    /// their snapshot view never changes mid-read.
    #[test]
    fn concurrent_readers_stable_snapshot() {
        let store = Arc::new(RwLock::new(MvccStore::new()));
        let block = BlockNumber(0);

        // Seed an initial version so readers have something to see.
        {
            let mut guard = store.write();
            let mut txn = guard.begin();
            txn.stage_write(block, vec![0; 64]);
            guard.commit(txn).expect("seed commit");
        }

        let snap = store.read().current_snapshot();
        let num_readers: usize = 4;
        let reads_per_thread: usize = 200;
        let barrier = Arc::new(std::sync::Barrier::new(num_readers + 1));

        // Reader threads: each reads the same block many times at `snap`.
        let reader_handles: Vec<_> = (0..num_readers)
            .map(|_| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let cx = Cx::for_testing();
                    let base = MemBlockDevice::new(64, 256);
                    let dev = MvccBlockDevice::new(base, Arc::clone(&store), snap);

                    barrier.wait();

                    for _ in 0..reads_per_thread {
                        let buf = dev.read_block(&cx, block).expect("read");
                        // Snapshot should always see version 0.
                        assert_eq!(buf.as_slice(), &[0; 64], "snapshot view changed");
                    }
                })
            })
            .collect();

        // Writer thread: commits new versions concurrently.
        let writer_store = Arc::clone(&store);
        let writer_barrier = Arc::clone(&barrier);
        let writer_handle = std::thread::spawn(move || {
            writer_barrier.wait();

            for v in 1_u8..=50 {
                let mut guard = writer_store.write();
                let mut txn = guard.begin();
                txn.stage_write(block, vec![v; 64]);
                guard.commit(txn).expect("writer commit");
            }
        });

        for h in reader_handles {
            h.join().expect("reader panicked");
        }
        writer_handle.join().expect("writer panicked");
    }
}
