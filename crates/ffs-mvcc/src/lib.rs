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
    /// Active snapshots: each entry is a `CommitSeq` from which a reader is
    /// still potentially reading.  The set uses a `BTreeSet` so that the
    /// minimum (oldest active snapshot) can be obtained in O(log n).
    ///
    /// Callers **must** pair every `register_snapshot` with a corresponding
    /// `release_snapshot` to avoid preventing GC indefinitely.
    active_snapshots: BTreeMap<CommitSeq, u32>,
}

impl MvccStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_txn: 1,
            next_commit: 1,
            versions: BTreeMap::new(),
            active_snapshots: BTreeMap::new(),
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

    // ── Watermark / active snapshot tracking ───────────────────────────

    /// Register a snapshot as active.  This prevents `prune_safe` from
    /// removing versions that this snapshot might still need.
    ///
    /// Multiple registrations of the same `CommitSeq` are ref-counted;
    /// each must be paired with a corresponding `release_snapshot`.
    pub fn register_snapshot(&mut self, snapshot: Snapshot) {
        *self.active_snapshots.entry(snapshot.high).or_insert(0) += 1;
    }

    /// Release a previously registered snapshot.  When the last reference
    /// at a given `CommitSeq` is released, that sequence is no longer
    /// considered active and versions below it become eligible for pruning.
    ///
    /// Returns `true` if the snapshot was still registered, `false` if it
    /// was already fully released (a logic error by the caller, but not
    /// fatal).
    pub fn release_snapshot(&mut self, snapshot: Snapshot) -> bool {
        if let Some(count) = self.active_snapshots.get_mut(&snapshot.high) {
            *count -= 1;
            if *count == 0 {
                self.active_snapshots.remove(&snapshot.high);
            }
            true
        } else {
            false
        }
    }

    /// The oldest active snapshot, or `None` if no snapshots are
    /// registered.
    ///
    /// This is the **safe watermark**: pruning versions with
    /// `commit_seq < watermark` will not break any active reader.
    #[must_use]
    pub fn watermark(&self) -> Option<CommitSeq> {
        self.active_snapshots.keys().next().copied()
    }

    /// Number of currently active (registered) snapshots.
    #[must_use]
    pub fn active_snapshot_count(&self) -> usize {
        self.active_snapshots.values().map(|c| *c as usize).sum()
    }

    /// Prune versions that are no longer needed by any active snapshot.
    ///
    /// Equivalent to `prune_versions_older_than(watermark)` where
    /// `watermark` is the oldest active snapshot.  If no snapshots are
    /// registered, prunes up to the current commit sequence (i.e., keeps
    /// only the latest version per block).
    ///
    /// Returns the watermark that was used.
    pub fn prune_safe(&mut self) -> CommitSeq {
        let wm = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        self.prune_versions_older_than(wm);
        wm
    }

    /// Total number of block versions stored across all blocks.
    #[must_use]
    pub fn version_count(&self) -> usize {
        self.versions.values().map(Vec::len).sum()
    }

    /// Number of distinct blocks that have at least one version.
    #[must_use]
    pub fn block_count_versioned(&self) -> usize {
        self.versions.len()
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

    // ── Lab runtime deterministic concurrency tests ─────────────────────
    //
    // These tests use the asupersync lab runtime for deterministic, seed-
    // driven scheduling.  Instead of OS thread interleaving (non-deterministic),
    // each test spawns async tasks that yield at specific points.  The lab
    // scheduler picks the next task deterministically based on the seed.
    //
    // Same seed → same interleaving → same result.  Different seeds explore
    // different interleavings.  This makes concurrency bugs reproducible.
    //
    // Invariants verified:
    //   1. Snapshot visibility — readers see only committed versions ≤ snap.
    //   2. FCW (first-committer-wins) — exactly one writer succeeds per block.
    //   3. No lost updates — every committed write is observable.
    //   4. Write skew — documents a known FCW limitation (SSI prerequisite).

    use asupersync::lab::{LabConfig, LabRuntime};
    use asupersync::types::Budget;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};

    /// A future that yields once before completing, creating a scheduling
    /// opportunity for the lab runtime.
    struct YieldOnce {
        yielded: bool,
    }

    impl Future for YieldOnce {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<()> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    async fn yield_now() {
        YieldOnce { yielded: false }.await;
    }

    /// Run N tasks that all write to the same block under lab scheduling.
    ///
    /// All transactions are pre-begun at the same snapshot so that the
    /// interesting interleaving is the commit order (which the lab
    /// scheduler determines based on the seed).
    ///
    /// Returns: (Vec<commit outcomes as Ok(seq)/Err>, steps executed).
    fn run_fcw_scenario(seed: u64, num_writers: usize) -> (Vec<Result<u64, usize>>, u64) {
        let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
        let region = runtime.state.create_root_region(Budget::INFINITE);

        let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));
        let results = Arc::new(std::sync::Mutex::new(vec![None; num_writers]));
        let block = BlockNumber(42);

        // Pre-begin all transactions at the same snapshot.  This ensures
        // FCW is actually exercised regardless of scheduling order.
        let txns: Vec<Transaction> = {
            let mut s = store.lock().unwrap();
            (0..num_writers).map(|_| s.begin()).collect()
        };

        for (i, txn) in txns.into_iter().enumerate() {
            let store = Arc::clone(&store);
            let results = Arc::clone(&results);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    // Stage write.
                    let mut txn = txn;
                    let writer_val = u8::try_from(i % 256).expect("fits u8");
                    txn.stage_write(block, vec![writer_val; 8]);
                    yield_now().await; // Scheduling point — other writers may stage.

                    // Commit (order determined by lab scheduler).
                    let outcome = {
                        let mut s = store.lock().unwrap();
                        s.commit(txn)
                    };
                    results.lock().unwrap()[i] = Some(outcome.map(|seq| seq.0).map_err(|_| i));
                })
                .expect("create task");
            runtime.scheduler.lock().unwrap().schedule(task_id, 0);
        }

        let steps = runtime.run_until_quiescent();

        let results: Vec<Result<u64, usize>> = Arc::try_unwrap(results)
            .unwrap()
            .into_inner()
            .unwrap()
            .into_iter()
            .map(|r| r.expect("task should have completed"))
            .collect();

        (results, steps)
    }

    /// Lab determinism: same seed → identical FCW conflict pattern.
    ///
    /// Runs the same scenario 3 times with the same seed and asserts the
    /// commit outcomes are identical.
    #[test]
    fn lab_deterministic_fcw_same_seed() {
        let seed = 42;
        let (r1, _) = run_fcw_scenario(seed, 4);
        let (r2, _) = run_fcw_scenario(seed, 4);
        let (r3, _) = run_fcw_scenario(seed, 4);

        assert_eq!(
            r1, r2,
            "same seed must produce identical outcomes (run 1 vs 2)"
        );
        assert_eq!(
            r2, r3,
            "same seed must produce identical outcomes (run 2 vs 3)"
        );
    }

    /// Lab invariant: FCW — across many seeds, exactly one writer succeeds.
    ///
    /// For each seed, N tasks write to the same block.  The invariant is
    /// that exactly one commit succeeds (Ok) and the rest fail (Err).
    #[test]
    fn lab_fcw_invariant_across_seeds() {
        let num_writers = 4;
        for seed in 0_u64..50 {
            let (results, _) = run_fcw_scenario(seed, num_writers);
            let successes = results.iter().filter(|r| r.is_ok()).count();
            assert_eq!(
                successes, 1,
                "seed {seed}: expected exactly 1 success, got {successes} in {results:?}"
            );
        }
    }

    /// Lab invariant: no lost updates — disjoint block writers under varied scheduling.
    ///
    /// N tasks each write to their own block.  Across many seeds, all N
    /// writes must be visible at the final snapshot.
    #[test]
    fn lab_no_lost_updates_disjoint_blocks() {
        let num_writers: usize = 8;

        for seed in 0_u64..30 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));
            let committed = Arc::new(std::sync::Mutex::new(Vec::new()));

            for i in 0..num_writers {
                let store = Arc::clone(&store);
                let committed = Arc::clone(&committed);
                let block = BlockNumber(u64::try_from(i).unwrap());
                let (task_id, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        let txn = {
                            let mut s = store.lock().unwrap();
                            s.begin()
                        };
                        yield_now().await;

                        let mut txn = txn;
                        let val = u8::try_from(i % 256).unwrap();
                        txn.stage_write(block, vec![val; 4]);
                        yield_now().await;

                        let result = {
                            let mut s = store.lock().unwrap();
                            s.commit(txn)
                        };
                        if result.is_ok() {
                            committed.lock().unwrap().push(i);
                        }
                    })
                    .expect("create task");
                runtime.scheduler.lock().unwrap().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let committed = Arc::try_unwrap(committed).unwrap().into_inner().unwrap();
            assert_eq!(
                committed.len(),
                num_writers,
                "seed {seed}: all {num_writers} disjoint writers must succeed, got {committed:?}"
            );

            // Verify all data is visible.
            let store = Arc::try_unwrap(store).unwrap().into_inner().unwrap();
            let snap = store.current_snapshot();
            for i in 0..num_writers {
                let block = BlockNumber(u64::try_from(i).unwrap());
                let val = u8::try_from(i % 256).unwrap();
                let data = store
                    .read_visible(block, snap)
                    .unwrap_or_else(|| panic!("seed {seed}: block {i} must be visible"));
                assert_eq!(data, &[val; 4], "seed {seed}: block {i} data mismatch");
            }
        }
    }

    /// Lab invariant: snapshot visibility under interleaved writers.
    ///
    /// A snapshot is captured before writers begin.  Under all interleavings,
    /// reads at that snapshot return the initial version, never a writer's.
    #[test]
    fn lab_snapshot_visibility_under_interleaving() {
        for seed in 0_u64..30 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));
            let block = BlockNumber(1);

            // Seed an initial version.
            {
                let mut s = store.lock().unwrap();
                let mut txn = s.begin();
                txn.stage_write(block, vec![0xAA; 4]);
                s.commit(txn).expect("seed commit");
            }

            // Pre-capture snapshot before any writer task runs.
            let reader_snap = store.lock().unwrap().current_snapshot();

            let reader_result = Arc::new(std::sync::Mutex::new(None));

            // Reader task: reads at the pre-captured snapshot.
            {
                let store = Arc::clone(&store);
                let reader_result = Arc::clone(&reader_result);
                let (task_id, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await; // Writers may commit here.
                        yield_now().await; // Extra yield for more interleaving.

                        let data = {
                            let s = store.lock().unwrap();
                            s.read_visible(block, reader_snap).map(<[u8]>::to_vec)
                        };
                        *reader_result.lock().unwrap() = Some(data);
                    })
                    .expect("create task");
                runtime.scheduler.lock().unwrap().schedule(task_id, 0);
            }

            // Writer tasks: commit new versions.
            for v in 1_u8..=3 {
                let store = Arc::clone(&store);
                let (task_id, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await;
                        let mut s = store.lock().unwrap();
                        let mut txn = s.begin();
                        txn.stage_write(block, vec![v; 4]);
                        s.commit(txn).expect("writer commit");
                    })
                    .expect("create task");
                runtime.scheduler.lock().unwrap().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let result = Arc::try_unwrap(reader_result)
                .unwrap()
                .into_inner()
                .unwrap()
                .expect("reader task should have completed");

            // The reader's snapshot was captured before writers,
            // so it must see 0xAA regardless of interleaving.
            let data = result.expect("block must be visible at initial snapshot");
            assert_eq!(
                data,
                vec![0xAA; 4],
                "seed {seed}: reader must see initial version (0xAA), not a later writer's data"
            );
        }
    }

    /// Lab: write skew scenario — documents the FCW limitation.
    ///
    /// Classic write skew: T1 reads block A, T2 reads block B.
    /// T1 writes block B based on A's value, T2 writes block A based on B's value.
    /// Under FCW, both succeed because they write disjoint blocks.
    /// This is a known anomaly that SSI (bd-1wx) will prevent.
    ///
    /// The test verifies:
    /// - FCW allows both commits (expected, not a bug under FCW).
    /// - The resulting state violates a cross-block constraint.
    ///
    /// When SSI is implemented, this test should be updated to assert that
    /// at least one transaction is aborted.
    #[test]
    fn lab_write_skew_under_fcw() {
        let block_a = BlockNumber(100);
        let block_b = BlockNumber(200);

        for seed in 0_u64..20 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));

            // Seed: both blocks start with value 1.
            // Constraint: block_a + block_b should remain ≤ 2.
            // Each transaction reads one block (sees 1), and sets the
            // other block to 2 (believing the total is 1+2=3 is ok for
            // its local view, but the combined effect is 2+2=4 — violated).
            {
                let mut s = store.lock().unwrap();
                let mut txn = s.begin();
                txn.stage_write(block_a, vec![1]);
                txn.stage_write(block_b, vec![1]);
                s.commit(txn).expect("seed commit");
            }

            let outcomes = Arc::new(std::sync::Mutex::new((None, None)));

            // Pre-begin both transactions at the same snapshot so they
            // each see A=1, B=1 and write disjoint blocks.
            let (txn1, txn2) = {
                let mut s = store.lock().unwrap();
                (s.begin(), s.begin())
            };

            // T1: writes B to 2 (based on having seen A=1 at snapshot).
            {
                let store = Arc::clone(&store);
                let outcomes = Arc::clone(&outcomes);
                let (task_id, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await;

                        let mut txn1 = txn1;
                        txn1.stage_write(block_b, vec![2]);
                        let result = {
                            let mut s = store.lock().unwrap();
                            s.commit(txn1)
                        };
                        outcomes.lock().unwrap().0 = Some(result.is_ok());
                    })
                    .expect("create task");
                runtime.scheduler.lock().unwrap().schedule(task_id, 0);
            }

            // T2: writes A to 2 (based on having seen B=1 at snapshot).
            {
                let store = Arc::clone(&store);
                let outcomes = Arc::clone(&outcomes);
                let (task_id, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await;

                        let mut txn2 = txn2;
                        txn2.stage_write(block_a, vec![2]);
                        let result = {
                            let mut s = store.lock().unwrap();
                            s.commit(txn2)
                        };
                        outcomes.lock().unwrap().1 = Some(result.is_ok());
                    })
                    .expect("create task");
                runtime.scheduler.lock().unwrap().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let outcomes = Arc::try_unwrap(outcomes).unwrap().into_inner().unwrap();
            let t1_ok = outcomes.0.expect("T1 should complete");
            let t2_ok = outcomes.1.expect("T2 should complete");

            // Under FCW, both succeed because they write disjoint blocks.
            // This IS the write skew anomaly — FCW does not detect it.
            assert!(
                t1_ok && t2_ok,
                "seed {seed}: under FCW, both disjoint-block writers should succeed \
                 (write skew is expected). Got t1={t1_ok}, t2={t2_ok}"
            );

            // Verify the constraint IS violated (both blocks are now 2).
            let s = store.lock().unwrap();
            let snap = s.current_snapshot();
            let a = s.read_visible(block_a, snap).unwrap()[0];
            let b = s.read_visible(block_b, snap).unwrap()[0];
            drop(s);
            assert!(
                a + b > 2,
                "seed {seed}: write skew should produce a+b > 2, got a={a} b={b}"
            );
        }
    }

    /// Lab: interleaved commit ordering with same-block conflict.
    ///
    /// Verifies that the commit-order winner is deterministic per seed.
    /// All transactions pre-begin at the same snapshot, all write the
    /// same block, and exactly one succeeds per seed.
    #[test]
    fn lab_commit_order_determines_winner() {
        let block = BlockNumber(7);
        let num_tasks: usize = 5;

        for seed in 0_u64..30 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));
            let winner = Arc::new(std::sync::Mutex::new(None));

            // Pre-begin all at the same snapshot.
            let txns: Vec<Transaction> = {
                let mut s = store.lock().unwrap();
                (0..num_tasks).map(|_| s.begin()).collect()
            };

            for (i, txn) in txns.into_iter().enumerate() {
                let store = Arc::clone(&store);
                let winner = Arc::clone(&winner);
                let (task_id, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        let mut txn = txn;
                        let val = u8::try_from(i % 256).unwrap();
                        txn.stage_write(block, vec![val; 4]);
                        yield_now().await;

                        let result = {
                            let mut s = store.lock().unwrap();
                            s.commit(txn)
                        };
                        if result.is_ok() {
                            let mut w = winner.lock().unwrap();
                            assert!(w.is_none(), "seed {seed}: two tasks both claimed to win!");
                            *w = Some(i);
                        }
                    })
                    .expect("create task");
                runtime.scheduler.lock().unwrap().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let w = Arc::try_unwrap(winner).unwrap().into_inner().unwrap();
            assert!(
                w.is_some(),
                "seed {seed}: no task won the FCW race (all failed?)"
            );

            // Verify the winner's data is visible.
            let data = {
                let s = store.lock().unwrap();
                let snap = s.current_snapshot();
                s.read_visible(block, snap)
                    .expect("winner data must be visible")
                    .to_vec()
            };
            let expected_val = u8::try_from(w.unwrap() % 256).unwrap();
            assert_eq!(
                data,
                vec![expected_val; 4],
                "seed {seed}: visible data should match winner's write"
            );
        }
    }

    // ── Watermark / GC tests ───────────────────────────────────────────

    #[test]
    fn watermark_empty_when_no_snapshots_registered() {
        let store = MvccStore::new();
        assert!(store.watermark().is_none());
        assert_eq!(store.active_snapshot_count(), 0);
    }

    #[test]
    fn register_and_release_snapshot() {
        let mut store = MvccStore::new();
        let snap = Snapshot { high: CommitSeq(5) };

        store.register_snapshot(snap);
        assert_eq!(store.watermark(), Some(CommitSeq(5)));
        assert_eq!(store.active_snapshot_count(), 1);

        assert!(store.release_snapshot(snap));
        assert!(store.watermark().is_none());
        assert_eq!(store.active_snapshot_count(), 0);
    }

    #[test]
    fn watermark_tracks_oldest_active_snapshot() {
        let mut store = MvccStore::new();
        let old = Snapshot { high: CommitSeq(3) };
        let mid = Snapshot { high: CommitSeq(7) };
        let new = Snapshot {
            high: CommitSeq(12),
        };

        store.register_snapshot(mid);
        store.register_snapshot(new);
        store.register_snapshot(old);

        assert_eq!(store.watermark(), Some(CommitSeq(3)));
        assert_eq!(store.active_snapshot_count(), 3);

        // Release the oldest — watermark advances.
        store.release_snapshot(old);
        assert_eq!(store.watermark(), Some(CommitSeq(7)));

        // Release mid — watermark advances again.
        store.release_snapshot(mid);
        assert_eq!(store.watermark(), Some(CommitSeq(12)));

        // Release last — no watermark.
        store.release_snapshot(new);
        assert!(store.watermark().is_none());
    }

    #[test]
    fn snapshot_ref_counting() {
        let mut store = MvccStore::new();
        let snap = Snapshot { high: CommitSeq(5) };

        // Register same snapshot twice.
        store.register_snapshot(snap);
        store.register_snapshot(snap);
        assert_eq!(store.active_snapshot_count(), 2);
        assert_eq!(store.watermark(), Some(CommitSeq(5)));

        // First release — still active.
        store.release_snapshot(snap);
        assert_eq!(store.active_snapshot_count(), 1);
        assert_eq!(store.watermark(), Some(CommitSeq(5)));

        // Second release — gone.
        store.release_snapshot(snap);
        assert_eq!(store.active_snapshot_count(), 0);
        assert!(store.watermark().is_none());
    }

    #[test]
    fn release_unregistered_snapshot_returns_false() {
        let mut store = MvccStore::new();
        let snap = Snapshot {
            high: CommitSeq(99),
        };
        assert!(!store.release_snapshot(snap));
    }

    #[test]
    fn prune_safe_respects_active_snapshots() {
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        // Write 5 versions (commit seqs 1..=5).
        let mut snaps = Vec::new();
        for v in 1_u8..=5 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
            snaps.push(store.current_snapshot());
        }

        // Register snapshot at commit 3.
        store.register_snapshot(snaps[2]);

        // Safe prune should keep versions readable at commit 3.
        let wm = store.prune_safe();
        assert_eq!(wm, CommitSeq(3));

        // Snapshot at commit 3 still works.
        assert_eq!(
            store.read_visible(block, snaps[2]).unwrap(),
            &[3],
            "version at commit 3 should survive pruning"
        );

        // Latest snapshot still works.
        assert_eq!(
            store.read_visible(block, snaps[4]).unwrap(),
            &[5],
            "latest version should always survive"
        );

        // Versions 1 and 2 should have been pruned.
        let snap_1 = Snapshot { high: CommitSeq(1) };
        let old_read = store.read_visible(block, snap_1);
        assert!(
            old_read.is_none() || old_read.unwrap() == [3],
            "version 1 should be pruned or replaced by version 3"
        );
    }

    #[test]
    fn prune_safe_with_no_snapshots_keeps_only_latest() {
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        // Write 10 versions.
        for v in 1_u8..=10 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
        }

        assert_eq!(store.version_count(), 10);

        // No active snapshots — prune should reduce to 1 per block.
        store.prune_safe();

        // At most 1 version per block should remain.
        assert!(
            store.version_count() <= 1,
            "expected <= 1 version, got {}",
            store.version_count()
        );

        // Latest version still readable.
        let snap = store.current_snapshot();
        assert_eq!(store.read_visible(block, snap).unwrap(), &[10]);
    }

    #[test]
    fn version_count_and_block_count_versioned() {
        let mut store = MvccStore::new();

        assert_eq!(store.version_count(), 0);
        assert_eq!(store.block_count_versioned(), 0);

        // 3 versions of block 1, 2 versions of block 2.
        for v in 1_u8..=3 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(1), vec![v]);
            store.commit(txn).expect("commit");
        }
        for v in 1_u8..=2 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(2), vec![v]);
            store.commit(txn).expect("commit");
        }

        assert_eq!(store.version_count(), 5);
        assert_eq!(store.block_count_versioned(), 2);
    }

    /// Memory bounding simulation: many commits with periodic pruning.
    ///
    /// Writes 200 versions to the same block.  With periodic `prune_safe`
    /// and a single active snapshot sliding forward, version count stays
    /// bounded.
    #[test]
    fn memory_bounded_under_periodic_gc() {
        let mut store = MvccStore::new();
        let block = BlockNumber(0);
        let mut max_versions = 0_usize;
        let mut current_snap: Option<Snapshot> = None;

        for round in 0_u64..200 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![u8::try_from(round % 256).unwrap()]);
            store.commit(txn).expect("commit");

            // Slide the active snapshot window every 10 commits.
            if round % 10 == 0 {
                if let Some(old) = current_snap {
                    store.release_snapshot(old);
                }
                let snap = store.current_snapshot();
                store.register_snapshot(snap);
                current_snap = Some(snap);

                store.prune_safe();
            }

            let vc = store.version_count();
            if vc > max_versions {
                max_versions = vc;
            }
        }

        // With pruning every 10 commits and a sliding window of ~10 commits,
        // the max version count should be bounded well below 200.
        assert!(
            max_versions < 25,
            "expected bounded version growth, but max_versions was {max_versions}"
        );

        // Final state: current snapshot still readable.
        let snap = store.current_snapshot();
        let data = store.read_visible(block, snap).expect("readable");
        assert_eq!(data, &[199_u8]);
    }

    /// Long-running simulation with multiple blocks.
    ///
    /// 500 commits across 10 blocks with periodic GC.  Verifies that
    /// version count stays bounded and all latest values are correct.
    #[test]
    fn memory_bounded_multi_block_simulation() {
        let mut store = MvccStore::new();
        let num_blocks = 10_u64;
        let num_rounds = 500_u64;
        let mut current_snap: Option<Snapshot> = None;

        for round in 0..num_rounds {
            let block = BlockNumber(round % num_blocks);
            let val = u8::try_from(round % 256).unwrap();

            let mut txn = store.begin();
            txn.stage_write(block, vec![val]);
            store.commit(txn).expect("commit");

            // Slide the active snapshot window every 20 commits.
            if round % 20 == 0 {
                if let Some(old) = current_snap {
                    store.release_snapshot(old);
                }
                let snap = store.current_snapshot();
                store.register_snapshot(snap);
                current_snap = Some(snap);

                store.prune_safe();
            }
        }

        // Final cleanup.
        if let Some(old) = current_snap {
            store.release_snapshot(old);
        }
        store.prune_safe();

        // After full cleanup, should have at most 1 version per block.
        let expected_max = usize::try_from(num_blocks).unwrap();
        assert!(
            store.version_count() <= expected_max,
            "expected <= {num_blocks} versions after full GC, got {}",
            store.version_count()
        );

        // Verify latest values are correct.
        let snap = store.current_snapshot();
        for b in 0..num_blocks {
            let block = BlockNumber(b);
            // The last round that wrote to this block:
            let last_round = num_rounds - num_blocks + b;
            let expected = u8::try_from(last_round % 256).unwrap();
            assert_eq!(
                store.read_visible(block, snap).unwrap(),
                &[expected],
                "block {b} should have latest value"
            );
        }
    }
}
