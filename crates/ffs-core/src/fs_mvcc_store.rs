//! MVCC store abstraction for the OpenFs hot path.
//!
//! `OpenFs` needs one uniform `&self` API over two lock models:
//! the legacy single `RwLock<MvccStore>` path and the sharded parallel-write
//! path. Keeping this adapter in `ffs-core` avoids changing the public
//! `ffs-mvcc::MvccBlockDevice` API while the filesystem wiring moves over.

use asupersync::Cx;
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result as FfsResult};
use ffs_mvcc::sharded::{PublicationMode, ShardedMvccStore};
use ffs_mvcc::{
    BlockVersionStats, CommitError, EbrVersionStats, MergeProof, MvccStore, Transaction,
    TransactionOutcomeStats, TxnAbortReason,
};
use ffs_types::{BlockNumber, CommitSeq, Snapshot};
use parking_lot::RwLock;
use std::sync::Arc;

const MVCC_COMMIT_PRUNE_INTERVAL: u64 = 256;

/// Convert a commit failure into an `FfsError`, PRESERVING a first-committer-wins
/// conflict as the typed [`FfsError::MvccConflict`] instead of flattening it into
/// an opaque `Format` string.
///
/// The type is what makes an optimistic retry possible: a caller whose patch is
/// replayable needs to distinguish "someone else committed this block first, try
/// again" from "this write is malformed", and those are not distinguishable once
/// both are a string. `MvccConflict` already maps to `EAGAIN`, which is the right
/// errno for a caller that does NOT retry, so nothing downstream regresses
/// (bd-y2t0r).
fn commit_error_to_ffs(error: &CommitError) -> FfsError {
    match error {
        CommitError::Conflict { block, .. } => FfsError::MvccConflict {
            tx: 0,
            block: block.0,
        },
        other => FfsError::Format(other.to_string()),
    }
}

/// The OpenFs MVCC store: single-lock or sharded, behind a uniform `&self` API./// The OpenFs MVCC store: single-lock or sharded, behind a uniform `&self` API.
///
/// The enum is always owned behind `Arc`; boxing a variant would add another
/// hot-path indirection without reducing the outer handle size.
#[allow(clippy::large_enum_variant)]
pub enum FsMvccStore {
    /// Single store behind a `RwLock`: legacy, JBD2, and MVCC-WAL configured path.
    Single(RwLock<MvccStore>),
    /// Sharded store: default in-memory parallel-write path.
    Sharded(ShardedMvccStore),
}

impl FsMvccStore {
    pub(super) fn single() -> Self {
        Self::Single(RwLock::new(MvccStore::new()))
    }

    pub(super) fn sharded() -> Self {
        // Size shards to the host (available_parallelism, bounded) rather than a
        // fixed 8: at 16/32 disjoint parallel writers the 8-shard cap adds
        // shard-lock contention that host-sized sharding avoids (measured
        // sharded_mvcc_disjoint: 16w 3.74->3.21 ms = 1.17x, 32w 10.53->8.15 ms
        // = 1.29x; 8w neutral). Correctness-identical (more shards, same
        // semantics) and the documented preferred high-core constructor. The
        // residual parallel-write gap (bd-bhh0i) is the global active_snapshots
        // lock, not shard count (docs/NEGATIVE_EVIDENCE.md).
        Self::Sharded(ShardedMvccStore::for_host_parallelism())
    }

    pub(super) fn sharded_with_publication_mode(mode: PublicationMode) -> Self {
        Self::Sharded(ShardedMvccStore::with_publication_mode(
            ShardedMvccStore::host_parallelism_shard_count(),
            mode,
        ))
    }

    pub(super) const fn is_sharded(&self) -> bool {
        matches!(self, Self::Sharded(_))
    }

    pub(super) fn begin(&self) -> Transaction {
        match self {
            Self::Single(lock) => lock.write().begin(),
            Self::Sharded(store) => store.begin(),
        }
    }

    pub(super) fn commit(&self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        match self {
            Self::Single(lock) => lock.write().commit(txn),
            Self::Sharded(store) => store.commit(txn).map_err(|(error, _txn)| error),
        }
    }

    pub(super) fn commit_ssi(&self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        match self {
            Self::Single(lock) => lock.write().commit_ssi(txn),
            Self::Sharded(store) => store.commit_ssi(txn).map_err(|(error, _txn)| error),
        }
    }

    pub(super) fn abort(&self, txn: Transaction, reason: TxnAbortReason, detail: Option<String>) {
        match self {
            Self::Single(lock) => lock.write().abort(txn, reason, detail),
            Self::Sharded(_) => drop((txn, reason, detail)),
        }
    }

    pub(super) fn read_visible(&self, block: BlockNumber, snapshot: Snapshot) -> Option<Vec<u8>> {
        match self {
            Self::Single(lock) => lock
                .read()
                .read_visible(block, snapshot)
                .map(std::borrow::Cow::into_owned),
            Self::Sharded(store) => store.read_visible(block, snapshot),
        }
    }

    pub(super) fn read_visible_block_buf(
        &self,
        block: BlockNumber,
        snapshot: Snapshot,
    ) -> Option<BlockBuf> {
        match self {
            Self::Single(lock) => lock.read().read_visible_block_buf(block, snapshot),
            Self::Sharded(store) => store.read_visible_block_buf(block, snapshot),
        }
    }

    pub(super) fn current_snapshot(&self) -> Snapshot {
        match self {
            Self::Single(lock) => lock.read().current_snapshot(),
            Self::Sharded(store) => store.current_snapshot(),
        }
    }

    pub(super) fn register_snapshot(&self, snapshot: Snapshot) {
        match self {
            Self::Single(lock) => lock.write().register_snapshot(snapshot),
            Self::Sharded(store) => store.register_snapshot(snapshot),
        }
    }

    pub(super) fn release_snapshot(&self, snapshot: Snapshot) -> bool {
        match self {
            Self::Single(lock) => lock.write().release_snapshot(snapshot),
            Self::Sharded(store) => store.release_snapshot(snapshot),
        }
    }

    pub(super) fn watermark(&self) -> Option<CommitSeq> {
        match self {
            Self::Single(lock) => lock.read().watermark(),
            Self::Sharded(store) => store.watermark(),
        }
    }

    pub(super) fn latest_commit_seq(&self, block: BlockNumber) -> CommitSeq {
        match self {
            Self::Single(lock) => lock.read().latest_commit_seq(block),
            Self::Sharded(store) => store.latest_commit_seq(block),
        }
    }

    /// Resolve a device fallback only while no newer version makes its ancestry
    /// ambiguous. A missing snapshot version is not necessarily an untouched
    /// block: an unregistered transaction can outlive that version's pruning.
    /// Refuse with the same retryable error as an optimistic commit conflict,
    /// rather than inventing a before-image from potentially stale disk bytes.
    fn read_unversioned_base_at_snapshot<T>(
        &self,
        block: BlockNumber,
        snapshot: Snapshot,
        read_base: impl FnOnce() -> FfsResult<T>,
    ) -> FfsResult<T> {
        let check = || {
            if self.latest_commit_seq(block) > snapshot.high {
                Err(FfsError::MvccConflict {
                    tx: 0,
                    block: block.0,
                })
            } else {
                Ok(())
            }
        };
        check()?;
        let base = read_base()?;
        // The device read can yield while another writer commits and flushes.
        // A check only before I/O could then accept post-snapshot disk content.
        check()?;
        Ok(base)
    }

    pub(super) fn prune_safe(&self) -> CommitSeq {
        match self {
            Self::Single(lock) => lock.write().prune_safe(),
            Self::Sharded(store) => store.prune_safe(),
        }
    }

    pub(super) fn prune_after_commit_if_due(&self, commit_seq: CommitSeq) -> Option<CommitSeq> {
        (commit_seq.0 != 0 && commit_seq.0.is_multiple_of(MVCC_COMMIT_PRUNE_INTERVAL))
            .then(|| self.prune_safe())
    }

    /// Read-modify-write one block in a single auto-committed transaction, staged
    /// under a merge `proof` — the proof-carrying, SNAPSHOT-CONSISTENT sibling of
    /// [`FsMvccBlockDevice::write_block`] (which stages the default `Unsafe` proof
    /// and takes pre-read bytes). The sharded (no-write-lock) inode write path
    /// (bd-bhh0i slice 2b) uses this to stage the patched inode-table block under
    /// a SLOT-SCOPED `timestamp_only_inode_range` proof, so two concurrent creates
    /// writing DISJOINT inode slots of the same 4 KiB table block MERGE instead of
    /// first-committer-wins conflicting.
    ///
    /// Crucially the base block is read AT THE TRANSACTION'S OWN SNAPSHOT (`begin`
    /// first, then read), NOT via a separate adapter read taken beforehand. A read
    /// taken BEFORE `begin` can observe an OLDER version than the transaction: if a
    /// concurrent writer to the same block commits in that window, the RMW's own
    /// commit sees `observed <= snapshot.high` (no conflict) and INSTALLS the
    /// stale-based block, silently clobbering the concurrent writer's disjoint slot
    /// — a corruption the merge proof cannot catch because the conflict path is
    /// never entered. Reading at `txn.snapshot()` closes that window: a commit
    /// after `begin` forces `observed > snapshot.high` → the conflict/merge path,
    /// which overlays only this write's declared range onto the latest version
    /// (correct); with no intervening commit the read is current and the install is
    /// fresh. `read_base` must read the same block. A device fallback is accepted
    /// only if no newer version appears before or during the read; otherwise its
    /// ancestry is ambiguous and the caller receives a retryable conflict.
    #[cfg(feature = "bhh0i_sharded_alloc")]
    pub(super) fn rmw_commit_block_with_proof<R, P>(
        &self,
        block: BlockNumber,
        proof: ffs_mvcc::MergeProof,
        read_base: R,
        patch: P,
    ) -> FfsResult<()>
    where
        R: FnOnce() -> FfsResult<Vec<u8>>,
        P: FnOnce(&mut Vec<u8>) -> FfsResult<()>,
    {
        let mut txn = self.begin();
        let snapshot = txn.snapshot();
        // The merge common ancestor is this block's content at the txn's snapshot:
        // the resident version if one exists, else the base-device bytes. Record it
        // as `staged_base` ALWAYS — do NOT rely on the version chain still holding
        // it at commit time. A concurrent committer's `prune_after_commit_if_due`
        // can drop the version at this (unregistered auto-commit) snapshot between
        // stage and commit, after which the sharded merge's `version_bytes_at`
        // yields an EMPTY base → a spurious length-mismatch abort of a disjoint
        // range-overlay (e.g. two creates writing different inode slots of the same
        // inode-table block). Recording the base makes the merge independent of
        // pruning (bd-bhh0i BUG-4 inode-table pruning race). The extra block-sized
        // clone is only consumed on a same-block conflict.
        let (mut data, base) = if let Some(bytes) = self.read_visible(block, snapshot) {
            (bytes.clone(), Some(bytes))
        } else {
            let device_base = self.read_unversioned_base_at_snapshot(block, snapshot, read_base)?;
            (device_base.clone(), Some(device_base))
        };
        patch(&mut data)?;
        txn.stage_write_with_proof_and_base(block, data, proof, base);
        let commit_seq = self
            .commit(txn)
            .map_err(|error| commit_error_to_ffs(&error))?;
        self.prune_after_commit_if_due(commit_seq);
        Ok(())
    }

    pub(super) fn flush_to_device_after<D: BlockDevice>(
        &self,
        cx: &Cx,
        device: &D,
        flushed_through: CommitSeq,
    ) -> FfsResult<(usize, CommitSeq)> {
        match self {
            Self::Single(lock) => lock
                .read()
                .flush_to_device_after(cx, device, flushed_through),
            Self::Sharded(store) => store.flush_to_device_after(cx, device, flushed_through),
        }
    }

    pub(super) fn version_count(&self) -> usize {
        match self {
            Self::Single(lock) => lock.read().version_count(),
            Self::Sharded(store) => store.version_count(),
        }
    }

    pub(super) fn active_snapshot_count(&self) -> usize {
        match self {
            Self::Single(lock) => lock.read().active_snapshot_count(),
            Self::Sharded(store) => store.active_snapshot_count(),
        }
    }

    pub(super) fn block_version_stats(&self) -> BlockVersionStats {
        match self {
            Self::Single(lock) => lock.read().block_version_stats(),
            Self::Sharded(store) => BlockVersionStats {
                tracked_blocks: store.version_count(),
                max_chain_length: 0,
                chains_over_cap: 0,
                chains_over_critical: 0,
                chain_cap: None,
                critical_chain_length: None,
            },
        }
    }

    pub(super) fn ebr_stats(&self) -> EbrVersionStats {
        match self {
            Self::Single(lock) => lock.read().ebr_stats(),
            Self::Sharded(_) => EbrVersionStats::default(),
        }
    }

    pub(super) fn transaction_outcome_stats(&self) -> TransactionOutcomeStats {
        match self {
            Self::Single(lock) => lock.read().transaction_outcome_stats(),
            Self::Sharded(_) => TransactionOutcomeStats::default(),
        }
    }

    pub(super) fn as_single(&self) -> Option<&RwLock<MvccStore>> {
        match self {
            Self::Single(lock) => Some(lock),
            Self::Sharded(_) => None,
        }
    }
}

enum SnapshotOwnership {
    Inline { snapshot: Snapshot },
    Unregistered { snapshot: Snapshot },
}

/// Block-device view over [`FsMvccStore`], preserving the old overlay ordering.
pub struct FsMvccBlockDevice<D: BlockDevice> {
    base: D,
    store: Arc<FsMvccStore>,
    ownership: SnapshotOwnership,
    read_your_writes: bool,
}

impl<D: BlockDevice> FsMvccBlockDevice<D> {
    pub(super) fn new(base: D, store: Arc<FsMvccStore>, snapshot: Snapshot) -> Self {
        store.register_snapshot(snapshot);
        Self {
            base,
            store,
            ownership: SnapshotOwnership::Inline { snapshot },
            read_your_writes: false,
        }
    }

    pub(super) fn new_unregistered(base: D, store: Arc<FsMvccStore>, snapshot: Snapshot) -> Self {
        Self {
            base,
            store,
            ownership: SnapshotOwnership::Unregistered { snapshot },
            read_your_writes: false,
        }
    }

    pub(super) fn with_read_your_writes(mut self) -> Self {
        if let SnapshotOwnership::Inline { snapshot } = self.ownership {
            let released = self.store.release_snapshot(snapshot);
            debug_assert!(
                released,
                "mvcc snapshot was not registered or already released: {snapshot:?}"
            );
            self.ownership = SnapshotOwnership::Unregistered { snapshot };
        }
        self.read_your_writes = true;
        self
    }

    fn snapshot(&self) -> Snapshot {
        match self.ownership {
            SnapshotOwnership::Inline { snapshot }
            | SnapshotOwnership::Unregistered { snapshot } => snapshot,
        }
    }

    fn read_snapshot(&self) -> Snapshot {
        if self.read_your_writes {
            // Read-your-writes wants the LATEST committed content. Resolve at the
            // MAX sentinel (newest RETAINED version) rather than a freshly fetched
            // `current_snapshot()`, which has a TOCTOU with pruning: bd-bhh0i
            // writable adapters are unregistered, so the prune watermark is the
            // chain head — a concurrent commit+prune between capturing `current`
            // and `read_visible` drops the captured version and the read falls to
            // the stale on-device block (bd-bhh0i BUG-4 read-your-writes vs prune).
            Snapshot {
                high: CommitSeq(u64::MAX),
            }
        } else {
            self.snapshot()
        }
    }

    fn reads_base_directly(&self) -> bool {
        matches!(self.ownership, SnapshotOwnership::Unregistered { .. }) && !self.read_your_writes
    }

    fn validate_range(&self, start: BlockNumber, count: u64) -> FfsResult<()> {
        if self.block_size() == 0 {
            return Err(FfsError::Format(
                "MVCC device has zero block size".to_owned(),
            ));
        }
        let end = start
            .0
            .checked_add(count)
            .ok_or_else(|| FfsError::Format("block range overflow".to_owned()))?;
        if end > self.block_count() {
            return Err(FfsError::Format(format!(
                "block range [{}, {end}) exceeds device block count {}",
                start.0,
                self.block_count()
            )));
        }
        Ok(())
    }

    fn validate_write_access(&self, cx: &Cx, block: BlockNumber) -> FfsResult<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        if self.reads_base_directly() {
            return Err(FfsError::UnsupportedFeature(
                "unregistered MVCC block device is read-only".to_owned(),
            ));
        }
        self.validate_range(block, 1)
    }

    fn validate_write_len(&self, actual: usize) -> FfsResult<()> {
        if actual != self.block_size() as usize {
            return Err(FfsError::Format(format!(
                "MVCC write length {actual} does not match block size {}",
                self.block_size()
            )));
        }
        Ok(())
    }

    fn validate_read_buf(&self, block: BlockNumber, buf: &BlockBuf) -> FfsResult<()> {
        if buf.as_slice().len() != self.block_size() as usize {
            return Err(FfsError::Corruption {
                block: block.0,
                detail: format!(
                    "MVCC read returned {} bytes for a {}-byte block",
                    buf.as_slice().len(),
                    self.block_size()
                ),
            });
        }
        Ok(())
    }

    fn rmw_with_proof(
        &self,
        cx: &Cx,
        block: BlockNumber,
        proof: MergeProof,
        patch: &mut dyn FnMut(&mut Vec<u8>) -> FfsResult<()>,
    ) -> FfsResult<()> {
        self.validate_write_access(cx, block)?;
        // Begin before reading, and retain the exact snapshot ancestor even if
        // another writer commits and prunes while the callback runs. All three
        // RMW variants use this gate so bitmap updates cannot bypass it.
        let mut txn = self.store.begin();
        let (buf, base) = self.read_merge_ancestor_at_snapshot(cx, block, txn.snapshot())?;
        let mut data = buf.into_inner();
        patch(&mut data)?;
        // A callback can resize the Vec or request cancellation. Neither may
        // publish a version; malformed data would otherwise panic a later read
        // or poison the durable flush. There is no fallible check AFTER commit.
        self.validate_write_len(data.len())?;
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        txn.stage_write_with_proof_and_base(block, data, proof, base);
        let commit_seq = self
            .store
            .commit(txn)
            .map_err(|error| commit_error_to_ffs(&error))?;
        self.store.prune_after_commit_if_due(commit_seq);
        Ok(())
    }
}

impl<D: BlockDevice> Drop for FsMvccBlockDevice<D> {
    fn drop(&mut self) {
        if let SnapshotOwnership::Inline { snapshot } = self.ownership {
            let released = self.store.release_snapshot(snapshot);
            debug_assert!(
                released,
                "mvcc snapshot was not registered or already released: {snapshot:?}"
            );
        }
    }
}

impl<D: BlockDevice> BlockDevice for FsMvccBlockDevice<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> FfsResult<BlockBuf> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        self.validate_range(block, 1)?;
        let buf = if self.reads_base_directly() {
            self.base.read_block(cx, block)?
        } else if let Some(buf) = self
            .store
            .read_visible_block_buf(block, self.read_snapshot())
        {
            buf
        } else {
            self.base.read_block(cx, block)?
        };
        self.validate_read_buf(block, &buf)?;
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        Ok(buf)
    }

    fn supports_contiguous_reads(&self) -> bool {
        self.base.supports_contiguous_reads()
    }

    fn read_contiguous_blocks(
        &self,
        cx: &Cx,
        start: BlockNumber,
        bufs: &mut [BlockBuf],
    ) -> FfsResult<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        if bufs.is_empty() {
            return Ok(());
        }
        let count = u64::try_from(bufs.len())
            .map_err(|_| FfsError::Format("block count does not fit u64".to_owned()))?;
        self.validate_range(start, count)?;
        if self.reads_base_directly() {
            self.base.read_contiguous_blocks(cx, start, bufs)?;
            for (delta, buf) in bufs.iter().enumerate() {
                self.validate_read_buf(BlockNumber(start.0 + delta as u64), buf)?;
            }
            return cx.checkpoint().map_err(|_| FfsError::Cancelled);
        }

        let snap = self.read_snapshot();
        let mut visible = Vec::with_capacity(bufs.len());
        let mut any_visible = false;
        for delta in 0..count {
            if delta.is_multiple_of(64) {
                cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            }
            let block = BlockNumber(start.0 + delta);
            match self.store.read_visible_block_buf(block, snap) {
                Some(buf) => {
                    self.validate_read_buf(block, &buf)?;
                    visible.push(Some(buf));
                    any_visible = true;
                }
                None => visible.push(None),
            }
        }
        if !any_visible {
            self.base.read_contiguous_blocks(cx, start, bufs)?;
            for (delta, buf) in bufs.iter().enumerate() {
                self.validate_read_buf(BlockNumber(start.0 + delta as u64), buf)?;
            }
            return cx.checkpoint().map_err(|_| FfsError::Cancelled);
        }

        let mut idx = 0usize;
        while idx < bufs.len() {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            if let Some(buf) = visible[idx].take() {
                bufs[idx] = buf;
                idx += 1;
                continue;
            }
            let run_start = idx;
            while idx < bufs.len() && visible[idx].is_none() {
                idx += 1;
            }
            let run_start_u64 = u64::try_from(run_start)
                .map_err(|_| FfsError::Format("block range exceeds u64".to_owned()))?;
            let run_block_start = BlockNumber(start.0 + run_start_u64);
            self.base
                .read_contiguous_blocks(cx, run_block_start, &mut bufs[run_start..idx])?;
            for (delta, buf) in bufs[run_start..idx].iter().enumerate() {
                self.validate_read_buf(BlockNumber(run_block_start.0 + delta as u64), buf)?;
            }
        }
        cx.checkpoint().map_err(|_| FfsError::Cancelled)
    }

    fn read_contiguous_into(&self, cx: &Cx, start: BlockNumber, dst: &mut [u8]) -> FfsResult<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let bs = self.block_size() as usize;
        if bs == 0 || !dst.len().is_multiple_of(bs) {
            return Err(FfsError::Format(
                "read_contiguous_into: dst length must be a multiple of block size".to_owned(),
            ));
        }
        if dst.is_empty() {
            return Ok(());
        }
        let count = dst.len() / bs;
        let count_u64 = u64::try_from(count)
            .map_err(|_| FfsError::Format("block range exceeds u64".to_owned()))?;
        self.validate_range(start, count_u64)?;
        if self.reads_base_directly() {
            self.base.read_contiguous_into(cx, start, dst)?;
            return cx.checkpoint().map_err(|_| FfsError::Cancelled);
        }

        let snap = self.read_snapshot();
        let mut visible = Vec::with_capacity(count);
        let mut any_visible = false;
        for delta in 0..count_u64 {
            if delta.is_multiple_of(64) {
                cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            }
            let block = BlockNumber(start.0 + delta);
            match self.store.read_visible_block_buf(block, snap) {
                Some(buf) => {
                    self.validate_read_buf(block, &buf)?;
                    visible.push(Some(buf));
                    any_visible = true;
                }
                None => visible.push(None),
            }
        }
        if !any_visible {
            self.base.read_contiguous_into(cx, start, dst)?;
            return cx.checkpoint().map_err(|_| FfsError::Cancelled);
        }

        let mut idx = 0usize;
        while idx < count {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            if let Some(buf) = visible[idx].take() {
                dst[idx * bs..(idx + 1) * bs].copy_from_slice(buf.as_slice());
                idx += 1;
                continue;
            }
            let run_start = idx;
            while idx < count && visible[idx].is_none() {
                idx += 1;
            }
            let run_start_u64 = u64::try_from(run_start)
                .map_err(|_| FfsError::Format("block range exceeds u64".to_owned()))?;
            let run_block_start = BlockNumber(start.0 + run_start_u64);
            self.base.read_contiguous_into(
                cx,
                run_block_start,
                &mut dst[run_start * bs..idx * bs],
            )?;
        }
        cx.checkpoint().map_err(|_| FfsError::Cancelled)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> FfsResult<()> {
        self.validate_write_access(cx, block)?;
        self.validate_write_len(data.len())?;
        let mut txn = self.store.begin();
        txn.stage_write(block, data.to_vec());
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let commit_seq = self
            .store
            .commit(txn)
            .map_err(|error| commit_error_to_ffs(&error))?;
        self.store.prune_after_commit_if_due(commit_seq);
        Ok(())
    }

    fn rmw_block(
        &self,
        cx: &Cx,
        block: BlockNumber,
        disjoint_ranges: &[(usize, usize)],
        patch: &mut dyn FnMut(&mut Vec<u8>) -> FfsResult<()>,
    ) -> FfsResult<()> {
        // Empty hint → identical to `write_block` (default `Unsafe` proof, no merge).
        // A non-empty hint stages a range-scoped `IndependentKeys` proof so writers
        // touching disjoint ranges of this block MERGE instead of FCW-conflicting.
        let proof = if disjoint_ranges.is_empty() {
            MergeProof::Unsafe
        } else {
            MergeProof::independent_keys(disjoint_ranges)
        };
        self.rmw_with_proof(cx, block, proof, patch)
    }

    fn rmw_block_bitmap_or(
        &self,
        cx: &Cx,
        block: BlockNumber,
        patch: &mut dyn FnMut(&mut Vec<u8>) -> FfsResult<()>,
    ) -> FfsResult<()> {
        self.rmw_with_proof(cx, block, MergeProof::BitmapOr, patch)
    }

    fn rmw_block_bitmap_delta(
        &self,
        cx: &Cx,
        block: BlockNumber,
        patch: &mut dyn FnMut(&mut Vec<u8>) -> FfsResult<()>,
    ) -> FfsResult<()> {
        self.rmw_with_proof(cx, block, MergeProof::BitmapDelta, patch)
    }

    fn read_merge_ancestor_at_snapshot(
        &self,
        cx: &Cx,
        block: BlockNumber,
        snapshot: Snapshot,
    ) -> FfsResult<(BlockBuf, Option<Vec<u8>>)> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        self.validate_range(block, 1)?;
        // Resolve the ancestor at the CALLER's snapshot, independent of this
        // device's own read-your-writes view. Retain the exact before-image even
        // when it came from MVCC: the caller can stage a batched transaction and
        // lose this version to pruning before commit. Re-deriving the ancestor
        // from that pruned chain would spuriously reject a disjoint merge. This
        // has the same owned-base contract as the auto-commit RMW paths above;
        // retaining bytes does not authorize overlapping changes or pin a read
        // snapshot that the caller has not registered.
        let buf = if let Some(buf) = self.store.read_visible_block_buf(block, snapshot) {
            buf
        } else {
            self.store
                .read_unversioned_base_at_snapshot(block, snapshot, || {
                    self.base.read_block(cx, block)
                })?
        };
        self.validate_read_buf(block, &buf)?;
        let base = buf.as_slice().to_vec();
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        Ok((buf, Some(base)))
    }

    fn block_size(&self) -> u32 {
        self.base.block_size()
    }

    fn block_count(&self) -> u64 {
        self.base.block_count()
    }

    fn sync(&self, cx: &Cx) -> FfsResult<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        self.base.sync(cx)
    }
}

#[cfg(test)]
mod block_device_tests {
    use super::*;
    use ffs_block::{ByteBlockDevice, FileByteDevice};
    use ffs_mvcc::ConflictPolicy;
    use tempfile::NamedTempFile;

    const BLOCK_SIZE: u32 = 4096;
    const BLOCK_COUNT: usize = 4;
    const BLOCK: BlockNumber = BlockNumber(1);

    #[derive(Clone, Copy)]
    enum RmwKind {
        Ranges,
        BitmapOr,
        BitmapDelta,
    }

    const RMW_KINDS: [RmwKind; 3] = [RmwKind::Ranges, RmwKind::BitmapOr, RmwKind::BitmapDelta];

    struct Fixture {
        image: NamedTempFile,
        store: Arc<FsMvccStore>,
        device: FsMvccBlockDevice<ByteBlockDevice<FileByteDevice>>,
    }

    impl Fixture {
        fn new(store: FsMvccStore) -> Self {
            let image = NamedTempFile::new().expect("image");
            std::fs::write(image.path(), vec![0xA5; BLOCK_SIZE as usize * BLOCK_COUNT])
                .expect("initialize image");
            let base = ByteBlockDevice::new(
                FileByteDevice::open(image.path()).expect("open image"),
                BLOCK_SIZE,
            )
            .expect("block device");
            let store = Arc::new(store);
            let device = FsMvccBlockDevice::new_unregistered(
                base,
                Arc::clone(&store),
                store.current_snapshot(),
            )
            .with_read_your_writes();
            Self {
                image,
                store,
                device,
            }
        }

        fn sharded() -> Self {
            let store = FsMvccStore::sharded();
            if let FsMvccStore::Sharded(shards) = &store {
                shards.set_conflict_policy(ConflictPolicy::SafeMerge);
            }
            Self::new(store)
        }

        fn commit(&self, block: BlockNumber, data: Vec<u8>) -> CommitSeq {
            let mut txn = self.store.begin();
            txn.stage_write(block, data);
            self.store.commit(txn).expect("commit")
        }

        fn assert_image_unchanged(&self) {
            assert_eq!(
                std::fs::read(self.image.path()).expect("read image"),
                vec![0xA5; BLOCK_SIZE as usize * BLOCK_COUNT]
            );
        }

        fn rmw(
            &self,
            kind: RmwKind,
            cx: &Cx,
            block: BlockNumber,
            patch: &mut dyn FnMut(&mut Vec<u8>) -> FfsResult<()>,
        ) -> FfsResult<()> {
            match kind {
                RmwKind::Ranges => self.device.rmw_block(cx, block, &[(0, 1)], patch),
                RmwKind::BitmapOr => self.device.rmw_block_bitmap_or(cx, block, patch),
                RmwKind::BitmapDelta => self.device.rmw_block_bitmap_delta(cx, block, patch),
            }
        }
    }

    #[test]
    fn merge_ancestor_retains_the_callers_snapshot_not_the_latest_view() {
        for store in [FsMvccStore::single(), FsMvccStore::sharded()] {
            let fixture = Fixture::new(store);
            let cx = Cx::for_testing();
            let original = vec![0x11; BLOCK_SIZE as usize];
            fixture.commit(BLOCK, original.clone());
            let snapshot = fixture.store.current_snapshot();
            fixture.commit(BLOCK, vec![0x22; BLOCK_SIZE as usize]);

            let (bytes, base) = fixture
                .device
                .read_merge_ancestor_at_snapshot(&cx, BLOCK, snapshot)
                .expect("snapshot ancestor");
            assert_eq!(bytes.as_slice(), original);
            assert_eq!(base.as_deref(), Some(original.as_slice()));
            assert_eq!(
                fixture
                    .device
                    .read_block(&cx, BLOCK)
                    .expect("latest")
                    .as_slice(),
                vec![0x22; BLOCK_SIZE as usize]
            );
            fixture.assert_image_unchanged();
        }
    }

    #[test]
    fn captured_merge_ancestor_survives_pruning_before_batched_commit() {
        let fixture = Fixture::sharded();
        let cx = Cx::for_testing();
        let original = vec![0x11; BLOCK_SIZE as usize];
        fixture.commit(BLOCK, original.clone());
        let mut delayed = fixture.store.begin();
        let snapshot = delayed.snapshot();
        let (bytes, base) = fixture
            .device
            .read_merge_ancestor_at_snapshot(&cx, BLOCK, snapshot)
            .expect("capture ancestor");
        let mut staged = bytes.into_inner();
        staged[0] = 0x22;

        let mut peer = original;
        peer[1] = 0x33;
        fixture.commit(BLOCK, peer.clone());
        fixture.store.prune_safe();
        assert!(fixture.store.read_visible(BLOCK, snapshot).is_none());
        delayed.stage_write_with_proof_and_base(
            BLOCK,
            staged,
            MergeProof::independent_keys(&[(0, 1)]),
            base,
        );
        fixture
            .store
            .commit(delayed)
            .expect("disjoint merge after prune");

        peer[0] = 0x22;
        assert_eq!(
            fixture
                .device
                .read_block(&cx, BLOCK)
                .expect("merged block")
                .as_slice(),
            peer
        );
        fixture.assert_image_unchanged();
    }

    #[test]
    fn captured_merge_ancestor_still_rejects_overlapping_writes_after_prune() {
        let fixture = Fixture::sharded();
        let cx = Cx::for_testing();
        fixture.commit(BLOCK, vec![0x11; BLOCK_SIZE as usize]);
        let mut delayed = fixture.store.begin();
        let (bytes, base) = fixture
            .device
            .read_merge_ancestor_at_snapshot(&cx, BLOCK, delayed.snapshot())
            .expect("capture ancestor");
        let mut staged = bytes.into_inner();
        let mut peer = staged.clone();
        staged[0] = 0x22;
        peer[0] = 0x33;
        fixture.commit(BLOCK, peer.clone());
        fixture.store.prune_safe();
        let before = fixture.store.current_snapshot();
        delayed.stage_write_with_proof_and_base(
            BLOCK,
            staged,
            MergeProof::independent_keys(&[(0, 1)]),
            base,
        );
        assert!(matches!(
            fixture.store.commit(delayed),
            Err(CommitError::Conflict { .. })
        ));
        assert_eq!(fixture.store.current_snapshot(), before);
        assert_eq!(
            fixture
                .device
                .read_block(&cx, BLOCK)
                .expect("peer block")
                .as_slice(),
            peer
        );
        fixture.assert_image_unchanged();
    }

    #[test]
    fn ancestor_pruned_before_capture_is_retryable_not_a_stale_disk_fallback() {
        let fixture = Fixture::sharded();
        let cx = Cx::for_testing();
        fixture.commit(BLOCK, vec![0x11; BLOCK_SIZE as usize]);
        let snapshot = fixture.store.current_snapshot();
        fixture.commit(BLOCK, vec![0x22; BLOCK_SIZE as usize]);
        fixture.store.prune_safe();
        assert!(fixture.store.read_visible(BLOCK, snapshot).is_none());
        let before = fixture.store.current_snapshot();
        let error = fixture
            .device
            .read_merge_ancestor_at_snapshot(&cx, BLOCK, snapshot)
            .expect_err("lost ancestor must not be replaced by stale disk bytes");
        assert!(matches!(error, FfsError::MvccConflict { block: 1, .. }));
        assert_eq!(error.to_errno(), libc::EAGAIN);
        assert_eq!(fixture.store.current_snapshot(), before);
        fixture.assert_image_unchanged();
    }

    #[test]
    fn ambiguous_device_fallback_refuses_before_io() {
        for store in [FsMvccStore::single(), FsMvccStore::sharded()] {
            let fixture = Fixture::new(store);
            let cx = Cx::for_testing();
            let snapshot = fixture.store.current_snapshot();
            fixture.commit(BLOCK, vec![0x22; BLOCK_SIZE as usize]);
            let mut called = false;
            let result = fixture
                .store
                .read_unversioned_base_at_snapshot(BLOCK, snapshot, || {
                    called = true;
                    fixture.device.base.read_block(&cx, BLOCK)
                });
            assert!(matches!(
                result,
                Err(FfsError::MvccConflict { block: 1, .. })
            ));
            assert!(!called);
            fixture.assert_image_unchanged();
        }
    }

    #[test]
    fn newer_commit_during_device_fallback_is_not_accepted_as_the_ancestor() {
        for store in [FsMvccStore::single(), FsMvccStore::sharded()] {
            let fixture = Fixture::new(store);
            let cx = Cx::for_testing();
            let snapshot = fixture.store.current_snapshot();
            let result = fixture
                .store
                .read_unversioned_base_at_snapshot(BLOCK, snapshot, || {
                    let bytes = fixture.device.base.read_block(&cx, BLOCK)?;
                    fixture.commit(BLOCK, vec![0x22; BLOCK_SIZE as usize]);
                    Ok(bytes)
                });
            assert!(matches!(
                result,
                Err(FfsError::MvccConflict { block: 1, .. })
            ));
            assert_eq!(fixture.store.current_snapshot().high.0, snapshot.high.0 + 1);
            assert_eq!(fixture.store.version_count(), 1);
            fixture.assert_image_unchanged();
        }
    }

    #[test]
    fn untouched_device_block_still_supplies_an_owned_merge_ancestor() {
        for store in [FsMvccStore::single(), FsMvccStore::sharded()] {
            let fixture = Fixture::new(store);
            let cx = Cx::for_testing();
            let (bytes, base) = fixture
                .device
                .read_merge_ancestor_at_snapshot(&cx, BLOCK, fixture.store.current_snapshot())
                .expect("untouched device ancestor");
            let expected = vec![0xA5; BLOCK_SIZE as usize];
            assert_eq!(bytes.as_slice(), expected);
            assert_eq!(base.as_deref(), Some(expected.as_slice()));
            assert_eq!(fixture.store.version_count(), 0);
            fixture.assert_image_unchanged();
        }
    }

    #[cfg(feature = "bhh0i_sharded_alloc")]
    #[test]
    fn inode_rmw_refuses_a_fallback_race_before_running_the_patch() {
        let fixture = Fixture::sharded();
        let cx = Cx::for_testing();
        let mut patched = false;
        let result = fixture.store.rmw_commit_block_with_proof(
            BLOCK,
            MergeProof::independent_keys(&[(0, 1)]),
            || {
                let bytes = fixture.device.base.read_block(&cx, BLOCK)?.into_inner();
                fixture.commit(BLOCK, vec![0x22; BLOCK_SIZE as usize]);
                Ok(bytes)
            },
            |_| {
                patched = true;
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(FfsError::MvccConflict { block: 1, .. })
        ));
        assert!(!patched);
        assert_eq!(fixture.store.version_count(), 1);
        fixture.assert_image_unchanged();
    }

    #[test]
    fn invalid_full_block_writes_never_publish_versions() {
        for store in [FsMvccStore::single(), FsMvccStore::sharded()] {
            let fixture = Fixture::new(store);
            let cx = Cx::for_testing();
            let before = fixture.store.current_snapshot();
            for len in [0, BLOCK_SIZE as usize - 1, BLOCK_SIZE as usize + 1] {
                assert!(matches!(
                    fixture.device.write_block(&cx, BLOCK, &vec![0x11; len]),
                    Err(FfsError::Format(_))
                ));
            }
            for block in [BlockNumber(BLOCK_COUNT as u64), BlockNumber(u64::MAX)] {
                assert!(matches!(
                    fixture
                        .device
                        .write_block(&cx, block, &vec![0x11; BLOCK_SIZE as usize]),
                    Err(FfsError::Format(_))
                ));
            }
            assert_eq!(fixture.store.current_snapshot(), before);
            assert_eq!(fixture.store.version_count(), 0);
            fixture.assert_image_unchanged();

            let last = BlockNumber(BLOCK_COUNT as u64 - 1);
            let data = vec![0x22; BLOCK_SIZE as usize];
            fixture
                .device
                .write_block(&cx, last, &data)
                .expect("valid write");
            assert_eq!(
                fixture
                    .device
                    .read_block(&cx, last)
                    .expect("read")
                    .as_slice(),
                data
            );
            fixture.assert_image_unchanged();
        }
    }

    #[test]
    fn all_rmw_paths_reject_resized_buffers_without_publishing() {
        for store in [FsMvccStore::single(), FsMvccStore::sharded()] {
            let fixture = Fixture::new(store);
            let cx = Cx::for_testing();
            for kind in RMW_KINDS {
                for len in [0, BLOCK_SIZE as usize - 1, BLOCK_SIZE as usize + 1] {
                    let before = fixture.store.current_snapshot();
                    assert!(matches!(
                        fixture.rmw(kind, &cx, BLOCK, &mut |data| {
                            data.resize(len, 0);
                            Ok(())
                        }),
                        Err(FfsError::Format(_))
                    ));
                    assert_eq!(fixture.store.current_snapshot(), before);
                    assert_eq!(fixture.store.version_count(), 0);
                }
            }
            fixture.assert_image_unchanged();
        }
    }

    #[test]
    fn all_rmw_paths_stop_before_invalid_targets_and_after_callback_failure() {
        for store in [FsMvccStore::single(), FsMvccStore::sharded()] {
            let fixture = Fixture::new(store);
            let cx = Cx::for_testing();
            for kind in RMW_KINDS {
                let mut called = false;
                assert!(matches!(
                    fixture.rmw(kind, &cx, BlockNumber(BLOCK_COUNT as u64), &mut |_| {
                        called = true;
                        Ok(())
                    }),
                    Err(FfsError::Format(_))
                ));
                assert!(!called);
                assert!(matches!(
                    fixture.rmw(kind, &cx, BLOCK, &mut |data| {
                        data[0] = 0;
                        Err(FfsError::NoSpace)
                    }),
                    Err(FfsError::NoSpace)
                ));
                assert_eq!(fixture.store.version_count(), 0);
            }
            fixture.assert_image_unchanged();
        }
    }

    #[test]
    fn all_rmw_paths_honor_callback_cancellation_before_commit() {
        for store in [FsMvccStore::single(), FsMvccStore::sharded()] {
            let fixture = Fixture::new(store);
            fixture.commit(BLOCK, vec![0x11; BLOCK_SIZE as usize]);
            for kind in RMW_KINDS {
                let cx = Cx::for_testing();
                let before = fixture.store.current_snapshot();
                let versions = fixture.store.version_count();
                assert!(matches!(
                    fixture.rmw(kind, &cx, BLOCK, &mut |data| {
                        data[0] |= 0x40;
                        cx.set_cancel_requested(true);
                        Ok(())
                    }),
                    Err(FfsError::Cancelled)
                ));
                assert_eq!(fixture.store.current_snapshot(), before);
                assert_eq!(fixture.store.version_count(), versions);
            }
            fixture.assert_image_unchanged();
        }
    }

    #[test]
    fn valid_rmw_variants_publish_exactly_one_complete_block() {
        for store in [FsMvccStore::single(), FsMvccStore::sharded()] {
            let fixture = Fixture::new(store);
            let cx = Cx::for_testing();
            for kind in RMW_KINDS {
                let before = fixture.store.current_snapshot();
                fixture
                    .rmw(kind, &cx, BLOCK, &mut |data| {
                        data[0] |= 0x40;
                        Ok(())
                    })
                    .expect("valid RMW");
                assert_eq!(fixture.store.current_snapshot().high.0, before.high.0 + 1);
                let mut expected = vec![0xA5; BLOCK_SIZE as usize];
                expected[0] |= 0x40;
                assert_eq!(
                    fixture
                        .device
                        .read_block(&cx, BLOCK)
                        .expect("read")
                        .as_slice(),
                    expected
                );
            }
            fixture.assert_image_unchanged();
        }
    }

    #[test]
    fn cancelled_requests_cannot_use_resident_versions_or_publish_writes() {
        for store in [FsMvccStore::single(), FsMvccStore::sharded()] {
            let fixture = Fixture::new(store);
            fixture.commit(BLOCK, vec![0x11; BLOCK_SIZE as usize]);
            let cx = Cx::for_testing();
            let mut bufs = vec![fixture.device.read_block(&cx, BLOCK).expect("seed buffer")];
            let before = fixture.store.current_snapshot();
            cx.set_cancel_requested(true);
            assert!(matches!(
                fixture.device.read_block(&cx, BLOCK),
                Err(FfsError::Cancelled)
            ));
            assert!(matches!(
                fixture
                    .device
                    .read_merge_ancestor_at_snapshot(&cx, BLOCK, before),
                Err(FfsError::Cancelled)
            ));
            assert!(matches!(
                fixture.device.read_contiguous_blocks(&cx, BLOCK, &mut bufs),
                Err(FfsError::Cancelled)
            ));
            let mut dst = vec![0xCC; BLOCK_SIZE as usize];
            assert!(matches!(
                fixture.device.read_contiguous_into(&cx, BLOCK, &mut dst),
                Err(FfsError::Cancelled)
            ));
            assert_eq!(dst, vec![0xCC; BLOCK_SIZE as usize]);
            assert!(matches!(
                fixture.device.write_block(&cx, BLOCK, &dst),
                Err(FfsError::Cancelled)
            ));
            for kind in RMW_KINDS {
                let mut called = false;
                assert!(matches!(
                    fixture.rmw(kind, &cx, BLOCK, &mut |_| {
                        called = true;
                        Ok(())
                    }),
                    Err(FfsError::Cancelled)
                ));
                assert!(!called);
            }
            assert_eq!(fixture.store.current_snapshot(), before);
            fixture.assert_image_unchanged();
        }
    }

    #[test]
    fn malformed_overlay_buffers_fail_closed_before_copy_or_patch() {
        for store in [FsMvccStore::single(), FsMvccStore::sharded()] {
            let fixture = Fixture::new(store);
            let cx = Cx::for_testing();
            // Deliberately bypass the adapter to model invalid replay/staged state.
            for len in [0, BLOCK_SIZE as usize - 1, BLOCK_SIZE as usize + 1] {
                fixture.commit(BLOCK, vec![0x11; len]);
                let before = fixture.store.current_snapshot();
                assert!(matches!(
                    fixture.device.read_block(&cx, BLOCK),
                    Err(FfsError::Corruption { block: 1, .. })
                ));
                let mut dst = vec![0xCC; 2 * BLOCK_SIZE as usize];
                assert!(matches!(
                    fixture
                        .device
                        .read_contiguous_into(&cx, BlockNumber(0), &mut dst),
                    Err(FfsError::Corruption { block: 1, .. })
                ));
                assert_eq!(dst, vec![0xCC; 2 * BLOCK_SIZE as usize]);
                let seed = fixture
                    .device
                    .base
                    .read_block(&cx, BlockNumber(0))
                    .expect("base");
                let mut bufs = vec![seed; 2];
                assert!(matches!(
                    fixture
                        .device
                        .read_contiguous_blocks(&cx, BlockNumber(0), &mut bufs),
                    Err(FfsError::Corruption { block: 1, .. })
                ));
                let expected = vec![0xA5; BLOCK_SIZE as usize];
                assert!(bufs.iter().all(|buf| buf.as_slice() == expected));
                for kind in RMW_KINDS {
                    let mut called = false;
                    assert!(matches!(
                        fixture.rmw(kind, &cx, BLOCK, &mut |_| {
                            called = true;
                            Ok(())
                        }),
                        Err(FfsError::Corruption { block: 1, .. })
                    ));
                    assert!(!called);
                }
                assert_eq!(fixture.store.current_snapshot(), before);
            }
            fixture.assert_image_unchanged();
        }
    }

    #[test]
    fn bulk_reads_validate_the_entire_range_before_modifying_output() {
        for store in [FsMvccStore::single(), FsMvccStore::sharded()] {
            let fixture = Fixture::new(store);
            let cx = Cx::for_testing();
            // An out-of-range overlay must not make an invalid device read succeed.
            fixture.commit(
                BlockNumber(BLOCK_COUNT as u64),
                vec![0x11; BLOCK_SIZE as usize],
            );
            for start in [BlockNumber(BLOCK_COUNT as u64 - 1), BlockNumber(u64::MAX)] {
                let mut dst = vec![0xCC; 2 * BLOCK_SIZE as usize];
                assert!(matches!(
                    fixture.device.read_contiguous_into(&cx, start, &mut dst),
                    Err(FfsError::Format(_))
                ));
                assert_eq!(dst, vec![0xCC; 2 * BLOCK_SIZE as usize]);
                let seed = fixture
                    .device
                    .base
                    .read_block(&cx, BlockNumber(0))
                    .expect("base");
                let mut bufs = vec![seed; 2];
                assert!(matches!(
                    fixture.device.read_contiguous_blocks(&cx, start, &mut bufs),
                    Err(FfsError::Format(_))
                ));
                let expected = vec![0xA5; BLOCK_SIZE as usize];
                assert!(bufs.iter().all(|buf| buf.as_slice() == expected));
            }
            assert!(matches!(
                fixture
                    .device
                    .read_block(&cx, BlockNumber(BLOCK_COUNT as u64)),
                Err(FfsError::Format(_))
            ));
            fixture.assert_image_unchanged();
        }
    }

    #[test]
    fn valid_bulk_reads_preserve_mixed_overlay_and_device_bytes() {
        for store in [FsMvccStore::single(), FsMvccStore::sharded()] {
            let fixture = Fixture::new(store);
            let cx = Cx::for_testing();
            fixture.commit(BlockNumber(1), vec![0x11; BLOCK_SIZE as usize]);
            fixture.commit(BlockNumber(3), vec![0x33; BLOCK_SIZE as usize]);
            let mut expected = vec![0xA5; BLOCK_COUNT * BLOCK_SIZE as usize];
            expected[BLOCK_SIZE as usize..2 * BLOCK_SIZE as usize].fill(0x11);
            expected[3 * BLOCK_SIZE as usize..].fill(0x33);
            let mut dst = vec![0; expected.len()];
            fixture
                .device
                .read_contiguous_into(&cx, BlockNumber(0), &mut dst)
                .expect("bulk read");
            assert_eq!(dst, expected);
            let seed = fixture
                .device
                .base
                .read_block(&cx, BlockNumber(0))
                .expect("base");
            let mut bufs = vec![seed; BLOCK_COUNT];
            fixture
                .device
                .read_contiguous_blocks(&cx, BlockNumber(0), &mut bufs)
                .expect("buffers");
            for (buf, bytes) in bufs
                .iter()
                .zip(expected.as_chunks::<{ BLOCK_SIZE as usize }>().0)
            {
                assert_eq!(buf.as_slice(), bytes);
            }
            fixture.assert_image_unchanged();
        }
    }
}
#[cfg(test)]
mod commit_error_mapping_tests {
    use super::commit_error_to_ffs;
    use ffs_error::FfsError;
    use ffs_mvcc::CommitError;
    use ffs_types::{BlockNumber, CommitSeq};

    /// bd-y2t0r: a first-committer-wins conflict must surface as `EAGAIN`, and
    /// this pins that deliberately rather than leaving it incidental.
    ///
    /// It is also a BEHAVIOUR CHANGE worth stating plainly: before the retry work
    /// these conflicts were flattened into `FfsError::Format`, which maps to
    /// `EINVAL`. `EINVAL` says the caller passed something invalid, which is
    /// false — nothing about the request was wrong, another writer simply
    /// committed the same block first. `EAGAIN` says "try again", which is what
    /// actually happened and what a caller can act on.
    ///
    /// Any caller that does NOT retry now surfaces `EAGAIN` where it previously
    /// surfaced `EINVAL`. That is an improvement, but it is a change, and a
    /// client keying on `EINVAL` for this case would need updating.
    #[test]
    fn a_first_committer_wins_conflict_maps_to_eagain_not_einval() {
        let conflict = CommitError::Conflict {
            block: BlockNumber(38),
            snapshot: CommitSeq(1),
            observed: CommitSeq(2),
        };
        let mapped = commit_error_to_ffs(&conflict);
        assert!(
            matches!(mapped, FfsError::MvccConflict { block: 38, .. }),
            "a conflict must keep its type and its block: {mapped:?}"
        );
        assert_eq!(
            mapped.to_errno(),
            libc::EAGAIN,
            "a transient conflict must be retryable, not reported as a bad argument"
        );
        assert_ne!(
            mapped.to_errno(),
            libc::EINVAL,
            "EINVAL was the PREVIOUS mapping and is wrong: the request was valid"
        );
    }

    /// Everything that is not a conflict keeps its previous shape, so the typed
    /// mapping did not widen beyond the one case that needed it.
    #[test]
    fn non_conflict_commit_failures_stay_format_errors() {
        let other = CommitError::DurabilityFailure {
            detail: "wal write failed".to_owned(),
        };
        assert!(matches!(commit_error_to_ffs(&other), FfsError::Format(_)));
    }
}
