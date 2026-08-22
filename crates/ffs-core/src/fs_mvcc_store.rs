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
    /// fresh. `read_base` supplies the block bytes only when the store holds no
    /// version at the snapshot (block still on the device); it must read the same
    /// block (its snapshot is immaterial — no version means no concurrent overlay).
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
            let device_base = read_base()?;
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
        if self.reads_base_directly() {
            return self.base.read_block(cx, block);
        }
        if let Some(buf) = self
            .store
            .read_visible_block_buf(block, self.read_snapshot())
        {
            return Ok(buf);
        }
        self.base.read_block(cx, block)
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
        if bufs.is_empty() {
            return Ok(());
        }
        let count = u64::try_from(bufs.len())
            .map_err(|_| FfsError::Format("block count does not fit u64".to_owned()))?;
        start
            .0
            .checked_add(count)
            .ok_or_else(|| FfsError::Format("block range overflow".to_owned()))?;
        if self.reads_base_directly() {
            return self.base.read_contiguous_blocks(cx, start, bufs);
        }

        let snap = self.read_snapshot();
        let mut visible = Vec::with_capacity(bufs.len());
        let mut any_visible = false;
        for delta in 0..count {
            let block = BlockNumber(start.0 + delta);
            match self.store.read_visible_block_buf(block, snap) {
                Some(buf) => {
                    visible.push(Some(buf));
                    any_visible = true;
                }
                None => visible.push(None),
            }
        }
        if !any_visible {
            return self.base.read_contiguous_blocks(cx, start, bufs);
        }

        let mut idx = 0usize;
        while idx < bufs.len() {
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
        }
        Ok(())
    }

    fn read_contiguous_into(&self, cx: &Cx, start: BlockNumber, dst: &mut [u8]) -> FfsResult<()> {
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
        start
            .0
            .checked_add(count_u64)
            .ok_or_else(|| FfsError::Format("block range overflow".to_owned()))?;
        if self.reads_base_directly() {
            return self.base.read_contiguous_into(cx, start, dst);
        }

        let snap = self.read_snapshot();
        let mut visible = Vec::with_capacity(count);
        let mut any_visible = false;
        for delta in 0..count_u64 {
            let block = BlockNumber(start.0 + delta);
            match self.store.read_visible_block_buf(block, snap) {
                Some(buf) => {
                    visible.push(Some(buf));
                    any_visible = true;
                }
                None => visible.push(None),
            }
        }
        if !any_visible {
            return self.base.read_contiguous_into(cx, start, dst);
        }

        let mut idx = 0usize;
        while idx < count {
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
        Ok(())
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> FfsResult<()> {
        if self.reads_base_directly() {
            return Err(FfsError::UnsupportedFeature(
                "unregistered MVCC block device is read-only".to_owned(),
            ));
        }

        let mut txn = self.store.begin();
        txn.stage_write(block, data.to_vec());
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
        if self.reads_base_directly() {
            return Err(FfsError::UnsupportedFeature(
                "unregistered MVCC block device is read-only".to_owned(),
            ));
        }
        // Begin the transaction FIRST, then read the base block AT the transaction's
        // snapshot (a read taken beforehand could observe an older version than the
        // txn — see `rmw_commit_block_with_proof`'s contract). When the store holds
        // no version at the snapshot, the block is still on the base device.
        let mut txn = self.store.begin();
        let snapshot = txn.snapshot();
        // Record the base-device content when no version exists at the snapshot,
        // so concurrent disjoint-range writers to the SAME freshly-allocated
        // block (e.g. two creates touching different group descriptors of a new
        // GDT block) merge instead of FCW-conflicting (bd-bhh0i; the version
        // chain gives an empty base otherwise).
        // Record the ancestor as `staged_base` ALWAYS, including when the store
        // holds a version at the snapshot. Relying on the version chain to still
        // hold it at commit time is what breaks: a concurrent
        // `prune_after_commit_if_due` can drop it between stage and commit, the
        // merge then resolves an EMPTY base, and a disjoint write is aborted on a
        // spurious length mismatch. `rmw_commit_block_with_proof` above already
        // records unconditionally for this exact reason (bd-bhh0i's inode-table
        // pruning race); these three device-level RMW paths were left behind, and
        // the gap only shows under enough load for a snapshot to age past a prune
        // (bd-y2t0r, block 2085).
        let (mut data, base) = if let Some(buf) = self.store.read_visible_block_buf(block, snapshot)
        {
            let resident = buf.as_slice().to_vec();
            (resident.clone(), Some(resident))
        } else {
            let device_base = self.base.read_block(cx, block)?.into_inner();
            (device_base.clone(), Some(device_base))
        };
        patch(&mut data)?;
        // Empty hint → identical to `write_block` (default `Unsafe` proof, no merge).
        // A non-empty hint stages a range-scoped `IndependentKeys` proof so writers
        // touching disjoint ranges of this block MERGE instead of FCW-conflicting.
        let proof = if disjoint_ranges.is_empty() {
            MergeProof::Unsafe
        } else {
            MergeProof::independent_keys(disjoint_ranges)
        };
        txn.stage_write_with_proof_and_base(block, data, proof, base);
        let commit_seq = self
            .store
            .commit(txn)
            .map_err(|error| commit_error_to_ffs(&error))?;
        self.store.prune_after_commit_if_due(commit_seq);
        Ok(())
    }

    fn rmw_block_bitmap_or(
        &self,
        cx: &Cx,
        block: BlockNumber,
        patch: &mut dyn FnMut(&mut Vec<u8>) -> FfsResult<()>,
    ) -> FfsResult<()> {
        if self.reads_base_directly() {
            return Err(FfsError::UnsupportedFeature(
                "unregistered MVCC block device is read-only".to_owned(),
            ));
        }
        // Same begin-first / read-base-at-snapshot contract as `rmw_block` (a
        // read taken before `begin` could observe an older version and silently
        // clobber a concurrent disjoint-bit writer). `patch` is the caller's
        // set-only bit mutation (allocation); staging `MergeProof::BitmapOr`
        // lets two concurrent allocators to disjoint blocks of the SAME group
        // bitmap block merge (`latest | staged`) instead of first-committer-wins
        // conflicting, even when their bits share a byte (bd-bhh0i BUG 4).
        let mut txn = self.store.begin();
        let snapshot = txn.snapshot();
        // Record the ancestor as `staged_base` ALWAYS, including when the store
        // holds a version at the snapshot. Relying on the version chain to still
        // hold it at commit time is what breaks: a concurrent
        // `prune_after_commit_if_due` can drop it between stage and commit, the
        // merge then resolves an EMPTY base, and a disjoint write is aborted on a
        // spurious length mismatch. `rmw_commit_block_with_proof` above already
        // records unconditionally for this exact reason (bd-bhh0i's inode-table
        // pruning race); these three device-level RMW paths were left behind, and
        // the gap only shows under enough load for a snapshot to age past a prune
        // (bd-y2t0r, block 2085).
        let (mut data, base) = if let Some(buf) = self.store.read_visible_block_buf(block, snapshot)
        {
            let resident = buf.as_slice().to_vec();
            (resident.clone(), Some(resident))
        } else {
            let device_base = self.base.read_block(cx, block)?.into_inner();
            (device_base.clone(), Some(device_base))
        };
        patch(&mut data)?;
        txn.stage_write_with_proof_and_base(block, data, MergeProof::BitmapOr, base);
        let commit_seq = self
            .store
            .commit(txn)
            .map_err(|error| commit_error_to_ffs(&error))?;
        self.store.prune_after_commit_if_due(commit_seq);
        Ok(())
    }

    fn rmw_block_bitmap_delta(
        &self,
        cx: &Cx,
        block: BlockNumber,
        patch: &mut dyn FnMut(&mut Vec<u8>) -> FfsResult<()>,
    ) -> FfsResult<()> {
        if self.reads_base_directly() {
            return Err(FfsError::UnsupportedFeature(
                "unregistered MVCC block device is read-only".to_owned(),
            ));
        }
        // Identical begin-first / read-base-at-snapshot contract as
        // `rmw_block_bitmap_or`; only the staged proof differs. `patch` may set
        // AND clear bits, so two threads whose create and unlink land in the same
        // inode-bitmap block merge on disjoint bits instead of first-committer-wins
        // conflicting (bd-y2t0r). Recording the base when no version exists at the
        // snapshot is what lets the merge see the true common ancestor.
        let mut txn = self.store.begin();
        let snapshot = txn.snapshot();
        // Record the ancestor as `staged_base` ALWAYS, including when the store
        // holds a version at the snapshot. Relying on the version chain to still
        // hold it at commit time is what breaks: a concurrent
        // `prune_after_commit_if_due` can drop it between stage and commit, the
        // merge then resolves an EMPTY base, and a disjoint write is aborted on a
        // spurious length mismatch. `rmw_commit_block_with_proof` above already
        // records unconditionally for this exact reason (bd-bhh0i's inode-table
        // pruning race); these three device-level RMW paths were left behind, and
        // the gap only shows under enough load for a snapshot to age past a prune
        // (bd-y2t0r, block 2085).
        let (mut data, base) = if let Some(buf) = self.store.read_visible_block_buf(block, snapshot)
        {
            let resident = buf.as_slice().to_vec();
            (resident.clone(), Some(resident))
        } else {
            let device_base = self.base.read_block(cx, block)?.into_inner();
            (device_base.clone(), Some(device_base))
        };
        patch(&mut data)?;
        txn.stage_write_with_proof_and_base(block, data, MergeProof::BitmapDelta, base);
        let commit_seq = self
            .store
            .commit(txn)
            .map_err(|error| commit_error_to_ffs(&error))?;
        self.store.prune_after_commit_if_due(commit_seq);
        Ok(())
    }

    fn read_merge_ancestor_at_snapshot(
        &self,
        cx: &Cx,
        block: BlockNumber,
        snapshot: Snapshot,
    ) -> FfsResult<(BlockBuf, Option<Vec<u8>>)> {
        // Resolve the ancestor at the CALLER's snapshot, independent of this
        // device's own read-your-writes view. A version at `snapshot` → the store
        // re-derives the base from its chain (record no base); otherwise the block
        // is only on the raw base device → return its bytes AND record them as
        // `staged_base` (mirrors the auto-commit rmw path).
        if let Some(buf) = self.store.read_visible_block_buf(block, snapshot) {
            Ok((buf, None))
        } else {
            let device = self.base.read_block(cx, block)?;
            let base = device.as_slice().to_vec();
            Ok((device, Some(base)))
        }
    }

    fn block_size(&self) -> u32 {
        self.base.block_size()
    }

    fn block_count(&self) -> u64 {
        self.base.block_count()
    }

    fn sync(&self, cx: &Cx) -> FfsResult<()> {
        self.base.sync(cx)
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
