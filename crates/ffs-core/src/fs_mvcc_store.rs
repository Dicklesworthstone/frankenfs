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

/// Number of independent buffer shards. A single mutex over the pending map
/// would replace one serialization point (the MVCC commit) with another, so the
/// buffer is striped by block number; each critical section is a hash lookup
/// plus a 4 KiB memcpy.
const MESSAGE_BUFFER_SHARDS: usize = 64;

/// Bε-tree-style message buffer for small metadata updates (bd-bhh0i lever 1).
///
/// The mounted create path read-modify-writes the SAME few hot blocks once per
/// file: for 512 creates into one directory that is 512 rewrites of one inode
/// bitmap block and ~32 inode-table blocks, each one its own `begin()` +
/// `commit()`. The updates are tiny (one bit; one 256-byte inode slot) and the
/// block set is small — the exact shape a Bε-tree amortizes by buffering
/// messages and flushing them in batches instead of pushing each one to its
/// node immediately.
///
/// So writes land here instead of opening a transaction, and drain into ONE
/// transaction at the durability boundary. The kernel cannot do this: ext4
/// journals in-place metadata updates, so each one is ordered work it must
/// perform. We only owe the operator durability at `fsync`.
///
/// **Visibility is not deferred, only durability.** The buffer is consulted
/// ahead of the version store on every read through this adapter, and it is
/// shared across adapters (one per `OpenFs`), so a buffered create is visible
/// to every other thread immediately — which is what POSIX requires. What is
/// deferred is the version-store commit and the device write, exactly the
/// tradeoff `gdt_persistence_deferred()` already makes for group descriptors.
///
/// A crash before `fsync` loses buffered metadata. That is POSIX-legal and is
/// the same exposure the existing group-descriptor deferral accepts.
pub struct MetadataMessageBuffer {
    shards: Vec<parking_lot::Mutex<rustc_hash::FxHashMap<BlockNumber, Vec<u8>>>>,
    pending: std::sync::atomic::AtomicUsize,
    /// Producers share this gate; a durability drain takes it exclusively.
    /// This makes the drain a linearization point: no write can land in a
    /// shard that has already been drained and then escape the current fsync.
    drain_gate: RwLock<()>,
    /// Drain threshold in blocks, so a workload that never fsyncs cannot grow
    /// the buffer without bound.
    capacity: usize,
}

impl MetadataMessageBuffer {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            shards: (0..MESSAGE_BUFFER_SHARDS)
                .map(|_| parking_lot::Mutex::new(rustc_hash::FxHashMap::default()))
                .collect(),
            pending: std::sync::atomic::AtomicUsize::new(0),
            drain_gate: RwLock::new(()),
            capacity,
        }
    }

    const fn shard_of(&self, block: BlockNumber) -> usize {
        // Block numbers on the hot metadata path are near-consecutive, so the
        // low bits are the discriminating ones.
        (block.0 as usize) % MESSAGE_BUFFER_SHARDS
    }

    /// Buffer one whole-block message, replacing any earlier pending one for the
    /// same block. Coalescing is the entire point: the 512th write of a block
    /// supersedes the previous 511 and only the survivor is ever committed.
    fn put(&self, block: BlockNumber, data: Vec<u8>) {
        let _producer = self.drain_gate.read();
        self.put_while_gated(block, data);
    }

    fn put_while_gated(&self, block: BlockNumber, data: Vec<u8>) {
        let shard = self.shard_of(block);
        let mut map = self.shards[shard].lock();
        if map.insert(block, data).is_none() {
            self.pending
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub(super) fn get(&self, block: BlockNumber) -> Option<Vec<u8>> {
        let _producer = self.drain_gate.read();
        let shard = self.shard_of(block);
        self.shards[shard].lock().get(&block).cloned()
    }

    /// Atomically patch one buffered block. Loading the committed/base value is
    /// done outside the shard mutex, then the shard is checked again so a peer
    /// that populated the block in the meantime wins and becomes our ancestor.
    /// The producer gate remains held throughout, preventing a drain between
    /// the ancestor read and publishing the replacement message.
    fn rmw(
        &self,
        block: BlockNumber,
        load_ancestor: impl FnOnce() -> FfsResult<Vec<u8>>,
        patch: &mut dyn FnMut(&mut Vec<u8>) -> FfsResult<()>,
    ) -> FfsResult<()> {
        let _producer = self.drain_gate.read();
        let shard = self.shard_of(block);

        {
            let mut map = self.shards[shard].lock();
            if let Some(current) = map.get_mut(&block) {
                let mut replacement = current.clone();
                patch(&mut replacement)?;
                *current = replacement;
                return Ok(());
            }
        }

        let ancestor = load_ancestor()?;
        let mut map = self.shards[shard].lock();
        if let Some(current) = map.get_mut(&block) {
            let mut replacement = current.clone();
            patch(&mut replacement)?;
            *current = replacement;
        } else {
            let mut replacement = ancestor;
            patch(&mut replacement)?;
            map.insert(block, replacement);
            self.pending
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    }

    /// True once the buffer holds at least `capacity` distinct blocks.
    fn is_full(&self) -> bool {
        self.pending.load(std::sync::atomic::Ordering::Relaxed) >= self.capacity
    }

    /// Remove and return every pending message.
    fn take_all_while_gated(&self) -> Vec<(BlockNumber, Vec<u8>)> {
        let mut drained = Vec::new();
        for shard in &self.shards {
            let mut map = shard.lock();
            drained.extend(map.drain());
        }
        self.pending.store(0, std::sync::atomic::Ordering::Relaxed);
        drained
    }

    /// Number of blocks currently buffered (diagnostic).
    #[must_use]
    pub fn pending_blocks(&self) -> usize {
        self.pending.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Drain every buffered message into ONE transaction and commit it. This is
    /// where the amortization is realized: N buffered updates to M distinct
    /// blocks cost one commit of M writes rather than N commits.
    ///
    /// # Errors
    /// Returns the commit error if the batched transaction cannot commit.
    pub fn drain_into(&self, store: &FsMvccStore) -> FfsResult<()> {
        let _drain = self.drain_gate.write();
        let drained = self.take_all_while_gated();
        if drained.is_empty() {
            return Ok(());
        }
        let mut txn = store.begin();
        // Keep the originals until commit succeeds so a rejected transaction
        // can restore the buffer without losing acknowledged metadata writes.
        for (block, data) in &drained {
            txn.stage_write(*block, data.clone());
        }
        let commit_seq = match store.commit(txn) {
            Ok(commit_seq) => commit_seq,
            Err(error) => {
                for (block, data) in drained {
                    self.put_while_gated(block, data);
                }
                return Err(FfsError::Format(error.to_string()));
            }
        };
        store.prune_after_commit_if_due(commit_seq);
        Ok(())
    }
}

/// The OpenFs MVCC store: single-lock or sharded, behind a uniform `&self` API.
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
        (commit_seq.0 != 0 && commit_seq.0 % MVCC_COMMIT_PRUNE_INTERVAL == 0)
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
        let (mut data, base) = match self.read_visible(block, snapshot) {
            Some(bytes) => (bytes.clone(), Some(bytes)),
            None => {
                let device_base = read_base()?;
                (device_base.clone(), Some(device_base))
            }
        };
        patch(&mut data)?;
        txn.stage_write_with_proof_and_base(block, data, proof, base);
        let commit_seq = self
            .commit(txn)
            .map_err(|error| FfsError::Format(error.to_string()))?;
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
    /// Bε message buffer (lever 1). When attached, whole-block metadata writes
    /// are buffered and coalesced instead of each opening its own transaction.
    buffer: Option<Arc<MetadataMessageBuffer>>,
}

impl<D: BlockDevice> FsMvccBlockDevice<D> {
    pub(super) fn new(base: D, store: Arc<FsMvccStore>, snapshot: Snapshot) -> Self {
        store.register_snapshot(snapshot);
        Self {
            base,
            store,
            ownership: SnapshotOwnership::Inline { snapshot },
            read_your_writes: false,
            buffer: None,
        }
    }

    pub(super) fn new_unregistered(base: D, store: Arc<FsMvccStore>, snapshot: Snapshot) -> Self {
        Self {
            base,
            store,
            ownership: SnapshotOwnership::Unregistered { snapshot },
            read_your_writes: false,
            buffer: None,
        }
    }

    /// Attach the Bε message buffer (lever 1). Whole-block writes are then
    /// coalesced in memory and committed as one batch at the durability
    /// boundary instead of one transaction each.
    pub(super) fn with_message_buffer(mut self, buffer: Arc<MetadataMessageBuffer>) -> Self {
        self.buffer = Some(buffer);
        self
    }

    /// Read the current content of `block` through the same precedence a read
    /// would see (buffer, then version store, then device), patch it, and buffer
    /// the result. Used by both RMW entry points when the buffer is attached.
    ///
    /// The merge proof is deliberately dropped: a buffered block is never staged
    /// in a concurrent transaction, so there is no first-committer-wins race for
    /// a proof to resolve. Serialization happens on the buffer shard instead,
    /// which is a hash lookup and a memcpy rather than a commit.
    fn buffered_rmw(
        &self,
        cx: &Cx,
        buffer: &Arc<MetadataMessageBuffer>,
        block: BlockNumber,
        patch: &mut dyn FnMut(&mut Vec<u8>) -> FfsResult<()>,
    ) -> FfsResult<()> {
        buffer.rmw(
            block,
            || match self
                .store
                .read_visible_block_buf(block, self.store.current_snapshot())
            {
                Some(buf) => Ok(buf.as_slice().to_vec()),
                None => Ok(self.base.read_block(cx, block)?.into_inner()),
            },
            patch,
        )?;
        if buffer.is_full() {
            buffer.drain_into(&self.store)?;
        }
        Ok(())
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
        // A buffered message is newer than any committed version by
        // construction, so it wins. This is what keeps VISIBILITY immediate
        // while durability is deferred.
        if let Some(buffered) = self.buffer.as_ref().and_then(|b| b.get(block)) {
            return Ok(BlockBuf::new(buffered));
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
            match self
                .buffer
                .as_ref()
                .and_then(|buffer| buffer.get(block))
                .map(BlockBuf::new)
                .or_else(|| self.store.read_visible_block_buf(block, snap))
            {
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
        if bs == 0 || dst.len() % bs != 0 {
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
            match self
                .buffer
                .as_ref()
                .and_then(|buffer| buffer.get(block))
                .map(BlockBuf::new)
                .or_else(|| self.store.read_visible_block_buf(block, snap))
            {
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

        // Bε: buffer the message instead of paying begin()+commit() per write.
        if let Some(buffer) = self.buffer.as_ref() {
            buffer.put(block, data.to_vec());
            if buffer.is_full() {
                buffer.drain_into(&self.store)?;
            }
            return Ok(());
        }

        let mut txn = self.store.begin();
        txn.stage_write(block, data.to_vec());
        let commit_seq = self
            .store
            .commit(txn)
            .map_err(|error| FfsError::Format(error.to_string()))?;
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
        if let Some(buffer) = self.buffer.as_ref() {
            return self.buffered_rmw(cx, buffer, block, patch);
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
        let (mut data, base) = match self.store.read_visible_block_buf(block, snapshot) {
            Some(buf) => (buf.as_slice().to_vec(), None),
            None => {
                let device_base = self.base.read_block(cx, block)?.into_inner();
                (device_base.clone(), Some(device_base))
            }
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
            .map_err(|error| FfsError::Format(error.to_string()))?;
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
        if let Some(buffer) = self.buffer.as_ref() {
            return self.buffered_rmw(cx, buffer, block, patch);
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
        let (mut data, base) = match self.store.read_visible_block_buf(block, snapshot) {
            Some(buf) => (buf.as_slice().to_vec(), None),
            None => {
                let device_base = self.base.read_block(cx, block)?.into_inner();
                (device_base.clone(), Some(device_base))
            }
        };
        patch(&mut data)?;
        txn.stage_write_with_proof_and_base(block, data, MergeProof::BitmapOr, base);
        let commit_seq = self
            .store
            .commit(txn)
            .map_err(|error| FfsError::Format(error.to_string()))?;
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
        match self.store.read_visible_block_buf(block, snapshot) {
            Some(buf) => Ok((buf, None)),
            None => {
                let device = self.base.read_block(cx, block)?;
                let base = device.as_slice().to_vec();
                Ok((device, Some(base)))
            }
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
