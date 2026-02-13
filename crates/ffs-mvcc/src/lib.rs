#![forbid(unsafe_code)]

pub mod compression;
pub mod persist;
pub mod sharded;
pub mod wal;

use asupersync::Cx;
pub use compression::CompressionPolicy;
use compression::{CompressionStats, VersionData};
use crossbeam_epoch as epoch;
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result as FfsResult};
use ffs_types::{BlockNumber, CommitSeq, Snapshot, TxnId};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockVersion {
    pub block: BlockNumber,
    pub commit_seq: CommitSeq,
    pub writer: TxnId,
    pub data: VersionData,
}

impl BlockVersion {
    /// Convenience: get inline bytes if this is a Full version, None for Identical.
    #[must_use]
    pub fn bytes_inline(&self) -> Option<&[u8]> {
        self.data.as_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalBlockVersion {
    pub logical: BlockNumber,
    pub physical: BlockNumber,
    pub commit_seq: CommitSeq,
    pub writer: TxnId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct CowRewriteIntent {
    old_physical: Option<BlockNumber>,
    new_physical: BlockNumber,
}

pub trait CowAllocator {
    /// Allocate a new physical block for a COW write.
    fn alloc_cow(&self, hint: Option<BlockNumber>, cx: &Cx) -> FfsResult<BlockNumber>;

    /// Mark a block as deferrable until the given commit is no longer visible.
    fn defer_free(&self, block: BlockNumber, commit_seq: CommitSeq);

    /// Free all deferred blocks eligible at `watermark`.
    fn gc_free(&self, watermark: CommitSeq, cx: &Cx) -> usize;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub id: TxnId,
    pub snapshot: Snapshot,
    writes: BTreeMap<BlockNumber, Vec<u8>>,
    /// Blocks read during the transaction's lifetime.  Each entry maps
    /// the block to the `CommitSeq` of the version that was read (or
    /// `CommitSeq(0)` if the block had no version at that snapshot).
    ///
    /// Populated by `record_read`.  Used by SSI conflict detection.
    reads: BTreeMap<BlockNumber, CommitSeq>,
    /// COW rewrite metadata for logical blocks staged in this transaction.
    ///
    /// This tracks the newly allocated physical location and the physical
    /// location that will become free after commit.
    cow_writes: BTreeMap<BlockNumber, CowRewriteIntent>,
    /// Newly allocated physical blocks superseded by a later write in the
    /// same transaction. These blocks never became visible and should be
    /// deferred for freeing on commit.
    cow_orphans: BTreeSet<BlockNumber>,
}

impl Transaction {
    /// Create a new transaction at the given snapshot.
    #[must_use]
    pub(crate) fn new(id: TxnId, snapshot: Snapshot) -> Self {
        Self {
            id,
            snapshot,
            writes: BTreeMap::new(),
            reads: BTreeMap::new(),
            cow_writes: BTreeMap::new(),
            cow_orphans: BTreeSet::new(),
        }
    }

    /// The transaction's unique ID.
    #[must_use]
    pub fn id(&self) -> TxnId {
        self.id
    }

    /// The snapshot this transaction reads at.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot
    }

    /// Consume the transaction and return its staged writes.
    pub(crate) fn into_writes(self) -> BTreeMap<BlockNumber, Vec<u8>> {
        self.writes
    }

    pub fn stage_write(&mut self, block: BlockNumber, bytes: Vec<u8>) {
        self.writes.insert(block, bytes);
    }

    fn stage_cow_rewrite(
        &mut self,
        logical: BlockNumber,
        old_physical: Option<BlockNumber>,
        new_physical: BlockNumber,
        bytes: Vec<u8>,
    ) {
        if let Some(previous) = self.cow_writes.insert(
            logical,
            CowRewriteIntent {
                old_physical,
                new_physical,
            },
        ) {
            self.cow_orphans.insert(previous.new_physical);
            trace!(
                txn_id = self.id.0,
                logical = logical.0,
                orphan_physical = previous.new_physical.0,
                "cow_orphan_staged_for_free"
            );
        }
        self.writes.insert(logical, bytes);
    }

    #[must_use]
    pub fn staged_write(&self, block: BlockNumber) -> Option<&[u8]> {
        self.writes.get(&block).map(Vec::as_slice)
    }

    #[must_use]
    pub fn pending_writes(&self) -> usize {
        self.writes.len()
    }

    /// Record that `block` was read at version `version_seq`.
    ///
    /// This is required for SSI conflict detection.  When using FCW-only
    /// mode this is a no-op — reads are not tracked and the `reads` map
    /// stays empty.
    ///
    /// Only the *first* read of a given block is recorded (the version
    /// seen at the transaction's snapshot).  Subsequent reads of the same
    /// block are no-ops.
    pub fn record_read(&mut self, block: BlockNumber, version_seq: CommitSeq) {
        use std::collections::btree_map::Entry;
        if let Entry::Vacant(e) = self.reads.entry(block) {
            e.insert(version_seq);
            trace!(
                target: "ffs::ssi",
                block_num = block.0,
                version_seen = version_seq.0,
                txn_id = self.id.0,
                read_set_size = self.reads.len(),
                "read_set_add"
            );
        }
    }

    /// The set of blocks this transaction has read (and their version).
    #[must_use]
    pub fn read_set(&self) -> &BTreeMap<BlockNumber, CommitSeq> {
        &self.reads
    }

    /// The set of blocks this transaction will write.
    #[must_use]
    pub fn write_set(&self) -> &BTreeMap<BlockNumber, Vec<u8>> {
        &self.writes
    }

    #[must_use]
    pub fn staged_physical(&self, block: BlockNumber) -> Option<BlockNumber> {
        self.cow_writes.get(&block).map(|w| w.new_physical)
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
    #[error(
        "SSI: dangerous structure detected — rw-antidependency cycle via block {pivot_block} \
         (this txn read it at {read_version:?}, concurrent txn {concurrent_txn:?} wrote it at {write_version:?})"
    )]
    SsiConflict {
        pivot_block: BlockNumber,
        read_version: CommitSeq,
        write_version: CommitSeq,
        concurrent_txn: TxnId,
    },
    #[error(
        "version chain backpressure on block {block}: len={chain_len}, cap={cap}, critical={critical_len}, watermark={watermark:?}"
    )]
    ChainBackpressure {
        block: BlockNumber,
        chain_len: usize,
        cap: usize,
        critical_len: usize,
        watermark: CommitSeq,
    },
}

/// Record of a committed transaction kept for SSI antidependency checking.
///
/// `snapshot` and `read_set` are retained for future bidirectional SSI
/// (checking if the committer's reads were invalidated by a *later*
/// concurrent reader that also committed).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct CommittedTxnRecord {
    pub(crate) txn_id: TxnId,
    pub(crate) commit_seq: CommitSeq,
    pub(crate) snapshot: Snapshot,
    pub(crate) write_set: BTreeSet<BlockNumber>,
    pub(crate) read_set: BTreeMap<BlockNumber, CommitSeq>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EbrVersionStats {
    pub retired_versions: u64,
    pub reclaimed_versions: u64,
}

impl EbrVersionStats {
    #[must_use]
    pub fn pending_versions(self) -> u64 {
        self.retired_versions
            .saturating_sub(self.reclaimed_versions)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockVersionStats {
    pub tracked_blocks: usize,
    pub max_chain_length: usize,
    pub chains_over_cap: usize,
    pub chains_over_critical: usize,
    pub chain_cap: Option<usize>,
    pub critical_chain_length: Option<usize>,
}

#[derive(Debug, Clone)]
struct EbrVersionReclaimer {
    collector: Arc<epoch::Collector>,
    retired_versions: Arc<AtomicU64>,
    reclaimed_versions: Arc<AtomicU64>,
}

impl Default for EbrVersionReclaimer {
    fn default() -> Self {
        Self {
            collector: Arc::new(epoch::Collector::new()),
            retired_versions: Arc::new(AtomicU64::new(0)),
            reclaimed_versions: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl EbrVersionReclaimer {
    fn retire_versions(&self, retired: Vec<BlockVersion>) {
        if retired.is_empty() {
            return;
        }
        let handle = self.collector.register();
        let guard = handle.pin();
        for version in retired {
            self.retired_versions.fetch_add(1, Ordering::Relaxed);
            let reclaimed = Arc::clone(&self.reclaimed_versions);
            guard.defer(move || {
                drop(version);
                reclaimed.fetch_add(1, Ordering::Relaxed);
            });
        }
    }

    fn collect(&self) {
        let passes = usize::try_from(self.stats().pending_versions().clamp(1, 8)).unwrap_or(8);
        for _ in 0..passes {
            let handle = self.collector.register();
            handle.pin().flush();
            if self.stats().pending_versions() == 0 {
                break;
            }
            std::thread::yield_now();
        }
    }

    fn stats(&self) -> EbrVersionStats {
        EbrVersionStats {
            retired_versions: self.retired_versions.load(Ordering::Relaxed),
            reclaimed_versions: self.reclaimed_versions.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MvccStore {
    next_txn: u64,
    next_commit: u64,
    versions: BTreeMap<BlockNumber, Vec<BlockVersion>>,
    physical_versions: BTreeMap<BlockNumber, Vec<PhysicalBlockVersion>>,
    /// Active snapshots: each entry is a `CommitSeq` from which a reader is
    /// still potentially reading.  The set uses a `BTreeMap` so that the
    /// minimum (oldest active snapshot) can be obtained in O(log n).
    ///
    /// Callers **must** pair every `register_snapshot` with a corresponding
    /// `release_snapshot` to avoid preventing GC indefinitely.
    ///
    /// NOTE: For new code, prefer using [`SnapshotRegistry`] + [`SnapshotHandle`]
    /// which provide thread-safe RAII lifecycle management decoupled from the
    /// version store lock.  These inline methods are retained for backward
    /// compatibility and for use in single-threaded / test contexts.
    active_snapshots: BTreeMap<CommitSeq, u32>,
    /// Recent committed transactions retained for SSI antidependency
    /// checking.  Pruned by `prune_ssi_log`.
    ssi_log: Vec<CommittedTxnRecord>,
    /// Version chain compression policy.
    compression_policy: CompressionPolicy,
    /// Epoch-based reclaimer for retired logical block versions.
    ebr_reclaimer: EbrVersionReclaimer,
}

impl Default for MvccStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MvccStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_txn: 1,
            next_commit: 1,
            versions: BTreeMap::new(),
            physical_versions: BTreeMap::new(),
            active_snapshots: BTreeMap::new(),
            ssi_log: Vec::new(),
            compression_policy: CompressionPolicy::default(),
            ebr_reclaimer: EbrVersionReclaimer::default(),
        }
    }

    /// Create a store with a custom compression policy.
    #[must_use]
    pub fn with_compression_policy(policy: CompressionPolicy) -> Self {
        Self {
            compression_policy: policy,
            ..Self::new()
        }
    }

    /// Returns the current compression policy.
    #[must_use]
    pub fn compression_policy(&self) -> &CompressionPolicy {
        &self.compression_policy
    }

    /// Compute compression statistics across all version chains.
    #[must_use]
    pub fn compression_stats(&self) -> CompressionStats {
        let mut stats = CompressionStats::default();
        for versions in self.versions.values() {
            for (idx, version) in versions.iter().enumerate() {
                match &version.data {
                    VersionData::Full(bytes) => {
                        stats.full_versions += 1;
                        stats.bytes_stored += bytes.len();
                    }
                    VersionData::Identical => {
                        stats.identical_versions += 1;
                        // Estimate bytes saved: use the resolved data size
                        if let Some(bytes) =
                            compression::resolve_data_with(versions, idx, |v| &v.data)
                        {
                            stats.bytes_saved += bytes.len();
                        }
                    }
                }
            }
        }
        stats
    }

    /// Epoch-based retirement/reclamation counters for logical block versions.
    #[must_use]
    pub fn ebr_stats(&self) -> EbrVersionStats {
        self.ebr_reclaimer.stats()
    }

    /// Best-effort collection pass for deferred version reclamation.
    pub fn ebr_collect(&self) {
        self.ebr_reclaimer.collect();
    }

    /// Chain-length monitoring snapshot for logical block versions.
    #[must_use]
    pub fn block_version_stats(&self) -> BlockVersionStats {
        let tracked_blocks = self.versions.len();
        let max_chain_length = self.versions.values().map(Vec::len).max().unwrap_or(0);
        let chain_cap = self.compression_policy.max_chain_length;
        let critical_chain_length = chain_cap.map(Self::critical_chain_len);

        let mut chains_over_cap = 0_usize;
        let mut chains_over_critical = 0_usize;
        if let Some(cap) = chain_cap {
            let critical = Self::critical_chain_len(cap);
            for chain in self.versions.values() {
                chains_over_cap += usize::from(chain.len() > cap);
                chains_over_critical += usize::from(chain.len() >= critical);
            }
        }

        BlockVersionStats {
            tracked_blocks,
            max_chain_length,
            chains_over_cap,
            chains_over_critical,
            chain_cap,
            critical_chain_length,
        }
    }

    fn critical_chain_len(max_len: usize) -> usize {
        let cap = max_len.max(1);
        cap.saturating_mul(4).max(cap.saturating_add(1))
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
            reads: BTreeMap::new(),
            cow_writes: BTreeMap::new(),
            cow_orphans: BTreeSet::new(),
        };
        self.next_txn = self.next_txn.saturating_add(1);
        txn
    }

    pub fn commit(&mut self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        self.commit_fcw_internal(txn)
            .map(|(commit_seq, _)| commit_seq)
    }

    pub fn commit_with_cow_allocator(
        &mut self,
        txn: Transaction,
        allocator: &dyn CowAllocator,
        cx: &Cx,
    ) -> Result<CommitSeq, CommitError> {
        let (commit_seq, deferred) = self.commit_fcw_internal(txn)?;
        for block in deferred {
            trace!(block = block.0, commit_seq = commit_seq.0, "cow_defer_free");
            allocator.defer_free(block, commit_seq);
        }
        let _ = self.gc_cow_blocks(allocator, cx);
        Ok(commit_seq)
    }

    /// Commit with Serializable Snapshot Isolation (SSI) enforcement.
    ///
    /// This extends FCW with rw-antidependency tracking.  A "dangerous
    /// structure" is detected when:
    ///
    /// 1. This transaction **read** block B at version V.
    /// 2. A concurrent transaction (committed after our snapshot) **wrote**
    ///    a newer version of B (i.e., `latest_commit_seq(B) > V` AND
    ///    the writer committed after our snapshot).
    /// 3. This transaction itself has writes — so it's not read-only.
    ///
    /// This is the simplified "first-updater-wins + read-set check" variant
    /// of SSI (as used by PostgreSQL).  Read-only transactions never trigger
    /// SSI aborts.
    pub fn commit_ssi(&mut self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        self.commit_ssi_internal(txn)
            .map(|(commit_seq, _)| commit_seq)
    }

    pub fn commit_ssi_with_cow_allocator(
        &mut self,
        txn: Transaction,
        allocator: &dyn CowAllocator,
        cx: &Cx,
    ) -> Result<CommitSeq, CommitError> {
        let (commit_seq, deferred) = self.commit_ssi_internal(txn)?;
        for block in deferred {
            trace!(block = block.0, commit_seq = commit_seq.0, "cow_defer_free");
            allocator.defer_free(block, commit_seq);
        }
        let _ = self.gc_cow_blocks(allocator, cx);
        Ok(commit_seq)
    }

    fn commit_fcw_internal(
        &mut self,
        txn: Transaction,
    ) -> Result<(CommitSeq, Vec<BlockNumber>), CommitError> {
        let chain_cap = self.compression_policy.max_chain_length;
        for block in txn.writes.keys() {
            let latest = self.latest_commit_seq(*block);
            if latest > txn.snapshot.high {
                return Err(CommitError::Conflict {
                    block: *block,
                    snapshot: txn.snapshot.high,
                    observed: latest,
                });
            }
            if let Some(cap) = chain_cap {
                self.enforce_chain_pressure(*block, cap)?;
            }
        }

        let Transaction {
            id: txn_id,
            snapshot: _,
            writes,
            reads: _,
            cow_writes,
            cow_orphans,
        } = txn;

        let commit_seq = CommitSeq(self.next_commit);
        self.next_commit = self.next_commit.saturating_add(1);
        let dedup_enabled = self.compression_policy.dedup_identical;

        for (block, bytes) in writes {
            let version_data = if dedup_enabled {
                self.maybe_dedup(block, &bytes)
            } else {
                VersionData::Full(bytes)
            };

            self.versions.entry(block).or_default().push(BlockVersion {
                block,
                commit_seq,
                writer: txn_id,
                data: version_data,
            });

            if let Some(intent) = cow_writes.get(&block) {
                self.physical_versions
                    .entry(block)
                    .or_default()
                    .push(PhysicalBlockVersion {
                        logical: block,
                        physical: intent.new_physical,
                        commit_seq,
                        writer: txn_id,
                    });
            }

            if let Some(cap) = chain_cap {
                self.enforce_chain_cap(block, cap);
                self.enforce_physical_chain_cap(block, cap);
            }
        }

        let deferred = Self::collect_cow_deferred_frees(&cow_writes, cow_orphans);
        Ok((commit_seq, deferred))
    }

    fn commit_ssi_internal(
        &mut self,
        txn: Transaction,
    ) -> Result<(CommitSeq, Vec<BlockNumber>), CommitError> {
        let chain_cap = self.compression_policy.max_chain_length;
        // Step 1: FCW check (write-write conflicts).
        for block in txn.writes.keys() {
            let latest = self.latest_commit_seq(*block);
            if latest > txn.snapshot.high {
                return Err(CommitError::Conflict {
                    block: *block,
                    snapshot: txn.snapshot.high,
                    observed: latest,
                });
            }
            if let Some(cap) = chain_cap {
                self.enforce_chain_pressure(*block, cap)?;
            }
        }

        // Step 2: SSI rw-antidependency check (phantom detection).
        let checks_performed = self.validate_ssi_read_set(&txn)?;

        let Transaction {
            id: txn_id,
            snapshot,
            writes,
            reads,
            cow_writes,
            cow_orphans,
        } = txn;

        let commit_seq = CommitSeq(self.next_commit);
        self.next_commit = self.next_commit.saturating_add(1);
        let dedup_enabled = self.compression_policy.dedup_identical;

        let write_keys: BTreeSet<BlockNumber> = writes.keys().copied().collect();
        for (block, bytes) in writes {
            let version_data = if dedup_enabled {
                self.maybe_dedup(block, &bytes)
            } else {
                VersionData::Full(bytes)
            };

            self.versions.entry(block).or_default().push(BlockVersion {
                block,
                commit_seq,
                writer: txn_id,
                data: version_data,
            });

            if let Some(intent) = cow_writes.get(&block) {
                self.physical_versions
                    .entry(block)
                    .or_default()
                    .push(PhysicalBlockVersion {
                        logical: block,
                        physical: intent.new_physical,
                        commit_seq,
                        writer: txn_id,
                    });
            }

            if let Some(cap) = chain_cap {
                self.enforce_chain_cap(block, cap);
                self.enforce_physical_chain_cap(block, cap);
            }
        }

        let read_set_size = reads.len();
        let write_set_size = write_keys.len();
        self.ssi_log.push(CommittedTxnRecord {
            txn_id,
            commit_seq,
            snapshot,
            write_set: write_keys,
            read_set: reads,
        });

        info!(
            target: "ffs::ssi",
            txn_id = txn_id.0,
            read_set_size,
            write_set_size,
            checks_performed,
            commit_seq = commit_seq.0,
            "ssi_commit_validated"
        );

        let deferred = Self::collect_cow_deferred_frees(&cow_writes, cow_orphans);
        Ok((commit_seq, deferred))
    }

    /// Check if `new_bytes` are identical to the latest version for `block`.
    /// If so, return `VersionData::Identical` (dedup); otherwise `VersionData::Full`.
    fn maybe_dedup(&self, block: BlockNumber, new_bytes: &[u8]) -> VersionData {
        if let Some(versions) = self.versions.get(&block) {
            if !versions.is_empty() {
                // Resolve the latest version's data (might itself be Identical).
                if let Some(existing) =
                    compression::resolve_data_with(versions, versions.len() - 1, |v| &v.data)
                    && existing == new_bytes
                {
                    trace!(
                        block = block.0,
                        chain_len = versions.len(),
                        bytes_saved = new_bytes.len(),
                        "version_dedup: identical to previous"
                    );
                    return VersionData::Identical;
                }
            }
        }
        VersionData::Full(new_bytes.to_vec())
    }

    fn validate_ssi_read_set(&self, txn: &Transaction) -> Result<u64, CommitError> {
        if txn.writes.is_empty() {
            return Ok(0);
        }

        let mut checks_performed = 0_u64;
        for (&block, &read_version) in &txn.reads {
            let mut found_conflict = None;
            for record in self.ssi_log.iter().rev() {
                if record.commit_seq <= txn.snapshot.high {
                    break;
                }
                checks_performed += 1;
                if record.write_set.contains(&block) {
                    found_conflict = Some((record.commit_seq, record.txn_id));
                    break;
                }
            }
            if let Some((write_version, concurrent_txn)) = found_conflict {
                debug!(
                    target: "ffs::ssi",
                    txn_id = txn.id.0,
                    concurrent_txn = concurrent_txn.0,
                    pivot_block = block.0,
                    read_version = read_version.0,
                    write_version = write_version.0,
                    cycle = %format_args!(
                        "T{} -rw[block {}]-> T{}: T{} read block {} at seq {}, T{} committed write at seq {}",
                        txn.id.0, block.0, concurrent_txn.0,
                        txn.id.0, block.0, read_version.0,
                        concurrent_txn.0, write_version.0
                    ),
                    "dangerous_structure"
                );
                warn!(
                    target: "ffs::ssi",
                    txn_id = txn.id.0,
                    concurrent_txn = concurrent_txn.0,
                    pivot_block = block.0,
                    conflict_type = "write_skew",
                    action = "abort",
                    "ssi_conflict"
                );
                return Err(CommitError::SsiConflict {
                    pivot_block: block,
                    read_version,
                    write_version,
                    concurrent_txn,
                });
            }
            trace!(
                target: "ffs::ssi",
                txn_id = txn.id.0,
                block_num = block.0,
                snapshot_ver = read_version.0,
                is_phantom = false,
                "phantom_check"
            );
        }
        Ok(checks_performed)
    }

    fn force_advance_oldest_snapshot(&mut self) -> Option<(CommitSeq, u32)> {
        let oldest = self.active_snapshots.keys().next().copied()?;
        let remaining_refs = {
            let count = self
                .active_snapshots
                .get_mut(&oldest)
                .expect("oldest snapshot must exist");
            *count = count.saturating_sub(1);
            *count
        };
        if remaining_refs == 0 {
            self.active_snapshots.remove(&oldest);
        }
        Some((oldest, remaining_refs))
    }

    fn chain_trim_blocked_by_snapshot(&self, block: BlockNumber, watermark: CommitSeq) -> bool {
        self.versions
            .get(&block)
            .is_some_and(|versions| versions.len() > 1 && versions[1].commit_seq > watermark)
    }

    fn enforce_chain_pressure(
        &mut self,
        block: BlockNumber,
        max_len: usize,
    ) -> Result<(), CommitError> {
        let chain_len = self.versions.get(&block).map_or(0, Vec::len);
        if chain_len == 0 {
            return Ok(());
        }
        let max_len = max_len.max(1);
        let critical_len = Self::critical_chain_len(max_len);
        if chain_len < critical_len {
            return Ok(());
        }

        let watermark = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        if !self.chain_trim_blocked_by_snapshot(block, watermark) {
            return Ok(());
        }

        warn!(
            target: "ffs::mvcc::gc",
            block = block.0,
            chain_len,
            cap = max_len,
            critical_len,
            watermark = watermark.0,
            "chain_pressure_snapshot_blocking"
        );

        if let Some((forced_snapshot, remaining_refs)) = self.force_advance_oldest_snapshot() {
            let new_watermark = self
                .watermark()
                .unwrap_or_else(|| self.current_snapshot().high);
            info!(
                target: "ffs::mvcc::gc",
                block = block.0,
                forced_snapshot = forced_snapshot.0,
                remaining_refs,
                new_watermark = new_watermark.0,
                "chain_pressure_force_advance_oldest_snapshot"
            );
            if !self.chain_trim_blocked_by_snapshot(block, new_watermark) {
                return Ok(());
            }
        }

        error!(
            target: "ffs::mvcc::gc",
            block = block.0,
            chain_len,
            cap = max_len,
            critical_len,
            watermark = watermark.0,
            "chain_backpressure_reject"
        );
        Err(CommitError::ChainBackpressure {
            block,
            chain_len,
            cap: max_len,
            critical_len,
            watermark,
        })
    }

    /// Enforce chain length cap for a block by pruning the oldest versions.
    ///
    /// Pruning is watermark-aware: versions are only dropped when doing so
    /// cannot break visibility for any active snapshot.
    fn enforce_chain_cap(&mut self, block: BlockNumber, max_len: usize) {
        let max_len = max_len.max(1);
        let watermark = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        let retired = self
            .versions
            .get_mut(&block)
            .map_or_else(Vec::new, |versions| {
                let (trimmed, retired_versions) =
                    Self::trim_block_chain_to_cap(versions, max_len, watermark);
                if trimmed > 0 {
                    Self::ensure_chain_head_full(versions);
                    trace!(
                        block = block.0,
                        watermark = watermark.0,
                        trimmed,
                        remaining = versions.len(),
                        "chain_cap_enforced"
                    );
                } else if versions.len() > max_len {
                    debug!(
                        target: "ffs::mvcc::gc",
                        block = block.0,
                        watermark = watermark.0,
                        cap = max_len,
                        current_len = versions.len(),
                        "chain_cap_pending_snapshot_release"
                    );
                }
                retired_versions
            });
        if !retired.is_empty() {
            self.ebr_reclaimer.retire_versions(retired);
        }
    }

    /// Enforce chain cap for physical versions using the same watermark-safe
    /// rule as logical versions.
    fn enforce_physical_chain_cap(&mut self, block: BlockNumber, max_len: usize) {
        let max_len = max_len.max(1);
        let watermark = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        if let Some(versions) = self.physical_versions.get_mut(&block) {
            let trimmed = Self::trim_physical_chain_to_cap(versions, max_len, watermark);
            if trimmed > 0 {
                trace!(
                    block = block.0,
                    watermark = watermark.0,
                    trimmed,
                    remaining = versions.len(),
                    "physical_chain_cap_enforced"
                );
            }
        }
    }

    fn trim_block_chain_to_cap(
        versions: &mut Vec<BlockVersion>,
        max_len: usize,
        watermark: CommitSeq,
    ) -> (usize, Vec<BlockVersion>) {
        let mut trim = 0_usize;
        while versions.len().saturating_sub(trim) > max_len {
            let next = trim + 1;
            if next >= versions.len() || versions[next].commit_seq > watermark {
                break;
            }
            trim += 1;
        }
        let retired = if trim > 0 {
            versions.drain(0..trim).collect()
        } else {
            Vec::new()
        };
        (trim, retired)
    }

    fn trim_physical_chain_to_cap(
        versions: &mut Vec<PhysicalBlockVersion>,
        max_len: usize,
        watermark: CommitSeq,
    ) -> usize {
        let mut trim = 0_usize;
        while versions.len().saturating_sub(trim) > max_len {
            let next = trim + 1;
            if next >= versions.len() || versions[next].commit_seq > watermark {
                break;
            }
            trim += 1;
        }
        if trim > 0 {
            versions.drain(0..trim);
        }
        trim
    }

    fn ensure_chain_head_full(versions: &mut [BlockVersion]) {
        if versions.first().is_none_or(|v| !v.data.is_identical()) {
            return;
        }
        if let Some(full_data) = versions
            .iter()
            .find_map(|v| v.data.as_bytes().map(ToOwned::to_owned))
        {
            versions[0].data = VersionData::Full(full_data);
        }
    }

    fn collect_cow_deferred_frees(
        cow_writes: &BTreeMap<BlockNumber, CowRewriteIntent>,
        mut cow_orphans: BTreeSet<BlockNumber>,
    ) -> Vec<BlockNumber> {
        for intent in cow_writes.values() {
            if let Some(old_physical) = intent.old_physical
                && old_physical != intent.new_physical
            {
                cow_orphans.insert(old_physical);
            }
        }
        cow_orphans.into_iter().collect()
    }

    /// Prune SSI log entries older than `watermark`.
    ///
    /// Once no active transaction has a snapshot older than `watermark`,
    /// those log entries can no longer participate in antidependency
    /// detection and can be safely removed.
    pub fn prune_ssi_log(&mut self, watermark: CommitSeq) {
        self.ssi_log.retain(|r| r.commit_seq > watermark);
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
            let idx = versions
                .iter()
                .rposition(|v| v.commit_seq <= snapshot.high)?;
            compression::resolve_data_with(versions, idx, |v| &v.data)
        })
    }

    #[must_use]
    pub fn read_visible_physical(
        &self,
        logical: BlockNumber,
        snapshot: Snapshot,
    ) -> Option<BlockNumber> {
        if let Some(versions) = self.physical_versions.get(&logical)
            && let Some(version) = versions
                .iter()
                .rev()
                .find(|version| version.commit_seq <= snapshot.high)
        {
            return Some(version.physical);
        }
        self.read_visible(logical, snapshot).map(|_| logical)
    }

    #[must_use]
    pub fn latest_physical_block(&self, logical: BlockNumber) -> Option<BlockNumber> {
        self.read_visible_physical(logical, self.current_snapshot())
    }

    pub fn write_cow(
        &self,
        logical: BlockNumber,
        data: &[u8],
        txn: &mut Transaction,
        allocator: &dyn CowAllocator,
        cx: &Cx,
    ) -> FfsResult<BlockNumber> {
        let committed_old = txn
            .cow_writes
            .get(&logical)
            .and_then(|intent| intent.old_physical)
            .or_else(|| self.read_visible_physical(logical, txn.snapshot));
        let allocation_hint = txn
            .cow_writes
            .get(&logical)
            .map(|intent| intent.new_physical)
            .or(committed_old);
        let new_physical = allocator.alloc_cow(allocation_hint, cx)?;
        trace!(
            txn_id = txn.id.0,
            logical = logical.0,
            old_physical = committed_old.map(|b| b.0),
            new_physical = new_physical.0,
            "cow_allocation"
        );
        txn.stage_cow_rewrite(logical, committed_old, new_physical, data.to_vec());
        Ok(new_physical)
    }

    pub fn gc_cow_blocks(&self, allocator: &dyn CowAllocator, cx: &Cx) -> usize {
        let watermark = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        let freed = allocator.gc_free(watermark, cx);
        debug!(watermark = watermark.0, freed_blocks = freed, "cow_gc");
        freed
    }

    pub fn prune_versions_older_than(&mut self, watermark: CommitSeq) {
        let mut retired_versions = Vec::new();
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
                retired_versions.extend(versions.drain(0..keep_from));
                Self::ensure_chain_head_full(versions);
            }
        }
        if !retired_versions.is_empty() {
            self.ebr_reclaimer.retire_versions(retired_versions);
        }

        for versions in self.physical_versions.values_mut() {
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
        let count = self.active_snapshots.entry(snapshot.high).or_insert(0);
        *count += 1;
        trace!(
            commit_seq = snapshot.high.0,
            ref_count_after = *count,
            "snapshot_acquire (inline)"
        );
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
            let count_after = *count;
            if count_after == 0 {
                self.active_snapshots.remove(&snapshot.high);
                debug!(
                    commit_seq = snapshot.high.0,
                    "snapshot_final_release (inline): ref_count reached 0"
                );
            } else {
                trace!(
                    commit_seq = snapshot.high.0,
                    ref_count_after = count_after,
                    "snapshot_release (inline)"
                );
            }
            true
        } else {
            error!(
                commit_seq = snapshot.high.0,
                "ref_count_underflow (inline): release called on unregistered snapshot"
            );
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
        let old_count = self.version_count();
        let wm = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        self.prune_versions_older_than(wm);
        let new_count = self.version_count();
        let freed = old_count.saturating_sub(new_count);
        if freed > 0 {
            debug!(
                watermark = wm.0,
                versions_freed = freed,
                versions_remaining = new_count,
                "watermark_advance: pruned old versions"
            );
        } else {
            trace!(
                watermark = wm.0,
                versions_count = new_count,
                "gc_eligible: no versions to prune"
            );
        }
        if !self.active_snapshots.is_empty() {
            trace!(
                active_snapshots = self.active_snapshot_count(),
                oldest_active = ?self.watermark(),
                "gc_blocked: active snapshots prevent full pruning"
            );
        }
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

// ── SnapshotRegistry: thread-safe, standalone snapshot lifecycle ──────────────

/// Thread-safe snapshot registry for managing active snapshot lifetimes.
///
/// This is decoupled from `MvccStore` so that FUSE request handlers can
/// acquire/release snapshots without holding the version-store lock.
/// Snapshot operations only contend on the registry's internal lock.
#[derive(Debug)]
pub struct SnapshotRegistry {
    active: RwLock<BTreeMap<CommitSeq, u32>>,
    /// Timestamp of the oldest currently active snapshot registration.
    /// Used for stall detection.
    oldest_registered_at: RwLock<Option<Instant>>,
    /// Duration threshold beyond which a stalled watermark is logged.
    stall_threshold_secs: u64,
    // Counters for metrics (monotonic).
    acquired_total: std::sync::atomic::AtomicU64,
    released_total: std::sync::atomic::AtomicU64,
}

impl Default for SnapshotRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotRegistry {
    /// Create a new empty registry with the default stall threshold (60s).
    #[must_use]
    pub fn new() -> Self {
        Self {
            active: RwLock::new(BTreeMap::new()),
            oldest_registered_at: RwLock::new(None),
            stall_threshold_secs: 60,
            acquired_total: std::sync::atomic::AtomicU64::new(0),
            released_total: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create a registry with a custom stall threshold.
    #[must_use]
    pub fn with_stall_threshold(stall_threshold_secs: u64) -> Self {
        Self {
            stall_threshold_secs,
            ..Self::new()
        }
    }

    /// Acquire a snapshot handle from an `Arc<SnapshotRegistry>`.
    ///
    /// The snapshot is registered as active and will prevent GC of versions
    /// at or after this commit sequence until the returned handle is dropped.
    pub fn acquire(this: &Arc<Self>, snapshot: Snapshot) -> SnapshotHandle {
        this.register(snapshot);
        SnapshotHandle {
            snapshot,
            registry: Arc::clone(this),
        }
    }

    /// Register a snapshot as active (increment ref count).
    pub fn register(&self, snapshot: Snapshot) {
        let mut active = self.active.write();
        let count = active.entry(snapshot.high).or_insert(0);
        *count += 1;
        let count_after = *count;

        // Track oldest registration time.
        if active.len() == 1 || self.oldest_registered_at.read().is_none() {
            *self.oldest_registered_at.write() = Some(Instant::now());
        }
        drop(active);

        self.acquired_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        trace!(
            commit_seq = snapshot.high.0,
            ref_count_after = count_after,
            "snapshot_acquire"
        );
    }

    /// Release a previously registered snapshot (decrement ref count).
    ///
    /// Returns `true` if the snapshot was still registered, `false` if
    /// it was already fully released (caller bug, but not fatal).
    pub fn release(&self, snapshot: Snapshot) -> bool {
        let mut active = self.active.write();
        let Some(mut count_after) = active.get(&snapshot.high).copied() else {
            error!(
                commit_seq = snapshot.high.0,
                "ref_count_underflow: release called on unregistered snapshot"
            );
            return false;
        };

        let mut clear_oldest = false;
        let mut reset_oldest = false;
        count_after = count_after.saturating_sub(1);
        if count_after == 0 {
            active.remove(&snapshot.high);
            debug!(
                commit_seq = snapshot.high.0,
                "snapshot_final_release: ref_count reached 0"
            );
            if active.is_empty() {
                clear_oldest = true;
            } else {
                reset_oldest = true;
            }
        } else {
            active.insert(snapshot.high, count_after);
            trace!(
                commit_seq = snapshot.high.0,
                ref_count_after = count_after,
                "snapshot_release"
            );
        }
        drop(active);
        if clear_oldest {
            *self.oldest_registered_at.write() = None;
        } else if reset_oldest {
            // Reset to now — imprecise but avoids tracking per-snapshot times.
            *self.oldest_registered_at.write() = Some(Instant::now());
        }

        self.released_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    }

    /// The oldest active snapshot (safe GC watermark), or `None` if empty.
    #[must_use]
    pub fn watermark(&self) -> Option<CommitSeq> {
        self.active.read().keys().next().copied()
    }

    /// Total number of active snapshot references (counting duplicates).
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.read().values().map(|c| *c as usize).sum()
    }

    /// Number of distinct commit sequences with active snapshots.
    #[must_use]
    pub fn distinct_count(&self) -> usize {
        self.active.read().len()
    }

    /// Check for stalled watermark and log if threshold exceeded.
    ///
    /// Returns `Some(stall_duration_secs)` if stalled, `None` otherwise.
    pub fn check_stalls(&self) -> Option<u64> {
        let oldest = *self.oldest_registered_at.read();
        if let (Some(registered_at), Some(wm)) = (oldest, self.watermark()) {
            let elapsed = registered_at.elapsed().as_secs();
            if elapsed >= self.stall_threshold_secs {
                info!(
                    current_watermark = wm.0,
                    oldest_active = wm.0,
                    stall_duration_secs = elapsed,
                    "watermark_stall: oldest active snapshot held for > {}s",
                    self.stall_threshold_secs
                );
                return Some(elapsed);
            }
        }
        None
    }

    /// Total snapshots acquired since creation (monotonic counter).
    #[must_use]
    pub fn acquired_total(&self) -> u64 {
        self.acquired_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total snapshots released since creation (monotonic counter).
    #[must_use]
    pub fn released_total(&self) -> u64 {
        self.released_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// RAII handle that releases a snapshot when dropped.
///
/// Acquire via [`SnapshotRegistry::acquire_from`].  The snapshot remains
/// active (preventing GC of versions at or after its commit sequence)
/// until this handle is dropped.  Panic-safe: `Drop` is always called.
#[derive(Debug)]
pub struct SnapshotHandle {
    snapshot: Snapshot,
    registry: Arc<SnapshotRegistry>,
}

impl SnapshotHandle {
    /// The snapshot this handle protects.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot
    }

    /// Reference to the underlying registry.
    #[must_use]
    pub fn registry(&self) -> &Arc<SnapshotRegistry> {
        &self.registry
    }
}

impl Drop for SnapshotHandle {
    fn drop(&mut self) {
        let released = self.registry.release(self.snapshot);
        debug_assert!(
            released,
            "SnapshotHandle: snapshot was not registered or already released: {:?}",
            self.snapshot
        );
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
///
/// Snapshot ownership mode for `MvccBlockDevice`.
///
/// Either the device manages its snapshot via the `MvccStore`'s inline
/// tracking (legacy) or via a standalone [`SnapshotHandle`] (preferred).
#[derive(Debug)]
enum SnapshotOwnership {
    /// Snapshot registered on MvccStore; released in Drop.
    Inline { snapshot: Snapshot },
    /// Snapshot managed by a SnapshotHandle (RAII, auto-released on drop).
    Handle { handle: SnapshotHandle },
}

#[derive(Debug)]
pub struct MvccBlockDevice<D: BlockDevice> {
    base: D,
    store: Arc<RwLock<MvccStore>>,
    ownership: SnapshotOwnership,
}

impl<D: BlockDevice> MvccBlockDevice<D> {
    /// Create a new MVCC block device at a given snapshot.
    ///
    /// The `store` is shared across all devices/transactions that
    /// participate in the same MVCC group.  The snapshot is tracked
    /// via `MvccStore`'s inline active_snapshots.
    pub fn new(base: D, store: Arc<RwLock<MvccStore>>, snapshot: Snapshot) -> Self {
        store.write().register_snapshot(snapshot);
        Self {
            base,
            store,
            ownership: SnapshotOwnership::Inline { snapshot },
        }
    }

    /// Create a new MVCC block device using a [`SnapshotRegistry`] for
    /// lifecycle management.
    ///
    /// The snapshot is tracked via the registry's RAII handle, which
    /// decouples snapshot lifecycle from the version-store lock.
    pub fn with_registry(
        base: D,
        store: Arc<RwLock<MvccStore>>,
        snapshot: Snapshot,
        registry: &Arc<SnapshotRegistry>,
    ) -> Self {
        let handle = SnapshotRegistry::acquire(registry, snapshot);
        Self {
            base,
            store,
            ownership: SnapshotOwnership::Handle { handle },
        }
    }

    /// The snapshot this device reads at.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        match &self.ownership {
            SnapshotOwnership::Inline { snapshot } => *snapshot,
            SnapshotOwnership::Handle { handle } => handle.snapshot(),
        }
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

impl<D: BlockDevice> Drop for MvccBlockDevice<D> {
    fn drop(&mut self) {
        match &self.ownership {
            SnapshotOwnership::Inline { snapshot } => {
                let released = self.store.write().release_snapshot(*snapshot);
                debug_assert!(
                    released,
                    "mvcc snapshot was not registered or already released: {snapshot:?}"
                );
            }
            SnapshotOwnership::Handle { .. } => {
                // SnapshotHandle's own Drop handles release.
            }
        }
    }
}

impl<D: BlockDevice> BlockDevice for MvccBlockDevice<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> ffs_error::Result<BlockBuf> {
        let snap = self.snapshot();
        // Check version store first (shared lock, no I/O).
        {
            let guard = self.store.read();
            if let Some(bytes) = guard.read_visible(block, snap) {
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
    use std::collections::{BTreeSet, HashMap};

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

    #[derive(Debug)]
    struct TestCowAllocator {
        next_block: std::sync::atomic::AtomicU64,
        allocated: parking_lot::Mutex<Vec<BlockNumber>>,
        deferred: parking_lot::Mutex<Vec<(BlockNumber, CommitSeq)>>,
        freed: parking_lot::Mutex<Vec<BlockNumber>>,
    }

    impl TestCowAllocator {
        fn new(start: u64) -> Self {
            Self {
                next_block: std::sync::atomic::AtomicU64::new(start),
                allocated: parking_lot::Mutex::new(Vec::new()),
                deferred: parking_lot::Mutex::new(Vec::new()),
                freed: parking_lot::Mutex::new(Vec::new()),
            }
        }

        fn allocated_blocks(&self) -> Vec<BlockNumber> {
            self.allocated.lock().clone()
        }

        fn freed_blocks(&self) -> Vec<BlockNumber> {
            self.freed.lock().clone()
        }
    }

    impl CowAllocator for TestCowAllocator {
        fn alloc_cow(&self, _hint: Option<BlockNumber>, _cx: &Cx) -> FfsResult<BlockNumber> {
            let next = self
                .next_block
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let block = BlockNumber(next);
            self.allocated.lock().push(block);
            Ok(block)
        }

        fn defer_free(&self, block: BlockNumber, commit_seq: CommitSeq) {
            self.deferred.lock().push((block, commit_seq));
        }

        fn gc_free(&self, watermark: CommitSeq, _cx: &Cx) -> usize {
            let mut deferred = self.deferred.lock();
            let mut still_deferred = Vec::with_capacity(deferred.len());
            let mut newly_freed = Vec::new();
            for (block, retire_seq) in deferred.drain(..) {
                if retire_seq <= watermark {
                    newly_freed.push(block);
                } else {
                    still_deferred.push((block, retire_seq));
                }
            }
            *deferred = still_deferred;
            drop(deferred);
            let freed_count = newly_freed.len();
            self.freed.lock().extend(newly_freed);
            freed_count
        }
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
            CommitError::SsiConflict { .. } => panic!("unexpected SSI conflict from FCW path"),
            CommitError::ChainBackpressure { .. } => {
                panic!("unexpected chain backpressure from FCW path")
            }
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

    #[test]
    fn cow_write_allocates_new_physical_block() {
        let cx = test_cx();
        let mut store = MvccStore::new();
        let allocator = TestCowAllocator::new(1_000);
        let logical = BlockNumber(7);

        let mut txn = store.begin();
        let new_physical = store
            .write_cow(logical, &[0xAB; 8], &mut txn, &allocator, &cx)
            .expect("cow allocation");
        assert_ne!(new_physical, logical);
        assert_eq!(txn.staged_physical(logical), Some(new_physical));

        let commit_seq = store
            .commit_with_cow_allocator(txn, &allocator, &cx)
            .expect("cow commit");
        assert_eq!(commit_seq, CommitSeq(1));

        let latest = store.current_snapshot();
        assert_eq!(store.read_visible(logical, latest).unwrap(), &[0xAB; 8]);
        assert_eq!(store.latest_physical_block(logical), Some(new_physical));
        assert!(allocator.freed_blocks().is_empty());
    }

    #[test]
    fn cow_preserves_old_snapshot_and_gc_frees_after_release() {
        let cx = test_cx();
        let mut store = MvccStore::new();
        let allocator = TestCowAllocator::new(2_000);
        let logical = BlockNumber(13);

        let mut seed = store.begin();
        seed.stage_write(logical, vec![0x11; 4]);
        store.commit(seed).expect("seed commit");

        let old_snapshot = store.current_snapshot();
        store.register_snapshot(old_snapshot);

        let mut txn = store.begin();
        let new_physical = store
            .write_cow(logical, &[0x22; 4], &mut txn, &allocator, &cx)
            .expect("cow allocation");
        store
            .commit_with_cow_allocator(txn, &allocator, &cx)
            .expect("cow commit");

        assert_eq!(
            store.read_visible(logical, old_snapshot).unwrap(),
            &[0x11; 4]
        );
        assert_eq!(
            store.read_visible_physical(logical, old_snapshot),
            Some(logical)
        );
        assert_eq!(store.latest_physical_block(logical), Some(new_physical));
        assert!(allocator.freed_blocks().is_empty());

        assert!(store.release_snapshot(old_snapshot));
        let freed_now = store.gc_cow_blocks(&allocator, &cx);
        assert_eq!(freed_now, 1);
        assert_eq!(allocator.freed_blocks(), vec![logical]);
    }

    #[test]
    fn cow_hundred_rewrites_produce_unique_physical_blocks() {
        let cx = test_cx();
        let mut store = MvccStore::new();
        let allocator = TestCowAllocator::new(3_000);
        let logical = BlockNumber(99);
        let mut seen = BTreeSet::new();

        for i in 0_u8..100_u8 {
            let mut txn = store.begin();
            let physical = store
                .write_cow(logical, &[i], &mut txn, &allocator, &cx)
                .expect("cow allocation");
            assert!(seen.insert(physical), "physical block was reused");
            store
                .commit_with_cow_allocator(txn, &allocator, &cx)
                .expect("cow commit");
        }

        assert_eq!(seen.len(), 100);
        assert_eq!(allocator.allocated_blocks().len(), 100);
        assert_eq!(
            store.latest_physical_block(logical),
            allocator.allocated_blocks().last().copied()
        );
    }

    #[test]
    fn cow_gc_reclaims_all_deferred_blocks_after_snapshot_release() {
        let cx = test_cx();
        let mut store = MvccStore::new();
        let allocator = TestCowAllocator::new(4_000);
        let logical = BlockNumber(17);

        let mut seed = store.begin();
        seed.stage_write(logical, vec![0xAA; 2]);
        store.commit(seed).expect("seed commit");

        let held_snapshot = store.current_snapshot();
        store.register_snapshot(held_snapshot);

        for i in 0_u8..5_u8 {
            let mut txn = store.begin();
            store
                .write_cow(logical, &[i; 2], &mut txn, &allocator, &cx)
                .expect("cow allocation");
            store
                .commit_with_cow_allocator(txn, &allocator, &cx)
                .expect("cow commit");
        }

        assert!(allocator.freed_blocks().is_empty());

        assert!(store.release_snapshot(held_snapshot));
        let freed_now = store.gc_cow_blocks(&allocator, &cx);
        assert_eq!(freed_now, 5);

        let freed_set: BTreeSet<BlockNumber> = allocator.freed_blocks().into_iter().collect();
        assert_eq!(freed_set.len(), 5);
        assert!(freed_set.contains(&logical));
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

    #[test]
    fn mvcc_device_registers_and_releases_snapshot_lifetime() {
        let store = Arc::new(RwLock::new(MvccStore::new()));
        let snap = store.read().current_snapshot();
        assert_eq!(store.read().active_snapshot_count(), 0);

        {
            let base = MemBlockDevice::new(512, 4);
            let dev = MvccBlockDevice::new(base, Arc::clone(&store), snap);
            assert_eq!(dev.snapshot(), snap);
            assert_eq!(store.read().active_snapshot_count(), 1);
        }

        assert_eq!(store.read().active_snapshot_count(), 0);
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

    // ── Version-chain compression tests ───────────────────────────────

    #[test]
    fn compression_reconstructs_chain_across_identical_markers() {
        let mut store = MvccStore::with_compression_policy(CompressionPolicy::dedup_only());
        let block = BlockNumber(9);
        let payloads = [
            vec![0xAA; 8],
            vec![0xAA; 8],
            vec![0xBB; 8],
            vec![0xBB; 8],
            vec![0xBB; 8],
            vec![0xCC; 8],
        ];

        let mut snaps = Vec::with_capacity(payloads.len());
        for payload in &payloads {
            let mut txn = store.begin();
            txn.stage_write(block, payload.clone());
            store.commit(txn).expect("commit");
            snaps.push(store.current_snapshot());
        }

        for (snap, expected) in snaps.iter().zip(payloads.iter()) {
            assert_eq!(
                store.read_visible(block, *snap).expect("visible"),
                expected.as_slice()
            );
        }

        let chain = store.versions.get(&block).expect("chain");
        assert!(matches!(chain[0].data, VersionData::Full(_)));
        assert!(matches!(chain[1].data, VersionData::Identical));
        assert!(matches!(chain[2].data, VersionData::Full(_)));
        assert!(matches!(chain[3].data, VersionData::Identical));
        assert!(matches!(chain[4].data, VersionData::Identical));
        assert!(matches!(chain[5].data, VersionData::Full(_)));
    }

    #[test]
    fn compression_chain_cap_respects_active_snapshot() {
        let mut store = MvccStore::with_compression_policy(CompressionPolicy {
            dedup_identical: false,
            max_chain_length: Some(3),
        });
        let block = BlockNumber(77);
        let mut snaps = Vec::new();

        for v in 1_u8..=4 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
            snaps.push(store.current_snapshot());
        }

        let held = snaps[3];
        store.register_snapshot(held);

        for v in 5_u8..=6 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
        }

        assert_eq!(
            store
                .read_visible(block, held)
                .expect("held snapshot remains visible"),
            &[4]
        );

        let chain = store.versions.get(&block).expect("chain");
        assert!(chain.len() >= 3);
        assert!(
            chain
                .first()
                .is_some_and(|v| matches!(v.data, VersionData::Full(_)))
        );

        assert!(store.release_snapshot(held));

        let mut txn = store.begin();
        txn.stage_write(block, vec![7]);
        store.commit(txn).expect("commit");

        let chain = store.versions.get(&block).expect("chain");
        assert!(chain.len() <= 3, "chain should be capped after release");
        assert!(
            chain
                .first()
                .is_some_and(|v| matches!(v.data, VersionData::Full(_)))
        );
    }

    #[test]
    fn chain_length_bounded_after_many_writes() {
        let mut store = MvccStore::with_compression_policy(CompressionPolicy {
            dedup_identical: false,
            max_chain_length: Some(8),
        });
        let block = BlockNumber(88);

        for v in 1_u8..=100 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
        }

        let chain_len = store.versions.get(&block).expect("chain").len();
        assert!(
            chain_len <= 8,
            "chain should remain bounded by cap, got {chain_len}"
        );

        let stats = store.block_version_stats();
        assert_eq!(stats.chain_cap, Some(8));
        assert_eq!(stats.tracked_blocks, 1);
        assert!(stats.max_chain_length <= 8);
    }

    #[test]
    fn chain_backpressure_triggers_and_force_advances_oldest_snapshot() {
        let mut store = MvccStore::with_compression_policy(CompressionPolicy {
            dedup_identical: false,
            max_chain_length: Some(2),
        });
        let block = BlockNumber(89);

        let mut snapshots = Vec::new();
        for v in 1_u8..=2 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("seed");
            snapshots.push(store.current_snapshot());
        }

        let oldest = snapshots[0];
        // Hold two refs to oldest snapshot so one forced advance still leaves
        // a pin, ensuring backpressure is observable.
        store.register_snapshot(oldest);
        store.register_snapshot(oldest);
        assert_eq!(store.active_snapshot_count(), 2);

        let mut saw_backpressure = false;
        for v in 3_u8..=64 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            match store.commit(txn) {
                Ok(_) => {}
                Err(CommitError::ChainBackpressure {
                    cap,
                    critical_len,
                    chain_len,
                    ..
                }) => {
                    assert_eq!(cap, 2);
                    assert!(chain_len >= critical_len);
                    saw_backpressure = true;
                    break;
                }
                Err(other) => panic!("unexpected commit error: {other:?}"),
            }
        }
        assert!(
            saw_backpressure,
            "expected backpressure at critical chain length"
        );
        assert_eq!(
            store.active_snapshot_count(),
            1,
            "one oldest snapshot ref should be force-advanced"
        );

        assert!(store.release_snapshot(oldest));
        store.prune_safe();
        store.ebr_collect();

        let mut retry = store.begin();
        retry.stage_write(block, vec![0xAA]);
        store
            .commit(retry)
            .expect("commit should recover after release");
        let chain_len = store.versions.get(&block).expect("chain").len();
        assert!(chain_len <= 2, "chain should recover back under cap");

        let stats = store.block_version_stats();
        assert_eq!(stats.chain_cap, Some(2));
        assert_eq!(stats.chains_over_critical, 0);
    }

    #[test]
    fn compression_hot_block_memory_reduction_is_measurable() {
        let mut store = MvccStore::with_compression_policy(CompressionPolicy::dedup_only());
        let block = BlockNumber(101);
        let payload = vec![0x42; 4096];
        let writes = 100_usize;

        for _ in 0..writes {
            let mut txn = store.begin();
            txn.stage_write(block, payload.clone());
            store.commit(txn).expect("commit");
        }

        let stats = store.compression_stats();
        let uncompressed = writes * payload.len();
        assert_eq!(stats.full_versions, 1);
        assert_eq!(stats.identical_versions, writes - 1);
        assert_eq!(stats.bytes_stored, payload.len());
        assert_eq!(stats.bytes_saved, uncompressed - payload.len());
        assert!(stats.compression_ratio() < 0.02);

        let latest = store.current_snapshot();
        assert_eq!(store.read_visible(block, latest).expect("latest"), payload);
    }

    #[test]
    fn ebr_reclaims_retired_versions_after_collect() {
        let mut store = MvccStore::new();
        let block = BlockNumber(333);

        for v in 1_u8..=12 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v; 32]);
            store.commit(txn).expect("commit");
        }

        let before = store.ebr_stats();
        store.prune_versions_older_than(CommitSeq(10));
        let after_prune = store.ebr_stats();
        assert!(
            after_prune.retired_versions > before.retired_versions,
            "prune should retire at least one version"
        );

        store.ebr_collect();
        let after_collect = store.ebr_stats();
        assert_eq!(
            after_collect.retired_versions, after_collect.reclaimed_versions,
            "all retired versions should be reclaimed after collection in quiescent state"
        );
        assert_eq!(after_collect.pending_versions(), 0);
    }

    #[test]
    fn ebr_retirement_waits_for_snapshot_safe_pruning() {
        let mut store = MvccStore::new();
        let block = BlockNumber(334);
        let mut snapshots = Vec::new();

        for v in 1_u8..=5 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
            snapshots.push(store.current_snapshot());
        }

        let held = snapshots[0];
        store.register_snapshot(held);

        let before = store.ebr_stats();
        let _ = store.prune_safe();
        let after_blocked = store.ebr_stats();
        assert_eq!(
            after_blocked.retired_versions, before.retired_versions,
            "oldest held snapshot should block retirement"
        );

        assert!(store.release_snapshot(held));
        let _ = store.prune_safe();
        store.ebr_collect();
        let after_release = store.ebr_stats();
        assert!(
            after_release.retired_versions > after_blocked.retired_versions,
            "retirement should progress after snapshot release"
        );
        assert_eq!(
            after_release.retired_versions, after_release.reclaimed_versions,
            "retired versions should be reclaimable after release"
        );
    }

    #[test]
    fn ebr_collect_is_noop_without_retirements() {
        let store = MvccStore::new();
        let before = store.ebr_stats();
        store.ebr_collect();
        let after = store.ebr_stats();
        assert_eq!(before, after);
        assert_eq!(after.pending_versions(), 0);
    }

    #[test]
    fn ebr_retirement_waits_for_all_snapshots_to_release() {
        let mut store = MvccStore::new();
        let block = BlockNumber(335);
        let mut snapshots = Vec::new();

        for v in 1_u8..=6 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
            snapshots.push(store.current_snapshot());
        }

        let oldest = snapshots[0];
        let middle = snapshots[2];
        store.register_snapshot(oldest);
        store.register_snapshot(middle);

        let before = store.ebr_stats();
        let _ = store.prune_safe();
        let after_two_pins = store.ebr_stats();
        assert_eq!(
            after_two_pins.retired_versions, before.retired_versions,
            "retirement must not start while oldest snapshot is pinned"
        );

        assert!(store.release_snapshot(middle));
        let _ = store.prune_safe();
        let after_one_pin = store.ebr_stats();
        assert_eq!(
            after_one_pin.retired_versions, before.retired_versions,
            "oldest snapshot pin should still block retirement"
        );

        assert!(store.release_snapshot(oldest));
        let _ = store.prune_safe();
        store.ebr_collect();
        let after_release = store.ebr_stats();
        assert!(
            after_release.retired_versions > before.retired_versions,
            "retirement should progress once all snapshots are released"
        );
        assert_eq!(after_release.pending_versions(), 0);
    }

    #[test]
    fn ebr_prune_reduces_chain_and_keeps_latest_visible() {
        let mut store = MvccStore::new();
        let block = BlockNumber(336);

        for v in 1_u8..=20 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v; 8]);
            store.commit(txn).expect("commit");
        }

        let latest_snapshot = store.current_snapshot();
        let latest_payload = store
            .read_visible(block, latest_snapshot)
            .expect("latest visible")
            .to_vec();
        let before_len = store.versions.get(&block).expect("chain before").len();
        let before_stats = store.ebr_stats();

        store.prune_versions_older_than(CommitSeq(19));
        let after_len = store.versions.get(&block).expect("chain after").len();
        let after_prune_stats = store.ebr_stats();
        store.ebr_collect();
        let after_collect_stats = store.ebr_stats();

        assert!(after_len < before_len, "prune should shrink version chain");
        assert!(
            after_len >= 1,
            "version chain must keep at least one committed version"
        );
        assert_eq!(
            store
                .read_visible(block, store.current_snapshot())
                .expect("latest remains visible"),
            latest_payload.as_slice()
        );

        let retired_delta = after_prune_stats.retired_versions - before_stats.retired_versions;
        let expected_delta = u64::try_from(before_len - after_len).expect("fits in u64");
        assert_eq!(
            retired_delta, expected_delta,
            "retired version accounting should match actual chain trimming"
        );
        assert_eq!(after_collect_stats.pending_versions(), 0);
    }

    #[test]
    fn ebr_batch_retirement_counts_across_multiple_blocks() {
        let mut store = MvccStore::new();
        let blocks = [BlockNumber(340), BlockNumber(341), BlockNumber(342)];

        for &block in &blocks {
            for v in 1_u8..=10 {
                let mut txn = store.begin();
                txn.stage_write(block, vec![v; 4]);
                store.commit(txn).expect("commit");
            }
        }

        let before_stats = store.ebr_stats();
        let before_total_len: usize = blocks
            .iter()
            .map(|block| store.versions.get(block).expect("chain before").len())
            .sum();

        store.prune_versions_older_than(CommitSeq(8));
        let after_stats = store.ebr_stats();
        let after_total_len: usize = blocks
            .iter()
            .map(|block| store.versions.get(block).expect("chain after").len())
            .sum();

        let expected_retired =
            u64::try_from(before_total_len - after_total_len).expect("fits in u64");
        assert_eq!(
            after_stats.retired_versions - before_stats.retired_versions,
            expected_retired,
            "retirement counter should match total trimmed versions across blocks"
        );

        store.ebr_collect();
        let collected = store.ebr_stats();
        assert_eq!(collected.pending_versions(), 0);
    }

    // ── SSI conflict detection tests ───────────────────────────────────

    /// Classic write-skew scenario that FCW allows but SSI rejects.
    ///
    /// T1 reads A, writes B.  T2 reads B, writes A.
    /// Both succeed under FCW (disjoint write sets).
    /// Under SSI, the second committer detects the rw-antidependency.
    #[test]
    fn ssi_detects_write_skew() {
        let mut store = MvccStore::new();
        let block_a = BlockNumber(100);
        let block_b = BlockNumber(200);

        // Seed: both blocks start at 1.
        let mut seed_txn = store.begin();
        seed_txn.stage_write(block_a, vec![1]);
        seed_txn.stage_write(block_b, vec![1]);
        store.commit_ssi(seed_txn).expect("seed");

        // T1: reads A (sees 1), writes B to 2.
        let mut t1 = store.begin();
        let a_version = store.latest_commit_seq(block_a);
        t1.record_read(block_a, a_version);
        t1.stage_write(block_b, vec![2]);

        // T2: reads B (sees 1), writes A to 2.
        let mut t2 = store.begin();
        let b_version = store.latest_commit_seq(block_b);
        t2.record_read(block_b, b_version);
        t2.stage_write(block_a, vec![2]);

        // T1 commits first — succeeds.
        store.commit_ssi(t1).expect("T1 should succeed");

        // T2 commits second — SSI detects that T2 read B, which T1 just wrote.
        let result = store.commit_ssi(t2);
        assert!(
            matches!(result, Err(CommitError::SsiConflict { .. })),
            "SSI should reject T2 due to rw-antidependency on block B, got {result:?}"
        );
    }

    /// SSI does not reject read-only transactions.
    #[test]
    fn ssi_allows_read_only_transactions() {
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        // Seed.
        let mut seed = store.begin();
        seed.stage_write(block, vec![1]);
        store.commit_ssi(seed).expect("seed");

        // T1: read-only, reads block 1.
        let mut t1 = store.begin();
        let v = store.latest_commit_seq(block);
        t1.record_read(block, v);

        // T2: writes block 1 to 2.
        let mut t2 = store.begin();
        t2.stage_write(block, vec![2]);
        store.commit_ssi(t2).expect("T2 should succeed");

        // T1: read-only commit — should succeed even though its read was
        // invalidated, because read-only txns have no writes.
        store.commit_ssi(t1).expect("read-only T1 should succeed");
    }

    /// SSI allows disjoint readers/writers (no overlap).
    #[test]
    fn ssi_allows_disjoint_read_write_sets() {
        let mut store = MvccStore::new();
        let block_a = BlockNumber(1);
        let block_b = BlockNumber(2);

        // Seed both blocks.
        let mut seed = store.begin();
        seed.stage_write(block_a, vec![1]);
        seed.stage_write(block_b, vec![1]);
        store.commit_ssi(seed).expect("seed");

        // T1: reads A, writes A (same block — no cross-block dependency).
        let mut t1 = store.begin();
        let v_a = store.latest_commit_seq(block_a);
        t1.record_read(block_a, v_a);
        t1.stage_write(block_a, vec![2]);

        // T2: reads B, writes B.
        let mut t2 = store.begin();
        let v_b = store.latest_commit_seq(block_b);
        t2.record_read(block_b, v_b);
        t2.stage_write(block_b, vec![2]);

        // Both should succeed — no cross-block rw-antidependencies.
        store.commit_ssi(t1).expect("T1 should succeed");
        store.commit_ssi(t2).expect("T2 should succeed");
    }

    /// SSI still catches write-write conflicts (FCW layer).
    #[test]
    fn ssi_fcw_layer_still_active() {
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        let mut seed = store.begin();
        seed.stage_write(block, vec![1]);
        store.commit_ssi(seed).expect("seed");

        let mut t1 = store.begin();
        let mut t2 = store.begin();

        t1.stage_write(block, vec![2]);
        t2.stage_write(block, vec![3]);

        store.commit_ssi(t1).expect("T1 should succeed");

        let result = store.commit_ssi(t2);
        assert!(
            matches!(result, Err(CommitError::Conflict { .. })),
            "FCW should reject T2, got {result:?}"
        );
    }

    /// SSI log pruning does not affect correctness for active transactions.
    #[test]
    fn ssi_log_pruning() {
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        // Create several committed transactions.
        for v in 1_u8..=5 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit_ssi(txn).expect("commit");
        }

        // SSI log should have 5 entries.
        assert_eq!(store.ssi_log.len(), 5);

        // Prune entries with commit_seq <= 3.
        store.prune_ssi_log(CommitSeq(3));

        // Should have 2 entries remaining (commit_seq 4 and 5).
        assert_eq!(store.ssi_log.len(), 2);
    }

    // ── Read-set tracking tests ─────────────────────────────────────────

    /// `record_read` tracks the block and version; first read wins.
    #[test]
    fn read_set_tracks_first_read() {
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        let mut seed = store.begin();
        seed.stage_write(block, vec![1]);
        store.commit(seed).expect("seed");

        let mut txn = store.begin();
        txn.record_read(block, CommitSeq(1));
        // Second record_read for same block is ignored (first wins).
        txn.record_read(block, CommitSeq(99));

        assert_eq!(txn.read_set().len(), 1);
        assert_eq!(txn.read_set().get(&block), Some(&CommitSeq(1)));
    }

    /// Multiple distinct blocks are tracked independently.
    #[test]
    fn read_set_tracks_multiple_blocks() {
        let mut store = MvccStore::new();
        let blocks: Vec<BlockNumber> = (1..=5).map(BlockNumber).collect();

        let mut seed = store.begin();
        for &b in &blocks {
            seed.stage_write(b, vec![0xAA]);
        }
        store.commit(seed).expect("seed");

        let mut txn = store.begin();
        for &b in &blocks {
            txn.record_read(b, CommitSeq(1));
        }

        assert_eq!(txn.read_set().len(), 5);
        for &b in &blocks {
            assert!(txn.read_set().contains_key(&b));
        }
    }

    /// A transaction with an empty read-set does not trigger SSI aborts.
    #[test]
    fn empty_read_set_no_ssi_conflict() {
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        let mut seed = store.begin();
        seed.stage_write(block, vec![1]);
        store.commit_ssi(seed).expect("seed");

        // T1 writes block without recording any reads.
        let mut t1 = store.begin();
        t1.stage_write(block, vec![2]);
        store.commit_ssi(t1).expect("T1 no read-set");

        // T2 also writes block without reads — FCW should still
        // trigger, but not SSI phantom.
        let mut t2 = store.begin();
        t2.stage_write(block, vec![3]);
        store
            .commit_ssi(t2)
            .expect("T2 no overlap with T1 writes (new snapshot)");
    }

    /// Phantom detection: a concurrent writer to a block we read causes
    /// an SSI abort.
    #[test]
    fn phantom_detected_concurrent_writer_to_read_block() {
        let mut store = MvccStore::new();
        let block_a = BlockNumber(10);
        let block_b = BlockNumber(20);

        // Seed both blocks.
        let mut seed = store.begin();
        seed.stage_write(block_a, vec![1]);
        seed.stage_write(block_b, vec![1]);
        store.commit_ssi(seed).expect("seed");

        // T1: reads block_a, writes block_b.
        let mut t1 = store.begin();
        let v_a = store.latest_commit_seq(block_a);
        t1.record_read(block_a, v_a);
        t1.stage_write(block_b, vec![2]);

        // T2: writes block_a (the block T1 read).
        let mut t2 = store.begin();
        t2.stage_write(block_a, vec![99]);
        store.commit_ssi(t2).expect("T2 commits first");

        // T1 commit should fail: T2 wrote to block_a which T1 read.
        let result = store.commit_ssi(t1);
        assert!(
            matches!(result, Err(CommitError::SsiConflict { pivot_block, .. }) if pivot_block == block_a),
            "expected SSI conflict on block_a, got {result:?}"
        );
    }

    /// No false positive: reading a block nobody else writes is clean.
    #[test]
    fn no_false_positive_when_read_block_unmodified() {
        let mut store = MvccStore::new();
        let block_a = BlockNumber(1);
        let block_b = BlockNumber(2);

        let mut seed = store.begin();
        seed.stage_write(block_a, vec![1]);
        seed.stage_write(block_b, vec![1]);
        store.commit_ssi(seed).expect("seed");

        // T1: reads block_a, writes block_b.
        let mut t1 = store.begin();
        let v_a = store.latest_commit_seq(block_a);
        t1.record_read(block_a, v_a);
        t1.stage_write(block_b, vec![2]);

        // T2: writes block_b (same write target as T1, but T1 didn't
        // read block_b).  This is a pure FCW conflict, not phantom.
        let mut t2 = store.begin();
        t2.stage_write(block_b, vec![3]);
        store.commit_ssi(t2).expect("T2 commits first");

        // T1 should fail with FCW Conflict, NOT SSI phantom.
        let result = store.commit_ssi(t1);
        assert!(
            matches!(result, Err(CommitError::Conflict { .. })),
            "expected FCW conflict, got {result:?}"
        );
    }

    /// SSI commit record preserves read-set in the ssi_log.
    #[test]
    fn ssi_log_contains_read_set() {
        let mut store = MvccStore::new();
        let block_a = BlockNumber(1);
        let block_b = BlockNumber(2);

        let mut seed = store.begin();
        seed.stage_write(block_a, vec![1]);
        seed.stage_write(block_b, vec![1]);
        store.commit_ssi(seed).expect("seed");

        let mut txn = store.begin();
        txn.record_read(block_a, CommitSeq(1));
        txn.record_read(block_b, CommitSeq(1));
        txn.stage_write(block_a, vec![2]);
        store.commit_ssi(txn).expect("commit");

        // The SSI log should contain both the read-set and write-set.
        assert_eq!(store.ssi_log.len(), 2); // seed + our txn
        let record = &store.ssi_log[1];
        assert_eq!(record.read_set.len(), 2);
        assert!(record.read_set.contains_key(&block_a));
        assert!(record.read_set.contains_key(&block_b));
        assert_eq!(record.write_set.len(), 1);
        assert!(record.write_set.contains(&block_a));
    }

    // ── SSI write-skew and false-positive tests ─────────────────────────

    /// Quantitative false-positive test: N non-conflicting concurrent
    /// transactions committed via SSI, each touching a unique pair of
    /// blocks.  Zero should be spuriously aborted.
    #[test]
    fn ssi_zero_false_positives_for_non_conflicting_workload() {
        let mut store = MvccStore::new();
        let n = 200_u64;

        // Seed: create blocks 0..2*N.
        let mut seed = store.begin();
        for i in 0..(2 * n) {
            seed.stage_write(BlockNumber(i), vec![0]);
        }
        store.commit_ssi(seed).expect("seed");

        // Each transaction reads block 2*i, writes block 2*i+1.
        // All pairs are disjoint so zero conflicts should arise.
        let mut aborts = 0_u64;
        for i in 0..n {
            let read_block = BlockNumber(2 * i);
            let write_block = BlockNumber(2 * i + 1);

            let mut txn = store.begin();
            let v = store.latest_commit_seq(read_block);
            txn.record_read(read_block, v);
            txn.stage_write(write_block, vec![1]);

            if store.commit_ssi(txn).is_err() {
                aborts += 1;
            }
        }

        assert_eq!(
            aborts, 0,
            "SSI should not spuriously abort non-conflicting transactions, \
             got {aborts}/{n} aborts"
        );
    }

    /// Three-way write-skew cycle: T1 reads A writes B, T2 reads B
    /// writes C, T3 reads C writes A.  SSI must abort at least one.
    #[test]
    fn ssi_three_way_write_skew_cycle() {
        let mut store = MvccStore::new();
        let a = BlockNumber(1);
        let b = BlockNumber(2);
        let c = BlockNumber(3);

        // Seed all three blocks.
        let mut seed = store.begin();
        seed.stage_write(a, vec![1]);
        seed.stage_write(b, vec![1]);
        seed.stage_write(c, vec![1]);
        store.commit_ssi(seed).expect("seed");

        // All three begin concurrently at the same snapshot.
        let mut t1 = store.begin();
        let mut t2 = store.begin();
        let mut t3 = store.begin();

        let v_a = store.latest_commit_seq(a);
        let v_b = store.latest_commit_seq(b);
        let v_c = store.latest_commit_seq(c);

        // T1: reads A, writes B.
        t1.record_read(a, v_a);
        t1.stage_write(b, vec![2]);

        // T2: reads B, writes C.
        t2.record_read(b, v_b);
        t2.stage_write(c, vec![2]);

        // T3: reads C, writes A.
        t3.record_read(c, v_c);
        t3.stage_write(a, vec![2]);

        // Commit T1 first — should succeed (nothing written to A yet).
        store.commit_ssi(t1).expect("T1 should succeed");

        // T2: reads B, which T1 just wrote → SSI conflict.
        let r2 = store.commit_ssi(t2);
        assert!(
            matches!(r2, Err(CommitError::SsiConflict { .. })),
            "T2 should be rejected (T1 wrote to B which T2 read), got {r2:?}"
        );

        // T3: reads C, nobody wrote C (T2 was aborted) → should succeed.
        store
            .commit_ssi(t3)
            .expect("T3 should succeed (C unmodified)");
    }

    /// SSI with the write-skew scenario across 20 seeds using the lab runtime.
    ///
    /// Under SSI (unlike FCW), exactly one of the two transactions must
    /// be rejected when they form a write-skew pattern.
    #[test]
    fn lab_ssi_rejects_write_skew() {
        let block_a = BlockNumber(100);
        let block_b = BlockNumber(200);

        for seed in 0_u64..20 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));

            // Seed: both blocks start with value 1.
            {
                let mut s = store.lock().unwrap();
                let mut txn = s.begin();
                txn.stage_write(block_a, vec![1]);
                txn.stage_write(block_b, vec![1]);
                s.commit_ssi(txn).expect("seed commit");
            }

            let outcomes = Arc::new(std::sync::Mutex::new((None, None)));

            // Pre-begin both at the same snapshot.
            let mut s = store.lock().unwrap();
            let t1 = s.begin();
            let a_ver = s.latest_commit_seq(block_a);
            let b_ver = s.latest_commit_seq(block_b);
            let t2 = s.begin();
            drop(s);
            let t1_base = (t1, a_ver);
            let t2_base = (t2, b_ver);

            // T1: reads A, writes B.
            {
                let store = Arc::clone(&store);
                let outcomes = Arc::clone(&outcomes);
                let (mut txn1, a_ver) = t1_base;
                let (task_id, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await;

                        txn1.record_read(block_a, a_ver);
                        txn1.stage_write(block_b, vec![2]);
                        let result = {
                            let mut s = store.lock().unwrap();
                            s.commit_ssi(txn1)
                        };
                        outcomes.lock().unwrap().0 = Some(result.is_ok());
                    })
                    .expect("create task");
                runtime.scheduler.lock().unwrap().schedule(task_id, 0);
            }

            // T2: reads B, writes A.
            {
                let store = Arc::clone(&store);
                let outcomes = Arc::clone(&outcomes);
                let (mut txn2, b_ver) = t2_base;
                let (task_id, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await;

                        txn2.record_read(block_b, b_ver);
                        txn2.stage_write(block_a, vec![2]);
                        let result = {
                            let mut s = store.lock().unwrap();
                            s.commit_ssi(txn2)
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

            // Under SSI, exactly one should succeed and one should fail.
            assert!(
                t1_ok ^ t2_ok,
                "seed {seed}: SSI should reject exactly one of the write-skew \
                 transactions. Got t1={t1_ok}, t2={t2_ok}"
            );

            // Under SSI, only one writer succeeds.  The winning writer sets
            // one block to 2 while the other remains 1, so a+b=3 (not 4 as
            // under FCW's write-skew).  The key SSI property is that the
            // "double write" (a=2, b=2, sum=4) is prevented.
            let s = store.lock().unwrap();
            let snap = s.current_snapshot();
            let a = s.read_visible(block_a, snap).unwrap()[0];
            let b = s.read_visible(block_b, snap).unwrap()[0];
            drop(s);
            assert_eq!(
                a + b,
                3,
                "seed {seed}: SSI should prevent both writers from succeeding, got a={a} b={b}"
            );
        }
    }

    // ── E2E: Concurrent SSI Scenarios ─────────────────────────────────

    /// E2E Scenario 1: Write-skew detection across many iterations.
    ///
    /// T1 reads A, writes B; T2 reads B, writes A.  Over 100 seeds,
    /// SSI must abort exactly one transaction every time.
    #[test]
    fn e2e_write_skew_detection_100_seeds() {
        let block_a = BlockNumber(100);
        let block_b = BlockNumber(200);

        for seed in 0_u64..100 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));
            {
                let mut s = store.lock().unwrap();
                let mut txn = s.begin();
                txn.stage_write(block_a, vec![1]);
                txn.stage_write(block_b, vec![1]);
                s.commit_ssi(txn).expect("seed");
            }

            let outcomes = Arc::new(std::sync::Mutex::new((None, None)));

            let mut s = store.lock().unwrap();
            let t1 = s.begin();
            let a_ver = s.latest_commit_seq(block_a);
            let b_ver = s.latest_commit_seq(block_b);
            let t2 = s.begin();
            drop(s);

            {
                let store = Arc::clone(&store);
                let outcomes = Arc::clone(&outcomes);
                let (mut txn1, a_v) = (t1, a_ver);
                let (task_id, _h) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await;
                        txn1.record_read(block_a, a_v);
                        txn1.stage_write(block_b, vec![2]);
                        let r = store.lock().unwrap().commit_ssi(txn1);
                        outcomes.lock().unwrap().0 = Some(r.is_ok());
                    })
                    .expect("create");
                runtime.scheduler.lock().unwrap().schedule(task_id, 0);
            }

            {
                let store = Arc::clone(&store);
                let outcomes = Arc::clone(&outcomes);
                let (mut txn2, b_v) = (t2, b_ver);
                let (task_id, _h) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await;
                        txn2.record_read(block_b, b_v);
                        txn2.stage_write(block_a, vec![2]);
                        let r = store.lock().unwrap().commit_ssi(txn2);
                        outcomes.lock().unwrap().1 = Some(r.is_ok());
                    })
                    .expect("create");
                runtime.scheduler.lock().unwrap().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let (t1_ok, t2_ok) = {
                let o = outcomes.lock().unwrap();
                (o.0.expect("T1 ran"), o.1.expect("T2 ran"))
            };

            assert!(
                t1_ok ^ t2_ok,
                "seed {seed}: SSI must reject exactly one, got t1={t1_ok}, t2={t2_ok}"
            );
        }
    }

    /// E2E Scenario 2: Lost update prevention.
    ///
    /// Two writers both read X, compute X+1, and write X.
    /// FCW must detect the conflict — final value is initial+1.
    #[test]
    fn e2e_lost_update_prevention() {
        let block_x = BlockNumber(42);

        for seed in 0_u64..100 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));
            {
                let mut s = store.lock().unwrap();
                let mut txn = s.begin();
                txn.stage_write(block_x, vec![10]); // initial value = 10
                s.commit(txn).expect("seed");
            }

            let outcomes = Arc::new(std::sync::Mutex::new((None, None)));

            let t1 = store.lock().unwrap().begin();
            let t2 = store.lock().unwrap().begin();

            for (i, txn) in [t1, t2].into_iter().enumerate() {
                let store = Arc::clone(&store);
                let outcomes = Arc::clone(&outcomes);
                let (task_id, _h) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await;
                        let mut txn = txn;
                        // Both "read" value 10 and write 11.
                        txn.stage_write(block_x, vec![11]);
                        let r = store.lock().unwrap().commit(txn);
                        if i == 0 {
                            outcomes.lock().unwrap().0 = Some(r.is_ok());
                        } else {
                            outcomes.lock().unwrap().1 = Some(r.is_ok());
                        }
                    })
                    .expect("create");
                runtime.scheduler.lock().unwrap().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let (t1_ok, t2_ok) = {
                let o = outcomes.lock().unwrap();
                (o.0.expect("T1 ran"), o.1.expect("T2 ran"))
            };

            // FCW: exactly one must succeed.
            assert!(
                t1_ok ^ t2_ok,
                "seed {seed}: FCW must reject one, got t1={t1_ok}, t2={t2_ok}"
            );

            // Final value must be 11 (not 12 from a lost update).
            let s = store.lock().unwrap();
            let snap = s.current_snapshot();
            let val = s.read_visible(block_x, snap).unwrap()[0];
            drop(s);
            assert_eq!(val, 11, "seed {seed}: lost update detected, val={val}");
        }
    }

    /// E2E Scenario 3: Phantom read prevention via SSI.
    ///
    /// T1 reads blocks 0..10, T2 writes to block 5, T2 commits first.
    /// T1 should be aborted because T2 modified a block in T1's read-set.
    #[test]
    fn e2e_phantom_read_prevention() {
        let mut store = MvccStore::new();

        // Seed blocks 0..10.
        let mut seed_txn = store.begin();
        for i in 0_u64..10 {
            seed_txn.stage_write(BlockNumber(i), vec![1]);
        }
        store.commit_ssi(seed_txn).expect("seed");

        // T1: reads blocks 0..10 (the "scan").
        let mut t1 = store.begin();
        for i in 0_u64..10 {
            let v = store.latest_commit_seq(BlockNumber(i));
            t1.record_read(BlockNumber(i), v);
        }
        // T1 also writes something (required for SSI check to fire).
        t1.stage_write(BlockNumber(100), vec![99]);

        // T2: writes block 5 (a "phantom" insert into T1's read range).
        let mut t2 = store.begin();
        t2.stage_write(BlockNumber(5), vec![2]);
        store.commit_ssi(t2).expect("T2 commits first");

        // T1 should be aborted — block 5 (in T1's read-set) was modified.
        let result = store.commit_ssi(t1);
        assert!(
            matches!(
                result,
                Err(CommitError::SsiConflict {
                    pivot_block: BlockNumber(5),
                    ..
                })
            ),
            "expected SSI conflict on block 5, got {result:?}"
        );
    }

    /// E2E Scenario 4: Multi-writer stress test (deterministic).
    ///
    /// 4 concurrent Lab tasks, each running 50 transactions.
    /// Each writes a unique block per iteration.  No conflicts should
    /// occur (disjoint write sets), and all commits should succeed.
    #[test]
    fn e2e_multi_writer_stress_disjoint() {
        for seed in 0_u64..10 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(500_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));
            let total_commits = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let total_aborts = Arc::new(std::sync::atomic::AtomicU64::new(0));

            let num_writers = 4_u64;
            let txns_per_writer = 50_u64;

            for writer_id in 0..num_writers {
                let store = Arc::clone(&store);
                let commits = Arc::clone(&total_commits);
                let aborts = Arc::clone(&total_aborts);
                let (task_id, _h) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        for j in 0..txns_per_writer {
                            yield_now().await;
                            let block = BlockNumber(writer_id * txns_per_writer + j);
                            let mut txn = store.lock().unwrap().begin();
                            #[allow(clippy::cast_possible_truncation)]
                            let tag = writer_id as u8;
                            txn.stage_write(block, vec![tag; 64]);
                            let r = store.lock().unwrap().commit_ssi(txn);
                            if r.is_ok() {
                                commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            } else {
                                aborts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    })
                    .expect("create");
                runtime.scheduler.lock().unwrap().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let commits = total_commits.load(std::sync::atomic::Ordering::Relaxed);
            let aborts = total_aborts.load(std::sync::atomic::Ordering::Relaxed);

            assert_eq!(
                commits,
                num_writers * txns_per_writer,
                "seed {seed}: all disjoint writes should commit, got {commits} commits, {aborts} aborts"
            );
            assert_eq!(aborts, 0, "seed {seed}: no aborts expected");
        }
    }

    /// E2E Scenario 5: High-contention hot key with retries.
    ///
    /// 4 Lab tasks each increment a shared counter block 20 times.
    /// On abort, they retry.  Final value must equal 4*20 = 80.
    #[test]
    fn e2e_hot_key_counter_with_retries() {
        let block = BlockNumber(0);

        for seed in 0_u64..10 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(1_000_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));
            // Seed: counter = 0.
            {
                let mut s = store.lock().unwrap();
                let mut txn = s.begin();
                txn.stage_write(block, vec![0; 8]); // u64 LE counter = 0
                s.commit(txn).expect("seed");
            }

            let total_aborts = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let num_workers = 4_u64;
            let increments_per = 20_u64;

            for _worker_id in 0..num_workers {
                let store = Arc::clone(&store);
                let aborts = Arc::clone(&total_aborts);
                let (task_id, _h) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        for _ in 0..increments_per {
                            loop {
                                yield_now().await;
                                let mut s = store.lock().unwrap();
                                let snap = s.current_snapshot();
                                let current_val = s.read_visible(block, snap).map_or(0, |b| {
                                    let mut buf = [0_u8; 8];
                                    let len = b.len().min(8);
                                    buf[..len].copy_from_slice(&b[..len]);
                                    u64::from_le_bytes(buf)
                                });
                                let new_val = current_val + 1;
                                let mut txn = s.begin();
                                txn.stage_write(block, new_val.to_le_bytes().to_vec());
                                match s.commit(txn) {
                                    Ok(_) => break,
                                    Err(_) => {
                                        aborts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    })
                    .expect("create");
                runtime.scheduler.lock().unwrap().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let s = store.lock().unwrap();
            let snap = s.current_snapshot();
            let final_bytes = s.read_visible(block, snap).expect("read counter");
            let mut buf = [0_u8; 8];
            let len = final_bytes.len().min(8);
            buf[..len].copy_from_slice(&final_bytes[..len]);
            let final_val = u64::from_le_bytes(buf);
            drop(s);

            let expected = num_workers * increments_per;
            assert_eq!(
                final_val, expected,
                "seed {seed}: counter should be {expected}, got {final_val}"
            );
        }
    }

    #[test]
    fn e2e_ebr_basic_reclamation_correctness() {
        let mut store = MvccStore::with_compression_policy(CompressionPolicy {
            dedup_identical: false,
            max_chain_length: Some(64),
        });
        let block = BlockNumber(910);
        let mut snapshots = Vec::new();

        for v in 1_u8..=8 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
            snapshots.push(store.current_snapshot());
        }

        let held_snapshot = snapshots[4]; // commit 5
        store.register_snapshot(held_snapshot);
        assert_eq!(
            store.read_visible(block, held_snapshot).expect("held read"),
            &[5]
        );

        let before = store.ebr_stats();
        let _ = store.prune_safe();
        store.ebr_collect();
        let during_pin = store.ebr_stats();
        assert!(
            during_pin.retired_versions >= before.retired_versions,
            "prune during pin should only retire versions safe under held snapshot"
        );
        assert_eq!(
            store
                .read_visible(block, held_snapshot)
                .expect("still pinned"),
            &[5],
            "held snapshot must keep version 5 visible"
        );

        assert!(store.release_snapshot(held_snapshot));
        let _ = store.prune_safe();
        store.ebr_collect();
        let after_release = store.ebr_stats();
        assert!(
            after_release.reclaimed_versions >= during_pin.reclaimed_versions,
            "reclamation should progress after release"
        );
        assert_eq!(after_release.pending_versions(), 0);

        let old_snapshot_value = store.read_visible(block, held_snapshot).map(<[u8]>::to_vec);
        assert_ne!(
            old_snapshot_value,
            Some(vec![5]),
            "old pinned version should no longer be retained after release+prune"
        );
    }

    #[test]
    fn e2e_ebr_multi_reader_multi_writer_release_order() {
        let blocks = [
            BlockNumber(0),
            BlockNumber(1),
            BlockNumber(2),
            BlockNumber(3),
        ];

        let mut base = MvccStore::with_compression_policy(CompressionPolicy {
            dedup_identical: false,
            max_chain_length: None,
        });
        let mut snapshots = Vec::new();

        for seq in 1_u64..=40 {
            let mut txn = base.begin();
            let idx = usize::try_from((seq - 1) % 4).expect("fits");
            let block = blocks[idx];
            let payload = vec![u8::try_from(seq).expect("seq fits in u8")];
            txn.stage_write(block, payload);
            base.commit(txn).expect("seed");
            if matches!(seq, 10 | 20 | 30 | 40) {
                snapshots.push(base.current_snapshot());
            }
        }
        for snap in &snapshots {
            base.register_snapshot(*snap);
        }

        let expected: Vec<(Snapshot, Vec<Vec<u8>>)> = snapshots
            .iter()
            .map(|snap| {
                let values = blocks
                    .iter()
                    .map(|block| {
                        base.read_visible(*block, *snap)
                            .expect("snapshot value")
                            .to_vec()
                    })
                    .collect();
                (*snap, values)
            })
            .collect();

        let shared = Arc::new(std::sync::Mutex::new(base));
        let mut handles = Vec::new();
        for writer_id in 0_u64..4 {
            let store = Arc::clone(&shared);
            handles.push(std::thread::spawn(move || {
                let mut rng = 0x9E37_79B9_u64.wrapping_add(writer_id);
                for i in 0_u64..1_000 {
                    rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    let idx = usize::try_from(rng % 4).expect("fits");
                    let block = blocks[idx];
                    let byte = u8::try_from((rng >> 16) & 0xFF).expect("fits");
                    let mut s = store.lock().expect("lock");
                    let mut txn = s.begin();
                    txn.stage_write(block, vec![byte; 8]);
                    let _ = s.commit(txn);
                    if i % 32 == 0 {
                        let _ = s.prune_safe();
                        s.ebr_collect();
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().expect("writer join");
        }

        let mut store = Arc::try_unwrap(shared)
            .expect("single owner")
            .into_inner()
            .expect("mutex");

        for (snap, values) in &expected {
            for (idx, block) in blocks.iter().enumerate() {
                assert_eq!(
                    store.read_visible(*block, *snap).expect("snapshot read"),
                    values[idx].as_slice(),
                    "snapshot {:?} on block {} must remain stable",
                    snap.high.0,
                    block.0
                );
            }
        }

        let mut reclaimed_prev = store.ebr_stats().reclaimed_versions;
        for snap in snapshots.iter().rev().copied() {
            assert!(store.release_snapshot(snap));
            let _ = store.prune_safe();
            store.ebr_collect();
            let now = store.ebr_stats().reclaimed_versions;
            assert!(now >= reclaimed_prev, "reclaimed counter must be monotonic");
            reclaimed_prev = now;
        }
        let _ = store.prune_safe();
        store.ebr_collect();
        let final_stats = store.ebr_stats();
        assert_eq!(final_stats.pending_versions(), 0);
        assert!(
            store.version_count() <= blocks.len(),
            "after all readers release, only latest versions should remain"
        );
    }

    #[test]
    fn e2e_ebr_reader_pin_blocks_reclamation_until_release() {
        let mut store = MvccStore::with_compression_policy(CompressionPolicy {
            dedup_identical: false,
            max_chain_length: None,
        });
        let block = BlockNumber(920);

        let mut seed = store.begin();
        seed.stage_write(block, vec![1]);
        store.commit(seed).expect("seed");
        let held_snapshot = store.current_snapshot();
        store.register_snapshot(held_snapshot);

        for v in 2_u8..=128 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
            let _ = store.prune_safe();
            store.ebr_collect();
            assert_eq!(
                store.read_visible(block, held_snapshot).expect("held read"),
                &[1],
                "held reader must keep original version visible"
            );
        }

        let version_count_during_pin = store.version_count();
        assert!(
            version_count_during_pin >= 100,
            "without cap and with held snapshot, chain should grow materially"
        );

        assert!(store.release_snapshot(held_snapshot));
        let _ = store.prune_safe();
        store.ebr_collect();

        let version_count_after_release = store.version_count();
        assert!(
            version_count_after_release < version_count_during_pin,
            "release should allow aggressive reclamation"
        );
        let old_visible = store.read_visible(block, held_snapshot).map(<[u8]>::to_vec);
        assert_ne!(
            old_visible,
            Some(vec![1]),
            "old value should no longer be retained post-release"
        );
        assert_eq!(store.ebr_stats().pending_versions(), 0);
    }

    #[test]
    fn e2e_ebr_chain_length_enforced_under_concurrent_writers() {
        let block = BlockNumber(930);
        let store = Arc::new(std::sync::Mutex::new(MvccStore::with_compression_policy(
            CompressionPolicy {
                dedup_identical: false,
                max_chain_length: Some(16),
            },
        )));

        let mut handles = Vec::new();
        for writer_id in 0_u64..4 {
            let store = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                for i in 0_u64..2_000 {
                    let mut s = store.lock().expect("lock");
                    let mut txn = s.begin();
                    let byte = u8::try_from((writer_id + i) % 255).expect("fits");
                    txn.stage_write(block, vec![byte; 16]);
                    let _ = s.commit(txn);
                    if i % 64 == 0 {
                        let _ = s.prune_safe();
                        s.ebr_collect();
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().expect("writer join");
        }

        let mut s = Arc::try_unwrap(store)
            .expect("single owner")
            .into_inner()
            .expect("mutex");
        let _ = s.prune_safe();
        s.ebr_collect();

        let chain_len = s.versions.get(&block).map_or(0, Vec::len);
        assert!(
            chain_len <= 16,
            "chain length should remain bounded by cap, got {chain_len}"
        );
        let chain_stats = s.block_version_stats();
        assert_eq!(chain_stats.chain_cap, Some(16));
        assert!(chain_stats.max_chain_length <= 16);

        let latest = s.current_snapshot();
        assert!(
            s.read_visible(block, latest).is_some(),
            "latest block value must remain readable"
        );
    }

    #[test]
    fn e2e_ebr_restart_preserves_latest_visible_value() {
        let cx = Cx::for_testing();
        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();
        let block = BlockNumber(940);

        {
            let store = crate::persist::PersistentMvccStore::open_with_options(
                &cx,
                &path,
                crate::persist::PersistOptions {
                    sync_on_commit: false,
                },
            )
            .expect("open persistent store");

            for v in 1_u8..=64 {
                let mut txn = store.begin();
                txn.stage_write(block, vec![v]);
                store.commit(txn).expect("commit");
            }
        }

        let reopened = crate::persist::PersistentMvccStore::open_with_options(
            &cx,
            &path,
            crate::persist::PersistOptions {
                sync_on_commit: false,
            },
        )
        .expect("reopen");
        let snap = reopened.current_snapshot();
        let recovered = reopened.read_visible(block, snap).expect("recovered value");
        assert_eq!(
            recovered,
            vec![64],
            "latest committed value should survive restart"
        );
        assert!(
            reopened.recovery_report().commits_replayed >= 1,
            "recovery report should show replay activity"
        );
    }

    // ── SnapshotRegistry + SnapshotHandle tests ─────────────────────────

    #[test]
    fn snapshot_handle_increments_ref_count_on_create() {
        let registry = Arc::new(SnapshotRegistry::new());
        let snap = Snapshot { high: CommitSeq(5) };

        assert_eq!(registry.active_count(), 0);
        let handle = SnapshotRegistry::acquire(&registry, snap);
        assert_eq!(registry.active_count(), 1);
        assert_eq!(handle.snapshot(), snap);
    }

    #[test]
    fn snapshot_handle_decrements_ref_count_on_drop() {
        let registry = Arc::new(SnapshotRegistry::new());
        let snap = Snapshot { high: CommitSeq(5) };

        let handle = SnapshotRegistry::acquire(&registry, snap);
        assert_eq!(registry.active_count(), 1);

        drop(handle);
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn registry_gc_respects_oldest_active_snapshot() {
        let registry = Arc::new(SnapshotRegistry::new());
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        // Write 5 versions.
        for v in 1_u8..=5 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
        }

        // Acquire a handle at commit 3.
        let snap3 = Snapshot { high: CommitSeq(3) };
        let _handle = SnapshotRegistry::acquire(&registry, snap3);

        // Use registry watermark for pruning.
        let wm = registry.watermark().unwrap();
        assert_eq!(wm, CommitSeq(3));
        store.prune_versions_older_than(wm);

        // Version at commit 3 should still be readable.
        assert_eq!(store.read_visible(block, snap3).unwrap(), &[3]);

        // Latest version should also be readable.
        let snap_latest = store.current_snapshot();
        assert_eq!(store.read_visible(block, snap_latest).unwrap(), &[5]);
    }

    #[test]
    fn registry_watermark_advances_when_oldest_released() {
        let registry = Arc::new(SnapshotRegistry::new());

        let old = Snapshot { high: CommitSeq(3) };
        let mid = Snapshot { high: CommitSeq(7) };
        let new = Snapshot {
            high: CommitSeq(12),
        };

        let h_old = SnapshotRegistry::acquire(&registry, old);
        let h_mid = SnapshotRegistry::acquire(&registry, mid);
        let _h_new = SnapshotRegistry::acquire(&registry, new);

        assert_eq!(registry.watermark(), Some(CommitSeq(3)));

        // Release oldest — watermark advances.
        drop(h_old);
        assert_eq!(registry.watermark(), Some(CommitSeq(7)));

        // Release mid — watermark advances again.
        drop(h_mid);
        assert_eq!(registry.watermark(), Some(CommitSeq(12)));
    }

    #[test]
    fn registry_multiple_handles_same_snapshot() {
        let registry = Arc::new(SnapshotRegistry::new());
        let snap = Snapshot { high: CommitSeq(5) };

        let h1 = SnapshotRegistry::acquire(&registry, snap);
        let h2 = SnapshotRegistry::acquire(&registry, snap);
        assert_eq!(registry.active_count(), 2);

        drop(h1);
        assert_eq!(registry.active_count(), 1);
        assert_eq!(registry.watermark(), Some(CommitSeq(5)));

        drop(h2);
        assert_eq!(registry.active_count(), 0);
        assert!(registry.watermark().is_none());
    }

    #[test]
    fn registry_no_memory_leak_100k_acquire_release() {
        let registry = Arc::new(SnapshotRegistry::new());

        for i in 0_u64..100_000 {
            let snap = Snapshot {
                high: CommitSeq(i % 100),
            };
            let handle = SnapshotRegistry::acquire(&registry, snap);
            drop(handle);
        }

        assert_eq!(registry.active_count(), 0);
        assert!(registry.watermark().is_none());
        assert_eq!(registry.acquired_total(), 100_000);
        assert_eq!(registry.released_total(), 100_000);
    }

    #[test]
    fn registry_concurrent_16_threads() {
        let registry = Arc::new(SnapshotRegistry::new());
        let num_threads: usize = 16;
        let ops_per_thread: usize = 1000;
        let barrier = Arc::new(std::sync::Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    for j in 0..ops_per_thread {
                        let seq = u64::try_from(i * ops_per_thread + j).unwrap();
                        let snap = Snapshot {
                            high: CommitSeq(seq % 50),
                        };
                        let handle = SnapshotRegistry::acquire(&registry, snap);
                        // Hold briefly.
                        std::hint::black_box(&handle);
                        drop(handle);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        assert_eq!(registry.active_count(), 0);
        let total = u64::try_from(num_threads * ops_per_thread).unwrap();
        assert_eq!(registry.acquired_total(), total);
        assert_eq!(registry.released_total(), total);
    }

    #[test]
    fn snapshot_handle_released_on_panic() {
        let registry = Arc::new(SnapshotRegistry::new());
        let snap = Snapshot { high: CommitSeq(7) };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _handle = SnapshotRegistry::acquire(&registry, snap);
            panic!("simulated FUSE handler panic");
        }));

        assert!(result.is_err(), "panic should have been caught");
        // The handle's Drop should have released the snapshot.
        assert_eq!(
            registry.active_count(),
            0,
            "snapshot should be released even after panic"
        );
    }

    #[test]
    fn registry_stall_detection() {
        // Use a very short threshold for testing.
        let registry = Arc::new(SnapshotRegistry::with_stall_threshold(0));
        let snap = Snapshot { high: CommitSeq(1) };

        let _handle = SnapshotRegistry::acquire(&registry, snap);
        // Even with threshold=0, the check should detect a stall.
        std::thread::sleep(std::time::Duration::from_millis(10));
        let stall = registry.check_stalls();
        assert!(stall.is_some(), "should detect stall with threshold=0");
    }

    #[test]
    fn registry_metrics_counters() {
        let registry = Arc::new(SnapshotRegistry::new());
        assert_eq!(registry.acquired_total(), 0);
        assert_eq!(registry.released_total(), 0);

        let snap = Snapshot { high: CommitSeq(1) };
        let h1 = SnapshotRegistry::acquire(&registry, snap);
        let h2 = SnapshotRegistry::acquire(&registry, snap);
        assert_eq!(registry.acquired_total(), 2);
        assert_eq!(registry.released_total(), 0);

        drop(h1);
        assert_eq!(registry.released_total(), 1);

        drop(h2);
        assert_eq!(registry.acquired_total(), 2);
        assert_eq!(registry.released_total(), 2);
    }

    #[test]
    fn mvcc_device_with_registry_lifecycle() {
        let store = Arc::new(RwLock::new(MvccStore::new()));
        let registry = Arc::new(SnapshotRegistry::new());
        let snap = store.read().current_snapshot();

        assert_eq!(registry.active_count(), 0);

        {
            let base = MemBlockDevice::new(512, 4);
            let dev = MvccBlockDevice::with_registry(base, Arc::clone(&store), snap, &registry);
            assert_eq!(dev.snapshot(), snap);
            assert_eq!(registry.active_count(), 1);
            // MvccStore's inline tracking should NOT be affected.
            assert_eq!(store.read().active_snapshot_count(), 0);
        }

        // After drop, registry count returns to 0.
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn mvcc_device_with_registry_reads_correctly() {
        let cx = test_cx();
        let store = Arc::new(RwLock::new(MvccStore::new()));
        let registry = Arc::new(SnapshotRegistry::new());

        // Commit a version.
        {
            let mut guard = store.write();
            let mut txn = guard.begin();
            txn.stage_write(BlockNumber(1), vec![0xAB; 512]);
            guard.commit(txn).expect("commit");
        }

        let snap = store.read().current_snapshot();
        let base = MemBlockDevice::new(512, 16);
        let dev = MvccBlockDevice::with_registry(base, Arc::clone(&store), snap, &registry);

        let buf = dev.read_block(&cx, BlockNumber(1)).expect("read");
        assert_eq!(buf.as_slice(), &[0xAB; 512]);
    }
}
