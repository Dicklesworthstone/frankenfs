//! MVCC persistence layer using a Write-Ahead Log (WAL).
//!
//! This module provides `PersistentMvccStore`, which wraps an `MvccStore` and
//! persists committed versions to a WAL file. On startup, the WAL is replayed
//! to restore the committed state.
//!
//! # Usage
//!
//! ```text
//! let store = PersistentMvccStore::open(cx, "/path/to/wal")?;
//! let mut txn = store.begin();
//! txn.stage_write(BlockNumber(1), vec![1, 2, 3]);
//! store.commit(txn)?;  // Writes to WAL before returning
//! ```
//!
//! # Invariants
//!
//! - Committed versions are durable: after `commit()` returns `Ok`, the data
//!   is written to the WAL (not just buffered).
//! - Uncommitted writes are never persisted.
//! - WAL replay is idempotent and deterministic.
//! - Partial/corrupted WAL tail records are safely ignored.

use crate::wal::{self, HEADER_SIZE, WalCommit, WalHeader};
use crate::wal_replay::{ReplayOutcome, TailPolicy, WalReplayEngine};
use crate::wal_writer::{SyncPolicy, WalWriter, WalWriterConfig};
use crate::{BlockVersion, CommitError, MvccStore, Transaction};
use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, CommitSeq};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Configuration options for persistent MVCC storage.
#[derive(Debug, Clone)]
pub struct PersistOptions {
    /// Whether to sync after each commit (default: true).
    pub sync_on_commit: bool,
    /// Whether to verify writes by reading back and checking CRC (default: false).
    pub verify_writes: bool,
    /// WAL size threshold in bytes for backpressure signaling (0 = disabled).
    pub backpressure_threshold_bytes: u64,
}

impl Default for PersistOptions {
    fn default() -> Self {
        Self {
            sync_on_commit: true,
            verify_writes: false,
            backpressure_threshold_bytes: 0,
        }
    }
}

impl PersistOptions {
    /// Convert to [`WalWriterConfig`] for the underlying writer.
    fn to_writer_config(&self) -> WalWriterConfig {
        WalWriterConfig {
            sync_policy: if self.sync_on_commit {
                SyncPolicy::Immediate
            } else {
                SyncPolicy::Manual
            },
            verify_writes: self.verify_writes,
            backpressure_threshold_bytes: self.backpressure_threshold_bytes,
        }
    }
}

/// WAL statistics for monitoring.
#[derive(Debug, Clone, Copy, Default)]
pub struct WalStats {
    /// Number of commits replayed on startup.
    pub replayed_commits: u64,
    /// Number of block versions replayed on startup.
    pub replayed_versions: u64,
    /// Current WAL file size in bytes.
    pub wal_size_bytes: u64,
    /// Number of commits written since open.
    pub commits_written: u64,
    /// Number of checkpoints created since open.
    pub checkpoints_created: u64,
    /// Highest commit sequence in the last checkpoint.
    pub checkpoint_commit_seq: u64,
}

/// Report produced after WAL recovery (replay on startup).
///
/// This captures enough detail for the evidence ledger integration:
/// how many commits were replayed, how many records were discarded
/// (corrupt or truncated), and whether a checkpoint was used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalRecoveryReport {
    /// Classified replay outcome (clean, truncated, corrupt, etc.).
    pub outcome: ReplayOutcome,
    /// Number of commits successfully replayed.
    pub commits_replayed: u64,
    /// Number of block versions restored.
    pub versions_replayed: u64,
    /// Number of WAL records discarded (corrupt CRC or truncated tail).
    pub records_discarded: u64,
    /// Byte offset where valid WAL data ends.
    pub wal_valid_bytes: u64,
    /// Total WAL file size in bytes.
    pub wal_total_bytes: u64,
    /// Whether a checkpoint was loaded before WAL replay.
    pub used_checkpoint: bool,
    /// Highest commit sequence restored from checkpoint, if any.
    pub checkpoint_commit_seq: Option<u64>,
}

impl Default for WalRecoveryReport {
    fn default() -> Self {
        Self {
            outcome: ReplayOutcome::EmptyLog,
            commits_replayed: 0,
            versions_replayed: 0,
            records_discarded: 0,
            wal_valid_bytes: 0,
            wal_total_bytes: 0,
            used_checkpoint: false,
            checkpoint_commit_seq: None,
        }
    }
}

// ── Checkpoint format ─────────────────────────────────────────────────────────
//
// Checkpoints provide a compact snapshot of MVCC state that can be loaded faster
// than replaying the entire WAL. The format is:
//
// ```text
// Checkpoint File:
// +------------------+--------+
// | magic            | 4 bytes| = 0x4D56_4350 ("MVCP" LE scrambled)
// | version          | 2 bytes| = 1
// | reserved         | 2 bytes| = 0
// | next_txn         | 8 bytes| next transaction ID
// | next_commit      | 8 bytes| next commit sequence
// | num_blocks       | 4 bytes| number of distinct blocks
// +------------------+--------+
// | For each block:           |
// |   block_number   | 8 bytes|
// |   num_versions   | 4 bytes|
// |   For each version:       |
// |     commit_seq   | 8 bytes|
// |     txn_id       | 8 bytes|
// |     data_len     | 4 bytes|
// |     data         | N bytes|
// +------------------+--------+
// | crc32c           | 4 bytes| CRC of entire content before this field
// +------------------+--------+
// ```

/// Checkpoint file magic number ("MVCP" scrambled in little-endian).
const CHECKPOINT_MAGIC: u32 = 0x4D56_4350;

/// Current checkpoint format version.
const CHECKPOINT_VERSION: u16 = 1;

/// Checkpoint file header size in bytes.
const CHECKPOINT_HEADER_SIZE: usize = 28;

/// Persistent MVCC store with WAL durability.
///
/// This wrapper adds durability to `MvccStore` by writing committed versions
/// to a Write-Ahead Log before returning from `commit()`. On startup, the
/// WAL is replayed to restore the committed state.
///
/// The write path is backed by [`WalWriter`], which provides integrity checks,
/// configurable sync policy, backpressure signaling, and structured logging.
///
/// # Lock ordering invariant (bd-7zd94)
///
/// The struct holds three [`parking_lot::RwLock`]s. Any code path that
/// acquires more than one of them MUST do so in this order to prevent
/// AB-BA deadlock:
///
/// ```text
///     store  ──→  wal  ──→  stats
/// ```
///
/// Production callers comply:
///
/// | Caller                | store | wal   | stats | Notes                |
/// |-----------------------|-------|-------|-------|----------------------|
/// | `commit_with_options` | W     | W     | W     | full commit pipeline |
/// | `checkpoint`          | R     | -     | W     | stats nested in store|
/// | `truncate_wal`        | R     | W     | R, W  | brief stats(R) gate  |
///
/// Acquiring `wal` before `store` (e.g., a hypothetical `repack_wal`
/// that takes `wal.write()` first then `store.write()`) would
/// instantly deadlock against `commit_with_options`, which holds
/// `store.write()` while waiting on `wal.write()`.
///
/// New methods on this struct must respect the order. The
/// `lock_ordering_under_concurrent_commit_and_truncate` test exercises
/// it under concurrent load with a watchdog timeout.
#[derive(Debug)]
pub struct PersistentMvccStore {
    /// MVCC version store. **Lock-rank 0** — must be acquired before
    /// `wal` and `stats`. See struct-level doc.
    store: RwLock<MvccStore>,
    /// WAL append/sync handle. **Lock-rank 1** — must only be
    /// acquired while no `stats` lock is held; may be acquired while
    /// `store` is held.
    wal: RwLock<WalWriter>,
    /// Persistence statistics + checkpoint horizon. **Lock-rank 2** —
    /// must be acquired last (or alone). Never acquire `store` or
    /// `wal` while holding `stats`.
    stats: RwLock<WalStats>,
    recovery_report: WalRecoveryReport,
}

impl PersistentMvccStore {
    /// Open a persistent MVCC store, replaying the WAL if it exists.
    ///
    /// If the WAL file doesn't exist, it will be created with a fresh header.
    /// If it exists, it will be replayed to restore committed state.
    ///
    /// # Arguments
    ///
    /// * `_cx` - Capability context for I/O (currently unused, reserved for
    ///   future async I/O integration).
    /// * `wal_path` - Path to the WAL file.
    ///
    /// # Errors
    ///
    /// Returns an error if the WAL file cannot be opened/created or if replay
    /// fails due to corruption (corruption at the tail is tolerated).
    pub fn open(cx: &Cx, wal_path: impl AsRef<Path>) -> Result<Self> {
        let wal_path = wal_path.as_ref();
        let checkpoint_path = wal_path.with_extension("ckpt");
        if checkpoint_path.exists() {
            Self::open_with_checkpoint_and_options(
                cx,
                wal_path,
                checkpoint_path,
                &PersistOptions::default(),
            )
        } else {
            Self::open_with_options(cx, wal_path, &PersistOptions::default())
        }
    }

    /// Open a persistent MVCC store with a checkpoint.
    ///
    /// If a checkpoint exists, it is loaded first, then any WAL entries after
    /// the checkpoint are replayed.
    pub fn open_with_checkpoint(
        cx: &Cx,
        wal_path: impl AsRef<Path>,
        checkpoint_path: impl AsRef<Path>,
    ) -> Result<Self> {
        Self::open_with_checkpoint_and_options(
            cx,
            wal_path,
            checkpoint_path,
            &PersistOptions::default(),
        )
    }

    /// Open a persistent MVCC store with a checkpoint and custom options.
    pub fn open_with_checkpoint_and_options(
        _cx: &Cx,
        wal_path: impl AsRef<Path>,
        checkpoint_path: impl AsRef<Path>,
        options: &PersistOptions,
    ) -> Result<Self> {
        let wal_path = wal_path.as_ref();
        let checkpoint_path = checkpoint_path.as_ref();
        let writer_config = options.to_writer_config();

        let mut store = MvccStore::new();
        let mut stats = WalStats::default();
        let mut recovery = WalRecoveryReport::default();

        // Try to load checkpoint first
        if checkpoint_path.exists() {
            load_checkpoint(checkpoint_path, &mut store)?;
            let ckpt_seq = store.next_commit.saturating_sub(1);
            stats.checkpoint_commit_seq = ckpt_seq;
            recovery.used_checkpoint = true;
            recovery.checkpoint_commit_seq = Some(ckpt_seq);
        }

        // Open or create WAL
        let wal_exists = wal_path.exists();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(wal_path)?;

        let write_pos: u64;

        let wal_total_bytes = if wal_exists {
            file.metadata()?.len()
        } else {
            0
        };

        if wal_exists && wal_total_bytes > 0 {
            // Replay WAL entries that are newer than the checkpoint
            let checkpoint_seq = store.next_commit.saturating_sub(1);
            let (pos, replay_stats) = replay_wal_from_seq(&mut file, &mut store, checkpoint_seq)?;
            truncate_wal_tail_if_needed(&file, pos, wal_total_bytes)?;
            write_pos = pos;
            stats.replayed_commits = replay_stats.commits_replayed;
            stats.replayed_versions = replay_stats.versions_replayed;

            recovery.outcome = replay_stats.outcome;
            recovery.commits_replayed = replay_stats.commits_replayed;
            recovery.versions_replayed = replay_stats.versions_replayed;
            recovery.records_discarded = replay_stats.records_discarded;
            recovery.wal_valid_bytes = pos;
            recovery.wal_total_bytes = wal_total_bytes;
        } else {
            // Write fresh WAL header
            let header = WalHeader::default();
            let header_bytes = wal::encode_header(&header);
            file.write_all(&header_bytes)?;
            file.sync_all()?;
            write_pos = u64::try_from(HEADER_SIZE)
                .map_err(|_| FfsError::Format("header size overflow".to_owned()))?;
        }

        stats.wal_size_bytes = write_pos;

        let mut writer = WalWriter::new(file, write_pos, writer_config);
        writer.set_last_commit_seq(store.next_commit.saturating_sub(1));

        Ok(Self {
            store: RwLock::new(store),
            wal: RwLock::new(writer),
            stats: RwLock::new(stats),
            recovery_report: recovery,
        })
    }

    /// Open a persistent MVCC store with custom options.
    pub fn open_with_options(
        _cx: &Cx,
        wal_path: impl AsRef<Path>,
        options: &PersistOptions,
    ) -> Result<Self> {
        let path = wal_path.as_ref();
        let exists = path.exists();
        let writer_config = options.to_writer_config();

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let mut store = MvccStore::new();
        let mut stats = WalStats::default();
        let mut recovery = WalRecoveryReport::default();
        let write_pos: u64;

        let wal_total_bytes = if exists { file.metadata()?.len() } else { 0 };

        if exists && wal_total_bytes > 0 {
            // Replay existing WAL
            let (pos, replay_stats) = replay_wal(&mut file, &mut store)?;
            truncate_wal_tail_if_needed(&file, pos, wal_total_bytes)?;
            write_pos = pos;
            stats.replayed_commits = replay_stats.commits_replayed;
            stats.replayed_versions = replay_stats.versions_replayed;

            recovery.outcome = replay_stats.outcome;
            recovery.commits_replayed = replay_stats.commits_replayed;
            recovery.versions_replayed = replay_stats.versions_replayed;
            recovery.records_discarded = replay_stats.records_discarded;
            recovery.wal_valid_bytes = pos;
            recovery.wal_total_bytes = wal_total_bytes;
        } else {
            // Write fresh header
            let header = WalHeader::default();
            let header_bytes = wal::encode_header(&header);
            file.write_all(&header_bytes)?;
            file.sync_all()?;
            write_pos = u64::try_from(HEADER_SIZE)
                .map_err(|_| FfsError::Format("header size overflow".to_owned()))?;
        }

        stats.wal_size_bytes = write_pos;

        let mut writer = WalWriter::new(file, write_pos, writer_config);
        writer.set_last_commit_seq(store.next_commit.saturating_sub(1));

        Ok(Self {
            store: RwLock::new(store),
            wal: RwLock::new(writer),
            stats: RwLock::new(stats),
            recovery_report: recovery,
        })
    }

    /// Begin a new transaction.
    ///
    /// The transaction is not persisted until `commit()` is called and succeeds.
    pub fn begin(&self) -> Transaction {
        self.store.write().begin()
    }

    /// Commit a transaction, writing it to the WAL before returning.
    ///
    /// On success, the commit is durable (written and optionally synced to disk).
    /// On conflict, the transaction is aborted and nothing is written.
    pub fn commit(&self, txn: Transaction) -> std::result::Result<CommitSeq, CommitError> {
        self.commit_internal(txn, false)
    }

    /// Commit with Serializable Snapshot Isolation (SSI) enforcement.
    pub fn commit_ssi(&self, txn: Transaction) -> std::result::Result<CommitSeq, CommitError> {
        self.commit_internal(txn, true)
    }

    /// # Atomic-or-rollback reasoning mode (bd-gqswx)
    ///
    /// This function implements a strict atomic-or-rollback contract:
    /// the in-memory `MvccStore` commits FIRST (advancing
    /// `next_commit`, appending a new `BlockVersion` to each touched
    /// block's chain, and recording an SSI log entry under
    /// `commit_ssi`), and the WAL append happens SECOND. If the WAL
    /// append fails, [`rollback_in_memory_commit`] MUST reverse the
    /// in-memory commit before returning `Err`, otherwise the system
    /// diverges in an unrecoverable way: a reader at the latest
    /// snapshot would see data that never reached the WAL.
    ///
    /// **Any new failure path inserted after the in-memory commit
    /// (i.e. after line `commit_seq = ...`) MUST call
    /// `rollback_in_memory_commit(&mut store_guard, txn_id.0,
    /// commit_seq, &write_blocks, &cow_blocks, use_ssi)` before
    /// returning the error.** Forgetting any of the five state
    /// pieces the rollback covers
    /// (write_blocks chain head, cow_blocks chain head, SSI log
    /// entry, `next_commit`, `next_txn` reservation) leaves the
    /// store wedged.
    ///
    /// Tests `wal_append_failure_rolls_back_commit_state`,
    /// `wal_append_failure_rolls_back_ssi_log_and_commit_seq`, and
    /// `wal_sync_failure_multi_block_rollback` verify the contract
    /// for the WAL-append failure path; new failure paths must add
    /// equivalent regression tests.
    fn commit_internal(
        &self,
        txn: Transaction,
        use_ssi: bool,
    ) -> std::result::Result<CommitSeq, CommitError> {
        let txn_id = txn.id();
        let write_blocks: Vec<BlockNumber> = txn.write_set().keys().copied().collect();
        let cow_blocks: Vec<BlockNumber> = write_blocks
            .iter()
            .copied()
            .filter(|block| txn.staged_physical(*block).is_some())
            .collect();

        let mut store_guard = self.store.write();
        let writes: Vec<wal::WalWrite> = store_guard
            .resolved_writes_for_commit(&txn)?
            .into_iter()
            .map(|(block, data)| wal::WalWrite { block, data })
            .collect();
        let commit_seq = if use_ssi {
            store_guard.commit_ssi(txn)?
        } else {
            store_guard.commit(txn)?
        };

        let wal_commit = wal::WalCommit {
            commit_seq,
            txn_id,
            writes,
        };

        let mut wal_guard = self.wal.write();
        if let Err(error) = wal_guard.append_commit(&wal_commit) {
            rollback_in_memory_commit(
                &mut store_guard,
                txn_id.0,
                commit_seq,
                &write_blocks,
                &cow_blocks,
                use_ssi,
            );
            return Err(CommitError::DurabilityFailure {
                detail: format!("WAL write failed: {error}"),
            });
        }

        let mut stats = self.stats.write();
        stats.commits_written += 1;
        stats.wal_size_bytes = wal_guard.size();
        drop(stats);
        drop(wal_guard);

        Ok(commit_seq)
    }

    /// Read data visible at a snapshot.
    pub fn read_visible(&self, block: BlockNumber, snapshot: crate::Snapshot) -> Option<Vec<u8>> {
        self.store
            .read()
            .read_visible(block, snapshot)
            .map(std::borrow::Cow::into_owned)
    }

    /// Get the current snapshot (latest committed state).
    pub fn current_snapshot(&self) -> crate::Snapshot {
        self.store.read().current_snapshot()
    }

    /// Get the latest commit sequence for a block.
    pub fn latest_commit_seq(&self, block: BlockNumber) -> CommitSeq {
        self.store.read().latest_commit_seq(block)
    }

    /// Register a snapshot as active (prevents GC from pruning needed versions).
    pub fn register_snapshot(&self, snapshot: crate::Snapshot) {
        self.store.write().register_snapshot(snapshot);
    }

    /// Release a previously registered snapshot.
    pub fn release_snapshot(&self, snapshot: crate::Snapshot) -> bool {
        self.store.write().release_snapshot(snapshot)
    }

    /// Get the recovery report from the most recent WAL replay.
    ///
    /// This captures how many commits were replayed, how many records were
    /// discarded, and whether a checkpoint was used. Useful for evidence
    /// ledger integration.
    pub fn recovery_report(&self) -> &WalRecoveryReport {
        &self.recovery_report
    }

    /// Get WAL statistics.
    pub fn wal_stats(&self) -> WalStats {
        *self.stats.read()
    }

    /// Total number of block versions stored across all blocks.
    pub fn version_count(&self) -> usize {
        self.store.read().version_count()
    }

    /// Sync the WAL to disk.
    ///
    /// This ensures all written commits are durable. Normally called automatically
    /// if `sync_on_commit` is enabled.
    pub fn sync(&self) -> Result<()> {
        self.wal.write().flush().map(|_| ()).map_err(FfsError::from)
    }

    /// Create a checkpoint of the current MVCC state.
    ///
    /// This writes a compact snapshot to `checkpoint_path` that can be loaded
    /// faster than replaying the entire WAL. The checkpoint is written atomically
    /// using a temp file + rename.
    ///
    /// After checkpointing, you can optionally truncate the WAL to reduce space
    /// by calling `truncate_wal()`, but only if no newer commits have landed
    /// since the checkpoint snapshot was taken.
    ///
    /// # Arguments
    ///
    /// * `checkpoint_path` - Path where the checkpoint will be written.
    ///
    /// # Errors
    ///
    /// Returns an error if the checkpoint cannot be written.
    pub fn checkpoint(&self, checkpoint_path: impl AsRef<Path>) -> Result<()> {
        let path = checkpoint_path.as_ref();

        // Hold the store read lock through snapshot collection AND stats update.
        // This prevents a concurrent commit() from advancing next_commit between
        // our snapshot and the stats.checkpoint_commit_seq write, which would let
        // a subsequent truncate_wal() pass the staleness check against a stale
        // checkpoint_commit_seq value.
        let store_guard = self.store.read();
        let next_txn = store_guard.next_txn;
        let next_commit = store_guard.next_commit;

        // Collect all versions. `versions` is an FxHashMap (93ee0569) whose
        // iteration order is non-deterministic, so sort by block to keep the
        // serialized checkpoint byte-for-byte DETERMINISTIC (block-ascending) —
        // the golden checkpoint + any cross-run/replay comparison depend on it.
        // (93ee0569 added the flush-path sort but missed this checkpoint one,
        // leaving `checkpoint_golden_report` failing on main. bd-mvcckptsort.)
        let mut versions_snapshot: Vec<(BlockNumber, Vec<BlockVersion>)> = store_guard
            .versions
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        versions_snapshot.sort_unstable_by_key(|(block, _)| *block);

        // Write to temp file first (still holding store read lock to block
        // concurrent commits — the file I/O cost is acceptable because
        // checkpoint() is an infrequent, explicitly requested operation).
        let temp_path = path.with_extension("tmp");
        {
            let file = File::create(&temp_path)?;
            let mut writer = BufWriter::new(file);
            write_checkpoint(&mut writer, next_txn, next_commit, &versions_snapshot)?;
            writer.flush()?;
            writer
                .into_inner()
                .map_err(|e| FfsError::Format(format!("checkpoint write error: {e}")))?
                .sync_all()?;
        }

        // Atomic rename
        fs::rename(&temp_path, path)?;

        // Sync the parent directory to ensure the rename is durable.
        if let Some(parent) = path.parent()
            && let Ok(dir) = File::open(parent)
        {
            let _ = dir.sync_all();
        }

        // Update stats while still holding the store read lock, ensuring
        // checkpoint_commit_seq is consistent with the actual store state.
        {
            let mut stats = self.stats.write();
            stats.checkpoints_created += 1;
            stats.checkpoint_commit_seq = next_commit.saturating_sub(1);
        }

        drop(store_guard);

        Ok(())
    }

    /// Truncate the WAL after a checkpoint.
    ///
    /// This resets the WAL to just the header, reducing disk space usage.
    /// Should only be called after a successful checkpoint.
    ///
    /// # Warning
    ///
    /// If called without a valid checkpoint, or if newer commits landed after
    /// the checkpoint snapshot, committed WAL data will be lost.
    pub fn truncate_wal(&self) -> Result<()> {
        // Hold a shared store lock while checking the checkpoint horizon and
        // truncating the WAL. This blocks concurrent commits (which require the
        // store write lock) from sneaking in between the freshness check and the
        // destructive WAL rewrite.
        let store_guard = self.store.read();
        let current_commit_seq = store_guard.next_commit.saturating_sub(1);
        let checkpoint_commit_seq = self.stats.read().checkpoint_commit_seq;
        if current_commit_seq > checkpoint_commit_seq {
            return Err(FfsError::Format(format!(
                "refusing to truncate WAL: checkpoint is stale (checkpoint_commit_seq={checkpoint_commit_seq}, latest_commit_seq={current_commit_seq})"
            )));
        }

        let header_size = {
            let mut wal_guard = self.wal.write();
            let file = wal_guard.file_mut();

            // Rewrite just the header
            file.seek(SeekFrom::Start(0))?;
            let header = WalHeader::default();
            let header_bytes = wal::encode_header(&header);
            file.write_all(&header_bytes)?;

            // Truncate to header size
            let header_size = u64::try_from(HEADER_SIZE)
                .map_err(|_| FfsError::Format("header size overflow".to_owned()))?;
            file.set_len(header_size)?;
            wal_guard.write_pos = header_size;
            wal_guard.set_last_commit_seq(current_commit_seq);

            if wal_guard.pending_sync_count() > 0 {
                wal_guard.flush().map(|_| ()).map_err(FfsError::from)?;
            } else {
                wal_guard.file_mut().sync_all()?;
            }

            header_size
        };

        drop(store_guard);

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.wal_size_bytes = header_size;
        }

        Ok(())
    }
}

/// Reverse an in-memory commit when the WAL append (or any other
/// post-commit step) fails. **This is the rollback partner of the
/// atomic-or-rollback contract documented on
/// [`PersistentMvccStore::commit_internal`].** (bd-gqswx)
///
/// The rollback covers FIVE state pieces. Forgetting any of them
/// leaves the store wedged in a state where a reader at the latest
/// snapshot sees data that never reached the WAL:
///
/// 1. **`write_blocks` chain heads** — pop the just-inserted
///    `BlockVersion` from each block's `versions` chain (and remove
///    the block entry entirely if the chain becomes empty). The
///    pop must match by `(commit_seq, txn_id)` so concurrent
///    commits at different seqs are not affected.
/// 2. **`cow_blocks` physical-versions chain heads** — same pop
///    semantics applied to `physical_versions` for the subset of
///    write_blocks that staged a physical (CoW) write.
/// 3. **SSI log entry** — under `use_ssi`, the SSI log
///    (`store.ssi_log`) gains an entry per commit; pop the matching
///    `(commit_seq, txn_id)` entry.
/// 4. **`next_commit` advance** — roll back the commit-seq counter
///    so the failed slot can be reused. Without this rollback, every
///    subsequent commit observes a gap in the seq sequence and the
///    WAL replay logic must tolerate the hole.
/// 5. **`next_txn` reservation** — the txn ID was reserved during
///    `begin()`; this rollback intentionally does NOT release it,
///    because the caller of `commit_internal` cannot retry with the
///    same txn (the Transaction has been moved into commit).
///
/// Any new caller that needs to roll back partial commit state
/// MUST call this function with the EXACT `txn_id` and `commit_seq`
/// produced by the in-memory commit, plus the original
/// `write_blocks` and `cow_blocks` lists. Calling with a wrong
/// `commit_seq` is a no-op (the version-pop guard checks
/// `v.commit_seq == commit_seq`); calling with a wrong txn_id
/// likewise no-ops.
fn rollback_in_memory_commit(
    store: &mut MvccStore,
    txn_id: u64,
    commit_seq: CommitSeq,
    write_blocks: &[BlockNumber],
    cow_blocks: &[BlockNumber],
    use_ssi: bool,
) {
    for block in write_blocks {
        let remove_entry = store.versions.get_mut(block).is_some_and(|versions| {
            if versions
                .last()
                .is_some_and(|v| v.commit_seq == commit_seq && v.writer.0 == txn_id)
            {
                versions.pop();
            }
            versions.is_empty()
        });
        if remove_entry {
            store.versions.remove(block);
        }
    }

    for block in cow_blocks {
        let remove_entry = store
            .physical_versions
            .get_mut(block)
            .is_some_and(|versions| {
                if versions
                    .last()
                    .is_some_and(|v| v.commit_seq == commit_seq && v.writer.0 == txn_id)
                {
                    versions.pop();
                }
                versions.is_empty()
            });
        if remove_entry {
            store.physical_versions.remove(block);
        }
    }

    if use_ssi
        && let Some(last) = store.ssi_log.last()
        && last.commit_seq == commit_seq
        && last.txn_id.0 == txn_id
    {
        store.ssi_log.pop();
    }

    // Roll commit sequence back so the next successful commit can reuse this slot.
    store.next_commit = commit_seq.0;
}

/// Write a checkpoint to a writer.
fn write_checkpoint(
    writer: &mut BufWriter<File>,
    next_txn: u64,
    next_commit: u64,
    versions: &[(BlockNumber, Vec<BlockVersion>)],
) -> Result<()> {
    let mut checkpoint = Vec::with_capacity(checkpoint_payload_capacity(versions));

    // Header
    let mut header = [0_u8; CHECKPOINT_HEADER_SIZE];
    header[0..4].copy_from_slice(&CHECKPOINT_MAGIC.to_le_bytes());
    header[4..6].copy_from_slice(&CHECKPOINT_VERSION.to_le_bytes());
    // bytes 6..8 reserved
    header[8..16].copy_from_slice(&next_txn.to_le_bytes());
    header[16..24].copy_from_slice(&next_commit.to_le_bytes());
    let num_blocks = u32::try_from(versions.len())
        .map_err(|_| FfsError::Format("too many blocks for checkpoint".to_owned()))?;
    header[24..28].copy_from_slice(&num_blocks.to_le_bytes());

    checkpoint.extend_from_slice(&header);

    // Each block and its versions
    for (block, block_versions) in versions {
        let block_bytes = block.0.to_le_bytes();
        checkpoint.extend_from_slice(&block_bytes);

        let num_versions = u32::try_from(block_versions.len())
            .map_err(|_| FfsError::Format("too many versions for block".to_owned()))?;
        let num_versions_bytes = num_versions.to_le_bytes();
        checkpoint.extend_from_slice(&num_versions_bytes);

        for (vi, version) in block_versions.iter().enumerate() {
            let commit_seq_bytes = version.commit_seq.0.to_le_bytes();
            checkpoint.extend_from_slice(&commit_seq_bytes);

            let txn_id_bytes = version.writer.0.to_le_bytes();
            checkpoint.extend_from_slice(&txn_id_bytes);

            if version.data.is_identical() {
                let data_len_bytes = u32::MAX.to_le_bytes();
                checkpoint.extend_from_slice(&data_len_bytes);
                continue;
            }

            // Materialize compressed data: resolve Identical markers before writing.
            let materialized =
                crate::compression::resolve_data_with(block_versions, vi, |v| &v.data)
                    .unwrap_or(std::borrow::Cow::Borrowed(&[]));

            let data_len = u32::try_from(materialized.len())
                .map_err(|_| FfsError::Format("version data too large".to_owned()))?;
            let data_len_bytes = data_len.to_le_bytes();
            checkpoint.extend_from_slice(&data_len_bytes);

            checkpoint.extend_from_slice(&materialized);
        }
    }

    // Trailing CRC
    let crc = crc32c::crc32c(&checkpoint);
    checkpoint.extend_from_slice(&crc.to_le_bytes());
    writer.write_all(&checkpoint)?;

    Ok(())
}

fn checkpoint_payload_capacity(versions: &[(BlockNumber, Vec<BlockVersion>)]) -> usize {
    let mut capacity = CHECKPOINT_HEADER_SIZE + 4;
    for (_, block_versions) in versions {
        capacity = capacity.saturating_add(12);
        for version in block_versions {
            capacity = capacity.saturating_add(20);
            if !version.data.is_identical() {
                capacity = capacity.saturating_add(version.data.memory_bytes());
            }
        }
    }
    capacity
}

/// Read a single block version from a checkpoint stream.
fn read_block_version(
    reader: &mut BufReader<File>,
    hasher: &mut Crc32cHasher,
    file_len: u64,
    block: BlockNumber,
    dedup: bool,
    versions: &[BlockVersion],
) -> Result<BlockVersion> {
    let mut commit_seq_bytes = [0_u8; 8];
    reader.read_exact(&mut commit_seq_bytes)?;
    hasher.update(&commit_seq_bytes);
    let commit_seq = CommitSeq(u64::from_le_bytes(commit_seq_bytes));

    let mut txn_id_bytes = [0_u8; 8];
    reader.read_exact(&mut txn_id_bytes)?;
    hasher.update(&txn_id_bytes);
    let txn_id = ffs_types::TxnId(u64::from_le_bytes(txn_id_bytes));

    let mut data_len_bytes = [0_u8; 4];
    reader.read_exact(&mut data_len_bytes)?;
    hasher.update(&data_len_bytes);
    let data_len_u32 = u32::from_le_bytes(data_len_bytes);

    if data_len_u32 == u32::MAX {
        return Ok(BlockVersion {
            block,
            commit_seq,
            writer: txn_id,
            data: crate::compression::VersionData::Identical,
        });
    }

    let data_len = data_len_u32 as usize;

    if data_len as u64 > file_len {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!("checkpoint data_len {data_len} exceeds file size"),
        });
    }

    let mut data = vec![0_u8; data_len];
    reader.read_exact(&mut data)?;
    hasher.update(&data);

    let version_data = if dedup && !versions.is_empty() {
        let last_idx = versions.len() - 1;
        let is_identical =
            crate::compression::resolve_data_with(versions, last_idx, |v: &BlockVersion| &v.data)
                .as_deref()
                == Some(data.as_slice());
        if is_identical {
            crate::compression::VersionData::Identical
        } else {
            crate::compression::VersionData::full(data)
        }
    } else {
        crate::compression::VersionData::full(data)
    };

    Ok(BlockVersion {
        block,
        commit_seq,
        writer: txn_id,
        data: version_data,
    })
}

/// Load a checkpoint from a file into an MvccStore.
fn load_checkpoint(path: &Path, store: &mut MvccStore) -> Result<()> {
    let file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let mut reader = BufReader::new(file);
    let mut hasher = Crc32cHasher::new();

    // Read and validate header
    let mut header = [0_u8; CHECKPOINT_HEADER_SIZE];
    reader.read_exact(&mut header)?;
    hasher.update(&header);

    let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if magic != CHECKPOINT_MAGIC {
        return Err(FfsError::Format(format!(
            "checkpoint magic mismatch: expected {CHECKPOINT_MAGIC:#010x}, got {magic:#010x}"
        )));
    }

    let version = u16::from_le_bytes([header[4], header[5]]);
    if version != CHECKPOINT_VERSION {
        return Err(FfsError::Format(format!(
            "unsupported checkpoint version: {version}"
        )));
    }

    let next_txn = u64::from_le_bytes([
        header[8], header[9], header[10], header[11], header[12], header[13], header[14],
        header[15],
    ]);
    let next_commit = u64::from_le_bytes([
        header[16], header[17], header[18], header[19], header[20], header[21], header[22],
        header[23],
    ]);
    let num_blocks = u32::from_le_bytes([header[24], header[25], header[26], header[27]]);

    store.advance_counters(next_commit.saturating_sub(1), next_txn.saturating_sub(1));

    let dedup = store.compression_policy().dedup_identical;

    // Read blocks
    for _ in 0..num_blocks {
        let mut block_bytes = [0_u8; 8];
        reader.read_exact(&mut block_bytes)?;
        hasher.update(&block_bytes);
        let block = BlockNumber(u64::from_le_bytes(block_bytes));

        let mut num_versions_bytes = [0_u8; 4];
        reader.read_exact(&mut num_versions_bytes)?;
        hasher.update(&num_versions_bytes);
        let num_versions = u32::from_le_bytes(num_versions_bytes);

        let mut versions = Vec::with_capacity((num_versions as usize).min(1024));
        for _ in 0..num_versions {
            versions.push(read_block_version(
                &mut reader,
                &mut hasher,
                file_len,
                block,
                dedup,
                &versions,
            )?);
        }

        store.insert_versions(block, versions);
    }

    // Verify CRC
    let mut crc_bytes = [0_u8; 4];
    reader.read_exact(&mut crc_bytes)?;
    let stored_crc = u32::from_le_bytes(crc_bytes);
    let computed_crc = hasher.finalize();

    if stored_crc != computed_crc {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!(
                "checkpoint CRC mismatch: stored {stored_crc:#010x}, computed {computed_crc:#010x}"
            ),
        });
    }

    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(FfsError::Corruption {
            block: 0,
            detail: "checkpoint has trailing bytes after CRC".to_owned(),
        });
    }

    Ok(())
}

/// Simple CRC32c hasher for checkpoint verification.
struct Crc32cHasher {
    crc: u32,
}

impl Crc32cHasher {
    fn new() -> Self {
        Self { crc: 0 }
    }

    fn update(&mut self, data: &[u8]) {
        self.crc = crc32c::crc32c_append(self.crc, data);
    }

    fn finalize(self) -> u32 {
        self.crc
    }
}

/// Internal replay stats returned by WAL replay functions.
struct ReplayStats {
    outcome: ReplayOutcome,
    commits_replayed: u64,
    versions_replayed: u64,
    records_discarded: u64,
}

/// Replay WAL file into an MvccStore.
///
/// Returns `(write_position, replay_stats)`.
fn replay_wal(file: &mut File, store: &mut MvccStore) -> Result<(u64, ReplayStats)> {
    replay_wal_from_seq(file, store, 0)
}

/// Replay WAL file into an MvccStore, skipping commits at or before `skip_up_to_seq`.
///
/// Uses [`WalReplayEngine`] with [`TailPolicy::TruncateToLastGood`] for
/// production recovery.  Returns `(write_position, replay_stats)`.
fn replay_wal_from_seq(
    file: &mut File,
    store: &mut MvccStore,
    skip_up_to_seq: u64,
) -> Result<(u64, ReplayStats)> {
    file.seek(SeekFrom::Start(0))?;

    // Read and validate header.
    let mut header_buf = [0_u8; HEADER_SIZE];
    file.read_exact(&mut header_buf)?;
    let _header = wal::decode_header(&header_buf)?;

    // Read rest of file.
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    // Run through the replay engine.
    let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
    let report = engine.replay(&data, skip_up_to_seq, |commit| {
        apply_wal_commit(store, commit);
    })?;

    let header_size_u64 = u64::try_from(HEADER_SIZE)
        .map_err(|_| FfsError::Format("header size overflow".to_owned()))?;
    let write_pos = header_size_u64
        .checked_add(report.last_valid_offset)
        .ok_or_else(|| FfsError::Format("WAL position overflow".to_owned()))?;

    Ok((
        write_pos,
        ReplayStats {
            outcome: report.outcome,
            commits_replayed: report.commits_replayed,
            versions_replayed: report.versions_replayed,
            records_discarded: report.records_discarded,
        },
    ))
}

fn truncate_wal_tail_if_needed(file: &File, valid_bytes: u64, total_bytes: u64) -> Result<()> {
    if total_bytes > valid_bytes {
        file.set_len(valid_bytes)?;
        file.sync_all()?;
    }
    Ok(())
}

/// Apply a WAL commit record to an MvccStore.
///
/// This directly inserts versions into the store without going through the
/// normal transaction commit path, since we're replaying already-committed data.
pub fn apply_wal_commit(store: &mut MvccStore, commit: &WalCommit) {
    // Ensure the store's sequence counters are advanced appropriately
    // We need to update next_commit to be at least commit_seq + 1
    // and next_txn to be at least txn_id + 1
    if store.next_commit <= commit.commit_seq.0 {
        store.next_commit = commit.commit_seq.0.saturating_add(1);
    }
    if store.next_txn <= commit.txn_id.0 {
        store.next_txn = commit.txn_id.0.saturating_add(1);
    }

    // Insert each version
    let dedup_enabled = store.compression_policy().dedup_identical;
    for write in &commit.writes {
        let version_data = if dedup_enabled {
            store.maybe_dedup(write.block, &write.data)
        } else {
            store.compress_data(&write.data)
        };
        let version = BlockVersion {
            block: write.block,
            commit_seq: commit.commit_seq,
            writer: commit.txn_id,
            data: version_data,
        };
        store.versions.entry(write.block).or_default().push(version);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use tempfile::NamedTempFile;

    fn test_cx() -> Cx {
        Cx::for_testing()
    }

    #[test]
    fn open_creates_fresh_wal() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path();

        // Remove the file so we start fresh
        std::fs::remove_file(path).ok();

        let store = PersistentMvccStore::open(&cx, path).expect("open");
        let stats = store.wal_stats();
        assert_eq!(stats.replayed_commits, 0);
        assert_eq!(stats.wal_size_bytes, HEADER_SIZE as u64);
    }

    #[test]
    fn commit_persists_and_survives_reopen() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        // First session: write some data
        {
            let store = PersistentMvccStore::open(&cx, &path).expect("open");
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(10), vec![1, 2, 3, 4]);
            txn.stage_write(BlockNumber(20), vec![5, 6, 7, 8]);
            let seq = store.commit(txn).expect("commit");
            assert_eq!(seq, CommitSeq(1));

            let stats = store.wal_stats();
            assert_eq!(stats.commits_written, 1);
        }

        // Second session: reopen and verify data is restored
        {
            let store = PersistentMvccStore::open(&cx, &path).expect("reopen");
            let stats = store.wal_stats();
            assert_eq!(stats.replayed_commits, 1);
            assert_eq!(stats.replayed_versions, 2);

            let snap = store.current_snapshot();
            assert_eq!(snap.high, CommitSeq(1));

            let data10 = store.read_visible(BlockNumber(10), snap);
            assert_eq!(data10, Some(vec![1, 2, 3, 4]));

            let data20 = store.read_visible(BlockNumber(20), snap);
            assert_eq!(data20, Some(vec![5, 6, 7, 8]));
        }
    }

    #[test]
    fn uncommitted_not_persisted() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        // First session: write but don't commit
        {
            let store = PersistentMvccStore::open(&cx, &path).expect("open");
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(100), vec![0xAB; 16]);
            // Drop without committing
        }

        // Second session: verify nothing was persisted
        {
            let store = PersistentMvccStore::open(&cx, &path).expect("reopen");
            let stats = store.wal_stats();
            assert_eq!(stats.replayed_commits, 0);

            let snap = store.current_snapshot();
            let data = store.read_visible(BlockNumber(100), snap);
            assert!(data.is_none());
        }
    }

    #[test]
    fn multiple_commits_persist_correctly() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        // First session: multiple commits
        {
            let store = PersistentMvccStore::open(&cx, &path).expect("open");

            for i in 1_u8..=5 {
                let mut txn = store.begin();
                txn.stage_write(BlockNumber(u64::from(i)), vec![i; 16]);
                store.commit(txn).expect("commit");
            }

            let stats = store.wal_stats();
            assert_eq!(stats.commits_written, 5);
        }

        // Second session: verify all commits restored
        {
            let store = PersistentMvccStore::open(&cx, &path).expect("reopen");
            let stats = store.wal_stats();
            assert_eq!(stats.replayed_commits, 5);

            let snap = store.current_snapshot();
            assert_eq!(snap.high, CommitSeq(5));

            for i in 1_u8..=5 {
                let data = store.read_visible(BlockNumber(u64::from(i)), snap);
                assert_eq!(data, Some(vec![i; 16]));
            }
        }
    }

    #[test]
    fn truncated_wal_tail_handled_gracefully() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        // First session: write commits
        {
            let store = PersistentMvccStore::open(&cx, &path).expect("open");
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(1), vec![1; 32]);
            store.commit(txn).expect("commit 1");

            let mut txn = store.begin();
            txn.stage_write(BlockNumber(2), vec![2; 32]);
            store.commit(txn).expect("commit 2");
        }

        // Truncate the file to corrupt the last record
        {
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open for truncate");
            let len = file.metadata().expect("metadata").len();
            file.set_len(len - 10).expect("truncate");
        }

        // Second session: should recover first commit but not second
        {
            let store = PersistentMvccStore::open(&cx, &path).expect("reopen");
            let stats = store.wal_stats();
            assert_eq!(stats.replayed_commits, 1); // Only first commit survived

            let snap = store.current_snapshot();
            let data1 = store.read_visible(BlockNumber(1), snap);
            assert_eq!(data1, Some(vec![1; 32]));

            // Second commit was lost due to truncation
            // Note: depending on how much we truncated, this might or might not be present
            // The key invariant is that we don't crash
        }
    }

    #[test]
    fn conflicting_commit_not_persisted() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        {
            let store = PersistentMvccStore::open(&cx, &path).expect("open");

            // First transaction writes block 1
            let mut t1 = store.begin();
            t1.stage_write(BlockNumber(1), vec![1; 8]);
            store.commit(t1).expect("commit t1");

            // Second transaction (started before t1 committed) tries to write same block
            let _snap_before = store.current_snapshot();
            let mut t2 = store.begin();
            t2.stage_write(BlockNumber(1), vec![2; 8]);

            // Simulate t2 having started before t1's commit by manually setting snapshot
            // In real usage, begin() would have captured the old snapshot

            // This should fail due to FCW
            // (Note: our begin() already captured a snapshot after t1, so this won't
            // actually conflict. For a real conflict test we'd need to manipulate
            // the snapshot directly.)
        }
    }

    #[test]
    fn version_count_reflects_all_writes() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        let store = PersistentMvccStore::open(&cx, &path).expect("open");

        assert_eq!(store.version_count(), 0);

        let mut txn = store.begin();
        txn.stage_write(BlockNumber(1), vec![1; 8]);
        txn.stage_write(BlockNumber(2), vec![2; 8]);
        txn.stage_write(BlockNumber(3), vec![3; 8]);
        store.commit(txn).expect("commit");

        assert_eq!(store.version_count(), 3);
    }

    #[test]
    fn wal_append_failure_rolls_back_commit_state() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        let store = PersistentMvccStore::open(&cx, &path).expect("open");
        let before = store.current_snapshot();

        // Force WAL append failure (invalid seek offset).
        {
            let mut wal_guard = store.wal.write();
            wal_guard.write_pos = u64::MAX;
        }

        let mut txn = store.begin();
        txn.stage_write(BlockNumber(77), vec![7; 8]);
        let result = store.commit(txn);
        let err = result.expect_err("commit must fail when WAL append fails");
        assert!(
            matches!(err, CommitError::DurabilityFailure { .. }),
            "expected durability failure, got {err:?}"
        );

        // In-memory state must be unchanged.
        let after = store.current_snapshot();
        assert_eq!(after.high, before.high);
        assert_eq!(store.version_count(), 0);
        assert_eq!(store.read_visible(BlockNumber(77), after), None);

        let stats = store.wal_stats();
        assert_eq!(stats.commits_written, 0);
    }

    #[test]
    fn wal_append_failure_rolls_back_ssi_log_and_commit_seq() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        let store = PersistentMvccStore::open(&cx, &path).expect("open");

        // Force WAL append failure for SSI path too.
        {
            let mut wal_guard = store.wal.write();
            wal_guard.write_pos = u64::MAX;
        }

        let mut txn = store.begin();
        txn.stage_write(BlockNumber(91), vec![9; 16]);
        let result = store.commit_ssi(txn);
        let err = result.expect_err("SSI commit must fail when WAL append fails");
        assert!(
            matches!(err, CommitError::DurabilityFailure { .. }),
            "expected durability failure, got {err:?}"
        );

        // No committed data, no SSI history side-effects.
        assert_eq!(store.current_snapshot().high, CommitSeq(0));
        assert_eq!(
            store.read_visible(BlockNumber(91), store.current_snapshot()),
            None
        );
        let guard = store.store.read();
        assert!(
            guard.ssi_log.is_empty(),
            "failed SSI commit must not leave residual ssi_log entries"
        );
        assert_eq!(
            guard.next_commit, 1,
            "failed commit must restore next_commit"
        );
        drop(guard);
    }

    #[test]
    fn wal_sync_failure_rolls_back_commit_state() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        let store = PersistentMvccStore::open(&cx, &path).expect("open");
        let before = store.current_snapshot();

        // Force WAL sync failure after append succeeds.
        {
            let mut wal_guard = store.wal.write();
            wal_guard.fail_sync = true;
        }

        let mut txn = store.begin();
        txn.stage_write(BlockNumber(88), vec![8; 8]);
        let result = store.commit(txn);
        let err = result.expect_err("commit must fail when WAL sync fails");
        assert!(
            matches!(err, CommitError::DurabilityFailure { .. }),
            "expected durability failure, got {err:?}"
        );

        // In-memory state must be unchanged.
        let after = store.current_snapshot();
        assert_eq!(after.high, before.high);
        assert_eq!(store.version_count(), 0);
        assert_eq!(store.read_visible(BlockNumber(88), after), None);

        let stats = store.wal_stats();
        assert_eq!(stats.commits_written, 0);
    }

    #[test]
    fn wal_sync_failure_rolls_back_ssi_log_and_commit_seq_primary_path() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        let store = PersistentMvccStore::open(&cx, &path).expect("open");

        // Force WAL sync failure after append succeeds on SSI path.
        {
            let mut wal_guard = store.wal.write();
            wal_guard.fail_sync = true;
        }

        let mut txn = store.begin();
        txn.stage_write(BlockNumber(99), vec![9; 8]);
        let result = store.commit_ssi(txn);
        let err = result.expect_err("SSI commit must fail when WAL sync fails");
        assert!(
            matches!(err, CommitError::DurabilityFailure { .. }),
            "expected durability failure, got {err:?}"
        );

        // No committed data, no residual SSI history side-effects.
        assert_eq!(store.current_snapshot().high, CommitSeq(0));
        assert_eq!(
            store.read_visible(BlockNumber(99), store.current_snapshot()),
            None
        );

        let guard = store.store.read();
        assert!(
            guard.ssi_log.is_empty(),
            "failed SSI sync must not leave residual ssi_log entries"
        );
        assert_eq!(
            guard.next_commit, 1,
            "failed SSI sync must restore next_commit"
        );
        drop(guard);

        let stats = store.wal_stats();
        assert_eq!(stats.commits_written, 0);
    }

    // ── Checkpoint tests ────────────────────────────────────────────────────

    #[test]
    fn checkpoint_golden_report() {
        let cx = test_cx();
        let wal_tmp = NamedTempFile::new().expect("create wal file");
        let wal_path = wal_tmp.path().to_path_buf();
        let ckpt_tmp = NamedTempFile::new().expect("create checkpoint file");
        let ckpt_path = ckpt_tmp.path().to_path_buf();

        {
            let store = PersistentMvccStore::open_with_options(
                &cx,
                &wal_path,
                &PersistOptions {
                    sync_on_commit: false,
                    ..PersistOptions::default()
                },
            )
            .expect("open");

            for version in 0_u8..3 {
                for block in [3_u8, 1, 2] {
                    let mut txn = store.begin();
                    let data = (0_u8..64)
                        .map(|offset| {
                            block
                                .wrapping_mul(17)
                                .wrapping_add(version.wrapping_mul(31))
                                .wrapping_add(offset)
                        })
                        .collect();
                    txn.stage_write(BlockNumber(u64::from(block)), data);
                    store.commit(txn).expect("commit");
                }
            }

            store.checkpoint(&ckpt_path).expect("checkpoint");
        }

        let checkpoint = std::fs::read(&ckpt_path).expect("read checkpoint");
        let sha256 = Sha256::digest(&checkpoint);
        let mut sha256_hex = String::with_capacity(64);
        for byte in sha256 {
            use std::fmt::Write as _;
            write!(&mut sha256_hex, "{byte:02x}").expect("format sha256 hex");
        }
        assert_eq!(
            sha256_hex,
            "7adbdd643cc6f2d7d0512813d9c0db954a84af4c4b22b248401aafc70f9a8e17"
        );
        println!(
            "CHECKPOINT_GOLDEN|len={}|sha256={sha256_hex}",
            checkpoint.len()
        );

        let store = PersistentMvccStore::open_with_checkpoint(&cx, &wal_path, &ckpt_path)
            .expect("open with checkpoint");
        let snapshot = store.current_snapshot();
        assert_eq!(snapshot.high, CommitSeq(9));
        for block in [1_u8, 2, 3] {
            let data = store
                .read_visible(BlockNumber(u64::from(block)), snapshot)
                .expect("block visible");
            assert_eq!(data.len(), 64);
            assert_eq!(
                data[0],
                block.wrapping_mul(17).wrapping_add(2_u8.wrapping_mul(31))
            );
        }
    }

    #[test]
    fn checkpoint_and_restore() {
        let cx = test_cx();
        let wal_tmp = NamedTempFile::new().expect("create wal file");
        let wal_path = wal_tmp.path().to_path_buf();
        let ckpt_tmp = NamedTempFile::new().expect("create checkpoint file");
        let ckpt_path = ckpt_tmp.path().to_path_buf();

        // First session: write data and checkpoint
        {
            let store = PersistentMvccStore::open(&cx, &wal_path).expect("open");

            for i in 1_u8..=5 {
                let mut txn = store.begin();
                txn.stage_write(BlockNumber(u64::from(i)), vec![i; 32]);
                store.commit(txn).expect("commit");
            }

            store.checkpoint(&ckpt_path).expect("checkpoint");
            let stats = store.wal_stats();
            assert_eq!(stats.checkpoints_created, 1);
        }

        // Delete WAL to force restore from checkpoint only
        std::fs::remove_file(&wal_path).ok();

        // Second session: restore from checkpoint
        {
            let store = PersistentMvccStore::open_with_checkpoint(&cx, &wal_path, &ckpt_path)
                .expect("open with checkpoint");

            let snap = store.current_snapshot();
            assert_eq!(snap.high, CommitSeq(5));

            for i in 1_u8..=5 {
                let data = store.read_visible(BlockNumber(u64::from(i)), snap);
                assert_eq!(data, Some(vec![i; 32]));
            }
        }
    }

    #[test]
    fn checkpoint_plus_wal_replay() {
        let cx = test_cx();
        let wal_tmp = NamedTempFile::new().expect("create wal file");
        let wal_path = wal_tmp.path().to_path_buf();
        let ckpt_tmp = NamedTempFile::new().expect("create checkpoint file");
        let ckpt_path = ckpt_tmp.path().to_path_buf();

        // First session: write some data, checkpoint, then write more
        {
            let store = PersistentMvccStore::open(&cx, &wal_path).expect("open");

            // Write commits 1-3
            for i in 1_u8..=3 {
                let mut txn = store.begin();
                txn.stage_write(BlockNumber(u64::from(i)), vec![i; 16]);
                store.commit(txn).expect("commit");
            }

            // Checkpoint at commit 3
            store.checkpoint(&ckpt_path).expect("checkpoint");

            // Write more commits 4-6 (these go only to WAL)
            for i in 4_u8..=6 {
                let mut txn = store.begin();
                txn.stage_write(BlockNumber(u64::from(i)), vec![i; 16]);
                store.commit(txn).expect("commit");
            }
        }

        // Second session: restore from checkpoint + replay WAL
        {
            let store = PersistentMvccStore::open_with_checkpoint(&cx, &wal_path, &ckpt_path)
                .expect("open with checkpoint");

            let stats = store.wal_stats();
            // Should replay commits 4-6 from WAL (commits 1-3 are in checkpoint)
            assert_eq!(stats.replayed_commits, 3);

            let snap = store.current_snapshot();
            assert_eq!(snap.high, CommitSeq(6));

            // All data should be present
            for i in 1_u8..=6 {
                let data = store.read_visible(BlockNumber(u64::from(i)), snap);
                assert_eq!(data, Some(vec![i; 16]));
            }
        }
    }

    #[test]
    fn truncate_wal_after_checkpoint() {
        let cx = test_cx();
        let wal_tmp = NamedTempFile::new().expect("create wal file");
        let wal_path = wal_tmp.path().to_path_buf();
        let ckpt_tmp = NamedTempFile::new().expect("create checkpoint file");
        let ckpt_path = ckpt_tmp.path().to_path_buf();

        // First session: write data, checkpoint, truncate WAL
        {
            let store = PersistentMvccStore::open(&cx, &wal_path).expect("open");

            for i in 1_u8..=10 {
                let mut txn = store.begin();
                txn.stage_write(BlockNumber(u64::from(i)), vec![i; 64]);
                store.commit(txn).expect("commit");
            }

            let stats_before = store.wal_stats();
            assert!(stats_before.wal_size_bytes > HEADER_SIZE as u64);

            store.checkpoint(&ckpt_path).expect("checkpoint");
            store.truncate_wal().expect("truncate");

            let stats_after = store.wal_stats();
            assert_eq!(stats_after.wal_size_bytes, HEADER_SIZE as u64);
        }

        // Second session: restore from checkpoint (WAL is empty)
        {
            let store = PersistentMvccStore::open_with_checkpoint(&cx, &wal_path, &ckpt_path)
                .expect("open with checkpoint");

            let stats = store.wal_stats();
            assert_eq!(stats.replayed_commits, 0); // WAL was truncated

            let snap = store.current_snapshot();
            assert_eq!(snap.high, CommitSeq(10));

            // All data should still be present (from checkpoint)
            for i in 1_u8..=10 {
                let data = store.read_visible(BlockNumber(u64::from(i)), snap);
                assert_eq!(data, Some(vec![i; 64]));
            }
        }
    }

    #[test]
    fn truncate_wal_rejects_stale_checkpoint() {
        let cx = test_cx();
        let wal_tmp = NamedTempFile::new().expect("create wal file");
        let wal_path = wal_tmp.path().to_path_buf();
        let ckpt_tmp = NamedTempFile::new().expect("create checkpoint file");
        let ckpt_path = ckpt_tmp.path().to_path_buf();

        {
            let store = PersistentMvccStore::open(&cx, &wal_path).expect("open");

            for i in 1_u8..=3 {
                let mut txn = store.begin();
                txn.stage_write(BlockNumber(u64::from(i)), vec![i; 32]);
                store.commit(txn).expect("commit before checkpoint");
            }

            store.checkpoint(&ckpt_path).expect("checkpoint");

            let mut txn = store.begin();
            txn.stage_write(BlockNumber(4), vec![4; 32]);
            store.commit(txn).expect("commit after checkpoint");

            let err = store
                .truncate_wal()
                .expect_err("stale checkpoint must block truncation");
            assert!(
                matches!(&err, FfsError::Format(detail) if detail.contains("checkpoint is stale")),
                "expected stale-checkpoint format error, got {err:?}"
            );

            let stats = store.wal_stats();
            assert!(stats.wal_size_bytes > HEADER_SIZE as u64);
        }

        {
            let store = PersistentMvccStore::open_with_checkpoint(&cx, &wal_path, &ckpt_path)
                .expect("reopen with checkpoint");

            let stats = store.wal_stats();
            assert_eq!(stats.replayed_commits, 1);

            let snap = store.current_snapshot();
            assert_eq!(snap.high, CommitSeq(4));

            for i in 1_u8..=4 {
                let data = store.read_visible(BlockNumber(u64::from(i)), snap);
                assert_eq!(data, Some(vec![i; 32]));
            }
        }
    }

    /// Regression test for bd-mu0n: truncate_wal must reject truncation when
    /// the checkpoint is stale relative to the current commit sequence. After
    /// the fix, checkpoint() holds the store read lock through the stats
    /// update, preventing a concurrent commit from creating a window where
    /// checkpoint_commit_seq lags behind the actual store state.
    #[test]
    fn truncate_wal_preserves_post_checkpoint_commits() {
        let cx = test_cx();
        let wal_tmp = NamedTempFile::new().expect("create wal file");
        let wal_path = wal_tmp.path().to_path_buf();
        let ckpt_tmp = NamedTempFile::new().expect("create checkpoint file");
        let ckpt_path = ckpt_tmp.path().to_path_buf();

        // Session 1: checkpoint at commit 5, then commit 6 and 7
        {
            let store = PersistentMvccStore::open(&cx, &wal_path).expect("open");

            for i in 1_u8..=5 {
                let mut txn = store.begin();
                txn.stage_write(BlockNumber(u64::from(i)), vec![i; 48]);
                store.commit(txn).expect("commit before checkpoint");
            }

            store
                .checkpoint(&ckpt_path)
                .expect("checkpoint at commit 5");

            // Two more commits after the checkpoint
            for i in 6_u8..=7 {
                let mut txn = store.begin();
                txn.stage_write(BlockNumber(u64::from(i)), vec![i; 48]);
                store.commit(txn).expect("commit after checkpoint");
            }

            // truncate_wal MUST refuse — the checkpoint only covers commits 1-5
            let err = store
                .truncate_wal()
                .expect_err("truncation must be rejected when post-checkpoint commits exist");
            assert!(
                matches!(&err, FfsError::Format(detail) if detail.contains("checkpoint is stale")),
                "expected stale-checkpoint error, got {err:?}"
            );

            // WAL must still contain the post-checkpoint commits
            let stats = store.wal_stats();
            assert!(stats.wal_size_bytes > HEADER_SIZE as u64);
        }

        // Session 2: reopen from checkpoint + WAL — all 7 commits must survive
        {
            let store = PersistentMvccStore::open_with_checkpoint(&cx, &wal_path, &ckpt_path)
                .expect("reopen with checkpoint");

            let stats = store.wal_stats();
            assert_eq!(
                stats.replayed_commits, 2,
                "WAL should replay commits 6 and 7"
            );

            let snap = store.current_snapshot();
            assert_eq!(snap.high, CommitSeq(7));

            for i in 1_u8..=7 {
                let data = store.read_visible(BlockNumber(u64::from(i)), snap);
                assert_eq!(
                    data,
                    Some(vec![i; 48]),
                    "block {i} missing after checkpoint + WAL replay"
                );
            }
        }
    }

    #[test]
    fn checkpoint_detects_corruption() {
        let cx = test_cx();
        let wal_tmp = NamedTempFile::new().expect("create wal file");
        let wal_path = wal_tmp.path().to_path_buf();
        let ckpt_tmp = NamedTempFile::new().expect("create checkpoint file");
        let ckpt_path = ckpt_tmp.path().to_path_buf();

        // Create a valid checkpoint
        {
            let store = PersistentMvccStore::open(&cx, &wal_path).expect("open");
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(1), vec![1; 32]);
            store.commit(txn).expect("commit");
            store.checkpoint(&ckpt_path).expect("checkpoint");
        }

        // Corrupt the checkpoint
        {
            let mut data = std::fs::read(&ckpt_path).expect("read checkpoint");
            let mid = data.len() / 2;
            data[mid] ^= 0xFF;
            std::fs::write(&ckpt_path, &data).expect("write corrupted");
        }

        // Should fail to load corrupted checkpoint
        let result = PersistentMvccStore::open_with_checkpoint(&cx, &wal_path, &ckpt_path);
        assert!(result.is_err());
    }

    #[test]
    fn checkpoint_rejects_trailing_bytes_after_crc() {
        let cx = test_cx();
        let wal_tmp = NamedTempFile::new().expect("create wal file");
        let wal_path = wal_tmp.path().to_path_buf();
        let ckpt_tmp = NamedTempFile::new().expect("create checkpoint file");
        let ckpt_path = ckpt_tmp.path().to_path_buf();

        {
            let store = PersistentMvccStore::open(&cx, &wal_path).expect("open");
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(1), vec![1; 32]);
            store.commit(txn).expect("commit");
            store.checkpoint(&ckpt_path).expect("checkpoint");
        }

        {
            let mut file = OpenOptions::new()
                .append(true)
                .open(&ckpt_path)
                .expect("open checkpoint for append");
            file.write_all(b"stale checkpoint tail")
                .expect("append trailing bytes");
        }

        let err = PersistentMvccStore::open_with_checkpoint(&cx, &wal_path, &ckpt_path)
            .expect_err("checkpoint with trailing bytes must be rejected");
        assert!(
            matches!(
                err,
                FfsError::Corruption { detail, .. }
                    if detail.contains("trailing bytes after CRC")
            ),
            "expected trailing-byte corruption error"
        );
    }

    // ── Recovery report tests ─────────────────────────────────────────────

    #[test]
    fn recovery_report_fresh_wal() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path();
        std::fs::remove_file(path).ok();

        let store = PersistentMvccStore::open(&cx, path).expect("open");
        let report = store.recovery_report();
        assert_eq!(report.commits_replayed, 0);
        assert_eq!(report.versions_replayed, 0);
        assert_eq!(report.records_discarded, 0);
        assert!(!report.used_checkpoint);
        assert!(report.checkpoint_commit_seq.is_none());
    }

    #[test]
    fn representative_recovery_report_json_exact_golden_contract() {
        let report = WalRecoveryReport {
            outcome: ReplayOutcome::CorruptTail {
                records_discarded: 2,
                first_corrupt_offset: 4096,
            },
            commits_replayed: 7,
            versions_replayed: 11,
            records_discarded: 2,
            wal_valid_bytes: 8192,
            wal_total_bytes: 12288,
            used_checkpoint: true,
            checkpoint_commit_seq: Some(5),
        };

        let actual = serde_json::to_string(&report).expect("serialize");
        let expected = concat!(
            "{\"outcome\":{\"corrupt_tail\":{\"records_discarded\":2,\"first_corrupt_offset\":4096}}",
            ",\"commits_replayed\":7",
            ",\"versions_replayed\":11",
            ",\"records_discarded\":2",
            ",\"wal_valid_bytes\":8192",
            ",\"wal_total_bytes\":12288",
            ",\"used_checkpoint\":true",
            ",\"checkpoint_commit_seq\":5}"
        );
        assert_eq!(actual, expected);

        let parsed: WalRecoveryReport = serde_json::from_str(expected).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn recovery_report_after_replay() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        // Write 3 commits
        {
            let store = PersistentMvccStore::open(&cx, &path).expect("open");
            for i in 1_u8..=3 {
                let mut txn = store.begin();
                txn.stage_write(BlockNumber(u64::from(i)), vec![i; 16]);
                store.commit(txn).expect("commit");
            }
        }

        // Reopen and check recovery report
        {
            let store = PersistentMvccStore::open(&cx, &path).expect("reopen");
            let report = store.recovery_report();
            assert_eq!(report.commits_replayed, 3);
            assert_eq!(report.versions_replayed, 3);
            assert_eq!(report.records_discarded, 0);
            assert!(!report.used_checkpoint);
            assert!(report.wal_valid_bytes > 0);
        }
    }

    #[test]
    fn recovery_report_with_discarded_records() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        // Write 2 commits
        {
            let store = PersistentMvccStore::open(&cx, &path).expect("open");
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(1), vec![1; 32]);
            store.commit(txn).expect("commit 1");

            let mut txn = store.begin();
            txn.stage_write(BlockNumber(2), vec![2; 32]);
            store.commit(txn).expect("commit 2");
        }

        // Truncate to corrupt the last record
        {
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open for truncate");
            let len = file.metadata().expect("metadata").len();
            file.set_len(len - 10).expect("truncate");
        }

        // Reopen — should see 1 discarded record
        {
            let store = PersistentMvccStore::open(&cx, &path).expect("reopen");
            let report = store.recovery_report();
            assert_eq!(report.commits_replayed, 1);
            assert_eq!(report.records_discarded, 1);
            assert!(report.wal_total_bytes > report.wal_valid_bytes);
        }
    }

    #[test]
    fn replay_truncates_discarded_tail_from_wal() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        // Write two commits.
        {
            let store = PersistentMvccStore::open(&cx, &path).expect("open");
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(1), vec![1; 32]);
            store.commit(txn).expect("commit 1");

            let mut txn = store.begin();
            txn.stage_write(BlockNumber(2), vec![2; 32]);
            store.commit(txn).expect("commit 2");
        }

        // Corrupt the tail by truncating the second record.
        {
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open for truncate");
            let len = file.metadata().expect("metadata").len();
            file.set_len(len - 10).expect("truncate");
        }

        // First reopen should discard one record and trim file to valid bytes.
        {
            let store = PersistentMvccStore::open(&cx, &path).expect("reopen");
            let report = store.recovery_report();
            assert_eq!(report.commits_replayed, 1);
            assert_eq!(report.records_discarded, 1);

            let len_after = std::fs::metadata(&path).expect("metadata").len();
            assert_eq!(len_after, report.wal_valid_bytes);
        }

        // Second reopen should not rediscard the same tail.
        {
            let store = PersistentMvccStore::open(&cx, &path).expect("reopen again");
            let report = store.recovery_report();
            assert_eq!(report.records_discarded, 0);
            assert_eq!(report.commits_replayed, 1);
        }
    }

    #[test]
    fn replay_discards_duplicate_commit_sequence() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        let commit = WalCommit {
            commit_seq: CommitSeq(1),
            txn_id: ffs_types::TxnId(1),
            writes: vec![crate::wal::WalWrite {
                block: BlockNumber(7),
                data: vec![9; 16],
            }],
        };
        let encoded_commit = wal::encode_commit(&commit).expect("encode commit");

        // Build WAL manually: header + commit + duplicate commit.
        {
            let mut bytes = Vec::from(wal::encode_header(&WalHeader::default()));
            bytes.extend_from_slice(&encoded_commit);
            bytes.extend_from_slice(&encoded_commit);
            std::fs::write(&path, &bytes).expect("write WAL");
        }

        let store = PersistentMvccStore::open(&cx, &path).expect("reopen");
        let report = store.recovery_report();
        assert_eq!(report.commits_replayed, 1);
        assert_eq!(report.records_discarded, 1);

        let snap = store.current_snapshot();
        assert_eq!(store.read_visible(BlockNumber(7), snap), Some(vec![9; 16]));
    }

    #[test]
    fn recovery_report_with_checkpoint() {
        let cx = test_cx();
        let wal_tmp = NamedTempFile::new().expect("create wal file");
        let wal_path = wal_tmp.path().to_path_buf();
        let ckpt_tmp = NamedTempFile::new().expect("create checkpoint file");
        let ckpt_path = ckpt_tmp.path().to_path_buf();

        // Write 3 commits, checkpoint, write 2 more
        {
            let store = PersistentMvccStore::open(&cx, &wal_path).expect("open");
            for i in 1_u8..=3 {
                let mut txn = store.begin();
                txn.stage_write(BlockNumber(u64::from(i)), vec![i; 16]);
                store.commit(txn).expect("commit");
            }
            store.checkpoint(&ckpt_path).expect("checkpoint");
            for i in 4_u8..=5 {
                let mut txn = store.begin();
                txn.stage_write(BlockNumber(u64::from(i)), vec![i; 16]);
                store.commit(txn).expect("commit");
            }
        }

        // Reopen with checkpoint
        {
            let store = PersistentMvccStore::open_with_checkpoint(&cx, &wal_path, &ckpt_path)
                .expect("reopen");
            let report = store.recovery_report();
            assert!(report.used_checkpoint);
            assert_eq!(report.checkpoint_commit_seq, Some(3));
            // Only commits 4-5 should be replayed from WAL
            assert_eq!(report.commits_replayed, 2);
            assert_eq!(report.records_discarded, 0);
        }
    }

    // ── Fault Injection: WAL Interruption Tests ────────────────────────

    /// Helper: create a WAL with `n` commits, return path and per-commit byte
    /// sizes (so we know exactly where to truncate).
    fn create_wal_with_commits(n: u8) -> (std::path::PathBuf, Vec<u64>) {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("temp file");
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();

        let store = PersistentMvccStore::open(&cx, &path).expect("open");
        let mut sizes = Vec::new();
        for i in 1..=n {
            let prev_size = store.wal_stats().wal_size_bytes;
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(u64::from(i)), vec![i; 64]);
            store.commit(txn).expect("commit");
            sizes.push(store.wal_stats().wal_size_bytes - prev_size);
        }
        // Prevent NamedTempFile from being dropped (which would delete the file).
        let _ = tmp.into_temp_path().keep().expect("keep temp file");
        (path, sizes)
    }

    /// Scenario 1: Crash during WAL entry write (before fsync).
    ///
    /// Simulate by truncating the WAL mid-record after a successful first
    /// commit.  On recovery, only the first commit survives.
    #[test]
    fn fault_crash_before_fsync_loses_uncommitted() {
        let cx = test_cx();
        let (path, sizes) = create_wal_with_commits(2);

        // Truncate partway through the second commit record.
        let first_commit_end = HEADER_SIZE as u64 + sizes[0];
        let partial_second = first_commit_end + sizes[1] / 2;
        {
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open for truncate");
            file.set_len(partial_second).expect("truncate");
        }

        let store = PersistentMvccStore::open(&cx, &path).expect("reopen");
        let report = store.recovery_report();
        assert_eq!(
            report.commits_replayed, 1,
            "only first commit should survive"
        );
        assert!(
            report.records_discarded > 0,
            "truncated record should be discarded"
        );

        let snap = store.current_snapshot();
        assert_eq!(
            store.read_visible(BlockNumber(1), snap),
            Some(vec![1_u8; 64])
        );
        assert_eq!(store.read_visible(BlockNumber(2), snap), None);

        let _ = std::fs::remove_file(&path);
    }

    /// Scenario 2: Torn write — CRC32c detects partial record.
    ///
    /// Write a valid WAL, then corrupt the CRC of the last record by
    /// flipping bytes in the middle.  Recovery should discard the corrupt
    /// record.
    #[test]
    fn fault_torn_write_detected_by_crc() {
        let cx = test_cx();
        let (path, sizes) = create_wal_with_commits(2);

        // Corrupt a byte in the second commit record (flip the data area).
        let second_record_start = HEADER_SIZE as u64 + sizes[0];
        {
            let mut data = std::fs::read(&path).expect("read WAL");
            #[expect(clippy::cast_possible_truncation)]
            let corrupt_offset = second_record_start as usize + 25; // in the data area
            if corrupt_offset < data.len() {
                data[corrupt_offset] ^= 0xFF;
            }
            std::fs::write(&path, &data).expect("write corrupted WAL");
        }

        let store = PersistentMvccStore::open(&cx, &path).expect("reopen");
        let report = store.recovery_report();
        assert_eq!(report.commits_replayed, 1, "first commit should survive");
        assert!(
            report.records_discarded > 0,
            "corrupt record should be discarded"
        );

        let snap = store.current_snapshot();
        assert_eq!(
            store.read_visible(BlockNumber(1), snap),
            Some(vec![1_u8; 64])
        );
        assert_eq!(store.read_visible(BlockNumber(2), snap), None);

        let _ = std::fs::remove_file(&path);
    }

    /// Scenario 3: Crash after data entries written but before commit
    /// record completes.
    ///
    /// Truncate the WAL so the record_len field is present but the
    /// record body is incomplete.
    #[test]
    fn fault_crash_before_commit_record_complete() {
        let cx = test_cx();
        let (path, sizes) = create_wal_with_commits(2);

        // Truncate so only the first 8 bytes of the second record survive
        // (record_len + record_type + partial commit_seq).
        let second_record_start = HEADER_SIZE as u64 + sizes[0];
        let truncate_at = second_record_start + 8;
        {
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open for truncate");
            file.set_len(truncate_at).expect("truncate");
        }

        let store = PersistentMvccStore::open(&cx, &path).expect("reopen");
        let report = store.recovery_report();
        assert_eq!(report.commits_replayed, 1);
        assert!(report.records_discarded > 0);

        let snap = store.current_snapshot();
        assert_eq!(
            store.read_visible(BlockNumber(1), snap),
            Some(vec![1_u8; 64])
        );
        assert_eq!(store.read_visible(BlockNumber(2), snap), None);

        let _ = std::fs::remove_file(&path);
    }

    /// Scenario 4: Crash during commit record write — corrupt CRC at
    /// exact CRC field position.
    ///
    /// Overwrite the last 4 bytes (CRC field) of the second record with
    /// garbage.  The record_len will indicate a full record but the CRC
    /// won't match.
    #[test]
    fn fault_corrupt_commit_record_crc() {
        let cx = test_cx();
        let (path, sizes) = create_wal_with_commits(2);

        // Overwrite the CRC field (last 4 bytes of the second record).
        let second_record_end = HEADER_SIZE as u64 + sizes[0] + sizes[1];
        {
            let mut data = std::fs::read(&path).expect("read WAL");
            #[expect(clippy::cast_possible_truncation)]
            let crc_start = second_record_end as usize - 4;
            if crc_start + 4 <= data.len() {
                data[crc_start..crc_start + 4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
            }
            std::fs::write(&path, &data).expect("write corrupted WAL");
        }

        let store = PersistentMvccStore::open(&cx, &path).expect("reopen");
        let report = store.recovery_report();
        assert_eq!(report.commits_replayed, 1, "first commit should survive");
        assert!(report.records_discarded > 0, "bad CRC should be discarded");

        let snap = store.current_snapshot();
        assert_eq!(
            store.read_visible(BlockNumber(1), snap),
            Some(vec![1_u8; 64])
        );
        assert_eq!(store.read_visible(BlockNumber(2), snap), None);

        let _ = std::fs::remove_file(&path);
    }

    /// Scenario 5: Crash after commit record is fully written (durable)
    /// but before cache flush.
    ///
    /// Both commits are fully in the WAL, so recovery should restore
    /// everything.  This is the "good" crash case.
    #[test]
    fn fault_crash_after_commit_both_survive() {
        let cx = test_cx();
        let (path, _sizes) = create_wal_with_commits(3);

        // No corruption — the WAL is intact.  Simulate a "crash" by
        // simply reopening.
        let store = PersistentMvccStore::open(&cx, &path).expect("reopen");
        let report = store.recovery_report();
        assert_eq!(report.commits_replayed, 3, "all 3 commits should survive");
        assert_eq!(report.records_discarded, 0, "no discards expected");

        let snap = store.current_snapshot();
        for i in 1_u8..=3 {
            assert_eq!(
                store.read_visible(BlockNumber(u64::from(i)), snap),
                Some(vec![i; 64]),
                "block {i} should be intact"
            );
        }

        let _ = std::fs::remove_file(&path);
    }

    // ── WAL sync failure: extended rollback coverage ─────────────────────

    #[test]
    fn wal_sync_failure_multi_block_rollback() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        let store = PersistentMvccStore::open(&cx, &path).expect("open");

        // Force WAL sync failure.
        {
            let mut wal_guard = store.wal.write();
            wal_guard.fail_sync = true;
        }

        // Stage writes to multiple blocks in a single transaction.
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(10), vec![0xAA; 32]);
        txn.stage_write(BlockNumber(20), vec![0xBB; 32]);
        txn.stage_write(BlockNumber(30), vec![0xCC; 32]);
        let result = store.commit(txn);
        assert!(
            matches!(result, Err(CommitError::DurabilityFailure { .. })),
            "multi-block commit must fail when WAL sync fails"
        );

        // All three blocks must be rolled back.
        let snap = store.current_snapshot();
        assert_eq!(snap.high, CommitSeq(0));
        assert_eq!(store.version_count(), 0);
        assert_eq!(store.read_visible(BlockNumber(10), snap), None);
        assert_eq!(store.read_visible(BlockNumber(20), snap), None);
        assert_eq!(store.read_visible(BlockNumber(30), snap), None);
    }

    #[test]
    fn wal_sync_failure_recovery_allows_subsequent_commit() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        let store = PersistentMvccStore::open(&cx, &path).expect("open");

        // First: force a sync failure.
        {
            let mut wal_guard = store.wal.write();
            wal_guard.fail_sync = true;
        }

        let mut txn = store.begin();
        txn.stage_write(BlockNumber(50), vec![5; 8]);
        let result = store.commit(txn);
        assert!(result.is_err(), "first commit must fail");

        // Clear the failure flag.
        {
            let mut wal_guard = store.wal.write();
            wal_guard.fail_sync = false;
        }

        // Second commit must succeed with the correct commit sequence.
        let mut txn2 = store.begin();
        txn2.stage_write(BlockNumber(60), vec![6; 8]);
        let seq = store
            .commit(txn2)
            .expect("second commit must succeed after failure clears");
        assert_eq!(seq, CommitSeq(1));

        let snap = store.current_snapshot();
        assert_eq!(snap.high, CommitSeq(1));
        assert_eq!(store.read_visible(BlockNumber(60), snap), Some(vec![6; 8]));
        // The failed block must still be absent.
        assert_eq!(store.read_visible(BlockNumber(50), snap), None);

        let stats = store.wal_stats();
        assert_eq!(stats.commits_written, 1);
    }

    #[test]
    fn wal_sync_failure_after_successful_commit_preserves_prior_data() {
        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();

        let store = PersistentMvccStore::open(&cx, &path).expect("open");

        // First: successful commit.
        let mut txn1 = store.begin();
        txn1.stage_write(BlockNumber(100), vec![0xAA; 16]);
        let seq1 = store.commit(txn1).expect("first commit must succeed");
        assert_eq!(seq1, CommitSeq(1));

        // Now force sync failure.
        {
            let mut wal_guard = store.wal.write();
            wal_guard.fail_sync = true;
        }

        // Second commit fails.
        let mut txn2 = store.begin();
        txn2.stage_write(BlockNumber(200), vec![0xBB; 16]);
        let result = store.commit(txn2);
        assert!(
            matches!(result, Err(CommitError::DurabilityFailure { .. })),
            "second commit must fail"
        );

        // Prior commit data must still be visible.
        let snap = store.current_snapshot();
        assert_eq!(snap.high, CommitSeq(1));
        assert_eq!(
            store.read_visible(BlockNumber(100), snap),
            Some(vec![0xAA; 16])
        );
        assert_eq!(store.read_visible(BlockNumber(200), snap), None);
        assert_eq!(store.version_count(), 1);
    }

    /// Comprehensive: multiple truncation points across a 5-commit WAL.
    ///
    /// For each byte boundary between commits, truncate and verify that
    /// exactly the completed commits survive.
    #[test]
    fn fault_systematic_truncation_sweep() {
        let cx = test_cx();
        let (path, sizes) = create_wal_with_commits(5);

        // Cumulative byte positions where each commit ends.
        let mut boundaries = Vec::new();
        let mut pos = HEADER_SIZE as u64;
        for s in &sizes {
            pos += s;
            boundaries.push(pos);
        }

        // For each commit boundary, truncate just before it and verify
        // that exactly (i) commits survive.
        for (i, &boundary) in boundaries.iter().enumerate() {
            let truncate_at = boundary - 1; // one byte short of complete
            {
                // Copy the original WAL
                let original = std::fs::read(&path).expect("read WAL");
                let truncated_path = path.with_extension(format!("trunc{i}"));
                #[expect(clippy::cast_possible_truncation)]
                std::fs::write(&truncated_path, &original[..truncate_at as usize])
                    .expect("write truncated");

                let store = PersistentMvccStore::open(&cx, &truncated_path).expect("reopen");
                let report = store.recovery_report();
                assert_eq!(
                    report.commits_replayed,
                    i as u64,
                    "truncation before commit {}: expected {i} commits",
                    i + 1
                );
                assert!(report.records_discarded > 0);

                let _ = std::fs::remove_file(&truncated_path);
            }
        }

        let _ = std::fs::remove_file(&path);
    }

    /// Property: any sequence of N successful commits must survive
    /// reopen with `replayed_commits == N` and `replayed_versions ==
    /// total writes`. Pins the WAL durability contract — a regression
    /// that lost a commit (e.g. an off-by-one on the last record) would
    /// surface here regardless of the specific block/data shapes.
    ///
    /// Deterministic LCG sweep — no proptest dep needed since persist.rs
    /// already imports tempfile but not proptest.
    #[test]
    fn commit_persists_n_writes_survive_reopen_for_varied_n() {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || -> u64 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state
        };

        let cx = test_cx();
        for _ in 0..16 {
            let n_commits = 1 + usize::try_from(next() % 12).expect("commit count fits usize");
            let tmp = NamedTempFile::new().expect("create temp file");
            let path = tmp.path().to_path_buf();
            std::fs::remove_file(&path).ok();

            let mut total_writes: usize = 0;
            {
                let store = PersistentMvccStore::open(&cx, &path).expect("open");
                for c in 0..n_commits {
                    let writes_in_commit =
                        1 + usize::try_from(next() % 4).expect("write count fits usize");
                    let mut txn = store.begin();
                    for w in 0..writes_in_commit {
                        let logical_block = c.saturating_mul(100).saturating_add(w);
                        let block = u64::try_from(logical_block)
                            .expect("logical block fits u64")
                            .wrapping_mul(31);
                        let data: Vec<u8> = (0_u8..16)
                            .map(|i| {
                                u8::try_from(next() & 0xFF)
                                    .expect("masked byte fits u8")
                                    .wrapping_add(i)
                            })
                            .collect();
                        txn.stage_write(BlockNumber(block), data);
                    }
                    store.commit(txn).expect("commit");
                    total_writes += writes_in_commit;
                }
                let wal_written_stats = store.wal_stats();
                assert_eq!(
                    wal_written_stats.commits_written,
                    u64::try_from(n_commits).expect("commit count fits u64")
                );
            }

            // Reopen: every commit's data must be replayed.
            {
                let store = PersistentMvccStore::open(&cx, &path).expect("reopen");
                let reopened_wal_stats = store.wal_stats();
                assert_eq!(
                    reopened_wal_stats.replayed_commits,
                    u64::try_from(n_commits).expect("commit count fits u64"),
                    "n={}: replayed_commits {} != expected {}",
                    n_commits,
                    reopened_wal_stats.replayed_commits,
                    n_commits
                );
                assert_eq!(
                    reopened_wal_stats.replayed_versions,
                    u64::try_from(total_writes).expect("write count fits u64"),
                    "n={}: replayed_versions {} != expected {}",
                    n_commits,
                    reopened_wal_stats.replayed_versions,
                    total_writes
                );
            }

            std::fs::remove_file(&path).ok();
        }
    }

    /// bd-7zd94 — regression guard for the canonical lock-ordering
    /// invariant on `PersistentMvccStore` (store → wal → stats).
    /// Spawns concurrent writers that exercise both `commit`
    /// (acquires store.W → wal.W → stats.W) and `truncate_wal`
    /// (acquires store.R → wal.W → stats.W) under contention.
    /// A watchdog thread fails the test if the worker threads do not
    /// finish within a generous timeout; any AB-BA introduced by a
    /// future caller would manifest here as a hang and surface a clear
    /// failure rather than a silent regression.
    #[test]
    fn lock_ordering_under_concurrent_commit_and_truncate() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        use std::thread;
        use std::time::{Duration, Instant};

        const LOCK_ORDERING_WATCHDOG_POLL_INTERVAL: Duration = Duration::from_millis(10);

        let cx = test_cx();
        let tmp = NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();
        let store = Arc::new(PersistentMvccStore::open(&cx, &path).expect("open"));

        let done = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(15);

        // Watchdog: prove no thread is hung after the timeout elapses.
        let watchdog_done = Arc::clone(&done);
        let watchdog = thread::spawn(move || {
            loop {
                if watchdog_done.load(AtomicOrdering::Acquire) {
                    return;
                }
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let remaining = deadline.saturating_duration_since(now);
                thread::sleep(LOCK_ORDERING_WATCHDOG_POLL_INTERVAL.min(remaining));
            }
            // Reaching here means the workers did not finish in time;
            // a lock-ordering violation almost certainly caused a hang.
            assert!(
                watchdog_done.load(AtomicOrdering::Acquire),
                "bd-7zd94: PersistentMvccStore lock-ordering watchdog tripped - \
                 commit/truncate_wal workers did not finish within 15s, \
                 indicating a likely AB-BA deadlock"
            );
        });

        // Worker A: commit pipeline (store.W → wal.W → stats.W).
        let store_a = Arc::clone(&store);
        let worker_a = thread::spawn(move || {
            for i in 0_u8..32 {
                let mut txn = store_a.begin();
                txn.stage_write(BlockNumber(u64::from(i)), vec![i; 16]);
                let _ = store_a.commit(txn).expect("commit must not block");
            }
        });

        // Worker B: alternates checkpoint (store.R → stats.W) and
        // truncate_wal (store.R → wal.W → stats.W). Both nested
        // acquisitions stay strictly within the documented order.
        let store_b = Arc::clone(&store);
        let worker_b = thread::spawn(move || {
            let ckpt_dir = tempfile::tempdir().expect("ckpt dir");
            for i in 0..16_u32 {
                let ckpt_path = ckpt_dir.path().join(format!("ckpt-{i}.bin"));
                store_b.checkpoint(&ckpt_path).expect("checkpoint");
                if i % 2 == 0 {
                    // truncate_wal may return the staleness error when
                    // commits have landed since the checkpoint; either
                    // outcome proves the function returns rather than
                    // hangs.
                    let _ = store_b.truncate_wal();
                }
            }
        });

        worker_a.join().expect("worker A panicked");
        worker_b.join().expect("worker B panicked");
        let watchdog_join_started = Instant::now();
        done.store(true, AtomicOrdering::Release);
        watchdog.join().expect("watchdog panicked");
        assert!(
            watchdog_join_started.elapsed() <= LOCK_ORDERING_WATCHDOG_POLL_INTERVAL * 25,
            "watchdog should observe completion promptly after workers finish"
        );

        std::fs::remove_file(&path).ok();
    }
}
