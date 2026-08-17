//! Append-only WAL writer with integrity checks, sync policy, and backpressure.
//!
//! This module provides [`WalWriter`], the write-path counterpart to the WAL
//! replay engine in [`crate::persist`].  It encodes commit records, appends
//! them atomically, optionally verifies the written data by reading back, and
//! manages durability boundaries according to a configurable [`SyncPolicy`].
//!
//! # Error Classification
//!
//! All write failures are returned as [`WalWriteError`], which distinguishes:
//!
//! - **Retryable** failures: I/O errors, backpressure — the caller may retry
//!   after addressing the underlying condition.
//! - **Fatal** failures: format violations, verification failures — these
//!   indicate a bug or unrecoverable state.
//!
//! # Invariants Enforced
//!
//! - **D1:** Commit sequence is strictly increasing (monotonicity).
//! - **D8:** Reserved sentinel values (`u64::MAX`) are rejected.
//! - Per-record CRC32C integrity (via [`crate::wal::encode_commit`]).

use crate::wal::{self, HEADER_SIZE, WalCommit, WalHeader};
use ffs_error::{FfsError, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;
use tracing::{debug, error, info, warn};

type CoalescedRecordOffsets = Vec<(usize, usize)>;
type EncodedCoalescedBatch = (Vec<u8>, CoalescedRecordOffsets);

// ── Error types ──────────────────────────────────────────────────────────────

/// Classified error for WAL write operations.
///
/// Each variant carries enough context to decide whether to retry, abort, or
/// escalate.  Use [`is_retryable`](WalWriteError::is_retryable) and
/// [`is_fatal`](WalWriteError::is_fatal) for programmatic triage.
#[derive(Debug)]
pub enum WalWriteError {
    /// I/O error during append — may be retryable (e.g. `ENOSPC`, `EINTR`).
    AppendIo {
        source: std::io::Error,
        bytes_attempted: usize,
    },
    /// I/O error during sync — data was appended but durability is not guaranteed.
    SyncIo { source: std::io::Error },
    /// Encoding or invariant violation — fatal, likely indicates a bug.
    FormatViolation { detail: String },
    /// Read-back verification failed: written data does not match expected CRC.
    VerificationFailed {
        expected_crc: u32,
        actual_crc: u32,
        offset: u64,
    },
    /// WAL size exceeds the configured backpressure threshold.
    Backpressure { wal_size: u64, threshold: u64 },
}

impl WalWriteError {
    /// Whether this error class is potentially retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::AppendIo { .. } | Self::Backpressure { .. })
    }

    /// Whether this error class is fatal (indicates a bug or unrecoverable state).
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::FormatViolation { .. } | Self::VerificationFailed { .. }
        )
    }
}

impl std::fmt::Display for WalWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AppendIo {
                source,
                bytes_attempted,
            } => {
                write!(
                    f,
                    "WAL append I/O error ({bytes_attempted} bytes attempted): {source}"
                )
            }
            Self::SyncIo { source } => write!(f, "WAL sync I/O error: {source}"),
            Self::FormatViolation { detail } => write!(f, "WAL format violation: {detail}"),
            Self::VerificationFailed {
                expected_crc,
                actual_crc,
                offset,
            } => {
                write!(
                    f,
                    "WAL write verification failed at offset {offset}: \
                     expected CRC {expected_crc:#010x}, got {actual_crc:#010x}"
                )
            }
            Self::Backpressure {
                wal_size,
                threshold,
            } => {
                write!(
                    f,
                    "WAL backpressure: size {wal_size} exceeds threshold {threshold}"
                )
            }
        }
    }
}

impl std::error::Error for WalWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AppendIo { source, .. } | Self::SyncIo { source } => Some(source),
            _ => None,
        }
    }
}

impl From<WalWriteError> for FfsError {
    fn from(e: WalWriteError) -> Self {
        match e {
            WalWriteError::AppendIo { source, .. } | WalWriteError::SyncIo { source } => {
                Self::Io(source)
            }
            WalWriteError::FormatViolation { detail } => Self::Format(detail),
            WalWriteError::VerificationFailed {
                expected_crc,
                actual_crc,
                offset,
            } => Self::Corruption {
                block: 0,
                detail: format!(
                    "WAL write verification failed at offset {offset}: \
                     expected CRC {expected_crc:#010x}, got {actual_crc:#010x}"
                ),
            },
            WalWriteError::Backpressure {
                wal_size,
                threshold,
            } => Self::Format(format!(
                "WAL backpressure: size {wal_size} exceeds threshold {threshold}"
            )),
        }
    }
}

// ── Sync policy ──────────────────────────────────────────────────────────────

/// Policy governing when `fsync` is called after appending records.
///
/// | Policy | Durability window | Throughput |
/// |--------|-------------------|------------|
/// | `Immediate` | Zero (every record synced) | Lowest |
/// | `EveryN(n)` | Up to `n-1` records | Medium |
/// | `Manual` | Unbounded until caller flushes | Highest |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncPolicy {
    /// Sync after every append (maximum durability, minimum throughput).
    #[default]
    Immediate,
    /// Sync after every `n` appends (trades durability window for throughput).
    EveryN(u32),
    /// Never auto-sync; caller manages durability via explicit [`WalWriter::flush`].
    Manual,
}

// ── Writer configuration ─────────────────────────────────────────────────────

/// Configuration for the WAL writer.
#[derive(Debug, Clone)]
pub struct WalWriterConfig {
    /// Sync policy (default: `Immediate`).
    pub sync_policy: SyncPolicy,
    /// Verify writes by reading back and checking CRC (default: `false`).
    ///
    /// Enabling this adds one seek + read per append. Useful for paranoid
    /// durability or debugging, not recommended for hot paths.
    pub verify_writes: bool,
    /// WAL size threshold in bytes for backpressure signaling (0 = disabled).
    ///
    /// When the WAL reaches this size, [`WalWriter::append_commit`] returns
    /// [`WalWriteError::Backpressure`] instead of writing. The caller should
    /// checkpoint and compact before retrying.
    pub backpressure_threshold_bytes: u64,
}

impl Default for WalWriterConfig {
    fn default() -> Self {
        Self {
            sync_policy: SyncPolicy::Immediate,
            verify_writes: false,
            backpressure_threshold_bytes: 0,
        }
    }
}

// ── Append result ────────────────────────────────────────────────────────────

/// Result of a successful append operation.
#[derive(Debug, Clone, Copy)]
pub struct AppendResult {
    /// Byte offset where the record was written.
    pub offset: u64,
    /// Number of bytes written.
    pub bytes_written: u64,
    /// Whether the write was synced to disk.
    pub synced: bool,
    /// Number of pending (unsynced) appends after this write.
    pub pending_sync_count: u32,
}

// ── WalWriter ────────────────────────────────────────────────────────────────

/// Append-only WAL writer with integrity checks, sync policy, and backpressure.
///
/// Encodes [`WalCommit`] records, appends them at the current write position,
/// optionally verifies the written data, and manages durability boundaries.
///
/// # Thread safety
///
/// `WalWriter` is **not** `Sync`.  In [`crate::persist::PersistentMvccStore`],
/// it is wrapped in `RwLock<WalWriter>` so that only one writer can append at
/// a time while readers can query metadata concurrently.
#[derive(Debug)]
pub struct WalWriter {
    file: File,
    pub(crate) write_pos: u64,
    config: WalWriterConfig,
    /// Number of appends since the last sync.
    appends_since_sync: u32,
    /// Highest `commit_seq` successfully appended.
    last_commit_seq: u64,
    /// Monotonically increasing operation counter for structured logging.
    next_operation_id: u64,
    /// Injected sync failure for testing.
    #[cfg(test)]
    pub(crate) fail_sync: bool,
    /// Injected append failure for testing.
    #[cfg(test)]
    pub(crate) fail_append: bool,
}

impl WalWriter {
    /// Create a writer wrapping an already-open file at the given position.
    ///
    /// The file must already contain a valid WAL header at offset 0.
    #[must_use]
    pub fn new(file: File, write_pos: u64, config: WalWriterConfig) -> Self {
        Self {
            file,
            write_pos,
            config,
            appends_since_sync: 0,
            last_commit_seq: 0,
            next_operation_id: 1,
            #[cfg(test)]
            fail_sync: false,
            #[cfg(test)]
            fail_append: false,
        }
    }

    /// Create a fresh WAL file with header and return a writer positioned after it.
    pub fn create(path: &Path, config: WalWriterConfig) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        let header = WalHeader::default();
        let header_bytes = wal::encode_header(&header);
        file.write_all(&header_bytes)?;
        file.sync_all()?;

        let write_pos = u64::try_from(HEADER_SIZE)
            .map_err(|_| FfsError::Format("header size overflow".to_owned()))?;

        Ok(Self::new(file, write_pos, config))
    }

    /// Append a commit record to the WAL.
    ///
    /// The record is encoded with CRC32C integrity, appended at the current
    /// write position, and optionally synced according to the configured
    /// [`SyncPolicy`].
    ///
    /// # Reasoning mode: append-only + strict-monotonic + atomic-rollback (bd-chmw4)
    ///
    /// This function implements an **append-only WAL with a strict-
    /// monotonic sequence check and atomic-rollback on any failure
    /// between encoded write and synced state**. The three modes
    /// compose as follows:
    ///
    /// * **Append-only**: writes always go to `self.write_pos`; the
    ///   file is never overwritten in place. The only function that
    ///   reduces `write_pos` is rollback (here and in
    ///   `rollback_failed_append`) or the explicit
    ///   `truncate_wal` after a successful checkpoint.
    /// * **Strict monotonic**: D1 below — `commit_seq` MUST be
    ///   strictly greater than `last_commit_seq`. Equality is a
    ///   FormatViolation. Replay relies on this to detect WAL
    ///   tampering.
    /// * **Atomic-rollback**: any failure path between the
    ///   `raw_append` call (l. 391) and the `last_commit_seq =
    ///   commit_seq` assignment (l. 425) MUST revert the partial
    ///   append, otherwise a reader at the WAL tail would see a
    ///   commit record whose in-memory state is unreachable. There
    ///   are two rollback paths:
    ///     1. **Verify failure** (`if self.config.verify_writes { ... }`):
    ///        resets `self.write_pos` and truncates the file. Does
    ///        NOT reset `appends_since_sync` because that counter is
    ///        incremented AFTER verify; if you move verify past the
    ///        increment, you MUST reset the counter here too.
    ///     2. **Sync failure** (after
    ///        `increment_pending_sync_count`): delegates to
    ///        `rollback_failed_append`, which reverts
    ///        `write_pos`, truncates the file, AND restores
    ///        `appends_since_sync` to its pre-increment value.
    ///
    /// Any new failure path inserted between `raw_append` and the
    /// final assignment MUST call `rollback_failed_append` (or the
    /// equivalent inline reset for pre-counter paths) before
    /// returning Err.
    ///
    /// # Monotonicity (D1)
    ///
    /// The commit's `commit_seq` must be strictly greater than any previously
    /// appended commit (unless this is the first append).  Violations return
    /// [`WalWriteError::FormatViolation`].
    ///
    /// # Sentinel rejection (D8)
    ///
    /// `commit_seq == u64::MAX` or `txn_id == u64::MAX` are rejected.
    ///
    /// # Errors
    ///
    /// Returns a classified [`WalWriteError`] distinguishing retryable I/O
    /// failures from fatal format/invariant violations.
    #[expect(clippy::too_many_lines)]
    pub fn append_commit(
        &mut self,
        commit: &WalCommit,
    ) -> std::result::Result<AppendResult, WalWriteError> {
        let op_id = self.next_op_id();
        let commit_seq = commit.commit_seq.0;
        let txn_id = commit.txn_id.0;
        let num_writes = commit.writes.len();

        debug!(
            operation_id = op_id,
            commit_seq, txn_id, num_writes, "wal_append_start"
        );

        // ── D8: reject reserved sentinels ────────────────────────────────
        if commit_seq == u64::MAX || txn_id == u64::MAX {
            error!(
                operation_id = op_id,
                commit_seq,
                txn_id,
                error_class = "format_violation",
                "wal_append_rejected_sentinel"
            );
            return Err(WalWriteError::FormatViolation {
                detail: "reserved sentinel value (u64::MAX) in commit_seq or txn_id".to_owned(),
            });
        }

        // ── D1: enforce strict monotonicity ──────────────────────────────
        if commit_seq <= self.last_commit_seq {
            error!(
                operation_id = op_id,
                commit_seq,
                last_commit_seq = self.last_commit_seq,
                error_class = "format_violation",
                "wal_append_rejected_monotonicity"
            );
            return Err(WalWriteError::FormatViolation {
                detail: format!(
                    "commit_seq {commit_seq} is not strictly greater than last appended {}",
                    self.last_commit_seq,
                ),
            });
        }

        // ── Backpressure check ───────────────────────────────────────────
        if self.config.backpressure_threshold_bytes > 0
            && self.write_pos >= self.config.backpressure_threshold_bytes
        {
            warn!(
                operation_id = op_id,
                wal_size = self.write_pos,
                threshold = self.config.backpressure_threshold_bytes,
                "wal_backpressure"
            );
            return Err(WalWriteError::Backpressure {
                wal_size: self.write_pos,
                threshold: self.config.backpressure_threshold_bytes,
            });
        }

        // ── Encode ───────────────────────────────────────────────────────
        let encoded = wal::encode_commit(commit).map_err(|e| WalWriteError::FormatViolation {
            detail: format!("failed to encode commit: {e}"),
        })?;
        let bytes_len = encoded.len();
        let bytes_written =
            u64::try_from(bytes_len).map_err(|_| WalWriteError::FormatViolation {
                detail: "commit length exceeds u64 capacity".into(),
            })?;
        let write_offset = self.write_pos;

        // ── Append ───────────────────────────────────────────────────────
        #[cfg(test)]
        if self.fail_append {
            return Err(WalWriteError::AppendIo {
                source: std::io::Error::other("injected append failure"),
                bytes_attempted: bytes_len,
            });
        }

        self.raw_append(&encoded).map_err(|e| {
            error!(
                operation_id = op_id,
                commit_seq,
                bytes_attempted = bytes_len,
                error_class = "append_io",
                error = %e,
                "wal_append_err"
            );
            WalWriteError::AppendIo {
                source: e,
                bytes_attempted: bytes_len,
            }
        })?;

        // ── Optional write verification ──────────────────────────────────
        if self.config.verify_writes
            && let Err(e) = self.verify_written_record(write_offset, &encoded, op_id)
        {
            // Revert the write position and truncate the file to avoid leaving a "successful" record in the WAL
            // that the caller will roll back in memory.
            self.write_pos = write_offset;
            let _ = self.file.set_len(write_offset);
            return Err(e);
        }

        // ── Sync policy ──────────────────────────────────────────────────
        let pending_before = self.appends_since_sync;
        self.increment_pending_sync_count(1);
        let synced = match self.maybe_sync(op_id, commit_seq) {
            Ok(s) => s,
            Err(e) => return Err(self.rollback_failed_append(write_offset, pending_before, e)),
        };

        self.last_commit_seq = commit_seq;

        info!(
            operation_id = op_id,
            commit_seq,
            txn_id,
            bytes_written,
            offset = write_offset,
            synced,
            "wal_append_ok"
        );

        Ok(AppendResult {
            offset: write_offset,
            bytes_written,
            synced,
            pending_sync_count: if synced { 0 } else { self.appends_since_sync },
        })
    }

    /// Force-sync all pending writes to disk.
    ///
    /// Returns the number of appends that were pending sync (0 if nothing was
    /// pending).
    pub fn flush(&mut self) -> std::result::Result<u32, WalWriteError> {
        let pending = self.appends_since_sync;
        if pending == 0 {
            return Ok(0);
        }
        let op_id = self.next_op_id();
        self.do_sync(op_id)?;
        info!(operation_id = op_id, flushed = pending, "wal_flush_ok");
        Ok(pending)
    }

    /// Current WAL file size (byte offset of the next write).
    #[must_use]
    pub fn size(&self) -> u64 {
        self.write_pos
    }

    /// Whether the WAL is currently above the backpressure threshold.
    #[must_use]
    pub fn is_backpressured(&self) -> bool {
        self.config.backpressure_threshold_bytes > 0
            && self.write_pos >= self.config.backpressure_threshold_bytes
    }

    /// Highest `commit_seq` successfully appended.
    #[must_use]
    pub fn last_commit_seq(&self) -> u64 {
        self.last_commit_seq
    }

    /// Number of appends pending sync.
    #[must_use]
    pub fn pending_sync_count(&self) -> u32 {
        self.appends_since_sync
    }

    /// Borrow the underlying file (for replay, truncation, etc.).
    #[must_use]
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Mutably borrow the underlying file.
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Set `last_commit_seq` (used after replay to synchronise writer state).
    pub fn set_last_commit_seq(&mut self, seq: u64) {
        self.last_commit_seq = seq;
    }

    /// Append multiple commit records as a single coalesced write + sync.
    ///
    /// Encodes all commits, writes them as a single contiguous I/O, and
    /// syncs once. This amortizes the per-commit overhead of separate
    /// `write_all` and `fsync` calls.
    ///
    /// All invariants (D1 monotonicity, D8 sentinel rejection, backpressure)
    /// are checked per-commit before any bytes are written. If any commit
    /// fails validation, no commits are written.
    ///
    /// Returns one `AppendResult` per commit, all sharing the same `synced`
    /// status.
    pub fn append_commits_coalesced(
        &mut self,
        commits: &[WalCommit],
    ) -> std::result::Result<Vec<AppendResult>, WalWriteError> {
        if commits.is_empty() {
            return Ok(Vec::new());
        }

        // For a single commit, delegate to the standard path.
        if commits.len() == 1 {
            return self.append_commit(&commits[0]).map(|r| vec![r]);
        }

        let op_id = self.next_op_id();

        let prev_seq = self.validate_coalesced_commits(commits)?;

        // ── Backpressure check ────────────────────────────────────────────
        if self.config.backpressure_threshold_bytes > 0
            && self.write_pos >= self.config.backpressure_threshold_bytes
        {
            return Err(WalWriteError::Backpressure {
                wal_size: self.write_pos,
                threshold: self.config.backpressure_threshold_bytes,
            });
        }

        let (coalesced_buf, record_offsets) = Self::encode_coalesced_commits(commits)?;

        let total_bytes = coalesced_buf.len();
        let base_offset = self.write_pos;

        debug!(
            operation_id = op_id,
            num_commits = commits.len(),
            total_bytes,
            "wal_coalesced_append_start"
        );

        // ── Single coalesced write ────────────────────────────────────────
        #[cfg(test)]
        if self.fail_append {
            return Err(WalWriteError::AppendIo {
                source: std::io::Error::other("injected append failure"),
                bytes_attempted: total_bytes,
            });
        }

        self.raw_append(&coalesced_buf).map_err(|e| {
            error!(
                operation_id = op_id,
                bytes_attempted = total_bytes,
                error_class = "append_io",
                error = %e,
                "wal_coalesced_append_err"
            );
            WalWriteError::AppendIo {
                source: e,
                bytes_attempted: total_bytes,
            }
        })?;

        self.verify_or_rollback_coalesced_write(base_offset, &coalesced_buf, op_id)?;

        // ── Single sync ───────────────────────────────────────────────────
        let pending_before = self.appends_since_sync;
        self.increment_pending_sync_count(u32::try_from(commits.len()).unwrap_or(u32::MAX));
        let synced = match self.maybe_sync(op_id, prev_seq) {
            Ok(s) => s,
            Err(e) => return Err(self.rollback_failed_append(base_offset, pending_before, e)),
        };

        self.last_commit_seq = prev_seq;

        // ── Build per-commit results ──────────────────────────────────────
        let results = record_offsets
            .iter()
            .map(|&(rel_offset, bytes_len)| AppendResult {
                offset: base_offset + rel_offset as u64,
                bytes_written: bytes_len as u64,
                synced,
                pending_sync_count: if synced { 0 } else { self.appends_since_sync },
            })
            .collect();

        info!(
            operation_id = op_id,
            num_commits = commits.len(),
            total_bytes,
            synced,
            "wal_coalesced_append_ok"
        );

        Ok(results)
    }

    /// Borrow the writer configuration.
    #[must_use]
    pub fn config(&self) -> &WalWriterConfig {
        &self.config
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    fn next_op_id(&mut self) -> u64 {
        let id = self.next_operation_id;
        self.next_operation_id = self.next_operation_id.saturating_add(1);
        id
    }

    fn increment_pending_sync_count(&mut self, delta: u32) {
        self.appends_since_sync = self.appends_since_sync.saturating_add(delta);
    }

    /// Reverse a partial WAL append when the post-append sync (or
    /// any other post-counter step) fails. **This is the rollback
    /// partner of the append-only/atomic-rollback contract documented
    /// on [`Self::append_commit`].** (bd-chmw4)
    ///
    /// The rollback covers THREE state pieces. Forgetting any of
    /// them leaves the WAL in a state where a tail reader sees a
    /// commit record whose corresponding in-memory state is
    /// unreachable:
    ///
    /// 1. **`write_pos`** — reset to the pre-append offset so the
    ///    next append re-uses the slot.
    /// 2. **File length** — `set_len(write_offset)` truncates the
    ///    on-disk record. The `let _ =` is intentional best-effort:
    ///    if the truncate itself fails (e.g., disk full, EROFS),
    ///    the WAL is in an undefined state but no reader can
    ///    legitimately observe partial commits because
    ///    `last_commit_seq` was NOT yet bumped — replay sees the
    ///    record as orphan and stops at the first decode error.
    /// 3. **`appends_since_sync`** — restored to its pre-increment
    ///    value so the next append's sync-policy decision is based
    ///    on the correct count. This is the piece the verify-failure
    ///    inline rollback in `append_commit` SKIPS, because verify
    ///    runs BEFORE `increment_pending_sync_count`. Any reordering
    ///    that puts the increment before verify MUST also start
    ///    resetting this counter on verify failure.
    ///
    /// Note: `last_commit_seq` is NOT yet updated when this function
    /// is reachable, so the strict-monotonic invariant is preserved
    /// without explicit rollback of that field.
    fn rollback_failed_append(
        &mut self,
        write_offset: u64,
        pending_before: u32,
        error: WalWriteError,
    ) -> WalWriteError {
        self.write_pos = write_offset;
        let _ = self.file.set_len(write_offset);
        self.appends_since_sync = pending_before;
        error
    }

    fn validate_coalesced_commits(
        &self,
        commits: &[WalCommit],
    ) -> std::result::Result<u64, WalWriteError> {
        let mut prev_seq = self.last_commit_seq;
        for commit in commits {
            let seq = commit.commit_seq.0;
            let txn = commit.txn_id.0;

            if seq == u64::MAX || txn == u64::MAX {
                return Err(WalWriteError::FormatViolation {
                    detail: "reserved sentinel value (u64::MAX) in coalesced batch".to_owned(),
                });
            }
            if seq <= prev_seq {
                return Err(WalWriteError::FormatViolation {
                    detail: format!(
                        "coalesced commit_seq {seq} not strictly greater than {prev_seq}"
                    ),
                });
            }
            prev_seq = seq;
        }
        Ok(prev_seq)
    }

    fn encode_coalesced_commits(
        commits: &[WalCommit],
    ) -> std::result::Result<EncodedCoalescedBatch, WalWriteError> {
        let mut coalesced_buf = Vec::new();
        let mut record_offsets = CoalescedRecordOffsets::with_capacity(commits.len());

        for commit in commits {
            let offset_in_buf = coalesced_buf.len();
            let encoded =
                wal::encode_commit(commit).map_err(|e| WalWriteError::FormatViolation {
                    detail: format!("failed to encode commit in coalesced batch: {e}"),
                })?;
            record_offsets.push((offset_in_buf, encoded.len()));
            coalesced_buf.extend_from_slice(&encoded);
        }

        Ok((coalesced_buf, record_offsets))
    }

    fn verify_or_rollback_coalesced_write(
        &mut self,
        base_offset: u64,
        coalesced_buf: &[u8],
        op_id: u64,
    ) -> std::result::Result<(), WalWriteError> {
        if let Err(error) = self.maybe_verify_coalesced_write(base_offset, coalesced_buf, op_id) {
            self.write_pos = base_offset;
            let _ = self.file.set_len(base_offset);
            return Err(error);
        }
        Ok(())
    }

    fn maybe_verify_coalesced_write(
        &mut self,
        base_offset: u64,
        coalesced_buf: &[u8],
        op_id: u64,
    ) -> std::result::Result<(), WalWriteError> {
        if self.config.verify_writes {
            self.verify_written_record(base_offset, coalesced_buf, op_id)?;
        }
        Ok(())
    }

    fn raw_append(&mut self, data: &[u8]) -> std::io::Result<()> {
        if let Err(e) = self.file.write_all_at(data, self.write_pos) {
            // Truncate to write_pos to remove any partially written bytes.
            let _ = self.file.set_len(self.write_pos);
            return Err(e);
        }
        let Ok(len_u64) = u64::try_from(data.len()) else {
            let _ = self.file.set_len(self.write_pos);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "data length exceeds u64",
            ));
        };
        self.write_pos = self.write_pos.checked_add(len_u64).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "write position overflowed",
            )
        })?;
        Ok(())
    }

    fn verify_written_record(
        &mut self,
        offset: u64,
        expected: &[u8],
        op_id: u64,
    ) -> std::result::Result<(), WalWriteError> {
        let mut readback = vec![0_u8; expected.len()];
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| WalWriteError::AppendIo {
                source: e,
                bytes_attempted: expected.len(),
            })?;
        self.file
            .read_exact(&mut readback)
            .map_err(|e| WalWriteError::AppendIo {
                source: e,
                bytes_attempted: expected.len(),
            })?;

        let expected_crc = crc32c::crc32c(expected);
        let actual_crc = crc32c::crc32c(&readback);

        if expected_crc != actual_crc {
            error!(
                operation_id = op_id,
                offset,
                expected_crc,
                actual_crc,
                error_class = "verification_failed",
                "wal_verify_err"
            );
            return Err(WalWriteError::VerificationFailed {
                expected_crc,
                actual_crc,
                offset,
            });
        }

        debug!(
            operation_id = op_id,
            offset,
            crc = expected_crc,
            "wal_verify_ok"
        );

        Ok(())
    }

    fn maybe_sync(
        &mut self,
        op_id: u64,
        commit_seq: u64,
    ) -> std::result::Result<bool, WalWriteError> {
        let should_sync = match self.config.sync_policy {
            SyncPolicy::Immediate => true,
            SyncPolicy::EveryN(n) => self.appends_since_sync >= n,
            SyncPolicy::Manual => false,
        };

        if should_sync {
            self.do_sync(op_id)?;
            info!(operation_id = op_id, commit_seq, "wal_sync_ok");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn do_sync(&mut self, op_id: u64) -> std::result::Result<(), WalWriteError> {
        #[cfg(test)]
        if self.fail_sync {
            return Err(WalWriteError::SyncIo {
                source: std::io::Error::other("injected sync failure"),
            });
        }

        self.file.sync_all().map_err(|e| {
            error!(
                operation_id = op_id,
                error_class = "sync_io",
                error = %e,
                "wal_sync_err"
            );
            WalWriteError::SyncIo { source: e }
        })?;

        self.appends_since_sync = 0;
        Ok(())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::{
        DecodeResult, WalWrite, {commit_byte_size, decode_commit, decode_header},
    };
    use ffs_types::{BlockNumber, CommitSeq, TxnId};
    use tempfile::NamedTempFile;

    fn make_commit(seq: u64, txn: u64, blocks: &[(u64, &[u8])]) -> WalCommit {
        WalCommit {
            commit_seq: CommitSeq(seq),
            txn_id: TxnId(txn),
            writes: blocks
                .iter()
                .map(|(b, d)| WalWrite {
                    block: BlockNumber(*b),
                    data: d.to_vec(),
                })
                .collect(),
        }
    }

    fn tmp_path() -> std::path::PathBuf {
        let t = NamedTempFile::new().expect("temp file");
        let p = t.path().to_path_buf();
        std::fs::remove_file(&p).ok();
        let _ = t.into_temp_path().keep().expect("keep temp file"); // prevent auto-delete
        p
    }

    // ── Basic append + decode ────────────────────────────────────────────

    #[test]
    fn append_single_commit_decodable() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        let commit = make_commit(1, 1, &[(10, &[0xAA; 32])]);
        let result = w.append_commit(&commit).expect("append");
        assert!(result.synced);
        assert!(result.bytes_written > 0);
        assert_eq!(result.offset, HEADER_SIZE as u64);

        // Read back and decode
        let data = std::fs::read(&path).expect("read");
        decode_header(&data[..HEADER_SIZE]).expect("header");
        match decode_commit(&data[HEADER_SIZE..]) {
            DecodeResult::Commit(c) => {
                assert_eq!(c.commit_seq, CommitSeq(1));
                assert_eq!(c.txn_id, TxnId(1));
                assert_eq!(c.writes.len(), 1);
                assert_eq!(c.writes[0].block, BlockNumber(10));
                assert_eq!(c.writes[0].data, vec![0xAA; 32]);
            }
            other => assert!(
                matches!(other, DecodeResult::Commit(_)),
                "expected Commit, got {other:?}"
            ),
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_multiple_commits_sequential_decode() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        for i in 1_u64..=5 {
            let byte = u8::try_from(i).expect("test value fits in u8");
            let commit = make_commit(i, i, &[(i, &[byte; 16])]);
            w.append_commit(&commit).expect("append");
        }

        let data = std::fs::read(&path).expect("read");
        let mut offset = HEADER_SIZE;
        for i in 1_u64..=5 {
            match decode_commit(&data[offset..]) {
                DecodeResult::Commit(c) => {
                    assert_eq!(c.commit_seq, CommitSeq(i));
                    let size = commit_byte_size(&data[offset..]).expect("size");
                    offset += size;
                }
                other => assert!(
                    matches!(other, DecodeResult::Commit(_)),
                    "expected Commit at seq {i}, got {other:?}"
                ),
            }
        }

        let _ = std::fs::remove_file(&path);
    }

    // ── Monotonicity enforcement (D1) ────────────────────────────────────

    #[test]
    fn rejects_non_monotonic_commit_seq() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        w.append_commit(&make_commit(5, 1, &[]))
            .expect("first append");

        // Same seq → rejected
        let err = w
            .append_commit(&make_commit(5, 2, &[]))
            .expect_err("duplicate seq");
        assert!(err.is_fatal());
        assert!(matches!(err, WalWriteError::FormatViolation { .. }));

        // Lower seq → rejected
        let err = w
            .append_commit(&make_commit(3, 3, &[]))
            .expect_err("lower seq");
        assert!(err.is_fatal());

        // Higher seq → accepted
        w.append_commit(&make_commit(6, 4, &[]))
            .expect("higher seq ok");

        let _ = std::fs::remove_file(&path);
    }

    // ── Sentinel rejection (D8) ──────────────────────────────────────────

    #[test]
    fn rejects_sentinel_commit_seq() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        let err = w
            .append_commit(&make_commit(u64::MAX, 1, &[]))
            .expect_err("sentinel commit_seq");
        assert!(err.is_fatal());
        assert!(matches!(err, WalWriteError::FormatViolation { .. }));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_sentinel_txn_id() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        let err = w
            .append_commit(&make_commit(1, u64::MAX, &[]))
            .expect_err("sentinel txn_id");
        assert!(err.is_fatal());

        let _ = std::fs::remove_file(&path);
    }

    // ── Backpressure ─────────────────────────────────────────────────────

    #[test]
    fn backpressure_threshold_triggers() {
        let path = tmp_path();
        let config = WalWriterConfig {
            backpressure_threshold_bytes: HEADER_SIZE as u64 + 50,
            ..WalWriterConfig::default()
        };
        let mut w = WalWriter::create(&path, config).expect("create");

        // First small commit should succeed
        w.append_commit(&make_commit(1, 1, &[(1, &[1; 8])]))
            .expect("under threshold");

        // Large commit that pushes us over
        w.append_commit(&make_commit(2, 2, &[(2, &[2; 64])]))
            .expect("at threshold append succeeds because checked before write");

        // Now WAL is above threshold → next append is rejected
        let err = w
            .append_commit(&make_commit(3, 3, &[(3, &[3; 8])]))
            .expect_err("backpressure");
        assert!(err.is_retryable());
        assert!(matches!(err, WalWriteError::Backpressure { .. }));
        assert!(w.is_backpressured());

        let _ = std::fs::remove_file(&path);
    }

    // ── Sync policy ──────────────────────────────────────────────────────

    #[test]
    fn sync_policy_immediate_syncs_every_write() {
        let path = tmp_path();
        let config = WalWriterConfig {
            sync_policy: SyncPolicy::Immediate,
            ..WalWriterConfig::default()
        };
        let mut w = WalWriter::create(&path, config).expect("create");

        for i in 1_u64..=3 {
            let r = w.append_commit(&make_commit(i, i, &[])).expect("append");
            assert!(r.synced, "commit {i} should be synced");
            assert_eq!(r.pending_sync_count, 0);
        }
        assert_eq!(w.pending_sync_count(), 0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sync_policy_every_n_batches_syncs() {
        let path = tmp_path();
        let config = WalWriterConfig {
            sync_policy: SyncPolicy::EveryN(3),
            ..WalWriterConfig::default()
        };
        let mut w = WalWriter::create(&path, config).expect("create");

        let r1 = w.append_commit(&make_commit(1, 1, &[])).expect("append 1");
        assert!(!r1.synced);
        assert_eq!(r1.pending_sync_count, 1);

        let r2 = w.append_commit(&make_commit(2, 2, &[])).expect("append 2");
        assert!(!r2.synced);
        assert_eq!(r2.pending_sync_count, 2);

        let r3 = w.append_commit(&make_commit(3, 3, &[])).expect("append 3");
        assert!(r3.synced, "third append should trigger sync");
        assert_eq!(r3.pending_sync_count, 0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sync_policy_manual_never_auto_syncs() {
        let path = tmp_path();
        let config = WalWriterConfig {
            sync_policy: SyncPolicy::Manual,
            ..WalWriterConfig::default()
        };
        let mut w = WalWriter::create(&path, config).expect("create");

        for i in 1_u64..=5 {
            let r = w.append_commit(&make_commit(i, i, &[])).expect("append");
            assert!(!r.synced);
        }
        assert_eq!(w.pending_sync_count(), 5);

        let flushed = w.flush().expect("flush");
        assert_eq!(flushed, 5);
        assert_eq!(w.pending_sync_count(), 0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pending_sync_count_saturates_at_numeric_limit() {
        let path = tmp_path();
        let config = WalWriterConfig {
            sync_policy: SyncPolicy::Manual,
            ..WalWriterConfig::default()
        };
        let mut w = WalWriter::create(&path, config).expect("create");
        w.appends_since_sync = u32::MAX;

        let result = w
            .append_commit(&make_commit(1, 1, &[]))
            .expect("append at saturated pending count");

        assert!(!result.synced);
        assert_eq!(result.pending_sync_count, u32::MAX);
        assert_eq!(w.pending_sync_count(), u32::MAX);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn operation_id_saturates_at_numeric_limit() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");
        w.next_operation_id = u64::MAX;

        assert_eq!(w.next_op_id(), u64::MAX);
        assert_eq!(w.next_operation_id, u64::MAX);
        assert_eq!(w.next_op_id(), u64::MAX);

        let _ = std::fs::remove_file(&path);
    }

    // ── Write verification ───────────────────────────────────────────────

    #[test]
    fn verify_writes_reads_back_successfully() {
        let path = tmp_path();
        let config = WalWriterConfig {
            verify_writes: true,
            ..WalWriterConfig::default()
        };
        let mut w = WalWriter::create(&path, config).expect("create");

        let commit = make_commit(1, 1, &[(10, &[0xBB; 128])]);
        w.append_commit(&commit)
            .expect("verified append should succeed");

        let _ = std::fs::remove_file(&path);
    }

    // ── Fault injection ──────────────────────────────────────────────────

    #[test]
    fn append_failure_returns_retryable_error() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        w.fail_append = true;
        let err = w
            .append_commit(&make_commit(1, 1, &[(1, &[1])]))
            .expect_err("injected failure");
        assert!(err.is_retryable());
        assert!(matches!(err, WalWriteError::AppendIo { .. }));

        // Writer state should be unchanged (no partial side effects)
        assert_eq!(w.last_commit_seq(), 0);
        assert_eq!(w.size(), HEADER_SIZE as u64);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sync_failure_returns_classified_error() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        w.fail_sync = true;
        let err = w
            .append_commit(&make_commit(1, 1, &[(1, &[1])]))
            .expect_err("injected sync failure");
        assert!(!err.is_retryable());
        assert!(!err.is_fatal());
        assert!(matches!(err, WalWriteError::SyncIo { .. }));
        assert_eq!(
            w.pending_sync_count(),
            0,
            "failed sync must not leave phantom pending appends"
        );
        assert_eq!(
            w.size(),
            HEADER_SIZE as u64,
            "failed sync must roll back WAL size"
        );
        assert_eq!(
            w.last_commit_seq(),
            0,
            "failed sync must not advance commit sequence"
        );

        let _ = std::fs::remove_file(&path);
    }

    // ── Error classification ─────────────────────────────────────────────

    #[test]
    fn error_classification_retryable() {
        let e = WalWriteError::AppendIo {
            source: std::io::Error::other("disk full"),
            bytes_attempted: 100,
        };
        assert!(e.is_retryable());
        assert!(!e.is_fatal());

        let e = WalWriteError::Backpressure {
            wal_size: 1000,
            threshold: 500,
        };
        assert!(e.is_retryable());
        assert!(!e.is_fatal());
    }

    #[test]
    fn error_classification_fatal() {
        let e = WalWriteError::FormatViolation {
            detail: "bad".to_owned(),
        };
        assert!(e.is_fatal());
        assert!(!e.is_retryable());

        let e = WalWriteError::VerificationFailed {
            expected_crc: 1,
            actual_crc: 2,
            offset: 0,
        };
        assert!(e.is_fatal());
        assert!(!e.is_retryable());
    }

    #[test]
    fn error_classification_sync_io_neither() {
        let e = WalWriteError::SyncIo {
            source: std::io::Error::other("oops"),
        };
        assert!(!e.is_retryable());
        assert!(!e.is_fatal());
    }

    // ── Conversion to FfsError ───────────────────────────────────────────

    #[test]
    fn wal_write_error_converts_to_ffs_error() {
        let e: FfsError = WalWriteError::AppendIo {
            source: std::io::Error::other("boom"),
            bytes_attempted: 10,
        }
        .into();
        assert!(matches!(e, FfsError::Io(_)));

        let e: FfsError = WalWriteError::FormatViolation {
            detail: "bad".to_owned(),
        }
        .into();
        assert!(matches!(e, FfsError::Format(_)));

        let e: FfsError = WalWriteError::VerificationFailed {
            expected_crc: 1,
            actual_crc: 2,
            offset: 0,
        }
        .into();
        assert!(matches!(e, FfsError::Corruption { .. }));
    }

    // ── Property: monotonic ordering across random sequences ─────────────

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn proptest_monotonic_ordering_preserved(
            seq_increments in proptest::collection::vec(1_u64..100, 1..20),
        ) {
            let path = tmp_path();
            let mut w = WalWriter::create(&path, WalWriterConfig {
                sync_policy: SyncPolicy::Manual,
                ..WalWriterConfig::default()
            }).expect("create");

            let mut current_seq = 0_u64;
            for delta in &seq_increments {
                current_seq += delta;
                let commit = make_commit(current_seq, current_seq, &[]);
                w.append_commit(&commit).expect("monotonic append");
            }

            // Read back and verify ordering
            let data = std::fs::read(&path).expect("read");
            let mut offset = HEADER_SIZE;
            let mut last_seq = 0_u64;
            while offset < data.len() {
                match decode_commit(&data[offset..]) {
                    DecodeResult::Commit(c) => {
                        prop_assert!(
                            c.commit_seq.0 > last_seq,
                            "decoded seq {} not > previous {}",
                            c.commit_seq.0,
                            last_seq
                        );
                        last_seq = c.commit_seq.0;
                        let size = commit_byte_size(&data[offset..]).expect("size");
                        offset += size;
                    }
                    DecodeResult::EndOfData => break,
                    other => {
                        prop_assert!(false, "unexpected decode result: {:?}", other);
                    }
                }
            }

            let _ = std::fs::remove_file(&path);
        }
    }

    // ── Flush when nothing pending ───────────────────────────────────────

    #[test]
    fn flush_with_nothing_pending_returns_zero() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        let flushed = w.flush().expect("flush");
        assert_eq!(flushed, 0);

        let _ = std::fs::remove_file(&path);
    }

    // ── last_commit_seq tracking ─────────────────────────────────────────

    #[test]
    fn last_commit_seq_tracks_appended_commits() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        assert_eq!(w.last_commit_seq(), 0);

        w.append_commit(&make_commit(10, 1, &[])).expect("append");
        assert_eq!(w.last_commit_seq(), 10);

        w.append_commit(&make_commit(20, 2, &[])).expect("append");
        assert_eq!(w.last_commit_seq(), 20);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_last_commit_seq_for_replay_sync() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        w.set_last_commit_seq(100);
        assert_eq!(w.last_commit_seq(), 100);

        // Now appending seq 50 should fail (non-monotonic)
        let err = w
            .append_commit(&make_commit(50, 1, &[]))
            .expect_err("non-monotonic after set");
        assert!(err.is_fatal());

        // But seq 101 should succeed
        w.append_commit(&make_commit(101, 2, &[]))
            .expect("monotonic after set");

        let _ = std::fs::remove_file(&path);
    }

    // ── Coalesced append tests ─────────────────────────────────────────

    #[test]
    fn coalesced_empty_returns_empty() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).unwrap();
        let results = w.append_commits_coalesced(&[]).unwrap();
        assert!(results.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn coalesced_single_delegates() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).unwrap();
        let commits = vec![make_commit(1, 1, &[(10, &[0xAA; 64])])];
        let results = w.append_commits_coalesced(&commits).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].synced); // Immediate sync
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn coalesced_multiple_writes_single_io() {
        let path = tmp_path();
        let cfg = WalWriterConfig {
            sync_policy: SyncPolicy::Immediate,
            verify_writes: false,
            backpressure_threshold_bytes: 0,
        };
        let mut w = WalWriter::create(&path, cfg).unwrap();

        let data = vec![0xBB_u8; 128];
        let commits = vec![
            make_commit(1, 1, &[(10, &data)]),
            make_commit(2, 2, &[(20, &data)]),
            make_commit(3, 3, &[(30, &data)]),
        ];

        let results = w.append_commits_coalesced(&commits).unwrap();
        assert_eq!(results.len(), 3);

        // Offsets should be strictly increasing.
        assert!(results[0].offset < results[1].offset);
        assert!(results[1].offset < results[2].offset);

        // Last commit seq should be 3.
        assert_eq!(w.last_commit_seq(), 3);

        // All records should be readable from file.
        let mut file = std::fs::File::open(&path).unwrap();
        let mut all_data = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut all_data).unwrap();

        // Verify header + 3 records are present.
        let header = decode_header(&all_data[..HEADER_SIZE]).unwrap();
        assert_eq!(header.version, 1);

        let mut offset = HEADER_SIZE;
        for seq in 1..=3_u64 {
            let result = decode_commit(&all_data[offset..]);
            match result {
                DecodeResult::Commit(commit) => {
                    assert_eq!(commit.commit_seq.0, seq);
                    let size = commit_byte_size(&all_data[offset..]).unwrap();
                    offset += size;
                }
                other => assert!(
                    matches!(other, DecodeResult::Commit(_)),
                    "expected Commit, got {other:?}"
                ),
            }
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn coalesced_pending_sync_count_saturates_at_numeric_limit() {
        let path = tmp_path();
        let config = WalWriterConfig {
            sync_policy: SyncPolicy::Manual,
            ..WalWriterConfig::default()
        };
        let mut w = WalWriter::create(&path, config).unwrap();
        w.appends_since_sync = u32::MAX - 1;

        let commits = vec![make_commit(1, 1, &[]), make_commit(2, 2, &[])];
        let results = w.append_commits_coalesced(&commits).unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|result| !result.synced));
        assert!(
            results
                .iter()
                .all(|result| result.pending_sync_count == u32::MAX)
        );
        assert_eq!(w.pending_sync_count(), u32::MAX);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn coalesced_rejects_non_monotonic() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).unwrap();

        let commits = vec![
            make_commit(1, 1, &[]),
            make_commit(3, 2, &[]),
            make_commit(2, 3, &[]), // Out of order!
        ];

        let err = w
            .append_commits_coalesced(&commits)
            .expect_err("non-monotonic");
        assert!(err.is_fatal());

        // No bytes should have been written (pre-validation).
        assert_eq!(w.size(), HEADER_SIZE as u64);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn coalesced_rejects_sentinel() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).unwrap();

        let commits = vec![
            make_commit(1, 1, &[]),
            make_commit(u64::MAX, 2, &[]), // Sentinel!
        ];

        let err = w.append_commits_coalesced(&commits).expect_err("sentinel");
        assert!(err.is_fatal());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn coalesced_respects_prior_commit_seq() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).unwrap();

        // Append a single commit first.
        w.append_commit(&make_commit(5, 1, &[])).unwrap();

        // Coalesced batch starting at seq 3 should fail (3 <= 5).
        let commits = vec![make_commit(3, 2, &[]), make_commit(6, 3, &[])];
        let err = w
            .append_commits_coalesced(&commits)
            .expect_err("non-monotonic vs prior");
        assert!(err.is_fatal());

        // Batch starting at 6 should succeed.
        let commits = vec![make_commit(6, 2, &[]), make_commit(7, 3, &[])];
        let results = w.append_commits_coalesced(&commits).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(w.last_commit_seq(), 7);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn coalesced_sync_failure_rolls_back_pending_state() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).unwrap();
        let commits = vec![make_commit(1, 1, &[]), make_commit(2, 2, &[])];

        w.fail_sync = true;
        let err = w
            .append_commits_coalesced(&commits)
            .expect_err("injected coalesced sync failure");
        assert!(matches!(err, WalWriteError::SyncIo { .. }));
        assert_eq!(
            w.pending_sync_count(),
            0,
            "failed coalesced sync must not leave phantom pending appends"
        );
        assert_eq!(
            w.size(),
            HEADER_SIZE as u64,
            "failed coalesced sync must roll back WAL size"
        );
        assert_eq!(
            w.last_commit_seq(),
            0,
            "failed coalesced sync must not advance commit sequence"
        );

        let _ = std::fs::remove_file(&path);
    }
}
