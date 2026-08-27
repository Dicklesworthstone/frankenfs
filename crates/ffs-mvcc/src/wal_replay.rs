//! WAL replay engine with configurable corruption/torn-record recovery policy.
//!
//! This module provides [`WalReplayEngine`], which decodes and validates WAL
//! commit records while enforcing a configurable [`TailPolicy`] for handling
//! truncated or corrupted tails.  The engine is decoupled from the MVCC store
//! via a caller-supplied apply closure, making it independently testable.
//!
//! # Tail Policies
//!
//! | Policy | Behaviour on bad tail |
//! |--------|-----------------------|
//! | [`TailPolicy::TruncateToLastGood`] | Stop replay at last valid record, report discarded count. |
//! | [`TailPolicy::FailFast`] | Return an error immediately — used for audit / strict verification. |
//!
//! # Replay Outcomes
//!
//! Every successful replay produces a [`ReplayOutcome`] classification:
//!
//! - `Clean` — all records decoded, no issues.
//! - `EmptyLog` — header only, no commit records.
//! - `TruncatedTail` — one or more partial records at end of log.
//! - `CorruptTail` — CRC mismatch detected; replayed up to last good record.
//! - `MonotonicityViolation` — non-increasing commit sequence detected.

use crate::wal::{self, DecodeResult, WalCommit};
use ffs_error::{FfsError, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ── Tail policy ──────────────────────────────────────────────────────────────

/// Policy governing how the replay engine handles corrupt or truncated WAL tails.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TailPolicy {
    /// Truncate the WAL to the last known-good record and continue.
    /// This is the default for production use.
    #[default]
    TruncateToLastGood,

    /// Abort replay immediately on any corruption or truncation.
    /// Used for audit, strict verification, or operator-override scenarios.
    FailFast,
}

// ── Replay outcome classification ────────────────────────────────────────────

/// Classification of how a WAL replay completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayOutcome {
    /// All records decoded cleanly with no issues.
    Clean,

    /// WAL contained no commit records (header only).
    EmptyLog,

    /// One or more truncated (partial) records at the end of the log.
    TruncatedTail {
        /// Number of records that could not be fully decoded.
        records_discarded: u64,
    },

    /// CRC corruption detected; replayed up to last good record.
    CorruptTail {
        /// Number of records discarded due to corruption.
        records_discarded: u64,
        /// Byte offset (relative to data start) where corruption was first seen.
        first_corrupt_offset: u64,
    },

    /// Non-increasing commit sequence detected in the log.
    MonotonicityViolation {
        /// The offending commit sequence number.
        violating_seq: u64,
        /// The previous (higher or equal) commit sequence.
        expected_after: u64,
    },
}

impl ReplayOutcome {
    /// Returns `true` if the replay completed without any discarded records.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::Clean | Self::EmptyLog)
    }
}

// ── Replay report ────────────────────────────────────────────────────────────

/// Detailed report produced by a WAL replay.
#[derive(Debug, Clone)]
pub struct ReplayReport {
    /// How the replay completed.
    pub outcome: ReplayOutcome,
    /// Number of commits successfully replayed (applied to store).
    pub commits_replayed: u64,
    /// Number of block versions restored.
    pub versions_replayed: u64,
    /// Number of WAL records discarded (corrupt, truncated, or invalid).
    pub records_discarded: u64,
    /// Byte offset (relative to data start, after header) where valid data ends.
    pub last_valid_offset: u64,
    /// Total size of WAL data (after header) provided to the engine.
    pub total_data_bytes: u64,
    /// Highest commit sequence number successfully replayed.
    pub last_commit_seq: u64,
}

// ── Replay engine ────────────────────────────────────────────────────────────

/// WAL replay engine with configurable tail-handling policy.
///
/// The engine decodes and validates commit records from raw WAL data (after the
/// file header), enforcing monotonicity and sentinel invariants.  Each valid
/// commit is passed to a caller-supplied closure for application to the MVCC
/// store.
#[derive(Debug)]
pub struct WalReplayEngine {
    tail_policy: TailPolicy,
}

impl WalReplayEngine {
    /// Create a new replay engine with the given tail-handling policy.
    #[must_use]
    pub fn new(tail_policy: TailPolicy) -> Self {
        Self { tail_policy }
    }

    /// Replay WAL data into the caller's store via the `apply` closure.
    ///
    /// `data` is the raw WAL content **after** the 16-byte file header.
    /// Commits with `commit_seq <= skip_up_to_seq` are decoded but not applied
    /// (used for checkpoint-based recovery where earlier commits are already
    /// loaded).
    ///
    /// Returns a [`ReplayReport`] describing what happened.  Under
    /// [`TailPolicy::FailFast`], returns `Err` on the first corrupt or
    /// truncated record instead of continuing.
    #[expect(clippy::too_many_lines)]
    pub fn replay<F>(&self, data: &[u8], skip_up_to_seq: u64, mut apply: F) -> Result<ReplayReport>
    where
        F: FnMut(&WalCommit),
    {
        let total_data_bytes = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let operation_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));

        info!(
            operation_id,
            total_data_bytes,
            skip_up_to_seq,
            tail_policy = ?self.tail_policy,
            "wal_replay_start"
        );

        if data.is_empty() {
            info!(operation_id, "wal_replay_empty");
            return Ok(ReplayReport {
                outcome: ReplayOutcome::EmptyLog,
                commits_replayed: 0,
                versions_replayed: 0,
                records_discarded: 0,
                last_valid_offset: 0,
                total_data_bytes,
                last_commit_seq: skip_up_to_seq,
            });
        }

        let mut offset = 0_usize;
        let mut commits_replayed = 0_u64;
        let mut versions_replayed = 0_u64;
        let mut records_discarded = 0_u64;
        let mut last_decoded_seq = 0_u64;
        let mut last_replayed_seq = skip_up_to_seq;
        let mut last_valid_offset = 0_usize;
        let mut outcome = ReplayOutcome::Clean;

        while offset < data.len() {
            let record_offset = offset;

            match wal::decode_commit(&data[offset..]) {
                DecodeResult::Commit(commit) => {
                    let Some(size) = wal::commit_byte_size(&data[offset..]) else {
                        debug!(
                            operation_id,
                            offset = record_offset,
                            "wal_replay_size_unknown"
                        );
                        records_discarded += 1;
                        outcome = ReplayOutcome::TruncatedTail { records_discarded };
                        break;
                    };
                    offset += size;

                    // D8: Reject sentinel values before checkpoint skipping so
                    // malformed covered prefixes cannot be reported clean.
                    if commit.commit_seq.0 == u64::MAX || commit.txn_id.0 == u64::MAX {
                        let record_offset_u64 = u64::try_from(record_offset).unwrap_or(u64::MAX);

                        if self.tail_policy == TailPolicy::FailFast {
                            warn!(
                                operation_id,
                                offset = record_offset,
                                commit_seq = commit.commit_seq.0,
                                txn_id = commit.txn_id.0,
                                "wal_replay_sentinel_fail_fast"
                            );
                            return Err(FfsError::Format(format!(
                                "WAL replay: sentinel value at offset {record_offset_u64}; \
                                 FailFast policy in effect"
                            )));
                        }

                        warn!(
                            operation_id,
                            offset = record_offset,
                            commit_seq = commit.commit_seq.0,
                            txn_id = commit.txn_id.0,
                            "wal_replay_sentinel_rejected"
                        );
                        records_discarded += 1;
                        outcome = ReplayOutcome::CorruptTail {
                            records_discarded,
                            first_corrupt_offset: record_offset_u64,
                        };
                        break;
                    }

                    // D1: Enforce strict monotonicity across every decoded
                    // record. `skip_up_to_seq` suppresses apply only; it must
                    // not hide malformed checkpoint-covered WAL prefixes.
                    if commit.commit_seq.0 <= last_decoded_seq {
                        let record_offset_u64 = u64::try_from(record_offset).unwrap_or(u64::MAX);

                        if self.tail_policy == TailPolicy::FailFast {
                            warn!(
                                operation_id,
                                offset = record_offset,
                                violating_seq = commit.commit_seq.0,
                                expected_after = last_decoded_seq,
                                "wal_replay_monotonicity_fail_fast"
                            );
                            return Err(FfsError::Format(format!(
                                "WAL replay: monotonicity violation at offset {record_offset_u64} \
                                 (seq {} <= {}); FailFast policy in effect",
                                commit.commit_seq.0, last_decoded_seq
                            )));
                        }

                        warn!(
                            operation_id,
                            offset = record_offset,
                            violating_seq = commit.commit_seq.0,
                            expected_after = last_decoded_seq,
                            "wal_replay_monotonicity_violation"
                        );
                        records_discarded += 1;
                        outcome = ReplayOutcome::MonotonicityViolation {
                            violating_seq: commit.commit_seq.0,
                            expected_after: last_decoded_seq,
                        };
                        break;
                    }
                    last_decoded_seq = commit.commit_seq.0;

                    // Skip commits already covered by checkpoint.
                    if commit.commit_seq.0 <= skip_up_to_seq {
                        last_valid_offset = offset;
                        continue;
                    }

                    // Apply the commit.
                    debug!(
                        operation_id,
                        commit_seq = commit.commit_seq.0,
                        txn_id = commit.txn_id.0,
                        writes = commit.writes.len(),
                        "wal_replay_apply"
                    );
                    apply(&commit);
                    last_replayed_seq = commit.commit_seq.0;
                    commits_replayed += 1;
                    versions_replayed += u64::try_from(commit.writes.len()).unwrap_or(u64::MAX);
                    last_valid_offset = offset;
                }
                DecodeResult::EndOfData => {
                    debug!(operation_id, offset, "wal_replay_end_of_data");
                    last_valid_offset = offset;
                    break;
                }
                DecodeResult::NeedMore(needed) => {
                    let record_offset_u64 = u64::try_from(record_offset).unwrap_or(u64::MAX);

                    if self.tail_policy == TailPolicy::FailFast {
                        warn!(
                            operation_id,
                            offset = record_offset,
                            needed,
                            "wal_replay_truncated_fail_fast"
                        );
                        return Err(FfsError::Format(format!(
                            "WAL replay: truncated record at offset {record_offset_u64} \
                             (need {needed} more bytes); FailFast policy in effect"
                        )));
                    }

                    warn!(
                        operation_id,
                        offset = record_offset,
                        needed,
                        "wal_replay_truncated_tail"
                    );
                    records_discarded += 1;
                    outcome = ReplayOutcome::TruncatedTail { records_discarded };
                    break;
                }
                DecodeResult::Corrupted(msg) => {
                    let record_offset_u64 = u64::try_from(record_offset).unwrap_or(u64::MAX);

                    if self.tail_policy == TailPolicy::FailFast {
                        warn!(
                            operation_id,
                            offset = record_offset,
                            reason = %msg,
                            "wal_replay_corrupt_fail_fast"
                        );
                        return Err(FfsError::Format(format!(
                            "WAL replay: corrupt record at offset {record_offset_u64}: \
                             {msg}; FailFast policy in effect"
                        )));
                    }

                    warn!(
                        operation_id,
                        offset = record_offset,
                        reason = %msg,
                        "wal_replay_corrupt_tail"
                    );
                    records_discarded += 1;
                    outcome = ReplayOutcome::CorruptTail {
                        records_discarded,
                        first_corrupt_offset: record_offset_u64,
                    };
                    break;
                }
            }
        }

        let last_valid_offset_u64 = u64::try_from(last_valid_offset).unwrap_or(u64::MAX);

        info!(
            operation_id,
            commits_replayed,
            versions_replayed,
            records_discarded,
            last_valid_offset = last_valid_offset_u64,
            outcome = ?outcome,
            "wal_replay_done"
        );

        Ok(ReplayReport {
            outcome,
            commits_replayed,
            versions_replayed,
            records_discarded,
            last_valid_offset: last_valid_offset_u64,
            total_data_bytes,
            last_commit_seq: last_replayed_seq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::{self, WalCommit, WalWrite};
    use ffs_types::{BlockNumber, CommitSeq, TxnId};

    /// Helper: encode a sequence of commits into raw data (no header).
    fn encode_commits(commits: &[WalCommit]) -> Vec<u8> {
        let mut data = Vec::new();
        for c in commits {
            data.extend_from_slice(&wal::encode_commit(c).expect("encode commit"));
        }
        data
    }

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

    // ── Clean replay ─────────────────────────────────────────────────────

    #[test]
    fn replay_clean_single_commit() {
        let commits = vec![make_commit(1, 1, &[(10, &[0xAA; 16])])];
        let data = encode_commits(&commits);

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let mut applied = Vec::new();
        let report = engine
            .replay(&data, 0, |c| applied.push(c.clone()))
            .expect("replay");

        assert_eq!(report.outcome, ReplayOutcome::Clean);
        assert_eq!(report.commits_replayed, 1);
        assert_eq!(report.versions_replayed, 1);
        assert_eq!(report.records_discarded, 0);
        assert_eq!(report.last_commit_seq, 1);
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].commit_seq, CommitSeq(1));
    }

    #[test]
    fn replay_clean_multiple_commits() {
        let commits = vec![
            make_commit(1, 1, &[(1, &[1; 8])]),
            make_commit(2, 2, &[(2, &[2; 8])]),
            make_commit(3, 3, &[(3, &[3; 8]), (4, &[4; 8])]),
        ];
        let data = encode_commits(&commits);

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let mut count = 0_u64;
        let report = engine.replay(&data, 0, |_| count += 1).expect("replay");

        assert_eq!(report.outcome, ReplayOutcome::Clean);
        assert_eq!(report.commits_replayed, 3);
        assert_eq!(report.versions_replayed, 4);
        assert_eq!(report.last_commit_seq, 3);
        assert_eq!(count, 3);
    }

    // ── Empty log ────────────────────────────────────────────────────────

    #[test]
    fn replay_empty_log() {
        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let mut applied = false;
        let report = engine.replay(&[], 0, |_| applied = true).expect("replay");

        assert_eq!(report.outcome, ReplayOutcome::EmptyLog);
        assert_eq!(report.commits_replayed, 0);
        assert_eq!(report.records_discarded, 0);
        assert!(!applied);
    }

    // ── Truncated tail ───────────────────────────────────────────────────

    #[test]
    fn replay_truncated_tail_truncate_policy() {
        let commits = vec![
            make_commit(1, 1, &[(1, &[1; 32])]),
            make_commit(2, 2, &[(2, &[2; 32])]),
        ];
        let mut data = encode_commits(&commits);
        // Chop last 10 bytes to create a truncated second record.
        data.truncate(data.len() - 10);

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let mut applied = Vec::new();
        let report = engine
            .replay(&data, 0, |c| applied.push(c.commit_seq.0))
            .expect("replay");

        assert_eq!(
            report.outcome,
            ReplayOutcome::TruncatedTail {
                records_discarded: 1
            }
        );
        assert_eq!(report.commits_replayed, 1);
        assert_eq!(report.records_discarded, 1);
        assert_eq!(applied, vec![1]);
    }

    #[test]
    fn replay_truncated_tail_fail_fast_policy() {
        let commits = vec![
            make_commit(1, 1, &[(1, &[1; 32])]),
            make_commit(2, 2, &[(2, &[2; 32])]),
        ];
        let mut data = encode_commits(&commits);
        data.truncate(data.len() - 10);

        let engine = WalReplayEngine::new(TailPolicy::FailFast);
        let mut applied = Vec::new();
        let result = engine.replay(&data, 0, |c| applied.push(c.commit_seq.0));

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("truncated"), "error: {err_msg}");
        assert!(err_msg.contains("FailFast"), "error: {err_msg}");
        // First commit was applied before the truncated second record.
        assert_eq!(applied, vec![1]);
    }

    // ── Corrupt CRC ──────────────────────────────────────────────────────

    #[test]
    fn replay_corrupt_crc_truncate_policy() {
        let commits = vec![
            make_commit(1, 1, &[(1, &[1; 32])]),
            make_commit(2, 2, &[(2, &[2; 32])]),
        ];
        let mut data = encode_commits(&commits);

        // Flip a byte in the second record's body (not the first).
        let first_encoded = wal::encode_commit(&commits[0]).unwrap();
        let corrupt_pos = first_encoded.len() + 8; // well into second record
        data[corrupt_pos] ^= 0xFF;

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let mut applied = Vec::new();
        let report = engine
            .replay(&data, 0, |c| applied.push(c.commit_seq.0))
            .expect("replay");

        assert!(matches!(
            report.outcome,
            ReplayOutcome::CorruptTail {
                records_discarded: 1,
                ..
            }
        ));
        assert_eq!(report.commits_replayed, 1);
        assert_eq!(applied, vec![1]);
    }

    #[test]
    fn replay_corrupt_crc_fail_fast_policy() {
        let commits = vec![
            make_commit(1, 1, &[(1, &[1; 32])]),
            make_commit(2, 2, &[(2, &[2; 32])]),
        ];
        let mut data = encode_commits(&commits);

        let first_encoded = wal::encode_commit(&commits[0]).unwrap();
        let corrupt_pos = first_encoded.len() + 8;
        data[corrupt_pos] ^= 0xFF;

        let engine = WalReplayEngine::new(TailPolicy::FailFast);
        let result = engine.replay(&data, 0, |_| {});

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("corrupt") || err_msg.contains("FailFast"));
    }

    // ── Monotonicity violation ───────────────────────────────────────────

    #[test]
    fn replay_rejects_non_monotonic_sequence() {
        // commit_seq goes 1 → 3 → 2 (violation)
        let commits = vec![
            make_commit(1, 1, &[(1, &[1; 8])]),
            make_commit(3, 3, &[(3, &[3; 8])]),
            make_commit(2, 2, &[(2, &[2; 8])]),
        ];
        let data = encode_commits(&commits);

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let mut applied = Vec::new();
        let report = engine
            .replay(&data, 0, |c| applied.push(c.commit_seq.0))
            .expect("replay");

        assert_eq!(
            report.outcome,
            ReplayOutcome::MonotonicityViolation {
                violating_seq: 2,
                expected_after: 3,
            }
        );
        assert_eq!(report.commits_replayed, 2);
        assert_eq!(applied, vec![1, 3]);
    }

    #[test]
    fn replay_rejects_duplicate_sequence() {
        let commits = vec![
            make_commit(1, 1, &[(1, &[1; 8])]),
            make_commit(1, 2, &[(2, &[2; 8])]), // duplicate seq
        ];
        let data = encode_commits(&commits);

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let report = engine.replay(&data, 0, |_| {}).expect("replay");

        assert!(matches!(
            report.outcome,
            ReplayOutcome::MonotonicityViolation {
                violating_seq: 1,
                expected_after: 1,
            }
        ));
        assert_eq!(report.commits_replayed, 1);
    }

    // ── Sentinel rejection ───────────────────────────────────────────────

    #[test]
    fn replay_rejects_sentinel_commit_seq() {
        let commits = vec![
            make_commit(1, 1, &[(1, &[1; 8])]),
            make_commit(u64::MAX, 2, &[(2, &[2; 8])]),
        ];
        let data = encode_commits(&commits);

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let report = engine.replay(&data, 0, |_| {}).expect("replay");

        assert!(matches!(
            report.outcome,
            ReplayOutcome::CorruptTail {
                records_discarded: 1,
                ..
            }
        ));
        assert_eq!(report.commits_replayed, 1);
    }

    #[test]
    fn replay_rejects_sentinel_txn_id() {
        let commits = vec![
            make_commit(1, 1, &[(1, &[1; 8])]),
            make_commit(2, u64::MAX, &[(2, &[2; 8])]),
        ];
        let data = encode_commits(&commits);

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let report = engine.replay(&data, 0, |_| {}).expect("replay");

        assert!(matches!(
            report.outcome,
            ReplayOutcome::CorruptTail {
                records_discarded: 1,
                ..
            }
        ));
        assert_eq!(report.commits_replayed, 1);
    }

    // ── Skip-up-to-seq (checkpoint recovery) ─────────────────────────────

    #[test]
    fn replay_skips_commits_before_checkpoint() {
        let commits = vec![
            make_commit(1, 1, &[(1, &[1; 8])]),
            make_commit(2, 2, &[(2, &[2; 8])]),
            make_commit(3, 3, &[(3, &[3; 8])]),
            make_commit(4, 4, &[(4, &[4; 8])]),
        ];
        let data = encode_commits(&commits);

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let mut applied = Vec::new();
        let report = engine
            .replay(&data, 2, |c| applied.push(c.commit_seq.0))
            .expect("replay");

        assert_eq!(report.outcome, ReplayOutcome::Clean);
        assert_eq!(report.commits_replayed, 2); // only 3 and 4
        assert_eq!(applied, vec![3, 4]);
        assert_eq!(report.last_commit_seq, 4);
    }

    #[test]
    fn replay_validates_monotonicity_inside_skipped_checkpoint_prefix() {
        let commits = vec![
            make_commit(1, 1, &[(1, &[1; 8])]),
            make_commit(3, 3, &[(3, &[3; 8])]),
            make_commit(2, 2, &[(2, &[2; 8])]),
            make_commit(4, 4, &[(4, &[4; 8])]),
        ];
        let data = encode_commits(&commits);

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let mut applied = Vec::new();
        let report = engine
            .replay(&data, 3, |c| applied.push(c.commit_seq.0))
            .expect("replay");

        assert_eq!(
            report.outcome,
            ReplayOutcome::MonotonicityViolation {
                violating_seq: 2,
                expected_after: 3,
            }
        );
        assert_eq!(report.commits_replayed, 0);
        assert_eq!(report.records_discarded, 1);
        assert_eq!(applied, [] as [u64; 0]);
    }

    #[test]
    fn replay_fail_fast_rejects_non_monotonic_skipped_prefix() {
        let commits = vec![
            make_commit(1, 1, &[(1, &[1; 8])]),
            make_commit(2, 2, &[(2, &[2; 8])]),
            make_commit(1, 3, &[(3, &[3; 8])]),
        ];
        let data = encode_commits(&commits);

        let engine = WalReplayEngine::new(TailPolicy::FailFast);
        let mut applied = false;
        let err = engine.replay(&data, 2, |_| applied = true).unwrap_err();

        let err_msg = err.to_string();
        assert!(err_msg.contains("monotonicity"), "error: {err_msg}");
        assert!(err_msg.contains("FailFast"), "error: {err_msg}");
        assert!(!applied);
    }

    #[test]
    fn replay_rejects_sentinel_even_when_checkpoint_would_skip_it() {
        let commits = vec![make_commit(u64::MAX, 1, &[(1, &[1; 8])])];
        let data = encode_commits(&commits);

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let mut applied = false;
        let report = engine
            .replay(&data, u64::MAX, |_| applied = true)
            .expect("replay");

        assert!(matches!(
            report.outcome,
            ReplayOutcome::CorruptTail {
                records_discarded: 1,
                first_corrupt_offset: 0,
            }
        ));
        assert_eq!(report.commits_replayed, 0);
        assert!(!applied);
    }

    // ── Idempotent replay ────────────────────────────────────────────────

    #[test]
    fn replay_is_idempotent() {
        let commits = vec![
            make_commit(1, 1, &[(10, &[0xAA; 16])]),
            make_commit(2, 2, &[(20, &[0xBB; 16])]),
        ];
        let data = encode_commits(&commits);

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);

        let mut applied_1 = Vec::new();
        let report_1 = engine
            .replay(&data, 0, |c| applied_1.push(c.clone()))
            .expect("replay 1");

        let mut applied_2 = Vec::new();
        let report_2 = engine
            .replay(&data, 0, |c| applied_2.push(c.clone()))
            .expect("replay 2");

        assert_eq!(report_1.outcome, report_2.outcome);
        assert_eq!(report_1.commits_replayed, report_2.commits_replayed);
        assert_eq!(report_1.versions_replayed, report_2.versions_replayed);
        assert_eq!(applied_1.len(), applied_2.len());
        for (a, b) in applied_1.iter().zip(applied_2.iter()) {
            assert_eq!(a.commit_seq, b.commit_seq);
            assert_eq!(a.txn_id, b.txn_id);
            assert_eq!(a.writes.len(), b.writes.len());
        }
    }

    // ── Property: ordering preserved ─────────────────────────────────────

    #[test]
    fn replay_preserves_commit_ordering() {
        // Generate 20 commits with strictly increasing sequences.
        let commits: Vec<WalCommit> = (1..=20)
            .map(|i| {
                let byte = u8::try_from(i).expect("test value fits in u8");
                make_commit(i, i, &[(i, &[byte; 8])])
            })
            .collect();
        let data = encode_commits(&commits);

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let mut seqs = Vec::new();
        let report = engine
            .replay(&data, 0, |c| seqs.push(c.commit_seq.0))
            .expect("replay");

        assert_eq!(report.outcome, ReplayOutcome::Clean);
        assert_eq!(report.commits_replayed, 20);
        // Verify strictly increasing order.
        for w in seqs.windows(2) {
            assert!(w[0] < w[1], "ordering violated: {} >= {}", w[0], w[1]);
        }
    }

    // ── Corrupt first record ─────────────────────────────────────────────

    #[test]
    fn replay_corrupt_first_record_zero_commits() {
        let commits = vec![make_commit(1, 1, &[(1, &[1; 32])])];
        let mut data = encode_commits(&commits);
        // Corrupt byte in the first (and only) record.
        data[8] ^= 0xFF;

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let report = engine.replay(&data, 0, |_| {}).expect("replay");

        assert!(matches!(
            report.outcome,
            ReplayOutcome::CorruptTail {
                records_discarded: 1,
                first_corrupt_offset: 0,
            }
        ));
        assert_eq!(report.commits_replayed, 0);
    }

    // ── Default policy ───────────────────────────────────────────────────

    #[test]
    fn default_tail_policy_is_truncate() {
        assert_eq!(TailPolicy::default(), TailPolicy::TruncateToLastGood);
    }

    // ── Outcome classification helpers ───────────────────────────────────

    #[test]
    fn outcome_is_clean() {
        assert!(ReplayOutcome::Clean.is_clean());
        assert!(ReplayOutcome::EmptyLog.is_clean());
        assert!(
            !ReplayOutcome::TruncatedTail {
                records_discarded: 1
            }
            .is_clean()
        );
        assert!(
            !ReplayOutcome::CorruptTail {
                records_discarded: 1,
                first_corrupt_offset: 0,
            }
            .is_clean()
        );
        assert!(
            !ReplayOutcome::MonotonicityViolation {
                violating_seq: 1,
                expected_after: 1,
            }
            .is_clean()
        );
    }

    // ── Negative: apply closure not called for skipped commits ───────────

    #[test]
    fn replay_does_not_apply_skipped_commits() {
        let commits = vec![
            make_commit(1, 1, &[(1, &[1; 8])]),
            make_commit(2, 2, &[(2, &[2; 8])]),
            make_commit(3, 3, &[(3, &[3; 8])]),
        ];
        let data = encode_commits(&commits);

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let mut applied_seqs = Vec::new();
        let _report = engine
            .replay(&data, 3, |c| applied_seqs.push(c.commit_seq.0))
            .expect("replay");

        // All commits have seq <= 3, so none should be applied.
        assert_eq!(applied_seqs, [] as [u64; 0]);
    }

    // ── Large commit count ───────────────────────────────────────────────

    #[test]
    fn replay_handles_many_commits() {
        let commits: Vec<WalCommit> = (1..=100)
            .map(|i| {
                let byte = u8::try_from(i).expect("test value fits in u8");
                make_commit(i, i, &[(i, &[byte; 4])])
            })
            .collect();
        let data = encode_commits(&commits);

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let report = engine.replay(&data, 0, |_| {}).expect("replay");

        assert_eq!(report.outcome, ReplayOutcome::Clean);
        assert_eq!(report.commits_replayed, 100);
        assert_eq!(report.last_commit_seq, 100);
    }

    // ── Error classification for FailFast ────────────────────────────────

    #[test]
    fn fail_fast_error_is_format_error() {
        let commits = vec![make_commit(1, 1, &[(1, &[1; 32])])];
        let mut data = encode_commits(&commits);
        data.truncate(data.len() - 5);

        let engine = WalReplayEngine::new(TailPolicy::FailFast);
        let err = engine.replay(&data, 0, |_| {}).unwrap_err();

        assert!(
            matches!(err, FfsError::Format(_)),
            "expected Format error, got {err:?}"
        );
    }

    // ── Property-based tests (proptest) ──────────────────────────────────

    use proptest::prelude::*;

    /// Strategy: generate 1..16 monotonically-increasing commits with
    /// 0..4 writes each, payload bytes free.
    fn monotonic_commits_strat() -> impl Strategy<Value = Vec<WalCommit>> {
        proptest::collection::vec(
            (
                1_u64..=64,   // seq delta from previous
                any::<u64>(), // txn_id
                proptest::collection::vec(
                    (any::<u64>(), proptest::collection::vec(any::<u8>(), 0..16)),
                    0..4,
                ),
            ),
            1..16,
        )
        .prop_map(|raw| {
            let mut seq: u64 = 0;
            raw.into_iter()
                .map(|(delta, txn, blocks)| {
                    seq = seq.saturating_add(delta);
                    WalCommit {
                        commit_seq: CommitSeq(seq),
                        txn_id: TxnId(txn),
                        writes: blocks
                            .into_iter()
                            .map(|(b, data)| WalWrite {
                                block: BlockNumber(b),
                                data,
                            })
                            .collect(),
                    }
                })
                .collect()
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Property: replaying any monotonic, well-formed commit sequence
        /// under TruncateToLastGood produces ReplayOutcome::Clean and
        /// applies every commit exactly once.
        #[test]
        fn proptest_clean_monotonic_replay_applies_every_commit(
            commits in monotonic_commits_strat(),
        ) {
            let data = encode_commits(&commits);
            let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
            let mut applied = Vec::new();
            let report = engine
                .replay(&data, 0, |c| applied.push(c.clone()))
                .expect("clean replay must not fail");
            prop_assert_eq!(report.outcome, ReplayOutcome::Clean);
            prop_assert_eq!(report.commits_replayed, commits.len() as u64);
            prop_assert_eq!(applied.len(), commits.len());
            // Every commit's seq matches what we encoded, in order.
            for (orig, app) in commits.iter().zip(applied.iter()) {
                prop_assert_eq!(orig.commit_seq, app.commit_seq);
                prop_assert_eq!(orig.txn_id, app.txn_id);
                prop_assert_eq!(orig.writes.len(), app.writes.len());
            }
            // versions_replayed = sum of all write counts.
            let total_writes: u64 = commits.iter().map(|c| c.writes.len() as u64).sum();
            prop_assert_eq!(report.versions_replayed, total_writes);
        }

        /// Property: skip_up_to_seq filters apply but never affects
        /// outcome classification on a clean stream — every commit with
        /// seq > skip_up_to_seq is applied; those with seq <= are
        /// silently skipped. The outcome stays Clean and records_discarded
        /// stays zero.
        #[test]
        fn proptest_skip_up_to_seq_filters_apply_only(
            commits in monotonic_commits_strat(),
            skip_idx_seed in 0_usize..16,
        ) {
            let data = encode_commits(&commits);
            let last_seq = commits.last().expect("commits non-empty").commit_seq.0;
            // Choose a skip cutoff between 0 and last_seq+10 so we exercise
            // both the "skip none" and "skip all" boundaries.
            let skip = (skip_idx_seed as u64).saturating_mul(7) % (last_seq + 11);
            let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
            let mut applied = Vec::new();
            let report = engine
                .replay(&data, skip, |c| applied.push(c.commit_seq.0))
                .expect("clean replay must not fail");
            prop_assert_eq!(report.outcome, ReplayOutcome::Clean);
            prop_assert_eq!(report.records_discarded, 0);
            // Applied commits must all have seq > skip.
            for seq in &applied {
                prop_assert!(*seq > skip,
                    "applied commit seq {} must be > skip {}", seq, skip);
            }
            // Count of applied commits = count of commits with seq > skip.
            let expected: usize = commits
                .iter()
                .filter(|c| c.commit_seq.0 > skip)
                .count();
            prop_assert_eq!(applied.len(), expected);
        }
    }
}
