//! Exercise failure paths against real temporary WAL files and the real decoder.
//! Injected failures happen at I/O boundaries, including after complete records
//! have reached the file. These are not power-loss or mounted-filesystem tests.

use super::*;
use crate::wal::WalWrite;
use crate::wal_replay::{TailPolicy, WalReplayEngine};
use ffs_types::{BlockNumber, CommitSeq, TxnId};
use std::path::PathBuf;
use tempfile::{TempDir, tempdir};

fn fixture(config: WalWriterConfig) -> (TempDir, PathBuf, WalWriter) {
    let directory = tempdir().expect("temporary WAL directory");
    let path = directory.path().join("versions.wal");
    let writer = WalWriter::create(&path, config).expect("create WAL");
    (directory, path, writer)
}

fn commit(seq: u64, byte: u8, len: usize) -> WalCommit {
    WalCommit {
        commit_seq: CommitSeq(seq),
        txn_id: TxnId(seq),
        writes: vec![WalWrite {
            block: BlockNumber(7),
            data: vec![byte; len],
        }],
    }
}

fn replay_file(path: &Path) -> Vec<WalCommit> {
    let bytes = std::fs::read(path).expect("read WAL through another file handle");
    wal::decode_header(&bytes[..HEADER_SIZE]).expect("valid header");
    let data = &bytes[HEADER_SIZE..];
    let mut commits = Vec::new();
    let report = WalReplayEngine::new(TailPolicy::FailFast)
        .replay(data, 0, |commit| commits.push(commit.clone()))
        .expect("strict replay must accept the entire WAL");
    assert!(report.outcome.is_clean());
    assert_eq!(report.last_valid_offset, u64::try_from(data.len()).unwrap());
    commits
}

fn assert_sealed(writer: &mut WalWriter, path: &Path) {
    let bytes = std::fs::read(path).expect("capture ambiguous WAL");
    let size = writer.size();
    let seq = writer.last_commit_seq();
    let pending = writer.pending_sync_count();
    writer.fail_append_after = None;
    writer.fail_sync = false;
    writer.fail_rollback_sync = false;
    writer.fail_rollback_truncate = false;

    for error in [
        writer.ensure_ready().expect_err("sealed health check"),
        writer
            .append_commit(&commit(10, 10, 1))
            .expect_err("sealed append"),
        writer
            .append_commits_coalesced(&[])
            .expect_err("sealed empty batch"),
        writer
            .append_commits_coalesced(&[commit(10, 10, 1), commit(11, 11, 1)])
            .expect_err("sealed coalesced append"),
        writer
            .flush()
            .expect_err("sealed flush must not acknowledge zero pending"),
    ] {
        assert!(matches!(error, WalWriteError::RecoveryRequired { .. }));
        assert!(error.is_fatal());
        assert!(!error.is_retryable());
    }
    assert_eq!(writer.size(), size);
    assert_eq!(writer.last_commit_seq(), seq);
    assert_eq!(writer.pending_sync_count(), pending);
    assert_eq!(
        std::fs::read(path).unwrap(),
        bytes,
        "sealed calls must not touch storage"
    );
}

#[test]
fn partial_append_restores_the_exact_prefix_before_a_smaller_retry() {
    let (_directory, path, mut writer) = fixture(WalWriterConfig::default());
    let first = commit(1, 1, 64);
    writer.append_commit(&first).expect("accepted prefix");
    let prefix = std::fs::read(&path).unwrap();
    let prefix_size = writer.size();

    writer.fail_append_after = Some(127);
    let error = writer
        .append_commit(&commit(2, 2, 4096))
        .expect_err("partial write");
    assert!(matches!(error, WalWriteError::AppendIo { .. }));
    assert!(error.is_retryable());
    assert_eq!(std::fs::read(&path).unwrap(), prefix);
    assert_eq!(writer.size(), prefix_size);
    assert_eq!(writer.last_commit_seq(), 1);
    writer
        .ensure_ready()
        .expect("durable rollback permits retry");

    writer.fail_append_after = None;
    let retry = commit(2, 3, 1);
    writer.append_commit(&retry).expect("shorter retry");
    drop(writer);
    assert_eq!(replay_file(&path), vec![first, retry]);
}

#[test]
fn complete_but_unacknowledged_record_is_removed_on_append_error() {
    let (_directory, path, mut writer) = fixture(WalWriterConfig {
        sync_policy: SyncPolicy::Manual,
        ..WalWriterConfig::default()
    });
    let prefix = std::fs::read(&path).unwrap();
    writer.fail_append_after = Some(usize::MAX);
    writer
        .append_commit(&commit(1, 1, 128))
        .expect_err("error after full record");
    assert_eq!(std::fs::read(&path).unwrap(), prefix);
    assert_eq!(writer.last_commit_seq(), 0);
    assert_eq!(writer.pending_sync_count(), 0);
    writer
        .ensure_ready()
        .expect("rollback includes mandatory sync in Manual mode");
    drop(writer);
    assert_eq!(replay_file(&path), Vec::new());
}

#[test]
fn coalesced_partial_append_never_publishes_its_complete_first_record() {
    let (_directory, path, mut writer) = fixture(WalWriterConfig::default());
    let first = commit(1, 1, 8);
    writer.append_commit(&first).unwrap();
    let prefix = std::fs::read(&path).unwrap();
    let batch = [commit(2, 2, 32), commit(3, 3, 2048)];
    writer.fail_append_after = Some(wal::encode_commit(&batch[0]).unwrap().len() + 7);
    writer
        .append_commits_coalesced(&batch)
        .expect_err("partially written batch");
    assert_eq!(std::fs::read(&path).unwrap(), prefix);
    assert_eq!(writer.last_commit_seq(), 1);
    assert_eq!(writer.pending_sync_count(), 0);
    writer.fail_append_after = None;
    let retry = commit(2, 4, 1);
    writer
        .append_commit(&retry)
        .expect("reuse failed batch sequence");
    drop(writer);
    assert_eq!(replay_file(&path), vec![first, retry]);
}

#[test]
fn failed_truncate_seals_writer_with_a_replayable_unacknowledged_record() {
    let (_directory, path, mut writer) = fixture(WalWriterConfig::default());
    let first = commit(1, 1, 8);
    let uncertain = commit(2, 2, 64);
    writer.append_commit(&first).unwrap();
    writer.fail_append_after = Some(usize::MAX);
    writer.fail_rollback_truncate = true;
    let error = writer
        .append_commit(&uncertain)
        .expect_err("rollback cannot truncate");
    assert!(matches!(error, WalWriteError::RecoveryRequired { .. }));
    assert!(error.to_string().contains("rollback truncate failure"));
    assert_eq!(writer.last_commit_seq(), 1);
    // The in-memory sequence does not make this valid on-disk record an orphan.
    assert_eq!(replay_file(&path), vec![first, uncertain]);
    assert_sealed(&mut writer, &path);
}

#[test]
fn rollback_sync_failure_is_not_mistaken_for_a_completed_rollback() {
    let (_directory, path, mut writer) = fixture(WalWriterConfig::default());
    let prefix = std::fs::read(&path).unwrap();
    writer.fail_append_after = Some(usize::MAX);
    writer.fail_rollback_sync = true;
    let error = writer
        .append_commit(&commit(1, 1, 64))
        .expect_err("rollback not durable");
    assert!(matches!(error, WalWriteError::RecoveryRequired { .. }));
    assert!(error.to_string().contains("rollback sync failure"));
    // A successful set_len alone is not evidence of power-loss durability.
    assert_eq!(std::fs::read(&path).unwrap(), prefix);
    assert_sealed(&mut writer, &path);
}

#[test]
fn sync_failure_rolls_back_only_the_new_record_and_preserves_pending_prefix() {
    let (_directory, path, mut writer) = fixture(WalWriterConfig {
        sync_policy: SyncPolicy::EveryN(3),
        ..WalWriterConfig::default()
    });
    let first = commit(1, 1, 8);
    let second = commit(2, 2, 8);
    writer.append_commit(&first).unwrap();
    writer.append_commit(&second).unwrap();
    let prefix = std::fs::read(&path).unwrap();
    writer.fail_sync = true;
    let error = writer
        .append_commit(&commit(3, 3, 1024))
        .expect_err("batch sync fails");
    assert!(matches!(error, WalWriteError::SyncIo { .. }));
    assert_eq!(std::fs::read(&path).unwrap(), prefix);
    assert_eq!(writer.last_commit_seq(), 2);
    assert_eq!(writer.pending_sync_count(), 2);
    writer.ensure_ready().expect("rollback sync succeeded");
    writer.fail_sync = false;
    let retry = commit(3, 4, 1);
    assert!(writer.append_commit(&retry).unwrap().synced);
    drop(writer);
    assert_eq!(replay_file(&path), vec![first, second, retry]);
}

#[test]
fn coalesced_sync_failure_seals_if_the_batch_cannot_be_removed() {
    let (_directory, path, mut writer) = fixture(WalWriterConfig::default());
    writer.fail_sync = true;
    writer.fail_rollback_truncate = true;
    let batch = [commit(1, 1, 32), commit(2, 2, 64)];
    let error = writer
        .append_commits_coalesced(&batch)
        .expect_err("batch rollback failure");
    assert!(matches!(error, WalWriteError::RecoveryRequired { .. }));
    assert_eq!(writer.last_commit_seq(), 0);
    assert_eq!(replay_file(&path), batch);
    assert_sealed(&mut writer, &path);
}

#[test]
fn verification_read_error_uses_the_same_durable_rollback() {
    let (_directory, path, writer) = fixture(WalWriterConfig::default());
    let prefix = std::fs::read(&path).unwrap();
    let offset = writer.size();
    drop(writer);
    // An actual write-only descriptor makes readback fail AFTER writing a
    // complete record, without substituting the verification implementation.
    let file = OpenOptions::new().write(true).open(&path).unwrap();
    let mut writer = WalWriter::new(
        file,
        offset,
        WalWriterConfig {
            verify_writes: true,
            ..WalWriterConfig::default()
        },
    );
    let error = writer
        .append_commit(&commit(1, 1, 512))
        .expect_err("readback on write-only fd");
    assert!(matches!(error, WalWriteError::AppendIo { .. }));
    assert_eq!(std::fs::read(&path).unwrap(), prefix);
    assert_eq!(writer.size(), offset);
    writer.ensure_ready().expect("verified rollback");
    writer.config.verify_writes = false;
    let retry = commit(1, 2, 1);
    writer
        .append_commit(&retry)
        .expect("retry after verified rollback");
    drop(writer);
    assert_eq!(replay_file(&path), vec![retry]);
}

#[test]
fn coalesced_verification_failure_cannot_hide_failed_rollback() {
    let (_directory, path, writer) = fixture(WalWriterConfig::default());
    let offset = writer.size();
    drop(writer);
    let file = OpenOptions::new().write(true).open(&path).unwrap();
    let mut writer = WalWriter::new(
        file,
        offset,
        WalWriterConfig {
            verify_writes: true,
            ..WalWriterConfig::default()
        },
    );
    writer.fail_rollback_truncate = true;
    let batch = [commit(1, 1, 8), commit(2, 2, 8)];
    let error = writer
        .append_commits_coalesced(&batch)
        .expect_err("readback and rollback failure");
    assert!(matches!(error, WalWriteError::RecoveryRequired { .. }));
    assert_eq!(replay_file(&path), batch);
    assert_sealed(&mut writer, &path);
}

#[test]
fn explicit_flush_failure_preserves_accepted_records_and_seals_writer() {
    let (_directory, path, mut writer) = fixture(WalWriterConfig {
        sync_policy: SyncPolicy::Manual,
        ..WalWriterConfig::default()
    });
    let first = commit(1, 1, 128);
    writer.append_commit(&first).unwrap();
    let prefix = std::fs::read(&path).unwrap();
    writer.fail_sync = true;
    let error = writer.flush().expect_err("explicit sync failure");
    assert!(matches!(error, WalWriteError::RecoveryRequired { .. }));
    assert_eq!(std::fs::read(&path).unwrap(), prefix);
    assert_eq!(writer.pending_sync_count(), 1);
    assert_eq!(writer.last_commit_seq(), 1);
    assert_sealed(&mut writer, &path);
    drop(writer);
    assert_eq!(replay_file(&path), vec![first]);
}

#[test]
fn append_offset_overflow_is_rejected_before_io_or_rollback() {
    let (_directory, path, mut writer) = fixture(WalWriterConfig::default());
    let prefix = std::fs::read(&path).unwrap();
    let actual_offset = writer.size();
    writer.write_pos = u64::MAX;
    writer.fail_rollback_truncate = true;
    let error = writer
        .append_commit(&commit(1, 1, 1))
        .expect_err("overflowing offset");
    assert!(matches!(error, WalWriteError::FormatViolation { .. }));
    assert_eq!(std::fs::read(&path).unwrap(), prefix);
    writer
        .ensure_ready()
        .expect("preflight error must not attempt rollback or poison");
    writer.write_pos = actual_offset;
    writer.fail_rollback_truncate = false;
    writer
        .append_commit(&commit(1, 2, 1))
        .expect("healthy writer remains usable");
}

#[test]
fn recovery_required_maps_to_io_error_and_is_not_retryable() {
    let error = WalWriteError::RecoveryRequired {
        detail: "uncertain tail".to_owned(),
    };
    assert!(error.is_fatal());
    assert!(!error.is_retryable());
    let error: FfsError = error.into();
    assert!(matches!(error, FfsError::Io(_)));
}
