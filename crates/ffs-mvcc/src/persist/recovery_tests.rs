//! Real-file startup recovery, cancellation, and tail-publication regressions.

use super::*;
use crate::wal::WalWrite;
use ffs_types::TxnId;
use tempfile::tempdir;

fn encoded_record(seq: u64, data: Vec<u8>) -> Vec<u8> {
    wal::encode_commit(&WalCommit {
        commit_seq: CommitSeq(seq),
        txn_id: TxnId(seq),
        writes: vec![WalWrite {
            block: BlockNumber(7),
            data,
        }],
    })
    .expect("encode record")
}

fn open_mode(mode: u8, cx: &Cx, path: &Path, checkpoint: &Path) -> Result<PersistentMvccStore> {
    match mode {
        0 => PersistentMvccStore::open(cx, path),
        1 => PersistentMvccStore::open_with_options(cx, path, &PersistOptions::default()),
        2 => PersistentMvccStore::open_with_checkpoint(cx, path, checkpoint),
        _ => PersistentMvccStore::open_with_checkpoint_and_options(
            cx,
            path,
            checkpoint,
            &PersistOptions::default(),
        ),
    }
}

#[test]
fn cancelled_open_paths_neither_create_nor_repair_files() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.wal");
    let checkpoint = path.with_extension("ckpt");
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    for mode in 0..4 {
        assert!(matches!(
            open_mode(mode, &cx, &path, &checkpoint),
            Err(FfsError::Cancelled)
        ));
        assert!(!path.exists());
        assert!(!checkpoint.exists());
    }

    let mut bytes = wal::encode_header(&WalHeader::default()).to_vec();
    bytes.extend(encoded_record(1, vec![7; 128]));
    bytes.extend([1, 2, 3]);
    std::fs::write(&path, &bytes).unwrap();
    // Cancellation must take precedence over decoding even a bad checkpoint.
    let checkpoint_bytes = b"must not be read by a cancelled open";
    std::fs::write(&checkpoint, checkpoint_bytes).unwrap();
    for mode in 0..4 {
        assert!(matches!(
            open_mode(mode, &cx, &path, &checkpoint),
            Err(FfsError::Cancelled)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(std::fs::read(&checkpoint).unwrap(), checkpoint_bytes);
    }
}

#[test]
fn cancellation_between_replay_and_tail_publication_preserves_the_log() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.wal");
    let mut bytes = wal::encode_header(&WalHeader::default()).to_vec();
    bytes.extend(encoded_record(1, vec![7; 128]));
    let valid = u64::try_from(bytes.len()).unwrap();
    bytes.extend([1, 2, 3]);
    std::fs::write(&path, &bytes).unwrap();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let captured = file.metadata().unwrap().len();
    let cx = Cx::for_testing();
    let mut restored = MvccStore::new();
    let (boundary, report) = replay_wal(&cx, &mut file, &mut restored, captured).unwrap();
    assert_eq!(boundary, valid);
    assert_eq!(report.commits_replayed, 1);
    assert_eq!(report.records_discarded, 1);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    cx.set_cancel_requested(true);
    assert!(matches!(
        truncate_wal_tail_if_needed(&cx, &file, boundary, captured),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn recovery_refuses_changed_length_even_when_no_tail_was_discarded() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.wal");
    let cx = Cx::for_testing();
    for with_tail in [false, true] {
        for grow in [false, true] {
            let mut bytes = wal::encode_header(&WalHeader::default()).to_vec();
            bytes.extend(encoded_record(1, vec![7; 128]));
            if with_tail {
                bytes.extend([1, 2, 3]);
            }
            std::fs::write(&path, &bytes).unwrap();
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            let captured = file.metadata().unwrap().len();
            let mut restored = MvccStore::new();
            let (boundary, _) = replay_wal(&cx, &mut file, &mut restored, captured).unwrap();
            file.set_len(if grow { captured + 1 } else { captured - 1 })
                .unwrap();
            let changed = std::fs::read(&path).unwrap();
            let error = truncate_wal_tail_if_needed(&cx, &file, boundary, captured).unwrap_err();
            assert!(matches!(error, FfsError::Io(_)));
            assert_eq!(std::fs::read(&path).unwrap(), changed);
        }
    }
}

#[test]
fn invalid_recovery_boundaries_cannot_trim_or_extend_the_log() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.wal");
    let mut bytes = wal::encode_header(&WalHeader::default()).to_vec();
    bytes.extend(encoded_record(1, vec![7; 128]));
    std::fs::write(&path, &bytes).unwrap();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let captured = file.metadata().unwrap().len();
    for invalid in [0, HEADER_SIZE as u64 - 1, captured + 1, u64::MAX] {
        assert!(matches!(
            truncate_wal_tail_if_needed(&Cx::for_testing(), &file, invalid, captured),
            Err(FfsError::Format(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn streamed_open_restores_large_records_and_resumes_durable_commits() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.wal");
    let payload = vec![0xB3; 3 * 64 * 1024 + 17];
    let mut bytes = wal::encode_header(&WalHeader::default()).to_vec();
    bytes.extend(encoded_record(1, payload.clone()));
    let valid = u64::try_from(bytes.len()).unwrap();
    let next = encoded_record(2, vec![2; 128]);
    bytes.extend_from_slice(&next[..next.len() - 1]);
    std::fs::write(&path, &bytes).unwrap();
    let cx = Cx::for_testing();
    let store = PersistentMvccStore::open(&cx, &path).unwrap();
    let report = store.recovery_report();
    assert_eq!(report.commits_replayed, 1);
    assert_eq!(report.records_discarded, 1);
    assert_eq!(report.wal_valid_bytes, valid);
    assert_eq!(report.wal_total_bytes, u64::try_from(bytes.len()).unwrap());
    assert_eq!(std::fs::metadata(&path).unwrap().len(), valid);
    assert_eq!(
        store.read_visible(BlockNumber(7), store.current_snapshot()),
        Some(payload.clone())
    );
    let mut transaction = store.begin();
    transaction.stage_write(BlockNumber(8), vec![8; 128]);
    assert_eq!(store.commit(transaction).unwrap(), CommitSeq(2));
    drop(store);
    let reopened = PersistentMvccStore::open(&cx, &path).unwrap();
    assert_eq!(reopened.recovery_report().commits_replayed, 2);
    assert_eq!(reopened.recovery_report().records_discarded, 0);
    let snapshot = reopened.current_snapshot();
    assert_eq!(
        reopened.read_visible(BlockNumber(7), snapshot),
        Some(payload)
    );
    assert_eq!(
        reopened.read_visible(BlockNumber(8), snapshot),
        Some(vec![8; 128])
    );
}

#[test]
fn streamed_open_validates_a_large_sparse_zero_tail() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.wal");
    let mut bytes = wal::encode_header(&WalHeader::default()).to_vec();
    bytes.extend(encoded_record(1, vec![7; 128]));
    std::fs::write(&path, &bytes).unwrap();
    let padded_len = 32 * 1024 * 1024;
    OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(padded_len)
        .unwrap();
    let store = PersistentMvccStore::open(&Cx::for_testing(), &path).unwrap();
    let report = store.recovery_report();
    assert_eq!(report.outcome, ReplayOutcome::Clean);
    assert_eq!(report.commits_replayed, 1);
    assert_eq!(report.wal_total_bytes, padded_len);
    assert_eq!(report.wal_valid_bytes, u64::try_from(bytes.len()).unwrap());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn checkpoint_and_plain_open_share_streamed_recovery_without_duplicate_versions() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.wal");
    let checkpoint = path.with_extension("ckpt");
    let cx = Cx::for_testing();
    let store = PersistentMvccStore::open(&cx, &path).unwrap();
    let mut transaction = store.begin();
    transaction.stage_write(BlockNumber(7), vec![1; 128]);
    store.commit(transaction).unwrap();
    store.checkpoint(&checkpoint).unwrap();
    drop(store);
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    for seq in 2..=6 {
        file.write_all(&encoded_record(seq, vec![u8::try_from(seq).unwrap(); 128]))
            .unwrap();
    }
    file.sync_all().unwrap();
    drop(file);
    for mode in 0..4 {
        let restored = open_mode(mode, &cx, &path, &checkpoint).unwrap();
        let report = restored.recovery_report();
        assert_eq!(report.used_checkpoint, mode != 1);
        assert_eq!(report.commits_replayed, if mode == 1 { 6 } else { 5 });
        assert_eq!(restored.version_count(), 6);
        assert_eq!(restored.current_snapshot().high, CommitSeq(6));
        assert_eq!(
            restored.read_visible(BlockNumber(7), restored.current_snapshot()),
            Some(vec![6; 128])
        );
    }
}
