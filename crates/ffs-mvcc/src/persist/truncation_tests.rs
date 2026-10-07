//! Checkpoint truncation against real WAL files. Sync faults are injected after
//! the real set_len call; these are durability-boundary tests, not power cuts.

use super::*;
use crate::wal_writer::WalWriteError;
use ffs_types::TxnId;
use tempfile::tempdir;

fn record(seq: u64) -> WalCommit {
    WalCommit {
        commit_seq: CommitSeq(seq),
        txn_id: TxnId(seq),
        writes: vec![wal::WalWrite {
            block: BlockNumber(7),
            data: vec![0xA5; 128],
        }],
    }
}

fn assert_store_sealed(store: &PersistentMvccStore, wal_path: &Path, unused_checkpoint: &Path) {
    let bytes = std::fs::read(wal_path).unwrap();
    let snapshot = store.current_snapshot();
    let versions = store.version_count();
    let stats = store.wal_stats();
    {
        let mut writer = store.wal.write();
        writer.fail_rollback_sync = false;
        writer.fail_rollback_truncate = false;
        assert!(matches!(
            writer.ensure_ready(),
            Err(WalWriteError::RecoveryRequired { .. })
        ));
        assert!(matches!(
            writer.append_commits_coalesced(&[]),
            Err(WalWriteError::RecoveryRequired { .. })
        ));
    }
    for use_ssi in [false, true] {
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(99), vec![99; 8]);
        let result = if use_ssi {
            store.commit_ssi(txn)
        } else {
            store.commit(txn)
        };
        assert!(matches!(result, Err(CommitError::DurabilityFailure { .. })));
    }
    for error in [
        store.sync().expect_err("sealed sync"),
        store.truncate_wal().expect_err("sealed maintenance retry"),
        store
            .checkpoint(unused_checkpoint)
            .expect_err("sealed publication"),
    ] {
        assert!(matches!(&error, FfsError::Io(_)));
        assert!(error.to_string().contains("recovery required"));
    }
    assert!(!unused_checkpoint.exists());
    assert_eq!(store.current_snapshot().high, snapshot.high);
    assert_eq!(store.version_count(), versions);
    assert_eq!(store.read_visible(BlockNumber(99), snapshot), None);
    assert_eq!(store.wal_stats().wal_size_bytes, stats.wal_size_bytes);
    assert_eq!(store.wal_stats().commits_written, stats.commits_written);
    assert_eq!(
        store.wal_stats().checkpoints_created,
        stats.checkpoints_created
    );
    assert_eq!(std::fs::read(wal_path).unwrap(), bytes);
    assert!(matches!(
        PersistentMvccStore::open(&Cx::for_testing(), wal_path),
        Err(FfsError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}

#[test]
fn checkpoint_truncation_sync_failure_seals_even_without_pending_appends() {
    let cx = Cx::for_testing();
    for sync_on_commit in [true, false] {
        let directory = tempdir().unwrap();
        let wal_path = directory.path().join("state.wal");
        let checkpoint_path = directory.path().join("state.ckpt");
        let store = PersistentMvccStore::open_with_checkpoint_and_options(
            &cx,
            &wal_path,
            &checkpoint_path,
            &PersistOptions {
                sync_on_commit,
                ..PersistOptions::default()
            },
        )
        .unwrap();
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(7), vec![0xA5; 128]);
        store.commit(txn).unwrap();
        store.checkpoint(&checkpoint_path).unwrap();
        let prefix = std::fs::read(&wal_path).unwrap();
        let checkpoint = std::fs::read(&checkpoint_path).unwrap();
        let previous_size = store.wal_stats().wal_size_bytes;
        let pending = u32::from(!sync_on_commit);
        assert_eq!(store.wal.read().pending_sync_count(), pending);
        store.wal.write().fail_rollback_sync = true;

        let error = store.truncate_wal().expect_err("post-truncate sync fails");
        assert!(
            error
                .to_string()
                .contains("checkpoint WAL truncation failed")
        );
        // set_len succeeded, but neither the cursor nor zero-pending fast path
        // may pretend the new append frontier is durably established.
        assert_eq!(std::fs::read(&wal_path).unwrap(), prefix[..HEADER_SIZE]);
        assert_eq!(store.wal.read().size(), previous_size);
        assert_eq!(store.wal.read().last_commit_seq(), 1);
        assert_eq!(store.wal.read().pending_sync_count(), pending);
        assert_store_sealed(&store, &wal_path, &directory.path().join("unused.ckpt"));
        assert_eq!(std::fs::read(&checkpoint_path).unwrap(), checkpoint);
        drop(store);

        let recovered = PersistentMvccStore::open(&cx, &wal_path).unwrap();
        let snapshot = recovered.current_snapshot();
        assert_eq!(snapshot.high, CommitSeq(1));
        assert_eq!(
            recovered.read_visible(BlockNumber(7), snapshot),
            Some(vec![0xA5; 128])
        );
        assert!(recovered.recovery_report().used_checkpoint);
        let mut txn = recovered.begin();
        txn.stage_write(BlockNumber(8), vec![8; 16]);
        assert_eq!(recovered.commit(txn).unwrap(), CommitSeq(2));
        drop(recovered);

        let reopened = PersistentMvccStore::open(&cx, &wal_path).unwrap();
        let snapshot = reopened.current_snapshot();
        assert_eq!(snapshot.high, CommitSeq(2));
        assert_eq!(
            reopened.read_visible(BlockNumber(7), snapshot),
            Some(vec![0xA5; 128])
        );
        assert_eq!(
            reopened.read_visible(BlockNumber(8), snapshot),
            Some(vec![8; 16])
        );
    }
}

#[test]
fn checkpoint_truncation_set_len_error_seals_without_modifying_storage() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("readonly.wal");
    let mut writer = WalWriter::create(&path, WalWriterConfig::default()).unwrap();
    writer.append_commit(&record(1)).unwrap();
    let previous_size = writer.size();
    let prefix = std::fs::read(&path).unwrap();
    drop(writer);

    // A real read-only descriptor makes set_len fail even for a privileged
    // test process. Acquire the same exclusive inode ownership as production.
    let file = File::open(&path).unwrap();
    file.try_lock().unwrap();
    let mut writer = WalWriter::new(file, previous_size, WalWriterConfig::default());
    writer.set_last_commit_seq(1);
    let error = writer
        .truncate_after_checkpoint(1)
        .expect_err("read-only truncate");
    assert!(matches!(error, WalWriteError::RecoveryRequired { .. }));
    assert_eq!(std::fs::read(&path).unwrap(), prefix);
    assert_eq!(writer.size(), previous_size);
    assert_eq!(writer.last_commit_seq(), 1);
    assert!(matches!(
        writer.flush(),
        Err(WalWriteError::RecoveryRequired { .. })
    ));
    assert!(matches!(
        writer.append_commit(&record(2)),
        Err(WalWriteError::RecoveryRequired { .. })
    ));
}

#[test]
fn checkpoint_truncation_success_preserves_header_inode_and_file_cursor() {
    let cx = Cx::for_testing();
    for sync_on_commit in [true, false] {
        let directory = tempdir().unwrap();
        let wal_path = directory.path().join("state.wal");
        let checkpoint_path = directory.path().join("state.ckpt");
        let store = PersistentMvccStore::open_with_checkpoint_and_options(
            &cx,
            &wal_path,
            &checkpoint_path,
            &PersistOptions {
                sync_on_commit,
                ..PersistOptions::default()
            },
        )
        .unwrap();
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(7), vec![7; 16]);
        store.commit(txn).unwrap();
        store.checkpoint(&checkpoint_path).unwrap();
        let before = std::fs::metadata(&wal_path).unwrap();
        let prefix = std::fs::read(&wal_path).unwrap();
        store
            .wal
            .write()
            .file_mut()
            .seek(SeekFrom::Start(3))
            .unwrap();
        store.truncate_wal().unwrap();
        let after = std::fs::metadata(&wal_path).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(std::fs::read(&wal_path).unwrap(), prefix[..HEADER_SIZE]);
        assert_eq!(store.wal_stats().wal_size_bytes, HEADER_SIZE as u64);
        {
            let mut writer = store.wal.write();
            assert_eq!(writer.size(), HEADER_SIZE as u64);
            assert_eq!(writer.last_commit_seq(), 1);
            assert_eq!(writer.pending_sync_count(), 0);
            assert_eq!(writer.file_mut().stream_position().unwrap(), 3);
        }
        assert!(matches!(
            PersistentMvccStore::open(&cx, &wal_path),
            Err(FfsError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(8), vec![8; 16]);
        assert_eq!(store.commit(txn).unwrap(), CommitSeq(2));
        store.sync().unwrap();
        drop(store);

        let reopened = PersistentMvccStore::open(&cx, &wal_path).unwrap();
        let snapshot = reopened.current_snapshot();
        assert_eq!(snapshot.high, CommitSeq(2));
        assert_eq!(
            reopened.read_visible(BlockNumber(7), snapshot),
            Some(vec![7; 16])
        );
        assert_eq!(
            reopened.read_visible(BlockNumber(8), snapshot),
            Some(vec![8; 16])
        );
    }
}

#[test]
fn checkpoint_truncation_rejects_stale_and_sentinel_horizons_before_io() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("horizon.wal");
    let mut writer = WalWriter::create(&path, WalWriterConfig::default()).unwrap();
    writer.append_commit(&record(2)).unwrap();
    let prefix = std::fs::read(&path).unwrap();
    let previous_size = writer.size();
    for horizon in [0, 1, u64::MAX] {
        assert!(matches!(
            writer.truncate_after_checkpoint(horizon),
            Err(WalWriteError::FormatViolation { .. })
        ));
        writer.ensure_ready().unwrap();
        assert_eq!(writer.size(), previous_size);
        assert_eq!(writer.last_commit_seq(), 2);
        assert_eq!(std::fs::read(&path).unwrap(), prefix);
    }
    writer.append_commit(&record(3)).unwrap();
}

#[test]
fn checkpoint_truncation_rejects_unexpected_file_length_without_further_io() {
    for short_length in [Some(0), Some(HEADER_SIZE as u64 - 1), None] {
        let directory = tempdir().unwrap();
        let path = directory.path().join("changed.wal");
        let mut writer = WalWriter::create(&path, WalWriterConfig::default()).unwrap();
        writer.append_commit(&record(1)).unwrap();
        let previous_size = writer.size();
        let changed_size = short_length.unwrap_or(previous_size + 1);
        writer.file().set_len(changed_size).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let error = writer
            .truncate_after_checkpoint(1)
            .expect_err("changed WAL length");
        assert!(matches!(error, WalWriteError::RecoveryRequired { .. }));
        assert_eq!(writer.size(), previous_size);
        assert_eq!(writer.last_commit_seq(), 1);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), changed_size);
    }
}

#[test]
fn checkpoint_truncation_every_n_has_a_mandatory_sync_barrier() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("batched.wal");
    let mut writer = WalWriter::create(
        &path,
        WalWriterConfig {
            sync_policy: SyncPolicy::EveryN(3),
            ..WalWriterConfig::default()
        },
    )
    .unwrap();
    writer.append_commit(&record(1)).unwrap();
    let previous_size = writer.size();
    assert_eq!(writer.pending_sync_count(), 1);
    writer.fail_rollback_sync = true;
    assert!(matches!(
        writer.truncate_after_checkpoint(1),
        Err(WalWriteError::RecoveryRequired { .. })
    ));
    assert_eq!(std::fs::metadata(&path).unwrap().len(), HEADER_SIZE as u64);
    assert_eq!(writer.size(), previous_size);
    assert_eq!(writer.last_commit_seq(), 1);
    assert_eq!(writer.pending_sync_count(), 1);
    writer.fail_rollback_sync = false;
    assert!(matches!(
        writer.truncate_after_checkpoint(1),
        Err(WalWriteError::RecoveryRequired { .. })
    ));
}
