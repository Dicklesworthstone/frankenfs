//! Checkpoint/WAL handoff regressions using the real persistence and replay paths.
//! Directory-sync injection observes the real post-rename boundary; it is not
//! evidence of a power-loss test or a mounted filesystem certification.

use super::*;
use crate::compression::VersionData;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::{TempDir, tempdir};

fn fixture() -> (TempDir, PathBuf, PathBuf, PersistentMvccStore) {
    let directory = tempdir().expect("temporary store directory");
    let wal = directory.path().join("state.wal");
    let checkpoint = directory.path().join("state.ckpt");
    let store = PersistentMvccStore::open(&Cx::for_testing(), &wal).expect("open store");
    (directory, wal, checkpoint, store)
}

fn commit_block(store: &PersistentMvccStore, block: u64, byte: u8) -> CommitSeq {
    let mut transaction = store.begin();
    transaction.stage_write(BlockNumber(block), vec![byte; 128]);
    store.commit(transaction).expect("commit block")
}

fn assert_recovery_required(error: &FfsError) {
    assert!(matches!(error, FfsError::Io(_)));
    assert!(error.to_string().contains("recovery required"));
}

#[test]
fn checkpoint_directory_sync_precedes_horizon_and_holds_both_guards() {
    let (_directory, _wal, checkpoint, store) = fixture();
    commit_block(&store, 7, 7);
    store
        .checkpoint_with_directory_sync(&checkpoint, |directory| {
            // The real file has been encoded, fsynced and renamed, but the
            // checkpoint must not yet authorize truncating its source WAL.
            let mut loaded = MvccStore::new();
            load_checkpoint(&checkpoint, &mut loaded).expect("published checkpoint decodes");
            assert_eq!(loaded.current_snapshot().high, CommitSeq(1));
            assert_eq!(store.wal_stats().checkpoint_commit_seq, 0);
            assert_eq!(store.wal_stats().checkpoints_created, 0);
            assert!(
                store.store.try_write().is_none(),
                "snapshot must stay pinned"
            );
            assert!(
                store.wal.try_write().is_none(),
                "WAL health must stay pinned"
            );
            directory.sync_all()
        })
        .expect("durable checkpoint");
    assert_eq!(store.wal_stats().checkpoint_commit_seq, 1);
    assert_eq!(store.wal_stats().checkpoints_created, 1);
}

#[test]
fn failed_directory_sync_cannot_advance_the_checkpoint_horizon() {
    let (_directory, wal, checkpoint, store) = fixture();
    commit_block(&store, 1, 1);
    store
        .checkpoint(&checkpoint)
        .expect("first durable checkpoint");
    commit_block(&store, 2, 2);
    let before = std::fs::read(&wal).expect("capture WAL");

    let error = store
        .checkpoint_with_directory_sync(&checkpoint, |_| {
            Err(std::io::Error::other("injected directory sync failure"))
        })
        .expect_err("rename without directory durability is not a completed checkpoint");
    assert!(matches!(error, FfsError::Io(_)));
    assert_eq!(store.wal_stats().checkpoint_commit_seq, 1);
    assert_eq!(store.wal_stats().checkpoints_created, 1);
    store
        .truncate_wal()
        .expect_err("old checkpoint cannot cover commit two");
    assert_eq!(std::fs::read(&wal).unwrap(), before);

    // A fresh, fully durable checkpoint can safely replace the failed attempt.
    store
        .checkpoint(&checkpoint)
        .expect("retry complete publication");
    store.truncate_wal().expect("now the WAL can be discarded");
    assert_eq!(store.wal_stats().wal_size_bytes, HEADER_SIZE as u64);
    drop(store);
    let reopened = PersistentMvccStore::open(&Cx::for_testing(), &wal).expect("reopen");
    let snapshot = reopened.current_snapshot();
    assert_eq!(snapshot.high, CommitSeq(2));
    for block in [1_u8, 2] {
        assert_eq!(
            reopened.read_visible(BlockNumber(u64::from(block)), snapshot),
            Some(vec![block; 128])
        );
    }
}

#[test]
fn failed_wal_rollback_blocks_checkpoint_truncate_and_future_commits() {
    let (_directory, wal, checkpoint, store) = fixture();
    commit_block(&store, 1, 1);
    store.checkpoint(&checkpoint).expect("accepted checkpoint");
    store.truncate_wal().expect("trim accepted prefix");
    let old_checkpoint = std::fs::read(&checkpoint).unwrap();
    {
        let mut writer = store.wal.write();
        writer.fail_sync = true;
        writer.fail_rollback_truncate = true;
    }
    let mut uncertain = store.begin();
    uncertain.stage_write(BlockNumber(2), vec![2; 128]);
    store
        .commit_ssi(uncertain)
        .expect_err("unacknowledged record remains on disk");
    assert_eq!(store.current_snapshot().high, CommitSeq(1));
    assert_eq!(store.wal_stats().checkpoint_commit_seq, 1);
    let uncertain_wal = std::fs::read(&wal).unwrap();
    {
        let mut writer = store.wal.write();
        writer.fail_sync = false;
        writer.fail_rollback_truncate = false;
    }

    assert_recovery_required(
        &store
            .checkpoint(&checkpoint)
            .expect_err("checkpoint blocked"),
    );
    assert_recovery_required(
        &store
            .truncate_wal()
            .expect_err("matching old horizon is insufficient"),
    );
    assert_recovery_required(
        &store
            .sync()
            .expect_err("empty pending counter must not bypass seal"),
    );
    let mut later = store.begin();
    later.stage_write(BlockNumber(3), vec![3; 128]);
    assert!(matches!(
        store.commit(later),
        Err(CommitError::DurabilityFailure { .. })
    ));
    assert_eq!(store.current_snapshot().high, CommitSeq(1));
    assert_eq!(store.version_count(), 1);
    assert_eq!(std::fs::read(&wal).unwrap(), uncertain_wal);
    assert_eq!(std::fs::read(&checkpoint).unwrap(), old_checkpoint);
    drop(store);

    // Recovery, not the stale in-memory counter, resolves the uncertain outcome.
    let reopened = PersistentMvccStore::open(&Cx::for_testing(), &wal).expect("recover WAL");
    let snapshot = reopened.current_snapshot();
    assert_eq!(snapshot.high, CommitSeq(2));
    assert_eq!(
        reopened.read_visible(BlockNumber(1), snapshot),
        Some(vec![1; 128])
    );
    assert_eq!(
        reopened.read_visible(BlockNumber(2), snapshot),
        Some(vec![2; 128])
    );
    assert_eq!(reopened.read_visible(BlockNumber(3), snapshot), None);
}

#[test]
fn failed_manual_flush_cannot_be_bypassed_with_a_checkpoint() {
    let directory = tempdir().unwrap();
    let wal = directory.path().join("state.wal");
    let checkpoint = directory.path().join("state.ckpt");
    let store = PersistentMvccStore::open_with_options(
        &Cx::for_testing(),
        &wal,
        &PersistOptions {
            sync_on_commit: false,
            ..PersistOptions::default()
        },
    )
    .expect("manual durability store");
    commit_block(&store, 1, 1);
    store.wal.write().fail_sync = true;
    store.sync().expect_err("injected flush error");
    let bytes = std::fs::read(&wal).unwrap();
    assert_recovery_required(
        &store
            .checkpoint(&checkpoint)
            .expect_err("checkpoint blocked"),
    );
    assert_recovery_required(&store.truncate_wal().expect_err("truncate blocked"));
    assert!(!checkpoint.exists());
    assert_eq!(store.wal_stats().checkpoints_created, 0);
    assert_eq!(std::fs::read(&wal).unwrap(), bytes);
}

#[test]
fn checkpoint_rejects_live_wal_path_and_inode_aliases_without_mutation() {
    let (directory, wal, _checkpoint, store) = fixture();
    commit_block(&store, 1, 1);
    let bytes = std::fs::read(&wal).unwrap();
    let hardlink = directory.path().join("hardlink.ckpt");
    let symlink = directory.path().join("symlink.ckpt");
    std::fs::hard_link(&wal, &hardlink).expect("hard link to WAL");
    std::os::unix::fs::symlink(&wal, &symlink).expect("symlink to WAL");
    for path in [&wal, &hardlink, &symlink] {
        let error = store
            .checkpoint(path)
            .expect_err("WAL alias cannot be a checkpoint");
        assert!(matches!(error, FfsError::Format(_)));
        assert!(error.to_string().contains("aliases the active WAL"));
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
    assert_eq!(store.wal_stats().checkpoints_created, 0);
    commit_block(&store, 2, 2);
    drop(store);
    let reopened =
        PersistentMvccStore::open(&Cx::for_testing(), &wal).expect("original WAL intact");
    assert_eq!(reopened.current_snapshot().high, CommitSeq(2));
}

#[test]
fn checkpoint_never_uses_the_live_wal_as_its_temporary_sibling() {
    let directory = tempdir().unwrap();
    let wal = directory.path().join("state.tmp");
    let checkpoint = directory.path().join("state.ckpt");
    let store =
        PersistentMvccStore::open(&Cx::for_testing(), &wal).expect("WAL with tmp extension");
    commit_block(&store, 1, 1);
    let bytes = std::fs::read(&wal).unwrap();
    store
        .checkpoint(&checkpoint)
        .expect("checkpoint must allocate its own temporary file");
    assert_eq!(std::fs::read(&wal).unwrap(), bytes);
    commit_block(&store, 2, 2);
    drop(store);
    let reopened =
        PersistentMvccStore::open(&Cx::for_testing(), &wal).expect("checkpoint plus WAL");
    assert_eq!(reopened.current_snapshot().high, CommitSeq(2));
    assert_eq!(reopened.wal_stats().replayed_commits, 1);
}

#[test]
fn checkpoint_preserves_an_unrelated_tmp_sibling() {
    let (_directory, _wal, checkpoint, store) = fixture();
    let unrelated = checkpoint.with_extension("tmp");
    let sentinel = b"this file is not a checkpoint scratch file";
    std::fs::write(&unrelated, sentinel).unwrap();
    commit_block(&store, 1, 1);
    store.checkpoint(&checkpoint).expect("checkpoint");
    assert_eq!(std::fs::read(&unrelated).unwrap(), sentinel);
    let mut loaded = MvccStore::new();
    load_checkpoint(&checkpoint, &mut loaded).expect("valid checkpoint");
    assert_eq!(loaded.current_snapshot().high, CommitSeq(1));
}

#[test]
fn bare_checkpoint_filename_uses_and_syncs_the_current_directory() {
    let (_directory, _wal, _checkpoint, store) = fixture();
    let target = tempfile::NamedTempFile::new_in(".").expect("unique local filename");
    let basename = Path::new(target.path().file_name().unwrap());
    assert!(basename.parent().unwrap().as_os_str().is_empty());
    commit_block(&store, 1, 1);
    store
        .checkpoint_with_directory_sync(basename, |directory| {
            let expected = File::open(".")?.metadata()?;
            let actual = directory.metadata()?;
            assert_eq!(
                (actual.dev(), actual.ino()),
                (expected.dev(), expected.ino())
            );
            directory.sync_all()
        })
        .expect("bare filename must not silently skip directory sync");
    let mut loaded = MvccStore::new();
    load_checkpoint(basename, &mut loaded).expect("read back local checkpoint");
    assert_eq!(loaded.current_snapshot().high, CommitSeq(1));
    assert_eq!(store.wal_stats().checkpoints_created, 1);
}

#[test]
fn concurrent_checkpoint_publication_keeps_a_valid_complete_snapshot() {
    let (_directory, wal, checkpoint, store) = fixture();
    commit_block(&store, 1, 1);
    let store = Arc::new(store);
    let mut workers = Vec::new();
    for _ in 0..4 {
        let store = Arc::clone(&store);
        let path = checkpoint.clone();
        workers.push(std::thread::spawn(move || {
            for _ in 0..8 {
                store
                    .checkpoint(&path)
                    .expect("independent temporary checkpoint file");
            }
        }));
    }
    for worker in workers {
        worker.join().expect("checkpoint worker");
    }
    assert_eq!(store.wal_stats().checkpoints_created, 32);
    store.truncate_wal().expect("durable published checkpoint");
    drop(store);
    let reopened = PersistentMvccStore::open(&Cx::for_testing(), &wal).expect("reopen checkpoint");
    assert_eq!(reopened.current_snapshot().high, CommitSeq(1));
    assert_eq!(
        reopened.read_visible(BlockNumber(1), reopened.current_snapshot()),
        Some(vec![1; 128])
    );
}

fn checkpoint_version(seq: u64, data: VersionData) -> BlockVersion {
    BlockVersion {
        block: BlockNumber(7),
        commit_seq: CommitSeq(seq),
        writer: ffs_types::TxnId(seq),
        data,
    }
}

#[test]
fn corrupt_history_cannot_replace_a_checkpoint_or_authorize_wal_truncation() {
    for invalid in [
        VersionData::Zstd(vec![0xFF, 0, 0x12, 0x34, 0x56, 0x78]),
        VersionData::Brotli(vec![0xFF; 8]),
        VersionData::Identical,
    ] {
        let (_directory, wal, checkpoint, store) = fixture();
        commit_block(&store, 7, 7);
        store.checkpoint(&checkpoint).expect("valid checkpoint");
        commit_block(&store, 7, 8);
        let old_checkpoint = std::fs::read(&checkpoint).unwrap();
        let old_wal = std::fs::read(&wal).unwrap();
        // Keep the latest version valid: an unreadable historical version is
        // still part of the checkpoint and must not be silently replaced.
        {
            let mut guard = store.store.write();
            guard.versions.get_mut(&BlockNumber(7)).unwrap()[0].data = invalid;
        }
        let mut reached_publication = false;
        let error = store
            .checkpoint_with_directory_sync(&checkpoint, |_| {
                reached_publication = true;
                Ok(())
            })
            .expect_err("invalid data must fail before publication");
        assert!(matches!(error, FfsError::Corruption { block: 7, .. }));
        assert!(!reached_publication);
        assert_eq!(store.wal_stats().checkpoints_created, 1);
        assert_eq!(store.wal_stats().checkpoint_commit_seq, 1);
        store.truncate_wal().expect_err("checkpoint is still stale");
        assert_eq!(std::fs::read(&checkpoint).unwrap(), old_checkpoint);
        assert_eq!(std::fs::read(&wal).unwrap(), old_wal);
        drop(store);

        let restored = PersistentMvccStore::open(&Cx::for_testing(), &wal).unwrap();
        let mut snapshot = restored.current_snapshot();
        assert_eq!(snapshot.high, CommitSeq(2));
        assert_eq!(
            restored.read_visible(BlockNumber(7), snapshot),
            Some(vec![8; 128])
        );
        snapshot.high = CommitSeq(1);
        assert_eq!(
            restored.read_visible(BlockNumber(7), snapshot),
            Some(vec![7; 128])
        );
    }
}

#[test]
fn checkpoint_stream_roundtrips_compression_dedup_and_genuinely_empty_versions() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("mixed.ckpt");
    let payload = vec![0x5A; 512];
    let compressed = zstd::encode_all(payload.as_slice(), 1).unwrap();
    let mut brotli = Vec::new();
    brotli::CompressorReader::new(payload.as_slice(), 4096, 4, 22)
        .read_to_end(&mut brotli)
        .unwrap();
    let chain = vec![
        checkpoint_version(1, VersionData::full(payload.clone())),
        checkpoint_version(2, VersionData::Identical),
        checkpoint_version(3, VersionData::full(Vec::new())),
        checkpoint_version(4, VersionData::Identical),
        checkpoint_version(5, VersionData::Zstd(compressed)),
        checkpoint_version(6, VersionData::Brotli(brotli)),
    ];
    let mut bytes = Vec::new();
    write_checkpoint(&mut bytes, 7, 7, &[(BlockNumber(7), &chain)]).unwrap();
    std::fs::write(&path, bytes).unwrap();
    let mut restored = MvccStore::new();
    load_checkpoint(&path, &mut restored).unwrap();
    assert_eq!(restored.version_count(), 6);
    assert_eq!(restored.next_txn, 7);
    assert_eq!(restored.current_snapshot().high, CommitSeq(6));
    for seq in 1..=6 {
        let mut snapshot = restored.current_snapshot();
        snapshot.high = CommitSeq(seq);
        let expected = if (3..=4).contains(&seq) {
            &[][..]
        } else {
            &payload[..]
        };
        assert_eq!(
            restored.read_visible(BlockNumber(7), snapshot).as_deref(),
            Some(expected)
        );
    }
}

struct ShortCheckpointSink {
    bytes: Vec<u8>,
    fail_at: usize,
}

impl Write for ShortCheckpointSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        assert!(bytes.len() <= CHECKPOINT_IO_CHUNK_BYTES);
        if self.bytes.len() >= self.fail_at {
            return Err(std::io::Error::other("injected checkpoint write failure"));
        }
        let count = bytes.len().min(17).min(self.fail_at - self.bytes.len());
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn checkpoint_stream_bounds_write_requests_and_handles_short_writes() {
    let payload = vec![0xA7; 3 * CHECKPOINT_IO_CHUNK_BYTES + 17];
    let chain = vec![checkpoint_version(1, VersionData::full(payload.clone()))];
    let mut sink = ShortCheckpointSink {
        bytes: Vec::new(),
        fail_at: usize::MAX,
    };
    write_checkpoint(&mut sink, 2, 2, &[(BlockNumber(7), &chain)]).unwrap();
    let crc_offset = sink.bytes.len() - 4;
    let stored_crc = u32::from_le_bytes(sink.bytes[crc_offset..].try_into().unwrap());
    assert_eq!(stored_crc, crc32c::crc32c(&sink.bytes[..crc_offset]));
    let directory = tempdir().unwrap();
    let path = directory.path().join("large.ckpt");
    std::fs::write(&path, sink.bytes).unwrap();
    let mut restored = MvccStore::new();
    load_checkpoint(&path, &mut restored).unwrap();
    assert_eq!(
        restored
            .read_visible(BlockNumber(7), restored.current_snapshot())
            .as_deref(),
        Some(payload.as_slice())
    );
}

#[test]
fn checkpoint_stream_propagates_write_failure_at_every_byte_boundary() {
    let chain = vec![
        checkpoint_version(1, VersionData::full(vec![0xA7; 31])),
        checkpoint_version(2, VersionData::Identical),
    ];
    let versions = [(BlockNumber(7), chain.as_slice())];
    let mut expected = Vec::new();
    write_checkpoint(&mut expected, 3, 3, &versions).unwrap();
    for fail_at in 0..expected.len() {
        let mut sink = ShortCheckpointSink {
            bytes: Vec::new(),
            fail_at,
        };
        let error = write_checkpoint(&mut sink, 3, 3, &versions).unwrap_err();
        assert!(matches!(error, FfsError::Io(_)));
        assert_eq!(sink.bytes, expected[..fail_at]);
    }
}

#[test]
fn checkpoint_writer_refuses_invalid_identity_order_and_counter_horizons() {
    let valid = checkpoint_version(1, VersionData::full(vec![7]));
    let mut wrong_block = valid.clone();
    wrong_block.block = BlockNumber(8);
    let mut wrong_writer = valid.clone();
    wrong_writer.writer = ffs_types::TxnId(3);
    for (next_txn, next_commit, chain) in [
        (0, 3, vec![valid.clone()]),
        (3, 0, vec![valid.clone()]),
        (3, 1, vec![valid.clone()]),
        (1, 3, vec![valid.clone()]),
        (3, 3, vec![wrong_block]),
        (3, 3, vec![wrong_writer]),
        (3, 3, vec![valid.clone(), valid.clone()]),
        (3, 3, vec![checkpoint_version(0, VersionData::full(vec![7]))]),
        (3, 3, vec![checkpoint_version(1, VersionData::Identical)]),
        (3, 3, Vec::new()),
    ] {
        let error = write_checkpoint(
            &mut Vec::new(),
            next_txn,
            next_commit,
            &[(BlockNumber(7), &chain)],
        )
        .unwrap_err();
        assert!(matches!(error, FfsError::Corruption { .. }));
    }
    let chain = [valid];
    let duplicate = [(BlockNumber(7), chain.as_slice()); 2];
    assert!(write_checkpoint(&mut Vec::new(), 3, 3, &duplicate).is_err());
}

#[test]
fn checkpoint_publication_borrows_pinned_version_data_instead_of_cloning_it() {
    let (_directory, _wal, checkpoint, store) = fixture();
    commit_block(&store, 7, 7);
    let bytes = {
        let guard = store.store.read();
        let VersionData::Full(bytes) = &guard.versions[&BlockNumber(7)][0].data else {
            panic!("default policy stores full data");
        };
        Arc::clone(bytes)
    };
    let owners_before = Arc::strong_count(&bytes);
    store
        .checkpoint_with_directory_sync(&checkpoint, |directory| {
            assert_eq!(Arc::strong_count(&bytes), owners_before);
            directory.sync_all()
        })
        .unwrap();
}
