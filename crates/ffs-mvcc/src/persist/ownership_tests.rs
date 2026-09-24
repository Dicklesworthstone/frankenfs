//! The ownership lease must also cover ambiguous failures and checkpoint publication.
#![forbid(unsafe_code)]

use super::*;

fn assert_busy(error: &FfsError) {
    assert!(
        matches!(error, FfsError::Io(source) if source.kind() == std::io::ErrorKind::WouldBlock),
        "expected ownership conflict, got {error}"
    );
}

#[test]
fn sealed_writer_retains_ownership_until_the_store_is_dropped() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.wal");
    let checkpoint = path.with_extension("ckpt");
    let cx = Cx::for_testing();
    let owner = PersistentMvccStore::open(&cx, &path).expect("owner");
    let mut first = owner.begin();
    first.stage_write(BlockNumber(1), vec![1; 32]);
    owner.commit(first).expect("first durable commit");
    owner.checkpoint(&checkpoint).expect("checkpoint");
    owner.truncate_wal().expect("trim accepted prefix");
    {
        let mut writer = owner.wal.write();
        writer.fail_sync = true;
        writer.fail_rollback_truncate = true;
    }
    let mut uncertain = owner.begin();
    uncertain.stage_write(BlockNumber(2), vec![2; 32]);
    assert!(matches!(
        owner.commit_ssi(uncertain),
        Err(CommitError::DurabilityFailure { .. })
    ));
    assert_eq!(owner.current_snapshot().high, CommitSeq(1));
    let bytes = std::fs::read(&path).expect("uncertain on-disk record");
    owner.wal.read().ensure_ready().expect_err("writer is sealed");
    assert_busy(&PersistentMvccStore::open(&cx, &path).expect_err("sealed owner still owns WAL"));
    assert_busy(
        &WalWriter::create(&path, WalWriterConfig::default())
            .expect_err("cannot erase an unresolved record"),
    );
    assert_eq!(std::fs::read(&path).expect("unchanged WAL"), bytes);
    drop(owner);

    // A complete unacknowledged record may be recovered as committed. Only
    // the new owner may resolve that outcome and continue the sequence.
    let recovered = PersistentMvccStore::open(&cx, &path).expect("recover after owner release");
    assert_eq!(recovered.current_snapshot().high, CommitSeq(2));
    assert_eq!(
        recovered.read_visible(BlockNumber(2), recovered.current_snapshot()),
        Some(vec![2; 32])
    );
    let mut next = recovered.begin();
    next.stage_write(BlockNumber(3), vec![3; 32]);
    assert_eq!(recovered.commit(next).expect("new owner commit"), CommitSeq(3));
}

#[test]
fn checkpoint_publication_never_releases_the_wal_inode() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.wal");
    let checkpoint = path.with_extension("ckpt");
    let cx = Cx::for_testing();
    let owner = PersistentMvccStore::open(&cx, &path).expect("owner");
    let mut transaction = owner.begin();
    transaction.stage_write(BlockNumber(7), vec![7; 32]);
    owner.commit(transaction).expect("commit");
    owner
        .checkpoint_with_directory_sync(&checkpoint, |directory| {
            // The checkpoint is already renamed, but its directory entry has
            // not been synced and the in-memory horizon has not advanced.
            assert_busy(
                &PersistentMvccStore::open(&cx, &path)
                    .expect_err("a new owner cannot observe intermediate publication"),
            );
            assert_busy(
                &WalWriter::create(&path, WalWriterConfig::default())
                    .expect_err("a creator cannot reset the live WAL"),
            );
            assert_eq!(owner.wal_stats().checkpoint_commit_seq, 0);
            directory.sync_all()
        })
        .expect("complete checkpoint publication");
    assert_eq!(owner.wal_stats().checkpoint_commit_seq, 1);
    owner.truncate_wal().expect("truncate without replacing inode");
    assert_busy(&PersistentMvccStore::open(&cx, &path).expect_err("ownership survives truncation"));
    drop(owner);
    let recovered = PersistentMvccStore::open(&cx, &path).expect("checkpoint recovery");
    assert_eq!(recovered.current_snapshot().high, CommitSeq(1));
    assert!(recovered.recovery_report().used_checkpoint);
}
