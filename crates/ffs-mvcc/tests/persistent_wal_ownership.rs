//! Ownership must cover recovery, checkpoint discovery, and the whole store lifetime.
#![forbid(unsafe_code)]

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_mvcc::persist::{PersistOptions, PersistentMvccStore};
use ffs_mvcc::wal::{self, HEADER_SIZE, WalCommit, WalHeader, WalWrite};
use ffs_mvcc::wal_writer::{WalWriter, WalWriterConfig};
use ffs_types::{BlockNumber, CommitSeq, TxnId};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier, RwLock, RwLockReadGuard, mpsc};
use std::time::Duration;

/// A spawned child shares every test thread's open descriptors until it
/// execs, and a flock belongs to the open file description, so a lock a
/// sibling test had just released could still be held by the child (seen in
/// the sibling file wal_writer_ownership.rs on CI). The spawning test holds
/// this exclusively for the spawn (`spawn` returns after the child's exec);
/// every other test holds it shared.
static CHILD_SPAWN_GATE: RwLock<()> = RwLock::new(());

fn flock_holder() -> RwLockReadGuard<'static, ()> {
    CHILD_SPAWN_GATE
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn open_mode(mode: u8, path: &Path, checkpoint: &Path) -> Result<PersistentMvccStore> {
    let cx = Cx::for_testing();
    match mode {
        0 => PersistentMvccStore::open(&cx, path),
        1 => PersistentMvccStore::open_with_options(&cx, path, &PersistOptions::default()),
        2 => PersistentMvccStore::open_with_checkpoint(&cx, path, checkpoint),
        _ => PersistentMvccStore::open_with_checkpoint_and_options(
            &cx,
            path,
            checkpoint,
            &PersistOptions::default(),
        ),
    }
}

fn assert_busy(error: &FfsError) {
    assert!(
        matches!(error, FfsError::Io(source) if source.kind() == std::io::ErrorKind::WouldBlock),
        "expected ownership conflict, got {error}"
    );
}

fn commit_block(store: &PersistentMvccStore, block: u8) -> CommitSeq {
    let mut transaction = store.begin();
    transaction.stage_write(BlockNumber(u64::from(block)), vec![block; 32]);
    store.commit(transaction).expect("durable commit")
}

fn one_commit_wal() -> Vec<u8> {
    let mut bytes = wal::encode_header(&WalHeader::default()).to_vec();
    bytes.extend(
        wal::encode_commit(&WalCommit {
            commit_seq: CommitSeq(1),
            txn_id: TxnId(1),
            writes: vec![WalWrite {
                block: BlockNumber(1),
                data: vec![1; 32],
            }],
        })
        .expect("encoded record"),
    );
    bytes
}

fn probe_released(path: &Path) {
    let file = File::options()
        .read(true)
        .write(true)
        .open(path)
        .expect("probe descriptor");
    file.try_lock().expect("failed admission released its lock");
}

#[test]
fn every_open_entrypoint_keeps_ownership_through_checkpoint_and_truncation() {
    let _flocks = flock_holder();
    for owner_mode in 0..4 {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("state.wal");
        let checkpoint = path.with_extension("ckpt");
        let owner = open_mode(owner_mode, &path, &checkpoint).expect("first owner");
        assert_eq!(commit_block(&owner, 1), CommitSeq(1));
        for phase in 0..3 {
            if phase == 1 {
                owner.checkpoint(&checkpoint).expect("publish checkpoint");
            } else if phase == 2 {
                owner.truncate_wal().expect("truncate owned WAL");
            }
            let before = fs::read(&path).expect("capture WAL");
            for contender_mode in 0..4 {
                assert_busy(
                    &open_mode(contender_mode, &path, &checkpoint)
                        .expect_err("second store must not enter recovery"),
                );
                assert_eq!(fs::read(&path).expect("WAL after conflict"), before);
            }
        }
        drop(owner);
        let recovered = open_mode(0, &path, &checkpoint).expect("next owner");
        assert_eq!(recovered.current_snapshot().high, CommitSeq(1));
        assert!(recovered.recovery_report().used_checkpoint);
        assert_eq!(recovered.recovery_report().commits_replayed, 0);
        assert_eq!(commit_block(&recovered, 2), CommitSeq(2));
    }
}

#[test]
fn standalone_writer_and_persistent_store_exclude_each_other() {
    let _flocks = flock_holder();
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.wal");
    let checkpoint = path.with_extension("ckpt");
    let writer = WalWriter::create(&path, WalWriterConfig::default()).expect("writer owner");
    for mode in 0..4 {
        assert_busy(&open_mode(mode, &path, &checkpoint).expect_err("writer owns the WAL"));
    }
    drop(writer);
    let store = open_mode(0, &path, &checkpoint).expect("store owner");
    commit_block(&store, 1);
    let before = fs::read(&path).expect("capture WAL");
    assert_busy(
        &WalWriter::create(&path, WalWriterConfig::default())
            .expect_err("creation cannot erase the store's WAL"),
    );
    assert_eq!(fs::read(&path).expect("preserved WAL"), before);
    assert_eq!(commit_block(&store, 2), CommitSeq(2));
    drop(store);
    let recovered = open_mode(0, &path, &checkpoint).expect("recover both commits");
    assert_eq!(recovered.current_snapshot().high, CommitSeq(2));
    assert_eq!(recovered.recovery_report().commits_replayed, 2);
}

#[test]
fn inode_aliases_cannot_admit_a_second_store() {
    let _flocks = flock_holder();
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.wal");
    let checkpoint = path.with_extension("ckpt");
    let hardlink = directory.path().join("hardlink.wal");
    let symlink = directory.path().join("symlink.wal");
    let owner = open_mode(0, &path, &checkpoint).expect("owner");
    commit_block(&owner, 1);
    owner.checkpoint(&checkpoint).expect("checkpoint");
    owner.truncate_wal().expect("trim checkpointed prefix");
    fs::hard_link(&path, &hardlink).expect("hard link");
    std::os::unix::fs::symlink(&path, &symlink).expect("symbolic link");
    let before = fs::read(&path).expect("capture WAL");
    for alias in [&hardlink, &symlink] {
        for mode in 0..4 {
            assert_busy(&open_mode(mode, alias, &checkpoint).expect_err("inode already owned"));
            assert_eq!(fs::read(alias).expect("preserved alias"), before);
        }
    }
    drop(owner);
    // An alias must explicitly select the original store's checkpoint path.
    let recovered = open_mode(2, &hardlink, &checkpoint).expect("released inode and checkpoint");
    assert_eq!(recovered.current_snapshot().high, CommitSeq(1));
    assert_eq!(
        recovered.read_visible(BlockNumber(1), recovered.current_snapshot()),
        Some(vec![1; 32])
    );
}

#[test]
fn admission_precedes_checkpoint_errors_and_any_tail_repair() {
    let _flocks = flock_holder();
    for tail in [vec![1, 2, 3], vec![0; 128 * 1024]] {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("state.wal");
        let checkpoint = path.with_extension("ckpt");
        let mut bytes = one_commit_wal();
        let valid = bytes.len();
        bytes.extend(tail);
        fs::write(&path, &bytes).expect("WAL with removable tail");
        let external = File::options()
            .read(true)
            .write(true)
            .open(&path)
            .expect("external owner");
        external.try_lock().expect("lock before contender starts");
        // A symlink loop makes even checkpoint discovery fail, not just loading.
        std::os::unix::fs::symlink(checkpoint.file_name().unwrap(), &checkpoint)
            .expect("invalid checkpoint namespace");
        for mode in 0..4 {
            assert_busy(&open_mode(mode, &path, &checkpoint).expect_err("ownership checked first"));
            assert_eq!(fs::read(&path).expect("unmodified owned WAL"), bytes);
        }
        fs::remove_file(&checkpoint).expect("remove invalid checkpoint link");
        drop(external);
        let recovered = open_mode(0, &path, &checkpoint).expect("recover after ownership release");
        assert_eq!(recovered.current_snapshot().high, CommitSeq(1));
        assert_eq!(fs::read(&path).expect("trimmed WAL"), bytes[..valid]);
        assert_eq!(commit_block(&recovered, 2), CommitSeq(2));
    }
}

#[test]
fn unsuccessful_recovery_releases_ownership_and_preserves_existing_bytes() {
    let _flocks = flock_holder();
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.wal");
    let checkpoint = path.with_extension("ckpt");
    let invalid = b"invalid WAL header";
    fs::write(&path, invalid).expect("bad WAL");
    for mode in 0..4 {
        let error = open_mode(mode, &path, &checkpoint).expect_err("bad header rejected");
        assert!(!matches!(
            error,
            FfsError::Io(ref source) if source.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert_eq!(fs::read(&path).expect("unmodified bad header"), invalid);
        probe_released(&path);
    }
    let bytes = one_commit_wal();
    fs::write(&path, &bytes).expect("valid WAL");
    fs::write(&checkpoint, b"invalid checkpoint").expect("bad checkpoint");
    for mode in [0, 2, 3] {
        open_mode(mode, &path, &checkpoint).expect_err("bad checkpoint rejected");
        assert_eq!(
            fs::read(&path).expect("WAL not changed by failed load"),
            bytes
        );
        probe_released(&path);
    }
    fs::remove_file(&checkpoint).expect("remove bad checkpoint");
    let recovered = open_mode(0, &path, &checkpoint).expect("retry can acquire the inode");
    assert_eq!(recovered.current_snapshot().high, CommitSeq(1));
}

#[test]
fn checkpoint_discovery_errors_are_not_treated_as_absence() {
    let _flocks = flock_holder();
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.wal");
    let checkpoint = path.with_extension("ckpt");
    let bytes = one_commit_wal();
    fs::write(&path, &bytes).expect("WAL");
    std::os::unix::fs::symlink(checkpoint.file_name().unwrap(), &checkpoint)
        .expect("checkpoint symlink loop");
    for mode in [0, 2, 3] {
        let error = open_mode(mode, &path, &checkpoint).expect_err("cannot inspect checkpoint");
        assert!(matches!(error, FfsError::Io(_)));
        assert_eq!(fs::read(&path).expect("unchanged WAL"), bytes);
        probe_released(&path);
    }
    // This entry point deliberately ignores checkpoint files, as before.
    let wal_only = open_mode(1, &path, &checkpoint).expect("explicit WAL-only recovery");
    assert_eq!(wal_only.current_snapshot().high, CommitSeq(1));
    assert!(!wal_only.recovery_report().used_checkpoint);
}

#[test]
fn simultaneous_recovery_admits_exactly_one_owner() {
    let _flocks = flock_holder();
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.wal");
    fs::write(&path, one_commit_wal()).expect("existing WAL");
    let barrier = Arc::new(Barrier::new(8));
    let mut workers = Vec::new();
    for mode in 0..8 {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            open_mode(mode % 4, &path, &path.with_extension("ckpt"))
        }));
    }
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("opener thread"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    for error in results.iter().filter_map(|result| result.as_ref().err()) {
        assert_busy(error);
    }
    let owner = results
        .iter()
        .find_map(|result| result.as_ref().ok())
        .expect("one successful opener");
    assert_eq!(owner.current_snapshot().high, CommitSeq(1));
    assert_eq!(commit_block(owner, 2), CommitSeq(2));
    drop(results);
    let recovered = open_mode(0, &path, &path.with_extension("ckpt")).expect("next owner");
    assert_eq!(recovered.current_snapshot().high, CommitSeq(2));
}

struct ChildOwner(Child);

impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn process_death_releases_ownership_for_checkpoint_plus_wal_recovery() {
    const CHILD_PATH: &str = "FFS_PERSISTENT_WAL_OWNERSHIP_CHILD";
    const READY: &str = "FFS_PERSISTENT_WAL_READY";
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        let path = Path::new(&path);
        let checkpoint = path.with_extension("ckpt");
        let owner = open_mode(0, path, &checkpoint).expect("child owner");
        commit_block(&owner, 1);
        owner.checkpoint(&checkpoint).expect("child checkpoint");
        owner.truncate_wal().expect("child WAL trim");
        commit_block(&owner, 2);
        println!("{READY}");
        std::io::stdout().flush().expect("publish child readiness");
        let mut stop = [0_u8; 1];
        std::io::stdin().read_exact(&mut stop).expect("parent pipe");
        drop(owner);
        return;
    }

    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.wal");
    let checkpoint = path.with_extension("ckpt");
    let spawned = {
        let _no_flock_holders = CHILD_SPAWN_GATE
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "process_death_releases_ownership_for_checkpoint_plus_wal_recovery",
                "--nocapture",
            ])
            .env(CHILD_PATH, &path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("independent process")
    };
    let mut child = ChildOwner(spawned);
    let stdout = child.0.stdout.take().expect("child stdout");
    let (ready, observed) = mpsc::sync_channel(1);
    let readiness_thread = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if line.expect("read child output").contains(READY) {
                let _ = ready.send(());
                return;
            }
        }
    });
    observed
        .recv_timeout(Duration::from_secs(15))
        .expect("child finished checkpoint and durable append");
    let before = fs::read(&path).expect("child WAL");
    let checkpoint_before = fs::read(&checkpoint).expect("child checkpoint");
    assert!(before.len() > HEADER_SIZE);
    for mode in 0..4 {
        assert_busy(&open_mode(mode, &path, &checkpoint).expect_err("child still owns the inode"));
    }
    assert_eq!(fs::read(&path).expect("untouched WAL"), before);
    assert_eq!(
        fs::read(&checkpoint).expect("untouched checkpoint"),
        checkpoint_before
    );
    child
        .0
        .kill()
        .expect("terminate owner without graceful close");
    child.0.wait().expect("reap child");
    readiness_thread.join().expect("readiness observer");

    let recovered =
        open_mode(0, &path, &checkpoint).expect("no stale owner survives process death");
    assert_eq!(recovered.current_snapshot().high, CommitSeq(2));
    assert!(recovered.recovery_report().used_checkpoint);
    assert_eq!(recovered.recovery_report().commits_replayed, 1);
    for block in [1_u8, 2] {
        assert_eq!(
            recovered.read_visible(BlockNumber(u64::from(block)), recovered.current_snapshot()),
            Some(vec![block; 32])
        );
    }
    assert_eq!(commit_block(&recovered, 3), CommitSeq(3));
    drop(recovered);
    let final_store = open_mode(0, &path, &checkpoint).expect("reopen after new owner's commit");
    assert_eq!(final_store.current_snapshot().high, CommitSeq(3));
}
