//! Real-file and subprocess checks for the WAL creation ownership boundary.
#![forbid(unsafe_code)]

use ffs_error::FfsError;
use ffs_mvcc::wal::{HEADER_SIZE, WalCommit, WalWrite};
use ffs_mvcc::wal_replay::{TailPolicy, WalReplayEngine};
use ffs_mvcc::wal_writer::{WalWriter, WalWriterConfig};
use ffs_types::{BlockNumber, CommitSeq, TxnId};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier, mpsc};
use std::time::Duration;

fn commit(sequence: u64) -> WalCommit {
    WalCommit {
        commit_seq: CommitSeq(sequence),
        txn_id: TxnId(sequence),
        writes: vec![WalWrite {
            block: BlockNumber(sequence),
            data: sequence.to_le_bytes().to_vec(),
        }],
    }
}

fn assert_busy(error: &FfsError) {
    assert!(
        matches!(error, FfsError::Io(source) if source.kind() == std::io::ErrorKind::WouldBlock),
        "expected ownership conflict, got {error}"
    );
}

fn replayed_sequences(path: &Path) -> Vec<u64> {
    let bytes = fs::read(path).expect("read actual WAL");
    let mut sequences = Vec::new();
    WalReplayEngine::new(TailPolicy::FailFast)
        .replay(&bytes[HEADER_SIZE..], 0, |record| {
            sequences.push(record.commit_seq.0);
        })
        .expect("strict replay");
    sequences
}

#[test]
fn competing_create_preserves_a_live_wal_and_its_append_position() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.wal");
    let mut owner = WalWriter::create(&path, WalWriterConfig::default()).expect("owner");
    owner.append_commit(&commit(1)).expect("first commit");
    let before = fs::read(&path).expect("capture WAL");
    for _ in 0..3 {
        assert_busy(
            &WalWriter::create(&path, WalWriterConfig::default())
                .expect_err("must acquire ownership before truncation"),
        );
        assert_eq!(fs::read(&path).expect("read after conflict"), before);
    }
    owner
        .append_commit(&commit(2))
        .expect("owner remains usable");
    assert_eq!(replayed_sequences(&path), [1, 2]);
}

#[test]
fn hardlink_and_symlink_names_do_not_bypass_inode_ownership() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.wal");
    let hardlink = directory.path().join("alias.wal");
    let symlink = directory.path().join("symlink.wal");
    let mut owner = WalWriter::create(&path, WalWriterConfig::default()).expect("owner");
    owner.append_commit(&commit(1)).expect("first commit");
    fs::hard_link(&path, &hardlink).expect("hard link");
    std::os::unix::fs::symlink(&path, &symlink).expect("symbolic link");
    let before = fs::read(&path).expect("capture WAL");
    for alias in [&hardlink, &symlink] {
        assert_busy(
            &WalWriter::create(alias, WalWriterConfig::default()).expect_err("inode is owned"),
        );
        assert_eq!(fs::read(alias).expect("read alias"), before);
    }
    drop(owner);
    let replacement = WalWriter::create(&hardlink, WalWriterConfig::default())
        .expect("released inode may be deliberately reinitialized");
    assert_eq!(replacement.size(), HEADER_SIZE as u64);
}

#[test]
fn last_descriptor_not_writer_drop_controls_ownership_release() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.wal");
    let owner = WalWriter::create(&path, WalWriterConfig::default()).expect("owner");
    let retained = owner.file().try_clone().expect("retain locked descriptor");
    drop(owner);
    assert_busy(
        &WalWriter::create(&path, WalWriterConfig::default()).expect_err("clone retains ownership"),
    );
    drop(retained);
    let next = WalWriter::create(&path, WalWriterConfig::default()).expect("new owner");
    assert_eq!(next.size(), HEADER_SIZE as u64);
}

#[test]
fn a_cooperating_external_owner_is_respected_before_any_header_write() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.wal");
    let sentinel = b"not yet initialized by this process";
    fs::write(&path, sentinel).expect("existing contents");
    let external = File::options()
        .read(true)
        .write(true)
        .open(&path)
        .expect("external descriptor");
    external.try_lock().expect("external ownership");
    assert_busy(
        &WalWriter::create(&path, WalWriterConfig::default()).expect_err("external owner wins"),
    );
    assert_eq!(fs::read(&path).expect("untouched file"), sentinel);
    drop(external);
    let writer = WalWriter::create(&path, WalWriterConfig::default()).expect("now unowned");
    assert_eq!(writer.size(), HEADER_SIZE as u64);
}

#[test]
fn concurrent_creators_cannot_both_own_the_same_wal() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.wal");
    let barrier = Arc::new(Barrier::new(8));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            WalWriter::create(&path, WalWriterConfig::default())
        }));
    }
    // Keep successful results alive until every contender has completed.
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("creator thread"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    for error in results.iter().filter_map(|result| result.as_ref().err()) {
        assert_busy(error);
    }
}

struct ChildOwner(Child);

impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn subprocess_owner_blocks_creation_and_process_death_releases_the_inode() {
    const CHILD_PATH: &str = "FFS_WAL_WRITER_OWNERSHIP_CHILD";
    const READY: &str = "FFS_WAL_OWNER_READY";
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        let mut owner = WalWriter::create(Path::new(&path), WalWriterConfig::default())
            .expect("child owns WAL");
        owner
            .append_commit(&commit(1))
            .expect("child durable commit");
        println!("{READY}");
        std::io::stdout().flush().expect("publish readiness");
        let mut stop = [0_u8; 1];
        std::io::stdin().read_exact(&mut stop).expect("parent pipe");
        drop(owner);
        return;
    }

    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.wal");
    let mut child = ChildOwner(
        Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "subprocess_owner_blocks_creation_and_process_death_releases_the_inode",
                "--nocapture",
            ])
            .env(CHILD_PATH, &path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("child process"),
    );
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
        .expect("child must report a locked, durable record");
    let before = fs::read(&path).expect("child WAL");
    assert_busy(
        &WalWriter::create(&path, WalWriterConfig::default()).expect_err("other process owns WAL"),
    );
    assert_eq!(fs::read(&path).expect("read after conflict"), before);
    child.0.kill().expect("simulate owner termination");
    child.0.wait().expect("reap terminated owner");
    readiness_thread.join().expect("readiness observer");

    let file = File::options()
        .read(true)
        .write(true)
        .open(&path)
        .expect("recovery descriptor");
    file.try_lock()
        .expect("no stale process-owned lock remains");
    let size = file.metadata().expect("size").len();
    let mut recovered = WalWriter::new(file, size, WalWriterConfig::default());
    recovered.set_last_commit_seq(1);
    recovered
        .append_commit(&commit(2))
        .expect("next durable commit");
    assert_eq!(replayed_sequences(&path), [1, 2]);
}
