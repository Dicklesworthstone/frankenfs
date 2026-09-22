//! Serialized, durable updates to the repair coordination record.
//!
//! Lock a separate, stable inode: locking the JSON file itself would lose
//! exclusion when publication replaces it with rename. The `.lock` file is
//! intentionally never removed, including when the ownership record is released.
//! These advisory locks require all writers to cooperate and a filesystem that
//! supports them; they are not a fencing mechanism for expired repair workers.

use super::{CoordinationRecord, cx_checkpoint, temp_record_path};
use asupersync::Cx;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// A bounded, exclusive read/compare/write transaction on one record.
/// Closing the file releases the lock, including on errors and cancellation.
#[derive(Debug)]
pub(super) struct RecordTransaction {
    record_path: PathBuf,
    _lock: File,
}

impl RecordTransaction {
    pub(super) fn begin(cx: &Cx, record_path: &Path) -> io::Result<Self> {
        cx_checkpoint(cx, "open ownership transaction lock")?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path(record_path))?;
        // Never wait indefinitely behind another process or hide cancellation
        // inside a blocking lock call. Unsupported locking is an error, too.
        lock.try_lock()?;
        cx_checkpoint(cx, "acquire ownership transaction lock")?;
        Ok(Self {
            record_path: record_path.to_owned(),
            _lock: lock,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.record_path
    }

    pub(super) fn publish(&self, cx: &Cx, record: &CoordinationRecord) -> io::Result<()> {
        cx_checkpoint(cx, "prepare ownership publication")?;
        let bytes = serde_json::to_vec_pretty(record).map_err(io::Error::other)?;
        let temp_path = temp_record_path(&self.record_path)?;
        self.publish_bytes(cx, &temp_path, &bytes)
    }

    fn publish_bytes(&self, cx: &Cx, temp_path: &Path, bytes: &[u8]) -> io::Result<()> {
        cx_checkpoint(cx, "write temporary ownership record")?;
        // Open the directory before changing the record. Platforms/filesystems
        // unable to open it fail before publication, not after replacing a lease.
        let parent = File::open(record_parent(&self.record_path))?;
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temp_path)?;
        temp.write_all(bytes)?;
        cx_checkpoint(cx, "sync temporary ownership record")?;
        temp.sync_all()?;
        drop(temp);
        cx_checkpoint(cx, "publish ownership record")?;
        std::fs::rename(temp_path, &self.record_path)?;
        // Complete the durability barrier even if cancellation arrives after
        // rename. A sync error here means publication happened but durability
        // is unknown; it must not be reported as a successful acquisition.
        parent.sync_all().map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("ownership record published but directory sync failed: {err}"),
            )
        })?;
        cx_checkpoint(cx, "finish ownership publication")
    }

    pub(super) fn remove(&self, cx: &Cx) -> io::Result<()> {
        cx_checkpoint(cx, "prepare ownership removal")?;
        let parent = File::open(record_parent(&self.record_path))?;
        cx_checkpoint(cx, "remove ownership record")?;
        match std::fs::remove_file(&self.record_path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err),
        }
        parent.sync_all().map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("ownership record removed but directory sync failed: {err}"),
            )
        })?;
        cx_checkpoint(cx, "finish ownership removal")
    }
}

pub(super) fn read_record(cx: &Cx, record_path: &Path) -> io::Result<CoordinationRecord> {
    cx_checkpoint(cx, "read ownership record")?;
    let contents = std::fs::read_to_string(record_path)?;
    cx_checkpoint(cx, "parse ownership record")?;
    serde_json::from_str(&contents)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn lock_path(record_path: &Path) -> PathBuf {
    let mut path = record_path.as_os_str().to_owned();
    path.push(".lock");
    PathBuf::from(path)
}

fn record_parent(record_path: &Path) -> &Path {
    record_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ownership::{AcquireResult, OwnershipGuard, RepairOwnership};
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::SystemTime;

    fn test_image() -> PathBuf {
        static NONCE: AtomicU64 = AtomicU64::new(0);
        let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
        let stamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ffs-ownership-record-{}-{stamp}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).expect("create isolated test directory");
        let image = dir.join("image.img");
        std::fs::write(&image, b"ownership protocol fixture").expect("create image path");
        image
    }

    fn acquire(cx: &Cx, image: &Path) -> (RepairOwnership, OwnershipGuard) {
        let manager = RepairOwnership::new("host-a".into(), "worker-a".into());
        let AcquireResult::Acquired(guard) = manager.try_acquire(cx, image).expect("acquire")
        else {
            panic!("fresh image must be acquired");
        };
        (manager, guard)
    }

    #[test]
    fn acquisition_refuses_held_transaction_without_publishing() {
        let image = test_image();
        let path = RepairOwnership::record_path_for(&image);
        let cx = Cx::for_testing();
        let transaction = RecordTransaction::begin(&cx, &path).expect("hold transaction");
        let manager = RepairOwnership::new("host-a".into(), "worker-a".into());
        let err = manager.try_acquire(&cx, &image).expect_err("must not race");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert!(!path.exists(), "contended acquisition must not publish");
        drop(transaction);
        assert!(matches!(
            manager.try_acquire(&cx, &image).expect("retry after unlock"),
            AcquireResult::Acquired(_)
        ));
    }

    #[test]
    fn renewal_and_release_refuse_held_transaction_without_mutation() {
        let image = test_image();
        let cx = Cx::for_testing();
        let (manager, mut guard) = acquire(&cx, &image);
        let path = guard.record_path().to_owned();
        let before = std::fs::read(&path).expect("read original");
        let expected = guard.record().clone();
        let _transaction = RecordTransaction::begin(&cx, &path).expect("hold transaction");
        let err = manager.renew(&cx, &mut guard).expect_err("renew must not race");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(guard.record(), &expected);
        let err = RepairOwnership::release(&cx, guard).expect_err("release must not race");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(std::fs::read(&path).expect("record retained"), before);
    }

    #[test]
    fn transaction_lock_survives_record_replacement_and_removal() {
        let image = test_image();
        let cx = Cx::for_testing();
        let (_, guard) = acquire(&cx, &image);
        let path = guard.record_path();
        let transaction = RecordTransaction::begin(&cx, path).expect("hold transaction");
        transaction.publish(&cx, guard.record()).expect("replace");
        assert_eq!(
            RecordTransaction::begin(&cx, path).expect_err("replacement keeps lock").kind(),
            io::ErrorKind::WouldBlock
        );
        transaction.remove(&cx).expect("remove record");
        assert!(!path.exists());
        assert!(lock_path(path).exists(), "lock inode must never be unlinked");
        assert_eq!(
            RecordTransaction::begin(&cx, path).expect_err("removal keeps lock").kind(),
            io::ErrorKind::WouldBlock
        );
        drop(transaction);
        let _next = RecordTransaction::begin(&cx, path).expect("lock released on drop");
    }

    #[test]
    fn simultaneous_claimants_publish_only_one_owner() {
        let image = test_image();
        let barrier = Barrier::new(8);
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|index| {
                    let barrier = &barrier;
                    let image = &image;
                    scope.spawn(move || {
                        let manager = RepairOwnership::new(
                            format!("host-{index}"),
                            format!("worker-{index}"),
                        );
                        let cx = Cx::for_testing();
                        barrier.wait();
                        manager.try_acquire(&cx, image)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("claimant did not panic"))
                .collect::<Vec<_>>()
        });
        let mut winners = Vec::new();
        for result in results {
            match result {
                Ok(AcquireResult::Acquired(guard)) => winners.push(guard),
                Ok(AcquireResult::OwnedByOther { .. }) => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                other => panic!("unexpected acquisition result: {other:?}"),
            }
        }
        assert_eq!(winners.len(), 1, "at most one writer may report acquisition");
        let cx = Cx::for_testing();
        let persisted = read_record(&cx, winners[0].record_path()).expect("read winner");
        assert_eq!(&persisted, winners[0].record());
    }

    #[test]
    fn cancelled_transaction_does_not_create_lock_or_record() {
        let image = test_image();
        let path = RepairOwnership::record_path_for(&image);
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let err = RecordTransaction::begin(&cx, &path).expect_err("cancelled");
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert!(!path.exists());
        assert!(!lock_path(&path).exists());
    }

    #[test]
    fn cancelled_publication_preserves_previous_record() {
        let image = test_image();
        let cx = Cx::for_testing();
        let (_, guard) = acquire(&cx, &image);
        let path = guard.record_path();
        let before = std::fs::read(path).expect("read previous");
        let transaction = RecordTransaction::begin(&cx, path).expect("hold transaction");
        let cancel = Cx::for_testing();
        cancel.set_cancel_requested(true);
        let err = transaction.publish(&cancel, guard.record()).expect_err("cancelled");
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert_eq!(std::fs::read(path).expect("record retained"), before);
    }

    #[test]
    fn temporary_path_collision_does_not_truncate_existing_file() {
        let image = test_image();
        let cx = Cx::for_testing();
        let (_, guard) = acquire(&cx, &image);
        let path = guard.record_path();
        let before = std::fs::read(path).expect("read previous");
        let transaction = RecordTransaction::begin(&cx, path).expect("hold transaction");
        let collision = path.with_extension("occupied.tmp");
        std::fs::write(&collision, b"do not overwrite").expect("create collision");
        let err = transaction
            .publish_bytes(&cx, &collision, b"replacement")
            .expect_err("create_new must reject collision");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&collision).expect("collision retained"), b"do not overwrite");
        assert_eq!(std::fs::read(path).expect("record retained"), before);
    }

    #[test]
    fn basename_record_uses_current_directory_for_durability_barrier() {
        assert_eq!(record_parent(Path::new("record.json")), Path::new("."));
        assert_eq!(record_parent(Path::new("a/record.json")), Path::new("a"));
        assert_eq!(lock_path(Path::new("record.json")), Path::new("record.json.lock"));
    }
}
