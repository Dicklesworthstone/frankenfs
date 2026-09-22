//! Serialized, durable updates to the repair coordination record.
//!
//! Lock a separate, stable inode: locking the JSON file itself would lose
//! exclusion when publication replaces it with rename. The `.lock` file is
//! intentionally never removed, including when the ownership record is released.
//! These advisory locks require all writers to cooperate and a filesystem that
//! supports them; they are not a fencing mechanism for expired repair workers.
//!
//! Release first durably publishes a `.released` record containing the retired
//! incarnation, then removes the active JSON file. The retired record is kept
//! across processes so a later acquisition cannot reuse an old guard's counters.
//! If release is interrupted between those steps, reads treat the old active
//! record as retired. Neither the `.lock` nor `.released` sidecar may be removed
//! while the image's ownership history is still in use.

use super::{CoordinationRecord, RECORD_VERSION, cx_checkpoint, temp_record_path};
use asupersync::Cx;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const RETIRED_AT: &str = "1970-01-01T00:00:00Z";

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
        // In particular, reject renewal of a retired guard when the active
        // file is absent. Reading that guard from history must never let its
        // unchanged counters resurrect the released incarnation.
        if let Some(retired) = read_retired_record(cx, &self.record_path)?
            && (record.repair_generation <= retired.repair_generation
                || record.lease_version <= retired.lease_version)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cannot publish a retired repair ownership incarnation; acquire a new lease",
            ));
        }
        let bytes = serde_json::to_vec_pretty(record).map_err(io::Error::other)?;
        let temp_path = temp_record_path(&self.record_path)?;
        self.publish_bytes(cx, &temp_path, &bytes)
    }

    fn publish_bytes(&self, cx: &Cx, temp_path: &Path, bytes: &[u8]) -> io::Result<()> {
        publish_bytes_at(cx, &self.record_path, temp_path, bytes)
    }

    /// Retirement is the release commit point. Keep the counters even when
    /// cancellation, an unlink error, or a crash leaves the active file behind.
    fn persist_retirement(&self, cx: &Cx, record: &CoordinationRecord) -> io::Result<()> {
        cx_checkpoint(cx, "prepare ownership retirement")?;
        if let Some(previous) = read_retired_record(cx, &self.record_path)?
            && (record.repair_generation <= previous.repair_generation
                || record.lease_version <= previous.lease_version)
        {
            if record.repair_generation == previous.repair_generation
                && record.lease_version == previous.lease_version
                && record.host_id == previous.host_id
                && record.pid == previous.pid
            {
                // A previous attempt may have renamed the retirement record
                // but failed its directory sync. Re-establish the barrier
                // before permitting active-record removal on a retry.
                let path = retired_path(&self.record_path);
                File::open(&path)?.sync_all()?;
                File::open(record_parent(&path))?.sync_all()?;
                return cx_checkpoint(cx, "finish existing ownership retirement");
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "repair ownership retirement would regress incarnation history",
            ));
        }
        let mut retired = record.clone();
        retired.claimed_at = RETIRED_AT.to_owned();
        retired.lease_ttl_secs = 0;
        let bytes = serde_json::to_vec_pretty(&retired).map_err(io::Error::other)?;
        let path = retired_path(&self.record_path);
        let temp_path = temp_record_path(&path)?;
        publish_bytes_at(cx, &path, &temp_path, &bytes)
    }

    pub(super) fn remove(&self, cx: &Cx) -> io::Result<()> {
        cx_checkpoint(cx, "prepare ownership removal")?;
        if read_optional_record(cx, &self.record_path)?.is_none() {
            return Ok(());
        }
        let parent = File::open(record_parent(&self.record_path))?;
        let current = read_record(cx, &self.record_path)?;
        self.persist_retirement(cx, &current)?;
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

fn publish_bytes_at(cx: &Cx, path: &Path, temp_path: &Path, bytes: &[u8]) -> io::Result<()> {
    cx_checkpoint(cx, "write temporary ownership record")?;
    // Open the directory before changing the record. Platforms/filesystems
    // unable to open it fail before publication, not after replacing a lease.
    let parent = File::open(record_parent(path))?;
    let mut temp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temp_path)?;
    temp.write_all(bytes)?;
    cx_checkpoint(cx, "sync temporary ownership record")?;
    temp.sync_all()?;
    drop(temp);
    cx_checkpoint(cx, "publish ownership record")?;
    std::fs::rename(temp_path, path)?;
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

pub(super) fn read_record(cx: &Cx, record_path: &Path) -> io::Result<CoordinationRecord> {
    let current = read_optional_record(cx, record_path)?;
    let retired = read_retired_record(cx, record_path)?;
    match (current, retired) {
        (Some(current), Some(retired)) => {
            if current.repair_generation > retired.repair_generation
                && current.lease_version > retired.lease_version
            {
                Ok(current)
            } else if current.repair_generation <= retired.repair_generation
                && current.lease_version <= retired.lease_version
            {
                // Release committed, but the old active file survived. Return
                // an expired record with the persisted high-water counters.
                Ok(retired)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "inconsistent active and retired repair ownership counters",
                ))
            }
        }
        (Some(record), None) | (None, Some(record)) => Ok(record),
        (None, None) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "repair ownership record and retirement history are absent",
        )),
    }
}

fn read_optional_record(cx: &Cx, record_path: &Path) -> io::Result<Option<CoordinationRecord>> {
    cx_checkpoint(cx, "read ownership record")?;
    let contents = match std::fs::read_to_string(record_path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    cx_checkpoint(cx, "parse ownership record")?;
    let record: CoordinationRecord = serde_json::from_str(&contents)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    if record.version != RECORD_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported repair ownership record version {}",
                record.version
            ),
        ));
    }
    Ok(Some(record))
}

fn read_retired_record(cx: &Cx, record_path: &Path) -> io::Result<Option<CoordinationRecord>> {
    let retired = read_optional_record(cx, &retired_path(record_path))?;
    if let Some(record) = &retired
        && (record.claimed_at != RETIRED_AT || record.lease_ttl_secs != 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid repair ownership retirement marker",
        ));
    }
    Ok(retired)
}

fn retired_path(record_path: &Path) -> PathBuf {
    let mut path = record_path.as_os_str().to_owned();
    path.push(".released");
    PathBuf::from(path)
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
            manager
                .try_acquire(&cx, &image)
                .expect("retry after unlock"),
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
        let err = manager
            .renew(&cx, &mut guard)
            .expect_err("renew must not race");
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
            RecordTransaction::begin(&cx, path)
                .expect_err("replacement keeps lock")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        transaction.remove(&cx).expect("remove record");
        assert!(!path.exists());
        assert!(
            lock_path(path).exists(),
            "lock inode must never be unlinked"
        );
        assert_eq!(
            RecordTransaction::begin(&cx, path)
                .expect_err("removal keeps lock")
                .kind(),
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
        assert_eq!(
            winners.len(),
            1,
            "at most one writer may report acquisition"
        );
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
        let err = transaction
            .publish(&cancel, guard.record())
            .expect_err("cancelled");
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
        assert_eq!(
            std::fs::read(&collision).expect("collision retained"),
            b"do not overwrite"
        );
        assert_eq!(std::fs::read(path).expect("record retained"), before);
    }

    #[test]
    fn basename_record_uses_current_directory_for_durability_barrier() {
        assert_eq!(record_parent(Path::new("record.json")), Path::new("."));
        assert_eq!(record_parent(Path::new("a/record.json")), Path::new("a"));
        assert_eq!(
            lock_path(Path::new("record.json")),
            Path::new("record.json.lock")
        );
    }

    #[test]
    fn incarnation_counters_survive_release_and_fresh_managers() {
        let image = test_image();
        let cx = Cx::for_testing();
        for expected in 1..=8 {
            // No in-memory ownership state is carried between iterations.
            let (manager, guard) = acquire(&cx, &image);
            assert_eq!(guard.record().repair_generation, expected);
            assert_eq!(guard.record().lease_version, expected);
            let path = guard.record_path().to_owned();
            RepairOwnership::release(&cx, guard).expect("release");
            assert!(!path.exists(), "active record is still removed on release");
            assert!(!manager.is_owned_by_us(&cx, &image).expect("status"));
            let retired = read_retired_record(&cx, &path)
                .expect("read retirement")
                .expect("retirement must survive release");
            assert_eq!(retired.repair_generation, expected);
            assert_eq!(retired.lease_version, expected);
            assert!(retired.is_expired(SystemTime::now()));
        }
    }

    #[test]
    fn stale_guard_cannot_renew_or_release_a_reacquired_incarnation() {
        let image = test_image();
        let cx = Cx::for_testing();
        let (manager, mut stale) = acquire(&cx, &image);
        // The API permits this process to reacquire, leaving its earlier
        // guard stale. Previously releasing v2 reset the next claim to v1,
        // making that old guard match again (an ABA ownership violation).
        let (_, second) = acquire(&cx, &image);
        assert_eq!(second.record().lease_version, 2);
        RepairOwnership::release(&cx, second).expect("release second claim");
        let (_, current) = acquire(&cx, &image);
        assert_eq!(current.record().lease_version, 3);
        let before = std::fs::read(current.record_path()).expect("read current");
        let err = manager
            .renew(&cx, &mut stale)
            .expect_err("old guard must stay stale after handoff");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let err = RepairOwnership::release(&cx, stale)
            .expect_err("old guard must not release new incarnation");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::read(current.record_path()).expect("retained"),
            before
        );
    }

    #[test]
    fn retired_guard_cannot_resurrect_an_absent_active_record() {
        let image = test_image();
        let cx = Cx::for_testing();
        let (manager, mut guard) = acquire(&cx, &image);
        let path = guard.record_path().to_owned();
        let transaction = RecordTransaction::begin(&cx, &path).expect("hold transaction");
        transaction.remove(&cx).expect("retire and remove");
        drop(transaction);
        let expected = guard.record().clone();
        let err = manager
            .renew(&cx, &mut guard)
            .expect_err("retired counters cannot be republished");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(guard.record(), &expected);
        assert!(!path.exists());
    }

    #[test]
    fn durable_retirement_wins_when_active_unlink_never_happens() {
        let image = test_image();
        let cx = Cx::for_testing();
        let (manager, mut old_guard) = acquire(&cx, &image);
        let path = old_guard.record_path().to_owned();
        let before = std::fs::read(&path).expect("read active");
        let transaction = RecordTransaction::begin(&cx, &path).expect("hold transaction");
        transaction
            .persist_retirement(&cx, old_guard.record())
            .expect("commit retirement without unlink, as before a crash");
        drop(transaction);
        assert_eq!(std::fs::read(&path).expect("old file remains"), before);
        let still_owned = manager.is_owned_by_us(&cx, &image).expect("retired status");
        assert!(!still_owned);
        let err = manager
            .renew(&cx, &mut old_guard)
            .expect_err("committed retirement cannot be renewed");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let other = RepairOwnership::new("host-b".into(), "worker-b".into());
        let AcquireResult::Acquired(next) = other.try_acquire(&cx, &image).expect("takeover")
        else {
            panic!("committed retirement must not wait for old TTL");
        };
        assert_eq!(next.record().repair_generation, 2);
        assert_eq!(next.record().lease_version, 2);
        assert_eq!(next.record().host_id, "host-b");
        assert_eq!(read_record(&cx, &path).expect("new active"), *next.record());
    }

    #[test]
    fn cancelled_retirement_keeps_active_lease_and_no_history() {
        let image = test_image();
        let cx = Cx::for_testing();
        let (manager, guard) = acquire(&cx, &image);
        let path = guard.record_path();
        let transaction = RecordTransaction::begin(&cx, path).expect("hold transaction");
        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        let err = transaction
            .persist_retirement(&cancelled, guard.record())
            .expect_err("retirement cancelled before publication");
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert!(!retired_path(path).exists());
        assert_eq!(read_record(&cx, path).expect("unchanged"), *guard.record());
        assert!(manager.is_owned_by_us(&cx, &image).expect("still owned"));
    }

    #[test]
    fn invalid_retirement_history_blocks_claim_instead_of_resetting_counters() {
        let image = test_image();
        let cx = Cx::for_testing();
        let (manager, guard) = acquire(&cx, &image);
        let path = guard.record_path().to_owned();
        RepairOwnership::release(&cx, guard).expect("release");
        std::fs::write(retired_path(&path), b"{torn retirement")
            .expect("inject torn retirement metadata");
        let err = manager
            .try_acquire(&cx, &image)
            .expect_err("unknown high-water counters must fail closed");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!path.exists());
    }

    #[test]
    fn live_record_cannot_be_misread_as_a_retirement_marker() {
        let image = test_image();
        let cx = Cx::for_testing();
        let (manager, guard) = acquire(&cx, &image);
        let path = guard.record_path();
        let active = std::fs::read(path).expect("read active");
        std::fs::write(retired_path(path), &active).expect("inject invalid marker");
        let err = manager
            .try_acquire(&cx, &image)
            .expect_err("live record is not a retirement marker");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(path).expect("active retained"), active);
    }

    #[test]
    fn retirement_persistence_error_does_not_remove_active_record() {
        let image = test_image();
        let cx = Cx::for_testing();
        let (_, guard) = acquire(&cx, &image);
        let path = guard.record_path().to_owned();
        let before = std::fs::read(&path).expect("read active");
        // An unreadable history path must not become an implicit fresh start.
        std::fs::create_dir(retired_path(&path)).expect("block history path");
        let transaction = RecordTransaction::begin(&cx, &path).expect("hold transaction");
        transaction
            .remove(&cx)
            .expect_err("history cannot be read or published");
        assert_eq!(std::fs::read(&path).expect("active retained"), before);
    }

    #[test]
    fn release_preserves_exhausted_counters_instead_of_restarting_at_one() {
        let image = test_image();
        let cx = Cx::for_testing();
        let (manager, mut guard) = acquire(&cx, &image);
        let path = guard.record_path().to_owned();
        guard.record.repair_generation = u64::MAX;
        guard.record.lease_version = u64::MAX;
        let transaction = RecordTransaction::begin(&cx, &path).expect("hold transaction");
        transaction
            .publish(&cx, guard.record())
            .expect("last incarnation");
        drop(transaction);
        RepairOwnership::release(&cx, guard).expect("retire last incarnation");
        let err = manager
            .try_acquire(&cx, &image)
            .expect_err("exhausted history must not wrap or restart");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!path.exists());
        let retired = read_retired_record(&cx, &path)
            .expect("read history")
            .expect("history retained");
        assert_eq!(retired.repair_generation, u64::MAX);
        assert_eq!(retired.lease_version, u64::MAX);
    }

    #[test]
    fn unknown_record_version_is_rejected_without_rewriting() {
        let image = test_image();
        let cx = Cx::for_testing();
        let (manager, guard) = acquire(&cx, &image);
        let path = guard.record_path();
        let mut future = guard.record().clone();
        future.version = RECORD_VERSION + 1;
        let bytes = serde_json::to_vec_pretty(&future).expect("encode future version");
        std::fs::write(path, &bytes).expect("inject future record");
        let err = manager
            .try_acquire(&cx, &image)
            .expect_err("unknown protocols must not be rewritten");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(path).expect("future record retained"), bytes);
    }

    #[test]
    fn current_lease_can_renew_above_retirement_history() {
        let image = test_image();
        let cx = Cx::for_testing();
        let (_, first) = acquire(&cx, &image);
        RepairOwnership::release(&cx, first).expect("release first");
        let (manager, mut current) = acquire(&cx, &image);
        manager.renew(&cx, &mut current).expect("renew current");
        assert_eq!(current.record().repair_generation, 2);
        assert_eq!(current.record().lease_version, 2);
        let persisted = read_record(&cx, current.record_path()).expect("read current");
        assert_eq!(&persisted, current.record());
        assert!(manager.is_owned_by_us(&cx, &image).expect("owned"));
    }

    #[test]
    fn retrying_committed_retirement_preserves_the_high_water_counters() {
        let image = test_image();
        let cx = Cx::for_testing();
        let (_, guard) = acquire(&cx, &image);
        let path = guard.record_path();
        let transaction = RecordTransaction::begin(&cx, path).expect("hold transaction");
        transaction
            .persist_retirement(&cx, guard.record())
            .expect("first retirement");
        let before = std::fs::read(retired_path(path)).expect("read retired");
        transaction
            .persist_retirement(&cx, guard.record())
            .expect("retry barriers for existing retirement");
        transaction.remove(&cx).expect("finish interrupted release");
        assert!(!path.exists());
        let after = std::fs::read(retired_path(path)).expect("retirement retained");
        assert_eq!(after, before);
        drop(transaction);
        let (_, next) = acquire(&cx, &image);
        assert_eq!(next.record().repair_generation, 2);
        assert_eq!(next.record().lease_version, 2);
    }

    #[test]
    fn inconsistent_counter_history_fails_closed() {
        let image = test_image();
        let cx = Cx::for_testing();
        let (_, first) = acquire(&cx, &image);
        RepairOwnership::release(&cx, first).expect("release first");
        let (manager, current) = acquire(&cx, &image);
        let mut inconsistent = current.record().clone();
        // Only one of the two incarnation counters advanced past retirement.
        inconsistent.lease_version = 1;
        let bytes = serde_json::to_vec_pretty(&inconsistent).expect("encode inconsistent record");
        std::fs::write(current.record_path(), &bytes).expect("inject counter regression");
        let err = manager
            .try_acquire(&cx, &image)
            .expect_err("counter histories must agree");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let after = std::fs::read(current.record_path()).expect("record retained");
        assert_eq!(after, bytes);
    }
}
