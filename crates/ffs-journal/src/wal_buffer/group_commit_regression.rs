#![forbid(unsafe_code)]

use super::*;
use std::sync::TryLockError;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::Duration;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct WriterState {
    written: Vec<WalEntry>,
    writes: usize,
    syncs: usize,
    fail_write: bool,
    sync_failures: usize,
}

#[derive(Clone, Default)]
struct TestWriter(Arc<Mutex<WriterState>>);

impl WalWriter for TestWriter {
    fn write_entries(&self, entries: &[WalEntry]) -> Result<(), FfsError> {
        let mut state = self.0.lock().expect("writer state");
        state.writes += 1;
        if state.fail_write {
            // A failed append may already have persisted a prefix.
            state.written.extend(entries.iter().take(1).cloned());
            return Err(FfsError::Io(std::io::Error::other(
                "injected write failure",
            )));
        }
        state.written.extend_from_slice(entries);
        Ok(())
    }

    fn sync(&self) -> Result<(), FfsError> {
        let mut state = self.0.lock().expect("writer state");
        state.syncs += 1;
        if state.sync_failures > 0 {
            state.sync_failures -= 1;
            return Err(FfsError::Io(std::io::Error::other("injected sync failure")));
        }
        Ok(())
    }
}

fn transaction(epoch: u64) -> Vec<WalEntry> {
    let mut buffer = CoreWalBuffer::new(0, WalBufferConfig::default());
    buffer.append_write(epoch, TxnId(epoch), BlockNumber(epoch), vec![1; 32]);
    buffer.append_commit(epoch, TxnId(epoch), CommitSeq(epoch));
    buffer.drain()
}

fn coordinator<W: WalWriter>(writer: W, max_retries: usize) -> GroupCommitCoordinator<W> {
    let manager = Arc::new(EpochManager::new(EpochManagerConfig::default()));
    // The tests submit closed epochs, not live producer buffers.
    while manager.current_epoch() <= 16 {
        manager.force_advance();
    }
    GroupCommitCoordinator::new(
        manager,
        Arc::new(DurabilityNotifier::new()),
        writer,
        GroupCommitConfig { max_retries },
    )
}

fn assert_failed<W: WalWriter>(coordinator: &GroupCommitCoordinator<W>, epoch: u64) {
    assert!(matches!(
        coordinator
            .notifier()
            .await_epoch_timeout(epoch, Duration::ZERO),
        Some(DurabilityOutcome::Failed(_))
    ));
}

#[test]
fn write_failure_wakes_the_entire_unflushed_prefix_and_preserves_the_tail() {
    let writer = TestWriter::default();
    writer.0.lock().expect("writer state").fail_write = true;
    let coordinator = coordinator(writer.clone(), 0);
    let entries: Vec<_> = [1, 3, 5].into_iter().flat_map(transaction).collect();
    let expected = entries.clone();
    let failure = coordinator
        .flush_epoch_recoverable(entries, 3)
        .expect_err("partial write must fail");
    assert_eq!(failure.entries, expected);
    assert_eq!(coordinator.epoch_manager().flushed_epoch(), 0);
    assert_eq!(coordinator.notifier().durable_epoch(), 0);
    for epoch in 1..=5 {
        assert_failed(&coordinator, epoch);
    }
    let state = writer.0.lock().expect("writer state");
    assert_eq!(state.writes, 1);
    assert_eq!(state.syncs, 0);
    assert_eq!(state.written.len(), 1);
}

#[test]
fn exhausted_sync_retries_preserve_all_entries_without_publishing_durability() {
    let writer = TestWriter::default();
    writer.0.lock().expect("writer state").sync_failures = 3;
    let coordinator = coordinator(writer.clone(), 1);
    let entries: Vec<_> = [1, 2, 4].into_iter().flat_map(transaction).collect();
    let expected = entries.clone();
    let failure = coordinator
        .flush_epoch_recoverable(entries, 2)
        .expect_err("sync retries must exhaust");
    assert_eq!(failure.entries, expected);
    assert_eq!(coordinator.epoch_manager().flushed_epoch(), 0);
    assert_eq!(coordinator.notifier().durable_epoch(), 0);
    assert_failed(&coordinator, 1);
    assert_failed(&coordinator, 2);
    let state = writer.0.lock().expect("writer state");
    assert_eq!(state.writes, 1);
    assert_eq!(state.syncs, 2);
}

#[test]
fn a_failed_batch_does_not_invalidate_the_previously_durable_prefix() {
    let writer = TestWriter::default();
    let coordinator = coordinator(writer.clone(), 0);
    coordinator
        .flush_epoch(transaction(1), 1)
        .expect("first epoch");
    writer.0.lock().expect("writer state").fail_write = true;
    let entries = [2, 3].into_iter().flat_map(transaction).collect();
    coordinator
        .flush_epoch(entries, 3)
        .expect_err("later failure");
    assert_eq!(coordinator.epoch_manager().flushed_epoch(), 1);
    assert_eq!(coordinator.notifier().durable_epoch(), 1);
    assert_eq!(
        coordinator
            .notifier()
            .await_epoch_timeout(1, Duration::ZERO),
        Some(DurabilityOutcome::Durable)
    );
    assert_failed(&coordinator, 2);
    assert_failed(&coordinator, 3);
}

#[test]
fn terminal_failure_rejects_later_nonempty_and_empty_flushes_before_io() {
    let writer = TestWriter::default();
    writer.0.lock().expect("writer state").fail_write = true;
    let coordinator = coordinator(writer.clone(), 0);
    coordinator
        .flush_epoch(transaction(1), 1)
        .expect_err("initial failure");
    writer.0.lock().expect("writer state").fail_write = false;
    coordinator
        .flush_epoch(Vec::new(), 8)
        .expect_err("empty flush must not cross a failed prefix");
    let later = transaction(2);
    let failure = coordinator
        .flush_epoch_recoverable(later.clone(), 2)
        .expect_err("failed writer must stay sealed");
    assert_eq!(failure.entries, later);
    assert_eq!(coordinator.epoch_manager().flushed_epoch(), 0);
    assert_eq!(coordinator.notifier().durable_epoch(), 0);
    let state = writer.0.lock().expect("writer state");
    assert_eq!(state.writes, 1);
    assert_eq!(state.syncs, 0);
}

#[test]
fn successful_sync_retry_writes_once_and_returns_future_entries() {
    let writer = TestWriter::default();
    writer.0.lock().expect("writer state").sync_failures = 2;
    let coordinator = coordinator(writer.clone(), 2);
    let now = transaction(1);
    let future = transaction(2);
    let entries = now.iter().chain(&future).cloned().collect();
    let (result, remaining) = coordinator
        .flush_epoch_recoverable(entries, 1)
        .expect("last retry succeeds");
    assert_eq!(result.fsyncs_issued, 3);
    assert_eq!(result.entries_written, now.len());
    assert_eq!(remaining, future);
    assert_eq!(coordinator.epoch_manager().flushed_epoch(), 1);
    assert_eq!(coordinator.notifier().durable_epoch(), 1);
    assert_eq!(
        coordinator
            .notifier()
            .await_epoch_timeout(2, Duration::ZERO),
        None
    );
    let state = writer.0.lock().expect("writer state");
    assert_eq!(state.writes, 1);
    assert_eq!(state.syncs, 3);
    assert_eq!(state.written, now);
}

#[test]
fn duplicate_durable_epoch_is_rejected_without_poisoning_a_healthy_writer() {
    let writer = TestWriter::default();
    let coordinator = coordinator(writer.clone(), 0);
    coordinator
        .flush_epoch(transaction(1), 1)
        .expect("first epoch");
    let duplicate = transaction(1);
    let failure = coordinator
        .flush_epoch_recoverable(duplicate.clone(), 1)
        .expect_err("must not append already durable records again");
    assert!(matches!(failure.error, FfsError::Format(_)));
    assert_eq!(failure.entries, duplicate);
    assert_eq!(writer.0.lock().expect("writer state").writes, 1);
    coordinator
        .flush_epoch(transaction(2), 2)
        .expect("next epoch");
    assert_eq!(coordinator.epoch_manager().flushed_epoch(), 2);
    assert_eq!(coordinator.notifier().durable_epoch(), 2);
}

#[derive(Clone)]
struct BlockingSyncWriter {
    events: Arc<Mutex<Vec<&'static str>>>,
    first_sync: Arc<AtomicBool>,
    sync_entered: SyncSender<()>,
    resume_sync: Arc<Mutex<Receiver<()>>>,
}

impl WalWriter for BlockingSyncWriter {
    fn write_entries(&self, _entries: &[WalEntry]) -> Result<(), FfsError> {
        self.events.lock().expect("events").push("write");
        Ok(())
    }

    fn sync(&self) -> Result<(), FfsError> {
        self.events.lock().expect("events").push("sync_begin");
        if !self.first_sync.swap(true, Ordering::SeqCst) {
            self.sync_entered.send(()).expect("sync observer");
            self.resume_sync
                .lock()
                .expect("resume receiver")
                .recv_timeout(TEST_TIMEOUT)
                .expect("test must release sync");
        }
        self.events.lock().expect("events").push("sync_end");
        Ok(())
    }
}

#[test]
fn concurrent_flush_holds_serialization_through_sync_and_publication() {
    let (sync_entered, observed_sync) = sync_channel(1);
    let (resume_sync, resume_receiver) = sync_channel(1);
    let events = Arc::new(Mutex::new(Vec::new()));
    let writer = BlockingSyncWriter {
        events: Arc::clone(&events),
        first_sync: Arc::new(AtomicBool::new(false)),
        sync_entered,
        resume_sync: Arc::new(Mutex::new(resume_receiver)),
    };
    let coordinator = Arc::new(coordinator(writer, 0));
    let first = {
        let coordinator = Arc::clone(&coordinator);
        std::thread::spawn(move || coordinator.flush_epoch(transaction(1), 1))
    };
    observed_sync
        .recv_timeout(TEST_TIMEOUT)
        .expect("first sync");
    assert_eq!(coordinator.epoch_manager().flushed_epoch(), 0);
    assert_eq!(coordinator.notifier().durable_epoch(), 0);
    // This is an explicit synchronization assertion, not a sleep-based guess
    // about whether the second thread happened to run before the first.
    assert!(matches!(
        coordinator.flush_failure.try_lock(),
        Err(TryLockError::WouldBlock)
    ));
    let (attempted, observed_attempt) = sync_channel(1);
    let second = {
        let coordinator = Arc::clone(&coordinator);
        std::thread::spawn(move || {
            attempted.send(()).expect("attempt observer");
            coordinator.flush_epoch(transaction(2), 2)
        })
    };
    observed_attempt
        .recv_timeout(TEST_TIMEOUT)
        .expect("second attempt");
    resume_sync.send(()).expect("release first sync");
    first.join().expect("first worker").expect("first flush");
    second.join().expect("second worker").expect("second flush");
    assert_eq!(
        *events.lock().expect("events"),
        [
            "write",
            "sync_begin",
            "sync_end",
            "write",
            "sync_begin",
            "sync_end"
        ]
    );
    assert_eq!(coordinator.epoch_manager().flushed_epoch(), 2);
    assert_eq!(coordinator.notifier().durable_epoch(), 2);
}

struct PanickingWriter;

impl WalWriter for PanickingWriter {
    fn write_entries(&self, _entries: &[WalEntry]) -> Result<(), FfsError> {
        panic!("injected writer panic");
    }

    fn sync(&self) -> Result<(), FfsError> {
        panic!("sync must not be reached");
    }
}

#[test]
fn writer_panic_wakes_waiters_and_poisoned_coordinator_returns_later_input() {
    let coordinator = coordinator(PanickingWriter, 0);
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        coordinator.flush_epoch(transaction(1), 1)
    }));
    assert!(panicked.is_err());
    // Notification must occur during unwinding, not only on the next flush.
    assert_failed(&coordinator, 1);
    assert_failed(&coordinator, 2);
    let later = transaction(2);
    let failure = coordinator
        .flush_epoch_recoverable(later.clone(), 2)
        .expect_err("poisoned writer must not be reused");
    assert_eq!(failure.entries, later);
    assert_eq!(coordinator.epoch_manager().flushed_epoch(), 0);
    assert_eq!(coordinator.notifier().durable_epoch(), 0);
}
