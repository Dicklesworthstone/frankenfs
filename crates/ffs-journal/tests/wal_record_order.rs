#![forbid(unsafe_code)]

use ffs_error::FfsError;
use ffs_journal::wal_buffer::{
    CoreWalBuffer, DurabilityNotifier, EpochManager, EpochManagerConfig, ExplicitWalPool,
    GroupCommitConfig, GroupCommitCoordinator, WalBufferConfig, WalEntry, WalEntryType, WalWriter,
};
use ffs_types::{BlockNumber, CommitSeq, TxnId};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct RecordingWriter(Arc<Mutex<Vec<WalEntry>>>);

impl WalWriter for RecordingWriter {
    fn write_entries(&self, entries: &[WalEntry]) -> Result<(), FfsError> {
        self.0
            .lock()
            .expect("recording lock")
            .extend_from_slice(entries);
        Ok(())
    }

    fn sync(&self) -> Result<(), FfsError> {
        Ok(())
    }
}

fn transaction(epoch: u64, txn: u64) -> Vec<WalEntry> {
    let mut buffer = CoreWalBuffer::new(0, WalBufferConfig::default());
    buffer.append_write(epoch, TxnId(txn), BlockNumber(7), vec![1; 16]);
    buffer.append_write(epoch, TxnId(txn), BlockNumber(7), vec![2; 16]);
    buffer.append_commit(epoch, TxnId(txn), CommitSeq(txn));
    buffer.drain()
}

#[test]
fn pooled_epoch_sort_preserves_each_transactions_write_and_commit_order() {
    let pool = ExplicitWalPool::new(WalBufferConfig::default());
    let mut buffers: Vec<_> = (0..8).map(|core| pool.allocate_buffer(core)).collect();
    for (core, buffer) in buffers.iter_mut().enumerate() {
        for epoch in 1..=64 {
            let txn = u64::try_from(core).expect("small core id") * 64 + epoch;
            buffer.append_write(epoch, TxnId(txn), BlockNumber(txn), vec![1]);
            buffer.append_write(epoch, TxnId(txn), BlockNumber(txn), vec![2]);
            buffer.append_commit(epoch, TxnId(txn), CommitSeq(txn));
        }
    }
    let (entries, result) = pool.drain_all(&mut buffers);
    assert_eq!(result.entries_flushed, 8 * 64 * 3);
    assert_eq!(result.buffers_drained, 8);
    assert!(buffers.iter().all(CoreWalBuffer::is_empty));
    assert!(
        entries
            .windows(2)
            .all(|pair| pair[0].epoch <= pair[1].epoch)
    );
    for txn in 1..=512 {
        let actual: Vec<_> = entries
            .iter()
            .filter(|entry| entry.txn_id == TxnId(txn))
            .map(|entry| entry.entry_type.clone())
            .collect();
        assert_eq!(
            actual,
            vec![
                WalEntryType::Write {
                    block: BlockNumber(txn),
                    data: vec![1],
                },
                WalEntryType::Write {
                    block: BlockNumber(txn),
                    data: vec![2],
                },
                WalEntryType::Commit,
            ],
            "transaction {txn} must retain write/write/commit order"
        );
    }
}

#[test]
fn coordinator_orders_unsorted_epochs_without_reordering_equal_epoch_records() {
    let manager = Arc::new(EpochManager::new(EpochManagerConfig::default()));
    while manager.current_epoch() <= 64 {
        manager.force_advance();
    }
    let writer = RecordingWriter::default();
    let coordinator = GroupCommitCoordinator::new(
        manager,
        Arc::new(DurabilityNotifier::new()),
        writer.clone(),
        GroupCommitConfig::default(),
    );
    let entries: Vec<_> = (1..=64)
        .rev()
        .flat_map(|epoch| transaction(epoch, epoch))
        .collect();
    let mut expected = entries.clone();
    expected.sort_by_key(|entry| entry.epoch);
    let (result, remaining) = coordinator.flush_epoch(entries, 64).expect("flush");
    assert_eq!(remaining, Vec::new());
    assert_eq!(result.entries_written, expected.len());
    assert_eq!(*writer.0.lock().expect("recorded entries"), expected);
}

#[test]
fn future_epoch_records_are_returned_without_being_written() {
    let manager = Arc::new(EpochManager::new(EpochManagerConfig::default()));
    manager.force_advance();
    let writer = RecordingWriter::default();
    let coordinator = GroupCommitCoordinator::new(
        manager,
        Arc::new(DurabilityNotifier::new()),
        writer.clone(),
        GroupCommitConfig::default(),
    );
    let now = transaction(1, 1);
    let future = transaction(2, 2);
    let entries = future.iter().chain(&now).cloned().collect();
    let (result, remaining) = coordinator.flush_epoch(entries, 1).expect("flush");
    assert_eq!(result.entries_written, now.len());
    assert_eq!(remaining, future);
    assert_eq!(*writer.0.lock().expect("recorded entries"), now);
}
