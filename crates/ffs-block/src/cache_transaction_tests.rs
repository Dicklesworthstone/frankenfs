//! Transactional cache regressions using real positional file I/O. The cache,
//! dirty tracker, staging API and flush pipeline are the production ones.
//! Fault injection covers write failure, not physical power-loss behavior.

use super::*;
use std::sync::atomic::AtomicBool;

const BLOCK_BYTES: usize = 512;

#[derive(Debug)]
struct DiskDevice {
    file: File,
    fail_writes: AtomicBool,
}

impl DiskDevice {
    fn new() -> Self {
        let file = tempfile::tempfile().expect("temporary device");
        file.set_len(32 * BLOCK_BYTES as u64).unwrap();
        Self {
            file,
            fail_writes: AtomicBool::new(false),
        }
    }

    fn bytes(&self, block: BlockNumber) -> Vec<u8> {
        let mut bytes = vec![0; BLOCK_BYTES];
        self.file
            .read_exact_at(&mut bytes, block.0 * BLOCK_BYTES as u64)
            .unwrap();
        bytes
    }
}

impl BlockDevice for DiskDevice {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        cx_checkpoint(cx)?;
        let mut bytes = vec![0; BLOCK_BYTES];
        self.file
            .read_exact_at(&mut bytes, block.0 * BLOCK_BYTES as u64)?;
        Ok(BlockBuf::new(bytes))
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        cx_checkpoint(cx)?;
        assert_eq!(data.len(), BLOCK_BYTES);
        if self.fail_writes.load(Ordering::Acquire) {
            return Err(FfsError::Io(std::io::Error::other("injected device write failure")));
        }
        self.file.write_all_at(data, block.0 * BLOCK_BYTES as u64)?;
        Ok(())
    }

    fn block_size(&self) -> u32 {
        u32::try_from(BLOCK_BYTES).unwrap()
    }

    fn block_count(&self) -> u64 {
        32
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        cx_checkpoint(cx)?;
        self.file.sync_all()?;
        Ok(())
    }
}

fn fixture() -> ArcCache<DiskDevice> {
    ArcCache::new_with_policy(DiskDevice::new(), 16, ArcWritePolicy::WriteBack).unwrap()
}

fn assert_staging_empty(cache: &ArcCache<DiskDevice>) {
    let state = cache.state.lock();
    assert!(state.staged_txn_writes.is_empty());
    assert!(state.staged_block_owner.is_empty());
    assert!(state.staged_previous_dirty.is_empty());
}

#[test]
fn abort_preserves_acknowledged_unflushed_resident_data() {
    let cx = Cx::for_testing();
    let cache = fixture();
    let block = BlockNumber(2);
    cache.write_block(&cx, block, &[0xA1; BLOCK_BYTES]).unwrap();
    cache
        .stage_txn_write(&cx, TxnId(10), block, &[0xB2; BLOCK_BYTES])
        .unwrap();
    assert_eq!(cache.read_block(&cx, block).unwrap().as_slice(), &[0xA1; BLOCK_BYTES]);
    assert_eq!(cache.inner().bytes(block), vec![0; BLOCK_BYTES]);
    assert_eq!(cache.abort_staged_txn(TxnId(10)), 1);
    assert_eq!(cache.dirty_count(), 1);
    assert_staging_empty(&cache);
    cache.evict(block);
    assert_eq!(cache.dirty_count(), 1, "the committed resident must remain pinned");
    cache.sync(&cx).unwrap();
    assert_eq!(cache.inner().bytes(block), vec![0xA1; BLOCK_BYTES]);
    cache.evict(block);
    assert_eq!(cache.read_block(&cx, block).unwrap().as_slice(), &[0xA1; BLOCK_BYTES]);
}

#[test]
fn abort_restores_transaction_identity_age_and_byte_accounting() {
    let cx = Cx::for_testing();
    let cache = fixture();
    let block = BlockNumber(2);
    cache.stage_txn_write(&cx, TxnId(1), block, &[1; BLOCK_BYTES]).unwrap();
    cache.commit_staged_txn(&cx, TxnId(1), CommitSeq(7)).unwrap();
    cache.write_block(&cx, BlockNumber(3), &[3; BLOCK_BYTES]).unwrap();
    let previous = cache.state.lock().dirty.entry(block).unwrap();
    let order = cache.dirty_blocks_oldest_first();
    let bytes = cache.metrics().dirty_bytes;
    for byte in [8, 9, 10] {
        cache.stage_txn_write(&cx, TxnId(2), block, &[byte; BLOCK_BYTES]).unwrap();
    }
    assert_eq!(cache.abort_staged_txn(TxnId(2)), 1);
    assert_eq!(cache.state.lock().dirty.entry(block), Some(previous));
    assert_eq!(cache.dirty_blocks_oldest_first(), order);
    assert_eq!(cache.metrics().dirty_bytes, bytes);
    assert_eq!(cache.flush_dirty_batch(&cx, 1).unwrap(), 1);
    assert_eq!(cache.inner().bytes(block), vec![1; BLOCK_BYTES]);
    assert_eq!(cache.inner().bytes(BlockNumber(3)), vec![0; BLOCK_BYTES]);
    cache.sync(&cx).unwrap();
    assert_eq!(cache.inner().bytes(BlockNumber(3)), vec![3; BLOCK_BYTES]);
    assert_staging_empty(&cache);
}

#[test]
fn abort_never_restores_an_older_obligation_over_a_direct_write() {
    let cx = Cx::for_testing();
    for restage in [false, true] {
        let cache = fixture();
        let block = BlockNumber(2);
        cache.write_block(&cx, block, &[1; BLOCK_BYTES]).unwrap();
        cache.stage_txn_write(&cx, TxnId(9), block, &[9; BLOCK_BYTES]).unwrap();
        cache.write_block(&cx, block, &[2; BLOCK_BYTES]).unwrap();
        let current = cache.state.lock().dirty.entry(block).unwrap();
        if restage {
            cache.stage_txn_write(&cx, TxnId(9), block, &[8; BLOCK_BYTES]).unwrap();
        }
        let _ = cache.abort_staged_txn(TxnId(9));
        assert_eq!(cache.state.lock().dirty.entry(block), Some(current));
        cache.sync(&cx).unwrap();
        assert_eq!(cache.inner().bytes(block), vec![2; BLOCK_BYTES]);
        assert_staging_empty(&cache);
    }
}

#[test]
fn restaging_after_a_direct_write_was_flushed_does_not_resurrect_old_dirty_state() {
    let cx = Cx::for_testing();
    let cache = fixture();
    let block = BlockNumber(2);
    cache.write_block(&cx, block, &[1; BLOCK_BYTES]).unwrap();
    cache.stage_txn_write(&cx, TxnId(9), block, &[9; BLOCK_BYTES]).unwrap();
    cache.write_block(&cx, block, &[2; BLOCK_BYTES]).unwrap();
    cache.sync(&cx).unwrap();
    cache.stage_txn_write(&cx, TxnId(9), block, &[8; BLOCK_BYTES]).unwrap();
    assert_eq!(cache.abort_staged_txn(TxnId(9)), 1);
    assert_eq!(cache.dirty_count(), 0);
    assert_eq!(cache.inner().bytes(block), vec![2; BLOCK_BYTES]);
    assert_staging_empty(&cache);
}

#[test]
fn abort_restores_retryable_dirty_data_after_a_failed_flush() {
    let cx = Cx::for_testing();
    let cache = fixture();
    let block = BlockNumber(2);
    cache.write_block(&cx, block, &[1; BLOCK_BYTES]).unwrap();
    cache.inner().fail_writes.store(true, Ordering::Release);
    assert!(cache.flush_dirty(&cx).is_err());
    assert!(!cache.state.lock().pending_flush.is_empty());
    cache.stage_txn_write(&cx, TxnId(9), block, &[9; BLOCK_BYTES]).unwrap();
    // A flush during staging filters the old retry candidate, but must not
    // make its resident bytes disposable after the transaction aborts.
    cache.flush_dirty(&cx).unwrap();
    assert!(cache.state.lock().pending_flush.is_empty());
    assert_eq!(cache.abort_staged_txn(TxnId(9)), 1);
    assert_eq!(cache.dirty_count(), 1);
    cache.inner().fail_writes.store(false, Ordering::Release);
    cache.sync(&cx).unwrap();
    assert_eq!(cache.inner().bytes(block), vec![1; BLOCK_BYTES]);
    assert_staging_empty(&cache);
}

#[test]
fn commit_consumes_rollback_state_and_a_later_abort_is_a_noop() {
    let cx = Cx::for_testing();
    let cache = fixture();
    for block in [BlockNumber(2), BlockNumber(3)] {
        cache.write_block(&cx, block, &[1; BLOCK_BYTES]).unwrap();
        cache.stage_txn_write(&cx, TxnId(9), block, &[9; BLOCK_BYTES]).unwrap();
    }
    assert_eq!(cache.commit_staged_txn(&cx, TxnId(9), CommitSeq(10)).unwrap(), 2);
    assert_staging_empty(&cache);
    assert_eq!(cache.abort_staged_txn(TxnId(9)), 0);
    cache.sync(&cx).unwrap();
    for block in [BlockNumber(2), BlockNumber(3)] {
        assert_eq!(cache.inner().bytes(block), vec![9; BLOCK_BYTES]);
    }
}

#[test]
fn conflicting_stager_cannot_change_another_transactions_rollback_state() {
    let cx = Cx::for_testing();
    let cache = fixture();
    let block = BlockNumber(2);
    cache.write_block(&cx, block, &[1; BLOCK_BYTES]).unwrap();
    let previous = cache.state.lock().dirty.entry(block).unwrap();
    cache.stage_txn_write(&cx, TxnId(9), block, &[9; BLOCK_BYTES]).unwrap();
    assert!(cache.stage_txn_write(&cx, TxnId(10), block, &[10; BLOCK_BYTES]).is_err());
    assert_eq!(cache.abort_staged_txn(TxnId(10)), 0);
    assert_eq!(cache.state.lock().staged_previous_dirty.get(&block), Some(&previous));
    assert_eq!(cache.abort_staged_txn(TxnId(9)), 1);
    assert_eq!(cache.state.lock().dirty.entry(block), Some(previous));
    cache.sync(&cx).unwrap();
    assert_eq!(cache.inner().bytes(block), vec![1; BLOCK_BYTES]);
    assert_staging_empty(&cache);
}

#[test]
fn abort_on_initially_clean_blocks_leaves_no_dirty_or_staged_state() {
    let cx = Cx::for_testing();
    let cache = fixture();
    let block = BlockNumber(2);
    cache.read_block(&cx, block).unwrap();
    cache.stage_txn_write(&cx, TxnId(9), block, &[9; BLOCK_BYTES]).unwrap();
    assert_eq!(cache.abort_staged_txn(TxnId(9)), 1);
    assert_eq!(cache.dirty_count(), 0);
    cache.sync(&cx).unwrap();
    assert_eq!(cache.inner().bytes(block), vec![0; BLOCK_BYTES]);
    assert_eq!(cache.read_block(&cx, block).unwrap().as_slice(), &[0; BLOCK_BYTES]);
    assert_staging_empty(&cache);
}

#[cfg(feature = "s3fifo")]
#[test]
fn staged_commit_replaces_warmed_fast_residents_and_revokes_late_old_inserts() {
    let cx = Cx::for_testing();
    let cache =
        ArcCache::new_with_policy(DiskDevice::new(), 512, ArcWritePolicy::WriteBack).unwrap();
    assert!(cache.s3_fast_hits_enabled);
    let block = BlockNumber(2);
    cache.write_block(&cx, block, &[1; BLOCK_BYTES]).unwrap();
    let delayed_old = cache.s3_fast_residents.get_valid(block).unwrap();
    assert_eq!(cache.s3_fast_hit(block).unwrap().as_slice(), &[1; BLOCK_BYTES]);
    assert!(
        cache
            .s3_thread_fast_hit(block, cache.s3_fast_mutation_epoch.load(Ordering::Acquire))
            .is_some()
    );
    cache.stage_txn_write(&cx, TxnId(9), block, &[9; BLOCK_BYTES]).unwrap();
    assert_eq!(cache.read_block(&cx, block).unwrap().as_slice(), &[1; BLOCK_BYTES]);
    cache.commit_staged_txn(&cx, TxnId(9), CommitSeq(10)).unwrap();
    assert_eq!(cache.s3_fast_hit(block).unwrap().as_slice(), &[9; BLOCK_BYTES]);
    assert!(!delayed_old.access.is_valid());
    // Simulate an old read-miss publisher resuming after this commit.
    cache.s3_fast_residents.insert(block, delayed_old);
    assert_eq!(cache.read_block(&cx, block).unwrap().as_slice(), &[9; BLOCK_BYTES]);
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                assert_eq!(
                    cache.read_block(&Cx::for_testing(), block).unwrap().as_slice(),
                    &[9; BLOCK_BYTES]
                );
            })
            .join()
            .unwrap();
    });
    cache.sync(&cx).unwrap();
    assert_eq!(cache.inner().bytes(block), vec![9; BLOCK_BYTES]);
}
