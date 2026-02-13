#![forbid(unsafe_code)]

use asupersync::Cx;
use ffs_block::{
    ArcCache, ArcWritePolicy, BlockDevice, ByteBlockDevice, ByteDevice, FlushDaemonConfig,
};
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, ByteOffset, CommitSeq, TxnId};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BLOCK_SIZE: u32 = 4096;

#[derive(Clone, Debug)]
struct SharedMemoryByteDevice {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl SharedMemoryByteDevice {
    fn new(len: usize) -> Self {
        Self {
            bytes: Arc::new(Mutex::new(vec![0_u8; len])),
        }
    }
}

impl ByteDevice for SharedMemoryByteDevice {
    fn len_bytes(&self) -> u64 {
        u64::try_from(self.bytes.lock().len()).unwrap_or(0)
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset.0)
            .map_err(|_| FfsError::Format("offset overflow".to_owned()))?;
        let end = start
            .checked_add(buf.len())
            .ok_or_else(|| FfsError::Format("read range overflow".to_owned()))?;
        let bytes = self.bytes.lock();
        if end > bytes.len() {
            return Err(FfsError::Format("read oob".to_owned()));
        }
        buf.copy_from_slice(&bytes[start..end]);
        drop(bytes);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        let start = usize::try_from(offset.0)
            .map_err(|_| FfsError::Format("offset overflow".to_owned()))?;
        let end = start
            .checked_add(buf.len())
            .ok_or_else(|| FfsError::Format("write range overflow".to_owned()))?;
        let mut bytes = self.bytes.lock();
        if end > bytes.len() {
            return Err(FfsError::Format("write oob".to_owned()));
        }
        bytes[start..end].copy_from_slice(buf);
        drop(bytes);
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct CountingBlockDevice<D: BlockDevice> {
    inner: D,
    writes: Mutex<Vec<BlockNumber>>,
    sync_calls: AtomicUsize,
}

impl<D: BlockDevice> CountingBlockDevice<D> {
    fn new(inner: D) -> Self {
        Self {
            inner,
            writes: Mutex::new(Vec::new()),
            sync_calls: AtomicUsize::new(0),
        }
    }

    fn write_count(&self) -> usize {
        self.writes.lock().len()
    }

    fn write_sequence(&self) -> Vec<BlockNumber> {
        self.writes.lock().clone()
    }

    fn sync_count(&self) -> usize {
        self.sync_calls.load(Ordering::SeqCst)
    }
}

impl<D: BlockDevice> BlockDevice for CountingBlockDevice<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<ffs_block::BlockBuf> {
        self.inner.read_block(cx, block)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        self.writes.lock().push(block);
        self.inner.write_block(cx, block, data)
    }

    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.sync_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sync(cx)
    }
}

type TestDevice = CountingBlockDevice<ByteBlockDevice<SharedMemoryByteDevice>>;
type WriteBackCache = ArcCache<TestDevice>;

fn block_payload(block: u64, salt: u8) -> Vec<u8> {
    let mut out = vec![salt; BLOCK_SIZE as usize];
    let bytes = block.to_le_bytes();
    for (idx, byte) in bytes.iter().enumerate() {
        out[idx] = *byte;
    }
    out
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn wait_for_dirty_drain(cache: &Arc<WriteBackCache>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cache.dirty_count() == 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(cache.dirty_count(), 0, "dirty blocks did not drain in time");
}

fn build_writeback_cache(shared: SharedMemoryByteDevice, capacity: usize) -> WriteBackCache {
    let block_dev = ByteBlockDevice::new(shared, BLOCK_SIZE).expect("byte block device");
    let counted = CountingBlockDevice::new(block_dev);
    ArcCache::new_with_policy(counted, capacity, ArcWritePolicy::WriteBack)
        .expect("write-back cache")
}

fn build_read_cache(
    shared: SharedMemoryByteDevice,
    capacity: usize,
) -> ArcCache<ByteBlockDevice<SharedMemoryByteDevice>> {
    let block_dev = ByteBlockDevice::new(shared, BLOCK_SIZE).expect("byte block device");
    ArcCache::new(block_dev, capacity).expect("read cache")
}

#[test]
fn scenario_1_basic_flush_correctness() {
    let cx = Cx::for_testing();
    let shared = SharedMemoryByteDevice::new(BLOCK_SIZE as usize * 1600);
    let cache = Arc::new(build_writeback_cache(shared.clone(), 1200));
    let daemon = cache
        .start_flush_daemon(FlushDaemonConfig {
            interval: Duration::from_millis(20),
            batch_size: 256,
            high_watermark: 0.99,
            critical_watermark: 1.0,
        })
        .expect("start flush daemon");

    let mut checksums = HashMap::new();
    for block in 0_u64..1000_u64 {
        let payload = block_payload(block, 0xA5);
        checksums.insert(block, blake3_hex(&payload));
        cache
            .write_block(&cx, BlockNumber(block), &payload)
            .expect("write block");
    }

    wait_for_dirty_drain(&cache, Duration::from_millis(120));
    daemon.shutdown();

    let reopened = build_read_cache(shared, 256);
    for block in 0_u64..1000_u64 {
        let data = reopened
            .read_block(&cx, BlockNumber(block))
            .expect("read block after remount");
        assert_eq!(blake3_hex(data.as_slice()), checksums[&block]);
    }
}

#[test]
fn scenario_2_clean_unmount_flushes_everything() {
    let cx = Cx::for_testing();
    let shared = SharedMemoryByteDevice::new(BLOCK_SIZE as usize * 900);
    let cache = Arc::new(build_writeback_cache(shared.clone(), 700));
    let daemon = cache
        .start_flush_daemon(FlushDaemonConfig {
            interval: Duration::from_secs(2),
            batch_size: 64,
            ..FlushDaemonConfig::default()
        })
        .expect("start flush daemon");

    let mut checksums = HashMap::new();
    for block in 0_u64..500_u64 {
        let payload = block_payload(block, 0x2A);
        checksums.insert(block, blake3_hex(&payload));
        cache
            .write_block(&cx, BlockNumber(block), &payload)
            .expect("write block");
    }

    assert!(
        cache.dirty_count() > 0,
        "expected dirty blocks before unmount"
    );
    daemon.shutdown();
    assert_eq!(
        cache.dirty_count(),
        0,
        "shutdown must flush all dirty blocks"
    );

    let reopened = build_read_cache(shared, 256);
    for block in 0_u64..500_u64 {
        let data = reopened
            .read_block(&cx, BlockNumber(block))
            .expect("read block after clean unmount");
        assert_eq!(blake3_hex(data.as_slice()), checksums[&block]);
    }
}

#[test]
fn scenario_3_sigkill_dirty_block_loss_is_clean() {
    let cx = Cx::for_testing();
    let shared = SharedMemoryByteDevice::new(BLOCK_SIZE as usize * 1200);
    let cache = build_writeback_cache(shared.clone(), 1100);

    let mut durable = HashMap::new();
    for block in 0_u64..100_u64 {
        let payload = block_payload(block, 0x10);
        durable.insert(block, blake3_hex(&payload));
        cache
            .write_block(&cx, BlockNumber(block), &payload)
            .expect("baseline write");
    }
    cache.sync(&cx).expect("sync durable baseline");

    let mut non_fsync = HashMap::new();
    for block in 100_u64..300_u64 {
        let payload = block_payload(block, 0x77);
        non_fsync.insert(block, blake3_hex(&payload));
        cache
            .write_block(&cx, BlockNumber(block), &payload)
            .expect("non-fsync write");
    }

    // Simulated SIGKILL: process exits without sync/clean shutdown.
    drop(cache);

    let reopened = build_read_cache(shared, 256);
    let zero_checksum = blake3_hex(&vec![0_u8; BLOCK_SIZE as usize]);

    for block in 0_u64..100_u64 {
        let data = reopened
            .read_block(&cx, BlockNumber(block))
            .expect("read durable block");
        assert_eq!(blake3_hex(data.as_slice()), durable[&block]);
    }

    for block in 100_u64..300_u64 {
        let data = reopened
            .read_block(&cx, BlockNumber(block))
            .expect("read non-fsync block");
        let checksum = blake3_hex(data.as_slice());
        assert!(
            checksum == zero_checksum || checksum == non_fsync[&block],
            "non-fsync block must be absent (zero) or fully present"
        );
    }
}

#[test]
fn scenario_4_abort_discards_dirty_blocks() {
    let cx = Cx::for_testing();
    let shared = SharedMemoryByteDevice::new(BLOCK_SIZE as usize * 512);
    let cache = build_writeback_cache(shared.clone(), 256);

    let mut committed = HashMap::new();
    for block in 0_u64..50_u64 {
        let payload = block_payload(block, 0x33);
        committed.insert(block, blake3_hex(&payload));
        cache
            .write_block(&cx, BlockNumber(block), &payload)
            .expect("commit baseline write");
    }
    cache.sync(&cx).expect("sync committed baseline");
    let writes_before_abort = cache.inner().write_count();

    for block in 0_u64..50_u64 {
        let payload = block_payload(block, 0xF0);
        cache
            .stage_txn_write(&cx, TxnId(500), BlockNumber(block), &payload)
            .expect("stage txn write");
    }
    assert!(cache.dirty_count() > 0);

    let discarded = cache.abort_staged_txn(TxnId(500));
    assert_eq!(discarded, 50);
    cache.flush_dirty(&cx).expect("flush after abort");

    assert_eq!(cache.inner().write_count(), writes_before_abort);

    let reopened = build_read_cache(shared, 128);
    for block in 0_u64..50_u64 {
        let data = reopened
            .read_block(&cx, BlockNumber(block))
            .expect("read committed block");
        assert_eq!(blake3_hex(data.as_slice()), committed[&block]);
    }
}

#[test]
fn scenario_5_backpressure_under_load() {
    let cache = Arc::new(build_writeback_cache(
        SharedMemoryByteDevice::new(BLOCK_SIZE as usize * 2048),
        16,
    ));
    let daemon = cache
        .start_flush_daemon(FlushDaemonConfig {
            interval: Duration::from_millis(10),
            batch_size: 4,
            high_watermark: 0.5,
            critical_watermark: 0.75,
        })
        .expect("start flush daemon");

    let writer = {
        let cache = Arc::clone(&cache);
        std::thread::spawn(move || {
            let cx = Cx::for_testing();
            for i in 0_u64..600_u64 {
                let payload = block_payload(i, 0x4D);
                cache
                    .write_block(&cx, BlockNumber(i), &payload)
                    .expect("write under pressure");
            }
        })
    };

    writer.join().expect("writer thread join");
    wait_for_dirty_drain(&cache, Duration::from_secs(2));
    daemon.shutdown();

    let metrics = cache.metrics();
    assert!(
        metrics.dirty_blocks <= metrics.capacity,
        "backpressure must prevent unbounded dirty growth"
    );
    assert!(
        cache.inner().write_count() > 0,
        "flushes must persist writes"
    );
}

#[test]
fn scenario_6_concurrent_transactions_and_flush() {
    let cx = Cx::for_testing();
    let shared = SharedMemoryByteDevice::new(BLOCK_SIZE as usize * 2048);
    let cache = Arc::new(build_writeback_cache(shared.clone(), 512));
    let daemon = cache
        .start_flush_daemon(FlushDaemonConfig {
            interval: Duration::from_millis(10),
            batch_size: 64,
            ..FlushDaemonConfig::default()
        })
        .expect("start flush daemon");

    let mut handles = Vec::new();
    for (txn_id, start_block, should_commit, commit_seq, salt) in [
        (TxnId(1), 0_u64, true, CommitSeq(10), 0x11),
        (TxnId(2), 100_u64, false, CommitSeq(20), 0x22),
        (TxnId(3), 200_u64, true, CommitSeq(30), 0x33),
        (TxnId(4), 300_u64, false, CommitSeq(40), 0x44),
    ] {
        let cache = Arc::clone(&cache);
        handles.push(std::thread::spawn(move || {
            let cx = Cx::for_testing();
            for offset in 0_u64..100_u64 {
                let block = start_block + offset;
                let payload = block_payload(block, salt);
                cache
                    .stage_txn_write(&cx, txn_id, BlockNumber(block), &payload)
                    .expect("stage txn write");
            }
            if should_commit {
                cache
                    .commit_staged_txn(&cx, txn_id, commit_seq)
                    .expect("commit txn");
            } else {
                let discarded = cache.abort_staged_txn(txn_id);
                assert_eq!(discarded, 100);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("worker join");
    }

    wait_for_dirty_drain(&cache, Duration::from_secs(2));
    daemon.shutdown();

    let reopened = build_read_cache(shared, 256);
    let zero_checksum = blake3_hex(&vec![0_u8; BLOCK_SIZE as usize]);

    for block in 0_u64..100_u64 {
        let data = reopened
            .read_block(&cx, BlockNumber(block))
            .expect("read committed range 1");
        assert_eq!(
            blake3_hex(data.as_slice()),
            blake3_hex(&block_payload(block, 0x11))
        );
    }
    for block in 100_u64..200_u64 {
        let data = reopened
            .read_block(&cx, BlockNumber(block))
            .expect("read aborted range 1");
        assert_eq!(blake3_hex(data.as_slice()), zero_checksum);
    }
    for block in 200_u64..300_u64 {
        let data = reopened
            .read_block(&cx, BlockNumber(block))
            .expect("read committed range 2");
        assert_eq!(
            blake3_hex(data.as_slice()),
            blake3_hex(&block_payload(block, 0x33))
        );
    }
    for block in 300_u64..400_u64 {
        let data = reopened
            .read_block(&cx, BlockNumber(block))
            .expect("read aborted range 2");
        assert_eq!(blake3_hex(data.as_slice()), zero_checksum);
    }

    let writes = cache.inner().write_sequence();
    assert!(writes.iter().any(|block| block.0 < 100));
    assert!(writes.iter().any(|block| (200..300).contains(&block.0)));
    assert!(!writes.iter().any(|block| (100..200).contains(&block.0)));
    assert!(!writes.iter().any(|block| (300..400).contains(&block.0)));

    assert_eq!(cache.inner().sync_count(), 0);
}
