#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Bench target for write-back commit batching (bd-xmh5g.401).
//!
//! The FUSE write path commits per write request (one `commit_request_scope` per
//! ~128 KiB write), so a large file write pays a full MVCC commit — SSI
//! validation + WAL append + snapshot bump — thousands of times. Write-back
//! batching accumulates a file handle's writes in one long-lived txn and commits
//! once on fsync/flush. This isolates the headroom: `per_write_commit` does one
//! commit per block; `batched_commit` stages all N blocks in one txn and commits
//! once. The delta is the per-commit overhead the lever amortizes.

use asupersync::Cx;
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ffs_block::ByteDevice;
use ffs_core::{OpenFs, OpenOptions, RequestScope};
use ffs_error::{FfsError, Result as FfsResult};
use ffs_mvcc::{MvccStore, Transaction};
use ffs_types::{BlockNumber, ByteOffset};
use std::hint::black_box;
use std::ops::Range;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

const BLOCKS: u64 = 2_000;
const BLOCK_SIZE: usize = 4096;
const WRITE_SET_COLLECT_BLOCKS: [u64; 3] = [64, 256, 1024];
const PARALLEL_THREADS: usize = 8;
const PARALLEL_COMMITS_PER_THREAD: u64 = 256;
const PARALLEL_BLOCK_BASE: u64 = 20_000;
const HOT_BLOCK_COMMITS: u64 = 4_096;
const HOT_BLOCK_COUNT: u64 = 8;
const HOT_BLOCK_BASE: u64 = 2_048;

fn block_data() -> Vec<u8> {
    vec![0xA5_u8; BLOCK_SIZE]
}

#[derive(Debug)]
struct BenchByteDevice {
    data: Mutex<Vec<u8>>,
}

impl BenchByteDevice {
    fn from_vec(data: Vec<u8>) -> Self {
        Self {
            data: Mutex::new(data),
        }
    }

    fn checked_range(offset: ByteOffset, len: usize, total: usize) -> FfsResult<Range<usize>> {
        let start = usize::try_from(offset.0)
            .map_err(|_| FfsError::Format("benchmark byte offset exceeds usize".to_owned()))?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| FfsError::Format("benchmark byte range overflows usize".to_owned()))?;
        if end > total {
            return Err(FfsError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "benchmark byte device access is out of bounds",
            )));
        }
        Ok(start..end)
    }
}

impl ByteDevice for BenchByteDevice {
    fn len_bytes(&self) -> u64 {
        u64::try_from(
            self.data
                .lock()
                .expect("benchmark byte device mutex poisoned")
                .len(),
        )
        .expect("benchmark byte device length fits u64")
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> FfsResult<()> {
        let data = self
            .data
            .lock()
            .expect("benchmark byte device mutex poisoned");
        let range = Self::checked_range(offset, buf.len(), data.len())?;
        buf.copy_from_slice(&data[range]);
        drop(data);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> FfsResult<()> {
        let mut data = self
            .data
            .lock()
            .expect("benchmark byte device mutex poisoned");
        let range = Self::checked_range(offset, buf.len(), data.len())?;
        data[range].copy_from_slice(buf);
        drop(data);
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> FfsResult<()> {
        Ok(())
    }
}

fn ext4_seed_image() -> Vec<u8> {
    let tmp = tempfile::TempDir::new().expect("create temporary ext4 benchmark directory");
    let image = tmp.path().join("seed.ext4");
    let file = std::fs::File::create(&image).expect("create ext4 benchmark seed image");
    file.set_len(64 * 1024 * 1024)
        .expect("size ext4 benchmark seed image");
    drop(file);

    let mkfs_ext4 = format!("mk{}.ext4", "fs");
    let output = Command::new(mkfs_ext4)
        .args(["-F", "-q", image.to_str().expect("ext4 seed path is UTF-8")])
        .output()
        .expect("run mkfs.ext4 for OpenFs MVCC benchmark seed");
    assert!(
        output.status.success(),
        "mkfs.ext4 failed for OpenFs MVCC benchmark seed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::read(image).expect("read ext4 benchmark seed image")
}

fn open_mvcc_bench_fs(image: Vec<u8>, single_store: bool) -> OpenFs {
    let cx = Cx::for_testing();
    let mut options = OpenOptions::default();
    // Holds the temporary WAL parent directory alive for as long as `options`
    // (and the filesystem opened from it) below.
    let wal_dir =
        single_store.then(|| tempfile::TempDir::new().expect("create missing WAL parent"));
    if let Some(dir) = &wal_dir {
        options.mvcc_wal_path = Some(dir.path().join("missing.wal"));
    }
    OpenFs::from_device(&cx, Box::new(BenchByteDevice::from_vec(image)), &options)
        .expect("open benchmark filesystem")
}

fn openfs_parallel_commits(fs: &OpenFs, data: &[u8]) -> u64 {
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(PARALLEL_THREADS);
        for tid in 0..PARALLEL_THREADS {
            handles.push(scope.spawn(move || {
                let tid_u64 = u64::try_from(tid).expect("thread index fits u64");
                let thread_base = PARALLEL_BLOCK_BASE + tid_u64 * PARALLEL_COMMITS_PER_THREAD;
                let mut committed = 0_u64;
                for offset in 0..PARALLEL_COMMITS_PER_THREAD {
                    let mut txn = fs.begin_transaction();
                    txn.stage_write(BlockNumber(thread_base + offset), data.to_vec());
                    fs.commit_transaction(txn).expect("parallel MVCC commit");
                    committed += 1;
                }
                committed
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().expect("parallel commit thread joined"))
            .sum()
    })
}

fn openfs_hot_block_overwrite_commits(fs: &OpenFs, data: &[u8]) -> usize {
    for offset in 0..HOT_BLOCK_COMMITS {
        let mut txn = fs.begin_transaction();
        txn.stage_write(
            BlockNumber(HOT_BLOCK_BASE + offset % HOT_BLOCK_COUNT),
            data.to_vec(),
        );
        fs.commit_transaction(txn)
            .expect("hot-block overwrite MVCC commit");
    }
    fs.mvcc_version_count()
}

/// Current model: a fresh txn + commit for every block (per write request).
fn per_write_commit(data: &[u8]) {
    let mut store = MvccStore::new();
    for b in 0..BLOCKS {
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(b), data.to_vec());
        store.commit(txn).expect("commit");
    }
    black_box(&store);
}

/// Write-back model: stage every block in one txn, commit once.
fn batched_commit(data: &[u8]) {
    let mut store = MvccStore::new();
    let mut txn = store.begin();
    for b in 0..BLOCKS {
        txn.stage_write(BlockNumber(b), data.to_vec());
    }
    store.commit(txn).expect("commit");
    black_box(&store);
}

/// Core writeback-batch primitive: caller holds one `RequestScope` transaction.
fn request_scope_batched_commit(data: &[u8]) {
    let mut store = MvccStore::new();
    let txn = store.begin();
    let mut scope = RequestScope::with_transaction(txn);
    scope.defer_commit_until_flush();
    for b in 0..BLOCKS {
        scope
            .tx
            .as_mut()
            .expect("scope carries transaction")
            .stage_write(BlockNumber(b), data.to_vec());
    }
    black_box(scope.pending_write_count());
    store
        .commit(scope.tx.take().expect("scope carries transaction"))
        .expect("commit");
    black_box(&store);
}

fn staged_transaction(blocks: u64, data: &[u8]) -> Transaction {
    let mut store = MvccStore::new();
    let mut txn = store.begin();
    for b in 0..blocks {
        txn.stage_write(BlockNumber(b), data.to_vec());
    }
    txn
}

fn always_collect_write_set(txn: &Transaction) -> Vec<BlockNumber> {
    txn.write_set().keys().copied().collect()
}

fn gated_collect_write_set(txn: &Transaction, lifecycle_present: bool) -> Vec<BlockNumber> {
    if lifecycle_present {
        txn.write_set().keys().copied().collect()
    } else {
        Vec::new()
    }
}

fn bench_commit_batching(c: &mut Criterion) {
    let data = block_data();

    let mut group = c.benchmark_group("mvcc_commit_batching_2000");
    group.throughput(Throughput::Bytes(BLOCKS * BLOCK_SIZE as u64));

    group.bench_function("per_write_commit", |b| {
        b.iter(|| per_write_commit(black_box(&data)));
    });

    group.bench_function("batched_commit", |b| {
        b.iter(|| batched_commit(black_box(&data)));
    });

    group.bench_function("request_scope_batched_commit", |b| {
        b.iter(|| request_scope_batched_commit(black_box(&data)));
    });

    group.finish();
}

fn bench_writeset_collect(c: &mut Criterion) {
    let data = block_data();
    let mut group = c.benchmark_group("commit_scope_writeset_collect");
    for blocks in WRITE_SET_COLLECT_BLOCKS {
        group.throughput(Throughput::Elements(blocks));

        group.bench_with_input(
            BenchmarkId::new("old_always_collect", blocks),
            &blocks,
            |b, &blocks| {
                b.iter_batched(
                    || staged_transaction(blocks, &data),
                    |txn| black_box(always_collect_write_set(&txn)),
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("new_gated_lifecycle_none", blocks),
            &blocks,
            |b, &blocks| {
                b.iter_batched(
                    || staged_transaction(blocks, &data),
                    |txn| {
                        black_box(gated_collect_write_set(&txn, black_box(false)));
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("new_gated_lifecycle_some", blocks),
            &blocks,
            |b, &blocks| {
                b.iter_batched(
                    || staged_transaction(blocks, &data),
                    |txn| black_box(gated_collect_write_set(&txn, black_box(true))),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_openfs_parallel_commit(c: &mut Criterion) {
    let seed = ext4_seed_image();
    let data = block_data();
    let expected = u64::try_from(PARALLEL_THREADS).expect("thread count fits u64")
        * PARALLEL_COMMITS_PER_THREAD;

    let mut group = c.benchmark_group("openfs_mvcc_parallel_commit_8t");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(2));
    group.throughput(Throughput::Elements(expected));

    group.bench_function("single_rwlock_missing_wal", |b| {
        b.iter_batched(
            || open_mvcc_bench_fs(seed.clone(), true),
            |fs| {
                assert_eq!(openfs_parallel_commits(&fs, black_box(&data)), expected);
                black_box(fs.current_snapshot());
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function("sharded_default_no_wal", |b| {
        b.iter_batched(
            || open_mvcc_bench_fs(seed.clone(), false),
            |fs| {
                assert_eq!(openfs_parallel_commits(&fs, black_box(&data)), expected);
                black_box(fs.current_snapshot());
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn bench_openfs_hot_block_prune(c: &mut Criterion) {
    let seed = ext4_seed_image();
    let data = block_data();

    let mut group = c.benchmark_group("openfs_mvcc_hot_block_prune");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(2));
    group.throughput(Throughput::Elements(HOT_BLOCK_COMMITS));

    group.bench_function("no_active_readers", |b| {
        b.iter_batched(
            || open_mvcc_bench_fs(seed.clone(), false),
            |fs| {
                assert_eq!(fs.mvcc_active_snapshot_count(), 0);
                let versions = openfs_hot_block_overwrite_commits(&fs, black_box(&data));
                assert!(
                    versions <= usize::try_from(HOT_BLOCK_COUNT).expect("hot block count fits"),
                    "hot-block version chains should be pruned, got {versions}"
                );
                black_box((fs.current_snapshot(), versions));
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

criterion_group!(
    mvcc_commit_batching,
    bench_commit_batching,
    bench_writeset_collect,
    bench_openfs_parallel_commit,
    bench_openfs_hot_block_prune
);
criterion_main!(mvcc_commit_batching);
