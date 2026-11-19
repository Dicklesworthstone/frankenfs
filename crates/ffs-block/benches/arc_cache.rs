#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

use asupersync::Cx;
use criterion::{BatchSize, Criterion, criterion_group};
use ffs_block::{
    ArcCache, ArcWritePolicy, BlockBuf, BlockDevice, ByteBlockDevice, ByteDevice, MemoryPressure,
    ShardedArcCache, ShardedExtentReadCache,
};
use ffs_error::Result;
use ffs_types::{BlockNumber, ByteOffset, TxnId};
use parking_lot::Mutex;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::env;
use std::fs::{self, File};
use std::hint::black_box;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc as StdArc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

const BLOCK_SIZE_4K: u32 = 4096;
const WORKLOAD_REPORT_ENV: &str = "FFS_BLOCK_CACHE_WORKLOAD_REPORT";
const POLICY_ARC: &str = "arc";
const POLICY_S3FIFO: &str = "s3fifo";

// ── In-memory ByteDevice for benchmarks (no file I/O) ──────────────────

#[derive(Debug)]
struct MemByteDevice {
    bytes: Mutex<Vec<u8>>,
}

impl MemByteDevice {
    fn new(size: usize) -> Self {
        Self {
            bytes: Mutex::new(vec![0u8; size]),
        }
    }
}

#[allow(clippy::cast_possible_truncation)]
impl ByteDevice for MemByteDevice {
    fn len_bytes(&self) -> u64 {
        self.bytes.lock().len() as u64
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let off = offset.0 as usize;
        let guard = self.bytes.lock();
        buf.copy_from_slice(&guard[off..off + buf.len()]);
        drop(guard);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        let off = offset.0 as usize;
        let mut guard = self.bytes.lock();
        guard[off..off + buf.len()].copy_from_slice(buf);
        drop(guard);
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

#[allow(clippy::cast_possible_truncation)]
fn make_cache(
    block_size: u32,
    block_count: usize,
    capacity: usize,
) -> ArcCache<ByteBlockDevice<MemByteDevice>> {
    let mem = MemByteDevice::new(block_size as usize * block_count);
    let dev = ByteBlockDevice::new(mem, block_size).expect("device");
    ArcCache::new(dev, capacity).expect("cache")
}

#[allow(clippy::cast_possible_truncation)]
fn make_writeback_cache(
    block_size: u32,
    block_count: usize,
    capacity: usize,
) -> ArcCache<ByteBlockDevice<MemByteDevice>> {
    let mem = MemByteDevice::new(block_size as usize * block_count);
    let dev = ByteBlockDevice::new(mem, block_size).expect("device");
    ArcCache::new_with_policy(dev, capacity, ArcWritePolicy::WriteBack).expect("cache")
}

fn make_sharded_cache(
    block_size: u32,
    block_count: usize,
    capacity: usize,
    shard_count: usize,
) -> ShardedArcCache<ByteBlockDevice<MemByteDevice>> {
    let byte_len = usize::try_from(block_size).expect("block size fits usize") * block_count;
    let dev = ByteBlockDevice::new(MemByteDevice::new(byte_len), block_size).expect("device");
    ShardedArcCache::new(dev, capacity, shard_count).expect("sharded cache")
}

#[derive(Debug, Clone, Copy)]
struct Rng64 {
    state: u64,
}

impl Rng64 {
    fn seeded(seed: u64) -> Self {
        Self {
            state: seed.wrapping_add(0x9E37_79B9_7F4A_7C15),
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    fn next_usize(&mut self, upper: usize) -> usize {
        if upper <= 1 {
            return 0;
        }
        (self.next_u64() % upper as u64) as usize
    }

    fn next_f64(&mut self) -> f64 {
        let value = self.next_u64() >> 11;
        value as f64 * (1.0 / (1_u64 << 53) as f64)
    }
}

#[derive(Debug, Clone)]
struct WorkloadCase {
    workload: &'static str,
    seed: u64,
    block_count: usize,
    capacity: usize,
    trace: Vec<BlockNumber>,
}

#[derive(Debug, Clone, Copy)]
struct WorkloadMetricsSnapshot {
    policy: &'static str,
    workload: &'static str,
    accesses: usize,
    hits: u64,
    misses: u64,
    hit_rate: f64,
    resident: usize,
    capacity: usize,
    b1_len: usize,
    b2_len: usize,
    memory_overhead_per_cached_block: f64,
}

#[must_use]
fn policy_label() -> &'static str {
    if cfg!(feature = "s3fifo") {
        POLICY_S3FIFO
    } else {
        POLICY_ARC
    }
}

fn zipf_cdf(domain: usize, exponent: f64) -> Vec<f64> {
    let mut cdf = Vec::with_capacity(domain);
    let mut total = 0.0_f64;
    for rank in 1..=domain {
        total += 1.0 / (rank as f64).powf(exponent);
        cdf.push(total);
    }
    if total > 0.0 {
        for probability in &mut cdf {
            *probability /= total;
        }
    }
    cdf
}

fn sample_zipf(cdf: &[f64], rng: &mut Rng64) -> usize {
    let needle = rng.next_f64();
    let idx =
        match cdf.binary_search_by(|value| value.partial_cmp(&needle).unwrap_or(Ordering::Less)) {
            Ok(pos) | Err(pos) => pos,
        };
    idx.min(cdf.len().saturating_sub(1))
}

fn sequential_scan_case() -> WorkloadCase {
    let block_count = 4_096_usize;
    let capacity = 512_usize;
    let seed = 0xA1A1_0001_u64;
    let passes = 4_usize;
    let mut trace = Vec::with_capacity(block_count * passes);
    for _ in 0..passes {
        for block in 0..block_count as u64 {
            trace.push(BlockNumber(block));
        }
    }

    WorkloadCase {
        workload: "sequential_scan",
        seed,
        block_count,
        capacity,
        trace,
    }
}

fn zipf_case() -> WorkloadCase {
    let block_count = 4_096_usize;
    let capacity = 512_usize;
    let seed = 0xA1A1_0002_u64;
    let accesses = 24_000_usize;
    let zipf = zipf_cdf(block_count, 1.07);
    let mut rng = Rng64::seeded(seed);
    let mut trace = Vec::with_capacity(accesses);
    for _ in 0..accesses {
        let sampled = sample_zipf(&zipf, &mut rng) as u64;
        trace.push(BlockNumber(sampled));
    }

    WorkloadCase {
        workload: "zipf_distribution",
        seed,
        block_count,
        capacity,
        trace,
    }
}

fn mixed_seq_hot_case() -> WorkloadCase {
    let block_count = 4_096_usize;
    let capacity = 512_usize;
    let seed = 0xA1A1_0003_u64;
    let accesses = 24_000_usize;
    let hot_set_len = 64_usize;
    let hot_set: Vec<BlockNumber> = (0..hot_set_len)
        .map(|idx| BlockNumber(idx as u64))
        .collect();
    let mut rng = Rng64::seeded(seed);
    let mut sequential_cursor = 0_u64;
    let mut trace = Vec::with_capacity(accesses);
    for _ in 0..accesses {
        if rng.next_f64() < 0.70 {
            trace.push(BlockNumber(sequential_cursor % block_count as u64));
            sequential_cursor = sequential_cursor.wrapping_add(1);
        } else {
            trace.push(hot_set[rng.next_usize(hot_set.len())]);
        }
    }

    WorkloadCase {
        workload: "mixed_seq70_hot30",
        seed,
        block_count,
        capacity,
        trace,
    }
}

fn compile_like_case() -> WorkloadCase {
    let seed = 0xA1A1_0004_u64;
    let capacity = 640_usize;
    let metadata_hot_blocks = 32_u64;
    let small_files = 1_536_usize;
    let large_files = 24_usize;
    let large_file_blocks = 96_usize;
    let rounds = 16_usize;
    let small_base = metadata_hot_blocks;
    let large_base = small_base + small_files as u64 + 128;
    let block_count = large_base as usize + large_files * large_file_blocks + 256;
    let mut rng = Rng64::seeded(seed);
    let mut trace =
        Vec::with_capacity(rounds * (metadata_hot_blocks as usize + 320 + 6 * large_file_blocks));

    for _ in 0..rounds {
        for block in 0..metadata_hot_blocks {
            trace.push(BlockNumber(block));
        }

        for _ in 0..320_usize {
            let file = rng.next_usize(small_files);
            trace.push(BlockNumber(small_base + file as u64));
        }

        for _ in 0..6_usize {
            let large = rng.next_usize(large_files);
            let start = large_base + (large * large_file_blocks) as u64;
            for offset in 0..large_file_blocks as u64 {
                trace.push(BlockNumber(start + offset));
            }
        }
    }

    WorkloadCase {
        workload: "compile_like",
        seed,
        block_count,
        capacity,
        trace,
    }
}

fn database_like_case() -> WorkloadCase {
    let seed = 0xA1A1_0005_u64;
    let capacity = 768_usize;
    let root_pages = [0_u64, 1_u64];
    let internal_start = 2_u64;
    let internal_pages = 128_usize;
    let leaf_start = 512_u64;
    let leaf_pages = 8_192_usize;
    let lookups = 12_000_usize;
    let leaf_zipf = zipf_cdf(leaf_pages, 1.12);
    let block_count = leaf_start as usize + leaf_pages + 256;
    let mut rng = Rng64::seeded(seed);
    let mut trace = Vec::with_capacity(lookups * 4);

    for _ in 0..lookups {
        trace.push(BlockNumber(root_pages[rng.next_usize(root_pages.len())]));
        trace.push(BlockNumber(
            internal_start + rng.next_usize(internal_pages) as u64,
        ));
        trace.push(BlockNumber(
            leaf_start + sample_zipf(&leaf_zipf, &mut rng) as u64,
        ));

        if rng.next_usize(100) < 2 {
            let scan_start = rng.next_usize(leaf_pages.saturating_sub(12));
            for offset in 0..12_usize {
                trace.push(BlockNumber(leaf_start + (scan_start + offset) as u64));
            }
        }
    }

    WorkloadCase {
        workload: "database_like",
        seed,
        block_count,
        capacity,
        trace,
    }
}

fn repeated_working_set_case() -> WorkloadCase {
    let seed = 0xA1A1_0006_u64;
    let capacity = 1_024_usize;
    let working_set = 768_usize;
    let cold_noise = 2_048_usize;
    let block_count = working_set + cold_noise + 64;
    let accesses = 20_000_usize;
    let mut rng = Rng64::seeded(seed);
    let mut trace = Vec::with_capacity(accesses);
    for _ in 0..accesses {
        if rng.next_usize(100) < 96 {
            trace.push(BlockNumber(rng.next_usize(working_set) as u64));
        } else {
            trace.push(BlockNumber(
                (working_set + rng.next_usize(cold_noise)) as u64,
            ));
        }
    }
    WorkloadCase {
        workload: "repeated_working_set",
        seed,
        block_count,
        capacity,
        trace,
    }
}

fn all_workload_cases() -> Vec<WorkloadCase> {
    vec![
        sequential_scan_case(),
        zipf_case(),
        mixed_seq_hot_case(),
        compile_like_case(),
        database_like_case(),
        repeated_working_set_case(),
    ]
}

fn replay_trace(cx: &Cx, cache: &ArcCache<ByteBlockDevice<MemByteDevice>>, trace: &[BlockNumber]) {
    for block in trace {
        let _ = cache.read_block(cx, *block).expect("cache read");
    }
}

fn run_workload(case: &WorkloadCase) -> WorkloadMetricsSnapshot {
    let cx = Cx::for_testing();
    let cache = make_cache(BLOCK_SIZE_4K, case.block_count, case.capacity);
    replay_trace(&cx, &cache, &case.trace);
    let metrics = cache.metrics();
    let ghost_entries = metrics.b1_len + metrics.b2_len;
    let memory_overhead_per_cached_block = if metrics.resident == 0 {
        0.0
    } else {
        ghost_entries as f64 / metrics.resident as f64
    };

    WorkloadMetricsSnapshot {
        policy: policy_label(),
        workload: case.workload,
        accesses: case.trace.len(),
        hits: metrics.hits,
        misses: metrics.misses,
        hit_rate: metrics.hit_ratio(),
        resident: metrics.resident,
        capacity: metrics.capacity,
        b1_len: metrics.b1_len,
        b2_len: metrics.b2_len,
        memory_overhead_per_cached_block,
    }
}

fn write_workload_report_to_writer<W: Write>(writer: &mut W) -> io::Result<()> {
    writeln!(
        writer,
        "policy\tworkload\taccesses\thits\tmisses\thit_rate\tresident\tcapacity\tb1_len\tb2_len\tmemory_overhead_per_cached_block\tseed"
    )?;

    for case in all_workload_cases() {
        let metrics = run_workload(&case);
        writeln!(
            writer,
            "{}\t{}\t{}\t{}\t{}\t{:.6}\t{}\t{}\t{}\t{}\t{:.6}\t{}",
            metrics.policy,
            metrics.workload,
            metrics.accesses,
            metrics.hits,
            metrics.misses,
            metrics.hit_rate,
            metrics.resident,
            metrics.capacity,
            metrics.b1_len,
            metrics.b2_len,
            metrics.memory_overhead_per_cached_block,
            case.seed,
        )?;
    }
    writer.flush()
}

fn write_workload_report(path: &Path) -> io::Result<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    write_workload_report_to_writer(&mut writer)
}

fn write_workload_report_stdout() -> io::Result<()> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    write_workload_report_to_writer(&mut lock)
}

fn maybe_write_workload_report_from_env() -> bool {
    let Some(report_path) = env::var_os(WORKLOAD_REPORT_ENV) else {
        return false;
    };

    let report_path = PathBuf::from(report_path);
    if report_path.as_os_str() == "-" {
        write_workload_report_stdout().expect("write workload report");
        return true;
    }

    if let Some(parent) = report_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).expect("create report directory");
    }
    write_workload_report(&report_path).expect("write workload report");
    true
}

fn bench_cache_workload(c: &mut Criterion, case: &WorkloadCase) {
    let bench_label = format!("block_cache_{}_{}", policy_label(), case.workload);
    c.bench_function(&bench_label, |b| {
        b.iter(|| {
            let metrics = run_workload(black_box(case));
            black_box(metrics.hit_rate);
            black_box(metrics.memory_overhead_per_cached_block);
        });
    });
}

fn bench_concurrent_hot_read_64threads(c: &mut Criterion) {
    const THREADS: usize = 64;
    const OPS_PER_THREAD: usize = 2_048;
    const HOT_BLOCKS: usize = 256;
    const BLOCK_COUNT: usize = 4_096;
    const CAPACITY: usize = 512;

    let cx = Cx::for_testing();
    let cache = StdArc::new(make_cache(BLOCK_SIZE_4K, BLOCK_COUNT, CAPACITY));
    for block in 0..HOT_BLOCKS {
        let block = BlockNumber(block as u64);
        let buf = cache.read_block(&cx, block).expect("warm hot block");
        black_box(buf.as_slice()[0]);
    }

    let bench_label = format!(
        "block_cache_{}_concurrent_hot_read_64threads",
        policy_label()
    );
    c.bench_function(&bench_label, |b| {
        b.iter_custom(|iters| {
            let mut elapsed = Duration::ZERO;
            for iter in 0..iters {
                let barrier = StdArc::new(Barrier::new(THREADS));
                let started = Instant::now();
                thread::scope(|scope| {
                    for thread_id in 0..THREADS {
                        let cache = StdArc::clone(&cache);
                        let barrier = StdArc::clone(&barrier);
                        scope.spawn(move || {
                            let cx = Cx::for_testing();
                            barrier.wait();
                            for op in 0..OPS_PER_THREAD {
                                let mixed = op
                                    .wrapping_mul(37)
                                    .wrapping_add(thread_id.wrapping_mul(13))
                                    .wrapping_add(iter as usize);
                                let block = BlockNumber((mixed % HOT_BLOCKS) as u64);
                                let buf = cache.read_block(&cx, block).expect("hot read");
                                black_box(buf.as_slice()[0]);
                            }
                        });
                    }
                });
                elapsed += started.elapsed();
            }
            elapsed
        });
    });
}

fn bench_sharded_concurrent_hot_read_64threads(c: &mut Criterion) {
    const THREADS: usize = 64;
    const OPS_PER_THREAD: usize = 2_048;
    const HOT_BLOCKS: usize = 256;
    const BLOCK_COUNT: usize = 4_096;
    const CAPACITY: usize = 512;
    const SHARDS: usize = 64;

    let cx = Cx::for_testing();
    let cache = StdArc::new(make_sharded_cache(
        BLOCK_SIZE_4K,
        BLOCK_COUNT,
        CAPACITY,
        SHARDS,
    ));
    for block in 0..HOT_BLOCKS {
        let block = BlockNumber(block as u64);
        let buf = cache.read_block(&cx, block).expect("warm hot block");
        black_box(buf.as_slice()[0]);
    }

    let bench_label = format!(
        "block_cache_sharded_{}_concurrent_hot_read_64threads",
        policy_label()
    );
    c.bench_function(&bench_label, |b| {
        b.iter_custom(|iters| {
            let mut elapsed = Duration::ZERO;
            for iter in 0..iters {
                let barrier = StdArc::new(Barrier::new(THREADS));
                let started = Instant::now();
                thread::scope(|scope| {
                    for thread_id in 0..THREADS {
                        let cache = StdArc::clone(&cache);
                        let barrier = StdArc::clone(&barrier);
                        scope.spawn(move || {
                            let cx = Cx::for_testing();
                            barrier.wait();
                            for op in 0..OPS_PER_THREAD {
                                let mixed = op
                                    .wrapping_mul(37)
                                    .wrapping_add(thread_id.wrapping_mul(13))
                                    .wrapping_add(iter as usize);
                                let block = BlockNumber((mixed % HOT_BLOCKS) as u64);
                                let buf = cache.read_block(&cx, block).expect("hot read");
                                black_box(buf.as_slice()[0]);
                            }
                        });
                    }
                });
                elapsed += started.elapsed();
            }
            elapsed
        });
    });
}

fn bench_shard_route_power2_modulo_baseline(c: &mut Criterion) {
    const SHARDS: usize = 64;
    let cache = make_sharded_cache(BLOCK_SIZE_4K, 4_096, 512, SHARDS);
    let mut block = 0_u64;

    c.bench_function("shard_route_power2_modulo_baseline", |b| {
        b.iter(|| {
            block = block.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let shard_count =
                u64::try_from(black_box(cache.shard_count())).expect("shard count fits u64");
            let shard = usize::try_from(black_box(block) % shard_count).expect("shard fits usize");
            black_box(shard);
        });
    });
}

fn bench_shard_route_power2_mask_production(c: &mut Criterion) {
    const SHARDS: usize = 64;
    let cache = make_sharded_cache(BLOCK_SIZE_4K, 4_096, 512, SHARDS);
    let mut block = 0_u64;

    c.bench_function("shard_route_power2_mask_production", |b| {
        b.iter(|| {
            block = block.wrapping_add(0x9E37_79B9_7F4A_7C15);
            black_box(cache.shard_index_for(BlockNumber(black_box(block))));
        });
    });
}

// ── Benchmarks ──────────────────────────────────────────────────────────

fn bench_cache_hit(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let cache = make_cache(BLOCK_SIZE_4K, 16, 8);

    // Warm up: read block 0 once (miss), then benchmark repeated hits.
    let _ = cache.read_block(&cx, BlockNumber(0)).expect("warmup");

    c.bench_function("arc_cache_hit_4k", |b| {
        b.iter(|| {
            let _buf: BlockBuf = cache
                .read_block(black_box(&cx), black_box(BlockNumber(0)))
                .expect("hit");
        });
    });
}

fn bench_cache_miss(c: &mut Criterion) {
    let cx = Cx::for_testing();
    // Capacity 1: every second distinct block evicts the previous one.
    let cache = make_cache(BLOCK_SIZE_4K, 256, 1);

    let mut block_id = 0_u64;
    c.bench_function("arc_cache_miss_4k", |b| {
        b.iter(|| {
            let _buf: BlockBuf = cache
                .read_block(black_box(&cx), BlockNumber(block_id % 256))
                .expect("miss");
            block_id += 1;
        });
    });
}

fn bench_cache_mixed_workload(c: &mut Criterion) {
    let cx = Cx::for_testing();
    // 8-block capacity with a 16-block working set → ~50% hit rate.
    let cache = make_cache(BLOCK_SIZE_4K, 16, 8);

    // Warm up all 16 blocks.
    for i in 0..16_u64 {
        let _ = cache.read_block(&cx, BlockNumber(i)).expect("warmup");
    }

    let mut iter = 0_u64;
    c.bench_function("arc_cache_mixed_4k", |b| {
        b.iter(|| {
            let block = BlockNumber(iter % 16);
            let _buf: BlockBuf = cache
                .read_block(black_box(&cx), black_box(block))
                .expect("read");
            iter += 1;
        });
    });
}

fn bench_metrics_snapshot(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let cache = make_cache(BLOCK_SIZE_4K, 16, 8);

    // Generate some activity.
    for i in 0..16_u64 {
        let _ = cache.read_block(&cx, BlockNumber(i)).expect("warmup");
    }

    c.bench_function("arc_cache_metrics_snapshot", |b| {
        b.iter(|| {
            let _m = cache.metrics();
        });
    });
}

fn bench_writeback_write_seq_4k(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let cache = make_writeback_cache(BLOCK_SIZE_4K, 2048, 1024);
    let payload = vec![0x91; BLOCK_SIZE_4K as usize];
    let mut block = 0_u64;

    c.bench_function("writeback_write_seq_4k", |b| {
        b.iter(|| {
            let target = BlockNumber(block % 1024);
            cache
                .write_block(black_box(&cx), black_box(target), black_box(&payload))
                .expect("write");
            block = block.wrapping_add(1);
        });
    });
}

fn bench_writeback_write_random_4k(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let cache = make_writeback_cache(BLOCK_SIZE_4K, 2048, 1024);
    let payload = vec![0x92; BLOCK_SIZE_4K as usize];
    let mut rng = Rng64::seeded(0xBEEF_1001);

    c.bench_function("writeback_write_random_4k", |b| {
        b.iter(|| {
            let target = BlockNumber(rng.next_u64() % 1024);
            cache
                .write_block(black_box(&cx), black_box(target), black_box(&payload))
                .expect("write");
        });
    });
}

fn bench_writeback_sync_single_4k(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let cache = make_writeback_cache(BLOCK_SIZE_4K, 512, 256);
    let payload = vec![0xAB; BLOCK_SIZE_4K as usize];
    let mut block = 0_u64;

    c.bench_function("writeback_sync_single_4k", |b| {
        b.iter(|| {
            let target = BlockNumber(block % 256);
            cache
                .write_block(black_box(&cx), black_box(target), black_box(&payload))
                .expect("write");
            cache.sync(black_box(&cx)).expect("sync");
            block = block.wrapping_add(1);
        });
    });
}

fn bench_writeback_sync_100x4k(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let cache = make_writeback_cache(BLOCK_SIZE_4K, 2048, 1024);
    let payload = vec![0xCD; BLOCK_SIZE_4K as usize];
    let mut base = 0_u64;

    c.bench_function("writeback_sync_100x4k", |b| {
        b.iter(|| {
            for offset in 0_u64..100_u64 {
                let target = BlockNumber((base + offset) % 1024);
                cache
                    .write_block(black_box(&cx), black_box(target), black_box(&payload))
                    .expect("write");
            }
            cache.sync(black_box(&cx)).expect("sync");
            base = base.wrapping_add(100);
        });
    });
}

/// Frozen pre-change selector: every selected dirty block is inserted even
/// though the dirty list is unique by construction.
fn legacy_flush_membership_select(
    pending: &[BlockNumber],
    dirty: &[BlockNumber],
    limit: usize,
) -> Vec<BlockNumber> {
    let mut selected = pending.iter().copied().take(limit).collect::<Vec<_>>();
    let mut queued = HashSet::with_capacity(selected.len());
    queued.extend(selected.iter().copied());
    for &block in dirty {
        if selected.len() >= limit {
            break;
        }
        if queued.contains(&block) {
            continue;
        }
        selected.push(block);
        queued.insert(block);
    }
    selected
}

/// Candidate selector: the membership set contains pending candidates only.
/// `DirtyTracker::dirty_blocks_oldest_first` cannot yield a block twice.
fn pending_only_flush_membership_select(
    pending: &[BlockNumber],
    dirty: &[BlockNumber],
    limit: usize,
) -> Vec<BlockNumber> {
    let mut selected = pending.iter().copied().take(limit).collect::<Vec<_>>();
    let mut queued = HashSet::with_capacity(selected.len());
    queued.extend(selected.iter().copied());
    for &block in dirty {
        if selected.len() >= limit {
            break;
        }
        if !queued.is_empty() && queued.contains(&block) {
            continue;
        }
        selected.push(block);
    }
    selected
}

fn bench_flush_pending_membership(c: &mut Criterion) {
    let dirty = (0..4_096_u64).map(BlockNumber).collect::<Vec<_>>();
    let pending_overlap = [dirty[0], dirty[2_048], dirty[4_095]];
    let pending_disjoint = [BlockNumber(9_000), BlockNumber(9_001)];

    for (pending, dirty_blocks, limit) in [
        (&[][..], &[][..], usize::MAX),
        (&[][..], &dirty[..1], usize::MAX),
        (&pending_overlap[..], dirty.as_slice(), usize::MAX),
        (&pending_overlap[..], dirty.as_slice(), 17),
        (&pending_disjoint[..], dirty.as_slice(), 1),
        (&pending_disjoint[..], dirty.as_slice(), 4_096),
    ] {
        assert_eq!(
            legacy_flush_membership_select(pending, dirty_blocks, limit),
            pending_only_flush_membership_select(pending, dirty_blocks, limit),
            "pending-only membership changed flush selection"
        );
    }

    let pending = Vec::new();
    let mut group = c.benchmark_group("arc_flush_pending_membership_4096");
    group.bench_function("legacy_a", |b| {
        b.iter(|| {
            black_box(legacy_flush_membership_select(
                black_box(&pending),
                black_box(&dirty),
                usize::MAX,
            ))
        });
    });
    group.bench_function("legacy_b", |b| {
        b.iter(|| {
            black_box(legacy_flush_membership_select(
                black_box(&pending),
                black_box(&dirty),
                usize::MAX,
            ))
        });
    });
    group.bench_function("pending_only", |b| {
        b.iter(|| {
            black_box(pending_only_flush_membership_select(
                black_box(&pending),
                black_box(&dirty),
                usize::MAX,
            ))
        });
    });
    group.finish();
}

fn make_dirty_front_pressure_cache(
    capacity: usize,
    dirty_prefix: usize,
) -> ArcCache<ByteBlockDevice<MemByteDevice>> {
    let cx = Cx::for_testing();
    let cache = make_writeback_cache(BLOCK_SIZE_4K, capacity + 128, capacity);
    let payload = vec![0xA7; BLOCK_SIZE_4K as usize];

    for block in 0..capacity {
        let block = BlockNumber(block as u64);
        let buf = cache.read_block(&cx, block).expect("warm resident block");
        black_box(buf.as_slice()[0]);
    }

    for block in 0..dirty_prefix {
        cache
            .stage_txn_write(
                &cx,
                TxnId(block as u64 + 1),
                BlockNumber(block as u64),
                &payload,
            )
            .expect("stage dirty-front block");
    }

    cache
}

fn bench_dirty_front_pressure_trim(c: &mut Criterion) {
    const CAPACITY: usize = 4_096;
    const DIRTY_PREFIX: usize = 3_072;

    c.bench_function("arc_dirty_front_pressure_trim_4096_dirty3072", |b| {
        b.iter_batched(
            || make_dirty_front_pressure_cache(CAPACITY, DIRTY_PREFIX),
            |cache| {
                let report = cache.memory_pressure_callback(MemoryPressure::Critical);
                black_box(report.current_size);
                black_box(report.target_size);
                black_box(report.dirty_count);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_workload_sequential_scan(c: &mut Criterion) {
    bench_cache_workload(c, &sequential_scan_case());
}

fn bench_workload_zipf(c: &mut Criterion) {
    bench_cache_workload(c, &zipf_case());
}

fn bench_workload_mixed_seq_hot(c: &mut Criterion) {
    bench_cache_workload(c, &mixed_seq_hot_case());
}

fn bench_workload_compile_like(c: &mut Criterion) {
    bench_cache_workload(c, &compile_like_case());
}

fn bench_workload_database_like(c: &mut Criterion) {
    bench_cache_workload(c, &database_like_case());
}

fn bench_workload_repeated_working_set(c: &mut Criterion) {
    bench_cache_workload(c, &repeated_working_set_case());
}

fn bench_sharded_extent_read_cache_repeated_working_set(c: &mut Criterion) {
    let cache = ShardedExtentReadCache::new(8 * 1024 * 1024);
    let tile_fill = vec![0x5A_u8; 32 * 4096];
    for tile in 0..32_u64 {
        cache.insert_unconditional(BlockNumber(tile * 32), 4096, &tile_fill);
    }
    let mut rng = Rng64::seeded(0xE710_4096);
    c.bench_function("extent_read_cache_hot_4k_randread", |b| {
        let mut dst = [0_u8; 4096];
        b.iter(|| {
            let blk = BlockNumber(rng.next_usize(32 * 32) as u64);
            let hit = cache.copy_into(black_box(blk), 4096, &mut dst);
            debug_assert!(hit);
            black_box(dst[0]);
        });
    });
}

criterion_group!(
    cache_benches,
    bench_cache_hit,
    bench_cache_miss,
    bench_cache_mixed_workload,
    bench_metrics_snapshot,
    bench_writeback_write_seq_4k,
    bench_writeback_write_random_4k,
    bench_writeback_sync_single_4k,
    bench_writeback_sync_100x4k,
    bench_flush_pending_membership,
    bench_dirty_front_pressure_trim,
    bench_workload_sequential_scan,
    bench_workload_zipf,
    bench_workload_mixed_seq_hot,
    bench_workload_compile_like,
    bench_workload_database_like,
    bench_workload_repeated_working_set,
    bench_sharded_extent_read_cache_repeated_working_set,
    bench_concurrent_hot_read_64threads,
    bench_sharded_concurrent_hot_read_64threads,
    bench_shard_route_power2_modulo_baseline,
    bench_shard_route_power2_mask_production,
);

fn main() {
    if maybe_write_workload_report_from_env() {
        return;
    }

    cache_benches();
    Criterion::default().configure_from_args().final_summary();
}
