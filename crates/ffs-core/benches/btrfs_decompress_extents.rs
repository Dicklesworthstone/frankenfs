#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for parallelizing the multi-extent btrfs decompress in
//! `btrfs_read_file` (bd-m6g2o).
//!
//! A btrfs read that spans N compressed extents decompresses each covering
//! extent (zstd/zlib/lzo) before copying its bytes into the output buffer.
//! Compressed extents are capped at 128 KiB uncompressed, so a multi-megabyte
//! read fans out across many independent decompress jobs. The old assembly
//! loop ran them serially, one per extent; the new code gathers the compressed
//! blobs and decompresses them in parallel across cores (rayon) before the
//! sequential copy-into-output assembly.
//!
//! This bench isolates that decompress fan-out: build N independently
//! zstd-compressed 128 KiB blobs, then decompress all N serially vs. via
//! `into_par_iter`. Both produce the identical decompressed blobs (asserted) —
//! `zstd::decode_all` is a pure function of its input, so parallelism only
//! reorders execution. The dedicated-pool arms model bd-defgb: large
//! compressed reads should avoid waking the full global rayon pool, while many
//! small files should not pay one dedicated-pool `install()` per file.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use rayon::{ThreadPool, ThreadPoolBuilder};
use smallvec::SmallVec;
use std::cell::RefCell;
use std::hint::black_box;
use std::sync::Arc;

const N: usize = 16; // compressed extents in the read (≈2 MiB read)
const LARGE_N: usize = 272; // ≈34 MiB compressed-read fan-out from bd-defgb
const TINY_FRAME_N: usize = 321; // /data/tmp/btrdiff2 compressible.bin fan-out
const TINY_CHUNK_FRAME_N: usize = 8; // one 1 MiB CLI read chunk over 128 KiB zstd extents
const SMALL_FILES: usize = 64;
const SMALL_EXTENTS_PER_FILE: usize = 4;
const DEDICATED_POOL_MAX_THREADS: usize = 16;
const DEDICATED_POOL_MIN_JOBS: usize = 17;
const RAM: usize = 128 * 1024; // uncompressed extent size (btrfs cap)

#[derive(Clone, Copy)]
struct BenchReadJob {
    idx: usize,
    logical: u64,
    compressed_len: usize,
    comp: u8,
    ram: usize,
    disk_bytenr: u64,
    extent_offset: u64,
    extent_delta: u64,
}

fn read_job_digest(job: BenchReadJob) -> u64 {
    u64::try_from(job.idx)
        .unwrap_or(u64::MAX)
        .wrapping_add(job.logical.rotate_left(7))
        .wrapping_add(u64::try_from(job.compressed_len).unwrap_or(u64::MAX))
        .wrapping_add(u64::from(job.comp))
        .wrapping_add(u64::try_from(job.ram).unwrap_or(u64::MAX))
        .wrapping_add(job.disk_bytenr.rotate_left(13))
        .wrapping_add(job.extent_offset)
        .wrapping_add(job.extent_delta)
}

fn single_read_job_heap_queue(job: BenchReadJob) -> u64 {
    let mut jobs = Vec::new();
    jobs.push(job);
    black_box(jobs).into_iter().map(read_job_digest).sum()
}

fn single_read_job_inline_queue(job: BenchReadJob) -> u64 {
    let mut jobs: SmallVec<[BenchReadJob; 1]> = SmallVec::new();
    jobs.push(job);
    black_box(jobs).into_iter().map(read_job_digest).sum()
}

thread_local! {
    static BENCH_ZSTD_DECOMPRESSOR: RefCell<Option<zstd::bulk::Decompressor<'static>>> =
        const { RefCell::new(None) };
}

fn criterion_filter_args() -> Vec<String> {
    let mut filters = Vec::new();
    let mut skip_next = false;
    for arg in std::env::args().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        match arg.as_str() {
            "--baseline" | "--color" | "--measurement-time" | "--output-format"
            | "--plotting-backend" | "--profile-time" | "--sample-size" | "--save-baseline"
            | "--warm-up-time" => {
                skip_next = true;
                continue;
            }
            _ => {}
        }
        if arg.starts_with('-') {
            continue;
        }
        filters.push(arg);
    }
    filters
}

fn should_build_group(names: &[&str]) -> bool {
    let filters = criterion_filter_args();
    filters.is_empty()
        || filters.iter().any(|filter| {
            names
                .iter()
                .any(|name| name.contains(filter) || filter.contains(name))
        })
}

fn bench_single_read_job_queue(c: &mut Criterion) {
    if !should_build_group(&[
        "btrfs_single_read_job_queue_1",
        "heap_vec_a",
        "heap_vec_b",
        "inline_smallvec_1",
    ]) {
        return;
    }

    let job = BenchReadJob {
        idx: 7,
        logical: 0x1000,
        compressed_len: 8192,
        comp: 3,
        ram: RAM,
        disk_bytenr: 0x20_0000,
        extent_offset: 4096,
        extent_delta: 8192,
    };
    assert_eq!(
        single_read_job_heap_queue(job),
        single_read_job_inline_queue(job),
        "inline-one read-job queue changed job order or contents"
    );

    let mut group = c.benchmark_group("btrfs_single_read_job_queue_1");
    for control in ["heap_vec_a", "heap_vec_b"] {
        group.bench_function(control, |b| {
            b.iter_batched(
                || job,
                |job| black_box(single_read_job_heap_queue(job)),
                BatchSize::SmallInput,
            );
        });
    }
    group.bench_function("inline_smallvec_1", |b| {
        b.iter_batched(
            || job,
            |job| black_box(single_read_job_inline_queue(job)),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

/// Deterministic pseudo-random byte (no `Math.random` in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

/// Build `n` zstd-compressed blobs of semi-compressible 128 KiB payloads
/// (mix of repeated runs + pseudo-random bytes — typical file data that
/// btrfs would choose to compress).
fn build_compressed(n: usize, seed: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|e| {
            let plain: Vec<u8> = (0..RAM)
                .map(|b| {
                    // ~Half the bytes are a low-entropy run, half pseudo-random,
                    // so zstd achieves a realistic (not pathological) ratio.
                    if b % 8 < 4 {
                        ((seed + e) as u8).wrapping_add((b / 64) as u8)
                    } else {
                        prng(((seed + e) as u64) << 24 ^ b as u64)
                    }
                })
                .collect();
            zstd::encode_all(plain.as_slice(), 3).expect("zstd compress")
        })
        .collect()
}

fn decompress_one(compressed: &[u8]) -> Vec<u8> {
    zstd::decode_all(compressed).expect("zstd decompress")
}

fn decompress_serial(blobs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    blobs.iter().map(|b| decompress_one(b)).collect()
}

fn decompress_parallel(blobs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    blobs.par_iter().map(|b| decompress_one(b)).collect()
}

fn decompress_parallel_sum(blobs: &[Vec<u8>]) -> usize {
    blobs.par_iter().map(|b| decompress_one(b).len()).sum()
}

fn dedicated_pool() -> &'static ThreadPool {
    static POOL: std::sync::OnceLock<ThreadPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        let threads = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(DEDICATED_POOL_MAX_THREADS)
            .min(DEDICATED_POOL_MAX_THREADS)
            .max(1);
        ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|idx| format!("bench-btrfs-decompress-{idx}"))
            .build()
            .expect("valid dedicated bench pool")
    })
}

fn decompress_parallel_pool(blobs: &[Vec<u8>], pool: &ThreadPool) -> Vec<Vec<u8>> {
    pool.install(|| decompress_parallel(blobs))
}

fn decompress_parallel_pool_sum(blobs: &[Vec<u8>], pool: &ThreadPool) -> usize {
    pool.install(|| decompress_parallel_sum(blobs))
}

fn build_small_files() -> Vec<Vec<Vec<u8>>> {
    (0..SMALL_FILES)
        .map(|file| build_compressed(SMALL_EXTENTS_PER_FILE, file * 1024))
        .collect()
}

fn decompress_files_always_pool(files: &[Vec<Vec<u8>>], pool: &ThreadPool) -> usize {
    files
        .iter()
        .map(|blobs| decompress_parallel_pool_sum(blobs, pool))
        .sum()
}

fn decompress_files_gated(files: &[Vec<Vec<u8>>], pool: &ThreadPool) -> usize {
    files
        .iter()
        .map(|blobs| {
            if blobs.len() >= DEDICATED_POOL_MIN_JOBS {
                decompress_parallel_pool_sum(blobs, pool)
            } else {
                decompress_parallel_sum(blobs)
            }
        })
        .sum()
}

fn build_quick_brown_blob() -> Vec<u8> {
    const PATTERN: &[u8] = b"The quick brown fox. ";
    let mut plain = Vec::with_capacity(RAM);
    while plain.len() < RAM {
        let take = (RAM - plain.len()).min(PATTERN.len());
        plain.extend_from_slice(&PATTERN[..take]);
    }
    let mut compressed = zstd::bulk::compress(&plain, 3).expect("compress quick-brown zstd extent");
    assert!(
        compressed.len() <= 4096,
        "quick-brown extent should fit in one btrfs sector"
    );
    compressed.resize(4096, 0);
    compressed
}

fn first_zstd_frame(compressed: &[u8]) -> &[u8] {
    let frame_len = zstd::zstd_safe::find_frame_compressed_size(compressed)
        .expect("find zstd frame in padded btrfs extent");
    &compressed[..frame_len]
}

fn decompress_tiny_frames_fresh(blobs: &[Vec<u8>]) -> usize {
    blobs
        .par_iter()
        .map(|blob| {
            zstd::bulk::decompress(first_zstd_frame(blob), RAM)
                .expect("fresh zstd decompress")
                .len()
        })
        .sum()
}

fn decompress_tiny_frames_reused(blobs: &[Vec<u8>]) -> usize {
    blobs
        .par_iter()
        .map(|blob| {
            BENCH_ZSTD_DECOMPRESSOR.with(|slot| {
                let mut slot = slot.borrow_mut();
                let decoder = slot.get_or_insert_with(|| {
                    zstd::bulk::Decompressor::new().expect("create reusable zstd decoder")
                });
                let mut out = Vec::with_capacity(RAM);
                decoder
                    .decompress_to_buffer(first_zstd_frame(blob), &mut out)
                    .expect("reused zstd decompress");
                out.len()
            })
        })
        .sum()
}

fn decompress_tiny_frames_reused_serial(blobs: &[Vec<u8>]) -> usize {
    blobs
        .iter()
        .map(|blob| {
            BENCH_ZSTD_DECOMPRESSOR.with(|slot| {
                let mut slot = slot.borrow_mut();
                let decoder = slot.get_or_insert_with(|| {
                    zstd::bulk::Decompressor::new().expect("create reusable zstd decoder")
                });
                let mut out = Vec::with_capacity(RAM);
                decoder
                    .decompress_to_buffer(first_zstd_frame(blob), &mut out)
                    .expect("reused zstd decompress");
                out.len()
            })
        })
        .sum()
}

fn cache_arc_slice_copy(decompressed: Vec<u8>) -> (Arc<[u8]>, [u8; 4096]) {
    let mut window = [0_u8; 4096];
    window.copy_from_slice(&decompressed[4096..8192]);
    let full = Arc::from(decompressed.into_boxed_slice());
    (full, window)
}

fn cache_arc_vec_move(decompressed: Vec<u8>) -> (Arc<Vec<u8>>, [u8; 4096]) {
    let mut window = [0_u8; 4096];
    window.copy_from_slice(&decompressed[4096..8192]);
    let full = Arc::new(decompressed);
    (full, window)
}

fn bench_decompressed_cache_admission(c: &mut Criterion) {
    if !should_build_group(&[
        "btrfs_decompressed_cache_admit_128k",
        "arc_slice_copy_a",
        "arc_slice_copy_b",
        "arc_vec_move",
    ]) {
        return;
    }

    let template: Vec<u8> = (0..RAM).map(|i| prng(i as u64)).collect();
    assert_eq!(template.len(), template.capacity());

    let control = cache_arc_slice_copy(template.clone());
    let candidate_input = template.clone();
    let candidate_input_ptr = candidate_input.as_ptr();
    let candidate = cache_arc_vec_move(candidate_input);
    assert_eq!(control.0.as_ref(), candidate.0.as_slice());
    assert_eq!(control.1, candidate.1);
    assert_eq!(candidate_input_ptr, candidate.0.as_ptr());

    let mut group = c.benchmark_group("btrfs_decompressed_cache_admit_128k");
    group.bench_function("arc_slice_copy_a", |b| {
        b.iter_batched(
            || template.clone(),
            |decompressed| black_box(cache_arc_slice_copy(decompressed)),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("arc_slice_copy_b", |b| {
        b.iter_batched(
            || template.clone(),
            |decompressed| black_box(cache_arc_slice_copy(decompressed)),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("arc_vec_move", |b| {
        b.iter_batched(
            || template.clone(),
            |decompressed| black_box(cache_arc_vec_move(decompressed)),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_decompress(c: &mut Criterion) {
    if !should_build_group(&[
        "btrfs_decompress_extents_n16_128k",
        "serial",
        "parallel_rayon",
    ]) {
        return;
    }

    let blobs = build_compressed(N, 0);

    // Isomorphism: parallel produces the identical decompressed extents, same
    // order, as the serial fan-out.
    assert_eq!(
        decompress_serial(&blobs),
        decompress_parallel(&blobs),
        "parallel decompress diverged from serial"
    );

    let mut group = c.benchmark_group("btrfs_decompress_extents_n16_128k");
    group.bench_function("serial", |b| {
        b.iter(|| black_box(decompress_serial(black_box(&blobs))));
    });
    group.bench_function("parallel_rayon", |b| {
        b.iter(|| black_box(decompress_parallel(black_box(&blobs))));
    });
    group.finish();
}

fn bench_decompress_pool(c: &mut Criterion) {
    if !should_build_group(&[
        "btrfs_decompress_pool_large_272x128k",
        "global_pool",
        "dedicated_pool_max16",
        "btrfs_decompress_pool_multifile_64x4x128k",
        "always_install_pool_max16",
        "gated_small_files",
    ]) {
        return;
    }

    let pool = dedicated_pool();
    let large_blobs = build_compressed(LARGE_N, 0);
    let small_files = build_small_files();

    assert_eq!(
        decompress_parallel(&large_blobs),
        decompress_parallel_pool(&large_blobs, pool),
        "dedicated-pool decompress diverged from global-pool decompress"
    );
    assert_eq!(
        decompress_files_always_pool(&small_files, pool),
        decompress_files_gated(&small_files, pool),
        "small-file gate changed decompressed byte count"
    );

    let mut large = c.benchmark_group("btrfs_decompress_pool_large_272x128k");
    large.bench_function("global_pool", |b| {
        b.iter(|| black_box(decompress_parallel_sum(black_box(&large_blobs))));
    });
    large.bench_function("dedicated_pool_max16", |b| {
        b.iter(|| black_box(decompress_parallel_pool_sum(black_box(&large_blobs), pool)));
    });
    large.finish();

    let mut small = c.benchmark_group("btrfs_decompress_pool_multifile_64x4x128k");
    small.bench_function("always_install_pool_max16", |b| {
        b.iter(|| black_box(decompress_files_always_pool(black_box(&small_files), pool)));
    });
    small.bench_function("gated_small_files", |b| {
        b.iter(|| black_box(decompress_files_gated(black_box(&small_files), pool)));
    });
    small.finish();
}

fn bench_decompress_tiny_frames(c: &mut Criterion) {
    if !should_build_group(&[
        "btrfs_decompress_tiny_zstd_321x4k_to_128k",
        "fresh_decompressor_per_frame",
        "thread_reused_decompressor",
    ]) {
        return;
    }

    let blob = build_quick_brown_blob();
    let blobs = vec![blob; TINY_FRAME_N];

    assert_eq!(
        decompress_tiny_frames_fresh(&blobs),
        decompress_tiny_frames_reused(&blobs),
        "reused zstd decoder changed decompressed byte count"
    );

    let mut group = c.benchmark_group("btrfs_decompress_tiny_zstd_321x4k_to_128k");
    group.bench_function("fresh_decompressor_per_frame", |b| {
        b.iter(|| black_box(decompress_tiny_frames_fresh(black_box(&blobs))));
    });
    group.bench_function("thread_reused_decompressor", |b| {
        b.iter(|| black_box(decompress_tiny_frames_reused(black_box(&blobs))));
    });
    group.finish();
}

fn bench_decompress_tiny_frame_scheduling(c: &mut Criterion) {
    if !should_build_group(&[
        "btrfs_decompress_tiny_zstd_8x4k_to_128k",
        "serial_thread_reused_decompressor",
        "parallel_thread_reused_decompressor",
    ]) {
        return;
    }

    let blob = build_quick_brown_blob();
    let blobs = vec![blob; TINY_CHUNK_FRAME_N];

    assert_eq!(
        decompress_tiny_frames_reused_serial(&blobs),
        decompress_tiny_frames_reused(&blobs),
        "serial and parallel reused zstd decoders changed decompressed byte count"
    );

    let mut group = c.benchmark_group("btrfs_decompress_tiny_zstd_8x4k_to_128k");
    group.bench_function("serial_thread_reused_decompressor", |b| {
        b.iter(|| black_box(decompress_tiny_frames_reused_serial(black_box(&blobs))));
    });
    group.bench_function("parallel_thread_reused_decompressor", |b| {
        b.iter(|| black_box(decompress_tiny_frames_reused(black_box(&blobs))));
    });
    group.finish();
}

// ── zlib decoder reuse (bd-4tw2n sibling) ──────────────────────────────────
// `btrfs_decompress`'s ZSTD arm reuses a thread-local decoder (the tiny-frame
// bench above proves that win), but its ZLIB arm creates a fresh
// `flate2::read::ZlibDecoder` per extent, allocating + zeroing the ~32 KiB
// inflate window every call. This isolates that per-extent init cost: fresh
// decoder per blob vs a reused thread-local `flate2::Decompress` reset per blob.
// Byte-identical output (same deflate stream, same inflated bytes; asserted).
thread_local! {
    static BENCH_ZLIB_DECOMPRESSOR: RefCell<Option<flate2::Decompress>> =
        const { RefCell::new(None) };
}

fn zlib_blob(payload: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(payload).expect("zlib encode");
    enc.finish().expect("zlib finish")
}

// Fresh `ZlibDecoder` per blob — exactly what production zlib decode does.
fn zlib_fresh(blobs: &[Vec<u8>], ulen: usize) -> usize {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    blobs
        .iter()
        .map(|blob| {
            let mut out = Vec::with_capacity(ulen);
            ZlibDecoder::new(blob.as_slice())
                .read_to_end(&mut out)
                .expect("fresh zlib decode");
            out.len()
        })
        .sum()
}

// Reused thread-local `Decompress`, reset per blob — the zstd optimization applied
// to zlib. `decompress_vec` fills `out` up to its capacity in one Finish.
fn zlib_reused(blobs: &[Vec<u8>], ulen: usize) -> usize {
    use flate2::FlushDecompress;
    blobs
        .iter()
        .map(|blob| {
            BENCH_ZLIB_DECOMPRESSOR.with(|slot| {
                let mut slot = slot.borrow_mut();
                let d = slot.get_or_insert_with(|| flate2::Decompress::new(true));
                d.reset(true);
                let mut out = Vec::with_capacity(ulen);
                d.decompress_vec(blob, &mut out, FlushDecompress::Finish)
                    .expect("reused zlib decode");
                out.len()
            })
        })
        .sum()
}

fn bench_zlib_reuse(c: &mut Criterion) {
    if !should_build_group(&["zlib_decode_reuse", "zlib_decode_reuse_e2compr_4k"]) {
        return;
    }
    // btrfs scale: 128 KiB extents (the btrfs cap), N of them.
    let payload: Vec<u8> = (0..RAM).map(|i| b"the quick brown fox "[i % 20]).collect();
    let zblobs: Vec<Vec<u8>> = (0..N).map(|_| zlib_blob(&payload)).collect();
    assert_eq!(zlib_fresh(&zblobs, RAM), zlib_reused(&zblobs, RAM), "zlib arms must agree");
    let mut group = c.benchmark_group("zlib_decode_reuse");
    group.bench_function("fresh_a", |b| b.iter(|| black_box(zlib_fresh(black_box(&zblobs), RAM))));
    group.bench_function("fresh_b", |b| b.iter(|| black_box(zlib_fresh(black_box(&zblobs), RAM))));
    group.bench_function("reused", |b| b.iter(|| black_box(zlib_reused(black_box(&zblobs), RAM))));
    group.finish();

    // e2compr scale: 4 KiB ext4 clusters, many of them — the fresh-decoder init is a
    // LARGER fraction of each small decode, so the reuse win is bigger here.
    const CLUSTER: usize = 4096;
    const CLUSTERS: usize = 128;
    let cpay: Vec<u8> = (0..CLUSTER).map(|i| b"the quick brown fox "[i % 20]).collect();
    let cblobs: Vec<Vec<u8>> = (0..CLUSTERS).map(|_| zlib_blob(&cpay)).collect();
    assert_eq!(zlib_fresh(&cblobs, CLUSTER), zlib_reused(&cblobs, CLUSTER), "4k arms must agree");
    let mut g2 = c.benchmark_group("zlib_decode_reuse_e2compr_4k");
    g2.bench_function("fresh_a", |b| b.iter(|| black_box(zlib_fresh(black_box(&cblobs), CLUSTER))));
    g2.bench_function("fresh_b", |b| b.iter(|| black_box(zlib_fresh(black_box(&cblobs), CLUSTER))));
    g2.bench_function("reused", |b| b.iter(|| black_box(zlib_reused(black_box(&cblobs), CLUSTER))));
    g2.finish();
}

// ── write-side: zlib ENCODE reuse (e2compr_compress) ───────────────────────
// `e2compr_compress`'s gzip arm creates a fresh `ZlibEncoder` per cluster,
// allocating the (larger) deflate state. This probes BOTH (1) whether a reused
// `flate2::Compress` produces BYTE-IDENTICAL output to `ZlibEncoder` — REQUIRED
// since the compressed bytes are written to disk + checksummed — and (2) the
// reuse speedup. If the identity assert fails, the lever is NOT shippable.
thread_local! {
    static BENCH_ZLIB_COMPRESSOR: RefCell<Option<flate2::Compress>> = const { RefCell::new(None) };
}

fn zlib_encode_fresh(payloads: &[Vec<u8>], level: u32) -> Vec<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;
    payloads
        .iter()
        .map(|p| {
            let mut e = ZlibEncoder::new(Vec::new(), Compression::new(level));
            e.write_all(p).expect("fresh zlib encode");
            e.finish().expect("fresh zlib finish")
        })
        .collect()
}

fn zlib_encode_reused(payloads: &[Vec<u8>], level: u32) -> Vec<Vec<u8>> {
    use flate2::{Compression, FlushCompress};
    payloads
        .iter()
        .map(|p| {
            BENCH_ZLIB_COMPRESSOR.with(|slot| {
                let mut slot = slot.borrow_mut();
                let c = slot.get_or_insert_with(|| flate2::Compress::new(Compression::new(level), true));
                c.reset();
                let mut out = Vec::with_capacity(p.len() + p.len() / 2 + 128);
                c.compress_vec(p, &mut out, FlushCompress::Finish)
                    .expect("reused zlib compress");
                out
            })
        })
        .collect()
}

fn bench_zlib_encode_reuse(c: &mut Criterion) {
    if !should_build_group(&["zlib_encode_reuse_4k"]) {
        return;
    }
    const CLUSTER: usize = 4096;
    const CLUSTERS: usize = 128;
    const LEVEL: u32 = 6; // flate2 default; e2compr methods map to fixed levels
    let payloads: Vec<Vec<u8>> = (0..CLUSTERS)
        .map(|k| (0..CLUSTER).map(|i| b"the quick brown fox "[(i + k) % 20]).collect())
        .collect();
    // DECISIVE: reused compressor must emit byte-identical output (written to disk).
    assert_eq!(
        zlib_encode_fresh(&payloads, LEVEL),
        zlib_encode_reused(&payloads, LEVEL),
        "reused zlib compress diverged from ZlibEncoder — NOT byte-identical, lever unshippable"
    );
    let mut g = c.benchmark_group("zlib_encode_reuse_4k");
    g.bench_function("fresh_a", |b| b.iter(|| black_box(zlib_encode_fresh(black_box(&payloads), LEVEL))));
    g.bench_function("fresh_b", |b| b.iter(|| black_box(zlib_encode_fresh(black_box(&payloads), LEVEL))));
    g.bench_function("reused", |b| b.iter(|| black_box(zlib_encode_reused(black_box(&payloads), LEVEL))));
    g.finish();
}

// ── btrfs LZO segment decode: fresh Vec per segment vs reused scratch ───────
// `btrfs_decompress_lzo` decodes each segment via `lzo::decompress`, which
// internally does `vec![0u8; page]` (malloc + zero) then `decompress_into`,
// then the caller `extend_from_slice`s it into `out`. A 128 KiB extent has ~32
// segments (one per sector) => ~32 (malloc + zero + free). Decoding into a REUSED
// scratch with `lzo::decompress_into` keeps only one alloc. Byte-identical (same
// LZO1X output into `out`).
fn lzo_decode_alloc(segs: &[Vec<u8>], page: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for s in segs {
        let d = lzo::decompress(s, page).expect("lzo decompress");
        out.extend_from_slice(&d);
    }
    out
}

fn lzo_decode_scratch(segs: &[Vec<u8>], page: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut scratch = vec![0u8; page];
    for s in segs {
        let n = lzo::decompress_into(s, &mut scratch[..page]).expect("lzo decompress_into");
        out.extend_from_slice(&scratch[..n]);
    }
    out
}

fn bench_lzo_segment_decode(c: &mut Criterion) {
    if !should_build_group(&["lzo_segment_decode"]) {
        return;
    }
    const SECTOR: usize = 4096;
    const SEGS: usize = 32; // 128 KiB extent = 32 sector-sized LZO segments
    let payloads: Vec<Vec<u8>> = (0..SEGS)
        .map(|k| (0..SECTOR).map(|i| b"the quick brown fox "[(i + k) % 20]).collect())
        .collect();
    let segs: Vec<Vec<u8>> = payloads
        .iter()
        .map(|p| lzokay_native::compress(p).expect("lzo compress"))
        .collect();
    assert_eq!(
        lzo_decode_alloc(&segs, SECTOR),
        lzo_decode_scratch(&segs, SECTOR),
        "LZO decode arms must agree"
    );
    let mut g = c.benchmark_group("lzo_segment_decode");
    g.bench_function("alloc_per_seg_a", |b| b.iter(|| black_box(lzo_decode_alloc(black_box(&segs), SECTOR))));
    g.bench_function("alloc_per_seg_b", |b| b.iter(|| black_box(lzo_decode_alloc(black_box(&segs), SECTOR))));
    g.bench_function("reused_scratch", |b| b.iter(|| black_box(lzo_decode_scratch(black_box(&segs), SECTOR))));
    g.finish();
}

criterion_group!(
    benches,
    bench_single_read_job_queue,
    bench_decompressed_cache_admission,
    bench_decompress,
    bench_decompress_pool,
    bench_decompress_tiny_frames,
    bench_decompress_tiny_frame_scheduling,
    bench_zlib_reuse,
    bench_zlib_encode_reuse,
    bench_lzo_segment_decode
);
criterion_main!(benches);
