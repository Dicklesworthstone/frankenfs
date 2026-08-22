#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for overlapping the per-block reads in ext4
//! `lookup_name_with_scope` (bd-xmh5g.194, I/O-overlap sibling of bd-2jurz).
//!
//! When the htree index misses (a negative lookup, or a non-htree / htree-stale
//! directory), `lookup_name_with_scope` falls back to a linear scan that reads
//! each present directory block and searches it for the target name. The
//! pre-bd-xmh5g.194 scan read those blocks serially — a large directory paid one
//! device-read latency per block in sequence, and a negative lookup (the hot
//! path behind every file-create existence check) read every block. bd-xmh5g.194
//! plans the present blocks serially (the resolve_extent descent stays serial),
//! then reads + searches them in a rayon `into_par_iter`, consuming the results
//! in logical-block order so the first match / lowest-block error still wins.
//!
//! This bench isolates that I/O fan-out with a per-block read that parks the
//! worker for a fixed latency before returning the block bytes, then searches
//! the block for an absent name (the negative-lookup case, where both arms read
//! every block — so this measures only the read-latency overlap, not the
//! early-exit difference):
//!   * `serial_blocks`   — pre-bd-xmh5g.194: read + search each block in turn.
//!   * `parallel_blocks` — bd-xmh5g.194: read + search blocks in an
//!     `into_par_iter`, results consumed in block order.

use asupersync::Cx;
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_block::ByteDevice;
use ffs_core::{OpenFs, OpenOptions};
use ffs_error::{FfsError, Result as FfsResult};
use ffs_types::{BlockNumber, ByteOffset};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::hint::black_box;
use std::ops::Range;
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

const BLOCKS: usize = 64; // present directory blocks scanned on an htree miss
const BS: usize = 4096; // ext4 block size
const HOT_READS: usize = 1092; // bd-9e810 delete trace pread64 count
const HOT_UNIQUE_BLOCKS: usize = 42; // bd-9e810 unique physical offsets
const OPENFS_HOT_BLOCK_BASE: u64 = 32; // safely away from the ext4 superblock
/// Per-block read access latency. Models a real-disk/SSD-queue round trip; the
/// in-memory unit-test device is zero-latency and cannot exhibit overlap.
const READ_LATENCY: Duration = Duration::from_micros(250);
/// Small per-block metadata read latency used by the cache A/B. The model
/// isolates syscall/device round-trip elimination; cache hits still materialize
/// an owned Vec, matching `read_block_vec` callers.
const HOT_READ_LATENCY: Duration = Duration::from_micros(4);

/// Deterministic pseudo-random byte (no `Math.random` in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

/// Read one directory block (park for the access latency) and search it for an
/// absent name. Returns `Some(block)` only on a (never-occurring) hit, modelling
/// the negative-lookup case where every block is read and searched.
fn read_and_search(block: usize) -> Option<usize> {
    std::thread::sleep(READ_LATENCY);
    // Byte scan over the block for a sentinel that never appears, matching the
    // per-block `lookup_in_dir_block` work that dominates after the read.
    let mut acc: u8 = 0;
    for i in 0..BS {
        acc ^= prng((block as u64) << 20 ^ i as u64);
    }
    // 0xFF_FF... sentinel is unreachable from the xor fold above in practice; the
    // result is always `None`, the negative-lookup outcome.
    (acc == 0 && block == usize::MAX).then_some(block)
}

/// Pre-bd-xmh5g.194: read + search every block serially, first match wins.
fn serial_blocks() -> Option<usize> {
    (0..BLOCKS).find_map(read_and_search)
}

/// bd-xmh5g.194: read + search blocks in parallel; lowest-block match wins.
fn parallel_blocks() -> Option<usize> {
    let results: Vec<Option<usize>> = (0..BLOCKS).into_par_iter().map(read_and_search).collect();
    results.into_iter().flatten().next()
}

fn htree_hot_blocks() -> Vec<Arc<[u8]>> {
    (0..HOT_UNIQUE_BLOCKS)
        .map(|block| {
            let mut bytes = vec![0_u8; BS];
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = prng((block as u64) << 32 ^ i as u64);
            }
            Arc::from(bytes.into_boxed_slice())
        })
        .collect()
}

fn htree_uncached_base_reads(blocks: &[Arc<[u8]>]) -> u64 {
    let mut checksum = 0_u64;
    for read in 0..HOT_READS {
        let block = read % HOT_UNIQUE_BLOCKS;
        std::thread::sleep(HOT_READ_LATENCY);
        let mut bytes = vec![0_u8; BS];
        bytes.copy_from_slice(blocks[block].as_ref());
        checksum ^= u64::from(bytes[(read * 31) % BS]);
    }
    checksum
}

fn htree_cached_base_reads(blocks: &[Arc<[u8]>]) -> u64 {
    let mut checksum = 0_u64;
    let mut cache: Vec<Option<Arc<[u8]>>> = vec![None; HOT_UNIQUE_BLOCKS];
    for read in 0..HOT_READS {
        let block = read % HOT_UNIQUE_BLOCKS;
        if cache[block].is_none() {
            std::thread::sleep(HOT_READ_LATENCY);
            cache[block] = Some(Arc::clone(&blocks[block]));
        }
        let bytes = cache[block]
            .as_ref()
            .expect("cache entry populated")
            .as_ref()
            .to_vec();
        checksum ^= u64::from(bytes[(read * 31) % BS]);
    }
    checksum
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
        .expect("run mkfs.ext4 for OpenFs ext4 read benchmark seed");
    assert!(
        output.status.success(),
        "mkfs.ext4 failed for OpenFs ext4 read benchmark seed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::read(image).expect("read ext4 benchmark seed image")
}

fn open_ext4_bench_fs(image: Vec<u8>) -> OpenFs {
    let cx = Cx::for_testing();
    OpenFs::from_device(
        &cx,
        Box::new(BenchByteDevice::from_vec(image)),
        &OpenOptions::default(),
    )
    .expect("open benchmark ext4 filesystem")
}

fn openfs_hot_read_block_vec(fs: &OpenFs) -> u64 {
    let cx = Cx::for_testing();
    let mut checksum = 0_u64;
    for read in 0..HOT_READS {
        let block = OPENFS_HOT_BLOCK_BASE
            + u64::try_from(read % HOT_UNIQUE_BLOCKS).expect("hot block index fits u64");
        let bytes = fs
            .read_block_vec(&cx, BlockNumber(block))
            .expect("OpenFs benchmark hot block read");
        checksum ^= u64::from(bytes[(read * 31) % BS]);
    }
    checksum
}

fn bench_ext4_lookup_run_overlap(c: &mut Criterion) {
    // Isomorphism: identical outcome (`None`) regardless of read order.
    assert_eq!(
        serial_blocks(),
        parallel_blocks(),
        "parallel lookup block scan diverged from serial"
    );

    let mut group = c.benchmark_group("ext4_lookup_run_overlap_64blocks");
    group
        .sample_size(10)
        .warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(3));
    group.bench_function("serial_blocks", |b| {
        b.iter(|| black_box(serial_blocks()));
    });
    group.bench_function("parallel_blocks", |b| {
        b.iter(|| black_box(parallel_blocks()));
    });
    group.finish();
}

fn bench_ext4_base_block_cache(c: &mut Criterion) {
    let blocks = htree_hot_blocks();
    assert_eq!(
        htree_uncached_base_reads(&blocks),
        htree_cached_base_reads(&blocks),
        "cached htree metadata read stream changed bytes"
    );

    let mut group = c.benchmark_group("ext4_base_block_cache_1092reads_42unique");
    group
        .sample_size(10)
        .warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(3));
    group.bench_function("uncached_read_block_vec", |b| {
        b.iter(|| black_box(htree_uncached_base_reads(black_box(&blocks))));
    });
    group.bench_function("cached_read_block_vec", |b| {
        b.iter(|| black_box(htree_cached_base_reads(black_box(&blocks))));
    });
    group.finish();
}

fn bench_openfs_ext4_read_block_vec_hot_cache(c: &mut Criterion) {
    let seed = ext4_seed_image();
    let fs = open_ext4_bench_fs(seed);
    assert_eq!(
        openfs_hot_read_block_vec(&fs),
        openfs_hot_read_block_vec(&fs),
        "OpenFs hot metadata read stream changed bytes"
    );

    let mut group = c.benchmark_group("openfs_ext4_read_block_vec_1092reads_42unique");
    group
        .sample_size(10)
        .warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(3));
    group.bench_function("public_read_block_vec", |b| {
        b.iter(|| black_box(openfs_hot_read_block_vec(black_box(&fs))));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_ext4_lookup_run_overlap,
    bench_ext4_base_block_cache,
    bench_openfs_ext4_read_block_vec_hot_cache
);
criterion_main!(benches);
