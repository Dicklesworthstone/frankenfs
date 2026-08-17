#![forbid(unsafe_code)]

//! Cost of the per-commit `write_blocks` Vec that ffs-core's commit paths
//! collected UNCONDITIONALLY (`txn.write_set().keys().copied().collect()`), even
//! though its only consumer — the repair-flush lifecycle — is absent in normal
//! operation (`repair_flush_lifecycle` is None). The fix guards the collect on
//! `repair_flush_lifecycle.is_some()`, so a normal commit skips this allocation.
//!
//! This models the eliminated op: collecting N `BlockNumber`s into a Vec (old,
//! per commit) vs `Vec::new()` (new), single-thread and under K parallel threads
//! (allocator pressure on the parallel-write path). N spans typical write-set
//! sizes (a create touches a handful of metadata blocks).

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ffs_types::BlockNumber;
use std::hint::black_box;

const PER_THREAD: u64 = 500_000;

fn collect_n(n: usize) -> Vec<BlockNumber> {
    (0..n as u64).map(BlockNumber).collect()
}

fn hammer(threads: usize, n: usize, collect: bool) {
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(move || {
                for _ in 0..PER_THREAD {
                    if collect {
                        black_box(collect_n(n));
                    } else {
                        black_box(Vec::<BlockNumber>::new());
                    }
                }
            });
        }
    });
}

fn bench_write_blocks(c: &mut Criterion) {
    // Single-thread: the isolated per-commit alloc cost across write-set sizes.
    // Scoped so each group is dropped before the next is created rather than
    // both living to the end of the function.
    {
        let mut sz = c.benchmark_group("mvcc_write_blocks_collect_size");
        sz.sample_size(20);
        for n in [2_usize, 5, 20] {
            sz.bench_with_input(BenchmarkId::new("collect", n), &n, |b, &n| {
                b.iter(|| hammer(1, n, true));
            });
            sz.bench_with_input(BenchmarkId::new("skip", n), &n, |b, &n| {
                b.iter(|| hammer(1, n, false));
            });
        }
        sz.finish();
    }

    // Parallel: allocator pressure at N=5 (a typical create write set).
    {
        let mut par = c.benchmark_group("mvcc_write_blocks_collect_parallel_n5");
        par.sample_size(20);
        for threads in [1_usize, 2, 4, 8] {
            par.bench_with_input(BenchmarkId::new("collect", threads), &threads, |b, &t| {
                b.iter(|| hammer(t, 5, true));
            });
            par.bench_with_input(BenchmarkId::new("skip", threads), &threads, |b, &t| {
                b.iter(|| hammer(t, 5, false));
            });
        }
        par.finish();
    }
}

criterion_group!(write_blocks_alloc, bench_write_blocks);
criterion_main!(write_blocks_alloc);
