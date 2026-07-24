#![forbid(unsafe_code)]

//! False-sharing cost of the immutable `shard_mask` sharing a cache line with the
//! per-commit-written counters (`next_commit`/`next_txn`), confirmed by the
//! `report_hot_field_cache_line_layout` test. `shard_mask` is read on every
//! `shard_index` (per block, every commit AND read); the commit counters are
//! written every commit. On the same line, each commit invalidates `shard_mask`
//! for all concurrent readers. The fix (`ShardMask` `#[repr(align(64))]`) gives it
//! its own line.
//!
//! Characterization of a REJECTED lever (see docs/progress/perf-negative-results.md,
//! 2026-07-13): the two layouts `Adjacent` (mask + counter same line) vs `Isolated`
//! (mask on its own 64-aligned line). Committer threads `fetch_add` the counter
//! (like `next_commit_seq`); reader threads compute `block & mask` (like
//! `shard_index`). VERDICT: NEUTRAL — a PLAIN (non-atomic) read-hot field is
//! register-hoisted out of the reader loop, so it is never re-read from the
//! invalidated line; false sharing only hurts ATOMIC reads. Production keeps the
//! plain `u64` `shard_mask` (no wrapper). Retained as re-verifiable evidence.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const ITERS: u64 = 2_000_000;
const READERS: usize = 4;

struct Adjacent {
    mask: u64,
    counter: AtomicU64,
}

#[repr(align(64))]
struct IsolatedMask(u64);

struct Isolated {
    mask: IsolatedMask,
    counter: AtomicU64,
}

fn run_adjacent(committers: usize) {
    let s = Arc::new(Adjacent {
        mask: 0x3f,
        counter: AtomicU64::new(0),
    });
    std::thread::scope(|scope| {
        for _ in 0..committers {
            let s = Arc::clone(&s);
            scope.spawn(move || {
                for _ in 0..ITERS {
                    s.counter.fetch_add(1, Ordering::Release);
                }
            });
        }
        for r in 0..READERS {
            let s = Arc::clone(&s);
            scope.spawn(move || {
                let mut acc = 0u64;
                for i in 0..ITERS {
                    acc ^= (i.wrapping_add(r as u64)) & s.mask;
                }
                black_box(acc);
            });
        }
    });
    black_box(s.counter.load(Ordering::Relaxed));
}

fn run_isolated(committers: usize) {
    let s = Arc::new(Isolated {
        mask: IsolatedMask(0x3f),
        counter: AtomicU64::new(0),
    });
    std::thread::scope(|scope| {
        for _ in 0..committers {
            let s = Arc::clone(&s);
            scope.spawn(move || {
                for _ in 0..ITERS {
                    s.counter.fetch_add(1, Ordering::Release);
                }
            });
        }
        for r in 0..READERS {
            let s = Arc::clone(&s);
            scope.spawn(move || {
                let mut acc = 0u64;
                for i in 0..ITERS {
                    acc ^= (i.wrapping_add(r as u64)) & s.mask.0;
                }
                black_box(acc);
            });
        }
    });
    black_box(s.counter.load(Ordering::Relaxed));
}

fn bench_shard_mask(c: &mut Criterion) {
    let mut group = c.benchmark_group("mvcc_shard_mask_false_sharing");
    group.sample_size(20);
    for committers in [1_usize, 2, 4] {
        group.bench_with_input(
            BenchmarkId::new("adjacent_same_line", committers),
            &committers,
            |b, &n| {
                b.iter(|| run_adjacent(n));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("isolated_own_line", committers),
            &committers,
            |b, &n| {
                b.iter(|| run_isolated(n));
            },
        );
    }
    group.finish();
}

criterion_group!(shard_mask_false_sharing, bench_shard_mask);
criterion_main!(shard_mask_false_sharing);
