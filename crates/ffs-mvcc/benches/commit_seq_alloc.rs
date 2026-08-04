#![forbid(unsafe_code)]

//! Characterization of a REJECTED lever (see docs/progress/perf-negative-results.md,
//! 2026-07-13): replacing the commit-seq / txn-id allocator's checked
//! `fetch_update` CAS loop with a wait-free `fetch_add`.
//!
//! `next_commit_seq` / `next_txn_id` allocate a monotonic counter once per commit
//! on the parallel commit path via `fetch_update(|c| c.checked_add(1))` — a load +
//! `compare_exchange` retry loop. A pure `fetch_add` is wait-free but WRAPS at the
//! ceiling, which breaks the no-wrap exhaustion contract (a wrapped id/seq could
//! be reissued); a margin-guarded `fetch_add` (relaxed load below a ceiling band,
//! CAS fallback near it) is correct but adds per-op overhead. This bench measures
//! the EXACT ops under N threads on one shared counter.
//!
//! Verdict: the isolated win is real (see the ledger table) but END-TO-END
//! NEGLIGIBLE — this atomic is <0.5% of a commit — so production keeps
//! `fetch_update`. Retained as re-verifiable evidence for the negative-ledger row.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const PER_THREAD: u64 = 200_000;

fn hammer_fetch_update(threads: usize) {
    let ctr = Arc::new(AtomicU64::new(1));
    std::thread::scope(|scope| {
        for _ in 0..threads {
            let ctr = Arc::clone(&ctr);
            scope.spawn(move || {
                for _ in 0..PER_THREAD {
                    let v = ctr
                        .try_update(Ordering::SeqCst, Ordering::SeqCst, |c| c.checked_add(1))
                        .expect("counter does not overflow in-bench");
                    black_box(v);
                }
            });
        }
    });
    black_box(ctr.load(Ordering::Relaxed));
}

// Production fast path: a relaxed load confirms we're far below the ceiling,
// then a wait-free `fetch_add` (no CAS retry). Mirrors `next_commit_seq` /
// `next_txn_id` exactly (the ceiling fallback is unreachable and not benched).
fn hammer_margin_guarded(threads: usize) {
    const MARGIN: u64 = 1 << 32;
    let ctr = Arc::new(AtomicU64::new(1));
    std::thread::scope(|scope| {
        for _ in 0..threads {
            let ctr = Arc::clone(&ctr);
            scope.spawn(move || {
                for _ in 0..PER_THREAD {
                    let v = if ctr.load(Ordering::Relaxed) < u64::MAX - MARGIN {
                        ctr.fetch_add(1, Ordering::SeqCst)
                    } else {
                        ctr.try_update(Ordering::SeqCst, Ordering::SeqCst, |c| c.checked_add(1))
                            .expect("counter does not overflow in-bench")
                    };
                    black_box(v);
                }
            });
        }
    });
    black_box(ctr.load(Ordering::Relaxed));
}

fn bench_commit_seq_alloc(c: &mut Criterion) {
    let mut group = c.benchmark_group("mvcc_commit_seq_alloc");
    group.sample_size(20);
    for threads in [1_usize, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("fetch_update_cas_loop", threads),
            &threads,
            |b, &threads| b.iter(|| hammer_fetch_update(threads)),
        );
        group.bench_with_input(
            BenchmarkId::new("margin_guarded_fetch_add", threads),
            &threads,
            |b, &threads| b.iter(|| hammer_margin_guarded(threads)),
        );
    }
    group.finish();
}

criterion_group!(commit_seq_alloc, bench_commit_seq_alloc);
criterion_main!(commit_seq_alloc);
