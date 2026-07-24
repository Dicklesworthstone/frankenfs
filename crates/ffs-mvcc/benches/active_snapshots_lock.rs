#![forbid(unsafe_code)]

//! Cost of the per-read-op `active_snapshots` register+release, now removed from
//! the read path (ffs-core `begin_request_scope`/`end_request_scope`).
//!
//! Every FS read op used to `register_snapshot` at begin and `release_snapshot`
//! at end — two acquisitions of the store's single GLOBAL `active_snapshots`
//! write lock per read, the documented residual parallel-write gap (bd-bhh0i,
//! docs/NEGATIVE_EVIDENCE.md). Reads never read a pinned overlay version, so the
//! pin had no effect on results; dropping it removes a per-read serialization
//! point on the parallel path.
//!
//! This benches the EXACT removed ops (`register_snapshot` + `release_snapshot`
//! of the current snapshot) under N threads. It does not scale with threads — the
//! single global write lock serializes them — which is precisely why it capped
//! parallel-read throughput; N parallel readers now pay ZERO of this.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ffs_mvcc::sharded::ShardedMvccStore;
use ffs_types::{CommitSeq, Snapshot};
use std::hint::black_box;
use std::sync::Arc;

const PER_THREAD: u64 = 100_000;

fn hammer_register_release(threads: usize) {
    let store = Arc::new(ShardedMvccStore::for_host_parallelism());
    let snapshot = Snapshot { high: CommitSeq(0) };
    std::thread::scope(|scope| {
        for _ in 0..threads {
            let store = Arc::clone(&store);
            scope.spawn(move || {
                for _ in 0..PER_THREAD {
                    // The register/release pair a read op used to pay per request.
                    store.register_snapshot(snapshot);
                    black_box(store.release_snapshot(snapshot));
                }
            });
        }
    });
    black_box(&store);
}

fn bench_active_snapshots_lock(c: &mut Criterion) {
    let mut group = c.benchmark_group("mvcc_active_snapshots_register_release");
    group.sample_size(20);
    for threads in [1_usize, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(threads),
            &threads,
            |b, &threads| b.iter(|| hammer_register_release(threads)),
        );
    }
    group.finish();
}

criterion_group!(active_snapshots_lock, bench_active_snapshots_lock);
criterion_main!(active_snapshots_lock);
