#![forbid(unsafe_code)]

//! De-risking A/B for a proposed `active_snapshots` atomic-refcount, to decide
//! whether it is worth a multi-turn (Loom-gated) implementation.
//!
//! After reads stopped pinning (0576bb8b), the remaining `active_snapshots`
//! contention is the per-WRITE register+release, which today take the store's
//! single `RwLock<BTreeMap>` WRITE lock. The proposed change keeps `write()` only
//! for INSERTING a new key and uses a shared `read()` lock + an `AtomicU64` value
//! to bump an EXISTING key's refcount, so concurrent ops at the SAME snapshot
//! don't serialize.
//!
//! The open question is workload sharing: parallel writers at a rapidly-advancing
//! head register DISTINCT snapshots (all hit the insert/write-lock path → no
//! benefit); only writers that SHARE a head (a burst of begins before commits
//! advance it) hit the read-lock fast path. This benches both extremes for the
//! current (write-lock) vs atomic (read-lock fast path) refcount, N threads.
//! `PARWRITE` prototypes are faithful to the two designs (not production code).

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const PER_THREAD: u64 = 100_000;

// ── Current design: write lock for every register/release ──────────────────
type CurrentMap = RwLock<BTreeMap<u64, u64>>;

fn current_register(map: &CurrentMap, key: u64) {
    map.write()
        .entry(key)
        .and_modify(|c| *c = c.saturating_add(1))
        .or_insert(1);
}

fn current_release(map: &CurrentMap, key: u64) {
    let mut m = map.write();
    if let Some(count) = m.get(&key).copied() {
        if count <= 1 {
            m.remove(&key);
        } else {
            m.insert(key, count - 1);
        }
    }
}

// ── Proposed design: read lock + atomic for existing keys, write only to insert ─
type AtomicMap = RwLock<BTreeMap<u64, AtomicU64>>;

fn atomic_register(map: &AtomicMap, key: u64) {
    {
        let m = map.read();
        if let Some(counter) = m.get(&key) {
            counter.fetch_add(1, Ordering::AcqRel);
            return;
        }
    }
    // Slow path: insert a new key under the write lock (double-checked).
    let mut m = map.write();
    m.entry(key)
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::AcqRel);
}

fn atomic_release(map: &AtomicMap, key: u64) {
    // Lazy remove (a sweep reclaims zeroed keys off the hot path); the bench keeps
    // register/release balanced so no underflow occurs.
    let m = map.read();
    if let Some(counter) = m.get(&key) {
        counter.fetch_sub(1, Ordering::AcqRel);
    }
}

fn run<M, R, L>(threads: usize, map: &Arc<M>, reg: R, rel: L, distinct: bool)
where
    M: Send + Sync + 'static,
    R: Fn(&M, u64) + Send + Sync + Copy + 'static,
    L: Fn(&M, u64) + Send + Sync + Copy + 'static,
{
    std::thread::scope(|scope| {
        for t in 0..threads {
            let map = Arc::clone(map);
            let key = if distinct { t as u64 + 1 } else { 0 };
            scope.spawn(move || {
                for _ in 0..PER_THREAD {
                    reg(&map, key);
                    rel(&map, key);
                }
            });
        }
    });
    black_box(&map);
}

fn bench_refcount(c: &mut Criterion) {
    for (label, distinct) in [("shared_key", false), ("distinct_keys", true)] {
        let mut group = c.benchmark_group(format!("mvcc_active_snapshots_refcount_{label}"));
        group.sample_size(20);
        for threads in [1_usize, 2, 4, 8] {
            group.bench_with_input(
                BenchmarkId::new("current_write_lock", threads),
                &threads,
                |b, &t| {
                    b.iter(|| {
                        run(
                            t,
                            &Arc::new(CurrentMap::new(BTreeMap::new())),
                            current_register,
                            current_release,
                            distinct,
                        );
                    });
                },
            );
            group.bench_with_input(
                BenchmarkId::new("atomic_read_fastpath", threads),
                &threads,
                |b, &t| {
                    b.iter(|| {
                        run(
                            t,
                            &Arc::new(AtomicMap::new(BTreeMap::new())),
                            atomic_register,
                            atomic_release,
                            distinct,
                        );
                    });
                },
            );
        }
        group.finish();
    }
}

criterion_group!(active_snapshots_refcount, bench_refcount);
criterion_main!(active_snapshots_refcount);
