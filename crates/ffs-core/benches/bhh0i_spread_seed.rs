#![forbid(unsafe_code)]

//! Same-machine A/B for the bd-bhh0i Part-B spread seed (sharded create/mkdir).
//!
//! `bhh0i_spread_seed` is called once per sharded create/mkdir to pick the
//! per-thread inode-scan start group. The seed is a pure function of the stable
//! `ThreadId`, so recomputing it every call — a `thread::current()` handle
//! clone/drop (an atomic `Arc` refcount round-trip) plus a `SipHash` over the id
//! — is redundant per-op overhead on the parallel-create path. This benches
//! recompute-per-call versus a thread-local cached read (the landed change).
//! Byte-identical: the same `ThreadId` yields the same seed on every call, so the
//! cached value equals what the recompute returns (asserted below).

use criterion::{Criterion, criterion_group, criterion_main};
use std::hash::{Hash, Hasher};
use std::hint::black_box;

fn recompute_seed() -> u32 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::thread::current().id().hash(&mut hasher);
    hasher.finish() as u32
}

fn cached_seed() -> u32 {
    thread_local! {
        static SEED: u32 = {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::thread::current().id().hash(&mut hasher);
            hasher.finish() as u32
        };
    }
    SEED.with(|seed| *seed)
}

fn bench_spread_seed(c: &mut Criterion) {
    // Isomorphism: both variants yield the same seed on this thread.
    assert_eq!(recompute_seed(), cached_seed(), "cached seed must equal recompute");

    let mut group = c.benchmark_group("bhh0i_spread_seed");
    // Old: recompute the SipHash over `thread::current().id()` on every call.
    group.bench_function("recompute_per_call", |b| {
        b.iter(|| black_box(recompute_seed()));
    });
    // New: read the per-thread cached seed.
    group.bench_function("thread_local_cached", |b| {
        b.iter(|| black_box(cached_seed()));
    });
    group.finish();
}

criterion_group!(bhh0i_spread_seed, bench_spread_seed);
criterion_main!(bhh0i_spread_seed);
