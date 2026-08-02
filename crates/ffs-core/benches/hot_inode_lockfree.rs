#![allow(clippy::cast_possible_truncation)]

//! bd-eflng primitive characterization: the mechanism behind the proposed
//! lock-free single-entry hot-inode RO cache (design in
//! `docs/NEGATIVE_EVIDENCE.md`, the lock-free-hot-inode-read entry).
//!
//! The single-file parallel-random-read residual (3.3x off kernel) is dominated
//! by the per-read `ShardedCache` shard-`Mutex` on the ONE hot inode-table block:
//! N reader threads all resolve the SAME inode -> the SAME shard -> the SAME
//! `WordLock`, so the cache `get` serialises. This bench isolates that mechanism
//! by comparing two ways to serve the hot key under contention:
//!
//!   * `sharded_mutex_get` — a `parking_lot::Mutex`-per-shard map (what
//!     `ShardedCache` is): a hot key locks one shard's Mutex on every read.
//!   * `arc_swap_load` — a single-slot `arc_swap::ArcSwapOption` (the proposed
//!     hot-inode cache): a lock-free RCU `load`, no per-read Mutex.
//!
//! Two workloads bracket the lever's expected win AND its risk:
//!   * `hot_key/*` (single-file random read): all threads read ONE key — this is
//!     where the lock-free slot should WIN (no shard-Mutex).
//!   * `distinct_keys/*` (multi-file): each thread reads its OWN key — the
//!     single-slot design THRASHES (every read misses -> store), quantifying the
//!     multi-file regression risk of the single-entry cache in ISOLATION (the
//!     real fs path amortises the store against the block read it replaces, so
//!     this is an upper bound on the thrash, not the net fs effect).
//!
//! Primitive-isolation A/B in the campaign's own style (cf. `ext4_group_lock_layout`,
//! `extent_leaf_search`). It does NOT touch `read_inode_with_scope` (lib.rs is
//! peer-reserved) — it characterises the primitive so the eventual cache change
//! lands with quantified evidence.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- \
//!     cargo bench --profile release-perf -p ffs-core --bench hot_inode_lockfree

use arc_swap::ArcSwapOption;
use criterion::{criterion_group, criterion_main, Criterion};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;

/// The width the shipped ext4 read fan-out uses after bd-ddryj (nproc/4 clamped
/// [4,16]); 16 is the measured optimum on the 64-core box, so it is the honest
/// concurrency at which to compare the primitives.
const THREADS: usize = 16;
/// Reads per thread per iteration — large enough that the steady-state per-read
/// primitive cost dominates the fixed `thread::scope` spawn cost (which is equal
/// across both arms and cancels in the A/B).
const OPS: usize = 20_000;
/// `ShardedCache`-like shard count (power of two; key -> `key % SHARDS`).
const SHARDS: usize = 64;
const HOT_KEY: u64 = 42;

/// A `parking_lot::Mutex`-per-shard map — the structural stand-in for the
/// `ShardedCache` whose per-shard `WordLock` the profile blamed.
struct ShardedMutexMap {
    shards: Vec<Mutex<HashMap<u64, u64>>>,
}

impl ShardedMutexMap {
    fn new() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }
    fn insert(&self, key: u64, val: u64) {
        self.shards[(key as usize) % SHARDS].lock().insert(key, val);
    }
    fn get(&self, key: u64) -> Option<u64> {
        self.shards[(key as usize) % SHARDS].lock().get(&key).copied()
    }
}

fn run_threads(op: impl Fn(usize) + Sync) {
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let op = &op;
            s.spawn(move || op(t));
        }
    });
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("hot_inode_lockfree");

    // ── hot key (single-file random read): all threads read the SAME inode ──
    g.bench_function("hot_key/sharded_mutex_get", |b| {
        let map = Arc::new(ShardedMutexMap::new());
        map.insert(HOT_KEY, 999);
        b.iter(|| {
            run_threads(|_| {
                let mut acc = 0u64;
                for _ in 0..OPS {
                    acc = acc.wrapping_add(map.get(HOT_KEY).unwrap_or(0));
                }
                black_box(acc);
            });
        });
    });
    g.bench_function("hot_key/arc_swap_load", |b| {
        let slot: Arc<ArcSwapOption<(u64, u64)>> =
            Arc::new(ArcSwapOption::from(Some(Arc::new((HOT_KEY, 999u64)))));
        b.iter(|| {
            run_threads(|_| {
                let mut acc = 0u64;
                for _ in 0..OPS {
                    if let Some(kv) = &*slot.load() {
                        if kv.0 == HOT_KEY {
                            acc = acc.wrapping_add(kv.1);
                        }
                    }
                }
                black_box(acc);
            });
        });
    });

    // ── distinct keys (multi-file): each thread reads its OWN inode ──
    g.bench_function("distinct_keys/sharded_mutex_get", |b| {
        let map = Arc::new(ShardedMutexMap::new());
        for t in 0..THREADS {
            map.insert(t as u64, t as u64 + 1);
        }
        b.iter(|| {
            run_threads(|t| {
                let key = t as u64;
                let mut acc = 0u64;
                for _ in 0..OPS {
                    acc = acc.wrapping_add(map.get(key).unwrap_or(0));
                }
                black_box(acc);
            });
        });
    });
    g.bench_function("distinct_keys/arc_swap_thrash", |b| {
        // Single slot + distinct per-thread keys ⇒ every read misses another
        // thread's key and stores its own: the worst-case thrash the single-entry
        // design pays under a multi-file workload.
        let slot: Arc<ArcSwapOption<(u64, u64)>> =
            Arc::new(ArcSwapOption::from(Some(Arc::new((0u64, 1u64)))));
        b.iter(|| {
            run_threads(|t| {
                let key = t as u64;
                let mut acc = 0u64;
                for _ in 0..OPS {
                    match &*slot.load() {
                        Some(kv) if kv.0 == key => acc = acc.wrapping_add(kv.1),
                        _ => slot.store(Some(Arc::new((key, key + 1)))),
                    }
                }
                black_box(acc);
            });
        });
    });

    g.finish();

    // Complete one-shot multi-file reads cannot reuse the single hot slot.
    // Mirror the miss-path publication cost with duplicate controls, then the
    // candidate's owned-local path. The payload keeps the Arc allocation
    // representative without benchmarking inode parsing itself.
    let mut g = c.benchmark_group("hot_inode_complete_read_admission_256");
    for name in ["control_publish_a", "control_publish_b"] {
        g.bench_function(name, |b| {
            let slot: Arc<ArcSwapOption<(u64, Arc<[u8; 256]>)>> =
                Arc::new(ArcSwapOption::empty());
            b.iter(|| {
                for key in 0..256u64 {
                    let parsed = Arc::new(black_box([key as u8; 256]));
                    slot.store(Some(Arc::new((key, Arc::clone(&parsed)))));
                    black_box(parsed);
                }
            });
        });
    }
    g.bench_function("candidate_keep_owned", |b| {
        b.iter(|| {
            for key in 0..256u64 {
                let parsed = black_box([key as u8; 256]);
                black_box(parsed);
            }
        });
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
