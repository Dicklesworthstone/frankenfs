#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Concurrent A/B for serving btrfs reads under a shared lock (bd-xenil).
//!
//! `OpenFs::btrfs_alloc_state` is a single `Mutex<BtrfsAllocState>` that every
//! btrfs read path (read / lookup / getattr / readdir / fiemap) locks while it
//! descends the COW tree to fetch the inode + extent items. FUSE dispatches
//! concurrent requests from up to `min(available_parallelism, 8)` worker
//! threads, so that exclusive `Mutex` serializes all concurrent metadata reads
//! even though they only need shared access. Read-only paths can instead take a
//! shared `RwLock::read()` guard and descend the tree in parallel.
//!
//! This bench isolates that contention: a representative read-only tree descent
//! (binary-search lookup + value parse, mirroring the locked metadata fetch in
//! `btrfs_read_file`), run by 8 threads under (a) `parking_lot::Mutex` (current,
//! exclusive — readers serialize) vs (b) `parking_lot::RwLock::read()` (shared —
//! readers run concurrently). Both compute identical results (asserted).

use criterion::{Criterion, criterion_group, criterion_main};
use parking_lot::{Mutex, RwLock};
use std::hint::black_box;
use std::sync::Arc;

const KEYS: usize = 16_384; // entries in the representative tree
const THREADS: usize = 8; // FUSE worker threads (auto cap)
const OPS_PER_THREAD: usize = 12_000; // lookups per thread per run

/// Representative COW-tree node: sorted keys + per-key value bytes. A read does
/// a binary-search descent then parses the value — the CPU work the btrfs read
/// path performs while holding the alloc lock (extent/inode item fetch+parse).
struct Tree {
    keys: Vec<u64>,
    vals: Vec<[u8; 64]>,
}

impl Tree {
    fn build() -> Self {
        let keys: Vec<u64> = (0..KEYS as u64).map(|i| i.wrapping_mul(2)).collect();
        let vals: Vec<[u8; 64]> = (0..KEYS)
            .map(|i| {
                let mut v = [0_u8; 64];
                for (b, slot) in v.iter_mut().enumerate() {
                    *slot = (i.wrapping_mul(31).wrapping_add(b)) as u8;
                }
                v
            })
            .collect();
        Self { keys, vals }
    }

    /// Binary-search descent + value parse (the locked metadata-fetch work).
    fn lookup(&self, k: u64) -> u64 {
        let i = self.keys.partition_point(|&x| x < k);
        if i < self.keys.len() && self.keys[i] == k {
            let v = &self.vals[i];
            let mut acc = 0_u64;
            let (chunks, _remainder) = v.as_chunks::<8>();
            for chunk in chunks {
                acc = acc.wrapping_add(u64::from_le_bytes(*chunk));
            }
            acc
        } else {
            0
        }
    }
}

/// Deterministic per-thread key stream (no `Math.random` in benches).
fn key_for(thread: usize, op: usize) -> u64 {
    let x = (thread as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(op as u64);
    (x % (KEYS as u64)).wrapping_mul(2)
}

fn run_mutex(tree: &Arc<Mutex<Tree>>) -> u64 {
    let total = Arc::new(std::sync::atomic::AtomicU64::new(0));
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let tree = Arc::clone(tree);
            let total = Arc::clone(&total);
            s.spawn(move || {
                let mut acc = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let g = tree.lock();
                    acc = acc.wrapping_add(g.lookup(key_for(t, op)));
                }
                total.fetch_add(acc, std::sync::atomic::Ordering::Relaxed);
            });
        }
    });
    total.load(std::sync::atomic::Ordering::Relaxed)
}

fn run_rwlock(tree: &Arc<RwLock<Tree>>) -> u64 {
    let total = Arc::new(std::sync::atomic::AtomicU64::new(0));
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let tree = Arc::clone(tree);
            let total = Arc::clone(&total);
            s.spawn(move || {
                let mut acc = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let g = tree.read();
                    acc = acc.wrapping_add(g.lookup(key_for(t, op)));
                }
                total.fetch_add(acc, std::sync::atomic::Ordering::Relaxed);
            });
        }
    });
    total.load(std::sync::atomic::Ordering::Relaxed)
}

fn bench_locks(c: &mut Criterion) {
    let mutex_tree = Arc::new(Mutex::new(Tree::build()));
    let rwlock_tree = Arc::new(RwLock::new(Tree::build()));

    // Isomorphism: shared-lock readers compute the identical aggregate as the
    // exclusive-lock readers (same descents, same parse).
    assert_eq!(
        run_mutex(&mutex_tree),
        run_rwlock(&rwlock_tree),
        "rwlock readers diverged from mutex readers"
    );

    let mut group = c.benchmark_group("btrfs_alloc_concurrent_reads_8t");
    group.bench_function("mutex_exclusive", |b| {
        b.iter(|| black_box(run_mutex(black_box(&mutex_tree))));
    });
    group.bench_function("rwlock_shared", |b| {
        b.iter(|| black_box(run_rwlock(black_box(&rwlock_tree))));
    });
    group.finish();
}

criterion_group!(benches, bench_locks);
criterion_main!(benches);
