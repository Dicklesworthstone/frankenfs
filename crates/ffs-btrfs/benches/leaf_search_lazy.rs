#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Primitive A/B for a btrfs leaf key search: eagerly parse ALL item keys into a
//! Vec then binary-search (what happens the FIRST time a node is parsed) vs a
//! binary search directly over the raw 25-byte item table, decoding only the
//! O(log N) keys the search probes.
//!
//! CAVEAT recorded with the result: production reads go through a parsed-node
//! CACHE (`BtrfsParsedNode`, the `parsed_node_cache` 6.37x win) that parses each
//! node's items ONCE and reuses them across every search of that node — so for a
//! node searched K times, eager-once (K reuses of one O(N) parse) beats lazy
//! (K × O(log N) re-decodes) whenever K is large, which is exactly the walk
//! workload. This bench isolates the single-search primitive to quantify that.
//!
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cc \
//!   rch exec -- cargo bench --profile release-perf -p ffs-btrfs --bench leaf_search_lazy

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const HEADER: usize = 101;
const ITEM: usize = 25;

/// Build a leaf item table: N items with objectid = idx (sorted), key at
/// item base (objectid u64 LE @0).
fn build_item_table(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; HEADER + n * ITEM];
    for i in 0..n {
        let base = HEADER + i * ITEM;
        buf[base..base + 8].copy_from_slice(&(i as u64).to_le_bytes());
    }
    buf
}

fn read_objectid(buf: &[u8], idx: usize) -> u64 {
    let base = HEADER + idx * ITEM;
    u64::from_le_bytes(buf[base..base + 8].try_into().unwrap())
}

/// Eager: decode all N objectids into a Vec, then binary-search.
fn eager_search(buf: &[u8], n: usize, target: u64) -> Option<usize> {
    let keys: Vec<u64> = (0..n).map(|i| read_objectid(buf, i)).collect();
    keys.binary_search(&target).ok()
}

/// Lazy: binary-search over the raw item table, decoding only probed keys.
fn lazy_search(buf: &[u8], n: usize, target: u64) -> Option<usize> {
    let (mut lo, mut hi) = (0usize, n);
    while lo < hi {
        let mid = lo.midpoint(hi);
        match read_objectid(buf, mid).cmp(&target) {
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
            std::cmp::Ordering::Equal => return Some(mid),
        }
    }
    None
}

fn bench(c: &mut Criterion) {
    for n in [64usize, 200] {
        let buf = build_item_table(n);
        let target = (n / 2) as u64;
        assert_eq!(eager_search(&buf, n, target), lazy_search(&buf, n, target));
        let mut g = c.benchmark_group(format!("btrfs_leaf_search_{n}items"));
        g.bench_function("eager_parse_all", |b| {
            b.iter(|| black_box(eager_search(black_box(&buf), n, black_box(target))));
        });
        g.bench_function("lazy_raw", |b| {
            b.iter(|| black_box(lazy_search(black_box(&buf), n, black_box(target))));
        });
        g.finish();
    }
}

/// Amortized: the production parsed-node cache parses a node ONCE (miss) then
/// reuses it across K searches (hits). Model that: parse all keys once, then K
/// searches over the parsed Vec.
fn eager_amortized(buf: &[u8], n: usize, k: usize) -> u64 {
    let keys: Vec<u64> = (0..n).map(|i| read_objectid(buf, i)).collect();
    let mut acc = 0u64;
    for t in 0..k {
        if let Ok(idx) = keys.binary_search(&((t % n) as u64)) {
            acc = acc.wrapping_add(idx as u64);
        }
    }
    acc
}

/// A lazy raw-search node has no parsed form to cache, so it re-decodes O(log N)
/// keys per search: K raw searches.
fn lazy_amortized(buf: &[u8], n: usize, k: usize) -> u64 {
    let mut acc = 0u64;
    for t in 0..k {
        if let Some(idx) = lazy_search(buf, n, (t % n) as u64) {
            acc = acc.wrapping_add(idx as u64);
        }
    }
    acc
}

fn bench_amortized(c: &mut Criterion) {
    let n = 200usize;
    let buf = build_item_table(n);
    // K = searches per node before eviction. Production walk has high cache-hit
    // (leaves hold ~200 items each accessed by many files), so K is large.
    for k in [1usize, 8, 64] {
        assert_eq!(eager_amortized(&buf, n, k), lazy_amortized(&buf, n, k));
        let mut g = c.benchmark_group(format!("btrfs_leaf_amortized_200items_k{k}"));
        g.bench_function("eager_parse_once_then_k", |b| {
            b.iter(|| black_box(eager_amortized(black_box(&buf), n, black_box(k))));
        });
        g.bench_function("lazy_k_raw", |b| {
            b.iter(|| black_box(lazy_amortized(black_box(&buf), n, black_box(k))));
        });
        g.finish();
    }
}

criterion_group!(benches, bench, bench_amortized);
criterion_main!(benches);
