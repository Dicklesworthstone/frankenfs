#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Single-threaded per-hit touch-cost isolation for the within-shard lever
//! (bd-xmh5g.382).
//!
//! The contention benches (`extent_cache_same_ns`, `extent_cache_real_contention`)
//! measure the multi-threaded lock cost. This one isolates the SINGLE-THREADED
//! per-hit work so the lever's tradeoff can be quantified without thread noise:
//!
//!   * `indexed_touch` — the production design: every hit refreshes
//!     `last_access` AND moves the entry's row in the `eviction_index` BTreeSet
//!     (one remove + one insert), so eviction is `O(log n)`.
//!   * `field_touch` — the lever's hot path: a hit only writes `last_access`
//!     (no index), so eviction must fall back to an `O(n) min_by_key` scan.
//!
//! Read-heavy workloads pay the `indexed_touch` cost on every hit but the
//! `field_touch` cost only on eviction, so the per-hit delta here times the
//! hit:eviction ratio is the lever's single-threaded headroom — the input to
//! the keep/reject decision (the multi-threaded lock-free-hit win is on top of
//! this). The aggregate fold is asserted identical first.

use criterion::{Criterion, criterion_group, criterion_main};
use smallvec::SmallVec;
use std::collections::{BTreeMap, BTreeSet};
use std::hint::black_box;

const ENTRIES: u32 = 256;
const OPS: usize = 2_000_000;
const INSERT_ENTRIES: u32 = 64;
const INSERT_OPS: usize = 4096;
const INVALIDATE_ENTRIES: u32 = 64;

fn mapping_for(lb: u32) -> u64 {
    u64::from(lb).wrapping_mul(1_000)
}

fn key(op: usize) -> u32 {
    ((op.wrapping_mul(2_654_435_761)) as u32) % ENTRIES
}

/// Production-shaped: hit refreshes `last_access` and moves the eviction-index
/// row (remove + insert).
struct Indexed {
    entries: BTreeMap<u32, (u64, u64)>, // (mapping, last_access)
    index: BTreeSet<(u64, u32)>,        // (last_access, key)
    hits: u64,
}

impl Indexed {
    fn seed() -> Self {
        let mut entries = BTreeMap::new();
        let mut index = BTreeSet::new();
        for lb in 0..ENTRIES {
            entries.insert(lb, (mapping_for(lb), 0));
            index.insert((0, lb));
        }
        Self {
            entries,
            index,
            hits: 0,
        }
    }

    fn lookup(&mut self, lb: u32) -> Option<u64> {
        self.hits = self.hits.wrapping_add(1);
        let clock = self.hits;
        let entry = self.entries.get_mut(&lb)?;
        self.index.remove(&(entry.1, lb));
        entry.1 = clock;
        self.index.insert((clock, lb));
        Some(entry.0.wrapping_add(u64::from(lb)))
    }
}

/// Lever hot path: hit only writes `last_access`; no index maintenance.
struct Field {
    entries: BTreeMap<u32, (u64, u64)>,
    hits: u64,
}

impl Field {
    fn seed() -> Self {
        let mut entries = BTreeMap::new();
        for lb in 0..ENTRIES {
            entries.insert(lb, (mapping_for(lb), 0));
        }
        Self { entries, hits: 0 }
    }

    fn lookup(&mut self, lb: u32) -> Option<u64> {
        self.hits = self.hits.wrapping_add(1);
        let clock = self.hits;
        let entry = self.entries.get_mut(&lb)?;
        entry.1 = clock;
        Some(entry.0.wrapping_add(u64::from(lb)))
    }
}

fn run_indexed(cache: &mut Indexed) -> u64 {
    let mut acc = 0_u64;
    for op in 0..OPS {
        if let Some(v) = cache.lookup(key(op)) {
            acc = acc.wrapping_add(v);
        }
    }
    acc
}

fn run_field(cache: &mut Field) -> u64 {
    let mut acc = 0_u64;
    for op in 0..OPS {
        if let Some(v) = cache.lookup(key(op)) {
            acc = acc.wrapping_add(v);
        }
    }
    acc
}

fn seed_insert_map() -> BTreeMap<u32, u64> {
    (0..INSERT_ENTRIES)
        .map(|key| (key, u64::from(key)))
        .collect()
}

fn evict_lru(entries: &mut BTreeMap<u32, u64>, protected_key: Option<u32>) {
    let victim = entries
        .iter()
        .filter(|&(&key, _)| Some(key) != protected_key)
        .min_by_key(|&(&key, &last_access)| (last_access, key))
        .map(|(&key, _)| key)
        .expect("full cache has an eviction candidate");
    entries.remove(&victim);
}

fn insert_control(entries: &mut BTreeMap<u32, u64>, key: u32, last_access: u64) {
    if entries.len() >= INSERT_ENTRIES as usize && !entries.contains_key(&key) {
        evict_lru(entries, None);
    }
    entries.insert(key, last_access);
}

fn insert_once(entries: &mut BTreeMap<u32, u64>, key: u32, last_access: u64) {
    let inserted_new = entries.insert(key, last_access).is_none();
    if inserted_new && entries.len() > INSERT_ENTRIES as usize {
        evict_lru(entries, Some(key));
    }
}

fn run_insert_workload(
    entries: &mut BTreeMap<u32, u64>,
    insert: fn(&mut BTreeMap<u32, u64>, u32, u64),
) -> u64 {
    for op in 0..INSERT_OPS {
        // One miss followed by three updates of the same newly-cached extent.
        let key = INSERT_ENTRIES + u32::try_from(op / 4).expect("bounded operation count");
        insert(
            entries,
            key,
            u64::try_from(INSERT_ENTRIES as usize + op).expect("bounded operation count"),
        );
    }
    entries.iter().fold(0_u64, |acc, (&key, &last_access)| {
        acc.wrapping_add(u64::from(key).rotate_left(17) ^ last_access)
    })
}

type InvalidateMap = BTreeMap<(u64, u32), (u32, u32)>;

fn seed_invalidate_map() -> InvalidateMap {
    (0..INVALIDATE_ENTRIES)
        .map(|index| {
            let logical_start = index * 10;
            ((0, logical_start), (logical_start, 10))
        })
        .collect()
}

fn overlaps_invalidation(
    logical_start: u32,
    count: u32,
    invalidate_start: u32,
    invalidate_end: u64,
) -> bool {
    let extent_start = u64::from(logical_start);
    let extent_end = extent_start + u64::from(count);
    extent_start < invalidate_end && extent_end > u64::from(invalidate_start)
}

fn invalidate_vec_control(entries: &mut InvalidateMap) {
    let invalidate_start = 200;
    let invalidate_end = 230;
    let keys: Vec<(u64, u32)> = entries
        .range((0, 0)..=(0, 230))
        .filter(|&(_, &(logical_start, count))| {
            overlaps_invalidation(logical_start, count, invalidate_start, invalidate_end)
        })
        .map(|(&key, _)| key)
        .collect();
    for key in keys {
        entries.remove(&key);
    }
}

fn invalidate_smallvec_candidate(entries: &mut InvalidateMap) {
    let invalidate_start = 200;
    let invalidate_end = 230;
    let keys: SmallVec<[(u64, u32); 4]> = entries
        .range((0, 0)..=(0, 230))
        .filter(|&(_, &(logical_start, count))| {
            overlaps_invalidation(logical_start, count, invalidate_start, invalidate_end)
        })
        .map(|(&key, _)| key)
        .collect();
    for key in keys {
        entries.remove(&key);
    }
}

fn invalidate_digest(entries: &InvalidateMap) -> u64 {
    entries.iter().fold(0_u64, |digest, (&key, &mapping)| {
        digest
            .rotate_left(7)
            .wrapping_add(key.0 ^ u64::from(key.1))
            .wrapping_add(u64::from(mapping.0).rotate_left(mapping.1))
    })
}

fn bench_cache(c: &mut Criterion) {
    assert_eq!(
        run_indexed(&mut Indexed::seed()),
        run_field(&mut Field::seed()),
        "field-touch fold diverged from indexed-touch"
    );

    let mut group = c.benchmark_group("extent_cache_hit_touch");
    group.bench_function("indexed_touch", |b| {
        b.iter_batched(
            Indexed::seed,
            |mut cache| black_box(run_indexed(black_box(&mut cache))),
            criterion::BatchSize::SmallInput,
        );
    });
    group.bench_function("field_touch", |b| {
        b.iter_batched(
            Field::seed,
            |mut cache| black_box(run_field(black_box(&mut cache))),
            criterion::BatchSize::SmallInput,
        );
    });
    group.finish();

    assert_eq!(
        run_insert_workload(&mut seed_insert_map(), insert_control),
        run_insert_workload(&mut seed_insert_map(), insert_once),
        "insert-once cache state diverged from the control"
    );

    let mut group = c.benchmark_group("extent_cache_insert_full");
    group.bench_function("contains_then_insert_control", |b| {
        b.iter_batched(
            seed_insert_map,
            |mut entries| black_box(run_insert_workload(black_box(&mut entries), insert_control)),
            criterion::BatchSize::SmallInput,
        );
    });
    group.bench_function("insert_once_candidate", |b| {
        b.iter_batched(
            seed_insert_map,
            |mut entries| black_box(run_insert_workload(black_box(&mut entries), insert_once)),
            criterion::BatchSize::SmallInput,
        );
    });
    group.finish();

    let mut control = seed_invalidate_map();
    let mut candidate = control.clone();
    invalidate_vec_control(&mut control);
    invalidate_smallvec_candidate(&mut candidate);
    assert_eq!(
        control, candidate,
        "inline invalidation keys changed the final cache map"
    );

    let mut group = c.benchmark_group("extent_cache_invalidate_inline_keys");
    for control_name in ["vec_control_a", "vec_control_b"] {
        group.bench_function(control_name, |b| {
            b.iter_batched(
                seed_invalidate_map,
                |mut entries| {
                    invalidate_vec_control(black_box(&mut entries));
                    black_box(invalidate_digest(&entries))
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.bench_function("smallvec_candidate", |b| {
        b.iter_batched(
            seed_invalidate_map,
            |mut entries| {
                invalidate_smallvec_candidate(black_box(&mut entries));
                black_box(invalidate_digest(&entries))
            },
            criterion::BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_cache);
criterion_main!(benches);
