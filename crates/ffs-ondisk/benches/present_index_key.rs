#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Hypothesis test for a lookup cache-locality lever (bd-cc-present-index-inline).
//!
//! The ext4 present-index is `FxHashMap<Vec<u8>, (u32, Ext4FileType)>` — each name
//! KEY is a separate heap allocation, so a `get(&[u8])` derefs the stored `Vec`'s
//! heap pointer to compare bytes = a cache miss per probed candidate. `lookup-bench`
//! measured cache-miss-bound (~37% miss rate, ~9 misses/lookup). This bench asks: does
//! an INLINE small-string key (`SmallVec<[u8; 24]>`, storing short names in the bucket
//! itself, no heap deref) beat the `Vec<u8>` key — or does the bigger key hurt bucket
//! density enough to offset it? Realistic short filenames (~17 bytes, inline in 24).

use criterion::{Criterion, criterion_group, criterion_main};
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;
use std::hint::black_box;

type InlineKey = SmallVec<[u8; 24]>;

fn names(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| format!("file_{i:08}.txt").into_bytes())
        .collect()
}

fn bench_present_index_key(c: &mut Criterion) {
    let keys = names(30_000);

    let vec_map: FxHashMap<Vec<u8>, u32> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (k.clone(), i as u32))
        .collect();
    let inline_map: FxHashMap<InlineKey, u32> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (SmallVec::from_slice(k), i as u32))
        .collect();

    // Correctness: both resolve every key identically.
    for k in &keys {
        assert_eq!(vec_map.get(k.as_slice()), inline_map.get(k.as_slice()));
    }

    let mut group = c.benchmark_group("present_index_key_30k");
    group.bench_function("vec_u8_key", |b| {
        b.iter(|| {
            let mut acc = 0u32;
            for k in &keys {
                if let Some(v) = vec_map.get(black_box(k.as_slice())) {
                    acc = acc.wrapping_add(*v);
                }
            }
            black_box(acc)
        });
    });
    group.bench_function("inline_smallvec_key", |b| {
        b.iter(|| {
            let mut acc = 0u32;
            for k in &keys {
                if let Some(v) = inline_map.get(black_box(k.as_slice())) {
                    acc = acc.wrapping_add(*v);
                }
            }
            black_box(acc)
        });
    });
    group.finish();
}

type PresentMap = FxHashMap<Vec<u8>, (u32, u8)>;

fn build_present_index_duplicate_names(keys: &[Vec<u8>]) -> (FxHashSet<Vec<u8>>, PresentMap) {
    let present: PresentMap = keys
        .iter()
        .enumerate()
        .map(|(i, key)| (key.clone(), (i as u32, 1)))
        .collect();
    let names = present.keys().cloned().collect();
    (names, present)
}

fn build_present_index_map_only(keys: &[Vec<u8>]) -> (FxHashSet<Vec<u8>>, PresentMap) {
    let present = keys
        .iter()
        .enumerate()
        .map(|(i, key)| (key.clone(), (i as u32, 1)))
        .collect();
    (FxHashSet::default(), present)
}

fn known_absent(names: &FxHashSet<Vec<u8>>, present: Option<&PresentMap>, name: &[u8]) -> bool {
    present.map_or_else(
        || !names.contains(name),
        |present| !present.contains_key(name),
    )
}

fn bench_present_index_build(c: &mut Criterion) {
    let keys = names(30_000);

    // The complete present map is authoritative while installed, so an empty
    // membership set has identical positive/negative answers. If that map is
    // demoted after a mutation, moving its owned keys restores the exact set
    // that the duplicate-key representation maintained.
    let (control_names, control_present) = build_present_index_duplicate_names(&keys);
    let (candidate_names, candidate_present) = build_present_index_map_only(&keys);
    assert_eq!(control_present, candidate_present);
    for key in &keys {
        assert_eq!(
            known_absent(&control_names, Some(&control_present), key),
            known_absent(&candidate_names, Some(&candidate_present), key)
        );
    }
    let absent = b"absent-file.txt";
    assert_eq!(
        known_absent(&control_names, Some(&control_present), absent),
        known_absent(&candidate_names, Some(&candidate_present), absent)
    );

    let (mut control_names, control_present) = build_present_index_duplicate_names(&keys);
    let (mut candidate_names, candidate_present) = build_present_index_map_only(&keys);
    control_names.extend(control_present.into_keys());
    candidate_names.extend(candidate_present.into_keys());
    let inserted = b"inserted-after-snapshot".to_vec();
    control_names.insert(inserted.clone());
    candidate_names.insert(inserted);
    assert_eq!(control_names, candidate_names);

    let mut group = c.benchmark_group("ext4_present_index_build_30k");
    group.bench_function("duplicate_names_a", |b| {
        b.iter(|| black_box(build_present_index_duplicate_names(black_box(&keys))));
    });
    group.bench_function("duplicate_names_b", |b| {
        b.iter(|| black_box(build_present_index_duplicate_names(black_box(&keys))));
    });
    group.bench_function("present_map_only", |b| {
        b.iter(|| black_box(build_present_index_map_only(black_box(&keys))));
    });
    group.finish();
}

// Second hypothesis (bd-cc-mvcc-chain-inline): the MVCC version store is
// `FxHashMap<BlockNumber, Vec<BlockVersion>>`. A newly-written block (the common
// case in create) has a SINGLE-element chain, so the `Vec` is a per-block heap
// alloc + a deref-on-read. `BlockVersion` is ~56 bytes (the 4 KiB payload is behind
// `VersionData::Full`'s pointer), so `SmallVec<[BlockVersion;1]>` would store the
// sole version INLINE in the hashmap value — no chain alloc on create, no deref on
// read — BUT makes the hashmap slots ~2.3× bigger (worse density) on the hot read
// path. This models it with a 56-byte value, measuring BOTH build (create's alloc)
// and get (read's deref).
#[derive(Clone, Copy)]
struct Val56 {
    /// Read by the get benches below to keep the load observable; the remaining
    /// fields are deliberately unused padding that fixes the value at 56 bytes.
    a: u64,
    _b: u64,
    _c: u64,
    _d: [u8; 32],
}
const V56: Val56 = Val56 {
    a: 1,
    _b: 2,
    _c: 3,
    _d: [7u8; 32],
};

fn bench_chain_value(c: &mut Criterion) {
    const N: u64 = 30_000;
    let mut group = c.benchmark_group("mvcc_chain_value_30k");

    group.bench_function("build_vec", |b| {
        b.iter(|| {
            let mut m: FxHashMap<u64, Vec<Val56>> = FxHashMap::default();
            for k in 0..N {
                m.insert(black_box(k), vec![V56]);
            }
            black_box(m.len())
        });
    });
    group.bench_function("build_smallvec1", |b| {
        b.iter(|| {
            let mut m: FxHashMap<u64, SmallVec<[Val56; 1]>> = FxHashMap::default();
            for k in 0..N {
                let mut sv = SmallVec::<[Val56; 1]>::new();
                sv.push(V56);
                m.insert(black_box(k), sv);
            }
            black_box(m.len())
        });
    });

    let vec_map: FxHashMap<u64, Vec<Val56>> = (0..N).map(|k| (k, vec![V56])).collect();
    let sv_map: FxHashMap<u64, SmallVec<[Val56; 1]>> = (0..N)
        .map(|k| {
            let mut sv = SmallVec::<[Val56; 1]>::new();
            sv.push(V56);
            (k, sv)
        })
        .collect();
    group.bench_function("get_vec", |b| {
        b.iter(|| {
            let mut acc = 0u64;
            for k in 0..N {
                if let Some(v) = vec_map.get(&black_box(k)) {
                    acc = acc.wrapping_add(v[0].a);
                }
            }
            black_box(acc)
        });
    });
    group.bench_function("get_smallvec1", |b| {
        b.iter(|| {
            let mut acc = 0u64;
            for k in 0..N {
                if let Some(v) = sv_map.get(&black_box(k)) {
                    acc = acc.wrapping_add(v[0].a);
                }
            }
            black_box(acc)
        });
    });
    group.finish();
}

// Third hypothesis (bd-cc-attr-cache-arc): the attr cache is
// `ShardedCache<u64, InodeAttr>` and `get` returns an OWNED ~120-byte `InodeAttr`
// clone per getattr (both filesystems' hottest read op). Storing `InodeAttr` INLINE
// makes each hashmap slot ~128 B (fat-slot / bad density — the same pattern the
// chain_value bench showed is 3× slower). `Arc<InodeAttr>` would make the slot 8 B
// (good density) and turn `get`'s 120-B memcpy into an 8-B atomic Arc clone — at the
// cost of a deref indirection when the caller reads fields. The chain_value result
// PREDICTS the pointer wins here (opposite of the chain, where the Vec was already a
// pointer). This models it: 30k entries, get-then-read-fields.
#[derive(Clone)]
struct Val120 {
    f: [u64; 15],
}
impl Val120 {
    fn new(k: u64) -> Self {
        Self { f: [k; 15] }
    }
    #[inline]
    fn sum(&self) -> u64 {
        // Read several fields, as a real getattr->FUSE-reply build would.
        self.f[0] ^ self.f[7] ^ self.f[14]
    }
}

fn bench_attr_cache_value(c: &mut Criterion) {
    use std::sync::Arc;
    const N: u64 = 30_000;
    let val_map: FxHashMap<u64, Val120> = (0..N).map(|k| (k, Val120::new(k))).collect();
    let arc_map: FxHashMap<u64, Arc<Val120>> =
        (0..N).map(|k| (k, Arc::new(Val120::new(k)))).collect();

    let mut group = c.benchmark_group("attr_cache_value_30k");
    group.bench_function("inline_val120_get_clone", |b| {
        b.iter(|| {
            let mut acc = 0u64;
            for k in 0..N {
                if let Some(v) = val_map.get(&black_box(k)) {
                    let owned: Val120 = v.clone(); // get returns owned, as ShardedCache does
                    acc = acc.wrapping_add(owned.sum());
                }
            }
            black_box(acc)
        });
    });
    group.bench_function("arc_val120_get_clone", |b| {
        b.iter(|| {
            let mut acc = 0u64;
            for k in 0..N {
                if let Some(v) = arc_map.get(&black_box(k)) {
                    let owned: Arc<Val120> = Arc::clone(v);
                    acc = acc.wrapping_add(owned.sum());
                }
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_present_index_key,
    bench_present_index_build,
    bench_chain_value,
    bench_attr_cache_value
);
criterion_main!(benches);
