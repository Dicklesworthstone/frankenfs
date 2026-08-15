#![forbid(unsafe_code)]
//! htree leaf split / build sorts entries by their 32-bit dx hash to find a
//! clean split boundary (`split_htree_leaf` @8267, `split_htree_leaf_in_dx_node`
//! @8393, the build path @7138). The code uses `sort_by_key` (STABLE), but the
//! authors' own comments state ties are irrelevant (equal-hash runs never
//! straddle the boundary; within-leaf order is a linear scan). A STABLE sort
//! allocates an O(n) temp buffer and preserves tie order at a cost; an UNSTABLE
//! sort is in-place and faster. A/B on a realistic ~340-entry leaf of fat
//! `(u32 hash, u32 ino, u8 ft, &[u8] name)` tuples (24-byte elements).
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench htree_split_sort
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench(c: &mut Criterion) {
    // 340 entries — a full 4 KiB leaf. Scrambled hashes with deliberate ties
    // (every 8th entry collides) to exercise the stable/unstable difference.
    let names: Vec<Vec<u8>> = (0..340)
        .map(|i| format!("file_{i:08}").into_bytes())
        .collect();
    let base: Vec<(u32, u32, u8, &[u8])> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let idx = u32::try_from(i).expect("fixture entry index fits u32");
            let h = if i % 8 == 0 {
                (idx / 8).wrapping_mul(0x9E37_79B1)
            } else {
                idx.wrapping_mul(0x9E37_79B1) ^ 0x5BD1_E995
            };
            (h, idx + 12, 1u8, n.as_slice())
        })
        .collect();

    // sanity: both orderings agree on the multiset and on the sorted hash order
    let mut a = base.clone();
    let mut b = base.clone();
    a.sort_by_key(|&(h, _, _, _)| h);
    b.sort_unstable_by_key(|&(h, _, _, _)| h);
    assert!(a.iter().map(|e| e.0).eq(b.iter().map(|e| e.0)));

    let mut g = c.benchmark_group("htree_split_sort");
    g.bench_function("stable", |bch| {
        bch.iter_batched(
            || base.clone(),
            |mut v| {
                v.sort_by_key(|&(h, _, _, _)| h);
                black_box(v)
            },
            BatchSize::SmallInput,
        );
    });
    g.bench_function("unstable", |bch| {
        bch.iter_batched(
            || base.clone(),
            |mut v| {
                v.sort_unstable_by_key(|&(h, _, _, _)| h);
                black_box(v)
            },
            BatchSize::SmallInput,
        );
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
