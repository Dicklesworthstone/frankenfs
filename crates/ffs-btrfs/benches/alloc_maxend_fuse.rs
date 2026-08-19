#![forbid(unsafe_code)]

//! Same-process A/B for folding `alloc_extent`'s `last_extent_end` computation
//! into the `allocated_ranges` build pass (bd-8fbka sibling).
//!
//! The slow path of `alloc_extent` builds a `Vec<(start,size)>` from the
//! block group's extent-tree range, then (previously) ran a SECOND O(E) walk
//! over that Vec to find the max extent end used to set `tail_verified` for the
//! next allocation. Because the Vec build already touches every extent, the max
//! end can be tracked in that same pass at zero extra cost. This benches the
//! OLD two-pass shape (build then rescan) against the NEW fused single pass,
//! for a fragmentation-heavy group where the direct-tail fast path misses and
//! the slow path runs per allocation.
//!
//! CONCLUSION (2026-07-04, BlackThrush) — REFUTED, production change reverted.
//! Measured (release-perf / opt-3, rch): two_pass **4.55 µs** vs fused
//! **5.18 µs** = fused ~**1.14x SLOWER**. Folding the max into the build loop
//! LOSES: a bulk `collect` + a SEPARATE tight max loop auto-vectorizes, while a
//! manual push-loop with an interleaved max defeats that vectorization. Classic
//! measure-don't-reason — "one fewer O(E) pass" is not faster when the fusion
//! blocks SIMD on the reduction. (Caveat: production's build is a `filter_map`
//! collect, not a memcpy `copied` collect as modelled here, so the exact prod
//! ratio differs — but the direction refutes the "fewer passes" hypothesis, so
//! the prod change was NOT a proven win and was reverted.) Kept as a guard so
//! this micro-opt isn't re-attempted.
//!
//! Self-contained; models the isolated build+maxend work (the tree range query,
//! identical in both, is excluded). Run per-crate:
//!   rch exec -- cargo bench --profile release-perf -p ffs-btrfs --bench alloc_maxend_fuse

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const E: usize = 4096; // extents in the block group (fragmentation-heavy slow path)
const EXT_SIZE: u64 = 16_384;
const BG_START: u64 = 1 << 30;
const MIN_USABLE: u64 = BG_START;

/// Raw per-extent keys the tree range yields (start, size); models the input to
/// the build loop (post `allocation_extent_range` decode).
fn raw_extents() -> Vec<(u64, u64)> {
    (0..E)
        .map(|i| (BG_START + i as u64 * EXT_SIZE, EXT_SIZE))
        .collect()
}

/// OLD: build the Vec, then a SEPARATE O(E) rescan for the max end.
fn two_pass(raw: &[(u64, u64)]) -> (Vec<(u64, u64)>, u64) {
    // Kept verbatim: this bench exists to measure the OLD construction against the
    // fused one, so the expression under test is the point. `to_vec()` would be the
    // same work under a different spelling, but rewriting the control arm of a
    // comparison to satisfy a lint is how a benchmark quietly stops measuring what
    // its name says.
    #[expect(clippy::iter_cloned_collect, reason = "the control arm's exact shape is the subject")]
    let allocated_ranges: Vec<(u64, u64)> = raw.iter().copied().collect();
    let mut last_extent_end = MIN_USABLE;
    for &(ext_start, ext_size) in &allocated_ranges {
        let ext_end = ext_start.checked_add(ext_size).unwrap();
        if ext_end > last_extent_end {
            last_extent_end = ext_end;
        }
    }
    (allocated_ranges, last_extent_end)
}

/// NEW: build the Vec and track the max end in the SAME pass.
fn fused(raw: &[(u64, u64)]) -> (Vec<(u64, u64)>, u64) {
    let mut allocated_ranges: Vec<(u64, u64)> = Vec::with_capacity(raw.len());
    let mut last_extent_end = MIN_USABLE;
    for &(ext_start, ext_size) in raw {
        let ext_end = ext_start.checked_add(ext_size).unwrap();
        if ext_end > last_extent_end {
            last_extent_end = ext_end;
        }
        allocated_ranges.push((ext_start, ext_size));
    }
    (allocated_ranges, last_extent_end)
}

fn bench(c: &mut Criterion) {
    let raw = raw_extents();

    // Equivalence: both paths produce identical range list + max end.
    let a = two_pass(&raw);
    let b = fused(&raw);
    assert_eq!(a.0, b.0, "range lists must match");
    assert_eq!(a.1, b.1, "last_extent_end must match");

    let mut g = c.benchmark_group("alloc_extent_build_maxend");
    g.bench_function("two_pass", |bch| {
        bch.iter(|| black_box(two_pass(black_box(&raw))));
    });
    g.bench_function("fused", |bch| {
        bch.iter(|| black_box(fused(black_box(&raw))));
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
