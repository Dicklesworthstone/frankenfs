#![forbid(unsafe_code)]
//! A/B for the ext4 extent leaf search (walk_extent_tree leaf scan): linear
//! `for ext in extents` early-exit vs binary search over the SORTED extents.
//! Re-run per resolved block (the child-cache stores the child block, not the
//! resolved extent), so for a fragmented file (many extents/leaf) it is O(E)
//! per block. Target = a late extent (worst case for linear).
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench extent_leaf_search
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
// (logical_block start, len) sorted by start; each extent covers [start, start+len).
fn make(e: u32) -> Vec<(u32, u32)> {
    (0..e).map(|i| (i * 4, 4)).collect()
}
fn linear(exts: &[(u32, u32)], target: u32) -> Option<usize> {
    for (i, &(start, len)) in exts.iter().enumerate() {
        if target >= start && target < start + len {
            return Some(i);
        }
    }
    None
}
fn binary(exts: &[(u32, u32)], target: u32) -> Option<usize> {
    // last extent with start <= target
    let p = exts.partition_point(|&(start, _)| start <= target);
    if p == 0 {
        return None;
    }
    let (start, len) = exts[p - 1];
    if target >= start && target < start + len {
        Some(p - 1)
    } else {
        None
    }
}
// Full per-block resolution for a depth-1 tree on a cache HIT: one index binary
// search (choose child) + one leaf binary search — the entire CPU cost of
// resolving one logical block once the child leaf is cached. Everything below
// this (read_block) is a zero-copy slice; everything above is the block copy.
fn resolve_depth1(index: &[(u32, u32)], leaf: &[(u32, u32)], target: u32) -> Option<usize> {
    let _child = binary(index, target)?; // extent_index_choose shape
    binary(leaf, target) // extent_leaf_lookup on the cached child
}

// Models `walk_extent_tree_cached`'s depth-1 cache-HIT path. `ExtentTree` owns a
// `Vec`, so `.take()` + store-back moves that owned enum out of the array and back
// on every block, purely for the borrow checker (the leaf recursion never touches
// `cache`). The lever borrows the leaf in place instead. Both are byte-identical.
/// Models the parsed on-disk extent header. The fields are never read by these
/// benches on purpose — the point is that the ORIG arm PARSES them per block
/// while the lever does not, so removing them would delete the very work being
/// measured. Same reasoning as `Tree::Index` below (bd-3ao0l).
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct Hdr {
    magic: u16,
    entries: u16,
    max: u16,
    depth: u16,
    generation: u32,
}
#[derive(Clone)]
enum Tree {
    Leaf(Vec<(u32, u32)>),
    #[allow(dead_code)]
    Index(Vec<(u32, u32)>),
}
type Slot = Option<(u64, Hdr, Tree)>;

fn take_store(slot: &mut Slot, key: u64, target: u32) -> Option<usize> {
    let cached = slot.take();
    let (h, t) = match cached {
        Some((lb, h, t)) if lb == key => (h, t),
        _ => return None,
    };
    let r = if let Tree::Leaf(exts) = &t {
        binary(exts, target)
    } else {
        None
    };
    *slot = Some((key, h, t));
    r
}
fn borrow_in_place(slot: &Slot, key: u64, target: u32) -> Option<usize> {
    if let Some((lb, _, Tree::Leaf(exts))) = slot
        && *lb == key
    {
        return binary(exts, target);
    }
    None
}
// Sequential resolution of a whole file (blocks 0..total in order), the read
// engine's access pattern. `binary_seq` = one partition_point per block (current
// ext4_resolve_block_from_mappings). `hint_seq` carries the last hit index and
// checks the current + next extent (O(1)) before falling back to binary. Results
// byte-identical; the hint just skips the log-E search when the next block is in
// the same or next extent — which sequential reads always are.
fn binary_seq(exts: &[(u32, u32)], total: u32) -> u64 {
    let mut acc = 0u64;
    let mut blk = 0u32;
    while blk < total {
        if let Some(i) = binary(exts, blk) {
            acc = acc.wrapping_add(i as u64);
        }
        blk += 1;
    }
    acc
}
fn hint_seq(exts: &[(u32, u32)], total: u32) -> u64 {
    let mut acc = 0u64;
    let mut hint = 0usize;
    let mut blk = 0u32;
    while blk < total {
        // Single-candidate hint: check ONLY the last-hit extent (the sequential
        // common case — same extent as the previous block); on a miss (extent
        // boundary or non-sequential) fall back to binary, which is identical.
        let found = match exts.get(hint) {
            Some(&(start, len)) if blk >= start && blk < start + len => Some(hint),
            _ => binary(exts, blk),
        };
        if let Some(i) = found {
            acc = acc.wrapping_add(i as u64);
            hint = i;
        }
        blk += 1;
    }
    acc
}
fn bench_search_cases(c: &mut Criterion) {
    // COMMON case first (e=1,2,4 with a FIRST-extent hit = linear's best case, and
    // the overwhelmingly common shape for real files), then the worst case the
    // original bench covered. `extent_leaf_lookup` runs per resolved block on EVERY
    // read, so the common case is the hot case; the "negligible for 1-4 extents"
    // claim in ext4.rs::extent_leaf_lookup is verified here, not assumed.
    // Cases: (extent_count, target, label).
    let cases: &[(u32, u32, &str)] = &[
        (1, 1, "e1_hit0"),        // single contiguous extent — the 90%+ case
        (2, 1, "e2_hit0"),        // first-extent hit, linear returns immediately
        (4, 1, "e4_hit0"),        // first-extent hit
        (4, 15, "e4_hitlast"),    // last-extent hit (linear worst case, small E)
        (64, 255, "e64_hitlast"), // fragmented, last hit — binary's win case
        (256, 1023, "e256_hitlast"),
    ];
    for &(e, target, label) in cases {
        let exts = make(e);
        assert_eq!(
            linear(&exts, target),
            binary(&exts, target),
            "arms must agree for {label}"
        );
        let mut g = c.benchmark_group(format!("extent_search_{label}"));
        // NULL CONTROL: identical arm registered twice — its ratio is the noise
        // floor; any linear-vs-binary gap smaller than binary-vs-binary is noise.
        g.bench_function("binary_a", |b| {
            b.iter(|| black_box(binary(black_box(&exts), black_box(target))));
        });
        g.bench_function("binary_b", |b| {
            b.iter(|| black_box(binary(black_box(&exts), black_box(target))));
        });
        g.bench_function("linear", |b| {
            b.iter(|| black_box(linear(black_box(&exts), black_box(target))));
        });
        g.finish();
    }
}

/// Full depth-1 per-block resolution (index choose + leaf lookup) on a cache
/// hit: the ENTIRE ffs-ondisk CPU budget for resolving one logical block.
fn bench_resolve_vs_copy(c: &mut Criterion) {
    // Compared against a warm 4 KiB block copy (the layer above) to show
    // Compared against a warm 4 KiB block copy (the layer above) to show
    // resolution is a small fraction of the read. index=256 children, leaf=256
    // extents (a heavily fragmented file — worst case for resolution cost).
    let index = make(256);
    let leaf = make(256);
    let target = 1023;
    let mut buf = vec![0u8; 4096];
    let src = vec![7u8; 4096];
    let mut g = c.benchmark_group("extent_resolve_vs_copy");
    g.bench_function("resolve_depth1_a", |b| {
        b.iter(|| {
            black_box(resolve_depth1(
                black_box(&index),
                black_box(&leaf),
                black_box(target),
            ))
        });
    });
    g.bench_function("resolve_depth1_b", |b| {
        b.iter(|| {
            black_box(resolve_depth1(
                black_box(&index),
                black_box(&leaf),
                black_box(target),
            ))
        });
    });
    g.bench_function("copy_4k_block", |b| {
        b.iter(|| {
            buf.copy_from_slice(black_box(&src));
            black_box(buf[0])
        });
    });
    g.finish();
}

/// The extent-cache lever: take/store (current) vs borrow-in-place (candidate)
/// on the depth-1 cache-HIT path. leaf=256 extents. Arms proven identical.
fn bench_cache_hit(c: &mut Criterion) {
    let key = 42u64;
    let hdr = Hdr {
        magic: 0xf30a,
        entries: 256,
        max: 256,
        depth: 0,
        generation: 0,
    };
    let leaf256 = make(256);
    let tgt = 1023u32;
    let mut slot: Slot = Some((key, hdr, Tree::Leaf(leaf256.clone())));
    let slot_ref: Slot = Some((key, hdr, Tree::Leaf(leaf256)));
    assert_eq!(
        take_store(&mut slot, key, tgt),
        borrow_in_place(&slot_ref, key, tgt)
    );
    let mut g = c.benchmark_group("extent_cache_hit");
    g.bench_function("take_store_a", |b| {
        b.iter(|| {
            black_box(take_store(
                black_box(&mut slot),
                black_box(key),
                black_box(tgt),
            ))
        });
    });
    g.bench_function("take_store_b", |b| {
        b.iter(|| {
            black_box(take_store(
                black_box(&mut slot),
                black_box(key),
                black_box(tgt),
            ))
        });
    });
    g.bench_function("borrow_in_place", |b| {
        b.iter(|| {
            black_box(borrow_in_place(
                black_box(&slot_ref),
                black_box(key),
                black_box(tgt),
            ))
        });
    });
    g.finish();
}

/// Sequential whole-file resolution: binary-per-block vs last-hit-hint. Files
/// with E extents each covering 4 blocks, read block-by-block in order (the
/// read engine's pattern). Arms proven identical over the full sweep.
fn bench_resolve_seq(c: &mut Criterion) {
    for e in [1u32, 4, 64, 256] {
        let exts = make(e);
        let total = e * 4;
        assert_eq!(
            binary_seq(&exts, total),
            hint_seq(&exts, total),
            "seq arms must agree e{e}"
        );
        let mut g = c.benchmark_group(format!("extent_resolve_seq_e{e}"));
        g.bench_function("binary_seq_a", |b| {
            b.iter(|| black_box(binary_seq(black_box(&exts), black_box(total))));
        });
        g.bench_function("binary_seq_b", |b| {
            b.iter(|| black_box(binary_seq(black_box(&exts), black_box(total))));
        });
        g.bench_function("hint_seq", |b| {
            b.iter(|| black_box(hint_seq(black_box(&exts), black_box(total))));
        });
        g.finish();
    }
}

/// Split into one function per group (bd-3ao0l): each `BenchmarkGroup` ends at
/// its own `finish()` instead of living to the end of a 123-line `bench`, which
/// is what `significant_drop_tightening` and `too_many_lines` were both pointing
/// at. The four sections already had independent fixtures.
fn bench(c: &mut Criterion) {
    bench_search_cases(c);
    bench_resolve_vs_copy(c);
    bench_cache_hit(c);
    bench_resolve_seq(c);
}

criterion_group!(benches, bench);
criterion_main!(benches);
