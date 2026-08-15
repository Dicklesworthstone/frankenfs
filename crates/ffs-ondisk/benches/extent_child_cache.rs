#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! A/B for caching the child extent block across a depth>0 extent walk.
//!
//! My prior win hoisted the ROOT extent-tree parse out of the per-block
//! read/readdir/lookup loops. For a depth ≥ 1 tree, `walk_extent_tree` still
//! re-reads AND re-parses the CHILD index/leaf block (a heap-allocating
//! `Vec<Ext4Extent>` build + sort/overlap validation) on EVERY logical block,
//! even though consecutive blocks fall under the same child (one 4 KiB leaf
//! covers up to ~340 extents). `ExtentResolveCache` memoizes the last child at
//! each level so a sequential walk parses each child once. This benches the
//! per-block child re-parse (old) vs parse-child-once (new), with the identical
//! root-index selection + leaf scan in both arms so the ratio isolates the
//! eliminated child parse+alloc.
//!
//! Run per-crate:
//!   CARGO_TARGET_DIR=/data/projects/frankenfs/.rch-targets/blackthrush-dig2 \
//!   rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench extent_child_cache

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::ext4::{ExtentTree, parse_extent_tree};
use std::hint::black_box;

const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
const N: u32 = 32; // logical blocks in one 128 KiB read
const SPLIT: u32 = 16; // first child covers 0..16, second 16..32

/// Build a depth-0 child extent-leaf block: 2 extents of 8 blocks covering
/// `[lo, lo+16)`.
fn child_leaf_bytes(lo: u32) -> Vec<u8> {
    let mut b = vec![0u8; 4096];
    b[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
    b[2..4].copy_from_slice(&2u16.to_le_bytes()); // entries
    b[4..6].copy_from_slice(&340u16.to_le_bytes()); // max_entries
    b[6..8].copy_from_slice(&0u16.to_le_bytes()); // depth=0
    for (i, (lb, phys)) in [(lo, lo + 2000), (lo + 8, lo + 3000)].iter().enumerate() {
        let o = 12 + i * 12;
        b[o..o + 4].copy_from_slice(&lb.to_le_bytes());
        b[o + 4..o + 6].copy_from_slice(&8u16.to_le_bytes()); // len=8
        b[o + 6..o + 8].copy_from_slice(&0u16.to_le_bytes());
        b[o + 8..o + 12].copy_from_slice(&phys.to_le_bytes());
    }
    b
}

/// Mirror of the production leaf scan (identical work in both arms).
fn walk_leaf(tree: &ExtentTree, logical_block: u32) -> Option<u64> {
    match tree {
        ExtentTree::Leaf(extents) => {
            for ext in extents {
                let start = ext.logical_block;
                let len = u32::from(ext.actual_len());
                if logical_block >= start && logical_block < start.saturating_add(len) {
                    return Some(ext.physical_start + u64::from(logical_block - start));
                }
            }
            None
        }
        ExtentTree::Index(_) => None,
    }
}

fn child_for(lb: u32) -> usize {
    usize::from(lb >= SPLIT)
}

/// OLD: re-parse the chosen child block on every logical block.
fn resolve_reparse_child(children: &[Vec<u8>; 2]) -> u64 {
    let mut acc = 0u64;
    for lb in 0..N {
        let (_h, tree) = parse_extent_tree(&children[child_for(lb)]).expect("child");
        if let Some(p) = walk_leaf(&tree, lb) {
            acc = acc.wrapping_add(p);
        }
    }
    acc
}

/// NEW: cache the parsed child; re-parse only when the child changes (2× total
/// for a boundary-crossing sequential read instead of 32×).
fn resolve_cached_child(children: &[Vec<u8>; 2]) -> u64 {
    let mut acc = 0u64;
    let mut cached: Option<(usize, ExtentTree)> = None;
    for lb in 0..N {
        let want = child_for(lb);
        let reuse = matches!(&cached, Some((c, _)) if *c == want);
        if !reuse {
            let (_h, tree) = parse_extent_tree(&children[want]).expect("child");
            cached = Some((want, tree));
        }
        let (_c, tree) = cached.as_ref().unwrap();
        if let Some(p) = walk_leaf(tree, lb) {
            acc = acc.wrapping_add(p);
        }
    }
    acc
}

fn bench(c: &mut Criterion) {
    let children = [child_leaf_bytes(0), child_leaf_bytes(SPLIT)];

    let old = resolve_reparse_child(&children);
    let new = resolve_cached_child(&children);
    assert_eq!(old, new, "cache must be behaviour-identical");

    let mut g = c.benchmark_group("ext4_extent_child_resolve_32blocks_depth1");
    g.bench_function("reparse_child_per_block", |b| {
        b.iter(|| black_box(resolve_reparse_child(black_box(&children))));
    });
    g.bench_function("cache_child", |b| {
        b.iter(|| black_box(resolve_cached_child(black_box(&children))));
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
