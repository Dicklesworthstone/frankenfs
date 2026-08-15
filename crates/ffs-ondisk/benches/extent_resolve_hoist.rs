#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! A/B for hoisting the ext4 inode extent-tree parse out of the per-block read
//! loop.
//!
//! `Ext4ImageReader::resolve_extent` calls `parse_inode_extent_tree` (a header
//! decode + a heap-allocating `Vec<Ext4Extent>` build with per-extent
//! `from_le_bytes` + sort/overlap validation) on EVERY call, and the three
//! hottest read paths (`read_inode_data`, `read_dir`, `lookup`) call it once
//! per logical block in a loop. The parsed tree is invariant across all blocks
//! of one inode, so a 128 KiB read (32 × 4 KiB blocks) re-parses and re-allocates
//! the identical tree 32 times. This benches the per-block re-parse (old) against
//! parsing once and reusing the tree (new = `resolve_extent_with_tree`), with the
//! identical leaf scan in both arms so the ratio isolates the hoisted parse+alloc.
//!
//! Run per-crate:
//!   CARGO_TARGET_DIR=/data/projects/frankenfs/.rch-targets/blackthrush-dig \
//!   rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench extent_resolve_hoist

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::ext4::{ExtentTree, parse_extent_tree};
use std::hint::black_box;

const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
const K: usize = 4; // extents that fit inline in the 60-byte i_block (12 + 4*12)
const LEN_PER: u32 = 8; // logical blocks per extent
const N: u32 = K as u32 * LEN_PER; // 32 logical blocks = one 128 KiB read at 4 KiB

/// Build a valid depth-0 (leaf) inode extent tree: `K` non-overlapping extents
/// of `LEN_PER` blocks each, covering logical blocks `0..N`.
fn make_extent_bytes() -> [u8; 60] {
    let mut b = [0u8; 60];
    b[0x00..0x02].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
    b[0x02..0x04].copy_from_slice(&(K as u16).to_le_bytes()); // eh_entries
    b[0x04..0x06].copy_from_slice(&(K as u16).to_le_bytes()); // eh_max
    b[0x06..0x08].copy_from_slice(&0u16.to_le_bytes()); // eh_depth = 0 (leaf)
    // eh_generation @ 0x08 left zero
    for i in 0..K {
        let base = 12 + i * 12;
        let ee_block = (i as u32) * LEN_PER;
        let phys_lo = ee_block + 1000; // arbitrary, non-overlapping physical start
        b[base..base + 4].copy_from_slice(&ee_block.to_le_bytes()); // ee_block
        b[base + 4..base + 6].copy_from_slice(&(LEN_PER as u16).to_le_bytes()); // ee_len
        b[base + 6..base + 8].copy_from_slice(&0u16.to_le_bytes()); // ee_start_hi
        b[base + 8..base + 12].copy_from_slice(&phys_lo.to_le_bytes()); // ee_start_lo
    }
    b
}

/// Mirror of the production `walk_extent_tree` leaf branch (linear scan). This
/// is identical work in both benchmark arms, so it does not bias the ratio; it
/// stands in for the walk that both the old and new resolve paths perform.
fn walk_leaf(tree: &ExtentTree, logical_block: u32) -> Option<u64> {
    match tree {
        ExtentTree::Leaf(extents) => {
            for ext in extents {
                let start = ext.logical_block;
                let len = u32::from(ext.actual_len());
                if logical_block >= start && logical_block < start.saturating_add(len) {
                    let offset_within = u64::from(logical_block - start);
                    return Some(ext.physical_start + offset_within);
                }
            }
            None
        }
        ExtentTree::Index(_) => None,
    }
}

/// OLD: re-parse the extent tree on every block (what `resolve_extent` did per
/// iteration).
fn resolve_all_parse_per_block(bytes: &[u8]) -> u64 {
    let mut acc = 0u64;
    for lb in 0..N {
        let (_h, tree) = parse_extent_tree(bytes).expect("valid tree");
        if let Some(phys) = walk_leaf(&tree, lb) {
            acc = acc.wrapping_add(phys);
        }
    }
    acc
}

/// NEW: parse once, reuse across all blocks (what the hoisted loop +
/// `resolve_extent_with_tree` now does).
fn resolve_all_parse_once(bytes: &[u8]) -> u64 {
    let (_h, tree) = parse_extent_tree(bytes).expect("valid tree");
    let mut acc = 0u64;
    for lb in 0..N {
        if let Some(phys) = walk_leaf(&tree, lb) {
            acc = acc.wrapping_add(phys);
        }
    }
    acc
}

fn bench(c: &mut Criterion) {
    let bytes = make_extent_bytes();

    // Equivalence: both arms resolve every logical block identically.
    let old = resolve_all_parse_per_block(&bytes);
    let new = resolve_all_parse_once(&bytes);
    assert_eq!(old, new, "hoist must be behaviour-identical");
    // And every block is mapped (sanity: sum of phys 1000..1032).
    let expect: u64 = (0..N).map(|lb| u64::from(lb + 1000)).sum();
    assert_eq!(new, expect, "all {N} blocks must map to phys lb+1000");

    let mut g = c.benchmark_group("ext4_extent_resolve_32blocks");
    g.bench_function("parse_per_block", |b| {
        b.iter(|| black_box(resolve_all_parse_per_block(black_box(&bytes))));
    });
    g.bench_function("parse_once_hoisted", |b| {
        b.iter(|| black_box(resolve_all_parse_once(black_box(&bytes))));
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
