#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for bounded ext4 extent collection (bd-yd3a0).
//!
//! `ext4_lseek_data` (SEEK_DATA) and `ext4_fiemap` used to flatten the WHOLE
//! extent tree per call (`collect_extents_with_scope`), reading and parsing every
//! leaf block. The new `collect_extents_from_with_scope` prunes index children
//! whose subtree ends at or before the query block, so a query into a large
//! fragmented file reads only the leaves from the covering one onward — the ext4
//! dual of the btrfs floor-seek. `cp --sparse` walking a big file with repeated
//! SEEK_DATA otherwise pays O(extents) per call (O(extents^2) for the copy).
//!
//! This models a depth-1 tree of `L` leaves × `M` extents over an in-memory
//! "device" (a block map) and benches one SEEK_DATA-style query at 75% of the
//! file: the old path parses all `L` leaves, the new path only the last quarter.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::{ExtentTree, parse_extent_tree};
use std::collections::HashMap;
use std::hint::black_box;

const L: u32 = 64; // leaf blocks (depth-1 tree)
const M: u32 = 340; // extents per 4 KiB leaf
const EXT4_EXTENT_MAGIC: u16 = 0xF30A;

type LeafIndex = Vec<(u32, u32)>;
type LeafBlocks = HashMap<u32, Vec<u8>>;

/// Build one depth-0 leaf block: `M` length-1 extents at logical `start..start+M`.
fn build_leaf(start: u32) -> Vec<u8> {
    let mut block = vec![0_u8; 12 + M as usize * 12];
    block[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
    block[2..4].copy_from_slice(&(M as u16).to_le_bytes());
    block[4..6].copy_from_slice(&(M as u16).to_le_bytes());
    block[6..8].copy_from_slice(&0_u16.to_le_bytes()); // depth 0
    for k in 0..M {
        let base = 12 + k as usize * 12;
        let logical = start + k;
        let phys = 100_000_u64 + u64::from(logical);
        block[base..base + 4].copy_from_slice(&logical.to_le_bytes());
        block[base + 4..base + 6].copy_from_slice(&1_u16.to_le_bytes());
        block[base + 6..base + 8].copy_from_slice(&((phys >> 32) as u16).to_le_bytes());
        block[base + 8..base + 12].copy_from_slice(&((phys & 0xFFFF_FFFF) as u32).to_le_bytes());
    }
    block
}

/// Index entries (first_logical, leaf_block_num) + the leaf block bytes.
fn build_tree() -> (LeafIndex, LeafBlocks) {
    let mut index = Vec::new();
    let mut dev = HashMap::new();
    for j in 0..L {
        let start = j * M;
        index.push((start, j));
        dev.insert(j, build_leaf(start));
    }
    (index, dev)
}

/// Old: flatten every leaf (collect_extents_with_scope, from_block 0).
fn collect_all(index: &[(u32, u32)], dev: &HashMap<u32, Vec<u8>>) -> Vec<u32> {
    let mut out = Vec::new();
    for &(_first, leaf) in index {
        let (_h, tree) = parse_extent_tree(&dev[&leaf]).unwrap();
        if let ExtentTree::Leaf(exts) = tree {
            out.extend(exts.iter().map(|e| e.logical_block));
        }
    }
    out
}

/// New: prune index children whose subtree ends at/before `from_block`
/// (next sibling starts at/below it), then flatten the kept leaves.
fn collect_from(index: &[(u32, u32)], dev: &HashMap<u32, Vec<u8>>, from_block: u32) -> Vec<u32> {
    let mut out = Vec::new();
    for (i, &(_first, leaf)) in index.iter().enumerate() {
        if let Some(&(next_first, _)) = index.get(i + 1)
            && next_first <= from_block
        {
            continue;
        }
        let (_h, tree) = parse_extent_tree(&dev[&leaf]).unwrap();
        if let ExtentTree::Leaf(exts) = tree {
            out.extend(exts.iter().map(|e| e.logical_block));
        }
    }
    out
}

fn bench_extent_collect_window(c: &mut Criterion) {
    let (index, dev) = build_tree();
    let from_block = (L * 3 / 4) * M; // query 75% into the file

    // Isomorphism: the bounded collection is exactly the suffix of the full
    // collection from the first kept leaf (pruned leaves all end <= from_block).
    let all = collect_all(&index, &dev);
    let from = collect_from(&index, &dev, from_block);
    let skip = all.len() - from.len();
    assert_eq!(from, all[skip..], "bounded collection diverged from suffix");
    assert!(
        from.iter().all(|&b| b + 1 > from_block - M),
        "kept window sane"
    );

    let mut group = c.benchmark_group("ext4_extent_collect_window_64x340");
    group.bench_function("collect_all", |b| {
        b.iter(|| black_box(collect_all(black_box(&index), black_box(&dev)).len()));
    });
    group.bench_function("collect_from_75pct", |b| {
        b.iter(|| {
            black_box(collect_from(black_box(&index), black_box(&dev), black_box(from_block)).len())
        });
    });
    group.finish();
}

criterion_group!(extent_collect_window, bench_extent_collect_window);
criterion_main!(extent_collect_window);
