#![forbid(unsafe_code)]
//! `ext4_count_extent_tree_meta_blocks` (ffs-core) runs PER WRITE to charge
//! extent-tree metadata blocks to i_blocks. A depth-0 (inline) extent tree — the
//! common case, extents fit in the inode — has ZERO external meta blocks, but the
//! old code called `parse_extent_tree` (parsing every leaf extent) just to then
//! see depth==0 and return 0. Reading `eh_depth` (root[6..8]) first skips that
//! parse entirely. A/B the parse vs the direct depth read on a depth-0 inline root.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench extent_meta_count
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::ext4::parse_extent_tree;
use std::hint::black_box;

/// A 60-byte inline (depth-0) extent root: 12-byte header + 4 populated extents.
fn depth0_root() -> [u8; 60] {
    let mut r = [0u8; 60];
    r[0..2].copy_from_slice(&0xF30Au16.to_le_bytes()); // eh_magic
    r[2..4].copy_from_slice(&4u16.to_le_bytes()); // eh_entries
    r[4..6].copy_from_slice(&4u16.to_le_bytes()); // eh_max
    r[6..8].copy_from_slice(&0u16.to_le_bytes()); // eh_depth = 0 (inline leaf)
    for i in 0..4 {
        let base = 12 + i * 12;
        r[base..base + 4].copy_from_slice(&((i as u32) * 100).to_le_bytes()); // logical
        r[base + 4..base + 6].copy_from_slice(&50u16.to_le_bytes()); // len
        r[base + 8..base + 12].copy_from_slice(&((i as u32) + 1000).to_le_bytes()); // start_lo
    }
    r
}

fn bench(c: &mut Criterion) {
    let root = depth0_root();
    // sanity: it parses as depth 0
    let (h, _t) = parse_extent_tree(&root).expect("valid depth-0 root");
    assert_eq!(h.depth, 0);

    let mut g = c.benchmark_group("extent_meta_count_depth0");
    g.bench_function("parse_full", |b| {
        // ORIG: parse the whole tree (leaf extents) then discover depth==0.
        b.iter(|| black_box(parse_extent_tree(black_box(&root)).unwrap().0.depth))
    });
    g.bench_function("read_depth", |b| {
        // NEW: read eh_depth directly.
        b.iter(|| {
            let r = black_box(&root);
            black_box(u16::from_le_bytes([r[6], r[7]]))
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
