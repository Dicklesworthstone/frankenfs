#![forbid(unsafe_code)]
//! Parsing a FULL extent-tree leaf (340 entries, the 4 KiB-block max) — the
//! per-block-resolve cost on a large / fragmented file's EXTERNAL extent tree
//! (cold reads/writes, before the extent snapshot / hot-extents cache warms).
//! `parse_extent_leaf` reads 4 bounds-checked LE fields per 12-byte entry in a
//! loop the compiler can't prove in-bounds → 4 checks/entry; a single
//! `read_fixed::<12>` is one check + const-offset array reads.
//! A/B is production vs the reverted 4-read form (rebuild).
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench extent_leaf_parse
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::ext4::parse_extent_tree;
use std::hint::black_box;

/// Build a leaf extent node: 12-byte header (depth 0) + `n` sorted,
/// non-overlapping, non-zero-length 12-byte extent entries.
fn build_leaf(n: u16) -> Vec<u8> {
    let mut b = vec![0u8; 12 + usize::from(n) * 12];
    b[0..2].copy_from_slice(&0xF30Au16.to_le_bytes()); // eh_magic
    b[2..4].copy_from_slice(&n.to_le_bytes()); // eh_entries
    b[4..6].copy_from_slice(&n.to_le_bytes()); // eh_max
    b[6..8].copy_from_slice(&0u16.to_le_bytes()); // eh_depth = 0 (leaf)
    for i in 0..usize::from(n) {
        let base = 12 + i * 12;
        let idx = u32::try_from(i).expect("fixture extent index fits u32");
        let logical = idx * 2; // sorted, gap so non-overlapping
        b[base..base + 4].copy_from_slice(&logical.to_le_bytes());
        b[base + 4..base + 6].copy_from_slice(&1u16.to_le_bytes()); // ee_len = 1
        b[base + 6..base + 8].copy_from_slice(&0u16.to_le_bytes()); // start_hi
        b[base + 8..base + 12].copy_from_slice(&(idx + 1000).to_le_bytes()); // start_lo
    }
    b
}

fn bench(c: &mut Criterion) {
    let n = 340u16; // (4096 - 12) / 12
    let block = build_leaf(n);
    // sanity: parses cleanly to a full leaf
    let (_h, _t) = parse_extent_tree(&block).expect("valid leaf");

    let mut g = c.benchmark_group("extent_leaf_parse");
    g.bench_function("full_leaf_340", |b| {
        b.iter(|| black_box(parse_extent_tree(black_box(&block)).unwrap()));
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
