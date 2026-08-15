#![forbid(unsafe_code)]
//! `lookup_in_dir_block` scanning a full htree leaf of SAME-LENGTH names for a
//! MISSING name (worst case: every entry compared). This is the path-resolution
//! / open / stat / linear-create-rename lookup. Its per-entry name compare
//! `name == target` (byte-slice `==`) does not word-wise-lower; a SWAR compare
//! (`names_eq`) wins for same-length names (numbered / log / hash / maildir).
//! A/B is production (`names_eq`) vs the reverted byte-slice `==` (rebuild).
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench lookup_leaf_scan
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::ext4::lookup_in_dir_block;
use std::hint::black_box;

/// Build a 4 KiB linear dir block packed with same-length names, filling the
/// whole block (last entry's rec_len spans to the end) so the walker validates.
fn build_leaf(bs: usize, name_len: usize) -> (Vec<u8>, usize) {
    // Checked once here rather than at each field write: the fixture shape is
    // fixed by the caller, so a bad one should fail loudly at construction.
    let rec_len_fits = |v: usize| u16::try_from(v).expect("dir entry rec_len fits u16");
    let name_len_u8 = u8::try_from(name_len).expect("fixture name_len fits u8");
    let mut block = vec![0u8; bs];
    let ent = 8 + name_len;
    let rec = (ent + 3) & !3; // 4-byte aligned
    let mut off = 0usize;
    let mut count = 0u32;
    // Leave room so the final entry can span to the end (>= one rec).
    while off + rec * 2 <= bs {
        let ino = count + 3;
        block[off..off + 4].copy_from_slice(&ino.to_le_bytes());
        block[off + 4..off + 6].copy_from_slice(&rec_len_fits(rec).to_le_bytes());
        block[off + 6] = name_len_u8;
        block[off + 7] = 1; // reg file
        let name = format!("cb_{:0width$}", count, width = name_len - 3);
        block[off + 8..off + 8 + name_len].copy_from_slice(&name.as_bytes()[..name_len]);
        off += rec;
        count += 1;
    }
    // Final entry fills the rest of the block.
    let ino = count + 3;
    let last_rec = bs - off;
    block[off..off + 4].copy_from_slice(&ino.to_le_bytes());
    block[off + 4..off + 6].copy_from_slice(&rec_len_fits(last_rec).to_le_bytes());
    block[off + 6] = name_len_u8;
    block[off + 7] = 1;
    let name = format!("cb_{:0width$}", count, width = name_len - 3);
    block[off + 8..off + 8 + name_len].copy_from_slice(&name.as_bytes()[..name_len]);
    (block, (count + 1) as usize)
}

fn bench(c: &mut Criterion) {
    let bs = 4096usize;
    let bs_u32 = u32::try_from(bs).expect("block size fits u32");
    let name_len = 11usize; // "cb_00000000"
    let (block, entries) = build_leaf(bs, name_len);
    // A missing same-length name → scans every entry.
    let miss = b"cb_zzzzzzzz";
    assert_eq!(miss.len(), name_len);
    assert!(lookup_in_dir_block(&block, bs_u32, miss).unwrap().is_none());
    // A present name (mid-block) still resolves.
    let hit = format!("cb_{:08}", entries / 2);
    assert!(
        lookup_in_dir_block(&block, bs_u32, hit.as_bytes())
            .unwrap()
            .is_some()
    );

    // Scoped so the `BenchmarkGroup`'s significant `Drop` runs at `finish()`
    // rather than at the end of the function (bd-3ao0l).
    {
        let mut g = c.benchmark_group("lookup_leaf_scan");
        g.bench_function("miss_full_leaf", |b| {
            b.iter(|| {
                black_box(lookup_in_dir_block(
                    black_box(&block),
                    bs_u32,
                    black_box(miss),
                ))
            });
        });
        g.finish();
    }
    eprintln!("leaf entries scanned per miss: {entries}");
}

criterion_group!(benches, bench);
criterion_main!(benches);
