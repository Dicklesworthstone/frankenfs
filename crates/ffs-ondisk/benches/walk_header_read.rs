#![forbid(unsafe_code)]
//! `walk_dir_block_entries` (ffs-ondisk, readdir+lookup hot path) reads 4 header
//! fields per entry — inode (u32 @off), rec_len (u16 @off+4), name_len (u8
//! @off+6), file_type (u8 @off+7). CRUCIAL difference from the ffs-dir walks
//! (which won 1.56x with an array-ref reslice): here the loop guard is
//! `offset + 8 <= block.len()` DIRECTLY (not `off+8 <= limit` through a separate
//! `limit` variable). So `offset+k <= block.len()` (k<=8) follows by simple
//! monotonicity — the compiler CAN elide the per-field checks, making the
//! array-ref reslice neutral (and read_fixed's COPY a net loss, as measured
//! before). This A/B confirms whether the direct guard already elides.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench walk_header_read
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_types::{ensure_slice, read_le_u16, read_le_u32};
use std::hint::black_box;

fn make_block() -> Vec<u8> {
    let mut block = vec![0u8; 4096];
    let rec_len: u16 = 24;
    let mut off = 0usize;
    let mut ino: u32 = 12;
    while off + rec_len as usize <= 4096 {
        block[off..off + 4].copy_from_slice(&ino.to_le_bytes());
        block[off + 4..off + 6].copy_from_slice(&rec_len.to_le_bytes());
        block[off + 6] = 11;
        block[off + 7] = 1;
        off += rec_len as usize;
        ino += 1;
    }
    block
}

/// Production shape: the EXACT `walk_dir_block_entries` reads —
/// `read_le_u32`/`read_le_u16`/`ensure_slice` (each an `ensure_slice` bounds
/// check), guard directly on block.len().
#[inline]
fn walk_checked(block: &[u8]) -> u64 {
    let mut off = 0usize;
    let mut acc: u64 = 0;
    while off + 8 <= block.len() {
        let inode = read_le_u32(block, off).unwrap();
        let rec_len = read_le_u16(block, off + 4).unwrap() as usize;
        let name_len = ensure_slice(block, off + 6, 1).unwrap()[0] as u64;
        let file_type = ensure_slice(block, off + 7, 1).unwrap()[0] as u64;
        if rec_len < 12 {
            break;
        }
        acc = acc
            .wrapping_add(inode as u64)
            .wrapping_add(name_len)
            .wrapping_add(file_type);
        off += rec_len;
    }
    acc
}

/// Array-ref reslice: one check per entry, then const-offset reads.
#[inline]
fn walk_arrayref(block: &[u8]) -> u64 {
    let mut off = 0usize;
    let mut acc: u64 = 0;
    while off + 8 <= block.len() {
        let h: &[u8; 8] = match block[off..off + 8].try_into() {
            Ok(h) => h,
            Err(_) => break,
        };
        let inode = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        let rec_len = u16::from_le_bytes([h[4], h[5]]) as usize;
        let name_len = h[6] as u64;
        let file_type = h[7] as u64;
        if rec_len < 12 {
            break;
        }
        acc = acc
            .wrapping_add(inode as u64)
            .wrapping_add(name_len)
            .wrapping_add(file_type);
        off += rec_len;
    }
    acc
}

// Models `parse_dir_block`'s collect (ffs-ondisk:3859), which builds a
// `Vec<Ext4DirEntry>` from a dir block on EVERY readdir block. It starts from
// `Vec::new()` and pushes per entry, so a full block (~170-340 entries)
// reallocates the Vec ~7-9 times. `with_cap` pre-sizes to `block.len()/12` (the
// max entry count, a 12-byte minimum record), eliminating the reallocations. The
// walk and per-entry `name.to_vec()` are common to both arms, so this isolates
// the reallocation delta. Byte-identical output (same entries).
#[derive(PartialEq)]
struct BenchEntry {
    inode: u32,
    rec_len: u32,
    name_len: u8,
    name: Vec<u8>,
}
#[inline]
fn collect(block: &[u8], with_cap: bool) -> Vec<BenchEntry> {
    let mut v: Vec<BenchEntry> = if with_cap {
        Vec::with_capacity(block.len() / 12)
    } else {
        Vec::new()
    };
    let mut off = 0usize;
    while off + 8 <= block.len() {
        let inode = read_le_u32(block, off).unwrap();
        let rec_len = read_le_u16(block, off + 4).unwrap() as usize;
        let name_len = ensure_slice(block, off + 6, 1).unwrap()[0];
        if rec_len < 12 {
            break;
        }
        let nl = name_len as usize;
        let name = if off + 8 + nl <= block.len() {
            block[off + 8..off + 8 + nl].to_vec()
        } else {
            Vec::new()
        };
        v.push(BenchEntry {
            inode,
            rec_len: rec_len as u32,
            name_len,
            name,
        });
        off += rec_len;
    }
    v
}

fn bench(c: &mut Criterion) {
    let block = make_block();
    assert_eq!(walk_checked(&block), walk_arrayref(&block));
    let mut g = c.benchmark_group("walk_header_read");
    g.bench_function("checked", |b| {
        b.iter(|| black_box(walk_checked(black_box(&block))))
    });
    g.bench_function("arrayref", |b| {
        b.iter(|| black_box(walk_arrayref(black_box(&block))))
    });
    g.finish();

    // parse_dir_block collect: Vec::new vs with_capacity (isolated realloc delta).
    assert!(
        collect(&block, false) == collect(&block, true),
        "collect arms must agree"
    );
    let mut g = c.benchmark_group("dir_collect");
    g.bench_function("vecnew_a", |b| {
        b.iter(|| black_box(collect(black_box(&block), false)))
    });
    g.bench_function("vecnew_b", |b| {
        b.iter(|| black_box(collect(black_box(&block), false)))
    });
    g.bench_function("withcap", |b| {
        b.iter(|| black_box(collect(black_box(&block), true)))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
