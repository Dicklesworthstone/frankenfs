#![forbid(unsafe_code)]
//! Per-entry duplicate-name scan of a full htree leaf — the hot inner loop of
//! `add_entry_reject_existing` / `block_contains_live_name` (profiled as the #1
//! FS self-time function on create-bench, 3.75%). The create-bench / numbered /
//! log / hash / maildir workloads use SAME-LENGTH names, so the length gate in
//! the byte-slice `==` never filters and every live entry pays a full compare.
//! A/B: the byte-slice `==` (which the annotation showed lowering to a byte-wise
//! loop) vs a SWAR word-at-a-time compare (SIMD-within-register).
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-dir --bench dirent_dup_scan
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_dir::{add_entry, init_dir_block};
use ffs_ondisk::Ext4FileType;
use std::hint::black_box;

const HDR: usize = 8;

/// Word-at-a-time byte-slice equality (SWAR).
#[inline]
fn names_eq_swar(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i + 8 <= a.len() {
        let wa = u64::from_ne_bytes(a[i..i + 8].try_into().unwrap());
        let wb = u64::from_ne_bytes(b[i..i + 8].try_into().unwrap());
        if wa != wb {
            return false;
        }
        i += 8;
    }
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Scan a leaf for a live `name`, using the supplied compare. Mirrors
/// `block_contains_live_name`'s loop (rec_len chase + per-entry name compare).
#[inline]
fn scan<F: Fn(&[u8], &[u8]) -> bool>(
    block: &[u8],
    name: &[u8],
    reserved_tail: usize,
    eq: F,
) -> bool {
    let limit = block.len() - reserved_tail;
    let mut off = 0usize;
    while off + HDR <= limit {
        let rec_len = usize::from(u16::from_le_bytes([block[off + 4], block[off + 5]]));
        if rec_len < HDR || rec_len % 4 != 0 {
            break;
        }
        let end = off + rec_len;
        if end > limit {
            break;
        }
        let cur_ino =
            u32::from_le_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
        let cur_name_len = usize::from(block[off + 6]);
        let name_end = off + HDR + cur_name_len;
        if name_end <= end && cur_ino != 0 && eq(&block[off + HDR..name_end], name) {
            return true;
        }
        off = end;
    }
    false
}

/// Same scan but reading rec_len/ino/name_len via `Option`-returning bounds-
/// checked accessors (mirrors production `read_u16_le`/`read_u32_le`), vs `scan`
/// which indexes directly (the loop invariant proves in-bounds → the compiler
/// elides the checks). Isolates the per-entry read overhead.
#[inline]
fn scan_checked<F: Fn(&[u8], &[u8]) -> bool>(
    block: &[u8],
    name: &[u8],
    reserved_tail: usize,
    eq: F,
) -> bool {
    let rd16 = |b: &[u8], i: usize| -> Option<u16> {
        b.get(i..i + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
    };
    let rd32 = |b: &[u8], i: usize| -> Option<u32> {
        b.get(i..i + 4)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    };
    let limit = block.len() - reserved_tail;
    let mut off = 0usize;
    while off + HDR <= limit {
        let Some(rec_len) = rd16(block, off + 4).map(usize::from) else {
            break;
        };
        if rec_len < HDR || rec_len % 4 != 0 {
            break;
        }
        let end = off + rec_len;
        if end > limit {
            break;
        }
        let Some(cur_ino) = rd32(block, off) else {
            break;
        };
        let cur_name_len = usize::from(block[off + 6]);
        let name_end = off + HDR + cur_name_len;
        if name_end <= end && cur_ino != 0 && eq(&block[off + HDR..name_end], name) {
            return true;
        }
        off = end;
    }
    false
}

/// One fixed-size header reslice per entry, matching the candidate production
/// read while retaining the same rec_len/name bounds checks and scan order.
#[inline]
fn scan_arrayref<F: Fn(&[u8], &[u8]) -> bool>(
    block: &[u8],
    name: &[u8],
    reserved_tail: usize,
    eq: F,
) -> bool {
    let limit = block.len() - reserved_tail;
    let mut off = 0usize;
    while off + HDR <= limit {
        let Ok(header) = <&[u8; HDR]>::try_from(&block[off..off + HDR]) else {
            break;
        };
        let rec_len = usize::from(u16::from_le_bytes([header[4], header[5]]));
        if rec_len < HDR || rec_len % 4 != 0 {
            break;
        }
        let end = off + rec_len;
        if end > limit {
            break;
        }
        let cur_ino = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let cur_name_len = usize::from(header[6]);
        let name_end = off + HDR + cur_name_len;
        if name_end <= end && cur_ino != 0 && eq(&block[off + HDR..name_end], name) {
            return true;
        }
        off = end;
    }
    false
}

fn bench(c: &mut Criterion) {
    let bs = 4096usize;
    let reserved_tail = 12usize;
    let mut block = vec![0u8; bs];
    init_dir_block(&mut block, 2, 2, reserved_tail).unwrap();
    // Fill with same-length names "cb_00000001".. (11 bytes each).
    let mut n = 3u32;
    loop {
        let name = format!("cb_{n:08}");
        if add_entry(
            &mut block,
            n,
            name.as_bytes(),
            Ext4FileType::RegFile,
            reserved_tail,
        )
        .is_err()
        {
            break;
        }
        n += 1;
    }
    let entries = n - 3;
    // A missing same-length name → worst case: scan every entry, full compare.
    let miss = b"cb_99999999";
    assert_eq!(miss.len(), 11);
    // sanity: both agree, and it's a miss
    assert!(!scan(&block, miss, reserved_tail, |a, b| a == b));
    assert!(!scan(&block, miss, reserved_tail, names_eq_swar));
    assert_eq!(
        scan_checked(&block, miss, reserved_tail, names_eq_swar),
        scan_arrayref(&block, miss, reserved_tail, names_eq_swar),
        "header-read variants diverged",
    );

    // Scoped so each group's significant `Drop` runs at `finish()` (bd-3ao0l).
    {
        let mut g = c.benchmark_group("dirent_dup_scan");
        g.bench_function("slice_eq", |b| {
            b.iter(|| {
                black_box(scan(
                    black_box(&block),
                    black_box(miss),
                    reserved_tail,
                    |x, y| x == y,
                ))
            });
        });
        g.bench_function("swar", |b| {
            b.iter(|| {
                black_box(scan(
                    black_box(&block),
                    black_box(miss),
                    reserved_tail,
                    names_eq_swar,
                ))
            });
        });
        // Checked-read (production read_u16_le style) + SWAR vs direct-index + SWAR:
        // isolates whether the Option-returning bounds-checked reads cost anything.
        g.bench_function("swar_checked_read", |b| {
            b.iter(|| {
                black_box(scan_checked(
                    black_box(&block),
                    black_box(miss),
                    reserved_tail,
                    names_eq_swar,
                ))
            });
        });
        g.finish();
    }

    {
        let mut header_group = c.benchmark_group("block_contains_header_arrayref_203");
        header_group.sample_size(10);
        header_group.bench_function("checked_control_a", |b| {
            b.iter(|| {
                black_box(scan_checked(
                    black_box(&block),
                    black_box(miss),
                    reserved_tail,
                    names_eq_swar,
                ))
            });
        });
        header_group.bench_function("arrayref_candidate", |b| {
            b.iter(|| {
                black_box(scan_arrayref(
                    black_box(&block),
                    black_box(miss),
                    reserved_tail,
                    names_eq_swar,
                ))
            });
        });
        header_group.bench_function("checked_control_b", |b| {
            b.iter(|| {
                black_box(scan_checked(
                    black_box(&block),
                    black_box(miss),
                    reserved_tail,
                    names_eq_swar,
                ))
            });
        });
        header_group.finish();
    }
    eprintln!("leaf entries scanned per call: {entries}");
}

criterion_group!(benches, bench);
criterion_main!(benches);
