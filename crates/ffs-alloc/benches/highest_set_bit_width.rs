#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Throwaway A/B for `highest_set_bit_index` (the `itable_unused` computation on
//! every inode alloc). It reverse-scans the group's inode bitmap for the top used
//! inode. On a SPARSE group (few low inodes used — the common early-fill state)
//! the scan walks all the high zero bytes to reach the top set bit. Old: byte-by-
//! byte. New: skip a u64 (8 bytes) per step. Runs under `alloc_mutex` on the
//! create serial floor.
//!
//!   rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench highest_set_bit_width

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

/// OLD: byte-by-byte reverse scan.
fn scalar(bitmap: &[u8], count: u32) -> Option<u32> {
    let count = count as usize;
    let nbytes = count.div_ceil(8).min(bitmap.len());
    for byte_idx in (0..nbytes).rev() {
        let byte = bitmap[byte_idx];
        if byte == 0 {
            continue;
        }
        for bit in (0..8u32).rev() {
            if byte & (1 << bit) != 0 {
                let idx = byte_idx * 8 + bit as usize;
                if idx < count {
                    return Some(idx as u32);
                }
            }
        }
    }
    None
}

/// NEW: word-at-a-time zero-skip (last byte scalar for the padding boundary,
/// lower fully-real bytes skipped a u64 at a time).
fn word(bitmap: &[u8], count: u32) -> Option<u32> {
    let count = count as usize;
    let nbytes = count.div_ceil(8).min(bitmap.len());
    if nbytes == 0 {
        return None;
    }
    let last = nbytes - 1;
    let byte = bitmap[last];
    if byte != 0 {
        for bit in (0..8u32).rev() {
            if byte & (1 << bit) != 0 {
                let idx = last * 8 + bit as usize;
                if idx < count {
                    return Some(idx as u32);
                }
            }
        }
    }
    let mut end = last;
    while end >= 8 {
        let w = u64::from_le_bytes(bitmap[end - 8..end].try_into().unwrap());
        if w != 0 {
            return Some(((end - 8) * 8) as u32 + w.ilog2());
        }
        end -= 8;
    }
    for byte_idx in (0..end).rev() {
        let byte = bitmap[byte_idx];
        if byte != 0 {
            return Some((byte_idx * 8) as u32 + byte.ilog2());
        }
    }
    None
}

fn bench(c: &mut Criterion) {
    for inodes_per_group in [2048u32, 8192, 65536] {
        let nbytes = (inodes_per_group / 8) as usize;
        // Sparse group: only the lowest inode (bit 0) used — worst case for the
        // reverse scan (walk every high zero byte to reach it).
        let mut bitmap = vec![0u8; nbytes];
        bitmap[0] = 0b0000_0001;
        assert_eq!(
            scalar(&bitmap, inodes_per_group),
            word(&bitmap, inodes_per_group),
            "isomorphism"
        );
        let mut g = c.benchmark_group(format!("highest_set_bit_{inodes_per_group}"));
        g.bench_function("scalar_byte", |b| {
            b.iter(|| black_box(scalar(black_box(&bitmap), black_box(inodes_per_group))));
        });
        g.bench_function("word_skip", |b| {
            b.iter(|| black_box(word(black_box(&bitmap), black_box(inodes_per_group))));
        });
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
