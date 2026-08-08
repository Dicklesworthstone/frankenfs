#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Throwaway A/B: does a 4-independent-popcount unroll beat the current one-u64
//! `bitmap_count_free` popcount-sum, or does the compiler already extract the
//! ILP (~0-gain)? `bitmap_count_free` recomputes a group's free count at
//! group-load/mount (per group), so it is on the per-invocation open cost.
//!
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cc \
//!   rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench bitmap_count_width

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

/// One-u64-per-iteration popcount sum (mirrors production).
fn count_word(bitmap: &[u8]) -> u32 {
    let mut free = 0u32;
    for chunk in bitmap.chunks_exact(8) {
        let word = u64::from_le_bytes(chunk.try_into().unwrap());
        free += (!word).count_ones();
    }
    free
}

/// Four independent popcounts per iteration (better ILP), summed.
fn count_unrolled4(bitmap: &[u8]) -> u32 {
    let mut free = 0u32;
    let mut chunks = bitmap.chunks_exact(32);
    for block in &mut chunks {
        let w0 = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let w1 = u64::from_le_bytes(block[8..16].try_into().unwrap());
        let w2 = u64::from_le_bytes(block[16..24].try_into().unwrap());
        let w3 = u64::from_le_bytes(block[24..32].try_into().unwrap());
        free += (!w0).count_ones() + (!w1).count_ones() + (!w2).count_ones() + (!w3).count_ones();
    }
    for chunk in chunks.remainder().chunks_exact(8) {
        let word = u64::from_le_bytes(chunk.try_into().unwrap());
        free += (!word).count_ones();
    }
    free
}

fn bench(c: &mut Criterion) {
    // Realistic group bitmaps: inodes_per_group (1 KiB) and blocks_per_group (4 KiB).
    for bytes in [1024usize, 4096] {
        // Half-allocated pattern (non-trivial popcount).
        let bitmap: Vec<u8> = (0..bytes).map(|i| (i as u8).wrapping_mul(37)).collect();
        assert_eq!(count_word(&bitmap), count_unrolled4(&bitmap));
        let mut g = c.benchmark_group(format!("bitmap_count_{bytes}bytes"));
        g.bench_function("word", |b| {
            b.iter(|| black_box(count_word(black_box(&bitmap))))
        });
        g.bench_function("unrolled4", |b| {
            b.iter(|| black_box(count_unrolled4(black_box(&bitmap))));
        });
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
