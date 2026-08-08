#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Throwaway A/B: `bitmap_largest_free_run` scans word-at-a-time via a branchy
//! per-word zero-run step (word==0 / word==MAX / mixed) — the same
//! vectorization-blocking shape that made `find_free` winnable. It is recomputed
//! per block-alloc (lazy-invalidated) under `alloc_mutex`, and during mass-alloc
//! the block bitmap is MOSTLY allocated (mostly all-`MAX` words). Does a 4-wide
//! "all 4 words == MAX -> run breaks, skip" fast path win, or ~0-gain?
//!
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cc \
//!   rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench bitmap_run_width

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn longest_zero_run_in_word(word: u64) -> u32 {
    let mut free = !word;
    let mut best = 0;
    while free != 0 {
        free &= free << 1;
        best += 1;
    }
    best
}

#[inline]
fn apply_word(word: u64, run: &mut u32, best: &mut u32) {
    if word == 0 {
        *run = run.saturating_add(64);
        *best = (*best).max(*run);
        return;
    }
    if word == u64::MAX {
        *run = 0;
        return;
    }
    let prefix = word.trailing_zeros();
    if prefix > 0 {
        *best = (*best).max(run.saturating_add(prefix));
    }
    *best = (*best).max(longest_zero_run_in_word(word));
    *run = word.leading_zeros();
}

/// Current: per-word branchy step.
fn run_word(bitmap: &[u8]) -> u32 {
    let (mut best, mut run) = (0u32, 0u32);
    for chunk in bitmap.chunks_exact(8) {
        apply_word(
            u64::from_le_bytes(chunk.try_into().unwrap()),
            &mut run,
            &mut best,
        );
    }
    best
}

/// 4-wide: skip fully-allocated 256-bit blocks with one AND+compare.
fn run_unrolled4(bitmap: &[u8]) -> u32 {
    let (mut best, mut run) = (0u32, 0u32);
    let mut chunks = bitmap.chunks_exact(32);
    for block in &mut chunks {
        let w0 = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let w1 = u64::from_le_bytes(block[8..16].try_into().unwrap());
        let w2 = u64::from_le_bytes(block[16..24].try_into().unwrap());
        let w3 = u64::from_le_bytes(block[24..32].try_into().unwrap());
        if (w0 & w1 & w2 & w3) == u64::MAX {
            run = 0; // all allocated: no free bit, break any in-flight run
            continue;
        }
        apply_word(w0, &mut run, &mut best);
        apply_word(w1, &mut run, &mut best);
        apply_word(w2, &mut run, &mut best);
        apply_word(w3, &mut run, &mut best);
    }
    for chunk in chunks.remainder().chunks_exact(8) {
        apply_word(
            u64::from_le_bytes(chunk.try_into().unwrap()),
            &mut run,
            &mut best,
        );
    }
    best
}

fn bench(c: &mut Criterion) {
    // blocks_per_group bitmap (4 KiB). "mostly allocated" = mass-alloc state:
    // 0xFF everywhere except a few free bytes scattered (short free runs).
    let bytes = 4096usize;
    let mut mostly_alloc = vec![0xFFu8; bytes];
    for i in (0..bytes).step_by(97) {
        mostly_alloc[i] = 0x0F; // a small free run every 97 bytes
    }
    // "half allocated" control (fewer MAX words -> less skip benefit).
    let half: Vec<u8> = (0..bytes).map(|i| (i as u8).wrapping_mul(37)).collect();

    for (name, bm) in [("mostly_alloc", &mostly_alloc), ("half", &half)] {
        assert_eq!(run_word(bm), run_unrolled4(bm));
        let mut g = c.benchmark_group(format!("bitmap_run_{name}"));
        g.bench_function("word", |b| b.iter(|| black_box(run_word(black_box(bm)))));
        g.bench_function("unrolled4", |b| {
            b.iter(|| black_box(run_unrolled4(black_box(bm))))
        });
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
