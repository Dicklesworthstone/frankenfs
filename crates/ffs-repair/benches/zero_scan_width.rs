#![forbid(unsafe_code)]

//! Throwaway A/B: scrub `is_all_zero` (scrub.rs:491) is `chunks_exact(8).all(==0)`
//! — one u64/iter with an early-exit branch, the same vectorization-blocking
//! shape as the alloc-bitmap scans. It full-scans only all-zero blocks (free /
//! unallocated space, common on a fresh or sparse image; non-zero data blocks
//! early-exit at word 0). Does a 4-wide OR-reduce beat it on the full-scan
//! (zero-block) case, or does the compiler auto-vectorize the all-zero check?
//!
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc \
//!   rch exec -- cargo bench --profile release-perf -p ffs-repair --bench zero_scan_width

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

/// Current production shape.
fn zero_word(data: &[u8]) -> bool {
    let (chunks, remainder) = data.as_chunks::<8>();
    chunks.iter().all(|c| u64::from_ne_bytes(*c) == 0) && remainder.iter().all(|&b| b == 0)
}

/// Byte-wise (the old storage.rs erasure-symbol shape before routing through
/// scrub::is_all_zero).
fn zero_byte(data: &[u8]) -> bool {
    data.iter().all(|&b| b == 0)
}

/// 4-wide OR-reduce: one branch per 256 bits.
fn zero_unrolled4(data: &[u8]) -> bool {
    let (chunks, rem) = data.as_chunks::<32>();
    for block in chunks {
        let w0 = u64::from_ne_bytes(block[0..8].try_into().unwrap());
        let w1 = u64::from_ne_bytes(block[8..16].try_into().unwrap());
        let w2 = u64::from_ne_bytes(block[16..24].try_into().unwrap());
        let w3 = u64::from_ne_bytes(block[24..32].try_into().unwrap());
        if (w0 | w1 | w2 | w3) != 0 {
            return false;
        }
    }
    let (tail, tail_rem) = rem.as_chunks::<8>();
    tail.iter().all(|c| u64::from_ne_bytes(*c) == 0) && tail_rem.iter().all(|&b| b == 0)
}

fn bench(c: &mut Criterion) {
    // Three cases: all-zero (full scan, the win case), non-zero at byte 0 (the
    // common data block — both exit immediately, checks the 4-wide's read-32-
    // before-exit downside), and non-zero at the last byte (worst-case full scan
    // then reject).
    let zero = vec![0u8; 4096];
    let mut early = vec![0u8; 4096];
    early[0] = 1;
    let mut late = vec![0u8; 4096];
    late[4095] = 1;
    for (name, block) in [
        ("zero", &zero),
        ("nonzero_early", &early),
        ("nonzero_late", &late),
    ] {
        assert_eq!(zero_word(block), zero_unrolled4(block));
        assert_eq!(zero_byte(block), zero_unrolled4(block));
        let mut g = c.benchmark_group(format!("scrub_is_all_zero_{name}"));
        g.bench_function("byte", |b| {
            b.iter(|| black_box(zero_byte(black_box(block))));
        });
        g.bench_function("word", |b| {
            b.iter(|| black_box(zero_word(black_box(block))));
        });
        g.bench_function("unrolled4", |b| {
            b.iter(|| black_box(zero_unrolled4(black_box(block))));
        });
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
