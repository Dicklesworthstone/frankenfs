#![forbid(unsafe_code)]

//! A/B for the write-path sparse-detection all-zero checks (ffs-core holemap
//! scan @15216 + btrfs_insert_regular_extent_segment @23522), which are
//! BYTE-wise `data.iter().all(|&b| b == 0)`. Does byte-wise auto-vectorize, or
//! does a word / 4-wide u64 OR-reduce win (as it did for the word-wise scrub
//! is_all_zero)? Runs on every written block/segment.
//!
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc \
//!   rch exec -- cargo bench --profile release-perf -p ffs-core --bench sparse_zero_scan

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn byte_all_zero(data: &[u8]) -> bool {
    data.iter().all(|&b| b == 0)
}

fn word_all_zero(data: &[u8]) -> bool {
    let mut chunks = data.chunks_exact(8);
    chunks.all(|c| u64::from_ne_bytes(c.try_into().unwrap()) == 0)
        && chunks.remainder().iter().all(|&b| b == 0)
}

fn unrolled4_all_zero(data: &[u8]) -> bool {
    let mut chunks = data.chunks_exact(32);
    for block in &mut chunks {
        let w0 = u64::from_ne_bytes(block[0..8].try_into().unwrap());
        let w1 = u64::from_ne_bytes(block[8..16].try_into().unwrap());
        let w2 = u64::from_ne_bytes(block[16..24].try_into().unwrap());
        let w3 = u64::from_ne_bytes(block[24..32].try_into().unwrap());
        if (w0 | w1 | w2 | w3) != 0 {
            return false;
        }
    }
    let mut tail = chunks.remainder().chunks_exact(8);
    tail.all(|c| u64::from_ne_bytes(c.try_into().unwrap()) == 0)
        && tail.remainder().iter().all(|&b| b == 0)
}

fn bench(c: &mut Criterion) {
    let zero = vec![0u8; 4096];
    let mut early = vec![0u8; 4096];
    early[0] = 1;
    for (name, block) in [("zero", &zero), ("nonzero_early", &early)] {
        assert_eq!(byte_all_zero(block), unrolled4_all_zero(block));
        assert_eq!(word_all_zero(block), unrolled4_all_zero(block));
        let mut g = c.benchmark_group(format!("sparse_zero_{name}"));
        g.bench_function("byte", |b| b.iter(|| black_box(byte_all_zero(black_box(block)))));
        g.bench_function("word", |b| b.iter(|| black_box(word_all_zero(black_box(block)))));
        g.bench_function("unrolled4", |b| b.iter(|| black_box(unrolled4_all_zero(black_box(block)))));
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
