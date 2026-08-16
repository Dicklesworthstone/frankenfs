#![forbid(unsafe_code)]
//! Before/after bench for bitmap_find_contiguous on a mostly-allocated bitmap
//! (mass-write into a filling group): searches from start=0 through an all-0xFF
//! prefix for a run of n free blocks near the end. Measures the all-MAX-word
//! skip lever (same as largest_free_run). Run once as baseline, once after the
//! production 4-wide all-MAX skip, and compare medians.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench contiguous_scan_width
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_alloc::bitmap_find_contiguous;
use std::hint::black_box;
fn bench(c: &mut Criterion) {
    // 8192 bytes = 65536 bits. All allocated except a free run of 16 bits near the end.
    let nbits = 65536u32;
    let mut bm = vec![0xFFu8; (nbits / 8) as usize];
    // free 16 bits at bit 65500..65516
    for slot in &mut bm[8187..8189] {
        *slot = 0;
    }
    let mut g = c.benchmark_group("contiguous_find");
    g.bench_function("mostly_alloc_n8", |b| {
        b.iter(|| black_box(bitmap_find_contiguous(black_box(&bm), nbits, 8, 0)));
    });
    g.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
