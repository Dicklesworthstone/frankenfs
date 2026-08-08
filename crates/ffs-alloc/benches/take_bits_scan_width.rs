#![forbid(unsafe_code)]
//! Before/after bench for bitmap_take_free_bits_cyclic (multi-block alloc take)
//! on a mostly-allocated group bitmap: takes 8 blocks starting from bit 0,
//! scanning the all-0xFF prefix to reach free bits near the end. Measures the
//! all-MAX-word skip lever (same as the contiguous finder). Run once as
//! baseline, once after the production 4-wide skip; compare medians.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench take_bits_scan_width
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ffs_alloc::bench_take_free_bits_cyclic;
use std::hint::black_box;
fn bench(c: &mut Criterion) {
    let nbits = 65536u32;
    let mut template = vec![0xFFu8; (nbits / 8) as usize];
    for byte in 8180..8192 {
        template[byte] = 0;
    } // free bits near the end
    c.bench_function("take_bits_mostly_alloc_n8", |b| {
        b.iter_batched(
            || template.clone(),
            |mut bm| black_box(bench_take_free_bits_cyclic(&mut bm, nbits, 8, 0)),
            BatchSize::SmallInput,
        )
    });
}
criterion_group!(benches, bench);
criterion_main!(benches);
