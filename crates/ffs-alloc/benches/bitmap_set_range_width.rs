#![forbid(unsafe_code)]
//! A/B: marking a contiguous allocation in the block bitmap bit-at-a-time
//! (`for i in start..end { bitmap_set(i) }`, as try_alloc_in_group did) vs a
//! word/byte-range set (fill the full middle bytes with 0xFF, only the two
//! boundary bytes need bit-ops). On the block-alloc write floor for large
//! contiguous extents.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench bitmap_set_range_width
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn set_bit(bitmap: &mut [u8], idx: u32) {
    let byte = (idx / 8) as usize;
    if let Some(b) = bitmap.get_mut(byte) {
        *b |= 1 << (idx % 8);
    }
}
fn mark_bitloop(bitmap: &mut [u8], start: u32, count: u32) {
    for i in start..start + count {
        set_bit(bitmap, i);
    }
}
fn mark_range(bitmap: &mut [u8], start: u32, count: u32) {
    if count == 0 {
        return;
    }
    let end = start + count;
    let mut idx = start;
    while idx < end && idx % 8 != 0 {
        set_bit(bitmap, idx);
        idx += 1;
    }
    let byte_start = (idx / 8) as usize;
    let full_end = end - (end % 8);
    let byte_end = ((full_end / 8) as usize).min(bitmap.len());
    if byte_end > byte_start {
        bitmap[byte_start..byte_end].fill(0xFF);
        idx = (byte_end as u32) * 8;
    }
    while idx < end {
        set_bit(bitmap, idx);
        idx += 1;
    }
}
fn bench(c: &mut Criterion) {
    for count in [8u32, 256, 4096] {
        let bytes = 8192usize; // 64k-bit group bitmap
        let start = 37u32; // unaligned start
        // equivalence check
        let (mut a, mut b) = (vec![0u8; bytes], vec![0u8; bytes]);
        mark_bitloop(&mut a, start, count);
        mark_range(&mut b, start, count);
        assert_eq!(a, b, "count={count}");
        let mut g = c.benchmark_group(format!("bitmap_mark_range_c{count}"));
        g.bench_function("bitloop", |bch| {
            bch.iter_batched(
                || vec![0u8; bytes],
                |mut bm| black_box(mark_bitloop(&mut bm, start, count)),
                BatchSize::SmallInput,
            )
        });
        g.bench_function("range", |bch| {
            bch.iter_batched(
                || vec![0u8; bytes],
                |mut bm| black_box(mark_range(&mut bm, start, count)),
                BatchSize::SmallInput,
            )
        });
        g.finish();
    }
}
criterion_group!(benches, bench);
criterion_main!(benches);
