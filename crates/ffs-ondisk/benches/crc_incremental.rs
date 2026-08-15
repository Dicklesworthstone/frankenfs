#![forbid(unsafe_code)]
//! Incremental crc32c update vs full recompute for a bitmap change.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench crc_incremental
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::crc_incremental::crc32c_update_region;
use std::hint::black_box;
fn bench(c: &mut Criterion) {
    let mut bitmap = vec![0xA5u8; 4096];
    let old_crc = crc32c::crc32c(&bitmap);
    // simulate a small contiguous alloc: set 8 bytes (64 blocks) at offset 3000.
    let start = 3000usize;
    let new_bytes = [0xFFu8; 8];
    let delta: Vec<u8> = new_bytes
        .iter()
        .zip(&bitmap[start..start + 8])
        .map(|(n, o)| n ^ o)
        .collect();
    let suffix = bitmap.len() - start - 8;
    // equivalence check
    let mut after = bitmap.clone();
    after[start..start + 8].copy_from_slice(&new_bytes);
    assert_eq!(
        crc32c_update_region(old_crc, &delta, suffix),
        crc32c::crc32c(&after)
    );
    bitmap[start..start + 8].copy_from_slice(&new_bytes); // reflect the change for the full-recompute arm
    // larger delta (128 bytes = 1024 blocks) to exercise the raw-crc portion.
    let start2 = 100usize;
    let nb2 = [0xFFu8; 128];
    let delta2: Vec<u8> = nb2
        .iter()
        .zip(&bitmap[start2..start2 + 128])
        .map(|(n, o)| n ^ o)
        .collect();
    let suffix2 = bitmap.len() - start2 - 128;
    // Production-representative: a small change lands at an ARBITRARY offset in
    // the block (dir entries / bitmap runs are anywhere), so the suffix length —
    // and thus the GF-shift cost — varies. Sum over a spread of suffixes to
    // measure the average, not one lucky low-popcount offset.
    let suffixes: Vec<usize> = (0..64).map(|i| i * 63 + 1).collect(); // 1..~4000, mixed popcounts
    // A deliberately high-popcount suffix (worst case for the bit-shift).
    let worst_suffix = 0x0AAA_usize; // 0b101010101010

    let mut g = c.benchmark_group("crc_bitmap_update");
    g.bench_function("full_recompute", |b| {
        b.iter(|| black_box(crc32c::crc32c(black_box(&bitmap))));
    });
    g.bench_function("incremental_8b", |b| {
        b.iter(|| {
            black_box(crc32c_update_region(
                black_box(old_crc),
                black_box(&delta),
                black_box(suffix),
            ))
        });
    });
    g.bench_function("incremental_128b", |b| {
        b.iter(|| {
            black_box(crc32c_update_region(
                black_box(old_crc),
                black_box(&delta2),
                black_box(suffix2),
            ))
        });
    });
    g.bench_function("incremental_avg_offsets", |b| {
        b.iter(|| {
            let mut acc = 0u32;
            for &s in &suffixes {
                acc ^= crc32c_update_region(black_box(old_crc), black_box(&delta), black_box(s));
            }
            black_box(acc)
        });
    });
    g.bench_function("incremental_worstcase", |b| {
        b.iter(|| {
            black_box(crc32c_update_region(
                black_box(old_crc),
                black_box(&delta),
                black_box(worst_suffix),
            ))
        });
    });
    g.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
