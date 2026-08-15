#![forbid(unsafe_code)]
//! Measures the per-alloc bitmap checksum recompute cost (full crc32c over a
//! blocks_per_group bitmap) vs the crc of just the changed region — pinpointing
//! the dominant per-alloc CPU cost AFTER the bit-loop->range wins made marking
//! O(N/8). NEGATIVE/FLAG: incremental crc via GF crc-shift is ~as expensive as
//! the full crc for an arbitrary-position delta; batching the recompute needs
//! deferring the bitmap write = owner-lane MVCC.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench bitmap_csum_recompute
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
fn bench(c: &mut Criterion) {
    let bitmap4k = vec![0xA5u8; 4096]; // 32768-block group bitmap
    let bitmap1k = vec![0xA5u8; 1024]; // 8192-inode group bitmap
    let delta = vec![0xFFu8; 8]; // one 64-bit word changed (a small alloc)
    let mut g = c.benchmark_group("bitmap_csum");
    g.bench_function("full_recompute_4k", |b| {
        b.iter(|| black_box(crc32c::crc32c(black_box(&bitmap4k))))
    });
    g.bench_function("full_recompute_1k", |b| {
        b.iter(|| black_box(crc32c::crc32c(black_box(&bitmap1k))))
    });
    g.bench_function("crc_of_delta_8b", |b| {
        b.iter(|| black_box(crc32c::crc32c(black_box(&delta))))
    });
    g.finish();

    // Zero-tail-aware block-bitmap checksum (production `block_bitmap_checksum_value`).
    // A group fills bottom-up, so a partially-full group's 4 KiB bitmap is a live
    // prefix + a zero tail (free high blocks) — the zero tail is skipped via the
    // GF(2) shift. `full` (0xA5, no trailing zeros) falls back to the straight CRC
    // and is the ORIG cost; `partial` (25% full) shows the win.
    use ffs_ondisk::ext4::block_bitmap_checksum_value;
    let seed = 0xDEAD_BEEFu32;
    let clusters = 32768u32; // 4096-byte bitmap
    let desc = 64u16;
    let mut partial = vec![0u8; 4096];
    for byte in partial.iter_mut().take(1024) {
        *byte = 0xFF; // ~8192 of 32768 blocks allocated (25% full)
    }
    let full = vec![0xA5u8; 4096];
    let mut g2 = c.benchmark_group("bitmap_csum_value");
    g2.bench_function("full_straight", |b| {
        b.iter(|| {
            black_box(block_bitmap_checksum_value(
                black_box(&full),
                seed,
                clusters,
                desc,
            ))
        })
    });
    g2.bench_function("partial_zeroaware", |b| {
        b.iter(|| {
            black_box(block_bitmap_checksum_value(
                black_box(&partial),
                seed,
                clusters,
                desc,
            ))
        })
    });
    g2.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
