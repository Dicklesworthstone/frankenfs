#![forbid(unsafe_code)]

//! Same-machine A/B for reusing a zstd decompression context across MVCC
//! version decompressions.
//!
//! `resolve_data` decompresses `VersionData::Zstd` via `zstd::decode_all`, which
//! constructs a fresh `DCtx` on every call. A thread-local reused
//! `zstd::bulk::Decompressor` (the same pattern the btrfs read path already
//! uses) amortizes that context construction. This bench measures whether the
//! reuse actually wins, and at which block sizes, before changing production.
//!
//! Both arms decompress identical bytes; the delta isolates the per-call DCtx
//! construction. Run as a single binary to keep the comparison on one CPU.

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn compressible(len: usize) -> Vec<u8> {
    // Realistic FS metadata-ish data: mostly-repeating with some structure, so
    // zstd actually compresses (a pure-random buffer would not).
    (0..len)
        .map(|i| u8::try_from((i / 17) % 251).expect("modulo 251 always fits a u8"))
        .collect()
}

fn bench(c: &mut Criterion) {
    for &size in &[4096_usize, 16384, 65536] {
        let raw = compressible(size);
        let comp = zstd::encode_all(raw.as_slice(), 3).expect("encode");
        let mut group = c.benchmark_group(format!("mvcc_zstd_decompress_{size}"));

        // Current shape: fresh DCtx per call.
        group.bench_function("decode_all_fresh", |b| {
            b.iter(|| {
                let out = zstd::decode_all(black_box(comp.as_slice())).expect("decode");
                black_box(out)
            });
        });

        // Candidate: one reused bulk Decompressor (models a thread-local).
        let mut dec = zstd::bulk::Decompressor::new().expect("decompressor");
        group.bench_function("reused_bulk_decompressor", |b| {
            b.iter(|| {
                let out = dec
                    .decompress(black_box(comp.as_slice()), size)
                    .expect("decompress");
                black_box(out)
            });
        });

        group.finish();
    }
}

criterion_group!(zstd_decompress_reuse, bench);
criterion_main!(zstd_decompress_reuse);
