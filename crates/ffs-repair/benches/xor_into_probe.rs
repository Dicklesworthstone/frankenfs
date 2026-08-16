#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Probe: is the local-parity `xor_into` (lrc.rs) already at the LLVM
//! auto-vectorized floor, or does an explicit word-wise (`chunks_exact(8)`)
//! XOR beat the byte-by-byte `iter_mut().zip()` form?
//!
//! UNLIKE the settled GF-mul SIMD dead-end (bd-416sl / gf_simd_probe): plain
//! XOR needs NO table gather / PSHUFB, so it vectorizes to SSE2 (the generic
//! x86-64 baseline) with zero unsafe and no CPU-baseline bump. This is the same
//! byte->word pattern that won ~20% on the scrub zero-check (b6bbdd6f).
//!
//! CONCLUSION (2026-07-04, BlackThrush) — NEUTRAL under the perf profile;
//! the win is a size-profile artifact, so DON'T convert production `xor_into`:
//!   4 KiB xor_into      byte_zip      word_chunks
//!   opt-level "z"       ~1.87 us      ~175 ns    (~10.7x — DEFAULT release!)
//!   opt-level 3         ~102 ns       ~107 ns    (NEUTRAL — perf profile)
//! Under opt-level 3 (`[profile.release-perf]`, the profile perf is measured on)
//! LLVM already auto-vectorizes the branchless byte `zip` to SSE2 (~40 GB/s,
//! L1-resident), so word-wise wins nothing. The 10x only appears under
//! `[profile.release]` opt-level "z" (size), which deliberately suppresses
//! vectorization — hand-vectorizing there would fight the size intent and only
//! matters if the size-optimized binary's erasure-repair (LRC local parity)
//! throughput ever becomes a goal (it is not a hot default-path op). Textbook
//! bench-profile != perf-profile trap; caught by re-running under opt 3.
//!
//! Self-contained; touches no production code. Kept as a reproducible guard so
//! this isn't re-litigated (mirrors gf_simd_probe). Run:
//!   cargo bench -p ffs-repair --bench xor_into_probe                 # opt "z"
//!   RUSTFLAGS="-C opt-level=3" cargo bench -p ffs-repair --bench xor_into_probe

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const BLOCK: usize = 4096;

/// Production form (lrc.rs:694): byte-by-byte zip.
fn xor_into_byte(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= s;
    }
}

/// Candidate: word-wise `u64` XOR with a byte-wise remainder (behaviour-identical).
fn xor_into_word(dst: &mut [u8], src: &[u8]) {
    let n = dst.len().min(src.len());
    let words = n / 8;
    let (dst_w, dst_rem) = dst.split_at_mut(words * 8);
    let (src_w, src_rem) = src.split_at(words * 8);
    let (dst_words, _) = dst_w.as_chunks_mut::<8>();
    let (src_words, _) = src_w.as_chunks::<8>();
    for (dc, sc) in dst_words.iter_mut().zip(src_words) {
        let d = u64::from_ne_bytes(*dc);
        let s = u64::from_ne_bytes(*sc);
        *dc = (d ^ s).to_ne_bytes();
    }
    let rem = dst_rem.len().min(src_rem.len());
    for (d, s) in dst_rem[..rem].iter_mut().zip(src_rem[..rem].iter()) {
        *d ^= s;
    }
}

fn bench_xor(c: &mut Criterion) {
    let src: Vec<u8> = (0..BLOCK).map(|i| (i * 31 + 7) as u8).collect();

    // Equivalence sanity.
    let mut a = vec![0xA5u8; BLOCK];
    let mut b = vec![0xA5u8; BLOCK];
    xor_into_byte(&mut a, &src);
    xor_into_word(&mut b, &src);
    assert_eq!(a, b, "byte and word xor_into must match");

    // Allocate dst ONCE and XOR in place each iteration (no per-iter clone/alloc
    // that would swamp the XOR cost). The buffer content drifts but the work per
    // call is identical; black_box blocks dead-code elimination.
    let mut g = c.benchmark_group("xor_into_4k");
    g.bench_function("byte_zip", |bch| {
        let mut dst = vec![0xA5u8; BLOCK];
        bch.iter(|| {
            xor_into_byte(black_box(&mut dst), black_box(&src));
            black_box(dst[0]);
        });
    });
    g.bench_function("word_chunks", |bch| {
        let mut dst = vec![0xA5u8; BLOCK];
        bch.iter(|| {
            xor_into_word(black_box(&mut dst), black_box(&src));
            black_box(dst[0]);
        });
    });
    g.finish();
}

criterion_group!(benches, bench_xor);
criterion_main!(benches);
