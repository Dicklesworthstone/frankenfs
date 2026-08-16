#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Foundation proof for the incremental-`dir_csum` lever (docs/NEGATIVE_EVIDENCE.md,
//! 2026-07-03): rename is crc-dominated (~13%), create/unlink pay a 4 KiB dir-block
//! crc per insert. When `add_dir_entry` changes only ~48 bytes of a 4 KiB leaf, the
//! new crc could be computed from the OLD crc + the small delta instead of re-crcing
//! 4 KiB — IF a correct `crc32c_combine` (GF(2) "advance a crc through N bytes")
//! primitive exists. This bench IMPLEMENTS and EMPIRICALLY VERIFIES that primitive
//! against the real `crc32c` crate (the assert is the proof), then measures the
//! incremental-vs-full speedup for a realistic 4 KiB-block / 48-byte-edit.
//!
//! CONCLUSION — incremental-crc is REFUTED (measured, not reasoned). The
//! `crc32c_combine` primitive and the incremental formula are CORRECT (both asserts
//! below pass on random inputs), BUT the incremental path is ~10× SLOWER than a full
//! re-crc: the software GF(2) matrix combine (~9.5 µs to advance a crc through the
//! ~4 KiB suffix) loses badly to the SSE4.2 hardware `crc32c` streaming the whole
//! 4 KiB block (~0.9 µs). The HW crc is simply too fast to beat with a scalar
//! polynomial combine. Kept as evidence so the incremental-`dir_csum` idea (which I
//! had estimated at ~5-6% on rename) is not re-attempted. Bench/proof code only — it
//! does NOT touch the filesystem.

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

/// CRC-32C (Castagnoli) reflected polynomial — matches the `crc32c` crate.
const CRC32C_REFLECTED_POLY: u32 = 0x82F6_3B78;
const GF2_DIM: usize = 32;

fn gf2_matrix_times(mat: &[u32; GF2_DIM], mut vec: u32) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    while vec != 0 {
        if vec & 1 != 0 {
            sum ^= mat[i];
        }
        vec >>= 1;
        i += 1;
    }
    sum
}

fn gf2_matrix_square(square: &mut [u32; GF2_DIM], mat: &[u32; GF2_DIM]) {
    for n in 0..GF2_DIM {
        square[n] = gf2_matrix_times(mat, mat[n]);
    }
}

/// Returns `crc32c(A ++ B)` given `crc1 = crc32c(A)`, `crc2 = crc32c(B)`, and
/// `len2 = B.len()` — WITHOUT touching A or B. Standard zlib `crc32_combine`
/// algorithm with the CRC-32C reflected polynomial. O(log len2) GF(2) matrix
/// squarings + a couple matrix-times, vs O(len2) for a full re-crc.
fn crc32c_combine(mut crc1: u32, crc2: u32, mut len2: u64) -> u32 {
    if len2 == 0 {
        return crc1;
    }
    let mut even = [0u32; GF2_DIM];
    let mut odd = [0u32; GF2_DIM];

    // `odd` = operator for a single zero BIT.
    odd[0] = CRC32C_REFLECTED_POLY;
    let mut row = 1u32;
    for slot in odd.iter_mut().take(GF2_DIM).skip(1) {
        *slot = row;
        row <<= 1;
    }
    gf2_matrix_square(&mut even, &odd); // even = 2 zero bits
    gf2_matrix_square(&mut odd, &even); // odd  = 4 zero bits

    loop {
        gf2_matrix_square(&mut even, &odd); // even = 8 bits = 1 byte (then 4, 16, ...)
        if len2 & 1 != 0 {
            crc1 = gf2_matrix_times(&even, crc1);
        }
        len2 >>= 1;
        if len2 == 0 {
            break;
        }
        gf2_matrix_square(&mut odd, &even);
        if len2 & 1 != 0 {
            crc1 = gf2_matrix_times(&odd, crc1);
        }
        len2 >>= 1;
        if len2 == 0 {
            break;
        }
    }
    crc1 ^ crc2
}

// Deterministic pseudo-random bytes (no Math.random; index-seeded).
fn prng_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// Incremental crc of `block` after XOR-ing `delta` into `block[pos..pos+delta.len()]`,
/// computed from `crc_old` + the delta only (no full re-crc). Uses crc linearity:
/// `crc(U) ^ crc(V) = crc(U^V) ^ crc(0^n)` for equal-length U,V, and the mostly-zero
/// `U^V` reduces to `crc32c(delta bytes) advanced through the suffix zeros`.
fn crc32c_incremental(crc_old: u32, block_len: usize, pos: usize, delta: &[u8]) -> u32 {
    let dlen = delta.len();
    let suffix = (block_len - pos - dlen) as u64;
    // `crc_new ^ crc_old = M(delta_block)` where M is the crc's LINEAR part (the
    // init/final XOR constants cancel between two equal-length inputs). For a block
    // that is zero except `delta` at `pos`, M reduces to the linear crc of `delta`
    // advanced through the `suffix` trailing zeros — the leading `pos` zeros don't
    // matter (M starts its register at 0). `M(x) = crc32c(x) ^ crc32c(0^len(x))`.
    let zeros = vec![0u8; dlen];
    let m_delta = crc32c::crc32c(delta) ^ crc32c::crc32c(&zeros);
    let effect = crc32c_combine(m_delta, 0, suffix);
    crc_old ^ effect
}

fn bench_crc_incremental(c: &mut Criterion) {
    // Hoisted from mid-function (bd-3ao0l): items are in scope from the start
    // of the block, so declaring one after statements misleads the reader.
    const N: usize = 4096;
    // ---- Correctness proof #1: crc32c_combine == full crc of concatenation ----
    for s in 0..64u64 {
        let a = prng_bytes(s + 1, (s as usize) * 7 + 3);
        let b = prng_bytes(s + 100, (s as usize) * 5 + 48);
        let mut ab = a.clone();
        ab.extend_from_slice(&b);
        let combined = crc32c_combine(crc32c::crc32c(&a), crc32c::crc32c(&b), b.len() as u64);
        assert_eq!(
            combined,
            crc32c::crc32c(&ab),
            "crc32c_combine mismatch at seed {s}"
        );
    }

    // ---- Correctness proof #2: incremental dir-edit crc == full re-crc ----
    for s in 0..32u64 {
        let mut block = prng_bytes(s + 7, N);
        let crc_old = crc32c::crc32c(&block);
        let pos = 3000 + (s as usize % 40); // realistic: near the used-space tail
        let new_bytes = prng_bytes(s + 555, 48);
        let delta: Vec<u8> = new_bytes
            .iter()
            .zip(&block[pos..pos + 48])
            .map(|(n, o)| n ^ o)
            .collect();
        // Apply the edit for the full re-crc reference.
        block[pos..pos + 48].copy_from_slice(&new_bytes);
        let full_new = crc32c::crc32c(&block);
        let incr_new = crc32c_incremental(crc_old, N, pos, &delta);
        assert_eq!(
            incr_new, full_new,
            "incremental dir-crc mismatch at seed {s}"
        );
    }

    // ---- Speedup: full 4 KiB crc vs incremental (48-byte edit) ----
    let base = prng_bytes(42, N);
    let crc_old = crc32c::crc32c(&base);
    let new_bytes = prng_bytes(43, 48);
    let delta: Vec<u8> = new_bytes
        .iter()
        .zip(&base[3000..3048])
        .map(|(n, o)| n ^ o)
        .collect();

    let mut group = c.benchmark_group("dir_csum_4k");
    group.bench_function("full_recrc", |bch| {
        bch.iter(|| {
            let mut blk = base.clone();
            blk[3000..3048].copy_from_slice(black_box(&new_bytes));
            black_box(crc32c::crc32c(&blk))
        });
    });
    group.bench_function("incremental", |bch| {
        bch.iter(|| {
            black_box(crc32c_incremental(
                black_box(crc_old),
                N,
                3000,
                black_box(&delta),
            ))
        });
    });
    group.finish();
}

criterion_group!(benches, bench_crc_incremental);
criterion_main!(benches);
