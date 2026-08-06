//! Incremental CRC32C update for in-place changes to a fixed-length buffer.
//!
//! Re-checksumming a whole 4 KiB group bitmap on every allocation (a single-bit
//! or short-range change) is O(buffer); after the bit-loop→range wins made the
//! bitmap marking O(N/8), that full crc32c recompute is the dominant per-create
//! serial CPU cost (bench `bitmap_csum_recompute`: ~648 ns for a 4 KiB block
//! bitmap). CRC is linear, so changing bytes `[start, start+len)` from `old` to
//! `new` shifts the checksum by exactly `crc32c_shift(raw_crc(old XOR new), suffix)`
//! where `suffix` is the number of unchanged bytes after the change. With the
//! per-power operator matrices precomputed once, that shift is O(log suffix) 32×32
//! GF(2) matrix-vector products — far cheaper than re-scanning the whole buffer.
//!
//! Standard reflected CRC32C (`crc32c` crate) is affine: for two SAME-LENGTH
//! buffers `std(a) XOR std(b) = raw(a XOR b)` (the init/final terms cancel), so a
//! cached *standard* crc updates correctly with this raw-CRC delta.

use std::sync::OnceLock;

/// Reflected CRC32C polynomial (Castagnoli, bit-reversed form).
const POLY: u32 = 0x82F6_3B78;

/// Byte-indexed CRC32C table for the reflected polynomial, built once.
fn crc32c_byte_table() -> &'static [u32; 256] {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for i in 0_u8..=u8::MAX {
            let mut c = u32::from(i);
            let mut b = 0;
            while b < 8 {
                c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
                b += 1;
            }
            t[usize::from(i)] = c;
        }
        t
    })
}

/// Delta length at/below which the byte-wise software table beats the
/// hardware-crc path. For a short delta the one-lookup-per-byte loop is only a
/// handful of iterations, cheaper than a `crc32c` crate call plus the single
/// init-constant shift the standard→raw conversion needs; above it the hardware
/// CRC32C (8 bytes/instruction) wins decisively. Measured crossover is a few
/// tens of bytes (bench `crc_incremental`: `incremental_8b` unchanged,
/// `incremental_128b` drops sharply).
const HW_RAW_CRC_MIN_LEN: usize = 16;

/// Raw reflected CRC32C: init 0, no final XOR. Linear in its input, unlike the
/// standard crc (init/final make it affine), which is what the incremental
/// combine needs.
///
/// Short deltas use the byte-wise table (one lookup per byte). Longer deltas use
/// the hardware-accelerated `crc32c` crate (SSE4.2 CRC32 instruction, ~8
/// bytes/instr) and convert its *standard* result to the raw form via CRC
/// linearity: `std(d) = shift(0xFFFF_FFFF, 8·len) XOR R0(d) XOR 0xFFFF_FFFF`
/// (init all-ones, invert output), hence
/// `R0(d) = std(d) XOR 0xFFFF_FFFF XOR shift(0xFFFF_FFFF, 8·len)`. The single
/// init-constant shift is O(log len) and independent of the delta bytes, so for
/// a delta beyond [`HW_RAW_CRC_MIN_LEN`] this replaces up to hundreds of table
/// iterations with a few hardware CRC instructions.
fn raw_crc32c(data: &[u8]) -> u32 {
    if data.len() <= HW_RAW_CRC_MIN_LEN {
        let table = crc32c_byte_table();
        let mut crc = 0u32;
        for &b in data {
            crc = table[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
        }
        crc
    } else {
        let std = crc32c::crc32c(data);
        let bit_len = u64::try_from(data.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(8);
        std ^ 0xFFFF_FFFF ^ crc32c_shift_bits(0xFFFF_FFFF, bit_len)
    }
}

/// Multiply a GF(2) 32×32 matrix (stored column-major as 32 u32s) by a vector.
fn gf2_matrix_times(mat: &[u32; 32], vec: u32) -> u32 {
    // Branchless: XOR row `i` in whenever bit `i` of `vec` is set, using a
    // full-width mask instead of a data-dependent branch. The per-shift caller
    // feeds ~random CRC values, so the old `if vec & 1` branch mispredicted ~50%
    // of iterations; masking is misprediction-free (and auto-vectorizes).
    let mut sum = 0u32;
    for (i, &row) in mat.iter().enumerate() {
        let mask = 0u32.wrapping_sub((vec >> i) & 1);
        sum ^= row & mask;
    }
    sum
}

fn gf2_matrix_square(square: &mut [u32; 32], mat: &[u32; 32]) {
    for (slot, &column) in square.iter_mut().zip(mat) {
        *slot = gf2_matrix_times(mat, column);
    }
}

/// Operator matrices for shifting a CRC by `2^k` zero *bits*, precomputed once.
/// `ops[k]` advances a CRC as if `2^k` zero bits were appended.
fn shift_operators() -> &'static [[u32; 32]; 40] {
    static OPS: OnceLock<[[u32; 32]; 40]> = OnceLock::new();
    OPS.get_or_init(|| {
        let mut ops = [[0u32; 32]; 40];
        // ops[0] = operator for one zero bit.
        ops[0][0] = POLY;
        let mut row = 1u32;
        for slot in ops[0].iter_mut().skip(1) {
            *slot = row;
            row <<= 1;
        }
        // ops[k+1] = ops[k]^2 (doubles the number of zero bits).
        for k in 1..40 {
            let prev = ops[k - 1];
            gf2_matrix_square(&mut ops[k], &prev);
        }
        ops
    })
}

/// Advance `crc` as if `zero_bits` zero bits were appended (multiply by x^zero_bits).
fn crc32c_shift_bits(crc: u32, mut zero_bits: u64) -> u32 {
    let ops = shift_operators();
    let mut c = crc;
    let mut k = 0usize;
    while zero_bits != 0 {
        if zero_bits & 1 != 0 {
            c = gf2_matrix_times(&ops[k], c);
        }
        zero_bits >>= 1;
        k += 1;
    }
    c
}

/// Identity operator (column-major): column `n` selects bit `n`.
fn gf2_identity() -> [u32; 32] {
    let mut m = [0u32; 32];
    for (n, col) in m.iter_mut().enumerate() {
        *col = 1u32 << n;
    }
    m
}

/// GF(2) 32×32 matrix product `a·b` (column-major), so
/// `gf2_matrix_times(a·b, v) == gf2_matrix_times(a, gf2_matrix_times(b, v))`.
fn gf2_matrix_mul(a: &[u32; 32], b: &[u32; 32]) -> [u32; 32] {
    let mut out = [0u32; 32];
    for (n, col) in out.iter_mut().enumerate() {
        *col = gf2_matrix_times(a, b[n]);
    }
    out
}

/// Byte-granular shift operators for a *constant-time* CRC advance. `lo[j]`
/// advances by `j` zero bytes (`8j` bits), `hi[k]` by `k·256` zero bytes. Any
/// byte count `n < 65536` factors as `hi[n>>8] · lo[n & 0xFF]`, so
/// [`crc32c_shift_bytes`] is exactly TWO matrix-vector products regardless of
/// `n` — versus [`crc32c_shift_bits`]'s `popcount(8n)` products (1..≈15, avg ~8
/// for a random offset in a 4 KiB block). ~64 KiB of static tables, built once.
#[allow(clippy::type_complexity)]
fn byte_shift_operators() -> &'static (Box<[[u32; 32]]>, Box<[[u32; 32]]>) {
    static TABLES: OnceLock<(Box<[[u32; 32]]>, Box<[[u32; 32]]>)> = OnceLock::new();
    TABLES.get_or_init(|| {
        let ops = shift_operators();
        let op8 = ops[3]; // shift by 2^3 = 8 bits = 1 byte
        let op2048 = ops[11]; // shift by 2^11 = 2048 bits = 256 bytes
        let mut lo = vec![[0u32; 32]; 256].into_boxed_slice();
        let mut hi = vec![[0u32; 32]; 256].into_boxed_slice();
        lo[0] = gf2_identity();
        hi[0] = gf2_identity();
        for j in 1..256 {
            lo[j] = gf2_matrix_mul(&op8, &lo[j - 1]);
            hi[j] = gf2_matrix_mul(&op2048, &hi[j - 1]);
        }
        (lo, hi)
    })
}

/// Advance `crc` as if `zero_bytes` zero bytes were appended.
///
/// Constant time (two matrix-vector products) for any `zero_bytes < 65536`, which
/// covers every ext4/btrfs block size. Falls back to the bit-decomposition shift
/// for larger counts, never reached for ≤64 KiB blocks.
///
/// This is a raw running-CRC advance: given the running CRC after some prefix,
/// it returns the running CRC after that prefix followed by `zero_bytes` zeros,
/// without touching those bytes.
///
/// Callers that CRC a block with a large trailing zero run (a freshly-built
/// directory block: entries then a zero gap) can CRC only the non-zero prefix
/// and shift over the rest.
#[must_use]
pub fn crc32c_shift_bytes(crc: u32, zero_bytes: usize) -> u32 {
    if zero_bytes >= 65536 {
        let zero_bits = u64::try_from(zero_bytes)
            .unwrap_or(u64::MAX)
            .saturating_mul(8);
        return crc32c_shift_bits(crc, zero_bits);
    }
    let (lo, hi) = byte_shift_operators();
    let c = gf2_matrix_times(&lo[zero_bytes & 0xFF], crc);
    gf2_matrix_times(&hi[zero_bytes >> 8], c)
}

/// Incrementally update a standard CRC32C after an in-place change.
///
/// `old_crc` is `crc32c(buffer_before)`. The change replaced `buffer[start..start+delta.len()]`
/// such that `delta[i] = before[start+i] XOR after[start+i]`. `suffix_bytes` is the
/// number of bytes AFTER the changed region (`buffer.len() - start - delta.len()`).
/// Returns `crc32c(buffer_after)`. Result-identical to a full recompute.
#[must_use]
pub fn crc32c_update_region(old_crc: u32, delta: &[u8], suffix_bytes: usize) -> u32 {
    let raw = raw_crc32c(delta);
    // Constant-time (two matrix products) suffix shift, independent of where in
    // the block the change lands — replaces the popcount-many products of the
    // bit-decomposition shift, which dominated the incremental cost after the
    // hardware-crc delta win.
    old_crc ^ crc32c_shift_bytes(raw, suffix_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(orig: &[u8], start: usize, new_bytes: &[u8]) -> Vec<u8> {
        let mut b = orig.to_vec();
        b[start..start + new_bytes.len()].copy_from_slice(new_bytes);
        b
    }

    fn check(orig: &[u8], start: usize, new_bytes: &[u8]) {
        let after = apply(orig, start, new_bytes);
        let old_crc = crc32c::crc32c(orig);
        let delta: Vec<u8> = new_bytes
            .iter()
            .zip(&orig[start..start + new_bytes.len()])
            .map(|(n, o)| n ^ o)
            .collect();
        let suffix = orig.len() - start - new_bytes.len();
        let got = crc32c_update_region(old_crc, &delta, suffix);
        assert_eq!(
            got,
            crc32c::crc32c(&after),
            "start={start} len={}",
            new_bytes.len()
        );
    }

    #[test]
    fn incremental_matches_full_recompute_cases() {
        let base: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(37) & 0xFF) as u8)
            .collect();
        // single-byte, short-range, and boundary changes at various positions.
        check(&base, 0, &[0xFF]);
        check(&base, 4095, &[0x01]);
        check(&base, 40, &[0xFF; 8]);
        check(&base, 2000, &[0x5A; 32]);
        check(&base, 4064, &[0xAB; 32]);
        check(&base, 1, &[0u8; 100]);
        // Straddle the byte-table / hardware-crc crossover (HW_RAW_CRC_MIN_LEN).
        check(&base, 10, &[0x11; 15]);
        check(&base, 10, &[0x22; 16]);
        check(&base, 10, &[0x33; 17]);
        check(&base, 500, &[0xC3; 200]);
        check(&base, 0, &[0x7Eu8; 256]);
        check(&base, 3840, &[0x01u8; 256]);
    }

    #[test]
    fn incremental_matches_full_recompute_prop() {
        // Deterministic pseudo-random sweep (proptest-style).
        let mut state = 0x1234_5678u32;
        let mut next = || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state
        };
        let base: Vec<u8> = (0..8192u32)
            .map(|i| (i.wrapping_mul(101) & 0xFF) as u8)
            .collect();
        for _ in 0..500 {
            // Sizes 1..=300 exercise both the byte-table (<= HW_RAW_CRC_MIN_LEN)
            // and hardware-crc (>) branches, spanning the create path's 256 B gate.
            let len = 1 + (next() as usize % 300);
            let start = (next() as usize) % (base.len() - len);
            let new_bytes: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
            check(&base, start, &new_bytes);
        }
    }

    #[test]
    fn byte_shift_tables_match_bit_shift_at_factor_boundaries() {
        for crc in [0, 0x1234_5678, u32::MAX] {
            for zero_bytes in [0_u16, 1, 255, 256, 511, u16::MAX] {
                assert_eq!(
                    crc32c_shift_bytes(crc, usize::from(zero_bytes)),
                    crc32c_shift_bits(crc, u64::from(zero_bytes) * 8),
                    "crc={crc:#010x}, zero_bytes={zero_bytes}",
                );
            }
        }
    }
}
