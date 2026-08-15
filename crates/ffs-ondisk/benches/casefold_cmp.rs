#![forbid(unsafe_code)]
//! `casefold_key_eq` / `ext4_casefold_eq` compare directory names case-
//! insensitively PER ENTRY in a casefold-dir leaf scan (every lookup/create in a
//! case-insensitive ext4 dir — Android /data, Windows-compat). For ASCII names
//! (the common case) they use `[u8]::eq_ignore_ascii_case`, which lowercases +
//! compares BYTE-WISE. A word-at-a-time SWAR ASCII case-fold compare (lowercase
//! 8 bytes/iter via the branchless in-range trick, then compare words) should
//! beat it on same-length names — the case-folding analogue of the `names_eq`
//! SWAR exact-compare win (a092e533, 1.43x). A/B on representative names.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench casefold_cmp
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

#[inline]
fn bytewise(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

const ONES: u64 = 0x0101_0101_0101_0101;
const HIGHS: u64 = 0x8080_8080_8080_8080;

/// Lowercase 8 ASCII bytes (high bit clear) branchlessly: add 0x20 to bytes in
/// 'A'..='Z'. No cross-byte carry (each 7-bit byte + constant stays < 0x100).
#[inline]
fn swar_to_lower(w: u64) -> u64 {
    let hi = w & HIGHS; // preserve any high bits (non-ASCII); ASCII => 0
    let x = w & 0x7f7f_7f7f_7f7f_7f7f;
    let ge_a = x + (0x7f - 0x41 + 1) * ONES; // 0x80 bit set where byte >= 'A'
    let gt_z = x + (0x7f - 0x5a) * ONES; // 0x80 bit set where byte > 'Z'
    let is_upper = ge_a & !gt_z & HIGHS; // 0x80 where 'A'..='Z'
    (x | (is_upper >> 2)) | hi // 0x80>>2 = 0x20
}

/// SWAR ASCII case-insensitive equality (callers gate on `is_ascii()`).
#[inline]
fn swar(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i + 8 <= a.len() {
        let wa = u64::from_ne_bytes(a[i..i + 8].try_into().unwrap());
        let wb = u64::from_ne_bytes(b[i..i + 8].try_into().unwrap());
        if swar_to_lower(wa) != swar_to_lower(wb) {
            return false;
        }
        i += 8;
    }
    while i < a.len() {
        if !a[i].eq_ignore_ascii_case(&b[i]) {
            return false;
        }
        i += 1;
    }
    true
}

fn bench(c: &mut Criterion) {
    // Same-length case-variant pairs (a casefold match): differ only in case.
    let cases: [(&[u8], &[u8]); 3] = [
        (b"File_00012345", b"file_00012345"),   // 13 B
        (b"MyDocument.TXT", b"mydocument.txt"), // 14 B
        (
            b"A_Rather_Longer_DirEntry_Name.Dat",
            b"a_rather_longer_direntry_name.dat",
        ), // 33 B
    ];
    // Correctness: SWAR must match eq_ignore_ascii_case on all ASCII inputs.
    for (x, y) in &cases {
        assert_eq!(bytewise(x, y), swar(x, y), "swar disagrees on {x:?}");
        assert!(swar(x, y), "should be case-insensitively equal");
        // a genuine mismatch
        assert_eq!(bytewise(x, b"zzz"), swar(x, b"zzz"));
    }

    let mut g = c.benchmark_group("casefold_cmp");
    for (label, (x, y)) in [
        ("short_13", cases[0]),
        ("mid_14", cases[1]),
        ("long_33", cases[2]),
    ] {
        g.bench_function(format!("bytewise/{label}"), |b| {
            b.iter(|| black_box(bytewise(black_box(x), black_box(y))))
        });
        g.bench_function(format!("swar/{label}"), |b| {
            b.iter(|| black_box(swar(black_box(x), black_box(y))))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
