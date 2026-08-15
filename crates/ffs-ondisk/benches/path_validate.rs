#![forbid(unsafe_code)]
//! Path-component validation scan: every lookup/create/delete/rename validates
//! its name component rejects '/' and NUL. The production check does TWO separate
//! `slice::contains` passes (one per byte); a SWAR one-pass checks 8 bytes at a
//! time for EITHER byte via the classic has-zero-byte trick
//! (`haszero(w) | haszero(w ^ broadcast('/'))`). This isolates that primitive.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench path_validate
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

/// Production form: two independent `contains` scans.
#[inline]
fn contains_two_pass(name: &[u8]) -> bool {
    name.contains(&b'/') || name.contains(&0)
}

const ONES: u64 = 0x0101_0101_0101_0101;
const HIGHS: u64 = 0x8080_8080_8080_8080;
const SLASH: u64 = 0x2F2F_2F2F_2F2F_2F2F;

#[inline]
fn haszero(v: u64) -> u64 {
    v.wrapping_sub(ONES) & !v & HIGHS
}

/// SWAR one-pass: word-at-a-time check for '/' or NUL.
#[inline]
fn swar_one_pass(name: &[u8]) -> bool {
    let mut i = 0;
    while i + 8 <= name.len() {
        let w = u64::from_le_bytes(name[i..i + 8].try_into().unwrap());
        if (haszero(w) | haszero(w ^ SLASH)) != 0 {
            return true;
        }
        i += 8;
    }
    while i < name.len() {
        let b = name[i];
        if b == b'/' || b == 0 {
            return true;
        }
        i += 1;
    }
    false
}

fn bench(c: &mut Criterion) {
    // Representative names: the common short numbered name, a max-length name,
    // and a mid-length one — all VALID (the hot path: no '/' or NUL, scan to end).
    let short = b"cb_00000001".to_vec(); // 11 bytes
    let mid = b"longer_filename_00042.dat".to_vec(); // 25 bytes
    let long = vec![b'x'; 255];

    // sanity: agree on valid + invalid
    for n in [&short, &mid, &long] {
        assert_eq!(contains_two_pass(n), swar_one_pass(n));
    }
    assert!(swar_one_pass(b"a/b") && swar_one_pass(b"a\0b") && !swar_one_pass(b"abc"));

    let mut g = c.benchmark_group("path_validate");
    for (label, n) in [("short_11", &short), ("mid_25", &mid), ("long_255", &long)] {
        g.bench_with_input(format!("two_pass/{label}"), n, |b, n| {
            b.iter(|| black_box(contains_two_pass(black_box(n))));
        });
        g.bench_with_input(format!("swar/{label}"), n, |b, n| {
            b.iter(|| black_box(swar_one_pass(black_box(n))));
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
