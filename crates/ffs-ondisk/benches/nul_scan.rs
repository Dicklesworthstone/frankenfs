#![forbid(unsafe_code)]
//! Find-first-NUL for symlink-target trimming (`read_symlink`). The production
//! form was `buf.iter().position(|&b| b == 0)` (byte-by-byte); the SWAR form
//! finds the first zero 8 bytes/iter via the has-zero-byte trick. A slow-symlink
//! buffer (up to PATH_MAX) with no NUL scans to the end — the big-win case.
//! A/B on a short path (fast symlink) and a long / no-NUL buffer (slow symlink).
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench nul_scan
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

#[inline]
fn bytewise(buf: &[u8]) -> Option<usize> {
    buf.iter().position(|&b| b == 0)
}

const ONES: u64 = 0x0101_0101_0101_0101;
const HIGHS: u64 = 0x8080_8080_8080_8080;

#[inline]
fn swar(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 8 <= buf.len() {
        let w = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        let z = w.wrapping_sub(ONES) & !w & HIGHS;
        if z != 0 {
            return Some(i + (z.trailing_zeros() / 8) as usize);
        }
        i += 8;
    }
    while i < buf.len() {
        if buf[i] == 0 {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn bench(c: &mut Criterion) {
    // Fast symlink: 60-byte inline area, ~30-byte relative path then NULs.
    let mut short = [0u8; 60];
    short[..30].copy_from_slice(b"../../usr/lib/x86_64/libfoo.so\0"[..30].as_ref());
    // Slow symlink: 256-byte buffer, NUL near the end.
    let mut long = vec![b'a'; 256];
    long[250] = 0;
    // Slow symlink worst case: no NUL, scan to the end.
    let none = vec![b'a'; 256];

    // sanity: agree
    assert_eq!(bytewise(&short), swar(&short));
    assert_eq!(bytewise(&long), swar(&long));
    assert_eq!(bytewise(&none), swar(&none));

    let mut g = c.benchmark_group("nul_scan");
    for (label, buf) in [
        ("short_60", &short[..]),
        ("long_256", &long[..]),
        ("none_256", &none[..]),
    ] {
        g.bench_with_input(format!("bytewise/{label}"), buf, |b, buf| {
            b.iter(|| black_box(bytewise(black_box(buf))))
        });
        g.bench_with_input(format!("swar/{label}"), buf, |b, buf| {
            b.iter(|| black_box(swar(black_box(buf))))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
