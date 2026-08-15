#![forbid(unsafe_code)]
//! `names_eq`'s ORIGINAL byte-wise TAIL loop (a092e533) was slow for lengths not
//! a multiple of 8 (12/13/… — common dir names): at those lengths it LOST to
//! slice `==`. The overlapping-final-word rewrite (3dcf558f-follow-up) compares
//! the last 8 bytes as one (possibly overlapping) word — no byte tail — so every
//! length >= 8 is all word-compares. A/B: LEGACY byte-tail (`names_eq_orig`) vs
//! the NEW production `names_eq` (overlap) vs slice `==`, looped 256×/iter.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench names_eq_crossover
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::ext4::names_eq;
use std::hint::black_box;

const N: usize = 256;

/// LEGACY (pre-overlap) names_eq: full words then a byte-wise tail loop.
#[inline]
fn names_eq_orig(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i + 8 <= a.len() {
        if u64::from_ne_bytes(a[i..i + 8].try_into().unwrap())
            != u64::from_ne_bytes(b[i..i + 8].try_into().unwrap())
        {
            return false;
        }
        i += 8;
    }
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

fn bench(c: &mut Criterion) {
    let sizes = [
        (11usize, "len_11"),
        (12, "len_12"),
        (13, "len_13"),
        (16, "len_16"),
        (21, "len_21"),
    ];
    let mut g = c.benchmark_group("names_eq_loop");
    for (len, label) in sizes {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..N)
            .map(|k| {
                let v: Vec<u8> = (0..len).map(|i| b'a' + ((i + k) % 26) as u8).collect();
                (v.clone(), v)
            })
            .collect();
        // NEW production names_eq is bit-identical to the legacy + to `==`.
        assert!(pairs.iter().all(|(a, b)| names_eq(a, b) == (a == b)));
        assert!(pairs.iter().all(|(a, b)| names_eq_orig(a, b) == (a == b)));

        macro_rules! run {
            ($name:expr, $f:expr) => {
                g.bench_function(format!("{}/{label}", $name), |bch| {
                    bch.iter(|| {
                        let mut acc = 0usize;
                        for (a, b) in black_box(&pairs) {
                            acc += $f(black_box(&a[..]), black_box(&b[..])) as usize;
                        }
                        black_box(acc)
                    })
                });
            };
        }
        run!("slice_eq", |a: &[u8], b: &[u8]| a == b);
        run!("orig", names_eq_orig);
        run!("new", names_eq);
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
