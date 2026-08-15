#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
//! ⛔ REJECTED (2026-07-10, bd-cc-interp-search) — KEPT as the documented
//! characterization. Interpolation search WINS only on synthetic-uniform large
//! arrays with NO production home, and REGRESSES 2.4-2.9x on realistic
//! non-uniform (skewed) extent starts. Measured medians (worker hz1, null floor
//! binary_a-vs-binary_b ~1.02-1.04x): uniform E4096 binary 2.40µs vs interp
//! 0.69µs = 3.46x FASTER, E65536 4.85µs vs 0.73µs = 6.6x FASTER; but SKEWED
//! E4096 binary 3.45µs vs interp 10.16µs = ~2.9x SLOWER, E65536 4.85µs vs
//! 12.41µs = ~2.6x SLOWER; E256 gated → neutral. Parity byte-identical every
//! case. Production per-block resolve (`ext4_resolve_block_from_mappings`)
//! searches ONE extent leaf (≤340 extents = L1-resident) where interpolation's
//! per-probe 64-bit DIVIDE loses to binary's comparisons (no cache misses to
//! amortize), and no hot path searches a larger flattened array — so the
//! E≥4096 win has no home and the non-uniform regression is the real regime.
//! DO NOT ship interp_hybrid to production. Retry only if a non-peer hot path
//! emerges that searches a genuinely LARGE (E≥~2000, cache-miss-bound) sorted
//! array of NEAR-UNIFORM keys — which ext4's ≤340-per-leaf extent structure
//! cannot produce.
//!
//! A/B for a GENUINELY DIFFERENT search primitive on the ext4 mapping-resolution
//! hot path (`ext4_resolve_block_from_mappings`, ffs-core lib.rs:11761): the
//! current `partition_point` (branchy/cmov binary search, O(log E)) vs an
//! INTERPOLATION-hybrid (O(log log E) for near-uniform extent starts), which is
//! an algorithmic change — NOT a cache-layout one (Eytzinger's real lever is
//! software prefetch, barred by `#![forbid(unsafe_code)]`).
//!
//! Why here: for a heavily-fragmented large file the flattened `mappings` array
//! is thousands of extents (exceeds L2), and RANDOM warm reads binary-search it
//! per block (sequential reads already resolve O(1) via the bd-vpypn hint). At
//! E in the thousands each `partition_point` is ~log2(E) cache-missing probes.
//! Interpolation narrows the range in ~log log E probes for near-uniform starts.
//!
//! SAFETY OF PARITY: `interp_hybrid_pp` returns byte-identically to
//! `partition_point`: it only ever narrows [lo, hi) preserving the invariant
//! "every index < lo has start <= target, every index >= hi has start > target"
//! (each probe compares and moves the guaranteed-safe bound), then a residual
//! `partition_point` over [lo, hi) yields the exact same count. Size-gated:
//! E <= 256 falls straight through to `partition_point` (no common-case cost;
//! real files are 1-few extents).
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench extent_search_large
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const INTERP_GATE: usize = 256;
const MAX_INTERP_STEPS: usize = 6;
const INTERP_RESIDUAL: usize = 32;

/// Current production form: last index with `start <= target` = partition_point.
#[inline]
fn binary_pp(starts: &[u32], target: u32) -> usize {
    starts.partition_point(|&s| s <= target)
}

/// Interpolation-hybrid: a few interpolation probes to narrow [lo, hi), then a
/// residual `partition_point`. Byte-identical to `binary_pp` (see module docs).
#[inline]
fn interp_hybrid_pp(starts: &[u32], target: u32) -> usize {
    let n = starts.len();
    if n <= INTERP_GATE {
        return starts.partition_point(|&s| s <= target);
    }
    let mut lo = 0usize; // every index < lo has start <= target
    let mut hi = n; // every index >= hi has start > target
    let mut steps = 0;
    while hi - lo > INTERP_RESIDUAL && steps < MAX_INTERP_STEPS {
        let slo = starts[lo];
        let shi = starts[hi - 1];
        if target < slo {
            hi = lo;
            break;
        }
        if target >= shi {
            lo = hi;
            break;
        }
        let span = u64::from(shi - slo);
        let pos_off = (u64::from(target - slo) * (hi - 1 - lo) as u64) / span;
        let mut probe = lo + pos_off as usize;
        if probe <= lo {
            probe = lo + 1;
        }
        if probe >= hi {
            probe = hi - 1;
        }
        if starts[probe] <= target {
            lo = probe + 1;
        } else {
            hi = probe;
        }
        steps += 1;
    }
    lo + starts[lo..hi].partition_point(|&s| s <= target)
}

// UNIFORM extent starts: every extent covers `stride` blocks (best case for
// interpolation — perfectly linear starts).
fn make_uniform(e: usize) -> Vec<u32> {
    (0..e as u32).map(|i| i * 4).collect()
}

// SKEWED extent starts: a few huge extents then many tiny ones (interpolation's
// adversarial case — verifies the hybrid degrades to ~binary, no big regression).
fn make_skewed(e: usize) -> Vec<u32> {
    let mut v = Vec::with_capacity(e);
    let mut cur = 0u32;
    for i in 0..e as u32 {
        v.push(cur);
        // first 1/8 of extents are huge (stride 4096), rest tiny (stride 1)
        cur += if i < (e as u32) / 8 { 4096 } else { 1 };
    }
    v
}

// A deterministic spread of query targets across the covered range (no RNG in
// benches). Uses an LCG-style stride coprime with the range for good coverage.
fn make_targets(starts: &[u32], count: usize) -> Vec<u32> {
    let max = *starts.last().unwrap();
    let stride = 2_654_435_761u64; // Knuth multiplicative
    (0..count as u64)
        .map(|i| ((i.wrapping_mul(stride)) % u64::from(max + 1)) as u32)
        .collect()
}

fn run_batch(f: impl Fn(&[u32], u32) -> usize, starts: &[u32], targets: &[u32]) -> u64 {
    let mut acc = 0u64;
    for &t in targets {
        acc = acc.wrapping_add(f(starts, t) as u64);
    }
    acc
}

fn bench(c: &mut Criterion) {
    for (label, genf) in [
        ("uniform", make_uniform as fn(usize) -> Vec<u32>),
        ("skewed", make_skewed as fn(usize) -> Vec<u32>),
    ] {
        for &e in &[256usize, 4096, 65536] {
            let starts = genf(e);
            let targets = make_targets(&starts, 256);
            // Byte-identical parity for EVERY target.
            for &t in &targets {
                assert_eq!(
                    binary_pp(&starts, t),
                    interp_hybrid_pp(&starts, t),
                    "parity mismatch {label} E={e} target={t}"
                );
            }
            let mut g = c.benchmark_group(format!("mapping_search_{label}_e{e}"));
            // NULL CONTROL: partition_point registered twice; its ratio is the
            // noise floor. Any interp-vs-binary gap below binary-vs-binary is noise.
            g.bench_function("binary_a", |b| {
                b.iter(|| {
                    black_box(run_batch(
                        binary_pp,
                        black_box(&starts),
                        black_box(&targets),
                    ))
                });
            });
            g.bench_function("binary_b", |b| {
                b.iter(|| {
                    black_box(run_batch(
                        binary_pp,
                        black_box(&starts),
                        black_box(&targets),
                    ))
                });
            });
            g.bench_function("interp_hybrid", |b| {
                b.iter(|| {
                    black_box(run_batch(
                        interp_hybrid_pp,
                        black_box(&starts),
                        black_box(&targets),
                    ))
                });
            });
            g.finish();
        }
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
