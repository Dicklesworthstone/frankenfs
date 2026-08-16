#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/Bs for recovery orchestration primitives.
//!
//! `RecoverySession::build_writeback_blocks` maps each recovered block back to
//! its scrub-time "expected current" bytes. The old code did this with an
//! `expected_current.iter().find(|(block, _)| *block == recovered.block)` — an
//! O(N) linear scan run once per recovered block (M of them), i.e. O(M·N) which
//! is ~O(N²) when most corrupt blocks are recovered.
//!
//! `expected_current` is built from the NORMALIZED corrupt indices
//! (`normalize_indices` does `sort_unstable` + `dedup`) with
//! `block = source_first_block + index`, so it is strictly ascending and unique
//! by block number. The new code binary-searches it, turning the per-recovery
//! cost into O(M·log N).
//!
//! This bench isolates that lookup: build a sorted/unique `expected_current` of
//! N (block, bytes) pairs and M recovered block numbers, then resolve every
//! recovered block via linear `find` vs `binary_search_by_key`. Both produce the
//! identical resolved bytes in the identical order (asserted).

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const BLOCK: usize = 4096; // expected-current payload size (bytes)

/// Deterministic pseudo-random byte (no `Math.random` in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

/// Sorted, unique `(block, bytes)` pairs — mirrors `capture_expected_current_blocks`
/// fed normalized (sorted + deduped) indices, `block = first + index`.
fn build_expected(n: usize) -> Vec<(u64, Vec<u8>)> {
    (0..n)
        .map(|i| {
            let block = 1_000 + i as u64; // strictly ascending, unique
            let bytes = (0..BLOCK)
                .map(|b| prng((i as u64) << 20 ^ b as u64))
                .collect();
            (block, bytes)
        })
        .collect()
}

/// The M recovered block numbers to resolve. Decode order is not sorted (it
/// follows the symbol-recovery order), so spread the lookups across the range.
fn build_recovered(n: usize) -> Vec<u64> {
    (0..n)
        .map(|i| {
            // Pseudo-shuffled index in [0, n) so lookups are not sequential.
            let j = (i.wrapping_mul(2_654_435_761)) % n;
            1_000 + j as u64
        })
        .collect()
}

/// OLD: linear scan per recovered block — O(M·N).
fn resolve_linear<'a>(expected: &'a [(u64, Vec<u8>)], recovered: &[u64]) -> Vec<&'a [u8]> {
    recovered
        .iter()
        .map(|&blk| {
            let (_, bytes) = expected
                .iter()
                .find(|(block, _)| *block == blk)
                .expect("block present");
            bytes.as_slice()
        })
        .collect()
}

/// NEW: binary search per recovered block — O(M·log N).
fn resolve_binary<'a>(expected: &'a [(u64, Vec<u8>)], recovered: &[u64]) -> Vec<&'a [u8]> {
    recovered
        .iter()
        .map(|&blk| {
            let idx = expected
                .binary_search_by_key(&blk, |(block, _)| *block)
                .expect("block present");
            expected[idx].1.as_slice()
        })
        .collect()
}

/// Candidate: use the shared normalized ordinal first, retaining the binary
/// search for behavior parity if a caller supplies an unexpected order.
fn resolve_ordinal_or_binary<'a>(
    expected: &'a [(u64, Vec<u8>)],
    recovered: &[u64],
) -> Vec<&'a [u8]> {
    recovered
        .iter()
        .enumerate()
        .map(|(position, &blk)| {
            if let Some((expected_block, bytes)) = expected.get(position)
                && *expected_block == blk
            {
                return bytes.as_slice();
            }
            let idx = expected
                .binary_search_by_key(&blk, |(block, _)| *block)
                .expect("block present");
            expected[idx].1.as_slice()
        })
        .collect()
}

fn bench_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("recovery_build_writeback_blocks");
    for &n in &[64_usize, 512, 4096] {
        let expected = build_expected(n);
        let recovered = build_recovered(n); // M = N (full recovery)

        // Isomorphism: both strategies resolve the identical bytes in order.
        assert_eq!(
            resolve_linear(&expected, &recovered),
            resolve_binary(&expected, &recovered),
            "binary-search lookup diverged from linear find (n={n})"
        );

        group.bench_with_input(BenchmarkId::new("linear_find", n), &n, |b, _| {
            b.iter(|| black_box(resolve_linear(black_box(&expected), black_box(&recovered))));
        });
        group.bench_with_input(BenchmarkId::new("binary_search", n), &n, |b, _| {
            b.iter(|| black_box(resolve_binary(black_box(&expected), black_box(&recovered))));
        });
    }
    group.finish();
}

fn bench_ordered_pairing(c: &mut Criterion) {
    const N: usize = 4_096;
    let expected = build_expected(N);
    let recovered: Vec<u64> = expected.iter().map(|(block, _)| *block).collect();
    let shuffled = build_recovered(N);

    assert_eq!(
        resolve_binary(&expected, &recovered),
        resolve_ordinal_or_binary(&expected, &recovered),
        "ordered recovery pairing changed resolved bytes"
    );
    assert_eq!(
        resolve_binary(&expected, &shuffled),
        resolve_ordinal_or_binary(&expected, &shuffled),
        "fallback recovery pairing changed reordered output"
    );

    let mut group = c.benchmark_group("recovery_writeback_ordered_pairing_4096");
    group.bench_function("binary_search_control_a", |b| {
        b.iter(|| black_box(resolve_binary(black_box(&expected), black_box(&recovered))));
    });
    group.bench_function("binary_search_control_b", |b| {
        b.iter(|| black_box(resolve_binary(black_box(&expected), black_box(&recovered))));
    });
    group.bench_function("ordinal_or_binary", |b| {
        b.iter(|| {
            black_box(resolve_ordinal_or_binary(
                black_box(&expected),
                black_box(&recovered),
            ))
        });
    });
    group.finish();
}

const ABSOLUTE_SOURCE_START: u64 = 1_000_000;
const ABSOLUTE_SOURCE_BLOCKS: u32 = 8_192;

fn normalize_indices(indices: &mut Vec<u32>, source_block_count: u32) -> Result<(), &'static str> {
    indices.sort_unstable();
    indices.dedup();
    if indices.iter().any(|&idx| idx >= source_block_count) {
        return Err("outside source range");
    }
    Ok(())
}

fn map_absolute_blocks(corrupt_blocks: &[u64]) -> Result<Vec<u32>, &'static str> {
    let end = ABSOLUTE_SOURCE_START + u64::from(ABSOLUTE_SOURCE_BLOCKS);
    let mut indices = Vec::with_capacity(corrupt_blocks.len());
    for &block in corrupt_blocks {
        if block < ABSOLUTE_SOURCE_START || block >= end {
            return Err("outside source range");
        }
        indices.push(
            u32::try_from(block - ABSOLUTE_SOURCE_START).map_err(|_| "index does not fit u32")?,
        );
    }
    normalize_indices(&mut indices, ABSOLUTE_SOURCE_BLOCKS)?;
    Ok(indices)
}

// The clone is NOT removable: this arm exists to measure the legacy path's
// extra copy, so deleting it would delete the thing being benchmarked.
#[expect(
    clippy::redundant_clone,
    reason = "the extra copy is the measured work"
)]
fn legacy_double_normalize(corrupt_blocks: &[u64]) -> Result<Vec<u32>, &'static str> {
    let indices = map_absolute_blocks(corrupt_blocks)?;
    let mut normalized = indices.clone();
    normalize_indices(&mut normalized, ABSOLUTE_SOURCE_BLOCKS)?;
    Ok(normalized)
}

fn owned_normalized_handoff(corrupt_blocks: &[u64]) -> Result<Vec<u32>, &'static str> {
    map_absolute_blocks(corrupt_blocks)
}

fn bench_absolute_recovery_normalization_handoff(c: &mut Criterion) {
    let cases = [
        Vec::new(),
        vec![ABSOLUTE_SOURCE_START],
        vec![
            ABSOLUTE_SOURCE_START + 4,
            ABSOLUTE_SOURCE_START,
            ABSOLUTE_SOURCE_START + 4,
            ABSOLUTE_SOURCE_START + 1,
        ],
        vec![ABSOLUTE_SOURCE_START - 1],
        vec![ABSOLUTE_SOURCE_START + u64::from(ABSOLUTE_SOURCE_BLOCKS)],
    ];
    for corrupt_blocks in &cases {
        assert_eq!(
            legacy_double_normalize(corrupt_blocks),
            owned_normalized_handoff(corrupt_blocks),
            "absolute recovery normalization handoff diverged for {corrupt_blocks:?}"
        );
    }

    let corrupt_blocks: Vec<u64> = (0..4_096_u64)
        .map(|idx| ABSOLUTE_SOURCE_START + idx)
        .collect();
    assert_eq!(
        legacy_double_normalize(&corrupt_blocks),
        owned_normalized_handoff(&corrupt_blocks)
    );

    let mut group = c.benchmark_group("recovery_absolute_indices_double_normalize_ab_4096");
    group.bench_function("legacy_double_normalize_a", |b| {
        b.iter(|| black_box(legacy_double_normalize(black_box(&corrupt_blocks))));
    });
    group.bench_function("legacy_double_normalize_b", |b| {
        b.iter(|| black_box(legacy_double_normalize(black_box(&corrupt_blocks))));
    });
    group.bench_function("owned_normalized_handoff", |b| {
        b.iter(|| black_box(owned_normalized_handoff(black_box(&corrupt_blocks))));
    });
    group.finish(); // ubs:ignore — Criterion finalization; no security token generation.
}

criterion_group!(
    benches,
    bench_lookup,
    bench_ordered_pairing,
    bench_absolute_recovery_normalization_handoff
);
criterion_main!(benches);
