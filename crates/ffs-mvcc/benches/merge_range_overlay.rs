#![forbid(unsafe_code)]

//! Same-binary A/B for the `RangeOverlay` merge validator (the byte algorithm
//! behind `MergeProof::{IndependentKeys,NonOverlappingExtents,TimestampOnlyInode}`).
//!
//! This runs on the contended commit path: when two transactions write
//! non-overlapping ranges of the *same* block (e.g. concurrent `write()`s to
//! disjoint offsets of one 4 KiB data block, which stage a
//! `non_overlapping_extent_range` proof), the second committer hits an FCW
//! conflict and merges under the shard lock. The validator must confirm the
//! staged block only modified the declared ranges.
//!
//! The old validator materialized a full-block `expected_staged = base.to_vec()`,
//! overlaid the declared ranges, and compared the whole buffer to `staged` — one
//! block-sized allocation + copy + full compare per merge. The equivalent check
//! is "`staged` equals `base` in the *complement* of the declared ranges", which
//! compares only the gaps and needs no scratch buffer. Both variants below are
//! faithful transcriptions of the two source implementations; the A/B isolates
//! the eliminated allocation + copy. The merge output (`latest` with the staged
//! ranges overlaid) is identical in both, so this benches only the validator.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ffs_mvcc::MergeByteRange;
use std::hint::black_box;

/// OLD validator: build `expected_staged` from `base`, overlay declared ranges,
/// compare the whole buffer to `staged`. Returns the merged block or `None`.
fn merge_old(
    touched: &[MergeByteRange],
    base: &[u8],
    latest: &[u8],
    staged: &[u8],
) -> Option<Vec<u8>> {
    if latest.len() != base.len() || staged.len() != base.len() {
        return None;
    }
    // (disjointness is checked by the caller in both variants; omitted here so
    // the A/B measures only the validate+overlay work that actually differs)
    let mut expected_staged = base.to_vec();
    for range in touched {
        if range.start.saturating_add(range.len) > base.len() {
            return None;
        }
        let end = range.start + range.len;
        expected_staged[range.start..end].copy_from_slice(&staged[range.start..end]);
    }
    if expected_staged != staged {
        return None;
    }
    let mut merged = latest.to_vec();
    for range in touched {
        let end = range.start + range.len;
        if latest[range.start..end] != base[range.start..end] {
            return None;
        }
        merged[range.start..end].copy_from_slice(&staged[range.start..end]);
    }
    Some(merged)
}

/// NEW validator: compare `staged` vs `base` only in the complement of the
/// declared ranges (no scratch buffer). Faithful copy of the source change.
fn merge_new(
    touched: &[MergeByteRange],
    base: &[u8],
    latest: &[u8],
    staged: &[u8],
) -> Option<Vec<u8>> {
    if latest.len() != base.len() || staged.len() != base.len() {
        return None;
    }
    for range in touched {
        if range.start.saturating_add(range.len) > base.len() {
            return None;
        }
    }
    let mut ordered: smallvec::SmallVec<[MergeByteRange; 1]> = touched.iter().copied().collect();
    ordered.sort_unstable_by_key(|range| range.start);
    let mut cursor = 0usize;
    for range in &ordered {
        if staged[cursor..range.start] != base[cursor..range.start] {
            return None;
        }
        cursor = range.start + range.len;
    }
    if staged[cursor..] != base[cursor..] {
        return None;
    }
    let mut merged = latest.to_vec();
    for range in touched {
        let end = range.start + range.len;
        if latest[range.start..end] != base[range.start..end] {
            return None;
        }
        merged[range.start..end].copy_from_slice(&staged[range.start..end]);
    }
    Some(merged)
}

/// VALIDATE-ONLY: the same checks as `merge_new` but WITHOUT building the merged
/// block — what the FCW *preflight* now runs (it only needs a yes/no answer; the
/// merged block is (re)built at install). Faithful copy of `merge_valid`'s range
/// path. The eliminated `latest.to_vec()` + overlay is the preflight saving.
fn validate_new(touched: &[MergeByteRange], base: &[u8], latest: &[u8], staged: &[u8]) -> bool {
    if latest.len() != base.len() || staged.len() != base.len() {
        return false;
    }
    for range in touched {
        if range.start.saturating_add(range.len) > base.len() {
            return false;
        }
    }
    let mut ordered: smallvec::SmallVec<[MergeByteRange; 1]> = touched.iter().copied().collect();
    ordered.sort_unstable_by_key(|range| range.start);
    let mut cursor = 0usize;
    for range in &ordered {
        if staged[cursor..range.start] != base[cursor..range.start] {
            return false;
        }
        cursor = range.start + range.len;
    }
    if staged[cursor..] != base[cursor..] {
        return false;
    }
    for range in touched {
        let end = range.start + range.len;
        if latest[range.start..end] != base[range.start..end] {
            return false;
        }
    }
    true
}

/// Build a merge scenario for a block of `bs` bytes: `staged` modifies one
/// declared range near the start; `latest` modifies a disjoint range near the
/// end (a clean, mergeable conflict — the common case).
fn scenario(bs: usize) -> (Vec<MergeByteRange>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let range_len = 256.min(bs / 4); // ~ one inode slot / small extent tail
    let touched = vec![MergeByteRange::new(0, range_len)];
    let base = vec![0_u8; bs];
    let mut staged = base.clone();
    for (i, b) in staged[0..range_len].iter_mut().enumerate() {
        *b = u8::try_from(i % 256).expect("modulo 256 fits a u8") | 1;
    }
    let mut latest = base.clone();
    for b in &mut latest[bs - range_len..] {
        *b = 0xAB;
    }
    (touched, base, latest, staged)
}

fn bench_merge(c: &mut Criterion) {
    // Scoped so the group is dropped at the end of the block rather than the fn.
    {
        let mut group = c.benchmark_group("mvcc_range_overlay_merge");
        for bs in [4096_usize, 16384, 65536] {
            let (touched, base, latest, staged) = scenario(bs);
            // Sanity: both variants agree on this input.
            assert_eq!(
                merge_old(&touched, &base, &latest, &staged),
                merge_new(&touched, &base, &latest, &staged),
            );
            group.bench_with_input(BenchmarkId::new("old_expected_copy", bs), &bs, |b, _| {
                b.iter(|| {
                    black_box(merge_old(
                        black_box(&touched),
                        black_box(&base),
                        black_box(&latest),
                        black_box(&staged),
                    ))
                });
            });
            group.bench_with_input(BenchmarkId::new("new_complement", bs), &bs, |b, _| {
                b.iter(|| {
                    black_box(merge_new(
                        black_box(&touched),
                        black_box(&base),
                        black_box(&latest),
                        black_box(&staged),
                    ))
                });
            });
        }
        group.finish();
    }

    // FCW-preflight A/B: the preflight used to run the FULL merge (build the
    // merged block, then discard it) just to decide "mergeable?"; it now runs
    // validate-only (no merged-output allocation). Same yes/no answer.
    let mut pf = c.benchmark_group("mvcc_merge_preflight");
    for bs in [4096_usize, 16384, 65536] {
        let (touched, base, latest, staged) = scenario(bs);
        assert!(validate_new(&touched, &base, &latest, &staged));
        assert!(merge_new(&touched, &base, &latest, &staged).is_some());
        pf.bench_with_input(BenchmarkId::new("full_merge_discarded", bs), &bs, |b, _| {
            b.iter(|| {
                black_box(
                    merge_new(
                        black_box(&touched),
                        black_box(&base),
                        black_box(&latest),
                        black_box(&staged),
                    )
                    .is_some(),
                )
            });
        });
        pf.bench_with_input(BenchmarkId::new("validate_only", bs), &bs, |b, _| {
            b.iter(|| {
                black_box(validate_new(
                    black_box(&touched),
                    black_box(&base),
                    black_box(&latest),
                    black_box(&staged),
                ))
            });
        });
    }
    pf.finish();
}

criterion_group!(merge_range_overlay, bench_merge);
criterion_main!(merge_range_overlay);
