#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for the trusted extent-leaf search helper (bd-xmh5g.386).
//!
//! `parse_leaf_entries` already validates each leaf once: every extent has
//! nonzero length and entries are sorted/non-overlapping. The old production
//! search immediately rescanned the whole validated leaf for zero-length
//! extents before doing its `partition_point` lookup. The new production path
//! uses a private trusted helper only after that parser has succeeded, while
//! keeping the checked helper for caller-supplied parsed roots.
//!
//! This bench isolates the removed work over a full 4K ext4 extent leaf
//! (340 entries): `old_checked_zero_scan` models the old extra validation pass,
//! and `trusted_validated_no_rescan` models the new private helper.
//! It also isolates the analogous validated index-node range-prefix bound over
//! 340 child separators.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btree::SearchResult;
use ffs_ondisk::{Ext4Extent, Ext4ExtentIndex};
use std::hint::black_box;

const LEAF_ENTRIES_4K: u32 = 340;
const INDEX_ENTRY_SIZE: usize = 12;
const INDEX_STRIDE: u32 = 1024;
const PROBE_COUNT: usize = 2048;

fn actual_len(raw_len: u16) -> u16 {
    const EXT_INIT_MAX_LEN: u16 = 1_u16 << 15;
    if raw_len <= EXT_INIT_MAX_LEN {
        raw_len
    } else {
        raw_len - EXT_INIT_MAX_LEN
    }
}

fn build_full_leaf() -> Vec<Ext4Extent> {
    (0..LEAF_ENTRIES_4K)
        .map(|i| Ext4Extent {
            logical_block: i * 2,
            raw_len: 1,
            physical_start: 1_000_000 + u64::from(i),
        })
        .collect()
}

fn build_full_index() -> Vec<Ext4ExtentIndex> {
    (0..LEAF_ENTRIES_4K)
        .map(|i| Ext4ExtentIndex {
            logical_block: i * INDEX_STRIDE,
            leaf_block: 2_000_000 + u64::from(i),
        })
        .collect()
}

fn encode_index_entries(indexes: &[Ext4ExtentIndex]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(indexes.len() * INDEX_ENTRY_SIZE);
    for index in indexes {
        encoded.extend_from_slice(&index.logical_block.to_le_bytes());
        encoded.extend_from_slice(&(index.leaf_block as u32).to_le_bytes());
        encoded.extend_from_slice(&((index.leaf_block >> 32) as u16).to_le_bytes());
        encoded.extend_from_slice(&0_u16.to_le_bytes());
    }
    encoded
}

fn decode_index_entries(encoded: &[u8]) -> Vec<Ext4ExtentIndex> {
    // `as_chunks::<N>()` rather than `chunks_exact(N)` (bd-3ao0l), matching the
    // ffs-types fix in 01cf8477: with a const chunk size each item arrives as a
    // fixed-size array, so the indexing below is bounds-checked once by the type
    // rather than per access. Same split point — `as_chunks` yields the same
    // `len/N*N` prefix `chunks_exact` did, and the trailing remainder is
    // discarded here exactly as `chunks_exact` discarded it.
    let (entries, _remainder) = encoded.as_chunks::<INDEX_ENTRY_SIZE>();
    entries
        .iter()
        .map(|entry| {
            let logical_block = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let leaf_lo = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
            let leaf_hi = u16::from_le_bytes([entry[8], entry[9]]);
            Ext4ExtentIndex {
                logical_block,
                leaf_block: u64::from(leaf_lo) | (u64::from(leaf_hi) << 32),
            }
        })
        .collect()
}

fn index_insert_digest(indexes: &[Ext4ExtentIndex]) -> u64 {
    indexes
        .iter()
        .fold(0xcbf2_9ce4_8422_2325_u64, |digest, index| {
            digest
                .wrapping_mul(0x100_0000_01b3)
                .wrapping_add(u64::from(index.logical_block))
                .wrapping_mul(0x100_0000_01b3)
                .wrapping_add(index.leaf_block)
        })
}

fn index_child_pos(indexes: &[Ext4ExtentIndex], target: u32) -> usize {
    indexes
        .partition_point(|index| index.logical_block <= target)
        .saturating_sub(1)
}

fn insert_with_parent_reparse(
    encoded: &[u8],
    target: u32,
    new_entry: Ext4ExtentIndex,
) -> (u64, u64) {
    let indexes = decode_index_entries(encoded);
    let child_block = indexes[index_child_pos(&indexes, target)].leaf_block;

    let mut indexes = decode_index_entries(encoded);
    let insert_pos = indexes.partition_point(|index| index.logical_block < new_entry.logical_block);
    indexes.insert(insert_pos, new_entry);
    (child_block, index_insert_digest(&indexes))
}

fn insert_with_retained_parent(
    encoded: &[u8],
    target: u32,
    new_entry: Ext4ExtentIndex,
) -> (u64, u64) {
    let mut indexes = decode_index_entries(encoded);
    let child_block = indexes[index_child_pos(&indexes, target)].leaf_block;

    let insert_pos = indexes.partition_point(|index| index.logical_block < new_entry.logical_block);
    indexes.insert(insert_pos, new_entry);
    (child_block, index_insert_digest(&indexes))
}

fn build_probes() -> Vec<u32> {
    let max_logical = LEAF_ENTRIES_4K * 2 + 32;
    let mut x = 0x9e37_79b9_7f4a_7c15_u64;
    (0..PROBE_COUNT)
        .map(|_| {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            ((x >> 11) % u64::from(max_logical)) as u32
        })
        .collect()
}

fn trusted_validated_search(extents: &[Ext4Extent], target: u32, upper_bound: u64) -> SearchResult {
    if extents.is_empty() {
        return SearchResult::Hole {
            hole_len: upper_bound.saturating_sub(u64::from(target)),
        };
    }

    let pos = extents.partition_point(|e| e.logical_block <= target);

    if pos > 0 {
        let ext = &extents[pos - 1];
        let len = actual_len(ext.raw_len);
        let end = u64::from(ext.logical_block) + u64::from(len);
        if u64::from(target) < end {
            return SearchResult::Found {
                extent: *ext,
                offset_in_extent: target - ext.logical_block,
            };
        }
    }

    let next_start = if pos < extents.len() {
        u64::from(extents[pos].logical_block)
    } else {
        upper_bound
    };
    SearchResult::Hole {
        hole_len: next_start.saturating_sub(u64::from(target)),
    }
}

fn old_checked_search(
    extents: &[Ext4Extent],
    target: u32,
    upper_bound: u64,
) -> Option<SearchResult> {
    for ext in extents {
        if actual_len(ext.raw_len) == 0 {
            return None;
        }
    }
    Some(trusted_validated_search(extents, target, upper_bound))
}

fn visit_range_linear(extents: &[Ext4Extent], start: u64, end: u64) -> (usize, u64) {
    let mut count = 0;
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for extent in extents {
        let extent_start = u64::from(extent.logical_block);
        let extent_end = extent_start + u64::from(actual_len(extent.raw_len));
        if extent_end <= start {
            continue;
        }
        if extent_start >= end {
            break;
        }
        count += 1;
        digest = digest
            .wrapping_mul(0x100_0000_01b3)
            .wrapping_add(extent.physical_start);
    }
    (count, digest)
}

fn visit_range_partitioned(extents: &[Ext4Extent], start: u64, end: u64) -> (usize, u64) {
    let first = extents.partition_point(|extent| {
        u64::from(extent.logical_block) + u64::from(actual_len(extent.raw_len)) <= start
    });
    let mut count = 0;
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for extent in &extents[first..] {
        if u64::from(extent.logical_block) >= end {
            break;
        }
        count += 1;
        digest = digest
            .wrapping_mul(0x100_0000_01b3)
            .wrapping_add(extent.physical_start);
    }
    (count, digest)
}

fn index_range_linear(indexes: &[Ext4ExtentIndex], start: u64, end: u64) -> (usize, u64) {
    let mut count = 0;
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for (pos, index) in indexes.iter().enumerate() {
        let child_start = u64::from(index.logical_block);
        let child_end = indexes
            .get(pos + 1)
            .map_or(1_u64 << 32, |next| u64::from(next.logical_block));
        if child_end <= start {
            continue;
        }
        if child_start >= end {
            break;
        }
        count += 1;
        digest = digest
            .wrapping_mul(0x100_0000_01b3)
            .wrapping_add(index.leaf_block);
    }
    (count, digest)
}

fn index_range_partitioned(indexes: &[Ext4ExtentIndex], start: u64, end: u64) -> (usize, u64) {
    let first = indexes
        .partition_point(|index| u64::from(index.logical_block) <= start)
        .saturating_sub(1);
    let mut count = 0;
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for (offset, index) in indexes[first..].iter().enumerate() {
        let pos = first + offset;
        let child_start = u64::from(index.logical_block);
        let child_end = indexes
            .get(pos + 1)
            .map_or(1_u64 << 32, |next| u64::from(next.logical_block));
        if child_end <= start {
            continue;
        }
        if child_start >= end {
            break;
        }
        count += 1;
        digest = digest
            .wrapping_mul(0x100_0000_01b3)
            .wrapping_add(index.leaf_block);
    }
    (count, digest)
}

fn bench_leaf_search_validation(c: &mut Criterion) {
    let extents = build_full_leaf();
    let probes = build_probes();
    let upper_bound = 1_u64 << 32;

    for &target in &probes {
        let checked = old_checked_search(&extents, target, upper_bound)
            .expect("benchmark leaf is parser-validated");
        let trusted = trusted_validated_search(&extents, target, upper_bound);
        assert_eq!(checked, trusted, "leaf search model diverged at {target}");
    }

    let mut group = c.benchmark_group("extent_leaf_search_validation_ab");
    group.bench_function("old_checked_zero_scan", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &target in &probes {
                let result = old_checked_search(black_box(&extents), target, upper_bound)
                    .expect("benchmark leaf is parser-validated");
                match result {
                    SearchResult::Found { extent, .. } => {
                        acc = acc.wrapping_add(extent.physical_start);
                    }
                    SearchResult::Hole { hole_len } => acc = acc.wrapping_add(hole_len),
                }
            }
            black_box(acc)
        });
    });
    group.bench_function("trusted_validated_no_rescan", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &target in &probes {
                let result = trusted_validated_search(black_box(&extents), target, upper_bound);
                match result {
                    SearchResult::Found { extent, .. } => {
                        acc = acc.wrapping_add(extent.physical_start);
                    }
                    SearchResult::Hole { hole_len } => acc = acc.wrapping_add(hole_len),
                }
            }
            black_box(acc)
        });
    });
    group.finish();
}

fn bench_leaf_range_prefix(c: &mut Criterion) {
    let extents = build_full_leaf();
    let start = u64::from(LEAF_ENTRIES_4K * 2 * 9 / 10);
    let end = start + 8;

    for &(range_start, range_end) in &[
        (0, 1),
        (1, 2),
        (start, end),
        (
            u64::from(LEAF_ENTRIES_4K * 2),
            u64::from(LEAF_ENTRIES_4K * 2) + 8,
        ),
    ] {
        assert_eq!(
            visit_range_linear(&extents, range_start, range_end),
            visit_range_partitioned(&extents, range_start, range_end),
            "leaf range selection diverged for [{range_start}, {range_end})"
        );
    }

    let mut group = c.benchmark_group("extent_leaf_range_prefix_ab");
    group.bench_function("linear_prefix_a", |b| {
        b.iter(|| {
            black_box(visit_range_linear(
                black_box(&extents),
                black_box(start),
                black_box(end),
            ))
        });
    });
    group.bench_function("linear_prefix_b", |b| {
        b.iter(|| {
            black_box(visit_range_linear(
                black_box(&extents),
                black_box(start),
                black_box(end),
            ))
        });
    });
    group.bench_function("partitioned_prefix", |b| {
        b.iter(|| {
            black_box(visit_range_partitioned(
                black_box(&extents),
                black_box(start),
                black_box(end),
            ))
        });
    });
    group.finish();
}

fn bench_index_range_prefix(c: &mut Criterion) {
    let indexes = build_full_index();
    let start = u64::from(LEAF_ENTRIES_4K * INDEX_STRIDE * 9 / 10);
    let end = start + 8;

    for &(range_start, range_end) in &[
        (0, 1),
        (u64::from(INDEX_STRIDE - 1), u64::from(INDEX_STRIDE)),
        (u64::from(INDEX_STRIDE), u64::from(INDEX_STRIDE) + 1),
        (start, end),
        ((1_u64 << 32) - 1, 1_u64 << 32),
    ] {
        assert_eq!(
            index_range_linear(&indexes, range_start, range_end),
            index_range_partitioned(&indexes, range_start, range_end),
            "index range selection diverged for [{range_start}, {range_end})"
        );
    }
    assert_eq!(
        index_range_linear(&indexes[1..], 0, 1),
        index_range_partitioned(&indexes[1..], 0, 1),
        "index range selection diverged before the first separator"
    );

    let mut group = c.benchmark_group("extent_index_range_prefix_ab");
    group.bench_function("linear_prefix_a", |b| {
        b.iter(|| {
            black_box(index_range_linear(
                black_box(&indexes),
                black_box(start),
                black_box(end),
            ))
        });
    });
    group.bench_function("linear_prefix_b", |b| {
        b.iter(|| {
            black_box(index_range_linear(
                black_box(&indexes),
                black_box(start),
                black_box(end),
            ))
        });
    });
    group.bench_function("partitioned_prefix", |b| {
        b.iter(|| {
            black_box(index_range_partitioned(
                black_box(&indexes),
                black_box(start),
                black_box(end),
            ))
        });
    });
    group.finish();
}

fn bench_index_insert_reparse(c: &mut Criterion) {
    let encoded = encode_index_entries(&build_full_index());
    let target = 200 * INDEX_STRIDE + 1;
    let new_entry = Ext4ExtentIndex {
        logical_block: 200 * INDEX_STRIDE + INDEX_STRIDE / 2,
        leaf_block: 3_000_000,
    };

    let reparsed = insert_with_parent_reparse(&encoded, target, new_entry);
    let retained = insert_with_retained_parent(&encoded, target, new_entry);
    assert_eq!(reparsed, retained, "retained parent changed insert result");

    let mut group = c.benchmark_group("extent_index_insert_reparse_340");
    group.bench_function("reparse_parent_a", |b| {
        b.iter(|| {
            black_box(insert_with_parent_reparse(
                black_box(&encoded),
                black_box(target),
                black_box(new_entry),
            ))
        });
    });
    group.bench_function("reparse_parent_b", |b| {
        b.iter(|| {
            black_box(insert_with_parent_reparse(
                black_box(&encoded),
                black_box(target),
                black_box(new_entry),
            ))
        });
    });
    group.bench_function("retain_validated_parent", |b| {
        b.iter(|| {
            black_box(insert_with_retained_parent(
                black_box(&encoded),
                black_box(target),
                black_box(new_entry),
            ))
        });
    });
    group.finish();
}

criterion_group!(
    extent_leaf_search,
    bench_leaf_search_validation,
    bench_leaf_range_prefix,
    bench_index_range_prefix,
    bench_index_insert_reparse
);
criterion_main!(extent_leaf_search);
