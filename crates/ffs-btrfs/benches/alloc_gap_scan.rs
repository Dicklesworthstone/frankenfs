#![forbid(unsafe_code)]

//! Same-process A/B for binary-searching `alloc_extent`'s forward gap scan
//! (bd-8fbka).
//!
//! `alloc_extent` searches `allocated_ranges` (sorted ascending by start,
//! non-overlapping) for the first gap `>= num_bytes` at or after a cursor that
//! starts at `bg_start + alloc_offset`. `alloc_offset` is a bump pointer that
//! advances past prior allocations, so during a sequential fill the cursor sits
//! near the end of the range list and every allocation re-walks O(E) extents
//! below it that are pure no-ops. Because `ext_end` is monotonic over the
//! sorted, non-overlapping list, a `partition_point` skips that no-op prefix,
//! turning each allocation into O(log E + tail).
//!
//! Benches the steady-state sequential-fill case: a full E-extent block group
//! with the cursor just past the last extent (the next bump-pointer allocation).
//! OLD scans from index 0; NEW partition_points to the suffix. Same answer
//! (asserted across several cursor positions).

use criterion::Criterion;
use ffs_btrfs::{
    BTRFS_BLOCK_GROUP_DATA, BTRFS_CHUNK_TREE_OBJECTID, BTRFS_CSUM_TREE_OBJECTID,
    BTRFS_EXTENT_TREE_OBJECTID, BTRFS_FS_TREE_OBJECTID, BTRFS_ITEM_EXTENT_ITEM,
    BTRFS_ITEM_METADATA_ITEM, BTRFS_ITEM_TREE_BLOCK_REF, BTRFS_ROOT_TREE_OBJECTID,
    BlockGroupFreeSpace, BtrfsBTree, BtrfsBlockGroupItem, BtrfsExtentAllocator, BtrfsKey,
    ExtentAllocation, ExtentKey,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

const E: usize = 4096; // extents already allocated in the block group
const EXT_SIZE: u64 = 16_384; // 16 KiB per extent (nodesize-ish)
const BG_START: u64 = 1 << 30;
const NUM_BYTES: u64 = 4096; // a one-page allocation request
const RECLAIM_ROUNDS: usize = 31;
const RECLAIM_MIN_OF: usize = 3;
const RECLAIM_MIN_SAMPLE_NS: u64 = 2_000_000;
const RECLAIM_BOOTSTRAP_RESAMPLES: usize = 20_000;
const RECLAIM_BOOTSTRAP_SEED: u64 = 0xF15A_1A11_2026_0727;
const MIN_RECLAIM_SAVED_FRACTION: f64 = 0.05;

/// Densely-packed allocated ranges: [BG_START, BG_START+EXT_SIZE),
/// [BG_START+EXT_SIZE, ...), ... — sorted, non-overlapping, no internal gaps
/// (worst case: the only gap is after the last extent).
fn build_ranges() -> Vec<(u64, u64)> {
    (0..E)
        .map(|i| (BG_START + i as u64 * EXT_SIZE, EXT_SIZE))
        .collect()
}

fn bg_end() -> u64 {
    BG_START + (E as u64 + 16) * EXT_SIZE
}

/// OLD: linear scan from index 0.
fn old_scan(ranges: &[(u64, u64)], mut cursor: u64, num_bytes: u64, bg_end: u64) -> Option<u64> {
    for &(ext_start, ext_size) in ranges {
        let ext_end = ext_start + ext_size;
        if cursor < ext_start && ext_start - cursor >= num_bytes {
            return Some(cursor);
        }
        if ext_end > cursor {
            cursor = ext_end;
        }
    }
    if cursor + num_bytes <= bg_end {
        return Some(cursor);
    }
    None
}

/// NEW: binary-search past the no-op prefix, then scan the suffix.
fn new_scan(ranges: &[(u64, u64)], mut cursor: u64, num_bytes: u64, bg_end: u64) -> Option<u64> {
    let start = ranges.partition_point(|&(s, sz)| s + sz <= cursor);
    for &(ext_start, ext_size) in &ranges[start..] {
        let ext_end = ext_start + ext_size;
        if cursor < ext_start && ext_start - cursor >= num_bytes {
            return Some(cursor);
        }
        if ext_end > cursor {
            cursor = ext_end;
        }
    }
    if cursor + num_bytes <= bg_end {
        return Some(cursor);
    }
    None
}

fn bench_alloc_gap_scan(c: &mut Criterion) {
    let ranges = build_ranges();
    let end = bg_end();
    // Steady-state cursor: just past the last allocated extent.
    let cursor = BG_START + E as u64 * EXT_SIZE;

    // Isomorphism across several cursor positions (start, middle, end, inside a
    // gap-free region).
    for probe in [
        BG_START,
        BG_START + (E as u64 / 2) * EXT_SIZE,
        cursor,
        BG_START + (E as u64 / 4) * EXT_SIZE + 1,
    ] {
        assert_eq!(
            old_scan(&ranges, probe, NUM_BYTES, end),
            new_scan(&ranges, probe, NUM_BYTES, end),
            "scan diverged at cursor {probe}"
        );
    }

    let mut group = c.benchmark_group("alloc_gap_scan_seqfill_4096ext");
    group.bench_function("linear_from_zero", |b| {
        b.iter(|| black_box(old_scan(black_box(&ranges), cursor, NUM_BYTES, end)));
    });
    group.bench_function("partition_point_suffix", |b| {
        b.iter(|| black_box(new_scan(black_box(&ranges), cursor, NUM_BYTES, end)));
    });
    group.finish();
}

fn build_largest_free_allocator() -> BtrfsExtentAllocator {
    let mut alloc = BtrfsExtentAllocator::new(7).expect("allocator");
    alloc.add_block_group(
        BG_START,
        BtrfsBlockGroupItem {
            total_bytes: (E as u64 + 16) * EXT_SIZE,
            used_bytes: E as u64 * EXT_SIZE,
            flags: BTRFS_BLOCK_GROUP_DATA,
        },
    );
    for i in 0..E as u64 {
        alloc
            .insert_data_extent_item(BG_START + i * EXT_SIZE, EXT_SIZE, 5, 256, i * EXT_SIZE, 7)
            .expect("insert data extent item");
    }
    alloc
}

fn legacy_allocated_ranges(alloc: &BtrfsExtentAllocator) -> Vec<(u64, u64)> {
    let total_bytes = (E as u64 + 16) * EXT_SIZE;
    let end = bg_end();
    let range_start = BtrfsKey {
        objectid: BG_START,
        item_type: BTRFS_ITEM_EXTENT_ITEM,
        offset: 0,
    };
    let range_end = BtrfsKey {
        objectid: end,
        item_type: BTRFS_ITEM_METADATA_ITEM,
        offset: u64::MAX,
    };
    let mut allocated_ranges = Vec::new();
    let mut materialized_used = 0_u64;
    for (key, _) in alloc
        .extent_tree()
        .range(&range_start, &range_end)
        .expect("bench extent range")
    {
        if key.objectid >= end {
            break;
        }
        if !matches!(
            key.item_type,
            BTRFS_ITEM_EXTENT_ITEM | BTRFS_ITEM_METADATA_ITEM
        ) {
            continue;
        }
        let extent_start = key.objectid.max(BG_START);
        let extent_end = key
            .objectid
            .checked_add(key.offset)
            .expect("bench extent end")
            .min(end);
        if extent_start < extent_end {
            materialized_used = materialized_used
                .checked_add(extent_end - extent_start)
                .expect("bench materialized bytes");
            allocated_ranges.push((extent_start, extent_end));
        }
    }

    let used_bytes = E as u64 * EXT_SIZE;
    let untracked_used = used_bytes
        .saturating_sub(materialized_used)
        .min(total_bytes);
    if untracked_used > 0 {
        allocated_ranges.push((BG_START, BG_START + untracked_used));
    }
    allocated_ranges.sort_unstable_by_key(|&(start, end)| (start, end));
    allocated_ranges
}

fn legacy_largest_free_extent(alloc: &BtrfsExtentAllocator) -> u64 {
    let mut cursor = BG_START;
    let mut group_best = 0_u64;
    for (extent_start, extent_end) in legacy_allocated_ranges(alloc) {
        if extent_end <= cursor {
            continue;
        }
        if cursor < extent_start {
            group_best = group_best.max(extent_start - cursor);
        }
        cursor = extent_end;
    }
    let end = bg_end();
    if cursor < end {
        group_best = group_best.max(end - cursor);
    }
    group_best.min(16 * EXT_SIZE)
}

fn legacy_free_space_extents(alloc: &BtrfsExtentAllocator) -> Vec<BlockGroupFreeSpace> {
    let mut free_ranges = Vec::new();
    let mut cursor = BG_START;
    for (extent_start, extent_end) in legacy_allocated_ranges(alloc) {
        if extent_end <= cursor {
            continue;
        }
        if cursor < extent_start {
            free_ranges.push((cursor, extent_start - cursor));
        }
        cursor = extent_end;
    }
    let end = bg_end();
    if cursor < end {
        free_ranges.push((cursor, end - cursor));
    }
    vec![BlockGroupFreeSpace {
        start: BG_START,
        total_bytes: (E as u64 + 16) * EXT_SIZE,
        flags: BTRFS_BLOCK_GROUP_DATA,
        free_ranges,
    }]
}

fn bench_largest_free_extent(c: &mut Criterion) {
    let alloc = build_largest_free_allocator();
    let expected = 16 * EXT_SIZE;
    assert_eq!(legacy_largest_free_extent(&alloc), expected);
    assert_eq!(
        alloc
            .largest_free_extent(BTRFS_BLOCK_GROUP_DATA)
            .expect("largest free extent"),
        expected
    );

    let mut group = c.benchmark_group("btrfs_largest_free_extent_keyscan_4096");
    group.bench_function("legacy_range_vec_sort_largest", |b| {
        b.iter(|| black_box(legacy_largest_free_extent(black_box(&alloc))));
    });
    group.bench_function("streaming_largest_free_extent", |b| {
        b.iter(|| {
            black_box(
                alloc
                    .largest_free_extent(black_box(BTRFS_BLOCK_GROUP_DATA))
                    .expect("largest free extent"),
            )
        });
    });
    group.finish();
}

fn bench_free_space_extents(c: &mut Criterion) {
    let alloc = build_largest_free_allocator();
    let legacy = legacy_free_space_extents(&alloc);
    let free_space = alloc.free_space_extents().expect("free space extents");
    assert_eq!(legacy, free_space);
    assert_eq!(free_space.len(), 1);
    assert_eq!(
        free_space[0].free_ranges,
        vec![(BG_START + E as u64 * EXT_SIZE, 16 * EXT_SIZE)]
    );

    let mut group = c.benchmark_group("btrfs_free_space_extents_keyscan_4096");
    group.bench_function("legacy_range_vec_sort_free_space", |b| {
        b.iter(|| black_box(legacy_free_space_extents(black_box(&alloc))));
    });
    group.bench_function("streaming_free_space_extents", |b| {
        b.iter(|| black_box(alloc.free_space_extents().expect("free space extents")));
    });
    group.finish();
}

fn bench_sync_block_group_accounting(c: &mut Criterion) {
    let mut alloc = build_largest_free_allocator();
    assert_eq!(
        alloc
            .sync_block_group_accounting()
            .expect("sync block group accounting"),
        E as u64 * EXT_SIZE
    );

    let mut group = c.benchmark_group("btrfs_sync_block_group_accounting_keyscan_4096");
    group.bench_function("production_sync_block_group_accounting", |b| {
        b.iter(|| {
            black_box(
                alloc
                    .sync_block_group_accounting()
                    .expect("sync block group accounting"),
            )
        });
    });
    group.finish();
}

/// OLD commit sequence: two adjacent passes over the same per-block-group
/// extent keys — accounting recompute then free-space derivation.
fn commit_accounting_free_space_production(
    alloc: &mut BtrfsExtentAllocator,
) -> (u64, Vec<BlockGroupFreeSpace>) {
    let bytes_used = alloc
        .sync_block_group_accounting()
        .expect("sync block group accounting");
    let free_space = alloc.free_space_extents().expect("free space extents");
    (bytes_used, free_space)
}

/// NEW commit sequence (bd-xmh5g.193): one fused scan computing both the
/// accounting grand total and the free-space groups.
fn commit_accounting_free_space_fused(
    alloc: &mut BtrfsExtentAllocator,
) -> (u64, Vec<BlockGroupFreeSpace>) {
    alloc
        .sync_accounting_and_free_space()
        .expect("fused accounting + free space")
}

fn bench_commit_accounting_free_space(c: &mut Criterion) {
    // Isomorphism: the fused single-scan helper returns byte-identical
    // accounting totals AND free-space groups to the two-pass sequence.
    let mut alloc_two_pass = build_largest_free_allocator();
    let mut alloc_fused = build_largest_free_allocator();
    let two_pass = commit_accounting_free_space_production(&mut alloc_two_pass);
    let fused = commit_accounting_free_space_fused(&mut alloc_fused);
    assert_eq!(two_pass.0, E as u64 * EXT_SIZE);
    assert_eq!(
        two_pass, fused,
        "fused commit accounting diverged from two-pass"
    );

    let mut group = c.benchmark_group("btrfs_commit_accounting_free_space_scan_4096");
    group.bench_function("production_two_pass", |b| {
        b.iter(|| black_box(commit_accounting_free_space_production(&mut alloc_two_pass)));
    });
    group.bench_function("fused_single_scan", |b| {
        b.iter(|| black_box(commit_accounting_free_space_fused(&mut alloc_fused)));
    });
    group.finish();
}

const REWRITTEN_ROOTS: [u64; 4] = [
    BTRFS_ROOT_TREE_OBJECTID,
    BTRFS_EXTENT_TREE_OBJECTID,
    BTRFS_FS_TREE_OBJECTID,
    BTRFS_CSUM_TREE_OBJECTID,
];

fn build_rewritten_metadata_allocator() -> BtrfsExtentAllocator {
    let mut alloc = build_largest_free_allocator();
    for (index, owner_root) in REWRITTEN_ROOTS
        .into_iter()
        .chain(std::iter::once(BTRFS_CHUNK_TREE_OBJECTID))
        .enumerate()
    {
        alloc
            .insert_self_metadata_item(
                BG_START + (E as u64 + index as u64) * EXT_SIZE,
                0,
                owner_root,
                7,
            )
            .expect("insert rewritten-root metadata item");
    }
    alloc
}

fn rewritten_metadata_key(key: BtrfsKey, value: &[u8]) -> Option<BtrfsKey> {
    if key.item_type != BTRFS_ITEM_METADATA_ITEM || value.len() < 33 {
        return None;
    }
    if value[24] != BTRFS_ITEM_TREE_BLOCK_REF {
        return None;
    }
    let mut root_bytes = [0_u8; 8];
    root_bytes.copy_from_slice(&value[25..33]);
    let root = u64::from_le_bytes(root_bytes);
    REWRITTEN_ROOTS.contains(&root).then_some(key)
}

/// Frozen control: materialize and clone every extent-tree payload before
/// retaining only rewritten-root metadata keys.
fn materialized_rewritten_metadata_keys(alloc: &BtrfsExtentAllocator) -> Vec<BtrfsKey> {
    let lo = BtrfsKey {
        objectid: 0,
        item_type: 0,
        offset: 0,
    };
    let hi = BtrfsKey {
        objectid: u64::MAX,
        item_type: u8::MAX,
        offset: u64::MAX,
    };
    alloc
        .extent_tree()
        .range(&lo, &hi)
        .expect("materialized extent-tree scan")
        .into_iter()
        .filter_map(|(key, value)| rewritten_metadata_key(key, &value))
        .collect()
}

/// Candidate: traverse the identical key range and inspect each payload in
/// place, retaining only the matching keys needed by the delete phase.
fn borrowed_rewritten_metadata_keys(alloc: &BtrfsExtentAllocator) -> Vec<BtrfsKey> {
    let lo = BtrfsKey {
        objectid: 0,
        item_type: 0,
        offset: 0,
    };
    let hi = BtrfsKey {
        objectid: u64::MAX,
        item_type: u8::MAX,
        offset: u64::MAX,
    };
    let mut keys = Vec::new();
    alloc
        .extent_tree()
        .range_with(&lo, &hi, |key, value| {
            if let Some(key) = rewritten_metadata_key(key, value) {
                keys.push(key);
            }
        })
        .expect("borrowed extent-tree scan");
    keys
}

fn bench_rewritten_metadata_keyscan(c: &mut Criterion) {
    let alloc = build_rewritten_metadata_allocator();
    let control = materialized_rewritten_metadata_keys(&alloc);
    let candidate = borrowed_rewritten_metadata_keys(&alloc);
    assert_eq!(control, candidate, "borrowed scan changed selected keys");
    assert_eq!(candidate.len(), REWRITTEN_ROOTS.len());

    let mut group = c.benchmark_group("btrfs_rewritten_metadata_keyscan_4101");
    group.bench_function("materialized_control_a", |b| {
        b.iter(|| black_box(materialized_rewritten_metadata_keys(black_box(&alloc))));
    });
    group.bench_function("materialized_control_b", |b| {
        b.iter(|| black_box(materialized_rewritten_metadata_keys(black_box(&alloc))));
    });
    group.bench_function("borrowed_range_with", |b| {
        b.iter(|| black_box(borrowed_rewritten_metadata_keys(black_box(&alloc))));
    });
    group.finish();
}

#[derive(Clone, Copy)]
enum ReclaimArm {
    MaterializedControl,
    BorrowedModel,
    Production,
}

struct ReclaimBenchState {
    alloc: BtrfsExtentAllocator,
    referenced: HashSet<ExtentKey>,
}

struct ReclaimPairedStats {
    p50_a_ns: f64,
    p50_b_ns: f64,
    ratio_p50: f64,
    ratio_ci: (f64, f64),
    cv_pct: f64,
    checksum: u64,
}

fn self_sha256() -> (String, u64, String) {
    let Ok(path) = std::env::current_exe() else {
        return ("unavailable".to_owned(), 0, "unavailable".to_owned());
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return ("unavailable".to_owned(), 0, path.display().to_string());
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    (
        encoded,
        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        path.display().to_string(),
    )
}

fn print_codegen_isa() {
    #[cfg(target_arch = "x86_64")]
    println!(
        "codegen_isa,target_arch=x86_64,compile_sse2={},compile_sse4_2={},compile_avx2={},compile_fma={},runtime_sse4_2={},runtime_avx2={},runtime_fma={}",
        cfg!(target_feature = "sse2"),
        cfg!(target_feature = "sse4.2"),
        cfg!(target_feature = "avx2"),
        cfg!(target_feature = "fma"),
        std::arch::is_x86_feature_detected!("sse4.2"),
        std::arch::is_x86_feature_detected!("avx2"),
        std::arch::is_x86_feature_detected!("fma"),
    );
}

fn reclaim_range() -> (BtrfsKey, BtrfsKey) {
    (
        BtrfsKey {
            objectid: BG_START,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: 0,
        },
        BtrfsKey {
            objectid: bg_end(),
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: u64::MAX,
        },
    )
}

fn build_reclaim_state() -> ReclaimBenchState {
    let alloc = build_largest_free_allocator();
    let referenced = (0..E as u64)
        .map(|index| ExtentKey {
            bytenr: BG_START + index * EXT_SIZE,
            num_bytes: EXT_SIZE,
        })
        .collect();
    ReclaimBenchState { alloc, referenced }
}

/// Frozen source-neutral control matching the current clean-recovery scan:
/// materialize every selected extent-tree payload, then consume only keys.
fn materialized_reclaim_scan(
    alloc: &BtrfsExtentAllocator,
    referenced: &HashSet<ExtentKey>,
) -> Vec<ExtentAllocation> {
    let (range_start, range_end) = reclaim_range();
    let mut orphaned = Vec::new();
    for (key, _) in alloc
        .extent_tree()
        .range(&range_start, &range_end)
        .expect("materialized reclaim range")
    {
        if key.objectid >= bg_end() || key.item_type != BTRFS_ITEM_EXTENT_ITEM {
            continue;
        }
        let extent = ExtentKey {
            bytenr: key.objectid,
            num_bytes: key.offset,
        };
        if !referenced.contains(&extent) {
            orphaned.push(ExtentAllocation {
                bytenr: extent.bytenr,
                num_bytes: extent.num_bytes,
                block_group_start: BG_START,
            });
        }
    }
    orphaned
}

/// Source-neutral candidate model: traverse the same inclusive key range but
/// never clone payload bytes that orphan classification does not observe.
fn borrowed_reclaim_scan(
    alloc: &BtrfsExtentAllocator,
    referenced: &HashSet<ExtentKey>,
) -> Vec<ExtentAllocation> {
    let (range_start, range_end) = reclaim_range();
    let mut orphaned = Vec::new();
    alloc
        .extent_tree()
        .range_with(&range_start, &range_end, |key, _| {
            if key.objectid >= bg_end() || key.item_type != BTRFS_ITEM_EXTENT_ITEM {
                return;
            }
            let extent = ExtentKey {
                bytenr: key.objectid,
                num_bytes: key.offset,
            };
            if !referenced.contains(&extent) {
                orphaned.push(ExtentAllocation {
                    bytenr: extent.bytenr,
                    num_bytes: extent.num_bytes,
                    block_group_start: BG_START,
                });
            }
        })
        .expect("borrowed reclaim range");
    orphaned
}

fn reclaim_checksum(extents: &[ExtentAllocation]) -> u64 {
    extents.iter().fold(0_u64, |digest, extent| {
        digest
            .wrapping_mul(1_000_003)
            .wrapping_add(extent.bytenr)
            .rotate_left(7)
            ^ extent.num_bytes
            ^ extent.block_group_start.rotate_right(11)
    })
}

fn reclaim_rotation(value: usize) -> u32 {
    u32::try_from(value % 64).expect("rotation amount is less than 64")
}

fn run_reclaim_arm(state: &mut ReclaimBenchState, arm: ReclaimArm) -> u64 {
    let orphaned = match arm {
        ReclaimArm::MaterializedControl => {
            materialized_reclaim_scan(&state.alloc, &state.referenced)
        }
        ReclaimArm::BorrowedModel => borrowed_reclaim_scan(&state.alloc, &state.referenced),
        ReclaimArm::Production => state
            .alloc
            .reclaim_unreferenced_data_extents(&state.referenced)
            .expect("production orphan reclaim"),
    };
    black_box(reclaim_checksum(&orphaned))
}

fn reclaim_sample(state: &mut ReclaimBenchState, arm: ReclaimArm, batch: usize) -> u64 {
    let mut digest = 0_u64;
    for iteration in 0..batch {
        digest ^= run_reclaim_arm(black_box(state), black_box(arm))
            .rotate_left(reclaim_rotation(iteration));
    }
    digest
}

fn reclaim_time_min(state: &mut ReclaimBenchState, arm: ReclaimArm, batch: usize) -> (u64, u64) {
    let mut best = u64::MAX;
    let mut digest = 0_u64;
    for replicate in 0..RECLAIM_MIN_OF {
        let started = Instant::now();
        let observed = reclaim_sample(state, arm, batch);
        let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        best = best.min(elapsed.max(1));
        digest ^= observed.rotate_left(reclaim_rotation(replicate));
    }
    (best, digest)
}

fn reclaim_calibrate_batch(state: &mut ReclaimBenchState, candidate: ReclaimArm) -> usize {
    black_box(reclaim_sample(state, ReclaimArm::MaterializedControl, 1));
    black_box(reclaim_sample(state, candidate, 1));

    let started = Instant::now();
    black_box(reclaim_sample(state, candidate, 1));
    let candidate_ns = u64::try_from(started.elapsed().as_nanos())
        .unwrap_or(u64::MAX)
        .max(1);
    usize::try_from(RECLAIM_MIN_SAMPLE_NS.div_ceil(candidate_ns))
        .unwrap_or(usize::MAX)
        .clamp(1, 64)
}

fn reclaim_median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable_by(f64::total_cmp);
    sorted[sorted.len() / 2]
}

fn reclaim_bootstrap_median_ci(values: &[f64], seed: u64) -> (f64, f64) {
    let mut state = seed;
    let mut medians = Vec::with_capacity(RECLAIM_BOOTSTRAP_RESAMPLES);
    let mut resample = Vec::with_capacity(values.len());
    for _ in 0..RECLAIM_BOOTSTRAP_RESAMPLES {
        resample.clear();
        for _ in 0..values.len() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let value_count = u64::try_from(values.len()).expect("sample count fits in u64");
            let index =
                usize::try_from(state % value_count).expect("index is less than sample count");
            resample.push(values[index]);
        }
        medians.push(reclaim_median(&resample));
    }
    medians.sort_unstable_by(f64::total_cmp);
    let low = RECLAIM_BOOTSTRAP_RESAMPLES * 25 / 1_000;
    let high = RECLAIM_BOOTSTRAP_RESAMPLES * 975 / 1_000;
    (medians[low], medians[high.min(medians.len() - 1)])
}

fn reclaim_paired(
    state: &mut ReclaimBenchState,
    arm_a: ReclaimArm,
    arm_b: ReclaimArm,
    batch: usize,
) -> ReclaimPairedStats {
    let mut times_a = Vec::with_capacity(RECLAIM_ROUNDS);
    let mut times_b = Vec::with_capacity(RECLAIM_ROUNDS);
    let mut ratios = Vec::with_capacity(RECLAIM_ROUNDS);
    let mut digest = 0_u64;
    for round in 0..RECLAIM_ROUNDS {
        let ((elapsed_a, digest_a), (elapsed_b, digest_b)) = if round % 2 == 0 {
            (
                reclaim_time_min(state, arm_a, batch),
                reclaim_time_min(state, arm_b, batch),
            )
        } else {
            let b = reclaim_time_min(state, arm_b, batch);
            let a = reclaim_time_min(state, arm_a, batch);
            (a, b)
        };
        times_a.push(elapsed_a as f64);
        times_b.push(elapsed_b as f64);
        ratios.push(elapsed_a as f64 / elapsed_b.max(1) as f64);
        digest ^= digest_a.rotate_left(reclaim_rotation(round));
        digest ^= digest_b.rotate_right(reclaim_rotation(round));
    }

    let ratio_p50 = reclaim_median(&ratios);
    let mean = ratios.iter().sum::<f64>() / ratios.len() as f64;
    let variance = ratios
        .iter()
        .map(|ratio| (ratio - mean) * (ratio - mean))
        .sum::<f64>()
        / (ratios.len() - 1) as f64;
    ReclaimPairedStats {
        p50_a_ns: reclaim_median(&times_a),
        p50_b_ns: reclaim_median(&times_b),
        ratio_p50,
        ratio_ci: reclaim_bootstrap_median_ci(&ratios, RECLAIM_BOOTSTRAP_SEED),
        cv_pct: variance.sqrt() / mean * 100.0,
        checksum: digest,
    }
}

fn print_reclaim_stats(label: &str, stats: &ReclaimPairedStats) {
    println!(
        "{label},rounds={RECLAIM_ROUNDS},min_of={RECLAIM_MIN_OF},p50_a_ns={:.0},p50_b_ns={:.0},ratio_p50={:.6},ratio_bootstrap_median_ci95=[{:.6},{:.6}],cv_pct={:.3},cv_used_as_gate=false,checksum={:016x}",
        stats.p50_a_ns,
        stats.p50_b_ns,
        stats.ratio_p50,
        stats.ratio_ci.0,
        stats.ratio_ci.1,
        stats.cv_pct,
        stats.checksum,
    );
}

fn reclaim_mechanism_count(state: &ReclaimBenchState) -> (usize, usize, usize) {
    let (range_start, range_end) = reclaim_range();
    let entries = state
        .alloc
        .extent_tree()
        .range(&range_start, &range_end)
        .expect("count reclaim range");
    let payload_bytes = entries.iter().map(|(_, payload)| payload.len()).sum();
    let extent_items = entries
        .iter()
        .filter(|(key, _)| key.objectid < bg_end() && key.item_type == BTRFS_ITEM_EXTENT_ITEM)
        .count();
    (entries.len(), extent_items, payload_bytes)
}

fn reclaim_decision(candidate: ReclaimArm, mode: &str) {
    let (binary_sha256, binary_bytes, binary_path) = self_sha256();
    println!(
        "bench_evidence,binary_sha256={binary_sha256},binary_bytes={binary_bytes},binary_path={binary_path},worker={}",
        std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_owned())
    );
    print_codegen_isa();

    let mut state = build_reclaim_state();
    let control = run_reclaim_arm(&mut state, ReclaimArm::MaterializedControl);
    let model = run_reclaim_arm(&mut state, ReclaimArm::BorrowedModel);
    let production = run_reclaim_arm(&mut state, ReclaimArm::Production);
    assert_eq!(
        (control, model, production),
        (control, control, control),
        "clean recovery orphan outputs diverged"
    );
    let (range_entries, extent_items, materialized_payload_bytes) = reclaim_mechanism_count(&state);
    println!(
        "behavior_parity=exact,ordering=block_group_then_extent_key_ascending,tie_breaking=na,floating_point=na,rng=na,referenced_extents={},orphaned_extents=0,output_checksum={control:016x}",
        state.referenced.len()
    );
    println!(
        "mechanism_count,range_entries={range_entries},extent_items={extent_items},materialized_payload_vecs={range_entries},materialized_payload_bytes={materialized_payload_bytes},borrowed_payload_vecs=0"
    );

    let batch = reclaim_calibrate_batch(&mut state, candidate);
    println!(
        "bench_config,mode={mode},batch={batch},rounds={RECLAIM_ROUNDS},min_sample_ns={RECLAIM_MIN_SAMPLE_NS},min_of={RECLAIM_MIN_OF},bootstrap_resamples={RECLAIM_BOOTSTRAP_RESAMPLES},bootstrap_seed={RECLAIM_BOOTSTRAP_SEED:016x}"
    );
    let null = reclaim_paired(
        &mut state,
        ReclaimArm::MaterializedControl,
        ReclaimArm::MaterializedControl,
        batch,
    );
    let real = reclaim_paired(
        &mut state,
        ReclaimArm::MaterializedControl,
        candidate,
        batch,
    );
    print_reclaim_stats("null_materialized_materialized", &null);
    print_reclaim_stats("real_materialized_borrowed", &real);

    let null_floor = null.ratio_ci.1.max(null.ratio_ci.0.recip());
    let twice_null_threshold = null_floor * null_floor;
    let saved_fraction_lower = (1.0 - real.ratio_ci.0.recip()).max(0.0);
    let admitted = real.ratio_ci.0 > twice_null_threshold
        && saved_fraction_lower >= MIN_RECLAIM_SAVED_FRACTION;
    let verdict = if admitted {
        "decidable_candidate_win"
    } else {
        "not_admitted"
    };
    println!(
        "median_ci_gate={verdict},null_symmetric_floor={null_floor:.6},twice_null_threshold={twice_null_threshold:.6},real_ci_lower={:.6},real_ci_upper={:.6},saved_fraction_ci_lower={saved_fraction_lower:.6},minimum_saved_fraction={MIN_RECLAIM_SAVED_FRACTION:.6},gate_basis=bootstrap_median_wall_ci,cv_used_as_gate=false,instructions_used_as_gate=false",
        real.ratio_ci.0, real.ratio_ci.1
    );
    if !admitted {
        std::process::exit(2);
    }
}

fn main() {
    if std::env::args().any(|arg| arg == "--reclaim-attribution-only") {
        reclaim_decision(ReclaimArm::BorrowedModel, "source_neutral_attribution");
        return;
    }
    if std::env::args().any(|arg| arg == "--reclaim-production-decision-only") {
        reclaim_decision(ReclaimArm::Production, "actual_production_decision");
        return;
    }

    let mut criterion = Criterion::default().configure_from_args();
    bench_alloc_gap_scan(&mut criterion);
    bench_largest_free_extent(&mut criterion);
    bench_free_space_extents(&mut criterion);
    bench_sync_block_group_accounting(&mut criterion);
    bench_commit_accounting_free_space(&mut criterion);
    bench_rewritten_metadata_keyscan(&mut criterion);
    criterion.final_summary();
}
