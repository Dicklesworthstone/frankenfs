#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

//! Null-controlled whole-callback A/B for queued repair group lookup/dedup.
//!
//! A repair-aware flush maps every committed block to a repair group. The
//! first banked lever indexed valid disjoint ranges and the second replaced its
//! temporary `BTreeSet` with compact `Vec` sort/dedup. This A/B freezes that
//! production callback against hash membership plus deterministic sort-on-drain
//! for the persistent queue.

use asupersync::Cx;
use ffs_block::RepairFlushLifecycle;
use ffs_repair::pipeline::{GroupConfig, QueuedRepairRefresh};
use ffs_repair::storage::RepairGroupLayout;
use ffs_types::{BlockNumber, GroupNumber};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::fmt::Write as _;
use std::hint::black_box;
use std::sync::Mutex;
use std::time::Instant;

const GROUPS: u32 = 4_096;
const BLOCKS_PER_GROUP: u32 = 64;
const SOURCE_BLOCKS_PER_GROUP: u32 = 32;
const WRITE_BLOCKS: u32 = 512;
const ROUNDS: usize = 41;
const MIN_OF: usize = 3;
const MIN_SAMPLE_NS: u64 = 2_000_000;
const BOOTSTRAP_RESAMPLES: usize = 20_000;
const BOOTSTRAP_SEED: u64 = 0xF5A1_9A2E_2026_0727;

#[derive(Clone, Copy)]
enum Arm {
    Baseline,
    Candidate,
}

#[derive(Clone, Copy)]
struct GroupRange {
    group: GroupNumber,
    start: u64,
    end: u64,
}

struct LegacyQueuedRepairRefresh {
    ranges: Vec<GroupRange>,
    queued_groups: Mutex<BTreeSet<GroupNumber>>,
}

impl LegacyQueuedRepairRefresh {
    fn new(configs: &[GroupConfig]) -> Self {
        Self {
            ranges: configs
                .iter()
                .map(|config| GroupRange {
                    group: config.layout.group,
                    start: config.source_first_block.0,
                    end: config.source_first_block.0 + u64::from(config.source_block_count),
                })
                .collect(),
            queued_groups: Mutex::new(BTreeSet::new()),
        }
    }

    fn on_flush_committed(&self, blocks: &[BlockNumber]) {
        let mut groups = BTreeSet::new();
        for block in blocks {
            if let Some(range) = self
                .ranges
                .iter()
                .find(|range| block.0 >= range.start && block.0 < range.end)
            {
                groups.insert(range.group);
            }
        }
        if groups.is_empty() {
            return;
        }

        let group_ids: Vec<u32> = groups.iter().map(|group| group.0).collect();
        tracing::debug!(
            target: "ffs::repair::refresh",
            group_ids = ?group_ids,
            block_count = blocks.len(),
            "flush_triggers_refresh"
        );

        let mut queued = self.queued_groups.lock().expect("legacy queue lock");
        for group in groups {
            queued.insert(group);
        }
    }

    fn drain(&self) -> Vec<GroupNumber> {
        let mut queued = self.queued_groups.lock().expect("legacy queue lock");
        let groups = queued.iter().copied().collect();
        queued.clear();
        groups
    }
}

struct IndexedTreeQueuedRepairRefresh {
    ranges: Vec<GroupRange>,
    queued_groups: Mutex<BTreeSet<GroupNumber>>,
}

impl IndexedTreeQueuedRepairRefresh {
    fn new(configs: &[GroupConfig]) -> Self {
        let mut ranges = configs
            .iter()
            .map(|config| GroupRange {
                group: config.layout.group,
                start: config.source_first_block.0,
                end: config.source_first_block.0 + u64::from(config.source_block_count),
            })
            .collect::<Vec<_>>();
        ranges.sort_by_key(|range| range.start);
        Self {
            ranges,
            queued_groups: Mutex::new(BTreeSet::new()),
        }
    }

    fn on_flush_committed(&self, blocks: &[BlockNumber]) {
        let mut groups = BTreeSet::new();
        for block in blocks {
            if let Some(range) = self
                .ranges
                .partition_point(|range| range.start <= block.0)
                .checked_sub(1)
                .and_then(|index| self.ranges.get(index))
                .filter(|range| block.0 < range.end)
            {
                groups.insert(range.group);
            }
        }
        if groups.is_empty() {
            return;
        }

        let group_ids: Vec<u32> = groups.iter().map(|group| group.0).collect();
        tracing::debug!(
            target: "ffs::repair::refresh",
            group_ids = ?group_ids,
            block_count = blocks.len(),
            "flush_triggers_refresh"
        );

        let mut queued = self.queued_groups.lock().expect("indexed-tree queue lock");
        for group in groups {
            queued.insert(group);
        }
    }

    fn drain(&self) -> Vec<GroupNumber> {
        let mut queued = self.queued_groups.lock().expect("indexed-tree queue lock");
        let groups = queued.iter().copied().collect();
        queued.clear();
        groups
    }
}

struct CompactVecQueuedRepairRefresh {
    ranges: Vec<GroupRange>,
    queued_groups: Mutex<BTreeSet<GroupNumber>>,
}

impl CompactVecQueuedRepairRefresh {
    fn new(configs: &[GroupConfig]) -> Self {
        let mut ranges = configs
            .iter()
            .map(|config| GroupRange {
                group: config.layout.group,
                start: config.source_first_block.0,
                end: config.source_first_block.0 + u64::from(config.source_block_count),
            })
            .collect::<Vec<_>>();
        ranges.sort_by_key(|range| range.start);
        Self {
            ranges,
            queued_groups: Mutex::new(BTreeSet::new()),
        }
    }

    fn on_flush_committed(&self, blocks: &[BlockNumber]) {
        let mut groups = Vec::with_capacity(blocks.len());
        for block in blocks {
            if let Some(range) = self
                .ranges
                .partition_point(|range| range.start <= block.0)
                .checked_sub(1)
                .and_then(|index| self.ranges.get(index))
                .filter(|range| block.0 < range.end)
            {
                groups.push(range.group);
            }
        }
        groups.sort_unstable();
        groups.dedup();
        if groups.is_empty() {
            return;
        }

        let group_ids: Vec<u32> = groups.iter().map(|group| group.0).collect();
        tracing::debug!(
            target: "ffs::repair::refresh",
            group_ids = ?group_ids,
            block_count = blocks.len(),
            "flush_triggers_refresh"
        );

        let mut queued = self.queued_groups.lock().expect("compact-vec queue lock");
        for group in groups {
            queued.insert(group);
        }
    }

    fn drain(&self) -> Vec<GroupNumber> {
        let mut queued = self.queued_groups.lock().expect("compact-vec queue lock");
        let groups = queued.iter().copied().collect();
        queued.clear();
        groups
    }
}

struct HashQueuedRepairRefresh {
    ranges: Vec<GroupRange>,
    queued_groups: Mutex<HashSet<GroupNumber>>,
}

impl HashQueuedRepairRefresh {
    fn new(configs: &[GroupConfig]) -> Self {
        let mut ranges = configs
            .iter()
            .map(|config| GroupRange {
                group: config.layout.group,
                start: config.source_first_block.0,
                end: config.source_first_block.0 + u64::from(config.source_block_count),
            })
            .collect::<Vec<_>>();
        ranges.sort_by_key(|range| range.start);
        Self {
            ranges,
            queued_groups: Mutex::new(HashSet::new()),
        }
    }

    fn on_flush_committed(&self, blocks: &[BlockNumber]) {
        let mut groups = Vec::with_capacity(blocks.len());
        for block in blocks {
            if let Some(range) = self
                .ranges
                .partition_point(|range| range.start <= block.0)
                .checked_sub(1)
                .and_then(|index| self.ranges.get(index))
                .filter(|range| block.0 < range.end)
            {
                groups.push(range.group);
            }
        }
        groups.sort_unstable();
        groups.dedup();
        if groups.is_empty() {
            return;
        }

        let group_ids: Vec<u32> = groups.iter().map(|group| group.0).collect();
        tracing::debug!(
            target: "ffs::repair::refresh",
            group_ids = ?group_ids,
            block_count = blocks.len(),
            "flush_triggers_refresh"
        );

        let mut queued = self.queued_groups.lock().expect("hash queue lock");
        queued.reserve(groups.len());
        for group in groups {
            queued.insert(group);
        }
    }

    fn drain(&self) -> Vec<GroupNumber> {
        let mut queued = self.queued_groups.lock().expect("hash queue lock");
        let mut groups = queued.drain().collect::<Vec<_>>();
        drop(queued);
        groups.sort_unstable();
        groups
    }
}

struct BenchState {
    cx: Cx,
    blocks: Vec<BlockNumber>,
    ranges: Vec<GroupRange>,
    linear: LegacyQueuedRepairRefresh,
    baseline: IndexedTreeQueuedRepairRefresh,
    candidate: CompactVecQueuedRepairRefresh,
    hash_candidate: HashQueuedRepairRefresh,
    production: QueuedRepairRefresh,
}

struct PairedStats {
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

fn build_configs() -> Vec<GroupConfig> {
    (0..GROUPS)
        .rev()
        .map(|group| {
            let start = u64::from(group) * u64::from(BLOCKS_PER_GROUP);
            GroupConfig {
                layout: RepairGroupLayout::new(
                    GroupNumber(group),
                    BlockNumber(start),
                    BLOCKS_PER_GROUP,
                    0,
                    4,
                )
                .expect("benchmark group layout"),
                source_first_block: BlockNumber(start),
                source_block_count: SOURCE_BLOCKS_PER_GROUP,
            }
        })
        .collect()
}

fn build_blocks() -> Vec<BlockNumber> {
    (0..WRITE_BLOCKS)
        .map(|index| {
            let group = index.wrapping_mul(17) % GROUPS;
            let offset = index % SOURCE_BLOCKS_PER_GROUP;
            BlockNumber(u64::from(group) * u64::from(BLOCKS_PER_GROUP) + u64::from(offset))
        })
        .collect()
}

fn build_state() -> BenchState {
    let configs = build_configs();
    BenchState {
        cx: Cx::for_testing(),
        blocks: build_blocks(),
        ranges: configs
            .iter()
            .map(|config| GroupRange {
                group: config.layout.group,
                start: config.source_first_block.0,
                end: config.source_first_block.0 + u64::from(config.source_block_count),
            })
            .collect(),
        linear: LegacyQueuedRepairRefresh::new(&configs),
        baseline: IndexedTreeQueuedRepairRefresh::new(&configs),
        candidate: CompactVecQueuedRepairRefresh::new(&configs),
        hash_candidate: HashQueuedRepairRefresh::new(&configs),
        production: QueuedRepairRefresh::from_group_configs(&configs),
    }
}

fn checksum(groups: &[GroupNumber]) -> u64 {
    groups.iter().fold(0_u64, |digest, group| {
        digest
            .wrapping_mul(1_000_003)
            .wrapping_add(u64::from(group.0))
    })
}

fn run_arm(state: &BenchState, arm: Arm) -> u64 {
    let groups = match arm {
        Arm::Baseline => {
            state.candidate.on_flush_committed(&state.blocks);
            state.candidate.drain()
        }
        Arm::Candidate => {
            state
                .production
                .on_flush_committed(&state.cx, &state.blocks)
                .expect("candidate queue callback");
            state
                .production
                .drain_queued_groups()
                .expect("candidate queue drain")
        }
    };
    black_box(checksum(&groups))
}

fn counted_mechanism(state: &BenchState) -> (usize, usize, Vec<GroupNumber>) {
    let mut linear_comparisons = 0_usize;
    let mut linear = BTreeSet::new();
    for block in &state.blocks {
        if let Some(range) = state.ranges.iter().find(|range| {
            linear_comparisons += 1;
            block.0 >= range.start && block.0 < range.end
        }) {
            linear.insert(range.group);
        }
    }

    let mut sorted = state.ranges.clone();
    sorted.sort_by_key(|range| range.start);
    let mut indexed_comparisons = 0_usize;
    let mut indexed = BTreeSet::new();
    for block in &state.blocks {
        let mut left = 0_usize;
        let mut right = sorted.len();
        while left < right {
            indexed_comparisons += 1;
            let middle = left + (right - left) / 2;
            if sorted[middle].start <= block.0 {
                left = middle + 1;
            } else {
                right = middle;
            }
        }
        if let Some(range) = left
            .checked_sub(1)
            .and_then(|index| sorted.get(index))
            .filter(|range| block.0 < range.end)
        {
            indexed.insert(range.group);
        }
    }

    assert_eq!(linear, indexed, "counted range lookups diverged");
    (
        linear_comparisons,
        indexed_comparisons,
        linear.into_iter().collect(),
    )
}

fn sample_arm(state: &BenchState, arm: Arm, batch: usize) -> u64 {
    let mut digest = 0_u64;
    for iteration in 0..batch {
        digest ^= run_arm(black_box(state), black_box(arm))
            .rotate_left((iteration % u64::BITS as usize) as u32);
    }
    digest
}

fn time_min(state: &BenchState, arm: Arm, batch: usize) -> (u64, u64) {
    let mut best = u64::MAX;
    let mut digest = 0_u64;
    for replicate in 0..MIN_OF {
        let started = Instant::now();
        let observed = sample_arm(state, arm, batch);
        let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        best = best.min(elapsed.max(1));
        digest ^= observed.rotate_left((replicate % u64::BITS as usize) as u32);
    }
    (best, digest)
}

fn calibrate_batch(state: &BenchState) -> usize {
    black_box(sample_arm(state, Arm::Baseline, 1));
    black_box(sample_arm(state, Arm::Candidate, 1));

    let started = Instant::now();
    black_box(sample_arm(state, Arm::Candidate, 1));
    let candidate_ns = u64::try_from(started.elapsed().as_nanos())
        .unwrap_or(u64::MAX)
        .max(1);
    usize::try_from(MIN_SAMPLE_NS.div_ceil(candidate_ns))
        .unwrap_or(usize::MAX)
        .clamp(1, 64)
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable_by(f64::total_cmp);
    sorted[sorted.len() / 2]
}

fn bootstrap_median_ci(values: &[f64], seed: u64) -> (f64, f64) {
    let mut state = seed;
    let mut medians = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    let mut resample = Vec::with_capacity(values.len());
    for _ in 0..BOOTSTRAP_RESAMPLES {
        resample.clear();
        for _ in 0..values.len() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            resample.push(values[(state as usize) % values.len()]);
        }
        medians.push(median(&resample));
    }
    medians.sort_unstable_by(f64::total_cmp);
    let low = BOOTSTRAP_RESAMPLES * 25 / 1_000;
    let high = BOOTSTRAP_RESAMPLES * 975 / 1_000;
    (medians[low], medians[high.min(medians.len() - 1)])
}

fn paired(state: &BenchState, arm_a: Arm, arm_b: Arm, batch: usize) -> PairedStats {
    let mut times_a = Vec::with_capacity(ROUNDS);
    let mut times_b = Vec::with_capacity(ROUNDS);
    let mut ratios = Vec::with_capacity(ROUNDS);
    let mut digest = 0_u64;
    for round in 0..ROUNDS {
        let ((elapsed_a, digest_a), (elapsed_b, digest_b)) = if round % 2 == 0 {
            (time_min(state, arm_a, batch), time_min(state, arm_b, batch))
        } else {
            let b = time_min(state, arm_b, batch);
            let a = time_min(state, arm_a, batch);
            (a, b)
        };
        times_a.push(elapsed_a as f64);
        times_b.push(elapsed_b as f64);
        ratios.push(elapsed_a as f64 / elapsed_b.max(1) as f64);
        digest ^= digest_a.rotate_left((round % u64::BITS as usize) as u32);
        digest ^= digest_b.rotate_right((round % u64::BITS as usize) as u32);
    }

    let ratio_p50 = median(&ratios);
    let mean = ratios.iter().sum::<f64>() / ratios.len() as f64;
    let variance = ratios
        .iter()
        .map(|ratio| (ratio - mean) * (ratio - mean))
        .sum::<f64>()
        / (ratios.len() - 1) as f64;
    PairedStats {
        p50_a_ns: median(&times_a),
        p50_b_ns: median(&times_b),
        ratio_p50,
        ratio_ci: bootstrap_median_ci(&ratios, BOOTSTRAP_SEED),
        cv_pct: variance.sqrt() / mean * 100.0,
        checksum: digest,
    }
}

fn print_stats(label: &str, stats: &PairedStats) {
    println!(
        "{label},rounds={ROUNDS},min_of={MIN_OF},p50_a_ns={:.0},p50_b_ns={:.0},ratio_p50={:.6},ratio_bootstrap_median_ci95=[{:.6},{:.6}],cv_pct={:.3},cv_used_as_gate=false,checksum={:016x}",
        stats.p50_a_ns,
        stats.p50_b_ns,
        stats.ratio_p50,
        stats.ratio_ci.0,
        stats.ratio_ci.1,
        stats.cv_pct,
        stats.checksum,
    );
}

fn main() {
    let (binary_sha256, binary_bytes, binary_path) = self_sha256();
    println!(
        "bench_evidence,binary_sha256={binary_sha256},binary_bytes={binary_bytes},binary_path={binary_path},worker={}",
        std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_owned())
    );
    print_codegen_isa();

    let state = build_state();
    let baseline = run_arm(&state, Arm::Baseline);
    state.hash_candidate.on_flush_committed(&state.blocks);
    let hash_candidate = checksum(&state.hash_candidate.drain());
    state.baseline.on_flush_committed(&state.blocks);
    let indexed_tree = checksum(&state.baseline.drain());
    state.linear.on_flush_committed(&state.blocks);
    let linear = checksum(&state.linear.drain());
    let production = run_arm(&state, Arm::Candidate);
    assert_eq!(
        (linear, indexed_tree, baseline, hash_candidate, production),
        (baseline, baseline, baseline, baseline, baseline),
        "queued group outputs diverged"
    );
    let (linear_comparisons, indexed_comparisons, groups) = counted_mechanism(&state);
    assert_eq!(checksum(&groups), baseline);
    println!(
        "behavior_parity=exact,ordering=group_number_ascending,tie_breaking=first_input_match_on_overlap,floating_point=na,rng=na,queued_groups={},output_checksum={baseline:016x}",
        groups.len()
    );
    println!(
        "mechanism_count,write_blocks={},repair_groups={},linear_range_comparisons={linear_comparisons},indexed_range_comparisons={indexed_comparisons},comparison_reduction={:.3}x,temporary_tree_insertions={},temporary_vec_pushes={},unique_groups={}",
        state.blocks.len(),
        state.ranges.len(),
        linear_comparisons as f64 / indexed_comparisons as f64,
        state.blocks.len(),
        state.blocks.len(),
        groups.len()
    );

    let batch = calibrate_batch(&state);
    println!(
        "bench_config=batch={batch},rounds={ROUNDS},min_sample_ns={MIN_SAMPLE_NS},min_of={MIN_OF},bootstrap_resamples={BOOTSTRAP_RESAMPLES},bootstrap_seed={BOOTSTRAP_SEED:016x}"
    );
    let null = paired(&state, Arm::Baseline, Arm::Baseline, batch);
    let real = paired(&state, Arm::Baseline, Arm::Candidate, batch);
    print_stats("null_persistent_tree_persistent_tree", &null);
    print_stats("real_persistent_tree_persistent_hash", &real);

    let null_floor = null.ratio_ci.1.max(null.ratio_ci.0.recip());
    let twice_null_threshold = null_floor * null_floor;
    let candidate_win = real.ratio_ci.0 > twice_null_threshold;
    let baseline_win = real.ratio_ci.1.recip() > twice_null_threshold;
    let verdict = if candidate_win {
        "decidable_candidate_win"
    } else if baseline_win {
        "decidable_baseline_win"
    } else {
        "unresolved"
    };
    println!(
        "median_ci_gate={verdict},null_symmetric_floor={null_floor:.6},twice_null_threshold={twice_null_threshold:.6},real_ci_lower={:.6},real_ci_upper={:.6},gate_basis=bootstrap_median_wall_ci,cv_used_as_gate=false,instructions_used_as_gate=false",
        real.ratio_ci.0, real.ratio_ci.1
    );
}
