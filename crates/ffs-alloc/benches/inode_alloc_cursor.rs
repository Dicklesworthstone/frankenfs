#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

//! Null-controlled A/B for the inode bitmap allocation cursor.
//!
//! The ext4 create path allocates many regular-file inodes from the parent
//! group. The old allocator restarted every bitmap search at bit 0, so each
//! create re-scanned the already allocated prefix while holding the allocator
//! lock. The cursor keeps the bitmap as authority but starts the wrapped search
//! after the last successful allocation.
//!
//! This benchmark implements the cross-repo bench contract:
//! - line one is the SHA-256 of the executable that is actually running;
//! - baseline/baseline and baseline/candidate use the same interleaved routine;
//! - the verdict is gated on a deterministic bootstrap 95% CI for the median,
//!   never on coefficient of variation (which is provenance only).

use ffs_alloc::{bitmap_find_free, bitmap_get, bitmap_set};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

const INODES: u32 = 131_072;
const RESERVED_INODES: u32 = 11;
const ALLOCATIONS: u32 = 16_384;
const ROUNDS: usize = 41;
const MIN_OF: usize = 3;
const MIN_SAMPLE_NS: u64 = 2_000_000;
const BOOTSTRAP_RESAMPLES: usize = 10_000;
const BOOTSTRAP_SEED: u64 = 0xF5A1_10C8_2026_0725;

#[derive(Clone, Copy)]
enum Arm {
    Baseline,
    Candidate,
}

struct PairedStats {
    p50_a_ns: f64,
    p50_b_ns: f64,
    p50_a_ci: (f64, f64),
    p50_b_ci: (f64, f64),
    ratio_p50: f64,
    ratio_ci: (f64, f64),
    cv_pct: f64,
    mad: f64,
    checksum: u64,
}

fn self_identity() -> String {
    let Ok(path) = std::env::current_exe() else {
        return "unavailable".to_owned();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return "unavailable".to_owned();
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    format!("{} ({} bytes) {}", encoded, bytes.len(), path.display())
}

fn seed_inode_bitmap() -> Vec<u8> {
    let mut bitmap = vec![0_u8; usize::try_from(INODES.div_ceil(8)).unwrap()];
    for idx in 0..RESERVED_INODES {
        bitmap_set(&mut bitmap, idx);
    }
    bitmap
}

fn restart_at_zero_allocs() -> (u64, Vec<u8>) {
    let mut bitmap = seed_inode_bitmap();
    let mut checksum = 0_u64;
    for _ in 0..ALLOCATIONS {
        let idx = bitmap_find_free(&bitmap, INODES, 0).expect("benchmark bitmap has free inodes");
        assert!(!bitmap_get(&bitmap, idx));
        bitmap_set(&mut bitmap, idx);
        checksum = checksum
            .wrapping_mul(1_000_003)
            .wrapping_add(u64::from(idx));
    }
    (checksum, bitmap)
}

fn cursor_allocs() -> (u64, Vec<u8>) {
    let mut bitmap = seed_inode_bitmap();
    let mut cursor = 0_u32;
    let mut checksum = 0_u64;
    for _ in 0..ALLOCATIONS {
        let idx =
            bitmap_find_free(&bitmap, INODES, cursor).expect("benchmark bitmap has free inodes");
        assert!(!bitmap_get(&bitmap, idx));
        bitmap_set(&mut bitmap, idx);
        cursor = idx
            .checked_add(1)
            .filter(|next| *next < INODES)
            .unwrap_or(0);
        checksum = checksum
            .wrapping_mul(1_000_003)
            .wrapping_add(u64::from(idx));
    }
    (checksum, bitmap)
}

fn run_arm(arm: Arm) -> (u64, Vec<u8>) {
    match arm {
        Arm::Baseline => restart_at_zero_allocs(),
        Arm::Candidate => cursor_allocs(),
    }
}

fn sample_arm(arm: Arm, batch: usize) -> u64 {
    let mut checksum = 0_u64;
    for iteration in 0..batch {
        let (sequence_checksum, bitmap) = black_box(run_arm(black_box(arm)));
        checksum ^= sequence_checksum
            .rotate_left((iteration % u64::BITS as usize) as u32)
            .wrapping_add(bitmap.len() as u64)
            .wrapping_add(u64::from(bitmap.first().copied().unwrap_or(0)))
            .wrapping_add(u64::from(bitmap.last().copied().unwrap_or(0)));
        black_box(bitmap);
    }
    checksum
}

fn time_min(arm: Arm, batch: usize) -> (u64, u64) {
    let mut best = u64::MAX;
    let mut checksum = 0_u64;
    for replicate in 0..MIN_OF {
        let started = Instant::now();
        let observed = sample_arm(arm, batch);
        let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        best = best.min(elapsed.max(1));
        checksum ^= observed.rotate_left((replicate % u64::BITS as usize) as u32);
    }
    (best, checksum)
}

fn calibrate_batch() -> usize {
    black_box(sample_arm(Arm::Baseline, 1));
    black_box(sample_arm(Arm::Candidate, 1));

    let baseline_started = Instant::now();
    black_box(sample_arm(Arm::Baseline, 1));
    let baseline_ns = u64::try_from(baseline_started.elapsed().as_nanos()).unwrap_or(u64::MAX);

    let candidate_started = Instant::now();
    black_box(sample_arm(Arm::Candidate, 1));
    let candidate_ns = u64::try_from(candidate_started.elapsed().as_nanos()).unwrap_or(u64::MAX);

    let faster_ns = baseline_ns.min(candidate_ns).max(1);
    usize::try_from(MIN_SAMPLE_NS.div_ceil(faster_ns))
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

fn paired(arm_a: Arm, arm_b: Arm, batch: usize) -> PairedStats {
    let mut times_a = Vec::with_capacity(ROUNDS);
    let mut times_b = Vec::with_capacity(ROUNDS);
    let mut ratios = Vec::with_capacity(ROUNDS);
    let mut checksum = 0_u64;

    for round in 0..ROUNDS {
        let ((elapsed_a, checksum_a), (elapsed_b, checksum_b)) = if round % 2 == 0 {
            (time_min(arm_a, batch), time_min(arm_b, batch))
        } else {
            let b = time_min(arm_b, batch);
            let a = time_min(arm_a, batch);
            (a, b)
        };
        times_a.push(elapsed_a as f64);
        times_b.push(elapsed_b as f64);
        ratios.push(elapsed_a as f64 / elapsed_b.max(1) as f64);
        checksum ^= checksum_a.rotate_left((round % u64::BITS as usize) as u32);
        checksum ^= checksum_b.rotate_right((round % u64::BITS as usize) as u32);
    }

    let ratio_p50 = median(&ratios);
    let mean = ratios.iter().sum::<f64>() / ratios.len() as f64;
    let variance = ratios
        .iter()
        .map(|ratio| {
            let delta = ratio - mean;
            delta * delta
        })
        .sum::<f64>()
        / (ratios.len() - 1) as f64;
    let deviations = ratios
        .iter()
        .map(|ratio| (ratio - ratio_p50).abs())
        .collect::<Vec<_>>();

    PairedStats {
        p50_a_ns: median(&times_a),
        p50_b_ns: median(&times_b),
        p50_a_ci: bootstrap_median_ci(&times_a, BOOTSTRAP_SEED ^ 0xA11C_E001),
        p50_b_ci: bootstrap_median_ci(&times_b, BOOTSTRAP_SEED ^ 0xB11C_E002),
        ratio_p50,
        ratio_ci: bootstrap_median_ci(&ratios, BOOTSTRAP_SEED ^ 0xAB11_CE03),
        cv_pct: variance.sqrt() / mean * 100.0,
        mad: median(&deviations),
        checksum,
    }
}

fn print_stats(label: &str, stats: &PairedStats) {
    println!(
        "{label},rounds={ROUNDS},min_of={MIN_OF},p50_a_ns={:.0},p50_b_ns={:.0},p50_a_ci95_ns=[{:.0},{:.0}],p50_b_ci95_ns=[{:.0},{:.0}],ratio_p50={:.6},ratio_ci95=[{:.6},{:.6}],cv_pct={:.3},mad={:.6},checksum={:016x}",
        stats.p50_a_ns,
        stats.p50_b_ns,
        stats.p50_a_ci.0,
        stats.p50_a_ci.1,
        stats.p50_b_ci.0,
        stats.p50_b_ci.1,
        stats.ratio_p50,
        stats.ratio_ci.0,
        stats.ratio_ci.1,
        stats.cv_pct,
        stats.mad,
        stats.checksum,
    );
}

fn main() {
    println!("bench_elf_sha256={}", self_identity());

    let baseline = restart_at_zero_allocs();
    let candidate = cursor_allocs();
    assert_eq!(
        baseline, candidate,
        "cursor changed sequential inode allocation results"
    );
    println!(
        "behavior_parity=exact,sequence_checksum={:016x},bitmap_bytes={}",
        baseline.0,
        baseline.1.len()
    );

    let batch = calibrate_batch();
    println!(
        "bench_config=batch={batch},rounds={ROUNDS},min_sample_ns={MIN_SAMPLE_NS},min_of={MIN_OF},bootstrap_resamples={BOOTSTRAP_RESAMPLES},bootstrap_seed={BOOTSTRAP_SEED:016x}"
    );

    let null = paired(Arm::Baseline, Arm::Baseline, batch);
    let real = paired(Arm::Baseline, Arm::Candidate, batch);
    print_stats("null_base_base", &null);
    print_stats("real_base_candidate", &real);

    let null_half_width = (null.ratio_ci.0 - 1.0)
        .abs()
        .max((null.ratio_ci.1 - 1.0).abs());
    let effect = if real.ratio_p50 >= 1.0 {
        real.ratio_p50 - 1.0
    } else {
        real.ratio_p50.recip() - 1.0
    };
    let outside_null_ci = real.ratio_p50 < null.ratio_ci.0 || real.ratio_p50 > null.ratio_ci.1;
    let decisive = outside_null_ci && effect >= 2.0 * null_half_width;
    let direction = if real.ratio_p50 >= 1.0 {
        "candidate_faster"
    } else {
        "baseline_faster"
    };
    println!(
        "median_ci_gate={},direction={direction},effect={effect:.6},null_half_width={null_half_width:.6},required_2x_margin={:.6},cv_is_provenance_only=true",
        if decisive { "decidable" } else { "unresolved" },
        2.0 * null_half_width
    );
}
