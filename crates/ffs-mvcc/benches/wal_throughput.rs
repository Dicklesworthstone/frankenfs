#![forbid(unsafe_code)]
#![allow(
    clippy::cast_precision_loss,
    clippy::significant_drop_tightening,
    clippy::too_many_arguments,
    clippy::map_unwrap_or,
    clippy::semicolon_if_nothing_returned
)]

//! WAL throughput and MVCC/EBR benchmark surface.
//!
//! Includes:
//! - WAL commit throughput microbenchmarks
//! - FCW vs SSI overhead microbenchmarks
//! - EBR memory-behavior scenario report (JSON artifact)

use asupersync::Cx;
use criterion::{BenchmarkId, Criterion, criterion_group};
use ffs_mvcc::compression::VersionData;
use ffs_mvcc::persist::{PersistOptions, PersistentMvccStore};
use ffs_mvcc::wal::{self, RECORD_TYPE_COMMIT, WalCommit, WalWrite};
use ffs_mvcc::{
    BlockVersion, CompressionAlgo, CompressionPolicy, ConflictPolicy, MergeProof, MvccStore,
};
use ffs_types::{BlockNumber, CommitSeq, TxnId};
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use serde::Serialize;
#[cfg(feature = "bench-instrumentation")]
use sha2::{Digest, Sha256};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::collections::BTreeSet;
// Aliased: `std::io::Write` below owns the bare name, and importing both traits
// unaliased makes the whole `bench-instrumentation` build fail to compile.
#[cfg(feature = "bench-instrumentation")]
use std::fmt::Write as FmtWrite;
use std::fs;
use std::hint::black_box;
#[cfg(feature = "bench-instrumentation")]
use std::io::Read;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
#[cfg(feature = "bench-instrumentation")]
use std::process::{Command, Stdio};
#[cfg(feature = "bench-instrumentation")]
use std::sync::Barrier;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
#[cfg(feature = "bench-instrumentation")]
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

#[cfg(feature = "bench-instrumentation")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "bench-instrumentation")]
#[derive(Default, Clone, Copy)]
struct ArenaCounters {
    num_ops: u64,
    num_spin_acq: u64,
    num_wait: u64,
    total_wait_time: u64,
    num_owner_switch: u64,
}

#[cfg(feature = "bench-instrumentation")]
impl ArenaCounters {
    fn saturating_delta(self, before: Self) -> Self {
        Self {
            num_ops: self.num_ops.saturating_sub(before.num_ops),
            num_spin_acq: self.num_spin_acq.saturating_sub(before.num_spin_acq),
            num_wait: self.num_wait.saturating_sub(before.num_wait),
            total_wait_time: self.total_wait_time.saturating_sub(before.total_wait_time),
            num_owner_switch: self
                .num_owner_switch
                .saturating_sub(before.num_owner_switch),
        }
    }

    fn merge(&mut self, other: Self) {
        self.num_ops = self.num_ops.saturating_add(other.num_ops);
        self.num_spin_acq = self.num_spin_acq.saturating_add(other.num_spin_acq);
        self.num_wait = self.num_wait.saturating_add(other.num_wait);
        self.total_wait_time = self.total_wait_time.saturating_add(other.total_wait_time);
        self.num_owner_switch = self.num_owner_switch.saturating_add(other.num_owner_switch);
    }
}

#[cfg(feature = "bench-instrumentation")]
struct ActualArmObservation {
    elapsed_ns: u64,
    profile: ffs_mvcc::sharded::CommitLockProfile,
    commits: u64,
    arena: ArenaCounters,
}

#[cfg(feature = "bench-instrumentation")]
struct ActualNullPair {
    lhs: ActualArmObservation,
    rhs: ActualArmObservation,
    order: &'static str,
}

#[cfg(feature = "bench-instrumentation")]
fn median(mut values: Vec<f64>) -> f64 {
    assert!(!values.is_empty(), "median requires at least one sample");
    values.sort_by(f64::total_cmp);
    let midpoint = values.len() / 2;
    if values.len() % 2 == 0 {
        values[midpoint - 1].midpoint(values[midpoint])
    } else {
        values[midpoint]
    }
}

#[cfg(feature = "bench-instrumentation")]
fn population_cv_pct(values: &[f64]) -> f64 {
    assert!(!values.is_empty(), "CV requires at least one sample");
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    if mean == 0.0 {
        return 0.0;
    }
    let variance = values
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / values.len() as f64;
    variance.sqrt() / mean * 100.0
}

#[cfg(feature = "bench-instrumentation")]
fn p90(mut values: Vec<f64>) -> f64 {
    assert!(!values.is_empty(), "p90 requires at least one sample");
    values.sort_by(f64::total_cmp);
    let rank = values.len().saturating_mul(90).div_ceil(100);
    values[rank.saturating_sub(1)]
}

#[cfg(feature = "bench-instrumentation")]
fn collect_arena_counters(value: &serde_json::Value, out: &mut ArenaCounters) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                match key.as_str() {
                    "num_ops" => {
                        out.num_ops = out.num_ops.saturating_add(child.as_u64().unwrap_or(0))
                    }
                    "num_spin_acq" => {
                        out.num_spin_acq =
                            out.num_spin_acq.saturating_add(child.as_u64().unwrap_or(0));
                    }
                    "num_wait" => {
                        out.num_wait = out.num_wait.saturating_add(child.as_u64().unwrap_or(0))
                    }
                    "total_wait_time" => {
                        out.total_wait_time = out
                            .total_wait_time
                            .saturating_add(child.as_u64().unwrap_or(0));
                    }
                    "num_owner_switch" => {
                        out.num_owner_switch = out
                            .num_owner_switch
                            .saturating_add(child.as_u64().unwrap_or(0));
                    }
                    _ => collect_arena_counters(child, out),
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_arena_counters(item, out);
            }
        }
        _ => {}
    }
}

#[cfg(feature = "bench-instrumentation")]
fn arena_counters() -> ArenaCounters {
    let _ = tikv_jemalloc_ctl::epoch::advance();
    let mut options = tikv_jemalloc_ctl::stats_print::Options::default();
    options.json_format = true;
    options.skip_constants = true;
    options.skip_per_arena = true;
    let mut bytes = Vec::with_capacity(1 << 20);
    tikv_jemalloc_ctl::stats_print::stats_print(&mut bytes, options).expect("jemalloc stats_print");
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("jemalloc JSON");
    let mut counters = ArenaCounters::default();
    collect_arena_counters(&json, &mut counters);
    counters
}

#[cfg(feature = "bench-instrumentation")]
fn print_bench_evidence_metadata() {
    let exe = std::env::current_exe().expect("bench executable");
    let mut file = fs::File::open(&exe).expect("open bench executable for hashing");
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let bytes_read = file.read(&mut buffer).expect("hash bench executable");
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    let worker = Command::new("hostname")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|hostname| !hostname.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    let digest = hasher.finalize();
    let mut sha256 = String::with_capacity(digest.len().saturating_mul(2));
    for byte in digest {
        write!(&mut sha256, "{byte:02x}").expect("format bench executable hash");
    }
    println!("bench_evidence,binary_sha256={sha256},worker={worker}");
}

#[cfg(all(feature = "bench-instrumentation", target_arch = "x86_64"))]
fn print_codegen_isa() {
    println!(
        "codegen_isa,target_arch=x86_64,compile_sse2={},compile_sse4_2={},compile_avx2={},runtime_sse4_2={},runtime_avx2={}",
        cfg!(target_feature = "sse2"),
        cfg!(target_feature = "sse4.2"),
        cfg!(target_feature = "avx2"),
        std::is_x86_feature_detected!("sse4.2"),
        std::is_x86_feature_detected!("avx2"),
    );
}

#[cfg(all(feature = "bench-instrumentation", not(target_arch = "x86_64")))]
fn print_codegen_isa() {
    println!("codegen_isa,target_arch=non_x86_64");
}

#[cfg(feature = "bench-instrumentation")]
fn run_actual_commit_arm(
    writers: usize,
    profiled: bool,
    mode: ffs_mvcc::sharded::PublicationMode,
) -> (Duration, ffs_mvcc::sharded::CommitLockProfile, u64) {
    use ffs_mvcc::sharded::{CommitLockProfile, ShardedMvccStore};
    const OPS: u64 = 256;
    let shard_count = 16_usize;
    let shard_stride = u64::try_from(shard_count).expect("benchmark shard count must fit u64");
    let store = Arc::new(ShardedMvccStore::with_publication_mode(shard_count, mode));
    let start_gate = Arc::new(Barrier::new(writers));
    let mut handles = Vec::with_capacity(writers);
    for writer in 0..writers {
        let writer = u64::try_from(writer).expect("benchmark writer index must fit u64");
        let store = Arc::clone(&store);
        let start_gate = Arc::clone(&start_gate);
        handles.push(thread::spawn(move || {
            let mut profile = CommitLockProfile::default();
            start_gate.wait();
            let start = Instant::now();
            for i in 0..OPS {
                let block = BlockNumber(i.saturating_mul(shard_stride).saturating_add(writer));
                let mut txn = store.begin();
                txn.stage_write(block, vec![0xAB; 4096]);
                if profiled {
                    store
                        .commit_profiled(txn, &mut profile)
                        .expect("profiled commit");
                } else {
                    store.commit(txn).expect("commit");
                }
            }
            (start.elapsed(), profile)
        }));
    }
    let mut elapsed = Duration::ZERO;
    let mut merged = ffs_mvcc::sharded::CommitLockProfile::default();
    for handle in handles {
        let (thread_elapsed, profile) = handle.join().expect("commit worker");
        elapsed = elapsed.max(thread_elapsed);
        merged.merge(&profile);
    }
    let committed = store.current_snapshot().high.0;
    assert_eq!(committed, OPS.saturating_mul(writers as u64));
    (elapsed, merged, committed)
}

#[cfg(feature = "bench-instrumentation")]
fn observe_actual_commit_arm(
    writers: usize,
    mode: ffs_mvcc::sharded::PublicationMode,
    profiled: bool,
) -> ActualArmObservation {
    const BATCHES_PER_ARM: usize = 16;
    let before = arena_counters();
    let mut elapsed_ns = 0_u64;
    let mut profile = ffs_mvcc::sharded::CommitLockProfile::default();
    let mut commits = 0_u64;
    for _ in 0..BATCHES_PER_ARM {
        let (elapsed, batch_profile, batch_commits) = black_box(run_actual_commit_arm(
            black_box(writers),
            black_box(profiled),
            black_box(mode),
        ));
        elapsed_ns =
            elapsed_ns.saturating_add(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX));
        profile.merge(&batch_profile);
        commits = commits.saturating_add(batch_commits);
    }
    let after = arena_counters();
    ActualArmObservation {
        elapsed_ns,
        profile,
        commits,
        arena: after.saturating_delta(before),
    }
}

/// Commit a deterministic multi-writer workload under `mode` and return the
/// final publication watermark plus a SHA-256 over every block's resolved bytes
/// at that watermark, in block order.
///
/// Each block is written by exactly one writer with a payload derived from
/// `(writer, index)`, so the correct final content is fixed and independent of
/// interleaving — any divergence is a real publication-visibility defect, not a
/// benign scheduling difference.
#[cfg(feature = "bench-instrumentation")]
fn publication_mode_content_digest(
    mode: ffs_mvcc::sharded::PublicationMode,
    writers: usize,
) -> (u64, String) {
    use ffs_mvcc::sharded::ShardedMvccStore;
    const OPS: u64 = 256;
    const BLOCK_LEN: usize = 4096;
    let shard_count = 16_usize;
    let shard_stride = u64::try_from(shard_count).expect("shard count fits u64");
    let store = Arc::new(ShardedMvccStore::with_publication_mode(shard_count, mode));
    let start_gate = Arc::new(Barrier::new(writers));
    let mut handles = Vec::with_capacity(writers);
    for writer in 0..writers {
        let writer = u64::try_from(writer).expect("writer index fits u64");
        let store = Arc::clone(&store);
        let start_gate = Arc::clone(&start_gate);
        handles.push(thread::spawn(move || {
            start_gate.wait();
            for i in 0..OPS {
                let block = BlockNumber(i.saturating_mul(shard_stride).saturating_add(writer));
                let mut payload = vec![0_u8; BLOCK_LEN];
                for (offset, byte) in payload.iter_mut().enumerate() {
                    *byte = (block.0 ^ (offset as u64).rotate_left(3) ^ i) as u8;
                }
                let mut txn = store.begin();
                txn.stage_write(block, payload);
                store.commit(txn).expect("identity-proof commit");
            }
        }));
    }
    for handle in handles {
        handle.join().expect("identity-proof writer");
    }

    let snapshot = store.current_snapshot();
    let mut hasher = Sha256::new();
    for i in 0..OPS {
        for writer in 0..u64::try_from(writers).expect("writers fits u64") {
            let block = BlockNumber(i.saturating_mul(shard_stride).saturating_add(writer));
            let bytes = store
                .read_visible(block, snapshot)
                .expect("every committed block resolves at the final watermark");
            hasher.update(block.0.to_le_bytes());
            hasher.update(&bytes);
        }
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len().saturating_mul(2));
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("format digest");
    }
    (snapshot.high.0, hex)
}

/// Behavior gate, run BEFORE any timing: the two publication modes must produce
/// an identical final watermark and identical resolved bytes for every block.
#[cfg(feature = "bench-instrumentation")]
fn assert_publication_mode_isomorphism() {
    use ffs_mvcc::sharded::PublicationMode;
    for writers in [1_usize, 2, 4, 8] {
        let (mutex_high, mutex_digest) =
            publication_mode_content_digest(PublicationMode::Mutex, writers);
        let (wait_free_high, wait_free_digest) =
            publication_mode_content_digest(PublicationMode::WaitFree, writers);
        assert_eq!(
            mutex_high, wait_free_high,
            "publication watermark diverged at {writers} writers"
        );
        assert_eq!(
            mutex_digest, wait_free_digest,
            "resolved block content diverged at {writers} writers"
        );
        println!(
            "publication_mode_isomorphism,threads={writers},watermark={mutex_high},sha256={mutex_digest},result=identical"
        );
    }
}

#[cfg(feature = "bench-instrumentation")]
fn print_actual_null_control() {
    use ffs_mvcc::sharded::PublicationMode;
    // A/A on the production gate, then the A/B against the wait-free gate, both
    // from THIS binary (see `bench_evidence,binary_sha256`) so codegen cannot
    // differ between arms. Campaign 2026-07-25 section 2.2: print both, always.
    // Profiled arms: per-phase publication p99s (attribution). The six
    // `Instant::now()` probes per commit are paid by BOTH arms, so they cancel
    // in the ratio but dilute its magnitude — the unprofiled pass below is the
    // decision measurement.
    for writers in [1_usize, 2, 4, 8] {
        run_paired_arms(
            writers,
            "profiled_aa",
            PublicationMode::Mutex,
            PublicationMode::Mutex,
            true,
        );
        run_paired_arms(
            writers,
            "profiled_publication_gate_ab",
            PublicationMode::Mutex,
            PublicationMode::WaitFree,
            true,
        );
    }
    // Unprofiled arms: the production commit path with no instrumentation. A/A
    // null first, then the A/B, at every thread count.
    for writers in [1_usize, 2, 4, 8] {
        run_paired_arms(
            writers,
            "unprofiled_aa",
            PublicationMode::Mutex,
            PublicationMode::Mutex,
            false,
        );
        run_paired_arms(
            writers,
            "unprofiled_publication_gate_ab",
            PublicationMode::Mutex,
            PublicationMode::WaitFree,
            false,
        );
    }
}

/// Interleave two arms inside one round, alternating which runs first, and
/// report the median of per-round ratios. With both modes equal this is the A/A
/// null floor; with `rhs` set to the candidate it is the decision A/B.
#[cfg(feature = "bench-instrumentation")]
fn run_paired_arms(
    writers: usize,
    phase: &str,
    lhs_mode: ffs_mvcc::sharded::PublicationMode,
    rhs_mode: ffs_mvcc::sharded::PublicationMode,
    profiled: bool,
) {
    const PAIRS: usize = 31;
    let mut pairs = Vec::with_capacity(PAIRS);
    for pair_index in 0..PAIRS {
        let (lhs, rhs, order) = if pair_index % 2 == 0 {
            (
                observe_actual_commit_arm(writers, lhs_mode, profiled),
                observe_actual_commit_arm(writers, rhs_mode, profiled),
                "AB",
            )
        } else {
            let rhs = observe_actual_commit_arm(writers, rhs_mode, profiled);
            let lhs = observe_actual_commit_arm(writers, lhs_mode, profiled);
            (lhs, rhs, "BA")
        };
        if profiled {
            let lhs_shard_wait = lhs.profile.shard_wait();
            let rhs_shard_wait = rhs.profile.shard_wait();
            assert_eq!(lhs_shard_wait.samples, lhs.commits);
            assert_eq!(lhs.profile.publication_total().samples, lhs.commits);
            assert_eq!(rhs_shard_wait.samples, rhs.commits);
            assert_eq!(rhs.profile.publication_total().samples, rhs.commits);
        }
        // Behavior gate: both gates must retire exactly the same number of
        // commits in the same workload, or the ratio below is meaningless.
        assert_eq!(
            lhs.commits, rhs.commits,
            "arms retired different commit counts at {writers} writers"
        );
        pairs.push(ActualNullPair { lhs, rhs, order });
    }
    print_actual_null_summary(writers, phase, &pairs);
}

#[cfg(feature = "bench-instrumentation")]
fn print_actual_null_summary(writers: usize, phase: &str, pairs: &[ActualNullPair]) {
    let lhs_elapsed = pairs
        .iter()
        .map(|pair| pair.lhs.elapsed_ns as f64)
        .collect::<Vec<_>>();
    let rhs_elapsed = pairs
        .iter()
        .map(|pair| pair.rhs.elapsed_ns as f64)
        .collect::<Vec<_>>();
    let log_ratios = pairs
        .iter()
        .map(|pair| (pair.lhs.elapsed_ns as f64 / pair.rhs.elapsed_ns as f64).ln())
        .collect::<Vec<_>>();
    let center = median(log_ratios.clone());
    let spread = p90(log_ratios
        .iter()
        .map(|ratio| (ratio - center).abs())
        .collect());
    let mut lhs_profile = ffs_mvcc::sharded::CommitLockProfile::default();
    let mut rhs_profile = ffs_mvcc::sharded::CommitLockProfile::default();
    let mut lhs_arena = ArenaCounters::default();
    let mut rhs_arena = ArenaCounters::default();
    for pair in pairs {
        lhs_profile.merge(&pair.lhs.profile);
        rhs_profile.merge(&pair.rhs.profile);
        lhs_arena.merge(pair.lhs.arena);
        rhs_arena.merge(pair.rhs.arena);
    }
    let ab_pairs = pairs.iter().filter(|pair| pair.order == "AB").count();
    let ba_pairs = pairs.len().saturating_sub(ab_pairs);
    let mut raw_pairs = String::with_capacity(pairs.len().saturating_mul(48));
    for (index, pair) in pairs.iter().enumerate() {
        if index > 0 {
            raw_pairs.push(';');
        }
        write!(
            &mut raw_pairs,
            "{}:{}:{}",
            pair.order, pair.lhs.elapsed_ns, pair.rhs.elapsed_ns
        )
        .expect("format raw A/A pair");
    }
    println!(
        "actual_commit_null_pairs,threads={writers},phase={phase},batches_per_arm=16,format=order:lhs_ns:rhs_ns,values={raw_pairs}"
    );
    println!(
        "actual_commit_null_summary,threads={writers},phase={phase},pairs={},batches_per_arm=16,ab_pairs={ab_pairs},ba_pairs={ba_pairs},lhs_median_ms={:.6},rhs_median_ms={:.6},lhs_cv_pct={:.3},rhs_cv_pct={:.3},null_median_ratio={:.6},null_spread_p90_ratio={:.6},null_floor_ratio={:.6},lhs_shard_wait_p99_ns={},rhs_shard_wait_p99_ns={},lhs_shard_hold_p99_ns={},rhs_shard_hold_p99_ns={},lhs_publish_wait_p99_ns={},rhs_publish_wait_p99_ns={},lhs_publish_hold_p99_ns={},rhs_publish_hold_p99_ns={},lhs_prefix_wait_p99_ns={},rhs_prefix_wait_p99_ns={},lhs_arena_num_ops={},rhs_arena_num_ops={},lhs_arena_spin_acq={},rhs_arena_spin_acq={},lhs_arena_num_wait={},rhs_arena_num_wait={},lhs_arena_wait_ns={},rhs_arena_wait_ns={},lhs_arena_owner_switch={},rhs_arena_owner_switch={},decomposition_gate=not_applicable",
        pairs.len(),
        median(lhs_elapsed.clone()) / 1e6,
        median(rhs_elapsed.clone()) / 1e6,
        population_cv_pct(&lhs_elapsed),
        population_cv_pct(&rhs_elapsed),
        center.exp(),
        spread.exp(),
        (center.abs() + spread).exp(),
        lhs_profile.shard_wait().p99_upper_ns,
        rhs_profile.shard_wait().p99_upper_ns,
        lhs_profile.shard_hold().p99_upper_ns,
        rhs_profile.shard_hold().p99_upper_ns,
        lhs_profile.publication_lock_wait().p99_upper_ns,
        rhs_profile.publication_lock_wait().p99_upper_ns,
        lhs_profile.publication_lock_hold().p99_upper_ns,
        rhs_profile.publication_lock_hold().p99_upper_ns,
        lhs_profile.publication_prefix_wait().p99_upper_ns,
        rhs_profile.publication_prefix_wait().p99_upper_ns,
        lhs_arena.num_ops,
        rhs_arena.num_ops,
        lhs_arena.num_spin_acq,
        rhs_arena.num_spin_acq,
        lhs_arena.num_wait,
        rhs_arena.num_wait,
        lhs_arena.total_wait_time,
        rhs_arena.total_wait_time,
        lhs_arena.num_owner_switch,
        rhs_arena.num_owner_switch,
    );
}

#[cfg(feature = "bench-instrumentation")]
fn profile_only() {
    // POST-LEVER frontier: profile the wait-free gate only, so the frame table
    // answers "what is the next serialization point now that the publication
    // mutex is gone" rather than re-measuring the mutex path we already know.
    use ffs_mvcc::sharded::PublicationMode;
    for _ in 0..4 {
        let _ = run_actual_commit_arm(8, false, PublicationMode::WaitFree);
    }
}

#[cfg(feature = "bench-instrumentation")]
fn profile_self_time_pct(report: &str, symbol: &str) -> Option<f64> {
    report
        .lines()
        .filter(|line| line.contains(symbol))
        .filter_map(|line| {
            line.split_whitespace().find_map(|field| {
                field
                    .strip_suffix('%')
                    .and_then(|percent| percent.parse::<f64>().ok())
            })
        })
        .reduce(f64::max)
}

#[cfg(feature = "bench-instrumentation")]
fn spawn_profile_report() {
    let exe = std::env::current_exe().expect("bench executable");
    let executable_name = exe
        .file_name()
        .and_then(|name| name.to_str())
        .expect("bench executable file name");
    let record = Command::new("perf")
        .args([
            "record",
            "-q",
            "-F",
            "999",
            "-g",
            "--call-graph",
            "fp",
            "-o",
            "-",
        ])
        .arg("--")
        .arg(&exe)
        .arg("--profile-only")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn();
    let Ok(mut record) = record else {
        println!("profile_blocker=perf_record_unavailable");
        return;
    };
    let perf_data = record.stdout.take().expect("perf pipe");
    let report = Command::new("perf")
        .args([
            "report",
            "-q",
            "--stdio",
            "--no-children",
            "-i",
            "-",
            "--percent-limit",
            "0",
            "--dsos",
        ])
        .arg(executable_name)
        .env("DEBUGINFOD_URLS", "")
        .stdin(Stdio::from(perf_data))
        .output();
    let Ok(report) = report else {
        println!("profile_blocker=perf_report_unavailable");
        let _ = record.wait();
        return;
    };
    let Ok(status) = record.wait() else {
        println!("profile_blocker=perf_record_wait_failed");
        return;
    };
    let text = String::from_utf8_lossy(&report.stdout);
    println!("profile_frame_table_begin\n{text}profile_frame_table_end");
    // Compact top-frame line so the frontier survives any log truncation.
    let mut frames: Vec<(f64, String)> = text
        .lines()
        .filter(|line| line.trim_start().starts_with(|c: char| c.is_ascii_digit()))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pct = fields.next()?.strip_suffix('%')?.parse::<f64>().ok()?;
            let symbol = line.split("] ").nth(1).unwrap_or("?").trim();
            Some((pct, symbol.chars().take(70).collect::<String>()))
        })
        .collect();
    frames.sort_by(|a, b| b.0.total_cmp(&a.0));
    frames.truncate(15);
    let mut top = String::new();
    for (pct, symbol) in &frames {
        if !top.is_empty() {
            top.push(';');
        }
        write!(&mut top, "{pct:.2}%={symbol}").expect("format top frame");
    }
    println!("profile_top_frames,mode=wait_free,threads=8,frames={top}");
    if !status.success() || !report.status.success() {
        println!(
            "profile_blocker=perf_permission_denied record_status={status} report_status={}",
            report.status
        );
    } else if let (Some(commit_pct), Some(publish_pct)) = (
        profile_self_time_pct(&text, "commit_with_probe"),
        profile_self_time_pct(&text, "publish_with_probe"),
    ) && commit_pct > 0.0
        && publish_pct > 0.0
    {
        println!(
            "profile_target_self_time,commit_with_probe_pct={commit_pct:.6},publish_with_probe_pct={publish_pct:.6},verified_nonzero=true"
        );
    } else {
        println!("profile_blocker=target_self_time_not_resolved");
    }
}

fn bench_wal_commit_throughput(c: &mut Criterion) {
    let cx = Cx::for_testing();

    // 4 KiB block — typical filesystem block size.
    let block_data = vec![0xAB_u8; 4096];

    c.bench_function("wal_commit_4k_sync", |b| {
        let tmp = NamedTempFile::new().expect("temp file");
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();

        let store = PersistentMvccStore::open_with_options(&cx, &path, &PersistOptions::default())
            .expect("open");

        let mut block_id = 0_u64;

        b.iter(|| {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(block_id % 1024), block_data.clone());
            store.commit(txn).expect("commit");
            block_id += 1;
        });
    });

    c.bench_function("wal_commit_4k_nosync", |b| {
        let tmp = NamedTempFile::new().expect("temp file");
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();

        let store = PersistentMvccStore::open_with_options(
            &cx,
            &path,
            &PersistOptions {
                sync_on_commit: false,
                ..PersistOptions::default()
            },
        )
        .expect("open");

        let mut block_id = 0_u64;

        b.iter(|| {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(block_id % 1024), block_data.clone());
            store.commit(txn).expect("commit");
            block_id += 1;
        });
    });

    // Multi-write commit: 4 blocks per transaction.
    c.bench_function("wal_commit_4x4k_nosync", |b| {
        let tmp = NamedTempFile::new().expect("temp file");
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();

        let store = PersistentMvccStore::open_with_options(
            &cx,
            &path,
            &PersistOptions {
                sync_on_commit: false,
                ..PersistOptions::default()
            },
        )
        .expect("open");

        let mut block_id = 0_u64;

        b.iter(|| {
            let mut txn = store.begin();
            for j in 0..4_u64 {
                txn.stage_write(BlockNumber((block_id + j) % 4096), block_data.clone());
            }
            store.commit(txn).expect("commit");
            block_id += 4;
        });
    });
}

fn encode_commit_zeroed_control(commit: &WalCommit) -> Vec<u8> {
    let data_size = commit
        .writes
        .iter()
        .map(|write| 8 + 4 + write.data.len())
        .sum::<usize>();
    let body_size = 1 + 8 + 8 + 4 + data_size + 4;
    let total_size = 4 + body_size;
    let mut buf = vec![0_u8; total_size];
    let mut offset = 0_usize;

    let record_len = u32::try_from(body_size).expect("fixture record length fits u32");
    buf[offset..offset + 4].copy_from_slice(&record_len.to_le_bytes());
    offset += 4;
    buf[offset] = RECORD_TYPE_COMMIT;
    offset += 1;
    buf[offset..offset + 8].copy_from_slice(&commit.commit_seq.0.to_le_bytes());
    offset += 8;
    buf[offset..offset + 8].copy_from_slice(&commit.txn_id.0.to_le_bytes());
    offset += 8;
    let num_writes = u32::try_from(commit.writes.len()).expect("fixture write count fits u32");
    buf[offset..offset + 4].copy_from_slice(&num_writes.to_le_bytes());
    offset += 4;

    for write in &commit.writes {
        buf[offset..offset + 8].copy_from_slice(&write.block.0.to_le_bytes());
        offset += 8;
        let data_len = u32::try_from(write.data.len()).expect("fixture write length fits u32");
        buf[offset..offset + 4].copy_from_slice(&data_len.to_le_bytes());
        offset += 4;
        buf[offset..offset + write.data.len()].copy_from_slice(&write.data);
        offset += write.data.len();
    }

    let crc = crc32c::crc32c(&buf[4..offset]);
    buf[offset..offset + 4].copy_from_slice(&crc.to_le_bytes());
    buf
}

fn bench_wal_encode_zero_fill_elision_ab(c: &mut Criterion) {
    let commit = WalCommit {
        commit_seq: CommitSeq(0x1020_3040_5060_7080),
        txn_id: TxnId(0x8877_6655_4433_2211),
        writes: (0_u64..32)
            .map(|index| WalWrite {
                block: BlockNumber(0x1000 + index),
                data: vec![index as u8; 4096],
            })
            .collect(),
    };

    let frozen = encode_commit_zeroed_control(&commit);
    let appended = wal::encode_commit(&commit).expect("encode fixture");
    assert_eq!(
        appended, frozen,
        "sequential encoder must be byte-identical"
    );

    let mut group = c.benchmark_group("wal_encode_zero_fill_elision_32x4k");
    for control in ["zeroed_offsets_a", "zeroed_offsets_b"] {
        group.bench_function(control, |b| {
            b.iter(|| black_box(encode_commit_zeroed_control(black_box(&commit))));
        });
    }
    group.bench_function("exact_capacity_append", |b| {
        b.iter(|| {
            black_box(wal::encode_commit(black_box(&commit)).expect("encode benchmark fixture"))
        });
    });
    group.finish();
}

/// Isolate the WAL append syscall primitive: the former seek+write pair versus
/// the positioned write used by `WalWriter::raw_append`.
fn bench_wal_positioned_append(c: &mut Criterion) {
    const RECORD_SIZE: usize = 256;
    const RECORD_SIZE_U64: u64 = 256;
    const APPENDS_PER_ITER: u64 = 512;
    const WINDOW_RECORDS: u64 = 4096;
    const WINDOW_BYTES: u64 = RECORD_SIZE_U64 * WINDOW_RECORDS;

    let record = (0_u8..=u8::MAX)
        .map(|index| index.wrapping_mul(31).wrapping_add(7))
        .collect::<Vec<_>>();

    // Prove both syscall shapes deposit exactly the same bytes before timing.
    let mut seek_write = tempfile::tempfile().expect("seek+write parity file");
    let positioned = tempfile::tempfile().expect("positioned parity file");
    let parity_offset = RECORD_SIZE_U64 * 17;
    seek_write
        .seek(SeekFrom::Start(parity_offset))
        .expect("seek parity offset");
    seek_write.write_all(&record).expect("seek+write parity");
    positioned
        .write_all_at(&record, parity_offset)
        .expect("positioned parity write");
    let mut seek_write_bytes = vec![0_u8; RECORD_SIZE];
    let mut positioned_bytes = vec![0_u8; RECORD_SIZE];
    seek_write
        .read_exact_at(&mut seek_write_bytes, parity_offset)
        .expect("read seek+write parity bytes");
    positioned
        .read_exact_at(&mut positioned_bytes, parity_offset)
        .expect("read positioned parity bytes");
    assert_eq!(seek_write_bytes, positioned_bytes);
    assert_eq!(positioned_bytes, record);

    let mut group = c.benchmark_group("wal_raw_append_positioned_256b");
    group.sample_size(30);
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(3));
    group.throughput(criterion::Throughput::Elements(APPENDS_PER_ITER));

    for control in ["seek_write_control_a", "seek_write_control_b"] {
        group.bench_function(control, |b| {
            let mut file = tempfile::tempfile().expect("seek+write benchmark file");
            file.set_len(WINDOW_BYTES).expect("size benchmark file");
            let mut offset = 0_u64;
            b.iter(|| {
                for _ in 0..APPENDS_PER_ITER {
                    file.seek(SeekFrom::Start(offset)).expect("seek append");
                    file.write_all(black_box(&record)).expect("write append");
                    offset += RECORD_SIZE_U64;
                    if offset == WINDOW_BYTES {
                        offset = 0;
                    }
                }
                black_box(offset);
            });
        });
    }

    group.bench_function("positioned_write_candidate", |b| {
        let file = tempfile::tempfile().expect("positioned benchmark file");
        file.set_len(WINDOW_BYTES).expect("size benchmark file");
        let mut offset = 0_u64;
        b.iter(|| {
            for _ in 0..APPENDS_PER_ITER {
                file.write_all_at(black_box(&record), offset)
                    .expect("positioned append");
                offset += RECORD_SIZE_U64;
                if offset == WINDOW_BYTES {
                    offset = 0;
                }
            }
            black_box(offset);
        });
    });
    group.finish();
}

fn setup_ssi_pivot_192reads_32records(block_data: &[u8]) -> (MvccStore, ffs_mvcc::Transaction) {
    let mut store = MvccStore::new();
    let mut pivot = store.begin();
    for r in 0..192_u64 {
        pivot.record_read(BlockNumber(r), CommitSeq(1));
    }
    pivot.stage_write(BlockNumber(1_000_000), block_data.to_vec());
    for k in 0..32_u64 {
        let mut w = store.begin();
        let base = 10_000 + k * 1_000;
        for r in 0..192_u64 {
            w.record_read(BlockNumber(base + r), CommitSeq(1));
        }
        w.stage_write(BlockNumber(2_000_000 + k), block_data.to_vec());
        store.commit_ssi(w).expect("seed concurrent record");
    }
    (store, pivot)
}

/// Compare FCW vs SSI commit cost to verify read-set tracking overhead.
fn bench_ssi_overhead(c: &mut Criterion) {
    use ffs_types::CommitSeq;

    let block_data = vec![0xAB_u8; 4096];

    // FCW commit (no read-set tracking).
    c.bench_function("mvcc_commit_fcw", |b| {
        let mut store = MvccStore::new();
        let mut block_id = 0_u64;

        b.iter(|| {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(block_id % 1024), block_data.clone());
            store.commit(txn).expect("commit");
            block_id += 1;
        });
    });

    // SSI commit with 5-block read-set per transaction.
    c.bench_function("mvcc_commit_ssi_5reads", |b| {
        let mut store = MvccStore::new();
        let mut block_id = 0_u64;

        // Seed some blocks so reads have versions.
        for i in 0_u64..1024 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(i), block_data.clone());
            store.commit_ssi(txn).expect("seed");
        }

        b.iter(|| {
            let mut txn = store.begin();
            // Record 5 reads.
            for r in 0..5_u64 {
                txn.record_read(BlockNumber((block_id + r) % 1024), CommitSeq(1));
            }
            txn.stage_write(BlockNumber(block_id % 1024), block_data.clone());
            store.commit_ssi(txn).expect("commit");
            block_id += 1;
        });
    });

    // Read-heavy SSI pivot scanned against many concurrent committed records —
    // the case the smaller-set rw-antidependency edge intersection targets
    // (perf: SSI edge detection iterates the smaller set). The pivot begins
    // first (so the records land after its snapshot and detect scans them all),
    // reads 192 blocks but writes 1; each of the 32 concurrent records is the
    // mirror (read-heavy, single disjoint write) so no dangerous structure forms
    // and detect scans every record fully (no early exit). The per-record edge
    // cost drops from O(192) to O(1).
    c.bench_function("mvcc_commit_ssi_pivot_192reads_32records", |b| {
        use criterion::BatchSize;
        b.iter_batched(
            || setup_ssi_pivot_192reads_32records(&block_data),
            |(mut store, pivot)| {
                black_box(store.commit_ssi(pivot).expect("pivot commit"));
            },
            BatchSize::SmallInput,
        );
    });

    // SSI commit with 0-block read-set (measures SSI log overhead alone).
    c.bench_function("mvcc_commit_ssi_0reads", |b| {
        let mut store = MvccStore::new();
        let mut block_id = 0_u64;

        b.iter(|| {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(block_id % 1024), block_data.clone());
            store.commit_ssi(txn).expect("commit");
            block_id += 1;
        });
    });

    for &write_count in &[64_u64, 256, 1024] {
        let mut txn = MvccStore::new().begin();
        for block in 0..write_count {
            txn.stage_write(BlockNumber(block), block_data.clone());
        }
        let expected: BTreeSet<BlockNumber> = txn.write_set().keys().copied().collect();
        let mut fused = BTreeSet::new();
        for &block in txn.write_set().keys() {
            fused.insert(block);
        }
        assert_eq!(
            expected, fused,
            "fused SSI write-key log must preserve the old prebuilt set"
        );

        c.bench_function(
            &format!("mvcc_commit_ssi_writekey_log_ab_prebuild_{write_count}"),
            |b| {
                b.iter(|| {
                    let write_keys: BTreeSet<BlockNumber> =
                        txn.write_set().keys().copied().collect();
                    let mut installed_checksum = 0_u64;
                    for block in txn.write_set().keys() {
                        installed_checksum = installed_checksum.wrapping_add(block.0);
                    }
                    black_box((write_keys, installed_checksum))
                });
            },
        );

        c.bench_function(
            &format!("mvcc_commit_ssi_writekey_log_ab_fused_{write_count}"),
            |b| {
                b.iter(|| {
                    let mut write_keys = BTreeSet::new();
                    let mut installed_checksum = 0_u64;
                    for &block in txn.write_set().keys() {
                        installed_checksum = installed_checksum.wrapping_add(block.0);
                        write_keys.insert(block);
                    }
                    black_box((write_keys, installed_checksum))
                });
            },
        );
    }
}

#[derive(Debug, Clone, Serialize)]
struct EbrScenarioReport {
    scenario: String,
    writers: usize,
    total_attempts: u64,
    committed: u64,
    failed: u64,
    collect_calls: u64,
    elapsed_ms: u128,
    rss_start_bytes: u64,
    rss_peak_bytes: u64,
    rss_end_bytes: u64,
    max_chain_length: usize,
    chains_over_cap: usize,
    chains_over_critical: usize,
    retired_versions: u64,
    reclaimed_versions: u64,
    pending_versions: u64,
    reclaim_rate_per_sec: f64,
    epoch_advance_hz_estimate: f64,
    rss_peak_during_pin_bytes: Option<u64>,
    rss_after_release_bytes: Option<u64>,
    version_count_during_pin: Option<usize>,
    version_count_after_release: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
struct EbrBenchmarkReport {
    generated_unix_ts: u64,
    scenarios: Vec<EbrScenarioReport>,
}

#[derive(Debug, Clone, Copy)]
struct ScenarioRuntime {
    writers: usize,
    attempts: u64,
    committed: u64,
    failed: u64,
    collect_calls: u64,
    elapsed_ms: u128,
    rss_start: u64,
    rss_peak: u64,
    rss_end: u64,
    rss_peak_during_pin: Option<u64>,
    rss_after_release: Option<u64>,
    version_count_during_pin: Option<usize>,
    version_count_after_release: Option<usize>,
}

static EBR_REPORT: OnceLock<EbrBenchmarkReport> = OnceLock::new();
static MERGE_PROOF_SUCCESS_REPORT: OnceLock<MergeProofSuccessReport> = OnceLock::new();

fn lcg_next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1);
    *state
}

fn payload_from_seed(seed: u64) -> Vec<u8> {
    seed.to_le_bytes().repeat(4)
}

fn process_rss_bytes() -> u64 {
    // Linux /proc format: size resident shared text lib data dt (in pages)
    let Ok(statm) = fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let resident_pages = statm
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    resident_pages.saturating_mul(4096)
}

fn collect_calls_hz(collect_calls: u64, elapsed_ms: u128) -> f64 {
    if elapsed_ms == 0 {
        return 0.0;
    }
    collect_calls as f64 / (elapsed_ms as f64 / 1000.0)
}

fn reclaim_rate(reclaimed: u64, elapsed_ms: u128) -> f64 {
    if elapsed_ms == 0 {
        return 0.0;
    }
    reclaimed as f64 / (elapsed_ms as f64 / 1000.0)
}

fn run_writer_workload(
    store: &Arc<Mutex<MvccStore>>,
    ops: u64,
    block_span: u64,
    mut seed: u64,
    sample_every: u64,
    peak_rss: &Arc<AtomicU64>,
) -> (u64, u64, u64) {
    let mut committed = 0_u64;
    let mut failed = 0_u64;
    let mut collect_calls = 0_u64;

    for i in 0..ops {
        let block = BlockNumber(lcg_next(&mut seed) % block_span.max(1));
        let payload = payload_from_seed(lcg_next(&mut seed));

        let mut guard = store.lock();
        let mut txn = guard.begin();
        txn.stage_write(block, payload);
        match guard.commit(txn) {
            Ok(_) => committed += 1,
            Err(_) => failed += 1,
        }
        if i % sample_every == 0 {
            let _ = guard.prune_safe();
            guard.ebr_collect();
            collect_calls += 1;
            peak_rss.fetch_max(process_rss_bytes(), Ordering::Relaxed);
        }
        drop(guard);
    }

    (committed, failed, collect_calls)
}

fn scenario_from_store(
    name: impl Into<String>,
    runtime: ScenarioRuntime,
    store: &MvccStore,
) -> EbrScenarioReport {
    let chain_stats = store.block_version_stats();
    let ebr = store.ebr_stats();
    let reclaimed = ebr.reclaimed_versions;
    EbrScenarioReport {
        scenario: name.into(),
        writers: runtime.writers,
        total_attempts: runtime.attempts,
        committed: runtime.committed,
        failed: runtime.failed,
        collect_calls: runtime.collect_calls,
        elapsed_ms: runtime.elapsed_ms,
        rss_start_bytes: runtime.rss_start,
        rss_peak_bytes: runtime.rss_peak,
        rss_end_bytes: runtime.rss_end,
        max_chain_length: chain_stats.max_chain_length,
        chains_over_cap: chain_stats.chains_over_cap,
        chains_over_critical: chain_stats.chains_over_critical,
        retired_versions: ebr.retired_versions,
        reclaimed_versions: reclaimed,
        pending_versions: ebr.pending_versions(),
        reclaim_rate_per_sec: reclaim_rate(reclaimed, runtime.elapsed_ms),
        epoch_advance_hz_estimate: collect_calls_hz(runtime.collect_calls, runtime.elapsed_ms),
        rss_peak_during_pin_bytes: runtime.rss_peak_during_pin,
        rss_after_release_bytes: runtime.rss_after_release,
        version_count_during_pin: runtime.version_count_during_pin,
        version_count_after_release: runtime.version_count_after_release,
    }
}

fn run_single_writer_steady_state() -> EbrScenarioReport {
    let store = Arc::new(Mutex::new(MvccStore::with_compression_policy(
        CompressionPolicy {
            dedup_identical: false,
            max_chain_length: Some(64),
            algo: CompressionAlgo::None,
        },
    )));
    let attempts = 100_000_u64;
    let rss_start = process_rss_bytes();
    let peak_rss = Arc::new(AtomicU64::new(rss_start));
    let start = Instant::now();
    let (committed, failed, collect_calls) =
        run_writer_workload(&store, attempts, 2048, 0xA11CE_u64, 128, &peak_rss);
    {
        let mut guard = store.lock();
        let _ = guard.prune_safe();
        guard.ebr_collect();
        drop(guard);
    }
    peak_rss.fetch_max(process_rss_bytes(), Ordering::Relaxed);
    let elapsed_ms = start.elapsed().as_millis();
    let rss_end = process_rss_bytes();
    let guard = store.lock();
    scenario_from_store(
        "single_writer_steady_state",
        ScenarioRuntime {
            writers: 1,
            attempts,
            committed,
            failed,
            collect_calls,
            elapsed_ms,
            rss_start,
            rss_peak: peak_rss.load(Ordering::Relaxed),
            rss_end,
            rss_peak_during_pin: None,
            rss_after_release: None,
            version_count_during_pin: None,
            version_count_after_release: None,
        },
        &guard,
    )
}

fn run_single_writer_no_gc_baseline() -> EbrScenarioReport {
    let store = Arc::new(Mutex::new(MvccStore::with_compression_policy(
        CompressionPolicy {
            dedup_identical: false,
            max_chain_length: Some(64),
            algo: CompressionAlgo::None,
        },
    )));
    let attempts = 50_000_u64;
    let rss_start = process_rss_bytes();
    let peak_rss = Arc::new(AtomicU64::new(rss_start));
    let start = Instant::now();

    let mut committed = 0_u64;
    let mut failed = 0_u64;
    let mut seed = 0xDEAD_BEEF_u64;
    for i in 0..attempts {
        let mut guard = store.lock();
        let mut txn = guard.begin();
        let payload = payload_from_seed(lcg_next(&mut seed));
        txn.stage_write(BlockNumber(0), payload);
        match guard.commit(txn) {
            Ok(_) => committed += 1,
            Err(_) => failed += 1,
        }
        if i % 256 == 0 {
            peak_rss.fetch_max(process_rss_bytes(), Ordering::Relaxed);
        }
        drop(guard);
    }

    let elapsed_ms = start.elapsed().as_millis();
    let rss_end = process_rss_bytes();
    peak_rss.fetch_max(rss_end, Ordering::Relaxed);
    let guard = store.lock();
    scenario_from_store(
        "single_writer_no_gc_baseline",
        ScenarioRuntime {
            writers: 1,
            attempts,
            committed,
            failed,
            collect_calls: 0,
            elapsed_ms,
            rss_start,
            rss_peak: peak_rss.load(Ordering::Relaxed),
            rss_end,
            rss_peak_during_pin: None,
            rss_after_release: None,
            version_count_during_pin: None,
            version_count_after_release: None,
        },
        &guard,
    )
}

fn run_multi_writer_scale(writers: usize) -> EbrScenarioReport {
    let store = Arc::new(Mutex::new(MvccStore::with_compression_policy(
        CompressionPolicy {
            dedup_identical: false,
            max_chain_length: None,
            algo: CompressionAlgo::None,
        },
    )));
    let ops_per_writer = 10_000_u64;
    let attempts = ops_per_writer.saturating_mul(u64::try_from(writers).expect("fits"));
    let rss_start = process_rss_bytes();
    let peak_rss = Arc::new(AtomicU64::new(rss_start));
    let start = Instant::now();

    let mut handles = Vec::with_capacity(writers);
    for idx in 0..writers {
        let store = Arc::clone(&store);
        let peak_rss = Arc::clone(&peak_rss);
        let seed = 0xBEEF_0000_u64.saturating_add(u64::try_from(idx).expect("fits"));
        handles.push(thread::spawn(move || {
            run_writer_workload(&store, ops_per_writer, 4096, seed, 128, &peak_rss)
        }));
    }

    let mut committed = 0_u64;
    let mut failed = 0_u64;
    let mut collect_calls = 0_u64;
    for handle in handles {
        let (c, f, g) = handle.join().expect("writer thread");
        committed += c;
        failed += f;
        collect_calls += g;
    }

    {
        let mut guard = store.lock();
        let _ = guard.prune_safe();
        guard.ebr_collect();
        drop(guard);
    }
    peak_rss.fetch_max(process_rss_bytes(), Ordering::Relaxed);
    let elapsed_ms = start.elapsed().as_millis();
    let rss_end = process_rss_bytes();
    let guard = store.lock();
    scenario_from_store(
        format!("multi_writer_scale_{writers}"),
        ScenarioRuntime {
            writers,
            attempts,
            committed,
            failed,
            collect_calls,
            elapsed_ms,
            rss_start,
            rss_peak: peak_rss.load(Ordering::Relaxed),
            rss_end,
            rss_peak_during_pin: None,
            rss_after_release: None,
            version_count_during_pin: None,
            version_count_after_release: None,
        },
        &guard,
    )
}

fn run_long_running_reader_pinning() -> EbrScenarioReport {
    let store = Arc::new(Mutex::new(MvccStore::with_compression_policy(
        CompressionPolicy {
            dedup_identical: false,
            max_chain_length: None,
            algo: CompressionAlgo::None,
        },
    )));
    let rss_start = process_rss_bytes();
    let peak_rss = Arc::new(AtomicU64::new(rss_start));
    let start = Instant::now();

    // Seed and hold an old snapshot so GC can't trim early history.
    let held_snapshot = {
        let mut guard = store.lock();
        let mut seed_txn = guard.begin();
        seed_txn.stage_write(BlockNumber(0), vec![1_u8; 32]);
        guard.commit(seed_txn).expect("seed");
        let snap = guard.current_snapshot();
        guard.register_snapshot(snap);
        snap
    };

    let writers = 8_usize;
    let ops_per_writer = 10_000_u64;
    let attempts = ops_per_writer.saturating_mul(u64::try_from(writers).expect("fits"));
    let mut handles = Vec::with_capacity(writers);
    for idx in 0..writers {
        let store = Arc::clone(&store);
        let peak_rss = Arc::clone(&peak_rss);
        let seed = 0xCAFE_1000_u64.saturating_add(u64::try_from(idx).expect("fits"));
        handles.push(thread::spawn(move || {
            run_writer_workload(&store, ops_per_writer, 1024, seed, 64, &peak_rss)
        }));
    }

    let mut committed = 0_u64;
    let mut failed = 0_u64;
    let mut collect_calls = 0_u64;
    for handle in handles {
        let (c, f, g) = handle.join().expect("writer thread");
        committed += c;
        failed += f;
        collect_calls += g;
    }
    let version_count_during_pin = {
        let guard = store.lock();
        guard.version_count()
    };
    let rss_peak_during_pin = peak_rss.load(Ordering::Relaxed);

    // Release held reader and let GC catch up.
    {
        let mut guard = store.lock();
        let _ = guard.release_snapshot(held_snapshot);
        for _ in 0..32 {
            let _ = guard.prune_safe();
            guard.ebr_collect();
            collect_calls += 1;
        }
        drop(guard);
    }
    let version_count_after_release = {
        let guard = store.lock();
        guard.version_count()
    };
    let rss_after_release = process_rss_bytes();
    peak_rss.fetch_max(rss_after_release, Ordering::Relaxed);

    let elapsed_ms = start.elapsed().as_millis();
    let rss_end = process_rss_bytes();
    let guard = store.lock();
    scenario_from_store(
        "long_running_reader_pinning",
        ScenarioRuntime {
            writers,
            attempts,
            committed,
            failed,
            collect_calls,
            elapsed_ms,
            rss_start,
            rss_peak: peak_rss.load(Ordering::Relaxed),
            rss_end,
            rss_peak_during_pin: Some(rss_peak_during_pin),
            rss_after_release: Some(rss_after_release),
            version_count_during_pin: Some(version_count_during_pin),
            version_count_after_release: Some(version_count_after_release),
        },
        &guard,
    )
}

fn run_hot_key_contention() -> EbrScenarioReport {
    let store = Arc::new(Mutex::new(MvccStore::with_compression_policy(
        CompressionPolicy {
            dedup_identical: false,
            max_chain_length: Some(64),
            algo: CompressionAlgo::None,
        },
    )));
    let writers = 16_usize;
    let ops_per_writer = 8_000_u64;
    let attempts = ops_per_writer.saturating_mul(u64::try_from(writers).expect("fits"));
    let rss_start = process_rss_bytes();
    let peak_rss = Arc::new(AtomicU64::new(rss_start));
    let start = Instant::now();

    let mut handles = Vec::with_capacity(writers);
    for idx in 0..writers {
        let store = Arc::clone(&store);
        let peak_rss = Arc::clone(&peak_rss);
        let seed = 0xFEED_2000_u64.saturating_add(u64::try_from(idx).expect("fits"));
        handles.push(thread::spawn(move || {
            // Hot-set of only 100 blocks.
            run_writer_workload(&store, ops_per_writer, 100, seed, 64, &peak_rss)
        }));
    }

    let mut committed = 0_u64;
    let mut failed = 0_u64;
    let mut collect_calls = 0_u64;
    for handle in handles {
        let (c, f, g) = handle.join().expect("writer thread");
        committed += c;
        failed += f;
        collect_calls += g;
    }

    {
        let mut guard = store.lock();
        let _ = guard.prune_safe();
        guard.ebr_collect();
        drop(guard);
    }
    peak_rss.fetch_max(process_rss_bytes(), Ordering::Relaxed);
    let elapsed_ms = start.elapsed().as_millis();
    let rss_end = process_rss_bytes();
    let guard = store.lock();
    scenario_from_store(
        "hot_key_contention",
        ScenarioRuntime {
            writers,
            attempts,
            committed,
            failed,
            collect_calls,
            elapsed_ms,
            rss_start,
            rss_peak: peak_rss.load(Ordering::Relaxed),
            rss_end,
            rss_peak_during_pin: None,
            rss_after_release: None,
            version_count_during_pin: None,
            version_count_after_release: None,
        },
        &guard,
    )
}

fn run_bursty_write_pattern() -> EbrScenarioReport {
    let store = Arc::new(Mutex::new(MvccStore::with_compression_policy(
        CompressionPolicy {
            dedup_identical: false,
            max_chain_length: Some(64),
            algo: CompressionAlgo::None,
        },
    )));
    let mut rng = 0x1234_5678_9ABC_DEF0_u64;
    let cycles = 6_u64;
    let burst_ops = 10_000_u64;
    let attempts = cycles.saturating_mul(burst_ops);
    let rss_start = process_rss_bytes();
    let peak_rss = Arc::new(AtomicU64::new(rss_start));
    let start = Instant::now();

    let mut committed = 0_u64;
    let mut failed = 0_u64;
    let mut collect_calls = 0_u64;
    for _ in 0..cycles {
        let (c, f, g) =
            run_writer_workload(&store, burst_ops, 1024, lcg_next(&mut rng), 64, &peak_rss);
        committed += c;
        failed += f;
        collect_calls += g;

        // Idle/catch-up phase.
        let mut guard = store.lock();
        for _ in 0..32 {
            let _ = guard.prune_safe();
            guard.ebr_collect();
            collect_calls += 1;
            peak_rss.fetch_max(process_rss_bytes(), Ordering::Relaxed);
        }
        drop(guard);
    }

    let elapsed_ms = start.elapsed().as_millis();
    let rss_end = process_rss_bytes();
    let guard = store.lock();
    scenario_from_store(
        "bursty_write_pattern",
        ScenarioRuntime {
            writers: 1,
            attempts,
            committed,
            failed,
            collect_calls,
            elapsed_ms,
            rss_start,
            rss_peak: peak_rss.load(Ordering::Relaxed),
            rss_end,
            rss_peak_during_pin: None,
            rss_after_release: None,
            version_count_during_pin: None,
            version_count_after_release: None,
        },
        &guard,
    )
}

fn write_ebr_report_json(report: &EbrBenchmarkReport) {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        );
    let out_path = repo_root.join("artifacts/benchmarks/ebr_memory_usage.json");
    if let Some(parent) = out_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(report) {
        let _ = fs::write(out_path, json);
    }
}

fn ebr_report() -> &'static EbrBenchmarkReport {
    EBR_REPORT.get_or_init(|| {
        let mut scenarios = Vec::new();
        scenarios.push(run_single_writer_no_gc_baseline());
        scenarios.push(run_single_writer_steady_state());
        for writers in [2_usize, 4, 8, 16] {
            scenarios.push(run_multi_writer_scale(writers));
        }
        scenarios.push(run_long_running_reader_pinning());
        scenarios.push(run_hot_key_contention());
        scenarios.push(run_bursty_write_pattern());

        let generated_unix_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let report = EbrBenchmarkReport {
            generated_unix_ts,
            scenarios,
        };
        write_ebr_report_json(&report);
        report
    })
}

/// Generates a deterministic EBR memory-behavior report once per run and
/// writes JSON to `artifacts/benchmarks/ebr_memory_usage.json`.
fn bench_ebr_memory_report(c: &mut Criterion) {
    let report = ebr_report();
    c.bench_function("mvcc_ebr_report_cached", |b| {
        b.iter(|| std::hint::black_box(report.scenarios.len()));
    });
}

#[derive(Debug, Clone, Serialize)]
struct MergeProofSuccessRow {
    workload_id: String,
    scenario: String,
    attempts: u64,
    conflicts: u64,
    successful_merges: u64,
    aborted: u64,
    merge_success_ratio: f64,
    elapsed_us: u64,
}

#[derive(Debug, Clone, Serialize)]
struct MergeProofSuccessReport {
    generated_unix_ts: u64,
    rows: Vec<MergeProofSuccessRow>,
}

fn run_append_only_merge_proof_success(attempts: u64) -> MergeProofSuccessRow {
    let mut store = MvccStore::new();
    store.set_conflict_policy(ConflictPolicy::SafeMerge);
    let block = BlockNumber(0);

    let mut seed_txn = store.begin();
    seed_txn.stage_write(block, vec![0_u8; 64]);
    store.commit(seed_txn).expect("seed append-only block");

    let started = Instant::now();
    for idx in 0..attempts {
        let snapshot = store.current_snapshot();
        let base = store
            .read_visible(block, snapshot)
            .expect("seeded block visible")
            .into_owned();
        let base_len = base.len();

        let mut stale_txn = store.begin();
        let mut competing_txn = store.begin();
        let mut competing_data = base.clone();
        competing_data.extend_from_slice(&idx.to_le_bytes());
        competing_txn.stage_write_with_proof(
            block,
            competing_data,
            MergeProof::AppendOnly { base_len },
        );
        store
            .commit(competing_txn)
            .expect("competing append-only commit");

        let mut stale_data = base;
        stale_data.extend_from_slice(&idx.wrapping_add(0xA5A5_A5A5_A5A5_A5A5).to_le_bytes());
        stale_txn.stage_write_with_proof(block, stale_data, MergeProof::AppendOnly { base_len });
        store.commit(stale_txn).expect("merge-proof commit");
    }

    let metrics = *store.contention_metrics();
    let merge_success_ratio = if metrics.total_conflicts == 0 {
        0.0
    } else {
        metrics.total_merges as f64 / metrics.total_conflicts as f64
    };
    MergeProofSuccessRow {
        workload_id: "mvcc_merge_proof_append_only_success_rate".to_owned(),
        scenario: "append_only_safe_merge_conflict".to_owned(),
        attempts,
        conflicts: metrics.total_conflicts,
        successful_merges: metrics.total_merges,
        aborted: metrics.total_aborts,
        merge_success_ratio,
        elapsed_us: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
    }
}

fn merge_proof_success_output_path() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("FFS_MVCC_MERGE_PROOF_REPORT") {
        return std::path::PathBuf::from(path);
    }
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        );
    repo_root.join("artifacts/benchmarks/mvcc_merge_proof_success_rate.json")
}

fn write_merge_proof_success_report_json(report: &MergeProofSuccessReport) {
    let out_path = merge_proof_success_output_path();
    if let Some(parent) = out_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(report) {
        let _ = fs::write(out_path, json);
    }
}

fn merge_proof_success_report() -> &'static MergeProofSuccessReport {
    MERGE_PROOF_SUCCESS_REPORT.get_or_init(|| {
        let generated_unix_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let report = MergeProofSuccessReport {
            generated_unix_ts,
            rows: vec![run_append_only_merge_proof_success(256)],
        };
        write_merge_proof_success_report_json(&report);
        report
    })
}

/// Compare RCU vs RwLock vs Mutex read throughput under concurrent writer
/// pressure.  Models the stat()/readdir() hot path where many readers access
/// metadata while occasional writes update it.
#[allow(clippy::too_many_lines)]
fn bench_rcu_read_throughput(c: &mut Criterion) {
    use ffs_mvcc::rcu::RcuCell;
    use parking_lot::RwLock;
    use std::sync::Barrier;

    // Simulated metadata payload (inode-like: uid, gid, mode, size, timestamps).
    #[derive(Clone, Debug)]
    struct InodeMeta {
        ino: u64,
        uid: u32,
        gid: u32,
        mode: u32,
        size: u64,
        atime_ns: u64,
        mtime_ns: u64,
    }

    impl InodeMeta {
        fn new(ino: u64) -> Self {
            Self {
                ino,
                uid: 1000,
                gid: 1000,
                mode: 0o100_644,
                size: 4_096,
                atime_ns: 1_700_000_000_000_000_000,
                mtime_ns: 1_700_000_000_000_000_000,
            }
        }

        fn digest(&self) -> u64 {
            self.ino
                .wrapping_add(u64::from(self.uid))
                .wrapping_add(u64::from(self.gid))
                .wrapping_add(u64::from(self.mode))
                .wrapping_add(self.size)
                .wrapping_add(self.atime_ns)
                .wrapping_add(self.mtime_ns)
        }
    }

    let reader_counts = [1_usize, 2, 4, 8, 16];
    let reads_per_iter = 10_000_u64;

    for &readers in &reader_counts {
        // ── RcuCell benchmark ──────────────────────────────────────────
        c.bench_function(&format!("rcu_cell_read_{readers}r_1w"), |b| {
            b.iter_custom(|iters| {
                let cell = Arc::new(RcuCell::new(InodeMeta::new(0)));
                let total_reads = iters.saturating_mul(reads_per_iter);
                let reads_per_thread = total_reads / u64::try_from(readers).expect("fits");
                let barrier = Arc::new(Barrier::new(readers + 1));

                // Writer: periodic updates.
                let writer_cell = Arc::clone(&cell);
                let writer_barrier = Arc::clone(&barrier);
                let writer = thread::spawn(move || {
                    writer_barrier.wait();
                    for i in 0..reads_per_thread.min(5_000) {
                        writer_cell.update(InodeMeta::new(i));
                    }
                });

                // Readers: measure elapsed time.
                let mut handles = Vec::with_capacity(readers);
                for _ in 0..readers {
                    let cell = Arc::clone(&cell);
                    let barrier = Arc::clone(&barrier);
                    handles.push(thread::spawn(move || {
                        barrier.wait();
                        let start = Instant::now();
                        let mut sum = 0_u64;
                        for _ in 0..reads_per_thread {
                            let guard = cell.load();
                            sum = sum.wrapping_add(guard.digest());
                        }
                        std::hint::black_box(sum);
                        start.elapsed()
                    }));
                }

                let _ = writer.join();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("reader thread"))
                    .max()
                    .unwrap_or_default()
            });
        });

        // ── RwLock benchmark ───────────────────────────────────────────
        c.bench_function(&format!("rwlock_read_{readers}r_1w"), |b| {
            b.iter_custom(|iters| {
                let lock = Arc::new(RwLock::new(InodeMeta::new(0)));
                let total_reads = iters.saturating_mul(reads_per_iter);
                let reads_per_thread = total_reads / u64::try_from(readers).expect("fits");
                let barrier = Arc::new(Barrier::new(readers + 1));

                let writer_lock = Arc::clone(&lock);
                let writer_barrier = Arc::clone(&barrier);
                let writer = thread::spawn(move || {
                    writer_barrier.wait();
                    for i in 0..reads_per_thread.min(5_000) {
                        *writer_lock.write() = InodeMeta::new(i);
                    }
                });

                let mut handles = Vec::with_capacity(readers);
                for _ in 0..readers {
                    let lock = Arc::clone(&lock);
                    let barrier = Arc::clone(&barrier);
                    handles.push(thread::spawn(move || {
                        barrier.wait();
                        let start = Instant::now();
                        let mut sum = 0_u64;
                        for _ in 0..reads_per_thread {
                            let guard = lock.read();
                            sum = sum.wrapping_add(guard.digest());
                        }
                        std::hint::black_box(sum);
                        start.elapsed()
                    }));
                }

                let _ = writer.join();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("reader thread"))
                    .max()
                    .unwrap_or_default()
            });
        });

        // ── Mutex benchmark ────────────────────────────────────────────
        c.bench_function(&format!("mutex_read_{readers}r_1w"), |b| {
            b.iter_custom(|iters| {
                let lock = Arc::new(Mutex::new(InodeMeta::new(0)));
                let total_reads = iters.saturating_mul(reads_per_iter);
                let reads_per_thread = total_reads / u64::try_from(readers).expect("fits");
                let barrier = Arc::new(Barrier::new(readers + 1));

                let writer_lock = Arc::clone(&lock);
                let writer_barrier = Arc::clone(&barrier);
                let writer = thread::spawn(move || {
                    writer_barrier.wait();
                    for i in 0..reads_per_thread.min(5_000) {
                        *writer_lock.lock() = InodeMeta::new(i);
                    }
                });

                let mut handles = Vec::with_capacity(readers);
                for _ in 0..readers {
                    let lock = Arc::clone(&lock);
                    let barrier = Arc::clone(&barrier);
                    handles.push(thread::spawn(move || {
                        barrier.wait();
                        let start = Instant::now();
                        let mut sum = 0_u64;
                        for _ in 0..reads_per_thread {
                            let guard = lock.lock();
                            sum = sum.wrapping_add(guard.digest());
                        }
                        std::hint::black_box(sum);
                        start.elapsed()
                    }));
                }

                let _ = writer.join();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("reader thread"))
                    .max()
                    .unwrap_or_default()
            });
        });
    }
}

/// Measure WAL write amplification: ratio of total bytes written to WAL
/// vs. user data bytes committed.
fn bench_write_amplification(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let block_data = vec![0xAB_u8; 4096];

    // Single-block transaction write amplification.
    c.bench_function("wal_write_amplification_1block", |b| {
        let tmp = NamedTempFile::new().expect("temp file");
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();

        let store = PersistentMvccStore::open_with_options(&cx, &path, &PersistOptions::default())
            .expect("open");

        let mut block_id = 0_u64;

        b.iter(|| {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(block_id % 1024), block_data.clone());
            store.commit(txn).expect("commit");
            block_id += 1;
        });
    });

    // 16-block transaction write amplification (amortized overhead).
    c.bench_function("wal_write_amplification_16block", |b| {
        let tmp = NamedTempFile::new().expect("temp file");
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();

        let store = PersistentMvccStore::open_with_options(&cx, &path, &PersistOptions::default())
            .expect("open");

        let mut block_id = 0_u64;

        b.iter(|| {
            let mut txn = store.begin();
            for j in 0..16_u64 {
                txn.stage_write(BlockNumber((block_id + j) % 4096), block_data.clone());
            }
            store.commit(txn).expect("commit");
            block_id += 16;
        });
    });
}

/// Measure MVCC commit throughput under multi-writer contention.
fn bench_mvcc_contention(c: &mut Criterion) {
    let block_data = vec![0xAB_u8; 4096];

    for &writers in &[2_usize, 4, 8] {
        let bench_name = format!("mvcc_contention_{writers}writers");

        c.bench_function(&bench_name, |b| {
            b.iter_custom(|iters| {
                let store = Arc::new(Mutex::new(MvccStore::new()));
                let ops_per_writer = iters / u64::try_from(writers).expect("fits");
                let barrier = Arc::new(std::sync::Barrier::new(writers));

                let mut handles = Vec::with_capacity(writers);
                for writer_id in 0..writers {
                    let store = Arc::clone(&store);
                    let barrier = Arc::clone(&barrier);
                    let data = block_data.clone();
                    handles.push(thread::spawn(move || {
                        barrier.wait();
                        let start = Instant::now();
                        for i in 0..ops_per_writer {
                            let block = BlockNumber(
                                (u64::try_from(writer_id).expect("fits") * 1024 + i) % 4096,
                            );
                            let mut guard = store.lock();
                            let mut txn = guard.begin();
                            txn.stage_write(block, data.clone());
                            let _ = guard.commit(txn);
                            drop(guard);
                        }
                        start.elapsed()
                    }));
                }

                handles
                    .into_iter()
                    .map(|h| h.join().expect("writer thread"))
                    .max()
                    .unwrap_or_default()
            });
        });
    }
}

/// Measure the proof-validation success ratio for append-only SafeMerge
/// conflicts and emit a JSON ratio report for performance-baseline consumers.
fn bench_merge_proof_success_rate(c: &mut Criterion) {
    let report = merge_proof_success_report();
    if let Some(row) = report.rows.first() {
        black_box(row.merge_success_ratio);
    }

    c.bench_function("mvcc_merge_proof_append_only_success_rate", |b| {
        b.iter(|| {
            let row = run_append_only_merge_proof_success(black_box(64));
            black_box(row.merge_success_ratio);
        });
    });
}

const GDT_BLOCK_BYTES: usize = 4096;
const GDT_WRITERS: usize = 8;
const GDT_DESCRIPTOR_BYTES: usize = 64;

fn apply_gdt_descriptor(bytes: &mut [u8], writer: usize) {
    let start = writer * GDT_DESCRIPTOR_BYTES;
    let end = start + GDT_DESCRIPTOR_BYTES;
    let value = u8::try_from(writer + 1).expect("writer marker fits u8");
    bytes[start..end].fill(value);
}

fn assert_gdt_descriptors(bytes: &[u8]) {
    for writer in 0..GDT_WRITERS {
        let start = writer * GDT_DESCRIPTOR_BYTES;
        let end = start + GDT_DESCRIPTOR_BYTES;
        let value = u8::try_from(writer + 1).expect("writer marker fits u8");
        assert!(
            bytes[start..end].iter().all(|&b| b == value),
            "descriptor {writer} did not land"
        );
    }
}

/// Model the ext4 group-descriptor-table conflict found in the parallel
/// metadata-write profile: all writers begin from the same snapshot, update
/// different descriptor-sized byte ranges inside one 4 KiB block, and then
/// commit. Strict FCW needs retry waves; SafeMerge commits the whole wave.
fn strict_retry_gdt_descriptor_writers() -> Vec<u8> {
    let block = BlockNumber(1659);
    let mut store = MvccStore::new();
    store.set_conflict_policy(ConflictPolicy::Strict);

    let mut seed = store.begin();
    seed.stage_write(block, vec![0; GDT_BLOCK_BYTES]);
    store.commit(seed).expect("seed GDT block");

    let mut remaining: Vec<usize> = (0..GDT_WRITERS).collect();
    while !remaining.is_empty() {
        let snapshot = store.current_snapshot();
        let base = store
            .read_visible(block, snapshot)
            .expect("seeded GDT block visible")
            .into_owned();
        let txns: Vec<(usize, _)> = remaining
            .iter()
            .map(|&writer| {
                let mut bytes = base.clone();
                apply_gdt_descriptor(&mut bytes, writer);
                let mut txn = store.begin();
                txn.stage_write(block, bytes);
                (writer, txn)
            })
            .collect();

        let mut retry = Vec::new();
        for (index, (writer, txn)) in txns.into_iter().enumerate() {
            let result = store.commit(txn);
            if index == 0 {
                result.expect("first writer in wave commits");
            } else {
                result.expect_err("same-snapshot strict writer must conflict");
                retry.push(writer);
            }
        }
        remaining = retry;
    }

    let latest = store.current_snapshot();
    let bytes = store
        .read_visible(block, latest)
        .expect("final GDT block visible")
        .into_owned();
    assert_gdt_descriptors(&bytes);
    bytes
}

fn safe_merge_gdt_descriptor_writers() -> Vec<u8> {
    let block = BlockNumber(1659);
    let mut store = MvccStore::new();
    store.set_conflict_policy(ConflictPolicy::SafeMerge);

    let mut seed = store.begin();
    seed.stage_write(block, vec![0; GDT_BLOCK_BYTES]);
    store.commit(seed).expect("seed GDT block");

    let snapshot = store.current_snapshot();
    let base = store
        .read_visible(block, snapshot)
        .expect("seeded GDT block visible")
        .into_owned();
    let txns: Vec<_> = (0..GDT_WRITERS)
        .map(|writer| {
            let mut bytes = base.clone();
            apply_gdt_descriptor(&mut bytes, writer);
            let mut txn = store.begin();
            txn.stage_write_with_proof(
                block,
                bytes,
                MergeProof::independent_key_range(
                    writer * GDT_DESCRIPTOR_BYTES,
                    GDT_DESCRIPTOR_BYTES,
                ),
            );
            txn
        })
        .collect();

    for txn in txns {
        store.commit(txn).expect("range-proof writer commits");
    }

    let latest = store.current_snapshot();
    let bytes = store
        .read_visible(block, latest)
        .expect("final GDT block visible")
        .into_owned();
    assert_gdt_descriptors(&bytes);
    bytes
}

fn serial_gdt_descriptor_writers() -> Vec<u8> {
    let block = BlockNumber(1659);
    let mut store = MvccStore::new();
    store.set_conflict_policy(ConflictPolicy::Strict);

    let mut seed = store.begin();
    seed.stage_write(block, vec![0; GDT_BLOCK_BYTES]);
    store.commit(seed).expect("seed GDT block");

    for writer in 0..GDT_WRITERS {
        let snapshot = store.current_snapshot();
        let mut bytes = store
            .read_visible(block, snapshot)
            .expect("GDT block visible")
            .into_owned();
        apply_gdt_descriptor(&mut bytes, writer);
        let mut txn = store.begin();
        txn.stage_write(block, bytes);
        store.commit(txn).expect("serial writer commits");
    }

    let latest = store.current_snapshot();
    let bytes = store
        .read_visible(block, latest)
        .expect("final GDT block visible")
        .into_owned();
    assert_gdt_descriptors(&bytes);
    bytes
}

fn bench_gdt_disjoint_range_conflict(c: &mut Criterion) {
    assert_eq!(
        strict_retry_gdt_descriptor_writers(),
        safe_merge_gdt_descriptor_writers(),
        "range-proof merge must match strict retry-wave final bytes"
    );
    assert_eq!(
        serial_gdt_descriptor_writers(),
        safe_merge_gdt_descriptor_writers(),
        "range-proof merge must match serial final bytes"
    );

    let mut group = c.benchmark_group("mvcc_gdt_disjoint_range_conflict_8writers");
    group.bench_function("strict_retry_waves", |b| {
        b.iter(|| black_box(strict_retry_gdt_descriptor_writers()));
    });
    group.bench_function("strict_serial_no_conflict", |b| {
        b.iter(|| black_box(serial_gdt_descriptor_writers()));
    });
    group.bench_function("safe_merge_one_wave", |b| {
        b.iter(|| black_box(safe_merge_gdt_descriptor_writers()));
    });
    group.finish();
}

const SINGLE_VERSION_CHAIN_BLOCKS: usize = 256;
type InlineVersionChain = SmallVec<[BlockVersion; 1]>;

fn single_version_chain_fixture() -> Vec<BlockVersion> {
    (0..SINGLE_VERSION_CHAIN_BLOCKS)
        .map(|index| {
            let index = u64::try_from(index).expect("fixture index fits");
            let block = BlockNumber(index);
            let fill = u8::try_from(index % 251).expect("fixture byte fits");
            BlockVersion {
                block,
                commit_seq: CommitSeq(index + 1),
                writer: TxnId(index + 1),
                data: VersionData::full(vec![fill; 4096]),
            }
        })
        .collect()
}

fn build_vec_version_chains(
    versions: Vec<BlockVersion>,
) -> FxHashMap<BlockNumber, Vec<BlockVersion>> {
    let mut chains: FxHashMap<BlockNumber, Vec<BlockVersion>> = FxHashMap::default();
    for version in versions {
        chains.entry(version.block).or_default().push(version);
    }
    chains
}

fn build_inline_version_chains(
    versions: Vec<BlockVersion>,
) -> FxHashMap<BlockNumber, InlineVersionChain> {
    let mut chains: FxHashMap<BlockNumber, InlineVersionChain> = FxHashMap::default();
    for version in versions {
        chains.entry(version.block).or_default().push(version);
    }
    chains
}

fn bench_single_version_chain_storage_ab(c: &mut Criterion) {
    let fixture = single_version_chain_fixture();
    let vec_chains = build_vec_version_chains(fixture.clone());
    let inline_chains = build_inline_version_chains(fixture.clone());
    assert_eq!(vec_chains.len(), inline_chains.len());
    for (block, versions) in &vec_chains {
        assert_eq!(
            versions.as_slice(),
            inline_chains
                .get(block)
                .expect("inline chain contains every block")
                .as_slice(),
            "inline version-chain storage changed version order or bytes"
        );
    }

    let mut group = c.benchmark_group("mvcc_single_version_chain_storage_256");
    for control in ["vec_chain_a", "vec_chain_b"] {
        group.bench_function(control, |b| {
            b.iter_batched(
                || fixture.clone(),
                |versions| black_box(build_vec_version_chains(versions)),
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.bench_function("inline_smallvec_1", |b| {
        b.iter_batched(
            || fixture.clone(),
            |versions| black_box(build_inline_version_chains(versions)),
            criterion::BatchSize::SmallInput,
        );
    });
    group.finish();
}

/// Measure sharded MVCC commit throughput on disjoint writer-owned block ranges.
///
/// This is the high-core counterpart to `bench_mvcc_contention`: it keeps the
/// same one-block transaction shape but removes the external `Mutex<MvccStore>`
/// serialization so the benchmark captures per-shard commit scaling and ordered
/// publication overhead.
fn bench_sharded_mvcc_contention(c: &mut Criterion) {
    use ffs_mvcc::sharded::ShardedMvccStore;

    let block_data = vec![0xAB_u8; 4096];
    let blocks_per_writer = 4096_u64;
    let ops_per_writer = 64_u64;

    for &writers in &[8_usize, 16, 32] {
        let bench_name = format!("sharded_mvcc_disjoint_{writers}writers");

        c.bench_function(&bench_name, |b| {
            b.iter(|| {
                let store = Arc::new(ShardedMvccStore::for_host_parallelism());
                let barrier = Arc::new(std::sync::Barrier::new(writers));

                let mut handles = Vec::with_capacity(writers);
                for writer_id in 0..writers {
                    let store = Arc::clone(&store);
                    let barrier = Arc::clone(&barrier);
                    let data = block_data.clone();
                    handles.push(thread::spawn(move || {
                        barrier.wait();
                        let writer_id = u64::try_from(writer_id).expect("writer id fits");
                        let block_base = writer_id.saturating_mul(blocks_per_writer);
                        for i in 0..ops_per_writer {
                            let mut txn = store.begin();
                            txn.stage_write(
                                BlockNumber(block_base + (i % blocks_per_writer)),
                                data.clone(),
                            );
                            let seq = store.commit(txn).expect("disjoint commit");
                            black_box(seq);
                        }
                    }));
                }

                for handle in handles {
                    handle.join().expect("writer thread");
                }
                black_box(store.current_snapshot());
            });
        });
    }
}

fn latest_published_seq_reverse_scan(
    versions: &[CommitSeq],
    published_high: CommitSeq,
) -> CommitSeq {
    versions
        .iter()
        .rev()
        .find(|seq| **seq <= published_high)
        .copied()
        .unwrap_or(CommitSeq(0))
}

fn latest_published_seq_partition_point(
    versions: &[CommitSeq],
    published_high: CommitSeq,
) -> CommitSeq {
    if let Some(commit_seq) = versions
        .last()
        .copied()
        .filter(|commit_seq| *commit_seq <= published_high)
    {
        return commit_seq;
    }

    let visible_len = versions.partition_point(|seq| *seq <= published_high);
    if visible_len == 0 {
        CommitSeq(0)
    } else {
        versions[visible_len - 1]
    }
}

fn bench_sharded_latest_published_search_ab(c: &mut Criterion) {
    let versions: Vec<CommitSeq> = (1..=4096_u64).map(CommitSeq).collect();
    let probes = [
        ("old_snapshot", CommitSeq(16)),
        ("mid_snapshot", CommitSeq(2048)),
        ("latest_snapshot", CommitSeq(4096)),
    ];

    let mut group = c.benchmark_group("sharded_latest_published_seq_chain4096");
    for &(label, published_high) in &probes {
        assert_eq!(
            latest_published_seq_reverse_scan(&versions, published_high),
            latest_published_seq_partition_point(&versions, published_high)
        );

        group.bench_with_input(
            BenchmarkId::new("reverse_scan", label),
            &published_high,
            |b, high| {
                b.iter(|| {
                    black_box(latest_published_seq_reverse_scan(
                        black_box(&versions),
                        black_box(*high),
                    ));
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("partition_point", label),
            &published_high,
            |b, high| {
                b.iter(|| {
                    black_box(latest_published_seq_partition_point(
                        black_box(&versions),
                        black_box(*high),
                    ));
                });
            },
        );
    }
    group.finish();
}

fn bench_shard_index_routing_ab(c: &mut Criterion) {
    let shard_count = 1024_u64;
    let shard_mask = shard_count - 1;
    let blocks_per_writer = 4096_u64;
    let ops_per_writer = 64_u64;
    let blocks: Vec<u64> = (0..32_u64)
        .flat_map(|writer_id| {
            let block_base = writer_id.saturating_mul(blocks_per_writer);
            (0..ops_per_writer).map(move |i| block_base + (i % blocks_per_writer))
        })
        .collect();

    let modulo_checksum = blocks.iter().fold(0_usize, |sum, block| {
        let idx = usize::try_from(*block % shard_count).expect("modulo shard index fits");
        sum.wrapping_add(idx)
    });
    let mask_checksum = blocks.iter().fold(0_usize, |sum, block| {
        let idx = usize::try_from(*block & shard_mask).expect("masked shard index fits");
        sum.wrapping_add(idx)
    });
    assert_eq!(modulo_checksum, mask_checksum);

    c.bench_function("shard_index_routing_modulo_ab", |b| {
        b.iter(|| {
            let shard_count = black_box(shard_count);
            let mut checksum = 0_usize;
            for &block in &blocks {
                let idx = usize::try_from(black_box(block) % shard_count).expect("fits");
                checksum = checksum.wrapping_add(idx);
            }
            black_box(checksum)
        });
    });

    c.bench_function("shard_index_routing_mask_ab", |b| {
        b.iter(|| {
            let shard_mask = black_box(shard_mask);
            let mut checksum = 0_usize;
            for &block in &blocks {
                let idx = usize::try_from(black_box(block) & shard_mask).expect("fits");
                checksum = checksum.wrapping_add(idx);
            }
            black_box(checksum)
        });
    });
}

fn bench_pruning_throughput(c: &mut Criterion) {
    let block_data = vec![0xAB_u8; 4096];
    let num_blocks = 256_u64;
    let versions_per_block = 32_u64;

    // Pruning a single-threaded MvccStore with many versions.
    c.bench_function("prune_256blocks_32versions", |b| {
        b.iter_batched(
            || {
                // Setup: build a store with many versions per block.
                let mut store = MvccStore::new();
                for v in 0..versions_per_block {
                    for blk in 0..num_blocks {
                        let mut txn = store.begin();
                        txn.stage_write(BlockNumber(blk), block_data.clone());
                        store.commit(txn).expect("commit");
                    }
                    // Register and release snapshots to allow pruning.
                    if v < versions_per_block - 2 {
                        let snap = store.current_snapshot();
                        store.register_snapshot(snap);
                        store.release_snapshot(snap);
                    }
                }
                // Register current snapshot so watermark is one behind head.
                let current = store.current_snapshot();
                store.register_snapshot(current);
                store.release_snapshot(current);
                store
            },
            |mut store| {
                store.prune_safe();
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Pruning with EBR reclamation cycle.
    c.bench_function("prune_and_reclaim_256blocks", |b| {
        b.iter_batched(
            || {
                let mut store = MvccStore::new();
                for _v in 0..versions_per_block {
                    for blk in 0..num_blocks {
                        let mut txn = store.begin();
                        txn.stage_write(BlockNumber(blk), block_data.clone());
                        store.commit(txn).expect("commit");
                    }
                }
                let current = store.current_snapshot();
                store.register_snapshot(current);
                store.release_snapshot(current);
                store
            },
            |mut store| {
                store.prune_safe();
                store.ebr_collect();
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Sharded pruning throughput.
    c.bench_function("prune_sharded_256blocks_32versions", |b| {
        use ffs_mvcc::sharded::ShardedMvccStore;
        b.iter_batched(
            || {
                let store = ShardedMvccStore::new(4);
                for _v in 0..versions_per_block {
                    for blk in 0..num_blocks {
                        let mut txn = store.begin();
                        txn.stage_write(BlockNumber(blk), block_data.clone());
                        store.commit(txn).expect("commit");
                    }
                }
                let snap = store.current_snapshot();
                store.register_snapshot(snap);
                store.release_snapshot(snap);
                store
            },
            |store| {
                store.prune_safe();
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

/// Compare coalesced vs individual WAL appends.
///
/// Measures the throughput improvement of `append_commits_coalesced` over
/// N individual `append_commit` calls, demonstrating I/O amortization.
fn bench_coalesced_append(c: &mut Criterion) {
    use ffs_mvcc::wal_writer::{SyncPolicy, WalWriter, WalWriterConfig};

    let block_data = vec![0xCC_u8; 256];
    let mut group = c.benchmark_group("wal_coalesce_20_commits");

    // Individual: 20 separate append + fsync.
    group.bench_function("individual_20", |b| {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();

        let cfg = WalWriterConfig {
            sync_policy: SyncPolicy::Immediate,
            verify_writes: false,
            backpressure_threshold_bytes: 0,
        };
        let mut w = WalWriter::create(&path, cfg).unwrap();
        let mut seq = 1_u64;

        b.iter(|| {
            for _ in 0..20 {
                let commit = ffs_mvcc::wal::WalCommit {
                    commit_seq: CommitSeq(seq),
                    txn_id: TxnId(seq),
                    writes: vec![ffs_mvcc::wal::WalWrite {
                        block: BlockNumber(seq % 1024),
                        data: block_data.clone(),
                    }],
                };
                w.append_commit(&commit).unwrap();
                seq += 1;
            }
        });

        let _ = std::fs::remove_file(&path);
    });

    // Coalesced: 20 commits in a single write + fsync.
    group.bench_function("coalesced_20", |b| {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();

        let cfg = WalWriterConfig {
            sync_policy: SyncPolicy::Immediate,
            verify_writes: false,
            backpressure_threshold_bytes: 0,
        };
        let mut w = WalWriter::create(&path, cfg).unwrap();
        let mut seq = 1_u64;

        b.iter(|| {
            let commits: Vec<_> = (0..20)
                .map(|_| {
                    let c = ffs_mvcc::wal::WalCommit {
                        commit_seq: CommitSeq(seq),
                        txn_id: TxnId(seq),
                        writes: vec![ffs_mvcc::wal::WalWrite {
                            block: BlockNumber(seq % 1024),
                            data: block_data.clone(),
                        }],
                    };
                    seq += 1;
                    c
                })
                .collect();
            w.append_commits_coalesced(&commits).unwrap();
        });

        let _ = std::fs::remove_file(&path);
    });

    group.finish();
}

// bd-enfch — bench coverage for PersistentMvccStore maintenance ops
// (checkpoint + truncate_wal). These are on the operator-facing
// maintenance path; a regression that made checkpoint quadratic in
// version count, or truncate_wal slower because of an extra fsync,
// would silently degrade the maintenance window without tripping any
// existing bench gate.

fn bench_checkpoint_throughput(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let block_data = vec![0xAB_u8; 4096];

    c.bench_function("persistent_mvcc_checkpoint_256blocks_8versions", |b| {
        b.iter_batched(
            || {
                // Seed: 256 blocks × 8 versions each.
                let tmp = NamedTempFile::new().expect("temp file");
                let path = tmp.path().to_path_buf();
                std::fs::remove_file(&path).ok();
                let store = PersistentMvccStore::open_with_options(
                    &cx,
                    &path,
                    &PersistOptions {
                        sync_on_commit: false,
                        ..PersistOptions::default()
                    },
                )
                .expect("open");
                for v in 0..8_u64 {
                    for blk in 0..256_u64 {
                        let mut txn = store.begin();
                        // Vary payload per version so dedup doesn't
                        // collapse the chain.
                        let mut data = block_data.clone();
                        data[0] = u8::try_from(v).unwrap_or(0);
                        txn.stage_write(BlockNumber(blk), data);
                        store.commit(txn).expect("commit");
                    }
                }
                let ckpt_dir = tempfile::tempdir().expect("ckpt dir");
                let ckpt_path = ckpt_dir.path().join("ckpt.bin");
                (store, ckpt_dir, ckpt_path)
            },
            |(store, _ckpt_dir, ckpt_path)| {
                store.checkpoint(black_box(&ckpt_path)).expect("checkpoint");
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_truncate_wal_throughput(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let block_data = vec![0xAB_u8; 4096];

    c.bench_function("persistent_mvcc_truncate_wal_after_checkpoint", |b| {
        b.iter_batched(
            || {
                // Seed: 64 commits, then checkpoint so truncate_wal
                // sees a fresh checkpoint horizon (no staleness
                // rejection). Without the checkpoint, truncate_wal
                // would Err on the staleness check rather than
                // exercise the truncate fast-path.
                let tmp = NamedTempFile::new().expect("temp file");
                let path = tmp.path().to_path_buf();
                std::fs::remove_file(&path).ok();
                let store = PersistentMvccStore::open_with_options(
                    &cx,
                    &path,
                    &PersistOptions {
                        sync_on_commit: false,
                        ..PersistOptions::default()
                    },
                )
                .expect("open");
                for i in 0..64_u64 {
                    let mut txn = store.begin();
                    txn.stage_write(BlockNumber(i % 32), block_data.clone());
                    store.commit(txn).expect("commit");
                }
                let ckpt_dir = tempfile::tempdir().expect("ckpt dir");
                let ckpt_path = ckpt_dir.path().join("ckpt.bin");
                store.checkpoint(&ckpt_path).expect("checkpoint");
                (store, ckpt_dir)
            },
            |(store, _ckpt_dir)| {
                store.truncate_wal().expect("truncate_wal");
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

/// Long-lived reader resolving a hot block whose version chain has grown deep.
///
/// Models the `run_long_running_reader_pinning` access pattern at read latency:
/// a write-heavy workload grows a block's chain while an old reader keeps GC
/// pinned, then that reader repeatedly resolves the version visible at its old
/// snapshot. `read_visible` must locate the newest version at or before the
/// reader's snapshot. Two access shapes are measured per depth:
/// - `old_snap`: read at an old snapshot (the long-lived-reader pathology).
/// - `latest`: read at the newest snapshot (the common case; must not regress).
fn bench_read_visible_deep_chain(c: &mut Criterion) {
    let block = BlockNumber(0);

    for &depth in &[256_u64, 4096_u64] {
        // No dedup / no chain cap so the chain actually grows to `depth`
        // (mirrors `run_long_running_reader_pinning`'s policy). Each version
        // carries distinct bytes so identical-write dedup cannot collapse it.
        let mut store = MvccStore::with_compression_policy(CompressionPolicy {
            dedup_identical: false,
            max_chain_length: None,
            algo: CompressionAlgo::None,
        });
        let mut old_snapshot = None;
        for v in 0..depth {
            let mut data = vec![0xCD_u8; 256];
            data[0..8].copy_from_slice(&v.to_le_bytes());
            let mut txn = store.begin();
            txn.stage_write(block, data);
            store.commit(txn).expect("commit");
            if v == 1 {
                old_snapshot = Some(store.current_snapshot());
            }
        }
        let old_snapshot = old_snapshot.expect("snapshot captured");
        let latest = store.current_snapshot();

        c.bench_function(
            &format!("read_visible_deep_chain_old_snap_depth{depth}"),
            |b| {
                b.iter(|| {
                    black_box(store.read_visible(black_box(block), black_box(old_snapshot)));
                });
            },
        );
        c.bench_function(
            &format!("read_visible_deep_chain_latest_depth{depth}"),
            |b| {
                b.iter(|| {
                    black_box(store.read_visible(black_box(block), black_box(latest)));
                });
            },
        );
    }
}

fn bench_conflict_merge_materialization_ab(c: &mut Criterion) {
    let mut group = c.benchmark_group("conflict_merge_materialization_ab");

    for &bytes in &[4096_usize, 16384, 65536] {
        let base = vec![0x11_u8; bytes];
        let latest = vec![0x22_u8; bytes];

        group.bench_with_input(
            BenchmarkId::new("old_vec_clone_base_latest", bytes),
            &(base.clone(), latest.clone()),
            |b, (base, latest)| {
                b.iter(|| {
                    let base = Cow::Borrowed(black_box(base.as_slice())).into_owned();
                    let latest = Cow::Borrowed(black_box(latest.as_slice())).into_owned();
                    black_box((base, latest));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("cow_borrow_base_latest", bytes),
            &(base, latest),
            |b, (base, latest)| {
                b.iter(|| {
                    let base = Cow::Borrowed(black_box(base.as_slice()));
                    let latest = Cow::Borrowed(black_box(latest.as_slice()));
                    black_box((base.as_ref(), latest.as_ref()));
                });
            },
        );
    }

    group.finish();
}

fn bench_bhh0i_actual_contention(c: &mut Criterion) {
    #[cfg(feature = "bench-instrumentation")]
    {
        let mut group = c.benchmark_group("bd_bhh0i_actual_commit");
        let mode = ffs_mvcc::sharded::PublicationMode::Mutex;
        for writers in [1_usize, 2, 4, 8] {
            group.bench_function(
                BenchmarkId::new("probe_overhead_pair_combined_no_ratio", writers),
                |b| {
                    b.iter_custom(|iters| {
                        let rounds = iters.clamp(2, 12);
                        let start = Instant::now();
                        for round in 0..rounds {
                            if round % 2 == 0 {
                                black_box(run_actual_commit_arm(black_box(writers), false, mode));
                                black_box(run_actual_commit_arm(black_box(writers), true, mode));
                            } else {
                                black_box(run_actual_commit_arm(black_box(writers), true, mode));
                                black_box(run_actual_commit_arm(black_box(writers), false, mode));
                            }
                        }
                        let elapsed = start.elapsed();
                        elapsed.mul_f64(iters as f64 / rounds as f64)
                    });
                },
            );
        }
        group.finish();
    }
    #[cfg(not(feature = "bench-instrumentation"))]
    let _ = c;
}

criterion_group!(
    wal_benches,
    bench_read_visible_deep_chain,
    bench_wal_commit_throughput,
    bench_wal_encode_zero_fill_elision_ab,
    bench_wal_positioned_append,
    bench_ssi_overhead,
    bench_ebr_memory_report,
    bench_rcu_read_throughput,
    bench_write_amplification,
    bench_mvcc_contention,
    bench_merge_proof_success_rate,
    bench_gdt_disjoint_range_conflict,
    bench_single_version_chain_storage_ab,
    bench_sharded_mvcc_contention,
    bench_sharded_latest_published_search_ab,
    bench_shard_index_routing_ab,
    bench_pruning_throughput,
    bench_coalesced_append,
    bench_checkpoint_throughput,
    bench_truncate_wal_throughput,
    bench_conflict_merge_materialization_ab,
    bench_bhh0i_actual_contention,
);

fn main() {
    #[cfg(feature = "bench-instrumentation")]
    {
        if std::env::args().any(|arg| arg == "--profile-only") {
            profile_only();
            return;
        }
        print_bench_evidence_metadata();
        print_codegen_isa();
        assert_publication_mode_isomorphism();
        print_actual_null_control();
        spawn_profile_report();
    }
    wal_benches();
}
