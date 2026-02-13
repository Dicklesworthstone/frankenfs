#![forbid(unsafe_code)]
#![allow(
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
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_mvcc::persist::{PersistOptions, PersistentMvccStore};
use ffs_mvcc::{CompressionPolicy, MvccStore};
use ffs_types::BlockNumber;
use parking_lot::Mutex;
use serde::Serialize;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

fn bench_wal_commit_throughput(c: &mut Criterion) {
    let cx = Cx::for_testing();

    // 4 KiB block — typical filesystem block size.
    let block_data = vec![0xAB_u8; 4096];

    c.bench_function("wal_commit_4k_sync", |b| {
        let tmp = NamedTempFile::new().expect("temp file");
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();

        let store = PersistentMvccStore::open_with_options(&cx, &path, PersistOptions::default())
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
            PersistOptions {
                sync_on_commit: false,
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
            PersistOptions {
                sync_on_commit: false,
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

criterion_group!(
    wal_benches,
    bench_wal_commit_throughput,
    bench_ssi_overhead,
    bench_ebr_memory_report
);
criterion_main!(wal_benches);
