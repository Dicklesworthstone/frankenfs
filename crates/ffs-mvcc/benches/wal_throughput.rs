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
use ffs_mvcc::{CompressionAlgo, CompressionPolicy, ConflictPolicy, MergeProof, MvccStore};
use ffs_types::{BlockNumber, CommitSeq, TxnId};
use parking_lot::Mutex;
use serde::Serialize;
use std::fs;
use std::hint::black_box;
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
            || {
                let mut store = MvccStore::new();
                let mut pivot = store.begin();
                for r in 0..192_u64 {
                    pivot.record_read(BlockNumber(r), CommitSeq(1));
                }
                pivot.stage_write(BlockNumber(1_000_000), block_data.clone());
                for k in 0..32_u64 {
                    let mut w = store.begin();
                    let base = 10_000 + k * 1_000;
                    for r in 0..192_u64 {
                        w.record_read(BlockNumber(base + r), CommitSeq(1));
                    }
                    w.stage_write(BlockNumber(2_000_000 + k), block_data.clone());
                    store.commit_ssi(w).expect("seed concurrent record");
                }
                (store, pivot)
            },
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

criterion_group!(
    wal_benches,
    bench_read_visible_deep_chain,
    bench_wal_commit_throughput,
    bench_ssi_overhead,
    bench_ebr_memory_report,
    bench_rcu_read_throughput,
    bench_write_amplification,
    bench_mvcc_contention,
    bench_merge_proof_success_rate,
    bench_sharded_mvcc_contention,
    bench_shard_index_routing_ab,
    bench_pruning_throughput,
    bench_coalesced_append,
    bench_checkpoint_throughput,
    bench_truncate_wal_throughput,
);
criterion_main!(wal_benches);
