use asupersync::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::Budget;
use ffs_mvcc::sharded::ShardedMvccStore;
use ffs_mvcc::{
    AdaptivePolicyConfig, CommitError, CompressionAlgo, CompressionPolicy, ConflictPolicy,
    GcBackpressureConfig, MergeProof, MergeProofMechanism, MvccStore,
};
use ffs_types::{BlockNumber, Snapshot};
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

struct YieldOnce {
    yielded: bool,
}

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<()> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

async fn yield_now() {
    YieldOnce { yielded: false }.await;
}

#[derive(Clone, Copy)]
enum WorkloadPattern {
    Random,
    Hotspot,
    Sequential,
    Adversarial,
}

fn lcg_next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1);
    *state
}

fn choose_block(
    pattern: WorkloadPattern,
    op: u64,
    rng_state: &mut u64,
    block_count: u64,
) -> BlockNumber {
    debug_assert!(block_count > 0);
    let block = match pattern {
        WorkloadPattern::Random => lcg_next(rng_state) % block_count,
        WorkloadPattern::Hotspot => {
            let hotset = (block_count / 10).max(1);
            if lcg_next(rng_state) % 10 < 9 {
                lcg_next(rng_state) % hotset
            } else {
                lcg_next(rng_state) % block_count
            }
        }
        WorkloadPattern::Sequential => op % block_count,
        WorkloadPattern::Adversarial => 0,
    };
    BlockNumber(block)
}

fn seed_sharded_blocks(store: &ShardedMvccStore, blocks: &[(BlockNumber, Vec<u8>)]) {
    let mut txn = store.begin();
    for (block, bytes) in blocks {
        txn.stage_write(*block, bytes.clone());
    }
    store.commit(txn).expect("seed commit should succeed");
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "stress test intentionally keeps end-to-end orchestration in one place"
)]
fn stress_concurrent_rw() {
    const BLOCK_COUNT: u64 = 64;
    const WRITER_COUNT: u64 = 6;
    const READER_COUNT: u64 = 6;
    const OPS_PER_WRITER: u64 = 300;
    const READS_PER_READER: u64 = 300;

    for seed in 0_u64..8 {
        let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(1_000_000));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let store = Arc::new(ShardedMvccStore::new(8));

        let mut seed_txn = store.begin();
        for block in 0_u64..BLOCK_COUNT {
            seed_txn.stage_write(BlockNumber(block), vec![0; 16]);
        }
        store.commit(seed_txn).expect("seed commit should succeed");

        let committed = Arc::new(AtomicU64::new(0));
        let conflicts = Arc::new(AtomicU64::new(0));
        let stable_reads = Arc::new(AtomicU64::new(0));

        let writer_patterns = [
            WorkloadPattern::Random,
            WorkloadPattern::Hotspot,
            WorkloadPattern::Sequential,
            WorkloadPattern::Adversarial,
            WorkloadPattern::Random,
            WorkloadPattern::Hotspot,
        ];

        for writer_id in 0_u64..WRITER_COUNT {
            let store = Arc::clone(&store);
            let committed = Arc::clone(&committed);
            let conflicts = Arc::clone(&conflicts);
            let pattern =
                writer_patterns[usize::try_from(writer_id).expect("writer id fits in usize")];
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let mut rng_state = seed
                        ^ writer_id
                            .wrapping_add(1)
                            .wrapping_mul(0x9E37_79B9_7F4A_7C15);
                    for op in 0_u64..OPS_PER_WRITER {
                        yield_now().await;
                        let block = choose_block(pattern, op, &mut rng_state, BLOCK_COUNT);
                        let mut txn = store.begin();
                        let byte = u8::try_from((writer_id + op) % 251).expect("value fits in u8");
                        txn.stage_write(block, vec![byte; 16]);
                        match store.commit(txn) {
                            Ok(_) => {
                                committed.fetch_add(1, Ordering::Relaxed);
                            }
                            Err((CommitError::Conflict { .. }, _)) => {
                                conflicts.fetch_add(1, Ordering::Relaxed);
                            }
                            Err((err, _)) => {
                                panic!("seed {seed}: writer {writer_id} op {op} unexpected {err:?}")
                            }
                        }
                    }
                })
                .expect("create writer task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        for reader_id in 0_u64..READER_COUNT {
            let store = Arc::clone(&store);
            let stable_reads = Arc::clone(&stable_reads);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let mut rng_state = seed
                        ^ reader_id
                            .wrapping_add(1)
                            .wrapping_mul(0xA076_1D64_78BD_642F_u64);
                    for op in 0_u64..READS_PER_READER {
                        yield_now().await;
                        let snapshot = store.current_snapshot();
                        let base_block =
                            choose_block(WorkloadPattern::Hotspot, op, &mut rng_state, BLOCK_COUNT);
                        for offset in 0_u64..4 {
                            let block = BlockNumber((base_block.0 + offset) % BLOCK_COUNT);
                            let first = store
                                .read_visible(block, snapshot)
                                .expect("seeded block must remain readable");
                            let second = store
                                .read_visible(block, snapshot)
                                .expect("seeded block must remain readable");
                            assert_eq!(
                                first, second,
                                "seed {seed}: reader {reader_id} observed non-repeatable read at op {op} block {}",
                                block.0
                            );
                            stable_reads.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
                .expect("create reader task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();

        let commit_count = committed.load(Ordering::Relaxed);
        let conflict_count = conflicts.load(Ordering::Relaxed);
        let stable_read_count = stable_reads.load(Ordering::Relaxed);

        assert!(
            commit_count > 0,
            "seed {seed}: expected at least one committed write"
        );
        assert!(
            stable_read_count > 0,
            "seed {seed}: expected reader checks to run"
        );
        assert!(
            commit_count + conflict_count == WRITER_COUNT * OPS_PER_WRITER,
            "seed {seed}: commit+conflict accounting mismatch"
        );

        let latest = store.current_snapshot();
        for block in 0_u64..BLOCK_COUNT {
            let data = store
                .read_visible(BlockNumber(block), latest)
                .expect("seeded block remains visible");
            assert_eq!(
                data.len(),
                16,
                "seed {seed}: block {block} should retain 16-byte payloads"
            );
        }
    }
}

#[test]
fn stress_fcw_conflicts() {
    const WRITER_PAIRS_PER_SEED: u64 = 2_000;
    let hot_block = BlockNumber(1);

    for seed in 0_u64..16 {
        let store = ShardedMvccStore::new(1);

        let mut seed_txn = store.begin();
        seed_txn.stage_write(hot_block, vec![0; 8]);
        store.commit(seed_txn).expect("seed commit should succeed");

        let mut commit_count = 0_u64;
        let mut conflict_count = 0_u64;

        let mut rng_state = seed.wrapping_add(0xD1B5_4A32_D192_ED03);
        for pair in 0_u64..WRITER_PAIRS_PER_SEED {
            let mut txn_one = store.begin();
            let mut txn_two = store.begin();
            let byte_one = u8::try_from((lcg_next(&mut rng_state) + pair) % 251).expect("fits");
            let byte_two = u8::try_from((lcg_next(&mut rng_state) + pair + 1) % 251).expect("fits");
            txn_one.stage_write(hot_block, vec![byte_one; 8]);
            txn_two.stage_write(hot_block, vec![byte_two; 8]);

            let (first, second) = if lcg_next(&mut rng_state).is_multiple_of(2) {
                (txn_one, txn_two)
            } else {
                (txn_two, txn_one)
            };

            match store.commit(first) {
                Ok(_) => commit_count += 1,
                Err((err, _)) => panic!("seed {seed}: first commit in pair {pair} failed: {err:?}"),
            }
            match store.commit(second) {
                Ok(_) => panic!("seed {seed}: second commit in pair {pair} must conflict"),
                Err((CommitError::Conflict { .. }, _)) => conflict_count += 1,
                Err((err, _)) => {
                    panic!("seed {seed}: unexpected FCW error in pair {pair}: {err:?}")
                }
            }
        }

        assert!(
            commit_count > 0,
            "seed {seed}: at least one writer should commit"
        );
        assert!(
            conflict_count > 0,
            "seed {seed}: FCW stress should produce conflicts on hot block"
        );
        assert_eq!(
            commit_count, WRITER_PAIRS_PER_SEED,
            "seed {seed}: every first commit should succeed"
        );
        assert_eq!(
            conflict_count, WRITER_PAIRS_PER_SEED,
            "seed {seed}: every second commit should conflict"
        );

        let latest = store.current_snapshot();
        let data = store
            .read_visible(hot_block, latest)
            .expect("hot block must remain readable");
        assert_eq!(data.len(), 8, "seed {seed}: payload width should remain 8");
    }
}

#[test]
fn stress_merge_proof_append_only_conflicts_emit_structured_progress() {
    const WRITER_COUNT: u8 = 100;
    let hot_block = BlockNumber(7);
    let store = ShardedMvccStore::with_compression_policy(1, CompressionPolicy::dedup_only());

    let mut seed_txn = store.begin();
    seed_txn.stage_write(hot_block, vec![0]);
    store.commit(seed_txn).expect("seed commit should succeed");

    let mut txns = Vec::new();
    for writer in 1_u8..=WRITER_COUNT {
        let mut txn = store.begin();
        txn.stage_write_with_proof(
            hot_block,
            vec![0, writer],
            MergeProof::AppendOnly { base_len: 1 },
        );
        txns.push((writer, txn));
    }

    for (writer, txn) in txns {
        let commit_seq = store
            .commit(txn)
            .expect("append-only merge proof should avoid unnecessary aborts");
        eprintln!(
            "event=merge_append_commit writer={} commit_seq={} block={}",
            writer, commit_seq.0, hot_block.0
        );
    }

    let latest = store.current_snapshot();
    let data = store
        .read_visible(hot_block, latest)
        .expect("hot block must remain readable");
    let mut expected = vec![0];
    expected.extend(1_u8..=WRITER_COUNT);
    assert_eq!(
        data, expected,
        "append-only merge stress must retain all tails"
    );
}

#[test]
fn stress_fcw_hotspot_retry_fairness() {
    const WRITER_COUNT: u64 = 6;
    const COMMITS_PER_WRITER: u64 = 64;
    const MAX_ATTEMPTS_PER_COMMIT: u64 = 512;
    let hot_block = BlockNumber(11);

    for seed in 0_u64..12 {
        let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(4_000_000));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let store = Arc::new(ShardedMvccStore::new(1));

        let mut seed_txn = store.begin();
        seed_txn.stage_write(hot_block, vec![0; 8]);
        store.commit(seed_txn).expect("seed commit should succeed");

        let writer_slots = usize::try_from(WRITER_COUNT).expect("writer count fits in usize");
        let per_writer_commits = Arc::new(
            (0..writer_slots)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>(),
        );
        let per_writer_conflicts = Arc::new(
            (0..writer_slots)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>(),
        );

        for writer_id in 0_u64..WRITER_COUNT {
            let store = Arc::clone(&store);
            let per_writer_commits = Arc::clone(&per_writer_commits);
            let per_writer_conflicts = Arc::clone(&per_writer_conflicts);
            let writer_idx = usize::try_from(writer_id).expect("writer id fits in usize");
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let mut rng_state = seed
                        ^ writer_id
                            .wrapping_add(11)
                            .wrapping_mul(0xA24B_1C62_44E3_0AA9);

                    for op in 0_u64..COMMITS_PER_WRITER {
                        let mut committed = false;
                        for attempt in 0_u64..MAX_ATTEMPTS_PER_COMMIT {
                            yield_now().await;
                            let mut txn = store.begin();
                            let token = lcg_next(&mut rng_state);
                            let byte = u8::try_from((token + writer_id + op + attempt) % 251)
                                .expect("fits in u8");
                            txn.stage_write(hot_block, vec![byte; 8]);
                            match store.commit(txn) {
                                Ok(_) => {
                                    per_writer_commits[writer_idx].fetch_add(1, Ordering::Relaxed);
                                    committed = true;
                                    break;
                                }
                                Err((CommitError::Conflict { .. }, _)) => {
                                    per_writer_conflicts[writer_idx]
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                Err((err, _)) => {
                                    panic!(
                                        "seed {seed}: writer {writer_id} op {op} unexpected {err:?}"
                                    )
                                }
                            }
                        }

                        assert!(
                            committed,
                            "seed {seed}: writer {writer_id} op {op} exceeded retry bound {MAX_ATTEMPTS_PER_COMMIT}"
                        );
                    }
                })
                .expect("create writer task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();

        let mut total_commits = 0_u64;
        let mut total_conflicts = 0_u64;
        for writer_idx in 0..writer_slots {
            let commits = per_writer_commits[writer_idx].load(Ordering::Relaxed);
            let conflicts = per_writer_conflicts[writer_idx].load(Ordering::Relaxed);
            total_commits = total_commits.saturating_add(commits);
            total_conflicts = total_conflicts.saturating_add(conflicts);
            assert_eq!(
                commits, COMMITS_PER_WRITER,
                "seed {seed}: writer {writer_idx} did not make bounded progress under hotspot contention"
            );
        }

        assert_eq!(
            total_commits,
            WRITER_COUNT * COMMITS_PER_WRITER,
            "seed {seed}: aggregate commit accounting mismatch"
        );
        let _ = total_conflicts;

        let latest = store.current_snapshot();
        let data = store
            .read_visible(hot_block, latest)
            .expect("hot block must remain readable");
        assert_eq!(data.len(), 8, "seed {seed}: payload width should remain 8");
    }
}

#[test]
fn stress_ssi_write_skew() {
    let block_a = BlockNumber(100);
    let block_b = BlockNumber(200);

    for seed in 0_u64..128 {
        let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(200_000));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let store = Arc::new(Mutex::new(MvccStore::new()));

        {
            let mut guard = store.lock().expect("store lock");
            let mut seed_txn = guard.begin();
            seed_txn.stage_write(block_a, vec![1]);
            seed_txn.stage_write(block_b, vec![1]);
            guard.commit_ssi(seed_txn).expect("seed commit");
        }

        let outcomes = Arc::new(Mutex::new((None, None)));
        let ((mut txn_one, a_ver), (mut txn_two, b_ver)) = {
            let mut guard = store.lock().expect("store lock");
            let first = guard.begin();
            let a_ver = guard.latest_commit_seq(block_a);
            let second = guard.begin();
            let b_ver = guard.latest_commit_seq(block_b);
            drop(guard);
            ((first, a_ver), (second, b_ver))
        };

        {
            let store = Arc::clone(&store);
            let outcomes = Arc::clone(&outcomes);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    if seed % 2 == 0 {
                        yield_now().await;
                    }
                    txn_one.record_read(block_a, a_ver);
                    txn_one.stage_write(block_b, vec![2]);
                    let result = store
                        .lock()
                        .expect("store lock")
                        .commit_ssi(txn_one)
                        .is_ok();
                    outcomes.lock().expect("outcomes lock").0 = Some(result);
                })
                .expect("create txn_one task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        {
            let store = Arc::clone(&store);
            let outcomes = Arc::clone(&outcomes);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    if seed % 2 == 1 {
                        yield_now().await;
                    }
                    txn_two.record_read(block_b, b_ver);
                    txn_two.stage_write(block_a, vec![2]);
                    let result = store
                        .lock()
                        .expect("store lock")
                        .commit_ssi(txn_two)
                        .is_ok();
                    outcomes.lock().expect("outcomes lock").1 = Some(result);
                })
                .expect("create txn_two task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();

        let (txn_one_ok, txn_two_ok) = {
            let guard = outcomes.lock().expect("outcomes lock");
            (
                guard.0.expect("txn_one completed"),
                guard.1.expect("txn_two completed"),
            )
        };
        assert!(
            txn_one_ok ^ txn_two_ok,
            "seed {seed}: SSI write-skew should allow exactly one commit, got txn_one={txn_one_ok}, txn_two={txn_two_ok}"
        );

        let guard = store.lock().expect("store lock");
        let snap = guard.current_snapshot();
        let a = guard.read_visible(block_a, snap).expect("A visible")[0];
        let b = guard.read_visible(block_b, snap).expect("B visible")[0];
        drop(guard);
        assert_eq!(
            a + b,
            3,
            "seed {seed}: SSI should prevent double-write skew (a={a}, b={b})"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn stress_honesty_ssi_single_edges_commit_two_edge_pivots_abort() {
    const CASES_PER_SEED: u64 = 18;

    for seed in 0_u64..32 {
        let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(300_000));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let store = Arc::new(Mutex::new(MvccStore::new()));
        let single_outgoing_commits = Arc::new(AtomicU64::new(0));
        let single_incoming_commits = Arc::new(AtomicU64::new(0));
        let two_edge_aborts = Arc::new(AtomicU64::new(0));

        for case_id in 0_u64..CASES_PER_SEED {
            let store = Arc::clone(&store);
            let single_outgoing_commits = Arc::clone(&single_outgoing_commits);
            let single_incoming_commits = Arc::clone(&single_incoming_commits);
            let two_edge_aborts = Arc::clone(&two_edge_aborts);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    yield_now().await;
                    let read_block = BlockNumber(
                        10_000_u64
                            .saturating_add(seed.saturating_mul(1_000))
                            .saturating_add(case_id.saturating_mul(10)),
                    );
                    let write_block = BlockNumber(read_block.0 + 1);
                    let side_block = BlockNumber(read_block.0 + 2);
                    let mut guard = store.lock().expect("store lock");

                    let mut seed_txn = guard.begin();
                    seed_txn.stage_write(read_block, vec![1]);
                    seed_txn.stage_write(write_block, vec![1]);
                    seed_txn.stage_write(side_block, vec![1]);
                    guard.commit_ssi(seed_txn).expect("seed commit");

                    match case_id % 3 {
                        0 => {
                            let mut pivot = guard.begin();
                            pivot.record_read(read_block, guard.latest_commit_seq(read_block));
                            pivot.stage_write(write_block, vec![2]);

                            let mut concurrent_writer = guard.begin();
                            concurrent_writer.stage_write(read_block, vec![3]);
                            guard
                                .commit_ssi(concurrent_writer)
                                .expect("concurrent writer commits");

                            guard.commit_ssi(pivot).unwrap_or_else(|err| {
                                panic!(
                                    "seed {seed} case {case_id}: single outgoing rw edge must commit, got {err:?}"
                                )
                            });
                            single_outgoing_commits.fetch_add(1, Ordering::Relaxed);
                            eprintln!(
                                "event=ssi_honesty seed={seed} case={case_id} outcome=single_outgoing_commit read_block={} write_block={}",
                                read_block.0, write_block.0
                            );
                        }
                        1 => {
                            let mut pivot = guard.begin();
                            pivot.stage_write(write_block, vec![2]);

                            let mut concurrent_reader = guard.begin();
                            concurrent_reader
                                .record_read(write_block, guard.latest_commit_seq(write_block));
                            concurrent_reader.stage_write(side_block, vec![3]);
                            guard
                                .commit_ssi(concurrent_reader)
                                .expect("concurrent reader commits");

                            guard.commit_ssi(pivot).unwrap_or_else(|err| {
                                panic!(
                                    "seed {seed} case {case_id}: single incoming rw edge must commit, got {err:?}"
                                )
                            });
                            single_incoming_commits.fetch_add(1, Ordering::Relaxed);
                            eprintln!(
                                "event=ssi_honesty seed={seed} case={case_id} outcome=single_incoming_commit reader_block={} write_block={}",
                                write_block.0, side_block.0
                            );
                        }
                        _ => {
                            let mut pivot = guard.begin();
                            pivot.record_read(read_block, guard.latest_commit_seq(read_block));
                            pivot.stage_write(write_block, vec![2]);

                            let mut concurrent_pivot_neighbor = guard.begin();
                            concurrent_pivot_neighbor
                                .record_read(write_block, guard.latest_commit_seq(write_block));
                            concurrent_pivot_neighbor.stage_write(read_block, vec![3]);
                            guard
                                .commit_ssi(concurrent_pivot_neighbor)
                                .expect("neighbor commits");

                            let err = guard
                                .commit_ssi(pivot)
                                .expect_err("two-edge dangerous-structure pivot must abort");
                            assert!(
                                matches!(err, CommitError::SsiConflict { .. }),
                                "seed {seed} case {case_id}: expected SsiConflict, got {err:?}"
                            );
                            two_edge_aborts.fetch_add(1, Ordering::Relaxed);
                            eprintln!(
                                "event=ssi_honesty seed={seed} case={case_id} outcome=two_edge_abort incoming_block={} outgoing_block={}",
                                write_block.0, read_block.0
                            );
                        }
                    }
                    drop(guard);
                })
                .expect("create ssi honesty task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();

        let outgoing = single_outgoing_commits.load(Ordering::Relaxed);
        let incoming = single_incoming_commits.load(Ordering::Relaxed);
        let two_edge = two_edge_aborts.load(Ordering::Relaxed);
        assert_eq!(
            outgoing,
            CASES_PER_SEED / 3,
            "seed {seed}: all single-outgoing cases must commit"
        );
        assert_eq!(
            incoming,
            CASES_PER_SEED / 3,
            "seed {seed}: all single-incoming cases must commit"
        );
        assert_eq!(
            two_edge,
            CASES_PER_SEED / 3,
            "seed {seed}: all two-edge pivot cases must abort"
        );
        eprintln!(
            "event=ssi_honesty_seed_summary seed={seed} single_outgoing_commits={outgoing} single_incoming_commits={incoming} two_edge_aborts={two_edge}"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn stress_honesty_merge_proofs_require_explicit_same_block_evidence() {
    const WRITERS_PER_MODE: u8 = 24;

    for seed in 0_u64..24 {
        let store = ShardedMvccStore::with_compression_policy(2, CompressionPolicy::dedup_only());
        store.set_conflict_policy(ConflictPolicy::SafeMerge);
        let default_block = BlockNumber(20_000 + seed.saturating_mul(10));
        let append_block = BlockNumber(default_block.0 + 1);
        let disjoint_label_block = BlockNumber(default_block.0 + 2);
        let range_base_block = BlockNumber(default_block.0 + 3);
        seed_sharded_blocks(
            &store,
            &[
                (default_block, vec![0]),
                (append_block, vec![0]),
                (disjoint_label_block, vec![0]),
                (range_base_block, vec![0; 8]),
                (BlockNumber(range_base_block.0 + 1), vec![0; 8]),
                (BlockNumber(range_base_block.0 + 2), vec![0; 8]),
            ],
        );

        let mut default_txns = Vec::new();
        for writer in 1_u8..=WRITERS_PER_MODE {
            let mut txn = store.begin();
            txn.stage_write(default_block, vec![0, writer]);
            default_txns.push(txn);
        }

        let mut default_commits = 0_u64;
        let mut default_conflicts = 0_u64;
        for txn in default_txns {
            match store.commit(txn) {
                Ok(_) => default_commits = default_commits.saturating_add(1),
                Err((CommitError::Conflict { .. }, _)) => {
                    default_conflicts = default_conflicts.saturating_add(1);
                }
                Err((err, _)) => panic!("seed {seed}: unexpected default-write error {err:?}"),
            }
        }
        assert_eq!(
            default_commits, 1,
            "seed {seed}: exactly one plain same-block writer should commit"
        );
        assert_eq!(
            default_conflicts,
            u64::from(WRITERS_PER_MODE - 1),
            "seed {seed}: plain same-block writers must not receive implicit merge evidence"
        );

        let mut append_txns = Vec::new();
        for writer in 1_u8..=WRITERS_PER_MODE {
            let mut txn = store.begin();
            txn.stage_write_with_proof(
                append_block,
                vec![0, writer],
                MergeProof::AppendOnly { base_len: 1 },
            );
            append_txns.push((writer, txn));
        }

        let mut append_commits = 0_u64;
        for (writer, txn) in append_txns {
            store
                .commit(txn)
                .unwrap_or_else(|_| panic!("seed {seed}: append writer {writer} should merge"));
            append_commits = append_commits.saturating_add(1);
        }
        assert_eq!(
            append_commits,
            u64::from(WRITERS_PER_MODE),
            "seed {seed}: explicit append-only proof should carry every writer"
        );
        let append_data = store
            .read_visible(append_block, store.current_snapshot())
            .expect("append block remains visible");
        let mut expected_append = vec![0];
        expected_append.extend(1_u8..=WRITERS_PER_MODE);
        assert_eq!(
            append_data, expected_append,
            "seed {seed}: append proof must preserve every tail in commit order"
        );

        let mut disjoint_first = store.begin();
        let mut disjoint_second = store.begin();
        disjoint_first.stage_write_with_proof(
            disjoint_label_block,
            vec![0, 1],
            MergeProof::DisjointBlocks,
        );
        disjoint_second.stage_write_with_proof(
            disjoint_label_block,
            vec![0, 2],
            MergeProof::DisjointBlocks,
        );
        store
            .commit(disjoint_first)
            .expect("first disjoint-label write has no conflict");
        let disjoint_err = store
            .commit(disjoint_second)
            .expect_err("DisjointBlocks is not same-block merge evidence");
        assert!(
            matches!(disjoint_err.0, CommitError::Conflict { .. }),
            "seed {seed}: DisjointBlocks same-block conflict should stay FCW, got {disjoint_err:?}"
        );

        let range_cases = [
            (
                "IndependentKeys",
                MergeProof::independent_key_range(0, 2),
                MergeProof::independent_key_range(2, 2),
            ),
            (
                "NonOverlappingExtents",
                MergeProof::non_overlapping_extent_range(0, 2),
                MergeProof::non_overlapping_extent_range(2, 2),
            ),
            (
                "TimestampOnlyInode",
                MergeProof::timestamp_only_inode_range(0, 2),
                MergeProof::timestamp_only_inode_range(2, 2),
            ),
        ];

        for (idx, (label, first_proof, second_proof)) in range_cases.into_iter().enumerate() {
            assert_eq!(
                first_proof.mechanism(),
                MergeProofMechanism::RangeOverlay,
                "{label} must remain a range-overlay label"
            );
            let block = BlockNumber(range_base_block.0 + u64::try_from(idx).expect("idx fits"));
            let mut first = store.begin();
            let mut second = store.begin();
            first.stage_write_with_proof(block, vec![10, 11, 0, 0, 0, 0, 0, 0], first_proof);
            second.stage_write_with_proof(block, vec![0, 0, 12, 13, 0, 0, 0, 0], second_proof);
            store
                .commit(first)
                .unwrap_or_else(|_| panic!("seed {seed}: {label} first write should commit"));
            store
                .commit(second)
                .unwrap_or_else(|_| panic!("seed {seed}: {label} second write should merge"));
            let merged = store
                .read_visible(block, store.current_snapshot())
                .expect("range-overlay block visible");
            assert_eq!(
                merged,
                vec![10, 11, 12, 13, 0, 0, 0, 0],
                "seed {seed}: {label} must share range-overlay byte behavior"
            );
        }

        assert_eq!(
            MergeProof::Unsafe.mechanism(),
            MergeProofMechanism::NoSameBlockMerge
        );
        assert_eq!(
            MergeProof::DisjointBlocks.mechanism(),
            MergeProofMechanism::NoSameBlockMerge
        );
        assert_eq!(
            (MergeProof::AppendOnly { base_len: 1 }).mechanism(),
            MergeProofMechanism::AppendOnly
        );
        eprintln!(
            "event=merge_honesty seed={seed} default_commits={default_commits} default_conflicts={default_conflicts} append_commits={append_commits} range_overlay_labels=3 no_same_block_merge_labels=2"
        );
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "stress test intentionally combines writers, GC, and cleanup assertions"
)]
fn stress_gc_under_load() {
    const BLOCK_COUNT: u64 = 32;
    const WRITER_COUNT: u64 = 4;
    const OPS_PER_WRITER: u64 = 500;
    const MAX_CHAIN: usize = 48;

    let gc_config = GcBackpressureConfig {
        min_poll_quota: 0,
        throttle_sleep: Duration::from_millis(0),
    };

    for seed in 0_u64..6 {
        let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(2_000_000));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let store = Arc::new(Mutex::new(MvccStore::with_compression_policy(
            CompressionPolicy {
                dedup_identical: false,
                max_chain_length: Some(MAX_CHAIN),
                algo: CompressionAlgo::None,
            },
        )));
        let held_snapshots: Arc<Mutex<VecDeque<Snapshot>>> = Arc::new(Mutex::new(VecDeque::new()));
        let gc_batches = Arc::new(AtomicU64::new(0));

        {
            let mut guard = store.lock().expect("store lock");
            let mut seed_txn = guard.begin();
            for block in 0_u64..BLOCK_COUNT {
                seed_txn.stage_write(BlockNumber(block), vec![0; 32]);
            }
            guard.commit(seed_txn).expect("seed commit");
        }

        for writer_id in 0_u64..WRITER_COUNT {
            let store = Arc::clone(&store);
            let held_snapshots = Arc::clone(&held_snapshots);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let mut rng_state = seed
                        ^ writer_id
                            .wrapping_add(5)
                            .wrapping_mul(0x517C_C1B7_2722_0A95);
                    for op in 0_u64..OPS_PER_WRITER {
                        yield_now().await;
                        let block =
                            choose_block(WorkloadPattern::Hotspot, op, &mut rng_state, BLOCK_COUNT);
                        let mut guard = store.lock().expect("store lock");
                        let mut txn = guard.begin();
                        let byte = u8::try_from((writer_id + op + seed) % 251).expect("fits in u8");
                        txn.stage_write(block, vec![byte; 32]);
                        match guard.commit(txn) {
                            Ok(_)
                            | Err(
                                CommitError::Conflict { .. }
                                | CommitError::ChainBackpressure { .. },
                            ) => {}
                            Err(err) => {
                                panic!("seed {seed}: writer {writer_id} op {op} unexpected {err:?}")
                            }
                        }

                        if op % 25 == 0 {
                            let snap = guard.current_snapshot();
                            guard.register_snapshot(snap);
                            let old = {
                                let mut held = held_snapshots.lock().expect("held snapshots");
                                held.push_back(snap);
                                (held.len() > 8)
                                    .then(|| held.pop_front().expect("existing snapshot"))
                            };
                            if let Some(old) = old {
                                let _ = guard.release_snapshot(old);
                            }
                        }

                        if op % 16 == 0 {
                            let _ = guard.prune_safe();
                        }
                    }
                })
                .expect("create writer task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        {
            let store = Arc::clone(&store);
            let gc_batches = Arc::clone(&gc_batches);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let cx = Cx::for_testing();
                    for _ in 0_u64..(OPS_PER_WRITER / 2) {
                        yield_now().await;
                        let mut guard = store.lock().expect("store lock");
                        let _ = guard.prune_safe();
                        let _ = guard.run_gc_batch(&cx, gc_config);
                        guard.ebr_collect();
                        drop(guard);
                        gc_batches.fetch_add(1, Ordering::Relaxed);
                    }
                })
                .expect("create gc task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();

        {
            let cx = Cx::for_testing();
            let mut guard = store.lock().expect("store lock");
            let mut held = held_snapshots.lock().expect("held snapshots");
            while let Some(snapshot) = held.pop_front() {
                let _ = guard.release_snapshot(snapshot);
            }
            drop(held);

            for _ in 0..8 {
                let _ = guard.prune_safe();
                let _ = guard.run_gc_batch(&cx, gc_config);
                guard.ebr_collect();
            }

            let ebr_stats = guard.ebr_stats();
            let block_stats = guard.block_version_stats();
            assert_eq!(
                ebr_stats.pending_versions(),
                0,
                "seed {seed}: GC should drain pending retired versions"
            );
            assert!(
                block_stats.max_chain_length <= MAX_CHAIN,
                "seed {seed}: max chain {} exceeded cap {MAX_CHAIN}",
                block_stats.max_chain_length
            );
            drop(guard);
        }

        assert!(
            gc_batches.load(Ordering::Relaxed) > 0,
            "seed {seed}: expected gc batches to run"
        );
    }
}

#[test]
fn stress_version_chain_growth() {
    const MAX_CHAIN: usize = 32;
    const WRITER_COUNT: u64 = 4;
    const OPS_PER_WRITER: u64 = 1_200;
    let hot_block = BlockNumber(930);

    for seed in 0_u64..8 {
        let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(2_500_000));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let store = Arc::new(Mutex::new(MvccStore::with_compression_policy(
            CompressionPolicy {
                dedup_identical: false,
                max_chain_length: Some(MAX_CHAIN),
                algo: CompressionAlgo::None,
            },
        )));
        let backpressure_events = Arc::new(AtomicU64::new(0));

        {
            let mut guard = store.lock().expect("store lock");
            let mut seed_txn = guard.begin();
            seed_txn.stage_write(hot_block, vec![0; 16]);
            guard.commit(seed_txn).expect("seed commit");
        }

        for writer_id in 0_u64..WRITER_COUNT {
            let store = Arc::clone(&store);
            let backpressure_events = Arc::clone(&backpressure_events);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    for op in 0_u64..OPS_PER_WRITER {
                        yield_now().await;
                        let mut guard = store.lock().expect("store lock");
                        let mut txn = guard.begin();
                        let byte = u8::try_from((writer_id + op + seed) % 251).expect("fits in u8");
                        txn.stage_write(hot_block, vec![byte; 16]);
                        match guard.commit(txn) {
                            Err(CommitError::ChainBackpressure { .. }) => {
                                backpressure_events.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(_) | Err(CommitError::Conflict { .. }) => {}
                            Err(err) => panic!("seed {seed}: unexpected commit error {err:?}"),
                        }
                        if op % 8 == 0 {
                            let _ = guard.prune_safe();
                        }
                    }
                })
                .expect("create writer task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();

        {
            let mut guard = store.lock().expect("store lock");
            let _ = guard.prune_safe();
            guard.ebr_collect();
            let block_stats = guard.block_version_stats();
            assert!(
                block_stats.max_chain_length <= MAX_CHAIN,
                "seed {seed}: chain length {} exceeded cap {MAX_CHAIN}",
                block_stats.max_chain_length
            );
            let latest = guard.current_snapshot();
            assert!(
                guard.read_visible(hot_block, latest).is_some(),
                "seed {seed}: latest value must remain visible"
            );
            drop(guard);
        }

        let _ = backpressure_events.load(Ordering::Relaxed);
    }
}

// ── Verification Gate: bd-m5wf.3.5 — safe-merge correctness ──────────────

/// Stress test: 100+ concurrent writers with a mix of AppendOnly, IndependentKeys,
/// and unmergeable (Unsafe) conflicts under adaptive policy.
///
/// Verifies:
/// 1. All merge proof variants produce correct merged state.
/// 2. No data corruption in any scenario.
/// 3. Adaptive policy tracks contention correctly.
/// 4. Expected-loss of SafeMerge is lower than Strict under measured contention.
#[test]
#[allow(clippy::too_many_lines)]
fn verification_gate_safe_merge_correctness_under_high_contention() {
    const WRITER_COUNT: u8 = 120;
    const BLOCK_SIZE: usize = 128;
    let hot_block_append = BlockNumber(100);
    let hot_block_keys = BlockNumber(101);
    let disjoint_blocks: Vec<BlockNumber> = (200..220).map(BlockNumber).collect();

    let store = ShardedMvccStore::with_compression_policy(4, CompressionPolicy::dedup_only());
    store.set_conflict_policy(ConflictPolicy::Adaptive);

    // Seed: block for append-only (base with 1 byte).
    let mut seed = store.begin();
    seed.stage_write(hot_block_append, vec![0xAA]);
    // Seed: block for independent-keys (128 bytes, zeroed).
    seed.stage_write(hot_block_keys, vec![0; BLOCK_SIZE]);
    // Seed: 20 disjoint blocks.
    for &blk in &disjoint_blocks {
        seed.stage_write(blk, vec![0; 8]);
    }
    store.commit(seed).expect("seed commit must succeed");

    // ── Phase 1: AppendOnly writers (writers 1..=40) ──
    let mut append_txns = Vec::new();
    for writer in 1_u8..=40 {
        let mut txn = store.begin();
        txn.stage_write_with_proof(
            hot_block_append,
            vec![0xAA, writer],
            MergeProof::AppendOnly { base_len: 1 },
        );
        append_txns.push((writer, txn));
    }
    for (writer, txn) in append_txns {
        store
            .commit(txn)
            .unwrap_or_else(|_| panic!("append-only writer {writer} should merge successfully"));
    }

    // Verify: block contains seed byte + all 40 writer bytes.
    let snap_after_append = store.current_snapshot();
    let append_data = store
        .read_visible(hot_block_append, snap_after_append)
        .expect("append block must be readable");
    let mut expected_append = vec![0xAA];
    expected_append.extend(1_u8..=40);
    assert_eq!(
        append_data, expected_append,
        "append-only merge must retain all tails in commit order"
    );

    // ── Phase 2: IndependentKeys writers (writers 41..=80) ──
    // Each writer touches a unique 3-byte range within the 128-byte block.
    let mut key_txns = Vec::new();
    for writer in 41_u8..=80 {
        let offset = usize::from(writer - 41) * 3; // 0, 3, 6, ..., 117
        let mut data = vec![0; BLOCK_SIZE];
        data[offset] = writer;
        data[offset + 1] = writer.wrapping_add(1);
        data[offset + 2] = writer.wrapping_add(2);
        let mut txn = store.begin();
        txn.stage_write_with_proof(
            hot_block_keys,
            data,
            MergeProof::independent_key_range(offset, 3),
        );
        key_txns.push((writer, txn));
    }
    for (writer, txn) in key_txns {
        store
            .commit(txn)
            .unwrap_or_else(|_| panic!("independent-keys writer {writer} should merge"));
    }

    // Verify: each 3-byte range contains the expected writer bytes.
    let snap_after_keys = store.current_snapshot();
    let keys_data = store
        .read_visible(hot_block_keys, snap_after_keys)
        .expect("keys block must be readable");
    for writer in 41_u8..=80 {
        let offset = usize::from(writer - 41) * 3;
        assert_eq!(
            keys_data[offset], writer,
            "independent-keys merge: byte at offset {offset} must be {writer}"
        );
    }

    // ── Phase 3: Disjoint block writers (writers 81..=100) ──
    // Each writer touches a unique block — no conflicts at all.
    let mut disjoint_txns = Vec::new();
    for writer in 81_u8..=100 {
        let block_idx = usize::from(writer - 81);
        let mut txn = store.begin();
        txn.stage_write_with_proof(
            disjoint_blocks[block_idx],
            vec![writer; 8],
            MergeProof::DisjointBlocks,
        );
        disjoint_txns.push((writer, txn));
    }
    for (writer, txn) in disjoint_txns {
        store
            .commit(txn)
            .unwrap_or_else(|_| panic!("disjoint-blocks writer {writer} should commit"));
    }

    // Verify: each disjoint block has the correct writer data.
    let snap_after_disjoint = store.current_snapshot();
    for writer in 81_u8..=100 {
        let block_idx = usize::from(writer - 81);
        let data = store
            .read_visible(disjoint_blocks[block_idx], snap_after_disjoint)
            .expect("disjoint block must be readable");
        assert_eq!(data, vec![writer; 8], "disjoint block {block_idx} mismatch");
    }

    // ── Phase 4: Unmergeable conflicts under Strict should abort ──
    // Temporarily switch to Strict, attempt a conflict, expect abort.
    store.set_conflict_policy(ConflictPolicy::Strict);

    // Begin txn B *before* committing A, so B has a stale snapshot.
    let mut conflict_b = store.begin();
    conflict_b.stage_write_with_proof(
        hot_block_append,
        vec![0xEE; 4],
        MergeProof::AppendOnly { base_len: 1 },
    );

    // Commit A to create a conflict on hot_block_append.
    let mut conflict_a = store.begin();
    conflict_a.stage_write(hot_block_append, vec![0xFF; 4]);
    store.commit(conflict_a).expect("first write succeeds");

    // Now B tries to commit at the old snapshot — should fail under Strict.
    let result = store.commit(conflict_b);
    assert!(
        result.is_err(),
        "Strict policy must reject even mergeable conflicts"
    );

    // Restore to Adaptive.
    store.set_conflict_policy(ConflictPolicy::Adaptive);

    // ── Phase 5: Verify contention metrics and expected-loss ──
    let metrics = store.contention_metrics();
    eprintln!(
        "Verification gate metrics: total_commits={} total_conflicts={} \
         total_merges={} total_aborts={} conflict_rate={:.4} \
         merge_success_rate={:.4} abort_rate={:.4}",
        metrics.total_commits,
        metrics.total_conflicts,
        metrics.total_merges,
        metrics.total_aborts,
        metrics.conflict_rate,
        metrics.merge_success_rate,
        metrics.abort_rate,
    );

    // There must have been some conflicts (phases 1 and 2 write to hot blocks).
    assert!(
        metrics.total_conflicts > 0,
        "contention tracking must record conflicts"
    );

    // Under high merge contention, SafeMerge expected loss should be lower than Strict.
    let config = AdaptivePolicyConfig::default();
    let loss_strict = metrics.expected_loss_strict(&config);
    let loss_merge = metrics.expected_loss_safe_merge(&config);
    eprintln!(
        "Expected loss: strict={loss_strict:.6} safe_merge={loss_merge:.6} \
         delta={:.6} (positive = SafeMerge cheaper)",
        loss_strict - loss_merge
    );
    assert!(
        loss_merge <= loss_strict,
        "SafeMerge expected loss ({loss_merge:.6}) must be <= Strict ({loss_strict:.6}) \
         under high-merge-success contention"
    );

    // Zero corruption: all blocks readable and consistent.
    let final_snap = store.current_snapshot();
    assert!(
        store.read_visible(hot_block_append, final_snap).is_some(),
        "append block must be readable at final snapshot"
    );
    assert!(
        store.read_visible(hot_block_keys, final_snap).is_some(),
        "keys block must be readable at final snapshot"
    );
    for &blk in &disjoint_blocks {
        assert!(
            store.read_visible(blk, final_snap).is_some(),
            "disjoint block {blk:?} must be readable at final snapshot"
        );
    }

    eprintln!(
        "VERIFICATION GATE PASSED: {WRITER_COUNT} total writers, zero data corruption, \
         expected-loss SafeMerge ({loss_merge:.6}) <= Strict ({loss_strict:.6})"
    );
}

#[test]
#[ignore = "canonical spec §22.1 Gate 4: MVCC concurrency"]
fn gate4_mvcc_concurrency() {
    stress_concurrent_rw();
    stress_fcw_conflicts();
    stress_ssi_write_skew();
    stress_gc_under_load();
}
