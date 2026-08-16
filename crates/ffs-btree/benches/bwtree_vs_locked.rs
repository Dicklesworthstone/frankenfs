#![forbid(unsafe_code)]
//! Benchmark: Bw-Tree vs Mutex-protected BTreeMap for concurrent extent index ops.
//!
//! Scenarios:
//! 1. Read-heavy (95% lookup, 5% insert)
//! 2. Write-heavy (30% lookup, 70% insert/delete)
//! 3. Mixed workload (50% lookup, 30% insert, 10% delete, 10% range scan)
//! 4. Single-threaded baseline
//! 5. Consolidation overhead

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use ffs_btree::bw_tree::{
    BwKey, BwValue, ConsolidationConfig, DeltaMutation, MappingTable, PageDelta, PageId,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

const PAGE_CAPACITY: usize = 16;
const PREPOPULATE: u64 = 10_000;
const OPS_PER_THREAD: u64 = 5_000;
const CONSOLIDATION_SCAN_PAGES: usize = 8_192;

// ── Locked BTreeMap baseline ────────────────────────────────────────────

struct LockedBTree {
    inner: Mutex<BTreeMap<u64, u64>>,
}

impl LockedBTree {
    fn new() -> Self {
        Self {
            inner: Mutex::new(BTreeMap::new()),
        }
    }

    fn insert(&self, key: u64, value: u64) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, value);
    }

    fn lookup(&self, key: u64) -> Option<u64> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .copied()
    }

    fn delete(&self, key: u64) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&key);
    }

    fn range_scan(&self, start: u64, count: usize) -> Vec<(u64, u64)> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .range(start..)
            .take(count)
            .map(|(&k, &v)| (k, v))
            .collect()
    }
}

// ── Deterministic RNG for workload generation ───────────────────────────

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

// ── Scenario 1: Read-Heavy (95% lookup, 5% insert) ─────────────────────

fn bench_read_heavy(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_heavy");
    group.sample_size(10);

    for threads in [1_usize, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("bwtree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let table = Arc::new(MappingTable::with_capacity(PAGE_CAPACITY));
                    let page = table.allocate_page().expect("alloc");
                    for i in 0..PREPOPULATE {
                        table.insert(page, BwKey(i), BwValue(i)).expect("insert");
                    }
                    // Consolidate before benchmark
                    let cfg = ConsolidationConfig::default();
                    let _ = table.consolidate_page(page, &cfg);

                    run_bwtree_workload(&table, page, thread_count, 95, 5, 0, 0);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("locked_btree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let tree = Arc::new(LockedBTree::new());
                    for i in 0..PREPOPULATE {
                        tree.insert(i, i);
                    }
                    run_locked_workload(&tree, thread_count, 95, 5, 0, 0);
                });
            },
        );
    }
    group.finish();
}

// ── Scenario 2: Write-Heavy (30% lookup, 70% insert/delete) ────────────

fn bench_write_heavy(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_heavy");
    group.sample_size(10);

    for threads in [1_usize, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("bwtree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let table = Arc::new(MappingTable::with_capacity(PAGE_CAPACITY));
                    let page = table.allocate_page().expect("alloc");
                    for i in 0..PREPOPULATE {
                        table.insert(page, BwKey(i), BwValue(i)).expect("insert");
                    }
                    let cfg = ConsolidationConfig::default();
                    let _ = table.consolidate_page(page, &cfg);

                    run_bwtree_workload(&table, page, thread_count, 30, 40, 30, 0);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("locked_btree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let tree = Arc::new(LockedBTree::new());
                    for i in 0..PREPOPULATE {
                        tree.insert(i, i);
                    }
                    run_locked_workload(&tree, thread_count, 30, 40, 30, 0);
                });
            },
        );
    }
    group.finish();
}

// ── Scenario 3: Mixed workload ──────────────────────────────────────────

fn bench_mixed(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed");
    group.sample_size(10);

    for threads in [1_usize, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("bwtree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let table = Arc::new(MappingTable::with_capacity(PAGE_CAPACITY));
                    let page = table.allocate_page().expect("alloc");
                    for i in 0..PREPOPULATE {
                        table.insert(page, BwKey(i), BwValue(i)).expect("insert");
                    }
                    let cfg = ConsolidationConfig::default();
                    let _ = table.consolidate_page(page, &cfg);

                    run_bwtree_workload(&table, page, thread_count, 50, 30, 10, 10);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("locked_btree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let tree = Arc::new(LockedBTree::new());
                    for i in 0..PREPOPULATE {
                        tree.insert(i, i);
                    }
                    run_locked_workload(&tree, thread_count, 50, 30, 10, 10);
                });
            },
        );
    }
    group.finish();
}

fn bench_mixed_auto_consolidation_ab(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed_auto_consolidation_ab");
    group.sample_size(10);

    group.bench_function("old_deferred_consolidation_8", |b| {
        b.iter(|| {
            let table = Arc::new(MappingTable::with_capacity(PAGE_CAPACITY));
            let page = table.allocate_page().expect("alloc");
            for i in 0..PREPOPULATE {
                legacy_insert_without_preconsolidation(&table, page, BwKey(i), BwValue(i));
            }
            let cfg = ConsolidationConfig::default();
            let _ = table.consolidate_page(page, &cfg);

            run_bwtree_workload_without_preconsolidation(&table, page, 8, 50, 30, 10, 10);
        });
    });

    group.bench_function("new_default_preconsolidation_8", |b| {
        b.iter(|| {
            let table = Arc::new(MappingTable::with_capacity(PAGE_CAPACITY));
            let page = table.allocate_page().expect("alloc");
            for i in 0..PREPOPULATE {
                table.insert(page, BwKey(i), BwValue(i)).expect("insert");
            }
            let cfg = ConsolidationConfig::default();
            let _ = table.consolidate_page(page, &cfg);

            run_bwtree_workload(&table, page, 8, 50, 30, 10, 10);
        });
    });

    group.finish();
}

fn bench_write_heavy_message_buffer_ab(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_heavy_message_buffer_ab");
    group.sample_size(10);

    group.bench_function("old_individual_preconsolidation_8", |b| {
        b.iter(|| {
            let table = Arc::new(MappingTable::with_capacity(PAGE_CAPACITY));
            let page = table.allocate_page().expect("alloc");
            for i in 0..PREPOPULATE {
                insert_without_message_buffer(&table, page, BwKey(i), BwValue(i));
            }
            let cfg = ConsolidationConfig::default();
            let _ = table.consolidate_page(page, &cfg);

            run_bwtree_workload_without_message_buffer(&table, page, 8, 30, 40, 30, 0);
        });
    });

    group.bench_function("new_message_buffer_8", |b| {
        b.iter(|| {
            let table = Arc::new(MappingTable::with_capacity(PAGE_CAPACITY));
            let page = table.allocate_page().expect("alloc");
            for i in 0..PREPOPULATE {
                table.insert(page, BwKey(i), BwValue(i)).expect("insert");
            }
            let cfg = ConsolidationConfig::default();
            let _ = table.consolidate_page(page, &cfg);

            run_bwtree_workload(&table, page, 8, 30, 40, 30, 0);
        });
    });

    group.finish();
}

// ── Scenario 5: Consolidation overhead ──────────────────────────────────

fn bench_consolidation_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("consolidation");
    group.sample_size(10);

    // Measure consolidation cost for varying chain lengths
    for chain_len in [10_u64, 50, 200] {
        group.bench_with_input(
            BenchmarkId::new("consolidate", chain_len),
            &chain_len,
            |b, &len| {
                b.iter(|| {
                    let table = MappingTable::with_capacity(1);
                    let page = table.allocate_page().expect("alloc");
                    for i in 0..len {
                        legacy_insert_without_preconsolidation(&table, page, BwKey(i), BwValue(i));
                    }
                    let cfg = ConsolidationConfig {
                        chain_threshold: 1,
                        max_retries: 64,
                    };
                    table.consolidate_page(page, &cfg).expect("consolidate");
                });
            },
        );
    }
    group.finish();
}

fn scan_for_consolidation_snapshot_control(
    table: &MappingTable,
    allocated: u64,
    threshold: usize,
) -> Vec<PageId> {
    let mut candidates = Vec::new();
    for raw_id in 0..allocated {
        let page_id = PageId(raw_id);
        if let Ok(snapshot) = table.get_page(page_id)
            && snapshot.chain_len > threshold
        {
            candidates.push(page_id);
        }
    }
    candidates
}

fn bench_consolidation_scan_ab(c: &mut Criterion) {
    let table = MappingTable::with_capacity(CONSOLIDATION_SCAN_PAGES);
    for page_index in 0..CONSOLIDATION_SCAN_PAGES {
        let page = table.allocate_page().expect("allocate scan fixture page");
        if page_index % 16 == 0 {
            table
                .insert(page, BwKey(page.0), BwValue(page.0))
                .expect("extend scan fixture chain");
        }
    }

    let allocated = u64::try_from(CONSOLIDATION_SCAN_PAGES).expect("page count fits u64");
    let control = scan_for_consolidation_snapshot_control(&table, allocated, 1);
    let candidate = table.scan_for_consolidation(1);
    assert_eq!(candidate, control);
    assert_eq!(candidate.len(), CONSOLIDATION_SCAN_PAGES / 16);
    assert_eq!(
        table.scan_for_consolidation(0),
        scan_for_consolidation_snapshot_control(&table, allocated, 0)
    );

    let mut group = c.benchmark_group("bwtree_consolidation_scan_8192_pages");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(2));

    for control in ["snapshot_control_a", "snapshot_control_b"] {
        group.bench_function(control, |b| {
            b.iter(|| {
                std::hint::black_box(scan_for_consolidation_snapshot_control(
                    std::hint::black_box(&table),
                    allocated,
                    1,
                ))
            });
        });
    }

    group.bench_function("direct_head_candidate", |b| {
        b.iter(|| {
            std::hint::black_box(
                std::hint::black_box(&table).scan_for_consolidation(std::hint::black_box(1)),
            )
        });
    });

    group.finish();
}

// ── Workload runners ────────────────────────────────────────────────────

fn run_bwtree_workload(
    table: &Arc<MappingTable>,
    page: PageId,
    thread_count: usize,
    lookup_pct: u64,
    insert_pct: u64,
    delete_pct: u64,
    scan_pct: u64,
) {
    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::new();
    let total = lookup_pct + insert_pct + delete_pct + scan_pct;

    for tid in 0..thread_count {
        let table = Arc::clone(table);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let mut rng = (tid as u64 + 1).wrapping_mul(6_364_136_223_846_793_005);
            for _ in 0..OPS_PER_THREAD {
                let op = xorshift64(&mut rng) % total;
                let key = xorshift64(&mut rng) % (PREPOPULATE * 2);
                if op < lookup_pct {
                    let _ = table.lookup(page, BwKey(key));
                } else if op < lookup_pct + insert_pct {
                    let _ = table.insert(page, BwKey(key), BwValue(key + 1));
                } else if op < lookup_pct + insert_pct + delete_pct {
                    let _ = table.delete(page, BwKey(key));
                } else {
                    let _ = table.range_scan(page, BwKey(key), 10);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("no panic");
    }
}

fn append_delta_without_preconsolidation(
    table: &MappingTable,
    page: PageId,
    mutation: DeltaMutation,
) {
    for _ in 0..1_024 {
        let snapshot = table.get_page(page).expect("snapshot");
        let new_head = Arc::new(match mutation {
            DeltaMutation::Insert { key, value } => PageDelta::Insert {
                key,
                value,
                next: snapshot.head,
            },
            DeltaMutation::Delete { key } => PageDelta::Delete {
                key,
                next: snapshot.head,
            },
            DeltaMutation::Split {
                separator,
                new_sibling,
            } => PageDelta::Split {
                separator,
                new_sibling,
                next: snapshot.head,
            },
            DeltaMutation::Merge { removed_sibling } => PageDelta::Merge {
                removed_sibling,
                next: snapshot.head,
            },
        });
        if table
            .cas_page(page, snapshot.epoch, new_head, snapshot.chain_len + 1)
            .expect("legacy cas")
        {
            return;
        }
    }
    panic!("legacy no-preconsolidation append exhausted CAS retries");
}

fn append_delta_without_message_buffer(
    table: &MappingTable,
    page: PageId,
    mutation: DeltaMutation,
) {
    let cfg = ConsolidationConfig::default();
    for _ in 0..1_024 {
        let snapshot = table.get_page(page).expect("snapshot");
        if snapshot.chain_len > cfg.chain_threshold {
            let _ = table.consolidate_page(page, &cfg);
            continue;
        }
        let new_head = Arc::new(match mutation {
            DeltaMutation::Insert { key, value } => PageDelta::Insert {
                key,
                value,
                next: snapshot.head,
            },
            DeltaMutation::Delete { key } => PageDelta::Delete {
                key,
                next: snapshot.head,
            },
            DeltaMutation::Split {
                separator,
                new_sibling,
            } => PageDelta::Split {
                separator,
                new_sibling,
                next: snapshot.head,
            },
            DeltaMutation::Merge { removed_sibling } => PageDelta::Merge {
                removed_sibling,
                next: snapshot.head,
            },
        });
        if table
            .cas_page(page, snapshot.epoch, new_head, snapshot.chain_len + 1)
            .expect("legacy cas")
        {
            return;
        }
    }
    panic!("individual preconsolidation append exhausted CAS retries");
}

fn insert_without_message_buffer(table: &MappingTable, page: PageId, key: BwKey, value: BwValue) {
    append_delta_without_message_buffer(table, page, DeltaMutation::Insert { key, value });
}

fn delete_without_message_buffer(table: &MappingTable, page: PageId, key: BwKey) {
    append_delta_without_message_buffer(table, page, DeltaMutation::Delete { key });
}

fn legacy_insert_without_preconsolidation(
    table: &MappingTable,
    page: PageId,
    key: BwKey,
    value: BwValue,
) {
    append_delta_without_preconsolidation(table, page, DeltaMutation::Insert { key, value });
}

fn legacy_delete_without_preconsolidation(table: &MappingTable, page: PageId, key: BwKey) {
    append_delta_without_preconsolidation(table, page, DeltaMutation::Delete { key });
}

fn run_bwtree_workload_without_preconsolidation(
    table: &Arc<MappingTable>,
    page: PageId,
    thread_count: usize,
    lookup_pct: u64,
    insert_pct: u64,
    delete_pct: u64,
    scan_pct: u64,
) {
    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::new();
    let total = lookup_pct + insert_pct + delete_pct + scan_pct;

    for tid in 0..thread_count {
        let table = Arc::clone(table);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let mut rng = (tid as u64 + 1).wrapping_mul(6_364_136_223_846_793_005);
            for _ in 0..OPS_PER_THREAD {
                let op = xorshift64(&mut rng) % total;
                let key = xorshift64(&mut rng) % (PREPOPULATE * 2);
                if op < lookup_pct {
                    let _ = table.lookup(page, BwKey(key));
                } else if op < lookup_pct + insert_pct {
                    legacy_insert_without_preconsolidation(
                        &table,
                        page,
                        BwKey(key),
                        BwValue(key + 1),
                    );
                } else if op < lookup_pct + insert_pct + delete_pct {
                    legacy_delete_without_preconsolidation(&table, page, BwKey(key));
                } else {
                    let _ = table.range_scan(page, BwKey(key), 10);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("no panic");
    }
}

fn run_bwtree_workload_without_message_buffer(
    table: &Arc<MappingTable>,
    page: PageId,
    thread_count: usize,
    lookup_pct: u64,
    insert_pct: u64,
    delete_pct: u64,
    scan_pct: u64,
) {
    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::new();
    let total = lookup_pct + insert_pct + delete_pct + scan_pct;

    for tid in 0..thread_count {
        let table = Arc::clone(table);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let mut rng = (tid as u64 + 1).wrapping_mul(6_364_136_223_846_793_005);
            for _ in 0..OPS_PER_THREAD {
                let op = xorshift64(&mut rng) % total;
                let key = xorshift64(&mut rng) % (PREPOPULATE * 2);
                if op < lookup_pct {
                    let _ = table.lookup(page, BwKey(key));
                } else if op < lookup_pct + insert_pct {
                    insert_without_message_buffer(&table, page, BwKey(key), BwValue(key + 1));
                } else if op < lookup_pct + insert_pct + delete_pct {
                    delete_without_message_buffer(&table, page, BwKey(key));
                } else {
                    let _ = table.range_scan(page, BwKey(key), 10);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("no panic");
    }
}

fn run_locked_workload(
    tree: &Arc<LockedBTree>,
    thread_count: usize,
    lookup_pct: u64,
    insert_pct: u64,
    delete_pct: u64,
    scan_pct: u64,
) {
    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::new();
    let total = lookup_pct + insert_pct + delete_pct + scan_pct;

    for tid in 0..thread_count {
        let tree = Arc::clone(tree);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let mut rng = (tid as u64 + 1).wrapping_mul(6_364_136_223_846_793_005);
            for _ in 0..OPS_PER_THREAD {
                let op = xorshift64(&mut rng) % total;
                let key = xorshift64(&mut rng) % (PREPOPULATE * 2);
                if op < lookup_pct {
                    let _ = tree.lookup(key);
                } else if op < lookup_pct + insert_pct {
                    tree.insert(key, key + 1);
                } else if op < lookup_pct + insert_pct + delete_pct {
                    tree.delete(key);
                } else {
                    let _ = tree.range_scan(key, 10);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("no panic");
    }
}

// ── Scenario 6: Point-lookup A/B (materialize vs direct chain walk) ─────
//
// Same-binary, same-worker A/B isolating the bd-xmh5g.2 lever: a single
// point query against a consolidated base page carrying a short post-
// consolidation delta chain. The OLD path clones the whole base BTreeMap
// and replays the chain before probing one key (`materialize_page` + get);
// the NEW path (`lookup`) walks newest→oldest deltas and short-circuits.
// Both arms run in the same binary so the ratio is machine-independent.

fn build_chained_page() -> (MappingTable, PageId) {
    let table = MappingTable::with_capacity(PAGE_CAPACITY);
    let page = table.allocate_page().expect("alloc");
    for i in 0..PREPOPULATE {
        table.insert(page, BwKey(i), BwValue(i)).expect("insert");
    }
    // Collapse the prepopulate chain into a single Base delta.
    let cfg = ConsolidationConfig::default();
    let _ = table.consolidate_page(page, &cfg);
    // Short realistic post-consolidation delta chain on top of the base.
    for i in 0..8u64 {
        table
            .insert(page, BwKey(i * 1000), BwValue(i * 1000 + 7))
            .expect("post insert");
        table
            .delete(page, BwKey(i * 1000 + 1))
            .expect("post delete");
    }
    (table, page)
}

fn bench_point_lookup_ab(c: &mut Criterion) {
    let mut group = c.benchmark_group("point_lookup");
    group.sample_size(50);

    let (table, page) = build_chained_page();
    // Spread of probe keys: base hits, deleted keys, and chain-shadowed keys.
    let probes: Vec<BwKey> = (0..64u64).map(|i| BwKey(i * 157 % PREPOPULATE)).collect();

    group.bench_function("old_materialize_then_get", |b| {
        b.iter(|| {
            let mut sum = 0u64;
            for &key in &probes {
                let state = table.materialize_page(page).expect("materialize");
                if let Some(v) = state.get(&key) {
                    sum = sum.wrapping_add(v.0);
                }
            }
            std::hint::black_box(sum)
        });
    });

    group.bench_function("new_direct_lookup", |b| {
        b.iter(|| {
            let mut sum = 0u64;
            for &key in &probes {
                if let Some(v) = table.lookup(page, key).expect("lookup") {
                    sum = sum.wrapping_add(v.0);
                }
            }
            std::hint::black_box(sum)
        });
    });

    group.finish();
}

// ── Scenario 7: Split materialization tail pruning A/A/B ───────────────
//
// Same-binary controls isolate the tail-pruning primitive used while a Bw-tree
// split delta is materialized. The frozen path first collects every key at or
// above the separator and then performs one tree lookup/removal per key. The
// candidate partitions the BTreeMap once and drops the detached upper half.

fn frozen_remove_split_tail(state: &mut BTreeMap<BwKey, BwValue>, separator: BwKey) {
    let keys_to_remove: Vec<_> = state.range(separator..).map(|(key, _)| *key).collect();
    for key in keys_to_remove {
        state.remove(&key);
    }
}

fn split_off_tail(state: &mut BTreeMap<BwKey, BwValue>, separator: BwKey) {
    drop(state.split_off(&separator));
}

fn split_materialization_fixture() -> BTreeMap<BwKey, BwValue> {
    (0..4096_u64)
        .map(|key| (BwKey(key), BwValue(key.wrapping_mul(17))))
        .collect()
}

fn bench_split_materialize_tail_ab(c: &mut Criterion) {
    let fixture = split_materialization_fixture();
    for separator in [0_u64, 1, 2048, 4095, 4096, 5000] {
        let mut control = fixture.clone();
        let mut candidate = fixture.clone();
        frozen_remove_split_tail(&mut control, BwKey(separator));
        split_off_tail(&mut candidate, BwKey(separator));
        assert_eq!(candidate, control, "separator {separator}");
    }

    let mut empty_control = BTreeMap::new();
    let mut empty_candidate = BTreeMap::new();
    frozen_remove_split_tail(&mut empty_control, BwKey(0));
    split_off_tail(&mut empty_candidate, BwKey(0));
    assert_eq!(empty_candidate, empty_control);

    let separator = BwKey(2048);
    let mut group = c.benchmark_group("bwtree_split_materialize_tail_4096");
    group.sample_size(30);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    for control in ["remove_control_a", "remove_control_b"] {
        group.bench_function(control, |b| {
            b.iter_batched(
                || fixture.clone(),
                |mut state| {
                    frozen_remove_split_tail(&mut state, separator);
                    std::hint::black_box(state.len())
                },
                BatchSize::PerIteration,
            );
        });
    }

    group.bench_function("split_off_candidate", |b| {
        b.iter_batched(
            || fixture.clone(),
            |mut state| {
                split_off_tail(&mut state, separator);
                std::hint::black_box(state.len())
            },
            BatchSize::PerIteration,
        );
    });

    group.finish();
}

// ── Scenario 8: Bounded range-scan delta candidates A/A/B ─────────────
//
// A range scan can return at most `count` rows, so delta inserts larger than
// the smallest `count` visible delta keys cannot affect its result. The
// candidate keeps that ordered top-k while retaining every key in the shadow
// set; the controls freeze the previous unbounded delta-value map.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeReplayOp {
    Insert { key: BwKey, value: BwValue },
    Delete { key: BwKey },
    Split { separator: BwKey },
}

fn before_range_bound(key: BwKey, bound: Option<BwKey>) -> bool {
    bound.is_none_or(|bound| key < bound)
}

fn replay_bounded_range<const RETAIN_TOP_K: bool, const FUSE_SHADOW_INSERT: bool>(
    entries: &BTreeMap<BwKey, BwValue>,
    ops: &[RangeReplayOp],
    start: BwKey,
    count: usize,
) -> Vec<(BwKey, BwValue)> {
    if count == 0 {
        return Vec::new();
    }

    let mut delta_values = BTreeMap::new();
    let mut shadowed_keys = std::collections::BTreeSet::new();
    let mut base_upper_bound: Option<BwKey> = None;

    for op in ops {
        match *op {
            RangeReplayOp::Insert { key, value } => {
                let first_seen = if FUSE_SHADOW_INSERT {
                    shadowed_keys.insert(key)
                } else {
                    !shadowed_keys.contains(&key)
                };
                if key >= start && first_seen && before_range_bound(key, base_upper_bound) {
                    let should_retain = !RETAIN_TOP_K
                        || delta_values.len() < count
                        || delta_values
                            .last_key_value()
                            .is_some_and(|(&largest_key, _)| key < largest_key);
                    if should_retain {
                        delta_values.insert(key, value);
                        if RETAIN_TOP_K && delta_values.len() > count {
                            let _ = delta_values.pop_last();
                        }
                    }
                }
                if !FUSE_SHADOW_INSERT {
                    shadowed_keys.insert(key);
                }
            }
            RangeReplayOp::Delete { key } => {
                shadowed_keys.insert(key);
            }
            RangeReplayOp::Split { separator } => {
                base_upper_bound =
                    Some(base_upper_bound.map_or(separator, |bound| bound.min(separator)));
            }
        }
    }

    let mut rows = Vec::with_capacity(count);
    let mut base_iter = entries.range(start..).peekable();
    let mut delta_iter = delta_values.iter().peekable();

    while rows.len() < count {
        let next_base = base_iter
            .peek()
            .map(|&(&key, &value)| (key, value))
            .filter(|&(key, _)| before_range_bound(key, base_upper_bound));
        let next_delta = delta_iter.peek().map(|&(&key, &value)| (key, value));

        match (next_base, next_delta) {
            (Some((base_key, base_value)), Some((delta_key, delta_value))) => {
                match base_key.cmp(&delta_key) {
                    std::cmp::Ordering::Less => {
                        base_iter.next();
                        if !shadowed_keys.contains(&base_key) {
                            rows.push((base_key, base_value));
                        }
                    }
                    std::cmp::Ordering::Greater => {
                        delta_iter.next();
                        rows.push((delta_key, delta_value));
                    }
                    std::cmp::Ordering::Equal => {
                        base_iter.next();
                        delta_iter.next();
                        rows.push((delta_key, delta_value));
                    }
                }
            }
            (Some((base_key, base_value)), None) => {
                base_iter.next();
                if !shadowed_keys.contains(&base_key) {
                    rows.push((base_key, base_value));
                }
            }
            (None, Some((delta_key, delta_value))) => {
                delta_iter.next();
                rows.push((delta_key, delta_value));
            }
            (None, None) => break,
        }
    }

    rows
}

fn range_delta_top_k_fixture() -> (BTreeMap<BwKey, BwValue>, Vec<RangeReplayOp>) {
    let entries = (0..8192_u64)
        .map(|key| (BwKey(key * 2), BwValue(key.wrapping_mul(17))))
        .collect();
    let ops = (0..8192_u64)
        .map(|ordinal| {
            let key = ((ordinal.wrapping_mul(4051)) & 8191) * 2 + 1;
            RangeReplayOp::Insert {
                key: BwKey(key),
                value: BwValue(key.wrapping_mul(31)),
            }
        })
        .collect();
    (entries, ops)
}

fn bench_range_delta_top_k_ab(c: &mut Criterion) {
    let (entries, ops) = range_delta_top_k_fixture();
    for start in [BwKey(0), BwKey(4096), BwKey(16_000)] {
        for count in [0, 1, 16, 1024, 8192] {
            assert_eq!(
                replay_bounded_range::<true, false>(&entries, &ops, start, count),
                replay_bounded_range::<false, false>(&entries, &ops, start, count),
                "start={} count={count}",
                start.0
            );
        }
    }

    let adversarial_entries = (0..32_u64).map(|key| (BwKey(key), BwValue(key))).collect();
    let adversarial_ops = [
        RangeReplayOp::Insert {
            key: BwKey(30),
            value: BwValue(300),
        },
        RangeReplayOp::Delete { key: BwKey(2) },
        RangeReplayOp::Insert {
            key: BwKey(30),
            value: BwValue(30),
        },
        RangeReplayOp::Insert {
            key: BwKey(3),
            value: BwValue(3000),
        },
        RangeReplayOp::Split {
            separator: BwKey(31),
        },
    ];
    for count in 0..=32 {
        assert_eq!(
            replay_bounded_range::<true, false>(
                &adversarial_entries,
                &adversarial_ops,
                BwKey(0),
                count,
            ),
            replay_bounded_range::<false, false>(
                &adversarial_entries,
                &adversarial_ops,
                BwKey(0),
                count,
            ),
            "adversarial count={count}"
        );
    }

    let mut group = c.benchmark_group("bwtree_range_delta_topk_8192_ops_count16");
    group.sample_size(30);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    for control in ["unbounded_control_a", "unbounded_control_b"] {
        group.bench_function(control, |b| {
            b.iter(|| {
                std::hint::black_box(replay_bounded_range::<false, false>(
                    &entries,
                    &ops,
                    BwKey(0),
                    16,
                ))
            });
        });
    }

    group.bench_function("topk_candidate", |b| {
        b.iter(|| {
            std::hint::black_box(replay_bounded_range::<true, false>(
                &entries,
                &ops,
                BwKey(0),
                16,
            ))
        });
    });

    group.finish();
}

// ── Scenario 9: Range-scan shadow membership A/A/B ────────────────────
//
// The frozen path probes `shadowed_keys` and then inserts the same key, paying
// for two ordered-tree descents. The candidate uses `insert`'s boolean result
// as the first-seen predicate and therefore performs one descent.

fn bench_range_shadow_insert_fusion_ab(c: &mut Criterion) {
    let (entries, ops) = range_delta_top_k_fixture();
    for start in [BwKey(0), BwKey(4096), BwKey(16_000)] {
        for count in [0, 1, 16, 1024, 8192] {
            assert_eq!(
                replay_bounded_range::<true, true>(&entries, &ops, start, count),
                replay_bounded_range::<true, false>(&entries, &ops, start, count),
                "start={} count={count}",
                start.0
            );
        }
    }

    let adversarial_entries = (0..32_u64).map(|key| (BwKey(key), BwValue(key))).collect();
    let adversarial_ops = [
        RangeReplayOp::Insert {
            key: BwKey(30),
            value: BwValue(300),
        },
        RangeReplayOp::Delete { key: BwKey(2) },
        RangeReplayOp::Insert {
            key: BwKey(30),
            value: BwValue(30),
        },
        RangeReplayOp::Insert {
            key: BwKey(3),
            value: BwValue(3000),
        },
        RangeReplayOp::Split {
            separator: BwKey(31),
        },
    ];
    for count in 0..=32 {
        assert_eq!(
            replay_bounded_range::<true, true>(
                &adversarial_entries,
                &adversarial_ops,
                BwKey(0),
                count,
            ),
            replay_bounded_range::<true, false>(
                &adversarial_entries,
                &adversarial_ops,
                BwKey(0),
                count,
            ),
            "adversarial count={count}"
        );
    }

    let mut group = c.benchmark_group("bwtree_range_shadow_insert_8192_ops_count16");
    group.sample_size(30);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    for control in ["contains_insert_control_a", "contains_insert_control_b"] {
        group.bench_function(control, |b| {
            b.iter(|| {
                std::hint::black_box(replay_bounded_range::<true, false>(
                    &entries,
                    &ops,
                    BwKey(0),
                    16,
                ))
            });
        });
    }

    group.bench_function("insert_result_candidate", |b| {
        b.iter(|| {
            std::hint::black_box(replay_bounded_range::<true, true>(
                &entries,
                &ops,
                BwKey(0),
                16,
            ))
        });
    });

    group.finish();
}

// ── Scenario 10: Range-scan delta-chain traversal A/A/B ──────────────
//
// The controls freeze the former range-scan walk, which clones and drops an
// Arc at every link. The candidate borrows each next link from the immutable
// head snapshot. Both arms inspect the same chain shape and return its length;
// range replay and result construction are intentionally outside this ratio.

fn range_chain_walk_fixture(delta_count: u64) -> Arc<PageDelta> {
    let mut head = Arc::new(PageDelta::Base {
        entries: BTreeMap::new(),
    });
    for key in 0..delta_count {
        head = Arc::new(PageDelta::Insert {
            key: BwKey(key),
            value: BwValue(key.wrapping_mul(17)),
            next: head,
        });
    }
    head
}

fn range_chain_walk_cloned(head: &Arc<PageDelta>) -> usize {
    let mut cursor = Arc::clone(head);
    let mut chain_len = 0_usize;

    loop {
        chain_len += 1;
        match cursor.as_ref() {
            PageDelta::Base { .. } => return chain_len,
            PageDelta::Insert { next, .. }
            | PageDelta::Delete { next, .. }
            | PageDelta::Split { next, .. }
            | PageDelta::Merge { next, .. }
            | PageDelta::MessageBuffer { next, .. }
            | PageDelta::AppendRun { next, .. } => cursor = Arc::clone(next),
        }
    }
}

fn range_chain_walk_borrowed(head: &Arc<PageDelta>) -> usize {
    let mut cursor = head.as_ref();
    let mut chain_len = 0_usize;

    loop {
        chain_len += 1;
        match cursor {
            PageDelta::Base { .. } => return chain_len,
            PageDelta::Insert { next, .. }
            | PageDelta::Delete { next, .. }
            | PageDelta::Split { next, .. }
            | PageDelta::Merge { next, .. }
            | PageDelta::MessageBuffer { next, .. }
            | PageDelta::AppendRun { next, .. } => cursor = next.as_ref(),
        }
    }
}

fn bench_range_chain_walk_ab(c: &mut Criterion) {
    let head = range_chain_walk_fixture(256);
    assert_eq!(range_chain_walk_cloned(&head), 257);
    assert_eq!(range_chain_walk_borrowed(&head), 257);

    let mut group = c.benchmark_group("bwtree_range_chain_walk_256_deltas");
    group.sample_size(30);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    for control in ["arc_clone_control_a", "arc_clone_control_b"] {
        group.bench_function(control, |b| {
            b.iter(|| std::hint::black_box(range_chain_walk_cloned(std::hint::black_box(&head))));
        });
    }

    group.bench_function("borrowed_candidate", |b| {
        b.iter(|| std::hint::black_box(range_chain_walk_borrowed(std::hint::black_box(&head))));
    });

    group.finish();
}

// ── Scenario 11: Materialization op-collection traversal A/A/B ───────
//
// Materialization first walks the immutable delta chain and records operations
// before it clones the base map and replays them. These controls freeze the
// former per-link Arc clone/drop; the candidate borrows each link. Base cloning
// and replay are intentionally excluded so this row isolates the changed phase.

fn collect_materialize_ops_cloned(head: &Arc<PageDelta>) -> (Vec<RangeReplayOp>, usize) {
    let mut ops = Vec::new();
    let mut cursor = Arc::clone(head);
    let mut chain_len = 0_usize;

    loop {
        chain_len += 1;
        match cursor.as_ref() {
            PageDelta::Base { .. } => return (ops, chain_len),
            PageDelta::Insert { key, value, next } => {
                ops.push(RangeReplayOp::Insert {
                    key: *key,
                    value: *value,
                });
                cursor = Arc::clone(next);
            }
            PageDelta::Delete { key, next } => {
                ops.push(RangeReplayOp::Delete { key: *key });
                cursor = Arc::clone(next);
            }
            PageDelta::Split {
                separator, next, ..
            } => {
                ops.push(RangeReplayOp::Split {
                    separator: *separator,
                });
                cursor = Arc::clone(next);
            }
            PageDelta::Merge { next, .. } => cursor = Arc::clone(next),
            PageDelta::MessageBuffer { .. } | PageDelta::AppendRun { .. } => {
                unreachable!("the direct-delta fixture contains no buffered nodes")
            }
        }
    }
}

fn collect_materialize_ops_borrowed(head: &Arc<PageDelta>) -> (Vec<RangeReplayOp>, usize) {
    let mut ops = Vec::new();
    let mut cursor = head.as_ref();
    let mut chain_len = 0_usize;

    loop {
        chain_len += 1;
        match cursor {
            PageDelta::Base { .. } => return (ops, chain_len),
            PageDelta::Insert { key, value, next } => {
                ops.push(RangeReplayOp::Insert {
                    key: *key,
                    value: *value,
                });
                cursor = next.as_ref();
            }
            PageDelta::Delete { key, next } => {
                ops.push(RangeReplayOp::Delete { key: *key });
                cursor = next.as_ref();
            }
            PageDelta::Split {
                separator, next, ..
            } => {
                ops.push(RangeReplayOp::Split {
                    separator: *separator,
                });
                cursor = next.as_ref();
            }
            PageDelta::Merge { next, .. } => cursor = next.as_ref(),
            PageDelta::MessageBuffer { .. } | PageDelta::AppendRun { .. } => {
                unreachable!("the direct-delta fixture contains no buffered nodes")
            }
        }
    }
}

fn bench_materialize_chain_collect_ab(c: &mut Criterion) {
    let head = range_chain_walk_fixture(256);
    let control = collect_materialize_ops_cloned(&head);
    let candidate = collect_materialize_ops_borrowed(&head);
    assert_eq!(candidate, control);
    assert_eq!(candidate.0.len(), 256);
    assert_eq!(candidate.1, 257);

    let mut group = c.benchmark_group("bwtree_materialize_collect_256_deltas");
    group.sample_size(30);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    for control in ["arc_clone_control_a", "arc_clone_control_b"] {
        group.bench_function(control, |b| {
            b.iter(|| {
                std::hint::black_box(collect_materialize_ops_cloned(std::hint::black_box(&head)))
            });
        });
    }

    group.bench_function("borrowed_candidate", |b| {
        b.iter(|| {
            std::hint::black_box(collect_materialize_ops_borrowed(std::hint::black_box(
                &head,
            )))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_read_heavy,
    bench_write_heavy,
    bench_mixed,
    bench_mixed_auto_consolidation_ab,
    bench_write_heavy_message_buffer_ab,
    bench_consolidation_overhead,
    bench_consolidation_scan_ab,
    bench_point_lookup_ab,
    bench_split_materialize_tail_ab,
    bench_range_delta_top_k_ab,
    bench_range_shadow_insert_fusion_ab,
    bench_range_chain_walk_ab,
    bench_materialize_chain_collect_ab,
);
criterion_main!(benches);
