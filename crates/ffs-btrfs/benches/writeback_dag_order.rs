#![forbid(unsafe_code)]

//! A/B benchmark for btrfs writeback DAG scheduling and construction
//! (`bd-f759f`, `bd-xmh5g.400`).
//!
//! `WriteDependencyDag::reverse_topological_order` runs before every metadata
//! writeback and during crash-consistency enumeration. The flush order is
//! determined by child-vector postorder plus the DAG's `BTreeMap` key order for
//! disconnected components; the visited set only answers membership. This
//! compares the old `BTreeSet` membership model against the production
//! HashSet-backed scheduler while asserting exact order and WB-I1 prefix
//! equivalence. The construction group compares the old child-vector
//! double-clone model against the moved-child production shape.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ffs_btrfs::writeback::{
    CrashPoint, DiskWritebackContext, WbI1Oracle, WriteDependencyDag, WritebackExecutor,
};
use ffs_btrfs::{BtrfsBTree, BtrfsCowNode, BtrfsKey, BtrfsMutationError, InMemoryCowBtrfsTree};
use std::collections::{BTreeMap, BTreeSet};
use std::hint::black_box;

const ITEMS: u64 = 2048;
const MAX_ITEMS: usize = 8;
const GENERATION: u64 = 123;
const NODESIZE: u32 = 16_384;

#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchDagNode {
    level: u8,
    children: Vec<u64>,
}

type BenchDag = BTreeMap<u64, BenchDagNode>;

fn build_tree() -> InMemoryCowBtrfsTree {
    let mut tree = InMemoryCowBtrfsTree::new(MAX_ITEMS).expect("create tree");
    for i in 0..ITEMS {
        let key = BtrfsKey {
            objectid: i,
            item_type: 0x84,
            offset: i * 4096,
        };
        tree.insert(key, &i.to_le_bytes()).expect("insert");
    }
    tree
}

fn build_dag() -> WriteDependencyDag {
    let tree = build_tree();
    WriteDependencyDag::from_cow_tree(&tree, GENERATION).expect("build dag")
}

fn collect_double_clone_model(
    tree: &InMemoryCowBtrfsTree,
    block: u64,
    nodes: &mut BenchDag,
    level: u8,
) -> Result<(), BtrfsMutationError> {
    if nodes.contains_key(&block) {
        return Ok(());
    }

    let node = tree.node_snapshot(block)?;
    let (node_level, children) = match &node {
        BtrfsCowNode::Leaf { .. } => (0, Vec::new()),
        BtrfsCowNode::Internal { children, .. } => (level, children.clone()),
    };

    nodes.insert(
        block,
        BenchDagNode {
            level: node_level,
            children: children.clone(),
        },
    );

    let child_level = level.saturating_sub(1);
    for child in children {
        collect_double_clone_model(tree, child, nodes, child_level)?;
    }

    Ok(())
}

fn collect_single_clone_model(
    tree: &InMemoryCowBtrfsTree,
    block: u64,
    nodes: &mut BenchDag,
    level: u8,
) -> Result<(), BtrfsMutationError> {
    if nodes.contains_key(&block) {
        return Ok(());
    }

    let node = tree.node_snapshot(block)?;
    let (node_level, children) = match node {
        BtrfsCowNode::Leaf { .. } => (0, Vec::new()),
        BtrfsCowNode::Internal { children, .. } => (level, children),
    };
    let recursion_children = children.clone();

    nodes.insert(
        block,
        BenchDagNode {
            level: node_level,
            children,
        },
    );

    let child_level = level.saturating_sub(1);
    for child in recursion_children {
        collect_single_clone_model(tree, child, nodes, child_level)?;
    }

    Ok(())
}

fn double_clone_model(tree: &InMemoryCowBtrfsTree) -> BenchDag {
    let mut nodes = BTreeMap::new();
    collect_double_clone_model(tree, tree.root_block(), &mut nodes, tree.root_level())
        .expect("old double-clone model");
    nodes
}

fn single_clone_model(tree: &InMemoryCowBtrfsTree) -> BenchDag {
    let mut nodes = BTreeMap::new();
    collect_single_clone_model(tree, tree.root_block(), &mut nodes, tree.root_level())
        .expect("single-clone model");
    nodes
}

fn dag_shape_digest(dag: &BenchDag) -> u64 {
    dag.iter()
        .fold(0xcbf2_9ce4_8422_2325_u64, |acc, (block, node)| {
            let mut digest = acc
                .wrapping_mul(0x100_0000_01b3)
                .wrapping_add(*block)
                .wrapping_add(u64::from(node.level));
            for child in &node.children {
                digest = digest.wrapping_mul(0x100_0000_01b3).wrapping_add(*child);
            }
            digest
        })
}

fn assert_build_isomorphic(tree: &InMemoryCowBtrfsTree) {
    let old = double_clone_model(tree);
    let new = single_clone_model(tree);
    assert_eq!(old, new, "single-clone model changed DAG shape");

    let production = WriteDependencyDag::from_cow_tree(tree, GENERATION).expect("production dag");
    assert_eq!(
        production.node_count(),
        old.len(),
        "production node count changed"
    );
    for (block, old_node) in &old {
        let production_node = production.get(*block).expect("production node");
        assert_eq!(production_node.level, old_node.level, "node level changed");
        assert_eq!(
            production_node.children, old_node.children,
            "node children changed"
        );
    }
}

fn btree_push_postorder(
    dag: &WriteDependencyDag,
    block: u64,
    visited: &mut BTreeSet<u64>,
    result: &mut Vec<u64>,
) {
    if !visited.insert(block) {
        return;
    }

    let Some(node) = dag.get(block) else {
        return;
    };

    for child in &node.children {
        btree_push_postorder(dag, *child, visited, result);
    }

    result.push(block);
}

fn btree_visited_order(dag: &WriteDependencyDag) -> Vec<u64> {
    let mut result = Vec::with_capacity(dag.node_count());
    let mut visited = BTreeSet::new();
    btree_push_postorder(dag, dag.root(), &mut visited, &mut result);
    for block in dag.blocks() {
        btree_push_postorder(dag, block, &mut visited, &mut result);
    }
    result
}

/// Guarded variant of `btree_visited_order`: skip the all-nodes robustness
/// sweep when the root walk already emitted every node. Mirrors the production
/// fast path in `reverse_topological_order` so the sweep's redundant
/// already-visited probes can be measured in isolation.
fn btree_visited_order_guarded(dag: &WriteDependencyDag) -> Vec<u64> {
    let mut result = Vec::with_capacity(dag.node_count());
    let mut visited = BTreeSet::new();
    btree_push_postorder(dag, dag.root(), &mut visited, &mut result);
    if result.len() != dag.node_count() {
        for block in dag.blocks() {
            btree_push_postorder(dag, block, &mut visited, &mut result);
        }
    }
    result
}

fn order_digest(order: &[u64]) -> u64 {
    order.iter().fold(0xcbf2_9ce4_8422_2325_u64, |acc, block| {
        acc.wrapping_mul(0x100_0000_01b3).wrapping_add(*block)
    })
}

fn collect_block_levels_current(dag: &WriteDependencyDag) -> Vec<(u64, u8)> {
    dag.all_blocks()
        .into_iter()
        .map(|block| {
            let level = dag
                .node_level(block)
                .expect("block collected from the DAG must have a level");
            (block, level)
        })
        .collect()
}

fn collect_block_levels_streamed(dag: &WriteDependencyDag) -> Vec<(u64, u8)> {
    dag.blocks_with_levels().collect()
}

fn serialize_block_levels(
    tree: &InMemoryCowBtrfsTree,
    block_levels: &[(u64, u8)],
) -> Vec<(u64, Vec<u8>)> {
    let allocated_addrs = block_levels
        .iter()
        .enumerate()
        .map(|(index, (block, _))| {
            let index = u64::try_from(index).expect("DAG index fits u64");
            (*block, 0x4000_0000_u64 + index * u64::from(NODESIZE))
        })
        .collect();
    let context = DiskWritebackContext::with_allocated_addresses(
        [0x11; 16],
        [0x22; 16],
        GENERATION,
        5,
        NODESIZE,
        ffs_types::BTRFS_CSUM_TYPE_CRC32C,
        4096,
        allocated_addrs,
    );

    block_levels
        .iter()
        .map(|(block, level)| {
            let bytes = context
                .serialize_node(tree, *block, *level)
                .expect("serialize benchmark DAG node");
            (*block, bytes)
        })
        .collect()
}

fn block_levels_digest(block_levels: &[(u64, u8)]) -> u64 {
    block_levels
        .iter()
        .fold(0xcbf2_9ce4_8422_2325_u64, |acc, (block, level)| {
            acc.wrapping_mul(0x100_0000_01b3)
                .wrapping_add(*block)
                .wrapping_add(u64::from(*level))
        })
}

fn crash_points_digest(points: &[CrashPoint]) -> u64 {
    points.iter().fold(0xcbf2_9ce4_8422_2325_u64, |acc, point| {
        let id_len = u64::try_from(point.id.len()).expect("crash point id length fits u64");
        let durable_len =
            u64::try_from(point.durable_blocks.len()).expect("durable block count fits u64");
        let mut digest = acc
            .wrapping_mul(0x100_0000_01b3)
            .wrapping_add(id_len)
            .wrapping_add(durable_len)
            .wrapping_add(u64::from(point.superblock_durable))
            .wrapping_add(point.superblock_generation.unwrap_or_default());
        for block in &point.durable_blocks {
            digest = digest.wrapping_mul(0x100_0000_01b3).wrapping_add(*block);
        }
        digest
    })
}

fn execute_legacy_full_dag_snapshots(mut dag: WriteDependencyDag) -> u64 {
    let order = dag.reverse_topological_order();
    let mut crash_points = Vec::with_capacity(order.len() * 2);

    for block in order {
        crash_points.push(CrashPoint::from_dag(
            &dag,
            format!("pre_flush_{block}"),
            false,
        ));
        let level = dag.node_level(block).unwrap_or(0);
        black_box(level);
        dag.mark_durable(block).expect("mark durable");
        crash_points.push(CrashPoint::from_dag(
            &dag,
            format!("post_flush_{block}"),
            false,
        ));
    }

    crash_points_digest(&crash_points)
}

fn execute_production_executor(dag: WriteDependencyDag) -> u64 {
    let mut executor = WritebackExecutor::new(dag);
    executor
        .execute(|block, level| {
            black_box((block, level));
            Ok(())
        })
        .expect("execute writeback");
    crash_points_digest(executor.crash_points())
}

fn assert_isomorphic(dag: &WriteDependencyDag) {
    let old = btree_visited_order(dag);
    let new = dag.reverse_topological_order();
    assert_eq!(
        old, new,
        "HashSet membership changed deterministic DAG flush order"
    );

    for end in 0..=new.len() {
        let durable = new[..end].iter().copied().collect();
        WbI1Oracle::new(durable)
            .check(dag)
            .expect("every flush-order prefix must satisfy WB-I1");
    }
}

fn bench_writeback_dag_order(c: &mut Criterion) {
    let dag = build_dag();
    assert_isomorphic(&dag);

    let mut group = c.benchmark_group("writeback_dag_order_hashset_ab");
    group.bench_function("old_btreeset_visited", |b| {
        b.iter(|| {
            let order = btree_visited_order(black_box(&dag));
            black_box(order_digest(&order))
        });
    });
    group.bench_function("production_hashset_visited", |b| {
        b.iter(|| {
            let order = black_box(&dag).reverse_topological_order();
            black_box(order_digest(&order))
        });
    });
    group.finish();
}

fn bench_writeback_dag_build(c: &mut Criterion) {
    let tree = build_tree();
    assert_build_isomorphic(&tree);

    let mut group = c.benchmark_group("writeback_dag_build_child_vector_ab");
    group.bench_function("old_double_clone_model", |b| {
        b.iter(|| {
            let dag = double_clone_model(black_box(&tree));
            black_box(dag_shape_digest(&dag))
        });
    });
    group.bench_function("single_clone_model", |b| {
        b.iter(|| {
            let dag = single_clone_model(black_box(&tree));
            black_box(dag_shape_digest(&dag))
        });
    });
    group.bench_function("production_from_cow_tree", |b| {
        b.iter(|| {
            let dag = WriteDependencyDag::from_cow_tree(black_box(&tree), GENERATION)
                .expect("build production dag");
            black_box(dag.node_count())
        });
    });
    group.finish();
}

fn bench_writeback_executor_crash_points(c: &mut Criterion) {
    let dag = build_dag();
    assert_eq!(
        execute_legacy_full_dag_snapshots(dag.clone()),
        execute_production_executor(dag.clone()),
        "production executor crash points diverged from legacy full-DAG snapshots"
    );

    let mut group = c.benchmark_group("writeback_executor_crash_points_2048");
    group.bench_function("legacy_full_dag_snapshot_each_flush", |b| {
        b.iter_batched(
            || dag.clone(),
            |dag| black_box(execute_legacy_full_dag_snapshots(dag)),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("production_executor", |b| {
        b.iter_batched(
            || dag.clone(),
            |dag| black_box(execute_production_executor(dag)),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_writeback_dag_block_level_iteration_current(c: &mut Criterion) {
    let tree = build_tree();
    let dag = WriteDependencyDag::from_cow_tree(&tree, GENERATION).expect("build DAG");
    let current_a = collect_block_levels_current(&dag);
    let current_b = collect_block_levels_current(&dag);
    assert_eq!(current_a, current_b, "identical current-code arms diverged");
    let streamed = collect_block_levels_streamed(&dag);
    assert_eq!(
        current_a, streamed,
        "streaming block-level iteration changed allocation order or levels"
    );
    assert_eq!(
        serialize_block_levels(&tree, &current_a),
        serialize_block_levels(&tree, &streamed),
        "streaming block-level iteration changed serialized node bytes"
    );

    let mut group = c.benchmark_group("writeback_dag_block_level_iteration_2048");
    group.bench_function("all_blocks_then_lookup_a", |b| {
        b.iter(|| {
            let block_levels = collect_block_levels_current(black_box(&dag));
            black_box(block_levels_digest(&block_levels))
        });
    });
    group.bench_function("all_blocks_then_lookup_b", |b| {
        b.iter(|| {
            let block_levels = collect_block_levels_current(black_box(&dag));
            black_box(block_levels_digest(&block_levels))
        });
    });
    group.bench_function("streamed_block_levels", |b| {
        b.iter(|| {
            let block_levels = collect_block_levels_streamed(black_box(&dag));
            black_box(block_levels_digest(&block_levels))
        });
    });
    group.finish();
}

// ── crash-tracking opt-out (production writeback never reads crash points) ──
//
// `WritebackExecutor::execute` records two crash points per flushed node, each
// cloning the growing durable-block `BTreeSet` (O(N²) copies over a commit) and
// formatting a per-node id string. The production btrfs commit drives writeback
// purely for the disk side effects in `flush_node` and never reads
// `crash_points()`, so it now calls `.without_crash_tracking()`. This measures
// the per-`execute` saving on the 2048-node DAG.

/// Run `execute`, capturing the exact `(block, level)` flush sequence and the
/// number of crash points recorded. Used to prove the toggle is byte-identical
/// on the disk-write path.
fn execute_flush_sequence(dag: WriteDependencyDag, track: bool) -> (Vec<(u64, u8)>, usize) {
    let mut executor = if track {
        WritebackExecutor::new(dag)
    } else {
        WritebackExecutor::new(dag).without_crash_tracking()
    };
    let mut calls: Vec<(u64, u8)> = Vec::new();
    executor
        .execute(|block, level| {
            calls.push((block, level));
            Ok(())
        })
        .expect("execute writeback");
    let crash_points = executor.crash_points().len();
    (calls, crash_points)
}

/// Minimal-closure `execute` for timing: measures the crash-tracking cost with
/// a trivial flush body so the recording delta dominates. Returns the crash
/// point count to defeat dead-code elimination.
fn execute_measure(dag: WriteDependencyDag, track: bool) -> usize {
    let mut executor = if track {
        WritebackExecutor::new(dag)
    } else {
        WritebackExecutor::new(dag).without_crash_tracking()
    };
    executor
        .execute(|block, level| {
            black_box((block, level));
            Ok(())
        })
        .expect("execute writeback");
    executor.crash_points().len()
}

fn bench_writeback_executor_crash_tracking(c: &mut Criterion) {
    let dag = build_dag();

    // Byte-identity proof: the `flush_node` closure performs every disk write in
    // production, and it receives the identical `(block, level)` sequence whether
    // or not crash points are recorded. Disabling recording only drops telemetry
    // that production never reads.
    let (tracked_calls, tracked_cp) = execute_flush_sequence(dag.clone(), true);
    let (untracked_calls, untracked_cp) = execute_flush_sequence(dag.clone(), false);
    assert_eq!(
        tracked_calls, untracked_calls,
        "without_crash_tracking changed the flush (block, level) sequence"
    );
    assert_eq!(
        untracked_cp, 0,
        "untracked executor must record zero crash points"
    );
    assert!(
        tracked_cp >= tracked_calls.len(),
        "tracked executor must still record per-flush crash points"
    );

    let mut group = c.benchmark_group("writeback_executor_crash_tracking_2048");
    group.bench_function("record_crash_points_a", |b| {
        b.iter_batched(
            || dag.clone(),
            |dag| black_box(execute_measure(dag, true)),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("record_crash_points_b", |b| {
        b.iter_batched(
            || dag.clone(),
            |dag| black_box(execute_measure(dag, true)),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("without_crash_tracking", |b| {
        b.iter_batched(
            || dag.clone(),
            |dag| black_box(execute_measure(dag, false)),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

// ── stream (block, level) from the postorder walk vs re-probe node_level ────
//
// `WritebackExecutor::execute` needs each flushed node's tree level. The old
// path built `reverse_topological_order()` then re-probed `node_level(block)`
// per node — a second BTreeMap lookup per flush. `reverse_topological_order_
// with_levels()` reads the level from the node already visited during the
// postorder walk, dropping the per-node relookup. Both produce the identical
// (block, level) sequence, so the flush order and disk output are unchanged.

fn order_then_relookup(dag: &WriteDependencyDag) -> Vec<(u64, u8)> {
    dag.reverse_topological_order()
        .into_iter()
        .map(|block| (block, dag.node_level(block).unwrap_or(0)))
        .collect()
}

fn order_levels_digest(order: &[(u64, u8)]) -> u64 {
    order
        .iter()
        .fold(0xcbf2_9ce4_8422_2325_u64, |acc, (block, level)| {
            acc.wrapping_mul(0x100_0000_01b3)
                .wrapping_add(*block)
                .wrapping_add(u64::from(*level))
        })
}

/// Faithful to `execute`'s old path: build the block order once, then read each
/// node's level via a per-node `node_level` probe folded inline (no re-collect).
fn digest_order_then_relookup(dag: &WriteDependencyDag) -> u64 {
    dag.reverse_topological_order()
        .into_iter()
        .fold(0xcbf2_9ce4_8422_2325_u64, |acc, block| {
            let level = dag.node_level(block).unwrap_or(0);
            acc.wrapping_mul(0x100_0000_01b3)
                .wrapping_add(block)
                .wrapping_add(u64::from(level))
        })
}

/// Faithful to `execute`'s new path: the level rides along from the postorder
/// walk, no per-node relookup.
fn digest_order_with_levels(dag: &WriteDependencyDag) -> u64 {
    order_levels_digest(&dag.reverse_topological_order_with_levels())
}

fn bench_writeback_order_with_levels(c: &mut Criterion) {
    let dag = build_dag();
    let relookup = order_then_relookup(&dag);
    let streamed = dag.reverse_topological_order_with_levels();
    assert_eq!(
        relookup, streamed,
        "streaming levels from the postorder walk changed the (block, level) flush sequence"
    );
    assert_eq!(
        digest_order_then_relookup(&dag),
        digest_order_with_levels(&dag),
        "relookup and streamed level digests diverged"
    );

    let mut group = c.benchmark_group("writeback_order_with_levels_2048");
    group.bench_function("order_then_relookup_a", |b| {
        b.iter(|| black_box(digest_order_then_relookup(black_box(&dag))));
    });
    group.bench_function("order_then_relookup_b", |b| {
        b.iter(|| black_box(digest_order_then_relookup(black_box(&dag))));
    });
    group.bench_function("order_with_levels", |b| {
        b.iter(|| black_box(digest_order_with_levels(black_box(&dag))));
    });
    group.finish();
}

fn bench_writeback_dag_order_sweep_guard(c: &mut Criterion) {
    let dag = build_dag();
    let unguarded = btree_visited_order(&dag);
    let guarded = btree_visited_order_guarded(&dag);
    assert_eq!(
        unguarded, guarded,
        "skipping the all-nodes sweep on a fully-reachable DAG changed the flush order"
    );
    // Also assert the production methods agree with the reference order (the
    // production guard lives in reverse_topological_order[_with_levels]).
    assert_eq!(
        dag.reverse_topological_order(),
        unguarded,
        "production reverse_topological_order diverged from the reference sweep order"
    );

    let mut group = c.benchmark_group("writeback_dag_order_sweep_guard_2048");
    group.bench_function("unguarded_full_sweep_a", |b| {
        b.iter(|| black_box(order_digest(&btree_visited_order(black_box(&dag)))));
    });
    group.bench_function("unguarded_full_sweep_b", |b| {
        b.iter(|| black_box(order_digest(&btree_visited_order(black_box(&dag)))));
    });
    group.bench_function("guarded_skip_sweep", |b| {
        b.iter(|| black_box(order_digest(&btree_visited_order_guarded(black_box(&dag)))));
    });
    group.finish();
}

// ── durability bookkeeping in execute (crash-tracking-off fast path) ────────
//
// execute's per-node `mark_durable` (a node-map get_mut) plus the durable-set
// seed exist only to build crash points / verify WB-I1. With crash tracking
// off (production writeback) that bookkeeping is dead, so it is now gated. The
// per-node mark_durable is the dominant part and is measurable via the public
// API here. The digest folds (block, level) identically in both arms, so the
// durability bookkeeping provably does not change the flush result.

/// execute-style flush loop that KEEPS the per-node durability bookkeeping
/// (matches production before this change). `mark_durable` is idempotent, so
/// the DAG can start fully durable and be re-driven in place across iterations
/// — no per-iteration clone, which is what made the earlier bench noisy.
fn flush_loop_mark(dag: &mut WriteDependencyDag) -> u64 {
    let order = dag.reverse_topological_order_with_levels();
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for (block, level) in order {
        digest = digest
            .wrapping_mul(0x100_0000_01b3)
            .wrapping_add(block)
            .wrapping_add(u64::from(level));
        dag.mark_durable(block).expect("mark durable");
    }
    digest
}

/// execute-style flush loop with the durability bookkeeping skipped (matches
/// production after this change, crash tracking off).
fn flush_loop_no_mark(dag: &WriteDependencyDag) -> u64 {
    dag.reverse_topological_order_with_levels()
        .into_iter()
        .fold(0xcbf2_9ce4_8422_2325_u64, |acc, (block, level)| {
            acc.wrapping_mul(0x100_0000_01b3)
                .wrapping_add(block)
                .wrapping_add(u64::from(level))
        })
}

fn bench_writeback_execute_durability(c: &mut Criterion) {
    let dag = build_dag();
    // Pre-mark every node durable once; mark_durable is then idempotent, so the
    // flush loop can be re-run in place with zero per-iteration allocation.
    let mut dag_durable = dag.clone();
    // ⚠️ THE COLLECT IS LOAD-BEARING, not needless as clippy reads it: it ends the
    // immutable borrow of `dag_durable` so the body can take `&mut` to mark each
    // block. Iterating lazily does not compile.
    #[expect(clippy::needless_collect, reason = "ends the borrow so the body can mutate")]
    for block in dag_durable.blocks().collect::<Vec<_>>() {
        dag_durable.mark_durable(block).expect("pre-mark durable");
    }

    assert_eq!(
        flush_loop_mark(&mut dag.clone()),
        flush_loop_no_mark(&dag),
        "skipping durability bookkeeping changed the flush (block, level) result"
    );

    let mut group = c.benchmark_group("writeback_execute_durability_2048");
    group.bench_function("with_durability_a", |b| {
        let mut d = dag_durable.clone();
        b.iter(|| black_box(flush_loop_mark(black_box(&mut d))));
    });
    group.bench_function("with_durability_b", |b| {
        let mut d = dag_durable.clone();
        b.iter(|| black_box(flush_loop_mark(black_box(&mut d))));
    });
    group.bench_function("without_durability", |b| {
        b.iter(|| black_box(flush_loop_no_mark(black_box(&dag))));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_writeback_dag_order,
    bench_writeback_dag_build,
    bench_writeback_executor_crash_points,
    bench_writeback_dag_block_level_iteration_current,
    bench_writeback_executor_crash_tracking,
    bench_writeback_order_with_levels,
    bench_writeback_dag_order_sweep_guard,
    bench_writeback_execute_durability
);
criterion_main!(benches);
