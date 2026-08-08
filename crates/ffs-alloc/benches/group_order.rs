#![forbid(unsafe_code)]

//! Criterion benchmark: `allocation_group_order` build cost (bd-8gh5e).
//!
//! `alloc_blocks` rebuilds the full group-traversal order on every call. The
//! order build walks `0..group_count` and deduped each candidate. The old code
//! used `order.contains()` — an O(group_count) scan over a growing Vec — making
//! the whole build O(group_count^2) per allocation. The fix uses an O(1) seen
//! bitset, dropping the build to O(group_count).
//!
//! The order is built eagerly (the whole `Vec` is returned before the alloc
//! loop iterates), so allocating a single block from group 0 of a many-group
//! geometry isolates the order-build cost: the success path does one bitmap op
//! while the dominant work is building the traversal order.

use asupersync::Cx;
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_alloc::{AllocHint, FsGeometry, GroupStats, alloc_blocks, allocation_group_order};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::Result as FfsResult;
use ffs_types::{BlockNumber, GroupNumber};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::{Mutex, OnceLock};

/// In-memory block device returning zeroed (all-free) bitmaps.
struct MemBlockDevice {
    block_size: u32,
    blocks: Mutex<HashMap<u64, Vec<u8>>>,
}

impl MemBlockDevice {
    fn new(block_size: u32) -> Self {
        Self {
            block_size,
            blocks: Mutex::new(HashMap::new()),
        }
    }
}

impl BlockDevice for MemBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> FfsResult<BlockBuf> {
        let guard = self.blocks.lock().unwrap();
        guard.get(&block.0).map_or_else(
            || Ok(BlockBuf::new(vec![0u8; self.block_size as usize])),
            |data| Ok(BlockBuf::new(data.clone())),
        )
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> FfsResult<()> {
        self.blocks.lock().unwrap().insert(block.0, data.to_vec());
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        1_000_000_000
    }

    fn sync(&self, _cx: &Cx) -> FfsResult<()> {
        Ok(())
    }
}

fn make_geometry(group_count: u32) -> FsGeometry {
    FsGeometry {
        blocks_per_group: 8192,
        inodes_per_group: 2048,
        block_size: 4096,
        total_blocks: u64::from(group_count) * 8192,
        total_inodes: group_count * 2048,
        first_data_block: 0,
        group_count,
        inode_size: 256,
        desc_size: 32,
        reserved_gdt_blocks: 0,
        first_meta_bg: 0,
        feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
        feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
        feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
        log_groups_per_flex: 0,
        backup_bgs: [0, 0],
        cluster_ratio: 1,
        first_inode: 11,
    }
}

fn make_groups(geo: &FsGeometry) -> Vec<GroupStats> {
    (0..geo.group_count)
        .map(|g| GroupStats {
            group: GroupNumber(g),
            free_blocks: geo.blocks_per_group,
            block_largest_free_run: None,
            free_inodes: geo.inodes_per_group,
            inode_search_start: 0,
            used_dirs: 0,
            block_bitmap_block: BlockNumber(u64::from(g) * 100 + 1),
            inode_bitmap_block: BlockNumber(u64::from(g) * 100 + 2),
            inode_table_block: BlockNumber(u64::from(g) * 100 + 3),
            flags: 0,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
            reserved_cache: OnceLock::new(),
            reserved_confirmed: OnceLock::new(),
        })
        .collect()
}

/// Allocate one block from group 0 of a many-group geometry. The order build
/// dominates; this exercises the O(group_count^2) -> O(group_count) lever.
fn bench_group_order(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let hint = AllocHint::default();

    let mut group = c.benchmark_group("allocation_group_order");
    for &group_count in &[1024_u32, 4096] {
        let geo = make_geometry(group_count);
        group.bench_function(format!("alloc1_{group_count}groups"), |b| {
            b.iter(|| {
                let dev = MemBlockDevice::new(4096);
                let mut groups = make_groups(&geo);
                let _ = alloc_blocks(
                    black_box(&cx),
                    black_box(&dev),
                    black_box(&geo),
                    black_box(&mut groups),
                    black_box(1),
                    black_box(&hint),
                )
                .unwrap();
            });
        });
    }
    group.finish();
}

/// Isolates the work the `alloc_blocks` goal-first fast path eliminates on the
/// common non-full allocation: building the whole O(group_count) traversal order
/// (`allocation_group_order`, a `group_count`-sized `Vec` + `seen` bitset) vs the
/// O(1) goal-group computation it now does instead. The delta grows with fs size.
fn bench_order_build_eliminated(c: &mut Criterion) {
    let hint = AllocHint::default();
    let mut group = c.benchmark_group("allocation_order_build_vs_goal");
    for &group_count in &[1024_u32, 4096, 16384] {
        let geo = make_geometry(group_count);
        group.bench_function(format!("full_order_build_{group_count}"), |b| {
            b.iter(|| {
                black_box(allocation_group_order(black_box(&geo), black_box(&hint)).unwrap())
            });
        });
        group.bench_function(format!("goal_group_only_{group_count}"), |b| {
            b.iter(|| {
                // What the fast path computes instead of the full order.
                let goal = black_box(&hint).goal_group.unwrap_or(GroupNumber(0));
                black_box(goal)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_group_order, bench_order_build_eliminated);
criterion_main!(benches);
