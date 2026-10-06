#![forbid(unsafe_code)]

//! Criterion benchmark: batch vs single block allocation.
//!
//! Compares the throughput of `alloc_blocks_batch_persist` against
//! N individual `alloc_blocks_persist(count=1)` calls, demonstrating
//! the I/O amortization benefit.

use asupersync::Cx;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ffs_alloc::{
    AllocHint, FsGeometry, GroupStats, PersistCtx, alloc_blocks, alloc_blocks_batch_persist,
    alloc_blocks_persist, bitmap_clear, bitmap_count_free, bitmap_largest_free_run, bitmap_set,
};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::Result as FfsResult;
use ffs_types::{BlockNumber, GroupNumber};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::{Mutex, OnceLock};

/// In-memory block device for benchmarks.
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
        1_000_000
    }

    fn sync(&self, _cx: &Cx) -> FfsResult<()> {
        Ok(())
    }
}

fn make_geometry() -> FsGeometry {
    FsGeometry {
        blocks_per_group: 8192,
        inodes_per_group: 2048,
        block_size: 4096,
        total_blocks: 32768,
        total_inodes: 8192,
        first_data_block: 0,
        group_count: 4,
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

fn make_skip_geometry(group_count: u32) -> FsGeometry {
    FsGeometry {
        group_count,
        total_blocks: u64::from(group_count) * 32_768,
        blocks_per_group: 32_768,
        block_size: 4096,
        ..make_geometry()
    }
}

fn make_persist_ctx() -> PersistCtx {
    PersistCtx {
        gdt_block: BlockNumber(50),
        gdt_blocks: None,
        desc_size: 32,
        has_metadata_csum: false,
        uuid: [0; 16],
        csum_seed: 0,
        group_desc_checksum_kind: ffs_ondisk::ext4::Ext4GroupDescChecksumKind::None,
        blocks_per_group: 32768,
        inodes_per_group: 2048,
    }
}

fn make_fragmented_bitmap(geo: &FsGeometry, groups: &[GroupStats], group: GroupNumber) -> Vec<u8> {
    let mut bitmap = vec![0xAA_u8; geo.block_size as usize];
    for &rel in ffs_alloc::reserved_blocks_in_group(geo, groups, group).iter() {
        bitmap_set(&mut bitmap, rel);
    }
    bitmap
}

fn make_final_run_bitmap(geo: &FsGeometry, groups: &[GroupStats], group: GroupNumber) -> Vec<u8> {
    let mut bitmap = vec![0xFF_u8; geo.block_size as usize];
    let run_start = 1024;
    for rel in run_start..run_start + 64 {
        bitmap_clear(&mut bitmap, rel);
    }
    for &rel in ffs_alloc::reserved_blocks_in_group(geo, groups, group).iter() {
        bitmap_set(&mut bitmap, rel);
    }
    bitmap
}

fn seed_contiguous_skip_world(
    cx: &Cx,
    dev: &MemBlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    exact_cache: bool,
) {
    let last_group = GroupNumber(geo.group_count - 1);
    for group_idx in 0..geo.group_count {
        let group = GroupNumber(group_idx);
        let gidx = group_idx as usize;
        let bitmap = if group == last_group {
            make_final_run_bitmap(geo, groups, group)
        } else {
            make_fragmented_bitmap(geo, groups, group)
        };
        let blocks_in_group = geo.blocks_in_group(group);
        groups[gidx].free_blocks = bitmap_count_free(&bitmap, blocks_in_group);
        groups[gidx].block_largest_free_run =
            exact_cache.then(|| bitmap_largest_free_run(&bitmap, blocks_in_group));
        dev.write_block(cx, groups[gidx].block_bitmap_block, &bitmap)
            .unwrap();
    }
}

fn make_contiguous_skip_world(
    exact_cache: bool,
) -> (Cx, MemBlockDevice, FsGeometry, Vec<GroupStats>) {
    let cx = Cx::for_testing();
    let geo = make_skip_geometry(128);
    let dev = MemBlockDevice::new(geo.block_size);
    let mut groups = make_groups(&geo);
    seed_contiguous_skip_world(&cx, &dev, &geo, &mut groups, exact_cache);
    (cx, dev, geo, groups)
}

/// Benchmark: allocate N blocks one at a time via alloc_blocks_persist.
fn bench_single_alloc(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let hint = AllocHint::default();
    let pctx = make_persist_ctx();
    let geo = make_geometry();

    let mut group = c.benchmark_group("alloc_20_blocks");

    group.bench_function("single_20x1", |b| {
        b.iter(|| {
            let dev = MemBlockDevice::new(4096);
            let mut groups = make_groups(&geo);
            for _ in 0..20 {
                let _ = alloc_blocks_persist(
                    black_box(&cx),
                    black_box(&dev),
                    black_box(&geo),
                    black_box(&mut groups),
                    black_box(1),
                    black_box(&hint),
                    black_box(&pctx),
                )
                .unwrap();
            }
        });
    });

    group.bench_function("batch_20", |b| {
        b.iter(|| {
            let dev = MemBlockDevice::new(4096);
            let mut groups = make_groups(&geo);
            let _ = alloc_blocks_batch_persist(
                black_box(&cx),
                black_box(&dev),
                black_box(&geo),
                black_box(&mut groups),
                black_box(20),
                black_box(&hint),
                black_box(&pctx),
            )
            .unwrap();
        });
    });

    group.finish();
}

/// Benchmark: 100-block allocation (simulates bulk file creation).
fn bench_bulk_alloc(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let hint = AllocHint::default();
    let pctx = make_persist_ctx();
    let geo = make_geometry();

    let mut group = c.benchmark_group("alloc_100_blocks");

    group.bench_function("single_100x1", |b| {
        b.iter(|| {
            let dev = MemBlockDevice::new(4096);
            let mut groups = make_groups(&geo);
            for _ in 0..100 {
                let _ = alloc_blocks_persist(
                    black_box(&cx),
                    black_box(&dev),
                    black_box(&geo),
                    black_box(&mut groups),
                    black_box(1),
                    black_box(&hint),
                    black_box(&pctx),
                )
                .unwrap();
            }
        });
    });

    group.bench_function("batch_100", |b| {
        b.iter(|| {
            let dev = MemBlockDevice::new(4096);
            let mut groups = make_groups(&geo);
            let _ = alloc_blocks_batch_persist(
                black_box(&cx),
                black_box(&dev),
                black_box(&geo),
                black_box(&mut groups),
                black_box(100),
                black_box(&hint),
                black_box(&pctx),
            )
            .unwrap();
        });
    });

    group.finish();
}

/// Benchmark: skip groups whose exact largest-run cache proves a multi-block
/// allocation cannot fit. The cache-disabled arm is the pre-optimization shape:
/// it reads and searches every fragmented group bitmap before reaching the
/// final satisfiable group.
fn bench_contiguous_cached_skip(c: &mut Criterion) {
    let hint = AllocHint::default();

    let (cx_old, dev_old, geo_old, mut groups_old) = make_contiguous_skip_world(false);
    let (cx_new, dev_new, geo_new, mut groups_new) = make_contiguous_skip_world(true);
    let old_alloc = alloc_blocks(&cx_old, &dev_old, &geo_old, &mut groups_old, 64, &hint).unwrap();
    let new_alloc = alloc_blocks(&cx_new, &dev_new, &geo_new, &mut groups_new, 64, &hint).unwrap();
    assert_eq!(
        old_alloc, new_alloc,
        "cached skip must preserve allocation choice"
    );

    let mut group = c.benchmark_group("alloc_contiguous_cached_skip_128groups");
    group.bench_function("cache_disabled_bitmap_probe", |b| {
        b.iter_batched(
            || make_contiguous_skip_world(false),
            |(cx, dev, geo, mut groups)| {
                black_box(
                    alloc_blocks(
                        black_box(&cx),
                        black_box(&dev),
                        black_box(&geo),
                        black_box(&mut groups),
                        black_box(64),
                        black_box(&hint),
                    )
                    .unwrap(),
                );
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("exact_cache_skip", |b| {
        b.iter_batched(
            || make_contiguous_skip_world(true),
            |(cx, dev, geo, mut groups)| {
                black_box(
                    alloc_blocks(
                        black_box(&cx),
                        black_box(&dev),
                        black_box(&geo),
                        black_box(&mut groups),
                        black_box(64),
                        black_box(&hint),
                    )
                    .unwrap(),
                );
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_single_alloc,
    bench_bulk_alloc,
    bench_contiguous_cached_skip
);
criterion_main!(benches);
