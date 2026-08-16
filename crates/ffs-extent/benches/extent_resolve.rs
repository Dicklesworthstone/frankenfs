#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Criterion benchmarks for extent tree resolve (logical → physical block mapping).
//!
//! Benchmarks both "uncached" (direct tree walk) and "cached" (repeated lookups
//! of the same logical blocks) paths to establish baseline latency for the
//! `map_logical_to_physical` function.

use asupersync::Cx;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_btree::SearchResult;
use ffs_error::Result as FfsResult;
use ffs_ondisk::{Ext4Extent, ExtentTree};
use ffs_types::BlockNumber;
use parking_lot::Mutex;
use std::hint::black_box;

// ── Constants ───────────────────────────────────────────────────────────────

const BLOCK_SIZE: u32 = 4096;
/// ext4 extent header magic.
const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
/// 12-byte header, 12-byte entries.
const HEADER_SIZE: usize = 12;
const ENTRY_SIZE: usize = 12;

/// Number of extents in the root node for the depth-0 benchmark.
const ROOT_EXTENTS: usize = 4; // max root entries for 60-byte i_block

/// Number of child blocks in the depth-1 benchmark.
const DEPTH1_CHILDREN: usize = 4;
/// Leaf entries per external node at 4K block size: (4096 - 12 - 4) / 12 = 340.
const LEAF_ENTRIES_PER_NODE: usize = 340;

// ── In-memory block device for benchmarks ──────────────────────────────────

/// A simple in-memory block device holding pre-populated blocks for tree lookups.
#[derive(Debug)]
struct MemBlockDevice {
    blocks: Mutex<Vec<Vec<u8>>>,
    block_size: u32,
}

impl MemBlockDevice {
    fn new(block_size: u32, block_count: usize) -> Self {
        let blocks = (0..block_count)
            .map(|_| vec![0u8; block_size as usize])
            .collect();
        Self {
            blocks: Mutex::new(blocks),
            block_size,
        }
    }

    fn write_block_data(&self, block: usize, data: &[u8]) {
        let mut guard = self.blocks.lock();
        guard[block][..data.len()].copy_from_slice(data);
    }
}

impl BlockDevice for MemBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> FfsResult<BlockBuf> {
        let data = self.blocks.lock()[block.0 as usize].clone();
        Ok(BlockBuf::new(data))
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> FfsResult<()> {
        self.blocks.lock()[block.0 as usize][..data.len()].copy_from_slice(data);
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        self.blocks.lock().len() as u64
    }

    fn sync(&self, _cx: &Cx) -> FfsResult<()> {
        Ok(())
    }
}

// ── Extent tree construction helpers ───────────────────────────────────────

/// Serialize an extent header into bytes.
fn write_header(buf: &mut [u8], entries: u16, max_entries: u16, depth: u16) {
    buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
    buf[2..4].copy_from_slice(&entries.to_le_bytes());
    buf[4..6].copy_from_slice(&max_entries.to_le_bytes());
    buf[6..8].copy_from_slice(&depth.to_le_bytes());
    buf[8..12].copy_from_slice(&0u32.to_le_bytes()); // generation
}

/// Serialize a leaf extent entry.
fn write_leaf_extent(buf: &mut [u8], logical_block: u32, raw_len: u16, physical_start: u64) {
    buf[0..4].copy_from_slice(&logical_block.to_le_bytes());
    buf[4..6].copy_from_slice(&raw_len.to_le_bytes());
    // Physical start is stored as: low 32 bits at [8..12], high 16 bits at [6..8]
    let phys_hi = ((physical_start >> 32) & 0xFFFF) as u16;
    let phys_lo = (physical_start & 0xFFFF_FFFF) as u32;
    buf[6..8].copy_from_slice(&phys_hi.to_le_bytes());
    buf[8..12].copy_from_slice(&phys_lo.to_le_bytes());
}

/// Serialize an index entry.
fn write_index_entry(buf: &mut [u8], logical_block: u32, leaf_block: u64) {
    buf[0..4].copy_from_slice(&logical_block.to_le_bytes());
    let lo = (leaf_block & 0xFFFF_FFFF) as u32;
    let hi = ((leaf_block >> 32) & 0xFFFF) as u16;
    buf[4..8].copy_from_slice(&lo.to_le_bytes());
    buf[8..10].copy_from_slice(&hi.to_le_bytes());
    buf[10..12].copy_from_slice(&0u16.to_le_bytes()); // unused
}

/// Build a depth-0 root with 4 contiguous extents, each mapping 100 logical blocks.
fn build_depth0_root() -> [u8; 60] {
    let mut root = [0u8; 60];
    write_header(
        &mut root[..HEADER_SIZE],
        ROOT_EXTENTS as u16,
        ROOT_EXTENTS as u16,
        0,
    );

    for i in 0..ROOT_EXTENTS {
        let offset = HEADER_SIZE + i * ENTRY_SIZE;
        let logical = (i as u32) * 100;
        let physical = 1000 + (i as u64) * 100;
        write_leaf_extent(
            &mut root[offset..offset + ENTRY_SIZE],
            logical,
            100,
            physical,
        );
    }

    root
}

/// Build a depth-1 tree: root has 4 index entries pointing to external leaf blocks.
/// Each leaf has `LEAF_ENTRIES_PER_NODE` contiguous extents of length 1.
/// Total coverage: 4 * 340 = 1360 logical blocks.
fn build_depth1_tree() -> (MemBlockDevice, [u8; 60]) {
    // We need 4 child blocks (blocks 10..13) + some padding blocks
    let dev = MemBlockDevice::new(BLOCK_SIZE, 20);

    // Root: depth=1, 4 index entries
    let mut root = [0u8; 60];
    write_header(
        &mut root[..HEADER_SIZE],
        DEPTH1_CHILDREN as u16,
        ROOT_EXTENTS as u16,
        1,
    );

    for i in 0..DEPTH1_CHILDREN {
        let offset = HEADER_SIZE + i * ENTRY_SIZE;
        let logical = (i * LEAF_ENTRIES_PER_NODE) as u32;
        let child_block = (10 + i) as u64;
        write_index_entry(&mut root[offset..offset + ENTRY_SIZE], logical, child_block);
    }

    // Build each leaf block
    for child_idx in 0..DEPTH1_CHILDREN {
        let mut block_data = vec![0u8; BLOCK_SIZE as usize];
        let entries_in_leaf = LEAF_ENTRIES_PER_NODE.min(340); // Cap at max
        write_header(
            &mut block_data[..HEADER_SIZE],
            entries_in_leaf as u16,
            entries_in_leaf as u16,
            0,
        );

        for e in 0..entries_in_leaf {
            let off = HEADER_SIZE + e * ENTRY_SIZE;
            let logical = (child_idx * LEAF_ENTRIES_PER_NODE + e) as u32;
            let physical = 5000 + u64::from(logical);
            write_leaf_extent(&mut block_data[off..off + ENTRY_SIZE], logical, 1, physical);
        }

        dev.write_block_data(10 + child_idx, &block_data);
    }

    (dev, root)
}

// ── Benchmarks ─────────────────────────────────────────────────────────────

/// Benchmark extent resolve on a depth-0 tree (extents in root node).
/// This is the "cached" scenario: all data is in the 60-byte root, no I/O.
fn bench_extent_resolve_depth0(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let root = build_depth0_root();
    // Use a dummy device (depth-0 never reads blocks)
    let dev = MemBlockDevice::new(BLOCK_SIZE, 1);

    c.bench_function("extent_resolve_depth0_cached", |b| {
        b.iter(|| {
            // Resolve logical block 150 → should be in the 2nd extent (100..199)
            let result = ffs_extent::map_logical_to_physical(
                black_box(&cx),
                black_box(&dev),
                black_box(&root),
                black_box(150),
                black_box(1),
            )
            .expect("resolve");
            black_box(result);
        });
    });
}

/// Benchmark extent resolve on a depth-1 tree requiring external block reads.
/// This is the "uncached" scenario: must read a leaf block from the device.
fn bench_extent_resolve_depth1(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let (dev, root) = build_depth1_tree();

    c.bench_function("extent_resolve_depth1_uncached", |b| {
        b.iter(|| {
            // Resolve logical block 700 → 3rd child, entry 700-680=20
            let result = ffs_extent::map_logical_to_physical(
                black_box(&cx),
                black_box(&dev),
                black_box(&root),
                black_box(700),
                black_box(1),
            )
            .expect("resolve");
            black_box(result);
        });
    });
}

/// Benchmark resolving a range of blocks (batch mapping).
fn bench_extent_resolve_range(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let root = build_depth0_root();
    let dev = MemBlockDevice::new(BLOCK_SIZE, 1);

    c.bench_function("extent_resolve_range_50blocks", |b| {
        b.iter(|| {
            let result = ffs_extent::map_logical_to_physical(
                black_box(&cx),
                black_box(&dev),
                black_box(&root),
                black_box(50),
                black_box(50),
            )
            .expect("resolve range");
            black_box(result);
        });
    });
}

/// Benchmark repeated lookups (simulates cached access pattern).
fn bench_extent_resolve_repeated(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let (dev, root) = build_depth1_tree();

    c.bench_function("extent_resolve_depth1_repeated", |b| {
        b.iter(|| {
            // Resolve same block 10 times (simulates hot path)
            for _ in 0..10 {
                let result = ffs_extent::map_logical_to_physical(
                    black_box(&cx),
                    black_box(&dev),
                    black_box(&root),
                    black_box(500),
                    black_box(1),
                )
                .expect("resolve");
                black_box(result);
            }
        });
    });
}

/// Benchmark repeated lookups WITH the ExtentCache (same logical block 10 times).
fn bench_extent_resolve_cached_repeated(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let (dev, root) = build_depth1_tree();
    let cache = ffs_extent::ExtentCache::new();

    // Warm the cache with one lookup.
    ffs_extent::cached_map_logical_to_physical(&cx, &dev, &root, 500, 1, &cache, 0).expect("warm");

    c.bench_function("extent_resolve_depth1_cached_repeated", |b| {
        b.iter(|| {
            for _ in 0..10 {
                let result = ffs_extent::cached_map_logical_to_physical(
                    black_box(&cx),
                    black_box(&dev),
                    black_box(&root),
                    black_box(500),
                    black_box(1),
                    black_box(&cache),
                    black_box(0),
                )
                .expect("resolve");
                black_box(result);
            }
        });
    });
}

/// Benchmark sequential read pattern: blocks 0..100, uncached vs cached.
fn bench_extent_sequential_uncached(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let (dev, root) = build_depth1_tree();

    c.bench_function("extent_sequential_100blocks_uncached", |b| {
        b.iter(|| {
            for blk in 0..100_u32 {
                let result = ffs_extent::map_logical_to_physical(
                    black_box(&cx),
                    black_box(&dev),
                    black_box(&root),
                    black_box(blk),
                    black_box(1),
                )
                .expect("resolve");
                black_box(result);
            }
        });
    });
}

fn map_single_old_double_parse(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root: &[u8; 60],
    logical_start: u32,
) -> FfsResult<Vec<ffs_extent::ExtentMapping>> {
    let (header, tree) = ffs_ondisk::parse_extent_tree(root).expect("valid root extent tree");
    assert!(header.depth <= 5, "valid ext4 root depth");
    assert!(
        !(header.depth > 0 && header.entries == 0),
        "non-leaf root has entries"
    );
    if let ExtentTree::Leaf(extents) = &tree {
        assert!(
            extents.iter().all(|ext| ext.actual_len() != 0),
            "leaf extents have nonzero length"
        );
    }

    let result = ffs_btree::search(cx, dev, root, logical_start)?;
    Ok(vec![mapping_from_search_result(logical_start, &result)])
}

fn mapping_from_search_result(
    logical_start: u32,
    result: &SearchResult,
) -> ffs_extent::ExtentMapping {
    match result {
        SearchResult::Found {
            extent,
            offset_in_extent,
        } => ffs_extent::ExtentMapping {
            logical_start,
            physical_start: extent.physical_start + u64::from(*offset_in_extent),
            count: 1,
            unwritten: extent.is_unwritten(),
        },
        SearchResult::Hole { .. } => ffs_extent::ExtentMapping {
            logical_start,
            physical_start: 0,
            count: 1,
            unwritten: false,
        },
    }
}

fn bench_extent_single_block_parse_root_ab(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let (dev, root) = build_depth1_tree();

    assert_eq!(
        map_single_old_double_parse(&cx, &dev, &root, 700).expect("old resolve"),
        ffs_extent::map_logical_to_physical(&cx, &dev, &root, 700, 1).expect("new resolve")
    );

    let mut group = c.benchmark_group("extent_single_block_parse_root_ab");
    group.bench_function("old_double_parse", |b| {
        b.iter(|| {
            let result = map_single_old_double_parse(
                black_box(&cx),
                black_box(&dev),
                black_box(&root),
                black_box(700),
            )
            .expect("resolve");
            black_box(result);
        });
    });
    group.bench_function("parsed_root", |b| {
        b.iter(|| {
            let result = ffs_extent::map_logical_to_physical(
                black_box(&cx),
                black_box(&dev),
                black_box(&root),
                black_box(700),
                black_box(1),
            )
            .expect("resolve");
            black_box(result);
        });
    });
    group.finish();
}

fn bench_extent_sequential_cached(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let (dev, root) = build_depth1_tree();
    let cache = ffs_extent::ExtentCache::new();

    c.bench_function("extent_sequential_100blocks_cached", |b| {
        b.iter(|| {
            for blk in 0..100_u32 {
                let result = ffs_extent::cached_map_logical_to_physical(
                    black_box(&cx),
                    black_box(&dev),
                    black_box(&root),
                    black_box(blk),
                    black_box(1),
                    black_box(&cache),
                    black_box(0),
                )
                .expect("resolve");
                black_box(result);
            }
        });
    });
}

fn cached_map_logical_to_physical_one_block_old(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root: &[u8; 60],
    logical_start: u32,
    cache: &ffs_extent::ExtentCache,
    ns: u64,
) -> FfsResult<Vec<ffs_extent::ExtentMapping>> {
    if let Some(hit) = cache.lookup(ns, logical_start) {
        return Ok(vec![ffs_extent::ExtentMapping {
            logical_start,
            physical_start: hit.physical_start,
            count: 1,
            unwritten: hit.unwritten,
        }]);
    }

    let mappings = ffs_extent::map_logical_to_physical(cx, dev, root, logical_start, 1)?;
    for mapping in &mappings {
        cache.insert(ns, *mapping);
    }
    Ok(mappings)
}

fn bench_extent_sequential_cached_cold_leaf_window(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let (dev, root) = build_depth1_tree();

    for blk in 0..100_u32 {
        let old_cache = ffs_extent::ExtentCache::new();
        let new_cache = ffs_extent::ExtentCache::new();
        let old =
            cached_map_logical_to_physical_one_block_old(&cx, &dev, &root, blk, &old_cache, 0)
                .expect("old resolve");
        let new =
            ffs_extent::cached_map_logical_to_physical(&cx, &dev, &root, blk, 1, &new_cache, 0)
                .expect("new resolve");
        debug_assert_eq!(old, new, "old and leaf-window cache miss must agree");
    }

    let mut group = c.benchmark_group("extent_sequential_100blocks_cached_cold_ab");
    group.bench_function("old_one_block_cache_miss", |b| {
        b.iter(|| {
            let cache = ffs_extent::ExtentCache::new();
            for blk in 0..100_u32 {
                let result = cached_map_logical_to_physical_one_block_old(
                    black_box(&cx),
                    black_box(&dev),
                    black_box(&root),
                    black_box(blk),
                    black_box(&cache),
                    black_box(0),
                )
                .expect("resolve");
                black_box(result);
            }
        });
    });
    group.bench_function("leaf_window_cache_miss", |b| {
        b.iter(|| {
            let cache = ffs_extent::ExtentCache::new();
            for blk in 0..100_u32 {
                let result = ffs_extent::cached_map_logical_to_physical(
                    black_box(&cx),
                    black_box(&dev),
                    black_box(&root),
                    black_box(blk),
                    black_box(1),
                    black_box(&cache),
                    black_box(0),
                )
                .expect("resolve");
                black_box(result);
            }
        });
    });
    group.finish();
}

// bd-wc9v4 — bench coverage for ExtentCache mutation paths
// (insert / invalidate_range / invalidate_all / eviction-at-capacity).
// bd-upa13 just landed 5 MR proptests pinning correctness; these
// benches pin the latency floor for the same code paths so a future
// regression that swapped the BTreeMap for a slower structure or
// removed the LRU optimisation would trip the perf gate.

fn bench_extent_cache_insert_cold(c: &mut Criterion) {
    let mapping = ffs_extent::ExtentMapping {
        logical_start: 100,
        physical_start: 5_000,
        count: 50,
        unwritten: false,
    };

    c.bench_function("extent_cache_insert_cold", |b| {
        b.iter(|| {
            // Fresh cache each iteration ensures we measure the cold-insert
            // path (no eviction, no LRU update).
            let cache = ffs_extent::ExtentCache::new();
            cache.insert(black_box(0), black_box(mapping));
            black_box(cache);
        });
    });
}

fn bench_extent_cache_invalidate_range_overlapping(c: &mut Criterion) {
    // Pre-populate a cache with 64 mappings in a single namespace.
    let cache = ffs_extent::ExtentCache::with_capacity(128);
    for i in 0..64_u32 {
        cache.insert(
            0,
            ffs_extent::ExtentMapping {
                logical_start: i * 10,
                physical_start: 1_000 + u64::from(i) * 10,
                count: 10,
                unwritten: false,
            },
        );
    }

    c.bench_function("extent_cache_invalidate_range_overlapping", |b| {
        b.iter(|| {
            // Re-insert and invalidate the same range — this measures
            // the BTreeMap range-scan + filter + remove pipeline.
            cache.insert(
                black_box(0),
                ffs_extent::ExtentMapping {
                    logical_start: 200,
                    physical_start: 9_999,
                    count: 30,
                    unwritten: false,
                },
            );
            cache.invalidate_range(black_box(0), black_box(200), black_box(30));
        });
    });
}

fn bench_extent_cache_invalidate_all(c: &mut Criterion) {
    // Pre-populate a cache with 64 mappings; each iteration re-inserts
    // and invalidates everything to measure the bulk-reset cost.
    let mapping = |i: u32| ffs_extent::ExtentMapping {
        logical_start: i * 10,
        physical_start: 1_000 + u64::from(i) * 10,
        count: 10,
        unwritten: false,
    };

    c.bench_function("extent_cache_invalidate_all_64entries", |b| {
        b.iter(|| {
            let cache = ffs_extent::ExtentCache::with_capacity(128);
            for i in 0..64_u32 {
                cache.insert(0, mapping(i));
            }
            cache.invalidate_all();
            black_box(cache);
        });
    });
}

fn bench_extent_cache_eviction_at_capacity(c: &mut Criterion) {
    // Steady-state churn: capacity 16, insert 32 mappings → 16 evictions.
    // Pins the LRU eviction tax under the workload that triggers it.
    c.bench_function("extent_cache_eviction_at_capacity_32inserts_cap16", |b| {
        b.iter(|| {
            let cache = ffs_extent::ExtentCache::with_capacity(16);
            for i in 0..32_u32 {
                cache.insert(
                    black_box(0),
                    ffs_extent::ExtentMapping {
                        logical_start: i * 10,
                        physical_start: 1_000 + u64::from(i) * 10,
                        count: 10,
                        unwritten: false,
                    },
                );
            }
            black_box(cache);
        });
    });
}

// ── A/B: eviction victim selection (bd-xmh5g.58) ─────────────────────────────
// Models the original linear `min_by_key` eviction scan so the production
// `BTreeSet` eviction index can be measured against it in the same binary.
// Pure-insert churn at capacity is the workload that triggers eviction; the
// scan is O(capacity) per eviction while the BTreeSet pop is O(log capacity).

use std::collections::BTreeMap;

/// Standalone reference cache reproducing the pre-`bd-xmh5g.58` eviction:
/// at capacity, choose the victim with a full `min_by_key(last_access, key)`
/// linear scan over all entries.
struct ScanEvictionCache {
    entries: BTreeMap<(u64, u32), (ffs_extent::ExtentMapping, u64)>,
    capacity: usize,
}

impl ScanEvictionCache {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity,
        }
    }

    fn insert(&mut self, ns: u64, mapping: ffs_extent::ExtentMapping) {
        if self.capacity == 0 || mapping.count == 0 {
            return;
        }
        let key = (ns, mapping.logical_start);
        // last_access mirrors hits+misses, which is 0 under pure-insert churn.
        let access = 0u64;
        if self.entries.len() >= self.capacity
            && !self.entries.contains_key(&key)
            && let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(k, (_, last))| (*last, **k))
                .map(|(k, _)| *k)
        {
            self.entries.remove(&victim);
        }
        self.entries.insert(key, (mapping, access));
    }

    fn resident_keys(&self) -> Vec<(u64, u32)> {
        self.entries.keys().copied().collect()
    }
}

fn churn_mapping(i: u32) -> ffs_extent::ExtentMapping {
    ffs_extent::ExtentMapping {
        logical_start: i * 10,
        physical_start: 1_000 + u64::from(i) * 10,
        count: 10,
        unwritten: false,
    }
}

fn bench_extent_cache_eviction_ab(c: &mut Criterion) {
    // Capacity 512, churn 2048 fresh keys → 1536 evictions. At this capacity the
    // O(n) scan tax is what the BTreeSet index removes.
    const CAP: usize = 512;
    const CHURN: u32 = 2048;

    // Isomorphism: both policies retain the identical resident key set.
    let mut scan = ScanEvictionCache::with_capacity(CAP);
    let real = ffs_extent::ExtentCache::with_capacity(CAP);
    for i in 0..CHURN {
        scan.insert(0, churn_mapping(i));
        real.insert(0, churn_mapping(i));
    }
    let real_keys: Vec<(u64, u32)> = (0..CHURN)
        .map(|i| (0u64, i * 10))
        .filter(|&(ns, l)| real.lookup(ns, l).is_some())
        .collect();
    assert_eq!(
        scan.resident_keys(),
        real_keys,
        "eviction policies diverged"
    );

    let mut group = c.benchmark_group("extent_cache_eviction_ab_cap512_churn2048");
    group.bench_function("old_min_by_key_scan", |b| {
        b.iter(|| {
            let mut cache = ScanEvictionCache::with_capacity(CAP);
            for i in 0..CHURN {
                cache.insert(black_box(0), churn_mapping(i));
            }
            black_box(cache.entries.len());
        });
    });
    group.bench_function("btreeset_index", |b| {
        b.iter(|| {
            let cache = ffs_extent::ExtentCache::with_capacity(CAP);
            for i in 0..CHURN {
                cache.insert(black_box(0), churn_mapping(i));
            }
            black_box(cache.stats().entries);
        });
    });
    group.finish();
}

// ── A/A/B: insert-range tail ordering ───────────────────────────────────────

const INSERT_RANGE_TAIL_EXTENTS: u32 = 8_192;

fn insert_range_tail_fixture(count: u32) -> Vec<Ext4Extent> {
    (0..count)
        .map(|i| Ext4Extent {
            logical_block: i * 2,
            raw_len: 1,
            physical_start: 1_000_000 + u64::from(i) * 2,
        })
        .collect()
}

fn legacy_sort_tail_descending(mut tail: Vec<Ext4Extent>) -> Vec<Ext4Extent> {
    tail.sort_by_key(|ext| std::cmp::Reverse(ext.logical_block));
    tail
}

fn reverse_ordered_tail(mut tail: Vec<Ext4Extent>) -> Vec<Ext4Extent> {
    tail.reverse();
    tail
}

fn bench_insert_range_tail_order_ab(c: &mut Criterion) {
    for count in [0, 1, INSERT_RANGE_TAIL_EXTENTS] {
        let ascending = insert_range_tail_fixture(count);
        let expected: Vec<Ext4Extent> = ascending.iter().rev().copied().collect();
        assert_eq!(legacy_sort_tail_descending(ascending.clone()), expected);
        assert_eq!(legacy_sort_tail_descending(ascending.clone()), expected);
        assert_eq!(reverse_ordered_tail(ascending), expected);
    }

    let fixture = insert_range_tail_fixture(INSERT_RANGE_TAIL_EXTENTS);
    let mut group = c.benchmark_group("extent_insert_range_tail_order_ab_8192");
    group.bench_function("legacy_sort_descending_a", |b| {
        b.iter_batched(
            || fixture.clone(),
            |tail| black_box(legacy_sort_tail_descending(tail)),
            BatchSize::LargeInput,
        );
    });
    group.bench_function("legacy_sort_descending_b", |b| {
        b.iter_batched(
            || fixture.clone(),
            |tail| black_box(legacy_sort_tail_descending(tail)),
            BatchSize::LargeInput,
        );
    });
    group.bench_function("reverse_ascending_tail", |b| {
        b.iter_batched(
            || fixture.clone(),
            |tail| black_box(reverse_ordered_tail(tail)),
            BatchSize::LargeInput,
        );
    });
    group.finish();
}

criterion_group!(
    extent_resolve,
    bench_extent_resolve_depth0,
    bench_extent_resolve_depth1,
    bench_extent_resolve_range,
    bench_extent_resolve_repeated,
    bench_extent_resolve_cached_repeated,
    bench_extent_sequential_uncached,
    bench_extent_single_block_parse_root_ab,
    bench_extent_sequential_cached,
    bench_extent_sequential_cached_cold_leaf_window,
    bench_extent_cache_insert_cold,
    bench_extent_cache_invalidate_range_overlapping,
    bench_extent_cache_invalidate_all,
    bench_extent_cache_eviction_at_capacity,
    bench_extent_cache_eviction_ab,
    bench_insert_range_tail_order_ab,
);
criterion_main!(extent_resolve);
