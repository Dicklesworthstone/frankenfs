#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! A/B benchmark for the parsed-node walker seam (bd-u1n5f).
//!
//! On a read-only mount the on-disk metadata is immutable, so a tree node read
//! once can be reused. The byte walkers nonetheless re-do the full per-node
//! cost on EVERY traversal: read (cache clone), checksum verification, header
//! parse/validate, and item parsing. A single `read`/`getattr`/`readdir`
//! already performs several range descents that re-walk the same root +
//! internal nodes, and repeated ops re-walk the same leaves.
//!
//! `walk_tree_range_with_nodes` takes an `Arc<BtrfsParsedNode>` provider, so a
//! parsed-node cache hands the walker verified+parsed nodes and skips read +
//! verify + parse on a hit. This benches walking the same tree repeatedly:
//! `byte_reparse` re-parses every visited node each pass; `parsed_cached` parses
//! each node once and reuses it.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ffs_btrfs::{
    BTRFS_FIRST_FREE_OBJECTID, BTRFS_HEADER_SIZE, BTRFS_ITEM_EXTENT_DATA, BTRFS_ITEM_INODE_ITEM,
    BTRFS_ITEM_ROOT_ITEM, BTRFS_ITEM_ROOT_REF, BTRFS_ITEM_SIZE, BTRFS_KEY_PTR_SIZE,
    BTRFS_ROOT_SUBVOL_RDONLY, BtrfsChunkEntry, BtrfsKey, BtrfsLeafEntry, BtrfsLeafEntryBatch,
    BtrfsParsedNode, BtrfsSnapshot, BtrfsStripe, BtrfsSubvolume, SnapshotChangeType,
    SnapshotDiffEntry, enumerate_snapshots, enumerate_subvolumes, parse_btrfs_tree_node,
    parse_inode_item, parse_root_item, parse_root_ref, snapshot_diff_by_generation,
    walk_tree_parallel_with_nodes, walk_tree_range, walk_tree_range_borrowed_with_nodes,
    walk_tree_range_parallel_with_nodes, walk_tree_range_with_nodes, walk_tree_with_nodes,
};
use rustc_hash::FxHashMap;
use std::collections::{BTreeMap, HashMap};
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

const NODESIZE: u32 = 16384;
const INODE: u64 = 257;
/// Number of leaves under the single internal root.
const LEAVES: u64 = 16;
/// Items packed into each leaf (drives per-leaf parse cost).
const ITEMS_PER_LEAF: u64 = 360;
/// Per-item payload size (small EXTENT_DATA-ish records pack densely).
const ITEM_LEN: usize = 8;
const ROOT_LOGICAL: u64 = 0x1_0000;

fn stamp_crc32c(block: &mut [u8]) {
    let csum = ffs_types::crc32c(&block[0x20..]);
    block[0..4].copy_from_slice(&csum.to_le_bytes());
}

fn write_header(block: &mut [u8], bytenr: u64, nritems: u32, level: u8) {
    block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
    block[0x50..0x58].copy_from_slice(&10_u64.to_le_bytes()); // generation
    block[0x58..0x60].copy_from_slice(&1_u64.to_le_bytes()); // owner (FS_TREE)
    block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
    block[0x64] = level;
}

fn write_leaf_item(block: &mut [u8], idx: usize, key: &BtrfsKey, data_off: u32, payload: &[u8]) {
    let base = BTRFS_HEADER_SIZE + idx * BTRFS_ITEM_SIZE;
    let enc = data_off - u32::try_from(BTRFS_HEADER_SIZE).unwrap();
    block[base..base + 8].copy_from_slice(&key.objectid.to_le_bytes());
    block[base + 8] = key.item_type;
    block[base + 9..base + 17].copy_from_slice(&key.offset.to_le_bytes());
    block[base + 17..base + 21].copy_from_slice(&enc.to_le_bytes());
    block[base + 21..base + 25].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    let start = data_off as usize;
    block[start..start + payload.len()].copy_from_slice(payload);
}

fn write_key_ptr(block: &mut [u8], idx: usize, key: &BtrfsKey, blockptr: u64) {
    let base = BTRFS_HEADER_SIZE + idx * BTRFS_KEY_PTR_SIZE;
    block[base..base + 8].copy_from_slice(&key.objectid.to_le_bytes());
    block[base + 8] = key.item_type;
    block[base + 9..base + 17].copy_from_slice(&key.offset.to_le_bytes());
    block[base + 17..base + 25].copy_from_slice(&blockptr.to_le_bytes());
    block[base + 25..base + 33].copy_from_slice(&10_u64.to_le_bytes()); // generation
}

/// Key for global item index `g` (sorted across the whole tree).
fn item_key(g: u64) -> BtrfsKey {
    BtrfsKey {
        objectid: INODE,
        item_type: BTRFS_ITEM_EXTENT_DATA,
        offset: g * 4096,
    }
}

/// Build a two-level tree: one internal root over `LEAVES` leaves, leaf `L`
/// holding items with global indices `[L*ITEMS_PER_LEAF, (L+1)*ITEMS_PER_LEAF)`.
fn build_tree() -> HashMap<u64, Vec<u8>> {
    let mut blocks = HashMap::new();
    let ns = NODESIZE as usize;
    let payload = vec![0xab_u8; ITEM_LEN];

    let mut root = vec![0_u8; ns];
    write_header(&mut root, ROOT_LOGICAL, LEAVES as u32, 1);
    for l in 0..LEAVES {
        let leaf_logical = 0x2_0000 + l * u64::from(NODESIZE);
        let first_g = l * ITEMS_PER_LEAF;
        write_key_ptr(&mut root, l as usize, &item_key(first_g), leaf_logical);

        let mut leaf = vec![0_u8; ns];
        write_header(&mut leaf, leaf_logical, ITEMS_PER_LEAF as u32, 0);
        for i in 0..ITEMS_PER_LEAF {
            let g = first_g + i;
            // Payloads pack downward from the tail of the block.
            let data_off = NODESIZE - (i as u32 + 1) * ITEM_LEN as u32;
            write_leaf_item(&mut leaf, i as usize, &item_key(g), data_off, &payload);
        }
        stamp_crc32c(&mut leaf);
        blocks.insert(leaf_logical, leaf);
    }
    stamp_crc32c(&mut root);
    blocks.insert(ROOT_LOGICAL, root);
    blocks
}

fn identity_chunks() -> Vec<BtrfsChunkEntry> {
    vec![BtrfsChunkEntry {
        key: BtrfsKey {
            objectid: 256,
            item_type: 228,
            offset: 0,
        },
        length: 0x4000_0000,
        owner: 2,
        stripe_len: 0x1_0000,
        chunk_type: 2,
        io_align: 4096,
        io_width: 4096,
        sector_size: 4096,
        num_stripes: 1,
        sub_stripes: 0,
        stripes: vec![BtrfsStripe {
            devid: 1,
            offset: 0,
            dev_uuid: [0_u8; 16],
        }],
    }]
}

/// Pre-parse every node once, keyed by its logical address (a warm cache).
fn parsed_cache(blocks: &HashMap<u64, Vec<u8>>) -> HashMap<u64, Arc<BtrfsParsedNode>> {
    let mut cache = HashMap::new();
    // Logical == physical under the identity chunk map used here.
    for (&logical, bytes) in blocks {
        let node = parse_btrfs_tree_node(bytes, 0, logical, NODESIZE).expect("parse node");
        cache.insert(logical, Arc::new(node));
    }
    cache
}

fn owned_from_batches(batches: &[BtrfsLeafEntryBatch]) -> Vec<BtrfsLeafEntry> {
    batches
        .iter()
        .flat_map(BtrfsLeafEntryBatch::to_owned_entries)
        .collect()
}

struct ParsedNodeBenchData {
    blocks: HashMap<u64, Vec<u8>>,
    chunks: Vec<BtrfsChunkEntry>,
    cache: HashMap<u64, Arc<BtrfsParsedNode>>,
    full_lo: BtrfsKey,
    full_hi: BtrfsKey,
    narrow_lo: BtrfsKey,
    narrow_hi: BtrfsKey,
}

impl ParsedNodeBenchData {
    fn new() -> Self {
        let blocks = build_tree();
        let chunks = identity_chunks();
        let cache = parsed_cache(&blocks);
        let needle = ITEMS_PER_LEAF + 5; // an item in leaf 1
        Self {
            blocks,
            chunks,
            cache,
            full_lo: item_key(0),
            full_hi: item_key(LEAVES * ITEMS_PER_LEAF),
            narrow_lo: item_key(needle),
            narrow_hi: item_key(needle + 1),
        }
    }

    fn read_block(&self, phys: u64) -> Result<Vec<u8>, ffs_types::ParseError> {
        self.blocks
            .get(&phys)
            .cloned()
            .ok_or(ffs_types::ParseError::InvalidField {
                field: "physical",
                reason: "missing",
            })
    }

    fn cached_node(&self, logical: u64) -> Result<Arc<BtrfsParsedNode>, ffs_types::ParseError> {
        self.cache
            .get(&logical)
            .cloned()
            .ok_or(ffs_types::ParseError::InvalidField {
                field: "logical",
                reason: "missing",
            })
    }

    fn cached_node_with_latency(
        &self,
        logical: u64,
    ) -> Result<Arc<BtrfsParsedNode>, ffs_types::ParseError> {
        std::thread::sleep(Duration::from_micros(250));
        self.cached_node(logical)
    }

    fn assert_isomorphic(&self) {
        let mut byte_read = |phys: u64| self.read_block(phys);
        let from_bytes = walk_tree_range(
            &mut byte_read,
            &self.chunks,
            ROOT_LOGICAL,
            NODESIZE,
            0,
            self.full_lo,
            self.full_hi,
        )
        .expect("bytes");
        let mut cache_provider = |logical: u64| self.cached_node(logical);
        let from_cache = walk_tree_range_with_nodes(
            &mut cache_provider,
            ROOT_LOGICAL,
            NODESIZE,
            self.full_lo,
            self.full_hi,
        )
        .expect("cached");
        assert_eq!(from_bytes, from_cache);
        assert_eq!(from_bytes.len() as u64, LEAVES * ITEMS_PER_LEAF);
        let borrowed = walk_tree_range_borrowed_with_nodes(
            &mut cache_provider,
            ROOT_LOGICAL,
            NODESIZE,
            self.full_lo,
            self.full_hi,
        )
        .expect("borrowed");
        assert_eq!(from_bytes, owned_from_batches(&borrowed));

        let latency_serial_provider = |logical: u64| self.cached_node_with_latency(logical);
        let parallel_latency = walk_tree_range_parallel_with_nodes(
            &latency_serial_provider,
            ROOT_LOGICAL,
            NODESIZE,
            self.full_lo,
            self.full_hi,
        )
        .expect("parallel latency");
        assert_eq!(from_bytes, parallel_latency);

        // bd-l8r3s: the full-tree parallel walk must equal the serial full walk.
        let mut full_serial_provider = |logical: u64| self.cached_node(logical);
        let full_serial = walk_tree_with_nodes(&mut full_serial_provider, ROOT_LOGICAL, NODESIZE)
            .expect("serial");
        let full_parallel_provider = |logical: u64| self.cached_node(logical);
        let full_parallel =
            walk_tree_parallel_with_nodes(&full_parallel_provider, ROOT_LOGICAL, NODESIZE)
                .expect("parallel");
        assert_eq!(full_serial, full_parallel);
    }

    fn bench_full_range(&self, c: &mut Criterion) {
        let mut group = c.benchmark_group("btrfs_parsed_node_walk_full");
        group.bench_function("byte_reparse", |b| {
            let mut rp = |phys: u64| self.read_block(phys);
            b.iter(|| {
                black_box(
                    walk_tree_range(
                        &mut rp,
                        black_box(&self.chunks),
                        ROOT_LOGICAL,
                        NODESIZE,
                        0,
                        self.full_lo,
                        self.full_hi,
                    )
                    .unwrap(),
                )
            });
        });
        group.bench_function("parsed_cached", |b| {
            let mut provider = |logical: u64| self.cached_node(logical);
            b.iter(|| {
                black_box(
                    walk_tree_range_with_nodes(
                        &mut provider,
                        ROOT_LOGICAL,
                        NODESIZE,
                        black_box(self.full_lo),
                        black_box(self.full_hi),
                    )
                    .unwrap(),
                )
            });
        });
        group.bench_function("parsed_cached_borrowed", |b| {
            let mut provider = |logical: u64| self.cached_node(logical);
            b.iter(|| {
                black_box(
                    walk_tree_range_borrowed_with_nodes(
                        &mut provider,
                        ROOT_LOGICAL,
                        NODESIZE,
                        black_box(self.full_lo),
                        black_box(self.full_hi),
                    )
                    .unwrap(),
                )
            });
        });
        group.finish();
    }

    fn bench_latency_full_range(&self, c: &mut Criterion) {
        let mut group = c.benchmark_group("btrfs_parsed_node_walk_latency_full");
        group
            .sample_size(10)
            .warm_up_time(Duration::from_millis(300))
            .measurement_time(Duration::from_secs(3));
        group.bench_function("serial_cached_latency", |b| {
            b.iter(|| {
                let mut provider = |logical: u64| self.cached_node_with_latency(logical);
                black_box(
                    walk_tree_range_with_nodes(
                        &mut provider,
                        ROOT_LOGICAL,
                        NODESIZE,
                        black_box(self.full_lo),
                        black_box(self.full_hi),
                    )
                    .unwrap(),
                )
            });
        });
        group.bench_function("parallel_cached_latency", |b| {
            b.iter(|| {
                let provider = |logical: u64| self.cached_node_with_latency(logical);
                black_box(
                    walk_tree_range_parallel_with_nodes(
                        &provider,
                        ROOT_LOGICAL,
                        NODESIZE,
                        black_box(self.full_lo),
                        black_box(self.full_hi),
                    )
                    .unwrap(),
                )
            });
        });
        group.finish();
    }

    fn bench_latency_full_walk(&self, c: &mut Criterion) {
        // bd-l8r3s: full-tree walk (no range) serial vs parallel under latency.
        let mut group = c.benchmark_group("btrfs_parsed_node_full_walk_latency");
        group
            .sample_size(10)
            .warm_up_time(Duration::from_millis(300))
            .measurement_time(Duration::from_secs(3));
        group.bench_function("serial_cached_latency", |b| {
            b.iter(|| {
                let mut provider = |logical: u64| self.cached_node_with_latency(logical);
                black_box(walk_tree_with_nodes(&mut provider, ROOT_LOGICAL, NODESIZE).unwrap())
            });
        });
        group.bench_function("parallel_cached_latency", |b| {
            b.iter(|| {
                let provider = |logical: u64| self.cached_node_with_latency(logical);
                black_box(walk_tree_parallel_with_nodes(&provider, ROOT_LOGICAL, NODESIZE).unwrap())
            });
        });
        group.finish();
    }

    fn bench_narrow_range(&self, c: &mut Criterion) {
        let mut group = c.benchmark_group("btrfs_parsed_node_walk_narrow");
        group.bench_function("byte_reparse", |b| {
            let mut rp = |phys: u64| self.read_block(phys);
            b.iter(|| {
                black_box(
                    walk_tree_range(
                        &mut rp,
                        black_box(&self.chunks),
                        ROOT_LOGICAL,
                        NODESIZE,
                        0,
                        self.narrow_lo,
                        self.narrow_hi,
                    )
                    .unwrap(),
                )
            });
        });
        group.bench_function("parsed_cached", |b| {
            let mut provider = |logical: u64| self.cached_node(logical);
            b.iter(|| {
                black_box(
                    walk_tree_range_with_nodes(
                        &mut provider,
                        ROOT_LOGICAL,
                        NODESIZE,
                        black_box(self.narrow_lo),
                        black_box(self.narrow_hi),
                    )
                    .unwrap(),
                )
            });
        });
        group.bench_function("parsed_cached_borrowed", |b| {
            let mut provider = |logical: u64| self.cached_node(logical);
            b.iter(|| {
                black_box(
                    walk_tree_range_borrowed_with_nodes(
                        &mut provider,
                        ROOT_LOGICAL,
                        NODESIZE,
                        black_box(self.narrow_lo),
                        black_box(self.narrow_hi),
                    )
                    .unwrap(),
                )
            });
        });
        group.finish();
    }
}

fn bench_parsed_node_cache(c: &mut Criterion) {
    let data = ParsedNodeBenchData::new();
    data.assert_isomorphic();
    data.bench_full_range(c);
    data.bench_latency_full_range(c);
    data.bench_latency_full_walk(c);
    data.bench_narrow_range(c);
}

fn bench_leaf_cache_admission(c: &mut Criterion) {
    let mut blocks = build_tree();
    let template = blocks
        .remove(&0x2_0000)
        .expect("first leaf must be present");

    let control_input = template.clone();
    let control_input_ptr = control_input.as_ptr();
    let control = Arc::<[u8]>::from(control_input.as_slice());
    assert_eq!(&*control, template.as_slice());
    assert_ne!(control_input_ptr, control.as_ptr());

    let candidate_input = template.clone();
    let candidate_input_ptr = candidate_input.as_ptr();
    let candidate = Arc::new(candidate_input);
    assert_eq!(candidate.as_slice(), template.as_slice());
    assert_eq!(candidate_input_ptr, candidate.as_ptr());

    let mut group = c.benchmark_group("btrfs_parsed_leaf_cache_admit_16k");
    group.sample_size(30);
    group.bench_function("copy_control_a", |b| {
        b.iter_batched(
            || template.clone(),
            |owned| black_box(Arc::<[u8]>::from(owned.as_slice())),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("copy_control_b", |b| {
        b.iter_batched(
            || template.clone(),
            |owned| black_box(Arc::<[u8]>::from(owned.as_slice())),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("retain_vec", |b| {
        b.iter_batched(
            || template.clone(),
            |owned| black_box(Arc::new(owned)),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn frozen_linear_subvolume_enumeration(entries: &[BtrfsLeafEntry]) -> Vec<BtrfsSubvolume> {
    let mut subvols = Vec::new();

    for entry in entries {
        if entry.key.item_type != BTRFS_ITEM_ROOT_ITEM {
            continue;
        }
        let id = entry.key.objectid;
        if id < BTRFS_FIRST_FREE_OBJECTID {
            continue;
        }
        let Ok(root) = parse_root_item(&entry.data) else {
            continue;
        };

        let (parent_id, name) = entries
            .iter()
            .find_map(|candidate| {
                if candidate.key.item_type == BTRFS_ITEM_ROOT_REF && candidate.key.offset == id {
                    let root_ref = parse_root_ref(&candidate.data).ok()?;
                    Some((
                        candidate.key.objectid,
                        String::from_utf8_lossy(&root_ref.name).into_owned(),
                    ))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| (0, format!("subvol-{id}")));

        subvols.push(BtrfsSubvolume {
            id,
            parent_id,
            name,
            generation: root.generation,
            read_only: root.flags & BTRFS_ROOT_SUBVOL_RDONLY != 0,
            bytenr: root.bytenr,
            level: root.level,
        });
    }

    subvols
}

fn subvolume_root_item(id: u64) -> BtrfsLeafEntry {
    let mut data = vec![0_u8; 279];
    data[160..168].copy_from_slice(&id.to_le_bytes());
    data[168..176].copy_from_slice(&256_u64.to_le_bytes());
    data[176..184].copy_from_slice(&(id * u64::from(NODESIZE)).to_le_bytes());
    data[208..216].copy_from_slice(&(id & 1).to_le_bytes());
    data[216..220].copy_from_slice(&1_u32.to_le_bytes());
    data[238] = 0;
    data[239..247].copy_from_slice(&id.to_le_bytes());
    BtrfsLeafEntry {
        key: BtrfsKey {
            objectid: id,
            item_type: BTRFS_ITEM_ROOT_ITEM,
            offset: 0,
        },
        data,
    }
}

fn subvolume_root_ref(parent_id: u64, child_id: u64, name: &[u8]) -> BtrfsLeafEntry {
    let mut data = Vec::with_capacity(18 + name.len());
    data.extend_from_slice(&256_u64.to_le_bytes());
    data.extend_from_slice(&0_u64.to_le_bytes());
    data.extend_from_slice(
        &u16::try_from(name.len())
            .expect("benchmark root-ref name must fit u16")
            .to_le_bytes(),
    );
    data.extend_from_slice(name);
    BtrfsLeafEntry {
        key: BtrfsKey {
            objectid: parent_id,
            item_type: BTRFS_ITEM_ROOT_REF,
            offset: child_id,
        },
        data,
    }
}

fn subvolume_catalog(count: u64) -> Vec<BtrfsLeafEntry> {
    let mut entries = Vec::with_capacity(usize::try_from(count * 2).expect("fixture size fits"));
    for id in BTRFS_FIRST_FREE_OBJECTID..BTRFS_FIRST_FREE_OBJECTID + count {
        entries.push(subvolume_root_ref(
            5,
            id,
            format!("catalog-{id}").as_bytes(),
        ));
    }
    for id in BTRFS_FIRST_FREE_OBJECTID..BTRFS_FIRST_FREE_OBJECTID + count {
        entries.push(subvolume_root_item(id));
    }
    entries
}

fn assert_subvolume_enumeration_isomorphic(entries: &[BtrfsLeafEntry]) {
    let expected = frozen_linear_subvolume_enumeration(entries);
    assert_eq!(frozen_linear_subvolume_enumeration(entries), expected);
    assert_eq!(enumerate_subvolumes(entries), expected);
}

fn bench_subvolume_root_ref_index(c: &mut Criterion) {
    assert_subvolume_enumeration_isomorphic(&[]);

    let singleton = vec![
        subvolume_root_ref(5, 256, b"singleton"),
        subvolume_root_item(256),
    ];
    assert_subvolume_enumeration_isomorphic(&singleton);

    let mut malformed = subvolume_root_ref(5, 257, b"broken");
    malformed.data.truncate(20);
    let first_valid = vec![
        malformed,
        subvolume_root_ref(7, 257, b"first-valid"),
        subvolume_root_ref(9, 257, b"later-valid"),
        subvolume_root_item(257),
    ];
    assert_subvolume_enumeration_isomorphic(&first_valid);

    assert_subvolume_enumeration_isomorphic(&[subvolume_root_item(258)]);
    assert_subvolume_enumeration_isomorphic(&[
        subvolume_root_ref(5, 259, &[0xff, b'x']),
        subvolume_root_item(259),
    ]);

    let entries = subvolume_catalog(4096);
    assert_subvolume_enumeration_isomorphic(&entries);

    let mut group = c.benchmark_group("btrfs_subvolume_root_ref_index_4096");
    group
        .sample_size(30)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    group.bench_function("linear_control_a", |b| {
        b.iter(|| {
            black_box(frozen_linear_subvolume_enumeration(black_box(
                entries.as_slice(),
            )))
        });
    });
    group.bench_function("linear_control_b", |b| {
        b.iter(|| {
            black_box(frozen_linear_subvolume_enumeration(black_box(
                entries.as_slice(),
            )))
        });
    });
    group.bench_function("indexed", |b| {
        b.iter(|| black_box(enumerate_subvolumes(black_box(entries.as_slice()))));
    });
    group.finish();
}

fn frozen_linear_snapshot_enumeration(entries: &[BtrfsLeafEntry]) -> Vec<BtrfsSnapshot> {
    let mut snapshots = Vec::new();

    for entry in entries {
        if entry.key.item_type != BTRFS_ITEM_ROOT_ITEM {
            continue;
        }
        let id = entry.key.objectid;
        if id < BTRFS_FIRST_FREE_OBJECTID {
            continue;
        }
        let Ok(root) = parse_root_item(&entry.data) else {
            continue;
        };
        if !root.parent_uuid.iter().any(|&byte| byte != 0) {
            continue;
        }

        let source_id = entries
            .iter()
            .find_map(|candidate| {
                if candidate.key.item_type != BTRFS_ITEM_ROOT_ITEM {
                    return None;
                }
                let source = parse_root_item(&candidate.data).ok()?;
                (source.uuid == root.parent_uuid).then_some(candidate.key.objectid)
            })
            .unwrap_or(0);

        let name = entries
            .iter()
            .find_map(|candidate| {
                if candidate.key.item_type == BTRFS_ITEM_ROOT_REF && candidate.key.offset == id {
                    let root_ref = parse_root_ref(&candidate.data).ok()?;
                    Some(String::from_utf8_lossy(&root_ref.name).into_owned())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| format!("snap-{id}"));

        snapshots.push(BtrfsSnapshot {
            id,
            source_id,
            name,
            generation: root.generation,
            uuid: root.uuid,
            parent_uuid: root.parent_uuid,
            bytenr: root.bytenr,
            level: root.level,
        });
    }

    snapshots
}

fn frozen_linear_snapshot_name_enumeration(entries: &[BtrfsLeafEntry]) -> Vec<BtrfsSnapshot> {
    let mut roots = Vec::new();
    let mut source_ids = FxHashMap::default();
    for entry in entries {
        if entry.key.item_type != BTRFS_ITEM_ROOT_ITEM {
            continue;
        }
        if let Ok(root) = parse_root_item(&entry.data) {
            if root.uuid.iter().any(|&byte| byte != 0) {
                source_ids.entry(root.uuid).or_insert(entry.key.objectid);
            }
            roots.push((entry.key.objectid, root));
        }
    }

    let mut snapshots = Vec::new();
    for (id, root) in roots {
        if id < BTRFS_FIRST_FREE_OBJECTID || !root.parent_uuid.iter().any(|&byte| byte != 0) {
            continue;
        }

        let source_id = source_ids.get(&root.parent_uuid).copied().unwrap_or(0);
        let name = entries
            .iter()
            .find_map(|candidate| {
                if candidate.key.item_type == BTRFS_ITEM_ROOT_REF && candidate.key.offset == id {
                    let root_ref = parse_root_ref(&candidate.data).ok()?;
                    Some(String::from_utf8_lossy(&root_ref.name).into_owned())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| format!("snap-{id}"));

        snapshots.push(BtrfsSnapshot {
            id,
            source_id,
            name,
            generation: root.generation,
            uuid: root.uuid,
            parent_uuid: root.parent_uuid,
            bytenr: root.bytenr,
            level: root.level,
        });
    }

    snapshots
}

fn snapshot_uuid(id: u64) -> [u8; 16] {
    let mut uuid = [0_u8; 16];
    uuid[..8].copy_from_slice(&id.to_le_bytes());
    uuid[8..].copy_from_slice(&(!id).to_le_bytes());
    uuid
}

fn snapshot_root_item(id: u64, uuid: [u8; 16], parent_uuid: [u8; 16]) -> BtrfsLeafEntry {
    let mut entry = subvolume_root_item(id);
    entry.data[247..263].copy_from_slice(&uuid);
    entry.data[263..279].copy_from_slice(&parent_uuid);
    entry
}

fn snapshot_catalog(count: u64) -> Vec<BtrfsLeafEntry> {
    let first_source = BTRFS_FIRST_FREE_OBJECTID;
    let first_snapshot = first_source + count;
    let mut entries = Vec::with_capacity(usize::try_from(count * 2).expect("fixture size fits"));
    for source_id in first_source..first_source + count {
        entries.push(snapshot_root_item(
            source_id,
            snapshot_uuid(source_id),
            [0; 16],
        ));
    }
    for offset in 0..count {
        let snapshot_id = first_snapshot + offset;
        let source_id = first_source + offset;
        entries.push(snapshot_root_item(
            snapshot_id,
            snapshot_uuid(snapshot_id),
            snapshot_uuid(source_id),
        ));
    }
    entries
}

fn named_snapshot_catalog(count: u64) -> Vec<BtrfsLeafEntry> {
    let first_source = BTRFS_FIRST_FREE_OBJECTID;
    let first_snapshot = first_source + count;
    let mut entries = Vec::with_capacity(usize::try_from(count * 3).expect("fixture size fits"));
    for snapshot_id in first_snapshot..first_snapshot + count {
        entries.push(subvolume_root_ref(
            5,
            snapshot_id,
            format!("catalog-{snapshot_id}").as_bytes(),
        ));
    }
    for source_id in first_source..first_source + count {
        entries.push(snapshot_root_item(
            source_id,
            snapshot_uuid(source_id),
            [0; 16],
        ));
    }
    for offset in 0..count {
        let snapshot_id = first_snapshot + offset;
        let source_id = first_source + offset;
        entries.push(snapshot_root_item(
            snapshot_id,
            snapshot_uuid(snapshot_id),
            snapshot_uuid(source_id),
        ));
    }
    entries
}

fn snapshot_candidate_filter_catalog(
    regular_count: u64,
    snapshot_count: u64,
) -> Vec<BtrfsLeafEntry> {
    let first_regular = BTRFS_FIRST_FREE_OBJECTID;
    let first_snapshot = first_regular + regular_count;
    let capacity = usize::try_from(regular_count + snapshot_count * 2)
        .expect("snapshot candidate fixture size fits");
    let mut entries = Vec::with_capacity(capacity);

    for id in first_regular..first_snapshot {
        entries.push(snapshot_root_item(id, snapshot_uuid(id), [0; 16]));
    }
    for offset in 0..snapshot_count {
        let snapshot_id = first_snapshot + offset;
        entries.push(subvolume_root_ref(
            5,
            snapshot_id,
            format!("filtered-{snapshot_id}").as_bytes(),
        ));
    }
    for offset in 0..snapshot_count {
        let snapshot_id = first_snapshot + offset;
        let source_id = first_regular + offset % regular_count;
        entries.push(snapshot_root_item(
            snapshot_id,
            snapshot_uuid(snapshot_id),
            snapshot_uuid(source_id),
        ));
    }

    entries
}

/// Same implementation shape on both arms. `FILTER_CANDIDATES=false` freezes
/// current production: retain every parsed root, then filter in the output
/// pass. `true` retains only output candidates during the parse/index pass.
fn snapshot_enumeration_candidate_filter<const FILTER_CANDIDATES: bool>(
    entries: &[BtrfsLeafEntry],
) -> Vec<BtrfsSnapshot> {
    let mut roots = Vec::new();
    let mut source_ids = FxHashMap::default();
    let mut snapshot_names = FxHashMap::default();
    for entry in entries {
        if entry.key.item_type == BTRFS_ITEM_ROOT_REF {
            if let std::collections::hash_map::Entry::Vacant(slot) =
                snapshot_names.entry(entry.key.offset)
                && let Ok(root_ref) = parse_root_ref(&entry.data)
            {
                slot.insert(root_ref.name);
            }
            continue;
        }
        if entry.key.item_type != BTRFS_ITEM_ROOT_ITEM {
            continue;
        }
        if let Ok(root) = parse_root_item(&entry.data) {
            if root.uuid.iter().any(|&byte| byte != 0) {
                source_ids.entry(root.uuid).or_insert(entry.key.objectid);
            }
            let is_snapshot = entry.key.objectid >= BTRFS_FIRST_FREE_OBJECTID
                && root.parent_uuid.iter().any(|&byte| byte != 0);
            if !FILTER_CANDIDATES || is_snapshot {
                roots.push((entry.key.objectid, root));
            }
        }
    }

    let mut snapshots = Vec::new();
    for (id, root) in roots {
        if !FILTER_CANDIDATES
            && (id < BTRFS_FIRST_FREE_OBJECTID || !root.parent_uuid.iter().any(|&byte| byte != 0))
        {
            continue;
        }

        let source_id = source_ids.get(&root.parent_uuid).copied().unwrap_or(0);
        let name = snapshot_names.get(&id).map_or_else(
            || format!("snap-{id}"),
            |name| String::from_utf8_lossy(name).into_owned(),
        );
        snapshots.push(BtrfsSnapshot {
            id,
            source_id,
            name,
            generation: root.generation,
            uuid: root.uuid,
            parent_uuid: root.parent_uuid,
            bytenr: root.bytenr,
            level: root.level,
        });
    }
    snapshots
}

fn assert_snapshot_candidate_filter_isomorphic(entries: &[BtrfsLeafEntry]) {
    let expected = snapshot_enumeration_candidate_filter::<false>(entries);
    assert_eq!(enumerate_snapshots(entries), expected);
    assert_eq!(
        snapshot_enumeration_candidate_filter::<true>(entries),
        expected
    );
}

fn bench_snapshot_candidate_filter(c: &mut Criterion) {
    // Hoisted: a `const` after a statement is an item declared in the middle of a
    // scope it is already visible throughout, which reads as sequencing it does
    // not have.
    const REGULAR_ROOTS: u64 = 16_384;
    const SNAPSHOTS: u64 = 64;

    assert_snapshot_candidate_filter_isomorphic(&[]);
    assert_snapshot_candidate_filter_isomorphic(&[snapshot_root_item(
        BTRFS_FIRST_FREE_OBJECTID,
        snapshot_uuid(BTRFS_FIRST_FREE_OBJECTID),
        [0; 16],
    )]);

    let system_uuid = snapshot_uuid(5);
    assert_snapshot_candidate_filter_isomorphic(&[
        snapshot_root_item(5, system_uuid, [0; 16]),
        snapshot_root_item(
            BTRFS_FIRST_FREE_OBJECTID,
            snapshot_uuid(BTRFS_FIRST_FREE_OBJECTID),
            system_uuid,
        ),
    ]);

    let duplicate_uuid = snapshot_uuid(700);
    let mut malformed = snapshot_root_item(699, duplicate_uuid, [0; 16]);
    malformed.data.truncate(20);
    assert_snapshot_candidate_filter_isomorphic(&[
        malformed,
        snapshot_root_item(700, duplicate_uuid, [0; 16]),
        snapshot_root_item(701, duplicate_uuid, [0; 16]),
        snapshot_root_item(800, snapshot_uuid(800), duplicate_uuid),
        snapshot_root_item(800, snapshot_uuid(801), duplicate_uuid),
    ]);

    let entries = snapshot_candidate_filter_catalog(REGULAR_ROOTS, SNAPSHOTS);
    assert_snapshot_candidate_filter_isomorphic(&entries);

    let mut group = c.benchmark_group("btrfs_snapshot_candidate_filter_16384_regular_64_snapshots");
    group
        .sample_size(30)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    group.bench_function("all_roots_control_a", |b| {
        b.iter(|| {
            black_box(snapshot_enumeration_candidate_filter::<false>(black_box(
                entries.as_slice(),
            )))
        });
    });
    group.bench_function("all_roots_control_b", |b| {
        b.iter(|| {
            black_box(snapshot_enumeration_candidate_filter::<false>(black_box(
                entries.as_slice(),
            )))
        });
    });
    group.bench_function("candidate_roots_only", |b| {
        b.iter(|| {
            black_box(snapshot_enumeration_candidate_filter::<true>(black_box(
                entries.as_slice(),
            )))
        });
    });
    group.finish();
}

fn snapshot_name_filter_catalog(regular_count: u64, snapshot_count: u64) -> Vec<BtrfsLeafEntry> {
    let first_regular = BTRFS_FIRST_FREE_OBJECTID;
    let first_snapshot = first_regular + regular_count;
    let capacity = usize::try_from((regular_count + snapshot_count) * 2)
        .expect("snapshot name-filter fixture size fits");
    let mut entries = Vec::with_capacity(capacity);

    for id in first_regular..first_snapshot {
        entries.push(subvolume_root_ref(
            5,
            id,
            format!("regular-{id}").as_bytes(),
        ));
    }
    for id in first_snapshot..first_snapshot + snapshot_count {
        entries.push(subvolume_root_ref(
            5,
            id,
            format!("snapshot-{id}").as_bytes(),
        ));
    }
    for id in first_regular..first_snapshot {
        entries.push(snapshot_root_item(id, snapshot_uuid(id), [0; 16]));
    }
    for offset in 0..snapshot_count {
        let snapshot_id = first_snapshot + offset;
        let source_id = first_regular + offset % regular_count;
        entries.push(snapshot_root_item(
            snapshot_id,
            snapshot_uuid(snapshot_id),
            snapshot_uuid(source_id),
        ));
    }

    entries
}

/// `CANDIDATE_NAMES_ONLY=false` freezes the pre-change single-pass name
/// index. `true` mirrors production's candidate-index plus second catalog scan.
fn snapshot_enumeration_name_filter<const CANDIDATE_NAMES_ONLY: bool>(
    entries: &[BtrfsLeafEntry],
) -> Vec<BtrfsSnapshot> {
    let mut roots = Vec::new();
    let mut source_ids = FxHashMap::default();
    let mut snapshot_names: FxHashMap<u64, Option<Vec<u8>>> = FxHashMap::default();

    for entry in entries {
        if entry.key.item_type == BTRFS_ITEM_ROOT_REF {
            if !CANDIDATE_NAMES_ONLY
                && let std::collections::hash_map::Entry::Vacant(slot) =
                    snapshot_names.entry(entry.key.offset)
                && let Ok(root_ref) = parse_root_ref(&entry.data)
            {
                slot.insert(Some(root_ref.name));
            }
            continue;
        }
        if entry.key.item_type != BTRFS_ITEM_ROOT_ITEM {
            continue;
        }
        if let Ok(root) = parse_root_item(&entry.data) {
            if root.uuid.iter().any(|&byte| byte != 0) {
                source_ids.entry(root.uuid).or_insert(entry.key.objectid);
            }
            if entry.key.objectid >= BTRFS_FIRST_FREE_OBJECTID
                && root.parent_uuid.iter().any(|&byte| byte != 0)
            {
                roots.push((entry.key.objectid, root));
            }
        }
    }

    if CANDIDATE_NAMES_ONLY {
        snapshot_names.extend(roots.iter().map(|(id, _)| (*id, None)));
        for entry in entries {
            if entry.key.item_type != BTRFS_ITEM_ROOT_REF {
                continue;
            }
            if let Some(name) = snapshot_names.get_mut(&entry.key.offset)
                && name.is_none()
                && let Ok(root_ref) = parse_root_ref(&entry.data)
            {
                *name = Some(root_ref.name);
            }
        }
    }

    roots
        .into_iter()
        .map(|(id, root)| BtrfsSnapshot {
            id,
            source_id: source_ids.get(&root.parent_uuid).copied().unwrap_or(0),
            name: snapshot_names
                .get(&id)
                .and_then(Option::as_ref)
                .map_or_else(
                    || format!("snap-{id}"),
                    |name| String::from_utf8_lossy(name).into_owned(),
                ),
            generation: root.generation,
            uuid: root.uuid,
            parent_uuid: root.parent_uuid,
            bytenr: root.bytenr,
            level: root.level,
        })
        .collect()
}

fn assert_snapshot_name_filter_isomorphic(entries: &[BtrfsLeafEntry]) {
    let expected = snapshot_enumeration_name_filter::<false>(entries);
    assert_eq!(snapshot_enumeration_name_filter::<false>(entries), expected);
    assert_eq!(snapshot_enumeration_name_filter::<true>(entries), expected);
    assert_eq!(enumerate_snapshots(entries), expected);
}

fn bench_snapshot_name_filter_group(c: &mut Criterion, label: &str, entries: &[BtrfsLeafEntry]) {
    let mut group = c.benchmark_group(format!("btrfs_snapshot_name_filter_{label}"));
    group
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2));
    for control in ["all_names_control_a", "all_names_control_b"] {
        group.bench_function(control, |b| {
            b.iter(|| {
                black_box(snapshot_enumeration_name_filter::<false>(black_box(
                    entries,
                )))
            });
        });
    }
    group.bench_function("snapshot_names_only", |b| {
        b.iter(|| black_box(snapshot_enumeration_name_filter::<true>(black_box(entries))));
    });
    group.finish();
}

fn bench_snapshot_name_filter(c: &mut Criterion) {
    // Hoisted, as above.
    const REGULAR_ROOTS: u64 = 4096;
    const SNAPSHOTS: u64 = 64;
    const DENSE_SNAPSHOTS: u64 = 1024;

    assert_snapshot_name_filter_isomorphic(&[]);

    let source_uuid = snapshot_uuid(300);
    let mut malformed = subvolume_root_ref(5, 400, b"broken");
    malformed.data.truncate(20);
    assert_snapshot_name_filter_isomorphic(&[
        subvolume_root_ref(5, 300, b"regular-name"),
        malformed,
        subvolume_root_ref(7, 400, &[0xff, b'x']),
        subvolume_root_ref(9, 400, b"later-valid"),
        snapshot_root_item(300, source_uuid, [0; 16]),
        snapshot_root_item(400, snapshot_uuid(400), source_uuid),
        snapshot_root_item(400, snapshot_uuid(401), source_uuid),
    ]);
    assert_snapshot_name_filter_isomorphic(&[
        snapshot_root_item(300, source_uuid, [0; 16]),
        snapshot_root_item(401, snapshot_uuid(401), source_uuid),
    ]);

    let sparse_entries = snapshot_name_filter_catalog(REGULAR_ROOTS, SNAPSHOTS);
    assert_snapshot_name_filter_isomorphic(&sparse_entries);

    let dense_entries = named_snapshot_catalog(DENSE_SNAPSHOTS);
    assert_snapshot_name_filter_isomorphic(&dense_entries);

    bench_snapshot_name_filter_group(c, "4096_regular_64_snapshots", &sparse_entries);
    bench_snapshot_name_filter_group(c, "dense_1024_snapshots", &dense_entries);
}

fn assert_snapshot_enumeration_isomorphic(entries: &[BtrfsLeafEntry]) {
    assert_eq!(
        enumerate_snapshots(entries),
        frozen_linear_snapshot_enumeration(entries)
    );
}

fn bench_snapshot_source_uuid_index(c: &mut Criterion) {
    assert_snapshot_enumeration_isomorphic(&[]);
    assert_snapshot_enumeration_isomorphic(&[snapshot_root_item(256, snapshot_uuid(256), [0; 16])]);

    let source_uuid = snapshot_uuid(300);
    let named_snapshot = vec![
        snapshot_root_item(300, source_uuid, [0; 16]),
        snapshot_root_item(400, snapshot_uuid(400), source_uuid),
        subvolume_root_ref(5, 400, b"named-snapshot"),
    ];
    assert_snapshot_enumeration_isomorphic(&named_snapshot);

    let duplicate_uuid = snapshot_uuid(500);
    let mut malformed = snapshot_root_item(499, duplicate_uuid, [0; 16]);
    malformed.data.truncate(20);
    let first_valid_source = vec![
        malformed,
        snapshot_root_item(500, duplicate_uuid, [0; 16]),
        snapshot_root_item(501, duplicate_uuid, [0; 16]),
        snapshot_root_item(600, snapshot_uuid(600), duplicate_uuid),
    ];
    assert_snapshot_enumeration_isomorphic(&first_valid_source);

    let system_uuid = snapshot_uuid(5);
    assert_snapshot_enumeration_isomorphic(&[
        snapshot_root_item(5, system_uuid, [0; 16]),
        snapshot_root_item(601, snapshot_uuid(601), system_uuid),
    ]);
    assert_snapshot_enumeration_isomorphic(&[snapshot_root_item(
        602,
        snapshot_uuid(602),
        snapshot_uuid(999),
    )]);

    let entries = snapshot_catalog(2048);
    assert_snapshot_enumeration_isomorphic(&entries);

    let mut group = c.benchmark_group("btrfs_snapshot_source_uuid_index_2048");
    group
        .sample_size(30)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    group.bench_function("linear_control_a", |b| {
        b.iter(|| {
            black_box(frozen_linear_snapshot_enumeration(black_box(
                entries.as_slice(),
            )))
        });
    });
    group.bench_function("linear_control_b", |b| {
        b.iter(|| {
            black_box(frozen_linear_snapshot_enumeration(black_box(
                entries.as_slice(),
            )))
        });
    });
    group.bench_function("uuid_indexed", |b| {
        b.iter(|| black_box(enumerate_snapshots(black_box(entries.as_slice()))));
    });
    group.finish();
}

fn assert_snapshot_name_enumeration_isomorphic(entries: &[BtrfsLeafEntry]) {
    let expected = frozen_linear_snapshot_name_enumeration(entries);
    assert_eq!(frozen_linear_snapshot_name_enumeration(entries), expected);
    assert_eq!(enumerate_snapshots(entries), expected);
}

fn frozen_linear_snapshot_names(entries: &[BtrfsLeafEntry], ids: &[u64]) -> Vec<String> {
    ids.iter()
        .map(|id| {
            entries
                .iter()
                .find_map(|candidate| {
                    if candidate.key.item_type == BTRFS_ITEM_ROOT_REF && candidate.key.offset == *id
                    {
                        let root_ref = parse_root_ref(&candidate.data).ok()?;
                        Some(String::from_utf8_lossy(&root_ref.name).into_owned())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| format!("snap-{id}"))
        })
        .collect()
}

fn indexed_snapshot_names(entries: &[BtrfsLeafEntry], ids: &[u64]) -> Vec<String> {
    let mut names = FxHashMap::default();
    for entry in entries {
        if entry.key.item_type != BTRFS_ITEM_ROOT_REF {
            continue;
        }
        if let std::collections::hash_map::Entry::Vacant(slot) = names.entry(entry.key.offset)
            && let Ok(root_ref) = parse_root_ref(&entry.data)
        {
            slot.insert(root_ref.name);
        }
    }

    ids.iter()
        .map(|id| {
            names.get(id).map_or_else(
                || format!("snap-{id}"),
                |name| String::from_utf8_lossy(name).into_owned(),
            )
        })
        .collect()
}

fn assert_snapshot_name_lookup_isomorphic(entries: &[BtrfsLeafEntry], ids: &[u64]) {
    let expected = frozen_linear_snapshot_names(entries, ids);
    assert_eq!(frozen_linear_snapshot_names(entries, ids), expected);
    assert_eq!(indexed_snapshot_names(entries, ids), expected);
}

fn bench_snapshot_root_ref_index(c: &mut Criterion) {
    assert_snapshot_name_enumeration_isomorphic(&[]);
    assert_snapshot_name_lookup_isomorphic(&[], &[]);
    assert_snapshot_name_enumeration_isomorphic(&[snapshot_root_item(
        256,
        snapshot_uuid(256),
        [0; 16],
    )]);

    let source_uuid = snapshot_uuid(300);
    let named = [
        snapshot_root_item(300, source_uuid, [0; 16]),
        snapshot_root_item(400, snapshot_uuid(400), source_uuid),
        subvolume_root_ref(5, 400, b"named-snapshot"),
    ];
    assert_snapshot_name_enumeration_isomorphic(&named);
    assert_snapshot_name_lookup_isomorphic(&named, &[400]);

    let mut malformed = subvolume_root_ref(5, 401, b"broken");
    malformed.data.truncate(20);
    let first_valid = [
        malformed,
        subvolume_root_ref(7, 401, &[0xff, b'x']),
        subvolume_root_ref(9, 401, b"later-valid"),
        snapshot_root_item(300, source_uuid, [0; 16]),
        snapshot_root_item(401, snapshot_uuid(401), source_uuid),
    ];
    assert_snapshot_name_enumeration_isomorphic(&first_valid);
    assert_snapshot_name_lookup_isomorphic(&first_valid, &[401]);

    let missing = [
        snapshot_root_item(300, source_uuid, [0; 16]),
        snapshot_root_item(402, snapshot_uuid(402), source_uuid),
    ];
    assert_snapshot_name_enumeration_isomorphic(&missing);
    assert_snapshot_name_lookup_isomorphic(&missing, &[402]);

    let entries = named_snapshot_catalog(4096);
    let first_snapshot = BTRFS_FIRST_FREE_OBJECTID + 4096;
    let snapshot_ids: Vec<_> = (first_snapshot..first_snapshot + 4096).collect();
    assert_snapshot_name_enumeration_isomorphic(&entries);
    assert_snapshot_name_lookup_isomorphic(&entries, &snapshot_ids);

    let mut group = c.benchmark_group("btrfs_snapshot_root_ref_index_4096");
    group
        .sample_size(30)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    group.bench_function("linear_control_a", |b| {
        b.iter(|| {
            black_box(frozen_linear_snapshot_names(
                black_box(entries.as_slice()),
                black_box(snapshot_ids.as_slice()),
            ))
        });
    });
    group.bench_function("linear_control_b", |b| {
        b.iter(|| {
            black_box(frozen_linear_snapshot_names(
                black_box(entries.as_slice()),
                black_box(snapshot_ids.as_slice()),
            ))
        });
    });
    group.bench_function("root_ref_indexed", |b| {
        b.iter(|| {
            black_box(indexed_snapshot_names(
                black_box(entries.as_slice()),
                black_box(snapshot_ids.as_slice()),
            ))
        });
    });
    group.finish();
}

fn snapshot_diff_inode_entry(objectid: u64, generation: u64) -> BtrfsLeafEntry {
    let mut data = vec![0_u8; 160];
    data[0..8].copy_from_slice(&generation.to_le_bytes());
    BtrfsLeafEntry {
        key: BtrfsKey {
            objectid,
            item_type: BTRFS_ITEM_INODE_ITEM,
            offset: 0,
        },
        data,
    }
}

fn snapshot_diff_catalog() -> (Vec<BtrfsLeafEntry>, Vec<BtrfsLeafEntry>) {
    const COUNT: u64 = 4096;
    const OVERLAP: u64 = 3072;

    let older = (0..COUNT)
        .map(|offset| snapshot_diff_inode_entry(BTRFS_FIRST_FREE_OBJECTID + offset, 10))
        .collect();
    let newer = (COUNT - OVERLAP..COUNT * 2 - OVERLAP)
        .map(|offset| {
            let generation = if offset & 1 == 0 { 11 } else { 10 };
            snapshot_diff_inode_entry(BTRFS_FIRST_FREE_OBJECTID + offset, generation)
        })
        .collect();
    (older, newer)
}

/// Frozen pre-change implementation: two membership/probe passes followed by
/// a result sort. This remains the same-binary control for the ordered merge.
fn frozen_sorted_snapshot_diff(
    older_entries: &[BtrfsLeafEntry],
    newer_entries: &[BtrfsLeafEntry],
) -> Vec<SnapshotDiffEntry> {
    let collect_inodes = |entries: &[BtrfsLeafEntry]| -> BTreeMap<u64, u64> {
        entries
            .iter()
            .filter(|entry| entry.key.item_type == BTRFS_ITEM_INODE_ITEM)
            .filter_map(|entry| {
                let inode = parse_inode_item(&entry.data).ok()?;
                Some((entry.key.objectid, inode.generation))
            })
            .collect()
    };

    let old_inodes = collect_inodes(older_entries);
    let new_inodes = collect_inodes(newer_entries);
    let mut diffs = Vec::new();

    for &objectid in old_inodes.keys() {
        if !new_inodes.contains_key(&objectid) {
            diffs.push(SnapshotDiffEntry {
                inode: objectid,
                change_type: SnapshotChangeType::Deleted,
            });
        }
    }
    for (&objectid, &new_generation) in &new_inodes {
        match old_inodes.get(&objectid) {
            None => diffs.push(SnapshotDiffEntry {
                inode: objectid,
                change_type: SnapshotChangeType::Added,
            }),
            Some(&old_generation) if new_generation > old_generation => {
                diffs.push(SnapshotDiffEntry {
                    inode: objectid,
                    change_type: SnapshotChangeType::Modified,
                });
            }
            _ => {}
        }
    }
    diffs.sort_by_key(|diff| diff.inode);
    diffs
}

fn bench_snapshot_diff_ordered_merge(c: &mut Criterion) {
    let (older, newer) = snapshot_diff_catalog();
    let expected = frozen_sorted_snapshot_diff(&older, &newer);
    assert_eq!(frozen_sorted_snapshot_diff(&older, &newer), expected);
    assert_eq!(snapshot_diff_by_generation(&older, &newer), expected);

    let mut group = c.benchmark_group("btrfs_snapshot_diff_ordered_merge_4096");
    group
        .sample_size(30)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    group.bench_function("sorted_control_a", |b| {
        b.iter(|| {
            black_box(frozen_sorted_snapshot_diff(
                black_box(older.as_slice()),
                black_box(newer.as_slice()),
            ))
        });
    });
    group.bench_function("sorted_control_b", |b| {
        b.iter(|| {
            black_box(frozen_sorted_snapshot_diff(
                black_box(older.as_slice()),
                black_box(newer.as_slice()),
            ))
        });
    });
    group.bench_function("production", |b| {
        b.iter(|| {
            black_box(snapshot_diff_by_generation(
                black_box(older.as_slice()),
                black_box(newer.as_slice()),
            ))
        });
    });
    group.finish();
}

criterion_group!(
    parsed_node_cache,
    bench_parsed_node_cache,
    bench_leaf_cache_admission,
    bench_subvolume_root_ref_index,
    bench_snapshot_source_uuid_index,
    bench_snapshot_root_ref_index,
    bench_snapshot_candidate_filter,
    bench_snapshot_name_filter,
    bench_snapshot_diff_ordered_merge
);
criterion_main!(parsed_node_cache);
