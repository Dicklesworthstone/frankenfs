#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! A/B benchmark for the btrfs readdir name-dedup lever (ffs-core
//! `btrfs_dedup_dir_rows`).
//!
//! A btrfs directory presents ~2 rows per file (a DIR_ITEM and a DIR_INDEX with
//! the same name), and readdir deduplicates by name keeping the first in sort
//! order. The prior implementation scanned every already-kept row per row —
//! O(rows^2), i.e. O(files^2) per `ls`. This benches that all-pairs scan against
//! the O(N) seen-name HashSet on a realistic 2x-duplicated, sorted row set. The
//! two standalone functions mirror the old/new implementations exactly (the real
//! helper is private to ffs-core).

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ffs_btrfs::{
    BTRFS_ITEM_DIR_INDEX, BTRFS_ITEM_DIR_ITEM, BtrfsBTree, BtrfsDirItem, BtrfsKey,
    InMemoryCowBtrfsTree, btrfs_name_hash, parse_dir_items, visit_dir_items,
};
use std::collections::HashSet;
use std::hint::black_box;

const FILES: usize = 3000;
const PARSE_PAYLOADS: usize = 1024;

type ProjectedDirItem = (u64, u8, u64, u8, Vec<u8>);

fn build_parse_payloads() -> Vec<Vec<u8>> {
    (0..PARSE_PAYLOADS)
        .map(|index| {
            BtrfsDirItem {
                child_objectid: 10_000 + index as u64,
                child_key_type: 1,
                child_key_offset: index as u64 * 7,
                file_type: 1,
                name: format!("file{index:06}").into_bytes(),
            }
            .to_bytes()
        })
        .collect()
}

fn project_owned_parser(payloads: &[Vec<u8>]) -> Vec<ProjectedDirItem> {
    let mut rows = Vec::with_capacity(payloads.len());
    for payload in payloads {
        for item in parse_dir_items(payload).expect("owned parse") {
            rows.push((
                item.child_objectid,
                item.child_key_type,
                item.child_key_offset,
                item.file_type,
                item.name,
            ));
        }
    }
    rows
}

fn project_borrowed_visitor(payloads: &[Vec<u8>]) -> Vec<ProjectedDirItem> {
    let mut rows = Vec::with_capacity(payloads.len());
    for payload in payloads {
        visit_dir_items(payload, |item| {
            rows.push((
                item.child_objectid,
                item.child_key_type,
                item.child_key_offset,
                item.file_type,
                item.name.to_vec(),
            ));
        })
        .expect("borrowed visit");
    }
    rows
}

fn bench_readdir_parse_projection(c: &mut Criterion) {
    let payloads = build_parse_payloads();
    let control = project_owned_parser(&payloads);
    let candidate = project_borrowed_visitor(&payloads);
    assert_eq!(
        candidate, control,
        "borrowed projection must match owned parser"
    );

    let mut group = c.benchmark_group("btrfs_readdir_parse_projection_1024");
    for control in ["owned_parser_control_a", "owned_parser_control_b"] {
        group.bench_function(control, |b| {
            b.iter(|| black_box(project_owned_parser(black_box(&payloads))));
        });
    }
    group.bench_function("borrowed_visitor_candidate", |b| {
        b.iter(|| black_box(project_borrowed_visitor(black_box(&payloads))));
    });
    group.finish();
}

/// Build the rows readdir produces: each file as a DIR_INDEX row and a DIR_ITEM
/// row (same name; DIR_ITEM gets the high-bit sort bias), then sorted by key.
fn build_rows() -> Vec<(u64, Vec<u8>)> {
    let mut rows = Vec::with_capacity(FILES * 2);
    for i in 0..FILES {
        let name = format!("file{i:06}").into_bytes();
        rows.push((i as u64, name.clone()));
        rows.push(((1_u64 << 63) | i as u64, name));
    }
    rows.sort_by_key(|(k, _)| *k);
    rows
}

/// Prior implementation: O(N^2) all-pairs keep-first-by-name scan.
fn dedup_linear(rows: Vec<(u64, Vec<u8>)>) -> Vec<(u64, Vec<u8>)> {
    let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
    for row in rows {
        if out.iter().any(|(_, name)| *name == row.1) {
            continue;
        }
        out.push(row);
    }
    out
}

/// New implementation: O(N) seen-name HashSet.
fn dedup_hashset(rows: Vec<(u64, Vec<u8>)>) -> Vec<(u64, Vec<u8>)> {
    let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(rows.len());
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        if seen.insert(row.1.clone()) {
            out.push(row);
        }
    }
    out
}

fn bench_readdir_dedup(c: &mut Criterion) {
    let rows = build_rows();
    // Isomorphism: both keep the same first-by-sort-order rows.
    assert_eq!(dedup_linear(rows.clone()), dedup_hashset(rows.clone()));
    assert_eq!(dedup_hashset(rows.clone()).len(), FILES);

    let mut group = c.benchmark_group("btrfs_readdir_dedup");
    group.sample_size(10);
    group.bench_function("linear_all_pairs", |b| {
        b.iter_batched(
            || rows.clone(),
            |r| black_box(dedup_linear(r)),
            BatchSize::LargeInput,
        );
    });
    group.bench_function("hashset", |b| {
        b.iter_batched(
            || rows.clone(),
            |r| black_box(dedup_hashset(r)),
            BatchSize::LargeInput,
        );
    });
    group.finish();
}

const DIR_INODE: u64 = 256;
/// Representative on-disk `btrfs_dir_item` payload: ~30-byte header plus a short
/// name. readdir parses-and-discards this for every entry, so the COW collection
/// previously cloned it into an intermediate `Vec<u8>` per entry.
const DIR_ITEM_LEN: usize = 40;

/// Build a directory's DIR_ITEM + DIR_INDEX span as readdir's COW path scans it
/// (`[DIR_ITEM offset 0, DIR_INDEX offset MAX]`): one of each per file.
fn build_dir_tree() -> InMemoryCowBtrfsTree {
    let mut tree = InMemoryCowBtrfsTree::new(1 << 22).expect("tree");
    let payload = vec![0_u8; DIR_ITEM_LEN];
    for i in 0..FILES as u64 {
        tree.insert(
            BtrfsKey {
                objectid: DIR_INODE,
                item_type: BTRFS_ITEM_DIR_ITEM,
                offset: i,
            },
            &payload,
        )
        .expect("insert dir_item");
        tree.insert(
            BtrfsKey {
                objectid: DIR_INODE,
                item_type: BTRFS_ITEM_DIR_INDEX,
                offset: i,
            },
            &payload,
        )
        .expect("insert dir_index");
    }
    tree
}

/// A/B for the readdir COW collection (bd-h9awv migration): the old path called
/// `range`, cloning every DIR entry's bytes into a throwaway `Vec<u8>` before
/// parsing; the new path uses `range_with` to parse against the borrowed node
/// bytes. The `ls` of a large directory walks 2 rows per file, so the clone is
/// paid `2 * files` times per readdir.
fn bench_readdir_collect(c: &mut Criterion) {
    let tree = build_dir_tree();
    let start = BtrfsKey {
        objectid: DIR_INODE,
        item_type: BTRFS_ITEM_DIR_ITEM,
        offset: 0,
    };
    let end = BtrfsKey {
        objectid: DIR_INODE,
        item_type: BTRFS_ITEM_DIR_INDEX,
        offset: u64::MAX,
    };

    // Isomorphism: range_with visits the same (key, bytes) sequence as range.
    let materialised = tree.range(&start, &end).expect("range");
    let mut collected = Vec::new();
    tree.range_with(&start, &end, |k, v| collected.push((k, v.to_vec())))
        .expect("range_with");
    assert_eq!(materialised.len(), FILES * 2);
    assert_eq!(materialised, collected);

    let mut group = c.benchmark_group("btrfs_readdir_collect");
    group.sample_size(20);
    // Old: clone each entry's bytes, then "parse" (here: sum lengths).
    group.bench_function("range_clones_each_entry", |b| {
        b.iter(|| {
            let items = tree.range(black_box(&start), black_box(&end)).unwrap();
            let mut bytes = 0_usize;
            for (_k, v) in &items {
                bytes += v.len();
            }
            black_box(bytes)
        });
    });
    // New: borrow each entry's bytes, parse in place — no per-entry allocation.
    group.bench_function("range_with_zero_copy", |b| {
        b.iter(|| {
            let mut bytes = 0_usize;
            tree.range_with(black_box(&start), black_box(&end), |_k, v| bytes += v.len())
                .unwrap();
            black_box(bytes)
        });
    });
    group.finish();
}

/// Build a directory's DIR_ITEM span as btrfs keys it: one DIR_ITEM per file at
/// key offset = `name_hash(name)` (the on-disk convention). Returns the tree and
/// a representative target name to remove.
fn build_dir_item_tree() -> (InMemoryCowBtrfsTree, Vec<u8>) {
    let mut tree = InMemoryCowBtrfsTree::new(1 << 22).expect("tree");
    let mut target = Vec::new();
    for i in 0..FILES {
        let name = format!("file{i:06}").into_bytes();
        let payload = BtrfsDirItem {
            child_objectid: 300 + i as u64,
            child_key_type: 1, // INODE_ITEM
            child_key_offset: 0,
            file_type: 1, // regular file
            name: name.clone(),
        }
        .to_bytes();
        let key = BtrfsKey {
            objectid: DIR_INODE,
            item_type: BTRFS_ITEM_DIR_ITEM,
            offset: u64::from(btrfs_name_hash(&name)),
        };
        tree.insert(key, &payload).expect("insert dir_item");
        if i == FILES / 2 {
            target = name;
        }
    }
    (tree, target)
}

/// Old removal path: range every DIR_ITEM in the directory (offset 0..MAX) and
/// parse each payload to find the bucket holding `name` — O(N) per removal.
fn find_via_full_scan(tree: &InMemoryCowBtrfsTree, name: &[u8]) -> Option<u64> {
    let start = BtrfsKey {
        objectid: DIR_INODE,
        item_type: BTRFS_ITEM_DIR_ITEM,
        offset: 0,
    };
    let end = BtrfsKey {
        objectid: DIR_INODE,
        item_type: BTRFS_ITEM_DIR_ITEM,
        offset: u64::MAX,
    };
    for (_k, payload) in tree.range(&start, &end).expect("range") {
        let entries = parse_dir_items(&payload).expect("parse");
        if let Some(e) = entries.into_iter().find(|e| e.name == name) {
            return Some(e.child_objectid);
        }
    }
    None
}

/// New removal path: seek straight to the name's hash bucket — an O(log N) point
/// query plus a scan of the (tiny) collision bucket.
fn find_via_point_query(tree: &InMemoryCowBtrfsTree, name: &[u8], name_hash: u64) -> Option<u64> {
    let key = BtrfsKey {
        objectid: DIR_INODE,
        item_type: BTRFS_ITEM_DIR_ITEM,
        offset: name_hash,
    };
    for (_k, payload) in tree.range(&key, &key).expect("range") {
        let entries = parse_dir_items(&payload).expect("parse");
        if let Some(e) = entries.into_iter().find(|e| e.name == name) {
            return Some(e.child_objectid);
        }
    }
    None
}

/// Build a directory's DIR_INDEX span as btrfs keys it: one DIR_INDEX per file
/// at key offset = the monotonic per-directory sequence stored in the matching
/// INODE_REF payload. Returns the tree, a target name, and that name's index.
fn build_dir_index_tree() -> (InMemoryCowBtrfsTree, Vec<u8>, u64) {
    let mut tree = InMemoryCowBtrfsTree::new(1 << 22).expect("tree");
    let mut target = Vec::new();
    let mut target_index = 0_u64;
    for i in 0..FILES {
        let name = format!("file{i:06}").into_bytes();
        let payload = BtrfsDirItem {
            child_objectid: 300 + i as u64,
            child_key_type: 1, // INODE_ITEM
            child_key_offset: 0,
            file_type: 1, // regular file
            name: name.clone(),
        }
        .to_bytes();
        let dir_index = 2 + i as u64;
        let key = BtrfsKey {
            objectid: DIR_INODE,
            item_type: BTRFS_ITEM_DIR_INDEX,
            offset: dir_index,
        };
        tree.insert(key, &payload).expect("insert dir_index");
        if i == FILES / 2 {
            target = name;
            target_index = dir_index;
        }
    }
    (tree, target, target_index)
}

/// Old removal path: range every DIR_INDEX in the directory and parse each
/// payload to find the matching name — O(N) per removal.
fn find_dir_index_via_full_scan(tree: &InMemoryCowBtrfsTree, name: &[u8]) -> Option<u64> {
    let start = BtrfsKey {
        objectid: DIR_INODE,
        item_type: BTRFS_ITEM_DIR_INDEX,
        offset: 0,
    };
    let end = BtrfsKey {
        objectid: DIR_INODE,
        item_type: BTRFS_ITEM_DIR_INDEX,
        offset: u64::MAX,
    };
    for (key, payload) in tree.range(&start, &end).expect("range") {
        let entries = parse_dir_items(&payload).expect("parse");
        if entries.iter().any(|e| e.name == name) {
            return Some(key.offset);
        }
    }
    None
}

/// New removal path: the matching INODE_REF already records the DIR_INDEX
/// sequence, so seek straight to that key and validate the name.
fn find_dir_index_via_point_query(
    tree: &InMemoryCowBtrfsTree,
    name: &[u8],
    dir_index: u64,
) -> Option<u64> {
    let key = BtrfsKey {
        objectid: DIR_INODE,
        item_type: BTRFS_ITEM_DIR_INDEX,
        offset: dir_index,
    };
    for (key, payload) in tree.range(&key, &key).expect("range") {
        let entries = parse_dir_items(&payload).expect("parse");
        if entries.iter().any(|e| e.name == name) {
            return Some(key.offset);
        }
    }
    None
}

/// A/B for `btrfs_remove_named_dir_item` (bd-* this session): the removal scanned
/// every DIR_ITEM in the directory to find a name that, by btrfs's hashed keying,
/// can only live in its own `name_hash` bucket. Seeking that bucket directly turns
/// each removal from O(N) into O(log N) — and a full directory delete from O(N^2)
/// into O(N). Mirrors the lookup fast path (bd-a9wot).
fn bench_remove_named_dir_item(c: &mut Criterion) {
    let (tree, target) = build_dir_item_tree();
    let target_hash = u64::from(btrfs_name_hash(&target));

    // Isomorphism: both resolve the same entry (the name lives in exactly one
    // hash bucket, so the point query sees everything the full scan would).
    let full = find_via_full_scan(&tree, &target);
    let point = find_via_point_query(&tree, &target, target_hash);
    assert_eq!(full, point);
    assert!(full.is_some());

    let mut group = c.benchmark_group("btrfs_remove_named_dir_item");
    group.sample_size(20);
    group.bench_function("full_scan_all_dir_items", |b| {
        b.iter(|| black_box(find_via_full_scan(&tree, black_box(&target))));
    });
    group.bench_function("point_query_at_name_hash", |b| {
        b.iter(|| {
            black_box(find_via_point_query(
                &tree,
                black_box(&target),
                black_box(target_hash),
            ))
        });
    });
    group.finish();
}

/// A/B for `btrfs_remove_named_dir_index`: the current path scans every
/// DIR_INDEX in the directory by name, but the matching INODE_REF carries the
/// monotonic index sequence that keys the exact DIR_INDEX item.
fn bench_remove_named_dir_index(c: &mut Criterion) {
    let (tree, target, target_index) = build_dir_index_tree();

    // Isomorphism: the INODE_REF-carried index points at the same entry the
    // current full scan finds by parsing every DIR_INDEX payload.
    let full = find_dir_index_via_full_scan(&tree, &target);
    let point = find_dir_index_via_point_query(&tree, &target, target_index);
    assert_eq!(full, point);
    assert_eq!(full, Some(target_index));

    let mut group = c.benchmark_group("btrfs_remove_named_dir_index");
    group.sample_size(20);
    group.bench_function("full_scan_all_dir_indexes", |b| {
        b.iter(|| black_box(find_dir_index_via_full_scan(&tree, black_box(&target))));
    });
    group.bench_function("point_query_at_inode_ref_index", |b| {
        b.iter(|| {
            black_box(find_dir_index_via_point_query(
                &tree,
                black_box(&target),
                black_box(target_index),
            ))
        });
    });
    group.finish();
}

/// Old counter-seed: range every DIR_INDEX of the directory and take the max key
/// offset — materialises and clones every payload just to read the keys.
fn max_dir_index_via_range(tree: &InMemoryCowBtrfsTree) -> u64 {
    let start = BtrfsKey {
        objectid: DIR_INODE,
        item_type: BTRFS_ITEM_DIR_INDEX,
        offset: 0,
    };
    let end = BtrfsKey {
        objectid: DIR_INODE,
        item_type: BTRFS_ITEM_DIR_INDEX,
        offset: u64::MAX,
    };
    tree.range(&start, &end)
        .expect("range")
        .iter()
        .map(|(k, _)| k.offset)
        .max()
        .map_or(2, |m| m.saturating_add(1))
}

/// New counter-seed: floor_key seeks the LAST DIR_INDEX key directly (O(log N),
/// zero clones) — the max of an offset-sorted key set is its last element.
fn max_dir_index_via_floor_key(tree: &InMemoryCowBtrfsTree) -> u64 {
    let seek = BtrfsKey {
        objectid: DIR_INODE,
        item_type: BTRFS_ITEM_DIR_INDEX,
        offset: u64::MAX,
    };
    match tree.floor_key(&seek).expect("floor_key") {
        Some(k) if k.objectid == DIR_INODE && k.item_type == BTRFS_ITEM_DIR_INDEX => {
            k.offset.saturating_add(1)
        }
        _ => 2,
    }
}

/// A/B for `btrfs_max_ondisk_dir_index_plus_one` (this session): seeding a
/// directory's monotonic DIR_INDEX counter on the first insert after mount ranged
/// and materialised every DIR_INDEX item just to take the max offset — O(N) plus a
/// Vec<u8> clone per entry. Since DIR_INDEX keys are offset-sorted, the max is the
/// last key; floor_key seeks it in O(log N) with no allocation.
fn bench_dir_index_seq_seed(c: &mut Criterion) {
    let (tree, _target, _index) = build_dir_index_tree();

    // Isomorphism: both yield max(existing DIR_INDEX offset) + 1.
    assert_eq!(
        max_dir_index_via_range(&tree),
        max_dir_index_via_floor_key(&tree)
    );

    let mut group = c.benchmark_group("btrfs_dir_index_seq_seed");
    group.sample_size(20);
    group.bench_function("range_max_all_dir_indexes", |b| {
        b.iter(|| black_box(max_dir_index_via_range(black_box(&tree))));
    });
    group.bench_function("floor_key_last_dir_index", |b| {
        b.iter(|| black_box(max_dir_index_via_floor_key(black_box(&tree))));
    });
    group.finish();
}

criterion_group!(
    readdir_dedup,
    bench_readdir_parse_projection,
    bench_readdir_dedup,
    bench_readdir_collect,
    bench_remove_named_dir_item,
    bench_remove_named_dir_index,
    bench_dir_index_seq_seed
);
criterion_main!(readdir_dedup);
