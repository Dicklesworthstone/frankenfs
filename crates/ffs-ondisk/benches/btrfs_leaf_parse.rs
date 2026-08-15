#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Criterion benchmark for `parse_leaf_items` (btrfs leaf-block parse).
//!
//! `parse_leaf_items` is on the hottest btrfs metadata path — it runs on every
//! leaf block read during a tree walk. Its per-item payload-overlap validation
//! is the dominant cost on a dense leaf (hundreds of items), so this benchmark
//! builds a packed leaf to establish the parse latency under load.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::{parse_internal_items, parse_leaf_items};
use std::hint::black_box;

/// btrfs on-disk header size (`sizeof(struct btrfs_header)`).
const BTRFS_HEADER_SIZE: usize = 101;
/// btrfs on-disk item-table entry size (`sizeof(struct btrfs_item)`).
const BTRFS_ITEM_SIZE: usize = 25;
/// btrfs on-disk internal key-pointer size (`sizeof(struct btrfs_key_ptr)`).
const BTRFS_KEY_PTR_SIZE: usize = 33;
/// `nritems` little-endian field offset inside the header.
const NRITEMS_OFFSET: usize = 0x60;
/// `level` byte offset inside the header.
const LEVEL_OFFSET: usize = 0x64;

/// Build a valid, densely packed btrfs leaf block: `nritems` items with strictly
/// increasing keys and `payload_size`-byte non-overlapping payloads laid out
/// downward from the block end. This is the worst case for the per-item
/// payload-overlap check.
fn build_dense_leaf(block_size: usize, payload_size: usize) -> Vec<u8> {
    let header_size = u32::try_from(BTRFS_HEADER_SIZE).unwrap();
    // Largest nritems whose item table + payloads fit the block.
    let nritems = (block_size - BTRFS_HEADER_SIZE) / (BTRFS_ITEM_SIZE + payload_size);
    let mut block = vec![0_u8; block_size];
    block[NRITEMS_OFFSET..NRITEMS_OFFSET + 4]
        .copy_from_slice(&u32::try_from(nritems).unwrap().to_le_bytes());
    block[LEVEL_OFFSET] = 0; // leaf

    for idx in 0..nritems {
        let base = BTRFS_HEADER_SIZE + idx * BTRFS_ITEM_SIZE;
        // Strictly increasing key (objectid = idx).
        block[base..base + 8].copy_from_slice(&(idx as u64).to_le_bytes());
        block[base + 8] = 1; // item_type
        block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes()); // key offset
        // Payload laid out downward from the block end; non-overlapping.
        let data_offset_abs = block_size - (idx + 1) * payload_size;
        let data_offset_rel = u32::try_from(data_offset_abs).unwrap() - header_size;
        block[base + 17..base + 21].copy_from_slice(&data_offset_rel.to_le_bytes());
        block[base + 21..base + 25]
            .copy_from_slice(&u32::try_from(payload_size).unwrap().to_le_bytes());
    }
    block
}

fn build_dense_internal_node(block_size: usize) -> Vec<u8> {
    let nritems = (block_size - BTRFS_HEADER_SIZE) / BTRFS_KEY_PTR_SIZE;
    let mut block = vec![0_u8; block_size];
    block[NRITEMS_OFFSET..NRITEMS_OFFSET + 4]
        .copy_from_slice(&u32::try_from(nritems).unwrap().to_le_bytes());
    block[LEVEL_OFFSET] = 1;

    for idx in 0..nritems {
        let base = BTRFS_HEADER_SIZE + idx * BTRFS_KEY_PTR_SIZE;
        let ordinal = u64::try_from(idx + 1).expect("fixture index fits");
        block[base..base + 8].copy_from_slice(&ordinal.to_le_bytes());
        block[base + 8] = 1;
        block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
        block[base + 17..base + 25].copy_from_slice(&ordinal.to_le_bytes());
        block[base + 25..base + 33].copy_from_slice(&(ordinal + 7).to_le_bytes());
    }
    block
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedLeafItemModel {
    objectid: u64,
    item_type: u8,
    key_offset: u64,
    data_offset: u32,
    data_size: u32,
}

fn read_u32_at(block: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(block[offset..offset + 4].try_into().expect("u32 field"))
}

fn read_u64_at(block: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(block[offset..offset + 8].try_into().expect("u64 field"))
}

fn eager_word_range_mask(lo: usize, hi: usize) -> u64 {
    let high = if hi >= 64 {
        u64::MAX
    } else {
        (1_u64 << hi) - 1
    };
    let low = (1_u64 << lo) - 1;
    high & !low
}

fn eager_payload_range_collides(bits: &mut [u64], start: usize, end: usize) -> bool {
    let first_word = start / 64;
    let last_word = (end - 1) / 64;
    let first_mask = eager_word_range_mask(start % 64, 64);
    let last_mask = eager_word_range_mask(0, (end - 1) % 64 + 1);

    if first_word == last_word {
        let mask = first_mask & last_mask;
        if bits[first_word] & mask != 0 {
            return true;
        }
        bits[first_word] |= mask;
        return false;
    }

    if bits[first_word] & first_mask != 0 || bits[last_word] & last_mask != 0 {
        return true;
    }
    if bits[first_word + 1..last_word].iter().any(|&w| w != 0) {
        return true;
    }

    bits[first_word] |= first_mask;
    bits[last_word] |= last_mask;
    for word in &mut bits[first_word + 1..last_word] {
        *word = u64::MAX;
    }
    false
}

fn parse_leaf_items_eager_coverage_model(block: &[u8]) -> Vec<ParsedLeafItemModel> {
    assert_eq!(block[LEVEL_OFFSET], 0, "model expects a leaf block");
    let nritems = usize::try_from(read_u32_at(block, NRITEMS_OFFSET)).expect("nritems fits");
    let items_end = BTRFS_HEADER_SIZE + nritems * BTRFS_ITEM_SIZE;
    assert!(block.len() >= items_end, "item table fits");

    let header_size = u32::try_from(BTRFS_HEADER_SIZE).expect("header size fits");
    let mut payload_coverage = vec![0_u64; block.len().div_ceil(64)];
    let mut previous_key = None;
    let mut out = Vec::with_capacity(nritems);

    for idx in 0..nritems {
        let base = BTRFS_HEADER_SIZE + idx * BTRFS_ITEM_SIZE;
        let objectid = read_u64_at(block, base);
        let item_type = block[base + 8];
        let key_offset = read_u64_at(block, base + 9);
        let key = (objectid, item_type, key_offset);
        if let Some(previous) = previous_key {
            assert!(previous < key, "keys are strictly increasing");
        }
        previous_key = Some(key);

        let data_offset = read_u32_at(block, base + 17)
            .checked_add(header_size)
            .expect("data offset fits");
        let data_size = read_u32_at(block, base + 21);
        let data_offset_usize = usize::try_from(data_offset).expect("offset fits");
        let data_size_usize = usize::try_from(data_size).expect("size fits");
        assert!(data_offset_usize >= items_end, "payload starts after table");
        let data_end = data_offset_usize
            .checked_add(data_size_usize)
            .expect("payload end fits");
        assert!(data_end <= block.len(), "payload lies inside block");
        if data_size_usize > 0 {
            assert!(
                !eager_payload_range_collides(&mut payload_coverage, data_offset_usize, data_end),
                "payloads do not overlap"
            );
        }

        out.push(ParsedLeafItemModel {
            objectid,
            item_type,
            key_offset,
            data_offset,
            data_size,
        });
    }

    out
}

fn assert_model_matches_parser(block: &[u8]) {
    let model = parse_leaf_items_eager_coverage_model(block);
    let (_, parsed) = parse_leaf_items(block).expect("production parser accepts dense leaf");
    assert_eq!(model.len(), parsed.len());
    for (model, parsed) in model.iter().zip(parsed.iter()) {
        assert_eq!(model.objectid, parsed.key.objectid);
        assert_eq!(model.item_type, parsed.key.item_type);
        assert_eq!(model.key_offset, parsed.key.offset);
        assert_eq!(model.data_offset, parsed.data_offset);
        assert_eq!(model.data_size, parsed.data_size);
    }
}

fn indexed_item_table_digest(block: &[u8]) -> u64 {
    let nritems = usize::try_from(read_u32_at(block, NRITEMS_OFFSET)).expect("nritems fits");
    let mut digest = 0_u64;
    for idx in 0..nritems {
        let base = BTRFS_HEADER_SIZE + idx * BTRFS_ITEM_SIZE;
        digest = digest.rotate_left(7) ^ read_u64_at(block, base);
        digest = digest.rotate_left(7) ^ u64::from(block[base + 8]);
        digest = digest.rotate_left(7) ^ read_u64_at(block, base + 9);
        digest = digest.rotate_left(7) ^ u64::from(read_u32_at(block, base + 17));
        digest = digest.rotate_left(7) ^ u64::from(read_u32_at(block, base + 21));
    }
    digest
}

fn chunked_item_table_digest(block: &[u8]) -> u64 {
    let nritems = usize::try_from(read_u32_at(block, NRITEMS_OFFSET)).expect("nritems fits");
    let items_end = BTRFS_HEADER_SIZE + nritems * BTRFS_ITEM_SIZE;
    let mut digest = 0_u64;
    for item in block[BTRFS_HEADER_SIZE..items_end].chunks_exact(BTRFS_ITEM_SIZE) {
        digest = digest.rotate_left(7) ^ read_u64_at(item, 0);
        digest = digest.rotate_left(7) ^ u64::from(item[8]);
        digest = digest.rotate_left(7) ^ read_u64_at(item, 9);
        digest = digest.rotate_left(7) ^ u64::from(read_u32_at(item, 17));
        digest = digest.rotate_left(7) ^ u64::from(read_u32_at(item, 21));
    }
    digest
}

fn indexed_key_ptr_table_digest(block: &[u8]) -> u64 {
    let nritems = usize::try_from(read_u32_at(block, NRITEMS_OFFSET)).expect("nritems fits");
    let mut digest = 0_u64;
    for idx in 0..nritems {
        let base = BTRFS_HEADER_SIZE + idx * BTRFS_KEY_PTR_SIZE;
        digest = digest.rotate_left(7) ^ read_u64_at(block, base);
        digest = digest.rotate_left(7) ^ u64::from(block[base + 8]);
        digest = digest.rotate_left(7) ^ read_u64_at(block, base + 9);
        digest = digest.rotate_left(7) ^ read_u64_at(block, base + 17);
        digest = digest.rotate_left(7) ^ read_u64_at(block, base + 25);
    }
    digest
}

fn chunked_key_ptr_table_digest(block: &[u8]) -> u64 {
    let nritems = usize::try_from(read_u32_at(block, NRITEMS_OFFSET)).expect("nritems fits");
    let table_end = BTRFS_HEADER_SIZE + nritems * BTRFS_KEY_PTR_SIZE;
    let mut digest = 0_u64;
    for key_ptr in block[BTRFS_HEADER_SIZE..table_end].chunks_exact(BTRFS_KEY_PTR_SIZE) {
        digest = digest.rotate_left(7) ^ read_u64_at(key_ptr, 0);
        digest = digest.rotate_left(7) ^ u64::from(key_ptr[8]);
        digest = digest.rotate_left(7) ^ read_u64_at(key_ptr, 9);
        digest = digest.rotate_left(7) ^ read_u64_at(key_ptr, 17);
        digest = digest.rotate_left(7) ^ read_u64_at(key_ptr, 25);
    }
    digest
}

fn normalize_offsets_with_conversion_inside(block: &[u8]) -> u64 {
    let nritems = usize::try_from(read_u32_at(block, NRITEMS_OFFSET)).expect("nritems fits");
    let items_end = BTRFS_HEADER_SIZE + nritems * BTRFS_ITEM_SIZE;
    let mut digest = 0_u64;
    for item in block[BTRFS_HEADER_SIZE..items_end].chunks_exact(BTRFS_ITEM_SIZE) {
        let header_size = u32::try_from(BTRFS_HEADER_SIZE).expect("header size fits");
        let absolute = read_u32_at(item, 17)
            .checked_add(header_size)
            .expect("fixture offset fits");
        digest = digest.rotate_left(7) ^ u64::from(absolute);
    }
    digest
}

fn normalize_offsets_with_conversion_hoisted(block: &[u8]) -> u64 {
    let nritems = usize::try_from(read_u32_at(block, NRITEMS_OFFSET)).expect("nritems fits");
    let items_end = BTRFS_HEADER_SIZE + nritems * BTRFS_ITEM_SIZE;
    let header_size = u32::try_from(BTRFS_HEADER_SIZE).expect("header size fits");
    let mut digest = 0_u64;
    for item in block[BTRFS_HEADER_SIZE..items_end].chunks_exact(BTRFS_ITEM_SIZE) {
        let absolute = read_u32_at(item, 17)
            .checked_add(header_size)
            .expect("fixture offset fits");
        digest = digest.rotate_left(7) ^ u64::from(absolute);
    }
    digest
}

fn bench_parse_dense_leaf(c: &mut Criterion) {
    // Default btrfs nodesize (16 KiB), 1-byte payloads → ~626 items.
    let leaf_16k = build_dense_leaf(16 * 1024, 1);
    // Smaller 4 KiB leaf → ~156 items.
    let leaf_4k = build_dense_leaf(4 * 1024, 1);

    // Sanity: both parse cleanly and match the old eager-coverage model before
    // benchmarking either shape.
    assert_model_matches_parser(&leaf_16k);
    assert_model_matches_parser(&leaf_4k);

    let mut group = c.benchmark_group("btrfs_leaf_parse");
    group.bench_function("parse_dense_leaf_16k", |b| {
        b.iter(|| black_box(parse_leaf_items(black_box(&leaf_16k)).unwrap()));
    });
    group.bench_function("parse_dense_leaf_4k", |b| {
        b.iter(|| black_box(parse_leaf_items(black_box(&leaf_4k)).unwrap()));
    });
    group.finish();
}

fn bench_payload_coverage_ab(c: &mut Criterion) {
    let leaf_16k = build_dense_leaf(16 * 1024, 1);
    assert_model_matches_parser(&leaf_16k);

    let mut group = c.benchmark_group("btrfs_leaf_payload_coverage_ab");
    group.bench_function("old_eager_coverage_model_16k", |b| {
        b.iter(|| black_box(parse_leaf_items_eager_coverage_model(black_box(&leaf_16k))));
    });
    group.bench_function("lazy_descending_fast_path_16k", |b| {
        b.iter(|| black_box(parse_leaf_items(black_box(&leaf_16k)).unwrap()));
    });
    group.finish();
}

fn bench_item_table_decode_ab(c: &mut Criterion) {
    let leaf_16k = build_dense_leaf(16 * 1024, 1);
    assert_eq!(
        indexed_item_table_digest(&leaf_16k),
        chunked_item_table_digest(&leaf_16k),
        "fixed-width item-table iteration changed decoded fields"
    );

    let mut group = c.benchmark_group("btrfs_leaf_item_decode_ab");
    for control in ["indexed_offsets_a", "indexed_offsets_b"] {
        group.bench_function(control, |b| {
            b.iter(|| black_box(indexed_item_table_digest(black_box(&leaf_16k))));
        });
    }
    group.bench_function("fixed_width_chunks", |b| {
        b.iter(|| black_box(chunked_item_table_digest(black_box(&leaf_16k))));
    });
    group.finish();
}

fn bench_internal_item_decode_ab(c: &mut Criterion) {
    let node_16k = build_dense_internal_node(16 * 1024);
    let (_, parsed) = parse_internal_items(&node_16k).expect("production internal parser");
    assert_eq!(
        parsed.len(),
        (16 * 1024 - BTRFS_HEADER_SIZE) / BTRFS_KEY_PTR_SIZE
    );
    for (idx, key_ptr) in parsed.iter().enumerate() {
        let ordinal = u64::try_from(idx + 1).expect("fixture index fits");
        assert_eq!(key_ptr.key.objectid, ordinal);
        assert_eq!(key_ptr.key.item_type, 1);
        assert_eq!(key_ptr.key.offset, 0);
        assert_eq!(key_ptr.blockptr, ordinal);
        assert_eq!(key_ptr.generation, ordinal + 7);
    }
    assert_eq!(
        indexed_key_ptr_table_digest(&node_16k),
        chunked_key_ptr_table_digest(&node_16k),
        "fixed-width key-pointer iteration changed decoded fields"
    );

    let mut group = c.benchmark_group("btrfs_internal_item_decode_ab");
    for control in ["indexed_offsets_a", "indexed_offsets_b"] {
        group.bench_function(control, |b| {
            b.iter(|| black_box(indexed_key_ptr_table_digest(black_box(&node_16k))));
        });
    }
    group.bench_function("fixed_width_chunks", |b| {
        b.iter(|| black_box(chunked_key_ptr_table_digest(black_box(&node_16k))));
    });
    group.finish();
}

fn bench_header_size_conversion_hoist_ab(c: &mut Criterion) {
    let leaf_16k = build_dense_leaf(16 * 1024, 1);
    assert_eq!(
        normalize_offsets_with_conversion_inside(&leaf_16k),
        normalize_offsets_with_conversion_hoisted(&leaf_16k),
        "hoisting the constant header-size conversion changed normalized offsets"
    );

    let mut group = c.benchmark_group("btrfs_leaf_header_size_hoist_ab");
    for control in ["conversion_inside_a", "conversion_inside_b"] {
        group.bench_function(control, |b| {
            b.iter(|| {
                black_box(normalize_offsets_with_conversion_inside(black_box(
                    &leaf_16k,
                )))
            });
        });
    }
    group.bench_function("conversion_hoisted", |b| {
        b.iter(|| {
            black_box(normalize_offsets_with_conversion_hoisted(black_box(
                &leaf_16k,
            )))
        });
    });
    group.finish();
}

criterion_group!(
    btrfs_leaf,
    bench_parse_dense_leaf,
    bench_payload_coverage_ab,
    bench_item_table_decode_ab,
    bench_internal_item_decode_ab,
    bench_header_size_conversion_hoist_ab
);
criterion_main!(btrfs_leaf);
