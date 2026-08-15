#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the ext4 `getxattr` by-name lookup (bd-abu3z).
//!
//! `getxattr` resolves ONE attribute. The old path parsed every attribute in
//! the block — allocating a name `Vec` and a value `Vec` per entry — then built
//! a `full_name` `String` per entry to `.find()` the one wanted. The new
//! `find_xattr_block_value_by_name` walks the entry table once, compares each
//! name to the target allocation-free, and materializes only the matched value.
//!
//! This benches resolving the LAST attribute in a 24-entry xattr block (the
//! worst case for the linear find, and the shape of an inode with an external
//! ACL/EA block holding many attributes).

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::{
    find_xattr_block_value_by_index_name, find_xattr_block_value_by_name,
    parse_xattr_block_with_inum,
};
use std::hint::black_box;

const N: usize = 24; // attributes packed in the external xattr block
const VALUE_LEN: usize = 64; // bytes per attribute value
const BLOCK_LEN: usize = 4096;
const EXT4_XATTR_MAGIC: u32 = 0xEA02_0000;
const EXT4_XATTR_INDEX_USER: u8 = 1;

/// Build a valid external xattr block holding `N` `user.attrNN` attributes,
/// each with a `VALUE_LEN`-byte value. Entry table grows from offset 32; values
/// live in the upper half of the block.
fn build_block() -> Vec<u8> {
    build_block_n(N)
}

/// `build_block` parameterized on the attribute count, so the by-name vs
/// by-index finder A/B can measure a realistic small (ibody-shaped) block as
/// well as the 24-entry worst case.
fn build_block_n(n: usize) -> Vec<u8> {
    let mut block = vec![0_u8; BLOCK_LEN];
    block[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());

    let mut entry_off = 32_usize;
    for i in 0..n {
        let name = format!("attr{i:02}"); // 6 bytes -> "user.attrNN"
        let name_bytes = name.as_bytes();
        let value_offs = 2048 + i * VALUE_LEN;

        block[entry_off] = name_bytes.len() as u8;
        block[entry_off + 1] = EXT4_XATTR_INDEX_USER;
        block[entry_off + 2..entry_off + 4].copy_from_slice(&(value_offs as u16).to_le_bytes());
        block[entry_off + 4..entry_off + 8].copy_from_slice(&0_u32.to_le_bytes()); // e_value_inum
        block[entry_off + 8..entry_off + 12].copy_from_slice(&(VALUE_LEN as u32).to_le_bytes()); // e_value_size
        block[entry_off + 12..entry_off + 16].copy_from_slice(&0_u32.to_le_bytes()); // hash
        block[entry_off + 16..entry_off + 16 + name_bytes.len()].copy_from_slice(name_bytes);

        // Distinct value bytes per attribute.
        for (j, b) in block[value_offs..value_offs + VALUE_LEN]
            .iter_mut()
            .enumerate()
        {
            *b = (i as u8).wrapping_mul(31).wrapping_add(j as u8);
        }

        entry_off = (entry_off + 16 + name_bytes.len() + 3) & !3;
    }
    // Terminator entry (name_len=0, name_index=0).
    block[entry_off] = 0;
    block[entry_off + 1] = 0;
    block
}

/// Old path: parse every attribute, then find the one whose full name matches.
fn parse_all_then_find(block: &[u8], target: &str) -> Option<Vec<u8>> {
    let xattrs = parse_xattr_block_with_inum(block).unwrap();
    xattrs
        .into_iter()
        .find(|(x, _)| x.full_name() == target)
        .map(|(x, _)| x.value)
}

fn bench_xattr_lookup(c: &mut Criterion) {
    let block = build_block();
    let target = format!("user.attr{:02}", N - 1); // worst case: the last entry

    // Isomorphism: the by-name finder returns the same value as parse-all+find.
    let old = parse_all_then_find(&block, &target);
    let new = find_xattr_block_value_by_name(&block, &target)
        .unwrap()
        .map(|(_, v, _)| v);
    assert_eq!(old, new, "by-name finder diverged from parse-all+find");
    assert!(new.is_some(), "target must be present");

    let mut group = c.benchmark_group("ext4_getxattr_block_24");
    group.bench_function("parse_all_then_find", |b| {
        b.iter(|| black_box(parse_all_then_find(black_box(&block), black_box(&target))));
    });
    group.bench_function("find_by_name", |b| {
        b.iter(|| {
            black_box(
                find_xattr_block_value_by_name(black_box(&block), black_box(&target))
                    .unwrap()
                    .map(|(_, v, _)| v),
            )
        });
    });
    group.finish();
}

// ── by-name (lossy, prefix-strip per entry) vs by-index (parse namespace once,
//    byte-compare per entry) getxattr finder ─────────────────────────────────
//
// ffs-core `getxattr` resolves the external block via `find_xattr_block_value_
// by_name`, which for EVERY entry re-strips the namespace prefix from the full
// target and does `String::from_utf8_lossy(name) == rest` (a UTF-8 validity scan
// of the name). The split finder `find_xattr_block_value_by_index_name` — which
// the write path's `entry_index` and the kernel's handler already use — parses
// the namespace ONCE and per entry does `name_index == want && name == suffix`
// (a raw byte compare, no validity scan). This A/B measures whether routing
// getxattr through the by-index finder is a real saving, at a realistic 4-entry
// (ibody-shaped) block and the 24-entry worst case. `_a`/`_b` are the A/A null.
fn bench_getxattr_finder_by_index(c: &mut Criterion) {
    for &n in &[4_usize, 24_usize] {
        let block = build_block_n(n);
        let target = format!("user.attr{:02}", n - 1); // worst case: last entry
        let suffix = format!("attr{:02}", n - 1);
        let suffix_bytes = suffix.as_bytes();

        // Isomorphism on this well-formed block: the by-index finder resolves the
        // same value as the by-name finder.
        let by_name = find_xattr_block_value_by_name(&block, &target)
            .unwrap()
            .map(|(_, v, _)| v);
        let by_index =
            find_xattr_block_value_by_index_name(&block, EXT4_XATTR_INDEX_USER, suffix_bytes)
                .unwrap()
                .map(|(_, v, _)| v);
        assert_eq!(by_name, by_index, "by-index finder diverged from by-name");
        assert!(by_name.is_some(), "target must be present");

        let mut group = c.benchmark_group(format!("ext4_getxattr_finder_{n}"));
        group.bench_function("by_name_lossy_a", |b| {
            b.iter(|| {
                black_box(
                    find_xattr_block_value_by_name(black_box(&block), black_box(&target))
                        .unwrap()
                        .map(|(_, v, _)| v),
                )
            });
        });
        group.bench_function("by_name_lossy_b", |b| {
            b.iter(|| {
                black_box(
                    find_xattr_block_value_by_name(black_box(&block), black_box(&target))
                        .unwrap()
                        .map(|(_, v, _)| v),
                )
            });
        });
        group.bench_function("by_index_bytes", |b| {
            b.iter(|| {
                black_box(
                    find_xattr_block_value_by_index_name(
                        black_box(&block),
                        EXT4_XATTR_INDEX_USER,
                        black_box(suffix_bytes),
                    )
                    .unwrap()
                    .map(|(_, v, _)| v),
                )
            });
        });
        group.finish();
    }
}

criterion_group!(
    xattr_lookup,
    bench_xattr_lookup,
    bench_getxattr_finder_by_index
);
criterion_main!(xattr_lookup);
