#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! A/B for btrfs `listxattr` names-only parsing.
//!
//! `btrfs_listxattr` collects every XATTR_ITEM's attributes via
//! `parse_xattr_items`, which copies each attribute's VALUE into a fresh `Vec`
//! (`data[name_end..value_end].to_vec()`) — then uses only the names and drops
//! the values. `parse_xattr_item_names` does the identical walk + bounds
//! validation but skips the value copy.
//!
//! Run per-crate:
//!   CARGO_TARGET_DIR=/data/projects/frankenfs/.rch-targets/blackthrush-dig8 \
//!   rch exec -- cargo bench --profile release -p ffs-btrfs --bench xattr_names

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::{find_xattr_item_value, parse_xattr_item_names, parse_xattr_items};
use ffs_types::ParseError;
use std::hint::black_box;
use std::time::Duration;

const HEADER: usize = 30;
const N: usize = 24;

/// Build a btrfs XATTR_ITEM payload of `n` attributes, each `user.attrNN` with a
/// `value_len`-byte value. Layout per item: 30-byte header (data_len @25..27,
/// name_len @27..29, rest ignored), name, value.
fn build_payload(n: usize, value_len: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    for i in 0..n {
        let name = format!("user.attr{i:02}");
        let name_bytes = name.as_bytes();
        let mut hdr = [0u8; HEADER];
        hdr[25..27].copy_from_slice(&(value_len as u16).to_le_bytes());
        hdr[27..29].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&hdr);
        buf.extend_from_slice(name_bytes);
        buf.extend(std::iter::repeat_n((i as u8).wrapping_mul(31), value_len));
    }
    buf
}

fn bench_group(c: &mut Criterion, value_len: usize, label: &str) {
    let payload = build_payload(N, value_len);
    // Isomorphism: names-only yields the same names as materialise-all.
    let full = parse_xattr_items(&payload).unwrap();
    let names = parse_xattr_item_names(&payload).unwrap();
    assert_eq!(names.len(), full.len());
    for (nm, item) in names.iter().zip(full.iter()) {
        assert_eq!(nm, &item.name, "names-only diverged ({label})");
    }

    let mut g = c.benchmark_group(format!("btrfs_listxattr_24_{label}"));
    g.bench_function("parse_items_with_values", |b| {
        b.iter(|| black_box(parse_xattr_items(black_box(&payload)).unwrap()));
    });
    g.bench_function("parse_names_only", |b| {
        b.iter(|| black_box(parse_xattr_item_names(black_box(&payload)).unwrap()));
    });
    g.finish();
}

fn bench(c: &mut Criterion) {
    bench_group(c, 32, "smallval");
    bench_group(c, 128, "largeval");
}

fn parse_items_then_find(data: &[u8], target: &[u8]) -> Result<Option<Vec<u8>>, ParseError> {
    Ok(parse_xattr_items(data)?
        .into_iter()
        .find(|item| item.name.as_slice() == target)
        .map(|item| item.value))
}

fn assert_getxattr_isomorphic(data: &[u8], target: &[u8]) {
    let control = parse_items_then_find(data, target);
    let candidate = find_xattr_item_value(data, target);
    match (control, candidate) {
        (Ok(control), Ok(candidate)) => assert_eq!(candidate, control),
        (Err(control), Err(candidate)) => {
            assert_eq!(format!("{candidate:?}"), format!("{control:?}"));
        }
        (control, candidate) => panic!("getxattr verdict diverged: {control:?} != {candidate:?}"),
    }
}

fn bench_getxattr_group(c: &mut Criterion, label: &str, payload: &[u8], target: &[u8]) {
    let mut group = c.benchmark_group(format!("btrfs_getxattr_value_{label}"));
    group
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2));
    for control in ["parse_all_control_a", "parse_all_control_b"] {
        group.bench_function(control, |b| {
            b.iter(|| {
                black_box(
                    parse_items_then_find(black_box(payload), black_box(target))
                        .expect("control parse"),
                )
            });
        });
    }
    group.bench_function("find_value_only", |b| {
        b.iter(|| {
            black_box(
                find_xattr_item_value(black_box(payload), black_box(target))
                    .expect("candidate parse"),
            )
        });
    });
    group.finish();
}

fn bench_getxattr_value(c: &mut Criterion) {
    let singleton = build_payload(1, 64);
    assert_getxattr_isomorphic(&singleton, b"user.attr00");
    assert_getxattr_isomorphic(&singleton, b"user.missing");

    let collisions = build_payload(8, 64);
    assert_getxattr_isomorphic(&collisions, b"user.attr07");
    assert_getxattr_isomorphic(&collisions, b"user.missing");

    let mut malformed_after_match = singleton.clone();
    malformed_after_match.push(0);
    assert_getxattr_isomorphic(&malformed_after_match, b"user.attr00");

    bench_getxattr_group(c, "singleton_hit_64", &singleton, b"user.attr00");
    bench_getxattr_group(c, "collision8_last_hit_64", &collisions, b"user.attr07");
}

criterion_group!(xattr_names, bench, bench_getxattr_value);
criterion_main!(xattr_names);
