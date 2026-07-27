#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the btrfs data-csum lookup (bd-dgih3).
//!
//! `lookup_data_block_csum` finds the EXTENT_CSUM item covering an on-disk
//! sector. Items are sorted ascending by `key.offset` (the order
//! `build_extent_csum_items` emits and a csum-tree walk yields), and the
//! covering item is the last whose offset is `<=` the target. The old code
//! scanned every item (O(items)); the new code binary-searches (O(log items)).
//!
//! Whole-file csum verification calls this once per sector against the *entire*
//! csum tree, so the scan made verification O(sectors * items): a multi-GiB file
//! has tens-to-hundreds of EXTENT_CSUM items and hundreds of thousands of
//! sectors.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::{
    BTRFS_EXTENT_CSUM_OBJECTID, BTRFS_ITEM_EXTENT_CSUM, BtrfsBTree, BtrfsKey, InMemoryCowBtrfsTree,
    lookup_data_block_csum,
};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::File;
use std::hint::black_box;
use std::io::Read;
use std::process::Command;
use std::time::Instant;

const N: usize = 4096; // EXTENT_CSUM items in the tree (each covers a run of sectors)
const SECTORSIZE: usize = 4096;
const CSUMS_PER_ITEM: u64 = 64; // sectors covered by one item
const CSUM_SIZE: usize = 4;
const DELETE_ITEMS: usize = 8;
const DELETE_PAYLOAD_BYTES: usize = 16 * 1024 - 256;
const DELETE_PAIRS: usize = 31;
const MAX_NULL_FLOOR_RATIO: f64 = 1.025;

#[derive(Clone, Copy)]
struct BootstrapMedianCi {
    median: f64,
    low: f64,
    high: f64,
}

fn median(mut values: Vec<f64>) -> f64 {
    assert!(!values.is_empty(), "median requires at least one sample");
    values.sort_by(f64::total_cmp);
    let midpoint = values.len() / 2;
    if values.len() % 2 == 0 {
        values[midpoint - 1].midpoint(values[midpoint])
    } else {
        values[midpoint]
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

fn bootstrap_median_ci(log_ratios: &[f64]) -> BootstrapMedianCi {
    const RESAMPLES: usize = 20_000;
    assert!(
        !log_ratios.is_empty(),
        "bootstrap median CI requires paired samples"
    );
    let mut state =
        0xC5A0_DE1E_2026_0727_u64 ^ u64::try_from(log_ratios.len()).expect("sample count fits");
    let mut bootstrapped = Vec::with_capacity(RESAMPLES);
    for _ in 0..RESAMPLES {
        let mut sample = Vec::with_capacity(log_ratios.len());
        for _ in log_ratios {
            let draw = splitmix64(&mut state)
                % u64::try_from(log_ratios.len()).expect("sample count fits");
            sample.push(log_ratios[usize::try_from(draw).expect("draw fits usize")]);
        }
        bootstrapped.push(median(sample));
    }
    bootstrapped.sort_by(f64::total_cmp);
    let low_index = RESAMPLES.saturating_mul(25) / 1000;
    let high_index = RESAMPLES
        .saturating_mul(975)
        .div_ceil(1000)
        .saturating_sub(1);
    BootstrapMedianCi {
        median: median(log_ratios.to_vec()).exp(),
        low: bootstrapped[low_index].exp(),
        high: bootstrapped[high_index].exp(),
    }
}

fn print_bench_evidence_metadata() {
    let exe = std::env::current_exe().expect("bench executable");
    let mut file = File::open(&exe).expect("open bench executable for hashing");
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let bytes_read = file.read(&mut buffer).expect("hash bench executable");
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    let worker = Command::new("hostname")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|hostname| !hostname.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    let digest = hasher.finalize();
    let mut sha256 = String::with_capacity(digest.len().saturating_mul(2));
    for byte in digest {
        write!(&mut sha256, "{byte:02x}").expect("format bench executable hash");
    }
    println!("bench_evidence,binary_sha256={sha256},worker={worker}");
}

#[cfg(target_arch = "x86_64")]
fn print_codegen_isa() {
    println!(
        "codegen_isa,target_arch=x86_64,compile_sse2={},compile_sse4_2={},compile_avx2={},compile_fma={},runtime_sse4_2={},runtime_avx2={},runtime_fma={}",
        cfg!(target_feature = "sse2"),
        cfg!(target_feature = "sse4.2"),
        cfg!(target_feature = "avx2"),
        cfg!(target_feature = "fma"),
        std::is_x86_feature_detected!("sse4.2"),
        std::is_x86_feature_detected!("avx2"),
        std::is_x86_feature_detected!("fma"),
    );
}

#[cfg(not(target_arch = "x86_64"))]
fn print_codegen_isa() {
    println!("codegen_isa,target_arch=non_x86_64");
}

fn delete_fixture() -> InMemoryCowBtrfsTree {
    let mut tree = InMemoryCowBtrfsTree::new(64).expect("delete fixture tree");
    let mut payload = vec![0_u8; DELETE_PAYLOAD_BYTES];
    for item_index in 0..DELETE_ITEMS {
        for (byte_index, byte) in payload.iter_mut().enumerate() {
            *byte = u8::try_from((item_index * 17 + byte_index) & 0xff).expect("masked byte");
        }
        tree.insert(
            BtrfsKey {
                objectid: BTRFS_EXTENT_CSUM_OBJECTID,
                item_type: BTRFS_ITEM_EXTENT_CSUM,
                offset: u64::try_from(item_index).expect("item index fits") * 16 * 1024 * 1024,
            },
            &payload,
        )
        .expect("insert checksum item");
    }
    tree
}

#[inline(never)]
fn materialized_delete(mut tree: InMemoryCowBtrfsTree) -> (usize, u64) {
    let lo = BtrfsKey {
        objectid: BTRFS_EXTENT_CSUM_OBJECTID,
        item_type: BTRFS_ITEM_EXTENT_CSUM,
        offset: 0,
    };
    let hi = BtrfsKey {
        objectid: BTRFS_EXTENT_CSUM_OBJECTID,
        item_type: BTRFS_ITEM_EXTENT_CSUM,
        offset: u64::MAX,
    };
    let keys = tree
        .range(&lo, &hi)
        .expect("materialize checksum range")
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    let mut digest = 0_u64;
    for key in &keys {
        digest = digest.rotate_left(7) ^ key.offset;
        tree.delete(key).expect("delete materialized key");
    }
    assert!(
        tree.range(&lo, &hi)
            .expect("scan materialized result")
            .is_empty()
    );
    (keys.len(), digest)
}

#[inline(never)]
fn projected_delete(mut tree: InMemoryCowBtrfsTree) -> (usize, u64) {
    let lo = BtrfsKey {
        objectid: BTRFS_EXTENT_CSUM_OBJECTID,
        item_type: BTRFS_ITEM_EXTENT_CSUM,
        offset: 0,
    };
    let hi = BtrfsKey {
        objectid: BTRFS_EXTENT_CSUM_OBJECTID,
        item_type: BTRFS_ITEM_EXTENT_CSUM,
        offset: u64::MAX,
    };
    let mut keys = Vec::new();
    tree.range_with(&lo, &hi, |key, _| keys.push(key))
        .expect("project checksum keys");
    let mut digest = 0_u64;
    for key in &keys {
        digest = digest.rotate_left(7) ^ key.offset;
        tree.delete(key).expect("delete projected key");
    }
    assert!(
        tree.range(&lo, &hi)
            .expect("scan projected result")
            .is_empty()
    );
    (keys.len(), digest)
}

fn observe_delete(operation: fn(InMemoryCowBtrfsTree) -> (usize, u64)) -> (f64, (usize, u64)) {
    let tree = delete_fixture();
    let started = Instant::now();
    let output = operation(black_box(tree));
    (started.elapsed().as_secs_f64() * 1e9, black_box(output))
}

fn csum_delete_projection_contract() {
    let expected = materialized_delete(delete_fixture());
    assert_eq!(
        projected_delete(delete_fixture()),
        expected,
        "key-only checksum deletion diverged"
    );
    print_bench_evidence_metadata();
    print_codegen_isa();
    println!(
        "csum_delete_mechanism,items={DELETE_ITEMS},payload_bytes_per_item={DELETE_PAYLOAD_BYTES},materialized_payload_bytes={},projected_payload_bytes=0,deleted_keys={}",
        DELETE_ITEMS * DELETE_PAYLOAD_BYTES,
        expected.0,
    );

    let mut control_lhs_ns = Vec::with_capacity(DELETE_PAIRS);
    let mut control_rhs_ns = Vec::with_capacity(DELETE_PAIRS);
    let mut candidate_ns = Vec::with_capacity(DELETE_PAIRS);
    let mut raw_pairs = String::new();
    for pair_index in 0..DELETE_PAIRS {
        let (lhs, rhs, candidate, order) = if pair_index % 2 == 0 {
            let (lhs, lhs_output) = observe_delete(materialized_delete);
            let (rhs, rhs_output) = observe_delete(materialized_delete);
            let (candidate, candidate_output) = observe_delete(projected_delete);
            assert_eq!(lhs_output, expected);
            assert_eq!(rhs_output, expected);
            assert_eq!(candidate_output, expected);
            (lhs, rhs, candidate, "AAB")
        } else {
            let (candidate, candidate_output) = observe_delete(projected_delete);
            let (rhs, rhs_output) = observe_delete(materialized_delete);
            let (lhs, lhs_output) = observe_delete(materialized_delete);
            assert_eq!(candidate_output, expected);
            assert_eq!(rhs_output, expected);
            assert_eq!(lhs_output, expected);
            (lhs, rhs, candidate, "BAA")
        };
        control_lhs_ns.push(lhs);
        control_rhs_ns.push(rhs);
        candidate_ns.push(candidate);
        if pair_index > 0 {
            raw_pairs.push(';');
        }
        write!(&mut raw_pairs, "{order}:{lhs:.3}:{rhs:.3}:{candidate:.3}")
            .expect("format checksum deletion A/A/B pair");
    }

    let null_log_ratios = control_lhs_ns
        .iter()
        .zip(&control_rhs_ns)
        .map(|(lhs, rhs)| (lhs / rhs).ln())
        .collect::<Vec<_>>();
    let speedup_log_ratios = control_lhs_ns
        .iter()
        .zip(&control_rhs_ns)
        .zip(&candidate_ns)
        .map(|((lhs, rhs), candidate)| (lhs.midpoint(*rhs) / candidate).ln())
        .collect::<Vec<_>>();
    let null_summary = bootstrap_median_ci(&null_log_ratios);
    let speedup_summary = bootstrap_median_ci(&speedup_log_ratios);
    let null_log_radius = null_summary
        .low
        .ln()
        .abs()
        .max(null_summary.high.ln().abs());
    let null_floor_ratio = null_log_radius.exp();
    let twice_null_ratio = (2.0 * null_log_radius).exp();
    let admitted = null_floor_ratio <= MAX_NULL_FLOOR_RATIO
        && speedup_summary.low > twice_null_ratio
        && speedup_summary.low > 1.0;
    let verdict = if admitted {
        "KEEP"
    } else if null_floor_ratio > MAX_NULL_FLOOR_RATIO {
        "REJECT_NULL_FLOOR"
    } else {
        "REJECT_BELOW_TWICE_NULL"
    };
    println!(
        "csum_delete_projection_pairs,pairs={DELETE_PAIRS},format=order:control_lhs_ns:control_rhs_ns:candidate_ns,values={raw_pairs}"
    );
    println!(
        "csum_delete_projection_ab,control_aa_median={:.6},control_aa_ci_low={:.6},control_aa_ci_high={:.6},control_aa_null_floor_ratio={null_floor_ratio:.6},maximum_null_floor_ratio={MAX_NULL_FLOOR_RATIO:.6},twice_null_ratio={twice_null_ratio:.6},control_over_candidate_median={:.6},control_over_candidate_ci_low={:.6},control_over_candidate_ci_high={:.6},admitted={admitted},verdict={verdict},gate_metric=wall_ns,gate_basis=bootstrap_median_ci,bootstrap_resamples=20000,cv_used=false",
        null_summary.median,
        null_summary.low,
        null_summary.high,
        speedup_summary.median,
        speedup_summary.low,
        speedup_summary.high,
    );
}

/// Build a sorted-by-offset csum-tree item list: item `i` covers
/// `CSUMS_PER_ITEM` sectors starting at disk bytenr `i * stride`.
fn build_items() -> Vec<(BtrfsKey, Vec<u8>)> {
    let stride = CSUMS_PER_ITEM * SECTORSIZE as u64;
    (0..N as u64)
        .map(|i| {
            let key = BtrfsKey {
                objectid: BTRFS_EXTENT_CSUM_OBJECTID,
                item_type: BTRFS_ITEM_EXTENT_CSUM,
                offset: i * stride,
            };
            // Distinct per-sector crc bytes so divergence would be observable.
            let mut value = vec![0_u8; CSUMS_PER_ITEM as usize * CSUM_SIZE];
            for (s, chunk) in value.chunks_exact_mut(CSUM_SIZE).enumerate() {
                let v = (i.wrapping_mul(131) + s as u64) as u32;
                chunk.copy_from_slice(&v.to_le_bytes());
            }
            (key, value)
        })
        .collect()
}

/// Linear scan (the pre-bd-dgih3 shape): greatest offset `<=` target among
/// EXTENT_CSUM items, then unpack the covering sector's crc32c.
fn linear(items: &[(BtrfsKey, Vec<u8>)], disk_bytenr: u64, sectorsize: usize) -> Option<u32> {
    let mut best: Option<(u64, &[u8])> = None;
    for (key, value) in items {
        if key.item_type != BTRFS_ITEM_EXTENT_CSUM || key.objectid != BTRFS_EXTENT_CSUM_OBJECTID {
            continue;
        }
        if key.offset > disk_bytenr {
            continue;
        }
        if best.is_none_or(|(off, _)| key.offset > off) {
            best = Some((key.offset, value.as_slice()));
        }
    }
    let (item_offset, value) = best?;
    let delta = usize::try_from(disk_bytenr.checked_sub(item_offset)?).ok()?;
    if delta % sectorsize != 0 {
        return None;
    }
    let base = (delta / sectorsize).checked_mul(CSUM_SIZE)?;
    let end = base.checked_add(CSUM_SIZE)?;
    if end > value.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        value[base],
        value[base + 1],
        value[base + 2],
        value[base + 3],
    ]))
}

fn bench_csum_lookup(c: &mut Criterion) {
    if std::env::var_os("FFS_BTRFS_CSUM_DELETE_GATE").is_some() {
        csum_delete_projection_contract();
    }

    let items = build_items();
    let stride = CSUMS_PER_ITEM * SECTORSIZE as u64;
    let max_bytenr = N as u64 * stride;

    // Deterministic spread of sector-aligned probe bytenrs across the range.
    let probes: Vec<u64> = {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        (0..1024)
            .map(|_| {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                ((x >> 11) % max_bytenr) / SECTORSIZE as u64 * SECTORSIZE as u64
            })
            .collect()
    };

    // Isomorphism: the binary-search lookup returns the same crc the linear
    // scan does for every probe.
    for &t in &probes {
        assert_eq!(
            lookup_data_block_csum(&items, t, SECTORSIZE),
            linear(&items, t, SECTORSIZE),
            "disk_bytenr {t} diverged"
        );
    }

    let mut group = c.benchmark_group("btrfs_csum_lookup_4096");
    group.bench_function("delete_projection_contract_marker", |b| {
        b.iter(|| black_box(DELETE_ITEMS * DELETE_PAYLOAD_BYTES));
    });
    group.bench_function("linear_scan", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &t in &probes {
                acc = acc.wrapping_add(u64::from(
                    linear(black_box(&items), t, SECTORSIZE).unwrap_or(0),
                ));
            }
            black_box(acc)
        });
    });
    group.bench_function("binary_search", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &t in &probes {
                acc = acc.wrapping_add(u64::from(
                    lookup_data_block_csum(black_box(&items), t, SECTORSIZE).unwrap_or(0),
                ));
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(csum_lookup, bench_csum_lookup);
criterion_main!(csum_lookup);
