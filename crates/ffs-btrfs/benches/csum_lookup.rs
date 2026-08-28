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
    BTRFS_EXTENT_CSUM_OBJECTID, BTRFS_ITEM_EXTENT_CSUM, BTRFS_ITEM_EXTENT_DATA_REF,
    BTRFS_ITEM_EXTENT_ITEM, BTRFS_ITEM_METADATA_ITEM, BtrfsBTree, BtrfsExtentAllocator,
    BtrfsExtentDataRef, BtrfsExtentItem, BtrfsKey, BtrfsMutationError, InMemoryCowBtrfsTree,
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
const BACKREF_DELETE_COUNT: usize = 512;
const BACKREF_DELETE_BYTENR: u64 = 3 << 30;
const MIN_BACKREF_DELETE_SAVED_FRACTION: f64 = 0.05;
const EXTENT_REFS_ITEMS: usize = 4096;
const EXTENT_REFS_REPEATS: usize = 4;
const EXTENT_REFS_BASE: u64 = 4 << 30;
const EXTENT_REFS_OBSERVATIONS: usize = 3;
const MIN_EXTENT_REFS_SAVED_FRACTION: f64 = 0.05;
const LOCATE_EXTENT_ITEMS: usize = 4096;
const LOCATE_EXTENT_REPEATS: usize = 4;
const LOCATE_EXTENT_BASE: u64 = 5 << 30;
const LOCATE_EXTENT_OBSERVATIONS: usize = 3;
const MIN_LOCATE_EXTENT_SAVED_FRACTION: f64 = 0.05;

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

#[derive(Debug, PartialEq, Eq)]
struct BackrefDeleteOutput {
    deleted: usize,
    deleted_key_digest: u64,
    remaining: Vec<(BtrfsKey, Vec<u8>)>,
}

#[derive(Clone, Copy)]
enum BackrefDeleteArm {
    BorrowedModel,
    RejectedCandidate,
}

fn backref_delete_range() -> (BtrfsKey, BtrfsKey) {
    (
        BtrfsKey {
            objectid: BACKREF_DELETE_BYTENR,
            item_type: BTRFS_ITEM_EXTENT_DATA_REF,
            offset: 0,
        },
        BtrfsKey {
            objectid: BACKREF_DELETE_BYTENR,
            item_type: BTRFS_ITEM_EXTENT_DATA_REF,
            offset: u64::MAX,
        },
    )
}

fn full_tree_range() -> (BtrfsKey, BtrfsKey) {
    (
        BtrfsKey {
            objectid: 0,
            item_type: 0,
            offset: 0,
        },
        BtrfsKey {
            objectid: u64::MAX,
            item_type: u8::MAX,
            offset: u64::MAX,
        },
    )
}

fn backref_delete_fixture() -> BtrfsExtentAllocator {
    let mut alloc = BtrfsExtentAllocator::new(1).expect("backref delete allocator");
    alloc
        .extent_tree_mut()
        .insert(
            BtrfsKey {
                objectid: BACKREF_DELETE_BYTENR - 1,
                item_type: BTRFS_ITEM_EXTENT_DATA_REF,
                offset: u64::MAX,
            },
            b"before",
        )
        .expect("insert before-range sentinel");
    for index in 0..BACKREF_DELETE_COUNT {
        let index = u64::try_from(index).expect("backref index fits in u64");
        let data_ref = BtrfsExtentDataRef {
            root: 5 + index % 4,
            objectid: 256 + index,
            offset: index * 4096,
            count: u32::try_from(index % 3 + 1).expect("backref count fits in u32"),
        };
        alloc
            .extent_tree_mut()
            .insert(
                BtrfsKey {
                    objectid: BACKREF_DELETE_BYTENR,
                    item_type: BTRFS_ITEM_EXTENT_DATA_REF,
                    offset: index,
                },
                &data_ref.to_bytes(),
            )
            .expect("insert keyed backref");
    }
    alloc
        .extent_tree_mut()
        .insert(
            BtrfsKey {
                objectid: BACKREF_DELETE_BYTENR + 1,
                item_type: BTRFS_ITEM_EXTENT_DATA_REF,
                offset: 0,
            },
            b"after",
        )
        .expect("insert after-range sentinel");
    alloc
}

fn backref_key_digest(keys: &[BtrfsKey]) -> u64 {
    keys.iter().fold(0_u64, |digest, key| {
        digest
            .wrapping_mul(1_000_003)
            .wrapping_add(key.objectid)
            .rotate_left(7)
            ^ u64::from(key.item_type)
            ^ key.offset.rotate_right(11)
    })
}

fn remaining_tree(alloc: &BtrfsExtentAllocator) -> Vec<(BtrfsKey, Vec<u8>)> {
    let (lo, hi) = full_tree_range();
    alloc
        .extent_tree()
        .range(&lo, &hi)
        .expect("read remaining extent tree")
}

#[inline(never)]
fn materialized_backref_delete(mut alloc: BtrfsExtentAllocator) -> BackrefDeleteOutput {
    let (lo, hi) = backref_delete_range();
    let keys = alloc
        .extent_tree()
        .range(&lo, &hi)
        .expect("materialize backref range")
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    let deleted_key_digest = backref_key_digest(&keys);
    for key in &keys {
        alloc
            .extent_tree_mut()
            .delete(key)
            .expect("delete materialized backref key");
    }
    BackrefDeleteOutput {
        deleted: keys.len(),
        deleted_key_digest,
        remaining: remaining_tree(&alloc),
    }
}

#[inline(never)]
fn borrowed_backref_delete_model(mut alloc: BtrfsExtentAllocator) -> BackrefDeleteOutput {
    let (lo, hi) = backref_delete_range();
    let mut keys = Vec::new();
    alloc
        .extent_tree()
        .range_with(&lo, &hi, |key, _| keys.push(key))
        .expect("project borrowed backref keys");
    let deleted_key_digest = backref_key_digest(&keys);
    for key in &keys {
        alloc
            .extent_tree_mut()
            .delete(key)
            .expect("delete borrowed backref key");
    }
    BackrefDeleteOutput {
        deleted: keys.len(),
        deleted_key_digest,
        remaining: remaining_tree(&alloc),
    }
}

#[inline(never)]
fn rejected_candidate_backref_delete(mut alloc: BtrfsExtentAllocator) -> BackrefDeleteOutput {
    alloc
        .bench_delete_backrefs_for_extent_borrowed_candidate(BACKREF_DELETE_BYTENR, false)
        .expect("rejected-candidate backref delete");
    let keys = (0..BACKREF_DELETE_COUNT)
        .map(|index| BtrfsKey {
            objectid: BACKREF_DELETE_BYTENR,
            item_type: BTRFS_ITEM_EXTENT_DATA_REF,
            offset: u64::try_from(index).expect("backref index fits in u64"),
        })
        .collect::<Vec<_>>();
    BackrefDeleteOutput {
        deleted: keys.len(),
        deleted_key_digest: backref_key_digest(&keys),
        remaining: remaining_tree(&alloc),
    }
}

fn observe_backref_delete(
    operation: fn(BtrfsExtentAllocator) -> BackrefDeleteOutput,
) -> (f64, BackrefDeleteOutput) {
    let alloc = backref_delete_fixture();
    let started = Instant::now();
    let output = operation(black_box(alloc));
    (started.elapsed().as_secs_f64() * 1e9, black_box(output))
}

type BackrefDeleteOperation = fn(BtrfsExtentAllocator) -> BackrefDeleteOutput;

struct BackrefDeleteSamples {
    control_lhs_ns: Vec<f64>,
    control_rhs_ns: Vec<f64>,
    candidate_ns: Vec<f64>,
    raw_pairs: String,
}

fn collect_backref_delete_samples(
    candidate: BackrefDeleteOperation,
    expected: &BackrefDeleteOutput,
) -> BackrefDeleteSamples {
    let mut control_lhs_ns = Vec::with_capacity(DELETE_PAIRS);
    let mut control_rhs_ns = Vec::with_capacity(DELETE_PAIRS);
    let mut candidate_ns = Vec::with_capacity(DELETE_PAIRS);
    let mut raw_pairs = String::new();
    for pair_index in 0..DELETE_PAIRS {
        let (lhs, rhs, candidate_ns_one, order) = if pair_index % 2 == 0 {
            let (lhs, lhs_output) = observe_backref_delete(materialized_backref_delete);
            let (rhs, rhs_output) = observe_backref_delete(materialized_backref_delete);
            let (candidate_ns_one, candidate_output) = observe_backref_delete(candidate);
            assert_eq!(&lhs_output, expected);
            assert_eq!(&rhs_output, expected);
            assert_eq!(&candidate_output, expected);
            (lhs, rhs, candidate_ns_one, "AAB")
        } else {
            let (candidate_ns_one, candidate_output) = observe_backref_delete(candidate);
            let (rhs, rhs_output) = observe_backref_delete(materialized_backref_delete);
            let (lhs, lhs_output) = observe_backref_delete(materialized_backref_delete);
            assert_eq!(&candidate_output, expected);
            assert_eq!(&rhs_output, expected);
            assert_eq!(&lhs_output, expected);
            (lhs, rhs, candidate_ns_one, "BAA")
        };
        control_lhs_ns.push(lhs);
        control_rhs_ns.push(rhs);
        candidate_ns.push(candidate_ns_one);
        if pair_index > 0 {
            raw_pairs.push(';');
        }
        write!(
            &mut raw_pairs,
            "{order}:{lhs:.3}:{rhs:.3}:{candidate_ns_one:.3}"
        )
        .expect("format backref delete A/A/B pair");
    }
    BackrefDeleteSamples {
        control_lhs_ns,
        control_rhs_ns,
        candidate_ns,
        raw_pairs,
    }
}

fn decide_backref_delete_samples(mode: &str, samples: &BackrefDeleteSamples) {
    let null_log_ratios = samples
        .control_lhs_ns
        .iter()
        .zip(&samples.control_rhs_ns)
        .map(|(lhs, rhs)| (lhs / rhs).ln())
        .collect::<Vec<_>>();
    let speedup_log_ratios = samples
        .control_lhs_ns
        .iter()
        .zip(&samples.control_rhs_ns)
        .zip(&samples.candidate_ns)
        .map(|((lhs, rhs), candidate_ns_one)| (lhs.midpoint(*rhs) / candidate_ns_one).ln())
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
    let saved_fraction_lower = (1.0 - speedup_summary.low.recip()).max(0.0);
    let admitted = null_floor_ratio <= MAX_NULL_FLOOR_RATIO
        && speedup_summary.low > twice_null_ratio
        && saved_fraction_lower >= MIN_BACKREF_DELETE_SAVED_FRACTION;
    let verdict = if admitted {
        "KEEP"
    } else if null_floor_ratio > MAX_NULL_FLOOR_RATIO {
        "REJECT_NULL_FLOOR"
    } else {
        "REJECT_BELOW_TWICE_NULL_OR_FIVE_PERCENT"
    };
    println!(
        "backref_delete_pairs,mode={mode},pairs={DELETE_PAIRS},format=order:control_lhs_ns:control_rhs_ns:candidate_ns,values={}",
        samples.raw_pairs
    );
    println!(
        "backref_delete_ab,mode={mode},control_aa_median={:.6},control_aa_ci_low={:.6},control_aa_ci_high={:.6},control_aa_null_floor_ratio={null_floor_ratio:.6},maximum_null_floor_ratio={MAX_NULL_FLOOR_RATIO:.6},twice_null_ratio={twice_null_ratio:.6},control_over_candidate_median={:.6},control_over_candidate_ci_low={:.6},control_over_candidate_ci_high={:.6},saved_fraction_ci_lower={saved_fraction_lower:.6},minimum_saved_fraction={MIN_BACKREF_DELETE_SAVED_FRACTION:.6},admitted={admitted},verdict={verdict},gate_metric=wall_ns,gate_basis=bootstrap_median_ci,bootstrap_resamples=20000,cv_used=false,instructions_used=false",
        null_summary.median,
        null_summary.low,
        null_summary.high,
        speedup_summary.median,
        speedup_summary.low,
        speedup_summary.high,
    );
    if !admitted {
        std::process::exit(2);
    }
}

fn backref_delete_contract(candidate_arm: BackrefDeleteArm) {
    print_bench_evidence_metadata();
    print_codegen_isa();

    let expected = materialized_backref_delete(backref_delete_fixture());
    assert_eq!(
        borrowed_backref_delete_model(backref_delete_fixture()),
        expected,
        "borrowed backref deletion changed final tree or key order"
    );
    let (candidate, mode): (BackrefDeleteOperation, &'static str) = match candidate_arm {
        BackrefDeleteArm::BorrowedModel => {
            (borrowed_backref_delete_model, "source_neutral_attribution")
        }
        BackrefDeleteArm::RejectedCandidate => {
            let actual = rejected_candidate_backref_delete(backref_delete_fixture());
            assert_eq!(
                actual, expected,
                "rejected-candidate backref deletion changed final tree or key order"
            );
            (
                rejected_candidate_backref_delete,
                "rejected_candidate_replay",
            )
        }
    };

    let fixture = backref_delete_fixture();
    let (lo, hi) = backref_delete_range();
    let materialized = fixture
        .extent_tree()
        .range(&lo, &hi)
        .expect("count materialized backref payloads");
    let materialized_payload_bytes = materialized
        .iter()
        .map(|(_, payload)| payload.len())
        .sum::<usize>();
    assert_eq!(materialized.len(), BACKREF_DELETE_COUNT);
    println!(
        "backref_delete_parity,mode={mode},ordering=extent_tree_key_ascending,tie_breaking=na,floating_point=na,rng=na,deleted_keys={},deleted_key_digest={:016x},remaining_items={}",
        expected.deleted,
        expected.deleted_key_digest,
        expected.remaining.len(),
    );
    println!(
        "backref_delete_mechanism,materialized_payload_vecs={},materialized_payload_bytes={materialized_payload_bytes},borrowed_payload_vecs=0,retained_key_vecs={}",
        materialized.len(),
        expected.deleted,
    );
    let samples = collect_backref_delete_samples(candidate, &expected);
    decide_backref_delete_samples(mode, &samples);
}

type ExtentRefsOperation = fn(&BtrfsExtentAllocator, &[(u64, u64)]) -> u64;

#[derive(Clone, Copy)]
enum ExtentRefsArm {
    BorrowedModel,
    ProductionCandidate,
}

struct ExtentRefsSamples {
    control_lhs_ns: Vec<f64>,
    control_rhs_ns: Vec<f64>,
    candidate_ns: Vec<f64>,
    raw_pairs: String,
}

fn extent_refs_fixture() -> (BtrfsExtentAllocator, Vec<(u64, u64)>) {
    let mut alloc = BtrfsExtentAllocator::new(1).expect("extent refs allocator");
    let mut probes = Vec::with_capacity(EXTENT_REFS_ITEMS);
    for index in 0..EXTENT_REFS_ITEMS {
        let index = u64::try_from(index).expect("extent index fits in u64");
        let bytenr = EXTENT_REFS_BASE + index * 4096;
        let num_bytes = 4096 + (index % 4) * 4096;
        let item = BtrfsExtentItem {
            refs: 1 + index % 7,
            generation: 100 + index,
            flags: BtrfsExtentItem::FLAG_DATA,
        };
        alloc
            .extent_tree_mut()
            .insert(
                BtrfsKey {
                    objectid: bytenr,
                    item_type: BTRFS_ITEM_EXTENT_ITEM,
                    offset: num_bytes,
                },
                &item.to_bytes(),
            )
            .expect("insert extent item");
        probes.push((bytenr, num_bytes));
    }
    (alloc, probes)
}

fn fold_extent_refs(digest: u64, refs: Option<u64>) -> u64 {
    digest
        .rotate_left(9)
        .wrapping_mul(1_000_003)
        .wrapping_add(refs.unwrap_or(u64::MAX))
}

fn materialized_extent_item_refs(
    alloc: &BtrfsExtentAllocator,
    bytenr: u64,
    num_bytes: u64,
) -> Option<u64> {
    let key = BtrfsKey {
        objectid: bytenr,
        item_type: BTRFS_ITEM_EXTENT_ITEM,
        offset: num_bytes,
    };
    alloc
        .extent_tree()
        .range(&key, &key)
        .expect("materialized extent-item lookup")
        .into_iter()
        .next()
        .and_then(|(_, data)| {
            if data.len() >= 8 {
                Some(u64::from_le_bytes(
                    data[0..8].try_into().expect("eight-byte refcount"),
                ))
            } else {
                None
            }
        })
}

fn borrowed_extent_item_refs(
    alloc: &BtrfsExtentAllocator,
    bytenr: u64,
    num_bytes: u64,
) -> Option<u64> {
    let key = BtrfsKey {
        objectid: bytenr,
        item_type: BTRFS_ITEM_EXTENT_ITEM,
        offset: num_bytes,
    };
    let mut refs = None;
    alloc
        .extent_tree()
        .range_with(&key, &key, |_, data| {
            if data.len() >= 8 {
                refs = Some(u64::from_le_bytes(
                    data[0..8].try_into().expect("eight-byte refcount"),
                ));
            }
        })
        .expect("borrowed extent-item lookup");
    refs
}

#[inline(never)]
fn materialized_extent_refs_batch(alloc: &BtrfsExtentAllocator, probes: &[(u64, u64)]) -> u64 {
    let mut digest = 0_u64;
    for _ in 0..EXTENT_REFS_REPEATS {
        for &(bytenr, num_bytes) in probes {
            digest = fold_extent_refs(
                digest,
                materialized_extent_item_refs(alloc, bytenr, num_bytes),
            );
        }
    }
    digest
}

#[inline(never)]
fn borrowed_extent_refs_batch(alloc: &BtrfsExtentAllocator, probes: &[(u64, u64)]) -> u64 {
    let mut digest = 0_u64;
    for _ in 0..EXTENT_REFS_REPEATS {
        for &(bytenr, num_bytes) in probes {
            digest = fold_extent_refs(digest, borrowed_extent_item_refs(alloc, bytenr, num_bytes));
        }
    }
    digest
}

#[inline(never)]
fn production_extent_refs_batch(alloc: &BtrfsExtentAllocator, probes: &[(u64, u64)]) -> u64 {
    let mut digest = 0_u64;
    for _ in 0..EXTENT_REFS_REPEATS {
        for &(bytenr, num_bytes) in probes {
            let refs = alloc
                .extent_item_refs(bytenr, num_bytes)
                .expect("production extent-item lookup");
            digest = fold_extent_refs(digest, refs);
        }
    }
    digest
}

fn extent_refs_oracle() {
    let mut alloc = BtrfsExtentAllocator::new(1).expect("extent refs oracle allocator");
    let valid_bytenr = EXTENT_REFS_BASE;
    let valid_num_bytes = 4096;
    let valid_key = BtrfsKey {
        objectid: valid_bytenr,
        item_type: BTRFS_ITEM_EXTENT_ITEM,
        offset: valid_num_bytes,
    };
    alloc
        .extent_tree_mut()
        .insert(
            valid_key,
            &BtrfsExtentItem {
                refs: 17,
                generation: 9,
                flags: BtrfsExtentItem::FLAG_DATA,
            }
            .to_bytes(),
        )
        .expect("insert valid extent item");
    let short_bytenr = EXTENT_REFS_BASE + 4096;
    let short_key = BtrfsKey {
        objectid: short_bytenr,
        item_type: BTRFS_ITEM_EXTENT_ITEM,
        offset: valid_num_bytes,
    };
    alloc
        .extent_tree_mut()
        .insert(short_key, b"short")
        .expect("insert short extent item");

    for &(bytenr, num_bytes, expected) in &[
        (valid_bytenr, valid_num_bytes, Some(17)),
        (short_bytenr, valid_num_bytes, None),
        (EXTENT_REFS_BASE + 8192, valid_num_bytes, None),
    ] {
        assert_eq!(
            materialized_extent_item_refs(&alloc, bytenr, num_bytes),
            expected
        );
        assert_eq!(
            borrowed_extent_item_refs(&alloc, bytenr, num_bytes),
            expected
        );
        assert_eq!(
            alloc
                .extent_item_refs(bytenr, num_bytes)
                .expect("production oracle lookup"),
            expected
        );
    }
}

fn observe_extent_refs(
    operation: ExtentRefsOperation,
    alloc: &BtrfsExtentAllocator,
    probes: &[(u64, u64)],
    expected: u64,
) -> f64 {
    let mut best_ns = f64::INFINITY;
    for _ in 0..EXTENT_REFS_OBSERVATIONS {
        let started = Instant::now();
        let output = operation(black_box(alloc), black_box(probes));
        let elapsed_ns = started.elapsed().as_secs_f64() * 1e9;
        assert_eq!(black_box(output), expected);
        best_ns = best_ns.min(elapsed_ns);
    }
    best_ns
}

fn collect_extent_refs_samples(
    candidate: ExtentRefsOperation,
    alloc: &BtrfsExtentAllocator,
    probes: &[(u64, u64)],
    expected: u64,
) -> ExtentRefsSamples {
    let mut control_lhs_ns = Vec::with_capacity(DELETE_PAIRS);
    let mut control_rhs_ns = Vec::with_capacity(DELETE_PAIRS);
    let mut candidate_ns = Vec::with_capacity(DELETE_PAIRS);
    let mut raw_pairs = String::new();
    for pair_index in 0..DELETE_PAIRS {
        let (lhs, rhs, candidate_ns_one, order) = if pair_index % 2 == 0 {
            (
                observe_extent_refs(materialized_extent_refs_batch, alloc, probes, expected),
                observe_extent_refs(materialized_extent_refs_batch, alloc, probes, expected),
                observe_extent_refs(candidate, alloc, probes, expected),
                "AAB",
            )
        } else {
            let candidate_ns_one = observe_extent_refs(candidate, alloc, probes, expected);
            let rhs = observe_extent_refs(materialized_extent_refs_batch, alloc, probes, expected);
            let lhs = observe_extent_refs(materialized_extent_refs_batch, alloc, probes, expected);
            (lhs, rhs, candidate_ns_one, "BAA")
        };
        control_lhs_ns.push(lhs);
        control_rhs_ns.push(rhs);
        candidate_ns.push(candidate_ns_one);
        if pair_index > 0 {
            raw_pairs.push(';');
        }
        write!(
            &mut raw_pairs,
            "{order}:{lhs:.3}:{rhs:.3}:{candidate_ns_one:.3}"
        )
        .expect("format extent refs A/A+B pair");
    }
    ExtentRefsSamples {
        control_lhs_ns,
        control_rhs_ns,
        candidate_ns,
        raw_pairs,
    }
}

fn decide_extent_refs_samples(mode: &str, samples: &ExtentRefsSamples) {
    let null_log_ratios = samples
        .control_lhs_ns
        .iter()
        .zip(&samples.control_rhs_ns)
        .map(|(lhs, rhs)| (lhs / rhs).ln())
        .collect::<Vec<_>>();
    let speedup_log_ratios = samples
        .control_lhs_ns
        .iter()
        .zip(&samples.control_rhs_ns)
        .zip(&samples.candidate_ns)
        .map(|((lhs, rhs), candidate_ns_one)| (lhs.midpoint(*rhs) / candidate_ns_one).ln())
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
    let saved_fraction_lower = (1.0 - speedup_summary.low.recip()).max(0.0);
    let admitted = null_floor_ratio <= MAX_NULL_FLOOR_RATIO
        && speedup_summary.low > twice_null_ratio
        && saved_fraction_lower >= MIN_EXTENT_REFS_SAVED_FRACTION;
    let verdict = if admitted {
        "KEEP"
    } else if null_floor_ratio > MAX_NULL_FLOOR_RATIO {
        "REJECT_NULL_FLOOR"
    } else {
        "REJECT_BELOW_TWICE_NULL_OR_FIVE_PERCENT"
    };
    println!(
        "extent_item_refs_pairs,mode={mode},pairs={DELETE_PAIRS},observations_per_arm={EXTENT_REFS_OBSERVATIONS},observation_reducer=min,format=order:control_lhs_ns:control_rhs_ns:candidate_ns,values={}",
        samples.raw_pairs
    );
    println!(
        "extent_item_refs_ab,mode={mode},control_aa_median={:.6},control_aa_ci_low={:.6},control_aa_ci_high={:.6},control_aa_null_floor_ratio={null_floor_ratio:.6},maximum_null_floor_ratio={MAX_NULL_FLOOR_RATIO:.6},twice_null_ratio={twice_null_ratio:.6},control_over_candidate_median={:.6},control_over_candidate_ci_low={:.6},control_over_candidate_ci_high={:.6},saved_fraction_ci_lower={saved_fraction_lower:.6},minimum_saved_fraction={MIN_EXTENT_REFS_SAVED_FRACTION:.6},admitted={admitted},verdict={verdict},gate_metric=wall_ns,gate_basis=bootstrap_median_ci,bootstrap_resamples=20000,cv_used=false,instructions_used=false",
        null_summary.median,
        null_summary.low,
        null_summary.high,
        speedup_summary.median,
        speedup_summary.low,
        speedup_summary.high,
    );
    if !admitted {
        std::process::exit(2);
    }
}

fn extent_item_refs_contract(candidate_arm: ExtentRefsArm) {
    print_bench_evidence_metadata();
    print_codegen_isa();
    extent_refs_oracle();

    let (alloc, probes) = extent_refs_fixture();
    let expected = materialized_extent_refs_batch(&alloc, &probes);
    assert_eq!(
        borrowed_extent_refs_batch(&alloc, &probes),
        expected,
        "borrowed extent refcounts changed values or probe order"
    );
    assert_eq!(
        production_extent_refs_batch(&alloc, &probes),
        expected,
        "production extent refcounts changed values or probe order"
    );
    let (candidate, mode): (ExtentRefsOperation, &'static str) = match candidate_arm {
        ExtentRefsArm::BorrowedModel => (borrowed_extent_refs_batch, "source_neutral_attribution"),
        ExtentRefsArm::ProductionCandidate => {
            (production_extent_refs_batch, "production_candidate")
        }
    };
    let calls = EXTENT_REFS_ITEMS * EXTENT_REFS_REPEATS;
    println!(
        "extent_item_refs_parity,mode={mode},items={EXTENT_REFS_ITEMS},repeats={EXTENT_REFS_REPEATS},calls={calls},digest={expected:016x},ordering=probe_order,tie_breaking=na,floating_point=na,rng=na,valid_short_absent_oracle=pass"
    );
    println!(
        "extent_item_refs_mechanism,mode={mode},materialized_result_vecs={calls},materialized_payload_vecs={calls},materialized_payload_bytes={},borrowed_result_vecs=0,borrowed_payload_vecs=0,borrowed_payload_bytes=0,attribution_scope=complete_public_lookup_batch,attribution_floor_fraction={MIN_EXTENT_REFS_SAVED_FRACTION:.6}",
        calls * 24,
    );
    for _ in 0..3 {
        assert_eq!(materialized_extent_refs_batch(&alloc, &probes), expected);
        assert_eq!(candidate(&alloc, &probes), expected);
    }
    let samples = collect_extent_refs_samples(candidate, &alloc, &probes, expected);
    decide_extent_refs_samples(mode, &samples);
}

type LocateExtentOneOperation =
    fn(&BtrfsExtentAllocator, u64, u64, bool) -> Result<BtrfsKey, BtrfsMutationError>;
type LocateExtentOperation = fn(&BtrfsExtentAllocator, &[LocateExtentProbe]) -> u64;

#[derive(Clone, Copy)]
enum LocateExtentArm {
    BorrowedModel,
    ProductionCandidate,
}

#[derive(Clone, Copy)]
struct LocateExtentProbe {
    bytenr: u64,
    num_bytes: u64,
    is_metadata: bool,
    expected: BtrfsKey,
}

struct LocateExtentSamples {
    control_lhs_ns: Vec<f64>,
    control_rhs_ns: Vec<f64>,
    candidate_ns: Vec<f64>,
    raw_pairs: String,
}

fn locate_extent_fixture() -> (BtrfsExtentAllocator, Vec<LocateExtentProbe>) {
    let mut alloc = BtrfsExtentAllocator::new(1).expect("locate extent allocator");
    let mut probes = Vec::with_capacity(LOCATE_EXTENT_ITEMS);
    for index in 0..LOCATE_EXTENT_ITEMS {
        let index = u64::try_from(index).expect("locate extent index fits in u64");
        let bytenr = LOCATE_EXTENT_BASE + index * 4096;
        let num_bytes = 4096 + (index % 4) * 4096;
        let is_metadata = index % 2 == 0;
        let key = BtrfsKey {
            objectid: bytenr,
            item_type: if is_metadata {
                BTRFS_ITEM_METADATA_ITEM
            } else {
                BTRFS_ITEM_EXTENT_ITEM
            },
            offset: if is_metadata { index % 8 } else { num_bytes },
        };
        let item = BtrfsExtentItem {
            refs: 1 + index % 7,
            generation: 100 + index,
            flags: if is_metadata {
                BtrfsExtentItem::FLAG_TREE_BLOCK
            } else {
                BtrfsExtentItem::FLAG_DATA
            },
        };
        alloc
            .extent_tree_mut()
            .insert(key, &item.to_bytes())
            .expect("insert locate extent item");
        probes.push(LocateExtentProbe {
            bytenr,
            num_bytes,
            is_metadata,
            expected: key,
        });
    }
    (alloc, probes)
}

fn materialized_locate_extent_key(
    alloc: &BtrfsExtentAllocator,
    bytenr: u64,
    num_bytes: u64,
    is_metadata: bool,
) -> Result<BtrfsKey, BtrfsMutationError> {
    let item_type = if is_metadata {
        BTRFS_ITEM_METADATA_ITEM
    } else {
        BTRFS_ITEM_EXTENT_ITEM
    };
    if is_metadata {
        let lo = BtrfsKey {
            objectid: bytenr,
            item_type,
            offset: 0,
        };
        let hi = BtrfsKey {
            objectid: bytenr,
            item_type,
            offset: u64::MAX,
        };
        alloc
            .extent_tree()
            .range(&lo, &hi)?
            .into_iter()
            .next()
            .map(|(key, _)| key)
            .ok_or(BtrfsMutationError::KeyNotFound)
    } else {
        let key = BtrfsKey {
            objectid: bytenr,
            item_type,
            offset: num_bytes,
        };
        if alloc.extent_tree().range(&key, &key)?.is_empty() {
            Err(BtrfsMutationError::KeyNotFound)
        } else {
            Ok(key)
        }
    }
}

fn borrowed_locate_extent_key(
    alloc: &BtrfsExtentAllocator,
    bytenr: u64,
    num_bytes: u64,
    is_metadata: bool,
) -> Result<BtrfsKey, BtrfsMutationError> {
    let item_type = if is_metadata {
        BTRFS_ITEM_METADATA_ITEM
    } else {
        BTRFS_ITEM_EXTENT_ITEM
    };
    let lo = BtrfsKey {
        objectid: bytenr,
        item_type,
        offset: if is_metadata { 0 } else { num_bytes },
    };
    let hi = BtrfsKey {
        objectid: bytenr,
        item_type,
        offset: if is_metadata { u64::MAX } else { num_bytes },
    };
    let mut found = None;
    alloc.extent_tree().range_with(&lo, &hi, |key, _| {
        if found.is_none() {
            found = Some(key);
        }
    })?;
    found.ok_or(BtrfsMutationError::KeyNotFound)
}

fn production_locate_extent_key(
    alloc: &BtrfsExtentAllocator,
    bytenr: u64,
    num_bytes: u64,
    is_metadata: bool,
) -> Result<BtrfsKey, BtrfsMutationError> {
    alloc.bench_locate_extent_key(bytenr, num_bytes, is_metadata)
}

fn fold_located_extent_key(digest: u64, key: BtrfsKey) -> u64 {
    digest
        .rotate_left(9)
        .wrapping_mul(1_000_003)
        .wrapping_add(key.objectid)
        .rotate_left(7)
        .wrapping_add(u64::from(key.item_type))
        .rotate_left(5)
        .wrapping_add(key.offset)
}

#[inline(never)]
fn materialized_locate_extent_batch(
    alloc: &BtrfsExtentAllocator,
    probes: &[LocateExtentProbe],
) -> u64 {
    locate_extent_batch(materialized_locate_extent_key, alloc, probes)
}

#[inline(never)]
fn borrowed_locate_extent_batch(alloc: &BtrfsExtentAllocator, probes: &[LocateExtentProbe]) -> u64 {
    locate_extent_batch(borrowed_locate_extent_key, alloc, probes)
}

#[inline(never)]
fn production_locate_extent_batch(
    alloc: &BtrfsExtentAllocator,
    probes: &[LocateExtentProbe],
) -> u64 {
    locate_extent_batch(production_locate_extent_key, alloc, probes)
}

fn locate_extent_batch(
    operation: LocateExtentOneOperation,
    alloc: &BtrfsExtentAllocator,
    probes: &[LocateExtentProbe],
) -> u64 {
    let mut digest = 0_u64;
    for _ in 0..LOCATE_EXTENT_REPEATS {
        for probe in probes {
            let key = operation(alloc, probe.bytenr, probe.num_bytes, probe.is_metadata)
                .expect("locate existing extent key");
            assert_eq!(key, probe.expected);
            digest = fold_located_extent_key(digest, key);
        }
    }
    digest
}

fn locate_extent_oracle() {
    let mut alloc = BtrfsExtentAllocator::new(1).expect("locate extent oracle allocator");
    let payload = BtrfsExtentItem {
        refs: 1,
        generation: 9,
        flags: BtrfsExtentItem::FLAG_TREE_BLOCK,
    }
    .to_bytes();
    let metadata_bytenr = LOCATE_EXTENT_BASE;
    let first_metadata_key = BtrfsKey {
        objectid: metadata_bytenr,
        item_type: BTRFS_ITEM_METADATA_ITEM,
        offset: 1,
    };
    let later_metadata_key = BtrfsKey {
        offset: 3,
        ..first_metadata_key
    };
    alloc
        .extent_tree_mut()
        .insert(first_metadata_key, &payload)
        .expect("insert first metadata key");
    alloc
        .extent_tree_mut()
        .insert(later_metadata_key, &payload)
        .expect("insert later metadata key");

    let data_key = BtrfsKey {
        objectid: LOCATE_EXTENT_BASE + 4096,
        item_type: BTRFS_ITEM_EXTENT_ITEM,
        offset: 8192,
    };
    alloc
        .extent_tree_mut()
        .insert(data_key, &payload)
        .expect("insert data key");

    for operation in [
        materialized_locate_extent_key as LocateExtentOneOperation,
        borrowed_locate_extent_key,
        production_locate_extent_key,
    ] {
        assert_eq!(
            operation(&alloc, metadata_bytenr, 4096, true),
            Ok(first_metadata_key)
        );
        assert_eq!(
            operation(&alloc, data_key.objectid, data_key.offset, false),
            Ok(data_key)
        );
        assert_eq!(
            operation(&alloc, data_key.objectid, 4096, false),
            Err(BtrfsMutationError::KeyNotFound)
        );
        assert_eq!(
            operation(&alloc, LOCATE_EXTENT_BASE + 8192, 4096, true),
            Err(BtrfsMutationError::KeyNotFound)
        );
    }
}

fn observe_locate_extent(
    operation: LocateExtentOperation,
    alloc: &BtrfsExtentAllocator,
    probes: &[LocateExtentProbe],
    expected: u64,
) -> f64 {
    let mut best_ns = f64::INFINITY;
    for _ in 0..LOCATE_EXTENT_OBSERVATIONS {
        let started = Instant::now();
        let output = operation(black_box(alloc), black_box(probes));
        let elapsed_ns = started.elapsed().as_secs_f64() * 1e9;
        assert_eq!(black_box(output), expected);
        best_ns = best_ns.min(elapsed_ns);
    }
    best_ns
}

fn collect_locate_extent_samples(
    candidate: LocateExtentOperation,
    alloc: &BtrfsExtentAllocator,
    probes: &[LocateExtentProbe],
    expected: u64,
) -> LocateExtentSamples {
    let mut control_lhs_ns = Vec::with_capacity(DELETE_PAIRS);
    let mut control_rhs_ns = Vec::with_capacity(DELETE_PAIRS);
    let mut candidate_ns = Vec::with_capacity(DELETE_PAIRS);
    let mut raw_pairs = String::new();
    for pair_index in 0..DELETE_PAIRS {
        let (lhs, rhs, candidate_ns_one, order) = if pair_index % 2 == 0 {
            (
                observe_locate_extent(materialized_locate_extent_batch, alloc, probes, expected),
                observe_locate_extent(materialized_locate_extent_batch, alloc, probes, expected),
                observe_locate_extent(candidate, alloc, probes, expected),
                "AAB",
            )
        } else {
            let candidate_ns_one = observe_locate_extent(candidate, alloc, probes, expected);
            let rhs =
                observe_locate_extent(materialized_locate_extent_batch, alloc, probes, expected);
            let lhs =
                observe_locate_extent(materialized_locate_extent_batch, alloc, probes, expected);
            (lhs, rhs, candidate_ns_one, "BAA")
        };
        control_lhs_ns.push(lhs);
        control_rhs_ns.push(rhs);
        candidate_ns.push(candidate_ns_one);
        if pair_index > 0 {
            raw_pairs.push(';');
        }
        write!(
            &mut raw_pairs,
            "{order}:{lhs:.3}:{rhs:.3}:{candidate_ns_one:.3}"
        )
        .expect("format locate extent A/A+B pair");
    }
    LocateExtentSamples {
        control_lhs_ns,
        control_rhs_ns,
        candidate_ns,
        raw_pairs,
    }
}

fn decide_locate_extent_samples(mode: &str, samples: &LocateExtentSamples) {
    let null_log_ratios = samples
        .control_lhs_ns
        .iter()
        .zip(&samples.control_rhs_ns)
        .map(|(lhs, rhs)| (lhs / rhs).ln())
        .collect::<Vec<_>>();
    let speedup_log_ratios = samples
        .control_lhs_ns
        .iter()
        .zip(&samples.control_rhs_ns)
        .zip(&samples.candidate_ns)
        .map(|((lhs, rhs), candidate_ns_one)| (lhs.midpoint(*rhs) / candidate_ns_one).ln())
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
    let saved_fraction_lower = (1.0 - speedup_summary.low.recip()).max(0.0);
    let admitted = null_floor_ratio <= MAX_NULL_FLOOR_RATIO
        && speedup_summary.low > twice_null_ratio
        && saved_fraction_lower >= MIN_LOCATE_EXTENT_SAVED_FRACTION;
    let verdict = if admitted {
        "KEEP"
    } else if null_floor_ratio > MAX_NULL_FLOOR_RATIO {
        "REJECT_NULL_FLOOR"
    } else {
        "REJECT_BELOW_TWICE_NULL_OR_FIVE_PERCENT"
    };
    println!(
        "locate_extent_key_pairs,mode={mode},pairs={DELETE_PAIRS},observations_per_arm={LOCATE_EXTENT_OBSERVATIONS},observation_reducer=min,format=order:control_lhs_ns:control_rhs_ns:candidate_ns,values={}",
        samples.raw_pairs
    );
    println!(
        "locate_extent_key_ab,mode={mode},control_aa_median={:.6},control_aa_ci_low={:.6},control_aa_ci_high={:.6},control_aa_null_floor_ratio={null_floor_ratio:.6},maximum_null_floor_ratio={MAX_NULL_FLOOR_RATIO:.6},twice_null_ratio={twice_null_ratio:.6},control_over_candidate_median={:.6},control_over_candidate_ci_low={:.6},control_over_candidate_ci_high={:.6},saved_fraction_ci_lower={saved_fraction_lower:.6},minimum_saved_fraction={MIN_LOCATE_EXTENT_SAVED_FRACTION:.6},admitted={admitted},verdict={verdict},gate_metric=wall_ns,gate_basis=bootstrap_median_ci,bootstrap_resamples=20000,cv_used=false,instructions_used=false",
        null_summary.median,
        null_summary.low,
        null_summary.high,
        speedup_summary.median,
        speedup_summary.low,
        speedup_summary.high,
    );
    if !admitted {
        std::process::exit(2);
    }
}

fn locate_extent_key_contract(candidate_arm: LocateExtentArm) {
    print_bench_evidence_metadata();
    print_codegen_isa();
    locate_extent_oracle();

    let (alloc, probes) = locate_extent_fixture();
    let expected = materialized_locate_extent_batch(&alloc, &probes);
    assert_eq!(
        borrowed_locate_extent_batch(&alloc, &probes),
        expected,
        "borrowed extent-key location changed keys or probe order"
    );
    assert_eq!(
        production_locate_extent_batch(&alloc, &probes),
        expected,
        "production extent-key location changed keys or probe order"
    );
    let (candidate, mode): (LocateExtentOperation, &'static str) = match candidate_arm {
        LocateExtentArm::BorrowedModel => {
            (borrowed_locate_extent_batch, "source_neutral_attribution")
        }
        LocateExtentArm::ProductionCandidate => {
            (production_locate_extent_batch, "production_candidate")
        }
    };
    let calls = LOCATE_EXTENT_ITEMS * LOCATE_EXTENT_REPEATS;
    let payload_len = BtrfsExtentItem {
        refs: 1,
        generation: 1,
        flags: BtrfsExtentItem::FLAG_DATA,
    }
    .to_bytes()
    .len();
    println!(
        "locate_extent_key_parity,mode={mode},items={LOCATE_EXTENT_ITEMS},data_items={},metadata_items={},repeats={LOCATE_EXTENT_REPEATS},calls={calls},digest={expected:016x},ordering=probe_order_and_first_metadata_key,tie_breaking=first_ascending_metadata_key,floating_point=na,rng=na,data_metadata_absent_oracle=pass",
        LOCATE_EXTENT_ITEMS / 2,
        LOCATE_EXTENT_ITEMS / 2,
    );
    println!(
        "locate_extent_key_mechanism,mode={mode},materialized_result_vecs={calls},materialized_payload_vecs={calls},materialized_payload_bytes={},borrowed_result_vecs=0,borrowed_payload_vecs=0,borrowed_payload_bytes=0,attribution_scope=complete_location_lookup_batch,attribution_floor_fraction={MIN_LOCATE_EXTENT_SAVED_FRACTION:.6}",
        calls * payload_len,
    );
    for _ in 0..3 {
        assert_eq!(materialized_locate_extent_batch(&alloc, &probes), expected);
        assert_eq!(candidate(&alloc, &probes), expected);
    }
    let samples = collect_locate_extent_samples(candidate, &alloc, &probes, expected);
    decide_locate_extent_samples(mode, &samples);
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
fn linear(items: &[(BtrfsKey, Vec<u8>)], disk_bytenr: u64, sectorsize: usize) -> Option<&[u8]> {
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
    Some(&value[base..end])
}

/// Fold a checksum into the accumulator so the benched result cannot be
/// optimized away. Width-agnostic, because the digest width now follows
/// `csum_type` rather than being a fixed `u32`.
fn fold_csum(acc: u64, csum: Option<&[u8]>) -> u64 {
    csum.unwrap_or(&[])
        .iter()
        .fold(acc, |a, &b| a.wrapping_mul(31).wrapping_add(u64::from(b)))
}

fn bench_csum_lookup(c: &mut Criterion) {
    if let Some(mode) = std::env::var_os("FFS_BTRFS_LOCATE_EXTENT_KEY_GATE") {
        match mode.to_str() {
            Some("source-neutral") => locate_extent_key_contract(LocateExtentArm::BorrowedModel),
            Some("candidate") => locate_extent_key_contract(LocateExtentArm::ProductionCandidate),
            _ => {
                panic!("FFS_BTRFS_LOCATE_EXTENT_KEY_GATE must be source-neutral or candidate")
            }
        }
        return;
    }
    if let Some(mode) = std::env::var_os("FFS_BTRFS_EXTENT_ITEM_REFS_GATE") {
        match mode.to_str() {
            Some("source-neutral") => extent_item_refs_contract(ExtentRefsArm::BorrowedModel),
            Some("candidate") => extent_item_refs_contract(ExtentRefsArm::ProductionCandidate),
            _ => {
                panic!("FFS_BTRFS_EXTENT_ITEM_REFS_GATE must be source-neutral or candidate")
            }
        }
        return;
    }
    if let Some(mode) = std::env::var_os("FFS_BTRFS_BACKREF_DELETE_GATE") {
        match mode.to_str() {
            Some("source-neutral") => backref_delete_contract(BackrefDeleteArm::BorrowedModel),
            Some("candidate") => backref_delete_contract(BackrefDeleteArm::RejectedCandidate),
            _ => {
                panic!("FFS_BTRFS_BACKREF_DELETE_GATE must be source-neutral or candidate")
            }
        }
        return;
    }
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
            lookup_data_block_csum(&items, t, SECTORSIZE, CSUM_SIZE),
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
                acc = fold_csum(acc, linear(black_box(&items), t, SECTORSIZE));
            }
            black_box(acc)
        });
    });
    group.bench_function("binary_search", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &t in &probes {
                acc = fold_csum(
                    acc,
                    lookup_data_block_csum(black_box(&items), t, SECTORSIZE, CSUM_SIZE),
                );
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(csum_lookup, bench_csum_lookup);
criterion_main!(csum_lookup);
