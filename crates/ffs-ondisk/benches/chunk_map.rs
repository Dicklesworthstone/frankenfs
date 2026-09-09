#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the btrfs chunk-map lookup (bd-6u6xb).
//!
//! `map_logical_to_physical` finds the chunk covering a logical address. Chunks
//! cover disjoint logical ranges and the full list is sorted ascending by
//! `key.offset`, so the covering chunk is the last one whose start is `<=` the
//! target. The old code scanned every chunk (O(N)); the new code binary-searches
//! large lists (O(log N)). A large btrfs filesystem has hundreds–thousands of
//! chunks, and this runs on every logical->physical mapping (every tree-node and
//! data-block read).

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ffs_ondisk::btrfs::bench_parse_sys_chunk_array;
use ffs_ondisk::{
    BtrfsChunkEntry, BtrfsKey, BtrfsPhysicalMapping, BtrfsRaidProfile, BtrfsStripe,
    map_logical_to_physical, map_logical_to_stripes, parse_sys_chunk_array,
};
use smallvec::SmallVec;
use std::hint::black_box;

const N: u64 = 1000; // a multi-TB filesystem's chunk count
const CHUNK_LEN: u64 = 1 << 30; // 1 GiB data chunks

fn build_chunks() -> Vec<BtrfsChunkEntry> {
    (0..N)
        .map(|i| {
            let logical = i * CHUNK_LEN;
            BtrfsChunkEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: 228, // CHUNK_ITEM
                    offset: logical,
                },
                length: CHUNK_LEN,
                owner: 2,
                stripe_len: 0x1_0000,
                chunk_type: 1, // BTRFS_BLOCK_GROUP_DATA -> Single profile
                io_align: 4096,
                io_width: 4096,
                sector_size: 4096,
                num_stripes: 1,
                sub_stripes: 0,
                stripes: vec![BtrfsStripe {
                    devid: 1,
                    offset: 0x10_0000 + i * CHUNK_LEN,
                    dev_uuid: [0_u8; 16],
                }],
            }
        })
        .collect()
}

/// Linear scan (the pre-bd-6u6xb shape): first chunk covering `logical`.
fn linear(chunks: &[BtrfsChunkEntry], logical: u64) -> Option<u64> {
    for c in chunks {
        if logical >= c.key.offset && logical < c.key.offset + c.length {
            return Some(c.stripes[0].offset + (logical - c.key.offset));
        }
    }
    None
}

/// Linear scan over the *stripe* resolver (the pre-bd-6tygu shape): first chunk
/// covering `logical`, returning its first readable stripe's physical offset.
fn linear_stripes(chunks: &[BtrfsChunkEntry], logical: u64) -> Option<u64> {
    for c in chunks {
        if logical >= c.key.offset && logical < c.key.offset + c.length {
            let m = map_logical_to_stripes(std::slice::from_ref(c), logical)
                .unwrap()
                .unwrap();
            return Some(m.stripes[0].physical);
        }
    }
    None
}

fn bench_chunk_map(c: &mut Criterion) {
    let chunks = build_chunks();
    let max_logical = N * CHUNK_LEN;

    // Deterministic spread of probe addresses across the whole logical range.
    let probes: Vec<u64> = {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        (0..1024)
            .map(|_| {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                (x >> 11) % max_logical
            })
            .collect()
    };

    // Isomorphism: the binary-search map returns the same physical address the
    // linear scan does for every probe.
    for &t in &probes {
        let mapped = map_logical_to_physical(&chunks, t)
            .unwrap()
            .map(|m| m.physical);
        assert_eq!(mapped, linear(&chunks, t), "logical {t} diverged");
    }

    let mut group = c.benchmark_group("btrfs_chunk_map_1000");
    group.bench_function("linear_scan", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &t in &probes {
                acc = acc.wrapping_add(linear(black_box(&chunks), t).unwrap_or(0));
            }
            black_box(acc)
        });
    });
    group.bench_function("binary_search", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &t in &probes {
                acc = acc.wrapping_add(
                    map_logical_to_physical(black_box(&chunks), t)
                        .unwrap()
                        .map_or(0, |m| m.physical),
                );
            }
            black_box(acc)
        });
    });
    group.finish();
}

fn bench_stripe_map(c: &mut Criterion) {
    let chunks = build_chunks();
    let max_logical = N * CHUNK_LEN;

    let probes: Vec<u64> = {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        (0..1024)
            .map(|_| {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                (x >> 11) % max_logical
            })
            .collect()
    };

    // Isomorphism: the binary-search stripe map returns the same physical
    // address the linear scan does for every probe.
    for &t in &probes {
        let mapped = map_logical_to_stripes(&chunks, t)
            .unwrap()
            .map(|m| m.stripes[0].physical);
        assert_eq!(mapped, linear_stripes(&chunks, t), "logical {t} diverged");
    }

    let mut group = c.benchmark_group("btrfs_stripe_map_1000");
    group.bench_function("linear_scan", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &t in &probes {
                acc = acc.wrapping_add(linear_stripes(black_box(&chunks), t).unwrap_or(0));
            }
            black_box(acc)
        });
    });
    group.bench_function("binary_search", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &t in &probes {
                acc = acc.wrapping_add(
                    map_logical_to_stripes(black_box(&chunks), t)
                        .unwrap()
                        .map_or(0, |m| m.stripes[0].physical),
                );
            }
            black_box(acc)
        });
    });
    group.finish();
}

#[derive(Clone, Copy)]
// Historical comparison of two non-parity rank selectors. Neither implements
// Linux RAID56's ordered data rotation; these timings do not measure the
// production mapper or establish filesystem correctness (bd-hk5w3).
struct Raid56PositionProbe {
    num_stripes: u64,
    parity_count: u64,
    p_pos: u64,
    q_pos: u64,
    data_index: u64,
}

#[inline(never)]
fn raid56_data_position_linear(probe: Raid56PositionProbe) -> u64 {
    let mut data_seen = 0_u64;
    for pos in 0..probe.num_stripes {
        if pos == probe.p_pos || (probe.parity_count == 2 && pos == probe.q_pos) {
            continue;
        }
        if data_seen == probe.data_index {
            return pos;
        }
        data_seen += 1;
    }
    u64::MAX
}

#[inline(never)]
fn raid56_data_position_bounded(probe: Raid56PositionProbe) -> u64 {
    if probe.parity_count == 1 {
        return if probe.data_index < probe.p_pos {
            probe.data_index
        } else {
            probe.data_index + 1
        };
    }

    let first_parity = probe.p_pos.min(probe.q_pos);
    let second_parity = probe.p_pos.max(probe.q_pos);
    let after_first = if probe.data_index < first_parity {
        probe.data_index
    } else {
        probe.data_index + 1
    };
    if after_first < second_parity {
        after_first
    } else {
        after_first + 1
    }
}

fn fold_raid56_positions(
    probes: &[Raid56PositionProbe],
    select: fn(Raid56PositionProbe) -> u64,
) -> u64 {
    probes.iter().copied().fold(0_u64, |digest, probe| {
        digest.rotate_left(7) ^ select(probe).wrapping_mul(0x9E37_79B1_85EB_CA87)
    })
}

fn raid56_position_probes(num_stripes: u64, parity_count: u64) -> Vec<Raid56PositionProbe> {
    let data_stripes = num_stripes - parity_count;
    let mut probes = Vec::with_capacity((num_stripes * data_stripes) as usize);
    for stripe_nr in 0..num_stripes {
        let rot = stripe_nr % num_stripes;
        let p_pos = (num_stripes - 1).saturating_sub(rot) % num_stripes;
        let q_pos = (num_stripes.saturating_sub(2) + num_stripes - rot) % num_stripes;
        for data_index in 0..data_stripes {
            probes.push(Raid56PositionProbe {
                num_stripes,
                parity_count,
                p_pos,
                q_pos,
                data_index,
            });
        }
    }
    probes
}

fn bench_raid56_data_position(c: &mut Criterion) {
    for num_stripes in 3..=64 {
        for parity_count in 1..=2 {
            if num_stripes < parity_count + 2 {
                continue;
            }
            for probe in raid56_position_probes(num_stripes, parity_count) {
                assert_eq!(
                    raid56_data_position_linear(probe),
                    raid56_data_position_bounded(probe),
                    "num_stripes={num_stripes} parity_count={parity_count}",
                );
            }
        }
    }

    let probes = raid56_position_probes(16, 2);
    assert_eq!(
        fold_raid56_positions(&probes, raid56_data_position_linear),
        fold_raid56_positions(&probes, raid56_data_position_bounded),
    );

    let mut group = c.benchmark_group("btrfs_raid56_data_position_16");
    group.bench_function("linear_control_a", |b| {
        b.iter(|| {
            black_box(fold_raid56_positions(
                black_box(&probes),
                raid56_data_position_linear,
            ))
        });
    });
    group.bench_function("linear_control_b", |b| {
        b.iter(|| {
            black_box(fold_raid56_positions(
                black_box(&probes),
                raid56_data_position_linear,
            ))
        });
    });
    group.bench_function("bounded_candidate", |b| {
        b.iter(|| {
            black_box(fold_raid56_positions(
                black_box(&probes),
                raid56_data_position_bounded,
            ))
        });
    });
    group.finish();
}

const STRIPE_RESULT_BATCH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
struct FrozenVecStripeMapping {
    profile: BtrfsRaidProfile,
    stripes: Vec<BtrfsPhysicalMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InlineStripeMapping {
    profile: BtrfsRaidProfile,
    stripes: SmallVec<[BtrfsPhysicalMapping; 4]>,
}

#[inline(never)]
fn frozen_vec_stripe_mapping(
    profile: BtrfsRaidProfile,
    stripes: &[BtrfsPhysicalMapping],
) -> FrozenVecStripeMapping {
    FrozenVecStripeMapping {
        profile,
        stripes: stripes.to_vec(),
    }
}

#[inline(never)]
fn inline_stripe_mapping(
    profile: BtrfsRaidProfile,
    stripes: &[BtrfsPhysicalMapping],
) -> InlineStripeMapping {
    InlineStripeMapping {
        profile,
        stripes: SmallVec::from_slice(stripes),
    }
}

const fn profile_tag(profile: BtrfsRaidProfile) -> u64 {
    match profile {
        BtrfsRaidProfile::Single => 1,
        BtrfsRaidProfile::Dup => 2,
        BtrfsRaidProfile::Raid0 => 3,
        BtrfsRaidProfile::Raid1 => 4,
        BtrfsRaidProfile::Raid1C3 => 5,
        BtrfsRaidProfile::Raid1C4 => 6,
        BtrfsRaidProfile::Raid10 => 7,
        BtrfsRaidProfile::Raid5 => 8,
        BtrfsRaidProfile::Raid6 => 9,
    }
}

fn fold_stripe_result(profile: BtrfsRaidProfile, stripes: &[BtrfsPhysicalMapping]) -> u64 {
    stripes.iter().fold(profile_tag(profile), |digest, stripe| {
        digest.rotate_left(7) ^ stripe.devid.wrapping_mul(17) ^ stripe.physical
    })
}

fn fold_frozen_vec_batch(
    stripes: &[BtrfsPhysicalMapping; 6],
    shapes: &[(BtrfsRaidProfile, usize)],
) -> u64 {
    (0..STRIPE_RESULT_BATCH).fold(0_u64, |digest, index| {
        let (profile, count) = shapes[index % shapes.len()];
        let result = frozen_vec_stripe_mapping(profile, &stripes[..count]);
        digest.rotate_left(3) ^ fold_stripe_result(result.profile, &result.stripes)
    })
}

fn fold_inline_batch(
    stripes: &[BtrfsPhysicalMapping; 6],
    shapes: &[(BtrfsRaidProfile, usize)],
) -> u64 {
    (0..STRIPE_RESULT_BATCH).fold(0_u64, |digest, index| {
        let (profile, count) = shapes[index % shapes.len()];
        let result = inline_stripe_mapping(profile, &stripes[..count]);
        digest.rotate_left(3) ^ fold_stripe_result(result.profile, &result.stripes)
    })
}

fn bench_stripe_result_storage(c: &mut Criterion) {
    let stripes = std::array::from_fn(|index| BtrfsPhysicalMapping {
        devid: index as u64 + 1,
        physical: 0x10_0000 + (index as u64 * 0x20_0000),
    });
    let shapes = [
        (BtrfsRaidProfile::Single, 1),
        (BtrfsRaidProfile::Dup, 2),
        (BtrfsRaidProfile::Raid0, 1),
        (BtrfsRaidProfile::Raid1, 2),
        (BtrfsRaidProfile::Raid1C3, 3),
        (BtrfsRaidProfile::Raid1C4, 4),
        (BtrfsRaidProfile::Raid10, 2),
        (BtrfsRaidProfile::Raid5, 1),
        (BtrfsRaidProfile::Raid6, 1),
    ];

    for &(profile, count) in &shapes {
        let control = frozen_vec_stripe_mapping(profile, &stripes[..count]);
        let candidate = inline_stripe_mapping(profile, &stripes[..count]);
        assert_eq!(control.profile, candidate.profile);
        assert_eq!(control.stripes.as_slice(), candidate.stripes.as_slice());
        assert!(!candidate.stripes.spilled());
    }

    let spill_control = frozen_vec_stripe_mapping(BtrfsRaidProfile::Raid1, &stripes);
    let spill_candidate = inline_stripe_mapping(BtrfsRaidProfile::Raid1, &stripes);
    assert_eq!(spill_control.profile, spill_candidate.profile);
    assert_eq!(
        spill_control.stripes.as_slice(),
        spill_candidate.stripes.as_slice()
    );
    assert!(spill_candidate.stripes.spilled());
    assert_eq!(
        fold_frozen_vec_batch(&stripes, &shapes),
        fold_inline_batch(&stripes, &shapes)
    );

    let mut group = c.benchmark_group("btrfs_stripe_result_storage_256");
    group.sample_size(10);
    group.throughput(Throughput::Elements(STRIPE_RESULT_BATCH as u64));
    group.bench_function("vec_control_a", |b| {
        b.iter(|| {
            black_box(fold_frozen_vec_batch(
                black_box(&stripes),
                black_box(&shapes),
            ))
        });
    });
    group.bench_function("smallvec_candidate", |b| {
        b.iter(|| black_box(fold_inline_batch(black_box(&stripes), black_box(&shapes))));
    });
    group.bench_function("vec_control_b", |b| {
        b.iter(|| {
            black_box(fold_frozen_vec_batch(
                black_box(&stripes),
                black_box(&shapes),
            ))
        });
    });
    group.finish();
}

fn build_sys_chunk_array(entry_count: u64) -> Vec<u8> {
    const DISK_KEY_SIZE: usize = 17;
    const CHUNK_FIXED_SIZE: usize = 48;
    const STRIPE_SIZE: usize = 32;

    let mut data = Vec::with_capacity(
        usize::try_from(entry_count).expect("entry count fits usize")
            * (DISK_KEY_SIZE + CHUNK_FIXED_SIZE + STRIPE_SIZE),
    );
    for index in 0..entry_count {
        data.extend_from_slice(&256_u64.to_le_bytes());
        data.push(228);
        data.extend_from_slice(&(index << 30).to_le_bytes());

        data.extend_from_slice(&(1_u64 << 30).to_le_bytes());
        data.extend_from_slice(&2_u64.to_le_bytes());
        data.extend_from_slice(&(1_u64 << 16).to_le_bytes());
        data.extend_from_slice(&1_u64.to_le_bytes());
        data.extend_from_slice(&4096_u32.to_le_bytes());
        data.extend_from_slice(&4096_u32.to_le_bytes());
        data.extend_from_slice(&4096_u32.to_le_bytes());
        data.extend_from_slice(&1_u16.to_le_bytes());
        data.extend_from_slice(&0_u16.to_le_bytes());

        data.extend_from_slice(&(index + 1).to_le_bytes());
        data.extend_from_slice(&(0x10_0000 + (index << 30)).to_le_bytes());
        data.extend_from_slice(&[index as u8; 16]);
    }
    data
}

fn bench_sys_chunk_parse_profile(c: &mut Criterion) {
    let data = build_sys_chunk_array(16);
    assert_eq!(
        parse_sys_chunk_array(&data)
            .expect("valid sys chunk array")
            .len(),
        16,
    );

    c.bench_function("btrfs_sys_chunk_parse_profile/current_vec_new_16", |b| {
        b.iter(|| black_box(parse_sys_chunk_array(black_box(&data)).expect("profile parse")));
    });
}

fn bench_sys_chunk_entry_prealloc(c: &mut Criterion) {
    for entry_count in [0_u64, 1, 16] {
        let data = build_sys_chunk_array(entry_count);
        assert_eq!(
            bench_parse_sys_chunk_array(&data, false),
            bench_parse_sys_chunk_array(&data, true),
            "entry_count={entry_count}",
        );
    }

    let mut malformed = build_sys_chunk_array(16);
    malformed.pop();
    assert_eq!(
        bench_parse_sys_chunk_array(&malformed, false),
        bench_parse_sys_chunk_array(&malformed, true),
        "truncated input must preserve the exact parse error",
    );

    let data = build_sys_chunk_array(16);
    let mut group = c.benchmark_group("btrfs_sys_chunk_entry_prealloc_16");
    for control in ["vec_new_control_a", "vec_new_control_b"] {
        group.bench_function(control, |b| {
            b.iter(|| {
                black_box(
                    bench_parse_sys_chunk_array(black_box(&data), false).expect("control parse"),
                )
            });
        });
    }
    group.bench_function("byte_bound_prealloc_candidate", |b| {
        b.iter(|| {
            black_box(bench_parse_sys_chunk_array(black_box(&data), true).expect("candidate parse"))
        });
    });
    group.finish();
}

criterion_group!(
    chunk_map,
    bench_chunk_map,
    bench_stripe_map,
    bench_raid56_data_position,
    bench_stripe_result_storage,
    bench_sys_chunk_parse_profile,
    bench_sys_chunk_entry_prealloc
);
criterion_main!(chunk_map);
