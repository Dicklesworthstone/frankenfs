#![forbid(unsafe_code)]

//! A/B benchmark for the group-descriptor flush read scope
//! (`ext4_persist_group_descriptors_from`, bd-cc-gdt-defer).
//!
//! The GDT flush at the durability boundary stamps every group descriptor's
//! bitmap checksum. It only needs the on-device bitmap bytes for a group that is
//! actually IN USE (an untouched lazy-init group passes no override). The old
//! code read both bitmaps for EVERY group up front and then discarded the bytes
//! for untouched groups; the new code reads only in-use groups. Each skipped
//! read is a real `read_block(...).into_inner()` = a block-sized allocation plus
//! a block-sized memcpy off the device. This models a large filesystem with few
//! touched groups (the common case for the create/durability path).

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const BS: usize = 4096;
const GROUPS: usize = 128;
/// 1 group in 16 is touched → 8 in-use, 120 untouched.
const IN_USE_EVERY: usize = 16;

fn in_use(g: usize) -> bool {
    g.is_multiple_of(IN_USE_EVERY)
}

/// Mirrors `direct.read_block(cx, block)?.into_inner()`: a block-sized alloc +
/// memcpy off the backing device.
fn read_block(device: &[u8], block: usize) -> Vec<u8> {
    device[block * BS..(block + 1) * BS].to_vec()
}

/// Stand-in for `persist_group_desc_force`: identical work in both arms, so the
/// measured delta is purely the eliminated untouched-group reads. Consumes the
/// override (Some only for in-use groups) so it cannot be elided.
fn persist_stub(block_override: Option<&[u8]>, inode_override: Option<&[u8]>) -> u64 {
    let mut acc = 1_u64;
    if let Some(b) = block_override {
        acc = acc.wrapping_add(u64::from(b[0]));
    }
    if let Some(i) = inode_override {
        acc = acc.wrapping_add(u64::from(i[0]));
    }
    acc
}

/// Old: read both bitmaps for EVERY group; use the override only when in use.
fn flush_read_all(device: &[u8]) -> u64 {
    let mut acc = 0_u64;
    for g in 0..GROUPS {
        let bb = read_block(device, 2 * g);
        let ib = read_block(device, 2 * g + 1);
        let bo = in_use(g).then_some(bb.as_slice());
        let io = in_use(g).then_some(ib.as_slice());
        acc = acc.wrapping_add(persist_stub(bo, io));
    }
    acc
}

/// New: read each bitmap only for an in-use group.
fn flush_read_in_use(device: &[u8]) -> u64 {
    let mut acc = 0_u64;
    for g in 0..GROUPS {
        let bb = in_use(g).then(|| read_block(device, 2 * g));
        let ib = in_use(g).then(|| read_block(device, 2 * g + 1));
        acc = acc.wrapping_add(persist_stub(bb.as_deref(), ib.as_deref()));
    }
    acc
}

fn bench_gdt_flush_untouched_reads(c: &mut Criterion) {
    let device = vec![0x5A_u8; GROUPS * 2 * BS];

    // Both arms persist the identical descriptor result — reading a bitmap that
    // is then discarded cannot change what gets stamped.
    assert_eq!(
        flush_read_all(&device),
        flush_read_in_use(&device),
        "narrowing the read scope changed the persisted result"
    );

    let mut group = c.benchmark_group("gdt_flush_untouched_reads_128groups");
    group.bench_function("read_all_groups_a", |b| {
        b.iter(|| black_box(flush_read_all(black_box(&device))));
    });
    group.bench_function("read_all_groups_b", |b| {
        b.iter(|| black_box(flush_read_all(black_box(&device))));
    });
    group.bench_function("read_in_use_only", |b| {
        b.iter(|| black_box(flush_read_in_use(black_box(&device))));
    });
    group.finish();
}

// ── superblock free-totals sum: two passes vs one fused pass ────────────────
//
// ext4_sync_superblock_free_totals summed free_blocks and free_inodes across the
// group array in two separate `.sum()` passes. Each `GroupStats` is ~96 bytes, so
// on a large filesystem the array exceeds cache and the second pass reloads every
// group. Fusing to one fold halves that memory traffic (free_blocks + free_inodes
// share a cache line). This models the array size at ~16k groups (a multi-TB fs).

/// ~96-byte stand-in for `GroupStats` so the array's cache footprint matches
/// production; free_blocks + free_inodes sit near the front (one cache line).
#[derive(Clone, Default)]
struct GroupLike {
    _group: u32,
    free_blocks: u32,
    _largest: u64,
    free_inodes: u32,
    _search: u32,
    _used_dirs: u32,
    _pad: [u64; 9],
}

const SUM_GROUPS: usize = 16_384;

fn two_pass_sum(groups: &[GroupLike]) -> (u64, u64) {
    let blocks: u64 = groups.iter().map(|g| u64::from(g.free_blocks)).sum();
    let inodes: u64 = groups.iter().map(|g| u64::from(g.free_inodes)).sum();
    (blocks, inodes)
}

fn one_pass_sum(groups: &[GroupLike]) -> (u64, u64) {
    groups.iter().fold((0_u64, 0_u64), |(blocks, inodes), g| {
        (
            blocks + u64::from(g.free_blocks),
            inodes + u64::from(g.free_inodes),
        )
    })
}

fn bench_ext4_free_totals_sum(c: &mut Criterion) {
    let groups: Vec<GroupLike> = (0..SUM_GROUPS)
        .map(|k| GroupLike {
            free_blocks: u32::try_from(k).expect("group count fits u32") & 0xFFFF,
            free_inodes: u32::try_from(k)
                .expect("group count fits u32")
                .wrapping_mul(3)
                & 0xFFFF,
            ..Default::default()
        })
        .collect();
    assert_eq!(
        two_pass_sum(&groups),
        one_pass_sum(&groups),
        "fusing the free-totals sum changed the totals"
    );

    let mut group = c.benchmark_group("ext4_free_totals_sum_16384groups");
    group.bench_function("two_pass_a", |b| {
        b.iter(|| black_box(two_pass_sum(black_box(&groups))));
    });
    group.bench_function("two_pass_b", |b| {
        b.iter(|| black_box(two_pass_sum(black_box(&groups))));
    });
    group.bench_function("one_pass_fold", |b| {
        b.iter(|| black_box(one_pass_sum(black_box(&groups))));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_gdt_flush_untouched_reads,
    bench_ext4_free_totals_sum
);
criterion_main!(benches);
