#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for `locate_inode`'s address arithmetic: the division/modulo
//! form (`÷ inodes_per_group`, `÷ block_size`) vs a strength-reduced form (shift
//! + mask for the power-of-two divisors that ext4 uses by invariant/default).
//! `locate_inode` runs on EVERY inode read/write — every `getattr`/walk stat, and
//! twice per create — so the per-call DIV cost is on the hot metadata path.
//!
//! REFUTED (do NOT re-implement): production `locate_inode` intentionally RETAINS
//! the division form. The strength-reduced form measured 1.00x (`division`
//! 24.674µs vs `strength_reduced` 24.942µs — marginally SLOWER; DIV throughput
//! ~6cyc is fully hidden by loop ILP). See docs/NEGATIVE_EVIDENCE.md 2026-07-05.
//! This bench is that rejection's retained guard. Both forms are bit-identical.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-inode --bench locate_inode

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_alloc::{FsGeometry, GroupStats};
use ffs_inode::{InodeLocation, locate_inode};
use ffs_types::{BlockNumber, GroupNumber, InodeNumber};
use std::hint::black_box;

fn make_geometry() -> FsGeometry {
    FsGeometry {
        blocks_per_group: 8192,
        inodes_per_group: 2048,
        block_size: 4096,
        cluster_ratio: 1,
        total_blocks: 32768,
        total_inodes: 8192,
        first_data_block: 0,
        group_count: 4,
        inode_size: 256,
        desc_size: 32,
        reserved_gdt_blocks: 0,
        feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
        feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
        feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
        log_groups_per_flex: 0,
        backup_bgs: [0, 0],
        first_meta_bg: 0,
        first_inode: 11,
    }
}

fn make_groups(geo: &FsGeometry) -> Vec<GroupStats> {
    (0..geo.group_count)
        .map(|g| GroupStats {
            group: GroupNumber(g),
            free_blocks: geo.blocks_per_group,
            block_largest_free_run: None,
            free_inodes: geo.inodes_per_group,
            used_dirs: 0,
            block_bitmap_block: BlockNumber(u64::from(g) * 100 + 1),
            inode_bitmap_block: BlockNumber(u64::from(g) * 100 + 2),
            inode_table_block: BlockNumber(u64::from(g) * 100 + 3),
            flags: 0,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
            inode_search_start: 0,
            reserved_cache: std::sync::OnceLock::new(),
            reserved_confirmed: std::sync::OnceLock::new(),
        })
        .collect()
}

/// Original division/modulo form (pre-strength-reduction), inlined for A/B.
fn locate_inode_div(
    ino: InodeNumber,
    geo: &FsGeometry,
    groups: &[GroupStats],
) -> Option<InodeLocation> {
    if ino.0 == 0 || geo.inodes_per_group == 0 || geo.block_size == 0 || geo.inode_size == 0 {
        return None;
    }
    let ino0 = ino.0.saturating_sub(1);
    let ipg = u64::from(geo.inodes_per_group);
    let group_u32 = (ino0 / ipg) as u32;
    let index = (ino0 % ipg) as u32;
    let gidx = group_u32 as usize;
    if gidx >= groups.len() {
        return None;
    }
    let byte_in_table = u64::from(index) * u64::from(geo.inode_size);
    let block_size = u64::from(geo.block_size);
    let block_offset = byte_in_table / block_size;
    let byte_offset = (byte_in_table % block_size) as usize;
    let block = BlockNumber(groups[gidx].inode_table_block.0.checked_add(block_offset)?);
    Some(InodeLocation { block, byte_offset })
}

fn bench_locate(c: &mut Criterion) {
    let geo = make_geometry();
    let groups = make_groups(&geo);
    // Walk-representative spread across all groups (every valid inode number).
    let inos: Vec<InodeNumber> = (1..=8192u64).map(InodeNumber).collect();

    // Correctness: the shipped form matches the division form for every inode.
    for &ino in &inos {
        let a = locate_inode(ino, &geo, &groups).map(|l| (l.block.0, l.byte_offset));
        let b = locate_inode_div(ino, &geo, &groups).map(|l| (l.block.0, l.byte_offset));
        assert_eq!(a, b, "mismatch at inode {}", ino.0);
    }

    let mut g = c.benchmark_group("locate_inode");
    g.bench_function("division", |b| {
        b.iter(|| {
            let mut acc = 0u64;
            for &ino in &inos {
                if let Some(loc) =
                    locate_inode_div(black_box(ino), black_box(&geo), black_box(&groups))
                {
                    acc = acc
                        .wrapping_add(loc.block.0)
                        .wrapping_add(loc.byte_offset as u64);
                }
            }
            black_box(acc)
        })
    });
    g.bench_function("strength_reduced", |b| {
        b.iter(|| {
            let mut acc = 0u64;
            for &ino in &inos {
                if let Some(loc) = locate_inode(black_box(ino), black_box(&geo), black_box(&groups))
                {
                    acc = acc
                        .wrapping_add(loc.block.0)
                        .wrapping_add(loc.byte_offset as u64);
                }
            }
            black_box(acc)
        })
    });
    g.finish();
}

criterion_group!(benches, bench_locate);
criterion_main!(benches);
