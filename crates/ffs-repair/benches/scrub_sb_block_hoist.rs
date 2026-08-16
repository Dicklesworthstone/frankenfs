#![forbid(unsafe_code)]

//! Same-process A/B for hoisting the per-block DIVISION out of the btrfs scrub
//! superblock/tree-block validators.
//!
//! Both `BtrfsSuperblockValidator` and `BtrfsTreeBlockValidator` run on EVERY
//! scanned block via `dyn BlockValidator`, and each computed
//! `BTRFS_SUPER_INFO_OFFSET / block_size` (a u64 division, ~20-40 cycles,
//! uninlinable/unhoistable under dynamic dispatch) just to reject the block on a
//! block-number check. After the fsid pre-check (e8932055) made the tree-block
//! validator's data-block path cheap, those 2 divisions/block are a large share
//! of the remaining per-block validation. Hoisting them into `new()` leaves the
//! hot path a plain compare. This benches the per-block cheap path a DATA block
//! traverses (2 validators → Skip) OLD (divisions) vs NEW (precomputed).
//!
//! RESULT (2026-07-04, BlackThrush): WIN. release-perf/opt-3, two runs agree:
//!   local  old 384.9 ns  vs  new 280.5 ns  = ~1.37x
//!   rch    old 485.7 ns  vs  new 341.8 ns  = ~1.42x
//! for the 256-block per-block sb/tree-block reject path. Behaviour-identical
//! (equivalence assert passed). Production hoisted the two divisions into the
//! validators' `new()`. Real scrub impact scales with the validation-vs-I/O
//! balance (this is one component of the now-cheap data-block validation, on top
//! of the fsid pre-check e8932055). Run per-crate:
//!   rch exec -- cargo bench --profile release-perf -p ffs-repair --bench scrub_sb_block_hoist

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const N: usize = 256; // blocks per iter (one read batch)
const BLOCK_SIZE: u64 = 16_384; // btrfs nodesize
const SUPER_INFO_OFFSET: u64 = 64 * 1024;

/// OLD: recompute the two target-block divisions per block, then reject.
fn old_path(block: u64, bs: u64) -> bool {
    // superblock validator: target_block_and_offset (division + modulo)
    let sb_target = SUPER_INFO_OFFSET / bs;
    black_box(SUPER_INFO_OFFSET % bs);
    if block != sb_target {
        // tree-block validator: superblock_block (division)
        let tb_sb = SUPER_INFO_OFFSET / bs;
        if block != tb_sb {
            return true; // reached the (cheap) fsid pre-check → not superblock
        }
    }
    false
}

/// NEW: compare against precomputed block numbers (no division).
fn new_path(block: u64, sb_target: u64, tb_sb: u64) -> bool {
    if block != sb_target && block != tb_sb {
        return true;
    }
    false
}

fn bench(c: &mut Criterion) {
    // Data blocks: none are the superblock block (which is 4 at 16 KiB).
    let blocks: Vec<u64> = (100..100 + N as u64).collect();
    let sb_target = SUPER_INFO_OFFSET / BLOCK_SIZE;
    let tb_sb = SUPER_INFO_OFFSET / BLOCK_SIZE;

    // Equivalence.
    for &b in &blocks {
        assert_eq!(old_path(b, BLOCK_SIZE), new_path(b, sb_target, tb_sb));
    }

    let mut g = c.benchmark_group("scrub_btrfs_sb_block_check_256");
    g.bench_function("old_per_block_div", |bch| {
        bch.iter(|| {
            let mut acc = 0u64;
            for &b in &blocks {
                acc += u64::from(old_path(black_box(b), black_box(BLOCK_SIZE)));
            }
            black_box(acc);
        });
    });
    g.bench_function("new_precomputed", |bch| {
        bch.iter(|| {
            let mut acc = 0u64;
            for &b in &blocks {
                acc += u64::from(new_path(
                    black_box(b),
                    black_box(sb_target),
                    black_box(tb_sb),
                ));
            }
            black_box(acc);
        });
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
