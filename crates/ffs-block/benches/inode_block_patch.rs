#![forbid(unsafe_code)]

//! Read-modify-write of a block to patch a ~256-byte inode slot, as
//! `ffs_inode::write_inode_at` does on every create/mkdir/setattr.
//!
//! The old code did `buf.as_slice().to_vec()` — an UNCONDITIONAL block-sized heap
//! alloc + memcpy — just to get a mutable buffer. `BlockBuf::make_mut()` is COW
//! (`Arc::make_mut`): free when the freshly-read block is uniquely owned, and a
//! one-time clone (== `to_vec`) when the buffer is shared with a cache. This times
//! ONLY the patch op (buffer construction is untimed setup) in both ownership
//! regimes.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ffs_block::BlockBuf;
use std::hint::black_box;

const INODE: usize = 256;
const OFF: usize = 512; // an inode slot offset within the block

fn block(bs: usize) -> Vec<u8> {
    (0..bs)
        .map(|i| u8::try_from(i & 0xff).expect("masked to u8"))
        .collect()
}

fn patch() -> [u8; INODE] {
    let mut p = [0_u8; INODE];
    for (i, b) in p.iter_mut().enumerate() {
        *b = u8::try_from(i & 0xff).expect("masked to u8") | 1;
    }
    p
}

fn bench_inode_block_patch(c: &mut Criterion) {
    let raw = patch();
    for bs in [4096_usize, 16384] {
        let src = block(bs);
        let mut group = c.benchmark_group(format!("inode_block_patch_{bs}"));
        group.sample_size(50);

        // OLD: to_vec() always copies the whole block.
        group.bench_function("to_vec", |b| {
            b.iter_batched(
                || BlockBuf::new(src.clone()),
                |buf| {
                    let mut block_data = buf.as_slice().to_vec();
                    block_data[OFF..OFF + INODE].copy_from_slice(&raw);
                    black_box(block_data[OFF]);
                },
                BatchSize::SmallInput,
            );
        });
        // NEW, uniquely-owned (fresh read): make_mut is free (no copy).
        group.bench_function("make_mut_unique", |b| {
            b.iter_batched(
                || BlockBuf::new(src.clone()),
                |mut buf| {
                    let block_data = buf.make_mut();
                    block_data[OFF..OFF + INODE].copy_from_slice(&raw);
                    black_box(buf.as_slice()[OFF]);
                },
                BatchSize::SmallInput,
            );
        });
        // NEW, shared (cached): make_mut clones once, == to_vec (Pareto floor).
        group.bench_function("make_mut_shared", |b| {
            b.iter_batched(
                || {
                    let buf = BlockBuf::new(src.clone());
                    let keep = buf.clone_ref(); // refcount 2 -> make_mut must clone
                    (buf, keep)
                },
                |(mut buf, _keep)| {
                    let block_data = buf.make_mut();
                    block_data[OFF..OFF + INODE].copy_from_slice(&raw);
                    black_box(buf.as_slice()[OFF]);
                },
                BatchSize::SmallInput,
            );
        });
        group.finish();
    }
}

criterion_group!(inode_block_patch, bench_inode_block_patch);
criterion_main!(inode_block_patch);
