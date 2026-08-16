#![forbid(unsafe_code)]

//! A/B for allocator bitmap descriptor checksums.
//!
//! Old eager-GDT persistence re-ran `stamp_block_bitmap_checksum` over the whole
//! bitmap after a short alloc/free bit-range change. The production fast path now
//! builds the changed-byte XOR delta from the known bit range and applies the
//! incremental CRC32C update.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::crc_incremental::crc32c_update_region;
use ffs_ondisk::ext4::{Ext4GroupDesc, stamp_block_bitmap_checksum};
use std::hint::black_box;

const BLOCKS_PER_GROUP: u32 = 32_768;
const BITMAP_BYTES: usize = 4_096;
const CSUM_SEED: u32 = 0x1357_2468;

fn make_bitmap_pair(bit_start: u32, bit_count: u32) -> (Vec<u8>, Vec<u8>) {
    let before: Vec<u8> = (0..BITMAP_BYTES)
        .map(|idx| {
            u8::try_from(idx % 256)
                .unwrap_or(0)
                .wrapping_mul(37)
                .rotate_left(1)
        })
        .collect();
    let mut after = before.clone();
    for bit in bit_start..bit_start + bit_count {
        let byte = (bit / 8) as usize;
        let mask = 1_u8 << (bit % 8);
        after[byte] ^= mask;
    }
    (before, after)
}

fn seeded_desc(bitmap: &[u8], desc_size: u16) -> Ext4GroupDesc {
    let mut gd = Ext4GroupDesc {
        block_bitmap: 1,
        inode_bitmap: 2,
        inode_table: 3,
        free_blocks_count: BLOCKS_PER_GROUP,
        free_inodes_count: 2_048,
        used_dirs_count: 0,
        flags: 0,
        checksum: 0,
        block_bitmap_csum: 0,
        inode_bitmap_csum: 0,
        itable_unused: 0,
    };
    stamp_block_bitmap_checksum(bitmap, CSUM_SEED, BLOCKS_PER_GROUP, &mut gd, desc_size);
    gd
}

fn incremental_checksum(
    old_checksum: u32,
    before: &[u8],
    after: &[u8],
    bit_start: u32,
    bit_count: u32,
    desc_size: u16,
) -> u32 {
    let checksum_len = (BLOCKS_PER_GROUP / 8) as usize;
    let byte_start = (bit_start / 8) as usize;
    let byte_end = (bit_start + bit_count).div_ceil(8) as usize;
    let byte_end = byte_end.min(checksum_len);
    let delta: Vec<u8> = before[byte_start..byte_end]
        .iter()
        .zip(&after[byte_start..byte_end])
        .map(|(old, new)| old ^ new)
        .collect();
    let suffix = checksum_len - byte_start - delta.len();
    let mut checksum = crc32c_update_region(old_checksum, &delta, suffix);
    if desc_size < 64 {
        checksum &= 0xFFFF;
    }
    checksum
}

fn bench_bitmap_csum_incremental(c: &mut Criterion) {
    let (before, after_1b) = make_bitmap_pair(513, 1);
    let (_, after_8b) = make_bitmap_pair(512, 64);

    for desc_size in [32_u16, 64] {
        let old_desc = seeded_desc(&before, desc_size);
        let mut full_group = c.benchmark_group(format!("bitmap_csum_desc{desc_size}_1bit"));
        full_group.bench_function("full_recompute", |b| {
            b.iter(|| {
                let mut gd = black_box(old_desc.clone());
                stamp_block_bitmap_checksum(
                    black_box(&after_1b),
                    black_box(CSUM_SEED),
                    black_box(BLOCKS_PER_GROUP),
                    &mut gd,
                    black_box(desc_size),
                );
                black_box(gd.block_bitmap_csum)
            });
        });
        full_group.bench_function("incremental", |b| {
            b.iter(|| {
                black_box(incremental_checksum(
                    black_box(old_desc.block_bitmap_csum),
                    black_box(&before),
                    black_box(&after_1b),
                    black_box(513),
                    black_box(1),
                    black_box(desc_size),
                ))
            });
        });
        full_group.finish();

        let mut eight_byte_group = c.benchmark_group(format!("bitmap_csum_desc{desc_size}_8byte"));
        eight_byte_group.bench_function("full_recompute", |b| {
            b.iter(|| {
                let mut gd = black_box(old_desc.clone());
                stamp_block_bitmap_checksum(
                    black_box(&after_8b),
                    black_box(CSUM_SEED),
                    black_box(BLOCKS_PER_GROUP),
                    &mut gd,
                    black_box(desc_size),
                );
                black_box(gd.block_bitmap_csum)
            });
        });
        eight_byte_group.bench_function("incremental", |b| {
            b.iter(|| {
                black_box(incremental_checksum(
                    black_box(old_desc.block_bitmap_csum),
                    black_box(&before),
                    black_box(&after_8b),
                    black_box(512),
                    black_box(64),
                    black_box(desc_size),
                ))
            });
        });
        eight_byte_group.finish();
    }
}

criterion_group!(benches, bench_bitmap_csum_incremental);
criterion_main!(benches);
