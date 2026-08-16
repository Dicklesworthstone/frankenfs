#![forbid(unsafe_code)]
//! A/B for ffs-alloc metadata-csum persistence: full bitmap CRC restamp vs the
//! known-range incremental CRC used after a small block bitmap mutation.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cod rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench bitmap_csum_incremental_persist

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::{Ext4GroupDesc, crc_incremental::crc32c_update_region};
use std::hint::black_box;

const INCREMENTAL_BITMAP_CSUM_MAX_DELTA_BYTES: usize = 128;

fn group_desc() -> Ext4GroupDesc {
    Ext4GroupDesc {
        block_bitmap: 0,
        inode_bitmap: 0,
        inode_table: 0,
        free_blocks_count: 0,
        free_inodes_count: 0,
        used_dirs_count: 0,
        itable_unused: 0,
        flags: 0,
        checksum: 0,
        block_bitmap_csum: 0,
        inode_bitmap_csum: 0,
    }
}

fn incremental_range_update(
    old_checksum: u32,
    before: &[u8],
    after: &[u8],
    byte_start: usize,
    byte_len: usize,
    checksum_len: usize,
) -> u32 {
    let delta: Vec<u8> = before[byte_start..byte_start + byte_len]
        .iter()
        .zip(&after[byte_start..byte_start + byte_len])
        .map(|(old, new)| old ^ new)
        .collect();
    crc32c_update_region(old_checksum, &delta, checksum_len - byte_start - byte_len)
}

fn incremental_mask_stack_update(
    old_checksum: u32,
    start_bit: u32,
    bit_count: u32,
    checksum_len: usize,
) -> u32 {
    let byte_start = (start_bit / 8) as usize;
    let byte_end = (start_bit + bit_count).div_ceil(8) as usize;
    let span = byte_end - byte_start;
    assert!(span <= INCREMENTAL_BITMAP_CSUM_MAX_DELTA_BYTES);

    let local_start = start_bit % 8;
    if span <= 16 {
        let mut delta = [0_u8; 16];
        fill_flipped_bit_delta(&mut delta[..span], local_start, bit_count);
        return crc32c_update_region(old_checksum, &delta[..span], checksum_len - byte_end);
    }

    let mut delta = [0_u8; INCREMENTAL_BITMAP_CSUM_MAX_DELTA_BYTES];
    fill_flipped_bit_delta(&mut delta[..span], local_start, bit_count);
    crc32c_update_region(old_checksum, &delta[..span], checksum_len - byte_end)
}

fn fill_flipped_bit_delta(delta: &mut [u8], local_start: u32, bit_count: u32) {
    if local_start == 0 && bit_count.is_multiple_of(8) {
        delta.fill(u8::MAX);
    } else {
        for bit in local_start..local_start + bit_count {
            delta[(bit / 8) as usize] |= 1_u8 << (bit % 8);
        }
    }
}

fn bench(c: &mut Criterion) {
    let csum_seed = 0x1357_2468;
    let blocks_per_group = 32_768;
    let desc_size = 64;
    let checksum_len = (blocks_per_group / 8) as usize;
    let byte_start = 3000usize;
    let byte_len = 8usize;
    let start_bit = u32::try_from(byte_start * 8).unwrap();
    let bit_count = u32::try_from(byte_len * 8).unwrap();

    let mut before = vec![0xA5_u8; checksum_len];
    before[byte_start..byte_start + byte_len].fill(0);
    let mut after = before.clone();
    after[byte_start..byte_start + byte_len].fill(0xFF);

    let mut before_desc = group_desc();
    ffs_ondisk::ext4::stamp_block_bitmap_checksum(
        &before,
        csum_seed,
        blocks_per_group,
        &mut before_desc,
        desc_size,
    );

    let mut full_desc = before_desc.clone();
    ffs_ondisk::ext4::stamp_block_bitmap_checksum(
        &after,
        csum_seed,
        blocks_per_group,
        &mut full_desc,
        desc_size,
    );
    assert_eq!(
        incremental_range_update(
            before_desc.block_bitmap_csum,
            &before,
            &after,
            byte_start,
            byte_len,
            checksum_len,
        ),
        full_desc.block_bitmap_csum
    );
    assert_eq!(
        incremental_mask_stack_update(
            before_desc.block_bitmap_csum,
            start_bit,
            bit_count,
            checksum_len,
        ),
        full_desc.block_bitmap_csum
    );

    let mut group = c.benchmark_group("bitmap_csum_incremental_persist");
    group.bench_function("full_stamp_4k_8byte_change", |b| {
        b.iter(|| {
            let mut desc = black_box(before_desc.clone());
            ffs_ondisk::ext4::stamp_block_bitmap_checksum(
                black_box(&after),
                black_box(csum_seed),
                black_box(blocks_per_group),
                black_box(&mut desc),
                black_box(desc_size),
            );
            black_box(desc.block_bitmap_csum)
        });
    });
    group.bench_function("incremental_range_8byte_change", |b| {
        b.iter(|| {
            black_box(incremental_range_update(
                black_box(before_desc.block_bitmap_csum),
                black_box(&before),
                black_box(&after),
                black_box(byte_start),
                black_box(byte_len),
                black_box(checksum_len),
            ))
        });
    });
    group.bench_function("incremental_mask_stack_8byte_change", |b| {
        b.iter(|| {
            black_box(incremental_mask_stack_update(
                black_box(before_desc.block_bitmap_csum),
                black_box(start_bit),
                black_box(bit_count),
                black_box(checksum_len),
            ))
        });
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
