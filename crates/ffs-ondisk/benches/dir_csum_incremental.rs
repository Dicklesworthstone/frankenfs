#![forbid(unsafe_code)]
//! Incremental dir-block csum update vs full recompute (per create/unlink).
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench dir_csum_incremental
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::ext4::{
    stamp_dir_block_checksum, stamp_dir_block_checksum_incremental, stamp_extent_block_checksum,
};
use std::hint::black_box;
fn bench(c: &mut Criterion) {
    let bs = 4096usize;
    let seed = 0xDEAD_BEEFu32;
    let ino = 42u32;
    let generation = 7u32;
    let mut base = vec![0xA5u8; bs];
    stamp_dir_block_checksum(&mut base, seed, ino, generation);
    // a ~28-byte entry insert region near the middle (apply the change to the content)
    let start = 2000usize;
    let delta = vec![0x5Au8; 28];
    let mut changed = base.clone();
    for (i, d) in delta.iter().enumerate() {
        changed[start + i] ^= d;
    }
    // equivalence check (incremental on the changed block carrying base's old tail)
    let mut inc0 = changed.clone();
    inc0[bs - 4..bs].copy_from_slice(&base[bs - 4..bs]);
    let mut full0 = changed.clone();
    assert!(stamp_dir_block_checksum_incremental(
        &mut inc0, start, &delta
    ));
    stamp_dir_block_checksum(&mut full0, seed, ino, generation);
    assert_eq!(&inc0[bs - 4..], &full0[bs - 4..]);

    // separate blocks per arm; no per-iter clone.
    let mut block_full = changed.clone();
    let mut block_inc = changed.clone();
    let old_tail = [base[bs - 4], base[bs - 3], base[bs - 2], base[bs - 1]];
    let mut g = c.benchmark_group("dir_csum");
    g.bench_function("full_recompute", |b| {
        b.iter(|| {
            stamp_dir_block_checksum(
                black_box(&mut block_full),
                black_box(seed),
                black_box(ino),
                black_box(generation),
            );
            black_box(block_full[bs - 1])
        })
    });
    g.bench_function("incremental", |b| {
        b.iter(|| {
            block_inc[bs - 4..bs].copy_from_slice(&old_tail);
            black_box(stamp_dir_block_checksum_incremental(
                black_box(&mut block_inc),
                black_box(start),
                black_box(&delta),
            ))
        })
    });
    g.finish();

    // Fresh dir block: a short entry prefix (. and ..) then a large zero gap —
    // the mkdir / new-leaf / large-slack full-stamp case. The zero-aware
    // crc_dir_coverage inside stamp_dir_block_checksum skips the ~4 KiB zero tail
    // via the algebraic shift, vs the ORIG straight ext4_chksum over the whole
    // coverage region.
    let cov = bs - 12;
    let mut fresh = vec![0u8; bs];
    for (i, byte) in fresh.iter_mut().take(24).enumerate() {
        *byte = (i as u8).wrapping_add(1);
    }
    let mut gf = c.benchmark_group("dir_csum_fresh");
    gf.bench_function("full_recompute", |b| {
        b.iter(|| {
            let s = ffs_ondisk::ext4::ext4_chksum(
                ffs_ondisk::ext4::ext4_chksum(black_box(seed), &ino.to_le_bytes()),
                &generation.to_le_bytes(),
            );
            black_box(ffs_ondisk::ext4::ext4_chksum(s, black_box(&fresh[..cov])))
        })
    });
    gf.bench_function("zero_aware", |b| {
        b.iter(|| {
            stamp_dir_block_checksum(
                black_box(&mut fresh),
                black_box(seed),
                black_box(ino),
                black_box(generation),
            );
            black_box(fresh[bs - 1])
        })
    });
    gf.finish();

    // Extent-tree node checksum: coverage spans all eh_max slots. A NOT-FULL node
    // (few entries, rest zeroed) has a zero tail the zero-aware CRC skips; a FULL
    // node (all slots used) falls back to the straight CRC (the ORIG cost).
    let eh_max: u16 = 340; // 4 KiB block: (4096-16)/12
    let mut not_full = vec![0u8; bs];
    not_full[0..2].copy_from_slice(&0xF30Au16.to_le_bytes()); // eh_magic
    not_full[2..4].copy_from_slice(&4u16.to_le_bytes()); // eh_entries = 4
    not_full[4..6].copy_from_slice(&eh_max.to_le_bytes());
    for (i, byte) in not_full.iter_mut().skip(12).take(48).enumerate() {
        *byte = (i as u8).wrapping_add(1); // 4 used extents (48 bytes)
    }
    let mut full = vec![0xA5u8; bs];
    full[2..4].copy_from_slice(&eh_max.to_le_bytes());
    full[4..6].copy_from_slice(&eh_max.to_le_bytes());
    let mut ge = c.benchmark_group("extent_csum");
    ge.bench_function("full_straight", |b| {
        b.iter(|| {
            stamp_extent_block_checksum(
                black_box(&mut full),
                black_box(seed),
                black_box(ino),
                black_box(generation),
            );
            black_box(full[bs - 1])
        })
    });
    ge.bench_function("not_full_zeroaware", |b| {
        b.iter(|| {
            stamp_extent_block_checksum(
                black_box(&mut not_full),
                black_box(seed),
                black_box(ino),
                black_box(generation),
            );
            black_box(not_full[bs - 1])
        })
    });
    ge.finish();

    // Superblock checksum: coverage is [0, 0x3FC); the ~392-byte s_reserved[98]
    // region before s_checksum is zero on standard filesystems.
    use ffs_ondisk::ext4::{ext4_chksum, ext4_chksum_skip_zero_tail};
    let mut sb = vec![0u8; 0x3FC];
    for (i, byte) in sb.iter_mut().take(0x274).enumerate() {
        *byte = (i as u8).wrapping_add(1); // live fields up to s_reserved
    }
    let mut gs = c.benchmark_group("sb_csum");
    gs.bench_function("full_straight", |b| {
        b.iter(|| black_box(ext4_chksum(black_box(!0u32), black_box(&sb))))
    });
    gs.bench_function("zero_aware", |b| {
        b.iter(|| black_box(ext4_chksum_skip_zero_tail(black_box(!0u32), black_box(&sb))))
    });
    gs.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
