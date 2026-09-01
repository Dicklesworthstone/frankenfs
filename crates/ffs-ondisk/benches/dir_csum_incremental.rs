#![forbid(unsafe_code)]
//! Incremental dir-block csum update vs full recompute (per create/unlink).
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench dir_csum_incremental
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::ext4::{
    ext4_chksum, ext4_chksum_skip_zero_tail, stamp_dir_block_checksum,
    stamp_dir_block_checksum_incremental, stamp_extent_block_checksum,
};
use std::hint::black_box;

const BS: usize = 4096;
const SEED: u32 = 0xDEAD_BEEF;
const INO: u32 = 42;
const GENERATION: u32 = 7;

/// Ascending byte pattern for a fixture region.
///
/// `u8::try_from(i % 256)` rather than `i as u8`: the cast is a denied lint and
/// the modulo says out loud that wrapping is the intent, not an accident
/// (bd-3ao0l).
fn fill_ascending(bytes: &mut [u8]) {
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from(i % 256)
            .expect("i % 256 fits u8")
            .wrapping_add(1);
    }
}

/// Incremental tail update vs full recompute on a block with one entry-sized edit.
fn bench_dir_csum(c: &mut Criterion) {
    let mut base = vec![0xA5u8; BS];
    stamp_dir_block_checksum(&mut base, SEED, INO, GENERATION);
    // a ~28-byte entry insert region near the middle (apply the change to the content)
    let start = 2000usize;
    let delta = vec![0x5Au8; 28];
    let mut changed = base.clone();
    for (i, d) in delta.iter().enumerate() {
        changed[start + i] ^= d;
    }
    // equivalence check (incremental on the changed block carrying base's old tail)
    let mut inc0 = changed.clone();
    inc0[BS - 4..BS].copy_from_slice(&base[BS - 4..BS]);
    let mut full0 = changed.clone();
    assert!(stamp_dir_block_checksum_incremental(
        &mut inc0, start, &delta
    ));
    stamp_dir_block_checksum(&mut full0, SEED, INO, GENERATION);
    assert_eq!(&inc0[BS - 4..], &full0[BS - 4..]);

    // separate blocks per arm; no per-iter clone.
    let mut block_full = changed.clone();
    let mut block_inc = changed.clone();
    let old_tail = [base[BS - 4], base[BS - 3], base[BS - 2], base[BS - 1]];

    let mut g = c.benchmark_group("dir_csum");
    g.bench_function("full_recompute", |b| {
        b.iter(|| {
            stamp_dir_block_checksum(
                black_box(&mut block_full),
                black_box(SEED),
                black_box(INO),
                black_box(GENERATION),
            );
            black_box(block_full[BS - 1])
        });
    });
    g.bench_function("incremental", |b| {
        b.iter(|| {
            block_inc[BS - 4..BS].copy_from_slice(&old_tail);
            black_box(stamp_dir_block_checksum_incremental(
                black_box(&mut block_inc),
                black_box(start),
                black_box(&delta),
            ))
        });
    });
    g.finish();
}

/// SWEEP the changed-span, to locate the crossover [`INCREMENTAL_DIR_CSUM_MAX_SPAN`]
/// asserts but never measured (bd-4sull).
///
/// That constant's doc says "the bench `dir_csum_incremental` crosses over well
/// below 256 B, so this is conservative". This file did not measure that: until
/// now every arm used ONE fixed 28-byte delta and never varied it, so no crossover
/// could be read off it in either direction. This group varies the only quantity
/// that decides the threshold.
///
/// What the two arms cost, from the implementation rather than from intuition:
/// `stamp_dir_block_checksum_incremental` calls `crc32c_update_region(old_tail,
/// delta, suffix)`, which is O(delta) in the same hardware CRC as the full path
/// plus an algebraic shift over the suffix, while `stamp_dir_block_checksum` is a
/// ~4 KiB CRC over the whole coverage region. Both arms run the same primitive at
/// the same rate and differ only in how many bytes they feed it, so the crossover
/// is a property of span-versus-block-size and is measurable right here.
///
/// Read the result as: the largest span at which `incremental` still beats
/// `full_recompute` is the largest span the constant should admit.
fn bench_dir_csum_span(c: &mut Criterion) {
    // 0xA5 fill, not zeros: a zero tail would let the full path's zero-aware skip
    // fire and would flatter it against a block shape a live directory never has.
    let mut base = vec![0xA5u8; BS];
    stamp_dir_block_checksum(&mut base, SEED, INO, GENERATION);
    // Low start so even the widest span stays inside the coverage region.
    let start = 64usize;
    let coverage_end = BS - 12;

    let mut g = c.benchmark_group("dir_csum_span");
    for span in [8usize, 16, 32, 64, 128, 256, 512, 1024, 2048, 3072] {
        assert!(start + span <= coverage_end, "span {span} escapes coverage");
        let delta = vec![0x5Au8; span];
        let mut changed = base.clone();
        for (i, d) in delta.iter().enumerate() {
            changed[start + i] ^= d;
        }

        // Equivalence at THIS span, checked before timing it. A span where the
        // incremental result diverges from the full recompute is not a data point
        // about speed, it is a correctness bug, and timing it would hide that.
        let mut inc0 = changed.clone();
        inc0[BS - 4..BS].copy_from_slice(&base[BS - 4..BS]);
        let mut full0 = changed.clone();
        assert!(
            stamp_dir_block_checksum_incremental(&mut inc0, start, &delta),
            "incremental refused span {span}"
        );
        stamp_dir_block_checksum(&mut full0, SEED, INO, GENERATION);
        assert_eq!(&inc0[BS - 4..], &full0[BS - 4..], "span {span} diverges");

        let mut block_full = changed.clone();
        let mut block_inc = changed.clone();
        let old_tail = [base[BS - 4], base[BS - 3], base[BS - 2], base[BS - 1]];

        g.bench_with_input(
            criterion::BenchmarkId::new("full_recompute", span),
            &span,
            |b, _| {
                b.iter(|| {
                    stamp_dir_block_checksum(
                        black_box(&mut block_full),
                        black_box(SEED),
                        black_box(INO),
                        black_box(GENERATION),
                    );
                    black_box(block_full[BS - 1])
                });
            },
        );
        g.bench_with_input(
            criterion::BenchmarkId::new("incremental", span),
            &span,
            |b, _| {
                b.iter(|| {
                    block_inc[BS - 4..BS].copy_from_slice(&old_tail);
                    black_box(stamp_dir_block_checksum_incremental(
                        black_box(&mut block_inc),
                        black_box(start),
                        black_box(&delta),
                    ))
                });
            },
        );
        // The arm that decides the CONSTANT, because it is what the caller pays.
        //
        // `ffs_dir::dir_block_edit` snapshots the pre-mutation region with
        // `to_vec()` before the stamp, so the real incremental path carries an
        // allocation and copy that grow with the span while the full path carries
        // neither. Timing the stamp alone would overstate the incremental arm at
        // exactly the wide spans where the threshold decision is made, which is
        // the shape of error that produces a lever reversed by wall-clock.
        g.bench_with_input(
            criterion::BenchmarkId::new("incremental_with_snapshot", span),
            &span,
            |b, _| {
                b.iter(|| {
                    let snapshot = black_box(&block_inc[start..start + span]).to_vec();
                    block_inc[BS - 4..BS].copy_from_slice(&old_tail);
                    let stamped = stamp_dir_block_checksum_incremental(
                        black_box(&mut block_inc),
                        black_box(start),
                        black_box(&delta),
                    );
                    black_box((stamped, snapshot.len()))
                });
            },
        );
    }
    g.finish();
}

/// Fresh dir block: a short entry prefix (. and ..) then a large zero gap —
/// the mkdir / new-leaf / large-slack full-stamp case. The zero-aware
/// `crc_dir_coverage` inside `stamp_dir_block_checksum` skips the ~4 KiB zero
/// tail via the algebraic shift, vs the ORIG straight `ext4_chksum` over the
/// whole coverage region.
fn bench_dir_csum_fresh(c: &mut Criterion) {
    let cov = BS - 12;
    let mut fresh = vec![0u8; BS];
    fill_ascending(&mut fresh[..24]);

    let mut gf = c.benchmark_group("dir_csum_fresh");
    gf.bench_function("full_recompute", |b| {
        b.iter(|| {
            let s = ext4_chksum(
                ext4_chksum(black_box(SEED), &INO.to_le_bytes()),
                &GENERATION.to_le_bytes(),
            );
            black_box(ext4_chksum(s, black_box(&fresh[..cov])))
        });
    });
    gf.bench_function("zero_aware", |b| {
        b.iter(|| {
            stamp_dir_block_checksum(
                black_box(&mut fresh),
                black_box(SEED),
                black_box(INO),
                black_box(GENERATION),
            );
            black_box(fresh[BS - 1])
        });
    });
    gf.finish();
}

/// Extent-tree node checksum: coverage spans all `eh_max` slots. A NOT-FULL node
/// (few entries, rest zeroed) has a zero tail the zero-aware CRC skips; a FULL
/// node (all slots used) falls back to the straight CRC (the ORIG cost).
fn bench_extent_csum(c: &mut Criterion) {
    let eh_max: u16 = 340; // 4 KiB block: (4096-16)/12
    let mut not_full = vec![0u8; BS];
    not_full[0..2].copy_from_slice(&0xF30Au16.to_le_bytes()); // eh_magic
    not_full[2..4].copy_from_slice(&4u16.to_le_bytes()); // eh_entries = 4
    not_full[4..6].copy_from_slice(&eh_max.to_le_bytes());
    fill_ascending(&mut not_full[12..60]); // 4 used extents (48 bytes)
    let mut full = vec![0xA5u8; BS];
    full[2..4].copy_from_slice(&eh_max.to_le_bytes());
    full[4..6].copy_from_slice(&eh_max.to_le_bytes());

    let mut ge = c.benchmark_group("extent_csum");
    ge.bench_function("full_straight", |b| {
        b.iter(|| {
            stamp_extent_block_checksum(
                black_box(&mut full),
                black_box(SEED),
                black_box(INO),
                black_box(GENERATION),
            );
            black_box(full[BS - 1])
        });
    });
    ge.bench_function("not_full_zeroaware", |b| {
        b.iter(|| {
            stamp_extent_block_checksum(
                black_box(&mut not_full),
                black_box(SEED),
                black_box(INO),
                black_box(GENERATION),
            );
            black_box(not_full[BS - 1])
        });
    });
    ge.finish();
}

/// Superblock checksum: coverage is `[0, 0x3FC)`; the ~392-byte `s_reserved[98]`
/// region before `s_checksum` is zero on standard filesystems.
fn bench_sb_csum(c: &mut Criterion) {
    let mut sb = vec![0u8; 0x3FC];
    fill_ascending(&mut sb[..0x274]); // live fields up to s_reserved

    let mut gs = c.benchmark_group("sb_csum");
    gs.bench_function("full_straight", |b| {
        b.iter(|| black_box(ext4_chksum(black_box(!0u32), black_box(&sb))));
    });
    gs.bench_function("zero_aware", |b| {
        b.iter(|| black_box(ext4_chksum_skip_zero_tail(black_box(!0u32), black_box(&sb))));
    });
    gs.finish();
}

/// Split into one function per group (bd-3ao0l). Each group's `BenchmarkGroup`
/// then ends at its own `finish()` instead of living to the end of a 121-line
/// `bench`, which is what `significant_drop_tightening` and `too_many_lines` were
/// both pointing at. The fixtures were already independent per group.
fn bench(c: &mut Criterion) {
    bench_dir_csum(c);
    bench_dir_csum_span(c);
    bench_dir_csum_fresh(c);
    bench_extent_csum(c);
    bench_sb_csum(c);
}

criterion_group!(benches, bench);
criterion_main!(benches);
