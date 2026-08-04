#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the per-block read-buffer construction lever (bd-kq3b4).
//!
//! The scalar device read path returns a `Vec<u8>` materialised from a
//! [`BlockBuf`]. Two ways to build that block buffer before the final
//! `as_slice().to_vec()`:
//!
//! * `via_unaligned_vec` — `vec![0; N]` (unaligned) then `BlockBuf::new`, which
//!   forces `AlignedVec::from_vec` down its realign path: an extra padded
//!   allocation + memset + memcpy on every block. This is the pre-bd-kq3b4
//!   shape of `ByteDeviceBlockAdapter::read_block`.
//! * `via_aligned_zeroed` — `BlockBuf::zeroed(N)` is block-aligned at
//!   construction, so the realign copy never happens. This is the post-bd-kq3b4
//!   shape (and matches what `read_contiguous_blocks` already did).
//!
//! Both variants do the same device-fill memcpy and the same trailing
//! `to_vec`, so the delta isolates exactly the eliminated realign work. Running
//! both in one binary keeps the comparison on a single CPU, side-stepping the
//! cross-worker timing skew that makes absolute rch numbers untrustworthy.
//! `block_vec_direct_final_buffer` measures the next owned-read lever: fill the
//! final `Vec<u8>` directly when the caller already wants owned bytes.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_block::BlockBuf;
use std::hint::black_box;

const BLOCK_SIZE: usize = 4096;

fn bench_block_buf_construct(c: &mut Criterion) {
    // Stand-in for the bytes a device read would deposit into the buffer.
    let src = vec![0xA5_u8; BLOCK_SIZE];
    let mut aligned = BlockBuf::zeroed(BLOCK_SIZE);
    aligned.make_mut().copy_from_slice(&src);
    let mut direct = vec![0_u8; BLOCK_SIZE];
    direct.copy_from_slice(&src);
    assert_eq!(aligned.as_slice(), direct.as_slice());

    c.bench_function("block_buf_via_unaligned_vec", |b| {
        b.iter(|| {
            let mut bytes = vec![0_u8; BLOCK_SIZE];
            bytes.copy_from_slice(black_box(&src));
            let buf = BlockBuf::new(bytes);
            black_box(buf.as_slice().to_vec())
        });
    });

    c.bench_function("block_buf_via_aligned_zeroed", |b| {
        b.iter(|| {
            let mut buf = BlockBuf::zeroed(BLOCK_SIZE);
            buf.make_mut().copy_from_slice(black_box(&src));
            black_box(buf.as_slice().to_vec())
        });
    });

    c.bench_function("block_vec_direct_final_buffer", |b| {
        b.iter(|| {
            let mut bytes = vec![0_u8; BLOCK_SIZE];
            bytes.copy_from_slice(black_box(&src));
            black_box(bytes)
        });
    });

    // ── Arc<[u8]> materialisation on the block-cache miss path ───────────────
    // The cache wrappers in ffs-core need an Arc<[u8]>. Building it through a
    // Vec (`Arc::from(buf.as_slice().to_vec())`) copies twice; building it from
    // the slice directly (`Arc::from(buf.as_slice())`) copies once.
    let mut filled = BlockBuf::zeroed(BLOCK_SIZE);
    filled.make_mut().copy_from_slice(&src);

    c.bench_function("block_arc_via_vec_two_copies", |b| {
        b.iter(|| {
            let buf = black_box(&filled);
            black_box(std::sync::Arc::<[u8]>::from(buf.as_slice().to_vec()))
        });
    });

    c.bench_function("block_arc_via_slice_one_copy", |b| {
        b.iter(|| {
            let buf = black_box(&filled);
            black_box(std::sync::Arc::<[u8]>::from(buf.as_slice()))
        });
    });

    // The read-only inode-table cache used to convert each device-returned
    // `BlockBuf` miss into `Arc<[u8]>`, allocating and copying all 4 KiB. The
    // candidate stores the native `BlockBuf` and clones its shared backing.
    // Keep two identical old-shape controls in the same binary so their spread
    // is the null floor for this isolated ownership transfer.
    let copied = std::sync::Arc::<[u8]>::from(filled.as_slice());
    let shared = filled.clone_ref();
    assert_eq!(copied.as_ref(), shared.as_slice());
    assert!(filled.shares_storage_with(&shared));

    c.bench_function("inode_cache_miss_arc_copy_a", |b| {
        b.iter(|| {
            let buf = black_box(&filled);
            black_box(std::sync::Arc::<[u8]>::from(buf.as_slice()))
        });
    });

    c.bench_function("inode_cache_miss_arc_copy_b", |b| {
        b.iter(|| {
            let buf = black_box(&filled);
            black_box(std::sync::Arc::<[u8]>::from(buf.as_slice()))
        });
    });

    c.bench_function("inode_cache_miss_blockbuf_share", |b| {
        b.iter(|| {
            let buf = black_box(&filled);
            black_box(buf.clone_ref())
        });
    });
}

// ── small-read staging buffer: fresh `vec![0;n]` per read vs reused scratch ──
//
// FileByteDevice::read_exact_at, for a sub-`file_device_direct_read_min` read,
// stages into a scratch buffer (to preserve the destination on a short-read
// error) then copies to the caller's buffer. The old code did `vec![0; n]` per
// read — an alloc + zero-init that the positioned read overwrites in full. A
// per-thread reused buffer drops the alloc+memset. Both arms do the same
// device-fill memcpy (modelled as a copy from `src`) and the same copy to the
// destination, so the delta isolates exactly the eliminated per-read alloc+memset.
fn bench_file_read_staging(c: &mut Criterion) {
    // Stand-in for the bytes the positioned read deposits into the staging slot.
    let src = vec![0x5A_u8; BLOCK_SIZE];
    let mut dst_fresh = vec![0_u8; BLOCK_SIZE];
    let mut dst_reused = vec![0_u8; BLOCK_SIZE];

    // Byte-identity: both strategies land the same bytes in the destination.
    {
        let mut staging = vec![0_u8; BLOCK_SIZE];
        staging.copy_from_slice(&src);
        dst_fresh.copy_from_slice(&staging);
        let mut reused = vec![0_u8; BLOCK_SIZE];
        reused[..BLOCK_SIZE].copy_from_slice(&src);
        dst_reused.copy_from_slice(&reused[..BLOCK_SIZE]);
        assert_eq!(dst_fresh, dst_reused, "staging strategy changed the bytes");
    }

    c.bench_function("file_read_staging_fresh_a", |b| {
        b.iter(|| {
            let mut staging = vec![0_u8; BLOCK_SIZE];
            staging.copy_from_slice(black_box(&src));
            dst_fresh.copy_from_slice(&staging);
            black_box(dst_fresh[0])
        });
    });
    c.bench_function("file_read_staging_fresh_b", |b| {
        b.iter(|| {
            let mut staging = vec![0_u8; BLOCK_SIZE];
            staging.copy_from_slice(black_box(&src));
            dst_fresh.copy_from_slice(&staging);
            black_box(dst_fresh[0])
        });
    });

    let mut reused = vec![0_u8; BLOCK_SIZE];
    c.bench_function("file_read_staging_reused", |b| {
        b.iter(|| {
            if reused.len() < BLOCK_SIZE {
                reused.resize(BLOCK_SIZE, 0);
            }
            let slot = &mut reused[..BLOCK_SIZE];
            slot.copy_from_slice(black_box(&src));
            dst_reused.copy_from_slice(slot);
            black_box(dst_reused[0])
        });
    });
}

// ── read_block: staged read-then-copy vs volatile direct read ───────────────
//
// ByteBlockDevice::read_block reads a fresh, throwaway BlockBuf. When the inner
// device stages small reads (FileByteDevice), the old `read_exact_at` filled a
// staging slot then copied it into the block buffer — two block-sized memcpys.
// `read_exact_at_volatile` reads straight into the buffer (it is discarded on
// error, so no destination-preservation is needed), leaving one memcpy. Both
// allocate the same BlockBuf; the delta is the eliminated staging→buffer copy.
fn bench_read_block_staged_vs_direct(c: &mut Criterion) {
    // Stand-in for the bytes the positioned read deposits.
    let src = vec![0x5A_u8; BLOCK_SIZE];
    let mut staging = vec![0_u8; BLOCK_SIZE]; // reused staging (post-3188e083)

    {
        let mut a = BlockBuf::zeroed(BLOCK_SIZE);
        staging.copy_from_slice(&src);
        a.make_mut().copy_from_slice(&staging);
        let mut b = BlockBuf::zeroed(BLOCK_SIZE);
        b.make_mut().copy_from_slice(&src);
        assert_eq!(
            a.as_slice(),
            b.as_slice(),
            "read_block strategy changed bytes"
        );
    }

    c.bench_function("read_block_staged_a", |b| {
        b.iter(|| {
            let mut buf = BlockBuf::zeroed(BLOCK_SIZE);
            staging.copy_from_slice(black_box(&src));
            buf.make_mut().copy_from_slice(&staging);
            black_box(buf.as_slice()[0])
        });
    });
    c.bench_function("read_block_staged_b", |b| {
        b.iter(|| {
            let mut buf = BlockBuf::zeroed(BLOCK_SIZE);
            staging.copy_from_slice(black_box(&src));
            buf.make_mut().copy_from_slice(&staging);
            black_box(buf.as_slice()[0])
        });
    });
    c.bench_function("read_block_direct", |b| {
        b.iter(|| {
            let mut buf = BlockBuf::zeroed(BLOCK_SIZE);
            buf.make_mut().copy_from_slice(black_box(&src));
            black_box(buf.as_slice()[0])
        });
    });
}

criterion_group!(
    benches,
    bench_block_buf_construct,
    bench_file_read_staging,
    bench_read_block_staged_vs_direct
);
criterion_main!(benches);
