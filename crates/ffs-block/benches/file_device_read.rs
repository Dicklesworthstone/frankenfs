#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::significant_drop_tightening)]

//! Same-machine A/B for the `FileByteDevice::read_exact_at` direct-read lever.
//!
//! `FileByteDevice` advertises `preserves_read_exact_at_destination_on_error`,
//! so `ByteBlockDevice::read_contiguous_into` passes the caller's output buffer
//! straight down to `read_exact_at`. The question this bench isolates is what
//! `read_exact_at` then does with that buffer:
//!
//! * `staged_scratch` — the pre-lever shape: allocate `vec![0; len]`, `pread`
//!   into the scratch, then `copy_from_slice` into the caller buffer. That is a
//!   per-read heap allocation + zero-init (memset) + a second memcpy on top of
//!   the single `pread`.
//! * `direct` — the post-lever shape (the real `FileByteDevice`): one `pread`
//!   straight into the caller buffer. No scratch, no memset, no second copy.
//!
//! Both deposit byte-identical data; the delta isolates exactly the eliminated
//! allocation + memset + memmove. The file is read warm (page-cache resident),
//! so the `pread` itself is a cheap cache copy and the userspace overhead — the
//! thing the lever removes — dominates the signal. Running both arms in one
//! binary keeps the comparison on a single CPU.

use asupersync::Cx;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ffs_block::{ByteDevice, FileByteDevice};
use ffs_types::ByteOffset;
use std::hint::black_box;
use std::io::{IoSliceMut, Write};
use std::os::unix::fs::FileExt;

const SPAN: usize = 4096 * 256; // a 1 MiB contiguous read, matching read_contiguous.rs

// Vectored A/B (bd-xmh5g.410): 128 KiB run scattered into 32 block-sized buffers
// (the `read_contiguous_blocks_into` shape; 128 KiB >= the 64 KiB direct gate).
const VBLOCKS: usize = 32;
const VBLK: usize = 4096;
const VSPAN: usize = VBLOCKS * VBLK;

fn main_bench(c: &mut Criterion) {
    // A real file, filled with non-zero data so a missed copy is visible, then
    // warmed into the page cache.
    let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let data: Vec<u8> = (0..SPAN).map(|i| (i * 31 + 7) as u8).collect();
    tmp.write_all(&data).expect("write");
    tmp.flush().expect("flush");
    let path = tmp.path().to_owned();

    let dev = FileByteDevice::open(&path).expect("open device");
    let raw = std::fs::File::open(&path).expect("open raw");
    let cx = Cx::for_testing();

    // Equivalence + warm the cache.
    let mut out_direct = vec![0_u8; SPAN];
    dev.read_exact_at(&cx, ByteOffset(0), &mut out_direct)
        .expect("direct read");
    assert_eq!(out_direct, data, "direct read must match");

    let mut group = c.benchmark_group("file_device_read_1mib");

    // Pre-lever: scratch Vec + zero-init + pread + memcpy into the caller buffer.
    group.bench_function("staged_scratch", |b| {
        b.iter(|| {
            let mut out = vec![0_u8; SPAN];
            let mut scratch = vec![0_u8; SPAN];
            raw.read_exact_at(scratch.as_mut_slice(), 0).unwrap();
            out.copy_from_slice(scratch.as_slice());
            black_box(out)
        });
    });

    // Post-lever: the real FileByteDevice reads one pread straight into `out`.
    group.bench_function("direct", |b| {
        b.iter(|| {
            let mut out = vec![0_u8; SPAN];
            dev.read_exact_at(black_box(&cx), ByteOffset(0), &mut out)
                .unwrap();
            black_box(out)
        });
    });

    group.finish();

    // ── Vectored A/B (bd-xmh5g.410): scatter a 128 KiB contiguous run into 32
    //    block-sized buffers (the `read_contiguous_blocks_into` shape). ──
    let mut vgroup = c.benchmark_group("file_device_vectored_read_128k");

    // Old shape: one big zeroed staging Vec + one pread + scatter-copy into the
    // 32 per-block buffers.
    vgroup.bench_function("staged_scratch_scatter", |b| {
        b.iter(|| {
            let mut bufs: Vec<Vec<u8>> = (0..VBLOCKS).map(|_| vec![0_u8; VBLK]).collect();
            let mut scratch = vec![0_u8; VSPAN];
            raw.read_exact_at(scratch.as_mut_slice(), 0).unwrap();
            let mut off = 0usize;
            for buf in &mut bufs {
                buf.copy_from_slice(&scratch[off..off + VBLK]);
                off += VBLK;
            }
            black_box(bufs)
        });
    });

    // New shape: the real FileByteDevice scatters straight into the buffers via
    // a single positioned `preadv` — no scratch, no zero-init, no scatter-copy.
    vgroup.bench_function("preadv_direct", |b| {
        b.iter(|| {
            let mut bufs: Vec<Vec<u8>> = (0..VBLOCKS).map(|_| vec![0_u8; VBLK]).collect();
            {
                let mut slices: Vec<IoSliceMut<'_>> =
                    bufs.iter_mut().map(|b| IoSliceMut::new(b)).collect();
                dev.read_vectored_exact_at(black_box(&cx), ByteOffset(0), &mut slices)
                    .unwrap();
            }
            black_box(bufs)
        });
    });

    vgroup.finish();

    // A one-iovec direct read has the same byte destination and one-syscall
    // contract under either dispatch. Prove equality before timing the syscall
    // primitive without destination-allocation noise.
    let mut preadv_out = vec![0_u8; VSPAN];
    let mut preadv_iov = [IoSliceMut::new(&mut preadv_out)];
    let preadv_read = nix::sys::uio::preadv(&raw, &mut preadv_iov, 0).expect("preadv parity");
    let mut scalar_out = vec![0_u8; VSPAN];
    let scalar_read = nix::sys::uio::pread(&raw, &mut scalar_out, 0).expect("pread parity");
    assert_eq!(preadv_read, VSPAN);
    assert_eq!(scalar_read, preadv_read);
    assert_eq!(scalar_out, preadv_out);
    assert_eq!(scalar_out, data[..VSPAN]);

    let mut single = c.benchmark_group("file_device_single_iovec_128k");
    for control in ["preadv_one_iovec_a", "preadv_one_iovec_b"] {
        single.bench_function(control, |b| {
            b.iter_batched(
                || vec![0_u8; VSPAN],
                |mut out| {
                    let mut iov = [IoSliceMut::new(&mut out)];
                    black_box(nix::sys::uio::preadv(&raw, &mut iov, 0).expect("preadv"))
                },
                BatchSize::SmallInput,
            );
        });
    }
    single.bench_function("pread_one_buffer", |b| {
        b.iter_batched(
            || vec![0_u8; VSPAN],
            |mut out| black_box(nix::sys::uio::pread(&raw, &mut out, 0).expect("pread")),
            BatchSize::SmallInput,
        );
    });
    single.finish();
}

criterion_group!(file_device_read, main_bench);
criterion_main!(file_device_read);
