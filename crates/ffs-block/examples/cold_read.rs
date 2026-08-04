#![forbid(unsafe_code)]
//! Cold-read A/B harness for the `posix_fadvise` read-ahead lever (bd-5v3mh).
//!
//! Warm tmpfs benches cannot see read-ahead — the data is already page-cache
//! resident, so the kernel's prefetch window is irrelevant. This harness reads a
//! file on a REAL disk (e.g. /data ext4) through `FileByteDevice`, the exact
//! device the FS read path uses, so a `drop_caches` between runs exposes the
//! cold gap the warm path hides. The `FFS_READ_FADVISE` env var (read by
//! `FileByteDevice::open`) selects the advice; run the same binary twice with
//! different values, dropping caches before each, to A/B the lever.
//!
//! Usage:
//!   FFS_READ_FADVISE=sequential cargo run --release --example cold_read -- <path> [chunk_kib] [threads]
//!
//! Reads the whole file in `chunk_kib`-sized `read_exact_at` calls (default
//! 1024), optionally split across `threads` contiguous ranges (default 1, to
//! mirror the parallel chunk read of the real path). Prints elapsed + MiB/s and
//! a checksum byte so the read cannot be optimized away.
//!
//! ## Do NOT use `cat` as the kernel baseline (2026-07-09)
//!
//! On this box `cat` is an alias for `bat`, and `/usr/bin/cat` is uutils
//! coreutils — **both issue 832-byte `read()` calls**, so they measure syscall
//! overhead, not the kernel's cold read path. Measured on an 800 MiB dense
//! fixture on /data ext4 with `drop_caches=3` before every run: `cat` 2932 ms
//! (273 MiB/s) versus 513 ms (1558 MiB/s) for a plain 1 MiB-read loop over the
//! same file. Any "vs kernel `cat`" cold ratio taken here is off by ~6x.
//!
//! Use a pure read loop at the SAME chunk size instead — no output write, so it
//! is apples-to-apples with this harness (`dd ... of=/dev/null` also pays a
//! `write()` per block and reads ~20% slow):
//!
//! ```text
//! python3 -c 'import os,sys,time
//! fd=os.open(sys.argv[1],os.O_RDONLY); s=time.perf_counter()
//! while os.read(fd,1<<20): pass
//! print(f"{(time.perf_counter()-s)*1000:.1f} ms")' <path>
//! ```
//!
//! Box load dominates single reps (kernel arm cv≈19% at load 30); take min-of-N.
//!
//! ## A loop-mounted kernel is only a fair comparator with `--direct-io=on`
//!
//! A *buffered* loop device serializes I/O; a *direct-I/O* one does not. Same
//! 128 MiB (sha256-identical across arms), `drop_caches=3` before every run,
//! min-of-5, thread sweep against the same loop mount:
//!
//! ```text
//!   loop dio=0 (default)   t=1 97.7   t=8 124.2   t=32 113.6 ms   <- no scaling
//!   loop dio=1             t=1 52.1   t=8  25.1   t=32  28.2 ms   <- scales
//! ```
//!
//! That is a **4.9x difference at t=8 on identical bytes**, produced by one
//! ioctl. So the rule is NOT "never loop-mount the kernel side" — it is **give
//! the kernel its best configuration**:
//!
//! ```text
//!   sudo losetup --direct-io=on /dev/loopN     # then check /sys/block/loopN/loop/dio
//! ```
//!
//! Benchmarking against a *buffered* loop mount measures the loop's workqueue,
//! not the kernel's ext4, and manufactures a phantom frankenfs win.
//!
//! ## Calibrate the buffered-vs-direct asymmetry before trusting a ratio
//!
//! `ffs-cli read` preads the image file *buffered*, while a dio loop reads the
//! backing file *direct* — different I/O modes. Bound that confound with a third
//! arm: a raw parallel `pread` of the same physical extents (buffered, no fs
//! parse). At t=32 it lands within **5.2%** of the dio-loop kernel (28.3 vs
//! 26.9 ms), so at high thread counts the mode difference is device-bound noise
//! and any larger gap is real. At t=1 it is NOT (109.5 vs 52.1 ms) — never take
//! a single-threaded buffered-vs-direct ratio at face value.
//!
//! ## Honest cold ext4 numbers (128 MiB extent file, 2 extents, real disk)
//!
//! ```text
//!   frankenfs  read      46.6 ms engine, 8.4 ms of which is per-open startup
//!                        (superblock + GDT + journal replay) -> 38.2 ms of read
//!   kernel     dio loop, t=32     26.9 ms   <- the kernel's best
//!   raw pread floor,     t=32     28.3 ms
//!   kernel     buffered loop, t=1 97.0 ms   <- what a `dd bs=1M` arm measures
//! ```
//!
//! frankenfs is **1.42x SLOWER than the kernel's best** (startup-corrected;
//! 2.64x on raw wall-clock) and **1.35x slower than a raw parallel `pread`** of
//! the same extents — that gap is the ext4 parse + safe-copy tax. Comparing it
//! instead against the buffered single-stream loop yields a bogus "2.54x
//! FASTER". Both framings are arithmetically correct; only the first is honest.
//! See bd-q6k00.

use asupersync::Cx;
use ffs_block::{ByteDevice, FileByteDevice};
use ffs_types::ByteOffset;
use std::sync::Arc;
use std::time::Instant;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .expect("usage: cold_read <path> [chunk_kib] [threads]");
    let chunk: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(1024) * 1024;
    let threads: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(1);
    // 4th arg: access pattern — "seq" (default) sweeps each thread's contiguous
    // range; "rand" does `len/chunk` reads at random chunk-aligned offsets across
    // the whole file (the random-read workload). The random arm answers whether
    // the default `POSIX_FADV_SEQUENTIAL` hint regresses random access (read
    // amplification) vs `none`/`random`.
    let pattern = args.next().unwrap_or_else(|| "seq".into());

    let dev = Arc::new(FileByteDevice::open(&path).expect("open device"));
    let len = dev.len_bytes();
    let mode = std::env::var("FFS_READ_FADVISE").unwrap_or_else(|_| "sequential(default)".into());

    let start = Instant::now();
    let per = len / threads as u64;
    let nchunks = len / chunk as u64; // chunk-aligned slots in the file
    let rand = pattern == "rand";
    let mut handles = Vec::new();
    for t in 0..threads {
        let dev = Arc::clone(&dev);
        let begin = per * t as u64;
        let end = if t + 1 == threads {
            len
        } else {
            per * (t as u64 + 1)
        };
        let pat_rand = rand;
        handles.push(std::thread::spawn(move || {
            let cx = Cx::for_testing();
            let mut buf = vec![0_u8; chunk];
            let mut sum: u64 = 0;
            if pat_rand {
                // Per-thread LCG (deterministic, no rand dep); each thread issues
                // `nchunks/threads` reads at random chunk-aligned offsets.
                let mut state: u64 = 0x9E37_79B9_7F4A_7C15 ^ (t as u64).wrapping_mul(0x0001_2345);
                let reads = (nchunks / threads as u64).max(1);
                for _ in 0..reads {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    let slot = if nchunks == 0 {
                        0
                    } else {
                        (state >> 33) % nchunks
                    };
                    let off = slot * chunk as u64;
                    let n = usize::try_from(std::cmp::min(chunk as u64, len - off))
                        .expect("chunk fits usize");
                    dev.read_exact_at(&cx, ByteOffset(off), &mut buf[..n])
                        .expect("read");
                    let mut i = 0;
                    while i < n {
                        sum = sum.wrapping_add(u64::from(buf[i]));
                        i += 4096;
                    }
                }
                return sum;
            }
            let mut off = begin;
            while off < end {
                let n = usize::try_from(std::cmp::min(chunk as u64, end - off))
                    .expect("chunk fits usize");
                dev.read_exact_at(&cx, ByteOffset(off), &mut buf[..n])
                    .expect("read");
                // Touch one byte per page so the read is not elided and pages fault.
                let mut i = 0;
                while i < n {
                    sum = sum.wrapping_add(u64::from(buf[i]));
                    i += 4096;
                }
                off += n as u64;
            }
            sum
        }));
    }
    let mut sum: u64 = 0;
    for h in handles {
        sum = sum.wrapping_add(h.join().expect("join"));
    }
    let elapsed = start.elapsed();
    let mib = len as f64 / (1024.0 * 1024.0);
    let secs = elapsed.as_secs_f64();
    println!(
        "fadvise={mode} pattern={pattern} threads={threads} chunk_kib={} bytes={len} elapsed_ms={:.2} MiB_s={:.1} cksum={sum}",
        chunk / 1024,
        secs * 1000.0,
        mib / secs,
    );
}
