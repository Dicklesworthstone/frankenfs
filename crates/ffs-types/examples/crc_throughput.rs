#![forbid(unsafe_code)]
//! crc32c throughput probe — is the checksum path (btrfs verifies crc32c on every
//! tree/data block read; ext4 metadata too) hardware-accelerated or a software
//! bottleneck worth a lever? The `crc32c` crate auto-detects SSE4.2 at runtime;
//! this confirms empirically. Hardware (SSE4.2 `crc32` instruction) sustains
//! ~10-25 GB/s; a software table fallback is ~0.3-1 GB/s. At a ~2 GB/s btrfs read,
//! a software crc would dominate (verify slower than the read); hardware makes it
//! a few percent. Run: `cargo run --release --example crc_throughput`.

use ffs_types::crc32c;
use std::time::Instant;

fn main() {
    // 64 MiB buffer, non-trivial content so the crc actually churns.
    //
    // The LCG is deliberately explicit `u32` wrapping arithmetic (bd-wc78p). It
    // used to read `(i * 1103515245 + 12345) as u8` on an inferred `i32`, which
    // OVERFLOWS: `i` reaches 67,108,863, so the multiply leaves `i32` range almost
    // immediately and this example panicked outright in a debug build. It only
    // appeared to work because it is documented to be run with `--release`, where
    // the overflow wraps silently. Taking the low byte via `to_ne_bytes()` instead
    // of `as u8` also keeps the generator free of lossy casts.
    let n: u32 = 64 * 1024 * 1024;
    let buf: Vec<u8> = (0..n)
        .map(|i| {
            i.wrapping_mul(1_103_515_245)
                .wrapping_add(12_345)
                .to_ne_bytes()[0]
        })
        .collect();
    // Warm.
    let _ = std::hint::black_box(crc32c(&buf[..1024]));

    let iters: u32 = 20;
    let start = Instant::now();
    let mut acc = 0u32;
    for _ in 0..iters {
        acc = acc.wrapping_add(crc32c(std::hint::black_box(&buf)));
    }
    std::hint::black_box(acc);
    let secs = start.elapsed().as_secs_f64();
    let gib = (f64::from(n) * f64::from(iters)) / (1024.0 * 1024.0 * 1024.0);
    let gbps = gib / secs;
    println!(
        "crc32c: {gib:.2} GiB in {:.3}s = {gbps:.2} GiB/s  ({})",
        secs,
        if gbps > 4.0 {
            "HARDWARE (SSE4.2) — no lever"
        } else {
            "SOFTWARE fallback — possible lever"
        }
    );
}
