#![forbid(unsafe_code)]
//! Parallel `BlockBuf` allocation convoy probe (bd-bhh0i follow-up).
//!
//! IvoryBirch's bd-bhh0i profile flags a "malloc-arena convoy" on parallel
//! metadata writes and proposes thread-local block-buffer pooling. `BlockBuf`
//! (the buffer that path allocates) lives in ffs-block, so this probes the
//! hypothesis directly and in isolation: each thread allocates+zeros+touches+
//! drops `BlockBuf::zeroed(4096)` in a tight loop. If glibc's per-thread arenas
//! absorb these sub-mmap-threshold allocations, the per-thread alloc rate holds
//! flat from 1 to N threads (NO convoy → pooling lever is inert). If a shared
//! arena lock serializes them, the per-thread rate collapses with N (convoy →
//! pooling would help). Reports per-thread ns/alloc so the scaling is read
//! directly, robust to absolute-time jitter under box load (relative across N).
//!
//! Usage: cargo run --release --example alloc_convoy -- [allocs_per_thread] [threads...]

use ffs_block::BlockBuf;
use std::time::Instant;

fn run(threads: usize, per: usize, sz: usize) -> f64 {
    let start = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            std::thread::spawn(move || {
                let mut acc: u64 = 0;
                let mask = sz - 1;
                for i in 0..per {
                    let mut b = BlockBuf::zeroed(sz);
                    let s = b.make_mut();
                    // Touch one byte per 4 KiB page so a freshly-mmap'd buffer
                    // faults every page (the read path's first-touch cost), not
                    // just the alloc — exposes mmap_lock/page-table convoy.
                    let mut p = 0;
                    while p < sz {
                        s[p] = u8::try_from(i & 0xff)
                            .expect("masked to u8")
                            .wrapping_add(1);
                        acc = acc.wrapping_add(u64::from(s[p]));
                        p += 4096;
                    }
                    std::hint::black_box(&mask);
                    std::hint::black_box(&b);
                }
                acc
            })
        })
        .collect();
    let mut acc = 0u64;
    for h in handles {
        acc = acc.wrapping_add(h.join().expect("join"));
    }
    std::hint::black_box(acc);
    let elapsed = start.elapsed().as_secs_f64();
    let total = (threads * per) as f64;
    elapsed * 1e9 / total // ns per alloc (wall, aggregate)
}

fn main() {
    let mut args = std::env::args().skip(1);
    // bytes of total alloc work per thread (scaled into iterations per size).
    let work: usize = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4_000_000_000);
    let sizes: Vec<usize> = {
        let rest: Vec<usize> = args.filter_map(|s| s.parse().ok()).collect();
        if rest.is_empty() {
            // 4K (control, arena), 64K (arena), 128K (== glibc mmap threshold),
            // 256K (clearly mmap'd). The read path chunks at 128K (32 blocks).
            vec![4096, 65_536, 131_072, 262_144]
        } else {
            rest
        }
    };
    println!(
        "# parallel scaling of alloc+per-page-touch by buffer size (1/T decay = perfect; flat ~1.0 = convoy)"
    );
    for &sz in &sizes {
        let per = (work / sz).max(1000);
        let _ = run(1, per / 20, sz); // warm arenas for this size
        let base = run(1, per, sz);
        let ns8 = run(8, per, sz);
        let s8 = ns8 / base; // ideal perfect = 0.125
        println!(
            "size={:>7}B  per_thread={per:>8}  1t={base:7.1}ns  8t={ns8:7.1}ns  scaling_8t={s8:.3} (ideal 0.125; convoy ->1.0)  conv_index={:.2}x",
            sz,
            s8 * 8.0 // 1.0 = perfect parallel; ->8 = full serialization
        );
    }
}
