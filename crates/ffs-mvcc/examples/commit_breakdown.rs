#![forbid(unsafe_code)]
//! Single-thread per-op cost decomposition of a sharded MVCC commit (bd-bhh0i).
//!
//! Prior work proved bd-bhh0i is NOT lock-bound (every commit lock is ns-scale;
//! the commit is µs-scale — see docs/NEGATIVE_EVIDENCE.md). This isolates WHERE
//! the µs go at 1 thread (no contention, pure per-op WORK), to pinpoint the
//! allocation to kill:
//!   A. begin + drop              -> Transaction allocation (snapshot, write_set)
//!   B. begin + stage_write + drop -> A + write_set insert + 4 KiB payload alloc
//!   C. begin + stage_write + commit -> B + version install (BTreeMap insert,
//!                                       Vec<BlockVersion> alloc) + publish
//! Deltas: (B-A)=stage+payload, (C-B)=version-store install, A=begin. Run with
//! DISTINCT blocks (each commit a fresh BlockNumber) to match the disjoint
//! workload whose per-op cost dominates. `cargo run --release --example
//! commit_breakdown -- [ops]`.

use ffs_mvcc::sharded::ShardedMvccStore;
use ffs_types::BlockNumber;
use std::time::Instant;

fn main() {
    let ops: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);
    let payload = vec![0xAB_u8; 4096];

    // A: begin + drop
    let store = ShardedMvccStore::for_host_parallelism();
    let _ = store.begin(); // warm
    let start = Instant::now();
    for _ in 0..ops {
        let t = store.begin();
        std::hint::black_box(&t);
    }
    let a = start.elapsed().as_secs_f64() * 1e9 / ops as f64;

    // B: begin + stage_write + drop (distinct blocks)
    let store = ShardedMvccStore::for_host_parallelism();
    let start = Instant::now();
    for i in 0..ops {
        let mut t = store.begin();
        t.stage_write(BlockNumber(i), payload.clone());
        std::hint::black_box(&t);
    }
    let b = start.elapsed().as_secs_f64() * 1e9 / ops as f64;

    // C: begin + stage_write + commit (distinct blocks)
    let store = ShardedMvccStore::for_host_parallelism();
    let start = Instant::now();
    for i in 0..ops {
        let mut t = store.begin();
        t.stage_write(BlockNumber(i), payload.clone());
        let seq = store.commit(t).expect("commit");
        std::hint::black_box(seq);
    }
    let c = start.elapsed().as_secs_f64() * 1e9 / ops as f64;

    println!("# single-thread per-op cost decomposition (ns/op), distinct blocks, ops={ops}");
    println!("A begin+drop            = {a:8.0} ns/op   (Transaction alloc)");
    println!(
        "B begin+stage+drop      = {b:8.0} ns/op   (+stage = {:.0} ns: write_set + 4KiB payload)",
        b - a
    );
    println!(
        "C begin+stage+commit    = {c:8.0} ns/op   (+install/publish = {:.0} ns: version store)",
        c - b
    );
}
