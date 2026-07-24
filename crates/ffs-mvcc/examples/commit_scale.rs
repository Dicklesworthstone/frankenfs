#![forbid(unsafe_code)]
//! Sharded MVCC disjoint-writer commit scaling probe (bd-bhh0i localization).
//!
//! The parallel-metadata-write gap (8.3x vs kernel @8t) is the per-op commit
//! coordination in `ShardedMvccStore`. The existing `sharded_mvcc_disjoint`
//! bench only sweeps 8/16/32 writers — no low-count baseline to see WHERE
//! scaling breaks. This sweeps 1..=32 disjoint writers (each committing
//! one-block txns into its own block range, mirroring the bench) and reports
//! commits/sec plus per-writer efficiency vs the 1-writer serial baseline.
//! A flat per-writer throughput = perfect scaling (commit is parallel); a
//! collapsing per-writer throughput pinpoints the serialization ceiling (the
//! global publication `wait_lock` / `active_snapshots` lock vs the per-shard
//! RwLock). Relative (per-writer efficiency) so it is robust to box load.
//!
//! Run: cargo run --release --example commit_scale -- [ops_per_writer]

use ffs_mvcc::sharded::ShardedMvccStore;
use ffs_types::BlockNumber;
use std::sync::{Arc, Barrier};
use std::time::Instant;

fn run(writers: usize, ops_per_writer: u64, disjoint_shards: bool) -> f64 {
    let block_data = vec![0xAB_u8; 4096];
    let blocks_per_writer = 4096_u64;
    let store = Arc::new(ShardedMvccStore::for_host_parallelism());
    let barrier = Arc::new(Barrier::new(writers + 1));
    let nwriters = writers as u64;
    let mut handles = Vec::with_capacity(writers);
    for writer_id in 0..writers {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let data = block_data.clone();
        handles.push(std::thread::spawn(move || {
            let wid = writer_id as u64;
            let base = wid.saturating_mul(blocks_per_writer);
            barrier.wait();
            for i in 0..ops_per_writer {
                // `alias` (default): block = w*4096 + (i%4096). Because 4096 is a
                // multiple of the shard count, shard = i & mask — SAME for every
                // writer (in-phase same-shard convoy; the bd-bhh0i bench's flaw).
                // `disjoint_shards`: block = i*W + w, so at any fixed i the
                // writers occupy DISTINCT shards (offset by w) — true per-shard
                // parallelism, isolating the global publication-gate cost.
                let block = if disjoint_shards {
                    i.saturating_mul(nwriters).saturating_add(wid)
                } else {
                    base + (i % blocks_per_writer)
                };
                let mut txn = store.begin();
                txn.stage_write(BlockNumber(block), data.clone());
                let seq = store.commit(txn).expect("disjoint commit");
                std::hint::black_box(seq);
            }
        }));
    }
    barrier.wait(); // release all writers together; time only the commit phase
    let start = Instant::now();
    for h in handles {
        h.join().expect("writer thread");
    }
    let secs = start.elapsed().as_secs_f64();
    std::hint::black_box(store.current_snapshot());
    (writers as f64 * ops_per_writer as f64) / secs // total commits/sec
}

fn sweep(ops: u64, disjoint: bool) {
    let _ = run(1, ops / 10, disjoint); // warm
    let base = run(1, ops, disjoint);
    let layout = if disjoint {
        "SHARD-DISJOINT (block=i*W+w)"
    } else {
        "ALIASED (block=w*4096+i, bench default)"
    };
    println!("# layout={layout}  ops/writer={ops}");
    println!("writers=1   commits/s={base:>10.0}  per_writer={base:>9.0}  eff=1.00 (baseline)");
    for &w in &[2usize, 4, 8, 16, 32] {
        let total = run(w, ops, disjoint);
        let per = total / w as f64;
        let eff = per / base; // 1.0 = perfect linear scaling; ->0 = full serialization
        println!(
            "writers={w:<3} commits/s={total:>10.0}  per_writer={per:>9.0}  eff={eff:.2} ({})",
            if eff > 0.7 {
                "scales"
            } else if eff > 0.35 {
                "partial"
            } else {
                "SERIALIZED"
            }
        );
    }
}

fn main() {
    let ops: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);
    // A/B the two block layouts to separate per-shard-lock convoy (aliased) from
    // the global publication-gate cost (shard-disjoint).
    sweep(ops, false);
    println!();
    sweep(ops, true);
}
