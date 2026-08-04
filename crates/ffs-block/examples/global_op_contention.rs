#![forbid(unsafe_code)]
//! Per-op contention of the global accesses a sharded MVCC `commit` makes on
//! EVERY op (bd-bhh0i localization, non-invasive). After the publication-gate
//! thundering-herd fix measured INERT (docs/NEGATIVE_EVIDENCE.md), the remaining
//! per-commit GLOBAL touches are: `next_commit` AtomicU64 `fetch_add` (assigns a
//! unique monotonic seq — UNAVOIDABLE), and `effective_policy()` reading
//! `conflict_policy: RwLock<ConflictPolicy>` (a candidate to make lock-free via
//! AtomicU8). This isolates their per-op cost at 1/8/32 threads so we can tell
//! whether dropping the RwLock read is worthwhile vs the fetch_add floor:
//!   - fetch_add  : models `next_commit` (the irreducible global counter)
//!   - rwlock_read: models the current `effective_policy` RwLock read
//!   - atomic_load: models the proposed AtomicU8 lock-free policy read
//!
//! Reports per-op ns at each thread count; scaling (8t/1t, 32t/1t) shows
//! contention. If rwlock_read >> fetch_add at 32t, the AtomicU8 lever is real;
//! if rwlock_read ~ fetch_add, the floor is the counter and the lever is moot.

use parking_lot::RwLock;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Instant;

fn bench<F: Fn() -> u64 + Send + Sync + 'static>(threads: usize, per: u64, op: &Arc<F>) -> f64 {
    let barrier = Arc::new(std::sync::Barrier::new(threads + 1));
    let mut handles = Vec::new();
    for _ in 0..threads {
        let op = Arc::clone(op);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let mut acc = 0u64;
            for _ in 0..per {
                acc = acc.wrapping_add(op());
            }
            std::hint::black_box(acc);
        }));
    }
    barrier.wait();
    let start = Instant::now();
    for h in handles {
        h.join().unwrap();
    }
    let secs = start.elapsed().as_secs_f64();
    secs * 1e9 / (threads as f64 * per as f64) // ns per op (aggregate)
}

fn main() {
    let per: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000_000);

    let counter = Arc::new(AtomicU64::new(0));
    let rwlock = Arc::new(RwLock::new(1u8));
    let atom8 = Arc::new(AtomicU8::new(1));

    let c1 = Arc::clone(&counter);
    let fetch_add = Arc::new(move || c1.fetch_add(1, Ordering::Relaxed));
    let r1 = Arc::clone(&rwlock);
    let rwlock_read = Arc::new(move || u64::from(*r1.read()));
    let a1 = Arc::clone(&atom8);
    let atomic_load = Arc::new(move || u64::from(a1.load(Ordering::Relaxed)));

    println!(
        "# per-op ns of global commit accesses at T threads (lower=better; flat across T=no contention)"
    );
    for (name, mk) in [
        ("fetch_add  (next_commit, UNAVOIDABLE)", 0u8),
        ("rwlock_read(effective_policy, current)", 1u8),
        ("atomic_load(proposed AtomicU8 policy) ", 2u8),
    ] {
        let mut row = format!("{name}:");
        let mut base = 0.0;
        for (idx, &t) in [1usize, 8, 32].iter().enumerate() {
            let ns = match mk {
                0 => bench(t, per / t as u64, &fetch_add),
                1 => bench(t, per / t as u64, &rwlock_read),
                _ => bench(t, per / t as u64, &atomic_load),
            };
            if idx == 0 {
                base = ns;
            }
            let _ = write!(row, "  {t}t={ns:6.2}ns({:.1}x)", ns / base);
        }
        println!("{row}");
    }
}
