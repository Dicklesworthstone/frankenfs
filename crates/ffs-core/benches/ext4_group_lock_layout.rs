#![forbid(unsafe_code)]

//! False-sharing guard for the bd-bhh0i per-group allocator refactor.
//!
//! The production gap is the global `RwLock<Ext4AllocState>::write` convoy.
//! Prior evidence says the real fix is per-group ownership. This benchmark
//! measures one design detail for that future layout: if the per-group hot lock
//! words and counters are stored adjacently, disjoint groups can still bounce the
//! same cache lines. Cache-line padding should remove that residual convoy.

use criterion::{Criterion, criterion_group, criterion_main};
use parking_lot::Mutex;
use std::hint::black_box;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

const GROUPS: usize = 8;
const THREADS: usize = GROUPS;
const OPS_PER_THREAD: usize = 50_000;
const COUNTER_THREADS: usize = 16;
const COUNTER_OPS_PER_THREAD: usize = 20_000;

#[derive(Clone)]
struct GroupHotStats {
    free_blocks: u32,
    free_inodes: u32,
    used_dirs: u32,
    cursor: u64,
}

impl GroupHotStats {
    fn new(group: usize) -> Self {
        Self {
            free_blocks: 1_000_000,
            free_inodes: 1_000_000 - u32::try_from(group).expect("group fits u32"),
            used_dirs: u32::try_from(group).expect("group fits u32"),
            cursor: (group as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        }
    }

    fn account_create(&mut self, op: usize) -> u64 {
        self.free_inodes = self.free_inodes.wrapping_sub(1);
        self.free_blocks = self.free_blocks.wrapping_sub(u32::from(op & 1 == 1));
        self.used_dirs = self
            .used_dirs
            .wrapping_add(u32::from(op.trailing_zeros() >= 2));
        self.cursor = self
            .cursor
            .wrapping_add(u64::from(self.free_inodes))
            .rotate_left(u32::try_from(op).expect("op fits u32") & 31)
            ^ u64::from(self.free_blocks);
        self.cursor ^ u64::from(self.used_dirs)
    }
}

struct PlainGroup {
    stats: Mutex<GroupHotStats>,
}

#[repr(align(64))]
struct PaddedGroup {
    stats: Mutex<GroupHotStats>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CounterTotals {
    free_blocks_delta: i64,
    free_inodes_delta: i64,
    used_dirs_delta: i64,
    digest: u64,
}

impl CounterTotals {
    fn apply(&mut self, delta: Self) {
        self.free_blocks_delta = self.free_blocks_delta.wrapping_add(delta.free_blocks_delta);
        self.free_inodes_delta = self.free_inodes_delta.wrapping_add(delta.free_inodes_delta);
        self.used_dirs_delta = self.used_dirs_delta.wrapping_add(delta.used_dirs_delta);
        self.digest = self.digest.wrapping_add(delta.digest);
    }
}

#[repr(align(64))]
struct DeltaBucket {
    free_blocks_delta: AtomicI64,
    free_inodes_delta: AtomicI64,
    used_dirs_delta: AtomicI64,
    digest: AtomicU64,
}

impl DeltaBucket {
    fn new() -> Self {
        Self {
            free_blocks_delta: AtomicI64::new(0),
            free_inodes_delta: AtomicI64::new(0),
            used_dirs_delta: AtomicI64::new(0),
            digest: AtomicU64::new(0),
        }
    }

    fn store(&self, totals: CounterTotals) {
        self.free_blocks_delta
            .store(totals.free_blocks_delta, Ordering::Relaxed);
        self.free_inodes_delta
            .store(totals.free_inodes_delta, Ordering::Relaxed);
        self.used_dirs_delta
            .store(totals.used_dirs_delta, Ordering::Relaxed);
        self.digest.store(totals.digest, Ordering::Relaxed);
    }

    fn load(&self) -> CounterTotals {
        CounterTotals {
            free_blocks_delta: self.free_blocks_delta.load(Ordering::Relaxed),
            free_inodes_delta: self.free_inodes_delta.load(Ordering::Relaxed),
            used_dirs_delta: self.used_dirs_delta.load(Ordering::Relaxed),
            digest: self.digest.load(Ordering::Relaxed),
        }
    }
}

fn make_plain_groups() -> Arc<Vec<PlainGroup>> {
    Arc::new(
        (0..GROUPS)
            .map(|group| PlainGroup {
                stats: Mutex::new(GroupHotStats::new(group)),
            })
            .collect(),
    )
}

fn make_padded_groups() -> Arc<Vec<PaddedGroup>> {
    Arc::new(
        (0..GROUPS)
            .map(|group| PaddedGroup {
                stats: Mutex::new(GroupHotStats::new(group)),
            })
            .collect(),
    )
}

fn make_delta_buckets() -> Arc<Vec<DeltaBucket>> {
    Arc::new((0..COUNTER_THREADS).map(|_| DeltaBucket::new()).collect())
}

fn counter_delta(thread_id: usize, group: usize, op: usize) -> CounterTotals {
    let mix = (op as u64)
        .wrapping_mul(0xD6E8_FEB8_6659_FD93)
        .rotate_left(u32::try_from(thread_id + group).expect("mix shift fits u32") & 31)
        ^ ((group as u64) << 48)
        ^ thread_id as u64;
    CounterTotals {
        free_blocks_delta: -i64::from(op & 1 != 0),
        free_inodes_delta: -1,
        used_dirs_delta: i64::from(op.trailing_zeros() >= 2),
        digest: mix,
    }
}

fn run_plain_groups(groups: &Arc<Vec<PlainGroup>>) -> u64 {
    let start = Arc::new(Barrier::new(THREADS));
    let total = Arc::new(AtomicU64::new(0));
    std::thread::scope(|scope| {
        for group in 0..GROUPS {
            let groups = Arc::clone(groups);
            let start = Arc::clone(&start);
            let total = Arc::clone(&total);
            scope.spawn(move || {
                start.wait();
                let mut local = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let mut stats = groups[group].stats.lock();
                    local = local.wrapping_add(stats.account_create(op));
                }
                total.fetch_add(local, Ordering::Relaxed);
            });
        }
    });
    total.load(Ordering::Relaxed)
}

fn run_padded_groups(groups: &Arc<Vec<PaddedGroup>>) -> u64 {
    let start = Arc::new(Barrier::new(THREADS));
    let total = Arc::new(AtomicU64::new(0));
    std::thread::scope(|scope| {
        for group in 0..GROUPS {
            let groups = Arc::clone(groups);
            let start = Arc::clone(&start);
            let total = Arc::clone(&total);
            scope.spawn(move || {
                start.wait();
                let mut local = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let mut stats = groups[group].stats.lock();
                    local = local.wrapping_add(stats.account_create(op));
                }
                total.fetch_add(local, Ordering::Relaxed);
            });
        }
    });
    total.load(Ordering::Relaxed)
}

fn run_global_counter_mutex(state: &Arc<Mutex<Vec<CounterTotals>>>) -> Vec<CounterTotals> {
    let start = Arc::new(Barrier::new(COUNTER_THREADS));
    std::thread::scope(|scope| {
        for thread_id in 0..COUNTER_THREADS {
            let state = Arc::clone(state);
            let start = Arc::clone(&start);
            scope.spawn(move || {
                let group = thread_id % GROUPS;
                start.wait();
                for op in 0..COUNTER_OPS_PER_THREAD {
                    let mut totals = state.lock();
                    totals[group].apply(counter_delta(thread_id, group, black_box(op)));
                }
            });
        }
    });
    state.lock().clone()
}

fn run_per_thread_delta_buckets(buckets: &Arc<Vec<DeltaBucket>>) -> Vec<CounterTotals> {
    let start = Arc::new(Barrier::new(COUNTER_THREADS));
    std::thread::scope(|scope| {
        for thread_id in 0..COUNTER_THREADS {
            let buckets = Arc::clone(buckets);
            let start = Arc::clone(&start);
            scope.spawn(move || {
                let group = thread_id % GROUPS;
                let mut local = CounterTotals::default();
                start.wait();
                for op in 0..COUNTER_OPS_PER_THREAD {
                    local.apply(counter_delta(thread_id, group, black_box(op)));
                }
                buckets[thread_id].store(local);
            });
        }
    });

    let mut folded = vec![CounterTotals::default(); GROUPS];
    for (thread_id, bucket) in buckets.iter().enumerate() {
        folded[thread_id % GROUPS].apply(bucket.load());
    }
    folded
}

fn bench_ext4_group_lock_layout(c: &mut Criterion) {
    let expected = run_plain_groups(&make_plain_groups());
    assert_eq!(
        expected,
        run_padded_groups(&make_padded_groups()),
        "padding changed the synthetic accounting result"
    );
    assert_eq!(
        run_global_counter_mutex(&Arc::new(Mutex::new(vec![
            CounterTotals::default();
            GROUPS
        ]))),
        run_per_thread_delta_buckets(&make_delta_buckets()),
        "per-thread delta buckets changed additive counter totals"
    );

    let plain_groups = make_plain_groups();
    let padded_groups = make_padded_groups();
    let global_counters = Arc::new(Mutex::new(vec![CounterTotals::default(); GROUPS]));
    let delta_buckets = make_delta_buckets();

    {
        let mut group = c.benchmark_group("ext4_group_lock_layout_8t");
        group.bench_function("plain_adjacent_group_locks", |b| {
            b.iter(|| black_box(run_plain_groups(black_box(&plain_groups))));
        });
        group.bench_function("cacheline_padded_group_locks", |b| {
            b.iter(|| black_box(run_padded_groups(black_box(&padded_groups))));
        });
        group.finish();
    }

    let mut counter_group = c.benchmark_group("ext4_counter_delta_16t");
    counter_group.bench_function("global_counter_mutex", |b| {
        b.iter(|| black_box(run_global_counter_mutex(black_box(&global_counters))));
    });
    counter_group.bench_function("per_thread_delta_buckets", |b| {
        b.iter(|| black_box(run_per_thread_delta_buckets(black_box(&delta_buckets))));
    });
    counter_group.finish();
}

criterion_group!(benches, bench_ext4_group_lock_layout);
criterion_main!(benches);
