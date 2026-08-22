#![forbid(unsafe_code)]

//! Synthetic A/B for the bd-bhh0i allocation-state convoy.
//!
//! The product gap is already localized to one global `RwLock<Ext4AllocState>`
//! taken in exclusive mode across metadata writes. This benchmark isolates the
//! lock topology from filesystem semantics: the same per-group accounting work
//! runs under (a) the current whole-state `RwLock::write`, (b) a whole-state
//! `Mutex`, (c) per-group `Mutex` shards, (d) a per-group atomic range lease,
//! and (e) a private per-thread/group delta fold. It is not a production proof
//! for sharding; it is a small guard that quantifies why lock-implementation
//! swaps cannot recover the measured bd-bhh0i gap while real sharding can.

use criterion::{Criterion, criterion_group, criterion_main};
use parking_lot::{Mutex, RwLock};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const GROUPS: usize = 8;
const THREADS: usize = 8;
const OPS_PER_THREAD: usize = 20_000;
const MICRO_BATCH: usize = 64;

#[derive(Clone)]
struct GroupModel {
    free_inodes: u64,
    checksum_words: [u64; 16],
}

impl GroupModel {
    fn new(group: usize) -> Self {
        let mut checksum_words = [0_u64; 16];
        for (idx, slot) in checksum_words.iter_mut().enumerate() {
            *slot = ((group as u64) << 32) ^ (idx as u64).wrapping_mul(0x9E37_79B9);
        }
        Self {
            free_inodes: 1_000_000,
            checksum_words,
        }
    }

    fn account_alloc(&mut self, op: usize) -> u64 {
        self.free_inodes = self.free_inodes.wrapping_sub(1);
        let lane = op & (self.checksum_words.len() - 1);
        let mix = (op as u64)
            .wrapping_mul(0xA24B_AED4_963E_E407)
            .rotate_left(u32::try_from(lane).expect("lane fits u32") & 31);
        self.checksum_words[lane] = self.checksum_words[lane]
            .wrapping_add(self.free_inodes)
            .rotate_left(7)
            ^ mix;
        self.checksum_words[lane]
    }
}

#[repr(align(64))]
struct AtomicGroupModel {
    free_inodes: AtomicU64,
    checksum_words: [AtomicU64; 16],
}

impl AtomicGroupModel {
    fn new(group: usize) -> Self {
        Self {
            free_inodes: AtomicU64::new(1_000_000),
            checksum_words: std::array::from_fn(|idx| {
                AtomicU64::new(((group as u64) << 32) ^ (idx as u64).wrapping_mul(0x9E37_79B9))
            }),
        }
    }

    fn account_alloc_range_lease(&self, start_op: usize, count: usize) -> u64 {
        let first_free_inode = self
            .free_inodes
            .fetch_sub(count as u64, Ordering::Relaxed)
            .wrapping_sub(1);
        let mut checksum_words: [u64; 16] =
            std::array::from_fn(|idx| self.checksum_words[idx].load(Ordering::Relaxed));
        let mut local = 0_u64;
        for offset in 0..count {
            let op = start_op + offset;
            let free_inodes = first_free_inode.wrapping_sub(offset as u64);
            let lane = op & (checksum_words.len() - 1);
            let mix = (op as u64)
                .wrapping_mul(0xA24B_AED4_963E_E407)
                .rotate_left(u32::try_from(lane).expect("lane fits u32") & 31);
            let next = checksum_words[lane]
                .wrapping_add(free_inodes)
                .rotate_left(7)
                ^ mix;
            checksum_words[lane] = next;
            local = local.wrapping_add(next);
        }
        for (idx, word) in checksum_words.into_iter().enumerate() {
            self.checksum_words[idx].store(word, Ordering::Relaxed);
        }
        local
    }
}

fn make_groups() -> Vec<GroupModel> {
    (0..GROUPS).map(GroupModel::new).collect()
}

fn make_atomic_groups() -> Arc<Vec<AtomicGroupModel>> {
    Arc::new((0..GROUPS).map(AtomicGroupModel::new).collect())
}

fn run_global_rwlock(state: &Arc<RwLock<Vec<GroupModel>>>) -> u64 {
    let total = Arc::new(AtomicU64::new(0));
    std::thread::scope(|scope| {
        for thread_id in 0..THREADS {
            let state = Arc::clone(state);
            let total = Arc::clone(&total);
            scope.spawn(move || {
                let group = thread_id % GROUPS;
                let mut local = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let mut groups = state.write();
                    local = local.wrapping_add(groups[group].account_alloc(op));
                }
                total.fetch_add(local, Ordering::Relaxed);
            });
        }
    });
    total.load(Ordering::Relaxed)
}

fn run_global_mutex(state: &Arc<Mutex<Vec<GroupModel>>>) -> u64 {
    let total = Arc::new(AtomicU64::new(0));
    std::thread::scope(|scope| {
        for thread_id in 0..THREADS {
            let state = Arc::clone(state);
            let total = Arc::clone(&total);
            scope.spawn(move || {
                let group = thread_id % GROUPS;
                let mut local = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let mut groups = state.lock();
                    local = local.wrapping_add(groups[group].account_alloc(op));
                }
                total.fetch_add(local, Ordering::Relaxed);
            });
        }
    });
    total.load(Ordering::Relaxed)
}

fn run_global_rwlock_microbatch(state: &Arc<RwLock<Vec<GroupModel>>>) -> u64 {
    let total = Arc::new(AtomicU64::new(0));
    std::thread::scope(|scope| {
        for thread_id in 0..THREADS {
            let state = Arc::clone(state);
            let total = Arc::clone(&total);
            scope.spawn(move || {
                let group = thread_id % GROUPS;
                let mut local = 0_u64;
                let mut op = 0;
                while op < OPS_PER_THREAD {
                    let end = (op + MICRO_BATCH).min(OPS_PER_THREAD);
                    {
                        let mut groups = state.write();
                        for batched_op in op..end {
                            local = local.wrapping_add(groups[group].account_alloc(batched_op));
                        }
                    }
                    op = end;
                }
                total.fetch_add(local, Ordering::Relaxed);
            });
        }
    });
    total.load(Ordering::Relaxed)
}

fn run_sharded_mutex(state: &Arc<Vec<Mutex<GroupModel>>>) -> u64 {
    let total = Arc::new(AtomicU64::new(0));
    std::thread::scope(|scope| {
        for thread_id in 0..THREADS {
            let state = Arc::clone(state);
            let total = Arc::clone(&total);
            scope.spawn(move || {
                let group = thread_id % GROUPS;
                let mut local = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let mut group_state = state[group].lock();
                    local = local.wrapping_add(group_state.account_alloc(op));
                }
                total.fetch_add(local, Ordering::Relaxed);
            });
        }
    });
    total.load(Ordering::Relaxed)
}

fn run_per_group_atomic_range_lease(state: &Arc<Vec<AtomicGroupModel>>) -> u64 {
    let total = Arc::new(AtomicU64::new(0));
    std::thread::scope(|scope| {
        for thread_id in 0..THREADS {
            let state = Arc::clone(state);
            let total = Arc::clone(&total);
            scope.spawn(move || {
                let group = thread_id % GROUPS;
                let local = state[group].account_alloc_range_lease(0, OPS_PER_THREAD);
                total.fetch_add(local, Ordering::Relaxed);
            });
        }
    });
    total.load(Ordering::Relaxed)
}

fn run_per_thread_group_delta_fold() -> u64 {
    let total = Arc::new(AtomicU64::new(0));
    let published = Arc::new(
        (0..GROUPS)
            .map(|group| Mutex::new(GroupModel::new(group)))
            .collect::<Vec<_>>(),
    );

    std::thread::scope(|scope| {
        for thread_id in 0..THREADS {
            let total = Arc::clone(&total);
            let published = Arc::clone(&published);
            scope.spawn(move || {
                let group = thread_id % GROUPS;
                let mut local_group = GroupModel::new(group);
                let mut local = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    local = local.wrapping_add(local_group.account_alloc(op));
                }
                *published[group].lock() = local_group;
                total.fetch_add(local, Ordering::Relaxed);
            });
        }
    });

    let mut digest = 0_u64;
    for group in published.iter() {
        let group = group.lock();
        digest = digest.wrapping_add(group.free_inodes);
        for word in group.checksum_words {
            digest ^= word.rotate_left((word & 31) as u32);
        }
    }
    black_box(digest);

    total.load(Ordering::Relaxed)
}

fn bench_ext4_alloc_lock_convoy(c: &mut Criterion) {
    let rwlock_probe = Arc::new(RwLock::new(make_groups()));
    let mutex_probe = Arc::new(Mutex::new(make_groups()));
    let microbatch_probe = Arc::new(RwLock::new(make_groups()));
    let sharded_probe = Arc::new(
        make_groups()
            .into_iter()
            .map(Mutex::new)
            .collect::<Vec<_>>(),
    );
    let atomic_probe = make_atomic_groups();

    let expected = run_global_rwlock(&Arc::new(RwLock::new(make_groups())));
    assert_eq!(
        expected,
        run_global_mutex(&Arc::new(Mutex::new(make_groups()))),
        "global mutex changed accounting result"
    );
    assert_eq!(
        expected,
        run_global_rwlock_microbatch(&Arc::new(RwLock::new(make_groups()))),
        "microbatched global rwlock changed accounting result"
    );
    assert_eq!(
        expected,
        run_sharded_mutex(&Arc::new(
            make_groups()
                .into_iter()
                .map(Mutex::new)
                .collect::<Vec<_>>()
        )),
        "sharded mutex changed accounting result"
    );
    assert_eq!(
        expected,
        run_per_group_atomic_range_lease(&make_atomic_groups()),
        "per-group atomic range-lease model changed accounting result"
    );
    assert_eq!(
        expected,
        run_per_thread_group_delta_fold(),
        "per-thread/group delta-fold model changed accounting result"
    );

    let mut group = c.benchmark_group("ext4_alloc_lock_convoy_8t");
    group.bench_function("global_rwlock_write", |b| {
        b.iter(|| black_box(run_global_rwlock(black_box(&rwlock_probe))));
    });
    group.bench_function("global_mutex", |b| {
        b.iter(|| black_box(run_global_mutex(black_box(&mutex_probe))));
    });
    group.bench_function("global_rwlock_microbatch_64", |b| {
        b.iter(|| black_box(run_global_rwlock_microbatch(black_box(&microbatch_probe))));
    });
    group.bench_function("sharded_group_mutex", |b| {
        b.iter(|| black_box(run_sharded_mutex(black_box(&sharded_probe))));
    });
    group.bench_function("per_group_atomic_range_lease", |b| {
        b.iter(|| black_box(run_per_group_atomic_range_lease(black_box(&atomic_probe))));
    });
    group.bench_function("per_thread_group_delta_fold", |b| {
        b.iter(|| black_box(run_per_thread_group_delta_fold()));
    });
    group.finish();
}

criterion_group!(benches, bench_ext4_alloc_lock_convoy);
criterion_main!(benches);
