#![forbid(unsafe_code)]

//! Non-production characterization for bd-bhh0i.
//!
//! This bench does not change filesystem behavior. It measures synthetic
//! critical-section wait/hold distributions for the current whole-state
//! allocation lock shape versus a decomposed per-group allocation shape with a
//! separate synthetic publication lock. Its small hand-enumerated model proves
//! final-state conservation only; the separate Loom test models the accepted
//! eager MVCC publication protocol and its lock order.

use parking_lot::Mutex;
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const GROUPS: usize = 8;
const OPS_PER_THREAD: usize = 4_000;
const ALLOC_BYTES: usize = 4096;

#[derive(Default)]
struct Samples {
    wait: Mutex<Vec<u64>>,
    hold: Mutex<Vec<u64>>,
    alloc: Mutex<Vec<u64>>,
}

impl Samples {
    fn record(&self, wait_ns: u64, hold_ns: u64, alloc_ns: u64) {
        self.wait.lock().push(wait_ns);
        self.hold.lock().push(hold_ns);
        self.alloc.lock().push(alloc_ns);
    }
}

#[derive(Default)]
struct GroupState {
    free_inodes: u64,
    checksum: u64,
}

impl GroupState {
    fn new(group: usize) -> Self {
        Self {
            free_inodes: 1_000_000,
            checksum: (group as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        }
    }

    fn account(&mut self, op: usize, seed: u64) -> u64 {
        self.free_inodes = self.free_inodes.wrapping_sub(1);
        self.checksum = self
            .checksum
            .wrapping_add(self.free_inodes)
            .rotate_left(u32::try_from(op & 31).expect("op & 31 fits u32"))
            ^ seed;
        self.checksum
    }
}

fn elapsed_ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn timed_alloc(seed: u8) -> (Vec<u8>, u64) {
    let start = Instant::now();
    let buf = vec![seed; ALLOC_BYTES];
    let ns = elapsed_ns(start);
    (buf, ns)
}

fn run_current_global(threads: usize) -> (Samples, Samples, u64) {
    let alloc_lock = Arc::new(Mutex::new(
        (0..GROUPS).map(GroupState::new).collect::<Vec<_>>(),
    ));
    let alloc_samples = Arc::new(Samples::default());
    let publish_samples = Arc::new(Samples::default());
    let digest = Arc::new(AtomicU64::new(0));

    std::thread::scope(|scope| {
        for tid in 0..threads {
            let alloc_lock = Arc::clone(&alloc_lock);
            let alloc_samples = Arc::clone(&alloc_samples);
            let digest = Arc::clone(&digest);
            scope.spawn(move || {
                let group = tid % GROUPS;
                let mut local = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let wait_start = Instant::now();
                    let mut groups = alloc_lock.lock();
                    let wait_ns = elapsed_ns(wait_start);

                    let hold_start = Instant::now();
                    let (buf, alloc_ns) = timed_alloc(u8::try_from(tid).expect("threads fit u8"));
                    local = local.wrapping_add(groups[group].account(op, u64::from(buf[0])));
                    black_box(&buf);
                    drop(buf);
                    let hold_ns = elapsed_ns(hold_start);
                    alloc_samples.record(wait_ns, hold_ns, alloc_ns);
                    drop(groups);
                }
                digest.fetch_add(local, Ordering::Relaxed);
            });
        }
    });

    let alloc_samples = Arc::try_unwrap(alloc_samples).unwrap_or_else(|_| Samples::default());
    let publish_samples = Arc::try_unwrap(publish_samples).unwrap_or_else(|_| Samples::default());
    (
        alloc_samples,
        publish_samples,
        digest.load(Ordering::Relaxed),
    )
}

fn run_decomposed(threads: usize) -> (Samples, Samples, u64) {
    let groups = Arc::new(
        (0..GROUPS)
            .map(|idx| Mutex::new(GroupState::new(idx)))
            .collect::<Vec<_>>(),
    );
    let publish_lock = Arc::new(Mutex::new(0_u64));
    let group_samples = Arc::new(Samples::default());
    let publish_samples = Arc::new(Samples::default());
    let digest = Arc::new(AtomicU64::new(0));

    std::thread::scope(|scope| {
        for tid in 0..threads {
            let groups = Arc::clone(&groups);
            let publish_lock = Arc::clone(&publish_lock);
            let group_samples = Arc::clone(&group_samples);
            let publish_samples = Arc::clone(&publish_samples);
            let digest = Arc::clone(&digest);
            scope.spawn(move || {
                let group = tid % GROUPS;
                let mut local = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let wait_start = Instant::now();
                    let mut group_state = groups[group].lock();
                    let wait_ns = elapsed_ns(wait_start);

                    let hold_start = Instant::now();
                    let (buf, alloc_ns) = timed_alloc(u8::try_from(tid).expect("threads fit u8"));
                    local = local.wrapping_add(group_state.account(op, u64::from(buf[0])));
                    black_box(&buf);
                    drop(buf);
                    let hold_ns = elapsed_ns(hold_start);
                    group_samples.record(wait_ns, hold_ns, alloc_ns);
                    drop(group_state);

                    let wait_start = Instant::now();
                    let mut published = publish_lock.lock();
                    let publish_wait_ns = elapsed_ns(wait_start);
                    let hold_start = Instant::now();
                    *published = published.wrapping_add(
                        local.rotate_left(u32::try_from(op & 31).expect("op & 31 fits u32")),
                    );
                    let publish_hold_ns = elapsed_ns(hold_start);
                    publish_samples.record(publish_wait_ns, publish_hold_ns, 0);
                    drop(published);
                }
                digest.fetch_add(local, Ordering::Relaxed);
            });
        }
    });

    let group_samples = Arc::try_unwrap(group_samples).unwrap_or_else(|_| Samples::default());
    let publish_samples = Arc::try_unwrap(publish_samples).unwrap_or_else(|_| Samples::default());
    (
        group_samples,
        publish_samples,
        digest.load(Ordering::Relaxed),
    )
}

fn percentile(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = sorted.len().saturating_mul(pct).saturating_add(99) / 100;
    sorted[idx.saturating_sub(1).min(sorted.len() - 1)]
}

fn stats(samples: &[u64]) -> (u64, u64, u64, f64) {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let median = percentile(&sorted, 50);
    let p95 = percentile(&sorted, 95);
    let p99 = percentile(&sorted, 99);
    let mean = if sorted.is_empty() {
        0.0
    } else {
        sorted.iter().map(|v| *v as f64).sum::<f64>() / sorted.len() as f64
    };
    (median, p95, p99, mean)
}

fn print_samples(label: &str, threads: usize, samples: &Samples) {
    let (op_count, (wait_med, wait_p95, wait_p99, wait_mean)) = {
        let wait = samples.wait.lock();
        (wait.len(), stats(&wait))
    };
    let (hold_med, hold_p95, hold_p99, hold_mean) = {
        let hold = samples.hold.lock();
        stats(&hold)
    };
    let (alloc_med, alloc_p95, alloc_p99, alloc_mean) = {
        let alloc = samples.alloc.lock();
        stats(&alloc)
    };
    println!(
        "{label},threads={threads},ops={},wait_us_med={:.3},wait_us_p95={:.3},wait_us_p99={:.3},wait_us_mean={:.3},hold_us_med={:.3},hold_us_p95={:.3},hold_us_p99={:.3},hold_us_mean={:.3},alloc_us_med={:.3},alloc_us_p95={:.3},alloc_us_p99={:.3},alloc_us_mean={:.3}",
        op_count,
        wait_med as f64 / 1000.0,
        wait_p95 as f64 / 1000.0,
        wait_p99 as f64 / 1000.0,
        wait_mean / 1000.0,
        hold_med as f64 / 1000.0,
        hold_p95 as f64 / 1000.0,
        hold_p99 as f64 / 1000.0,
        hold_mean / 1000.0,
        alloc_med as f64 / 1000.0,
        alloc_p95 as f64 / 1000.0,
        alloc_p99 as f64 / 1000.0,
        alloc_mean / 1000.0,
    );
}

#[derive(Clone, Copy)]
enum Op {
    LockGroup(usize),
    ApplyPrivate(usize),
    UnlockGroup(usize),
    LockPublish,
    Publish,
    UnlockPublish,
}

#[derive(Clone)]
struct ModelState {
    pc: [usize; 2],
    group_owner: [Option<usize>; 2],
    publish_owner: Option<usize>,
    private_delta: [[u32; 2]; 2],
    global_delta: [u32; 2],
    published: Vec<usize>,
}

fn model_program(thread: usize) -> &'static [Op] {
    const T0: &[Op] = &[
        Op::LockGroup(0),
        Op::ApplyPrivate(0),
        Op::UnlockGroup(0),
        Op::LockPublish,
        Op::Publish,
        Op::UnlockPublish,
    ];
    const T1: &[Op] = &[
        Op::LockGroup(1),
        Op::ApplyPrivate(1),
        Op::UnlockGroup(1),
        Op::LockPublish,
        Op::Publish,
        Op::UnlockPublish,
    ];
    if thread == 0 { T0 } else { T1 }
}

fn model_step(mut state: ModelState, thread: usize) -> Option<ModelState> {
    let program = model_program(thread);
    let op = *program.get(state.pc[thread])?;
    match op {
        Op::LockGroup(group) => {
            if state.group_owner[group].is_some() {
                return None;
            }
            state.group_owner[group] = Some(thread);
        }
        Op::ApplyPrivate(group) => {
            if state.group_owner[group] != Some(thread) {
                return None;
            }
            state.private_delta[thread][group] =
                state.private_delta[thread][group].saturating_add(1);
        }
        Op::UnlockGroup(group) => {
            if state.group_owner[group] != Some(thread) {
                return None;
            }
            state.group_owner[group] = None;
        }
        Op::LockPublish => {
            if state.publish_owner.is_some() {
                return None;
            }
            state.publish_owner = Some(thread);
        }
        Op::Publish => {
            if state.publish_owner != Some(thread) {
                return None;
            }
            for group in 0..2 {
                state.global_delta[group] =
                    state.global_delta[group].saturating_add(state.private_delta[thread][group]);
                state.private_delta[thread][group] = 0;
            }
            state.published.push(thread);
        }
        Op::UnlockPublish => {
            if state.publish_owner != Some(thread) {
                return None;
            }
            state.publish_owner = None;
        }
    }
    state.pc[thread] += 1;
    Some(state)
}

fn explore_model(state: &ModelState, terminal: &mut u64, deadlocks: &mut u64) {
    let done = (0..2).all(|thread| state.pc[thread] == model_program(thread).len());
    if done {
        assert_eq!(state.global_delta, [1, 1]);
        assert_eq!(state.private_delta, [[0, 0], [0, 0]]);
        assert_eq!(state.group_owner, [None, None]);
        assert_eq!(state.publish_owner, None);
        assert_eq!(state.published.len(), 2);
        *terminal += 1;
        return;
    }

    let mut enabled = 0_u64;
    for thread in 0..2 {
        if let Some(next) = model_step(state.clone(), thread) {
            enabled += 1;
            explore_model(&next, terminal, deadlocks);
        }
    }
    if enabled == 0 {
        *deadlocks += 1;
    }
}

fn run_model() {
    let mut terminal = 0_u64;
    let mut deadlocks = 0_u64;
    let state = ModelState {
        pc: [0, 0],
        group_owner: [None, None],
        publish_owner: None,
        private_delta: [[0, 0], [0, 0]],
        global_delta: [0, 0],
        published: Vec::new(),
    };
    explore_model(&state, &mut terminal, &mut deadlocks);
    println!(
        "bounded_model,threads=2,terminal_interleavings={terminal},deadlocks={deadlocks},final_state_conserved=true,linearizable=unproven"
    );
    assert!(terminal > 0);
    assert_eq!(deadlocks, 0);
}

fn main() {
    println!("bd_bhh0i_contention_histograms,ops_per_thread={OPS_PER_THREAD}");
    for threads in [1_usize, 2, 4, 8] {
        let (alloc, publish, current_digest) = run_current_global(threads);
        let (group, decomposed_publish, decomposed_digest) = run_decomposed(threads);
        print_samples("current_global_alloc_lock", threads, &alloc);
        print_samples("current_publish_lock_masked_by_alloc", threads, &publish);
        print_samples("decomposed_group_lock", threads, &group);
        print_samples("decomposed_publish_lock", threads, &decomposed_publish);
        println!(
            "digest,threads={threads},current={current_digest},decomposed={decomposed_digest}"
        );
    }
    run_model();
}
