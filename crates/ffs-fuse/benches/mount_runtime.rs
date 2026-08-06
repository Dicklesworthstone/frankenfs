#![forbid(unsafe_code)]

//! Benchmarks for mount runtime mode dispatch infrastructure.
//!
//! Measures the overhead of per-core routing, work-stealing decisions,
//! aggregate metrics collection, backpressure decisions, and atomic
//! metrics recording. These operate without actual FUSE mounts.

use asupersync::Cx;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ffs_core::{FsOps, InodeAttr, ReaddirPage, RequestOp, RequestScope};
use ffs_error::FfsError;
use ffs_fuse::per_core::{PerCoreConfig, PerCoreDispatcher, inode_to_core};
use ffs_fuse::{AtomicMetrics, FrankenFuse, MountOptions, WritebackCacheMode};
use ffs_types::{CommitSeq, InodeNumber};
use std::ffi::OsStr;
use std::hint::black_box;
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::Duration;

fn legacy_inode_to_core(ino: u64, num_cores: u32) -> u32 {
    if num_cores == 0 {
        return 0;
    }
    let mixed = ino.wrapping_mul(0x517c_c1b7_2722_0a95);
    #[expect(clippy::cast_possible_truncation)] // intentional 64->32 fold
    let folded = (mixed ^ (mixed >> 32)) as u32;
    folded % num_cores
}

fn bench_per_core_route_hash_ab(c: &mut Criterion) {
    let num_cores = 8_u32;
    let mut group = c.benchmark_group("mount_runtime_per_core_route_hash_ab");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(1));

    group.bench_function("legacy_modulo", |b| {
        let mut ino = 2_u64;
        b.iter(|| {
            let core = legacy_inode_to_core(black_box(ino), black_box(num_cores));
            ino = ino.wrapping_add(1);
            black_box(core);
        });
    });

    group.bench_function("power2_mask", |b| {
        let mut ino = 2_u64;
        b.iter(|| {
            let core = inode_to_core(black_box(ino), black_box(num_cores));
            ino = ino.wrapping_add(1);
            black_box(core);
        });
    });
    group.finish();
}

fn bench_per_core_route_inode(c: &mut Criterion) {
    let dispatcher = PerCoreDispatcher::new(PerCoreConfig {
        num_cores: 8,
        ..PerCoreConfig::default()
    });

    c.bench_function("mount_runtime_per_core_route_inode", |b| {
        let mut ino = 2_u64;
        b.iter(|| {
            let core = dispatcher.route_inode(black_box(ino));
            ino = ino.wrapping_add(1);
            black_box(core);
        });
    });
}

fn bench_per_core_route_lookup(c: &mut Criterion) {
    let dispatcher = PerCoreDispatcher::new(PerCoreConfig {
        num_cores: 8,
        ..PerCoreConfig::default()
    });

    c.bench_function("mount_runtime_per_core_route_lookup", |b| {
        let mut parent_ino = 2_u64;
        b.iter(|| {
            let core = dispatcher.route_lookup(black_box(parent_ino));
            parent_ino = parent_ino.wrapping_add(1);
            black_box(core);
        });
    });
}

fn bench_per_core_should_steal(c: &mut Criterion) {
    let dispatcher = PerCoreDispatcher::new(PerCoreConfig {
        num_cores: 8,
        ..PerCoreConfig::default()
    });

    // Create imbalanced load: core 0 gets all requests, others idle.
    if let Some(m) = dispatcher.core_metrics(0) {
        for _ in 0..10_000 {
            m.begin_request();
        }
    }

    c.bench_function("mount_runtime_per_core_should_steal", |b| {
        b.iter(|| {
            // Check if core 1 (idle) should steal from others.
            black_box(dispatcher.should_steal(black_box(1)));
        });
    });
}

fn bench_per_core_aggregate_metrics(c: &mut Criterion) {
    let dispatcher = PerCoreDispatcher::new(PerCoreConfig {
        num_cores: 8,
        ..PerCoreConfig::default()
    });

    // Populate some realistic metrics.
    for core_id in 0..8_u32 {
        if let Some(m) = dispatcher.core_metrics(core_id) {
            for _ in 0..(1000 * (core_id as usize + 1)) {
                m.record_request();
                m.record_hit();
            }
            for _ in 0..(100 * (core_id as usize + 1)) {
                m.record_miss();
            }
        }
    }

    c.bench_function("mount_runtime_per_core_aggregate_metrics", |b| {
        b.iter(|| {
            black_box(dispatcher.aggregate_metrics());
        });
    });
}

fn bench_metrics_record_throughput(c: &mut Criterion) {
    let metrics = AtomicMetrics::new();

    c.bench_function("mount_runtime_metrics_record_throughput", |b| {
        b.iter(|| {
            metrics.requests_total.0.fetch_add(1, Ordering::Relaxed);
            metrics.requests_ok.0.fetch_add(1, Ordering::Relaxed);
            black_box(&metrics);
        });
    });
}

fn bench_backpressure_normal(c: &mut Criterion) {
    use asupersync::SystemPressure;
    use ffs_core::{BackpressureGate, DegradationFsm, RequestOp};
    use std::sync::Arc;

    let pressure = Arc::new(SystemPressure::new());
    let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
    let gate = BackpressureGate::new(fsm);

    c.bench_function("mount_runtime_backpressure_normal", |b| {
        b.iter(|| {
            black_box(gate.check(black_box(RequestOp::Read)));
        });
    });
}

fn bench_backpressure_degraded(c: &mut Criterion) {
    use asupersync::SystemPressure;
    use ffs_core::{BackpressureGate, DegradationFsm, RequestOp};
    use std::sync::Arc;

    // headroom=0.2 → degraded after tick
    let pressure = Arc::new(SystemPressure::with_headroom(0.2));
    let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
    fsm.tick();
    let gate = BackpressureGate::new(fsm);

    c.bench_function("mount_runtime_backpressure_degraded", |b| {
        b.iter(|| {
            // Read ops proceed even under degraded state (no throttle delay).
            black_box(gate.check(black_box(RequestOp::Read)));
        });
    });
}

fn bench_backpressure_emergency(c: &mut Criterion) {
    use asupersync::SystemPressure;
    use ffs_core::{BackpressureGate, DegradationFsm, RequestOp};
    use std::sync::Arc;

    // headroom=0.02 → emergency after tick
    let pressure = Arc::new(SystemPressure::with_headroom(0.02));
    let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
    fsm.tick();
    let gate = BackpressureGate::new(fsm);

    c.bench_function("mount_runtime_backpressure_emergency", |b| {
        b.iter(|| {
            // Write ops get shed under emergency — measures decision latency only.
            black_box(gate.check(black_box(RequestOp::Write)));
        });
    });
}

struct WritebackBenchFs {
    writes: AtomicU64,
    commits: AtomicU64,
    commit_work: u64,
}

impl WritebackBenchFs {
    fn new(commit_work: u64) -> Self {
        Self {
            writes: AtomicU64::new(0),
            commits: AtomicU64::new(0),
            commit_work,
        }
    }
}

impl FsOps for WritebackBenchFs {
    fn getattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::UnsupportedFeature(
            "writeback bench does not model getattr".to_owned(),
        ))
    }

    fn lookup(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::UnsupportedFeature(
            "writeback bench does not model lookup".to_owned(),
        ))
    }

    fn readdir(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
    ) -> ffs_error::Result<ReaddirPage> {
        Err(FfsError::UnsupportedFeature(
            "writeback bench does not model readdir".to_owned(),
        ))
    }

    fn read(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
        size: u32,
    ) -> ffs_error::Result<Vec<u8>> {
        Ok(vec![0; usize::try_from(size).unwrap_or(usize::MAX)])
    }

    fn readlink(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "writeback bench does not model readlink".to_owned(),
        ))
    }

    fn write(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
        data: &[u8],
    ) -> ffs_error::Result<u32> {
        self.writes.fetch_add(1, AtomicOrdering::Relaxed);
        Ok(u32::try_from(data.len()).unwrap_or(u32::MAX))
    }

    fn begin_request_scope(&self, _cx: &Cx, _op: RequestOp) -> ffs_error::Result<RequestScope> {
        Ok(RequestScope::empty())
    }

    fn commit_request_scope(&self, _scope: &mut RequestScope) -> ffs_error::Result<CommitSeq> {
        let mut state = self.commits.load(AtomicOrdering::Relaxed);
        for n in 0..self.commit_work {
            state = state.wrapping_add(n.rotate_left(7)).rotate_left(13) ^ 0x9E37_79B9_7F4A_7C15;
        }
        black_box(state);
        let seq = self.commits.fetch_add(1, AtomicOrdering::Relaxed) + 1;
        Ok(CommitSeq(seq))
    }

    fn end_request_scope(
        &self,
        _cx: &Cx,
        _op: RequestOp,
        _scope: RequestScope,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    fn fsync(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _fh: u64,
        _datasync: bool,
    ) -> ffs_error::Result<()> {
        Ok(())
    }
}

fn run_writeback_batch(writeback_cache: bool, writes: usize, payload: &[u8], commit_work: u64) {
    let options = MountOptions {
        read_only: false,
        writeback_cache: WritebackCacheMode::from_enabled(writeback_cache),
        ..MountOptions::default()
    };
    let fuse = FrankenFuse::with_options(Box::new(WritebackBenchFs::new(commit_work)), &options);
    for index in 0..writes {
        let offset = i64::try_from(index.saturating_mul(payload.len())).unwrap_or(i64::MAX);
        let written = fuse
            .write_for_fuzzing(44, offset, payload)
            .expect("bench write succeeds");
        assert_eq!(written as usize, payload.len());
    }
    if writeback_cache {
        fuse.flush_for_fuzzing(44, 0, 0)
            .expect("bench flush commits deferred writeback");
    }
}

fn bench_writeback_cache_batching(c: &mut Criterion) {
    let payload = vec![0x5A_u8; 32 * 1024];
    let writes = 32_usize;
    let commit_work = 512_u64;
    let mut group = c.benchmark_group("mount_runtime_writeback");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(1));

    group.bench_function("per_write_commit_32x32k", |b| {
        b.iter(|| run_writeback_batch(false, writes, black_box(&payload), commit_work));
    });

    group.bench_function("deferred_flush_32x32k", |b| {
        b.iter(|| run_writeback_batch(true, writes, black_box(&payload), commit_work));
    });
    group.finish();
}

fn readahead_empty_head_append(mut fetched: Vec<u8>, head_len: usize) -> (Vec<u8>, Vec<u8>) {
    let mut served = Vec::new();
    let tail = fetched.split_off(head_len);
    served.append(&mut fetched);
    (served, tail)
}

fn readahead_empty_head_move(mut fetched: Vec<u8>, head_len: usize) -> (Vec<u8>, Vec<u8>) {
    let tail = fetched.split_off(head_len);
    (fetched, tail)
}

fn bench_readahead_empty_head_ownership(c: &mut Criterion) {
    const FETCHED_LEN: usize = 256 * 1024;
    let template: Vec<u8> = (0..FETCHED_LEN)
        .map(|index| {
            u8::try_from(index & 0xff)
                .expect("masked index fits u8")
                .wrapping_mul(131)
        })
        .collect();
    assert_eq!(template.len(), template.capacity());

    let control = readahead_empty_head_append(template.clone(), 128 * 1024);
    let candidate_input = template.clone();
    let candidate_ptr = candidate_input.as_ptr();
    let candidate = readahead_empty_head_move(candidate_input, 128 * 1024);
    assert_eq!(control, candidate);
    assert_eq!(candidate_ptr, candidate.0.as_ptr());

    let mut group = c.benchmark_group("mount_runtime_readahead_empty_head_ownership_128k_of_256k");
    group.bench_function("append_copy_a", |b| {
        b.iter_batched(
            || template.clone(),
            |fetched| black_box(readahead_empty_head_append(fetched, 128 * 1024)),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("append_copy_b", |b| {
        b.iter_batched(
            || template.clone(),
            |fetched| black_box(readahead_empty_head_append(fetched, 128 * 1024)),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("move_head", |b| {
        b.iter_batched(
            || template.clone(),
            |fetched| black_box(readahead_empty_head_move(fetched, 128 * 1024)),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_readahead_empty_head_ownership_no_tail(c: &mut Criterion) {
    const FETCHED_LEN: usize = 128 * 1024;
    let template = vec![0xA5_u8; FETCHED_LEN];
    assert_eq!(template.len(), template.capacity());

    let control = readahead_empty_head_append(template.clone(), FETCHED_LEN);
    let candidate_input = template.clone();
    let candidate_ptr = candidate_input.as_ptr();
    let candidate = readahead_empty_head_move(candidate_input, FETCHED_LEN);
    assert_eq!(control, candidate);
    assert_eq!(candidate_ptr, candidate.0.as_ptr());
    assert_eq!(control.0.capacity(), candidate.0.capacity());

    let mut group = c.benchmark_group("mount_runtime_readahead_empty_head_ownership_128k_no_tail");
    group.bench_function("append_copy_a", |b| {
        b.iter_batched(
            || template.clone(),
            |fetched| black_box(readahead_empty_head_append(fetched, FETCHED_LEN)),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("append_copy_b", |b| {
        b.iter_batched(
            || template.clone(),
            |fetched| black_box(readahead_empty_head_append(fetched, FETCHED_LEN)),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("move_head", |b| {
        b.iter_batched(
            || template.clone(),
            |fetched| black_box(readahead_empty_head_move(fetched, FETCHED_LEN)),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn encode_xattr_names_control(names: &[String]) -> Vec<u8> {
    let total_len = names.iter().map(|name| name.len() + 1).sum();
    let mut bytes = Vec::with_capacity(total_len);
    for name in names {
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
    }
    bytes
}

fn xattr_names_encoded_len(names: &[String]) -> usize {
    names.iter().map(|name| name.len() + 1).sum()
}

fn bench_listxattr_size_probe_payload_elision(c: &mut Criterion) {
    let names: Vec<String> = (0..24)
        .map(|index| format!("user.frankenfs_attribute_{index:02}"))
        .collect();
    let encoded = encode_xattr_names_control(&names);
    assert_eq!(encoded.len(), xattr_names_encoded_len(&names));
    // Assert the exact wire bytes rather than counting NUL separators: it pins
    // the order and the payload too, not just how many terminators there are.
    let expected: Vec<u8> = names
        .iter()
        .flat_map(|name| name.as_bytes().iter().copied().chain(std::iter::once(0)))
        .collect();
    assert_eq!(encoded, expected);

    let mut group = c.benchmark_group("mount_runtime_listxattr_size_probe_24");
    group.sample_size(30);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
    group.bench_function("encode_payload_a", |b| {
        b.iter(|| black_box(encode_xattr_names_control(black_box(&names))));
    });
    group.bench_function("encode_payload_b", |b| {
        b.iter(|| black_box(encode_xattr_names_control(black_box(&names))));
    });
    group.bench_function("length_only", |b| {
        b.iter(|| black_box(xattr_names_encoded_len(black_box(&names))));
    });
    group.finish();
}

criterion_group!(
    mount_runtime,
    bench_per_core_route_hash_ab,
    bench_per_core_route_inode,
    bench_per_core_route_lookup,
    bench_per_core_should_steal,
    bench_per_core_aggregate_metrics,
    bench_metrics_record_throughput,
    bench_backpressure_normal,
    bench_backpressure_degraded,
    bench_backpressure_emergency,
    bench_writeback_cache_batching,
    bench_readahead_empty_head_ownership,
    bench_readahead_empty_head_ownership_no_tail,
    bench_listxattr_size_probe_payload_elision,
);
criterion_main!(mount_runtime);
