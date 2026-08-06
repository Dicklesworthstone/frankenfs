#![forbid(unsafe_code)]

//! Benchmarks for degraded/backpressure runtime behavior under load.
//!
//! Measures throughput impact of escalating pressure levels on foreground
//! workloads, FSM tick overhead, and concurrent backpressure contention.

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;

fn make_gate(headroom: f32) -> ffs_core::BackpressureGate {
    use asupersync::SystemPressure;
    use ffs_core::DegradationFsm;

    let pressure = Arc::new(SystemPressure::with_headroom(headroom));
    let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
    fsm.tick();
    ffs_core::BackpressureGate::new(fsm)
}

fn bench_degraded_throughput_warning(c: &mut Criterion) {
    use ffs_core::RequestOp;

    // Warning: headroom 0.35 → background paused, foreground unaffected
    let gate = make_gate(0.35);

    c.bench_function("degraded_throughput_warning_read", |b| {
        b.iter(|| black_box(gate.check(black_box(RequestOp::Read))));
    });

    c.bench_function("degraded_throughput_warning_write", |b| {
        b.iter(|| black_box(gate.check(black_box(RequestOp::Write))));
    });

    c.bench_function("degraded_throughput_warning_mixed", |b| {
        let mut i = 0_u64;
        b.iter(|| {
            let op = if i.is_multiple_of(3) {
                RequestOp::Write
            } else {
                RequestOp::Read
            };
            i = i.wrapping_add(1);
            black_box(gate.check(black_box(op)));
        });
    });
}

fn bench_degraded_throughput_critical(c: &mut Criterion) {
    use ffs_core::RequestOp;

    // Critical: headroom 0.08 → writes throttled, metadata writes shed
    let gate = make_gate(0.08);

    c.bench_function("degraded_throughput_critical_read", |b| {
        b.iter(|| black_box(gate.check(black_box(RequestOp::Read))));
    });

    // Note: Critical Write returns Throttle (not Shed), so no sleep in bench.
    // We measure the decision latency, not the throttle delay.
    c.bench_function("degraded_throughput_critical_write", |b| {
        b.iter(|| black_box(gate.check(black_box(RequestOp::Write))));
    });

    c.bench_function("degraded_throughput_critical_mixed", |b| {
        let mut i = 0_u64;
        b.iter(|| {
            let op = if i.is_multiple_of(3) {
                RequestOp::Write
            } else {
                RequestOp::Read
            };
            i = i.wrapping_add(1);
            black_box(gate.check(black_box(op)));
        });
    });
}

fn bench_fsm_tick_latency(c: &mut Criterion) {
    use asupersync::SystemPressure;
    use ffs_core::DegradationFsm;

    let pressure = Arc::new(SystemPressure::with_headroom(0.5_f32));
    let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 3));

    c.bench_function("degraded_fsm_tick_latency", |b| {
        b.iter(|| {
            black_box(fsm.tick());
        });
    });
}

fn bench_backpressure_contention_4threads(c: &mut Criterion) {
    use ffs_core::RequestOp;

    // Normal pressure: measures lock-free contention overhead
    let gate = Arc::new(make_gate(0.6));

    c.bench_function("degraded_backpressure_contention_4threads", |b| {
        b.iter(|| {
            std::thread::scope(|s| {
                for _ in 0..4 {
                    let g = Arc::clone(&gate);
                    s.spawn(move || {
                        for _ in 0..100 {
                            black_box(g.check(black_box(RequestOp::Read)));
                        }
                    });
                }
            });
        });
    });
}

criterion_group!(
    degraded_pressure,
    bench_degraded_throughput_warning,
    bench_degraded_throughput_critical,
    bench_fsm_tick_latency,
    bench_backpressure_contention_4threads,
);
criterion_main!(degraded_pressure);
