#![forbid(unsafe_code)]
//! A/B for the free-path reserved-block validation (free_blocks_persist): old
//! per-block `for i in segment { is_reserved(reserved, i) }` (binary_search per
//! block, O(count·log R)) vs a single binary range-overlap (O(log R)). R models
//! a flex-leader group (~8000 reserved). Completes the free-path range-ification
//! begun in b9389ced (double-free + clear); the reserved-check was the last
//! per-block cost.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench reserved_overlap_check
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn old_check(reserved: &[u32], start: u32, count: u32) -> Option<u32> {
    for i in start..start + count {
        if reserved.binary_search(&i).is_ok() {
            return Some(i);
        }
    }
    None
}
fn new_check(reserved: &[u32], start: u32, count: u32) -> Option<u32> {
    let end = start + count;
    let p = reserved.partition_point(|&r| r < start);
    reserved.get(p).copied().filter(|&r| r < end)
}
fn bench(c: &mut Criterion) {
    let reserved: Vec<u32> = (30000..38000).collect(); // R=8000, none in [start,start+count)
    let start = 40u32;
    for count in [256u32, 4096] {
        assert_eq!(
            old_check(&reserved, start, count),
            new_check(&reserved, start, count)
        );
        let mut g = c.benchmark_group(format!("reserved_check_c{count}"));
        g.bench_function("per_block", |b| {
            b.iter(|| black_box(old_check(black_box(&reserved), start, count)))
        });
        g.bench_function("range_overlap", |b| {
            b.iter(|| black_box(new_check(black_box(&reserved), start, count)))
        });
        g.finish();
    }
}
criterion_group!(benches, bench);
criterion_main!(benches);
