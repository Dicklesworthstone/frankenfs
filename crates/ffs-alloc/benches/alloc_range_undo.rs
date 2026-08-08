#![forbid(unsafe_code)]
//! A/B for the transactional alloc path (try_alloc_safe): old per-block
//! reserved-check (is_reserved binary_search per block) + per-bit mark-with-undo,
//! vs new single binary range-overlap check + range-set (alloc range is the undo).
//! Reserved list R models a flex-leader group. Large-extent alloc on the write floor.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench alloc_range_undo
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn old_alloc(bitmap: &mut [u8], reserved: &[u32], start: u32, count: u32) -> u32 {
    // reserved-check per block
    for i in start..start + count {
        if reserved.binary_search(&i).is_ok() {
            return i;
        }
    }
    // mark with per-bit undo
    let mut undo: Vec<u32> = Vec::with_capacity(count as usize);
    for i in start..start + count {
        let b = (i / 8) as usize;
        if let Some(byte) = bitmap.get_mut(b) {
            if (*byte >> (i % 8)) & 1 == 0 {
                *byte |= 1 << (i % 8);
                undo.push(i);
            }
        }
    }
    black_box(&undo);
    u32::MAX
}
fn new_alloc(bitmap: &mut [u8], reserved: &[u32], start: u32, count: u32) -> u32 {
    let end = start + count;
    let p = reserved.partition_point(|&r| r < start);
    if let Some(&r) = reserved.get(p) {
        if r < end {
            return r;
        }
    }
    // range-set
    let mut idx = start;
    while idx < end && idx % 8 != 0 {
        let b = (idx / 8) as usize;
        bitmap[b] |= 1 << (idx % 8);
        idx += 1;
    }
    let bs = (idx / 8) as usize;
    let fe = end - (end % 8);
    let be = ((fe / 8) as usize).min(bitmap.len());
    if be > bs {
        bitmap[bs..be].fill(0xFF);
        idx = (be as u32) * 8;
    }
    while idx < end {
        let b = (idx / 8) as usize;
        bitmap[b] |= 1 << (idx % 8);
        idx += 1;
    }
    u32::MAX
}
fn bench(c: &mut Criterion) {
    // reserved list: 8000 blocks (flex-leader), none in [start, start+count)
    let reserved: Vec<u32> = (30000..38000).collect();
    let start = 40u32;
    for count in [256u32, 4096] {
        let bytes = 8192usize;
        let mut oa = vec![0u8; bytes];
        let mut nb = vec![0u8; bytes];
        assert_eq!(
            old_alloc(&mut oa, &reserved, start, count),
            new_alloc(&mut nb, &reserved, start, count)
        );
        assert_eq!(oa, nb, "count={count}");
        let mut g = c.benchmark_group(format!("alloc_range_c{count}"));
        g.bench_function("old", |b| {
            b.iter_batched(
                || vec![0u8; bytes],
                |mut bm| black_box(old_alloc(&mut bm, &reserved, start, count)),
                BatchSize::SmallInput,
            )
        });
        g.bench_function("new", |b| {
            b.iter_batched(
                || vec![0u8; bytes],
                |mut bm| black_box(new_alloc(&mut bm, &reserved, start, count)),
                BatchSize::SmallInput,
            )
        });
        g.finish();
    }
}
criterion_group!(benches, bench);
criterion_main!(benches);
