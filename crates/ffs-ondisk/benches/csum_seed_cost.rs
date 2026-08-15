#![forbid(unsafe_code)]
//! Measures the per-op cost `csum_seed()` recomputes for a non-CSUM_SEED ext4 FS
//! (`crc32c(uuid)`, 16 bytes) vs returning a cached u32. NEGATIVE-EVIDENCE: the
//! redundancy is real but ~0-gain — callers (e.g. ffs-core create @3454) already
//! cache the seed once per op in a struct field and pass it down; there are no
//! per-block/per-group loop calls. So caching it at mount saves one crc32c per
//! op, below the drop threshold. Recorded to stop re-investigation.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench csum_seed_cost
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
fn bench(c: &mut Criterion) {
    let uuid = [0x11u8; 16];
    let cached: u32 = 0xDEAD_BEEF;
    let mut g = c.benchmark_group("csum_seed");
    g.bench_function("recompute_crc32c_uuid", |b| {
        b.iter(|| black_box(crc32c::crc32c(black_box(&uuid))))
    });
    g.bench_function("cached_read", |b| b.iter(|| black_box(cached)));
    g.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
