#![forbid(unsafe_code)]
//! `dx_hash` (half-MD4, hash_version 1) runs on every htree lookup (hash the
//! target name) and every htree build/split (hash every name). Its inner
//! `half_md4_transform` takes `buf: &[u32]` and reads it via
//! `buf.get(i).copied().unwrap_or(0)` — a bounds check + unwrap_or for each of
//! ~24 accesses per transform — even though the caller always passes a
//! `[u32; 8]`. If the transform doesn't inline, those checks are live. This
//! benches dx_hash over representative names for a rebuild-A/B: change
//! `half_md4_transform` to take `&[u32; 8]` + index directly, rebuild, compare.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench dx_hash_transform
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::ext4::dx_hash;
use std::hint::black_box;

fn bench(c: &mut Criterion) {
    let seed: [u32; 4] = [0x1234_5678, 0x9abc_def0, 0x0f1e_2d3c, 0x4b5a_6978];
    let short = b"file_00012345"; // 13 bytes, 1 half-MD4 chunk
    let long = b"a_rather_longer_directory_entry_name.txt"; // 40 bytes, 2 chunks

    // sanity: deterministic
    assert_eq!(dx_hash(1, short, &seed), dx_hash(1, short, &seed));

    let mut g = c.benchmark_group("dx_hash_transform");
    g.bench_function("short_13", |b| {
        b.iter(|| black_box(dx_hash(1, black_box(&short[..]), black_box(&seed))))
    });
    g.bench_function("long_40", |b| {
        b.iter(|| black_box(dx_hash(1, black_box(&long[..]), black_box(&seed))))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
