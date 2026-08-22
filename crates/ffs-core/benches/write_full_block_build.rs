#![forbid(unsafe_code)]

//! A/B for building a FULL-block-overwrite buffer on the ext4 write path.
//!
//! For an aligned full-block write (`block_offset == 0 && chunk_len == bs`), the
//! block staged into the MVCC txn IS the write data. The old code built it as
//! `vec![0u8; bs]` (a full-block memset) + `copy_from_slice(data)` (memcpy) — the
//! zero-init is entirely overwritten. The new code takes `data[..].to_vec()` (one
//! memcpy). This benches the two builds at a 4 KiB block: the delta is the
//! eliminated memset. Byte-identical output (asserted).
//!   rch exec -- cargo bench --profile release-perf -p ffs-core --bench write_full_block_build

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const BS: usize = 4096;

fn memset_then_copy(data: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; BS];
    b[..BS].copy_from_slice(&data[..BS]);
    b
}

fn direct_to_vec(data: &[u8]) -> Vec<u8> {
    data[..BS].to_vec()
}

fn bench(c: &mut Criterion) {
    let mut data = vec![0u8; BS];
    for (i, x) in data.iter_mut().enumerate() {
        *x = u8::try_from(i & 0xFF)
            .expect("index masked into u8 range")
            .wrapping_mul(37)
            .wrapping_add(3);
    }
    assert_eq!(memset_then_copy(&data), direct_to_vec(&data), "isomorphism");

    let mut g = c.benchmark_group("write_full_block_build_4k");
    g.bench_function("memset_then_copy", |b| {
        b.iter(|| black_box(memset_then_copy(black_box(&data))));
    });
    g.bench_function("direct_to_vec", |b| {
        b.iter(|| black_box(direct_to_vec(black_box(&data))));
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
