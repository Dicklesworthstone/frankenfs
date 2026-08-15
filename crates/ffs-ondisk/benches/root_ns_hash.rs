#![forbid(unsafe_code)]
//! `extent_root_namespace` (ffs-core) hashes the inode's ≤64-byte extent root to
//! a cache key — computed PER WRITE in `ext4_write_extents_with_scope`. The
//! production form is byte-wise FNV-1a: a 60-iteration sequential XOR+multiply
//! dependency chain the compiler cannot vectorize. A word-at-a-time hash mixes 8
//! bytes/iter (7 iters + tail), same "every byte affects the hash" property, for
//! an in-memory cache key (values need only be deterministic + change-on-mutation).
//! A/B the two hash forms over a representative 60-byte extent root.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench root_ns_hash
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01b3;

/// Production: byte-wise FNV-1a.
#[inline]
fn root_ns_bytewise(bytes: &[u8]) -> u64 {
    let mut h: u64 = FNV_OFFSET;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Word-at-a-time: mix 8 bytes/iter (each byte still affects h; 8B↔u64 is a
/// bijection so distinct byte sequences give distinct word sequences).
#[inline]
fn root_ns_wordwise(bytes: &[u8]) -> u64 {
    let mut h: u64 = FNV_OFFSET;
    let mut i = 0;
    while i + 8 <= bytes.len() {
        h ^= u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
        h = h.wrapping_mul(FNV_PRIME);
        i += 8;
    }
    if i < bytes.len() {
        let mut tail = [0u8; 8];
        tail[..bytes.len() - i].copy_from_slice(&bytes[i..]);
        h ^= u64::from_le_bytes(tail);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

fn bench(c: &mut Criterion) {
    // A representative 60-byte ext4 extent root: 12-byte header + 4 populated
    // 12-byte extents.
    let mut root = [0u8; 60];
    root[0..2].copy_from_slice(&0xF30Au16.to_le_bytes()); // eh_magic
    root[2..4].copy_from_slice(&2u16.to_le_bytes()); // eh_entries
    root[4..6].copy_from_slice(&4u16.to_le_bytes()); // eh_max
    for (i, b) in root.iter_mut().enumerate().skip(12) {
        *b = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
    // change-detection sanity: mutating any byte changes both hashes.
    let mut m = root;
    m[40] ^= 1;
    assert_ne!(root_ns_bytewise(&root), root_ns_bytewise(&m));
    assert_ne!(root_ns_wordwise(&root), root_ns_wordwise(&m));

    let mut g = c.benchmark_group("root_ns_hash");
    g.bench_function("bytewise_fnv", |b| {
        b.iter(|| black_box(root_ns_bytewise(black_box(&root))))
    });
    g.bench_function("wordwise", |b| {
        b.iter(|| black_box(root_ns_wordwise(black_box(&root))))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
