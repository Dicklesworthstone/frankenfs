#![forbid(unsafe_code)]

//! Publish-a-value-into-a-shared-slot: MOVE it into an `Arc` and share via a
//! refcount clone, vs DEEP-CLONE it. Models the ext4 read hot-inode MISS path in
//! `OpenFs::read_into`, which published the parsed `Ext4Inode` into the hot slot.
//! The old code did `Arc::new(parsed.clone())` — a deep clone of the whole struct
//! (including its heap `xattr_ibody: Vec<u8>`) while also keeping the original;
//! the new code moves it into one `Arc` and shares that with the slot via
//! `Arc::clone` (a refcount bump), then borrows the stored Arc for the read.
//!
//! `Payload` mimics the shape: fixed POD (the ~128-byte base inode) plus a heap
//! `Vec<u8>` (the xattr body). The deep-clone cost is the same one the hot-HIT
//! path already eliminated (bd-cc-hotinode, ~6.6% of warm random-read).

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;

#[derive(Clone)]
struct Payload {
    pod: [u8; 160],
    xattr: Vec<u8>,
}

fn payload(xattr_len: usize) -> Payload {
    Payload {
        pod: [0x5A; 160],
        xattr: vec![0xC3; xattr_len],
    }
}

fn bench_publish(c: &mut Criterion) {
    // The heap field exists to be deep-cloned by the "old" arm; assert its
    // shape here (outside timing) so the payload contract is checked and read.
    assert_eq!(payload(64).xattr.len(), 64);
    let mut group = c.benchmark_group("inode_publish_arc_vs_clone");
    group.sample_size(50);
    // xattr_len 0 = the common no-xattr inode; larger = inodes carrying xattrs.
    for xattr_len in [0_usize, 64, 512] {
        // OLD: deep-clone the value into the slot Arc, keep the original locally.
        group.bench_with_input(
            BenchmarkId::new("deep_clone", xattr_len),
            &xattr_len,
            |b, &n| {
                b.iter_batched(
                    || payload(n),
                    |parsed| {
                        let slot = Arc::new(("k", Arc::new(parsed.clone())));
                        let local = parsed; // original kept for the current read
                        black_box((slot, local.pod[0]));
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
        // NEW: move into one Arc, share with the slot via a refcount clone, borrow it.
        group.bench_with_input(
            BenchmarkId::new("arc_move_share", xattr_len),
            &xattr_len,
            |b, &n| {
                b.iter_batched(
                    || payload(n),
                    |parsed| {
                        let arc = Arc::new(parsed);
                        let slot = Arc::new(("k", Arc::clone(&arc)));
                        black_box((slot, arc.as_ref().pod[0]));
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(arc_publish_vs_deep_clone, bench_publish);
criterion_main!(arc_publish_vs_deep_clone);
