#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for the inode serialization buffer: the heap-allocating
//! `serialize_inode` (`vec![0; inode_size]` per call) vs the stack-buffer
//! `serialize_inode_into` used by the hot `write_inode` path
//! (bd-cc-serialize-into). Both produce identical bytes (asserted); this
//! isolates the per-call heap-alloc cost that `write_inode` runs on every
//! create/mkdir/rename/unlink inode write.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_inode::{serialize_inode, serialize_inode_into};
use ffs_ondisk::ext4::Ext4Inode;
use std::hint::black_box;

fn make_inode() -> Ext4Inode {
    // A zeroed 256-byte inode parses to a valid (empty) inode — enough to
    // exercise the full serialize field-write path.
    let mut raw = vec![0u8; 256];
    // Give it a plausible mode (S_IFREG | 0644) so no field is trivially skipped.
    raw[0..2].copy_from_slice(&0x81A4u16.to_le_bytes());
    Ext4Inode::parse_from_bytes(&raw).expect("parse zeroed inode")
}

fn bench_serialize(c: &mut Criterion) {
    let inode = make_inode();
    let inode_size = 256usize;

    // Correctness: both paths agree.
    let mut stack = [0u8; 256];
    serialize_inode_into(&inode, inode_size, &mut stack);
    assert_eq!(&stack[..], &serialize_inode(&inode, inode_size)[..]);

    let mut group = c.benchmark_group("serialize_inode_256");
    group.bench_function("heap_vec", |b| {
        b.iter(|| black_box(serialize_inode(black_box(&inode), inode_size)));
    });
    group.bench_function("stack_buf", |b| {
        let mut buf = [0u8; 256];
        b.iter(|| {
            serialize_inode_into(black_box(&inode), inode_size, &mut buf);
            black_box(&buf);
        });
    });
    group.finish();
}

// prepare_inode builds the empty extent-tree root for every created inode. The
// old code did `vec![0;60].into()` — `From<Vec>` for SmallVec SPILLS (reuses the
// heap buffer, never inlines), so every created inode's extent_bytes was heap-
// allocated. The fix builds a stack array and `.as_slice().into()` (`From<&[u8]>`
// copies inline for len<=64). This isolates that construction difference.
fn bench_extent_bytes_construct(c: &mut Criterion) {
    use ffs_ondisk::ext4::Ext4InodeBlockBytes;
    let mut group = c.benchmark_group("prepare_inode_extent_bytes");
    group.bench_function("vec_into_spill", |b| {
        b.iter(|| {
            let mut v = vec![0u8; 60];
            v[0] = 0x0A;
            v[4] = 4;
            black_box(Ext4InodeBlockBytes::from(black_box(v)))
        });
    });
    group.bench_function("array_slice_into_inline", |b| {
        b.iter(|| {
            let mut a = [0u8; 60];
            a[0] = 0x0A;
            a[4] = 4;
            black_box(Ext4InodeBlockBytes::from(black_box(a).as_slice()))
        });
    });
    group.finish();
}

criterion_group!(benches, bench_serialize, bench_extent_bytes_construct);
criterion_main!(benches);
