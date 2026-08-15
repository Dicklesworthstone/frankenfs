#![forbid(unsafe_code)]
//! Does the inode parser's `if bytes.len() < 128 { return Err }` guard already let
//! LLVM elide the per-field `.get()` bounds checks in the base area (all offsets
//! < 128)? If so, the array-ref hoist (b83531ef — which WON on the write side,
//! where the only length fact was a `debug_assert` LLVM ignores) is a no-op on the
//! READ side, whose real guard establishes `len >= 128` for range analysis.
//!
//! A/B: sum the ~15 base-area fields the inode parser reads, via the production
//! `ffs_types::read_le_*` (relies on inline + const-offset + len>=128 to elide) vs
//! a `&[u8; 128]` array-ref with LITERAL const offsets (provably check-free). Both
//! keep the `len < 128` guard. Neutral ⇒ the guard already elides ⇒ no lever.
//!   rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench inode_base_read_hoist
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_types::{read_le_u16, read_le_u32};
use std::hint::black_box;

fn sum_read_le(b: &[u8]) -> u32 {
    if b.len() < 128 {
        return 0;
    }
    let mut s = 0u32;
    s = s.wrapping_add(u32::from(read_le_u16(b, 0x00).unwrap()));
    s = s.wrapping_add(u32::from(read_le_u16(b, 0x02).unwrap()));
    s = s.wrapping_add(read_le_u32(b, 0x04).unwrap());
    s = s.wrapping_add(read_le_u32(b, 0x08).unwrap());
    s = s.wrapping_add(read_le_u32(b, 0x0C).unwrap());
    s = s.wrapping_add(read_le_u32(b, 0x10).unwrap());
    s = s.wrapping_add(read_le_u32(b, 0x14).unwrap());
    s = s.wrapping_add(u32::from(read_le_u16(b, 0x18).unwrap()));
    s = s.wrapping_add(u32::from(read_le_u16(b, 0x1A).unwrap()));
    s = s.wrapping_add(read_le_u32(b, 0x1C).unwrap());
    s = s.wrapping_add(read_le_u32(b, 0x20).unwrap());
    s = s.wrapping_add(read_le_u32(b, 0x24).unwrap());
    s = s.wrapping_add(read_le_u32(b, 0x64).unwrap());
    s = s.wrapping_add(read_le_u32(b, 0x68).unwrap());
    s = s.wrapping_add(read_le_u32(b, 0x6C).unwrap());
    s
}

#[allow(clippy::identity_op)]
fn sum_arrayref(b: &[u8]) -> u32 {
    if b.len() < 128 {
        return 0;
    }
    let a: &[u8; 128] = b[..128].try_into().unwrap();
    let mut s = 0u32;
    s = s.wrapping_add(u32::from(u16::from_le_bytes([a[0x00], a[0x01]])));
    s = s.wrapping_add(u32::from(u16::from_le_bytes([a[0x02], a[0x03]])));
    s = s.wrapping_add(u32::from_le_bytes([a[0x04], a[0x05], a[0x06], a[0x07]]));
    s = s.wrapping_add(u32::from_le_bytes([a[0x08], a[0x09], a[0x0A], a[0x0B]]));
    s = s.wrapping_add(u32::from_le_bytes([a[0x0C], a[0x0D], a[0x0E], a[0x0F]]));
    s = s.wrapping_add(u32::from_le_bytes([a[0x10], a[0x11], a[0x12], a[0x13]]));
    s = s.wrapping_add(u32::from_le_bytes([a[0x14], a[0x15], a[0x16], a[0x17]]));
    s = s.wrapping_add(u32::from(u16::from_le_bytes([a[0x18], a[0x19]])));
    s = s.wrapping_add(u32::from(u16::from_le_bytes([a[0x1A], a[0x1B]])));
    s = s.wrapping_add(u32::from_le_bytes([a[0x1C], a[0x1D], a[0x1E], a[0x1F]]));
    s = s.wrapping_add(u32::from_le_bytes([a[0x20], a[0x21], a[0x22], a[0x23]]));
    s = s.wrapping_add(u32::from_le_bytes([a[0x24], a[0x25], a[0x26], a[0x27]]));
    s = s.wrapping_add(u32::from_le_bytes([a[0x64], a[0x65], a[0x66], a[0x67]]));
    s = s.wrapping_add(u32::from_le_bytes([a[0x68], a[0x69], a[0x6A], a[0x6B]]));
    s = s.wrapping_add(u32::from_le_bytes([a[0x6C], a[0x6D], a[0x6E], a[0x6F]]));
    s
}

fn bench(c: &mut Criterion) {
    let mut buf = [0u8; 256];
    for (i, x) in buf.iter_mut().enumerate() {
        *x = u8::try_from(i % 256)
            .expect("i % 256 fits u8")
            .wrapping_mul(31)
            .wrapping_add(7);
    }
    assert_eq!(sum_read_le(&buf), sum_arrayref(&buf), "isomorphism");

    let mut g = c.benchmark_group("inode_base_read");
    g.bench_function("read_le_per_field", |b| {
        b.iter(|| black_box(sum_read_le(black_box(&buf))));
    });
    g.bench_function("arrayref_const_offset", |b| {
        b.iter(|| black_box(sum_arrayref(black_box(&buf))));
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
