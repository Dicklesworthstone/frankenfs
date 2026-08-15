#![forbid(unsafe_code)]
//! `write_entry`'s 8-byte dir-entry header write (inode u32, rec_len u16,
//! name_len u8, file_type u8) at a RUNTIME offset into a cross-function block —
//! on the hot create/rename add path. `write_entry` first checks
//! `offset + rec_len <= block.len()` (same-function). Q: are the 4 per-field
//! bounds checks elided by that check, or does an array-ref reslice
//! (`&mut block[off..off+8] as &mut [u8; 8]`, one check + const-offset writes)
//! win? Measure both, replicating the same-function length check.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-dir --bench entry_header_write
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const HDR: usize = 8;

/// Production shape: 4 bounds-checked slice writes after the end<=len check.
#[inline]
fn checked(block: &mut [u8], off: usize, rec_len: usize, ino: u32, nl: u8, ft: u8) -> bool {
    let end = match off.checked_add(rec_len) {
        Some(e) => e,
        None => return false,
    };
    if end > block.len() || rec_len < HDR {
        return false;
    }
    block[off..off + 4].copy_from_slice(&ino.to_le_bytes());
    block[off + 4..off + 6].copy_from_slice(&(rec_len as u16).to_le_bytes());
    block[off + 6] = nl;
    block[off + 7] = ft;
    true
}

/// Array-ref reslice: one bounds check (`try_into`), then const-offset writes.
#[inline]
fn arrayref(block: &mut [u8], off: usize, rec_len: usize, ino: u32, nl: u8, ft: u8) -> bool {
    let end = match off.checked_add(rec_len) {
        Some(e) => e,
        None => return false,
    };
    if end > block.len() || rec_len < HDR {
        return false;
    }
    let Ok(h) = <&mut [u8; 8]>::try_from(&mut block[off..off + 8]) else {
        return false;
    };
    h[0..4].copy_from_slice(&ino.to_le_bytes());
    h[4..6].copy_from_slice(&(rec_len as u16).to_le_bytes());
    h[6] = nl;
    h[7] = ft;
    true
}

fn bench(c: &mut Criterion) {
    let mut block = vec![0u8; 4096];
    // sanity: identical bytes
    let mut a = block.clone();
    let mut b = block.clone();
    checked(&mut a, 100, 20, 0x1234_5678, 11, 1);
    arrayref(&mut b, 100, 20, 0x1234_5678, 11, 1);
    assert_eq!(a, b);

    let mut g = c.benchmark_group("entry_header_write");
    g.bench_function("checked", |bch| {
        bch.iter(|| {
            let off = black_box(100usize);
            black_box(checked(
                black_box(&mut block),
                off,
                black_box(20),
                black_box(0x1234_5678),
                11,
                1,
            ))
        })
    });
    g.bench_function("arrayref", |bch| {
        bch.iter(|| {
            let off = black_box(100usize);
            black_box(arrayref(
                black_box(&mut block),
                off,
                black_box(20),
                black_box(0x1234_5678),
                11,
                1,
            ))
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
