#![forbid(unsafe_code)]
//! `add_entry_tracked` / `remove_entry_take_inode_tracked` walk a dir block
//! reading 3 header fields per entry — inode (u32 @off), rec_len (u16 @off+4),
//! name_len (u8 @off+6) — via the `get()`-based `read_u16_le`/`read_u32_le`
//! helpers (1 slice check each) + `block[off+6]`, inside a loop guarded by
//! `off + 8 <= limit`. FAITHFUL model of production: `limit` comes from
//! `validate_reserved_tail` (an OPAQUE value — the compiler cannot prove
//! `limit <= block.len()`), so the per-field checks against `block.len()` are
//! NOT elided. The array-REF reslice does one check per entry. This is the
//! honest baseline (the helpers, opaque limit) — NOT direct byte-indexing.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-dir --bench entry_header_read
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const HDR: usize = 8;

/// ffs-dir's actual `read_u16_le` (get-based, one slice check).
#[inline]
fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    let b = buf.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}
#[inline]
fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn make_block() -> Vec<u8> {
    let mut block = vec![0u8; 4096];
    let rec_len: u16 = 24;
    let mut off = 0usize;
    let mut ino: u32 = 12;
    while off + rec_len as usize <= 4096 {
        block[off..off + 4].copy_from_slice(&ino.to_le_bytes());
        block[off + 4..off + 6].copy_from_slice(&rec_len.to_le_bytes());
        block[off + 6] = 11;
        block[off + 7] = 1;
        off += rec_len as usize;
        ino += 1;
    }
    block
}

/// Production shape: the real `get()`-based helpers, opaque `limit`.
#[inline]
fn walk_checked(block: &[u8], limit: usize) -> u64 {
    let mut off = 0usize;
    let mut acc: u64 = 0;
    while off + HDR <= limit {
        let rec_len = read_u16_le(block, off + 4).unwrap() as usize;
        if rec_len < HDR {
            break;
        }
        let ino = read_u32_le(block, off).unwrap();
        let name_len = u64::from(block[off + 6]);
        acc = acc.wrapping_add(u64::from(ino)).wrapping_add(name_len);
        off += rec_len;
    }
    acc
}

/// Array-ref reslice: one check per entry, then const-offset reads.
#[inline]
fn walk_arrayref(block: &[u8], limit: usize) -> u64 {
    let mut off = 0usize;
    let mut acc: u64 = 0;
    while off + HDR <= limit {
        let h: &[u8; 8] = match block[off..off + HDR].try_into() {
            Ok(h) => h,
            Err(_) => break,
        };
        let rec_len = u16::from_le_bytes([h[4], h[5]]) as usize;
        if rec_len < HDR {
            break;
        }
        let ino = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        let name_len = u64::from(h[6]);
        acc = acc.wrapping_add(u64::from(ino)).wrapping_add(name_len);
        off += rec_len;
    }
    acc
}

fn bench(c: &mut Criterion) {
    let block = make_block();
    // Opaque limit < block.len() (models validate_reserved_tail's reserved tail).
    let limit = black_box(block.len() - 12);
    assert_eq!(walk_checked(&block, limit), walk_arrayref(&block, limit));

    let mut g = c.benchmark_group("entry_header_read");
    g.bench_function("checked", |b| {
        b.iter(|| black_box(walk_checked(black_box(&block), black_box(limit))));
    });
    g.bench_function("arrayref", |b| {
        b.iter(|| black_box(walk_arrayref(black_box(&block), black_box(limit))));
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
