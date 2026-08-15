#![forbid(unsafe_code)]
//! `inode_to_attr` (every getattr/lookup on a cache miss — the cache-disabled
//! stat walk) builds 4 `SystemTime`s (atime/mtime/ctime/crtime) via
//! `UNIX_EPOCH.checked_add(Duration::new(secs, nsec))`. The FUSE reply then
//! converts each SystemTime BACK to (secs, nsec) — a round-trip. An InodeAttr
//! that stored raw (secs, nsec) would skip both. Measure the construction cost:
//! 4× `*_system_time()` (current) vs 4× `*_full()` (raw (secs,nsec) extraction,
//! what a compact InodeAttr would use). If the delta is large the design turn
//! pays; if tiny, it does not.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench inode_attr_times
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::ext4::Ext4Inode;
use std::hint::black_box;

fn make_inode() -> [u8; 256] {
    let mut b = [0u8; 256];
    b[0..2].copy_from_slice(&0x81A4u16.to_le_bytes());
    b[4..8].copy_from_slice(&4096u32.to_le_bytes());
    b[26..28].copy_from_slice(&1u16.to_le_bytes());
    // atime/ctime/mtime at 0x08/0x0C/0x10; extra times at 0x84.. — give them
    // realistic non-zero (secs, nsec) so both paths do real work.
    b[0x08..0x0C].copy_from_slice(&1_700_000_000u32.to_le_bytes()); // atime
    b[0x0C..0x10].copy_from_slice(&1_700_000_001u32.to_le_bytes()); // ctime
    b[0x10..0x14].copy_from_slice(&1_700_000_002u32.to_le_bytes()); // mtime
    b[128..130].copy_from_slice(&32u16.to_le_bytes()); // i_extra_isize
    b[0x84..0x88].copy_from_slice(&((250u32 << 2) | 1).to_le_bytes()); // ctime_extra: nsec 250, epoch bit
    b[0x88..0x8C].copy_from_slice(&((500u32 << 2) | 1).to_le_bytes()); // mtime_extra
    b[0x8C..0x90].copy_from_slice(&((750u32 << 2) | 1).to_le_bytes()); // atime_extra
    b[0x90..0x94].copy_from_slice(&((123u32 << 2) | 1).to_le_bytes()); // crtime_extra
    b
}

fn bench(c: &mut Criterion) {
    let buf = make_inode();
    let inode = Ext4Inode::parse_from_bytes(&buf).expect("parse");

    let mut g = c.benchmark_group("inode_attr_times");
    // Current: 4 SystemTime constructions (as inode_to_attr does).
    g.bench_function("systemtime_x4", |b| {
        b.iter(|| {
            let a = black_box(&inode);
            black_box((
                a.atime_system_time(),
                a.mtime_system_time(),
                a.ctime_system_time(),
                a.crtime_system_time(),
            ))
        })
    });
    // Compact: 4 raw (secs, nsec) extractions (what a raw-time InodeAttr uses).
    g.bench_function("raw_full_x4", |b| {
        b.iter(|| {
            let a = black_box(&inode);
            black_box((
                a.atime_full(),
                a.mtime_full(),
                a.ctime_full(),
                a.crtime_full(),
            ))
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
