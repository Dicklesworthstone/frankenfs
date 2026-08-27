#![forbid(unsafe_code)]
//! A FULL inode parse (`parse_from_bytes`) copies the inode's ibody xattr region
//! (`bytes[128+extra_isize..].to_vec()`) into a heap `Vec` — an alloc + copy —
//! even for inodes with NO inline xattrs (the common case). A metadata-only
//! parse (`parse_metadata_from_bytes`) skips it. Callers that need only the
//! fixed fields (times/size/mode/number) — e.g. `note_dir_name_index_insert`'s
//! per-create validation-stamp read — can use the metadata parse. A/B on a
//! 256-byte inode with `extra_isize = 32` (96-byte ibody region).
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench inode_parse_metadata
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::ext4::Ext4Inode;
use std::hint::black_box;

fn make_inode() -> [u8; 256] {
    let mut b = [0u8; 256];
    b[0..2].copy_from_slice(&0x81A4u16.to_le_bytes()); // i_mode = regular 0644
    b[4..8].copy_from_slice(&4096u32.to_le_bytes()); // i_size_lo
    b[26..28].copy_from_slice(&1u16.to_le_bytes()); // i_links_count
    b[0x28] = 0x0A; // i_block[0]: extent magic lo (0xF30A) so extent_bytes look plausible
    b[0x29] = 0xF3;
    b[128..130].copy_from_slice(&32u16.to_le_bytes()); // i_extra_isize = 32
    // Fill the ibody region [160..256] with non-zero bytes (no xattr magic).
    for (i, x) in b[160..256].iter_mut().enumerate() {
        *x = u8::try_from(i % 256)
            .expect("i % 256 fits u8")
            .wrapping_mul(7)
            .wrapping_add(1);
    }
    b
}

/// A char-device inode: i_block[0] holds the old-format rdev.
fn make_device_inode() -> [u8; 256] {
    let mut b = make_inode();
    b[0..2].copy_from_slice(&0x21A4u16.to_le_bytes()); // i_mode = S_IFCHR | 0644
    b[0x28..0x2C].copy_from_slice(&0x0103u32.to_le_bytes()); // i_block[0] = rdev 1:3
    b
}

fn bench(c: &mut Criterion) {
    let buf = make_inode();
    let full = Ext4Inode::parse_from_bytes(&buf).expect("full parse");
    let meta = Ext4Inode::parse_metadata_from_bytes(&buf).expect("metadata parse");
    let attr = Ext4Inode::parse_attr_from_bytes(&buf).expect("attr parse");
    // metadata skips the ibody copy; attr ALSO skips the extent copy (non-device).
    assert_eq!(full.size, meta.size);
    assert_eq!(full.mode, attr.mode);
    assert_eq!(meta.xattr_ibody, [] as [u8; 0]);
    assert_ne!(full.xattr_ibody, [] as [u8; 0]);
    assert!(
        attr.extent_bytes.is_empty(),
        "attr skips extents for a regular file"
    );
    // But a DEVICE inode keeps extent_bytes so device_number() still works.
    let dev = make_device_inode();
    let dev_attr = Ext4Inode::parse_attr_from_bytes(&dev).expect("attr parse device");
    assert_eq!(
        dev_attr.device_number(),
        Ext4Inode::parse_from_bytes(&dev).unwrap().device_number(),
        "device rdev preserved under attr parse"
    );

    let mut g = c.benchmark_group("inode_parse");
    g.bench_function("full", |b| {
        b.iter(|| black_box(Ext4Inode::parse_from_bytes(black_box(&buf)).unwrap()));
    });
    g.bench_function("metadata", |b| {
        b.iter(|| black_box(Ext4Inode::parse_metadata_from_bytes(black_box(&buf)).unwrap()));
    });
    g.bench_function("attr", |b| {
        b.iter(|| black_box(Ext4Inode::parse_attr_from_bytes(black_box(&buf)).unwrap()));
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
