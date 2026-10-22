//! Exercise the real FsOps adapter over the existing sparse native-layout device.
//! These are not kernel FUSE or independent native-tool qualification results.

use super::*;
use crate::FatFs;
use ffs_core::{FsOps, RequestScope, SeekWhence};
use ffs_types::InodeNumber;
use std::ffi::OsStr;

const ROOT: InodeNumber = InodeNumber(1);

fn mount(fixture: &Fixture, writable: bool) -> FatFs {
    FatFs::new_with_mode(
        &Cx::for_testing(),
        fixture.device.volume(),
        1000,
        1000,
        writable,
    )
    .unwrap()
}

fn lookup(fs: &FatFs, name: &str) -> ffs_core::InodeAttr {
    fs.lookup(
        &Cx::for_testing(),
        &mut RequestScope::empty(),
        ROOT,
        OsStr::new(name),
    )
    .unwrap()
}

fn fat_reads(device: &Device) -> usize {
    device
        .0
        .trace
        .lock()
        .unwrap()
        .reads
        .iter()
        .filter(|(at, length)| {
            device
                .0
                .fats
                .iter()
                .any(|range| *at < range.end && *at + *length as u64 > range.start)
        })
        .count()
}

fn add_file(fixture: &Fixture, slot: u64, name: &[u8; 11], first: u32, count: u32, size: u32) {
    let geometry = &fixture.volume.geometry;
    let kind = geometry.kind();
    let mut record = [0_u8; 32];
    record[..11].copy_from_slice(name);
    record[11] = 0x20;
    if kind == FatKind::Fat32 {
        record[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
    }
    record[26..28].copy_from_slice(&(first as u16).to_le_bytes());
    record[28..32].copy_from_slice(&size.to_le_bytes());
    fixture
        .device
        .put(fixture.device.0.root + slot * 32, &record);
    for copy in 0..2 {
        for index in 0..count {
            let value = if index + 1 == count {
                if kind == FatKind::Fat16 {
                    0xffff_u32
                } else {
                    0x0fff_ffff
                }
            } else {
                first + index + 1
            };
            fixture.device.put(
                BASE + geometry.entry_offset(copy, first + index).unwrap(),
                &value.to_le_bytes()[..kind.entry_bytes() as usize],
            );
        }
    }
}

#[test]
fn immutable_fsops_maximum_file_keeps_sparse_index_through_stat_open_seek_and_read() {
    let count = u64::from(u32::MAX).div_ceil(4096) as usize;
    let fixture = Fixture::linear(FatKind::Fat32, 4096, count, u32::MAX);
    let fs = mount(&fixture, false);
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    fixture.device.reset();
    let attr = lookup(&fs, "DATA.BIN");
    assert_eq!(attr.size, u64::from(u32::MAX));
    assert_eq!(attr.blocks, count as u64 * 8);
    assert_eq!(fixture.device.data_reads(), Vec::<(u64, usize)>::new());
    let usage = fs.immutable_cache_usage();
    assert_eq!((usage.0, usage.2), (1, 0));
    assert!(usage.1 <= 16 * 1024, "{usage:?}");

    // Warm stat/open/seek need counts, not another million-cluster vector or walk.
    fixture.device.reset();
    assert_eq!(
        fs.getattr(&cx, &mut scope, attr.ino).unwrap().size,
        attr.size
    );
    fs.open(&cx, &mut scope, attr.ino, libc::O_RDONLY).unwrap();
    assert_eq!(
        fs.lseek(&cx, &mut scope, attr.ino, 0, SeekWhence::Hole)
            .unwrap(),
        attr.size
    );
    assert_eq!(
        fixture.device.0.trace.lock().unwrap().reads,
        Vec::<(u64, usize)>::new()
    );
    for at in [0, 1, 1_048_575, 2_147_483_647, u64::from(u32::MAX) - 4097] {
        assert_eq!(
            fs.read(&cx, &mut scope, attr.ino, at, 8192).unwrap(),
            fixture.expected(&[], at, 8192)
        );
    }
    fixture.device.reset();
    assert_eq!(
        fs.read(&cx, &mut scope, attr.ino, attr.size, 8192)
            .unwrap(),
        Vec::<u8>::new()
    );
    assert_eq!(
        fs.read(&cx, &mut scope, attr.ino, u64::MAX, 8192)
            .unwrap(),
        Vec::<u8>::new()
    );
    assert_eq!(
        fixture.device.0.trace.lock().unwrap().reads,
        Vec::<(u64, usize)>::new()
    );
    assert_eq!(fs.immutable_cache_usage(), usage);
}

#[test]
fn readonly_fragmented_reads_and_block_counts_preserve_preallocation_and_native_eof() {
    let chain: Vec<_> = (0..1031_u32).map(|n| 3 + (n * 37) % 1031).collect();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512_u16, 4096] {
            let fixture = Fixture::new(kind, sector, &chain, 1000 * u32::from(sector) - 17);
            let fs = mount(&fixture, false);
            let attr = lookup(&fs, "data.bin");
            let cx = Cx::for_testing();
            let mut scope = RequestScope::empty();
            assert_eq!(attr.blocks, chain.len() as u64 * u64::from(sector) / 512);
            for n in [999, 0, 256, 255, 513, 512, 1, 998, 768, 767] {
                let at = n * u64::from(sector) + 13;
                assert_eq!(
                    fs.read(&cx, &mut scope, attr.ino, at, 8197).unwrap(),
                    fixture.expected(&chain, at, 8197)
                );
            }
            assert_eq!(
                fs.lseek(&cx, &mut scope, attr.ino, 17, SeekWhence::Data)
                    .unwrap(),
                17
            );
            assert_eq!(
                fs.lseek(&cx, &mut scope, attr.ino, 17, SeekWhence::Hole)
                    .unwrap(),
                attr.size
            );
            assert_eq!(
                fs.lseek(&cx, &mut scope, attr.ino, attr.size, SeekWhence::Data)
                    .unwrap_err()
                    .to_errno(),
                libc::ENXIO
            );
            assert_eq!(
                fs.write(&cx, &mut scope, attr.ino, 0, b"no")
                    .unwrap_err()
                    .to_errno(),
                libc::EROFS
            );
            assert_eq!(
                fs.open(&cx, &mut scope, attr.ino, libc::O_RDWR)
                    .unwrap_err()
                    .to_errno(),
                libc::EROFS
            );
            assert_eq!(fs.immutable_cache_usage().2, 0);
        }
    }
}

#[test]
fn cache_eviction_respects_capacity_and_entry_limits_without_stale_inode_reuse() {
    for (bytes, entries) in [(128, 2), (4096, 1), (0, 4), (4096, 0)] {
        let fixture = Fixture::linear(FatKind::Fat16, 512, 600, 600 * 512);
        add_file(&fixture, 1, b"SECOND  BIN", 1203, 600, 600 * 512);
        add_file(&fixture, 2, b"THIRD   BIN", 2403, 600, 600 * 512);
        let fs = mount(&fixture, false);
        fs.limit_immutable_cache(bytes, entries);
        let attrs = [
            lookup(&fs, "DATA.BIN"),
            lookup(&fs, "SECOND.BIN"),
            lookup(&fs, "THIRD.BIN"),
        ];
        for (attr, head) in attrs.iter().zip([3, 1203, 2403]) {
            fixture.device.reset();
            let cx = Cx::for_testing();
            let got = fs
                .read(&cx, &mut RequestScope::empty(), attr.ino, 17, 67)
                .unwrap();
            let physical = BASE + fixture.volume.geometry.cluster_offset(head).unwrap() + 17;
            let expected: Vec<_> = (physical..physical + 67)
                .map(|at| (at % 251) as u8)
                .collect();
            assert_eq!(got, expected);
            let (retained, capacity, maps) = fs.immutable_cache_usage();
            assert!(retained <= entries && capacity <= bytes);
            assert_eq!(maps, 0);
            // The first object was evicted or never admitted. Reuse has to
            // validate that object's complete chain before serving its bytes.
            if head == 3 {
                assert!(fat_reads(&fixture.device) > 0);
            }
        }
    }
}

#[test]
fn zero_byte_indexes_still_obey_entry_bound_and_keep_allocated_empty_files_empty() {
    for allocated in [0, 600] {
        let fixture = Fixture::linear(FatKind::Fat32, 512, allocated, 0);
        add_file(&fixture, 1, b"SECOND  BIN", 0, 0, 0);
        add_file(&fixture, 2, b"THIRD   BIN", 0, 0, 0);
        let fs = mount(&fixture, false);
        fs.limit_immutable_cache(4096, 2);
        let attr = lookup(&fs, "DATA.BIN");
        assert_eq!((attr.size, attr.blocks), (0, allocated as u64));
        for name in ["SECOND.BIN", "THIRD.BIN"] {
            lookup(&fs, name);
        }
        fixture.device.reset();
        let read = fs
            .read(
                &Cx::for_testing(),
                &mut RequestScope::empty(),
                attr.ino,
                0,
                4096,
            )
            .unwrap();
        assert_eq!(read, Vec::<u8>::new());
        assert_eq!(fixture.device.data_reads(), Vec::<(u64, usize)>::new());
        assert!(fs.immutable_cache_usage().0 <= 2);
        assert_eq!(fs.immutable_cache_usage().2, 0);
    }
}

#[test]
fn invalid_cold_tail_cannot_enter_mounted_cache_or_expose_payload() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for fault in ["free", "bad", "cycle", "mirror"] {
            let fixture = Fixture::linear(kind, 512, 600, 1);
            let fs = mount(&fixture, false);
            let value = match (kind, fault) {
                (FatKind::Fat16, "bad") => 0xfff7_u32,
                (FatKind::Fat32, "bad") => 0x0fff_fff7,
                (_, "cycle") => 259,
                _ => 0,
            };
            for copy in 0..if fault == "mirror" { 1 } else { 2 } {
                fixture.device.put(
                    BASE + fixture.volume.geometry.entry_offset(copy, 602).unwrap(),
                    &value.to_le_bytes()[..kind.entry_bytes() as usize],
                );
            }
            fixture.device.reset();
            assert!(
                fs.lookup(
                    &Cx::for_testing(),
                    &mut RequestScope::empty(),
                    ROOT,
                    OsStr::new("DATA.BIN")
                )
                .is_err(),
                "{kind:?}/{fault}"
            );
            assert_eq!(fs.immutable_cache_usage(), (0, 0, 0));
            assert_eq!(fixture.device.data_reads(), Vec::<(u64, usize)>::new());
        }
    }
}

#[test]
fn cached_reads_have_request_local_errors_and_cancellation_never_return_partial_data() {
    let fixture = Fixture::linear(FatKind::Fat32, 512, 2000, 2000 * 512);
    let fs = mount(&fixture, false);
    let attr = lookup(&fs, "DATA.BIN");
    let usage = fs.immutable_cache_usage();
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    fixture.device.reset();
    let bad = BASE + fixture.volume.geometry.cluster_offset(3).unwrap() + 65_536;
    fixture.device.0.trace.lock().unwrap().fail = Some(bad..bad + 1);
    assert!(fs.read(&cx, &mut scope, attr.ino, 0, 131_072).is_err());
    assert_eq!(fixture.device.data_reads().len(), 2);
    fixture.device.reset();
    assert_eq!(
        fs.read(&cx, &mut scope, attr.ino, 0, 131_072).unwrap(),
        fixture.expected(&[], 0, 131_072)
    );

    fixture.device.reset();
    let bad = BASE + fixture.volume.geometry.entry_offset(1, 260).unwrap();
    fixture.device.0.trace.lock().unwrap().fail = Some(bad..bad + 4);
    assert!(fs.read(&cx, &mut scope, attr.ino, 270 * 512, 1).is_err());
    assert_eq!(fixture.device.data_reads(), Vec::<(u64, usize)>::new());
    fixture.device.reset();
    assert_eq!(
        fs.read(&cx, &mut scope, attr.ino, 270 * 512, 1).unwrap(),
        fixture.expected(&[], 270 * 512, 1)
    );

    fixture.device.reset();
    let cancelled = Cx::for_testing();
    fixture.device.0.trace.lock().unwrap().cancel_after = Some(1);
    assert!(matches!(
        fs.read(&cancelled, &mut scope, attr.ino, 0, 1),
        Err(FfsError::Cancelled)
    ));
    fixture.device.reset();
    assert!(matches!(
        fs.read(&cancelled, &mut scope, attr.ino, u64::MAX, 0),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(
        fixture.device.0.trace.lock().unwrap().reads,
        Vec::<(u64, usize)>::new()
    );
    assert_eq!(
        fs.read(&cx, &mut scope, attr.ino, 0, 1).unwrap(),
        fixture.expected(&[], 0, 1)
    );
    assert_eq!(fs.immutable_cache_usage(), usage);
}

#[test]
fn cancelled_cold_validation_does_not_publish_partial_indexes_or_poison_retry() {
    let fixture = Fixture::linear(FatKind::Fat32, 512, 2000, 2000 * 512);
    let fs = mount(&fixture, false);
    let page = fs
        .readdir(&Cx::for_testing(), &mut RequestScope::empty(), ROOT, 0)
        .unwrap();
    let ino = page
        .iter()
        .find(|entry| entry.name == b"DATA.BIN")
        .unwrap()
        .ino;
    fixture.device.reset();
    let cancelled = Cx::for_testing();
    fixture.device.0.trace.lock().unwrap().cancel_after = Some(2);
    assert!(matches!(
        fs.read(&cancelled, &mut RequestScope::empty(), ino, 0, 1),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(fs.immutable_cache_usage(), (0, 0, 0));
    assert_eq!(fixture.device.data_reads(), Vec::<(u64, usize)>::new());
    fixture.device.reset();
    assert_eq!(
        fs.read(&Cx::for_testing(), &mut RequestScope::empty(), ino, 0, 17)
            .unwrap(),
        fixture.expected(&[], 0, 17)
    );
    assert_eq!(fs.immutable_cache_usage().0, 1);
    assert_eq!(fs.immutable_cache_usage().2, 0);
}

#[test]
fn concurrent_cold_fsops_reads_share_only_index_evidence_not_seek_cursors() {
    let fixture = Fixture::linear(FatKind::Fat32, 512, 2000, 2000 * 512);
    let fs = Arc::new(mount(&fixture, false));
    // Register a node without getattr building its allocation index first.
    let page = fs
        .readdir(&Cx::for_testing(), &mut RequestScope::empty(), ROOT, 0)
        .unwrap();
    let ino = page
        .iter()
        .find(|entry| entry.name == b"DATA.BIN")
        .unwrap()
        .ino;
    assert_eq!(fs.immutable_cache_usage(), (0, 0, 0));
    let start = Arc::new(std::sync::Barrier::new(8));
    let mut threads = Vec::new();
    for thread in 0..8_u64 {
        let fs = Arc::clone(&fs);
        let start = Arc::clone(&start);
        let cases: Vec<_> = (0..16_u64)
            .map(|n| {
                let offset = (thread * 71_111 + n * 7919) % (2000 * 512 - 4099);
                (offset, fixture.expected(&[], offset, 4099))
            })
            .collect();
        threads.push(std::thread::spawn(move || {
            let cx = Cx::for_testing();
            let mut scope = RequestScope::empty();
            start.wait();
            for (offset, expected) in cases {
                assert_eq!(
                    fs.read(&cx, &mut scope, ino, offset, 4099).unwrap(),
                    expected
                );
            }
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }
    let one_index = fixture
        .volume
        .open_file_reader(&Cx::for_testing(), &fixture.entry)
        .unwrap();
    assert_eq!(
        fs.immutable_cache_usage(),
        (1, one_index.index_storage_bytes(), 0)
    );
}

#[test]
fn explicit_fiemap_uses_temporary_map_without_polluting_immutable_cache() {
    let chain = [3, 4, 700, 701];
    let fixture = Fixture::new(FatKind::Fat16, 512, &chain, 3 * 512 + 7);
    let fs = mount(&fixture, false);
    let attr = lookup(&fs, "DATA.BIN");
    let usage = fs.immutable_cache_usage();
    let extents = fs
        .fiemap(
            &Cx::for_testing(),
            &mut RequestScope::empty(),
            attr.ino,
            0,
            u64::MAX,
        )
        .unwrap();
    assert_eq!(extents.len(), 3);
    assert_eq!((extents[0].logical, extents[0].length), (0, 1024));
    assert_eq!(
        extents[0].physical,
        fixture.volume.geometry.cluster_offset(3).unwrap()
    );
    assert_eq!((extents[1].logical, extents[1].length), (1024, 519));
    assert_eq!(
        extents[1].physical,
        fixture.volume.geometry.cluster_offset(700).unwrap()
    );
    assert_eq!((extents[2].logical, extents[2].length), (1543, 505));
    assert_ne!(extents[2].flags & 0x0800, 0);
    assert_eq!(fs.immutable_cache_usage(), usage);
}

#[test]
fn writable_mount_keeps_materialized_cache_and_does_not_retain_immutable_evidence() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let fixture = Fixture::linear(kind, 512, 600, 600 * 512);
        let fs = mount(&fixture, true);
        let attr = lookup(&fs, "DATA.BIN");
        assert_eq!(fs.immutable_cache_usage(), (0, 0, 1));
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        fs.open(&cx, &mut scope, attr.ino, libc::O_RDONLY).unwrap();
        assert_eq!(
            fs.read(&cx, &mut scope, attr.ino, 27, 4097).unwrap(),
            fixture.expected(&[], 27, 4097)
        );
        assert_eq!(fs.immutable_cache_usage(), (0, 0, 1));
    }
}
