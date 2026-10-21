//! ZERO_RANGE exercised through FsOps, including the native allocation and
//! failure-quarantine paths. Reuse the pending/durable image fixture unchanged.

use super::*;

const ZERO: i32 = libc::FALLOC_FL_ZERO_RANGE;
const KEEP: i32 = libc::FALLOC_FL_KEEP_SIZE;

fn target(kind: FatKind, sector: u32, active: bool, payload: &[u8]) -> (Image, FatFs, InodeNumber) {
    let image = Image::new(kind, sector, active);
    let (fs, _) = image.mount();
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let ino = fs
        .create(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("ZERO.BIN"),
            0o644,
            1000,
            1000,
        )
        .unwrap()
        .ino;
    if !payload.is_empty() {
        fs.write(&cx, &mut scope, ino, 0, payload).unwrap();
    }
    image.device.disk.lock().unwrap().attempts = 0;
    (image, fs, ino)
}

fn profiles() -> [(FatKind, bool); 3] {
    [
        (FatKind::Fat16, false),
        (FatKind::Fat32, false),
        (FatKind::Fat32, true),
    ]
}

#[test]
fn zero_range_preserves_unaligned_edges_fragmented_chains_and_reopened_bytes() {
    for (kind, active) in profiles() {
        for sector in [512, 4096] {
            let mut expected: Vec<u8> = (0..3 * sector + 37)
                .map(|at| (at % 251 + 1) as u8)
                .collect();
            let (image, fs, ino) = target(kind, sector, active, &expected);
            let cx = Cx::for_testing();
            let mut scope = RequestScope::empty();
            let chain = native_chain(&fs, "/ZERO.BIN");
            assert!(chain.clusters.windows(2).any(|pair| pair[1] != pair[0] + 1));
            let before = fs.getattr(&cx, &mut scope, ino).unwrap();
            let before_free = free(&fs);
            let start = u64::from(sector) - 7;
            let length = u64::from(sector) + 23;
            fs.fallocate(&cx, &mut scope, ino, start, length, ZERO)
                .unwrap();
            expected[start as usize..(start + length) as usize].fill(0);
            assert_eq!(
                fs.read(&cx, &mut scope, ino, 0, before.size as u32)
                    .unwrap(),
                expected
            );
            assert_eq!(native_chain(&fs, "/ZERO.BIN").clusters, chain.clusters);
            let after = fs.getattr(&cx, &mut scope, ino).unwrap();
            assert_eq!(
                (after.size, after.blocks, after.ino),
                (before.size, before.blocks, ino)
            );
            assert_eq!(free(&fs), before_free);
            let reopened = image.volume();
            let entry = reopened.resolve(&cx, "/ZERO.BIN").unwrap().unwrap();
            let chain = reopened.file_chain(&cx, &entry).unwrap();
            assert_eq!(
                reopened.read(&cx, &chain, 0, expected.len()).unwrap(),
                expected
            );
            assert!(reopened.check(&cx).unwrap().clean);
            image.guards();
        }
    }
}

#[test]
fn zero_keep_size_reserves_without_exposing_eof_and_later_growth_reuses_capacity() {
    for (kind, active) in profiles() {
        for sector in [512, 4096] {
            let mut expected = vec![0x6D; sector as usize + 17];
            let (image, fs, ino) = target(kind, sector, active, &expected);
            let cx = Cx::for_testing();
            let mut scope = RequestScope::empty();
            let before_free = free(&fs);
            let original = native_chain(&fs, "/ZERO.BIN");
            let inactive = (kind == FatKind::Fat32 && active).then(|| {
                let at = image.base + image.geometry.entry_offset(0, 2).unwrap() - 8;
                (at, image.bytes(at, sector as usize))
            });
            let start = u64::from(sector) + 5;
            let end = 3 * u64::from(sector) + 16;
            fs.fallocate(&cx, &mut scope, ino, start, end - start, ZERO | KEEP)
                .unwrap();
            expected[start as usize..].fill(0);
            let after = fs.getattr(&cx, &mut scope, ino).unwrap();
            assert_eq!(after.size, expected.len() as u64);
            assert_eq!(after.blocks, 4 * u64::from(sector) / 512);
            assert_eq!(free(&fs), before_free - 2);
            assert_eq!(
                fs.statfs(&cx, &mut scope, ROOT).unwrap().blocks_free,
                before_free - 2
            );
            assert_eq!(
                fs.read(&cx, &mut scope, ino, 0, end as u32).unwrap(),
                expected
            );
            let reserved = native_chain(&fs, "/ZERO.BIN");
            assert_eq!(
                &reserved.clusters[..original.clusters.len()],
                &original.clusters
            );
            let reopened = image.volume();
            let entry = reopened.resolve(&cx, "/ZERO.BIN").unwrap().unwrap();
            assert_eq!(entry.native.size as usize, expected.len());
            assert_eq!(
                reopened.file_chain(&cx, &entry).unwrap().clusters,
                reserved.clusters
            );
            fs.fallocate(&cx, &mut scope, ino, 0, end, 0).unwrap();
            expected.resize(end as usize, 0);
            assert_eq!(
                fs.read(&cx, &mut scope, ino, 0, end as u32).unwrap(),
                expected
            );
            assert_eq!(native_chain(&fs, "/ZERO.BIN").clusters, reserved.clusters);
            assert_eq!(free(&fs), before_free - 2);
            if let Some((at, bytes)) = inactive {
                assert_eq!(image.bytes(at, bytes.len()), bytes);
            }
            image.guards();
        }
    }
}

#[test]
fn empty_zero_reservations_and_full_volume_zeroing_need_no_replacement_chain() {
    for (kind, active) in profiles() {
        let (image, fs, ino) = target(kind, 512, active, &[]);
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        fs.fallocate(&cx, &mut scope, ino, 700, 900, ZERO | KEEP)
            .unwrap();
        assert_eq!(fs.getattr(&cx, &mut scope, ino).unwrap().size, 0);
        assert_eq!(fs.getattr(&cx, &mut scope, ino).unwrap().blocks, 4);
        assert_eq!(
            fs.read(&cx, &mut scope, ino, 0, 1600).unwrap(),
            [] as [u8; 0]
        );
        fs.write(&cx, &mut scope, ino, 1599, b"Z").unwrap();
        let mut expected = vec![0; 1600];
        expected[1599] = b'Z';
        assert_eq!(fs.read(&cx, &mut scope, ino, 0, 1600).unwrap(), expected);
        image.guards();
    }
    let (image, fs, ino) = target(FatKind::Fat16, 512, false, b"untouched");
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let capacity = (free(&fs) + 1) * 512;
    fs.fallocate(&cx, &mut scope, ino, 0, capacity, KEEP)
        .unwrap();
    let reserved = native_chain(&fs, "/ZERO.BIN").clusters;
    assert_eq!(free(&fs), 0);
    fs.fallocate(&cx, &mut scope, ino, 1, 4, ZERO | KEEP)
        .unwrap();
    let mut expected = b"untouched".to_vec();
    expected[1..5].fill(0);
    assert_eq!(fs.read(&cx, &mut scope, ino, 0, 9).unwrap(), expected);
    fs.fallocate(&cx, &mut scope, ino, capacity - 7, 7, ZERO)
        .unwrap();
    assert_eq!(fs.getattr(&cx, &mut scope, ino).unwrap().size, capacity);
    assert_eq!(
        fs.read(&cx, &mut scope, ino, capacity - 8, 8).unwrap(),
        [0; 8]
    );
    assert_eq!(fs.read(&cx, &mut scope, ino, 0, 9).unwrap(), expected);
    assert_eq!(native_chain(&fs, "/ZERO.BIN").clusters, reserved);
    assert_eq!(free(&fs), 0);
    let attempts = image.device.disk.lock().unwrap().attempts;
    assert!(matches!(
        fs.fallocate(&cx, &mut scope, ino, capacity, 1, ZERO),
        Err(FfsError::NoSpace)
    ));
    assert_eq!(image.device.disk.lock().unwrap().attempts, attempts);
    image.guards();
}

#[test]
fn invalid_zero_requests_preserve_bytes_and_leave_the_mount_usable() {
    for (kind, active) in profiles() {
        let (image, fs, ino) = target(kind, 512, active, b"unchanged");
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let before = image.device.disk.lock().unwrap().durable.clone();
        for (offset, length, mode, errno) in [
            (0, 0, ZERO, libc::EINVAL),
            (u64::MAX, 2, ZERO, libc::EFBIG),
            (u64::from(u32::MAX), 1, ZERO | KEEP, libc::EFBIG),
            (
                0,
                1,
                ZERO | libc::FALLOC_FL_PUNCH_HOLE | KEEP,
                libc::EOPNOTSUPP,
            ),
            (
                0,
                1,
                ZERO | libc::FALLOC_FL_COLLAPSE_RANGE,
                libc::EOPNOTSUPP,
            ),
            (0, 1, -1, libc::EOPNOTSUPP),
        ] {
            assert!(
                matches!(fs.fallocate(&cx, &mut scope, ino, offset, length, mode), Err(FfsError::Io(error)) if error.raw_os_error() == Some(errno))
            );
        }
        assert!(matches!(
            fs.fallocate(&cx, &mut scope, ROOT, 0, 1, ZERO),
            Err(FfsError::IsDirectory)
        ));
        assert!(matches!(
            fs.fallocate(&cx, &mut scope, ino, 0, u64::from(u32::MAX), ZERO),
            Err(FfsError::NoSpace)
        ));
        let cancelled = Cx::for_testing();
        cancelled.cancel_with(
            asupersync::types::CancelKind::User,
            Some("before zero range"),
        );
        assert!(matches!(
            fs.fallocate(&cancelled, &mut scope, ino, 0, 1, ZERO),
            Err(FfsError::Cancelled)
        ));
        {
            let disk = image.device.disk.lock().unwrap();
            assert_eq!(disk.attempts, 0);
            assert_eq!(disk.durable, before);
            assert!(disk.pending.is_empty());
        }
        fs.fallocate(&cx, &mut scope, ino, 1, 1, ZERO).unwrap();
        assert_eq!(fs.read(&cx, &mut scope, ino, 0, 9).unwrap(), b"u\0changed");
        fs.setattr(
            &cx,
            &mut scope,
            ino,
            &SetAttrRequest {
                mode: Some(0o444),
                ..Default::default()
            },
        )
        .unwrap();
        let attempts = image.device.disk.lock().unwrap().attempts;
        assert!(matches!(
            fs.fallocate(&cx, &mut scope, ino, 0, 1, ZERO),
            Err(FfsError::PermissionDenied)
        ));
        assert_eq!(image.device.disk.lock().unwrap().attempts, attempts);
        image.guards();
    }
}

#[test]
fn every_zero_write_and_sync_cut_quarantines_without_a_clean_partial_success() {
    for (kind, active) in profiles() {
        for mode in [ZERO, ZERO | KEEP] {
            let (baseline, fs, ino) = target(kind, 512, active, b"ABCDEFGH");
            fs.fallocate(
                &Cx::for_testing(),
                &mut RequestScope::empty(),
                ino,
                2,
                1600,
                mode,
            )
            .unwrap();
            let count = baseline.device.disk.lock().unwrap().attempts;
            assert!(count > 8);
            for fail in 1..=count {
                for tear in [0, 17, 511] {
                    let (image, fs, ino) = target(kind, 512, active, b"ABCDEFGH");
                    {
                        let mut disk = image.device.disk.lock().unwrap();
                        disk.fail_at = Some(fail);
                        disk.tear = tear;
                    }
                    assert!(
                        fs.fallocate(
                            &Cx::for_testing(),
                            &mut RequestScope::empty(),
                            ino,
                            2,
                            1600,
                            mode
                        )
                        .is_err(),
                        "{kind:?} mode={mode} fail={fail} tear={tear}"
                    );
                    stopped(&fs, &image, ino);
                    image.guards();
                    for retain in [false, true] {
                        let durable = {
                            let disk = image.device.disk.lock().unwrap();
                            let mut bytes = disk.durable.clone();
                            if retain {
                                bytes.extend(disk.pending.clone());
                            }
                            bytes
                        };
                        let device = Device {
                            disk: Arc::new(Mutex::new(Disk {
                                durable,
                                ..Disk::default()
                            })),
                            length: image.device.length,
                        };
                        let cx = Cx::for_testing();
                        if let Ok(reopened) = FatVolume::from_device(
                            &cx,
                            Box::new(device),
                            image.base,
                            image.geometry.volume_bytes(),
                        ) {
                            let check = reopened.check(&cx).unwrap();
                            if check.clean && check.complete && check.namespace_complete {
                                let entry = reopened.resolve(&cx, "/ZERO.BIN").unwrap().unwrap();
                                let chain = reopened.file_chain(&cx, &entry).unwrap();
                                let bytes = reopened.read(&cx, &chain, 0, 1603).unwrap();
                                let mut expected = b"AB".to_vec();
                                expected.resize(if mode == ZERO { 1602 } else { 8 }, 0);
                                assert!(bytes == b"ABCDEFGH" || bytes == expected);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn lost_zero_overwrites_are_detected_instead_of_reading_back_their_own_oracle() {
    for (kind, active) in profiles() {
        let (image, fs, ino) = target(kind, 512, active, b"ABCDEFGH");
        let first = native_chain(&fs, "/ZERO.BIN").clusters[0];
        let physical = image.base + image.geometry.cluster_offset(first).unwrap();
        image.device.disk.lock().unwrap().drop_write_at = Some(physical + 1);
        assert!(
            fs.fallocate(
                &Cx::for_testing(),
                &mut RequestScope::empty(),
                ino,
                1,
                1,
                ZERO | KEEP
            )
            .is_err()
        );
        assert_eq!(image.bytes(physical, 8), b"ABCDEFGH");
        stopped(&fs, &image, ino);
        image.guards();
    }
}

#[test]
fn zero_ranges_larger_than_the_read_request_limit_remain_bounded_and_persistent() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let (image, fs, ino) = target(kind, 4096, kind == FatKind::Fat32, b"preserved");
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let start = 32_771;
        let length = 16 * 1024 * 1024 + 19;
        let end = start + length;
        fs.fallocate(&cx, &mut scope, ino, start, length, ZERO)
            .unwrap();
        assert_eq!(fs.getattr(&cx, &mut scope, ino).unwrap().size, end);
        assert_eq!(fs.read(&cx, &mut scope, ino, 0, 9).unwrap(), b"preserved");
        for at in [9, start - 7, start, 16 * 1024 * 1024] {
            assert_eq!(fs.read(&cx, &mut scope, ino, at, 31).unwrap(), [0; 31]);
        }
        let reopened = image.volume();
        let entry = reopened.resolve(&cx, "/ZERO.BIN").unwrap().unwrap();
        let chain = reopened.file_chain(&cx, &entry).unwrap();
        assert_eq!(u64::from(chain.size), end);
        assert_eq!(reopened.read(&cx, &chain, end - 19, 32).unwrap(), [0; 19]);
        assert!(reopened.check(&cx).unwrap().clean);
        image.guards();
    }
}
