//! Historical constructed RAIDZ1/2/3 roots retain their selected object-set owner.
//! These regressions are not native-pool or kernel FUSE interoperability evidence.

use super::*;
use crate::filesystem::ZfsFs;
use crate::reader::tests::mirror::Fault;
use crate::reader::tests::raidz::fixture::{ROOT, StripedImage, count};
use ffs_core::{FsOps, RequestScope};
use ffs_types::InodeNumber;
use std::ffi::OsStr;

const OLD_TABLE: u64 = DATA_OFFSET + 0x3_0000;
const OLD_DIRECTORY: u64 = DATA_OFFSET + 0x3_4200;
const OLD_INDIRECT: u64 = DATA_OFFSET + 0x3_5000;
const OLD_FIRST: u64 = DATA_OFFSET + 0x3_6000;
const OLD_LAST: u64 = DATA_OFFSET + 0x3_6800;
const LIVE_FIRST: u64 = DATA_OFFSET + 0x5_6000;

fn width(parity: usize) -> usize {
    if parity == 1 { 3 } else { parity + 3 }
}

fn striped_pool(order: Endian, case: u8, parity: usize) -> StripedImage {
    let image = Image::new(order, case);
    let mut meta = node(10, 16_384, 1, 0, order);
    meta[64..192].copy_from_slice(&pointer(&image.table, MOS, 10, 0, 80, order, order));
    let mut root = vec![0; 1024];
    root[..512].copy_from_slice(&meta);
    w64(&mut root, 704, 1, order);
    if parity == 1 {
        StripedImage::graph(&image.bytes, root, order, 3, 100, 90)
    } else {
        StripedImage::graph_with_parity(&image.bytes, root, order, width(parity), 100, 90, parity)
    }
}

fn poison_parity_budget(image: &mut StripedImage, key: u64, parity: usize) {
    let data = image
        .map(key)
        .columns()
        .iter()
        .filter(|column| column.data_offset.is_some())
        .count()
        .min(parity);
    for ordinal in parity..parity + data {
        image.poison(key, ordinal, ordinal * 7);
    }
    for ordinal in 0..parity - data {
        image.poison(key, ordinal, 32 + ordinal * 11);
    }
}

#[test]
fn raidz_snapshot_mounts_reconstruct_historical_bytes_without_changing_view_identity() {
    let cx = Cx::for_testing();
    for nparity in 1..=3 {
        for order in [Endian::Little, Endian::Big] {
            for case in [0, 21] {
                let mut image = striped_pool(order, case, nparity);
                let mut damaged = vec![
                    ROOT,
                    MOS,
                    MAP,
                    OLDER_ROOT,
                    OLD_TABLE,
                    OLD_DIRECTORY,
                    OLD_INDIRECT,
                ];
                if case == 0 {
                    damaged.extend_from_slice(&[OLD_FIRST, OLD_LAST, LIVE_FIRST]);
                }
                assert_eq!(image.has_block(OLD_FIRST), case == 0);
                let recovered: Vec<_> = damaged
                    .iter()
                    .map(|key| (image.column(*key, nparity), image.column(*key, 0)))
                    .collect();
                for key in damaged {
                    poison_parity_budget(&mut image, key, nparity);
                }
                let reads = image.reads();
                let (head, before, after) = {
                    let source = image.open(&vec![Fault::None; width(nparity)], true);
                    let mut objects = source.objects(&cx, 0, 2, 123).unwrap();
                    assert_eq!(objects.snapshots(&cx, &[]).unwrap().len(), 2);
                    let head = ZfsFs::new(&cx, objects.zpl(&cx, &[]).unwrap(), 1000, 1000).unwrap();
                    let before = ZfsFs::new(
                        &cx,
                        objects.zpl_snapshot(&cx, &[], b"before").unwrap(),
                        1000,
                        1000,
                    )
                    .unwrap();
                    let after = ZfsFs::new(
                        &cx,
                        objects.zpl_snapshot(&cx, &[], b"after").unwrap(),
                        1000,
                        1000,
                    )
                    .unwrap();
                    (head, before, after)
                };
                let mut scope = RequestScope::empty();
                let root = InodeNumber(1);
                let current_file = head
                    .lookup(&cx, &mut scope, root, OsStr::new("file"))
                    .unwrap();
                let old_file = before
                    .lookup(&cx, &mut scope, root, OsStr::new("file"))
                    .unwrap();
                let middle_file = after
                    .lookup(&cx, &mut scope, root, OsStr::new("file"))
                    .unwrap();
                assert_eq!(
                    (current_file.ino, old_file.ino, middle_file.ino),
                    (InodeNumber(4), InodeNumber(4), InodeNumber(4))
                );
                assert_eq!(
                    (current_file.size, old_file.size, middle_file.size),
                    (900, 2049, 600)
                );
                for _ in 0..3 {
                    assert_eq!(
                        before.read(&cx, &mut scope, old_file.ino, 0, 4096).unwrap(),
                        old_bytes()
                    );
                    assert_eq!(
                        before
                            .read(&cx, &mut scope, old_file.ino, 510, 1029)
                            .unwrap(),
                        old_bytes()[510..1539]
                    );
                    assert_eq!(
                        head.read(&cx, &mut scope, current_file.ino, 0, 8).unwrap(),
                        b"EEEEEEEE"
                    );
                    assert_eq!(
                        after.read(&cx, &mut scope, middle_file.ino, 0, 8).unwrap(),
                        b"CCCCCCCC"
                    );
                    assert!(
                        before
                            .lookup(&cx, &mut scope, root, OsStr::new("gone"))
                            .is_ok()
                    );
                    assert!(matches!(
                        head.lookup(&cx, &mut scope, root, OsStr::new("gone")),
                        Err(FfsError::NotFound(_))
                    ));
                }
                for (data, parity) in recovered {
                    assert!(count(&reads, data) > 0);
                    assert!(count(&reads, parity) > 0);
                }
            }
        }
    }
}

#[test]
fn a_failed_later_raidz_snapshot_block_returns_no_prefix_or_current_dataset_fallback() {
    let cx = Cx::for_testing();
    for nparity in 1..=3 {
        for case in 0..3 {
            let mut image = striped_pool(Endian::Little, 0, nparity);
            let data = image.column(OLD_LAST, nparity);
            let parity: Vec<_> = (0..nparity)
                .map(|index| image.column(OLD_LAST, index))
                .collect();
            let first = image.column(OLD_FIRST, nparity);
            let live = image.column(LIVE_FIRST, nparity);
            let mut faults = vec![Fault::None; width(nparity)];
            match case {
                0 => {
                    image.poison(OLD_LAST, nparity, 0);
                    for ordinal in 0..nparity {
                        image.poison(OLD_LAST, ordinal, 32 + ordinal * 11);
                    }
                }
                1 => faults[data.0] = Fault::Cancel(data.1),
                _ => {
                    image.poison(OLD_LAST, nparity, 0);
                    let cancel = parity[nparity - 1];
                    faults[cancel.0] = Fault::Cancel(cancel.1);
                }
            }
            let reads = image.reads();
            let source = image.open(&faults, true);
            let mut objects = source.objects(&cx, 0, 2, 123).unwrap();
            let mut before = objects.zpl_snapshot(&cx, &[], b"before").unwrap();
            let result = before.read(&cx, 3, 0, 2049);
            if case == 0 {
                assert!(result.is_err());
            } else {
                assert!(matches!(result, Err(FfsError::Cancelled)));
            }
            assert_eq!(count(&reads, first), 1);
            assert_eq!(count(&reads, data), 1);
            for address in parity {
                assert_eq!(count(&reads, address), usize::from(case != 1));
            }
            assert_eq!(count(&reads, live), 0);
            let cached_data: Vec<_> = before
                .objects
                .cache
                .iter()
                .filter(|(pointer, _)| pointer.object_type() == 19 && pointer.level() == 0)
                .collect();
            assert!(!cached_data.is_empty());
            assert!(
                cached_data
                    .iter()
                    .all(|(_, block)| block.bytes.as_slice() == [b'A'; 512])
            );
            assert_eq!(before.stat(&cx, 3).unwrap().0.size, 2049);
            assert_eq!(
                objects.zpl(&cx, &[]).unwrap().read(&cx, 3, 0, 8).unwrap(),
                b"EEEEEEEE"
            );
        }
    }
}

#[test]
fn scrub_raidz_snapshots_use_verified_reconstruction_and_remain_historical() {
    use crate::reader::dmu::scrub::ScrubLimits;

    let cx = Cx::for_testing();
    for nparity in 1..=3 {
        for order in [Endian::Little, Endian::Big] {
            for case in [0, 21] {
                let mut image = striped_pool(order, case, nparity);
                let mut damaged = vec![OLD_TABLE, OLD_DIRECTORY, OLD_INDIRECT];
                if case == 0 {
                    damaged.extend_from_slice(&[OLD_FIRST, OLD_LAST]);
                }
                let recovered: Vec<_> = damaged
                    .iter()
                    .map(|key| (image.column(*key, nparity), image.column(*key, 0)))
                    .collect();
                for key in damaged {
                    poison_parity_budget(&mut image, key, nparity);
                }
                let live = (case == 0).then(|| image.column(LIVE_FIRST, nparity));
                let reads = image.reads();
                let source = image.open(&vec![Fault::None; width(nparity)], true);
                let mut objects = source.objects(&cx, 0, 2, 123).unwrap();
                let before = objects.zpl_snapshot(&cx, &[], b"before").unwrap();
                let report = before.scrub(&cx, ScrubLimits::default()).unwrap();
                assert!(
                    report.is_clean(),
                    "parity={nparity}, case={case}: {report:?}"
                );
                assert_eq!(report.root_birth, 18);
                assert_eq!(report.view_txg, before.view_txg());
                assert_eq!(report.objects_examined, 5);
                assert_eq!(report.verified_blocks, 6);
                for (data, parity) in recovered {
                    assert!(count(&reads, data) > 0);
                    assert!(count(&reads, parity) > 0);
                }
                if let Some(live) = live {
                    assert_eq!(count(&reads, live), 0);
                }
            }
        }
    }
}

#[test]
fn scrub_raidz_unrecoverable_data_and_cancellation_never_become_clean() {
    use crate::reader::dmu::scrub::ScrubLimits;

    let cx = Cx::for_testing();
    for nparity in 1..=3 {
        for cancel in [false, true] {
            let mut image = striped_pool(Endian::Little, 0, nparity);
            let data = image.column(OLD_LAST, nparity);
            let live = image.column(LIVE_FIRST, nparity);
            let mut faults = vec![Fault::None; width(nparity)];
            if cancel {
                faults[data.0] = Fault::Cancel(data.1);
            } else {
                image.poison(OLD_LAST, nparity, 0);
                for ordinal in 0..nparity {
                    image.poison(OLD_LAST, ordinal, 32 + ordinal * 11);
                }
            }
            let reads = image.reads();
            let source = image.open(&faults, true);
            let mut objects = source.objects(&cx, 0, 2, 123).unwrap();
            let before = objects.zpl_snapshot(&cx, &[], b"before").unwrap();
            let result = before.scrub(&cx, ScrubLimits::default());
            if cancel {
                assert!(matches!(result, Err(FfsError::Cancelled)));
            } else {
                let report = result.unwrap();
                assert!(!report.is_clean());
                assert_eq!(report.errors, 1);
                assert_eq!(report.issues[0].object, 3);
                assert_eq!(report.issues[0].block, Some(2));
            }
            assert_eq!(count(&reads, live), 0);
        }
    }
}

#[test]
fn missing_raidz_filesystem_views_retain_head_and_snapshot_owners_after_pool_drop() {
    use crate::reader::Pool;

    let cx = Cx::for_testing();
    for nparity in 1..=3 {
        for order in [Endian::Little, Endian::Big] {
            for case in [0, 21] {
                let image = striped_pool(order, case, nparity);
                let reads = image.reads();
                let complete = image.open(&vec![Fault::None; width(nparity)], false);
                let leaves = complete
                    .leaves()
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index >= nparity)
                    .rev()
                    .map(|(_, leaf)| leaf.clone())
                    .collect();
                let missing = (0..nparity).map(|id| 1001 + id as u64).collect();
                let pool = Pool::from_raidz_survivors(&cx, leaves, missing).unwrap();
                drop(complete);
                let mut objects = pool.objects(&cx, 0, 2, 123).unwrap();
                assert_eq!(objects.snapshots(&cx, &[]).unwrap().len(), 2);
                let head = ZfsFs::new(&cx, objects.zpl(&cx, &[]).unwrap(), 1000, 1000).unwrap();
                let before = ZfsFs::new(
                    &cx,
                    objects.zpl_snapshot(&cx, &[], b"before").unwrap(),
                    1000,
                    1000,
                )
                .unwrap();
                let after = ZfsFs::new(
                    &cx,
                    objects.zpl_snapshot(&cx, &[], b"after").unwrap(),
                    1000,
                    1000,
                )
                .unwrap();
                drop(objects);
                drop(pool);
                let mut scope = RequestScope::empty();
                let root = InodeNumber(1);
                let current = head
                    .lookup(&cx, &mut scope, root, OsStr::new("file"))
                    .unwrap();
                let old = before
                    .lookup(&cx, &mut scope, root, OsStr::new("file"))
                    .unwrap();
                let middle = after
                    .lookup(&cx, &mut scope, root, OsStr::new("file"))
                    .unwrap();
                assert_eq!((current.size, old.size, middle.size), (900, 2049, 600));
                for _ in 0..3 {
                    assert_eq!(
                        head.read(&cx, &mut scope, current.ino, 0, 8).unwrap(),
                        b"EEEEEEEE"
                    );
                    assert_eq!(
                        before.read(&cx, &mut scope, old.ino, 0, 4096).unwrap(),
                        old_bytes()
                    );
                    assert_eq!(
                        before.read(&cx, &mut scope, old.ino, 510, 1029).unwrap(),
                        old_bytes()[510..1539]
                    );
                    assert_eq!(
                        after.read(&cx, &mut scope, middle.ino, 0, 8).unwrap(),
                        b"CCCCCCCC"
                    );
                    assert!(
                        before
                            .lookup(&cx, &mut scope, root, OsStr::new("gone"))
                            .is_ok()
                    );
                    assert!(matches!(
                        head.lookup(&cx, &mut scope, root, OsStr::new("gone")),
                        Err(FfsError::NotFound(_))
                    ));
                }
                for log in &reads[..nparity] {
                    assert!(log.lock().unwrap().is_empty(), "absent child was read");
                }
            }
        }
    }
}

#[test]
fn missing_raidz_historical_read_failure_never_falls_back_to_live_data() {
    use crate::reader::Pool;

    let cx = Cx::for_testing();
    for nparity in 1..=3 {
        for cancel in [false, true] {
            let mut image = striped_pool(Endian::Little, 0, nparity);
            let absent = image.column(OLD_LAST, nparity).0;
            let live: Vec<_> = image
                .map(LIVE_FIRST)
                .columns()
                .iter()
                .enumerate()
                .filter(|(_, column)| column.bytes != 0)
                .map(|(index, _)| image.column(LIVE_FIRST, index))
                .collect();
            let parity = image.column(OLD_LAST, 0);
            let mut faults = vec![Fault::None; width(nparity)];
            if cancel {
                faults[parity.0] = Fault::Cancel(parity.1);
            } else {
                for ordinal in 0..nparity {
                    image.poison(OLD_LAST, ordinal, 32 + ordinal * 11);
                }
            }
            let reads = image.reads();
            let complete = image.open(&faults, false);
            let leaves = complete
                .leaves()
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != absent)
                .rev()
                .map(|(_, leaf)| leaf.clone())
                .collect();
            let pool = Pool::from_raidz_survivors(&cx, leaves, vec![1001 + absent as u64]).unwrap();
            drop(complete);
            let mut objects = pool.objects(&cx, 0, 2, 123).unwrap();
            let mut before = objects.zpl_snapshot(&cx, &[], b"before").unwrap();
            drop(objects);
            drop(pool);
            let result = before.read(&cx, 3, 0, 2049);
            if cancel {
                assert!(matches!(result, Err(FfsError::Cancelled)));
            } else {
                assert!(result.is_err());
            }
            assert_eq!(before.stat(&cx, 3).unwrap().0.size, 2049);
            for address in live {
                assert_eq!(count(&reads, address), 0);
            }
            assert!(reads[absent].lock().unwrap().is_empty());
        }
    }
}
