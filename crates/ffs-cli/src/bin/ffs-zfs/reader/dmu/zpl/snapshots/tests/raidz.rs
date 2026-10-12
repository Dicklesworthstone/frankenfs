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
        StripedImage::graph_with_parity(
            &image.bytes, root, order, width(parity), 100, 90, parity,
        )
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
