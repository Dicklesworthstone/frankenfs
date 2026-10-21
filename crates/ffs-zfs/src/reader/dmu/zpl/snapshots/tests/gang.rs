//! Historical gang trees retain their owning object set and birth ceiling.

use super::*;
use crate::filesystem::ZfsFs;
use crate::reader::tests::mirror::Fault;
use crate::reader::tests::raidz::fixture::{StripedImage, count};
use ffs_core::{FsOps, RequestScope};
use ffs_types::InodeNumber;
use std::ffi::OsStr;

const OLD_FIRST: u64 = DATA_OFFSET + 0x3_6000;
const OLD_LAST: u64 = DATA_OFFSET + 0x3_6800;
const LIVE_FIRST: u64 = DATA_OFFSET + 0x5_6000;

fn fragmented_pool(order: Endian, case: u8, parity: usize) -> StripedImage {
    let image = Image::new(order, case);
    let mut meta = node(10, 16_384, 1, 0, order);
    meta[64..192].copy_from_slice(&pointer(&image.table, MOS, 10, 0, 80, order, order));
    let mut root = vec![0; 1024];
    root[..512].copy_from_slice(&meta);
    w64(&mut root, 704, 1, order);
    StripedImage::gang_graph(&image.bytes, root, order, parity + 3, 100, 90, parity)
}

fn old_contents() -> Vec<u8> {
    let mut bytes = vec![b'A'; 1024];
    bytes.extend_from_slice(&[0; 1024]);
    bytes.push(b'B');
    bytes
}

#[test]
fn fragmented_snapshots_preserve_distinct_file_bytes_names_and_cached_views() {
    let cx = Cx::for_testing();
    for parity in 1..=3 {
        for order in [Endian::Little, Endian::Big] {
            let mut image = fragmented_pool(order, 27, parity);
            let late = image.gang_children(OLD_LAST)[1];
            for key in [OLDER_ROOT, OLD_FIRST, OLD_LAST, late] {
                image.poison(key, parity, 0);
            }
            let source = image.open(&vec![Fault::None; parity + 3], true);
            let mut objects = source.objects(&cx, 0, 2, 123).unwrap();
            let snapshots = objects.snapshots(&cx, &[]).unwrap();
            assert_eq!(
                snapshots
                    .iter()
                    .map(|row| row.name.as_slice())
                    .collect::<Vec<_>>(),
                [b"after".as_slice(), b"before"]
            );
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
            let mut scope = RequestScope::empty();
            let mut inodes = Vec::new();
            for fs in [&head, &before, &after] {
                inodes.push(
                    fs.lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("file"))
                        .unwrap()
                        .ino,
                );
            }
            assert_eq!(inodes, [InodeNumber(4); 3]);
            for _ in 0..2 {
                assert_eq!(
                    before.read(&cx, &mut scope, inodes[1], 0, 4096).unwrap(),
                    old_contents()
                );
                assert_eq!(
                    before.read(&cx, &mut scope, inodes[1], 1022, 4096).unwrap(),
                    old_contents()[1022..]
                );
                assert_eq!(
                    head.read(&cx, &mut scope, inodes[0], 0, 8).unwrap(),
                    b"EEEEEEEE"
                );
                assert_eq!(
                    after.read(&cx, &mut scope, inodes[2], 0, 8).unwrap(),
                    b"CCCCCCCC"
                );
                assert!(
                    before
                        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("gone"))
                        .is_ok()
                );
                assert!(matches!(
                    head.lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("gone")),
                    Err(FfsError::NotFound(_))
                ));
            }
        }
    }
}

#[test]
fn failed_snapshot_fragments_and_younger_gang_leaders_never_select_current_data() {
    let cx = Cx::for_testing();
    for case in 0..3 {
        let parity = 2;
        let mut image = fragmented_pool(Endian::Little, if case == 2 { 28 } else { 27 }, parity);
        let late = image.gang_children(OLD_LAST)[1];
        let data = image.column(late, parity);
        let live = image.column(LIVE_FIRST, parity);
        let future = image.column(OLD_FIRST, parity);
        let mut faults = vec![Fault::None; parity + 3];
        if case == 0 {
            for ordinal in 0..=parity {
                image.poison(late, ordinal, 0);
            }
        } else if case == 1 {
            faults[data.0] = Fault::Cancel(data.1);
        }
        let reads = image.reads();
        let source = image.open(&faults, true);
        let mut objects = source.objects(&cx, 0, 2, 123).unwrap();
        let mut before = objects.zpl_snapshot(&cx, &[], b"before").unwrap();
        let result = before.read(&cx, 3, 0, 4096);
        if case == 1 {
            assert!(matches!(result, Err(FfsError::Cancelled)));
        } else {
            assert!(result.is_err());
        }
        assert_eq!(count(&reads, live), 0);
        if case == 2 {
            assert_eq!(count(&reads, future), 0);
            assert_eq!(count(&reads, data), 0);
        } else {
            assert_eq!(count(&reads, data), 1);
            assert_eq!(before.read(&cx, 3, 0, 3).unwrap(), b"AAA");
        }
    }
}
