//! Complete fragmented MOS/DSL/ZPL/file streams through the FsOps boundary.

use super::*;
use crate::filesystem::ZfsFs;
use crate::reader::tests::mirror::Fault;
use crate::reader::tests::raidz::fixture::{ROOT, StripedImage, count};
use ffs_core::{FsOps, RequestScope};
use ffs_types::InodeNumber;
use std::ffi::OsStr;

fn fragmented_graph(order: Endian, sa: u8, parity: usize) -> StripedImage {
    let cx = Cx::for_testing();
    let (source, _) = graph(order, sa, 32, Arc::default(), None);
    let mut bytes = vec![0; BASE + LENGTH + 512];
    bytes[BASE..BASE + LENGTH].copy_from_slice(&source.read(&cx, 0, LENGTH).unwrap());
    let table = source.read(&cx, MOS, 16_384).unwrap();
    let mut meta = node(10, 16_384, 1, 0, &[], 0, order);
    meta[64..192].copy_from_slice(&bp(&table, MOS, 10, 0, 50, order, order));
    let mut root = vec![0; 1024];
    root[..512].copy_from_slice(&meta);
    root[704..712].copy_from_slice(&order.encode(1));
    StripedImage::gang_graph(&bytes, root, order, parity + 3, 61, 60, parity)
}

fn expected() -> Vec<u8> {
    let mut bytes = vec![b'A'; 1024];
    bytes.extend_from_slice(&[0; 1024]);
    bytes.extend_from_slice(b"BBB");
    bytes
}

#[test]
fn fragmented_metadata_and_files_preserve_legacy_sa_spill_hardlinks_and_eof() {
    let cx = Cx::for_testing();
    for parity in 1..=3 {
        for order in [Endian::Little, Endian::Big] {
            for sa in 0..=2 {
                let mut image = fragmented_graph(order, sa, parity);
                let child = image.gang_children(FIRST)[0];
                // Exercise header and fragment checksums through the same
                // parity reader that supplies checked DMU ancestors.
                for key in [ROOT, MOS, TABLE, INDIRECT, FIRST, child] {
                    image.poison(key, parity, 0);
                }
                let reads = image.reads();
                let source = image.open(&vec![Fault::None; parity + 3], true);
                let mut view = source
                    .objects(&cx, 0, 2, 123)
                    .unwrap()
                    .zpl(&cx, &[])
                    .unwrap();
                assert_eq!(view.read(&cx, 3, 0, 4096).unwrap(), expected());
                assert!(view.objects.cache.iter().any(|(pointer, _)| pointer.gang()
                    && pointer.object_type() == 19
                    && pointer.level() == 0));
                let fs = ZfsFs::new(&cx, view, 1000, 1000).unwrap();
                let mut scope = RequestScope::empty();
                let file = fs
                    .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("file.bin"))
                    .unwrap();
                let alias = fs
                    .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("alias.bin"))
                    .unwrap();
                assert_eq!(file.ino, alias.ino);
                assert_eq!(file.size, 2051);
                let before: Vec<_> = reads.iter().map(|log| log.lock().unwrap().len()).collect();
                assert_eq!(
                    fs.read(&cx, &mut scope, alias.ino, 1022, 2000).unwrap(),
                    expected()[1022..]
                );
                assert!(
                    fs.read(&cx, &mut scope, file.ino, 2051, 3)
                        .unwrap()
                        .is_empty()
                );
                assert_eq!(
                    reads
                        .iter()
                        .map(|log| log.lock().unwrap().len())
                        .collect::<Vec<_>>(),
                    before
                );
            }
        }
    }
}

#[test]
fn a_bad_late_fragment_does_not_cache_a_partial_gang_block_or_return_file_prefixes() {
    let cx = Cx::for_testing();
    for parity in 1..=3 {
        for cancelled in [false, true] {
            let mut image = fragmented_graph(Endian::Little, 2, parity);
            let late = image.gang_children(LAST)[1];
            let data = image.column(late, parity);
            let mut faults = vec![Fault::None; parity + 3];
            if cancelled {
                faults[data.0] = Fault::Cancel(data.1);
            } else {
                for ordinal in 0..=parity {
                    image.poison(late, ordinal, 0);
                }
            }
            let reads = image.reads();
            let source = image.open(&faults, true);
            let mut view = source
                .objects(&cx, 0, 2, 123)
                .unwrap()
                .zpl(&cx, &[])
                .unwrap();
            for attempt in 1..=2 {
                let result = view.read(&cx, 3, 0, 4096);
                if cancelled {
                    assert!(matches!(result, Err(FfsError::Cancelled)));
                } else {
                    assert!(result.is_err());
                }
                assert_eq!(count(&reads, data), attempt);
                assert_eq!(
                    view.objects
                        .cache
                        .iter()
                        .filter(|(pointer, _)| pointer.object_type() == 19 && pointer.level() == 0)
                        .count(),
                    1
                );
                assert_eq!(view.read(&cx, 3, 0, 3).unwrap(), b"AAA");
            }
        }
    }
}
