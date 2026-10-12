//! Complete constructed RAIDZ1 -> MOS -> DSL -> ZPL -> FsOps reads.
//! The original fixtures are re-encoded bottom-up; these are not native-pool
//! import or kernel FUSE tests.

use super::*;
use crate::filesystem::ZfsFs;
use crate::reader::tests::mirror::Fault;
use crate::reader::tests::raidz::fixture::{ROOT, StripedImage, count};
use ffs_core::{FsOps, RequestScope};
use ffs_types::InodeNumber;
use std::ffi::OsStr;

fn striped_graph(order: Endian, sa: u8, case: u8) -> StripedImage {
    let cx = Cx::for_testing();
    let (source, _) = graph(order, sa, case, Arc::default(), None);
    let mut bytes = vec![0; BASE + LENGTH + 512];
    bytes[BASE..BASE + LENGTH].copy_from_slice(&source.read(&cx, 0, LENGTH).unwrap());
    let table = source.read(&cx, MOS, 16_384).unwrap();
    let mut meta = node(10, 16_384, 1, 0, &[], 0, order);
    meta[64..192].copy_from_slice(&bp(&table, MOS, 10, 0, 50, order, order));
    let mut root = vec![0; 1024];
    root[..512].copy_from_slice(&meta);
    root[704..712].copy_from_slice(&order.encode(1));
    StripedImage::graph(&bytes, root, order, 3, 61, 60)
}

#[test]
fn raidz_mount_recovers_metadata_legacy_sa_spill_and_embedded_file_parents() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for sa in 0..=2 {
            for case in [0, 9] {
                let mut image = striped_graph(order, sa, case);
                let mut damaged = vec![ROOT, MOS, TABLE, ROOT_MAP, INDIRECT];
                if sa != 0 {
                    damaged.extend_from_slice(&[SA_MASTER, SA_REGISTRY, SA_LAYOUTS]);
                }
                if sa == 2 {
                    damaged.push(SPILL);
                }
                if case == 0 {
                    damaged.extend_from_slice(&[FIRST, LAST]);
                }
                assert_eq!(image.has_block(FIRST), case == 0);
                assert_eq!(image.has_block(LAST), case == 0);
                let recovered: Vec<_> = damaged
                    .iter()
                    .map(|key| (image.column(*key, 1), image.column(*key, 0)))
                    .collect();
                for key in damaged {
                    image.poison(key, 1, 0);
                }
                let reads = image.reads();
                let view = {
                    let pool = image.open(&[Fault::None; 3], true);
                    pool.objects(&cx, 0, 2, 123).unwrap().zpl(&cx, &[]).unwrap()
                };
                let fs = ZfsFs::new(&cx, view, 1000, 1000).unwrap();
                let mut scope = RequestScope::empty();
                let root = InodeNumber(1);
                let file = fs
                    .lookup(&cx, &mut scope, root, OsStr::new("file.bin"))
                    .unwrap();
                let alias = fs
                    .lookup(&cx, &mut scope, root, OsStr::new("alias.bin"))
                    .unwrap();
                assert_eq!(file.ino, alias.ino);
                let mut expected = vec![b'A'; 512];
                expected.extend_from_slice(&[0; 512]);
                expected.extend_from_slice(b"BBB");
                assert_eq!(
                    fs.read(&cx, &mut scope, file.ino, 0, 4096).unwrap(),
                    expected
                );
                let before: Vec<_> = reads.iter().map(|log| log.lock().unwrap().len()).collect();
                assert_eq!(
                    fs.read(&cx, &mut scope, alias.ino, 510, 600).unwrap(),
                    expected[510..]
                );
                assert!(
                    fs.read(&cx, &mut scope, file.ino, 1027, 1)
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
                for (data, parity) in recovered {
                    assert!(count(&reads, data) > 0);
                    assert!(count(&reads, parity) > 0);
                }
                for log in &reads {
                    assert!(log.lock().unwrap().iter().all(|(at, size)| {
                        *at >= BASE as u64 && *at + *size as u64 <= (BASE + LENGTH) as u64
                    }));
                }
            }
        }
    }
}

#[test]
fn failed_or_cancelled_raidz_file_data_is_never_cached_and_no_prefix_escapes() {
    let cx = Cx::for_testing();
    for case in 0..4 {
        let mut image = striped_graph(Endian::Little, 2, 0);
        let data = image.column(FIRST, 1);
        let parity = image.column(FIRST, 0);
        let last = image.column(LAST, 1);
        let mut faults = [Fault::None; 3];
        match case {
            0 => {
                image.poison(FIRST, 1, 0);
                image.poison(FIRST, 0, 32);
            }
            1 => faults[data.0] = Fault::Cancel(data.1),
            2 => {
                faults[data.0] = Fault::Io(data.1);
                faults[parity.0] = Fault::Cancel(parity.1);
            }
            _ => {
                faults[data.0] = Fault::Io(data.1);
                faults[parity.0] = Fault::Io(parity.1);
            }
        }
        let reads = image.reads();
        let pool = image.open(&faults, true);
        let mut objects = pool.objects(&cx, 0, 2, 123).unwrap();
        let mut view = objects.zpl(&cx, &[]).unwrap();
        let result = view.read(&cx, 3, 0, 1027);
        if matches!(case, 1 | 2) {
            assert!(matches!(result, Err(FfsError::Cancelled)));
        } else {
            assert!(result.is_err());
        }
        assert!(
            view.objects
                .cache
                .iter()
                .all(|(pointer, _)| { pointer.object_type() != 19 || pointer.level() != 0 })
        );
        assert!(!view.objects.cache.is_empty());
        assert_eq!(count(&reads, data), 1);
        assert_eq!(count(&reads, parity), usize::from(case != 1));
        assert_eq!(count(&reads, last), 0);
        assert_eq!(view.stat(&cx, 3).unwrap().0.size, 1027);
    }
}
