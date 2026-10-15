//! Sparse-seek regression coverage through constructed native DMU/ZPL graphs.

use super::*;

fn assert_enxio(result: Result<u64>) {
    assert!(matches!(
        result,
        Err(FfsError::Io(error)) if error.raw_os_error() == Some(libc::ENXIO)
    ));
}

#[test]
fn sparse_seeks_follow_native_records_for_legacy_sa_and_hardlinks() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for sa in 0..=2 {
            for case in [0, 32] {
                let reads: Reads = Arc::default();
                let (leaf, meta) = graph(order, sa, case, Arc::clone(&reads), None);
                let view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
                let fs = ZfsFs::new(&cx, view, 0, 0).unwrap();
                let mut scope = RequestScope::empty();
                let file = fs
                    .lookup(&cx, &mut scope, ROOT, OsStr::new("file.bin"))
                    .unwrap();
                let alias = fs
                    .lookup(&cx, &mut scope, ROOT, OsStr::new("alias.bin"))
                    .unwrap();
                assert_eq!(file.ino, alias.ino);
                let block = if case == 32 { 1024_u64 } else { 512 };
                let eof = 2 * block + 3;
                for ino in [file.ino, alias.ino] {
                    for (offset, data, hole) in [
                        (0, 0, block),
                        (block - 1, block - 1, block),
                        (block, 2 * block, block),
                        (block + 1, 2 * block, block + 1),
                        (2 * block - 1, 2 * block, 2 * block - 1),
                        (2 * block, 2 * block, eof),
                        (eof - 1, eof - 1, eof),
                    ] {
                        assert_eq!(
                            fs.lseek(&cx, &mut scope, ino, offset, SeekWhence::Data)
                                .unwrap(),
                            data
                        );
                        assert_eq!(
                            fs.lseek(&cx, &mut scope, ino, offset, SeekWhence::Hole)
                                .unwrap(),
                            hole
                        );
                    }
                    for offset in [eof, eof + 1, u64::MAX] {
                        for whence in [SeekWhence::Data, SeekWhence::Hole] {
                            assert_enxio(fs.lseek(&cx, &mut scope, ino, offset, whence));
                        }
                    }
                }
                let reads = reads.lock().unwrap();
                assert!(reads.iter().all(|(at, _)| {
                    *at != BASE as u64 + FIRST && *at != BASE as u64 + LAST
                }));
                assert_eq!(
                    reads.iter().filter(|(at, _)| *at == BASE as u64 + INDIRECT).count(),
                    1,
                    "the root-local metadata cache should retain the indirect block"
                );
            }
        }
    }
}

#[test]
fn sparse_seeks_skip_terabyte_tails_and_reject_empty_or_nonregular_files() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let reads: Reads = Arc::default();
        let (leaf, meta) = graph(order, 0, 0, Arc::clone(&reads), None);
        let mut view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
        let before = reads.lock().unwrap().len();
        for offset in [0, 1, 511, 512, 1 << 40, (1 << 40) + 4] {
            assert_eq!(view.seek(&cx, 7, offset, SeekWhence::Hole).unwrap(), offset);
            assert_enxio(view.seek(&cx, 7, offset, SeekWhence::Data));
        }
        for whence in [SeekWhence::Data, SeekWhence::Hole] {
            assert_enxio(view.seek(&cx, 7, (1 << 40) + 5, whence));
            assert_enxio(view.seek(&cx, 6, 0, whence));
            assert!(matches!(
                view.seek(&cx, 2, 0, whence),
                Err(FfsError::UnsupportedFeature(_))
            ));
            assert!(matches!(
                view.seek(&cx, 5, 0, whence),
                Err(FfsError::UnsupportedFeature(_))
            ));
        }
        assert_eq!(reads.lock().unwrap().len(), before);
    }
}

#[test]
fn sparse_seeks_do_not_turn_bad_or_cancelled_metadata_into_holes() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let (leaf, meta) = graph(order, 0, 11, Arc::default(), None);
        let mut view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
        for whence in [SeekWhence::Data, SeekWhence::Hole] {
            let error = view.seek(&cx, 3, 512, whence).unwrap_err();
            assert!(!matches!(
                error,
                FfsError::Io(error) if error.raw_os_error() == Some(libc::ENXIO)
            ));
        }
        let reads: Reads = Arc::default();
        let (leaf, meta) = graph(
            order,
            0,
            0,
            Arc::clone(&reads),
            Some(BASE as u64 + INDIRECT),
        );
        let mut view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
        for whence in [SeekWhence::Data, SeekWhence::Hole] {
            assert!(matches!(
                view.seek(&cx, 3, 512, whence),
                Err(FfsError::Cancelled)
            ));
        }
        assert_eq!(
            reads.lock().unwrap().iter()
                .filter(|(at, _)| *at == BASE as u64 + INDIRECT).count(),
            2,
            "failed indirect reads must not enter the cache"
        );
        let (leaf, meta) = graph(order, 0, 0, Arc::default(), Some(BASE as u64 + FIRST));
        let mut view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
        assert_eq!(view.seek(&cx, 3, 0, SeekWhence::Data).unwrap(), 0);
        assert_eq!(view.seek(&cx, 3, 0, SeekWhence::Hole).unwrap(), 512);
        assert!(matches!(view.read(&cx, 3, 0, 1), Err(FfsError::Cancelled)));
    }
}

#[test]
fn sparse_seeks_treat_admitted_embedded_records_as_data() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let (leaf, meta) = graph(order, 0, 9, Arc::default(), None);
        let mut objects = mos(&leaf, meta);
        let mut refused = objects.zpl(&cx, &[]).unwrap();
        assert!(matches!(
            refused.seek(&cx, 3, 0, SeekWhence::Data),
            Err(FfsError::UnsupportedFeature(_))
        ));
        objects.config.read_features.push("com.delphix:embedded_data".into());
        let mut view = objects.zpl(&cx, &[]).unwrap();
        assert_eq!(view.seek(&cx, 3, 0, SeekWhence::Data).unwrap(), 0);
        assert_eq!(view.seek(&cx, 3, 1, SeekWhence::Hole).unwrap(), 512);
        assert_eq!(view.seek(&cx, 3, 512, SeekWhence::Data).unwrap(), 1024);
        assert_eq!(view.seek(&cx, 3, 1024, SeekWhence::Hole).unwrap(), 1027);
    }
}
