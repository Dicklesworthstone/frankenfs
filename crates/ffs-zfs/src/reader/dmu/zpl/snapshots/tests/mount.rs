//! Separate mounted views over constructed historical native roots.

use super::*;
use crate::filesystem::ZfsFs;
use ffs_core::{FsOps, RequestScope};
use ffs_types::InodeNumber;
use std::ffi::OsStr;

const ROOT: InodeNumber = InodeNumber(1);

#[test]
fn extraction_mounts_keep_snapshot_and_head_namespaces_and_data_separate() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let reads: Reads = Arc::default();
        let (live, before, after) = {
            let (leaf, meta) = Image::new(order, 0).open(Arc::clone(&reads), None);
            let mut pool = pool(&leaf, meta);
            let live = ZfsFs::new(&cx, pool.zpl(&cx, &[]).unwrap(), 1000, 1000).unwrap();
            let before = ZfsFs::new(
                &cx,
                pool.zpl_snapshot(&cx, &[], b"before").unwrap(),
                1000,
                1000,
            )
            .unwrap();
            let after = ZfsFs::new(
                &cx,
                pool.zpl_snapshot(&cx, &[], b"after").unwrap(),
                1000,
                1000,
            )
            .unwrap();
            (live, before, after)
        };
        // The original image owner and the MOS reader have both been dropped.
        let mut scope = RequestScope::empty();
        let live_file = live
            .lookup(&cx, &mut scope, ROOT, OsStr::new("file"))
            .unwrap();
        let old_file = before
            .lookup(&cx, &mut scope, ROOT, OsStr::new("file"))
            .unwrap();
        let after_file = after
            .lookup(&cx, &mut scope, ROOT, OsStr::new("file"))
            .unwrap();
        assert_eq!(
            (live_file.ino, old_file.ino, after_file.ino),
            (InodeNumber(4), InodeNumber(4), InodeNumber(4))
        );
        assert_eq!(
            (live_file.size, old_file.size, after_file.size),
            (900, 2049, 600)
        );
        let mut live_bytes = vec![b'E'; 512];
        live_bytes.resize(900, 0);
        let mut after_bytes = vec![b'C'; 512];
        after_bytes.resize(600, 0);
        for _ in 0..3 {
            assert_eq!(
                before.read(&cx, &mut scope, old_file.ino, 0, 4096).unwrap(),
                old_bytes()
            );
            assert_eq!(
                live.read(&cx, &mut scope, live_file.ino, 0, 4096).unwrap(),
                live_bytes
            );
            assert_eq!(
                after
                    .read(&cx, &mut scope, after_file.ino, 0, 4096)
                    .unwrap(),
                after_bytes
            );
            assert_eq!(
                before
                    .read(&cx, &mut scope, old_file.ino, 510, 1029)
                    .unwrap(),
                old_bytes()[510..1539]
            );
            assert_eq!(
                before.read(&cx, &mut scope, old_file.ino, 2049, 1).unwrap(),
                [] as [u8; 0]
            );
            assert!(
                before
                    .lookup(&cx, &mut scope, ROOT, OsStr::new("gone"))
                    .is_ok()
            );
            for fs in [&live, &after] {
                assert!(matches!(
                    fs.lookup(&cx, &mut scope, ROOT, OsStr::new("gone")),
                    Err(FfsError::NotFound(_))
                ));
            }
            for fs in [&live, &before, &after] {
                let link = fs
                    .lookup(&cx, &mut scope, ROOT, OsStr::new("link"))
                    .unwrap();
                assert_eq!(fs.readlink(&cx, &mut scope, link.ino).unwrap(), b"file");
            }
            let older = before.readdir(&cx, &mut scope, ROOT, 0).unwrap();
            let current = live.readdir(&cx, &mut scope, ROOT, 0).unwrap();
            assert_eq!((older.len(), current.len()), (5, 4));
            assert!(older.iter().any(|entry| entry.name == b"gone"));
            assert!(!current.iter().any(|entry| entry.name == b"gone"));
        }
        assert!(
            reads
                .lock()
                .unwrap()
                .iter()
                .all(|at| *at >= BASE as u64 && *at < (BASE + LENGTH) as u64)
        );
    }
}
