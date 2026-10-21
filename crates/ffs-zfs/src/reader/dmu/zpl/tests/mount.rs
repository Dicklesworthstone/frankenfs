//! Constructed native graph coverage for the extraction mount, not kernel FUSE evidence.

use super::*;
use crate::filesystem::ZfsFs;
use ffs_core::{FileType, FsOps, RequestScope, SeekWhence};
use ffs_types::InodeNumber;
use std::ffi::OsStr;

mod sparse;

const ROOT: InodeNumber = InodeNumber(1);

#[test]
fn extraction_mount_reads_native_graph_and_preserves_hardlinks_and_root_identity() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for sa in 0..=2 {
            let reads: Reads = Arc::default();
            let view = {
                let (leaf, meta) = graph(order, sa, 0, Arc::clone(&reads), None);
                mos(&leaf, meta).zpl(&cx, &[]).unwrap()
            };
            // Both the original Leaf and the temporary MOS view have gone.
            let fs = ZfsFs::new(&cx, view, 1234, 5678).unwrap();
            let mut scope = RequestScope::empty();
            let root = fs.getattr(&cx, &mut scope, ROOT).unwrap();
            assert_eq!(root.ino, ROOT);
            assert_eq!(root.kind, FileType::Directory);
            assert_eq!((root.uid, root.gid, root.perm), (1234, 5678, 0o555));
            let file = fs
                .lookup(&cx, &mut scope, ROOT, OsStr::new("file.bin"))
                .unwrap();
            let alias = fs
                .lookup(&cx, &mut scope, ROOT, OsStr::new("alias.bin"))
                .unwrap();
            let sub = fs.lookup(&cx, &mut scope, ROOT, OsStr::new("sub")).unwrap();
            let nested = fs
                .lookup(&cx, &mut scope, sub.ino, OsStr::new("nested"))
                .unwrap();
            assert_eq!(
                (file.ino, alias.ino, nested.ino),
                (InodeNumber(4), file.ino, file.ino)
            );
            assert_eq!(
                (file.kind, file.size, file.nlink),
                (FileType::RegularFile, 1027, 2)
            );
            assert_eq!(
                (file.uid, file.gid, file.perm, file.blocks),
                (1234, 5678, 0o444, 10)
            );
            assert_eq!(
                fs.lookup(&cx, &mut scope, sub.ino, OsStr::new(".."))
                    .unwrap()
                    .ino,
                ROOT
            );
            assert_eq!(
                fs.lookup(&cx, &mut scope, sub.ino, OsStr::new("."))
                    .unwrap()
                    .ino,
                sub.ino
            );
            for forged in [InodeNumber(0), InodeNumber(3), InodeNumber(u64::MAX)] {
                assert!(fs.getattr(&cx, &mut scope, forged).is_err());
            }
            let mut expected = vec![b'A'; 512];
            expected.extend_from_slice(&[0; 512]);
            expected.extend_from_slice(b"BBB");
            assert_eq!(
                fs.read(&cx, &mut scope, file.ino, 0, 4096).unwrap(),
                expected
            );
            assert_eq!(
                fs.read(&cx, &mut scope, alias.ino, 510, 600).unwrap(),
                expected[510..]
            );
            assert_eq!(
                fs.read(&cx, &mut scope, nested.ino, 1027, 5).unwrap(),
                [] as [u8; 0]
            );
            let empty = fs
                .lookup(&cx, &mut scope, ROOT, OsStr::new("empty"))
                .unwrap();
            let sparse = fs
                .lookup(&cx, &mut scope, ROOT, OsStr::new("sparse"))
                .unwrap();
            assert_eq!(
                fs.read(&cx, &mut scope, empty.ino, u64::MAX, 9).unwrap(),
                [] as [u8; 0]
            );
            assert_eq!(
                fs.read(&cx, &mut scope, sparse.ino, (1 << 40) + 2, 8)
                    .unwrap(),
                vec![0; 3]
            );
            let link = fs
                .lookup(&cx, &mut scope, ROOT, OsStr::new("link"))
                .unwrap();
            assert_eq!((link.kind, link.size), (FileType::Symlink, 8));
            assert_eq!(fs.readlink(&cx, &mut scope, link.ino).unwrap(), b"file.bin");
            let page = fs.readdir(&cx, &mut scope, ROOT, 0).unwrap();
            assert_eq!(
                page.iter()
                    .map(|entry| entry.name.as_slice())
                    .collect::<Vec<_>>(),
                [
                    b".".as_slice(),
                    b"..",
                    b"alias.bin",
                    b"empty",
                    b"file.bin",
                    b"link",
                    b"sparse",
                    b"sub"
                ]
            );
            assert_eq!(page.end_cookie(), Some(8));
            for (index, entry) in page.iter().enumerate() {
                assert_eq!(entry.offset, index as u64 + 1);
                let tail = fs.readdir(&cx, &mut scope, ROOT, entry.offset).unwrap();
                assert_eq!(tail.len(), page.len() - index - 1);
                assert_eq!(tail.end_cookie(), page.end_cookie());
            }
            assert!(
                fs.readdir(&cx, &mut scope, ROOT, u64::MAX)
                    .unwrap()
                    .is_empty()
            );
            assert!(reads.lock().unwrap().iter().all(|(offset, count)| {
                *offset >= BASE as u64 && *offset + *count as u64 <= (BASE + LENGTH) as u64
            }));
        }
    }
}

#[test]
fn extraction_mount_refuses_writes_and_preserves_corruption_and_cancellation_errors() {
    let cx = Cx::for_testing();
    for case in 1..=4 {
        let (leaf, meta) = graph(Endian::Little, 0, case, Arc::default(), None);
        let view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
        assert!(
            ZfsFs::new(&cx, view, 0, 0).is_err(),
            "corrupt root case {case}"
        );
    }
    let reads: Reads = Arc::default();
    let (leaf, meta) = graph(
        Endian::Little,
        0,
        0,
        Arc::clone(&reads),
        Some(BASE as u64 + LAST),
    );
    let view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
    let fs = ZfsFs::new(&cx, view, 0, 0).unwrap();
    let mut scope = RequestScope::empty();
    let file = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("file.bin"))
        .unwrap();
    assert!(fs.open(&cx, &mut scope, file.ino, libc::O_RDONLY).is_ok());
    for flags in [libc::O_WRONLY, libc::O_RDWR, libc::O_TRUNC, libc::O_CREAT] {
        assert!(matches!(
            fs.open(&cx, &mut scope, file.ino, flags),
            Err(FfsError::ReadOnly)
        ));
    }
    assert!(matches!(
        fs.write(&cx, &mut scope, file.ino, 0, b"bad"),
        Err(FfsError::ReadOnly)
    ));
    assert!(matches!(
        fs.unlink(&cx, &mut scope, ROOT, OsStr::new("file.bin")),
        Err(FfsError::ReadOnly)
    ));
    assert!(matches!(
        fs.read(&cx, &mut scope, file.ino, 0, 1027),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(
        reads
            .lock()
            .unwrap()
            .iter()
            .filter(|(at, _)| *at == BASE as u64 + LAST)
            .count(),
        1
    );
    assert!(matches!(
        fs.read(&cx, &mut scope, ROOT, 0, 1),
        Err(FfsError::IsDirectory)
    ));
    assert!(matches!(
        fs.readdir(&cx, &mut scope, file.ino, 0),
        Err(FfsError::NotDirectory)
    ));
    assert!(matches!(
        fs.lookup(&cx, &mut scope, ROOT, OsStr::new("missing")),
        Err(FfsError::NotFound(_))
    ));
    assert!(fs.lookup(&cx, &mut scope, ROOT, OsStr::new("a/b")).is_err());
    assert_eq!(fs.listxattr(&cx, file.ino).unwrap(), [] as [String; 0]);
    assert_eq!(fs.getxattr(&cx, file.ino, "user.missing").unwrap(), None);
    assert!(matches!(
        fs.getxattr(&cx, file.ino, "security.capability"),
        Err(FfsError::UnsupportedFeature(_))
    ));
    let st = fs.statfs(&cx, &mut scope, ROOT).unwrap();
    assert_eq!(st.block_size, 4096);
    assert_eq!(st.fragment_size, 512);
    assert!(st.blocks > 0);
    assert!(st.blocks_free <= st.blocks);
    assert_eq!(st.name_max, 255);
    assert!(matches!(
        fs.statfs(&cx, &mut scope, InodeNumber(999)),
        Err(FfsError::NotFound(_))
    ));
    assert_eq!(
        fs.lseek(&cx, &mut scope, file.ino, 1, SeekWhence::Data)
            .unwrap(),
        1
    );
    assert_eq!(
        fs.lseek(&cx, &mut scope, file.ino, 1, SeekWhence::Hole)
            .unwrap(),
        512
    );
    assert!(
        fs.lseek(&cx, &mut scope, file.ino, 1027, SeekWhence::Hole)
            .is_err()
    );
    fs.fsync(&cx, &mut scope, file.ino, 0, false).unwrap();
    fs.fsyncdir(&cx, &mut scope, ROOT, 0, false).unwrap();
    assert!(matches!(
        fs.fsyncdir(&cx, &mut scope, file.ino, 0, false),
        Err(FfsError::NotDirectory)
    ));
}
