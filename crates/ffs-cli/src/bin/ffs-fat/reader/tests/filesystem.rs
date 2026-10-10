use super::*;
use crate::filesystem::FatFs;
use ffs_core::{FsOps, RequestScope, SeekWhence};
use ffs_types::InodeNumber;
use std::ffi::OsStr;

#[test]
fn fsops_root_lookup_read_cookies_parent_and_read_only_contract() {
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let fs = FatFs::new(&cx, Image::new(kind).volume(), 123, 456).unwrap();
        let root = InodeNumber(1);
        let attr = fs.getattr(&cx, &mut scope, root).unwrap();
        assert_eq!(attr.ino, root);
        assert_eq!(attr.perm, 0o555);
        assert_eq!((attr.uid, attr.gid), (123, 456));
        assert_eq!(attr.nlink, 3);
        assert_eq!(attr.size, if kind == FatKind::Fat16 { 1024 } else { 512 });
        let file = fs
            .lookup(&cx, &mut scope, root, OsStr::new("hello.txt"))
            .unwrap();
        assert_eq!((file.size, file.blocks, file.perm), (1029, 3, 0o444));
        assert_eq!(
            fs.lookup(&cx, &mut scope, root, OsStr::new("HELLO.TXT"))
                .unwrap()
                .ino,
            file.ino
        );
        assert_eq!(
            fs.read(&cx, &mut scope, file.ino, 510, 520).unwrap(),
            payload()[510..]
        );
        assert!(
            fs.read(&cx, &mut scope, file.ino, u64::MAX, 1)
                .unwrap()
                .is_empty()
        );
        assert!(fs.open(&cx, &mut scope, file.ino, libc::O_RDONLY).is_ok());
        assert!(matches!(
            fs.open(&cx, &mut scope, file.ino, libc::O_WRONLY),
            Err(FfsError::ReadOnly)
        ));
        assert!(matches!(
            fs.open(&cx, &mut scope, file.ino, libc::O_RDONLY | libc::O_TRUNC),
            Err(FfsError::ReadOnly)
        ));
        assert!(matches!(
            fs.write(&cx, &mut scope, file.ino, 0, b"overwrite"),
            Err(FfsError::ReadOnly)
        ));
        assert!(fs.fsync(&cx, &mut scope, file.ino, 0, false).is_ok());
        assert!(fs.fsyncdir(&cx, &mut scope, root, 0, false).is_ok());
        let page = fs.readdir(&cx, &mut scope, root, 0).unwrap();
        assert_eq!(page.len(), 5);
        assert_eq!(page.end_cookie(), Some(5));
        assert_eq!(page[0].name, b".");
        assert_eq!(page[1].name, b"..");
        assert_eq!(page[2].ino, file.ino);
        let tail = fs.readdir(&cx, &mut scope, root, page[2].offset).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0], page[3]);
        assert!(fs.readdir(&cx, &mut scope, root, 5).unwrap().is_empty());
        let dir = fs
            .lookup(&cx, &mut scope, root, OsStr::new("SUBDIR"))
            .unwrap();
        assert_eq!(
            fs.lookup(&cx, &mut scope, dir.ino, OsStr::new(".."))
                .unwrap()
                .ino,
            root
        );
        let nested = fs
            .lookup(&cx, &mut scope, dir.ino, OsStr::new("nested.bin"))
            .unwrap();
        assert_eq!(
            fs.read(&cx, &mut scope, nested.ino, 0, 100).unwrap(),
            b"FAT!"
        );
        assert!(matches!(
            fs.getattr(&cx, &mut scope, InodeNumber(0)),
            Err(FfsError::NotFound(_))
        ));
        assert_eq!(
            fs.lseek(&cx, &mut scope, file.ino, 10, SeekWhence::Data)
                .unwrap(),
            10
        );
        assert_eq!(
            fs.lseek(&cx, &mut scope, file.ino, 10, SeekWhence::Hole)
                .unwrap(),
            1029
        );
        assert!(
            fs.lseek(&cx, &mut scope, file.ino, 1029, SeekWhence::Data)
                .is_err()
        );
        let stat = fs.statfs(&cx, &mut scope, root).unwrap();
        let expected_used = if kind == FatKind::Fat16 { 5 } else { 6 };
        assert_eq!(stat.blocks - stat.blocks_free, expected_used);
        let cached = fs.statfs(&cx, &mut scope, root).unwrap();
        assert_eq!(cached.blocks_free, stat.blocks_free);
        assert_eq!(cached.blocks_available, stat.blocks_free);
        assert_eq!(cached.block_size, 512);
    }
}

#[test]
fn fsops_rejects_directory_ancestor_links_and_ambiguous_names() {
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let mut image = Image::new(FatKind::Fat32);
    let at = image.root_location() + 32;
    image.record(at, b"SUBDIR     ", 2, 0, true);
    let fs = FatFs::new(&cx, image.volume(), 0, 0).unwrap();
    assert!(matches!(
        fs.lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("SUBDIR")),
        Err(FfsError::Corruption { .. })
    ));
    let mut image = Image::new(FatKind::Fat16);
    let at = image.root_location() + 64;
    image.record(at, b"HELLO   TXT", 11, 4, false);
    assert!(FatFs::new(&cx, image.volume(), 0, 0).is_err());
}

#[test]
fn directory_allocation_chain_is_validated_even_after_early_end_marker() {
    let cx = Cx::for_testing();
    let mut image = Image::new(FatKind::Fat32);
    image.set_link(2, 4);
    image.set_link(4, 2);
    let volume = image.volume();
    assert_eq!(volume.list(&cx, Directory::Root).unwrap().len(), 3);
    assert!(volume.directory_size(&cx, Directory::Root).is_err());
    assert!(FatFs::new(&cx, volume, 0, 0).is_err());
}
