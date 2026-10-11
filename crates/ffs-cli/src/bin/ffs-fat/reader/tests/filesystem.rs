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
        assert_eq!(
            fs.read(&cx, &mut scope, file.ino, u64::MAX, 1).unwrap(),
            [] as [u8; 0]
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
    assert!(volume.list(&cx, Directory::Root).is_err());
    assert!(volume.directory_size(&cx, Directory::Root).is_err());
    assert!(FatFs::new(&cx, volume, 0, 0).is_err());
}

#[test]
fn fsops_exposes_native_access_modification_and_creation_times() {
    use std::time::UNIX_EPOCH;

    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = Image::new(kind);
        let at = image.root_location();
        image.bytes[at + 13] = 157;
        image.bytes[at + 14..at + 16].copy_from_slice(&0x645C_u16.to_le_bytes());
        image.bytes[at + 16..at + 18].copy_from_slice(&0x585D_u16.to_le_bytes());
        image.bytes[at + 18..at + 20].copy_from_slice(&0x5861_u16.to_le_bytes());
        image.bytes[at + 22..at + 24].copy_from_slice(&0x1883_u16.to_le_bytes());
        image.bytes[at + 24..at + 26].copy_from_slice(&0x5862_u16.to_le_bytes());
        let fs = FatFs::new(&cx, image.volume(), 0, 0).unwrap();
        let attr = fs
            .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("HELLO.TXT"))
            .unwrap();
        let created = attr.crtime.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(
            (created.as_secs(), created.subsec_nanos()),
            (1_709_210_097, 570_000_000)
        );
        assert_eq!(
            attr.atime.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            1_709_251_200
        );
        assert_eq!(
            attr.mtime.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            1_709_348_646
        );
        assert_eq!(attr.ctime, UNIX_EPOCH);

        let unknown = fs
            .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("EMPTY.TXT"))
            .unwrap();
        assert_eq!(unknown.atime, UNIX_EPOCH);
        assert_eq!(unknown.mtime, UNIX_EPOCH);
        assert_eq!(unknown.crtime, UNIX_EPOCH);
        let root = fs.getattr(&cx, &mut scope, InodeNumber(1)).unwrap();
        assert_eq!(root.atime, UNIX_EPOCH);
        assert_eq!(root.mtime, UNIX_EPOCH);
        assert_eq!(root.crtime, UNIX_EPOCH);
    }
}

#[test]
fn fsops_rejects_invalid_native_timestamps_at_the_directory_record() {
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for case in 0..5 {
            let mut image = Image::new(kind);
            let at = image.root_location();
            let expected_block = ((at - image.base) / 512) as u64;
            image.bytes[at + 14..at + 16].copy_from_slice(&0x645C_u16.to_le_bytes());
            image.bytes[at + 16..at + 18].copy_from_slice(&0x585D_u16.to_le_bytes());
            match case {
                0 => image.bytes[at + 13] = 200,
                1 => {
                    image.bytes[at + 16..at + 18]
                        .copy_from_slice(&0x565D_u16.to_le_bytes());
                }
                2 => {
                    image.bytes[at + 18..at + 20]
                        .copy_from_slice(&0x565D_u16.to_le_bytes());
                }
                3 => {
                    image.bytes[at + 22..at + 24]
                        .copy_from_slice(&0xC000_u16.to_le_bytes());
                    image.bytes[at + 24..at + 26]
                        .copy_from_slice(&0x585D_u16.to_le_bytes());
                }
                _ => {
                    image.bytes[at + 22..at + 24]
                        .copy_from_slice(&1_u16.to_le_bytes());
                }
            }
            let fs = FatFs::new(&cx, image.volume(), 0, 0).unwrap();
            assert!(
                matches!(
                    fs.lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("HELLO.TXT")),
                    Err(FfsError::Corruption { block, .. }) if block == expected_block
                ),
                "kind={kind:?}, case={case}"
            );
        }
    }
}
