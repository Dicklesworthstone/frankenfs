use super::*;
use ffs_core::XattrSetMode;
use ffs_ondisk::ntfs::{EA, EA_INFORMATION};

fn values(entries: &[(&[u8], &[u8])]) -> (Vec<u8>, Vec<u8>) {
    let mut bytes = Vec::new();
    let mut packed = 0_u16;
    for &(name, value) in entries {
        let used = 9 + name.len() + value.len();
        let length = used.next_multiple_of(4);
        let mut entry = vec![0xBE; length];
        entry[..4].copy_from_slice(&(length as u32).to_le_bytes());
        entry[4] = 0;
        entry[5] = name.len() as u8;
        entry[6..8].copy_from_slice(&(value.len() as u16).to_le_bytes());
        entry[8..8 + name.len()].copy_from_slice(name);
        entry[8 + name.len()] = 0;
        entry[9 + name.len()..used].copy_from_slice(value);
        bytes.extend(entry);
        packed += (used - 4) as u16;
    }
    let mut info = vec![0; 8];
    info[..2].copy_from_slice(&packed.to_le_bytes());
    info[4..].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    (info, bytes)
}

fn put_file_eas(image: &mut [u8], info: &[u8], value: &[u8]) {
    put(
        image,
        24,
        &record(
            24,
            false,
            2,
            &[
                standard(),
                resident(DATA, 0, "", b"hello"),
                resident(0x30, 2, "", &filename(5, "hello.txt", 1)),
                resident(0x30, 3, "", &filename(5, "HELLO~1.TXT", 2)),
                resident(0x30, 4, "", &filename(27, "link.txt", 1)),
                resident(EA_INFORMATION, 6, "", info),
                resident(EA, 7, "", value),
            ],
        ),
    );
}

fn native_image() -> Vec<u8> {
    let mut bytes = image();
    let (info, value) = values(&[
        (b"user.note", &[0, 0xFF, 1]),
        (b"user.empty", &[]),
        (b"user.Z", b"last"),
        (b"system.posix_acl_access", &[0xCC, 0, 1]),
        (b"security.capability", &[0xDD, 0, 2]),
        (b"$LXUID", &[42, 0, 0, 0]),
        (b"User.case", b"native"),
        (b"OS2NAME", b"native"),
    ]);
    put_file_eas(&mut bytes, &info, &value);
    let (info, value) = values(&[(b"user.folder", &[7, 0, 8])]);
    put(
        &mut bytes,
        27,
        &record(
            27,
            true,
            1,
            &[
                standard(),
                index(&[(24, "link.txt", 1), (25, "payload.bin", 1)], 27),
                resident(0x30, 2, "", &filename(5, "Subdir", 1)),
                resident(EA_INFORMATION, 6, "", &info),
                resident(EA, 7, "", &value),
            ],
        ),
    );
    bytes
}

#[test]
fn mounted_user_eas_preserve_binary_values_hard_links_and_conservative_namespaces() {
    let cx = Cx::for_testing();
    let fs = open(native_image(), Arc::default(), None).unwrap();
    let mut scope = RequestScope::empty();
    let file = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("hello.txt"))
        .unwrap();
    let alias = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("HELLO~1.TXT"))
        .unwrap();
    let dir = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("Subdir"))
        .unwrap();
    let link = fs
        .lookup(&cx, &mut scope, dir.ino, OsStr::new("link.txt"))
        .unwrap();
    assert_eq!((file.ino, file.ino), (alias.ino, link.ino));
    assert_eq!(
        (file.uid, file.gid, file.perm, file.size),
        (123, 456, 0o444, 5)
    );
    for ino in [file.ino, alias.ino, link.ino] {
        assert_eq!(
            fs.listxattr(&cx, ino).unwrap(),
            ["user.Z", "user.empty", "user.note"]
        );
        assert_eq!(
            fs.getxattr(&cx, ino, "user.note").unwrap(),
            Some(vec![0, 0xFF, 1])
        );
        assert_eq!(
            fs.getxattr(&cx, ino, "user.empty").unwrap(),
            Some(Vec::new())
        );
        assert_eq!(fs.getxattr(&cx, ino, "user.z").unwrap(), None);
        assert_eq!(fs.getxattr(&cx, ino, "user.OS2NAME").unwrap(), None);
        assert_eq!(
            fs.getxattr(&cx, ino, "user.security.capability").unwrap(),
            None
        );
    }
    assert_eq!(fs.listxattr(&cx, dir.ino).unwrap(), ["user.folder"]);
    assert_eq!(
        fs.getxattr(&cx, dir.ino, "user.folder").unwrap(),
        Some(vec![7, 0, 8])
    );
    assert!(fs.listxattr(&cx, ROOT).unwrap().is_empty());
    assert_eq!(fs.getxattr(&cx, ROOT, "user.missing").unwrap(), None);
    for name in [
        "security.capability",
        "system.posix_acl_access",
        "$LXUID",
        "User.case",
        "OS2NAME",
    ] {
        assert!(matches!(
            fs.getxattr(&cx, file.ino, name),
            Err(FfsError::UnsupportedFeature(_))
        ));
    }
    for name in ["user.", "user.bad\0name"] {
        assert!(matches!(
            fs.getxattr(&cx, file.ino, name),
            Err(FfsError::Format(_))
        ));
    }
    assert!(matches!(
        fs.getxattr(&cx, file.ino, &"user.x".repeat(50)),
        Err(FfsError::NameTooLong)
    ));
    assert!(matches!(
        fs.setxattr(
            &cx,
            &mut scope,
            file.ino,
            "user.note",
            b"changed",
            XattrSetMode::Set
        ),
        Err(FfsError::ReadOnly)
    ));
    assert!(matches!(
        fs.removexattr(&cx, &mut scope, file.ino, "user.note"),
        Err(FfsError::ReadOnly)
    ));
    assert_eq!(
        fs.read(&cx, &mut scope, file.ino, 0, 100).unwrap(),
        b"hello"
    );
}

fn fragmented_image() -> (Vec<u8>, Vec<u8>, usize) {
    let mut image = image();
    let payload: Vec<_> = (0..700).map(|offset| (offset % 251) as u8).collect();
    let (info, value) = values(&[(b"user.large", &payload)]);
    image[BASE + 630 * 512..BASE + 631 * 512].copy_from_slice(&value[..512]);
    image[BASE + 620 * 512..BASE + 620 * 512 + value.len() - 512].copy_from_slice(&value[512..]);
    let mut ea = mapped(
        &[0x21, 1, 0x76, 2, 0x11, 1, 0xF6, 0],
        2,
        value.len() as u64,
        false,
    );
    ea[..4].copy_from_slice(&EA.to_le_bytes());
    ea[14..16].copy_from_slice(&7_u16.to_le_bytes());
    put(
        &mut image,
        25,
        &record(
            25,
            false,
            1,
            &[
                standard(),
                mapped(&[0x21, 1, 88, 2, 0x11, 1, 0xF6, 0], 2, 600, false),
                resident(0x30, 2, "", &filename(27, "payload.bin", 1)),
                resident(EA_INFORMATION, 6, "", &info),
                ea,
            ],
        ),
    );
    (image, payload, value.len())
}

#[test]
fn mounted_fragmented_eas_read_only_the_ea_stream_and_propagate_late_cancellation() {
    let cx = Cx::for_testing();
    let (image, payload, size) = fragmented_image();
    let reads: Reads = Arc::default();
    let fs = open(image.clone(), Arc::clone(&reads), None).unwrap();
    let mut scope = RequestScope::empty();
    let dir = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("Subdir"))
        .unwrap();
    let file = fs
        .lookup(&cx, &mut scope, dir.ino, OsStr::new("payload.bin"))
        .unwrap();
    reads.lock().unwrap().clear();
    assert_eq!(
        fs.getxattr(&cx, file.ino, "user.large").unwrap(),
        Some(payload)
    );
    let captured = reads.lock().unwrap().clone();
    assert_eq!(
        &captured[captured.len() - 2..],
        &[
            (BASE as u64 + 630 * 512, 512),
            (BASE as u64 + 620 * 512, size - 512),
        ]
    );
    assert!(
        !captured
            .iter()
            .any(|(offset, _)| [BASE as u64 + 600 * 512, BASE as u64 + 590 * 512].contains(offset))
    );
    let fs = open(image, Arc::default(), Some(BASE as u64 + 620 * 512)).unwrap();
    assert!(matches!(
        fs.getxattr(&cx, file.ino, "user.large"),
        Err(FfsError::Cancelled)
    ));
    assert!(matches!(
        fs.listxattr(&cx, file.ino),
        Err(FfsError::Cancelled)
    ));
}

#[test]
fn mounted_eas_validate_hidden_tail_names_and_reject_lossy_user_projections() {
    let cx = Cx::for_testing();
    for name in [b"user.\xFF".as_slice(), b"user."] {
        let mut image = image();
        let (info, value) = values(&[(b"user.good", b"first"), (name, b"native")]);
        put_file_eas(&mut image, &info, &value);
        let fs = open(image, Arc::default(), None).unwrap();
        let ino = fs
            .inode(NtfsReference {
                record: 24,
                sequence: SEQUENCE,
            })
            .unwrap();
        let record = fs.record(&cx, ino).unwrap();
        assert_eq!(
            fs.volume
                .extended_attributes(&cx, &record)
                .unwrap()
                .entries
                .len(),
            2
        );
        assert!(matches!(
            fs.listxattr(&cx, ino),
            Err(FfsError::UnsupportedFeature(_))
        ));
        assert!(matches!(
            fs.getxattr(&cx, ino, "user.good"),
            Err(FfsError::UnsupportedFeature(_))
        ));
    }
    let mut image = image();
    let (info, mut value) = values(&[(b"user.good", b"first"), (b"security.hidden", b"bad")]);
    let second = (9 + b"user.good".len() + b"first".len()).next_multiple_of(4);
    value[second + 4] = 1;
    put_file_eas(&mut image, &info, &value);
    let fs = open(image, Arc::default(), None).unwrap();
    let ino = fs
        .inode(NtfsReference {
            record: 24,
            sequence: SEQUENCE,
        })
        .unwrap();
    assert!(matches!(
        fs.listxattr(&cx, ino),
        Err(FfsError::Corruption { .. })
    ));
    assert!(matches!(
        fs.getxattr(&cx, ino, "user.good"),
        Err(FfsError::Corruption { .. })
    ));
}

#[test]
fn ea_queries_recheck_inode_identity_even_after_metadata_cache_hits() {
    let cx = Cx::for_testing();
    let fs = open(native_image(), Arc::default(), None).unwrap();
    let mut scope = RequestScope::empty();
    let file = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("hello.txt"))
        .unwrap();
    assert!(fs.getattr(&cx, &mut scope, file.ino).is_ok());
    for ino in [
        InodeNumber(0),
        InodeNumber(file.ino.0 + (1 << 32)),
        InodeNumber(u64::MAX),
    ] {
        assert!(fs.listxattr(&cx, ino).is_err());
        assert!(fs.getxattr(&cx, ino, "user.note").is_err());
    }
}
