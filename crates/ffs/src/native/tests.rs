//! Constructed native-image and authority controls, not mounted-kernel proof.

use super::*;
use clap::Parser;
use ffs_core::{FileType, RequestScope};
use ffs_types::InodeNumber;
use std::ffi::OsStr;
use std::fs;

fn fat_image(cx: &Cx, directory: &Path, kind: &str) -> PathBuf {
    let image = directory.join(format!("{kind}.img"));
    let cli = ffs_fat::Cli::try_parse_from([
        "ffs-fat",
        "format",
        image.to_str().unwrap(),
        "--kind",
        kind,
        "--size-mib",
        if kind == "fat16" { "8" } else { "64" },
    ])
    .unwrap();
    let ffs_fat::Command::Format { options } = cli.command else {
        panic!("expected format options");
    };
    ffs_fat::formatter::create(cx, &options).unwrap();
    let args = ffs_fat::ImageArgs {
        image: image.clone(),
        offset: 0,
        length: None,
        oem_code_page: FatOemCodePage::Ascii,
        sidecar: None,
    };
    let volume = ffs_fat::reader::replacement::open_volume(cx, &args, true).unwrap();
    ffs_fat::reader::replacement::create_in_volume(
        cx,
        &volume,
        "/hello.txt",
        b"native facade payload\0",
        1_700_000_000,
        false,
    )
    .unwrap();
    image
}

fn ext4_image() -> Vec<u8> {
    // One 4 KiB-block group, dynamic inodes, no metadata checksums or journal.
    // The root metadata is independently specified; validation stays enabled.
    let mut image = vec![0_u8; 256 * 1024];
    let sb = &mut image[1024..2048];
    for (offset, value) in [
        (0, 128_u32),
        (4, 64),
        (24, 2),
        (32, 64),
        (40, 128),
        (76, 1),
        (84, 11),
        (96, 0x42),
    ] {
        sb[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    sb[56..58].copy_from_slice(&0xEF53_u16.to_le_bytes());
    sb[58..60].copy_from_slice(&1_u16.to_le_bytes());
    sb[88..90].copy_from_slice(&256_u16.to_le_bytes());
    for (offset, value) in [(4096, 2_u32), (4100, 3), (4104, 4)] {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    let root = 4 * 4096 + 256;
    image[root..root + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
    image[root + 4..root + 8].copy_from_slice(&4096_u32.to_le_bytes());
    image[root + 26..root + 28].copy_from_slice(&2_u16.to_le_bytes());
    image[root + 128..root + 130].copy_from_slice(&32_u16.to_le_bytes());
    image
}

#[test]
fn native_fat_both_dialects_open_through_bounded_facade_and_preserve_container() {
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    for (kind, expected) in [
        ("fat16", FsFormatKind::Fat16),
        ("fat32", FsFormatKind::Fat32),
    ] {
        let image = fat_image(&cx, directory.path(), kind);
        let volume = fs::read(&image).unwrap();
        let mut container = vec![0xA7; 4096];
        container.extend_from_slice(&volume);
        container.extend_from_slice(&[0xD3; 8192]);
        let path = directory.path().join(format!("{kind}.container"));
        fs::write(&path, &container).unwrap();
        let opened = open_read_only(
            &cx,
            &path,
            &ReadOnlyOpenOptions {
                offset: 4096,
                length: Some(volume.len() as u64),
                uid: 123,
                gid: 456,
                ..ReadOnlyOpenOptions::default()
            },
        )
        .unwrap();
        assert_eq!(opened.format, expected);
        let mut scope = RequestScope::empty();
        let root = InodeNumber(1);
        let file = opened
            .filesystem
            .lookup(&cx, &mut scope, root, OsStr::new("hello.txt"))
            .unwrap();
        assert_eq!((file.uid, file.gid), (123, 456));
        assert_eq!(
            opened
                .filesystem
                .read(&cx, &mut scope, file.ino, 0, 128)
                .unwrap(),
            b"native facade payload\0"
        );
        assert!(matches!(
            opened
                .filesystem
                .write(&cx, &mut scope, file.ino, 0, b"mutate"),
            Err(FfsError::ReadOnly)
        ));
        assert_eq!(fs::read(&path).unwrap(), container);
        let exclusive = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(
            exclusive.try_lock().is_err(),
            "the facade must retain its shared image lock"
        );
        drop(opened);
        exclusive.try_lock().unwrap();
        drop(exclusive);
        let mismatched = ReadOnlyOpenOptions {
            backend: ReadOnlyBackend::Ntfs,
            ..ReadOnlyOpenOptions::default()
        };
        assert!(matches!(
            open_read_only(&cx, &image, &mismatched),
            Err(FfsError::Format(_))
        ));
        let truncated = ReadOnlyOpenOptions {
            length: Some(512),
            ..ReadOnlyOpenOptions::default()
        };
        assert!(open_read_only(&cx, &image, &truncated).is_err());
        assert_eq!(fs::read(&image).unwrap(), volume);
    }
}

#[test]
fn ext4_facade_uses_real_core_metadata_without_granting_write_authority() {
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    let image = ext4_image();
    let path = directory.path().join("ext4.img");
    fs::write(&path, &image).unwrap();
    let opened = open_read_only(&cx, &path, &ReadOnlyOpenOptions::default()).unwrap();
    assert_eq!(opened.format, FsFormatKind::Ext4);
    let root = opened
        .filesystem
        .getattr(&cx, &mut RequestScope::empty(), InodeNumber(1))
        .unwrap();
    assert_eq!((root.kind, root.perm), (FileType::Directory, 0o755));
    assert!(matches!(
        opened
            .filesystem
            .write(&cx, &mut RequestScope::empty(), root.ino, 0, b"bad"),
        Err(FfsError::ReadOnly)
    ));
    assert_eq!(fs::read(&path).unwrap(), image);
}

#[test]
fn residual_valid_signature_is_ambiguous_even_with_explicit_backend_selection() {
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    let path = fat_image(&cx, directory.path(), "fat16");
    let mut image = fs::read(&path).unwrap();
    image[1024..2048].copy_from_slice(&ext4_image()[1024..2048]);
    fs::write(&path, &image).unwrap();
    for backend in [
        ReadOnlyBackend::Auto,
        ReadOnlyBackend::Fat {
            oem_code_page: FatOemCodePage::Ascii,
        },
    ] {
        let result = open_read_only(
            &cx,
            &path,
            &ReadOnlyOpenOptions {
                backend,
                ..ReadOnlyOpenOptions::default()
            },
        );
        assert!(matches!(result, Err(FfsError::Format(ref error)) if error.contains("ambiguous")));
    }
    assert_eq!(fs::read(&path).unwrap(), image);
}

#[test]
fn image_admission_retains_exclusive_lock_refusal_and_rejects_nonregular_backing() {
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("locked.img");
    fs::write(&path, [0_u8; 2048]).unwrap();
    let owner = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    owner.try_lock().unwrap();
    assert!(matches!(
        open_read_only(&cx, &path, &ReadOnlyOpenOptions::default()),
        Err(FfsError::Io(_))
    ));
    assert!(matches!(
        open_read_only(&cx, "/dev/null", &ReadOnlyOpenOptions::default()),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), vec![0_u8; 2048]);
}

#[test]
fn invalid_missing_member_requests_and_cancellation_fail_before_path_open() {
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    let absent = directory.path().join("absent.img");
    let candidate = ZfsRootSelection::Candidate {
        pool_guid: 42,
        label: 0,
        slot: 0,
    };
    let selections = [
        ZfsReadOptions {
            missing: ZfsMissingMembers::Mirror(vec![1]),
            ..ZfsReadOptions::default()
        },
        ZfsReadOptions {
            root: ZfsRootSelection::Pool(42),
            missing: ZfsMissingMembers::Raidz(vec![1]),
            ..ZfsReadOptions::default()
        },
        ZfsReadOptions {
            root: candidate.clone(),
            replay_zil: true,
            missing: ZfsMissingMembers::Mirror(vec![1]),
            ..ZfsReadOptions::default()
        },
        ZfsReadOptions {
            root: candidate.clone(),
            missing: ZfsMissingMembers::Mirror(vec![0]),
            ..ZfsReadOptions::default()
        },
        ZfsReadOptions {
            root: candidate.clone(),
            missing: ZfsMissingMembers::Mirror(vec![1, 1]),
            ..ZfsReadOptions::default()
        },
        ZfsReadOptions {
            root: candidate.clone(),
            missing: ZfsMissingMembers::Raidz(vec![1, 2, 3, 4]),
            ..ZfsReadOptions::default()
        },
        ZfsReadOptions {
            root: ZfsRootSelection::Candidate {
                pool_guid: 0,
                label: 0,
                slot: 0,
            },
            missing: ZfsMissingMembers::Mirror(vec![1]),
            ..ZfsReadOptions::default()
        },
        ZfsReadOptions {
            replay_zil: true,
            snapshot: Some(b"saved".to_vec()),
            ..ZfsReadOptions::default()
        },
    ];
    for selection in selections {
        let options = ReadOnlyOpenOptions {
            backend: ReadOnlyBackend::Zfs(selection),
            ..ReadOnlyOpenOptions::default()
        };
        assert!(matches!(
            open_read_only(&cx, &absent, &options),
            Err(FfsError::UnsupportedFeature(_))
        ));
    }
    let cancelled = Cx::for_testing();
    cancelled.cancel_with(asupersync::types::CancelKind::User, None);
    assert!(matches!(
        open_read_only(&cancelled, &absent, &ReadOnlyOpenOptions::default()),
        Err(FfsError::Cancelled)
    ));
    assert!(!absent.exists());
}
