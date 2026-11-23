//! Constructed-image operations and admission controls, plus an explicitly
//! ignored native-oracle test. These do not establish mounted crash readiness.

use super::*;
use crate::{InodeNumber, ReadOnlyOpenOptions, SetAttrRequest, open_read_only};
use clap::Parser;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn authorized() -> ReadWriteOpenOptions {
    ReadWriteOpenOptions {
        offline_image: true,
        allow_write: true,
        uid: 123,
        gid: 456,
        ..ReadWriteOpenOptions::default()
    }
}

fn formatted_image(cx: &Cx, directory: &Path, kind: &str) -> PathBuf {
    let path = directory.join(format!("{kind}.img"));
    if kind == "ntfs" {
        let report = ffs_ntfs::format_image_file(
            cx,
            &ffs_ntfs::NtfsFormatOptions::new_image(path.clone(), 12),
            None,
        )
        .unwrap();
        assert!(report.boot_published && report.check_clean);
    } else {
        let cli = ffs_fat::Cli::try_parse_from([
            "ffs-fat",
            "format",
            path.to_str().unwrap(),
            "--kind",
            kind,
            "--size-mib",
            if kind == "fat16" { "8" } else { "64" },
        ])
        .unwrap();
        let ffs_fat::Command::Format { options } = cli.command else {
            panic!("format command");
        };
        ffs_fat::formatter::create(cx, &options).unwrap();
    }
    path
}

#[test]
fn fat_and_ntfs_writers_preserve_bounds_and_reopen_native_namespace_and_data() {
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    for (kind, format) in [
        ("fat16", FsFormatKind::Fat16),
        ("fat32", FsFormatKind::Fat32),
        ("ntfs", FsFormatKind::Ntfs),
    ] {
        let image = formatted_image(&cx, directory.path(), kind);
        let native = fs::read(&image).unwrap();
        let mut container = vec![0xA7; 4096];
        container.extend_from_slice(&native);
        container.extend_from_slice(&[0xD3; 8192]);
        let path = directory.path().join(format!("{kind}.container"));
        fs::write(&path, &container).unwrap();
        let options = ReadWriteOpenOptions {
            offset: 4096,
            length: Some(native.len() as u64),
            ..authorized()
        };
        let opened = open_read_write(&cx, &path, &options).unwrap();
        assert_eq!(opened.format, format);
        let root = InodeNumber(1);
        let mut scope = RequestScope::empty();
        let folder = opened
            .filesystem
            .mkdir(&cx, &mut scope, root, OsStr::new("docs"), 0o755, 123, 456)
            .unwrap();
        let file = opened
            .filesystem
            .create(&cx, &mut scope, root, OsStr::new("payload"), 0o644, 123, 456)
            .unwrap();
        assert_eq!(
            opened
                .filesystem
                .write(&cx, &mut scope, file.ino, 0, b"native bytes")
                .unwrap(),
            12
        );
        assert_eq!(
            opened
                .filesystem
                .write(&cx, &mut scope, file.ino, 4096, b"tail")
                .unwrap(),
            4
        );
        opened
            .filesystem
            .setattr(
                &cx,
                &mut scope,
                file.ino,
                &SetAttrRequest {
                    size: Some(4098),
                    ..SetAttrRequest::default()
                },
            )
            .unwrap();
        opened
            .filesystem
            .rename(
                &cx,
                &mut scope,
                root,
                OsStr::new("payload"),
                folder.ino,
                OsStr::new("saved"),
            )
            .unwrap();
        opened.sync(&cx).unwrap();
        drop(opened);

        let read_options = ReadOnlyOpenOptions {
            offset: options.offset,
            length: options.length,
            ..ReadOnlyOpenOptions::default()
        };
        let reader = open_read_only(&cx, &path, &read_options).unwrap();
        let folder = reader
            .filesystem
            .lookup(&cx, &mut scope, root, OsStr::new("docs"))
            .unwrap();
        let file = reader
            .filesystem
            .lookup(&cx, &mut scope, folder.ino, OsStr::new("saved"))
            .unwrap();
        assert_eq!(file.size, 4098);
        let actual = reader
            .filesystem
            .read(&cx, &mut scope, file.ino, 0, 8192)
            .unwrap();
        let mut expected = vec![0; 4098];
        expected[..12].copy_from_slice(b"native bytes");
        expected[4096..].copy_from_slice(b"ta");
        assert_eq!(actual, expected, "{kind}: positioned growth and truncate");
        assert!(
            reader
                .filesystem
                .lookup(&cx, &mut scope, root, OsStr::new("payload"))
                .is_err()
        );
        assert!(matches!(
            reader.filesystem.write(&cx, &mut scope, file.ino, 0, b"bad"),
            Err(FfsError::ReadOnly)
        ));
        drop(reader);

        let reopened = open_read_write(&cx, &path, &options).unwrap();
        let folder = reopened
            .filesystem
            .lookup(&cx, &mut scope, root, OsStr::new("docs"))
            .unwrap();
        reopened
            .filesystem
            .unlink(&cx, &mut scope, folder.ino, OsStr::new("saved"))
            .unwrap();
        reopened
            .filesystem
            .rmdir(&cx, &mut scope, root, OsStr::new("docs"))
            .unwrap();
        reopened.sync(&cx).unwrap();
        drop(reopened);
        let reader = open_read_only(&cx, &path, &read_options).unwrap();
        assert!(
            reader
                .filesystem
                .lookup(&cx, &mut scope, root, OsStr::new("docs"))
                .is_err()
        );
        let after = fs::read(&path).unwrap();
        assert_eq!(&after[..4096], &container[..4096]);
        assert_eq!(&after[4096 + native.len()..], &container[4096 + native.len()..]);
    }
}

#[derive(Debug)]
struct ObservedDevice {
    bytes: Mutex<Vec<u8>>,
    reads: AtomicUsize,
    writes: AtomicUsize,
    syncs: AtomicUsize,
    fail_sync: AtomicBool,
}

impl ObservedDevice {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Mutex::new(bytes),
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            syncs: AtomicUsize::new(0),
            fail_sync: AtomicBool::new(false),
        }
    }
}

impl ByteDevice for ObservedDevice {
    fn len_bytes(&self) -> u64 {
        self.bytes.lock().unwrap().len() as u64
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        self.reads.fetch_add(1, Ordering::SeqCst);
        let bytes = self.bytes.lock().unwrap();
        let start = usize::try_from(offset.0).unwrap();
        let source = bytes.get(start..start + buf.len()).ok_or_else(|| {
            FfsError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "test-device bounds",
            ))
        })?;
        buf.copy_from_slice(source);
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        checkpoint(cx)?;
        self.writes.fetch_add(1, Ordering::SeqCst);
        let mut bytes = self.bytes.lock().unwrap();
        let start = usize::try_from(offset.0).unwrap();
        let dest = bytes.get_mut(start..start + buf.len()).ok_or_else(|| {
            FfsError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "test-device bounds",
            ))
        })?;
        dest.copy_from_slice(buf);
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        self.syncs.fetch_add(1, Ordering::SeqCst);
        if self.fail_sync.load(Ordering::SeqCst) {
            return Err(FfsError::Io(std::io::Error::other("injected sync failure")));
        }
        Ok(())
    }
}

#[test]
fn writable_authority_and_device_only_selection_fail_before_io() {
    let cx = Cx::for_testing();
    let device = Arc::new(ObservedDevice::new(vec![0; 4096]));
    for (offline_image, allow_write) in [(false, false), (true, false), (false, true)] {
        let options = ReadWriteOpenOptions {
            offline_image,
            allow_write,
            ..authorized()
        };
        assert!(matches!(
            open_read_write_device(&cx, device.clone(), &options),
            Err(FfsError::PermissionDenied)
        ));
        assert!(matches!(
            open_read_write(&cx, "/missing/unauthorized.img", &options),
            Err(FfsError::PermissionDenied)
        ));
    }
    let options = ReadWriteOpenOptions {
        backend: ReadWriteBackend::Zfs(ZfsWriteSelection {
            pool_guid: 123,
            additional_images: vec![ImageSource {
                path: PathBuf::from("/never/open/member.img"),
                offset: 0,
                length: None,
            }],
            ..ZfsWriteSelection::default()
        }),
        ..authorized()
    };
    assert!(matches!(
        open_read_write_device(&cx, device.clone(), &options),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert!(matches!(
        open_read_write_devices(&cx, device.clone(), vec![device.clone()], &authorized()),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert_eq!(device.reads.load(Ordering::SeqCst), 0);
    assert_eq!(device.writes.load(Ordering::SeqCst), 0);
    assert_eq!(device.syncs.load(Ordering::SeqCst), 0);
}

#[test]
fn unsupported_ext4_write_features_are_refused_before_orphan_recovery() {
    let cx = Cx::for_testing();
    let mut dirty = crate::native::tests::ext4_image();
    dirty[1024 + 58..1024 + 60].copy_from_slice(&5_u16.to_le_bytes());

    // The orphan flag alone requires cleanup even with an empty orphan chain.
    // Confirm that this independently specified fixture reaches physical
    // recovery when its supported feature set grants writer admission.
    let control = Arc::new(ObservedDevice::new(dirty.clone()));
    let recovered = OpenFs::from_devices(
        &cx,
        Box::new(control.clone()),
        &OpenOptions::default(),
        VolumeAccess::ReadWrite,
        None,
        Vec::new(),
    )
    .unwrap();
    drop(recovered);
    assert!(control.writes.load(Ordering::SeqCst) > 0);

    for feature in [
        ffs_ondisk::Ext4RoCompatFeatures::QUOTA,
        ffs_ondisk::Ext4RoCompatFeatures::PROJECT,
        ffs_ondisk::Ext4RoCompatFeatures::READONLY,
    ] {
        let mut image = dirty.clone();
        image[1024 + 100..1024 + 104].copy_from_slice(&feature.bits().to_le_bytes());
        let device = Arc::new(ObservedDevice::new(image.clone()));
        let error = open_read_write_device(&cx, device.clone(), &authorized()).unwrap_err();
        assert!(matches!(error, FfsError::UnsupportedFeature(_)));
        assert_eq!(device.writes.load(Ordering::SeqCst), 0);
        assert_eq!(device.syncs.load(Ordering::SeqCst), 0);
        assert_eq!(*device.bytes.lock().unwrap(), image);

        let reader =
            crate::open_read_only_device(&cx, device.clone(), &ReadOnlyOpenOptions::default())
                .unwrap();
        assert_eq!(reader.format, FsFormatKind::Ext4);
        drop(reader);
        assert_eq!(device.writes.load(Ordering::SeqCst), 0);
        assert_eq!(*device.bytes.lock().unwrap(), image);
    }
}

#[test]
fn filesystem_sync_reaches_backing_and_propagates_barrier_failure() {
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    let image = formatted_image(&cx, directory.path(), "fat16");
    let device = Arc::new(ObservedDevice::new(fs::read(&image).unwrap()));
    let opened = open_read_write_device(&cx, device.clone(), &authorized()).unwrap();
    opened.sync(&cx).unwrap();
    assert!(device.syncs.load(Ordering::SeqCst) > 0);
    device.fail_sync.store(true, Ordering::SeqCst);
    assert!(matches!(opened.sync(&cx), Err(FfsError::Io(_))));
}

#[test]
fn moved_filesystem_retains_exclusive_descriptor_until_last_owner_drops() {
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    let path = formatted_image(&cx, directory.path(), "fat16");
    let opened = open_read_write(&cx, &path, &authorized()).unwrap();
    let filesystem = opened.filesystem;
    let contender = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert!(contender.try_lock().is_err());
    assert!(contender.try_lock_shared().is_err());
    assert!(open_read_write(&cx, &path, &authorized()).is_err());
    assert!(open_read_only(&cx, &path, &ReadOnlyOpenOptions::default()).is_err());
    drop(filesystem);
    contender.try_lock().unwrap();
}

#[test]
fn writable_admission_refuses_mismatches_ambiguous_media_and_symlinks_without_writes() {
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    let path = formatted_image(&cx, directory.path(), "fat16");
    let before = fs::read(&path).unwrap();
    let mismatched = ReadWriteOpenOptions {
        backend: ReadWriteBackend::Ext4,
        ..authorized()
    };
    assert!(matches!(
        open_read_write(&cx, &path, &mismatched),
        Err(FfsError::Format(_))
    ));
    let truncated = ReadWriteOpenOptions {
        length: Some(512),
        ..authorized()
    };
    assert!(open_read_write(&cx, &path, &truncated).is_err());
    let alias = directory.path().join("alias.img");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(open_read_write(&cx, &alias, &authorized()).is_err());
    assert!(open_read_write(&cx, "/dev/null", &authorized()).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);

    let mut ambiguous = before;
    // Independently specified valid ext4 geometry in the FAT reserved area.
    let sb = &mut ambiguous[1024..2048];
    for (at, value) in [
        (0, 128_u32),
        (4, 64),
        (24, 2),
        (32, 64),
        (40, 128),
        (76, 1),
        (84, 11),
        (96, 0x42),
    ] {
        sb[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    sb[56..58].copy_from_slice(&0xEF53_u16.to_le_bytes());
    sb[58..60].copy_from_slice(&1_u16.to_le_bytes());
    sb[88..90].copy_from_slice(&256_u16.to_le_bytes());
    let device = Arc::new(ObservedDevice::new(ambiguous));
    assert!(matches!(
        open_read_write_device(&cx, device.clone(), &authorized()),
        Err(FfsError::Format(message)) if message.contains("ambiguous")
    ));
    assert_eq!(device.writes.load(Ordering::SeqCst), 0);
}

#[test]
fn mbr_partition_writer_does_not_mutate_partition_table_or_adjacent_storage() {
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    let image = formatted_image(&cx, directory.path(), "fat16");
    let native = fs::read(&image).unwrap();
    let start = 2048 * 512;
    let mut bytes = vec![0xA9; start];
    bytes[..512].fill(0);
    bytes[446 + 4] = 0x06;
    bytes[446 + 8..446 + 12].copy_from_slice(&2048_u32.to_le_bytes());
    bytes[446 + 12..446 + 16].copy_from_slice(&(native.len() as u32 / 512).to_le_bytes());
    bytes[510..512].copy_from_slice(&[0x55, 0xAA]);
    bytes.extend_from_slice(&native);
    bytes.extend_from_slice(&[0xDA; 4096]);
    let device = Arc::new(ObservedDevice::new(bytes.clone()));
    let options = ReadWriteOpenOptions {
        partition: Some(PartitionSelector::Index(1)),
        ..authorized()
    };
    let opened = open_read_write_device(&cx, device.clone(), &options).unwrap();
    assert_eq!(opened.partition.as_ref().unwrap().start_byte, start as u64);
    let file = opened
        .filesystem
        .create(
            &cx,
            &mut RequestScope::empty(),
            InodeNumber(1),
            OsStr::new("inside"),
            0o644,
            123,
            456,
        )
        .unwrap();
    opened
        .filesystem
        .write(
            &cx,
            &mut RequestScope::empty(),
            file.ino,
            0,
            b"only this partition",
        )
        .unwrap();
    opened.sync(&cx).unwrap();
    let after = device.bytes.lock().unwrap();
    assert_eq!(&after[..start], &bytes[..start]);
    assert_eq!(&after[start + native.len()..], &bytes[start + native.len()..]);
}

fn native_command(program: &str, args: &[&OsStr]) -> Vec<u8> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("required native oracle {program}: {error}"));
    assert!(
        output.status.success(),
        "{program} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output.stdout
}

#[test]
#[ignore = "requires mkfs.ext4, e2fsck, debugfs, mkfs.btrfs and btrfs native tools"]
fn native_ext4_and_btrfs_writers_reopen_and_pass_independent_checkers() {
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    for (kind, format) in [("ext4", FsFormatKind::Ext4), ("btrfs", FsFormatKind::Btrfs)] {
        let path = directory.path().join(format!("native.{kind}"));
        let image = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        image.set_len(128 * 1024 * 1024).unwrap();
        drop(image);
        if kind == "ext4" {
            native_command(
                "mkfs.ext4",
                &[
                    OsStr::new("-q"),
                    OsStr::new("-F"),
                    OsStr::new("-b"),
                    OsStr::new("4096"),
                    OsStr::new("-E"),
                    OsStr::new("lazy_itable_init=0,lazy_journal_init=0"),
                    path.as_os_str(),
                ],
            );
        } else {
            native_command(
                "mkfs.btrfs",
                &[
                    OsStr::new("-q"),
                    OsStr::new("-f"),
                    OsStr::new("-m"),
                    OsStr::new("single"),
                    OsStr::new("-d"),
                    OsStr::new("single"),
                    path.as_os_str(),
                ],
            );
        }
        let opened = open_read_write(&cx, &path, &authorized()).unwrap();
        assert_eq!(opened.format, format);
        let mut scope = RequestScope::empty();
        let file = opened
            .filesystem
            .create(
                &cx,
                &mut scope,
                InodeNumber(1),
                OsStr::new("from-facade"),
                0o644,
                123,
                456,
            )
            .unwrap();
        let payload = b"native writer facade durability\n";
        assert_eq!(
            opened
                .filesystem
                .write(&cx, &mut scope, file.ino, 0, payload)
                .unwrap() as usize,
            payload.len(),
        );
        opened.sync(&cx).unwrap();
        drop(opened);
        let reader = open_read_only(&cx, &path, &ReadOnlyOpenOptions::default()).unwrap();
        let file = reader
            .filesystem
            .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("from-facade"))
            .unwrap();
        assert_eq!(
            reader
                .filesystem
                .read(&cx, &mut scope, file.ino, 0, 128)
                .unwrap(),
            payload
        );
        drop(reader);
        if kind == "ext4" {
            native_command(
                "e2fsck",
                &[OsStr::new("-f"), OsStr::new("-n"), path.as_os_str()],
            );
            assert_eq!(
                native_command(
                    "debugfs",
                    &[
                        OsStr::new("-R"),
                        OsStr::new("cat /from-facade"),
                        path.as_os_str(),
                    ],
                ),
                payload
            );
        } else {
            native_command(
                "btrfs",
                &[
                    OsStr::new("check"),
                    OsStr::new("--readonly"),
                    path.as_os_str(),
                ],
            );
            let restored = directory.path().join("native-restored");
            fs::create_dir(&restored).unwrap();
            native_command(
                "btrfs",
                &[OsStr::new("restore"), path.as_os_str(), restored.as_os_str()],
            );
            assert_eq!(fs::read(restored.join("from-facade")).unwrap(), payload);
        }
    }
}
