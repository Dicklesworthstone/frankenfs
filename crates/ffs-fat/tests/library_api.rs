//! Consumer-side native-image controls for the extracted public library.
//! These exercise FsOps directly; they are not mounted-kernel qualification.

use asupersync::Cx;
use clap::Parser;
use ffs_core::{FsOps, RequestScope};
use ffs_error::FfsError;
use ffs_fat::{Cli, Command, FatFs, FatVolume, formatter, reader};
use ffs_ondisk::fat::FatKind;
use ffs_types::InodeNumber;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;

fn format(cx: &Cx, image: &Path, kind: &str, size: &str) {
    let cli = Cli::try_parse_from([
        "ffs-fat",
        "format",
        image.to_str().unwrap(),
        "--kind",
        kind,
        "--size-mib",
        size,
    ])
    .unwrap();
    let Command::Format { options } = cli.command else {
        panic!("expected format options");
    };
    formatter::create(cx, &options).unwrap();
}

#[test]
fn downstream_native_operations_share_caller_context_and_keep_default_fs_read_only() {
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("payload.bin");
    let payload = b"native FAT library payload\0with a second cluster".repeat(37);
    fs::write(&source, &payload).unwrap();

    for (kind, size) in [("fat16", "8"), ("fat32", "64")] {
        let image = directory.path().join(format!("{kind}.img"));
        format(&cx, &image, kind, size);
        // Both calls previously installed a process-global handler. A library
        // operation must be repeatable under the consumer's existing context.
        for path in ["/first", "/second"] {
            let cli = Cli::try_parse_from([
                "ffs-fat",
                "mkdir",
                image.to_str().unwrap(),
                path,
                "--offline-image",
            ])
            .unwrap();
            let Command::Mkdir { options } = cli.command else {
                panic!("expected mkdir options");
            };
            reader::replacement::run_mkdir(&cx, &options).unwrap();
        }
        for path in ["/first/data.bin", "/second/data.bin"] {
            let cli = Cli::try_parse_from([
                "ffs-fat",
                "replace",
                image.to_str().unwrap(),
                path,
                "--source",
                source.to_str().unwrap(),
                "--create",
                "--offline-image",
            ])
            .unwrap();
            let Command::Replace { options } = cli.command else {
                panic!("expected replace options");
            };
            reader::replacement::replace(&cx, &options).unwrap();
        }
        for _ in 0..2 {
            let cli = Cli::try_parse_from([
                "ffs-fat",
                "recover",
                image.to_str().unwrap(),
                "--offline-image",
                "--dry-run",
            ])
            .unwrap();
            let Command::Recover { options } = cli.command else {
                panic!("expected recovery options");
            };
            let report = reader::recovery::recover(&cx, &options).unwrap();
            assert_eq!(report["dry_run"], true);
            assert_eq!(report["before"]["clean"], true);
            assert_eq!(report["planned_reclaimed_clusters"], 0);
        }

        let before = fs::read(&image).unwrap();
        let volume = FatVolume::open(&cx, &image, 0, None).unwrap();
        let fs = FatFs::new(&cx, volume, 123, 456).unwrap();
        let mut scope = RequestScope::empty();
        let root = InodeNumber(1);
        let first = fs
            .lookup(&cx, &mut scope, root, OsStr::new("first"))
            .unwrap();
        let file = fs
            .lookup(&cx, &mut scope, first.ino, OsStr::new("data.bin"))
            .unwrap();
        assert_eq!((file.uid, file.gid), (123, 456));
        assert_eq!(
            fs.read(
                &cx,
                &mut scope,
                file.ino,
                0,
                u32::try_from(payload.len()).unwrap()
            )
            .unwrap(),
            payload
        );
        assert!(matches!(
            fs.open(&cx, &mut scope, file.ino, libc::O_WRONLY),
            Err(FfsError::ReadOnly)
        ));
        assert!(matches!(
            fs.write(&cx, &mut scope, file.ino, 0, b"changed"),
            Err(FfsError::ReadOnly)
        ));
        drop(fs);
        assert_eq!(fs::read(&image).unwrap(), before);
    }
}

#[test]
fn downstream_read_admission_refuses_dirty_native_images_and_cancelled_contexts() {
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    for (kind, size) in [("fat16", "8"), ("fat32", "64")] {
        let image = directory.path().join(format!("{kind}.img"));
        format(&cx, &image, kind, size);
        let volume = FatVolume::open(&cx, &image, 0, None).unwrap();
        let geometry = volume.geometry.clone();
        drop(volume);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&image)
            .unwrap();
        for copy in 0..geometry.fat_count() {
            // entry_offset admits data clusters only. Reserved FAT[1] is one
            // native entry before FAT[2], within this explicitly selected copy.
            let width = geometry.kind().entry_bytes();
            let offset = geometry
                .entry_offset(copy, 2)
                .unwrap()
                .checked_sub(u64::from(width))
                .unwrap();
            let mut original = [0; 4];
            file.read_exact_at(&mut original[..width as usize], offset)
                .unwrap();
            let (value_mask, clean_mask) = match geometry.kind() {
                FatKind::Fat16 => (0xFFFF, 0x8000),
                FatKind::Fat32 => (0x0FFF_FFFF, 0x0800_0000),
            };
            let original = u32::from_le_bytes(original);
            assert_eq!(original & value_mask, value_mask);
            let dirty = (original & !clean_mask).to_le_bytes();
            file.write_all_at(&dirty[..width as usize], offset).unwrap();
            let mut readback = [0; 4];
            file.read_exact_at(&mut readback[..width as usize], offset)
                .unwrap();
            assert_eq!(&readback[..width as usize], &dirty[..width as usize]);
            assert_eq!(u32::from_le_bytes(readback) ^ original, clean_mask);
        }
        file.sync_all().unwrap();
        drop(file);
        let before = fs::read(&image).unwrap();
        assert!(FatVolume::open(&cx, &image, 0, None).is_err());
        let cancelled = Cx::for_testing();
        cancelled.cancel_with(asupersync::types::CancelKind::User, None);
        assert!(matches!(
            FatVolume::open(&cancelled, &image, 0, None),
            Err(FfsError::Cancelled)
        ));
        assert_eq!(fs::read(&image).unwrap(), before);
    }
}
