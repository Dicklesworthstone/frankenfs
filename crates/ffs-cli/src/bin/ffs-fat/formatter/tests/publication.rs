use super::*;
use std::os::unix::fs::MetadataExt;

#[test]
fn freshly_formatted_files_have_native_layouts_and_readable_empty_roots() {
    let directory = tempfile::tempdir().unwrap();
    for (kind, expected_clusters, expected_fat, expected_root) in [
        (FormatKind::Fat16, 65_264_u64, 255_u64, 511_u64),
        (FormatKind::Fat32, 129_022, 1009, 2050),
    ] {
        let mut args = options(directory.path().join(format!("native-{kind:?}.img")), kind);
        args.size_mib = 64;
        let cx = Cx::for_testing();
        let report = create(&cx, &args).unwrap();
        assert_eq!(report["data_clusters"], expected_clusters);
        assert_eq!(report["fat_sectors"], expected_fat);
        assert_eq!(report["durability"], "file_and_parent_synced");
        let file = File::open(&args.image).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 64 * 1_048_576);
        let boot = read_sector(&file, 0);
        let fat_sector = u64::from(short(&boot, 14));
        let width = if kind == FormatKind::Fat16 { 2 } else { 4 };
        let fat_length = usize::try_from(expected_fat * 512).unwrap();
        let mut first_fat = vec![0; fat_length];
        let mut second_fat = vec![0; fat_length];
        file.read_exact_at(&mut first_fat, fat_sector * 512)
            .unwrap();
        file.read_exact_at(&mut second_fat, (fat_sector + expected_fat) * 512)
            .unwrap();
        assert_eq!(first_fat, second_fat);
        // Decode all addressable FAT entries using their native byte widths,
        // independently of FatTable and the candidate allocation checker.
        let mut free = 0_u64;
        for cluster in 2..expected_clusters + 2 {
            let offset = usize::try_from(cluster).unwrap() * width;
            let entry = if width == 2 {
                u32::from(short(&first_fat, offset))
            } else {
                long(&first_fat, offset) & 0x0FFF_FFFF
            };
            if kind == FormatKind::Fat32 && cluster == 2 {
                assert_eq!(entry, 0x0FFF_FFFF);
            } else {
                assert_eq!(entry, 0, "{kind:?} cluster {cluster}");
                free += 1;
            }
        }
        let addressed = usize::try_from(expected_clusters + 2).unwrap() * width;
        assert!(first_fat[addressed..].iter().all(|byte| *byte == 0));
        assert_eq!(
            free,
            expected_clusters - u64::from(kind == FormatKind::Fat32)
        );
        assert_eq!(report["verification"]["free_clusters"], free);
        let root = read_sector(&file, expected_root);
        assert_eq!(&root[..11], b"FRANK DATA ");
        assert_eq!(root[11], 0x08);
        assert!(root[32..].iter().all(|byte| *byte == 0));
        for sector in [expected_root + 1, 65_536, 131_071] {
            assert_eq!(read_sector(&file, sector), [0; 512]);
        }
        let volume = FatVolume::open(&cx, &args.image, 0, None).unwrap();
        assert!(
            volume
                .list(&cx, super::super::super::reader::Directory::Root)
                .unwrap()
                .is_empty()
        );
        let checked = volume.check(&cx).unwrap();
        assert!(checked.clean && checked.complete && checked.namespace_complete);
        assert_eq!(checked.free_clusters, free);
        assert_eq!(checked.lost_clusters, Some(0));
        assert!(checked.issues.is_empty());
        assert_eq!(checked.omitted_issues, 0);
    }
}

#[test]
fn create_new_preserves_existing_files_hardlinks_directories_and_symlinks() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original.img");
    let hardlink = directory.path().join("hardlink.img");
    let link = directory.path().join("symlink.img");
    let dangling = directory.path().join("dangling.img");
    let absent = directory.path().join("absent.img");
    let bytes = b"existing native image bytes must survive every refusal";
    std::fs::write(&original, bytes).unwrap();
    std::fs::hard_link(&original, &hardlink).unwrap();
    symlink(&original, &link).unwrap();
    symlink(&absent, &dangling).unwrap();
    let before = std::fs::metadata(&original).unwrap();
    let cx = Cx::for_testing();
    for kind in [FormatKind::Fat16, FormatKind::Fat32] {
        for path in [&original, &hardlink, &link, &dangling] {
            let error = create(&cx, &options(path.clone(), kind)).unwrap_err();
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().kind(),
                io::ErrorKind::AlreadyExists
            );
            assert_eq!(std::fs::read(&original).unwrap(), bytes);
            assert_eq!(std::fs::read(&hardlink).unwrap(), bytes);
        }
        let error = create(&cx, &options(directory.path().to_owned(), kind)).unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::AlreadyExists
        );
    }
    let after = std::fs::metadata(&original).unwrap();
    assert_eq!(
        (after.dev(), after.ino(), after.nlink()),
        (before.dev(), before.ino(), before.nlink())
    );
    assert_eq!(std::fs::read_link(&link).unwrap(), original);
    assert_eq!(std::fs::read_link(&dangling).unwrap(), absent);
    assert!(!absent.exists());
}

#[test]
fn explicit_cluster_selection_and_decimal_or_hex_serial_reach_native_metadata() {
    for (kind, mib, spc, expected_fat, expected_clusters) in [
        ("fat16", "64", "4", 128, 32_695),
        ("fat32", "128", "2", 1016, 130_040),
    ] {
        for serial in ["2309737967", "0x89ABCDEF", "0X89abcdef"] {
            let cli = Cli::try_parse_from([
                "ffs-fat",
                "format",
                "new.img",
                "--kind",
                kind,
                "--size-mib",
                mib,
                "--sectors-per-cluster",
                spc,
                "--serial",
                serial,
            ])
            .unwrap();
            let Command::Format { options } = cli.command else {
                panic!("expected format");
            };
            assert_eq!(options.serial, Some(0x89AB_CDEF));
            assert_eq!(options.sectors_per_cluster, Some(spc.parse().unwrap()));
            assert!(options.label.is_none());
            let plan = FormatPlan::prepare(&options).unwrap();
            assert_eq!(plan.boot[13], spc.parse::<u8>().unwrap());
            assert_eq!(plan.layout.fat_sectors, expected_fat);
            assert_eq!(plan.layout.data_clusters, expected_clusters);
            let serial_offset = if kind == "fat16" { 39 } else { 67 };
            assert_eq!(long(&plan.boot, serial_offset), 0x89AB_CDEF);
            assert_eq!(
                &plan.boot[serial_offset + 4..serial_offset + 15],
                b"NO NAME    "
            );
        }
    }
    // Preserve the incoming large-cluster profile when explicitly requested.
    assert!(Layout::calculate_with_cluster(FormatKind::Fat16, 2048, Some(128)).is_ok());
    for invalid in ["0x", "0x100000000", "4294967296", "-1", "garbage"] {
        assert!(
            Cli::try_parse_from([
                "ffs-fat",
                "format",
                "new.img",
                "--kind",
                "fat16",
                "--size-mib",
                "4",
                "--serial",
                invalid,
            ])
            .is_err(),
            "{invalid}"
        );
    }
    assert!(
        Cli::try_parse_from([
            "ffs-fat",
            "format",
            "new.img",
            "--kind",
            "fat16",
            "--size-mib",
            "4",
            "--sectors-per-cluster",
            "256",
        ])
        .is_err()
    );
}

#[test]
fn a_pending_user_interrupt_reaches_precreation_device_reads_and_the_full_checker() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("must-not-exist.img");
    let cx = Cx::for_testing();
    // Use the same supported production API and cloned context as Ctrl+C.
    let signal = cx.clone();
    signal.cancel_with(CancelKind::User, Some("format interruption test"));
    assert!(cx.is_cancel_requested());
    assert!(cx.cancelled_by(CancelKind::User));
    let error = create(&cx, &options(path.clone(), FormatKind::Fat16)).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<FfsError>(),
        Some(FfsError::Cancelled)
    ));
    assert!(!path.exists());

    let args = options(directory.path().join("initialized.img"), FormatKind::Fat32);
    let plan = FormatPlan::prepare(&args).unwrap();
    let cx = Cx::for_testing();
    let file = new_file(&args.image);
    initialize(&cx, &file, &plan, || Ok(())).unwrap();
    let device = CreatedImage {
        file: file.try_clone().unwrap(),
        length: plan.layout.image_bytes(),
    };
    let volume = FatVolume::from_device(
        &cx,
        Box::new(CreatedImage {
            file: file.try_clone().unwrap(),
            length: plan.layout.image_bytes(),
        }),
        0,
        plan.layout.image_bytes(),
    )
    .unwrap();
    // Use the shared request context, so the checker's own checkpoints observe
    // the signal as well as this readback device's I/O checkpoints.
    cx.clone()
        .cancel_with(CancelKind::User, Some("cancel allocation verification"));
    assert!(matches!(volume.check(&cx), Err(FfsError::Cancelled)));
    let mut untouched = [0xCC; 512];
    assert!(matches!(
        device.read_exact_at(&cx, ByteOffset(0), &mut untouched),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(untouched, [0xCC; 512]);
    assert_eq!(read_sector(&file, 0), plan.boot);
    assert_eq!(read_sector(&file, 6), plan.boot);
}

#[test]
fn verification_rejects_each_byte_class_in_both_fat32_boot_extensions() {
    let directory = tempfile::tempdir().unwrap();
    for sector in [2, 8] {
        for offset in [0, 257, 510, 511] {
            let args = options(
                directory
                    .path()
                    .join(format!("extension-{sector}-{offset}.img")),
                FormatKind::Fat32,
            );
            let plan = FormatPlan::prepare(&args).unwrap();
            let cx = Cx::for_testing();
            let file = new_file(&args.image);
            initialize(&cx, &file, &plan, || Ok(())).unwrap();
            let expected = read_sector(&file, sector);
            file.write_all_at(&[expected[offset] ^ 0xFF], sector * 512 + offset as u64)
                .unwrap();
            let error = verify_created(&cx, &file, &plan).unwrap_err();
            assert!(error.to_string().contains(&format!(
                "metadata readback mismatch at byte {}",
                sector * 512
            )));
            assert_eq!(read_sector(&file, 0), plan.boot);
            assert_eq!(read_sector(&file, 6), plan.boot);
        }
    }
}

#[test]
fn verification_stays_on_the_locked_inode_when_the_leaf_path_is_replaced() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("created.img");
    let retained = directory.path().join("retained.img");
    let args = options(path.clone(), FormatKind::Fat16);
    let plan = FormatPlan::prepare(&args).unwrap();
    let cx = Cx::for_testing();
    let file = new_file(&path);
    file.try_lock().unwrap();
    initialize(&cx, &file, &plan, || Ok(())).unwrap();
    let inode = file.metadata().unwrap().ino();
    std::fs::rename(&path, &retained).unwrap();
    let replacement = new_file(&path);
    replacement
        .write_all_at(b"an unrelated replacement", 0)
        .unwrap();
    assert_ne!(replacement.metadata().unwrap().ino(), inode);
    assert!(verify_created(&cx, &file, &plan).is_ok());
    assert_eq!(std::fs::read(&path).unwrap(), b"an unrelated replacement");
    assert_eq!(std::fs::metadata(&retained).unwrap().ino(), inode);
    assert_eq!(read_sector(&file, 0), plan.boot);
}
