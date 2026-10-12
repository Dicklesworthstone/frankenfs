use super::*;
use crate::reader::Directory;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;

fn source_options(directory: &Path, kind: FormatKind) -> FormatArgs {
    let source = directory.join("source");
    fs::create_dir(&source).unwrap();
    let mut args = options(directory.join("populated.img"), kind);
    args.source_dir = Some(source);
    args
}

fn write_source(args: &FormatArgs, name: &str, bytes: &[u8]) {
    let path = args.source_dir.as_ref().unwrap().join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn populated_plan(cx: &Cx, args: &FormatArgs) -> FormatPlan {
    let mut plan = FormatPlan::prepare(args).unwrap();
    plan.prepare_source(cx, args).unwrap();
    plan
}

fn read_native(cx: &Cx, volume: &FatVolume, path: &str) -> Vec<u8> {
    let entry = volume.resolve(cx, path).unwrap().unwrap();
    let chain = volume.file_chain(cx, &entry).unwrap();
    volume.read(cx, &chain, 0, chain.size as usize).unwrap()
}

fn assert_unpublished(file: &File, kind: FormatKind) {
    assert_eq!(&read_sector(file, 0)[510..], &[0, 0]);
    if kind == FormatKind::Fat32 {
        assert_eq!(&read_sector(file, 6)[510..], &[0, 0]);
    }
}

#[test]
fn source_cli_preserves_existing_geometry_and_reports_native_payload_verification() {
    let parsed = Cli::try_parse_from([
        "ffs-fat",
        "format",
        "fresh.img",
        "--kind",
        "fat16",
        "--size-mib",
        "4",
        "--source-dir",
        "tree",
    ])
    .unwrap();
    let Command::Format { options } = parsed.command else {
        panic!("expected format")
    };
    assert_eq!(options.source_dir.as_deref(), Some(Path::new("tree")));
    assert_eq!(options.size_mib, 4);
    for kind in [FormatKind::Fat16, FormatKind::Fat32] {
        let temporary = tempfile::tempdir().unwrap();
        let args = source_options(temporary.path(), kind);
        write_source(&args, "A.BIN", &[0xA5; 600]);
        write_source(&args, "DIR/B.BIN", b"B");
        write_source(&args, "EMPTY.BIN", b"");
        let cx = Cx::for_testing();
        let report = create(&cx, &args).unwrap();
        assert_eq!(report["copied_files"], 3);
        assert_eq!(report["copied_directories"], 2);
        assert_eq!(report["copied_bytes"], 601);
        assert_eq!(report["payload_verification"], "sha256_via_native_reader");
        assert_eq!(
            report["source_directory"],
            args.source_dir
                .as_ref()
                .unwrap()
                .canonicalize()
                .unwrap()
                .display()
                .to_string()
        );
        assert_eq!(report["verification"]["files"], 3);
        assert_eq!(report["verification"]["directories"], 2);
        assert_eq!(report["verification"]["clean"], true);
        assert_eq!(report["verification"]["complete"], true);
        assert_eq!(report["verification"]["namespace_complete"], true);
        assert_eq!(report["verification"]["lost_clusters"], 0);
        assert_eq!(report["durability"], "file_and_parent_synced");
        let volume = FatVolume::open(&cx, &args.image, 0, None).unwrap();
        assert_eq!(read_native(&cx, &volume, "/A.BIN"), [0xA5; 600]);
        assert_eq!(read_native(&cx, &volume, "/DIR/B.BIN"), b"B");
        assert!(read_native(&cx, &volume, "/EMPTY.BIN").is_empty());
        assert_eq!(
            fs::read(args.source_dir.as_ref().unwrap().join("A.BIN")).unwrap(),
            [0xA5; 600]
        );
    }
}

#[test]
fn populated_native_fats_dots_and_slack_match_independent_constants() {
    for kind in [FormatKind::Fat16, FormatKind::Fat32] {
        let temporary = tempfile::tempdir().unwrap();
        let args = source_options(temporary.path(), kind);
        write_source(&args, "A.BIN", &[0xA5; 600]);
        write_source(&args, "DIR/B.BIN", b"B");
        write_source(&args, "EMPTY.BIN", b"");
        let cx = Cx::for_testing();
        let report = create(&cx, &args).unwrap();
        let file = File::open(&args.image).unwrap();
        let boot = read_sector(&file, 0);
        let fat_start = u64::from(short(&boot, 14));
        let fat_sectors = if kind == FormatKind::Fat16 {
            u32::from(short(&boot, 22))
        } else {
            long(&boot, 36)
        };
        let root_sector = fat_start + 2 * u64::from(fat_sectors);
        let data_sector = root_sector + if kind == FormatKind::Fat16 { 32 } else { 0 };
        let mut first = vec![0_u8; fat_sectors as usize * 512];
        let mut second = vec![0_u8; first.len()];
        file.read_exact_at(&mut first, fat_start * 512).unwrap();
        file.read_exact_at(&mut second, (fat_start + u64::from(fat_sectors)) * 512)
            .unwrap();
        assert_eq!(first, second);
        let expected: &[u32] = if kind == FormatKind::Fat16 {
            &[0xFFF8, 0xFFFF, 3, 0xFFFF, 0xFFFF, 0xFFFF]
        } else {
            &[
                0x0FFF_FFF8,
                0x0FFF_FFFF,
                0x0FFF_FFFF,
                4,
                0x0FFF_FFFF,
                0x0FFF_FFFF,
                0x0FFF_FFFF,
            ]
        };
        let width = if kind == FormatKind::Fat16 { 2 } else { 4 };
        for (index, value) in expected.iter().enumerate() {
            assert_eq!(
                &first[index * width..(index + 1) * width],
                &value.to_le_bytes()[..width]
            );
        }
        assert!(
            first[expected.len() * width..]
                .iter()
                .all(|byte| *byte == 0)
        );
        let allocated = if kind == FormatKind::Fat16 { 4 } else { 5 };
        assert_eq!(report["verification"]["allocated_clusters"], allocated);
        assert_eq!(report["verification"]["referenced_clusters"], allocated);
        assert_eq!(report["verification"]["preallocated_clusters"], 0);
        let root = read_sector(&file, root_sector);
        assert_eq!(&root[32..43], b"A       BIN");
        assert_eq!(&root[64..75], b"DIR        ");
        assert_eq!(&root[96..107], b"EMPTY   BIN");
        assert_eq!(long(&root, 32 + 28), 600);
        assert_eq!(short(&root, 96 + 26), 0);
        assert_eq!(long(&root, 96 + 28), 0);
        let directory_cluster = if kind == FormatKind::Fat16 { 4 } else { 5 };
        let directory_sector = data_sector + directory_cluster - 2;
        let directory = read_sector(&file, directory_sector);
        assert_eq!(&directory[..11], b".          ");
        assert_eq!(&directory[32..43], b"..         ");
        assert_eq!(directory[11], 0x10);
        assert_eq!(directory[43], 0x10);
        assert_eq!(u64::from(short(&directory, 26)), directory_cluster);
        assert_eq!(
            short(&directory, 32 + 26),
            0,
            "root parent is zero even on FAT32"
        );
        assert_eq!(long(&directory, 28), 0);
        assert_eq!(long(&directory, 60), 0);
        assert_eq!(&directory[64..75], b"B       BIN");
        assert!(directory[96..].iter().all(|byte| *byte == 0));
        let file_cluster = if kind == FormatKind::Fat16 { 2 } else { 3 };
        let tail = read_sector(&file, data_sector + file_cluster - 2 + 1);
        assert_eq!(&tail[..88], &[0xA5; 88]);
        assert!(tail[88..].iter().all(|byte| *byte == 0));
        let b_cluster = if kind == FormatKind::Fat16 { 5 } else { 6 };
        let b_sector = read_sector(&file, data_sector + b_cluster - 2);
        assert_eq!(b_sector[0], b'B');
        assert!(b_sector[1..].iter().all(|byte| *byte == 0));
        if kind == FormatKind::Fat32 {
            let info = read_sector(&file, 1);
            assert_eq!(info, read_sector(&file, 7));
            assert_eq!(
                u64::from(long(&info, 488)),
                report["data_clusters"].as_u64().unwrap() - 5
            );
            assert_eq!(long(&info, 492), 7);
            for sector in 0..3 {
                assert_eq!(read_sector(&file, sector), read_sector(&file, sector + 6));
            }
        }
    }
}

#[test]
fn unicode_names_short_case_flags_and_reserved_aliases_round_trip_exactly() {
    for kind in [FormatKind::Fat16, FormatKind::Fat32] {
        let temporary = tempfile::tempdir().unwrap();
        let args = source_options(temporary.path(), kind);
        let names = [
            "LONGNA~1.TXT",
            "Longname one.txt",
            "Longname two.txt",
            "lower.txt",
            "UPPER.BIN",
            "Mixed.TxT",
            "café.txt",
            "雪だるま.txt",
            "😀.bin",
            ".hidden",
            "123456789ABCD",
            "123456789ABCDE",
        ];
        for (index, name) in names.iter().enumerate() {
            write_source(&args, name, &[index as u8; 17]);
        }
        let longest = "x".repeat(255);
        write_source(&args, &longest, b"maximum component");
        let cx = Cx::for_testing();
        create(&cx, &args).unwrap();
        let volume = FatVolume::open(&cx, &args.image, 0, None).unwrap();
        let entries: BTreeMap<_, _> = volume
            .list(&cx, Directory::Root)
            .unwrap()
            .into_iter()
            .map(|entry| (entry.name().unwrap(), entry))
            .collect();
        assert_eq!(entries.len(), names.len() + 1);
        for (index, name) in names.iter().enumerate() {
            assert_eq!(
                read_native(&cx, &volume, &format!("/{name}")),
                [index as u8; 17]
            );
        }
        assert_eq!(
            read_native(&cx, &volume, &format!("/{longest}")),
            b"maximum component"
        );
        assert_eq!(entries["LONGNA~1.TXT"].native.short_name, *b"LONGNA~1TXT");
        assert_eq!(
            entries["Longname one.txt"].native.short_name,
            *b"LONGNA~2TXT"
        );
        assert_eq!(
            entries["Longname two.txt"].native.short_name,
            *b"LONGNA~3TXT"
        );
        assert_eq!(entries["lower.txt"].native.short_name, *b"LOWER   TXT");
        assert_eq!(entries["lower.txt"].native.case_flags, 0x18);
        assert!(entries["lower.txt"].native.long_name.is_none());
        assert_eq!(entries["UPPER.BIN"].native.case_flags, 0);
        assert!(entries["UPPER.BIN"].native.long_name.is_none());
        assert_eq!(entries["Mixed.TxT"].native.short_name, *b"MIXED   TXT");
        assert_eq!(
            entries["Mixed.TxT"].native.long_name.as_deref(),
            Some("Mixed.TxT".encode_utf16().collect::<Vec<_>>().as_slice())
        );
        let file = File::open(&args.image).unwrap();
        for (name, short_name, checksum) in [
            ("123456789ABCD", *b"123456~1   ", 205_u8),
            ("123456789ABCDE", *b"123456~2   ", 237),
            (longest.as_str(), *b"XXXXXX~1   ", 33),
        ] {
            let entry = &entries[name];
            assert_eq!(entry.native.short_name, short_name);
            let units: Vec<_> = name.encode_utf16().collect();
            let count = units.len().div_ceil(13);
            let mut raw = vec![0; count * 32];
            file.read_exact_at(&mut raw, entry.offset - count as u64 * 32)
                .unwrap();
            // Fixed native checksum vectors, independent of the encoder helper.
            for (slot, bytes) in raw.as_chunks::<32>().0.iter().enumerate() {
                let ordinal = count - slot;
                assert_eq!(bytes[0], ordinal as u8 | if slot == 0 { 0x40 } else { 0 });
                assert_eq!(bytes[11], 0x0F);
                assert_eq!(bytes[12], 0);
                assert_eq!(bytes[13], checksum);
                assert_eq!(short(bytes, 26), 0);
                for (within, at) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
                    .into_iter()
                    .enumerate()
                {
                    let position = (ordinal - 1) * 13 + within;
                    let expected = if position < units.len() {
                        units[position]
                    } else if position == units.len() {
                        0
                    } else {
                        0xFFFF
                    };
                    assert_eq!(short(bytes, at), expected);
                }
            }
        }
    }
}

#[test]
fn root_and_subdirectory_growth_keep_complete_native_chains() {
    let temporary = tempfile::tempdir().unwrap();
    let args = source_options(temporary.path(), FormatKind::Fat32);
    for index in 0..40 {
        write_source(
            &args,
            &format!("Root long filename {index:02}.txt"),
            &[index as u8; 37],
        );
        write_source(
            &args,
            &format!("nested/Subdirectory long filename {index:02}.txt"),
            &[index as u8; 41],
        );
    }
    fs::create_dir(args.source_dir.as_ref().unwrap().join("nested/empty")).unwrap();
    let cx = Cx::for_testing();
    let report = create(&cx, &args).unwrap();
    assert_eq!(report["copied_files"], 80);
    assert_eq!(report["copied_directories"], 3);
    let volume = FatVolume::open(&cx, &args.image, 0, None).unwrap();
    assert!(volume.directory_size(&cx, Directory::Root).unwrap() > 512);
    let nested = volume
        .resolve(&cx, "/nested")
        .unwrap()
        .unwrap()
        .directory()
        .unwrap();
    assert!(volume.directory_size(&cx, nested).unwrap() > 512);
    assert_eq!(volume.list(&cx, Directory::Root).unwrap().len(), 41);
    assert_eq!(volume.list(&cx, nested).unwrap().len(), 41);
    for index in 0..40 {
        assert_eq!(
            read_native(&cx, &volume, &format!("/Root long filename {index:02}.txt")),
            [index as u8; 37]
        );
        assert_eq!(
            read_native(
                &cx,
                &volume,
                &format!("/nested/Subdirectory long filename {index:02}.txt")
            ),
            [index as u8; 41]
        );
    }
    let empty = volume.resolve(&cx, "/nested/empty").unwrap().unwrap();
    assert!(
        volume
            .list(&cx, empty.directory().unwrap())
            .unwrap()
            .is_empty()
    );
    let file = File::open(&args.image).unwrap();
    let mut dot_entries = [0_u8; 64];
    file.read_exact_at(
        &mut dot_entries,
        volume
            .geometry
            .cluster_offset(empty.native.first_cluster)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(&dot_entries[32..43], b"..         ");
    let parent_cluster = volume
        .resolve(&cx, "/nested")
        .unwrap()
        .unwrap()
        .native
        .first_cluster;
    assert_eq!(
        u32::from(short(&dot_entries, 58)) | (u32::from(short(&dot_entries, 52)) << 16),
        parent_cluster
    );
}

#[test]
fn fat16_fixed_root_capacity_counts_all_lfn_and_label_slots_before_creation() {
    let temporary = tempfile::tempdir().unwrap();
    let mut args = source_options(temporary.path(), FormatKind::Fat16);
    args.label = None;
    for index in 0..512 {
        write_source(&args, &format!("F{index:07}"), b"");
    }
    let cx = Cx::for_testing();
    let report = create(&cx, &args).unwrap();
    assert_eq!(report["copied_files"], 512);
    assert_eq!(report["verification"]["allocated_clusters"], 0);
    let volume = FatVolume::open(&cx, &args.image, 0, None).unwrap();
    assert_eq!(volume.list(&cx, Directory::Root).unwrap().len(), 512);
    args.image = temporary.path().join("label-overflow.img");
    args.label = Some("LABEL".into());
    let error = create(&cx, &args).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<FfsError>(),
        Some(FfsError::NoSpace)
    ));
    assert!(format!("{error:#}").contains("requires 513 native slots; limit is 512"));
    assert!(!args.image.exists());
    args.label = None;
    write_source(&args, "EXTRA.TXT", b"");
    args.image = temporary.path().join("entry-overflow.img");
    let error = create(&cx, &args).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<FfsError>(),
        Some(FfsError::NoSpace)
    ));
    assert!(!args.image.exists());

    let long_tree = tempfile::tempdir().unwrap();
    let mut long_args = source_options(long_tree.path(), FormatKind::Fat16);
    long_args.label = None;
    for index in 0..25 {
        write_source(&long_args, &format!("{index:03}{}", "x".repeat(252)), b"");
    }
    let error = create(&cx, &long_args).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<FfsError>(),
        Some(FfsError::NoSpace)
    ));
    assert!(format!("{error:#}").contains("requires 525 native slots"));
    assert!(!long_args.image.exists());
}

#[test]
fn data_enospc_and_native_file_size_limits_precede_destination_creation() {
    let temporary = tempfile::tempdir().unwrap();
    let args = source_options(temporary.path(), FormatKind::Fat16);
    let huge = args.source_dir.as_ref().unwrap().join("large.bin");
    new_file(&huge).set_len(4 * 1_048_576).unwrap();
    let cx = Cx::for_testing();
    let error = create(&cx, &args).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<FfsError>(),
        Some(FfsError::NoSpace)
    ));
    assert!(format!("{error:#}").contains("does not fit the image's native data clusters"));
    assert!(!args.image.exists());

    let oversized = tempfile::tempdir().unwrap();
    let args = source_options(oversized.path(), FormatKind::Fat32);
    let path = args.source_dir.as_ref().unwrap().join("too-large.bin");
    new_file(&path).set_len(u64::from(u32::MAX) + 1).unwrap();
    let error = create(&cx, &args).unwrap_err();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::FileTooLarge
    );
    assert!(format!("{error:#}").contains("4294967295-byte file limit"));
    assert!(!args.image.exists());
}

#[test]
fn source_case_device_invalid_and_non_utf8_names_are_explicit_preflight_refusals() {
    for names in [
        vec!["Readme.txt", "README.TXT"],
        vec!["é.txt", "É.txt"],
        vec!["straße.txt", "STRASSE.TXT"],
        vec!["trailing."],
        vec!["trailing "],
        vec!["bad:name"],
        vec!["bad\\name"],
        vec!["CON.txt"],
        vec!["com1"],
        vec!["LPT².log"],
        vec!["control\u{1}.txt"],
        vec!["padding\u{FFFF}.txt"],
    ] {
        let temporary = tempfile::tempdir().unwrap();
        let args = source_options(temporary.path(), FormatKind::Fat16);
        for name in &names {
            write_source(&args, name, b"untouched");
        }
        let error = create(&Cx::for_testing(), &args).unwrap_err();
        let evidence = format!("{error:#}");
        assert!(
            evidence.contains("source-tree preflight failed"),
            "{names:?}: {evidence}"
        );
        assert!(
            evidence.contains("creation case profile")
                || evidence.contains("creation profile")
                || evidence.contains("reserved DOS device"),
            "{evidence}"
        );
        assert!(!args.image.exists());
        for name in names {
            assert_eq!(
                fs::read(args.source_dir.as_ref().unwrap().join(name)).unwrap(),
                b"untouched"
            );
        }
    }
    let temporary = tempfile::tempdir().unwrap();
    let args = source_options(temporary.path(), FormatKind::Fat16);
    let native = std::ffi::OsString::from_vec(vec![b'n', 0xFF]);
    fs::write(args.source_dir.as_ref().unwrap().join(native), b"raw name").unwrap();
    let error = create(&Cx::for_testing(), &args).unwrap_err();
    assert!(format!("{error:#}").contains("lossless UTF-8"));
    assert!(!args.image.exists());
}

#[test]
fn symlink_special_sources_and_destinations_inside_sources_are_refused() {
    let temporary = tempfile::tempdir().unwrap();
    let mut args = source_options(temporary.path(), FormatKind::Fat16);
    let source = args.source_dir.clone().unwrap();
    let outside = temporary.path().join("outside");
    fs::write(&outside, b"outside bytes").unwrap();
    symlink(&outside, source.join("link")).unwrap();
    let error = create(&Cx::for_testing(), &args).unwrap_err();
    assert!(format!("{error:#}").contains("source symlink is unsupported"));
    assert!(!args.image.exists());
    assert_eq!(fs::read(&outside).unwrap(), b"outside bytes");
    let link = temporary.path().join("source-link");
    symlink(&source, &link).unwrap();
    args.source_dir = Some(link);
    let error = create(&Cx::for_testing(), &args).unwrap_err();
    assert!(format!("{error:#}").contains("not a symlink or special file"));
    assert!(!args.image.exists());

    let special = tempfile::tempdir().unwrap();
    let args = source_options(special.path(), FormatKind::Fat16);
    let socket_path = args.source_dir.as_ref().unwrap().join("socket");
    let _socket = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    let error = create(&Cx::for_testing(), &args).unwrap_err();
    assert!(format!("{error:#}").contains("source special file is unsupported"));
    assert!(!args.image.exists());

    let internal = tempfile::tempdir().unwrap();
    let mut args = source_options(internal.path(), FormatKind::Fat32);
    args.image = args.source_dir.as_ref().unwrap().join("recursive.img");
    let error = create(&Cx::for_testing(), &args).unwrap_err();
    assert!(format!("{error:#}").contains("must be outside --source-dir"));
    assert!(!args.image.exists());
}

#[test]
fn host_hardlinks_become_independent_native_chains_and_empty_sources_match_empty_format() {
    let temporary = tempfile::tempdir().unwrap();
    let args = source_options(temporary.path(), FormatKind::Fat16);
    write_source(&args, "first.bin", &[0x81; 1025]);
    fs::hard_link(
        args.source_dir.as_ref().unwrap().join("first.bin"),
        args.source_dir.as_ref().unwrap().join("second.bin"),
    )
    .unwrap();
    let cx = Cx::for_testing();
    let report = create(&cx, &args).unwrap();
    assert_eq!(report["copied_bytes"], 2050);
    assert_eq!(report["verification"]["allocated_clusters"], 6);
    let volume = FatVolume::open(&cx, &args.image, 0, None).unwrap();
    let first = volume.resolve(&cx, "/first.bin").unwrap().unwrap();
    let second = volume.resolve(&cx, "/second.bin").unwrap().unwrap();
    assert_ne!(first.native.first_cluster, second.native.first_cluster);
    assert_eq!(read_native(&cx, &volume, "/first.bin"), [0x81; 1025]);
    assert_eq!(read_native(&cx, &volume, "/second.bin"), [0x81; 1025]);

    for kind in [FormatKind::Fat16, FormatKind::Fat32] {
        let temporary = tempfile::tempdir().unwrap();
        let populated = source_options(temporary.path(), kind);
        let mut empty = options(temporary.path().join("empty.img"), kind);
        empty.label = populated.label.clone();
        empty.serial = populated.serial;
        let plan = populated_plan(&cx, &populated);
        let empty_plan = FormatPlan::prepare(&empty).unwrap();
        assert_eq!(
            plan.metadata_sectors()
                .map(|sector| (sector.offset, sector.bytes))
                .collect::<Vec<_>>(),
            empty_plan
                .metadata_sectors()
                .map(|sector| (sector.offset, sector.bytes))
                .collect::<Vec<_>>()
        );
        create(&cx, &populated).unwrap();
        create(&cx, &empty).unwrap();
        let left = File::open(&populated.image).unwrap();
        let right = File::open(&empty.image).unwrap();
        let mut a = [0_u8; 64 * 1024];
        let mut b = [0_u8; 64 * 1024];
        for offset in (0..plan.layout.image_bytes()).step_by(a.len()) {
            left.read_exact_at(&mut a, offset).unwrap();
            right.read_exact_at(&mut b, offset).unwrap();
            assert_eq!(a, b);
        }
    }
}

#[test]
fn source_replacement_and_content_changes_are_detected_before_either_bpb() {
    for kind in [FormatKind::Fat16, FormatKind::Fat32] {
        for replacement in [false, true] {
            let temporary = tempfile::tempdir().unwrap();
            let args = source_options(temporary.path(), kind);
            write_source(&args, "payload.bin", &[0x61; 1025]);
            let cx = Cx::for_testing();
            let plan = populated_plan(&cx, &args);
            let source = args.source_dir.as_ref().unwrap().join("payload.bin");
            if replacement {
                fs::rename(&source, temporary.path().join("retained-original.bin")).unwrap();
                fs::write(&source, [0x61; 1025]).unwrap();
            } else {
                OpenOptions::new()
                    .write(true)
                    .open(&source)
                    .unwrap()
                    .write_all_at(&[0x62; 512], 0)
                    .unwrap();
            }
            let file = new_file(&args.image);
            let error = initialize(&cx, &file, &plan, || Ok(())).unwrap_err();
            assert!(format!("{error:#}").contains("source changed during image creation"));
            assert!(format!("{error:#}").contains("incomplete before boot publication"));
            assert_unpublished(&file, kind);
            assert!(args.image.is_file());
            if replacement {
                assert_eq!(
                    fs::read(temporary.path().join("retained-original.bin")).unwrap(),
                    [0x61; 1025]
                );
            }
        }
    }
}

struct SourceChangingTarget {
    file: File,
    source: PathBuf,
    directory_change: bool,
    changed: Cell<bool>,
}

impl ImageTarget for SourceChangingTarget {
    fn resize(&self, length: u64) -> io::Result<()> {
        self.file.set_len(length)
    }
    fn write_sector(&self, offset: u64, bytes: &[u8; 512]) -> io::Result<()> {
        self.file.write_all_at(bytes, offset)?;
        if !self.changed.replace(true) {
            if self.directory_change {
                fs::write(&self.source, b"new sibling")?;
            } else {
                // Beyond the already buffered first 64 KiB: the next copy
                // chunk must disagree with the preflight payload digest.
                OpenOptions::new()
                    .write(true)
                    .open(&self.source)?
                    .write_all_at(&[0x99; 512], 70_000)?;
            }
        }
        Ok(())
    }
    fn flush(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}

#[test]
fn source_changes_during_copy_or_directory_preparation_leave_no_admitted_bpb() {
    for directory_change in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        let args = source_options(temporary.path(), FormatKind::Fat32);
        write_source(&args, "payload.bin", &[0x51; 131_073]);
        let cx = Cx::for_testing();
        let plan = populated_plan(&cx, &args);
        let target = SourceChangingTarget {
            file: new_file(&args.image),
            source: args.source_dir.as_ref().unwrap().join(if directory_change {
                "new.txt"
            } else {
                "payload.bin"
            }),
            directory_change,
            changed: Cell::new(false),
        };
        let error = initialize(&cx, &target, &plan, || Ok(())).unwrap_err();
        let evidence = format!("{error:#}");
        assert!(evidence.contains("incomplete before boot publication"));
        assert!(
            evidence.contains("source") && evidence.contains("changed"),
            "{evidence}"
        );
        if !directory_change {
            assert!(evidence.contains("source payload changed since preflight"));
        }
        assert!(target.changed.get());
        assert_unpublished(&target.file, FormatKind::Fat32);
    }
}

#[test]
fn payload_and_extra_metadata_failures_and_cancellation_are_unpublished() {
    for kind in [FormatKind::Fat16, FormatKind::Fat32] {
        let temporary = tempfile::tempdir().unwrap();
        let args = source_options(temporary.path(), kind);
        write_source(&args, "payload.bin", &[0x71; 140_001]);
        write_source(&args, "nested/child.txt", b"child");
        let plan = populated_plan(&Cx::for_testing(), &args);
        assert!(plan.preparation_sectors().count() > plan.before_boot.len() + 2);
        let payload_sectors = 140_001_usize.div_ceil(512) + 1;
        let before_flush = 1 + payload_sectors + plan.preparation_sectors().count();
        let positions = [
            1,
            2,
            128,
            payload_sectors,
            1 + payload_sectors + plan.before_boot.len(),
            before_flush - 1,
            before_flush,
        ];
        for cancel in [false, true] {
            for position in positions {
                let path = temporary
                    .path()
                    .join(format!("{kind:?}-{cancel}-{position}.img"));
                let cx = Cx::for_testing();
                let target = FaultTarget {
                    file: new_file(&path),
                    events: RefCell::new(Vec::new()),
                    calls: Cell::new(0),
                    fail_at: (!cancel).then_some(position),
                    cancel_at: cancel.then_some(position),
                    cx: cx.clone(),
                };
                let error = initialize(&cx, &target, &plan, || target.event(Event::ParentSync))
                    .unwrap_err();
                let evidence = format!("{error:#}");
                assert!(
                    evidence.contains("incomplete before boot publication"),
                    "{position}: {evidence}"
                );
                if cancel {
                    assert!(matches!(
                        error.downcast_ref::<FfsError>(),
                        Some(FfsError::Cancelled)
                    ));
                } else {
                    assert!(evidence.contains("injected creation I/O failure"));
                }
                assert_unpublished(&target.file, kind);
                assert!(!target.events.borrow().contains(&Event::ParentSync));
                assert!(path.is_file());
            }
        }
    }
}

#[test]
fn native_payload_readback_rejects_data_corruption_even_when_allocation_is_clean() {
    for kind in [FormatKind::Fat16, FormatKind::Fat32] {
        let temporary = tempfile::tempdir().unwrap();
        let args = source_options(temporary.path(), kind);
        write_source(&args, "nested/payload.bin", &[0x2A; 140_001]);
        let cx = Cx::for_testing();
        let plan = populated_plan(&cx, &args);
        let file = new_file(&args.image);
        initialize(&cx, &file, &plan, || Ok(())).unwrap();
        let before = verify_created(&cx, &file, &plan).unwrap();
        assert_eq!(before["files"], 1);
        assert_eq!(before["directories"], 2);
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
        let entry = volume.resolve(&cx, "/nested/payload.bin").unwrap().unwrap();
        let offset = volume
            .geometry
            .cluster_offset(entry.native.first_cluster)
            .unwrap();
        file.write_all_at(&[0x7C], offset + 70_000).unwrap();
        assert!(
            volume.check(&cx).unwrap().clean,
            "allocation-only checking cannot detect payload corruption"
        );
        let error = verify_created(&cx, &file, &plan).unwrap_err();
        assert!(format!("{error:#}").contains("native payload SHA-256 mismatch"));
        assert_eq!(&read_sector(&file, 0)[510..], &[0x55, 0xAA]);
        assert!(args.image.is_file());
        assert_eq!(
            fs::read(args.source_dir.as_ref().unwrap().join("nested/payload.bin")).unwrap(),
            [0x2A; 140_001]
        );
    }
}

#[test]
fn populated_verification_retains_the_created_inode_and_is_cancellable_after_publication() {
    let temporary = tempfile::tempdir().unwrap();
    let args = source_options(temporary.path(), FormatKind::Fat32);
    write_source(&args, "payload.bin", &[0x42; 1500]);
    let cx = Cx::for_testing();
    let plan = populated_plan(&cx, &args);
    let file = new_file(&args.image);
    file.try_lock().unwrap();
    initialize(&cx, &file, &plan, || Ok(())).unwrap();
    let created_inode = file.metadata().unwrap().ino();
    let moved = temporary.path().join("created-inode.img");
    fs::rename(&args.image, &moved).unwrap();
    fs::write(&args.image, b"replacement path").unwrap();
    assert_eq!(verify_created(&cx, &file, &plan).unwrap()["files"], 1);
    assert_eq!(file.metadata().unwrap().ino(), created_inode);
    assert_eq!(fs::read(&args.image).unwrap(), b"replacement path");
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    let error = verify_created(&cancelled, &file, &plan).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<FfsError>(),
        Some(FfsError::Cancelled)
    ));
    assert_eq!(&read_sector(&file, 0)[510..], &[0x55, 0xAA]);
    assert_eq!(fs::metadata(moved).unwrap().ino(), created_inode);
}

#[test]
fn bounded_source_depth_refuses_before_creating_the_output() {
    let temporary = tempfile::tempdir().unwrap();
    let args = source_options(temporary.path(), FormatKind::Fat16);
    let mut path = args.source_dir.clone().unwrap();
    for _ in 0..64 {
        path.push("d");
        fs::create_dir(&path).unwrap();
    }
    fs::write(path.join("too-deep.txt"), b"retained").unwrap();
    let error = create(&Cx::for_testing(), &args).unwrap_err();
    assert!(format!("{error:#}").contains("64-level population budget"));
    assert!(!args.image.exists());
}
