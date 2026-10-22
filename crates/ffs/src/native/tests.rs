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
        assert!(opened.ntfs_volume().is_none());
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
        for indexed_lookup in [false, true] {
            let mismatched = ReadOnlyOpenOptions {
                backend: ReadOnlyBackend::Ntfs { indexed_lookup },
                ..ReadOnlyOpenOptions::default()
            };
            assert!(matches!(
                open_read_only(&cx, &image, &mismatched),
                Err(FfsError::Format(_))
            ));
        }
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
            root: candidate,
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

/// Separate native-producer proof from the constructed-image controls above.
/// Explicit invocation is required; missing tools fail rather than skip cases.
#[test]
#[ignore = "requires dosfstools, mtools and ntfs-3g; retains native images and command logs"]
fn native_producer_interchange_reads_and_refuses_mutation_through_public_facade() {
    use std::io::Write;
    use std::process::Command;

    fn command(root: &Path, label: &str, tool: &str, arguments: &[&OsStr]) -> Vec<u8> {
        // A caller may supply an isolated, provenance-checked mtools directory.
        // Other tools retain ordinary executable lookup; no substitute oracle.
        let executable = if matches!(tool, "mcopy" | "mmd") {
            std::env::var_os("FFS_NATIVE_ORACLE_BIN")
                .map_or_else(|| PathBuf::from(tool), |bin| PathBuf::from(bin).join(tool))
        } else {
            PathBuf::from(tool)
        };
        let output = Command::new(&executable)
            .args(arguments)
            .output()
            .unwrap_or_else(|error| {
                panic!("native oracle {executable:?} could not execute: {error}")
            });
        fs::write(root.join(format!("{label}.stdout")), &output.stdout).unwrap();
        fs::write(root.join(format!("{label}.stderr")), &output.stderr).unwrap();
        fs::write(
            root.join(format!("{label}.command")),
            format!("{executable:?} {arguments:?}\nstatus={}\n", output.status),
        )
        .unwrap();
        assert!(
            output.status.success(),
            "native oracle {label} failed; see {root:?}"
        );
        output.stdout
    }

    fn record_offset(cx: &Cx, volume: &ffs_ntfs::NtfsVolume, number: u32) -> usize {
        use ffs_ondisk::ntfs::{DATA, NtfsValue, decode_mapping_pairs};

        // Locate planted damage through the actual native MFT mapping, never
        // assume the formatter placed all FILE records in one physical run.
        let record = volume.record(cx, 0, None).unwrap();
        let attribute = record
            .attributes()
            .unwrap()
            .into_iter()
            .find(|attribute| attribute.kind == DATA && attribute.name.is_empty())
            .unwrap();
        let NtfsValue::NonResident(value) = attribute.value else {
            panic!("native MFT DATA must be nonresident");
        };
        let runs = decode_mapping_pairs(
            value.mapping_pairs,
            value.first_vcn,
            value.last_vcn,
            volume.geometry.cluster_count(),
        )
        .unwrap();
        let cluster = u64::from(volume.geometry.cluster_bytes());
        let logical = u64::from(number) * u64::from(volume.geometry.record_bytes());
        let run = runs
            .iter()
            .find(|run| {
                logical >= run.vcn * cluster
                    && logical + 4 <= (run.vcn + run.clusters) * cluster
            })
            .unwrap();
        usize::try_from(run.lcn.unwrap() * cluster + logical - run.vcn * cluster).unwrap()
    }

    let root = tempfile::Builder::new()
        .prefix("ffs-facade-native-")
        .tempdir()
        .unwrap()
        .keep();
    println!("retained native facade evidence: {}", root.display());
    let cx = Cx::for_testing();
    let payload: Vec<u8> = (0_u32..131_111)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect();
    let source = root.join("source.bin");
    fs::write(&source, &payload).unwrap();
    let named_payload = b"independent native named DATA\0\xff";
    let named_source = root.join("named.bin");
    fs::write(&named_source, named_payload).unwrap();
    for (kind, expected) in [
        ("fat16", FsFormatKind::Fat16),
        ("fat32", FsFormatKind::Fat32),
        ("ntfs", FsFormatKind::Ntfs),
    ] {
        let directory = root.join(kind);
        fs::create_dir(&directory).unwrap();
        let image = directory.join("native.img");
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&image)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();
        let name = OsStr::new("Native payload.bin");
        if kind == "ntfs" {
            // Force is confined to this new regular scratch file.
            command(
                &directory,
                "format",
                "mkntfs",
                &[
                    OsStr::new("-F"),
                    OsStr::new("-Q"),
                    OsStr::new("-s"),
                    OsStr::new("512"),
                    OsStr::new("-c"),
                    OsStr::new("4096"),
                    image.as_os_str(),
                ],
            );
            command(
                &directory,
                "populate",
                "ntfscp",
                &[
                    image.as_os_str(),
                    source.as_os_str(),
                    OsStr::new("/Native payload.bin"),
                ],
            );
            command(
                &directory,
                "populate-stream",
                "ntfscp",
                &[
                    OsStr::new("-N"),
                    OsStr::new("note"),
                    image.as_os_str(),
                    named_source.as_os_str(),
                    OsStr::new("/Native payload.bin"),
                ],
            );
            command(
                &directory,
                "populate-unrelated",
                "ntfscp",
                &[
                    image.as_os_str(),
                    named_source.as_os_str(),
                    OsStr::new("/Unrelated.bin"),
                ],
            );
            assert_eq!(
                command(
                    &directory,
                    "reference-stream",
                    "ntfscat",
                    &[
                        OsStr::new("-n"),
                        OsStr::new("note"),
                        image.as_os_str(),
                        OsStr::new("/Native payload.bin"),
                    ]
                ),
                named_payload
            );
            assert_eq!(
                command(
                    &directory,
                    "reference",
                    "ntfscat",
                    &[image.as_os_str(), OsStr::new("/Native payload.bin"),]
                ),
                payload
            );
        } else {
            command(
                &directory,
                "format",
                "mkfs.fat",
                &[
                    OsStr::new("-F"),
                    OsStr::new(if kind == "fat16" { "16" } else { "32" }),
                    image.as_os_str(),
                ],
            );
            command(
                &directory,
                "populate",
                "mcopy",
                &[
                    OsStr::new("-i"),
                    image.as_os_str(),
                    source.as_os_str(),
                    OsStr::new("::/Native payload.bin"),
                ],
            );
            let reference = directory.join("reference.bin");
            command(
                &directory,
                "reference",
                "mcopy",
                &[
                    OsStr::new("-i"),
                    image.as_os_str(),
                    OsStr::new("::/Native payload.bin"),
                    reference.as_os_str(),
                ],
            );
            assert_eq!(fs::read(reference).unwrap(), payload);
            command(
                &directory,
                "check-before",
                "fsck.fat",
                &[OsStr::new("-n"), image.as_os_str()],
            );
        }
        let native = fs::read(&image).unwrap();
        let mut container = vec![0xA7; 4096];
        container.extend_from_slice(&native);
        container.extend_from_slice(&[0xD3; 8192]);
        let bounded = directory.join("bounded.img");
        fs::write(&bounded, &container).unwrap();
        let mut views = vec![
            (&image, 0, None, ReadOnlyBackend::Auto),
            (
                &bounded,
                4096,
                Some(native.len() as u64),
                ReadOnlyBackend::Auto,
            ),
        ];
        if kind == "ntfs" {
            for indexed_lookup in [false, true] {
                views.push((&image, 0, None, ReadOnlyBackend::Ntfs { indexed_lookup }));
                views.push((
                    &bounded,
                    4096,
                    Some(native.len() as u64),
                    ReadOnlyBackend::Ntfs { indexed_lookup },
                ));
            }
        }
        for (path, offset, length, backend) in views {
            let opened = open_read_only(
                &cx,
                path,
                &ReadOnlyOpenOptions {
                    offset,
                    length,
                    backend,
                    ..ReadOnlyOpenOptions::default()
                },
            )
            .unwrap();
            assert_eq!(opened.format, expected);
            if kind == "ntfs" {
                let volume = opened.ntfs_volume().unwrap();
                let record = volume
                    .resolve_no_follow(&cx, "/Native payload.bin")
                    .unwrap();
                let name: Vec<_> = "note".encode_utf16().collect();
                let stream = volume.data_stream(&cx, &record, &name).unwrap();
                assert_eq!(stream.size, named_payload.len() as u64);
                assert_eq!(volume.read(&cx, &stream, 0, 4096).unwrap(), named_payload);
                assert_eq!(
                    volume.read(&cx, &stream, 5, 7).unwrap(),
                    named_payload[5..12]
                );
                assert_eq!(
                    volume.read(&cx, &stream, stream.size, 9).unwrap(),
                    [] as [u8; 0]
                );
                assert_eq!(
                    volume.read(&cx, &stream, stream.size + 5, 9).unwrap(),
                    [] as [u8; 0]
                );
                for absent in ["NOTE", "missing"] {
                    assert!(matches!(
                        volume.data_stream(
                            &cx,
                            &record,
                            &absent.encode_utf16().collect::<Vec<_>>()
                        ),
                        Err(FfsError::NotFound(_))
                    ));
                }
                let cancelled = Cx::for_testing();
                cancelled.cancel_with(asupersync::types::CancelKind::User, None);
                assert!(matches!(
                    volume.read(&cancelled, &stream, 0, 1),
                    Err(FfsError::Cancelled)
                ));
            } else {
                assert!(opened.ntfs_volume().is_none());
            }
            let mut scope = RequestScope::empty();
            let file = opened
                .filesystem
                .lookup(&cx, &mut scope, InodeNumber(1), name)
                .unwrap();
            let stat = opened
                .filesystem
                .getattr(&cx, &mut scope, file.ino)
                .unwrap();
            assert_eq!(
                (stat.kind, stat.size),
                (FileType::RegularFile, payload.len() as u64)
            );
            assert!(
                opened
                    .filesystem
                    .readdir(&cx, &mut scope, InodeNumber(1), 0)
                    .unwrap()
                    .iter()
                    .any(|entry| entry.name == name.as_encoded_bytes())
            );
            let mut actual = Vec::new();
            while actual.len() < payload.len() {
                let part = opened
                    .filesystem
                    .read(&cx, &mut scope, file.ino, actual.len() as u64, 8191)
                    .unwrap();
                assert!(
                    !part.is_empty(),
                    "native read ended before the known payload"
                );
                actual.extend_from_slice(&part);
            }
            assert_eq!(actual, payload);
            assert_eq!(
                opened
                    .filesystem
                    .read(&cx, &mut scope, file.ino, 507, 1031)
                    .unwrap(),
                payload[507..1538]
            );
            assert_eq!(
                opened
                    .filesystem
                    .read(&cx, &mut scope, file.ino, payload.len() as u64, 8)
                    .unwrap(),
                [] as [u8; 0]
            );
            assert!(matches!(
                opened
                    .filesystem
                    .write(&cx, &mut scope, file.ino, 0, b"forbidden"),
                Err(FfsError::ReadOnly)
            ));
        }
        if kind == "ntfs" {
            let volume = ffs_ntfs::NtfsVolume::open(&cx, &image, 0, None).unwrap();
            let selected = volume
                .resolve_no_follow(&cx, "/Native payload.bin")
                .unwrap();
            let unrelated = volume.resolve_no_follow(&cx, "/Unrelated.bin").unwrap();
            assert_ne!(selected.number, unrelated.number);
            for (label, record) in [("unrelated", unrelated), ("selected", selected)] {
                let at = record_offset(&cx, &volume, record.number);
                assert_eq!(&native[at..at + 4], b"FILE");
                assert_eq!(
                    u32::from_le_bytes(native[at + 44..at + 48].try_into().unwrap()),
                    record.number
                );
                for offset in [0, 4096] {
                    let mut damaged = if offset == 0 {
                        native.clone()
                    } else {
                        container.clone()
                    };
                    damaged[offset + at..offset + at + 4].copy_from_slice(b"FAIL");
                    let path = directory.join(format!("{label}-{offset}.img"));
                    fs::OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .write_all(&damaged)
                        .unwrap();
                    let mut options = ReadOnlyOpenOptions {
                        offset: offset as u64,
                        length: Some(native.len() as u64),
                        ..ReadOnlyOpenOptions::default()
                    };
                    // Default and explicitly strict views retain whole-root
                    // admission and must see even an unrelated broken target.
                    for backend in [
                        ReadOnlyBackend::Auto,
                        ReadOnlyBackend::Ntfs {
                            indexed_lookup: false,
                        },
                    ] {
                        options.backend = backend;
                        assert!(matches!(
                            open_read_only(&cx, &path, &options),
                            Err(FfsError::Corruption { .. })
                        ));
                    }
                    options.backend = ReadOnlyBackend::Ntfs {
                        indexed_lookup: true,
                    };
                    let opened = open_read_only(&cx, &path, &options).unwrap();
                    let mut scope = RequestScope::empty();
                    let result = opened.filesystem.lookup(&cx, &mut scope, InodeNumber(1), name);
                    if label == "selected" {
                        assert!(matches!(result, Err(FfsError::Corruption { .. })));
                    } else {
                        let file = result.unwrap();
                        assert_eq!(
                            opened
                                .filesystem
                                .read(&cx, &mut scope, file.ino, 507, 1031)
                                .unwrap(),
                            payload[507..1538]
                        );
                    }
                    assert!(matches!(
                        opened.filesystem.readdir(&cx, &mut scope, InodeNumber(1), 0),
                        Err(FfsError::Corruption { .. })
                    ));
                    assert_eq!(fs::read(&path).unwrap(), damaged);
                }
            }
        }
        assert!(
            open_read_only(
                &cx,
                &bounded,
                &ReadOnlyOpenOptions {
                    offset: 4096,
                    length: Some(512),
                    ..ReadOnlyOpenOptions::default()
                }
            )
            .is_err()
        );
        assert_eq!(fs::read(&image).unwrap(), native);
        assert_eq!(fs::read(&bounded).unwrap(), container);
        if kind != "ntfs" {
            command(
                &directory,
                "check-after",
                "fsck.fat",
                &[OsStr::new("-n"), image.as_os_str()],
            );
            assert_eq!(fs::read(&image).unwrap(), native);
        }
        println!(
            "native {kind}: plain/bounded lookup/getattr/readdir/full/ranged/EOF reads, RO refusal and unchanged bytes passed; NTFS includes automatic, explicit strict and indexed modes"
        );
    }
}
