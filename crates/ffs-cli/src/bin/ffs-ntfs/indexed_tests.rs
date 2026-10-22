//! CLI admission controls; native branch/identity/I/O controls live in ffs-ntfs.

use super::*;

#[test]
fn indexed_lookup_is_explicit_and_preserves_path_and_volume_selection() {
    for command in ["ls", "read", "readlink"] {
        for indexed in [false, true] {
            let mut args = vec![
                "ffs-ntfs",
                command,
                "unopened.img",
                "/Subdir/Ä.bin",
                "--offline-image",
                "--offset",
                "1048576",
                "--length",
                "67108864",
            ];
            if indexed {
                args.push("--indexed-lookup");
            }
            let parsed = Cli::try_parse_from(args).unwrap();
            let (Command::Ls {
                image,
                path,
                indexed_lookup,
            }
            | Command::Read {
                image,
                path,
                indexed_lookup,
                ..
            }
            | Command::Readlink {
                image,
                path,
                indexed_lookup,
            }) = parsed.command
            else {
                panic!("native path command");
            };
            assert_eq!(indexed_lookup, indexed);
            assert_eq!(path, "/Subdir/Ä.bin");
            assert_eq!(image.image, PathBuf::from("unopened.img"));
            assert_eq!((image.offset, image.length), (1_048_576, Some(67_108_864)));
            assert!(image.offline_image);
        }
    }
    let cli = Cli::try_parse_from([
        "ffs-ntfs",
        "ls",
        "unopened.img",
        "--offline-image",
        "--indexed-lookup",
    ])
    .unwrap();
    let Command::Ls {
        path,
        indexed_lookup,
        ..
    } = cli.command
    else {
        panic!("ls");
    };
    assert_eq!(path, "/");
    assert!(indexed_lookup);
}

#[test]
fn indexed_lookup_retains_exact_raw_stream_identity_and_range_admission() {
    let base = [
        "ffs-ntfs",
        "read",
        "unopened.img",
        "/Subdir/Ä.bin",
        "--offline-image",
        "--indexed-lookup",
        "--stream-utf16",
        "d800,006E",
        "--start",
        "513",
        "--bytes",
        "1025",
    ];
    let parsed = Cli::try_parse_from(base).unwrap();
    let Command::Read {
        indexed_lookup,
        stream,
        stream_utf16,
        start,
        bytes,
        ..
    } = parsed.command
    else {
        panic!("read");
    };
    assert!(indexed_lookup && stream.is_none());
    assert_eq!(stream_utf16.unwrap().as_units(), [0xD800, 0x006E]);
    assert_eq!((start, bytes), (513, Some(1025)));
    assert!(Cli::try_parse_from(base.into_iter().chain(["--stream", "other"])).is_err());
    for invalid in ["0000", "d80", "10000", "d800,"] {
        assert!(
            Cli::try_parse_from([
                "ffs-ntfs",
                "read",
                "unopened.img",
                "/file",
                "--offline-image",
                "--indexed-lookup",
                "--stream-utf16",
                invalid,
            ])
            .is_err()
        );
    }
}

#[test]
fn indexed_lookup_does_not_expand_write_mount_or_record_command_authority() {
    for command in ["ls", "read", "readlink"] {
        assert!(
            Cli::try_parse_from([
                "ffs-ntfs",
                command,
                "unopened.img",
                "/file",
                "--indexed-lookup",
            ])
            .is_err()
        );
        for option in ["--rw", "--force", "--repair"] {
            assert!(
                Cli::try_parse_from([
                    "ffs-ntfs",
                    command,
                    "unopened.img",
                    "/file",
                    "--offline-image",
                    "--indexed-lookup",
                    option,
                ])
                .is_err()
            );
        }
    }
    for command in ["cat", "record", "streams", "security", "ea"] {
        assert!(
            Cli::try_parse_from([
                "ffs-ntfs",
                command,
                "unopened.img",
                "24",
                "--offline-image",
                "--indexed-lookup",
            ])
            .is_err()
        );
    }
    for command in ["inspect", "check-allocation"] {
        assert!(
            Cli::try_parse_from([
                "ffs-ntfs",
                command,
                "unopened.img",
                "--offline-image",
                "--indexed-lookup",
            ])
            .is_err()
        );
    }
    assert!(
        Cli::try_parse_from([
            "ffs-ntfs",
            "mount",
            "unopened.img",
            "/mnt/ntfs",
            "--offline-image",
            "--indexed-lookup",
        ])
        .is_err()
    );
}
