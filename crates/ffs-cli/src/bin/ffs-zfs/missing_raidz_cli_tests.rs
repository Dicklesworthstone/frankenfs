//! Public option and pre-I/O authority controls for missing RAIDZ extraction.

use super::*;

fn candidate(missing: Vec<u64>) -> CandidateArgs {
    CandidateArgs {
        image: ImageArgs {
            image: PathBuf::from("unopened-raidz-primary.img"),
            offset: 4096,
            length: Some(67_108_864),
            offline_image: true,
            sidecar: None,
        },
        auto_import: false,
        replay_zil: false,
        label: 2,
        slot: 7,
        pool_guid: 123,
        members: Vec::new(),
        missing_mirror_members: Vec::new(),
        missing_raidz_members: missing,
    }
}

#[test]
fn missing_raidz_cli_routes_explicit_candidate_members_and_volume_bounds() {
    let options = [
        "--offline-image", "--pool-guid", "123", "--label", "2", "--slot", "7",
        "--offset", "4096", "--length", "67108864", "--member", "second.img",
        "--missing-raidz-member", "1003", "--missing-raidz-member", "1004",
    ];
    for command in [
        vec!["root", "first.img"],
        vec!["object", "first.img", "7"],
        vec!["object-read", "first.img", "7", "--bytes", "32"],
        vec!["zap", "first.img", "7"],
        vec!["datasets", "first.img"],
    ] {
        let cli = Cli::try_parse_from(std::iter::once("ffs-zfs").chain(command).chain(options))
            .unwrap();
        let (Command::Root { candidate }
        | Command::Object { candidate, .. }
        | Command::ObjectRead { candidate, .. }
        | Command::Zap { candidate, .. }
        | Command::Datasets { candidate }) = cli.command else {
            panic!("raw candidate command");
        };
        assert_eq!(candidate.missing_raidz_members, [1003, 1004]);
        assert_eq!(candidate.members, [PathBuf::from("second.img")]);
        assert!(candidate.missing_mirror_members.is_empty());
        assert_eq!((candidate.pool_guid, candidate.label, candidate.slot), (123, 2, 7));
        assert_eq!((candidate.image.offset, candidate.image.length), (4096, Some(67_108_864)));
        assert!(!candidate.auto_import && !candidate.replay_zil);
    }
    for command in [
        vec!["ls", "first.img", "/"],
        vec!["read", "first.img", "/file"],
        vec!["mount", "first.img", "/mnt/extraction"],
    ] {
        assert!(Cli::try_parse_from(std::iter::once("ffs-zfs").chain(command).chain(options)).is_ok());
    }
    for extra in [
        vec!["--auto-import"], vec!["--replay-zil"], vec!["--missing-mirror-member", "1005"],
        vec!["--rw"],
    ] {
        assert!(Cli::try_parse_from(["ffs-zfs", "root", "first.img"].into_iter()
            .chain(options).chain(extra)).is_err());
    }
    assert!(Cli::try_parse_from([
        "ffs-zfs", "root", "first.img", "--offline-image", "--missing-raidz-member", "1002",
    ]).is_err());
    assert!(Cli::try_parse_from([
        "ffs-zfs", "inspect", "first.img", "--offline-image", "--missing-raidz-member", "1002",
    ]).is_err());
}

#[test]
fn missing_raidz_invalid_authority_and_request_shapes_fail_before_opening_images() {
    for case in 0..8 {
        let mut args = candidate(vec![1002]);
        let reason = match case {
            0 => { args.missing_raidz_members = vec![0]; "nonzero and unique" }
            1 => { args.missing_raidz_members = vec![1002, 1002]; "nonzero and unique" }
            2 => { args.missing_raidz_members = vec![1002, 1003, 1004, 1005]; "one through three" }
            3 => { args.members = vec![PathBuf::from("unopened-member.img"); 7]; "at most eight total" }
            4 => { args.auto_import = true; "without mirror declarations, import or replay" }
            5 => { args.replay_zil = true; "without mirror declarations, import or replay" }
            6 => { args.pool_guid = 0; "without mirror declarations, import or replay" }
            _ => { args.missing_mirror_members = vec![1003]; "without mirror declarations, import or replay" }
        };
        let Err(error) = args.open(&Cx::for_testing()) else {
            panic!("invalid absent-member authority must fail before image I/O");
        };
        assert!(error.to_string().contains(reason), "case {case}: {error}");
    }
}

#[test]
fn missing_raidz_separate_zil_commands_refuse_before_any_image_open() {
    for (command, extra) in [
        ("zil-inspect", Vec::new()),
        ("zil-read", vec!["/file", "--bytes", "1"]),
    ] {
        let cli = Cli::try_parse_from([
            "ffs-zfs", command, "unopened-raidz.img", "--offline-image",
            "--pool-guid", "123", "--label", "0", "--slot", "2",
            "--missing-raidz-member", "1002",
        ].into_iter().chain(extra)).unwrap();
        let Command::File(command) = cli.command else { panic!("ZIL command"); };
        let error = command.run(&Cx::for_testing()).unwrap_err();
        assert!(error.to_string().contains("missing RAIDZ members"), "{error}");
        assert!(error.to_string().contains("not ZIL inspection or recovery"), "{error}");
    }
}
