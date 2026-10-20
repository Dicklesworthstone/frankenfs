//! Explicit native-log inspection and memory-only file-data recovery commands.

use super::{CandidateArgs, Cx, Result, bail, dataset_components, json};
use clap::Subcommand;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect a head's checksum-verified native ZIL prefix without replaying it.
    ZilInspect {
        #[command(flatten)]
        candidate: CandidateArgs,
        /// Head dataset relative to the pool; snapshots and zvols are not admitted.
        #[arg(long, default_value = "")]
        dataset: String,
    },
    /// Recover an existing file range from copied writes/EOF truncations into memory.
    ZilRead {
        #[command(flatten)]
        candidate: CandidateArgs,
        #[arg(long, default_value = "")]
        dataset: String,
        /// Existing regular file inside the committed dataset; no symlink following.
        path: PathBuf,
        #[arg(long, default_value_t = 0)]
        start: u64,
        /// Required explicit count; maximum 16 MiB. Output is staged before stdout.
        #[arg(long)]
        bytes: usize,
        /// Accept only the verified prefix when an unclaimed tail has no valid checksum.
        /// That tail may be unwritten OR damaged; this cannot certify complete recovery.
        #[arg(long)]
        allow_unverified_tail: bool,
    },
}

fn preflight(candidate: &CandidateArgs) -> Result<()> {
    if !candidate.missing_mirror_members.is_empty() {
        bail!("missing mirror members admit committed-view extraction, not ZIL inspection or recovery");
    }
    // The live sidecar can heal through a read. Reject before opening either
    // file, not merely after wrapping a potentially writable backing device.
    if candidate.image.sidecar.is_some() {
        bail!("read-only ZIL inspection/recovery does not admit sidecar healing");
    }
    if candidate.members.len() > 7 {
        bail!("at most seven additional ZIL member images are supported");
    }
    Ok(())
}

impl Command {
    pub(super) fn run(self, cx: &Cx) -> Result<()> {
        match self {
            Self::ZilInspect { candidate, dataset } => {
                preflight(&candidate)?;
                let components = dataset_components(&dataset)?;
                let log = candidate.objects(cx)?.intent_log(cx, &components)?;
                cx.checkpoint()
                    .map_err(|_| ffs_error::FfsError::Cancelled)?;
                json(&serde_json::json!({
                    "format": "ZFS", "operation": "zil_inspect", "dataset": dataset,
                    "scope": "selected_head_native_log_prefix",
                    "read_only": true, "replay_performed": false, "backing_writes": false,
                    "complete_recovery_certified": false, "log": log
                }))
            }
            Self::ZilRead {
                candidate,
                dataset,
                path,
                start,
                bytes,
                allow_unverified_tail,
            } => {
                preflight(&candidate)?;
                if bytes > 16 * 1024 * 1024 {
                    bail!("ZIL recovered range exceeds 16 MiB");
                }
                let components = dataset_components(&dataset)?;
                let recovered = candidate.objects(cx)?.read_with_intent_log(
                    cx,
                    &components,
                    path.as_os_str().as_bytes(),
                    start,
                    bytes,
                    allow_unverified_tail,
                )?;
                cx.checkpoint()
                    .map_err(|_| ffs_error::FfsError::Cancelled)?;
                let receipt = serde_json::json!({
                    "format": "ZFS", "operation": "zil_read", "dataset": dataset,
                    "scope": "existing_regular_file_copied_writes_and_eof_truncation",
                    "read_only": true, "backing_writes": false,
                    "native_replay_performed": false, "complete_recovery_certified": false,
                    "pool_guid": recovered.log.pool_guid.to_string(),
                    "dataset_guid": recovered.log.dataset_guid.to_string(),
                    "selected_txg": recovered.log.selected_txg,
                    "termination": recovered.log.termination,
                    "allow_unverified_tail": allow_unverified_tail,
                    "file_size": recovered.file_size, "start": start,
                    "returned_bytes": recovered.bytes.len(),
                    "applied_records": recovered.applied_records
                });
                let mut err = io::stderr().lock();
                serde_json::to_writer(&mut err, &receipt)?;
                writeln!(err)?;
                err.flush()?;
                let mut out = io::stdout().lock();
                out.write_all(&recovered.bytes)?;
                out.flush()?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_commands::FileCommand;
    use crate::{Cli, Command as TopCommand};
    use clap::Parser;

    #[test]
    fn missing_mirror_zil_requests_are_refused_before_any_image_open() {
        for (command, extra) in [
            ("zil-inspect", Vec::new()),
            ("zil-read", vec!["/file", "--bytes", "1"]),
        ] {
            let cli = Cli::try_parse_from([
                "ffs-zfs", command, "unopened-mirror.img", "--offline-image",
                "--pool-guid", "123", "--label", "0", "--slot", "2",
                "--missing-mirror-member", "1002",
            ].into_iter().chain(extra)).unwrap();
            let TopCommand::File(command) = cli.command else {
                panic!("ZIL command");
            };
            assert!(command.run(&Cx::for_testing()).unwrap_err().to_string()
                .contains("not ZIL inspection or recovery"));
        }
    }

    #[test]
    fn zil_commands_keep_selection_and_require_explicit_recovery_ranges() {
        let base = [
            "ffs-zfs",
            "zil-read",
            "leaf.img",
            "/file",
            "--offline-image",
            "--auto-import",
        ];
        assert!(Cli::try_parse_from(base).is_err());
        let parsed = Cli::try_parse_from(base.into_iter().chain([
            "--bytes",
            "8192",
            "--start",
            "510",
            "--dataset",
            "data",
        ]))
        .unwrap();
        let TopCommand::File(FileCommand::Zil(Command::ZilRead {
            candidate,
            dataset,
            path,
            start,
            bytes,
            allow_unverified_tail,
        })) = parsed.command
        else {
            panic!("ZIL recovery command");
        };
        assert!(candidate.auto_import);
        assert!(candidate.image.offline_image);
        assert_eq!(dataset, "data");
        assert_eq!(path, PathBuf::from("/file"));
        assert_eq!((start, bytes, allow_unverified_tail), (510, 8192, false));
        for option in ["--snapshot", "--rw", "--force", "--heal"] {
            assert!(Cli::try_parse_from(base.into_iter().chain(["--bytes", "1", option])).is_err());
        }
        let parsed = Cli::try_parse_from(base.into_iter().chain([
            "--bytes",
            "1",
            "--allow-unverified-tail",
        ]))
        .unwrap();
        assert!(matches!(
            parsed.command,
            TopCommand::File(FileCommand::Zil(Command::ZilRead {
                allow_unverified_tail: true,
                ..
            }))
        ));
        let parsed = Cli::try_parse_from([
            "ffs-zfs",
            "zil-inspect",
            "leaf.img",
            "--offline-image",
            "--pool-guid",
            "123",
            "--label",
            "2",
            "--slot",
            "7",
        ])
        .unwrap();
        let TopCommand::File(FileCommand::Zil(Command::ZilInspect { candidate, .. })) =
            parsed.command
        else {
            panic!("ZIL inspection command");
        };
        assert_eq!(
            (candidate.pool_guid, candidate.label, candidate.slot),
            (123, 2, 7)
        );
    }

    #[test]
    fn zil_preflight_refuses_healing_excess_members_and_unbounded_ranges_before_open() {
        for (command, extra) in [
            ("zil-inspect", Vec::new()),
            ("zil-read", vec!["/file", "--bytes", "1"]),
        ] {
            for (options, reason) in [
                (
                    vec!["--sidecar", "nonexistent-zil-sidecar.rq"],
                    "does not admit sidecar healing",
                ),
                (
                    ["--member", "nonexistent-zil-member.img"].repeat(8),
                    "at most seven additional ZIL member images",
                ),
            ] {
                let cli = Cli::try_parse_from(
                    [
                        "ffs-zfs",
                        command,
                        "nonexistent-zil-fixture.img",
                        "--offline-image",
                        "--auto-import",
                    ]
                    .into_iter()
                    .chain(extra.clone())
                    .chain(options),
                )
                .unwrap();
                let TopCommand::File(command) = cli.command else {
                    panic!("ZIL command");
                };
                let error = command.run(&Cx::for_testing()).unwrap_err();
                assert!(error.to_string().contains(reason), "{error}");
            }
        }
        let cli = Cli::try_parse_from([
            "ffs-zfs",
            "zil-read",
            "nonexistent-zil-fixture.img",
            "/file",
            "--offline-image",
            "--auto-import",
            "--bytes",
            "16777217",
        ])
        .unwrap();
        let TopCommand::File(command) = cli.command else {
            panic!("ZIL command");
        };
        assert!(
            command
                .run(&Cx::for_testing())
                .unwrap_err()
                .to_string()
                .contains("exceeds 16 MiB")
        );
    }

    #[test]
    fn zil_commands_retain_complete_member_and_partition_selection() {
        for alias in [
            "--member",
            "--mirror-member",
            "--raidz-member",
            "--striped-member",
        ] {
            for (command, extra) in [
                ("zil-inspect", Vec::new()),
                ("zil-read", vec!["/file", "--bytes", "4096"]),
            ] {
                let cli = Cli::try_parse_from(
                    [
                        "ffs-zfs",
                        command,
                        "first.img",
                        "--offline-image",
                        "--auto-import",
                        alias,
                        "second.img",
                        "--offset",
                        "4096",
                        "--length",
                        "67108864",
                    ]
                    .into_iter()
                    .chain(extra),
                )
                .unwrap();
                let TopCommand::File(FileCommand::Zil(
                    Command::ZilInspect { candidate, .. } | Command::ZilRead { candidate, .. },
                )) = cli.command
                else {
                    panic!("ZIL command");
                };
                assert_eq!(candidate.members, [PathBuf::from("second.img")]);
                assert_eq!(
                    (candidate.image.offset, candidate.image.length),
                    (4096, Some(67_108_864))
                );
                assert!(candidate.image.offline_image);
                preflight(&candidate).unwrap();
            }
        }
    }
}
