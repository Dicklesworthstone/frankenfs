//! Native volume commands; these do not resolve ZPL or host-device paths.
use super::{CandidateArgs, Cx, Result, bail, dataset_components, json};
use clap::{Args, Subcommand, ValueEnum};
use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;

#[derive(Debug, Args)]
pub struct VolumeArgs {
    #[command(flatten)]
    candidate: CandidateArgs,
    /// Exact head dataset relative to the pool, not a /dev/zvol or ZPL path.
    #[arg(long)]
    dataset: String,
    /// Exact native snapshot; omit for this volume's committed head.
    #[arg(long)]
    snapshot: Option<OsString>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SeekKind {
    Data,
    Hole,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect native zvol capacity, block size and pinned head/snapshot identity.
    ZvolInfo {
        #[command(flatten)]
        volume: VolumeArgs,
    },
    /// Extract a native zvol byte range to stdout without creating a host device.
    ZvolRead {
        #[command(flatten)]
        volume: VolumeArgs,
        #[arg(long, default_value_t = 0)]
        start: u64,
        /// Exact byte count; omit to extract the remainder of native capacity.
        #[arg(long)]
        bytes: Option<u64>,
    },
    /// Locate allocated data or a native hole, without scrubbing data payloads.
    ZvolSeek {
        #[command(flatten)]
        volume: VolumeArgs,
        #[arg(long, default_value_t = 0)]
        start: u64,
        #[arg(long, value_enum)]
        kind: SeekKind,
    },
}

enum Action {
    Info,
    Read(u64, Option<u64>),
    Seek(u64, SeekKind),
}

fn length(capacity: u64, start: u64, requested: Option<u64>) -> Result<u64> {
    let remaining = capacity
        .checked_sub(start)
        .ok_or_else(|| anyhow::anyhow!("zvol start exceeds native capacity"))?;
    let count = requested.unwrap_or(remaining);
    if count > remaining {
        bail!("zvol byte range exceeds native capacity");
    }
    Ok(count)
}

impl Command {
    pub(super) fn run(self, cx: &Cx) -> Result<()> {
        let (args, action) = match self {
            Self::ZvolInfo { volume } => (volume, Action::Info),
            Self::ZvolRead {
                volume,
                start,
                bytes,
            } => (volume, Action::Read(start, bytes)),
            Self::ZvolSeek {
                volume,
                start,
                kind,
            } => (volume, Action::Seek(start, kind)),
        };
        // Read-triggered sidecar healing is not strict read-only extraction.
        // Refuse before opening any backing image or native pool metadata.
        if args.candidate.image.sidecar.is_some() {
            bail!("read-only zvol commands do not admit sidecar healing");
        }
        let components = dataset_components(&args.dataset)?;
        let mut objects = args.candidate.objects(cx)?;
        let mut volume = objects.zvol(
            cx,
            &components,
            args.snapshot.as_deref().map(OsStrExt::as_bytes),
        )?;
        match action {
            Action::Read(start, requested) => {
                let bytes = length(volume.info().size_bytes, start, requested)?;
                let mut out = io::stdout().lock();
                let mut done = 0_u64;
                while done < bytes {
                    cx.checkpoint()
                        .map_err(|_| ffs_error::FfsError::Cancelled)?;
                    let count = (bytes - done).min(1024 * 1024) as usize;
                    let data = volume.read(cx, start + done, count)?;
                    if data.len() != count {
                        bail!("zvol reader returned a short exact range");
                    }
                    out.write_all(&data)?;
                    done += count as u64;
                }
                cx.checkpoint()
                    .map_err(|_| ffs_error::FfsError::Cancelled)?;
                out.flush()?;
                Ok(())
            }
            Action::Info | Action::Seek(..) => {
                let found = match action {
                    Action::Seek(start, kind) => {
                        Some(volume.seek_data_hole(cx, start, matches!(kind, SeekKind::Data))?)
                    }
                    _ => None,
                };
                let info = volume.info();
                cx.checkpoint()
                    .map_err(|_| ffs_error::FfsError::Cancelled)?;
                json(&serde_json::json!({
                    "format": "ZFS", "kind": "zvol", "read_only": true,
                    "operation": if found.is_some() { "zvol-seek" } else { "zvol-info" },
                    "dataset": args.dataset,
                    "snapshot": args.snapshot.as_deref().and_then(|name| name.to_str()),
                    "snapshot_name_bytes": args.snapshot.as_deref().map(OsStrExt::as_bytes),
                    "pool_guid": info.pool_guid.to_string(), "dataset_guid": info.dataset_guid.to_string(),
                    "pool_txg": info.pool_txg, "view_txg": info.view_txg, "root_birth": info.root_birth,
                    "size_bytes": info.size_bytes, "volblocksize": info.block_bytes,
                    "dnode_used_bytes": info.dnode_used_bytes, "offset": found,
                    "scope": "selected committed native volume; no ZIL replay or host device",
                    "payloads_scrubbed": false
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_commands::FileCommand;
    use crate::{Cli, Command as RootCommand};
    use clap::Parser;

    #[test]
    fn native_volume_commands_retain_candidate_members_partition_and_snapshot() {
        for verb in ["zvol-info", "zvol-read", "zvol-seek"] {
            let mut args = vec![
                "ffs-zfs",
                verb,
                "first.img",
                "--offline-image",
                "--auto-import",
                "--member",
                "second.img",
                "--offset",
                "1048576",
                "--length",
                "67108864",
                "--dataset",
                "vm/disk",
                "--snapshot",
                "before",
            ];
            if verb == "zvol-read" {
                args.extend(["--start", "510", "--bytes", "600"]);
            }
            if verb == "zvol-seek" {
                args.extend(["--start", "510", "--kind", "hole"]);
            }
            let cli = Cli::try_parse_from(args).unwrap();
            let RootCommand::File(FileCommand::Zvol(command)) = cli.command else {
                panic!("zvol command");
            };
            let volume = match command {
                Command::ZvolInfo { volume } => volume,
                Command::ZvolRead {
                    volume,
                    start,
                    bytes,
                } => {
                    assert_eq!((start, bytes), (510, Some(600)));
                    volume
                }
                Command::ZvolSeek {
                    volume,
                    start,
                    kind,
                } => {
                    assert_eq!(start, 510);
                    assert!(matches!(kind, SeekKind::Hole));
                    volume
                }
            };
            assert_eq!(volume.dataset, "vm/disk");
            assert_eq!(volume.snapshot, Some(OsString::from("before")));
            assert!(volume.candidate.auto_import && volume.candidate.image.offline_image);
            assert_eq!(volume.candidate.image.offset, 1048576);
            assert_eq!(volume.candidate.image.length, Some(67108864));
            assert_eq!(
                volume.candidate.members,
                [std::path::PathBuf::from("second.img")]
            );
        }
    }

    #[test]
    fn volume_selection_is_explicit_and_mutation_options_are_not_admitted() {
        let base = [
            "ffs-zfs",
            "zvol-info",
            "image",
            "--offline-image",
            "--auto-import",
            "--dataset",
            "vm",
        ];
        for option in ["--rw", "--force", "--replay", "--create-device"] {
            assert!(Cli::try_parse_from(base.into_iter().chain([option])).is_err());
        }
        assert!(
            Cli::try_parse_from([
                "ffs-zfs",
                "zvol-info",
                "image",
                "--offline-image",
                "--auto-import"
            ])
            .is_err()
        );
        assert!(Cli::try_parse_from(["ffs-zfs", "zvol-info", "image", "--dataset", "vm"]).is_err());
        let cli = Cli::try_parse_from(base.into_iter().chain(["--sidecar", "absent.rq"])).unwrap();
        let RootCommand::File(FileCommand::Zvol(command)) = cli.command else {
            panic!("zvol command");
        };
        assert!(
            command
                .run(&Cx::for_testing())
                .unwrap_err()
                .to_string()
                .contains("do not admit sidecar healing")
        );
    }

    #[test]
    fn extraction_ranges_do_not_wrap_or_silently_truncate() {
        assert_eq!(length(32768, 510, None).unwrap(), 32258);
        assert_eq!(length(32768, 510, Some(600)).unwrap(), 600);
        assert_eq!(length(32768, 32768, None).unwrap(), 0);
        assert!(length(32768, 32769, Some(0)).is_err());
        assert!(length(32768, 32768, Some(1)).is_err());
        assert!(length(32768, 1, Some(u64::MAX)).is_err());
        assert_eq!(length(u64::MAX, u64::MAX - 7, Some(7)).unwrap(), 7);
        assert!(length(u64::MAX, u64::MAX - 7, Some(8)).is_err());
    }
}
