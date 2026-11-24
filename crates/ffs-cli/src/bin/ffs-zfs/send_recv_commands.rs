//! Native OpenZFS `DMU_BACKUP_STREAM` send, resumable receive, abort, and
//! `receive_resume_token` inspection CLI subcommands.
//!
//! Security boundary:
//! - `send` and `recv-token-inspect` are strictly read-only (never require `--allow-write`,
//!   never modify backing images).
//! - `recv` and `recv-abort` require explicit `--offline-image`, `--allow-write`,
//!   `--pool-guid`, `--label`, `--slot`, and caller-owned `--dataset`.
//! - Untrusted stream headers (`drr_toname`, embedded XDR nvlists) and resume tokens
//!   NEVER choose host paths, devices, pools, key files, or import authority.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write as _};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::Subcommand;
use ffs_ondisk::zfs::Endian;
use ffs_ondisk::zfs::send_stream::ReceiveResumeToken;
use ffs_zfs::{
    ZfsRecvRequest, ZfsSendFrom, ZfsSendRequest, ZfsTxOutcome, inspect_receive_resume_state_in_mos,
    send_stream,
};

use super::write_commands::{WritePoolArgs, parse_dataset_components};
use super::{CandidateArgs, KeyArgs, json};

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum SendRecvCommand {
    /// Emit a native OpenZFS `DMU_BACKUP_STREAM` from an offline ZFS snapshot (read-only).
    Send {
        #[command(flatten)]
        candidate: CandidateArgs,
        /// Pool-relative source dataset path (`""` selects the pool root).
        #[arg(long, default_value = "")]
        dataset: String,
        /// Target snapshot name to send (optional when `--resume-token` matches by `toguid`).
        #[arg(long, required_unless_present = "resume_token")]
        snapshot: Option<OsString>,
        /// Incremental base snapshot name (`-i @from`).
        #[arg(long, conflicts_with = "from_bookmark")]
        from_snapshot: Option<OsString>,
        /// Incremental base bookmark name (`-i #from`).
        #[arg(long, conflicts_with = "from_snapshot")]
        from_bookmark: Option<OsString>,
        /// Include intermediary snapshots (`-I`) between `--from-*` and `--snapshot`.
        #[arg(short = 'I', long)]
        intermediary: bool,
        /// Raw encrypted/compressed send (`-w`); works keylessly on locked encrypted datasets.
        #[arg(short = 'w', long)]
        raw: bool,
        /// Send compressed physical blocks directly (`-c`).
        #[arg(short = 'c', long)]
        compressed: bool,
        /// Send embedded data blocks directly (`-e`).
        #[arg(short = 'e', long)]
        embedded: bool,
        /// Allow blocks larger than 128 KiB (`-L`).
        #[arg(short = 'L', long)]
        large_blocks: bool,
        /// Emit compound stream packaging dataset properties (`-p`).
        #[arg(short = 'p', long)]
        props: bool,
        /// OpenZFS v1 `receive_resume_token` (`-t`) to resume an interrupted receive.
        #[arg(short = 't', long)]
        resume_token: Option<String>,
        /// Emit stream headers in big-endian byte order instead of little-endian.
        #[arg(long)]
        big_endian: bool,
        #[command(flatten)]
        key: KeyArgs,
        /// Destination file for stream bytes (defaults to stdout).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Optional JSON file path for the structured send audit report.
        #[arg(long)]
        report_json: Option<PathBuf>,
    },
    /// Receive a native OpenZFS `DMU_BACKUP_STREAM` into an explicitly authorized offline pool.
    Recv {
        #[command(flatten)]
        pool: WritePoolArgs,
        /// Input file containing the stream bytes (defaults to stdin).
        #[arg(long = "in")]
        input: Option<PathBuf>,
        /// Optional explicit target snapshot name overriding validated `drr_toname` suffix.
        #[arg(long)]
        snapshot: Option<OsString>,
        /// Persist private resumable `%recv` / `DS_FLAG_INCONSISTENT` checkpoints (`-s`).
        #[arg(short = 's', long)]
        resumable: bool,
        /// Roll back unsnapshotted live head divergence on incremental receive (`-F`).
        #[arg(short = 'F', long)]
        force: bool,
        /// Payload byte interval between atomic TXG checkpoints during receive.
        #[arg(
            long,
            default_value_t = 4 * 1024 * 1024,
            value_parser = clap::value_parser!(u64).range(1..)
        )]
        checkpoint_bytes: u64,
    },
    /// Atomically abort an incomplete resumable receive (`%recv` / `DS_FLAG_INCONSISTENT`) and reclaim space.
    RecvAbort {
        #[command(flatten)]
        pool: WritePoolArgs,
    },
    /// Inspect an OpenZFS v1 `receive_resume_token` offline (`--token`) or from an offline pool image (read-only).
    RecvTokenInspect {
        /// Raw OpenZFS v1 `receive_resume_token` string (pure offline parse; zero image I/O).
        #[arg(long, conflicts_with_all = ["image", "offline_image", "auto_import", "pool_guid"])]
        token: Option<String>,
        /// Offline ZFS regular image (used when `--token` is not supplied).
        #[arg(required_unless_present = "token")]
        image: Option<PathBuf>,
        /// Acknowledge no kernel or external writer will modify the image.
        #[arg(long, requires = "image")]
        offline_image: bool,
        #[arg(long, default_value_t = 0)]
        offset: u64,
        #[arg(long)]
        length: Option<u64>,
        #[arg(long)]
        auto_import: bool,
        #[arg(long, default_value_t = 0)]
        label: usize,
        #[arg(long, default_value_t = 0)]
        slot: usize,
        #[arg(long, default_value_t = 0)]
        pool_guid: u64,
        #[arg(
            long = "member",
            visible_aliases = ["mirror-member", "raidz-member", "striped-member"],
            value_name = "IMAGE"
        )]
        members: Vec<PathBuf>,
        /// Target dataset whose incomplete receive state should be inspected.
        #[arg(long, default_value = "")]
        dataset: String,
    },
}

fn ensure_output_does_not_alias_backing_images(
    out_path: &Path,
    candidate: &CandidateArgs,
) -> Result<()> {
    let Ok(out_canon) = out_path.canonicalize() else {
        return Ok(());
    };
    for img in std::iter::once(&candidate.image.image).chain(&candidate.members) {
        if let Ok(img_canon) = img.canonicalize()
            && img_canon == out_canon
        {
            bail!(
                "refusing to write send output over backing pool image {}",
                img.display()
            );
        }
    }
    Ok(())
}

impl SendRecvCommand {
    #[allow(clippy::too_many_lines)]
    pub fn run(self, cx: &Cx) -> Result<()> {
        match self {
            Self::Send {
                candidate,
                dataset,
                snapshot,
                from_snapshot,
                from_bookmark,
                intermediary,
                raw,
                compressed,
                embedded,
                large_blocks,
                props,
                resume_token,
                big_endian,
                key,
                out,
                report_json,
            } => {
                if let Some(ref out_path) = out {
                    ensure_output_does_not_alias_backing_images(out_path, &candidate)?;
                }
                if let Some(ref rep_path) = report_json {
                    ensure_output_does_not_alias_backing_images(rep_path, &candidate)?;
                }
                let components = parse_dataset_components(&dataset)?;
                let mut mos = candidate.objects(cx)?;
                key.load_into_objects(cx, &mut mos, &components)?;

                let from = match (from_snapshot, from_bookmark) {
                    (Some(s), None) => Some(ZfsSendFrom::Snapshot(s.as_bytes().to_vec())),
                    (None, Some(b)) => Some(ZfsSendFrom::Bookmark(b.as_bytes().to_vec())),
                    (None, None) => None,
                    (Some(_), Some(_)) => {
                        bail!("--from-snapshot and --from-bookmark are mutually exclusive")
                    }
                };
                let to_snapshot = snapshot.map_or_else(Vec::new, |s| s.as_bytes().to_vec());
                let req = ZfsSendRequest {
                    dataset: components,
                    to_snapshot,
                    from,
                    include_intermediaries: intermediary,
                    raw,
                    compressed,
                    embedded,
                    large_blocks,
                    properties: props,
                    resume_token,
                    stream_order: if big_endian {
                        Endian::Big
                    } else {
                        Endian::Little
                    },
                };

                let report = if let Some(ref out_path) = out {
                    let file = File::create(out_path).with_context(|| {
                        format!("creating send stream file {}", out_path.display())
                    })?;
                    let mut writer = BufWriter::new(file);
                    let rep = send_stream(cx, &mut mos, &req, &mut writer)
                        .context("emitting ZFS DMU send stream")?;
                    writer.flush().context("flushing send stream file")?;
                    rep
                } else {
                    let stdout = io::stdout();
                    let mut writer = BufWriter::new(stdout.lock());
                    let rep = send_stream(cx, &mut mos, &req, &mut writer)
                        .context("emitting ZFS DMU send stream to stdout")?;
                    writer.flush().context("flushing send stream stdout")?;
                    rep
                };

                let payload = serde_json::json!({
                    "format": "ZFS",
                    "operation": "send",
                    "dataset": dataset,
                    "report": report,
                });
                if let Some(ref rep_path) = report_json {
                    let mut f = File::create(rep_path).with_context(|| {
                        format!("creating send report file {}", rep_path.display())
                    })?;
                    serde_json::to_writer_pretty(&mut f, &payload)?;
                    writeln!(f)?;
                } else if out.is_some() {
                    json(&payload)?;
                }
                Ok(())
            }
            Self::Recv {
                pool,
                input,
                snapshot,
                resumable,
                force,
                checkpoint_bytes,
            } => {
                let (mut engine, components) = pool.open_engine(cx)?;
                let mut req = ZfsRecvRequest::new(components.clone());
                req.snapshot_override = snapshot.map(|s| s.as_bytes().to_vec());
                req.resumable = resumable;
                req.force = force;
                req.checkpoint_bytes = checkpoint_bytes;

                let outcome = if let Some(ref in_path) = input {
                    let file = File::open(in_path).with_context(|| {
                        format!("opening send stream file {}", in_path.display())
                    })?;
                    let mut reader = BufReader::new(file);
                    engine.receive_stream(cx, &req, &mut reader)
                } else {
                    let stdin = io::stdin();
                    let mut reader = BufReader::new(stdin.lock());
                    engine.receive_stream(cx, &req, &mut reader)
                };

                match outcome {
                    ZfsTxOutcome::Committed { value, token } => {
                        engine
                            .verify_token(&token)
                            .context("verifying storage/topology/TXG-bound ZFS durable token")?;
                        json(&serde_json::json!({
                            "format": "ZFS",
                            "operation": "recv",
                            "outcome": "Committed",
                            "dataset": pool.dataset,
                            "report": value,
                            "committed_txg": engine.committed_txg(),
                            "published_slot": engine.committed_slot(),
                            "token": token,
                        }))
                    }
                    ZfsTxOutcome::NotCommitted(err) => {
                        if resumable
                            && let Ok(Some(state)) =
                                engine.inspect_receive_resume_state(cx, &components)
                        {
                            eprintln!(
                                "receive interrupted with persisted resumable state; receive_resume_token={} object={} offset={} bytes={}",
                                state.token, state.object, state.offset, state.bytes
                            );
                        }
                        bail!("ZFS TXG recv NotCommitted: {err}");
                    }
                    ZfsTxOutcome::Uncertain { reason, .. } => {
                        bail!("ZFS TXG recv Uncertain: {reason}");
                    }
                }
            }
            Self::RecvAbort { pool } => {
                let (mut engine, components) = pool.open_engine(cx)?;
                match engine.abort_receive(cx, &components) {
                    ZfsTxOutcome::Committed { value, token } => {
                        engine
                            .verify_token(&token)
                            .context("verifying storage/topology/TXG-bound ZFS durable token")?;
                        json(&serde_json::json!({
                            "format": "ZFS",
                            "operation": "recv_abort",
                            "outcome": "Committed",
                            "dataset": pool.dataset,
                            "reclaimed_bytes": value,
                            "committed_txg": engine.committed_txg(),
                            "published_slot": engine.committed_slot(),
                            "token": token,
                        }))
                    }
                    ZfsTxOutcome::NotCommitted(err) => {
                        bail!("ZFS TXG recv_abort NotCommitted: {err}");
                    }
                    ZfsTxOutcome::Uncertain { reason, .. } => {
                        bail!("ZFS TXG recv_abort Uncertain: {reason}");
                    }
                }
            }
            Self::RecvTokenInspect {
                token,
                image,
                offline_image,
                offset,
                length,
                auto_import,
                label,
                slot,
                pool_guid,
                members,
                dataset,
            } => {
                if let Some(raw_token) = token {
                    let parsed = ReceiveResumeToken::parse(&raw_token)
                        .map_err(|e| anyhow::anyhow!("invalid receive_resume_token: {e}"))?;
                    return json(&serde_json::json!({
                        "format": "ZFS",
                        "operation": "recv_token_inspect",
                        "source": "token",
                        "toguid": parsed.toguid,
                        "fromguid": parsed.fromguid,
                        "object": parsed.object,
                        "offset": parsed.offset,
                        "bytes": parsed.bytes,
                        "toname": parsed.toname,
                        "compressok": parsed.compressok,
                        "embedok": parsed.embedok,
                        "largeblockok": parsed.largeblockok,
                        "rawok": parsed.rawok,
                        "saved": parsed.saved,
                        "ivsetguid": parsed.ivsetguid,
                    }));
                }
                let Some(image_path) = image else {
                    bail!("either --token or an offline ZFS image path is required");
                };
                if !offline_image {
                    bail!("--offline-image is required when inspecting a pool image");
                }
                if !auto_import && pool_guid == 0 {
                    bail!("--pool-guid is required unless --auto-import is set");
                }
                let candidate = CandidateArgs {
                    image: super::ImageArgs {
                        image: image_path,
                        offset,
                        length,
                        offline_image,
                        sidecar: None,
                    },
                    auto_import,
                    replay_zil: false,
                    label,
                    slot,
                    pool_guid,
                    members,
                    draid_members: Vec::new(),
                    missing_mirror_members: Vec::new(),
                    missing_raidz_members: Vec::new(),
                    missing_draid_members: Vec::new(),
                };
                let components = parse_dataset_components(&dataset)?;
                let mut mos = candidate.objects(cx)?;
                let state = inspect_receive_resume_state_in_mos(cx, &mut mos, &components)?;
                json(&serde_json::json!({
                    "format": "ZFS",
                    "operation": "recv_token_inspect",
                    "source": "pool",
                    "dataset": dataset,
                    "resume_state": state,
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use clap::Parser;

    #[test]
    fn cli_send_recv_authority_and_flag_conflicts() {
        // Read-only `send` parses with CandidateArgs (no --allow-write!) and supports -i/-I/-w/-c/-e/-L/-p/-t.
        assert!(
            Cli::try_parse_from([
                "ffs-zfs",
                "send",
                "src.img",
                "--offline-image",
                "--pool-guid",
                "123",
                "--label",
                "0",
                "--slot",
                "2",
                "--dataset",
                "data",
                "--snapshot",
                "s2",
                "--from-snapshot",
                "s1",
                "-I",
                "-w",
                "-c",
                "-e",
                "-L",
                "-p",
                "--out",
                "/tmp/stream.zfs",
            ])
            .is_ok()
        );
        // `--from-snapshot` and `--from-bookmark` conflict.
        assert!(
            Cli::try_parse_from([
                "ffs-zfs",
                "send",
                "src.img",
                "--offline-image",
                "--pool-guid",
                "123",
                "--label",
                "0",
                "--slot",
                "2",
                "--dataset",
                "data",
                "--snapshot",
                "s2",
                "--from-snapshot",
                "s1",
                "--from-bookmark",
                "bm1",
            ])
            .is_err()
        );
        // `send` with `--resume-token` does not require `--snapshot`.
        assert!(
            Cli::try_parse_from([
                "ffs-zfs",
                "send",
                "src.img",
                "--offline-image",
                "--pool-guid",
                "123",
                "--label",
                "0",
                "--slot",
                "2",
                "--dataset",
                "data",
                "--resume-token",
                "1-deadbeef-10-789c",
            ])
            .is_ok()
        );
        // `recv` and `recv-abort` MUST fail clap parsing without `--allow-write` or `--offline-image`.
        for sub in ["recv", "recv-abort"] {
            assert!(
                Cli::try_parse_from([
                    "ffs-zfs",
                    sub,
                    "dst.img",
                    "--offline-image",
                    "--pool-guid",
                    "123",
                    "--label",
                    "0",
                    "--slot",
                    "2",
                    "--dataset",
                    "data/dst",
                ])
                .is_err()
            );
            assert!(
                Cli::try_parse_from([
                    "ffs-zfs",
                    sub,
                    "dst.img",
                    "--allow-write",
                    "--pool-guid",
                    "123",
                    "--label",
                    "0",
                    "--slot",
                    "2",
                    "--dataset",
                    "data/dst",
                ])
                .is_err()
            );
            assert!(
                Cli::try_parse_from([
                    "ffs-zfs",
                    sub,
                    "dst.img",
                    "--offline-image",
                    "--allow-write",
                    "--pool-guid",
                    "123",
                    "--label",
                    "0",
                    "--slot",
                    "2",
                    "--dataset",
                    "data/dst",
                ])
                .is_ok()
            );
        }
        // `recv` flags (`-s`, `-F`, `--checkpoint-bytes`, `--snapshot`, `--in`).
        let parsed = Cli::try_parse_from([
            "ffs-zfs",
            "recv",
            "dst.img",
            "--offline-image",
            "--allow-write",
            "--pool-guid",
            "123",
            "--label",
            "0",
            "--slot",
            "2",
            "--dataset",
            "data/dst",
            "-s",
            "-F",
            "--checkpoint-bytes",
            "8192",
            "--snapshot",
            "custom_snap",
            "--in",
            "/tmp/in.zfs",
        ])
        .unwrap();
        let crate::Command::SendRecv(SendRecvCommand::Recv {
            resumable,
            force,
            checkpoint_bytes,
            snapshot,
            input,
            ..
        }) = parsed.command
        else {
            panic!("expected Recv");
        };
        assert!(resumable && force);
        assert_eq!(checkpoint_bytes, 8192);
        assert_eq!(snapshot, Some(OsString::from("custom_snap")));
        assert_eq!(input, Some(PathBuf::from("/tmp/in.zfs")));

        // `recv` rejects zero `--checkpoint-bytes`.
        assert!(
            Cli::try_parse_from([
                "ffs-zfs",
                "recv",
                "dst.img",
                "--offline-image",
                "--allow-write",
                "--pool-guid",
                "123",
                "--label",
                "0",
                "--slot",
                "2",
                "--dataset",
                "data/dst",
                "--checkpoint-bytes",
                "0",
            ])
            .is_err()
        );

        // `recv-token-inspect --token` parses offline without any image path or --allow-write.
        assert!(
            Cli::try_parse_from(["ffs-zfs", "recv-token-inspect", "--token", "1-0-0-"]).is_ok()
        );
        // `recv-token-inspect --token` rejects conflicting image path.
        assert!(
            Cli::try_parse_from([
                "ffs-zfs",
                "recv-token-inspect",
                "dst.img",
                "--token",
                "1-0-0-",
            ])
            .is_err()
        );
    }

    #[test]
    fn recv_token_inspect_parses_token_offline_without_touching_host_paths() {
        let tok = ReceiveResumeToken {
            toguid: 0x1122_3344_5566_7788,
            fromguid: Some(0x99aa_bbcc_ddee_ff00),
            object: 42,
            offset: 65_536,
            bytes: 131_072,
            toname: "/etc/passwd/../../../evil@snap1".to_owned(),
            compressok: true,
            embedok: true,
            largeblockok: true,
            rawok: true,
            saved: false,
            ivsetguid: Some(0x7777_8888_9999_aaaa),
        };
        let encoded = tok.encode().unwrap();
        let parsed = ReceiveResumeToken::parse(&encoded).unwrap();
        assert_eq!(parsed, tok);
    }
}
