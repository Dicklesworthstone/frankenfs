//! Explicit offline ZFS native TXG writer admission and ZPL mutation subcommands.
//!
//! All write subcommands require `--offline-image`, `--allow-write`, `--pool-guid`,
//! `--label`, and `--slot`. Active pools, active MMP, pending ZIL, and torn Uberblock
//! rings (unless `--reconcile-torn-uberblocks` is explicitly passed) fail closed
//! before mutating pool data.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::{Args, Subcommand};
use ffs_ondisk::zfs_zpl::Timestamp;
use ffs_zfs::{Leaf, ZfsDataChecksum, ZfsTransactionEngine, ZfsTxOutcome, ZfsWriteOptions};

use super::json;

#[derive(Debug, Args)]
pub struct AdmitArgs {
    /// Offline ZFS regular file image (primary leaf or first mirror member).
    pub image: PathBuf,
    /// Acknowledge that the image is an unmounted offline file, not a live block device.
    #[arg(long, required = true)]
    pub offline_image: bool,
    /// Partition byte offset within each backing member file.
    #[arg(long, default_value_t = 0, requires = "length")]
    pub offset: u64,
    /// Partition byte length within each backing member file.
    #[arg(long)]
    pub length: Option<u64>,
    /// Additional mirror/vdev member images in explicit pool order.
    #[arg(long = "member", visible_aliases = ["mirror-member", "raidz-member"])]
    pub members: Vec<PathBuf>,
    /// Explicit label index (`0..=3`) for Uberblock candidate admission.
    #[arg(long, value_parser = clap::value_parser!(u64).range(0..=3))]
    pub label: u64,
    /// Explicit Uberblock ring slot index.
    #[arg(long, value_parser = clap::value_parser!(u64).range(0..128))]
    pub slot: u64,
    /// Expected `pool_guid` pinned by the caller.
    #[arg(long)]
    pub pool_guid: u64,
}

#[derive(Debug, Args)]
pub struct WritePoolArgs {
    /// Offline ZFS regular file image (primary leaf or first mirror member).
    pub image: PathBuf,
    /// Acknowledge that the image is an unmounted offline file, not a live block device.
    #[arg(long, required = true)]
    pub offline_image: bool,
    /// Explicitly authorize native ZFS TXG allocation, COW DMU writes, and 4-label Uberblock publication.
    #[arg(long, required = true)]
    pub allow_write: bool,
    /// Partition byte offset within each backing member file.
    #[arg(long, default_value_t = 0, requires = "length")]
    pub offset: u64,
    /// Partition byte length within each backing member file.
    #[arg(long)]
    pub length: Option<u64>,
    /// Additional mirror member images in explicit pool order.
    #[arg(long = "member", visible_aliases = ["mirror-member"])]
    pub members: Vec<PathBuf>,
    /// Explicit label index (`0..=3`) for pinned predecessor Uberblock admission.
    #[arg(long, value_parser = clap::value_parser!(u64).range(0..=3))]
    pub label: u64,
    /// Explicit Uberblock ring slot index for pinned predecessor Uberblock admission.
    #[arg(long, value_parser = clap::value_parser!(u64).range(0..128))]
    pub slot: u64,
    /// Expected `pool_guid` pinned by the caller.
    #[arg(long)]
    pub pool_guid: u64,
    /// Relative head dataset name (`""` selects the pool root dataset).
    #[arg(long, default_value = "")]
    pub dataset: String,
    /// Explicitly synchronize a torn/split Uberblock ring across all 4 labels after full scrub.
    #[arg(long)]
    pub reconcile_torn_uberblocks: bool,
    /// Deterministic POSIX seconds timestamp recorded on modified ZPL nodes and published Uberblock.
    #[arg(long, default_value_t = 1_710_000_000)]
    pub timestamp: i64,
    /// Stamp newly written file data blocks with `ZIO_CHECKSUM_SHA256` instead of `Fletcher4`.
    #[arg(long)]
    pub sha256: bool,
}

impl WritePoolArgs {
    fn open_engine(&self, cx: &Cx) -> Result<(ZfsTransactionEngine, Vec<Vec<u8>>)> {
        if self.members.len() > 7 {
            bail!("at most seven additional member images are supported");
        }
        let components = parse_dataset_components(&self.dataset)?;
        let mut all_paths: Vec<&Path> = Vec::with_capacity(1 + self.members.len());
        all_paths.push(self.image.as_path());
        for m in &self.members {
            all_paths.push(m.as_path());
        }
        let options = ZfsWriteOptions {
            offline_image: self.offline_image,
            allow_write: self.allow_write,
            pool_guid: self.pool_guid,
            label: self.label as usize,
            slot: self.slot as usize,
            reconcile_torn_uberblocks: self.reconcile_torn_uberblocks,
        };
        let engine =
            ZfsTransactionEngine::open_files_at(cx, &all_paths, self.offset, self.length, options)
                .with_context(|| {
                    format!("admitting ZFS native writer on {}", self.image.display())
                })?;
        Ok((engine, components))
    }

    const fn zpl_timestamp(&self) -> Timestamp {
        Timestamp {
            seconds: self.timestamp,
            nanos: 0,
        }
    }

    const fn data_checksum(&self) -> ZfsDataChecksum {
        if self.sha256 {
            ZfsDataChecksum::Sha256
        } else {
            ZfsDataChecksum::Fletcher4
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum WriteCommand {
    /// Dry-run ZFS native TXG writer admission without opening writable FDs or modifying bytes.
    AdmitWrite {
        #[command(flatten)]
        args: AdmitArgs,
    },
    /// Create a new regular file in a ZPL head dataset and publish a committed TXG.
    TxCreate {
        #[command(flatten)]
        pool: WritePoolArgs,
        /// Target ZPL path inside the selected dataset (e.g. `/dir/file.txt`).
        path: PathBuf,
        /// Octal (e.g. `0644`) or decimal permission bits.
        #[arg(long, default_value = "0644")]
        mode: String,
        #[arg(long, default_value_t = 0)]
        uid: u64,
        #[arg(long, default_value_t = 0)]
        gid: u64,
    },
    /// Create a new directory in a ZPL head dataset and publish a committed TXG.
    TxMkdir {
        #[command(flatten)]
        pool: WritePoolArgs,
        /// Target ZPL directory path inside the selected dataset (e.g. `/dir/sub`).
        path: PathBuf,
        /// Octal (e.g. `0755`) or decimal permission bits.
        #[arg(long, default_value = "0755")]
        mode: String,
        #[arg(long, default_value_t = 0)]
        uid: u64,
        #[arg(long, default_value_t = 0)]
        gid: u64,
    },
    /// Write bytes into an existing regular ZPL file and publish a committed TXG.
    TxWrite {
        #[command(flatten)]
        pool: WritePoolArgs,
        /// Target ZPL regular-file path inside the selected dataset.
        path: PathBuf,
        /// Byte offset inside the file at which to write.
        #[arg(long, default_value_t = 0)]
        write_offset: u64,
        /// UTF-8 literal payload to write.
        #[arg(long, conflicts_with_all = ["data_file", "empty"])]
        data: Option<String>,
        /// Host file whose bytes will be written into the ZPL file.
        #[arg(long, conflicts_with_all = ["data", "empty"])]
        data_file: Option<PathBuf>,
        /// Explicitly write zero bytes.
        #[arg(long, conflicts_with_all = ["data", "data_file"])]
        empty: bool,
    },
    /// Truncate or extend a regular ZPL file to `--size` bytes and publish a committed TXG.
    TxTruncate {
        #[command(flatten)]
        pool: WritePoolArgs,
        /// Target ZPL regular-file path inside the selected dataset.
        path: PathBuf,
        /// Target logical file size in bytes.
        #[arg(long)]
        size: u64,
    },
    /// Create another name for a regular file in the same ZPL head dataset.
    TxLink {
        #[command(flatten)]
        pool: WritePoolArgs,
        /// Existing regular-file path inside the selected dataset.
        src_path: PathBuf,
        /// New path inside the same dataset; it must not already exist.
        dst_path: PathBuf,
    },
    /// Rename a ZPL file or directory within a head dataset and publish a committed TXG.
    TxRename {
        #[command(flatten)]
        pool: WritePoolArgs,
        /// Existing ZPL source path inside the selected dataset.
        src_path: PathBuf,
        /// Target ZPL destination path inside the selected dataset.
        dst_path: PathBuf,
        /// Optional idempotency guard refusing duplicate renames if the source object changed.
        #[arg(long)]
        expected_object: Option<u64>,
    },
    /// Unlink a regular ZPL file (or remove an empty directory with `--rmdir`) and publish a TXG.
    TxUnlink {
        #[command(flatten)]
        pool: WritePoolArgs,
        /// Existing ZPL path inside the selected dataset.
        path: PathBuf,
        /// Remove an empty directory instead of unlinking a regular file.
        #[arg(long)]
        rmdir: bool,
    },
}

fn parse_dataset_components(dataset: &str) -> Result<Vec<Vec<u8>>> {
    if dataset.is_empty() {
        return Ok(Vec::new());
    }
    if dataset.starts_with('/') || dataset.ends_with('/') || dataset.contains("//") {
        bail!("dataset path must be relative without leading, trailing, or empty components");
    }
    let mut out = Vec::new();
    for part in dataset.split('/') {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.contains('@')
            || part.contains('#')
        {
            bail!("invalid dataset component `{part}`");
        }
        out.push(part.as_bytes().to_vec());
    }
    Ok(out)
}

fn parse_mode_bits(raw: &str) -> Result<u16> {
    let trimmed = raw.trim();
    let parsed = if let Some(oct) = trimmed
        .strip_prefix("0o")
        .or_else(|| trimmed.strip_prefix("0O"))
    {
        u16::from_str_radix(oct, 8).with_context(|| format!("invalid octal mode `{raw}`"))?
    } else if trimmed.starts_with('0')
        && trimmed.len() > 1
        && trimmed.bytes().all(|b| (b'0'..=b'7').contains(&b))
    {
        u16::from_str_radix(trimmed, 8).with_context(|| format!("invalid octal mode `{raw}`"))?
    } else {
        trimmed
            .parse::<u16>()
            .with_context(|| format!("invalid mode `{raw}`"))?
    };
    Ok(parsed & 0o7777)
}

fn split_parent_and_leaf(path: &OsStr) -> Result<(Vec<u8>, Vec<u8>)> {
    let raw = path.as_bytes();
    let trimmed = raw
        .iter()
        .rposition(|&b| b != b'/')
        .map_or(&[][..], |end| &raw[..=end]);
    if trimmed.is_empty() {
        bail!("ZPL mutation target cannot be the dataset root `/`");
    }
    if let Some(pos) = trimmed.iter().rposition(|&b| b == b'/') {
        let parent = if pos == 0 {
            b"/".to_vec()
        } else {
            trimmed[..pos].to_vec()
        };
        let name = trimmed[pos + 1..].to_vec();
        if name.is_empty() || name == b"." || name == b".." {
            bail!("invalid final ZPL path component");
        }
        Ok((parent, name))
    } else {
        if trimmed == b"." || trimmed == b".." {
            bail!("invalid final ZPL path component");
        }
        Ok((b"/".to_vec(), trimmed.to_vec()))
    }
}

fn resolve_parent_dir(
    cx: &Cx,
    engine: &ZfsTransactionEngine,
    components: &[Vec<u8>],
    parent_path: &[u8],
) -> Result<u64> {
    let mut mos = engine.open_read_objects(cx)?;
    let mut zpl = mos.zpl(cx, components)?;
    Ok(zpl.resolve(cx, parent_path)?)
}

fn resolve_target_object(
    cx: &Cx,
    engine: &ZfsTransactionEngine,
    components: &[Vec<u8>],
    path: &OsStr,
) -> Result<u64> {
    let mut mos = engine.open_read_objects(cx)?;
    let mut zpl = mos.zpl(cx, components)?;
    Ok(zpl.resolve(cx, path.as_bytes())?)
}

fn emit_tx_outcome(
    operation: &'static str,
    dataset: &str,
    engine: &ZfsTransactionEngine,
    outcome: ZfsTxOutcome<u64>,
) -> Result<()> {
    match outcome {
        ZfsTxOutcome::Committed { value, token } => {
            engine
                .verify_token(&token)
                .context("verifying storage/topology/TXG-bound ZFS durable token")?;
            json(&serde_json::json!({
                "format": "ZFS",
                "operation": operation,
                "outcome": "Committed",
                "dataset": dataset,
                "result": value,
                "committed_txg": engine.committed_txg(),
                "published_slot": engine.committed_slot(),
                "token": token,
            }))
        }
        ZfsTxOutcome::NotCommitted(err) => {
            bail!("ZFS TXG {operation} NotCommitted (prior TXG preserved): {err}");
        }
        ZfsTxOutcome::Uncertain {
            reason,
            target_txg,
            target_slot,
        } => {
            bail!("ZFS TXG {operation} Uncertain at txg={target_txg} slot={target_slot}: {reason}");
        }
    }
}

impl WriteCommand {
    pub fn run(self, cx: &Cx) -> Result<()> {
        match self {
            Self::AdmitWrite { args } => {
                if !args.offline_image {
                    bail!("ZFS writer admission requires --offline-image");
                }
                if args.members.len() > 7 {
                    bail!("at most seven additional member images are supported");
                }
                let mut leaves = Vec::with_capacity(1 + args.members.len());
                for path in std::iter::once(&args.image).chain(&args.members) {
                    leaves.push(
                        Leaf::open(cx, path, args.offset, args.length)
                            .with_context(|| format!("opening ZFS member {}", path.display()))?,
                    );
                }
                let report = ZfsTransactionEngine::inspect_admission(
                    cx,
                    leaves,
                    ZfsWriteOptions {
                        offline_image: args.offline_image,
                        allow_write: true,
                        pool_guid: args.pool_guid,
                        label: args.label as usize,
                        slot: args.slot as usize,
                        reconcile_torn_uberblocks: false,
                    },
                )?;
                json(&serde_json::json!({
                    "format": "ZFS",
                    "operation": "admit_write",
                    "backing_writes": false,
                    "admission": report,
                }))
            }
            Self::TxCreate {
                pool,
                path,
                mode,
                uid,
                gid,
            } => {
                let perm = parse_mode_bits(&mode)?;
                let (parent_path, name) = split_parent_and_leaf(path.as_os_str())?;
                let (mut engine, components) = pool.open_engine(cx)?;
                let parent_dir = resolve_parent_dir(cx, &engine, &components, &parent_path)?;
                let outcome = engine.create_file(
                    cx,
                    &components,
                    parent_dir,
                    &name,
                    perm,
                    uid,
                    gid,
                    pool.zpl_timestamp(),
                    pool.data_checksum(),
                );
                emit_tx_outcome("tx_create", &pool.dataset, &engine, outcome)
            }
            Self::TxMkdir {
                pool,
                path,
                mode,
                uid,
                gid,
            } => {
                let perm = parse_mode_bits(&mode)?;
                let (parent_path, name) = split_parent_and_leaf(path.as_os_str())?;
                let (mut engine, components) = pool.open_engine(cx)?;
                let parent_dir = resolve_parent_dir(cx, &engine, &components, &parent_path)?;
                let outcome = engine.mkdir(
                    cx,
                    &components,
                    parent_dir,
                    &name,
                    perm,
                    uid,
                    gid,
                    pool.zpl_timestamp(),
                );
                emit_tx_outcome("tx_mkdir", &pool.dataset, &engine, outcome)
            }
            Self::TxWrite {
                pool,
                path,
                write_offset,
                data,
                data_file,
                empty,
            } => {
                let payload = match (data, data_file, empty) {
                    (Some(text), None, false) => text.into_bytes(),
                    (None, Some(host_path), false) => std::fs::read(&host_path)
                        .with_context(|| format!("reading --data-file {}", host_path.display()))?,
                    (None, None, true) => Vec::new(),
                    _ => bail!("specify exactly one of --data, --data-file, or --empty"),
                };
                let (mut engine, components) = pool.open_engine(cx)?;
                let file_obj = resolve_target_object(cx, &engine, &components, path.as_os_str())?;
                let outcome = engine.write_file_data(
                    cx,
                    &components,
                    file_obj,
                    write_offset,
                    &payload,
                    pool.zpl_timestamp(),
                    pool.data_checksum(),
                );
                emit_tx_outcome("tx_write", &pool.dataset, &engine, outcome)
            }
            Self::TxTruncate { pool, path, size } => {
                let (mut engine, components) = pool.open_engine(cx)?;
                let file_obj = resolve_target_object(cx, &engine, &components, path.as_os_str())?;
                let outcome = engine.truncate_file(
                    cx,
                    &components,
                    file_obj,
                    size,
                    pool.zpl_timestamp(),
                    pool.data_checksum(),
                );
                emit_tx_outcome("tx_truncate", &pool.dataset, &engine, outcome)
            }
            Self::TxLink {
                pool,
                src_path,
                dst_path,
            } => {
                let (parent_path, name) = split_parent_and_leaf(dst_path.as_os_str())?;
                let (mut engine, components) = pool.open_engine(cx)?;
                let source = resolve_target_object(cx, &engine, &components, src_path.as_os_str())?;
                let parent_dir = resolve_parent_dir(cx, &engine, &components, &parent_path)?;
                let outcome = engine.link_entry(
                    cx,
                    &components,
                    source,
                    parent_dir,
                    &name,
                    pool.zpl_timestamp(),
                );
                emit_tx_outcome("tx_link", &pool.dataset, &engine, outcome)
            }
            Self::TxRename {
                pool,
                src_path,
                dst_path,
                expected_object,
            } => {
                let (src_parent, src_name) = split_parent_and_leaf(src_path.as_os_str())?;
                let (dst_parent, dst_name) = split_parent_and_leaf(dst_path.as_os_str())?;
                let (mut engine, components) = pool.open_engine(cx)?;
                let src_dir = resolve_parent_dir(cx, &engine, &components, &src_parent)?;
                let dst_dir = resolve_parent_dir(cx, &engine, &components, &dst_parent)?;
                let outcome = engine.rename_entry(
                    cx,
                    &components,
                    src_dir,
                    &src_name,
                    dst_dir,
                    &dst_name,
                    expected_object,
                    pool.zpl_timestamp(),
                );
                emit_tx_outcome("tx_rename", &pool.dataset, &engine, outcome)
            }
            Self::TxUnlink { pool, path, rmdir } => {
                let (parent_path, name) = split_parent_and_leaf(path.as_os_str())?;
                let (mut engine, components) = pool.open_engine(cx)?;
                let parent_dir = resolve_parent_dir(cx, &engine, &components, &parent_path)?;
                let outcome = engine.unlink_entry(
                    cx,
                    &components,
                    parent_dir,
                    &name,
                    rmdir,
                    pool.zpl_timestamp(),
                );
                emit_tx_outcome("tx_unlink", &pool.dataset, &engine, outcome)
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
    fn cli_write_subcommands_require_explicit_offline_and_write_flags() {
        // Missing --offline-image fails clap parsing.
        assert!(
            Cli::try_parse_from([
                "ffs-zfs",
                "admit-write",
                "leaf.img",
                "--pool-guid",
                "123",
                "--label",
                "0",
                "--slot",
                "2",
            ])
            .is_err()
        );
        // Missing --allow-write on mutating tx-mkdir fails clap parsing.
        assert!(
            Cli::try_parse_from([
                "ffs-zfs",
                "tx-mkdir",
                "leaf.img",
                "/sub",
                "--offline-image",
                "--pool-guid",
                "123",
                "--label",
                "0",
                "--slot",
                "2",
            ])
            .is_err()
        );
        // Complete explicit flags parse cleanly.
        assert!(
            Cli::try_parse_from([
                "ffs-zfs",
                "tx-write",
                "leaf.img",
                "/dir/hello.txt",
                "--offline-image",
                "--allow-write",
                "--pool-guid",
                "123",
                "--label",
                "0",
                "--slot",
                "2",
                "--dataset",
                "data",
                "--write-offset",
                "64",
                "--data",
                "payload",
                "--sha256",
            ])
            .is_ok()
        );
    }

    #[test]
    fn cli_hard_link_requires_both_paths_and_explicit_write_authority() {
        let base = [
            "ffs-zfs",
            "tx-link",
            "leaf.img",
            "/source",
            "/new-name",
            "--pool-guid",
            "123",
            "--label",
            "0",
            "--slot",
            "2",
            "--dataset",
            "data",
        ];
        for flags in [vec![], vec!["--offline-image"], vec!["--allow-write"]] {
            assert!(Cli::try_parse_from(base.into_iter().chain(flags)).is_err());
        }
        let args =
            Cli::try_parse_from(base.into_iter().chain(["--offline-image", "--allow-write"]))
                .unwrap();
        let crate::Command::Write(WriteCommand::TxLink { .. }) = args.command else {
            panic!("tx-link must dispatch to the native writer");
        };
        assert!(
            Cli::try_parse_from([
                "ffs-zfs",
                "tx-link",
                "leaf.img",
                "/source",
                "--offline-image",
                "--allow-write",
                "--pool-guid",
                "123",
                "--label",
                "0",
                "--slot",
                "2",
            ])
            .is_err()
        );
    }

    #[test]
    fn split_parent_and_mode_helpers_reject_invalid_inputs() {
        assert!(split_parent_and_leaf(OsStr::new("/")).is_err());
        assert_eq!(
            split_parent_and_leaf(OsStr::new("/alpha")).unwrap(),
            (b"/".to_vec(), b"alpha".to_vec())
        );
        assert_eq!(
            split_parent_and_leaf(OsStr::new("/dir/sub/beta/")).unwrap(),
            (b"/dir/sub".to_vec(), b"beta".to_vec())
        );
        assert_eq!(parse_mode_bits("0644").unwrap(), 0o644);
        assert_eq!(parse_mode_bits("0o755").unwrap(), 0o755);
        assert_eq!(parse_mode_bits("420").unwrap(), 420);
    }
}
