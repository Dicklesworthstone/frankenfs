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
use ffs_zfs::{
    Leaf, ZfsDataChecksum, ZfsMountWriteOptions, ZfsPosixSetAttr, ZfsPropertySetValue,
    ZfsTransactionEngine, ZfsTxOutcome, ZfsWriteOptions, ZfsXattrSetMode,
};

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
    /// Mount one head dataset using the explicitly admitted synchronous native TXG writer.
    MountWrite {
        #[command(flatten)]
        target: AdmitArgs,
        /// Existing empty host directory outside every backing image's path.
        mountpoint: PathBuf,
        /// Explicitly authorize native allocation and durable pool mutations.
        #[arg(long, required = true)]
        allow_write: bool,
        /// Relative head dataset name; empty selects the pool root dataset.
        #[arg(long, default_value = "")]
        dataset: String,
        /// Reconcile split uberblock copies after complete writer admission.
        #[arg(long)]
        reconcile_torn_uberblocks: bool,
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
    /// Create an atomic DSL snapshot (`<dataset>@<snap_name>`) and publish a TXG.
    TxSnapshot {
        #[command(flatten)]
        pool: WritePoolArgs,
        /// Snapshot name component (without `@`, `/`, or `#`).
        snap_name: String,
    },
    /// Destroy `<dataset>@<snap_name>` (or defer destroy with `--defer` when held/cloned).
    TxDestroySnapshot {
        #[command(flatten)]
        pool: WritePoolArgs,
        /// Snapshot name component to destroy.
        snap_name: String,
        /// Set `DS_FLAG_DEFER_DESTROY` instead of failing with `EBUSY` if holds or clones exist.
        #[arg(long)]
        defer: bool,
    },
    /// Rename `<dataset>@<old_snap_name>` to `<dataset>@<new_snap_name>` and publish a TXG.
    TxRenameSnapshot {
        #[command(flatten)]
        pool: WritePoolArgs,
        old_snap_name: String,
        new_snap_name: String,
    },
    /// Place a user hold `<tag>` on `<dataset>@<snap_name>` (`DMU_OT_USERREFS`).
    TxHold {
        #[command(flatten)]
        pool: WritePoolArgs,
        snap_name: String,
        tag: String,
    },
    /// Release user hold `<tag>` on `<dataset>@<snap_name>` (auto-destroying if deferred and unreferenced).
    TxRelease {
        #[command(flatten)]
        pool: WritePoolArgs,
        snap_name: String,
        tag: String,
    },
    /// Create a bookmark `<dataset>#<bookmark_name>` from `--snapshot <snap>` or `--source-bookmark <bm>`.
    TxBookmark {
        #[command(flatten)]
        pool: WritePoolArgs,
        bookmark_name: String,
        /// Source snapshot name on the same dataset.
        #[arg(long, conflicts_with = "source_bookmark")]
        snapshot: Option<String>,
        /// Source bookmark name on the same dataset.
        #[arg(long, conflicts_with = "snapshot")]
        source_bookmark: Option<String>,
    },
    /// Destroy bookmark `<dataset>#<bookmark_name>` and publish a TXG.
    TxDestroyBookmark {
        #[command(flatten)]
        pool: WritePoolArgs,
        bookmark_name: String,
    },
    /// Create a fresh child ZPL filesystem dataset `<dataset>/<child_name>` and publish a TXG.
    TxCreateDataset {
        #[command(flatten)]
        pool: WritePoolArgs,
        /// Single child dataset name component created beneath `--dataset`.
        child_name: String,
        /// Initial property assignment `name=value` (repeatable).
        #[arg(long = "prop")]
        props: Vec<String>,
    },
    /// Create a writable clone dataset `<target_dataset>` from `<dataset>@<origin_snap>`.
    TxClone {
        #[command(flatten)]
        pool: WritePoolArgs,
        /// Origin snapshot name on `--dataset`.
        origin_snap: String,
        /// Pool-relative target clone dataset path (e.g. `data/clone1` or `clone_root`).
        target_dataset: String,
        /// Initial property assignment `name=value` on the clone (repeatable).
        #[arg(long = "prop")]
        props: Vec<String>,
    },
    /// Rename non-root dataset `--dataset` to `<new_dataset>` (transferring parent space/reservations).
    TxRenameDataset {
        #[command(flatten)]
        pool: WritePoolArgs,
        /// New pool-relative dataset path.
        new_dataset: String,
    },
    /// Destroy leaf dataset or clone `--dataset` (pruning `birth > origin_txg` blocks).
    TxDestroyDataset {
        #[command(flatten)]
        pool: WritePoolArgs,
    },
    /// Set a native or user (`ns:name`) property on `--dataset` and publish a TXG.
    TxSetProp {
        #[command(flatten)]
        pool: WritePoolArgs,
        property: String,
        value: String,
    },
    /// Inherit (clear local value of) a property on `--dataset` and publish a TXG.
    TxInheritProp {
        #[command(flatten)]
        pool: WritePoolArgs,
        property: String,
    },
    /// Update POSIX mode, uid, gid, size, or timestamps on an existing ZPL node in one TXG.
    TxSetattr {
        #[command(flatten)]
        pool: WritePoolArgs,
        /// Target ZPL path inside `--dataset` (`/` is allowed for dataset root chmod/chown/utimes).
        path: PathBuf,
        #[arg(long)]
        mode: Option<String>,
        #[arg(long)]
        uid: Option<u64>,
        #[arg(long)]
        gid: Option<u64>,
        #[arg(long)]
        size: Option<u64>,
        #[arg(long)]
        atime_sec: Option<i64>,
        #[arg(long)]
        mtime_sec: Option<i64>,
        #[arg(long)]
        clear_suid_sgid: bool,
    },
    /// Set or replace a `user.*` SA extended attribute (`ZPL_DXATTR` inline or spill) in one TXG.
    TxSetxattr {
        #[command(flatten)]
        pool: WritePoolArgs,
        /// Target ZPL path inside `--dataset`.
        path: PathBuf,
        /// Extended attribute name (`user.<name>`).
        name: String,
        /// UTF-8 attribute value.
        #[arg(long, conflicts_with = "value_file")]
        value: Option<String>,
        /// Host file containing raw binary xattr bytes.
        #[arg(long, conflicts_with = "value")]
        value_file: Option<PathBuf>,
        /// Fail if the xattr already exists (`XATTR_CREATE`).
        #[arg(long, conflicts_with = "replace")]
        create: bool,
        /// Fail if the xattr does not already exist (`XATTR_REPLACE`).
        #[arg(long, conflicts_with = "create")]
        replace: bool,
    },
    /// Remove a `user.*` SA extended attribute in one TXG.
    TxRmxattr {
        #[command(flatten)]
        pool: WritePoolArgs,
        /// Target ZPL path inside `--dataset`.
        path: PathBuf,
        /// Extended attribute name (`user.<name>`).
        name: String,
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

fn writable_mountpoint(target: &AdmitArgs, path: &Path) -> Result<PathBuf> {
    let mountpoint = path.canonicalize().context("resolve ZFS mountpoint")?;
    if !mountpoint.is_dir()
        || std::fs::read_dir(&mountpoint)?
            .next()
            .transpose()?
            .is_some()
    {
        bail!("ZFS mountpoint must be an existing empty directory");
    }
    for image in std::iter::once(&target.image).chain(&target.members) {
        if image.canonicalize()?.starts_with(&mountpoint) {
            bail!("ZFS mountpoint would hide a backing image");
        }
    }
    Ok(mountpoint)
}

fn parse_size_or_u64(raw: &str) -> Result<u64> {
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("none") {
        return Ok(0);
    }
    let (digits, mult) = match trimmed.as_bytes().last().copied() {
        Some(b'k' | b'K') => (&trimmed[..trimmed.len() - 1], 1024_u64),
        Some(b'm' | b'M') => (&trimmed[..trimmed.len() - 1], 1024_u64 * 1024),
        Some(b'g' | b'G') => (&trimmed[..trimmed.len() - 1], 1024_u64 * 1024 * 1024),
        Some(b't' | b'T') => (&trimmed[..trimmed.len() - 1], 1024_u64 * 1024 * 1024 * 1024),
        _ => (trimmed, 1_u64),
    };
    let base: u64 = digits
        .parse()
        .with_context(|| format!("invalid integer/size property value `{raw}`"))?;
    base.checked_mul(mult)
        .ok_or_else(|| anyhow::anyhow!("property size `{raw}` overflows u64"))
}

fn parse_property_set_value(name: &str, raw: &str) -> Result<ZfsPropertySetValue> {
    if name.contains(':') {
        return Ok(ZfsPropertySetValue::Text(raw.as_bytes().to_vec()));
    }
    let norm = raw.trim().to_ascii_lowercase();
    let num = match name {
        "readonly" | "atime" => match norm.as_str() {
            "on" | "1" | "true" => 1,
            "off" | "0" | "false" => 0,
            _ => bail!("boolean property `{name}` expects `on` or `off`, got `{raw}`"),
        },
        "checksum" => match norm.as_str() {
            "on" | "1" => 1,
            "fletcher4" | "7" => 7,
            "sha256" | "8" => 8,
            _ => bail!("checksum property expects `on`, `fletcher4`, or `sha256`, got `{raw}`"),
        },
        "quota" | "refquota" | "reservation" | "refreservation" | "recordsize" => {
            parse_size_or_u64(raw)?
        }
        _ => parse_size_or_u64(raw)?,
    };
    Ok(ZfsPropertySetValue::Number(num))
}

fn parse_prop_assignments(raw_props: &[String]) -> Result<Vec<(String, ZfsPropertySetValue)>> {
    let mut out = Vec::with_capacity(raw_props.len());
    for spec in raw_props {
        let Some((name, val)) = spec.split_once('=') else {
            bail!("invalid `--prop {spec}`: expected `name=value`");
        };
        if name.is_empty() {
            bail!("empty property name in `--prop {spec}`");
        }
        out.push((name.to_owned(), parse_property_set_value(name, val)?));
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
            Self::MountWrite {
                target,
                mountpoint,
                allow_write,
                dataset,
                reconcile_torn_uberblocks,
            } => {
                if !target.offline_image || !allow_write {
                    bail!("writable ZFS mounts require --offline-image and --allow-write");
                }
                if target.members.len() > 7 {
                    bail!("at most seven additional member images are supported");
                }
                let components = parse_dataset_components(&dataset)?;
                // Host paths and dataset component syntax are checked before
                // writable opens and explicitly requested ring reconciliation.
                let mountpoint = writable_mountpoint(&target, &mountpoint)?;
                let paths: Vec<&Path> = std::iter::once(&target.image)
                    .chain(&target.members)
                    .map(PathBuf::as_path)
                    .collect();
                let engine = ZfsTransactionEngine::open_files_at(
                    cx,
                    &paths,
                    target.offset,
                    target.length,
                    ZfsWriteOptions {
                        offline_image: target.offline_image,
                        allow_write,
                        pool_guid: target.pool_guid,
                        label: target.label as usize,
                        slot: target.slot as usize,
                        reconcile_torn_uberblocks,
                    },
                )
                .context("admitting the native ZFS mount writer")?;
                let fs = ffs_zfs::ZfsFs::with_writer_options(
                    cx,
                    engine,
                    components,
                    ZfsMountWriteOptions {
                        allow_mode_and_owner_setattr: true,
                    },
                )?;
                let options = ffs_fuse::MountOptions {
                    read_only: false,
                    allow_other: false,
                    auto_unmount: true,
                    atime: ffs_fuse::AtimePolicy::NoAtime,
                    ..ffs_fuse::MountOptions::default()
                };
                eprintln!(
                    "experimental ZFS writer: synchronous native TXG commits; native mode/ownership/SA-xattr/open-unlink, noatime; non-trivial ACL enforcement is not implemented"
                );
                let _ = ffs_fuse::mount(Box::new(fs), &mountpoint, &options)?;
                Ok(())
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
            Self::TxSnapshot { pool, snap_name } => {
                let (mut engine, components) = pool.open_engine(cx)?;
                let outcome = engine.create_snapshot(
                    cx,
                    &components,
                    snap_name.as_bytes(),
                    pool.zpl_timestamp(),
                );
                emit_tx_outcome("tx_snapshot", &pool.dataset, &engine, outcome)
            }
            Self::TxDestroySnapshot {
                pool,
                snap_name,
                defer,
            } => {
                let (mut engine, components) = pool.open_engine(cx)?;
                let outcome = engine.destroy_snapshot(cx, &components, snap_name.as_bytes(), defer);
                emit_tx_outcome("tx_destroy_snapshot", &pool.dataset, &engine, outcome)
            }
            Self::TxRenameSnapshot {
                pool,
                old_snap_name,
                new_snap_name,
            } => {
                let (mut engine, components) = pool.open_engine(cx)?;
                let outcome = engine.rename_snapshot(
                    cx,
                    &components,
                    old_snap_name.as_bytes(),
                    new_snap_name.as_bytes(),
                );
                emit_tx_outcome("tx_rename_snapshot", &pool.dataset, &engine, outcome)
            }
            Self::TxHold {
                pool,
                snap_name,
                tag,
            } => {
                let (mut engine, components) = pool.open_engine(cx)?;
                let outcome = engine.hold_snapshot(
                    cx,
                    &components,
                    snap_name.as_bytes(),
                    tag.as_bytes(),
                    pool.zpl_timestamp(),
                );
                emit_tx_outcome("tx_hold", &pool.dataset, &engine, outcome)
            }
            Self::TxRelease {
                pool,
                snap_name,
                tag,
            } => {
                let (mut engine, components) = pool.open_engine(cx)?;
                let outcome =
                    engine.release_snapshot(cx, &components, snap_name.as_bytes(), tag.as_bytes());
                emit_tx_outcome("tx_release", &pool.dataset, &engine, outcome)
            }
            Self::TxBookmark {
                pool,
                bookmark_name,
                snapshot,
                source_bookmark,
            } => {
                let (source_name, is_bm) = match (snapshot, source_bookmark) {
                    (Some(s), None) => (s, false),
                    (None, Some(b)) => (b, true),
                    _ => bail!("specify exactly one of --snapshot or --source-bookmark"),
                };
                let (mut engine, components) = pool.open_engine(cx)?;
                let outcome = engine.create_bookmark(
                    cx,
                    &components,
                    bookmark_name.as_bytes(),
                    source_name.as_bytes(),
                    is_bm,
                );
                emit_tx_outcome("tx_bookmark", &pool.dataset, &engine, outcome)
            }
            Self::TxDestroyBookmark {
                pool,
                bookmark_name,
            } => {
                let (mut engine, components) = pool.open_engine(cx)?;
                let outcome = engine.destroy_bookmark(cx, &components, bookmark_name.as_bytes());
                emit_tx_outcome("tx_destroy_bookmark", &pool.dataset, &engine, outcome)
            }
            Self::TxCreateDataset {
                pool,
                child_name,
                props,
            } => {
                let parsed_props = parse_prop_assignments(&props)?;
                let (mut engine, components) = pool.open_engine(cx)?;
                let outcome = engine.create_dataset(
                    cx,
                    &components,
                    child_name.as_bytes(),
                    &parsed_props,
                    pool.zpl_timestamp(),
                );
                emit_tx_outcome("tx_create_dataset", &pool.dataset, &engine, outcome)
            }
            Self::TxClone {
                pool,
                origin_snap,
                target_dataset,
                props,
            } => {
                let parsed_props = parse_prop_assignments(&props)?;
                let mut target_parts = parse_dataset_components(&target_dataset)?;
                let Some(target_name) = target_parts.pop() else {
                    bail!("target clone dataset cannot be the pool root");
                };
                let (mut engine, origin_components) = pool.open_engine(cx)?;
                let outcome = engine.create_clone(
                    cx,
                    &origin_components,
                    origin_snap.as_bytes(),
                    &target_parts,
                    &target_name,
                    &parsed_props,
                    pool.zpl_timestamp(),
                );
                emit_tx_outcome("tx_clone", &target_dataset, &engine, outcome)
            }
            Self::TxRenameDataset { pool, new_dataset } => {
                let new_components = parse_dataset_components(&new_dataset)?;
                if new_components.is_empty() {
                    bail!("new dataset name cannot be the pool root");
                }
                let (mut engine, old_components) = pool.open_engine(cx)?;
                let outcome = engine.rename_dataset(cx, &old_components, &new_components);
                emit_tx_outcome("tx_rename_dataset", &new_dataset, &engine, outcome)
            }
            Self::TxDestroyDataset { pool } => {
                let (mut engine, components) = pool.open_engine(cx)?;
                let outcome = engine.destroy_dataset(cx, &components);
                emit_tx_outcome("tx_destroy_dataset", &pool.dataset, &engine, outcome)
            }
            Self::TxSetProp {
                pool,
                property,
                value,
            } => {
                let parsed_val = parse_property_set_value(&property, &value)?;
                let (mut engine, components) = pool.open_engine(cx)?;
                let outcome = engine.set_property(cx, &components, &property, parsed_val);
                emit_tx_outcome("tx_set_prop", &pool.dataset, &engine, outcome)
            }
            Self::TxInheritProp { pool, property } => {
                let (mut engine, components) = pool.open_engine(cx)?;
                let outcome = engine.inherit_property(cx, &components, &property);
                emit_tx_outcome("tx_inherit_prop", &pool.dataset, &engine, outcome)
            }
            Self::TxSetattr {
                pool,
                path,
                mode,
                uid,
                gid,
                size,
                atime_sec,
                mtime_sec,
                clear_suid_sgid,
            } => {
                let mode_bits = mode.as_deref().map(parse_mode_bits).transpose()?;
                let attrs = ZfsPosixSetAttr {
                    size,
                    atime: atime_sec.map(|seconds| Timestamp { seconds, nanos: 0 }),
                    mtime: mtime_sec.map(|seconds| Timestamp { seconds, nanos: 0 }),
                    mode: mode_bits,
                    uid,
                    gid,
                    clear_suid_sgid,
                };
                let (mut engine, components) = pool.open_engine(cx)?;
                let target_obj = resolve_target_object(cx, &engine, &components, path.as_os_str())?;
                let outcome = engine.set_posix_attributes(
                    cx,
                    &components,
                    target_obj,
                    &attrs,
                    pool.zpl_timestamp(),
                    pool.data_checksum(),
                );
                emit_tx_outcome("tx_setattr", &pool.dataset, &engine, outcome)
            }
            Self::TxSetxattr {
                pool,
                path,
                name,
                value,
                value_file,
                create,
                replace,
            } => {
                let payload = match (value, value_file) {
                    (Some(text), None) => text.into_bytes(),
                    (None, Some(host_path)) => std::fs::read(&host_path)
                        .with_context(|| format!("reading --value-file {}", host_path.display()))?,
                    _ => bail!("specify exactly one of --value or --value-file"),
                };
                let xattr_mode = if create {
                    ZfsXattrSetMode::Create
                } else if replace {
                    ZfsXattrSetMode::Replace
                } else {
                    ZfsXattrSetMode::Auto
                };
                let (mut engine, components) = pool.open_engine(cx)?;
                let target_obj = resolve_target_object(cx, &engine, &components, path.as_os_str())?;
                let outcome = engine.set_xattr(
                    cx,
                    &components,
                    target_obj,
                    &name,
                    &payload,
                    xattr_mode,
                    pool.zpl_timestamp(),
                );
                emit_tx_outcome("tx_setxattr", &pool.dataset, &engine, outcome)
            }
            Self::TxRmxattr { pool, path, name } => {
                let (mut engine, components) = pool.open_engine(cx)?;
                let target_obj = resolve_target_object(cx, &engine, &components, path.as_os_str())?;
                let outcome =
                    engine.remove_xattr(cx, &components, target_obj, &name, pool.zpl_timestamp());
                emit_tx_outcome("tx_rmxattr", &pool.dataset, &engine, outcome)
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
    fn writable_mount_requires_authority_and_keeps_explicit_pool_selection() {
        let base = [
            "ffs-zfs",
            "mount-write",
            "primary.img",
            "/mnt/zfs",
            "--pool-guid",
            "123",
            "--label",
            "2",
            "--slot",
            "11",
            "--dataset",
            "data/work",
            "--member",
            "mirror.img",
            "--offset",
            "4096",
            "--length",
            "16777216",
            "--reconcile-torn-uberblocks",
        ];
        for authority in [vec![], vec!["--offline-image"], vec!["--allow-write"]] {
            assert!(Cli::try_parse_from(base.into_iter().chain(authority)).is_err());
        }
        let args =
            Cli::try_parse_from(base.into_iter().chain(["--offline-image", "--allow-write"]))
                .unwrap();
        let crate::Command::Write(WriteCommand::MountWrite {
            target,
            mountpoint,
            allow_write,
            dataset,
            reconcile_torn_uberblocks,
        }) = args.command
        else {
            panic!("mount-write must dispatch to the explicit native writer");
        };
        assert!(target.offline_image && allow_write && reconcile_torn_uberblocks);
        assert_eq!(target.image, PathBuf::from("primary.img"));
        assert_eq!(target.members, vec![PathBuf::from("mirror.img")]);
        assert_eq!(target.pool_guid, 123);
        assert_eq!((target.label, target.slot), (2, 11));
        assert_eq!((target.offset, target.length), (4096, Some(16_777_216)));
        assert_eq!(mountpoint, PathBuf::from("/mnt/zfs"));
        assert_eq!(
            parse_dataset_components(&dataset).unwrap(),
            [b"data".to_vec(), b"work".to_vec()]
        );
        for forbidden in [
            vec!["--auto-import"],
            vec!["--replay-zil"],
            vec!["--snapshot", "before"],
            vec!["--sidecar", "pool.ffs-repair"],
            vec!["--allow-other"],
            vec!["--timestamp", "1710000000"],
        ] {
            assert!(
                Cli::try_parse_from(
                    base.into_iter()
                        .chain(["--offline-image", "--allow-write"])
                        .chain(forbidden),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn writable_mountpoint_preflight_preserves_all_backing_files() {
        let temp = tempfile::tempdir().unwrap();
        let primary = temp.path().join("primary.img");
        let member = temp.path().join("member.img");
        let mountpoint = temp.path().join("mount");
        std::fs::write(&primary, b"primary sentinel").unwrap();
        std::fs::write(&member, b"mirror sentinel").unwrap();
        std::fs::create_dir(&mountpoint).unwrap();
        let mut target = AdmitArgs {
            image: primary.clone(),
            offline_image: true,
            offset: 0,
            length: None,
            members: vec![member.clone()],
            label: 0,
            slot: 2,
            pool_guid: 123,
        };
        assert_eq!(
            writable_mountpoint(&target, &mountpoint).unwrap(),
            mountpoint.canonicalize().unwrap()
        );
        assert!(writable_mountpoint(&target, temp.path()).is_err());
        assert!(writable_mountpoint(&target, &primary).is_err());
        assert!(writable_mountpoint(&target, &temp.path().join("absent")).is_err());
        let alias = temp.path().join("member-link.img");
        std::os::unix::fs::symlink(&member, &alias).unwrap();
        target.members = vec![alias];
        assert_eq!(
            writable_mountpoint(&target, &mountpoint).unwrap(),
            mountpoint.canonicalize().unwrap()
        );
        std::fs::write(mountpoint.join("occupied"), b"existing content").unwrap();
        assert!(writable_mountpoint(&target, &mountpoint).is_err());
        assert_eq!(std::fs::read(&primary).unwrap(), b"primary sentinel");
        assert_eq!(std::fs::read(&member).unwrap(), b"mirror sentinel");
        assert_eq!(
            std::fs::read(mountpoint.join("occupied")).unwrap(),
            b"existing content"
        );
    }

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

    #[test]
    fn cli_dsl_and_extended_zpl_subcommands_require_authority_and_parse_properties() {
        let auth = [
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
        ];
        for cmd in [
            vec!["ffs-zfs", "tx-snapshot", "leaf.img", "s1"],
            vec![
                "ffs-zfs",
                "tx-destroy-snapshot",
                "leaf.img",
                "s1",
                "--defer",
            ],
            vec!["ffs-zfs", "tx-rename-snapshot", "leaf.img", "s1", "s2"],
            vec!["ffs-zfs", "tx-hold", "leaf.img", "s1", "keep"],
            vec!["ffs-zfs", "tx-release", "leaf.img", "s1", "keep"],
            vec![
                "ffs-zfs",
                "tx-bookmark",
                "leaf.img",
                "bm1",
                "--snapshot",
                "s1",
            ],
            vec!["ffs-zfs", "tx-destroy-bookmark", "leaf.img", "bm1"],
            vec![
                "ffs-zfs",
                "tx-create-dataset",
                "leaf.img",
                "child",
                "--prop",
                "quota=64M",
                "--prop",
                "app:env=prod",
            ],
            vec![
                "ffs-zfs",
                "tx-clone",
                "leaf.img",
                "s1",
                "data/clone1",
                "--prop",
                "refquota=32M",
            ],
            vec!["ffs-zfs", "tx-rename-dataset", "leaf.img", "data_moved"],
            vec!["ffs-zfs", "tx-destroy-dataset", "leaf.img"],
            vec!["ffs-zfs", "tx-set-prop", "leaf.img", "reservation", "16M"],
            vec!["ffs-zfs", "tx-inherit-prop", "leaf.img", "reservation"],
            vec![
                "ffs-zfs",
                "tx-setattr",
                "leaf.img",
                "/file.txt",
                "--mode",
                "0600",
                "--uid",
                "1000",
                "--gid",
                "1000",
            ],
            vec![
                "ffs-zfs",
                "tx-setxattr",
                "leaf.img",
                "/file.txt",
                "user.tag",
                "--value",
                "v1",
                "--create",
            ],
            vec!["ffs-zfs", "tx-rmxattr", "leaf.img", "/file.txt", "user.tag"],
        ] {
            // Without --allow-write must fail clap parsing.
            assert!(
                Cli::try_parse_from(cmd.iter().copied().chain([
                    "--offline-image",
                    "--pool-guid",
                    "123",
                    "--label",
                    "0",
                    "--slot",
                    "2"
                ]))
                .is_err()
            );
            assert!(Cli::try_parse_from(cmd.into_iter().chain(auth)).is_ok());
        }
        // Bookmark conflicting source flags rejected by clap.
        assert!(
            Cli::try_parse_from(
                [
                    "ffs-zfs",
                    "tx-bookmark",
                    "leaf.img",
                    "bm1",
                    "--snapshot",
                    "s1",
                    "--source-bookmark",
                    "bm0",
                ]
                .into_iter()
                .chain(auth),
            )
            .is_err()
        );
        assert_eq!(
            parse_property_set_value("quota", "none").unwrap(),
            ZfsPropertySetValue::Number(0)
        );
        assert_eq!(
            parse_property_set_value("quota", "64M").unwrap(),
            ZfsPropertySetValue::Number(64 * 1024 * 1024)
        );
        assert_eq!(
            parse_property_set_value("readonly", "on").unwrap(),
            ZfsPropertySetValue::Number(1)
        );
        assert_eq!(
            parse_property_set_value("org:owner", "alice").unwrap(),
            ZfsPropertySetValue::Text(b"alice".to_vec())
        );
    }
}
