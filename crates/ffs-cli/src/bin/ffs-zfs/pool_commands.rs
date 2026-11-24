//! Native OpenZFS `zfs-2.4.0` pool creation and resumable pool lifecycle CLI
//! subcommands (`pool-create`, `pool-import`, `pool-export`, `pool-attach`,
//! `pool-replace`, `pool-detach`, `pool-online`, `pool-offline`, `pool-spare`,
//! `pool-scrub`, `pool-resilver`, `pool-trim`, `pool-checkpoint`, `pool-remove`,
//! `pool-expand`).
//!
//! Security boundary:
//! - Every mutating command requires explicit `--offline-image` and `--allow-write`.
//! - Active foreign-hostid and MMP-enabled pools are strictly refused; never force-imports.
//! - Degraded survivor extraction never enables write admission.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::{Args, Subcommand, ValueEnum};
use ffs_zfs::{
    AllocClass, Leaf, ZfsCreateVdevKind, ZfsCreateVdevSpec, ZfsPoolCreateSpec, ZfsScanLimits,
    ZfsTransactionEngine, ZfsTxOutcome, ZfsWriteOptions, create_pool_files, export_pool_leaves,
    import_pool_leaves,
};

use super::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CreateTopologyArg {
    Leaf,
    Mirror,
    Raidz1,
    Raidz2,
    Raidz3,
    Draid1,
    Draid2,
    Draid3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SpareActionArg {
    Add,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScrubActionArg {
    Start,
    Resume,
    Cancel,
    Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ResilverActionArg {
    Start,
    Resume,
    Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CheckpointActionArg {
    Create,
    Discard,
    Rewind,
    Status,
}

/// Explicit offline pool target supporting single-leaf, mirror, RAIDZ1/2/3,
/// wide dRAID1/2/3 (`2..=255` leaves), and multi-vdev pools.
#[derive(Debug, Args)]
pub struct PoolLifecycleArgs {
    /// Primary offline ZFS regular file image.
    pub image: PathBuf,
    /// Acknowledge that all backing images are unmounted offline files.
    #[arg(long, required = true)]
    pub offline_image: bool,
    /// Explicitly authorize durable native ZFS mutations on the backing images.
    #[arg(long, required = true)]
    pub allow_write: bool,
    /// Partition byte offset within each backing member file.
    #[arg(long, default_value_t = 0, requires = "length")]
    pub offset: u64,
    /// Partition byte length within each backing member file.
    #[arg(long)]
    pub length: Option<u64>,
    /// Additional member images in explicit pool order (up to 254 extra members).
    #[arg(
        long = "member",
        visible_aliases = ["mirror-member", "raidz-member", "draid-member"],
        value_name = "IMAGE"
    )]
    pub members: Vec<PathBuf>,
    /// Explicit label index (`0..=3`) for pinned predecessor Uberblock admission.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..=3))]
    pub label: u64,
    /// Explicit Uberblock ring slot index for pinned predecessor Uberblock admission.
    #[arg(long, value_parser = clap::value_parser!(u64).range(0..128))]
    pub slot: u64,
    /// Expected `pool_guid` pinned by the caller.
    #[arg(long)]
    pub pool_guid: u64,
    /// Explicitly reconcile torn Uberblock copies across all 4 labels after full scrub.
    #[arg(long)]
    pub reconcile_torn_uberblocks: bool,
}

impl PoolLifecycleArgs {
    fn all_paths(&self) -> Result<Vec<&Path>> {
        if self.members.len() > 254 {
            bail!("at most 254 additional pool member images are supported");
        }
        let mut paths = Vec::with_capacity(1 + self.members.len());
        paths.push(self.image.as_path());
        for m in &self.members {
            paths.push(m.as_path());
        }
        Ok(paths)
    }

    fn write_options(&self) -> ZfsWriteOptions {
        ZfsWriteOptions {
            offline_image: self.offline_image,
            allow_write: self.allow_write,
            pool_guid: self.pool_guid,
            label: self.label as usize,
            slot: self.slot as usize,
            reconcile_torn_uberblocks: self.reconcile_torn_uberblocks,
        }
    }

    fn open_engine(&self, cx: &Cx) -> Result<ZfsTransactionEngine> {
        let paths = self.all_paths()?;
        ZfsTransactionEngine::open_files_at(
            cx,
            &paths,
            self.offset,
            self.length,
            self.write_options(),
        )
        .with_context(|| {
            format!(
                "admitting ZFS pool lifecycle writer on {}",
                self.image.display()
            )
        })
    }

    fn open_writable_leaves(&self, cx: &Cx) -> Result<Vec<Leaf>> {
        let paths = self.all_paths()?;
        let mut leaves = Vec::with_capacity(paths.len());
        for path in paths {
            let (leaf, _) = Leaf::open_writable(cx, path, self.offset, self.length)
                .with_context(|| format!("opening writable ZFS leaf {}", path.display()))?;
            leaves.push(leaf);
        }
        Ok(leaves)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
#[allow(clippy::enum_variant_names)]
pub enum PoolCommand {
    /// Create a fresh native OpenZFS `zfs-2.4.0` pool (leaf, mirror, RAIDZ1-3, dRAID1-3, special/log/spares).
    PoolCreate {
        /// Primary backing regular file image (must already exist with >= 6 MiB capacity).
        image: PathBuf,
        /// Additional member images for mirror, RAIDZ, or dRAID data vdevs.
        #[arg(long = "member", value_name = "IMAGE")]
        members: Vec<PathBuf>,
        /// Optional `special` allocation-class member image(s).
        #[arg(long = "special-member", value_name = "IMAGE")]
        special_members: Vec<PathBuf>,
        /// Optional dedicated SLOG (`is_log=1`) member image(s).
        #[arg(long = "log-member", value_name = "IMAGE")]
        log_members: Vec<PathBuf>,
        /// Optional hot-spare member image(s) appended after data vdevs.
        #[arg(long = "spare-member", value_name = "IMAGE")]
        spare_members: Vec<PathBuf>,
        /// Acknowledge that all backing images are unmounted offline files.
        #[arg(long, required = true)]
        offline_image: bool,
        /// Explicitly authorize overwriting the backing images with a fresh native ZFS pool.
        #[arg(long, required = true)]
        allow_write: bool,
        /// Native ZFS pool name.
        #[arg(long)]
        pool_name: String,
        /// Non-zero 64-bit native pool GUID.
        #[arg(long)]
        pool_guid: u64,
        /// Sector shift (`9..=16`, default `12` = 4 KiB).
        #[arg(long, default_value_t = 12, value_parser = clap::value_parser!(u8).range(9..=16))]
        ashift: u8,
        /// Primary top-level vdev topology.
        #[arg(long, value_enum, default_value_t = CreateTopologyArg::Leaf)]
        topology: CreateTopologyArg,
        /// dRAID data columns per redundancy group (required for `draid1`/`draid2`/`draid3`).
        #[arg(long)]
        draid_ndata: Option<usize>,
        /// dRAID distributed spare count (`0..children`).
        #[arg(long, default_value_t = 0)]
        draid_nspares: usize,
        /// dRAID redundancy group count (`>= 1`).
        #[arg(long, default_value_t = 1)]
        draid_ngroups: usize,
        /// Non-zero hostid recorded in initial pool labels & MOS config.
        #[arg(long, default_value_t = 0x4646_5331)]
        hostid: u64,
        /// Hostname recorded in initial pool labels & MOS config.
        #[arg(long, default_value = "frankenfs")]
        hostname: String,
        /// Create the pool in active (`state=0`) instead of exported (`state=1`) state.
        #[arg(long)]
        active: bool,
    },
    /// Cleanly transition an exported offline pool to active (`state=0`); strictly refuses foreign hostids & MMP.
    PoolImport {
        image: PathBuf,
        #[arg(long = "member", value_name = "IMAGE")]
        members: Vec<PathBuf>,
        #[arg(long, required = true)]
        offline_image: bool,
        #[arg(long, required = true)]
        allow_write: bool,
        #[arg(long)]
        pool_guid: u64,
        #[arg(long, default_value_t = 0x4646_5331)]
        hostid: u64,
        #[arg(long, default_value = "frankenfs")]
        hostname: String,
    },
    /// Cleanly transition an offline pool to exported (`state=1`); strictly refuses foreign hostids & MMP.
    PoolExport {
        image: PathBuf,
        #[arg(long = "member", value_name = "IMAGE")]
        members: Vec<PathBuf>,
        #[arg(long, required = true)]
        offline_image: bool,
        #[arg(long, required = true)]
        allow_write: bool,
        #[arg(long)]
        pool_guid: u64,
        #[arg(long, default_value_t = 0x4646_5331)]
        hostid: u64,
        #[arg(long, default_value = "frankenfs")]
        hostname: String,
    },
    /// Attach a new mirror member (promoting a single leaf to a 2-way mirror or growing a mirror).
    PoolAttach {
        #[command(flatten)]
        pool: PoolLifecycleArgs,
        /// Backing image of the newly attached mirror member.
        #[arg(long)]
        new_member: PathBuf,
    },
    /// Replace an existing member at `--target-index` with `--new-member`.
    PoolReplace {
        #[command(flatten)]
        pool: PoolLifecycleArgs,
        #[arg(long)]
        target_index: usize,
        #[arg(long)]
        new_member: PathBuf,
    },
    /// Detach a redundant mirror member at `--target-index` (never detaches the last healthy replica).
    PoolDetach {
        #[command(flatten)]
        pool: PoolLifecycleArgs,
        #[arg(long)]
        target_index: usize,
    },
    /// Mark a pool member ONLINE in MOS config.
    PoolOnline {
        #[command(flatten)]
        pool: PoolLifecycleArgs,
        #[arg(long)]
        target_index: usize,
    },
    /// Mark a redundant pool member OFFLINE in MOS config (enforces redundancy/parity floor).
    PoolOffline {
        #[command(flatten)]
        pool: PoolLifecycleArgs,
        #[arg(long)]
        target_index: usize,
    },
    /// Add or remove a hot spare GUID in MOS config without altering data `guid_sum`.
    PoolSpare {
        #[command(flatten)]
        pool: PoolLifecycleArgs,
        #[arg(long, value_enum)]
        action: SpareActionArg,
        #[arg(long)]
        spare_guid: u64,
    },
    /// Start, resume, cancel, or inspect a resumable MOS `"scan"` pool scrub (heals recoverable damage).
    PoolScrub {
        #[command(flatten)]
        pool: PoolLifecycleArgs,
        #[arg(long, value_enum, default_value_t = ScrubActionArg::Start)]
        action: ScrubActionArg,
        /// Maximum blocks examined in this TXG chunk before checkpointing progress.
        #[arg(long, default_value_t = usize::MAX)]
        max_blocks: usize,
    },
    /// Start, resume, or inspect a TXG-filtered resumable MOS `"scan"` pool resilver.
    PoolResilver {
        #[command(flatten)]
        pool: PoolLifecycleArgs,
        #[arg(long, value_enum, default_value_t = ResilverActionArg::Start)]
        action: ResilverActionArg,
        /// Minimum birth TXG to resilver (used with `--action start`).
        #[arg(long, default_value_t = 0)]
        min_txg: u64,
        /// Maximum blocks examined in this TXG chunk before checkpointing progress.
        #[arg(long, default_value_t = usize::MAX)]
        max_blocks: usize,
    },
    /// Resumable pool TRIM across free metaslab extents (persists `"vdev_trim_progress"`).
    PoolTrim {
        #[command(flatten)]
        pool: PoolLifecycleArgs,
        /// Maximum free ranges processed in this TXG chunk.
        #[arg(long, default_value_t = usize::MAX)]
        max_ranges: usize,
        /// Reset any saved TRIM cursor back to offset 0 before scanning.
        #[arg(long)]
        reset: bool,
    },
    /// Create, discard, inspect, or crash-safely rewind a pool-wide checkpoint (`com.delphix:zpool_checkpoint`).
    PoolCheckpoint {
        #[command(flatten)]
        pool: PoolLifecycleArgs,
        #[arg(long, value_enum)]
        action: CheckpointActionArg,
    },
    /// Remove a top-level leaf/mirror vdev by evacuating extents and writing OpenZFS indirect mappings.
    PoolRemove {
        #[command(flatten)]
        pool: PoolLifecycleArgs,
        #[arg(long)]
        remove_vdev: u32,
        #[arg(long)]
        target_vdev: u32,
        /// Repeatable `<offset>:<length>` extent pair (512-byte aligned) to evacuate from `--remove-vdev`.
        #[arg(long = "extent", value_name = "OFFSET:LEN")]
        extents: Vec<String>,
    },
    /// Resumable RAIDZ1/2/3 width expansion (`org.openzfs:raidz_expansion`) onto `--new-member`.
    PoolExpand {
        #[command(flatten)]
        pool: PoolLifecycleArgs,
        /// New physical member appended to widen the RAIDZ group (`width -> width + 1`).
        #[arg(long)]
        new_member: PathBuf,
        /// Logical reflow chunk size in bytes (must be ashift-aligned).
        #[arg(long, default_value_t = 65_536)]
        chunk_bytes: u64,
        /// Maximum chunks processed per TXG before checkpointing `ub_raidz_reflow_info`.
        #[arg(long, default_value_t = 16)]
        max_chunks: usize,
    },
}

fn parse_extent_spec(spec: &str) -> Result<(u64, u64)> {
    let Some((off_s, len_s)) = spec.split_once(':') else {
        bail!("invalid --extent `{spec}` (expected `<offset>:<length>`)");
    };
    let off: u64 = off_s
        .parse()
        .with_context(|| format!("parsing extent offset in `{spec}`"))?;
    let len: u64 = len_s
        .parse()
        .with_context(|| format!("parsing extent length in `{spec}`"))?;
    if len == 0 {
        bail!("extent length must be non-zero in `{spec}`");
    }
    Ok((off, len))
}

fn emit_tx_outcome<T: serde::Serialize>(operation: &str, outcome: ZfsTxOutcome<T>) -> Result<()> {
    match outcome {
        ZfsTxOutcome::Committed { value, token } => json(&serde_json::json!({
            "format": "ZFS",
            "operation": operation,
            "outcome": "committed",
            "committed_txg": token.committed_txg(),
            "published_slot": token.published_slot(),
            "generation": token.generation(),
            "result": value,
        })),
        ZfsTxOutcome::NotCommitted(err) => {
            Err(err).with_context(|| format!("{operation} not committed"))
        }
        ZfsTxOutcome::Uncertain {
            reason,
            target_txg,
            target_slot,
        } => bail!(
            "{operation} outcome uncertain at target_txg={target_txg} slot={target_slot}: {reason}"
        ),
    }
}

impl PoolCommand {
    #[allow(clippy::too_many_lines)]
    pub fn run(self, cx: &Cx) -> Result<()> {
        match self {
            Self::PoolCreate {
                image,
                members,
                special_members,
                log_members,
                spare_members,
                offline_image,
                allow_write,
                pool_name,
                pool_guid,
                ashift,
                topology,
                draid_ndata,
                draid_nspares,
                draid_ngroups,
                hostid,
                hostname,
                active,
            } => {
                if !offline_image || !allow_write {
                    bail!("pool-create requires both --offline-image and --allow-write");
                }
                let primary_count = 1 + members.len();
                let primary_kind = match topology {
                    CreateTopologyArg::Leaf => {
                        if primary_count != 1 {
                            bail!("leaf topology accepts no additional --member images");
                        }
                        ZfsCreateVdevKind::Leaf
                    }
                    CreateTopologyArg::Mirror => ZfsCreateVdevKind::Mirror {
                        width: primary_count,
                    },
                    CreateTopologyArg::Raidz1 => ZfsCreateVdevKind::Raidz {
                        parity: 1,
                        width: primary_count,
                    },
                    CreateTopologyArg::Raidz2 => ZfsCreateVdevKind::Raidz {
                        parity: 2,
                        width: primary_count,
                    },
                    CreateTopologyArg::Raidz3 => ZfsCreateVdevKind::Raidz {
                        parity: 3,
                        width: primary_count,
                    },
                    CreateTopologyArg::Draid1
                    | CreateTopologyArg::Draid2
                    | CreateTopologyArg::Draid3 => {
                        let nparity = match topology {
                            CreateTopologyArg::Draid1 => 1,
                            CreateTopologyArg::Draid2 => 2,
                            CreateTopologyArg::Draid3 => 3,
                            _ => unreachable!(),
                        };
                        let ndata = draid_ndata.unwrap_or_else(|| {
                            primary_count
                                .saturating_sub(nparity)
                                .saturating_sub(draid_nspares)
                                .max(1)
                        });
                        ZfsCreateVdevKind::Draid {
                            ndata,
                            nparity,
                            children: primary_count,
                            nspares: draid_nspares,
                            ngroups: draid_ngroups,
                        }
                    }
                };
                let mut vdevs = vec![ZfsCreateVdevSpec {
                    kind: primary_kind,
                    alloc_class: AllocClass::Normal,
                }];
                let mut all_paths: Vec<&Path> = Vec::with_capacity(
                    primary_count + special_members.len() + log_members.len() + spare_members.len(),
                );
                all_paths.push(image.as_path());
                for m in &members {
                    all_paths.push(m.as_path());
                }
                for s in &special_members {
                    vdevs.push(ZfsCreateVdevSpec {
                        kind: ZfsCreateVdevKind::Leaf,
                        alloc_class: AllocClass::Special,
                    });
                    all_paths.push(s.as_path());
                }
                for l in &log_members {
                    vdevs.push(ZfsCreateVdevSpec {
                        kind: ZfsCreateVdevKind::Leaf,
                        alloc_class: AllocClass::Log,
                    });
                    all_paths.push(l.as_path());
                }
                for sp in &spare_members {
                    all_paths.push(sp.as_path());
                }
                let spec = ZfsPoolCreateSpec {
                    pool_name,
                    pool_guid,
                    ashift,
                    hostid,
                    hostname,
                    vdevs,
                    spare_count: spare_members.len(),
                    exported: !active,
                };
                let report =
                    create_pool_files(cx, &all_paths, &spec).context("creating native ZFS pool")?;
                json(&serde_json::json!({
                    "format": "ZFS",
                    "operation": "pool_create",
                    "report": report,
                }))
            }
            Self::PoolImport {
                image,
                members,
                offline_image,
                allow_write,
                pool_guid,
                hostid,
                hostname,
            } => {
                if !offline_image || !allow_write {
                    bail!("pool-import requires both --offline-image and --allow-write");
                }
                let leaves = open_state_transition_leaves(cx, &image, &members)?;
                let report = import_pool_leaves(cx, &leaves, pool_guid, hostid, &hostname)
                    .context("importing offline ZFS pool")?;
                json(&serde_json::json!({
                    "format": "ZFS",
                    "operation": "pool_import",
                    "report": report,
                }))
            }
            Self::PoolExport {
                image,
                members,
                offline_image,
                allow_write,
                pool_guid,
                hostid,
                hostname,
            } => {
                if !offline_image || !allow_write {
                    bail!("pool-export requires both --offline-image and --allow-write");
                }
                let leaves = open_state_transition_leaves(cx, &image, &members)?;
                let report = export_pool_leaves(cx, &leaves, pool_guid, hostid, &hostname)
                    .context("exporting offline ZFS pool")?;
                json(&serde_json::json!({
                    "format": "ZFS",
                    "operation": "pool_export",
                    "report": report,
                }))
            }
            Self::PoolAttach { pool, new_member } => {
                let mut engine = pool.open_engine(cx)?;
                let (leaf, _) = Leaf::open_writable(cx, &new_member, pool.offset, pool.length)
                    .with_context(|| format!("opening new member {}", new_member.display()))?;
                let outcome = engine.attach_member(cx, leaf);
                emit_tx_outcome("pool_attach", outcome)
            }
            Self::PoolReplace {
                pool,
                target_index,
                new_member,
            } => {
                let mut engine = pool.open_engine(cx)?;
                let (leaf, _) = Leaf::open_writable(cx, &new_member, pool.offset, pool.length)
                    .with_context(|| {
                        format!("opening replacement member {}", new_member.display())
                    })?;
                let outcome = engine.replace_member(cx, target_index, leaf);
                emit_tx_outcome("pool_replace", outcome)
            }
            Self::PoolDetach { pool, target_index } => {
                let mut engine = pool.open_engine(cx)?;
                let outcome = engine.detach_member(cx, target_index);
                emit_tx_outcome("pool_detach", outcome)
            }
            Self::PoolOnline { pool, target_index } => {
                let mut engine = pool.open_engine(cx)?;
                let outcome = engine.set_member_offline(cx, target_index, false);
                emit_tx_outcome("pool_online", outcome)
            }
            Self::PoolOffline { pool, target_index } => {
                let mut engine = pool.open_engine(cx)?;
                let outcome = engine.set_member_offline(cx, target_index, true);
                emit_tx_outcome("pool_offline", outcome)
            }
            Self::PoolSpare {
                pool,
                action,
                spare_guid,
            } => {
                let mut engine = pool.open_engine(cx)?;
                let outcome = engine.manage_spare(cx, spare_guid, action == SpareActionArg::Add);
                emit_tx_outcome("pool_spare", outcome)
            }
            Self::PoolScrub {
                pool,
                action,
                max_blocks,
            } => {
                let mut engine = pool.open_engine(cx)?;
                match action {
                    ScrubActionArg::Status => {
                        let status = engine.scan_status(cx)?;
                        json(&serde_json::json!({
                            "format": "ZFS",
                            "operation": "pool_scrub_status",
                            "scan": status.map(|s| serde_json::json!({
                                "func": s.func as u64,
                                "state": s.state as u64,
                                "min_txg": s.min_txg,
                                "max_txg": s.max_txg,
                                "examined": s.examined,
                                "processed": s.processed,
                                "errors": s.errors,
                                "bookmark_objset": s.bookmark.objset,
                                "bookmark_object": s.bookmark.object,
                                "bookmark_level": s.bookmark.level,
                                "bookmark_blkid": s.bookmark.blkid,
                            })),
                        }))
                    }
                    ScrubActionArg::Start => {
                        let outcome = engine.scrub_start(
                            cx,
                            ZfsScanLimits {
                                max_blocks_per_txg: max_blocks,
                            },
                        );
                        emit_tx_outcome("pool_scrub_start", outcome)
                    }
                    ScrubActionArg::Resume => {
                        let outcome = engine.scrub_resume(
                            cx,
                            ZfsScanLimits {
                                max_blocks_per_txg: max_blocks,
                            },
                        );
                        emit_tx_outcome("pool_scrub_resume", outcome)
                    }
                    ScrubActionArg::Cancel => {
                        let outcome = engine.scrub_cancel(cx);
                        emit_tx_outcome("pool_scrub_cancel", outcome)
                    }
                }
            }
            Self::PoolResilver {
                pool,
                action,
                min_txg,
                max_blocks,
            } => {
                let mut engine = pool.open_engine(cx)?;
                match action {
                    ResilverActionArg::Status => {
                        let status = engine.scan_status(cx)?;
                        json(&serde_json::json!({
                            "format": "ZFS",
                            "operation": "pool_resilver_status",
                            "scan": status.map(|s| serde_json::json!({
                                "func": s.func as u64,
                                "state": s.state as u64,
                                "min_txg": s.min_txg,
                                "max_txg": s.max_txg,
                                "examined": s.examined,
                                "processed": s.processed,
                                "errors": s.errors,
                            })),
                        }))
                    }
                    ResilverActionArg::Start => {
                        let outcome = engine.resilver_start(
                            cx,
                            min_txg,
                            ZfsScanLimits {
                                max_blocks_per_txg: max_blocks,
                            },
                        );
                        emit_tx_outcome("pool_resilver_start", outcome)
                    }
                    ResilverActionArg::Resume => {
                        let outcome = engine.resilver_resume(
                            cx,
                            ZfsScanLimits {
                                max_blocks_per_txg: max_blocks,
                            },
                        );
                        emit_tx_outcome("pool_resilver_resume", outcome)
                    }
                }
            }
            Self::PoolTrim {
                pool,
                max_ranges,
                reset,
            } => {
                let mut engine = pool.open_engine(cx)?;
                let outcome = engine.trim_pool(cx, max_ranges, reset);
                emit_tx_outcome("pool_trim", outcome)
            }
            Self::PoolCheckpoint { pool, action } => match action {
                CheckpointActionArg::Status => {
                    let engine = pool.open_engine(cx)?;
                    let status = engine.checkpoint_status(cx)?;
                    json(&serde_json::json!({
                        "format": "ZFS",
                        "operation": "pool_checkpoint_status",
                        "checkpoint": status,
                    }))
                }
                CheckpointActionArg::Create => {
                    let mut engine = pool.open_engine(cx)?;
                    let outcome = engine.checkpoint_create(cx);
                    emit_tx_outcome("pool_checkpoint_create", outcome)
                }
                CheckpointActionArg::Discard => {
                    let mut engine = pool.open_engine(cx)?;
                    let outcome = engine.checkpoint_discard(cx);
                    emit_tx_outcome("pool_checkpoint_discard", outcome)
                }
                CheckpointActionArg::Rewind => {
                    let leaves = pool.open_writable_leaves(cx)?;
                    let outcome = ZfsTransactionEngine::import_rewind_to_checkpoint(
                        cx,
                        leaves,
                        pool.write_options(),
                    )?;
                    emit_tx_outcome("pool_checkpoint_rewind", outcome)
                }
            },
            Self::PoolRemove {
                pool,
                remove_vdev,
                target_vdev,
                extents,
            } => {
                let parsed: Vec<(u64, u64)> = extents
                    .iter()
                    .map(|e| parse_extent_spec(e))
                    .collect::<Result<_>>()?;
                let mut engine = pool.open_engine(cx)?;
                let outcome = engine.remove_vdev(cx, remove_vdev, target_vdev, &parsed);
                emit_tx_outcome("pool_remove", outcome)
            }
            Self::PoolExpand {
                pool,
                new_member,
                chunk_bytes,
                max_chunks,
            } => {
                let mut engine = pool.open_engine(cx)?;
                let (leaf, _) = Leaf::open_writable(cx, &new_member, pool.offset, pool.length)
                    .with_context(|| {
                        format!("opening expansion member {}", new_member.display())
                    })?;
                let outcome = engine.expand_raidz(cx, leaf, chunk_bytes, max_chunks);
                emit_tx_outcome("pool_expand", outcome)
            }
        }
    }
}

fn open_state_transition_leaves(cx: &Cx, image: &Path, members: &[PathBuf]) -> Result<Vec<Leaf>> {
    if members.len() > 254 {
        bail!("at most 254 additional pool member images are supported");
    }
    let mut leaves = Vec::with_capacity(1 + members.len());
    let (primary, _) = Leaf::open_writable(cx, image, 0, None)
        .with_context(|| format!("opening writable ZFS image {}", image.display()))?;
    leaves.push(primary);
    for path in members {
        let (leaf, _) = Leaf::open_writable(cx, path, 0, None)
            .with_context(|| format!("opening writable ZFS member {}", path.display()))?;
        leaves.push(leaf);
    }
    Ok(leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command};
    use clap::Parser;

    #[test]
    fn pool_create_and_lifecycle_cli_require_explicit_write_authority() {
        assert!(
            Cli::try_parse_from([
                "ffs-zfs",
                "pool-create",
                "d0.img",
                "--offline-image",
                "--pool-name",
                "tank",
                "--pool-guid",
                "42",
            ])
            .is_err()
        );
        let parsed = Cli::try_parse_from([
            "ffs-zfs",
            "pool-create",
            "d0.img",
            "--member",
            "d1.img",
            "--member",
            "d2.img",
            "--member",
            "d3.img",
            "--topology",
            "draid1",
            "--draid-ndata",
            "2",
            "--draid-nspares",
            "1",
            "--draid-ngroups",
            "1",
            "--offline-image",
            "--allow-write",
            "--pool-name",
            "draidtank",
            "--pool-guid",
            "9001",
        ])
        .unwrap();
        let Command::Pool(PoolCommand::PoolCreate {
            topology,
            draid_ndata,
            draid_nspares,
            members,
            ..
        }) = parsed.command
        else {
            panic!("expected pool-create");
        };
        assert_eq!(topology, CreateTopologyArg::Draid1);
        assert_eq!(draid_ndata, Some(2));
        assert_eq!(draid_nspares, 1);
        assert_eq!(members.len(), 3);
    }

    #[test]
    fn pool_scrub_checkpoint_remove_expand_parse_cleanly() {
        let base = [
            "--offline-image",
            "--allow-write",
            "--pool-guid",
            "777",
            "--label",
            "0",
            "--slot",
            "4",
        ];
        for extra in [
            vec![
                "pool-scrub",
                "d0.img",
                "--action",
                "start",
                "--max-blocks",
                "8",
            ],
            vec![
                "pool-resilver",
                "d0.img",
                "--action",
                "resume",
                "--max-blocks",
                "4",
            ],
            vec!["pool-trim", "d0.img", "--max-ranges", "2", "--reset"],
            vec!["pool-checkpoint", "d0.img", "--action", "create"],
            vec!["pool-checkpoint", "d0.img", "--action", "rewind"],
            vec!["pool-attach", "d0.img", "--new-member", "d1.img"],
            vec!["pool-detach", "d0.img", "--target-index", "1"],
            vec!["pool-offline", "d0.img", "--target-index", "1"],
            vec!["pool-online", "d0.img", "--target-index", "1"],
            vec![
                "pool-spare",
                "d0.img",
                "--action",
                "add",
                "--spare-guid",
                "999",
            ],
            vec![
                "pool-remove",
                "d0.img",
                "--member",
                "d1.img",
                "--remove-vdev",
                "1",
                "--target-vdev",
                "0",
                "--extent",
                "4096:8192",
            ],
            vec![
                "pool-expand",
                "d0.img",
                "--member",
                "d1.img",
                "--member",
                "d2.img",
                "--new-member",
                "d3.img",
                "--chunk-bytes",
                "65536",
            ],
        ] {
            let parsed = Cli::try_parse_from(std::iter::once("ffs-zfs").chain(extra).chain(base));
            assert!(parsed.is_ok(), "failed parsing: {:?}", parsed.err());
        }
    }

    #[test]
    fn parse_extent_spec_rejects_malformed_or_zero_length() {
        assert_eq!(parse_extent_spec("4096:8192").unwrap(), (4096, 8192));
        assert!(parse_extent_spec("4096").is_err());
        assert!(parse_extent_spec("4096:0").is_err());
        assert!(parse_extent_spec("abc:4096").is_err());
    }
}
