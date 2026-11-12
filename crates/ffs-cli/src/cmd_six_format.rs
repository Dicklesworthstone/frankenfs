//! Unified six-format operator CLI routing, bounded MBR/GPT partition slice
//! discovery, native FAT formatting, NTFS alternate data stream inspection, and
//! ZFS pool/dataset inspection (`bd-unified-six-format-cli-partitions-and-doc-truth-x9kjz`).

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::{Args, Subcommand};
use ffs::{
    ImageSource, PartitionByteDevice, ReadOnlyBackend, ReadOnlyFs, ReadOnlyOpenOptions,
    ZfsMissingMembers, ZfsReadOptions, ZfsRootSelection, discover_partitions,
    open_partition_read_only, open_read_only,
};
use ffs_block::io_engine::VolumeAccess;
use ffs_block::{ByteBlockDevice, ByteDevice};
use ffs_core::{
    BtrfsMountSelection, DetectedFilesystem, Ext4JournalReplayMode, FileType, FsFlavor,
    FsFormatKind, FsOps, OpenFs, OpenOptions, RequestOp, RequestScope,
    detect_all_filesystems_at_path, detect_all_filesystems_on_device,
};
use ffs_error::FfsError;
use ffs_ondisk::fat::FatOemCodePage;
use ffs_ondisk::ntfs::{DATA, NtfsValue};
use ffs_ondisk::partition::{
    MAX_GPT_PARTITIONS, PartUuid, PartitionEntry, PartitionParseOptions, PartitionScheme,
    PartitionSelector, SyntheticGptPartitionSpec, write_gpt_partition_table,
};
use ffs_ondisk::zfs::{
    DATA_OFFSET, Endian, LABEL_BYTES, LABEL_CONFIG_BYTES, LABEL_CONFIG_OFFSET,
    UBERBLOCK_RING_BYTES, UBERBLOCK_RING_OFFSET, checksum as zfs_checksum, label_offsets,
};
use ffs_repair::scrub::{Ext4SuperblockValidator, Scrubber, Severity};
use ffs_types::InodeNumber;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::{
    Ext4OrphanDiagnosticsOutput, FreeSpaceMismatch, FsckCommandOptions, InfoCommandOptions,
    InspectOutput, MountCmdOptions, MountRuntimeMode, ScrubFindingOutput, ScrubOutput,
    choose_btrfs_scrub_block_size, cli_cx, count_blocks_at_severity_or_higher,
    ext4_quota_inodes_for_output, mkfs_cmd, print_scrub_output, scrub_validator,
};

/// Global CLI selector and admission flags shared across all six-format subcommands.
#[derive(Debug, Clone, Default, Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "CLI global admission switches map 1:1 to explicit operator flags"
)]
pub struct SixFormatCliArgs {
    /// Select a validated MBR or GPT partition slice (`1`, `<partuuid>`, or `label:<name>`).
    #[arg(long, global = true, value_name = "SELECTOR")]
    pub partition: Option<String>,
    /// Allow falling back to the backup GPT header when the primary GPT fails CRC validation.
    #[arg(long = "allow-backup-gpt", global = true)]
    pub allow_backup_gpt: bool,
    /// Acknowledge that the backing image is offline and not concurrently modified by external writers.
    #[arg(long = "offline-image", global = true)]
    pub offline_image: bool,
    /// Admit a verified volatile NTFS `$LogFile` recovery view without mutating the backing image.
    #[arg(long = "recover-logfile", global = true)]
    pub recover_logfile: bool,
    /// Use NTFS `$I30` branch-selective lookup instead of full sibling verification.
    #[arg(long = "ntfs-indexed-lookup", global = true)]
    pub ntfs_indexed_lookup: bool,
    /// Automatically select the highest-TXG active/exported ZFS uberblock across labels.
    #[arg(long = "zfs-auto-import", global = true)]
    pub zfs_auto_import: bool,
    /// Bind ZFS pool selection to an explicit nonzero pool GUID.
    #[arg(long = "pool-guid", global = true, value_name = "GUID")]
    pub pool_guid: Option<u64>,
    /// Explicit ZFS vdev label index (`0..=3`) for candidate selection.
    #[arg(long = "zfs-label", global = true, value_name = "INDEX")]
    pub zfs_label: Option<usize>,
    /// Explicit ZFS uberblock ring slot index for candidate selection.
    #[arg(long = "zfs-slot", global = true, value_name = "SLOT")]
    pub zfs_slot: Option<usize>,
    /// Additional immutable ZFS vdev member image (repeatable).
    #[arg(long = "zfs-member", global = true, value_name = "PATH")]
    pub zfs_members: Vec<PathBuf>,
    /// Explicitly absent ZFS mirror child GUID (repeatable).
    #[arg(long = "missing-mirror-member", global = true, value_name = "GUID")]
    pub missing_mirror_members: Vec<u64>,
    /// Explicitly absent ZFS RAIDZ child GUID (repeatable).
    #[arg(long = "missing-raidz-member", global = true, value_name = "GUID")]
    pub missing_raidz_members: Vec<u64>,
    /// Relative ZFS head dataset name inside the pool (empty = pool root).
    #[arg(long = "zfs-dataset", global = true, value_name = "DATASET")]
    pub zfs_dataset: Option<String>,
    /// ZFS snapshot name within the selected head dataset.
    #[arg(long = "zfs-snapshot", global = true, value_name = "SNAPSHOT")]
    pub zfs_snapshot: Option<String>,
    /// Replay uncommitted ZFS ZIL records into a volatile read-only overlay.
    #[arg(long = "zfs-replay-zil", global = true)]
    pub zfs_replay_zil: bool,
}

impl SixFormatCliArgs {
    #[must_use]
    pub const fn partition_parse_options(&self) -> PartitionParseOptions {
        PartitionParseOptions {
            logical_block_bytes: 512,
            max_gpt_entries: MAX_GPT_PARTITIONS,
            allow_backup_gpt_fallback: self.allow_backup_gpt,
        }
    }

    pub fn partition_selector(&self) -> Result<Option<PartitionSelector>> {
        self.partition
            .as_deref()
            .map(|raw| {
                PartitionSelector::from_str(raw)
                    .map_err(|err| anyhow::anyhow!("invalid --partition selector {raw:?}: {err}"))
            })
            .transpose()
    }

    #[must_use]
    pub fn has_zfs_flags(&self) -> bool {
        self.zfs_auto_import
            || self.pool_guid.is_some()
            || self.zfs_label.is_some()
            || self.zfs_slot.is_some()
            || !self.zfs_members.is_empty()
            || !self.missing_mirror_members.is_empty()
            || !self.missing_raidz_members.is_empty()
            || self.zfs_dataset.is_some()
            || self.zfs_snapshot.is_some()
            || self.zfs_replay_zil
    }

    #[must_use]
    pub const fn has_ntfs_flags(&self) -> bool {
        self.recover_logfile || self.ntfs_indexed_lookup
    }

    pub fn validate_format_compatibility(&self, kind: FsFormatKind) -> Result<()> {
        if self.has_ntfs_flags() && kind != FsFormatKind::Ntfs {
            bail!(
                "--recover-logfile and --ntfs-indexed-lookup are only valid for NTFS images (detected {})",
                kind.as_str()
            );
        }
        if self.has_zfs_flags() && kind != FsFormatKind::Zfs {
            bail!(
                "ZFS pool/dataset flags are only valid for ZFS images (detected {})",
                kind.as_str()
            );
        }
        if matches!(kind, FsFormatKind::Ntfs | FsFormatKind::Zfs) && !self.offline_image {
            bail!(
                "--offline-image is required for {} operations; advisory file locks do not exclude external OS/hypervisor writers",
                kind.as_str()
            );
        }
        Ok(())
    }

    pub fn build_zfs_read_options(&self) -> Result<ZfsReadOptions> {
        if !self.missing_mirror_members.is_empty() && !self.missing_raidz_members.is_empty() {
            bail!("--missing-mirror-member and --missing-raidz-member are mutually exclusive");
        }
        let missing = if !self.missing_mirror_members.is_empty() {
            ZfsMissingMembers::Mirror(self.missing_mirror_members.clone())
        } else if !self.missing_raidz_members.is_empty() {
            ZfsMissingMembers::Raidz(self.missing_raidz_members.clone())
        } else {
            ZfsMissingMembers::None
        };
        let root = match (self.pool_guid, self.zfs_label, self.zfs_slot) {
            (Some(pool_guid), Some(label), Some(slot)) => ZfsRootSelection::Candidate {
                pool_guid,
                label,
                slot,
            },
            (Some(pool_guid), None, None) => ZfsRootSelection::Pool(pool_guid),
            (None, None, None) => ZfsRootSelection::Auto,
            _ => bail!(
                "explicit ZFS candidate selection requires all three of --pool-guid, --zfs-label, and --zfs-slot"
            ),
        };
        let dataset = parse_zfs_dataset_components(self.zfs_dataset.as_deref().unwrap_or(""))?;
        let additional_images = self
            .zfs_members
            .iter()
            .map(|member| ImageSource {
                path: member.clone(),
                offset: 0,
                length: None,
            })
            .collect();
        Ok(ZfsReadOptions {
            additional_images,
            root,
            dataset,
            snapshot: self.zfs_snapshot.as_ref().map(|s| s.as_bytes().to_vec()),
            replay_zil: self.zfs_replay_zil,
            missing,
        })
    }

    pub fn build_read_only_options(
        &self,
        kind: FsFormatKind,
        btrfs_root: Option<BtrfsMountSelection>,
        btrfs_devices: &[PathBuf],
        uid: u32,
        gid: u32,
    ) -> Result<ReadOnlyOpenOptions> {
        self.validate_format_compatibility(kind)?;
        let partition = self.partition_selector()?;
        let backend = match kind {
            FsFormatKind::Ext4 => ReadOnlyBackend::Ext4 {
                external_journal: None,
            },
            FsFormatKind::Btrfs => ReadOnlyBackend::Btrfs {
                root: btrfs_root.unwrap_or(BtrfsMountSelection::DefaultRoot),
                additional_devices: btrfs_devices
                    .iter()
                    .map(|path| ImageSource {
                        path: path.clone(),
                        offset: 0,
                        length: None,
                    })
                    .collect(),
            },
            FsFormatKind::Fat16 | FsFormatKind::Fat32 => ReadOnlyBackend::Fat {
                oem_code_page: FatOemCodePage::Ascii,
            },
            FsFormatKind::Ntfs => ReadOnlyBackend::Ntfs {
                indexed_lookup: self.ntfs_indexed_lookup,
                recover_logfile: self.recover_logfile,
            },
            FsFormatKind::Zfs => ReadOnlyBackend::Zfs(self.build_zfs_read_options()?),
        };
        Ok(ReadOnlyOpenOptions {
            offset: 0,
            length: None,
            partition,
            allow_backup_gpt: self.allow_backup_gpt,
            uid,
            gid,
            backend,
        })
    }
}

#[derive(Debug, Subcommand)]
pub enum PoolCommand {
    /// Inspect ZFS vdev labels and checksum-valid uberblock candidates.
    Inspect {
        /// Path to the ZFS image or partitioned whole-disk image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Show read-only ZFS pool status, active TXG, and dataset count.
    Status {
        /// Path to the ZFS image or partitioned whole-disk image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum DatasetCommand {
    /// List ZFS head datasets beneath the selected pool MOS.
    List {
        /// Path to the ZFS image or partitioned whole-disk image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// List snapshots of a ZFS head dataset.
    Snapshots {
        /// Path to the ZFS image or partitioned whole-disk image.
        image: PathBuf,
        /// Relative ZFS head dataset name (empty = pool root).
        #[arg(long, default_value = "")]
        dataset: String,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Scrub allocated DMU blocks of a ZFS dataset or snapshot without mutating the image.
    Scrub {
        /// Path to the ZFS image or partitioned whole-disk image.
        image: PathBuf,
        /// Relative ZFS head dataset name (empty = pool root).
        #[arg(long, default_value = "")]
        dataset: String,
        /// Optional snapshot name within the selected dataset.
        #[arg(long)]
        snapshot: Option<String>,
        /// Also verify ordinary DVA copies and RAIDZ parity columns.
        #[arg(long)]
        verify_redundancy: bool,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
}

#[must_use]
pub fn partition_id_label(entry: Option<&PartitionEntry>) -> String {
    entry.map_or_else(
        || "whole_image".to_owned(),
        |part| {
            part.label.as_ref().map_or_else(
                || {
                    part.part_uuid.map_or_else(
                        || format!("p{}", part.index),
                        |uuid| format!("p{}:{uuid}", part.index),
                    )
                },
                |label| format!("p{}:{label}", part.index),
            )
        },
    )
}

pub fn sha256_regular_file(path: &Path) -> Option<[u8; 32]> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0_u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hasher.finalize().into())
}

pub fn emit_router_telemetry(
    command: &'static str,
    format: &'static str,
    partition: Option<&PartitionEntry>,
    capability_admitted: bool,
    before_sha256: Option<[u8; 32]>,
    image_path: &Path,
) {
    let after_sha256 = before_sha256.and_then(|_| sha256_regular_file(image_path));
    let backing_unchanged = match (before_sha256, after_sha256) {
        (Some(before), Some(after)) => before == after,
        _ => false,
    };
    let partition_id = partition_id_label(partition);
    info!(
        target: "ffs::cli::router",
        command,
        format,
        partition_id = %partition_id,
        capability_admitted,
        backing_sha256_unchanged = backing_unchanged,
        "six_format_router_complete"
    );
}

pub fn detect_target_format(
    cx: &Cx,
    path: &Path,
    six: &SixFormatCliArgs,
) -> Result<(
    FsFormatKind,
    DetectedFilesystem,
    Option<PartitionEntry>,
    Option<PartitionByteDevice>,
)> {
    if let Some(selector) = six.partition_selector()? {
        let (_table, part_dev) =
            open_partition_read_only(cx, path, &selector, &six.partition_parse_options())
                .with_context(|| {
                    format!(
                        "failed to select partition {:?} in {}",
                        six.partition,
                        path.display()
                    )
                })?;
        let entry = part_dev.entry().clone();
        let detected = detect_all_filesystems_on_device(cx, &part_dev).with_context(|| {
            format!(
                "failed to detect filesystem in partition #{} of {}",
                entry.index,
                path.display()
            )
        })?;
        Ok((detected.kind(), detected, Some(entry), Some(part_dev)))
    } else {
        let detected = detect_all_filesystems_at_path(cx, path)
            .with_context(|| format!("failed to detect filesystem in {}", path.display()))?;
        Ok((detected.kind(), detected, None, None))
    }
}

pub fn parse_zfs_dataset_components(name: &str) -> Result<Vec<Vec<u8>>> {
    if name.is_empty() {
        return Ok(Vec::new());
    }
    if name.len() > 65_536 {
        bail!("ZFS dataset path is too long");
    }
    let mut out = Vec::new();
    for part in name.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains(['\0', '@', '#']) {
            bail!(
                "expected a relative ZFS head dataset name (e.g. 'app/db'), not a snapshot or host path"
            );
        }
        out.push(part.as_bytes().to_vec());
        if out.len() > 64 {
            bail!("ZFS dataset path exceeds 64 components");
        }
    }
    Ok(out)
}

#[derive(Debug, Serialize)]
struct PartitionRowOutput {
    index: u32,
    scheme: &'static str,
    start_lba: u64,
    end_lba_inclusive: u64,
    start_byte: u64,
    byte_len: u64,
    mbr_type: Option<String>,
    mbr_bootable: bool,
    type_guid: Option<String>,
    part_uuid: Option<String>,
    label: Option<String>,
    filesystem: Option<String>,
}

#[derive(Debug, Serialize)]
struct PartitionTableOutput {
    image: String,
    scheme: &'static str,
    logical_block_bytes: u32,
    disk_guid: Option<String>,
    used_backup_gpt: bool,
    partitions: Vec<PartitionRowOutput>,
}

const fn partition_scheme_str(scheme: PartitionScheme) -> &'static str {
    match scheme {
        PartitionScheme::Mbr => "mbr",
        PartitionScheme::Gpt => "gpt",
    }
}

pub fn partitions_cmd(path: &Path, json: bool, six: &SixFormatCliArgs) -> Result<()> {
    let cx = cli_cx();
    let before = sha256_regular_file(path);
    let opts = six.partition_parse_options();
    let table = discover_partitions(&cx, path, &opts)
        .with_context(|| format!("failed to discover partition table in {}", path.display()))?;
    let mut rows = Vec::with_capacity(table.partitions.len());
    for entry in &table.partitions {
        let selector = PartitionSelector::Index(entry.index);
        let fs_kind = open_partition_read_only(&cx, path, &selector, &opts)
            .ok()
            .and_then(|(_, dev)| detect_all_filesystems_on_device(&cx, &dev).ok())
            .map(|detected| detected.kind().as_str().to_owned());
        rows.push(PartitionRowOutput {
            index: entry.index,
            scheme: partition_scheme_str(entry.scheme),
            start_lba: entry.start_lba,
            end_lba_inclusive: entry.end_lba_inclusive,
            start_byte: entry.start_byte,
            byte_len: entry.byte_len,
            mbr_type: entry.mbr_type.map(|code| format!("0x{code:02x}")),
            mbr_bootable: entry.mbr_bootable,
            type_guid: entry.type_guid.map(|g| g.to_string()),
            part_uuid: entry.part_uuid.map(|g| g.to_string()),
            label: entry.label.clone(),
            filesystem: fs_kind,
        });
    }
    let output = PartitionTableOutput {
        image: path.display().to_string(),
        scheme: partition_scheme_str(table.scheme),
        logical_block_bytes: table.logical_block_bytes,
        disk_guid: table.disk_guid.map(|g| g.to_string()),
        used_backup_gpt: table.used_backup_gpt_header,
        partitions: rows,
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize partition table")?
        );
    } else {
        println!(
            "Partition table: {} (sector={}B, entries={}, backup_gpt={})",
            output.scheme,
            output.logical_block_bytes,
            output.partitions.len(),
            output.used_backup_gpt
        );
        for row in &output.partitions {
            println!(
                "  #{:<3} lba={}..={} start={}B len={}B fs={} uuid={} label={}",
                row.index,
                row.start_lba,
                row.end_lba_inclusive,
                row.start_byte,
                row.byte_len,
                row.filesystem.as_deref().unwrap_or("unknown"),
                row.part_uuid.as_deref().unwrap_or("-"),
                row.label.as_deref().unwrap_or("-"),
            );
        }
    }
    emit_router_telemetry("partitions", output.scheme, None, true, before, path);
    Ok(())
}

pub fn inspect_partitioned_cmd(
    path: &Path,
    json: bool,
    list_subvolumes: bool,
    list_snapshots: bool,
    six: &SixFormatCliArgs,
) -> Result<()> {
    let cx = cli_cx();
    let before = sha256_regular_file(path);
    let (kind, detected, part_entry, part_dev) = detect_target_format(&cx, path, six)?;
    six.validate_format_compatibility(kind)?;
    let part_dev = part_dev.context("partitioned inspect requires --partition")?;
    let open_opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };

    if list_subvolumes || list_snapshots {
        if !matches!(detected, DetectedFilesystem::Btrfs(_)) {
            bail!("--subvolumes and --snapshots are only supported for btrfs images");
        }
        let fs = OpenFs::from_devices(
            &cx,
            Box::new(part_dev),
            &open_opts,
            VolumeAccess::ReadOnly,
            None,
            Vec::new(),
        )
        .context("open partitioned btrfs slice")?;
        let root_entries = fs
            .walk_btrfs_root_tree(&cx)
            .context("walk btrfs root tree")?;
        if list_subvolumes {
            let subvols = ffs_btrfs::enumerate_subvolumes(&root_entries);
            if json {
                let rows: Vec<_> = subvols
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "id": s.id,
                            "parent_id": s.parent_id,
                            "name": s.name,
                            "generation": s.generation,
                            "read_only": s.read_only,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                println!("Subvolumes ({} found):", subvols.len());
                for s in &subvols {
                    println!(
                        "  id={} parent={} gen={} ro={} name={}",
                        s.id, s.parent_id, s.generation, s.read_only, s.name
                    );
                }
            }
        }
        if list_snapshots {
            let snaps = ffs_btrfs::enumerate_snapshots(&root_entries);
            if json {
                let rows: Vec<_> = snaps
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "id": s.id,
                            "source_id": s.source_id,
                            "name": s.name,
                            "generation": s.generation,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                println!("Snapshots ({} found):", snaps.len());
                for s in &snaps {
                    println!(
                        "  id={} source={} gen={} name={}",
                        s.id, s.source_id, s.generation, s.name
                    );
                }
            }
        }
        emit_router_telemetry(
            "inspect",
            kind.as_str(),
            part_entry.as_ref(),
            true,
            before,
            path,
        );
        return Ok(());
    }

    let output = match &detected {
        DetectedFilesystem::Ext4(sb) => {
            let open_fs = OpenFs::from_devices(
                &cx,
                Box::new(part_dev),
                &open_opts,
                VolumeAccess::ReadOnly,
                None,
                Vec::new(),
            )
            .context("open partitioned ext4 slice")?;
            let summary = open_fs.free_space_summary(&cx)?;
            let orphans = open_fs.read_ext4_orphan_list(&cx)?;
            let orphan_diagnostics =
                (!orphans.inodes.is_empty()).then(|| Ext4OrphanDiagnosticsOutput {
                    count: u32::try_from(orphans.count()).unwrap_or(u32::MAX),
                    sample_inodes: orphans.inodes.iter().take(16).map(|ino| ino.0).collect(),
                });
            let mismatch =
                (summary.blocks_mismatch || summary.inodes_mismatch).then_some(FreeSpaceMismatch {
                    gd_free_blocks: summary.gd_free_blocks_total,
                    gd_free_inodes: summary.gd_free_inodes_total,
                });
            InspectOutput::Ext4 {
                block_size: sb.block_size,
                inodes_count: sb.inodes_count,
                blocks_count: sb.blocks_count,
                volume_name: sb.volume_name.clone(),
                free_blocks_total: summary.free_blocks_total,
                free_inodes_total: summary.free_inodes_total,
                quota_inodes: ext4_quota_inodes_for_output(sb),
                free_space_mismatch: mismatch,
                orphan_diagnostics,
            }
        }
        DetectedFilesystem::Btrfs(sb) => InspectOutput::Btrfs {
            sectorsize: sb.sectorsize,
            nodesize: sb.nodesize,
            generation: sb.generation,
            label: sb.label.clone(),
        },
        DetectedFilesystem::Fat16(fat) => InspectOutput::Fat16 {
            sector_bytes: fat.sector_bytes,
            cluster_bytes: fat.cluster_bytes,
            cluster_count: fat.cluster_count,
            volume_bytes: fat.volume_bytes,
            fat_count: fat.fat_count,
            active_fat: fat.active_fat,
            mirrored: fat.mirrored,
        },
        DetectedFilesystem::Fat32(fat) => InspectOutput::Fat32 {
            sector_bytes: fat.sector_bytes,
            cluster_bytes: fat.cluster_bytes,
            cluster_count: fat.cluster_count,
            volume_bytes: fat.volume_bytes,
            fat_count: fat.fat_count,
            active_fat: fat.active_fat,
            mirrored: fat.mirrored,
            root_cluster: fat.root_cluster,
            fs_info_sector: fat.fs_info_sector,
            backup_boot_sector: fat.backup_boot_sector,
        },
        DetectedFilesystem::Ntfs(ntfs) => InspectOutput::Ntfs {
            sector_bytes: ntfs.sector_bytes,
            cluster_bytes: ntfs.cluster_bytes,
            volume_bytes: ntfs.volume_bytes,
            cluster_count: ntfs.cluster_count,
            mft_cluster: ntfs.mft_cluster,
            mirror_cluster: ntfs.mirror_cluster,
            record_bytes: ntfs.record_bytes,
            index_bytes: ntfs.index_bytes,
            serial: ntfs.serial,
        },
        DetectedFilesystem::Zfs(zfs) => InspectOutput::Zfs {
            valid_labels: zfs.valid_labels,
            pool_name: zfs.pool_name.clone(),
            pool_guid: zfs.pool_guid.map(|g| g.to_string()),
            leaf_guid: zfs.leaf_guid.map(|g| g.to_string()),
            version: zfs.version,
            state: zfs.state,
            config_txg: zfs.config_txg,
            vdev_type: zfs.vdev_type.clone(),
            highest_uberblock_txg: zfs.highest_uberblock_txg,
            candidate_uberblocks: zfs.candidate_uberblocks,
        },
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        crate::cmd_inspect::print_inspect_output(&output);
    }
    emit_router_telemetry(
        "inspect",
        kind.as_str(),
        part_entry.as_ref(),
        true,
        before,
        path,
    );
    Ok(())
}

pub fn maybe_route_info_cmd(
    path: &PathBuf,
    options: InfoCommandOptions,
    six: &SixFormatCliArgs,
) -> Result<bool> {
    let cx = cli_cx();
    let before = sha256_regular_file(path);
    let (kind, detected, part_entry, _part_dev) = detect_target_format(&cx, path, six)?;
    six.validate_format_compatibility(kind)?;
    if part_entry.is_none() && matches!(kind, FsFormatKind::Ext4 | FsFormatKind::Btrfs) {
        return Ok(false);
    }

    let ro_opts = six.build_read_only_options(kind, None, &[], 0, 0)?;
    let opened = open_read_only(&cx, path, &ro_opts)
        .with_context(|| format!("failed to open {} for info", path.display()))?;
    let mut scope = RequestScope::empty();
    let stat = opened
        .filesystem
        .statfs(&cx, &mut scope, InodeNumber(1))
        .context("statfs root for info")?;

    let partition_json = part_entry.as_ref().map(|entry| {
        serde_json::json!({
            "index": entry.index,
            "scheme": partition_scheme_str(entry.scheme),
            "start_byte": entry.start_byte,
            "byte_len": entry.byte_len,
            "part_uuid": entry.part_uuid.map(|u| u.to_string()),
            "label": entry.label,
        })
    });

    let details = match &detected {
        DetectedFilesystem::Ext4(sb) => serde_json::json!({
            "block_size": sb.block_size,
            "blocks_count": sb.blocks_count,
            "inodes_count": sb.inodes_count,
            "volume_name": sb.volume_name,
        }),
        DetectedFilesystem::Btrfs(sb) => serde_json::json!({
            "sectorsize": sb.sectorsize,
            "nodesize": sb.nodesize,
            "generation": sb.generation,
            "label": sb.label,
        }),
        DetectedFilesystem::Fat16(fat) => serde_json::json!({
            "sector_bytes": fat.sector_bytes,
            "cluster_bytes": fat.cluster_bytes,
            "cluster_count": fat.cluster_count,
            "volume_bytes": fat.volume_bytes,
            "fat_count": fat.fat_count,
            "mirrored": fat.mirrored,
        }),
        DetectedFilesystem::Fat32(fat) => serde_json::json!({
            "sector_bytes": fat.sector_bytes,
            "cluster_bytes": fat.cluster_bytes,
            "cluster_count": fat.cluster_count,
            "volume_bytes": fat.volume_bytes,
            "root_cluster": fat.root_cluster,
            "fs_info_sector": fat.fs_info_sector,
            "backup_boot_sector": fat.backup_boot_sector,
        }),
        DetectedFilesystem::Ntfs(ntfs) => {
            let (vol_flags, logfile_recovered) = opened.ntfs_volume().map_or((0, false), |v| {
                (v.volume_flags, v.logfile_recovery.is_some())
            });
            serde_json::json!({
                "sector_bytes": ntfs.sector_bytes,
                "cluster_bytes": ntfs.cluster_bytes,
                "cluster_count": ntfs.cluster_count,
                "volume_bytes": ntfs.volume_bytes,
                "mft_cluster": ntfs.mft_cluster,
                "mirror_cluster": ntfs.mirror_cluster,
                "record_bytes": ntfs.record_bytes,
                "serial": format!("0x{:016x}", ntfs.serial),
                "volume_flags": vol_flags,
                "logfile_recovered": logfile_recovered,
            })
        }
        DetectedFilesystem::Zfs(zfs) => serde_json::json!({
            "pool_name": zfs.pool_name,
            "pool_guid": zfs.pool_guid.map(|g| g.to_string()),
            "leaf_guid": zfs.leaf_guid.map(|g| g.to_string()),
            "valid_labels": zfs.valid_labels,
            "version": zfs.version,
            "vdev_type": zfs.vdev_type,
            "highest_uberblock_txg": zfs.highest_uberblock_txg,
            "candidate_uberblocks": zfs.candidate_uberblocks,
        }),
    };

    let payload = serde_json::json!({
        "filesystem": kind.as_str(),
        "read_only": true,
        "partition": partition_json,
        "statfs": {
            "blocks": stat.blocks,
            "bfree": stat.blocks_free,
            "bavail": stat.blocks_available,
            "files": stat.files,
            "ffree": stat.files_free,
            "bsize": stat.block_size,
            "namelen": stat.name_max,
        },
        "superblock": details,
    });

    if options.json {
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("FrankenFS Info ({})", kind.as_str());
        if let Some(part) = &part_entry {
            println!(
                "  partition: #{} ({}, start={}B, len={}B, label={})",
                part.index,
                partition_scheme_str(part.scheme),
                part.start_byte,
                part.byte_len,
                part.label.as_deref().unwrap_or("-")
            );
        }
        println!(
            "  statfs: blocks={} free={} bsize={} files={} ffree={}",
            stat.blocks, stat.blocks_free, stat.block_size, stat.files, stat.files_free
        );
        println!("  metadata: {details}");
    }
    drop(opened);
    emit_router_telemetry(
        "info",
        kind.as_str(),
        part_entry.as_ref(),
        true,
        before,
        path,
    );
    Ok(true)
}

fn resolve_readonly_path(cx: &Cx, opened: &ReadOnlyFs, file_path: &str) -> Result<InodeNumber> {
    let mut ino = InodeNumber(1);
    for comp in file_path.split('/').filter(|c| !c.is_empty()) {
        let mut scope = opened
            .filesystem
            .begin_request_scope(cx, RequestOp::Lookup)?;
        let attr = opened
            .filesystem
            .lookup(cx, &mut scope, ino, OsStr::new(comp))
            .with_context(|| format!("failed to resolve {file_path:?} at component {comp:?}"))?;
        ino = attr.ino;
    }
    Ok(ino)
}

pub fn maybe_route_read_cmd(
    path: &PathBuf,
    file_path: &str,
    discard: bool,
    bench_evidence: bool,
    six: &SixFormatCliArgs,
) -> Result<bool> {
    if bench_evidence && six.partition.is_none() {
        return Ok(false);
    }
    let cx = cli_cx();
    let (kind, _detected, part_entry, _part_dev) = detect_target_format(&cx, path, six)?;
    six.validate_format_compatibility(kind)?;
    if part_entry.is_none() && matches!(kind, FsFormatKind::Ext4 | FsFormatKind::Btrfs) {
        return Ok(false);
    }
    if bench_evidence {
        bail!("--bench-evidence is only supported on unpartitioned ext4/btrfs read benchmarks");
    }

    let before = sha256_regular_file(path);
    let ro_opts = six.build_read_only_options(kind, None, &[], 0, 0)?;
    let opened = open_read_only(&cx, path, &ro_opts)
        .with_context(|| format!("failed to open {} ({})", path.display(), kind.as_str()))?;
    let ino = resolve_readonly_path(&cx, &opened, file_path)?;
    let mut stat_scope = opened
        .filesystem
        .begin_request_scope(&cx, RequestOp::Getattr)?;
    let size = opened
        .filesystem
        .getattr(&cx, &mut stat_scope, ino)
        .with_context(|| format!("failed to stat {file_path}"))?
        .size;
    drop(stat_scope);

    let mut out = io::stdout().lock();
    let mut off = 0_u64;
    let mut total = 0_u64;
    let chunk_bytes: u32 = 1024 * 1024;
    while off < size {
        let want = u32::try_from((size - off).min(u64::from(chunk_bytes))).unwrap_or(chunk_bytes);
        let mut read_scope = opened
            .filesystem
            .begin_request_scope(&cx, RequestOp::Read)?;
        let data = opened
            .filesystem
            .read(&cx, &mut read_scope, ino, off, want)
            .with_context(|| format!("failed to read {file_path} at offset {off}"))?;
        if data.is_empty() {
            break;
        }
        let n = u64::try_from(data.len()).unwrap_or(0);
        off += n;
        total += n;
        if !discard {
            out.write_all(&data)
                .context("failed to write file bytes to stdout")?;
        }
    }
    out.flush().context("flush stdout")?;
    if discard {
        eprintln!("read {total} bytes from {file_path}");
    }
    drop(opened);
    emit_router_telemetry(
        "read",
        kind.as_str(),
        part_entry.as_ref(),
        true,
        before,
        path,
    );
    Ok(true)
}

#[derive(Debug, Serialize)]
struct LsEntryOutput {
    name: String,
    ino: u64,
    kind: String,
    size: u64,
    perm: u16,
}

pub fn ls_cmd(path: &Path, dir_path: &str, json: bool, six: &SixFormatCliArgs) -> Result<()> {
    let cx = cli_cx();
    let before = sha256_regular_file(path);
    let (kind, _detected, part_entry, _part_dev) = detect_target_format(&cx, path, six)?;
    let ro_opts = six.build_read_only_options(kind, None, &[], 0, 0)?;
    let opened = open_read_only(&cx, path, &ro_opts)
        .with_context(|| format!("failed to open {} ({})", path.display(), kind.as_str()))?;
    let dir_ino = resolve_readonly_path(&cx, &opened, dir_path)?;
    let mut entries_out = Vec::new();
    let mut offset = 0_u64;
    let mut seen_offsets = std::collections::BTreeSet::new();
    loop {
        let mut scope = opened
            .filesystem
            .begin_request_scope(&cx, RequestOp::Readdir)?;
        let batch = opened
            .filesystem
            .readdir(&cx, &mut scope, dir_ino, offset)
            .with_context(|| format!("failed to list directory {dir_path:?}"))?;
        drop(scope);
        if batch.is_empty() {
            break;
        }
        let mut next_offset = offset;
        for entry in &batch {
            next_offset = entry.offset;
            if entry.name == b"." || entry.name == b".." {
                continue;
            }
            let name = String::from_utf8_lossy(&entry.name).into_owned();
            let mut attr_scope = opened
                .filesystem
                .begin_request_scope(&cx, RequestOp::Getattr)?;
            let (size, perm) = opened
                .filesystem
                .getattr(&cx, &mut attr_scope, entry.ino)
                .map_or((0, 0), |attr| (attr.size, attr.perm));
            entries_out.push(LsEntryOutput {
                name,
                ino: entry.ino.0,
                kind: format!("{:?}", entry.kind),
                size,
                perm,
            });
        }
        if next_offset == 0 || !seen_offsets.insert(next_offset) {
            break;
        }
        offset = next_offset;
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&entries_out)?);
    } else {
        for row in &entries_out {
            println!(
                "{:<12} {:>10} 0{:04o} ino={:<8} {}",
                row.kind, row.size, row.perm, row.ino, row.name
            );
        }
    }
    drop(opened);
    emit_router_telemetry("ls", kind.as_str(), part_entry.as_ref(), true, before, path);
    Ok(())
}

pub fn maybe_route_walk_cmd(
    path: &PathBuf,
    no_stat: bool,
    read_data: bool,
    six: &SixFormatCliArgs,
) -> Result<bool> {
    let cx = cli_cx();
    let (kind, _detected, part_entry, _part_dev) = detect_target_format(&cx, path, six)?;
    six.validate_format_compatibility(kind)?;
    if part_entry.is_none() && matches!(kind, FsFormatKind::Ext4 | FsFormatKind::Btrfs) {
        return Ok(false);
    }

    let before = sha256_regular_file(path);
    let started = std::time::Instant::now();
    let ro_opts = six.build_read_only_options(kind, None, &[], 0, 0)?;
    let opened = open_read_only(&cx, path, &ro_opts)
        .with_context(|| format!("failed to open {} ({})", path.display(), kind.as_str()))?;
    let mut queue = std::collections::VecDeque::from([InodeNumber(1)]);
    let mut visited_dirs = std::collections::BTreeSet::from([1_u64]);
    let mut dirs = 1_u64;
    let mut files = 0_u64;
    let mut stats = 0_u64;
    let mut bytes = 0_u64;

    while let Some(dir_ino) = queue.pop_front() {
        let mut offset = 0_u64;
        let mut seen_offsets = std::collections::BTreeSet::new();
        loop {
            let mut scope = opened
                .filesystem
                .begin_request_scope(&cx, RequestOp::Readdir)?;
            let batch = opened
                .filesystem
                .readdir(&cx, &mut scope, dir_ino, offset)?;
            drop(scope);
            if batch.is_empty() {
                break;
            }
            let mut next_offset = offset;
            for entry in &batch {
                next_offset = entry.offset;
                if entry.name == b"." || entry.name == b".." || entry.name == b".zfs" {
                    continue;
                }
                let file_size = if !no_stat || read_data {
                    let mut attr_scope = opened
                        .filesystem
                        .begin_request_scope(&cx, RequestOp::Getattr)?;
                    let attr = opened.filesystem.getattr(&cx, &mut attr_scope, entry.ino)?;
                    stats += 1;
                    attr.size
                } else {
                    0_u64
                };
                if entry.kind == FileType::Directory {
                    if visited_dirs.insert(entry.ino.0) {
                        dirs += 1;
                        queue.push_back(entry.ino);
                    }
                } else {
                    files += 1;
                    if read_data && entry.kind == FileType::RegularFile {
                        let mut off = 0_u64;
                        while off < file_size {
                            let want =
                                u32::try_from((file_size - off).min(262_144)).unwrap_or(262_144);
                            let mut rscope = opened
                                .filesystem
                                .begin_request_scope(&cx, RequestOp::Read)?;
                            let data =
                                opened
                                    .filesystem
                                    .read(&cx, &mut rscope, entry.ino, off, want)?;
                            if data.is_empty() {
                                break;
                            }
                            let n = u64::try_from(data.len()).unwrap_or(0);
                            off += n;
                            bytes += n;
                        }
                    }
                }
            }
            if next_offset == 0 || !seen_offsets.insert(next_offset) {
                break;
            }
            offset = next_offset;
        }
    }

    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    println!(
        "walk ({}) dirs={dirs} files={files} stats={stats} bytes={bytes} elapsed_ms={elapsed_ms:.2}",
        kind.as_str()
    );
    drop(opened);
    emit_router_telemetry(
        "walk",
        kind.as_str(),
        part_entry.as_ref(),
        true,
        before,
        path,
    );
    Ok(true)
}

fn open_zfs_pool_and_objects(
    cx: &Cx,
    path: &Path,
    part_entry: Option<&PartitionEntry>,
    six: &SixFormatCliArgs,
) -> Result<(ffs_zfs::reader::Pool, ffs_zfs::reader::dmu::Objects)> {
    if !six.offline_image {
        bail!("--offline-image is required for ZFS pool and dataset operations");
    }
    let (offset, length) = part_entry.map_or((0, None), |p| (p.start_byte, Some(p.byte_len)));
    let primary = ffs_zfs::reader::Leaf::open(cx, path, offset, length)
        .with_context(|| format!("opening ZFS leaf {}", path.display()))?;
    let mut leaves = Vec::with_capacity(six.zfs_members.len() + 1);
    leaves.push(primary);
    for member in &six.zfs_members {
        if part_entry.is_some() {
            bail!("--zfs-member cannot be combined with --partition");
        }
        leaves.push(
            ffs_zfs::reader::Leaf::open(cx, member, 0, None)
                .with_context(|| format!("opening ZFS member {}", member.display()))?,
        );
    }
    let pool = if !six.missing_raidz_members.is_empty() {
        ffs_zfs::reader::Pool::from_raidz_survivors(cx, leaves, six.missing_raidz_members.clone())?
    } else if !six.missing_mirror_members.is_empty() {
        ffs_zfs::reader::Pool::from_mirror_survivors(
            cx,
            leaves,
            six.missing_mirror_members.clone(),
        )?
    } else {
        ffs_zfs::reader::Pool::from_leaves(leaves)?
    };

    let objects = match (six.pool_guid, six.zfs_label, six.zfs_slot) {
        (Some(pool_guid), Some(label), Some(slot)) => pool.objects(cx, label, slot, pool_guid)?,
        (pool_guid, None, None) => pool.import_objects(cx, pool_guid)?,
        _ => bail!(
            "explicit ZFS candidate selection requires all three of --pool-guid, --zfs-label, and --zfs-slot"
        ),
    };
    Ok((pool, objects))
}

pub fn maybe_route_fsck_cmd(
    path: &Path,
    options: FsckCommandOptions,
    six: &SixFormatCliArgs,
) -> Result<bool> {
    let cx = cli_cx();
    let (kind, detected, part_entry, part_dev) = detect_target_format(&cx, path, six)?;
    six.validate_format_compatibility(kind)?;
    if part_entry.is_none() && matches!(kind, FsFormatKind::Ext4 | FsFormatKind::Btrfs) {
        return Ok(false);
    }

    let repair = options.flags.repair();
    let json_out = options.flags.json();
    if repair && part_entry.is_some() {
        bail!(
            "--repair on a --partition slice is refused; extract or repair an offline standalone volume"
        );
    }
    if repair && matches!(kind, FsFormatKind::Ntfs | FsFormatKind::Zfs) {
        bail!(
            "--repair is not supported for {} (FrankenFS provides read-only verification for {})",
            kind.as_str(),
            kind.as_str()
        );
    }

    let before = (!repair).then(|| sha256_regular_file(path)).flatten();
    let (offset, length) = part_entry
        .as_ref()
        .map_or((0_u64, None), |p| (p.start_byte, Some(p.byte_len)));

    let (clean, report_json) = match kind {
        FsFormatKind::Fat16 | FsFormatKind::Fat32 => {
            if repair {
                if !six.offline_image {
                    bail!("--offline-image is required for FAT fsck --repair");
                }
                let rec_args = ffs_fat::reader::recovery::RecoverArgs {
                    image: ffs_fat::ImageArgs {
                        image: path.to_path_buf(),
                        offset: 0,
                        length: None,
                        oem_code_page: FatOemCodePage::Ascii,
                        sidecar: None,
                    },
                    offline_image: true,
                    reclaim_lost: true,
                    discard_orphan_lfn: true,
                    repair_mirrors_from: None,
                    repair_boot_from: None,
                    salvage_to: None,
                    dry_run: false,
                };
                let rec = ffs_fat::reader::recovery::recover(&cx, &rec_args)?;
                let chk = ffs_fat::reader::recovery::check(&cx, &rec_args.image)?;
                (
                    chk.clean,
                    serde_json::json!({ "recover": rec, "post_check": chk }),
                )
            } else {
                let img = ffs_fat::ImageArgs {
                    image: path.to_path_buf(),
                    offset,
                    length,
                    oem_code_page: FatOemCodePage::Ascii,
                    sidecar: None,
                };
                let chk = ffs_fat::reader::recovery::check(&cx, &img)?;
                (chk.clean, serde_json::to_value(&chk)?)
            }
        }
        FsFormatKind::Ntfs => {
            let volume = ffs_ntfs::NtfsVolume::open_with_options(&cx, path, offset, length, false)?;
            let alloc = volume.check_allocations(
                &cx,
                ffs_ntfs::reader::allocation::AllocationLimits::default(),
            )?;
            let mirror = volume.check_mft_mirror(
                &cx,
                ffs_ntfs::reader::allocation::RecordOwnershipLimits::default(),
            )?;
            let ownership = volume.check_record_ownership(
                &cx,
                ffs_ntfs::reader::allocation::RecordOwnershipLimits::default(),
            )?;
            let namespace = volume.check_namespace(
                &cx,
                ffs_ntfs::reader::allocation::NamespaceLimits::default(),
            )?;
            let clean = alloc.is_consistent()
                && mirror.is_consistent()
                && ownership.is_consistent()
                && namespace.is_consistent();
            let summary = serde_json::json!({
                "allocation_consistent": alloc.is_consistent(),
                "mft_mirror_consistent": mirror.is_consistent(),
                "record_ownership_consistent": ownership.is_consistent(),
                "namespace_consistent": namespace.is_consistent(),
                "allocated_records_examined": alloc.allocated_records_examined,
                "referenced_clusters": alloc.referenced_clusters,
                "bitmap_allocated_clusters": alloc.bitmap_allocated_clusters,
                "cross_linked_clusters": alloc.cross_linked_clusters,
                "referenced_free_clusters": alloc.referenced_free_clusters,
                "allocated_without_reference": alloc.allocated_without_reference,
                "mft_mirror_records_checked": mirror.record_pairs_examined,
            });
            (clean, summary)
        }
        FsFormatKind::Zfs => {
            let (_pool, mut objects) =
                open_zfs_pool_and_objects(&cx, path, part_entry.as_ref(), six)?;
            let ds_components =
                parse_zfs_dataset_components(six.zfs_dataset.as_deref().unwrap_or(""))?;
            let zpl = match six.zfs_snapshot.as_deref() {
                Some(snap) => objects.zpl_snapshot(&cx, &ds_components, snap.as_bytes())?,
                None => objects.zpl(&cx, &ds_components)?,
            };
            let limits = ffs_zfs::reader::dmu::scrub::ScrubLimits {
                pointers: 16_777_216,
                decoded_bytes: 1_099_511_627_776,
                objects: 1_048_576,
                copy_bytes: None,
            };
            let scrub = zpl.scrub(&cx, limits)?;
            let clean = scrub.is_clean();
            (clean, serde_json::to_value(&scrub)?)
        }
        FsFormatKind::Ext4 | FsFormatKind::Btrfs => {
            let part_dev = part_dev.context("partitioned ext4/btrfs fsck requires partition")?;
            let (flavor, block_size) = match &detected {
                DetectedFilesystem::Ext4(sb) => (FsFlavor::Ext4(sb.clone()), sb.block_size),
                DetectedFilesystem::Btrfs(sb) => {
                    let bs = choose_btrfs_scrub_block_size(
                        part_dev.len_bytes(),
                        sb.nodesize,
                        sb.sectorsize,
                    )?;
                    (FsFlavor::Btrfs(sb.clone()), bs)
                }
                _ => unreachable!(),
            };
            let block_dev = ByteBlockDevice::new(part_dev, block_size)?;
            let validator: Box<dyn ffs_repair::scrub::BlockValidator> = match &flavor {
                FsFlavor::Ext4(_) => Box::new(Ext4SuperblockValidator::new(block_size)),
                FsFlavor::Btrfs(_) => scrub_validator(&flavor, block_size),
            };
            let report = Scrubber::new(&block_dev, &*validator).scrub_all(&cx)?;
            let errs = count_blocks_at_severity_or_higher(&report, Severity::Error);
            let clean = errs == 0;
            let summary = serde_json::json!({
                "blocks_scanned": report.blocks_scanned,
                "blocks_corrupt": report.blocks_corrupt,
                "blocks_error_or_higher": errs,
            });
            (clean, summary)
        }
    };

    let exit_code = i32::from(!clean);
    let out_doc = serde_json::json!({
        "filesystem": kind.as_str(),
        "partition": part_entry.as_ref().map(|p| p.index),
        "clean": clean,
        "exit_code": exit_code,
        "details": report_json,
    });
    if json_out {
        println!("{}", serde_json::to_string_pretty(&out_doc)?);
    } else {
        println!(
            "FrankenFS fsck ({}): status={} (exit_code={exit_code})",
            kind.as_str(),
            if clean { "clean" } else { "errors_detected" }
        );
    }
    emit_router_telemetry(
        "fsck",
        kind.as_str(),
        part_entry.as_ref(),
        true,
        before,
        path,
    );
    if !clean {
        std::process::exit(exit_code);
    }
    Ok(true)
}

pub fn maybe_route_scrub_cmd(path: &Path, json: bool, six: &SixFormatCliArgs) -> Result<bool> {
    let cx = cli_cx();
    let (kind, detected, part_entry, part_dev) = detect_target_format(&cx, path, six)?;
    six.validate_format_compatibility(kind)?;
    if part_entry.is_none() && matches!(kind, FsFormatKind::Ext4 | FsFormatKind::Btrfs) {
        return Ok(false);
    }

    let before = sha256_regular_file(path);
    let (offset, length) = part_entry
        .as_ref()
        .map_or((0_u64, None), |p| (p.start_byte, Some(p.byte_len)));

    let (scanned, corrupt, findings) = match kind {
        FsFormatKind::Zfs => {
            let (_pool, mut objects) =
                open_zfs_pool_and_objects(&cx, path, part_entry.as_ref(), six)?;
            let ds = parse_zfs_dataset_components(six.zfs_dataset.as_deref().unwrap_or(""))?;
            let zpl = match six.zfs_snapshot.as_deref() {
                Some(snap) => objects.zpl_snapshot(&cx, &ds, snap.as_bytes())?,
                None => objects.zpl(&cx, &ds)?,
            };
            let report = zpl.scrub(
                &cx,
                ffs_zfs::reader::dmu::scrub::ScrubLimits {
                    pointers: 16_777_216,
                    decoded_bytes: 1_099_511_627_776,
                    objects: 1_048_576,
                    copy_bytes: None,
                },
            )?;
            let findings: Vec<ScrubFindingOutput> = report
                .issues
                .iter()
                .map(|issue| ScrubFindingOutput {
                    block: issue.block.unwrap_or(issue.object),
                    kind: issue.category.to_owned(),
                    severity: "error".to_owned(),
                    detail: issue.detail.clone(),
                })
                .collect();
            (report.verified_blocks, report.errors, findings)
        }
        FsFormatKind::Fat16 | FsFormatKind::Fat32 => {
            let img = ffs_fat::ImageArgs {
                image: path.to_path_buf(),
                offset,
                length,
                oem_code_page: FatOemCodePage::Ascii,
                sidecar: None,
            };
            let chk = ffs_fat::reader::recovery::check(&cx, &img)?;
            let corrupt = u64::from(!chk.clean);
            let findings = if chk.clean {
                Vec::new()
            } else {
                vec![ScrubFindingOutput {
                    block: 0,
                    kind: "fat_consistency".to_owned(),
                    severity: "error".to_owned(),
                    detail: chk.status.to_owned(),
                }]
            };
            (chk.allocated_clusters, corrupt, findings)
        }
        FsFormatKind::Ntfs => {
            let volume = ffs_ntfs::NtfsVolume::open_with_options(&cx, path, offset, length, false)?;
            let alloc = volume.check_allocations(
                &cx,
                ffs_ntfs::reader::allocation::AllocationLimits::default(),
            )?;
            let mirror = volume.check_mft_mirror(
                &cx,
                ffs_ntfs::reader::allocation::RecordOwnershipLimits::default(),
            )?;
            let mut findings: Vec<ScrubFindingOutput> = alloc
                .issues
                .iter()
                .map(|issue| ScrubFindingOutput {
                    block: issue.first_cluster.unwrap_or(0),
                    kind: issue.category.to_owned(),
                    severity: "error".to_owned(),
                    detail: issue.detail.clone(),
                })
                .collect();
            if !mirror.is_consistent() {
                findings.push(ScrubFindingOutput {
                    block: volume.geometry.mirror_cluster(),
                    kind: "mft_mirror_mismatch".to_owned(),
                    severity: "error".to_owned(),
                    detail: format!("different_records={}", mirror.different_records),
                });
            }
            let corrupt = u64::from(!(alloc.is_consistent() && mirror.is_consistent()));
            (alloc.referenced_clusters, corrupt, findings)
        }
        FsFormatKind::Ext4 | FsFormatKind::Btrfs => {
            let part_dev = part_dev.context("partitioned scrub requires partition")?;
            let (flavor, block_size) = match &detected {
                DetectedFilesystem::Ext4(sb) => (FsFlavor::Ext4(sb.clone()), sb.block_size),
                DetectedFilesystem::Btrfs(sb) => {
                    let bs = choose_btrfs_scrub_block_size(
                        part_dev.len_bytes(),
                        sb.nodesize,
                        sb.sectorsize,
                    )?;
                    (FsFlavor::Btrfs(sb.clone()), bs)
                }
                _ => unreachable!(),
            };
            let block_dev = ByteBlockDevice::new(part_dev, block_size)?;
            let validator: Box<dyn ffs_repair::scrub::BlockValidator> = match &flavor {
                FsFlavor::Ext4(_) => Box::new(Ext4SuperblockValidator::new(block_size)),
                FsFlavor::Btrfs(_) => scrub_validator(&flavor, block_size),
            };
            let report = Scrubber::new(&block_dev, &*validator).scrub_all(&cx)?;
            let errs = count_blocks_at_severity_or_higher(&report, Severity::Error);
            let out = ScrubOutput {
                blocks_scanned: report.blocks_scanned,
                blocks_corrupt: report.blocks_corrupt,
                blocks_error_or_higher: errs,
                blocks_io_error: report.blocks_io_error,
                findings: report
                    .findings
                    .iter()
                    .map(|f| ScrubFindingOutput {
                        block: f.block.0,
                        kind: f.kind.to_string(),
                        severity: f.severity.to_string(),
                        detail: f.detail.clone(),
                    })
                    .collect(),
            };
            print_scrub_output(json, &out, &report)?;
            emit_router_telemetry(
                "scrub",
                kind.as_str(),
                part_entry.as_ref(),
                true,
                before,
                path,
            );
            if errs > 0 {
                std::process::exit(2);
            }
            return Ok(true);
        }
    };

    let out = ScrubOutput {
        blocks_scanned: scanned,
        blocks_corrupt: corrupt,
        blocks_error_or_higher: corrupt,
        blocks_io_error: 0,
        findings,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!(
            "Scrub ({}): scanned={} corrupt={}",
            kind.as_str(),
            out.blocks_scanned,
            out.blocks_corrupt
        );
    }
    emit_router_telemetry(
        "scrub",
        kind.as_str(),
        part_entry.as_ref(),
        true,
        before,
        path,
    );
    if corrupt > 0 {
        std::process::exit(2);
    }
    Ok(true)
}

pub fn maybe_route_mount_cmd(
    image_path: &Path,
    mountpoint: &Path,
    options: &MountCmdOptions,
    six: &SixFormatCliArgs,
) -> Result<bool> {
    if six.partition.is_none() && options.runtime.validate().is_err() {
        return Ok(false);
    }
    let cx = cli_cx();
    let (kind, _detected, part_entry, _part_dev) = match detect_target_format(&cx, image_path, six)
    {
        Ok(target) => target,
        Err(_err) if six.partition.is_none() && !six.has_ntfs_flags() && !six.has_zfs_flags() => {
            return Ok(false);
        }
        Err(err) => {
            return Err(err).with_context(|| {
                format!("failed to open filesystem image: {}", image_path.display())
            });
        }
    };
    six.validate_format_compatibility(kind)?;
    if part_entry.is_none() && matches!(kind, FsFormatKind::Ext4 | FsFormatKind::Btrfs) {
        return Ok(false);
    }
    options.runtime.validate()?;

    if !six.offline_image && !matches!(kind, FsFormatKind::Ext4 | FsFormatKind::Btrfs) {
        bail!(
            "--offline-image is required when mounting {} images",
            kind.as_str()
        );
    }
    if options.read_write {
        if part_entry.is_some() {
            bail!("--rw mount on a --partition slice is refused; mount read-only or extract slice");
        }
        if matches!(kind, FsFormatKind::Ntfs | FsFormatKind::Zfs) {
            bail!(
                "--rw mount is not supported for {} (read-only extraction mount only)",
                kind.as_str()
            );
        }
    }

    let mountpoint_canon = mountpoint
        .canonicalize()
        .with_context(|| format!("resolve mountpoint {}", mountpoint.display()))?;
    if !mountpoint_canon.is_dir()
        || fs::read_dir(&mountpoint_canon)?
            .next()
            .transpose()?
            .is_some()
    {
        bail!(
            "mountpoint {} must be an existing empty directory",
            mountpoint.display()
        );
    }
    if image_path.canonicalize()?.starts_with(&mountpoint_canon) {
        bail!("mountpoint would hide the backing image");
    }

    let fuse_opts = ffs_fuse::MountOptions {
        read_only: !options.read_write,
        allow_other: options.allow_other,
        auto_unmount: options.fuseblk_device.is_none(),
        fuseblk: options.fuseblk_device.is_some(),
        fsname: options.fsname.clone(),
        subtype: options.subtype.clone(),
        atime: options.atime,
        dev: options.dev,
        suid: options.suid,
        ..ffs_fuse::MountOptions::default()
    };

    let before = (!options.read_write)
        .then(|| sha256_regular_file(image_path))
        .flatten();

    let fs_ops: Box<dyn ffs_core::FsOps> = if options.read_write {
        // Unpartitioned writable FAT16/FAT32 mount.
        let img = ffs_fat::ImageArgs {
            image: image_path.to_path_buf(),
            offset: 0,
            length: None,
            oem_code_page: FatOemCodePage::Ascii,
            sidecar: None,
        };
        let volume = ffs_fat::reader::replacement::open_volume(&cx, &img, true)?;
        let fat_fs = ffs_fat::FatFs::new_with_mode(&cx, volume, 0, 0, true)?;
        Box::new(fat_fs)
    } else {
        let ro_opts = six.build_read_only_options(
            kind,
            Some(options.btrfs_mount_selection.clone()),
            &options.btrfs_device_paths,
            0,
            0,
        )?;
        let opened = open_read_only(&cx, image_path, &ro_opts)?;
        opened.filesystem
    };

    match options.runtime.mode {
        MountRuntimeMode::Standard => {
            ffs_fuse::mount(fs_ops, &mountpoint_canon, &fuse_opts)?;
        }
        MountRuntimeMode::Managed | MountRuntimeMode::PerCore => {
            let stop = Arc::new(AtomicBool::new(false));
            let stop_sig = Arc::clone(&stop);
            let _ = ctrlc::set_handler(move || {
                stop_sig.store(true, Ordering::SeqCst);
            });
            let handle = ffs_fuse::mount_background(fs_ops, &mountpoint_canon, &fuse_opts)?;
            while !stop.load(Ordering::SeqCst) && mountpoint_canon.exists() {
                std::thread::sleep(Duration::from_millis(50));
            }
            drop(handle);
        }
    }

    emit_router_telemetry(
        "mount",
        kind.as_str(),
        part_entry.as_ref(),
        true,
        before,
        image_path,
    );
    Ok(true)
}

#[expect(
    clippy::too_many_arguments,
    reason = "CLI format subcommand forwards explicit format arguments directly"
)]
pub fn format_cmd(
    output: &Path,
    filesystem: &str,
    size_mib: u64,
    label: Option<&str>,
    block_size: Option<u32>,
    sectors_per_cluster: Option<u8>,
    delegate_host_mkfs: bool,
    json: bool,
) -> Result<()> {
    let cx = cli_cx();
    let fs_norm = filesystem.trim().to_ascii_lowercase();
    match fs_norm.as_str() {
        "fat16" | "fat32" => {
            if let Some(bs) = block_size
                && bs != 512
            {
                bail!("native FAT formatter uses 512-byte logical sectors (got --block-size {bs})");
            }
            let kind = if fs_norm == "fat16" {
                ffs_fat::formatter::FormatKind::Fat16
            } else {
                ffs_fat::formatter::FormatKind::Fat32
            };
            let args = ffs_fat::formatter::FormatArgs {
                image: output.to_path_buf(),
                kind,
                size_mib,
                sectors_per_cluster,
                label: label.map(str::to_owned),
                serial: Some(0x4646_5331),
                source_dir: None,
                sidecar: None,
            };
            let report = ffs_fat::formatter::create(&cx, &args).with_context(|| {
                format!("failed to format native {fs_norm} at {}", output.display())
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "Formatted native {} image at {} ({} MiB)",
                    fs_norm,
                    output.display(),
                    size_mib
                );
            }
            info!(
                target: "ffs::cli::router",
                command = "format",
                format = %fs_norm,
                partition_id = "whole_image",
                capability_admitted = true,
                native_rust_formatter = true,
                "six_format_router_complete"
            );
            Ok(())
        }
        "ext4" => {
            if !delegate_host_mkfs {
                bail!(
                    "native Rust ext4 formatting is not yet implemented; pass --delegate-host-mkfs to explicitly invoke host mkfs.ext4 (or use --filesystem fat16|fat32 for pure-Rust formatting)"
                );
            }
            mkfs_cmd(
                output,
                size_mib,
                block_size.unwrap_or(4096),
                label.unwrap_or("frankenfs"),
                json,
                true,
            )
        }
        "btrfs" => {
            if !delegate_host_mkfs {
                bail!(
                    "native Rust btrfs formatting is not yet implemented; pass --delegate-host-mkfs to explicitly invoke host mkfs.btrfs"
                );
            }
            let size_bytes = size_mib
                .checked_mul(1024 * 1024)
                .context("size_mib overflow")?;
            let f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)
                .with_context(|| format!("create new btrfs image {}", output.display()))?;
            f.set_len(size_bytes)?;
            drop(f);
            let mut cmd = ProcessCommand::new("mkfs.btrfs");
            cmd.args(["-f", "-q"]);
            if let Some(lbl) = label {
                cmd.args(["-L", lbl]);
            }
            let out = cmd.arg(output).output().context("invoke host mkfs.btrfs")?;
            if !out.status.success() {
                bail!(
                    "mkfs.btrfs failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            let verified = OpenFs::open(&cx, output)?;
            let generation = match &verified.flavor {
                FsFlavor::Btrfs(sb) => sb.generation,
                FsFlavor::Ext4(_) => bail!("expected btrfs image after mkfs.btrfs"),
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "filesystem": "btrfs",
                        "path": output.display().to_string(),
                        "size_bytes": size_bytes,
                        "generation": generation,
                        "delegated_host_mkfs": true,
                    }))?
                );
            } else {
                println!(
                    "Formatted btrfs image (via host mkfs.btrfs) at {} ({size_mib} MiB)",
                    output.display()
                );
            }
            Ok(())
        }
        "ntfs" | "zfs" => bail!(
            "ffs format --filesystem {fs_norm} is refused: FrankenFS provides read-only native inspection/extraction for {fs_norm} and does not format {fs_norm} volumes"
        ),
        other => bail!(
            "unsupported --filesystem {other:?}; expected one of: fat16, fat32, ext4, btrfs, ntfs, zfs"
        ),
    }
}

pub fn streams_cmd(
    image: &Path,
    target: &str,
    stream: Option<&str>,
    by_record: bool,
    json: bool,
    six: &SixFormatCliArgs,
) -> Result<()> {
    let cx = cli_cx();
    let before = sha256_regular_file(image);
    let (kind, _detected, part_entry, _part_dev) = detect_target_format(&cx, image, six)?;
    if kind != FsFormatKind::Ntfs {
        bail!(
            "ffs streams requires an NTFS volume (detected {})",
            kind.as_str()
        );
    }
    six.validate_format_compatibility(kind)?;
    let (offset, length) = part_entry
        .as_ref()
        .map_or((0_u64, None), |p| (p.start_byte, Some(p.byte_len)));
    let volume =
        ffs_ntfs::NtfsVolume::open_with_options(&cx, image, offset, length, six.recover_logfile)?;
    let record = if by_record {
        let rec_no: u64 = target
            .parse()
            .with_context(|| format!("invalid MFT record number {target:?}"))?;
        volume.record(&cx, rec_no, None)?
    } else if six.ntfs_indexed_lookup {
        volume.resolve_indexed_no_follow(&cx, target)?
    } else {
        volume.resolve_no_follow(&cx, target)?
    };

    if let Some(stream_name) = stream {
        let units: Vec<u16> = stream_name.encode_utf16().collect();
        let data_stream = volume
            .data_stream(&cx, &record, &units)
            .with_context(|| format!("locating NTFS DATA stream {stream_name:?}"))?;
        let mut out = io::stdout().lock();
        let mut pos = 0_u64;
        while pos < data_stream.size {
            let want = usize::try_from((data_stream.size - pos).min(65_536)).unwrap_or(65_536);
            let chunk = volume.read(&cx, &data_stream, pos, want)?;
            if chunk.is_empty() {
                break;
            }
            out.write_all(&chunk)?;
            pos += u64::try_from(chunk.len()).unwrap_or(0);
        }
        out.flush()?;
    } else {
        let catalog: Vec<_> = volume
            .data_streams(&cx, &record)?
            .into_iter()
            .map(|entry| {
                let name = String::from_utf16(&entry.name).ok();
                let profile = match entry.read_profile {
                    Ok(meta) => serde_json::json!({
                        "admitted": true,
                        "resident": meta.resident,
                        "size": meta.size,
                        "initialized": meta.initialized,
                        "allocated_bytes": meta.allocated,
                    }),
                    Err(err) => serde_json::json!({
                        "admitted": false,
                        "error": err,
                    }),
                };
                serde_json::json!({
                    "name": name,
                    "name_utf16": entry.name,
                    "attribute_extents": entry.attribute_extents,
                    "read_profile": profile,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "filesystem": "ntfs",
            "record": record.number,
            "sequence": record.sequence,
            "streams": catalog,
        });
        if json {
            println!("{}", serde_json::to_string_pretty(&doc)?);
        } else {
            println!(
                "NTFS DATA streams for record {} (count={}):",
                record.number,
                doc["streams"].as_array().map_or(0, Vec::len)
            );
            for item in doc["streams"].as_array().into_iter().flatten() {
                let name_disp = item["name"].as_str().unwrap_or("<non-utf8>");
                let label = if name_disp.is_empty() {
                    "::$DATA (unnamed)"
                } else {
                    name_disp
                };
                println!(
                    "  stream={label} size={} resident={}",
                    item["read_profile"]["size"], item["read_profile"]["resident"]
                );
            }
        }
    }

    emit_router_telemetry("streams", "ntfs", part_entry.as_ref(), true, before, image);
    Ok(())
}

pub fn pool_cmd(command: &PoolCommand, six: &SixFormatCliArgs) -> Result<()> {
    let cx = cli_cx();
    match command {
        PoolCommand::Inspect { image, json } => {
            let before = sha256_regular_file(image);
            let (kind, _detected, part_entry, _part_dev) = detect_target_format(&cx, image, six)?;
            if kind != FsFormatKind::Zfs {
                bail!(
                    "ffs pool inspect requires a ZFS image (detected {})",
                    kind.as_str()
                );
            }
            six.validate_format_compatibility(kind)?;
            let (offset, length) = part_entry
                .as_ref()
                .map_or((0_u64, None), |p| (p.start_byte, Some(p.byte_len)));
            let leaf = ffs_zfs::reader::Leaf::open(&cx, image, offset, length)?;
            let mut labels = Vec::new();
            let mut valid = 0_usize;
            for idx in 0..4 {
                match leaf.label(&cx, idx) {
                    Ok(lbl) => {
                        valid += 1;
                        let mut candidates = 0_usize;
                        for slot in 0..(UBERBLOCK_RING_BYTES / lbl.slot_bytes) {
                            if leaf.uberblock(&cx, &lbl, slot).is_ok() {
                                candidates += 1;
                            }
                        }
                        labels.push(serde_json::json!({
                            "label": idx,
                            "checksum_valid": true,
                            "pool_name": lbl.config.text("name"),
                            "pool_guid": lbl.config.unsigned("pool_guid").map(|g| g.to_string()),
                            "leaf_guid": lbl.config.unsigned("guid").map(|g| g.to_string()),
                            "version": lbl.config.unsigned("version"),
                            "state": lbl.config.unsigned("state"),
                            "config_txg": lbl.config.unsigned("txg"),
                            "candidate_uberblocks": candidates,
                        }));
                    }
                    Err(FfsError::Cancelled) => return Err(FfsError::Cancelled.into()),
                    Err(err) => labels.push(serde_json::json!({
                        "label": idx,
                        "checksum_valid": false,
                        "error": err.to_string(),
                    })),
                }
            }
            let doc = serde_json::json!({
                "filesystem": "zfs",
                "operation": "pool_inspect",
                "valid_labels": valid,
                "labels": labels,
            });
            if *json {
                println!("{}", serde_json::to_string_pretty(&doc)?);
            } else {
                println!("ZFS Pool Inspect: valid_labels={valid}");
                for l in &labels {
                    println!("  label {}: {l}", l["label"]);
                }
            }
            emit_router_telemetry("pool", "zfs", part_entry.as_ref(), true, before, image);
            Ok(())
        }
        PoolCommand::Status { image, json } => {
            let before = sha256_regular_file(image);
            let (kind, _detected, part_entry, _part_dev) = detect_target_format(&cx, image, six)?;
            if kind != FsFormatKind::Zfs {
                bail!(
                    "ffs pool status requires a ZFS image (detected {})",
                    kind.as_str()
                );
            }
            let (_pool, mut objects) =
                open_zfs_pool_and_objects(&cx, image, part_entry.as_ref(), six)?;
            let datasets = objects.datasets(&cx)?;
            let doc = serde_json::json!({
                "filesystem": "zfs",
                "operation": "pool_status",
                "pool_guid": objects.pool_guid().to_string(),
                "txg": objects.txg,
                "datasets_count": datasets.len(),
                "missing_mirror_members": six.missing_mirror_members,
                "missing_raidz_members": six.missing_raidz_members,
            });
            if *json {
                println!("{}", serde_json::to_string_pretty(&doc)?);
            } else {
                println!(
                    "ZFS Pool Status: pool_guid={} txg={} datasets={}",
                    objects.pool_guid(),
                    objects.txg,
                    datasets.len()
                );
            }
            emit_router_telemetry("pool", "zfs", part_entry.as_ref(), true, before, image);
            Ok(())
        }
    }
}

pub fn dataset_cmd(command: &DatasetCommand, six: &SixFormatCliArgs) -> Result<()> {
    let cx = cli_cx();
    match command {
        DatasetCommand::List { image, json } => {
            let before = sha256_regular_file(image);
            let (kind, _detected, part_entry, _part_dev) = detect_target_format(&cx, image, six)?;
            if kind != FsFormatKind::Zfs {
                bail!(
                    "ffs dataset list requires a ZFS image (detected {})",
                    kind.as_str()
                );
            }
            let (_pool, mut objects) =
                open_zfs_pool_and_objects(&cx, image, part_entry.as_ref(), six)?;
            let rows: Vec<_> = objects
                .datasets(&cx)?
                .into_iter()
                .map(|ds| {
                    let name = ds
                        .components
                        .iter()
                        .map(|c| String::from_utf8_lossy(c))
                        .collect::<Vec<_>>()
                        .join("/");
                    serde_json::json!({
                        "name": name,
                        "directory_object": ds.directory_object,
                        "head_object": ds.head_object,
                        "guid": ds.guid.to_string(),
                        "creation_txg": ds.creation_txg,
                        "objectset_kind": ds.objectset_kind,
                    })
                })
                .collect();
            let doc = serde_json::json!({
                "filesystem": "zfs",
                "pool_guid": objects.pool_guid().to_string(),
                "txg": objects.txg,
                "datasets": rows,
            });
            if *json {
                println!("{}", serde_json::to_string_pretty(&doc)?);
            } else {
                println!(
                    "ZFS Datasets (pool_guid={}, txg={}, count={}):",
                    objects.pool_guid(),
                    objects.txg,
                    doc["datasets"].as_array().map_or(0, Vec::len)
                );
                for ds in doc["datasets"].as_array().into_iter().flatten() {
                    let disp = ds["name"].as_str().unwrap_or("");
                    println!(
                        "  dataset={:?} guid={} creation_txg={}",
                        disp, ds["guid"], ds["creation_txg"]
                    );
                }
            }
            emit_router_telemetry("dataset", "zfs", part_entry.as_ref(), true, before, image);
            Ok(())
        }
        DatasetCommand::Snapshots {
            image,
            dataset,
            json,
        } => {
            let before = sha256_regular_file(image);
            let (kind, _detected, part_entry, _part_dev) = detect_target_format(&cx, image, six)?;
            if kind != FsFormatKind::Zfs {
                bail!(
                    "ffs dataset snapshots requires a ZFS image (detected {})",
                    kind.as_str()
                );
            }
            let (_pool, mut objects) =
                open_zfs_pool_and_objects(&cx, image, part_entry.as_ref(), six)?;
            let comps = parse_zfs_dataset_components(dataset)?;
            let snaps: Vec<_> = objects
                .snapshots(&cx, &comps)?
                .into_iter()
                .map(|s| {
                    serde_json::json!({
                        "name": String::from_utf8_lossy(&s.name),
                        "object": s.object,
                        "guid": s.guid.to_string(),
                        "creation_txg": s.creation_txg,
                        "creation_time": s.creation_time,
                    })
                })
                .collect();
            let doc = serde_json::json!({
                "filesystem": "zfs",
                "pool_guid": objects.pool_guid().to_string(),
                "dataset": dataset,
                "snapshots": snaps,
            });
            if *json {
                println!("{}", serde_json::to_string_pretty(&doc)?);
            } else {
                println!(
                    "ZFS Snapshots for dataset {:?} (count={}):",
                    dataset,
                    doc["snapshots"].as_array().map_or(0, Vec::len)
                );
                for s in doc["snapshots"].as_array().into_iter().flatten() {
                    println!(
                        "  @{} guid={} creation_txg={}",
                        s["name"].as_str().unwrap_or("?"),
                        s["guid"],
                        s["creation_txg"]
                    );
                }
            }
            emit_router_telemetry("dataset", "zfs", part_entry.as_ref(), true, before, image);
            Ok(())
        }
        DatasetCommand::Scrub {
            image,
            dataset,
            snapshot,
            verify_redundancy,
            json,
        } => {
            let before = sha256_regular_file(image);
            let (kind, _detected, part_entry, _part_dev) = detect_target_format(&cx, image, six)?;
            if kind != FsFormatKind::Zfs {
                bail!(
                    "ffs dataset scrub requires a ZFS image (detected {})",
                    kind.as_str()
                );
            }
            let (_pool, mut objects) =
                open_zfs_pool_and_objects(&cx, image, part_entry.as_ref(), six)?;
            let comps = parse_zfs_dataset_components(dataset)?;
            let zpl = match snapshot.as_deref() {
                Some(snap) => objects.zpl_snapshot(&cx, &comps, snap.as_bytes())?,
                None => objects.zpl(&cx, &comps)?,
            };
            let report = zpl.scrub(
                &cx,
                ffs_zfs::reader::dmu::scrub::ScrubLimits {
                    pointers: 16_777_216,
                    decoded_bytes: 1_099_511_627_776,
                    objects: 1_048_576,
                    copy_bytes: verify_redundancy.then_some(1_u64 << 40),
                },
            )?;
            let clean = report.is_clean();
            let doc = serde_json::json!({
                "filesystem": "zfs",
                "pool_guid": report.pool_guid.to_string(),
                "dataset": dataset,
                "snapshot": snapshot,
                "clean": clean,
                "report": report,
            });
            if *json {
                println!("{}", serde_json::to_string_pretty(&doc)?);
            } else {
                println!(
                    "ZFS Dataset Scrub ({:?}): clean={} verified_blocks={} errors={}",
                    dataset, clean, report.verified_blocks, report.errors
                );
            }
            emit_router_telemetry("dataset", "zfs", part_entry.as_ref(), true, before, image);
            if !clean {
                bail!("ZFS dataset scrub detected errors");
            }
            Ok(())
        }
    }
}

// ── Deterministic Pure-Rust Six-Format + GPT Fixture Synthesis ──────────────

fn ntfs_resident_attr(kind: u32, id: u16, name: &str, value: &[u8]) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let start = (24 + units.len() * 2).next_multiple_of(8);
    let length = (start + value.len()).next_multiple_of(8);
    let mut attr = vec![0_u8; length];
    attr[..4].copy_from_slice(&kind.to_le_bytes());
    attr[4..8].copy_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
    attr[9] = u8::try_from(units.len()).unwrap();
    attr[10..12].copy_from_slice(&24_u16.to_le_bytes());
    attr[14..16].copy_from_slice(&id.to_le_bytes());
    attr[16..20].copy_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
    attr[20..22].copy_from_slice(&u16::try_from(start).unwrap().to_le_bytes());
    for (idx, unit) in units.iter().enumerate() {
        attr[24 + idx * 2..26 + idx * 2].copy_from_slice(&unit.to_le_bytes());
    }
    attr[start..start + value.len()].copy_from_slice(value);
    attr
}

fn ntfs_mapped_attr(kind: u32, id: u16, pairs: &[u8], clusters: u64, size: u64) -> Vec<u8> {
    let start = 64_usize;
    let length = (start + pairs.len()).next_multiple_of(8);
    let mut attr = vec![0_u8; length];
    attr[..4].copy_from_slice(&kind.to_le_bytes());
    attr[4..8].copy_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
    attr[8] = 1;
    attr[14..16].copy_from_slice(&id.to_le_bytes());
    attr[24..32].copy_from_slice(&(clusters - 1).to_le_bytes());
    attr[32..34].copy_from_slice(&u16::try_from(start).unwrap().to_le_bytes());
    attr[40..48].copy_from_slice(&(clusters * 512).to_le_bytes());
    attr[48..56].copy_from_slice(&size.to_le_bytes());
    attr[56..64].copy_from_slice(&size.to_le_bytes());
    attr[start..start + pairs.len()].copy_from_slice(pairs);
    attr
}

fn ntfs_record(number: u32, directory: bool, links: u16, attrs: &[Vec<u8>]) -> Vec<u8> {
    const SEQ: u16 = 7;
    let mut raw = vec![0_u8; 1024];
    raw[..4].copy_from_slice(b"FILE");
    raw[4..6].copy_from_slice(&48_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&3_u16.to_le_bytes());
    raw[16..18].copy_from_slice(&SEQ.to_le_bytes());
    raw[18..20].copy_from_slice(&links.to_le_bytes());
    raw[20..22].copy_from_slice(&56_u16.to_le_bytes());
    raw[22..24].copy_from_slice(&(if directory { 3_u16 } else { 1 }).to_le_bytes());
    raw[28..32].copy_from_slice(&1024_u32.to_le_bytes());
    raw[44..48].copy_from_slice(&number.to_le_bytes());
    let mut at = 56_usize;
    for attr in attrs {
        raw[at..at + attr.len()].copy_from_slice(attr);
        at += attr.len();
    }
    raw[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    raw[24..28].copy_from_slice(&u32::try_from(at + 8).unwrap().to_le_bytes());
    raw[48..50].copy_from_slice(&0x1234_u16.to_le_bytes());
    for part in 1..=2 {
        let saved = [raw[part * 512 - 2], raw[part * 512 - 1]];
        raw[48 + part * 2..50 + part * 2].copy_from_slice(&saved);
        raw[part * 512 - 2..part * 512].copy_from_slice(&0x1234_u16.to_le_bytes());
    }
    raw
}

#[must_use]
pub fn build_synthetic_ntfs_image() -> Vec<u8> {
    const SEQ: u16 = 7;
    const UNIX_FILETIME: u64 = 116_444_736_000_000_000;
    let mut image = vec![0_u8; 1024 * 512];

    // Boot sector: 1024 sectors (total_sectors_minus_1 = 1023 -> 1024 clusters of 512B).
    let boot = &mut image[..512];
    boot[3..11].copy_from_slice(b"NTFS    ");
    boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
    boot[13] = 1;
    boot[21] = 0xF8;
    boot[40..48].copy_from_slice(&1023_u64.to_le_bytes());
    boot[48..56].copy_from_slice(&4_u64.to_le_bytes()); // $MFT at LCN 4
    boot[56..64].copy_from_slice(&128_u64.to_le_bytes()); // $MFTMirr at LCN 128
    boot[64] = 0xF6; // 1024-byte MFT records (-10)
    boot[68] = 0xF4; // 4096-byte index blocks (-12)
    boot[72..80].copy_from_slice(&0x4646_5336_2026_1111_u64.to_le_bytes());
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);

    let standard = || {
        let mut info = [0_u8; 72];
        for (idx, t) in [UNIX_FILETIME; 4].iter().enumerate() {
            info[idx * 8..idx * 8 + 8].copy_from_slice(&t.to_le_bytes());
        }
        ntfs_resident_attr(0x10, 0, "", &info)
    };
    let filename = |parent: u64, name: &str, ns: u8| {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut raw = vec![0_u8; 66 + units.len() * 2];
        raw[..8].copy_from_slice(&((u64::from(SEQ) << 48) | parent).to_le_bytes());
        raw[64] = u8::try_from(units.len()).unwrap();
        raw[65] = ns;
        for (i, u) in units.iter().enumerate() {
            raw[66 + i * 2..68 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        raw
    };
    let index_root = |children: &[(u32, &str, u8)], parent: u64| {
        let mut root = vec![0_u8; 32];
        root[..4].copy_from_slice(&0x30_u32.to_le_bytes());
        root[4..8].copy_from_slice(&1_u32.to_le_bytes());
        root[8..12].copy_from_slice(&4096_u32.to_le_bytes());
        root[12] = 8;
        root[16..20].copy_from_slice(&16_u32.to_le_bytes());
        for &(rec, name, ns) in children {
            let val = filename(parent, name, ns);
            let len = (16 + val.len()).next_multiple_of(8);
            let mut entry = vec![0_u8; len];
            entry[..8].copy_from_slice(&((u64::from(SEQ) << 48) | u64::from(rec)).to_le_bytes());
            entry[8..10].copy_from_slice(&u16::try_from(len).unwrap().to_le_bytes());
            entry[10..12].copy_from_slice(&u16::try_from(val.len()).unwrap().to_le_bytes());
            entry[16..16 + val.len()].copy_from_slice(&val);
            root.extend(entry);
        }
        let mut last = [0_u8; 16];
        last[8] = 16;
        last[12] = 2;
        root.extend(last);
        let used = u32::try_from(root.len() - 16).unwrap();
        root[20..24].copy_from_slice(&used.to_le_bytes());
        root[24..28].copy_from_slice(&used.to_le_bytes());
        ntfs_resident_attr(0x90, 2, "$I30", &root)
    };
    let put_rec = |img: &mut [u8], num: u32, raw: &[u8]| {
        let at = 4 * 512 + (num as usize) * 1024;
        img[at..at + 1024].copy_from_slice(raw);
    };

    // Allocated MFT slots: 0 ($MFT), 1 ($MFTMirr), 2 ($LogFile), 3 ($Volume),
    // 5 (root "."), 6 ($Bitmap), 10 ($UpCase), 24 (hello.txt).
    // 40 logical records in $MFT (80 clusters * 512B / 1024B = 40 records -> 5 bitmap bytes).
    let mut mft_bitmap = [0_u8; 5];
    for slot in [0_usize, 1, 2, 3, 5, 6, 10, 24] {
        mft_bitmap[slot / 8] |= 1_u8 << (slot % 8);
    }
    let mft_rec = ntfs_record(
        0,
        false,
        0,
        &[
            standard(),
            ntfs_mapped_attr(DATA, 1, &[0x11, 80, 4, 0], 80, 40_960),
            ntfs_resident_attr(0xB0, 2, "", &mft_bitmap),
        ],
    );
    let mft_mirr_rec = ntfs_record(
        1,
        false,
        0,
        &[
            standard(),
            // 8 clusters at LCN 128 = 4096 bytes = mirror of records 0..4!
            ntfs_mapped_attr(DATA, 1, &[0x21, 8, 128, 0, 0], 8, 4096),
        ],
    );
    let logfile_rec = ntfs_record(
        2,
        false,
        0,
        &[
            standard(),
            ntfs_mapped_attr(DATA, 1, &[0x21, 64, 192, 0, 0], 64, 32_768),
        ],
    );
    let mut vol_info = [0_u8; 12];
    vol_info[8..10].copy_from_slice(&[3, 1]);
    let volume_rec = ntfs_record(
        3,
        false,
        0,
        &[standard(), ntfs_resident_attr(0x70, 1, "", &vol_info)],
    );

    // Root directory (record 5) carries its self-referencing "." FILE_NAME (links=1)
    // and indexes user entry "hello.txt" (record 24); system records 0, 1, 2, 3, 6, 10
    // have links=0 and no FILE_NAME attribute.
    let root_children = [(24_u32, "hello.txt", 1_u8)];
    let root_dir_rec = ntfs_record(
        5,
        true,
        1,
        &[
            standard(),
            ntfs_resident_attr(0x30, 1, "", &filename(5, ".", 3)),
            index_root(&root_children, 5),
        ],
    );

    // Volume $Bitmap: 1023 clusters -> 128 bytes.
    // Claimed cluster ranges:
    // - $MFT: 4..84 (80 clusters)
    // - $MFTMirr: 128..136 (8 clusters)
    // - $LogFile: 192..256 (64 clusters)
    // - $UpCase: 300..556 (256 clusters)
    let mut vol_bitmap = [0_u8; 128];
    for c in (4..84).chain(128..136).chain(192..256).chain(300..556) {
        vol_bitmap[c / 8] |= 1_u8 << (c % 8);
    }
    let bitmap_rec = ntfs_record(
        6,
        false,
        0,
        &[standard(), ntfs_resident_attr(DATA, 1, "", &vol_bitmap)],
    );
    let upcase_rec = ntfs_record(
        10,
        false,
        0,
        &[
            standard(),
            ntfs_mapped_attr(DATA, 1, &[0x22, 0, 1, 44, 1, 0], 256, 131_072),
        ],
    );
    // Record 24: /hello.txt with unnamed DATA + named ADS "note"!
    // Attributes in ascending (type, name) order: 0x10, 0x30, 0x80 (""), 0x80 ("note").
    let hello_file_rec = ntfs_record(
        24,
        false,
        1,
        &[
            standard(),
            ntfs_resident_attr(0x30, 1, "", &filename(5, "hello.txt", 1)),
            ntfs_resident_attr(DATA, 2, "", b"hello from ntfs\n"),
            ntfs_resident_attr(DATA, 3, "note", b"secret alternate stream\n"),
        ],
    );

    put_rec(&mut image, 0, &mft_rec);
    put_rec(&mut image, 1, &mft_mirr_rec);
    put_rec(&mut image, 2, &logfile_rec);
    put_rec(&mut image, 3, &volume_rec);
    put_rec(&mut image, 5, &root_dir_rec);
    put_rec(&mut image, 6, &bitmap_rec);
    put_rec(&mut image, 10, &upcase_rec);
    put_rec(&mut image, 24, &hello_file_rec);

    // Copy records 0..4 (4096 bytes) to $MFTMirr at LCN 128!
    let mft_head = image[4 * 512..4 * 512 + 4096].to_vec();
    image[128 * 512..128 * 512 + 4096].copy_from_slice(&mft_head);

    // Fill $LogFile (LCN 192..256) with 0xFF (clean erased state).
    image[192 * 512..256 * 512].fill(0xFF);

    // Populate $UpCase table at LCN 300..556 (65536 u16 entries = 131072 bytes).
    for unit in 0..=u16::MAX {
        let upper = if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) {
            unit - 32
        } else {
            unit
        };
        let at = 300 * 512 + usize::from(unit) * 2;
        image[at..at + 2].copy_from_slice(&upper.to_le_bytes());
    }

    let _ = NtfsValue::Resident(&[]); // keep import used
    image
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn build_synthetic_zfs_image() -> Vec<u8> {
    const LENGTH: usize = 8 * 1024 * 1024;
    const POOL_GUID: u64 = 424_242;
    const LEAF_GUID: u64 = 1_001;
    let order = Endian::Little;
    let mut image = vec![0_u8; LENGTH];

    let xstring = |val: &str| -> Vec<u8> {
        let mut b = u32::try_from(val.len()).unwrap().to_be_bytes().to_vec();
        b.extend_from_slice(val.as_bytes());
        b.resize(b.len().next_multiple_of(4), 0);
        b
    };
    let nv_pair = |name: &str, kind: u32, data: &[u8]| -> Vec<u8> {
        let mut b = vec![0_u8; 8];
        b.extend_from_slice(&xstring(name));
        b.extend_from_slice(&kind.to_be_bytes());
        b.extend_from_slice(&1_u32.to_be_bytes());
        b.extend_from_slice(data);
        let len = u32::try_from(b.len()).unwrap();
        b[..4].copy_from_slice(&len.to_be_bytes());
        b[4..8].copy_from_slice(&64_u32.to_be_bytes());
        b
    };
    let nv_uint = |name: &str, val: u64| nv_pair(name, 8, &val.to_be_bytes());
    let nv_list = |pairs: &[Vec<u8>]| -> Vec<u8> {
        let mut b = vec![0, 0, 0, 0, 0, 0, 0, 1];
        for p in pairs {
            b.extend_from_slice(p);
        }
        b.extend_from_slice(&[0; 8]);
        b
    };
    let stamp = |block: &mut [u8], offset: u64| {
        let at = block.len() - 40;
        block[at..at + 8].copy_from_slice(&order.encode(0x0210_da7a_b10c_7a11));
        block[at + 8..].fill(0);
        block[at + 8..at + 16].copy_from_slice(&order.encode(offset));
        let digest = Sha256::digest(&*block);
        for i in 0..4 {
            let word = u64::from_be_bytes(std::array::from_fn(|n| digest[i * 8 + n]));
            block[at + 8 + i * 8..at + 16 + i * 8].copy_from_slice(&order.encode(word));
        }
    };
    let bp = |raw: &[u8], at: u64, kind: u8, level: u8, birth: u64| -> Vec<u8> {
        let sectors = u64::try_from(raw.len() / 512).unwrap();
        let mut words = [0_u64; 16];
        words[0] = sectors;
        words[1] = (at - DATA_OFFSET) / 512;
        words[6] = (sectors - 1)
            | ((sectors - 1) << 16)
            | (2 << 32)
            | (7 << 40)
            | (u64::from(kind) << 48)
            | (u64::from(level) << 56)
            | (1_u64 << 63);
        words[10] = birth;
        words[12..].copy_from_slice(&zfs_checksum(raw, 7, order).unwrap());
        words.into_iter().flat_map(|w| order.encode(w)).collect()
    };
    let dnode = |kind: u8,
                 block: usize,
                 levels: u8,
                 max_blk: u64,
                 bonus: &[u8],
                 bonus_type: u8|
     -> Vec<u8> {
        let mut raw = vec![0_u8; 512];
        raw[0] = kind;
        raw[1] = 12;
        raw[2] = levels;
        raw[3] = 1;
        raw[4] = bonus_type;
        raw[7] = 1;
        raw[8..10].copy_from_slice(&u16::try_from(block / 512).unwrap().to_le_bytes());
        raw[10..12].copy_from_slice(&u16::try_from(bonus.len()).unwrap().to_le_bytes());
        raw[16..24].copy_from_slice(&order.encode(max_blk));
        raw[192..192 + bonus.len()].copy_from_slice(bonus);
        raw
    };
    let micro_zap = |entries: &[(&[u8], u64)]| -> Vec<u8> {
        let mut raw = vec![0_u8; 512];
        raw[..8].copy_from_slice(&order.encode((1_u64 << 63) + 3));
        for (i, (name, val)) in entries.iter().enumerate() {
            let at = 64 + i * 64;
            raw[at..at + 8].copy_from_slice(&order.encode(*val));
            raw[at + 14..at + 14 + name.len()].copy_from_slice(name);
        }
        raw
    };
    let legacy_znode = |mode: u64, size: u64, parent: u64| -> Vec<u8> {
        let mut raw = vec![0_u8; 264];
        for (at, val) in [
            (0_usize, 1_700_000_000_u64),
            (8, 0),
            (64, 10),
            (72, mode),
            (80, size),
            (88, parent),
            (96, 1),
            (128, 0),
            (136, 0),
        ] {
            raw[at..at + 8].copy_from_slice(&order.encode(val));
        }
        raw
    };

    let store = |img: &mut [u8], at: u64, data: &[u8]| {
        let start = usize::try_from(at).unwrap();
        img[start..start + data.len()].copy_from_slice(data);
    };

    // Build ZPL object set (OS_AT): master node (obj 1), root dir (obj 2), hello.txt (obj 3).
    let master_zap = micro_zap(&[(b"ROOT", 2), (b"VERSION", 4)]);
    let root_dir_zap = micro_zap(&[(b"hello.txt", (8_u64 << 60) | 3)]);
    let mut file_block = vec![0_u8; 512];
    let payload = b"hello from zfs\n";
    file_block[..payload.len()].copy_from_slice(payload);

    let master_at = DATA_OFFSET + 0x25_000;
    let root_dir_at = DATA_OFFSET + 0x26_000;
    let file_data_at = DATA_OFFSET + 0x28_000;
    let zpl_table_at = DATA_OFFSET + 0x20_000;
    let os_at = DATA_OFFSET + 0x18_000;

    store(&mut image, master_at, &master_zap);
    store(&mut image, root_dir_at, &root_dir_zap);
    store(&mut image, file_data_at, &file_block);

    let mut zpl_table = vec![0_u8; 16_384];
    let mut obj1 = dnode(21, 512, 1, 0, &[], 0);
    obj1[64..192].copy_from_slice(&bp(&master_zap, master_at, 21, 0, 20));
    zpl_table[512..1024].copy_from_slice(&obj1);

    let mut obj2 = dnode(20, 512, 1, 0, &legacy_znode(0o040_755, 3, 2), 17);
    obj2[64..192].copy_from_slice(&bp(&root_dir_zap, root_dir_at, 20, 0, 20));
    zpl_table[1024..1536].copy_from_slice(&obj2);

    let mut obj3 = dnode(
        19,
        512,
        1,
        0,
        &legacy_znode(0o100_644, payload.len() as u64, 2),
        17,
    );
    obj3[24..32].copy_from_slice(&order.encode(512));
    obj3[64..192].copy_from_slice(&bp(&file_block, file_data_at, 19, 0, 20));
    zpl_table[1536..2048].copy_from_slice(&obj3);
    store(&mut image, zpl_table_at, &zpl_table);

    let mut os = vec![0_u8; 1024];
    let mut os_meta = dnode(10, 16_384, 1, 0, &[], 0);
    os_meta[64..192].copy_from_slice(&bp(&zpl_table, zpl_table_at, 10, 0, 30));
    os[..512].copy_from_slice(&os_meta);
    os[704..712].copy_from_slice(&order.encode(2)); // DMU_OST_ZFS = 2
    store(&mut image, os_at, &os);

    // Build MOS table:
    // obj 1: pool dir ("root_dataset" -> 2)
    // obj 2: root DSL dir (head=3, parent=0, children=6)
    // obj 3: root head DSL dataset (dir=2, prev=5, prev_txg=35, names=4, creation_txg=45, guid=987001)
    // obj 4: root snapnames ZAP ("snap1" -> 5)
    // obj 5: snapshot DSL dataset (dir=2, next=3, children=1, creation_txg=35, guid=987000)
    // obj 6: child dir map ZAP ("app" -> 7)
    // obj 7: child DSL dir (head=8, parent=2, children=0)
    // obj 8: child head DSL dataset (dir=7, names=9, creation_txg=46, guid=987002)
    // obj 9: empty snapnames ZAP for child
    let pool_dir_zap = micro_zap(&[(b"root_dataset", 2)]);
    let snapnames_zap = micro_zap(&[(b"snap1", 5)]);
    let child_map_zap = micro_zap(&[(b"app", 7)]);
    let empty_zap = micro_zap(&[]);

    let pool_dir_at = DATA_OFFSET + 0x14_000;
    let snapnames_at = DATA_OFFSET + 0x15_000;
    let child_map_at = DATA_OFFSET + 0x16_000;
    let empty_zap_at = DATA_OFFSET + 0x17_000;
    let mos_table_at = DATA_OFFSET + 0x10_000;
    let mos_os_at = DATA_OFFSET + 0x0C_000;

    store(&mut image, pool_dir_at, &pool_dir_zap);
    store(&mut image, snapnames_at, &snapnames_zap);
    store(&mut image, child_map_at, &child_map_zap);
    store(&mut image, empty_zap_at, &empty_zap);

    let mut mos_table = vec![0_u8; 16_384];
    let mut mos_obj1 = dnode(1, 512, 1, 0, &[], 0);
    mos_obj1[64..192].copy_from_slice(&bp(&pool_dir_zap, pool_dir_at, 1, 0, 20));
    mos_table[512..1024].copy_from_slice(&mos_obj1);

    let mut root_dsl_dir = vec![0_u8; 256];
    root_dsl_dir[8..16].copy_from_slice(&order.encode(3)); // head = 3
    root_dsl_dir[32..40].copy_from_slice(&order.encode(6)); // children = 6
    mos_table[1024..1536].copy_from_slice(&dnode(12, 512, 1, 0, &root_dsl_dir, 12));

    let os_bp = bp(&os, os_at, 11, 0, 30);
    let mut root_ds = vec![0_u8; 320];
    for (at, val) in [
        (0_usize, 2_u64), // dir = 2
        (8, 5),           // prev = 5 (snap1)
        (16, 35),         // prev_txg = 35
        (32, 4),          // snapnames = 4
        (48, 1_700_000_010),
        (56, 45), // creation_txg = 45
        (112, 987_001),
    ] {
        root_ds[at..at + 8].copy_from_slice(&order.encode(val));
    }
    root_ds[128..256].copy_from_slice(&os_bp);
    mos_table[1536..2048].copy_from_slice(&dnode(16, 512, 1, 0, &root_ds, 16));

    let mut mos_obj4 = dnode(196, 512, 1, 0, &[], 0);
    mos_obj4[64..192].copy_from_slice(&bp(&snapnames_zap, snapnames_at, 196, 0, 35));
    mos_table[2048..2560].copy_from_slice(&mos_obj4);

    let mut snap_ds = vec![0_u8; 320];
    for (at, val) in [
        (0_usize, 2_u64), // dir = 2
        (24, 3),          // next = 3
        (40, 1),          // numclones + 1 = 1
        (48, 1_700_000_000),
        (56, 35), // creation_txg = 35
        (112, 987_000),
    ] {
        snap_ds[at..at + 8].copy_from_slice(&order.encode(val));
    }
    snap_ds[128..256].copy_from_slice(&os_bp);
    mos_table[2560..3072].copy_from_slice(&dnode(16, 512, 1, 0, &snap_ds, 16));

    let mut mos_obj6 = dnode(13, 512, 1, 0, &[], 0);
    mos_obj6[64..192].copy_from_slice(&bp(&child_map_zap, child_map_at, 13, 0, 40));
    mos_table[3072..3584].copy_from_slice(&mos_obj6);

    let mut app_dsl_dir = vec![0_u8; 256];
    app_dsl_dir[8..16].copy_from_slice(&order.encode(8)); // head = 8
    app_dsl_dir[16..24].copy_from_slice(&order.encode(2)); // parent = 2
    mos_table[3584..4096].copy_from_slice(&dnode(12, 512, 1, 0, &app_dsl_dir, 12));

    let mut app_ds = vec![0_u8; 320];
    for (at, val) in [
        (0_usize, 7_u64), // dir = 7
        (32, 9),          // snapnames = 9
        (48, 1_700_000_020),
        (56, 46),
        (112, 987_002),
    ] {
        app_ds[at..at + 8].copy_from_slice(&order.encode(val));
    }
    app_ds[128..256].copy_from_slice(&os_bp);
    mos_table[4096..4608].copy_from_slice(&dnode(16, 512, 1, 0, &app_ds, 16));

    let mut mos_obj9 = dnode(196, 512, 1, 0, &[], 0);
    mos_obj9[64..192].copy_from_slice(&bp(&empty_zap, empty_zap_at, 196, 0, 46));
    mos_table[4608..5120].copy_from_slice(&mos_obj9);

    store(&mut image, mos_table_at, &mos_table);

    let mut mos_os = vec![0_u8; 1024];
    let mut mos_meta = dnode(10, 16_384, 1, 0, &[], 0);
    mos_meta[64..192].copy_from_slice(&bp(&mos_table, mos_table_at, 10, 0, 55));
    mos_os[..512].copy_from_slice(&mos_meta);
    mos_os[704..712].copy_from_slice(&order.encode(1)); // DMU_OST_META = 1
    store(&mut image, mos_os_at, &mos_os);

    // Label nvlist config (version = 28 -> historical SPA version without feature-ZAP mandate) + uberblock.
    let vdev_tree = nv_list(&[
        nv_pair("type", 9, &xstring("file")),
        nv_uint("id", 0),
        nv_uint("guid", LEAF_GUID),
        nv_uint("ashift", 9),
        nv_uint("asize", LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES),
        nv_uint("is_log", 0),
    ]);
    let mut cfg = vec![1, 1, 0, 0];
    cfg.extend_from_slice(&nv_list(&[
        nv_uint("version", 28),
        nv_uint("state", 1), // POOL_STATE_EXPORTED
        nv_uint("txg", 60),
        nv_uint("pool_guid", POOL_GUID),
        nv_uint("guid", LEAF_GUID),
        nv_uint("top_guid", LEAF_GUID),
        nv_uint("vdev_children", 1),
        nv_pair("name", 9, &xstring("tank")),
        nv_pair("vdev_tree", 19, &vdev_tree),
    ]));

    let mos_bp = bp(&mos_os, mos_os_at, 11, 0, 60);
    let mut ub = vec![0_u8; 1024];
    for (at, val) in [
        (0_usize, 0x00ba_b10c_u64),
        (8, 28),
        (16, 60),
        (24, POOL_GUID + LEAF_GUID),
        (32, 1_700_000_100),
    ] {
        ub[at..at + 8].copy_from_slice(&order.encode(val));
    }
    ub[40..168].copy_from_slice(&mos_bp);

    for lbl_off in label_offsets(LENGTH as u64).unwrap() {
        let cfg_off = lbl_off + LABEL_CONFIG_OFFSET;
        let mut cfg_blk = vec![0_u8; LABEL_CONFIG_BYTES];
        cfg_blk[..cfg.len()].copy_from_slice(&cfg);
        stamp(&mut cfg_blk, cfg_off);
        store(&mut image, cfg_off, &cfg_blk);

        let ub_off = lbl_off + UBERBLOCK_RING_OFFSET;
        let mut ub_blk = ub.clone();
        stamp(&mut ub_blk, ub_off);
        store(&mut image, ub_off, &ub_blk);
    }

    image
}

fn write_hello_via_openfs(cx: &Cx, image_path: &Path, payload: &[u8]) -> Result<()> {
    let mut fs = OpenFs::open_read_write(cx, image_path, &OpenOptions::default())?;
    fs.enable_writes(cx)?;
    let mut create_scope = FsOps::begin_request_scope(&fs, cx, RequestOp::Create)?;
    let created = FsOps::create(
        &fs,
        cx,
        &mut create_scope,
        InodeNumber(1),
        OsStr::new("hello.txt"),
        0o644,
        0,
        0,
    )?;
    FsOps::commit_request_scope(&fs, cx, &mut create_scope)?;
    FsOps::end_request_scope(&fs, cx, RequestOp::Create, create_scope)?;
    let mut write_scope = FsOps::begin_request_scope(&fs, cx, RequestOp::Write)?;
    let written = FsOps::write(&fs, cx, &mut write_scope, created.ino, 0, payload)?;
    if usize::try_from(written).unwrap_or(0) != payload.len() {
        bail!("short OpenFs fixture write: {written} != {}", payload.len());
    }
    FsOps::commit_request_scope(&fs, cx, &mut write_scope)?;
    FsOps::end_request_scope(&fs, cx, RequestOp::Write, write_scope)?;
    fs.sync_all_to_device(cx)?;
    Ok(())
}

pub fn synthesize_six_format_fixtures_cmd(output_dir: &Path, json: bool) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("create fixture directory {}", output_dir.display()))?;
    let cx = cli_cx();

    // 1. FAT16 (8 MiB) + /hello.txt
    let fat16_path = output_dir.join("fat16.img");
    if !fat16_path.exists() {
        format_cmd(
            &fat16_path,
            "fat16",
            8,
            Some("FAT16VOL"),
            None,
            None,
            false,
            true,
        )?;
        let args = ffs_fat::ImageArgs {
            image: fat16_path.clone(),
            offset: 0,
            length: None,
            oem_code_page: FatOemCodePage::Ascii,
            sidecar: None,
        };
        let vol = ffs_fat::reader::replacement::open_volume(&cx, &args, true)?;
        ffs_fat::reader::replacement::create_in_volume(
            &cx,
            &vol,
            "/hello.txt",
            b"hello from fat16\n",
            1_700_000_000,
            false,
        )?;
    }

    // 2. FAT32 (64 MiB) + /hello.txt
    let fat32_path = output_dir.join("fat32.img");
    if !fat32_path.exists() {
        format_cmd(
            &fat32_path,
            "fat32",
            64,
            Some("FAT32VOL"),
            None,
            None,
            false,
            true,
        )?;
        let args = ffs_fat::ImageArgs {
            image: fat32_path.clone(),
            offset: 0,
            length: None,
            oem_code_page: FatOemCodePage::Ascii,
            sidecar: None,
        };
        let vol = ffs_fat::reader::replacement::open_volume(&cx, &args, true)?;
        ffs_fat::reader::replacement::create_in_volume(
            &cx,
            &vol,
            "/hello.txt",
            b"hello from fat32\n",
            1_700_000_000,
            false,
        )?;
    }

    // 3. NTFS (512 KiB) with /hello.txt + ADS "note"
    let ntfs_path = output_dir.join("ntfs.img");
    if !ntfs_path.exists() {
        fs::write(&ntfs_path, build_synthetic_ntfs_image())?;
    }

    // 4. ZFS (8 MiB) pool "tank" (GUID 424242) with root + "app" dataset + "@snap1" + /hello.txt
    let zfs_path = output_dir.join("zfs.img");
    if !zfs_path.exists() {
        fs::write(&zfs_path, build_synthetic_zfs_image())?;
    }

    // 5. Ext4 (16 MiB) + /hello.txt
    let ext4_path = output_dir.join("ext4.img");
    if !ext4_path.exists() {
        format_cmd(
            &ext4_path,
            "ext4",
            16,
            Some("ext4vol"),
            Some(4096),
            None,
            true,
            true,
        )?;
        write_hello_via_openfs(&cx, &ext4_path, b"hello from ext4\n")?;
    }

    // 6. Btrfs (128 MiB) + /hello.txt
    let btrfs_path = output_dir.join("btrfs.img");
    if !btrfs_path.exists() {
        format_cmd(
            &btrfs_path,
            "btrfs",
            128,
            Some("btrfsvol"),
            None,
            None,
            true,
            true,
        )?;
        write_hello_via_openfs(&cx, &btrfs_path, b"hello from btrfs\n")?;
    }

    // 7. GPT whole-disk image packing FAT16 (p1), Ext4 (p2), NTFS (p3), ZFS (p4)!
    let gpt_path = output_dir.join("gpt_multi.img");
    if !gpt_path.exists() {
        let p1_bytes = fs::read(&fat16_path)?;
        let p2_bytes = fs::read(&ext4_path)?;
        let p3_bytes = fs::read(&ntfs_path)?;
        let p4_bytes = fs::read(&zfs_path)?;

        let p1_lba_start = 64_u64;
        let p1_lbas = u64::try_from(p1_bytes.len() / 512).unwrap();
        let p2_lba_start = p1_lba_start + p1_lbas + 8;
        let p2_lbas = u64::try_from(p2_bytes.len() / 512).unwrap();
        let p3_lba_start = p2_lba_start + p2_lbas + 8;
        let p3_lbas = u64::try_from(p3_bytes.len() / 512).unwrap();
        let p4_lba_start = p3_lba_start + p3_lbas + 8;
        let p4_lbas = u64::try_from(p4_bytes.len() / 512).unwrap();
        let total_lbas = p4_lba_start + p4_lbas + 64;

        let mut disk = vec![0_u8; usize::try_from(total_lbas * 512).unwrap()];
        let disk_guid = PartUuid::from_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let basic_type = PartUuid::from_str("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7").unwrap();
        let linux_type = PartUuid::from_str("0fc63daf-8483-4772-8e79-3d69d8477de4").unwrap();
        let specs = [
            SyntheticGptPartitionSpec {
                type_guid: basic_type,
                part_uuid: PartUuid::from_str("11111111-2222-3333-4444-555555555501").unwrap(),
                start_lba: p1_lba_start,
                end_lba_inclusive: p1_lba_start + p1_lbas - 1,
                attributes: 0,
                label: "EFI-FAT16".to_owned(),
            },
            SyntheticGptPartitionSpec {
                type_guid: linux_type,
                part_uuid: PartUuid::from_str("11111111-2222-3333-4444-555555555502").unwrap(),
                start_lba: p2_lba_start,
                end_lba_inclusive: p2_lba_start + p2_lbas - 1,
                attributes: 0,
                label: "LINUX-EXT4".to_owned(),
            },
            SyntheticGptPartitionSpec {
                type_guid: basic_type,
                part_uuid: PartUuid::from_str("11111111-2222-3333-4444-555555555503").unwrap(),
                start_lba: p3_lba_start,
                end_lba_inclusive: p3_lba_start + p3_lbas - 1,
                attributes: 0,
                label: "WIN-NTFS".to_owned(),
            },
            SyntheticGptPartitionSpec {
                type_guid: linux_type,
                part_uuid: PartUuid::from_str("11111111-2222-3333-4444-555555555504").unwrap(),
                start_lba: p4_lba_start,
                end_lba_inclusive: p4_lba_start + p4_lbas - 1,
                attributes: 0,
                label: "SOLARIS-ZFS".to_owned(),
            },
        ];
        write_gpt_partition_table(&mut disk, disk_guid, &specs)
            .map_err(|err| anyhow::anyhow!("write GPT table: {err}"))?;
        for (start_lba, payload) in [
            (p1_lba_start, &p1_bytes),
            (p2_lba_start, &p2_bytes),
            (p3_lba_start, &p3_bytes),
            (p4_lba_start, &p4_bytes),
        ] {
            let off = usize::try_from(start_lba * 512).unwrap();
            disk[off..off + payload.len()].copy_from_slice(payload);
        }
        fs::write(&gpt_path, disk)?;
    }

    let manifest = serde_json::json!({
        "ext4": ext4_path.display().to_string(),
        "btrfs": btrfs_path.display().to_string(),
        "fat16": fat16_path.display().to_string(),
        "fat32": fat32_path.display().to_string(),
        "ntfs": ntfs_path.display().to_string(),
        "zfs": zfs_path.display().to_string(),
        "gpt_multi": gpt_path.display().to_string(),
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&manifest)?);
    } else {
        println!(
            "Synthesized six-format + GPT fixtures in {}",
            output_dir.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_ntfs_and_zfs_fixtures_pass_full_consistency_and_ads_dataset_workflows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ntfs_path = dir.path().join("ntfs.img");
        let zfs_path = dir.path().join("zfs.img");
        fs::write(&ntfs_path, build_synthetic_ntfs_image()).expect("write ntfs");
        fs::write(&zfs_path, build_synthetic_zfs_image()).expect("write zfs");

        let ntfs_before = sha256_regular_file(&ntfs_path).expect("hash ntfs");
        let zfs_before = sha256_regular_file(&zfs_path).expect("hash zfs");

        // Admission: NTFS and ZFS must fail closed without --offline-image.
        let missing_offline = SixFormatCliArgs::default();
        assert!(
            missing_offline
                .validate_format_compatibility(FsFormatKind::Ntfs)
                .is_err()
        );
        assert!(
            missing_offline
                .validate_format_compatibility(FsFormatKind::Zfs)
                .is_err()
        );

        let offline = SixFormatCliArgs {
            offline_image: true,
            ..SixFormatCliArgs::default()
        };

        // NTFS fsck, streams, ls, read, walk:
        assert!(
            maybe_route_fsck_cmd(
                &ntfs_path,
                FsckCommandOptions {
                    flags: crate::FsckFlags::empty().with_json(true),
                    block_group: None,
                },
                &offline,
            )
            .expect("ntfs fsck")
        );
        streams_cmd(&ntfs_path, "/hello.txt", None, false, true, &offline).expect("ntfs streams");
        ls_cmd(&ntfs_path, "/", true, &offline).expect("ntfs ls");
        assert!(maybe_route_read_cmd(&ntfs_path, "/hello.txt", true, false, &offline).unwrap());
        assert!(maybe_route_walk_cmd(&ntfs_path, false, true, &offline).unwrap());

        // ZFS pool, dataset list/snapshots/scrub, fsck, read, walk:
        pool_cmd(
            &PoolCommand::Inspect {
                image: zfs_path.clone(),
                json: true,
            },
            &offline,
        )
        .expect("zfs pool inspect");
        pool_cmd(
            &PoolCommand::Status {
                image: zfs_path.clone(),
                json: true,
            },
            &offline,
        )
        .expect("zfs pool status");
        dataset_cmd(
            &DatasetCommand::List {
                image: zfs_path.clone(),
                json: true,
            },
            &offline,
        )
        .expect("zfs dataset list");
        dataset_cmd(
            &DatasetCommand::Snapshots {
                image: zfs_path.clone(),
                dataset: String::new(),
                json: true,
            },
            &offline,
        )
        .expect("zfs dataset snapshots");
        dataset_cmd(
            &DatasetCommand::Scrub {
                image: zfs_path.clone(),
                dataset: String::new(),
                snapshot: None,
                verify_redundancy: false,
                json: true,
            },
            &offline,
        )
        .expect("zfs dataset scrub");
        assert!(maybe_route_read_cmd(&zfs_path, "/hello.txt", true, false, &offline).unwrap());
        assert!(maybe_route_walk_cmd(&zfs_path, false, true, &offline).unwrap());

        assert_eq!(sha256_regular_file(&ntfs_path), Some(ntfs_before));
        assert_eq!(sha256_regular_file(&zfs_path), Some(zfs_before));
    }

    #[test]
    fn format_cmd_formats_native_fat_and_requires_explicit_delegation_for_ext4() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fat16 = dir.path().join("native_fat16.img");
        format_cmd(&fat16, "fat16", 8, Some("TEST16"), None, None, false, true)
            .expect("native fat16 format");

        let ext4 = dir.path().join("refused_ext4.img");
        let err = format_cmd(
            &ext4,
            "ext4",
            16,
            Some("ext4"),
            Some(4096),
            None,
            false,
            true,
        )
        .expect_err("ext4 format without --delegate-host-mkfs must fail closed");
        assert!(err.to_string().contains("--delegate-host-mkfs"));
        assert!(!ext4.exists());
    }
}
