//! CLI `inspect` subcommand execution and formatting.
//!
//! Clap schema and serialized output types remain in the crate root; this
//! module owns only the independently dispatched inspect implementation.

use anyhow::{Context, Result};
use asupersync::Cx;
use ffs_core::{Ext4JournalReplayMode, FsFlavor, OpenFs, OpenOptions, detect_filesystem_at_path};
use ffs_ondisk::Ext4Superblock;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{info, info_span};

use crate::{
    Ext4OrphanDiagnosticsOutput, FreeSpaceMismatch, InspectOutput, cli_cx,
    ext4_quota_inodes_for_output, format_ext4_quota_inodes,
};

pub fn inspect(
    path: &PathBuf,
    json: bool,
    list_subvolumes: bool,
    list_snapshots: bool,
) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::inspect",
        "inspect",
        image = %path.display(),
        output_json = json
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::inspect", "inspect_start");

    let cx = cli_cx();
    let open_opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;

    // Handle --subvolumes and --snapshots for btrfs
    if (list_subvolumes || list_snapshots) && matches!(&flavor, FsFlavor::Btrfs(_)) {
        return inspect_btrfs_subvolumes(&cx, path, &flavor, json, list_subvolumes, list_snapshots);
    }
    if (list_subvolumes || list_snapshots) && matches!(&flavor, FsFlavor::Ext4(_)) {
        anyhow::bail!("--subvolumes and --snapshots are only supported for btrfs images");
    }

    let output = match &flavor {
        FsFlavor::Ext4(sb) => inspect_ext4_output(&cx, path, &open_opts, sb)?,
        FsFlavor::Btrfs(sb) => InspectOutput::Btrfs {
            sectorsize: sb.sectorsize,
            nodesize: sb.nodesize,
            generation: sb.generation,
            label: sb.label.clone(),
        },
    };

    info!(
        target: "ffs::cli::inspect",
        filesystem = match &flavor {
            FsFlavor::Ext4(_) => "ext4",
            FsFlavor::Btrfs(_) => "btrfs",
        },
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "inspect_detected_filesystem"
    );

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize output")?
        );
    } else {
        print_inspect_output(&output);
    }

    info!(
        target: "ffs::cli::inspect",
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "inspect_complete"
    );

    Ok(())
}

fn print_inspect_output(output: &InspectOutput) {
    println!("FrankenFS Inspector");
    match output {
        InspectOutput::Ext4 {
            block_size,
            inodes_count,
            blocks_count,
            volume_name,
            free_blocks_total,
            free_inodes_total,
            quota_inodes,
            free_space_mismatch,
            orphan_diagnostics,
        } => {
            println!("filesystem: ext4");
            println!("block_size: {block_size}");
            println!("inodes_count: {inodes_count}");
            println!("blocks_count: {blocks_count}");
            println!("volume_name: {volume_name}");
            println!("free_blocks: {free_blocks_total}");
            println!("free_inodes: {free_inodes_total}");
            if let Some(quota_inodes) = quota_inodes {
                println!("quota_inodes: {}", format_ext4_quota_inodes(quota_inodes));
            }
            if let Some(mismatch) = free_space_mismatch {
                println!(
                    "WARNING: mismatch with group descriptors (gd_free_blocks={}, gd_free_inodes={})",
                    mismatch.gd_free_blocks, mismatch.gd_free_inodes
                );
            }
            if let Some(orphan_diag) = orphan_diagnostics {
                println!(
                    "orphans: count={} sample_inodes={:?}",
                    orphan_diag.count, orphan_diag.sample_inodes
                );
            }
        }
        InspectOutput::Btrfs {
            sectorsize,
            nodesize,
            generation,
            label,
        } => {
            println!("filesystem: btrfs");
            println!("sectorsize: {sectorsize}");
            println!("nodesize: {nodesize}");
            println!("generation: {generation}");
            println!("label: {label}");
        }
    }
}

fn inspect_btrfs_subvolumes(
    cx: &Cx,
    path: &Path,
    _flavor: &FsFlavor,
    json: bool,
    list_subvolumes: bool,
    list_snapshots: bool,
) -> Result<()> {
    let fs = OpenFs::open(cx, path).with_context(|| format!("open {}", path.display()))?;

    // Walk the root tree to get all leaf entries
    let root_entries = fs
        .walk_btrfs_root_tree(cx)
        .context("walk btrfs root tree")?;

    if list_subvolumes {
        let subvols = ffs_btrfs::enumerate_subvolumes(&root_entries);
        if json {
            #[derive(serde::Serialize)]
            struct SubvolEntry {
                id: u64,
                parent_id: u64,
                name: String,
                generation: u64,
                read_only: bool,
            }
            let entries: Vec<SubvolEntry> = subvols
                .iter()
                .map(|s| SubvolEntry {
                    id: s.id,
                    parent_id: s.parent_id,
                    name: s.name.clone(),
                    generation: s.generation,
                    read_only: s.read_only,
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&entries).context("serialize")?
            );
        } else {
            println!("Subvolumes ({} found):", subvols.len());
            println!(
                "{:<8} {:<8} {:<12} {:<5} Name",
                "ID", "Parent", "Generation", "RO"
            );
            for s in &subvols {
                println!(
                    "{:<8} {:<8} {:<12} {:<5} {}",
                    s.id,
                    s.parent_id,
                    s.generation,
                    if s.read_only { "yes" } else { "no" },
                    s.name
                );
            }
        }
    }

    if list_snapshots {
        let snapshots = ffs_btrfs::enumerate_snapshots(&root_entries);
        if json {
            #[derive(serde::Serialize)]
            struct SnapEntry {
                id: u64,
                source_id: u64,
                name: String,
                generation: u64,
            }
            let entries: Vec<SnapEntry> = snapshots
                .iter()
                .map(|s| SnapEntry {
                    id: s.id,
                    source_id: s.source_id,
                    name: s.name.clone(),
                    generation: s.generation,
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&entries).context("serialize")?
            );
        } else {
            println!("Snapshots ({} found):", snapshots.len());
            println!("{:<8} {:<8} {:<12} Name", "ID", "Source", "Generation");
            for s in &snapshots {
                println!(
                    "{:<8} {:<8} {:<12} {}",
                    s.id, s.source_id, s.generation, s.name
                );
            }
        }
    }

    Ok(())
}

pub fn inspect_ext4_output(
    cx: &Cx,
    path: &PathBuf,
    open_opts: &OpenOptions,
    sb: &Ext4Superblock,
) -> Result<InspectOutput> {
    // Open the filesystem to read bitmaps for free space and orphan diagnostics.
    let open_fs = OpenFs::open_with_options(cx, path, open_opts)
        .with_context(|| format!("failed to open ext4 image: {}", path.display()))?;
    let summary = open_fs
        .free_space_summary(cx)
        .context("failed to compute free space summary")?;
    let orphans = open_fs
        .read_ext4_orphan_list(cx)
        .context("failed to read ext4 orphan list")?;
    let orphan_diagnostics = if orphans.inodes.is_empty() {
        None
    } else {
        Some(Ext4OrphanDiagnosticsOutput {
            count: u32::try_from(orphans.count()).unwrap_or(u32::MAX),
            sample_inodes: orphans.inodes.iter().take(16).map(|ino| ino.0).collect(),
        })
    };

    let mismatch = if summary.blocks_mismatch || summary.inodes_mismatch {
        Some(FreeSpaceMismatch {
            gd_free_blocks: summary.gd_free_blocks_total,
            gd_free_inodes: summary.gd_free_inodes_total,
        })
    } else {
        None
    };

    Ok(InspectOutput::Ext4 {
        block_size: sb.block_size,
        inodes_count: sb.inodes_count,
        blocks_count: sb.blocks_count,
        volume_name: sb.volume_name.clone(),
        free_blocks_total: summary.free_blocks_total,
        free_inodes_total: summary.free_inodes_total,
        quota_inodes: ext4_quota_inodes_for_output(sb),
        free_space_mismatch: mismatch,
        orphan_diagnostics,
    })
}
