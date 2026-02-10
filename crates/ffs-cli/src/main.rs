#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use asupersync::{Budget, Cx};
use clap::{Parser, Subcommand};
use ffs_core::{FsFlavor, FsOps, OpenFs, detect_filesystem_at_path};
use ffs_fuse::MountOptions;
use ffs_harness::ParityReport;
use serde::Serialize;
use std::path::PathBuf;

// ── Production Cx acquisition ───────────────────────────────────────────────

fn cli_cx() -> Cx {
    Cx::for_request()
}

#[allow(dead_code)]
fn cli_cx_with_timeout_secs(secs: u64) -> Cx {
    Cx::for_request_with_budget(Budget::with_deadline_secs(secs))
}

// ── CLI definition ──────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "ffs", about = "FrankenFS — memory-safe filesystem toolkit")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect a filesystem image (ext4 or btrfs).
    Inspect {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Mount a filesystem image via FUSE (read-only).
    Mount {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Mountpoint directory.
        mountpoint: PathBuf,
        /// Allow other users to access the mount.
        #[arg(long)]
        allow_other: bool,
    },
    /// Show feature parity coverage report.
    Parity {
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
}

// ── Serializable outputs ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(tag = "filesystem", rename_all = "lowercase")]
enum InspectOutput {
    Ext4 {
        block_size: u32,
        inodes_count: u32,
        blocks_count: u64,
        volume_name: String,
    },
    Btrfs {
        sectorsize: u32,
        nodesize: u32,
        generation: u64,
        label: String,
    },
}

// ── Main ────────────────────────────────────────────────────────────────────

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Inspect { image, json } => inspect(&image, json),
        Command::Mount {
            image,
            mountpoint,
            allow_other,
        } => mount_cmd(&image, &mountpoint, allow_other),
        Command::Parity { json } => parity(json),
    }
}

fn inspect(path: &PathBuf, json: bool) -> Result<()> {
    let cx = cli_cx();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;

    let output = match flavor {
        FsFlavor::Ext4(sb) => InspectOutput::Ext4 {
            block_size: sb.block_size,
            inodes_count: sb.inodes_count,
            blocks_count: sb.blocks_count,
            volume_name: sb.volume_name,
        },
        FsFlavor::Btrfs(sb) => InspectOutput::Btrfs {
            sectorsize: sb.sectorsize,
            nodesize: sb.nodesize,
            generation: sb.generation,
            label: sb.label,
        },
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize output")?
        );
    } else {
        println!("FrankenFS Inspector");
        match output {
            InspectOutput::Ext4 {
                block_size,
                inodes_count,
                blocks_count,
                volume_name,
            } => {
                println!("filesystem: ext4");
                println!("block_size: {block_size}");
                println!("inodes_count: {inodes_count}");
                println!("blocks_count: {blocks_count}");
                println!("volume_name: {volume_name}");
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

    Ok(())
}

fn mount_cmd(image_path: &PathBuf, mountpoint: &PathBuf, allow_other: bool) -> Result<()> {
    let cx = cli_cx();
    let open_fs = OpenFs::open(&cx, image_path)
        .with_context(|| format!("failed to open filesystem image: {}", image_path.display()))?;

    match &open_fs.flavor {
        FsFlavor::Ext4(sb) => {
            eprintln!(
                "Mounting ext4 image (block_size={}, blocks={}) at {}",
                sb.block_size,
                sb.blocks_count,
                mountpoint.display()
            );
        }
        FsFlavor::Btrfs(sb) => {
            bail!(
                "btrfs mount not yet supported (image label: {:?})",
                sb.label
            );
        }
    }

    let opts = MountOptions {
        read_only: true,
        allow_other,
        auto_unmount: true,
    };

    let fs_ops: Box<dyn FsOps> = Box::new(open_fs);
    ffs_fuse::mount(fs_ops, mountpoint, &opts)
        .with_context(|| format!("FUSE mount failed at {}", mountpoint.display()))?;

    Ok(())
}

fn parity(json: bool) -> Result<()> {
    let report = ParityReport::current();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).context("serialize parity report")?
        );
    } else {
        println!("FrankenFS Feature Parity Report");
        println!();
        for domain in &report.domains {
            println!(
                "  {:<35} {:>2}/{:<2}  ({:.1}%)",
                domain.domain, domain.implemented, domain.total, domain.coverage_percent
            );
        }
        println!();
        println!(
            "  {:<35} {:>2}/{:<2}  ({:.1}%)",
            "OVERALL",
            report.overall_implemented,
            report.overall_total,
            report.overall_coverage_percent
        );
    }

    Ok(())
}
