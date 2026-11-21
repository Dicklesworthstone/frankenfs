//! Unified non-mutating structural `check`, native `format`, and
//! source-preserving offline `resize` commands for `ffs-ntfs`.

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::{Args, ValueEnum};
use ffs_ntfs::formatter::{NtfsFormatOptions, NtfsFormatVersion, format_image_file, plan_format};
use ffs_ntfs::reader::check::repair::{apply_bounded_repair, plan_bounded_repair};
use ffs_ntfs::reader::check::{NtfsCheckLimits, check_image_file};
use ffs_ntfs::resize::{NtfsResizeOptions, run_resize};

/// Target NTFS format version selectable on the CLI (`3.1` or `3.0`).
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliNtfsVersion {
    #[value(name = "3.1")]
    V3_1,
    #[value(name = "3.0")]
    V3_0,
}

impl From<CliNtfsVersion> for NtfsFormatVersion {
    fn from(value: CliNtfsVersion) -> Self {
        match value {
            CliNtfsVersion::V3_1 => Self::V3_1,
            CliNtfsVersion::V3_0 => Self::V3_0,
        }
    }
}

fn parse_serial(raw: &str) -> std::result::Result<u64, String> {
    raw.strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .map_or_else(
            || {
                raw.parse::<u64>()
                    .map_err(|e| format!("invalid serial {raw:?}: {e}"))
            },
            |hex| {
                u64::from_str_radix(hex, 16).map_err(|e| format!("invalid hex serial {raw:?}: {e}"))
            },
        )
}

/// Arguments for `ffs-ntfs check`.
#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Offline NTFS image file.
    pub image: PathBuf,
    /// Byte offset of an already selected NTFS volume, not a sector number.
    #[arg(long, default_value_t = 0)]
    pub offset: u64,
    /// Restrict inspection to this many bytes of the selected volume.
    #[arg(long)]
    pub length: Option<u64>,
    /// Confirm the image is offline and not mounted elsewhere.
    #[arg(long, required = true)]
    pub offline_image: bool,
    /// Emit a deterministic bounded repair plan alongside the check report (still read-only).
    #[arg(long)]
    pub repair_plan: bool,
    /// Apply eligible bounded repairs (`--allow-write` also required; never repairs ambiguous damage).
    #[arg(long, requires = "allow_write")]
    pub apply_repair: bool,
    /// Explicitly authorize bounded repair writes when combined with `--apply-repair`.
    #[arg(long)]
    pub allow_write: bool,
    /// Maximum logical MFT record slots checked.
    #[arg(long, default_value_t = 1_048_576)]
    pub max_records: u64,
    /// Maximum volume clusters checked.
    #[arg(long, default_value_t = 33_554_432)]
    pub max_clusters: u64,
    /// Maximum decoded mapping runs checked.
    #[arg(long, default_value_t = 1_048_576)]
    pub max_runs: usize,
    /// Metadata byte budget for ownership/mirror/namespace/security passes.
    #[arg(long, default_value_t = 1 << 30)]
    pub max_metadata_bytes: u64,
}

/// Arguments for `ffs-ntfs format`.
#[derive(Debug, Args)]
pub struct FormatArgs {
    /// Target image file to create (or overwrite only with `--offline-image --allow-overwrite`).
    pub image: PathBuf,
    /// Target volume size in MiB.
    #[arg(long, conflicts_with = "size_bytes")]
    pub size_mib: Option<u64>,
    /// Exact target volume size in bytes.
    #[arg(long, conflicts_with = "size_mib")]
    pub size_bytes: Option<u64>,
    /// Logical sector size in bytes (512, 1024, 2048, or 4096).
    #[arg(long, default_value_t = 512)]
    pub sector_bytes: u32,
    /// Cluster size in bytes (power of two in 512..=65536).
    #[arg(long)]
    pub cluster_bytes: Option<u32>,
    /// Target NTFS version profile (`3.1` default or `3.0`).
    #[arg(long, value_enum, default_value_t = CliNtfsVersion::V3_1)]
    pub ntfs_version: CliNtfsVersion,
    /// Optional volume label (up to 127 UTF-16 code units).
    #[arg(long)]
    pub label: Option<String>,
    /// Optional explicit 64-bit volume serial number (decimal or `0x...` hex).
    #[arg(long, value_parser = parse_serial)]
    pub serial: Option<u64>,
    /// Optional `$LogFile` size in bytes (4 KiB multiple, >= 256 KiB).
    #[arg(long)]
    pub logfile_bytes: Option<u64>,
    /// Optional deterministic NTFS timestamp (100ns ticks since 1601-01-01 UTC).
    #[arg(long)]
    pub timestamp: Option<u64>,
    /// Print planned layout without creating or writing the image.
    #[arg(long)]
    pub dry_run: bool,
    /// Confirm target is an offline regular file when overwriting an existing image.
    #[arg(long)]
    pub offline_image: bool,
    /// Explicitly authorize overwriting an existing offline regular image.
    #[arg(long, requires = "offline_image")]
    pub allow_overwrite: bool,
}

/// Arguments for `ffs-ntfs resize`.
#[derive(Debug, Args)]
pub struct ResizeArgs {
    /// Offline read-only source NTFS image.
    pub source_image: PathBuf,
    /// Brand-new standalone output image path (existing files/symlinks refused).
    #[arg(long)]
    pub output: PathBuf,
    /// Target output volume size in MiB.
    #[arg(long, conflicts_with = "size_bytes")]
    pub size_mib: Option<u64>,
    /// Exact target output volume size in bytes.
    #[arg(long, conflicts_with = "size_mib")]
    pub size_bytes: Option<u64>,
    /// Byte offset of an already selected NTFS volume inside `source_image`.
    #[arg(long, default_value_t = 0)]
    pub offset: u64,
    /// Byte length of the selected NTFS volume inside `source_image`.
    #[arg(long)]
    pub length: Option<u64>,
    /// Authorize moving live tail clusters into retained free slots when shrinking.
    #[arg(long)]
    pub relocate: bool,
    /// Confirm `source_image` remains offline and immutable for the entire operation.
    #[arg(long, required = true)]
    pub offline_image: bool,
    /// Validate source and print the relocation plan without creating `output`.
    #[arg(long)]
    pub dry_run: bool,
}

fn write_json(value: &impl serde::Serialize) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

pub fn run_check(cx: &Cx, args: &CheckArgs) -> Result<()> {
    if !args.offline_image {
        bail!("--offline-image is required for NTFS structural checking");
    }
    let defaults = NtfsCheckLimits::default();
    let limits = NtfsCheckLimits {
        records: args.max_records,
        clusters: args.max_clusters,
        runs: args.max_runs,
        metadata_bytes: args.max_metadata_bytes,
        namespace_entries: defaults.namespace_entries,
        security_entries: defaults.security_entries,
    };

    if args.apply_repair {
        let (plan, after) = apply_bounded_repair(
            cx,
            &args.image,
            args.offset,
            args.length,
            args.offline_image,
            args.allow_write,
            limits,
        )
        .with_context(|| format!("applying bounded NTFS repair on {}", args.image.display()))?;
        let payload = serde_json::json!({
            "operation": "bounded_repair",
            "plan": plan,
            "post_repair_check": after,
        });
        write_json(&payload)?;
        if !after.clean {
            bail!(
                "NTFS volume {} remained unclean after bounded repair ({:?})",
                args.image.display(),
                after.status
            );
        }
        return Ok(());
    }

    let report = check_image_file(cx, &args.image, args.offset, args.length, limits)
        .with_context(|| format!("checking offline NTFS image {}", args.image.display()))?;
    if args.repair_plan {
        let plan = plan_bounded_repair(&report);
        let payload = serde_json::json!({
            "check": report,
            "repair_plan": plan,
        });
        write_json(&payload)?;
    } else {
        write_json(&report)?;
    }
    if !report.clean {
        bail!(
            "NTFS structural check found status {:?} ({} issue(s)); zero backing writes performed",
            report.status,
            report.issues.len()
        );
    }
    Ok(())
}

pub fn run_format(cx: &Cx, args: &FormatArgs) -> Result<()> {
    let opts = NtfsFormatOptions {
        image: args.image.clone(),
        allow_existing_target: args.allow_overwrite,
        offline_image: args.offline_image,
        size_bytes: args.size_bytes,
        size_mib: args.size_mib,
        sector_bytes: args.sector_bytes,
        cluster_bytes: args.cluster_bytes,
        version: args.ntfs_version.into(),
        label: args.label.clone(),
        serial: args.serial,
        logfile_bytes: args.logfile_bytes,
        timestamp_100ns: args.timestamp,
    };
    if args.dry_run {
        let layout = plan_format(&opts).context("planning native NTFS format layout")?;
        write_json(&layout)?;
        return Ok(());
    }
    let report = format_image_file(cx, &opts, None)
        .with_context(|| format!("formatting native NTFS image {}", args.image.display()))?;
    write_json(&report)
}

pub fn run_resize_cmd(cx: &Cx, args: &ResizeArgs) -> Result<()> {
    let opts = NtfsResizeOptions {
        source_image: args.source_image.clone(),
        source_offset: args.offset,
        source_length: args.length,
        output: args.output.clone(),
        size_bytes: args.size_bytes,
        size_mib: args.size_mib,
        relocate: args.relocate,
        offline_image: args.offline_image,
        dry_run: args.dry_run,
    };
    let report = run_resize(cx, &opts, None).with_context(|| {
        format!(
            "resizing offline NTFS image {} -> {}",
            args.source_image.display(),
            args.output.display()
        )
    })?;
    write_json(&report)
}
