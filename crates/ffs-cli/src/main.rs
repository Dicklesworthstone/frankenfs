#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use asupersync::{Budget, Cx};
use clap::{Parser, Subcommand};
use ffs_block::{BlockDevice, ByteBlockDevice, ByteDevice, FileByteDevice};
use ffs_core::{
    Ext4JournalReplayMode, FsFlavor, FsOps, OpenFs, OpenOptions, detect_filesystem_at_path,
};
use ffs_fuse::MountOptions;
use ffs_harness::ParityReport;
use ffs_repair::evidence::{self, EvidenceEventType, EvidenceRecord};
use ffs_repair::scrub::{
    BlockValidator, BtrfsSuperblockValidator, CompositeValidator, Ext4SuperblockValidator,
    ScrubReport, Scrubber, Severity, ZeroCheckValidator,
};
use serde::Serialize;
use std::collections::BTreeSet;
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
    /// Mount a filesystem image via FUSE.
    Mount {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Mountpoint directory.
        mountpoint: PathBuf,
        /// Allow other users to access the mount.
        #[arg(long)]
        allow_other: bool,
        /// Mount read-write (default is read-only).
        #[arg(long)]
        rw: bool,
    },
    /// Run a read-only integrity scan (scrub) on a filesystem image.
    Scrub {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Show feature parity coverage report.
    Parity {
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Display the repair evidence ledger (JSONL).
    Evidence {
        /// Path to the evidence ledger file.
        ledger: PathBuf,
        /// Output in JSON format (array of records).
        #[arg(long)]
        json: bool,
        /// Filter by event type (e.g., corruption_detected, repair_succeeded).
        #[arg(long)]
        event_type: Option<String>,
        /// Show only the last N records.
        #[arg(long)]
        tail: Option<usize>,
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
        free_blocks_total: u64,
        free_inodes_total: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        free_space_mismatch: Option<FreeSpaceMismatch>,
        #[serde(skip_serializing_if = "Option::is_none")]
        orphan_diagnostics: Option<Ext4OrphanDiagnosticsOutput>,
    },
    Btrfs {
        sectorsize: u32,
        nodesize: u32,
        generation: u64,
        label: String,
    },
}

/// Optional field indicating a mismatch between bitmap and group descriptor counts.
#[derive(Debug, Serialize)]
struct FreeSpaceMismatch {
    gd_free_blocks: u64,
    gd_free_inodes: u64,
}

#[derive(Debug, Serialize)]
struct Ext4OrphanDiagnosticsOutput {
    count: u32,
    sample_inodes: Vec<u64>,
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
            rw,
        } => mount_cmd(&image, &mountpoint, allow_other, rw),
        Command::Scrub { image, json } => scrub_cmd(&image, json),
        Command::Parity { json } => parity(json),
        Command::Evidence {
            ledger,
            json,
            event_type,
            tail,
        } => evidence_cmd(&ledger, json, event_type.as_deref(), tail),
    }
}

fn inspect(path: &PathBuf, json: bool) -> Result<()> {
    let cx = cli_cx();
    let open_opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;

    let output = match &flavor {
        FsFlavor::Ext4(sb) => inspect_ext4_output(
            &cx,
            path,
            &open_opts,
            sb.block_size,
            sb.inodes_count,
            sb.blocks_count,
            &sb.volume_name,
        )?,
        FsFlavor::Btrfs(sb) => InspectOutput::Btrfs {
            sectorsize: sb.sectorsize,
            nodesize: sb.nodesize,
            generation: sb.generation,
            label: sb.label.clone(),
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
                free_blocks_total,
                free_inodes_total,
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

    Ok(())
}

fn inspect_ext4_output(
    cx: &Cx,
    path: &PathBuf,
    open_opts: &OpenOptions,
    block_size: u32,
    inodes_count: u32,
    blocks_count: u64,
    volume_name: &str,
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
        block_size,
        inodes_count,
        blocks_count,
        volume_name: volume_name.to_owned(),
        free_blocks_total: summary.free_blocks_total,
        free_inodes_total: summary.free_inodes_total,
        free_space_mismatch: mismatch,
        orphan_diagnostics,
    })
}

fn mount_cmd(
    image_path: &PathBuf,
    mountpoint: &PathBuf,
    allow_other: bool,
    rw: bool,
) -> Result<()> {
    let cx = cli_cx();
    let open_opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let mut open_fs = OpenFs::open_with_options(&cx, image_path, &open_opts)
        .with_context(|| format!("failed to open filesystem image: {}", image_path.display()))?;

    let mode_str = if rw { "rw" } else { "ro" };
    match &open_fs.flavor {
        FsFlavor::Ext4(sb) => {
            eprintln!(
                "Mounting ext4 image (block_size={}, blocks={}, {mode_str}) at {}",
                sb.block_size,
                sb.blocks_count,
                mountpoint.display()
            );
        }
        FsFlavor::Btrfs(sb) => {
            if rw {
                bail!("btrfs read-write mount is not yet supported");
            }
            eprintln!(
                "Mounting btrfs image (sectorsize={}, nodesize={}, label={:?}, {mode_str}) at {}",
                sb.sectorsize,
                sb.nodesize,
                sb.label,
                mountpoint.display()
            );
        }
    }

    if let Some(recovery) = open_fs.crash_recovery() {
        if recovery.recovery_performed() {
            eprintln!(
                "  crash recovery: unclean shutdown detected (state=0x{:04X}, errors={}, orphans={})",
                recovery.raw_state, recovery.had_errors, recovery.had_orphans
            );
            if recovery.journal_txns_replayed > 0 {
                eprintln!(
                    "  journal replay: {} transactions, {} blocks replayed",
                    recovery.journal_txns_replayed, recovery.journal_blocks_replayed
                );
            }
            if recovery.mvcc_reset {
                eprintln!("  mvcc: version store reset (in-flight transactions discarded)");
            }
        }
    }

    if rw {
        open_fs
            .enable_writes(&cx)
            .context("failed to enable write support")?;
    }

    let opts = MountOptions {
        read_only: !rw,
        allow_other,
        auto_unmount: true,
        worker_threads: 0,
    };

    let fs_ops: Box<dyn FsOps> = Box::new(open_fs);
    ffs_fuse::mount(fs_ops, mountpoint, &opts)
        .with_context(|| format!("FUSE mount failed at {}", mountpoint.display()))?;

    Ok(())
}

// ── Scrub command ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct ScrubOutput {
    blocks_scanned: u64,
    blocks_corrupt: u64,
    blocks_error_or_higher: u64,
    blocks_io_error: u64,
    findings: Vec<ScrubFindingOutput>,
}

#[derive(Debug, Serialize)]
struct ScrubFindingOutput {
    block: u64,
    kind: String,
    severity: String,
    detail: String,
}

fn choose_btrfs_scrub_block_size(image_len: u64, nodesize: u32, sectorsize: u32) -> Result<u32> {
    if nodesize == 0 || !nodesize.is_power_of_two() {
        bail!("invalid btrfs nodesize={nodesize}; expected non-zero power-of-two");
    }

    // Btrfs superblock region is 4 KiB; scrub block size must hold it.
    let min_block_size = if sectorsize.is_power_of_two() {
        sectorsize.max(4096)
    } else {
        4096
    };

    if min_block_size > nodesize {
        bail!(
            "invalid btrfs geometry: sectorsize={sectorsize} nodesize={nodesize} (expected sectorsize <= nodesize)"
        );
    }

    let mut candidate = nodesize;
    while candidate >= min_block_size {
        if image_len % u64::from(candidate) == 0 {
            return Ok(candidate);
        }
        candidate /= 2;
    }

    bail!(
        "image length is not aligned to any supported btrfs scrub block size: len_bytes={image_len}, nodesize={nodesize}, sectorsize={sectorsize}"
    )
}

fn count_blocks_at_severity_or_higher(report: &ScrubReport, min: Severity) -> u64 {
    report
        .findings
        .iter()
        .filter(|finding| finding.severity >= min)
        .map(|finding| finding.block.0)
        .collect::<BTreeSet<_>>()
        .len() as u64
}

fn scrub_cmd(path: &PathBuf, json: bool) -> Result<()> {
    let cx = cli_cx();

    // Detect filesystem to get the block size.
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;

    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let image_len = byte_dev.len_bytes();

    let block_size = match &flavor {
        FsFlavor::Ext4(sb) => sb.block_size,
        FsFlavor::Btrfs(sb) => choose_btrfs_scrub_block_size(image_len, sb.nodesize, sb.sectorsize)
            .with_context(|| {
                format!(
                    "failed to derive aligned btrfs scrub block size (len_bytes={image_len}, nodesize={}, sectorsize={})",
                    sb.nodesize, sb.sectorsize
                )
            })?,
    };

    let block_dev = ByteBlockDevice::new(byte_dev, block_size)
        .with_context(|| format!("failed to create block device (block_size={block_size})"))?;

    let validator: Box<dyn BlockValidator> = match &flavor {
        FsFlavor::Ext4(_) => Box::new(CompositeValidator::new(vec![
            Box::new(ZeroCheckValidator),
            Box::new(Ext4SuperblockValidator::new(block_size)),
        ])),
        FsFlavor::Btrfs(_) => Box::new(CompositeValidator::new(vec![
            Box::new(ZeroCheckValidator),
            Box::new(BtrfsSuperblockValidator::new(block_size)),
        ])),
    };

    if !json {
        let fs_name = match &flavor {
            FsFlavor::Ext4(_) => "ext4",
            FsFlavor::Btrfs(_) => "btrfs",
        };
        eprintln!(
            "Scrubbing {fs_name} image: {} ({} blocks, block_size={block_size})",
            path.display(),
            block_dev.block_count(),
        );
    }

    let report = Scrubber::new(&block_dev, &*validator)
        .scrub_all(&cx)
        .with_context(|| "scrub failed")?;

    let blocks_error_or_higher = count_blocks_at_severity_or_higher(&report, Severity::Error);

    let output = ScrubOutput {
        blocks_scanned: report.blocks_scanned,
        blocks_corrupt: report.blocks_corrupt,
        blocks_error_or_higher,
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

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize scrub report")?
        );
    } else {
        println!("FrankenFS Scrub Report");
        println!(
            "scanned {} blocks: {} corrupt, {} error+, {} io_errors, {} findings",
            output.blocks_scanned,
            output.blocks_corrupt,
            output.blocks_error_or_higher,
            output.blocks_io_error,
            output.findings.len(),
        );
        if !report.findings.is_empty() {
            println!();
            for f in &report.findings {
                println!("  {f}");
            }
        }
    }

    // Exit with non-zero status if corruption found at Error or above.
    if report.count_at_severity(Severity::Error) > 0 {
        std::process::exit(2);
    }

    Ok(())
}

fn evidence_cmd(
    path: &PathBuf,
    json: bool,
    event_type_filter: Option<&str>,
    tail: Option<usize>,
) -> Result<()> {
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read evidence ledger: {}", path.display()))?;

    let mut records = evidence::parse_evidence_ledger(&data);

    // Filter by event type if requested.
    if let Some(filter) = event_type_filter {
        records.retain(|r| {
            let type_str = serde_json::to_value(r.event_type)
                .ok()
                .and_then(|v| v.as_str().map(String::from));
            type_str.as_deref() == Some(filter)
        });
    }

    // Tail: keep only the last N records.
    if let Some(n) = tail {
        if records.len() > n {
            records.drain(..records.len() - n);
        }
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&records).context("serialize evidence records")?
        );
    } else {
        if records.is_empty() {
            println!("No evidence records found.");
            return Ok(());
        }
        println!("FrankenFS Evidence Ledger ({} records)", records.len());
        println!();
        for record in &records {
            print_evidence_record(record);
        }
    }

    Ok(())
}

fn print_evidence_record(record: &EvidenceRecord) {
    let ts_secs = record.timestamp_ns / 1_000_000_000;
    let ts_nanos = record.timestamp_ns % 1_000_000_000;
    let event = serde_json::to_value(record.event_type)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| format!("{:?}", record.event_type));

    print!(
        "  [{ts_secs}.{ts_nanos:09}] {event:<24} group={}",
        record.block_group
    );

    if let Some((start, end)) = record.block_range {
        print!(" blocks={start}..{end}");
    }

    match record.event_type {
        EvidenceEventType::CorruptionDetected => {
            if let Some(ref c) = record.corruption {
                print!(
                    " blocks_affected={} kind={} severity={}",
                    c.blocks_affected, c.corruption_kind, c.severity
                );
            }
        }
        EvidenceEventType::RepairAttempted
        | EvidenceEventType::RepairSucceeded
        | EvidenceEventType::RepairFailed => {
            if let Some(ref r) = record.repair {
                print!(
                    " corrupt={} symbols={}/{} verify={}",
                    r.corrupt_count, r.symbols_used, r.symbols_available, r.verify_pass
                );
                if let Some(ref reason) = r.reason {
                    print!(" reason=\"{reason}\"");
                }
            }
        }
        EvidenceEventType::ScrubCycleComplete => {
            if let Some(ref s) = record.scrub_cycle {
                print!(
                    " scanned={} corrupt={} io_errors={} findings={}",
                    s.blocks_scanned, s.blocks_corrupt, s.blocks_io_error, s.findings_count
                );
            }
        }
        EvidenceEventType::PolicyDecision => {
            if let Some(ref p) = record.policy {
                print!(
                    " posterior={:.4} overhead={:.3} risk_bound={:.1e} decision=\"{}\"",
                    p.corruption_posterior, p.overhead_ratio, p.risk_bound, p.decision
                );
            }
        }
        EvidenceEventType::SymbolRefresh => {
            if let Some(ref s) = record.symbol_refresh {
                print!(
                    " gen={}→{} symbols={}",
                    s.previous_generation, s.new_generation, s.symbols_generated
                );
            }
        }
        EvidenceEventType::WalRecovery => {
            if let Some(ref w) = record.wal_recovery {
                print!(
                    " commits={} versions={} discarded={} valid={}/{}",
                    w.commits_replayed,
                    w.versions_replayed,
                    w.records_discarded,
                    w.wal_valid_bytes,
                    w.wal_total_bytes
                );
                if w.used_checkpoint {
                    if let Some(seq) = w.checkpoint_commit_seq {
                        print!(" checkpoint_seq={seq}");
                    }
                }
            }
        }
    }

    println!();
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
