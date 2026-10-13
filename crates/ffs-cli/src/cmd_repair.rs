use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_block::{BlockDevice, ByteBlockDevice, ByteDevice, FileByteDevice};
use ffs_core::native_repair::{NativeRepairReport, NativeRepairStorage, NativeValidationReport};
use ffs_core::{Ext4JournalReplayMode, FsFlavor, OpenFs, OpenOptions, detect_filesystem_at_path};
use ffs_ondisk::btrfs::BTRFS_FIRST_CHUNK_TREE_OBJECTID;
use ffs_ondisk::{
    BtrfsChunkEntry, BtrfsSuperblock, Ext4Superblock, map_logical_to_physical,
    verify_btrfs_superblock_checksum,
};
use ffs_repair::codec::{EncodedGroup, encode_group};
use ffs_repair::ownership::{AcquireResult, OwnershipGuard, RepairOwnership};
use ffs_repair::recovery::{GroupRecoveryOrchestrator, RecoveryOutcome};
use ffs_repair::scrub::{BlockValidator, Ext4MetadataValidator, ScrubReport, Scrubber, Severity};
use ffs_repair::storage::{REPAIR_DESC_SLOT_COUNT, RepairGroupLayout, RepairGroupStorage};
use ffs_repair::symbol::RepairGroupDescExt;
use ffs_types::{
    BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, BlockNumber, ByteOffset, GroupNumber, MountMode,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, info_span, warn};

use crate::{
    RepairActionOutput, RepairCommandOptions, RepairFlags, RepairOutput, RepairScopeOutput,
    RepairScrubOutput, choose_btrfs_scrub_block_size, cli_cx, count_blocks_at_severity_or_higher,
    ext4_appears_clean_state, ext4_group_scrub_scope, ext4_recovery_detail, filesystem_name,
    offline_ext4_scrub_validator,
    repair_btrfs_parsers::{parse_btrfs_block_group_item, parse_btrfs_root_item_bytenr},
    run_ext4_mount_recovery, scrub_validator,
};

/// Maximum ext4 groups the repair CLI will expand into per-group repair specs.
///
/// This mirrors the integrity verifier's group-scan cap and rejects corrupt
/// superblocks that advertise billions of groups before allocation.
pub const MAX_EXT4_REPAIR_GROUP_SPECS: u32 = 65_536;

#[derive(Debug, Serialize)]
struct NativePrepareOutput {
    image: PathBuf,
    check_only: bool,
    storage_prepared: bool,
    protection_active: bool,
    storage: NativeRepairStorage,
}

struct NativePrepareLock(Arc<std::fs::File>);

impl Drop for NativePrepareLock {
    fn drop(&mut self) {
        // Release explicitly even if a fork retained the same open-file description.
        if let Err(error) = self.0.unlock() {
            warn!(%error, "native preparation image unlock failed");
        }
    }
}

fn lock_native_prepare_image(
    path: &Path,
    check: bool,
) -> Result<(FileByteDevice, NativePrepareLock)> {
    if !std::fs::metadata(path)?.is_file() {
        bail!("native preparation requires a regular image file");
    }
    let device = if check {
        FileByteDevice::open_read_only(path)?
    } else {
        FileByteDevice::open(path)?
    };
    if !device.file().metadata()?.is_file() {
        bail!("native preparation requires a regular image file");
    }
    // FileByteDevice::open can fall back to O_RDONLY. Refuse that fallback
    // before entering any conversion code, including when running as root.
    let access = nix::fcntl::fcntl(device.file().as_raw_fd(), nix::fcntl::FcntlArg::F_GETFL)?;
    if !check && access & libc::O_ACCMODE != libc::O_RDWR {
        bail!("native preparation requires a writable image file");
    }
    let file = Arc::clone(device.file());
    if check {
        file.try_lock_shared()
    } else {
        file.try_lock()
    }
    .with_context(|| format!("lock {} for native preparation", path.display()))?;
    Ok((device, NativePrepareLock(file)))
}

fn open_native_prepare_view(cx: &Cx, device: FileByteDevice) -> Result<OpenFs> {
    let fs = OpenFs::from_device(
        cx,
        Box::new(device),
        &OpenOptions {
            mount_mode: MountMode::Native,
            ext4_journal_replay_mode: Ext4JournalReplayMode::Skip,
            ..OpenOptions::default()
        },
    )?;
    let sb = fs
        .ext4_superblock()
        .context("native preparation currently requires ext4")?;
    if sb.state != ffs_ondisk::ext4::EXT4_VALID_FS
        || sb.has_incompat(ffs_ondisk::Ext4IncompatFeatures::RECOVER)
    {
        bail!("native preparation requires clean ext4; recover offline first");
    }
    Ok(fs)
}

fn build_native_prepare_output(
    path: &Path,
    basis_points: u32,
    check: bool,
) -> Result<NativePrepareOutput> {
    let cx = cli_cx();
    let (device, lock) = lock_native_prepare_image(path, check)?;
    let fs = open_native_prepare_view(&cx, device)?;
    let storage = if check {
        fs.native_ext4_repair_storage(&cx)?
    } else {
        let prepared = fs.prepare_native_ext4_repair(&cx, basis_points)?;
        // The consumed view may cache pre-conversion metadata. Discover from
        // a new read-only device while retaining the original exclusive lock.
        let device = FileByteDevice::open_read_only(path)?;
        let locked = lock.0.metadata()?;
        let reopened = device.file().metadata()?;
        if (locked.dev(), locked.ino()) != (reopened.dev(), reopened.ino()) {
            bail!("native preparation image path changed before discovery");
        }
        let discovered = open_native_prepare_view(&cx, device)?.native_ext4_repair_storage(&cx)?;
        if discovered != prepared {
            bail!("reopened native repair ownership differs from the prepared storage");
        }
        discovered
    };
    Ok(NativePrepareOutput {
        image: path.to_path_buf(),
        check_only: check,
        storage_prepared: true,
        protection_active: false,
        storage,
    })
}

pub fn native_prepare_cmd(path: &Path, basis_points: u32, check: bool, json: bool) -> Result<()> {
    let output = match build_native_prepare_output(path, basis_points, check) {
        Ok(output) => output,
        Err(error) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "error",
                        "image": path,
                        "check_only": check,
                        "error": format!("{error:#}"),
                        "protection_active": false,
                    })
                );
            }
            return Err(error);
        }
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Native repair storage: {}", path.display());
        println!("storage_prepared=true protection_active=false");
        println!(
            "Owner inode: {}; groups: {}; repair basis points: {}",
            output.storage.owner_inode.0,
            output.storage.tails.len(),
            output.storage.repair_basis_points
        );
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct NativeValidateOutput {
    image: PathBuf,
    initialize: bool,
    validation_initialized: bool,
    source_matches: bool,
    protection_active: bool,
    validation: NativeValidationReport,
}

fn build_native_validate_output(path: &Path, initialize: bool) -> Result<NativeValidateOutput> {
    let cx = cli_cx();
    let (device, lock) = lock_native_prepare_image(path, !initialize)?;
    let fs = open_native_prepare_view(&cx, device)?;
    let validation = if initialize {
        let expected = fs.initialize_native_ext4_validation(&cx)?;
        let device = FileByteDevice::open_read_only(path)?;
        let locked = lock.0.metadata()?;
        let reopened = device.file().metadata()?;
        if (locked.dev(), locked.ino()) != (reopened.dev(), reopened.ino()) {
            bail!("native validation image path changed before discovery");
        }
        let checked = open_native_prepare_view(&cx, device)?.check_native_ext4_validation(&cx)?;
        if checked != expected {
            bail!("reopened native validation differs from initialization");
        }
        checked
    } else {
        fs.check_native_ext4_validation(&cx)?
    };
    Ok(NativeValidateOutput {
        image: path.to_path_buf(),
        initialize,
        validation_initialized: true,
        source_matches: true,
        protection_active: false,
        validation,
    })
}

pub fn native_validate_cmd(path: &Path, initialize: bool, json: bool) -> Result<()> {
    let output = match build_native_validate_output(path, initialize) {
        Ok(output) => output,
        Err(error) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "error", "image": path, "initialize": initialize,
                        "error": format!("{error:#}"), "protection_active": false,
                    })
                );
            }
            return Err(error);
        }
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Native source validation: {}", path.display());
        println!("validation_initialized=true source_matches=true protection_active=false");
        println!(
            "Groups: {}; source blocks checked: {}",
            output.validation.groups, output.validation.source_blocks
        );
    }
    Ok(())
}

fn native_codec_working_bytes(mib: u64) -> Result<u64> {
    if mib == 0 {
        bail!("native codec memory limit must be positive");
    }
    mib.checked_mul(1024 * 1024)
        .context("native codec memory limit overflows bytes")
}

#[derive(Debug, Serialize)]
struct NativeEncodeOutput {
    image: PathBuf,
    check_only: bool,
    baseline_verified: bool,
    protection_active: bool,
    repair: NativeRepairReport,
}

fn build_native_encode_output(
    path: &Path,
    check: bool,
    max_codec_memory_mib: u64,
) -> Result<NativeEncodeOutput> {
    let max_working_bytes = native_codec_working_bytes(max_codec_memory_mib)?;
    let cx = cli_cx();
    let (device, lock) = lock_native_prepare_image(path, check)?;
    let fs = open_native_prepare_view(&cx, device)?;
    let repair = if check {
        fs.check_native_ext4_repair(&cx)?
    } else {
        let expected = fs.initialize_native_ext4_repair(&cx, max_working_bytes)?;
        let device = FileByteDevice::open_read_only(path)?;
        let locked = lock.0.metadata()?;
        let reopened = device.file().metadata()?;
        if (locked.dev(), locked.ino()) != (reopened.dev(), reopened.ino()) {
            bail!("native encoding image path changed before verification");
        }
        let checked = open_native_prepare_view(&cx, device)?.check_native_ext4_repair(&cx)?;
        if checked != expected {
            bail!("reopened native repair evidence differs from encoding");
        }
        checked
    };
    Ok(NativeEncodeOutput {
        image: path.to_path_buf(),
        check_only: check,
        baseline_verified: true,
        protection_active: false,
        repair,
    })
}

pub fn native_encode_cmd(
    path: &Path,
    check: bool,
    max_codec_memory_mib: u64,
    json: bool,
) -> Result<()> {
    let output = match build_native_encode_output(path, check, max_codec_memory_mib) {
        Ok(output) => output,
        Err(error) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "error", "image": path, "check_only": check,
                        "error": format!("{error:#}"), "protection_active": false,
                    })
                );
            }
            return Err(error);
        }
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Native offline repair baseline: {}", path.display());
        println!("baseline_verified=true protection_active=false");
        println!(
            "Groups: {}; source blocks: {}; repair blocks: {}",
            output.repair.groups, output.repair.source_blocks, output.repair.repair_blocks
        );
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct NativeRecoverOutput {
    image: PathBuf,
    output: PathBuf,
    block: BlockNumber,
    generation: u64,
    bytes: usize,
    baseline_verified: bool,
    protection_active: bool,
}

fn write_native_reconstruction(cx: &Cx, path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;

    cx.checkpoint()
        .map_err(|_| ffs_error::FfsError::Cancelled)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create new native reconstruction output {}", path.display()))?;
    output.write_all(data)?;
    output.sync_all()?;
    cx.checkpoint()
        .map_err(|_| ffs_error::FfsError::Cancelled)?;
    Ok(())
}

fn build_native_recover_output(
    path: &Path,
    block: BlockNumber,
    output: &Path,
    max_codec_memory_mib: u64,
) -> Result<NativeRecoverOutput> {
    let max_working_bytes = native_codec_working_bytes(max_codec_memory_mib)?;
    let cx = cli_cx();
    let (device, lock) = lock_native_prepare_image(path, true)?;
    let fs = open_native_prepare_view(&cx, device)?;
    let block_size = fs
        .ext4_superblock()
        .context("native reconstruction requires ext4")?
        .block_size;
    let recovered = fs.reconstruct_native_ext4_block(&cx, block, max_working_bytes)?;
    if recovered.block != block
        || recovered.generation == 0
        || recovered.data.len() != block_size as usize
    {
        bail!("native reconstruction returned an invalid block or generation");
    }
    let locked = lock.0.metadata()?;
    let current = std::fs::metadata(path)?;
    if (locked.dev(), locked.ino()) != (current.dev(), current.ino()) {
        bail!("native reconstruction image path changed before export");
    }
    write_native_reconstruction(&cx, output, &recovered.data)?;
    Ok(NativeRecoverOutput {
        image: path.to_path_buf(),
        output: output.to_path_buf(),
        block: recovered.block,
        generation: recovered.generation,
        bytes: recovered.data.len(),
        baseline_verified: true,
        protection_active: false,
    })
}

pub fn native_recover_cmd(
    path: &Path,
    block: BlockNumber,
    output_path: &Path,
    max_codec_memory_mib: u64,
    json: bool,
) -> Result<()> {
    let output = match build_native_recover_output(path, block, output_path, max_codec_memory_mib) {
        Ok(output) => output,
        Err(error) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "error", "image": path, "block": block,
                        "output": output_path, "error": format!("{error:#}"),
                        "protection_active": false,
                    })
                );
            }
            return Err(error);
        }
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Native baseline reconstruction: {}", output_path.display());
        println!("baseline_verified=true protection_active=false");
        println!(
            "Block: {}; generation: {}; bytes: {}",
            output.block.0, output.generation, output.bytes
        );
    }
    Ok(())
}

/// A write plan rejected before any of its repair symbols or descriptors change.
#[derive(Debug, Serialize)]
pub struct RepairTailRefusal {
    pub code: &'static str,
    pub phase: &'static str,
    pub filesystem: &'static str,
    pub group: Option<u32>,
    pub detail: String,
}

impl std::fmt::Display for RepairTailRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}: {} repair plan refused during {}: {}",
            self.code, self.filesystem, self.phase, self.detail
        )
    }
}

impl std::error::Error for RepairTailRefusal {}

fn repair_tail_refusal(
    phase: &'static str,
    filesystem: &'static str,
    group: Option<u32>,
    detail: String,
) -> anyhow::Error {
    let refusal = RepairTailRefusal {
        code: "FFS_REPAIR_TAIL_UNSAFE",
        phase,
        filesystem,
        group,
        detail,
    };
    warn!(
        target: "ffs::cli::repair",
        code = refusal.code,
        phase,
        filesystem,
        group,
        detail = refusal.detail,
        "repair_tail_plan_refused"
    );
    refusal.into()
}

pub fn repair_cmd(path: &PathBuf, options: RepairCommandOptions) -> Result<()> {
    let flags = options.flags;
    let command_span = info_span!(
        target: "ffs::cli::repair",
        "repair",
        image = %path.display(),
        full_scrub = flags.full_scrub(),
        verify_only = flags.verify_only(),
        rebuild_symbols = flags.rebuild_symbols(),
        block_group = options.block_group.unwrap_or(u32::MAX),
        max_threads = options.max_threads.unwrap_or(0),
        output_json = flags.json()
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::repair", "repair_start");

    let output = match build_repair_output(path, options) {
        Ok(output) => output,
        Err(err) => {
            if flags.json() {
                let error_msg = format!("{err:#}");
                let mut output = serde_json::json!({
                    "status": "operational_error", "exit_code": 4, "error": error_msg,
                });
                if let Some(refusal) = err.downcast_ref::<RepairTailRefusal>() {
                    output["refusal"] = serde_json::to_value(refusal)?;
                }
                println!("{output}");
            } else {
                eprintln!("repair operational error: {err:#}");
            }
            std::process::exit(4);
        }
    };

    print_repair_output(flags.json(), &output)?;

    info!(
        target: "ffs::cli::repair",
        filesystem = output.filesystem,
        action = ?output.action,
        exit_code = output.exit_code,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "repair_complete"
    );

    if output.exit_code != 0 {
        std::process::exit(output.exit_code);
    }

    Ok(())
}

pub fn repair_worker_limit(requested: Option<u32>) -> (usize, Option<u32>) {
    let available = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let requested_raw = requested.unwrap_or(1).max(1);
    let requested_threads = usize::try_from(requested_raw).unwrap_or(usize::MAX);
    let effective = requested_threads.min(available).max(1);
    let capped = (requested_threads > effective).then_some(requested_raw);
    (effective, capped)
}

pub fn partition_scrub_range(
    start: BlockNumber,
    count: u64,
    workers: usize,
) -> Vec<(BlockNumber, u64)> {
    if count == 0 || workers == 0 {
        return Vec::new();
    }

    let workers_u64 = u64::try_from(workers).unwrap_or(u64::MAX).min(count);
    let base = count / workers_u64;
    let remainder = count % workers_u64;
    let mut cursor = start.0;
    let mut ranges = Vec::with_capacity(usize::try_from(workers_u64).unwrap_or(usize::MAX));
    for worker_idx in 0..workers_u64 {
        let width = base + u64::from(worker_idx < remainder);
        ranges.push((BlockNumber(cursor), width));
        cursor = cursor.saturating_add(width);
    }
    ranges
}

pub fn merge_scrub_reports(reports: Vec<ScrubReport>) -> ScrubReport {
    let mut merged = ScrubReport {
        findings: Vec::new(),
        blocks_scanned: 0,
        blocks_corrupt: 0,
        blocks_io_error: 0,
    };
    for report in reports {
        merged.blocks_scanned = merged.blocks_scanned.saturating_add(report.blocks_scanned);
        merged.blocks_corrupt = merged.blocks_corrupt.saturating_add(report.blocks_corrupt);
        merged.blocks_io_error = merged
            .blocks_io_error
            .saturating_add(report.blocks_io_error);
        merged.findings.extend(report.findings);
    }
    merged
}

pub const DEFAULT_REPAIR_OVERHEAD_RATIO: f64 = 1.05;
const DEFAULT_REPAIR_VALIDATION_BLOCK_COUNT: u32 = 0;
const BTRFS_EXTENT_TREE_OBJECTID: u64 = 2;
const BTRFS_ROOT_ITEM_TYPE: u8 = 132;
const BTRFS_BLOCK_GROUP_ITEM_TYPE: u8 = 192;
const BTRFS_SUPER_MIRROR_MAX: u32 = 3;
const BTRFS_SUPER_MIRROR_SHIFT: u32 = 12;
const BTRFS_FIRST_BACKUP_SUPER_OFFSET: u64 = 64 * 1024 * 1024;
const BTRFS_SUPER_BYTENR_OFFSET: usize = 0x30;
const BTRFS_SUPER_CSUM_OFFSET: usize = 0;
const BTRFS_SUPER_CSUM_LEN: usize = 4;
const BTRFS_SUPER_CSUM_DATA_OFFSET: usize = 0x20;
/// Coordination policy identifier surfaced in repair/fsck JSON output.
///
/// `lease_v1` denotes the lease-based ownership protocol from
/// `ffs_repair::ownership`: write-side repair is owned by one host at a time
/// via a TTL-bounded coordination record, expired leases can be taken over,
/// and concurrent claims converge through a deterministic host-id tiebreak.
const REPAIR_COORDINATION_POLICY: &str = "lease_v1";
pub const REPAIR_COORDINATION_SCENARIO_REPAIR: &str = "cli_repair_multi_host_guard";
pub const REPAIR_COORDINATION_SCENARIO_FSCK: &str = "cli_fsck_repair_multi_host_guard";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairCoordinationStatus {
    NotRequired,
    Claimed,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RepairCoordinationOutput {
    pub policy: String,
    pub status: RepairCoordinationStatus,
    pub operation_id: String,
    pub scenario_id: String,
    pub coordination_file: String,
    pub local_host: String,
    /// Stable host identifier of this process, used for deterministic
    /// lease-conflict tiebreaks (derived from the host machine-id).
    pub host_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_host: Option<String>,
    /// Host identifier of the lease owner (this host when claimed, the
    /// foreign or winning host when blocked).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_host_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_process_id: Option<u32>,
    /// Lease incarnation counter from the coordination record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_version: Option<u64>,
    /// Monotonic repair-generation counter from the coordination record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repair_generation: Option<u64>,
    /// Lease time-to-live in seconds for the claimed lease.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_ttl_secs: Option<u64>,
    /// Remaining seconds before a blocking foreign lease expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_expires_in_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    pub detail: String,
}

impl RepairCoordinationOutput {
    #[must_use]
    pub const fn is_blocked(&self) -> bool {
        matches!(self.status, RepairCoordinationStatus::Blocked)
    }
}

#[derive(Debug, Clone)]
pub struct RepairCoordinationDecision {
    pub output: RepairCoordinationOutput,
    pub writes_allowed: bool,
}

fn local_host_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "unknown-host".to_owned())
}

fn sanitize_token(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "unknown".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Path of the per-image repair coordination record.
///
/// Delegates to [`RepairOwnership::record_path_for`] so the CLI and the
/// shared lease protocol always agree on the `.<image>.ffs-repair-owner.json`
/// location.
pub fn repair_coordination_record_path(image: &Path) -> PathBuf {
    RepairOwnership::record_path_for(image)
}

/// Derive a stable per-host identifier for repair-ownership tiebreaks.
///
/// Prefers the systemd / D-Bus machine-id (a stable per-host UUID), which
/// gives a deterministic lexicographic tiebreak across hosts that never
/// communicate. An explicit `FFS_REPAIR_HOST_ID` override takes precedence
/// for hosts without a machine-id or for controlled multi-host testing.
/// Falls back to a hostname-derived token so the protocol still functions
/// everywhere, and finally to a fixed sentinel.
fn repair_host_id(local_host: &str) -> String {
    let env_override = std::env::var("FFS_REPAIR_HOST_ID").ok();
    let machine_id = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .into_iter()
        .find_map(|path| std::fs::read_to_string(path).ok());
    resolve_host_id(env_override.as_deref(), machine_id.as_deref(), local_host)
}

/// Pure host-id resolution from candidate sources.
///
/// Split out from [`repair_host_id`] so the precedence rules (explicit
/// override, then a hex machine-id, then a hostname-derived token) can be
/// exercised without environment or filesystem access.
fn resolve_host_id(
    env_override: Option<&str>,
    machine_id: Option<&str>,
    local_host: &str,
) -> String {
    if let Some(value) = env_override {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    if let Some(raw) = machine_id {
        let id = raw.trim();
        if !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return id.to_ascii_lowercase();
        }
    }
    let token = sanitize_token(local_host);
    if token == "unknown" {
        "unknown-host-id".to_owned()
    } else {
        format!("host-{token}")
    }
}

fn repair_coordination_operation_id(command: &str, image: &Path, host: &str) -> String {
    let image_slug = image
        .file_name()
        .and_then(|name| name.to_str())
        .map_or_else(|| "image".to_owned(), sanitize_token);
    format!(
        "{command}-coordination-{}-{image_slug}",
        sanitize_token(host)
    )
}

#[derive(Debug)]
struct RepairCoordinationContext {
    target: &'static str,
    scenario_id: &'static str,
    command: &'static str,
    local_host: String,
    host_id: String,
    operation_id: String,
    coordination_file: PathBuf,
    coordination_file_display: String,
}

#[derive(Debug, Clone, Copy)]
struct RepairCoordinationLogRecord<'a> {
    outcome: &'static str,
    error_class: &'static str,
    owner_host: Option<&'a str>,
    event_name: &'static str,
}

impl RepairCoordinationContext {
    fn new(
        target: &'static str,
        scenario_id: &'static str,
        command: &'static str,
        path: &Path,
    ) -> Self {
        let local_host = local_host_name();
        let host_id = repair_host_id(&local_host);
        let coordination_file = repair_coordination_record_path(path);
        let operation_id = repair_coordination_operation_id(command, path, &local_host);
        let coordination_file_display = coordination_file.display().to_string();
        Self {
            target,
            scenario_id,
            command,
            local_host,
            host_id,
            operation_id,
            coordination_file,
            coordination_file_display,
        }
    }

    fn log_info(&self, record: RepairCoordinationLogRecord<'_>) {
        macro_rules! emit {
            ($log_target:literal) => {
                if let Some(owner_host) = record.owner_host {
                    info!(
                        target: $log_target,
                        operation_id = %self.operation_id,
                        scenario_id = self.scenario_id,
                        outcome = record.outcome,
                        error_class = record.error_class,
                        coordination_file = %self.coordination_file_display,
                        local_host = %self.local_host,
                        owner_host = %owner_host,
                        command = self.command,
                        event_name = record.event_name
                    );
                } else {
                    info!(
                        target: $log_target,
                        operation_id = %self.operation_id,
                        scenario_id = self.scenario_id,
                        outcome = record.outcome,
                        error_class = record.error_class,
                        coordination_file = %self.coordination_file_display,
                        local_host = %self.local_host,
                        command = self.command,
                        event_name = record.event_name
                    );
                }
            };
        }

        match self.target {
            "ffs::cli::repair" => emit!("ffs::cli::repair"),
            "ffs::cli::fsck" => emit!("ffs::cli::fsck"),
            "ffs::test" => emit!("ffs::test"),
            _ => emit!("ffs::cli::repair"),
        }
    }

    fn log_warn(&self, error_class: &'static str, owner_host: Option<&str>) {
        macro_rules! emit {
            ($log_target:literal) => {
                if let Some(owner_host) = owner_host {
                    warn!(
                        target: $log_target,
                        operation_id = %self.operation_id,
                        scenario_id = self.scenario_id,
                        outcome = "rejected",
                        error_class,
                        coordination_file = %self.coordination_file_display,
                        local_host = %self.local_host,
                        owner_host = %owner_host,
                        command = self.command,
                        event_name = "repair_coordination_rejected"
                    );
                } else {
                    warn!(
                        target: $log_target,
                        operation_id = %self.operation_id,
                        scenario_id = self.scenario_id,
                        outcome = "rejected",
                        error_class,
                        coordination_file = %self.coordination_file_display,
                        local_host = %self.local_host,
                        command = self.command,
                        event_name = "repair_coordination_rejected"
                    );
                }
            };
        }

        match self.target {
            "ffs::cli::repair" => emit!("ffs::cli::repair"),
            "ffs::cli::fsck" => emit!("ffs::cli::fsck"),
            "ffs::test" => emit!("ffs::test"),
            _ => emit!("ffs::cli::repair"),
        }
    }

    fn decision(
        &self,
        status: RepairCoordinationStatus,
        writes_allowed: bool,
        error_class: Option<&str>,
        detail: String,
        lease: LeaseFields,
    ) -> RepairCoordinationDecision {
        RepairCoordinationDecision {
            output: RepairCoordinationOutput {
                policy: REPAIR_COORDINATION_POLICY.to_owned(),
                status,
                operation_id: self.operation_id.clone(),
                scenario_id: self.scenario_id.to_owned(),
                coordination_file: self.coordination_file_display.clone(),
                local_host: self.local_host.clone(),
                host_id: self.host_id.clone(),
                owner_host: lease.owner_host,
                owner_host_id: lease.owner_host_id,
                owner_process_id: lease.owner_process_id,
                lease_version: lease.lease_version,
                repair_generation: lease.repair_generation,
                lease_ttl_secs: lease.lease_ttl_secs,
                lease_expires_in_secs: lease.lease_expires_in_secs,
                error_class: error_class.map(str::to_owned),
                detail,
            },
            writes_allowed,
        }
    }
}

/// Lease-derived fields attached to a [`RepairCoordinationOutput`].
///
/// Populated from an [`AcquireResult`]: claimed leases carry this host's
/// incarnation counters, while blocked decisions carry the foreign or
/// winning host's identity and (for live foreign leases) remaining TTL.
#[derive(Debug, Clone, Default)]
struct LeaseFields {
    owner_host: Option<String>,
    owner_host_id: Option<String>,
    owner_process_id: Option<u32>,
    lease_version: Option<u64>,
    repair_generation: Option<u64>,
    lease_ttl_secs: Option<u64>,
    lease_expires_in_secs: Option<u64>,
}

fn not_required_decision(ctx: &RepairCoordinationContext) -> RepairCoordinationDecision {
    let detail =
        "write-side repair was not requested; lease-based ownership coordination is not required"
            .to_owned();
    ctx.log_info(RepairCoordinationLogRecord {
        outcome: "not_required",
        error_class: "none",
        owner_host: None,
        event_name: "repair_coordination_not_required",
    });
    ctx.decision(
        RepairCoordinationStatus::NotRequired,
        false,
        None,
        detail,
        LeaseFields::default(),
    )
}

fn claimed_decision(
    ctx: &RepairCoordinationContext,
    guard: &OwnershipGuard,
) -> RepairCoordinationDecision {
    let record = guard.record();
    let detail = format!(
        "FrankenFS lease-based repair ownership claimed for host {} (host_id {}, pid {}); \
         lease v{} generation {} ttl {}s; coordination record {}",
        ctx.local_host,
        ctx.host_id,
        record.pid,
        record.lease_version,
        record.repair_generation,
        record.lease_ttl_secs,
        ctx.coordination_file.display(),
    );
    ctx.log_info(RepairCoordinationLogRecord {
        outcome: "applied",
        error_class: "none",
        owner_host: Some(&ctx.local_host),
        event_name: "repair_coordination_applied",
    });
    ctx.decision(
        RepairCoordinationStatus::Claimed,
        true,
        None,
        detail,
        LeaseFields {
            owner_host: Some(ctx.local_host.clone()),
            owner_host_id: Some(ctx.host_id.clone()),
            owner_process_id: Some(record.pid),
            lease_version: Some(record.lease_version),
            repair_generation: Some(record.repair_generation),
            lease_ttl_secs: Some(record.lease_ttl_secs),
            lease_expires_in_secs: None,
        },
    )
}

fn foreign_lease_decision(
    ctx: &RepairCoordinationContext,
    owner_host_id: &str,
    owner_hostname: &str,
    expires_in_secs: u64,
) -> RepairCoordinationDecision {
    let detail = format!(
        "FrankenFS blocks write-side repair on host {} (host_id {}) because coordination record {} \
         holds a live lease for host {} (host_id {}); the lease expires in {expires_in_secs}s. \
         Use read-only diagnostics, or retry after the lease expires or is handed off.",
        ctx.local_host,
        ctx.host_id,
        ctx.coordination_file.display(),
        owner_hostname,
        owner_host_id,
    );
    ctx.log_warn("foreign_lease_active", Some(owner_hostname));
    ctx.decision(
        RepairCoordinationStatus::Blocked,
        false,
        Some("foreign_lease_active"),
        detail,
        LeaseFields {
            owner_host: Some(owner_hostname.to_owned()),
            owner_host_id: Some(owner_host_id.to_owned()),
            lease_expires_in_secs: Some(expires_in_secs),
            ..LeaseFields::default()
        },
    )
}

fn conflict_lost_decision(
    ctx: &RepairCoordinationContext,
    winner_host_id: &str,
) -> RepairCoordinationDecision {
    let detail = format!(
        "FrankenFS blocks write-side repair on host {} (host_id {}) because a concurrent claim on \
         coordination record {} won the deterministic ownership tiebreak for host_id \
         {winner_host_id}. Retry after a short backoff.",
        ctx.local_host,
        ctx.host_id,
        ctx.coordination_file.display(),
    );
    ctx.log_warn("ownership_conflict_lost", None);
    ctx.decision(
        RepairCoordinationStatus::Blocked,
        false,
        Some("ownership_conflict_lost"),
        detail,
        LeaseFields {
            owner_host_id: Some(winner_host_id.to_owned()),
            ..LeaseFields::default()
        },
    )
}

fn coordination_error_decision(
    ctx: &RepairCoordinationContext,
    error: &std::io::Error,
) -> RepairCoordinationDecision {
    let (error_class, reason) = match error.kind() {
        std::io::ErrorKind::InvalidData => (
            "coordination_metadata_invalid",
            "is unreadable or holds an invalid lease record",
        ),
        std::io::ErrorKind::Interrupted => (
            "coordination_cancelled",
            "could not be evaluated because the operation was cancelled",
        ),
        _ => ("coordination_io", "could not be read or written"),
    };
    let detail = format!(
        "FrankenFS blocks write-side repair because coordination record {} {reason}: {error}. \
         Review the record before retrying.",
        ctx.coordination_file.display(),
    );
    ctx.log_warn(error_class, None);
    ctx.decision(
        RepairCoordinationStatus::Blocked,
        false,
        Some(error_class),
        detail,
        LeaseFields::default(),
    )
}

/// Gate write-side repair behind the shared lease-based ownership protocol.
///
/// Delegates the acquire decision to [`ffs_repair::ownership::RepairOwnership`]:
/// an absent or expired lease is claimed (and an expired foreign lease is
/// taken over), a live foreign lease is rejected with its remaining TTL, a
/// lost deterministic tiebreak is reported as a conflict, and an unreadable
/// record fails closed. Read-only diagnostics pass `require_write_guard=false`
/// and never touch the coordination record.
pub fn coordinate_repair_write_access(
    cx: &Cx,
    target: &'static str,
    scenario_id: &'static str,
    command: &'static str,
    path: &Path,
    require_write_guard: bool,
) -> RepairCoordinationDecision {
    let ctx = RepairCoordinationContext::new(target, scenario_id, command, path);

    if !require_write_guard {
        return not_required_decision(&ctx);
    }

    let ownership = RepairOwnership::new(ctx.host_id.clone(), ctx.local_host.clone());
    match ownership.try_acquire(cx, path) {
        Ok(AcquireResult::Acquired(guard)) => claimed_decision(&ctx, &guard),
        Ok(AcquireResult::OwnedByOther {
            owner_host_id,
            owner_hostname,
            expires_in_secs,
        }) => foreign_lease_decision(&ctx, &owner_host_id, &owner_hostname, expires_in_secs),
        Ok(AcquireResult::ConflictLost { winner_host_id }) => {
            conflict_lost_decision(&ctx, &winner_host_id)
        }
        Err(error) => coordination_error_decision(&ctx, &error),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BtrfsRepairGroupSpec {
    pub group: u32,
    pub logical_start: u64,
    pub logical_bytes: u64,
    pub physical_start_block: BlockNumber,
    pub physical_block_count: u64,
    /// Source payload blocks (total minus repair metadata).
    pub source_block_count: u32,
    /// Repair tail layout for RaptorQ symbol storage/recovery.
    pub layout: RepairGroupLayout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ext4RepairStaleness {
    Fresh,
    Stale,
    Untracked,
}

#[derive(Debug, Clone, Copy)]
pub struct Ext4RepairGroupSpec {
    pub group: u32,
    pub scrub_start_block: BlockNumber,
    pub scrub_block_count: u64,
    pub source_first_block: BlockNumber,
    pub source_block_count: u32,
    pub layout: RepairGroupLayout,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RepairExecutionStats {
    pub recovery_attempted: bool,
    pub recovery_unrecovered_blocks: u64,
    pub symbol_rebuild_attempted: bool,
    pub symbol_rebuild_groups: u64,
    pub symbol_rebuild_failed_groups: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct BtrfsSuperblockRecoverySource {
    pub offset: u64,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BtrfsMirrorRepairOutcome {
    pub attempted: bool,
    pub repaired: u32,
}

pub fn btrfs_super_mirror_offsets(image_len: u64) -> Vec<u64> {
    let mut offsets = Vec::new();
    for mirror in 0..BTRFS_SUPER_MIRROR_MAX {
        let offset = if mirror == 0 {
            BTRFS_SUPER_INFO_OFFSET as u64
        } else {
            // Backup superblocks follow the kernel layout: 64 MiB, then each
            // later mirror shifts by BTRFS_SUPER_MIRROR_SHIFT (256 GiB for mirror 2).
            let Some(shift) = BTRFS_SUPER_MIRROR_SHIFT.checked_mul(mirror - 1) else {
                continue;
            };
            let Some(candidate) = BTRFS_FIRST_BACKUP_SUPER_OFFSET.checked_shl(shift) else {
                continue;
            };
            candidate
        };
        let Some(end) =
            offset.checked_add(u64::try_from(BTRFS_SUPER_INFO_SIZE).unwrap_or(u64::MAX))
        else {
            continue;
        };
        if end <= image_len {
            offsets.push(offset);
        }
    }
    offsets
}

pub fn block_range_contains(start: BlockNumber, count: u64, target: BlockNumber) -> bool {
    if count == 0 || target.0 < start.0 {
        return false;
    }
    if count == u64::MAX {
        return true;
    }
    start.0.checked_add(count).is_none_or(|end| target.0 < end)
}

pub fn primary_btrfs_superblock_block(block_size: u32) -> BlockNumber {
    BlockNumber((BTRFS_SUPER_INFO_OFFSET as u64) / u64::from(block_size))
}

pub fn report_has_error_or_higher_for_block(report: &ScrubReport, block: BlockNumber) -> bool {
    report
        .findings
        .iter()
        .any(|finding| finding.block == block && finding.severity >= Severity::Error)
}

pub fn normalize_btrfs_superblock_for_offset(region: &mut [u8], bytenr: u64) -> Result<()> {
    if region.len() < BTRFS_SUPER_INFO_SIZE {
        bail!(
            "btrfs superblock region too short: expected {} bytes, got {}",
            BTRFS_SUPER_INFO_SIZE,
            region.len()
        );
    }
    region[BTRFS_SUPER_BYTENR_OFFSET..BTRFS_SUPER_BYTENR_OFFSET + 8]
        .copy_from_slice(&bytenr.to_le_bytes());
    let checksum = crc32c::crc32c(&region[BTRFS_SUPER_CSUM_DATA_OFFSET..BTRFS_SUPER_INFO_SIZE]);
    region[BTRFS_SUPER_CSUM_OFFSET..BTRFS_SUPER_CSUM_OFFSET + BTRFS_SUPER_CSUM_LEN]
        .copy_from_slice(&checksum.to_le_bytes());
    Ok(())
}

pub fn normalize_btrfs_superblock_as_primary(region: &mut [u8]) -> Result<()> {
    normalize_btrfs_superblock_for_offset(region, BTRFS_SUPER_INFO_OFFSET as u64)
}

pub fn append_btrfs_repair_detail(detail: &mut Option<String>, message: impl Into<String>) {
    let message = message.into();
    if let Some(existing) = detail.as_mut() {
        if !existing.contains(&message) {
            if !existing.is_empty() {
                existing.push_str("; ");
            }
            existing.push_str(&message);
        }
    } else {
        *detail = Some(message);
    }
}

#[allow(clippy::too_many_lines)]
pub fn repair_corrupt_btrfs_superblock_mirrors_from_primary(
    path: &PathBuf,
    block_size: u32,
    scrub_start: BlockNumber,
    scrub_count: u64,
    limitations: &mut Vec<String>,
) -> Result<BtrfsMirrorRepairOutcome> {
    let cx = cli_cx();
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let image_len = byte_dev.len_bytes();
    let primary_offset = BTRFS_SUPER_INFO_OFFSET as u64;
    let block_size_u64 = u64::from(block_size);

    let mut corrupt_mirror_offsets = Vec::new();
    for offset in btrfs_super_mirror_offsets(image_len)
        .into_iter()
        .filter(|offset| *offset != primary_offset)
    {
        if offset % block_size_u64 != 0 {
            limitations.push(format!(
                "cannot evaluate btrfs superblock mirror at byte offset {offset} with scrub block size {block_size}"
            ));
            continue;
        }
        let mirror_block = BlockNumber(offset / block_size_u64);
        if !block_range_contains(scrub_start, scrub_count, mirror_block) {
            continue;
        }

        let mut mirror_region = vec![0_u8; BTRFS_SUPER_INFO_SIZE];
        if let Err(error) = byte_dev.read_exact_at(&cx, ByteOffset(offset), &mut mirror_region) {
            limitations.push(format!(
                "failed to read btrfs superblock mirror at byte offset {offset} while checking repair scope: {error}"
            ));
            corrupt_mirror_offsets.push(offset);
            continue;
        }

        let mut mirror_valid = true;
        match BtrfsSuperblock::parse_superblock_region(&mirror_region) {
            Ok(parsed) => {
                if parsed.bytenr != offset {
                    mirror_valid = false;
                    limitations.push(format!(
                        "btrfs superblock mirror at byte offset {offset} reports bytenr={} and needs repair",
                        parsed.bytenr
                    ));
                }
            }
            Err(error) => {
                mirror_valid = false;
                limitations.push(format!(
                    "btrfs superblock mirror at byte offset {offset} failed structural validation and needs repair: {error}"
                ));
            }
        }
        if let Err(error) = verify_btrfs_superblock_checksum(&mirror_region) {
            mirror_valid = false;
            limitations.push(format!(
                "btrfs superblock mirror at byte offset {offset} failed checksum validation and needs repair: {error}"
            ));
        }

        if !mirror_valid {
            corrupt_mirror_offsets.push(offset);
        }
    }

    if corrupt_mirror_offsets.is_empty() {
        return Ok(BtrfsMirrorRepairOutcome::default());
    }

    let mut outcome = BtrfsMirrorRepairOutcome {
        attempted: true,
        repaired: 0,
    };
    let mut primary_region = vec![0_u8; BTRFS_SUPER_INFO_SIZE];
    if let Err(error) = byte_dev.read_exact_at(&cx, ByteOffset(primary_offset), &mut primary_region)
    {
        limitations.push(format!(
            "failed to read primary btrfs superblock while restoring mirror copies: {error}"
        ));
        return Ok(outcome);
    }

    let parsed_primary = match BtrfsSuperblock::parse_superblock_region(&primary_region) {
        Ok(parsed) => parsed,
        Err(error) => {
            limitations.push(format!(
                "failed to parse primary btrfs superblock while restoring mirror copies: {error}"
            ));
            return Ok(outcome);
        }
    };
    if parsed_primary.bytenr != primary_offset {
        limitations.push(format!(
            "primary btrfs superblock reports bytenr={} and cannot seed mirror restoration",
            parsed_primary.bytenr
        ));
        return Ok(outcome);
    }
    if let Err(error) = verify_btrfs_superblock_checksum(&primary_region) {
        limitations.push(format!(
            "primary btrfs superblock checksum is invalid; mirror restoration skipped: {error}"
        ));
        return Ok(outcome);
    }

    let mut repaired_offsets = Vec::new();
    for offset in corrupt_mirror_offsets {
        let mut mirror_region = primary_region.clone();
        if let Err(error) = normalize_btrfs_superblock_for_offset(&mut mirror_region, offset) {
            limitations.push(format!(
                "failed to retarget btrfs superblock mirror at byte offset {offset}: {error:#}"
            ));
            continue;
        }
        if let Err(error) = BtrfsSuperblock::parse_superblock_region(&mirror_region) {
            limitations.push(format!(
                "re-encoded btrfs superblock mirror at byte offset {offset} failed validation: {error}"
            ));
            continue;
        }
        if let Err(error) = verify_btrfs_superblock_checksum(&mirror_region) {
            limitations.push(format!(
                "re-encoded btrfs superblock mirror at byte offset {offset} failed checksum validation: {error}"
            ));
            continue;
        }
        match byte_dev.write_all_at(&cx, ByteOffset(offset), &mirror_region) {
            Ok(()) => repaired_offsets.push(offset),
            Err(error) => limitations.push(format!(
                "failed to write recovered btrfs superblock mirror at byte offset {offset}: {error}"
            )),
        }
    }

    if repaired_offsets.is_empty() {
        return Ok(outcome);
    }

    byte_dev
        .sync(&cx)
        .context("failed to sync image after btrfs superblock mirror recovery")?;
    outcome.repaired = u32::try_from(repaired_offsets.len()).unwrap_or(u32::MAX);
    let offsets = repaired_offsets
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    limitations.push(format!(
        "restored {} btrfs superblock mirror(s) from primary superblock at byte offset(s): {offsets}",
        outcome.repaired
    ));
    Ok(outcome)
}

pub fn recover_primary_btrfs_superblock_from_backup(
    path: &PathBuf,
    limitations: &mut Vec<String>,
) -> Result<Option<BtrfsSuperblockRecoverySource>> {
    let cx = cli_cx();
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let image_len = byte_dev.len_bytes();
    let primary_offset = BTRFS_SUPER_INFO_OFFSET as u64;

    let mut selected: Option<(Vec<u8>, BtrfsSuperblockRecoverySource)> = None;
    for offset in btrfs_super_mirror_offsets(image_len)
        .into_iter()
        .filter(|offset| *offset != primary_offset)
    {
        let mut region = vec![0_u8; BTRFS_SUPER_INFO_SIZE];
        if let Err(error) = byte_dev.read_exact_at(&cx, ByteOffset(offset), &mut region) {
            limitations.push(format!(
                "failed to read btrfs superblock mirror at byte offset {offset}: {error}"
            ));
            continue;
        }

        let parsed = match BtrfsSuperblock::parse_superblock_region(&region) {
            Ok(parsed) => parsed,
            Err(error) => {
                limitations.push(format!(
                    "btrfs superblock mirror at byte offset {offset} is structurally invalid: {error}"
                ));
                continue;
            }
        };
        if parsed.bytenr != offset {
            limitations.push(format!(
                "btrfs superblock mirror at byte offset {offset} reports bytenr={} and was skipped",
                parsed.bytenr
            ));
            continue;
        }
        if let Err(error) = verify_btrfs_superblock_checksum(&region) {
            limitations.push(format!(
                "btrfs superblock mirror at byte offset {offset} failed checksum validation: {error}"
            ));
            continue;
        }

        let source = BtrfsSuperblockRecoverySource {
            offset,
            generation: parsed.generation,
        };
        let keep_candidate = selected.as_ref().is_none_or(|(_, current)| {
            source.generation > current.generation
                || (source.generation == current.generation && source.offset < current.offset)
        });
        if keep_candidate {
            selected = Some((region, source));
        }
    }

    let Some((mut recovered_region, source)) = selected else {
        return Ok(None);
    };
    normalize_btrfs_superblock_as_primary(&mut recovered_region)?;
    BtrfsSuperblock::parse_superblock_region(&recovered_region)
        .context("recovered primary btrfs superblock failed structural validation")?;
    verify_btrfs_superblock_checksum(&recovered_region)
        .context("recovered primary btrfs superblock failed checksum validation")?;

    byte_dev
        .write_all_at(&cx, ByteOffset(primary_offset), &recovered_region)
        .context("failed to write recovered primary btrfs superblock")?;
    byte_dev
        .sync(&cx)
        .context("failed to sync image after primary btrfs superblock recovery")?;

    Ok(Some(source))
}

pub fn detect_flavor_with_optional_btrfs_bootstrap(
    cx: &Cx,
    path: &PathBuf,
    allow_bootstrap: bool,
    limitations: &mut Vec<String>,
) -> Result<(FsFlavor, Option<BtrfsSuperblockRecoverySource>)> {
    match detect_filesystem_at_path(cx, path) {
        Ok(flavor) => Ok((flavor, None)),
        Err(detect_error) => {
            if !allow_bootstrap {
                return Err(detect_error).with_context(|| {
                    format!("failed to detect ext4/btrfs metadata in {}", path.display())
                });
            }

            let source = match recover_primary_btrfs_superblock_from_backup(path, limitations) {
                Ok(Some(source)) => source,
                Ok(None) => {
                    return Err(detect_error).with_context(|| {
                        format!(
                            "failed to detect ext4/btrfs metadata in {}; bootstrap btrfs superblock \
                             recovery found no valid backup mirrors",
                            path.display()
                        )
                    });
                }
                Err(recover_error) => {
                    return Err(detect_error).with_context(|| {
                        format!(
                            "failed to detect ext4/btrfs metadata in {}; bootstrap btrfs superblock \
                             recovery failed: {recover_error:#}",
                            path.display()
                        )
                    });
                }
            };
            limitations.push(format!(
                "bootstrap restored primary btrfs superblock from backup mirror at byte offset {} \
                 (generation={})",
                source.offset, source.generation
            ));

            let flavor = detect_filesystem_at_path(cx, path).with_context(|| {
                format!(
                    "failed to detect ext4/btrfs metadata in {} after bootstrap btrfs superblock \
                     recovery",
                    path.display()
                )
            })?;
            Ok((flavor, Some(source)))
        }
    }
}

/// A contiguous physical writer needs one unambiguous chunk for its full span.
/// Matching endpoints cannot prove interior mapping or unique physical ownership.
fn btrfs_repair_range_chunk(
    group: u32,
    logical_start: u64,
    logical_bytes: u64,
    chunks: &[BtrfsChunkEntry],
) -> Result<&BtrfsChunkEntry> {
    let logical_end = logical_start
        .checked_add(logical_bytes)
        .filter(|end| *end > logical_start)
        .ok_or_else(|| anyhow::anyhow!("btrfs group {group} has an invalid logical repair span"))?;
    let mut covering = None;
    for chunk in chunks {
        let chunk_end = chunk.key.offset.checked_add(chunk.length).ok_or_else(|| {
            anyhow::anyhow!("btrfs group {group} chunk coverage has an overflowing logical range")
        })?;
        if chunk.key.offset >= logical_end || chunk_end <= logical_start {
            continue;
        }
        if covering.is_some() || chunk.key.offset > logical_start || chunk_end < logical_end {
            bail!("btrfs group {group} repair span is not covered by one unambiguous chunk");
        }
        covering = Some(chunk);
    }
    let covering = covering.ok_or_else(|| {
        anyhow::anyhow!("btrfs group {group} repair span is not covered by one unambiguous chunk")
    })?;
    let mapping = map_logical_to_physical(std::slice::from_ref(covering), logical_start)?
        .ok_or_else(|| anyhow::anyhow!("btrfs group {group} has no physical repair mapping"))?;
    let physical_end = mapping.physical.checked_add(logical_bytes).ok_or_else(|| {
        anyhow::anyhow!("btrfs group {group} has an overflowing physical repair span")
    })?;
    for chunk in chunks {
        // The contiguous writer supports only Single/DUP. Validate that shape
        // before interpreting each stripe as a full-length physical copy.
        map_logical_to_physical(std::slice::from_ref(chunk), chunk.key.offset)?
            .ok_or_else(|| anyhow::anyhow!("btrfs group {group} has an empty chunk mapping"))?;
        for (index, stripe) in chunk.stripes.iter().enumerate() {
            if stripe.devid != mapping.devid || (std::ptr::eq(chunk, covering) && index == 0) {
                continue;
            }
            let stripe_end = stripe.offset.checked_add(chunk.length).ok_or_else(|| {
                anyhow::anyhow!("btrfs group {group} has an overflowing physical chunk range")
            })?;
            if stripe.offset < physical_end && stripe_end > mapping.physical {
                bail!(
                    "btrfs group {group} physical repair span [{}, {physical_end}) aliases chunk {} stripe {index} [{}, {stripe_end}) on device {}",
                    mapping.physical,
                    chunk.key.offset,
                    stripe.offset,
                    stripe.devid
                );
            }
        }
    }
    Ok(covering)
}

pub fn build_btrfs_repair_group_spec(
    group: u32,
    logical_start: u64,
    logical_bytes: u64,
    block_size: u32,
    chunks: &[BtrfsChunkEntry],
) -> Result<BtrfsRepairGroupSpec> {
    if logical_bytes == 0 {
        bail!("btrfs block group {group} has zero logical span");
    }
    if block_size == 0 {
        bail!("btrfs block group {group} scrub block size must be nonzero");
    }
    let logical_end = logical_start
        .checked_add(logical_bytes.saturating_sub(1))
        .ok_or_else(|| anyhow::anyhow!("btrfs block group {group} logical range overflow"))?;
    let start_mapping = map_logical_to_physical(chunks, logical_start)
        .with_context(|| format!("failed to map btrfs group {group} logical start"))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "btrfs block group {group} logical start {logical_start} is not covered by any chunk"
            )
        })?;
    let end_mapping = map_logical_to_physical(chunks, logical_end)
        .with_context(|| format!("failed to map btrfs group {group} logical end"))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "btrfs block group {group} logical end {logical_end} is not covered by any chunk"
            )
        })?;
    if start_mapping.devid != end_mapping.devid {
        bail!(
            "btrfs block group {group} spans multiple devices (start devid={}, end devid={})",
            start_mapping.devid,
            end_mapping.devid
        );
    }
    let expected_end_physical = start_mapping
        .physical
        .checked_add(logical_bytes.saturating_sub(1))
        .ok_or_else(|| anyhow::anyhow!("btrfs block group {group} physical range overflow"))?;
    if end_mapping.physical != expected_end_physical {
        bail!(
            "btrfs block group {group} spans non-contiguous chunk mapping (start_physical={}, end_physical={}, expected_end={expected_end_physical})",
            start_mapping.physical,
            end_mapping.physical
        );
    }
    btrfs_repair_range_chunk(group, logical_start, logical_bytes, chunks)?;
    let block_size_u64 = u64::from(block_size);
    let start_block = start_mapping.physical / block_size_u64;
    let end_exclusive = expected_end_physical
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("btrfs block group {group} end overflow"))?;
    let end_block = end_exclusive.div_ceil(block_size_u64);
    let block_count = end_block.saturating_sub(start_block);
    if block_count == 0 {
        bail!("btrfs block group {group} maps to zero scrub blocks");
    }

    let blocks_per_group = u32::try_from(block_count).with_context(|| {
        format!("btrfs block group {group} block count does not fit u32 ({block_count})")
    })?;
    // Compute tail layout for RaptorQ repair symbols (same scheme as ext4).
    let source_and_repair_budget = if blocks_per_group > REPAIR_DESC_SLOT_COUNT + 1 {
        blocks_per_group.saturating_sub(REPAIR_DESC_SLOT_COUNT)
    } else {
        // Group too small for repair metadata — treat entire span as source.
        blocks_per_group
    };
    let desired_repair = RepairGroupDescExt::compute_repair_block_count(
        source_and_repair_budget,
        DEFAULT_REPAIR_OVERHEAD_RATIO,
    )
    .max(1);
    let repair_block_count = desired_repair
        .min(source_and_repair_budget.saturating_sub(1))
        .max(1);
    let source_block_count = source_and_repair_budget.saturating_sub(repair_block_count);
    let layout = RepairGroupLayout::new(
        GroupNumber(group),
        BlockNumber(start_block),
        blocks_per_group,
        DEFAULT_REPAIR_VALIDATION_BLOCK_COUNT,
        repair_block_count,
    )?;

    Ok(BtrfsRepairGroupSpec {
        group,
        logical_start,
        logical_bytes,
        physical_start_block: BlockNumber(start_block),
        physical_block_count: block_count,
        source_block_count,
        layout,
    })
}

pub fn discover_btrfs_repair_group_specs(
    path: &PathBuf,
    block_size: u32,
) -> Result<Vec<BtrfsRepairGroupSpec>> {
    let cx = cli_cx();
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let fs = OpenFs::from_device(&cx, Box::new(byte_dev), &OpenOptions::default())
        .with_context(|| format!("failed to open btrfs image at {}", path.display()))?;
    if !fs.is_btrfs() {
        bail!("image is not btrfs");
    }
    let chunks = fs
        .btrfs_context()
        .ok_or_else(|| anyhow::anyhow!("btrfs context is unavailable"))?
        .chunks
        .clone();

    let root_entries = fs
        .walk_btrfs_root_tree(&cx)
        .context("failed to walk btrfs root tree")?;
    let extent_root_entry = root_entries
        .iter()
        .find(|entry| {
            entry.key.objectid == BTRFS_EXTENT_TREE_OBJECTID
                && entry.key.item_type == BTRFS_ROOT_ITEM_TYPE
        })
        .ok_or_else(|| anyhow::anyhow!("failed to locate btrfs extent tree root item"))?;
    let extent_root_bytenr = parse_btrfs_root_item_bytenr(&extent_root_entry.data)
        .context("failed to parse btrfs extent tree root item")?;

    let extent_entries = fs
        .walk_btrfs_tree(&cx, extent_root_bytenr)
        .with_context(|| format!("failed to walk btrfs extent tree at {extent_root_bytenr}"))?;

    let mut specs = Vec::new();
    let mut group_index = 0_u32;
    for entry in extent_entries
        .iter()
        .filter(|entry| entry.key.item_type == BTRFS_BLOCK_GROUP_ITEM_TYPE)
    {
        // A block group's length is carried by its KEY (key.offset), never by
        // the item payload: struct btrfs_block_group_item is {used,
        // chunk_objectid, flags}. The previous payload parse read the
        // chunk_objectid slot (always 256) as a "total" fallback and silently
        // sized repair groups at 256 bytes on zero-length keys (bd-k1738).
        if entry.key.offset == 0 {
            bail!(
                "btrfs block-group key at objectid={} has zero length; extent tree is corrupt",
                entry.key.objectid
            );
        }
        let item = parse_btrfs_block_group_item(&entry.data).with_context(|| {
            format!(
                "failed to parse btrfs block-group payload for key objectid={} offset={}",
                entry.key.objectid, entry.key.offset
            )
        })?;
        if item.chunk_objectid != BTRFS_FIRST_CHUNK_TREE_OBJECTID {
            bail!(
                "btrfs block-group item at objectid={} has chunk_objectid {} (expected {BTRFS_FIRST_CHUNK_TREE_OBJECTID}); extent tree is corrupt",
                entry.key.objectid,
                item.chunk_objectid
            );
        }
        let spec = build_btrfs_repair_group_spec(
            group_index,
            entry.key.objectid,
            entry.key.offset,
            block_size,
            &chunks,
        )?;
        specs.push(spec);
        group_index = group_index.saturating_add(1);
    }

    if specs.is_empty() {
        bail!("no btrfs block groups discovered from extent tree");
    }

    Ok(specs)
}

pub fn build_ext4_repair_group_spec(
    sb: &Ext4Superblock,
    group: u32,
) -> Result<Ext4RepairGroupSpec> {
    let (scrub_start, scrub_count) = ext4_group_scrub_scope(sb, group)?;
    let blocks_per_group = u32::try_from(scrub_count).with_context(|| {
        format!("ext4 group {group} scrub span does not fit u32 blocks ({scrub_count})")
    })?;
    if blocks_per_group <= REPAIR_DESC_SLOT_COUNT + 1 {
        bail!(
            "ext4 group {group} is too small for repair tail layout (blocks_per_group={blocks_per_group})"
        );
    }

    let source_and_repair_budget = blocks_per_group.saturating_sub(REPAIR_DESC_SLOT_COUNT);
    let desired_repair = RepairGroupDescExt::compute_repair_block_count(
        source_and_repair_budget,
        DEFAULT_REPAIR_OVERHEAD_RATIO,
    )
    .max(1);
    let repair_block_count = desired_repair
        .min(source_and_repair_budget.saturating_sub(1))
        .max(1);
    let source_block_count = source_and_repair_budget.saturating_sub(repair_block_count);
    if source_block_count == 0 {
        bail!(
            "ext4 group {group} has no source payload blocks after reserving repair metadata \
             (blocks_per_group={blocks_per_group}, repair_blocks={repair_block_count})"
        );
    }

    let layout = RepairGroupLayout::new(
        GroupNumber(group),
        scrub_start,
        blocks_per_group,
        DEFAULT_REPAIR_VALIDATION_BLOCK_COUNT,
        repair_block_count,
    )?;

    Ok(Ext4RepairGroupSpec {
        group,
        scrub_start_block: scrub_start,
        scrub_block_count: scrub_count,
        source_first_block: scrub_start,
        source_block_count,
        layout,
    })
}

pub fn build_ext4_repair_group_specs(sb: &Ext4Superblock) -> Result<Vec<Ext4RepairGroupSpec>> {
    let group_count = sb.groups_count();
    if group_count > MAX_EXT4_REPAIR_GROUP_SPECS {
        bail!(
            "ext4 repair group count {group_count} exceeds supported repair scan cap {MAX_EXT4_REPAIR_GROUP_SPECS}; \
             superblock geometry is likely corrupt or outside V1 repair scope"
        );
    }

    let capacity =
        usize::try_from(group_count).context("ext4 repair group count does not fit this target")?;
    let mut specs = Vec::with_capacity(capacity);
    for group in 0..group_count {
        specs.push(build_ext4_repair_group_spec(sb, group)?);
    }
    Ok(specs)
}

pub fn probe_ext4_repair_staleness(
    path: &PathBuf,
    block_size: u32,
    specs: &[Ext4RepairGroupSpec],
) -> Result<Vec<(u32, Ext4RepairStaleness)>> {
    let cx = cli_cx();
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let block_dev = ByteBlockDevice::new(byte_dev, block_size)
        .with_context(|| format!("failed to create block device (block_size={block_size})"))?;

    let mut states = Vec::with_capacity(specs.len());
    for spec in specs {
        let storage = RepairGroupStorage::new(&block_dev, spec.layout);
        let state =
            storage
                .read_group_desc_ext(&cx)
                .map_or(Ext4RepairStaleness::Untracked, |desc| {
                    if desc.repair_generation == 0 {
                        Ext4RepairStaleness::Stale
                    } else {
                        match storage.read_repair_symbols(&cx) {
                            Ok(symbols) if symbols.is_empty() => Ext4RepairStaleness::Stale,
                            Ok(_) => Ext4RepairStaleness::Fresh,
                            Err(_) => Ext4RepairStaleness::Stale,
                        }
                    }
                });
        states.push((spec.group, state));
    }

    Ok(states)
}

pub fn probe_btrfs_repair_staleness(
    path: &PathBuf,
    block_size: u32,
    specs: &[BtrfsRepairGroupSpec],
) -> Result<Vec<(u32, Ext4RepairStaleness)>> {
    let cx = cli_cx();
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let block_dev = ByteBlockDevice::new(byte_dev, block_size)
        .with_context(|| format!("failed to create block device (block_size={block_size})"))?;

    let mut states = Vec::with_capacity(specs.len());
    for spec in specs {
        let storage = RepairGroupStorage::new(&block_dev, spec.layout);
        let state =
            storage
                .read_group_desc_ext(&cx)
                .map_or(Ext4RepairStaleness::Untracked, |desc| {
                    if desc.repair_generation == 0 {
                        Ext4RepairStaleness::Stale
                    } else {
                        match storage.read_repair_symbols(&cx) {
                            Ok(symbols) if symbols.is_empty() => Ext4RepairStaleness::Stale,
                            Ok(_) => Ext4RepairStaleness::Fresh,
                            Err(_) => Ext4RepairStaleness::Stale,
                        }
                    }
                });
        states.push((spec.group, state));
    }

    Ok(states)
}

pub fn select_ext4_repair_groups(
    flags: RepairFlags,
    ext4_clean: bool,
    all_groups: &[u32],
    staleness: &[(u32, Ext4RepairStaleness)],
) -> Vec<u32> {
    if flags.full_scrub() || flags.rebuild_symbols() {
        return all_groups.to_vec();
    }

    let stale: Vec<u32> = staleness
        .iter()
        .filter_map(|(group, state)| (*state == Ext4RepairStaleness::Stale).then_some(*group))
        .collect();
    if !stale.is_empty() {
        return stale;
    }

    let has_fresh = staleness
        .iter()
        .any(|(_, state)| *state == Ext4RepairStaleness::Fresh);
    if has_fresh || ext4_clean {
        return Vec::new();
    }

    all_groups.to_vec()
}

pub fn select_btrfs_repair_groups(
    flags: RepairFlags,
    all_groups: &[u32],
    staleness: &[(u32, Ext4RepairStaleness)],
    limitations: &mut Vec<String>,
) -> Vec<u32> {
    let selected = select_ext4_repair_groups(flags, false, all_groups, staleness);
    if selected.is_empty() {
        let stale_count = staleness
            .iter()
            .filter(|(_, state)| *state == Ext4RepairStaleness::Stale)
            .count();
        let fresh_count = staleness
            .iter()
            .filter(|(_, state)| *state == Ext4RepairStaleness::Fresh)
            .count();
        let untracked_count = staleness
            .iter()
            .filter(|(_, state)| *state == Ext4RepairStaleness::Untracked)
            .count();

        if stale_count == 0 && fresh_count > 0 {
            limitations.push(
                "stale-only scope found no stale btrfs groups; running full scrub".to_owned(),
            );
        } else if stale_count == 0 && fresh_count == 0 && untracked_count > 0 {
            limitations.push(
                "stale-only scope could not infer btrfs group staleness from on-image repair metadata; running full scrub"
                    .to_owned(),
            );
        } else {
            limitations.push(
                "stale-only scope yielded no explicit btrfs candidates; running full scrub"
                    .to_owned(),
            );
        }
        return all_groups.to_vec();
    }

    if selected.len() < all_groups.len() {
        let stale_count = staleness
            .iter()
            .filter(|(_, state)| *state == Ext4RepairStaleness::Stale)
            .count();
        let fresh_count = staleness
            .iter()
            .filter(|(_, state)| *state == Ext4RepairStaleness::Fresh)
            .count();
        let untracked_count = staleness
            .iter()
            .filter(|(_, state)| *state == Ext4RepairStaleness::Untracked)
            .count();
        limitations.push(format!(
            "stale-only scope selected {}/{} btrfs groups (stale={}, fresh={}, untracked={})",
            selected.len(),
            all_groups.len(),
            stale_count,
            fresh_count,
            untracked_count
        ));
    }

    selected
}

pub fn scrub_ext4_groups_for_repair(
    path: &PathBuf,
    flavor: &FsFlavor,
    specs: &[Ext4RepairGroupSpec],
    groups: &[u32],
    max_threads: Option<u32>,
    limitations: &mut Vec<String>,
) -> Result<ScrubReport> {
    if groups.is_empty() {
        return Ok(ScrubReport {
            findings: Vec::new(),
            blocks_scanned: 0,
            blocks_corrupt: 0,
            blocks_io_error: 0,
        });
    }

    let FsFlavor::Ext4(sb) = flavor else {
        bail!("ext4 repair helper called for non-ext4 flavor");
    };
    let block_size = sb.block_size;
    // bd-jufod: repair detects with the same validator as `ffs scrub`, built
    // once per pass from the image as it is now (the post-repair verification
    // pass calls this again and so sees the repaired descriptors).
    let validator = {
        let byte_dev = FileByteDevice::open(path)
            .with_context(|| format!("failed to open image: {}", path.display()))?;
        let block_dev = ByteBlockDevice::new(byte_dev, block_size)
            .with_context(|| format!("failed to create block device (block_size={block_size})"))?;
        offline_ext4_scrub_validator(&cli_cx(), path, &block_dev, sb)?
    };

    let mut reports = Vec::with_capacity(groups.len());
    for group in groups {
        let spec = specs
            .iter()
            .find(|spec| spec.group == *group)
            .ok_or_else(|| {
                anyhow::anyhow!("ext4 repair group {group} is not available in the computed layout")
            })?;
        let report = scrub_range_for_repair(
            path,
            &*validator,
            block_size,
            spec.scrub_start_block,
            spec.scrub_block_count,
            max_threads,
            limitations,
        )
        .with_context(|| format!("failed to scrub ext4 group {group}"))?;
        reports.push(report);
    }

    Ok(merge_scrub_reports(reports))
}

pub fn scrub_btrfs_groups_for_repair(
    path: &PathBuf,
    flavor: &FsFlavor,
    block_size: u32,
    specs: &[BtrfsRepairGroupSpec],
    groups: &[u32],
    max_threads: Option<u32>,
    limitations: &mut Vec<String>,
) -> Result<ScrubReport> {
    if groups.is_empty() {
        return Ok(ScrubReport {
            findings: Vec::new(),
            blocks_scanned: 0,
            blocks_corrupt: 0,
            blocks_io_error: 0,
        });
    }

    let spec_by_group: BTreeMap<u32, BtrfsRepairGroupSpec> = specs
        .iter()
        .copied()
        .map(|spec| (spec.group, spec))
        .collect();
    let mut reports = Vec::with_capacity(groups.len());
    for group in groups {
        let spec = spec_by_group.get(group).ok_or_else(|| {
            anyhow::anyhow!("btrfs repair group {group} is not available in the computed layout")
        })?;
        let report = scrub_range_for_repair(
            path,
            &*scrub_validator(flavor, block_size),
            block_size,
            spec.physical_start_block,
            spec.physical_block_count,
            max_threads,
            limitations,
        )
        .with_context(|| format!("failed to scrub btrfs block group {group}"))?;
        reports.push(report);
    }

    Ok(merge_scrub_reports(reports))
}

pub fn corrupt_blocks_at_error_or_higher(report: &ScrubReport) -> Vec<BlockNumber> {
    let mut blocks: Vec<BlockNumber> = report
        .findings
        .iter()
        .filter(|finding| finding.severity >= Severity::Error)
        .map(|finding| finding.block)
        .collect();
    blocks.sort_unstable_by_key(|block| block.0);
    blocks.dedup_by_key(|block| block.0);
    blocks
}

pub fn group_ext4_corrupt_blocks(
    report: &ScrubReport,
    specs: &[Ext4RepairGroupSpec],
) -> (BTreeMap<u32, Vec<BlockNumber>>, u64) {
    let mut grouped: BTreeMap<u32, Vec<BlockNumber>> = BTreeMap::new();
    let mut outside_source_ranges = 0_u64;

    for block in corrupt_blocks_at_error_or_higher(report) {
        if let Some(spec) = specs.iter().find(|spec| {
            let start = spec.source_first_block.0;
            let end = start.saturating_add(u64::from(spec.source_block_count));
            block.0 >= start && block.0 < end
        }) {
            grouped.entry(spec.group).or_default().push(block);
        } else {
            outside_source_ranges = outside_source_ranges.saturating_add(1);
        }
    }

    (grouped, outside_source_ranges)
}

pub fn recover_ext4_corrupt_blocks(
    path: &PathBuf,
    sb: &Ext4Superblock,
    specs: &[Ext4RepairGroupSpec],
    report: &ScrubReport,
    limitations: &mut Vec<String>,
) -> Result<(u64, u64, Vec<u32>)> {
    let block_size = sb.block_size;
    let cx = cli_cx();
    // bd-jufod: every decoded block must pass the image's own metadata
    // checksums before it is written. The validator is built over the image
    // as it would be after the writeback, so a repaired descriptor block and
    // the bitmaps it describes are judged together. Inode-owned blocks
    // (extent/dir/xattr) are not covered here: identifying them needs an
    // inode walk of that same view.
    let validator_over_view =
        |cx: &Cx, view: &dyn BlockDevice| -> ffs_error::Result<Box<dyn BlockValidator>> {
            Ok(Box::new(Ext4MetadataValidator::from_device(cx, view, sb)?))
        };
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let block_dev = ByteBlockDevice::new(byte_dev, block_size)
        .with_context(|| format!("failed to create block device (block_size={block_size})"))?;

    let (grouped, outside_source_ranges) = group_ext4_corrupt_blocks(report, specs);
    if outside_source_ranges > 0 {
        limitations.push(format!(
            "{outside_source_ranges} corrupt block(s) were outside ext4 source repair ranges and \
             could not be reconstructed with block symbols"
        ));
    }

    let mut recovered_blocks = 0_u64;
    let mut unrecovered_blocks = 0_u64;
    let mut repaired_groups = Vec::new();

    for (group, corrupt_blocks) in grouped {
        let spec = specs
            .iter()
            .find(|spec| spec.group == group)
            .ok_or_else(|| {
                anyhow::anyhow!("ext4 recovery group {group} missing from computed repair layout")
            })?;
        let orchestrator = GroupRecoveryOrchestrator::new(
            &block_dev,
            sb.uuid,
            spec.layout,
            spec.source_first_block,
            spec.source_block_count,
        )
        .with_context(|| format!("failed to create recovery orchestrator for group {group}"))?
        .with_decoded_view_validator(&validator_over_view);

        let outcome = orchestrator.recover_from_corrupt_blocks(&cx, &corrupt_blocks);
        let repaired = u64::try_from(outcome.repaired_blocks.len()).unwrap_or(u64::MAX);
        let corrupt = u64::try_from(corrupt_blocks.len()).unwrap_or(u64::MAX);
        let unrecovered = corrupt.saturating_sub(repaired);
        recovered_blocks = recovered_blocks.saturating_add(repaired);
        unrecovered_blocks = unrecovered_blocks.saturating_add(unrecovered);
        if repaired > 0
            && unrecovered == 0
            && outcome.evidence.outcome == RecoveryOutcome::Recovered
        {
            repaired_groups.push(group);
        }

        if outcome.evidence.outcome != RecoveryOutcome::Recovered || unrecovered > 0 {
            let reason = outcome.evidence.reason.as_deref().unwrap_or("unspecified");
            limitations.push(format!(
                "ext4 group {group} recovery outcome={:?} recovered={repaired} unrecovered={unrecovered} reason={reason}",
                outcome.evidence.outcome
            ));
        }
    }

    Ok((recovered_blocks, unrecovered_blocks, repaired_groups))
}

/// Group corrupt blocks from a scrub report into btrfs block-group buckets.
pub fn group_btrfs_corrupt_blocks(
    report: &ScrubReport,
    specs: &[BtrfsRepairGroupSpec],
) -> (BTreeMap<u32, Vec<BlockNumber>>, u64) {
    let mut grouped: BTreeMap<u32, Vec<BlockNumber>> = BTreeMap::new();
    let mut outside_source_ranges = 0_u64;

    for block in corrupt_blocks_at_error_or_higher(report) {
        if let Some(spec) = specs.iter().find(|spec| {
            let start = spec.physical_start_block.0;
            let end = start.saturating_add(u64::from(spec.source_block_count));
            block.0 >= start && block.0 < end
        }) {
            grouped.entry(spec.group).or_default().push(block);
        } else {
            outside_source_ranges = outside_source_ranges.saturating_add(1);
        }
    }

    (grouped, outside_source_ranges)
}

/// Attempt RaptorQ symbol reconstruction for corrupt btrfs blocks.
pub fn recover_btrfs_corrupt_blocks(
    path: &PathBuf,
    block_size: u32,
    fs_uuid: [u8; 16],
    specs: &[BtrfsRepairGroupSpec],
    report: &ScrubReport,
    limitations: &mut Vec<String>,
) -> Result<(u64, u64, Vec<u32>)> {
    let cx = cli_cx();
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let block_dev = ByteBlockDevice::new(byte_dev, block_size)
        .with_context(|| format!("failed to create block device (block_size={block_size})"))?;

    let (grouped, outside_source_ranges) = group_btrfs_corrupt_blocks(report, specs);
    if outside_source_ranges > 0 {
        limitations.push(format!(
            "{outside_source_ranges} corrupt block(s) were outside btrfs source repair ranges and \
             could not be reconstructed with block symbols"
        ));
    }

    let mut recovered_blocks = 0_u64;
    let mut unrecovered_blocks = 0_u64;
    let mut repaired_groups = Vec::new();

    for (group, corrupt_blocks) in grouped {
        let spec = specs
            .iter()
            .find(|spec| spec.group == group)
            .ok_or_else(|| {
                anyhow::anyhow!("btrfs recovery group {group} missing from computed repair layout")
            })?;
        let orchestrator = GroupRecoveryOrchestrator::new(
            &block_dev,
            fs_uuid,
            spec.layout,
            spec.physical_start_block,
            spec.source_block_count,
        )
        .with_context(|| {
            format!("failed to create recovery orchestrator for btrfs group {group}")
        })?;

        let outcome = orchestrator.recover_from_corrupt_blocks(&cx, &corrupt_blocks);
        let repaired = u64::try_from(outcome.repaired_blocks.len()).unwrap_or(u64::MAX);
        let corrupt = u64::try_from(corrupt_blocks.len()).unwrap_or(u64::MAX);
        let unrecovered = corrupt.saturating_sub(repaired);
        recovered_blocks = recovered_blocks.saturating_add(repaired);
        unrecovered_blocks = unrecovered_blocks.saturating_add(unrecovered);
        if repaired > 0
            && unrecovered == 0
            && outcome.evidence.outcome == RecoveryOutcome::Recovered
        {
            repaired_groups.push(group);
        }

        if outcome.evidence.outcome != RecoveryOutcome::Recovered || unrecovered > 0 {
            let reason = outcome.evidence.reason.as_deref().unwrap_or("unspecified");
            limitations.push(format!(
                "btrfs group {group} recovery outcome={:?} recovered={repaired} unrecovered={unrecovered} reason={reason}",
                outcome.evidence.outcome
            ));
        }
    }

    Ok((recovered_blocks, unrecovered_blocks, repaired_groups))
}

/// bd-plamw: open an image purely to read its allocation state. Journal
/// replay is skipped (which also skips orphan recovery), so this never
/// mutates the image.
fn open_for_repair_tail_check(cx: &Cx, path: &Path) -> Result<OpenFs> {
    let device = FileByteDevice::open_read_only(path).with_context(|| {
        format!(
            "failed to open read-only repair-tail image: {}",
            path.display()
        )
    })?;
    OpenFs::from_device(
        cx,
        Box::new(device),
        &OpenOptions {
            ext4_journal_replay_mode: ffs_core::Ext4JournalReplayMode::Skip,
            ..OpenOptions::default()
        },
    )
    .with_context(|| {
        format!(
            "failed to open image for repair-tail check: {}",
            path.display()
        )
    })
}

/// bd-plamw: the repair tail of an ext4 group, as absolute blocks
/// `[first, end)`: everything after the protected source range up to the end
/// of the group's scrub span (repair symbols plus descriptor slots).
#[must_use]
pub fn ext4_repair_tail_range(spec: &Ext4RepairGroupSpec) -> (u64, u64) {
    let first = spec
        .source_first_block
        .0
        .saturating_add(u64::from(spec.source_block_count));
    let end = spec
        .scrub_start_block
        .0
        .saturating_add(spec.scrub_block_count);
    (first, end.max(first))
}

/// bd-plamw: refuse to place repair symbols over allocated ext4 blocks.
///
/// The tail is computed arithmetically and is NOT reserved in the block
/// bitmap, so file data or metadata may already live there. Returns a
/// human-readable refusal when any tail block is allocated (or the bitmap
/// cannot be read); `Ok(())` only when the whole tail is provably free.
pub fn ext4_repair_tail_free(cx: &Cx, fs: &OpenFs, spec: &Ext4RepairGroupSpec) -> Result<()> {
    let (first, end) = ext4_repair_tail_range(spec);
    let allocated = fs
        .ext4_allocated_blocks_in_range(cx, GroupNumber(spec.group), first, end)
        .with_context(|| {
            format!(
                "cannot verify that the ext4 group {} repair tail [{first}, {end}) is free",
                spec.group
            )
        })?;
    if allocated > 0 {
        bail!(
            "ext4 group {} repair tail [{first}, {end}) overlaps {allocated} allocated block(s); \
             refusing to write repair symbols over live data (bd-plamw)",
            spec.group
        );
    }
    Ok(())
}

/// bd-plamw: btrfs counterpart of [`ext4_repair_tail_free`]. The tail is the
/// end of the chunk's span after the protected source blocks; it is checked
/// against the extent tree. Physical padding outside that logical span is
/// not covered by this proof and must never become symbol storage.
pub fn btrfs_repair_tail_free(
    cx: &Cx,
    fs: &OpenFs,
    spec: &BtrfsRepairGroupSpec,
    block_size: u32,
) -> Result<()> {
    let block_bytes = u64::from(block_size);
    let chunks = &fs
        .btrfs_context()
        .ok_or_else(|| anyhow::anyhow!("btrfs chunk map is unavailable"))?
        .chunks;
    let chunk =
        btrfs_repair_range_chunk(spec.group, spec.logical_start, spec.logical_bytes, chunks)?;
    let mapping = map_logical_to_physical(std::slice::from_ref(chunk), spec.logical_start)?
        .ok_or_else(|| anyhow::anyhow!("btrfs repair group has no physical mapping"))?;
    if block_bytes == 0
        || !spec.logical_start.is_multiple_of(block_bytes)
        || !spec.logical_bytes.is_multiple_of(block_bytes)
        || spec.physical_start_block.0.checked_mul(block_bytes) != Some(mapping.physical)
        || spec.physical_block_count.checked_mul(block_bytes) != Some(spec.logical_bytes)
    {
        bail!(
            "btrfs group {} repair blocks extend outside its proven logical coverage",
            spec.group
        );
    }
    let source_bytes = u64::from(spec.source_block_count).saturating_mul(u64::from(block_size));
    let physical_first = mapping.physical.saturating_add(source_bytes);
    let physical_end = mapping.physical.saturating_add(spec.logical_bytes);
    // Superblock stripes are excluded from the kernel allocator independently
    // of extent-tree records (Linux fs/btrfs/block-group.c exclude_super_stripes).
    for mirror in btrfs_super_mirror_offsets(fs.device_len()) {
        let stripe_end = mirror.saturating_add(ffs_btrfs::BTRFS_STRIPE_LEN);
        if physical_first < stripe_end && physical_end > mirror {
            bail!(
                "btrfs group {} physical repair tail [{physical_first}, {physical_end}) overlaps reserved superblock stripe [{mirror}, {stripe_end})",
                spec.group
            );
        }
    }
    let first = spec.logical_start.saturating_add(source_bytes);
    let end = spec.logical_start.saturating_add(spec.logical_bytes);
    if first < BTRFS_SUPER_INFO_OFFSET as u64 {
        bail!(
            "btrfs group {} logical repair tail [{first}, {end}) overlaps reserved logical header space",
            spec.group
        );
    }
    let allocated = fs
        .btrfs_allocated_bytes_in_logical_range(cx, first, end)
        .with_context(|| {
            format!(
                "cannot verify that the btrfs group {} repair tail [{first}, {end}) is free",
                spec.group
            )
        })?;
    if allocated > 0 {
        bail!(
            "btrfs group {} repair tail [{first}, {end}) overlaps {allocated} allocated byte(s); \
             refusing to write repair symbols over live extents (bd-plamw)",
            spec.group
        );
    }
    Ok(())
}

fn require_clean_repair_tail_state(fs: &OpenFs, phase: &'static str) -> Result<()> {
    if let Some(sb) = fs.ext4_superblock()
        && (!ext4_appears_clean_state(sb.state)
            || sb.last_orphan != 0
            || sb.has_incompat(ffs_ondisk::Ext4IncompatFeatures::RECOVER)
            || sb.has_ro_compat(ffs_ondisk::Ext4RoCompatFeatures::ORPHAN_PRESENT))
    {
        return Err(repair_tail_refusal(
            phase,
            "ext4",
            None,
            "pending recovery prevents a trustworthy allocation proof; recover without --rebuild-symbols first".to_owned(),
        ));
    }
    if let Some(sb) = fs.btrfs_superblock()
        && (sb.log_root != 0
            || sb.is_seeding()
            || sb.num_devices != 1
            || !fs.btrfs_device_inventory_verified())
    {
        return Err(repair_tail_refusal(
            phase,
            "btrfs",
            None,
            "repair writes require a clean, verified, non-seed single-device inventory".to_owned(),
        ));
    }
    Ok(())
}

pub fn preflight_ext4_repair_groups<'a>(
    cx: &Cx,
    fs: &OpenFs,
    specs: &'a [Ext4RepairGroupSpec],
    groups: &[u32],
    phase: &'static str,
) -> Result<Vec<&'a Ext4RepairGroupSpec>> {
    require_clean_repair_tail_state(fs, phase)?;
    let by_group: BTreeMap<_, _> = specs.iter().map(|spec| (spec.group, spec)).collect();
    groups
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|group| {
            let spec = by_group.get(&group).copied().ok_or_else(|| {
                repair_tail_refusal(
                    phase,
                    "ext4",
                    Some(group),
                    "group layout is unavailable".to_owned(),
                )
            })?;
            ext4_repair_tail_free(cx, fs, spec).map_err(|error| {
                repair_tail_refusal(phase, "ext4", Some(group), format!("{error:#}"))
            })?;
            Ok(spec)
        })
        .collect()
}

pub fn preflight_btrfs_repair_groups<'a>(
    cx: &Cx,
    fs: &OpenFs,
    specs: &'a [BtrfsRepairGroupSpec],
    groups: &[u32],
    block_size: u32,
    phase: &'static str,
) -> Result<Vec<&'a BtrfsRepairGroupSpec>> {
    require_clean_repair_tail_state(fs, phase)?;
    let by_group: BTreeMap<_, _> = specs.iter().map(|spec| (spec.group, spec)).collect();
    groups
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|group| {
            let spec = by_group.get(&group).copied().ok_or_else(|| {
                repair_tail_refusal(
                    phase,
                    "btrfs",
                    Some(group),
                    "group layout is unavailable".to_owned(),
                )
            })?;
            btrfs_repair_tail_free(cx, fs, spec, block_size).map_err(|error| {
                repair_tail_refusal(phase, "btrfs", Some(group), format!("{error:#}"))
            })?;
            Ok(spec)
        })
        .collect()
}

/// Refuse to replace repair evidence with bytes still known to be corrupt.
/// This checks the complete source range, including after partial recovery or
/// when the command's initial scrub covered only a different selected group.
fn check_rebuild_sources(
    cx: &Cx,
    device: &dyn BlockDevice,
    validator: &dyn BlockValidator,
    first: BlockNumber,
    count: u32,
) -> Result<()> {
    cx.checkpoint()
        .map_err(|_| ffs_error::FfsError::Cancelled)?;
    let report = Scrubber::new(device, validator).scrub_range(cx, first, u64::from(count))?;
    if count == 0
        || report.blocks_scanned != u64::from(count)
        || report.blocks_io_error != 0
        || report.count_at_severity(Severity::Error) != 0
    {
        bail!(
            "repair source validation refused: requested={count} scanned={} io_errors={} errors={}",
            report.blocks_scanned,
            report.blocks_io_error,
            report.count_at_severity(Severity::Error)
        );
    }
    Ok(())
}

/// Explicit regeneration may advance a pending generation, but may never use
/// that generation for recovery or erase its high-water mark by bootstrapping.
fn publish_rebuilt_symbols(
    cx: &Cx,
    device: &dyn BlockDevice,
    layout: RepairGroupLayout,
    encoded: EncodedGroup,
) -> Result<()> {
    let storage = RepairGroupStorage::new(device, layout);
    let bootstrap = RepairGroupDescExt {
        transfer_length: u64::from(encoded.source_block_count) * u64::from(encoded.symbol_size),
        symbol_size: u16::try_from(encoded.symbol_size)
            .context("repair symbol size exceeds u16")?,
        source_block_count: u16::try_from(encoded.source_block_count)
            .context("repair source block count exceeds u16")?,
        sub_blocks: 1,
        symbol_alignment: 4,
        repair_start_block: layout.repair_start_block(),
        repair_block_count: layout.repair_block_count,
        repair_generation: 0,
        checksum: 0,
    };
    let mut pristine = true;
    for block in layout.descriptor_blocks() {
        cx.checkpoint()
            .map_err(|_| ffs_error::FfsError::Cancelled)?;
        let bytes = device.read_block(cx, block)?;
        if bytes.len() != device.block_size() as usize {
            bail!("short repair descriptor read");
        }
        pristine &= bytes.as_slice().iter().all(|&byte| byte == 0);
    }
    let current = if pristine {
        bootstrap.clone()
    } else {
        storage.read_refresh_descriptor(cx)?
    };
    let next = current
        .repair_generation
        .checked_add(1)
        .context("repair generation exhausted")?;
    let mut geometry = current;
    geometry.repair_generation = 0;
    geometry.checksum = 0;
    if geometry.to_bytes() != bootstrap.to_bytes() {
        bail!("stored repair geometry differs from regenerated source geometry");
    }
    if pristine {
        storage.write_group_desc_ext(cx, &bootstrap)?;
    }
    let symbols: Vec<_> = encoded
        .repair_symbols
        .into_iter()
        .map(|symbol| (symbol.esi, symbol.data))
        .collect();
    storage.write_repair_symbols(cx, &symbols, next)?;
    Ok(())
}

/// Re-encode symbols only after the entire requested write plan is admitted.
#[allow(clippy::too_many_lines)]
pub fn rebuild_btrfs_repair_symbols(
    path: &PathBuf,
    block_size: u32,
    fs_uuid: [u8; 16],
    specs: &[BtrfsRepairGroupSpec],
    groups: &[u32],
    limitations: &mut Vec<String>,
) -> Result<(u64, u64)> {
    if groups.is_empty() {
        return Ok((0, 0));
    }

    let cx = cli_cx();
    let tail_fs = open_for_repair_tail_check(&cx, path).map_err(|error| {
        repair_tail_refusal("symbol_rebuild", "btrfs", None, format!("{error:#}"))
    })?;
    let admitted =
        preflight_btrfs_repair_groups(&cx, &tail_fs, specs, groups, block_size, "symbol_rebuild")?;
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let block_dev = ByteBlockDevice::new(byte_dev, block_size)
        .with_context(|| format!("failed to create block device (block_size={block_size})"))?;
    let validator = scrub_validator(&tail_fs.flavor, block_size);
    let mut rebuilt_groups = 0_u64;
    let mut failed_groups = 0_u64;
    for spec in admitted {
        let group = spec.group;

        if let Err(error) = check_rebuild_sources(
            &cx,
            &block_dev,
            &*validator,
            spec.physical_start_block,
            spec.source_block_count,
        ) {
            failed_groups = failed_groups.saturating_add(1);
            limitations.push(format!(
                "cannot rebuild symbols for btrfs group {group}: {error}"
            ));
            continue;
        }

        let encoded = match encode_group(
            &cx,
            &block_dev,
            &fs_uuid,
            GroupNumber(group),
            spec.physical_start_block,
            spec.source_block_count,
            spec.layout.repair_block_count,
        ) {
            Ok(encoded) => encoded,
            Err(error) => {
                failed_groups = failed_groups.saturating_add(1);
                limitations.push(format!(
                    "failed to encode repair symbols for btrfs group {group}: {error}"
                ));
                continue;
            }
        };

        match publish_rebuilt_symbols(&cx, &block_dev, spec.layout, encoded) {
            Ok(()) => {
                rebuilt_groups = rebuilt_groups.saturating_add(1);
            }
            Err(error) => {
                failed_groups = failed_groups.saturating_add(1);
                limitations.push(format!(
                    "failed to publish rebuilt symbols for btrfs group {group}: {error}"
                ));
            }
        }
    }

    Ok((rebuilt_groups, failed_groups))
}

#[allow(clippy::too_many_lines)]
pub fn rebuild_ext4_repair_symbols(
    path: &PathBuf,
    block_size: u32,
    fs_uuid: [u8; 16],
    specs: &[Ext4RepairGroupSpec],
    groups: &[u32],
    limitations: &mut Vec<String>,
) -> Result<(u64, u64)> {
    if groups.is_empty() {
        return Ok((0, 0));
    }

    let cx = cli_cx();
    let tail_fs = open_for_repair_tail_check(&cx, path).map_err(|error| {
        repair_tail_refusal("symbol_rebuild", "ext4", None, format!("{error:#}"))
    })?;
    let admitted = preflight_ext4_repair_groups(&cx, &tail_fs, specs, groups, "symbol_rebuild")?;
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let block_dev = ByteBlockDevice::new(byte_dev, block_size)
        .with_context(|| format!("failed to create block device (block_size={block_size})"))?;
    let sb = tail_fs
        .ext4_superblock()
        .context("ext4 repair rebuild requires an ext4 image")?;
    let validator = offline_ext4_scrub_validator(&cx, path, &block_dev, sb)?;
    let mut rebuilt_groups = 0_u64;
    let mut failed_groups = 0_u64;
    for spec in admitted {
        let group = spec.group;

        if let Err(error) = check_rebuild_sources(
            &cx,
            &block_dev,
            &*validator,
            spec.source_first_block,
            spec.source_block_count,
        ) {
            failed_groups = failed_groups.saturating_add(1);
            limitations.push(format!(
                "cannot rebuild symbols for ext4 group {group}: {error}"
            ));
            continue;
        }

        let encoded = match encode_group(
            &cx,
            &block_dev,
            &fs_uuid,
            GroupNumber(group),
            spec.source_first_block,
            spec.source_block_count,
            spec.layout.repair_block_count,
        ) {
            Ok(encoded) => encoded,
            Err(error) => {
                failed_groups = failed_groups.saturating_add(1);
                limitations.push(format!(
                    "failed to encode repair symbols for ext4 group {group}: {error}"
                ));
                continue;
            }
        };

        match publish_rebuilt_symbols(&cx, &block_dev, spec.layout, encoded) {
            Ok(()) => {
                rebuilt_groups = rebuilt_groups.saturating_add(1);
            }
            Err(error) => {
                failed_groups = failed_groups.saturating_add(1);
                limitations.push(format!(
                    "failed to publish rebuilt symbols for ext4 group {group}: {error}"
                ));
            }
        }
    }

    Ok((rebuilt_groups, failed_groups))
}

pub fn scrub_range_for_repair(
    path: &PathBuf,
    validator: &dyn BlockValidator,
    block_size: u32,
    start: BlockNumber,
    count: u64,
    max_threads: Option<u32>,
    limitations: &mut Vec<String>,
) -> Result<ScrubReport> {
    let seed_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let seed_block_dev = ByteBlockDevice::new(seed_dev, block_size)
        .with_context(|| format!("failed to create block device (block_size={block_size})"))?;
    let available_blocks = seed_block_dev.block_count();
    let effective_count = if start.0 >= available_blocks {
        0
    } else {
        count.min(available_blocks.saturating_sub(start.0))
    };
    if effective_count == 0 {
        return Ok(ScrubReport {
            findings: Vec::new(),
            blocks_scanned: 0,
            blocks_corrupt: 0,
            blocks_io_error: 0,
        });
    }

    let (worker_limit, capped_from) = repair_worker_limit(max_threads);
    if let Some(requested) = capped_from {
        limitations.push(format!(
            "--max-threads={requested} exceeds host parallelism; capped at {worker_limit}"
        ));
    }

    if worker_limit <= 1 || effective_count <= 1 {
        let cx = cli_cx();
        return Scrubber::new(&seed_block_dev, validator)
            .scrub_range(&cx, start, effective_count)
            .with_context(|| {
                format!(
                    "failed to scrub range starting at block {} for {} blocks",
                    start.0, effective_count
                )
            });
    }

    drop(seed_block_dev);
    let ranges = partition_scrub_range(start, effective_count, worker_limit);
    let mut reports = Vec::with_capacity(ranges.len());

    std::thread::scope(|scope| -> Result<()> {
        let mut handles = Vec::with_capacity(ranges.len());
        for (worker_idx, (range_start, range_count)) in ranges.into_iter().enumerate() {
            let path = path.clone();
            handles.push(scope.spawn(move || -> Result<ScrubReport> {
                let cx = cli_cx();
                let byte_dev = FileByteDevice::open(&path)
                    .with_context(|| format!("failed to open image: {}", path.display()))?;
                let block_dev = ByteBlockDevice::new(byte_dev, block_size).with_context(|| {
                    format!("failed to create block device (block_size={block_size})")
                })?;
                Scrubber::new(&block_dev, validator)
                    .scrub_range(&cx, range_start, range_count)
                    .with_context(|| {
                        format!(
                            "repair scrub worker {worker_idx} failed at block {} for {} blocks",
                            range_start.0, range_count
                        )
                    })
            }));
        }

        for handle in handles {
            let shard = handle
                .join()
                .map_err(|_| anyhow::anyhow!("repair scrub worker panicked"))??;
            reports.push(shard);
        }
        Ok(())
    })?;

    Ok(merge_scrub_reports(reports))
}

/// Explicit rebuild must prove its entire target set before bootstrap or journal
/// recovery can change the image. Ordinary source recovery keeps its own path;
/// its subsequent symbol refresh is preflighted by the rebuild helper.
fn preflight_explicit_rebuild(path: &PathBuf, block_group: Option<u32>) -> Result<()> {
    let phase = "before_recovery";
    let cx = cli_cx();
    let fs = open_for_repair_tail_check(&cx, path)
        .map_err(|error| repair_tail_refusal(phase, "unknown", None, format!("{error:#}")))?;
    require_clean_repair_tail_state(&fs, phase)?;
    if let Some(sb) = fs.ext4_superblock() {
        let specs = build_ext4_repair_group_specs(sb)
            .map_err(|error| repair_tail_refusal(phase, "ext4", None, format!("{error:#}")))?;
        let groups = block_group.map_or_else(
            || specs.iter().map(|spec| spec.group).collect(),
            |group| vec![group],
        );
        preflight_ext4_repair_groups(&cx, &fs, &specs, &groups, phase)?;
    } else if let Some(sb) = fs.btrfs_superblock() {
        let block_size = choose_btrfs_scrub_block_size(fs.device_len(), sb.nodesize, sb.sectorsize)
            .map_err(|error| repair_tail_refusal(phase, "btrfs", None, format!("{error:#}")))?;
        let specs = discover_btrfs_repair_group_specs(path, block_size)
            .map_err(|error| repair_tail_refusal(phase, "btrfs", None, format!("{error:#}")))?;
        // The existing btrfs explicit-rebuild path writes every discovered
        // group, even when --block-group narrows the preceding scrub.
        let groups: Vec<_> = specs.iter().map(|spec| spec.group).collect();
        if groups.is_empty() {
            return Err(repair_tail_refusal(
                phase,
                "btrfs",
                None,
                "no repair groups discovered".to_owned(),
            ));
        }
        preflight_btrfs_repair_groups(&cx, &fs, &specs, &groups, block_size, phase)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub fn build_repair_output(path: &PathBuf, options: RepairCommandOptions) -> Result<RepairOutput> {
    let flags = options.flags;
    let cx = cli_cx();
    let mut limitations = Vec::new();
    let repair_coordination = coordinate_repair_write_access(
        &cx,
        "ffs::cli::repair",
        REPAIR_COORDINATION_SCENARIO_REPAIR,
        "repair",
        path,
        !flags.verify_only(),
    );
    if repair_coordination.output.is_blocked() {
        limitations.push(repair_coordination.output.detail.clone());
    }
    let rebuild_symbols_requested = flags.rebuild_symbols() && !flags.verify_only();
    if rebuild_symbols_requested && repair_coordination.writes_allowed {
        preflight_explicit_rebuild(path, options.block_group)?;
    }
    let (flavor, bootstrap_recovery_source) = detect_flavor_with_optional_btrfs_bootstrap(
        &cx,
        path,
        !flags.verify_only() && repair_coordination.writes_allowed,
        &mut limitations,
    )
    .with_context(|| {
        if repair_coordination.output.is_blocked() {
            format!(
                "repair coordination blocked any write-side bootstrap path: {}",
                repair_coordination.output.detail
            )
        } else {
            format!("failed to detect ext4/btrfs metadata in {}", path.display())
        }
    })?;
    if flags.rebuild_symbols() && flags.verify_only() {
        limitations.push("--rebuild-symbols is ignored when --verify-only is set".to_owned());
    }

    let ext4_recovery = if flags.verify_only() || !repair_coordination.writes_allowed {
        None
    } else {
        match &flavor {
            FsFlavor::Ext4(_) => Some(run_ext4_mount_recovery(path)?),
            FsFlavor::Btrfs(_) => None,
        }
    };
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let image_len = byte_dev.len_bytes();

    let (scope, report, execution_stats) = match &flavor {
        FsFlavor::Ext4(sb) => {
            let specs = build_ext4_repair_group_specs(sb)
                .context("failed to compute ext4 repair group layout")?;
            let all_groups: Vec<u32> = specs.iter().map(|spec| spec.group).collect();
            let selected_groups = if let Some(group) = options.block_group {
                vec![group]
            } else {
                let staleness = probe_ext4_repair_staleness(path, sb.block_size, &specs)
                    .context("failed to inspect ext4 repair symbol staleness")?;
                let selection_flags = RepairFlags::empty()
                    .with_full_scrub(flags.full_scrub())
                    .with_rebuild_symbols(rebuild_symbols_requested);
                let selected = select_ext4_repair_groups(
                    selection_flags,
                    ext4_appears_clean_state(sb.state),
                    &all_groups,
                    &staleness,
                );

                if !selection_flags.full_scrub() && !selection_flags.rebuild_symbols() {
                    let stale_count = staleness
                        .iter()
                        .filter(|(_, state)| *state == Ext4RepairStaleness::Stale)
                        .count();
                    let fresh_count = staleness
                        .iter()
                        .filter(|(_, state)| *state == Ext4RepairStaleness::Fresh)
                        .count();
                    let untracked_count = staleness
                        .iter()
                        .filter(|(_, state)| *state == Ext4RepairStaleness::Untracked)
                        .count();

                    if selected.is_empty() {
                        if stale_count == 0 && fresh_count > 0 {
                            limitations.push(
                                "stale-only scope found no stale ext4 groups; scrub skipped (use --full-scrub to force)"
                                    .to_owned(),
                            );
                        } else if stale_count == 0
                            && fresh_count == 0
                            && ext4_appears_clean_state(sb.state)
                        {
                            limitations.push(
                                "stale-only scope found no tracked repair metadata and filesystem is clean; scrub skipped (use --full-scrub to force)"
                                    .to_owned(),
                            );
                        } else if stale_count == 0 && fresh_count == 0 && untracked_count > 0 {
                            limitations.push(
                                "stale-only scope could not infer group staleness from on-image repair metadata; running full scrub because filesystem is not clean"
                                    .to_owned(),
                            );
                        }
                    } else if selected.len() < all_groups.len() {
                        limitations.push(format!(
                            "stale-only scope selected {}/{} ext4 groups (stale={}, fresh={}, untracked={})",
                            selected.len(),
                            all_groups.len(),
                            stale_count,
                            fresh_count,
                            untracked_count
                        ));
                    }
                }

                if selected.is_empty() && !ext4_appears_clean_state(sb.state) {
                    limitations.push(
                        "stale-only scope yielded no explicit candidates on a non-clean filesystem; running full scrub"
                            .to_owned(),
                    );
                    all_groups
                } else {
                    selected
                }
            };

            let scope = if let Some(group) = options.block_group {
                let spec = specs
                    .iter()
                    .find(|spec| spec.group == group)
                    .ok_or_else(|| anyhow::anyhow!("ext4 block group {group} is unavailable"))?;
                RepairScopeOutput::Ext4BlockGroup {
                    group,
                    start_block: spec.scrub_start_block.0,
                    block_count: spec.scrub_block_count,
                }
            } else {
                RepairScopeOutput::Full
            };

            let selected_set: BTreeSet<u32> = selected_groups.iter().copied().collect();
            let selected_specs: Vec<Ext4RepairGroupSpec> = specs
                .iter()
                .copied()
                .filter(|spec| selected_set.contains(&spec.group))
                .collect();
            let mut report = scrub_ext4_groups_for_repair(
                path,
                &flavor,
                &specs,
                &selected_groups,
                options.max_threads,
                &mut limitations,
            )
            .context("failed to scrub ext4 image")?;

            let mut stats = RepairExecutionStats::default();
            if repair_coordination.writes_allowed
                && !selected_specs.is_empty()
                && count_blocks_at_severity_or_higher(&report, Severity::Error) > 0
            {
                let (_recovered, unrecovered, repaired_groups) = recover_ext4_corrupt_blocks(
                    path,
                    sb,
                    &selected_specs,
                    &report,
                    &mut limitations,
                )
                .context("failed to run ext4 block-symbol recovery")?;
                stats.recovery_attempted = true;
                stats.recovery_unrecovered_blocks = unrecovered;

                if !repaired_groups.is_empty() {
                    let (rebuilt, failed) = rebuild_ext4_repair_symbols(
                        path,
                        sb.block_size,
                        sb.uuid,
                        &selected_specs,
                        &repaired_groups,
                        &mut limitations,
                    )
                    .context("failed to refresh ext4 repair symbols after recovery")?;
                    stats.symbol_rebuild_attempted = true;
                    stats.symbol_rebuild_groups =
                        stats.symbol_rebuild_groups.saturating_add(rebuilt);
                    stats.symbol_rebuild_failed_groups =
                        stats.symbol_rebuild_failed_groups.saturating_add(failed);
                }
            }

            if repair_coordination.writes_allowed
                && rebuild_symbols_requested
                && !selected_specs.is_empty()
            {
                let (rebuilt, failed) = rebuild_ext4_repair_symbols(
                    path,
                    sb.block_size,
                    sb.uuid,
                    &selected_specs,
                    &selected_groups,
                    &mut limitations,
                )
                .context("failed to rebuild ext4 repair symbols")?;
                stats.symbol_rebuild_attempted = true;
                stats.symbol_rebuild_groups = stats.symbol_rebuild_groups.saturating_add(rebuilt);
                stats.symbol_rebuild_failed_groups =
                    stats.symbol_rebuild_failed_groups.saturating_add(failed);
            }

            if repair_coordination.writes_allowed
                && (stats.recovery_attempted || stats.symbol_rebuild_attempted)
            {
                report = scrub_ext4_groups_for_repair(
                    path,
                    &flavor,
                    &specs,
                    &selected_groups,
                    options.max_threads,
                    &mut limitations,
                )
                .context("failed to verify ext4 image after repair writes")?;
            }

            if stats.symbol_rebuild_failed_groups > 0 {
                limitations.push(format!(
                    "symbol re-encoding failed for {} ext4 group(s)",
                    stats.symbol_rebuild_failed_groups
                ));
            }

            (scope, report, stats)
        }
        FsFlavor::Btrfs(sb) => {
            let block_size = choose_btrfs_scrub_block_size(image_len, sb.nodesize, sb.sectorsize)
                .with_context(|| {
                    format!(
                        "failed to derive aligned btrfs scrub block size (len_bytes={image_len}, nodesize={}, sectorsize={})",
                        sb.nodesize, sb.sectorsize
                    )
                })?;
            let mut scoped_btrfs_groups = Vec::new();
            let mut scoped_btrfs_specs = Vec::new();
            let (scope, scrub_start, scrub_count) = if let Some(group) = options.block_group {
                let specs = discover_btrfs_repair_group_specs(path, block_size)
                    .context("failed to discover btrfs block groups for scoped repair")?;
                let spec = specs
                    .iter()
                    .find(|spec| spec.group == group)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "btrfs block group {group} is unavailable (valid range: 0..{})",
                            specs.len().saturating_sub(1)
                        )
                    })?;
                (
                    RepairScopeOutput::BtrfsBlockGroup {
                        group,
                        logical_start: spec.logical_start,
                        logical_bytes: spec.logical_bytes,
                        start_block: spec.physical_start_block.0,
                        block_count: spec.physical_block_count,
                    },
                    spec.physical_start_block,
                    spec.physical_block_count,
                )
            } else {
                if !flags.full_scrub() && !rebuild_symbols_requested {
                    match discover_btrfs_repair_group_specs(path, block_size) {
                        Ok(specs) if !specs.is_empty() => {
                            let all_groups: Vec<u32> =
                                specs.iter().map(|spec| spec.group).collect();
                            match probe_btrfs_repair_staleness(path, block_size, &specs) {
                                Ok(staleness) => {
                                    let selected = select_btrfs_repair_groups(
                                        RepairFlags::empty(),
                                        &all_groups,
                                        &staleness,
                                        &mut limitations,
                                    );
                                    if selected.len() < all_groups.len() {
                                        let selected_set: BTreeSet<u32> =
                                            selected.iter().copied().collect();
                                        scoped_btrfs_specs = specs
                                            .iter()
                                            .copied()
                                            .filter(|spec| selected_set.contains(&spec.group))
                                            .collect();
                                        if scoped_btrfs_specs.len() == selected.len() {
                                            scoped_btrfs_groups = selected;
                                        } else {
                                            scoped_btrfs_specs.clear();
                                            limitations.push(
                                                "stale-only btrfs group selection could not be mapped to discovered group layouts; running full scrub"
                                                    .to_owned(),
                                            );
                                        }
                                    }
                                }
                                Err(error) => {
                                    limitations.push(format!(
                                        "failed to inspect btrfs repair symbol staleness: {error:#}; running full scrub"
                                    ));
                                }
                            }
                        }
                        Ok(_) => limitations.push(
                            "no btrfs block groups discovered for stale-only selection; running full scrub"
                                .to_owned(),
                        ),
                        Err(error) => limitations.push(format!(
                            "failed to discover btrfs block groups for stale-only selection: {error:#}; running full scrub"
                        )),
                    }
                }
                (RepairScopeOutput::Full, BlockNumber(0), u64::MAX)
            };

            let mut report = if scoped_btrfs_groups.is_empty() {
                scrub_range_for_repair(
                    path,
                    &*scrub_validator(&flavor, block_size),
                    block_size,
                    scrub_start,
                    scrub_count,
                    options.max_threads,
                    &mut limitations,
                )
                .context("failed to scrub btrfs image")?
            } else {
                scrub_btrfs_groups_for_repair(
                    path,
                    &flavor,
                    block_size,
                    &scoped_btrfs_specs,
                    &scoped_btrfs_groups,
                    options.max_threads,
                    &mut limitations,
                )
                .context("failed to scrub selected btrfs block groups")?
            };

            let mut stats = RepairExecutionStats {
                recovery_attempted: bootstrap_recovery_source.is_some(),
                ..RepairExecutionStats::default()
            };
            let mut verify_after_repair_writes = false;
            let primary_superblock = primary_btrfs_superblock_block(block_size);
            let superblock_in_scope = if scoped_btrfs_specs.is_empty() {
                block_range_contains(scrub_start, scrub_count, primary_superblock)
            } else {
                scoped_btrfs_specs.iter().any(|spec| {
                    block_range_contains(
                        spec.physical_start_block,
                        spec.physical_block_count,
                        primary_superblock,
                    )
                })
            };
            if repair_coordination.writes_allowed
                && superblock_in_scope
                && report_has_error_or_higher_for_block(&report, primary_superblock)
            {
                stats.recovery_attempted = true;
                match recover_primary_btrfs_superblock_from_backup(path, &mut limitations) {
                    Ok(Some(source)) => {
                        verify_after_repair_writes = true;
                        limitations.push(format!(
                            "restored primary btrfs superblock from backup mirror at byte offset {} (generation={})",
                            source.offset, source.generation
                        ));
                    }
                    Ok(None) => {
                        limitations.push(
                            "btrfs superblock corruption detected, but no valid backup superblock mirror was available for restoration"
                                .to_owned(),
                        );
                    }
                    Err(error) => {
                        limitations.push(format!(
                            "btrfs superblock recovery attempt failed: {error:#}"
                        ));
                    }
                }
            }

            if repair_coordination.writes_allowed && superblock_in_scope {
                let (mirror_scope_start, mirror_scope_count) = if scoped_btrfs_specs.is_empty() {
                    (scrub_start, scrub_count)
                } else {
                    (primary_superblock, 1)
                };
                match repair_corrupt_btrfs_superblock_mirrors_from_primary(
                    path,
                    block_size,
                    mirror_scope_start,
                    mirror_scope_count,
                    &mut limitations,
                ) {
                    Ok(mirror_outcome) => {
                        if mirror_outcome.attempted {
                            stats.recovery_attempted = true;
                            if mirror_outcome.repaired > 0 {
                                verify_after_repair_writes = true;
                            }
                        }
                    }
                    Err(error) => {
                        stats.recovery_attempted = true;
                        limitations.push(format!(
                            "btrfs superblock mirror recovery attempt failed: {error:#}"
                        ));
                    }
                }
            }

            // Attempt RaptorQ block-symbol recovery for non-superblock corruption.
            let mut btrfs_repaired_groups: Vec<u32> = Vec::new();
            let mut btrfs_specs_for_rebuild: Vec<BtrfsRepairGroupSpec> = Vec::new();
            if repair_coordination.writes_allowed
                && count_blocks_at_severity_or_higher(&report, Severity::Error) > 0
            {
                match discover_btrfs_repair_group_specs(path, block_size) {
                    Ok(btrfs_specs) if !btrfs_specs.is_empty() => {
                        btrfs_specs_for_rebuild.clone_from(&btrfs_specs);
                        match recover_btrfs_corrupt_blocks(
                            path,
                            block_size,
                            sb.fsid,
                            &btrfs_specs,
                            &report,
                            &mut limitations,
                        ) {
                            Ok((recovered, unrecovered, repaired_groups)) => {
                                stats.recovery_attempted = true;
                                stats.recovery_unrecovered_blocks = unrecovered;
                                btrfs_repaired_groups = repaired_groups;
                                if recovered > 0 {
                                    verify_after_repair_writes = true;
                                }
                            }
                            Err(error) => {
                                stats.recovery_attempted = true;
                                limitations.push(format!(
                                    "btrfs block-symbol recovery attempt failed: {error:#}"
                                ));
                            }
                        }
                    }
                    Ok(_) => {
                        limitations.push(
                            "no btrfs block groups discovered; block-symbol recovery skipped"
                                .to_owned(),
                        );
                    }
                    Err(error) => {
                        limitations.push(format!(
                            "failed to discover btrfs repair group layout: {error:#}"
                        ));
                    }
                }
            }

            // Rebuild repair symbols for repaired groups or on explicit request.
            if repair_coordination.writes_allowed {
                let rebuild_groups = if rebuild_symbols_requested {
                    // --rebuild-symbols: discover all groups and rebuild.
                    if btrfs_specs_for_rebuild.is_empty() {
                        match discover_btrfs_repair_group_specs(path, block_size) {
                            Ok(specs) => btrfs_specs_for_rebuild = specs,
                            Err(error) => {
                                limitations.push(format!(
                                    "failed to discover btrfs repair groups: {error:#}"
                                ));
                            }
                        }
                    }
                    btrfs_specs_for_rebuild
                        .iter()
                        .map(|spec| spec.group)
                        .collect::<Vec<_>>()
                } else {
                    btrfs_repaired_groups
                };
                if !rebuild_groups.is_empty() {
                    stats.symbol_rebuild_attempted = true;
                    match rebuild_btrfs_repair_symbols(
                        path,
                        block_size,
                        sb.fsid,
                        &btrfs_specs_for_rebuild,
                        &rebuild_groups,
                        &mut limitations,
                    ) {
                        Ok((rebuilt, failed)) => {
                            stats.symbol_rebuild_groups = rebuilt;
                            stats.symbol_rebuild_failed_groups = failed;
                            if rebuilt > 0 {
                                verify_after_repair_writes = true;
                            }
                        }
                        Err(error) => {
                            stats.symbol_rebuild_failed_groups =
                                u64::try_from(rebuild_groups.len()).unwrap_or(u64::MAX);
                            limitations
                                .push(format!("btrfs symbol rebuild attempt failed: {error:#}"));
                        }
                    }
                }
            }

            if repair_coordination.writes_allowed && verify_after_repair_writes {
                report = if scoped_btrfs_groups.is_empty() {
                    scrub_range_for_repair(
                        path,
                        &*scrub_validator(&flavor, block_size),
                        block_size,
                        scrub_start,
                        scrub_count,
                        options.max_threads,
                        &mut limitations,
                    )
                    .context("failed to verify btrfs image after repairs")?
                } else {
                    scrub_btrfs_groups_for_repair(
                        path,
                        &flavor,
                        block_size,
                        &scoped_btrfs_specs,
                        &scoped_btrfs_groups,
                        options.max_threads,
                        &mut limitations,
                    )
                    .context("failed to verify selected btrfs block groups after repairs")?
                };
            }

            (scope, report, stats)
        }
    };
    let scrub = repair_scrub_from_report(&report);
    let action = if flags.verify_only() {
        RepairActionOutput::VerifyOnly
    } else if repair_coordination.output.is_blocked() {
        RepairActionOutput::RepairBlocked
    } else if ext4_recovery.is_some()
        || execution_stats.recovery_attempted
        || execution_stats.symbol_rebuild_attempted
    {
        RepairActionOutput::RepairRequested
    } else if scrub.error_or_higher > 0 {
        limitations.push(
            "repair found actionable corruption, but no write-side workflow is available for the detected corruption class"
                .to_owned(),
        );
        RepairActionOutput::RepairRequested
    } else {
        RepairActionOutput::NoCorruptionDetected
    };

    if execution_stats.recovery_unrecovered_blocks > 0 {
        limitations.push(format!(
            "{} corrupt block(s) remained unrecovered after block-symbol reconstruction attempts",
            execution_stats.recovery_unrecovered_blocks
        ));
    }

    let exit_code = if repair_coordination.output.is_blocked() {
        2
    } else {
        i32::from(
            scrub.error_or_higher > 0
                || execution_stats.recovery_unrecovered_blocks > 0
                || execution_stats.symbol_rebuild_failed_groups > 0,
        )
    };

    Ok(RepairOutput {
        filesystem: filesystem_name(&flavor).to_owned(),
        scope,
        action,
        scrub,
        repair_coordination: repair_coordination.output,
        ext4_recovery,
        exit_code,
        limitations,
    })
}

pub fn repair_scrub_from_report(report: &ScrubReport) -> RepairScrubOutput {
    RepairScrubOutput {
        scanned: report.blocks_scanned,
        corrupt: report.blocks_corrupt,
        error_or_higher: count_blocks_at_severity_or_higher(report, Severity::Error),
        io_error: report.blocks_io_error,
    }
}

pub fn print_repair_output(json: bool, output: &RepairOutput) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(output).context("serialize repair output")?
        );
        return Ok(());
    }

    println!("FrankenFS Repair");
    println!("filesystem: {}", output.filesystem);
    match &output.scope {
        RepairScopeOutput::Full => println!("scope: full"),
        RepairScopeOutput::Ext4BlockGroup {
            group,
            start_block,
            block_count,
        } => {
            println!(
                "scope: ext4 group {} (blocks {}..{})",
                group,
                start_block,
                start_block.saturating_add(*block_count).saturating_sub(1)
            );
        }
        RepairScopeOutput::BtrfsBlockGroup {
            group,
            logical_start,
            logical_bytes,
            start_block,
            block_count,
        } => {
            println!(
                "scope: btrfs group {} (logical {}..{}, physical blocks {}..{})",
                group,
                logical_start,
                logical_start
                    .saturating_add(*logical_bytes)
                    .saturating_sub(1),
                start_block,
                start_block.saturating_add(*block_count).saturating_sub(1)
            );
        }
    }
    println!("action: {:?}", output.action);
    println!(
        "scrub: scanned={} corrupt={} error_or_higher={} io_errors={}",
        output.scrub.scanned,
        output.scrub.corrupt,
        output.scrub.error_or_higher,
        output.scrub.io_error
    );
    if let Some(recovery) = &output.ext4_recovery {
        println!("ext4_recovery: {}", ext4_recovery_detail(recovery));
    }
    println!(
        "repair_coordination: status={:?} policy={} operation_id={} scenario_id={}",
        output.repair_coordination.status,
        output.repair_coordination.policy,
        output.repair_coordination.operation_id,
        output.repair_coordination.scenario_id
    );
    println!(
        "repair_coordination_detail: {} (coordination_file={}, local_host={}, host_id={})",
        output.repair_coordination.detail,
        output.repair_coordination.coordination_file,
        output.repair_coordination.local_host,
        output.repair_coordination.host_id
    );
    if let Some(owner_host) = &output.repair_coordination.owner_host {
        println!("repair_coordination_owner_host: {owner_host}");
    }
    if let Some(owner_host_id) = &output.repair_coordination.owner_host_id {
        println!("repair_coordination_owner_host_id: {owner_host_id}");
    }
    if let Some(owner_process_id) = output.repair_coordination.owner_process_id {
        println!("repair_coordination_owner_process_id: {owner_process_id}");
    }
    if let Some(lease_version) = output.repair_coordination.lease_version {
        println!("repair_coordination_lease_version: {lease_version}");
    }
    if let Some(repair_generation) = output.repair_coordination.repair_generation {
        println!("repair_coordination_repair_generation: {repair_generation}");
    }
    if let Some(lease_ttl_secs) = output.repair_coordination.lease_ttl_secs {
        println!("repair_coordination_lease_ttl_secs: {lease_ttl_secs}");
    }
    if let Some(expires_in) = output.repair_coordination.lease_expires_in_secs {
        println!("repair_coordination_lease_expires_in_secs: {expires_in}");
    }
    if let Some(error_class) = &output.repair_coordination.error_class {
        println!("repair_coordination_error_class: {error_class}");
    }
    println!("exit_code: {}", output.exit_code);
    if !output.limitations.is_empty() {
        println!("limitations:");
        for limitation in &output.limitations {
            println!("  - {limitation}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod coordination_tests {
    use super::*;
    use ffs_repair::ownership::CoordinationRecord;

    #[test]
    fn native_codec_memory_conversion_is_checked_before_image_access() {
        assert_eq!(native_codec_working_bytes(4096).unwrap(), 4_294_967_296);
        let maximum = u64::MAX / (1024 * 1024);
        assert_eq!(
            native_codec_working_bytes(maximum).unwrap(),
            maximum * (1024 * 1024)
        );
        assert!(native_codec_working_bytes(0).is_err());
        assert!(native_codec_working_bytes(maximum + 1).is_err());
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.img");
        let output = directory.path().join("output.bin");
        for check in [false, true] {
            let error = build_native_encode_output(&missing, check, u64::MAX).unwrap_err();
            assert!(error.to_string().contains("overflows bytes"));
        }
        let error =
            build_native_recover_output(&missing, BlockNumber(0), &output, u64::MAX).unwrap_err();
        assert!(error.to_string().contains("overflows bytes"));
        assert!(!missing.exists());
        assert!(!output.exists());
    }

    #[test]
    fn native_codec_commands_refuse_locked_and_invalid_images_without_output() {
        let directory = tempfile::tempdir().unwrap();
        let image = tempfile::NamedTempFile::new().unwrap();
        let output = directory.path().join("output.bin");
        let bytes = vec![0xA5; 128 * 1024];
        std::fs::write(image.path(), &bytes).unwrap();
        image.as_file().try_lock().unwrap();
        for check in [false, true] {
            let error = build_native_encode_output(image.path(), check, 4096).unwrap_err();
            assert!(error.chain().any(|cause| matches!(
                cause.downcast_ref::<std::fs::TryLockError>(),
                Some(std::fs::TryLockError::WouldBlock)
            )));
        }
        let error =
            build_native_recover_output(image.path(), BlockNumber(1), &output, 4096).unwrap_err();
        assert!(error.chain().any(|cause| matches!(
            cause.downcast_ref::<std::fs::TryLockError>(),
            Some(std::fs::TryLockError::WouldBlock)
        )));
        assert!(!output.exists());
        assert_eq!(std::fs::read(image.path()).unwrap(), bytes);
        image.as_file().unlock().unwrap();
        for check in [false, true] {
            let error = build_native_encode_output(image.path(), check, 4096).unwrap_err();
            assert!(format!("{error:#}").contains("not a recognized ext4 or btrfs filesystem"));
        }
        let error =
            build_native_recover_output(image.path(), BlockNumber(1), &output, 4096).unwrap_err();
        assert!(format!("{error:#}").contains("not a recognized ext4 or btrfs filesystem"));
        assert_eq!(std::fs::read(image.path()).unwrap(), bytes);
        assert!(!output.exists());
        let (_device, _lock) = lock_native_prepare_image(image.path(), false).unwrap();
    }

    #[test]
    fn native_reconstruction_output_is_exact_exclusive_and_cancel_safe() {
        let cx = Cx::for_testing();
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("block.bin");
        // This exercises output file I/O only; it is not decoder evidence.
        let bytes = [0_u8, 1, 255, 42, 0, 127];
        write_native_reconstruction(&cx, &output, &bytes).unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), bytes);
        let error = write_native_reconstruction(&cx, &output, b"overwrite").unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        let alias = directory.path().join("alias.bin");
        std::os::unix::fs::symlink(&output, &alias).unwrap();
        assert!(write_native_reconstruction(&cx, &alias, b"overwrite").is_err());
        assert_eq!(std::fs::read(&output).unwrap(), bytes);
        let cancelled = directory.path().join("cancelled.bin");
        cx.set_cancel_requested(true);
        let error = write_native_reconstruction(&cx, &cancelled, &bytes).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ffs_error::FfsError>(),
            Some(ffs_error::FfsError::Cancelled)
        ));
        assert!(!cancelled.exists());
        assert_eq!(std::fs::read(&output).unwrap(), bytes);
    }

    #[test]
    fn native_prepare_check_holds_shared_lock_and_read_only_descriptor() {
        use std::os::unix::fs::FileExt;

        let image = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(image.path(), b"unchanged image").unwrap();
        let (device, lock) = lock_native_prepare_image(image.path(), true).unwrap();
        assert_eq!(
            device.file().write_at(b"X", 0).unwrap_err().raw_os_error(),
            Some(libc::EBADF),
            "check must use an actual O_RDONLY descriptor"
        );
        let (other_device, other_lock) = lock_native_prepare_image(image.path(), true).unwrap();
        assert!(lock_native_prepare_image(image.path(), false).is_err());
        drop(device);
        drop(lock);
        assert!(lock_native_prepare_image(image.path(), false).is_err());
        drop(other_device);
        drop(other_lock);
        let (_device, _lock) = lock_native_prepare_image(image.path(), false).unwrap();
        assert_eq!(std::fs::read(image.path()).unwrap(), b"unchanged image");
    }

    #[test]
    fn native_prepare_exclusive_lock_survives_consumed_device_and_releases_explicitly() {
        let image = tempfile::NamedTempFile::new().unwrap();
        let (device, lock) = lock_native_prepare_image(image.path(), false).unwrap();
        let inherited = device.file().try_clone().unwrap();
        drop(device);
        assert!(lock_native_prepare_image(image.path(), true).is_err());
        assert!(lock_native_prepare_image(image.path(), false).is_err());
        drop(lock);
        let (_device, _lock) = lock_native_prepare_image(image.path(), false).unwrap();
        // An inherited open-file description must not extend the lock lifetime.
        drop(inherited);
    }

    #[test]
    fn native_prepare_refuses_nonregular_and_invalid_images_without_writes_or_lock_leaks() {
        let directory = tempfile::tempdir().unwrap();
        for check in [false, true] {
            let error = build_native_prepare_output(directory.path(), 500, check).unwrap_err();
            assert!(error.to_string().contains("regular image file"));
            let error = build_native_validate_output(directory.path(), !check).unwrap_err();
            assert!(error.to_string().contains("regular image file"));
        }
        let image = tempfile::NamedTempFile::new().unwrap();
        let bytes = vec![0xA5; 128 * 1024];
        std::fs::write(image.path(), &bytes).unwrap();
        for check in [false, true] {
            let error = build_native_prepare_output(image.path(), 500, check).unwrap_err();
            assert!(
                format!("{error:#}").contains("not a recognized ext4 or btrfs filesystem"),
                "invalid image must fail format admission: {error:#}"
            );
            assert_eq!(std::fs::read(image.path()).unwrap(), bytes);
            let error = build_native_validate_output(image.path(), !check).unwrap_err();
            assert!(format!("{error:#}").contains("not a recognized ext4 or btrfs filesystem"));
            assert_eq!(std::fs::read(image.path()).unwrap(), bytes);
            let (_device, _lock) = lock_native_prepare_image(image.path(), false).unwrap();
        }
    }

    fn repair_rebuild_fixture() -> (PathBuf, ByteBlockDevice<FileByteDevice>, RepairGroupLayout) {
        let dir = tempfile::tempdir().unwrap().keep();
        let path = dir.join("repair-blocks.img");
        let mut bytes = vec![0; 16 * 512];
        for (index, byte) in bytes[..4 * 512].iter_mut().enumerate() {
            *byte = u8::try_from(index % 251).unwrap();
        }
        std::fs::write(&path, bytes).unwrap();
        let device = ByteBlockDevice::new(FileByteDevice::open(&path).unwrap(), 512).unwrap();
        let layout = RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 16, 0, 2).unwrap();
        (path, device, layout)
    }

    fn repair_rebuild_encoding(cx: &Cx, device: &dyn BlockDevice) -> EncodedGroup {
        encode_group(cx, device, &[7; 16], GroupNumber(0), BlockNumber(0), 4, 2).unwrap()
    }

    struct InterruptedParityWrite<'a> {
        device: &'a dyn BlockDevice,
        first_parity: BlockNumber,
        fail_read: Option<BlockNumber>,
    }

    impl BlockDevice for InterruptedParityWrite<'_> {
        fn read_block(
            &self,
            cx: &Cx,
            block: BlockNumber,
        ) -> ffs_error::Result<ffs_block::BlockBuf> {
            if self.fail_read == Some(block) {
                return Err(ffs_error::FfsError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "planted descriptor read denial",
                )));
            }
            self.device.read_block(cx, block)
        }

        fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> ffs_error::Result<()> {
            if block == self.first_parity {
                return Err(ffs_error::FfsError::Io(std::io::Error::other(
                    "planted interruption after durable pending descriptors",
                )));
            }
            self.device.write_block(cx, block, data)
        }

        fn block_size(&self) -> u32 {
            self.device.block_size()
        }

        fn block_count(&self) -> u64 {
            self.device.block_count()
        }

        fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
            self.device.sync(cx)
        }
    }

    #[test]
    fn repair_rebuild_resumes_durable_pending_generation_without_source_writes() {
        let (path, device, layout) = repair_rebuild_fixture();
        let cx = cli_cx();
        let original = std::fs::read(&path).unwrap();
        publish_rebuilt_symbols(&cx, &device, layout, repair_rebuild_encoding(&cx, &device))
            .unwrap();
        let encoded = repair_rebuild_encoding(&cx, &device);
        let expected: Vec<_> = encoded
            .repair_symbols
            .into_iter()
            .map(|symbol| (symbol.esi, symbol.data))
            .collect();
        let interrupted = InterruptedParityWrite {
            device: &device,
            first_parity: layout.repair_start_block(),
            fail_read: None,
        };
        let error = RepairGroupStorage::new(&interrupted, layout)
            .write_repair_symbols(&cx, &expected, 7)
            .unwrap_err();
        assert!(error.to_string().contains("planted interruption"));
        // Reopen the real backing file: the fence must survive process-local state.
        let reopened = ByteBlockDevice::new(FileByteDevice::open(&path).unwrap(), 512).unwrap();
        let storage = RepairGroupStorage::new(&reopened, layout);
        assert_eq!(
            storage
                .read_refresh_descriptor(&cx)
                .unwrap()
                .repair_generation,
            7
        );
        assert!(storage.read_group_desc_ext(&cx).is_err());
        assert!(storage.read_repair_symbols(&cx).is_err());
        publish_rebuilt_symbols(
            &cx,
            &reopened,
            layout,
            repair_rebuild_encoding(&cx, &reopened),
        )
        .unwrap();
        assert_eq!(
            storage.read_group_desc_ext(&cx).unwrap().repair_generation,
            8
        );
        assert_eq!(storage.read_repair_symbols(&cx).unwrap(), expected);
        assert_eq!(
            &std::fs::read(path).unwrap()[..4 * 512],
            &original[..4 * 512]
        );
    }

    #[test]
    fn repair_rebuild_refuses_ambiguous_corrupt_and_exhausted_descriptors_without_writes() {
        for case in ["ambiguous", "corrupt", "exhausted", "geometry"] {
            let (path, device, layout) = repair_rebuild_fixture();
            let cx = cli_cx();
            publish_rebuilt_symbols(&cx, &device, layout, repair_rebuild_encoding(&cx, &device))
                .unwrap();
            let storage = RepairGroupStorage::new(&device, layout);
            let mut descriptor = storage.read_refresh_descriptor(&cx).unwrap();
            match case {
                "ambiguous" => {
                    descriptor.symbol_alignment = 8;
                    let mut bytes = vec![0; 512];
                    bytes[..RepairGroupDescExt::SIZE].copy_from_slice(&descriptor.to_bytes());
                    device
                        .write_block(&cx, layout.descriptor_blocks()[0], &bytes)
                        .unwrap();
                }
                "corrupt" => {
                    for block in layout.descriptor_blocks() {
                        device.write_block(&cx, block, &[0xA5; 512]).unwrap();
                    }
                }
                "exhausted" => {
                    descriptor.repair_generation = u64::MAX;
                    storage.write_group_desc_ext(&cx, &descriptor).unwrap();
                }
                "geometry" => {
                    descriptor.repair_generation = 2;
                    descriptor.symbol_alignment = 8;
                    storage.write_group_desc_ext(&cx, &descriptor).unwrap();
                }
                _ => unreachable!(),
            }
            device.sync(&cx).unwrap();
            let before = std::fs::read(&path).unwrap();
            let error = publish_rebuilt_symbols(
                &cx,
                &device,
                layout,
                repair_rebuild_encoding(&cx, &device),
            )
            .unwrap_err();
            let expected = match case {
                "ambiguous" => "ambiguous descriptors",
                "corrupt" => "no committed raw repair descriptor",
                "exhausted" => "generation exhausted",
                _ => "geometry differs",
            };
            assert!(error.to_string().contains(expected), "{case}: {error:#}");
            assert_eq!(std::fs::read(path).unwrap(), before, "{case}");
        }
    }

    #[test]
    fn repair_rebuild_rejects_incomplete_or_corrupt_source_coverage() {
        let (path, _, _) = repair_rebuild_fixture();
        let device = ByteBlockDevice::new(FileByteDevice::open(&path).unwrap(), 1024).unwrap();
        let cx = cli_cx();
        let validator = ffs_repair::scrub::Ext4SuperblockValidator::new(1024);
        // Block 1 contains the ext4 superblock location but no valid superblock.
        assert!(check_rebuild_sources(&cx, &device, &validator, BlockNumber(1), 1).is_err());
        assert!(check_rebuild_sources(&cx, &device, &validator, BlockNumber(7), 2).is_err());
        assert!(check_rebuild_sources(&cx, &device, &validator, BlockNumber(0), 0).is_err());
        check_rebuild_sources(&cx, &device, &validator, BlockNumber(0), 1).unwrap();
    }

    #[test]
    fn repair_rebuild_preserves_descriptor_io_and_cancellation_errors() {
        let (path, device, layout) = repair_rebuild_fixture();
        let cx = cli_cx();
        let before = std::fs::read(&path).unwrap();
        let denied = InterruptedParityWrite {
            device: &device,
            first_parity: layout.repair_start_block(),
            fail_read: Some(layout.descriptor_blocks()[1]),
        };
        let error =
            publish_rebuilt_symbols(&cx, &denied, layout, repair_rebuild_encoding(&cx, &device))
                .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ffs_error::FfsError>(),
            Some(ffs_error::FfsError::Io(error))
                if error.kind() == std::io::ErrorKind::PermissionDenied
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let encoded = repair_rebuild_encoding(&cx, &device);
        cx.set_cancel_requested(true);
        let error = publish_rebuilt_symbols(&cx, &device, layout, encoded).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ffs_error::FfsError>(),
            Some(ffs_error::FfsError::Cancelled)
        ));
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    /// Create a unique temporary directory and return a fake image path inside
    /// it. The image file itself is not created; coordination only needs the
    /// parent directory to exist for the adjacent record file.
    fn temp_image_path() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ffs-cli-coord-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir.join("image.ext4")
    }

    fn cleanup(image: &Path) {
        if let Some(parent) = image.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    fn foreign_record(host_id: &str, hostname: &str, expired: bool) -> CoordinationRecord {
        let mut record = CoordinationRecord {
            version: 1,
            host_id: host_id.to_owned(),
            hostname: hostname.to_owned(),
            pid: 999_001,
            claimed_at: "2020-01-01T00:00:00Z".to_owned(),
            lease_ttl_secs: if expired { 1 } else { 300 },
            lease_version: 4,
            repair_generation: 7,
            groups_owned: Vec::new(),
        };
        if !expired {
            // Re-stamp claimed_at to now so the lease is live.
            record.renew();
        }
        record
    }

    fn write_record(image: &Path, record: &CoordinationRecord) {
        let path = repair_coordination_record_path(image);
        std::fs::write(
            &path,
            serde_json::to_string_pretty(record).expect("serialize"),
        )
        .expect("write coordination record");
    }

    #[test]
    fn build_btrfs_repair_group_spec_rejects_invalid_inputs() {
        // Zero logical span.
        assert!(build_btrfs_repair_group_spec(0, 1000, 0, 4096, &[]).is_err());
        // Zero scrub block size.
        assert!(build_btrfs_repair_group_spec(0, 1000, 4096, 0, &[]).is_err());
        // Logical range overflow (start + bytes - 1 overflows u64).
        assert!(build_btrfs_repair_group_spec(0, u64::MAX, u64::MAX, 4096, &[]).is_err());
        // A logical start not covered by any chunk is rejected.
        assert!(build_btrfs_repair_group_spec(0, 1000, 4096, 4096, &[]).is_err());
    }

    #[test]
    fn merge_scrub_reports_sums_counters_and_concatenates_findings() {
        use ffs_repair::scrub::{CorruptionKind, ScrubFinding};
        let finding = |block: u64| ScrubFinding {
            block: BlockNumber(block),
            kind: CorruptionKind::ChecksumMismatch,
            severity: Severity::Error,
            detail: String::new(),
        };

        // Empty input yields a zeroed report.
        let empty = merge_scrub_reports(Vec::new());
        assert_eq!(empty.blocks_scanned, 0);
        assert_eq!(empty.blocks_corrupt, 0);
        assert_eq!(empty.blocks_io_error, 0);
        assert!(empty.findings.is_empty());

        let r1 = ScrubReport {
            findings: vec![finding(10)],
            blocks_scanned: 100,
            blocks_corrupt: 1,
            blocks_io_error: 0,
        };
        let r2 = ScrubReport {
            findings: vec![finding(20), finding(30)],
            blocks_scanned: 50,
            blocks_corrupt: 2,
            blocks_io_error: 3,
        };
        let merged = merge_scrub_reports(vec![r1, r2]);
        assert_eq!(merged.blocks_scanned, 150);
        assert_eq!(merged.blocks_corrupt, 3);
        assert_eq!(merged.blocks_io_error, 3);
        // Findings are concatenated in input order.
        let blocks: Vec<u64> = merged.findings.iter().map(|f| f.block.0).collect();
        assert_eq!(blocks, vec![10, 20, 30]);
    }

    #[test]
    fn select_ext4_repair_groups_scopes_by_flags_and_staleness() {
        use Ext4RepairStaleness::{Fresh, Stale, Untracked};
        let all = vec![0_u32, 1, 2];

        // full_scrub / rebuild_symbols select every group regardless of staleness.
        let full = RepairFlags::empty().with_full_scrub(true);
        assert_eq!(
            select_ext4_repair_groups(full, false, &all, &[(0, Fresh), (1, Fresh)]),
            all
        );
        let rebuild = RepairFlags::empty().with_rebuild_symbols(true);
        assert_eq!(select_ext4_repair_groups(rebuild, false, &all, &[]), all);

        let flags = RepairFlags::empty();
        // Only stale groups are selected when some are stale.
        assert_eq!(
            select_ext4_repair_groups(flags, false, &all, &[(0, Fresh), (1, Stale), (2, Stale)]),
            vec![1, 2]
        );
        // All fresh (no stale) -> nothing to repair.
        assert_eq!(
            select_ext4_repair_groups(flags, false, &all, &[(0, Fresh), (1, Fresh)]),
            [] as [u32; 0]
        );
        // A clean filesystem short-circuits to empty.
        assert_eq!(
            select_ext4_repair_groups(flags, true, &all, &[(0, Untracked)]),
            [] as [u32; 0]
        );
        // No stale, no fresh, not clean (untracked) -> conservative full set.
        assert_eq!(
            select_ext4_repair_groups(flags, false, &all, &[(0, Untracked), (1, Untracked)]),
            all
        );
    }

    #[test]
    fn group_btrfs_corrupt_blocks_assigns_blocks_to_specs_and_counts_outsiders() {
        use ffs_repair::scrub::{CorruptionKind, ScrubFinding};

        let finding = |block: u64, severity| ScrubFinding {
            block: BlockNumber(block),
            kind: CorruptionKind::ChecksumMismatch,
            severity,
            detail: String::new(),
        };
        let spec = |group: u32, start: u64, count: u32| BtrfsRepairGroupSpec {
            group,
            logical_start: 0,
            logical_bytes: 0,
            physical_start_block: BlockNumber(start),
            physical_block_count: u64::from(count),
            source_block_count: count,
            layout: RepairGroupLayout {
                group: ffs_types::GroupNumber(group),
                group_start: BlockNumber(start),
                blocks_per_group: count,
                validation_block_count: 0,
                repair_block_count: 0,
            },
        };
        let report = ScrubReport {
            findings: vec![
                finding(110, Severity::Error),   // spec A [100, 150)
                finding(210, Severity::Error),   // spec B [200, 250)
                finding(300, Severity::Error),   // outside both specs
                finding(120, Severity::Warning), // sub-Error -> ignored
            ],
            blocks_scanned: 0,
            blocks_corrupt: 0,
            blocks_io_error: 0,
        };
        let specs = vec![spec(1, 100, 50), spec(2, 200, 50)];

        let (grouped, outside) = group_btrfs_corrupt_blocks(&report, &specs);
        assert_eq!(grouped.get(&1), Some(&vec![BlockNumber(110)]));
        assert_eq!(grouped.get(&2), Some(&vec![BlockNumber(210)]));
        assert_eq!(
            outside, 1,
            "block 300 lies outside every spec's source range"
        );
        // The Warning-severity finding must not be grouped.
        assert!(!grouped.values().any(|v| v.contains(&BlockNumber(120))));
    }

    #[test]
    fn block_range_contains_handles_boundaries_and_overflow() {
        let start = BlockNumber(100);
        // An empty range contains nothing.
        assert!(!block_range_contains(start, 0, BlockNumber(100)));
        // A target below the start is excluded.
        assert!(!block_range_contains(start, 10, BlockNumber(99)));
        // The first and last blocks of [100, 110) are included.
        assert!(block_range_contains(start, 10, BlockNumber(100)));
        assert!(block_range_contains(start, 10, BlockNumber(109)));
        // One past the end is excluded.
        assert!(!block_range_contains(start, 10, BlockNumber(110)));
        // count == u64::MAX covers everything at or above start.
        assert!(block_range_contains(start, u64::MAX, BlockNumber(u64::MAX)));
        assert!(!block_range_contains(start, u64::MAX, BlockNumber(99)));
        // A range whose end overflows u64 still contains targets at/above start.
        assert!(block_range_contains(
            BlockNumber(u64::MAX - 5),
            100,
            BlockNumber(u64::MAX)
        ));
    }

    #[test]
    fn partition_scrub_range_covers_exactly_without_overlap() {
        // No work when count or workers is zero.
        assert_eq!(
            partition_scrub_range(BlockNumber(0), 0, 4),
            [] as [(ffs_types::BlockNumber, u64); 0]
        );
        assert_eq!(
            partition_scrub_range(BlockNumber(0), 100, 0),
            [] as [(ffs_types::BlockNumber, u64); 0]
        );

        // 100 blocks across 3 workers: 33 each, remainder 1 to the first worker.
        let parts = partition_scrub_range(BlockNumber(10), 100, 3);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], (BlockNumber(10), 34));
        assert_eq!(parts[1], (BlockNumber(44), 33));
        assert_eq!(parts[2], (BlockNumber(77), 33));

        // The partitions exactly cover [start, start+count) with no overlap/gap.
        let total: u64 = parts.iter().map(|(_, width)| *width).sum();
        assert_eq!(total, 100);
        for win in parts.windows(2) {
            assert_eq!(
                win[0].0.0 + win[0].1,
                win[1].0.0,
                "ranges must be contiguous"
            );
        }
        let last = parts.last().unwrap();
        assert_eq!(last.0.0 + last.1, 110, "must end at start + count");

        // More workers than blocks caps at `count` single-block ranges.
        let many = partition_scrub_range(BlockNumber(0), 2, 8);
        assert_eq!(many, vec![(BlockNumber(0), 1), (BlockNumber(1), 1)]);
    }

    #[test]
    fn resolve_host_id_prefers_explicit_override() {
        assert_eq!(
            resolve_host_id(Some("  pinned-host-id  "), Some("deadbeef"), "worker-1"),
            "pinned-host-id"
        );
    }

    #[test]
    fn resolve_host_id_uses_lowercased_hex_machine_id() {
        assert_eq!(
            resolve_host_id(None, Some("ABCDEF0123456789\n"), "worker-1"),
            "abcdef0123456789"
        );
    }

    #[test]
    fn resolve_host_id_skips_non_hex_machine_id_for_hostname_token() {
        // A non-hex machine-id is not a valid stable UUID; fall back to host.
        assert_eq!(
            resolve_host_id(None, Some("not-a-machine-id"), "Worker Box 7"),
            "host-worker-box-7"
        );
    }

    #[test]
    fn resolve_host_id_sentinel_when_hostname_is_empty() {
        assert_eq!(resolve_host_id(None, None, ""), "unknown-host-id");
    }

    #[test]
    fn coordinate_not_required_when_write_guard_unset() {
        let image = temp_image_path();
        let cx = Cx::for_testing();
        let decision = coordinate_repair_write_access(
            &cx,
            "ffs::test",
            REPAIR_COORDINATION_SCENARIO_REPAIR,
            "repair",
            &image,
            false,
        );
        assert!(!decision.writes_allowed);
        assert_eq!(
            decision.output.status,
            RepairCoordinationStatus::NotRequired
        );
        assert!(!repair_coordination_record_path(&image).exists());
        cleanup(&image);
    }

    #[test]
    fn coordinate_claims_absent_record() {
        let image = temp_image_path();
        let cx = Cx::for_testing();
        let decision = coordinate_repair_write_access(
            &cx,
            "ffs::test",
            REPAIR_COORDINATION_SCENARIO_REPAIR,
            "repair",
            &image,
            true,
        );
        assert!(decision.writes_allowed);
        assert_eq!(decision.output.status, RepairCoordinationStatus::Claimed);
        assert_eq!(decision.output.policy, "lease_v1");
        assert_eq!(decision.output.repair_generation, Some(1));
        assert_eq!(decision.output.lease_version, Some(1));
        assert_eq!(decision.output.lease_ttl_secs, Some(300));
        assert_eq!(
            decision.output.owner_host_id.as_deref(),
            Some(decision.output.host_id.as_str())
        );
        assert!(repair_coordination_record_path(&image).exists());
        cleanup(&image);
    }

    #[test]
    fn coordinate_same_incarnation_refreshes_and_bumps_generation() {
        let image = temp_image_path();
        let cx = Cx::for_testing();
        let first = coordinate_repair_write_access(
            &cx,
            "ffs::test",
            REPAIR_COORDINATION_SCENARIO_REPAIR,
            "repair",
            &image,
            true,
        );
        let second = coordinate_repair_write_access(
            &cx,
            "ffs::test",
            REPAIR_COORDINATION_SCENARIO_REPAIR,
            "repair",
            &image,
            true,
        );
        assert!(first.writes_allowed && second.writes_allowed);
        assert_eq!(first.output.repair_generation, Some(1));
        assert_eq!(second.output.repair_generation, Some(2));
        assert_eq!(second.output.status, RepairCoordinationStatus::Claimed);
        cleanup(&image);
    }

    #[test]
    fn coordinate_blocks_live_foreign_lease_with_remaining_ttl() {
        let image = temp_image_path();
        write_record(
            &image,
            &foreign_record("ffs-test-foreign-host-id", "foreign-worker", false),
        );
        let cx = Cx::for_testing();
        let decision = coordinate_repair_write_access(
            &cx,
            "ffs::test",
            REPAIR_COORDINATION_SCENARIO_REPAIR,
            "repair",
            &image,
            true,
        );
        assert!(!decision.writes_allowed);
        assert_eq!(decision.output.status, RepairCoordinationStatus::Blocked);
        assert_eq!(
            decision.output.error_class.as_deref(),
            Some("foreign_lease_active")
        );
        assert_eq!(
            decision.output.owner_host.as_deref(),
            Some("foreign-worker")
        );
        assert_eq!(
            decision.output.owner_host_id.as_deref(),
            Some("ffs-test-foreign-host-id")
        );
        let remaining = decision
            .output
            .lease_expires_in_secs
            .expect("live foreign lease must report remaining TTL");
        assert!(
            remaining > 0 && remaining <= 300,
            "remaining TTL out of range: {remaining}"
        );
        cleanup(&image);
    }

    #[test]
    fn coordinate_takes_over_expired_foreign_lease() {
        let image = temp_image_path();
        write_record(
            &image,
            &foreign_record("ffs-test-dead-host-id", "crashed-worker", true),
        );
        let cx = Cx::for_testing();
        let decision = coordinate_repair_write_access(
            &cx,
            "ffs::test",
            REPAIR_COORDINATION_SCENARIO_REPAIR,
            "repair",
            &image,
            true,
        );
        assert!(
            decision.writes_allowed,
            "expired foreign lease must be taken over"
        );
        assert_eq!(decision.output.status, RepairCoordinationStatus::Claimed);
        // Takeover increments the foreign record's repair_generation (7 -> 8).
        assert_eq!(decision.output.repair_generation, Some(8));
        assert_eq!(
            decision.output.owner_host_id.as_deref(),
            Some(decision.output.host_id.as_str())
        );
        cleanup(&image);
    }

    #[test]
    fn coordinate_fails_closed_on_invalid_record() {
        let image = temp_image_path();
        std::fs::write(repair_coordination_record_path(&image), b"{ not valid json")
            .expect("write invalid record");
        let cx = Cx::for_testing();
        let decision = coordinate_repair_write_access(
            &cx,
            "ffs::test",
            REPAIR_COORDINATION_SCENARIO_REPAIR,
            "repair",
            &image,
            true,
        );
        assert!(!decision.writes_allowed);
        assert_eq!(decision.output.status, RepairCoordinationStatus::Blocked);
        assert_eq!(
            decision.output.error_class.as_deref(),
            Some("coordination_metadata_invalid")
        );
        cleanup(&image);
    }

    #[test]
    fn conflict_lost_decision_fails_closed_for_winning_host() {
        let image = temp_image_path();
        let ctx = RepairCoordinationContext::new(
            "ffs::test",
            REPAIR_COORDINATION_SCENARIO_REPAIR,
            "repair",
            &image,
        );
        let decision = conflict_lost_decision(&ctx, "winner-host-id");
        assert!(!decision.writes_allowed);
        assert_eq!(decision.output.status, RepairCoordinationStatus::Blocked);
        assert_eq!(
            decision.output.error_class.as_deref(),
            Some("ownership_conflict_lost")
        );
        assert_eq!(
            decision.output.owner_host_id.as_deref(),
            Some("winner-host-id")
        );
        assert!(
            decision
                .output
                .detail
                .contains("deterministic ownership tiebreak")
        );
        cleanup(&image);
    }

    #[test]
    fn coordination_error_decision_classifies_io_kinds() {
        let image = temp_image_path();
        let ctx = RepairCoordinationContext::new(
            "ffs::test",
            REPAIR_COORDINATION_SCENARIO_REPAIR,
            "repair",
            &image,
        );
        let invalid = std::io::Error::new(std::io::ErrorKind::InvalidData, "bad record");
        assert_eq!(
            coordination_error_decision(&ctx, &invalid)
                .output
                .error_class
                .as_deref(),
            Some("coordination_metadata_invalid")
        );
        let cancelled = std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled");
        assert_eq!(
            coordination_error_decision(&ctx, &cancelled)
                .output
                .error_class
                .as_deref(),
            Some("coordination_cancelled")
        );
        let other = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        assert_eq!(
            coordination_error_decision(&ctx, &other)
                .output
                .error_class
                .as_deref(),
            Some("coordination_io")
        );
        cleanup(&image);
    }
}
