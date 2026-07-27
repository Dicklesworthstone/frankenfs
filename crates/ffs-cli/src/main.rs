#![forbid(unsafe_code)]

// jemalloc global allocator: glibc malloc was ~40% of single-thread create CPU
// and its arena lock convoyed parallel writers into NEGATIVE scaling (bd-bhh0i).
// jemalloc gives ~1.6x single-thread and ~2.2x parallel on alloc-heavy paths
// (block-read + dir-parse buffers). Safe to declare under forbid(unsafe_code) —
// the GlobalAlloc impl's unsafety lives in the jemallocator crate.
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod cmd_evidence;
mod cmd_repair;
mod mount_console;
mod repair_btrfs_parsers;

use cmd_repair::{
    DEFAULT_REPAIR_OVERHEAD_RATIO, Ext4RepairStaleness, REPAIR_COORDINATION_SCENARIO_FSCK,
    RepairCoordinationOutput, append_btrfs_repair_detail, block_range_contains,
    build_ext4_repair_group_specs, coordinate_repair_write_access,
    detect_flavor_with_optional_btrfs_bootstrap, discover_btrfs_repair_group_specs,
    primary_btrfs_superblock_block, probe_btrfs_repair_staleness, probe_ext4_repair_staleness,
    recover_btrfs_corrupt_blocks, recover_primary_btrfs_superblock_from_backup,
    repair_corrupt_btrfs_superblock_mirrors_from_primary, report_has_error_or_higher_for_block,
    scrub_range_for_repair,
};

use anyhow::{Context, Result, bail};
use asupersync::{Cx, SystemPressure};
use clap::{Parser, Subcommand, ValueEnum};
use ffs_block::{BlockDevice, ByteBlockDevice, ByteDevice, FileByteDevice};
use ffs_btrfs::{
    BTRFS_FS_TREE_OBJECTID, BTRFS_ITEM_INODE_ITEM, BTRFS_ITEM_ROOT_ITEM, BtrfsInodeItem,
    parse_inode_item, parse_root_item,
};
use ffs_core::degradation::DegradationLevel;
use ffs_core::{
    BackpressureGate, BtrfsMountSelection, CrashRecoveryOutcome, DegradationFsm, Ext4DataErrPolicy,
    Ext4JournalReplayMode, FsFlavor, FsOps, OpenFs, OpenOptions, RepairWritebackBlock,
    detect_filesystem_at_path,
};
use ffs_fuse::{MountConfig, MountOptions, WritebackCacheMode, mount_managed};
use ffs_harness::{
    ParityReport,
    adaptive_runtime_manifest::{
        AdaptiveRuntimeEvidenceValidationConfig, AdaptiveRuntimeMode,
        fail_on_adaptive_runtime_evidence_errors, load_adaptive_runtime_evidence_manifest,
        validate_adaptive_runtime_evidence_manifest_with_config,
    },
    runtime_console_report::RuntimeConsoleMode,
    writeback_cache_audit::{
        build_writeback_cache_audit_report, build_writeback_crash_replay_report,
        build_writeback_ordering_report, fail_on_writeback_cache_audit_errors,
        fail_on_writeback_crash_replay_errors, fail_on_writeback_ordering_errors,
        load_writeback_cache_audit_gate, load_writeback_crash_replay_oracle,
        load_writeback_ordering_oracle,
    },
};
#[cfg(feature = "bhh0i_sharded_alloc")]
use ffs_mvcc::sharded::PublicationMode;
use ffs_ondisk::{
    BtrfsSuperblock, Ext4DirEntry, Ext4Extent, Ext4ExtentHeader, Ext4ExtentIndex, Ext4GroupDesc,
    Ext4ImageReader, Ext4Inode, Ext4Superblock, ExtentTree, ext4::Ext4QuotaInodes, parse_dx_root,
    parse_extent_tree, parse_inode_extent_tree,
};
use ffs_repair::pipeline::{
    GroupConfig, ScrubDaemon, ScrubDaemonConfig, ScrubDaemonMetrics, ScrubWithRecovery,
};
use ffs_repair::recovery::{RecoveryWriteback, RecoveryWritebackBlock};
use ffs_repair::scrub::{
    BlockValidator, BtrfsScrubValidator, Ext4SuperblockValidator, ScrubReport, Scrubber, Severity,
};
use ffs_types::{
    BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, BlockNumber, ByteOffset,
    EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE, GroupNumber, InodeNumber, MountMode,
};
use mount_console::{
    MountConsoleConfig, MountConsoleCore, MountConsoleObservation, emit_mount_console,
};
use serde::Serialize;
use std::collections::BTreeSet;
use std::env::VarError;
use std::fmt::Write;
use std::fs::{File, OpenOptions as StdOpenOptions};
use std::io::{Read, Seek, SeekFrom, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, info_span, warn};
use tracing_subscriber::EnvFilter;

// ── Production Cx acquisition ───────────────────────────────────────────────

#[must_use]
pub fn cli_cx() -> Cx {
    Cx::for_request()
}

// ── CLI definition ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LogFormat {
    Human,
    Json,
}

impl LogFormat {
    const ENV_KEY: &'static str = "FFS_LOG_FORMAT";

    fn parse(raw: &str) -> Result<Self> {
        <Self as ValueEnum>::from_str(raw.trim(), true).map_err(|_| {
            anyhow::anyhow!(
                "invalid {key}={raw:?}; expected one of: human, json",
                key = Self::ENV_KEY
            )
        })
    }

    fn from_env() -> Result<Option<Self>> {
        match std::env::var(Self::ENV_KEY) {
            Ok(value) => Ok(Some(Self::parse(&value)?)),
            Err(VarError::NotPresent) => Ok(None),
            Err(VarError::NotUnicode(_)) => {
                bail!("{key} contains non-UTF-8 bytes", key = Self::ENV_KEY)
            }
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Json => "json",
        }
    }
}

const DEFAULT_MANAGED_UNMOUNT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MOUNT_BACKGROUND_SCRUB_INTERVAL_SECS: u64 = 5;
const WRITEBACK_CACHE_KILL_SWITCH_ENV: &str = "FFS_WRITEBACK_CACHE_KILL_SWITCH";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum MountRuntimeMode {
    Standard,
    Managed,
    #[value(name = "per-core")]
    PerCore,
}

impl MountRuntimeMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Managed => "managed",
            Self::PerCore => "per-core",
        }
    }

    const fn scenario_id(self, read_write: bool) -> &'static str {
        match (self, read_write) {
            (Self::Standard, false) => "cli_mount_runtime_standard_ro",
            (Self::Standard, true) => "cli_mount_runtime_standard_rw",
            (Self::Managed, false) => "cli_mount_runtime_managed_ro",
            (Self::Managed, true) => "cli_mount_runtime_managed_rw",
            (Self::PerCore, false) => "cli_mount_runtime_per_core_ro",
            (Self::PerCore, true) => "cli_mount_runtime_per_core_rw",
        }
    }

    const fn adaptive_runtime_mode(self) -> AdaptiveRuntimeMode {
        match self {
            Self::Standard => AdaptiveRuntimeMode::Standard,
            Self::Managed => AdaptiveRuntimeMode::Managed,
            Self::PerCore => AdaptiveRuntimeMode::PerCore,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MountRuntimeConfig {
    mode: MountRuntimeMode,
    managed_unmount_timeout_secs: Option<u64>,
}

impl MountRuntimeConfig {
    fn validate(self) -> Result<Self> {
        if self.mode == MountRuntimeMode::Standard && self.managed_unmount_timeout_secs.is_some() {
            bail!("--managed-unmount-timeout-secs requires --runtime-mode managed or per-core");
        }
        Ok(self)
    }

    fn managed_unmount_timeout_secs(self) -> u64 {
        self.managed_unmount_timeout_secs
            .unwrap_or(DEFAULT_MANAGED_UNMOUNT_TIMEOUT_SECS)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountAdaptiveRuntimeConfig {
    enabled: bool,
    manifest_path: Option<PathBuf>,
}

impl MountAdaptiveRuntimeConfig {
    #[cfg(test)]
    const fn disabled() -> Self {
        Self {
            enabled: false,
            manifest_path: None,
        }
    }

    fn from_cli(enabled: bool, manifest_path: Option<PathBuf>) -> Self {
        Self {
            enabled,
            manifest_path,
        }
    }
}

#[derive(Clone)]
struct MountAdaptiveRuntimePlan {
    manifest_path: PathBuf,
    manifest_scenario_id: String,
    run_id: String,
    release_claim_state: String,
    backpressure_policy_id: String,
    artifact_paths: Vec<String>,
    raw_stdout_path: String,
    raw_stderr_path: String,
    raw_log_paths: Vec<String>,
    cleanup_status: String,
    git_sha: String,
    reproduction_command: String,
    fsm: Arc<DegradationFsm>,
    gate: Arc<BackpressureGate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountAdaptiveRuntimeSummaryConfig {
    json_path: Option<PathBuf>,
    markdown_path: Option<PathBuf>,
}

impl MountAdaptiveRuntimeSummaryConfig {
    #[cfg(test)]
    const fn disabled() -> Self {
        Self {
            json_path: None,
            markdown_path: None,
        }
    }

    fn from_cli(json_path: Option<PathBuf>, markdown_path: Option<PathBuf>) -> Self {
        Self {
            json_path,
            markdown_path,
        }
    }

    fn enabled(&self) -> bool {
        self.json_path.is_some() || self.markdown_path.is_some()
    }
}

#[derive(Debug, Clone)]
struct MountAdaptiveRuntimeShutdownObservation {
    metrics: ffs_fuse::MetricsSnapshot,
    worker_count: u32,
    per_core: Option<MountAdaptiveRuntimePerCoreObservation>,
}

#[derive(Debug, Clone)]
struct MountAdaptiveRuntimePerCoreObservation {
    total_cache_hits: u64,
    total_cache_misses: u64,
    imbalance_ratio: f64,
    per_core_distribution: Vec<MountAdaptiveRuntimeCoreRequestSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct MountAdaptiveRuntimeCoreRequestSummary {
    core_id: u32,
    requests: u64,
    cache_hits: u64,
    cache_misses: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct MountAdaptiveRuntimeDegradationTransitionLedger {
    current_level: String,
    transition_count: u64,
    transitions: Vec<MountAdaptiveRuntimeDegradationTransitionSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct MountAdaptiveRuntimeDegradationTransitionSummary {
    from: String,
    to: String,
    headroom_milli: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct MountAdaptiveRuntimeShutdownSummary {
    schema_version: u32,
    adaptive_runtime_enabled: bool,
    runtime_mode: String,
    read_write: bool,
    run_id: String,
    scenario_id: String,
    cli_scenario_id: String,
    release_claim_state: String,
    degradation_level_transitions: MountAdaptiveRuntimeDegradationTransitionLedger,
    backpressure_policy_id: Option<String>,
    requests_throttled: u64,
    requests_shed: u64,
    total_requests: u64,
    cache_hits: Option<u64>,
    cache_misses: Option<u64>,
    per_core_request_distribution: Vec<MountAdaptiveRuntimeCoreRequestSummary>,
    per_core_imbalance_ratio: Option<f64>,
    worker_count: u32,
    artifact_paths: Vec<String>,
    raw_stdout_path: Option<String>,
    raw_stderr_path: Option<String>,
    raw_log_paths: Vec<String>,
    cleanup_status: String,
    git_sha: String,
    reproduction_command: String,
}

#[derive(Clone, Copy)]
struct MountAdaptiveRuntimeShutdownContext<'a> {
    image_path: &'a Path,
    mountpoint: &'a Path,
    runtime: MountRuntimeConfig,
    read_write: bool,
    operation_id: &'a str,
    cli_scenario_id: &'a str,
    plan: Option<&'a MountAdaptiveRuntimePlan>,
    summary_config: &'a MountAdaptiveRuntimeSummaryConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountBackgroundScrubConfig {
    enabled: bool,
    explicit: bool,
    repair_writes_enabled: bool,
    interval_secs: u64,
    ledger_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MountAccessMode {
    ReadOnly,
    ReadWrite,
}

impl MountAccessMode {
    const fn from_read_write(read_write: bool) -> Self {
        if read_write {
            Self::ReadWrite
        } else {
            Self::ReadOnly
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MountBackgroundScrubMode {
    Auto,
    Enabled,
    Disabled,
    Conflicting,
}

impl MountBackgroundScrubMode {
    const fn from_cli(background_scrub: bool, no_background_scrub: bool) -> Self {
        match (background_scrub, no_background_scrub) {
            (true, true) => Self::Conflicting,
            (true, false) => Self::Enabled,
            (false, true) => Self::Disabled,
            (false, false) => Self::Auto,
        }
    }

    const fn explicit(self) -> bool {
        matches!(self, Self::Enabled | Self::Disabled | Self::Conflicting)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MountBackgroundRepairMode {
    Disabled,
    Enabled,
}

impl MountBackgroundRepairMode {
    const fn from_cli(background_repair: bool) -> Self {
        if background_repair {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }

    const fn enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MountBackgroundScrubRequest {
    access: MountAccessMode,
    scrub: MountBackgroundScrubMode,
    repair: MountBackgroundRepairMode,
}

impl MountBackgroundScrubRequest {
    const fn new(
        access_mode: MountAccessMode,
        scrub_mode: MountBackgroundScrubMode,
        repair_mode: MountBackgroundRepairMode,
    ) -> Self {
        Self {
            access: access_mode,
            scrub: scrub_mode,
            repair: repair_mode,
        }
    }
}

impl MountBackgroundScrubConfig {
    fn resolve(
        request: MountBackgroundScrubRequest,
        interval_secs: Option<u64>,
        ledger_path: Option<PathBuf>,
    ) -> Result<Self> {
        if request.scrub == MountBackgroundScrubMode::Conflicting {
            bail!("--background-scrub and --no-background-scrub are mutually exclusive");
        }
        let background_repair = request.repair.enabled();
        if background_repair && request.scrub == MountBackgroundScrubMode::Disabled {
            bail!("--background-repair cannot be combined with --no-background-scrub");
        }
        if background_repair && ledger_path.is_none() {
            bail!("--background-repair requires --background-scrub-ledger for durable evidence");
        }

        let explicit = request.scrub.explicit() || background_repair;
        let enabled = match request.scrub {
            MountBackgroundScrubMode::Enabled => true,
            MountBackgroundScrubMode::Auto => request.access == MountAccessMode::ReadOnly,
            MountBackgroundScrubMode::Disabled | MountBackgroundScrubMode::Conflicting => false,
        };
        let enabled = enabled || background_repair;
        if !enabled && interval_secs.is_some() {
            bail!("--background-scrub-interval-secs requires background scrub to be enabled");
        }
        if !enabled && ledger_path.is_some() {
            bail!("--background-scrub-ledger requires background scrub to be enabled");
        }

        Ok(Self {
            enabled,
            explicit,
            repair_writes_enabled: background_repair,
            interval_secs: interval_secs.unwrap_or(DEFAULT_MOUNT_BACKGROUND_SCRUB_INTERVAL_SECS),
            ledger_path,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountWritebackCacheConfig {
    enabled: bool,
    audit_gate_path: Option<PathBuf>,
    ordering_oracle_path: Option<PathBuf>,
    crash_replay_oracle_path: Option<PathBuf>,
    runtime_kill_switch: bool,
}

impl MountWritebackCacheConfig {
    #[cfg(test)]
    const fn disabled() -> Self {
        Self {
            enabled: false,
            audit_gate_path: None,
            ordering_oracle_path: None,
            crash_replay_oracle_path: None,
            runtime_kill_switch: false,
        }
    }

    fn from_cli(
        enabled: bool,
        audit_gate_path: Option<PathBuf>,
        ordering_oracle_path: Option<PathBuf>,
        crash_replay_oracle_path: Option<PathBuf>,
    ) -> Self {
        Self {
            enabled,
            audit_gate_path,
            ordering_oracle_path,
            crash_replay_oracle_path,
            runtime_kill_switch: writeback_cache_runtime_kill_switch_enabled(),
        }
    }

    #[cfg(test)]
    fn from_cli_with_runtime_kill_switch(
        enabled: bool,
        audit_gate_path: Option<PathBuf>,
        ordering_oracle_path: Option<PathBuf>,
        crash_replay_oracle_path: Option<PathBuf>,
        runtime_kill_switch: bool,
    ) -> Self {
        Self {
            enabled,
            audit_gate_path,
            ordering_oracle_path,
            crash_replay_oracle_path,
            runtime_kill_switch,
        }
    }
}

fn writeback_cache_runtime_kill_switch_enabled() -> bool {
    env_bool(WRITEBACK_CACHE_KILL_SWITCH_ENV, false).unwrap_or(true)
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
struct MountCmdOptions {
    allow_other: bool,
    read_write: bool,
    mount_mode: MountMode,
    btrfs_mount_selection: BtrfsMountSelection,
    ext4_data_err_policy: Ext4DataErrPolicy,
    ext4_verify_journal_checksums: bool,
    /// Use ephemeral (tree-log only) commit strategy instead of full durable commit.
    btrfs_rw_ephemeral_ok: bool,
    runtime: MountRuntimeConfig,
    adaptive_runtime: MountAdaptiveRuntimeConfig,
    adaptive_runtime_summary: MountAdaptiveRuntimeSummaryConfig,
    background_scrub: MountBackgroundScrubConfig,
    writeback_cache: MountWritebackCacheConfig,
    console: MountConsoleConfig,
}

fn default_env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
}

fn env_bool(key: &str, default: bool) -> Result<bool> {
    match std::env::var(key) {
        Ok(value) => {
            let value = value.trim();
            if value == "1"
                || value.eq_ignore_ascii_case("true")
                || value.eq_ignore_ascii_case("yes")
                || value.eq_ignore_ascii_case("on")
            {
                Ok(true)
            } else if value == "0"
                || value.eq_ignore_ascii_case("false")
                || value.eq_ignore_ascii_case("no")
                || value.eq_ignore_ascii_case("off")
            {
                Ok(false)
            } else {
                bail!("invalid {key}={value:?}; expected one of: 1,0,true,false,yes,no,on,off")
            }
        }
        Err(VarError::NotPresent) => Ok(default),
        Err(VarError::NotUnicode(_)) => bail!("{key} contains non-UTF-8 bytes"),
    }
}

fn init_logging(log_format_override: Option<LogFormat>) -> Result<LogFormat> {
    let format = log_format_override
        .or(LogFormat::from_env()?)
        .unwrap_or(LogFormat::Human);

    match format {
        // Logs go to STDERR (not the default stdout), so commands that emit data to
        // stdout — notably `read`, which writes raw file bytes — keep stdout clean.
        LogFormat::Human => tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(default_env_filter())
            .with_target(true)
            .with_level(true)
            .compact()
            .try_init()
            .map_err(|err| anyhow::anyhow!("failed to initialize human logger: {err}"))?,
        LogFormat::Json => tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_env_filter(default_env_filter())
            .with_target(true)
            .with_level(true)
            .try_init()
            .map_err(|err| anyhow::anyhow!("failed to initialize JSON logger: {err}"))?,
    }

    Ok(format)
}

#[derive(Parser)]
#[command(name = "ffs", about = "FrankenFS — memory-safe filesystem toolkit")]
struct Cli {
    /// Log output format (`human` or `json`).
    ///
    /// Precedence: `--log-format` > `FFS_LOG_FORMAT` > `human`.
    #[arg(long, value_enum, global = true)]
    log_format: Option<LogFormat>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[expect(
    clippy::large_enum_variant,
    reason = "clap subcommands keep typed flag payloads inline for direct parsing"
)]
enum Command {
    /// Print the executing CLI's benchmark identity.
    ///
    /// Hidden from normal help because this is a measurement-harness contract,
    /// not an end-user filesystem operation.
    #[command(name = "bench-evidence", hide = true)]
    BenchEvidence,
    /// Inspect a filesystem image (ext4 or btrfs).
    Inspect {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
        /// List all btrfs subvolumes.
        #[arg(long)]
        subvolumes: bool,
        /// List all btrfs snapshots.
        #[arg(long)]
        snapshots: bool,
    },
    /// Read a file's data from a filesystem image to stdout (no FUSE mount).
    ///
    /// Reads `path` (absolute, e.g. `/bigfile`) from `image` via the in-process
    /// read engine and writes its bytes to stdout. Enables a no-FUSE head-to-head
    /// read-throughput comparison against the kernel filesystem.
    Read {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Absolute path of the file inside the image (e.g. /bigfile).
        path: String,
        /// Discard bytes (write to a sink) instead of stdout; report only the count.
        #[arg(long)]
        discard: bool,
        /// Emit the in-process ELF/ISA/profile witness and timed read result.
        ///
        /// Hidden because this is the `bd-b9dug` measurement contract, not an
        /// end-user read mode. It is valid only with `--discard`, keeping stdout
        /// machine-readable instead of mixing evidence with file bytes.
        #[arg(long, hide = true)]
        bench_evidence: bool,
    },
    /// Random-read benchmark: open once, then read `count` random page-aligned
    /// blocks of `size` bytes from `path` (no FUSE) and report engine time,
    /// throughput and IOPS. This is the random-access analogue of `read` — it
    /// exercises one extent-map lookup per access (sequential `read` coalesces
    /// contiguous runs, hiding per-lookup cost), for a head-to-head against a
    /// kernel random `pread` loop.
    RandRead {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Absolute path of the file inside the image (e.g. /bigfile).
        path: String,
        /// Number of random reads to issue.
        #[arg(long, default_value_t = 100_000)]
        count: usize,
        /// Bytes per read (page-aligned offset, this many bytes each).
        #[arg(long, default_value_t = 4096)]
        size: usize,
        /// Issue the reads concurrently across the rayon pool (models a
        /// many-threaded random-read workload); default is single-threaded.
        #[arg(long)]
        parallel: bool,
        /// Deterministic PRNG seed for the offset sequence (reproducible A/B).
        #[arg(long, default_value_t = 0x9E37_79B9_7F4A_7C15)]
        seed: u64,
    },
    /// Benchmark file writes (no FUSE): `enable_writes`, then write `count`
    /// blocks of `size` bytes into an existing file at sequential or random
    /// page-aligned offsets, timing total throughput. Each write goes through
    /// the full MVCC commit path, so this measures the write/commit engine for a
    /// head-to-head vs a kernel RW mount's `pwrite`. MUTATES the image — run on a
    /// throwaway copy.
    WriteBench {
        /// Path to the filesystem image (mutated in place).
        image: PathBuf,
        /// Absolute path of an existing file inside the image to overwrite.
        path: String,
        /// Number of writes to issue.
        #[arg(long, default_value_t = 50_000)]
        count: usize,
        /// Bytes per write.
        #[arg(long, default_value_t = 4096)]
        size: usize,
        /// Random page-aligned offsets instead of sequential.
        #[arg(long)]
        random: bool,
        /// Deterministic PRNG seed for random offsets.
        #[arg(long, default_value_t = 0x9E37_79B9_7F4A_7C15)]
        seed: u64,
        /// Create the file (in its parent dir) if missing and pre-fill it with
        /// `count * size` bytes of data before benchmarking. Lets this command
        /// build a sized data fixture for `rand-read` (whose file must already
        /// have blocks) without a kernel mount.
        #[arg(long)]
        create: bool,
    },
    /// Benchmark name lookups in a directory (no FUSE): readdir the directory
    /// once to collect its entry names, then resolve `count` random names via
    /// `lookup`, timing total throughput. On a large htree-indexed directory
    /// this exposes whether lookup uses the index (O(log N)) or linear-scans
    /// every block (O(N)) — a head-to-head vs a kernel mount's `stat`.
    LookupBench {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Absolute path of the directory whose entries are looked up.
        dir: String,
        /// Number of lookups to issue.
        #[arg(long, default_value_t = 20_000)]
        count: usize,
        /// Deterministic PRNG seed for the name sequence.
        #[arg(long, default_value_t = 0x9E37_79B9_7F4A_7C15)]
        seed: u64,
    },
    /// Benchmark metadata WRITES: `enable_writes`, then create `count` empty
    /// files in `dir` and FLUSH the overlay to the image (`sync_all_to_device`),
    /// timing the whole thing. Each create is existence-check lookup + inode
    /// alloc + directory insert + MVCC commit, then one final persist — a valid
    /// persisted head-to-head vs a kernel RW mount creating files (tar-extract /
    /// git-checkout shape; the re-opened image / kernel mount sees the files).
    /// MUTATES the image — run on a throwaway copy.
    CreateBench {
        /// Path to the filesystem image (mutated in place).
        image: PathBuf,
        /// Absolute path of an existing directory to create files in.
        dir: String,
        /// Number of files to create.
        #[arg(long, default_value_t = 20_000)]
        count: usize,
        /// Parallel writer threads (each creates count/threads files in its
        /// own subdir, isolating the MVCC commit-lock contention). 1 = serial.
        #[arg(long, default_value_t = 1)]
        threads: usize,
        /// Repeat the create phase `rounds` times in ONE process against ONE
        /// image, timing each round's creates SEPARATELY and flushing once at
        /// the end.
        ///
        /// `--rounds 1` (the default) is byte-identical to the historical
        /// behaviour, flush inside the timer and all, so every previously
        /// published create-bench number stays comparable.
        ///
        /// `--rounds N > 1` exists because the historical shape cannot decide a
        /// small effect: it needs a fresh 2 GiB image copy per run (thread
        /// subdirs `t{t}` collide on reuse) and it times the whole-image flush,
        /// so run-to-run variance is page-cache and writeback dominated rather
        /// than filesystem dominated. The bd-bhh0i cutover gate measured a
        /// 1-thread NEGATIVE CONTROL swinging 52% on that shape, which cannot
        /// resolve the ~6% effect under test. Rounds share one image (no copy)
        /// and exclude the flush, leaving the create loop as the signal.
        #[arg(long, default_value_t = 1)]
        rounds: usize,
    },
    /// Run the bd-bhh0i cutover decision as one self-contained invocation:
    /// interleaved 1-thread Mutex/Mutex A/A followed by interleaved 8-thread
    /// WaitFree/Mutex A/B, with a deterministic bootstrap median CI.
    ///
    /// Each arm needs its own byte-identical, non-reflink clone of one freshly
    /// formatted ext4 image because the benchmark mutates it. All four images
    /// must have the same SHA-256 and be no larger than 2 GiB. Flushes occur
    /// after every timed round and are excluded from the statistic; the
    /// resulting images remain available for e2fsck.
    #[command(name = "create-bench-cutover-gate")]
    CreateBenchCutoverGate {
        /// Cloned ext4 image for the left A/A Mutex arm.
        aa_lhs_image: PathBuf,
        /// Cloned ext4 image for the right A/A Mutex arm.
        aa_rhs_image: PathBuf,
        /// Cloned ext4 image for the A/B Mutex control arm.
        ab_base_image: PathBuf,
        /// Cloned ext4 image for the A/B WaitFree candidate arm.
        ab_candidate_image: PathBuf,
        /// Absolute path of an existing directory to create files in.
        dir: String,
        /// Number of files created by each arm per paired round.
        #[arg(long, default_value_t = 40_000)]
        count: usize,
        /// Parallel writers in the A/B pair. The A/A pair is always 1-thread.
        #[arg(long, default_value_t = 8)]
        threads: usize,
        /// Interleaved paired rounds. Arm order alternates every round.
        #[arg(long, default_value_t = 11)]
        rounds: usize,
    },
    /// Re-measure the corrected bounded read pool against the shipped
    /// quarter-nproc rule in one self-hashing whole-binary invocation.
    ///
    /// Hidden because this is a campaign evidence gate, not an end-user
    /// filesystem operation. The gate copies `fixture`, creates a dense file in
    /// the copy, then runs child instances of this exact ELF with cold-cache
    /// A/A and A/B arms.
    #[command(name = "read-pool-cutover-gate", hide = true)]
    ReadPoolCutoverGate {
        /// Existing ext4 image copied and mutated to build the private fixture.
        fixture: PathBuf,
        /// Number of 4 KiB blocks in the dense read target.
        #[arg(long, default_value_t = 8_192)]
        blocks: usize,
        /// Interleaved paired A/A and A/B rounds.
        #[arg(long, default_value_t = 31)]
        rounds: usize,
    },
    /// Benchmark mkdir: create `count` subdirectories in `dir` + flush, timing
    /// total throughput. Each mkdir is an existence-check lookup + inode/dir
    /// alloc + parent insert + MVCC commit — exercises the name-index across a
    /// mkdir stream (bd-f8rd8). MUTATES the image — run on a throwaway copy.
    MkdirBench {
        /// Path to the filesystem image (mutated in place).
        image: PathBuf,
        /// Absolute path of an existing directory to create subdirs in.
        dir: String,
        /// Number of subdirectories to create.
        #[arg(long, default_value_t = 20_000)]
        count: usize,
    },
    /// Benchmark directory removal: create `count` empty subdirs (setup,
    /// untimed), then time removing all of them + a flush. Each removal is a
    /// positive lookup + empty-check + parent-entry removal + MVCC commit.
    /// MUTATES the image — run on a throwaway copy.
    #[command(name = "rdbench")]
    RmdirBench {
        /// Path to the filesystem image (mutated in place).
        image: PathBuf,
        /// Absolute path of an existing directory to remove subdirs in.
        dir: String,
        /// Number of subdirectories to create-then-remove.
        #[arg(long, default_value_t = 20_000)]
        count: usize,
    },
    /// Benchmark metadata DELETES: create `count` files (setup, untimed), then
    /// time unlinking all of them + a final flush. Each unlink is a positive
    /// lookup + directory-entry removal + inode/bitmap free + MVCC commit — a
    /// persisted head-to-head vs a kernel RW mount deleting files (rm -rf /
    /// git-checkout shape). MUTATES the image — run on a throwaway copy.
    #[command(name = "delbench")]
    UnlinkBench {
        /// Path to the filesystem image (mutated in place).
        image: PathBuf,
        /// Absolute path of an existing directory to delete files in.
        dir: String,
        /// Number of files to create-then-unlink.
        #[arg(long, default_value_t = 20_000)]
        count: usize,
    },
    /// Benchmark metadata RENAMES: create `count` files (setup, untimed), then
    /// time renaming each to a new name in the same directory + a final flush.
    /// Each rename is a positive lookup + old-entry removal + new-entry insert +
    /// MVCC commit — a persisted head-to-head vs a kernel RW mount (mv / atomic
    /// save-rename shape). MUTATES the image — run on a throwaway copy.
    RenameBench {
        /// Path to the filesystem image (mutated in place).
        image: PathBuf,
        /// Absolute path of an existing directory to rename files in.
        dir: String,
        /// Number of files to create-then-rename.
        #[arg(long, default_value_t = 20_000)]
        count: usize,
    },
    /// Recursively walk every directory and stat every entry (no FUSE).
    ///
    /// Equivalent to `find <mnt> | xargs stat` — a metadata-heavy workload
    /// (readdir each directory + getattr each entry) for a no-FUSE head-to-head
    /// vs the kernel filesystem on cold `ls -lR` / `find` / stat workloads.
    Walk {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Skip the per-entry getattr (readdir-only walk).
        #[arg(long)]
        no_stat: bool,
        /// Walk directories concurrently (level-parallel BFS), modeling the
        /// concurrent readdir+getattr a FUSE-mounted fs sees from its worker
        /// threads. Overlaps cold per-directory metadata reads across threads.
        #[arg(long)]
        parallel: bool,
        /// Also read each regular file's full data (the `grep -r` / `tar` /
        /// build-source-read workload), reporting total bytes. Combine with
        /// `--parallel` to overlap the cold data reads across threads.
        #[arg(long)]
        read_data: bool,
    },
    /// Show MVCC and EBR version statistics for a filesystem image.
    MvccStats {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Show filesystem information (superblock + optional detailed sections).
    Info {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Include block group table (ext4) or chunk map (btrfs).
        #[arg(long)]
        groups: bool,
        /// Include MVCC engine status.
        #[arg(long)]
        mvcc: bool,
        /// Include repair subsystem status.
        #[arg(long)]
        repair: bool,
        /// Include journal status.
        #[arg(long)]
        journal: bool,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Dump low-level filesystem metadata.
    Dump {
        #[command(subcommand)]
        command: DumpCommand,
    },
    /// Run offline filesystem checks.
    Fsck {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Attempt repair actions when possible.
        #[arg(long, short = 'r')]
        repair: bool,
        /// Force a full check even if the filesystem appears clean.
        #[arg(long, short = 'f')]
        force: bool,
        /// Emit detailed phase progress.
        #[arg(long, short = 'v')]
        verbose: bool,
        /// Restrict checks to one ext4 group or btrfs block-group index.
        #[arg(long)]
        block_group: Option<u32>,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Trigger manual repair workflows.
    Repair {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Scrub all groups (default behavior is stale-only intent).
        #[arg(long)]
        full_scrub: bool,
        /// Restrict to one ext4 group or btrfs block-group index.
        #[arg(long)]
        block_group: Option<u32>,
        /// Force re-encoding of repair symbols.
        #[arg(long)]
        rebuild_symbols: bool,
        /// Verify only; do not attempt repair writes.
        #[arg(long)]
        verify_only: bool,
        /// Maximum worker threads for repair workflow.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        max_threads: Option<u32>,
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
        /// Runtime execution mode.
        ///
        /// Active controls by mode:
        /// - `standard` (default): blocking `ffs_fuse::mount` path. Process exits
        ///   on unmount or signal.
        /// - `managed`: background mount with lifecycle control, graceful Ctrl+C
        ///   shutdown, and final metrics logging.
        /// - `per-core`: managed mount with thread-per-core dispatch. Sets worker
        ///   threads to match detected cores and logs per-core metrics on shutdown.
        /// - Kernel FUSE `writeback_cache` mode is default-off in V1.x and only
        ///   enabled by `--writeback-cache` after the audit gate, ordering
        ///   oracle, crash/replay oracle, runtime guard, and host/lane evidence
        ///   accept.
        #[arg(long = "runtime-mode", value_enum, default_value_t = MountRuntimeMode::Standard)]
        runtime_mode: MountRuntimeMode,
        /// Graceful unmount timeout for managed/per-core modes (seconds).
        ///
        /// Invalid when used with `--runtime-mode standard`.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        managed_unmount_timeout_secs: Option<u64>,
        /// Enable adaptive managed/per-core runtime controls after evidence validation.
        ///
        /// Requires `--runtime-mode managed` or `--runtime-mode per-core` and
        /// `--adaptive-runtime-manifest`.
        #[arg(long = "adaptive-runtime")]
        adaptive_runtime: bool,
        /// Adaptive runtime evidence manifest accepted by `ffs-harness`.
        #[arg(long = "adaptive-runtime-manifest")]
        adaptive_runtime_manifest: Option<PathBuf>,
        /// Write adaptive runtime shutdown evidence as machine JSON.
        ///
        /// When adaptive runtime is off, the summary still records
        /// `adaptive_runtime_enabled=false` so proof bundles cannot mistake
        /// absent evidence for accepted runtime controls.
        #[arg(long = "adaptive-runtime-summary-json")]
        adaptive_runtime_summary_json: Option<PathBuf>,
        /// Write adaptive runtime shutdown evidence as concise Markdown.
        #[arg(long = "adaptive-runtime-summary-md")]
        adaptive_runtime_summary_md: Option<PathBuf>,
        /// Enable the operator runtime console for this managed/per-core mount.
        ///
        /// On shutdown the console emits a bounded, redacted, schema-pinned
        /// `runtime_console_report` artifact (request counters, throttled/shed
        /// counts, degradation level, per-core distribution, cleanup status).
        /// Requires `--runtime-mode managed` or `--runtime-mode per-core`.
        /// Console output is operational observability only: it never promotes
        /// `swarm.responsiveness` or `adaptive_runtime` readiness.
        #[arg(long = "console")]
        console: bool,
        /// Write the runtime console snapshot as machine JSON (requires `--console`).
        ///
        /// Defaults to `artifacts/runtime-console/<operation-id>.json` when
        /// `--console` is set without an explicit path.
        #[arg(long = "console-json")]
        console_json: Option<PathBuf>,
        /// Write the runtime console snapshot as a Markdown summary (requires `--console`).
        #[arg(long = "console-summary")]
        console_summary: Option<PathBuf>,
        /// Allow other users to access the mount.
        #[arg(long)]
        allow_other: bool,
        /// Mount read-write (default is read-only).
        #[arg(long)]
        rw: bool,
        /// Opt into kernel FUSE writeback_cache after the safety gate accepts.
        ///
        /// Requires `--rw`, `--writeback-cache-gate`,
        /// `--writeback-cache-ordering-oracle`, and
        /// `--writeback-cache-crash-replay-oracle`. The gate must also carry a
        /// fresh runtime guard with CLI-explicit config source, accepted feature
        /// state, matching host/lane manifest, and disarmed kill switch.
        /// `flush` remains non-durable; `fsync` and `fsyncdir` are the
        /// durability boundaries. `FFS_WRITEBACK_CACHE_KILL_SWITCH` fails
        /// closed before artifact I/O.
        #[arg(long = "writeback-cache")]
        writeback_cache: bool,
        /// Audit gate JSON required by `--writeback-cache`.
        #[arg(long = "writeback-cache-gate")]
        writeback_cache_gate: Option<PathBuf>,
        /// Dirty-page ordering oracle JSON required by `--writeback-cache`.
        #[arg(long = "writeback-cache-ordering-oracle")]
        writeback_cache_ordering_oracle: Option<PathBuf>,
        /// Crash/replay matrix oracle JSON required by `--writeback-cache`.
        #[arg(long = "writeback-cache-crash-replay-oracle")]
        writeback_cache_crash_replay_oracle: Option<PathBuf>,
        /// Force background scrub even when mounting read-write.
        ///
        /// Without this flag, read-only mounts start a detection-only scrub
        /// daemon automatically and read-write mounts leave it disabled to
        /// avoid racing the mutable mount path.
        #[arg(long, conflicts_with = "no_background_scrub")]
        background_scrub: bool,
        /// Disable the automatic read-only background scrub daemon.
        #[arg(long = "no-background-scrub")]
        no_background_scrub: bool,
        /// Background scrub tick interval in seconds.
        #[arg(long = "background-scrub-interval-secs", value_parser = clap::value_parser!(u64).range(1..))]
        background_scrub_interval_secs: Option<u64>,
        /// Append background scrub evidence records to this JSONL file.
        #[arg(long = "background-scrub-ledger")]
        background_scrub_ledger: Option<PathBuf>,
        /// Allow mounted background scrub to repair blocks and refresh repair symbols.
        ///
        /// This is an explicit backing-image mutation permission. Read-write
        /// mounts route recovered source blocks through the mounted MVCC
        /// serializer and still require `--background-scrub-ledger` so every
        /// automatic repair attempt has a durable evidence trail.
        #[arg(long = "background-repair", conflicts_with = "no_background_scrub")]
        background_repair: bool,
        /// Enable native MVCC mode (allows repair symbols, version store, BLAKE3).
        ///
        /// By default FrankenFS mounts in compatibility mode where only standard
        /// ext4/btrfs on-disk structures are written. Native mode enables
        /// FrankenFS-specific features: MVCC version chains, RaptorQ repair
        /// symbols, and BLAKE3 checksums.
        #[arg(long)]
        native: bool,
        /// Abort the ext4 journal on ordered-mode file-data I/O errors.
        #[arg(long = "ext4-data-err-abort")]
        ext4_data_err_abort: bool,
        /// Disable JBD2 checksum verification during ext4 journal replay.
        #[arg(long = "ext4-nojournal-checksum")]
        ext4_nojournal_checksum: bool,
        /// Mount a specific btrfs subvolume by name.
        #[arg(long)]
        subvol: Option<String>,
        /// Mount a specific btrfs snapshot by name.
        #[arg(long)]
        snapshot: Option<String>,
        /// Use ephemeral (tree-log only) commit strategy for btrfs.
        ///
        /// By default, btrfs RW is durable: full transaction commit on fsync/unmount
        /// via btrfs_full_transaction_commit(). This flag switches to tree-log only
        /// commits for faster fsync at the cost of durability - changes may be lost
        /// if the process crashes before unmount completes the final commit.
        #[arg(long = "btrfs-rw-ephemeral-ok")]
        btrfs_rw_ephemeral_ok: bool,
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
        /// Path to the evidence ledger JSONL or metrics snapshot JSON file.
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
        /// Filter ledger records to one block group.
        #[arg(long = "block-group")]
        block_group: Option<u32>,
        /// Preset query:
        /// replay-anomalies, repair-failures, pressure-transitions, contention,
        /// metrics, cache, mvcc, repair-live.
        #[arg(long)]
        preset: Option<String>,
        /// Show aggregated summary instead of individual records.
        #[arg(long)]
        summary: bool,
    },
    /// Create a new ext4 filesystem image.
    ///
    /// Wraps `mkfs.ext4` to create a properly formatted ext4 image,
    /// then verifies the result via FrankenFS parsing.
    Mkfs {
        /// Output path for the new image file.
        output: PathBuf,
        /// Image size in megabytes.
        #[arg(long, default_value = "64")]
        size_mb: u64,
        /// Block size in bytes (1024, 2048, or 4096).
        #[arg(long, default_value = "4096")]
        block_size: u32,
        /// Volume label.
        #[arg(long, default_value = "frankenfs")]
        label: String,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum DumpCommand {
    /// Dump superblock fields.
    Superblock {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
        /// Include a raw hex dump of the on-disk structure.
        #[arg(long)]
        hex: bool,
    },
    /// Dump one ext4 group descriptor or btrfs chunk.
    Group {
        /// Block group index (ext4) or chunk index (btrfs).
        group: u32,
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
        /// Include a raw hex dump of the on-disk structure.
        #[arg(long)]
        hex: bool,
    },
    /// Dump one ext4 or btrfs inode.
    Inode {
        /// Inode number.
        inode: u64,
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
        /// Include a raw hex dump of the on-disk structure.
        #[arg(long)]
        hex: bool,
    },
    /// Dump one ext4 inode's full extent tree.
    Extents {
        /// Inode number.
        inode: u64,
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
        /// Include raw hex dumps of extent nodes.
        #[arg(long)]
        hex: bool,
    },
    /// Dump one ext4 or btrfs directory inode's entries (and htree metadata if ext4 indexed).
    Dir {
        /// Inode number.
        inode: u64,
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
        /// Include raw hex dumps of directory data blocks.
        #[arg(long)]
        hex: bool,
    },
}

impl Command {
    const fn name(&self) -> &'static str {
        match self {
            Self::BenchEvidence => "bench-evidence",
            Self::Inspect { .. } => "inspect",
            Self::Read { .. } => "read",
            Self::RandRead { .. } => "randread",
            Self::WriteBench { .. } => "writebench",
            Self::LookupBench { .. } => "lookupbench",
            Self::CreateBench { .. } => "createbench",
            Self::CreateBenchCutoverGate { .. } => "createbench-cutover-gate",
            Self::ReadPoolCutoverGate { .. } => "read-pool-cutover-gate",
            Self::MkdirBench { .. } => "mkdirbench",
            Self::RmdirBench { .. } => "rmdirbench",
            Self::UnlinkBench { .. } => "unlinkbench",
            Self::RenameBench { .. } => "renamebench",
            Self::Walk { .. } => "walk",
            Self::MvccStats { .. } => "mvcc-stats",
            Self::Info { .. } => "info",
            Self::Dump { .. } => "dump",
            Self::Fsck { .. } => "fsck",
            Self::Repair { .. } => "repair",
            Self::Mount { .. } => "mount",
            Self::Scrub { .. } => "scrub",
            Self::Parity { .. } => "parity",
            Self::Evidence { .. } => "evidence",
            Self::Mkfs { .. } => "mkfs",
        }
    }
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
        quota_inodes: Option<Ext4QuotaInodes>,
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

#[derive(Debug, Serialize)]
struct MvccStatsOutput {
    block_versions: BlockVersionStatsOutput,
    ebr_versions: EbrVersionStatsOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    wal_replay: Option<WalReplayInfoOutput>,
}

#[derive(Debug, Serialize)]
struct BlockVersionStatsOutput {
    tracked_blocks: usize,
    max_chain_length: usize,
    chains_over_cap: usize,
    chains_over_critical: usize,
    chain_cap: Option<usize>,
    critical_chain_length: Option<usize>,
}

#[derive(Debug, Serialize)]
struct EbrVersionStatsOutput {
    #[serde(rename = "retired_versions")]
    retired: u64,
    #[serde(rename = "reclaimed_versions")]
    reclaimed: u64,
    #[serde(rename = "pending_versions")]
    pending: u64,
}

#[derive(Debug, Serialize)]
struct InfoOutput {
    filesystem: String,
    superblock: SuperblockInfoOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<GroupsInfoOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mvcc: Option<MvccInfoOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repair: Option<RepairInfoOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    journal: Option<JournalInfoOutput>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum GroupsInfoOutput {
    Ext4 { entries: Vec<Ext4GroupInfoOutput> },
    Btrfs { entries: Vec<BtrfsGroupInfoOutput> },
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum SuperblockInfoOutput {
    Ext4 {
        uuid: String,
        label: String,
        block_size: u32,
        blocks_total: u64,
        blocks_free: u64,
        blocks_reserved: u64,
        inodes_total: u32,
        inodes_free: u32,
        blocks_per_group: u32,
        inodes_per_group: u32,
        groups_count: u32,
        mount_count: u16,
        max_mount_count: u16,
        state_flags: Vec<String>,
        feature_compat: String,
        feature_incompat: String,
        feature_ro_compat: String,
        checksum_type: String,
        checksum_seed: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        quota_inodes: Option<Ext4QuotaInodes>,
        mtime: u32,
        wtime: u32,
        lastcheck: u32,
        mkfs_time: u32,
    },
    Btrfs {
        fsid: String,
        label: String,
        sectorsize: u32,
        nodesize: u32,
        generation: u64,
        total_bytes: u64,
        bytes_used: u64,
        bytes_free: u64,
        num_devices: u64,
        csum_type: String,
        compat_flags_hex: String,
        compat_ro_flags_hex: String,
        incompat_flags_hex: String,
    },
}

#[derive(Debug, Serialize)]
struct Ext4GroupInfoOutput {
    group: u32,
    block_start: u64,
    block_end_inclusive: u64,
    free_blocks: u32,
    inode_start: u64,
    inode_end_inclusive: u64,
    free_inodes: u32,
    flags_raw: u16,
    flags: Vec<String>,
}

/// Maximum ext4 groups expanded into detailed `info --groups` output.
///
/// The plain superblock summary still reports the raw group count. This cap
/// protects the optional per-group descriptor expansion from corrupted geometry
/// that would otherwise allocate or iterate billions of group entries.
const MAX_EXT4_INFO_GROUPS: u32 = 65_536;

#[derive(Debug, Clone, Serialize)]
struct BtrfsGroupInfoOutput {
    chunk_index: u32,
    logical_start: u64,
    logical_end_inclusive: u64,
    logical_bytes: u64,
    chunk_type_raw: u64,
    chunk_type_flags: Vec<String>,
    owner: u64,
    stripe_len: u64,
    sector_size: u32,
    stripe_count: u16,
    stripes: Vec<BtrfsStripeInfoOutput>,
}

#[derive(Debug, Clone, Serialize)]
struct BtrfsStripeInfoOutput {
    stripe_index: u16,
    devid: u64,
    physical_start: u64,
    physical_end_inclusive: u64,
    device_uuid: String,
}

#[derive(Debug, Serialize)]
struct MvccInfoOutput {
    current_commit_seq: u64,
    active_snapshot_count: usize,
    oldest_active_snapshot: Option<u64>,
    total_versioned_blocks: usize,
    max_chain_depth: usize,
    average_chain_depth: String,
    blocks_pending_gc: u64,
    ssi_conflict_count: Option<u64>,
    abort_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wal_replay: Option<WalReplayInfoOutput>,
}

/// WAL replay health telemetry for CLI output.
#[derive(Debug, Serialize)]
struct WalReplayInfoOutput {
    /// Classified replay outcome (Clean, EmptyLog, TruncatedTail, CorruptTail, etc.).
    outcome: String,
    /// Whether the replay completed without discarded records.
    is_clean: bool,
    /// Number of commits successfully replayed.
    commits_replayed: u64,
    /// Number of block versions restored.
    versions_replayed: u64,
    /// Number of WAL records discarded (corrupt or truncated).
    records_discarded: u64,
    /// Byte offset where valid WAL data ends.
    wal_valid_bytes: u64,
    /// Total WAL file size in bytes.
    wal_total_bytes: u64,
    /// Whether a checkpoint was used during recovery.
    used_checkpoint: bool,
    /// Highest commit sequence from checkpoint, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint_commit_seq: Option<u64>,
}

#[derive(Debug, Serialize)]
struct RepairInfoOutput {
    configured_overhead_ratio: f64,
    metrics_available: bool,
    note: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups_total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups_fresh: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups_stale: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups_untracked: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
struct InfoCommandOptions {
    sections: InfoSections,
    json: bool,
}

#[derive(Debug, Clone, Copy)]
struct InfoSections(u8);

impl InfoSections {
    const GROUPS: u8 = 1 << 0;
    const MVCC: u8 = 1 << 1;
    const REPAIR: u8 = 1 << 2;
    const JOURNAL: u8 = 1 << 3;

    const fn empty() -> Self {
        Self(0)
    }

    const fn with_groups(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::GROUPS;
        }
        self
    }

    const fn with_mvcc(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::MVCC;
        }
        self
    }

    const fn with_repair(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::REPAIR;
        }
        self
    }

    const fn with_journal(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::JOURNAL;
        }
        self
    }

    const fn groups(self) -> bool {
        (self.0 & Self::GROUPS) != 0
    }

    const fn mvcc(self) -> bool {
        (self.0 & Self::MVCC) != 0
    }

    const fn repair(self) -> bool {
        (self.0 & Self::REPAIR) != 0
    }

    const fn journal(self) -> bool {
        (self.0 & Self::JOURNAL) != 0
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum JournalInfoOutput {
    Ext4 {
        journal_inode: u32,
        external_journal_dev: u32,
        journal_uuid: String,
        journal_size_bytes: Option<u64>,
        replayed_transactions: u32,
        replayed_blocks: u64,
        scanned_blocks: u64,
        descriptor_blocks: u64,
        commit_blocks: u64,
        revoke_blocks: u64,
        skipped_revoked_blocks: u64,
        incomplete_transactions: u64,
    },
    Unsupported {
        reason: String,
    },
}

#[derive(Debug, Serialize)]
struct DumpSuperblockOutput {
    filesystem: String,
    superblock: SuperblockInfoOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_hex: Option<String>,
}

#[derive(Debug, Serialize)]
struct DumpGroupOutput {
    filesystem: String,
    group: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    descriptor: Option<Ext4GroupDesc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    btrfs_chunk: Option<BtrfsGroupInfoOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_hex: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DumpInodeOutput {
    filesystem: String,
    inode: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ext4_parsed: Option<Ext4Inode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    btrfs_parsed: Option<DumpBtrfsInodeParsedOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_hex: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DumpBtrfsInodeParsedOutput {
    size: u64,
    nbytes: u64,
    nlink: u32,
    uid: u32,
    gid: u32,
    mode: u32,
    rdev: u64,
    atime_sec: u64,
    atime_nsec: u32,
    ctime_sec: u64,
    ctime_nsec: u32,
    mtime_sec: u64,
    mtime_nsec: u32,
    otime_sec: u64,
    otime_nsec: u32,
}

impl From<BtrfsInodeItem> for DumpBtrfsInodeParsedOutput {
    fn from(value: BtrfsInodeItem) -> Self {
        Self {
            size: value.size,
            nbytes: value.nbytes,
            nlink: value.nlink,
            uid: value.uid,
            gid: value.gid,
            mode: value.mode,
            rdev: value.rdev,
            atime_sec: value.atime_sec,
            atime_nsec: value.atime_nsec,
            ctime_sec: value.ctime_sec,
            ctime_nsec: value.ctime_nsec,
            mtime_sec: value.mtime_sec,
            mtime_nsec: value.mtime_nsec,
            otime_sec: value.otime_sec,
            otime_nsec: value.otime_nsec,
        }
    }
}

#[derive(Debug, Serialize)]
struct DumpExtentOutput {
    filesystem: String,
    inode: u64,
    root_depth: u16,
    nodes: Vec<DumpExtentNodeOutput>,
    flattened_extents: Vec<DumpExtentEntryOutput>,
}

#[derive(Debug, Serialize)]
struct DumpExtentNodeOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    source_block: Option<u64>,
    header: Ext4ExtentHeader,
    #[serde(flatten)]
    node: DumpExtentNodeKindOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_hex: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "node_kind", rename_all = "lowercase")]
enum DumpExtentNodeKindOutput {
    Leaf { extents: Vec<DumpExtentEntryOutput> },
    Index { indexes: Vec<Ext4ExtentIndex> },
}

#[derive(Debug, Serialize)]
struct DumpExtentEntryOutput {
    logical_block: u32,
    physical_start: u64,
    physical_end_inclusive: u64,
    raw_len: u16,
    actual_len: u16,
    initialized: bool,
}

#[derive(Debug, Serialize)]
struct DumpDirOutput {
    filesystem: String,
    inode: u64,
    entries: Vec<DumpDirEntryOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    htree: Option<DumpDxRootOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_hex_blocks: Option<Vec<DumpHexBlockOutput>>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DumpDirEntryOutput {
    index: usize,
    inode: u64,
    rec_len: u32,
    file_type: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct DumpDxRootOutput {
    hash_version: u8,
    indirect_levels: u8,
    entries: Vec<DumpDxEntryOutput>,
}

#[derive(Debug, Serialize)]
struct DumpDxEntryOutput {
    hash: u32,
    block: u32,
}

#[derive(Debug, Serialize)]
struct DumpHexBlockOutput {
    logical_block: u32,
    physical_block: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    item_kind: Option<String>,
    hex: String,
}

#[derive(Debug, Clone, Copy)]
struct FsckCommandOptions {
    flags: FsckFlags,
    block_group: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
struct FsckFlags(u8);

impl FsckFlags {
    const REPAIR: u8 = 1 << 0;
    const FORCE: u8 = 1 << 1;
    const VERBOSE: u8 = 1 << 2;
    const JSON: u8 = 1 << 3;

    const fn empty() -> Self {
        Self(0)
    }

    const fn with_repair(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::REPAIR;
        }
        self
    }

    const fn with_force(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::FORCE;
        }
        self
    }

    const fn with_verbose(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::VERBOSE;
        }
        self
    }

    const fn with_json(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::JSON;
        }
        self
    }

    const fn repair(self) -> bool {
        (self.0 & Self::REPAIR) != 0
    }

    const fn force(self) -> bool {
        (self.0 & Self::FORCE) != 0
    }

    const fn verbose(self) -> bool {
        (self.0 & Self::VERBOSE) != 0
    }

    const fn json(self) -> bool {
        (self.0 & Self::JSON) != 0
    }
}

#[derive(Debug, Serialize)]
struct FsckOutput {
    filesystem: String,
    scope: FsckScopeOutput,
    phases: Vec<FsckPhaseOutput>,
    scrub: FsckScrubOutput,
    repair_status: FsckRepairStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    repair_coordination: Option<RepairCoordinationOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ext4_recovery: Option<Ext4RecoveryOutput>,
    outcome: FsckOutcome,
    exit_code: i32,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FsckScopeOutput {
    Full,
    Ext4BlockGroup {
        group: u32,
        start_block: u64,
        block_count: u64,
    },
    BtrfsBlockGroup {
        group: u32,
        logical_start: u64,
        logical_bytes: u64,
        start_block: u64,
        block_count: u64,
    },
}

#[derive(Debug, Serialize)]
struct FsckPhaseOutput {
    phase: String,
    status: String,
    detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum FsckRepairStatus {
    NotRequested,
    RequestedPerformed,
    RequestedNotPerformed,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum FsckOutcome {
    Clean,
    ErrorsFound,
}

#[derive(Debug, Serialize)]
pub struct FsckScrubOutput {
    pub scanned: u64,
    pub corrupt: u64,
    pub error_or_higher: u64,
    pub io_error: u64,
}

#[derive(Debug, Serialize)]
pub struct Ext4RecoveryOutput {
    pub recovery_performed: bool,
    #[serde(flatten)]
    pub crash_recovery: CrashRecoveryOutcome,
}

#[derive(Debug, Clone, Copy)]
pub struct RepairCommandOptions {
    pub flags: RepairFlags,
    pub block_group: Option<u32>,
    pub max_threads: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
pub struct RepairFlags(u8);

impl RepairFlags {
    const FULL_SCRUB: u8 = 1 << 0;
    const REBUILD_SYMBOLS: u8 = 1 << 1;
    const VERIFY_ONLY: u8 = 1 << 2;
    const JSON: u8 = 1 << 3;

    const fn empty() -> Self {
        Self(0)
    }

    const fn with_full_scrub(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::FULL_SCRUB;
        }
        self
    }

    const fn with_rebuild_symbols(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::REBUILD_SYMBOLS;
        }
        self
    }

    const fn with_verify_only(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::VERIFY_ONLY;
        }
        self
    }

    const fn with_json(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::JSON;
        }
        self
    }

    const fn full_scrub(self) -> bool {
        (self.0 & Self::FULL_SCRUB) != 0
    }

    const fn rebuild_symbols(self) -> bool {
        (self.0 & Self::REBUILD_SYMBOLS) != 0
    }

    const fn verify_only(self) -> bool {
        (self.0 & Self::VERIFY_ONLY) != 0
    }

    const fn json(self) -> bool {
        (self.0 & Self::JSON) != 0
    }
}

#[derive(Debug, Serialize)]
pub struct RepairOutput {
    pub filesystem: String,
    pub scope: RepairScopeOutput,
    pub action: RepairActionOutput,
    pub scrub: RepairScrubOutput,
    pub repair_coordination: RepairCoordinationOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext4_recovery: Option<Ext4RecoveryOutput>,
    pub exit_code: i32,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RepairScopeOutput {
    Full,
    Ext4BlockGroup {
        group: u32,
        start_block: u64,
        block_count: u64,
    },
    BtrfsBlockGroup {
        group: u32,
        logical_start: u64,
        logical_bytes: u64,
        start_block: u64,
        block_count: u64,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairActionOutput {
    VerifyOnly,
    RepairBlocked,
    RepairRequested,
    NoCorruptionDetected,
}

#[derive(Debug, Serialize)]
pub struct RepairScrubOutput {
    pub scanned: u64,
    pub corrupt: u64,
    pub error_or_higher: u64,
    pub io_error: u64,
}

// ── Main ────────────────────────────────────────────────────────────────────

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_lines)]
fn run() -> Result<()> {
    let cli = Cli::parse();
    let log_format = init_logging(cli.log_format)?;
    let command_name = cli.command.name();
    let run_span = info_span!(
        target: "ffs::cli",
        "command",
        command = command_name,
        log_format = log_format.as_str()
    );
    let _run_guard = run_span.enter();
    let started = Instant::now();

    let evidence_must_be_first = matches!(
        &cli.command,
        Command::BenchEvidence
            | Command::CreateBenchCutoverGate { .. }
            | Command::ReadPoolCutoverGate { .. }
            | Command::Read {
                bench_evidence: true,
                ..
            }
    );
    if !evidence_must_be_first {
        info!(
            target: "ffs::cli",
            command = command_name,
            log_format = log_format.as_str(),
            "command_start"
        );
    }

    let result = match cli.command {
        Command::BenchEvidence => bench_evidence_cmd(),
        Command::Inspect {
            image,
            json,
            subvolumes,
            snapshots,
        } => inspect(&image, json, subvolumes, snapshots),
        Command::Read {
            image,
            path,
            discard,
            bench_evidence,
        } => read_file_cmd(&image, &path, discard, bench_evidence),
        Command::RandRead {
            image,
            path,
            count,
            size,
            parallel,
            seed,
        } => randread_cmd(&image, &path, count, size, parallel, seed),
        Command::WriteBench {
            image,
            path,
            count,
            size,
            random,
            seed,
            create,
        } => writebench_cmd(&image, &path, count, size, random, seed, create),
        Command::LookupBench {
            image,
            dir,
            count,
            seed,
        } => lookupbench_cmd(&image, &dir, count, seed),
        Command::CreateBench {
            image,
            dir,
            count,
            threads,
            rounds,
        } => createbench_cmd(&image, &dir, count, threads, rounds),
        Command::CreateBenchCutoverGate {
            aa_lhs_image,
            aa_rhs_image,
            ab_base_image,
            ab_candidate_image,
            dir,
            count,
            threads,
            rounds,
        } => createbench_cutover_gate_cmd(
            [&aa_lhs_image, &aa_rhs_image],
            [&ab_base_image, &ab_candidate_image],
            &dir,
            count,
            threads,
            rounds,
        ),
        Command::ReadPoolCutoverGate {
            fixture,
            blocks,
            rounds,
        } => read_pool_cutover_gate_cmd(&fixture, blocks, rounds),
        Command::MkdirBench { image, dir, count } => mkdirbench_cmd(&image, &dir, count),
        Command::RmdirBench { image, dir, count } => rmdirbench_cmd(&image, &dir, count),
        Command::UnlinkBench { image, dir, count } => unlinkbench_cmd(&image, &dir, count),
        Command::RenameBench { image, dir, count } => renamebench_cmd(&image, &dir, count),
        Command::Walk {
            image,
            no_stat,
            parallel,
            read_data,
        } => walk_cmd(&image, no_stat, parallel, read_data),
        Command::MvccStats { image, json } => mvcc_stats_cmd(&image, json),
        Command::Info {
            image,
            groups,
            mvcc,
            repair,
            journal,
            json,
        } => info_cmd(
            &image,
            InfoCommandOptions {
                sections: InfoSections::empty()
                    .with_groups(groups)
                    .with_mvcc(mvcc)
                    .with_repair(repair)
                    .with_journal(journal),
                json,
            },
        ),
        Command::Dump { command } => dump_cmd(&command),
        Command::Fsck {
            image,
            repair,
            force,
            verbose,
            block_group,
            json,
        } => fsck_cmd(
            &image,
            FsckCommandOptions {
                flags: FsckFlags::empty()
                    .with_repair(repair)
                    .with_force(force)
                    .with_verbose(verbose)
                    .with_json(json),
                block_group,
            },
        ),
        Command::Repair {
            image,
            full_scrub,
            block_group,
            rebuild_symbols,
            verify_only,
            max_threads,
            json,
        } => cmd_repair::repair_cmd(
            &image,
            RepairCommandOptions {
                flags: RepairFlags::empty()
                    .with_full_scrub(full_scrub)
                    .with_rebuild_symbols(rebuild_symbols)
                    .with_verify_only(verify_only)
                    .with_json(json),
                block_group,
                max_threads,
            },
        ),
        Command::Mount {
            image,
            mountpoint,
            runtime_mode,
            managed_unmount_timeout_secs,
            adaptive_runtime,
            adaptive_runtime_manifest,
            adaptive_runtime_summary_json,
            adaptive_runtime_summary_md,
            console,
            console_json,
            console_summary,
            allow_other,
            rw,
            writeback_cache,
            writeback_cache_gate,
            writeback_cache_ordering_oracle,
            writeback_cache_crash_replay_oracle,
            background_scrub,
            no_background_scrub,
            background_scrub_interval_secs,
            background_scrub_ledger,
            background_repair,
            native,
            ext4_data_err_abort,
            ext4_nojournal_checksum,
            subvol,
            snapshot,
            btrfs_rw_ephemeral_ok,
        } => {
            let btrfs_mount_selection = parse_btrfs_mount_selection(subvol, snapshot)?;
            let background_scrub = MountBackgroundScrubConfig::resolve(
                MountBackgroundScrubRequest::new(
                    MountAccessMode::from_read_write(rw),
                    MountBackgroundScrubMode::from_cli(background_scrub, no_background_scrub),
                    MountBackgroundRepairMode::from_cli(background_repair),
                ),
                background_scrub_interval_secs,
                background_scrub_ledger,
            )?;
            let console = mount_console::MountConsoleConfig::from_cli(
                console,
                console_json,
                console_summary,
            )?;
            console.reject_unsupported_runtime(runtime_mode == MountRuntimeMode::Standard)?;
            mount_cmd(
                &image,
                &mountpoint,
                &MountCmdOptions {
                    allow_other,
                    read_write: rw,
                    mount_mode: if native {
                        MountMode::Native
                    } else {
                        MountMode::Compat
                    },
                    btrfs_mount_selection,
                    ext4_data_err_policy: if ext4_data_err_abort {
                        Ext4DataErrPolicy::Abort
                    } else {
                        Ext4DataErrPolicy::Ignore
                    },
                    ext4_verify_journal_checksums: !ext4_nojournal_checksum,
                    btrfs_rw_ephemeral_ok,
                    runtime: MountRuntimeConfig {
                        mode: runtime_mode,
                        managed_unmount_timeout_secs,
                    },
                    adaptive_runtime: MountAdaptiveRuntimeConfig::from_cli(
                        adaptive_runtime,
                        adaptive_runtime_manifest,
                    ),
                    adaptive_runtime_summary: MountAdaptiveRuntimeSummaryConfig::from_cli(
                        adaptive_runtime_summary_json,
                        adaptive_runtime_summary_md,
                    ),
                    background_scrub,
                    writeback_cache: MountWritebackCacheConfig::from_cli(
                        writeback_cache,
                        writeback_cache_gate,
                        writeback_cache_ordering_oracle,
                        writeback_cache_crash_replay_oracle,
                    ),
                    console,
                },
            )
        }
        Command::Scrub { image, json } => scrub_cmd(&image, json),
        Command::Parity { json } => parity(json),
        Command::Evidence {
            ledger,
            json,
            event_type,
            tail,
            block_group,
            preset,
            summary,
        } => cmd_evidence::evidence_cmd(
            &ledger,
            json,
            event_type.as_deref(),
            tail,
            preset.as_deref(),
            block_group,
            summary,
        ),
        Command::Mkfs {
            output,
            size_mb,
            block_size,
            label,
            json,
        } => mkfs_cmd(&output, size_mb, block_size, &label, json),
    };

    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    if let Err(err) = &result {
        error!(
            target: "ffs::cli",
            command = command_name,
            duration_us,
            error = %err,
            "command_failed"
        );
    } else {
        info!(
            target: "ffs::cli",
            command = command_name,
            duration_us,
            "command_succeeded"
        );
    }

    result
}

fn inspect(path: &PathBuf, json: bool, list_subvolumes: bool, list_snapshots: bool) -> Result<()> {
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

fn build_wal_replay_info(open_fs: &OpenFs) -> Option<WalReplayInfoOutput> {
    open_fs.mvcc_wal_recovery().map(|report| {
        let outcome_str = format!("{:?}", report.outcome);
        let is_clean = report.outcome.is_clean();
        WalReplayInfoOutput {
            outcome: outcome_str,
            is_clean,
            commits_replayed: report.commits_replayed,
            versions_replayed: report.versions_replayed,
            records_discarded: report.records_discarded,
            wal_valid_bytes: report.wal_valid_bytes,
            wal_total_bytes: report.wal_total_bytes,
            used_checkpoint: report.used_checkpoint,
            checkpoint_commit_seq: report.checkpoint_commit_seq,
        }
    })
}

fn print_wal_replay_info(wal: &WalReplayInfoOutput, indent: &str) {
    println!("{indent}outcome: {}", wal.outcome);
    println!("{indent}is_clean: {}", wal.is_clean);
    println!("{indent}commits_replayed: {}", wal.commits_replayed);
    println!("{indent}versions_replayed: {}", wal.versions_replayed);
    println!("{indent}records_discarded: {}", wal.records_discarded);
    println!("{indent}wal_valid_bytes: {}", wal.wal_valid_bytes);
    println!("{indent}wal_total_bytes: {}", wal.wal_total_bytes);
    println!("{indent}used_checkpoint: {}", wal.used_checkpoint);
    if let Some(cp_seq) = wal.checkpoint_commit_seq {
        println!("{indent}checkpoint_commit_seq: {cp_seq}");
    }
}

/// Emit structured log event for WAL recovery telemetry.
///
/// The `tracing::info!` macro requires a string literal for `target:`, so callers
/// should invoke this macro-style helper at the call site instead. This function
/// provides a fallback using a generic target for contexts where the exact
/// target is not critical.
fn log_wal_recovery_telemetry(wal: &WalReplayInfoOutput) {
    info!(
        target: "ffs::cli",
        outcome = %wal.outcome,
        is_clean = wal.is_clean,
        commits_replayed = wal.commits_replayed,
        versions_replayed = wal.versions_replayed,
        records_discarded = wal.records_discarded,
        wal_valid_bytes = wal.wal_valid_bytes,
        wal_total_bytes = wal.wal_total_bytes,
        used_checkpoint = wal.used_checkpoint,
        "wal_recovery_telemetry"
    );
}

fn read_file_cmd(
    path: &PathBuf,
    file_path: &str,
    discard: bool,
    bench_evidence: bool,
) -> Result<()> {
    if bench_evidence {
        if !discard {
            bail!("--bench-evidence requires --discard");
        }
        // This runs inside the exact child process that performs the timed read.
        // Keep it before the timer so hashing the ELF proves identity without
        // contaminating the read wall-time decision.
        bench_evidence_cmd()?;
    }
    let bench_started = bench_evidence.then(Instant::now);

    // The per-stream output buffer size. A large buffer is a fresh anon
    // allocation whose pages the kernel faults + zero-fills on first write
    // (bd-zvn7r: 28.91% of cold-read *cycles* at 64 MiB = ~16,384 faulted pages).
    // The read parallelism comes from the engine's internal 128 KiB chunking
    // (`PARALLEL_READ_CHUNK_BLOCKS`), NOT this outer buffer — at 32 MiB the read
    // still issues 256 parallel 128 KiB jobs per `read_into`, saturating the
    // bounded read pool many times over, so shrinking 64→32 MiB halves the
    // per-stream faulted pages without losing overlap. Measured (cold, in-tree,
    // drop_caches/rep, 30 interleaved reps, 128 MiB ext4 read; `duration_us`):
    // 64 MiB 48.16 ms vs **32 MiB 46.26 ms = 1.04x**, above the identical-arm null
    // floor (64a vs 64b = 1.01x); faults 19,806→11,603; RSS 68→35 MiB. Byte-
    // identical output (sha256 parity for every size). Below ~16 MiB the extra
    // `read_into` boundaries lose more overlap than the faults save (8 MiB 0.98x,
    // 4 MiB 0.88x, 2 MiB 0.73x), so 32 MiB is the plateau's low-fault edge. The
    // win only appears when device I/O does not hide the fault work, so on a
    // slow-I/O device it is neutral, never a regression. `FFS_STREAM_CHUNK_MB`
    // overrides for per-device tuning.
    let stream_chunk: u32 = std::env::var("FFS_STREAM_CHUNK_MB")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|&mb| mb > 0)
        .map_or(32 * 1024 * 1024, |mb| mb.saturating_mul(1024 * 1024));

    use std::io::Write;
    let cx = cli_cx();
    let open_fs = OpenFs::open(&cx, path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;

    // Flavor-agnostic path resolution: descend from the FUSE root (InodeNumber(1),
    // mapped internally to ext4 inode 2 / the btrfs subvolume root) via `lookup`, so
    // `read` works on BOTH ext4 and btrfs images. read/lookup/getattr are
    // self-scoping (with_latest_scope), so no long-lived scope is held.
    let mut ino = InodeNumber(1);
    for comp in file_path.split('/').filter(|c| !c.is_empty()) {
        let attr = open_fs
            .lookup(&cx, ino, std::ffi::OsStr::new(comp))
            .with_context(|| format!("failed to resolve {file_path} at component {comp:?}"))?;
        ino = attr.ino;
    }
    let size = open_fs
        .getattr(&cx, ino)
        .with_context(|| format!("failed to stat {file_path}"))?
        .size;

    // Stream the file in chunks through the read engine (each `read` chunk uses the
    // chunked-parallel engine internally); write to stdout, or discard for perf
    // probes (avoids materializing the whole file at once).
    let mut out = std::io::stdout();
    let mut off: u64 = 0;
    let mut total: u64 = 0;
    // Reuse one chunk buffer across the whole stream via read_into, so a
    // multi-chunk file does not allocate (and mmap/page-fault/munmap) a fresh
    // multi-MiB Vec per chunk (bd-2x68s). Sized to the first chunk's need.
    let first = u32::try_from(size.min(u64::from(stream_chunk))).unwrap_or(stream_chunk);
    let mut buf: Vec<u8> = vec![0_u8; first.max(1) as usize];
    while off < size {
        let want = u32::try_from((size - off).min(u64::from(stream_chunk))).unwrap_or(stream_chunk);
        let n = open_fs
            .read_into(&cx, ino, off, &mut buf[..want as usize])
            .with_context(|| format!("failed to read {file_path} at {off}"))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        off += n as u64;
        if !discard {
            out.write_all(&buf[..n])
                .with_context(|| "failed to write file data to stdout".to_string())?;
        }
    }
    if discard {
        eprintln!("read {total} bytes from {file_path}");
    }
    if let Some(started) = bench_started {
        println!(
            "bd_b9dug_read_observation,path={file_path},bytes={total},duration_us={},\
gate_metric=read_wall_us",
            started.elapsed().as_micros()
        );
    }
    Ok(())
}

/// Random-read benchmark (no FUSE): open once, resolve `file_path`, then issue
/// `count` random page-aligned reads of `size` bytes each via the positioned
/// read engine (`read_into`). Reports the engine time (excluding open/resolve),
/// throughput and IOPS as a JSON-able `info!` line, for a head-to-head against
/// a kernel random `pread` loop. Random access does one extent-map lookup per
/// read (sequential `read` coalesces runs), so this exercises the per-lookup
/// path (e.g. the `ffs-extent` cache) that sequential reads hide (bd-7f6yr).
fn createbench_cmd(
    path: &PathBuf,
    dir_path: &str,
    count: usize,
    threads: usize,
    rounds: usize,
) -> Result<()> {
    let cx = cli_cx();
    let mut open_fs = OpenFs::open(&cx, path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    open_fs
        .enable_writes(&cx)
        .with_context(|| "failed to enable writes (alloc state)".to_string())?;
    // bd-bhh0i cutover A/B: FFS_BHH0I_SHARDED=1 routes create/mkdir through the
    // lock-free sharded allocator (no whole-state write lock). Set BEFORE the setup
    // mkdirs so they too go through the sharded structure (else the free-states
    // diverge). No-op unless built with `--features bhh0i_sharded_alloc`.
    #[cfg(feature = "bhh0i_sharded_alloc")]
    if std::env::var_os("FFS_BHH0I_SHARDED").is_some() {
        open_fs.set_bhh0i_sharded_ops(true);
        eprintln!("createbench: bd-bhh0i sharded create path ENABLED (FFS_BHH0I_SHARDED=1)");
    }
    let mut parent = InodeNumber(1);
    for comp in dir_path.split('/').filter(|c| !c.is_empty()) {
        let attr = open_fs
            .lookup(&cx, parent, std::ffi::OsStr::new(comp))
            .with_context(|| format!("failed to resolve {dir_path} at component {comp:?}"))?;
        parent = attr.ino;
    }
    // Low-variance mode (`--rounds N > 1`). Everything below the historical
    // single-round paths, so `--rounds 1` reaches them untouched.
    if rounds > 1 {
        return createbench_rounds(&cx, &open_fs, parent, count, threads, rounds);
    }

    // Parallel mode: each thread creates in its own subdir, so the only shared
    // contention is the MVCC commit lock — isolating whether writes scale.
    if threads > 1 {
        let mut tdirs: Vec<InodeNumber> = Vec::with_capacity(threads);
        for t in 0..threads {
            let attr = open_fs
                .mkdir(&cx, parent, std::ffi::OsStr::new(&format!("t{t}")), 0o755, 0, 0)
                .with_context(|| format!("failed to mkdir t{t}"))?;
            tdirs.push(attr.ino);
        }
        let per = count / threads;
        let started = Instant::now();
        std::thread::scope(|s| {
            for (t, &tdir) in tdirs.iter().enumerate() {
                let fs = &open_fs;
                let cxr = &cx;
                s.spawn(move || {
                    for i in 0..per {
                        let name = format!("cb_{t}_{i:08}");
                        fs.create(cxr, tdir, std::ffi::OsStr::new(&name), 0o644, 0, 0)
                            .unwrap_or_else(|e| panic!("create {name}: {e:?}"));
                    }
                });
            }
        });
        open_fs
            .sync_all_to_device(&cx)
            .with_context(|| "failed to flush creates".to_string())?;
        let elapsed = started.elapsed();
        let total = (per * threads) as f64;
        let cps = total / elapsed.as_secs_f64().max(1e-9);
        eprintln!(
            "createbench: {} creates / {threads} threads in {} us = {} creates/s",
            per * threads,
            elapsed.as_micros(),
            cps as u64
        );
        return Ok(());
    }
    let started = Instant::now();
    let mut created = 0_u64;
    for i in 0..count {
        let name = format!("cb_{i:08}");
        open_fs
            .create(&cx, parent, std::ffi::OsStr::new(&name), 0o644, 0, 0)
            .with_context(|| format!("failed to create {name}"))?;
        created += 1;
    }
    // Persist the committed creates to the image (the step a real mount does at
    // umount). Without this the creates live only in the in-memory MVCC overlay
    // and a re-open / kernel mount sees nothing — so the throughput would not be
    // a valid persisted head-to-head vs a kernel RW mount (bd-c2bvq).
    open_fs
        .sync_all_to_device(&cx)
        .with_context(|| "failed to flush created files to image".to_string())?;
    let elapsed = started.elapsed();
    let duration_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
    let secs = elapsed.as_secs_f64().max(1e-9);
    let creates_per_s = (count as f64) / secs;
    info!(
        target: "ffs::cli::createbench",
        count,
        created,
        duration_us,
        creates_per_s = creates_per_s as u64,
        "createbench_done"
    );
    eprintln!(
        "createbench: {count} creates in {dir_path} -> {created} created in {duration_us} us = {} creates/s",
        creates_per_s as u64
    );
    Ok(())
}

/// Repeat the create phase in one process against one image, timing each round's
/// creates alone and flushing once at the end.
///
/// Why this exists: the historical shape times creates AND a whole-image
/// `sync_all_to_device`, and needs a fresh image per run because the `t{t}`
/// thread subdirs collide on reuse. Both make the measurement page-cache and
/// writeback bound. On the bd-bhh0i cutover gate that produced a 1-thread
/// negative control — where the lever under test is provably inert — swinging
/// **52%**, against a ~6% effect under test. An instrument whose null moves 52%
/// cannot decide 6%.
///
/// Rounds share one image so no copy is needed, and the flush is reported
/// separately so it stops contributing variance to the statistic.
///
/// Rounds are NOT independent: the filesystem fills monotonically, so round N
/// starts fuller than round 1. That is why per-round lines are printed rather
/// than a single aggregate — the caller alternates arms ACROSS rounds, which
/// cancels the fill trend to first order, and can inspect it directly.
fn sha256_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(64), |mut acc, byte| {
            use std::fmt::Write as _;
            let _ = write!(&mut acc, "{byte:02x}");
            acc
        })
}

fn file_sha256(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("open {} for SHA-256", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0_u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("read {} for SHA-256", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(sha256_hex(&hasher.finalize()))
}

/// Hash equal-size A/A and A/B input files in round-robin chunks. Sequentially
/// scanning multi-gigabyte images immediately before the first observation
/// gives the last path a page-cache recency advantage; interleaving bounds that
/// skew to one 64 KiB chunk while still proving complete-byte identity.
fn interleaved_file_sha256(paths: [&Path; 4]) -> Result<[String; 4]> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        files.push(
            std::fs::File::open(path)
                .with_context(|| format!("open {} for interleaved SHA-256", path.display()))?,
        );
    }
    let mut hashers: [Sha256; 4] = std::array::from_fn(|_| Sha256::new());
    let mut buffers: [Vec<u8>; 4] = std::array::from_fn(|_| vec![0_u8; 64 * 1024]);
    loop {
        let mut any_read = false;
        for index in 0..paths.len() {
            let n = files[index].read(&mut buffers[index]).with_context(|| {
                format!("read {} for interleaved SHA-256", paths[index].display())
            })?;
            if n != 0 {
                hashers[index].update(&buffers[index][..n]);
                any_read = true;
            }
        }
        if !any_read {
            break;
        }
    }
    Ok(hashers.map(|hasher| sha256_hex(&hasher.finalize())))
}

/// SHA-256 of the executing binary, hashed in-process from `current_exe()`.
fn elf_self_sha256() -> Result<String> {
    let exe = std::env::current_exe().context("current_exe")?;
    file_sha256(&exe).with_context(|| format!("self-hash executing ELF {}", exe.display()))
}

#[derive(Clone, Copy)]
struct BootstrapMedianCi {
    median: f64,
    low: f64,
    high: f64,
}

fn median(mut values: Vec<f64>) -> f64 {
    assert!(!values.is_empty(), "median requires at least one sample");
    values.sort_by(f64::total_cmp);
    let midpoint = values.len() / 2;
    if values.len() % 2 == 0 {
        values[midpoint - 1].midpoint(values[midpoint])
    } else {
        values[midpoint]
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

/// Deterministic paired bootstrap over log ratios. The cutover verdict consumes
/// only this median confidence interval; CV is neither computed nor consulted.
fn bootstrap_median_ci(log_ratios: &[f64]) -> BootstrapMedianCi {
    const RESAMPLES: usize = 20_000;
    assert!(
        !log_ratios.is_empty(),
        "bootstrap median CI requires paired samples"
    );
    let mut state =
        0xB440_10C1_2026_0726_u64 ^ u64::try_from(log_ratios.len()).expect("length fits u64");
    let mut bootstrapped = Vec::with_capacity(RESAMPLES);
    for _ in 0..RESAMPLES {
        let mut sample = Vec::with_capacity(log_ratios.len());
        for _ in log_ratios {
            let draw =
                splitmix64(&mut state) % u64::try_from(log_ratios.len()).expect("length fits u64");
            sample.push(log_ratios[usize::try_from(draw).expect("draw fits usize")]);
        }
        bootstrapped.push(median(sample));
    }
    bootstrapped.sort_by(f64::total_cmp);
    let low_index = RESAMPLES.saturating_mul(25) / 1000;
    let high_index = RESAMPLES
        .saturating_mul(975)
        .div_ceil(1000)
        .saturating_sub(1);
    BootstrapMedianCi {
        median: median(log_ratios.to_vec()).exp(),
        low: bootstrapped[low_index].exp(),
        high: bootstrapped[high_index].exp(),
    }
}

#[cfg(target_arch = "x86_64")]
fn print_codegen_isa() {
    println!(
        "codegen_isa,target_arch=x86_64,compile_sse2={},compile_sse4_2={},compile_avx2={},compile_fma={},runtime_sse4_2={},runtime_avx2={},runtime_fma={}",
        cfg!(target_feature = "sse2"),
        cfg!(target_feature = "sse4.2"),
        cfg!(target_feature = "avx2"),
        cfg!(target_feature = "fma"),
        std::is_x86_feature_detected!("sse4.2"),
        std::is_x86_feature_detected!("avx2"),
        std::is_x86_feature_detected!("fma"),
    );
}

#[cfg(not(target_arch = "x86_64"))]
fn print_codegen_isa() {
    println!("codegen_isa,target_arch=non_x86_64");
}

fn bench_evidence_cmd() -> Result<()> {
    let sha = elf_self_sha256()?;
    println!("bench_evidence,binary_sha256={sha}");
    print_codegen_isa();
    println!(
        "build_profile,pgo_profile_sha256={}",
        option_env!("FFS_PGO_PROFILE_SHA256").unwrap_or("none")
    );
    Ok(())
}

fn createbench_one_round(
    cx: &Cx,
    open_fs: &OpenFs,
    parent: InodeNumber,
    count: usize,
    threads: usize,
    round: usize,
) -> Result<Duration> {
    let per = if threads > 1 { count / threads } else { count };
    let elapsed = if threads > 1 {
        let mut tdirs: Vec<InodeNumber> = Vec::with_capacity(threads);
        for t in 0..threads {
            let attr = open_fs
                .mkdir(
                    cx,
                    parent,
                    std::ffi::OsStr::new(&format!("t{t}_r{round}")),
                    0o755,
                    0,
                    0,
                )
                .with_context(|| format!("failed to mkdir t{t}_r{round}"))?;
            tdirs.push(attr.ino);
        }
        let started = Instant::now();
        std::thread::scope(|s| {
            for (t, &tdir) in tdirs.iter().enumerate() {
                let fs = &*open_fs;
                s.spawn(move || {
                    for i in 0..per {
                        let name = format!("cb_{t}_{i:08}");
                        fs.create(cx, tdir, std::ffi::OsStr::new(&name), 0o644, 0, 0)
                            .unwrap_or_else(|e| panic!("create {name}: {e:?}"));
                    }
                });
            }
        });
        started.elapsed()
    } else {
        let started = Instant::now();
        for i in 0..per {
            let name = format!("cb_r{round}_{i:08}");
            open_fs
                .create(cx, parent, std::ffi::OsStr::new(&name), 0o644, 0, 0)
                .with_context(|| format!("failed to create {name}"))?;
        }
        started.elapsed()
    };
    Ok(elapsed)
}

fn createbench_rounds(
    cx: &Cx,
    open_fs: &OpenFs,
    parent: InodeNumber,
    count: usize,
    threads: usize,
    rounds: usize,
) -> Result<()> {
    // Self-report the EXECUTING ELF's SHA-256. A `sha256sum` run beside the
    // benchmark proves which file exists on disk, not which binary the kernel
    // actually mapped — the two diverge whenever a concurrent build replaces the
    // file mid-run, which has happened in this fleet. Hash `current_exe()` from
    // inside the measuring process, outside the timed region.
    match elf_self_sha256() {
        Ok(sha) => println!("bench_evidence,binary_sha256={sha}"),
        Err(err) => println!("bench_evidence,binary_sha256=unavailable,error={err}"),
    }
    let per = if threads > 1 { count / threads } else { count };
    let per_round_total = per * threads.max(1);
    for round in 0..rounds {
        let create_us = createbench_one_round(cx, open_fs, parent, count, threads, round)?;
        let secs = create_us.as_secs_f64().max(1e-9);
        println!(
            "createbench_round,round={round},threads={threads},count={per_round_total},\
create_us={},creates_per_s={}",
            create_us.as_micros(),
            (per_round_total as f64 / secs) as u64
        );
    }
    // One flush for the whole run, timed and reported separately so it can be
    // read but never contributes to the per-round statistic.
    let flush_started = Instant::now();
    open_fs
        .sync_all_to_device(cx)
        .with_context(|| "failed to flush creates".to_string())?;
    println!(
        "createbench_flush,rounds={rounds},flush_us={}",
        flush_started.elapsed().as_micros()
    );
    Ok(())
}

#[cfg(feature = "bhh0i_sharded_alloc")]
struct CreateBenchCutoverArm {
    label: &'static str,
    cx: Cx,
    open_fs: OpenFs,
    parent: InodeNumber,
}

#[cfg(feature = "bhh0i_sharded_alloc")]
impl CreateBenchCutoverArm {
    fn open(
        label: &'static str,
        path: &Path,
        dir_path: &str,
        publication_mode: PublicationMode,
    ) -> Result<Self> {
        let cx = cli_cx();
        let mut open_fs = OpenFs::open(&cx, path)
            .with_context(|| format!("failed to open {label} image: {}", path.display()))?;
        open_fs
            .set_empty_mvcc_publication_mode_for_bench(publication_mode)
            .with_context(|| format!("failed to select {label} publication mode"))?;
        open_fs
            .enable_writes(&cx)
            .with_context(|| format!("failed to enable writes for {label}"))?;
        open_fs.set_bhh0i_sharded_ops(true);

        let mut parent = InodeNumber(1);
        for comp in dir_path
            .split('/')
            .filter(|component| !component.is_empty())
        {
            let attr = open_fs
                .lookup(&cx, parent, std::ffi::OsStr::new(comp))
                .with_context(|| {
                    format!("failed to resolve {dir_path} for {label} at component {comp:?}")
                })?;
            parent = attr.ino;
        }
        Ok(Self {
            label,
            cx,
            open_fs,
            parent,
        })
    }

    fn time_and_flush(&self, count: usize, threads: usize, round: usize) -> Result<Duration> {
        let elapsed =
            createbench_one_round(&self.cx, &self.open_fs, self.parent, count, threads, round)?;
        let flush_started = Instant::now();
        self.open_fs
            .sync_all_to_device(&self.cx)
            .with_context(|| format!("failed to flush {} after round {round}", self.label))?;
        println!(
            "createbench_cutover_flush,arm={},round={round},flush_us={}",
            self.label,
            flush_started.elapsed().as_micros()
        );
        Ok(elapsed)
    }
}

#[cfg(feature = "bhh0i_sharded_alloc")]
#[allow(clippy::too_many_arguments)]
fn run_createbench_cutover_pair(
    phase: &str,
    logical_lhs: &CreateBenchCutoverArm,
    logical_rhs: &CreateBenchCutoverArm,
    count: usize,
    threads: usize,
    round: usize,
    lhs_first: bool,
) -> Result<f64> {
    let (lhs_elapsed, rhs_elapsed) = if lhs_first {
        (
            logical_lhs.time_and_flush(count, threads, round)?,
            logical_rhs.time_and_flush(count, threads, round)?,
        )
    } else {
        let rhs = logical_rhs.time_and_flush(count, threads, round)?;
        let lhs = logical_lhs.time_and_flush(count, threads, round)?;
        (lhs, rhs)
    };
    let lhs_seconds = lhs_elapsed.as_secs_f64().max(1e-9);
    let rhs_seconds = rhs_elapsed.as_secs_f64().max(1e-9);
    let lhs_over_rhs = rhs_seconds / lhs_seconds;
    println!(
        "createbench_cutover_pair,phase={phase},round={round},order={},threads={threads},\
lhs={},rhs={},lhs_us={},rhs_us={},lhs_over_rhs={lhs_over_rhs:.6}",
        if lhs_first { "lhs_rhs" } else { "rhs_lhs" },
        logical_lhs.label,
        logical_rhs.label,
        lhs_elapsed.as_micros(),
        rhs_elapsed.as_micros(),
    );
    Ok(lhs_over_rhs.ln())
}

#[cfg(feature = "bhh0i_sharded_alloc")]
fn validate_cutover_images(paths: [&Path; 4]) -> Result<(u64, String)> {
    const MAX_IMAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
    let mut canonical_paths = BTreeSet::new();
    #[cfg(unix)]
    let mut file_identities = BTreeSet::new();
    let mut image_size = None;
    for path in paths {
        let canonical = std::fs::canonicalize(path)
            .with_context(|| format!("canonicalize cutover image {}", path.display()))?;
        if !canonical_paths.insert(canonical) {
            bail!("cutover gate requires four distinct image files");
        }
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("stat cutover image {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !file_identities.insert((metadata.dev(), metadata.ino())) {
                bail!("cutover gate rejects hard-linked image paths");
            }
        }
        let len = metadata.len();
        if len > MAX_IMAGE_BYTES {
            bail!(
                "cutover image {} is {len} bytes; cap is {MAX_IMAGE_BYTES}",
                path.display()
            );
        }
        match image_size {
            None => image_size = Some(len),
            Some(expected) if expected == len => {}
            Some(expected) => bail!(
                "cutover images differ in size: expected {expected} bytes, {} is {len}",
                path.display()
            ),
        }
    }
    let image_shas = interleaved_file_sha256(paths)?;
    let expected_sha = &image_shas[0];
    for (path, sha) in paths.iter().zip(image_shas.iter()).skip(1) {
        if sha != expected_sha {
            bail!(
                "cutover images are not byte-identical: expected SHA-256 {expected_sha}, {} is {sha}",
                path.display()
            );
        }
    }
    Ok((
        image_size.context("cutover gate requires four image files")?,
        expected_sha.clone(),
    ))
}

#[cfg(feature = "bhh0i_sharded_alloc")]
fn measure_createbench_cutover(
    null_images: [&PathBuf; 2],
    decision_images: [&PathBuf; 2],
    dir_path: &str,
    count: usize,
    threads: usize,
    rounds: usize,
) -> Result<(BootstrapMedianCi, BootstrapMedianCi)> {
    let null_lhs = CreateBenchCutoverArm::open(
        "aa_mutex_lhs",
        null_images[0],
        dir_path,
        PublicationMode::Mutex,
    )?;
    let null_rhs = CreateBenchCutoverArm::open(
        "aa_mutex_rhs",
        null_images[1],
        dir_path,
        PublicationMode::Mutex,
    )?;
    let mutex_control = CreateBenchCutoverArm::open(
        "ab_mutex_base",
        decision_images[0],
        dir_path,
        PublicationMode::Mutex,
    )?;
    let wait_free_candidate = CreateBenchCutoverArm::open(
        "ab_wait_free_candidate",
        decision_images[1],
        dir_path,
        PublicationMode::WaitFree,
    )?;

    let mut null_log_ratios = Vec::with_capacity(rounds);
    let mut candidate_log_ratios = Vec::with_capacity(rounds);
    for round in 0..rounds {
        null_log_ratios.push(run_createbench_cutover_pair(
            "aa",
            &null_lhs,
            &null_rhs,
            count,
            1,
            round,
            round % 2 == 0,
        )?);
        candidate_log_ratios.push(run_createbench_cutover_pair(
            "ab",
            &wait_free_candidate,
            &mutex_control,
            count,
            threads,
            round,
            round % 2 != 0,
        )?);
    }
    Ok((
        bootstrap_median_ci(&null_log_ratios),
        bootstrap_median_ci(&candidate_log_ratios),
    ))
}

#[cfg(feature = "bhh0i_sharded_alloc")]
fn createbench_cutover_gate_cmd(
    null_images: [&PathBuf; 2],
    decision_images: [&PathBuf; 2],
    dir_path: &str,
    count: usize,
    threads: usize,
    rounds: usize,
) -> Result<()> {
    let sha = elf_self_sha256().context("self-hash executing cutover ELF")?;
    let worker = std::process::Command::new("hostname")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|hostname| !hostname.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("bench_evidence,binary_sha256={sha},worker={worker}");
    print_codegen_isa();

    if rounds < 5 {
        bail!("cutover gate requires at least 5 paired rounds");
    }
    if threads < 2 {
        bail!("cutover A/B requires at least 2 writer threads");
    }
    if count == 0 || count % threads != 0 {
        bail!("count must be nonzero and divisible by threads");
    }
    let (image_size, image_sha256) = validate_cutover_images([
        null_images[0].as_path(),
        null_images[1].as_path(),
        decision_images[0].as_path(),
        decision_images[1].as_path(),
    ])?;
    println!(
        "createbench_cutover_config,same_invocation=true,rounds={rounds},count={count},\
aa_threads=1,ab_threads={threads},image_size={image_size},sharded_alloc=true,\
input_image_sha256={image_sha256},gate_basis=bootstrap_median_ci,\
bootstrap_resamples=20000,cv_used=false"
    );

    let (null_ci, candidate_ci) = measure_createbench_cutover(
        null_images,
        decision_images,
        dir_path,
        count,
        threads,
        rounds,
    )?;
    let null_log_margin = null_ci.low.ln().abs().max(null_ci.high.ln().abs());
    let null_floor_ratio = null_log_margin.exp();
    let twice_null_ratio = (2.0 * null_log_margin).exp();
    let aa_inside_1_10 = (1.0 / 1.10..=1.10).contains(&null_ci.median);
    let null_floor_le_1_15 = null_floor_ratio <= 1.15;
    let ab_clears_twice_null = candidate_ci.low > twice_null_ratio;
    let performance_admitted = aa_inside_1_10 && null_floor_le_1_15 && ab_clears_twice_null;

    println!(
        "createbench_cutover_median_ci,phase=aa,lhs_over_rhs_median={:.6},\
bootstrap_median_ci95_low={:.6},bootstrap_median_ci95_high={:.6}",
        null_ci.median, null_ci.low, null_ci.high
    );
    println!(
        "createbench_cutover_median_ci,phase=ab,candidate_over_base_median={:.6},\
bootstrap_median_ci95_low={:.6},bootstrap_median_ci95_high={:.6}",
        candidate_ci.median, candidate_ci.low, candidate_ci.high
    );
    println!(
        "createbench_cutover_decision,aa_inside_1_10={aa_inside_1_10},\
null_floor_ratio={null_floor_ratio:.6},null_floor_le_1_15={null_floor_le_1_15},\
twice_null_ratio={twice_null_ratio:.6},ab_ci_clears_twice_null={ab_clears_twice_null},\
performance_admitted={performance_admitted},external_fsck_required=true,\
gate_basis=bootstrap_median_ci,cv_used=false"
    );
    println!(
        "createbench_cutover_expected_files,aa_each={},ab_each={}",
        12_usize.saturating_add(count.saturating_mul(rounds)),
        12_usize
            .saturating_add(count.saturating_mul(rounds))
            .saturating_add(threads.saturating_mul(rounds))
    );
    if performance_admitted {
        Ok(())
    } else {
        bail!("cutover performance gate rejected the candidate; see decision row")
    }
}

#[cfg(not(feature = "bhh0i_sharded_alloc"))]
fn createbench_cutover_gate_cmd(
    _null_images: [&PathBuf; 2],
    _decision_images: [&PathBuf; 2],
    _dir_path: &str,
    _count: usize,
    _threads: usize,
    _rounds: usize,
) -> Result<()> {
    bail!("create-bench-cutover-gate requires --features bhh0i_sharded_alloc")
}

const READ_POOL_GATE_FILE: &str = "/read_pool_gate.bin";

fn copy_read_pool_fixture(source: &Path) -> Result<PathBuf> {
    use std::io::{BufReader, BufWriter, Write as _};

    const MAX_IMAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
    let source_len = std::fs::metadata(source)
        .with_context(|| format!("stat read-pool fixture {}", source.display()))?
        .len();
    if source_len > MAX_IMAGE_BYTES {
        bail!(
            "read-pool fixture {} is {source_len} bytes; cap is {MAX_IMAGE_BYTES}",
            source.display()
        );
    }

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_nanos();
    let destination = std::env::temp_dir().join(format!(
        "frankenfs-read-pool-gate-{}-{nonce}.img",
        std::process::id()
    ));
    let mut input = BufReader::new(
        std::fs::File::open(source)
            .with_context(|| format!("open read-pool fixture {}", source.display()))?,
    );
    let mut output = BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .with_context(|| format!("create private read-pool image {}", destination.display()))?,
    );
    let copied = std::io::copy(&mut input, &mut output)
        .with_context(|| format!("copy read-pool fixture to {}", destination.display()))?;
    output
        .flush()
        .with_context(|| format!("flush private read-pool image {}", destination.display()))?;
    if copied != source_len {
        bail!("fixture copy was short: expected {source_len} bytes, copied {copied}");
    }
    Ok(destination)
}

fn run_read_pool_setup(exe: &Path, image: &Path, blocks: usize) -> Result<()> {
    let output = std::process::Command::new(exe)
        .arg("--log-format")
        .arg("human")
        .arg("write-bench")
        .arg(image)
        .arg(READ_POOL_GATE_FILE)
        .arg("--count")
        .arg(blocks.to_string())
        .arg("--size")
        .arg("4096")
        .arg("--create")
        .env("RUST_LOG", "error")
        .output()
        .with_context(|| format!("launch read-pool fixture setup from {}", exe.display()))?;
    if !output.status.success() {
        bail!(
            "read-pool fixture setup failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn verify_read_pool_child_identity(exe: &Path, parent_sha256: &str) -> Result<()> {
    let output = std::process::Command::new(exe)
        .arg("bench-evidence")
        .env("RUST_LOG", "error")
        .output()
        .with_context(|| format!("launch read-pool identity child from {}", exe.display()))?;
    if !output.status.success() {
        bail!(
            "read-pool identity child failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let child_sha256 = stdout
        .lines()
        .find_map(|line| line.strip_prefix("bench_evidence,binary_sha256="))
        .and_then(|rest| rest.split(',').next())
        .context("identity child omitted its in-process ELF SHA-256")?;
    if child_sha256 != parent_sha256 {
        bail!("read-pool parent/child ELF mismatch: parent {parent_sha256}, child {child_sha256}");
    }
    println!(
        "read_pool_child_identity,parent_binary_sha256={parent_sha256},\
child_binary_sha256={child_sha256},same_elf=true"
    );
    Ok(())
}

fn evict_read_pool_fixture(image: &Path) -> Result<()> {
    use nix::fcntl::{PosixFadviseAdvice, posix_fadvise};
    use std::os::fd::AsRawFd;

    let file = std::fs::File::open(image)
        .with_context(|| format!("open {} for DONTNEED", image.display()))?;
    posix_fadvise(
        file.as_raw_fd(),
        0,
        0,
        PosixFadviseAdvice::POSIX_FADV_DONTNEED,
    )
    .with_context(|| format!("POSIX_FADV_DONTNEED {}", image.display()))
}

struct ReadPoolChild {
    elapsed: Duration,
    stdout: Vec<u8>,
}

fn run_read_pool_child(
    exe: &Path,
    image: &Path,
    threads: Option<usize>,
    discard: bool,
) -> Result<ReadPoolChild> {
    evict_read_pool_fixture(image)?;
    let mut command = std::process::Command::new(exe);
    command
        .arg("--log-format")
        .arg("human")
        .arg("read")
        .arg(image)
        .arg(READ_POOL_GATE_FILE)
        .env("RUST_LOG", "error");
    if discard {
        command.arg("--discard");
    }
    match threads {
        Some(threads) => {
            command.env("FFS_READ_PARALLELISM", threads.to_string());
        }
        None => {
            command.env_remove("FFS_READ_PARALLELISM");
        }
    }
    let started = Instant::now();
    let output = command
        .output()
        .with_context(|| format!("launch read-pool child from {}", exe.display()))?;
    let elapsed = started.elapsed();
    if !output.status.success() {
        bail!(
            "read-pool child failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(ReadPoolChild {
        elapsed,
        stdout: output.stdout,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_read_pool_pair(
    phase: &str,
    exe: &Path,
    image: &Path,
    lhs_label: &str,
    lhs_threads: Option<usize>,
    rhs_label: &str,
    rhs_threads: Option<usize>,
    round: usize,
    lhs_first: bool,
) -> Result<f64> {
    let (lhs, rhs) = if lhs_first {
        (
            run_read_pool_child(exe, image, lhs_threads, true)?,
            run_read_pool_child(exe, image, rhs_threads, true)?,
        )
    } else {
        let rhs = run_read_pool_child(exe, image, rhs_threads, true)?;
        let lhs = run_read_pool_child(exe, image, lhs_threads, true)?;
        (lhs, rhs)
    };
    let lhs_seconds = lhs.elapsed.as_secs_f64().max(1e-9);
    let rhs_seconds = rhs.elapsed.as_secs_f64().max(1e-9);
    let lhs_over_rhs = rhs_seconds / lhs_seconds;
    println!(
        "read_pool_cutover_pair,phase={phase},round={round},order={},lhs={lhs_label},\
rhs={rhs_label},lhs_us={},rhs_us={},lhs_over_rhs={lhs_over_rhs:.6}",
        if lhs_first { "lhs_rhs" } else { "rhs_lhs" },
        lhs.elapsed.as_micros(),
        rhs.elapsed.as_micros(),
    );
    Ok(lhs_over_rhs.ln())
}

#[allow(clippy::too_many_lines)]
fn read_pool_cutover_gate_cmd(fixture: &Path, blocks: usize, rounds: usize) -> Result<()> {
    use sha2::{Digest, Sha256};

    let sha = elf_self_sha256().context("self-hash executing read-pool gate ELF")?;
    let worker = std::process::Command::new("hostname")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|hostname| !hostname.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("bench_evidence,binary_sha256={sha},worker={worker}");
    print_codegen_isa();
    println!(
        "build_profile,pgo_profile_sha256={}",
        option_env!("FFS_PGO_PROFILE_SHA256").unwrap_or("none")
    );

    if rounds < 5 {
        bail!("read-pool cutover gate requires at least 5 paired rounds");
    }
    if blocks == 0 {
        bail!("read-pool cutover gate requires at least one data block");
    }
    let expected_bytes = blocks
        .checked_mul(4096)
        .context("read-pool target byte count overflow")?;
    let available_threads =
        std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
    let candidate_threads = available_threads.min(16);
    let old_quarter_threads = (available_threads / 4).clamp(4, 16);
    if old_quarter_threads == candidate_threads {
        bail!(
            "read-pool A/B needs the old quarter-width rule ({old_quarter_threads}) to differ \
             from the corrected production width ({candidate_threads}); nproc={available_threads}"
        );
    }

    let exe = std::env::current_exe().context("resolve read-pool gate current_exe")?;
    verify_read_pool_child_identity(&exe, &sha)?;
    let image = copy_read_pool_fixture(fixture)?;
    run_read_pool_setup(&exe, &image, blocks)?;
    let image_sha256 = file_sha256(&image)?;

    let candidate_bytes = run_read_pool_child(&exe, &image, None, false)?.stdout;
    let control_bytes = run_read_pool_child(&exe, &image, Some(old_quarter_threads), false)?.stdout;
    if candidate_bytes.len() != expected_bytes || control_bytes.len() != expected_bytes {
        bail!(
            "read-pool parity length mismatch: expected {expected_bytes}, candidate {}, control {}",
            candidate_bytes.len(),
            control_bytes.len()
        );
    }
    if candidate_bytes != control_bytes {
        bail!("read-pool candidate/control bytes differ");
    }
    if candidate_bytes.iter().any(|&byte| byte != 0xA5) {
        bail!("read-pool fixture bytes differ from the deterministic 0xA5 payload");
    }
    let stream_sha256 = sha256_hex(&Sha256::digest(&candidate_bytes));
    println!(
        "read_pool_cutover_config,same_invocation=true,rounds={rounds},blocks={blocks},\
bytes={expected_bytes},available_threads={available_threads},\
candidate_default_threads={candidate_threads},control_old_quarter_threads={old_quarter_threads},\
fixture={},private_image={},private_image_sha256={image_sha256},\
stream_sha256={stream_sha256},exact_stream_parity=true,cold_cache=posix_fadvise_dontneed,\
gate_basis=bootstrap_median_ci,bootstrap_resamples=20000,cv_used=false",
        fixture.display(),
        image.display(),
    );

    let mut null_log_ratios = Vec::with_capacity(rounds);
    let mut candidate_log_ratios = Vec::with_capacity(rounds);
    for round in 0..rounds {
        null_log_ratios.push(run_read_pool_pair(
            "aa",
            &exe,
            &image,
            "default_lhs",
            None,
            "default_rhs",
            None,
            round,
            round % 2 == 0,
        )?);
        candidate_log_ratios.push(run_read_pool_pair(
            "ab",
            &exe,
            &image,
            "default_candidate",
            None,
            "old_quarter_control",
            Some(old_quarter_threads),
            round,
            round % 2 != 0,
        )?);
    }

    let null_ci = bootstrap_median_ci(&null_log_ratios);
    let candidate_ci = bootstrap_median_ci(&candidate_log_ratios);
    let null_log_margin = null_ci.low.ln().abs().max(null_ci.high.ln().abs());
    let null_floor_ratio = null_log_margin.exp();
    let twice_null_ratio = (2.0 * null_log_margin).exp();
    let aa_inside_1_10 = (1.0 / 1.10..=1.10).contains(&null_ci.median);
    let null_floor_le_1_15 = null_floor_ratio <= 1.15;
    let ab_clears_twice_null = candidate_ci.low > twice_null_ratio;
    let performance_admitted = aa_inside_1_10 && null_floor_le_1_15 && ab_clears_twice_null;
    println!(
        "read_pool_cutover_median_ci,phase=aa,lhs_over_rhs_median={:.6},\
bootstrap_median_ci95_low={:.6},bootstrap_median_ci95_high={:.6}",
        null_ci.median, null_ci.low, null_ci.high
    );
    println!(
        "read_pool_cutover_median_ci,phase=ab,candidate_over_control_median={:.6},\
bootstrap_median_ci95_low={:.6},bootstrap_median_ci95_high={:.6}",
        candidate_ci.median, candidate_ci.low, candidate_ci.high
    );
    println!(
        "read_pool_cutover_decision,aa_inside_1_10={aa_inside_1_10},\
null_floor_ratio={null_floor_ratio:.6},null_floor_le_1_15={null_floor_le_1_15},\
twice_null_ratio={twice_null_ratio:.6},ab_ci_clears_twice_null={ab_clears_twice_null},\
performance_admitted={performance_admitted},gate_basis=bootstrap_median_ci,cv_used=false"
    );
    if performance_admitted {
        Ok(())
    } else {
        bail!("read-pool performance gate rejected the candidate; see decision row")
    }
}

fn mkdirbench_cmd(path: &PathBuf, dir_path: &str, count: usize) -> Result<()> {
    let cx = cli_cx();
    let mut open_fs = OpenFs::open(&cx, path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    open_fs
        .enable_writes(&cx)
        .with_context(|| "failed to enable writes (alloc state)".to_string())?;
    let mut parent = InodeNumber(1);
    for comp in dir_path.split('/').filter(|c| !c.is_empty()) {
        let attr = open_fs
            .lookup(&cx, parent, std::ffi::OsStr::new(comp))
            .with_context(|| format!("failed to resolve {dir_path} at component {comp:?}"))?;
        parent = attr.ino;
    }
    let started = Instant::now();
    let mut made = 0_u64;
    for i in 0..count {
        let name = format!("md_{i:08}");
        open_fs
            .mkdir(&cx, parent, std::ffi::OsStr::new(&name), 0o755, 0, 0)
            .with_context(|| format!("failed to mkdir {name}"))?;
        made += 1;
    }
    open_fs
        .sync_all_to_device(&cx)
        .with_context(|| "failed to flush mkdirs to image".to_string())?;
    let elapsed = started.elapsed();
    let duration_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
    let secs = elapsed.as_secs_f64().max(1e-9);
    let mkdirs_per_s = (count as f64) / secs;
    info!(
        target: "ffs::cli::mkdirbench",
        count,
        made,
        duration_us,
        mkdirs_per_s = mkdirs_per_s as u64,
        "mkdirbench_done"
    );
    eprintln!(
        "mkdirbench: {count} mkdirs in {dir_path} -> {made} made in {duration_us} us = {} mkdirs/s",
        mkdirs_per_s as u64
    );
    Ok(())
}

fn rmdirbench_cmd(path: &PathBuf, dir_path: &str, count: usize) -> Result<()> {
    let cx = cli_cx();
    let mut open_fs = OpenFs::open(&cx, path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    open_fs
        .enable_writes(&cx)
        .with_context(|| "failed to enable writes (alloc state)".to_string())?;
    let mut parent = InodeNumber(1);
    for comp in dir_path.split('/').filter(|c| !c.is_empty()) {
        let attr = open_fs
            .lookup(&cx, parent, std::ffi::OsStr::new(comp))
            .with_context(|| format!("failed to resolve {dir_path} at component {comp:?}"))?;
        parent = attr.ino;
    }
    // Setup (untimed): create the subdirs to be removed.
    for i in 0..count {
        let name = format!("rd_{i:08}");
        open_fs
            .mkdir(&cx, parent, std::ffi::OsStr::new(&name), 0o755, 0, 0)
            .with_context(|| format!("failed to mkdir {name}"))?;
    }
    // Timed: remove all of them + persist.
    let started = Instant::now();
    let mut removed = 0_u64;
    for i in 0..count {
        let name = format!("rd_{i:08}");
        open_fs
            .rmdir(&cx, parent, std::ffi::OsStr::new(&name))
            .with_context(|| format!("failed to rmdir {name}"))?;
        removed += 1;
    }
    open_fs
        .sync_all_to_device(&cx)
        .with_context(|| "failed to flush removals to image".to_string())?;
    let elapsed = started.elapsed();
    let duration_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
    let secs = elapsed.as_secs_f64().max(1e-9);
    let rmdirs_per_s = (count as f64) / secs;
    info!(
        target: "ffs::cli::rmdirbench",
        count,
        removed,
        duration_us,
        rmdirs_per_s = rmdirs_per_s as u64,
        "rmdirbench_done"
    );
    eprintln!(
        "rmdirbench: {count} rmdirs in {dir_path} -> {removed} removed in {duration_us} us = {} rmdirs/s",
        rmdirs_per_s as u64
    );
    Ok(())
}

fn unlinkbench_cmd(path: &PathBuf, dir_path: &str, count: usize) -> Result<()> {
    let cx = cli_cx();
    let mut open_fs = OpenFs::open(&cx, path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    open_fs
        .enable_writes(&cx)
        .with_context(|| "failed to enable writes (alloc state)".to_string())?;
    let mut parent = InodeNumber(1);
    for comp in dir_path.split('/').filter(|c| !c.is_empty()) {
        let attr = open_fs
            .lookup(&cx, parent, std::ffi::OsStr::new(comp))
            .with_context(|| format!("failed to resolve {dir_path} at component {comp:?}"))?;
        parent = attr.ino;
    }
    // Setup (untimed): create the files to be deleted.
    for i in 0..count {
        let name = format!("ub_{i:08}");
        open_fs
            .create(&cx, parent, std::ffi::OsStr::new(&name), 0o644, 0, 0)
            .with_context(|| format!("failed to create {name}"))?;
    }
    // Timed: unlink all of them + persist (the step a real mount does at umount).
    let started = Instant::now();
    let mut removed = 0_u64;
    for i in 0..count {
        let name = format!("ub_{i:08}");
        open_fs
            .unlink(&cx, parent, std::ffi::OsStr::new(&name))
            .with_context(|| format!("failed to unlink {name}"))?;
        removed += 1;
    }
    open_fs
        .sync_all_to_device(&cx)
        .with_context(|| "failed to flush unlinks to image".to_string())?;
    let elapsed = started.elapsed();
    let duration_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
    let secs = elapsed.as_secs_f64().max(1e-9);
    let unlinks_per_s = (count as f64) / secs;
    info!(
        target: "ffs::cli::unlinkbench",
        count,
        removed,
        duration_us,
        unlinks_per_s = unlinks_per_s as u64,
        "unlinkbench_done"
    );
    eprintln!(
        "unlinkbench: {count} unlinks in {dir_path} -> {removed} removed in {duration_us} us = {} unlinks/s",
        unlinks_per_s as u64
    );
    Ok(())
}

fn renamebench_cmd(path: &PathBuf, dir_path: &str, count: usize) -> Result<()> {
    let cx = cli_cx();
    let mut open_fs = OpenFs::open(&cx, path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    open_fs
        .enable_writes(&cx)
        .with_context(|| "failed to enable writes (alloc state)".to_string())?;
    let mut parent = InodeNumber(1);
    for comp in dir_path.split('/').filter(|c| !c.is_empty()) {
        let attr = open_fs
            .lookup(&cx, parent, std::ffi::OsStr::new(comp))
            .with_context(|| format!("failed to resolve {dir_path} at component {comp:?}"))?;
        parent = attr.ino;
    }
    // Setup (untimed): create the files to be renamed.
    for i in 0..count {
        let name = format!("rb_{i:08}");
        open_fs
            .create(&cx, parent, std::ffi::OsStr::new(&name), 0o644, 0, 0)
            .with_context(|| format!("failed to create {name}"))?;
    }
    // Timed: rename each to a new name in the same dir + persist.
    let started = Instant::now();
    let mut renamed = 0_u64;
    for i in 0..count {
        let from = format!("rb_{i:08}");
        let to = format!("rn_{i:08}");
        open_fs
            .rename(
                &cx,
                parent,
                std::ffi::OsStr::new(&from),
                parent,
                std::ffi::OsStr::new(&to),
            )
            .with_context(|| format!("failed to rename {from} -> {to}"))?;
        renamed += 1;
    }
    open_fs
        .sync_all_to_device(&cx)
        .with_context(|| "failed to flush renames to image".to_string())?;
    let elapsed = started.elapsed();
    let duration_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
    let secs = elapsed.as_secs_f64().max(1e-9);
    let renames_per_s = (count as f64) / secs;
    info!(
        target: "ffs::cli::renamebench",
        count,
        renamed,
        duration_us,
        renames_per_s = renames_per_s as u64,
        "renamebench_done"
    );
    eprintln!(
        "renamebench: {count} renames in {dir_path} -> {renamed} renamed in {duration_us} us = {} renames/s",
        renames_per_s as u64
    );
    Ok(())
}

fn lookupbench_cmd(path: &PathBuf, dir_path: &str, count: usize, seed: u64) -> Result<()> {
    let cx = cli_cx();
    let open_fs = OpenFs::open(&cx, path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let mut ino = InodeNumber(1);
    for comp in dir_path.split('/').filter(|c| !c.is_empty()) {
        let attr = open_fs
            .lookup(&cx, ino, std::ffi::OsStr::new(comp))
            .with_context(|| format!("failed to resolve {dir_path} at component {comp:?}"))?;
        ino = attr.ino;
    }
    // Collect ALL the directory's entry names via paginated readdir (a single
    // page returns only the first dir blocks' entries — querying just those
    // would make a linear-scan lookup terminate early and hide its O(N) cost).
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut off = 0_u64;
    loop {
        let page = open_fs
            .readdir(&cx, ino, off)
            .with_context(|| format!("failed to readdir {dir_path} at offset {off}"))?;
        let entries = page.to_vec();
        if entries.is_empty() {
            break;
        }
        for e in &entries {
            off = off.max(e.offset);
            if e.name.as_slice() != b"." && e.name.as_slice() != b".." {
                names.push(e.name.clone());
            }
        }
    }
    if names.is_empty() {
        bail!("directory {dir_path} has no entries to look up");
    }
    let n_names = names.len() as u64;
    let mut state = seed;
    let mut next_idx = || -> usize {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        usize::try_from(z % n_names).unwrap_or(0)
    };
    use std::os::unix::ffi::OsStrExt;
    let started = Instant::now();
    let mut found = 0_u64;
    for _ in 0..count {
        let name = std::ffi::OsStr::from_bytes(&names[next_idx()]);
        if open_fs.lookup(&cx, ino, name).is_ok() {
            found += 1;
        }
    }
    let elapsed = started.elapsed();
    let duration_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
    let secs = elapsed.as_secs_f64().max(1e-9);
    let lookups_per_s = (count as f64) / secs;
    info!(
        target: "ffs::cli::lookupbench",
        count,
        dir_entries = names.len(),
        found,
        duration_us,
        lookups_per_s = lookups_per_s as u64,
        "lookupbench_done"
    );
    eprintln!(
        "lookupbench: {count} lookups in {dir_path} ({} entries) -> {found} found in {duration_us} us = {} lookups/s",
        names.len(),
        lookups_per_s as u64
    );
    Ok(())
}

fn writebench_cmd(
    path: &PathBuf,
    file_path: &str,
    count: usize,
    size: usize,
    random: bool,
    seed: u64,
    create: bool,
) -> Result<()> {
    let cx = cli_cx();
    let mut open_fs = OpenFs::open(&cx, path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    open_fs
        .enable_writes(&cx)
        .with_context(|| "failed to enable writes (alloc state)".to_string())?;
    let mut ino = InodeNumber(1);
    if create {
        // Resolve the parent dir, create the final component if missing, and
        // pre-fill it with count*size bytes so `rand-read` has real blocks.
        let comps: Vec<&str> = file_path.split('/').filter(|c| !c.is_empty()).collect();
        let (name, parents) = comps
            .split_last()
            .with_context(|| format!("invalid file path {file_path}"))?;
        for comp in parents {
            ino = open_fs
                .lookup(&cx, ino, std::ffi::OsStr::new(comp))
                .with_context(|| format!("failed to resolve parent component {comp:?}"))?
                .ino;
        }
        let file_ino = match open_fs.lookup(&cx, ino, std::ffi::OsStr::new(name)) {
            Ok(attr) => attr.ino,
            Err(_) => {
                open_fs
                    .create(&cx, ino, std::ffi::OsStr::new(name), 0o644, 0, 0)
                    .with_context(|| format!("failed to create {file_path}"))?
                    .ino
            }
        };
        let fill = vec![0xA5_u8; size];
        for i in 0..count {
            let off = (i as u64) * size as u64;
            open_fs
                .write(&cx, file_ino, off, &fill)
                .with_context(|| format!("failed prefill write at {off}"))?;
        }
        ino = file_ino;
    } else {
        for comp in file_path.split('/').filter(|c| !c.is_empty()) {
            let attr = open_fs
                .lookup(&cx, ino, std::ffi::OsStr::new(comp))
                .with_context(|| format!("failed to resolve {file_path} at component {comp:?}"))?;
            ino = attr.ino;
        }
    }
    let fsize = open_fs
        .getattr(&cx, ino)
        .with_context(|| format!("failed to stat {file_path}"))?
        .size;
    if size == 0 || (fsize as usize) < size {
        bail!("file {file_path} ({fsize} B) is smaller than the write size {size} B");
    }
    let bs: u64 = 4096;
    let span_blocks = ((fsize - size as u64) / bs).max(1);
    let mut state = seed;
    let mut next_off = |i: usize| -> u64 {
        if random {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            (z % span_blocks) * bs
        } else {
            ((i as u64) % span_blocks) * bs
        }
    };
    let buf = vec![0xA5_u8; size];
    let started = Instant::now();
    let mut total_bytes: u64 = 0;
    for i in 0..count {
        let off = next_off(i);
        total_bytes += u64::from(
            open_fs
                .write(&cx, ino, off, &buf)
                .with_context(|| format!("failed write at {off}"))?,
        );
    }
    let elapsed = started.elapsed();
    let duration_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
    let secs = elapsed.as_secs_f64().max(1e-9);
    let iops = (count as f64) / secs;
    let mib_s = (total_bytes as f64) / secs / (1024.0 * 1024.0);
    info!(
        target: "ffs::cli::writebench",
        count,
        size,
        random,
        bytes = total_bytes,
        duration_us,
        iops = iops as u64,
        mib_per_s = mib_s as u64,
        "writebench_done"
    );
    eprintln!(
        "writebench: {count} x {size}B {} -> {total_bytes} B in {duration_us} us = {} IOPS, {} MiB/s",
        if random { "random" } else { "sequential" },
        iops as u64,
        mib_s as u64
    );
    // Persist the overlay (created file + written blocks) to the image so a
    // fresh open (e.g. a following `rand-read`) observes them.
    open_fs
        .sync_all_to_device(&cx)
        .with_context(|| "failed to sync writes to device".to_string())?;
    Ok(())
}

fn randread_cmd(
    path: &PathBuf,
    file_path: &str,
    count: usize,
    size: usize,
    parallel: bool,
    seed: u64,
) -> Result<()> {
    use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
    let cx = cli_cx();
    let open_fs = OpenFs::open(&cx, path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let mut ino = InodeNumber(1);
    for comp in file_path.split('/').filter(|c| !c.is_empty()) {
        let attr = open_fs
            .lookup(&cx, ino, std::ffi::OsStr::new(comp))
            .with_context(|| format!("failed to resolve {file_path} at component {comp:?}"))?;
        ino = attr.ino;
    }
    let fsize = open_fs
        .getattr(&cx, ino)
        .with_context(|| format!("failed to stat {file_path}"))?
        .size;
    if size == 0 || (fsize as usize) < size {
        bail!("file {file_path} ({fsize} B) is smaller than the read size {size} B");
    }
    // Page-aligned random offsets in [0, fsize - size]. SplitMix64 keeps the
    // sequence deterministic across A/B runs (no wall-clock/RNG entropy).
    let bs: u64 = 4096;
    let span_blocks = ((fsize - size as u64) / bs).max(1);
    let mut state = seed;
    let mut next_off = || -> u64 {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        (z % span_blocks) * bs
    };
    let offsets: Vec<u64> = (0..count).map(|_| next_off()).collect();

    let started = Instant::now();
    let total_bytes: u64 = if parallel {
        // Each task reads into its own small buffer; `read_into` is `&self` and
        // self-scoping, so concurrent positioned reads are isomorphic to serial.
        // Each read gets its OWN `Cx::for_request()`, exactly as the FUSE layer
        // does per request (`Cx::for_request()` in every fuse handler). Sharing
        // a single Cx across all parallel reads is a measurement ARTIFACT: every
        // `cx_checkpoint` then takes that one Cx's inner RwLock in shared mode,
        // so at 64 threads all workers ping-pong one reader-count cacheline
        // (~32% `lock_shared_slow` + ~27% `Cx::checkpoint` in the 64t profile) —
        // contention a real FUSE mount never sees. A per-read Cx restores the
        // like-for-like head-to-head vs the kernel (which has no such object).
        offsets
            .par_iter()
            .map(|&off| {
                let read_cx = cli_cx();
                let mut buf = vec![0_u8; size];
                open_fs
                    .read_into(&read_cx, ino, off, &mut buf)
                    .map(|n| n as u64)
                    .unwrap_or(0)
            })
            .sum()
    } else {
        let mut buf = vec![0_u8; size];
        let mut acc: u64 = 0;
        for &off in &offsets {
            acc += open_fs
                .read_into(&cx, ino, off, &mut buf)
                .with_context(|| format!("failed random read at {off}"))? as u64;
        }
        acc
    };
    let elapsed = started.elapsed();
    let duration_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
    let secs = elapsed.as_secs_f64().max(1e-9);
    let iops = (count as f64) / secs;
    let mib_s = (total_bytes as f64) / secs / (1024.0 * 1024.0);
    info!(
        target: "ffs::cli::randread",
        count,
        size,
        parallel,
        bytes = total_bytes,
        duration_us,
        iops = iops as u64,
        mib_per_s = mib_s as u64,
        "randread_done"
    );
    eprintln!(
        "randread: {count} x {size}B {} -> {total_bytes} B in {duration_us} us = {} IOPS, {} MiB/s",
        if parallel { "parallel" } else { "serial" },
        iops as u64,
        mib_s as u64
    );
    Ok(())
}

/// Per-directory walk tally: entries readdir'd + statted in one directory, plus
/// the child directories discovered (to recurse into).
struct DirWalk {
    files: u64,
    dirs: u64,
    stats: u64,
    bytes: u64,
    subdirs: Vec<InodeNumber>,
}

/// Walk a single directory: paginated `readdir` (advancing the continuation
/// offset cookie until a page comes back empty, with a no-progress guard) plus a
/// per-entry `getattr` unless `no_stat`. Returns the tally and child dirs.
fn walk_one_dir(
    open_fs: &OpenFs,
    cx: &Cx,
    ino: InodeNumber,
    no_stat: bool,
    read_data: bool,
) -> Result<DirWalk> {
    // 1 MiB read chunk for the --read-data path (the chunked-parallel read
    // engine still parallelizes within each chunk internally).
    const READ_CHUNK: u32 = 1024 * 1024;
    let mut out = DirWalk {
        files: 0,
        dirs: 0,
        stats: 0,
        bytes: 0,
        subdirs: Vec::new(),
    };
    // bd-xmh5g.419: the file-data reads are collected here and read in PARALLEL
    // across files after the (cheap) serial metadata pass — reading them serially
    // left the 64 cores idle and measured 3.85x slower than kernel `cat` on many
    // small files (per-file overhead ~0.18ms x N dominates). Each rayon worker
    // reuses one buffer (map_init below), so the per-file fresh-Vec alloc churn
    // (bd-2x68s) is still avoided.
    let mut file_inos: Vec<InodeNumber> = Vec::new();
    let mut next_off: u64 = 0;
    loop {
        let off_in = next_off;
        let entries = open_fs
            .readdir(cx, ino, off_in)
            .with_context(|| format!("failed to readdir inode {}", ino.0))?;
        if entries.is_empty() {
            break;
        }
        for entry in &entries {
            next_off = entry.offset;
            if entry.name == b"." || entry.name == b".." {
                continue;
            }
            // Direct enum compare, not `format!("{:?}", entry.kind) == "..."`:
            // the old form heap-allocated a String and ran Debug formatting twice
            // per entry purely to compare a Copy enum — dead work on every one of
            // (potentially) tens of thousands of dir entries. `FileType` is
            // `PartialEq`, so this is a single integer compare.
            let is_dir = entry.kind == ffs_core::FileType::Directory;
            let is_file = entry.kind == ffs_core::FileType::RegularFile;
            if !no_stat {
                let _attr = open_fs
                    .getattr(cx, entry.ino)
                    .with_context(|| format!("failed to getattr inode {}", entry.ino.0))?;
                out.stats += 1;
            }
            if read_data && is_file {
                // Defer the read; collected files are read in parallel below.
                file_inos.push(entry.ino);
            }
            if is_dir {
                out.dirs += 1;
                out.subdirs.push(entry.ino);
            } else {
                out.files += 1;
            }
        }
        // No-progress guard: if the continuation offset did not advance past the
        // offset we passed in, stop rather than re-reading the same page.
        if next_off <= off_in {
            break;
        }
    }
    // bd-xmh5g.419: read this directory's files in PARALLEL across files. The
    // metadata pass above is cheap (~1us/entry); the per-file data read is the
    // cost, and reading files serially leaves the pool idle. Each worker reuses
    // one READ_CHUNK buffer (map_init) — no per-file alloc churn. Data is
    // discarded; only the byte tally is summed (try_reduce surfaces the first
    // read error). For nested calls (the --parallel cross-dir path) this shares
    // the global rayon pool cooperatively.
    if read_data && !file_inos.is_empty() {
        use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
        let read_one = |buf: &mut Vec<u8>, fino: InodeNumber| -> Result<u64> {
            let mut off: u64 = 0;
            let mut total: u64 = 0;
            loop {
                let n = open_fs
                    .read_into(cx, fino, off, buf)
                    .with_context(|| format!("failed to read inode {}", fino.0))?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                off += n as u64;
                if n < READ_CHUNK as usize {
                    break;
                }
            }
            Ok(total)
        };
        // Parallelize across files ONLY when there are enough to fill the pool. A
        // directory in a deep TREE typically holds few files (~10-30); fanning those
        // across the 64-wide pool — especially nested under the --parallel cross-dir
        // path — is over-subscription churn (measured: a 15-files/dir tree is faster
        // reading each dir's files serially while --parallel carries the across-dir
        // parallelism). A single big directory (thousands of files) still fans out
        // and wins big (the many-small-files 5x). Same serialize-when-undersubscribed
        // rule as the readdir prefetch (1411c3f1).
        if file_inos.len() < rayon::current_num_threads().max(2) {
            let mut buf = vec![0_u8; READ_CHUNK as usize];
            for &fino in &file_inos {
                out.bytes += read_one(&mut buf, fino)?;
            }
        } else {
            let bytes = file_inos
                .par_iter()
                .map_init(
                    || vec![0_u8; READ_CHUNK as usize],
                    |buf, &fino| read_one(buf, fino),
                )
                .try_reduce(|| 0_u64, |a, b| Ok(a + b))?;
            out.bytes += bytes;
        }
    }
    Ok(out)
}

/// Recursively walk every directory from root, statting each entry — the no-FUSE
/// `find | xargs stat` analogue. Exercises the cold metadata path (readdir +
/// per-inode getattr → inode-table block reads + inode parse) so it can be raced
/// head-to-head against the kernel filesystem on `ls -lR` / `find` workloads.
///
/// `parallel` walks each BFS level concurrently across `available_parallelism`
/// threads — modeling the concurrent readdir+getattr a FUSE-mounted fs sees from
/// its worker threads, so the cold per-directory metadata reads overlap (the
/// single-threaded walk serializes them and understates frankenfs's throughput).
#[allow(clippy::too_many_lines)]
fn walk_cmd(path: &PathBuf, no_stat: bool, parallel: bool, read_data: bool) -> Result<()> {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    // (Removed the metadata-walk global-pool cap: the readdir inode-table prefetch
    // now serializes small per-page block sets internally, eliminating the rayon
    // over-subscription at its source — so the walk keeps the full pool and runs
    // FASTER than the old cap (warm 24.6 -> 17.8ms, cold 25.2 -> 23.4ms at the
    // natural 64-wide pool), and the fix also covers the FUSE readdir path.)

    // Cap the GLOBAL rayon pool the per-file/per-inode work fans onto to
    // min(nproc, 16) for ANY parallel walk. An nproc-wide pool (e.g. 64)
    // over-provisions the walk's actual parallelism and adds pure overhead:
    //   * --read-data: each read worker's cold pread first-touches + faults its
    //     destination buffer, so nproc buffers fault CONCURRENTLY -> kernel
    //     LRU-lock (folio_lruvec_lock_irqsave) contention (~45% of cycles,
    //     bd-kdmu4). 64t 20.7 ms/20,430 faults -> 16t 15.9 ms/5,559 = 1.30x.
    //   * metadata-only (getattr): rayon idle-worker Sleep::sleep/wait_until_cold
    //     churn + 64-thread pool spin-up dominate a short walk (bd-57lae). 16t is
    //     a clear optimum, monotonically better than 64t and NEVER a regression
    //     across scales (re-measured cold: flat 256 files 3.5->2.3 ms = 1.5x;
    //     585 dirs/5,120 files 12.0->10.7 = 1.13x; 1,111 dirs/10,000 files
    //     16.5->16.0 = 1.03x, asymptotically neutral). This differs from the old
    //     removed metadata cap (a different mechanism that regressed deep trees);
    //     a direct global-pool cap wins small and is neutral large.
    // bd-ddryj already caps the INNER read fan-out; this caps the OUTER walk.
    // build_global is best-effort (already-init = no-op). Byte-identical.
    if parallel {
        let cap = std::thread::available_parallelism()
            .map_or(8, std::num::NonZeroUsize::get)
            .min(16);
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(cap)
            .build_global();
    }

    let cx = cli_cx();
    let open_fs = OpenFs::open(&cx, path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    // A pure readdir walk (no per-entry getattr AND no file-data read) never
    // touches the entries' inodes, so the speculative inode-table prefetch in
    // readdir is dead work — disable it to elide its rayon fan-out (bd-neteo).
    // `--read-data` still resolves each inode, so keep the prefetch there.
    if (no_stat && !read_data) || std::env::var_os("FFS_NO_READDIR_PREFETCH").is_some() {
        open_fs.set_readdir_prefetch_disabled(true);
    }
    // A walk is a ONE-PASS sweep in EVERY mode: it getattrs entries by inode and
    // never resolves a name via `lookup`, and visits each inode once. So the
    // read-only repeat-access caches (readdir present-index + per-inode attr
    // cache) can only ever miss here — disable them so they are not built/grown
    // during the walk. (The prefetch above is orthogonal: it warms getattr and
    // stays on for the stat walk.)
    open_fs.set_readonly_lookup_cache_disabled(true);
    if matches!(&open_fs.flavor, FsFlavor::Btrfs(_)) {
        open_fs
            .prewarm_btrfs_read_plan_index(&cx)
            .context("failed to prewarm btrfs walk plan index")?;
    }

    // The FsOps/FUSE layer uses InodeNumber(1) as the canonical root for BOTH
    // ext4 (mapped to inode 2 internally) and btrfs (mapped to the subvolume
    // root) — so the walk is flavor-agnostic. readdir/getattr are self-scoping
    // (with_latest_scope), so no long-lived scope is held.
    let root_ino = InodeNumber(1);

    let dirs: u64;
    let files: u64;
    let stats: u64;
    let bytes: u64;
    let mode: String;
    let started = Instant::now();
    if parallel {
        let threads = std::env::var("FFS_WALK_PARALLEL_THREADS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map_or(8, std::num::NonZeroUsize::get)
                    .min(16)
            });
        mode = format!("parallel x{threads}");
        let a_dirs = AtomicU64::new(1); // count root
        let a_files = AtomicU64::new(0);
        let a_stats = AtomicU64::new(0);
        let a_bytes = AtomicU64::new(0);
        let first_err: Mutex<Option<anyhow::Error>> = Mutex::new(None);
        // Shared references captured by-value (Copy) into each `move` worker
        // closure, so the closures may own `chunk` without borrowing locals.
        let fs_ref = &open_fs;
        let cx_ref = &cx;
        let err_ref = &first_err;
        let files_ctr = &a_files;
        let dirs_ctr = &a_dirs;
        let stats_ctr = &a_stats;
        let bytes_ctr = &a_bytes;
        let mut level = vec![root_ino];
        let mut visited_dirs = std::collections::HashSet::from([root_ino.0]);
        while !level.is_empty() {
            let next: Mutex<Vec<InodeNumber>> = Mutex::new(Vec::new());
            let next_ref = &next;
            let chunk_size = level.len().div_ceil(threads).max(1);
            std::thread::scope(|s| {
                for chunk in level.chunks(chunk_size) {
                    s.spawn(move || {
                        let mut local_files = 0_u64;
                        let mut local_stats = 0_u64;
                        let mut local_bytes = 0_u64;
                        let mut lsub: Vec<InodeNumber> = Vec::new();
                        for &ino in chunk {
                            match walk_one_dir(fs_ref, cx_ref, ino, no_stat, read_data) {
                                Ok(r) => {
                                    local_files += r.files;
                                    local_stats += r.stats;
                                    local_bytes += r.bytes;
                                    lsub.extend(r.subdirs);
                                }
                                Err(e) => {
                                    let mut guard = err_ref.lock().unwrap();
                                    if guard.is_none() {
                                        *guard = Some(e);
                                    }
                                }
                            }
                        }
                        files_ctr.fetch_add(local_files, Ordering::Relaxed);
                        stats_ctr.fetch_add(local_stats, Ordering::Relaxed);
                        bytes_ctr.fetch_add(local_bytes, Ordering::Relaxed);
                        next_ref.lock().unwrap().extend(lsub);
                    });
                }
            });
            let pending_err = first_err.lock().unwrap().take();
            if let Some(e) = pending_err {
                return Err(e);
            }
            let raw_next = next.into_inner().unwrap();
            let mut unique_next = Vec::with_capacity(raw_next.len());
            for dir in raw_next {
                if visited_dirs.insert(dir.0) {
                    unique_next.push(dir);
                }
            }
            dirs_ctr.fetch_add(unique_next.len() as u64, Ordering::Relaxed);
            level = unique_next;
        }
        files = a_files.load(Ordering::Relaxed);
        dirs = a_dirs.load(Ordering::Relaxed);
        stats = a_stats.load(Ordering::Relaxed);
        bytes = a_bytes.load(Ordering::Relaxed);
    } else {
        mode = "serial".to_owned();
        let mut dir_count: u64 = 1; // count root
        let mut file_count: u64 = 0;
        let mut stat_count: u64 = 0;
        let mut byte_count: u64 = 0;
        let mut stack = vec![root_ino];
        let mut visited_dirs = std::collections::HashSet::from([root_ino.0]);
        while let Some(ino) = stack.pop() {
            let r = walk_one_dir(&open_fs, &cx, ino, no_stat, read_data)?;
            file_count += r.files;
            stat_count += r.stats;
            byte_count += r.bytes;
            for subdir in r.subdirs {
                if visited_dirs.insert(subdir.0) {
                    dir_count += 1;
                    stack.push(subdir);
                }
            }
        }
        dirs = dir_count;
        files = file_count;
        stats = stat_count;
        bytes = byte_count;
    }
    let elapsed = started.elapsed();
    let total = dirs + files;
    let per_entry_us = if total > 0 {
        (elapsed.as_secs_f64() * 1e6) / (total as f64)
    } else {
        0.0
    };
    let mb = bytes as f64 / (1024.0 * 1024.0);
    let mb_s = if elapsed.as_secs_f64() > 0.0 {
        mb / elapsed.as_secs_f64()
    } else {
        0.0
    };
    eprintln!(
        "walked {dirs} dirs + {files} files ({total} entries, {stats} stats, {bytes} bytes / \
         {mb:.1} MiB @ {mb_s:.0} MiB/s) [{mode}] in {elapsed:?} ({per_entry_us:.2} us/entry)"
    );
    Ok(())
}

fn mvcc_stats_cmd(path: &PathBuf, json: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::mvcc_stats",
        "mvcc_stats",
        image = %path.display(),
        output_json = json
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::mvcc_stats", "mvcc_stats_start");

    let cx = cli_cx();
    let open_opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let open_fs = OpenFs::open_with_options(&cx, path, &open_opts)
        .with_context(|| format!("failed to open image: {}", path.display()))?;

    let block_stats = open_fs.mvcc_block_version_stats();
    let ebr_stats = open_fs.mvcc_ebr_stats();

    let output = MvccStatsOutput {
        block_versions: BlockVersionStatsOutput {
            tracked_blocks: block_stats.tracked_blocks,
            max_chain_length: block_stats.max_chain_length,
            chains_over_cap: block_stats.chains_over_cap,
            chains_over_critical: block_stats.chains_over_critical,
            chain_cap: block_stats.chain_cap,
            critical_chain_length: block_stats.critical_chain_length,
        },
        ebr_versions: EbrVersionStatsOutput {
            retired: ebr_stats.retired_versions,
            reclaimed: ebr_stats.reclaimed_versions,
            pending: ebr_stats.pending_versions(),
        },
        wal_replay: build_wal_replay_info(&open_fs),
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize mvcc stats output")?
        );
    } else {
        println!("FrankenFS MVCC/EBR Stats");
        println!("block_versions:");
        println!("  tracked_blocks: {}", output.block_versions.tracked_blocks);
        println!(
            "  max_chain_length: {}",
            output.block_versions.max_chain_length
        );
        println!(
            "  chains_over_cap: {}",
            output.block_versions.chains_over_cap
        );
        println!(
            "  chains_over_critical: {}",
            output.block_versions.chains_over_critical
        );
        println!("  chain_cap: {:?}", output.block_versions.chain_cap);
        println!(
            "  critical_chain_length: {:?}",
            output.block_versions.critical_chain_length
        );
        println!("ebr_versions:");
        println!("  retired_versions: {}", output.ebr_versions.retired);
        println!("  reclaimed_versions: {}", output.ebr_versions.reclaimed);
        println!("  pending_versions: {}", output.ebr_versions.pending);
        if let Some(wal) = &output.wal_replay {
            println!("wal_replay:");
            print_wal_replay_info(wal, "  ");
        }
    }

    if let Some(wal) = &output.wal_replay {
        log_wal_recovery_telemetry(wal);
    }

    info!(
        target: "ffs::cli::mvcc_stats",
        tracked_blocks = output.block_versions.tracked_blocks,
        max_chain_length = output.block_versions.max_chain_length,
        pending_versions = output.ebr_versions.pending,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "mvcc_stats_complete"
    );

    Ok(())
}

fn info_cmd(path: &PathBuf, options: InfoCommandOptions) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::info",
        "info",
        image = %path.display(),
        include_groups = options.sections.groups(),
        include_mvcc = options.sections.mvcc(),
        include_repair = options.sections.repair(),
        include_journal = options.sections.journal(),
        output_json = options.json
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::info", "info_start");

    let cx = cli_cx();
    let open_opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let open_fs = OpenFs::open_with_options(&cx, path, &open_opts)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let output = build_info_output(path, &cx, &open_fs, options)?;

    print_info_output(options.json, &output)?;

    info!(
        target: "ffs::cli::info",
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        limitations = output.limitations.len(),
        "info_complete"
    );

    Ok(())
}

fn build_info_output(
    path: &PathBuf,
    cx: &Cx,
    open_fs: &OpenFs,
    options: InfoCommandOptions,
) -> Result<InfoOutput> {
    let mut limitations = Vec::new();

    let groups_output = if options.sections.groups() {
        match &open_fs.flavor {
            FsFlavor::Ext4(sb) => Some(GroupsInfoOutput::Ext4 {
                entries: build_ext4_group_info(path, sb)?,
            }),
            FsFlavor::Btrfs(sb) => Some(GroupsInfoOutput::Btrfs {
                entries: build_btrfs_group_info(open_fs, sb, &mut limitations),
            }),
        }
    } else {
        None
    };

    let mvcc_output = if options.sections.mvcc() {
        Some(build_mvcc_info(open_fs))
    } else {
        None
    };

    let repair_output = if options.sections.repair() {
        Some(build_repair_info(path, open_fs, &mut limitations))
    } else {
        None
    };

    let journal_output = if options.sections.journal() {
        match &open_fs.flavor {
            FsFlavor::Ext4(sb) => Some(build_ext4_journal_info(cx, open_fs, sb)),
            FsFlavor::Btrfs(_) => Some(JournalInfoOutput::Unsupported {
                reason: "btrfs journal status is not applicable (btrfs is copy-on-write)"
                    .to_owned(),
            }),
        }
    } else {
        None
    };

    Ok(InfoOutput {
        filesystem: filesystem_name(&open_fs.flavor).to_owned(),
        superblock: superblock_info_for(&open_fs.flavor),
        groups: groups_output,
        mvcc: mvcc_output,
        repair: repair_output,
        journal: journal_output,
        limitations,
    })
}

#[must_use]
pub fn filesystem_name(flavor: &FsFlavor) -> &'static str {
    match flavor {
        FsFlavor::Ext4(_) => "ext4",
        FsFlavor::Btrfs(_) => "btrfs",
    }
}

fn ext4_quota_inodes_for_output(sb: &Ext4Superblock) -> Option<Ext4QuotaInodes> {
    let quota_inodes = sb.quota_inodes();
    (quota_inodes.user.is_some() || quota_inodes.group.is_some() || quota_inodes.project.is_some())
        .then_some(quota_inodes)
}

fn format_ext4_quota_inodes(quota_inodes: &Ext4QuotaInodes) -> String {
    let mut entries = Vec::new();
    if let Some(user) = quota_inodes.user {
        entries.push(format!("user={user}"));
    }
    if let Some(group) = quota_inodes.group {
        entries.push(format!("group={group}"));
    }
    if let Some(project) = quota_inodes.project {
        entries.push(format!("project={project}"));
    }
    entries.join(" ")
}

fn superblock_info_for(flavor: &FsFlavor) -> SuperblockInfoOutput {
    match flavor {
        FsFlavor::Ext4(sb) => {
            let checksum_type = if sb.checksum_type == 1 {
                "crc32c".to_owned()
            } else {
                format!("unknown({})", sb.checksum_type)
            };

            SuperblockInfoOutput::Ext4 {
                uuid: format_uuid(&sb.uuid),
                label: sb.volume_name.clone(),
                block_size: sb.block_size,
                blocks_total: sb.blocks_count,
                blocks_free: sb.free_blocks_count,
                blocks_reserved: sb.reserved_blocks_count,
                inodes_total: sb.inodes_count,
                inodes_free: sb.free_inodes_count,
                blocks_per_group: sb.blocks_per_group,
                inodes_per_group: sb.inodes_per_group,
                groups_count: sb.groups_count(),
                mount_count: sb.mnt_count,
                max_mount_count: sb.max_mnt_count,
                state_flags: ext4_state_flag_names(sb.state),
                feature_compat: format!("{}", sb.feature_compat),
                feature_incompat: format!("{}", sb.feature_incompat),
                feature_ro_compat: format!("{}", sb.feature_ro_compat),
                checksum_type,
                checksum_seed: sb.csum_seed(),
                quota_inodes: ext4_quota_inodes_for_output(sb),
                mtime: sb.mtime,
                wtime: sb.wtime,
                lastcheck: sb.lastcheck,
                mkfs_time: sb.mkfs_time,
            }
        }
        FsFlavor::Btrfs(sb) => SuperblockInfoOutput::Btrfs {
            fsid: format_uuid(&sb.fsid),
            label: sb.label.clone(),
            sectorsize: sb.sectorsize,
            nodesize: sb.nodesize,
            generation: sb.generation,
            total_bytes: sb.total_bytes,
            bytes_used: sb.bytes_used,
            bytes_free: sb.total_bytes.saturating_sub(sb.bytes_used),
            num_devices: sb.num_devices,
            csum_type: btrfs_checksum_type_name(sb.csum_type),
            compat_flags_hex: format!("0x{:016x}", sb.compat_flags),
            compat_ro_flags_hex: format!("0x{:016x}", sb.compat_ro_flags),
            incompat_flags_hex: format!("0x{:016x}", sb.incompat_flags),
        },
    }
}

fn build_ext4_group_info(path: &PathBuf, sb: &Ext4Superblock) -> Result<Vec<Ext4GroupInfoOutput>> {
    let groups_count = sb.groups_count();
    if groups_count > MAX_EXT4_INFO_GROUPS {
        bail!(
            "ext4 info group count {groups_count} exceeds supported info scan cap {MAX_EXT4_INFO_GROUPS}; \
             superblock geometry is likely corrupt or outside V1 info scope"
        );
    }

    let capacity =
        usize::try_from(groups_count).context("ext4 info group count does not fit this target")?;
    let mut groups = Vec::with_capacity(capacity);
    let inodes_total = u64::from(sb.inodes_count);

    for group in 0..groups_count {
        let (desc, _raw_desc) = read_ext4_group_desc_from_path(path, sb, group)?;

        let block_start = u64::from(sb.first_data_block)
            .saturating_add(u64::from(group).saturating_mul(u64::from(sb.blocks_per_group)));
        let block_end_exclusive = block_start
            .saturating_add(u64::from(sb.blocks_per_group))
            .min(sb.blocks_count);

        let inode_start = u64::from(group)
            .saturating_mul(u64::from(sb.inodes_per_group))
            .saturating_add(1);
        let inode_end_exclusive = inode_start
            .saturating_add(u64::from(sb.inodes_per_group))
            .min(inodes_total.saturating_add(1));

        groups.push(Ext4GroupInfoOutput {
            group,
            block_start,
            block_end_inclusive: block_end_exclusive.saturating_sub(1),
            free_blocks: desc.free_blocks_count,
            inode_start,
            inode_end_inclusive: inode_end_exclusive.saturating_sub(1),
            free_inodes: desc.free_inodes_count,
            flags_raw: desc.flags,
            flags: ext4_group_flag_names(desc.flags),
        });
    }

    Ok(groups)
}

fn build_btrfs_group_info(
    open_fs: &OpenFs,
    _sb: &BtrfsSuperblock,
    limitations: &mut Vec<String>,
) -> Vec<BtrfsGroupInfoOutput> {
    let Some(ctx) = open_fs.btrfs_context() else {
        limitations.push("btrfs chunk mapping context is unavailable".to_owned());
        return Vec::new();
    };

    let mut entries = Vec::with_capacity(ctx.chunks.len());
    for (chunk_index, chunk) in ctx.chunks.iter().enumerate() {
        let logical_end_inclusive = chunk
            .key
            .offset
            .saturating_add(chunk.length.saturating_sub(1));

        let stripes = chunk
            .stripes
            .iter()
            .enumerate()
            .map(|(stripe_index, stripe)| BtrfsStripeInfoOutput {
                stripe_index: u16::try_from(stripe_index).unwrap_or(u16::MAX),
                devid: stripe.devid,
                physical_start: stripe.offset,
                physical_end_inclusive: stripe
                    .offset
                    .saturating_add(chunk.length.saturating_sub(1)),
                device_uuid: format_uuid(&stripe.dev_uuid),
            })
            .collect();

        entries.push(BtrfsGroupInfoOutput {
            chunk_index: u32::try_from(chunk_index).unwrap_or(u32::MAX),
            logical_start: chunk.key.offset,
            logical_end_inclusive,
            logical_bytes: chunk.length,
            chunk_type_raw: chunk.chunk_type,
            chunk_type_flags: btrfs_chunk_type_flag_names(chunk.chunk_type),
            owner: chunk.owner,
            stripe_len: chunk.stripe_len,
            sector_size: chunk.sector_size,
            stripe_count: chunk.num_stripes,
            stripes,
        });
    }

    entries
}

#[must_use]
fn encode_btrfs_chunk_entry_bytes(chunk: &ffs_ondisk::BtrfsChunkEntry) -> Vec<u8> {
    debug_assert_eq!(usize::from(chunk.num_stripes), chunk.stripes.len());

    let mut out = Vec::with_capacity(17 + 48 + chunk.stripes.len().saturating_mul(32));
    out.extend_from_slice(&chunk.key.objectid.to_le_bytes());
    out.push(chunk.key.item_type);
    out.extend_from_slice(&chunk.key.offset.to_le_bytes());
    out.extend_from_slice(&chunk.length.to_le_bytes());
    out.extend_from_slice(&chunk.owner.to_le_bytes());
    out.extend_from_slice(&chunk.stripe_len.to_le_bytes());
    out.extend_from_slice(&chunk.chunk_type.to_le_bytes());
    out.extend_from_slice(&chunk.io_align.to_le_bytes());
    out.extend_from_slice(&chunk.io_width.to_le_bytes());
    out.extend_from_slice(&chunk.sector_size.to_le_bytes());
    out.extend_from_slice(&chunk.num_stripes.to_le_bytes());
    out.extend_from_slice(&chunk.sub_stripes.to_le_bytes());

    for stripe in &chunk.stripes {
        out.extend_from_slice(&stripe.devid.to_le_bytes());
        out.extend_from_slice(&stripe.offset.to_le_bytes());
        out.extend_from_slice(&stripe.dev_uuid);
    }

    out
}

fn build_mvcc_info(open_fs: &OpenFs) -> MvccInfoOutput {
    let current_commit_seq = open_fs.current_snapshot().high.0;
    let active_snapshot_count = open_fs.mvcc_active_snapshot_count();
    let oldest_active_snapshot = open_fs.mvcc_oldest_active_snapshot().map(|seq| seq.0);
    let block_stats = open_fs.mvcc_block_version_stats();
    let total_versioned_entries = open_fs.mvcc_version_count();
    let ebr_stats = open_fs.mvcc_ebr_stats();
    let txn_outcomes = open_fs.mvcc_transaction_outcome_stats();

    let wal_replay = build_wal_replay_info(open_fs);
    if let Some(wal) = &wal_replay {
        log_wal_recovery_telemetry(wal);
    }

    MvccInfoOutput {
        current_commit_seq,
        active_snapshot_count,
        oldest_active_snapshot,
        total_versioned_blocks: block_stats.tracked_blocks,
        max_chain_depth: block_stats.max_chain_length,
        average_chain_depth: format_ratio_thousandths(
            total_versioned_entries,
            block_stats.tracked_blocks,
        ),
        blocks_pending_gc: ebr_stats.pending_versions(),
        ssi_conflict_count: Some(txn_outcomes.ssi_conflicts),
        abort_count: Some(txn_outcomes.aborted_transactions),
        wal_replay,
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct RepairStalenessSummary {
    total: u32,
    fresh: u32,
    stale: u32,
    untracked: u32,
}

fn summarize_repair_staleness(states: &[(u32, Ext4RepairStaleness)]) -> RepairStalenessSummary {
    let mut summary = RepairStalenessSummary {
        total: u32::try_from(states.len()).unwrap_or(u32::MAX),
        ..RepairStalenessSummary::default()
    };

    for (_, state) in states {
        match state {
            Ext4RepairStaleness::Fresh => {
                summary.fresh = summary.fresh.saturating_add(1);
            }
            Ext4RepairStaleness::Stale => {
                summary.stale = summary.stale.saturating_add(1);
            }
            Ext4RepairStaleness::Untracked => {
                summary.untracked = summary.untracked.saturating_add(1);
            }
        }
    }

    summary
}

fn unavailable_repair_info(note: &str) -> RepairInfoOutput {
    RepairInfoOutput {
        configured_overhead_ratio: DEFAULT_REPAIR_OVERHEAD_RATIO,
        metrics_available: false,
        note: note.to_owned(),
        groups_total: None,
        groups_fresh: None,
        groups_stale: None,
        groups_untracked: None,
    }
}

fn build_repair_info(
    path: &PathBuf,
    open_fs: &OpenFs,
    limitations: &mut Vec<String>,
) -> RepairInfoOutput {
    match &open_fs.flavor {
        FsFlavor::Ext4(sb) => {
            match build_ext4_repair_group_specs(sb).and_then(|specs| {
                probe_ext4_repair_staleness(path, sb.block_size, &specs)
                    .map(|states| summarize_repair_staleness(&states))
            }) {
                Ok(summary) => RepairInfoOutput {
                    configured_overhead_ratio: DEFAULT_REPAIR_OVERHEAD_RATIO,
                    metrics_available: true,
                    note: "live ext4 repair-group descriptor/symbol status".to_owned(),
                    groups_total: Some(summary.total),
                    groups_fresh: Some(summary.fresh),
                    groups_stale: Some(summary.stale),
                    groups_untracked: Some(summary.untracked),
                },
                Err(error) => {
                    limitations.push(format!(
                        "repair metrics probe failed for ext4 image: {error:#}"
                    ));
                    unavailable_repair_info(
                        "live ext4 repair metrics unavailable (see limitations)",
                    )
                }
            }
        }
        FsFlavor::Btrfs(sb) => {
            let metrics = std::fs::metadata(path)
                .with_context(|| format!("failed to inspect image metadata: {}", path.display()))
                .map(|meta| meta.len())
                .and_then(|image_len| {
                    choose_btrfs_scrub_block_size(image_len, sb.nodesize, sb.sectorsize)
                        .with_context(|| {
                            format!(
                                "failed to determine btrfs scrub block size (len_bytes={image_len}, nodesize={}, sectorsize={})",
                                sb.nodesize, sb.sectorsize
                            )
                        })
                })
                .and_then(|block_size| {
                    discover_btrfs_repair_group_specs(path, block_size).and_then(|specs| {
                        probe_btrfs_repair_staleness(path, block_size, &specs)
                            .map(|states| summarize_repair_staleness(&states))
                    })
                });

            match metrics {
                Ok(summary) => RepairInfoOutput {
                    configured_overhead_ratio: DEFAULT_REPAIR_OVERHEAD_RATIO,
                    metrics_available: true,
                    note: "live btrfs repair-group descriptor/symbol status".to_owned(),
                    groups_total: Some(summary.total),
                    groups_fresh: Some(summary.fresh),
                    groups_stale: Some(summary.stale),
                    groups_untracked: Some(summary.untracked),
                },
                Err(error) => {
                    limitations.push(format!(
                        "repair metrics probe failed for btrfs image: {error:#}"
                    ));
                    unavailable_repair_info(
                        "live btrfs repair metrics unavailable (see limitations)",
                    )
                }
            }
        }
    }
}

fn build_ext4_journal_info(cx: &Cx, open_fs: &OpenFs, sb: &Ext4Superblock) -> JournalInfoOutput {
    let journal_size_bytes = if sb.journal_inum == 0 {
        None
    } else {
        open_fs
            .read_inode(cx, InodeNumber(u64::from(sb.journal_inum)))
            .ok()
            .map(|inode| inode.size)
    };

    let replayed_transactions = open_fs.ext4_journal_replay().map_or(0_u32, |replay| {
        u32::try_from(replay.committed_sequences.len()).unwrap_or(u32::MAX)
    });
    let replayed_blocks = open_fs
        .ext4_journal_replay()
        .map_or(0_u64, |replay| replay.stats.replayed_blocks);
    let scanned_blocks = open_fs
        .ext4_journal_replay()
        .map_or(0_u64, |replay| replay.stats.scanned_blocks);
    let descriptor_blocks = open_fs
        .ext4_journal_replay()
        .map_or(0_u64, |replay| replay.stats.descriptor_blocks);
    let commit_blocks = open_fs
        .ext4_journal_replay()
        .map_or(0_u64, |replay| replay.stats.commit_blocks);
    let revoke_blocks = open_fs
        .ext4_journal_replay()
        .map_or(0_u64, |replay| replay.stats.revoke_blocks);
    let skipped_revoked_blocks = open_fs
        .ext4_journal_replay()
        .map_or(0_u64, |replay| replay.stats.skipped_revoked_blocks);
    let incomplete_transactions = open_fs
        .ext4_journal_replay()
        .map_or(0_u64, |replay| replay.stats.incomplete_transactions);

    JournalInfoOutput::Ext4 {
        journal_inode: sb.journal_inum,
        external_journal_dev: sb.journal_dev,
        journal_uuid: format_uuid(&sb.journal_uuid),
        journal_size_bytes,
        replayed_transactions,
        replayed_blocks,
        scanned_blocks,
        descriptor_blocks,
        commit_blocks,
        revoke_blocks,
        skipped_revoked_blocks,
        incomplete_transactions,
    }
}

fn print_info_output(json: bool, output: &InfoOutput) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(output).context("serialize info output")?
        );
        return Ok(());
    }

    println!("FrankenFS Filesystem Info");
    println!("filesystem: {}", output.filesystem);
    print_superblock_info(&output.superblock);

    if let Some(groups) = &output.groups {
        print_groups_info(groups);
    }

    if let Some(mvcc) = &output.mvcc {
        print_mvcc_info(mvcc);
    }

    if let Some(repair) = &output.repair {
        print_repair_info(repair);
    }

    if let Some(journal) = &output.journal {
        print_journal_info(journal);
    }

    if !output.limitations.is_empty() {
        print_limitations(&output.limitations);
    }

    Ok(())
}

fn print_groups_info(groups: &GroupsInfoOutput) {
    match groups {
        GroupsInfoOutput::Ext4 { entries } => {
            println!();
            println!("groups: {}", entries.len());
            for group in entries {
                println!(
                    "  group={} blocks={}..{} free_blocks={} inodes={}..{} free_inodes={} flags={}",
                    group.group,
                    group.block_start,
                    group.block_end_inclusive,
                    group.free_blocks,
                    group.inode_start,
                    group.inode_end_inclusive,
                    group.free_inodes,
                    group.flags.join("|")
                );
            }
        }
        GroupsInfoOutput::Btrfs { entries } => {
            println!();
            println!("chunks: {}", entries.len());
            for chunk in entries {
                println!(
                    "  chunk={} logical={}..{} bytes={} type={} stripes={} flags={}",
                    chunk.chunk_index,
                    chunk.logical_start,
                    chunk.logical_end_inclusive,
                    chunk.logical_bytes,
                    chunk.chunk_type_raw,
                    chunk.stripe_count,
                    chunk.chunk_type_flags.join("|")
                );
                for stripe in &chunk.stripes {
                    println!(
                        "    stripe={} devid={} physical={}..{}",
                        stripe.stripe_index,
                        stripe.devid,
                        stripe.physical_start,
                        stripe.physical_end_inclusive
                    );
                }
            }
        }
    }
}

fn print_mvcc_info(mvcc: &MvccInfoOutput) {
    println!();
    println!("mvcc:");
    println!("  current_commit_seq: {}", mvcc.current_commit_seq);
    println!("  active_snapshot_count: {}", mvcc.active_snapshot_count);
    println!(
        "  oldest_active_snapshot: {}",
        mvcc.oldest_active_snapshot
            .map_or_else(|| "none".to_owned(), |value| value.to_string())
    );
    println!("  total_versioned_blocks: {}", mvcc.total_versioned_blocks);
    println!("  max_chain_depth: {}", mvcc.max_chain_depth);
    println!("  average_chain_depth: {}", mvcc.average_chain_depth);
    println!("  blocks_pending_gc: {}", mvcc.blocks_pending_gc);
    if let Some(ssi_conflict_count) = mvcc.ssi_conflict_count {
        println!("  ssi_conflict_count: {ssi_conflict_count}");
    }
    if let Some(abort_count) = mvcc.abort_count {
        println!("  abort_count: {abort_count}");
    }
    if let Some(wal) = &mvcc.wal_replay {
        println!("  wal_replay:");
        print_wal_replay_info(wal, "    ");
    }
}

fn print_repair_info(repair: &RepairInfoOutput) {
    println!();
    println!("repair:");
    println!(
        "  configured_overhead_ratio: {:.3}",
        repair.configured_overhead_ratio
    );
    println!("  metrics_available: {}", repair.metrics_available);
    println!("  note: {}", repair.note);
    if let Some(groups_total) = repair.groups_total {
        println!("  groups_total: {groups_total}");
    }
    if let Some(groups_fresh) = repair.groups_fresh {
        println!("  groups_fresh: {groups_fresh}");
    }
    if let Some(groups_stale) = repair.groups_stale {
        println!("  groups_stale: {groups_stale}");
    }
    if let Some(groups_untracked) = repair.groups_untracked {
        println!("  groups_untracked: {groups_untracked}");
    }
}

fn print_journal_info(journal: &JournalInfoOutput) {
    println!();
    match journal {
        JournalInfoOutput::Ext4 {
            journal_inode,
            external_journal_dev,
            journal_uuid,
            journal_size_bytes,
            replayed_transactions,
            replayed_blocks,
            scanned_blocks,
            descriptor_blocks,
            commit_blocks,
            revoke_blocks,
            skipped_revoked_blocks,
            incomplete_transactions,
        } => {
            println!("journal:");
            println!("  inode: {journal_inode}");
            println!("  external_dev: {external_journal_dev}");
            println!("  uuid: {journal_uuid}");
            println!(
                "  size_bytes: {}",
                journal_size_bytes.map_or_else(|| "unknown".to_owned(), |value| value.to_string())
            );
            println!("  replayed_transactions: {replayed_transactions}");
            println!("  replayed_blocks: {replayed_blocks}");
            println!("  scanned_blocks: {scanned_blocks}");
            println!("  descriptor_blocks: {descriptor_blocks}");
            println!("  commit_blocks: {commit_blocks}");
            println!("  revoke_blocks: {revoke_blocks}");
            println!("  skipped_revoked_blocks: {skipped_revoked_blocks}");
            println!("  incomplete_transactions: {incomplete_transactions}");
        }
        JournalInfoOutput::Unsupported { reason } => {
            println!("journal: unsupported ({reason})");
        }
    }
}

fn print_limitations(limitations: &[String]) {
    println!();
    println!("limitations:");
    for limitation in limitations {
        println!("  - {limitation}");
    }
}

fn print_superblock_info(superblock: &SuperblockInfoOutput) {
    match superblock {
        SuperblockInfoOutput::Ext4 {
            uuid,
            label,
            block_size,
            blocks_total,
            blocks_free,
            blocks_reserved,
            inodes_total,
            inodes_free,
            blocks_per_group,
            inodes_per_group,
            groups_count,
            mount_count,
            max_mount_count,
            state_flags,
            feature_compat,
            feature_incompat,
            feature_ro_compat,
            checksum_type,
            checksum_seed,
            quota_inodes,
            mtime,
            wtime,
            lastcheck,
            mkfs_time,
        } => {
            println!("superblock (ext4):");
            println!("  uuid: {uuid}");
            println!("  label: {label}");
            println!("  block_size: {block_size}");
            println!("  blocks_total: {blocks_total}");
            println!("  blocks_free: {blocks_free}");
            println!("  blocks_reserved: {blocks_reserved}");
            println!("  inodes_total: {inodes_total}");
            println!("  inodes_free: {inodes_free}");
            println!("  blocks_per_group: {blocks_per_group}");
            println!("  inodes_per_group: {inodes_per_group}");
            println!("  groups_count: {groups_count}");
            println!("  mount_count: {mount_count}");
            println!("  max_mount_count: {max_mount_count}");
            println!("  state_flags: {}", state_flags.join("|"));
            println!("  feature_compat: {feature_compat}");
            println!("  feature_incompat: {feature_incompat}");
            println!("  feature_ro_compat: {feature_ro_compat}");
            println!("  checksum_type: {checksum_type}");
            println!("  checksum_seed: {checksum_seed}");
            if let Some(quota_inodes) = quota_inodes {
                println!("  quota_inodes: {}", format_ext4_quota_inodes(quota_inodes));
            }
            println!("  mtime: {mtime}");
            println!("  wtime: {wtime}");
            println!("  lastcheck: {lastcheck}");
            println!("  mkfs_time: {mkfs_time}");
        }
        SuperblockInfoOutput::Btrfs {
            fsid,
            label,
            sectorsize,
            nodesize,
            generation,
            total_bytes,
            bytes_used,
            bytes_free,
            num_devices,
            csum_type,
            compat_flags_hex,
            compat_ro_flags_hex,
            incompat_flags_hex,
        } => {
            println!("superblock (btrfs):");
            println!("  fsid: {fsid}");
            println!("  label: {label}");
            println!("  sectorsize: {sectorsize}");
            println!("  nodesize: {nodesize}");
            println!("  generation: {generation}");
            println!("  total_bytes: {total_bytes}");
            println!("  bytes_used: {bytes_used}");
            println!("  bytes_free: {bytes_free}");
            println!("  num_devices: {num_devices}");
            println!("  checksum_type: {csum_type}");
            println!("  compat_flags: {compat_flags_hex}");
            println!("  compat_ro_flags: {compat_ro_flags_hex}");
            println!("  incompat_flags: {incompat_flags_hex}");
        }
    }
}

fn ext4_state_flag_names(state: u16) -> Vec<String> {
    const EXT4_VALID_FS: u16 = 0x0001;
    const EXT4_ERROR_FS: u16 = 0x0002;
    const EXT4_ORPHAN_FS: u16 = 0x0004;

    let mut names = Vec::new();
    if (state & EXT4_VALID_FS) != 0 {
        names.push("VALID_FS".to_owned());
    }
    if (state & EXT4_ERROR_FS) != 0 {
        names.push("ERROR_FS".to_owned());
    }
    if (state & EXT4_ORPHAN_FS) != 0 {
        names.push("ORPHAN_FS".to_owned());
    }

    let known = EXT4_VALID_FS | EXT4_ERROR_FS | EXT4_ORPHAN_FS;
    let unknown = state & !known;
    if unknown != 0 {
        names.push(format!("UNKNOWN(0x{unknown:04X})"));
    }
    if names.is_empty() {
        names.push("NONE".to_owned());
    }
    names
}

#[must_use]
pub fn ext4_appears_clean_state(state: u16) -> bool {
    const EXT4_VALID_FS: u16 = 0x0001;
    const EXT4_ERROR_FS: u16 = 0x0002;
    const EXT4_ORPHAN_FS: u16 = 0x0004;

    (state & EXT4_VALID_FS) != 0 && (state & EXT4_ERROR_FS) == 0 && (state & EXT4_ORPHAN_FS) == 0
}

fn ext4_group_flag_names(flags: u16) -> Vec<String> {
    // bd-glkri — use the canonical kernel-conformance-pinned constants
    // from ffs_ondisk instead of fn-local re-derivations.
    use ffs_ondisk::{EXT4_BG_BLOCK_UNINIT, EXT4_BG_INODE_UNINIT, EXT4_BG_INODE_ZEROED};

    let mut names = Vec::new();
    if (flags & EXT4_BG_INODE_UNINIT) != 0 {
        names.push("INODE_UNINIT".to_owned());
    }
    if (flags & EXT4_BG_BLOCK_UNINIT) != 0 {
        names.push("BLOCK_UNINIT".to_owned());
    }
    if (flags & EXT4_BG_INODE_ZEROED) != 0 {
        names.push("INODE_ZEROED".to_owned());
    }

    let known = EXT4_BG_INODE_UNINIT | EXT4_BG_BLOCK_UNINIT | EXT4_BG_INODE_ZEROED;
    let unknown = flags & !known;
    if unknown != 0 {
        names.push(format!("UNKNOWN(0x{unknown:04X})"));
    }
    if names.is_empty() {
        names.push("NONE".to_owned());
    }
    names
}

fn btrfs_chunk_type_flag_names(chunk_type: u64) -> Vec<String> {
    const BTRFS_BLOCK_GROUP_DATA: u64 = 1;
    const BTRFS_BLOCK_GROUP_SYSTEM: u64 = 2;
    const BTRFS_BLOCK_GROUP_METADATA: u64 = 4;

    let mut flags = Vec::new();
    if (chunk_type & BTRFS_BLOCK_GROUP_DATA) != 0 {
        flags.push("DATA".to_owned());
    }
    if (chunk_type & BTRFS_BLOCK_GROUP_SYSTEM) != 0 {
        flags.push("SYSTEM".to_owned());
    }
    if (chunk_type & BTRFS_BLOCK_GROUP_METADATA) != 0 {
        flags.push("METADATA".to_owned());
    }

    let known = BTRFS_BLOCK_GROUP_DATA | BTRFS_BLOCK_GROUP_SYSTEM | BTRFS_BLOCK_GROUP_METADATA;
    let unknown = chunk_type & !known;
    if unknown != 0 {
        flags.push(format!("UNKNOWN(0x{unknown:016x})"));
    }
    if flags.is_empty() {
        flags.push("NONE".to_owned());
    }
    flags
}

fn btrfs_checksum_type_name(csum_type: u16) -> String {
    if csum_type == ffs_types::BTRFS_CSUM_TYPE_CRC32C {
        "crc32c".to_owned()
    } else {
        format!("unknown({csum_type})")
    }
}

fn format_uuid(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn format_ratio_thousandths(numerator: usize, denominator: usize) -> String {
    if denominator == 0 {
        return "0.000".to_owned();
    }

    let numerator_u128 = u128::try_from(numerator).unwrap_or(u128::MAX);
    let denominator_u128 = u128::try_from(denominator).unwrap_or(1);
    let milli = numerator_u128
        .saturating_mul(1000)
        .saturating_div(denominator_u128);
    let whole = milli / 1000;
    let fractional = milli % 1000;
    format!("{whole}.{fractional:03}")
}

fn dump_cmd(command: &DumpCommand) -> Result<()> {
    match command {
        DumpCommand::Superblock { image, json, hex } => dump_superblock_cmd(image, *json, *hex),
        DumpCommand::Group {
            group,
            image,
            json,
            hex,
        } => dump_group_cmd(*group, image, *json, *hex),
        DumpCommand::Inode {
            inode,
            image,
            json,
            hex,
        } => dump_inode_cmd(*inode, image, *json, *hex),
        DumpCommand::Extents {
            inode,
            image,
            json,
            hex,
        } => dump_extents_cmd(*inode, image, *json, *hex),
        DumpCommand::Dir {
            inode,
            image,
            json,
            hex,
        } => dump_dir_cmd(*inode, image, *json, *hex),
    }
}

fn dump_superblock_cmd(path: &PathBuf, json: bool, hex: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::dump::superblock",
        "dump_superblock",
        image = %path.display(),
        output_json = json,
        include_hex = hex
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::dump::superblock", "dump_superblock_start");

    let cx = cli_cx();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;

    let raw_hex = if hex {
        let (offset, len, label) = match &flavor {
            FsFlavor::Ext4(_) => (
                EXT4_SUPERBLOCK_OFFSET,
                EXT4_SUPERBLOCK_SIZE,
                "ext4 superblock",
            ),
            FsFlavor::Btrfs(_) => (
                BTRFS_SUPER_INFO_OFFSET,
                BTRFS_SUPER_INFO_SIZE,
                "btrfs superblock",
            ),
        };
        let bytes = read_file_region(path, offset, len, label)?;
        Some(bytes_to_hex_dump(&bytes))
    } else {
        None
    };

    let output = DumpSuperblockOutput {
        filesystem: filesystem_name(&flavor).to_owned(),
        superblock: superblock_info_for(&flavor),
        raw_hex,
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize dump superblock output")?
        );
    } else {
        println!("FrankenFS Dump: superblock");
        println!("filesystem: {}", output.filesystem);
        print_superblock_info(&output.superblock);
        if let Some(raw_hex) = &output.raw_hex {
            println!();
            println!("raw_hex:");
            println!("{raw_hex}");
        }
    }

    info!(
        target: "ffs::cli::dump::superblock",
        filesystem = output.filesystem,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "dump_superblock_complete"
    );

    Ok(())
}

fn dump_group_cmd(group: u32, path: &PathBuf, json: bool, hex: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::dump::group",
        "dump_group",
        image = %path.display(),
        group,
        output_json = json,
        include_hex = hex
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::dump::group", "dump_group_start");

    let output = build_dump_group_output(path, group, hex)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize dump group output")?
        );
    } else {
        println!("FrankenFS Dump: group");
        println!("filesystem: {}", output.filesystem);
        println!("group: {}", output.group);
        if let Some(descriptor) = &output.descriptor {
            println!("descriptor:");
            println!("  block_bitmap: {}", descriptor.block_bitmap);
            println!("  inode_bitmap: {}", descriptor.inode_bitmap);
            println!("  inode_table: {}", descriptor.inode_table);
            println!("  free_blocks_count: {}", descriptor.free_blocks_count);
            println!("  free_inodes_count: {}", descriptor.free_inodes_count);
            println!("  used_dirs_count: {}", descriptor.used_dirs_count);
            println!("  itable_unused: {}", descriptor.itable_unused);
            println!("  flags: 0x{:04X}", descriptor.flags);
            println!("  checksum: 0x{:04X}", descriptor.checksum);
        }
        if let Some(chunk) = &output.btrfs_chunk {
            println!("chunk:");
            println!(
                "  logical: {}..{} (bytes={})",
                chunk.logical_start, chunk.logical_end_inclusive, chunk.logical_bytes
            );
            println!(
                "  type: {} ({})",
                chunk.chunk_type_raw,
                chunk.chunk_type_flags.join("|")
            );
            println!("  owner: {}", chunk.owner);
            println!("  stripe_len: {}", chunk.stripe_len);
            println!("  sector_size: {}", chunk.sector_size);
            println!("  stripes: {}", chunk.stripe_count);
            for stripe in &chunk.stripes {
                println!(
                    "    stripe={} devid={} physical={}..{}",
                    stripe.stripe_index,
                    stripe.devid,
                    stripe.physical_start,
                    stripe.physical_end_inclusive
                );
            }
        }

        if let Some(raw_hex) = &output.raw_hex {
            println!();
            println!("raw_hex:");
            println!("{raw_hex}");
        }
        if !output.limitations.is_empty() {
            println!();
            println!("limitations:");
            for limitation in &output.limitations {
                println!("  - {limitation}");
            }
        }
    }

    info!(
        target: "ffs::cli::dump::group",
        group,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "dump_group_complete"
    );

    Ok(())
}

fn build_dump_group_output(path: &PathBuf, group: u32, hex: bool) -> Result<DumpGroupOutput> {
    let cx = cli_cx();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;

    match flavor {
        FsFlavor::Ext4(sb) => {
            let (desc, raw_desc) = read_ext4_group_desc_from_path(path, &sb, group)?;
            let raw_hex = if hex {
                Some(bytes_to_hex_dump(&raw_desc))
            } else {
                None
            };
            Ok(DumpGroupOutput {
                filesystem: "ext4".to_owned(),
                group,
                descriptor: Some(desc),
                btrfs_chunk: None,
                raw_hex,
                limitations: Vec::new(),
            })
        }
        FsFlavor::Btrfs(sb) => {
            let open_fs = OpenFs::open_with_options(&cx, path, &OpenOptions::default())
                .with_context(|| format!("failed to open image: {}", path.display()))?;
            let mut limitations = Vec::new();
            let entries = build_btrfs_group_info(&open_fs, &sb, &mut limitations);
            let index = usize::try_from(group)
                .with_context(|| format!("group index {group} does not fit usize"))?;
            let chunk = entries.get(index).cloned().ok_or_else(|| {
                anyhow::anyhow!(
                    "btrfs chunk index {} is out of range (available chunks: {})",
                    group,
                    entries.len()
                )
            })?;
            let raw_hex = if hex {
                open_fs
                    .btrfs_context()
                    .and_then(|ctx| ctx.chunks.get(index))
                    .map(encode_btrfs_chunk_entry_bytes)
                    .map(|bytes| bytes_to_hex_dump(&bytes))
            } else {
                None
            };
            Ok(DumpGroupOutput {
                filesystem: "btrfs".to_owned(),
                group,
                descriptor: None,
                btrfs_chunk: Some(chunk),
                raw_hex,
                limitations,
            })
        }
    }
}

fn dump_inode_cmd(inode: u64, path: &PathBuf, json: bool, hex: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::dump::inode",
        "dump_inode",
        image = %path.display(),
        inode,
        output_json = json,
        include_hex = hex
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::dump::inode", "dump_inode_start");

    let output = build_dump_inode_output(path, inode, hex)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize dump inode output")?
        );
    } else {
        println!("FrankenFS Dump: inode");
        println!("filesystem: {}", output.filesystem);
        println!("inode: {}", output.inode);

        if let Some(parsed) = &output.ext4_parsed {
            println!("mode: 0x{:04X}", parsed.mode);
            println!("uid: {}", parsed.uid);
            println!("gid: {}", parsed.gid);
            println!("size: {}", parsed.size);
            println!("links_count: {}", parsed.links_count);
            println!("blocks: {}", parsed.blocks);
            println!("flags: 0x{:08X}", parsed.flags);
            println!("generation: {}", parsed.generation);
            println!("file_acl: {}", parsed.file_acl);
            println!("atime: {}", parsed.atime);
            println!("ctime: {}", parsed.ctime);
            println!("mtime: {}", parsed.mtime);
            println!("dtime: {}", parsed.dtime);
            println!("extra_isize: {}", parsed.extra_isize);
            println!("checksum: 0x{:08X}", parsed.checksum);
            println!("projid: {}", parsed.projid);
        }

        if let Some(parsed) = &output.btrfs_parsed {
            println!("mode: 0o{:o}", parsed.mode);
            println!("uid: {}", parsed.uid);
            println!("gid: {}", parsed.gid);
            println!("size: {}", parsed.size);
            println!("nbytes: {}", parsed.nbytes);
            println!("nlink: {}", parsed.nlink);
            println!("rdev: {}", parsed.rdev);
            println!("atime: {}.{:09}", parsed.atime_sec, parsed.atime_nsec);
            println!("ctime: {}.{:09}", parsed.ctime_sec, parsed.ctime_nsec);
            println!("mtime: {}.{:09}", parsed.mtime_sec, parsed.mtime_nsec);
            println!("otime: {}.{:09}", parsed.otime_sec, parsed.otime_nsec);
        }

        if !output.limitations.is_empty() {
            println!("limitations:");
            for limitation in &output.limitations {
                println!("  - {limitation}");
            }
        }

        if let Some(raw_hex) = &output.raw_hex {
            println!();
            println!("raw_hex:");
            println!("{raw_hex}");
        }
    }

    info!(
        target: "ffs::cli::dump::inode",
        inode,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "dump_inode_complete"
    );

    Ok(())
}

fn build_dump_inode_output(path: &PathBuf, inode: u64, hex: bool) -> Result<DumpInodeOutput> {
    let cx = cli_cx();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;
    match flavor {
        FsFlavor::Ext4(sb) => {
            let inode_number = InodeNumber(inode);
            let (parsed, raw_inode) = read_ext4_inode_from_path(path, &sb, inode_number)
                .with_context(|| format!("failed to read inode {inode}"))?;
            let raw_hex = if hex {
                Some(bytes_to_hex_dump(&raw_inode))
            } else {
                None
            };
            Ok(DumpInodeOutput {
                filesystem: "ext4".to_owned(),
                inode,
                ext4_parsed: Some(parsed),
                btrfs_parsed: None,
                raw_hex,
                limitations: Vec::new(),
            })
        }
        FsFlavor::Btrfs(sb) => {
            let open_fs = OpenFs::open(&cx, path)
                .with_context(|| format!("failed to open image: {}", path.display()))?;
            let root_items = open_fs
                .walk_btrfs_root_tree(&cx)
                .context("failed to walk btrfs root tree")?;
            let fs_tree_root_item = root_items
                .iter()
                .find(|item| {
                    item.key.objectid == BTRFS_FS_TREE_OBJECTID
                        && item.key.item_type == BTRFS_ITEM_ROOT_ITEM
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "failed to locate btrfs FS tree root item (objectid={BTRFS_FS_TREE_OBJECTID})"
                    )
                })?;
            let fs_tree_root = parse_root_item(&fs_tree_root_item.data)
                .context("failed to parse btrfs FS tree root item")?;
            let fs_tree_entries = open_fs
                .walk_btrfs_tree(&cx, fs_tree_root.bytenr)
                .with_context(|| {
                    format!("failed to walk btrfs FS tree at {}", fs_tree_root.bytenr)
                })?;
            let canonical_inode = if inode == 1 {
                sb.root_dir_objectid
            } else {
                inode
            };
            let inode_item = fs_tree_entries
                .iter()
                .find(|item| {
                    item.key.objectid == canonical_inode
                        && item.key.item_type == BTRFS_ITEM_INODE_ITEM
                        && item.key.offset == 0
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "failed to locate btrfs inode item for objectid {canonical_inode}"
                    )
                })?;
            let parsed = parse_inode_item(&inode_item.data).with_context(|| {
                format!("failed to parse btrfs inode item for objectid {canonical_inode}")
            })?;
            let mut limitations = Vec::new();
            if inode == 1 && canonical_inode != 1 {
                limitations.push(format!(
                    "inode 1 maps to btrfs root objectid {canonical_inode}"
                ));
            }
            let raw_hex = if hex {
                Some(bytes_to_hex_dump(&inode_item.data))
            } else {
                None
            };
            Ok(DumpInodeOutput {
                filesystem: "btrfs".to_owned(),
                inode,
                ext4_parsed: None,
                btrfs_parsed: Some(parsed.into()),
                raw_hex,
                limitations,
            })
        }
    }
}

#[allow(clippy::too_many_lines)]
fn dump_extents_cmd(inode: u64, path: &PathBuf, json: bool, hex: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::dump::extents",
        "dump_extents",
        image = %path.display(),
        inode,
        output_json = json,
        include_hex = hex
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::dump::extents", "dump_extents_start");

    let (image, reader) = load_ext4_reader(path, "dump extents")?;
    let inode_number = InodeNumber(inode);
    let parsed_inode = reader
        .read_inode(&image, inode_number)
        .with_context(|| format!("failed to read inode {inode}"))?;
    let (root_header, _) = parse_inode_extent_tree(&parsed_inode)
        .with_context(|| format!("inode {inode} is not extent-backed"))?;

    let mut nodes = Vec::new();
    collect_extent_nodes(
        &reader,
        &image,
        None,
        &parsed_inode.extent_bytes,
        root_header.depth,
        hex,
        &mut nodes,
    )?;

    let flattened_extents = reader
        .collect_extents(&image, &parsed_inode)
        .with_context(|| format!("failed to collect extents for inode {inode}"))?
        .into_iter()
        .map(dump_extent_entry)
        .collect();

    let output = DumpExtentOutput {
        filesystem: "ext4".to_owned(),
        inode,
        root_depth: root_header.depth,
        nodes,
        flattened_extents,
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize dump extents output")?
        );
    } else {
        println!("FrankenFS Dump: extents");
        println!("filesystem: {}", output.filesystem);
        println!("inode: {}", output.inode);
        println!("root_depth: {}", output.root_depth);
        println!("nodes: {}", output.nodes.len());

        for node in &output.nodes {
            let source = node
                .source_block
                .map_or_else(|| "inode_root".to_owned(), |block| block.to_string());
            println!(
                "  node source={} depth={} entries={} max_entries={} generation={}",
                source,
                node.header.depth,
                node.header.entries,
                node.header.max_entries,
                node.header.generation
            );
            match &node.node {
                DumpExtentNodeKindOutput::Leaf { extents } => {
                    for extent in extents {
                        println!(
                            "    leaf logical={} physical={}..{} len={} initialized={}",
                            extent.logical_block,
                            extent.physical_start,
                            extent.physical_end_inclusive,
                            extent.actual_len,
                            extent.initialized
                        );
                    }
                }
                DumpExtentNodeKindOutput::Index { indexes } => {
                    for index in indexes {
                        println!(
                            "    index logical={} child_block={}",
                            index.logical_block, index.leaf_block
                        );
                    }
                }
            }
            if let Some(raw_hex) = &node.raw_hex {
                println!("    raw_hex:");
                println!("{raw_hex}");
            }
        }
    }

    info!(
        target: "ffs::cli::dump::extents",
        inode,
        nodes = output.nodes.len(),
        flattened_extents = output.flattened_extents.len(),
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "dump_extents_complete"
    );

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn dump_dir_cmd(inode: u64, path: &PathBuf, json: bool, hex: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::dump::dir",
        "dump_dir",
        image = %path.display(),
        inode,
        output_json = json,
        include_hex = hex
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::dump::dir", "dump_dir_start");

    let output = build_dump_dir_output(path, inode, hex)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize dump dir output")?
        );
    } else {
        println!("FrankenFS Dump: dir");
        println!("filesystem: {}", output.filesystem);
        println!("inode: {}", output.inode);
        println!("entries: {}", output.entries.len());
        for entry in &output.entries {
            println!(
                "  index={} inode={} rec_len={} type={} name={}",
                entry.index, entry.inode, entry.rec_len, entry.file_type, entry.name
            );
        }

        if let Some(htree) = &output.htree {
            println!();
            println!("htree:");
            println!("  hash_version: {}", htree.hash_version);
            println!("  indirect_levels: {}", htree.indirect_levels);
            for entry in &htree.entries {
                println!("  entry hash=0x{:08X} block={}", entry.hash, entry.block);
            }
        }

        if let Some(raw_hex_blocks) = &output.raw_hex_blocks {
            println!();
            println!("raw_hex_blocks: {}", raw_hex_blocks.len());
            for block in raw_hex_blocks {
                println!(
                    "  logical_block={} physical_block={}{}",
                    block.logical_block,
                    block.physical_block,
                    block
                        .item_kind
                        .as_ref()
                        .map(|kind| format!(" item_kind={kind}"))
                        .unwrap_or_default()
                );
                println!("{}", block.hex);
            }
        }

        if !output.limitations.is_empty() {
            println!();
            println!("limitations:");
            for limitation in &output.limitations {
                println!("  - {limitation}");
            }
        }
    }

    info!(
        target: "ffs::cli::dump::dir",
        inode,
        entries = output.entries.len(),
        has_htree = output.htree.is_some(),
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "dump_dir_complete"
    );

    Ok(())
}

fn build_dump_dir_output(path: &PathBuf, inode: u64, hex: bool) -> Result<DumpDirOutput> {
    let cx = cli_cx();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;
    match flavor {
        FsFlavor::Ext4(_) => build_ext4_dump_dir_output(path, inode, hex),
        FsFlavor::Btrfs(_) => build_btrfs_dump_dir_output(path, inode, hex),
    }
}

fn build_ext4_dump_dir_output(path: &PathBuf, inode: u64, hex: bool) -> Result<DumpDirOutput> {
    let (image, reader) = load_ext4_reader(path, "dump dir")?;
    let inode_number = InodeNumber(inode);
    let parsed_inode = reader
        .read_inode(&image, inode_number)
        .with_context(|| format!("failed to read inode {inode}"))?;
    let entries = reader
        .read_dir(&image, &parsed_inode)
        .with_context(|| format!("failed to read directory entries for inode {inode}"))?;

    let htree = match reader
        .resolve_extent(&image, &parsed_inode, 0)
        .with_context(|| format!("failed to resolve first directory block for inode {inode}"))?
    {
        Some(physical_block) => {
            let block = reader
                .read_block(&image, BlockNumber(physical_block))
                .with_context(|| format!("failed to read directory block {physical_block}"))?;
            parse_dx_root(block).ok().map(|root| DumpDxRootOutput {
                hash_version: root.hash_version,
                indirect_levels: root.indirect_levels,
                entries: root
                    .entries
                    .iter()
                    .map(|entry| DumpDxEntryOutput {
                        hash: entry.hash,
                        block: entry.block,
                    })
                    .collect(),
            })
        }
        None => None,
    };

    let raw_hex_blocks = if hex {
        Some(read_ext4_directory_hex_blocks(
            &image,
            &reader,
            &parsed_inode,
        )?)
    } else {
        None
    };

    let mut limitations = Vec::new();
    limitations.push(
        "directory entry byte offsets are not exposed by parser APIs; `index` preserves on-disk iteration order"
            .to_owned(),
    );
    if htree.is_none() {
        limitations.push(
            "htree metadata is only shown for indexed directories with a parseable dx root"
                .to_owned(),
        );
    }

    Ok(DumpDirOutput {
        filesystem: "ext4".to_owned(),
        inode,
        entries: entries
            .iter()
            .enumerate()
            .map(|(index, entry)| dump_dir_entry(index, entry))
            .collect(),
        htree,
        raw_hex_blocks,
        limitations,
    })
}

fn build_btrfs_dump_dir_output(path: &PathBuf, inode: u64, hex: bool) -> Result<DumpDirOutput> {
    let cx = cli_cx();
    let open_fs = OpenFs::open(&cx, path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let entries = open_fs
        .readdir(&cx, InodeNumber(inode), 0)
        .with_context(|| format!("failed to read btrfs directory entries for inode {inode}"))?;
    let mut limitations = vec![
        "btrfs directory dump uses VFS readdir projection; on-disk rec_len offsets are not available"
            .to_owned(),
        "htree metadata is ext4-specific and not available for btrfs directories".to_owned(),
    ];
    let raw_hex_blocks = if hex {
        let items = open_fs
            .walk_btrfs_dir_entry_items(&cx, inode)
            .context("failed to read btrfs directory items")?;
        let blocks: Vec<DumpHexBlockOutput> = items
            .iter()
            .enumerate()
            .map(|(idx, (item_type, key_offset, raw))| {
                #[allow(clippy::cast_possible_truncation)]
                DumpHexBlockOutput {
                    logical_block: idx as u32,
                    physical_block: *key_offset,
                    item_kind: Some(
                        match *item_type {
                            ffs_btrfs::BTRFS_ITEM_DIR_ITEM => "dir_item",
                            ffs_btrfs::BTRFS_ITEM_DIR_INDEX => "dir_index",
                            _ => "unknown",
                        }
                        .to_owned(),
                    ),
                    hex: bytes_to_hex_dump(raw),
                }
            })
            .collect();
        limitations.push(
            "btrfs hex dump shows raw DIR_ITEM/DIR_INDEX payloads from B-tree leaves; \
             logical_block is the item index, physical_block is the key offset"
                .to_owned(),
        );
        Some(blocks)
    } else {
        None
    };
    Ok(DumpDirOutput {
        filesystem: "btrfs".to_owned(),
        inode,
        entries: entries
            .iter()
            .enumerate()
            .map(|(index, entry)| DumpDirEntryOutput {
                index,
                inode: entry.ino.0,
                rec_len: 0,
                file_type: format!("{:?}", entry.kind).to_ascii_lowercase(),
                name: entry.name_str(),
            })
            .collect(),
        htree: None,
        raw_hex_blocks,
        limitations,
    })
}

fn load_ext4_reader(path: &PathBuf, action: &str) -> Result<(Vec<u8>, Ext4ImageReader)> {
    let cx = cli_cx();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;
    if !matches!(flavor, FsFlavor::Ext4(_)) {
        bail!("{action} currently supports ext4 images only");
    }

    let image = std::fs::read(path)
        .with_context(|| format!("failed to read filesystem image: {}", path.display()))?;
    let reader = Ext4ImageReader::new(&image).context("failed to parse ext4 superblock")?;
    Ok((image, reader))
}

fn read_ext4_group_desc_from_path(
    path: &PathBuf,
    sb: &Ext4Superblock,
    group: u32,
) -> Result<(Ext4GroupDesc, Vec<u8>)> {
    let group_number = GroupNumber(group);
    let offset_u64 = sb
        .group_desc_offset(group_number)
        .ok_or_else(|| anyhow::anyhow!("group descriptor offset overflow for group {group}"))?;
    let offset = usize::try_from(offset_u64)
        .with_context(|| format!("group descriptor offset does not fit usize for group {group}"))?;
    let desc_size = sb.group_desc_size();
    let raw_desc = read_file_region(
        path,
        offset,
        usize::from(desc_size),
        "ext4 group descriptor",
    )
    .with_context(|| format!("failed to read ext4 group descriptor {group}"))?;
    let desc = Ext4GroupDesc::parse_from_bytes(&raw_desc, desc_size)
        .with_context(|| format!("failed to parse ext4 group descriptor {group}"))?;
    Ok((desc, raw_desc))
}

fn read_ext4_inode_from_path(
    path: &PathBuf,
    sb: &Ext4Superblock,
    inode: InodeNumber,
) -> Result<(Ext4Inode, Vec<u8>)> {
    let location = sb
        .locate_inode(inode)
        .with_context(|| format!("failed to locate inode {}", inode.0))?;
    let (group_desc, _raw_group_desc) = read_ext4_group_desc_from_path(path, sb, location.group.0)
        .with_context(|| format!("failed to read group descriptor {}", location.group.0))?;
    let inode_offset = sb
        .inode_device_offset(&location, group_desc.inode_table)
        .with_context(|| format!("failed to compute inode offset for inode {}", inode.0))?;
    let offset = usize::try_from(inode_offset)
        .with_context(|| format!("inode offset does not fit usize for inode {}", inode.0))?;
    let inode_size = usize::from(sb.inode_size);
    let raw_inode = read_file_region(path, offset, inode_size, "ext4 inode")
        .with_context(|| format!("failed to read raw inode bytes for inode {}", inode.0))?;
    let parsed = Ext4Inode::parse_from_bytes(&raw_inode)
        .with_context(|| format!("failed to parse inode {}", inode.0))?;
    Ok((parsed, raw_inode))
}

fn read_file_region(path: &PathBuf, offset: usize, len: usize, label: &str) -> Result<Vec<u8>> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open filesystem image: {}", path.display()))?;
    let file_len = file
        .metadata()
        .with_context(|| format!("failed to stat filesystem image: {}", path.display()))?
        .len();
    let offset_u64 = u64::try_from(offset)
        .with_context(|| format!("{label} offset does not fit in u64 (offset={offset})"))?;
    let len_u64 = u64::try_from(len)
        .with_context(|| format!("{label} length does not fit in u64 (len={len})"))?;
    let end = offset_u64
        .checked_add(len_u64)
        .ok_or_else(|| anyhow::anyhow!("{label} region overflow (offset={offset}, len={len})"))?;
    if end > file_len {
        bail!("{label} region out of bounds (offset={offset}, len={len}, image_len={file_len})");
    }

    file.seek(SeekFrom::Start(offset_u64))
        .with_context(|| format!("failed to seek to {label} offset {offset}"))?;
    let mut bytes = vec![0_u8; len];
    file.read_exact(&mut bytes)
        .with_context(|| format!("failed to read {label} bytes"))?;
    Ok(bytes)
}

fn bytes_to_hex_dump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (line, chunk) in bytes.chunks(16).enumerate() {
        let offset = line.saturating_mul(16);
        write!(&mut out, "{offset:08x}:").expect("write to String cannot fail");
        for byte in chunk {
            write!(&mut out, " {byte:02x}").expect("write to String cannot fail");
        }
        out.push('\n');
    }
    out
}

fn dump_extent_entry(extent: Ext4Extent) -> DumpExtentEntryOutput {
    let actual_len = extent.actual_len();
    let initialized = !extent.is_unwritten();
    DumpExtentEntryOutput {
        logical_block: extent.logical_block,
        physical_start: extent.physical_start,
        physical_end_inclusive: extent
            .physical_start
            .saturating_add(u64::from(actual_len))
            .saturating_sub(1),
        raw_len: extent.raw_len,
        actual_len,
        initialized,
    }
}

fn collect_extent_nodes(
    reader: &Ext4ImageReader,
    image: &[u8],
    source_block: Option<u64>,
    raw_node: &[u8],
    expected_depth: u16,
    include_hex: bool,
    nodes: &mut Vec<DumpExtentNodeOutput>,
) -> Result<()> {
    let (header, tree) = parse_extent_tree(raw_node).context("failed to parse extent tree node")?;
    if header.depth != expected_depth {
        bail!(
            "extent tree depth mismatch: expected {expected_depth}, parsed {}",
            header.depth
        );
    }

    let raw_hex = include_hex.then(|| bytes_to_hex_dump(raw_node));

    match tree {
        ExtentTree::Leaf(extents) => {
            nodes.push(DumpExtentNodeOutput {
                source_block,
                header,
                node: DumpExtentNodeKindOutput::Leaf {
                    extents: extents.into_iter().map(dump_extent_entry).collect(),
                },
                raw_hex,
            });
        }
        ExtentTree::Index(indexes) => {
            nodes.push(DumpExtentNodeOutput {
                source_block,
                header,
                node: DumpExtentNodeKindOutput::Index {
                    indexes: indexes.clone(),
                },
                raw_hex,
            });

            let next_depth = expected_depth
                .checked_sub(1)
                .ok_or_else(|| anyhow::anyhow!("invalid extent depth transition from 0"))?;
            for index in indexes {
                let child = reader
                    .read_block(image, BlockNumber(index.leaf_block))
                    .with_context(|| {
                        format!(
                            "failed to read extent child block {} (logical={})",
                            index.leaf_block, index.logical_block
                        )
                    })?;
                collect_extent_nodes(
                    reader,
                    image,
                    Some(index.leaf_block),
                    child,
                    next_depth,
                    include_hex,
                    nodes,
                )?;
            }
        }
    }

    Ok(())
}

fn dump_dir_entry(index: usize, entry: &Ext4DirEntry) -> DumpDirEntryOutput {
    DumpDirEntryOutput {
        index,
        inode: u64::from(entry.inode),
        rec_len: entry.rec_len,
        file_type: format!("{:?}", entry.file_type).to_ascii_lowercase(),
        name: entry.name_str(),
    }
}

fn read_ext4_directory_hex_blocks(
    image: &[u8],
    reader: &Ext4ImageReader,
    inode: &Ext4Inode,
) -> Result<Vec<DumpHexBlockOutput>> {
    let block_size = u64::from(reader.sb.block_size);
    let block_count_u64 = inode.size.div_ceil(block_size);
    let block_count = u32::try_from(block_count_u64).with_context(|| {
        format!("directory block count exceeds supported range: {block_count_u64}")
    })?;

    let mut blocks = Vec::new();
    for logical_block in 0..block_count {
        if let Some(physical_block) = reader
            .resolve_extent(image, inode, logical_block)
            .with_context(|| format!("failed to resolve directory block {logical_block}"))?
        {
            let block = reader
                .read_block(image, BlockNumber(physical_block))
                .with_context(|| format!("failed to read directory block {physical_block}"))?;
            blocks.push(DumpHexBlockOutput {
                logical_block,
                physical_block,
                item_kind: None,
                hex: bytes_to_hex_dump(block),
            });
        }
    }

    Ok(blocks)
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

fn inspect_ext4_output(
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

const fn ext4_mount_replay_mode(read_write: bool) -> Ext4JournalReplayMode {
    if read_write {
        Ext4JournalReplayMode::Apply
    } else {
        Ext4JournalReplayMode::SimulateOverlay
    }
}

fn mount_operation_id(
    image_path: &Path,
    mountpoint: &Path,
    runtime_mode: MountRuntimeMode,
    read_write: bool,
) -> String {
    let read_write_mode = if read_write { "rw" } else { "ro" };
    let material = format!(
        "{}|{}|{}|{}",
        runtime_mode.as_str(),
        read_write_mode,
        image_path.display(),
        mountpoint.display()
    );
    let digest = crc32c::crc32c(material.as_bytes());
    format!("mount-{digest:08x}")
}

#[derive(Debug, Clone, Copy)]
struct Ext4MmpRefusalLogContext {
    status_class: &'static str,
    error_class: &'static str,
    sequence: Option<u32>,
}

fn parse_ext4_mmp_sequence(message: &str) -> Option<u32> {
    let rest = message.strip_prefix("ext4 MMP sequence 0x")?;
    let hex = rest.get(..8)?;
    u32::from_str_radix(hex, 16).ok()
}

fn ext4_mmp_refusal_log_context(error: &ffs_error::FfsError) -> Option<Ext4MmpRefusalLogContext> {
    let ffs_error::FfsError::UnsupportedFeature(message) = error else {
        return None;
    };

    if message == "ext4 MMP block reports fsck in progress; refusing mount" {
        Some(Ext4MmpRefusalLogContext {
            status_class: "fsck",
            error_class: "fsck_in_progress",
            sequence: None,
        })
    } else if message.contains("another writer may be active")
        && message.contains("instead of participating in periodic MMP heartbeat updates")
    {
        Some(Ext4MmpRefusalLogContext {
            status_class: "active",
            error_class: "active_writer_maybe",
            sequence: parse_ext4_mmp_sequence(message),
        })
    } else if message.contains("unsafe/unknown; refusing mount") {
        Some(Ext4MmpRefusalLogContext {
            status_class: "unsafe_unknown",
            error_class: "unsafe_unknown_status",
            sequence: parse_ext4_mmp_sequence(message),
        })
    } else {
        None
    }
}

fn log_mount_open_rejected(
    operation_id: &str,
    scenario_id: &str,
    read_write: bool,
    error: &ffs_error::FfsError,
) {
    if let Some(context) = ext4_mmp_refusal_log_context(error) {
        if let Some(sequence) = context.sequence {
            error!(
                target: "ffs::cli::mount",
                operation_id,
                scenario_id,
                outcome = "mount_open_rejected",
                error_class = context.error_class,
                mmp_status_class = context.status_class,
                mmp_sequence = sequence,
                read_write,
                errno = error.to_errno(),
                reason = %error,
                "mount_open_rejected"
            );
        } else {
            error!(
                target: "ffs::cli::mount",
                operation_id,
                scenario_id,
                outcome = "mount_open_rejected",
                error_class = context.error_class,
                mmp_status_class = context.status_class,
                read_write,
                errno = error.to_errno(),
                reason = %error,
                "mount_open_rejected"
            );
        }
        return;
    }

    error!(
        target: "ffs::cli::mount",
        operation_id,
        scenario_id,
        outcome = "mount_open_rejected",
        error_class = "filesystem_open_failed",
        read_write,
        errno = error.to_errno(),
        reason = %error,
        "mount_open_rejected"
    );
}

fn log_mount_runtime_selected(
    operation_id: &str,
    scenario_id: &str,
    runtime: MountRuntimeConfig,
    allow_other: bool,
    auto_unmount: bool,
    read_write: bool,
) {
    info!(
        target: "ffs::cli::mount",
        operation_id,
        scenario_id,
        outcome = "runtime_mode_selected",
        runtime_mode = runtime.mode.as_str(),
        allow_other,
        auto_unmount,
        read_write,
        managed_unmount_timeout_secs = runtime.managed_unmount_timeout_secs(),
        "mount_runtime_mode_selected"
    );
}

fn log_mount_runtime_rejected(
    operation_id: &str,
    scenario_id: &str,
    runtime: MountRuntimeConfig,
    read_write: bool,
    error_class: &'static str,
    reason: &str,
) {
    error!(
        target: "ffs::cli::mount",
        operation_id,
        scenario_id,
        outcome = "runtime_mode_rejected",
        error_class,
        runtime_mode = runtime.mode.as_str(),
        read_write,
        managed_unmount_timeout_secs = runtime.managed_unmount_timeout_secs(),
        reason,
        "mount_runtime_mode_rejected"
    );
}

fn log_mount_writeback_cache_rejected(
    operation_id: &str,
    scenario_id: &str,
    error_class: &'static str,
    reason: &str,
) {
    error!(
        target: "ffs::cli::mount",
        operation_id,
        scenario_id,
        outcome = "writeback_cache_rejected",
        error_class,
        reason,
        "mount_writeback_cache_rejected"
    );
}

fn log_mount_writeback_cache_accepted(
    operation_id: &str,
    scenario_id: &str,
    audit_gate_path: &Path,
    ordering_oracle_path: &Path,
    crash_replay_oracle_path: &Path,
) {
    info!(
        target: "ffs::cli::mount",
        operation_id,
        scenario_id,
        outcome = "writeback_cache_accepted",
        audit_gate = %audit_gate_path.display(),
        ordering_oracle = %ordering_oracle_path.display(),
        crash_replay_oracle = %crash_replay_oracle_path.display(),
        durability_flush = "non_durable",
        durability_boundaries = "fsync,fsyncdir",
        "mount_writeback_cache_accepted"
    );
}

fn emit_mount_banner(
    open_fs: &OpenFs,
    mountpoint: &Path,
    read_write: bool,
    runtime_mode: MountRuntimeMode,
) {
    let mode_str = if read_write { "rw" } else { "ro" };
    let runtime = runtime_mode.as_str();
    match &open_fs.flavor {
        FsFlavor::Ext4(sb) => {
            eprintln!(
                "Mounting ext4 image (block_size={}, blocks={}, {mode_str}, runtime={runtime}) at {}",
                sb.block_size,
                sb.blocks_count,
                mountpoint.display()
            );
        }
        FsFlavor::Btrfs(sb) => {
            eprintln!(
                "Mounting btrfs image (sectorsize={}, nodesize={}, label={:?}, {mode_str}, runtime={runtime}) at {}",
                sb.sectorsize,
                sb.nodesize,
                sb.label,
                mountpoint.display()
            );
        }
    }
}

fn emit_crash_recovery_details(recovery: &CrashRecoveryOutcome) {
    if !recovery.recovery_performed() {
        return;
    }

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

fn emit_optional_recovery_banner(open_fs: &OpenFs) {
    if let Some(recovery) = open_fs.crash_recovery() {
        emit_crash_recovery_details(recovery);
    }
}

struct MountWritebackCacheEvidence<'a> {
    audit_gate_path: &'a Path,
    ordering_oracle_path: &'a Path,
    crash_replay_oracle_path: &'a Path,
    reproduction_command: String,
}

fn prepare_mount_writeback_cache_evidence<'a>(
    image_path: &Path,
    mountpoint: &Path,
    options: &'a MountCmdOptions,
    operation_id: &str,
    scenario_id: &str,
) -> Result<Option<MountWritebackCacheEvidence<'a>>> {
    let request = &options.writeback_cache;
    if !request.enabled {
        if request.audit_gate_path.is_some()
            || request.ordering_oracle_path.is_some()
            || request.crash_replay_oracle_path.is_some()
        {
            let reason = "--writeback-cache-gate, --writeback-cache-ordering-oracle, and --writeback-cache-crash-replay-oracle require --writeback-cache";
            log_mount_writeback_cache_rejected(
                operation_id,
                scenario_id,
                "gate_without_opt_in",
                reason,
            );
            bail!("{reason}");
        }
        return Ok(None);
    }

    if request.runtime_kill_switch {
        let reason = "writeback_cache blocked by FFS_WRITEBACK_CACHE_KILL_SWITCH";
        log_mount_writeback_cache_rejected(
            operation_id,
            scenario_id,
            "runtime_kill_switch_engaged",
            reason,
        );
        bail!("{reason}");
    }

    if !options.read_write {
        let reason = "--writeback-cache requires --rw; flush is non-durable and fsync/fsyncdir are the durability boundaries";
        log_mount_writeback_cache_rejected(
            operation_id,
            scenario_id,
            "read_only_writeback_cache",
            reason,
        );
        bail!("{reason}");
    }

    let Some(audit_gate_path) = request.audit_gate_path.as_deref() else {
        let reason = "--writeback-cache requires --writeback-cache-gate";
        log_mount_writeback_cache_rejected(operation_id, scenario_id, "missing_audit_gate", reason);
        bail!("{reason}");
    };
    let Some(ordering_oracle_path) = request.ordering_oracle_path.as_deref() else {
        let reason = "--writeback-cache requires --writeback-cache-ordering-oracle";
        log_mount_writeback_cache_rejected(
            operation_id,
            scenario_id,
            "missing_ordering_oracle",
            reason,
        );
        bail!("{reason}");
    };
    let Some(crash_replay_oracle_path) = request.crash_replay_oracle_path.as_deref() else {
        let reason = "--writeback-cache requires --writeback-cache-crash-replay-oracle";
        log_mount_writeback_cache_rejected(
            operation_id,
            scenario_id,
            "missing_crash_replay_oracle",
            reason,
        );
        bail!("{reason}");
    };

    let reproduction_command = format!(
        "ffs mount --rw --writeback-cache --writeback-cache-gate {} --writeback-cache-ordering-oracle {} --writeback-cache-crash-replay-oracle {} {} {}",
        audit_gate_path.display(),
        ordering_oracle_path.display(),
        crash_replay_oracle_path.display(),
        image_path.display(),
        mountpoint.display()
    );
    Ok(Some(MountWritebackCacheEvidence {
        audit_gate_path,
        ordering_oracle_path,
        crash_replay_oracle_path,
        reproduction_command,
    }))
}

fn validate_mount_writeback_cache_audit_gate(
    path: &Path,
    scenario_id: &str,
    reproduction_command: &str,
    operation_id: &str,
) -> Result<()> {
    let audit_gate = match load_writeback_cache_audit_gate(path) {
        Ok(gate) => gate,
        Err(error) => {
            let reason = format!("{error:#}");
            log_mount_writeback_cache_rejected(
                operation_id,
                scenario_id,
                "audit_gate_invalid",
                &reason,
            );
            return Err(error.context("failed to load writeback-cache audit gate"));
        }
    };
    let audit_report =
        match build_writeback_cache_audit_report(&audit_gate, scenario_id, reproduction_command) {
            Ok(report) => report,
            Err(error) => {
                let reason = format!("{error:#}");
                log_mount_writeback_cache_rejected(
                    operation_id,
                    scenario_id,
                    "audit_gate_invalid",
                    &reason,
                );
                return Err(error.context("failed to validate writeback-cache audit gate"));
            }
        };
    if let Err(error) = fail_on_writeback_cache_audit_errors(&audit_report) {
        let reason = format!("{error:#}");
        log_mount_writeback_cache_rejected(
            operation_id,
            scenario_id,
            "audit_gate_rejected",
            &reason,
        );
        return Err(error.context("writeback-cache audit gate rejected CLI opt-in"));
    }
    Ok(())
}

fn validate_mount_writeback_cache_ordering_oracle(
    path: &Path,
    scenario_id: &str,
    reproduction_command: &str,
    operation_id: &str,
) -> Result<()> {
    let ordering_oracle = match load_writeback_ordering_oracle(path) {
        Ok(oracle) => oracle,
        Err(error) => {
            let reason = format!("{error:#}");
            log_mount_writeback_cache_rejected(
                operation_id,
                scenario_id,
                "ordering_oracle_invalid",
                &reason,
            );
            return Err(error.context("failed to load writeback-cache ordering oracle"));
        }
    };
    let ordering_report = match build_writeback_ordering_report(
        &ordering_oracle,
        scenario_id,
        reproduction_command,
    ) {
        Ok(report) => report,
        Err(error) => {
            let reason = format!("{error:#}");
            log_mount_writeback_cache_rejected(
                operation_id,
                scenario_id,
                "ordering_oracle_invalid",
                &reason,
            );
            return Err(error.context("failed to validate writeback-cache ordering oracle"));
        }
    };
    if let Err(error) = fail_on_writeback_ordering_errors(&ordering_report) {
        let reason = format!("{error:#}");
        log_mount_writeback_cache_rejected(
            operation_id,
            scenario_id,
            "ordering_oracle_rejected",
            &reason,
        );
        return Err(error.context("writeback-cache ordering oracle rejected CLI opt-in"));
    }
    Ok(())
}

fn validate_mount_writeback_cache_crash_replay_oracle(
    path: &Path,
    scenario_id: &str,
    reproduction_command: &str,
    operation_id: &str,
) -> Result<()> {
    let crash_replay_oracle = match load_writeback_crash_replay_oracle(path) {
        Ok(oracle) => oracle,
        Err(error) => {
            let reason = format!("{error:#}");
            log_mount_writeback_cache_rejected(
                operation_id,
                scenario_id,
                "crash_replay_oracle_invalid",
                &reason,
            );
            return Err(error.context("failed to load writeback-cache crash/replay oracle"));
        }
    };
    let crash_replay_report = match build_writeback_crash_replay_report(
        &crash_replay_oracle,
        scenario_id,
        reproduction_command,
    ) {
        Ok(report) => report,
        Err(error) => {
            let reason = format!("{error:#}");
            log_mount_writeback_cache_rejected(
                operation_id,
                scenario_id,
                "crash_replay_oracle_invalid",
                &reason,
            );
            return Err(error.context("failed to validate writeback-cache crash/replay oracle"));
        }
    };
    if let Err(error) = fail_on_writeback_crash_replay_errors(&crash_replay_report) {
        let reason = format!("{error:#}");
        log_mount_writeback_cache_rejected(
            operation_id,
            scenario_id,
            "crash_replay_oracle_rejected",
            &reason,
        );
        return Err(error.context("writeback-cache crash/replay oracle rejected CLI opt-in"));
    }
    Ok(())
}

fn validate_mount_writeback_cache_request(
    image_path: &Path,
    mountpoint: &Path,
    options: &MountCmdOptions,
    operation_id: &str,
    scenario_id: &str,
) -> Result<()> {
    let Some(evidence) = prepare_mount_writeback_cache_evidence(
        image_path,
        mountpoint,
        options,
        operation_id,
        scenario_id,
    )?
    else {
        return Ok(());
    };
    validate_mount_writeback_cache_audit_gate(
        evidence.audit_gate_path,
        scenario_id,
        &evidence.reproduction_command,
        operation_id,
    )?;
    validate_mount_writeback_cache_ordering_oracle(
        evidence.ordering_oracle_path,
        scenario_id,
        &evidence.reproduction_command,
        operation_id,
    )?;
    validate_mount_writeback_cache_crash_replay_oracle(
        evidence.crash_replay_oracle_path,
        scenario_id,
        &evidence.reproduction_command,
        operation_id,
    )?;
    log_mount_writeback_cache_accepted(
        operation_id,
        scenario_id,
        evidence.audit_gate_path,
        evidence.ordering_oracle_path,
        evidence.crash_replay_oracle_path,
    );
    Ok(())
}

fn log_mount_adaptive_runtime_rejected(
    operation_id: &str,
    scenario_id: &str,
    error_class: &str,
    reason: &str,
    manifest_path: Option<&Path>,
) {
    let manifest_path =
        manifest_path.map_or_else(|| "<none>".to_owned(), |path| path.display().to_string());
    warn!(
        target: "ffs::cli::mount",
        operation_id,
        scenario_id,
        outcome = "adaptive_runtime_rejected",
        error_class,
        reason,
        manifest_path = %manifest_path,
        "adaptive_runtime_rejected"
    );
}

fn log_mount_adaptive_runtime_accepted(
    operation_id: &str,
    scenario_id: &str,
    plan: &MountAdaptiveRuntimePlan,
) {
    info!(
        target: "ffs::cli::mount",
        operation_id,
        scenario_id,
        outcome = "adaptive_runtime_accepted",
        manifest_path = %plan.manifest_path.display(),
        manifest_scenario_id = %plan.manifest_scenario_id,
        run_id = %plan.run_id,
        backpressure_policy_id = %plan.backpressure_policy_id,
        "adaptive_runtime_accepted"
    );
}

fn mount_runtime_reproduction_command(
    image_path: &Path,
    mountpoint: &Path,
    runtime: MountRuntimeConfig,
    read_write: bool,
) -> String {
    let rw_flag = if read_write { " --rw" } else { "" };
    format!(
        "ffs mount --runtime-mode {}{} {} {}",
        runtime.mode.as_str(),
        rw_flag,
        image_path.display(),
        mountpoint.display()
    )
}

fn collect_mount_adaptive_runtime_artifact_paths(
    plan: Option<&MountAdaptiveRuntimePlan>,
    summary_config: &MountAdaptiveRuntimeSummaryConfig,
) -> Vec<String> {
    let mut paths = BTreeSet::new();
    if let Some(plan) = plan {
        paths.extend(plan.artifact_paths.iter().cloned());
    }
    if let Some(path) = summary_config.json_path.as_ref() {
        paths.insert(path.display().to_string());
    }
    if let Some(path) = summary_config.markdown_path.as_ref() {
        paths.insert(path.display().to_string());
    }
    paths.into_iter().collect()
}

fn build_mount_adaptive_runtime_degradation_ledger(
    plan: Option<&MountAdaptiveRuntimePlan>,
) -> MountAdaptiveRuntimeDegradationTransitionLedger {
    plan.map_or_else(
        || MountAdaptiveRuntimeDegradationTransitionLedger {
            current_level: "not_applicable".to_owned(),
            transition_count: 0,
            transitions: Vec::new(),
        },
        |plan| MountAdaptiveRuntimeDegradationTransitionLedger {
            current_level: plan.gate.level().label().to_owned(),
            transition_count: plan.fsm.transition_count(),
            transitions: Vec::new(),
        },
    )
}

fn build_mount_adaptive_runtime_shutdown_summary(
    context: MountAdaptiveRuntimeShutdownContext<'_>,
    observation: &MountAdaptiveRuntimeShutdownObservation,
) -> MountAdaptiveRuntimeShutdownSummary {
    let adaptive_runtime_enabled = context.plan.is_some();
    let per_core = observation.per_core.as_ref();
    MountAdaptiveRuntimeShutdownSummary {
        schema_version: 1,
        adaptive_runtime_enabled,
        runtime_mode: context.runtime.mode.as_str().to_owned(),
        read_write: context.read_write,
        run_id: context.plan.map_or_else(
            || context.operation_id.to_owned(),
            |plan| plan.run_id.clone(),
        ),
        scenario_id: context.plan.map_or_else(
            || context.cli_scenario_id.to_owned(),
            |plan| plan.manifest_scenario_id.clone(),
        ),
        cli_scenario_id: context.cli_scenario_id.to_owned(),
        release_claim_state: context.plan.map_or_else(
            || "disabled".to_owned(),
            |plan| plan.release_claim_state.clone(),
        ),
        degradation_level_transitions: build_mount_adaptive_runtime_degradation_ledger(
            context.plan,
        ),
        backpressure_policy_id: context.plan.map(|plan| plan.backpressure_policy_id.clone()),
        requests_throttled: observation.metrics.requests_throttled,
        requests_shed: observation.metrics.requests_shed,
        total_requests: observation.metrics.requests_total,
        cache_hits: per_core.map(|metrics| metrics.total_cache_hits),
        cache_misses: per_core.map(|metrics| metrics.total_cache_misses),
        per_core_request_distribution: per_core
            .map_or_else(Vec::new, |metrics| metrics.per_core_distribution.clone()),
        per_core_imbalance_ratio: per_core.map(|metrics| metrics.imbalance_ratio),
        worker_count: observation.worker_count,
        artifact_paths: collect_mount_adaptive_runtime_artifact_paths(
            context.plan,
            context.summary_config,
        ),
        raw_stdout_path: context.plan.map(|plan| plan.raw_stdout_path.clone()),
        raw_stderr_path: context.plan.map(|plan| plan.raw_stderr_path.clone()),
        raw_log_paths: context
            .plan
            .map_or_else(Vec::new, |plan| plan.raw_log_paths.clone()),
        cleanup_status: context.plan.map_or_else(
            || "not_applicable".to_owned(),
            |plan| plan.cleanup_status.clone(),
        ),
        git_sha: context
            .plan
            .map_or_else(|| "unknown".to_owned(), |plan| plan.git_sha.clone()),
        reproduction_command: context.plan.map_or_else(
            || {
                mount_runtime_reproduction_command(
                    context.image_path,
                    context.mountpoint,
                    context.runtime,
                    context.read_write,
                )
            },
            |plan| plan.reproduction_command.clone(),
        ),
    }
}

fn render_mount_adaptive_runtime_shutdown_markdown(
    summary: &MountAdaptiveRuntimeShutdownSummary,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Adaptive Runtime Shutdown Evidence\n");
    let _ = writeln!(
        out,
        "- Adaptive runtime enabled: `{}`",
        summary.adaptive_runtime_enabled
    );
    let _ = writeln!(out, "- Runtime mode: `{}`", summary.runtime_mode);
    let _ = writeln!(out, "- Run: `{}`", summary.run_id);
    let _ = writeln!(out, "- Scenario: `{}`", summary.scenario_id);
    let _ = writeln!(out, "- CLI scenario: `{}`", summary.cli_scenario_id);
    let _ = writeln!(out, "- Release claim: `{}`", summary.release_claim_state);
    let _ = writeln!(out, "- Git SHA: `{}`", summary.git_sha);
    let _ = writeln!(out, "- Reproduction: `{}`", summary.reproduction_command);

    out.push_str("\n## Backpressure\n\n");
    let _ = writeln!(
        out,
        "- Policy: `{}`",
        summary
            .backpressure_policy_id
            .as_deref()
            .unwrap_or("not_applicable")
    );
    let _ = writeln!(
        out,
        "- Current degradation level: `{}`",
        summary.degradation_level_transitions.current_level
    );
    let _ = writeln!(
        out,
        "- Degradation transitions observed: `{}`",
        summary.degradation_level_transitions.transition_count
    );
    let _ = writeln!(
        out,
        "- Requests: total=`{}`, throttled=`{}`, shed=`{}`",
        summary.total_requests, summary.requests_throttled, summary.requests_shed
    );

    out.push_str("\n## Per-Core\n\n");
    let _ = writeln!(out, "- Worker count: `{}`", summary.worker_count);
    match (summary.cache_hits, summary.cache_misses) {
        (Some(hits), Some(misses)) => {
            let _ = writeln!(out, "- Cache hits/misses: `{hits}` / `{misses}`");
        }
        _ => out.push_str("- Cache hits/misses: `not_available`\n"),
    }
    if let Some(ratio) = summary.per_core_imbalance_ratio {
        let _ = writeln!(out, "- Imbalance ratio: `{ratio:.6}`");
    } else {
        out.push_str("- Imbalance ratio: `not_available`\n");
    }
    if summary.per_core_request_distribution.is_empty() {
        out.push_str("- Request distribution: `not_available`\n");
    } else {
        let mut distribution = String::new();
        for core in &summary.per_core_request_distribution {
            if !distribution.is_empty() {
                distribution.push_str(", ");
            }
            let _ = write!(
                distribution,
                "core{}={} (hits={}, misses={})",
                core.core_id, core.requests, core.cache_hits, core.cache_misses
            );
        }
        let _ = writeln!(out, "- Request distribution: `{distribution}`");
    }

    out.push_str("\n## Artifacts\n\n");
    if summary.artifact_paths.is_empty() {
        out.push_str("- Artifact paths: `none`\n");
    } else {
        let _ = writeln!(
            out,
            "- Artifact paths: `{}`",
            summary.artifact_paths.join("`, `")
        );
    }
    let _ = writeln!(
        out,
        "- Raw stdout: `{}`",
        summary
            .raw_stdout_path
            .as_deref()
            .unwrap_or("not_available")
    );
    let _ = writeln!(
        out,
        "- Raw stderr: `{}`",
        summary
            .raw_stderr_path
            .as_deref()
            .unwrap_or("not_available")
    );
    if summary.raw_log_paths.is_empty() {
        out.push_str("- Raw logs: `none`\n");
    } else {
        let _ = writeln!(out, "- Raw logs: `{}`", summary.raw_log_paths.join("`, `"));
    }
    let _ = writeln!(out, "- Cleanup: `{}`", summary.cleanup_status);
    out
}

fn write_mount_adaptive_runtime_shutdown_summary(
    config: &MountAdaptiveRuntimeSummaryConfig,
    summary: &MountAdaptiveRuntimeShutdownSummary,
) -> Result<()> {
    if let Some(path) = config.json_path.as_ref() {
        let json =
            serde_json::to_string_pretty(summary).context("serialize adaptive runtime summary")?;
        write_mount_adaptive_runtime_summary_artifact(
            path,
            json.as_bytes(),
            "adaptive runtime summary JSON",
        )?;
    }
    if let Some(path) = config.markdown_path.as_ref() {
        let markdown = render_mount_adaptive_runtime_shutdown_markdown(summary);
        write_mount_adaptive_runtime_summary_artifact(
            path,
            markdown.as_bytes(),
            "adaptive runtime summary Markdown",
        )?;
    }
    Ok(())
}

fn write_mount_adaptive_runtime_summary_artifact(
    path: &Path,
    bytes: &[u8],
    label: &str,
) -> Result<()> {
    let mut file = StdOpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "create {label} {}; refusing to overwrite existing evidence",
                path.display()
            )
        })?;
    file.write_all(bytes)
        .with_context(|| format!("write {label} {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {label} {}", path.display()))
}

fn emit_mount_adaptive_runtime_shutdown_summary(
    context: MountAdaptiveRuntimeShutdownContext<'_>,
    observation: &MountAdaptiveRuntimeShutdownObservation,
) -> Result<()> {
    if !context.summary_config.enabled() {
        return Ok(());
    }
    let summary = build_mount_adaptive_runtime_shutdown_summary(context, observation);
    write_mount_adaptive_runtime_shutdown_summary(context.summary_config, &summary)?;
    info!(
        target: "ffs::cli::mount",
        operation_id = context.operation_id,
        scenario_id = context.cli_scenario_id,
        outcome = "adaptive_runtime_shutdown_summary_emitted",
        adaptive_runtime_enabled = summary.adaptive_runtime_enabled,
        json_path = %context
            .summary_config
            .json_path
            .as_ref()
            .map_or_else(|| "<none>".to_owned(), |path| path.display().to_string()),
        markdown_path = %context
            .summary_config
            .markdown_path
            .as_ref()
            .map_or_else(|| "<none>".to_owned(), |path| path.display().to_string()),
        "adaptive_runtime_shutdown_summary_emitted"
    );
    Ok(())
}

fn adaptive_runtime_rejection_class(
    report: &ffs_harness::adaptive_runtime_manifest::AdaptiveRuntimeEvidenceReport,
) -> &'static str {
    if report.issues.iter().any(|issue| issue.path == "expires_at") {
        "stale_manifest"
    } else if report.release_claim_state == "small_host_smoke" {
        "small_host_smoke"
    } else if report.release_claim_state == "capability_downgraded_smoke" {
        "capability_downgraded_smoke"
    } else if !report.valid {
        "invalid_manifest"
    } else {
        "runtime_controls_not_accepted"
    }
}

fn build_adaptive_runtime_backpressure_gate() -> (Arc<DegradationFsm>, Arc<BackpressureGate>) {
    let pressure = Arc::new(SystemPressure::new());
    let fsm = Arc::new(DegradationFsm::new(pressure, 1));
    let gate = Arc::new(BackpressureGate::new(Arc::clone(&fsm)));
    (fsm, gate)
}

fn load_validated_mount_adaptive_runtime_manifest(
    manifest_path: &Path,
    operation_id: &str,
    scenario_id: &str,
    validation_config: &AdaptiveRuntimeEvidenceValidationConfig,
) -> Result<ffs_harness::adaptive_runtime_manifest::AdaptiveRuntimeEvidenceManifest> {
    let manifest = match load_adaptive_runtime_evidence_manifest(manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => {
            let reason = format!("{error:#}");
            log_mount_adaptive_runtime_rejected(
                operation_id,
                scenario_id,
                "manifest_invalid",
                &reason,
                Some(manifest_path),
            );
            return Err(error
                .context("manifest_invalid: failed to load adaptive runtime evidence manifest"));
        }
    };

    let report =
        validate_adaptive_runtime_evidence_manifest_with_config(&manifest, validation_config);
    if let Err(error) = fail_on_adaptive_runtime_evidence_errors(&report) {
        let reason = format!("{error:#}");
        let error_class = adaptive_runtime_rejection_class(&report);
        log_mount_adaptive_runtime_rejected(
            operation_id,
            scenario_id,
            error_class,
            &reason,
            Some(manifest_path),
        );
        return Err(error.context(format!(
            "{error_class}: adaptive runtime evidence rejected CLI opt-in"
        )));
    }

    Ok(manifest)
}

fn validate_mount_adaptive_runtime_request(
    request: &MountAdaptiveRuntimeConfig,
    runtime: MountRuntimeConfig,
    read_write: bool,
    operation_id: &str,
    scenario_id: &str,
) -> Result<Option<MountAdaptiveRuntimePlan>> {
    validate_mount_adaptive_runtime_request_with_config(
        request,
        runtime,
        read_write,
        operation_id,
        scenario_id,
        &AdaptiveRuntimeEvidenceValidationConfig::with_current_reference(),
    )
}

fn validate_mount_adaptive_runtime_request_with_config(
    request: &MountAdaptiveRuntimeConfig,
    runtime: MountRuntimeConfig,
    read_write: bool,
    operation_id: &str,
    scenario_id: &str,
    validation_config: &AdaptiveRuntimeEvidenceValidationConfig,
) -> Result<Option<MountAdaptiveRuntimePlan>> {
    if !request.enabled {
        if request.manifest_path.is_some() {
            let reason = "--adaptive-runtime-manifest requires --adaptive-runtime";
            log_mount_adaptive_runtime_rejected(
                operation_id,
                scenario_id,
                "manifest_without_opt_in",
                reason,
                request.manifest_path.as_deref(),
            );
            bail!("manifest_without_opt_in: {reason}");
        }
        return Ok(None);
    }

    if runtime.mode == MountRuntimeMode::Standard {
        let reason = "--adaptive-runtime requires --runtime-mode managed or per-core";
        log_mount_adaptive_runtime_rejected(
            operation_id,
            scenario_id,
            "unsupported_runtime_mode",
            reason,
            request.manifest_path.as_deref(),
        );
        bail!("unsupported_runtime_mode: {reason}");
    }

    let manifest_path = request.manifest_path.as_deref().ok_or_else(|| {
        let reason = "--adaptive-runtime requires --adaptive-runtime-manifest FILE";
        log_mount_adaptive_runtime_rejected(
            operation_id,
            scenario_id,
            "missing_manifest",
            reason,
            None,
        );
        anyhow::anyhow!("missing_manifest: {reason}")
    })?;

    let manifest = load_validated_mount_adaptive_runtime_manifest(
        manifest_path,
        operation_id,
        scenario_id,
        validation_config,
    )?;

    if manifest.runtime_mode != runtime.mode.adaptive_runtime_mode() {
        let reason = format!(
            "manifest runtime_mode={} does not match requested runtime_mode={}",
            manifest.runtime_mode.label(),
            runtime.mode.as_str()
        );
        log_mount_adaptive_runtime_rejected(
            operation_id,
            scenario_id,
            "runtime_mode_mismatch",
            &reason,
            Some(manifest_path),
        );
        bail!("runtime_mode_mismatch: {reason}");
    }

    if manifest.read_write != read_write {
        let reason = format!(
            "manifest read_write={} does not match requested read_write={read_write}",
            manifest.read_write
        );
        log_mount_adaptive_runtime_rejected(
            operation_id,
            scenario_id,
            "access_mode_mismatch",
            &reason,
            Some(manifest_path),
        );
        bail!("access_mode_mismatch: {reason}");
    }

    let (fsm, gate) = build_adaptive_runtime_backpressure_gate();
    let plan = MountAdaptiveRuntimePlan {
        manifest_path: manifest_path.to_path_buf(),
        manifest_scenario_id: manifest.scenario_id,
        run_id: manifest.run_id,
        release_claim_state: manifest.release_claim_state.label().to_owned(),
        backpressure_policy_id: manifest.backpressure_policy_id,
        artifact_paths: manifest.artifact_paths,
        raw_stdout_path: manifest.raw_stdout_path,
        raw_stderr_path: manifest.raw_stderr_path,
        raw_log_paths: manifest.raw_log_paths,
        cleanup_status: manifest.cleanup_status.label().to_owned(),
        git_sha: manifest.git_sha,
        reproduction_command: manifest.reproduction_command,
        fsm,
        gate,
    };
    log_mount_adaptive_runtime_accepted(operation_id, scenario_id, &plan);
    Ok(Some(plan))
}

fn mount_with_fuse(
    open_fs: Arc<OpenFs>,
    mountpoint: &Path,
    read_write: bool,
    allow_other: bool,
    auto_unmount: bool,
    writeback_cache: WritebackCacheMode,
) -> Result<()> {
    let opts = MountOptions {
        read_only: !read_write,
        allow_other,
        auto_unmount,
        writeback_cache,
        ioctl_trace_path: None,
        worker_threads: 0,
    };

    let fs_ops: Box<dyn FsOps> = Box::new(open_fs);
    ffs_fuse::mount(fs_ops, mountpoint, &opts)
        .with_context(|| format!("FUSE mount failed at {}", mountpoint.display()))
}

/// Parameters shared by managed and per-core mount paths.
struct ManagedMountParams<'a> {
    image_path: &'a Path,
    mountpoint: &'a Path,
    runtime: MountRuntimeConfig,
    read_write: bool,
    allow_other: bool,
    auto_unmount: bool,
    writeback_cache: WritebackCacheMode,
    backpressure: Option<Arc<BackpressureGate>>,
    adaptive_runtime_plan: Option<&'a MountAdaptiveRuntimePlan>,
    adaptive_runtime_summary: &'a MountAdaptiveRuntimeSummaryConfig,
    console: &'a MountConsoleConfig,
    unmount_timeout_secs: u64,
    operation_id: &'a str,
    scenario_id: &'a str,
}

fn worker_count_from_usize(worker_count: usize) -> u32 {
    u32::try_from(worker_count).unwrap_or(u32::MAX)
}

fn build_mount_per_core_shutdown_observation(
    metrics: ffs_fuse::MetricsSnapshot,
    worker_count: u32,
    aggregate: &ffs_fuse::per_core::AggregateMetrics,
) -> MountAdaptiveRuntimeShutdownObservation {
    let per_core_distribution = aggregate
        .per_core
        .iter()
        .enumerate()
        .map(|(core_id, core)| MountAdaptiveRuntimeCoreRequestSummary {
            core_id: u32::try_from(core_id).unwrap_or(u32::MAX),
            requests: core.requests,
            cache_hits: core.cache_hits,
            cache_misses: core.cache_misses,
        })
        .collect();
    MountAdaptiveRuntimeShutdownObservation {
        metrics,
        worker_count,
        per_core: Some(MountAdaptiveRuntimePerCoreObservation {
            total_cache_hits: aggregate.total_cache_hits,
            total_cache_misses: aggregate.total_cache_misses,
            imbalance_ratio: aggregate.imbalance_ratio(),
            per_core_distribution,
        }),
    }
}

fn mount_with_managed_fuse(open_fs: Arc<OpenFs>, params: &ManagedMountParams<'_>) -> Result<()> {
    let mount_started = std::time::SystemTime::now();
    let config = MountConfig {
        options: MountOptions {
            read_only: !params.read_write,
            allow_other: params.allow_other,
            auto_unmount: params.auto_unmount,
            writeback_cache: params.writeback_cache,
            ioctl_trace_path: None,
            worker_threads: 0,
        },
        backpressure: params.backpressure.clone(),
        unmount_timeout: std::time::Duration::from_secs(params.unmount_timeout_secs),
    };

    info!(
        target: "ffs::cli::mount",
        operation_id = params.operation_id,
        scenario_id = params.scenario_id,
        outcome = "managed_mount_starting",
        unmount_timeout_secs = params.unmount_timeout_secs,
        thread_count = config.options.resolved_thread_count(),
        "managed_mount_start"
    );

    let fs_ops: Box<dyn FsOps> = Box::new(open_fs);
    let handle = mount_managed(fs_ops, params.mountpoint, &config).with_context(|| {
        format!(
            "FUSE managed mount failed at {}",
            params.mountpoint.display()
        )
    })?;

    wire_ctrlc_shutdown(&handle)?;

    info!(
        target: "ffs::cli::mount",
        operation_id = params.operation_id,
        scenario_id = params.scenario_id,
        outcome = "managed_mount_active",
        "managed_mount_waiting_for_shutdown"
    );

    let metrics = handle.wait();
    let mount_ended = std::time::SystemTime::now();
    log_mount_shutdown_metrics(params.operation_id, params.scenario_id, &metrics);
    emit_mount_console(
        params.console,
        &mount_console_observation(
            params,
            RuntimeConsoleMode::Managed,
            MountConsoleRuntimeMetrics::from_snapshot(&metrics),
            Vec::new(),
            mount_started,
            mount_ended,
        ),
    )?;
    emit_mount_adaptive_runtime_shutdown_summary(
        MountAdaptiveRuntimeShutdownContext {
            image_path: params.image_path,
            mountpoint: params.mountpoint,
            runtime: params.runtime,
            read_write: params.read_write,
            operation_id: params.operation_id,
            cli_scenario_id: params.scenario_id,
            plan: params.adaptive_runtime_plan,
            summary_config: params.adaptive_runtime_summary,
        },
        &MountAdaptiveRuntimeShutdownObservation {
            metrics,
            worker_count: worker_count_from_usize(config.options.resolved_thread_count()),
            per_core: None,
        },
    )?;
    Ok(())
}

/// Runtime counters lifted from a `MetricsSnapshot` for the console observation.
#[derive(Clone, Copy)]
struct MountConsoleRuntimeMetrics {
    requests_total: u64,
    requests_err: u64,
    bytes_read: u64,
    requests_throttled: u64,
    requests_shed: u64,
}

impl MountConsoleRuntimeMetrics {
    fn from_snapshot(metrics: &ffs_fuse::MetricsSnapshot) -> Self {
        Self {
            requests_total: metrics.requests_total,
            requests_err: metrics.requests_err,
            bytes_read: metrics.bytes_read,
            requests_throttled: metrics.requests_throttled,
            requests_shed: metrics.requests_shed,
        }
    }
}

/// Assemble a `MountConsoleObservation` from a finished managed/per-core mount.
fn mount_console_observation(
    params: &ManagedMountParams<'_>,
    runtime_mode: RuntimeConsoleMode,
    metrics: MountConsoleRuntimeMetrics,
    per_core: Vec<MountConsoleCore>,
    started_at: std::time::SystemTime,
    shutdown_at: std::time::SystemTime,
) -> MountConsoleObservation {
    let degradation_level = params
        .backpressure
        .as_ref()
        .map_or(DegradationLevel::Normal, |gate| gate.level());
    MountConsoleObservation {
        operation_id: params.operation_id.to_owned(),
        scenario_id: params.scenario_id.to_owned(),
        runtime_mode,
        read_write: params.read_write,
        started_at,
        shutdown_at,
        requests_total: metrics.requests_total,
        requests_err: metrics.requests_err,
        bytes_read: metrics.bytes_read,
        requests_throttled: metrics.requests_throttled,
        requests_shed: metrics.requests_shed,
        degradation_level,
        per_core,
        clean_shutdown: true,
        reproduction_command: mount_runtime_reproduction_command(
            params.image_path,
            params.mountpoint,
            params.runtime,
            params.read_write,
        ),
    }
}

/// Emit the runtime console artifact for a finished per-core mount.
fn emit_per_core_mount_console(
    params: &ManagedMountParams<'_>,
    metrics: &ffs_fuse::MetricsSnapshot,
    aggregate: &ffs_fuse::per_core::AggregateMetrics,
    started_at: std::time::SystemTime,
    shutdown_at: std::time::SystemTime,
) -> Result<()> {
    let per_core: Vec<MountConsoleCore> = aggregate
        .per_core
        .iter()
        .enumerate()
        .map(|(core_id, core)| MountConsoleCore {
            core_id: u32::try_from(core_id).unwrap_or(u32::MAX),
            requests: core.requests,
            cache_hits: core.cache_hits,
            cache_misses: core.cache_misses,
        })
        .collect();
    emit_mount_console(
        params.console,
        &mount_console_observation(
            params,
            RuntimeConsoleMode::PerCore,
            MountConsoleRuntimeMetrics::from_snapshot(metrics),
            per_core,
            started_at,
            shutdown_at,
        ),
    )
}

fn mount_with_per_core_fuse(open_fs: Arc<OpenFs>, params: &ManagedMountParams<'_>) -> Result<()> {
    use ffs_fuse::per_core::{PerCoreConfig, PerCoreDispatcher};

    let mount_started = std::time::SystemTime::now();
    let per_core_config = PerCoreConfig::default();
    let dispatcher = PerCoreDispatcher::new(per_core_config.clone());

    info!(
        target: "ffs::cli::mount",
        operation_id = params.operation_id,
        scenario_id = params.scenario_id,
        outcome = "per_core_mount_starting",
        num_cores = dispatcher.num_cores(),
        cache_blocks_per_core = per_core_config.cache_blocks_per_core,
        total_cache_blocks = per_core_config.total_cache_blocks(),
        steal_threshold = per_core_config.steal_threshold,
        advisory_affinity = per_core_config.advisory_affinity,
        "per_core_mount_start"
    );

    let config = MountConfig {
        options: MountOptions {
            read_only: !params.read_write,
            allow_other: params.allow_other,
            auto_unmount: params.auto_unmount,
            writeback_cache: params.writeback_cache,
            ioctl_trace_path: None,
            worker_threads: dispatcher.num_cores() as usize,
        },
        backpressure: params.backpressure.clone(),
        unmount_timeout: std::time::Duration::from_secs(params.unmount_timeout_secs),
    };

    let fs_ops: Box<dyn FsOps> = Box::new(open_fs);
    let handle = mount_managed(fs_ops, params.mountpoint, &config).with_context(|| {
        format!(
            "FUSE per-core mount failed at {}",
            params.mountpoint.display()
        )
    })?;

    wire_ctrlc_shutdown(&handle)?;

    info!(
        target: "ffs::cli::mount",
        operation_id = params.operation_id,
        scenario_id = params.scenario_id,
        outcome = "per_core_mount_active",
        "per_core_mount_waiting_for_shutdown"
    );

    let metrics = handle.wait();
    let mount_ended = std::time::SystemTime::now();

    let aggregate = dispatcher.aggregate_metrics();
    debug!(
        target: "ffs::cli::mount",
        operation_id = params.operation_id,
        scenario_id = params.scenario_id,
        imbalance_ratio = aggregate.imbalance_ratio(),
        total_requests = aggregate.total_requests,
        total_cache_hits = aggregate.total_cache_hits,
        total_cache_misses = aggregate.total_cache_misses,
        "per_core_aggregate_metrics"
    );

    info!(
        target: "ffs::cli::mount",
        operation_id = params.operation_id,
        scenario_id = params.scenario_id,
        outcome = "per_core_mount_shutdown",
        requests_total = metrics.requests_total,
        requests_ok = metrics.requests_ok,
        requests_err = metrics.requests_err,
        bytes_read = metrics.bytes_read,
        num_cores = dispatcher.num_cores(),
        imbalance_ratio = aggregate.imbalance_ratio(),
        "per_core_mount_shutdown_complete"
    );

    emit_per_core_mount_console(params, &metrics, &aggregate, mount_started, mount_ended)?;

    let observation =
        build_mount_per_core_shutdown_observation(metrics, dispatcher.num_cores(), &aggregate);
    emit_mount_adaptive_runtime_shutdown_summary(
        MountAdaptiveRuntimeShutdownContext {
            image_path: params.image_path,
            mountpoint: params.mountpoint,
            runtime: params.runtime,
            read_write: params.read_write,
            operation_id: params.operation_id,
            cli_scenario_id: params.scenario_id,
            plan: params.adaptive_runtime_plan,
            summary_config: params.adaptive_runtime_summary,
        },
        &observation,
    )?;
    Ok(())
}

fn wire_ctrlc_shutdown(handle: &ffs_fuse::MountHandle) -> Result<()> {
    let shutdown = handle.shutdown_flag().clone();
    ctrlc::set_handler(move || {
        shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    })
    .context("failed to set Ctrl+C handler")
}

fn log_mount_shutdown_metrics(
    operation_id: &str,
    scenario_id: &str,
    metrics: &ffs_fuse::MetricsSnapshot,
) {
    info!(
        target: "ffs::cli::mount",
        operation_id,
        scenario_id,
        outcome = "managed_mount_shutdown",
        requests_total = metrics.requests_total,
        requests_ok = metrics.requests_ok,
        requests_err = metrics.requests_err,
        bytes_read = metrics.bytes_read,
        requests_throttled = metrics.requests_throttled,
        requests_shed = metrics.requests_shed,
        "managed_mount_shutdown_complete"
    );
}

struct MountBackgroundScrubPlan {
    flavor: FsFlavor,
    block_size: u32,
    fs_uuid: [u8; 16],
    groups: Vec<GroupConfig>,
}

struct MountBackgroundScrubGuard {
    cx: Cx,
    handle: Option<JoinHandle<Result<ScrubDaemonMetrics>>>,
    operation_id: String,
    scenario_id: String,
}

impl MountBackgroundScrubGuard {
    fn stop(&mut self) {
        self.cx.set_cancel_requested(true);
        let Some(handle) = self.handle.take() else {
            return;
        };

        match handle.join() {
            Ok(Ok(metrics)) => {
                info!(
                    target: "ffs::cli::mount",
                    operation_id = %self.operation_id,
                    scenario_id = %self.scenario_id,
                    outcome = "background_scrub_stopped",
                    blocks_scanned_total = metrics.blocks_scanned_total,
                    blocks_corrupt_found = metrics.blocks_corrupt_found,
                    blocks_recovered = metrics.blocks_recovered,
                    blocks_unrecoverable = metrics.blocks_unrecoverable,
                    scrub_rounds_completed = metrics.scrub_rounds_completed,
                    "mount_background_scrub_stop"
                );
            }
            Ok(Err(error)) => {
                error!(
                    target: "ffs::cli::mount",
                    operation_id = %self.operation_id,
                    scenario_id = %self.scenario_id,
                    outcome = "background_scrub_failed",
                    reason = %error,
                    "mount_background_scrub_stop"
                );
            }
            Err(_) => {
                error!(
                    target: "ffs::cli::mount",
                    operation_id = %self.operation_id,
                    scenario_id = %self.scenario_id,
                    outcome = "background_scrub_panicked",
                    "mount_background_scrub_stop"
                );
            }
        }
    }
}

impl Drop for MountBackgroundScrubGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

fn build_mount_background_scrub_plan(
    image_path: &Path,
    open_fs: &OpenFs,
) -> Result<MountBackgroundScrubPlan> {
    if let Some(sb) = open_fs.ext4_superblock() {
        let specs = build_ext4_repair_group_specs(sb)
            .context("failed to compute ext4 repair group layout for mount background scrub")?;
        let groups = specs
            .iter()
            .map(|spec| GroupConfig {
                layout: spec.layout,
                source_first_block: spec.source_first_block,
                source_block_count: spec.source_block_count,
            })
            .collect();
        return Ok(MountBackgroundScrubPlan {
            flavor: FsFlavor::Ext4(Box::new(sb.clone())),
            block_size: sb.block_size,
            fs_uuid: sb.uuid,
            groups,
        });
    }

    if let Some(sb) = open_fs.btrfs_superblock() {
        let image_len = open_fs.device_len();
        let block_size = choose_btrfs_scrub_block_size(image_len, sb.nodesize, sb.sectorsize)
            .with_context(|| {
                format!(
                    "failed to derive btrfs mount background scrub block size \
                     (len_bytes={image_len}, nodesize={}, sectorsize={})",
                    sb.nodesize, sb.sectorsize
                )
            })?;
        let image_path = image_path.to_path_buf();
        let specs = discover_btrfs_repair_group_specs(&image_path, block_size)
            .context("failed to discover btrfs repair group layout for mount background scrub")?;
        let groups = specs
            .iter()
            .map(|spec| GroupConfig {
                layout: spec.layout,
                source_first_block: spec.physical_start_block,
                source_block_count: spec.source_block_count,
            })
            .collect();
        return Ok(MountBackgroundScrubPlan {
            flavor: FsFlavor::Btrfs(Box::new(sb.clone())),
            block_size,
            fs_uuid: sb.fsid,
            groups,
        });
    }

    bail!("mount background scrub supports ext4 and btrfs images only")
}

fn open_mount_background_scrub_ledger(
    path: Option<&Path>,
) -> Result<Box<dyn std::io::Write + Send>> {
    match path {
        Some(path) => {
            let file = StdOpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| {
                    format!(
                        "failed to open mount background scrub evidence ledger: {}",
                        path.display()
                    )
                })?;
            Ok(Box::new(file))
        }
        None => Ok(Box::new(std::io::sink())),
    }
}

fn ensure_mount_background_repair_write_access(image_path: &Path) -> Result<()> {
    StdOpenOptions::new()
        .read(true)
        .write(true)
        .open(image_path)
        .map(drop)
        .with_context(|| {
            format!(
                "background repair requires writable backing image access: {}",
                image_path.display()
            )
        })
}

#[derive(Debug, Clone)]
struct MountedRecoveryWriteback {
    open_fs: Arc<OpenFs>,
}

impl RecoveryWriteback for MountedRecoveryWriteback {
    fn writeback_recovered(
        &self,
        cx: &Cx,
        _device: &dyn BlockDevice,
        recovered: &[RecoveryWritebackBlock<'_>],
    ) -> ffs_error::Result<()> {
        let entries: Vec<RepairWritebackBlock<'_>> = recovered
            .iter()
            .map(|block| RepairWritebackBlock {
                block: block.block,
                expected_current: block.expected_current,
                data: block.data,
            })
            .collect();
        self.open_fs
            .repair_writeback_blocks_via_mounted_mutation_path(cx, &entries)?;
        Ok(())
    }

    fn authority_name(&self) -> &'static str {
        "mounted_mvcc_request_scope"
    }
}

fn mount_background_repair_symbol_count(
    groups: &[GroupConfig],
    repair_writes_enabled: bool,
) -> u32 {
    if !repair_writes_enabled {
        return 0;
    }
    groups
        .iter()
        .map(|group| group.layout.repair_block_count)
        .max()
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
struct MountBackgroundScrubThreadConfig<'a> {
    interval: Duration,
    ledger_path: Option<&'a Path>,
    repair_writes_enabled: bool,
    mounted_repair_writeback: Option<Arc<OpenFs>>,
    operation_id: &'a str,
    scenario_id: &'a str,
}

fn run_mount_background_scrub_daemon(
    cx: &Cx,
    image_path: &Path,
    plan: MountBackgroundScrubPlan,
    config: MountBackgroundScrubThreadConfig<'_>,
) -> Result<ScrubDaemonMetrics> {
    let interval = config.interval;
    let operation_id = config.operation_id;
    let scenario_id = config.scenario_id;
    let repair_writes_enabled = config.repair_writes_enabled;
    if repair_writes_enabled {
        ensure_mount_background_repair_write_access(image_path)?;
    }
    let byte_dev = FileByteDevice::open(image_path).with_context(|| {
        format!(
            "failed to open image for background scrub: {}",
            image_path.display()
        )
    })?;
    let block_dev = ByteBlockDevice::new(byte_dev, plan.block_size).with_context(|| {
        format!(
            "failed to create background scrub block device (block_size={})",
            plan.block_size
        )
    })?;
    let validator = scrub_validator(&plan.flavor, plan.block_size);
    let ledger = open_mount_background_scrub_ledger(config.ledger_path)?;
    let repair_symbol_count =
        mount_background_repair_symbol_count(&plan.groups, repair_writes_enabled);
    let mut pipeline = ScrubWithRecovery::new(
        &block_dev,
        validator.as_ref(),
        plan.fs_uuid,
        plan.groups,
        ledger,
        repair_symbol_count,
    )
    .with_repair_writes_enabled(repair_writes_enabled);
    if let Some(open_fs) = config.mounted_repair_writeback {
        pipeline = pipeline.with_recovery_writeback(Arc::new(MountedRecoveryWriteback { open_fs }));
    }
    let mut daemon = ScrubDaemon::new(
        pipeline,
        ScrubDaemonConfig {
            interval,
            ..ScrubDaemonConfig::default()
        },
    );

    info!(
        target: "ffs::cli::mount",
        operation_id,
        scenario_id,
        interval_secs = interval.as_secs(),
        repair_writes_enabled,
        "mount_background_scrub_thread_start"
    );

    daemon.run_until_cancelled(cx).map_err(anyhow::Error::new)
}

fn start_mount_background_scrub(
    image_path: &Path,
    open_fs: &OpenFs,
    config: &MountBackgroundScrubConfig,
    mounted_repair_writeback: Option<Arc<OpenFs>>,
    operation_id: &str,
    scenario_id: &str,
) -> Result<Option<MountBackgroundScrubGuard>> {
    if !config.enabled {
        debug!(
            target: "ffs::cli::mount",
            operation_id,
            scenario_id,
            outcome = "background_scrub_disabled",
            explicit = config.explicit,
            "mount_background_scrub_disabled"
        );
        return Ok(None);
    }

    let plan = match build_mount_background_scrub_plan(image_path, open_fs) {
        Ok(plan) => plan,
        Err(error) if !config.explicit => {
            warn!(
                target: "ffs::cli::mount",
                operation_id,
                scenario_id,
                outcome = "background_scrub_unavailable",
                reason = %error,
                "mount_background_scrub_unavailable"
            );
            return Ok(None);
        }
        Err(error) => return Err(error),
    };

    let group_count = plan.groups.len();
    let block_size = plan.block_size;
    let repair_writes_enabled = config.repair_writes_enabled;
    let repair_symbol_count =
        mount_background_repair_symbol_count(&plan.groups, repair_writes_enabled);
    if repair_writes_enabled {
        ensure_mount_background_repair_write_access(image_path)?;
    }
    let interval = Duration::from_secs(config.interval_secs);
    let thread_cx = Cx::for_request();
    let guard_cx = thread_cx.clone();
    let image_path = image_path.to_path_buf();
    let ledger_path = config.ledger_path.clone();
    let thread_operation_id = operation_id.to_owned();
    let thread_scenario_id = scenario_id.to_owned();

    info!(
        target: "ffs::cli::mount",
        operation_id,
        scenario_id,
        outcome = "background_scrub_starting",
        groups = group_count,
        block_size,
        interval_secs = config.interval_secs,
        repair_writes_enabled,
        repair_symbol_count,
        "mount_background_scrub_start"
    );

    let handle = std::thread::Builder::new()
        .name(if repair_writes_enabled {
            "ffs-mount-repair".to_owned()
        } else {
            "ffs-mount-scrub".to_owned()
        })
        .spawn(move || {
            run_mount_background_scrub_daemon(
                &thread_cx,
                &image_path,
                plan,
                MountBackgroundScrubThreadConfig {
                    interval,
                    ledger_path: ledger_path.as_deref(),
                    repair_writes_enabled,
                    mounted_repair_writeback,
                    operation_id: &thread_operation_id,
                    scenario_id: &thread_scenario_id,
                },
            )
        })
        .context("failed to spawn mount background scrub daemon")?;

    Ok(Some(MountBackgroundScrubGuard {
        cx: guard_cx,
        handle: Some(handle),
        operation_id: operation_id.to_owned(),
        scenario_id: scenario_id.to_owned(),
    }))
}

#[allow(clippy::too_many_lines)]
fn mount_cmd(image_path: &Path, mountpoint: &Path, options: &MountCmdOptions) -> Result<()> {
    if env_bool("FFS_MOUNT_BENCH_EVIDENCE", false)? {
        let sha = elf_self_sha256().context("self-hash executing mounted benchmark ELF")?;
        eprintln!("mount_bench_evidence,binary_sha256={sha}");
        eprintln!(
            "mount_build_profile,pgo_profile_sha256={}",
            option_env!("FFS_PGO_PROFILE_SHA256").unwrap_or("none")
        );
    }

    let auto_unmount = env_bool("FFS_AUTO_UNMOUNT", true)?;
    let requested_runtime = options.runtime;
    let operation_id = mount_operation_id(
        image_path,
        mountpoint,
        requested_runtime.mode,
        options.read_write,
    );
    let scenario_id = requested_runtime.mode.scenario_id(options.read_write);
    let command_span = info_span!(
        target: "ffs::cli::mount",
        "mount",
        operation_id = %operation_id,
        scenario_id,
        image = %image_path.display(),
        mountpoint = %mountpoint.display(),
        runtime_mode = requested_runtime.mode.as_str(),
        managed_unmount_timeout_secs = requested_runtime.managed_unmount_timeout_secs,
        allow_other = options.allow_other,
        auto_unmount,
        read_write = options.read_write,
        adaptive_runtime = options.adaptive_runtime.enabled,
        writeback_cache = options.writeback_cache.enabled,
        background_repair = options.background_scrub.repair_writes_enabled
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(
        target: "ffs::cli::mount",
        operation_id = %operation_id,
        scenario_id,
        "mount_start"
    );

    let runtime = match requested_runtime.validate() {
        Ok(runtime) => runtime,
        Err(error) => {
            let reason = error.to_string();
            log_mount_runtime_rejected(
                &operation_id,
                scenario_id,
                requested_runtime,
                options.read_write,
                "invalid_runtime_mode_flags",
                &reason,
            );
            return Err(error);
        }
    };

    log_mount_runtime_selected(
        &operation_id,
        scenario_id,
        runtime,
        options.allow_other,
        auto_unmount,
        options.read_write,
    );

    let adaptive_runtime_plan = validate_mount_adaptive_runtime_request(
        &options.adaptive_runtime,
        runtime,
        options.read_write,
        &operation_id,
        scenario_id,
    )?;

    validate_mount_writeback_cache_request(
        image_path,
        mountpoint,
        options,
        &operation_id,
        scenario_id,
    )?;

    let mut open_fs = match open_filesystem_for_mount(image_path, options) {
        Ok(open_fs) => open_fs,
        Err(error) => {
            if let Some(ffs_error) = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<ffs_error::FfsError>())
            {
                log_mount_open_rejected(&operation_id, scenario_id, options.read_write, ffs_error);
            } else {
                error!(
                    target: "ffs::cli::mount",
                    operation_id,
                    scenario_id,
                    outcome = "mount_open_rejected",
                    error_class = "filesystem_open_failed",
                    read_write = options.read_write,
                    reason = %error,
                    "mount_open_rejected"
                );
            }
            return Err(error);
        }
    };
    emit_mount_banner(&open_fs, mountpoint, options.read_write, runtime.mode);
    emit_optional_recovery_banner(&open_fs);

    if options.read_write {
        let cx = cli_cx();
        open_fs
            .enable_writes(&cx)
            .context("failed to enable write support")?;
        if options.background_scrub.repair_writes_enabled && !open_fs.is_writable() {
            bail!(
                "read-write background repair requires the mounted MVCC serialization gate to enable write support"
            );
        }
    }
    let open_fs = Arc::new(open_fs);
    let mounted_repair_writeback = (options.read_write
        && options.background_scrub.repair_writes_enabled)
        .then(|| Arc::clone(&open_fs));

    let _background_scrub_guard = start_mount_background_scrub(
        image_path,
        open_fs.as_ref(),
        &options.background_scrub,
        mounted_repair_writeback,
        &operation_id,
        scenario_id,
    )?;

    match runtime.mode {
        MountRuntimeMode::Standard => {
            mount_with_fuse(
                Arc::clone(&open_fs),
                mountpoint,
                options.read_write,
                options.allow_other,
                auto_unmount,
                WritebackCacheMode::from_enabled(options.writeback_cache.enabled),
            )?;
            emit_mount_adaptive_runtime_shutdown_summary(
                MountAdaptiveRuntimeShutdownContext {
                    image_path,
                    mountpoint,
                    runtime,
                    read_write: options.read_write,
                    operation_id: &operation_id,
                    cli_scenario_id: scenario_id,
                    plan: None,
                    summary_config: &options.adaptive_runtime_summary,
                },
                &MountAdaptiveRuntimeShutdownObservation {
                    metrics: ffs_fuse::MetricsSnapshot {
                        requests_total: 0,
                        requests_ok: 0,
                        requests_err: 0,
                        bytes_read: 0,
                        requests_throttled: 0,
                        requests_shed: 0,
                    },
                    worker_count: 0,
                    per_core: None,
                },
            )?;
        }
        MountRuntimeMode::Managed | MountRuntimeMode::PerCore => {
            let params = ManagedMountParams {
                image_path,
                mountpoint,
                runtime,
                read_write: options.read_write,
                allow_other: options.allow_other,
                auto_unmount,
                writeback_cache: WritebackCacheMode::from_enabled(options.writeback_cache.enabled),
                backpressure: adaptive_runtime_plan
                    .as_ref()
                    .map(|plan| Arc::clone(&plan.gate)),
                adaptive_runtime_plan: adaptive_runtime_plan.as_ref(),
                adaptive_runtime_summary: &options.adaptive_runtime_summary,
                console: &options.console,
                unmount_timeout_secs: runtime.managed_unmount_timeout_secs(),
                operation_id: &operation_id,
                scenario_id,
            };
            if runtime.mode == MountRuntimeMode::PerCore {
                mount_with_per_core_fuse(Arc::clone(&open_fs), &params)?;
            } else {
                mount_with_managed_fuse(Arc::clone(&open_fs), &params)?;
            }
        }
    }

    info!(
        target: "ffs::cli::mount",
        operation_id = %operation_id,
        scenario_id,
        outcome = "runtime_mode_completed",
        runtime_mode = runtime.mode.as_str(),
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "mount_complete"
    );

    Ok(())
}

fn open_filesystem_for_mount(image_path: &Path, options: &MountCmdOptions) -> Result<OpenFs> {
    let cx = cli_cx();
    let open_opts = build_mount_open_options(options);
    let open_fs = OpenFs::open_with_options(&cx, image_path, &open_opts)
        .map_err(anyhow::Error::new)
        .with_context(|| format!("failed to open filesystem image: {}", image_path.display()))?;
    if !matches!(
        options.btrfs_mount_selection,
        BtrfsMountSelection::DefaultRoot
    ) && !open_fs.is_btrfs()
    {
        bail!(
            "{} requires a btrfs image",
            btrfs_mount_selection_flag(&options.btrfs_mount_selection)
        );
    }
    Ok(open_fs)
}

fn build_mount_open_options(options: &MountCmdOptions) -> OpenOptions {
    OpenOptions {
        ext4_journal_replay_mode: ext4_mount_replay_mode(options.read_write),
        ext4_data_err_policy: options.ext4_data_err_policy,
        ext4_verify_journal_checksums: options.ext4_verify_journal_checksums,
        mount_mode: options.mount_mode,
        btrfs_mount_selection: options.btrfs_mount_selection.clone(),
        btrfs_rw_ephemeral_ok: options.btrfs_rw_ephemeral_ok,
        ..OpenOptions::default()
    }
}

fn parse_btrfs_mount_selection(
    subvol: Option<String>,
    snapshot: Option<String>,
) -> Result<BtrfsMountSelection> {
    match (subvol, snapshot) {
        (Some(_), Some(_)) => bail!("--subvol and --snapshot are mutually exclusive"),
        (Some(name), None) => Ok(BtrfsMountSelection::Subvolume(name)),
        (None, Some(name)) => Ok(BtrfsMountSelection::Snapshot(name)),
        (None, None) => Ok(BtrfsMountSelection::DefaultRoot),
    }
}

fn btrfs_mount_selection_flag(selection: &BtrfsMountSelection) -> &'static str {
    match selection {
        BtrfsMountSelection::DefaultRoot => "(default btrfs root)",
        BtrfsMountSelection::Subvolume(_) => "--subvol",
        BtrfsMountSelection::Snapshot(_) => "--snapshot",
    }
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

pub fn choose_btrfs_scrub_block_size(
    image_len: u64,
    nodesize: u32,
    sectorsize: u32,
) -> Result<u32> {
    if nodesize == 0 || !nodesize.is_power_of_two() {
        bail!("invalid btrfs nodesize={nodesize}; expected non-zero power-of-two");
    }

    // Btrfs superblock region must fit; scrub block size must hold it.
    let super_info_size = u32::try_from(ffs_types::BTRFS_SUPER_INFO_SIZE)
        .map_err(|_| anyhow::anyhow!("btrfs superblock size does not fit in u32"))?;
    let min_block_size = if sectorsize.is_power_of_two() {
        sectorsize.max(super_info_size)
    } else {
        super_info_size
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

#[must_use]
pub fn count_blocks_at_severity_or_higher(report: &ScrubReport, min: Severity) -> u64 {
    report
        .findings
        .iter()
        .filter(|finding| finding.severity >= min)
        .map(|finding| finding.block.0)
        .collect::<BTreeSet<_>>()
        .len() as u64
}

#[must_use]
pub fn scrub_validator(flavor: &FsFlavor, block_size: u32) -> Box<dyn BlockValidator> {
    match flavor {
        // No blind `ZeroCheckValidator` here: a whole-image scrub has no
        // allocation map, and unallocated ext4 blocks are legitimately all
        // zeroes, so zero-flagging them reports free space as corruption. A
        // zeroed superblock is still caught by `Ext4SuperblockValidator`, which
        // rejects the failed magic/parse.
        FsFlavor::Ext4(_) => Box::new(Ext4SuperblockValidator::new(block_size)),
        // `sb.total_bytes` (the filesystem size, not the image file size) decides
        // which superblock mirrors btrfs actually wrote, and so which are
        // expected to validate.
        FsFlavor::Btrfs(sb) => Box::new(BtrfsScrubValidator::new(
            block_size,
            sb.fsid,
            sb.csum_type,
            sb.total_bytes,
        )),
    }
}

fn print_scrub_output(json: bool, output: &ScrubOutput, report: &ScrubReport) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(output).context("serialize scrub report")?
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
            for finding in &report.findings {
                println!("  {finding}");
            }
        }
    }

    Ok(())
}

fn scrub_cmd(path: &PathBuf, json: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::scrub",
        "scrub",
        image = %path.display(),
        output_json = json
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::scrub", "scrub_start");

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

    let validator = scrub_validator(&flavor, block_size);

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

    print_scrub_output(json, &output, &report)?;

    let has_error_findings = report.count_at_severity(Severity::Error) > 0;

    info!(
        target: "ffs::cli::scrub",
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        blocks_scanned = output.blocks_scanned,
        blocks_corrupt = output.blocks_corrupt,
        blocks_error_or_higher = output.blocks_error_or_higher,
        has_error_findings,
        "scrub_complete"
    );

    // Exit with non-zero status if corruption found at Error or above.
    if has_error_findings {
        std::process::exit(2);
    }

    Ok(())
}

fn fsck_cmd(path: &PathBuf, options: FsckCommandOptions) -> Result<()> {
    let flags = options.flags;
    let command_span = info_span!(
        target: "ffs::cli::fsck",
        "fsck",
        image = %path.display(),
        repair = flags.repair(),
        force = flags.force(),
        verbose = flags.verbose(),
        block_group = options.block_group.unwrap_or(u32::MAX),
        output_json = flags.json()
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::fsck", "fsck_start");

    let output = match build_fsck_output(path, options) {
        Ok(output) => output,
        Err(err) => {
            if flags.json() {
                let error_msg = format!("{err:#}");
                let escaped = serde_json::to_string(&error_msg)
                    .unwrap_or_else(|_| "\"unknown_error\"".to_string());
                println!(
                    "{{\"status\":\"operational_error\",\"exit_code\":4,\"error\":{escaped}}}"
                );
            } else {
                eprintln!("fsck operational error: {err:#}");
            }
            std::process::exit(4);
        }
    };

    print_fsck_output(flags.json(), &output)?;

    info!(
        target: "ffs::cli::fsck",
        filesystem = output.filesystem,
        outcome = ?output.outcome,
        repair_status = ?output.repair_status,
        exit_code = output.exit_code,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "fsck_complete"
    );

    if output.exit_code != 0 {
        std::process::exit(output.exit_code);
    }

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn build_fsck_output(path: &PathBuf, options: FsckCommandOptions) -> Result<FsckOutput> {
    let flags = options.flags;
    let cx = cli_cx();
    let mut phases = Vec::new();
    let mut limitations = Vec::new();
    let repair_coordination = coordinate_repair_write_access(
        &cx,
        "ffs::cli::fsck",
        REPAIR_COORDINATION_SCENARIO_FSCK,
        "fsck",
        path,
        flags.repair(),
    );
    if repair_coordination.output.is_blocked() {
        limitations.push(repair_coordination.output.detail.clone());
    }
    let (flavor, bootstrap_recovery_source) = detect_flavor_with_optional_btrfs_bootstrap(
        &cx,
        path,
        flags.repair() && repair_coordination.writes_allowed,
        &mut limitations,
    )?;
    let mut ext4_recovery = None;
    let mut btrfs_repair_attempted = bootstrap_recovery_source.is_some();
    let mut btrfs_repair_performed = bootstrap_recovery_source.is_some();
    let mut btrfs_repair_detail = bootstrap_recovery_source.map(|source| {
        format!(
            "bootstrap restored primary btrfs superblock from backup mirror at byte offset {} \
             (generation={})",
            source.offset, source.generation
        )
    });
    if flags.repair() && repair_coordination.writes_allowed {
        if let FsFlavor::Ext4(_) = &flavor {
            ext4_recovery = Some(run_ext4_mount_recovery(path)?);
        }
    }

    phases.push(FsckPhaseOutput {
        phase: "superblock_validation".to_owned(),
        status: "ok".to_owned(),
        detail: match &flavor {
            FsFlavor::Ext4(sb) => format!(
                "ext4 superblock parsed (block_size={}, blocks={}, inodes={})",
                sb.block_size, sb.blocks_count, sb.inodes_count
            ),
            FsFlavor::Btrfs(sb) => format!(
                "btrfs superblock parsed (sectorsize={}, nodesize={}, generation={})",
                sb.sectorsize, sb.nodesize, sb.generation
            ),
        },
    });

    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let image_len = byte_dev.len_bytes();

    let (scope, report, block_size, scrub_skipped_detail) = match &flavor {
        FsFlavor::Ext4(sb) => {
            // ext4 fsck's in-memory reader only parses the superblock + group
            // descriptor table (validate_ext4_group_descriptors -> read_group_desc);
            // it never touches inodes or data blocks, and the Scrubber re-reads the
            // rest via batched vectored I/O (bd-a384r). Read only the [0, gdt_end)
            // prefix instead of the whole device. Clamp to the device length so a
            // truncated / malformed descriptor table yields the identical
            // descriptor-validation error as the previous full-image read; fall
            // back to the full length if the offset cannot be computed.
            let prefix_len = sb
                .group_desc_offset(GroupNumber(sb.groups_count().saturating_sub(1)))
                .and_then(|off| off.checked_add(u64::from(sb.group_desc_size())))
                .map_or(image_len, |gdt_end| gdt_end.min(image_len));
            let prefix_len = usize::try_from(prefix_len)
                .context("ext4 group-descriptor prefix length does not fit usize")?;
            let mut image = vec![0u8; prefix_len];
            byte_dev
                .read_exact_at(&cx, ByteOffset(0), &mut image)
                .context("failed to read ext4 superblock + group descriptor prefix")?;
            let reader = Ext4ImageReader::new(&image).context("failed to parse ext4 superblock")?;
            let desc_status = validate_ext4_group_descriptors(&reader, &image, options.block_group);
            phases.push(desc_status);

            let block_size = sb.block_size;
            let block_dev = ByteBlockDevice::new(byte_dev, block_size).with_context(|| {
                format!("failed to create block device (block_size={block_size})")
            })?;
            let validator = scrub_validator(&flavor, block_size);

            let skip_full_scrub = options.block_group.is_none()
                && !flags.force()
                && ext4_appears_clean_state(sb.state);

            let (scope, report, skipped_detail) = if let Some(group) = options.block_group {
                let (start, count) = ext4_group_scrub_scope(sb, group)?;
                if flags.verbose() && !flags.json() {
                    eprintln!(
                        "fsck: ext4 group {} -> scrub blocks {}..{}",
                        group,
                        start.0,
                        start.0.saturating_add(count).saturating_sub(1)
                    );
                }
                let report = Scrubber::new(&block_dev, &*validator)
                    .scrub_range(&cx, start, count)
                    .with_context(|| format!("failed to scrub ext4 group {group}"))?;
                (
                    FsckScopeOutput::Ext4BlockGroup {
                        group,
                        start_block: start.0,
                        block_count: count,
                    },
                    report,
                    None,
                )
            } else if skip_full_scrub {
                let detail = format!(
                    "filesystem appears clean (state_flags={}); skipped block-level scrub; pass --force for full scrub",
                    ext4_state_flag_names(sb.state).join("|")
                );
                if flags.verbose() && !flags.json() {
                    eprintln!("fsck: {detail}");
                }
                limitations.push(
                    "filesystem appears clean; skipped block-level scrub (use --force for full scrub)"
                        .to_owned(),
                );
                (
                    FsckScopeOutput::Full,
                    ScrubReport {
                        findings: Vec::new(),
                        blocks_scanned: 0,
                        blocks_corrupt: 0,
                        blocks_io_error: 0,
                    },
                    Some(detail),
                )
            } else {
                if flags.verbose() && !flags.json() {
                    eprintln!(
                        "fsck: ext4 full scrub across {} blocks",
                        block_dev.block_count()
                    );
                }
                let report = Scrubber::new(&block_dev, &*validator)
                    .scrub_all(&cx)
                    .context("failed to scrub ext4 image")?;
                (FsckScopeOutput::Full, report, None)
            };
            (scope, report, block_size, skipped_detail)
        }
        FsFlavor::Btrfs(sb) => {
            phases.push(FsckPhaseOutput {
                phase: "group_descriptor_validation".to_owned(),
                status: "skipped".to_owned(),
                detail: "ext4-specific group descriptor checks do not apply to btrfs".to_owned(),
            });

            let block_size = choose_btrfs_scrub_block_size(image_len, sb.nodesize, sb.sectorsize)
                .with_context(|| {
                    format!(
                        "failed to derive aligned btrfs scrub block size (len_bytes={image_len}, nodesize={}, sectorsize={})",
                        sb.nodesize, sb.sectorsize
                    )
                })?;
            let (scope, scrub_start, scrub_count, mut report) = if let Some(group) =
                options.block_group
            {
                let specs = discover_btrfs_repair_group_specs(path, block_size)
                    .context("failed to discover btrfs block groups for scoped fsck")?;
                let spec = specs
                    .iter()
                    .find(|spec| spec.group == group)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "btrfs block group {group} is unavailable (valid range: 0..{})",
                            specs.len().saturating_sub(1)
                        )
                    })?;
                if flags.verbose() && !flags.json() {
                    eprintln!(
                        "fsck: btrfs group {} -> logical {}..{}, physical blocks {}..{}",
                        group,
                        spec.logical_start,
                        spec.logical_start
                            .saturating_add(spec.logical_bytes)
                            .saturating_sub(1),
                        spec.physical_start_block.0,
                        spec.physical_start_block
                            .0
                            .saturating_add(spec.physical_block_count)
                            .saturating_sub(1)
                    );
                }
                let report = scrub_range_for_repair(
                    path,
                    &flavor,
                    block_size,
                    spec.physical_start_block,
                    spec.physical_block_count,
                    None,
                    &mut limitations,
                )
                .with_context(|| format!("failed to scrub btrfs group {group}"))?;
                (
                    FsckScopeOutput::BtrfsBlockGroup {
                        group,
                        logical_start: spec.logical_start,
                        logical_bytes: spec.logical_bytes,
                        start_block: spec.physical_start_block.0,
                        block_count: spec.physical_block_count,
                    },
                    spec.physical_start_block,
                    spec.physical_block_count,
                    report,
                )
            } else {
                let block_dev = ByteBlockDevice::new(byte_dev, block_size).with_context(|| {
                    format!("failed to create block device (block_size={block_size})")
                })?;
                let validator = scrub_validator(&flavor, block_size);
                if flags.verbose() && !flags.json() {
                    eprintln!(
                        "fsck: btrfs full scrub across {} blocks (block_size={block_size})",
                        block_dev.block_count()
                    );
                }
                let report = Scrubber::new(&block_dev, &*validator)
                    .scrub_all(&cx)
                    .context("failed to scrub btrfs image")?;
                (FsckScopeOutput::Full, BlockNumber(0), u64::MAX, report)
            };

            if flags.repair() && repair_coordination.writes_allowed {
                let mut verify_after_repair_writes = false;
                let primary_superblock = primary_btrfs_superblock_block(block_size);
                let superblock_in_scope =
                    block_range_contains(scrub_start, scrub_count, primary_superblock);
                if superblock_in_scope
                    && report_has_error_or_higher_for_block(&report, primary_superblock)
                {
                    btrfs_repair_attempted = true;
                    match recover_primary_btrfs_superblock_from_backup(path, &mut limitations) {
                        Ok(Some(source)) => {
                            btrfs_repair_performed = true;
                            verify_after_repair_writes = true;
                            let detail = format!(
                                "restored primary btrfs superblock from backup mirror at byte offset {} (generation={})",
                                source.offset, source.generation
                            );
                            append_btrfs_repair_detail(&mut btrfs_repair_detail, detail.clone());
                            limitations.push(detail);
                        }
                        Ok(None) => {
                            let detail =
                                "btrfs superblock corruption detected, but no valid backup superblock mirror was available for restoration"
                                    .to_owned();
                            append_btrfs_repair_detail(&mut btrfs_repair_detail, detail.clone());
                            limitations.push(detail);
                        }
                        Err(error) => {
                            let detail =
                                format!("btrfs superblock recovery attempt failed: {error:#}");
                            append_btrfs_repair_detail(&mut btrfs_repair_detail, detail.clone());
                            limitations.push(detail);
                        }
                    }
                }

                match repair_corrupt_btrfs_superblock_mirrors_from_primary(
                    path,
                    block_size,
                    scrub_start,
                    scrub_count,
                    &mut limitations,
                ) {
                    Ok(mirror_outcome) => {
                        if mirror_outcome.attempted {
                            btrfs_repair_attempted = true;
                            if mirror_outcome.repaired > 0 {
                                btrfs_repair_performed = true;
                                verify_after_repair_writes = true;
                                append_btrfs_repair_detail(
                                    &mut btrfs_repair_detail,
                                    format!(
                                        "restored {} btrfs superblock mirror(s) from primary superblock",
                                        mirror_outcome.repaired
                                    ),
                                );
                            } else {
                                append_btrfs_repair_detail(
                                    &mut btrfs_repair_detail,
                                    "btrfs superblock mirror corruption detected but restoration from primary did not complete",
                                );
                            }
                        }
                    }
                    Err(error) => {
                        btrfs_repair_attempted = true;
                        let detail =
                            format!("btrfs superblock mirror recovery attempt failed: {error:#}");
                        append_btrfs_repair_detail(&mut btrfs_repair_detail, detail.clone());
                        limitations.push(detail);
                    }
                }

                // Attempt RaptorQ block-symbol recovery for non-superblock
                // corruption in the fsck --repair path.
                if count_blocks_at_severity_or_higher(&report, Severity::Error) > 0 {
                    match discover_btrfs_repair_group_specs(path, block_size) {
                        Ok(btrfs_specs) if !btrfs_specs.is_empty() => {
                            match recover_btrfs_corrupt_blocks(
                                path,
                                block_size,
                                sb.fsid,
                                &btrfs_specs,
                                &report,
                                &mut limitations,
                            ) {
                                Ok((recovered, _unrecovered, _repaired_groups)) => {
                                    if recovered > 0 {
                                        btrfs_repair_attempted = true;
                                        btrfs_repair_performed = true;
                                        verify_after_repair_writes = true;
                                        append_btrfs_repair_detail(
                                            &mut btrfs_repair_detail,
                                            format!(
                                                "recovered {recovered} btrfs block(s) via RaptorQ symbol reconstruction"
                                            ),
                                        );
                                    }
                                }
                                Err(error) => {
                                    btrfs_repair_attempted = true;
                                    let detail = format!(
                                        "btrfs block-symbol recovery attempt failed: {error:#}"
                                    );
                                    append_btrfs_repair_detail(
                                        &mut btrfs_repair_detail,
                                        detail.clone(),
                                    );
                                    limitations.push(detail);
                                }
                            }
                        }
                        Ok(_) => {
                            limitations.push(
                                "no btrfs block groups discovered; fsck block-symbol recovery skipped"
                                    .to_owned(),
                            );
                        }
                        Err(error) => {
                            limitations.push(format!(
                                "failed to discover btrfs repair group layout for fsck: {error:#}"
                            ));
                        }
                    }
                }

                if !btrfs_repair_performed && btrfs_repair_detail.is_none() {
                    if superblock_in_scope {
                        btrfs_repair_detail = Some(
                            "no primary btrfs superblock corruption detected in selected fsck scope"
                                .to_owned(),
                        );
                    } else {
                        btrfs_repair_detail = Some(
                            "repair scope does not include the primary btrfs superblock".to_owned(),
                        );
                    }
                }

                if verify_after_repair_writes {
                    report = scrub_range_for_repair(
                        path,
                        &flavor,
                        block_size,
                        scrub_start,
                        scrub_count,
                        None,
                        &mut limitations,
                    )
                    .context("failed to verify btrfs image after fsck repairs")?;
                }
            }

            (scope, report, block_size, None)
        }
    };
    let scrub = scrub_report_to_phase(&report);
    let scrub_phase_status = if scrub_skipped_detail.is_some() {
        "skipped"
    } else if scrub.error_or_higher == 0 {
        "ok"
    } else {
        "error"
    };
    let scrub_phase_detail = scrub_skipped_detail.unwrap_or_else(|| {
        format!(
            "scanned={} corrupt={} error_or_higher={} io_errors={}",
            scrub.scanned, scrub.corrupt, scrub.error_or_higher, scrub.io_error
        )
    });
    phases.push(FsckPhaseOutput {
        phase: "checksum_scrub".to_owned(),
        status: scrub_phase_status.to_owned(),
        detail: scrub_phase_detail,
    });

    let repair_status = if flags.repair() {
        if repair_coordination.output.is_blocked() {
            phases.push(FsckPhaseOutput {
                phase: "repair".to_owned(),
                status: "error".to_owned(),
                detail: repair_coordination.output.detail.clone(),
            });
            FsckRepairStatus::RequestedNotPerformed
        } else if let Some(recovery) = &ext4_recovery {
            phases.push(FsckPhaseOutput {
                phase: "repair".to_owned(),
                status: "ok".to_owned(),
                detail: ext4_recovery_detail(recovery),
            });
            FsckRepairStatus::RequestedPerformed
        } else if matches!(flavor, FsFlavor::Btrfs(_)) {
            let (status, detail, performed) = if btrfs_repair_performed {
                (
                    "ok".to_owned(),
                    btrfs_repair_detail.unwrap_or_else(|| {
                        "restored primary btrfs superblock from backup mirror".to_owned()
                    }),
                    true,
                )
            } else if btrfs_repair_attempted {
                (
                    "error".to_owned(),
                    btrfs_repair_detail.unwrap_or_else(|| {
                        "btrfs superblock corruption detected but recovery did not complete"
                            .to_owned()
                    }),
                    false,
                )
            } else {
                (
                    "skipped".to_owned(),
                    btrfs_repair_detail.unwrap_or_else(|| {
                        "repair requested but no primary btrfs superblock corruption was detected in scope"
                            .to_owned()
                    }),
                    false,
                )
            };
            phases.push(FsckPhaseOutput {
                phase: "repair".to_owned(),
                status,
                detail,
            });
            if performed {
                FsckRepairStatus::RequestedPerformed
            } else {
                FsckRepairStatus::RequestedNotPerformed
            }
        } else {
            phases.push(FsckPhaseOutput {
                phase: "repair".to_owned(),
                status: "skipped".to_owned(),
                detail:
                    "repair requested but no write-side workflow is available for this filesystem flavor"
                        .to_owned(),
            });
            FsckRepairStatus::RequestedNotPerformed
        }
    } else {
        FsckRepairStatus::NotRequested
    };

    limitations.push(format!(
        "fsck currently covers superblock/group-descriptor validation plus block-level scrub checks (block_size={block_size})"
    ));

    let outcome = if scrub.error_or_higher > 0 {
        FsckOutcome::ErrorsFound
    } else {
        FsckOutcome::Clean
    };
    let exit_code = if repair_coordination.output.is_blocked() {
        2
    } else {
        match outcome {
            FsckOutcome::Clean => 0,
            FsckOutcome::ErrorsFound => 1,
        }
    };

    Ok(FsckOutput {
        filesystem: filesystem_name(&flavor).to_owned(),
        scope,
        phases,
        scrub,
        repair_status,
        repair_coordination: flags.repair().then_some(repair_coordination.output),
        ext4_recovery,
        outcome,
        exit_code,
        limitations,
    })
}

fn validate_ext4_group_descriptors(
    reader: &Ext4ImageReader,
    image: &[u8],
    only_group: Option<u32>,
) -> FsckPhaseOutput {
    if let Some(group) = only_group {
        return match reader.read_group_desc(image, GroupNumber(group)) {
            Ok(_) => FsckPhaseOutput {
                phase: "group_descriptor_validation".to_owned(),
                status: "ok".to_owned(),
                detail: format!("validated ext4 group descriptor {group}"),
            },
            Err(err) => FsckPhaseOutput {
                phase: "group_descriptor_validation".to_owned(),
                status: "error".to_owned(),
                detail: format!("group {group} failed validation: {err}"),
            },
        };
    }

    let groups = reader.sb.groups_count();
    for group in 0..groups {
        if let Err(err) = reader.read_group_desc(image, GroupNumber(group)) {
            return FsckPhaseOutput {
                phase: "group_descriptor_validation".to_owned(),
                status: "error".to_owned(),
                detail: format!("group {group} failed validation: {err}"),
            };
        }
    }

    FsckPhaseOutput {
        phase: "group_descriptor_validation".to_owned(),
        status: "ok".to_owned(),
        detail: format!("validated {groups} ext4 group descriptors"),
    }
}

pub fn ext4_group_scrub_scope(sb: &Ext4Superblock, group: u32) -> Result<(BlockNumber, u64)> {
    let groups = sb.groups_count();
    if group >= groups {
        bail!("block group {group} out of range (groups_count={groups})");
    }

    let start = u64::from(sb.first_data_block)
        .saturating_add(u64::from(group).saturating_mul(u64::from(sb.blocks_per_group)));
    let end_exclusive = start
        .saturating_add(u64::from(sb.blocks_per_group))
        .min(sb.blocks_count);
    let count = end_exclusive.saturating_sub(start);

    Ok((BlockNumber(start), count))
}

fn scrub_report_to_phase(report: &ScrubReport) -> FsckScrubOutput {
    FsckScrubOutput {
        scanned: report.blocks_scanned,
        corrupt: report.blocks_corrupt,
        error_or_higher: count_blocks_at_severity_or_higher(report, Severity::Error),
        io_error: report.blocks_io_error,
    }
}

pub fn run_ext4_mount_recovery(path: &PathBuf) -> Result<Ext4RecoveryOutput> {
    let cx = cli_cx();
    let open = OpenFs::open_with_options(
        &cx,
        path,
        &OpenOptions {
            skip_validation: false,
            ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
            ..OpenOptions::default()
        },
    )
    .with_context(|| {
        format!(
            "failed to open ext4 image for repair workflow: {}",
            path.display()
        )
    })?;

    let outcome = open.crash_recovery().cloned().ok_or_else(|| {
        anyhow::anyhow!("ext4 repair workflow expected crash recovery outcome but found none")
    })?;
    Ok(Ext4RecoveryOutput {
        recovery_performed: outcome.recovery_performed(),
        crash_recovery: outcome,
    })
}

#[must_use]
pub fn ext4_recovery_detail(recovery: &Ext4RecoveryOutput) -> String {
    format!(
        "recovery_performed={} clean={} had_errors={} had_orphans={} journal_txns_replayed={} journal_blocks_replayed={}",
        recovery.recovery_performed,
        recovery.crash_recovery.was_clean,
        recovery.crash_recovery.had_errors,
        recovery.crash_recovery.had_orphans,
        recovery.crash_recovery.journal_txns_replayed,
        recovery.crash_recovery.journal_blocks_replayed
    )
}

fn print_fsck_output(json: bool, output: &FsckOutput) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(output).context("serialize fsck output")?
        );
        return Ok(());
    }

    println!("FrankenFS FSCK");
    println!("filesystem: {}", output.filesystem);
    match &output.scope {
        FsckScopeOutput::Full => println!("scope: full"),
        FsckScopeOutput::Ext4BlockGroup {
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
        FsckScopeOutput::BtrfsBlockGroup {
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
    println!("phases:");
    for phase in &output.phases {
        println!(
            "  - {}: {} ({})",
            phase.phase.replace('_', " "),
            phase.status,
            phase.detail
        );
    }
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
    println!("repair_status: {:?}", output.repair_status);
    if let Some(coordination) = &output.repair_coordination {
        println!(
            "repair_coordination: status={:?} policy={} operation_id={} scenario_id={}",
            coordination.status,
            coordination.policy,
            coordination.operation_id,
            coordination.scenario_id
        );
        println!(
            "repair_coordination_detail: {} (coordination_file={}, local_host={})",
            coordination.detail, coordination.coordination_file, coordination.local_host
        );
        if let Some(owner_host) = &coordination.owner_host {
            println!("repair_coordination_owner_host: {owner_host}");
        }
        if let Some(owner_process_id) = coordination.owner_process_id {
            println!("repair_coordination_owner_process_id: {owner_process_id}");
        }
        if let Some(error_class) = &coordination.error_class {
            println!("repair_coordination_error_class: {error_class}");
        }
    }
    println!("outcome: {:?}", output.outcome);
    println!("exit_code: {}", output.exit_code);
    if !output.limitations.is_empty() {
        println!("limitations:");
        for limitation in &output.limitations {
            println!("  - {limitation}");
        }
    }

    Ok(())
}

fn parity(json: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::parity",
        "parity",
        output_json = json
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::parity", "parity_start");

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

    info!(
        target: "ffs::cli::parity",
        overall_coverage_percent = report.overall_coverage_percent,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "parity_complete"
    );

    Ok(())
}

// ── Mkfs command ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct MkfsOutput {
    path: String,
    size_bytes: u64,
    block_size: u32,
    label: String,
    block_count: u64,
    groups_count: u32,
    inodes_count: u32,
}

fn mkfs_cmd(output: &Path, size_mb: u64, block_size: u32, label: &str, json: bool) -> Result<()> {
    mkfs_cmd_with_program(
        output,
        size_mb,
        block_size,
        label,
        json,
        Path::new("mkfs.ext4"),
    )
}

fn emit_mkfs_output(result: &MkfsOutput, size_mb: u64, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(result).context("serialize mkfs output")?
        );
    } else {
        println!("FrankenFS mkfs");
        println!("  Path:        {}", result.path);
        println!(
            "  Size:        {} MiB ({} bytes)",
            size_mb, result.size_bytes
        );
        println!("  Block size:  {}", result.block_size);
        println!("  Label:       {}", result.label);
        println!("  Blocks:      {}", result.block_count);
        println!("  Groups:      {}", result.groups_count);
        println!("  Inodes:      {}", result.inodes_count);
        println!("Image created successfully.");
    }

    Ok(())
}

fn validate_mkfs_params(output: &Path, size_mb: u64, block_size: u32) -> Result<u64> {
    if ![1024, 2048, 4096].contains(&block_size) {
        bail!("block_size must be 1024, 2048, or 4096 (got {block_size})");
    }
    if size_mb == 0 {
        bail!("size_mb must be > 0");
    }
    let output_str = output.as_os_str().to_string_lossy();
    if output_str.starts_with('-') {
        bail!("output path must not start with '-' (use ./ or an absolute path): {output_str}");
    }
    size_mb
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow::anyhow!("size_mb too large to represent bytes"))
}

fn create_sparse_image(output: &Path, size_bytes: u64) -> Result<()> {
    let f = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
    {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!("output file already exists: {}", output.display());
        }
        Err(err) => {
            return Err(err).with_context(|| format!("create image file {}", output.display()));
        }
    };
    f.set_len(size_bytes)
        .with_context(|| format!("set image size to {size_bytes}"))?;
    drop(f);
    Ok(())
}

fn run_mkfs_program(
    mkfs_program: &Path,
    output: &Path,
    block_size: u32,
    label: &str,
) -> Result<()> {
    let mkfs_output = std::process::Command::new(mkfs_program)
        .arg("-F")
        .arg("-b")
        .arg(block_size.to_string())
        .arg("-L")
        .arg(label)
        .arg(output)
        .output()
        .with_context(|| {
            format!(
                "failed to run {} for {} (output image preserved at {})",
                mkfs_program.display(),
                output.display(),
                output.display()
            )
        })?;

    if !mkfs_output.status.success() {
        let stderr = String::from_utf8_lossy(&mkfs_output.stderr);
        let stderr = stderr.trim();
        let status = mkfs_output.status;
        let failure_detail = if stderr.is_empty() {
            format!("exit status {status}")
        } else {
            format!("exit status {status}: {stderr}")
        };
        bail!(
            "mkfs.ext4 failed for {}. Preserved partial image at {}. {}",
            output.display(),
            output.display(),
            failure_detail
        );
    }
    Ok(())
}

fn mkfs_cmd_with_program(
    output: &Path,
    size_mb: u64,
    block_size: u32,
    label: &str,
    json: bool,
    mkfs_program: &Path,
) -> Result<()> {
    let size_bytes = validate_mkfs_params(output, size_mb, block_size)?;
    create_sparse_image(output, size_bytes)?;
    run_mkfs_program(mkfs_program, output, block_size, label)?;

    // Verify the new image by opening it with FrankenFS.
    let cx = cli_cx();
    let fs = OpenFs::open(&cx, output)
        .with_context(|| format!("verify new image at {}", output.display()))?;

    let (result, actual_label) = match &fs.flavor {
        FsFlavor::Ext4(sb) => {
            let actual_label = sb.volume_name.clone();
            (
                MkfsOutput {
                    path: output.display().to_string(),
                    size_bytes,
                    block_size: sb.block_size,
                    label: actual_label.clone(),
                    block_count: sb.blocks_count,
                    groups_count: sb.groups_count(),
                    inodes_count: sb.inodes_count,
                },
                actual_label,
            )
        }
        FsFlavor::Btrfs(_) => {
            bail!(
                "mkfs.ext4 verification opened {} as btrfs; refusing to continue",
                output.display()
            );
        }
    };

    if actual_label != label {
        warn!(
            target: "ffs::cli",
            requested_label = %label,
            resolved_label = %actual_label,
            "mkfs label adjusted by mkfs.ext4"
        );
    }

    emit_mkfs_output(&result, size_mb, json)?;

    info!(
        target: "ffs::cli",
        path = %output.display(),
        size_bytes,
        block_size,
        label = %actual_label,
        "mkfs_complete"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        BTRFS_FS_TREE_OBJECTID, BTRFS_ITEM_INODE_ITEM, BTRFS_ITEM_ROOT_ITEM, BtrfsInodeItem,
        BtrfsMountSelection, Cli, Command, DumpCommand, Ext4DataErrPolicy, Ext4JournalReplayMode,
        Ext4RecoveryOutput, FsckCommandOptions, FsckFlags, InfoCommandOptions, InfoSections,
        LogFormat, MAX_EXT4_INFO_GROUPS, MountAccessMode, MountAdaptiveRuntimeConfig,
        MountAdaptiveRuntimeSummaryConfig, MountBackgroundRepairMode, MountBackgroundScrubConfig,
        MountBackgroundScrubMode, MountBackgroundScrubRequest, MountCmdOptions, MountConsoleConfig,
        MountMode, MountRuntimeConfig, MountRuntimeMode, MountWritebackCacheConfig,
        RepairCommandOptions, RepairFlags, WRITEBACK_CACHE_KILL_SWITCH_ENV,
        btrfs_checksum_type_name, btrfs_chunk_type_flag_names, build_ext4_group_info,
        build_fsck_output, build_info_output, build_mount_open_options,
        choose_btrfs_scrub_block_size, count_blocks_at_severity_or_higher,
        ext4_appears_clean_state, ext4_group_flag_names, ext4_group_scrub_scope,
        ext4_mount_replay_mode, ext4_recovery_detail, ext4_state_flag_names, filesystem_name,
        format_ext4_quota_inodes, format_ratio_thousandths, format_uuid,
        log_mount_runtime_rejected, log_mount_runtime_selected, mount_cmd, mount_operation_id,
        open_filesystem_for_mount, parse_btrfs_mount_selection, read_ext4_group_desc_from_path,
        read_ext4_inode_from_path, read_file_region, start_mount_background_scrub,
        summarize_repair_staleness, unavailable_repair_info,
        validate_mount_adaptive_runtime_request_with_config,
        validate_mount_writeback_cache_request,
    };
    use crate::cmd_evidence::{
        EvidenceHistogramBucket, EvidenceHistogramSnapshot, EvidenceMvccRuntimeMetricsSnapshot,
        load_evidence_records, load_metrics_report_for_test,
    };
    use crate::cmd_repair::{
        Ext4RepairStaleness, MAX_EXT4_REPAIR_GROUP_SPECS, REPAIR_COORDINATION_SCENARIO_REPAIR,
        RepairCoordinationStatus, btrfs_super_mirror_offsets, build_btrfs_repair_group_spec,
        build_ext4_repair_group_specs, build_repair_output, coordinate_repair_write_access,
        merge_scrub_reports, normalize_btrfs_superblock_as_primary, partition_scrub_range,
        repair_coordination_record_path, repair_worker_limit, select_btrfs_repair_groups,
        select_ext4_repair_groups,
    };
    use clap::Parser;
    use ffs_block::CacheRuntimeMetricsSnapshot;
    use ffs_harness::adaptive_runtime_manifest::{
        AdaptiveRuntimeCleanupStatus, AdaptiveRuntimeDegradationThresholds,
        AdaptiveRuntimeEvidenceManifest, AdaptiveRuntimeEvidenceValidationConfig,
        AdaptiveRuntimeFuseCapabilityState, AdaptiveRuntimeFuseCapabilitySummary,
        AdaptiveRuntimeHostFingerprint, AdaptiveRuntimeHostLane, AdaptiveRuntimeMode,
        AdaptiveRuntimePerCoreConfig, AdaptiveRuntimeReleaseClaimState,
        AdaptiveRuntimeResourceCaps,
    };
    use ffs_harness::artifact_manifest::parse_manifest_timestamp_epoch_days;
    use ffs_repair::evidence::{EvidenceEventType, EvidenceRecord};
    use ffs_repair::ownership::CoordinationRecord;
    use ffs_repair::pipeline::RepairRuntimeMetricsSnapshot;
    use ffs_repair::scrub::{CorruptionKind, ScrubFinding, ScrubReport, Severity};
    use ffs_types::BlockNumber;
    use serde_json::Value;
    use std::io::{self, Seek, SeekFrom, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn cli_parses_read_pool_cutover_gate() {
        let cli = Cli::try_parse_from([
            "ffs",
            "read-pool-cutover-gate",
            "/tmp/ext4.img",
            "--blocks",
            "4096",
            "--rounds",
            "17",
        ])
        .expect("read-pool cutover gate should parse");

        match cli.command {
            Command::ReadPoolCutoverGate {
                fixture,
                blocks,
                rounds,
            } => {
                assert_eq!(fixture, PathBuf::from("/tmp/ext4.img"));
                assert_eq!(blocks, 4096);
                assert_eq!(rounds, 17);
            }
            other => assert!(
                matches!(other, Command::ReadPoolCutoverGate { .. }),
                "expected read-pool cutover gate"
            ),
        }
    }
    use tracing::{info, info_span};
    use tracing_subscriber::fmt::MakeWriter;

    fn test_mount_background_scrub_disabled() -> MountBackgroundScrubConfig {
        MountBackgroundScrubConfig {
            enabled: false,
            explicit: true,
            repair_writes_enabled: false,
            interval_secs: super::DEFAULT_MOUNT_BACKGROUND_SCRUB_INTERVAL_SECS,
            ledger_path: None,
        }
    }

    fn test_mount_cmd_options(
        read_write: bool,
        writeback_cache: MountWritebackCacheConfig,
    ) -> MountCmdOptions {
        MountCmdOptions {
            allow_other: false,
            read_write,
            mount_mode: MountMode::Compat,
            btrfs_mount_selection: BtrfsMountSelection::DefaultRoot,
            ext4_data_err_policy: Ext4DataErrPolicy::Ignore,
            ext4_verify_journal_checksums: true,
            btrfs_rw_ephemeral_ok: false,
            runtime: MountRuntimeConfig {
                mode: MountRuntimeMode::Standard,
                managed_unmount_timeout_secs: None,
            },
            adaptive_runtime: MountAdaptiveRuntimeConfig::disabled(),
            adaptive_runtime_summary: MountAdaptiveRuntimeSummaryConfig::disabled(),
            background_scrub: test_mount_background_scrub_disabled(),
            writeback_cache,
            console: MountConsoleConfig::default(),
        }
    }

    fn test_mount_runtime_config(mode: MountRuntimeMode) -> MountRuntimeConfig {
        MountRuntimeConfig {
            mode,
            managed_unmount_timeout_secs: None,
        }
    }

    fn adaptive_runtime_test_validation_config() -> AdaptiveRuntimeEvidenceValidationConfig {
        AdaptiveRuntimeEvidenceValidationConfig {
            reference_epoch_days: parse_manifest_timestamp_epoch_days("2026-05-07T12:00:00Z"),
            current_git_sha: None,
        }
    }

    fn adaptive_runtime_fixture(
        runtime_mode: AdaptiveRuntimeMode,
        read_write: bool,
        release_claim_state: AdaptiveRuntimeReleaseClaimState,
        expires_at: &str,
    ) -> AdaptiveRuntimeEvidenceManifest {
        let (lane, cpu_count, ram_bytes, numa_nodes, fuse_state) = match release_claim_state {
            AdaptiveRuntimeReleaseClaimState::AcceptedLargeHost => (
                AdaptiveRuntimeHostLane::PermissionedLargeHost,
                96,
                512_u64 * 1024 * 1024 * 1024,
                2,
                AdaptiveRuntimeFuseCapabilityState::Available,
            ),
            AdaptiveRuntimeReleaseClaimState::SmallHostSmoke => (
                AdaptiveRuntimeHostLane::LocalSmoke,
                8,
                32_u64 * 1024 * 1024 * 1024,
                1,
                AdaptiveRuntimeFuseCapabilityState::Available,
            ),
            AdaptiveRuntimeReleaseClaimState::CapabilityDowngradedSmoke => (
                AdaptiveRuntimeHostLane::CapabilityDowngraded,
                96,
                512_u64 * 1024 * 1024 * 1024,
                2,
                AdaptiveRuntimeFuseCapabilityState::PermissionDenied,
            ),
        };
        let per_core_enabled = matches!(runtime_mode, AdaptiveRuntimeMode::PerCore);

        AdaptiveRuntimeEvidenceManifest {
            manifest_version: 1,
            scenario_id: "adaptive_runtime_accepted_large_host".to_owned(),
            run_id: "adaptive-runtime-run-20260507T000000Z".to_owned(),
            runtime_mode,
            read_write,
            host_fingerprint: AdaptiveRuntimeHostFingerprint {
                host_fingerprint: "permissioned-96c-512gb-2numa".to_owned(),
                cpu_count,
                ram_bytes,
                numa_nodes,
                kernel: "Linux 6.17.0-14-generic x86_64".to_owned(),
                lane,
            },
            fuse_capability_summary: AdaptiveRuntimeFuseCapabilitySummary {
                state: fuse_state,
                detail: "/dev/fuse and fusermount3 probed for adaptive runtime".to_owned(),
            },
            backpressure_policy_id: "adaptive-runtime-default-v1".to_owned(),
            degradation_thresholds: AdaptiveRuntimeDegradationThresholds {
                throttle_dirty_ratio: 0.70,
                shed_dirty_ratio: 0.85,
                emergency_dirty_ratio: 0.95,
            },
            per_core_config: AdaptiveRuntimePerCoreConfig {
                enabled: per_core_enabled,
                worker_count: if per_core_enabled { 64 } else { 0 },
                queue_policy: "metadata/write/repair queues isolated by runtime lane".to_owned(),
                work_stealing: per_core_enabled,
            },
            resource_caps: AdaptiveRuntimeResourceCaps {
                max_duration_secs: 900,
                max_threads: 96,
                max_memory_bytes: 128_u64 * 1024 * 1024 * 1024,
                max_temp_bytes: 64_u64 * 1024 * 1024 * 1024,
                max_queue_depth: 4096,
            },
            artifact_paths: vec![
                "artifacts/adaptive-runtime/report.json".to_owned(),
                "artifacts/adaptive-runtime/summary.md".to_owned(),
            ],
            raw_stdout_path: "artifacts/adaptive-runtime/stdout.log".to_owned(),
            raw_stderr_path: "artifacts/adaptive-runtime/stderr.log".to_owned(),
            raw_log_paths: vec!["artifacts/adaptive-runtime/structured.jsonl".to_owned()],
            cleanup_status: AdaptiveRuntimeCleanupStatus::Clean,
            controlling_ack_env: "FFS_ADAPTIVE_RUNTIME_REAL_RUN_ACK".to_owned(),
            controlling_ack_value: "adaptive-runtime-may-mount-and-generate-load".to_owned(),
            release_claim_state,
            generated_at: "2026-05-07T00:00:00Z".to_owned(),
            expires_at: expires_at.to_owned(),
            git_sha: "c87266f2".to_owned(),
            reproduction_command: "cargo run -p ffs-harness -- validate-adaptive-runtime-manifest"
                .to_owned(),
        }
    }

    fn with_adaptive_runtime_manifest_path<T>(
        manifest: &AdaptiveRuntimeEvidenceManifest,
        f: impl FnOnce(PathBuf) -> T,
    ) -> T {
        let json = serde_json::to_vec(manifest).expect("serialize adaptive runtime manifest");
        with_temp_image_path(&json, f)
    }

    #[test]
    fn adaptive_runtime_config_default_is_disabled() {
        let plan = validate_mount_adaptive_runtime_request_with_config(
            &MountAdaptiveRuntimeConfig::disabled(),
            test_mount_runtime_config(MountRuntimeMode::Standard),
            false,
            "test-operation",
            "cli_mount_runtime_standard_ro",
            &adaptive_runtime_test_validation_config(),
        )
        .expect("disabled adaptive runtime should be a no-op");

        assert!(plan.is_none());
    }

    #[test]
    fn adaptive_runtime_manifest_without_opt_in_is_rejected() {
        let err = validate_mount_adaptive_runtime_request_with_config(
            &MountAdaptiveRuntimeConfig::from_cli(false, Some(PathBuf::from("manifest.json"))),
            test_mount_runtime_config(MountRuntimeMode::Managed),
            false,
            "test-operation",
            "cli_mount_runtime_managed_ro",
            &adaptive_runtime_test_validation_config(),
        )
        .err()
        .expect("manifest path without opt-in should reject");

        assert!(format!("{err:#}").contains("manifest_without_opt_in"));
    }

    #[test]
    fn cli_parses_mount_adaptive_runtime_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "mount",
            "--runtime-mode",
            "per-core",
            "--rw",
            "--adaptive-runtime",
            "--adaptive-runtime-manifest",
            "manifest.json",
            "--adaptive-runtime-summary-json",
            "shutdown.json",
            "--adaptive-runtime-summary-md",
            "shutdown.md",
            "/tmp/fs.img",
            "/tmp/mnt",
        ])
        .expect("mount adaptive runtime flags should parse");

        match cli.command {
            Command::Mount {
                runtime_mode,
                rw,
                adaptive_runtime,
                adaptive_runtime_manifest,
                adaptive_runtime_summary_json,
                adaptive_runtime_summary_md,
                ..
            } => {
                assert_eq!(runtime_mode, MountRuntimeMode::PerCore);
                assert!(rw);
                assert!(adaptive_runtime);
                assert_eq!(
                    adaptive_runtime_manifest,
                    Some(PathBuf::from("manifest.json"))
                );
                assert_eq!(
                    adaptive_runtime_summary_json,
                    Some(PathBuf::from("shutdown.json"))
                );
                assert_eq!(
                    adaptive_runtime_summary_md,
                    Some(PathBuf::from("shutdown.md"))
                );
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn mount_adaptive_runtime_rejects_standard_mode() {
        let err = validate_mount_adaptive_runtime_request_with_config(
            &MountAdaptiveRuntimeConfig::from_cli(true, Some(PathBuf::from("manifest.json"))),
            test_mount_runtime_config(MountRuntimeMode::Standard),
            true,
            "test-operation",
            "cli_mount_runtime_standard_rw",
            &adaptive_runtime_test_validation_config(),
        )
        .err()
        .expect("standard runtime must reject adaptive controls");

        assert!(format!("{err:#}").contains("unsupported_runtime_mode"));
    }

    #[test]
    fn mount_adaptive_runtime_rejects_missing_manifest() {
        let err = validate_mount_adaptive_runtime_request_with_config(
            &MountAdaptiveRuntimeConfig::from_cli(true, None),
            test_mount_runtime_config(MountRuntimeMode::PerCore),
            true,
            "test-operation",
            "cli_mount_runtime_per_core_rw",
            &adaptive_runtime_test_validation_config(),
        )
        .err()
        .expect("adaptive runtime requires a manifest");

        assert!(format!("{err:#}").contains("missing_manifest"));
    }

    #[test]
    fn mount_adaptive_runtime_rejects_malformed_manifest() {
        with_temp_image_path(b"{not-json", |path| {
            let err = validate_mount_adaptive_runtime_request_with_config(
                &MountAdaptiveRuntimeConfig::from_cli(true, Some(path)),
                test_mount_runtime_config(MountRuntimeMode::PerCore),
                true,
                "test-operation",
                "cli_mount_runtime_per_core_rw",
                &adaptive_runtime_test_validation_config(),
            )
            .err()
            .expect("malformed manifest should reject");

            assert!(format!("{err:#}").contains("manifest_invalid"));
        });
    }

    #[test]
    fn mount_adaptive_runtime_rejects_stale_manifest() {
        let manifest = adaptive_runtime_fixture(
            AdaptiveRuntimeMode::PerCore,
            true,
            AdaptiveRuntimeReleaseClaimState::AcceptedLargeHost,
            "2026-05-01T00:00:00Z",
        );

        with_adaptive_runtime_manifest_path(&manifest, |path| {
            let err = validate_mount_adaptive_runtime_request_with_config(
                &MountAdaptiveRuntimeConfig::from_cli(true, Some(path)),
                test_mount_runtime_config(MountRuntimeMode::PerCore),
                true,
                "test-operation",
                "cli_mount_runtime_per_core_rw",
                &adaptive_runtime_test_validation_config(),
            )
            .err()
            .expect("stale manifest should reject");

            assert!(format!("{err:#}").contains("stale_manifest"));
        });
    }

    #[test]
    fn mount_adaptive_runtime_rejects_small_host_smoke_manifest() {
        let manifest = adaptive_runtime_fixture(
            AdaptiveRuntimeMode::PerCore,
            true,
            AdaptiveRuntimeReleaseClaimState::SmallHostSmoke,
            "2026-05-08T00:00:00Z",
        );

        with_adaptive_runtime_manifest_path(&manifest, |path| {
            let err = validate_mount_adaptive_runtime_request_with_config(
                &MountAdaptiveRuntimeConfig::from_cli(true, Some(path)),
                test_mount_runtime_config(MountRuntimeMode::PerCore),
                true,
                "test-operation",
                "cli_mount_runtime_per_core_rw",
                &adaptive_runtime_test_validation_config(),
            )
            .err()
            .expect("small host smoke evidence should reject runtime controls");

            assert!(format!("{err:#}").contains("small_host_smoke"));
        });
    }

    #[test]
    fn mount_adaptive_runtime_rejects_capability_downgraded_smoke_manifest() {
        let manifest = adaptive_runtime_fixture(
            AdaptiveRuntimeMode::PerCore,
            true,
            AdaptiveRuntimeReleaseClaimState::CapabilityDowngradedSmoke,
            "2026-05-08T00:00:00Z",
        );

        with_adaptive_runtime_manifest_path(&manifest, |path| {
            let err = validate_mount_adaptive_runtime_request_with_config(
                &MountAdaptiveRuntimeConfig::from_cli(true, Some(path)),
                test_mount_runtime_config(MountRuntimeMode::PerCore),
                true,
                "test-operation",
                "cli_mount_runtime_per_core_rw",
                &adaptive_runtime_test_validation_config(),
            )
            .err()
            .expect("capability downgraded smoke evidence should reject runtime controls");

            assert!(format!("{err:#}").contains("capability_downgraded_smoke"));
        });
    }

    #[test]
    fn mount_adaptive_runtime_accepts_large_host_manifest() {
        let manifest = adaptive_runtime_fixture(
            AdaptiveRuntimeMode::PerCore,
            true,
            AdaptiveRuntimeReleaseClaimState::AcceptedLargeHost,
            "2026-05-08T00:00:00Z",
        );

        with_adaptive_runtime_manifest_path(&manifest, |path| {
            let plan = validate_mount_adaptive_runtime_request_with_config(
                &MountAdaptiveRuntimeConfig::from_cli(true, Some(path.clone())),
                test_mount_runtime_config(MountRuntimeMode::PerCore),
                true,
                "test-operation",
                "cli_mount_runtime_per_core_rw",
                &adaptive_runtime_test_validation_config(),
            )
            .expect("accepted large-host evidence should validate")
            .expect("accepted large-host evidence should build a runtime plan");

            assert_eq!(plan.manifest_path, path);
            assert_eq!(
                plan.manifest_scenario_id,
                "adaptive_runtime_accepted_large_host"
            );
            assert_eq!(plan.run_id, "adaptive-runtime-run-20260507T000000Z");
            assert_eq!(plan.backpressure_policy_id, "adaptive-runtime-default-v1");
            assert_eq!(
                plan.gate.check(ffs_core::RequestOp::Read),
                ffs_core::BackpressureDecision::Proceed
            );
        });
    }

    #[test]
    fn mount_adaptive_runtime_shutdown_summary_reports_per_core_backpressure_evidence() {
        let manifest = adaptive_runtime_fixture(
            AdaptiveRuntimeMode::PerCore,
            true,
            AdaptiveRuntimeReleaseClaimState::AcceptedLargeHost,
            "2026-05-08T00:00:00Z",
        );

        with_adaptive_runtime_manifest_path(&manifest, |path| {
            let plan = validate_mount_adaptive_runtime_request_with_config(
                &MountAdaptiveRuntimeConfig::from_cli(true, Some(path)),
                test_mount_runtime_config(MountRuntimeMode::PerCore),
                true,
                "mount-op",
                "cli_mount_runtime_per_core_rw",
                &adaptive_runtime_test_validation_config(),
            )
            .expect("accepted large-host evidence should validate")
            .expect("accepted large-host evidence should build a runtime plan");
            let summary_config = super::MountAdaptiveRuntimeSummaryConfig::from_cli(
                Some(PathBuf::from("artifacts/out/shutdown.json")),
                Some(PathBuf::from("artifacts/out/shutdown.md")),
            );
            let observation = super::MountAdaptiveRuntimeShutdownObservation {
                metrics: ffs_fuse::MetricsSnapshot {
                    requests_total: 13,
                    requests_ok: 12,
                    requests_err: 1,
                    bytes_read: 4096,
                    requests_throttled: 4,
                    requests_shed: 1,
                },
                worker_count: 2,
                per_core: Some(super::MountAdaptiveRuntimePerCoreObservation {
                    total_cache_hits: 7,
                    total_cache_misses: 6,
                    imbalance_ratio: 1.6,
                    per_core_distribution: vec![
                        super::MountAdaptiveRuntimeCoreRequestSummary {
                            core_id: 0,
                            requests: 5,
                            cache_hits: 4,
                            cache_misses: 1,
                        },
                        super::MountAdaptiveRuntimeCoreRequestSummary {
                            core_id: 1,
                            requests: 8,
                            cache_hits: 3,
                            cache_misses: 5,
                        },
                    ],
                }),
            };

            let summary = super::build_mount_adaptive_runtime_shutdown_summary(
                super::MountAdaptiveRuntimeShutdownContext {
                    image_path: Path::new("/tmp/fs.img"),
                    mountpoint: Path::new("/tmp/mnt"),
                    runtime: test_mount_runtime_config(MountRuntimeMode::PerCore),
                    read_write: true,
                    operation_id: "mount-op",
                    cli_scenario_id: "cli_mount_runtime_per_core_rw",
                    plan: Some(&plan),
                    summary_config: &summary_config,
                },
                &observation,
            );
            let json = serde_json::to_value(&summary).expect("summary serializes");

            assert!(summary.adaptive_runtime_enabled);
            assert_eq!(summary.runtime_mode, "per-core");
            assert_eq!(summary.scenario_id, "adaptive_runtime_accepted_large_host");
            assert_eq!(summary.cli_scenario_id, "cli_mount_runtime_per_core_rw");
            assert_eq!(summary.release_claim_state, "accepted_large_host");
            assert_eq!(
                summary.backpressure_policy_id.as_deref(),
                Some("adaptive-runtime-default-v1")
            );
            assert_eq!(summary.total_requests, 13);
            assert_eq!(summary.requests_throttled, 4);
            assert_eq!(summary.requests_shed, 1);
            assert_eq!(summary.cache_hits, Some(7));
            assert_eq!(summary.cache_misses, Some(6));
            assert_eq!(summary.worker_count, 2);
            assert_eq!(
                json["per_core_request_distribution"][1]["requests"],
                serde_json::json!(8)
            );
            assert_eq!(
                json["raw_log_paths"][0],
                serde_json::json!("artifacts/adaptive-runtime/structured.jsonl")
            );
        });
    }

    #[test]
    fn mount_adaptive_runtime_shutdown_markdown_is_stable() {
        let summary = super::MountAdaptiveRuntimeShutdownSummary {
            schema_version: 1,
            adaptive_runtime_enabled: true,
            runtime_mode: "per-core".to_owned(),
            read_write: true,
            run_id: "adaptive-runtime-run-20260507T000000Z".to_owned(),
            scenario_id: "adaptive_runtime_accepted_large_host".to_owned(),
            cli_scenario_id: "cli_mount_runtime_per_core_rw".to_owned(),
            release_claim_state: "accepted_large_host".to_owned(),
            degradation_level_transitions: super::MountAdaptiveRuntimeDegradationTransitionLedger {
                current_level: "normal".to_owned(),
                transition_count: 0,
                transitions: Vec::new(),
            },
            backpressure_policy_id: Some("adaptive-runtime-default-v1".to_owned()),
            requests_throttled: 4,
            requests_shed: 1,
            total_requests: 13,
            cache_hits: Some(7),
            cache_misses: Some(6),
            per_core_request_distribution: vec![
                super::MountAdaptiveRuntimeCoreRequestSummary {
                    core_id: 0,
                    requests: 5,
                    cache_hits: 4,
                    cache_misses: 1,
                },
                super::MountAdaptiveRuntimeCoreRequestSummary {
                    core_id: 1,
                    requests: 8,
                    cache_hits: 3,
                    cache_misses: 5,
                },
            ],
            per_core_imbalance_ratio: Some(1.6),
            worker_count: 2,
            artifact_paths: vec![
                "artifacts/adaptive-runtime/report.json".to_owned(),
                "artifacts/adaptive-runtime/summary.md".to_owned(),
            ],
            raw_stdout_path: Some("artifacts/adaptive-runtime/stdout.log".to_owned()),
            raw_stderr_path: Some("artifacts/adaptive-runtime/stderr.log".to_owned()),
            raw_log_paths: vec!["artifacts/adaptive-runtime/structured.jsonl".to_owned()],
            cleanup_status: "clean".to_owned(),
            git_sha: "c87266f2".to_owned(),
            reproduction_command: "cargo run -p ffs-harness -- validate-adaptive-runtime-manifest"
                .to_owned(),
        };

        let markdown = super::render_mount_adaptive_runtime_shutdown_markdown(&summary);

        assert_eq!(
            markdown,
            "# Adaptive Runtime Shutdown Evidence\n\n\
- Adaptive runtime enabled: `true`\n\
- Runtime mode: `per-core`\n\
- Run: `adaptive-runtime-run-20260507T000000Z`\n\
- Scenario: `adaptive_runtime_accepted_large_host`\n\
- CLI scenario: `cli_mount_runtime_per_core_rw`\n\
- Release claim: `accepted_large_host`\n\
- Git SHA: `c87266f2`\n\
- Reproduction: `cargo run -p ffs-harness -- validate-adaptive-runtime-manifest`\n\
\n\
## Backpressure\n\
\n\
- Policy: `adaptive-runtime-default-v1`\n\
- Current degradation level: `normal`\n\
- Degradation transitions observed: `0`\n\
- Requests: total=`13`, throttled=`4`, shed=`1`\n\
\n\
## Per-Core\n\
\n\
- Worker count: `2`\n\
- Cache hits/misses: `7` / `6`\n\
- Imbalance ratio: `1.600000`\n\
- Request distribution: `core0=5 (hits=4, misses=1), core1=8 (hits=3, misses=5)`\n\
\n\
## Artifacts\n\
\n\
- Artifact paths: `artifacts/adaptive-runtime/report.json`, `artifacts/adaptive-runtime/summary.md`\n\
- Raw stdout: `artifacts/adaptive-runtime/stdout.log`\n\
- Raw stderr: `artifacts/adaptive-runtime/stderr.log`\n\
- Raw logs: `artifacts/adaptive-runtime/structured.jsonl`\n\
- Cleanup: `clean`\n"
        );
    }

    #[test]
    fn mount_adaptive_runtime_shutdown_summary_reports_default_off_explicitly() {
        let observation = super::MountAdaptiveRuntimeShutdownObservation {
            metrics: ffs_fuse::MetricsSnapshot {
                requests_total: 0,
                requests_ok: 0,
                requests_err: 0,
                bytes_read: 0,
                requests_throttled: 0,
                requests_shed: 0,
            },
            worker_count: 0,
            per_core: None,
        };
        let summary_config = super::MountAdaptiveRuntimeSummaryConfig::disabled();
        let summary = super::build_mount_adaptive_runtime_shutdown_summary(
            super::MountAdaptiveRuntimeShutdownContext {
                image_path: Path::new("/tmp/fs.img"),
                mountpoint: Path::new("/tmp/mnt"),
                runtime: test_mount_runtime_config(MountRuntimeMode::Standard),
                read_write: false,
                operation_id: "mount-op",
                cli_scenario_id: "cli_mount_runtime_standard_ro",
                plan: None,
                summary_config: &summary_config,
            },
            &observation,
        );
        let json = serde_json::to_value(&summary).expect("summary serializes");

        assert!(!summary.adaptive_runtime_enabled);
        assert_eq!(summary.release_claim_state, "disabled");
        assert_eq!(
            summary.degradation_level_transitions.current_level,
            "not_applicable"
        );
        assert_eq!(summary.cache_hits, None);
        assert_eq!(summary.per_core_request_distribution, Vec::new());
        assert_eq!(json["adaptive_runtime_enabled"], serde_json::json!(false));
        assert_eq!(json["backpressure_policy_id"], Value::Null);
    }

    #[test]
    fn mount_adaptive_runtime_rejects_runtime_mode_mismatch() {
        let manifest = adaptive_runtime_fixture(
            AdaptiveRuntimeMode::PerCore,
            true,
            AdaptiveRuntimeReleaseClaimState::AcceptedLargeHost,
            "2026-05-08T00:00:00Z",
        );

        with_adaptive_runtime_manifest_path(&manifest, |path| {
            let err = validate_mount_adaptive_runtime_request_with_config(
                &MountAdaptiveRuntimeConfig::from_cli(true, Some(path)),
                test_mount_runtime_config(MountRuntimeMode::Managed),
                true,
                "test-operation",
                "cli_mount_runtime_managed_rw",
                &adaptive_runtime_test_validation_config(),
            )
            .err()
            .expect("manifest runtime mismatch should reject");

            assert!(format!("{err:#}").contains("runtime_mode_mismatch"));
        });
    }

    #[test]
    fn mount_adaptive_runtime_rejects_read_write_mismatch() {
        let manifest = adaptive_runtime_fixture(
            AdaptiveRuntimeMode::PerCore,
            true,
            AdaptiveRuntimeReleaseClaimState::AcceptedLargeHost,
            "2026-05-08T00:00:00Z",
        );

        with_adaptive_runtime_manifest_path(&manifest, |path| {
            let err = validate_mount_adaptive_runtime_request_with_config(
                &MountAdaptiveRuntimeConfig::from_cli(true, Some(path)),
                test_mount_runtime_config(MountRuntimeMode::PerCore),
                false,
                "test-operation",
                "cli_mount_runtime_per_core_ro",
                &adaptive_runtime_test_validation_config(),
            )
            .err()
            .expect("access mode mismatch should reject");

            assert!(format!("{err:#}").contains("access_mode_mismatch"));
        });
    }

    fn write_happy_writeback_artifacts(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
        write_writeback_artifacts(dir, |_| {})
    }

    fn writeback_artifact_state(id: &str) -> serde_json::Value {
        serde_json::json!({
            "artifact_id": id,
            "present": true,
            "fresh": true,
            "passed": true,
            "artifact_path": format!("artifacts/writeback-cache/{id}.json")
        })
    }

    fn happy_writeback_gate() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "gate_version": "bd-rchk0.2.2-cli-gate-v1",
            "bead_id": "bd-rchk0.2.2",
            "mount_options": {
                "raw_options": ["rw", "fsname=frankenfs", "writeback_cache"],
                "fs_name": "frankenfs",
                "allow_other": false,
                "auto_unmount": true,
                "default_permissions": true,
                "mode": "rw"
            },
            "repair_serialization_state": "rw_lane_accepted",
            "fuse_capability": {
                "probe_status": "available",
                "kernel_supports_writeback_cache": true,
                "helper_binary_present": true
            },
            "epoch_barrier_artifact": writeback_artifact_state("epoch_barrier_proof"),
            "crash_matrix_artifact": writeback_artifact_state("writeback_crash_matrix"),
            "fsync_evidence_artifact": writeback_artifact_state("fsync_fsyncdir_boundary"),
            "filesystem_flavor": "ext4",
            "operation_class": "mounted_write",
            "explicit_opt_in": true,
            "conflicting_flags": [],
            "runtime_guard": {
                "kill_switch_state": "disarmed",
                "feature_state": "accepted",
                "config_source": "cli_explicit",
                "gate_artifact_hash": "blake3:bd-rchk0.2.2-cli-gate-v1",
                "gate_fresh": true,
                "gate_age_secs": 30,
                "gate_max_age_secs": 86400,
                "host_capability_fingerprint": "linux-fuse-writeback-cache-v1",
                "lane_manifest_id": "authoritative-env-frankenfs-fuse-v1",
                "lane_manifest_path": "artifacts/qa/authoritative_environment_manifest.json",
                "lane_manifest_fresh": true,
                "lane_manifest_matches_host": true,
                "release_gate_consumer": "writeback_cache.release_gate"
            }
        })
    }

    fn happy_writeback_ordering_oracle() -> serde_json::Value {
        let invariant_evidence: Vec<_> = ["I1", "I2", "I3", "I4", "I5", "I6"]
            .into_iter()
            .map(|id| {
                serde_json::json!({
                    "id": id,
                    "supported": true,
                    "test_id": format!("writeback_ordering_{id}_test"),
                    "artifact_field": format!("ordering.{id}.artifact"),
                    "release_gate_consumer": "writeback_cache.release_gate",
                    "unsupported_rationale": ""
                })
            })
            .collect();
        serde_json::json!({
            "schema_version": 1,
            "gate_version": "bd-rchk0.2.2-ordering-v1",
            "bead_id": "bd-rchk0.2.2",
            "mount_options": {
                "raw_options": ["rw", "fsname=frankenfs", "writeback_cache"],
                "fs_name": "frankenfs",
                "allow_other": false,
                "auto_unmount": true,
                "default_permissions": true,
                "mode": "rw"
            },
            "raw_fuser_options": ["fsname=frankenfs", "subtype=ffs", "writeback_cache"],
            "dirty_page_state": "fsynced_durable",
            "metadata_state": "metadata_after_data",
            "flush_observed_non_durable": true,
            "fsync_observed_durable": true,
            "fsyncdir_observed_durable": true,
            "cancellation_state": "cancelled_before_writeback_classified",
            "unmount_state": "dirty_pages_flushed_or_rejected",
            "crash_reopen_state": "survivor_set_verified",
            "epoch_id": "epoch-0007",
            "epoch_state": "fresh",
            "repair_symbol_generation": 8,
            "repair_symbol_refresh": "refreshed_after_writeback",
            "invariant_evidence": invariant_evidence,
            "expected_ordering": ["dirty_data", "fsync", "metadata", "fsyncdir", "repair_symbol_refresh"],
            "observed_ordering": ["dirty_data", "fsync", "metadata", "fsyncdir", "repair_symbol_refresh"],
            "artifact_paths": [
                "artifacts/writeback-cache/ordering.json",
                "artifacts/writeback-cache/crash_reopen.json"
            ]
        })
    }

    const WRITEBACK_CRASH_REPLAY_REQUIRED_POINTS: &[&str] = &[
        "cp01_before_first_write",
        "cp02_after_first_write_before_flush",
        "cp03_after_flush_before_fsync",
        "cp04_after_fsync_before_metadata",
        "cp05_after_metadata_before_fsyncdir",
        "cp06_after_fsyncdir_before_unmount",
        "cp07_after_repeated_write_before_fsync",
        "cp08_after_repeated_write_fsync",
        "cp09_after_cancellation_before_writeback",
        "cp10_after_clean_unmount_before_reopen",
        "cp11_after_reopen_before_repair_refresh",
        "cp12_after_repair_refresh",
    ];

    const WRITEBACK_CRASH_REPLAY_OPERATIONS: &[(&str, &str)] = &[
        ("create", "none"),
        ("write", "kernel_writeback_cache"),
        ("flush", "non_durable"),
        ("fsync", "file_durable"),
        ("rename", "metadata_after_data"),
        ("fsyncdir", "directory_durable"),
        ("write", "repeated_write"),
        ("fsync", "last_write_durable"),
        ("cancel", "classified_before_writeback"),
        ("unmount", "dirty_pages_flushed_or_rejected"),
        ("reopen", "survivor_set_verified"),
        ("repair_refresh", "post_writeback_refresh"),
    ];

    fn writeback_crash_replay_operation_trace() -> Vec<serde_json::Value> {
        WRITEBACK_CRASH_REPLAY_OPERATIONS
            .iter()
            .enumerate()
            .map(|(index, (operation, boundary))| {
                serde_json::json!({
                    "step": index + 1,
                    "operation": operation,
                    "target": "/writeback/data.bin",
                    "durability_boundary": boundary,
                    "expected_result": "success"
                })
            })
            .collect()
    }

    fn writeback_crash_replay_points() -> Vec<serde_json::Value> {
        WRITEBACK_CRASH_REPLAY_REQUIRED_POINTS
            .iter()
            .enumerate()
            .map(|(index, crash_point_id)| {
                let step = index + 1;
                let cancellation_state = if step == 9 {
                    "cancelled_before_writeback_classified"
                } else {
                    "none"
                };
                let repeated_write_state = if step == 7 || step == 8 {
                    "last_fsynced_write_survived"
                } else {
                    "not_applicable"
                };
                serde_json::json!({
                    "crash_point_id": crash_point_id,
                    "description": format!("{crash_point_id} mounted writeback-cache crash point"),
                    "operation_step": step,
                    "expected_survivor_set": [
                        "/",
                        "/writeback",
                        "/writeback/data.bin:blake3=stable-v2"
                    ],
                    "actual_survivor_set": [
                        "/writeback/data.bin:blake3=stable-v2",
                        "/writeback",
                        "/"
                    ],
                    "fsync_observed_durable": true,
                    "fsyncdir_observed_durable": true,
                    "flush_observed_non_durable": true,
                    "metadata_after_data_observed": true,
                    "unmount_reopen_observed": true,
                    "cancellation_state": cancellation_state,
                    "repeated_write_state": repeated_write_state,
                    "replay_status": "survivor_set_verified",
                    "stdout_path": format!("artifacts/writeback-cache/crash-replay/{crash_point_id}.stdout"),
                    "stderr_path": format!("artifacts/writeback-cache/crash-replay/{crash_point_id}.stderr"),
                    "cleanup_status": "retained_for_qa"
                })
            })
            .collect()
    }

    fn happy_writeback_crash_replay_oracle() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "gate_version": "bd-rchk0.2.3-crash-replay-v1",
            "bead_id": "bd-rchk0.2.3",
            "matrix_id": "writeback_cache_crash_replay_matrix_v1",
            "mount_options": {
                "raw_options": ["rw", "fsname=frankenfs", "writeback_cache"],
                "fs_name": "frankenfs",
                "allow_other": false,
                "auto_unmount": true,
                "default_permissions": true,
                "mode": "rw"
            },
            "raw_fuser_options": ["fsname=frankenfs", "subtype=ffs", "rw", "writeback_cache"],
            "epoch_id": "epoch-writeback-crash-0001",
            "epoch_state": "fresh",
            "host_capability_fingerprint": "fuse3-writeback-cache-enabled-host",
            "lane_manifest_id": "fuse-writeback-cache-rw-lane-v1",
            "operation_trace": writeback_crash_replay_operation_trace(),
            "crash_points": writeback_crash_replay_points(),
            "unsupported_combinations": [
                {
                    "combination_id": "writeback_cache_ro_mount",
                    "rejected": true,
                    "reason": "read_only_writeback_cache",
                    "follow_up_bead": "bd-rchk0.2.4"
                }
            ],
            "artifact_paths": [
                "artifacts/writeback-cache/crash-replay/matrix.json",
                "artifacts/writeback-cache/crash-replay/results.json",
                "artifacts/writeback-cache/crash-replay/run.log"
            ]
        })
    }

    fn write_writeback_artifacts(
        dir: &Path,
        mutate_gate: impl FnOnce(&mut serde_json::Value),
    ) -> (PathBuf, PathBuf, PathBuf) {
        let gate_path = dir.join("writeback_gate.json");
        let oracle_path = dir.join("writeback_ordering_oracle.json");
        let crash_replay_path = dir.join("writeback_crash_replay_oracle.json");
        let mut gate = happy_writeback_gate();
        mutate_gate(&mut gate);
        let oracle = happy_writeback_ordering_oracle();
        let crash_replay_oracle = happy_writeback_crash_replay_oracle();
        std::fs::write(
            &gate_path,
            serde_json::to_vec_pretty(&gate).expect("serialize gate"),
        )
        .expect("write gate");
        std::fs::write(
            &oracle_path,
            serde_json::to_vec_pretty(&oracle).expect("serialize oracle"),
        )
        .expect("write oracle");
        std::fs::write(
            &crash_replay_path,
            serde_json::to_vec_pretty(&crash_replay_oracle).expect("serialize crash/replay oracle"),
        )
        .expect("write crash/replay oracle");
        (gate_path, oracle_path, crash_replay_path)
    }

    #[derive(Clone, Default)]
    struct SharedLogBuffer {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedLogBuffer {
        fn as_string(&self) -> String {
            let bytes = self.bytes.lock().expect("log buffer lock poisoned").clone();
            String::from_utf8(bytes).expect("log buffer must be utf-8")
        }
    }

    struct SharedLogWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for SharedLogWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes
                .lock()
                .expect("log buffer lock poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for SharedLogBuffer {
        type Writer = SharedLogWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            SharedLogWriter {
                bytes: Arc::clone(&self.bytes),
            }
        }
    }

    fn log_contract_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        let mutex = LOCK.get_or_init(|| std::sync::Mutex::new(()));
        mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn parse_first_json_line(buffer: &SharedLogBuffer) -> Value {
        let logs = buffer.as_string();
        let line = logs
            .lines()
            .find(|line| !line.trim().is_empty())
            .expect("expected at least one log line");
        serde_json::from_str(line).expect("line should parse as JSON")
    }

    fn parse_json_logs(buffer: &SharedLogBuffer) -> Vec<Value> {
        buffer
            .as_string()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect()
    }

    #[allow(clippy::cast_possible_truncation)]
    fn build_test_ext4_image_with_state(state: u16) -> Vec<u8> {
        const BLOCK_SIZE_LOG: u32 = 2; // 4K blocks
        let block_size = 1024_u32 << BLOCK_SIZE_LOG;
        let image_size: u32 = 128 * 1024;
        let mut image = vec![0_u8; image_size as usize];
        let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;

        // Core superblock fields needed by parser + geometry checks.
        image[sb_off + 0x38..sb_off + 0x3A]
            .copy_from_slice(&ffs_types::EXT4_SUPER_MAGIC.to_le_bytes());
        image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&BLOCK_SIZE_LOG.to_le_bytes());
        let blocks_count = image_size / block_size;
        image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
        image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes()); // inodes_count
        image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes()); // first_data_block
        image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes()); // blocks_per_group
        image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes()); // inodes_per_group
        image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size
        image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes()); // rev_level
        image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes()); // first_ino
        let filetype: u32 = 0x0002;
        let extents: u32 = 0x0040;
        image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&(filetype | extents).to_le_bytes());
        image[sb_off + 0x3A..sb_off + 0x3C].copy_from_slice(&state.to_le_bytes());

        // Minimal group descriptor so group-descriptor validation succeeds.
        let gdt_off = block_size as usize;
        image[gdt_off + 0x08..gdt_off + 0x0C].copy_from_slice(&5_u32.to_le_bytes()); // inode table block

        image
    }

    fn build_test_ext4_image_with_quota_inodes(state: u16) -> Vec<u8> {
        let mut image = build_test_ext4_image_with_state(state);
        let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;
        let ro_compat =
            ffs_ondisk::Ext4RoCompatFeatures::QUOTA.0 | ffs_ondisk::Ext4RoCompatFeatures::PROJECT.0;
        image[sb_off + 0x64..sb_off + 0x68].copy_from_slice(&ro_compat.to_le_bytes());
        image[sb_off + 0x240..sb_off + 0x244].copy_from_slice(&3_u32.to_le_bytes());
        image[sb_off + 0x244..sb_off + 0x248].copy_from_slice(&4_u32.to_le_bytes());
        image[sb_off + 0x26C..sb_off + 0x270].copy_from_slice(&11_u32.to_le_bytes());
        image
    }

    fn build_test_ext4_image_with_mmp(state: u16, seq: u32) -> Vec<u8> {
        let mut image = build_test_ext4_image_with_state(state);
        let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;

        let mut incompat_bytes = [0_u8; 4];
        incompat_bytes.copy_from_slice(&image[sb_off + 0x60..sb_off + 0x64]);
        let incompat = u32::from_le_bytes(incompat_bytes) | ffs_ondisk::Ext4IncompatFeatures::MMP.0;
        image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat.to_le_bytes());

        let mmp_block = 8_u64;
        image[sb_off + 0x166..sb_off + 0x168].copy_from_slice(&5_u16.to_le_bytes());
        image[sb_off + 0x168..sb_off + 0x170].copy_from_slice(&mmp_block.to_le_bytes());

        let mmp_offset = usize::try_from(mmp_block * 4096).expect("mmp offset should fit");
        image[mmp_offset..mmp_offset + 4]
            .copy_from_slice(&ffs_ondisk::ext4::EXT4_MMP_MAGIC.to_le_bytes());
        image[mmp_offset + 4..mmp_offset + 8].copy_from_slice(&seq.to_le_bytes());
        image[mmp_offset + 8..mmp_offset + 16].copy_from_slice(&1_700_000_123_u64.to_le_bytes());
        image[mmp_offset + 0x10..mmp_offset + 0x18].copy_from_slice(b"ffs-node");
        image[mmp_offset + 0x50..mmp_offset + 0x5B].copy_from_slice(b"/dev/testfs");
        image[mmp_offset + 0x70..mmp_offset + 0x72].copy_from_slice(&5_u16.to_le_bytes());

        image
    }

    fn build_test_btrfs_superblock(bytenr: u64, generation: u64) -> Vec<u8> {
        let mut sb = vec![0_u8; super::BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&ffs_types::BTRFS_MAGIC.to_le_bytes());
        sb[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
        sb[0x48..0x50].copy_from_slice(&generation.to_le_bytes());
        sb[0x50..0x58].copy_from_slice(&4096_u64.to_le_bytes()); // root
        sb[0x58..0x60].copy_from_slice(&8192_u64.to_le_bytes()); // chunk_root
        sb[0x70..0x78].copy_from_slice(&1_000_000_u64.to_le_bytes()); // total_bytes
        sb[0x78..0x80].copy_from_slice(&123_456_u64.to_le_bytes()); // bytes_used
        sb[0x80..0x88].copy_from_slice(&6_u64.to_le_bytes()); // root_dir_objectid
        sb[0x88..0x90].copy_from_slice(&1_u64.to_le_bytes()); // num_devices
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes()); // sectorsize
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes()); // nodesize
        sb[0x9C..0xA0].copy_from_slice(&4096_u32.to_le_bytes()); // stripesize
        sb[0xC4..0xC6].copy_from_slice(&ffs_types::BTRFS_CSUM_TYPE_CRC32C.to_le_bytes());
        let checksum = crc32c::crc32c(&sb[0x20..super::BTRFS_SUPER_INFO_SIZE]);
        sb[0..4].copy_from_slice(&checksum.to_le_bytes());
        sb
    }

    #[allow(clippy::cast_possible_truncation)]
    fn build_test_btrfs_superblock_with_single_chunk(
        bytenr: u64,
        generation: u64,
        logical_start: u64,
        logical_length: u64,
        physical_start: u64,
        chunk_type: u64,
    ) -> Vec<u8> {
        const BTRFS_SYS_CHUNK_ARRAY_OFFSET_TEST: usize = 0x32B;
        let mut sb = build_test_btrfs_superblock(bytenr, generation);

        // One sys_chunk_array entry:
        // disk_key (17) + chunk_fixed (48) + 1 stripe (32) = 97 bytes.
        let mut entry = Vec::with_capacity(97);

        // disk_key
        entry.extend_from_slice(&256_u64.to_le_bytes()); // objectid
        entry.push(228_u8); // CHUNK_ITEM_KEY
        entry.extend_from_slice(&logical_start.to_le_bytes());

        // chunk fixed fields
        entry.extend_from_slice(&logical_length.to_le_bytes()); // length
        entry.extend_from_slice(&2_u64.to_le_bytes()); // owner (chunk tree)
        entry.extend_from_slice(&(64 * 1024_u64).to_le_bytes()); // stripe_len
        entry.extend_from_slice(&chunk_type.to_le_bytes()); // type flags
        entry.extend_from_slice(&4096_u32.to_le_bytes()); // io_align
        entry.extend_from_slice(&4096_u32.to_le_bytes()); // io_width
        entry.extend_from_slice(&4096_u32.to_le_bytes()); // sector_size
        entry.extend_from_slice(&1_u16.to_le_bytes()); // num_stripes
        entry.extend_from_slice(&0_u16.to_le_bytes()); // sub_stripes

        // one stripe
        entry.extend_from_slice(&1_u64.to_le_bytes()); // devid
        entry.extend_from_slice(&physical_start.to_le_bytes()); // physical offset
        entry.extend_from_slice(&[0_u8; 16]); // dev_uuid

        let array_size = u32::try_from(entry.len()).expect("chunk entry length fits in u32");
        sb[0xA0..0xA4].copy_from_slice(&array_size.to_le_bytes());
        let array_start = BTRFS_SYS_CHUNK_ARRAY_OFFSET_TEST;
        let array_end = array_start + entry.len();
        sb[array_start..array_end].copy_from_slice(&entry);

        // Recompute checksum after mutating sys_chunk_array.
        let checksum = crc32c::crc32c(&sb[0x20..super::BTRFS_SUPER_INFO_SIZE]);
        sb[0..4].copy_from_slice(&checksum.to_le_bytes());
        sb
    }

    fn write_btrfs_leaf_header(
        image: &mut [u8],
        leaf_offset: usize,
        logical_bytenr: u64,
        owner: u64,
        item_count: u32,
    ) {
        image[leaf_offset + 0x30..leaf_offset + 0x38]
            .copy_from_slice(&logical_bytenr.to_le_bytes());
        image[leaf_offset + 0x50..leaf_offset + 0x58].copy_from_slice(&1_u64.to_le_bytes());
        image[leaf_offset + 0x58..leaf_offset + 0x60].copy_from_slice(&owner.to_le_bytes());
        image[leaf_offset + 0x60..leaf_offset + 0x64].copy_from_slice(&item_count.to_le_bytes());
        image[leaf_offset + 0x64] = 0;
    }

    #[allow(clippy::too_many_arguments)]
    fn write_btrfs_leaf_item(
        image: &mut [u8],
        leaf_offset: usize,
        item_index: usize,
        objectid: u64,
        item_type: u8,
        key_offset: u64,
        data_offset: u32,
        data_size: u32,
    ) {
        const BTRFS_LEAF_HEADER_SIZE: usize = 101;
        const BTRFS_LEAF_ITEM_SIZE: usize = 25;
        let item_offset = leaf_offset + BTRFS_LEAF_HEADER_SIZE + item_index * BTRFS_LEAF_ITEM_SIZE;
        let data_offset_rel = data_offset
            .checked_sub(u32::try_from(BTRFS_LEAF_HEADER_SIZE).expect("header size fits"))
            .expect("test item payload must live after the leaf header");
        image[item_offset..item_offset + 8].copy_from_slice(&objectid.to_le_bytes());
        image[item_offset + 8] = item_type;
        image[item_offset + 9..item_offset + 17].copy_from_slice(&key_offset.to_le_bytes());
        image[item_offset + 17..item_offset + 21].copy_from_slice(&data_offset_rel.to_le_bytes());
        image[item_offset + 21..item_offset + 25].copy_from_slice(&data_size.to_le_bytes());
    }

    fn stamp_btrfs_test_tree_block_crc32c(image: &mut [u8], logical: usize) {
        let block = &mut image[logical..logical + 16 * 1024];
        let checksum = crc32c::crc32c(&block[0x20..]);
        block[0..4].copy_from_slice(&checksum.to_le_bytes());
    }

    fn map_btrfs_test_chunk_physical_offset(
        logical_start: u64,
        physical_start: u64,
        logical_bytenr: u64,
    ) -> usize {
        let delta = logical_bytenr
            .checked_sub(logical_start)
            .expect("test logical bytenr should be inside the synthetic chunk");
        usize::try_from(physical_start + delta).expect("mapped tree block offset should fit")
    }

    #[allow(clippy::cast_possible_truncation)]
    fn build_test_btrfs_image_with_root_inode_item_for_chunk(
        logical_start: u64,
        logical_length: u64,
        physical_start: u64,
        chunk_type: u64,
    ) -> Vec<u8> {
        let image_size: usize = 512 * 1024;
        let mut image = vec![0_u8; image_size];
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let root_tree_logical = 0x4_000_u64;
        let fs_tree_logical = 0x8_000_u64;
        let root_dir_objectid = 256_u64;

        let mut sb = build_test_btrfs_superblock_with_single_chunk(
            primary_offset as u64,
            11,
            logical_start,
            logical_length,
            physical_start,
            chunk_type,
        );
        sb[0x50..0x58].copy_from_slice(&root_tree_logical.to_le_bytes());
        sb[0x80..0x88].copy_from_slice(&root_dir_objectid.to_le_bytes());
        sb[0x88..0x90].copy_from_slice(&1_u64.to_le_bytes());
        sb[0xC6] = 0;
        let checksum = crc32c::crc32c(&sb[0x20..super::BTRFS_SUPER_INFO_SIZE]);
        sb[0..4].copy_from_slice(&checksum.to_le_bytes());
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb);

        let root_leaf_offset =
            map_btrfs_test_chunk_physical_offset(logical_start, physical_start, root_tree_logical);
        write_btrfs_leaf_header(&mut image, root_leaf_offset, root_tree_logical, 1, 1);
        let root_item_offset = 3000_u32;
        let root_item_size = 239_u32;
        write_btrfs_leaf_item(
            &mut image,
            root_leaf_offset,
            0,
            BTRFS_FS_TREE_OBJECTID,
            BTRFS_ITEM_ROOT_ITEM,
            0,
            root_item_offset,
            root_item_size,
        );
        let mut root_item =
            vec![0_u8; usize::try_from(root_item_size).expect("root item size fits")];
        root_item[168..176].copy_from_slice(&root_dir_objectid.to_le_bytes());
        root_item[176..184].copy_from_slice(&fs_tree_logical.to_le_bytes());
        let root_item_last = root_item.len() - 1;
        root_item[root_item_last] = 0;
        let root_data_start =
            root_leaf_offset + usize::try_from(root_item_offset).expect("root item offset fits");
        image[root_data_start..root_data_start + root_item.len()].copy_from_slice(&root_item);

        let fs_leaf_offset =
            map_btrfs_test_chunk_physical_offset(logical_start, physical_start, fs_tree_logical);
        write_btrfs_leaf_header(
            &mut image,
            fs_leaf_offset,
            fs_tree_logical,
            BTRFS_FS_TREE_OBJECTID,
            1,
        );
        let inode_item = BtrfsInodeItem {
            generation: 1,
            size: 4096,
            nbytes: 4096,
            nlink: 2,
            uid: 1000,
            gid: 1000,
            mode: 0o040_755,
            rdev: 0,
            flags: 0,
            atime_sec: 10,
            atime_nsec: 0,
            ctime_sec: 10,
            ctime_nsec: 0,
            mtime_sec: 10,
            mtime_nsec: 0,
            otime_sec: 10,
            otime_nsec: 0,
        };
        let inode_bytes = inode_item.to_bytes();
        let inode_data_offset = 3200_u32;
        write_btrfs_leaf_item(
            &mut image,
            fs_leaf_offset,
            0,
            root_dir_objectid,
            BTRFS_ITEM_INODE_ITEM,
            0,
            inode_data_offset,
            u32::try_from(inode_bytes.len()).expect("inode size fits"),
        );
        let inode_data_start =
            fs_leaf_offset + usize::try_from(inode_data_offset).expect("inode offset fits");
        image[inode_data_start..inode_data_start + inode_bytes.len()].copy_from_slice(&inode_bytes);

        stamp_btrfs_test_tree_block_crc32c(&mut image, root_leaf_offset);
        stamp_btrfs_test_tree_block_crc32c(&mut image, fs_leaf_offset);

        image
    }

    #[allow(clippy::cast_possible_truncation)]
    fn build_test_btrfs_image_with_root_inode_item() -> Vec<u8> {
        build_test_btrfs_image_with_root_inode_item_for_chunk(0, 512 * 1024, 0, 2)
    }

    fn encode_btrfs_dir_index_entry(name: &[u8], child_objectid: u64, file_type: u8) -> Vec<u8> {
        let mut entry = vec![0_u8; 30 + name.len()];
        entry[0..8].copy_from_slice(&child_objectid.to_le_bytes());
        entry[8] = BTRFS_ITEM_INODE_ITEM;
        entry[9..17].copy_from_slice(&0_u64.to_le_bytes());
        entry[17..25].copy_from_slice(&1_u64.to_le_bytes());
        entry[25..27].copy_from_slice(&0_u16.to_le_bytes());
        let name_len = u16::try_from(name.len()).expect("test name length should fit in u16");
        entry[27..29].copy_from_slice(&name_len.to_le_bytes());
        entry[29] = file_type;
        entry[30..30 + name.len()].copy_from_slice(name);
        entry
    }

    fn encode_btrfs_regular_extent(disk_bytenr: u64, num_bytes: u64) -> [u8; 53] {
        let mut extent = [0_u8; 53];
        extent[0..8].copy_from_slice(&1_u64.to_le_bytes());
        extent[8..16].copy_from_slice(&num_bytes.to_le_bytes());
        extent[20] = ffs_btrfs::BTRFS_FILE_EXTENT_REG;
        extent[21..29].copy_from_slice(&disk_bytenr.to_le_bytes());
        extent[29..37].copy_from_slice(&num_bytes.to_le_bytes());
        extent[37..45].copy_from_slice(&0_u64.to_le_bytes());
        extent[45..53].copy_from_slice(&num_bytes.to_le_bytes());
        extent
    }

    fn build_test_btrfs_root_item(
        bytenr: u64,
        generation: u64,
        root_dirid: u64,
        flags: u64,
        uuid: [u8; 16],
        parent_uuid: [u8; 16],
    ) -> Vec<u8> {
        // ROOT_ITEM offsets per parse_root_item in ffs-btrfs:
        // 160: generation, 168: root_dirid, 176: bytenr, 208: flags, 216: refs,
        // 238: level, 239: generation_v2, 247: uuid, 263: parent_uuid
        let mut root_item = vec![0_u8; 279]; // 263 + 16 = 279 for parent_uuid end
        root_item[160..168].copy_from_slice(&generation.to_le_bytes());
        root_item[168..176].copy_from_slice(&root_dirid.to_le_bytes());
        root_item[176..184].copy_from_slice(&bytenr.to_le_bytes());
        root_item[208..216].copy_from_slice(&flags.to_le_bytes());
        root_item[216..220].copy_from_slice(&1_u32.to_le_bytes()); // refs (u32)
        root_item[238] = 0; // level
        root_item[239..247].copy_from_slice(&generation.to_le_bytes()); // generation_v2 must equal generation
        root_item[247..263].copy_from_slice(&uuid);
        root_item[263..279].copy_from_slice(&parent_uuid);
        let last = root_item.len() - 1;
        root_item[last] = 0;
        root_item
    }

    fn build_test_btrfs_root_ref(name: &str, dirid: u64, sequence: u64) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let mut root_ref = Vec::with_capacity(18 + name_bytes.len());
        root_ref.extend_from_slice(&dirid.to_le_bytes());
        root_ref.extend_from_slice(&sequence.to_le_bytes());
        root_ref.extend_from_slice(
            &u16::try_from(name_bytes.len())
                .expect("btrfs test root ref name length should fit in u16")
                .to_le_bytes(),
        );
        root_ref.extend_from_slice(name_bytes);
        root_ref
    }

    struct BtrfsRegularFileLeafPayloads {
        root_inode: Vec<u8>,
        dir_index: Vec<u8>,
        file_inode: Vec<u8>,
        extent: Vec<u8>,
    }

    fn build_test_btrfs_regular_file_leaf_payloads(
        file_objectid: u64,
        file_name: &str,
        file_contents: &[u8],
        data_logical: u64,
    ) -> BtrfsRegularFileLeafPayloads {
        let root_inode = make_test_btrfs_inode_item(0o040_755, 4096, 2).to_bytes();
        let file_size = u64::try_from(file_contents.len()).expect("file payload length should fit");
        let file_inode = make_test_btrfs_inode_item(0o100_644, file_size, 1).to_bytes();
        let dir_index = encode_btrfs_dir_index_entry(
            file_name.as_bytes(),
            file_objectid,
            ffs_btrfs::BTRFS_FT_REG_FILE,
        );
        let extent = encode_btrfs_regular_extent(data_logical, file_size).to_vec();
        BtrfsRegularFileLeafPayloads {
            root_inode,
            dir_index,
            file_inode,
            extent,
        }
    }

    fn make_test_btrfs_inode_item(mode: u32, size: u64, nlink: u32) -> BtrfsInodeItem {
        BtrfsInodeItem {
            generation: 1,
            size,
            nbytes: size,
            nlink,
            uid: 1000,
            gid: 1000,
            mode,
            rdev: 0,
            flags: 0,
            atime_sec: 10,
            atime_nsec: 0,
            ctime_sec: 10,
            ctime_nsec: 0,
            mtime_sec: 10,
            mtime_nsec: 0,
            otime_sec: 10,
            otime_nsec: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write_test_btrfs_regular_file_tree(
        image: &mut [u8],
        leaf_logical: u64,
        tree_objectid: u64,
        file_objectid: u64,
        file_name: &str,
        file_contents: &[u8],
        data_logical: u64,
    ) {
        const ROOT_INODE_DATA_OFFSET: u32 = 3200;
        const DIR_INDEX_DATA_OFFSET: u32 = 3060;
        const FILE_INODE_DATA_OFFSET: u32 = 2860;
        const EXTENT_DATA_OFFSET: u32 = 2780;
        const ROOT_DIR_OBJECTID: u64 = 256;

        let leaf_offset = usize::try_from(leaf_logical).expect("leaf logical should fit");
        write_btrfs_leaf_header(image, leaf_offset, leaf_logical, tree_objectid, 4);

        let payloads = build_test_btrfs_regular_file_leaf_payloads(
            file_objectid,
            file_name,
            file_contents,
            data_logical,
        );

        write_btrfs_leaf_item(
            image,
            leaf_offset,
            0,
            ROOT_DIR_OBJECTID,
            BTRFS_ITEM_INODE_ITEM,
            0,
            ROOT_INODE_DATA_OFFSET,
            u32::try_from(payloads.root_inode.len()).expect("root inode size should fit"),
        );
        write_btrfs_leaf_item(
            image,
            leaf_offset,
            1,
            ROOT_DIR_OBJECTID,
            ffs_btrfs::BTRFS_ITEM_DIR_INDEX,
            2,
            DIR_INDEX_DATA_OFFSET,
            u32::try_from(payloads.dir_index.len()).expect("dir index size should fit"),
        );
        write_btrfs_leaf_item(
            image,
            leaf_offset,
            2,
            file_objectid,
            BTRFS_ITEM_INODE_ITEM,
            0,
            FILE_INODE_DATA_OFFSET,
            u32::try_from(payloads.file_inode.len()).expect("file inode size should fit"),
        );
        write_btrfs_leaf_item(
            image,
            leaf_offset,
            3,
            file_objectid,
            ffs_btrfs::BTRFS_ITEM_EXTENT_DATA,
            0,
            EXTENT_DATA_OFFSET,
            u32::try_from(payloads.extent.len()).expect("extent size should fit"),
        );

        copy_into_leaf(
            image,
            leaf_offset,
            ROOT_INODE_DATA_OFFSET,
            &payloads.root_inode,
        );
        copy_into_leaf(
            image,
            leaf_offset,
            DIR_INDEX_DATA_OFFSET,
            &payloads.dir_index,
        );
        copy_into_leaf(
            image,
            leaf_offset,
            FILE_INODE_DATA_OFFSET,
            &payloads.file_inode,
        );
        copy_into_leaf(image, leaf_offset, EXTENT_DATA_OFFSET, &payloads.extent);
        stamp_btrfs_test_tree_block_crc32c(image, leaf_offset);

        let file_data_start = usize::try_from(data_logical).expect("file data logical fits");
        image[file_data_start..file_data_start + file_contents.len()]
            .copy_from_slice(file_contents);
    }

    fn copy_into_leaf(image: &mut [u8], leaf_offset: usize, data_offset: u32, payload: &[u8]) {
        let start = leaf_offset + usize::try_from(data_offset).expect("leaf data offset fits");
        image[start..start + payload.len()].copy_from_slice(payload);
    }

    #[allow(clippy::too_many_lines)]
    fn build_test_btrfs_image_with_named_mount_selections() -> Vec<u8> {
        const ROOT_TREE_LOGICAL: u64 = 0x4_000;
        const SUBVOL_TREE_LOGICAL: u64 = 0x8_000;
        const SNAPSHOT_TREE_LOGICAL: u64 = 0xC_000;
        const SUBVOL_FILE_DATA_LOGICAL: u64 = 0x12_000;
        const SNAPSHOT_FILE_DATA_LOGICAL: u64 = 0x14_000;
        const ROOT_DIR_OBJECTID: u64 = 256;
        const SUBVOL_FILE_OBJECTID: u64 = 257;
        const SNAPSHOT_FILE_OBJECTID: u64 = 258;
        const SUBVOL_ROOT_ITEM_OFFSET: u32 = 3400;
        const SUBVOL_ROOT_REF_OFFSET: u32 = 3320;
        const SNAPSHOT_ROOT_ITEM_OFFSET: u32 = 3000;
        const SNAPSHOT_ROOT_REF_OFFSET: u32 = 2920;

        let image_size: usize = 512 * 1024;
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let subvol_id = ffs_btrfs::BTRFS_FIRST_FREE_OBJECTID;
        let snapshot_id = subvol_id + 1;
        let subvol_uuid = [1_u8; 16];
        let snapshot_uuid = [2_u8; 16];
        let mut image = vec![0_u8; image_size];

        let mut sb = build_test_btrfs_superblock_with_single_chunk(
            primary_offset as u64,
            11,
            0,
            image_size as u64,
            0,
            2,
        );
        sb[0x50..0x58].copy_from_slice(&ROOT_TREE_LOGICAL.to_le_bytes());
        sb[0x80..0x88].copy_from_slice(&ROOT_DIR_OBJECTID.to_le_bytes());
        sb[0x88..0x90].copy_from_slice(&1_u64.to_le_bytes());
        sb[0xC6] = 0;
        let checksum = crc32c::crc32c(&sb[0x20..super::BTRFS_SUPER_INFO_SIZE]);
        sb[0..4].copy_from_slice(&checksum.to_le_bytes());
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb);

        let root_leaf_offset = usize::try_from(ROOT_TREE_LOGICAL).expect("root tree offset fits");
        write_btrfs_leaf_header(&mut image, root_leaf_offset, ROOT_TREE_LOGICAL, 1, 4);

        let subvol_root_item = build_test_btrfs_root_item(
            SUBVOL_TREE_LOGICAL,
            21,
            ROOT_DIR_OBJECTID,
            0,
            subvol_uuid,
            [0_u8; 16],
        );
        let subvol_root_ref = build_test_btrfs_root_ref("home", ROOT_DIR_OBJECTID, 1);
        let snapshot_root_item = build_test_btrfs_root_item(
            SNAPSHOT_TREE_LOGICAL,
            22,
            ROOT_DIR_OBJECTID,
            1,
            snapshot_uuid,
            subvol_uuid,
        );
        let snapshot_root_ref = build_test_btrfs_root_ref("snap-home", ROOT_DIR_OBJECTID, 2);

        // Btrfs leaf item keys must be strictly increasing by
        // `(objectid, item_type, offset)`.
        write_btrfs_leaf_item(
            &mut image,
            root_leaf_offset,
            0,
            BTRFS_FS_TREE_OBJECTID,
            ffs_btrfs::BTRFS_ITEM_ROOT_REF,
            subvol_id,
            SUBVOL_ROOT_REF_OFFSET,
            u32::try_from(subvol_root_ref.len()).expect("subvolume root ref size should fit"),
        );
        write_btrfs_leaf_item(
            &mut image,
            root_leaf_offset,
            1,
            BTRFS_FS_TREE_OBJECTID,
            ffs_btrfs::BTRFS_ITEM_ROOT_REF,
            snapshot_id,
            SNAPSHOT_ROOT_REF_OFFSET,
            u32::try_from(snapshot_root_ref.len()).expect("snapshot root ref size should fit"),
        );
        write_btrfs_leaf_item(
            &mut image,
            root_leaf_offset,
            2,
            subvol_id,
            BTRFS_ITEM_ROOT_ITEM,
            0,
            SUBVOL_ROOT_ITEM_OFFSET,
            u32::try_from(subvol_root_item.len()).expect("subvolume root item size should fit"),
        );
        write_btrfs_leaf_item(
            &mut image,
            root_leaf_offset,
            3,
            snapshot_id,
            BTRFS_ITEM_ROOT_ITEM,
            0,
            SNAPSHOT_ROOT_ITEM_OFFSET,
            u32::try_from(snapshot_root_item.len()).expect("snapshot root item size should fit"),
        );

        let subvol_root_item_start =
            root_leaf_offset + usize::try_from(SUBVOL_ROOT_ITEM_OFFSET).expect("offset fits");
        image[subvol_root_item_start..subvol_root_item_start + subvol_root_item.len()]
            .copy_from_slice(&subvol_root_item);
        let subvol_root_ref_start =
            root_leaf_offset + usize::try_from(SUBVOL_ROOT_REF_OFFSET).expect("offset fits");
        image[subvol_root_ref_start..subvol_root_ref_start + subvol_root_ref.len()]
            .copy_from_slice(&subvol_root_ref);
        let snapshot_root_item_start =
            root_leaf_offset + usize::try_from(SNAPSHOT_ROOT_ITEM_OFFSET).expect("offset fits");
        image[snapshot_root_item_start..snapshot_root_item_start + snapshot_root_item.len()]
            .copy_from_slice(&snapshot_root_item);
        let snapshot_root_ref_start =
            root_leaf_offset + usize::try_from(SNAPSHOT_ROOT_REF_OFFSET).expect("offset fits");
        image[snapshot_root_ref_start..snapshot_root_ref_start + snapshot_root_ref.len()]
            .copy_from_slice(&snapshot_root_ref);
        stamp_btrfs_test_tree_block_crc32c(&mut image, root_leaf_offset);

        write_test_btrfs_regular_file_tree(
            &mut image,
            SUBVOL_TREE_LOGICAL,
            subvol_id,
            SUBVOL_FILE_OBJECTID,
            "selected.txt",
            b"hello from subvolume root\n",
            SUBVOL_FILE_DATA_LOGICAL,
        );
        write_test_btrfs_regular_file_tree(
            &mut image,
            SNAPSHOT_TREE_LOGICAL,
            snapshot_id,
            SNAPSHOT_FILE_OBJECTID,
            "selected.txt",
            b"hello from snapshot root\n",
            SNAPSHOT_FILE_DATA_LOGICAL,
        );

        image
    }

    #[allow(clippy::too_many_lines)]
    fn build_test_btrfs_image_with_dir_index_entry() -> Vec<u8> {
        let image_size: usize = 512 * 1024;
        let mut image = vec![0_u8; image_size];
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let root_tree_logical = 0x4_000_u64;
        let fs_tree_logical = 0x8_000_u64;
        let root_dir_objectid = 256_u64;
        let child_objectid = 257_u64;

        let mut sb = build_test_btrfs_superblock_with_single_chunk(
            primary_offset as u64,
            11,
            0,
            image_size as u64,
            0,
            2,
        );
        sb[0x50..0x58].copy_from_slice(&root_tree_logical.to_le_bytes());
        sb[0x80..0x88].copy_from_slice(&root_dir_objectid.to_le_bytes());
        sb[0x88..0x90].copy_from_slice(&1_u64.to_le_bytes());
        sb[0xC6] = 0;
        let checksum = crc32c::crc32c(&sb[0x20..super::BTRFS_SUPER_INFO_SIZE]);
        sb[0..4].copy_from_slice(&checksum.to_le_bytes());
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb);

        let root_leaf_offset = usize::try_from(root_tree_logical).expect("root tree offset fits");
        write_btrfs_leaf_header(&mut image, root_leaf_offset, root_tree_logical, 1, 1);
        let root_item_offset = 3000_u32;
        let root_item_size = 239_u32;
        write_btrfs_leaf_item(
            &mut image,
            root_leaf_offset,
            0,
            BTRFS_FS_TREE_OBJECTID,
            BTRFS_ITEM_ROOT_ITEM,
            0,
            root_item_offset,
            root_item_size,
        );
        let mut root_item =
            vec![0_u8; usize::try_from(root_item_size).expect("root item size fits")];
        root_item[168..176].copy_from_slice(&root_dir_objectid.to_le_bytes());
        root_item[176..184].copy_from_slice(&fs_tree_logical.to_le_bytes());
        let root_item_last = root_item.len() - 1;
        root_item[root_item_last] = 0;
        let root_data_start =
            root_leaf_offset + usize::try_from(root_item_offset).expect("root item offset fits");
        image[root_data_start..root_data_start + root_item.len()].copy_from_slice(&root_item);

        let fs_leaf_offset = usize::try_from(fs_tree_logical).expect("fs tree offset fits");
        write_btrfs_leaf_header(
            &mut image,
            fs_leaf_offset,
            fs_tree_logical,
            BTRFS_FS_TREE_OBJECTID,
            3,
        );

        let root_inode = BtrfsInodeItem {
            generation: 1,
            size: 4096,
            nbytes: 4096,
            nlink: 2,
            uid: 1000,
            gid: 1000,
            mode: 0o040_755,
            rdev: 0,
            flags: 0,
            atime_sec: 10,
            atime_nsec: 0,
            ctime_sec: 10,
            ctime_nsec: 0,
            mtime_sec: 10,
            mtime_nsec: 0,
            otime_sec: 10,
            otime_nsec: 0,
        };
        let child_inode = BtrfsInodeItem {
            mode: 0o100_644,
            nlink: 1,
            size: 0,
            nbytes: 0,
            ..root_inode
        };

        let root_inode_bytes = root_inode.to_bytes();
        let dir_index_bytes = encode_btrfs_dir_index_entry(
            b"hello.txt",
            child_objectid,
            ffs_btrfs::BTRFS_FT_REG_FILE,
        );
        let child_inode_bytes = child_inode.to_bytes();

        let mut data_cursor = 16 * 1024;
        data_cursor -= root_inode_bytes.len();
        write_btrfs_leaf_item(
            &mut image,
            fs_leaf_offset,
            0,
            root_dir_objectid,
            BTRFS_ITEM_INODE_ITEM,
            0,
            u32::try_from(data_cursor).expect("root inode offset fits"),
            u32::try_from(root_inode_bytes.len()).expect("root inode size fits"),
        );
        image[fs_leaf_offset + data_cursor..fs_leaf_offset + data_cursor + root_inode_bytes.len()]
            .copy_from_slice(&root_inode_bytes);

        data_cursor -= dir_index_bytes.len();
        write_btrfs_leaf_item(
            &mut image,
            fs_leaf_offset,
            1,
            root_dir_objectid,
            ffs_btrfs::BTRFS_ITEM_DIR_INDEX,
            2,
            u32::try_from(data_cursor).expect("dir index offset fits"),
            u32::try_from(dir_index_bytes.len()).expect("dir index size fits"),
        );
        image[fs_leaf_offset + data_cursor..fs_leaf_offset + data_cursor + dir_index_bytes.len()]
            .copy_from_slice(&dir_index_bytes);

        data_cursor -= child_inode_bytes.len();
        write_btrfs_leaf_item(
            &mut image,
            fs_leaf_offset,
            2,
            child_objectid,
            BTRFS_ITEM_INODE_ITEM,
            0,
            u32::try_from(data_cursor).expect("child inode offset fits"),
            u32::try_from(child_inode_bytes.len()).expect("child inode size fits"),
        );
        image[fs_leaf_offset + data_cursor..fs_leaf_offset + data_cursor + child_inode_bytes.len()]
            .copy_from_slice(&child_inode_bytes);

        stamp_btrfs_test_tree_block_crc32c(&mut image, root_leaf_offset);
        stamp_btrfs_test_tree_block_crc32c(&mut image, fs_leaf_offset);

        image
    }

    fn test_btrfs_chunk_entry(
        logical_start: u64,
        length: u64,
        physical_start: u64,
    ) -> ffs_ondisk::BtrfsChunkEntry {
        ffs_ondisk::BtrfsChunkEntry {
            key: ffs_ondisk::BtrfsKey {
                objectid: 0,
                item_type: 0,
                offset: logical_start,
            },
            length,
            owner: 0,
            stripe_len: 0,
            chunk_type: 0,
            io_align: 0,
            io_width: 0,
            sector_size: 4096,
            num_stripes: 1,
            sub_stripes: 1,
            stripes: vec![ffs_ondisk::BtrfsStripe {
                devid: 1,
                offset: physical_start,
                dev_uuid: [0_u8; 16],
            }],
        }
    }

    fn write_sparse_test_image(path: &std::path::Path, image: &[u8]) -> io::Result<()> {
        let mut file = std::fs::File::create(path)?;
        file.set_len(u64::try_from(image.len()).expect("test image length should fit into u64"))?;

        let mut run_start: Option<usize> = None;
        for (idx, byte) in image.iter().enumerate() {
            if *byte == 0 {
                if let Some(start) = run_start.take() {
                    file.seek(SeekFrom::Start(
                        u64::try_from(start).expect("run start should fit into u64"),
                    ))?;
                    file.write_all(&image[start..idx])?;
                }
            } else if run_start.is_none() {
                run_start = Some(idx);
            }
        }

        if let Some(start) = run_start {
            file.seek(SeekFrom::Start(
                u64::try_from(start).expect("run start should fit into u64"),
            ))?;
            file.write_all(&image[start..])?;
        }

        file.sync_all()
    }

    fn with_temp_image_path<T>(image: &[u8], f: impl FnOnce(PathBuf) -> T) -> T {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        path.push(format!(
            "ffs-cli-fsck-force-{}-{ts}-{count}.img",
            std::process::id()
        ));
        write_sparse_test_image(&path, image).expect("write test filesystem image");
        let result = f(path.clone());
        let _ = std::fs::remove_file(path);
        result
    }

    fn test_local_host_name() -> String {
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

    /// Write a live foreign-host lease record so write-side repair coordination
    /// is blocked by another host's active ownership lease.
    fn write_test_coordination_record(image: &std::path::Path, owner_host: &str) -> PathBuf {
        let record_path = repair_coordination_record_path(image);
        let mut record = CoordinationRecord {
            version: 1,
            host_id: format!("ffs-test-host-id-{owner_host}"),
            hostname: owner_host.to_owned(),
            pid: 4242,
            claimed_at: "2020-01-01T00:00:00Z".to_owned(),
            lease_ttl_secs: 300,
            lease_version: 4,
            repair_generation: 7,
            groups_owned: Vec::new(),
        };
        // Re-stamp claimed_at to the current time so the foreign lease is live.
        record.renew();
        let mut bytes =
            serde_json::to_vec_pretty(&record).expect("coordination record should serialize");
        bytes.push(b'\n');
        std::fs::write(&record_path, bytes).expect("write coordination record");
        record_path
    }

    #[test]
    fn read_file_region_reads_exact_window() {
        let image: Vec<u8> = (0_u8..64).collect();
        with_temp_image_path(&image, |path| {
            let region = read_file_region(&path, 16, 8, "test window")
                .expect("region read should succeed for in-bounds window");
            assert_eq!(region, image[16..24]);
        });
    }

    #[test]
    fn read_file_region_rejects_out_of_bounds_window() {
        let image = vec![0_u8; 32];
        with_temp_image_path(&image, |path| {
            let err = read_file_region(&path, 24, 16, "test window")
                .expect_err("region read should fail for out-of-bounds window");
            let message = format!("{err:#}");
            assert!(
                message.contains("out of bounds"),
                "expected out-of-bounds error, got: {message}"
            );
        });
    }

    #[test]
    fn load_evidence_records_skips_invalid_lines_and_filters_by_event_type() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"corruption_detected\",\"block_group\":1}\n",
            "{not-json\n",
            "\n",
            "{\"timestamp_ns\":2,\"event_type\":\"repair_failed\",\"block_group\":2}\n",
            "{\"timestamp_ns\":3,\"event_type\":\"repair_failed\",\"block_group\":3}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records = load_evidence_records(&path, Some("repair_failed"), None, None, None)
                .expect("filtered evidence read should succeed");
            assert_eq!(records.len(), 2);
            assert!(
                records
                    .iter()
                    .all(|record| record.event_type == EvidenceEventType::RepairFailed)
            );
            assert_eq!(records[0].block_group, 2);
            assert_eq!(records[1].block_group, 3);
        });
    }

    #[test]
    fn load_evidence_records_tail_keeps_last_filtered_records() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
            "{\"timestamp_ns\":2,\"event_type\":\"corruption_detected\",\"block_group\":2}\n",
            "{\"timestamp_ns\":3,\"event_type\":\"repair_failed\",\"block_group\":3}\n",
            "{\"timestamp_ns\":4,\"event_type\":\"repair_failed\",\"block_group\":4}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records = load_evidence_records(&path, Some("repair_failed"), Some(2), None, None)
                .expect("tailed evidence read should succeed");
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].timestamp_ns, 3);
            assert_eq!(records[1].timestamp_ns, 4);
            assert_eq!(records[0].block_group, 3);
            assert_eq!(records[1].block_group, 4);
        });
    }

    #[test]
    fn load_evidence_records_filters_by_block_group() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
            "{\"timestamp_ns\":2,\"event_type\":\"repair_succeeded\",\"block_group\":7}\n",
            "{\"timestamp_ns\":3,\"event_type\":\"repair_failed\",\"block_group\":7}\n",
            "{\"timestamp_ns\":4,\"event_type\":\"repair_failed\",\"block_group\":9}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records = load_evidence_records(&path, Some("repair_failed"), None, None, Some(7))
                .expect("block-group evidence filter should succeed");
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].timestamp_ns, 3);
            assert_eq!(records[0].event_type, EvidenceEventType::RepairFailed);
            assert_eq!(records[0].block_group, 7);
        });
    }

    #[test]
    fn load_evidence_records_tail_applies_after_block_group_filter() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"repair_failed\",\"block_group\":7}\n",
            "{\"timestamp_ns\":2,\"event_type\":\"repair_failed\",\"block_group\":9}\n",
            "{\"timestamp_ns\":3,\"event_type\":\"repair_failed\",\"block_group\":7}\n",
            "{\"timestamp_ns\":4,\"event_type\":\"repair_failed\",\"block_group\":7}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records =
                load_evidence_records(&path, Some("repair_failed"), Some(2), None, Some(7))
                    .expect("tail should apply after block-group filtering");
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].timestamp_ns, 3);
            assert_eq!(records[1].timestamp_ns, 4);
            assert!(records.iter().all(|record| record.block_group == 7));
        });
    }

    #[test]
    fn load_evidence_records_tail_zero_returns_empty() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
            "{\"timestamp_ns\":2,\"event_type\":\"repair_failed\",\"block_group\":2}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records = load_evidence_records(&path, Some("repair_failed"), Some(0), None, None)
                .expect("tail=0 evidence read should succeed");
            assert!(
                records.is_empty(),
                "tail=0 should suppress all returned records"
            );
        });
    }

    #[test]
    fn load_evidence_records_skips_non_utf8_lines() {
        let mut ledger = Vec::new();
        ledger.extend_from_slice(
            b"{\"timestamp_ns\":1,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
        );
        ledger.extend_from_slice(&[0xFF, 0xFE, 0x00, b'\n']);
        ledger.extend_from_slice(
            b"{\"timestamp_ns\":2,\"event_type\":\"repair_failed\",\"block_group\":2}\n",
        );

        with_temp_image_path(&ledger, |path| {
            let records = load_evidence_records(&path, Some("repair_failed"), None, None, None)
                .expect("evidence read should tolerate non-utf8 torn lines");
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].timestamp_ns, 1);
            assert_eq!(records[1].timestamp_ns, 2);
        });
    }

    #[test]
    fn load_evidence_records_preset_filters_multiple_types() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"wal_recovery\",\"block_group\":0}\n",
            "{\"timestamp_ns\":2,\"event_type\":\"corruption_detected\",\"block_group\":1}\n",
            "{\"timestamp_ns\":3,\"event_type\":\"txn_aborted\",\"block_group\":0}\n",
            "{\"timestamp_ns\":4,\"event_type\":\"serialization_conflict\",\"block_group\":0}\n",
            "{\"timestamp_ns\":5,\"event_type\":\"flush_batch\",\"block_group\":0}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            // replay-anomalies preset: wal_recovery + txn_aborted + serialization_conflict
            let records = load_evidence_records(&path, None, None, Some("replay-anomalies"), None)
                .expect("preset filter should work");
            assert_eq!(records.len(), 3);
            assert_eq!(records[0].event_type, EvidenceEventType::WalRecovery);
            assert_eq!(records[1].event_type, EvidenceEventType::TxnAborted);
            assert_eq!(
                records[2].event_type,
                EvidenceEventType::SerializationConflict
            );
        });
    }

    #[test]
    fn load_evidence_records_preset_repair_failures_selects_correctly() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"corruption_detected\",\"block_group\":1}\n",
            "{\"timestamp_ns\":2,\"event_type\":\"repair_attempted\",\"block_group\":1}\n",
            "{\"timestamp_ns\":3,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
            "{\"timestamp_ns\":4,\"event_type\":\"wal_recovery\",\"block_group\":0}\n",
            "{\"timestamp_ns\":5,\"event_type\":\"scrub_cycle_complete\",\"block_group\":1}\n",
            "{\"timestamp_ns\":6,\"event_type\":\"repair_succeeded\",\"block_group\":1}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records = load_evidence_records(&path, None, None, Some("repair-failures"), None)
                .expect("repair-failures preset should work");
            assert_eq!(records.len(), 5);
            // wal_recovery should be excluded
            assert!(
                records
                    .iter()
                    .all(|r| r.event_type != EvidenceEventType::WalRecovery)
            );
        });
    }

    #[test]
    fn load_evidence_records_preset_pressure_transitions() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"backpressure_activated\",\"block_group\":0}\n",
            "{\"timestamp_ns\":2,\"event_type\":\"flush_batch\",\"block_group\":0}\n",
            "{\"timestamp_ns\":3,\"event_type\":\"durability_policy_changed\",\"block_group\":0}\n",
            "{\"timestamp_ns\":4,\"event_type\":\"refresh_policy_changed\",\"block_group\":1}\n",
            "{\"timestamp_ns\":5,\"event_type\":\"repair_failed\",\"block_group\":2}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records =
                load_evidence_records(&path, None, None, Some("pressure-transitions"), None)
                    .expect("pressure-transitions preset should work");
            assert_eq!(records.len(), 4);
            // repair_failed should be excluded
            assert!(
                records
                    .iter()
                    .all(|r| r.event_type != EvidenceEventType::RepairFailed)
            );
        });
    }

    #[test]
    fn load_evidence_records_preset_contention_selects_correctly() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"merge_proof_checked\",\"block_group\":0}\n",
            "{\"timestamp_ns\":2,\"event_type\":\"merge_applied\",\"block_group\":1}\n",
            "{\"timestamp_ns\":3,\"event_type\":\"policy_switched\",\"block_group\":0}\n",
            "{\"timestamp_ns\":4,\"event_type\":\"repair_failed\",\"block_group\":2}\n",
            "{\"timestamp_ns\":5,\"event_type\":\"contention_sample\",\"block_group\":0}\n",
            "{\"timestamp_ns\":6,\"event_type\":\"merge_rejected\",\"block_group\":1}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records = load_evidence_records(&path, None, None, Some("contention"), None)
                .expect("contention preset should work");
            assert_eq!(records.len(), 5);
            assert!(
                records
                    .iter()
                    .all(|r| r.event_type != EvidenceEventType::RepairFailed)
            );
            assert_eq!(records[0].event_type, EvidenceEventType::MergeProofChecked);
            assert_eq!(records[1].event_type, EvidenceEventType::MergeApplied);
            assert_eq!(records[2].event_type, EvidenceEventType::PolicySwitched);
            assert_eq!(records[3].event_type, EvidenceEventType::ContentionSample);
            assert_eq!(records[4].event_type, EvidenceEventType::MergeRejected);
        });
    }

    #[test]
    fn load_evidence_records_preset_tail_keeps_last_matching_records() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
            "{\"timestamp_ns\":2,\"event_type\":\"wal_recovery\",\"block_group\":0}\n",
            "{\"timestamp_ns\":3,\"event_type\":\"repair_succeeded\",\"block_group\":1}\n",
            "{\"timestamp_ns\":4,\"event_type\":\"flush_batch\",\"block_group\":0}\n",
            "{\"timestamp_ns\":5,\"event_type\":\"scrub_cycle_complete\",\"block_group\":1}\n",
            "{\"timestamp_ns\":6,\"event_type\":\"durability_policy_changed\",\"block_group\":0}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records =
                load_evidence_records(&path, None, Some(2), Some("repair-failures"), None)
                    .expect("preset+tail evidence read should succeed");
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].timestamp_ns, 3);
            assert_eq!(records[1].timestamp_ns, 5);
            assert_eq!(records[0].event_type, EvidenceEventType::RepairSucceeded);
            assert_eq!(records[1].event_type, EvidenceEventType::ScrubCycleComplete);
        });
    }

    #[test]
    fn load_evidence_records_preset_tail_keeps_last_matching_records_for_remaining_ledger_presets()
    {
        let cases = [
            (
                "replay-anomalies",
                concat!(
                    "{\"timestamp_ns\":1,\"event_type\":\"wal_recovery\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":2,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
                    "{\"timestamp_ns\":3,\"event_type\":\"txn_aborted\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":4,\"event_type\":\"flush_batch\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":5,\"event_type\":\"serialization_conflict\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":6,\"event_type\":\"repair_succeeded\",\"block_group\":1}\n",
                ),
                &[
                    EvidenceEventType::TxnAborted,
                    EvidenceEventType::SerializationConflict,
                ][..],
                &[3_u64, 5_u64][..],
            ),
            (
                "pressure-transitions",
                concat!(
                    "{\"timestamp_ns\":1,\"event_type\":\"backpressure_activated\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":2,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
                    "{\"timestamp_ns\":3,\"event_type\":\"flush_batch\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":4,\"event_type\":\"refresh_policy_changed\",\"block_group\":1}\n",
                    "{\"timestamp_ns\":5,\"event_type\":\"repair_succeeded\",\"block_group\":1}\n",
                    "{\"timestamp_ns\":6,\"event_type\":\"durability_policy_changed\",\"block_group\":0}\n",
                ),
                &[
                    EvidenceEventType::RefreshPolicyChanged,
                    EvidenceEventType::DurabilityPolicyChanged,
                ][..],
                &[4_u64, 6_u64][..],
            ),
            (
                "contention",
                concat!(
                    "{\"timestamp_ns\":1,\"event_type\":\"merge_proof_checked\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":2,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
                    "{\"timestamp_ns\":3,\"event_type\":\"merge_applied\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":4,\"event_type\":\"policy_switched\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":5,\"event_type\":\"flush_batch\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":6,\"event_type\":\"contention_sample\",\"block_group\":0}\n",
                ),
                &[
                    EvidenceEventType::PolicySwitched,
                    EvidenceEventType::ContentionSample,
                ][..],
                &[4_u64, 6_u64][..],
            ),
        ];

        for (preset, ledger, expected_types, expected_timestamps) in cases {
            with_temp_image_path(ledger.as_bytes(), |path| {
                let records = load_evidence_records(&path, None, Some(2), Some(preset), None)
                    .expect("preset+tail evidence read should succeed");
                assert_eq!(records.len(), 2, "preset {preset}");
                assert_eq!(
                    records
                        .iter()
                        .map(|record| record.timestamp_ns)
                        .collect::<Vec<_>>(),
                    expected_timestamps,
                    "preset {preset}"
                );
                assert_eq!(
                    records
                        .iter()
                        .map(|record| record.event_type)
                        .collect::<Vec<_>>(),
                    expected_types,
                    "preset {preset}"
                );
            });
        }
    }

    #[test]
    fn preset_event_types_returns_none_for_unknown() {
        use crate::cmd_evidence::{KNOWN_PRESETS, preset_event_types};
        assert!(preset_event_types("nonexistent").is_none());
        for name in KNOWN_PRESETS {
            assert!(
                preset_event_types(name).is_some(),
                "known preset {name} should return Some"
            );
        }
    }

    fn test_histogram(count: u64, sum: u64) -> EvidenceHistogramSnapshot {
        EvidenceHistogramSnapshot {
            buckets: vec![
                EvidenceHistogramBucket { le: 10, count: 1 },
                EvidenceHistogramBucket {
                    le: 100,
                    count: count.saturating_sub(1),
                },
            ],
            inf_count: 0,
            sum,
            count,
        }
    }

    #[test]
    fn load_metrics_report_metrics_preset_reads_bundle() {
        let bundle = serde_json::json!({
            "metrics": {
                "requests_total": 100,
                "requests_ok": 97,
                "requests_err": 3,
                "bytes_read": 8192,
                "requests_throttled": 4,
                "requests_shed": 1
            },
            "cache": {
                "cache_hits": 80,
                "cache_misses": 20,
                "cache_evictions": 5,
                "cache_dirty_count": 9,
                "writeback_queue_depth": 3,
                "hit_rate": 0.8
            },
            "mvcc": {
                "active_snapshots": 2,
                "commit_rate": 15.0,
                "conflict_rate": 0.125,
                "abort_rate": 0.125,
                "version_chain_max_length": 6,
                "prune_throughput": 42.0,
                "commit_attempts_total": 80,
                "commit_successes_total": 70,
                "conflicts_total": 10,
                "aborts_total": 10,
                "pruned_versions_total": 120,
                "commit_latency_us": {
                    "buckets": [{"le": 10, "count": 1}, {"le": 100, "count": 7}],
                    "inf_count": 0,
                    "sum": 800,
                    "count": 8
                },
                "conflict_resolution_latency_us": {
                    "buckets": [{"le": 10, "count": 1}, {"le": 100, "count": 3}],
                    "inf_count": 0,
                    "sum": 250,
                    "count": 4
                }
            },
            "repair_live": {
                "groups_scrubbed": 12,
                "corruption_detected": 2,
                "decode_attempts": 5,
                "decode_successes": 4,
                "symbol_refresh_count": 8,
                "symbol_staleness_max_seconds": 12.5
            }
        });

        with_temp_image_path(
            serde_json::to_string_pretty(&bundle)
                .expect("serialize bundle")
                .as_bytes(),
            |path| {
                let report =
                    load_metrics_report_for_test(&path, "metrics").expect("load metrics report");
                let value = serde_json::to_value(report).expect("serialize report");
                assert_eq!(value["preset"], "metrics");
                assert_eq!(value["metrics"]["requests_total"], 100);
                assert_eq!(value["cache"]["cache_hits"], 80);
                assert_eq!(value["mvcc"]["commit_attempts_total"], 80);
                assert_eq!(value["repair_live"]["decode_successes"], 4);
                assert_eq!(value["analyses"]["repair_freshness"], "fresh");
                assert_eq!(value["analyses"]["mvcc_contention_level"], "high");
            },
        );
    }

    #[test]
    fn load_metrics_report_cache_preset_reads_direct_snapshot() {
        let snapshot = CacheRuntimeMetricsSnapshot {
            cache_hits: 90,
            cache_misses: 10,
            cache_evictions: 3,
            cache_dirty_count: 40,
            writeback_queue_depth: 12,
            hit_rate: 0.9,
        };
        with_temp_image_path(
            serde_json::to_string_pretty(&snapshot)
                .expect("serialize cache snapshot")
                .as_bytes(),
            |path| {
                let report =
                    load_metrics_report_for_test(&path, "cache").expect("load cache report");
                let value = serde_json::to_value(report).expect("serialize report");
                assert_eq!(value["preset"], "cache");
                assert_eq!(value["snapshot"]["cache_hits"], 90);
                assert_eq!(value["miss_rate"], 0.1);
                assert_eq!(value["dirty_pressure"], "high");
                assert_eq!(value["writeback_pressure"], "queued");
            },
        );
    }

    #[test]
    fn load_metrics_report_cache_preset_reads_bundle_member() {
        let bundle = serde_json::json!({
            "cache": {
                "cache_hits": 120,
                "cache_misses": 30,
                "cache_evictions": 7,
                "cache_dirty_count": 16,
                "writeback_queue_depth": 6,
                "hit_rate": 0.8
            }
        });

        with_temp_image_path(
            serde_json::to_string_pretty(&bundle)
                .expect("serialize bundle")
                .as_bytes(),
            |path| {
                let report =
                    load_metrics_report_for_test(&path, "cache").expect("load cache report");
                let value = serde_json::to_value(report).expect("serialize report");
                assert_eq!(value["preset"], "cache");
                assert_eq!(value["snapshot"]["cache_hits"], 120);
                assert_eq!(value["snapshot"]["cache_misses"], 30);
                assert_eq!(value["miss_rate"], 0.2);
                assert_eq!(value["dirty_pressure"], "elevated");
                assert_eq!(value["writeback_pressure"], "active");
            },
        );
    }

    #[test]
    fn load_metrics_report_mvcc_preset_reads_direct_snapshot() {
        let snapshot = EvidenceMvccRuntimeMetricsSnapshot {
            active_snapshots: 3,
            commit_rate: 10.0,
            conflict_rate: 0.05,
            abort_rate: 0.02,
            version_chain_max_length: 4,
            prune_throughput: 11.0,
            commit_attempts_total: 50,
            commit_successes_total: 45,
            conflicts_total: 2,
            aborts_total: 1,
            pruned_versions_total: 99,
            commit_latency_us: test_histogram(5, 200),
            conflict_resolution_latency_us: test_histogram(2, 50),
        };
        with_temp_image_path(
            serde_json::to_string_pretty(&snapshot)
                .expect("serialize mvcc snapshot")
                .as_bytes(),
            |path| {
                let report = load_metrics_report_for_test(&path, "mvcc").expect("load mvcc report");
                let value = serde_json::to_value(report).expect("serialize report");
                assert_eq!(value["preset"], "mvcc");
                assert_eq!(value["snapshot"]["active_snapshots"], 3);
                assert_eq!(value["commit_success_rate"], 0.9);
                assert_eq!(value["contention_level"], "elevated");
            },
        );
    }

    #[test]
    fn load_metrics_report_mvcc_preset_reads_bundle_member() {
        let bundle = serde_json::json!({
            "mvcc": {
                "active_snapshots": 4,
                "commit_rate": 12.0,
                "conflict_rate": 0.2,
                "abort_rate": 0.05,
                "version_chain_max_length": 9,
                "prune_throughput": 17.0,
                "commit_attempts_total": 100,
                "commit_successes_total": 72,
                "conflicts_total": 18,
                "aborts_total": 5,
                "pruned_versions_total": 144,
                "commit_latency_us": {
                    "buckets": [{"le": 10, "count": 2}, {"le": 100, "count": 6}],
                    "inf_count": 0,
                    "sum": 420,
                    "count": 8
                },
                "conflict_resolution_latency_us": {
                    "buckets": [{"le": 10, "count": 1}, {"le": 100, "count": 4}],
                    "inf_count": 0,
                    "sum": 190,
                    "count": 5
                }
            }
        });

        with_temp_image_path(
            serde_json::to_string_pretty(&bundle)
                .expect("serialize bundle")
                .as_bytes(),
            |path| {
                let report = load_metrics_report_for_test(&path, "mvcc").expect("load mvcc report");
                let value = serde_json::to_value(report).expect("serialize report");
                assert_eq!(value["preset"], "mvcc");
                assert_eq!(value["snapshot"]["active_snapshots"], 4);
                assert_eq!(value["snapshot"]["commit_attempts_total"], 100);
                assert_eq!(value["commit_success_rate"], 0.72);
                assert_eq!(value["contention_level"], "high");
            },
        );
    }

    #[test]
    fn load_metrics_report_repair_live_reads_direct_snapshot() {
        let snapshot = RepairRuntimeMetricsSnapshot {
            groups_scrubbed: 20,
            corruption_detected: 5,
            decode_attempts: 8,
            decode_successes: 6,
            symbol_refresh_count: 14,
            symbol_staleness_max_seconds: 120.0,
        };
        with_temp_image_path(
            serde_json::to_string_pretty(&snapshot)
                .expect("serialize repair snapshot")
                .as_bytes(),
            |path| {
                let report = load_metrics_report_for_test(&path, "repair-live")
                    .expect("load repair-live report");
                let value = serde_json::to_value(report).expect("serialize report");
                assert_eq!(value["preset"], "repair-live");
                assert_eq!(value["snapshot"]["groups_scrubbed"], 20);
                assert_eq!(value["decode_success_rate"], 0.75);
                assert_eq!(value["freshness"], "aging");
            },
        );
    }

    #[test]
    fn load_metrics_report_repair_live_reads_bundle_member() {
        let bundle = serde_json::json!({
            "repair_live": {
                "groups_scrubbed": 15,
                "corruption_detected": 3,
                "decode_attempts": 9,
                "decode_successes": 3,
                "symbol_refresh_count": 11,
                "symbol_staleness_max_seconds": 601.0
            }
        });

        with_temp_image_path(
            serde_json::to_string_pretty(&bundle)
                .expect("serialize bundle")
                .as_bytes(),
            |path| {
                let report = load_metrics_report_for_test(&path, "repair-live")
                    .expect("load repair-live report");
                let value = serde_json::to_value(report).expect("serialize report");
                assert_eq!(value["preset"], "repair-live");
                assert_eq!(value["snapshot"]["groups_scrubbed"], 15);
                assert_eq!(value["snapshot"]["decode_successes"], 3);
                assert_eq!(value["decode_success_rate"], 0.333_333_333_333_333_3);
                assert_eq!(value["freshness"], "stale");
            },
        );
    }

    #[test]
    fn load_metrics_report_rejects_unsupported_preset() {
        with_temp_image_path(b"{}", |path| {
            let err = load_metrics_report_for_test(&path, "not-a-real-preset")
                .expect_err("unsupported metrics preset should fail");
            assert!(
                err.to_string().contains(
                    "metrics report requested for unsupported preset 'not-a-real-preset'"
                )
            );
        });
    }

    #[test]
    fn evidence_metrics_preset_rejects_summary_flag() {
        let bundle = serde_json::json!({
            "metrics": {
                "requests_total": 1,
                "requests_ok": 1,
                "requests_err": 0,
                "bytes_read": 64,
                "requests_throttled": 0,
                "requests_shed": 0
            }
        });

        with_temp_image_path(
            serde_json::to_string_pretty(&bundle)
                .expect("serialize bundle")
                .as_bytes(),
            |path| {
                let err = crate::cmd_evidence::evidence_cmd(
                    &path,
                    false,
                    None,
                    None,
                    Some("metrics"),
                    None,
                    true,
                )
                .expect_err("metrics preset should reject --summary");
                assert!(
                    err.to_string()
                        .contains("--summary is only supported for ledger-backed evidence presets")
                );
            },
        );
    }

    #[test]
    fn evidence_metrics_preset_rejects_tail_flag() {
        let bundle = serde_json::json!({
            "metrics": {
                "requests_total": 1,
                "requests_ok": 1,
                "requests_err": 0,
                "bytes_read": 64,
                "requests_throttled": 0,
                "requests_shed": 0
            }
        });

        with_temp_image_path(
            serde_json::to_string_pretty(&bundle)
                .expect("serialize bundle")
                .as_bytes(),
            |path| {
                let err = crate::cmd_evidence::evidence_cmd(
                    &path,
                    false,
                    None,
                    Some(5),
                    Some("metrics"),
                    None,
                    false,
                )
                .expect_err("metrics preset should reject --tail");
                assert!(
                    err.to_string()
                        .contains("--tail is only supported for ledger-backed evidence presets")
                );
            },
        );
    }

    #[test]
    fn evidence_metrics_preset_rejects_block_group_filter() {
        let bundle = serde_json::json!({
            "metrics": {
                "requests_total": 1,
                "requests_ok": 1,
                "requests_err": 0,
                "bytes_read": 64,
                "requests_throttled": 0,
                "requests_shed": 0
            }
        });

        with_temp_image_path(
            serde_json::to_string_pretty(&bundle)
                .expect("serialize bundle")
                .as_bytes(),
            |path| {
                let err = crate::cmd_evidence::evidence_cmd(
                    &path,
                    false,
                    None,
                    None,
                    Some("metrics"),
                    Some(7),
                    false,
                )
                .expect_err("metrics preset should reject --block-group");
                assert!(err.to_string().contains(
                    "--block-group is only supported for ledger-backed evidence presets"
                ));
            },
        );
    }

    #[test]
    fn evidence_summary_aggregates_correctly() {
        let ledger = concat!(
            "{\"timestamp_ns\":100,\"event_type\":\"wal_recovery\",\"block_group\":0,",
            "\"wal_recovery\":{\"commits_replayed\":5,\"versions_replayed\":10,",
            "\"records_discarded\":2,\"wal_valid_bytes\":1000,\"wal_total_bytes\":1024,",
            "\"used_checkpoint\":false}}\n",
            "{\"timestamp_ns\":200,\"event_type\":\"txn_aborted\",\"block_group\":0}\n",
            "{\"timestamp_ns\":300,\"event_type\":\"corruption_detected\",\"block_group\":1,",
            "\"corruption\":{\"blocks_affected\":3,\"corruption_kind\":\"crc\",",
            "\"severity\":\"error\",\"detail\":\"bad crc\"}}\n",
            "{\"timestamp_ns\":400,\"event_type\":\"repair_succeeded\",\"block_group\":1}\n",
            "{\"timestamp_ns\":500,\"event_type\":\"backpressure_activated\",\"block_group\":0}\n",
            "{\"timestamp_ns\":600,\"event_type\":\"flush_batch\",\"block_group\":0,",
            "\"flush_batch\":{\"blocks_flushed\":42,\"bytes_written\":172032,",
            "\"flush_duration_us\":500}}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records =
                load_evidence_records(&path, None, None, None, None).expect("load should succeed");
            let summary = crate::cmd_evidence::build_summary_for_test(&records, None);
            assert_eq!(summary.total_records, 6);
            assert_eq!(summary.time_span_ns, Some((100, 600)));
            assert_eq!(summary.block_groups_seen, vec![1]);

            let replay = summary.replay_summary.as_ref().expect("replay summary");
            assert_eq!(replay.recovery_count, 1);
            assert_eq!(replay.total_commits_replayed, 5);
            assert_eq!(replay.total_records_discarded, 2);
            assert_eq!(replay.aborts, 1);

            let repair = summary.repair_summary.as_ref().expect("repair summary");
            assert_eq!(repair.corruptions_detected, 1);
            assert_eq!(repair.repairs_succeeded, 1);
            assert_eq!(repair.total_blocks_corrupt, 3);

            let pressure = summary.pressure_summary.as_ref().expect("pressure summary");
            assert_eq!(pressure.backpressure_events, 1);
            assert_eq!(pressure.flush_batches, 1);
            assert_eq!(pressure.total_blocks_flushed, 42);
        });
    }

    #[test]
    fn evidence_summary_aggregates_contention_rollup() {
        let ledger = concat!(
            "{\"timestamp_ns\":100,\"event_type\":\"merge_proof_checked\",\"block_group\":0,",
            "\"merge_proof_checked\":{\"txn_id\":11,\"block_id\":7,",
            "\"proof_variant\":\"AppendOnly\",\"valid\":true}}\n",
            "{\"timestamp_ns\":200,\"event_type\":\"merge_proof_checked\",\"block_group\":0,",
            "\"merge_proof_checked\":{\"txn_id\":12,\"block_id\":8,",
            "\"proof_variant\":\"AppendOnly\",\"valid\":false,",
            "\"rejection_reason\":\"overlap\"}}\n",
            "{\"timestamp_ns\":300,\"event_type\":\"merge_applied\",\"block_group\":0,",
            "\"merge_applied\":{\"txn_id\":13,\"merged_block_count\":2,",
            "\"combined_write_set_bytes\":4096,\"proof_variant\":\"AppendOnly\"}}\n",
            "{\"timestamp_ns\":400,\"event_type\":\"merge_rejected\",\"block_group\":0,",
            "\"merge_rejected\":{\"txn_id\":14,\"block_id\":9,",
            "\"proof_variant\":\"AppendOnly\",\"reason\":\"merge_validation_failed\"}}\n",
            "{\"timestamp_ns\":500,\"event_type\":\"policy_switched\",\"block_group\":0,",
            "\"policy_switched\":{\"from_policy\":\"Strict\",\"to_policy\":\"SafeMerge\",",
            "\"expected_loss_delta\":0.125,\"trigger_reason\":\"contention_rate_change\"}}\n",
            "{\"timestamp_ns\":600,\"event_type\":\"contention_sample\",\"block_group\":0,",
            "\"contention_sample\":{\"conflict_rate\":0.25,",
            "\"merge_success_rate\":0.5,\"abort_rate\":0.125,",
            "\"total_commits\":101,\"total_conflicts\":25,",
            "\"total_merges\":12,\"total_aborts\":3,",
            "\"effective_policy\":\"SafeMerge\"}}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records =
                load_evidence_records(&path, None, None, Some("contention"), None).expect("load");
            let summary = crate::cmd_evidence::build_summary_for_test(&records, Some("contention"));
            let contention = summary
                .contention_summary
                .as_ref()
                .expect("contention summary");

            assert_eq!(summary.total_records, 6);
            assert_eq!(contention.merge_proofs_checked, 2);
            assert_eq!(contention.merge_proofs_valid, 1);
            assert_eq!(contention.merge_proofs_invalid, 1);
            assert_eq!(contention.merges_applied, 1);
            assert_eq!(contention.merges_rejected, 1);
            assert_eq!(contention.total_merged_blocks, 2);
            assert_eq!(contention.total_combined_write_set_bytes, 4096);
            assert_eq!(contention.policy_switches, 1);
            assert_eq!(contention.contention_samples, 1);
            assert_eq!(contention.latest_conflict_rate, Some(0.25));
            assert_eq!(contention.latest_merge_success_rate, Some(0.5));
            assert_eq!(contention.latest_abort_rate, Some(0.125));
            assert_eq!(contention.latest_total_commits, Some(101));
            assert_eq!(contention.latest_total_conflicts, Some(25));
            assert_eq!(contention.latest_total_merges, Some(12));
            assert_eq!(contention.latest_total_aborts, Some(3));
            assert_eq!(
                contention.latest_effective_policy.as_deref(),
                Some("SafeMerge")
            );
        });
    }

    #[test]
    fn evidence_summary_json_schema_has_required_fields() {
        let ledger = "{\"timestamp_ns\":100,\"event_type\":\"repair_failed\",\"block_group\":1}\n";
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records =
                load_evidence_records(&path, None, None, None, None).expect("load should succeed");
            let summary =
                crate::cmd_evidence::build_summary_for_test(&records, Some("repair-failures"));
            let json_val = serde_json::to_value(&summary).expect("serialize summary");
            // Required top-level fields
            assert!(json_val.get("total_records").is_some());
            assert!(json_val.get("event_type_counts").is_some());
            assert!(json_val.get("block_groups_seen").is_some());
            assert!(json_val.get("preset").is_some());
            // Conditional fields omitted when empty
            assert!(json_val.get("replay_summary").is_none());
            assert!(json_val.get("pressure_summary").is_none());
            assert!(json_val.get("contention_summary").is_none());
        });
    }

    #[test]
    fn evidence_summary_normalizes_block_groups() {
        let ledger = concat!(
            "{\"timestamp_ns\":100,\"event_type\":\"repair_failed\",\"block_group\":7}\n",
            "{\"timestamp_ns\":200,\"event_type\":\"repair_succeeded\",\"block_group\":0}\n",
            "{\"timestamp_ns\":300,\"event_type\":\"repair_attempted\",\"block_group\":3}\n",
            "{\"timestamp_ns\":400,\"event_type\":\"scrub_cycle_complete\",\"block_group\":7}\n",
            "{\"timestamp_ns\":500,\"event_type\":\"corruption_detected\",\"block_group\":3}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records =
                load_evidence_records(&path, None, None, None, None).expect("load should succeed");
            let summary =
                crate::cmd_evidence::build_summary_for_test(&records, Some("repair-failures"));
            assert_eq!(summary.block_groups_seen, vec![3, 7]);
        });
    }

    #[test]
    fn evidence_record_json_schema_stability() {
        // Verify that EvidenceRecord JSON contains expected top-level keys.
        let json_str = r#"{"timestamp_ns":1,"event_type":"repair_failed","block_group":2}"#;
        let record: EvidenceRecord = serde_json::from_str(json_str).expect("parse");
        let round_trip = serde_json::to_value(&record).expect("serialize");
        assert!(round_trip.get("timestamp_ns").is_some());
        assert!(round_trip.get("event_type").is_some());
        assert!(round_trip.get("block_group").is_some());
        // event_type is serialized as snake_case
        assert_eq!(round_trip["event_type"], "repair_failed");
    }

    #[test]
    fn build_ext4_group_info_reads_descriptors_from_disk_regions() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let sb =
            super::Ext4Superblock::parse_from_image(&image).expect("parse test ext4 superblock");
        let expected_groups = usize::try_from(sb.groups_count()).expect("groups_count fits usize");

        with_temp_image_path(&image, |path| {
            let groups = build_ext4_group_info(&path, &sb).expect("build ext4 group info");
            assert_eq!(groups.len(), expected_groups);
            assert_eq!(groups[0].group, 0);
        });
    }

    #[test]
    fn build_ext4_group_info_rejects_excessive_group_count_before_allocation() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let mut image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;
        let mut blocks_per_group = [0_u8; 4];
        blocks_per_group.copy_from_slice(&image[sb_off + 0x20..sb_off + 0x24]);
        let blocks_per_group = u32::from_le_bytes(blocks_per_group);
        let excessive_blocks = MAX_EXT4_INFO_GROUPS
            .saturating_add(1)
            .saturating_mul(blocks_per_group);
        image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&excessive_blocks.to_le_bytes());

        let sb =
            super::Ext4Superblock::parse_from_image(&image).expect("parse malformed superblock");
        assert!(
            sb.groups_count() > MAX_EXT4_INFO_GROUPS,
            "test fixture must advertise more groups than the info cap"
        );

        with_temp_image_path(&image, |path| {
            let err = build_ext4_group_info(&path, &sb)
                .expect_err("excessive group count must reject before reading descriptors");
            let message = format!("{err:#}");
            assert!(
                message.contains("exceeds supported info scan cap"),
                "unexpected error: {message}"
            );
        });
    }

    #[test]
    fn build_ext4_repair_group_specs_rejects_excessive_group_count_before_allocation() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let mut image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;
        let mut blocks_per_group = [0_u8; 4];
        blocks_per_group.copy_from_slice(&image[sb_off + 0x20..sb_off + 0x24]);
        let blocks_per_group = u32::from_le_bytes(blocks_per_group);
        let excessive_blocks = MAX_EXT4_REPAIR_GROUP_SPECS
            .saturating_add(1)
            .saturating_mul(blocks_per_group);
        image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&excessive_blocks.to_le_bytes());

        let sb =
            super::Ext4Superblock::parse_from_image(&image).expect("parse malformed superblock");
        assert!(
            sb.groups_count() > MAX_EXT4_REPAIR_GROUP_SPECS,
            "test fixture must advertise more groups than the repair cap"
        );

        let err = build_ext4_repair_group_specs(&sb)
            .expect_err("excessive group count must reject before reserving specs");
        let message = format!("{err:#}");
        assert!(
            message.contains("exceeds supported repair scan cap"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn read_ext4_group_desc_from_path_reads_single_descriptor_window() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let sb =
            super::Ext4Superblock::parse_from_image(&image).expect("parse test ext4 superblock");

        with_temp_image_path(&image, |path| {
            let (desc, raw) = read_ext4_group_desc_from_path(&path, &sb, 0)
                .expect("read ext4 group descriptor from path");
            assert_eq!(desc.inode_table, 5);
            assert_eq!(raw.len(), usize::from(sb.group_desc_size()));
        });
    }

    #[test]
    fn read_ext4_inode_from_path_reads_inode_window() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let sb =
            super::Ext4Superblock::parse_from_image(&image).expect("parse test ext4 superblock");

        with_temp_image_path(&image, |path| {
            let (inode, raw) = read_ext4_inode_from_path(&path, &sb, ffs_types::InodeNumber(2))
                .expect("read ext4 inode from path");
            assert_eq!(raw.len(), usize::from(sb.inode_size));
            assert_eq!(inode.mode, 0);
        });
    }

    #[test]
    fn log_format_parser_supports_human_and_json() {
        assert_eq!(
            LogFormat::parse("human").expect("parse human"),
            LogFormat::Human
        );
        assert_eq!(
            LogFormat::parse("JSON").expect("parse json"),
            LogFormat::Json
        );
        assert!(LogFormat::parse("invalid").is_err());
    }

    #[test]
    fn json_log_serializes_domain_fields() {
        let _guard = log_contract_guard();
        let buffer = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_max_level(tracing::Level::INFO)
            .with_writer(buffer.clone())
            .finish();

        let dispatch = tracing::Dispatch::new(subscriber);
        let _default = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();

        info!(
            target: "ffs::test",
            event_name = "transaction_commit",
            txn_id = 42_u64,
            write_set_size = 3_u64,
            duration_us = 900_u64,
            "transaction_commit"
        );

        let json = parse_first_json_line(&buffer);
        assert_eq!(json["event_name"], "transaction_commit");
        assert_eq!(json["txn_id"], 42);
        assert_eq!(json["write_set_size"], 3);
        assert_eq!(json["duration_us"], 900);
        assert_eq!(json["target"], "ffs::test");
        assert_eq!(json["level"], "INFO");
    }

    #[test]
    fn json_log_preserves_span_context() {
        let _guard = log_contract_guard();
        let buffer = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_max_level(tracing::Level::INFO)
            .with_writer(buffer.clone())
            .finish();

        let dispatch = tracing::Dispatch::new(subscriber);
        let _default = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();

        {
            let span = info_span!("mount", image = "/tmp/ext4.img", mode = "ro");
            let _guard = span.enter();
            info!(target: "ffs::test", action = "mount_begin", "mount_begin");
        }

        let json = parse_first_json_line(&buffer);
        assert_eq!(json["action"], "mount_begin");
        assert_eq!(json["span"]["name"], "mount");
        assert_eq!(json["span"]["image"], "/tmp/ext4.img");
        assert_eq!(json["span"]["mode"], "ro");
    }

    #[test]
    fn ext4_mount_replay_mode_is_persistent_for_rw() {
        assert_eq!(ext4_mount_replay_mode(true), Ext4JournalReplayMode::Apply);
        assert_eq!(
            ext4_mount_replay_mode(false),
            Ext4JournalReplayMode::SimulateOverlay
        );
    }

    #[test]
    fn mount_runtime_config_rejects_timeout_for_standard_mode() {
        let err = MountRuntimeConfig {
            mode: MountRuntimeMode::Standard,
            managed_unmount_timeout_secs: Some(15),
        }
        .validate()
        .expect_err("standard mode with managed timeout should fail");
        let message = format!("{err:#}");
        assert!(
            message.contains(
                "--managed-unmount-timeout-secs requires --runtime-mode managed or per-core"
            ),
            "unexpected validation message: {message}"
        );
    }

    #[test]
    fn mount_runtime_config_accepts_managed_timeout() {
        let cfg = MountRuntimeConfig {
            mode: MountRuntimeMode::Managed,
            managed_unmount_timeout_secs: Some(45),
        }
        .validate()
        .expect("managed mode with timeout should validate");
        assert_eq!(cfg.managed_unmount_timeout_secs(), 45);
    }

    #[test]
    fn mount_runtime_mode_scenario_ids_are_stable() {
        assert_eq!(
            MountRuntimeMode::Standard.scenario_id(false),
            "cli_mount_runtime_standard_ro"
        );
        assert_eq!(
            MountRuntimeMode::Managed.scenario_id(true),
            "cli_mount_runtime_managed_rw"
        );
        assert_eq!(
            MountRuntimeMode::PerCore.scenario_id(false),
            "cli_mount_runtime_per_core_ro"
        );
    }

    #[test]
    fn mount_background_scrub_defaults_to_read_only_auto() {
        let cfg = MountBackgroundScrubConfig::resolve(
            MountBackgroundScrubRequest::new(
                MountAccessMode::ReadOnly,
                MountBackgroundScrubMode::Auto,
                MountBackgroundRepairMode::Disabled,
            ),
            None,
            None,
        )
        .expect("read-only default should resolve");
        assert!(cfg.enabled);
        assert!(!cfg.explicit);
        assert!(!cfg.repair_writes_enabled);
        assert_eq!(
            cfg.interval_secs,
            super::DEFAULT_MOUNT_BACKGROUND_SCRUB_INTERVAL_SECS
        );
        assert!(cfg.ledger_path.is_none());
    }

    #[test]
    fn mount_background_scrub_defaults_off_for_read_write() {
        let cfg = MountBackgroundScrubConfig::resolve(
            MountBackgroundScrubRequest::new(
                MountAccessMode::ReadWrite,
                MountBackgroundScrubMode::Auto,
                MountBackgroundRepairMode::Disabled,
            ),
            None,
            None,
        )
        .expect("read-write default should resolve");
        assert!(!cfg.enabled);
        assert!(!cfg.explicit);
        assert!(!cfg.repair_writes_enabled);
    }

    #[test]
    fn mount_background_scrub_flag_forces_read_write_detection() {
        let cfg = MountBackgroundScrubConfig::resolve(
            MountBackgroundScrubRequest::new(
                MountAccessMode::ReadWrite,
                MountBackgroundScrubMode::Enabled,
                MountBackgroundRepairMode::Disabled,
            ),
            Some(11),
            Some(PathBuf::from("/tmp/ffs-scrub.jsonl")),
        )
        .expect("explicit background scrub should resolve");
        assert!(cfg.enabled);
        assert!(cfg.explicit);
        assert!(!cfg.repair_writes_enabled);
        assert_eq!(cfg.interval_secs, 11);
        assert_eq!(cfg.ledger_path, Some(PathBuf::from("/tmp/ffs-scrub.jsonl")));
    }

    #[test]
    fn mount_background_scrub_rejects_disabled_interval() {
        let err = MountBackgroundScrubConfig::resolve(
            MountBackgroundScrubRequest::new(
                MountAccessMode::ReadOnly,
                MountBackgroundScrubMode::Disabled,
                MountBackgroundRepairMode::Disabled,
            ),
            Some(3),
            None,
        )
        .expect_err("disabled scrub cannot accept an interval");
        assert!(
            err.to_string()
                .contains("--background-scrub-interval-secs requires background scrub")
        );
    }

    #[test]
    fn mount_background_scrub_rejects_read_write_interval_without_opt_in() {
        let err = MountBackgroundScrubConfig::resolve(
            MountBackgroundScrubRequest::new(
                MountAccessMode::ReadWrite,
                MountBackgroundScrubMode::Auto,
                MountBackgroundRepairMode::Disabled,
            ),
            Some(3),
            None,
        )
        .expect_err("read-write mount requires explicit scrub opt-in for interval");
        assert!(
            err.to_string()
                .contains("--background-scrub-interval-secs requires background scrub")
        );
    }

    #[test]
    fn mount_background_scrub_rejects_read_write_ledger_without_opt_in() {
        let err = MountBackgroundScrubConfig::resolve(
            MountBackgroundScrubRequest::new(
                MountAccessMode::ReadWrite,
                MountBackgroundScrubMode::Auto,
                MountBackgroundRepairMode::Disabled,
            ),
            None,
            Some(PathBuf::from("/tmp/scrub.jsonl")),
        )
        .expect_err("read-write mount requires explicit scrub opt-in for ledger");
        assert!(
            err.to_string()
                .contains("--background-scrub-ledger requires background scrub")
        );
    }

    #[test]
    fn mount_background_repair_implies_scrub_for_read_only_mount() {
        let cfg = MountBackgroundScrubConfig::resolve(
            MountBackgroundScrubRequest::new(
                MountAccessMode::ReadOnly,
                MountBackgroundScrubMode::Auto,
                MountBackgroundRepairMode::Enabled,
            ),
            Some(7),
            Some(PathBuf::from("/tmp/ffs-repair.jsonl")),
        )
        .expect("background repair should imply scrub");
        assert!(cfg.enabled);
        assert!(cfg.explicit);
        assert!(cfg.repair_writes_enabled);
        assert_eq!(cfg.interval_secs, 7);
        assert_eq!(
            cfg.ledger_path,
            Some(PathBuf::from("/tmp/ffs-repair.jsonl"))
        );
    }

    #[test]
    fn mount_background_repair_implies_scrub_for_read_write_mount() {
        let cfg = MountBackgroundScrubConfig::resolve(
            MountBackgroundScrubRequest::new(
                MountAccessMode::ReadWrite,
                MountBackgroundScrubMode::Auto,
                MountBackgroundRepairMode::Enabled,
            ),
            Some(7),
            Some(PathBuf::from("/tmp/ffs-rw-repair.jsonl")),
        )
        .expect("read-write background repair should resolve after serialization gate");
        assert!(cfg.enabled);
        assert!(cfg.explicit);
        assert!(cfg.repair_writes_enabled);
        assert_eq!(cfg.interval_secs, 7);
        assert_eq!(
            cfg.ledger_path,
            Some(PathBuf::from("/tmp/ffs-rw-repair.jsonl"))
        );
    }

    #[test]
    fn mount_background_repair_rejects_missing_ledger() {
        let err = MountBackgroundScrubConfig::resolve(
            MountBackgroundScrubRequest::new(
                MountAccessMode::ReadOnly,
                MountBackgroundScrubMode::Auto,
                MountBackgroundRepairMode::Enabled,
            ),
            None,
            None,
        )
        .expect_err("background repair needs durable evidence");
        assert!(
            err.to_string()
                .contains("--background-repair requires --background-scrub-ledger")
        );
    }

    #[test]
    fn mount_background_repair_rejects_no_background_scrub() {
        let err = MountBackgroundScrubConfig::resolve(
            MountBackgroundScrubRequest::new(
                MountAccessMode::ReadOnly,
                MountBackgroundScrubMode::Disabled,
                MountBackgroundRepairMode::Enabled,
            ),
            None,
            Some(PathBuf::from("/tmp/ffs-repair.jsonl")),
        )
        .expect_err("background repair cannot disable scrub");
        assert!(
            err.to_string()
                .contains("--background-repair cannot be combined")
        );
    }

    #[test]
    fn mount_background_repair_rejects_read_write_missing_ledger() {
        let err = MountBackgroundScrubConfig::resolve(
            MountBackgroundScrubRequest::new(
                MountAccessMode::ReadWrite,
                MountBackgroundScrubMode::Auto,
                MountBackgroundRepairMode::Enabled,
            ),
            None,
            None,
        )
        .expect_err("read-write background repair needs durable evidence");
        assert!(
            err.to_string()
                .contains("--background-repair requires --background-scrub-ledger")
        );
    }

    #[test]
    fn mount_background_scrub_can_start_and_stop_for_ext4() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        with_temp_image_path(&image, |path| {
            let cx = asupersync::Cx::for_testing();
            let open_fs =
                super::OpenFs::open_with_options(&cx, &path, &super::OpenOptions::default())
                    .expect("test ext4 image should open");
            let cfg = MountBackgroundScrubConfig::resolve(
                MountBackgroundScrubRequest::new(
                    MountAccessMode::ReadOnly,
                    MountBackgroundScrubMode::Enabled,
                    MountBackgroundRepairMode::Disabled,
                ),
                Some(1),
                None,
            )
            .expect("background scrub config should resolve");
            let mut guard = start_mount_background_scrub(
                &path,
                &open_fs,
                &cfg,
                None,
                "mount-bg-scrub-test",
                "cli_mount_background_scrub_ro",
            )
            .expect("background scrub should start")
            .expect("background scrub should be enabled");
            guard.stop();
        });
    }

    #[test]
    fn mount_operation_id_reflects_runtime_mode() {
        let image = PathBuf::from("/tmp/fs.img");
        let mountpoint = PathBuf::from("/tmp/mnt");
        let standard = mount_operation_id(&image, &mountpoint, MountRuntimeMode::Standard, false);
        let managed = mount_operation_id(&image, &mountpoint, MountRuntimeMode::Managed, false);
        assert_ne!(
            standard, managed,
            "operation ids should differ when runtime mode differs"
        );
    }

    #[test]
    fn mount_runtime_selection_log_contains_required_fields() {
        let _guard = log_contract_guard();
        let buffer = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_max_level(tracing::Level::INFO)
            .with_writer(buffer.clone())
            .finish();

        let dispatch = tracing::Dispatch::new(subscriber);
        let _default = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();

        let runtime = MountRuntimeConfig {
            mode: MountRuntimeMode::Standard,
            managed_unmount_timeout_secs: None,
        }
        .validate()
        .expect("runtime config should validate");
        log_mount_runtime_selected(
            "mount-op-test",
            runtime.mode.scenario_id(false),
            runtime,
            false,
            true,
            false,
        );

        let json = parse_first_json_line(&buffer);
        assert_eq!(json["operation_id"], "mount-op-test");
        assert_eq!(json["scenario_id"], "cli_mount_runtime_standard_ro");
        assert_eq!(json["outcome"], "runtime_mode_selected");
        assert_eq!(json["runtime_mode"], "standard");
        assert_eq!(json["managed_unmount_timeout_secs"], 30);
    }

    #[test]
    fn mount_runtime_rejection_log_contains_error_class_fields() {
        let _guard = log_contract_guard();
        let buffer = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_max_level(tracing::Level::ERROR)
            .with_writer(buffer.clone())
            .finish();

        let dispatch = tracing::Dispatch::new(subscriber);
        let _default = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();

        let runtime = MountRuntimeConfig {
            mode: MountRuntimeMode::Managed,
            managed_unmount_timeout_secs: Some(12),
        }
        .validate()
        .expect("managed runtime config should validate");
        log_mount_runtime_rejected(
            "mount-op-reject",
            runtime.mode.scenario_id(true),
            runtime,
            true,
            "runtime_mode_unavailable",
            "managed mode denied by operator policy",
        );

        let json = parse_first_json_line(&buffer);
        assert_eq!(json["operation_id"], "mount-op-reject");
        assert_eq!(json["scenario_id"], "cli_mount_runtime_managed_rw");
        assert_eq!(json["outcome"], "runtime_mode_rejected");
        assert_eq!(json["error_class"], "runtime_mode_unavailable");
        assert_eq!(json["reason"], "managed mode denied by operator policy");
        assert_eq!(json["runtime_mode"], "managed");
    }

    #[test]
    fn repair_coordination_claim_log_contains_required_fields() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let _guard = log_contract_guard();
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let buffer = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_max_level(tracing::Level::INFO)
            .with_writer(buffer.clone())
            .finish();

        let dispatch = tracing::Dispatch::new(subscriber);
        let _default = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();

        with_temp_image_path(&image, |path| {
            let decision = coordinate_repair_write_access(
                &crate::cli_cx(),
                "ffs::test",
                REPAIR_COORDINATION_SCENARIO_REPAIR,
                "repair",
                &path,
                true,
            );
            assert!(decision.writes_allowed);
        });

        let json = parse_first_json_line(&buffer);
        assert_eq!(json["scenario_id"], REPAIR_COORDINATION_SCENARIO_REPAIR);
        assert_eq!(json["outcome"], "applied");
        assert_eq!(json["error_class"], "none");
        assert_eq!(json["command"], "repair");
        assert_eq!(json["level"], "INFO");
        assert_eq!(json["target"], "ffs::test");
        assert!(
            json["operation_id"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert!(
            json["coordination_file"]
                .as_str()
                .is_some_and(|value| { value.ends_with(".ffs-repair-owner.json") })
        );
        assert_eq!(json["local_host"], json["owner_host"]);
    }

    #[test]
    fn repair_coordination_rejection_log_contains_error_class_fields() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let _guard = log_contract_guard();
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let buffer = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_max_level(tracing::Level::INFO)
            .with_writer(buffer.clone())
            .finish();

        let dispatch = tracing::Dispatch::new(subscriber);
        let _default = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();

        with_temp_image_path(&image, |path| {
            write_test_coordination_record(&path, "remote-host");
            let decision = coordinate_repair_write_access(
                &crate::cli_cx(),
                "ffs::test",
                REPAIR_COORDINATION_SCENARIO_REPAIR,
                "repair",
                &path,
                true,
            );
            assert!(!decision.writes_allowed);
        });

        // The lease protocol also emits its own `ffs::repair::ownership` logs,
        // so select the CLI coordination event explicitly rather than the
        // first line.
        let logs = parse_json_logs(&buffer);
        let json = logs
            .iter()
            .find(|line| line["event_name"] == "repair_coordination_rejected")
            .expect("expected a repair_coordination_rejected log line");
        assert_eq!(json["scenario_id"], REPAIR_COORDINATION_SCENARIO_REPAIR);
        assert_eq!(json["outcome"], "rejected");
        assert_eq!(json["error_class"], "foreign_lease_active");
        assert_eq!(json["command"], "repair");
        assert_eq!(json["level"], "WARN");
        assert_eq!(json["target"], "ffs::test");
        assert_eq!(json["owner_host"], "remote-host");
        assert!(
            json["operation_id"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
    }

    #[test]
    fn info_cmd_accepts_clean_ext4_mmp_state() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image =
            build_test_ext4_image_with_mmp(EXT4_VALID_FS, ffs_ondisk::ext4::EXT4_MMP_SEQ_CLEAN);

        with_temp_image_path(&image, |path| {
            super::info_cmd(
                &path,
                InfoCommandOptions {
                    sections: InfoSections::empty(),
                    json: true,
                },
            )
            .expect("clean MMP state should remain readable through info");
        });
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn mount_cmd_logs_ext4_mmp_refusal_states() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let cases = [
            (
                "fsck",
                ffs_ondisk::ext4::EXT4_MMP_SEQ_FSCK,
                "fsck_in_progress",
                "fsck",
                None,
                "ext4 MMP block reports fsck in progress; refusing mount",
            ),
            (
                "active",
                42_u32,
                "active_writer_maybe",
                "active",
                Some(42_u32),
                "another writer may be active",
            ),
            (
                "unsafe_unknown",
                0_u32,
                "unsafe_unknown_status",
                "unsafe_unknown",
                Some(0_u32),
                "unsafe/unknown; refusing mount",
            ),
        ];

        for (label, seq, error_class, status_class, expected_sequence, needle) in cases {
            let _guard = log_contract_guard();
            let buffer = SharedLogBuffer::default();
            let subscriber = tracing_subscriber::fmt()
                .json()
                .flatten_event(true)
                .with_current_span(true)
                .with_span_list(true)
                .with_max_level(tracing::Level::ERROR)
                .with_writer(buffer.clone())
                .finish();

            let dispatch = tracing::Dispatch::new(subscriber);
            let _default = tracing::dispatcher::set_default(&dispatch);
            tracing::callsite::rebuild_interest_cache();

            let image = build_test_ext4_image_with_mmp(EXT4_VALID_FS, seq);
            with_temp_image_path(&image, |path| {
                let err = mount_cmd(
                    &path,
                    &PathBuf::from("/definitely/not-used"),
                    &MountCmdOptions {
                        allow_other: false,
                        read_write: true,
                        btrfs_rw_ephemeral_ok: false,
                        mount_mode: MountMode::Compat,
                        btrfs_mount_selection: BtrfsMountSelection::DefaultRoot,
                        ext4_data_err_policy: Ext4DataErrPolicy::Ignore,
                        ext4_verify_journal_checksums: true,
                        runtime: MountRuntimeConfig {
                            mode: MountRuntimeMode::Standard,
                            managed_unmount_timeout_secs: None,
                        },
                        adaptive_runtime: MountAdaptiveRuntimeConfig::disabled(),
                        adaptive_runtime_summary: MountAdaptiveRuntimeSummaryConfig::disabled(),
                        background_scrub: test_mount_background_scrub_disabled(),
                        writeback_cache: MountWritebackCacheConfig::disabled(),
                        console: MountConsoleConfig::default(),
                    },
                )
                .expect_err("non-clean MMP state should reject mount before FUSE starts");

                let message = format!("{err:#}");
                assert!(
                    message.contains("failed to open filesystem image"),
                    "expected mount open context for {label}, got: {message}"
                );
                assert!(
                    message.contains(needle),
                    "expected stable refusal detail for {label}, got: {message}"
                );
            });

            let logs = parse_json_logs(&buffer);
            let rejected = logs.iter().find(|entry| {
                entry.get("message").and_then(Value::as_str) == Some("mount_open_rejected")
            });
            assert!(
                rejected.is_some(),
                "missing mount_open_rejected log for {label}: {logs:?}"
            );
            let rejected = rejected.expect("mount_open_rejected log should exist after assert");
            assert_eq!(
                rejected.get("outcome").and_then(Value::as_str),
                Some("mount_open_rejected"),
                "unexpected outcome for {label}"
            );
            assert_eq!(
                rejected.get("error_class").and_then(Value::as_str),
                Some(error_class),
                "unexpected error_class for {label}"
            );
            assert_eq!(
                rejected.get("mmp_status_class").and_then(Value::as_str),
                Some(status_class),
                "unexpected mmp_status_class for {label}"
            );
            assert_eq!(
                rejected.get("errno").and_then(Value::as_i64),
                Some(i64::from(libc::EOPNOTSUPP)),
                "unexpected errno for {label}"
            );
            assert_eq!(
                rejected.get("mmp_sequence").and_then(Value::as_u64),
                expected_sequence.map(u64::from),
                "unexpected mmp_sequence for {label}"
            );
        }
    }

    #[test]
    fn mount_cmd_managed_mode_fails_at_image_open_not_validation() {
        let _guard = log_contract_guard();
        let err = mount_cmd(
            &PathBuf::from("/definitely/missing.img"),
            &PathBuf::from("/definitely/missing-mountpoint"),
            &MountCmdOptions {
                allow_other: false,
                read_write: false,
                btrfs_rw_ephemeral_ok: false,
                mount_mode: MountMode::Compat,
                btrfs_mount_selection: BtrfsMountSelection::DefaultRoot,
                ext4_data_err_policy: Ext4DataErrPolicy::Ignore,
                ext4_verify_journal_checksums: true,
                runtime: MountRuntimeConfig {
                    mode: MountRuntimeMode::Managed,
                    managed_unmount_timeout_secs: Some(30),
                },
                adaptive_runtime: MountAdaptiveRuntimeConfig::disabled(),
                adaptive_runtime_summary: MountAdaptiveRuntimeSummaryConfig::disabled(),
                background_scrub: test_mount_background_scrub_disabled(),
                writeback_cache: MountWritebackCacheConfig::disabled(),
                console: MountConsoleConfig::default(),
            },
        )
        .expect_err("managed mode with missing image should fail at open");
        let message = format!("{err:#}");
        // Managed mode is wired — the error should come from image open, not
        // from a "not wired" rejection.
        assert!(
            message.contains("failed to open filesystem image"),
            "expected image-open failure, got: {message}"
        );
    }

    #[test]
    fn mount_cmd_per_core_mode_fails_at_image_open_not_validation() {
        let _guard = log_contract_guard();
        let err = mount_cmd(
            &PathBuf::from("/definitely/missing.img"),
            &PathBuf::from("/definitely/missing-mountpoint"),
            &MountCmdOptions {
                allow_other: false,
                read_write: false,
                btrfs_rw_ephemeral_ok: false,
                mount_mode: MountMode::Compat,
                btrfs_mount_selection: BtrfsMountSelection::DefaultRoot,
                ext4_data_err_policy: Ext4DataErrPolicy::Ignore,
                ext4_verify_journal_checksums: true,
                runtime: MountRuntimeConfig {
                    mode: MountRuntimeMode::PerCore,
                    managed_unmount_timeout_secs: None,
                },
                adaptive_runtime: MountAdaptiveRuntimeConfig::disabled(),
                adaptive_runtime_summary: MountAdaptiveRuntimeSummaryConfig::disabled(),
                background_scrub: test_mount_background_scrub_disabled(),
                writeback_cache: MountWritebackCacheConfig::disabled(),
                console: MountConsoleConfig::default(),
            },
        )
        .expect_err("per-core mode with missing image should fail at open");
        let message = format!("{err:#}");
        assert!(
            message.contains("failed to open filesystem image"),
            "expected image-open failure, got: {message}"
        );
    }

    #[test]
    fn parse_btrfs_mount_selection_defaults_to_root() {
        let selection =
            parse_btrfs_mount_selection(None, None).expect("default selection should parse");
        assert_eq!(selection, BtrfsMountSelection::DefaultRoot);
    }

    #[test]
    fn parse_btrfs_mount_selection_accepts_subvol_flag() {
        let selection = parse_btrfs_mount_selection(Some("home".to_owned()), None)
            .expect("subvolume selection should parse");
        assert_eq!(selection, BtrfsMountSelection::Subvolume("home".to_owned()));
    }

    #[test]
    fn parse_btrfs_mount_selection_accepts_snapshot_flag() {
        let selection = parse_btrfs_mount_selection(None, Some("snap-1".to_owned()))
            .expect("snapshot selection should parse");
        assert_eq!(
            selection,
            BtrfsMountSelection::Snapshot("snap-1".to_owned())
        );
    }

    #[test]
    fn parse_btrfs_mount_selection_rejects_conflicting_flags() {
        let err = parse_btrfs_mount_selection(Some("home".to_owned()), Some("snap-1".to_owned()))
            .expect_err("conflicting mount selections should be rejected");
        let message = err.to_string();
        assert!(
            message.contains("mutually exclusive"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn build_mount_open_options_defaults_to_btrfs_root_selection() {
        let open_options = build_mount_open_options(&MountCmdOptions {
            allow_other: false,
            read_write: false,
            btrfs_rw_ephemeral_ok: false,
            mount_mode: MountMode::Compat,
            btrfs_mount_selection: BtrfsMountSelection::DefaultRoot,
            ext4_data_err_policy: Ext4DataErrPolicy::Ignore,
            ext4_verify_journal_checksums: true,
            runtime: MountRuntimeConfig {
                mode: MountRuntimeMode::Standard,
                managed_unmount_timeout_secs: None,
            },
            adaptive_runtime: MountAdaptiveRuntimeConfig::disabled(),
            adaptive_runtime_summary: MountAdaptiveRuntimeSummaryConfig::disabled(),
            background_scrub: test_mount_background_scrub_disabled(),
            writeback_cache: MountWritebackCacheConfig::disabled(),
            console: MountConsoleConfig::default(),
        });
        assert_eq!(
            open_options.btrfs_mount_selection,
            BtrfsMountSelection::DefaultRoot
        );
    }

    #[test]
    fn build_mount_open_options_threads_explicit_btrfs_subvolume_selection() {
        let open_options = build_mount_open_options(&MountCmdOptions {
            allow_other: false,
            read_write: true,
            btrfs_rw_ephemeral_ok: false,
            mount_mode: MountMode::Compat,
            btrfs_mount_selection: BtrfsMountSelection::Subvolume("home".to_owned()),
            ext4_data_err_policy: Ext4DataErrPolicy::Ignore,
            ext4_verify_journal_checksums: true,
            runtime: MountRuntimeConfig {
                mode: MountRuntimeMode::Standard,
                managed_unmount_timeout_secs: None,
            },
            adaptive_runtime: MountAdaptiveRuntimeConfig::disabled(),
            adaptive_runtime_summary: MountAdaptiveRuntimeSummaryConfig::disabled(),
            background_scrub: test_mount_background_scrub_disabled(),
            writeback_cache: MountWritebackCacheConfig::disabled(),
            console: MountConsoleConfig::default(),
        });
        assert_eq!(
            open_options.btrfs_mount_selection,
            BtrfsMountSelection::Subvolume("home".to_owned())
        );
        assert_eq!(
            open_options.ext4_journal_replay_mode,
            ext4_mount_replay_mode(true)
        );
    }

    #[test]
    fn build_mount_open_options_threads_explicit_btrfs_snapshot_selection() {
        let open_options = build_mount_open_options(&MountCmdOptions {
            allow_other: false,
            read_write: false,
            btrfs_rw_ephemeral_ok: false,
            mount_mode: MountMode::Native,
            btrfs_mount_selection: BtrfsMountSelection::Snapshot("snap-1".to_owned()),
            ext4_data_err_policy: Ext4DataErrPolicy::Abort,
            ext4_verify_journal_checksums: false,
            runtime: MountRuntimeConfig {
                mode: MountRuntimeMode::Standard,
                managed_unmount_timeout_secs: None,
            },
            adaptive_runtime: MountAdaptiveRuntimeConfig::disabled(),
            adaptive_runtime_summary: MountAdaptiveRuntimeSummaryConfig::disabled(),
            background_scrub: test_mount_background_scrub_disabled(),
            writeback_cache: MountWritebackCacheConfig::disabled(),
            console: MountConsoleConfig::default(),
        });
        assert_eq!(
            open_options.btrfs_mount_selection,
            BtrfsMountSelection::Snapshot("snap-1".to_owned())
        );
        assert_eq!(open_options.mount_mode, MountMode::Native);
        assert_eq!(open_options.ext4_data_err_policy, Ext4DataErrPolicy::Abort);
        assert!(!open_options.ext4_verify_journal_checksums);
    }

    #[test]
    fn mount_cmd_missing_btrfs_subvolume_reports_stable_open_error() {
        let image = build_test_btrfs_image_with_root_inode_item();
        with_temp_image_path(&image, |path| {
            let err = mount_cmd(
                &path,
                &PathBuf::from("/definitely/not-used"),
                &MountCmdOptions {
                    allow_other: false,
                    read_write: false,
                    btrfs_rw_ephemeral_ok: false,
                    mount_mode: MountMode::Compat,
                    btrfs_mount_selection: BtrfsMountSelection::Subvolume("missing".to_owned()),
                    ext4_data_err_policy: Ext4DataErrPolicy::Ignore,
                    ext4_verify_journal_checksums: true,
                    runtime: MountRuntimeConfig {
                        mode: MountRuntimeMode::Standard,
                        managed_unmount_timeout_secs: None,
                    },
                    adaptive_runtime: MountAdaptiveRuntimeConfig::disabled(),
                    adaptive_runtime_summary: MountAdaptiveRuntimeSummaryConfig::disabled(),
                    background_scrub: test_mount_background_scrub_disabled(),
                    writeback_cache: MountWritebackCacheConfig::disabled(),
                    console: MountConsoleConfig::default(),
                },
            )
            .expect_err("missing btrfs subvolume should fail before FUSE mount");

            let message = format!("{err:#}");
            assert!(
                message.contains("failed to open filesystem image"),
                "expected mount open context, got: {message}"
            );
            assert!(
                message.contains("btrfs subvolume `missing`"),
                "expected stable missing subvolume detail, got: {message}"
            );
            println!(
                "SCENARIO_RESULT|scenario_id=cli_mount_btrfs_missing_subvolume_open_error|outcome=PASS|detail=missing=NotFound"
            );
        });
    }

    #[test]
    fn mount_cmd_missing_btrfs_snapshot_reports_stable_open_error() {
        let image = build_test_btrfs_image_with_root_inode_item();
        with_temp_image_path(&image, |path| {
            let err = mount_cmd(
                &path,
                &PathBuf::from("/definitely/not-used"),
                &MountCmdOptions {
                    allow_other: false,
                    read_write: false,
                    btrfs_rw_ephemeral_ok: false,
                    mount_mode: MountMode::Compat,
                    btrfs_mount_selection: BtrfsMountSelection::Snapshot(
                        "missing-snapshot".to_owned(),
                    ),
                    ext4_data_err_policy: Ext4DataErrPolicy::Ignore,
                    ext4_verify_journal_checksums: true,
                    runtime: MountRuntimeConfig {
                        mode: MountRuntimeMode::Standard,
                        managed_unmount_timeout_secs: None,
                    },
                    adaptive_runtime: MountAdaptiveRuntimeConfig::disabled(),
                    adaptive_runtime_summary: MountAdaptiveRuntimeSummaryConfig::disabled(),
                    background_scrub: test_mount_background_scrub_disabled(),
                    writeback_cache: MountWritebackCacheConfig::disabled(),
                    console: MountConsoleConfig::default(),
                },
            )
            .expect_err("missing btrfs snapshot should fail before FUSE mount");

            let message = format!("{err:#}");
            assert!(
                message.contains("failed to open filesystem image"),
                "expected mount open context, got: {message}"
            );
            assert!(
                message.contains("btrfs snapshot `missing-snapshot`"),
                "expected stable missing snapshot detail, got: {message}"
            );
            println!(
                "SCENARIO_RESULT|scenario_id=cli_mount_btrfs_missing_snapshot_open_error|outcome=PASS|detail=missing=NotFound"
            );
        });
    }

    #[test]
    fn open_filesystem_for_mount_scopes_named_btrfs_subvolume_operator_path() {
        let image = build_test_btrfs_image_with_named_mount_selections();
        with_temp_image_path(&image, |path| {
            let fs = open_filesystem_for_mount(
                &path,
                &MountCmdOptions {
                    allow_other: false,
                    read_write: false,
                    btrfs_rw_ephemeral_ok: false,
                    mount_mode: MountMode::Compat,
                    btrfs_mount_selection: BtrfsMountSelection::Subvolume("home".to_owned()),
                    ext4_data_err_policy: Ext4DataErrPolicy::Ignore,
                    ext4_verify_journal_checksums: true,
                    runtime: MountRuntimeConfig {
                        mode: MountRuntimeMode::Standard,
                        managed_unmount_timeout_secs: None,
                    },
                    adaptive_runtime: MountAdaptiveRuntimeConfig::disabled(),
                    adaptive_runtime_summary: MountAdaptiveRuntimeSummaryConfig::disabled(),
                    background_scrub: test_mount_background_scrub_disabled(),
                    writeback_cache: MountWritebackCacheConfig::disabled(),
                    console: MountConsoleConfig::default(),
                },
            )
            .expect("named btrfs subvolume should open through mount operator path");

            let cx = asupersync::Cx::for_testing();
            let ctx = fs.btrfs_context().expect("btrfs context should be present");
            assert_eq!(ctx.subvol_objectid, ffs_btrfs::BTRFS_FIRST_FREE_OBJECTID);
            assert_eq!(ctx.subvol_root_dirid, 256);

            let root_attr = fs
                .getattr(&cx, ffs_types::InodeNumber(1))
                .expect("get mounted subvolume root");
            assert_eq!(root_attr.ino, ffs_types::InodeNumber(1));

            let child = fs
                .lookup(
                    &cx,
                    ffs_types::InodeNumber(1),
                    std::ffi::OsStr::new("selected.txt"),
                )
                .expect("lookup file through selected subvolume root");
            let entries = fs
                .readdir(&cx, ffs_types::InodeNumber(1), 0)
                .expect("readdir selected subvolume root");
            let data = fs
                .read(&cx, child.ino, 0, 128)
                .expect("read selected subvolume file");

            assert_eq!(entries.len(), 3);
            assert_eq!(entries[2].name, b"selected.txt");
            assert_eq!(&data, b"hello from subvolume root\n");

            println!(
                "SCENARIO_RESULT|scenario_id=cli_mount_btrfs_named_subvolume_operator_path|outcome=PASS|detail=selector=home_root_scoped=selected.txt"
            );
        });
    }

    #[test]
    fn open_filesystem_for_mount_scopes_named_btrfs_snapshot_operator_path() {
        let image = build_test_btrfs_image_with_named_mount_selections();
        with_temp_image_path(&image, |path| {
            let fs = open_filesystem_for_mount(
                &path,
                &MountCmdOptions {
                    allow_other: false,
                    read_write: false,
                    btrfs_rw_ephemeral_ok: false,
                    mount_mode: MountMode::Compat,
                    btrfs_mount_selection: BtrfsMountSelection::Snapshot("snap-home".to_owned()),
                    ext4_data_err_policy: Ext4DataErrPolicy::Ignore,
                    ext4_verify_journal_checksums: true,
                    runtime: MountRuntimeConfig {
                        mode: MountRuntimeMode::Standard,
                        managed_unmount_timeout_secs: None,
                    },
                    adaptive_runtime: MountAdaptiveRuntimeConfig::disabled(),
                    adaptive_runtime_summary: MountAdaptiveRuntimeSummaryConfig::disabled(),
                    background_scrub: test_mount_background_scrub_disabled(),
                    writeback_cache: MountWritebackCacheConfig::disabled(),
                    console: MountConsoleConfig::default(),
                },
            )
            .expect("named btrfs snapshot should open through mount operator path");

            let cx = asupersync::Cx::for_testing();
            let ctx = fs.btrfs_context().expect("btrfs context should be present");
            assert_eq!(
                ctx.subvol_objectid,
                ffs_btrfs::BTRFS_FIRST_FREE_OBJECTID + 1
            );
            assert_eq!(ctx.subvol_root_dirid, 256);

            let root_attr = fs
                .getattr(&cx, ffs_types::InodeNumber(1))
                .expect("get mounted snapshot root");
            assert_eq!(root_attr.ino, ffs_types::InodeNumber(1));

            let child = fs
                .lookup(
                    &cx,
                    ffs_types::InodeNumber(1),
                    std::ffi::OsStr::new("selected.txt"),
                )
                .expect("lookup file through selected snapshot root");
            let entries = fs
                .readdir(&cx, ffs_types::InodeNumber(1), 0)
                .expect("readdir selected snapshot root");
            let data = fs
                .read(&cx, child.ino, 0, 128)
                .expect("read selected snapshot file");

            assert_eq!(entries.len(), 3);
            assert_eq!(entries[2].name, b"selected.txt");
            assert_eq!(&data, b"hello from snapshot root\n");

            println!(
                "SCENARIO_RESULT|scenario_id=cli_mount_btrfs_named_snapshot_operator_path|outcome=PASS|detail=selector=snap-home_root_scoped=selected.txt"
            );
        });
    }

    #[test]
    fn cli_parses_mount_per_core_runtime() {
        let cli = Cli::try_parse_from([
            "ffs",
            "mount",
            "--runtime-mode",
            "per-core",
            "/tmp/fs.img",
            "/tmp/mnt",
        ])
        .expect("mount command with per-core runtime should parse");

        match cli.command {
            Command::Mount {
                runtime_mode,
                managed_unmount_timeout_secs,
                ..
            } => {
                assert_eq!(runtime_mode, MountRuntimeMode::PerCore);
                assert_eq!(managed_unmount_timeout_secs, None);
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn mount_default_mode_is_standard_and_stable() {
        // Verify that the default runtime mode for mount is Standard.
        // This is a stability contract: changing the default is a breaking change.
        let cli = Cli::try_parse_from(["ffs", "mount", "/img", "/mnt"])
            .expect("mount should parse with defaults");
        match cli.command {
            Command::Mount { runtime_mode, .. } => {
                assert_eq!(
                    runtime_mode,
                    MountRuntimeMode::Standard,
                    "default mount runtime mode must remain standard"
                );
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn mount_native_flag_defaults_to_false() {
        let cli = Cli::try_parse_from(["ffs", "mount", "/img", "/mnt"])
            .expect("mount should parse with defaults");
        match cli.command {
            Command::Mount { native, .. } => {
                assert!(!native, "default native flag must be false (compat mode)");
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn mount_native_flag_opt_in() {
        let cli = Cli::try_parse_from(["ffs", "mount", "--native", "/img", "/mnt"])
            .expect("mount with --native should parse");
        match cli.command {
            Command::Mount { native, .. } => {
                assert!(native, "--native flag should set native to true");
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn mount_writeback_cache_flag_defaults_to_false() {
        let cli = Cli::try_parse_from(["ffs", "mount", "/img", "/mnt"])
            .expect("mount should parse with defaults");
        match cli.command {
            Command::Mount {
                writeback_cache,
                writeback_cache_gate,
                writeback_cache_ordering_oracle,
                writeback_cache_crash_replay_oracle,
                ..
            } => {
                assert!(!writeback_cache);
                assert_eq!(writeback_cache_gate, None);
                assert_eq!(writeback_cache_ordering_oracle, None);
                assert_eq!(writeback_cache_crash_replay_oracle, None);
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn mount_writeback_cache_flag_opt_in_parses_gate_paths() {
        let cli = Cli::try_parse_from([
            "ffs",
            "mount",
            "--rw",
            "--writeback-cache",
            "--writeback-cache-gate",
            "/tmp/gate.json",
            "--writeback-cache-ordering-oracle",
            "/tmp/oracle.json",
            "--writeback-cache-crash-replay-oracle",
            "/tmp/crash-replay.json",
            "/img",
            "/mnt",
        ])
        .expect("mount with explicit writeback-cache gate should parse");
        match cli.command {
            Command::Mount {
                rw,
                writeback_cache,
                writeback_cache_gate,
                writeback_cache_ordering_oracle,
                writeback_cache_crash_replay_oracle,
                ..
            } => {
                assert!(rw);
                assert!(writeback_cache);
                assert_eq!(writeback_cache_gate, Some(PathBuf::from("/tmp/gate.json")));
                assert_eq!(
                    writeback_cache_ordering_oracle,
                    Some(PathBuf::from("/tmp/oracle.json"))
                );
                assert_eq!(
                    writeback_cache_crash_replay_oracle,
                    Some(PathBuf::from("/tmp/crash-replay.json"))
                );
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn mount_writeback_cache_rejects_read_only_before_gate_io() {
        let options = test_mount_cmd_options(
            false,
            MountWritebackCacheConfig::from_cli(
                true,
                Some(PathBuf::from("/missing/gate.json")),
                Some(PathBuf::from("/missing/oracle.json")),
                Some(PathBuf::from("/missing/crash-replay.json")),
            ),
        );
        let err = validate_mount_writeback_cache_request(
            Path::new("/img"),
            Path::new("/mnt"),
            &options,
            "mount-op",
            "cli_mount_runtime_standard_ro",
        )
        .expect_err("read-only writeback_cache should reject before reading gate files");
        let message = format!("{err:#}");
        assert!(
            message.contains("--writeback-cache requires --rw"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn mount_writeback_cache_rejects_missing_gate_with_stable_diagnostic() {
        let options = test_mount_cmd_options(
            true,
            MountWritebackCacheConfig::from_cli(
                true,
                None,
                Some(PathBuf::from("/tmp/oracle")),
                Some(PathBuf::from("/tmp/crash-replay")),
            ),
        );
        let first = validate_mount_writeback_cache_request(
            Path::new("/img"),
            Path::new("/mnt"),
            &options,
            "mount-op-a",
            "cli_mount_runtime_standard_rw",
        )
        .expect_err("missing gate should reject");
        let second = validate_mount_writeback_cache_request(
            Path::new("/img"),
            Path::new("/mnt"),
            &options,
            "mount-op-b",
            "cli_mount_runtime_standard_rw",
        )
        .expect_err("repeated missing gate should reject the same way");
        assert_eq!(first.to_string(), second.to_string());
        assert!(
            first
                .to_string()
                .contains("--writeback-cache requires --writeback-cache-gate")
        );
    }

    #[test]
    fn mount_writeback_cache_rejects_gate_paths_without_opt_in() {
        let options = test_mount_cmd_options(
            true,
            MountWritebackCacheConfig::from_cli(
                false,
                Some(PathBuf::from("/tmp/gate")),
                Some(PathBuf::from("/tmp/oracle")),
                Some(PathBuf::from("/tmp/crash-replay")),
            ),
        );
        let err = validate_mount_writeback_cache_request(
            Path::new("/img"),
            Path::new("/mnt"),
            &options,
            "mount-op",
            "cli_mount_runtime_standard_rw",
        )
        .expect_err("gate paths without opt-in should reject");
        let message = err.to_string();
        assert!(
            message.contains("require --writeback-cache"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn mount_writeback_cache_runtime_kill_switch_rejects_before_gate_io() {
        let options = test_mount_cmd_options(
            true,
            MountWritebackCacheConfig::from_cli_with_runtime_kill_switch(
                true,
                Some(PathBuf::from("/missing/gate.json")),
                Some(PathBuf::from("/missing/oracle.json")),
                Some(PathBuf::from("/missing/crash-replay.json")),
                true,
            ),
        );
        let err = validate_mount_writeback_cache_request(
            Path::new("/img"),
            Path::new("/mnt"),
            &options,
            "mount-op",
            "cli_mount_runtime_standard_rw",
        )
        .expect_err("runtime kill switch should reject before reading gate files");
        let message = format!("{err:#}");
        assert!(
            message.contains(WRITEBACK_CACHE_KILL_SWITCH_ENV),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn mount_writeback_cache_rejects_stale_gate_artifact() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (gate_path, oracle_path, crash_replay_path) =
            write_writeback_artifacts(temp.path(), |gate| {
                gate["runtime_guard"]["gate_fresh"] = serde_json::Value::Bool(false);
            });
        let options = test_mount_cmd_options(
            true,
            MountWritebackCacheConfig::from_cli(
                true,
                Some(gate_path),
                Some(oracle_path),
                Some(crash_replay_path),
            ),
        );
        let err = validate_mount_writeback_cache_request(
            Path::new("/img"),
            Path::new("/mnt"),
            &options,
            "mount-op",
            "cli_mount_runtime_standard_rw",
        )
        .expect_err("stale runtime gate should reject");
        let message = format!("{err:#}");
        assert!(
            message.contains("stale_gate_artifact"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn mount_writeback_cache_rejects_downgraded_feature_state_repeatedly() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (gate_path, oracle_path, crash_replay_path) =
            write_writeback_artifacts(temp.path(), |gate| {
                gate["runtime_guard"]["feature_state"] =
                    serde_json::Value::String("downgraded".to_owned());
            });
        let options = test_mount_cmd_options(
            true,
            MountWritebackCacheConfig::from_cli(
                true,
                Some(gate_path),
                Some(oracle_path),
                Some(crash_replay_path),
            ),
        );
        let first = validate_mount_writeback_cache_request(
            Path::new("/img"),
            Path::new("/mnt"),
            &options,
            "mount-op-a",
            "cli_mount_runtime_standard_rw",
        )
        .expect_err("downgraded feature state should reject");
        let second = validate_mount_writeback_cache_request(
            Path::new("/img"),
            Path::new("/mnt"),
            &options,
            "mount-op-b",
            "cli_mount_runtime_standard_rw",
        )
        .expect_err("repeated downgraded state should reject");
        assert_eq!(first.to_string(), second.to_string());
        let message = format!("{first:#}");
        assert!(
            message.contains("writeback_feature_downgraded"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn mount_writeback_cache_rejects_config_default_gate() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (gate_path, oracle_path, crash_replay_path) =
            write_writeback_artifacts(temp.path(), |gate| {
                gate["runtime_guard"]["config_source"] =
                    serde_json::Value::String("config_default".to_owned());
            });
        let options = test_mount_cmd_options(
            true,
            MountWritebackCacheConfig::from_cli(
                true,
                Some(gate_path),
                Some(oracle_path),
                Some(crash_replay_path),
            ),
        );
        let err = validate_mount_writeback_cache_request(
            Path::new("/img"),
            Path::new("/mnt"),
            &options,
            "mount-op",
            "cli_mount_runtime_standard_rw",
        )
        .expect_err("config-default gate should reject");
        let message = format!("{err:#}");
        assert!(
            message.contains("config_default_attempt"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn mount_writeback_cache_rejects_host_manifest_mismatch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (gate_path, oracle_path, crash_replay_path) =
            write_writeback_artifacts(temp.path(), |gate| {
                gate["runtime_guard"]["lane_manifest_matches_host"] =
                    serde_json::Value::Bool(false);
            });
        let options = test_mount_cmd_options(
            true,
            MountWritebackCacheConfig::from_cli(
                true,
                Some(gate_path),
                Some(oracle_path),
                Some(crash_replay_path),
            ),
        );
        let err = validate_mount_writeback_cache_request(
            Path::new("/img"),
            Path::new("/mnt"),
            &options,
            "mount-op",
            "cli_mount_runtime_standard_rw",
        )
        .expect_err("host-mismatch gate should reject");
        let message = format!("{err:#}");
        assert!(
            message.contains("host_capability_mismatch"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn mount_writeback_cache_rejects_missing_crash_replay_oracle() {
        let options = test_mount_cmd_options(
            true,
            MountWritebackCacheConfig::from_cli(
                true,
                Some(PathBuf::from("/tmp/gate")),
                Some(PathBuf::from("/tmp/oracle")),
                None,
            ),
        );
        let err = validate_mount_writeback_cache_request(
            Path::new("/img"),
            Path::new("/mnt"),
            &options,
            "mount-op",
            "cli_mount_runtime_standard_rw",
        )
        .expect_err("missing crash/replay oracle should reject before reading artifacts");
        let message = err.to_string();
        assert!(
            message.contains("--writeback-cache requires --writeback-cache-crash-replay-oracle"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn mount_writeback_cache_accepts_complete_gate_ordering_and_crash_replay_oracles() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (gate_path, oracle_path, crash_replay_path) =
            write_happy_writeback_artifacts(temp.path());
        let options = test_mount_cmd_options(
            true,
            MountWritebackCacheConfig::from_cli(
                true,
                Some(gate_path),
                Some(oracle_path),
                Some(crash_replay_path),
            ),
        );
        validate_mount_writeback_cache_request(
            Path::new("/img"),
            Path::new("/mnt"),
            &options,
            "mount-op",
            "cli_mount_runtime_standard_rw",
        )
        .expect("complete gate, ordering oracle, and crash/replay oracle should accept before image open");
    }

    #[test]
    fn mount_ext4_data_err_abort_defaults_to_false() {
        let cli = Cli::try_parse_from(["ffs", "mount", "/img", "/mnt"])
            .expect("mount should parse with defaults");
        match cli.command {
            Command::Mount {
                ext4_data_err_abort,
                ..
            } => {
                assert!(
                    !ext4_data_err_abort,
                    "default ext4 data_err=abort flag must be false"
                );
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn mount_ext4_data_err_abort_opt_in() {
        let cli = Cli::try_parse_from(["ffs", "mount", "--ext4-data-err-abort", "/img", "/mnt"])
            .expect("mount with --ext4-data-err-abort should parse");
        match cli.command {
            Command::Mount {
                ext4_data_err_abort,
                ..
            } => {
                assert!(
                    ext4_data_err_abort,
                    "--ext4-data-err-abort should opt into abort policy"
                );
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn mount_ext4_nojournal_checksum_defaults_to_false() {
        let cli = Cli::try_parse_from(["ffs", "mount", "/img", "/mnt"])
            .expect("mount should parse with defaults");
        match cli.command {
            Command::Mount {
                ext4_nojournal_checksum,
                ..
            } => {
                assert!(
                    !ext4_nojournal_checksum,
                    "default ext4 nojournal_checksum flag must be false"
                );
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn mount_ext4_nojournal_checksum_opt_in() {
        let cli =
            Cli::try_parse_from(["ffs", "mount", "--ext4-nojournal-checksum", "/img", "/mnt"])
                .expect("mount with --ext4-nojournal-checksum should parse");
        match cli.command {
            Command::Mount {
                ext4_nojournal_checksum,
                ..
            } => {
                assert!(
                    ext4_nojournal_checksum,
                    "--ext4-nojournal-checksum should disable checksum verification"
                );
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn mount_runtime_config_default_timeout_is_30s() {
        let cfg = MountRuntimeConfig {
            mode: MountRuntimeMode::Managed,
            managed_unmount_timeout_secs: None,
        }
        .validate()
        .expect("managed without explicit timeout should validate");
        assert_eq!(
            cfg.managed_unmount_timeout_secs(),
            30,
            "default managed unmount timeout must be 30s"
        );
    }

    #[test]
    fn mount_per_core_config_rejects_timeout_with_standard() {
        // Per-core timeout is also rejected in standard mode (same validation path).
        let err = MountRuntimeConfig {
            mode: MountRuntimeMode::Standard,
            managed_unmount_timeout_secs: Some(42),
        }
        .validate()
        .expect_err("standard mode with timeout should be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--managed-unmount-timeout-secs requires"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn mount_per_core_config_accepts_timeout() {
        let cfg = MountRuntimeConfig {
            mode: MountRuntimeMode::PerCore,
            managed_unmount_timeout_secs: Some(60),
        }
        .validate()
        .expect("per-core mode with timeout should validate");
        assert_eq!(cfg.managed_unmount_timeout_secs(), 60);
    }

    #[test]
    fn mount_scenario_ids_cover_all_mode_rw_combinations() {
        // Exhaustive check that all (mode, rw) pairs produce distinct scenario IDs.
        let mut ids = std::collections::HashSet::new();
        for mode in [
            MountRuntimeMode::Standard,
            MountRuntimeMode::Managed,
            MountRuntimeMode::PerCore,
        ] {
            for rw in [false, true] {
                let id = mode.scenario_id(rw);
                assert!(
                    ids.insert(id),
                    "duplicate scenario_id: {id} for mode={mode:?} rw={rw}"
                );
            }
        }
        assert_eq!(ids.len(), 6, "expected 6 distinct scenario IDs");
    }

    #[test]
    fn mount_operation_ids_differ_by_rw() {
        let image = PathBuf::from("/tmp/fs.img");
        let mountpoint = PathBuf::from("/tmp/mnt");
        let ro = mount_operation_id(&image, &mountpoint, MountRuntimeMode::Standard, false);
        let rw = mount_operation_id(&image, &mountpoint, MountRuntimeMode::Standard, true);
        assert_ne!(
            ro, rw,
            "operation ids should differ when read_write differs"
        );
    }

    #[test]
    fn cli_parses_info_command_with_all_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "info",
            "--groups",
            "--mvcc",
            "--repair",
            "--journal",
            "--json",
            "/tmp/fs.img",
        ])
        .expect("info command should parse");

        match cli.command {
            Command::Info {
                image,
                groups,
                mvcc,
                repair,
                journal,
                json,
            } => {
                assert_eq!(image, std::path::PathBuf::from("/tmp/fs.img"));
                assert!(groups);
                assert!(mvcc);
                assert!(repair);
                assert!(journal);
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Info { .. }),
                "expected info command"
            ),
        }
    }

    #[test]
    fn cli_parses_inspect_with_json() {
        let cli = Cli::try_parse_from(["ffs", "inspect", "--json", "/tmp/fs.img"])
            .expect("inspect command should parse");

        match cli.command {
            Command::Inspect { image, json, .. } => {
                assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Inspect { .. }),
                "expected inspect command"
            ),
        }
    }

    #[test]
    fn cli_parses_mvcc_stats_minimal() {
        let cli = Cli::try_parse_from(["ffs", "mvcc-stats", "/tmp/fs.img"])
            .expect("mvcc-stats command should parse");

        match cli.command {
            Command::MvccStats { image, json } => {
                assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                assert!(!json);
            }
            other => assert!(
                matches!(other, Command::MvccStats { .. }),
                "expected mvcc-stats command"
            ),
        }
    }

    #[test]
    fn cli_parses_info_command_without_optional_flags() {
        let cli = Cli::try_parse_from(["ffs", "info", "/tmp/fs.img"])
            .expect("minimal info command should parse");

        match cli.command {
            Command::Info {
                groups,
                mvcc,
                repair,
                journal,
                json,
                ..
            } => {
                assert!(!groups);
                assert!(!mvcc);
                assert!(!repair);
                assert!(!journal);
                assert!(!json);
            }
            other => assert!(
                matches!(other, Command::Info { .. }),
                "expected info command"
            ),
        }
    }

    #[test]
    fn cli_parses_dump_superblock_command_with_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "dump",
            "superblock",
            "--json",
            "--hex",
            "/tmp/fs.img",
        ])
        .expect("dump superblock command should parse");

        match cli.command {
            Command::Dump { command } => match command {
                DumpCommand::Superblock { image, json, hex } => {
                    assert_eq!(image, std::path::PathBuf::from("/tmp/fs.img"));
                    assert!(json);
                    assert!(hex);
                }
                other => assert!(
                    matches!(other, DumpCommand::Superblock { .. }),
                    "expected dump superblock command"
                ),
            },
            other => assert!(
                matches!(other, Command::Dump { .. }),
                "expected dump command"
            ),
        }
    }

    #[test]
    fn cli_parses_dump_group_command() {
        let cli = Cli::try_parse_from(["ffs", "dump", "group", "7", "/tmp/fs.img"])
            .expect("dump group command should parse");

        match cli.command {
            Command::Dump { command } => match command {
                DumpCommand::Group {
                    group,
                    image,
                    json,
                    hex,
                } => {
                    assert_eq!(group, 7);
                    assert_eq!(image, std::path::PathBuf::from("/tmp/fs.img"));
                    assert!(!json);
                    assert!(!hex);
                }
                other => assert!(
                    matches!(other, DumpCommand::Group { .. }),
                    "expected dump group command"
                ),
            },
            other => assert!(
                matches!(other, Command::Dump { .. }),
                "expected dump command"
            ),
        }
    }

    #[test]
    fn cli_parses_dump_inode_command_with_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "dump",
            "inode",
            "42",
            "--json",
            "--hex",
            "/tmp/fs.img",
        ])
        .expect("dump inode command should parse");

        match cli.command {
            Command::Dump { command } => match command {
                DumpCommand::Inode {
                    inode,
                    image,
                    json,
                    hex,
                } => {
                    assert_eq!(inode, 42);
                    assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                    assert!(json);
                    assert!(hex);
                }
                other => assert!(
                    matches!(other, DumpCommand::Inode { .. }),
                    "expected dump inode command"
                ),
            },
            other => assert!(
                matches!(other, Command::Dump { .. }),
                "expected dump command"
            ),
        }
    }

    #[test]
    fn cli_parses_dump_extents_command_minimal() {
        let cli = Cli::try_parse_from(["ffs", "dump", "extents", "11", "/tmp/fs.img"])
            .expect("dump extents command should parse");

        match cli.command {
            Command::Dump { command } => match command {
                DumpCommand::Extents {
                    inode,
                    image,
                    json,
                    hex,
                } => {
                    assert_eq!(inode, 11);
                    assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                    assert!(!json);
                    assert!(!hex);
                }
                other => assert!(
                    matches!(other, DumpCommand::Extents { .. }),
                    "expected dump extents command"
                ),
            },
            other => assert!(
                matches!(other, Command::Dump { .. }),
                "expected dump command"
            ),
        }
    }

    #[test]
    fn cli_parses_dump_dir_command_with_hex() {
        let cli = Cli::try_parse_from(["ffs", "dump", "dir", "2", "--hex", "/tmp/fs.img"])
            .expect("dump dir command should parse");

        match cli.command {
            Command::Dump { command } => match command {
                DumpCommand::Dir {
                    inode,
                    image,
                    json,
                    hex,
                } => {
                    assert_eq!(inode, 2);
                    assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                    assert!(!json);
                    assert!(hex);
                }
                other => assert!(
                    matches!(other, DumpCommand::Dir { .. }),
                    "expected dump dir command"
                ),
            },
            other => assert!(
                matches!(other, Command::Dump { .. }),
                "expected dump command"
            ),
        }
    }

    #[test]
    fn cli_parses_fsck_with_all_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "fsck",
            "-r",
            "-f",
            "-v",
            "--block-group",
            "3",
            "--json",
            "/tmp/fs.img",
        ])
        .expect("fsck command should parse");

        match cli.command {
            Command::Fsck {
                image,
                repair,
                force,
                verbose,
                block_group,
                json,
            } => {
                assert_eq!(image, std::path::PathBuf::from("/tmp/fs.img"));
                assert!(repair);
                assert!(force);
                assert!(verbose);
                assert_eq!(block_group, Some(3));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Fsck { .. }),
                "expected fsck command"
            ),
        }
    }

    #[test]
    fn cli_parses_fsck_minimal() {
        let cli = Cli::try_parse_from(["ffs", "fsck", "/tmp/fs.img"]).expect("fsck should parse");

        match cli.command {
            Command::Fsck {
                image,
                repair,
                force,
                verbose,
                block_group,
                json,
            } => {
                assert_eq!(image, std::path::PathBuf::from("/tmp/fs.img"));
                assert!(!repair);
                assert!(!force);
                assert!(!verbose);
                assert_eq!(block_group, None);
                assert!(!json);
            }
            other => assert!(
                matches!(other, Command::Fsck { .. }),
                "expected fsck command"
            ),
        }
    }

    #[test]
    fn cli_parses_repair_with_all_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "repair",
            "--full-scrub",
            "--block-group",
            "9",
            "--rebuild-symbols",
            "--verify-only",
            "--max-threads",
            "4",
            "--json",
            "/tmp/fs.img",
        ])
        .expect("repair command should parse");

        match cli.command {
            Command::Repair {
                image,
                full_scrub,
                block_group,
                rebuild_symbols,
                verify_only,
                max_threads,
                json,
            } => {
                assert_eq!(image, std::path::PathBuf::from("/tmp/fs.img"));
                assert!(full_scrub);
                assert_eq!(block_group, Some(9));
                assert!(rebuild_symbols);
                assert!(verify_only);
                assert_eq!(max_threads, Some(4));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Repair { .. }),
                "expected repair command"
            ),
        }
    }

    #[test]
    fn cli_parses_repair_minimal() {
        let cli =
            Cli::try_parse_from(["ffs", "repair", "/tmp/fs.img"]).expect("repair should parse");

        match cli.command {
            Command::Repair {
                image,
                full_scrub,
                block_group,
                rebuild_symbols,
                verify_only,
                max_threads,
                json,
            } => {
                assert_eq!(image, std::path::PathBuf::from("/tmp/fs.img"));
                assert!(!full_scrub);
                assert_eq!(block_group, None);
                assert!(!rebuild_symbols);
                assert!(!verify_only);
                assert_eq!(max_threads, None);
                assert!(!json);
            }
            other => assert!(
                matches!(other, Command::Repair { .. }),
                "expected repair command"
            ),
        }
    }

    #[test]
    fn cli_parses_mount_with_all_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "mount",
            "--runtime-mode",
            "standard",
            "--allow-other",
            "--rw",
            "--background-scrub",
            "--background-scrub-interval-secs",
            "9",
            "--background-scrub-ledger",
            "/tmp/scrub.jsonl",
            "/tmp/fs.img",
            "/tmp/mnt",
        ])
        .expect("mount command should parse");

        match cli.command {
            Command::Mount {
                image,
                mountpoint,
                runtime_mode,
                managed_unmount_timeout_secs,
                allow_other,
                rw,
                background_scrub,
                no_background_scrub,
                background_scrub_interval_secs,
                background_scrub_ledger,
                background_repair,
                native,
                ..
            } => {
                assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                assert_eq!(mountpoint, PathBuf::from("/tmp/mnt"));
                assert_eq!(runtime_mode, MountRuntimeMode::Standard);
                assert_eq!(managed_unmount_timeout_secs, None);
                assert!(allow_other);
                assert!(rw);
                assert!(background_scrub);
                assert!(!no_background_scrub);
                assert_eq!(background_scrub_interval_secs, Some(9));
                assert_eq!(
                    background_scrub_ledger,
                    Some(PathBuf::from("/tmp/scrub.jsonl"))
                );
                assert!(!background_repair);
                assert!(!native);
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn cli_parses_mount_minimal() {
        let cli = Cli::try_parse_from(["ffs", "mount", "/tmp/fs.img", "/tmp/mnt"])
            .expect("mount command should parse");

        match cli.command {
            Command::Mount {
                image,
                mountpoint,
                runtime_mode,
                managed_unmount_timeout_secs,
                allow_other,
                rw,
                background_scrub,
                no_background_scrub,
                background_scrub_interval_secs,
                background_scrub_ledger,
                background_repair,
                native,
                ..
            } => {
                assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                assert_eq!(mountpoint, PathBuf::from("/tmp/mnt"));
                assert_eq!(runtime_mode, MountRuntimeMode::Standard);
                assert_eq!(managed_unmount_timeout_secs, None);
                assert!(!allow_other);
                assert!(!rw);
                assert!(!background_scrub);
                assert!(!no_background_scrub);
                assert_eq!(background_scrub_interval_secs, None);
                assert_eq!(background_scrub_ledger, None);
                assert!(!background_repair);
                assert!(!native);
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn cli_parses_mount_background_repair_flag() {
        let cli = Cli::try_parse_from([
            "ffs",
            "mount",
            "--background-repair",
            "--background-scrub-ledger",
            "/tmp/repair.jsonl",
            "/tmp/fs.img",
            "/tmp/mnt",
        ])
        .expect("mount command with background repair should parse");

        match cli.command {
            Command::Mount {
                background_repair,
                background_scrub_ledger,
                ..
            } => {
                assert!(background_repair);
                assert_eq!(
                    background_scrub_ledger,
                    Some(PathBuf::from("/tmp/repair.jsonl"))
                );
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn cli_parses_read_write_mount_background_repair_flag() {
        let cli = Cli::try_parse_from([
            "ffs",
            "mount",
            "--rw",
            "--background-repair",
            "--background-scrub-ledger",
            "/tmp/rw-repair.jsonl",
            "/tmp/fs.img",
            "/tmp/mnt",
        ])
        .expect("read-write mount command with background repair should parse");

        match cli.command {
            Command::Mount {
                rw,
                background_repair,
                background_scrub_ledger,
                ..
            } => {
                assert!(rw);
                assert!(background_repair);
                assert_eq!(
                    background_scrub_ledger,
                    Some(PathBuf::from("/tmp/rw-repair.jsonl"))
                );
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn cli_parses_mount_managed_runtime_with_timeout() {
        let cli = Cli::try_parse_from([
            "ffs",
            "mount",
            "--runtime-mode",
            "managed",
            "--managed-unmount-timeout-secs",
            "42",
            "/tmp/fs.img",
            "/tmp/mnt",
        ])
        .expect("mount command with managed runtime should parse");

        match cli.command {
            Command::Mount {
                image,
                mountpoint,
                runtime_mode,
                managed_unmount_timeout_secs,
                allow_other,
                rw,
                native,
                ..
            } => {
                assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                assert_eq!(mountpoint, PathBuf::from("/tmp/mnt"));
                assert_eq!(runtime_mode, MountRuntimeMode::Managed);
                assert_eq!(managed_unmount_timeout_secs, Some(42));
                assert!(!allow_other);
                assert!(!rw);
                assert!(!native);
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn cli_parses_scrub_with_json() {
        let cli = Cli::try_parse_from(["ffs", "scrub", "--json", "/tmp/fs.img"])
            .expect("scrub command should parse");

        match cli.command {
            Command::Scrub { image, json } => {
                assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Scrub { .. }),
                "expected scrub command"
            ),
        }
    }

    #[test]
    fn cli_parses_scrub_minimal() {
        let cli = Cli::try_parse_from(["ffs", "scrub", "/tmp/fs.img"]).expect("scrub should parse");

        match cli.command {
            Command::Scrub { image, json } => {
                assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                assert!(!json);
            }
            other => assert!(
                matches!(other, Command::Scrub { .. }),
                "expected scrub command"
            ),
        }
    }

    #[test]
    fn cli_parses_parity_with_json() {
        let cli =
            Cli::try_parse_from(["ffs", "parity", "--json"]).expect("parity command should parse");

        match cli.command {
            Command::Parity { json } => {
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Parity { .. }),
                "expected parity command"
            ),
        }
    }

    #[test]
    fn cli_parses_parity_minimal() {
        let cli = Cli::try_parse_from(["ffs", "parity"]).expect("parity command should parse");

        match cli.command {
            Command::Parity { json } => {
                assert!(!json);
            }
            other => assert!(
                matches!(other, Command::Parity { .. }),
                "expected parity command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_with_all_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--json",
            "--event-type",
            "repair_succeeded",
            "--tail",
            "25",
            "--block-group",
            "7",
            "/tmp/evidence.jsonl",
        ])
        .expect("evidence command should parse");

        match cli.command {
            Command::Evidence {
                ledger,
                json,
                event_type,
                tail,
                block_group,
                preset,
                summary,
            } => {
                assert_eq!(ledger, PathBuf::from("/tmp/evidence.jsonl"));
                assert!(json);
                assert_eq!(event_type.as_deref(), Some("repair_succeeded"));
                assert_eq!(tail, Some(25));
                assert_eq!(block_group, Some(7));
                assert_eq!(preset, None);
                assert!(!summary);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_minimal() {
        let cli = Cli::try_parse_from(["ffs", "evidence", "/tmp/evidence.jsonl"])
            .expect("evidence command should parse");

        match cli.command {
            Command::Evidence {
                ledger,
                json,
                event_type,
                tail,
                block_group,
                preset,
                summary,
            } => {
                assert_eq!(ledger, PathBuf::from("/tmp/evidence.jsonl"));
                assert!(!json);
                assert_eq!(event_type, None);
                assert_eq!(tail, None);
                assert_eq!(block_group, None);
                assert_eq!(preset, None);
                assert!(!summary);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_with_preset() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--preset",
            "replay-anomalies",
            "--summary",
            "/tmp/evidence.jsonl",
        ])
        .expect("evidence command should parse");

        match cli.command {
            Command::Evidence {
                ledger,
                json,
                event_type,
                tail,
                block_group,
                preset,
                summary,
            } => {
                assert_eq!(ledger, PathBuf::from("/tmp/evidence.jsonl"));
                assert!(!json);
                assert_eq!(event_type, None);
                assert_eq!(tail, None);
                assert_eq!(block_group, None);
                assert_eq!(preset.as_deref(), Some("replay-anomalies"));
                assert!(summary);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_preset_repair_failures() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--preset",
            "repair-failures",
            "--json",
            "/tmp/evidence.jsonl",
        ])
        .expect("evidence command should parse");

        match cli.command {
            Command::Evidence { preset, json, .. } => {
                assert_eq!(preset.as_deref(), Some("repair-failures"));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_preset_pressure_transitions() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--preset",
            "pressure-transitions",
            "--tail",
            "10",
            "/tmp/evidence.jsonl",
        ])
        .expect("evidence command should parse");

        match cli.command {
            Command::Evidence { preset, tail, .. } => {
                assert_eq!(preset.as_deref(), Some("pressure-transitions"));
                assert_eq!(tail, Some(10));
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_preset_contention() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--preset",
            "contention",
            "--summary",
            "/tmp/evidence.jsonl",
        ])
        .expect("evidence command should parse");

        match cli.command {
            Command::Evidence {
                ledger,
                preset,
                summary,
                ..
            } => {
                assert_eq!(ledger, PathBuf::from("/tmp/evidence.jsonl"));
                assert_eq!(preset.as_deref(), Some("contention"));
                assert!(summary);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_preset_metrics() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--preset",
            "metrics",
            "--json",
            "/tmp/metrics.json",
        ])
        .expect("evidence metrics command should parse");

        match cli.command {
            Command::Evidence {
                ledger,
                preset,
                json,
                ..
            } => {
                assert_eq!(ledger, PathBuf::from("/tmp/metrics.json"));
                assert_eq!(preset.as_deref(), Some("metrics"));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_preset_cache() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--preset",
            "cache",
            "--json",
            "/tmp/cache-metrics.json",
        ])
        .expect("evidence cache command should parse");

        match cli.command {
            Command::Evidence {
                ledger,
                preset,
                json,
                ..
            } => {
                assert_eq!(ledger, PathBuf::from("/tmp/cache-metrics.json"));
                assert_eq!(preset.as_deref(), Some("cache"));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_preset_mvcc() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--preset",
            "mvcc",
            "--json",
            "/tmp/mvcc-metrics.json",
        ])
        .expect("evidence mvcc command should parse");

        match cli.command {
            Command::Evidence {
                ledger,
                preset,
                json,
                ..
            } => {
                assert_eq!(ledger, PathBuf::from("/tmp/mvcc-metrics.json"));
                assert_eq!(preset.as_deref(), Some("mvcc"));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_preset_repair_live() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--preset",
            "repair-live",
            "--json",
            "/tmp/repair-live-metrics.json",
        ])
        .expect("evidence repair-live command should parse");

        match cli.command {
            Command::Evidence {
                ledger,
                preset,
                json,
                ..
            } => {
                assert_eq!(ledger, PathBuf::from("/tmp/repair-live-metrics.json"));
                assert_eq!(preset.as_deref(), Some("repair-live"));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_mkfs_with_all_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "mkfs",
            "--size-mb",
            "128",
            "--block-size",
            "2048",
            "--label",
            "testvol",
            "--json",
            "/tmp/new.img",
        ])
        .expect("mkfs command should parse");

        match cli.command {
            Command::Mkfs {
                output,
                size_mb,
                block_size,
                label,
                json,
            } => {
                assert_eq!(output, PathBuf::from("/tmp/new.img"));
                assert_eq!(size_mb, 128);
                assert_eq!(block_size, 2048);
                assert_eq!(label, "testvol");
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Mkfs { .. }),
                "expected mkfs command"
            ),
        }
    }

    #[test]
    fn cli_parses_mkfs_minimal_uses_defaults() {
        let cli = Cli::try_parse_from(["ffs", "mkfs", "/tmp/new.img"])
            .expect("mkfs command should parse");

        match cli.command {
            Command::Mkfs {
                output,
                size_mb,
                block_size,
                label,
                json,
            } => {
                assert_eq!(output, PathBuf::from("/tmp/new.img"));
                assert_eq!(size_mb, 64);
                assert_eq!(block_size, 4096);
                assert_eq!(label, "frankenfs");
                assert!(!json);
            }
            other => assert!(
                matches!(other, Command::Mkfs { .. }),
                "expected mkfs command"
            ),
        }
    }

    #[test]
    fn cli_rejects_mount_without_mountpoint() {
        let result = Cli::try_parse_from(["ffs", "mount", "/tmp/fs.img"]);
        assert!(result.is_err(), "mount requires an image and mountpoint");
    }

    #[test]
    fn cli_rejects_scrub_without_image() {
        let result = Cli::try_parse_from(["ffs", "scrub"]);
        assert!(result.is_err(), "scrub requires an image path");
    }

    #[test]
    fn cli_rejects_parity_with_unexpected_positional() {
        let result = Cli::try_parse_from(["ffs", "parity", "/tmp/extra"]);
        assert!(result.is_err(), "parity should not accept positional args");
    }

    #[test]
    fn cli_rejects_evidence_non_numeric_tail() {
        let result = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--tail",
            "not-a-number",
            "/tmp/evidence.jsonl",
        ]);
        assert!(result.is_err(), "evidence --tail must be numeric");
    }

    #[test]
    fn cli_rejects_mkfs_non_numeric_size_mb() {
        let result =
            Cli::try_parse_from(["ffs", "mkfs", "--size-mb", "sixty-four", "/tmp/new.img"]);
        assert!(result.is_err(), "mkfs --size-mb must be numeric");
    }

    #[test]
    fn mkfs_cmd_rejects_size_mb_overflow() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let mut output = std::env::temp_dir();
        output.push(format!("ffs-cli-mkfs-overflow-{}-{ts}", std::process::id()));
        let too_large = u64::MAX / (1024 * 1024) + 1;

        let err = super::mkfs_cmd_with_program(
            &output,
            too_large,
            1024,
            "overflow",
            false,
            std::path::Path::new("mkfs.ext4"),
        )
        .expect_err("oversized mkfs requests should be rejected");
        let message = format!("{err:#}");
        assert!(
            message.contains("size_mb too large"),
            "expected overflow guardrail, got: {message}"
        );
        assert!(
            !output.exists(),
            "overflow check should run before creating the image file"
        );
    }

    #[test]
    fn mkfs_cmd_rejects_dash_prefixed_output() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let output = PathBuf::from(format!("-ffs-cli-mkfs-dash-{}-{ts}", std::process::id()));

        let err = super::mkfs_cmd_with_program(
            &output,
            8,
            1024,
            "dash",
            false,
            std::path::Path::new("mkfs.ext4"),
        )
        .expect_err("dash-prefixed output should be rejected");
        let message = format!("{err:#}");
        assert!(
            message.contains("must not start with '-'"),
            "expected dash-prefixed output guardrail, got: {message}"
        );
        assert!(
            !output.exists(),
            "dash-prefixed output guardrail should run before creating the image file"
        );
    }

    #[test]
    fn mkfs_cmd_rejects_existing_output_without_truncation() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let mut output = std::env::temp_dir();
        output.push(format!("ffs-cli-mkfs-exists-{}-{ts}", std::process::id()));

        let payload = b"already-here";
        std::fs::write(&output, payload).expect("seed existing output");

        let err = super::mkfs_cmd_with_program(
            &output,
            8,
            1024,
            "exists",
            false,
            std::path::Path::new("mkfs.ext4"),
        )
        .expect_err("existing output path should be rejected");
        let message = format!("{err:#}");
        assert!(
            message.contains("output file already exists"),
            "expected existing-output guardrail, got: {message}"
        );
        assert_eq!(
            std::fs::metadata(&output)
                .expect("stat existing output")
                .len(),
            payload.len() as u64,
            "existing output must not be truncated"
        );

        let _ = std::fs::remove_file(&output);
    }

    #[test]
    fn mkfs_cmd_preserves_output_image_when_mkfs_ext4_fails() {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();

        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "ffs-cli-mkfs-failure-{}-{ts}-{count}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).expect("create temporary mkfs test directory");

        let mut fake_mkfs = dir.clone();
        fake_mkfs.push("mkfs.ext4");
        std::fs::write(
            &fake_mkfs,
            "#!/bin/sh\nprintf 'simulated mkfs failure\\n' >&2\nexit 1\n",
        )
        .expect("write fake mkfs.ext4");
        let mut perms = std::fs::metadata(&fake_mkfs)
            .expect("stat fake mkfs.ext4")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_mkfs, perms).expect("chmod fake mkfs.ext4");

        let mut output = dir.clone();
        output.push("preserved.img");

        let err = super::mkfs_cmd_with_program(&output, 8, 1024, "failtest", false, &fake_mkfs)
            .expect_err("fake mkfs.ext4 failure should bubble up");
        let message = format!("{err:#}");
        assert!(
            message.contains("Preserved partial image"),
            "expected preserved-image guidance, got: {message}"
        );
        assert!(
            message.contains(&output.display().to_string()),
            "expected output path in error, got: {message}"
        );
        assert!(
            output.exists(),
            "mkfs failure must leave the sparse image in place"
        );
        assert_eq!(
            std::fs::metadata(&output)
                .expect("stat preserved output image")
                .len(),
            8 * 1024 * 1024,
            "preserved image should retain the requested size"
        );

        let _ = std::fs::remove_file(&output);
        let _ = std::fs::remove_file(&fake_mkfs);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn repair_worker_limit_defaults_to_single() {
        let (workers, capped) = repair_worker_limit(None);
        assert_eq!(workers, 1);
        assert_eq!(capped, None);
    }

    #[test]
    fn partition_scrub_range_covers_exact_range() {
        let ranges = partition_scrub_range(super::BlockNumber(10), 11, 3);
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0], (super::BlockNumber(10), 4));
        assert_eq!(ranges[1], (super::BlockNumber(14), 4));
        assert_eq!(ranges[2], (super::BlockNumber(18), 3));
    }

    #[test]
    fn merge_scrub_reports_accumulates_counts() {
        let merged = merge_scrub_reports(vec![
            super::ScrubReport {
                findings: Vec::new(),
                blocks_scanned: 10,
                blocks_corrupt: 2,
                blocks_io_error: 1,
            },
            super::ScrubReport {
                findings: Vec::new(),
                blocks_scanned: 7,
                blocks_corrupt: 0,
                blocks_io_error: 3,
            },
        ]);
        assert_eq!(merged.blocks_scanned, 17);
        assert_eq!(merged.blocks_corrupt, 2);
        assert_eq!(merged.blocks_io_error, 4);
    }

    #[test]
    fn ext4_clean_state_detection_matches_expected_flags() {
        assert!(ext4_appears_clean_state(0x0001));
        assert!(!ext4_appears_clean_state(0x0000));
        assert!(!ext4_appears_clean_state(0x0001 | 0x0002));
        assert!(!ext4_appears_clean_state(0x0001 | 0x0004));
    }

    #[test]
    fn summarize_repair_staleness_reports_zero_for_empty_input() {
        let summary = summarize_repair_staleness(&[]);
        assert_eq!(summary.total, 0);
        assert_eq!(summary.fresh, 0);
        assert_eq!(summary.stale, 0);
        assert_eq!(summary.untracked, 0);
    }

    #[test]
    fn summarize_repair_staleness_counts_mixed_states() {
        let staleness = vec![
            (0, Ext4RepairStaleness::Fresh),
            (1, Ext4RepairStaleness::Stale),
            (2, Ext4RepairStaleness::Untracked),
            (3, Ext4RepairStaleness::Fresh),
            (4, Ext4RepairStaleness::Stale),
        ];
        let summary = summarize_repair_staleness(&staleness);
        assert_eq!(summary.total, 5);
        assert_eq!(summary.fresh, 2);
        assert_eq!(summary.stale, 2);
        assert_eq!(summary.untracked, 1);
    }

    #[test]
    fn summarize_repair_staleness_counts_states_regardless_of_group_ids() {
        let staleness = vec![
            (42, Ext4RepairStaleness::Stale),
            (7, Ext4RepairStaleness::Fresh),
            (42, Ext4RepairStaleness::Fresh),
            (999, Ext4RepairStaleness::Untracked),
            (1, Ext4RepairStaleness::Stale),
        ];
        let summary = summarize_repair_staleness(&staleness);
        assert_eq!(summary.total, 5);
        assert_eq!(summary.fresh, 2);
        assert_eq!(summary.stale, 2);
        assert_eq!(summary.untracked, 1);
    }

    #[test]
    fn build_info_output_ext4_repair_metrics_fallback_sets_limitation() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);

        with_temp_image_path(&image, |path| {
            let cx = super::cli_cx();
            let open_opts = super::OpenOptions {
                ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
                ..super::OpenOptions::default()
            };
            let open_fs = super::OpenFs::open_with_options(&cx, &path, &open_opts)
                .expect("open ext4 image for info repair fallback test");

            // Keep `open_fs` valid but force the probe path to fail.
            let missing_path = path.with_extension("missing");
            let output = build_info_output(
                &missing_path,
                &cx,
                &open_fs,
                InfoCommandOptions {
                    sections: InfoSections::empty().with_repair(true),
                    json: false,
                },
            )
            .expect("build info output with repair section");

            let repair = output.repair.expect("repair section should be present");
            assert!(!repair.metrics_available);
            assert_eq!(
                repair.note,
                "live ext4 repair metrics unavailable (see limitations)"
            );
            assert_eq!(repair.groups_total, None);
            assert_eq!(repair.groups_fresh, None);
            assert_eq!(repair.groups_stale, None);
            assert_eq!(repair.groups_untracked, None);
            assert!(output.limitations.iter().any(|limitation| {
                limitation.contains("repair metrics probe failed for ext4 image")
            }));
        });
    }

    #[test]
    fn build_info_output_btrfs_groups_reports_chunk_layout() {
        let image = build_test_btrfs_image_with_root_inode_item_for_chunk(
            0x0,
            0x10000,
            0x20000,
            1 | 4, // DATA|METADATA
        );

        with_temp_image_path(&image, |path| {
            let cx = super::cli_cx();
            let open_fs =
                super::OpenFs::open_with_options(&cx, &path, &super::OpenOptions::default())
                    .expect("open btrfs image for info groups test");

            let output = build_info_output(
                &path,
                &cx,
                &open_fs,
                InfoCommandOptions {
                    sections: InfoSections::empty().with_groups(true),
                    json: false,
                },
            )
            .expect("build info output with btrfs groups");

            let groups = output.groups.expect("groups section should be present");
            match groups {
                super::GroupsInfoOutput::Btrfs { entries } => {
                    assert_eq!(entries.len(), 1);
                    let chunk = &entries[0];
                    assert_eq!(chunk.chunk_index, 0);
                    assert_eq!(chunk.logical_start, 0);
                    assert_eq!(chunk.logical_end_inclusive, 0x0_FFFF);
                    assert_eq!(chunk.logical_bytes, 0x10000);
                    assert_eq!(chunk.chunk_type_raw, 5);
                    assert_eq!(chunk.chunk_type_flags, vec!["DATA", "METADATA"]);
                    assert_eq!(chunk.stripe_count, 1);
                    assert_eq!(chunk.stripes.len(), 1);
                    assert_eq!(chunk.stripes[0].devid, 1);
                    assert_eq!(chunk.stripes[0].physical_start, 0x20000);
                    assert_eq!(chunk.stripes[0].physical_end_inclusive, 0x2_FFFF);
                }
                other @ super::GroupsInfoOutput::Ext4 { .. } => assert!(
                    matches!(other, super::GroupsInfoOutput::Btrfs { .. }),
                    "expected btrfs groups output"
                ),
            }

            assert!(!output.limitations.iter().any(|limitation| {
                limitation.contains("--groups is currently implemented for ext4 images only")
            }));
        });
    }

    #[test]
    fn build_dump_group_output_btrfs_returns_chunk_mapping() {
        let image = build_test_btrfs_image_with_root_inode_item_for_chunk(
            0x0,
            0x10000,
            0x20000,
            1 | 2, // DATA|SYSTEM
        );

        with_temp_image_path(&image, |path| {
            let output = super::build_dump_group_output(&path, 0, true)
                .expect("build dump group output for btrfs image");
            assert_eq!(output.filesystem, "btrfs");
            assert_eq!(output.group, 0);
            assert!(output.descriptor.is_none());
            let raw_hex = output
                .raw_hex
                .as_ref()
                .expect("btrfs chunk raw hex should be available");
            assert!(
                raw_hex.starts_with("00000000: 00 01 00 00 00 00 00 00 e4 00 00 00 00 00 00 00\n")
            );
            assert!(output.limitations.is_empty());

            let chunk = output
                .btrfs_chunk
                .expect("btrfs chunk should be present in dump output");
            assert_eq!(chunk.chunk_index, 0);
            assert_eq!(chunk.logical_start, 0);
            assert_eq!(chunk.logical_end_inclusive, 0x0_FFFF);
            assert_eq!(chunk.logical_bytes, 0x10000);
            assert_eq!(chunk.chunk_type_flags, vec!["DATA", "SYSTEM"]);
            assert_eq!(chunk.stripe_count, 1);
            assert_eq!(chunk.stripes.len(), 1);
            assert_eq!(chunk.stripes[0].physical_start, 0x20000);
            assert_eq!(chunk.stripes[0].physical_end_inclusive, 0x2_FFFF);
        });
    }

    #[test]
    fn build_dump_inode_output_btrfs_reads_root_inode_alias() {
        let image = build_test_btrfs_image_with_root_inode_item();
        with_temp_image_path(&image, |path| {
            let output = super::build_dump_inode_output(&path, 1, true)
                .expect("build dump inode output for btrfs image");

            assert_eq!(output.filesystem, "btrfs");
            assert!(output.ext4_parsed.is_none());
            let parsed = output
                .btrfs_parsed
                .as_ref()
                .expect("btrfs parsed inode should be present");
            assert_eq!(parsed.mode, 0o040_755);
            assert_eq!(parsed.uid, 1000);
            assert_eq!(parsed.gid, 1000);
            assert_eq!(parsed.nlink, 2);
            assert!(output.raw_hex.as_ref().is_some_and(|raw| !raw.is_empty()));
            assert!(
                output.limitations.iter().any(|limitation| {
                    limitation.contains("inode 1 maps to btrfs root objectid")
                })
            );
        });
    }

    #[test]
    fn build_dump_dir_output_btrfs_returns_vfs_directory_projection() {
        let image = build_test_btrfs_image_with_root_inode_item();
        with_temp_image_path(&image, |path| {
            let output = super::build_dump_dir_output(&path, 1, true)
                .expect("build dump dir output for btrfs image");

            assert_eq!(output.filesystem, "btrfs");
            assert_eq!(output.inode, 1);
            assert!(output.htree.is_none());
            // The root-only fixture has no on-disk directory-entry items.
            assert!(output.raw_hex_blocks.is_some());
            assert!(
                output
                    .raw_hex_blocks
                    .as_ref()
                    .is_some_and(std::vec::Vec::is_empty)
            );
            assert!(output.entries.iter().all(|entry| entry.rec_len == 0));
            assert!(output.entries.iter().any(|entry| entry.name == "."));
            assert!(output.entries.iter().any(|entry| entry.name == ".."));
            assert!(output.limitations.iter().any(|limitation| {
                limitation.contains("btrfs hex dump shows raw DIR_ITEM/DIR_INDEX payloads")
            }));
        });
    }

    #[test]
    fn build_dump_dir_output_btrfs_hex_returns_dir_index_payloads() {
        let image = build_test_btrfs_image_with_dir_index_entry();
        with_temp_image_path(&image, |path| {
            let output = super::build_dump_dir_output(&path, 1, true)
                .expect("build dump dir output for btrfs directory image");

            let raw_hex_blocks = output
                .raw_hex_blocks
                .as_ref()
                .expect("btrfs hex dump should include raw blocks");
            assert!(!raw_hex_blocks.is_empty());
            assert!(
                raw_hex_blocks
                    .iter()
                    .any(|block| block.item_kind.as_deref() == Some("dir_index"))
            );
            assert!(
                raw_hex_blocks
                    .iter()
                    .all(|block| !block.hex.trim().is_empty())
            );
            assert!(output.entries.iter().any(|entry| entry.name == "hello.txt"));
        });
    }

    #[test]
    fn build_info_output_mvcc_includes_transaction_counters_without_placeholder_limitation() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);

        with_temp_image_path(&image, |path| {
            let cx = super::cli_cx();
            let open_opts = super::OpenOptions {
                ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
                ..super::OpenOptions::default()
            };
            let open_fs = super::OpenFs::open_with_options(&cx, &path, &open_opts)
                .expect("open ext4 image for info mvcc test");

            let output = build_info_output(
                &path,
                &cx,
                &open_fs,
                InfoCommandOptions {
                    sections: InfoSections::empty().with_mvcc(true),
                    json: false,
                },
            )
            .expect("build info output with mvcc section");

            let mvcc = output.mvcc.expect("mvcc section should be present");
            assert_eq!(mvcc.ssi_conflict_count, Some(0));
            assert_eq!(mvcc.abort_count, Some(0));
            assert!(!output.limitations.iter().any(|limitation| {
                limitation.contains("transaction/SSI counters are not yet wired")
            }));
        });
    }

    #[test]
    fn build_info_output_ext4_superblock_exposes_quota_inodes() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_quota_inodes(EXT4_VALID_FS);

        with_temp_image_path(&image, |path| {
            let cx = super::cli_cx();
            let open_opts = super::OpenOptions {
                ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
                ..super::OpenOptions::default()
            };
            let open_fs = super::OpenFs::open_with_options(&cx, &path, &open_opts)
                .expect("open ext4 image for quota info output test");

            let output = build_info_output(
                &path,
                &cx,
                &open_fs,
                InfoCommandOptions {
                    sections: InfoSections::empty(),
                    json: true,
                },
            )
            .expect("build info output with ext4 quota metadata");

            assert!(
                matches!(output.superblock, super::SuperblockInfoOutput::Ext4 { .. }),
                "expected ext4 superblock output"
            );
            if let super::SuperblockInfoOutput::Ext4 { quota_inodes, .. } = output.superblock {
                assert_eq!(
                    quota_inodes,
                    Some(ffs_ondisk::ext4::Ext4QuotaInodes {
                        user: Some(3),
                        group: Some(4),
                        project: Some(11),
                    })
                );
            }

            let json = serde_json::to_value(&output).expect("serialize info output to json");
            assert_eq!(json["superblock"]["quota_inodes"]["user"], 3);
            assert_eq!(json["superblock"]["quota_inodes"]["group"], 4);
            assert_eq!(json["superblock"]["quota_inodes"]["project"], 11);
        });
    }

    #[test]
    fn build_info_output_ext4_superblock_omits_quota_inodes_when_features_absent() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);

        with_temp_image_path(&image, |path| {
            let cx = super::cli_cx();
            let open_opts = super::OpenOptions {
                ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
                ..super::OpenOptions::default()
            };
            let open_fs = super::OpenFs::open_with_options(&cx, &path, &open_opts)
                .expect("open ext4 image without quota features");

            let output = build_info_output(
                &path,
                &cx,
                &open_fs,
                InfoCommandOptions {
                    sections: InfoSections::empty(),
                    json: true,
                },
            )
            .expect("build info output without ext4 quota metadata");

            assert!(
                matches!(output.superblock, super::SuperblockInfoOutput::Ext4 { .. }),
                "expected ext4 superblock output"
            );
            if let super::SuperblockInfoOutput::Ext4 { quota_inodes, .. } = output.superblock {
                assert!(quota_inodes.is_none());
            }

            let json = serde_json::to_value(&output).expect("serialize info output to json");
            assert!(
                json["superblock"].get("quota_inodes").is_none(),
                "quota_inodes should be omitted when quota features are absent"
            );
        });
    }

    #[test]
    fn inspect_ext4_output_exposes_quota_inodes() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_quota_inodes(EXT4_VALID_FS);

        with_temp_image_path(&image, |path| {
            let cx = super::cli_cx();
            let open_opts = super::OpenOptions {
                ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
                ..super::OpenOptions::default()
            };
            let flavor = super::detect_filesystem_at_path(&cx, &path)
                .expect("detect ext4 image for inspect quota test");
            assert!(
                matches!(flavor, super::FsFlavor::Ext4(_)),
                "expected ext4 flavor"
            );
            let super::FsFlavor::Ext4(sb) = flavor else {
                return;
            };

            let output = super::inspect_ext4_output(&cx, &path, &open_opts, &sb)
                .expect("build inspect output with ext4 quota metadata");

            assert!(
                matches!(output, super::InspectOutput::Ext4 { .. }),
                "expected ext4 inspect output"
            );
            if let super::InspectOutput::Ext4 { quota_inodes, .. } = output {
                assert_eq!(
                    quota_inodes,
                    Some(ffs_ondisk::ext4::Ext4QuotaInodes {
                        user: Some(3),
                        group: Some(4),
                        project: Some(11),
                    })
                );
            }

            let json = serde_json::to_value(&output).expect("serialize inspect output to json");
            assert_eq!(json["quota_inodes"]["user"], 3);
            assert_eq!(json["quota_inodes"]["group"], 4);
            assert_eq!(json["quota_inodes"]["project"], 11);
        });
    }

    #[test]
    fn btrfs_chunk_type_flag_names_reports_known_and_unknown_bits() {
        assert_eq!(btrfs_chunk_type_flag_names(0), vec!["NONE"]);
        assert_eq!(btrfs_chunk_type_flag_names(3), vec!["DATA", "SYSTEM"]);

        let flags = btrfs_chunk_type_flag_names(1 | (1_u64 << 9));
        assert!(flags.iter().any(|flag| flag == "DATA"));
        assert!(
            flags
                .iter()
                .any(|flag| flag.starts_with("UNKNOWN(0x0000000000000200)"))
        );
    }

    #[test]
    fn unavailable_repair_info_clears_group_metrics() {
        let info =
            unavailable_repair_info("live ext4 repair metrics unavailable (see limitations)");
        assert!(!info.metrics_available);
        assert_eq!(
            info.note,
            "live ext4 repair metrics unavailable (see limitations)"
        );
        assert_eq!(info.groups_total, None);
        assert_eq!(info.groups_fresh, None);
        assert_eq!(info.groups_stale, None);
        assert_eq!(info.groups_untracked, None);
        assert!(
            (info.configured_overhead_ratio - super::DEFAULT_REPAIR_OVERHEAD_RATIO).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn unavailable_repair_info_supports_btrfs_fallback_note() {
        let info =
            unavailable_repair_info("live btrfs repair metrics unavailable (see limitations)");
        assert!(!info.metrics_available);
        assert_eq!(
            info.note,
            "live btrfs repair metrics unavailable (see limitations)"
        );
        assert_eq!(info.groups_total, None);
    }

    #[test]
    fn fsck_skips_clean_ext4_scrub_without_force() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let output = with_temp_image_path(&image, |path| {
            build_fsck_output(
                &path,
                FsckCommandOptions {
                    flags: FsckFlags::empty(),
                    block_group: None,
                },
            )
            .expect("build fsck output for clean ext4 image")
        });

        assert_eq!(output.scrub.scanned, 0);
        assert_eq!(output.scrub.corrupt, 0);
        assert_eq!(output.scrub.error_or_higher, 0);
        let scrub_phase = output
            .phases
            .iter()
            .find(|phase| phase.phase == "checksum_scrub")
            .expect("checksum_scrub phase should be present");
        assert_eq!(scrub_phase.status, "skipped");
        assert!(scrub_phase.detail.contains("pass --force for full scrub"));
        assert!(
            output
                .limitations
                .iter()
                .any(|limitation| limitation.contains("skipped block-level scrub"))
        );
    }

    #[test]
    fn fsck_force_runs_full_scrub_for_clean_ext4() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let output = with_temp_image_path(&image, |path| {
            build_fsck_output(
                &path,
                FsckCommandOptions {
                    flags: FsckFlags::empty().with_force(true),
                    block_group: None,
                },
            )
            .expect("build fsck output for forced clean ext4 image")
        });

        assert!(output.scrub.scanned > 0);
        let scrub_phase = output
            .phases
            .iter()
            .find(|phase| phase.phase == "checksum_scrub")
            .expect("checksum_scrub phase should be present");
        assert_eq!(scrub_phase.status, "ok");
        assert!(
            !output
                .limitations
                .iter()
                .any(|limitation| limitation.contains("skipped block-level scrub"))
        );
    }

    #[test]
    fn repair_selection_prefers_explicit_stale_groups() {
        let all = vec![0, 1, 2, 3];
        let staleness = vec![
            (0, Ext4RepairStaleness::Fresh),
            (1, Ext4RepairStaleness::Stale),
            (2, Ext4RepairStaleness::Untracked),
            (3, Ext4RepairStaleness::Stale),
        ];
        let selected = select_ext4_repair_groups(RepairFlags::empty(), true, &all, &staleness);
        assert_eq!(selected, vec![1, 3]);
    }

    #[test]
    fn repair_selection_skips_when_clean_and_untracked() {
        let all = vec![0, 1];
        let staleness = vec![
            (0, Ext4RepairStaleness::Untracked),
            (1, Ext4RepairStaleness::Untracked),
        ];
        let selected = select_ext4_repair_groups(RepairFlags::empty(), true, &all, &staleness);
        assert!(selected.is_empty());
    }

    #[test]
    fn repair_selection_runs_full_when_dirty_and_untracked() {
        let all = vec![0, 1, 2];
        let staleness = vec![
            (0, Ext4RepairStaleness::Untracked),
            (1, Ext4RepairStaleness::Untracked),
            (2, Ext4RepairStaleness::Untracked),
        ];
        let selected = select_ext4_repair_groups(RepairFlags::empty(), false, &all, &staleness);
        assert_eq!(selected, all);
    }

    #[test]
    fn repair_selection_rebuild_symbols_forces_full_scope() {
        let all = vec![0, 1, 2];
        let staleness = vec![
            (0, Ext4RepairStaleness::Fresh),
            (1, Ext4RepairStaleness::Stale),
            (2, Ext4RepairStaleness::Untracked),
        ];
        let selected = select_ext4_repair_groups(
            RepairFlags::empty().with_rebuild_symbols(true),
            true,
            &all,
            &staleness,
        );
        assert_eq!(selected, all);
    }

    #[test]
    fn btrfs_repair_selection_prefers_stale_groups() {
        let all = vec![0, 1, 2, 3];
        let staleness = vec![
            (0, Ext4RepairStaleness::Fresh),
            (1, Ext4RepairStaleness::Stale),
            (2, Ext4RepairStaleness::Untracked),
            (3, Ext4RepairStaleness::Stale),
        ];
        let mut limitations = Vec::new();

        let selected =
            select_btrfs_repair_groups(RepairFlags::empty(), &all, &staleness, &mut limitations);

        assert_eq!(selected, vec![1, 3]);
        assert!(
            limitations
                .iter()
                .any(|limitation| limitation.contains("selected 2/4 btrfs groups"))
        );
    }

    #[test]
    fn btrfs_repair_selection_falls_back_to_full_when_all_fresh() {
        let all = vec![0, 1, 2];
        let staleness = vec![
            (0, Ext4RepairStaleness::Fresh),
            (1, Ext4RepairStaleness::Fresh),
            (2, Ext4RepairStaleness::Fresh),
        ];
        let mut limitations = Vec::new();

        let selected =
            select_btrfs_repair_groups(RepairFlags::empty(), &all, &staleness, &mut limitations);

        assert_eq!(selected, all);
        assert!(limitations.iter().any(|limitation| {
            limitation.contains("found no stale btrfs groups; running full scrub")
        }));
    }

    #[test]
    fn repair_verify_only_ignores_rebuild_symbols_write_path() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let output = with_temp_image_path(&image, |path| {
            build_repair_output(
                &path,
                RepairCommandOptions {
                    flags: RepairFlags::empty()
                        .with_verify_only(true)
                        .with_rebuild_symbols(true),
                    block_group: None,
                    max_threads: None,
                },
            )
            .expect("build repair output for verify-only rebuild request")
        });

        assert!(
            output
                .limitations
                .iter()
                .any(|limitation| limitation.contains("ignored when --verify-only"))
        );
        assert!(matches!(
            output.action,
            super::RepairActionOutput::VerifyOnly
        ));
    }

    #[test]
    fn repair_coordination_allows_same_host_refresh() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let _guard = log_contract_guard();
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);

        with_temp_image_path(&image, |path| {
            let local_host = test_local_host_name();
            let first = coordinate_repair_write_access(
                &crate::cli_cx(),
                "ffs::test",
                REPAIR_COORDINATION_SCENARIO_REPAIR,
                "repair",
                &path,
                true,
            );
            assert!(first.writes_allowed);
            assert!(matches!(
                first.output.status,
                RepairCoordinationStatus::Claimed
            ));

            let second = coordinate_repair_write_access(
                &crate::cli_cx(),
                "ffs::test",
                REPAIR_COORDINATION_SCENARIO_REPAIR,
                "repair",
                &path,
                true,
            );
            assert!(second.writes_allowed);
            assert!(matches!(
                second.output.status,
                RepairCoordinationStatus::Claimed
            ));
            // The same host+process incarnation reclaims its own lease and the
            // monotonic repair generation advances on each renewal.
            assert_eq!(first.output.repair_generation, Some(1));
            assert_eq!(second.output.repair_generation, Some(2));
            assert!(
                second
                    .output
                    .detail
                    .contains("lease-based repair ownership claimed"),
                "unexpected same-host refresh detail: {}",
                second.output.detail
            );

            let record_bytes = std::fs::read(repair_coordination_record_path(&path))
                .expect("read persisted coordination record");
            let record: CoordinationRecord =
                serde_json::from_slice(&record_bytes).expect("parse persisted coordination record");
            assert_eq!(record.hostname, local_host);
            assert_eq!(record.host_id, second.output.host_id);
            assert_eq!(record.pid, std::process::id());
            assert_eq!(record.repair_generation, 2);
        });
    }

    #[test]
    fn repair_coordination_blocks_foreign_host_owner() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let _guard = log_contract_guard();
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);

        with_temp_image_path(&image, |path| {
            write_test_coordination_record(&path, "remote-host");
            let decision = coordinate_repair_write_access(
                &crate::cli_cx(),
                "ffs::test",
                REPAIR_COORDINATION_SCENARIO_REPAIR,
                "repair",
                &path,
                true,
            );

            assert!(!decision.writes_allowed);
            assert!(matches!(
                decision.output.status,
                RepairCoordinationStatus::Blocked
            ));
            assert_eq!(decision.output.owner_host.as_deref(), Some("remote-host"));
            assert_eq!(
                decision.output.error_class.as_deref(),
                Some("foreign_lease_active")
            );
            assert_eq!(
                decision.output.owner_host_id.as_deref(),
                Some("ffs-test-host-id-remote-host")
            );
            assert!(
                decision
                    .output
                    .lease_expires_in_secs
                    .is_some_and(|remaining| remaining > 0),
                "live foreign lease must report remaining TTL"
            );
        });
    }

    #[test]
    fn btrfs_super_mirror_offsets_follow_kernel_layout() {
        let one_gib_image_len = 1024 * 1024 * 1024;
        let offsets = btrfs_super_mirror_offsets(one_gib_image_len);
        assert_eq!(
            offsets,
            vec![
                64 * 1024,        // Primary: 64 KiB
                64 * 1024 * 1024, // Mirror 1: 64 MiB
            ]
        );

        let third_mirror_offset = 256_u64 * 1024 * 1024 * 1024;
        let large_image_len =
            third_mirror_offset + u64::try_from(super::BTRFS_SUPER_INFO_SIZE).unwrap();
        let offsets = btrfs_super_mirror_offsets(large_image_len);
        assert_eq!(
            offsets,
            vec![
                64 * 1024,           // Primary: 64 KiB
                64 * 1024 * 1024,    // Mirror 1: 64 MiB
                third_mirror_offset, // Mirror 2: 256 GiB
            ]
        );
    }

    #[test]
    fn btrfs_superblock_normalization_retargets_primary_offset() {
        let mut region = build_test_btrfs_superblock(64 * 1024 * 1024, 3);
        normalize_btrfs_superblock_as_primary(&mut region)
            .expect("normalize mirror superblock for primary slot");
        let parsed = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(&region)
            .expect("normalized superblock should parse");
        assert_eq!(parsed.bytenr, super::BTRFS_SUPER_INFO_OFFSET as u64);
        ffs_ondisk::verify_btrfs_superblock_checksum(&region)
            .expect("normalized superblock checksum should be valid");
    }

    #[test]
    fn repair_restores_primary_btrfs_superblock_from_backup_mirror() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let mut image = vec![0_u8; image_len];

        let mut primary = build_test_btrfs_superblock(primary_offset as u64, 5);
        primary[0] ^= 0xA5; // Corrupt checksum but keep structure parseable.
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let backup = build_test_btrfs_superblock(backup_offset as u64, 9);
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (output, parsed_primary) = with_temp_image_path(&image, |path| {
            build_repair_output(
                &path,
                RepairCommandOptions {
                    flags: RepairFlags::empty(),
                    block_group: None,
                    max_threads: Some(1),
                },
            )
            .map(|output| {
                let repaired = std::fs::read(&path).expect("read repaired image");
                let sb_region =
                    &repaired[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE];
                ffs_ondisk::verify_btrfs_superblock_checksum(sb_region)
                    .expect("repaired primary checksum should be valid");
                let parsed = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(sb_region)
                    .expect("repaired primary should parse");
                (output, parsed)
            })
            .expect("repair output for btrfs mirror recovery")
        });

        assert!(matches!(
            output.action,
            super::RepairActionOutput::RepairRequested
        ));
        assert_eq!(parsed_primary.bytenr, primary_offset as u64);
        assert!(
            output
                .limitations
                .iter()
                .any(|limitation| limitation.contains("restored primary btrfs superblock"))
        );
    }

    #[test]
    fn repair_blocked_preserves_corrupt_btrfs_backup_superblock() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let mut image = vec![0_u8; image_len];

        let primary = build_test_btrfs_superblock(primary_offset as u64, 21);
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let mut backup = build_test_btrfs_superblock(backup_offset as u64, 17);
        backup[0] ^= 0x7E; // Corrupt checksum but keep structure parseable.
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (output, backup_still_corrupt) = with_temp_image_path(&image, |path| {
            write_test_coordination_record(&path, "remote-host");
            build_repair_output(
                &path,
                RepairCommandOptions {
                    flags: RepairFlags::empty(),
                    block_group: None,
                    max_threads: Some(1),
                },
            )
            .map(|output| {
                let repaired = std::fs::read(&path).expect("read image after blocked repair");
                let sb_region =
                    &repaired[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE];
                let backup_still_corrupt =
                    ffs_ondisk::verify_btrfs_superblock_checksum(sb_region).is_err();
                (output, backup_still_corrupt)
            })
            .expect("repair output for blocked multi-host repair")
        });

        assert!(matches!(
            output.action,
            super::RepairActionOutput::RepairBlocked
        ));
        assert!(matches!(
            output.repair_coordination.status,
            RepairCoordinationStatus::Blocked
        ));
        assert_eq!(
            output.repair_coordination.owner_host.as_deref(),
            Some("remote-host")
        );
        assert_eq!(output.exit_code, 2);
        assert!(backup_still_corrupt);
        assert!(
            output
                .limitations
                .iter()
                .any(|limitation| { limitation.contains("holds a live lease for host") })
        );
    }

    #[test]
    fn repair_restores_corrupt_btrfs_backup_superblock_from_primary() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let mut image = vec![0_u8; image_len];

        let primary = build_test_btrfs_superblock(primary_offset as u64, 21);
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let mut backup = build_test_btrfs_superblock(backup_offset as u64, 17);
        backup[0] ^= 0x7E; // Corrupt checksum but keep structure parseable.
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (output, parsed_backup) = with_temp_image_path(&image, |path| {
            build_repair_output(
                &path,
                RepairCommandOptions {
                    flags: RepairFlags::empty(),
                    block_group: None,
                    max_threads: Some(1),
                },
            )
            .map(|output| {
                let repaired = std::fs::read(&path).expect("read repaired image");
                let sb_region =
                    &repaired[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE];
                ffs_ondisk::verify_btrfs_superblock_checksum(sb_region)
                    .expect("repaired backup checksum should be valid");
                let parsed = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(sb_region)
                    .expect("repaired backup should parse");
                (output, parsed)
            })
            .expect("repair output for btrfs backup mirror recovery")
        });

        assert!(matches!(
            output.action,
            super::RepairActionOutput::RepairRequested
        ));
        assert_eq!(parsed_backup.bytenr, backup_offset as u64);
        assert!(output.limitations.iter().any(|limitation| {
            limitation.contains("restored 1 btrfs superblock mirror(s) from primary superblock")
        }));
    }

    #[test]
    fn mirror_repair_skips_when_corrupt_backup_superblock_outside_scope() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let block_size = 4096_u32;
        let mut image = vec![0_u8; image_len];

        let primary = build_test_btrfs_superblock(primary_offset as u64, 53);
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let mut backup = build_test_btrfs_superblock(backup_offset as u64, 51);
        backup[0] ^= 0x55; // Corrupt checksum but keep structure parseable.
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (outcome, limitations, backup_still_corrupt) = with_temp_image_path(&image, |path| {
            let mut limitations = Vec::new();
            let outcome = super::repair_corrupt_btrfs_superblock_mirrors_from_primary(
                &path,
                block_size,
                super::BlockNumber(0),
                8,
                &mut limitations,
            )
            .expect("run scoped mirror repair outside backup scope");
            let repaired = std::fs::read(&path).expect("read image after scoped mirror repair");
            let sb_region = &repaired[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE];
            let backup_still_corrupt =
                ffs_ondisk::verify_btrfs_superblock_checksum(sb_region).is_err();
            (outcome, limitations, backup_still_corrupt)
        });

        assert!(!outcome.attempted);
        assert_eq!(outcome.repaired, 0);
        assert!(backup_still_corrupt);
        assert!(!limitations.iter().any(|limitation| {
            limitation.contains("restored 1 btrfs superblock mirror(s) from primary superblock")
        }));
    }

    #[test]
    fn mirror_repair_restores_corrupt_backup_superblock_when_in_scope() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let block_size = 4096_u32;
        let mut image = vec![0_u8; image_len];

        let primary = build_test_btrfs_superblock(primary_offset as u64, 63);
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let mut backup = build_test_btrfs_superblock(backup_offset as u64, 61);
        backup[0] ^= 0xAA; // Corrupt checksum but keep structure parseable.
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (outcome, limitations, parsed_backup) = with_temp_image_path(&image, |path| {
            let mut limitations = Vec::new();
            let backup_block = super::BlockNumber((backup_offset as u64) / u64::from(block_size));
            let outcome = super::repair_corrupt_btrfs_superblock_mirrors_from_primary(
                &path,
                block_size,
                backup_block,
                1,
                &mut limitations,
            )
            .expect("run scoped mirror repair for backup slot");
            let repaired = std::fs::read(&path).expect("read image after scoped mirror repair");
            let sb_region = &repaired[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE];
            ffs_ondisk::verify_btrfs_superblock_checksum(sb_region)
                .expect("repaired backup checksum should be valid");
            let parsed = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(sb_region)
                .expect("repaired backup should parse");
            (outcome, limitations, parsed)
        });

        assert!(outcome.attempted);
        assert_eq!(outcome.repaired, 1);
        assert_eq!(parsed_backup.bytenr, backup_offset as u64);
        assert!(limitations.iter().any(|limitation| {
            limitation.contains("restored 1 btrfs superblock mirror(s) from primary superblock")
        }));
    }

    #[test]
    fn fsck_repair_restores_primary_btrfs_superblock_from_backup_mirror() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let mut image = vec![0_u8; image_len];

        let mut primary = build_test_btrfs_superblock(primary_offset as u64, 11);
        primary[0] ^= 0x3C; // Corrupt checksum but keep structure parseable.
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let backup = build_test_btrfs_superblock(backup_offset as u64, 13);
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (output, parsed_primary) = with_temp_image_path(&image, |path| {
            build_fsck_output(
                &path,
                FsckCommandOptions {
                    flags: FsckFlags::empty().with_repair(true),
                    block_group: None,
                },
            )
            .map(|output| {
                let repaired = std::fs::read(&path).expect("read repaired image");
                let sb_region =
                    &repaired[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE];
                ffs_ondisk::verify_btrfs_superblock_checksum(sb_region)
                    .expect("repaired primary checksum should be valid");
                let parsed = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(sb_region)
                    .expect("repaired primary should parse");
                (output, parsed)
            })
            .expect("fsck output for btrfs mirror recovery")
        });

        assert!(matches!(
            output.repair_status,
            super::FsckRepairStatus::RequestedPerformed
        ));
        let repair_phase = output
            .phases
            .iter()
            .find(|phase| phase.phase == "repair")
            .expect("repair phase should be present");
        assert_eq!(repair_phase.status, "ok");
        assert!(
            repair_phase
                .detail
                .contains("restored primary btrfs superblock")
        );
        assert_eq!(parsed_primary.bytenr, primary_offset as u64);
        assert!(output.scrub.scanned > 0);
    }

    #[test]
    fn fsck_repair_blocked_preserves_corrupt_btrfs_backup_superblock() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let mut image = vec![0_u8; image_len];

        let primary = build_test_btrfs_superblock(primary_offset as u64, 29);
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let mut backup = build_test_btrfs_superblock(backup_offset as u64, 26);
        backup[0] ^= 0x19; // Corrupt checksum but keep structure parseable.
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (output, backup_still_corrupt) = with_temp_image_path(&image, |path| {
            write_test_coordination_record(&path, "remote-host");
            build_fsck_output(
                &path,
                FsckCommandOptions {
                    flags: FsckFlags::empty().with_repair(true),
                    block_group: None,
                },
            )
            .map(|output| {
                let repaired = std::fs::read(&path).expect("read image after blocked fsck repair");
                let sb_region =
                    &repaired[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE];
                let backup_still_corrupt =
                    ffs_ondisk::verify_btrfs_superblock_checksum(sb_region).is_err();
                (output, backup_still_corrupt)
            })
            .expect("fsck output for blocked multi-host repair")
        });

        assert!(matches!(
            output.repair_status,
            super::FsckRepairStatus::RequestedNotPerformed
        ));
        assert!(matches!(
            output
                .repair_coordination
                .as_ref()
                .expect("repair coordination should be reported")
                .status,
            RepairCoordinationStatus::Blocked
        ));
        let repair_phase = output
            .phases
            .iter()
            .find(|phase| phase.phase == "repair")
            .expect("repair phase should be present");
        assert_eq!(repair_phase.status, "error");
        assert!(
            repair_phase.detail.contains("holds a live lease for host"),
            "unexpected blocked repair detail: {}",
            repair_phase.detail
        );
        assert_eq!(output.exit_code, 2);
        assert!(backup_still_corrupt);
    }

    #[test]
    fn fsck_repair_restores_corrupt_btrfs_backup_superblock_from_primary() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let mut image = vec![0_u8; image_len];

        let primary = build_test_btrfs_superblock(primary_offset as u64, 29);
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let mut backup = build_test_btrfs_superblock(backup_offset as u64, 26);
        backup[0] ^= 0x19; // Corrupt checksum but keep structure parseable.
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (output, parsed_backup) = with_temp_image_path(&image, |path| {
            build_fsck_output(
                &path,
                FsckCommandOptions {
                    flags: FsckFlags::empty().with_repair(true),
                    block_group: None,
                },
            )
            .map(|output| {
                let repaired = std::fs::read(&path).expect("read repaired image");
                let sb_region =
                    &repaired[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE];
                ffs_ondisk::verify_btrfs_superblock_checksum(sb_region)
                    .expect("repaired backup checksum should be valid");
                let parsed = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(sb_region)
                    .expect("repaired backup should parse");
                (output, parsed)
            })
            .expect("fsck output for btrfs backup mirror recovery")
        });

        assert!(matches!(
            output.repair_status,
            super::FsckRepairStatus::RequestedPerformed
        ));
        let repair_phase = output
            .phases
            .iter()
            .find(|phase| phase.phase == "repair")
            .expect("repair phase should be present");
        assert_eq!(repair_phase.status, "ok");
        assert!(
            repair_phase
                .detail
                .contains("restored 1 btrfs superblock mirror(s) from primary superblock")
        );
        assert_eq!(parsed_backup.bytenr, backup_offset as u64);
    }

    #[test]
    fn repair_bootstraps_btrfs_detection_from_backup_superblock() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let mut image = vec![0_u8; image_len];

        let mut primary = build_test_btrfs_superblock(primary_offset as u64, 31);
        primary[0x40..0x48].fill(0); // Break magic so initial filesystem detection fails.
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let backup = build_test_btrfs_superblock(backup_offset as u64, 33);
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (output, parsed_primary) = with_temp_image_path(&image, |path| {
            build_repair_output(
                &path,
                RepairCommandOptions {
                    flags: RepairFlags::empty(),
                    block_group: None,
                    max_threads: Some(1),
                },
            )
            .map(|output| {
                let repaired = std::fs::read(&path).expect("read repaired image");
                let sb_region =
                    &repaired[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE];
                ffs_ondisk::verify_btrfs_superblock_checksum(sb_region)
                    .expect("repaired primary checksum should be valid");
                let parsed = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(sb_region)
                    .expect("repaired primary should parse");
                (output, parsed)
            })
            .expect("repair output for btrfs bootstrap recovery")
        });

        assert!(matches!(
            output.action,
            super::RepairActionOutput::RepairRequested
        ));
        assert_eq!(parsed_primary.bytenr, primary_offset as u64);
        assert!(
            output.limitations.iter().any(
                |limitation| limitation.contains("bootstrap restored primary btrfs superblock")
            )
        );
    }

    #[test]
    fn fsck_repair_bootstraps_btrfs_detection_from_backup_superblock() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let mut image = vec![0_u8; image_len];

        let mut primary = build_test_btrfs_superblock(primary_offset as u64, 41);
        primary[0x40..0x48].fill(0); // Break magic so initial filesystem detection fails.
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let backup = build_test_btrfs_superblock(backup_offset as u64, 44);
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (output, parsed_primary) = with_temp_image_path(&image, |path| {
            build_fsck_output(
                &path,
                FsckCommandOptions {
                    flags: FsckFlags::empty().with_repair(true),
                    block_group: None,
                },
            )
            .map(|output| {
                let repaired = std::fs::read(&path).expect("read repaired image");
                let sb_region =
                    &repaired[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE];
                ffs_ondisk::verify_btrfs_superblock_checksum(sb_region)
                    .expect("repaired primary checksum should be valid");
                let parsed = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(sb_region)
                    .expect("repaired primary should parse");
                (output, parsed)
            })
            .expect("fsck output for btrfs bootstrap recovery")
        });

        assert!(matches!(
            output.repair_status,
            super::FsckRepairStatus::RequestedPerformed
        ));
        let repair_phase = output
            .phases
            .iter()
            .find(|phase| phase.phase == "repair")
            .expect("repair phase should be present");
        assert_eq!(repair_phase.status, "ok");
        assert!(
            repair_phase
                .detail
                .contains("bootstrap restored primary btrfs superblock")
        );
        assert_eq!(parsed_primary.bytenr, primary_offset as u64);
        assert!(output.scrub.scanned > 0);
    }

    #[test]
    fn btrfs_repair_group_spec_maps_contiguous_single_chunk() {
        // Group must be large enough for the repair tail (>= 4 blocks):
        // REPAIR_DESC_SLOT_COUNT (2) + at least 1 repair block + source blocks.
        // Chunk covers [0x1000..0x20FFF], group occupies [0x2000..0x11FFF] (16 blocks).
        let chunks = vec![test_btrfs_chunk_entry(0x1000, 0x20000, 0x8000)];
        let spec = build_btrfs_repair_group_spec(2, 0x2000, 0x10000, 4096, &chunks)
            .expect("map contiguous btrfs group");
        assert_eq!(spec.group, 2);
        assert_eq!(spec.logical_start, 0x2000);
        assert_eq!(spec.logical_bytes, 0x10000);
        // physical_start = chunk_physical + (logical_start - chunk_logical) = 0x8000 + (0x2000 - 0x1000) = 0x9000
        // start_block = 0x9000 / 4096 = 9
        assert_eq!(spec.physical_start_block.0, 9);
        // block_count = 0x10000 / 4096 = 16
        assert_eq!(spec.physical_block_count, 16);
    }

    #[test]
    fn btrfs_repair_group_spec_rejects_zero_block_size() {
        let err = build_btrfs_repair_group_spec(3, 0x2000, 0x10000, 0, &[])
            .expect_err("zero scrub block size should fail before block math");
        let detail = format!("{err:#}");
        assert_eq!(
            detail,
            "btrfs block group 3 scrub block size must be nonzero"
        );
    }

    const BTRFS_REPAIR_GROUP_SPEC_UNMAPPED_RANGE_GOLDEN: &str =
        "btrfs block group 0 logical start 16384 is not covered by any chunk";

    #[test]
    fn btrfs_repair_group_spec_rejects_unmapped_range() {
        let chunks = vec![test_btrfs_chunk_entry(0x1000, 0x1000, 0x8000)];
        let err = build_btrfs_repair_group_spec(0, 0x4000, 0x1000, 4096, &chunks)
            .expect_err("unmapped logical range should fail");
        let detail = format!("{err:#}");
        assert_eq!(detail, BTRFS_REPAIR_GROUP_SPEC_UNMAPPED_RANGE_GOLDEN);
    }

    const BTRFS_REPAIR_GROUP_SPEC_NON_CONTIGUOUS_GOLDEN: &str = "btrfs block group 1 spans non-contiguous chunk mapping (start_physical=65536, end_physical=200703, expected_end=73727)";

    #[test]
    fn btrfs_repair_group_spec_rejects_non_contiguous_chunk_mapping() {
        let chunks = vec![
            test_btrfs_chunk_entry(0x0, 0x1000, 0x10000),
            test_btrfs_chunk_entry(0x1000, 0x1000, 0x30000),
        ];
        let err = build_btrfs_repair_group_spec(1, 0x0, 0x2000, 4096, &chunks)
            .expect_err("discontiguous mapping should fail");
        let detail = format!("{err:#}");
        assert_eq!(detail, BTRFS_REPAIR_GROUP_SPEC_NON_CONTIGUOUS_GOLDEN);
    }

    // ── summarize_repair_staleness: additional edge cases ─────────────────

    #[test]
    fn summarize_repair_staleness_all_fresh() {
        let staleness = vec![
            (0, Ext4RepairStaleness::Fresh),
            (1, Ext4RepairStaleness::Fresh),
            (2, Ext4RepairStaleness::Fresh),
        ];
        let summary = summarize_repair_staleness(&staleness);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.fresh, 3);
        assert_eq!(summary.stale, 0);
        assert_eq!(summary.untracked, 0);
    }

    #[test]
    fn summarize_repair_staleness_all_stale() {
        let staleness = vec![
            (0, Ext4RepairStaleness::Stale),
            (1, Ext4RepairStaleness::Stale),
        ];
        let summary = summarize_repair_staleness(&staleness);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.fresh, 0);
        assert_eq!(summary.stale, 2);
        assert_eq!(summary.untracked, 0);
    }

    #[test]
    fn summarize_repair_staleness_all_untracked() {
        let staleness = vec![
            (0, Ext4RepairStaleness::Untracked),
            (1, Ext4RepairStaleness::Untracked),
            (2, Ext4RepairStaleness::Untracked),
            (3, Ext4RepairStaleness::Untracked),
        ];
        let summary = summarize_repair_staleness(&staleness);
        assert_eq!(summary.total, 4);
        assert_eq!(summary.fresh, 0);
        assert_eq!(summary.stale, 0);
        assert_eq!(summary.untracked, 4);
    }

    #[test]
    fn summarize_repair_staleness_single_entry() {
        let summary = summarize_repair_staleness(&[(42, Ext4RepairStaleness::Stale)]);
        assert_eq!(summary.total, 1);
        assert_eq!(summary.fresh, 0);
        assert_eq!(summary.stale, 1);
        assert_eq!(summary.untracked, 0);
    }

    // ── ext4_state_flag_names: filesystem state display ───────────────────

    #[test]
    fn ext4_state_flag_names_valid() {
        let names = ext4_state_flag_names(0x0001);
        assert_eq!(names, vec!["VALID_FS"]);
    }

    #[test]
    fn ext4_state_flag_names_error() {
        let names = ext4_state_flag_names(0x0002);
        assert_eq!(names, vec!["ERROR_FS"]);
    }

    #[test]
    fn ext4_state_flag_names_multiple() {
        let names = ext4_state_flag_names(0x0007); // VALID | ERROR | ORPHAN
        assert_eq!(names, vec!["VALID_FS", "ERROR_FS", "ORPHAN_FS"]);
    }

    #[test]
    fn ext4_state_flag_names_zero() {
        let names = ext4_state_flag_names(0);
        assert_eq!(names, vec!["NONE"]);
    }

    #[test]
    fn ext4_state_flag_names_unknown() {
        let names = ext4_state_flag_names(0x0008);
        assert_eq!(names, vec!["UNKNOWN(0x0008)"]);
    }

    // ── ext4_appears_clean_state: filesystem cleanliness check ───────────

    #[test]
    fn ext4_appears_clean_state_valid_only() {
        assert!(ext4_appears_clean_state(0x0001)); // VALID_FS only
    }

    #[test]
    fn ext4_appears_clean_state_with_error() {
        assert!(!ext4_appears_clean_state(0x0003)); // VALID | ERROR
    }

    #[test]
    fn ext4_appears_clean_state_with_orphan() {
        assert!(!ext4_appears_clean_state(0x0005)); // VALID | ORPHAN
    }

    #[test]
    fn ext4_appears_clean_state_not_valid() {
        assert!(!ext4_appears_clean_state(0x0000)); // no VALID flag
    }

    // ── ext4_group_flag_names: block group flag display ───────────────────

    #[test]
    fn ext4_group_flag_names_inode_uninit() {
        let names = ext4_group_flag_names(ffs_ondisk::EXT4_BG_INODE_UNINIT);
        assert_eq!(names, vec!["INODE_UNINIT"]);
    }

    #[test]
    fn ext4_group_flag_names_block_uninit() {
        let names = ext4_group_flag_names(ffs_ondisk::EXT4_BG_BLOCK_UNINIT);
        assert_eq!(names, vec!["BLOCK_UNINIT"]);
    }

    #[test]
    fn ext4_group_flag_names_combined() {
        let flags = ffs_ondisk::EXT4_BG_INODE_UNINIT
            | ffs_ondisk::EXT4_BG_BLOCK_UNINIT
            | ffs_ondisk::EXT4_BG_INODE_ZEROED;
        let names = ext4_group_flag_names(flags);
        assert_eq!(names, vec!["INODE_UNINIT", "BLOCK_UNINIT", "INODE_ZEROED"]);
    }

    #[test]
    fn ext4_group_flag_names_zero() {
        let names = ext4_group_flag_names(0);
        assert_eq!(names, vec!["NONE"]);
    }

    #[test]
    fn ext4_group_flag_names_unknown() {
        let names = ext4_group_flag_names(0x0008);
        assert_eq!(names, vec!["UNKNOWN(0x0008)"]);
    }

    // ── btrfs_chunk_type_flag_names: chunk type display ────────────────────

    #[test]
    fn btrfs_chunk_type_flag_names_data() {
        let names = btrfs_chunk_type_flag_names(1);
        assert_eq!(names, vec!["DATA"]);
    }

    #[test]
    fn btrfs_chunk_type_flag_names_system() {
        let names = btrfs_chunk_type_flag_names(2);
        assert_eq!(names, vec!["SYSTEM"]);
    }

    #[test]
    fn btrfs_chunk_type_flag_names_metadata() {
        let names = btrfs_chunk_type_flag_names(4);
        assert_eq!(names, vec!["METADATA"]);
    }

    #[test]
    fn btrfs_chunk_type_flag_names_combined() {
        let names = btrfs_chunk_type_flag_names(7); // DATA | SYSTEM | METADATA
        assert_eq!(names, vec!["DATA", "SYSTEM", "METADATA"]);
    }

    #[test]
    fn btrfs_chunk_type_flag_names_zero() {
        let names = btrfs_chunk_type_flag_names(0);
        assert_eq!(names, vec!["NONE"]);
    }

    // ── btrfs_checksum_type_name: checksum type display ──────────────────

    #[test]
    fn btrfs_checksum_type_name_crc32c() {
        assert_eq!(
            btrfs_checksum_type_name(ffs_types::BTRFS_CSUM_TYPE_CRC32C),
            "crc32c"
        );
    }

    #[test]
    fn btrfs_checksum_type_name_unknown() {
        assert_eq!(btrfs_checksum_type_name(99), "unknown(99)");
    }

    // ── format_uuid: UUID display helper ──────────────────────────────────

    #[test]
    fn format_uuid_all_zeros() {
        let uuid = [0u8; 16];
        assert_eq!(format_uuid(&uuid), "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn format_uuid_all_ff() {
        let uuid = [0xffu8; 16];
        assert_eq!(format_uuid(&uuid), "ffffffff-ffff-ffff-ffff-ffffffffffff");
    }

    #[test]
    fn format_uuid_typical() {
        let uuid = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        assert_eq!(format_uuid(&uuid), "12345678-9abc-def0-1122-334455667788");
    }

    // ── filesystem_name: fs flavor to display string ──────────────────────

    #[test]
    fn filesystem_name_ext4() {
        use ffs_core::FsFlavor;
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let ext4_sb = ffs_ondisk::Ext4Superblock::parse_from_image(&image)
            .expect("parse test ext4 superblock");
        let flavor = FsFlavor::Ext4(Box::new(ext4_sb));
        assert_eq!(filesystem_name(&flavor), "ext4");
    }

    #[test]
    fn filesystem_name_btrfs() {
        use ffs_core::FsFlavor;
        let image = build_test_btrfs_superblock(ffs_types::BTRFS_SUPER_INFO_OFFSET as u64, 1);
        let btrfs_sb = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(&image)
            .expect("parse test btrfs superblock");
        let flavor = FsFlavor::Btrfs(Box::new(btrfs_sb));
        assert_eq!(filesystem_name(&flavor), "btrfs");
    }

    // ── format_ratio_thousandths: metrics display helper ──────────────────

    #[test]
    fn format_ratio_thousandths_zero_denominator_returns_zero() {
        assert_eq!(format_ratio_thousandths(5, 0), "0.000");
    }

    #[test]
    fn format_ratio_thousandths_zero_numerator() {
        assert_eq!(format_ratio_thousandths(0, 100), "0.000");
    }

    #[test]
    fn format_ratio_thousandths_exact_ratio() {
        assert_eq!(format_ratio_thousandths(1, 1), "1.000");
        assert_eq!(format_ratio_thousandths(3, 1), "3.000");
    }

    #[test]
    fn format_ratio_thousandths_fractional() {
        assert_eq!(format_ratio_thousandths(1, 3), "0.333");
        assert_eq!(format_ratio_thousandths(2, 3), "0.666");
        assert_eq!(format_ratio_thousandths(7, 2), "3.500");
    }

    #[test]
    fn format_ratio_thousandths_large_values() {
        let result = format_ratio_thousandths(usize::MAX, 1);
        assert!(!result.is_empty());
        assert!(result.contains('.'));
    }

    // ── format_ext4_quota_inodes: quota display formatting ───────────────

    #[test]
    fn format_ext4_quota_inodes_all_present() {
        use ffs_ondisk::ext4::Ext4QuotaInodes;
        let quota = Ext4QuotaInodes {
            user: Some(3),
            group: Some(4),
            project: Some(11),
        };
        let result = format_ext4_quota_inodes(&quota);
        assert!(result.contains("user=3"));
        assert!(result.contains("group=4"));
        assert!(result.contains("project=11"));
    }

    #[test]
    fn format_ext4_quota_inodes_partial() {
        use ffs_ondisk::ext4::Ext4QuotaInodes;
        let quota = Ext4QuotaInodes {
            user: Some(3),
            group: None,
            project: Some(11),
        };
        let result = format_ext4_quota_inodes(&quota);
        assert!(result.contains("user=3"));
        assert!(!result.contains("group"));
        assert!(result.contains("project=11"));
    }

    #[test]
    fn format_ext4_quota_inodes_empty() {
        use ffs_ondisk::ext4::Ext4QuotaInodes;
        let quota = Ext4QuotaInodes {
            user: None,
            group: None,
            project: None,
        };
        let result = format_ext4_quota_inodes(&quota);
        assert!(result.is_empty());
    }

    // ── bytes_to_hex_dump: raw data display helper ───────────────────────

    #[test]
    fn bytes_to_hex_dump_empty_input() {
        use super::bytes_to_hex_dump;
        let result = bytes_to_hex_dump(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn bytes_to_hex_dump_single_byte() {
        use super::bytes_to_hex_dump;
        let result = bytes_to_hex_dump(&[0xab]);
        assert_eq!(result, "00000000: ab\n");
    }

    #[test]
    fn bytes_to_hex_dump_full_line() {
        use super::bytes_to_hex_dump;
        let input: Vec<u8> = (0u8..16).collect();
        let result = bytes_to_hex_dump(&input);
        assert!(result.starts_with("00000000:"));
        assert!(result.contains(" 00 01 02 03"));
        assert!(result.contains(" 0f"));
        assert_eq!(result.lines().count(), 1);
    }

    #[test]
    fn bytes_to_hex_dump_multiple_lines() {
        use super::bytes_to_hex_dump;
        let input: Vec<u8> = (0u8..32).collect();
        let result = bytes_to_hex_dump(&input);
        let lines: Vec<_> = result.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("00000000:"));
        assert!(lines[1].starts_with("00000010:"));
    }

    #[test]
    fn bytes_to_hex_dump_partial_last_line() {
        use super::bytes_to_hex_dump;
        let input: Vec<u8> = (0u8..20).collect();
        let result = bytes_to_hex_dump(&input);
        let lines: Vec<_> = result.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[1].starts_with("00000010:"));
        assert!(lines[1].contains(" 10 11 12 13"));
    }

    // ── choose_btrfs_scrub_block_size: geometry validation ───────────────

    #[test]
    fn choose_btrfs_scrub_block_size_aligned_to_nodesize() {
        let block_size = choose_btrfs_scrub_block_size(16384 * 10, 16384, 4096)
            .expect("aligned image should succeed");
        assert_eq!(block_size, 16384);
    }

    #[test]
    fn choose_btrfs_scrub_block_size_falls_back_to_smaller_alignment() {
        // image length 40960 = 10 * 4096, not divisible by 16384
        let block_size = choose_btrfs_scrub_block_size(40960, 16384, 4096)
            .expect("should fall back to smaller aligned block size");
        assert!(block_size <= 16384);
        assert!(block_size >= 4096);
        assert_eq!(40960 % u64::from(block_size), 0);
    }

    #[test]
    fn choose_btrfs_scrub_block_size_rejects_zero_nodesize() {
        let err = choose_btrfs_scrub_block_size(65536, 0, 4096);
        assert!(err.is_err());
    }

    #[test]
    fn choose_btrfs_scrub_block_size_rejects_non_power_of_two_nodesize() {
        let err = choose_btrfs_scrub_block_size(65536, 12288, 4096);
        assert!(err.is_err());
    }

    #[test]
    fn choose_btrfs_scrub_block_size_rejects_unaligned_image() {
        let err = choose_btrfs_scrub_block_size(4097, 4096, 4096);
        assert!(err.is_err());
    }

    #[test]
    fn choose_btrfs_scrub_block_size_enforces_minimum_4096() {
        // sectorsize < 4096 should still enforce 4096 floor
        let block_size = choose_btrfs_scrub_block_size(4096 * 4, 4096, 512)
            .expect("should succeed with 4096 floor");
        assert!(block_size >= 4096);
    }

    // ── count_blocks_at_severity_or_higher: block deduplication ──────────

    #[test]
    fn count_blocks_at_severity_or_higher_empty_report() {
        let report = ScrubReport {
            findings: vec![],
            blocks_scanned: 100,
            blocks_corrupt: 0,
            blocks_io_error: 0,
        };
        assert_eq!(
            count_blocks_at_severity_or_higher(&report, Severity::Info),
            0
        );
        assert_eq!(
            count_blocks_at_severity_or_higher(&report, Severity::Error),
            0
        );
    }

    #[test]
    fn count_blocks_at_severity_or_higher_deduplicates_same_block() {
        let report = ScrubReport {
            findings: vec![
                ScrubFinding {
                    block: BlockNumber(1),
                    kind: CorruptionKind::ChecksumMismatch,
                    severity: Severity::Error,
                    detail: "first error".into(),
                },
                ScrubFinding {
                    block: BlockNumber(1),
                    kind: CorruptionKind::ChecksumMismatch,
                    severity: Severity::Error,
                    detail: "second error same block".into(),
                },
            ],
            blocks_scanned: 100,
            blocks_corrupt: 1,
            blocks_io_error: 0,
        };
        // Two findings on same block should count as 1 block.
        assert_eq!(
            count_blocks_at_severity_or_higher(&report, Severity::Error),
            1
        );
    }

    #[test]
    fn count_blocks_at_severity_or_higher_filters_by_severity() {
        let report = ScrubReport {
            findings: vec![
                ScrubFinding {
                    block: BlockNumber(1),
                    kind: CorruptionKind::ChecksumMismatch,
                    severity: Severity::Info,
                    detail: "info finding".into(),
                },
                ScrubFinding {
                    block: BlockNumber(2),
                    kind: CorruptionKind::ChecksumMismatch,
                    severity: Severity::Warning,
                    detail: "warning finding".into(),
                },
                ScrubFinding {
                    block: BlockNumber(3),
                    kind: CorruptionKind::ChecksumMismatch,
                    severity: Severity::Error,
                    detail: "error finding".into(),
                },
                ScrubFinding {
                    block: BlockNumber(4),
                    kind: CorruptionKind::ChecksumMismatch,
                    severity: Severity::Critical,
                    detail: "critical finding".into(),
                },
            ],
            blocks_scanned: 100,
            blocks_corrupt: 4,
            blocks_io_error: 0,
        };
        assert_eq!(
            count_blocks_at_severity_or_higher(&report, Severity::Info),
            4
        );
        assert_eq!(
            count_blocks_at_severity_or_higher(&report, Severity::Warning),
            3
        );
        assert_eq!(
            count_blocks_at_severity_or_higher(&report, Severity::Error),
            2
        );
        assert_eq!(
            count_blocks_at_severity_or_higher(&report, Severity::Critical),
            1
        );
    }

    // ── ext4_group_scrub_scope: block group geometry ─────────────────────

    #[test]
    fn ext4_group_scrub_scope_first_group() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let sb = ffs_ondisk::Ext4Superblock::parse_from_image(&image)
            .expect("parse test ext4 superblock");
        let (start, count) = ext4_group_scrub_scope(&sb, 0).expect("group 0 should be valid");
        assert_eq!(start.0, u64::from(sb.first_data_block));
        assert!(count > 0);
    }

    #[test]
    fn ext4_group_scrub_scope_out_of_range() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let sb = ffs_ondisk::Ext4Superblock::parse_from_image(&image)
            .expect("parse test ext4 superblock");
        let err = ext4_group_scrub_scope(&sb, 9999);
        assert!(err.is_err(), "group 9999 should be out of range");
    }

    // ── ext4_recovery_detail: formatting output ──────────────────────────

    #[test]
    fn ext4_recovery_detail_formats_all_fields() {
        let recovery = Ext4RecoveryOutput {
            recovery_performed: true,
            crash_recovery: ffs_core::CrashRecoveryOutcome {
                was_clean: false,
                raw_state: 0x0002,
                had_errors: true,
                had_orphans: true,
                journal_txns_replayed: 5,
                journal_blocks_replayed: 10,
                mvcc_reset: true,
            },
        };
        let detail = ext4_recovery_detail(&recovery);
        assert!(detail.contains("recovery_performed=true"));
        assert!(detail.contains("clean=false"));
        assert!(detail.contains("had_errors=true"));
        assert!(detail.contains("had_orphans=true"));
        assert!(detail.contains("journal_txns_replayed=5"));
        assert!(detail.contains("journal_blocks_replayed=10"));
    }

    #[test]
    fn ext4_recovery_detail_clean_filesystem() {
        let recovery = Ext4RecoveryOutput {
            recovery_performed: false,
            crash_recovery: ffs_core::CrashRecoveryOutcome {
                was_clean: true,
                raw_state: 0x0001,
                had_errors: false,
                had_orphans: false,
                journal_txns_replayed: 0,
                journal_blocks_replayed: 0,
                mvcc_reset: false,
            },
        };
        let detail = ext4_recovery_detail(&recovery);
        assert!(detail.contains("recovery_performed=false"));
        assert!(detail.contains("clean=true"));
        assert!(detail.contains("had_errors=false"));
        assert!(detail.contains("had_orphans=false"));
    }

    // ── select_ext4_repair_groups: fresh-only path ───────────────────────

    #[test]
    fn repair_selection_returns_empty_when_all_fresh() {
        let all = vec![0, 1, 2];
        let staleness = vec![
            (0, Ext4RepairStaleness::Fresh),
            (1, Ext4RepairStaleness::Fresh),
            (2, Ext4RepairStaleness::Fresh),
        ];
        let selected = select_ext4_repair_groups(RepairFlags::empty(), false, &all, &staleness);
        assert!(selected.is_empty());
    }

    #[test]
    fn repair_selection_full_scrub_overrides_fresh_state() {
        let all = vec![0, 1, 2];
        let staleness = vec![
            (0, Ext4RepairStaleness::Fresh),
            (1, Ext4RepairStaleness::Fresh),
            (2, Ext4RepairStaleness::Fresh),
        ];
        let selected = select_ext4_repair_groups(
            RepairFlags::empty().with_full_scrub(true),
            true,
            &all,
            &staleness,
        );
        assert_eq!(selected, all);
    }

    #[test]
    fn repair_selection_empty_staleness_and_dirty_returns_all() {
        let all = vec![0, 1, 2];
        let staleness: Vec<(u32, Ext4RepairStaleness)> = vec![];
        let selected = select_ext4_repair_groups(RepairFlags::empty(), false, &all, &staleness);
        assert_eq!(selected, all);
    }

    #[test]
    fn repair_selection_empty_staleness_and_clean_skips_repair() {
        let all = vec![0, 1, 2];
        let staleness: Vec<(u32, Ext4RepairStaleness)> = vec![];
        let selected = select_ext4_repair_groups(RepairFlags::empty(), true, &all, &staleness);
        assert!(selected.is_empty());
    }

    // ── WAL replay telemetry tests ──────────────────────────────────────

    const REPRESENTATIVE_MVCC_INFO_OUTPUT_GOLDEN: &str = r#"{
  "current_commit_seq": 10,
  "active_snapshot_count": 1,
  "oldest_active_snapshot": 5,
  "total_versioned_blocks": 20,
  "max_chain_depth": 3,
  "average_chain_depth": "1.500",
  "blocks_pending_gc": 4,
  "ssi_conflict_count": 0,
  "abort_count": 0,
  "wal_replay": {
    "outcome": "EmptyLog",
    "is_clean": true,
    "commits_replayed": 0,
    "versions_replayed": 0,
    "records_discarded": 0,
    "wal_valid_bytes": 16,
    "wal_total_bytes": 16,
    "used_checkpoint": false
  }
}"#;

    #[test]
    fn wal_replay_info_output_serializes_to_stable_json_schema() {
        use super::WalReplayInfoOutput;

        let info = WalReplayInfoOutput {
            outcome: "Clean".to_owned(),
            is_clean: true,
            commits_replayed: 5,
            versions_replayed: 12,
            records_discarded: 0,
            wal_valid_bytes: 2048,
            wal_total_bytes: 2048,
            used_checkpoint: false,
            checkpoint_commit_seq: None,
        };
        let json_str =
            serde_json::to_string_pretty(&info).expect("WalReplayInfoOutput should serialize");
        let parsed: Value = serde_json::from_str(&json_str).expect("should parse as JSON");

        assert_eq!(parsed["outcome"], "Clean");
        assert_eq!(parsed["is_clean"], true);
        assert_eq!(parsed["commits_replayed"], 5);
        assert_eq!(parsed["versions_replayed"], 12);
        assert_eq!(parsed["records_discarded"], 0);
        assert_eq!(parsed["wal_valid_bytes"], 2048);
        assert_eq!(parsed["wal_total_bytes"], 2048);
        assert_eq!(parsed["used_checkpoint"], false);
        // checkpoint_commit_seq should be omitted when None
        assert!(parsed.get("checkpoint_commit_seq").is_none());
    }

    #[test]
    fn wal_replay_info_output_includes_checkpoint_when_present() {
        use super::WalReplayInfoOutput;

        let info = WalReplayInfoOutput {
            outcome: "TruncatedTail".to_owned(),
            is_clean: false,
            commits_replayed: 3,
            versions_replayed: 7,
            records_discarded: 1,
            wal_valid_bytes: 1024,
            wal_total_bytes: 1500,
            used_checkpoint: true,
            checkpoint_commit_seq: Some(42),
        };
        let json_str =
            serde_json::to_string_pretty(&info).expect("WalReplayInfoOutput should serialize");
        let parsed: Value = serde_json::from_str(&json_str).expect("should parse as JSON");

        assert_eq!(parsed["is_clean"], false);
        assert_eq!(parsed["records_discarded"], 1);
        assert_eq!(parsed["used_checkpoint"], true);
        assert_eq!(parsed["checkpoint_commit_seq"], 42);
    }

    #[test]
    fn mvcc_stats_output_omits_wal_replay_when_none() {
        use super::{BlockVersionStatsOutput, EbrVersionStatsOutput, MvccStatsOutput};

        let output = MvccStatsOutput {
            block_versions: BlockVersionStatsOutput {
                tracked_blocks: 10,
                max_chain_length: 2,
                chains_over_cap: 0,
                chains_over_critical: 0,
                chain_cap: Some(8),
                critical_chain_length: Some(6),
            },
            ebr_versions: EbrVersionStatsOutput {
                retired: 5,
                reclaimed: 3,
                pending: 2,
            },
            wal_replay: None,
        };
        let json_str =
            serde_json::to_string_pretty(&output).expect("MvccStatsOutput should serialize");
        let parsed: Value = serde_json::from_str(&json_str).expect("should parse as JSON");

        assert!(
            parsed.get("wal_replay").is_none(),
            "wal_replay should be omitted from JSON when None"
        );
        assert_eq!(parsed["block_versions"]["tracked_blocks"], 10);
    }

    #[test]
    fn mvcc_stats_output_includes_wal_replay_when_present() {
        use super::{
            BlockVersionStatsOutput, EbrVersionStatsOutput, MvccStatsOutput, WalReplayInfoOutput,
        };

        let output = MvccStatsOutput {
            block_versions: BlockVersionStatsOutput {
                tracked_blocks: 5,
                max_chain_length: 1,
                chains_over_cap: 0,
                chains_over_critical: 0,
                chain_cap: None,
                critical_chain_length: None,
            },
            ebr_versions: EbrVersionStatsOutput {
                retired: 0,
                reclaimed: 0,
                pending: 0,
            },
            wal_replay: Some(WalReplayInfoOutput {
                outcome: "CorruptTail".to_owned(),
                is_clean: false,
                commits_replayed: 1,
                versions_replayed: 2,
                records_discarded: 3,
                wal_valid_bytes: 512,
                wal_total_bytes: 800,
                used_checkpoint: false,
                checkpoint_commit_seq: None,
            }),
        };
        let json_str =
            serde_json::to_string_pretty(&output).expect("MvccStatsOutput should serialize");
        let parsed: Value = serde_json::from_str(&json_str).expect("should parse as JSON");

        let wal = &parsed["wal_replay"];
        assert_eq!(wal["outcome"], "CorruptTail");
        assert_eq!(wal["is_clean"], false);
        assert_eq!(wal["commits_replayed"], 1);
        assert_eq!(wal["records_discarded"], 3);
    }

    #[test]
    fn mvcc_info_output_includes_wal_replay_when_present() {
        use super::{MvccInfoOutput, WalReplayInfoOutput};

        let output = MvccInfoOutput {
            current_commit_seq: 10,
            active_snapshot_count: 1,
            oldest_active_snapshot: Some(5),
            total_versioned_blocks: 20,
            max_chain_depth: 3,
            average_chain_depth: "1.500".to_owned(),
            blocks_pending_gc: 4,
            ssi_conflict_count: Some(0),
            abort_count: Some(0),
            wal_replay: Some(WalReplayInfoOutput {
                outcome: "EmptyLog".to_owned(),
                is_clean: true,
                commits_replayed: 0,
                versions_replayed: 0,
                records_discarded: 0,
                wal_valid_bytes: 16,
                wal_total_bytes: 16,
                used_checkpoint: false,
                checkpoint_commit_seq: None,
            }),
        };
        let json_str =
            serde_json::to_string_pretty(&output).expect("MvccInfoOutput should serialize");
        let parsed: Value = serde_json::from_str(&json_str).expect("should parse as JSON");

        assert_eq!(parsed["current_commit_seq"], 10);
        let wal = &parsed["wal_replay"];
        assert_eq!(wal["outcome"], "EmptyLog");
        assert_eq!(wal["is_clean"], true);
        assert_eq!(wal["wal_valid_bytes"], 16);
    }

    #[test]
    fn representative_mvcc_info_json_exact_golden_contract() {
        use super::{MvccInfoOutput, WalReplayInfoOutput};

        let output = MvccInfoOutput {
            current_commit_seq: 10,
            active_snapshot_count: 1,
            oldest_active_snapshot: Some(5),
            total_versioned_blocks: 20,
            max_chain_depth: 3,
            average_chain_depth: "1.500".to_owned(),
            blocks_pending_gc: 4,
            ssi_conflict_count: Some(0),
            abort_count: Some(0),
            wal_replay: Some(WalReplayInfoOutput {
                outcome: "EmptyLog".to_owned(),
                is_clean: true,
                commits_replayed: 0,
                versions_replayed: 0,
                records_discarded: 0,
                wal_valid_bytes: 16,
                wal_total_bytes: 16,
                used_checkpoint: false,
                checkpoint_commit_seq: None,
            }),
        };

        let json = serde_json::to_string_pretty(&output).expect("MvccInfoOutput should serialize");
        assert_eq!(json, REPRESENTATIVE_MVCC_INFO_OUTPUT_GOLDEN);
    }

    // ── Property-based tests ────────────────────────────────────────────────

    mod proptests {
        use super::{format_ratio_thousandths, format_uuid};
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn format_ratio_thousandths_always_has_three_decimal_places(
                num in 0_usize..=usize::MAX / 2,
                denom in 0_usize..=usize::MAX / 2,
            ) {
                let result = format_ratio_thousandths(num, denom);
                prop_assert!(result.contains('.'), "missing decimal point: {}", result);
                let parts: Vec<_> = result.split('.').collect();
                prop_assert_eq!(parts.len(), 2, "expected exactly one decimal point: {}", result);
                prop_assert_eq!(parts[1].len(), 3, "expected 3 decimal places: {}", result);
            }

            #[test]
            fn format_uuid_always_36_chars(uuid in proptest::collection::vec(any::<u8>(), 16..=16)) {
                let uuid_arr: [u8; 16] = uuid.try_into().unwrap();
                let result = format_uuid(&uuid_arr);
                prop_assert_eq!(result.len(), 36, "UUID should be 36 chars: {}", result);
            }

            #[test]
            fn format_uuid_has_correct_dash_positions(uuid in proptest::collection::vec(any::<u8>(), 16..=16)) {
                let uuid_arr: [u8; 16] = uuid.try_into().unwrap();
                let result = format_uuid(&uuid_arr);
                let chars: Vec<_> = result.chars().collect();
                prop_assert_eq!(chars[8], '-', "expected dash at pos 8");
                prop_assert_eq!(chars[13], '-', "expected dash at pos 13");
                prop_assert_eq!(chars[18], '-', "expected dash at pos 18");
                prop_assert_eq!(chars[23], '-', "expected dash at pos 23");
            }

            #[test]
            fn format_uuid_only_hex_and_dashes(uuid in proptest::collection::vec(any::<u8>(), 16..=16)) {
                let uuid_arr: [u8; 16] = uuid.try_into().unwrap();
                let result = format_uuid(&uuid_arr);
                for c in result.chars() {
                    prop_assert!(
                        c.is_ascii_hexdigit() || c == '-',
                        "unexpected char '{c}' in UUID: {result}"
                    );
                }
            }
        }
    }
}
