#![forbid(unsafe_code)]

//! Real mounted-kernel versus FrankenFS FUSE comparator.
//!
//! The harness owns four live mounts in one invocation:
//! two byte-identical kernel filesystems and two byte-identical FrankenFS FUSE
//! filesystems. A balanced physical-arm crossover interleaves all four mounts,
//! so the two kernel mounts provide an incumbent A/A null and the two FUSE
//! mounts provide a candidate A/A null without confounding either null with a
//! fixed image or loop-device effect. Competitive latency is reported only
//! when both crossover-block null confidence intervals are tight, mount
//! identity is proven at runtime, the FUSE daemons self-report their executing
//! ELF SHA-256, and untimed content and metadata parity pass.

use anyhow::{Context, Result, anyhow, bail, ensure};
use nix::sched::{CpuSet, sched_getcpu, sched_setaffinity};
use nix::unistd::Pid;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::hint::black_box;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BOOTSTRAP_RESAMPLES: usize = 20_000;
const MAXIMUM_NULL_MEDIAN_DEVIATION: f64 = 0.02;
const MIN_FREE_BYTES: u64 = 120 * 1024 * 1024 * 1024;
const MAX_IMAGE_MIB: u64 = 2048;
const PAYLOAD_BYTES: usize = 1024 * 1024;
const MOUNT_READY_TIMEOUT: Duration = Duration::from_secs(20);
const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const CPU_SAMPLE_INTERVAL_MS: u64 = 1_000;
const CPU_SAMPLE_INTERVAL: Duration = Duration::from_millis(CPU_SAMPLE_INTERVAL_MS);
const MAX_DRIVER_PREFLIGHT_BUSY: f64 = 0.20;
const MAX_FUSE_PREFLIGHT_BUSY: f64 = 0.35;
const DEFAULT_HOST_QUIET_SAMPLES: usize = 5;
const DEFAULT_HOST_QUIET_TIMEOUT_MS: u64 = 300_000;
const MAX_HOST_QUIET_SAMPLES: usize = 60;
const MAX_HOST_QUIET_TIMEOUT_MS: u64 = 900_000;
const MOUNT_ROOT: &str = "/tmp/frankenfs-mounted-kernel-mounts";
const DEFAULT_PARALLEL_THREADS: usize = 8;
/// One daemon CPU is what every banked row was measured at; see `Config::fuse_cpu_count`.
const DEFAULT_FUSE_CPUS: usize = 1;
const MAX_CLIENT_THREADS: usize = 4096;
const PARALLEL_READ_FILE_BYTES: usize = 256 * 1024;
const BULK_DURABLE_FILE: &str = "bulk-durable.bin";
const BULK_DURABLE_CHUNK_BYTES: usize = 1024 * 1024;
const BULK_DURABLE_IMAGE_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;
const XATTR_INLINE_FILE: &str = "xattr-inline.bin";
const XATTR_EXTERNAL_FILE: &str = "xattr-external.bin";
const XATTR_MANY_FILE: &str = "xattr-many.bin";
const XATTR_INLINE_NAME: &str = "user.inline";
const XATTR_EXTERNAL_NAME: &str = "user.external";
const XATTR_ABSENT_NAME: &str = "user.absent";
const XATTR_INLINE_VALUE: &[u8] = b"inline-value";
const XATTR_EXTERNAL_VALUE_BYTES: usize = 512;
const XATTR_MANY_NAMES: usize = 24;
const WARMUP_ROUNDS: usize = 8;
const PHYSICAL_ROLE_CROSSOVER_ROUNDS: usize = 2;
const ESTIMATOR_BLOCK_ROUNDS: usize = 4;
const ESTIMATOR_BLOCK_DIVISOR: f64 = 4.0;
const MAX_ARM_SETTLE_MS: u64 = 10_000;
const MAX_PRE_MEASUREMENT_SETTLE_MS: u64 = 60_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FilesystemKind {
    Ext4,
    Btrfs,
}

impl FilesystemKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Ext4 => "ext4",
            Self::Btrfs => "btrfs",
        }
    }

    const fn kernel_module(self) -> &'static str {
        match self {
            Self::Ext4 => "ext4",
            Self::Btrfs => "btrfs",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestedFilesystems {
    Ext4,
    Btrfs,
    Both,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlacementScope {
    SameLlc,
    HostWide,
}

impl PlacementScope {
    const fn label(self) -> &'static str {
        match self {
            Self::SameLlc => "same_llc",
            Self::HostWide => "host_wide",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Workload {
    WarmStat,
    ParallelMetadataWrite,
    ParallelRead8,
    ParallelRead8ColdCache,
    CreateDeleteStorm,
    ReaddirStat8,
    FsyncJournalCommit,
    BulkDurableWrite,
    XattrGetListReport,
}

impl Workload {
    const fn label(self) -> &'static str {
        match self {
            Self::WarmStat => "warm_stat",
            Self::ParallelMetadataWrite => "parallel_metadata_write",
            Self::ParallelRead8 => "parallel_read_multifile_8t",
            Self::ParallelRead8ColdCache => "parallel_read_multifile_8t_cold_cache",
            Self::CreateDeleteStorm => "small_file_create_delete_storm",
            Self::ReaddirStat8 => "large_directory_readdir_stat_8t",
            Self::FsyncJournalCommit => "fsync_journal_commit",
            Self::BulkDurableWrite => "bulk_durable_write",
            Self::XattrGetListReport => "xattr_get_list_report",
        }
    }

    const fn is_mutating(self) -> bool {
        matches!(
            self,
            Self::ParallelMetadataWrite
                | Self::CreateDeleteStorm
                | Self::FsyncJournalCommit
                | Self::BulkDurableWrite
        )
    }

    const fn client_threads(self, configured: usize) -> usize {
        match self {
            Self::ParallelMetadataWrite => configured,
            Self::ParallelRead8 | Self::ParallelRead8ColdCache | Self::ReaddirStat8 => {
                DEFAULT_PARALLEL_THREADS
            }
            Self::WarmStat
            | Self::CreateDeleteStorm
            | Self::FsyncJournalCommit
            | Self::BulkDurableWrite
            | Self::XattrGetListReport => 1,
        }
    }

    const fn durability(self) -> &'static str {
        match self {
            Self::ParallelMetadataWrite => "create_then_fsync_each_worker_directory",
            Self::CreateDeleteStorm => "create_fsyncdir_delete_fsyncdir",
            Self::FsyncJournalCommit => "write_4k_then_fsync_each_operation",
            Self::BulkDurableWrite => "overwrite_1m_chunks_then_single_file_fsync",
            Self::WarmStat
            | Self::ParallelRead8
            | Self::ParallelRead8ColdCache
            | Self::ReaddirStat8
            | Self::XattrGetListReport => "read_only_no_mutation",
        }
    }

    const fn observation_reducer(self) -> &'static str {
        if self.is_mutating() { "single" } else { "min" }
    }

    const fn worker_thread_observation_method(self) -> &'static str {
        match self {
            Self::ParallelMetadataWrite
            | Self::ParallelRead8
            | Self::ParallelRead8ColdCache
            | Self::ReaddirStat8 => "unique Linux TIDs reported by workers inside each timed batch",
            Self::WarmStat
            | Self::CreateDeleteStorm
            | Self::FsyncJournalCommit
            | Self::BulkDurableWrite
            | Self::XattrGetListReport => {
                "single Linux benchmark-driver TID observed before and after each timed batch"
            }
        }
    }

    fn job_statement(self, operations: usize, client_threads: usize) -> String {
        match self {
            Self::WarmStat => format!(
                "one warm-cache metadata report job: issue {operations} stat calls for one \
                 mounted file and aggregate the observed metadata"
            ),
            Self::ParallelMetadataWrite => format!(
                "one parallel namespace job: {client_threads} workers create exactly \
                 {operations} empty files across private directories and fsync every worker \
                 directory"
            ),
            Self::ParallelRead8 => format!(
                "one warm-cache multi-file read job: enumerate and byte-sort {operations} \
                 separate {PARALLEL_READ_FILE_BYTES}-byte files, then {client_threads} workers \
                 open and pread every file exactly once ({} total bytes) and aggregate a \
                 content digest",
                operations.saturating_mul(PARALLEL_READ_FILE_BYTES)
            ),
            Self::ParallelRead8ColdCache => format!(
                "one cold-cache multi-file read job: before every timed batch, sync and write 3 \
                 to /proc/sys/vm/drop_caches; then enumerate and byte-sort {operations} separate \
                 {PARALLEL_READ_FILE_BYTES}-byte files, and have {client_threads} workers open \
                 and pread every file exactly once ({} total bytes) and aggregate a content digest",
                operations.saturating_mul(PARALLEL_READ_FILE_BYTES)
            ),
            Self::CreateDeleteStorm => format!(
                "one small-file namespace transaction job: serially create {operations} empty \
                 files, fsync the parent directory, delete all {operations} files, and fsync \
                 the parent directory again"
            ),
            Self::ReaddirStat8 => format!(
                "one warm-cache large-directory report job: enumerate {operations} zero-byte \
                 entries, then {client_threads} workers read metadata for every entry exactly \
                 once and aggregate a metadata digest"
            ),
            Self::FsyncJournalCommit => format!(
                "one durability job: perform {operations} 4096-byte positioned writes to one \
                 mounted file and fsync after every write"
            ),
            Self::BulkDurableWrite => format!(
                "one bulk durable output job: overwrite one preallocated file with {operations} \
                 sequential {BULK_DURABLE_CHUNK_BYTES}-byte positioned writes ({} total bytes), \
                 then fsync the file once",
                operations.saturating_mul(BULK_DURABLE_CHUNK_BYTES)
            ),
            Self::XattrGetListReport => format!(
                "one warm-cache xattr report job: repeat {operations} complete five-call \
                 reports, each reading one inline value, reading one external-block value, \
                 checking one absent name, listing one name, and listing {XATTR_MANY_NAMES} \
                 names"
            ),
        }
    }

    fn chooser_statement(
        self,
        filesystem: FilesystemKind,
        operations: usize,
        requested_threads: usize,
        observed_threads: Option<usize>,
    ) -> String {
        let observed = observed_threads
            .map_or_else(|| "not admitted".to_owned(), |threads| threads.to_string());
        format!(
            "For operators choosing between FrankenFS FUSE and Linux kernel {} for \
             workload={} on the recorded host, ISA, frequency policy, mount options, and \
             {} regime: this result applies only to operations={operations}, \
             requested_worker_threads={requested_threads}, \
             observed_worker_threads={observed}, and durability={}; do not generalize it to \
             other filesystem, working-set, cache, thread, durability, mount, or hardware \
             shapes.",
            filesystem.label(),
            self.label(),
            self.cache_regime_label(),
            self.durability()
        )
    }

    fn semantic_work_contract(self, operations: usize, client_threads: usize) -> Value {
        let common = json!({
            "operations_parameter": operations,
            "requested_worker_threads": client_threads,
            "same_driver_implementation_for_all_four_arms": true,
            "exact_work_required_for_admission": true,
        });
        let detail = match self {
            Self::WarmStat => json!({
                "stat_calls": operations,
                "input_files": 1,
            }),
            Self::ParallelMetadataWrite => json!({
                "files_created": operations,
                "worker_directories_fsynced": client_threads,
                "deterministic_remainder_partition": true,
            }),
            Self::ParallelRead8 => json!({
                "files_enumerated": operations,
                "files_opened": operations,
                "positioned_reads": operations,
                "bytes_per_file": PARALLEL_READ_FILE_BYTES,
                "total_bytes_read": operations.saturating_mul(PARALLEL_READ_FILE_BYTES),
            }),
            Self::ParallelRead8ColdCache => json!({
                "files_enumerated": operations,
                "files_opened": operations,
                "positioned_reads": operations,
                "bytes_per_file": PARALLEL_READ_FILE_BYTES,
                "total_bytes_read": operations.saturating_mul(PARALLEL_READ_FILE_BYTES),
                "cache_clear_before_every_timed_batch": "sync; write 3 to /proc/sys/vm/drop_caches",
                "warmup_batches": 0,
            }),
            Self::CreateDeleteStorm => json!({
                "empty_files_created": operations,
                "empty_files_deleted": operations,
                "parent_directory_fsyncs": 2,
            }),
            Self::ReaddirStat8 => json!({
                "directory_entries_enumerated": operations,
                "metadata_reads": operations,
                "fixture_entry_bytes": 0,
            }),
            Self::FsyncJournalCommit => json!({
                "positioned_writes": operations,
                "bytes_per_write": 4096,
                "file_fsyncs": operations,
                "total_bytes_written": operations.saturating_mul(4096),
            }),
            Self::BulkDurableWrite => json!({
                "positioned_writes": operations,
                "bytes_per_write": BULK_DURABLE_CHUNK_BYTES,
                "file_fsyncs": 1,
                "total_bytes_written": operations.saturating_mul(BULK_DURABLE_CHUNK_BYTES),
                "preallocated_fixed_length_file": true,
                "entire_file_overwritten": true,
                "final_bytes_and_sha256_validated_outside_timing": true,
            }),
            Self::XattrGetListReport => json!({
                "complete_reports": operations,
                "xattr_api_calls_per_report": 5,
                "total_xattr_api_calls": operations.saturating_mul(5),
                "inline_get_hits": operations,
                "external_block_get_hits": operations,
                "absent_get_lookups": operations,
                "single_name_lists": operations,
                "many_name_lists": operations,
                "many_list_names": XATTR_MANY_NAMES,
                "returned_names_and_values_validated_outside_timing": true,
            }),
        };
        json!({
            "common": common,
            "workload_specific": detail,
        })
    }

    const fn uses_cold_cache(self) -> bool {
        matches!(self, Self::ParallelRead8ColdCache)
    }

    const fn warmup_rounds(self) -> usize {
        if self.uses_cold_cache() {
            0
        } else {
            WARMUP_ROUNDS
        }
    }

    const fn cache_regime_label(self) -> &'static str {
        if self.uses_cold_cache() {
            "cold-cache (sync then write 3 to /proc/sys/vm/drop_caches before every timed batch)"
        } else {
            "warm-cache"
        }
    }

    const fn cache_regime_provenance(self) -> &'static str {
        if self.uses_cold_cache() {
            "cold-cache: warmups disabled; before every timed batch run sync, then write 3 to /proc/sys/vm/drop_caches outside the timed interval"
        } else {
            "identical balanced warm-cache rounds; no global cache drop"
        }
    }
}

#[derive(Clone, Debug)]
struct Config {
    ffs_cli: PathBuf,
    artifact_root: PathBuf,
    filesystems: RequestedFilesystems,
    workload: Workload,
    pairs: usize,
    operations: usize,
    observation_repeats: usize,
    image_size_mib: u64,
    maximum_null_ratio: f64,
    arm_settle_ms: u64,
    pre_measurement_settle_ms: u64,
    client_threads: usize,
    /// Logical CPUs the FrankenFS daemon is pinned to.
    ///
    /// The default of one reproduces every banked row. It is also an asymmetry:
    /// in the kernel arm the filesystem executes inside the client threads, so
    /// in-kernel ext4 gets one CPU of filesystem capacity per client thread
    /// while the FUSE arm gets one in total. Raising this matches the two arms'
    /// filesystem CPU budgets; both placements must be published side by side,
    /// and a number taken at one of them never replaces a number taken at the
    /// other.
    fuse_cpu_count: usize,
    placement_scope: PlacementScope,
    host_quiet_samples: usize,
    host_quiet_timeout_ms: u64,
    /// Machine that produced the driver ELF, and the one that produced the
    /// candidate ELF. `rch exec` has no artifact-retrieval mechanism, so both
    /// binaries are built on a remote worker and copied here; a binary of
    /// unknown origin is not evidence, so both are mandatory and recorded.
    harness_builder: String,
    candidate_builder: String,
    output: Option<PathBuf>,
}

impl Config {
    const fn client_threads(&self) -> usize {
        self.workload.client_threads(self.client_threads)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ffs_cli: PathBuf::new(),
            artifact_root: PathBuf::from("/data/tmp/frankenfs-mounted-kernel"),
            filesystems: RequestedFilesystems::Both,
            workload: Workload::WarmStat,
            pairs: 32,
            operations: 2_000,
            observation_repeats: 3,
            image_size_mib: 256,
            maximum_null_ratio: 1.025,
            arm_settle_ms: 100,
            pre_measurement_settle_ms: 1_000,
            client_threads: DEFAULT_PARALLEL_THREADS,
            fuse_cpu_count: DEFAULT_FUSE_CPUS,
            placement_scope: PlacementScope::SameLlc,
            host_quiet_samples: DEFAULT_HOST_QUIET_SAMPLES,
            host_quiet_timeout_ms: DEFAULT_HOST_QUIET_TIMEOUT_MS,
            harness_builder: String::new(),
            candidate_builder: String::new(),
            output: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Arm {
    KernelA,
    KernelB,
    FuseA,
    FuseB,
}

impl Arm {
    const fn label(self) -> &'static str {
        match self {
            Self::KernelA => "kernel_a",
            Self::KernelB => "kernel_b",
            Self::FuseA => "fuse_a",
            Self::FuseB => "fuse_b",
        }
    }

    const fn crossover_peer(self) -> Self {
        match self {
            Self::KernelA => Self::KernelB,
            Self::KernelB => Self::KernelA,
            Self::FuseA => Self::FuseB,
            Self::FuseB => Self::FuseA,
        }
    }
}

const BALANCED_ORDERS: [[Arm; 4]; 4] = [
    [Arm::KernelA, Arm::FuseA, Arm::KernelB, Arm::FuseB],
    [Arm::FuseB, Arm::KernelB, Arm::FuseA, Arm::KernelA],
    [Arm::KernelB, Arm::FuseB, Arm::KernelA, Arm::FuseA],
    [Arm::FuseA, Arm::KernelA, Arm::FuseB, Arm::KernelB],
];

#[derive(Clone, Copy, Debug)]
struct BootstrapMedianCi {
    median: f64,
    low: f64,
    high: f64,
}

impl BootstrapMedianCi {
    fn symmetric_spread(self) -> f64 {
        self.high.max(1.0 / self.low)
    }

    fn median_within_null_bias_limit(self) -> bool {
        ((1.0 - MAXIMUM_NULL_MEDIAN_DEVIATION)..=(1.0 + MAXIMUM_NULL_MEDIAN_DEVIATION))
            .contains(&self.median)
    }

    /// Telemetry only: CI straddling is deliberately not an admission input.
    fn contains_null(self) -> bool {
        self.low <= 1.0 && self.high >= 1.0
    }
}

fn null_control_is_clear(ci: BootstrapMedianCi, maximum_null_ratio: f64) -> bool {
    ci.median_within_null_bias_limit() && ci.symmetric_spread() <= maximum_null_ratio
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MountInfo {
    major_minor: String,
    root: String,
    mountpoint: PathBuf,
    mount_options: BTreeSet<String>,
    filesystem_type: String,
    source: String,
    super_options: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Default)]
struct CpuTicks {
    total: u64,
    idle: u64,
}

#[derive(Clone, Debug)]
struct CpuPlacement {
    driver_cpu: usize,
    driver_cpus: Vec<usize>,
    fuse_cpus: Vec<usize>,
    driver_guard_cpus: BTreeSet<usize>,
    fuse_guard_cpus: BTreeSet<usize>,
    /// How the daemon's CPUs relate to the clients', so a report can never be
    /// read as if the two placements were interchangeable.
    fuse_cpu_isolation: &'static str,
    last_level_cache_cpus: BTreeSet<usize>,
    allowed_cpus: BTreeSet<usize>,
    busy_fractions: BTreeMap<usize, f64>,
    initial_host_quiet_window: Option<HostQuietWindow>,
}

#[derive(Clone, Debug)]
struct HostQuietWindow {
    busy_fractions: BTreeMap<usize, f64>,
    samples_observed: usize,
    elapsed_ms: u64,
}

#[derive(Clone, Debug)]
struct HostProvenance {
    hostname: String,
    cpu_model: String,
    online_cpus: BTreeSet<usize>,
    allowed_cpus_before_pin: BTreeSet<usize>,
    cgroup_cpuset_effective: Option<String>,
    physical_cores: usize,
    memory_bytes: u64,
    numa_nodes: usize,
    runtime_features: BTreeSet<&'static str>,
    cpu_frequency_policy: CpuFrequencyPolicy,
}

#[derive(Clone, Debug)]
struct CpuFrequencyPolicy {
    drivers: BTreeMap<usize, String>,
    governors: BTreeMap<usize, String>,
    energy_performance_preferences: BTreeMap<usize, String>,
}

impl CpuFrequencyPolicy {
    fn governor_warning(&self) -> bool {
        self.governors
            .values()
            .any(|governor| governor != "performance")
    }
}

struct DriverPlacementContext<'a> {
    scope: PlacementScope,
    ranked: &'a [(usize, f64)],
    busy: &'a BTreeMap<usize, f64>,
    driver_domain: &'a BTreeSet<usize>,
    fuse_guard_cpus: &'a BTreeSet<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParityWitness {
    file_sha256: String,
    len: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TreeWitness {
    sha256: String,
    entries: u64,
    regular_files: u64,
    directories: u64,
    bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct XattrWitness {
    sha256: String,
    inline_value_bytes: usize,
    external_value_bytes: usize,
    single_list_names: usize,
    many_list_names: usize,
    absent_lookup_none: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BulkDurableWriteWitness {
    sha256: String,
    bytes: u64,
    uniform_byte: Option<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FfsBinaryIdentity {
    binary_sha256: String,
    pgo_profile_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KernelEngineIdentity {
    release: String,
    artifact: PathBuf,
    artifact_sha256: String,
    runtime_notes_sha256: String,
}

#[derive(Debug)]
struct WorkloadBatch {
    elapsed_ns: u64,
    digest: u64,
    observed_worker_threads: Option<usize>,
    /// CPUs the timed threads were actually running on after being bound.
    observed_worker_cpus: BTreeSet<usize>,
}

#[derive(Debug)]
struct Observation {
    elapsed_ns: u64,
    digest: u64,
    observed_worker_threads: BTreeSet<usize>,
    observed_worker_cpus: BTreeSet<usize>,
}

#[derive(Debug)]
struct TimedSamples {
    /// Samples indexed by the counterbalanced logical A/B assignment.
    values: BTreeMap<Arm, Vec<u64>>,
    /// The same samples indexed by the physical image/mount that executed.
    physical_values: BTreeMap<Arm, Vec<u64>>,
    digests: BTreeMap<Arm, u64>,
    /// Runtime-observed Linux worker-TID counts for each logical arm.
    observed_worker_threads: BTreeMap<Arm, BTreeSet<usize>>,
    /// Runtime-observed running CPUs for each logical arm's timed threads.
    observed_worker_cpus: BTreeMap<Arm, BTreeSet<usize>>,
    /// Last sequence actually executed by every physical arm.
    last_sequence: usize,
}

#[derive(Debug)]
struct MountedArm {
    arm: Arm,
    mountpoint: PathBuf,
    image: PathBuf,
    mount_info: MountInfo,
    kind: MountedArmKind,
}

#[derive(Debug)]
enum MountedArmKind {
    Kernel,
    Fuse {
        child: Child,
        stdout_log: PathBuf,
        stderr_log: PathBuf,
        self_reported_sha256: String,
        proc_exe_sha256: String,
        pgo_profile_sha256: String,
    },
}

impl MountedArm {
    fn workload_root(&self) -> &Path {
        &self.mountpoint
    }

    fn unmount(&mut self) -> Result<()> {
        match &mut self.kind {
            MountedArmKind::Kernel => {
                let status = Command::new("sudo")
                    .args(["-n", "umount"])
                    .arg(&self.mountpoint)
                    .status()
                    .with_context(|| format!("unmount kernel arm {}", self.mountpoint.display()))?;
                ensure!(
                    status.success(),
                    "kernel unmount failed for {}: {status}",
                    self.mountpoint.display()
                );
            }
            MountedArmKind::Fuse { child, .. } => {
                let unmount = Command::new("fusermount3")
                    .args(["-u", "--"])
                    .arg(&self.mountpoint)
                    .status()
                    .with_context(|| format!("unmount FUSE arm {}", self.mountpoint.display()))?;
                ensure!(
                    unmount.success(),
                    "FUSE unmount failed for {}: {unmount}",
                    self.mountpoint.display()
                );
                wait_for_child(child, CHILD_EXIT_TIMEOUT).with_context(|| {
                    format!("wait for FUSE daemon at {}", self.mountpoint.display())
                })?;
            }
        }
        ensure!(
            find_mount(&self.mountpoint)?.is_none(),
            "mount remained active after cleanup: {}",
            self.mountpoint.display()
        );
        Ok(())
    }

    fn identity_json(&self) -> Value {
        let base = json!({
            "arm": self.arm.label(),
            "image": self.image,
            "mountpoint": self.mountpoint,
            "major_minor": self.mount_info.major_minor,
            "root": self.mount_info.root,
            "mount_options": self.mount_info.mount_options,
            "filesystem_type": self.mount_info.filesystem_type,
            "source": self.mount_info.source,
            "super_options": self.mount_info.super_options,
        });
        match &self.kind {
            MountedArmKind::Kernel => base,
            MountedArmKind::Fuse {
                child,
                stdout_log,
                stderr_log,
                self_reported_sha256,
                proc_exe_sha256,
                pgo_profile_sha256,
                ..
            } => {
                let mut object = base.as_object().cloned().unwrap_or_default();
                object.insert("stdout_log".to_owned(), json!(stdout_log));
                object.insert("stderr_log".to_owned(), json!(stderr_log));
                object.insert("pid".to_owned(), json!(child.id()));
                object.insert(
                    "self_reported_sha256".to_owned(),
                    json!(self_reported_sha256),
                );
                object.insert("proc_exe_sha256".to_owned(), json!(proc_exe_sha256));
                object.insert("pgo_profile_sha256".to_owned(), json!(pgo_profile_sha256));
                Value::Object(object)
            }
        }
    }
}

impl Drop for MountedArm {
    fn drop(&mut self) {
        let Ok(Some(_)) = find_mount(&self.mountpoint) else {
            return;
        };
        match &mut self.kind {
            MountedArmKind::Kernel => {
                let _ = Command::new("sudo")
                    .args(["-n", "umount"])
                    .arg(&self.mountpoint)
                    .status();
            }
            MountedArmKind::Fuse { child, .. } => {
                let _ = Command::new("fusermount3")
                    .args(["-u", "--"])
                    .arg(&self.mountpoint)
                    .status();
                if wait_for_child(child, Duration::from_secs(2)).is_err() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
    }
}

fn usage() {
    println!(
        "Usage: ffs-mounted-kernel-bench --ffs-cli PATH [OPTIONS]\n\
         \n\
         Options:\n\
           --filesystem ext4|btrfs|both   Filesystem arm(s), default both\n\
           --workload NAME                warm-stat | parallel-metadata-write |\n\
                                          parallel-read-8t | parallel-read-8t-cold-cache |\n\
                                          create-delete-storm |\n\
                                          readdir-stat-8t | fsync-journal-commit |\n\
                                          bulk-durable-write | xattr-get-list-report\n\
           --artifact-root PATH           Persistent artifacts under /data/tmp\n\
           --pairs N                      Paired rounds, multiple of 4 and >= 12 (default 32)\n\
           --operations N                 Workload operations per observation (default 2000)\n\
           --client-threads N             Actual parallel-metadata worker threads (default 8)\n\
           --fuse-cpus N                  CPUs pinned to the FrankenFS daemon (default 1;\n\
                                          every banked row was taken at 1, and the kernel\n\
                                          arm runs its filesystem on all client CPUs)\n\
           --placement-scope SCOPE        same-llc | host-wide (default same-llc)\n\
           --observation-repeats N        min-of-N repeats for read-only workloads (default 3)\n\
           --image-size-mib N             Per-image size, <= 2048 (default 256)\n\
           --maximum-null-ratio R         Max symmetric A/A CI spread (default 1.025)\n\
           --arm-settle-ms N              Untimed delay after every arm (default 100)\n\
           --pre-measurement-settle-ms N  Untimed delay after durable fixture setup (default 1000)\n\
           --host-quiet-samples N         Consecutive clear host-wide samples (default 5)\n\
           --host-quiet-timeout-ms N      Fail-closed quiet-window timeout (default 300000)\n\
           --harness-builder ID           Machine that built this driver ELF (required)\n\
           --candidate-builder ID         Machine that built the candidate ELF (required)\n\
           --out PATH                     JSON report path (default inside run dir)\n\
           -h, --help                     Show this help"
    );
}

fn parse_value<T: std::str::FromStr>(args: &[String], index: &mut usize, name: &str) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    *index += 1;
    let value = args
        .get(*index)
        .ok_or_else(|| anyhow!("missing value for {name}"))?;
    value
        .parse::<T>()
        .map_err(|error| anyhow!("invalid value for {name}: {value}: {error}"))
}

fn parse_workload(value: &str) -> Result<Workload> {
    match value {
        "warm-stat" => Ok(Workload::WarmStat),
        "parallel-metadata-write" | "parallel-metadata-write-8t" => {
            Ok(Workload::ParallelMetadataWrite)
        }
        "parallel-read-8t" => Ok(Workload::ParallelRead8),
        "parallel-read-8t-cold-cache" => Ok(Workload::ParallelRead8ColdCache),
        "create-delete-storm" => Ok(Workload::CreateDeleteStorm),
        "readdir-stat-8t" => Ok(Workload::ReaddirStat8),
        "fsync-journal-commit" => Ok(Workload::FsyncJournalCommit),
        "bulk-durable-write" => Ok(Workload::BulkDurableWrite),
        "xattr-get-list-report" => Ok(Workload::XattrGetListReport),
        _ => bail!(
            "unsupported --workload {value}; expected warm-stat|parallel-metadata-write|parallel-read-8t|parallel-read-8t-cold-cache|create-delete-storm|readdir-stat-8t|fsync-journal-commit|bulk-durable-write|xattr-get-list-report"
        ),
    }
}

fn parse_placement_scope(value: &str) -> Result<PlacementScope> {
    match value {
        "same-llc" => Ok(PlacementScope::SameLlc),
        "host-wide" => Ok(PlacementScope::HostWide),
        _ => bail!("unsupported --placement-scope {value}; expected same-llc|host-wide"),
    }
}

fn bulk_durable_total_bytes(operations: usize) -> Result<usize> {
    operations
        .checked_mul(BULK_DURABLE_CHUNK_BYTES)
        .ok_or_else(|| anyhow!("bulk durable write byte count overflow for {operations} chunks"))
}

fn validate_config(config: &Config) -> Result<()> {
    ensure!(
        !config.ffs_cli.as_os_str().is_empty(),
        "--ffs-cli is required"
    );
    ensure!(
        config.ffs_cli.is_file(),
        "ffs-cli does not exist: {}",
        config.ffs_cli.display()
    );
    // `rch exec` has no artifact-retrieval mechanism, so both ELFs are built on
    // a remote worker and copied to this host. Record which worker produced
    // each one: a binary of unknown origin is not evidence.
    for (value, flag) in [
        (&config.harness_builder, "--harness-builder"),
        (&config.candidate_builder, "--candidate-builder"),
    ] {
        ensure!(
            !value.trim().is_empty(),
            "{flag} is required: name the machine that built the ELF"
        );
    }
    ensure!(
        config.pairs >= 12 && config.pairs % BALANCED_ORDERS.len() == 0,
        "--pairs must be a multiple of 4 and at least 12"
    );
    ensure!(config.operations > 0, "--operations must be positive");
    ensure!(
        config.observation_repeats > 0,
        "--observation-repeats must be positive"
    );
    ensure!(
        !config.workload.is_mutating() || config.observation_repeats == 1,
        "mutating workloads require --observation-repeats 1 so every timed row has one durability boundary"
    );
    ensure!(
        (1..=MAX_CLIENT_THREADS).contains(&config.client_threads()),
        "--client-threads must be in 1..={MAX_CLIENT_THREADS}"
    );
    ensure!(
        (1..=MAX_CLIENT_THREADS).contains(&config.fuse_cpu_count),
        "--fuse-cpus must be in 1..={MAX_CLIENT_THREADS}"
    );
    ensure!(
        config.operations >= config.client_threads(),
        "{} requires at least one operation per requested client thread",
        config.workload.label()
    );
    ensure!(
        (1..=MAX_IMAGE_MIB).contains(&config.image_size_mib),
        "--image-size-mib must be in 1..={MAX_IMAGE_MIB}"
    );
    ensure!(
        config.maximum_null_ratio > 1.0,
        "--maximum-null-ratio must exceed 1.0"
    );
    ensure!(
        config.arm_settle_ms <= MAX_ARM_SETTLE_MS,
        "--arm-settle-ms must be at most {MAX_ARM_SETTLE_MS}"
    );
    ensure!(
        config.pre_measurement_settle_ms <= MAX_PRE_MEASUREMENT_SETTLE_MS,
        "--pre-measurement-settle-ms must be at most {MAX_PRE_MEASUREMENT_SETTLE_MS}"
    );
    ensure!(
        (1..=MAX_HOST_QUIET_SAMPLES).contains(&config.host_quiet_samples),
        "--host-quiet-samples must be in 1..={MAX_HOST_QUIET_SAMPLES}"
    );
    ensure!(
        config.host_quiet_timeout_ms <= MAX_HOST_QUIET_TIMEOUT_MS,
        "--host-quiet-timeout-ms must be at most {MAX_HOST_QUIET_TIMEOUT_MS}"
    );
    ensure!(
        config.host_quiet_timeout_ms
            >= CPU_SAMPLE_INTERVAL_MS.saturating_mul(config.host_quiet_samples as u64),
        "--host-quiet-timeout-ms must cover at least --host-quiet-samples one-second samples"
    );
    ensure!(
        config.workload != Workload::XattrGetListReport
            || config.filesystems == RequestedFilesystems::Ext4,
        "xattr-get-list-report currently requires --filesystem ext4 because its inline/external storage-shape proof is ext4-specific"
    );
    if config.workload == Workload::BulkDurableWrite {
        let payload_bytes = u64::try_from(bulk_durable_total_bytes(config.operations)?)
            .context("bulk durable byte count does not fit u64")?;
        let required_bytes = payload_bytes
            .checked_add(u64::try_from(PAYLOAD_BYTES).expect("payload size fits u64"))
            .and_then(|bytes| bytes.checked_add(BULK_DURABLE_IMAGE_HEADROOM_BYTES))
            .ok_or_else(|| anyhow!("bulk durable fixture size overflow"))?;
        let image_bytes = config
            .image_size_mib
            .checked_mul(1024 * 1024)
            .ok_or_else(|| anyhow!("image byte count overflow"))?;
        ensure!(
            required_bytes <= image_bytes,
            "bulk-durable-write requires at least {} image bytes for {} payload bytes plus fixed fixture/headroom, but --image-size-mib={} provides {image_bytes}",
            required_bytes,
            payload_bytes,
            config.image_size_mib
        );
    }
    Ok(())
}

fn parse_args() -> Result<Option<Config>> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut config = Config::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" => {
                usage();
                return Ok(None);
            }
            "--ffs-cli" => {
                config.ffs_cli = parse_value::<PathBuf>(&args, &mut index, "--ffs-cli")?;
            }
            "--artifact-root" => {
                config.artifact_root =
                    parse_value::<PathBuf>(&args, &mut index, "--artifact-root")?;
            }
            "--filesystem" => {
                let value = parse_value::<String>(&args, &mut index, "--filesystem")?;
                config.filesystems = match value.as_str() {
                    "ext4" => RequestedFilesystems::Ext4,
                    "btrfs" => RequestedFilesystems::Btrfs,
                    "both" => RequestedFilesystems::Both,
                    _ => bail!("unsupported --filesystem {value}; expected ext4|btrfs|both"),
                };
            }
            "--workload" => {
                let value = parse_value::<String>(&args, &mut index, "--workload")?;
                config.workload = parse_workload(&value)?;
            }
            "--pairs" => config.pairs = parse_value(&args, &mut index, "--pairs")?,
            "--operations" => {
                config.operations = parse_value(&args, &mut index, "--operations")?;
            }
            "--fuse-cpus" => {
                config.fuse_cpu_count = parse_value(&args, &mut index, "--fuse-cpus")?;
            }
            "--client-threads" => {
                config.client_threads = parse_value(&args, &mut index, "--client-threads")?;
            }
            "--placement-scope" => {
                let value = parse_value::<String>(&args, &mut index, "--placement-scope")?;
                config.placement_scope = parse_placement_scope(&value)?;
            }
            "--observation-repeats" => {
                config.observation_repeats =
                    parse_value(&args, &mut index, "--observation-repeats")?;
            }
            "--image-size-mib" => {
                config.image_size_mib = parse_value(&args, &mut index, "--image-size-mib")?;
            }
            "--maximum-null-ratio" => {
                config.maximum_null_ratio = parse_value(&args, &mut index, "--maximum-null-ratio")?;
            }
            "--arm-settle-ms" => {
                config.arm_settle_ms = parse_value(&args, &mut index, "--arm-settle-ms")?;
            }
            "--pre-measurement-settle-ms" => {
                config.pre_measurement_settle_ms =
                    parse_value(&args, &mut index, "--pre-measurement-settle-ms")?;
            }
            "--harness-builder" => {
                config.harness_builder = parse_value(&args, &mut index, "--harness-builder")?;
            }
            "--candidate-builder" => {
                config.candidate_builder = parse_value(&args, &mut index, "--candidate-builder")?;
            }
            "--host-quiet-samples" => {
                config.host_quiet_samples = parse_value(&args, &mut index, "--host-quiet-samples")?;
            }
            "--host-quiet-timeout-ms" => {
                config.host_quiet_timeout_ms =
                    parse_value(&args, &mut index, "--host-quiet-timeout-ms")?;
            }
            "--out" => config.output = Some(parse_value(&args, &mut index, "--out")?),
            other => bail!("unknown argument: {other}"),
        }
        index += 1;
    }

    validate_config(&config)?;
    Ok(Some(config))
}

fn sha256_reader(mut reader: impl Read) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 128 * 1024];
    loop {
        let read = reader.read(&mut buffer).context("read for SHA-256")?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn file_sha256(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("open {} for SHA-256", path.display()))?;
    sha256_reader(file)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn current_elf_sha256() -> Result<String> {
    let executable = env::current_exe().context("resolve current executable")?;
    file_sha256(&executable)
        .with_context(|| format!("self-hash executing ELF {}", executable.display()))
}

fn privileged_file_sha256(path: &Path) -> Result<String> {
    if let Ok(sha256) = file_sha256(path) {
        return Ok(sha256);
    }
    let output = Command::new("sudo")
        .args(["-n", "sha256sum", "--"])
        .arg(path)
        .output()
        .with_context(|| format!("hash privileged artifact {}", path.display()))?;
    ensure!(
        output.status.success(),
        "privileged SHA-256 failed for {}: status={} stderr={}",
        path.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let stdout =
        String::from_utf8(output.stdout).context("privileged sha256sum output is not UTF-8")?;
    let sha256 = stdout
        .split_ascii_whitespace()
        .next()
        .ok_or_else(|| anyhow!("privileged sha256sum returned no digest"))?
        .to_owned();
    ensure!(
        is_sha256(&sha256),
        "privileged sha256sum returned invalid digest for {}: {sha256}",
        path.display()
    );
    Ok(sha256)
}

fn kernel_engine_identity(kind: FilesystemKind) -> Result<KernelEngineIdentity> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .context("read running kernel release")?
        .trim()
        .to_owned();
    let module_artifact = Command::new("modinfo")
        .args(["-n", kind.kernel_module()])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|path| PathBuf::from(path.trim()))
        .filter(|path| path.is_file());
    let artifact = module_artifact
        .or_else(|| {
            [
                PathBuf::from(format!("/boot/vmlinuz-{release}")),
                PathBuf::from(format!("/usr/lib/modules/{release}/vmlinuz")),
            ]
            .into_iter()
            .find(|path| path.is_file())
        })
        .ok_or_else(|| anyhow!("running kernel artifact for {release} is unavailable"))?;
    let runtime_notes = PathBuf::from(format!(
        "/sys/module/{}/notes/.note.gnu.build-id",
        kind.kernel_module()
    ));
    let runtime_notes = if runtime_notes.is_file() {
        runtime_notes
    } else {
        PathBuf::from("/sys/kernel/notes")
    };
    let artifact_sha256 = privileged_file_sha256(&artifact)?;
    let runtime_notes_sha256 = file_sha256(&runtime_notes)
        .with_context(|| format!("hash runtime kernel notes {}", runtime_notes.display()))?;
    ensure!(
        is_sha256(&artifact_sha256) && is_sha256(&runtime_notes_sha256),
        "kernel engine provenance did not produce two SHA-256 identities"
    );
    Ok(KernelEngineIdentity {
        release,
        artifact,
        artifact_sha256,
        runtime_notes_sha256,
    })
}

fn unique_prefixed_line<'a>(content: &'a str, prefix: &str, label: &str) -> Result<&'a str> {
    let mut matches = content
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .map(str::trim);
    let value = matches
        .next()
        .ok_or_else(|| anyhow!("{label} was not reported"))?;
    ensure!(
        matches.next().is_none(),
        "{label} was reported more than once"
    );
    Ok(value)
}

fn inspect_ffs_binary(path: &Path) -> Result<FfsBinaryIdentity> {
    let output = Command::new(path)
        .arg("bench-evidence")
        .env("RUST_LOG", "off")
        .output()
        .with_context(|| format!("run {} bench-evidence", path.display()))?;
    ensure!(
        output.status.success(),
        "{} bench-evidence failed: {}",
        path.display(),
        output.status
    );
    let stdout = String::from_utf8(output.stdout).context("bench-evidence stdout is not UTF-8")?;
    let binary_sha256 = unique_prefixed_line(
        &stdout,
        "bench_evidence,binary_sha256=",
        "candidate ELF SHA-256",
    )?
    .to_owned();
    ensure!(
        is_sha256(&binary_sha256),
        "candidate reported invalid ELF SHA-256: {binary_sha256}"
    );
    ensure!(
        file_sha256(path)? == binary_sha256,
        "candidate bench-evidence SHA-256 differs from its on-disk path"
    );
    let codegen = stdout
        .lines()
        .find(|line| line.starts_with("codegen_isa,"))
        .ok_or_else(|| anyhow!("candidate codegen ISA was not reported"))?;
    for required in [
        "target_arch=x86_64",
        "compile_sse4_2=true",
        "compile_avx2=true",
        "compile_fma=true",
    ] {
        ensure!(
            codegen.split(',').any(|field| field == required),
            "candidate is not the x86-64-v3 production ISA: missing {required}"
        );
    }
    let pgo_profile_sha256 = unique_prefixed_line(
        &stdout,
        "build_profile,pgo_profile_sha256=",
        "candidate PGO profile SHA-256",
    )?
    .to_owned();
    ensure!(
        is_sha256(&pgo_profile_sha256),
        "candidate is not a PGO production build: {pgo_profile_sha256}"
    );
    Ok(FfsBinaryIdentity {
        binary_sha256,
        pgo_profile_sha256,
    })
}

fn write_deterministic_payload(path: &Path) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create fixture payload {}", path.display()))?;
    let mut block = [0_u8; 4096];
    for (index, byte) in block.iter_mut().enumerate() {
        *byte = u8::try_from((index * 131 + 17) % 251).expect("fixture byte fits u8");
    }
    for _ in 0..(PAYLOAD_BYTES / block.len()) {
        file.write_all(&block)
            .with_context(|| format!("write fixture payload {}", path.display()))?;
    }
    file.sync_all()
        .with_context(|| format!("sync fixture payload {}", path.display()))
}

fn write_fixture_file(path: &Path, bytes: usize, seed: usize) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create fixture file {}", path.display()))?;
    let mut block = [0_u8; 4096];
    for (index, byte) in block.iter_mut().enumerate() {
        *byte = u8::try_from((index * 131 + seed * 29 + 17) % 251).expect("fixture byte fits u8");
    }
    let full_blocks = bytes / block.len();
    let tail = bytes % block.len();
    for _ in 0..full_blocks {
        file.write_all(&block)
            .with_context(|| format!("write fixture file {}", path.display()))?;
    }
    file.write_all(&block[..tail])
        .with_context(|| format!("write fixture tail {}", path.display()))
}

fn create_fixture_tree(run_dir: &Path, config: &Config) -> Result<PathBuf> {
    let root = run_dir.join("fixture-root");
    fs::create_dir(&root).with_context(|| format!("create {}", root.display()))?;
    write_deterministic_payload(&root.join("payload.bin"))?;
    let nested = root.join("nested");
    fs::create_dir(&nested).with_context(|| format!("create {}", nested.display()))?;
    fs::write(
        nested.join("sentinel.txt"),
        b"frankenfs-mounted-kernel-v1\n",
    )
    .context("write fixture sentinel")?;
    match config.workload {
        Workload::WarmStat => {}
        Workload::ParallelMetadataWrite => {
            let parent = root.join("parallel-metadata");
            fs::create_dir(&parent).with_context(|| format!("create {}", parent.display()))?;
            for worker in 0..config.client_threads() {
                let path = parent.join(format!("worker-{worker}"));
                fs::create_dir(&path).with_context(|| format!("create {}", path.display()))?;
            }
        }
        Workload::ParallelRead8 | Workload::ParallelRead8ColdCache => {
            let parent = root.join("parallel-read");
            fs::create_dir(&parent).with_context(|| format!("create {}", parent.display()))?;
            for index in 0..config.operations {
                write_fixture_file(
                    &parent.join(format!("read-{index:06}.bin")),
                    PARALLEL_READ_FILE_BYTES,
                    index,
                )?;
            }
        }
        Workload::CreateDeleteStorm => {
            let path = root.join("create-delete-storm");
            fs::create_dir(&path).with_context(|| format!("create {}", path.display()))?;
        }
        Workload::ReaddirStat8 => {
            let parent = root.join("large-directory");
            fs::create_dir(&parent).with_context(|| format!("create {}", parent.display()))?;
            for index in 0..config.operations {
                File::create(parent.join(format!("entry-{index:08}")))
                    .with_context(|| format!("create large-directory fixture entry {index}"))?;
            }
        }
        Workload::FsyncJournalCommit => {
            write_fixture_file(&root.join("fsync.bin"), 4096, 0xF5)?;
        }
        Workload::BulkDurableWrite => {
            write_fixture_file(
                &root.join(BULK_DURABLE_FILE),
                bulk_durable_total_bytes(config.operations)?,
                0xB7,
            )?;
        }
        Workload::XattrGetListReport => {
            for name in [XATTR_INLINE_FILE, XATTR_EXTERNAL_FILE, XATTR_MANY_FILE] {
                File::create(root.join(name))
                    .with_context(|| format!("create xattr fixture file {name}"))?;
            }
        }
    }
    Ok(root)
}

fn create_sized_file(path: &Path, size_mib: u64) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create image {}", path.display()))?;
    file.set_len(size_mib * 1024 * 1024)
        .with_context(|| format!("size image {}", path.display()))
}

fn sync_image(path: &Path) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("open image for durability sync {}", path.display()))?
        .sync_all()
        .with_context(|| format!("durability sync image {}", path.display()))
}

fn run_checked(command: &mut Command, label: &str) -> Result<()> {
    let status = command.status().with_context(|| format!("spawn {label}"))?;
    ensure!(status.success(), "{label} failed: {status}");
    Ok(())
}

fn xattr_many_name(index: usize) -> String {
    format!("user.item{index:02}")
}

fn xattr_external_value() -> Vec<u8> {
    (0..XATTR_EXTERNAL_VALUE_BYTES)
        .map(|index| b'A' + u8::try_from(index % 26).expect("alphabet index fits u8"))
        .collect()
}

fn debugfs_set_xattr(image: &Path, file: &str, name: &str, value: &[u8]) -> Result<()> {
    let value = std::str::from_utf8(value).context("debugfs fixture xattr must be ASCII")?;
    run_checked(
        Command::new("debugfs")
            .args(["-w", "-R", &format!("ea_set /{file} {name} {value}")])
            .arg(image)
            .stdout(Stdio::null()),
        &format!("debugfs set {name} on {file}"),
    )
}

fn debugfs_file_acl_block(image: &Path, file: &str) -> Result<u64> {
    let output = Command::new("debugfs")
        .args(["-R", &format!("stat /{file}")])
        .arg(image)
        .output()
        .with_context(|| format!("debugfs stat xattr fixture {file}"))?;
    ensure!(
        output.status.success(),
        "debugfs stat xattr fixture {file} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let stdout = String::from_utf8(output.stdout).context("debugfs stat output is not UTF-8")?;
    stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("File ACL:"))
        .ok_or_else(|| anyhow!("debugfs stat for {file} omitted File ACL"))
        .and_then(|value| {
            value
                .trim()
                .parse::<u64>()
                .with_context(|| format!("parse debugfs File ACL for {file}"))
        })
}

fn seed_ext4_xattr_fixture(image: &Path) -> Result<()> {
    debugfs_set_xattr(
        image,
        XATTR_INLINE_FILE,
        XATTR_INLINE_NAME,
        XATTR_INLINE_VALUE,
    )?;
    debugfs_set_xattr(
        image,
        XATTR_EXTERNAL_FILE,
        XATTR_EXTERNAL_NAME,
        &xattr_external_value(),
    )?;
    for index in 0..XATTR_MANY_NAMES {
        let name = xattr_many_name(index);
        let value = format!("{index:02}");
        debugfs_set_xattr(image, XATTR_MANY_FILE, &name, value.as_bytes())?;
    }
    ensure!(
        debugfs_file_acl_block(image, XATTR_INLINE_FILE)? == 0,
        "single small xattr unexpectedly escaped the ext4 inode body"
    );
    ensure!(
        debugfs_file_acl_block(image, XATTR_EXTERNAL_FILE)? != 0,
        "large xattr did not allocate an ext4 external xattr block"
    );
    ensure!(
        debugfs_file_acl_block(image, XATTR_MANY_FILE)? != 0,
        "24-name list fixture did not allocate an ext4 external xattr block"
    );
    Ok(())
}

fn create_base_image(
    kind: FilesystemKind,
    fixture_root: &Path,
    run_dir: &Path,
    config: &Config,
) -> Result<PathBuf> {
    let image = run_dir.join(format!("{}.base.img", kind.label()));
    create_sized_file(&image, config.image_size_mib)?;
    match kind {
        FilesystemKind::Ext4 => {
            let mut command = Command::new("mke2fs");
            command.args(["-t", "ext4", "-F", "-q", "-b", "4096"]);
            if config.workload == Workload::ParallelMetadataWrite {
                // A 2 GiB sweep image must retain enough inodes for
                // (warmup + measured rounds) * operations unique creates.
                command.args(["-i", "4096"]);
            }
            run_checked(
                command.arg("-d").arg(fixture_root).arg(&image),
                "mke2fs ext4 fixture",
            )?;
            if config.workload == Workload::XattrGetListReport {
                seed_ext4_xattr_fixture(&image)?;
            }
        }
        FilesystemKind::Btrfs => run_checked(
            Command::new("mkfs.btrfs")
                .args(["-f", "-q", "-r"])
                .arg(fixture_root)
                .arg(&image),
            "mkfs.btrfs fixture",
        )?,
    }
    validate_image(kind, &image)?;
    sync_image(&image)?;
    Ok(image)
}

fn validate_image(kind: FilesystemKind, image: &Path) -> Result<()> {
    match kind {
        FilesystemKind::Ext4 => {
            let status = Command::new("e2fsck")
                .args(["-fn"])
                .arg(image)
                .stdout(Stdio::null())
                .status()
                .with_context(|| format!("run e2fsck on {}", image.display()))?;
            ensure!(
                status.code() == Some(0),
                "e2fsck did not report clean image {}: {status}",
                image.display()
            );
        }
        FilesystemKind::Btrfs => run_checked(
            Command::new("btrfs")
                .args(["check", "--readonly"])
                .arg(image)
                .stdout(Stdio::null()),
            "btrfs check --readonly",
        )?,
    }
    Ok(())
}

fn clone_images(
    kind: FilesystemKind,
    base: &Path,
    run_dir: &Path,
) -> Result<BTreeMap<Arm, PathBuf>> {
    let expected_sha = file_sha256(base)?;
    let mut images = BTreeMap::new();
    for arm in [Arm::KernelA, Arm::KernelB, Arm::FuseA, Arm::FuseB] {
        let path = run_dir.join(format!("{}.{}.img", kind.label(), arm.label()));
        fs::copy(base, &path)
            .with_context(|| format!("clone {} to {}", base.display(), path.display()))?;
        sync_image(&path)?;
        let actual_sha = file_sha256(&path)?;
        ensure!(
            actual_sha == expected_sha,
            "image clone digest mismatch for {}",
            path.display()
        );
        images.insert(arm, path);
    }
    Ok(images)
}

fn mountinfo_unescape(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && bytes[index + 1..=index + 3].iter().all(u8::is_ascii_digit)
        {
            let octal = (bytes[index + 1] - b'0') * 64
                + (bytes[index + 2] - b'0') * 8
                + (bytes[index + 3] - b'0');
            output.push(octal);
            index += 4;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn option_set(value: &str) -> BTreeSet<String> {
    value
        .split(',')
        .filter(|option| !option.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse_mountinfo_line(line: &str) -> Result<MountInfo> {
    let (left, right) = line
        .split_once(" - ")
        .ok_or_else(|| anyhow!("mountinfo row has no separator"))?;
    let left_fields: Vec<&str> = left.split_ascii_whitespace().collect();
    let right_fields: Vec<&str> = right.split_ascii_whitespace().collect();
    ensure!(
        left_fields.len() >= 6 && right_fields.len() >= 3,
        "mountinfo row is too short"
    );
    Ok(MountInfo {
        major_minor: left_fields[2].to_owned(),
        root: mountinfo_unescape(left_fields[3]),
        mountpoint: PathBuf::from(mountinfo_unescape(left_fields[4])),
        mount_options: option_set(left_fields[5]),
        filesystem_type: right_fields[0].to_owned(),
        source: mountinfo_unescape(right_fields[1]),
        super_options: option_set(right_fields[2]),
    })
}

fn is_fuse_mountinfo_type(filesystem_type: &str) -> bool {
    matches!(filesystem_type, "fuse" | "fuse.ffs")
}

fn find_mount(mountpoint: &Path) -> Result<Option<MountInfo>> {
    let target = fs::canonicalize(mountpoint)
        .with_context(|| format!("canonicalize mountpoint {}", mountpoint.display()))?;
    let file = File::open("/proc/self/mountinfo").context("open /proc/self/mountinfo")?;
    for line in BufReader::new(file).lines() {
        let line = line.context("read /proc/self/mountinfo")?;
        let parsed = parse_mountinfo_line(&line)?;
        if parsed.mountpoint == target {
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}

fn wait_for_mount(
    mountpoint: &Path,
    mut child: Option<&mut Child>,
    interrupted: &AtomicBool,
) -> Result<MountInfo> {
    let deadline = Instant::now() + MOUNT_READY_TIMEOUT;
    loop {
        ensure!(
            !interrupted.load(Ordering::Relaxed),
            "interrupted while waiting for mount"
        );
        if let Some(info) = find_mount(mountpoint)? {
            fs::metadata(mountpoint)
                .with_context(|| format!("stat ready mount {}", mountpoint.display()))?;
            return Ok(info);
        }
        if let Some(process) = child.as_deref_mut()
            && let Some(status) = process.try_wait().context("poll FUSE mount process")?
        {
            bail!("FUSE mount process exited before readiness: {status}");
        }
        ensure!(
            Instant::now() < deadline,
            "mount readiness timed out at {}",
            mountpoint.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_common_mount_options(info: &MountInfo, label: &str, read_write: bool) -> Result<()> {
    let access = if read_write { "rw" } else { "ro" };
    for required in [access, "noatime", "nodev", "nosuid"] {
        ensure!(
            info.mount_options.contains(required) || info.super_options.contains(required),
            "{label} mount missing required option {required}: mount={:?} super={:?}",
            info.mount_options,
            info.super_options
        );
    }
    let forbidden = if read_write { "ro" } else { "rw" };
    ensure!(
        !info.mount_options.contains(forbidden) && !info.super_options.contains(forbidden),
        "{label} unexpectedly reports {forbidden} mount options"
    );
    Ok(())
}

fn loop_backing_path(info: &MountInfo) -> Result<PathBuf> {
    let loop_name = Path::new(&info.source)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            anyhow!(
                "kernel source has no UTF-8 loop device name: {}",
                info.source
            )
        })?;
    let loop_index = loop_name
        .strip_prefix("loop")
        .ok_or_else(|| anyhow!("kernel source is not a loop device: {}", info.source))?;
    ensure!(
        !loop_index.is_empty() && loop_index.bytes().all(|byte| byte.is_ascii_digit()),
        "kernel source has invalid loop device name: {}",
        info.source
    );
    let path = PathBuf::from("/sys/class/block")
        .join(loop_name)
        .join("loop/backing_file");
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read loop backing file {}", path.display()))?;
    let trimmed = raw.trim();
    let absolute = if trimmed.starts_with('/') {
        PathBuf::from(trimmed)
    } else {
        PathBuf::from("/").join(trimmed)
    };
    fs::canonicalize(&absolute)
        .with_context(|| format!("canonicalize loop backing file {}", absolute.display()))
}

fn mount_kernel(
    kind: FilesystemKind,
    arm: Arm,
    image: &Path,
    mountpoint: &Path,
    read_write: bool,
    interrupted: &AtomicBool,
) -> Result<MountedArm> {
    fs::create_dir(mountpoint)
        .with_context(|| format!("create kernel mountpoint {}", mountpoint.display()))?;
    let canonical_mountpoint = fs::canonicalize(mountpoint)
        .with_context(|| format!("canonicalize mountpoint {}", mountpoint.display()))?;
    let expected_image = fs::canonicalize(image)
        .with_context(|| format!("canonicalize image {}", image.display()))?;
    let options = match (kind, read_write) {
        (FilesystemKind::Ext4, false) => "loop,ro,noload,noatime,nodev,nosuid",
        (FilesystemKind::Ext4, true) => "loop,rw,noatime,nodev,nosuid,data=ordered",
        (FilesystemKind::Btrfs, false) => "loop,ro,noatime,nodev,nosuid",
        (FilesystemKind::Btrfs, true) => "loop,rw,noatime,nodev,nosuid",
    };
    run_checked(
        Command::new("sudo")
            .args(["-n", "mount", "-t", kind.label(), "-o", options])
            .arg(image)
            .arg(mountpoint),
        &format!("mount kernel {}", kind.label()),
    )?;
    let info = wait_for_mount(mountpoint, None, interrupted)?;
    let mounted = MountedArm {
        arm,
        mountpoint: canonical_mountpoint,
        image: expected_image,
        mount_info: info,
        kind: MountedArmKind::Kernel,
    };
    assert_common_mount_options(&mounted.mount_info, arm.label(), read_write)?;
    ensure!(
        mounted.mount_info.filesystem_type == kind.label(),
        "{} incumbent identity mismatch: expected {}, observed {}",
        arm.label(),
        kind.label(),
        mounted.mount_info.filesystem_type
    );
    ensure!(
        mounted.mount_info.source.starts_with("/dev/loop"),
        "{} incumbent source is not a loop device: {}",
        arm.label(),
        mounted.mount_info.source
    );
    ensure!(
        loop_backing_path(&mounted.mount_info)? == mounted.image,
        "{} loop device does not reference its declared image",
        arm.label()
    );
    Ok(mounted)
}

fn parse_mount_self_report(log_path: &Path) -> Result<FfsBinaryIdentity> {
    let content = fs::read_to_string(log_path)
        .with_context(|| format!("read FUSE mount log {}", log_path.display()))?;
    let binary_sha256 = unique_prefixed_line(
        &content,
        "mount_bench_evidence,binary_sha256=",
        "FUSE mount executing ELF SHA-256",
    )?
    .to_owned();
    ensure!(
        is_sha256(&binary_sha256),
        "invalid FUSE mount ELF SHA-256: {binary_sha256}"
    );
    let pgo_profile_sha256 = unique_prefixed_line(
        &content,
        "mount_build_profile,pgo_profile_sha256=",
        "FUSE mount PGO profile SHA-256",
    )?
    .to_owned();
    ensure!(
        is_sha256(&pgo_profile_sha256),
        "FUSE mount is not running a PGO production build: {pgo_profile_sha256}"
    );
    Ok(FfsBinaryIdentity {
        binary_sha256,
        pgo_profile_sha256,
    })
}

// Keep the lifecycle linear: every identity check must remain visibly between
// daemon spawn and the cleanup guard that owns it.
#[allow(clippy::too_many_lines)]
fn mount_fuse(
    config: &Config,
    expected_identity: &FfsBinaryIdentity,
    arm: Arm,
    image: &Path,
    mountpoint: &Path,
    fuse_cpus: &[usize],
    interrupted: &AtomicBool,
) -> Result<MountedArm> {
    fs::create_dir(mountpoint)
        .with_context(|| format!("create FUSE mountpoint {}", mountpoint.display()))?;
    let canonical_mountpoint = fs::canonicalize(mountpoint)
        .with_context(|| format!("canonicalize mountpoint {}", mountpoint.display()))?;
    let canonical_image = fs::canonicalize(image)
        .with_context(|| format!("canonicalize image {}", image.display()))?;
    let stdout_log = mountpoint.with_extension("stdout.log");
    let stderr_log = mountpoint.with_extension("stderr.log");
    let stdout = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stdout_log)
        .with_context(|| format!("create {}", stdout_log.display()))?;
    let stderr = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stderr_log)
        .with_context(|| format!("create {}", stderr_log.display()))?;
    let cpu_list = fuse_cpus
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut command = Command::new("taskset");
    command
        .args(["-c", &cpu_list])
        .arg(&config.ffs_cli)
        .arg("mount");
    if config.workload.is_mutating() {
        command.arg("--rw");
    }
    let mut child = command
        .arg("--no-background-scrub")
        .arg(image)
        .arg(mountpoint)
        .env("FFS_AUTO_UNMOUNT", "0")
        .env("FFS_MOUNT_BENCH_EVIDENCE", "1")
        .env("RUST_LOG", "off")
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| format!("spawn FrankenFS FUSE arm {}", arm.label()))?;
    let info = wait_for_mount(mountpoint, Some(&mut child), interrupted).with_context(|| {
        let log = fs::read_to_string(&stderr_log).unwrap_or_default();
        format!("wait for {} FUSE mount; stderr={log}", arm.label())
    })?;
    let mut mounted = MountedArm {
        arm,
        mountpoint: canonical_mountpoint,
        image: canonical_image,
        mount_info: info,
        kind: MountedArmKind::Fuse {
            child,
            stdout_log,
            stderr_log,
            self_reported_sha256: String::new(),
            proc_exe_sha256: String::new(),
            pgo_profile_sha256: String::new(),
        },
    };
    assert_common_mount_options(
        &mounted.mount_info,
        arm.label(),
        config.workload.is_mutating(),
    )?;
    // Linux mountinfo may expose the requested FUSE subtype (`fuse.ffs`) or
    // collapse it to the generic `fuse` type. Exact source, child PID/ELF,
    // in-process SHA/PGO, image, and option checks below remain mandatory.
    ensure!(
        is_fuse_mountinfo_type(&mounted.mount_info.filesystem_type),
        "{} FUSE identity mismatch: expected fuse or fuse.ffs, observed {}",
        arm.label(),
        mounted.mount_info.filesystem_type
    );
    ensure!(
        mounted.mount_info.source == "frankenfs",
        "{} FUSE source mismatch: expected frankenfs, observed {}",
        arm.label(),
        mounted.mount_info.source
    );
    ensure!(
        !mounted.mount_info.mount_options.contains("writeback_cache")
            && !mounted.mount_info.super_options.contains("writeback_cache"),
        "{} unexpectedly enabled FUSE writeback_cache",
        arm.label()
    );
    let (child_id, stderr_log) = match &mounted.kind {
        MountedArmKind::Fuse {
            child, stderr_log, ..
        } => (child.id(), stderr_log.clone()),
        MountedArmKind::Kernel => unreachable!("constructed FUSE mount"),
    };
    let self_report = parse_mount_self_report(&stderr_log)?;
    let proc_exe_sha256 = file_sha256(&PathBuf::from(format!("/proc/{child_id}/exe")))
        .with_context(|| format!("hash mapped FUSE executable for pid {child_id}"))?;
    ensure!(
        self_report.binary_sha256 == proc_exe_sha256,
        "{} self-reported ELF differs from /proc/{child_id}/exe",
        arm.label(),
    );
    ensure!(
        &self_report == expected_identity,
        "{} runtime daemon identity differs from the v3+PGO preflight",
        arm.label()
    );
    let MountedArmKind::Fuse {
        self_reported_sha256: reported,
        proc_exe_sha256: mapped,
        pgo_profile_sha256: pgo,
        ..
    } = &mut mounted.kind
    else {
        unreachable!("constructed FUSE mount");
    };
    *reported = self_report.binary_sha256;
    *mapped = proc_exe_sha256;
    *pgo = self_report.pgo_profile_sha256;
    Ok(mounted)
}

fn parity_witness(path: &Path) -> Result<ParityWitness> {
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    Ok(ParityWitness {
        file_sha256: file_sha256(path)?,
        len: metadata.len(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        nlink: metadata.nlink(),
    })
}

fn tree_witness(root: &Path) -> Result<TreeWitness> {
    let mut hasher = Sha256::new();
    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0_u64;
    let mut regular_files = 0_u64;
    let mut directories = 0_u64;
    let mut bytes = 0_u64;
    let mut buffer = vec![0_u8; 128 * 1024];
    while let Some(path) = pending.pop() {
        if path != root && path.file_name().is_some_and(|name| name == "lost+found") {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("tree parity metadata {}", path.display()))?;
        let relative = path
            .strip_prefix(root)
            .with_context(|| format!("tree parity path escaped root: {}", path.display()))?;
        hasher.update(relative.as_os_str().as_bytes());
        hasher.update([0]);
        hasher.update(metadata.mode().to_le_bytes());
        hasher.update(metadata.uid().to_le_bytes());
        hasher.update(metadata.gid().to_le_bytes());
        hasher.update(metadata.nlink().to_le_bytes());
        entries = entries.saturating_add(1);
        if metadata.is_dir() {
            // Directory st_size is an implementation-specific allocation detail:
            // ext4 legitimately retains grown directory blocks after unlink.
            directories = directories.saturating_add(1);
            let mut children = fs::read_dir(&path)
                .with_context(|| format!("tree parity readdir {}", path.display()))?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::io::Result<Vec<_>>>()
                .with_context(|| format!("tree parity collect {}", path.display()))?;
            children.sort_by(|left, right| {
                left.as_os_str()
                    .as_bytes()
                    .cmp(right.as_os_str().as_bytes())
            });
            pending.extend(children.into_iter().rev());
        } else if metadata.is_file() {
            hasher.update(metadata.len().to_le_bytes());
            regular_files = regular_files.saturating_add(1);
            bytes = bytes.saturating_add(metadata.len());
            let mut file = File::open(&path)
                .with_context(|| format!("tree parity open {}", path.display()))?;
            loop {
                let read = file
                    .read(&mut buffer)
                    .with_context(|| format!("tree parity read {}", path.display()))?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
        } else {
            bail!(
                "tree parity fixture contains unsupported non-file entry {}",
                path.display()
            );
        }
        hasher.update([0xFF]);
    }
    Ok(TreeWitness {
        sha256: hex::encode(hasher.finalize()),
        entries,
        regular_files,
        directories,
        bytes,
    })
}

fn bulk_durable_sequence_byte(sequence: usize) -> u8 {
    u8::try_from(((sequence % 251) * 37 + 113) % 251).expect("bulk durable sequence byte fits u8")
}

fn bulk_durable_write_witness(
    root: &Path,
    expected_bytes: usize,
    expected_uniform_byte: Option<u8>,
) -> Result<BulkDurableWriteWitness> {
    let path = root.join(BULK_DURABLE_FILE);
    let mut file = File::open(&path)
        .with_context(|| format!("open bulk durable witness {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat bulk durable witness {}", path.display()))?;
    let expected_bytes_u64 =
        u64::try_from(expected_bytes).context("bulk durable witness length does not fit u64")?;
    ensure!(
        metadata.len() == expected_bytes_u64,
        "bulk durable witness length is {}, expected {expected_bytes}",
        metadata.len()
    );
    let mut hasher = Sha256::new();
    let mut total_read = 0_usize;
    let mut buffer = vec![0_u8; 128 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read bulk durable witness {}", path.display()))?;
        if read == 0 {
            break;
        }
        if let Some(expected) = expected_uniform_byte {
            ensure!(
                buffer[..read].iter().all(|byte| *byte == expected),
                "bulk durable witness contains a byte other than {expected}"
            );
        }
        hasher.update(&buffer[..read]);
        total_read = total_read.saturating_add(read);
    }
    ensure!(
        total_read == expected_bytes,
        "bulk durable witness read {total_read} bytes, expected {expected_bytes}"
    );
    Ok(BulkDurableWriteWitness {
        sha256: hex::encode(hasher.finalize()),
        bytes: metadata.len(),
        uniform_byte: expected_uniform_byte,
    })
}

fn list_xattr_names(path: &Path) -> Result<Vec<Vec<u8>>> {
    let mut names = xattr::list(path)
        .with_context(|| format!("list xattrs for {}", path.display()))?
        .map(OsStringExt::into_vec)
        .collect::<Vec<_>>();
    names.sort();
    Ok(names)
}

fn required_xattr(path: &Path, name: &str) -> Result<Vec<u8>> {
    xattr::get(path, name)
        .with_context(|| format!("get xattr {name} from {}", path.display()))?
        .ok_or_else(|| anyhow!("required xattr {name} absent from {}", path.display()))
}

fn hash_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn xattr_witness(root: &Path) -> Result<XattrWitness> {
    let inline_path = root.join(XATTR_INLINE_FILE);
    let external_path = root.join(XATTR_EXTERNAL_FILE);
    let many_path = root.join(XATTR_MANY_FILE);
    let inline_value = required_xattr(&inline_path, XATTR_INLINE_NAME)?;
    let external_value = required_xattr(&external_path, XATTR_EXTERNAL_NAME)?;
    let absent_lookup_none = xattr::get(&inline_path, XATTR_ABSENT_NAME)
        .with_context(|| format!("get absent xattr from {}", inline_path.display()))?
        .is_none();
    let single_names = list_xattr_names(&inline_path)?;
    let many_names = list_xattr_names(&many_path)?;
    let expected_many_names = (0..XATTR_MANY_NAMES)
        .map(|index| xattr_many_name(index).into_bytes())
        .collect::<Vec<_>>();
    ensure!(
        inline_value == XATTR_INLINE_VALUE,
        "inline xattr value differs from fixture contract"
    );
    ensure!(
        external_value == xattr_external_value(),
        "external-block xattr value differs from fixture contract"
    );
    ensure!(
        absent_lookup_none,
        "absent xattr lookup unexpectedly returned a value"
    );
    ensure!(
        single_names == [XATTR_INLINE_NAME.as_bytes().to_vec()],
        "single-name xattr list differs from fixture contract: {single_names:?}"
    );
    ensure!(
        many_names == expected_many_names,
        "{XATTR_MANY_NAMES}-name xattr list differs from fixture contract"
    );

    let mut hasher = Sha256::new();
    hash_length_prefixed(&mut hasher, &inline_value);
    hash_length_prefixed(&mut hasher, &external_value);
    hasher.update([u8::from(absent_lookup_none)]);
    for name in &single_names {
        hash_length_prefixed(&mut hasher, name);
    }
    for name in &many_names {
        hash_length_prefixed(&mut hasher, name);
    }
    Ok(XattrWitness {
        sha256: hex::encode(hasher.finalize()),
        inline_value_bytes: inline_value.len(),
        external_value_bytes: external_value.len(),
        single_list_names: single_names.len(),
        many_list_names: many_names.len(),
        absent_lookup_none,
    })
}

fn assert_independent_arms(mounts: &[MountedArm]) -> Result<()> {
    ensure!(mounts.len() == 4, "independence proof requires four mounts");
    let images: BTreeSet<PathBuf> = mounts.iter().map(|mount| mount.image.clone()).collect();
    let mountpoints: BTreeSet<PathBuf> = mounts
        .iter()
        .map(|mount| mount.mountpoint.clone())
        .collect();
    ensure!(
        images.len() == 4 && mountpoints.len() == 4,
        "mounted arms do not own four distinct images and mountpoints"
    );

    let kernel_devices: BTreeSet<String> = mounts
        .iter()
        .filter(|mount| matches!(&mount.kind, MountedArmKind::Kernel))
        .map(|mount| mount.mount_info.major_minor.clone())
        .collect();
    let kernel_sources: BTreeSet<String> = mounts
        .iter()
        .filter(|mount| matches!(&mount.kind, MountedArmKind::Kernel))
        .map(|mount| mount.mount_info.source.clone())
        .collect();
    ensure!(
        kernel_devices.len() == 2 && kernel_sources.len() == 2,
        "kernel A/A arms share a mounted superblock or loop source"
    );

    let fuse_devices: BTreeSet<String> = mounts
        .iter()
        .filter(|mount| matches!(&mount.kind, MountedArmKind::Fuse { .. }))
        .map(|mount| mount.mount_info.major_minor.clone())
        .collect();
    let fuse_pids: BTreeSet<u32> = mounts
        .iter()
        .filter_map(|mount| match &mount.kind {
            MountedArmKind::Fuse { child, .. } => Some(child.id()),
            MountedArmKind::Kernel => None,
        })
        .collect();
    ensure!(
        fuse_devices.len() == 2 && fuse_pids.len() == 2,
        "FUSE A/A arms share a mount device or daemon process"
    );
    Ok(())
}

fn stat_batch(path: &Path, operations: usize) -> Result<(u64, u64)> {
    let mut digest = 0x9E37_79B9_7F4A_7C15_u64;
    let started = Instant::now();
    for index in 0..operations {
        let metadata = fs::metadata(black_box(path))
            .with_context(|| format!("timed stat {}", path.display()))?;
        let row = metadata.len().wrapping_mul(0xD6E8_FEB8_6659_FD93)
            ^ u64::from(metadata.mode()).rotate_left(17)
            ^ metadata.nlink().rotate_left(31)
            ^ u64::try_from(index).unwrap_or(u64::MAX);
        digest = digest.rotate_left(9) ^ row;
    }
    let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    black_box(digest);
    Ok((elapsed, digest))
}

fn fold_xattr_bytes(mut digest: u64, bytes: &[u8]) -> u64 {
    digest ^= u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    digest = digest.wrapping_mul(0x0000_0100_0000_01B3);
    for byte in bytes {
        digest = (digest ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01B3);
    }
    digest
}

fn fold_xattr_names(mut digest: u64, names: &[Vec<u8>]) -> u64 {
    digest ^= u64::try_from(names.len()).unwrap_or(u64::MAX);
    for name in names {
        digest = fold_xattr_bytes(digest, name);
    }
    digest
}

fn xattr_get_list_report_batch(root: &Path, operations: usize) -> Result<(u64, u64)> {
    let inline_path = root.join(XATTR_INLINE_FILE);
    let external_path = root.join(XATTR_EXTERNAL_FILE);
    let many_path = root.join(XATTR_MANY_FILE);
    let mut digest = 0xCBF2_9CE4_8422_2325_u64;
    let started = Instant::now();
    for report in 0..operations {
        let inline = xattr::get(black_box(&inline_path), XATTR_INLINE_NAME)
            .with_context(|| format!("timed getxattr {}", inline_path.display()))?;
        let external = xattr::get(black_box(&external_path), XATTR_EXTERNAL_NAME)
            .with_context(|| format!("timed getxattr {}", external_path.display()))?;
        let absent = xattr::get(black_box(&inline_path), XATTR_ABSENT_NAME)
            .with_context(|| format!("timed absent getxattr {}", inline_path.display()))?;
        let single_names = list_xattr_names(black_box(&inline_path))?;
        let many_names = list_xattr_names(black_box(&many_path))?;

        digest ^= u64::try_from(report).unwrap_or(u64::MAX).rotate_left(17);
        digest = fold_xattr_bytes(digest, inline.as_deref().unwrap_or_default());
        digest = fold_xattr_bytes(digest, external.as_deref().unwrap_or_default());
        digest ^= if absent.is_none() {
            0xA11C_E000_0000_0001
        } else {
            0xA11C_E000_0000_0000
        };
        digest = fold_xattr_names(digest, &single_names);
        digest = fold_xattr_names(digest, &many_names);
    }
    let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    black_box(digest);
    Ok((elapsed, digest))
}

fn digest_path(path: &Path) -> u64 {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .as_bytes()
        .iter()
        .fold(0xCBF2_9CE4_8422_2325_u64, |digest, byte| {
            (digest ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01B3)
        })
}

fn current_linux_tid() -> Result<u32> {
    let target = fs::read_link("/proc/thread-self").context("resolve current Linux thread ID")?;
    target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("current Linux thread link has no TID: {}", target.display()))?
        .parse::<u32>()
        .with_context(|| format!("parse current Linux TID from {}", target.display()))
}

/// Distinct Linux TIDs and running CPUs reported by one batch's timed threads.
#[derive(Debug)]
struct WorkerObservation {
    threads: usize,
    cpus: BTreeSet<usize>,
}

impl WorkerObservation {
    fn collect(receiver: mpsc::Receiver<(u32, usize)>) -> Self {
        let reported = receiver.into_iter().collect::<Vec<_>>();
        let threads = reported
            .iter()
            .map(|&(tid, _)| tid)
            .collect::<BTreeSet<_>>()
            .len();
        Self {
            threads,
            cpus: reported.into_iter().map(|(_, cpu)| cpu).collect(),
        }
    }

    fn ensure_non_empty(&self, label: &str) -> Result<()> {
        ensure!(self.threads > 0, "{label} batch observed no worker threads");
        ensure!(
            !self.cpus.is_empty(),
            "{label} batch observed no worker CPUs"
        );
        Ok(())
    }
}

fn worker_operation_count(operations: usize, client_threads: usize, worker: usize) -> usize {
    debug_assert!(client_threads > 0);
    debug_assert!(worker < client_threads);
    operations / client_threads + usize::from(worker < operations % client_threads)
}

fn parallel_metadata_write_batch(
    root: &Path,
    operations: usize,
    sequence: usize,
    client_threads: usize,
    pinning: &WorkerPinning,
) -> Result<WorkloadBatch> {
    let parent = root.join("parallel-metadata");
    let (thread_id_sender, thread_id_receiver) = mpsc::channel();
    let started = Instant::now();
    let (digest, observed) = thread::scope(|scope| -> Result<(u64, WorkerObservation)> {
        let mut handles = Vec::with_capacity(client_threads);
        for worker in 0..client_threads {
            let worker_dir = parent.join(format!("worker-{worker}"));
            let worker_operations = worker_operation_count(operations, client_threads, worker);
            let thread_id_sender = thread_id_sender.clone();
            handles.push(scope.spawn(move || -> Result<u64> {
                // Bind first: a freshly spawned thread inherits the driver
                // thread's single-CPU mask, so this must be its first action to
                // keep that window to one syscall.
                let cpu = pinning.bind_current_thread(worker)?;
                thread_id_sender
                    .send((current_linux_tid()?, cpu))
                    .context("report parallel metadata worker TID")?;
                let mut digest = 0_u64;
                for index in 0..worker_operations {
                    let path = worker_dir.join(format!("r{sequence:06}-{index:06}"));
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .with_context(|| format!("parallel metadata create {}", path.display()))?;
                    digest ^= u64::try_from(index + 1)
                        .unwrap_or(u64::MAX)
                        .rotate_left(u32::try_from(worker * 7).unwrap_or(0));
                }
                Ok(digest)
            }));
        }
        drop(thread_id_sender);
        let mut digest = 0_u64;
        for handle in handles {
            digest ^= handle
                .join()
                .map_err(|_| anyhow!("parallel metadata worker panicked"))??;
        }
        Ok((digest, WorkerObservation::collect(thread_id_receiver)))
    })?;
    observed.ensure_non_empty("parallel metadata")?;
    for worker in 0..client_threads {
        let worker_dir = File::open(parent.join(format!("worker-{worker}")))
            .with_context(|| format!("open metadata worker directory {worker}"))?;
        worker_dir
            .sync_all()
            .with_context(|| format!("fsync metadata worker directory {worker}"))?;
    }
    let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    black_box(digest);
    Ok(WorkloadBatch {
        elapsed_ns: elapsed,
        digest: digest ^ u64::try_from(operations).unwrap_or(u64::MAX),
        observed_worker_threads: Some(observed.threads),
        observed_worker_cpus: observed.cpus,
    })
}

fn reset_parallel_metadata_write_batch(
    root: &Path,
    operations: usize,
    sequence: usize,
    client_threads: usize,
) -> Result<()> {
    let parent = root.join("parallel-metadata");
    let removed = thread::scope(|scope| -> Result<usize> {
        let mut handles = Vec::with_capacity(client_threads);
        for worker in 0..client_threads {
            let worker_dir = parent.join(format!("worker-{worker}"));
            let worker_operations = worker_operation_count(operations, client_threads, worker);
            handles.push(scope.spawn(move || -> Result<usize> {
                for index in 0..worker_operations {
                    let path = worker_dir.join(format!("r{sequence:06}-{index:06}"));
                    fs::remove_file(&path).with_context(|| {
                        format!("reset parallel metadata file {}", path.display())
                    })?;
                }
                Ok(worker_operations)
            }));
        }
        let mut removed = 0_usize;
        for handle in handles {
            removed += handle
                .join()
                .map_err(|_| anyhow!("parallel metadata reset worker panicked"))??;
        }
        Ok(removed)
    })?;
    ensure!(
        removed == operations,
        "parallel metadata reset removed {removed} files, expected {operations}"
    );
    for worker in 0..client_threads {
        let worker_dir = parent.join(format!("worker-{worker}"));
        ensure!(
            fs::read_dir(&worker_dir)
                .with_context(|| format!("inspect reset directory {}", worker_dir.display()))?
                .next()
                .transpose()
                .with_context(|| format!("read reset directory {}", worker_dir.display()))?
                .is_none(),
            "parallel metadata reset left entries in {}",
            worker_dir.display()
        );
    }
    Ok(())
}

fn reset_workload_state(root: &Path, config: &Config, sequence: usize) -> Result<()> {
    if config.workload == Workload::ParallelMetadataWrite {
        reset_parallel_metadata_write_batch(
            root,
            config.operations,
            sequence,
            config.client_threads(),
        )?;
    }
    Ok(())
}

fn parallel_read_batch(
    root: &Path,
    operations: usize,
    pinning: &WorkerPinning,
) -> Result<WorkloadBatch> {
    let parent = root.join("parallel-read");
    let (thread_id_sender, thread_id_receiver) = mpsc::channel();
    let started = Instant::now();
    let mut paths = fs::read_dir(&parent)
        .with_context(|| format!("parallel read readdir {}", parent.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("parallel read collect {}", parent.display()))?;
    paths.sort_by(|left, right| {
        left.as_os_str()
            .as_bytes()
            .cmp(right.as_os_str().as_bytes())
    });
    ensure!(
        paths.len() == operations,
        "parallel read fixture has {} files, expected {operations}",
        paths.len()
    );
    let digest = thread::scope(|scope| -> Result<u64> {
        let mut handles = Vec::with_capacity(DEFAULT_PARALLEL_THREADS);
        for worker in 0..DEFAULT_PARALLEL_THREADS {
            let paths = &paths;
            let thread_id_sender = thread_id_sender.clone();
            handles.push(scope.spawn(move || -> Result<u64> {
                let cpu = pinning.bind_current_thread(worker)?;
                thread_id_sender
                    .send((current_linux_tid()?, cpu))
                    .context("report parallel read worker TID")?;
                let mut buffer = vec![0_u8; PARALLEL_READ_FILE_BYTES];
                let mut digest = 0_u64;
                for index in (worker..paths.len()).step_by(DEFAULT_PARALLEL_THREADS) {
                    let path = &paths[index];
                    let file = File::open(path)
                        .with_context(|| format!("parallel read open {}", path.display()))?;
                    file.read_exact_at(&mut buffer, 0)
                        .with_context(|| format!("parallel pread {}", path.display()))?;
                    let row = u64::from(buffer[0])
                        | (u64::from(buffer[buffer.len() / 2]) << 8)
                        | (u64::from(buffer[buffer.len() - 1]) << 16)
                        | u64::try_from(buffer.len())
                            .unwrap_or(u64::MAX)
                            .rotate_left(29)
                        | u64::try_from(index).unwrap_or(u64::MAX).rotate_left(41);
                    digest = digest.rotate_left(11) ^ row;
                    black_box(&buffer);
                }
                Ok(digest)
            }));
        }
        drop(thread_id_sender);
        let mut digest = 0_u64;
        for handle in handles {
            digest ^= handle
                .join()
                .map_err(|_| anyhow!("parallel read worker panicked"))??;
        }
        Ok(digest)
    })?;
    let observed = WorkerObservation::collect(thread_id_receiver);
    observed.ensure_non_empty("parallel read")?;
    let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    black_box(digest);
    Ok(WorkloadBatch {
        elapsed_ns: elapsed,
        digest,
        observed_worker_threads: Some(observed.threads),
        observed_worker_cpus: observed.cpus,
    })
}

fn create_delete_storm_batch(root: &Path, operations: usize) -> Result<(u64, u64)> {
    let parent = root.join("create-delete-storm");
    let started = Instant::now();
    let mut digest = 0_u64;
    for index in 0..operations {
        let path = parent.join(format!("storm-{index:08}"));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("storm create {}", path.display()))?;
        digest ^= digest_path(&path);
    }
    File::open(&parent)
        .with_context(|| format!("open storm directory {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("fsync storm directory after create {}", parent.display()))?;
    for index in 0..operations {
        let path = parent.join(format!("storm-{index:08}"));
        fs::remove_file(&path).with_context(|| format!("storm delete {}", path.display()))?;
    }
    File::open(&parent)
        .with_context(|| format!("open storm directory {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("fsync storm directory after delete {}", parent.display()))?;
    let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    black_box(digest);
    Ok((
        elapsed,
        digest ^ u64::try_from(operations).unwrap_or(u64::MAX),
    ))
}

fn readdir_stat_batch(
    root: &Path,
    operations: usize,
    pinning: &WorkerPinning,
) -> Result<WorkloadBatch> {
    let parent = root.join("large-directory");
    let (thread_id_sender, thread_id_receiver) = mpsc::channel();
    let started = Instant::now();
    let paths = fs::read_dir(&parent)
        .with_context(|| format!("large-directory readdir {}", parent.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("large-directory collect {}", parent.display()))?;
    ensure!(
        paths.len() == operations,
        "large-directory fixture has {} entries, expected {operations}",
        paths.len()
    );
    let digest = thread::scope(|scope| -> Result<u64> {
        let mut handles = Vec::with_capacity(DEFAULT_PARALLEL_THREADS);
        for worker in 0..DEFAULT_PARALLEL_THREADS {
            let paths = &paths;
            let thread_id_sender = thread_id_sender.clone();
            handles.push(scope.spawn(move || -> Result<u64> {
                let cpu = pinning.bind_current_thread(worker)?;
                thread_id_sender
                    .send((current_linux_tid()?, cpu))
                    .context("report readdir+stat worker TID")?;
                let mut digest = 0_u64;
                for index in (worker..paths.len()).step_by(DEFAULT_PARALLEL_THREADS) {
                    let path = &paths[index];
                    let metadata = fs::symlink_metadata(path)
                        .with_context(|| format!("large-directory stat {}", path.display()))?;
                    let row = metadata.len().wrapping_mul(0xD6E8_FEB8_6659_FD93)
                        ^ u64::from(metadata.mode()).rotate_left(17)
                        ^ metadata.nlink().rotate_left(31)
                        ^ digest_path(path);
                    digest = digest.wrapping_add(row);
                }
                Ok(digest)
            }));
        }
        drop(thread_id_sender);
        let mut digest = 0_u64;
        for handle in handles {
            digest = digest.wrapping_add(
                handle
                    .join()
                    .map_err(|_| anyhow!("readdir+stat worker panicked"))??,
            );
        }
        Ok(digest)
    })?;
    let observed = WorkerObservation::collect(thread_id_receiver);
    observed.ensure_non_empty("readdir+stat")?;
    let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    black_box(digest);
    Ok(WorkloadBatch {
        elapsed_ns: elapsed,
        digest,
        observed_worker_threads: Some(observed.threads),
        observed_worker_cpus: observed.cpus,
    })
}

fn write_all_at(file: &File, mut bytes: &[u8], mut offset: u64, path: &Path) -> Result<()> {
    while !bytes.is_empty() {
        let written = file
            .write_at(bytes, offset)
            .with_context(|| format!("positioned write {}", path.display()))?;
        ensure!(
            written > 0,
            "positioned write returned zero for {}",
            path.display()
        );
        bytes = &bytes[written..];
        offset = offset.saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
    }
    Ok(())
}

fn fsync_journal_batch(root: &Path, operations: usize, sequence: usize) -> Result<(u64, u64)> {
    let path = root.join("fsync.bin");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("open fsync workload {}", path.display()))?;
    let started = Instant::now();
    let mut digest = 0_u64;
    for index in 0..operations {
        let value = u8::try_from((sequence * 37 + index * 17) % 251).expect("fsync byte fits u8");
        let payload = [value; 4096];
        write_all_at(&file, &payload, 0, &path)?;
        file.sync_all()
            .with_context(|| format!("fsync workload {}", path.display()))?;
        digest ^= u64::from(value).rotate_left(u32::try_from(index % 64).unwrap_or(0));
    }
    let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    black_box(digest);
    Ok((
        elapsed,
        u64::try_from(operations)
            .unwrap_or(u64::MAX)
            .wrapping_mul(4096),
    ))
}

fn bulk_durable_write_batch(root: &Path, operations: usize, sequence: usize) -> Result<(u64, u64)> {
    let path = root.join(BULK_DURABLE_FILE);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("open bulk durable workload {}", path.display()))?;
    let total_bytes = bulk_durable_total_bytes(operations)?;
    let total_bytes_u64 =
        u64::try_from(total_bytes).context("bulk durable byte count does not fit u64")?;
    ensure!(
        file.metadata()
            .with_context(|| format!("stat bulk durable workload {}", path.display()))?
            .len()
            == total_bytes_u64,
        "bulk durable workload file length differs from its exact work contract"
    );
    let value = bulk_durable_sequence_byte(sequence);
    let payload = vec![value; BULK_DURABLE_CHUNK_BYTES];
    let started = Instant::now();
    for index in 0..operations {
        let offset = index
            .checked_mul(BULK_DURABLE_CHUNK_BYTES)
            .ok_or_else(|| anyhow!("bulk durable write offset overflow"))?;
        write_all_at(
            &file,
            black_box(&payload),
            u64::try_from(offset).context("bulk durable write offset does not fit u64")?,
            &path,
        )?;
    }
    file.sync_all()
        .with_context(|| format!("fsync bulk durable workload {}", path.display()))?;
    let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    black_box(&payload);
    Ok((elapsed, total_bytes_u64))
}

fn workload_batch(
    root: &Path,
    config: &Config,
    sequence: usize,
    pinning: &WorkerPinning,
) -> Result<WorkloadBatch> {
    match config.workload {
        Workload::ParallelMetadataWrite => {
            return parallel_metadata_write_batch(
                root,
                config.operations,
                sequence,
                config.client_threads(),
                pinning,
            );
        }
        Workload::ParallelRead8 | Workload::ParallelRead8ColdCache => {
            return parallel_read_batch(root, config.operations, pinning);
        }
        Workload::ReaddirStat8 => return readdir_stat_batch(root, config.operations, pinning),
        Workload::WarmStat
        | Workload::CreateDeleteStorm
        | Workload::FsyncJournalCommit
        | Workload::BulkDurableWrite
        | Workload::XattrGetListReport => {}
    }
    // The driver thread is bound once at startup; reaffirm and capture it here
    // so a serial batch still proves which CPU it ran on.
    let driver_cpu = pinning.bind_driver_thread()?;
    let driver_tid_before = current_linux_tid()?;
    let (elapsed_ns, digest) = match config.workload {
        Workload::WarmStat => stat_batch(&root.join("payload.bin"), config.operations)?,
        Workload::ParallelMetadataWrite
        | Workload::ParallelRead8
        | Workload::ParallelRead8ColdCache
        | Workload::ReaddirStat8 => {
            unreachable!("parallel workloads handled above")
        }
        Workload::CreateDeleteStorm => create_delete_storm_batch(root, config.operations)?,
        Workload::FsyncJournalCommit => fsync_journal_batch(root, config.operations, sequence)?,
        Workload::BulkDurableWrite => bulk_durable_write_batch(root, config.operations, sequence)?,
        Workload::XattrGetListReport => xattr_get_list_report_batch(root, config.operations)?,
    };
    let driver_tid_after = current_linux_tid()?;
    ensure!(
        driver_tid_before == driver_tid_after,
        "serial workload moved between Linux threads: {driver_tid_before} -> {driver_tid_after}"
    );
    let driver_cpu_after = observed_running_cpu()?;
    ensure!(
        driver_cpu == driver_cpu_after,
        "serial workload migrated from cpu{driver_cpu} to cpu{driver_cpu_after}"
    );
    Ok(WorkloadBatch {
        elapsed_ns,
        digest,
        observed_worker_threads: Some(1),
        observed_worker_cpus: BTreeSet::from([driver_cpu]),
    })
}

fn observe(
    root: &Path,
    config: &Config,
    sequence: usize,
    pinning: &WorkerPinning,
) -> Result<Observation> {
    let mut best = u64::MAX;
    let mut expected_digest = None;
    let mut observed_worker_threads = BTreeSet::new();
    let mut observed_worker_cpus = BTreeSet::new();
    for repeat in 0..config.observation_repeats {
        let current_sequence = sequence
            .saturating_mul(config.observation_repeats)
            .saturating_add(repeat);
        if config.workload.uses_cold_cache() {
            clear_linux_page_cache()?;
        }
        let batch = workload_batch(root, config, current_sequence, pinning)?;
        if let Some(expected) = expected_digest {
            ensure!(
                batch.digest == expected,
                "timed workload digest changed within one arm"
            );
        } else {
            expected_digest = Some(batch.digest);
        }
        if let Some(observed) = batch.observed_worker_threads {
            observed_worker_threads.insert(observed);
        }
        observed_worker_cpus.extend(batch.observed_worker_cpus);
        best = best.min(batch.elapsed_ns);
    }
    Ok(Observation {
        elapsed_ns: best,
        digest: expected_digest.unwrap_or(0),
        observed_worker_threads,
        observed_worker_cpus,
    })
}

const fn physical_arm_for(logical_arm: Arm, round: usize) -> Arm {
    if round % PHYSICAL_ROLE_CROSSOVER_ROUNDS == 0 {
        logical_arm
    } else {
        logical_arm.crossover_peer()
    }
}

fn quiesce_arm(root: &Path, config: &Config) -> Result<()> {
    if config.workload.is_mutating() {
        let output = Command::new("sync")
            .arg("-f")
            .arg(root)
            .output()
            .with_context(|| format!("syncfs quiescence for {}", root.display()))?;
        ensure!(
            output.status.success(),
            "syncfs quiescence failed for {}: status={} stderr={}",
            root.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    thread::sleep(Duration::from_millis(config.arm_settle_ms));
    Ok(())
}

/// Untimed warmup on the same balanced crossover schedule as the measured
/// rounds. Cold-cache workloads intentionally skip these reads so no timed
/// batch receives a cache residency advantage from harness warmup.
fn run_warmup_rounds(
    roots: &BTreeMap<Arm, PathBuf>,
    config: &Config,
    pinning: &WorkerPinning,
    next_sequences: &mut BTreeMap<Arm, usize>,
) -> Result<()> {
    for round in 0..config.workload.warmup_rounds() {
        for logical_arm in BALANCED_ORDERS[round % BALANCED_ORDERS.len()] {
            let physical_arm = physical_arm_for(logical_arm, round);
            let root = roots
                .get(&physical_arm)
                .ok_or_else(|| anyhow!("missing workload root for {}", physical_arm.label()))?;
            let sequence = next_sequences[&physical_arm];
            let batch = workload_batch(root, config, sequence, pinning)?;
            *next_sequences
                .get_mut(&physical_arm)
                .expect("all arms initialized") += 1;
            black_box(batch.digest);
            reset_workload_state(root, config, sequence)?;
            quiesce_arm(root, config)?;
        }
    }
    Ok(())
}

/// Clear the Linux page cache before a cold-cache timed batch. This is
/// deliberately outside the measured interval and fails closed when the
/// harness lacks the privilege required to write the global cache control.
fn clear_linux_page_cache() -> Result<()> {
    let sync = Command::new("sync")
        .output()
        .context("sync before cold-cache timed batch")?;
    ensure!(
        sync.status.success(),
        "sync before cold-cache timed batch failed: status={} stderr={}",
        sync.status,
        String::from_utf8_lossy(&sync.stderr).trim()
    );
    fs::write("/proc/sys/vm/drop_caches", "3\n")
        .context("write 3 to /proc/sys/vm/drop_caches before cold-cache timed batch")
}

fn collect_samples(
    roots: &BTreeMap<Arm, PathBuf>,
    config: &Config,
    pinning: &WorkerPinning,
    interrupted: &AtomicBool,
) -> Result<TimedSamples> {
    let mut next_sequences = BTreeMap::from([
        (Arm::KernelA, 0_usize),
        (Arm::KernelB, 0_usize),
        (Arm::FuseA, 0_usize),
        (Arm::FuseB, 0_usize),
    ]);
    run_warmup_rounds(roots, config, pinning, &mut next_sequences)?;

    let mut values = BTreeMap::from([
        (Arm::KernelA, Vec::with_capacity(config.pairs)),
        (Arm::KernelB, Vec::with_capacity(config.pairs)),
        (Arm::FuseA, Vec::with_capacity(config.pairs)),
        (Arm::FuseB, Vec::with_capacity(config.pairs)),
    ]);
    let mut physical_values = BTreeMap::from([
        (Arm::KernelA, Vec::with_capacity(config.pairs)),
        (Arm::KernelB, Vec::with_capacity(config.pairs)),
        (Arm::FuseA, Vec::with_capacity(config.pairs)),
        (Arm::FuseB, Vec::with_capacity(config.pairs)),
    ]);
    let mut digests = BTreeMap::new();
    let mut observed_worker_threads = BTreeMap::from([
        (Arm::KernelA, BTreeSet::new()),
        (Arm::KernelB, BTreeSet::new()),
        (Arm::FuseA, BTreeSet::new()),
        (Arm::FuseB, BTreeSet::new()),
    ]);
    let mut observed_worker_cpus = BTreeMap::from([
        (Arm::KernelA, BTreeSet::new()),
        (Arm::KernelB, BTreeSet::new()),
        (Arm::FuseA, BTreeSet::new()),
        (Arm::FuseB, BTreeSet::new()),
    ]);
    for round in 0..config.pairs {
        ensure!(
            !interrupted.load(Ordering::Relaxed),
            "interrupted during timed workload"
        );
        for logical_arm in BALANCED_ORDERS[round % BALANCED_ORDERS.len()] {
            let physical_arm = physical_arm_for(logical_arm, round);
            let root = roots
                .get(&physical_arm)
                .ok_or_else(|| anyhow!("missing workload root for {}", physical_arm.label()))?;
            let sequence = next_sequences[&physical_arm];
            let observation = observe(root, config, sequence, pinning)?;
            *next_sequences
                .get_mut(&physical_arm)
                .expect("all arms initialized") += 1;
            values
                .get_mut(&logical_arm)
                .expect("all arms initialized")
                .push(observation.elapsed_ns);
            physical_values
                .get_mut(&physical_arm)
                .expect("all physical arms initialized")
                .push(observation.elapsed_ns);
            observed_worker_threads
                .get_mut(&logical_arm)
                .expect("all arms initialized")
                .extend(observation.observed_worker_threads);
            observed_worker_cpus
                .get_mut(&logical_arm)
                .expect("all arms initialized")
                .extend(observation.observed_worker_cpus);
            if let Some(expected) = digests.insert(physical_arm, observation.digest) {
                ensure!(
                    expected == observation.digest,
                    "{} workload digest changed across rounds",
                    physical_arm.label()
                );
            }
            reset_workload_state(root, config, sequence)?;
            quiesce_arm(root, config)?;
        }
    }
    let expected_digest = digests
        .get(&Arm::KernelA)
        .copied()
        .ok_or_else(|| anyhow!("kernel A workload digest missing"))?;
    ensure!(
        digests.values().all(|digest| *digest == expected_digest),
        "workload result parity failed across mounted arms: {digests:?}"
    );
    let expected_next_sequence = config
        .workload
        .warmup_rounds()
        .checked_add(config.pairs)
        .ok_or_else(|| anyhow!("per-arm observation count overflow"))?;
    ensure!(
        next_sequences
            .values()
            .all(|sequence| *sequence == expected_next_sequence),
        "balanced schedule advanced physical arms unevenly: {next_sequences:?}"
    );
    Ok(TimedSamples {
        values,
        physical_values,
        digests,
        observed_worker_threads,
        observed_worker_cpus,
        last_sequence: expected_next_sequence
            .checked_sub(1)
            .ok_or_else(|| anyhow!("per-arm final sequence underflow"))?,
    })
}

fn median(mut values: Vec<f64>) -> f64 {
    assert!(!values.is_empty(), "median requires samples");
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len() % 2 == 0 {
        values[middle - 1].midpoint(values[middle])
    } else {
        values[middle]
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

fn bootstrap_median_ci(log_ratios: &[f64], seed: u64) -> BootstrapMedianCi {
    assert!(!log_ratios.is_empty(), "bootstrap requires samples");
    let mut state = seed ^ u64::try_from(log_ratios.len()).expect("sample count fits u64");
    let mut bootstrapped = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    for _ in 0..BOOTSTRAP_RESAMPLES {
        let mut sample = Vec::with_capacity(log_ratios.len());
        for _ in log_ratios {
            let draw =
                splitmix64(&mut state) % u64::try_from(log_ratios.len()).expect("length fits u64");
            sample.push(log_ratios[usize::try_from(draw).expect("draw fits usize")]);
        }
        bootstrapped.push(median(sample));
    }
    bootstrapped.sort_by(f64::total_cmp);
    let low_index = BOOTSTRAP_RESAMPLES * 25 / 1000;
    let high_index = (BOOTSTRAP_RESAMPLES * 975).div_ceil(1000).saturating_sub(1);
    BootstrapMedianCi {
        median: median(log_ratios.to_vec()).exp(),
        low: bootstrapped[low_index].exp(),
        high: bootstrapped[high_index].exp(),
    }
}

fn null_log_margin(kernel: BootstrapMedianCi, fuse: BootstrapMedianCi) -> f64 {
    [kernel.low, kernel.high, fuse.low, fuse.high]
        .into_iter()
        .map(|ratio| ratio.ln().abs())
        .fold(0.0_f64, f64::max)
}

fn clears_twice_null_margin(
    competitive: BootstrapMedianCi,
    kernel_null: BootstrapMedianCi,
    fuse_null: BootstrapMedianCi,
) -> bool {
    let required_log_margin = 2.0 * null_log_margin(kernel_null, fuse_null);
    competitive.low.ln() > required_log_margin || -competitive.high.ln() > required_log_margin
}

fn worker_thread_observation_is_clear(
    observed_by_arm: &BTreeMap<Arm, BTreeSet<usize>>,
    requested: usize,
) -> bool {
    let expected = BTreeSet::from([requested]);
    [Arm::KernelA, Arm::KernelB, Arm::FuseA, Arm::FuseB]
        .into_iter()
        .all(|arm| observed_by_arm.get(&arm) == Some(&expected))
}

/// Every arm's timed threads must have run on exactly the bound CPU set.
///
/// A thread that reported any other CPU means the single-CPU binding did not
/// hold, which is the variance source the A/A nulls are sensitive to, so the
/// run is not admissible.
fn worker_cpu_pinning_is_clear(
    observed_by_arm: &BTreeMap<Arm, BTreeSet<usize>>,
    expected: &BTreeSet<usize>,
) -> bool {
    [Arm::KernelA, Arm::KernelB, Arm::FuseA, Arm::FuseB]
        .into_iter()
        .all(|arm| observed_by_arm.get(&arm) == Some(expected))
}

fn crossover_log_ratios(numerator: &[u64], denominator: &[u64]) -> Result<Vec<f64>> {
    ensure!(
        numerator.len() == denominator.len() && !numerator.is_empty(),
        "paired ratio arms must be non-empty and equal length"
    );
    ensure!(
        numerator.len() % ESTIMATOR_BLOCK_ROUNDS == 0,
        "paired ratio arms must contain complete crossover blocks"
    );
    let per_round = numerator
        .iter()
        .zip(denominator)
        .map(|(&num, &den)| {
            ensure!(num > 0 && den > 0, "timed samples must be positive");
            Ok((num as f64).ln() - (den as f64).ln())
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(per_round
        .chunks_exact(ESTIMATOR_BLOCK_ROUNDS)
        .map(|block| block.iter().sum::<f64>() / ESTIMATOR_BLOCK_DIVISOR)
        .collect())
}

fn competitive_log_ratios(samples: &TimedSamples) -> Result<Vec<f64>> {
    let kernel_a = &samples.values[&Arm::KernelA];
    let kernel_b = &samples.values[&Arm::KernelB];
    let fuse_a = &samples.values[&Arm::FuseA];
    let fuse_b = &samples.values[&Arm::FuseB];
    ensure!(
        kernel_a.len() == kernel_b.len()
            && kernel_a.len() == fuse_a.len()
            && kernel_a.len() == fuse_b.len(),
        "competitive arms must have equal sample counts"
    );
    ensure!(
        kernel_a.len() % ESTIMATOR_BLOCK_ROUNDS == 0,
        "competitive arms must contain complete crossover blocks"
    );
    let per_round = kernel_a
        .iter()
        .zip(kernel_b)
        .zip(fuse_a.iter().zip(fuse_b))
        .map(
            |((&kernel_left, &kernel_right), (&fuse_left, &fuse_right))| {
                0.5 * ((fuse_left as f64).ln() + (fuse_right as f64).ln()
                    - (kernel_left as f64).ln()
                    - (kernel_right as f64).ln())
            },
        )
        .collect::<Vec<_>>();
    Ok(per_round
        .chunks_exact(ESTIMATOR_BLOCK_ROUNDS)
        .map(|block| block.iter().sum::<f64>() / ESTIMATOR_BLOCK_DIVISOR)
        .collect())
}

fn read_cpu_ticks() -> Result<BTreeMap<usize, CpuTicks>> {
    let content = fs::read_to_string("/proc/stat").context("read /proc/stat")?;
    let mut cpus = BTreeMap::new();
    for line in content.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(label) = fields.next() else {
            continue;
        };
        let Some(suffix) = label.strip_prefix("cpu") else {
            continue;
        };
        if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let cpu = suffix.parse::<usize>().context("parse CPU index")?;
        let ticks = fields
            .map(str::parse::<u64>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .with_context(|| format!("parse /proc/stat ticks for cpu{cpu}"))?;
        ensure!(ticks.len() >= 5, "cpu{cpu} /proc/stat row is too short");
        let total = ticks.iter().copied().sum();
        let idle = ticks[3].saturating_add(ticks[4]);
        cpus.insert(cpu, CpuTicks { total, idle });
    }
    ensure!(!cpus.is_empty(), "no per-CPU rows in /proc/stat");
    Ok(cpus)
}

fn sample_cpu_busy() -> Result<BTreeMap<usize, f64>> {
    let before = read_cpu_ticks()?;
    thread::sleep(CPU_SAMPLE_INTERVAL);
    let after = read_cpu_ticks()?;
    let mut busy = BTreeMap::new();
    for (cpu, start) in before {
        let end = after
            .get(&cpu)
            .ok_or_else(|| anyhow!("cpu{cpu} disappeared during load sample"))?;
        let total = end.total.saturating_sub(start.total);
        let idle = end.idle.saturating_sub(start.idle);
        let fraction = if total == 0 {
            1.0
        } else {
            total.saturating_sub(idle) as f64 / total as f64
        };
        busy.insert(cpu, fraction);
    }
    Ok(busy)
}

fn busy_cpus_above_limit(
    busy: &BTreeMap<usize, f64>,
    allowed_cpus: &BTreeSet<usize>,
    limit: f64,
) -> Result<Vec<(usize, f64)>> {
    allowed_cpus
        .iter()
        .map(|cpu| {
            let load = busy
                .get(cpu)
                .copied()
                .ok_or_else(|| anyhow!("allowed cpu{cpu} disappeared during load sample"))?;
            Ok((*cpu, load))
        })
        .filter_map(|row: Result<(usize, f64)>| match row {
            Ok((cpu, load)) if load > limit => Some(Ok((cpu, load))),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn format_busy_cpus(cpus: &[(usize, f64)]) -> String {
    if cpus.is_empty() {
        return "none".to_owned();
    }
    cpus.iter()
        .map(|(cpu, load)| format!("cpu{cpu}={:.1}%", load * 100.0))
        .collect::<Vec<_>>()
        .join(",")
}

fn wait_for_host_quiet(
    allowed_cpus: &BTreeSet<usize>,
    required_clear_samples: usize,
    timeout_ms: u64,
    phase: &str,
) -> Result<HostQuietWindow> {
    let started = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let mut samples_observed = 0;
    let mut consecutive_clear = 0;
    loop {
        let busy_fractions = sample_cpu_busy()?;
        samples_observed += 1;
        let busy_cpus =
            busy_cpus_above_limit(&busy_fractions, allowed_cpus, MAX_DRIVER_PREFLIGHT_BUSY)?;
        if busy_cpus.is_empty() {
            consecutive_clear += 1;
            if consecutive_clear >= required_clear_samples {
                return Ok(HostQuietWindow {
                    busy_fractions,
                    samples_observed,
                    elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                });
            }
        } else {
            consecutive_clear = 0;
        }
        if started.elapsed() >= timeout {
            bail!(
                "{phase} did not obtain {required_clear_samples} consecutive clear host-wide samples within {timeout_ms} ms after {samples_observed} samples; last busy CPUs above {:.1}%: {}",
                MAX_DRIVER_PREFLIGHT_BUSY * 100.0,
                format_busy_cpus(&busy_cpus)
            );
        }
    }
}

fn parse_cpu_list(value: &str) -> Result<BTreeSet<usize>> {
    let mut cpus = BTreeSet::new();
    for range in value.trim().split(',').filter(|part| !part.is_empty()) {
        if let Some((start, end)) = range.split_once('-') {
            let start = start.parse::<usize>().context("parse CPU range start")?;
            let end = end.parse::<usize>().context("parse CPU range end")?;
            ensure!(start <= end, "descending CPU range: {range}");
            cpus.extend(start..=end);
        } else {
            cpus.insert(range.parse::<usize>().context("parse CPU index")?);
        }
    }
    ensure!(!cpus.is_empty(), "CPU list is empty");
    Ok(cpus)
}

fn format_cpu_list(cpus: impl IntoIterator<Item = usize>) -> String {
    cpus.into_iter()
        .map(|cpu| cpu.to_string())
        .collect::<Vec<_>>()
        .join(":")
}

fn self_allowed_cpus() -> Result<BTreeSet<usize>> {
    let status = fs::read_to_string("/proc/self/status").context("read /proc/self/status")?;
    let allowed = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:\t"))
        .ok_or_else(|| anyhow!("Cpus_allowed_list missing from /proc/self/status"))?;
    parse_cpu_list(allowed)
}

fn self_cpu_affinity_mask() -> Result<String> {
    let status = fs::read_to_string("/proc/self/status").context("read /proc/self/status")?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed:\t"))
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("Cpus_allowed missing from /proc/self/status"))
}

fn cgroup_cpuset_effective() -> Option<String> {
    let cgroup = fs::read_to_string("/proc/self/cgroup").ok()?;
    let mut candidates = Vec::new();
    for line in cgroup.lines() {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let relative = fields.next()?.trim_start_matches('/');
        if controllers.is_empty() {
            candidates.push(
                Path::new("/sys/fs/cgroup")
                    .join(relative)
                    .join("cpuset.cpus.effective"),
            );
        } else if controllers.split(',').any(|name| name == "cpuset") {
            candidates.push(
                Path::new("/sys/fs/cgroup/cpuset")
                    .join(relative)
                    .join("cpuset.cpus.effective"),
            );
            candidates.push(
                Path::new("/sys/fs/cgroup/cpuset")
                    .join(relative)
                    .join("cpuset.cpus"),
            );
        }
    }
    candidates
        .into_iter()
        .find_map(|path| fs::read_to_string(path).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn per_cpu_frequency_value(
    cpus: &BTreeSet<usize>,
    filename: &str,
    required: bool,
) -> Result<BTreeMap<usize, String>> {
    let mut values = BTreeMap::new();
    for &cpu in cpus {
        let path = PathBuf::from(format!(
            "/sys/devices/system/cpu/cpu{cpu}/cpufreq/{filename}"
        ));
        match fs::read_to_string(&path) {
            Ok(value) => {
                let value = value.trim();
                ensure!(
                    !value.is_empty(),
                    "CPU frequency policy file is empty: {}",
                    path.display()
                );
                values.insert(cpu, value.to_owned());
            }
            Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("read CPU frequency policy {}", path.display()));
            }
        }
    }
    if required {
        ensure!(
            values.len() == cpus.len(),
            "{filename} provenance covers {} of {} allowed CPUs",
            values.len(),
            cpus.len()
        );
    }
    Ok(values)
}

fn cpu_frequency_policy(cpus: &BTreeSet<usize>) -> Result<CpuFrequencyPolicy> {
    Ok(CpuFrequencyPolicy {
        drivers: per_cpu_frequency_value(cpus, "scaling_driver", true)?,
        governors: per_cpu_frequency_value(cpus, "scaling_governor", true)?,
        energy_performance_preferences: per_cpu_frequency_value(
            cpus,
            "energy_performance_preference",
            false,
        )?,
    })
}

fn distinct_frequency_values(values: &BTreeMap<usize, String>) -> String {
    values
        .values()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(":")
}

fn cpu_frequency_policy_json(policy: &CpuFrequencyPolicy) -> Value {
    json!({
        "drivers_by_cpu": policy.drivers,
        "governors_by_cpu": policy.governors,
        "energy_performance_preferences_by_cpu": policy.energy_performance_preferences,
        "distinct_drivers": distinct_frequency_values(&policy.drivers),
        "distinct_governors": distinct_frequency_values(&policy.governors),
        "distinct_energy_performance_preferences": distinct_frequency_values(
            &policy.energy_performance_preferences
        ),
        "non_performance_or_mixed_governor_warning": policy.governor_warning(),
    })
}

fn cpu_topology_id(cpu: usize, name: &str) -> Result<usize> {
    let path = PathBuf::from(format!("/sys/devices/system/cpu/cpu{cpu}/topology/{name}"));
    fs::read_to_string(&path)
        .with_context(|| format!("read CPU topology {}", path.display()))?
        .trim()
        .parse::<usize>()
        .with_context(|| format!("parse CPU topology {}", path.display()))
}

fn physical_core_count(cpus: &BTreeSet<usize>) -> Result<usize> {
    let mut cores = BTreeSet::new();
    for &cpu in cpus {
        cores.insert((
            cpu_topology_id(cpu, "physical_package_id")?,
            cpu_topology_id(cpu, "core_id")?,
        ));
    }
    ensure!(!cores.is_empty(), "host exposes no physical CPU cores");
    Ok(cores.len())
}

fn total_memory_bytes() -> Result<u64> {
    let meminfo = fs::read_to_string("/proc/meminfo").context("read /proc/meminfo")?;
    let kib = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|value| value.split_ascii_whitespace().next())
        .ok_or_else(|| anyhow!("MemTotal is missing from /proc/meminfo"))?
        .parse::<u64>()
        .context("parse MemTotal KiB")?;
    kib.checked_mul(1024)
        .ok_or_else(|| anyhow!("MemTotal byte count overflow"))
}

fn numa_node_count() -> Result<usize> {
    let nodes = parse_cpu_list(
        &fs::read_to_string("/sys/devices/system/node/online")
            .context("read online NUMA node list")?,
    )?;
    ensure!(!nodes.is_empty(), "host exposes no online NUMA nodes");
    Ok(nodes.len())
}

fn host_provenance() -> Result<HostProvenance> {
    let online_cpus = parse_cpu_list(
        &fs::read_to_string("/sys/devices/system/cpu/online").context("read online CPU list")?,
    )?;
    let allowed_cpus_before_pin = self_allowed_cpus()?;
    ensure!(
        allowed_cpus_before_pin.is_subset(&online_cpus),
        "process CPU allowance includes offline CPUs"
    );
    let cpu_info = fs::read_to_string("/proc/cpuinfo").context("read /proc/cpuinfo")?;
    let cpu_model = cpu_info
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            matches!(key.trim(), "model name" | "Hardware").then(|| value.trim().to_owned())
        })
        .ok_or_else(|| anyhow!("CPU model missing from /proc/cpuinfo"))?;
    let runtime_features = [
        ("sse2", std::is_x86_feature_detected!("sse2")),
        ("sse4.2", std::is_x86_feature_detected!("sse4.2")),
        ("avx", std::is_x86_feature_detected!("avx")),
        ("avx2", std::is_x86_feature_detected!("avx2")),
        ("f16c", std::is_x86_feature_detected!("f16c")),
        ("fma", std::is_x86_feature_detected!("fma")),
        ("avx512f", std::is_x86_feature_detected!("avx512f")),
        ("avx512bw", std::is_x86_feature_detected!("avx512bw")),
    ]
    .into_iter()
    .filter_map(|(name, detected)| detected.then_some(name))
    .collect();
    let cpu_frequency_policy = cpu_frequency_policy(&allowed_cpus_before_pin)?;
    Ok(HostProvenance {
        hostname: fs::read_to_string("/proc/sys/kernel/hostname")
            .context("read hostname")?
            .trim()
            .to_owned(),
        cpu_model,
        physical_cores: physical_core_count(&online_cpus)?,
        memory_bytes: total_memory_bytes()?,
        numa_nodes: numa_node_count()?,
        online_cpus,
        allowed_cpus_before_pin,
        cgroup_cpuset_effective: cgroup_cpuset_effective(),
        runtime_features,
        cpu_frequency_policy,
    })
}

fn runtime_isa_label(host: &HostProvenance) -> String {
    host.runtime_features
        .iter()
        .copied()
        .collect::<Vec<_>>()
        .join("+")
}

fn thread_siblings(cpu: usize) -> Result<BTreeSet<usize>> {
    let path = PathBuf::from(format!(
        "/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
    ));
    let value = fs::read_to_string(&path)
        .with_context(|| format!("read thread siblings {}", path.display()))?;
    parse_cpu_list(&value)
}

fn last_level_cache_siblings(cpu: usize) -> Result<BTreeSet<usize>> {
    let cache_root = PathBuf::from(format!("/sys/devices/system/cpu/cpu{cpu}/cache"));
    let mut highest: Option<(u32, BTreeSet<usize>)> = None;
    for entry in fs::read_dir(&cache_root)
        .with_context(|| format!("read CPU cache topology {}", cache_root.display()))?
    {
        let path = entry.context("read CPU cache topology entry")?.path();
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("index"))
        {
            continue;
        }
        let cache_type = fs::read_to_string(path.join("type"))
            .with_context(|| format!("read cache type {}", path.display()))?;
        if !matches!(cache_type.trim(), "Unified" | "Data") {
            continue;
        }
        let level = fs::read_to_string(path.join("level"))
            .with_context(|| format!("read cache level {}", path.display()))?
            .trim()
            .parse::<u32>()
            .with_context(|| format!("parse cache level {}", path.display()))?;
        let shared = parse_cpu_list(
            &fs::read_to_string(path.join("shared_cpu_list"))
                .with_context(|| format!("read shared CPU list {}", path.display()))?,
        )?;
        if highest.as_ref().is_none_or(|(current, _)| level > *current) {
            highest = Some((level, shared));
        }
    }
    let (level, siblings) =
        highest.ok_or_else(|| anyhow!("cpu{cpu} exposes no data or unified cache topology"))?;
    ensure!(
        siblings.contains(&cpu),
        "cpu{cpu} is absent from its L{level} shared CPU list: {siblings:?}"
    );
    Ok(siblings)
}

fn select_cpu_placement(
    client_threads: usize,
    fuse_cpu_count: usize,
    scope: PlacementScope,
    allowed_cpus: &BTreeSet<usize>,
    host_quiet_samples: usize,
    host_quiet_timeout_ms: u64,
) -> Result<CpuPlacement> {
    let initial_host_quiet_window = if scope == PlacementScope::HostWide {
        Some(wait_for_host_quiet(
            allowed_cpus,
            host_quiet_samples,
            host_quiet_timeout_ms,
            "initial placement",
        )?)
    } else {
        None
    };
    let busy = if let Some(window) = &initial_host_quiet_window {
        window.busy_fractions.clone()
    } else {
        sample_cpu_busy()?
    };
    let mut ranked: Vec<(usize, f64)> = busy
        .iter()
        .filter(|(cpu, _)| allowed_cpus.contains(cpu))
        .map(|(&cpu, &load)| (cpu, load))
        .collect();
    ensure!(!ranked.is_empty(), "no allowed CPUs were sampled");
    if scope == PlacementScope::HostWide {
        ensure!(
            ranked.len() == allowed_cpus.len(),
            "host-wide placement sampled {} of {} allowed CPUs",
            ranked.len(),
            allowed_cpus.len()
        );
        ensure!(
            busy_cpus_above_limit(&busy, allowed_cpus, MAX_DRIVER_PREFLIGHT_BUSY)?.is_empty(),
            "host-wide quiet-window helper returned a busy final sample"
        );
    }
    ranked.sort_by(|left, right| {
        left.1
            .total_cmp(&right.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    let mut driver = None;
    for &(cpu, load) in &ranked {
        let siblings = thread_siblings(cpu)?
            .intersection(allowed_cpus)
            .copied()
            .collect::<BTreeSet<_>>();
        if siblings.iter().all(|sibling| {
            busy.get(sibling)
                .is_some_and(|value| *value <= MAX_DRIVER_PREFLIGHT_BUSY)
        }) {
            driver = Some((cpu, load, siblings));
            break;
        }
    }
    let (driver_cpu, driver_busy, driver_guard_cpus) = driver.ok_or_else(|| {
        anyhow!("no physical core has every SMT thread below the driver contention limit")
    })?;
    ensure!(
        driver_busy <= MAX_DRIVER_PREFLIGHT_BUSY,
        "quietest driver CPU cpu{driver_cpu} was {:.1}% busy, above {:.1}% limit",
        driver_busy * 100.0,
        MAX_DRIVER_PREFLIGHT_BUSY * 100.0
    );
    let last_level_cache_cpus = last_level_cache_siblings(driver_cpu)?
        .intersection(allowed_cpus)
        .copied()
        .collect::<BTreeSet<_>>();
    let driver_domain = match scope {
        PlacementScope::SameLlc => &last_level_cache_cpus,
        PlacementScope::HostWide => allowed_cpus,
    };
    // One daemon CPU keeps the historical order: the daemon claims a private
    // physical core first, then the clients fill in around its guarded sibling
    // set. That is the placement every banked row was taken at, so its selection
    // must stay byte-identical.
    //
    // More than one daemon CPU cannot use that order: a domain with C physical
    // cores cannot hand private cores to both a C-thread client set and a
    // C-CPU daemon. The clients are placed first — exactly as they are today —
    // and the daemon then takes quiet CPUs the clients did not claim, which in
    // a single last-level-cache domain are their SMT siblings. That is the
    // conservative direction: the daemon shares execution resources with the
    // very threads it serves rather than being handed free cores.
    let (fuse_cpus, fuse_guard_cpus, driver_cpus, driver_guard_cpus, fuse_cpu_isolation) =
        if fuse_cpu_count == 1 {
            let (fuse_cpus, fuse_guard_cpus) = select_fuse_cpus(
                &ranked,
                &busy,
                &last_level_cache_cpus,
                &driver_guard_cpus,
                allowed_cpus,
            )?;
            let driver_context = DriverPlacementContext {
                scope,
                ranked: &ranked,
                busy: &busy,
                driver_domain,
                fuse_guard_cpus: &fuse_guard_cpus,
            };
            let (driver_cpus, driver_guard_cpus) = select_driver_cpus(
                client_threads,
                driver_cpu,
                driver_guard_cpus,
                &driver_context,
            )?;
            (
                fuse_cpus,
                fuse_guard_cpus,
                driver_cpus,
                driver_guard_cpus,
                "private_physical_core_clients_placed_after",
            )
        } else {
            let driver_context = DriverPlacementContext {
                scope,
                ranked: &ranked,
                busy: &busy,
                driver_domain,
                fuse_guard_cpus: &BTreeSet::new(),
            };
            let (driver_cpus, driver_guard_cpus) = select_driver_cpus(
                client_threads,
                driver_cpu,
                driver_guard_cpus,
                &driver_context,
            )?;
            let claimed = driver_cpus.iter().copied().collect::<BTreeSet<_>>();
            let (fuse_cpus, fuse_guard_cpus) = select_multi_fuse_cpus(
                fuse_cpu_count,
                &ranked,
                &busy,
                driver_domain,
                &claimed,
                allowed_cpus,
            )?;
            (
                fuse_cpus,
                fuse_guard_cpus,
                driver_cpus,
                driver_guard_cpus,
                "shares_physical_cores_with_clients_placed_after",
            )
        };
    Ok(CpuPlacement {
        driver_cpu,
        driver_cpus,
        fuse_cpus,
        driver_guard_cpus,
        fuse_guard_cpus,
        fuse_cpu_isolation,
        last_level_cache_cpus,
        allowed_cpus: allowed_cpus.clone(),
        busy_fractions: busy,
        initial_host_quiet_window,
    })
}

fn select_fuse_cpus(
    ranked: &[(usize, f64)],
    busy: &BTreeMap<usize, f64>,
    last_level_cache_cpus: &BTreeSet<usize>,
    driver_guard_cpus: &BTreeSet<usize>,
    allowed_cpus: &BTreeSet<usize>,
) -> Result<(Vec<usize>, BTreeSet<usize>)> {
    for &(cpu, load) in ranked {
        if !last_level_cache_cpus.contains(&cpu)
            || driver_guard_cpus.contains(&cpu)
            || load > MAX_FUSE_PREFLIGHT_BUSY
        {
            continue;
        }
        let siblings = thread_siblings(cpu)?
            .intersection(allowed_cpus)
            .copied()
            .collect::<BTreeSet<_>>();
        if siblings.iter().any(|sibling| {
            busy.get(sibling)
                .is_none_or(|value| *value > MAX_FUSE_PREFLIGHT_BUSY)
        }) {
            continue;
        }
        // Both identical FUSE daemons share one quiet physical CPU. The arms
        // execute serially, so this avoids cross-core scheduler asymmetry
        // without making the measured arms contend with each other. Requiring
        // the driver's LLC domain also avoids cross-CCD request/response bias.
        return Ok((vec![cpu], siblings));
    }
    bail!(
        "no non-sibling CPU in the driver's last-level-cache domain has every SMT thread below the FUSE contention limit"
    )
}

/// Places a multi-CPU FUSE daemon in the CPUs the clients did not claim.
///
/// Only the daemon's own CPUs are required to be quiet here. The single-CPU
/// selector additionally demands a quiet SMT sibling, but at this CPU count the
/// siblings are the benchmark's own client threads: load put there by the job
/// under measurement is the placement, not contamination. Foreign load is still
/// excluded, because every candidate CPU must clear the same busy limit.
fn select_multi_fuse_cpus(
    count: usize,
    ranked: &[(usize, f64)],
    busy: &BTreeMap<usize, f64>,
    driver_domain: &BTreeSet<usize>,
    client_cpus: &BTreeSet<usize>,
    allowed_cpus: &BTreeSet<usize>,
) -> Result<(Vec<usize>, BTreeSet<usize>)> {
    let mut chosen = Vec::with_capacity(count);
    let mut used_cores = BTreeSet::new();
    // Two passes so the daemon spreads over distinct physical cores whenever the
    // domain still has them, and only doubles up on a core once it must.
    for require_free_core in [true, false] {
        for &(cpu, load) in ranked {
            if chosen.len() == count {
                break;
            }
            if !driver_domain.contains(&cpu)
                || client_cpus.contains(&cpu)
                || chosen.contains(&cpu)
                || load > MAX_FUSE_PREFLIGHT_BUSY
            {
                continue;
            }
            if require_free_core && used_cores.contains(&cpu) {
                continue;
            }
            used_cores.extend(thread_siblings(cpu)?.intersection(allowed_cpus).copied());
            chosen.push(cpu);
        }
    }
    ensure!(
        chosen.len() == count,
        "the driver's placement domain supplied only {} quiet non-client CPUs; {count} needed for the requested daemon CPU count",
        chosen.len(),
    );
    let mut guards = BTreeSet::new();
    for &cpu in &chosen {
        guards.extend(thread_siblings(cpu)?.intersection(allowed_cpus).copied());
    }
    chosen.sort_unstable();
    Ok((chosen, guards))
}

fn select_driver_cpus(
    client_threads: usize,
    driver_cpu: usize,
    mut driver_guard_cpus: BTreeSet<usize>,
    context: &DriverPlacementContext<'_>,
) -> Result<(Vec<usize>, BTreeSet<usize>)> {
    let available_cpu_count = context
        .driver_domain
        .difference(context.fuse_guard_cpus)
        .count();
    let target_cpu_count = client_threads.min(available_cpu_count);
    ensure!(
        target_cpu_count > 0,
        "placement leaves no CPU for benchmark clients"
    );
    if context.scope == PlacementScope::SameLlc {
        ensure!(
            target_cpu_count == client_threads,
            "LLC domain has only {available_cpu_count} non-FUSE CPUs for a {client_threads}-thread workload"
        );
    }
    let mut driver_cpus = vec![driver_cpu];
    if target_cpu_count > 1 {
        for &(cpu, load) in context.ranked {
            if driver_cpus.len() >= target_cpu_count {
                break;
            }
            if !context.driver_domain.contains(&cpu)
                || context.fuse_guard_cpus.contains(&cpu)
                || driver_guard_cpus.contains(&cpu)
                || load > MAX_DRIVER_PREFLIGHT_BUSY
            {
                continue;
            }
            let siblings = thread_siblings(cpu)?
                .intersection(context.driver_domain)
                .copied()
                .collect::<BTreeSet<_>>();
            if siblings.iter().any(|sibling| {
                context
                    .busy
                    .get(sibling)
                    .is_none_or(|value| *value > MAX_DRIVER_PREFLIGHT_BUSY)
            }) {
                continue;
            }
            driver_cpus.push(cpu);
            driver_guard_cpus.extend(siblings);
        }
        for cpu in driver_guard_cpus.clone() {
            if driver_cpus.len() >= target_cpu_count {
                break;
            }
            if !driver_cpus.contains(&cpu)
                && !context.fuse_guard_cpus.contains(&cpu)
                && context
                    .busy
                    .get(&cpu)
                    .is_some_and(|load| *load <= MAX_DRIVER_PREFLIGHT_BUSY)
            {
                driver_cpus.push(cpu);
            }
        }
    }
    ensure!(
        driver_cpus.len() == target_cpu_count,
        "{} domain supplied only {} quiet client CPUs; {target_cpu_count} needed for {client_threads} requested client threads",
        context.scope.label(),
        driver_cpus.len(),
    );
    driver_cpus.sort_unstable();
    Ok((driver_cpus, driver_guard_cpus))
}

fn pin_current_process(cpus: &[usize]) -> Result<()> {
    let cpu_list = cpus
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",");
    run_checked(
        Command::new("taskset")
            .args(["-pc", &cpu_list, &std::process::id().to_string()])
            .stdout(Stdio::null()),
        "pin mounted benchmark driver",
    )?;
    let status = fs::read_to_string("/proc/self/status").context("read /proc/self/status")?;
    let allowed = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:\t"))
        .ok_or_else(|| anyhow!("Cpus_allowed_list missing from /proc/self/status"))?;
    ensure!(
        parse_cpu_list(allowed)? == cpus.iter().copied().collect(),
        "driver affinity did not resolve to {cpu_list}: {allowed}"
    );
    Ok(())
}

/// Reads the CPU the calling thread is currently executing on.
///
/// `/proc/thread-self/stat` reports `processor` as field 39. The `comm` field
/// can contain spaces, so parsing starts after its closing parenthesis, where
/// the next token is `state` (field 3).
fn observed_running_cpu() -> Result<usize> {
    let stat = fs::read_to_string("/proc/thread-self/stat")
        .context("read /proc/thread-self/stat for the running CPU")?;
    let after_comm = stat
        .rsplit_once(')')
        .ok_or_else(|| anyhow!("/proc/thread-self/stat has no comm terminator"))?
        .1;
    after_comm
        .split_whitespace()
        .nth(36)
        .ok_or_else(|| anyhow!("/proc/thread-self/stat has no processor field"))?
        .parse::<usize>()
        .context("parse the running CPU from /proc/thread-self/stat")
}

/// One fixed CPU per timed thread.
///
/// `pin_current_process` only constrains the *process* to the placement's CPU
/// set. That leaves the kernel free to place, and then migrate, each freshly
/// spawned worker anywhere inside that set on every timed batch, so per-round
/// L1/L2/LLC residency and SMT pairing vary. The variation is independent
/// between the two same-type physical arms, so it does not cancel in the A/A
/// crossover difference the way host-wide common-mode noise does, and it was
/// what pushed the warm-cache A/A nulls past the admission gate. Binding worker
/// `w` to one fixed CPU removes that degree of freedom, and it is applied
/// identically in all four arms so it cannot bias the competitive ratio.
#[derive(Clone, Debug)]
struct WorkerPinning {
    cpus: Vec<usize>,
}

impl WorkerPinning {
    fn new(cpus: Vec<usize>) -> Result<Self> {
        ensure!(
            !cpus.is_empty(),
            "timed-worker pinning requires at least one placement CPU"
        );
        Ok(Self { cpus })
    }

    fn cpu_for(&self, worker: usize) -> usize {
        self.cpus[worker % self.cpus.len()]
    }

    /// The CPU set every timed thread of one batch is expected to report.
    fn expected_cpus(&self, client_threads: usize) -> BTreeSet<usize> {
        (0..client_threads).map(|w| self.cpu_for(w)).collect()
    }

    /// Binds the benchmark driver thread itself.
    ///
    /// The driver thread is not just a spawner: it enumerates directories, joins
    /// the workers, and — for the parallel metadata workload — performs every
    /// worker directory's `fsync` inside the timed region. On ext4 `data=ordered`
    /// each of those forces a journal commit, so that serial tail is a large
    /// fraction of the batch. Leaving it free to migrate across the placement set
    /// reintroduced exactly the per-round variance the worker binding removes,
    /// and it was what kept the parallel-metadata A/A null above the gate after
    /// the workers were bound.
    fn bind_driver_thread(&self) -> Result<usize> {
        self.bind_current_thread(0)
    }

    /// Binds the calling thread to exactly one CPU and returns the CPU it is
    /// running on afterwards, so the binding is proven rather than assumed.
    fn bind_current_thread(&self, worker: usize) -> Result<usize> {
        let cpu = self.cpu_for(worker);
        let mut set = CpuSet::new();
        set.set(cpu)
            .with_context(|| format!("build single-CPU affinity mask for cpu{cpu}"))?;
        sched_setaffinity(Pid::from_raw(0), &set)
            .with_context(|| format!("bind timed worker {worker} to cpu{cpu}"))?;
        // Parallel workers are spawned inside the timed region, so the
        // confirmation runs there too. `sched_getcpu` is vDSO-backed and costs
        // tens of nanoseconds; parsing `/proc/thread-self/stat` here would add
        // back a variable fixed cost of exactly the kind this pinning removes.
        let observed = sched_getcpu()
            .with_context(|| format!("read running CPU for timed worker {worker}"))?;
        ensure!(
            observed == cpu,
            "timed worker {worker} was bound to cpu{cpu} but is running on cpu{observed}"
        );
        Ok(observed)
    }
}

fn free_bytes_on_data() -> Result<u64> {
    let output = Command::new("df")
        .args(["--output=avail", "-B1", "/data"])
        .output()
        .context("run df for /data")?;
    ensure!(output.status.success(), "df /data failed");
    let stdout = String::from_utf8(output.stdout).context("df output is not UTF-8")?;
    stdout
        .lines()
        .filter_map(|line| line.trim().parse::<u64>().ok())
        .next_back()
        .ok_or_else(|| anyhow!("could not parse available bytes from df"))
}

fn create_run_dir(root: &Path) -> Result<PathBuf> {
    ensure!(
        root.is_absolute() && root.starts_with("/data/tmp"),
        "artifact root must be an absolute path below /data/tmp"
    );
    fs::create_dir_all(root).with_context(|| format!("create {}", root.display()))?;
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time predates Unix epoch")?
        .as_secs();
    let run_dir = root.join(format!("run_{epoch}_{}", std::process::id()));
    fs::create_dir(&run_dir).with_context(|| format!("create {}", run_dir.display()))?;
    Ok(run_dir)
}

fn create_mount_run_dir(artifact_run_dir: &Path) -> Result<PathBuf> {
    let run_name = artifact_run_dir
        .file_name()
        .ok_or_else(|| anyhow!("artifact run directory has no final component"))?;
    let mount_root = Path::new(MOUNT_ROOT);
    fs::create_dir_all(mount_root)
        .with_context(|| format!("create mount root {}", mount_root.display()))?;
    let mount_run_dir = mount_root.join(run_name);
    fs::create_dir(&mount_run_dir)
        .with_context(|| format!("create mount run directory {}", mount_run_dir.display()))?;
    Ok(mount_run_dir)
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().context("poll child exit")? {
            ensure!(status.success(), "child exited unsuccessfully: {status}");
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let status = child.wait().context("wait after killing child")?;
            bail!("child did not exit after unmount; killed with status {status}");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

// This is the auditable four-arm transaction boundary. Splitting its context
// across helper state would make mount ownership and teardown harder to verify.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn fs_report(
    kind: FilesystemKind,
    config: &Config,
    expected_identity: &FfsBinaryIdentity,
    host: &HostProvenance,
    run_dir: &Path,
    mount_run_dir: &Path,
    fixture_root: &Path,
    placement: &CpuPlacement,
    interrupted: &AtomicBool,
) -> Result<Value> {
    let fs_dir = run_dir.join(kind.label());
    fs::create_dir(&fs_dir).with_context(|| format!("create {}", fs_dir.display()))?;
    let mount_fs_dir = mount_run_dir.join(kind.label());
    fs::create_dir(&mount_fs_dir)
        .with_context(|| format!("create mount directory {}", mount_fs_dir.display()))?;
    let base = create_base_image(kind, fixture_root, &fs_dir, config)?;
    let images = clone_images(kind, &base, &fs_dir)?;

    let mut mounts = Vec::with_capacity(4);
    for arm in [Arm::KernelA, Arm::KernelB] {
        mounts.push(mount_kernel(
            kind,
            arm,
            &images[&arm],
            &mount_fs_dir.join(arm.label()),
            config.workload.is_mutating(),
            interrupted,
        )?);
    }
    for arm in [Arm::FuseA, Arm::FuseB] {
        mounts.push(mount_fuse(
            config,
            expected_identity,
            arm,
            &images[&arm],
            &mount_fs_dir.join(arm.label()),
            &placement.fuse_cpus,
            interrupted,
        )?);
    }
    assert_independent_arms(&mounts)?;
    let kernel_identity = kernel_engine_identity(kind)?;
    let client_affinity_mask = self_cpu_affinity_mask()?;
    let client_affinity_list = format_cpu_list(self_allowed_cpus()?);

    let fuse_shas: BTreeSet<String> = mounts
        .iter()
        .filter_map(|mount| match &mount.kind {
            MountedArmKind::Fuse {
                self_reported_sha256,
                ..
            } => Some(self_reported_sha256.clone()),
            MountedArmKind::Kernel => None,
        })
        .collect();
    ensure!(
        fuse_shas.len() == 1,
        "FUSE A/A arms executed different ELFs: {fuse_shas:?}"
    );

    let identities: Vec<Value> = mounts.iter().map(MountedArm::identity_json).collect();
    let mut parity = BTreeMap::new();
    let mut initial_trees = BTreeMap::new();
    let mut initial_xattrs = BTreeMap::new();
    let mut initial_bulk_writes = BTreeMap::new();
    let mut roots = BTreeMap::new();
    for mount in &mounts {
        parity.insert(
            mount.arm,
            parity_witness(&mount.workload_root().join("payload.bin"))?,
        );
        initial_trees.insert(mount.arm, tree_witness(mount.workload_root())?);
        if config.workload == Workload::XattrGetListReport {
            initial_xattrs.insert(mount.arm, xattr_witness(mount.workload_root())?);
        }
        if config.workload == Workload::BulkDurableWrite {
            initial_bulk_writes.insert(
                mount.arm,
                bulk_durable_write_witness(
                    mount.workload_root(),
                    bulk_durable_total_bytes(config.operations)?,
                    None,
                )?,
            );
        }
        roots.insert(mount.arm, mount.workload_root().to_path_buf());
    }
    let expected_parity = parity
        .get(&Arm::KernelA)
        .cloned()
        .ok_or_else(|| anyhow!("kernel A parity witness missing"))?;
    ensure!(
        parity.values().all(|witness| witness == &expected_parity),
        "mounted parity mismatch for {}: {parity:?}",
        kind.label()
    );
    let expected_initial_tree = initial_trees
        .get(&Arm::KernelA)
        .cloned()
        .ok_or_else(|| anyhow!("kernel A initial tree witness missing"))?;
    ensure!(
        initial_trees
            .values()
            .all(|witness| witness == &expected_initial_tree),
        "initial mounted tree parity mismatch for {}: {initial_trees:?}",
        kind.label()
    );
    let expected_initial_xattr = if config.workload == Workload::XattrGetListReport {
        let expected = initial_xattrs
            .get(&Arm::KernelA)
            .cloned()
            .ok_or_else(|| anyhow!("kernel A initial xattr witness missing"))?;
        ensure!(
            initial_xattrs.values().all(|witness| witness == &expected),
            "initial mounted xattr parity mismatch for {}: {initial_xattrs:?}",
            kind.label()
        );
        Some(expected)
    } else {
        None
    };
    let expected_initial_bulk_write = if config.workload == Workload::BulkDurableWrite {
        let expected = initial_bulk_writes
            .get(&Arm::KernelA)
            .cloned()
            .ok_or_else(|| anyhow!("kernel A initial bulk-write witness missing"))?;
        ensure!(
            initial_bulk_writes
                .values()
                .all(|witness| witness == &expected),
            "initial mounted bulk-write parity mismatch for {}: {initial_bulk_writes:?}",
            kind.label()
        );
        Some(expected)
    } else {
        None
    };

    thread::sleep(Duration::from_millis(config.pre_measurement_settle_ms));
    let post_mount_host_quiet_window = if config.placement_scope == PlacementScope::HostWide {
        Some(wait_for_host_quiet(
            &placement.allowed_cpus,
            config.host_quiet_samples,
            config.host_quiet_timeout_ms,
            "post-mount pre-measurement",
        )?)
    } else {
        None
    };
    let contention = if let Some(window) = &post_mount_host_quiet_window {
        window.busy_fractions.clone()
    } else {
        sample_cpu_busy()?
    };
    if let Some(window) = &post_mount_host_quiet_window {
        println!(
            "host_wide_quiescence,allowed_cpu_count={},sample_interval_ms={},required_consecutive_clear_samples={},samples_observed={},wait_ms={},timeout_ms={},maximum_busy_fraction={:.3},busy_cpu_count_above_limit=0,verdict=clear",
            placement.allowed_cpus.len(),
            CPU_SAMPLE_INTERVAL_MS,
            config.host_quiet_samples,
            window.samples_observed,
            window.elapsed_ms,
            config.host_quiet_timeout_ms,
            MAX_DRIVER_PREFLIGHT_BUSY,
        );
    }
    for &cpu in &placement.driver_guard_cpus {
        let load = contention
            .get(&cpu)
            .copied()
            .ok_or_else(|| anyhow!("driver guard cpu{cpu} disappeared before measurement"))?;
        ensure!(
            load <= MAX_DRIVER_PREFLIGHT_BUSY,
            "driver guard cpu{cpu} became {:.1}% busy before measurement",
            load * 100.0
        );
    }
    for &cpu in &placement.fuse_guard_cpus {
        let load = contention
            .get(&cpu)
            .copied()
            .ok_or_else(|| anyhow!("FUSE guard cpu{cpu} disappeared before measurement"))?;
        ensure!(
            load <= MAX_FUSE_PREFLIGHT_BUSY,
            "FUSE cpu{cpu} became {:.1}% busy before measurement",
            load * 100.0
        );
    }

    let pinning = WorkerPinning::new(placement.driver_cpus.clone())?;
    let samples = collect_samples(&roots, config, &pinning, interrupted)?;
    let kernel_null = bootstrap_median_ci(
        &crossover_log_ratios(
            &samples.values[&Arm::KernelA],
            &samples.values[&Arm::KernelB],
        )?,
        0x4B45_524E_454C_4141,
    );
    let fuse_null = bootstrap_median_ci(
        &crossover_log_ratios(&samples.values[&Arm::FuseA], &samples.values[&Arm::FuseB])?,
        0x4655_5345_5F41_4141,
    );
    let fuse_over_kernel =
        bootstrap_median_ci(&competitive_log_ratios(&samples)?, 0x4B45_524E_454C_4142);
    let kernel_ci_contains_one = kernel_null.contains_null();
    let fuse_ci_contains_one = fuse_null.contains_null();
    let kernel_median_within_null_bias_limit = kernel_null.median_within_null_bias_limit();
    let fuse_median_within_null_bias_limit = fuse_null.median_within_null_bias_limit();
    let kernel_clear = null_control_is_clear(kernel_null, config.maximum_null_ratio);
    let fuse_clear = null_control_is_clear(fuse_null, config.maximum_null_ratio);
    let worker_thread_observation_clear = worker_thread_observation_is_clear(
        &samples.observed_worker_threads,
        config.client_threads(),
    );
    let expected_worker_cpus = pinning.expected_cpus(config.client_threads());
    let worker_cpu_pinning_clear =
        worker_cpu_pinning_is_clear(&samples.observed_worker_cpus, &expected_worker_cpus);
    let actual_observed_worker_threads =
        worker_thread_observation_clear.then_some(config.client_threads());
    let job_statement = config
        .workload
        .job_statement(config.operations, config.client_threads());
    let chooser_statement = config.workload.chooser_statement(
        kind,
        config.operations,
        config.client_threads(),
        actual_observed_worker_threads,
    );
    let semantic_work_contract = config
        .workload
        .semantic_work_contract(config.operations, config.client_threads());
    let admitted =
        kernel_clear && fuse_clear && worker_thread_observation_clear && worker_cpu_pinning_clear;
    let twice_null_log_margin = 2.0 * null_log_margin(kernel_null, fuse_null);
    let twice_null_ratio = twice_null_log_margin.exp();
    let directional_claim_clear =
        admitted && clears_twice_null_margin(fuse_over_kernel, kernel_null, fuse_null);
    let verdict = if !worker_thread_observation_clear {
        "BLOCKED_THREAD_OBSERVATION"
    } else if !worker_cpu_pinning_clear {
        "BLOCKED_WORKER_CPU_PINNING"
    } else if !kernel_clear || !fuse_clear {
        "BLOCKED_NULL"
    } else if !directional_claim_clear {
        "HONEST_NEUTRAL"
    } else if fuse_over_kernel.median > 1.0 {
        "HONEST_LOSS"
    } else {
        "HONEST_WIN"
    };
    let kernel_median_wall_ns = median(
        [Arm::KernelA, Arm::KernelB]
            .into_iter()
            .flat_map(|arm| samples.values[&arm].iter().copied())
            .map(|value| value as f64)
            .collect(),
    );
    let fuse_median_wall_ns = median(
        [Arm::FuseA, Arm::FuseB]
            .into_iter()
            .flat_map(|arm| samples.values[&arm].iter().copied())
            .map(|value| value as f64)
            .collect(),
    );
    let kernel_operations_per_second =
        config.operations as f64 * 1_000_000_000.0 / kernel_median_wall_ns;
    let fuse_operations_per_second =
        config.operations as f64 * 1_000_000_000.0 / fuse_median_wall_ns;

    for arm in [Arm::KernelA, Arm::KernelB, Arm::FuseA, Arm::FuseB] {
        println!(
            "mounted_kernel_arm,filesystem={},workload={},assignment_arm={},median_wall_ns={:.0},samples={}",
            kind.label(),
            config.workload.label(),
            arm.label(),
            median(
                samples.values[&arm]
                    .iter()
                    .map(|&value| value as f64)
                    .collect()
            ),
            samples.values[&arm].len(),
        );
        println!(
            "mounted_kernel_physical_arm,filesystem={},workload={},physical_arm={},median_wall_ns={:.0},samples={}",
            kind.label(),
            config.workload.label(),
            arm.label(),
            median(
                samples.physical_values[&arm]
                    .iter()
                    .map(|&value| value as f64)
                    .collect()
            ),
            samples.physical_values[&arm].len(),
        );
    }
    println!(
        "mounted_kernel_identity,filesystem={},workload={},kernel_release={},kernel_module={},kernel_engine_artifact={},kernel_engine_sha256={},kernel_runtime_notes_sha256={},kernel_arms=2,fuse_arms=2,fuse_binary_sha256={},mount_identity=pass,independent_arms=pass,options={}+noatime+nodev+nosuid,durability={}",
        kind.label(),
        config.workload.label(),
        kernel_identity.release,
        kind.kernel_module(),
        kernel_identity.artifact.display(),
        kernel_identity.artifact_sha256,
        kernel_identity.runtime_notes_sha256,
        fuse_shas
            .iter()
            .next()
            .map_or("unavailable", String::as_str),
        if config.workload.is_mutating() {
            "rw"
        } else {
            "ro"
        },
        config.workload.durability(),
    );
    println!(
        "mounted_kernel_job,filesystem={},workload={},operations={},requested_client_threads={},statement={job_statement:?}",
        kind.label(),
        config.workload.label(),
        config.operations,
        config.client_threads(),
    );
    println!(
        "mounted_kernel_incumbent_isolation,filesystem={},candidate=FrankenFS_FUSE,incumbent=Linux_kernel_{},same_invocation=true,independent_physical_arms=true,runtime_isa={},verdict=pass",
        kind.label(),
        kind.label(),
        runtime_isa_label(host),
    );
    println!(
        "mounted_kernel_chooser,filesystem={},workload={},statement={chooser_statement:?}",
        kind.label(),
        config.workload.label(),
    );
    println!(
        "mounted_kernel_parity,filesystem={},workload={},arms=4,file_sha256={},len={},mode={:o},uid={},gid={},nlink={},tree_sha256={},tree_entries={},tree_files={},tree_dirs={},tree_bytes={},verdict=pass",
        kind.label(),
        config.workload.label(),
        expected_parity.file_sha256,
        expected_parity.len,
        expected_parity.mode,
        expected_parity.uid,
        expected_parity.gid,
        expected_parity.nlink,
        expected_initial_tree.sha256,
        expected_initial_tree.entries,
        expected_initial_tree.regular_files,
        expected_initial_tree.directories,
        expected_initial_tree.bytes,
    );
    if let Some(xattr) = &expected_initial_xattr {
        println!(
            "mounted_kernel_xattr_parity,filesystem={},workload={},arms=4,xattr_sha256={},inline_value_bytes={},external_value_bytes={},single_list_names={},many_list_names={},absent_lookup_none={},external_storage_proof=debugfs_nonzero_file_acl_block,validation_timing=outside_measurement,verdict=pass",
            kind.label(),
            config.workload.label(),
            xattr.sha256,
            xattr.inline_value_bytes,
            xattr.external_value_bytes,
            xattr.single_list_names,
            xattr.many_list_names,
            xattr.absent_lookup_none,
        );
    }
    if let Some(bulk_write) = &expected_initial_bulk_write {
        println!(
            "mounted_kernel_bulk_durable_initial_parity,filesystem={},workload={},arms=4,file_sha256={},bytes={},validation_timing=outside_measurement,verdict=pass",
            kind.label(),
            config.workload.label(),
            bulk_write.sha256,
            bulk_write.bytes,
        );
    }
    for arm in [Arm::KernelA, Arm::KernelB, Arm::FuseA, Arm::FuseB] {
        println!(
            "mounted_kernel_worker_threads,filesystem={},workload={},assignment_arm={},requested={},runtime_observed_values={},observation_method={},clear={}",
            kind.label(),
            config.workload.label(),
            arm.label(),
            config.client_threads(),
            samples.observed_worker_threads[&arm]
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(":"),
            config.workload.worker_thread_observation_method(),
            worker_thread_observation_clear,
        );
        println!(
            "mounted_kernel_worker_cpu_pinning,filesystem={},workload={},assignment_arm={},bound_cpus={},runtime_observed_cpus={},binding=one_fixed_cpu_per_timed_thread,method=sched_setaffinity_then_sched_getcpu,serial_arm_extra_check=proc_thread_self_stat_no_migration,clear={}",
            kind.label(),
            config.workload.label(),
            arm.label(),
            format_cpu_list(expected_worker_cpus.iter().copied()),
            format_cpu_list(samples.observed_worker_cpus[&arm].iter().copied()),
            worker_cpu_pinning_clear,
        );
    }
    if config.workload == Workload::ParallelMetadataWrite {
        let operations_per_worker_min = config.operations / config.client_threads();
        let workers_with_extra_operation = config.operations % config.client_threads();
        let operations_per_worker_max =
            operations_per_worker_min + usize::from(workers_with_extra_operation > 0);
        println!(
            "mounted_kernel_work_distribution,filesystem={},workload={},operations_per_observation={},requested_client_threads={},operations_per_worker_min={},operations_per_worker_max={},workers_with_extra_operation={},exact_total=true",
            kind.label(),
            config.workload.label(),
            config.operations,
            config.client_threads(),
            operations_per_worker_min,
            operations_per_worker_max,
            workers_with_extra_operation,
        );
        println!(
            "mounted_kernel_state_reset,filesystem={},workload={},timed_files_per_arm_observation={},reset_files_per_arm_observation={},warmup_observations_per_arm={},measured_observations_per_arm={},reset_timing=excluded,post_reset_sync=sync_f,verdict=pass",
            kind.label(),
            config.workload.label(),
            config.operations,
            config.operations,
            WARMUP_ROUNDS,
            config.pairs,
        );
    }
    println!(
        "mounted_kernel_null,filesystem={},workload={},arm=kernel,median={:.6},median_deviation_from_one={:.6},maximum_median_deviation={:.6},median_within_limit={},ci_low={:.6},ci_high={:.6},ci_contains_one={},ci_contains_one_gate_input=false,symmetric_spread={:.6},maximum={:.6},crossover_blocks={},estimator=four_round_balanced_crossover_bootstrap_median_ci,clear={}",
        kind.label(),
        config.workload.label(),
        kernel_null.median,
        (kernel_null.median - 1.0).abs(),
        MAXIMUM_NULL_MEDIAN_DEVIATION,
        kernel_median_within_null_bias_limit,
        kernel_null.low,
        kernel_null.high,
        kernel_ci_contains_one,
        kernel_null.symmetric_spread(),
        config.maximum_null_ratio,
        config.pairs / ESTIMATOR_BLOCK_ROUNDS,
        kernel_clear,
    );
    println!(
        "mounted_kernel_null,filesystem={},workload={},arm=fuse,median={:.6},median_deviation_from_one={:.6},maximum_median_deviation={:.6},median_within_limit={},ci_low={:.6},ci_high={:.6},ci_contains_one={},ci_contains_one_gate_input=false,symmetric_spread={:.6},maximum={:.6},crossover_blocks={},estimator=four_round_balanced_crossover_bootstrap_median_ci,clear={}",
        kind.label(),
        config.workload.label(),
        fuse_null.median,
        (fuse_null.median - 1.0).abs(),
        MAXIMUM_NULL_MEDIAN_DEVIATION,
        fuse_median_within_null_bias_limit,
        fuse_null.low,
        fuse_null.high,
        fuse_ci_contains_one,
        fuse_null.symmetric_spread(),
        config.maximum_null_ratio,
        config.pairs / ESTIMATOR_BLOCK_ROUNDS,
        fuse_clear,
    );
    println!(
        "mounted_kernel_ratio,filesystem={},metric=wall_ns,workload={},requested_client_threads={},actual_observed_worker_threads={},operations_per_observation={},pairs={},crossover_blocks={},observation_reducer={},observation_repeats={},fuse_over_kernel_median={:.6},ci_low={:.6},ci_high={:.6},twice_null_margin_ratio={:.6},directional_claim_clear={},admitted={},verdict={},gate_basis=four_round_balanced_crossover_null_median_within_2pct_and_ci_spread_with_twice_widest_null_log_margin,bootstrap_resamples={},cv_used=false,instructions_used=false",
        kind.label(),
        config.workload.label(),
        config.client_threads(),
        actual_observed_worker_threads
            .map_or_else(|| "not_observed".to_owned(), |value| value.to_string()),
        config.operations,
        config.pairs,
        config.pairs / ESTIMATOR_BLOCK_ROUNDS,
        config.workload.observation_reducer(),
        config.observation_repeats,
        fuse_over_kernel.median,
        fuse_over_kernel.low,
        fuse_over_kernel.high,
        twice_null_ratio,
        directional_claim_clear,
        admitted,
        verdict,
        BOOTSTRAP_RESAMPLES,
    );
    println!(
        "mounted_kernel_throughput,filesystem={},workload={},requested_client_threads={},actual_observed_worker_threads={},operations_per_observation={},kernel_median_wall_ns={kernel_median_wall_ns:.0},fuse_median_wall_ns={fuse_median_wall_ns:.0},kernel_operations_per_second={kernel_operations_per_second:.3},fuse_operations_per_second={fuse_operations_per_second:.3},diagnostic_only=true",
        kind.label(),
        config.workload.label(),
        config.client_threads(),
        actual_observed_worker_threads
            .map_or_else(|| "not_observed".to_owned(), |value| value.to_string()),
        config.operations,
    );

    let raw_samples = samples
        .values
        .iter()
        .map(|(arm, values)| (arm.label().to_owned(), json!(values)))
        .collect::<serde_json::Map<_, _>>();
    let raw_physical_samples = samples
        .physical_values
        .iter()
        .map(|(arm, values)| (arm.label().to_owned(), json!(values)))
        .collect::<serde_json::Map<_, _>>();
    let observed_worker_threads_by_arm = samples
        .observed_worker_threads
        .iter()
        .map(|(arm, values)| (arm.label().to_owned(), json!(values)))
        .collect::<serde_json::Map<_, _>>();
    let observed_worker_cpus_by_arm = samples
        .observed_worker_cpus
        .iter()
        .map(|(arm, values)| (arm.label().to_owned(), json!(values)))
        .collect::<serde_json::Map<_, _>>();
    let workload_digests = samples
        .digests
        .iter()
        .map(|(arm, digest)| (arm.label().to_owned(), json!(format!("{digest:016x}"))))
        .collect::<serde_json::Map<_, _>>();

    let mut final_trees = BTreeMap::new();
    for mount in &mounts {
        final_trees.insert(mount.arm, tree_witness(mount.workload_root())?);
    }
    let expected_final_tree = final_trees
        .get(&Arm::KernelA)
        .cloned()
        .ok_or_else(|| anyhow!("kernel A final tree witness missing"))?;
    ensure!(
        final_trees
            .values()
            .all(|witness| witness == &expected_final_tree),
        "post-workload mounted tree parity mismatch for {}: {final_trees:?}",
        kind.label()
    );
    let expected_final_xattr = if config.workload == Workload::XattrGetListReport {
        let final_xattrs = mounts
            .iter()
            .map(|mount| Ok((mount.arm, xattr_witness(mount.workload_root())?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let expected = final_xattrs
            .get(&Arm::KernelA)
            .cloned()
            .ok_or_else(|| anyhow!("kernel A final xattr witness missing"))?;
        ensure!(
            final_xattrs.values().all(|witness| witness == &expected),
            "post-workload mounted xattr parity mismatch for {}: {final_xattrs:?}",
            kind.label()
        );
        ensure!(
            Some(&expected) == expected_initial_xattr.as_ref(),
            "read-only xattr workload changed its returned names or values"
        );
        Some(expected)
    } else {
        None
    };
    let expected_final_bulk_write = if config.workload == Workload::BulkDurableWrite {
        let expected_byte = bulk_durable_sequence_byte(samples.last_sequence);
        let expected_bytes = bulk_durable_total_bytes(config.operations)?;
        let final_bulk_writes = mounts
            .iter()
            .map(|mount| {
                Ok((
                    mount.arm,
                    bulk_durable_write_witness(
                        mount.workload_root(),
                        expected_bytes,
                        Some(expected_byte),
                    )?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let expected = final_bulk_writes
            .get(&Arm::KernelA)
            .cloned()
            .ok_or_else(|| anyhow!("kernel A final bulk-write witness missing"))?;
        ensure!(
            final_bulk_writes
                .values()
                .all(|witness| witness == &expected),
            "post-workload mounted bulk-write parity mismatch for {}: {final_bulk_writes:?}",
            kind.label()
        );
        Some(expected)
    } else {
        None
    };
    if !config.workload.is_mutating()
        || matches!(
            config.workload,
            Workload::ParallelMetadataWrite | Workload::CreateDeleteStorm
        )
    {
        ensure!(
            expected_final_tree == expected_initial_tree,
            "{} changed the mounted tree despite a nonpersistent workload",
            config.workload.label()
        );
    }
    println!(
        "mounted_kernel_post_parity,filesystem={},workload={},arms=4,tree_sha256={},tree_entries={},tree_files={},tree_dirs={},tree_bytes={},verdict=pass",
        kind.label(),
        config.workload.label(),
        expected_final_tree.sha256,
        expected_final_tree.entries,
        expected_final_tree.regular_files,
        expected_final_tree.directories,
        expected_final_tree.bytes,
    );
    if let Some(xattr) = &expected_final_xattr {
        println!(
            "mounted_kernel_post_xattr_parity,filesystem={},workload={},arms=4,xattr_sha256={},validation_timing=outside_measurement,verdict=pass",
            kind.label(),
            config.workload.label(),
            xattr.sha256,
        );
    }
    if let Some(bulk_write) = &expected_final_bulk_write {
        println!(
            "mounted_kernel_post_bulk_durable_parity,filesystem={},workload={},arms=4,file_sha256={},bytes={},uniform_byte={},validation_timing=outside_measurement,verdict=pass",
            kind.label(),
            config.workload.label(),
            bulk_write.sha256,
            bulk_write.bytes,
            bulk_write
                .uniform_byte
                .expect("final bulk-write witness records its expected byte"),
        );
    }

    for mount in mounts.iter_mut().rev() {
        mount.unmount()?;
    }
    for image in images.values() {
        validate_image(kind, image)?;
    }

    let kernel_engine_identity_json = json!({
        "release": kernel_identity.release,
        "module": kind.kernel_module(),
        "artifact": kernel_identity.artifact,
        "artifact_sha256": kernel_identity.artifact_sha256,
        "runtime_notes_sha256": kernel_identity.runtime_notes_sha256,
    });
    let incumbent_isolation_proof_json = json!({
        "verdict": "pass",
        "candidate": {
            "name": "FrankenFS FUSE",
            "boundary": "Linux VFS through two independent FrankenFS FUSE mounts",
            "physical_arms": ["fuse_a", "fuse_b"],
            "executing_elf_sha256": expected_identity.binary_sha256,
        },
        "incumbent": {
            "name": format!("Linux kernel {}", kind.label()),
            "boundary": format!(
                "Linux VFS through two independent in-kernel {} mounts",
                kind.label()
            ),
            "physical_arms": ["kernel_a", "kernel_b"],
            "release": kernel_identity.release,
            "module": kind.kernel_module(),
            "artifact": kernel_identity.artifact,
            "artifact_sha256": kernel_identity.artifact_sha256,
            "runtime_notes_sha256": kernel_identity.runtime_notes_sha256,
        },
        "same_invocation": true,
        "same_harness_process": true,
        "same_host": host.hostname,
        "same_fixture_bytes": true,
        "matched_mount_options": if config.workload.is_mutating() {
            "rw+noatime+nodev+nosuid"
        } else {
            "ro+noatime+nodev+nosuid"
        },
        "runtime_detected_isa": runtime_isa_label(host),
        "runtime_features": {
            "sse2": host.runtime_features.contains("sse2"),
            "sse4_2": host.runtime_features.contains("sse4.2"),
            "avx": host.runtime_features.contains("avx"),
            "avx2": host.runtime_features.contains("avx2"),
            "f16c": host.runtime_features.contains("f16c"),
            "fma": host.runtime_features.contains("fma"),
            "avx512f": host.runtime_features.contains("avx512f"),
            "avx512bw": host.runtime_features.contains("avx512bw"),
        },
    });
    let xattr_parity_json = match (&expected_initial_xattr, &expected_final_xattr) {
        (Some(initial), Some(final_witness)) => json!({
            "verdict": "pass",
            "validation_timing": "outside_measurement",
            "storage_shape_proof": {
                "inline": "debugfs_file_acl_zero",
                "external": "debugfs_file_acl_nonzero",
                "many_name_list": "debugfs_file_acl_nonzero",
            },
            "initial_sha256": initial.sha256,
            "final_sha256": final_witness.sha256,
            "inline_value_bytes": initial.inline_value_bytes,
            "external_value_bytes": initial.external_value_bytes,
            "single_list_names": initial.single_list_names,
            "many_list_names": initial.many_list_names,
            "absent_lookup_none": initial.absent_lookup_none,
        }),
        (None, None) => json!("not_applicable"),
        _ => unreachable!("xattr witnesses must be present at both parity boundaries"),
    };
    let bulk_durable_write_parity_json =
        match (&expected_initial_bulk_write, &expected_final_bulk_write) {
            (Some(initial), Some(final_witness)) => json!({
                "verdict": "pass",
                "validation_timing": "outside_measurement",
                "initial_sha256": initial.sha256,
                "final_sha256": final_witness.sha256,
                "bytes": final_witness.bytes,
                "final_sequence": samples.last_sequence,
                "final_uniform_byte": final_witness.uniform_byte,
                "positioned_write_bytes": BULK_DURABLE_CHUNK_BYTES,
                "file_fsyncs_per_observation": 1,
                "entire_file_overwritten": true,
            }),
            (None, None) => json!("not_applicable"),
            _ => unreachable!("bulk durable witnesses must be present at both parity boundaries"),
        };
    let parity_json = json!({
        "verdict": "pass",
        "file_sha256": expected_parity.file_sha256,
        "len": expected_parity.len,
        "mode": expected_parity.mode,
        "uid": expected_parity.uid,
        "gid": expected_parity.gid,
        "nlink": expected_parity.nlink,
        "initial_tree": {
            "sha256": expected_initial_tree.sha256,
            "entries": expected_initial_tree.entries,
            "regular_files": expected_initial_tree.regular_files,
            "directories": expected_initial_tree.directories,
            "bytes": expected_initial_tree.bytes,
        },
        "final_tree": {
            "sha256": expected_final_tree.sha256,
            "entries": expected_final_tree.entries,
            "regular_files": expected_final_tree.regular_files,
            "directories": expected_final_tree.directories,
            "bytes": expected_final_tree.bytes,
        },
        "xattr": xattr_parity_json,
        "bulk_durable_write": bulk_durable_write_parity_json,
    });
    let host_wide_quiescence_json = post_mount_host_quiet_window.as_ref().map_or_else(
        || json!("not_applicable"),
        |window| {
            json!({
                "verdict": "clear",
                "allowed_cpu_count": placement.allowed_cpus.len(),
                "sample_interval_ms": CPU_SAMPLE_INTERVAL_MS,
                "required_consecutive_clear_samples": config.host_quiet_samples,
                "samples_observed": window.samples_observed,
                "wait_ms": window.elapsed_ms,
                "timeout_ms": config.host_quiet_timeout_ms,
                "maximum_busy_fraction": MAX_DRIVER_PREFLIGHT_BUSY,
                "busy_cpu_count_above_limit": 0,
            })
        },
    );
    let diagnostic_throughput_json = json!({
        "gate_input": false,
        "kernel_median_wall_ns": kernel_median_wall_ns,
        "fuse_median_wall_ns": fuse_median_wall_ns,
        "kernel_operations_per_second": kernel_operations_per_second,
        "fuse_operations_per_second": fuse_operations_per_second,
    });
    let kernel_aa_json = json!({
        "median": kernel_null.median,
        "median_deviation_from_one": (kernel_null.median - 1.0).abs(),
        "maximum_median_deviation": MAXIMUM_NULL_MEDIAN_DEVIATION,
        "median_within_limit": kernel_median_within_null_bias_limit,
        "ci_low": kernel_null.low,
        "ci_high": kernel_null.high,
        "ci_contains_one": kernel_ci_contains_one,
        "ci_contains_one_gate_input": false,
        "symmetric_spread": kernel_null.symmetric_spread(),
        "clear": kernel_clear,
    });
    let fuse_aa_json = json!({
        "median": fuse_null.median,
        "median_deviation_from_one": (fuse_null.median - 1.0).abs(),
        "maximum_median_deviation": MAXIMUM_NULL_MEDIAN_DEVIATION,
        "median_within_limit": fuse_median_within_null_bias_limit,
        "ci_low": fuse_null.low,
        "ci_high": fuse_null.high,
        "ci_contains_one": fuse_ci_contains_one,
        "ci_contains_one_gate_input": false,
        "symmetric_spread": fuse_null.symmetric_spread(),
        "clear": fuse_clear,
    });
    let competitive_json = json!({
        "median": fuse_over_kernel.median,
        "ci_low": fuse_over_kernel.low,
        "ci_high": fuse_over_kernel.high,
        "twice_null_log_margin": twice_null_log_margin,
        "twice_null_margin_ratio": twice_null_ratio,
        "directional_claim_clear": directional_claim_clear,
    });
    let cpu_frequency_policy_json = cpu_frequency_policy_json(&host.cpu_frequency_policy);

    let Value::Object(mut report) = json!({
        "filesystem": kind.label(),
        "workload": config.workload.label(),
        "job_statement": job_statement,
        "semantic_work_contract": semantic_work_contract,
        "chooser_statement": chooser_statement,
        "incumbent_isolation_proof": incumbent_isolation_proof_json,
        "host_identity": host.hostname,
        "physical_cores": host.physical_cores,
        "logical_threads": host.online_cpus.len(),
        "memory_bytes": host.memory_bytes,
        "numa_nodes": host.numa_nodes,
        "runtime_detected_isa": runtime_isa_label(host),
        "cpu_frequency_policy": cpu_frequency_policy_json,
    }) else {
        unreachable!("JSON object literal must construct an object");
    };
    let Value::Object(execution_shape) = json!({
        "requested_client_threads": config.client_threads(),
        "actual_observed_worker_threads": actual_observed_worker_threads,
        "observed_worker_threads_by_arm": observed_worker_threads_by_arm,
        "timed_worker_cpu_binding": "one_fixed_cpu_per_timed_thread",
        "timed_worker_bound_cpus": expected_worker_cpus,
        "observed_worker_cpus_by_arm": observed_worker_cpus_by_arm,
        "worker_cpu_pinning_clear": worker_cpu_pinning_clear,
        "worker_thread_observation_method": config.workload.worker_thread_observation_method(),
        "worker_thread_observation_clear": worker_thread_observation_clear,
        "engine_sha256": {
            "incumbent_kernel": kernel_identity.artifact_sha256,
            "candidate_ffs": expected_identity.binary_sha256,
        },
        "client_affinity_mask": client_affinity_mask,
        "client_affinity_list": client_affinity_list,
        "client_affinity_cpu_count": placement.driver_cpus.len(),
        "client_affinity_cpus": placement.driver_cpus,
        "requested_client_threads_per_affinity_cpu": config.client_threads() as f64 / placement.driver_cpus.len() as f64,
        "placement_scope": config.placement_scope.label(),
        "cpu_busy_sample_interval_ms": CPU_SAMPLE_INTERVAL_MS,
        "host_quiet_required_consecutive_samples": config.host_quiet_samples,
        "host_quiet_timeout_ms": config.host_quiet_timeout_ms,
    }) else {
        unreachable!("JSON object literal must construct an object");
    };
    report.extend(execution_shape);
    let Value::Object(methodology) = json!({
        "operations_per_observation": config.operations,
        "pairs": config.pairs,
        "crossover_blocks": config.pairs / ESTIMATOR_BLOCK_ROUNDS,
        "estimator_block_rounds": ESTIMATOR_BLOCK_ROUNDS,
        "physical_role_crossover_rounds": PHYSICAL_ROLE_CROSSOVER_ROUNDS,
        "warmup_rounds": config.workload.warmup_rounds(),
        "arm_settle_ms": config.arm_settle_ms,
        "pre_measurement_settle_ms": config.pre_measurement_settle_ms,
        "pre_measurement_quiescence": "base and four cloned image files sync_all before mount, then untimed settle after mount identity and initial parity",
        "between_arm_quiescence": if config.workload.is_mutating() {
            if config.workload == Workload::ParallelMetadataWrite {
                "remove exact timed create batch, verify empty worker directories, sync -f physical mount, then settle; all outside timed interval"
            } else {
                "sync -f physical mount outside timed interval, then settle"
            }
        } else {
            "read-only; settle only"
        },
        "observation_start_state": match config.workload {
            Workload::ParallelMetadataWrite => "empty per-thread worker directories",
            Workload::BulkDurableWrite => {
                "preallocated fixed-length file; every observation overwrites every prior byte"
            }
            _ => "fixture-defined stable state",
        },
        "cache_regime": config.workload.cache_regime_provenance(),
        "observation_repeats": config.observation_repeats,
        "observation_reducer": config.workload.observation_reducer(),
        "identities": identities,
    }) else {
        unreachable!("JSON object literal must construct an object");
    };
    report.extend(methodology);
    let Value::Object(measurement_evidence) = json!({
        "kernel_engine_identity": kernel_engine_identity_json,
        "parity": parity_json,
        "pre_measurement_cpu_busy": contention,
        "host_wide_quiescence": host_wide_quiescence_json,
        "raw_wall_ns": raw_samples,
        "raw_physical_wall_ns": raw_physical_samples,
        "diagnostic_side_throughput": diagnostic_throughput_json,
        "workload_digests": workload_digests,
        "kernel_aa": kernel_aa_json,
        "fuse_aa": fuse_aa_json,
        "fuse_over_kernel": competitive_json,
        "maximum_null_ratio": config.maximum_null_ratio,
        "maximum_null_median_deviation": MAXIMUM_NULL_MEDIAN_DEVIATION,
        "gate_metric": "wall_ns",
        "gate_basis": "four_round_balanced_crossover_null_median_within_2pct_and_ci_spread_with_twice_widest_null_log_margin",
        "bootstrap_resamples": BOOTSTRAP_RESAMPLES,
        "cv_used": false,
        "instructions_used": false,
        "admitted": admitted,
        "verdict": verdict.to_ascii_lowercase(),
        "post_unmount_validation": "clean",
    }) else {
        unreachable!("JSON object literal must construct an object");
    };
    report.extend(measurement_evidence);
    let operations_per_worker_min = config.operations / config.client_threads();
    let workers_with_extra_operation = config.operations % config.client_threads();
    report.insert(
        "operations_per_requested_client_thread_min".to_owned(),
        json!(operations_per_worker_min),
    );
    report.insert(
        "operations_per_requested_client_thread_max".to_owned(),
        json!(operations_per_worker_min + usize::from(workers_with_extra_operation > 0)),
    );
    report.insert(
        "requested_client_threads_with_extra_operation".to_owned(),
        json!(workers_with_extra_operation),
    );
    report.insert("operation_distribution_exact_total".to_owned(), json!(true));
    Ok(Value::Object(report))
}

// Top-level preflight and evidence emission intentionally remain in one
// straight-line routine so no benchmark can bypass a gate.
#[allow(clippy::too_many_lines)]
fn run() -> Result<Option<PathBuf>> {
    let Some(config) = parse_args()? else {
        return Ok(None);
    };
    let host = host_provenance()?;
    ensure!(
        config.client_threads() <= host.allowed_cpus_before_pin.len(),
        "{} requested client threads exceed the pre-pin process allowance of {} logical CPUs",
        config.client_threads(),
        host.allowed_cpus_before_pin.len()
    );
    let ffs_binary_identity = inspect_ffs_binary(&config.ffs_cli)?;
    let harness_sha = current_elf_sha256()?;
    println!("bench_evidence,binary_sha256={harness_sha}");
    println!(
        "candidate_identity,binary_sha256={},pgo_profile_sha256={},isa=x86-64-v3,verdict=pass",
        ffs_binary_identity.binary_sha256, ffs_binary_identity.pgo_profile_sha256
    );
    // Both ELFs are cross-built on an rch worker and copied here, so the
    // executing host and the building host are different machines by design.
    println!(
        "binary_provenance,driver_elf_sha256={harness_sha},driver_built_on={},candidate_elf_sha256={},candidate_built_on={},executed_on={},retrieval=scp_from_rch_worker",
        config.harness_builder,
        ffs_binary_identity.binary_sha256,
        config.candidate_builder,
        host.hostname,
    );
    println!(
        "codegen_isa,target_arch={},compile_sse2={},compile_sse4_2={},compile_avx={},compile_avx2={},compile_f16c={},compile_fma={},compile_avx512f={},compile_avx512bw={},runtime_sse2={},runtime_sse4_2={},runtime_avx={},runtime_avx2={},runtime_f16c={},runtime_fma={},runtime_avx512f={},runtime_avx512bw={}",
        env::consts::ARCH,
        cfg!(target_feature = "sse2"),
        cfg!(target_feature = "sse4.2"),
        cfg!(target_feature = "avx"),
        cfg!(target_feature = "avx2"),
        cfg!(target_feature = "f16c"),
        cfg!(target_feature = "fma"),
        cfg!(target_feature = "avx512f"),
        cfg!(target_feature = "avx512bw"),
        host.runtime_features.contains("sse2"),
        host.runtime_features.contains("sse4.2"),
        host.runtime_features.contains("avx"),
        host.runtime_features.contains("avx2"),
        host.runtime_features.contains("f16c"),
        host.runtime_features.contains("fma"),
        host.runtime_features.contains("avx512f"),
        host.runtime_features.contains("avx512bw"),
    );
    println!(
        "baseline_host,hostname={},cpu_model={},physical_cores={},logical_threads={},memory_bytes={},numa_nodes={},requested_client_threads={},runtime_isa={},cpu_frequency_drivers={},scaling_governors={},energy_performance_preferences={},non_performance_or_mixed_governor_warning={},placement_scope={},cpu_busy_sample_interval_ms={},host_quiet_required_consecutive_samples={},host_quiet_timeout_ms={},pre_pin_allowed_cpus={},pre_pin_allowed_cpu_count={},cgroup_cpuset_effective={}",
        host.hostname,
        host.cpu_model,
        host.physical_cores,
        host.online_cpus.len(),
        host.memory_bytes,
        host.numa_nodes,
        config.client_threads(),
        runtime_isa_label(&host),
        distinct_frequency_values(&host.cpu_frequency_policy.drivers),
        distinct_frequency_values(&host.cpu_frequency_policy.governors),
        distinct_frequency_values(&host.cpu_frequency_policy.energy_performance_preferences),
        host.cpu_frequency_policy.governor_warning(),
        config.placement_scope.label(),
        CPU_SAMPLE_INTERVAL_MS,
        config.host_quiet_samples,
        config.host_quiet_timeout_ms,
        format_cpu_list(host.allowed_cpus_before_pin.iter().copied()),
        host.allowed_cpus_before_pin.len(),
        host.cgroup_cpuset_effective
            .as_deref()
            .unwrap_or("unavailable"),
    );

    let free_before = free_bytes_on_data()?;
    ensure!(
        free_before >= MIN_FREE_BYTES,
        "/data has {:.1} GiB free, below the 120 GiB abort floor",
        free_before as f64 / 1024.0_f64.powi(3)
    );
    let run_dir = create_run_dir(&config.artifact_root)?;
    let mount_run_dir = create_mount_run_dir(&run_dir)?;
    let output = config
        .output
        .clone()
        .unwrap_or_else(|| run_dir.join("mounted-kernel-report.json"));
    let fixture_root = create_fixture_tree(&run_dir, &config)?;
    let placement = select_cpu_placement(
        config.client_threads(),
        config.fuse_cpu_count,
        config.placement_scope,
        &host.allowed_cpus_before_pin,
        config.host_quiet_samples,
        config.host_quiet_timeout_ms,
    )?;
    pin_current_process(&placement.driver_cpus)?;
    let driver_pinning = WorkerPinning::new(placement.driver_cpus.clone())?;
    let driver_thread_cpu = driver_pinning.bind_driver_thread()?;
    println!(
        "mounted_kernel_driver_thread_binding,requested_client_threads={},placement_cpus={},driver_thread_cpu={driver_thread_cpu},binding=one_fixed_cpu,reason=the_timed_region_includes_driver_thread_directory_fsyncs,verdict=bound",
        config.client_threads(),
        format_cpu_list(placement.driver_cpus.iter().copied()),
    );
    println!(
        "core_contention_preflight,workload={},requested_client_threads={},client_affinity_cpu_count={},requested_client_threads_per_affinity_cpu={:.6},driver_cpus={},driver_guard_cpus={},driver_busy_fraction={:.6},fuse_cpus={},requested_fuse_cpus={},fuse_cpu_isolation={},fuse_guard_cpus={},fuse_busy_fractions={},placement_scope={},same_llc={},llc_cpus={},host_quiet_required_consecutive_samples={},initial_host_quiet_samples_observed={},initial_host_quiet_wait_ms={},host_quiet_timeout_ms={},driver_limit={:.3},fuse_limit={:.3},verdict=clear",
        config.workload.label(),
        config.client_threads(),
        placement.driver_cpus.len(),
        config.client_threads() as f64 / placement.driver_cpus.len() as f64,
        format_cpu_list(placement.driver_cpus.iter().copied()),
        format_cpu_list(placement.driver_guard_cpus.iter().copied()),
        placement.busy_fractions[&placement.driver_cpu],
        format_cpu_list(placement.fuse_cpus.iter().copied()),
        config.fuse_cpu_count,
        placement.fuse_cpu_isolation,
        format_cpu_list(placement.fuse_guard_cpus.iter().copied()),
        placement
            .fuse_cpus
            .iter()
            .map(|cpu| format!("{:.6}", placement.busy_fractions[cpu]))
            .collect::<Vec<_>>()
            .join(":"),
        config.placement_scope.label(),
        config.placement_scope == PlacementScope::SameLlc,
        format_cpu_list(placement.last_level_cache_cpus.iter().copied()),
        config.host_quiet_samples,
        placement
            .initial_host_quiet_window
            .as_ref()
            .map_or(0, |window| window.samples_observed),
        placement
            .initial_host_quiet_window
            .as_ref()
            .map_or(0, |window| window.elapsed_ms),
        config.host_quiet_timeout_ms,
        MAX_DRIVER_PREFLIGHT_BUSY,
        MAX_FUSE_PREFLIGHT_BUSY,
    );

    let interrupted = Arc::new(AtomicBool::new(false));
    let signal_flag = Arc::clone(&interrupted);
    ctrlc::set_handler(move || signal_flag.store(true, Ordering::Relaxed))
        .context("install SIGINT/SIGTERM handler")?;

    let requested = match config.filesystems {
        RequestedFilesystems::Ext4 => vec![FilesystemKind::Ext4],
        RequestedFilesystems::Btrfs => vec![FilesystemKind::Btrfs],
        RequestedFilesystems::Both => vec![FilesystemKind::Ext4, FilesystemKind::Btrfs],
    };
    let mut filesystem_reports = Vec::with_capacity(requested.len());
    let mut blocked_filesystems = Vec::new();
    for kind in requested {
        filesystem_reports.push(fs_report(
            kind,
            &config,
            &ffs_binary_identity,
            &host,
            &run_dir,
            &mount_run_dir,
            &fixture_root,
            &placement,
            &interrupted,
        )?);
        let report = filesystem_reports
            .last()
            .expect("just pushed filesystem report");
        if report["admitted"].as_bool() != Some(true) {
            blocked_filesystems.push(kind.label());
        }
    }

    let free_after = free_bytes_on_data()?;
    // Built as two objects and merged: one `json!` literal carrying every
    // top-level key exceeds the macro's recursion limit.
    let timed_thread_binding_json = json!({
        "driver_thread_cpu": driver_thread_cpu,
        "driver_thread_binding": "one_fixed_cpu_for_the_whole_run",
        "reason": "the timed region includes driver-thread directory fsyncs, so the driver thread is bound like every worker",
    });
    let binary_provenance_json = json!({
        "driver_elf_sha256": harness_sha,
        "driver_built_on": config.harness_builder,
        "candidate_elf_sha256": ffs_binary_identity.binary_sha256,
        "candidate_built_on": config.candidate_builder,
        "executed_on": host.hostname,
        "retrieval": "scp_from_rch_worker",
        "note": "rch exec has no artifact-retrieval mechanism; both ELFs are built on a remote worker and copied to the executing host",
    });
    let Value::Object(identity_section) = json!({
        "schema_version": 6,
        "harness": "ffs-mounted-kernel-bench",
        "harness_binary_sha256": harness_sha,
        "ffs_cli": fs::canonicalize(&config.ffs_cli)?,
        "ffs_binary_sha256": ffs_binary_identity.binary_sha256,
        "ffs_pgo_profile_sha256": ffs_binary_identity.pgo_profile_sha256,
        "timed_thread_binding": timed_thread_binding_json,
        "binary_provenance": binary_provenance_json,
    }) else {
        unreachable!("JSON object literal must construct an object");
    };
    let report = json!({
        "kernel_release": fs::read_to_string("/proc/sys/kernel/osrelease")?.trim(),
        "artifact_root": run_dir,
        "mount_root": mount_run_dir,
        "disk_free_before_bytes": free_before,
        "disk_free_after_bytes": free_after,
        "host": {
            "hostname": host.hostname,
            "cpu_model": host.cpu_model,
            "physical_cores": host.physical_cores,
            "logical_threads": host.online_cpus.len(),
            "memory_bytes": host.memory_bytes,
            "numa_nodes": host.numa_nodes,
            "online_cpus": host.online_cpus,
            "pre_pin_allowed_cpus": host.allowed_cpus_before_pin,
            "pre_pin_allowed_cpu_count": host.allowed_cpus_before_pin.len(),
            "cgroup_cpuset_effective": host.cgroup_cpuset_effective,
            "runtime_isa": runtime_isa_label(&host),
            "runtime_features": {
                "sse2": host.runtime_features.contains("sse2"),
                "sse4_2": host.runtime_features.contains("sse4.2"),
                "avx": host.runtime_features.contains("avx"),
                "avx2": host.runtime_features.contains("avx2"),
                "f16c": host.runtime_features.contains("f16c"),
                "fma": host.runtime_features.contains("fma"),
                "avx512f": host.runtime_features.contains("avx512f"),
                "avx512bw": host.runtime_features.contains("avx512bw"),
            },
            "cpu_frequency_policy": cpu_frequency_policy_json(&host.cpu_frequency_policy),
            "cpu_busy_sample_interval_ms": CPU_SAMPLE_INTERVAL_MS,
            "host_quiet_required_consecutive_samples": config.host_quiet_samples,
            "host_quiet_timeout_ms": config.host_quiet_timeout_ms,
        },
        "driver_cpu": placement.driver_cpu,
        "driver_cpus": placement.driver_cpus,
        "client_affinity_cpu_count": placement.driver_cpus.len(),
        "requested_client_threads_per_affinity_cpu": config.client_threads() as f64 / placement.driver_cpus.len() as f64,
        "fuse_cpus": placement.fuse_cpus,
        "requested_fuse_cpus": config.fuse_cpu_count,
        "fuse_cpu_isolation": placement.fuse_cpu_isolation,
        "driver_guard_cpus": placement.driver_guard_cpus,
        "fuse_guard_cpus": placement.fuse_guard_cpus,
        "last_level_cache_cpus": placement.last_level_cache_cpus,
        "initial_cpu_busy_fractions": placement.busy_fractions,
        "initial_host_wide_quiescence": placement.initial_host_quiet_window.as_ref().map_or_else(
            || json!("not_applicable"),
            |window| json!({
                "verdict": "clear",
                "allowed_cpu_count": placement.allowed_cpus.len(),
                "sample_interval_ms": CPU_SAMPLE_INTERVAL_MS,
                "required_consecutive_clear_samples": config.host_quiet_samples,
                "samples_observed": window.samples_observed,
                "wait_ms": window.elapsed_ms,
                "timeout_ms": config.host_quiet_timeout_ms,
                "maximum_busy_fraction": MAX_DRIVER_PREFLIGHT_BUSY,
                "busy_cpu_count_above_limit": 0,
            }),
        ),
        "mount_contract": {
            "kernel": if config.workload.is_mutating() {
                "real kernel filesystem on read-write loop device"
            } else {
                "real kernel filesystem on read-only loop device"
            },
            "candidate": "FrankenFS FUSE",
            "common": [
                if config.workload.is_mutating() { "rw" } else { "ro" },
                "noatime",
                "nodev",
                "nosuid"
            ],
            "ext4_kernel_only": if config.workload.is_mutating() {
                json!(["data=ordered"])
            } else {
                json!(["noload"])
            },
            "fuse_only": ["no_background_scrub", "writeback_cache_disabled"],
            "durability": config.workload.durability(),
        },
        "workload": config.workload.label(),
        "requested_client_threads": config.client_threads(),
        "actual_observed_worker_threads": "recorded per filesystem row",
        "placement_scope": config.placement_scope.label(),
        "schedule": {
            "kind": "balanced four-arm interleave with independent kernel and FUSE A/A",
            "physical_role_assignment": "A/B physical mounts exchange logical roles every round",
            "estimator_block_rounds": ESTIMATOR_BLOCK_ROUNDS,
            "physical_role_crossover_rounds": PHYSICAL_ROLE_CROSSOVER_ROUNDS,
            "warmup_rounds": config.workload.warmup_rounds(),
            "arm_settle_ms": config.arm_settle_ms,
            "pre_measurement_settle_ms": config.pre_measurement_settle_ms,
            "host_quiet_required_consecutive_samples": config.host_quiet_samples,
            "host_quiet_timeout_ms": config.host_quiet_timeout_ms,
            "pre_measurement_quiescence": "base and four cloned image files sync_all before mount, then untimed settle after mount identity and initial parity",
            "mutating_quiescence": if config.workload.is_mutating() {
                if config.workload == Workload::ParallelMetadataWrite {
                    "remove exact timed create batch, verify empty worker directories, then sync -f; all outside timed interval"
                } else {
                    "sync -f physical mount outside timed interval"
                }
            } else {
                "not applicable"
            },
            "cache_regime": config.workload.cache_regime_provenance(),
        },
        "filesystems": filesystem_reports,
    });
    // Merge the identity section in; one `json!` literal carrying every
    // top-level key exceeds the macro's recursion limit.
    let Value::Object(report_map) = report else {
        unreachable!("JSON object literal must construct an object");
    };
    let mut merged = identity_section;
    merged.extend(report_map);
    let report = Value::Object(merged);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create report parent {}", parent.display()))?;
    }
    fs::write(&output, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("write report {}", output.display()))?;
    println!(
        "mounted_kernel_report,path={},disk_free_before_bytes={},disk_free_after_bytes={}",
        output.display(),
        free_before,
        free_after
    );
    ensure!(
        blocked_filesystems.is_empty(),
        "A/A null gate blocked filesystem(s) {}; report preserved at {}",
        blocked_filesystems.join(","),
        output.display()
    );
    Ok(Some(output))
}

fn main() -> ExitCode {
    match run() {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mounted_kernel_gate,error={error:#}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balanced_orders_put_every_arm_in_every_position() {
        for arm in [Arm::KernelA, Arm::KernelB, Arm::FuseA, Arm::FuseB] {
            let positions: BTreeSet<usize> = BALANCED_ORDERS
                .iter()
                .flat_map(|order| {
                    order
                        .iter()
                        .enumerate()
                        .filter_map(move |(index, candidate)| (*candidate == arm).then_some(index))
                })
                .collect();
            assert_eq!(positions, BTreeSet::from([0, 1, 2, 3]));
        }
    }

    #[test]
    fn crossover_exchanges_physical_roles_and_preserves_side() {
        assert_eq!(physical_arm_for(Arm::KernelA, 0), Arm::KernelA);
        assert_eq!(physical_arm_for(Arm::KernelA, 1), Arm::KernelB);
        assert_eq!(physical_arm_for(Arm::KernelB, 1), Arm::KernelA);
        assert_eq!(physical_arm_for(Arm::FuseA, 0), Arm::FuseA);
        assert_eq!(physical_arm_for(Arm::FuseA, 1), Arm::FuseB);
        assert_eq!(physical_arm_for(Arm::FuseB, 1), Arm::FuseA);
    }

    #[test]
    fn crossover_schedule_puts_every_physical_arm_in_every_position() {
        for physical_arm in [Arm::KernelA, Arm::KernelB, Arm::FuseA, Arm::FuseB] {
            let positions: BTreeSet<usize> = BALANCED_ORDERS
                .iter()
                .enumerate()
                .flat_map(|(round, order)| {
                    order
                        .iter()
                        .enumerate()
                        .filter_map(move |(position, logical_arm)| {
                            (physical_arm_for(*logical_arm, round) == physical_arm)
                                .then_some(position)
                        })
                })
                .collect();
            assert_eq!(positions, BTreeSet::from([0, 1, 2, 3]));
        }
    }

    #[test]
    fn mountinfo_parser_preserves_runtime_identity() {
        let row = "42 31 7:3 / /data/tmp/run/mnt ro,nosuid,nodev,noatime shared:1 - ext4 /dev/loop3 ro,noload";
        let parsed = parse_mountinfo_line(row).expect("parse mountinfo");
        assert_eq!(parsed.major_minor, "7:3");
        assert_eq!(parsed.mountpoint, Path::new("/data/tmp/run/mnt"));
        assert_eq!(parsed.filesystem_type, "ext4");
        assert_eq!(parsed.source, "/dev/loop3");
        assert!(parsed.mount_options.contains("ro"));
        assert!(parsed.mount_options.contains("noatime"));
        assert!(parsed.super_options.contains("noload"));
    }

    #[test]
    fn fuse_mountinfo_type_accepts_only_generic_or_ffs_subtype() {
        assert!(is_fuse_mountinfo_type("fuse"));
        assert!(is_fuse_mountinfo_type("fuse.ffs"));
        assert!(!is_fuse_mountinfo_type("fuseblk"));
        assert!(!is_fuse_mountinfo_type("fuse.other"));
        assert!(!is_fuse_mountinfo_type("ext4"));
    }

    #[test]
    fn mountinfo_unescapes_paths() {
        assert_eq!(
            mountinfo_unescape("/data/tmp/with\\040space"),
            "/data/tmp/with space"
        );
    }

    #[test]
    fn cpu_list_parser_handles_ranges() {
        assert_eq!(
            parse_cpu_list("0-2,8,10-11").expect("parse CPU list"),
            BTreeSet::from([0, 1, 2, 8, 10, 11])
        );
    }

    #[test]
    fn host_quiet_classifier_is_strict_and_requires_every_allowed_cpu() {
        let allowed = BTreeSet::from([0, 1]);
        let busy = BTreeMap::from([(0, MAX_DRIVER_PREFLIGHT_BUSY), (1, 0.201)]);
        assert_eq!(
            busy_cpus_above_limit(&busy, &allowed, MAX_DRIVER_PREFLIGHT_BUSY)
                .expect("classify busy CPUs"),
            vec![(1, 0.201)]
        );
        assert!(
            busy_cpus_above_limit(
                &BTreeMap::from([(0, 0.0)]),
                &allowed,
                MAX_DRIVER_PREFLIGHT_BUSY
            )
            .is_err()
        );
    }

    #[test]
    fn both_builder_identities_are_mandatory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cli = temp.path().join("ffs-cli");
        fs::write(&cli, b"placeholder").expect("write placeholder candidate");
        let base = Config {
            ffs_cli: cli,
            harness_builder: "hz1".to_owned(),
            candidate_builder: "hz2".to_owned(),
            ..Config::default()
        };
        validate_config(&base).expect("both builders recorded");

        let mut missing_driver = base.clone();
        missing_driver.harness_builder = String::new();
        assert!(validate_config(&missing_driver).is_err());

        // Whitespace is not a recorded origin either.
        let mut blank_candidate = base;
        blank_candidate.candidate_builder = "   ".to_owned();
        assert!(validate_config(&blank_candidate).is_err());
    }

    #[test]
    fn worker_pinning_assigns_one_distinct_cpu_per_worker() {
        let pinning = WorkerPinning::new(vec![4, 5, 6, 7]).expect("non-empty placement");
        assert_eq!(pinning.cpu_for(0), 4);
        assert_eq!(pinning.cpu_for(3), 7);
        // Every worker of an eight-thread workload on four CPUs still resolves
        // to a fixed CPU, so no worker is left free to migrate.
        assert_eq!(pinning.cpu_for(4), 4);
        assert_eq!(
            pinning.expected_cpus(4),
            BTreeSet::from([4, 5, 6, 7]),
            "one worker per placement CPU"
        );
        assert_eq!(pinning.expected_cpus(2), BTreeSet::from([4, 5]));
        assert!(WorkerPinning::new(Vec::new()).is_err());
    }

    #[test]
    fn worker_cpu_pinning_gate_requires_every_arm_on_the_bound_cpus() {
        let expected = BTreeSet::from([4, 5, 6, 7]);
        let clear = BTreeMap::from([
            (Arm::KernelA, expected.clone()),
            (Arm::KernelB, expected.clone()),
            (Arm::FuseA, expected.clone()),
            (Arm::FuseB, expected.clone()),
        ]);
        assert!(worker_cpu_pinning_is_clear(&clear, &expected));

        // A thread that escaped its binding onto an unbound CPU blocks the run.
        let mut escaped = clear.clone();
        escaped.insert(Arm::FuseB, BTreeSet::from([4, 5, 6, 7, 12]));
        assert!(!worker_cpu_pinning_is_clear(&escaped, &expected));

        // So does an arm that never covered the full bound set.
        let mut partial = clear.clone();
        partial.insert(Arm::KernelA, BTreeSet::from([4, 5]));
        assert!(!worker_cpu_pinning_is_clear(&partial, &expected));

        let mut missing = clear;
        missing.remove(&Arm::KernelB);
        assert!(!worker_cpu_pinning_is_clear(&missing, &expected));
    }

    #[test]
    fn bulk_durable_workload_accepts_each_filesystem_and_bounds_image_capacity() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cli = temp.path().join("ffs-cli");
        fs::write(&cli, b"placeholder").expect("write placeholder candidate");
        let base = Config {
            ffs_cli: cli,
            filesystems: RequestedFilesystems::Ext4,
            workload: Workload::BulkDurableWrite,
            operations: 64,
            observation_repeats: 1,
            image_size_mib: 256,
            harness_builder: "hz1".to_owned(),
            candidate_builder: "hz2".to_owned(),
            ..Config::default()
        };
        validate_config(&base).expect("bounded ext4 bulk workload");

        let mut btrfs = base.clone();
        btrfs.filesystems = RequestedFilesystems::Btrfs;
        validate_config(&btrfs).expect("bounded btrfs bulk workload");

        let mut both = base.clone();
        both.filesystems = RequestedFilesystems::Both;
        validate_config(&both).expect("bounded dual-filesystem bulk workload");

        let mut undersized = base;
        undersized.image_size_mib = 128;
        assert!(validate_config(&undersized).is_err());
    }

    #[test]
    fn only_metadata_scaling_uses_configured_client_threads() {
        assert_eq!(Workload::ParallelMetadataWrite.client_threads(96), 96);
        assert_eq!(
            Workload::ParallelRead8.client_threads(96),
            DEFAULT_PARALLEL_THREADS
        );
        assert_eq!(
            Workload::ParallelRead8ColdCache.client_threads(96),
            DEFAULT_PARALLEL_THREADS
        );
        assert_eq!(Workload::CreateDeleteStorm.client_threads(96), 1);
        assert_eq!(Workload::BulkDurableWrite.client_threads(96), 1);
        assert_eq!(Workload::XattrGetListReport.client_threads(96), 1);
    }

    #[test]
    fn cold_parallel_read_is_a_separate_no_warmup_cache_clearing_workload() {
        let cold = parse_workload("parallel-read-8t-cold-cache")
            .expect("cold parallel read workload must parse");
        assert_eq!(cold, Workload::ParallelRead8ColdCache);
        assert_eq!(cold.label(), "parallel_read_multifile_8t_cold_cache");
        assert!(cold.uses_cold_cache());
        assert_eq!(cold.warmup_rounds(), 0);
        assert!(
            cold.cache_regime_provenance()
                .contains("write 3 to /proc/sys/vm/drop_caches")
        );

        let warm = Workload::ParallelRead8;
        assert!(!warm.uses_cold_cache());
        assert_eq!(warm.warmup_rounds(), WARMUP_ROUNDS);
        assert_ne!(cold.label(), warm.label());
        assert_eq!(
            cold.semantic_work_contract(1024, DEFAULT_PARALLEL_THREADS)["workload_specific"]["warmup_batches"],
            0
        );
    }

    #[test]
    fn realistic_job_and_chooser_statements_bound_claim_shape() {
        let read = Workload::ParallelRead8.job_statement(1024, 8);
        assert!(read.contains("1024 separate 262144-byte files"));
        assert!(read.contains("268435456 total bytes"));
        assert!(read.contains("8 workers"));

        let storm = Workload::CreateDeleteStorm.job_statement(2000, 1);
        assert!(storm.contains("create 2000 empty files"));
        assert!(storm.contains("delete all 2000 files"));
        assert!(storm.contains("fsync the parent directory again"));

        let readdir = Workload::ReaddirStat8.job_statement(65_536, 8);
        assert!(readdir.contains("enumerate 65536 zero-byte entries"));
        assert!(readdir.contains("8 workers"));
        assert!(readdir.contains("every entry exactly once"));

        let bulk_write = Workload::BulkDurableWrite.job_statement(64, 1);
        assert!(bulk_write.contains("64 sequential 1048576-byte positioned writes"));
        assert!(bulk_write.contains("67108864 total bytes"));
        assert!(bulk_write.contains("fsync the file once"));

        let xattr = Workload::XattrGetListReport.job_statement(2_000, 1);
        assert!(xattr.contains("2000 complete five-call reports"));
        assert!(xattr.contains("external-block value"));
        assert!(xattr.contains("listing 24 names"));

        let chooser =
            Workload::ParallelRead8.chooser_statement(FilesystemKind::Ext4, 1024, 8, Some(8));
        assert!(
            chooser
                .starts_with("For operators choosing between FrankenFS FUSE and Linux kernel ext4")
        );
        assert!(chooser.contains("operations=1024"));
        assert!(chooser.contains("requested_worker_threads=8"));
        assert!(chooser.contains("observed_worker_threads=8"));
        assert!(chooser.contains("do not generalize"));

        let work = Workload::ParallelRead8.semantic_work_contract(1024, 8);
        assert_eq!(work["workload_specific"]["positioned_reads"], 1024);
        assert_eq!(work["workload_specific"]["total_bytes_read"], 268_435_456);
        assert_eq!(
            work["common"]["same_driver_implementation_for_all_four_arms"],
            true
        );

        let bulk_work = Workload::BulkDurableWrite.semantic_work_contract(64, 1);
        assert_eq!(bulk_work["workload_specific"]["positioned_writes"], 64);
        assert_eq!(
            bulk_work["workload_specific"]["total_bytes_written"],
            67_108_864
        );
        assert_eq!(bulk_work["workload_specific"]["file_fsyncs"], 1);
    }

    #[test]
    fn bulk_durable_batch_overwrites_every_byte_and_matches_untimed_witness() {
        let temp = tempfile::tempdir().expect("tempdir");
        let operations = 3;
        write_fixture_file(
            &temp.path().join(BULK_DURABLE_FILE),
            bulk_durable_total_bytes(operations).expect("bulk byte count"),
            0xB7,
        )
        .expect("bulk durable fixture");

        let sequence = 7;
        let (elapsed_ns, digest) =
            bulk_durable_write_batch(temp.path(), operations, sequence).expect("bulk batch");
        assert!(elapsed_ns > 0);
        assert_eq!(digest, 3 * 1024 * 1024);

        let witness = bulk_durable_write_witness(
            temp.path(),
            bulk_durable_total_bytes(operations).expect("bulk byte count"),
            Some(bulk_durable_sequence_byte(sequence)),
        )
        .expect("exact final bulk witness");
        assert_eq!(witness.bytes, 3 * 1024 * 1024);
        assert_eq!(
            witness.uniform_byte,
            Some(bulk_durable_sequence_byte(sequence))
        );
        assert_eq!(witness.sha256.len(), 64);
    }

    #[test]
    fn xattr_report_batch_matches_untimed_exact_witness() {
        let temp = tempfile::tempdir().expect("tempdir");
        for name in [XATTR_INLINE_FILE, XATTR_EXTERNAL_FILE, XATTR_MANY_FILE] {
            File::create(temp.path().join(name)).expect("create xattr fixture file");
        }
        xattr::set(
            temp.path().join(XATTR_INLINE_FILE),
            XATTR_INLINE_NAME,
            XATTR_INLINE_VALUE,
        )
        .expect("set inline xattr");
        xattr::set(
            temp.path().join(XATTR_EXTERNAL_FILE),
            XATTR_EXTERNAL_NAME,
            &xattr_external_value(),
        )
        .expect("set external xattr");
        for index in 0..XATTR_MANY_NAMES {
            xattr::set(
                temp.path().join(XATTR_MANY_FILE),
                xattr_many_name(index),
                format!("{index:02}").as_bytes(),
            )
            .expect("set many-list xattr");
        }

        let witness = xattr_witness(temp.path()).expect("exact xattr witness");
        assert_eq!(witness.inline_value_bytes, XATTR_INLINE_VALUE.len());
        assert_eq!(witness.external_value_bytes, XATTR_EXTERNAL_VALUE_BYTES);
        assert_eq!(witness.single_list_names, 1);
        assert_eq!(witness.many_list_names, XATTR_MANY_NAMES);
        assert!(witness.absent_lookup_none);

        let (elapsed_ns, first_digest) =
            xattr_get_list_report_batch(temp.path(), 2).expect("first xattr report");
        let (_, second_digest) =
            xattr_get_list_report_batch(temp.path(), 2).expect("second xattr report");
        assert!(elapsed_ns > 0);
        assert_eq!(first_digest, second_digest);
    }

    #[test]
    fn thread_observation_requires_requested_count_in_every_arm() {
        let mut observed = BTreeMap::from([
            (Arm::KernelA, BTreeSet::from([8])),
            (Arm::KernelB, BTreeSet::from([8])),
            (Arm::FuseA, BTreeSet::from([8])),
            (Arm::FuseB, BTreeSet::from([8])),
        ]);
        assert!(worker_thread_observation_is_clear(&observed, 8));
        observed.get_mut(&Arm::KernelB).expect("kernel B").insert(7);
        assert!(!worker_thread_observation_is_clear(&observed, 8));
        observed.insert(Arm::KernelB, BTreeSet::from([8]));
        assert!(!worker_thread_observation_is_clear(&observed, 1));
        observed.remove(&Arm::FuseB);
        assert!(!worker_thread_observation_is_clear(&observed, 8));
    }

    /// A pinning drawn from the CPUs this test process may actually use, so the
    /// batch helpers exercise the real `sched_setaffinity` path anywhere.
    fn test_pinning(threads: usize) -> WorkerPinning {
        let cpus = self_allowed_cpus()
            .expect("read this process's allowed CPUs")
            .into_iter()
            .take(threads)
            .collect::<Vec<_>>();
        WorkerPinning::new(cpus).expect("at least one allowed CPU")
    }

    #[test]
    fn fixed_parallel_workloads_report_eight_worker_tids_on_their_bound_cpus() {
        let pinning = test_pinning(DEFAULT_PARALLEL_THREADS);
        let expected_cpus = pinning.expected_cpus(DEFAULT_PARALLEL_THREADS);
        let temp = tempfile::tempdir().expect("tempdir");
        let parallel_read = temp.path().join("parallel-read");
        fs::create_dir(&parallel_read).expect("parallel read directory");
        for index in 0..DEFAULT_PARALLEL_THREADS {
            write_fixture_file(
                &parallel_read.join(format!("read-{index:06}.bin")),
                PARALLEL_READ_FILE_BYTES,
                index,
            )
            .expect("parallel read fixture");
        }
        let read = parallel_read_batch(temp.path(), DEFAULT_PARALLEL_THREADS, &pinning)
            .expect("parallel read batch");
        assert_eq!(read.observed_worker_threads, Some(DEFAULT_PARALLEL_THREADS));
        assert_eq!(read.observed_worker_cpus, expected_cpus);

        let large_directory = temp.path().join("large-directory");
        fs::create_dir(&large_directory).expect("large directory");
        for index in 0..DEFAULT_PARALLEL_THREADS {
            File::create(large_directory.join(format!("entry-{index:08}")))
                .expect("large-directory fixture entry");
        }
        let readdir = readdir_stat_batch(temp.path(), DEFAULT_PARALLEL_THREADS, &pinning)
            .expect("readdir+stat batch");
        assert_eq!(
            readdir.observed_worker_threads,
            Some(DEFAULT_PARALLEL_THREADS)
        );
        assert_eq!(readdir.observed_worker_cpus, expected_cpus);
    }

    #[test]
    fn parallel_metadata_reset_restores_empty_worker_directories() {
        let temp = tempfile::tempdir().expect("tempdir");
        let parent = temp.path().join("parallel-metadata");
        fs::create_dir(&parent).expect("parallel metadata parent");
        for worker in 0..2 {
            fs::create_dir(parent.join(format!("worker-{worker}"))).expect("worker directory");
        }
        let pinning = test_pinning(2);
        let batch = parallel_metadata_write_batch(temp.path(), 9, 7, 2, &pinning)
            .expect("create metadata batch");
        assert_eq!(batch.observed_worker_threads, Some(2));
        assert_eq!(batch.observed_worker_cpus, pinning.expected_cpus(2));
        assert_eq!(
            fs::read_dir(parent.join("worker-0"))
                .expect("read first worker directory")
                .count(),
            5
        );
        assert_eq!(
            fs::read_dir(parent.join("worker-1"))
                .expect("read second worker directory")
                .count(),
            4
        );
        reset_parallel_metadata_write_batch(temp.path(), 9, 7, 2).expect("reset metadata batch");
        for worker in 0..2 {
            assert_eq!(
                fs::read_dir(parent.join(format!("worker-{worker}")))
                    .expect("read worker directory")
                    .count(),
                0
            );
        }
    }

    #[test]
    fn metadata_work_distribution_preserves_exact_non_divisible_total() {
        let counts = (0..96)
            .map(|worker| worker_operation_count(8192, 96, worker))
            .collect::<Vec<_>>();
        assert_eq!(counts.iter().sum::<usize>(), 8192);
        assert_eq!(counts.iter().filter(|&&count| count == 86).count(), 32);
        assert_eq!(counts.iter().filter(|&&count| count == 85).count(), 64);
    }

    #[test]
    fn bootstrap_null_is_exact_for_identical_pairs() {
        let ratios = vec![0.0; 31];
        let ci = bootstrap_median_ci(&ratios, 7);
        assert_eq!(ci.median, 1.0);
        assert_eq!(ci.low, 1.0);
        assert_eq!(ci.high, 1.0);
        assert!(ci.median_within_null_bias_limit());
        assert!(ci.contains_null());
        assert_eq!(ci.symmetric_spread(), 1.0);
        assert!(null_control_is_clear(ci, 1.025));
    }

    #[test]
    fn ci_straddle_is_telemetry_not_a_null_veto() {
        let ci = BootstrapMedianCi {
            median: 1.009_041,
            low: 1.001_744,
            high: 1.013_361,
        };
        assert!(!ci.contains_null());
        assert!(ci.median_within_null_bias_limit());
        assert!(null_control_is_clear(ci, 1.025));
    }

    #[test]
    fn null_median_two_percent_boundary_is_inclusive() {
        let ci = |median| BootstrapMedianCi {
            median,
            low: 0.99,
            high: 1.01,
        };
        assert!(ci(0.98).median_within_null_bias_limit());
        assert!(ci(1.02).median_within_null_bias_limit());
        assert!(!ci(0.979_999).median_within_null_bias_limit());
        assert!(!ci(1.020_001).median_within_null_bias_limit());
    }

    #[test]
    fn historical_three_row_gate_audit_yields_one_loss_and_no_wins() {
        let rows = [
            (
                BootstrapMedianCi {
                    median: 0.966_904,
                    low: 0.933_998,
                    high: 1.008_743,
                },
                BootstrapMedianCi {
                    median: 0.991_734,
                    low: 0.969_409,
                    high: 1.036_149,
                },
                BootstrapMedianCi {
                    median: 1.203_230,
                    low: 1.162_802,
                    high: 1.239_236,
                },
            ),
            (
                BootstrapMedianCi {
                    median: 1.009_041,
                    low: 1.001_744,
                    high: 1.013_361,
                },
                BootstrapMedianCi {
                    median: 1.000_952,
                    low: 0.995_548,
                    high: 1.008_376,
                },
                BootstrapMedianCi {
                    median: 2.957_531,
                    low: 2.939_013,
                    high: 2.971_326,
                },
            ),
            (
                BootstrapMedianCi {
                    median: 0.990_140,
                    low: 0.975_169,
                    high: 1.009_721,
                },
                BootstrapMedianCi {
                    median: 1.000_955,
                    low: 0.996_572,
                    high: 1.007_587,
                },
                BootstrapMedianCi {
                    median: 4.212_274,
                    low: 4.068_120,
                    high: 4.290_202,
                },
            ),
        ];
        let mut decidable = 0;
        let mut wins = 0;
        let mut losses = 0;
        for (kernel_null, fuse_null, competitive) in rows {
            let admitted = null_control_is_clear(kernel_null, 1.025)
                && null_control_is_clear(fuse_null, 1.025);
            if admitted && clears_twice_null_margin(competitive, kernel_null, fuse_null) {
                decidable += 1;
                if competitive.median < 1.0 {
                    wins += 1;
                } else {
                    losses += 1;
                }
            }
        }
        assert_eq!((decidable, wins, losses), (1, 0, 1));
    }

    #[test]
    fn competitive_ci_must_clear_twice_the_worst_null_log_margin() {
        let kernel_null = BootstrapMedianCi {
            median: 1.0,
            low: 0.99,
            high: 1.01,
        };
        let fuse_null = BootstrapMedianCi {
            median: 1.0,
            low: 0.98,
            high: 1.02,
        };
        let too_close = BootstrapMedianCi {
            median: 1.03,
            low: 1.025,
            high: 1.035,
        };
        let clear = BootstrapMedianCi {
            median: 1.08,
            low: 1.06,
            high: 1.10,
        };
        assert!(!clears_twice_null_margin(too_close, kernel_null, fuse_null));
        assert!(clears_twice_null_margin(clear, kernel_null, fuse_null));
    }

    #[test]
    fn governor_warning_distinguishes_performance_from_dynamic_policy() {
        let mut policy = CpuFrequencyPolicy {
            drivers: BTreeMap::from([(0, "amd-pstate-epp".to_owned())]),
            governors: BTreeMap::from([(0, "performance".to_owned())]),
            energy_performance_preferences: BTreeMap::new(),
        };
        assert!(!policy.governor_warning());
        policy.governors.insert(1, "powersave".to_owned());
        assert!(policy.governor_warning());
    }

    #[test]
    fn crossover_null_cancels_fixed_physical_arm_bias() {
        let logical_a = [100, 120, 100, 120];
        let logical_b = [120, 100, 120, 100];
        let ratios = crossover_log_ratios(&logical_a, &logical_b).expect("crossover ratios");
        assert_eq!(ratios.len(), 1);
        assert!(ratios.iter().all(|ratio| ratio.abs() < 1e-12));
    }

    #[test]
    fn competitive_ratio_uses_both_aa_arms() {
        let samples = TimedSamples {
            values: BTreeMap::from([
                (Arm::KernelA, vec![10, 10, 10, 10]),
                (Arm::KernelB, vec![10, 10, 10, 10]),
                (Arm::FuseA, vec![40, 40, 40, 40]),
                (Arm::FuseB, vec![40, 40, 40, 40]),
            ]),
            physical_values: BTreeMap::new(),
            digests: BTreeMap::new(),
            observed_worker_threads: BTreeMap::new(),
            observed_worker_cpus: BTreeMap::new(),
            last_sequence: 0,
        };
        let ratios = competitive_log_ratios(&samples).expect("competitive ratios");
        assert!(ratios.iter().all(|ratio| (ratio.exp() - 4.0).abs() < 1e-12));
    }
}
