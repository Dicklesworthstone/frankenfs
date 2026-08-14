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
    Arc, Mutex,
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
    /// Busy-host mode: use the balanced crossover schedule and post-hoc A/A
    /// nulls instead of an unsatisfiable host-wide quiet precondition.
    BalancedSquare,
}

impl PlacementScope {
    const fn label(self) -> &'static str {
        match self {
            Self::SameLlc => "same_llc",
            Self::HostWide => "host_wide",
            Self::BalancedSquare => "balanced_square",
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
    /// Reusable root for the bulk scratch (arm images + fixture tree).
    ///
    /// Defaults to `<artifact_root>/scratch` and is CLEARED at the start of
    /// every run, so disk sits at one run's worth instead of growing 5-11 GiB
    /// per invocation (bd-v0igv). The per-run directory still holds the report.
    scratch_root: Option<PathBuf>,
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
    /// Optional FUSE request-dispatch worker count for the candidate daemon.
    ///
    /// Omitted preserves the banked serial dispatcher. When specified, the
    /// value is injected into both FUSE A/A arms, so the null gate still
    /// exercises exactly the candidate configuration being compared to Linux.
    fuse_workers: Option<usize>,
    /// Second candidate configuration mounted in the same window (bd-3tqgc).
    ///
    /// Omitted keeps the banked four-arm shape byte for byte. When present the
    /// harness mounts two more FUSE arms from the SAME ELF, differing only by
    /// the recorded runtime knobs, and reports a within-window paired
    /// candidate-vs-candidate ratio in which the window effect cancels the way
    /// the kernel arm already cancels host drift for `fuse_over_kernel`.
    candidate_comparison: Option<CandidateComparison>,
    placement_scope: PlacementScope,
    host_quiet_samples: usize,
    host_quiet_timeout_ms: u64,
    /// Machine that produced the driver ELF, and the one that produced the
    /// candidate ELF. `rch exec` has no artifact-retrieval mechanism, so both
    /// binaries are built on a remote worker and copied here; a binary of
    /// unknown origin is not evidence, so both are mandatory and recorded.
    harness_builder: String,
    candidate_builder: String,
    /// How the large fixture directory is constructed (bd-pb85e).
    ///
    /// Defaults to the only bankable form. `Baked` restores the pre-bd-plkzd
    /// unindexed construction so both can be measured in one window on one ELF,
    /// and forces `BLOCKED_UNFAIR_FIXTURE` so it can never be quoted as a row.
    fixture_construction: FixtureConstruction,
    output: Option<PathBuf>,
}

/// The second candidate configuration of a same-window A/B (bd-3tqgc).
///
/// It is deliberately expressed as a set of environment overrides rather than a
/// second binary: the whole point of the estimator is that both arms execute
/// ONE ELF, so the only admissible difference is a runtime knob the daemon
/// resolves and reports back.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct CandidateComparison {
    /// Extra environment applied only to the candidate-B daemons.
    env: Vec<(String, String)>,
}

impl CandidateComparison {
    /// Whether the two candidate configurations are meant to differ at all.
    ///
    /// Empty means the run is the estimator's own A/A null control: four FUSE
    /// arms with identical configuration, where the candidate-vs-candidate
    /// ratio must come out at 1.0 or the instrument is not trustworthy.
    fn configurations_differ(&self) -> bool {
        !self.env.is_empty()
    }

    fn env_json(&self) -> Value {
        Value::Object(
            self.env
                .iter()
                .map(|(key, value)| (key.clone(), json!(value)))
                .collect(),
        )
    }
}

impl Config {
    const fn client_threads(&self) -> usize {
        self.workload.client_threads(self.client_threads)
    }

    /// Where the bulk scratch lives: `--scratch-root` if given, else a fixed
    /// `scratch` directory beside the per-run report directories.
    fn scratch_root(&self) -> PathBuf {
        self.scratch_root
            .clone()
            .unwrap_or_else(|| self.artifact_root.join("scratch"))
    }

    const fn compares_candidates(&self) -> bool {
        self.candidate_comparison.is_some()
    }

    /// Whether the two candidate configurations are meant to differ.
    ///
    /// False for a four-arm run (there is only one candidate configuration) and
    /// for the estimator's A/A null control.
    fn candidate_configurations_differ(&self) -> bool {
        self.candidate_comparison
            .as_ref()
            .is_some_and(CandidateComparison::configurations_differ)
    }

    /// Environment applied to the daemons of a given arm.
    fn arm_env(&self, arm: Arm) -> &[(String, String)] {
        match (arm, self.candidate_comparison.as_ref()) {
            (Arm::CandidateBA | Arm::CandidateBB, Some(comparison)) => &comparison.env,
            _ => &[],
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ffs_cli: PathBuf::new(),
            artifact_root: PathBuf::from("/data/tmp/frankenfs-mounted-kernel"),
            scratch_root: None,
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
            fuse_workers: None,
            candidate_comparison: None,
            placement_scope: PlacementScope::SameLlc,
            host_quiet_samples: DEFAULT_HOST_QUIET_SAMPLES,
            host_quiet_timeout_ms: DEFAULT_HOST_QUIET_TIMEOUT_MS,
            harness_builder: String::new(),
            candidate_builder: String::new(),
            fixture_construction: FixtureConstruction::Seeded,
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
    /// First replica of the second candidate configuration (bd-3tqgc).
    CandidateBA,
    /// Second replica of the second candidate configuration (bd-3tqgc).
    CandidateBB,
}

impl Arm {
    const fn label(self) -> &'static str {
        match self {
            Self::KernelA => "kernel_a",
            Self::KernelB => "kernel_b",
            Self::FuseA => "fuse_a",
            Self::FuseB => "fuse_b",
            Self::CandidateBA => "fuse_candidate_b_a",
            Self::CandidateBB => "fuse_candidate_b_b",
        }
    }

    const fn crossover_peer(self) -> Self {
        match self {
            Self::KernelA => Self::KernelB,
            Self::KernelB => Self::KernelA,
            Self::FuseA => Self::FuseB,
            Self::FuseB => Self::FuseA,
            Self::CandidateBA => Self::CandidateBB,
            Self::CandidateBB => Self::CandidateBA,
        }
    }
}

const BALANCED_ORDERS: [[Arm; 4]; 4] = [
    [Arm::KernelA, Arm::FuseA, Arm::KernelB, Arm::FuseB],
    [Arm::FuseB, Arm::KernelB, Arm::FuseA, Arm::KernelA],
    [Arm::KernelB, Arm::FuseB, Arm::KernelA, Arm::FuseA],
    [Arm::FuseA, Arm::KernelA, Arm::FuseB, Arm::KernelB],
];

/// Six-arm schedule for a same-window candidate-vs-candidate comparison.
///
/// A Williams square over the six arms: every arm occupies every position
/// exactly once (so position bias cancels the way it does in the four-arm
/// schedule), and every ordered pair of arms is adjacent exactly once (so
/// first-order carryover between neighbouring arms cancels too). Both
/// properties are asserted in the unit tests rather than trusted.
///
/// Constructed from the zig-zag base row `0,1,5,2,4,3` cyclically shifted; its
/// adjacent index differences are `1,4,3,2,5`, all five non-zero residues, which
/// is exactly the Williams condition.
const CANDIDATE_BALANCED_ORDERS: [[Arm; 6]; 6] = [
    [
        Arm::KernelA,
        Arm::FuseA,
        Arm::CandidateBB,
        Arm::CandidateBA,
        Arm::FuseB,
        Arm::KernelB,
    ],
    [
        Arm::FuseA,
        Arm::CandidateBA,
        Arm::KernelA,
        Arm::KernelB,
        Arm::CandidateBB,
        Arm::FuseB,
    ],
    [
        Arm::CandidateBA,
        Arm::KernelB,
        Arm::FuseA,
        Arm::FuseB,
        Arm::KernelA,
        Arm::CandidateBB,
    ],
    [
        Arm::KernelB,
        Arm::FuseB,
        Arm::CandidateBA,
        Arm::CandidateBB,
        Arm::FuseA,
        Arm::KernelA,
    ],
    [
        Arm::FuseB,
        Arm::CandidateBB,
        Arm::KernelB,
        Arm::KernelA,
        Arm::CandidateBA,
        Arm::FuseA,
    ],
    [
        Arm::CandidateBB,
        Arm::KernelA,
        Arm::FuseB,
        Arm::FuseA,
        Arm::KernelB,
        Arm::CandidateBA,
    ],
];

/// Order in which the Williams rows are visited across one schedule period.
///
/// Deliberately not a plain repetition of `0..6`. [`physical_arm_for`]
/// exchanges physical roles on odd rounds, so with six rows each row would be
/// pinned to a fixed round parity: physical `kernel_a` would then only ever
/// occupy the positions where logical `kernel_a` sits on even rows or logical
/// `kernel_b` sits on odd rows — three of six positions, measured. The
/// schedule would still look balanced by logical arm while quietly favouring
/// one image. Rotating the row index on the second pass gives every row one
/// even and one odd round, so every physical arm reaches every position.
const CANDIDATE_ROW_SEQUENCE: [usize; 12] = [0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 0];

const FOUR_ARM_SET: [Arm; 4] = [Arm::KernelA, Arm::KernelB, Arm::FuseA, Arm::FuseB];
const SIX_ARM_SET: [Arm; 6] = [
    Arm::KernelA,
    Arm::KernelB,
    Arm::FuseA,
    Arm::FuseB,
    Arm::CandidateBA,
    Arm::CandidateBB,
];
const CANDIDATE_A_ARMS: [Arm; 2] = [Arm::FuseA, Arm::FuseB];
const CANDIDATE_B_ARMS: [Arm; 2] = [Arm::CandidateBA, Arm::CandidateBB];
const KERNEL_ARMS: [Arm; 2] = [Arm::KernelA, Arm::KernelB];
const BOTH_CANDIDATE_FUSE_ARMS: [Arm; 4] =
    [Arm::FuseA, Arm::FuseB, Arm::CandidateBA, Arm::CandidateBB];

/// Every mounted arm of a run, in a stable order.
const fn measured_arms(candidate_comparison: bool) -> &'static [Arm] {
    if candidate_comparison {
        &SIX_ARM_SET
    } else {
        &FOUR_ARM_SET
    }
}

/// The FUSE arms of a run: two daemons normally, four when a second candidate
/// configuration is mounted alongside the first.
const fn fuse_arms(candidate_comparison: bool) -> &'static [Arm] {
    if candidate_comparison {
        &BOTH_CANDIDATE_FUSE_ARMS
    } else {
        &CANDIDATE_A_ARMS
    }
}

/// Balanced visiting order for one measured round.
fn balanced_order(candidate_comparison: bool, round: usize) -> &'static [Arm] {
    if candidate_comparison {
        &CANDIDATE_BALANCED_ORDERS[CANDIDATE_ROW_SEQUENCE[round % CANDIDATE_ROW_SEQUENCE.len()]]
    } else {
        &BALANCED_ORDERS[round % BALANCED_ORDERS.len()]
    }
}

/// Rounds after which the balanced schedule repeats.
const fn balanced_order_count(candidate_comparison: bool) -> usize {
    if candidate_comparison {
        CANDIDATE_ROW_SEQUENCE.len()
    } else {
        BALANCED_ORDERS.len()
    }
}

/// Round count that completes both the balanced schedule and the estimator
/// blocks it is chunked into, so `--pairs` must be a multiple of it.
const fn schedule_period(candidate_comparison: bool) -> usize {
    let orders = balanced_order_count(candidate_comparison);
    let mut multiple = orders;
    while multiple % ESTIMATOR_BLOCK_ROUNDS != 0 {
        multiple += orders;
    }
    multiple
}

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

/// Everything a mounted FUSE daemon reports about itself at startup.
#[derive(Clone, Debug, Eq, PartialEq)]
struct FfsMountSelfReport {
    identity: FfsBinaryIdentity,
    /// Verbatim `mount_candidate_knobs,...` line: the effective values of the
    /// runtime knobs, resolved by the daemon through the functions its hot
    /// paths call rather than echoed back from its environment.
    runtime_knobs: String,
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
        /// Effective runtime knobs this daemon reported at startup.
        runtime_knobs: String,
        /// Environment this arm was launched with beyond the shared baseline.
        candidate_env: Vec<(String, String)>,
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
                runtime_knobs,
                candidate_env,
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
                object.insert(
                    "self_reported_runtime_knobs".to_owned(),
                    json!(runtime_knobs),
                );
                object.insert(
                    "candidate_env".to_owned(),
                    Value::Object(
                        candidate_env
                            .iter()
                            .map(|(key, value)| (key.clone(), json!(value)))
                            .collect(),
                    ),
                );
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
           --pairs N                      Paired rounds, multiple of 4 and >= 12 (default 32;\n\
                                          with a candidate comparison the schedule period is\n\
                                          12, so pairs must be a multiple of 12, default 36)\n\
           --candidate-b-env K=V          Mount two MORE FUSE arms from the same ELF with this\n\
                                          extra environment, and report a within-window paired\n\
                                          candidate-vs-candidate ratio (repeatable; keys must\n\
                                          start with FFS_)\n\
           --candidate-aa                 Same six-arm shape with IDENTICAL candidate\n\
                                          configurations: the estimator's own A/A null control\n\
           --operations N                 Workload operations per observation (default 2000)\n\
           --client-threads N             Actual parallel-metadata worker threads (default 8)\n\
           --fuse-cpus N                  CPUs pinned to the FrankenFS daemon (default 1;\n\
                                          every banked row was taken at 1, and the kernel\n\
                                          arm runs its filesystem on all client CPUs)\n\
           --fuse-workers N               FUSE request-dispatch workers for both FUSE A/A arms\n\
                                          (default serial dispatcher; 0 selects serial explicitly)\n\
           --placement-scope SCOPE        same-llc | host-wide | balanced-square (default same-llc)\n\
           --fixture-construction MODE    seeded | baked (default seeded). `baked` restores the\n\
                                          pre-bd-plkzd unindexed fixture for ATTRIBUTION ONLY and\n\
                                          FORCES the BLOCKED_UNFAIR_FIXTURE verdict (bd-pb85e)\n\
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

/// How the two ELFs under measurement reached the host that executed them.
///
/// `rch exec` has no artifact-retrieval mechanism, so an ELF built on a remote
/// worker has to be copied here — that is the usual case and it used to be the
/// only one the report could express, as a hardcoded string. A build that runs
/// ON the executing host is equally legitimate (the mounted run is local-only
/// anyway), and a report that claims it was copied from a worker records a
/// provenance that did not happen. A false provenance line is worse than a
/// coarse one: it is the field a later reader uses to decide whether two rows
/// share a binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetrievalProvenance {
    /// Both ELFs were built somewhere else and copied here.
    ScpFromBuilder,
    /// Both ELFs were built on the machine that ran the measurement.
    BuiltInPlace,
    /// One of each — recorded distinctly rather than rounded to either.
    Mixed,
}

impl RetrievalProvenance {
    /// Classify by comparing each builder name against the executing host.
    fn classify(harness_builder: &str, candidate_builder: &str, executing_host: &str) -> Self {
        let local = |builder: &str| builder.trim().eq_ignore_ascii_case(executing_host.trim());
        match (local(harness_builder), local(candidate_builder)) {
            (true, true) => Self::BuiltInPlace,
            (false, false) => Self::ScpFromBuilder,
            _ => Self::Mixed,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::ScpFromBuilder => "scp_from_rch_worker",
            Self::BuiltInPlace => "built_in_place_on_executing_host",
            Self::Mixed => "mixed_scp_from_rch_worker_and_built_in_place",
        }
    }

    const fn note(self) -> &'static str {
        match self {
            Self::ScpFromBuilder => {
                "rch exec has no artifact-retrieval mechanism; both ELFs are built on a remote \
                 worker and copied to the executing host"
            }
            Self::BuiltInPlace => {
                "both ELFs were built on the machine that executed the measurement; nothing was \
                 copied in"
            }
            Self::Mixed => {
                "one ELF was built on the executing host and the other on a remote worker and \
                 copied in; compare the per-ELF builder fields, not this summary"
            }
        }
    }
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
        "balanced-square" => Ok(PlacementScope::BalancedSquare),
        _ => bail!("unsupported --placement-scope {value}; expected same-llc|host-wide|balanced-square"),
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
    let period = schedule_period(config.compares_candidates());
    ensure!(
        config.pairs >= 12 && config.pairs % period == 0,
        "--pairs must be a multiple of {period} and at least 12"
    );
    if let Some(comparison) = &config.candidate_comparison {
        let mut keys = BTreeSet::new();
        for (key, _) in &comparison.env {
            ensure!(
                key.starts_with("FFS_"),
                "--candidate-b-env key {key} must start with FFS_: the two candidate arms differ \
                 by a FrankenFS runtime knob on one ELF, not by their process environment at large"
            );
            ensure!(
                keys.insert(key.clone()),
                "--candidate-b-env {key} was given more than once"
            );
        }
    }
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
        config
            .fuse_workers
            .is_none_or(|workers| workers <= MAX_CLIENT_THREADS),
        "--fuse-workers must be in 0..={MAX_CLIENT_THREADS}"
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
    parse_config_args(&args)
}

fn parse_candidate_env_assignment(value: &str) -> Result<(String, String)> {
    let (key, assigned) = value
        .split_once('=')
        .ok_or_else(|| anyhow!("--candidate-b-env expects KEY=VALUE, got {value}"))?;
    ensure!(
        !key.is_empty(),
        "--candidate-b-env expects a non-empty key, got {value}"
    );
    Ok((key.to_owned(), assigned.to_owned()))
}

fn parse_config_args(args: &[String]) -> Result<Option<Config>> {
    let mut config = Config::default();
    let mut pairs_explicit = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" => {
                usage();
                return Ok(None);
            }
            "--ffs-cli" => {
                config.ffs_cli = parse_value::<PathBuf>(args, &mut index, "--ffs-cli")?;
            }
            "--artifact-root" => {
                config.artifact_root = parse_value::<PathBuf>(args, &mut index, "--artifact-root")?;
            }
            "--scratch-root" => {
                config.scratch_root =
                    Some(parse_value::<PathBuf>(args, &mut index, "--scratch-root")?);
            }
            "--filesystem" => {
                let value = parse_value::<String>(args, &mut index, "--filesystem")?;
                config.filesystems = match value.as_str() {
                    "ext4" => RequestedFilesystems::Ext4,
                    "btrfs" => RequestedFilesystems::Btrfs,
                    "both" => RequestedFilesystems::Both,
                    _ => bail!("unsupported --filesystem {value}; expected ext4|btrfs|both"),
                };
            }
            "--workload" => {
                let value = parse_value::<String>(args, &mut index, "--workload")?;
                config.workload = parse_workload(&value)?;
            }
            "--pairs" => {
                config.pairs = parse_value(args, &mut index, "--pairs")?;
                pairs_explicit = true;
            }
            "--candidate-b-env" => {
                let value = parse_value::<String>(args, &mut index, "--candidate-b-env")?;
                config
                    .candidate_comparison
                    .get_or_insert_with(CandidateComparison::default)
                    .env
                    .push(parse_candidate_env_assignment(&value)?);
            }
            "--candidate-aa" => {
                config
                    .candidate_comparison
                    .get_or_insert_with(CandidateComparison::default);
            }
            "--operations" => {
                config.operations = parse_value(args, &mut index, "--operations")?;
            }
            "--fuse-cpus" => {
                config.fuse_cpu_count = parse_value(args, &mut index, "--fuse-cpus")?;
            }
            "--fuse-workers" => {
                config.fuse_workers = Some(parse_value(args, &mut index, "--fuse-workers")?);
            }
            "--client-threads" => {
                config.client_threads = parse_value(args, &mut index, "--client-threads")?;
            }
            "--fixture-construction" => {
                let value = parse_value::<String>(args, &mut index, "--fixture-construction")?;
                config.fixture_construction = parse_fixture_construction(&value)?;
            }
            "--placement-scope" => {
                let value = parse_value::<String>(args, &mut index, "--placement-scope")?;
                config.placement_scope = parse_placement_scope(&value)?;
            }
            "--observation-repeats" => {
                config.observation_repeats =
                    parse_value(args, &mut index, "--observation-repeats")?;
            }
            "--image-size-mib" => {
                config.image_size_mib = parse_value(args, &mut index, "--image-size-mib")?;
            }
            "--maximum-null-ratio" => {
                config.maximum_null_ratio = parse_value(args, &mut index, "--maximum-null-ratio")?;
            }
            "--arm-settle-ms" => {
                config.arm_settle_ms = parse_value(args, &mut index, "--arm-settle-ms")?;
            }
            "--pre-measurement-settle-ms" => {
                config.pre_measurement_settle_ms =
                    parse_value(args, &mut index, "--pre-measurement-settle-ms")?;
            }
            "--harness-builder" => {
                config.harness_builder = parse_value(args, &mut index, "--harness-builder")?;
            }
            "--candidate-builder" => {
                config.candidate_builder = parse_value(args, &mut index, "--candidate-builder")?;
            }
            "--host-quiet-samples" => {
                config.host_quiet_samples = parse_value(args, &mut index, "--host-quiet-samples")?;
            }
            "--host-quiet-timeout-ms" => {
                config.host_quiet_timeout_ms =
                    parse_value(args, &mut index, "--host-quiet-timeout-ms")?;
            }
            "--out" => config.output = Some(parse_value(args, &mut index, "--out")?),
            other => bail!("unknown argument: {other}"),
        }
        index += 1;
    }

    // The six-arm schedule only closes on a multiple of 12 rounds, so the
    // four-arm default of 32 is not expressible there. Take the smallest legal
    // count above it rather than silently running an unbalanced schedule.
    if config.compares_candidates() && !pairs_explicit {
        config.pairs = 36;
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
    optional_prefixed_line(content, prefix, label)?
        .ok_or_else(|| anyhow!("{label} was not reported"))
}

/// A line the log is allowed to omit, but never allowed to make ambiguous.
///
/// Absence is a fact about the emitting binary that a caller may legitimately
/// tolerate. Two disagreeing lines is a broken log, and silently picking one of
/// them would be inventing an observation, so that stays an error either way.
fn optional_prefixed_line<'a>(
    content: &'a str,
    prefix: &str,
    label: &str,
) -> Result<Option<&'a str>> {
    let mut matches = content
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .map(str::trim);
    let Some(value) = matches.next() else {
        return Ok(None);
    };
    ensure!(
        matches.next().is_none(),
        "{label} was reported more than once"
    );
    Ok(Some(value))
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
            // EMPTY on purpose (bd-c5210), for exactly the reason `large-directory`
            // below is. Baking the 256 files in here means `mke2fs -d` writes them
            // into linear directory blocks and never builds the htree — measured:
            // the same 256 `read-%06d.bin` entries come back "Not a hash-indexed
            // directory" when baked and "Hash Version: 1" when created through a
            // mount, at 8192 bytes, i.e. two blocks and past the threshold where a
            // real ext4 indexes. btrfs has no analogue, so the two arms were again
            // built by mechanisms with different indexing outcomes. This matters
            // inside the timed region: `parallel_read_batch` starts its clock, then
            // does one `File::open` per file — 256 path lookups measured.
            //
            // Caller-owned for the same reason as `large-directory`: a fresh mkfs
            // root is uid 0 and `mke2fs -d` preserves the host tree's ownership, so
            // creating it here as the caller is what lets the seeding step write
            // into it without running as root.
            let parent = root.join("parallel-read");
            fs::create_dir(&parent).with_context(|| format!("create {}", parent.display()))?;
            bake_fixture_entries_if_requested(config, SeededFixture::ParallelRead, &parent)?;
        }
        Workload::CreateDeleteStorm => {
            let path = root.join("create-delete-storm");
            fs::create_dir(&path).with_context(|| format!("create {}", path.display()))?;
        }
        Workload::ReaddirStat8 => {
            // EMPTY on purpose (bd-plkzd). Populating it here means the entries
            // are baked in by `mke2fs -d`, which writes linear directory blocks
            // and never builds the htree — measured: `debugfs htree_dump` on a
            // 32,768-entry fixture built that way reports "Not a hash-indexed
            // directory" even though `dir_index` is in the feature set. Every
            // lookup in the ext4 arm then degrades to an O(N) scan, so the sweep
            // is O(N^2) and the row describes a directory shape no real ext4
            // filesystem has. btrfs has no analogue (DIR_ITEM/DIR_INDEX are
            // inherent to the format), so the two arms were not the same
            // filesystem shape.
            //
            // The entries are created through a kernel mount instead, by
            // `seed_readdir_fixture_through_mount`, before the base image is
            // cloned to the arms. The directory must be caller-owned — a fresh
            // mkfs root is uid 0, and `mke2fs -d` preserves the host tree's
            // ownership, so creating it here as the caller is what lets the
            // seeding step write into it without running as root.
            let parent = root.join("large-directory");
            fs::create_dir(&parent).with_context(|| format!("create {}", parent.display()))?;
            bake_fixture_entries_if_requested(config, SeededFixture::LargeDirectory, &parent)?;
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

/// Populate a fixture directory in the HOST tree under `--fixture-construction
/// baked`, so `mke2fs -d` writes the entries into the base image (bd-pb85e).
///
/// Under the default `seeded` this is a no-op and the directory is left empty for
/// `seed_fixture_through_mount`, exactly as bd-plkzd left it. The entries are
/// produced by `SeededFixture::create_entry` — the SAME code the seeded path uses
/// — so the two constructions differ in mechanism and in nothing else. That is
/// what makes the A/B an attribution rather than another confounded comparison:
/// same names, same bytes, same count, same everything except who wrote them.
fn bake_fixture_entries_if_requested(
    config: &Config,
    fixture: SeededFixture,
    parent: &Path,
) -> Result<()> {
    if config.fixture_construction != FixtureConstruction::Baked {
        return Ok(());
    }
    for index in 0..config.operations {
        fixture.create_entry(parent, index)?;
    }
    Ok(())
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
    // Images are deterministic intermediates rebuilt on every invocation. Keep
    // one reusable image directory beside the per-run report directory so
    // repeated comparator runs cannot grow scratch space without bound
    // (bd-v0igv). Concurrent runs are unsupported by the host-quiet gate.
    let image_dir = scratch_image_dir(run_dir)?;
    fs::create_dir_all(&image_dir)
        .with_context(|| format!("create image directory {}", image_dir.display()))?;
    let image = image_dir.join(format!("{}.base.img", kind.label()));
    create_sized_file(&image, config.image_size_mib)?;
    match kind {
        FilesystemKind::Ext4 => {
            let mut command = Command::new("mke2fs");
            command.args(["-t", "ext4", "-F", "-q", "-b", "4096"]);
            if config.workload == Workload::ParallelMetadataWrite
                || SeededFixture::for_workload(config.workload).is_some()
            {
                // A 2 GiB sweep image must retain enough inodes for
                // (warmup + measured rounds) * operations unique creates.
                //
                // The seeded workloads need this for a reason bd-plkzd introduced
                // and bd-c5210 inherited: their entries are now created AFTER
                // mkfs, through a mount, so mke2fs sizes the inode table from its
                // default ratio (one inode per 16 KiB) with no idea how many files
                // are coming. A 32,768-entry readdir-stat run on the 256 MiB
                // default image gets ~16k inodes and dies MID-SEED with ENOSPC,
                // after the mkfs and the mount — the most expensive place to fail.
                // Before bd-plkzd, `mke2fs -d` saw the populated tree and sized or
                // refused up front, so the failure mode did not exist.
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

/// Whether `debugfs htree_dump` output describes a hash-indexed directory.
///
/// Split out from the command invocation so the decision is unit-testable
/// without root, a loop device, or e2fsprogs. debugfs prints its banner to the
/// same stream, and reports a plain `htree_dump: Not a hash-indexed directory`
/// for a linear one, so presence of the root-node `Hash Version` line is the
/// discriminator (bd-plkzd).
fn htree_dump_reports_indexed(output: &str) -> bool {
    output.lines().any(|line| line.contains("Hash Version"))
}

/// The block size `create_base_image` formats ext4 with. An ext4 directory only
/// converts to an htree once it outgrows a single block, so this is also the
/// threshold below which "not indexed" is the CORRECT state, not a defect.
const EXT4_FIXTURE_BLOCK_BYTES: u64 = 4096;

/// Directory byte size from `debugfs stat`, used to decide whether an htree is
/// expected at all.
fn debugfs_directory_size(image: &Path, dir: &str) -> Result<u64> {
    let output = Command::new("debugfs")
        .arg("-R")
        .arg(format!("stat /{dir}"))
        .arg(image)
        .output()
        .with_context(|| format!("run debugfs stat /{dir} on {}", image.display()))?;
    let combined = String::from_utf8_lossy(&output.stdout);
    combined
        .split_whitespace()
        .skip_while(|token| !token.starts_with("Size:"))
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| anyhow!("debugfs stat /{dir} reported no parsable Size:\n{combined}"))
}

/// Fail closed unless an ext4 fixture directory that is BIG ENOUGH TO BE INDEXED
/// genuinely is (bd-plkzd, generalized for bd-c5210).
///
/// `dir_index` in the superblock feature set only says the filesystem MAY have
/// htrees; it says nothing about whether this directory got one. Asserting the
/// directory itself is the whole point: the fixture defect this guards against
/// was invisible for exactly as long as nobody looked past the feature flag.
///
/// The size precondition is not a loophole, it is the control's correctness. ext4
/// converts a directory to an htree only once it outgrows one block, so a small
/// directory is legitimately unindexed and a real ext4 would leave it that way —
/// measured: a 3-entry directory comes back "Not a hash-indexed directory" whether
/// it was baked by `mke2fs -d` or created through a mount, while a 256-entry one
/// (8192 bytes, two blocks) differs between them. Asserting unconditionally would
/// fail a legitimately small `--operations` run; asserting only above one block
/// makes the check track the actual ext4 rule.
fn ensure_ext4_directory_is_htree_indexed(image: &Path, dir: &str) -> Result<()> {
    let size = debugfs_directory_size(image, dir)?;
    if size <= EXT4_FIXTURE_BLOCK_BYTES {
        // Fits in one block: ext4 would not index it either. Say so out loud, so a
        // silently-skipped control is never mistaken for a passing one.
        eprintln!(
            "note: ext4 /{dir} is {size} bytes (<= one {EXT4_FIXTURE_BLOCK_BYTES}-byte block), \
             so no htree is expected and none is required; the index control does not apply \
             at this --operations count"
        );
        return Ok(());
    }
    let output = Command::new("debugfs")
        .arg("-R")
        .arg(format!("htree_dump /{dir}"))
        .arg(image)
        .output()
        .with_context(|| format!("run debugfs htree_dump on {}", image.display()))?;
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    ensure!(
        htree_dump_reports_indexed(&combined),
        "ext4 /{dir} is {size} bytes — past the one-block threshold, so a real ext4 would \
         have built an htree — but it is NOT hash-indexed, so every lookup is an O(N) scan \
         and this row would describe a directory shape no real ext4 filesystem has \
         (bd-plkzd / bd-c5210). debugfs said:\n{combined}"
    );
    Ok(())
}

/// A fixture directory whose entries must be created THROUGH a mount rather than
/// baked in with `mke2fs -d`, because `mke2fs -d` writes linear directory blocks
/// and never builds ext4's htree (bd-plkzd for readdir+stat, bd-c5210 for
/// parallel read).
/// How a large fixture directory's entries are put into the base image.
///
/// This exists to ATTRIBUTE a measurement, not to offer a choice (bd-pb85e).
/// bd-plkzd replaced the baked construction with through-mount seeding because
/// `mke2fs -d` writes linear directory blocks and never builds ext4's htree, and
/// the ext4 readdir+stat row moved ~18% IN FRANKENFS'S FAVOUR across that change.
/// Four things moved at once (fixture, candidate ELF, PGO profile, kernel), so no
/// one can say how much of the 18% the fixture was — and a movement in our own
/// favour is exactly the kind that must not be banked on a confounded comparison.
///
/// Restoring the baked path lets both constructions run in ONE window on ONE ELF,
/// which removes every confounder except the fixture. That is the entire purpose.
///
/// ⛔ `Baked` is KNOWN-UNFAIR and can never produce a bankable row: it is exactly
/// the defect bd-plkzd fixed. The harness therefore fails closed — a baked run is
/// forced to the `BLOCKED_UNFAIR_FIXTURE` verdict regardless of how the numbers
/// come out, so it can be read for attribution and never quoted as a scorecard
/// row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum FixtureConstruction {
    /// Entries created through a kernel mount of the base image, so each
    /// filesystem builds its own native directory index. The only bankable form.
    #[default]
    Seeded,
    /// Entries baked into the host tree so `mke2fs -d` writes them — the
    /// pre-bd-plkzd construction. Measurement-only, never bankable.
    Baked,
}

impl FixtureConstruction {
    const fn label(self) -> &'static str {
        match self {
            Self::Seeded => "seeded",
            Self::Baked => "baked",
        }
    }

    const fn is_bankable(self) -> bool {
        matches!(self, Self::Seeded)
    }

    const fn bankability_reason(self) -> &'static str {
        match self {
            Self::Seeded => "seeded_through_mount",
            Self::Baked => "baked_with_mke2fs_d_known_unfair",
        }
    }
}

fn parse_fixture_construction(value: &str) -> Result<FixtureConstruction> {
    match value {
        "seeded" => Ok(FixtureConstruction::Seeded),
        "baked" => Ok(FixtureConstruction::Baked),
        other => bail!(
            "--fixture-construction must be `seeded` or `baked`, got `{other}`. \
             `baked` restores the pre-bd-plkzd unindexed fixture for ATTRIBUTION ONLY \
             (bd-pb85e) and forces the BLOCKED_UNFAIR_FIXTURE verdict."
        ),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SeededFixture {
    /// `large-directory`: `operations` empty entries (bd-plkzd).
    LargeDirectory,
    /// `parallel-read`: `operations` files of `PARALLEL_READ_FILE_BYTES` carrying
    /// the SAME deterministic per-index payload `write_fixture_file` baked in
    /// before (bd-c5210). The bytes are load-bearing, not incidental —
    /// `parallel_read_batch` folds them into a content digest that four-arm parity
    /// compares, so any change here shows up as a parity failure, not a silent
    /// drift.
    ParallelRead,
}

impl SeededFixture {
    const fn for_workload(workload: Workload) -> Option<Self> {
        match workload {
            Workload::ReaddirStat8 => Some(Self::LargeDirectory),
            Workload::ParallelRead8 | Workload::ParallelRead8ColdCache => Some(Self::ParallelRead),
            _ => None,
        }
    }

    const fn dir_name(self) -> &'static str {
        match self {
            Self::LargeDirectory => "large-directory",
            Self::ParallelRead => "parallel-read",
        }
    }

    fn create_entry(self, parent: &Path, index: usize) -> Result<()> {
        match self {
            Self::LargeDirectory => File::create(parent.join(format!("entry-{index:08}")))
                .map(drop)
                .with_context(|| format!("create large-directory entry {index} through the mount")),
            Self::ParallelRead => write_fixture_file(
                &parent.join(format!("read-{index:06}.bin")),
                PARALLEL_READ_FILE_BYTES,
                index,
            )
            .with_context(|| format!("create parallel-read file {index} through the mount")),
        }
    }
}

/// Create a fixture directory's entries THROUGH a kernel mount of the base image,
/// so each filesystem builds its own native directory index (bd-plkzd, bd-c5210).
///
/// Seeding through the KERNEL rather than through FrankenFS is deliberate: the
/// incumbent is the reference implementation of the on-disk layout, and it keeps
/// the candidate out of fixture construction entirely — otherwise a FrankenFS
/// write defect could shape the very fixture the FrankenFS read arm is then
/// measured on. Runs on the base image BEFORE it is cloned to the arms, so all
/// four arms still measure a byte-identical filesystem.
fn seed_fixture_through_mount(
    kind: FilesystemKind,
    image: &Path,
    fixture: SeededFixture,
    operations: usize,
    interrupted: &AtomicBool,
) -> Result<()> {
    let mount_dir = image
        .parent()
        .ok_or_else(|| anyhow!("base image {} has no parent", image.display()))?
        .join("seed-mnt");
    fs::create_dir(&mount_dir)
        .with_context(|| format!("create seed mountpoint {}", mount_dir.display()))?;

    let options = match kind {
        FilesystemKind::Ext4 => "loop,rw,noatime,nodev,nosuid,data=ordered",
        FilesystemKind::Btrfs => "loop,rw,noatime,nodev,nosuid",
    };
    run_checked(
        Command::new("sudo")
            .args(["-n", "mount", "-t", kind.label(), "-o", options])
            .arg(image)
            .arg(&mount_dir),
        &format!(
            "mount {} to seed the {} fixture",
            kind.label(),
            fixture.dir_name()
        ),
    )?;
    wait_for_mount(&mount_dir, None, interrupted)?;

    let parent = mount_dir.join(fixture.dir_name());
    let seed_result = (0..operations).try_for_each(|index| fixture.create_entry(&parent, index));

    // Unmount before reporting a seeding failure, or the loop device leaks and
    // every later arm inherits a broken scratch dir.
    let synced = seed_result.and_then(|()| {
        run_checked(
            &mut Command::new("sync"),
            "sync after seeding the fixture directory",
        )
    });
    let unmounted = run_checked(
        Command::new("sudo").args(["-n", "umount"]).arg(&mount_dir),
        "unmount fixture seed mount",
    );
    synced?;
    unmounted?;

    Ok(())
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
    arms: &[Arm],
) -> Result<BTreeMap<Arm, PathBuf>> {
    let expected_sha = file_sha256(base)?;
    let image_dir = scratch_image_dir(run_dir)?;
    fs::create_dir_all(&image_dir)
        .with_context(|| format!("create image directory {}", image_dir.display()))?;
    let mut images = BTreeMap::new();
    for &arm in arms {
        let path = image_dir.join(format!("{}.{}.img", kind.label(), arm.label()));
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

fn scratch_image_dir(run_dir: &Path) -> Result<PathBuf> {
    run_dir
        .parent()
        .map(|parent| parent.join("images"))
        .ok_or_else(|| anyhow!("artifact run directory has no scratch parent"))
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

/// What a daemon that never reported its effective knobs is recorded as.
///
/// Never an empty string and never a plausible-looking knob list: a reader must
/// be able to tell "this ELF predates knob self-reporting" from "these were the
/// knobs", because the second would be a fabricated observation.
const UNREPORTED_RUNTIME_KNOBS: &str = "unreported_by_this_elf";

fn parse_mount_self_report(log_path: &Path, knobs_required: bool) -> Result<FfsMountSelfReport> {
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
    // A daemon that cannot report which knob values it actually resolved must
    // never be an arm of a candidate-vs-candidate comparison: an ELF too old to
    // emit the line is exactly the bd-d9378 failure this evidence exists to
    // catch, where the requested override reached nothing the ELF reads. A
    // single-configuration run has no divergence to prove, so it may mount such
    // an ELF — the only way a historical build can be re-measured at all — and
    // records the absence instead of a knob list.
    let runtime_knobs = match optional_prefixed_line(
        &content,
        "mount_candidate_knobs,",
        "FUSE mount effective runtime knobs",
    )? {
        Some(knobs) => knobs.to_owned(),
        None => {
            ensure!(
                !knobs_required,
                "FUSE mount effective runtime knobs was not reported: this ELF predates knob \
                 self-reporting, so it cannot be an arm of a candidate-vs-candidate comparison"
            );
            UNREPORTED_RUNTIME_KNOBS.to_owned()
        }
    };
    Ok(FfsMountSelfReport {
        identity: FfsBinaryIdentity {
            binary_sha256,
            pgo_profile_sha256,
        },
        runtime_knobs,
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
    let candidate_env = config.arm_env(arm).to_vec();
    let mut command = Command::new("taskset");
    command
        .args(["-c", &cpu_list])
        .arg(&config.ffs_cli)
        .arg("mount");
    apply_fuse_dispatch_workers(&mut command, config.fuse_workers);
    for (key, value) in &candidate_env {
        command.env(key, value);
    }
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
            runtime_knobs: String::new(),
            candidate_env,
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
    let self_report = parse_mount_self_report(&stderr_log, config.compares_candidates())?;
    let proc_exe_sha256 = file_sha256(&PathBuf::from(format!("/proc/{child_id}/exe")))
        .with_context(|| format!("hash mapped FUSE executable for pid {child_id}"))?;
    ensure!(
        self_report.identity.binary_sha256 == proc_exe_sha256,
        "{} self-reported ELF differs from /proc/{child_id}/exe",
        arm.label(),
    );
    ensure!(
        &self_report.identity == expected_identity,
        "{} runtime daemon identity differs from the v3+PGO preflight",
        arm.label()
    );
    let MountedArmKind::Fuse {
        self_reported_sha256: reported,
        proc_exe_sha256: mapped,
        pgo_profile_sha256: pgo,
        runtime_knobs: knobs,
        ..
    } = &mut mounted.kind
    else {
        unreachable!("constructed FUSE mount");
    };
    *reported = self_report.identity.binary_sha256;
    *mapped = proc_exe_sha256;
    *pgo = self_report.identity.pgo_profile_sha256;
    *knobs = self_report.runtime_knobs;
    Ok(mounted)
}

/// Proof that the two candidate configurations are what the run claims.
///
/// The estimator's whole value comes from both arms executing one ELF and
/// differing only by a runtime knob. Two ways that can silently fail: the
/// replicas of one configuration disagree with each other (then the "A/A" null
/// is not a null), or the two configurations agree (then a supposed A/B is
/// measuring nothing — the bd-d9378 failure, where the ELF predated the flag
/// and ignored it). Both are checked against what the daemons resolved, not
/// against what the harness intended.
fn candidate_knob_divergence(
    mounts: &[MountedArm],
    configurations_differ: bool,
) -> Result<(String, String)> {
    let knobs_for = |arms: &[Arm], label: &str| -> Result<String> {
        let reported: BTreeSet<String> = mounts
            .iter()
            .filter(|mount| arms.contains(&mount.arm))
            .filter_map(|mount| match &mount.kind {
                MountedArmKind::Fuse { runtime_knobs, .. } => Some(runtime_knobs.clone()),
                MountedArmKind::Kernel => None,
            })
            .collect();
        ensure!(
            reported.len() == 1,
            "candidate {label} replicas reported different effective runtime knobs: {reported:?}"
        );
        reported
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("candidate {label} reported no runtime knobs"))
    };
    let candidate_a = knobs_for(&CANDIDATE_A_ARMS, "A")?;
    let candidate_b = knobs_for(&CANDIDATE_B_ARMS, "B")?;
    if configurations_differ {
        ensure!(
            candidate_a != candidate_b,
            "the two candidate configurations resolved IDENTICAL runtime knobs ({candidate_a}); \
             the requested override never reached a knob this ELF reads, so the run would compare \
             a configuration against itself"
        );
    } else {
        ensure!(
            candidate_a == candidate_b,
            "the candidate A/A null control resolved DIFFERENT runtime knobs: {candidate_a} vs \
             {candidate_b}"
        );
    }
    Ok((candidate_a, candidate_b))
}

fn apply_fuse_dispatch_workers(command: &mut Command, fuse_workers: Option<usize>) {
    if let Some(fuse_workers) = fuse_workers {
        command.env("FFS_FUSE_WORKERS", fuse_workers.to_string());
    }
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

fn assert_independent_arms(mounts: &[MountedArm], expected_fuse_arms: usize) -> Result<()> {
    let expected = 2 + expected_fuse_arms;
    ensure!(
        mounts.len() == expected,
        "independence proof requires {expected} mounts, found {}",
        mounts.len()
    );
    let images: BTreeSet<PathBuf> = mounts.iter().map(|mount| mount.image.clone()).collect();
    let mountpoints: BTreeSet<PathBuf> = mounts
        .iter()
        .map(|mount| mount.mountpoint.clone())
        .collect();
    ensure!(
        images.len() == expected && mountpoints.len() == expected,
        "mounted arms do not own {expected} distinct images and mountpoints"
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
        fuse_devices.len() == expected_fuse_arms && fuse_pids.len() == expected_fuse_arms,
        "FUSE arms share a mount device or daemon process"
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
        for &logical_arm in balanced_order(config.compares_candidates(), round) {
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
    let arms = measured_arms(config.compares_candidates());
    let mut next_sequences: BTreeMap<Arm, usize> = arms.iter().map(|&arm| (arm, 0_usize)).collect();
    run_warmup_rounds(roots, config, pinning, &mut next_sequences)?;

    let mut values: BTreeMap<Arm, Vec<u64>> = arms
        .iter()
        .map(|&arm| (arm, Vec::with_capacity(config.pairs)))
        .collect();
    let mut physical_values: BTreeMap<Arm, Vec<u64>> = arms
        .iter()
        .map(|&arm| (arm, Vec::with_capacity(config.pairs)))
        .collect();
    let mut digests = BTreeMap::new();
    let mut observed_worker_threads: BTreeMap<Arm, BTreeSet<usize>> =
        arms.iter().map(|&arm| (arm, BTreeSet::new())).collect();
    let mut observed_worker_cpus: BTreeMap<Arm, BTreeSet<usize>> =
        arms.iter().map(|&arm| (arm, BTreeSet::new())).collect();
    for round in 0..config.pairs {
        ensure!(
            !interrupted.load(Ordering::Relaxed),
            "interrupted during timed workload"
        );
        for &logical_arm in balanced_order(config.compares_candidates(), round) {
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
    arms: &[Arm],
) -> bool {
    let expected = BTreeSet::from([requested]);
    arms.iter()
        .all(|arm| observed_by_arm.get(arm) == Some(&expected))
}

/// Every arm's timed threads must have run on exactly the bound CPU set.
///
/// A thread that reported any other CPU means the single-CPU binding did not
/// hold, which is the variance source the A/A nulls are sensitive to, so the
/// run is not admissible.
fn worker_cpu_pinning_is_clear(
    observed_by_arm: &BTreeMap<Arm, BTreeSet<usize>>,
    expected: &BTreeSet<usize>,
    arms: &[Arm],
) -> bool {
    arms.iter()
        .all(|arm| observed_by_arm.get(arm) == Some(expected))
}

/// Gate for the candidate-vs-candidate estimator itself.
///
/// When the two candidate configurations are deliberately identical, the
/// cross-pair ratio is a null and has to land at 1.0 within the same bar every
/// other A/A null clears — that null is what makes any later
/// candidate-vs-candidate number worth reading. When they differ the ratio is
/// the estimate, not a null, and this is vacuously true.
fn candidate_cross_null_is_clear(
    configurations_differ: bool,
    ratio: Option<BootstrapMedianCi>,
    maximum_null_ratio: f64,
) -> bool {
    if configurations_differ {
        return true;
    }
    match ratio {
        Some(ratio) => null_control_is_clear(ratio, maximum_null_ratio),
        None => true,
    }
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

/// Within-window paired log ratio between two A/A arm pairs.
///
/// Each round contributes the difference of the two pairs' mean log wall time,
/// so anything common to the whole round — host drift, thermal state, whatever
/// else moved between windows — cancels before the ratio is formed. Blocks of
/// [`ESTIMATOR_BLOCK_ROUNDS`] rounds are then averaged so one bootstrap sample
/// is a complete balanced crossover block.
///
/// `fuse_over_kernel` uses it with the FUSE and kernel pairs; a
/// candidate-vs-candidate comparison uses it with the two candidate pairs, and
/// gets exactly the same cancellation for free. That is the whole point of
/// bd-3tqgc: the arms it compares ran in the SAME window, so the 4.71%
/// cross-window spread that swamped every remaining metadata lever never
/// enters the estimate.
fn paired_group_log_ratios(
    samples: &TimedSamples,
    numerator: [Arm; 2],
    denominator: [Arm; 2],
) -> Result<Vec<f64>> {
    let series = |arm: Arm| -> Result<&Vec<u64>> {
        samples
            .values
            .get(&arm)
            .ok_or_else(|| anyhow!("missing timed samples for {}", arm.label()))
    };
    let numerator_left = series(numerator[0])?;
    let numerator_right = series(numerator[1])?;
    let denominator_left = series(denominator[0])?;
    let denominator_right = series(denominator[1])?;
    ensure!(
        numerator_left.len() == numerator_right.len()
            && numerator_left.len() == denominator_left.len()
            && numerator_left.len() == denominator_right.len(),
        "paired arms must have equal sample counts"
    );
    ensure!(
        !numerator_left.is_empty() && numerator_left.len() % ESTIMATOR_BLOCK_ROUNDS == 0,
        "paired arms must contain complete crossover blocks"
    );
    let per_round = numerator_left
        .iter()
        .zip(numerator_right)
        .zip(denominator_left.iter().zip(denominator_right))
        .map(|((&num_left, &num_right), (&den_left, &den_right))| {
            ensure!(
                num_left > 0 && num_right > 0 && den_left > 0 && den_right > 0,
                "timed samples must be positive"
            );
            Ok(0.5
                * ((num_left as f64).ln() + (num_right as f64).ln()
                    - (den_left as f64).ln()
                    - (den_right as f64).ln()))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(per_round
        .chunks_exact(ESTIMATOR_BLOCK_ROUNDS)
        .map(|block| block.iter().sum::<f64>() / ESTIMATOR_BLOCK_DIVISOR)
        .collect())
}

fn competitive_log_ratios(samples: &TimedSamples) -> Result<Vec<f64>> {
    paired_group_log_ratios(samples, CANDIDATE_A_ARMS, KERNEL_ARMS)
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

/// A CPU outside the placement set counts as carrying EXTERNAL load above this
/// busy fraction (bd-bt2dy).
///
/// Calibrated against the two real windows that motivated this, both sampled by
/// the harness itself: the contended window had 5 off-placement CPUs above `0.2`
/// (one pinned at `1.000`, off-placement mean `0.081`), the quiet window had 0
/// (max `0.170`, mean `0.028`). `0.25` sits above the quiet window's worst CPU
/// and far below the contended window's, so the two separate cleanly.
const EXTERNAL_BUSY_CPU_FRACTION: f64 = 0.25;

/// How many off-placement CPUs may carry external load before a SAMPLE counts as
/// contended. Two is deliberately permissive — a lone background daemon does not
/// invalidate a measurement — while the case that flipped a published verdict
/// showed five.
const MAX_EXTERNAL_BUSY_CPUS: usize = 2;

/// Fraction of contended samples above which a run is refused.
///
/// ⚠ The first version of this gate refused a run on a SINGLE contended sample.
/// That was wrong, and it was measured to be wrong within the hour, on real runs:
///
///   synthetic sustained load (the shape that flipped a verdict)   23/23 = 100.0%
///   quiet box, warm-stat run 1                                     2/71 =   2.8%
///   quiet box, warm-stat run 2                                     1/70 =   1.4%
///
/// Both quiet-box runs were refused, and neither had a co-tenant — just ordinary
/// background churn on a 64-thread machine. Transient blips sit at or below 3%;
/// genuine contention sat at 100%. `0.10` separates them by more than 3x either
/// way.
///
/// This is a policy correction, not a convenience threshold, and the distinction
/// is real: a median-of-32-pairs crossover estimator is *designed* to absorb a
/// perturbation touching a couple of pairs, whereas sustained load biases every
/// pair. The two cases differ in kind, not merely in degree.
const MAX_CONTENDED_SAMPLE_FRACTION: f64 = 0.10;

/// Consecutive contended samples that refuse a run regardless of the fraction.
///
/// The fraction alone is blind to a short, dense burst inside a long run: three
/// back-to-back contended samples is a real event, not sampling noise, even when
/// it is 3% of a 100-sample run.
const MAX_CONSECUTIVE_CONTENDED_SAMPLES: usize = 3;

/// Verdict for one during-run external-load sample.
///
/// Split out as a pure function so the policy is testable without spawning a
/// thread or needing a busy machine.
fn external_busy_cpu_count(
    busy: &BTreeMap<usize, f64>,
    placement_cpus: &BTreeSet<usize>,
    limit_fraction: f64,
) -> usize {
    busy.iter()
        .filter(|(cpu, _)| !placement_cpus.contains(*cpu))
        .filter(|(_, load)| **load > limit_fraction)
        .count()
}

/// Accumulated external-load evidence for one run (bd-bt2dy).
#[derive(Debug, Default, Clone)]
struct ExternalLoadWitness {
    samples: usize,
    max_busy_cpus: usize,
    /// Samples whose busy-CPU count exceeded the limit.
    over_limit_samples: usize,
    /// Longest run of consecutive contended samples — the signal that separates a
    /// dense burst from scattered background churn.
    max_consecutive_over_limit: usize,
    /// Live counter feeding `max_consecutive_over_limit`.
    current_consecutive: usize,
    /// Largest off-placement mean busy fraction seen in any single sample.
    peak_mean_busy: f64,
}

impl ExternalLoadWitness {
    fn observe(&mut self, busy: &BTreeMap<usize, f64>, placement: &BTreeSet<usize>, limit: usize) {
        self.samples += 1;
        let count = external_busy_cpu_count(busy, placement, EXTERNAL_BUSY_CPU_FRACTION);
        self.max_busy_cpus = self.max_busy_cpus.max(count);
        if count > limit {
            self.over_limit_samples += 1;
            self.current_consecutive += 1;
            self.max_consecutive_over_limit = self
                .max_consecutive_over_limit
                .max(self.current_consecutive);
        } else {
            self.current_consecutive = 0;
        }
        let off: Vec<f64> = busy
            .iter()
            .filter(|(cpu, _)| !placement.contains(*cpu))
            .map(|(_, load)| *load)
            .collect();
        if !off.is_empty() {
            let mean = off.iter().sum::<f64>() / off.len() as f64;
            if mean > self.peak_mean_busy {
                self.peak_mean_busy = mean;
            }
        }
    }

    /// Fraction of samples that were contended.
    fn contended_fraction(&self) -> f64 {
        if self.samples == 0 {
            return 0.0;
        }
        self.over_limit_samples as f64 / self.samples as f64
    }

    /// A run is refused only for SUSTAINED contention: too large a share of the
    /// measured region, or a dense burst inside it. Scattered single samples on a
    /// busy-ish shared box are tolerated, because the crossover estimator absorbs
    /// a perturbation touching a couple of pairs.
    fn clean(&self) -> bool {
        self.contended_fraction() <= MAX_CONTENDED_SAMPLE_FRACTION
            && self.max_consecutive_over_limit < MAX_CONSECUTIVE_CONTENDED_SAMPLES
    }
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
    // More than one daemon CPU is tried the same way FIRST and only falls back
    // when the domain genuinely cannot supply it. Inside one last-level-cache
    // domain it usually cannot — C physical cores cannot host both a C-thread
    // client set and a C-CPU daemon privately — and then the clients are placed
    // first, exactly as they are today, with the daemon taking quiet CPUs they
    // did not claim, which in that domain are their SMT siblings.
    //
    // The fallback is NOT a neutral choice, which is why the private attempt now
    // comes first: bd-svhrq measured the serial dispatcher failing its OWN A/A
    // null in 4 of 4 runs taken under the sibling-sharing placement, at 4 and 8
    // daemon CPUs, at both scopes, and worse at 48 pairs than at 24. Host-wide
    // scope on a 32-core box can seat 8 clients and 8 daemon CPUs on distinct
    // physical cores; refusing to even try meant no wide-cpuset run could be
    // admitted. Either way the placement is reported, so a row can never be read
    // as if the two placements were interchangeable.
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
        } else if let Some((fuse_cpus, fuse_guard_cpus, driver_cpus, guarded)) =
            place_daemon_on_private_cores(
                fuse_cpu_count,
                client_threads,
                driver_cpu,
                &driver_guard_cpus,
                &PrivateCorePlacementContext {
                    scope,
                    ranked: &ranked,
                    busy: &busy,
                    driver_domain,
                    allowed_cpus,
                },
            )?
        {
            (
                fuse_cpus,
                fuse_guard_cpus,
                driver_cpus,
                guarded,
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
/// excluded, because every candidate CPU must clear the same busy limit — the
/// per-CPU load carried in `ranked`, which is the same measurement the quiet
/// window produced.
fn select_multi_fuse_cpus(
    count: usize,
    ranked: &[(usize, f64)],
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

/// Everything `place_daemon_on_private_cores` needs that it does not own.
struct PrivateCorePlacementContext<'a> {
    scope: PlacementScope,
    ranked: &'a [(usize, f64)],
    busy: &'a BTreeMap<usize, f64>,
    driver_domain: &'a BTreeSet<usize>,
    allowed_cpus: &'a BTreeSet<usize>,
}

/// Try the one-daemon-CPU placement order for a multi-CPU daemon: the daemon
/// claims private physical cores first, then the clients fill in around the
/// guarded sibling set.
///
/// Returns `Ok(None)` — not an error — when the domain cannot supply that many
/// private cores, or when the clients then do not fit. Both are ordinary
/// outcomes inside one last-level-cache domain, and the caller falls back to the
/// clients-first placement rather than failing the run.
fn place_daemon_on_private_cores(
    fuse_cpu_count: usize,
    client_threads: usize,
    driver_cpu: usize,
    driver_guard_cpus: &BTreeSet<usize>,
    context: &PrivateCorePlacementContext<'_>,
) -> Result<Option<(Vec<usize>, BTreeSet<usize>, Vec<usize>, BTreeSet<usize>)>> {
    let mut siblings = BTreeMap::new();
    for &(cpu, _) in context.ranked {
        if context.driver_domain.contains(&cpu) {
            siblings.insert(
                cpu,
                thread_siblings(cpu)?
                    .intersection(context.allowed_cpus)
                    .copied()
                    .collect::<BTreeSet<_>>(),
            );
        }
    }
    let Some((fuse_cpus, fuse_guard_cpus)) = select_private_core_cpus(
        fuse_cpu_count,
        context.ranked,
        context.driver_domain,
        driver_guard_cpus,
        &siblings,
    ) else {
        return Ok(None);
    };
    let driver_context = DriverPlacementContext {
        scope: context.scope,
        ranked: context.ranked,
        busy: context.busy,
        driver_domain: context.driver_domain,
        fuse_guard_cpus: &fuse_guard_cpus,
    };
    // The clients not fitting around a private daemon is a reason to fall back,
    // not a reason to fail: the clients-first placement may still seat them.
    let Ok((driver_cpus, guarded)) = select_driver_cpus(
        client_threads,
        driver_cpu,
        driver_guard_cpus.clone(),
        &driver_context,
    ) else {
        return Ok(None);
    };
    Ok(Some((fuse_cpus, fuse_guard_cpus, driver_cpus, guarded)))
}

/// Pick `count` quiet CPUs on pairwise-distinct physical cores, avoiding every
/// CPU the driver thread already guards.
///
/// Pure so it can be tested without sysfs: `siblings` maps a CPU to its SMT
/// sibling set. `None` means the domain has no such placement — the caller must
/// treat that as "fall back", never as "good enough", because a daemon sharing a
/// physical core with the clients it serves is exactly the configuration whose
/// A/A null bd-svhrq found unstable.
fn select_private_core_cpus(
    count: usize,
    ranked: &[(usize, f64)],
    domain: &BTreeSet<usize>,
    reserved: &BTreeSet<usize>,
    siblings: &BTreeMap<usize, BTreeSet<usize>>,
) -> Option<(Vec<usize>, BTreeSet<usize>)> {
    let mut chosen = Vec::with_capacity(count);
    let mut guards = BTreeSet::new();
    for &(cpu, load) in ranked {
        if chosen.len() == count {
            break;
        }
        if !domain.contains(&cpu)
            || reserved.contains(&cpu)
            || guards.contains(&cpu)
            || load > MAX_FUSE_PREFLIGHT_BUSY
        {
            continue;
        }
        let core = siblings.get(&cpu)?;
        // A core is only private if NONE of its threads is spoken for.
        if core.iter().any(|sibling| reserved.contains(sibling)) {
            continue;
        }
        guards.extend(core.iter().copied());
        chosen.push(cpu);
    }
    if chosen.len() < count {
        return None;
    }
    chosen.sort_unstable();
    Some((chosen, guards))
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

/// Marker written into a reusable scratch root, so clearing one can never touch
/// a directory this harness did not create.
const SCRATCH_MARKER: &str = ".ffs-mounted-kernel-scratch";

/// Prepare the reusable scratch root that holds this run's arm images and
/// fixture tree.
///
/// Every invocation used to mint `run_<epoch>_<pid>/` and fill it with one
/// 1 GiB image PER ARM plus a base, and nothing ever removed them: 5-11 GiB per
/// invocation, unbounded (bd-v0igv found 133 GiB of them). The per-arm images
/// are deterministic intermediates — every run rebuilds them from `mke2fs` or
/// `mkfs.btrfs` before it measures anything, and no banked row cites one — so a
/// per-run directory buys nothing for them. The small `report.json` still gets
/// its own per-run directory; only the bulk is reused.
///
/// The pristine-image guarantee is preserved rather than traded away:
/// `create_sized_file` keeps its `create_new(true)`, so a stale image can still
/// never be measured. This clears the scratch root FIRST, which is what makes
/// the fresh creates succeed. It refuses to clear anything lacking
/// [`SCRATCH_MARKER`], so a mistyped `--scratch-root` cannot remove data this
/// harness did not write.
fn prepare_scratch_dir(root: &Path) -> Result<PathBuf> {
    ensure!(
        root.is_absolute() && root.starts_with("/data/tmp"),
        "scratch root must be an absolute path below /data/tmp"
    );
    let marker = root.join(SCRATCH_MARKER);
    if root.exists() {
        ensure!(
            marker.is_file(),
            "refusing to reuse {} as a scratch root: it has no {SCRATCH_MARKER} marker, so this \
             harness did not create it",
            root.display()
        );
        for entry in
            fs::read_dir(root).with_context(|| format!("read scratch root {}", root.display()))?
        {
            let entry = entry.with_context(|| format!("read entry in {}", root.display()))?;
            if entry.file_name() == SCRATCH_MARKER {
                continue;
            }
            let path = entry.path();
            let removed = if entry
                .file_type()
                .with_context(|| format!("stat {}", path.display()))?
                .is_dir()
            {
                fs::remove_dir_all(&path)
            } else {
                fs::remove_file(&path)
            };
            removed.with_context(|| format!("clear stale scratch entry {}", path.display()))?;
        }
    } else {
        fs::create_dir_all(root).with_context(|| format!("create {}", root.display()))?;
        fs::write(&marker, b"ffs-mounted-kernel-bench reusable scratch root\n")
            .with_context(|| format!("write {}", marker.display()))?;
    }
    Ok(root.to_path_buf())
}

/// Marker that tells the host's disk-pressure reclaimer (`sbh`) to skip a
/// subtree; `sbh protect <path>` writes exactly this file and nothing else, so
/// writing it directly costs nothing and adds no dependency on sbh being present.
const RECLAIM_PROTECT_MARKER: &str = ".sbh-protect";

/// Protect the directory holding this run's REPORT from disk-pressure
/// reclamation (bd-v0igv).
///
/// Measured, not precautionary. `/data/tmp` sat at 90% when bd-v0igv enumerated 46
/// comparator reports as KEEP (1.4 MiB total, against 133 GiB of regenerable arm
/// images). By 2026-08-08 the images were gone — good — and so were 45 of the 46
/// reports. Two banked rows now cite provenance that no longer exists: the
/// 2026-07-31 bulk-durable row's `mounted-kernel-report.json`, and the entire
/// `frankenfs-mounted-btrfs/run_*` tree the btrfs scorecard pointed at for all six
/// of its rows. A report is ~48 KiB and is the only artifact here that cannot be
/// rebuilt; the images are deterministic intermediates every run remakes from
/// scratch. Reclaiming the rebuildable thing while eating the unrebuildable one is
/// exactly backwards.
///
/// The marker protects a SUBTREE, so it goes on the report's own directory and
/// emphatically NOT on the artifact root: the scratch root defaults to
/// `<artifact_root>/scratch`, a sibling of the per-run report directories, and
/// protecting their common parent would make the 5–11 GiB of arm images
/// unreclaimable — the precise outcome bd-v0igv exists to prevent. Scratch must
/// stay reclaimable; it is cleared by the next run anyway.
///
/// Best-effort: a run must not fail because a marker could not be written.
fn protect_report_dir_from_reclaim(report_dir: &Path, scratch_root: &Path) {
    if report_dir.starts_with(scratch_root) {
        // An --output inside the scratch root would drag the arm images under the
        // protection marker. Say so rather than silently pinning 5-11 GiB.
        eprintln!(
            "warning: report directory {} is inside the scratch root {}; not writing a \
             {RECLAIM_PROTECT_MARKER} marker, because it would also protect the \
             regenerable arm images. Move --output outside the scratch root to keep \
             the report durable.",
            report_dir.display(),
            scratch_root.display()
        );
        return;
    }
    let marker = report_dir.join(RECLAIM_PROTECT_MARKER);
    if marker.exists() {
        return;
    }
    if let Err(error) = fs::write(
        &marker,
        b"frankenfs mounted-comparator report (bd-v0igv). The arm images are\n\
          regenerable and live in the scratch root, which is NOT protected; the\n\
          report here cannot be rebuilt and is cited as provenance by the perf\n\
          scorecards. Written by ffs-mounted-kernel-bench, equivalent to `sbh protect`.\n",
    ) {
        eprintln!(
            "warning: could not write {} ({error}); this run's report is reclaimable \
             under disk pressure",
            marker.display()
        );
    }
}

fn create_run_dir(root: &Path) -> Result<PathBuf> {
    ensure!(
        root.is_absolute() && root.starts_with("/data/tmp"),
        "artifact root must be an absolute path below /data/tmp"
    );
    fs::create_dir_all(root).with_context(|| format!("create {}", root.display()))?;
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time predates Unix epoch")?;
    // Sub-second uniqueness matters when a measurement script retries a
    // rejected invocation in the same second: reports must never collide even
    // when the PID is reused by a wrapper (bd-v0igv).
    let run_dir = root.join(format!(
        "run_{}_{}_{}",
        epoch.as_secs(),
        epoch.subsec_nanos(),
        std::process::id()
    ));
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
    scratch_dir: &Path,
    mount_run_dir: &Path,
    fixture_root: &Path,
    placement: &CpuPlacement,
    interrupted: &AtomicBool,
) -> Result<Value> {
    let fs_dir = scratch_dir.join(kind.label());
    fs::create_dir(&fs_dir).with_context(|| format!("create {}", fs_dir.display()))?;
    let mount_fs_dir = mount_run_dir.join(kind.label());
    fs::create_dir(&mount_fs_dir)
        .with_context(|| format!("create mount directory {}", mount_fs_dir.display()))?;
    let compares_candidates = config.compares_candidates();
    let arms = measured_arms(compares_candidates);
    let candidate_arms = fuse_arms(compares_candidates);
    let base = create_base_image(kind, fixture_root, &fs_dir, config)?;
    // bd-plkzd / bd-c5210: fixture directories large enough to be indexed are
    // seeded THROUGH a kernel mount of the base image, before cloning, so each
    // filesystem builds its own native directory index and all four arms still
    // clone from one byte-identical image. Baking the entries in with `mke2fs -d`
    // left ext4 with a linear, unindexed directory while btrfs got a normal one,
    // so the two arms were not the same filesystem shape. The ext4 index is then
    // ASSERTED, not assumed.
    if let Some(fixture) = SeededFixture::for_workload(config.workload) {
        if config.fixture_construction == FixtureConstruction::Baked {
            // bd-pb85e: the entries are already in the image, written by
            // `mke2fs -d` from the host tree. Seeding again would double them, and
            // the htree assertion is deliberately NOT run — a baked ext4 directory
            // is linear and unindexed BY CONSTRUCTION, which is the property being
            // measured. Asserting it here would just fail the run and destroy the
            // comparison. The fail-closed verdict, not this assertion, is what
            // stops a baked run being banked.
            validate_image(kind, &base)?;
        } else {
            seed_fixture_through_mount(kind, &base, fixture, config.operations, interrupted)?;
            if kind == FilesystemKind::Ext4 {
                ensure_ext4_directory_is_htree_indexed(&base, fixture.dir_name())?;
            }
            validate_image(kind, &base)?;
        }
    }
    let images = clone_images(kind, &base, &fs_dir, arms)?;

    let mut mounts = Vec::with_capacity(arms.len());
    for arm in KERNEL_ARMS {
        mounts.push(mount_kernel(
            kind,
            arm,
            &images[&arm],
            &mount_fs_dir.join(arm.label()),
            config.workload.is_mutating(),
            interrupted,
        )?);
    }
    for &arm in candidate_arms {
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
    assert_independent_arms(&mounts, candidate_arms.len())?;
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
        "FUSE arms executed different ELFs: {fuse_shas:?}"
    );
    // With a second candidate configuration mounted, the single-ELF check above
    // is the load-bearing half of "one ELF, two configurations"; this is the
    // other half.
    let candidate_knobs = compares_candidates
        .then(|| candidate_knob_divergence(&mounts, config.candidate_configurations_differ()))
        .transpose()?;

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
    // Second candidate configuration: its own A/A null, and the within-window
    // paired ratio against the first configuration.
    let candidate_b_null = compares_candidates
        .then(|| -> Result<BootstrapMedianCi> {
            Ok(bootstrap_median_ci(
                &crossover_log_ratios(
                    &samples.values[&Arm::CandidateBA],
                    &samples.values[&Arm::CandidateBB],
                )?,
                0x4341_4E44_425F_4141,
            ))
        })
        .transpose()?;
    let candidate_b_over_candidate_a = compares_candidates
        .then(|| -> Result<BootstrapMedianCi> {
            Ok(bootstrap_median_ci(
                &paired_group_log_ratios(&samples, CANDIDATE_B_ARMS, CANDIDATE_A_ARMS)?,
                0x4341_4E44_425F_4142,
            ))
        })
        .transpose()?;
    let kernel_ci_contains_one = kernel_null.contains_null();
    let fuse_ci_contains_one = fuse_null.contains_null();
    let kernel_median_within_null_bias_limit = kernel_null.median_within_null_bias_limit();
    let fuse_median_within_null_bias_limit = fuse_null.median_within_null_bias_limit();
    let kernel_clear = null_control_is_clear(kernel_null, config.maximum_null_ratio);
    let fuse_clear = null_control_is_clear(fuse_null, config.maximum_null_ratio);
    let candidate_b_clear =
        candidate_b_null.is_none_or(|ci| null_control_is_clear(ci, config.maximum_null_ratio));
    // When the two candidate configurations are deliberately identical, the
    // cross-pair ratio is itself a null and has to clear the same bar. That is
    // the gate for the new estimator: if a four-FUSE-arm A/A cannot come out at
    // 1.0, no candidate-vs-candidate number taken with this instrument means
    // anything.
    let candidate_cross_null_clear = candidate_cross_null_is_clear(
        config.candidate_configurations_differ(),
        candidate_b_over_candidate_a,
        config.maximum_null_ratio,
    );
    let worker_thread_observation_clear = worker_thread_observation_is_clear(
        &samples.observed_worker_threads,
        config.client_threads(),
        arms,
    );
    let expected_worker_cpus = pinning.expected_cpus(config.client_threads());
    let worker_cpu_pinning_clear =
        worker_cpu_pinning_is_clear(&samples.observed_worker_cpus, &expected_worker_cpus, arms);
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
    let admitted = kernel_clear
        && fuse_clear
        && candidate_b_clear
        && candidate_cross_null_clear
        && worker_thread_observation_clear
        && worker_cpu_pinning_clear;
    let twice_null_log_margin = 2.0 * null_log_margin(kernel_null, fuse_null);
    let twice_null_ratio = twice_null_log_margin.exp();
    let directional_claim_clear =
        admitted && clears_twice_null_margin(fuse_over_kernel, kernel_null, fuse_null);
    // The candidate-vs-candidate claim is bounded by the two candidate nulls,
    // not the kernel one: those are the arms it is built from.
    let candidate_twice_null_log_margin = candidate_b_null
        .map(|candidate_b| 2.0 * null_log_margin(fuse_null, candidate_b))
        .unwrap_or_default();
    let candidate_claim_clear = admitted
        && config.candidate_configurations_differ()
        && match (candidate_b_over_candidate_a, candidate_b_null) {
            (Some(ratio), Some(candidate_b)) => {
                clears_twice_null_margin(ratio, fuse_null, candidate_b)
            }
            _ => false,
        };
    // bd-pb85e: a baked fixture is the known-unfair construction bd-plkzd removed
    // — an unindexed ext4 directory that forces every lookup into an O(N) scan.
    // It is restored ONLY so the fixture effect can be attributed in one window on
    // one ELF, so this is checked FIRST and unconditionally: no combination of
    // clear nulls, clear placement or a favourable ratio can produce a bankable
    // verdict from it. Fail closed, not by convention or by a reviewer noticing.
    let verdict = if !config.fixture_construction.is_bankable() {
        "BLOCKED_UNFAIR_FIXTURE"
    } else if !worker_thread_observation_clear {
        "BLOCKED_THREAD_OBSERVATION"
    } else if !worker_cpu_pinning_clear {
        "BLOCKED_WORKER_CPU_PINNING"
    } else if !kernel_clear || !fuse_clear || !candidate_b_clear || !candidate_cross_null_clear {
        "BLOCKED_NULL"
    } else if !directional_claim_clear {
        "HONEST_NEUTRAL"
    } else if fuse_over_kernel.median > 1.0 {
        "HONEST_LOSS"
    } else {
        "HONEST_WIN"
    };
    let candidate_verdict = if !compares_candidates {
        "NOT_APPLICABLE"
    } else if !admitted {
        verdict
    } else if !config.candidate_configurations_differ() {
        "CANDIDATE_AA_NULL_CLEAR"
    } else if !candidate_claim_clear {
        "CANDIDATE_NEUTRAL"
    } else if candidate_b_over_candidate_a.is_some_and(|ratio| ratio.median > 1.0) {
        "CANDIDATE_B_SLOWER"
    } else {
        "CANDIDATE_B_FASTER"
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

    for &arm in arms {
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
        "mounted_kernel_identity,filesystem={},workload={},kernel_release={},kernel_module={},kernel_engine_artifact={},kernel_engine_sha256={},kernel_runtime_notes_sha256={},kernel_arms=2,fuse_arms={},fuse_binary_sha256={},mount_identity=pass,independent_arms=pass,options={}+noatime+nodev+nosuid,durability={}",
        kind.label(),
        config.workload.label(),
        kernel_identity.release,
        kind.kernel_module(),
        kernel_identity.artifact.display(),
        kernel_identity.artifact_sha256,
        kernel_identity.runtime_notes_sha256,
        candidate_arms.len(),
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
        "mounted_kernel_parity,filesystem={},workload={},arms={},file_sha256={},len={},mode={:o},uid={},gid={},nlink={},tree_sha256={},tree_entries={},tree_files={},tree_dirs={},tree_bytes={},verdict=pass",
        kind.label(),
        config.workload.label(),
        arms.len(),
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
            "mounted_kernel_xattr_parity,filesystem={},workload={},arms={},xattr_sha256={},inline_value_bytes={},external_value_bytes={},single_list_names={},many_list_names={},absent_lookup_none={},external_storage_proof=debugfs_nonzero_file_acl_block,validation_timing=outside_measurement,verdict=pass",
            kind.label(),
            config.workload.label(),
            arms.len(),
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
            "mounted_kernel_bulk_durable_initial_parity,filesystem={},workload={},arms={},file_sha256={},bytes={},validation_timing=outside_measurement,verdict=pass",
            kind.label(),
            config.workload.label(),
            arms.len(),
            bulk_write.sha256,
            bulk_write.bytes,
        );
    }
    for &arm in arms {
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
    if let (Some(candidate_b), Some(candidate_ratio), Some((knobs_a, knobs_b))) = (
        candidate_b_null,
        candidate_b_over_candidate_a,
        candidate_knobs.as_ref(),
    ) {
        println!(
            "mounted_kernel_null,filesystem={},workload={},arm=fuse_candidate_b,median={:.6},median_deviation_from_one={:.6},maximum_median_deviation={:.6},median_within_limit={},ci_low={:.6},ci_high={:.6},ci_contains_one={},ci_contains_one_gate_input=false,symmetric_spread={:.6},maximum={:.6},crossover_blocks={},estimator=four_round_balanced_crossover_bootstrap_median_ci,clear={}",
            kind.label(),
            config.workload.label(),
            candidate_b.median,
            (candidate_b.median - 1.0).abs(),
            MAXIMUM_NULL_MEDIAN_DEVIATION,
            candidate_b.median_within_null_bias_limit(),
            candidate_b.low,
            candidate_b.high,
            candidate_b.contains_null(),
            candidate_b.symmetric_spread(),
            config.maximum_null_ratio,
            config.pairs / ESTIMATOR_BLOCK_ROUNDS,
            candidate_b_clear,
        );
        println!(
            "mounted_kernel_candidate_identity,filesystem={},workload={},workload_arms={},candidate_a_arms={},candidate_b_arms={},one_elf=true,elf_sha256={},candidate_a_runtime_knobs={:?},candidate_b_runtime_knobs={:?},candidate_b_env={:?},configurations_differ={},knob_divergence_proof=daemon_self_reported_effective_values,verdict=pass",
            kind.label(),
            config.workload.label(),
            arms.len(),
            CANDIDATE_A_ARMS.map(Arm::label).join(":"),
            CANDIDATE_B_ARMS.map(Arm::label).join(":"),
            expected_identity.binary_sha256,
            knobs_a,
            knobs_b,
            config
                .candidate_comparison
                .as_ref()
                .map(|comparison| comparison
                    .env
                    .iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect::<Vec<_>>()
                    .join(","))
                .unwrap_or_default(),
            config.candidate_configurations_differ(),
        );
        println!(
            "mounted_kernel_candidate_ratio,filesystem={},metric=wall_ns,workload={},pairs={},crossover_blocks={},schedule=six_arm_williams_square,same_window=true,candidate_b_over_candidate_a_median={:.6},ci_low={:.6},ci_high={:.6},twice_null_margin_ratio={:.6},minimum_decidable_effect_ratio={:.6},achieved_resolution_ratio={:.6},candidate_claim_clear={},admitted={},verdict={},gate_basis=within_window_paired_candidate_crossover_gated_on_both_candidate_aa_nulls,bootstrap_resamples={}",
            kind.label(),
            config.workload.label(),
            config.pairs,
            config.pairs / ESTIMATOR_BLOCK_ROUNDS,
            candidate_ratio.median,
            candidate_ratio.low,
            candidate_ratio.high,
            candidate_twice_null_log_margin.exp(),
            candidate_twice_null_log_margin.exp(),
            candidate_ratio.symmetric_spread(),
            candidate_claim_clear,
            admitted,
            candidate_verdict,
            BOOTSTRAP_RESAMPLES,
        );
    }
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
        "mounted_kernel_post_parity,filesystem={},workload={},arms={},tree_sha256={},tree_entries={},tree_files={},tree_dirs={},tree_bytes={},verdict=pass",
        kind.label(),
        config.workload.label(),
        arms.len(),
        expected_final_tree.sha256,
        expected_final_tree.entries,
        expected_final_tree.regular_files,
        expected_final_tree.directories,
        expected_final_tree.bytes,
    );
    if let Some(xattr) = &expected_final_xattr {
        println!(
            "mounted_kernel_post_xattr_parity,filesystem={},workload={},arms={},xattr_sha256={},validation_timing=outside_measurement,verdict=pass",
            kind.label(),
            config.workload.label(),
            arms.len(),
            xattr.sha256,
        );
    }
    if let Some(bulk_write) = &expected_final_bulk_write {
        println!(
            "mounted_kernel_post_bulk_durable_parity,filesystem={},workload={},arms={},file_sha256={},bytes={},uniform_byte={},validation_timing=outside_measurement,verdict=pass",
            kind.label(),
            config.workload.label(),
            arms.len(),
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
        // Keep both absolute arms beside the quotient.  A cross-window drift
        // diagnosis is impossible from the ratio alone because incumbent
        // volatility is multiplied into it (bd-4sull).
        "fuse_median_wall_ns": fuse_median_wall_ns,
        "kernel_median_wall_ns": kernel_median_wall_ns,
        "ci_low": fuse_over_kernel.low,
        "ci_high": fuse_over_kernel.high,
        "twice_null_log_margin": twice_null_log_margin,
        "twice_null_margin_ratio": twice_null_ratio,
        "directional_claim_clear": directional_claim_clear,
    });
    ensure!(
        absolute_arm_medians_are_valid(fuse_median_wall_ns, kernel_median_wall_ns),
        "competitive ratio requires finite, non-zero absolute arm medians"
    );
    let candidate_b_aa_json = candidate_b_null.map_or_else(
        || json!("not_applicable"),
        |candidate_b| {
            json!({
                "median": candidate_b.median,
                "median_deviation_from_one": (candidate_b.median - 1.0).abs(),
                "maximum_median_deviation": MAXIMUM_NULL_MEDIAN_DEVIATION,
                "median_within_limit": candidate_b.median_within_null_bias_limit(),
                "ci_low": candidate_b.low,
                "ci_high": candidate_b.high,
                "ci_contains_one": candidate_b.contains_null(),
                "ci_contains_one_gate_input": false,
                "symmetric_spread": candidate_b.symmetric_spread(),
                "clear": candidate_b_clear,
            })
        },
    );
    let candidate_comparison_json = match (
        &config.candidate_comparison,
        candidate_b_over_candidate_a,
        candidate_knobs.as_ref(),
    ) {
        (Some(comparison), Some(ratio), Some((knobs_a, knobs_b))) => json!({
            "estimator": "within_window_paired_candidate_crossover",
            "why": "the candidate arms run inside the same balanced schedule, so the window \
                    effect cancels between them exactly as the kernel arm cancels host drift \
                    for fuse_over_kernel (bd-3tqgc)",
            "schedule": "six_arm_williams_square",
            "same_window": true,
            "one_elf": true,
            "elf_sha256": expected_identity.binary_sha256,
            "candidate_a_arms": CANDIDATE_A_ARMS.map(Arm::label),
            "candidate_b_arms": CANDIDATE_B_ARMS.map(Arm::label),
            "candidate_b_env": comparison.env_json(),
            "configurations_differ": comparison.configurations_differ(),
            "candidate_a_runtime_knobs": knobs_a,
            "candidate_b_runtime_knobs": knobs_b,
            "knob_divergence_proof": "daemon_self_reported_effective_values",
            "candidate_b_over_candidate_a": {
                "median": ratio.median,
                "ci_low": ratio.low,
                "ci_high": ratio.high,
                "symmetric_spread": ratio.symmetric_spread(),
            },
            // What this instrument can and cannot decide, so the next lever is
            // not spent finding out the hard way.
            "resolution": {
                "achieved_resolution_ratio": ratio.symmetric_spread(),
                "minimum_decidable_effect_ratio": candidate_twice_null_log_margin.exp(),
                "twice_candidate_null_log_margin": candidate_twice_null_log_margin,
            },
            "candidate_aa_null_clear": candidate_cross_null_clear,
            "candidate_claim_clear": candidate_claim_clear,
            "verdict": candidate_verdict.to_ascii_lowercase(),
        }),
        _ => json!("not_applicable"),
    };
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
        // bd-pb85e: which construction built the fixture, and whether a row from
        // this run may be banked at all. Recorded unconditionally, including on
        // the default seeded path, so a reader never has to infer it from the
        // absence of a field — a banked row's provenance should not depend on
        // remembering which flag was in force the day it was taken.
        "fixture_construction": config.fixture_construction.label(),
        "fixture_construction_bankable": config.fixture_construction.is_bankable(),
        "fixture_construction_reason": config.fixture_construction.bankability_reason(),
        "mechanism_attribution": workload_mechanism_attribution(config.workload),
        "mechanism_attribution_owner": workload_mechanism_owner(config.workload),
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
        "measured_arms": arms.iter().map(|arm| arm.label()).collect::<Vec<_>>(),
        "balanced_schedule": if compares_candidates {
            "six_arm_williams_square"
        } else {
            "four_arm_latin_square"
        },
        "balanced_schedule_orders": balanced_order_count(compares_candidates),
        "balanced_schedule_period_rounds": schedule_period(compares_candidates),
        "warmup_rounds": config.workload.warmup_rounds(),
        "arm_settle_ms": config.arm_settle_ms,
        "pre_measurement_settle_ms": config.pre_measurement_settle_ms,
        "pre_measurement_quiescence": format!(
            "base and {} cloned image files sync_all before mount, then untimed settle after mount identity and initial parity",
            arms.len()
        ),
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
        "fuse_candidate_b_aa": candidate_b_aa_json,
        "candidate_comparison": candidate_comparison_json,
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

fn workload_mechanism_attribution(workload: Workload) -> &'static str {
    match workload {
        Workload::ReaddirStat8 => "enumerate_then_stat_inode_resolution",
        _ => "workload_specific_unattributed",
    }
}

fn workload_mechanism_owner(workload: Workload) -> &'static str {
    match workload {
        Workload::ReaddirStat8 => "btrfs_inode_resolution_or_shared_fuse_floor",
        _ => "unattributed",
    }
}

fn absolute_arm_medians_are_valid(fuse_median_ns: f64, kernel_median_ns: f64) -> bool {
    fuse_median_ns.is_finite()
        && kernel_median_ns.is_finite()
        && fuse_median_ns > 0.0
        && kernel_median_ns > 0.0
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
    // Where each ELF was built is recorded, and whether it had to be copied
    // here is derived from that rather than assumed: see `RetrievalProvenance`.
    let retrieval = RetrievalProvenance::classify(
        &config.harness_builder,
        &config.candidate_builder,
        &host.hostname,
    );
    println!(
        "binary_provenance,driver_elf_sha256={harness_sha},driver_built_on={},candidate_elf_sha256={},candidate_built_on={},executed_on={},retrieval={}",
        config.harness_builder,
        ffs_binary_identity.binary_sha256,
        config.candidate_builder,
        host.hostname,
        retrieval.label(),
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
    // The report keeps its per-run directory; the arm images and fixture tree —
    // the 5-11 GiB of it — go in a scratch root that every run reuses and
    // clears (bd-v0igv).
    let scratch_dir = prepare_scratch_dir(&config.scratch_root())?;
    // Mark the report's directory (not the artifact root, not scratch) so the
    // host's disk-pressure reclaimer keeps the one artifact that cannot be
    // rebuilt. 45 of 46 banked comparator reports were already lost this way.
    if let Some(report_dir) = output.parent() {
        protect_report_dir_from_reclaim(report_dir, &scratch_dir);
    }
    let fixture_root = create_fixture_tree(&scratch_dir, &config)?;
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
        matches!(
            config.placement_scope,
            PlacementScope::SameLlc | PlacementScope::BalancedSquare
        ),
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
    // bd-bt2dy: sample EXTERNAL load for the whole measured region, not just once
    // before it. The pre-run gate gets the placement CPUs right and is blind to
    // everything else on the socket; a peer's build on other cores flipped a
    // published verdict (bd-ws9dg) while `core_contention_preflight` correctly
    // reported `verdict=clear`. Bandwidth, LLC and boost budget are shared even
    // when the placement cores are idle.
    let external_load_stop = Arc::new(AtomicBool::new(false));
    let external_load_witness = Arc::new(Mutex::new(ExternalLoadWitness::default()));
    let sampler_placement: BTreeSet<usize> = placement
        .driver_cpus
        .iter()
        .chain(placement.driver_guard_cpus.iter())
        .chain(placement.fuse_cpus.iter())
        .chain(placement.fuse_guard_cpus.iter())
        .copied()
        .collect();
    let sampler = {
        let stop = Arc::clone(&external_load_stop);
        let witness = Arc::clone(&external_load_witness);
        let placement_cpus = sampler_placement.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                // Errors here must never fail a run: this is evidence, not a gate
                // input, until the verdict below reads it.
                if let Ok(busy) = sample_cpu_busy() {
                    if let Some(mut w) = witness.lock().ok() {
                        w.observe(&busy, &placement_cpus, MAX_EXTERNAL_BUSY_CPUS);
                    }
                }
            }
        })
    };

    let mut filesystem_reports = Vec::with_capacity(requested.len());
    let mut blocked_filesystems = Vec::new();
    for kind in requested {
        filesystem_reports.push(fs_report(
            kind,
            &config,
            &ffs_binary_identity,
            &host,
            &scratch_dir,
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

    external_load_stop.store(true, Ordering::Relaxed);
    let _ = sampler.join();
    let external_load = external_load_witness
        .lock()
        .map(|w| w.clone())
        .unwrap_or_default();
    let external_load_clean = external_load.clean();
    println!(
        "external_load_during_run,samples={},max_external_busy_cpus={},over_limit_samples={},\
         contended_fraction={:.4},max_consecutive_over_limit={},\
         peak_off_placement_mean_busy={:.6},busy_cpu_fraction_limit={:.2},max_external_busy_cpus_limit={},\
         max_contended_fraction_limit={:.2},max_consecutive_limit={},\
         placement_cpus_excluded={},verdict={}",
        external_load.samples,
        external_load.max_busy_cpus,
        external_load.over_limit_samples,
        external_load.contended_fraction(),
        external_load.max_consecutive_over_limit,
        external_load.peak_mean_busy,
        EXTERNAL_BUSY_CPU_FRACTION,
        MAX_EXTERNAL_BUSY_CPUS,
        MAX_CONTENDED_SAMPLE_FRACTION,
        MAX_CONSECUTIVE_CONTENDED_SAMPLES,
        sampler_placement.len(),
        if external_load_clean {
            "clear"
        } else {
            "CONTENDED"
        }
    );

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
        "retrieval": retrieval.label(),
        "note": retrieval.note(),
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
        // Recorded distinctly from artifact_root: the scratch root is REUSED and
        // cleared by the next run, so a later reader must not expect this run's
        // images to still be there (bd-v0igv).
        "scratch_root": scratch_dir,
        "scratch_root_lifetime": "reused_and_cleared_by_the_next_run",
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
        // bd-bt2dy: the DURING-run external-load witness, recorded whether or not
        // it is clean so a later reader can disqualify a banked row without
        // re-running it. The pre-run fields above describe the placement CPUs at
        // one instant; these describe everything else for the whole measured region.
        "external_load_during_run": json!({
            "samples": external_load.samples,
            "max_external_busy_cpus": external_load.max_busy_cpus,
            "over_limit_samples": external_load.over_limit_samples,
            "contended_fraction": external_load.contended_fraction(),
            "max_consecutive_over_limit": external_load.max_consecutive_over_limit,
            "peak_off_placement_mean_busy": external_load.peak_mean_busy,
            "busy_cpu_fraction_limit": EXTERNAL_BUSY_CPU_FRACTION,
            "max_external_busy_cpus_limit": MAX_EXTERNAL_BUSY_CPUS,
            "max_contended_fraction_limit": MAX_CONTENDED_SAMPLE_FRACTION,
            "max_consecutive_limit": MAX_CONSECUTIVE_CONTENDED_SAMPLES,
            "placement_cpus_excluded": sampler_placement.len(),
            "sample_interval_ms": CPU_SAMPLE_INTERVAL_MS,
            "verdict": if external_load_clean { "clear" } else { "contended" },
        }),
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
    // bd-bt2dy: refuse the run if EXTERNAL load contended the socket during the
    // measured region. Ordered after the A/A gate deliberately — a row that fails
    // its nulls should say so first — and fails closed like every other gate here,
    // because the alternative is what happened on 2026-08-08: two admitted runs
    // under a peer's build returned opposite verdicts and one was published.
    // The report is written before this check, so a refused run is still
    // diagnosable from its own external_load_during_run block.
    ensure!(
        external_load_clean,
        "external load contended the socket during the measured region: \
         {} of {} samples ({:.1}%, limit {:.0}%) had more than {} off-placement CPUs above \
         {:.0}% busy, longest consecutive run {} (limit {}), peak {} busy CPUs, peak \
         off-placement mean busy {:.1}%. The placement CPUs may well have been idle — that is \
         what the pre-run gate checks — but memory bandwidth, LLC and boost budget are \
         socket-wide. Re-run in a quiet window. Report preserved at {}",
        external_load.over_limit_samples,
        external_load.samples,
        external_load.contended_fraction() * 100.0,
        MAX_CONTENDED_SAMPLE_FRACTION * 100.0,
        MAX_EXTERNAL_BUSY_CPUS,
        EXTERNAL_BUSY_CPU_FRACTION * 100.0,
        external_load.max_consecutive_over_limit,
        MAX_CONSECUTIVE_CONTENDED_SAMPLES,
        external_load.max_busy_cpus,
        external_load.peak_mean_busy * 100.0,
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
        for arm in FOUR_ARM_SET {
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
    fn candidate_schedule_visits_every_arm_once_in_every_position() {
        for order in CANDIDATE_BALANCED_ORDERS {
            assert_eq!(
                order.iter().copied().collect::<BTreeSet<_>>(),
                SIX_ARM_SET.into_iter().collect::<BTreeSet<_>>(),
                "every round must run every arm exactly once"
            );
        }
        for arm in SIX_ARM_SET {
            let positions: BTreeSet<usize> = CANDIDATE_BALANCED_ORDERS
                .iter()
                .flat_map(|order| {
                    order
                        .iter()
                        .enumerate()
                        .filter_map(move |(index, candidate)| (*candidate == arm).then_some(index))
                })
                .collect();
            assert_eq!(positions, BTreeSet::from([0, 1, 2, 3, 4, 5]));
        }
    }

    /// The six-arm schedule must also balance first-order carryover: with six
    /// arms per round an unbalanced order would leave one candidate arm always
    /// executing right after the same neighbour, which is a bias the paired
    /// estimator cannot cancel. A plain cyclic rotation would pass the
    /// position test above and fail this one.
    #[test]
    fn candidate_schedule_is_a_williams_square() {
        let mut adjacent = BTreeMap::new();
        for order in CANDIDATE_BALANCED_ORDERS {
            for pair in order.windows(2) {
                *adjacent.entry((pair[0], pair[1])).or_insert(0_usize) += 1;
            }
        }
        assert_eq!(
            adjacent.len(),
            SIX_ARM_SET.len() * (SIX_ARM_SET.len() - 1),
            "every ordered pair of distinct arms must be adjacent somewhere"
        );
        assert!(
            adjacent.values().all(|&count| count == 1),
            "every ordered pair must be adjacent exactly once: {adjacent:?}"
        );
    }

    #[test]
    fn schedule_period_covers_both_the_square_and_the_estimator_blocks() {
        assert_eq!(schedule_period(false), 4);
        assert_eq!(schedule_period(true), 12);
        assert_eq!(balanced_order_count(true), 12);
        assert_eq!(measured_arms(true).len(), 6);
        assert_eq!(fuse_arms(true).len(), 4);
        assert_eq!(fuse_arms(false).len(), 2);
        // The four-arm schedule must stay byte-identical to the banked one.
        assert_eq!(balanced_order(false, 5), BALANCED_ORDERS[1]);
        assert_eq!(balanced_order(true, 7), CANDIDATE_BALANCED_ORDERS[2]);
        // Every Williams row is visited twice per period, once on each parity.
        let mut parities: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        for (round, &row) in CANDIDATE_ROW_SEQUENCE.iter().enumerate() {
            parities.entry(row).or_default().insert(round % 2);
        }
        assert_eq!(parities.len(), CANDIDATE_BALANCED_ORDERS.len());
        assert!(
            parities
                .values()
                .all(|seen| *seen == BTreeSet::from([0, 1])),
            "each row must run on both round parities: {parities:?}"
        );
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
        for physical_arm in FOUR_ARM_SET {
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
    fn candidate_crossover_schedule_puts_every_physical_arm_in_every_position() {
        for physical_arm in SIX_ARM_SET {
            let positions: BTreeSet<usize> = (0..schedule_period(true))
                .flat_map(|round| {
                    balanced_order(true, round).iter().enumerate().filter_map(
                        move |(position, logical_arm)| {
                            (physical_arm_for(*logical_arm, round) == physical_arm)
                                .then_some(position)
                        },
                    )
                })
                .collect();
            assert_eq!(positions, BTreeSet::from([0, 1, 2, 3, 4, 5]));
        }
        // Every physical arm must also execute the same number of times per
        // period, or the "balanced" schedule silently favours one image.
        let mut executions = BTreeMap::new();
        for round in 0..schedule_period(true) {
            for &logical_arm in balanced_order(true, round) {
                *executions
                    .entry(physical_arm_for(logical_arm, round))
                    .or_insert(0_usize) += 1;
            }
        }
        assert_eq!(executions.len(), SIX_ARM_SET.len());
        assert!(
            executions
                .values()
                .all(|&count| count == schedule_period(true))
        );
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

    /// Eight physical cores, two SMT threads each: cpu N pairs with cpu N + 8.
    fn smt_pairs(cores: usize) -> BTreeMap<usize, BTreeSet<usize>> {
        (0..cores * 2)
            .map(|cpu| {
                let core = cpu % cores;
                (cpu, BTreeSet::from([core, core + cores]))
            })
            .collect()
    }

    #[test]
    fn private_core_selection_never_puts_two_daemon_cpus_on_one_physical_core() {
        let siblings = smt_pairs(8);
        let domain: BTreeSet<usize> = (0..16).collect();
        let ranked: Vec<(usize, f64)> = (0..16).map(|cpu| (cpu, 0.0)).collect();

        let (chosen, guards) =
            select_private_core_cpus(4, &ranked, &domain, &BTreeSet::new(), &siblings)
                .expect("8 free cores can seat 4 private daemon CPUs");
        assert_eq!(chosen.len(), 4);
        let cores: BTreeSet<usize> = chosen.iter().map(|cpu| cpu % 8).collect();
        assert_eq!(
            cores.len(),
            4,
            "each daemon CPU needs its own physical core"
        );
        for &cpu in &chosen {
            assert!(
                guards.contains(&(cpu % 8)) && guards.contains(&(cpu % 8 + 8)),
                "both SMT threads of a claimed core must be guarded"
            );
        }
    }

    #[test]
    fn private_core_selection_declines_rather_than_sharing_a_core_with_the_driver() {
        let siblings = smt_pairs(8);
        let domain: BTreeSet<usize> = (0..16).collect();
        let ranked: Vec<(usize, f64)> = (0..16).map(|cpu| (cpu, 0.0)).collect();

        // The driver guards one whole core; its sibling must not be handed out
        // even though that sibling is itself unreserved.
        let reserved = BTreeSet::from([0, 8]);
        let (chosen, _) = select_private_core_cpus(7, &ranked, &domain, &reserved, &siblings)
            .expect("the other 7 cores are still free");
        assert!(
            !chosen.contains(&0) && !chosen.contains(&8),
            "the driver's core is off limits on both threads"
        );

        // Asking for more private cores than exist declines instead of doubling
        // up — the caller falls back to the clients-first placement.
        assert!(
            select_private_core_cpus(8, &ranked, &domain, &reserved, &siblings).is_none(),
            "7 free cores cannot seat 8 private daemon CPUs"
        );
    }

    #[test]
    fn private_core_selection_skips_busy_cpus_and_cpus_outside_the_domain() {
        let siblings = smt_pairs(8);
        // Only half the machine is in the placement domain.
        let domain: BTreeSet<usize> = (0..4).chain(8..12).collect();
        let mut ranked: Vec<(usize, f64)> = (0..16).map(|cpu| (cpu, 0.0)).collect();
        ranked[1].1 = MAX_FUSE_PREFLIGHT_BUSY + 0.1;
        ranked[9].1 = MAX_FUSE_PREFLIGHT_BUSY + 0.1;

        let (chosen, _) =
            select_private_core_cpus(3, &ranked, &domain, &BTreeSet::new(), &siblings)
                .expect("cores 0, 2 and 3 remain");
        assert!(
            chosen.iter().all(|cpu| domain.contains(cpu)),
            "no CPU outside the domain may be chosen"
        );
        assert!(
            !chosen.contains(&1),
            "a CPU over the daemon contention limit is not quiet enough to choose"
        );
        // Core 1 is busy on cpu1 but its sibling cpu9 is also busy, so only
        // three private cores are actually available in this domain.
        assert!(
            select_private_core_cpus(4, &ranked, &domain, &BTreeSet::new(), &siblings).is_none()
        );
    }

    #[test]
    fn scratch_root_is_reused_but_only_ever_clears_a_directory_it_marked() {
        // The scratch root is required to live under /data/tmp, so this test
        // works there rather than in a tempdir, under a unique name.
        let root = PathBuf::from(format!(
            "/data/tmp/ffs-scratch-guard-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);

        // First use creates the root and its marker.
        let prepared = prepare_scratch_dir(&root).expect("create a fresh scratch root");
        assert_eq!(prepared, root);
        assert!(root.join(SCRATCH_MARKER).is_file());

        // A second run clears the previous run's bulk but keeps the marker, so
        // create_sized_file's create_new(true) still succeeds on a fresh image
        // and can never be handed a stale one.
        fs::write(root.join("ext4.base.img"), b"stale").expect("write stale image");
        fs::create_dir(root.join("fixture-root")).expect("stale fixture tree");
        prepare_scratch_dir(&root).expect("reuse the scratch root");
        assert!(!root.join("ext4.base.img").exists());
        assert!(!root.join("fixture-root").exists());
        assert!(root.join(SCRATCH_MARKER).is_file());

        // A directory this harness did not create is refused, not cleared.
        let foreign = root.join("foreign");
        fs::create_dir(&foreign).expect("create foreign dir");
        let precious = foreign.join("someone-elses-data");
        fs::write(&precious, b"do not delete").expect("write foreign data");
        let error = prepare_scratch_dir(&foreign).expect_err("no marker means refuse");
        assert!(
            error.to_string().contains(SCRATCH_MARKER),
            "the refusal must name the missing marker, got: {error}"
        );
        assert!(precious.is_file(), "foreign data must survive the refusal");

        // A path outside /data/tmp is refused before anything is inspected.
        assert!(prepare_scratch_dir(Path::new("/tmp/ffs-scratch-guard")).is_err());

        let _ = fs::remove_dir_all(&root);
    }

    /// bd-v0igv: the reclaim-protection marker must land on the REPORT's
    /// directory and never anywhere that contains the arm images. The marker
    /// protects a subtree, so getting this wrong does not lose a report — it
    /// pins 5-11 GiB of regenerable images per run, which is the exact problem
    /// bd-v0igv was filed about.
    #[test]
    fn reclaim_protection_marks_the_report_dir_and_refuses_to_pin_the_scratch_root() {
        let root = PathBuf::from(format!(
            "/data/tmp/ffs-protect-guard-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let scratch = root.join("scratch");
        let run_dir = root.join("run_1_1");
        fs::create_dir_all(&scratch).expect("scratch");
        fs::create_dir_all(&run_dir).expect("run dir");

        // The normal shape: report dir is a SIBLING of scratch, so it is marked
        // and scratch is left reclaimable.
        protect_report_dir_from_reclaim(&run_dir, &scratch);
        assert!(
            run_dir.join(RECLAIM_PROTECT_MARKER).is_file(),
            "the report's own directory must be protected"
        );
        assert!(
            !scratch.join(RECLAIM_PROTECT_MARKER).exists(),
            "the scratch root holds the regenerable images and must stay reclaimable"
        );
        assert!(
            !root.join(RECLAIM_PROTECT_MARKER).exists(),
            "protecting the artifact root would protect scratch too, since the marker \
             covers a subtree — that is the failure this test exists to catch"
        );

        // Idempotent: a second call does not rewrite or duplicate the marker.
        let first = fs::read(run_dir.join(RECLAIM_PROTECT_MARKER)).expect("marker body");
        protect_report_dir_from_reclaim(&run_dir, &scratch);
        assert_eq!(
            fs::read(run_dir.join(RECLAIM_PROTECT_MARKER)).expect("marker body"),
            first
        );

        // An --output aimed inside the scratch root is REFUSED, not honoured:
        // marking there would drag the arm images under the protection.
        let inside = scratch.join("nested");
        fs::create_dir_all(&inside).expect("nested scratch dir");
        protect_report_dir_from_reclaim(&inside, &scratch);
        assert!(
            !inside.join(RECLAIM_PROTECT_MARKER).exists(),
            "a report directory inside the scratch root must not be marked"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn scratch_images_live_beside_per_run_reports_bd_v0igv() {
        let run = Path::new("/data/tmp/comparator/run_1_1");
        assert_eq!(
            scratch_image_dir(run).unwrap(),
            Path::new("/data/tmp/comparator/images")
        );
    }

    #[test]
    fn run_directory_rejects_non_artifact_roots_bd_v0igv() {
        let error = create_run_dir(Path::new("relative-artifacts"))
            .expect_err("measurement artifacts must not escape /data/tmp");
        assert!(error.to_string().contains("absolute path below /data/tmp"));
    }

    #[test]
    fn retrieval_provenance_is_derived_from_the_builders_not_assumed() {
        // The remote case, which used to be the only string the report could
        // emit.
        assert_eq!(
            RetrievalProvenance::classify("hz1", "hz2", "thinkstation1"),
            RetrievalProvenance::ScpFromBuilder
        );
        // A build that ran on the executing host was previously reported as
        // copied in from an rch worker, which is a provenance that did not
        // happen.
        assert_eq!(
            RetrievalProvenance::classify("thinkstation1", "thinkstation1", "thinkstation1"),
            RetrievalProvenance::BuiltInPlace
        );
        assert_eq!(
            RetrievalProvenance::classify("ThinkStation1", " thinkstation1 ", "thinkstation1"),
            RetrievalProvenance::BuiltInPlace,
            "hostname comparison is case- and whitespace-insensitive"
        );
        // One of each is recorded as such rather than rounded to whichever is
        // more convenient.
        assert_eq!(
            RetrievalProvenance::classify("hz1", "thinkstation1", "thinkstation1"),
            RetrievalProvenance::Mixed
        );
        assert_eq!(
            RetrievalProvenance::classify("thinkstation1", "hz2", "thinkstation1"),
            RetrievalProvenance::Mixed
        );

        // Every classification says something different, in both fields: a
        // shared label or note would defeat the point of deriving it.
        let labels = [
            RetrievalProvenance::ScpFromBuilder,
            RetrievalProvenance::BuiltInPlace,
            RetrievalProvenance::Mixed,
        ]
        .map(RetrievalProvenance::label);
        let notes = [
            RetrievalProvenance::ScpFromBuilder,
            RetrievalProvenance::BuiltInPlace,
            RetrievalProvenance::Mixed,
        ]
        .map(RetrievalProvenance::note);
        assert_eq!(
            labels.iter().collect::<BTreeSet<_>>().len(),
            labels.len(),
            "each retrieval mode needs its own label"
        );
        assert_eq!(
            notes.iter().collect::<BTreeSet<_>>().len(),
            notes.len(),
            "each retrieval mode needs its own note"
        );
        assert!(
            !RetrievalProvenance::BuiltInPlace
                .note()
                .contains("copied to"),
            "an in-place build must not describe itself as copied in"
        );
    }

    #[test]
    fn readdir_stat_report_names_inode_resolution_mechanism_bd_fhb53() {
        assert_eq!(
            workload_mechanism_attribution(Workload::ReaddirStat8),
            "enumerate_then_stat_inode_resolution"
        );
        assert_eq!(
            workload_mechanism_attribution(Workload::WarmStat),
            "workload_specific_unattributed"
        );
        assert_eq!(
            workload_mechanism_owner(Workload::ReaddirStat8),
            "btrfs_inode_resolution_or_shared_fuse_floor"
        );
    }

    #[test]
    fn competitive_ratio_requires_absolute_arm_medians_bd_4sull() {
        assert!(absolute_arm_medians_are_valid(1.0, 1.0));
        assert!(!absolute_arm_medians_are_valid(0.0, 1.0));
        assert!(!absolute_arm_medians_are_valid(f64::NAN, 1.0));
    }

    #[test]
    fn balanced_square_scope_skips_host_wide_precondition_bd_fleet() {
        assert_eq!(
            parse_placement_scope("balanced-square").unwrap(),
            PlacementScope::BalancedSquare
        );
        assert_eq!(PlacementScope::BalancedSquare.label(), "balanced_square");
    }

    /// bd-pb85e: the baked fixture is restored for attribution, so the thing that
    /// keeps it from becoming a scorecard row must be mechanical rather than a
    /// convention someone remembers.
    #[test]
    fn baked_fixture_construction_is_parsed_and_can_never_be_banked() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cli = temp.path().join("ffs-cli");
        fs::write(&cli, b"placeholder").expect("write placeholder candidate");
        let base_args = |mode: &str| {
            vec![
                "--ffs-cli".to_owned(),
                cli.display().to_string(),
                "--harness-builder".to_owned(),
                "hz1".to_owned(),
                "--candidate-builder".to_owned(),
                "hz2".to_owned(),
                "--fixture-construction".to_owned(),
                mode.to_owned(),
            ]
        };

        let baked = parse_config_args(&base_args("baked"))
            .expect("parse baked fixture construction")
            .expect("normal invocation");
        assert_eq!(baked.fixture_construction, FixtureConstruction::Baked);
        assert!(
            !baked.fixture_construction.is_bankable(),
            "a baked fixture is the known-unfair pre-bd-plkzd construction and must \
             never be bankable, whatever the numbers come out at"
        );
        assert_eq!(
            baked.fixture_construction.bankability_reason(),
            "baked_with_mke2fs_d_known_unfair"
        );

        let seeded = parse_config_args(&base_args("seeded"))
            .expect("parse seeded fixture construction")
            .expect("normal invocation");
        assert_eq!(seeded.fixture_construction, FixtureConstruction::Seeded);
        assert!(seeded.fixture_construction.is_bankable());
        assert_eq!(
            seeded.fixture_construction.bankability_reason(),
            "seeded_through_mount"
        );

        // The DEFAULT is the bankable one. If this ever inverts, every row taken
        // without the flag silently becomes unfair, which is the exact defect
        // bd-plkzd fixed.
        let defaulted = parse_config_args(&[
            "--ffs-cli".to_owned(),
            cli.display().to_string(),
            "--harness-builder".to_owned(),
            "hz1".to_owned(),
            "--candidate-builder".to_owned(),
            "hz2".to_owned(),
        ])
        .expect("parse without the flag")
        .expect("normal invocation");
        assert_eq!(defaulted.fixture_construction, FixtureConstruction::Seeded);

        // An unknown mode is refused rather than silently defaulted — a typo must
        // not quietly produce a run of the wrong construction.
        assert!(parse_fixture_construction("indexed").is_err());
        assert!(parse_fixture_construction("").is_err());
    }

    #[test]
    fn fuse_dispatch_worker_option_reaches_both_fuse_arms_only_when_requested() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cli = temp.path().join("ffs-cli");
        fs::write(&cli, b"placeholder").expect("write placeholder candidate");
        let args = vec![
            "--ffs-cli".to_owned(),
            cli.display().to_string(),
            "--harness-builder".to_owned(),
            "hz1".to_owned(),
            "--candidate-builder".to_owned(),
            "hz2".to_owned(),
            "--fuse-workers".to_owned(),
            "8".to_owned(),
        ];
        let config = parse_config_args(&args)
            .expect("parse fuse worker option")
            .expect("normal invocation");
        assert_eq!(config.fuse_workers, Some(8));

        let mut enabled = Command::new("true");
        apply_fuse_dispatch_workers(&mut enabled, config.fuse_workers);
        let enabled_worker = enabled
            .get_envs()
            .find(|(key, _)| key.to_str() == Some("FFS_FUSE_WORKERS"))
            .and_then(|(_, value)| value)
            .expect("worker setting reaches FUSE launcher");
        assert_eq!(enabled_worker, "8");

        let mut banked = Command::new("true");
        apply_fuse_dispatch_workers(&mut banked, Config::default().fuse_workers);
        assert!(
            banked
                .get_envs()
                .all(|(key, _)| key.to_str() != Some("FFS_FUSE_WORKERS")),
            "omitting the option must preserve the serial banked dispatcher"
        );
    }

    #[test]
    fn fuse_dispatch_worker_option_rejects_more_than_supported_workers() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cli = temp.path().join("ffs-cli");
        fs::write(&cli, b"placeholder").expect("write placeholder candidate");
        let args = vec![
            "--ffs-cli".to_owned(),
            cli.display().to_string(),
            "--harness-builder".to_owned(),
            "hz1".to_owned(),
            "--candidate-builder".to_owned(),
            "hz2".to_owned(),
            "--fuse-workers".to_owned(),
            (MAX_CLIENT_THREADS + 1).to_string(),
        ];
        let error = parse_config_args(&args).expect_err("oversized worker count must fail");
        assert!(error.to_string().contains("--fuse-workers"));
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
        let clear: BTreeMap<Arm, BTreeSet<usize>> = FOUR_ARM_SET
            .into_iter()
            .map(|arm| (arm, expected.clone()))
            .collect();
        assert!(worker_cpu_pinning_is_clear(
            &clear,
            &expected,
            &FOUR_ARM_SET
        ));

        // A thread that escaped its binding onto an unbound CPU blocks the run.
        let mut escaped = clear.clone();
        escaped.insert(Arm::FuseB, BTreeSet::from([4, 5, 6, 7, 12]));
        assert!(!worker_cpu_pinning_is_clear(
            &escaped,
            &expected,
            &FOUR_ARM_SET
        ));

        // So does an arm that never covered the full bound set.
        let mut partial = clear.clone();
        partial.insert(Arm::KernelA, BTreeSet::from([4, 5]));
        assert!(!worker_cpu_pinning_is_clear(
            &partial,
            &expected,
            &FOUR_ARM_SET
        ));

        let mut missing = clear.clone();
        missing.remove(&Arm::KernelB);
        assert!(!worker_cpu_pinning_is_clear(
            &missing,
            &expected,
            &FOUR_ARM_SET
        ));

        // The extra candidate arms are gated too: a four-arm-clear map is not
        // clear for a six-arm run, so the added arms cannot skip the check.
        assert!(!worker_cpu_pinning_is_clear(
            &clear,
            &expected,
            &SIX_ARM_SET
        ));
        let six: BTreeMap<Arm, BTreeSet<usize>> = SIX_ARM_SET
            .into_iter()
            .map(|arm| (arm, expected.clone()))
            .collect();
        assert!(worker_cpu_pinning_is_clear(&six, &expected, &SIX_ARM_SET));
        let mut candidate_escaped = six;
        candidate_escaped.insert(Arm::CandidateBB, BTreeSet::from([4, 5, 6, 7, 12]));
        assert!(!worker_cpu_pinning_is_clear(
            &candidate_escaped,
            &expected,
            &SIX_ARM_SET
        ));
        assert!(!worker_thread_observation_is_clear(
            &BTreeMap::from([
                (Arm::KernelA, BTreeSet::from([8])),
                (Arm::KernelB, BTreeSet::from([8])),
                (Arm::FuseA, BTreeSet::from([8])),
                (Arm::FuseB, BTreeSet::from([8])),
            ]),
            8,
            &SIX_ARM_SET
        ));
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
        assert!(worker_thread_observation_is_clear(
            &observed,
            8,
            &FOUR_ARM_SET
        ));
        observed.get_mut(&Arm::KernelB).expect("kernel B").insert(7);
        assert!(!worker_thread_observation_is_clear(
            &observed,
            8,
            &FOUR_ARM_SET
        ));
        observed.insert(Arm::KernelB, BTreeSet::from([8]));
        assert!(!worker_thread_observation_is_clear(
            &observed,
            1,
            &FOUR_ARM_SET
        ));
        observed.remove(&Arm::FuseB);
        assert!(!worker_thread_observation_is_clear(
            &observed,
            8,
            &FOUR_ARM_SET
        ));
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

    fn candidate_samples(candidate_a: [[u64; 4]; 2], candidate_b: [[u64; 4]; 2]) -> TimedSamples {
        TimedSamples {
            values: BTreeMap::from([
                (Arm::KernelA, vec![10, 10, 10, 10]),
                (Arm::KernelB, vec![10, 10, 10, 10]),
                (Arm::FuseA, candidate_a[0].to_vec()),
                (Arm::FuseB, candidate_a[1].to_vec()),
                (Arm::CandidateBA, candidate_b[0].to_vec()),
                (Arm::CandidateBB, candidate_b[1].to_vec()),
            ]),
            physical_values: BTreeMap::new(),
            digests: BTreeMap::new(),
            observed_worker_threads: BTreeMap::new(),
            observed_worker_cpus: BTreeMap::new(),
            last_sequence: 0,
        }
    }

    /// This is the whole reason bd-3tqgc exists: a window effect that scales
    /// every arm of a round must leave the candidate-vs-candidate ratio
    /// untouched, because both candidate configurations ran inside that window.
    /// A cross-window estimator (comparing candidate A's rounds against
    /// candidate B's rounds taken later) would report the window instead.
    #[test]
    fn candidate_ratio_cancels_a_window_effect_that_a_cross_window_estimator_reports() {
        // Rounds 2 and 3 are 20% slower for everything on the host.
        let window = [1.0_f64, 1.0, 1.2, 1.2];
        let scale = |base: u64| -> [u64; 4] {
            let mut scaled = [0_u64; 4];
            for (slot, factor) in scaled.iter_mut().zip(window) {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                {
                    *slot = (base as f64 * factor).round() as u64;
                }
            }
            scaled
        };
        let samples = candidate_samples([scale(1000), scale(1000)], [scale(1100), scale(1100)]);
        let ratios = paired_group_log_ratios(&samples, CANDIDATE_B_ARMS, CANDIDATE_A_ARMS)
            .expect("candidate ratios");
        assert_eq!(ratios.len(), 1);
        assert!(
            (ratios[0].exp() - 1.1).abs() < 1e-9,
            "the 10% candidate effect must survive the window, got {}",
            ratios[0].exp()
        );

        // The same numbers read across windows: candidate A measured in the
        // quiet rounds, candidate B in the slow ones. That is what the current
        // sequential-window practice does, and it reports 1.32 instead of 1.10.
        let candidate_a_quiet = f64::from(1000_u16).ln();
        let candidate_b_slow = f64::from(1320_u16).ln();
        assert!(((candidate_b_slow - candidate_a_quiet).exp() - 1.32).abs() < 1e-9);
    }

    #[test]
    fn candidate_ratio_is_exactly_one_when_both_configurations_are_identical() {
        let arm = [900, 1100, 950, 1050];
        let samples = candidate_samples([arm, arm], [arm, arm]);
        let ratios = paired_group_log_ratios(&samples, CANDIDATE_B_ARMS, CANDIDATE_A_ARMS)
            .expect("candidate ratios");
        assert!(ratios.iter().all(|ratio| ratio.abs() < 1e-12));
        let ci = bootstrap_median_ci(&ratios, 11);
        assert!(candidate_cross_null_is_clear(false, Some(ci), 1.025));
    }

    #[test]
    fn candidate_aa_null_must_land_at_one_but_only_gates_the_identical_case() {
        let drifted = BootstrapMedianCi {
            median: 1.06,
            low: 1.05,
            high: 1.07,
        };
        // Two configurations that are supposed to be identical but measure 6%
        // apart mean the instrument is not measuring the knob.
        assert!(!candidate_cross_null_is_clear(false, Some(drifted), 1.025));
        // The same interval is a legitimate estimate when they do differ.
        assert!(candidate_cross_null_is_clear(true, Some(drifted), 1.025));
        assert!(candidate_cross_null_is_clear(false, None, 1.025));

        // A candidate claim is only decidable once it clears twice the worse of
        // the two CANDIDATE nulls: the kernel null is irrelevant here.
        let candidate_a_null = BootstrapMedianCi {
            median: 1.0,
            low: 0.995,
            high: 1.005,
        };
        let candidate_b_null = BootstrapMedianCi {
            median: 1.0,
            low: 0.99,
            high: 1.01,
        };
        let inside_floor = BootstrapMedianCi {
            median: 1.015,
            low: 1.012,
            high: 1.018,
        };
        let outside_floor = BootstrapMedianCi {
            median: 1.05,
            low: 1.04,
            high: 1.06,
        };
        assert!(!clears_twice_null_margin(
            inside_floor,
            candidate_a_null,
            candidate_b_null
        ));
        assert!(clears_twice_null_margin(
            outside_floor,
            candidate_a_null,
            candidate_b_null
        ));
    }

    #[test]
    fn candidate_comparison_selects_the_six_arm_schedule_and_a_legal_round_count() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cli = temp.path().join("ffs-cli");
        fs::write(&cli, b"placeholder").expect("write placeholder candidate");
        let base = vec![
            "--ffs-cli".to_owned(),
            cli.display().to_string(),
            "--harness-builder".to_owned(),
            "hz1".to_owned(),
            "--candidate-builder".to_owned(),
            "hz2".to_owned(),
        ];

        let banked = parse_config_args(&base)
            .expect("parse banked invocation")
            .expect("normal invocation");
        assert!(!banked.compares_candidates());
        assert_eq!(banked.pairs, 32);
        assert_eq!(measured_arms(banked.compares_candidates()).len(), 4);

        let mut compared = base.clone();
        compared.extend([
            "--candidate-b-env".to_owned(),
            "FFS_D9378_COUNT_MEMOIZED=0".to_owned(),
        ]);
        let config = parse_config_args(&compared)
            .expect("parse candidate comparison")
            .expect("normal invocation");
        assert!(config.compares_candidates());
        assert!(config.candidate_configurations_differ());
        assert_eq!(
            config.arm_env(Arm::CandidateBA),
            [("FFS_D9378_COUNT_MEMOIZED".to_owned(), "0".to_owned())]
        );
        // The first candidate configuration must stay the untouched baseline.
        assert!(config.arm_env(Arm::FuseA).is_empty());
        assert!(config.arm_env(Arm::KernelA).is_empty());
        // The banked default of 32 does not complete the six-arm square.
        assert_eq!(config.pairs, 36);

        let mut null_control = base.clone();
        null_control.push("--candidate-aa".to_owned());
        let control = parse_config_args(&null_control)
            .expect("parse candidate A/A control")
            .expect("normal invocation");
        assert!(control.compares_candidates());
        assert!(!control.candidate_configurations_differ());
        assert!(control.arm_env(Arm::CandidateBA).is_empty());

        // An explicit round count that does not complete the square is refused
        // rather than silently truncated.
        let mut unbalanced = compared.clone();
        unbalanced.extend(["--pairs".to_owned(), "32".to_owned()]);
        let error = parse_config_args(&unbalanced).expect_err("32 rounds cannot balance six arms");
        assert!(error.to_string().contains("multiple of 12"));

        let mut balanced = compared.clone();
        balanced.extend(["--pairs".to_owned(), "24".to_owned()]);
        assert_eq!(
            parse_config_args(&balanced)
                .expect("24 rounds balance six arms")
                .expect("normal invocation")
                .pairs,
            24
        );

        // Only FrankenFS runtime knobs may differ between the arms.
        let mut foreign = base.clone();
        foreign.extend([
            "--candidate-b-env".to_owned(),
            "LD_PRELOAD=/tmp/evil.so".to_owned(),
        ]);
        assert!(parse_config_args(&foreign).is_err());

        let mut malformed = base;
        malformed.extend(["--candidate-b-env".to_owned(), "FFS_NO_VALUE".to_owned()]);
        assert!(parse_config_args(&malformed).is_err());
    }

    fn fuse_mount_for_test(arm: Arm, runtime_knobs: &str) -> MountedArm {
        let child = Command::new("true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn placeholder daemon");
        MountedArm {
            arm,
            mountpoint: PathBuf::from(format!("/nonexistent/mount/{}", arm.label())),
            image: PathBuf::from(format!("/nonexistent/image/{}", arm.label())),
            mount_info: MountInfo {
                major_minor: "0:0".to_owned(),
                mountpoint: PathBuf::from("/nonexistent"),
                root: "/".to_owned(),
                mount_options: BTreeSet::new(),
                filesystem_type: "fuse".to_owned(),
                source: "frankenfs".to_owned(),
                super_options: BTreeSet::new(),
            },
            kind: MountedArmKind::Fuse {
                child,
                stdout_log: PathBuf::from("/nonexistent/stdout.log"),
                stderr_log: PathBuf::from("/nonexistent/stderr.log"),
                self_reported_sha256: String::new(),
                proc_exe_sha256: String::new(),
                pgo_profile_sha256: String::new(),
                runtime_knobs: runtime_knobs.to_owned(),
                candidate_env: Vec::new(),
            },
        }
    }

    /// The bd-d9378 failure, reproduced as a test: the env var was set, the ELF
    /// ignored it, and both "arms" ran the identical configuration. A naive
    /// implementation that trusts the harness's intent passes such a run and
    /// publishes a 1.0 as if it had measured something.
    #[test]
    fn candidate_knob_divergence_rejects_arms_that_resolved_the_same_configuration() {
        let counted = "count_memoized_requests=true,fuse_dispatch_workers=0";
        let uncounted = "count_memoized_requests=false,fuse_dispatch_workers=0";
        let diverged = vec![
            fuse_mount_for_test(Arm::FuseA, counted),
            fuse_mount_for_test(Arm::FuseB, counted),
            fuse_mount_for_test(Arm::CandidateBA, uncounted),
            fuse_mount_for_test(Arm::CandidateBB, uncounted),
        ];
        assert_eq!(
            candidate_knob_divergence(&diverged, true).expect("configurations diverged"),
            (counted.to_owned(), uncounted.to_owned())
        );

        let ignored_override = vec![
            fuse_mount_for_test(Arm::FuseA, counted),
            fuse_mount_for_test(Arm::FuseB, counted),
            fuse_mount_for_test(Arm::CandidateBA, counted),
            fuse_mount_for_test(Arm::CandidateBB, counted),
        ];
        let error = candidate_knob_divergence(&ignored_override, true)
            .expect_err("an ELF that ignored the knob must fail the run closed");
        assert!(error.to_string().contains("IDENTICAL runtime knobs"));

        // The A/A control has the opposite requirement.
        candidate_knob_divergence(&ignored_override, false).expect("A/A control agrees");
        assert!(candidate_knob_divergence(&diverged, false).is_err());

        // Replicas of one configuration disagreeing is never acceptable.
        let split_replicas = vec![
            fuse_mount_for_test(Arm::FuseA, counted),
            fuse_mount_for_test(Arm::FuseB, uncounted),
            fuse_mount_for_test(Arm::CandidateBA, uncounted),
            fuse_mount_for_test(Arm::CandidateBB, uncounted),
        ];
        assert!(candidate_knob_divergence(&split_replicas, true).is_err());
    }

    /// bd-plkzd: the htree control must accept a real indexed dump and reject
    /// the exact string `mke2fs -d` fixtures produce.
    ///
    /// Both samples are verbatim debugfs 1.47.2 output captured while
    /// reproducing `create_base_image`'s ext4 path at 32,768 entries — the
    /// linear one is what the comparator was silently measuring.
    #[test]
    fn htree_dump_discriminates_indexed_from_linear_directories_bd_plkzd() {
        let linear = "debugfs 1.47.2 (1-Jan-2025)\nhtree_dump: Not a hash-indexed directory\n";
        assert!(
            !htree_dump_reports_indexed(linear),
            "an unindexed directory must FAIL the control — this exact output is what \
             `mke2fs -d` produces and what went unnoticed"
        );

        let indexed = "debugfs 1.47.2 (1-Jan-2025)\nRoot node dump:\n\t Reserved zero: 0\n\t \
                       Hash Version: 1\n\t Info length: 8\n\t Indirect levels: 1\n";
        assert!(
            htree_dump_reports_indexed(indexed),
            "a genuinely hash-indexed directory must PASS"
        );

        // Empty / missing output is a failure, not a pass: a control that treats
        // "debugfs said nothing" as success is not a control at all.
        assert!(!htree_dump_reports_indexed(""));
        assert!(!htree_dump_reports_indexed("debugfs: command not found\n"));
    }

    /// bd-bt2dy: the during-run external-load policy, calibrated on the two REAL
    /// windows that motivated it rather than on invented numbers. Both figure sets
    /// are the harness's own `pre_measurement_cpu_busy` from the reports of
    /// 2026-08-08: the contended window (a peer's build) and the quiet one whose
    /// re-run confirmed the btrfs parallel-read win.
    #[test]
    fn external_load_policy_separates_the_two_real_windows_bd_bt2dy() {
        let placement: BTreeSet<usize> = [0, 1, 2, 3, 4, 5, 6, 7, 32, 33, 34, 35, 36, 37, 38, 39]
            .into_iter()
            .collect();

        // Contended: five off-placement CPUs above 0.2, one pinned at 1.000.
        let mut contended: BTreeMap<usize, f64> = BTreeMap::new();
        for cpu in 0..64 {
            contended.insert(cpu, 0.01);
        }
        for (cpu, load) in [(16, 1.000), (19, 0.61), (48, 0.44), (51, 0.33), (54, 0.26)] {
            contended.insert(cpu, load);
        }

        // Quiet: nothing off-placement above 0.170.
        let mut quiet: BTreeMap<usize, f64> = BTreeMap::new();
        for cpu in 0..64 {
            quiet.insert(cpu, 0.02);
        }
        quiet.insert(16, 0.170);
        quiet.insert(19, 0.09);

        assert_eq!(
            external_busy_cpu_count(&contended, &placement, EXTERNAL_BUSY_CPU_FRACTION),
            5,
            "the contended window's five loaded off-placement CPUs must all be seen"
        );
        assert_eq!(
            external_busy_cpu_count(&quiet, &placement, EXTERNAL_BUSY_CPU_FRACTION),
            0,
            "the quiet window's worst off-placement CPU (0.170) sits below the 0.25 limit, \
             so a quiet run must not be refused"
        );

        // Load ON the placement CPUs is the pre-run gate's business, not this one:
        // the bench itself saturates them, so counting them would refuse every run.
        let mut bench_running: BTreeMap<usize, f64> = BTreeMap::new();
        for cpu in 0..64 {
            bench_running.insert(cpu, 0.01);
        }
        for cpu in &placement {
            bench_running.insert(*cpu, 1.0);
        }
        assert_eq!(
            external_busy_cpu_count(&bench_running, &placement, EXTERNAL_BUSY_CPU_FRACTION),
            0,
            "a fully busy placement set is the bench doing its job and must never count \
             as external load"
        );
    }

    /// bd-bt2dy: the witness accepts a clean run and refuses a SUSTAINED-contended
    /// one. (An earlier version refused on a single sample; see the
    /// transient-versus-sustained test below for why that was wrong.)
    #[test]
    fn external_load_witness_fails_closed_on_sustained_contention_bd_bt2dy() {
        let placement: BTreeSet<usize> = (0..8).collect();
        let mut busy_quiet: BTreeMap<usize, f64> = (0..64).map(|c| (c, 0.02)).collect();
        busy_quiet.insert(3, 0.99); // placement CPU: the bench, ignored
        let mut busy_loaded: BTreeMap<usize, f64> = (0..64).map(|c| (c, 0.02)).collect();
        for cpu in [20, 21, 22, 23] {
            busy_loaded.insert(cpu, 0.8);
        }

        let mut clean = ExternalLoadWitness::default();
        for _ in 0..10 {
            clean.observe(&busy_quiet, &placement, MAX_EXTERNAL_BUSY_CPUS);
        }
        assert!(clean.clean());
        assert_eq!(clean.samples, 10);
        assert_eq!(clean.max_busy_cpus, 0);

        // Sustained contention refuses: the synthetic negative test's shape.
        let mut sustained = ExternalLoadWitness::default();
        for _ in 0..23 {
            sustained.observe(&busy_loaded, &placement, MAX_EXTERNAL_BUSY_CPUS);
        }
        assert!(
            !sustained.clean(),
            "100% contended samples must refuse the run"
        );
        assert_eq!(sustained.over_limit_samples, 23);
        assert_eq!(sustained.max_consecutive_over_limit, 23);
        assert_eq!(sustained.max_busy_cpus, 4);
        assert!(sustained.peak_mean_busy > 0.0);

        // Exactly at the limit is permitted: two busy off-placement CPUs is the
        // documented tolerance for ordinary background daemons.
        let mut at_limit: BTreeMap<usize, f64> = (0..64).map(|c| (c, 0.02)).collect();
        at_limit.insert(30, 0.9);
        at_limit.insert(31, 0.9);
        let mut edge = ExternalLoadWitness::default();
        edge.observe(&at_limit, &placement, MAX_EXTERNAL_BUSY_CPUS);
        assert!(edge.clean(), "2 busy CPUs is at the limit, not over it");
    }

    /// bd-bt2dy: the SUSTAINED-versus-TRANSIENT correction, pinned against the
    /// three real datasets that produced it.
    ///
    /// The first version of this gate refused on a single contended sample, and it
    /// was measured wrong within the hour: it rejected two consecutive warm-stat
    /// runs on an idle box, on 2 of 71 and 1 of 70 samples respectively, with no
    /// co-tenant present — just ordinary background churn across 60 watched CPUs.
    /// A median-of-32-pairs crossover absorbs a perturbation touching a couple of
    /// pairs; sustained load biases every pair. This test holds that line.
    #[test]
    fn external_load_tolerates_transient_blips_but_not_sustained_load_bd_bt2dy() {
        let placement: BTreeSet<usize> = (0..4).collect();
        let quiet: BTreeMap<usize, f64> = (0..64).map(|c| (c, 0.02)).collect();
        let mut loaded: BTreeMap<usize, f64> = (0..64).map(|c| (c, 0.02)).collect();
        for cpu in [16, 19, 48, 51] {
            loaded.insert(cpu, 1.0);
        }

        // Replay a run's contended/total counts with the contended samples spread
        // out, which is what the quiet box actually produced — background churn,
        // not a burst.
        let replay = |over: usize, total: usize| -> ExternalLoadWitness {
            let mut w = ExternalLoadWitness::default();
            let stride = if over == 0 { total + 1 } else { total / over };
            for i in 0..total {
                if over > 0 && i % stride == 0 && w.over_limit_samples < over {
                    w.observe(&loaded, &placement, MAX_EXTERNAL_BUSY_CPUS);
                } else {
                    w.observe(&quiet, &placement, MAX_EXTERNAL_BUSY_CPUS);
                }
            }
            w
        };

        // warm-stat run 1: 2 of 71 = 2.8%. It was REFUSED by the first version;
        // it must pass now. This assertion is the whole point of the correction.
        let r1 = replay(2, 71);
        assert_eq!(r1.over_limit_samples, 2);
        assert!(
            r1.clean(),
            "2 of 71 scattered contended samples on an idle box must not refuse a run"
        );

        // warm-stat run 2: 1 of 70 = 1.4%.
        assert!(replay(1, 70).clean(), "1 of 70 must not refuse a run");

        // The synthetic negative test: 23 of 23 = 100%, must still refuse.
        assert!(
            !replay(23, 23).clean(),
            "sustained contention must still refuse"
        );

        // The fraction boundary, both sides.
        assert!(replay(10, 100).clean(), "10% is the limit, not over it");
        assert!(!replay(11, 100).clean(), "11% exceeds the fraction limit");

        // A dense burst refuses even when the fraction is small: three consecutive
        // contended samples is 3% of a 100-sample run — under the fraction limit —
        // but is a real event rather than sampling noise.
        let mut burst = ExternalLoadWitness::default();
        for i in 0..100 {
            if (40..43).contains(&i) {
                burst.observe(&loaded, &placement, MAX_EXTERNAL_BUSY_CPUS);
            } else {
                burst.observe(&quiet, &placement, MAX_EXTERNAL_BUSY_CPUS);
            }
        }
        assert_eq!(burst.max_consecutive_over_limit, 3);
        assert!(burst.contended_fraction() < MAX_CONTENDED_SAMPLE_FRACTION);
        assert!(
            !burst.clean(),
            "3 consecutive contended samples must refuse even at 3% of the run"
        );
    }

    /// bd-c5210: every workload whose fixture directory `mke2fs -d` would bake in
    /// must be seeded through the mount instead, and no other workload may be.
    /// The list is the whole finding — it came from measuring each fixture shape
    /// (scripts/cmp_fixture_audit.sh), not from reading the code.
    #[test]
    fn only_the_indexable_fixture_directories_are_seeded_through_the_mount_bd_c5210() {
        assert_eq!(
            SeededFixture::for_workload(Workload::ReaddirStat8),
            Some(SeededFixture::LargeDirectory)
        );
        // Both parallel-read variants share one fixture, so both must be covered;
        // the cold-cache arm is the one where an unindexed lookup becomes real I/O.
        assert_eq!(
            SeededFixture::for_workload(Workload::ParallelRead8),
            Some(SeededFixture::ParallelRead)
        );
        assert_eq!(
            SeededFixture::for_workload(Workload::ParallelRead8ColdCache),
            Some(SeededFixture::ParallelRead)
        );

        // The rest are clean for a reason, not by luck: parallel-metadata-write and
        // create-delete-storm bake EMPTY directories and create through the mount at
        // measure time; warm-stat adds no directory; fsync and bulk-durable are one
        // file each at the fixture root; xattr is three files at the root, measured
        // unindexed on BOTH construction paths (the audit's negative control).
        for workload in [
            Workload::WarmStat,
            Workload::ParallelMetadataWrite,
            Workload::CreateDeleteStorm,
            Workload::FsyncJournalCommit,
            Workload::BulkDurableWrite,
            Workload::XattrGetListReport,
        ] {
            assert_eq!(
                SeededFixture::for_workload(workload),
                None,
                "{workload:?} has no directory that mke2fs -d could leave unindexed; \
                 seeding it through a mount would add a mount for nothing"
            );
        }

        assert_eq!(SeededFixture::LargeDirectory.dir_name(), "large-directory");
        assert_eq!(SeededFixture::ParallelRead.dir_name(), "parallel-read");
    }

    /// bd-c5210: moving the parallel-read files from `mke2fs -d` to the mount must
    /// not change a single byte of their contents. `parallel_read_batch` folds them
    /// into a digest that four-arm parity compares, so a payload drift here would
    /// surface as a parity failure rather than as anything legible.
    #[test]
    fn seeding_parallel_read_through_the_mount_writes_the_same_bytes_as_before_bd_c5210() {
        let temp = tempfile::tempdir().expect("tempdir");
        let seeded = temp.path().join("seeded");
        let baked = temp.path().join("baked");
        fs::create_dir(&seeded).expect("seeded dir");
        fs::create_dir(&baked).expect("baked dir");

        for index in [0_usize, 1, 7, 255] {
            SeededFixture::ParallelRead
                .create_entry(&seeded, index)
                .expect("seed one parallel-read file through the fixture factory");
            // The pre-bd-c5210 call, verbatim from the old create_fixture_tree arm.
            write_fixture_file(
                &baked.join(format!("read-{index:06}.bin")),
                PARALLEL_READ_FILE_BYTES,
                index,
            )
            .expect("bake one parallel-read file the old way");

            let name = format!("read-{index:06}.bin");
            let from_seed = fs::read(seeded.join(&name)).expect("read seeded file");
            let from_bake = fs::read(baked.join(&name)).expect("read baked file");
            assert_eq!(
                from_seed.len(),
                PARALLEL_READ_FILE_BYTES,
                "the seeded file must keep its size"
            );
            assert_eq!(
                from_seed, from_bake,
                "seeded and baked payloads must be byte-identical for file {index}"
            );
        }

        // And the names must still be what the workload's readdir + sort expects.
        let mut names: Vec<String> = fs::read_dir(&seeded)
            .expect("list seeded dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "read-000000.bin".to_owned(),
                "read-000001.bin".to_owned(),
                "read-000007.bin".to_owned(),
                "read-000255.bin".to_owned(),
            ]
        );
    }

    #[test]
    fn mount_self_report_requires_the_effective_runtime_knob_line() {
        let temp = tempfile::tempdir().expect("tempdir");
        let sha = "a".repeat(64);
        let pgo = "b".repeat(64);
        let complete = temp.path().join("complete.log");
        fs::write(
            &complete,
            format!(
                "mount_bench_evidence,binary_sha256={sha}\n\
                 mount_build_profile,pgo_profile_sha256={pgo}\n\
                 mount_candidate_knobs,count_memoized_requests=true,fuse_dispatch_workers=0\n"
            ),
        )
        .expect("write mount log");
        let report = parse_mount_self_report(&complete, true).expect("parse self report");
        assert_eq!(report.identity.binary_sha256, sha);
        assert_eq!(
            report.runtime_knobs,
            "count_memoized_requests=true,fuse_dispatch_workers=0"
        );

        // An ELF too old to report its effective knobs cannot be an arm of a
        // candidate comparison, so the run fails at mount rather than at
        // publication.
        let legacy = temp.path().join("legacy.log");
        fs::write(
            &legacy,
            format!(
                "mount_bench_evidence,binary_sha256={sha}\n\
                 mount_build_profile,pgo_profile_sha256={pgo}\n"
            ),
        )
        .expect("write legacy mount log");
        assert!(parse_mount_self_report(&legacy, true).is_err());

        // A single-configuration run has no knob divergence to prove, so it may
        // re-measure a historical ELF — and records the absence verbatim rather
        // than a knob list it never observed.
        let tolerated = parse_mount_self_report(&legacy, false).expect("parse legacy self report");
        assert_eq!(tolerated.runtime_knobs, UNREPORTED_RUNTIME_KNOBS);
        assert!(!UNREPORTED_RUNTIME_KNOBS.is_empty());
        assert!(!UNREPORTED_RUNTIME_KNOBS.contains('='));

        // Tolerating absence must not tolerate ambiguity: two disagreeing knob
        // lines is a broken log under either requirement.
        let ambiguous = temp.path().join("ambiguous.log");
        fs::write(
            &ambiguous,
            format!(
                "mount_bench_evidence,binary_sha256={sha}\n\
                 mount_build_profile,pgo_profile_sha256={pgo}\n\
                 mount_candidate_knobs,count_memoized_requests=true\n\
                 mount_candidate_knobs,count_memoized_requests=false\n"
            ),
        )
        .expect("write ambiguous mount log");
        assert!(parse_mount_self_report(&ambiguous, false).is_err());
        assert!(parse_mount_self_report(&ambiguous, true).is_err());
    }

    /// The sentinel must fail an A/B on its own, independently of the mount-time
    /// gate — two historical daemons both reporting "unreported" are identical,
    /// not different, so they can never masquerade as a divergent A/B.
    #[test]
    fn unreported_knobs_cannot_pass_a_candidate_comparison() {
        let mounts = vec![
            fuse_mount_for_test(Arm::FuseA, UNREPORTED_RUNTIME_KNOBS),
            fuse_mount_for_test(Arm::FuseB, UNREPORTED_RUNTIME_KNOBS),
            fuse_mount_for_test(Arm::CandidateBA, UNREPORTED_RUNTIME_KNOBS),
            fuse_mount_for_test(Arm::CandidateBB, UNREPORTED_RUNTIME_KNOBS),
        ];
        assert!(candidate_knob_divergence(&mounts, true).is_err());
    }
}
