#![forbid(unsafe_code)]

//! Benchmark taxonomy, host profiles, and acceptance envelopes.
//!
//! Maps every benchmark operation to an owning subsystem (family), defines host
//! environment profiles for normalization, and encodes noise-aware regression
//! thresholds with documented rationale.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use tracing::{debug, info, warn};

// ── Benchmark Families ─────────────────────────────────────────────────────

/// Top-level classification for benchmark operations.
///
/// Each family groups benchmarks by the subsystem they stress. Families have
/// distinct noise characteristics that justify independent threshold tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkFamily {
    /// On-disk structure parsing (superblock, inode, dir block, extent tree).
    /// CPU-bound, low variance, sub-millisecond expected. Tight thresholds safe.
    Parser,
    /// FUSE mount lifecycle (cold, warm, recovery).
    /// System-call-heavy, FUSE kernel roundtrip, high variance. Wide thresholds.
    Mount,
    /// CLI/harness metadata operations (parity, inspect, scrub, check-fixtures).
    /// Mixed I/O + CPU, moderate variance.
    MetadataOps,
    /// Block cache policy benchmarks (ARC, S3-FIFO workload scenarios).
    /// Memory-allocation-heavy, moderate variance from allocator behavior.
    BlockCache,
    /// Write path benchmarks (sequential, random, fsync single/batch).
    /// I/O-bound, moderate variance from filesystem layer.
    WritePath,
    /// Concurrency benchmarks (Bw-tree, WAL throughput, MVCC commit, RCU/RwLock).
    /// Thread-scheduling-sensitive, high variance. Wide thresholds.
    Concurrency,
    /// Repair/self-healing benchmarks (scrub, RaptorQ encode/decode).
    /// CPU-heavy (erasure coding), moderate variance.
    Repair,
    /// Degraded-mode benchmarks (under backpressure, partial corruption).
    /// Intentionally stressed, high variance. Widest thresholds.
    DegradedMode,
}

impl BenchmarkFamily {
    /// Human-readable label for reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Parser => "Parser (on-disk structure parsing)",
            Self::Mount => "Mount (FUSE lifecycle)",
            Self::MetadataOps => "Metadata Ops (CLI/harness)",
            Self::BlockCache => "Block Cache (ARC/S3-FIFO workloads)",
            Self::WritePath => "Write Path (seq/random/fsync)",
            Self::Concurrency => "Concurrency (Bw-tree/WAL/MVCC)",
            Self::Repair => "Repair (scrub/RaptorQ)",
            Self::DegradedMode => "Degraded Mode (backpressure/corruption)",
        }
    }

    /// Owning crate for this family.
    #[must_use]
    pub const fn owning_crate(self) -> &'static str {
        match self {
            Self::Parser => "ffs-ondisk",
            Self::Mount => "ffs-fuse",
            Self::MetadataOps => "ffs-harness",
            Self::BlockCache | Self::WritePath => "ffs-block",
            Self::Concurrency => "ffs-mvcc",
            Self::Repair => "ffs-repair",
            Self::DegradedMode => "ffs-core",
        }
    }

    /// Default noise tolerance based on the family's variance characteristics.
    #[must_use]
    pub const fn default_envelope(self) -> AcceptanceEnvelope {
        match self {
            // CPU-bound, low variance → tight thresholds
            Self::Parser => AcceptanceEnvelope {
                warn_percent: 8.0,
                fail_percent: 15.0,
                noise_floor_percent: 3.0,
                rationale: "CPU-bound parsing with sub-ms latency; \
                            variance dominated by instruction cache effects. \
                            3% noise floor covers normal run-to-run jitter.",
            },
            // FUSE kernel roundtrip → wide thresholds
            Self::Mount => AcceptanceEnvelope {
                warn_percent: 25.0,
                fail_percent: 50.0,
                noise_floor_percent: 10.0,
                rationale: "FUSE mounts involve kernel VFS, fusermount3 exec, \
                            and device setup. 10% noise floor reflects system \
                            call scheduling variance across host loads.",
            },
            // Mixed I/O + CPU → moderate
            Self::MetadataOps => AcceptanceEnvelope {
                warn_percent: 10.0,
                fail_percent: 20.0,
                noise_floor_percent: 5.0,
                rationale: "CLI commands read disk images and compute parity. \
                            Moderate I/O mix produces 5% typical variance.",
            },
            // Memory-allocation-heavy → moderate
            Self::BlockCache => AcceptanceEnvelope {
                warn_percent: 12.0,
                fail_percent: 25.0,
                noise_floor_percent: 5.0,
                rationale: "Cache eviction benchmarks are sensitive to allocator \
                            behavior and NUMA topology. 5% noise floor covers \
                            jemalloc/system allocator variance.",
            },
            // I/O-bound → moderate
            Self::WritePath => AcceptanceEnvelope {
                warn_percent: 12.0,
                fail_percent: 25.0,
                noise_floor_percent: 5.0,
                rationale: "Write-path latency depends on filesystem sync \
                            behavior and I/O scheduler. 5% noise floor.",
            },
            // Thread-scheduling-sensitive → wide
            Self::Concurrency => AcceptanceEnvelope {
                warn_percent: 20.0,
                fail_percent: 40.0,
                noise_floor_percent: 8.0,
                rationale: "Multi-threaded benchmarks (Bw-tree, WAL, RCU) are \
                            sensitive to OS scheduler decisions, core migration, \
                            and contention. 8% noise floor for scheduling jitter.",
            },
            // CPU-heavy erasure coding → moderate
            Self::Repair => AcceptanceEnvelope {
                warn_percent: 10.0,
                fail_percent: 20.0,
                noise_floor_percent: 5.0,
                rationale: "RaptorQ encode/decode is compute-bound with \
                            predictable variance. Same envelope as metadata ops.",
            },
            // Intentionally stressed → widest
            Self::DegradedMode => AcceptanceEnvelope {
                warn_percent: 30.0,
                fail_percent: 60.0,
                noise_floor_percent: 15.0,
                rationale: "Degraded-mode benchmarks operate under backpressure \
                            or partial corruption. High variance is expected \
                            and acceptable — the goal is behavior correctness, \
                            not tight latency bounds.",
            },
        }
    }
}

// ── Acceptance Envelopes ───────────────────────────────────────────────────

/// Regression detection thresholds with noise tolerance.
///
/// Deltas within `noise_floor_percent` are always ignored (status = Ok).
/// Above the noise floor, `warn_percent` and `fail_percent` gate CI.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AcceptanceEnvelope {
    /// Percentage regression that triggers a CI warning.
    pub warn_percent: f64,
    /// Percentage regression that fails CI.
    pub fail_percent: f64,
    /// Percentage below which deltas are considered noise and ignored.
    pub noise_floor_percent: f64,
    /// Human-readable rationale for threshold choices.
    #[serde(default, skip_serializing_if = "str::is_empty")]
    pub rationale: &'static str,
}

impl AcceptanceEnvelope {
    /// Classify an observed delta percentage against this envelope.
    #[must_use]
    pub fn classify(&self, delta_percent: f64) -> EnvelopeVerdict {
        if delta_percent <= self.noise_floor_percent {
            EnvelopeVerdict::Noise
        } else if delta_percent <= self.warn_percent {
            EnvelopeVerdict::Ok
        } else if delta_percent <= self.fail_percent {
            EnvelopeVerdict::Warn
        } else {
            EnvelopeVerdict::Fail
        }
    }
}

/// Result of classifying a delta against an acceptance envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeVerdict {
    /// Delta is within the noise floor — effectively zero.
    Noise,
    /// Delta is above noise but within warning threshold.
    Ok,
    /// Delta exceeds warning threshold but not failure threshold.
    Warn,
    /// Delta exceeds failure threshold — CI should block.
    Fail,
}

// ── Host Profiles ──────────────────────────────────────────────────────────

/// Describes the host environment where benchmarks run.
///
/// Used for baseline normalization: results from different host profiles
/// should not be directly compared without adjustment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostProfile {
    /// Profile identifier (e.g., "csd-threadripper", "ci-github-actions").
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// CPU model string (from /proc/cpuinfo or equivalent).
    pub cpu_model: String,
    /// Minimum physical core count for this profile.
    pub min_cores: u32,
    /// Minimum memory in GiB for this profile.
    pub min_memory_gib: u32,
    /// Whether FUSE mount benchmarks are available.
    pub fuse_available: bool,
    /// Normalization factor relative to the reference profile (1.0 = reference).
    /// A profile with factor 0.5 runs benchmarks ~2x slower than reference.
    pub normalization_factor: f64,
}

impl HostProfile {
    /// The reference host profile (csd — development server).
    #[must_use]
    pub fn reference() -> Self {
        Self {
            id: "csd-threadripper".to_owned(),
            description: "AMD Ryzen Threadripper PRO 5995WX 64-core development server".to_owned(),
            cpu_model: "AMD Ryzen Threadripper PRO 5995WX 64-Cores".to_owned(),
            min_cores: 64,
            min_memory_gib: 512,
            fuse_available: true,
            normalization_factor: 1.0,
        }
    }

    /// GitHub Actions CI runner profile.
    #[must_use]
    pub fn ci_github_actions() -> Self {
        Self {
            id: "ci-github-actions".to_owned(),
            description: "GitHub Actions ubuntu-latest (2-4 vCPU, 7-16GB RAM)".to_owned(),
            cpu_model: "GitHub Actions runner".to_owned(),
            min_cores: 2,
            min_memory_gib: 7,
            fuse_available: false, // FUSE requires privileged containers
            normalization_factor: 0.15,
        }
    }

    /// Contabo VPS worker profile (used by rch).
    #[must_use]
    pub fn rch_contabo_worker() -> Self {
        Self {
            id: "rch-contabo".to_owned(),
            description: "Contabo VPS 8-core worker (rch fleet)".to_owned(),
            cpu_model: "Contabo VPS".to_owned(),
            min_cores: 8,
            min_memory_gib: 16,
            fuse_available: false,
            normalization_factor: 0.25,
        }
    }

    /// Adjust a threshold by the normalization factor.
    ///
    /// On slower hosts, thresholds should be wider (more tolerance) to avoid
    /// false regression signals from hardware differences.
    #[must_use]
    pub fn adjust_threshold(&self, base_threshold_percent: f64) -> f64 {
        if self.normalization_factor <= 0.0 || self.normalization_factor >= 1.0 {
            return base_threshold_percent;
        }
        // Widen by inverse of normalization: a 0.25 host gets 4x wider thresholds,
        // capped at 3x the base to avoid meaningless bounds.
        let scale = (1.0 / self.normalization_factor).min(3.0);
        base_threshold_percent * scale
    }
}

// ── Taxonomy ───────────────────────────────────────────────────────────────

/// A single benchmark operation entry in the taxonomy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkEntry {
    /// Unique operation ID (matches `thresholds.toml` keys and baseline JSON).
    pub operation_id: String,
    /// Family classification.
    pub family: BenchmarkFamily,
    /// Primary metric type.
    pub metric: MetricType,
    /// Crate that owns the benchmark implementation.
    pub owning_crate: String,
    /// One-line description of what this benchmark measures.
    pub description: String,
    /// Per-operation acceptance envelope override (None = use family default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_override: Option<SerializableEnvelope>,
}

/// Metric type for a benchmark operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricType {
    /// Latency (lower is better), measured in microseconds.
    Latency,
    /// Throughput (higher is better), measured in ops/sec or MB/sec.
    Throughput,
    /// Hit rate (higher is better), measured as percentage.
    HitRate,
    /// Memory overhead ratio (lower is better).
    OverheadRatio,
}

/// Serializable version of `AcceptanceEnvelope` (without `&'static str`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SerializableEnvelope {
    pub warn_percent: f64,
    pub fail_percent: f64,
    pub noise_floor_percent: f64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rationale: String,
}

/// The complete benchmark taxonomy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Taxonomy {
    /// Taxonomy schema version.
    pub version: u32,
    /// All registered benchmark operations, keyed by operation ID.
    pub operations: BTreeMap<String, BenchmarkEntry>,
    /// Known host profiles, keyed by profile ID.
    pub host_profiles: BTreeMap<String, HostProfile>,
}

impl Taxonomy {
    /// Build the canonical taxonomy from the known benchmark inventory.
    #[must_use]
    pub fn canonical() -> Self {
        let mut operations = BTreeMap::new();
        Self::register_metadata_ops(&mut operations);
        Self::register_block_cache_ops(&mut operations);
        Self::register_write_path_ops(&mut operations);
        Self::register_mount_ops(&mut operations);
        Self::register_concurrency_ops(&mut operations);
        Self::register_repair_ops(&mut operations);
        Self::register_extent_ops(&mut operations);

        let mut host_profiles = BTreeMap::new();
        for profile in [
            HostProfile::reference(),
            HostProfile::ci_github_actions(),
            HostProfile::rch_contabo_worker(),
        ] {
            host_profiles.insert(profile.id.clone(), profile);
        }

        Self {
            version: 1,
            operations,
            host_profiles,
        }
    }

    fn insert_ops(
        ops: &mut BTreeMap<String, BenchmarkEntry>,
        entries: &[(&str, &str)],
        family: BenchmarkFamily,
        crate_name: &str,
    ) {
        for &(id, desc) in entries {
            ops.insert(
                id.to_owned(),
                BenchmarkEntry {
                    operation_id: id.to_owned(),
                    family,
                    metric: MetricType::Latency,
                    owning_crate: crate_name.to_owned(),
                    description: desc.to_owned(),
                    envelope_override: None,
                },
            );
        }
    }

    fn register_metadata_ops(ops: &mut BTreeMap<String, BenchmarkEntry>) {
        Self::insert_ops(
            ops,
            &[
                (
                    "metadata_parity_cli",
                    "CLI parity report generation latency",
                ),
                (
                    "metadata_parity_harness",
                    "Harness parity report generation latency",
                ),
                (
                    "fixture_validation",
                    "Conformance fixture check-fixtures latency",
                ),
                (
                    "read_metadata_inspect_ext4_reference",
                    "CLI inspect of ext4 8MB reference image",
                ),
                (
                    "read_metadata_scrub_ext4_reference",
                    "CLI scrub of ext4 8MB reference image",
                ),
                (
                    "cli_metadata_parse_conformance",
                    "Criterion metadata parse conformance fixture latency",
                ),
            ],
            BenchmarkFamily::MetadataOps,
            "ffs-harness",
        );
    }

    fn register_block_cache_ops(ops: &mut BTreeMap<String, BenchmarkEntry>) {
        for policy in ["arc", "s3fifo"] {
            for (workload, desc) in [
                ("sequential_scan", "4-pass sequential scan"),
                ("zipf_distribution", "Zipf(1.07) random access"),
                ("mixed_seq70_hot30", "70% sequential + 30% hot set"),
                (
                    "concurrent_hot_read_64threads",
                    "64-thread hot-cache read burst",
                ),
                ("compile_like", "Metadata hot blocks + file I/O mix"),
                ("database_like", "B-tree simulation workload"),
            ] {
                let id = format!("block_cache_{policy}_{workload}");
                ops.insert(
                    id.clone(),
                    BenchmarkEntry {
                        operation_id: id,
                        family: BenchmarkFamily::BlockCache,
                        metric: MetricType::Latency,
                        owning_crate: "ffs-block".to_owned(),
                        description: format!("{policy} policy: {desc}"),
                        envelope_override: None,
                    },
                );
            }
        }
        for policy in ["arc", "s3fifo"] {
            let id = format!("block_cache_sharded_{policy}_concurrent_hot_read_64threads");
            ops.insert(
                id.clone(),
                BenchmarkEntry {
                    operation_id: id,
                    family: BenchmarkFamily::BlockCache,
                    metric: MetricType::Latency,
                    owning_crate: "ffs-block".to_owned(),
                    description: format!("sharded {policy} policy: 64-thread hot-cache read burst"),
                    envelope_override: None,
                },
            );
        }
    }

    fn register_write_path_ops(ops: &mut BTreeMap<String, BenchmarkEntry>) {
        Self::insert_ops(
            ops,
            &[
                ("write_seq_4k", "Sequential 4K block writes"),
                ("write_random_4k", "Random 4K block writes"),
                ("fsync_single_write", "Single 4K write + fsync"),
                ("fsync_batch_100", "100x 4K writes + fsync batch"),
            ],
            BenchmarkFamily::WritePath,
            "ffs-block",
        );
    }

    fn register_mount_ops(ops: &mut BTreeMap<String, BenchmarkEntry>) {
        Self::insert_ops(
            ops,
            &[
                ("mount_cold", "Cold FUSE mount latency (no page cache)"),
                ("mount_warm", "Warm FUSE mount latency (primed page cache)"),
                (
                    "mount_recovery",
                    "Mount with journal recovery replay latency",
                ),
            ],
            BenchmarkFamily::Mount,
            "ffs-fuse",
        );

        // Mount runtime mode comparison benchmarks (bd-h6nz.2.5).
        Self::insert_ops(
            ops,
            &[
                (
                    "mount_runtime_per_core_route_inode",
                    "Per-core dispatcher inode routing latency",
                ),
                (
                    "mount_runtime_per_core_route_lookup",
                    "Per-core dispatcher lookup routing latency",
                ),
                (
                    "mount_runtime_per_core_should_steal",
                    "Per-core work-stealing decision latency",
                ),
                (
                    "mount_runtime_per_core_aggregate_metrics",
                    "Per-core aggregate metrics collection latency",
                ),
                (
                    "mount_runtime_metrics_record_throughput",
                    "AtomicMetrics record_ok throughput (ops/sec)",
                ),
            ],
            BenchmarkFamily::Mount,
            "ffs-fuse",
        );

        Self::register_degraded_mode_ops(ops);
    }

    fn register_degraded_mode_ops(ops: &mut BTreeMap<String, BenchmarkEntry>) {
        let before = ops.len();

        // Backpressure decision latency at each pressure level (bd-h6nz.2.5)
        for (suffix, desc) in [
            ("normal", "Backpressure decision latency under normal load"),
            (
                "degraded",
                "Backpressure decision latency under degraded state",
            ),
            (
                "emergency",
                "Backpressure shed decision latency under emergency state",
            ),
        ] {
            let id = format!("mount_runtime_backpressure_{suffix}");
            ops.insert(
                id.clone(),
                BenchmarkEntry {
                    operation_id: id,
                    family: BenchmarkFamily::DegradedMode,
                    metric: MetricType::Latency,
                    owning_crate: "ffs-fuse".to_owned(),
                    description: desc.to_owned(),
                    envelope_override: None,
                },
            );
        }

        // Degraded-mode throughput benchmarks (bd-h6nz.5.4)
        for (level, desc) in [
            (
                "warning",
                "Warning-level (background paused, foreground unaffected)",
            ),
            (
                "critical",
                "Critical-level (writes throttled, metadata writes shed)",
            ),
        ] {
            for op_type in ["read", "write", "mixed"] {
                let id = format!("degraded_throughput_{level}_{op_type}");
                ops.insert(
                    id.clone(),
                    BenchmarkEntry {
                        operation_id: id,
                        family: BenchmarkFamily::DegradedMode,
                        metric: MetricType::Throughput,
                        owning_crate: "ffs-fuse".to_owned(),
                        description: format!("{desc}: {op_type} throughput under pressure"),
                        envelope_override: None,
                    },
                );
            }
        }

        // FSM tick overhead
        ops.insert(
            "degraded_fsm_tick_latency".to_owned(),
            BenchmarkEntry {
                operation_id: "degraded_fsm_tick_latency".to_owned(),
                family: BenchmarkFamily::DegradedMode,
                metric: MetricType::Latency,
                owning_crate: "ffs-core".to_owned(),
                description: "DegradationFsm tick latency (pressure sample processing)".to_owned(),
                envelope_override: None,
            },
        );

        // Multi-threaded backpressure contention
        ops.insert(
            "degraded_backpressure_contention_4threads".to_owned(),
            BenchmarkEntry {
                operation_id: "degraded_backpressure_contention_4threads".to_owned(),
                family: BenchmarkFamily::DegradedMode,
                metric: MetricType::Throughput,
                owning_crate: "ffs-fuse".to_owned(),
                description: "4-thread concurrent BackpressureGate.check() throughput".to_owned(),
                envelope_override: None,
            },
        );

        let added = ops.len() - before;
        debug!(
            target: "ffs::benchmark_taxonomy",
            degraded_mode_ops = added,
            scenario_id = "degraded_mode_benchmark_registration",
            operation_id = "register_degraded_mode_ops",
            "degraded_mode_benchmark_ops_registered"
        );
    }

    fn register_concurrency_ops(ops: &mut BTreeMap<String, BenchmarkEntry>) {
        Self::insert_ops(
            ops,
            &[
                ("wal_commit_4k_sync", "WAL 4K commit with fsync"),
                ("mvcc_commit_fcw", "MVCC first-committer-wins commit"),
                (
                    "mvcc_commit_ssi_5reads",
                    "MVCC SSI commit with 5-read read set",
                ),
                (
                    "wal_write_amplification_1block",
                    "WAL write amplification ratio for 1-block txn",
                ),
                (
                    "wal_write_amplification_16block",
                    "WAL write amplification ratio for 16-block txn",
                ),
                (
                    "mvcc_contention_2writers",
                    "MVCC commit throughput with 2 concurrent writers",
                ),
                (
                    "mvcc_contention_4writers",
                    "MVCC commit throughput with 4 concurrent writers",
                ),
                (
                    "mvcc_contention_8writers",
                    "MVCC commit throughput with 8 concurrent writers",
                ),
            ],
            BenchmarkFamily::Concurrency,
            "ffs-mvcc",
        );
    }

    fn register_repair_ops(ops: &mut BTreeMap<String, BenchmarkEntry>) {
        Self::insert_ops(
            ops,
            &[
                (
                    "scrub_clean_256blocks",
                    "Scrub 256 clean blocks (no corruption)",
                ),
                (
                    "scrub_corrupted_256blocks",
                    "Scrub 256 blocks with 10% corruption",
                ),
                (
                    "raptorq_encode_group_16blocks",
                    "RaptorQ encode a 16-block repair group",
                ),
                (
                    "raptorq_decode_group_16blocks",
                    "RaptorQ decode a 16-block repair group",
                ),
                (
                    "repair_symbol_refresh_staleness_latency",
                    "Refresh policy staleness decision latency",
                ),
            ],
            BenchmarkFamily::Repair,
            "ffs-repair",
        );
    }

    fn register_extent_ops(ops: &mut BTreeMap<String, BenchmarkEntry>) {
        Self::insert_ops(
            ops,
            &[
                (
                    "extent_resolve_depth0_cached",
                    "Extent tree resolve in root node (depth-0, no I/O)",
                ),
                (
                    "extent_resolve_depth1_uncached",
                    "Extent tree resolve with external leaf read (depth-1)",
                ),
                (
                    "extent_resolve_range_50blocks",
                    "Extent tree batch resolve of 50 contiguous logical blocks",
                ),
                (
                    "extent_resolve_depth1_repeated",
                    "Extent tree repeated resolve of same block (10x, depth-1)",
                ),
            ],
            BenchmarkFamily::Parser,
            "ffs-extent",
        );
    }

    /// Load a taxonomy from a TOML file, or fall back to canonical if not found.
    pub fn load_or_canonical(path: &Path) -> Result<Self, TaxonomyError> {
        if !path.exists() {
            info!(
                target: "ffs::benchmark_taxonomy",
                path = %path.display(),
                source = "canonical",
                "taxonomy_load"
            );
            return Ok(Self::canonical());
        }
        let text = std::fs::read_to_string(path).map_err(|e| TaxonomyError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        let taxonomy: Self = toml::from_str(&text).map_err(|e| TaxonomyError::Parse {
            path: path.display().to_string(),
            source: e,
        })?;
        info!(
            target: "ffs::benchmark_taxonomy",
            path = %path.display(),
            source = "file",
            operations = taxonomy.operations.len(),
            host_profiles = taxonomy.host_profiles.len(),
            "taxonomy_load"
        );
        Ok(taxonomy)
    }

    /// Get the effective acceptance envelope for an operation.
    ///
    /// Checks operation-level override first, then falls back to family default.
    #[must_use]
    pub fn envelope_for(&self, operation_id: &str) -> AcceptanceEnvelope {
        if let Some(entry) = self.operations.get(operation_id) {
            if let Some(ref ovr) = entry.envelope_override {
                return AcceptanceEnvelope {
                    warn_percent: ovr.warn_percent,
                    fail_percent: ovr.fail_percent,
                    noise_floor_percent: ovr.noise_floor_percent,
                    rationale: "", // Dynamic override, no static rationale
                };
            }
            entry.family.default_envelope()
        } else {
            // Unknown operation → use MetadataOps defaults (moderate)
            BenchmarkFamily::MetadataOps.default_envelope()
        }
    }

    /// Validate that all operations in a baseline JSON are covered by the taxonomy.
    ///
    /// Returns operation IDs that exist in the baseline but not in the taxonomy.
    #[must_use]
    pub fn uncovered_operations<'a>(&self, baseline_ops: &'a [String]) -> Vec<&'a String> {
        let uncovered: Vec<&'a String> = baseline_ops
            .iter()
            .filter(|op| !self.operations.contains_key(op.as_str()))
            .collect();
        if uncovered.is_empty() {
            debug!(
                target: "ffs::benchmark_taxonomy",
                baseline_ops = baseline_ops.len(),
                outcome = "all_covered",
                "taxonomy_coverage_check"
            );
        } else {
            warn!(
                target: "ffs::benchmark_taxonomy",
                baseline_ops = baseline_ops.len(),
                uncovered_count = uncovered.len(),
                outcome = "gaps_found",
                "taxonomy_coverage_check"
            );
        }
        uncovered
    }

    /// Generate a summary table suitable for Markdown rendering.
    #[must_use]
    pub fn summary_table(&self) -> String {
        let mut lines = Vec::new();
        lines
            .push("| Operation ID | Family | Metric | Crate | Warn% | Fail% | Noise% |".to_owned());
        lines.push("|---|---|---|---|---|---|---|".to_owned());

        for (id, entry) in &self.operations {
            let env = self.envelope_for(id);
            lines.push(format!(
                "| `{}` | {} | {:?} | `{}` | {:.0} | {:.0} | {:.0} |",
                id,
                entry.family.label(),
                entry.metric,
                entry.owning_crate,
                env.warn_percent,
                env.fail_percent,
                env.noise_floor_percent,
            ));
        }

        lines.join("\n")
    }
}

// ── Errors ─────────────────────────────────────────────────────────────────

/// Errors from taxonomy loading.
#[derive(Debug)]
pub enum TaxonomyError {
    Io {
        path: String,
        source: std::io::Error,
    },
    Parse {
        path: String,
        source: toml::de::Error,
    },
}

impl std::fmt::Display for TaxonomyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "taxonomy I/O error at {path}: {source}"),
            Self::Parse { path, source } => write!(f, "taxonomy parse error at {path}: {source}"),
        }
    }
}

impl std::error::Error for TaxonomyError {}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};

    fn first_uncovered<'a>(uncovered: &'a [&'a String]) -> Result<&'a str> {
        uncovered
            .first()
            .map(|operation| operation.as_str())
            .context("uncovered operation list has at least one entry")
    }

    fn taxonomy_entry<'a>(taxonomy: &'a Taxonomy, op: &str) -> Result<&'a BenchmarkEntry> {
        taxonomy
            .operations
            .get(op)
            .with_context(|| format!("{op} operation registered"))
    }

    #[test]
    fn canonical_taxonomy_has_all_baseline_operations() {
        let taxonomy = Taxonomy::canonical();
        let expected_ops = [
            "metadata_parity_cli",
            "metadata_parity_harness",
            "fixture_validation",
            "read_metadata_inspect_ext4_reference",
            "read_metadata_scrub_ext4_reference",
            "cli_metadata_parse_conformance",
            "block_cache_arc_sequential_scan",
            "block_cache_arc_zipf_distribution",
            "block_cache_arc_mixed_seq70_hot30",
            "block_cache_arc_concurrent_hot_read_64threads",
            "block_cache_sharded_arc_concurrent_hot_read_64threads",
            "block_cache_arc_compile_like",
            "block_cache_arc_database_like",
            "block_cache_s3fifo_sequential_scan",
            "block_cache_s3fifo_zipf_distribution",
            "block_cache_s3fifo_mixed_seq70_hot30",
            "block_cache_s3fifo_concurrent_hot_read_64threads",
            "block_cache_sharded_s3fifo_concurrent_hot_read_64threads",
            "block_cache_s3fifo_compile_like",
            "block_cache_s3fifo_database_like",
            "write_seq_4k",
            "write_random_4k",
            "fsync_single_write",
            "fsync_batch_100",
            "wal_commit_4k_sync",
            "wal_write_amplification_1block",
            "wal_write_amplification_16block",
            "mvcc_contention_2writers",
            "mvcc_contention_4writers",
            "mvcc_contention_8writers",
            "scrub_clean_256blocks",
            "scrub_corrupted_256blocks",
            "raptorq_encode_group_16blocks",
            "raptorq_decode_group_16blocks",
            "repair_symbol_refresh_staleness_latency",
            "mount_cold",
            "mount_warm",
            "mount_recovery",
            "mount_runtime_per_core_route_inode",
            "mount_runtime_per_core_route_lookup",
            "mount_runtime_per_core_should_steal",
            "mount_runtime_per_core_aggregate_metrics",
            "mount_runtime_metrics_record_throughput",
            "mount_runtime_backpressure_normal",
            "mount_runtime_backpressure_degraded",
            "mount_runtime_backpressure_emergency",
            "extent_resolve_depth0_cached",
            "extent_resolve_depth1_uncached",
            "extent_resolve_range_50blocks",
            "extent_resolve_depth1_repeated",
        ];
        for op in &expected_ops {
            assert!(
                taxonomy.operations.contains_key(*op),
                "missing operation: {op}"
            );
        }
    }

    #[test]
    fn canonical_taxonomy_covers_existing_thresholds_toml_keys() {
        // These are the operation IDs from benchmarks/thresholds.toml
        let thresholds_keys = [
            "metadata_parity_cli",
            "metadata_parity_harness",
            "fixture_validation",
            "read_metadata_inspect_ext4_reference",
            "read_metadata_scrub_ext4_reference",
            "cli_metadata_parse_conformance",
            "block_cache_arc_sequential_scan",
            "block_cache_arc_zipf_distribution",
            "block_cache_arc_mixed_seq70_hot30",
            "block_cache_arc_concurrent_hot_read_64threads",
            "block_cache_sharded_arc_concurrent_hot_read_64threads",
            "block_cache_arc_compile_like",
            "block_cache_arc_database_like",
            "block_cache_s3fifo_sequential_scan",
            "block_cache_s3fifo_zipf_distribution",
            "block_cache_s3fifo_mixed_seq70_hot30",
            "block_cache_s3fifo_concurrent_hot_read_64threads",
            "block_cache_sharded_s3fifo_concurrent_hot_read_64threads",
            "block_cache_s3fifo_compile_like",
            "block_cache_s3fifo_database_like",
            "wal_commit_4k_sync",
            "wal_write_amplification_1block",
            "wal_write_amplification_16block",
            "mvcc_contention_2writers",
            "mvcc_contention_4writers",
            "mvcc_contention_8writers",
            "scrub_clean_256blocks",
            "scrub_corrupted_256blocks",
            "raptorq_encode_group_16blocks",
            "raptorq_decode_group_16blocks",
            "repair_symbol_refresh_staleness_latency",
            "extent_resolve_depth0_cached",
            "extent_resolve_depth1_uncached",
            "extent_resolve_range_50blocks",
            "extent_resolve_depth1_repeated",
            "block_cache_lookup_latency",
            "block_cache_writeback_single_4k",
            "block_cache_writeback_batch_100x4k",
        ];
        let taxonomy = Taxonomy::canonical();
        let baseline_ops: Vec<String> = thresholds_keys.iter().map(|s| (*s).to_owned()).collect();
        let uncovered = taxonomy.uncovered_operations(&baseline_ops);
        // Some thresholds.toml keys use old naming that differs from baseline JSON.
        // The taxonomy follows baseline JSON naming. Old-naming keys are acceptable
        // as uncovered since they map to canonical entries under different IDs.
        for op in &uncovered {
            assert!(
                op.starts_with("block_cache_lookup") || op.starts_with("block_cache_writeback"),
                "unexpected uncovered operation: {op}",
            );
        }
    }

    #[test]
    fn every_family_has_at_least_one_operation() {
        let taxonomy = Taxonomy::canonical();
        let families_with_ops: std::collections::BTreeSet<BenchmarkFamily> =
            taxonomy.operations.values().map(|e| e.family).collect();

        // All families with registered operations must be present.
        for family in [
            BenchmarkFamily::Parser,
            BenchmarkFamily::MetadataOps,
            BenchmarkFamily::BlockCache,
            BenchmarkFamily::WritePath,
            BenchmarkFamily::Mount,
            BenchmarkFamily::Concurrency,
            BenchmarkFamily::Repair,
            BenchmarkFamily::DegradedMode,
        ] {
            assert!(
                families_with_ops.contains(&family),
                "family {family:?} has no operations in taxonomy",
            );
        }
    }

    #[test]
    fn envelope_classify_noise_floor() {
        let env = BenchmarkFamily::Parser.default_envelope();
        assert_eq!(env.classify(2.0), EnvelopeVerdict::Noise);
        assert_eq!(env.classify(3.0), EnvelopeVerdict::Noise);
    }

    #[test]
    fn envelope_classify_ok() {
        let env = BenchmarkFamily::Parser.default_envelope();
        assert_eq!(env.classify(5.0), EnvelopeVerdict::Ok);
    }

    #[test]
    fn envelope_classify_warn() {
        let env = BenchmarkFamily::Parser.default_envelope();
        assert_eq!(env.classify(10.0), EnvelopeVerdict::Warn);
    }

    #[test]
    fn envelope_classify_fail() {
        let env = BenchmarkFamily::Parser.default_envelope();
        assert_eq!(env.classify(20.0), EnvelopeVerdict::Fail);
    }

    #[test]
    fn envelope_classify_negative_delta_is_noise() {
        let env = BenchmarkFamily::MetadataOps.default_envelope();
        // Negative delta = improvement, should be within noise floor
        assert_eq!(env.classify(-5.0), EnvelopeVerdict::Noise);
    }

    #[test]
    fn host_profile_reference_no_adjustment() {
        let profile = HostProfile::reference();
        let adjusted = profile.adjust_threshold(10.0);
        assert!((adjusted - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn host_profile_ci_widens_threshold() {
        let profile = HostProfile::ci_github_actions();
        let adjusted = profile.adjust_threshold(10.0);
        // normalization_factor = 0.15, scale = min(1/0.15, 3.0) = 3.0
        assert!((adjusted - 30.0).abs() < f64::EPSILON);
    }

    #[test]
    fn host_profile_rch_widens_threshold() {
        let profile = HostProfile::rch_contabo_worker();
        let adjusted = profile.adjust_threshold(10.0);
        // normalization_factor = 0.25, scale = min(4.0, 3.0) = 3.0
        assert!((adjusted - 30.0).abs() < f64::EPSILON);
    }

    #[test]
    fn uncovered_operations_detected() -> Result<()> {
        let taxonomy = Taxonomy::canonical();
        let ops = vec![
            "metadata_parity_cli".to_owned(),
            "completely_unknown_benchmark".to_owned(),
        ];
        let uncovered = taxonomy.uncovered_operations(&ops);
        assert_eq!(uncovered.len(), 1);
        assert_eq!(first_uncovered(&uncovered)?, "completely_unknown_benchmark");
        Ok(())
    }

    #[test]
    fn summary_table_includes_all_operations() {
        let taxonomy = Taxonomy::canonical();
        let table = taxonomy.summary_table();
        for op_id in taxonomy.operations.keys() {
            assert!(
                table.contains(op_id),
                "summary table missing operation: {op_id}",
            );
        }
    }

    #[test]
    fn summary_table_canonical_snapshot() {
        let taxonomy = Taxonomy::canonical();
        let table = taxonomy.summary_table();
        insta::assert_snapshot!("summary_table_canonical", table);
    }

    #[test]
    fn taxonomy_version_is_set() {
        let taxonomy = Taxonomy::canonical();
        assert_eq!(taxonomy.version, 1);
    }

    #[test]
    fn all_host_profiles_have_positive_normalization() {
        let taxonomy = Taxonomy::canonical();
        for (id, profile) in &taxonomy.host_profiles {
            assert!(
                profile.normalization_factor > 0.0,
                "host profile {id} has non-positive normalization factor",
            );
        }
    }

    #[test]
    fn envelope_warn_less_than_fail() {
        let taxonomy = Taxonomy::canonical();
        for id in taxonomy.operations.keys() {
            let env = taxonomy.envelope_for(id);
            assert!(
                env.warn_percent < env.fail_percent,
                "operation {id}: warn ({}) >= fail ({})",
                env.warn_percent,
                env.fail_percent,
            );
            assert!(
                env.noise_floor_percent < env.warn_percent,
                "operation {id}: noise_floor ({}) >= warn ({})",
                env.noise_floor_percent,
                env.warn_percent,
            );
        }
    }

    #[test]
    fn canonical_taxonomy_has_expanded_suite_operations() {
        let taxonomy = Taxonomy::canonical();
        // bd-h6nz.5.2: write amplification, contention, repair operations
        let expanded_ops = [
            "cli_metadata_parse_conformance",
            "block_cache_arc_concurrent_hot_read_64threads",
            "block_cache_s3fifo_concurrent_hot_read_64threads",
            "block_cache_sharded_arc_concurrent_hot_read_64threads",
            "block_cache_sharded_s3fifo_concurrent_hot_read_64threads",
            "wal_commit_4k_sync",
            "wal_write_amplification_1block",
            "wal_write_amplification_16block",
            "mvcc_contention_2writers",
            "mvcc_contention_4writers",
            "mvcc_contention_8writers",
            "scrub_clean_256blocks",
            "scrub_corrupted_256blocks",
            "raptorq_encode_group_16blocks",
            "raptorq_decode_group_16blocks",
            "repair_symbol_refresh_staleness_latency",
        ];
        for op in &expanded_ops {
            assert!(
                taxonomy.operations.contains_key(*op),
                "missing expanded operation: {op}"
            );
        }
    }

    #[test]
    fn mount_runtime_mode_benchmarks_registered() -> Result<()> {
        let taxonomy = Taxonomy::canonical();

        // Mount family entries for dispatch infrastructure
        let mount_runtime_ops = [
            "mount_runtime_per_core_route_inode",
            "mount_runtime_per_core_route_lookup",
            "mount_runtime_per_core_should_steal",
            "mount_runtime_per_core_aggregate_metrics",
            "mount_runtime_metrics_record_throughput",
        ];
        for op in &mount_runtime_ops {
            let entry = taxonomy_entry(&taxonomy, op)?;
            assert_eq!(entry.family, BenchmarkFamily::Mount);
            assert_eq!(entry.owning_crate, "ffs-fuse");
        }

        // DegradedMode family entries for backpressure decision
        let backpressure_ops = [
            "mount_runtime_backpressure_normal",
            "mount_runtime_backpressure_degraded",
            "mount_runtime_backpressure_emergency",
        ];
        for op in &backpressure_ops {
            let entry = taxonomy_entry(&taxonomy, op)?;
            assert_eq!(entry.family, BenchmarkFamily::DegradedMode);
            assert_eq!(entry.owning_crate, "ffs-fuse");
        }
        Ok(())
    }

    #[test]
    fn mount_runtime_benchmark_envelopes_match_family() {
        let taxonomy = Taxonomy::canonical();

        // Mount family ops should use Mount envelope (wide: 25%/50%/10%)
        let mount_env = BenchmarkFamily::Mount.default_envelope();
        for op in [
            "mount_runtime_per_core_route_inode",
            "mount_runtime_per_core_route_lookup",
            "mount_runtime_per_core_should_steal",
            "mount_runtime_per_core_aggregate_metrics",
            "mount_runtime_metrics_record_throughput",
        ] {
            let env = taxonomy.envelope_for(op);
            assert_eq!(
                env.warn_percent, mount_env.warn_percent,
                "op {op}: warn mismatch"
            );
            assert_eq!(
                env.fail_percent, mount_env.fail_percent,
                "op {op}: fail mismatch"
            );
        }

        // DegradedMode ops should use DegradedMode envelope (widest: 30%/60%/15%)
        let deg_env = BenchmarkFamily::DegradedMode.default_envelope();
        for op in [
            "mount_runtime_backpressure_normal",
            "mount_runtime_backpressure_degraded",
            "mount_runtime_backpressure_emergency",
        ] {
            let env = taxonomy.envelope_for(op);
            assert_eq!(
                env.warn_percent, deg_env.warn_percent,
                "op {op}: warn mismatch"
            );
            assert_eq!(
                env.fail_percent, deg_env.fail_percent,
                "op {op}: fail mismatch"
            );
        }
    }

    #[test]
    fn degraded_throughput_benchmarks_registered() -> Result<()> {
        let taxonomy = Taxonomy::canonical();

        // All degraded throughput scenarios must exist
        let degraded_throughput_ops = [
            "degraded_throughput_warning_read",
            "degraded_throughput_warning_write",
            "degraded_throughput_warning_mixed",
            "degraded_throughput_critical_read",
            "degraded_throughput_critical_write",
            "degraded_throughput_critical_mixed",
            "degraded_fsm_tick_latency",
            "degraded_backpressure_contention_4threads",
        ];
        for op in &degraded_throughput_ops {
            let entry = taxonomy_entry(&taxonomy, op)?;
            assert_eq!(
                entry.family,
                BenchmarkFamily::DegradedMode,
                "op {op}: wrong family"
            );
        }

        // Throughput ops must have Throughput metric
        for op in [
            "degraded_throughput_warning_read",
            "degraded_throughput_critical_write",
            "degraded_backpressure_contention_4threads",
        ] {
            let entry = taxonomy_entry(&taxonomy, op)?;
            assert_eq!(
                entry.metric,
                MetricType::Throughput,
                "op {op}: should be Throughput metric"
            );
        }

        // FSM tick is latency
        assert_eq!(
            taxonomy_entry(&taxonomy, "degraded_fsm_tick_latency")?.metric,
            MetricType::Latency,
        );
        Ok(())
    }

    #[test]
    fn mount_runtime_benchmark_ops_not_in_baseline_flagged() -> Result<()> {
        // Negative test: unknown benchmark operations should be detected as uncovered.
        let taxonomy = Taxonomy::canonical();
        let ops = vec![
            "mount_runtime_per_core_route_inode".to_owned(),
            "mount_runtime_nonexistent_scenario".to_owned(),
        ];
        let uncovered = taxonomy.uncovered_operations(&ops);
        assert_eq!(uncovered.len(), 1);
        assert_eq!(
            first_uncovered(&uncovered)?,
            "mount_runtime_nonexistent_scenario"
        );
        Ok(())
    }

    #[test]
    fn taxonomy_json_round_trip() -> Result<()> {
        let taxonomy = Taxonomy::canonical();
        let json = serde_json::to_string_pretty(&taxonomy)?;
        let parsed: Taxonomy = serde_json::from_str(&json)?;
        assert_eq!(parsed, taxonomy);
        Ok(())
    }

    #[test]
    fn canonical_taxonomy_json_snapshot() -> Result<()> {
        let taxonomy = Taxonomy::canonical();
        let json = serde_json::to_string_pretty(&taxonomy)?;
        insta::assert_snapshot!("canonical_taxonomy_v1", json);
        Ok(())
    }

    #[test]
    fn triage_module_covers_all_taxonomy_families() {
        use crate::perf_comparison::{ComparisonVerdict, SampleStats, TTestResult};
        use crate::perf_triage::{TriageAction, TriageCause, classify_triage};

        // Every family in the taxonomy must produce a valid triage decision
        // for both pass and fail scenarios.
        let families = [
            BenchmarkFamily::Parser,
            BenchmarkFamily::Mount,
            BenchmarkFamily::MetadataOps,
            BenchmarkFamily::BlockCache,
            BenchmarkFamily::WritePath,
            BenchmarkFamily::Concurrency,
            BenchmarkFamily::Repair,
            BenchmarkFamily::DegradedMode,
        ];

        let make_fail = |op: &str| crate::perf_comparison::ComparisonResult {
            operation_id: op.to_owned(),
            baseline: SampleStats {
                n: 10,
                mean: 100.0,
                std_dev: 3.0,
                cv_percent: 3.0,
                min: 97.0,
                max: 103.0,
                median: 100.0,
            },
            current: SampleStats {
                n: 10,
                mean: 130.0,
                std_dev: 3.0,
                cv_percent: 2.3,
                min: 127.0,
                max: 133.0,
                median: 130.0,
            },
            delta_percent: 30.0,
            effect_size: 1.2,
            effect_label: "large",
            t_test: Some(TTestResult {
                t_stat: 4.5,
                df: 18.0,
                p_value: 0.0003,
            }),
            significant: true,
            envelope_verdict: EnvelopeVerdict::Fail,
            final_verdict: ComparisonVerdict::Fail,
            explanation: "confirmed regression".to_owned(),
        };

        for family in families {
            let result = make_fail(&format!("test_{}", family.label()));
            let decision = classify_triage(&result, family, None);

            // Every family must map to a recognized cause and action
            assert!(
                matches!(
                    decision.cause,
                    TriageCause::CodeRegression
                        | TriageCause::EnvironmentChange
                        | TriageCause::ThresholdCalibration
                ),
                "family {:?} produced unexpected cause {:?}",
                family,
                decision.cause,
            );
            assert!(
                matches!(
                    decision.action,
                    TriageAction::BisectCommits
                        | TriageAction::CheckEnvironment
                        | TriageAction::RecalibrateThresholds
                        | TriageAction::RerunOnReference
                ),
                "family {:?} produced unexpected action {:?}",
                family,
                decision.action,
            );
        }
    }

    #[test]
    fn triage_runbook_file_path_matches_module_constant() {
        assert_eq!(
            crate::perf_triage::runbook_path(),
            "docs/runbooks/perf-regression-triage.md",
        );
    }
}
