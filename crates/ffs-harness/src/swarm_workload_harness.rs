#![allow(clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! NUMA-aware swarm workload harness contract for `bd-p2j3e.2`.
//!
//! This validator defines the workload plan and host fingerprint needed before
//! a 64-core/256GB swarm run can strengthen performance claims. Local smoke
//! rows must stay downgraded when NUMA visibility, host resources, FUSE
//! capability, or worker isolation evidence is missing.

use crate::artifact_manifest::parse_manifest_timestamp_epoch_days;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_SWARM_WORKLOAD_HARNESS_MANIFEST: &str =
    "benchmarks/swarm_workload_harness_manifest.json";
pub const SWARM_WORKLOAD_HARNESS_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_SWARM_WORKLOAD_HARNESS_MAX_AGE_DAYS: u32 = 14;

const REQUIRED_WORKLOAD_CLASSES: [SwarmWorkloadClass; 5] = [
    SwarmWorkloadClass::MetadataStorm,
    SwarmWorkloadClass::AppendFsync,
    SwarmWorkloadClass::MixedReadWrite,
    SwarmWorkloadClass::ScrubRepairOverlap,
    SwarmWorkloadClass::CachePressure,
];

const REQUIRED_LOG_FIELDS: [&str; 18] = [
    "scenario_id",
    "host_fingerprint",
    "cpu_cores_logical",
    "numa_nodes",
    "ram_total_gb",
    "ram_available_gb",
    "storage_class",
    "fuse_capability",
    "kernel",
    "rch_or_local_lane",
    "worker_isolation_notes",
    "workload_profile_id",
    "workload_seeds",
    "queue_depth",
    "backpressure_state",
    "cleanup_status",
    "release_claim_state",
    "reproduction_command",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmWorkloadHarnessManifest {
    pub schema_version: u32,
    pub manifest_id: String,
    pub generated_at: String,
    pub target_host: SwarmWorkloadTargetHost,
    pub workload_profiles: Vec<SwarmWorkloadProfile>,
    pub scenarios: Vec<SwarmWorkloadScenario>,
    #[serde(default)]
    pub required_log_fields: Vec<String>,
    #[serde(default)]
    pub proof_consumers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmWorkloadTargetHost {
    pub min_cpu_cores_logical: u32,
    pub min_ram_total_gb: u32,
    pub min_ram_available_gb: u32,
    pub min_numa_nodes: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmWorkloadProfile {
    pub workload_profile_id: String,
    pub workload_class: SwarmWorkloadClass,
    pub description: String,
    pub command_plan: SwarmCommandPlan,
    pub placement: SwarmPlacementIntent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmWorkloadClass {
    MetadataStorm,
    AppendFsync,
    MixedReadWrite,
    ScrubRepairOverlap,
    CachePressure,
}

impl SwarmWorkloadClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MetadataStorm => "metadata_storm",
            Self::AppendFsync => "append_fsync",
            Self::MixedReadWrite => "mixed_read_write",
            Self::ScrubRepairOverlap => "scrub_repair_overlap",
            Self::CachePressure => "cache_pressure",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmCommandPlan {
    pub plan_id: String,
    pub plan_mode: SwarmCommandPlanMode,
    pub exact_command: String,
    pub dry_run_only: bool,
    pub mutates_host_filesystems: bool,
    pub expected_artifacts: Vec<SwarmExpectedArtifact>,
    pub resource_caps: SwarmResourceCaps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmCommandPlanMode {
    DryRun,
    PermissionedReal,
}

impl SwarmCommandPlanMode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DryRun => "dry_run",
            Self::PermissionedReal => "permissioned_real",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmExpectedArtifact {
    pub path: String,
    pub kind: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmResourceCaps {
    pub max_duration_secs: u64,
    pub max_threads: u32,
    pub max_memory_gb: f64,
    pub max_temp_storage_gb: f64,
    pub max_queue_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPlacementIntent {
    pub shard_count: u32,
    pub core_allocation: String,
    pub numa_policy: String,
    pub queue_isolation: String,
    pub cleanup_policy: SwarmCleanupPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmCleanupPolicy {
    ControlledTempRoots,
    NoHostMutation,
    Missing,
}

impl SwarmCleanupPolicy {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ControlledTempRoots => "controlled_temp_roots",
            Self::NoHostMutation => "no_host_mutation",
            Self::Missing => "missing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmWorkloadScenario {
    pub scenario_id: String,
    pub host: SwarmHostFingerprint,
    pub workload_profile_ids: Vec<String>,
    pub workload_seeds: Vec<u64>,
    pub counters: SwarmQueueBackpressureCounters,
    pub cleanup_status: SwarmCleanupStatus,
    pub classification: SwarmHarnessClassification,
    pub release_claim_state: SwarmHarnessReleaseClaimState,
    pub reproduction_command: String,
    pub raw_logs: Vec<String>,
    pub artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmHostFingerprint {
    pub host_fingerprint: String,
    pub cpu_cores_logical: u32,
    pub numa: SwarmNumaObservation,
    pub ram_total_gb: f64,
    pub ram_available_gb: f64,
    pub storage_class: String,
    pub fuse_capability: SwarmFuseCapability,
    pub kernel: String,
    pub lane: SwarmHostLane,
    pub rch_or_local_lane: SwarmRchOrLocalLane,
    pub worker_isolation_notes: String,
}

impl SwarmHostFingerprint {
    #[must_use]
    pub fn meets_target(&self, target: &SwarmWorkloadTargetHost) -> bool {
        self.cpu_cores_logical >= target.min_cpu_cores_logical
            && self.ram_total_gb >= f64::from(target.min_ram_total_gb)
            && self.ram_available_gb >= f64::from(target.min_ram_available_gb)
            && self
                .numa
                .node_count
                .is_some_and(|nodes| nodes >= target.min_numa_nodes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmNumaObservation {
    pub observable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_count: Option<u32>,
    pub placement_intent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing_reason: Option<String>,
}

impl SwarmNumaObservation {
    #[must_use]
    pub fn authoritative(&self) -> bool {
        self.observable && self.node_count.is_some_and(|nodes| nodes > 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmFuseCapability {
    pub state: SwarmFuseCapabilityState,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmFuseCapabilityState {
    Available,
    Missing,
    Unknown,
    NotRequired,
}

impl SwarmFuseCapabilityState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Missing => "missing",
            Self::Unknown => "unknown",
            Self::NotRequired => "not_required",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmHostLane {
    DeveloperSmoke,
    RchWorker,
    PermissionedLargeHost,
    CiSmoke,
}

impl SwarmHostLane {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DeveloperSmoke => "developer_smoke",
            Self::RchWorker => "rch_worker",
            Self::PermissionedLargeHost => "permissioned_large_host",
            Self::CiSmoke => "ci_smoke",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmRchOrLocalLane {
    Local,
    Rch,
    Ci,
    Unknown,
}

impl SwarmRchOrLocalLane {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Rch => "rch",
            Self::Ci => "ci",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmQueueBackpressureCounters {
    pub max_queue_depth: u32,
    pub average_queue_depth: f64,
    pub backpressure_state: SwarmBackpressureState,
    pub throttle_events: u64,
    pub rejected_writes: u64,
    pub p99_latency_budget_us: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmBackpressureState {
    Healthy,
    Throttled,
    Critical,
    Unknown,
}

impl SwarmBackpressureState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Throttled => "throttled",
            Self::Critical => "critical",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmCleanupStatus {
    NotStartedDryRun,
    Clean,
    PartialArtifactsPreserved,
    Failed,
    Unknown,
}

impl SwarmCleanupStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotStartedDryRun => "not_started_dry_run",
            Self::Clean => "clean",
            Self::PartialArtifactsPreserved => "partial_artifacts_preserved",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmHarnessClassification {
    Pass,
    Warn,
    Fail,
    CapabilitySkip,
}

impl SwarmHarnessClassification {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::CapabilitySkip => "capability_skip",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmHarnessReleaseClaimState {
    Experimental,
    PlanReady,
    SmallHostSmoke,
    CapabilitySkip,
    MeasuredLocal,
    MeasuredAuthoritative,
    Blocked,
}

impl SwarmHarnessReleaseClaimState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Experimental => "experimental",
            Self::PlanReady => "plan_ready",
            Self::SmallHostSmoke => "small_host_smoke",
            Self::CapabilitySkip => "capability_skip",
            Self::MeasuredLocal => "measured_local",
            Self::MeasuredAuthoritative => "measured_authoritative",
            Self::Blocked => "blocked",
        }
    }

    #[must_use]
    pub const fn safe_for_inadequate_host(self) -> bool {
        matches!(
            self,
            Self::Experimental | Self::SmallHostSmoke | Self::CapabilitySkip | Self::Blocked
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmWorkloadHarnessValidationConfig {
    pub reference_epoch_days: Option<u32>,
    pub max_age_days: u32,
}

impl Default for SwarmWorkloadHarnessValidationConfig {
    fn default() -> Self {
        Self {
            reference_epoch_days: None,
            max_age_days: DEFAULT_SWARM_WORKLOAD_HARNESS_MAX_AGE_DAYS,
        }
    }
}

impl SwarmWorkloadHarnessValidationConfig {
    #[must_use]
    pub fn with_current_reference() -> Self {
        Self {
            reference_epoch_days: current_epoch_days(),
            max_age_days: DEFAULT_SWARM_WORKLOAD_HARNESS_MAX_AGE_DAYS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationVerdict {
    Pass,
    Fail,
    Skip,
    Error,
}

impl SwarmValidationVerdict {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skip => "skip",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmValidationIssue {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmScenarioValidationRow {
    pub scenario_id: String,
    pub verdict: SwarmValidationVerdict,
    pub classification: String,
    pub release_claim_state: String,
    pub host_lane: String,
    pub host_meets_target: bool,
    pub numa_authoritative: bool,
    pub issue_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmWorkloadHarnessReport {
    pub schema_version: u32,
    pub manifest_id: String,
    pub valid: bool,
    pub profile_count: usize,
    pub scenario_count: usize,
    pub command_plan_count: usize,
    pub required_workload_class_count: usize,
    pub missing_workload_classes: Vec<String>,
    pub large_host_plan_count: usize,
    pub host_downgrade_count: usize,
    pub verdict_counts: BTreeMap<String, usize>,
    pub classification_counts: BTreeMap<String, usize>,
    pub release_claim_counts: BTreeMap<String, usize>,
    pub scenario_verdicts: Vec<SwarmScenarioValidationRow>,
    pub profile_matrix: Vec<SwarmProfileMatrixRow>,
    pub issues: Vec<SwarmValidationIssue>,
    pub errors: Vec<String>,
}

#[derive(Debug, Default)]
struct SwarmScenarioValidationSummary {
    classification_counts: BTreeMap<String, usize>,
    release_claim_counts: BTreeMap<String, usize>,
    verdict_counts: BTreeMap<String, usize>,
    scenario_verdicts: Vec<SwarmScenarioValidationRow>,
    large_host_plan_count: usize,
    host_downgrade_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmProfileMatrixRow {
    pub workload_profile_id: String,
    pub workload_class: String,
    pub plan_mode: String,
    pub exact_command: String,
    pub max_threads: u32,
    pub max_memory_gb: f64,
    pub max_queue_depth: u32,
    pub shard_count: u32,
    pub numa_policy: String,
    pub cleanup_policy: String,
}

pub fn load_swarm_workload_harness_manifest(path: &Path) -> Result<SwarmWorkloadHarnessManifest> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read swarm workload manifest {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid swarm workload manifest JSON {}", path.display()))
}

#[must_use]
pub fn validate_swarm_workload_harness_manifest(
    manifest: &SwarmWorkloadHarnessManifest,
) -> SwarmWorkloadHarnessReport {
    validate_swarm_workload_harness_manifest_with_config(
        manifest,
        &SwarmWorkloadHarnessValidationConfig::default(),
    )
}

#[must_use]
pub fn validate_swarm_workload_harness_manifest_with_config(
    manifest: &SwarmWorkloadHarnessManifest,
    config: &SwarmWorkloadHarnessValidationConfig,
) -> SwarmWorkloadHarnessReport {
    let mut issues = Vec::new();
    validate_header(manifest, config, &mut issues);

    let profile_ids = validate_profiles(manifest, &mut issues);
    let missing_workload_classes = missing_required_workload_classes(manifest);
    for workload_class in &missing_workload_classes {
        push_issue(
            &mut issues,
            "workload_profiles",
            format!("missing required workload profile class {workload_class}"),
        );
    }

    let scenario_summary = validate_scenarios(manifest, &profile_ids, &mut issues);
    let profile_matrix = build_profile_matrix(manifest);
    let errors = issues
        .iter()
        .map(|issue| format!("{}: {}", issue.path, issue.message))
        .collect::<Vec<_>>();

    SwarmWorkloadHarnessReport {
        schema_version: SWARM_WORKLOAD_HARNESS_SCHEMA_VERSION,
        manifest_id: manifest.manifest_id.clone(),
        valid: errors.is_empty(),
        profile_count: manifest.workload_profiles.len(),
        scenario_count: manifest.scenarios.len(),
        command_plan_count: manifest.workload_profiles.len(),
        required_workload_class_count: REQUIRED_WORKLOAD_CLASSES.len(),
        missing_workload_classes,
        large_host_plan_count: scenario_summary.large_host_plan_count,
        host_downgrade_count: scenario_summary.host_downgrade_count,
        verdict_counts: scenario_summary.verdict_counts,
        classification_counts: scenario_summary.classification_counts,
        release_claim_counts: scenario_summary.release_claim_counts,
        scenario_verdicts: scenario_summary.scenario_verdicts,
        profile_matrix,
        issues,
        errors,
    }
}

fn current_epoch_days() -> Option<u32> {
    let unix_epoch_days = parse_manifest_timestamp_epoch_days("1970-01-01T00:00:00Z")?;
    let elapsed_days = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() / 86_400;
    let total_days = u64::from(unix_epoch_days).checked_add(elapsed_days)?;
    u32::try_from(total_days).ok()
}

fn push_issue(
    issues: &mut Vec<SwarmValidationIssue>,
    path: impl Into<String>,
    message: impl Into<String>,
) {
    issues.push(SwarmValidationIssue {
        path: path.into(),
        message: message.into(),
    });
}

fn scenario_verdict(
    scenario: &SwarmWorkloadScenario,
    scenario_issue_count: usize,
) -> SwarmValidationVerdict {
    if scenario_issue_count > 0 {
        SwarmValidationVerdict::Error
    } else if matches!(scenario.classification, SwarmHarnessClassification::Fail) {
        SwarmValidationVerdict::Fail
    } else if matches!(
        scenario.classification,
        SwarmHarnessClassification::CapabilitySkip
    ) || matches!(
        scenario.release_claim_state,
        SwarmHarnessReleaseClaimState::SmallHostSmoke
            | SwarmHarnessReleaseClaimState::CapabilitySkip
            | SwarmHarnessReleaseClaimState::Blocked
    ) {
        SwarmValidationVerdict::Skip
    } else {
        SwarmValidationVerdict::Pass
    }
}

#[must_use]
pub fn render_swarm_workload_harness_markdown(report: &SwarmWorkloadHarnessReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Swarm Workload Harness\n");
    let _ = writeln!(out, "- Manifest: `{}`", report.manifest_id);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Workload profiles: `{}`", report.profile_count);
    let _ = writeln!(out, "- Scenarios: `{}`", report.scenario_count);
    let _ = writeln!(
        out,
        "- Large-host plans: `{}`",
        report.large_host_plan_count
    );
    let _ = writeln!(out, "- Host downgrades: `{}`", report.host_downgrade_count);
    out.push_str("\n## Verdict Counts\n\n");
    for (verdict, count) in &report.verdict_counts {
        let _ = writeln!(out, "- `{verdict}`: {count}");
    }
    out.push_str("\n## Classification Counts\n\n");
    for (classification, count) in &report.classification_counts {
        let _ = writeln!(out, "- `{classification}`: {count}");
    }
    out.push_str("\n## Release Claim Counts\n\n");
    for (claim, count) in &report.release_claim_counts {
        let _ = writeln!(out, "- `{claim}`: {count}");
    }
    out.push_str("\n## Workload Profiles\n\n");
    out.push_str(
        "| Profile | Class | Plan | Max threads | Max memory | Queue cap | NUMA policy |\n",
    );
    out.push_str("|---|---|---|---:|---:|---:|---|\n");
    for row in &report.profile_matrix {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | {} | {:.1} GB | {} | {} |",
            row.workload_profile_id,
            row.workload_class,
            row.plan_mode,
            row.max_threads,
            row.max_memory_gb,
            row.max_queue_depth,
            row.numa_policy.replace('|', "/")
        );
    }
    out.push_str("\n## Scenario Verdicts\n\n");
    out.push_str("| Scenario | Verdict | Classification | Release claim | Host lane | Target | NUMA | Issues |\n");
    out.push_str("|---|---|---|---|---|---:|---:|---|\n");
    for row in &report.scenario_verdicts {
        let issue_paths = if row.issue_paths.is_empty() {
            "none".to_owned()
        } else {
            row.issue_paths.join(", ")
        };
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | `{}` | `{}` | {} | {} | {} |",
            row.scenario_id,
            row.verdict.label(),
            row.classification,
            row.release_claim_state,
            row.host_lane,
            row.host_meets_target,
            row.numa_authoritative,
            issue_paths.replace('|', "/")
        );
    }
    if !report.missing_workload_classes.is_empty() {
        out.push_str("\n## Missing Workload Classes\n\n");
        for workload_class in &report.missing_workload_classes {
            let _ = writeln!(out, "- `{workload_class}`");
        }
    }
    if !report.errors.is_empty() {
        out.push_str("\n## Errors\n\n");
        for issue in &report.issues {
            let _ = writeln!(out, "- `{}`: {}", issue.path, issue.message);
        }
    }
    out
}

pub fn fail_on_swarm_workload_harness_errors(report: &SwarmWorkloadHarnessReport) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "swarm workload harness validation failed: errors={}",
            report.errors.len()
        )
    }
}

fn validate_header(
    manifest: &SwarmWorkloadHarnessManifest,
    config: &SwarmWorkloadHarnessValidationConfig,
    issues: &mut Vec<SwarmValidationIssue>,
) {
    if manifest.schema_version != SWARM_WORKLOAD_HARNESS_SCHEMA_VERSION {
        push_issue(
            issues,
            "schema_version",
            format!("must be {SWARM_WORKLOAD_HARNESS_SCHEMA_VERSION}"),
        );
    }
    if manifest.manifest_id.trim().is_empty() {
        push_issue(issues, "manifest_id", "must not be empty");
    }
    if manifest.generated_at.trim().is_empty() {
        push_issue(issues, "generated_at", "must not be empty");
    } else if let Some(created_epoch_days) =
        parse_manifest_timestamp_epoch_days(&manifest.generated_at)
    {
        if let Some(reference_epoch_days) = config.reference_epoch_days {
            if created_epoch_days > reference_epoch_days {
                push_issue(
                    issues,
                    "generated_at",
                    "must not be after the validation reference timestamp",
                );
            } else if reference_epoch_days - created_epoch_days > config.max_age_days {
                push_issue(
                    issues,
                    "generated_at",
                    format!(
                        "stale manifest is older than {} day(s)",
                        config.max_age_days
                    ),
                );
            }
        }
    } else {
        push_issue(
            issues,
            "generated_at",
            "must be an RFC3339 timestamp with timezone",
        );
    }
    if manifest.target_host.min_cpu_cores_logical < 64 {
        push_issue(
            issues,
            "target_host.min_cpu_cores_logical",
            "must be at least 64",
        );
    }
    if manifest.target_host.min_ram_total_gb < 256 {
        push_issue(
            issues,
            "target_host.min_ram_total_gb",
            "must be at least 256",
        );
    }
    if manifest.target_host.min_ram_available_gb == 0 {
        push_issue(
            issues,
            "target_host.min_ram_available_gb",
            "must be positive",
        );
    }
    if manifest.target_host.min_numa_nodes == 0 {
        push_issue(issues, "target_host.min_numa_nodes", "must be positive");
    }
    if manifest.workload_profiles.is_empty() {
        push_issue(issues, "workload_profiles", "must not be empty");
    }
    if manifest.scenarios.is_empty() {
        push_issue(issues, "scenarios", "must not be empty");
    }
    for required in REQUIRED_LOG_FIELDS {
        if !manifest
            .required_log_fields
            .iter()
            .any(|field| field == required)
        {
            push_issue(issues, "required_log_fields", format!("missing {required}"));
        }
    }
    if manifest.proof_consumers.is_empty() {
        push_issue(issues, "proof_consumers", "must not be empty");
    }
}

fn validate_profiles(
    manifest: &SwarmWorkloadHarnessManifest,
    issues: &mut Vec<SwarmValidationIssue>,
) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    for (profile_index, profile) in manifest.workload_profiles.iter().enumerate() {
        let profile_path = format!("workload_profiles[{profile_index}]");
        if profile.workload_profile_id.trim().is_empty() {
            push_issue(
                issues,
                format!("{profile_path}.workload_profile_id"),
                "must not be empty",
            );
        }
        if !seen.insert(profile.workload_profile_id.clone()) {
            push_issue(
                issues,
                format!("{profile_path}.workload_profile_id"),
                format!("duplicate {}", profile.workload_profile_id),
            );
        }
        if profile.description.trim().is_empty() {
            push_issue(
                issues,
                format!("{profile_path}.description"),
                "must not be empty",
            );
        }
        validate_command_plan(profile, profile_index, issues);
        validate_placement(profile, profile_index, issues);
    }
    seen
}

fn validate_command_plan(
    profile: &SwarmWorkloadProfile,
    profile_index: usize,
    issues: &mut Vec<SwarmValidationIssue>,
) {
    let plan = &profile.command_plan;
    let plan_path = format!("workload_profiles[{profile_index}].command_plan");
    if plan.plan_id.trim().is_empty() {
        push_issue(issues, format!("{plan_path}.plan_id"), "must not be empty");
    }
    if plan.exact_command.trim().is_empty() {
        push_issue(
            issues,
            format!("{plan_path}.exact_command"),
            "must not be empty",
        );
    }
    if matches!(plan.plan_mode, SwarmCommandPlanMode::DryRun) && !plan.dry_run_only {
        push_issue(
            issues,
            format!("{plan_path}.dry_run_only"),
            "dry_run plan must set dry_run_only",
        );
    }
    if plan.mutates_host_filesystems {
        push_issue(
            issues,
            format!("{plan_path}.mutates_host_filesystems"),
            "must be false for dry-run-safe swarm workload plans",
        );
    }
    if plan.expected_artifacts.is_empty() {
        push_issue(
            issues,
            format!("{plan_path}.expected_artifacts"),
            "must not be empty",
        );
    }
    for (artifact_index, artifact) in plan.expected_artifacts.iter().enumerate() {
        if artifact.path.trim().is_empty() || artifact.kind.trim().is_empty() {
            push_issue(
                issues,
                format!("{plan_path}.expected_artifacts[{artifact_index}]"),
                "path and kind must not be empty",
            );
        }
    }
    validate_resource_caps(profile, profile_index, issues);
}

fn validate_resource_caps(
    profile: &SwarmWorkloadProfile,
    profile_index: usize,
    issues: &mut Vec<SwarmValidationIssue>,
) {
    let caps = &profile.command_plan.resource_caps;
    let caps_path = format!("workload_profiles[{profile_index}].command_plan.resource_caps");
    if caps.max_duration_secs == 0 {
        push_issue(
            issues,
            format!("{caps_path}.max_duration_secs"),
            "must be positive",
        );
    }
    if caps.max_threads == 0 {
        push_issue(
            issues,
            format!("{caps_path}.max_threads"),
            "must be positive",
        );
    }
    if caps.max_memory_gb <= 0.0 {
        push_issue(
            issues,
            format!("{caps_path}.max_memory_gb"),
            "must be positive",
        );
    }
    if caps.max_temp_storage_gb < 0.0 {
        push_issue(
            issues,
            format!("{caps_path}.max_temp_storage_gb"),
            "must not be negative",
        );
    }
    if caps.max_queue_depth == 0 {
        push_issue(
            issues,
            format!("{caps_path}.max_queue_depth"),
            "must be positive",
        );
    }
}

fn validate_placement(
    profile: &SwarmWorkloadProfile,
    profile_index: usize,
    issues: &mut Vec<SwarmValidationIssue>,
) {
    let placement = &profile.placement;
    let placement_path = format!("workload_profiles[{profile_index}].placement");
    if placement.shard_count == 0 {
        push_issue(
            issues,
            format!("{placement_path}.shard_count"),
            "must be positive",
        );
    }
    for (field, value) in [
        ("core_allocation", placement.core_allocation.as_str()),
        ("numa_policy", placement.numa_policy.as_str()),
        ("queue_isolation", placement.queue_isolation.as_str()),
    ] {
        if value.trim().is_empty() {
            push_issue(
                issues,
                format!("{placement_path}.{field}"),
                "must not be empty",
            );
        }
    }
    if matches!(placement.cleanup_policy, SwarmCleanupPolicy::Missing) {
        push_issue(
            issues,
            format!("{placement_path}.cleanup_policy"),
            "must not be missing",
        );
    }
}

fn missing_required_workload_classes(manifest: &SwarmWorkloadHarnessManifest) -> Vec<String> {
    let covered = manifest
        .workload_profiles
        .iter()
        .map(|profile| profile.workload_class)
        .collect::<BTreeSet<_>>();
    REQUIRED_WORKLOAD_CLASSES
        .iter()
        .filter(|workload_class| !covered.contains(workload_class))
        .map(|workload_class| workload_class.label().to_owned())
        .collect()
}

fn validate_scenarios(
    manifest: &SwarmWorkloadHarnessManifest,
    profile_ids: &BTreeSet<String>,
    issues: &mut Vec<SwarmValidationIssue>,
) -> SwarmScenarioValidationSummary {
    let mut seen = BTreeSet::new();
    let mut summary = SwarmScenarioValidationSummary::default();

    for (scenario_index, scenario) in manifest.scenarios.iter().enumerate() {
        let issue_start = issues.len();
        let scenario_path = format!("scenarios[{scenario_index}]");
        if scenario.scenario_id.trim().is_empty() {
            push_issue(
                issues,
                format!("{scenario_path}.scenario_id"),
                "must not be empty",
            );
        }
        if !seen.insert(scenario.scenario_id.clone()) {
            push_issue(
                issues,
                format!("{scenario_path}.scenario_id"),
                format!("duplicate {}", scenario.scenario_id),
            );
        }
        *summary
            .classification_counts
            .entry(scenario.classification.label().to_owned())
            .or_insert(0) += 1;
        *summary
            .release_claim_counts
            .entry(scenario.release_claim_state.label().to_owned())
            .or_insert(0) += 1;

        validate_scenario_shape(scenario, scenario_index, profile_ids, issues);
        validate_host(&scenario.host, scenario_index, issues);
        validate_counters(scenario, scenario_index, issues);

        let meets_target = scenario.host.meets_target(&manifest.target_host);
        let numa_authoritative = scenario.host.numa.authoritative();
        let inadequate_or_unobservable = !meets_target || !numa_authoritative;
        if inadequate_or_unobservable {
            summary.host_downgrade_count += 1;
            validate_downgraded_scenario(scenario, scenario_index, issues);
        }
        if matches!(
            scenario.release_claim_state,
            SwarmHarnessReleaseClaimState::MeasuredAuthoritative
        ) {
            validate_authoritative_scenario(
                scenario,
                scenario_index,
                meets_target,
                numa_authoritative,
                issues,
            );
        }
        if matches!(
            scenario.release_claim_state,
            SwarmHarnessReleaseClaimState::PlanReady
                | SwarmHarnessReleaseClaimState::MeasuredAuthoritative
        ) {
            summary.large_host_plan_count += 1;
        }

        let scenario_issue_count = issues.len() - issue_start;
        let verdict = scenario_verdict(scenario, scenario_issue_count);
        *summary
            .verdict_counts
            .entry(verdict.label().to_owned())
            .or_insert(0) += 1;
        summary.scenario_verdicts.push(SwarmScenarioValidationRow {
            scenario_id: scenario.scenario_id.clone(),
            verdict,
            classification: scenario.classification.label().to_owned(),
            release_claim_state: scenario.release_claim_state.label().to_owned(),
            host_lane: scenario.host.lane.label().to_owned(),
            host_meets_target: meets_target,
            numa_authoritative,
            issue_paths: issues[issue_start..]
                .iter()
                .map(|issue| issue.path.clone())
                .collect(),
        });
    }

    summary
}

fn validate_scenario_shape(
    scenario: &SwarmWorkloadScenario,
    scenario_index: usize,
    profile_ids: &BTreeSet<String>,
    issues: &mut Vec<SwarmValidationIssue>,
) {
    let scenario_path = format!("scenarios[{scenario_index}]");
    if scenario.workload_profile_ids.is_empty() {
        push_issue(
            issues,
            format!("{scenario_path}.workload_profile_ids"),
            "must reference at least one workload profile",
        );
    }
    if scenario.workload_seeds.is_empty() {
        push_issue(
            issues,
            format!("{scenario_path}.workload_seeds"),
            "must not be empty",
        );
    }
    if matches!(scenario.cleanup_status, SwarmCleanupStatus::Unknown) {
        push_issue(
            issues,
            format!("{scenario_path}.cleanup_status"),
            "must not be unknown",
        );
    }
    for (workload_index, workload_profile_id) in scenario.workload_profile_ids.iter().enumerate() {
        if !profile_ids.contains(workload_profile_id) {
            push_issue(
                issues,
                format!("{scenario_path}.workload_profile_ids[{workload_index}]"),
                format!("references unknown workload profile {workload_profile_id}"),
            );
        }
    }
    if scenario.reproduction_command.trim().is_empty() {
        push_issue(
            issues,
            format!("{scenario_path}.reproduction_command"),
            "must not be empty",
        );
    }
    if scenario.raw_logs.is_empty() {
        push_issue(
            issues,
            format!("{scenario_path}.raw_logs"),
            "must not be empty",
        );
    }
    if scenario.artifact_paths.is_empty() {
        push_issue(
            issues,
            format!("{scenario_path}.artifact_paths"),
            "must not be empty",
        );
    }
}

fn validate_host(
    host: &SwarmHostFingerprint,
    scenario_index: usize,
    issues: &mut Vec<SwarmValidationIssue>,
) {
    let host_path = format!("scenarios[{scenario_index}].host");
    for (field, value) in [
        ("host_fingerprint", host.host_fingerprint.as_str()),
        ("storage_class", host.storage_class.as_str()),
        ("kernel", host.kernel.as_str()),
        (
            "worker_isolation_notes",
            host.worker_isolation_notes.as_str(),
        ),
        (
            "fuse_capability.detail",
            host.fuse_capability.detail.as_str(),
        ),
        ("numa.placement_intent", host.numa.placement_intent.as_str()),
    ] {
        if value.trim().is_empty() {
            push_issue(issues, format!("{host_path}.{field}"), "must not be empty");
        }
    }
    if host.cpu_cores_logical == 0 {
        push_issue(
            issues,
            format!("{host_path}.cpu_cores_logical"),
            "must be positive",
        );
    }
    if host.ram_total_gb <= 0.0 || host.ram_available_gb < 0.0 {
        push_issue(
            issues,
            format!("{host_path}.ram_total_gb"),
            "RAM totals must be non-negative and total must be positive",
        );
    }
    if host.ram_available_gb > host.ram_total_gb {
        push_issue(
            issues,
            format!("{host_path}.ram_available_gb"),
            "cannot exceed ram_total_gb",
        );
    }
    if host.numa.observable && host.numa.node_count.is_none_or(|nodes| nodes == 0) {
        push_issue(
            issues,
            format!("{host_path}.numa.node_count"),
            "NUMA is observable but node_count is missing or zero",
        );
    }
    if !host.numa.observable
        && host
            .numa
            .missing_reason
            .as_ref()
            .is_none_or(|reason| reason.trim().is_empty())
    {
        push_issue(
            issues,
            format!("{host_path}.numa.missing_reason"),
            "NUMA is not observable but missing_reason is absent",
        );
    }
    if matches!(host.rch_or_local_lane, SwarmRchOrLocalLane::Unknown) {
        push_issue(
            issues,
            format!("{host_path}.rch_or_local_lane"),
            "must not be unknown",
        );
    }
}

fn validate_counters(
    scenario: &SwarmWorkloadScenario,
    scenario_index: usize,
    issues: &mut Vec<SwarmValidationIssue>,
) {
    let counters = &scenario.counters;
    let counters_path = format!("scenarios[{scenario_index}].counters");
    if counters.average_queue_depth < 0.0 {
        push_issue(
            issues,
            format!("{counters_path}.average_queue_depth"),
            "must not be negative",
        );
    }
    if counters.average_queue_depth > f64::from(counters.max_queue_depth) {
        push_issue(
            issues,
            format!("{counters_path}.average_queue_depth"),
            "cannot exceed max_queue_depth",
        );
    }
    if counters.p99_latency_budget_us <= 0.0 {
        push_issue(
            issues,
            format!("{counters_path}.p99_latency_budget_us"),
            "must be positive",
        );
    }
    if matches!(counters.backpressure_state, SwarmBackpressureState::Unknown) {
        push_issue(
            issues,
            format!("{counters_path}.backpressure_state"),
            "must not be unknown",
        );
    }
}

fn validate_downgraded_scenario(
    scenario: &SwarmWorkloadScenario,
    scenario_index: usize,
    issues: &mut Vec<SwarmValidationIssue>,
) {
    let scenario_path = format!("scenarios[{scenario_index}]");
    if matches!(scenario.classification, SwarmHarnessClassification::Pass) {
        push_issue(
            issues,
            format!("{scenario_path}.classification"),
            "is below target or lacks NUMA visibility but is classified pass",
        );
    }
    if !scenario.release_claim_state.safe_for_inadequate_host() {
        push_issue(
            issues,
            format!("{scenario_path}.release_claim_state"),
            format!(
                "is below target or lacks NUMA visibility but release_claim_state is {}",
                scenario.release_claim_state.label()
            ),
        );
    }
}

fn validate_authoritative_scenario(
    scenario: &SwarmWorkloadScenario,
    scenario_index: usize,
    meets_target: bool,
    numa_authoritative: bool,
    issues: &mut Vec<SwarmValidationIssue>,
) {
    let scenario_path = format!("scenarios[{scenario_index}]");
    if !meets_target {
        push_issue(
            issues,
            format!("{scenario_path}.release_claim_state"),
            "measured_authoritative claim is below the 64-core/256GB target",
        );
    }
    if !numa_authoritative {
        push_issue(
            issues,
            format!("{scenario_path}.host.numa"),
            "measured_authoritative claim lacks observable NUMA nodes",
        );
    }
    if !matches!(scenario.host.lane, SwarmHostLane::PermissionedLargeHost) {
        push_issue(
            issues,
            format!("{scenario_path}.host.lane"),
            "measured_authoritative claim must use permissioned_large_host lane",
        );
    }
}

fn build_profile_matrix(manifest: &SwarmWorkloadHarnessManifest) -> Vec<SwarmProfileMatrixRow> {
    manifest
        .workload_profiles
        .iter()
        .map(|profile| SwarmProfileMatrixRow {
            workload_profile_id: profile.workload_profile_id.clone(),
            workload_class: profile.workload_class.label().to_owned(),
            plan_mode: profile.command_plan.plan_mode.label().to_owned(),
            exact_command: profile.command_plan.exact_command.clone(),
            max_threads: profile.command_plan.resource_caps.max_threads,
            max_memory_gb: profile.command_plan.resource_caps.max_memory_gb,
            max_queue_depth: profile.command_plan.resource_caps.max_queue_depth,
            shard_count: profile.placement.shard_count,
            numa_policy: profile.placement.numa_policy.clone(),
            cleanup_policy: profile.placement.cleanup_policy.label().to_owned(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_swarm_workload_harness_manifest_validates() -> Result<()> {
        let manifest = load_swarm_workload_harness_manifest(Path::new(&workspace_path(
            DEFAULT_SWARM_WORKLOAD_HARNESS_MANIFEST,
        )))?;
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(
            report.valid,
            "checked-in swarm workload harness manifest should validate: {:?}",
            report.errors
        );
        assert_eq!(report.profile_count, REQUIRED_WORKLOAD_CLASSES.len());
        assert_eq!(report.host_downgrade_count, 1);
        assert_eq!(report.large_host_plan_count, 1);
        assert_eq!(report.verdict_counts.get("pass"), Some(&1));
        assert_eq!(report.verdict_counts.get("skip"), Some(&1));
        assert_eq!(report.issues, [] as [SwarmValidationIssue; 0]);
        Ok(())
    }

    /// The markdown renderer is consumed by proof-bundle and release-gate
    /// operator workflows. Validator assertions above pin manifest semantics;
    /// this snapshot pins the title, metadata bullets, count sections,
    /// workload-profile table, scenario-verdict table, boolean formatting, and
    /// omitted Missing Workload Classes / Errors sections for the checked-in
    /// manifest fixture.
    #[test]
    fn render_swarm_workload_harness_markdown_checked_in_manifest_snapshot() -> Result<()> {
        let manifest = load_swarm_workload_harness_manifest(Path::new(&workspace_path(
            DEFAULT_SWARM_WORKLOAD_HARNESS_MANIFEST,
        )))?;
        let report = validate_swarm_workload_harness_manifest(&manifest);
        let markdown = render_swarm_workload_harness_markdown(&report);

        insta::assert_snapshot!(
            "render_swarm_workload_harness_markdown_checked_in_manifest",
            markdown
        );
        Ok(())
    }

    #[test]
    fn swarm_workload_harness_report_json_shape() -> Result<()> {
        let manifest = load_swarm_workload_harness_manifest(Path::new(&workspace_path(
            DEFAULT_SWARM_WORKLOAD_HARNESS_MANIFEST,
        )))?;
        let report = validate_swarm_workload_harness_manifest(&manifest);
        let json = serde_json::to_string_pretty(&report)?;

        insta::assert_snapshot!("swarm_workload_harness_report_json_shape", json);

        let roundtrip: SwarmWorkloadHarnessReport = serde_json::from_str(&json)?;
        assert_eq!(roundtrip, report);
        Ok(())
    }

    fn scenario_mut(
        manifest: &mut SwarmWorkloadHarnessManifest,
        index: usize,
    ) -> Result<&mut SwarmWorkloadScenario> {
        manifest
            .scenarios
            .get_mut(index)
            .with_context(|| format!("fixture must include scenario at index {index}"))
    }

    fn workload_profile_mut(
        manifest: &mut SwarmWorkloadHarnessManifest,
        index: usize,
    ) -> Result<&mut SwarmWorkloadProfile> {
        manifest
            .workload_profiles
            .get_mut(index)
            .with_context(|| format!("fixture must include workload profile at index {index}"))
    }

    fn scenario_path(index: usize, suffix: &str) -> String {
        format!("scenarios[{index}].{suffix}")
    }

    #[test]
    fn small_host_pass_claim_fails_closed() -> Result<()> {
        let mut manifest = fixture_manifest();
        let scenario = scenario_mut(&mut manifest, 1)?;
        scenario.classification = SwarmHarnessClassification::Pass;
        scenario.release_claim_state = SwarmHarnessReleaseClaimState::MeasuredAuthoritative;
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("classified pass"))
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("below the 64-core/256GB target"))
        );
        assert!(
            report
                .scenario_verdicts
                .iter()
                .any(|row| row.scenario_id == "swarm_workload_small_host_smoke"
                    && row.verdict == SwarmValidationVerdict::Error)
        );
        Ok(())
    }

    #[test]
    fn missing_numa_reason_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest();
        scenario_mut(&mut manifest, 1)?.host.numa.missing_reason = None;
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("missing_reason"))
        );
        Ok(())
    }

    #[test]
    fn missing_required_workload_class_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .workload_profiles
            .retain(|profile| profile.workload_class != SwarmWorkloadClass::CachePressure);
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(!report.valid);
        assert!(
            report
                .missing_workload_classes
                .contains(&"cache_pressure".to_owned())
        );
    }

    #[test]
    fn missing_workload_seeds_are_rejected() -> Result<()> {
        let mut manifest = fixture_manifest();
        scenario_mut(&mut manifest, 0)?.workload_seeds.clear();
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("workload_seeds"))
        );
        Ok(())
    }

    #[test]
    fn unknown_cleanup_status_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest();
        scenario_mut(&mut manifest, 0)?.cleanup_status = SwarmCleanupStatus::Unknown;
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("cleanup_status"))
        );
        Ok(())
    }

    #[test]
    fn stale_manifest_is_rejected_with_exact_path() {
        let manifest = fixture_manifest();
        let config = SwarmWorkloadHarnessValidationConfig {
            reference_epoch_days: parse_manifest_timestamp_epoch_days("2026-05-20T00:00:00Z"),
            max_age_days: 7,
        };
        let report = validate_swarm_workload_harness_manifest_with_config(&manifest, &config);
        assert!(!report.valid);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.path == "generated_at"
                    && issue.message.contains("stale manifest"))
        );
    }

    #[test]
    fn missing_raw_logs_are_rejected_with_exact_path() -> Result<()> {
        let mut manifest = fixture_manifest();
        scenario_mut(&mut manifest, 0)?.raw_logs.clear();
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(!report.valid);
        let raw_logs_path = scenario_path(0, "raw_logs");
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.path == raw_logs_path)
        );
        Ok(())
    }

    #[test]
    fn missing_cpu_ram_and_numa_visibility_are_rejected() -> Result<()> {
        let mut manifest = fixture_manifest();
        let scenario = scenario_mut(&mut manifest, 0)?;
        scenario.host.cpu_cores_logical = 0;
        scenario.host.ram_total_gb = 0.0;
        scenario.host.numa.node_count = None;
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(!report.valid);
        let cpu_path = scenario_path(0, "host.cpu_cores_logical");
        let ram_path = scenario_path(0, "host.ram_total_gb");
        let numa_path = scenario_path(0, "host.numa.node_count");
        assert!(report.issues.iter().any(|issue| issue.path == cpu_path));
        assert!(report.issues.iter().any(|issue| issue.path == ram_path));
        assert!(report.issues.iter().any(|issue| issue.path == numa_path));
        Ok(())
    }

    #[test]
    fn invalid_backpressure_state_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest();
        scenario_mut(&mut manifest, 0)?.counters.backpressure_state =
            SwarmBackpressureState::Unknown;
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(!report.valid);
        let backpressure_path = scenario_path(0, "counters.backpressure_state");
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.path == backpressure_path)
        );
        Ok(())
    }

    #[test]
    fn mutating_command_plan_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest();
        workload_profile_mut(&mut manifest, 0)?
            .command_plan
            .mutates_host_filesystems = true;
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("dry-run-safe swarm workload plans"))
        );
        Ok(())
    }

    fn fixture_manifest() -> SwarmWorkloadHarnessManifest {
        let target_host = SwarmWorkloadTargetHost {
            min_cpu_cores_logical: 64,
            min_ram_total_gb: 256,
            min_ram_available_gb: 192,
            min_numa_nodes: 2,
        };
        let profiles = REQUIRED_WORKLOAD_CLASSES
            .iter()
            .map(|workload_class| fixture_profile(*workload_class))
            .collect::<Vec<_>>();
        SwarmWorkloadHarnessManifest {
            schema_version: SWARM_WORKLOAD_HARNESS_SCHEMA_VERSION,
            manifest_id: "test-swarm-workload-harness".to_owned(),
            generated_at: "2026-05-03T23:20:00Z".to_owned(),
            target_host,
            workload_profiles: profiles,
            scenarios: vec![large_host_scenario(), small_host_scenario()],
            required_log_fields: REQUIRED_LOG_FIELDS
                .iter()
                .map(|field| (*field).to_owned())
                .collect(),
            proof_consumers: vec!["bd-p2j3e.2".to_owned(), "proof-bundle".to_owned()],
        }
    }

    fn fixture_profile(workload_class: SwarmWorkloadClass) -> SwarmWorkloadProfile {
        let workload_id = format!("{}_dry_run", workload_class.label());
        SwarmWorkloadProfile {
            workload_profile_id: workload_id.clone(),
            workload_class,
            description: format!("dry-run plan for {}", workload_class.label()),
            command_plan: SwarmCommandPlan {
                plan_id: format!("{workload_id}_plan"),
                plan_mode: SwarmCommandPlanMode::DryRun,
                exact_command: format!(
                    "cargo run -p ffs-harness -- validate-swarm-workload-harness --manifest {DEFAULT_SWARM_WORKLOAD_HARNESS_MANIFEST}"
                ),
                dry_run_only: true,
                mutates_host_filesystems: false,
                expected_artifacts: vec![SwarmExpectedArtifact {
                    path: format!("artifacts/performance/swarm-workload/{workload_id}.json"),
                    kind: "json_report".to_owned(),
                    required: true,
                }],
                resource_caps: SwarmResourceCaps {
                    max_duration_secs: 600,
                    max_threads: 64,
                    max_memory_gb: 64.0,
                    max_temp_storage_gb: 16.0,
                    max_queue_depth: 4096,
                },
            },
            placement: SwarmPlacementIntent {
                shard_count: 64,
                core_allocation: "spread across isolated worker core groups".to_owned(),
                numa_policy: "pin shards to observed NUMA nodes; downgrade if unavailable"
                    .to_owned(),
                queue_isolation: "separate metadata/write/repair queues".to_owned(),
                cleanup_policy: SwarmCleanupPolicy::NoHostMutation,
            },
        }
    }

    fn large_host_scenario() -> SwarmWorkloadScenario {
        SwarmWorkloadScenario {
            scenario_id: "swarm_workload_64c_256gb_dry_run_plan".to_owned(),
            host: SwarmHostFingerprint {
                host_fingerprint: "synthetic-96c-512gb-2numa-plan-lane".to_owned(),
                cpu_cores_logical: 96,
                numa: SwarmNumaObservation {
                    observable: true,
                    node_count: Some(2),
                    placement_intent: "2-node spread with per-node shard groups".to_owned(),
                    missing_reason: None,
                },
                ram_total_gb: 512.0,
                ram_available_gb: 420.0,
                storage_class: "nvme".to_owned(),
                fuse_capability: SwarmFuseCapability {
                    state: SwarmFuseCapabilityState::Available,
                    detail: "permissioned lane reports /dev/fuse and fusermount3".to_owned(),
                },
                kernel: "Linux 6.17.0-14-generic x86_64 GNU/Linux".to_owned(),
                lane: SwarmHostLane::PermissionedLargeHost,
                rch_or_local_lane: SwarmRchOrLocalLane::Rch,
                worker_isolation_notes: "reserved worker with isolated target dir".to_owned(),
            },
            workload_profile_ids: REQUIRED_WORKLOAD_CLASSES
                .iter()
                .map(|workload_class| format!("{}_dry_run", workload_class.label()))
                .collect(),
            workload_seeds: vec![10_001, 10_002, 10_003, 10_004, 10_005],
            counters: SwarmQueueBackpressureCounters {
                max_queue_depth: 4096,
                average_queue_depth: 512.0,
                backpressure_state: SwarmBackpressureState::Healthy,
                throttle_events: 0,
                rejected_writes: 0,
                p99_latency_budget_us: 12_000.0,
            },
            cleanup_status: SwarmCleanupStatus::NotStartedDryRun,
            classification: SwarmHarnessClassification::Pass,
            release_claim_state: SwarmHarnessReleaseClaimState::PlanReady,
            reproduction_command: format!(
                "cargo run -p ffs-harness -- validate-swarm-workload-harness --manifest {DEFAULT_SWARM_WORKLOAD_HARNESS_MANIFEST}"
            ),
            raw_logs: vec!["artifacts/performance/swarm-workload/large-host/run.log".to_owned()],
            artifact_paths: vec![
                "artifacts/performance/swarm-workload/large-host/report.json".to_owned(),
            ],
        }
    }

    fn small_host_scenario() -> SwarmWorkloadScenario {
        SwarmWorkloadScenario {
            scenario_id: "swarm_workload_small_host_smoke".to_owned(),
            host: SwarmHostFingerprint {
                host_fingerprint: "developer-smoke-16c-64gb-no-numa".to_owned(),
                cpu_cores_logical: 16,
                numa: SwarmNumaObservation {
                    observable: false,
                    node_count: None,
                    placement_intent: "single-node smoke; no placement claim".to_owned(),
                    missing_reason: Some("NUMA topology not visible in developer lane".to_owned()),
                },
                ram_total_gb: 64.0,
                ram_available_gb: 40.0,
                storage_class: "nvme".to_owned(),
                fuse_capability: SwarmFuseCapability {
                    state: SwarmFuseCapabilityState::Unknown,
                    detail: "developer smoke does not require mounted execution".to_owned(),
                },
                kernel: "Linux developer-smoke".to_owned(),
                lane: SwarmHostLane::DeveloperSmoke,
                rch_or_local_lane: SwarmRchOrLocalLane::Local,
                worker_isolation_notes: "uses dry-run-only artifacts".to_owned(),
            },
            workload_profile_ids: vec!["metadata_storm_dry_run".to_owned()],
            workload_seeds: vec![20_001],
            counters: SwarmQueueBackpressureCounters {
                max_queue_depth: 128,
                average_queue_depth: 4.0,
                backpressure_state: SwarmBackpressureState::Healthy,
                throttle_events: 0,
                rejected_writes: 0,
                p99_latency_budget_us: 25_000.0,
            },
            cleanup_status: SwarmCleanupStatus::NotStartedDryRun,
            classification: SwarmHarnessClassification::CapabilitySkip,
            release_claim_state: SwarmHarnessReleaseClaimState::SmallHostSmoke,
            reproduction_command: format!(
                "cargo run -p ffs-harness -- validate-swarm-workload-harness --manifest {DEFAULT_SWARM_WORKLOAD_HARNESS_MANIFEST}"
            ),
            raw_logs: vec!["artifacts/performance/swarm-workload/small-host/run.log".to_owned()],
            artifact_paths: vec![
                "artifacts/performance/swarm-workload/small-host/report.json".to_owned(),
            ],
        }
    }

    fn workspace_path(relative: &str) -> String {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
            .display()
            .to_string()
    }
}
