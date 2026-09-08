#![allow(clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! Swarm-scale cache admission and memory-budget contract for `bd-p2j3e.5`.
//!
//! This validator keeps large-host cache tuning honest: fixture smoke on a
//! small host cannot become a 256GB/64-core claim, and every tuning candidate
//! must carry backpressure, flush, raw-log, and reproduction evidence.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const DEFAULT_SWARM_CACHE_CONTROLLER_CONTRACT: &str =
    "benchmarks/swarm_cache_controller_contract.json";
pub const SWARM_CACHE_CONTROLLER_SCHEMA_VERSION: u32 = 1;

const REQUIRED_LOG_FIELDS: [&str; 16] = [
    "scenario_id",
    "host_fingerprint",
    "cpu_cores_logical",
    "ram_total_gb",
    "workload_class",
    "candidate_id",
    "algorithm",
    "hit_rate",
    "p99_latency_us",
    "dirty_ratio",
    "eviction_pressure",
    "admission_decision",
    "backpressure_state",
    "flush_policy",
    "release_claim_state",
    "reproduction_command",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmCacheControllerContract {
    pub schema_version: u32,
    pub contract_id: String,
    pub generated_at: String,
    pub target_host: SwarmCacheTargetHost,
    pub fallback_candidate_id: String,
    pub candidates: Vec<CacheAdmissionCandidate>,
    pub scenarios: Vec<SwarmCacheScenario>,
    #[serde(default)]
    pub required_log_fields: Vec<String>,
    #[serde(default)]
    pub release_gate_consumers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmCacheTargetHost {
    pub min_cpu_cores_logical: u32,
    pub min_ram_total_gb: u32,
    pub min_ram_available_gb: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheAdmissionCandidate {
    pub candidate_id: String,
    pub algorithm: CacheAdmissionAlgorithm,
    pub description: String,
    pub fallback_candidate_id: String,
    pub expected_loss_rule: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheAdmissionAlgorithm {
    CurrentArc,
    S3Fifo,
    SegmentedAdmission,
    ArcWithPressureGuard,
    Other,
}

impl CacheAdmissionAlgorithm {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CurrentArc => "current_arc",
            Self::S3Fifo => "s3_fifo",
            Self::SegmentedAdmission => "segmented_admission",
            Self::ArcWithPressureGuard => "arc_with_pressure_guard",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmCacheScenario {
    pub scenario_id: String,
    pub workload_class: SwarmCacheWorkloadClass,
    pub host: SwarmCacheHostObservation,
    pub measurements: Vec<CacheCandidateMeasurement>,
    pub backpressure: CacheBackpressureObservation,
    pub release_claim_state: CacheReleaseClaimState,
    pub reproduction_command: String,
    pub raw_logs: Vec<String>,
    pub artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmCacheWorkloadClass {
    MetadataStorm,
    AppendFsync,
    MixedReadWrite,
    ScrubRepairOverlap,
    CachePressure,
    FixtureSmoke,
}

impl SwarmCacheWorkloadClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MetadataStorm => "metadata_storm",
            Self::AppendFsync => "append_fsync",
            Self::MixedReadWrite => "mixed_read_write",
            Self::ScrubRepairOverlap => "scrub_repair_overlap",
            Self::CachePressure => "cache_pressure",
            Self::FixtureSmoke => "fixture_smoke",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmCacheHostObservation {
    pub host_fingerprint: String,
    pub cpu_cores_logical: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub numa_nodes: Option<u32>,
    pub ram_total_gb: f64,
    pub ram_available_gb: f64,
    pub storage_class: String,
    pub lane: SwarmCacheLane,
}

impl SwarmCacheHostObservation {
    #[must_use]
    pub fn meets_target(&self, target: &SwarmCacheTargetHost) -> bool {
        self.cpu_cores_logical >= target.min_cpu_cores_logical
            && self.ram_total_gb >= f64::from(target.min_ram_total_gb)
            && self.ram_available_gb >= f64::from(target.min_ram_available_gb)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmCacheLane {
    DeveloperSmoke,
    RchWorker,
    PermissionedLargeHost,
    CiSmoke,
}

impl SwarmCacheLane {
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheCandidateMeasurement {
    pub candidate_id: String,
    pub hit_rate: f64,
    pub p99_latency_us: f64,
    pub dirty_ratio: f64,
    pub memory_overhead_gb: f64,
    pub eviction_pressure: f64,
    pub admission_decision: CacheAdmissionDecision,
    pub release_claim_state: CacheReleaseClaimState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheAdmissionDecision {
    Admit,
    Bypass,
    EvictThenAdmit,
    FallbackToCurrentArc,
    RejectUntilMeasured,
}

impl CacheAdmissionDecision {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Bypass => "bypass",
            Self::EvictThenAdmit => "evict_then_admit",
            Self::FallbackToCurrentArc => "fallback_to_current_arc",
            Self::RejectUntilMeasured => "reject_until_measured",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheReleaseClaimState {
    Experimental,
    FixtureSmokeOnly,
    SmallHostSmoke,
    CapabilitySkip,
    MeasuredLocal,
    MeasuredAuthoritative,
    Blocked,
}

impl CacheReleaseClaimState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Experimental => "experimental",
            Self::FixtureSmokeOnly => "fixture_smoke_only",
            Self::SmallHostSmoke => "small_host_smoke",
            Self::CapabilitySkip => "capability_skip",
            Self::MeasuredLocal => "measured_local",
            Self::MeasuredAuthoritative => "measured_authoritative",
            Self::Blocked => "blocked",
        }
    }

    #[must_use]
    pub const fn requires_large_host(self) -> bool {
        matches!(self, Self::MeasuredAuthoritative)
    }

    #[must_use]
    pub const fn stronger_than_smoke(self) -> bool {
        matches!(self, Self::MeasuredLocal | Self::MeasuredAuthoritative)
    }

    #[must_use]
    pub const fn safe_for_small_host(self) -> bool {
        matches!(
            self,
            Self::Experimental
                | Self::FixtureSmokeOnly
                | Self::SmallHostSmoke
                | Self::CapabilitySkip
                | Self::Blocked
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheBackpressureObservation {
    pub dirty_high_watermark: f64,
    pub dirty_critical_watermark: f64,
    pub current_dirty_ratio: f64,
    pub flush_policy: String,
    pub flush_batch_size: u32,
    pub backpressure_state: CacheBackpressureState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheBackpressureState {
    Healthy,
    Throttled,
    Critical,
    Unknown,
}

impl CacheBackpressureState {
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmCacheValidationReport {
    pub schema_version: u32,
    pub contract_id: String,
    pub valid: bool,
    pub candidate_count: usize,
    pub scenario_count: usize,
    pub small_host_downgrade_count: usize,
    pub authoritative_claim_count: usize,
    pub claim_state_counts: BTreeMap<String, usize>,
    pub rows: Vec<SwarmCacheValidationRow>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmCacheValidationRow {
    pub scenario_id: String,
    pub workload_class: String,
    pub host_meets_target: bool,
    pub release_claim_state: String,
    pub lane: String,
    pub candidate_ids: Vec<String>,
    pub best_p99_candidate_id: String,
    pub current_arc_p99_us: f64,
    pub best_p99_us: f64,
    pub backpressure_state: String,
}

pub fn load_swarm_cache_controller_contract(path: &Path) -> Result<SwarmCacheControllerContract> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read swarm cache contract {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid swarm cache contract JSON {}", path.display()))
}

#[must_use]
pub fn validate_swarm_cache_controller_contract(
    contract: &SwarmCacheControllerContract,
) -> SwarmCacheValidationReport {
    let mut errors = validate_contract_shape(contract);
    let candidate_ids = collect_candidate_ids(contract, &mut errors);
    let current_arc_id = current_arc_candidate_id(contract, &mut errors);
    let mut rows = Vec::new();

    for scenario in &contract.scenarios {
        validate_scenario(
            contract,
            scenario,
            &candidate_ids,
            current_arc_id.as_deref(),
            &mut errors,
        );
        if let Some(row) = build_row(contract, scenario, current_arc_id.as_deref(), &mut errors) {
            rows.push(row);
        }
    }

    let small_host_downgrade_count = contract
        .scenarios
        .iter()
        .filter(|scenario| {
            !scenario.host.meets_target(&contract.target_host)
                && scenario.release_claim_state.safe_for_small_host()
        })
        .count();
    let authoritative_claim_count = contract
        .scenarios
        .iter()
        .filter(|scenario| {
            scenario
                .release_claim_state
                .eq(&CacheReleaseClaimState::MeasuredAuthoritative)
        })
        .count();
    let claim_state_counts = count_claim_states(contract);

    SwarmCacheValidationReport {
        schema_version: SWARM_CACHE_CONTROLLER_SCHEMA_VERSION,
        contract_id: contract.contract_id.clone(),
        valid: errors.is_empty(),
        candidate_count: contract.candidates.len(),
        scenario_count: contract.scenarios.len(),
        small_host_downgrade_count,
        authoritative_claim_count,
        claim_state_counts,
        rows,
        errors,
    }
}

pub fn fail_on_swarm_cache_controller_errors(report: &SwarmCacheValidationReport) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "swarm cache controller contract invalid: {} error(s)",
            report.errors.len()
        )
    }
}

#[must_use]
pub fn render_swarm_cache_controller_markdown(report: &SwarmCacheValidationReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Swarm Cache Controller Contract");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Contract: `{}`", report.contract_id);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Candidates: `{}`", report.candidate_count);
    let _ = writeln!(out, "- Scenarios: `{}`", report.scenario_count);
    let _ = writeln!(
        out,
        "- Small-host downgrades: `{}`",
        report.small_host_downgrade_count
    );
    let _ = writeln!(
        out,
        "- Authoritative claims: `{}`",
        report.authoritative_claim_count
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Scenario | Workload | Host target | Claim | Lane | Best p99 | Backpressure |"
    );
    let _ = writeln!(
        out,
        "|----------|----------|-------------|-------|------|----------|--------------|"
    );
    for row in &report.rows {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` `{:.1}us` | `{}` |",
            row.scenario_id,
            row.workload_class,
            row.host_meets_target,
            row.release_claim_state,
            row.lane,
            row.best_p99_candidate_id,
            row.best_p99_us,
            row.backpressure_state
        );
    }

    if !report.errors.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "## Errors");
        for error in &report.errors {
            let _ = writeln!(out, "- {error}");
        }
    }

    out
}

fn validate_contract_shape(contract: &SwarmCacheControllerContract) -> Vec<String> {
    let mut errors = Vec::new();
    if contract
        .schema_version
        .ne(&SWARM_CACHE_CONTROLLER_SCHEMA_VERSION)
    {
        errors.push(format!(
            "schema_version must be {}; got {}",
            SWARM_CACHE_CONTROLLER_SCHEMA_VERSION, contract.schema_version
        ));
    }
    require_non_empty("contract_id", &contract.contract_id, &mut errors);
    require_non_empty("generated_at", &contract.generated_at, &mut errors);
    require_non_empty(
        "fallback_candidate_id",
        &contract.fallback_candidate_id,
        &mut errors,
    );
    if contract.target_host.min_cpu_cores_logical < 64 {
        errors.push("target_host.min_cpu_cores_logical must be at least 64".to_owned());
    }
    if contract.target_host.min_ram_total_gb < 256 {
        errors.push("target_host.min_ram_total_gb must be at least 256".to_owned());
    }
    if contract.target_host.min_ram_available_gb.eq(&0) {
        errors.push("target_host.min_ram_available_gb must be positive".to_owned());
    }
    if contract.candidates.is_empty() {
        errors.push("at least one cache admission candidate is required".to_owned());
    }
    if contract.scenarios.is_empty() {
        errors.push("at least one scenario is required".to_owned());
    }
    validate_required_log_fields(&contract.required_log_fields, &mut errors);
    if contract.release_gate_consumers.is_empty() {
        errors.push("release_gate_consumers must include at least one consumer".to_owned());
    }
    errors
}

fn collect_candidate_ids(
    contract: &SwarmCacheControllerContract,
    errors: &mut Vec<String>,
) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for candidate in &contract.candidates {
        require_non_empty("candidate.candidate_id", &candidate.candidate_id, errors);
        require_non_empty("candidate.description", &candidate.description, errors);
        require_non_empty(
            "candidate.fallback_candidate_id",
            &candidate.fallback_candidate_id,
            errors,
        );
        require_non_empty(
            "candidate.expected_loss_rule",
            &candidate.expected_loss_rule,
            errors,
        );
        if !ids.insert(candidate.candidate_id.clone()) {
            errors.push(format!("duplicate candidate_id {}", candidate.candidate_id));
        }
    }

    if !contract.fallback_candidate_id.is_empty() && !ids.contains(&contract.fallback_candidate_id)
    {
        errors.push(format!(
            "fallback_candidate_id {} is not a declared candidate",
            contract.fallback_candidate_id
        ));
    }

    for candidate in &contract.candidates {
        if !candidate.fallback_candidate_id.is_empty()
            && !ids.contains(&candidate.fallback_candidate_id)
        {
            errors.push(format!(
                "candidate {} references unknown fallback {}",
                candidate.candidate_id, candidate.fallback_candidate_id
            ));
        }
    }

    ids
}

fn current_arc_candidate_id(
    contract: &SwarmCacheControllerContract,
    errors: &mut Vec<String>,
) -> Option<String> {
    let current_arc_candidates = contract
        .candidates
        .iter()
        .filter(|candidate| candidate.algorithm.eq(&CacheAdmissionAlgorithm::CurrentArc))
        .collect::<Vec<_>>();

    match current_arc_candidates.as_slice() {
        [candidate] => {
            if candidate.candidate_id.ne(&contract.fallback_candidate_id) {
                errors.push(format!(
                    "current ARC candidate {} must be the top-level fallback {}",
                    candidate.candidate_id, contract.fallback_candidate_id
                ));
            }
            Some(candidate.candidate_id.clone())
        }
        [] => {
            errors
                .push("one current_arc candidate is required as conservative fallback".to_owned());
            None
        }
        _ => {
            errors.push("exactly one current_arc candidate is required".to_owned());
            None
        }
    }
}

fn validate_scenario(
    contract: &SwarmCacheControllerContract,
    scenario: &SwarmCacheScenario,
    candidate_ids: &BTreeSet<String>,
    current_arc_id: Option<&str>,
    errors: &mut Vec<String>,
) {
    require_non_empty("scenario.scenario_id", &scenario.scenario_id, errors);
    require_non_empty(
        "scenario.host.host_fingerprint",
        &scenario.host.host_fingerprint,
        errors,
    );
    require_non_empty(
        "scenario.host.storage_class",
        &scenario.host.storage_class,
        errors,
    );
    require_non_empty(
        "scenario.reproduction_command",
        &scenario.reproduction_command,
        errors,
    );
    validate_non_empty_paths("scenario.raw_logs", &scenario.raw_logs, errors);
    validate_non_empty_paths("scenario.artifact_paths", &scenario.artifact_paths, errors);
    validate_host_observation(contract, scenario, errors);
    validate_backpressure(&scenario.scenario_id, &scenario.backpressure, errors);
    validate_measurements(
        &scenario.scenario_id,
        &scenario.measurements,
        candidate_ids,
        current_arc_id,
        scenario.host.meets_target(&contract.target_host),
        errors,
    );
}

fn validate_host_observation(
    contract: &SwarmCacheControllerContract,
    scenario: &SwarmCacheScenario,
    errors: &mut Vec<String>,
) {
    if scenario.host.cpu_cores_logical.eq(&0) {
        errors.push(format!(
            "scenario {} host.cpu_cores_logical must be positive",
            scenario.scenario_id
        ));
    }
    if let Some(numa_nodes) = scenario.host.numa_nodes
        && numa_nodes.eq(&0)
    {
        errors.push(format!(
            "scenario {} host.numa_nodes must be positive when present",
            scenario.scenario_id
        ));
    }
    if scenario.host.ram_total_gb <= 0.0 || scenario.host.ram_available_gb <= 0.0 {
        errors.push(format!(
            "scenario {} host RAM totals must be positive",
            scenario.scenario_id
        ));
    }
    if scenario.host.ram_available_gb > scenario.host.ram_total_gb {
        errors.push(format!(
            "scenario {} ram_available_gb exceeds ram_total_gb",
            scenario.scenario_id
        ));
    }

    let meets_target = scenario.host.meets_target(&contract.target_host);
    if !meets_target && !scenario.release_claim_state.safe_for_small_host() {
        errors.push(format!(
            "scenario {} is below the 64-core/256GB target but claims {}",
            scenario.scenario_id,
            scenario.release_claim_state.label()
        ));
    }
    if scenario.release_claim_state.requires_large_host()
        && scenario
            .host
            .lane
            .ne(&SwarmCacheLane::PermissionedLargeHost)
    {
        errors.push(format!(
            "scenario {} authoritative claim must run in permissioned_large_host lane",
            scenario.scenario_id
        ));
    }
}

fn validate_backpressure(
    scenario_id: &str,
    backpressure: &CacheBackpressureObservation,
    errors: &mut Vec<String>,
) {
    if !(0.0..=1.0).contains(&backpressure.dirty_high_watermark) {
        errors.push(format!(
            "scenario {scenario_id} dirty_high_watermark must be in [0,1]"
        ));
    }
    if !(0.0..=1.0).contains(&backpressure.dirty_critical_watermark) {
        errors.push(format!(
            "scenario {scenario_id} dirty_critical_watermark must be in [0,1]"
        ));
    }
    if backpressure.dirty_high_watermark >= backpressure.dirty_critical_watermark {
        errors.push(format!(
            "scenario {scenario_id} dirty_high_watermark must be below dirty_critical_watermark"
        ));
    }
    if !(0.0..=1.0).contains(&backpressure.current_dirty_ratio) {
        errors.push(format!(
            "scenario {scenario_id} current_dirty_ratio must be in [0,1]"
        ));
    }
    require_non_empty(
        &format!("scenario {scenario_id} flush_policy"),
        &backpressure.flush_policy,
        errors,
    );
    if backpressure.flush_batch_size.eq(&0) {
        errors.push(format!(
            "scenario {scenario_id} flush_batch_size must be positive"
        ));
    }
}

fn validate_measurements(
    scenario_id: &str,
    measurements: &[CacheCandidateMeasurement],
    candidate_ids: &BTreeSet<String>,
    current_arc_id: Option<&str>,
    host_meets_target: bool,
    errors: &mut Vec<String>,
) {
    if measurements.is_empty() {
        errors.push(format!("scenario {scenario_id} requires measurements"));
        return;
    }

    let mut seen = BTreeSet::new();
    for measurement in measurements {
        if !candidate_ids.contains(&measurement.candidate_id) {
            errors.push(format!(
                "scenario {scenario_id} references unknown candidate {}",
                measurement.candidate_id
            ));
        }
        if !seen.insert(measurement.candidate_id.clone()) {
            errors.push(format!(
                "scenario {scenario_id} duplicates candidate measurement {}",
                measurement.candidate_id
            ));
        }
        validate_ratio(
            scenario_id,
            &measurement.candidate_id,
            "hit_rate",
            measurement.hit_rate,
            errors,
        );
        validate_ratio(
            scenario_id,
            &measurement.candidate_id,
            "dirty_ratio",
            measurement.dirty_ratio,
            errors,
        );
        if measurement.p99_latency_us <= 0.0 {
            errors.push(format!(
                "scenario {scenario_id} candidate {} p99_latency_us must be positive",
                measurement.candidate_id
            ));
        }
        if measurement.memory_overhead_gb < 0.0 {
            errors.push(format!(
                "scenario {scenario_id} candidate {} memory_overhead_gb must be non-negative",
                measurement.candidate_id
            ));
        }
        if measurement.eviction_pressure < 0.0 {
            errors.push(format!(
                "scenario {scenario_id} candidate {} eviction_pressure must be non-negative",
                measurement.candidate_id
            ));
        }
        if !host_meets_target && !measurement.release_claim_state.safe_for_small_host() {
            errors.push(format!(
                "scenario {scenario_id} candidate {} is below target but claims {}",
                measurement.candidate_id,
                measurement.release_claim_state.label()
            ));
        }
        if measurement.release_claim_state.requires_large_host() && !host_meets_target {
            errors.push(format!(
                "scenario {scenario_id} candidate {} authoritative claim lacks large-host evidence",
                measurement.candidate_id
            ));
        }
    }

    if let Some(current_arc_id) = current_arc_id
        && !seen.contains(current_arc_id)
    {
        errors.push(format!(
            "scenario {scenario_id} must include current ARC measurement {current_arc_id}"
        ));
    }
    if seen.len() < 2 {
        errors.push(format!(
            "scenario {scenario_id} must compare current ARC with at least one candidate"
        ));
    }
}

fn validate_ratio(
    scenario_id: &str,
    candidate_id: &str,
    field: &str,
    value: f64,
    errors: &mut Vec<String>,
) {
    if !(0.0..=1.0).contains(&value) {
        errors.push(format!(
            "scenario {scenario_id} candidate {candidate_id} {field} must be in [0,1]"
        ));
    }
}

fn build_row(
    contract: &SwarmCacheControllerContract,
    scenario: &SwarmCacheScenario,
    current_arc_id: Option<&str>,
    errors: &mut Vec<String>,
) -> Option<SwarmCacheValidationRow> {
    let best = scenario
        .measurements
        .iter()
        .min_by(|left, right| left.p99_latency_us.total_cmp(&right.p99_latency_us))?;
    let current_arc_id = current_arc_id?;
    let current_arc = scenario
        .measurements
        .iter()
        .find(|measurement| measurement.candidate_id.eq(current_arc_id));

    let Some(current_arc) = current_arc else {
        errors.push(format!(
            "scenario {} is missing current ARC row {}",
            scenario.scenario_id, current_arc_id
        ));
        return None;
    };

    Some(SwarmCacheValidationRow {
        scenario_id: scenario.scenario_id.clone(),
        workload_class: scenario.workload_class.label().to_owned(),
        host_meets_target: scenario.host.meets_target(&contract.target_host),
        release_claim_state: scenario.release_claim_state.label().to_owned(),
        lane: scenario.host.lane.label().to_owned(),
        candidate_ids: scenario
            .measurements
            .iter()
            .map(|measurement| measurement.candidate_id.clone())
            .collect(),
        best_p99_candidate_id: best.candidate_id.clone(),
        current_arc_p99_us: current_arc.p99_latency_us,
        best_p99_us: best.p99_latency_us,
        backpressure_state: scenario.backpressure.backpressure_state.label().to_owned(),
    })
}

fn count_claim_states(contract: &SwarmCacheControllerContract) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for scenario in &contract.scenarios {
        *counts
            .entry(scenario.release_claim_state.label().to_owned())
            .or_insert(0) += 1;
        for measurement in &scenario.measurements {
            *counts
                .entry(measurement.release_claim_state.label().to_owned())
                .or_insert(0) += 1;
        }
    }
    counts
}

fn validate_required_log_fields(required_log_fields: &[String], errors: &mut Vec<String>) {
    let actual = required_log_fields
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for required in REQUIRED_LOG_FIELDS {
        if !actual.contains(required) {
            errors.push(format!("required_log_fields missing {required}"));
        }
    }
}

fn require_non_empty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
}

fn validate_non_empty_paths(field: &str, paths: &[String], errors: &mut Vec<String>) {
    if paths.is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
    for path in paths {
        require_non_empty(field, path, errors);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario_mut(
        contract: &mut SwarmCacheControllerContract,
        index: usize,
    ) -> Result<&mut SwarmCacheScenario> {
        contract
            .scenarios
            .get_mut(index)
            .with_context(|| format!("contract includes scenario {index}"))
    }

    fn first_measurement_mut(
        scenario: &mut SwarmCacheScenario,
    ) -> Result<&mut CacheCandidateMeasurement> {
        scenario
            .measurements
            .first_mut()
            .context("scenario includes first measurement")
    }

    #[test]
    fn valid_contract_accepts_large_host_and_small_host_downgrade() {
        let report = validate_swarm_cache_controller_contract(&sample_contract());

        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.scenario_count, 2);
        assert_eq!(report.candidate_count, 3);
        assert_eq!(report.small_host_downgrade_count, 1);
        assert_eq!(report.authoritative_claim_count, 1);
    }

    #[test]
    fn checked_in_swarm_cache_controller_contract_validates() -> Result<()> {
        let contract = load_swarm_cache_controller_contract(Path::new(&workspace_path(
            DEFAULT_SWARM_CACHE_CONTROLLER_CONTRACT,
        )))?;
        let report = validate_swarm_cache_controller_contract(&contract);

        assert!(
            report.valid,
            "checked-in swarm cache controller contract should validate: {:?}",
            report.errors
        );
        assert_eq!(report.scenario_count, 2);
        assert_eq!(report.candidate_count, 3);
        assert_eq!(report.small_host_downgrade_count, 1);
        assert_eq!(report.authoritative_claim_count, 1);
        assert_eq!(report.errors, [] as [String; 0]);
        Ok(())
    }

    #[test]
    fn swarm_cache_controller_report_json_shape() -> Result<()> {
        let contract = load_swarm_cache_controller_contract(Path::new(&workspace_path(
            DEFAULT_SWARM_CACHE_CONTROLLER_CONTRACT,
        )))?;
        let report = validate_swarm_cache_controller_contract(&contract);
        let json = serde_json::to_string_pretty(&report)?;

        insta::assert_snapshot!("swarm_cache_controller_report_json_shape", json);
        let parsed: SwarmCacheValidationReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    /// The markdown renderer feeds proof-bundle and release-gate operator
    /// workflows. The checked-in fixture validation above pins semantics; this
    /// snapshot pins the title, metadata bullets, scenario table layout,
    /// boolean formatting, best-p99 candidate rendering, and omitted Errors
    /// section for the committed cache-controller contract.
    #[test]
    fn render_swarm_cache_controller_markdown_checked_in_contract_snapshot() -> Result<()> {
        let contract = load_swarm_cache_controller_contract(Path::new(&workspace_path(
            DEFAULT_SWARM_CACHE_CONTROLLER_CONTRACT,
        )))?;
        let report = validate_swarm_cache_controller_contract(&contract);
        let markdown = render_swarm_cache_controller_markdown(&report);

        insta::assert_snapshot!(
            "render_swarm_cache_controller_markdown_checked_in_contract",
            markdown
        );
        Ok(())
    }

    #[test]
    fn small_host_cannot_claim_authoritative_measurement() -> Result<()> {
        let mut contract = sample_contract();
        let scenario = scenario_mut(&mut contract, 1)?;
        scenario.release_claim_state = CacheReleaseClaimState::MeasuredAuthoritative;
        first_measurement_mut(scenario)?.release_claim_state =
            CacheReleaseClaimState::MeasuredAuthoritative;

        let report = validate_swarm_cache_controller_contract(&contract);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("below the 64-core/256GB target"))
        );
        Ok(())
    }

    #[test]
    fn missing_current_arc_candidate_fails() {
        let mut contract = sample_contract();
        contract
            .candidates
            .retain(|candidate| candidate.algorithm.ne(&CacheAdmissionAlgorithm::CurrentArc));

        let report = validate_swarm_cache_controller_contract(&contract);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("current_arc candidate"))
        );
    }

    #[test]
    fn dirty_watermarks_must_be_ordered() -> Result<()> {
        let mut contract = sample_contract();
        let scenario = scenario_mut(&mut contract, 0)?;
        scenario.backpressure.dirty_high_watermark = 0.95;
        scenario.backpressure.dirty_critical_watermark = 0.80;

        let report = validate_swarm_cache_controller_contract(&contract);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("dirty_high_watermark must be below"))
        );
        Ok(())
    }

    fn sample_contract() -> SwarmCacheControllerContract {
        SwarmCacheControllerContract {
            schema_version: SWARM_CACHE_CONTROLLER_SCHEMA_VERSION,
            contract_id: "swarm-cache-controller-test".to_owned(),
            generated_at: "2026-05-03T00:00:00Z".to_owned(),
            target_host: SwarmCacheTargetHost {
                min_cpu_cores_logical: 64,
                min_ram_total_gb: 256,
                min_ram_available_gb: 192,
            },
            fallback_candidate_id: "current_arc".to_owned(),
            candidates: vec![
                CacheAdmissionCandidate {
                    candidate_id: "current_arc".to_owned(),
                    algorithm: CacheAdmissionAlgorithm::CurrentArc,
                    description: "current ARC conservative fallback".to_owned(),
                    fallback_candidate_id: "current_arc".to_owned(),
                    expected_loss_rule: "baseline comparison only".to_owned(),
                },
                CacheAdmissionCandidate {
                    candidate_id: "s3_fifo_guarded".to_owned(),
                    algorithm: CacheAdmissionAlgorithm::S3Fifo,
                    description: "S3-FIFO candidate with dirty pressure guard".to_owned(),
                    fallback_candidate_id: "current_arc".to_owned(),
                    expected_loss_rule: "admit when p99 and dirty risk improve".to_owned(),
                },
                CacheAdmissionCandidate {
                    candidate_id: "segmented_pressure".to_owned(),
                    algorithm: CacheAdmissionAlgorithm::SegmentedAdmission,
                    description: "segmented admission candidate".to_owned(),
                    fallback_candidate_id: "current_arc".to_owned(),
                    expected_loss_rule: "admit when hit gain exceeds memory cost".to_owned(),
                },
            ],
            scenarios: vec![large_host_scenario(), small_host_scenario()],
            required_log_fields: REQUIRED_LOG_FIELDS
                .iter()
                .map(|field| (*field).to_owned())
                .collect(),
            release_gate_consumers: vec!["bd-p2j3e".to_owned(), "proof-bundle".to_owned()],
        }
    }

    fn large_host_scenario() -> SwarmCacheScenario {
        SwarmCacheScenario {
            scenario_id: "cache_pressure_256gb_authoritative".to_owned(),
            workload_class: SwarmCacheWorkloadClass::CachePressure,
            host: SwarmCacheHostObservation {
                host_fingerprint: "large-host-fixture".to_owned(),
                cpu_cores_logical: 96,
                numa_nodes: Some(2),
                ram_total_gb: 512.0,
                ram_available_gb: 420.0,
                storage_class: "nvme".to_owned(),
                lane: SwarmCacheLane::PermissionedLargeHost,
            },
            measurements: vec![
                measurement(
                    "current_arc",
                    0.82,
                    5400.0,
                    CacheAdmissionDecision::FallbackToCurrentArc,
                    CacheReleaseClaimState::MeasuredAuthoritative,
                ),
                measurement(
                    "s3_fifo_guarded",
                    0.88,
                    4100.0,
                    CacheAdmissionDecision::Admit,
                    CacheReleaseClaimState::MeasuredAuthoritative,
                ),
                measurement(
                    "segmented_pressure",
                    0.86,
                    4500.0,
                    CacheAdmissionDecision::Admit,
                    CacheReleaseClaimState::MeasuredAuthoritative,
                ),
            ],
            backpressure: backpressure(),
            release_claim_state: CacheReleaseClaimState::MeasuredAuthoritative,
            reproduction_command: "ffs-harness validate-swarm-cache-controller".to_owned(),
            raw_logs: vec!["artifacts/cache/large-host/run.log".to_owned()],
            artifact_paths: vec!["artifacts/cache/large-host/report.json".to_owned()],
        }
    }

    fn small_host_scenario() -> SwarmCacheScenario {
        SwarmCacheScenario {
            scenario_id: "cache_pressure_small_host_smoke".to_owned(),
            workload_class: SwarmCacheWorkloadClass::FixtureSmoke,
            host: SwarmCacheHostObservation {
                host_fingerprint: "small-host-fixture".to_owned(),
                cpu_cores_logical: 16,
                numa_nodes: Some(1),
                ram_total_gb: 64.0,
                ram_available_gb: 40.0,
                storage_class: "nvme".to_owned(),
                lane: SwarmCacheLane::DeveloperSmoke,
            },
            measurements: vec![
                measurement(
                    "current_arc",
                    0.74,
                    8000.0,
                    CacheAdmissionDecision::FallbackToCurrentArc,
                    CacheReleaseClaimState::SmallHostSmoke,
                ),
                measurement(
                    "s3_fifo_guarded",
                    0.79,
                    6900.0,
                    CacheAdmissionDecision::RejectUntilMeasured,
                    CacheReleaseClaimState::SmallHostSmoke,
                ),
            ],
            backpressure: backpressure(),
            release_claim_state: CacheReleaseClaimState::SmallHostSmoke,
            reproduction_command: "ffs-harness validate-swarm-cache-controller".to_owned(),
            raw_logs: vec!["artifacts/cache/small-host/run.log".to_owned()],
            artifact_paths: vec!["artifacts/cache/small-host/report.json".to_owned()],
        }
    }

    fn measurement(
        candidate_id: &str,
        hit_rate: f64,
        p99_latency_us: f64,
        admission_decision: CacheAdmissionDecision,
        release_claim_state: CacheReleaseClaimState,
    ) -> CacheCandidateMeasurement {
        CacheCandidateMeasurement {
            candidate_id: candidate_id.to_owned(),
            hit_rate,
            p99_latency_us,
            dirty_ratio: 0.42,
            memory_overhead_gb: 12.0,
            eviction_pressure: 0.21,
            admission_decision,
            release_claim_state,
        }
    }

    fn backpressure() -> CacheBackpressureObservation {
        CacheBackpressureObservation {
            dirty_high_watermark: 0.80,
            dirty_critical_watermark: 0.95,
            current_dirty_ratio: 0.42,
            flush_policy: "writeback_batch_with_dirty_pressure_guard".to_owned(),
            flush_batch_size: 256,
            backpressure_state: CacheBackpressureState::Healthy,
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
