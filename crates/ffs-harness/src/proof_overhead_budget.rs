#![allow(clippy::too_many_lines)]

//! Proof instrumentation overhead budget evaluator for `bd-rchk0.5.14`.
//!
//! The evaluator consumes a budget schema plus observed proof-workflow metrics
//! and emits a release-gate report. It keeps timing, memory, logs, artifacts,
//! repair symbols, upload size, and campaign duration visible without allowing
//! proof bundles to grow unbounded.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

pub const PROOF_OVERHEAD_BUDGET_SCHEMA_VERSION: u32 = 1;

const REQUIRED_LOG_FIELDS: [&str; 10] = [
    "scenario_id",
    "profile",
    "baseline_id",
    "observed_value",
    "budget_value",
    "unit",
    "threshold_decision",
    "artifact_sizes",
    "compression_retention_decision",
    "reproduction_command",
];

const RETENTION_VALIDATOR_PASS: &str = "pass";
const RETENTION_CLEANUP_CLEAN: &str = "clean";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetProfile {
    DeveloperSmoke,
    CiRequired,
    NightlyStress,
    PermissionedMount,
    ReleaseReadiness,
}

impl BudgetProfile {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DeveloperSmoke => "developer_smoke",
            Self::CiRequired => "ci_required",
            Self::NightlyStress => "nightly_stress",
            Self::PermissionedMount => "permissioned_mount",
            Self::ReleaseReadiness => "release_readiness",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetCategory {
    RuntimeOverhead,
    MemoryOverhead,
    ArtifactDiskUsage,
    LogVolume,
    RepairSymbolStorage,
    RchUploadSize,
    CampaignDuration,
    OperatorReportSize,
}

impl BudgetCategory {
    #[must_use]
    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::RuntimeOverhead => "runtime_overhead",
            Self::MemoryOverhead => "memory_overhead",
            Self::ArtifactDiskUsage => "artifact_disk_usage",
            Self::LogVolume => "log_volume",
            Self::RepairSymbolStorage => "repair_symbol_storage",
            Self::RchUploadSize => "rch_upload_size",
            Self::CampaignDuration => "campaign_duration",
            Self::OperatorReportSize => "operator_report_size",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetUnit {
    Percent,
    Bytes,
    Seconds,
    Count,
}

impl BudgetUnit {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Percent => "percent",
            Self::Bytes => "bytes",
            Self::Seconds => "seconds",
            Self::Count => "count",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDecision {
    Pass,
    Warn,
    Fail,
    Excepted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionCompressionSetting {
    Disabled,
    Allowed,
    Required,
}

impl RetentionCompressionSetting {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Allowed => "allowed",
            Self::Required => "required",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionRedactionPolicy {
    None,
    HostDetails,
    SecretsAndHostDetails,
}

impl RetentionRedactionPolicy {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HostDetails => "host_details",
            Self::SecretsAndHostDetails => "secrets_and_host_details",
        }
    }
}

impl BudgetDecision {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Excepted => "excepted",
        }
    }

    #[must_use]
    pub const fn blocks_release(self) -> bool {
        matches!(self, Self::Fail)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofOverheadBudgetConfig {
    pub schema_version: u32,
    pub profile: BudgetProfile,
    pub baseline_id: String,
    pub baseline_captured_at: String,
    pub max_baseline_age_days: u32,
    pub metrics: Vec<MetricBudget>,
    pub retention: ProofRetentionPolicy,
    #[serde(default)]
    pub required_log_fields: Vec<String>,
    #[serde(default)]
    pub release_gate_consumers: Vec<String>,
    #[serde(default)]
    pub exceptions: Vec<BudgetException>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricBudget {
    pub category: BudgetCategory,
    pub metric: String,
    pub unit: BudgetUnit,
    pub warn_at: f64,
    pub fail_at: f64,
    #[serde(default = "default_release_gate_required")]
    pub release_gate_required: bool,
    #[serde(default)]
    pub exception_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRetentionPolicy {
    pub max_total_artifact_bytes: u64,
    pub compress_above_bytes: u64,
    pub retention_count: u32,
    #[serde(default)]
    pub mandatory_artifact_classes: Vec<String>,
    #[serde(default)]
    pub artifact_class_policies: Vec<RetentionArtifactClassPolicy>,
    pub preserve_reproduction_command: bool,
    pub retention_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionArtifactClassPolicy {
    pub artifact_class: String,
    pub retention_days: u32,
    pub retention_count: u32,
    pub max_size_bytes: u64,
    pub compression: RetentionCompressionSetting,
    pub redaction_policy: RetentionRedactionPolicy,
    pub redaction_policy_version: String,
    pub mandatory_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetException {
    pub id: String,
    pub metric: String,
    pub reason: String,
    pub user_impact: String,
    pub expires_at: String,
    pub follow_up_bead: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedProofMetrics {
    pub scenario_id: String,
    pub profile: BudgetProfile,
    pub baseline_id: String,
    pub observed_at: String,
    pub metrics: Vec<ObservedMetric>,
    #[serde(default)]
    pub artifacts: Vec<ObservedArtifact>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedMetric {
    pub category: BudgetCategory,
    pub metric: String,
    pub value: f64,
    pub unit: BudgetUnit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedArtifact {
    pub path: String,
    pub class: String,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compressed_size_bytes: Option<u64>,
    #[serde(default)]
    pub mandatory: bool,
    pub redaction_policy_version: String,
    #[serde(default)]
    pub dropped_fields: Vec<String>,
    #[serde(default)]
    pub sampled_fields: Vec<String>,
    pub validator_result: String,
    pub cleanup_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofOverheadBudgetReport {
    pub schema_version: u32,
    pub scenario_id: String,
    pub profile: BudgetProfile,
    pub baseline_id: String,
    pub baseline_age_days: u32,
    pub baseline_stale: bool,
    pub release_gate_verdict: BudgetDecision,
    pub release_gate_consumers: Vec<String>,
    pub metric_results: Vec<MetricBudgetResult>,
    pub retention_result: RetentionBudgetResult,
    pub log_records: Vec<BudgetLogRecord>,
    pub required_log_fields: Vec<String>,
    pub human_summary: String,
    pub reproduction_command: String,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricBudgetResult {
    pub category: BudgetCategory,
    pub metric: String,
    pub observed_value: Option<f64>,
    pub warn_budget_value: f64,
    pub budget_value: f64,
    pub unit: BudgetUnit,
    pub threshold_decision: BudgetDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception_id: Option<String>,
    pub release_gate_required: bool,
    pub diagnostic: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionBudgetResult {
    pub total_artifact_bytes: u64,
    pub compressed_total_artifact_bytes: u64,
    pub max_total_artifact_bytes: u64,
    pub compress_above_bytes: u64,
    pub retention_count: u32,
    pub retention_days: u32,
    pub compression_retention_decision: BudgetDecision,
    pub action: String,
    pub missing_mandatory_artifact_classes: Vec<String>,
    pub reproduction_command_preserved: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetLogRecord {
    pub scenario_id: String,
    pub profile: BudgetProfile,
    pub baseline_id: String,
    pub metric: String,
    pub category: BudgetCategory,
    pub observed_value: Option<f64>,
    pub budget_value: f64,
    pub unit: BudgetUnit,
    pub threshold_decision: BudgetDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception_id: Option<String>,
    pub artifact_sizes: Vec<ArtifactSizeLog>,
    pub compression_retention_decision: BudgetDecision,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSizeLog {
    pub path: String,
    pub class: String,
    pub artifact_class: String,
    pub original_size_bytes: u64,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compressed_size_bytes: Option<u64>,
    pub retention_action: String,
    pub retention_decision: String,
    pub redaction_policy_version: String,
    pub dropped_fields: Vec<String>,
    pub sampled_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception_id: Option<String>,
    pub validator_result: String,
    pub cleanup_status: String,
}

fn default_release_gate_required() -> bool {
    true
}

pub fn load_proof_overhead_budget_config(path: &Path) -> Result<ProofOverheadBudgetConfig> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read budget config {}", path.display()))?;
    parse_proof_overhead_budget_config(&text)
        .with_context(|| format!("invalid budget config {}", path.display()))
}

pub fn load_observed_proof_metrics(path: &Path) -> Result<ObservedProofMetrics> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read observed metrics {}", path.display()))?;
    parse_observed_proof_metrics(&text)
        .with_context(|| format!("invalid observed metrics {}", path.display()))
}

pub fn parse_proof_overhead_budget_config(text: &str) -> Result<ProofOverheadBudgetConfig> {
    serde_json::from_str(text).context("failed to parse proof overhead budget schema")
}

pub fn parse_observed_proof_metrics(text: &str) -> Result<ObservedProofMetrics> {
    serde_json::from_str(text).context("failed to parse observed proof metrics")
}

#[must_use]
pub fn validate_proof_overhead_budget_config(config: &ProofOverheadBudgetConfig) -> Vec<String> {
    let mut errors = Vec::new();
    if config.schema_version != PROOF_OVERHEAD_BUDGET_SCHEMA_VERSION {
        errors.push(format!(
            "unsupported schema_version {} expected {}",
            config.schema_version, PROOF_OVERHEAD_BUDGET_SCHEMA_VERSION
        ));
    }
    if config.baseline_id.trim().is_empty() {
        errors.push("baseline_id is required".to_owned());
    }
    if parse_epoch_days(&config.baseline_captured_at).is_none() {
        errors.push(format!(
            "baseline_captured_at is invalid: {}",
            config.baseline_captured_at
        ));
    }
    if config.max_baseline_age_days == 0 {
        errors.push("max_baseline_age_days must be greater than zero".to_owned());
    }
    if config.metrics.is_empty() {
        errors.push("at least one metric budget is required".to_owned());
    }
    validate_metric_budgets(&config.metrics, &mut errors);
    validate_required_log_fields(&config.required_log_fields, &mut errors);
    validate_retention_policy(&config.retention, &mut errors);
    validate_exceptions(&config.exceptions, &mut errors);
    errors
}

#[must_use]
pub fn validate_observed_proof_metrics(
    config: &ProofOverheadBudgetConfig,
    observed: &ObservedProofMetrics,
) -> Vec<String> {
    let mut errors = Vec::new();
    if !is_valid_scenario_id(&observed.scenario_id) {
        errors.push(format!("invalid scenario_id {}", observed.scenario_id));
    }
    if observed.profile != config.profile {
        errors.push(format!(
            "profile mismatch observed={} budget={}",
            observed.profile.label(),
            config.profile.label()
        ));
    }
    if observed.baseline_id != config.baseline_id {
        errors.push(format!(
            "baseline_id mismatch observed={} budget={}",
            observed.baseline_id, config.baseline_id
        ));
    }
    if parse_epoch_days(&observed.observed_at).is_none() {
        errors.push(format!("observed_at is invalid: {}", observed.observed_at));
    }
    if let (Some(baseline_day), Some(observed_day)) = (
        parse_epoch_days(&config.baseline_captured_at),
        parse_epoch_days(&observed.observed_at),
    ) && baseline_day > observed_day
    {
        errors.push(format!(
            "baseline_captured_at {} is after observed_at {}",
            config.baseline_captured_at, observed.observed_at
        ));
    }
    if observed.reproduction_command.trim().is_empty() {
        errors.push("reproduction_command is required".to_owned());
    }
    validate_observed_metric_rows(observed, &mut errors);
    validate_observed_artifacts(config, observed, &mut errors);
    errors
}

#[must_use]
pub fn evaluate_proof_overhead_budget(
    config: &ProofOverheadBudgetConfig,
    observed: &ObservedProofMetrics,
) -> ProofOverheadBudgetReport {
    let mut errors = validate_proof_overhead_budget_config(config);
    errors.extend(validate_observed_proof_metrics(config, observed));

    let baseline_age_days = baseline_age_days(config, observed);
    let baseline_stale = baseline_age_days > config.max_baseline_age_days;
    if baseline_stale {
        errors.push(format!(
            "baseline {} is stale: age_days={} max_age_days={}",
            config.baseline_id, baseline_age_days, config.max_baseline_age_days
        ));
    }

    let retention_result = evaluate_retention_policy(&config.retention, observed);
    if retention_result
        .compression_retention_decision
        .blocks_release()
    {
        errors.push(format!(
            "retention policy failed: action={} total_artifact_bytes={} max_total_artifact_bytes={}",
            retention_result.action,
            retention_result.total_artifact_bytes,
            retention_result.max_total_artifact_bytes
        ));
    }

    let metric_results = evaluate_metric_budgets(config, observed);
    errors.extend(
        metric_results
            .iter()
            .filter(|result| result.threshold_decision.blocks_release())
            .map(|result| result.diagnostic.clone()),
    );

    let mut warnings = Vec::new();
    warnings.extend(
        metric_results
            .iter()
            .filter(|result| {
                matches!(
                    result.threshold_decision,
                    BudgetDecision::Warn | BudgetDecision::Excepted
                )
            })
            .map(|result| result.diagnostic.clone()),
    );
    if retention_result.compression_retention_decision == BudgetDecision::Warn {
        warnings.push(format!(
            "retention policy requires compression: total_artifact_bytes={} compressed_total_artifact_bytes={}",
            retention_result.total_artifact_bytes, retention_result.compressed_total_artifact_bytes
        ));
    }

    let release_gate_verdict = release_gate_verdict(&metric_results, &retention_result, &errors);
    let artifact_sizes = artifact_size_logs(observed, &retention_result);
    let log_records = build_log_records(
        observed,
        &metric_results,
        &retention_result,
        &artifact_sizes,
    );
    let required_log_fields = required_log_fields(config);
    let human_summary = human_summary(
        observed,
        release_gate_verdict,
        metric_results.len(),
        errors.len(),
        warnings.len(),
        &retention_result,
    );

    ProofOverheadBudgetReport {
        schema_version: PROOF_OVERHEAD_BUDGET_SCHEMA_VERSION,
        scenario_id: observed.scenario_id.clone(),
        profile: observed.profile,
        baseline_id: observed.baseline_id.clone(),
        baseline_age_days,
        baseline_stale,
        release_gate_verdict,
        release_gate_consumers: release_gate_consumers(config),
        metric_results,
        retention_result,
        log_records,
        required_log_fields,
        human_summary,
        reproduction_command: observed.reproduction_command.clone(),
        errors,
        warnings,
    }
}

pub fn fail_on_proof_overhead_budget_errors(report: &ProofOverheadBudgetReport) -> Result<()> {
    if report.release_gate_verdict.blocks_release() {
        bail!(
            "proof overhead budget failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(())
}

fn validate_metric_budgets(metrics: &[MetricBudget], errors: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    for metric in metrics {
        if metric.metric.trim().is_empty() {
            errors.push("metric budget name is required".to_owned());
        }
        if !metric.warn_at.is_finite() || !metric.fail_at.is_finite() {
            errors.push(format!(
                "metric {} thresholds must be finite",
                metric.metric
            ));
        } else if metric.warn_at > metric.fail_at {
            errors.push(format!(
                "metric {} has warn_at greater than fail_at",
                metric.metric
            ));
        }
        if !seen.insert(metric.metric.clone()) {
            errors.push(format!("duplicate metric budget {}", metric.metric));
        }
    }
}

fn validate_required_log_fields(fields: &[String], errors: &mut Vec<String>) {
    for required in REQUIRED_LOG_FIELDS {
        if !fields.iter().any(|field| field == required) {
            errors.push(format!("required_log_fields missing {required}"));
        }
    }
}

fn validate_retention_policy(policy: &ProofRetentionPolicy, errors: &mut Vec<String>) {
    if policy.max_total_artifact_bytes == 0 {
        errors.push("retention max_total_artifact_bytes must be greater than zero".to_owned());
    }
    if policy.compress_above_bytes == 0 {
        errors.push("retention compress_above_bytes must be greater than zero".to_owned());
    }
    if policy.retention_days == 0 {
        errors.push("retention_days must be greater than zero".to_owned());
    }
    if policy.retention_count == 0 {
        errors.push("retention_count must be greater than zero".to_owned());
    }
    if !policy.preserve_reproduction_command {
        errors.push("retention must preserve reproduction_command".to_owned());
    }
    if policy.artifact_class_policies.is_empty() {
        errors.push("retention artifact_class_policies must not be empty".to_owned());
    }
    validate_artifact_class_policies(policy, errors);
}

fn validate_artifact_class_policies(policy: &ProofRetentionPolicy, errors: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    for class_policy in &policy.artifact_class_policies {
        if class_policy.artifact_class.trim().is_empty() {
            errors.push("retention artifact class is required".to_owned());
        }
        if !seen.insert(class_policy.artifact_class.clone()) {
            errors.push(format!(
                "duplicate retention artifact class {}",
                class_policy.artifact_class
            ));
        }
        if class_policy.retention_days == 0 {
            errors.push(format!(
                "retention artifact class {} retention_days must be greater than zero",
                class_policy.artifact_class
            ));
        }
        if class_policy.retention_count == 0 {
            errors.push(format!(
                "retention artifact class {} retention_count must be greater than zero",
                class_policy.artifact_class
            ));
        }
        if class_policy.max_size_bytes == 0 {
            errors.push(format!(
                "retention artifact class {} max_size_bytes must be greater than zero",
                class_policy.artifact_class
            ));
        }
        if class_policy.redaction_policy_version.trim().is_empty() {
            errors.push(format!(
                "retention artifact class {} redaction_policy_version is required",
                class_policy.artifact_class
            ));
        }
        if class_policy.mandatory_fields.is_empty() {
            errors.push(format!(
                "retention artifact class {} mandatory_fields must not be empty",
                class_policy.artifact_class
            ));
        }
    }
    for mandatory_class in &policy.mandatory_artifact_classes {
        if !seen.contains(mandatory_class) {
            errors.push(format!(
                "mandatory artifact class {mandatory_class} has no retention class policy"
            ));
        }
    }
}

fn validate_exceptions(exceptions: &[BudgetException], errors: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    for exception in exceptions {
        if exception.id.trim().is_empty() {
            errors.push("exception id is required".to_owned());
        }
        if !seen.insert(exception.id.clone()) {
            errors.push(format!("duplicate exception {}", exception.id));
        }
        if exception.metric.trim().is_empty() {
            errors.push(format!("exception {} metric is required", exception.id));
        }
        if exception.reason.trim().is_empty() {
            errors.push(format!("exception {} reason is required", exception.id));
        }
        if exception.user_impact.trim().is_empty() {
            errors.push(format!(
                "exception {} user_impact is required",
                exception.id
            ));
        }
        if parse_epoch_days(&exception.expires_at).is_none() {
            errors.push(format!(
                "exception {} expires_at is invalid: {}",
                exception.id, exception.expires_at
            ));
        }
        if !exception.follow_up_bead.starts_with("bd-") {
            errors.push(format!(
                "exception {} follow_up_bead must name a bead",
                exception.id
            ));
        }
    }
}

fn validate_observed_metric_rows(observed: &ObservedProofMetrics, errors: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    for metric in &observed.metrics {
        if metric.metric.trim().is_empty() {
            errors.push("observed metric name is required".to_owned());
        }
        if !metric.value.is_finite() {
            errors.push(format!(
                "observed metric {} value must be finite",
                metric.metric
            ));
        }
        if !seen.insert(metric.metric.clone()) {
            errors.push(format!("duplicate observed metric {}", metric.metric));
        }
    }
}

fn validate_observed_artifacts(
    config: &ProofOverheadBudgetConfig,
    observed: &ObservedProofMetrics,
    errors: &mut Vec<String>,
) {
    let mut seen = BTreeSet::new();
    let class_policies: BTreeMap<&str, &RetentionArtifactClassPolicy> = config
        .retention
        .artifact_class_policies
        .iter()
        .map(|policy| (policy.artifact_class.as_str(), policy))
        .collect();
    for artifact in &observed.artifacts {
        if artifact.path.trim().is_empty() {
            errors.push("artifact path is required".to_owned());
        }
        if artifact.class.trim().is_empty() {
            errors.push(format!("artifact {} class is required", artifact.path));
        }
        if !seen.insert(artifact.path.clone()) {
            errors.push(format!("duplicate artifact {}", artifact.path));
        }
        let Some(policy) = class_policies.get(artifact.class.as_str()).copied() else {
            errors.push(format!(
                "artifact {} class {} has no retention policy",
                artifact.path, artifact.class
            ));
            continue;
        };
        if artifact.redaction_policy_version.trim().is_empty() {
            errors.push(format!(
                "artifact {} redaction_policy_version is required",
                artifact.path
            ));
        } else if artifact.redaction_policy_version != policy.redaction_policy_version {
            errors.push(format!(
                "artifact {} redaction policy mismatch observed={} expected={}",
                artifact.path, artifact.redaction_policy_version, policy.redaction_policy_version
            ));
        }
        if artifact.validator_result.trim().is_empty() {
            errors.push(format!(
                "artifact {} validator_result is required",
                artifact.path
            ));
        } else if !matches!(
            artifact.validator_result.as_str(),
            RETENTION_VALIDATOR_PASS | "warn" | "fail"
        ) {
            errors.push(format!(
                "artifact {} validator_result={} is not supported",
                artifact.path, artifact.validator_result
            ));
        } else if artifact.validator_result == "fail" {
            errors.push(format!(
                "artifact {} retention validator failed",
                artifact.path
            ));
        }
        if artifact.cleanup_status.trim().is_empty() {
            errors.push(format!(
                "artifact {} cleanup_status is required",
                artifact.path
            ));
        } else if !matches!(
            artifact.cleanup_status.as_str(),
            RETENTION_CLEANUP_CLEAN | "preserved_artifacts" | "failed" | "not_run"
        ) {
            errors.push(format!(
                "artifact {} cleanup_status={} is not supported",
                artifact.path, artifact.cleanup_status
            ));
        } else if matches!(artifact.cleanup_status.as_str(), "failed" | "not_run") {
            errors.push(format!(
                "artifact {} cleanup_status={} is not release-gate safe",
                artifact.path, artifact.cleanup_status
            ));
        }
        if artifact.size_bytes > policy.max_size_bytes
            && artifact
                .compressed_size_bytes
                .is_none_or(|compressed| compressed > policy.max_size_bytes)
        {
            errors.push(format!(
                "artifact {} exceeds class max_size_bytes {}",
                artifact.path, policy.max_size_bytes
            ));
        }
        if artifact
            .compressed_size_bytes
            .is_some_and(|compressed| compressed > artifact.size_bytes)
        {
            errors.push(format!(
                "artifact {} compressed_size_bytes exceeds original size",
                artifact.path
            ));
        }
        if policy.compression == RetentionCompressionSetting::Required
            && artifact.compressed_size_bytes.is_none()
        {
            errors.push(format!(
                "artifact {} requires compression but compressed_size_bytes is missing",
                artifact.path
            ));
        }
        if policy.compression == RetentionCompressionSetting::Disabled
            && artifact.compressed_size_bytes.is_some()
        {
            errors.push(format!(
                "artifact {} records compression but class policy disables compression",
                artifact.path
            ));
        }
        for mandatory_field in &policy.mandatory_fields {
            if artifact
                .dropped_fields
                .iter()
                .any(|field| field == mandatory_field)
            {
                errors.push(format!(
                    "artifact {} dropped mandatory field {}",
                    artifact.path, mandatory_field
                ));
            }
        }
    }
}

fn evaluate_metric_budgets(
    config: &ProofOverheadBudgetConfig,
    observed: &ObservedProofMetrics,
) -> Vec<MetricBudgetResult> {
    let observed_by_metric: BTreeMap<&str, &ObservedMetric> = observed
        .metrics
        .iter()
        .map(|metric| (metric.metric.as_str(), metric))
        .collect();
    let exceptions_by_id: BTreeMap<&str, &BudgetException> = config
        .exceptions
        .iter()
        .map(|exception| (exception.id.as_str(), exception))
        .collect();

    config
        .metrics
        .iter()
        .map(|budget| {
            evaluate_metric_budget(
                budget,
                observed_by_metric.get(budget.metric.as_str()).copied(),
                &exceptions_by_id,
                observed.observed_at.as_str(),
            )
        })
        .collect()
}

fn evaluate_metric_budget(
    budget: &MetricBudget,
    observed: Option<&ObservedMetric>,
    exceptions_by_id: &BTreeMap<&str, &BudgetException>,
    observed_at: &str,
) -> MetricBudgetResult {
    let Some(observed) = observed else {
        return MetricBudgetResult {
            category: budget.category,
            metric: budget.metric.clone(),
            observed_value: None,
            warn_budget_value: budget.warn_at,
            budget_value: budget.fail_at,
            unit: budget.unit,
            threshold_decision: BudgetDecision::Fail,
            exception_id: None,
            release_gate_required: budget.release_gate_required,
            diagnostic: format!("missing observed metric {}", budget.metric),
        };
    };

    if observed.unit != budget.unit || observed.category != budget.category {
        return MetricBudgetResult {
            category: budget.category,
            metric: budget.metric.clone(),
            observed_value: Some(observed.value),
            warn_budget_value: budget.warn_at,
            budget_value: budget.fail_at,
            unit: budget.unit,
            threshold_decision: BudgetDecision::Fail,
            exception_id: None,
            release_gate_required: budget.release_gate_required,
            diagnostic: format!(
                "metric {} shape mismatch observed_category={} observed_unit={}",
                budget.metric,
                observed.category.metric_label(),
                observed.unit.label()
            ),
        };
    }

    let initial_decision = threshold_decision(observed.value, budget.warn_at, budget.fail_at);
    if matches!(initial_decision, BudgetDecision::Pass) {
        return metric_result_without_exception(budget, observed, initial_decision);
    }

    if let Some(exception) = find_valid_exception(budget, exceptions_by_id, observed_at) {
        return MetricBudgetResult {
            category: budget.category,
            metric: budget.metric.clone(),
            observed_value: Some(observed.value),
            warn_budget_value: budget.warn_at,
            budget_value: budget.fail_at,
            unit: budget.unit,
            threshold_decision: BudgetDecision::Excepted,
            exception_id: Some(exception.id.clone()),
            release_gate_required: budget.release_gate_required,
            diagnostic: format!(
                "metric {} exceeded budget but is covered by exception {} until {}",
                budget.metric, exception.id, exception.expires_at
            ),
        };
    }

    metric_result_without_exception(budget, observed, initial_decision)
}

fn metric_result_without_exception(
    budget: &MetricBudget,
    observed: &ObservedMetric,
    decision: BudgetDecision,
) -> MetricBudgetResult {
    MetricBudgetResult {
        category: budget.category,
        metric: budget.metric.clone(),
        observed_value: Some(observed.value),
        warn_budget_value: budget.warn_at,
        budget_value: budget.fail_at,
        unit: budget.unit,
        threshold_decision: decision,
        exception_id: None,
        release_gate_required: budget.release_gate_required,
        diagnostic: format!(
            "metric {} observed={} {} warn_at={} fail_at={} decision={}",
            budget.metric,
            observed.value,
            budget.unit.label(),
            budget.warn_at,
            budget.fail_at,
            decision.label()
        ),
    }
}

fn threshold_decision(observed_value: f64, warn_at: f64, fail_at: f64) -> BudgetDecision {
    if observed_value > fail_at {
        BudgetDecision::Fail
    } else if observed_value > warn_at {
        BudgetDecision::Warn
    } else {
        BudgetDecision::Pass
    }
}

fn find_valid_exception<'a>(
    budget: &MetricBudget,
    exceptions_by_id: &'a BTreeMap<&str, &BudgetException>,
    observed_at: &str,
) -> Option<&'a BudgetException> {
    budget
        .exception_ids
        .iter()
        .filter_map(|id| exceptions_by_id.get(id.as_str()).copied())
        .find(|exception| {
            exception.metric == budget.metric
                && parse_epoch_days(&exception.expires_at)
                    .zip(parse_epoch_days(observed_at))
                    .is_some_and(|(expiry, observed_day)| expiry >= observed_day)
                && !exception.reason.trim().is_empty()
                && !exception.user_impact.trim().is_empty()
                && exception.follow_up_bead.starts_with("bd-")
        })
}

fn evaluate_retention_policy(
    policy: &ProofRetentionPolicy,
    observed: &ObservedProofMetrics,
) -> RetentionBudgetResult {
    let total_artifact_bytes = observed
        .artifacts
        .iter()
        .map(|artifact| artifact.size_bytes)
        .sum();
    let compressed_total_artifact_bytes = observed
        .artifacts
        .iter()
        .map(|artifact| {
            artifact
                .compressed_size_bytes
                .unwrap_or(artifact.size_bytes)
        })
        .sum();
    let present_classes: BTreeSet<&str> = observed
        .artifacts
        .iter()
        .map(|artifact| artifact.class.as_str())
        .collect();
    let missing_mandatory_artifact_classes = policy
        .mandatory_artifact_classes
        .iter()
        .filter(|class| !present_classes.contains(class.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let reproduction_command_preserved =
        !policy.preserve_reproduction_command || !observed.reproduction_command.trim().is_empty();
    let compression_needed = observed
        .artifacts
        .iter()
        .any(|artifact| artifact.size_bytes > policy.compress_above_bytes);

    let (compression_retention_decision, action) =
        if !missing_mandatory_artifact_classes.is_empty() || !reproduction_command_preserved {
            (BudgetDecision::Fail, "reject_missing_required_evidence")
        } else if total_artifact_bytes > policy.max_total_artifact_bytes
            && compressed_total_artifact_bytes > policy.max_total_artifact_bytes
        {
            (BudgetDecision::Fail, "reject_over_budget_artifacts")
        } else if compression_needed || total_artifact_bytes > policy.max_total_artifact_bytes {
            (BudgetDecision::Warn, "compress_and_retain")
        } else {
            (BudgetDecision::Pass, "retain")
        };

    RetentionBudgetResult {
        total_artifact_bytes,
        compressed_total_artifact_bytes,
        max_total_artifact_bytes: policy.max_total_artifact_bytes,
        compress_above_bytes: policy.compress_above_bytes,
        retention_count: policy.retention_count,
        retention_days: policy.retention_days,
        compression_retention_decision,
        action: action.to_owned(),
        missing_mandatory_artifact_classes,
        reproduction_command_preserved,
    }
}

fn artifact_size_logs(
    observed: &ObservedProofMetrics,
    retention: &RetentionBudgetResult,
) -> Vec<ArtifactSizeLog> {
    observed
        .artifacts
        .iter()
        .map(|artifact| {
            let artifact_needs_compression = artifact.size_bytes > retention.compress_above_bytes;
            let run_exceeds_limit =
                retention.total_artifact_bytes > retention.max_total_artifact_bytes;
            let retention_action = if artifact_needs_compression || run_exceeds_limit {
                "compress"
            } else {
                "retain"
            };
            ArtifactSizeLog {
                path: artifact.path.clone(),
                class: artifact.class.clone(),
                artifact_class: artifact.class.clone(),
                original_size_bytes: artifact.size_bytes,
                size_bytes: artifact.size_bytes,
                compressed_size_bytes: artifact.compressed_size_bytes,
                retention_action: retention_action.to_owned(),
                retention_decision: retention_action.to_owned(),
                redaction_policy_version: artifact.redaction_policy_version.clone(),
                dropped_fields: artifact.dropped_fields.clone(),
                sampled_fields: artifact.sampled_fields.clone(),
                exception_id: artifact.exception_id.clone(),
                validator_result: artifact.validator_result.clone(),
                cleanup_status: artifact.cleanup_status.clone(),
            }
        })
        .collect()
}

fn build_log_records(
    observed: &ObservedProofMetrics,
    metric_results: &[MetricBudgetResult],
    retention: &RetentionBudgetResult,
    artifact_sizes: &[ArtifactSizeLog],
) -> Vec<BudgetLogRecord> {
    metric_results
        .iter()
        .map(|result| BudgetLogRecord {
            scenario_id: observed.scenario_id.clone(),
            profile: observed.profile,
            baseline_id: observed.baseline_id.clone(),
            metric: result.metric.clone(),
            category: result.category,
            observed_value: result.observed_value,
            budget_value: result.budget_value,
            unit: result.unit,
            threshold_decision: result.threshold_decision,
            exception_id: result.exception_id.clone(),
            artifact_sizes: artifact_sizes.to_vec(),
            compression_retention_decision: retention.compression_retention_decision,
            reproduction_command: observed.reproduction_command.clone(),
        })
        .collect()
}

fn release_gate_verdict(
    metric_results: &[MetricBudgetResult],
    retention: &RetentionBudgetResult,
    errors: &[String],
) -> BudgetDecision {
    if !errors.is_empty()
        || retention.compression_retention_decision.blocks_release()
        || metric_results
            .iter()
            .any(|result| result.threshold_decision.blocks_release())
    {
        BudgetDecision::Fail
    } else if retention.compression_retention_decision == BudgetDecision::Warn
        || metric_results.iter().any(|result| {
            matches!(
                result.threshold_decision,
                BudgetDecision::Warn | BudgetDecision::Excepted
            )
        })
    {
        BudgetDecision::Warn
    } else {
        BudgetDecision::Pass
    }
}

fn release_gate_consumers(config: &ProofOverheadBudgetConfig) -> Vec<String> {
    if config.release_gate_consumers.is_empty() {
        vec!["release-gates".to_owned()]
    } else {
        config.release_gate_consumers.clone()
    }
}

fn required_log_fields(config: &ProofOverheadBudgetConfig) -> Vec<String> {
    if config.required_log_fields.is_empty() {
        REQUIRED_LOG_FIELDS
            .iter()
            .map(ToString::to_string)
            .collect()
    } else {
        config.required_log_fields.clone()
    }
}

fn human_summary(
    observed: &ObservedProofMetrics,
    verdict: BudgetDecision,
    metric_count: usize,
    error_count: usize,
    warning_count: usize,
    retention: &RetentionBudgetResult,
) -> String {
    format!(
        "scenario={} profile={} baseline={} verdict={} metrics={} errors={} warnings={} artifacts={} retention_action={} reproduction_command={}",
        observed.scenario_id,
        observed.profile.label(),
        observed.baseline_id,
        verdict.label(),
        metric_count,
        error_count,
        warning_count,
        retention.total_artifact_bytes,
        retention.action,
        observed.reproduction_command
    )
}

fn baseline_age_days(config: &ProofOverheadBudgetConfig, observed: &ObservedProofMetrics) -> u32 {
    parse_epoch_days(&config.baseline_captured_at)
        .zip(parse_epoch_days(&observed.observed_at))
        .map_or(0, |(baseline_day, observed_day)| {
            observed_day.saturating_sub(baseline_day)
        })
}

fn is_valid_scenario_id(value: &str) -> bool {
    let mut parts = value.split('_');
    let Some(first) = parts.next() else {
        return false;
    };
    let mut part_count = 1_usize;
    if !is_valid_scenario_part(first, true) {
        return false;
    }
    for part in parts {
        part_count = part_count.saturating_add(1);
        if !is_valid_scenario_part(part, false) {
            return false;
        }
    }
    part_count >= 3
}

fn is_valid_scenario_part(part: &str, first_part: bool) -> bool {
    if part.is_empty() {
        return false;
    }
    let mut chars = part.chars();
    if first_part {
        let Some(first) = chars.next() else {
            return false;
        };
        if !first.is_ascii_lowercase() {
            return false;
        }
    }
    part.chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
}

fn parse_epoch_days(timestamp: &str) -> Option<u32> {
    let bytes = timestamp.as_bytes();
    if bytes.len() < 10 || bytes.get(4).copied()? != b'-' || bytes.get(7).copied()? != b'-' {
        return None;
    }
    let year = parse_fixed_digits(bytes, 0, 4)?;
    let month = parse_fixed_digits(bytes, 5, 2)?;
    let day = parse_fixed_digits(bytes, 8, 2)?;
    epoch_days_from_date(year, month, day)
}

fn parse_fixed_digits(bytes: &[u8], start: usize, count: usize) -> Option<u32> {
    let end = start.checked_add(count)?;
    let digits = bytes.get(start..end)?;
    let mut value = 0_u32;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    Some(value)
}

fn epoch_days_from_date(year: u32, month: u32, day: u32) -> Option<u32> {
    if year == 0 || !(1..=12).contains(&month) {
        return None;
    }
    let days_in_month = days_in_month(year, month)?;
    if day == 0 || day > days_in_month {
        return None;
    }
    let years_before = year.checked_sub(1)?;
    let leap_days_before_year = years_before / 4 - years_before / 100 + years_before / 400;
    let common_days_before_year = years_before.checked_mul(365)?;
    let days_before_year = common_days_before_year.checked_add(leap_days_before_year)?;
    days_before_year.checked_add(day_of_year(year, month, day)? - 1)
}

fn day_of_year(year: u32, month: u32, day: u32) -> Option<u32> {
    const DAYS_BEFORE_MONTH_COMMON: [u32; 12] =
        [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let month_index = usize::try_from(month.checked_sub(1)?).ok()?;
    let mut ordinal = *DAYS_BEFORE_MONTH_COMMON.get(month_index)?;
    if month > 2 && is_leap_year(year) {
        ordinal = ordinal.checked_add(1)?;
    }
    ordinal.checked_add(day)
}

fn days_in_month(year: u32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if is_leap_year(year) => Some(29),
        2 => Some(28),
        _ => None,
    }
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget_config() -> ProofOverheadBudgetConfig {
        ProofOverheadBudgetConfig {
            schema_version: PROOF_OVERHEAD_BUDGET_SCHEMA_VERSION,
            profile: BudgetProfile::DeveloperSmoke,
            baseline_id: "budget-baseline-2026-05-01".to_owned(),
            baseline_captured_at: "2026-05-01T00:00:00Z".to_owned(),
            max_baseline_age_days: 14,
            metrics: vec![
                metric_budget(
                    BudgetCategory::RuntimeOverhead,
                    "runtime_overhead_percent",
                    BudgetUnit::Percent,
                    8.0,
                    12.0,
                ),
                metric_budget(
                    BudgetCategory::MemoryOverhead,
                    "memory_overhead_percent",
                    BudgetUnit::Percent,
                    10.0,
                    20.0,
                ),
                metric_budget(
                    BudgetCategory::LogVolume,
                    "log_bytes",
                    BudgetUnit::Bytes,
                    4_096.0,
                    8_192.0,
                ),
            ],
            retention: ProofRetentionPolicy {
                max_total_artifact_bytes: 8_192,
                compress_above_bytes: 3_000,
                retention_count: 20,
                mandatory_artifact_classes: vec![
                    "proof_bundle".to_owned(),
                    "reproduction_pack".to_owned(),
                ],
                artifact_class_policies: vec![
                    retention_class_policy(
                        "proof_bundle",
                        RetentionCompressionSetting::Allowed,
                        RetentionRedactionPolicy::HostDetails,
                        &[
                            "scenario_id",
                            "workflow",
                            "duration_seconds",
                            "reproduction_command",
                        ],
                    ),
                    retention_class_policy(
                        "reproduction_pack",
                        RetentionCompressionSetting::Allowed,
                        RetentionRedactionPolicy::HostDetails,
                        &["scenario_id", "reproduction_command", "inputs"],
                    ),
                    retention_class_policy(
                        "raw_log",
                        RetentionCompressionSetting::Allowed,
                        RetentionRedactionPolicy::SecretsAndHostDetails,
                        &["stderr_tail", "reproduction_command"],
                    ),
                ],
                preserve_reproduction_command: true,
                retention_days: 30,
            },
            required_log_fields: REQUIRED_LOG_FIELDS
                .iter()
                .map(ToString::to_string)
                .collect(),
            release_gate_consumers: vec!["release-gates".to_owned(), "ci-required".to_owned()],
            exceptions: Vec::new(),
        }
    }

    fn metric_budget(
        category: BudgetCategory,
        metric: &str,
        unit: BudgetUnit,
        warn_at: f64,
        fail_at: f64,
    ) -> MetricBudget {
        MetricBudget {
            category,
            metric: metric.to_owned(),
            unit,
            warn_at,
            fail_at,
            release_gate_required: true,
            exception_ids: Vec::new(),
        }
    }

    fn retention_class_policy(
        artifact_class: &str,
        compression: RetentionCompressionSetting,
        redaction_policy: RetentionRedactionPolicy,
        mandatory_fields: &[&str],
    ) -> RetentionArtifactClassPolicy {
        RetentionArtifactClassPolicy {
            artifact_class: artifact_class.to_owned(),
            retention_days: 30,
            retention_count: 20,
            max_size_bytes: 8_192,
            compression,
            redaction_policy,
            redaction_policy_version: "redact-v1".to_owned(),
            mandatory_fields: mandatory_fields.iter().map(ToString::to_string).collect(),
        }
    }

    fn observed_metrics() -> ObservedProofMetrics {
        ObservedProofMetrics {
            scenario_id: "proof_budget_developer_smoke".to_owned(),
            profile: BudgetProfile::DeveloperSmoke,
            baseline_id: "budget-baseline-2026-05-01".to_owned(),
            observed_at: "2026-05-03T00:00:00Z".to_owned(),
            metrics: vec![
                observed_metric(
                    BudgetCategory::RuntimeOverhead,
                    "runtime_overhead_percent",
                    4.0,
                    BudgetUnit::Percent,
                ),
                observed_metric(
                    BudgetCategory::MemoryOverhead,
                    "memory_overhead_percent",
                    7.0,
                    BudgetUnit::Percent,
                ),
                observed_metric(BudgetCategory::LogVolume, "log_bytes", 2_048.0, BudgetUnit::Bytes),
            ],
            artifacts: vec![
                observed_artifact("artifacts/proof/bundle.json", "proof_bundle", 2_000, None),
                observed_artifact(
                    "artifacts/proof/repro.json",
                    "reproduction_pack",
                    900,
                    None,
                ),
            ],
            reproduction_command: "ffs-harness validate-proof-overhead-budget --budget budget.json --metrics metrics.json".to_owned(),
        }
    }

    fn observed_metric(
        category: BudgetCategory,
        metric: &str,
        value: f64,
        unit: BudgetUnit,
    ) -> ObservedMetric {
        ObservedMetric {
            category,
            metric: metric.to_owned(),
            value,
            unit,
        }
    }

    fn observed_artifact(
        path: &str,
        class: &str,
        size_bytes: u64,
        compressed_size_bytes: Option<u64>,
    ) -> ObservedArtifact {
        ObservedArtifact {
            path: path.to_owned(),
            class: class.to_owned(),
            size_bytes,
            compressed_size_bytes,
            mandatory: true,
            redaction_policy_version: "redact-v1".to_owned(),
            dropped_fields: Vec::new(),
            sampled_fields: Vec::new(),
            validator_result: RETENTION_VALIDATOR_PASS.to_owned(),
            cleanup_status: RETENTION_CLEANUP_CLEAN.to_owned(),
            exception_id: None,
        }
    }

    fn first_retention_policy_mut(
        config: &mut ProofOverheadBudgetConfig,
    ) -> Result<&mut RetentionArtifactClassPolicy> {
        config
            .retention
            .artifact_class_policies
            .first_mut()
            .context("missing retention artifact class policy")
    }

    fn first_observed_artifact_mut(
        observed: &mut ObservedProofMetrics,
    ) -> Result<&mut ObservedArtifact> {
        observed
            .artifacts
            .first_mut()
            .context("missing first observed artifact")
    }

    fn first_two_observed_artifacts_mut(
        observed: &mut ObservedProofMetrics,
    ) -> Result<(&mut ObservedArtifact, &mut ObservedArtifact)> {
        let (first, rest) = observed
            .artifacts
            .split_first_mut()
            .context("missing first observed artifact")?;
        let second = rest
            .first_mut()
            .context("missing second observed artifact")?;
        Ok((first, second))
    }

    fn decision_for(report: &ProofOverheadBudgetReport, metric: &str) -> BudgetDecision {
        report
            .metric_results
            .iter()
            .find(|result| result.metric == metric)
            .map_or(BudgetDecision::Fail, |result| result.threshold_decision)
    }

    #[test]
    fn proof_overhead_budget_report_json_shape() -> Result<()> {
        let report = evaluate_proof_overhead_budget(&budget_config(), &observed_metrics());
        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("proof_overhead_budget_report_json_shape", json);
        let parsed: ProofOverheadBudgetReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn parses_budget_schema_and_observed_metrics_json() -> Result<()> {
        let budget_json = serde_json::to_string(&budget_config())?;
        let metrics_json = serde_json::to_string(&observed_metrics())?;
        let parsed_budget = parse_proof_overhead_budget_config(&budget_json)?;
        let parsed_metrics = parse_observed_proof_metrics(&metrics_json)?;

        assert!(
            validate_proof_overhead_budget_config(&parsed_budget).is_empty(),
            "budget schema should validate"
        );
        assert!(
            validate_observed_proof_metrics(&parsed_budget, &parsed_metrics).is_empty(),
            "observed metrics should validate"
        );
        assert_eq!(parsed_budget.profile, BudgetProfile::DeveloperSmoke);
        assert_eq!(parsed_metrics.metrics.len(), 3);
        Ok(())
    }

    #[test]
    fn classifies_pass_warn_and_fail_thresholds() {
        let config = budget_config();
        let mut observed = observed_metrics();
        observed.metrics = vec![
            observed_metric(
                BudgetCategory::RuntimeOverhead,
                "runtime_overhead_percent",
                4.0,
                BudgetUnit::Percent,
            ),
            observed_metric(
                BudgetCategory::MemoryOverhead,
                "memory_overhead_percent",
                15.0,
                BudgetUnit::Percent,
            ),
            observed_metric(
                BudgetCategory::LogVolume,
                "log_bytes",
                9_000.0,
                BudgetUnit::Bytes,
            ),
        ];

        let report = evaluate_proof_overhead_budget(&config, &observed);

        assert_eq!(
            decision_for(&report, "runtime_overhead_percent"),
            BudgetDecision::Pass
        );
        assert_eq!(
            decision_for(&report, "memory_overhead_percent"),
            BudgetDecision::Warn
        );
        assert_eq!(decision_for(&report, "log_bytes"), BudgetDecision::Fail);
        assert_eq!(report.release_gate_verdict, BudgetDecision::Fail);
    }

    #[test]
    fn missing_metric_fails_release_gate() {
        let config = budget_config();
        let mut observed = observed_metrics();
        observed
            .metrics
            .retain(|metric| metric.metric != "log_bytes");

        let report = evaluate_proof_overhead_budget(&config, &observed);

        assert_eq!(decision_for(&report, "log_bytes"), BudgetDecision::Fail);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("missing observed metric log_bytes"))
        );
    }

    #[test]
    fn stale_baseline_fails_release_gate() {
        let mut config = budget_config();
        config.baseline_captured_at = "2026-01-01T00:00:00Z".to_owned();
        config.max_baseline_age_days = 7;

        let report = evaluate_proof_overhead_budget(&config, &observed_metrics());

        assert!(report.baseline_stale);
        assert_eq!(report.release_gate_verdict, BudgetDecision::Fail);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("baseline budget-baseline-2026-05-01 is stale"))
        );
    }

    #[test]
    fn future_baseline_capture_is_rejected() {
        let mut config = budget_config();
        config.baseline_captured_at = "2026-05-04T00:00:00Z".to_owned();
        let report = evaluate_proof_overhead_budget(&config, &observed_metrics());

        assert_eq!(report.baseline_age_days, 0);
        assert_eq!(report.release_gate_verdict, BudgetDecision::Fail);
        assert!(report.errors.iter().any(|error| {
            error.contains(
                "baseline_captured_at 2026-05-04T00:00:00Z is after observed_at 2026-05-03T00:00:00Z",
            )
        }));
    }

    #[test]
    fn exception_can_cover_over_budget_metric_until_expiry() {
        let mut config = budget_config();
        let exception = BudgetException {
            id: "budget-exception-1".to_owned(),
            metric: "log_bytes".to_owned(),
            reason: "CI log contract rollout".to_owned(),
            user_impact: "developer smoke remains bounded".to_owned(),
            expires_at: "2026-05-10T00:00:00Z".to_owned(),
            follow_up_bead: "bd-0rfm5".to_owned(),
        };
        config
            .metrics
            .iter_mut()
            .filter(|metric| metric.metric == "log_bytes")
            .for_each(|metric| metric.exception_ids.push(exception.id.clone()));
        config.exceptions.push(exception);
        let mut observed = observed_metrics();
        observed
            .metrics
            .iter_mut()
            .filter(|metric| metric.metric == "log_bytes")
            .for_each(|metric| metric.value = 9_000.0);

        let report = evaluate_proof_overhead_budget(&config, &observed);

        assert_eq!(decision_for(&report, "log_bytes"), BudgetDecision::Excepted);
        assert_eq!(report.release_gate_verdict, BudgetDecision::Warn);
        assert!(report.errors.is_empty());
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("budget-exception-1"))
        );
    }

    #[test]
    fn expired_exception_does_not_hide_failure() {
        let mut config = budget_config();
        let exception = BudgetException {
            id: "expired-budget-exception".to_owned(),
            metric: "log_bytes".to_owned(),
            reason: "expired rollout".to_owned(),
            user_impact: "log volume may slow CI".to_owned(),
            expires_at: "2026-05-02T00:00:00Z".to_owned(),
            follow_up_bead: "bd-0rfm5".to_owned(),
        };
        config
            .metrics
            .iter_mut()
            .filter(|metric| metric.metric == "log_bytes")
            .for_each(|metric| metric.exception_ids.push(exception.id.clone()));
        config.exceptions.push(exception);
        let mut observed = observed_metrics();
        observed
            .metrics
            .iter_mut()
            .filter(|metric| metric.metric == "log_bytes")
            .for_each(|metric| metric.value = 9_000.0);

        let report = evaluate_proof_overhead_budget(&config, &observed);

        assert_eq!(decision_for(&report, "log_bytes"), BudgetDecision::Fail);
        assert_eq!(report.release_gate_verdict, BudgetDecision::Fail);
    }

    #[test]
    fn retention_policy_warns_for_compression_and_fails_missing_mandatory_artifact() {
        let mut observed = observed_metrics();
        observed.artifacts = vec![
            observed_artifact(
                "artifacts/proof/bundle.json",
                "proof_bundle",
                6_000,
                Some(2_000),
            ),
            observed_artifact(
                "artifacts/proof/repro.json",
                "reproduction_pack",
                1_000,
                Some(800),
            ),
        ];
        let compressed_report = evaluate_proof_overhead_budget(&budget_config(), &observed);

        assert_eq!(
            compressed_report
                .retention_result
                .compression_retention_decision,
            BudgetDecision::Warn
        );
        assert_eq!(compressed_report.release_gate_verdict, BudgetDecision::Warn);

        observed
            .artifacts
            .retain(|artifact| artifact.class != "reproduction_pack");
        let missing_report = evaluate_proof_overhead_budget(&budget_config(), &observed);
        assert_eq!(
            missing_report
                .retention_result
                .compression_retention_decision,
            BudgetDecision::Fail
        );
        assert_eq!(missing_report.release_gate_verdict, BudgetDecision::Fail);
    }

    #[test]
    fn retention_policy_schema_rejects_missing_class_controls() -> Result<()> {
        let mut config = budget_config();
        config.retention.retention_count = 0;
        let policy = first_retention_policy_mut(&mut config)?;
        policy.retention_days = 0;
        policy.retention_count = 0;
        policy.max_size_bytes = 0;
        policy.redaction_policy_version.clear();
        policy.mandatory_fields.clear();

        let errors = validate_proof_overhead_budget_config(&config);

        assert!(
            errors
                .iter()
                .any(|error| error == "retention_count must be greater than zero")
        );
        assert!(errors.iter().any(|error| {
            error.contains("proof_bundle retention_days must be greater than zero")
        }));
        assert!(errors.iter().any(|error| {
            error.contains("proof_bundle retention_count must be greater than zero")
        }));
        assert!(errors.iter().any(|error| {
            error.contains("proof_bundle max_size_bytes must be greater than zero")
        }));
        assert!(
            errors.iter().any(|error| {
                error.contains("proof_bundle redaction_policy_version is required")
            })
        );
        assert!(
            errors
                .iter()
                .any(|error| { error.contains("proof_bundle mandatory_fields must not be empty") })
        );
        Ok(())
    }

    #[test]
    fn observed_artifact_validation_rejects_compression_corruption() -> Result<()> {
        let config = budget_config();
        let mut observed = observed_metrics();
        let artifact = first_observed_artifact_mut(&mut observed)?;
        artifact.compressed_size_bytes = Some(artifact.size_bytes + 1);

        let report = evaluate_proof_overhead_budget(&config, &observed);

        assert_eq!(report.release_gate_verdict, BudgetDecision::Fail);
        assert!(
            report
                .errors
                .iter()
                .any(|error| { error.contains("compressed_size_bytes exceeds original size") })
        );
        Ok(())
    }

    #[test]
    fn observed_artifact_validation_rejects_redaction_mismatch_and_mandatory_drop() -> Result<()> {
        let config = budget_config();
        let mut observed = observed_metrics();
        let artifact = first_observed_artifact_mut(&mut observed)?;
        artifact.redaction_policy_version = "redact-v0".to_owned();
        artifact.dropped_fields.push("scenario_id".to_owned());

        let report = evaluate_proof_overhead_budget(&config, &observed);

        assert_eq!(report.release_gate_verdict, BudgetDecision::Fail);
        assert!(
            report
                .errors
                .iter()
                .any(|error| { error.contains("redaction policy mismatch") })
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| { error.contains("dropped mandatory field scenario_id") })
        );
        Ok(())
    }

    #[test]
    fn observed_artifact_validation_rejects_cleanup_and_validator_failures() -> Result<()> {
        let config = budget_config();
        let mut observed = observed_metrics();
        let (first, second) = first_two_observed_artifacts_mut(&mut observed)?;
        first.validator_result = "fail".to_owned();
        second.cleanup_status = "failed".to_owned();

        let report = evaluate_proof_overhead_budget(&config, &observed);

        assert_eq!(report.release_gate_verdict, BudgetDecision::Fail);
        assert!(
            report
                .errors
                .iter()
                .any(|error| { error.contains("retention validator failed") })
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| { error.contains("cleanup_status=failed is not release-gate safe") })
        );
        Ok(())
    }

    #[test]
    fn reproduction_command_loss_fails_release_gate() {
        let config = budget_config();
        let mut observed = observed_metrics();
        observed.reproduction_command.clear();

        let report = evaluate_proof_overhead_budget(&config, &observed);

        assert_eq!(report.release_gate_verdict, BudgetDecision::Fail);
        assert!(
            report
                .errors
                .iter()
                .any(|error| { error.contains("reproduction_command is required") })
        );
        assert!(!report.retention_result.reproduction_command_preserved);
    }

    #[test]
    fn required_log_field_loss_fails_schema_validation() {
        let mut config = budget_config();
        config
            .required_log_fields
            .retain(|field| field != "compression_retention_decision");

        let errors = validate_proof_overhead_budget_config(&config);

        assert!(errors.iter().any(|error| {
            error.contains("required_log_fields missing compression_retention_decision")
        }));
    }

    #[test]
    fn human_summary_and_logs_expose_release_gate_contract() {
        let report = evaluate_proof_overhead_budget(&budget_config(), &observed_metrics());

        assert_eq!(report.release_gate_verdict, BudgetDecision::Pass);
        assert!(REQUIRED_LOG_FIELDS.iter().all(|field| {
            report
                .required_log_fields
                .iter()
                .any(|value| value == field)
        }));
        assert_eq!(report.log_records.len(), report.metric_results.len());
        assert!(report.log_records.iter().all(|record| {
            !record.scenario_id.is_empty()
                && !record.baseline_id.is_empty()
                && !record.reproduction_command.is_empty()
                && !record.artifact_sizes.is_empty()
        }));
        assert!(report.log_records.iter().all(|record| {
            record.artifact_sizes.iter().all(|artifact| {
                artifact.original_size_bytes == artifact.size_bytes
                    && artifact.redaction_policy_version == "redact-v1"
                    && artifact.validator_result == RETENTION_VALIDATOR_PASS
                    && artifact.cleanup_status == RETENTION_CLEANUP_CLEAN
            })
        }));
        assert!(report.human_summary.contains("verdict=pass"));
        assert!(report.human_summary.contains("retention_action=retain"));
    }
}
