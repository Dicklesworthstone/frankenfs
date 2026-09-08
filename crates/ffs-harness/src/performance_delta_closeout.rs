#![allow(clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! Performance delta closeout for `bd-rchk5.4`.
//!
//! The closeout consumes measured baseline artifacts and reference-comparison
//! artifacts, then turns them into release-safe tracking signal. Rows that
//! regress, lack a comparable reference, or remain unmeasured must link to a
//! live bead before the report is valid.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const DEFAULT_PERFORMANCE_DELTA_CLOSEOUT_CONFIG: &str =
    "benchmarks/performance_delta_closeout.json";
pub const PERFORMANCE_DELTA_CLOSEOUT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceDeltaCloseoutConfig {
    pub schema_version: u32,
    pub closeout_id: String,
    pub source_bead_id: String,
    pub generated_at: String,
    pub issues_path: String,
    pub reference_baselines: Vec<String>,
    pub current_baselines: Vec<String>,
    pub comparison_artifacts: Vec<String>,
    pub policy: PerformanceDeltaPolicy,
    #[serde(default)]
    pub follow_up_overrides: Vec<PerformanceDeltaFollowUpOverride>,
    #[serde(default)]
    pub unmeasured_claims: Vec<PerformanceUnmeasuredClaim>,
    #[serde(default)]
    pub missing_reference_decisions: Vec<PerformanceMissingReferenceDecision>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceDeltaPolicy {
    pub p99_warn_percent: f64,
    pub p99_fail_percent: f64,
    pub throughput_fail_percent: f64,
    pub missing_reference_follow_up_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceDeltaFollowUpOverride {
    pub operation: String,
    pub follow_up_bead: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<PerformanceDeltaClassification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_contains: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceUnmeasuredClaim {
    pub claim_id: String,
    pub operation: String,
    pub reason: String,
    pub follow_up_bead: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceMissingReferenceDecision {
    pub operation: String,
    pub no_reference_claim_state: String,
    pub comparison_target_rationale: String,
    pub release_wording: String,
    pub raw_logs: Vec<String>,
    pub reproduction_command: String,
    pub validation_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceDeltaClassification {
    Improved,
    WithinThreshold,
    Warning,
    Regression,
    Noisy,
    StaleBaseline,
    MissingReference,
    EnvironmentMismatch,
    MissingMeasurement,
    UnsupportedWorkload,
    OverBudgetInstrumentation,
    PendingCapability,
    Unmeasured,
}

impl PerformanceDeltaClassification {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Improved => "improved",
            Self::WithinThreshold => "within_threshold",
            Self::Warning => "warning",
            Self::Regression => "regression",
            Self::Noisy => "noisy",
            Self::StaleBaseline => "stale_baseline",
            Self::MissingReference => "missing_reference",
            Self::EnvironmentMismatch => "environment_mismatch",
            Self::MissingMeasurement => "missing_measurement",
            Self::UnsupportedWorkload => "unsupported_workload",
            Self::OverBudgetInstrumentation => "over_budget_instrumentation",
            Self::PendingCapability => "pending_capability",
            Self::Unmeasured => "unmeasured",
        }
    }

    #[must_use]
    pub const fn requires_follow_up(self) -> bool {
        matches!(
            self,
            Self::Warning
                | Self::Regression
                | Self::Noisy
                | Self::StaleBaseline
                | Self::MissingReference
                | Self::EnvironmentMismatch
                | Self::MissingMeasurement
                | Self::UnsupportedWorkload
                | Self::OverBudgetInstrumentation
                | Self::PendingCapability
                | Self::Unmeasured
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceFollowUpPayload {
    pub follow_up_bead: String,
    pub classification: PerformanceDeltaClassification,
    pub workload_id: String,
    pub command_template: String,
    pub profile: String,
    pub environment_manifest_id: String,
    pub baseline_artifact_hash: String,
    pub current_artifact_hash: String,
    pub observed_value: f64,
    pub threshold_value: f64,
    pub unit: String,
    pub suspected_subsystem: String,
    pub raw_logs: Vec<String>,
    pub validation_command: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceDeltaRow {
    pub row_id: String,
    pub row_kind: String,
    pub operation: String,
    pub source_artifact: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_artifact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_source_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_p99_us: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_p99_us: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p99_delta_percent: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_throughput_ops_sec: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_throughput_ops_sec: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throughput_delta_percent: Option<f64>,
    pub classification: PerformanceDeltaClassification,
    pub release_claim_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_bead: Option<String>,
    pub follow_up_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_payload: Option<PerformanceFollowUpPayload>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw_logs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparison_target_rationale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_wording: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_command: Option<String>,
    pub rationale: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceDeltaCloseoutReport {
    pub schema_version: u32,
    pub closeout_id: String,
    pub source_bead_id: String,
    pub generated_at: String,
    pub issue_ledger: PerformanceIssueLedgerDiagnostics,
    pub valid: bool,
    pub row_count: usize,
    pub classification_counts: BTreeMap<String, usize>,
    pub follow_up_beads: Vec<String>,
    pub follow_up_payloads: Vec<PerformanceFollowUpPayload>,
    pub rows_requiring_follow_up: usize,
    pub rows: Vec<PerformanceDeltaRow>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceIssueLedgerDiagnostics {
    pub path: String,
    pub issue_count: usize,
    pub sha256: String,
    pub missing_follow_up_beads: Vec<String>,
}

#[derive(Debug, Clone)]
struct Measurement {
    operation: String,
    source_artifact: String,
    source_json: Option<String>,
    p99_us: Option<f64>,
    throughput_ops_sec: Option<f64>,
    status: String,
    command: String,
    environment_manifest_id: String,
    artifact_hash: String,
}

#[derive(Debug, Clone)]
struct IssueLedger {
    ids: BTreeSet<String>,
    diagnostics: PerformanceIssueLedgerDiagnostics,
}

pub fn load_performance_delta_closeout_config(
    path: &Path,
) -> Result<PerformanceDeltaCloseoutConfig> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read performance closeout {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid performance closeout JSON {}", path.display()))
}

pub fn run_performance_delta_closeout(
    config: &PerformanceDeltaCloseoutConfig,
) -> Result<PerformanceDeltaCloseoutReport> {
    let mut errors = validate_config_shape(config);
    let issue_ledger = load_issue_ledger(Path::new(&config.issues_path))?;
    let issue_ids = &issue_ledger.ids;
    let reference_map = load_reference_measurements(config)?;
    let mut rows = Vec::new();

    for artifact in &config.current_baselines {
        rows.extend(load_current_rows(
            artifact,
            &reference_map,
            config,
            issue_ids,
            &mut errors,
        )?);
    }

    for artifact in &config.comparison_artifacts {
        rows.extend(load_comparison_rows(
            artifact,
            config,
            issue_ids,
            &mut errors,
        )?);
    }

    for claim in &config.unmeasured_claims {
        rows.push(unmeasured_claim_row(claim, issue_ids, &mut errors));
    }

    validate_follow_up_overrides(config, issue_ids, &mut errors);
    validate_required_follow_ups(&rows, &mut errors);
    let mut issue_ledger_diagnostics = issue_ledger.diagnostics;
    issue_ledger_diagnostics.missing_follow_up_beads =
        missing_follow_up_beads(config, &rows, issue_ids);
    if !issue_ledger_diagnostics.missing_follow_up_beads.is_empty() {
        errors.push(format!(
            "issue ledger {} sha256={} issue_count={} is missing follow-up beads: {}",
            issue_ledger_diagnostics.path,
            issue_ledger_diagnostics.sha256,
            issue_ledger_diagnostics.issue_count,
            issue_ledger_diagnostics.missing_follow_up_beads.join(", ")
        ));
    }
    let classification_counts = count_classifications(&rows);
    let follow_up_beads = rows
        .iter()
        .filter_map(|row| row.follow_up_bead.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let follow_up_payloads = deduplicate_follow_up_payloads(&rows);
    let rows_requiring_follow_up = rows
        .iter()
        .filter(|row| row.classification.requires_follow_up())
        .count();

    Ok(PerformanceDeltaCloseoutReport {
        schema_version: PERFORMANCE_DELTA_CLOSEOUT_SCHEMA_VERSION,
        closeout_id: config.closeout_id.clone(),
        source_bead_id: config.source_bead_id.clone(),
        generated_at: config.generated_at.clone(),
        issue_ledger: issue_ledger_diagnostics,
        valid: errors.is_empty(),
        row_count: rows.len(),
        classification_counts,
        follow_up_beads,
        follow_up_payloads,
        rows_requiring_follow_up,
        rows,
        errors,
    })
}

#[must_use]
pub fn render_performance_delta_closeout_markdown(
    report: &PerformanceDeltaCloseoutReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Performance Delta Closeout\n");
    let _ = writeln!(out, "- Closeout: `{}`", report.closeout_id);
    let _ = writeln!(out, "- Source bead: `{}`", report.source_bead_id);
    let _ = writeln!(out, "- Generated at: `{}`", report.generated_at);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Rows: `{}`", report.row_count);
    let _ = writeln!(
        out,
        "- Rows requiring follow-up: `{}`",
        report.rows_requiring_follow_up
    );
    let missing_followups = if report.issue_ledger.missing_follow_up_beads.is_empty() {
        "none".to_owned()
    } else {
        report.issue_ledger.missing_follow_up_beads.join(", ")
    };
    out.push_str("\n## Issue Ledger\n\n");
    let _ = writeln!(out, "- Path: `{}`", report.issue_ledger.path);
    let _ = writeln!(out, "- Issue count: `{}`", report.issue_ledger.issue_count);
    let _ = writeln!(out, "- SHA-256: `{}`", report.issue_ledger.sha256);
    let _ = writeln!(out, "- Missing follow-up beads: `{missing_followups}`");
    out.push('\n');
    out.push_str("## Classification Counts\n\n");
    for (class, count) in &report.classification_counts {
        let _ = writeln!(out, "- `{class}`: {count}");
    }
    out.push_str("\n## Follow-Up Beads\n\n");
    for bead in &report.follow_up_beads {
        let _ = writeln!(out, "- `{bead}`");
    }
    out.push_str("\n## Rows\n\n");
    out.push_str("| Operation | Class | Claim state | p99 delta | Throughput delta | Follow-up | Rationale |\n");
    out.push_str("|---|---:|---|---:|---:|---|---|\n");
    for row in &report.rows {
        let p99 = format_optional_percent(row.p99_delta_percent);
        let throughput = format_optional_percent(row.throughput_delta_percent);
        let follow_up = row.follow_up_bead.as_deref().unwrap_or("n/a");
        let rationale = row
            .release_wording
            .as_deref()
            .unwrap_or(&row.rationale)
            .replace('|', "/");
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | {} | {} | `{}` | {} |",
            row.operation,
            row.classification.label(),
            row.release_claim_state,
            p99,
            throughput,
            follow_up,
            rationale
        );
    }
    if !report.errors.is_empty() {
        out.push_str("\n## Errors\n\n");
        for error in &report.errors {
            let _ = writeln!(out, "- {error}");
        }
    }
    out
}

pub fn fail_on_performance_delta_closeout_errors(
    report: &PerformanceDeltaCloseoutReport,
) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "performance delta closeout validation failed: errors={}",
            report.errors.len()
        )
    }
}

fn validate_config_shape(config: &PerformanceDeltaCloseoutConfig) -> Vec<String> {
    let mut errors = Vec::new();
    if config.schema_version != PERFORMANCE_DELTA_CLOSEOUT_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {PERFORMANCE_DELTA_CLOSEOUT_SCHEMA_VERSION}"
        ));
    }
    if config.closeout_id.trim().is_empty() {
        errors.push("closeout_id must not be empty".to_owned());
    }
    if config.source_bead_id.trim().is_empty() {
        errors.push("source_bead_id must not be empty".to_owned());
    }
    if config.reference_baselines.is_empty() {
        errors.push("reference_baselines must not be empty".to_owned());
    }
    if config.current_baselines.is_empty() && config.comparison_artifacts.is_empty() {
        errors.push("at least one current baseline or comparison artifact is required".to_owned());
    }
    if config.policy.p99_warn_percent <= 0.0 {
        errors.push("policy.p99_warn_percent must be positive".to_owned());
    }
    if config.policy.p99_fail_percent <= config.policy.p99_warn_percent {
        errors.push("policy.p99_fail_percent must exceed p99_warn_percent".to_owned());
    }
    if config.policy.throughput_fail_percent >= 0.0 {
        errors.push("policy.throughput_fail_percent must be negative".to_owned());
    }
    if config
        .policy
        .missing_reference_follow_up_bead
        .trim()
        .is_empty()
    {
        errors.push("policy.missing_reference_follow_up_bead must not be empty".to_owned());
    }
    validate_missing_reference_decisions(config, &mut errors);
    errors
}

fn validate_missing_reference_decisions(
    config: &PerformanceDeltaCloseoutConfig,
    errors: &mut Vec<String>,
) {
    let mut seen = BTreeSet::new();
    for decision in &config.missing_reference_decisions {
        if decision.operation.trim().is_empty() {
            errors.push("missing_reference_decisions.operation must not be empty".to_owned());
        }
        if !seen.insert(decision.operation.clone()) {
            errors.push(format!(
                "duplicate missing_reference_decision for {}",
                decision.operation
            ));
        }
        if decision.no_reference_claim_state.trim().is_empty() {
            errors.push(format!(
                "{} missing_reference_decision must declare no_reference_claim_state",
                decision.operation
            ));
        }
        let claim_state = decision.no_reference_claim_state.to_ascii_lowercase();
        if claim_state.contains("regression_free")
            || claim_state.contains("authoritative")
            || claim_state == "measured_local"
        {
            errors.push(format!(
                "{} no-reference claim state must stay conservative",
                decision.operation
            ));
        }
        if decision.comparison_target_rationale.trim().is_empty() {
            errors.push(format!(
                "{} missing_reference_decision must explain comparison_target_rationale",
                decision.operation
            ));
        }
        if decision.release_wording.trim().is_empty() {
            errors.push(format!(
                "{} missing_reference_decision must provide release_wording",
                decision.operation
            ));
        }
        let release_wording = decision.release_wording.to_ascii_lowercase();
        if release_wording.contains("regression-free")
            || release_wording.contains("regression free")
        {
            errors.push(format!(
                "{} release wording must not claim regression-free status",
                decision.operation
            ));
        }
        if decision.raw_logs.is_empty() || decision.raw_logs.iter().any(|log| log.trim().is_empty())
        {
            errors.push(format!(
                "{} missing_reference_decision must list raw log links",
                decision.operation
            ));
        }
        if decision.reproduction_command.trim().is_empty() {
            errors.push(format!(
                "{} missing_reference_decision must provide reproduction_command",
                decision.operation
            ));
        }
        if decision.validation_command.trim().is_empty() {
            errors.push(format!(
                "{} missing_reference_decision must provide validation_command",
                decision.operation
            ));
        }
    }
}

fn load_issue_ledger(path: &Path) -> Result<IssueLedger> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read issue JSONL {}", path.display()))?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("issue JSONL {} is not UTF-8", path.display()))?;
    let mut ids = BTreeSet::new();
    for (line_no, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(trimmed).with_context(|| {
            format!(
                "invalid issue JSON at {}:{}",
                path.display(),
                line_no.saturating_add(1)
            )
        })?;
        if let Some(id) = value.get("id").and_then(Value::as_str) {
            ids.insert(id.to_owned());
        }
    }
    let diagnostics = PerformanceIssueLedgerDiagnostics {
        path: path.display().to_string(),
        issue_count: ids.len(),
        sha256: format!("sha256:{}", sha256_hex(&bytes)),
        missing_follow_up_beads: Vec::new(),
    };
    Ok(IssueLedger { ids, diagnostics })
}

fn load_reference_measurements(
    config: &PerformanceDeltaCloseoutConfig,
) -> Result<BTreeMap<String, Measurement>> {
    let mut map = BTreeMap::new();
    for artifact in &config.reference_baselines {
        for measurement in load_measurements(artifact)? {
            map.insert(measurement.operation.clone(), measurement);
        }
    }
    Ok(map)
}

fn load_current_rows(
    artifact: &str,
    reference_map: &BTreeMap<String, Measurement>,
    config: &PerformanceDeltaCloseoutConfig,
    issue_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) -> Result<Vec<PerformanceDeltaRow>> {
    let mut rows = Vec::new();
    for current in load_measurements(artifact)? {
        if current.status != "measured" {
            let classification = if current.status == "pending" {
                PerformanceDeltaClassification::PendingCapability
            } else if let Some(classification) = classification_from_status(&current.status) {
                classification
            } else {
                PerformanceDeltaClassification::Unmeasured
            };
            rows.push(row_without_reference(
                "measurement",
                &current,
                classification,
                config,
                issue_ids,
                errors,
            ));
            continue;
        }
        if let Some(reference) = reference_map.get(&current.operation) {
            rows.push(row_with_reference(
                "measurement",
                &current,
                reference,
                config,
                issue_ids,
                errors,
            ));
        } else {
            rows.push(row_without_reference(
                "measurement",
                &current,
                PerformanceDeltaClassification::MissingReference,
                config,
                issue_ids,
                errors,
            ));
        }
    }
    Ok(rows)
}

fn load_comparison_rows(
    artifact: &str,
    config: &PerformanceDeltaCloseoutConfig,
    issue_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) -> Result<Vec<PerformanceDeltaRow>> {
    let value = load_json_file(artifact)?;
    let artifact_hash = hash_existing_or_marker(artifact);
    let environment_manifest_id = environment_manifest_id(&value, artifact);
    let rows = value
        .get("rows")
        .and_then(Value::as_array)
        .with_context(|| format!("{artifact} must contain rows[]"))?;
    let mut out = Vec::new();
    for row in rows {
        let operation = string_field(row, "operation")
            .with_context(|| format!("{artifact} comparison row missing operation"))?;
        let p99_delta = number_field(row, "p99_delta_percent");
        let throughput_delta = number_field(row, "throughput_delta_percent");
        let classification = explicit_comparison_classification(row)
            .unwrap_or_else(|| classify_delta(p99_delta, throughput_delta, config));
        let follow_up = follow_up_for(
            &operation,
            classification,
            artifact,
            config,
            issue_ids,
            errors,
        );
        let current_source_json = string_field(row, "current_source_json");
        let follow_up_present = follow_up
            .as_ref()
            .is_some_and(|bead| issue_ids.contains(bead));
        let follow_up_payload = follow_up.as_ref().map(|bead| {
            comparison_follow_up_payload(&ComparisonFollowUpPayloadInput {
                bead,
                row,
                operation: &operation,
                classification,
                artifact,
                artifact_hash: &artifact_hash,
                environment_manifest_id: &environment_manifest_id,
                p99_delta,
                throughput_delta,
                config,
            })
        });
        out.push(PerformanceDeltaRow {
            row_id: format!("comparison:{operation}:{artifact}"),
            row_kind: "comparison".to_owned(),
            operation: operation.clone(),
            source_artifact: artifact.to_owned(),
            reference_artifact: string_field(row, "reference_source_json"),
            current_source_json,
            reference_p99_us: number_field(row, "reference_p99_us"),
            current_p99_us: number_field(row, "current_p99_us"),
            p99_delta_percent: p99_delta,
            reference_throughput_ops_sec: number_field(row, "reference_throughput_ops_sec"),
            current_throughput_ops_sec: number_field(row, "current_throughput_ops_sec"),
            throughput_delta_percent: throughput_delta,
            classification,
            release_claim_state: release_claim_state(classification).to_owned(),
            follow_up_present,
            follow_up_payload,
            follow_up_bead: follow_up,
            raw_logs: raw_logs_for([
                string_field(row, "current_source_json"),
                string_field(row, "current_probe_report_json"),
                Some(artifact.to_owned()),
            ]),
            comparison_target_rationale: None,
            release_wording: None,
            validation_command: Some(format!(
                "cargo run -p ffs-harness -- performance-delta-closeout --config {DEFAULT_PERFORMANCE_DELTA_CLOSEOUT_CONFIG}"
            )),
            rationale: comparison_rationale(row, classification),
            reproduction_command: format!(
                "cargo run -p ffs-harness -- performance-delta-closeout --config {DEFAULT_PERFORMANCE_DELTA_CLOSEOUT_CONFIG}"
            ),
        });
    }
    Ok(out)
}

fn unmeasured_claim_row(
    claim: &PerformanceUnmeasuredClaim,
    issue_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) -> PerformanceDeltaRow {
    let follow_up_present = issue_ids.contains(&claim.follow_up_bead);
    if !follow_up_present {
        errors.push(format!(
            "unmeasured claim {} references missing follow-up bead {}",
            claim.claim_id, claim.follow_up_bead
        ));
    }
    PerformanceDeltaRow {
        row_id: format!("claim:{}", claim.claim_id),
        row_kind: "claim".to_owned(),
        operation: claim.operation.clone(),
        source_artifact: claim.claim_id.clone(),
        reference_artifact: None,
        current_source_json: None,
        reference_p99_us: None,
        current_p99_us: None,
        p99_delta_percent: None,
        reference_throughput_ops_sec: None,
        current_throughput_ops_sec: None,
        throughput_delta_percent: None,
        classification: PerformanceDeltaClassification::Unmeasured,
        release_claim_state: release_claim_state(PerformanceDeltaClassification::Unmeasured)
            .to_owned(),
        follow_up_bead: Some(claim.follow_up_bead.clone()),
        follow_up_present,
        follow_up_payload: Some(claim_follow_up_payload(claim)),
        raw_logs: vec![claim.claim_id.clone()],
        comparison_target_rationale: None,
        release_wording: None,
        validation_command: Some(claim.reproduction_command.clone()),
        rationale: claim.reason.clone(),
        reproduction_command: claim.reproduction_command.clone(),
    }
}

fn load_measurements(artifact: &str) -> Result<Vec<Measurement>> {
    let value = load_json_file(artifact)?;
    let environment_manifest_id = environment_manifest_id(&value, artifact);
    let artifact_hash = hash_existing_or_marker(artifact);
    let measurements = value
        .get("measurements")
        .and_then(Value::as_array)
        .with_context(|| format!("{artifact} must contain measurements[]"))?;
    let mut out = Vec::new();
    for row in measurements {
        let operation = string_field(row, "operation")
            .with_context(|| format!("{artifact} measurement missing operation"))?;
        out.push(Measurement {
            operation,
            source_artifact: artifact.to_owned(),
            source_json: string_field(row, "source_json"),
            p99_us: number_field(row, "p99_us"),
            throughput_ops_sec: number_field(row, "throughput_ops_sec"),
            status: string_field(row, "status").unwrap_or_else(|| "unknown".to_owned()),
            command: string_field(row, "command").unwrap_or_default(),
            environment_manifest_id: environment_manifest_id.clone(),
            artifact_hash: artifact_hash.clone(),
        });
    }
    Ok(out)
}

fn load_json_file(path: &str) -> Result<Value> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read artifact {path}"))?;
    serde_json::from_str(&text).with_context(|| format!("invalid JSON artifact {path}"))
}

fn row_with_reference(
    row_kind: &str,
    current: &Measurement,
    reference: &Measurement,
    config: &PerformanceDeltaCloseoutConfig,
    issue_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) -> PerformanceDeltaRow {
    let p99_delta = match (current.p99_us, reference.p99_us) {
        (Some(current_p99), Some(reference_p99)) if reference_p99 > 0.0 => {
            Some(percent_delta(current_p99, reference_p99))
        }
        _ => None,
    };
    let throughput_delta = match (current.throughput_ops_sec, reference.throughput_ops_sec) {
        (Some(current_tput), Some(reference_tput)) if reference_tput > 0.0 => {
            Some(percent_delta(current_tput, reference_tput))
        }
        _ => None,
    };
    let classification = classify_delta(p99_delta, throughput_delta, config);
    let follow_up = follow_up_for(
        &current.operation,
        classification,
        &current.source_artifact,
        config,
        issue_ids,
        errors,
    );
    let follow_up_present = follow_up
        .as_ref()
        .is_some_and(|bead| issue_ids.contains(bead));
    let follow_up_payload = follow_up.as_ref().map(|bead| {
        measurement_follow_up_payload(
            bead,
            current,
            Some(reference),
            classification,
            p99_delta,
            throughput_delta,
            config,
        )
    });
    PerformanceDeltaRow {
        row_id: format!(
            "{row_kind}:{}:{}",
            current.operation, current.source_artifact
        ),
        row_kind: row_kind.to_owned(),
        operation: current.operation.clone(),
        source_artifact: current.source_artifact.clone(),
        reference_artifact: Some(reference.source_artifact.clone()),
        current_source_json: current.source_json.clone(),
        reference_p99_us: reference.p99_us,
        current_p99_us: current.p99_us,
        p99_delta_percent: p99_delta,
        reference_throughput_ops_sec: reference.throughput_ops_sec,
        current_throughput_ops_sec: current.throughput_ops_sec,
        throughput_delta_percent: throughput_delta,
        classification,
        release_claim_state: release_claim_state(classification).to_owned(),
        follow_up_present,
        follow_up_payload,
        follow_up_bead: follow_up,
        raw_logs: raw_logs_for([
            current.source_json.clone(),
            reference.source_json.clone(),
            Some(current.source_artifact.clone()),
        ]),
        comparison_target_rationale: Some(format!(
            "same-operation reference baseline from {}",
            reference.source_artifact
        )),
        release_wording: None,
        validation_command: Some(current.command.clone()),
        rationale: reference_rationale(current, reference, classification),
        reproduction_command: current.command.clone(),
    }
}

fn row_without_reference(
    row_kind: &str,
    current: &Measurement,
    classification: PerformanceDeltaClassification,
    config: &PerformanceDeltaCloseoutConfig,
    issue_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) -> PerformanceDeltaRow {
    let follow_up = follow_up_for(
        &current.operation,
        classification,
        &current.source_artifact,
        config,
        issue_ids,
        errors,
    );
    let follow_up_present = follow_up
        .as_ref()
        .is_some_and(|bead| issue_ids.contains(bead));
    let follow_up_payload = follow_up.as_ref().map(|bead| {
        measurement_follow_up_payload(bead, current, None, classification, None, None, config)
    });
    let decision = (classification == PerformanceDeltaClassification::MissingReference)
        .then(|| missing_reference_decision_for(&current.operation, config))
        .flatten();
    if classification == PerformanceDeltaClassification::MissingReference && decision.is_none() {
        errors.push(format!(
            "{} is missing an explicit no-reference decision",
            current.operation
        ));
    }
    let raw_logs = decision.map_or_else(
        || {
            raw_logs_for([
                current.source_json.clone(),
                Some(current.source_artifact.clone()),
            ])
        },
        |decision| decision.raw_logs.clone(),
    );
    let comparison_target_rationale =
        decision.map(|decision| decision.comparison_target_rationale.clone());
    let release_wording = decision.map(|decision| decision.release_wording.clone());
    let validation_command = decision.map(|decision| decision.validation_command.clone());
    let release_claim_state = decision.map_or_else(
        || release_claim_state(classification).to_owned(),
        |decision| decision.no_reference_claim_state.clone(),
    );
    let rationale = decision.map_or_else(
        || missing_reference_rationale(current, classification),
        |decision| decision.comparison_target_rationale.clone(),
    );
    let reproduction_command = decision.map_or_else(
        || current.command.clone(),
        |decision| decision.reproduction_command.clone(),
    );
    PerformanceDeltaRow {
        row_id: format!(
            "{row_kind}:{}:{}",
            current.operation, current.source_artifact
        ),
        row_kind: row_kind.to_owned(),
        operation: current.operation.clone(),
        source_artifact: current.source_artifact.clone(),
        reference_artifact: None,
        current_source_json: current.source_json.clone(),
        reference_p99_us: None,
        current_p99_us: current.p99_us,
        p99_delta_percent: None,
        reference_throughput_ops_sec: None,
        current_throughput_ops_sec: current.throughput_ops_sec,
        throughput_delta_percent: None,
        classification,
        release_claim_state,
        follow_up_present,
        follow_up_payload,
        follow_up_bead: follow_up,
        raw_logs,
        comparison_target_rationale,
        release_wording,
        validation_command,
        rationale,
        reproduction_command,
    }
}

fn classify_delta(
    p99_delta: Option<f64>,
    throughput_delta: Option<f64>,
    config: &PerformanceDeltaCloseoutConfig,
) -> PerformanceDeltaClassification {
    if p99_delta.is_none() && throughput_delta.is_none() {
        return PerformanceDeltaClassification::MissingReference;
    }
    if p99_delta.is_some_and(|delta| delta >= config.policy.p99_fail_percent)
        || throughput_delta.is_some_and(|delta| delta <= config.policy.throughput_fail_percent)
    {
        return PerformanceDeltaClassification::Regression;
    }
    if p99_delta.is_some_and(|delta| delta >= config.policy.p99_warn_percent) {
        return PerformanceDeltaClassification::Warning;
    }
    if p99_delta.is_some_and(|delta| delta < 0.0)
        || throughput_delta.is_some_and(|delta| delta > 0.0)
    {
        return PerformanceDeltaClassification::Improved;
    }
    PerformanceDeltaClassification::WithinThreshold
}

fn classification_from_status(status: &str) -> Option<PerformanceDeltaClassification> {
    match status {
        "noisy" => Some(PerformanceDeltaClassification::Noisy),
        "stale" | "stale_baseline" => Some(PerformanceDeltaClassification::StaleBaseline),
        "environment_mismatch" => Some(PerformanceDeltaClassification::EnvironmentMismatch),
        "missing" | "missing_measurement" => {
            Some(PerformanceDeltaClassification::MissingMeasurement)
        }
        "unsupported" | "unsupported_workload" => {
            Some(PerformanceDeltaClassification::UnsupportedWorkload)
        }
        "over_budget" | "over_budget_instrumentation" => {
            Some(PerformanceDeltaClassification::OverBudgetInstrumentation)
        }
        "unmeasured" => Some(PerformanceDeltaClassification::Unmeasured),
        _ => None,
    }
}

fn explicit_comparison_classification(row: &Value) -> Option<PerformanceDeltaClassification> {
    string_field(row, "classification")
        .or_else(|| string_field(row, "verdict"))
        .and_then(|classification| classification_from_status(&classification))
}

fn follow_up_for(
    operation: &str,
    classification: PerformanceDeltaClassification,
    source_artifact: &str,
    config: &PerformanceDeltaCloseoutConfig,
    issue_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) -> Option<String> {
    if !classification.requires_follow_up() {
        return None;
    }
    let exact = config
        .follow_up_overrides
        .iter()
        .find(|override_row| {
            override_row.operation == operation
                && override_row
                    .classification
                    .is_none_or(|class| class == classification)
                && override_row
                    .source_contains
                    .as_ref()
                    .is_none_or(|needle| source_artifact.contains(needle))
        })
        .map(|override_row| override_row.follow_up_bead.clone());
    let follow_up = exact.unwrap_or_else(|| {
        if classification == PerformanceDeltaClassification::MissingReference {
            config.policy.missing_reference_follow_up_bead.clone()
        } else {
            String::new()
        }
    });
    if follow_up.is_empty() {
        errors.push(format!(
            "{operation} has classification {} but no follow-up bead",
            classification.label()
        ));
        return None;
    }
    if !issue_ids.contains(&follow_up) {
        errors.push(format!(
            "{operation} follow-up bead {follow_up} is missing from {}",
            config.issues_path
        ));
    }
    Some(follow_up)
}

fn missing_reference_decision_for<'a>(
    operation: &str,
    config: &'a PerformanceDeltaCloseoutConfig,
) -> Option<&'a PerformanceMissingReferenceDecision> {
    config
        .missing_reference_decisions
        .iter()
        .find(|decision| decision.operation == operation)
}

fn validate_follow_up_overrides(
    config: &PerformanceDeltaCloseoutConfig,
    issue_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    for override_row in &config.follow_up_overrides {
        if override_row.operation.trim().is_empty() {
            errors.push("follow_up_overrides.operation must not be empty".to_owned());
        }
        if !issue_ids.contains(&override_row.follow_up_bead) {
            errors.push(format!(
                "follow-up override for {} references missing bead {}",
                override_row.operation, override_row.follow_up_bead
            ));
        }
    }
    if !issue_ids.contains(&config.policy.missing_reference_follow_up_bead) {
        errors.push(format!(
            "missing-reference follow-up bead {} is absent from {}",
            config.policy.missing_reference_follow_up_bead, config.issues_path
        ));
    }
}

fn validate_required_follow_ups(rows: &[PerformanceDeltaRow], errors: &mut Vec<String>) {
    for row in rows {
        if row.classification.requires_follow_up() && row.follow_up_bead.is_none() {
            errors.push(format!(
                "{} requires follow-up for {}",
                row.row_id,
                row.classification.label()
            ));
        }
        if row.classification.requires_follow_up() && !row.follow_up_present {
            errors.push(format!(
                "{} follow-up bead is not present in tracker",
                row.row_id
            ));
        }
        if row.classification.requires_follow_up() {
            match &row.follow_up_payload {
                Some(payload) => validate_follow_up_payload(row, payload, errors),
                None => errors.push(format!("{} missing follow-up payload", row.row_id)),
            }
        }
        if row.classification == PerformanceDeltaClassification::MissingReference {
            validate_missing_reference_row(row, errors);
        }
    }
}

fn missing_follow_up_beads(
    config: &PerformanceDeltaCloseoutConfig,
    rows: &[PerformanceDeltaRow],
    issue_ids: &BTreeSet<String>,
) -> Vec<String> {
    let mut missing = BTreeSet::new();
    record_missing_follow_up(
        &config.policy.missing_reference_follow_up_bead,
        issue_ids,
        &mut missing,
    );
    for override_row in &config.follow_up_overrides {
        record_missing_follow_up(&override_row.follow_up_bead, issue_ids, &mut missing);
    }
    for claim in &config.unmeasured_claims {
        record_missing_follow_up(&claim.follow_up_bead, issue_ids, &mut missing);
    }
    for row in rows {
        if let Some(follow_up) = &row.follow_up_bead {
            record_missing_follow_up(follow_up, issue_ids, &mut missing);
        }
    }
    missing.into_iter().collect()
}

fn record_missing_follow_up(
    follow_up: &str,
    issue_ids: &BTreeSet<String>,
    missing: &mut BTreeSet<String>,
) {
    if !follow_up.trim().is_empty() && !issue_ids.contains(follow_up) {
        missing.insert(follow_up.to_owned());
    }
}

fn validate_missing_reference_row(row: &PerformanceDeltaRow, errors: &mut Vec<String>) {
    if row.raw_logs.is_empty() {
        errors.push(format!("{} missing no-reference raw_logs", row.row_id));
    }
    if row
        .comparison_target_rationale
        .as_deref()
        .is_none_or(str::is_empty)
    {
        errors.push(format!(
            "{} missing no-reference comparison_target_rationale",
            row.row_id
        ));
    }
    if row.release_wording.as_deref().is_none_or(str::is_empty) {
        errors.push(format!(
            "{} missing no-reference release_wording",
            row.row_id
        ));
    }
    if row.validation_command.as_deref().is_none_or(str::is_empty) {
        errors.push(format!(
            "{} missing no-reference validation_command",
            row.row_id
        ));
    }
    let claim_state = row.release_claim_state.to_ascii_lowercase();
    if claim_state.contains("regression_free")
        || claim_state.contains("authoritative")
        || claim_state == "measured_local"
        || claim_state == "unknown"
    {
        errors.push(format!(
            "{} no-reference release_claim_state must be explicit and conservative",
            row.row_id
        ));
    }
    if row
        .release_wording
        .as_deref()
        .is_some_and(claims_regression_free)
    {
        errors.push(format!(
            "{} no-reference release wording must not claim regression-free status",
            row.row_id
        ));
    }
}

fn claims_regression_free(wording: &str) -> bool {
    let lower = wording.to_ascii_lowercase();
    lower.contains("regression-free") || lower.contains("regression free")
}

fn validate_follow_up_payload(
    row: &PerformanceDeltaRow,
    payload: &PerformanceFollowUpPayload,
    errors: &mut Vec<String>,
) {
    let required = [
        ("workload_id", payload.workload_id.as_str()),
        ("command_template", payload.command_template.as_str()),
        ("profile", payload.profile.as_str()),
        (
            "environment_manifest_id",
            payload.environment_manifest_id.as_str(),
        ),
        (
            "baseline_artifact_hash",
            payload.baseline_artifact_hash.as_str(),
        ),
        (
            "current_artifact_hash",
            payload.current_artifact_hash.as_str(),
        ),
        ("unit", payload.unit.as_str()),
        ("suspected_subsystem", payload.suspected_subsystem.as_str()),
        ("validation_command", payload.validation_command.as_str()),
    ];
    for (field, value) in required {
        if value.trim().is_empty() {
            errors.push(format!("{} follow-up payload missing {field}", row.row_id));
        }
    }
    if payload.raw_logs.is_empty() {
        errors.push(format!("{} follow-up payload missing raw_logs", row.row_id));
    }
    if payload.follow_up_bead.trim().is_empty() {
        errors.push(format!(
            "{} follow-up payload missing follow_up_bead",
            row.row_id
        ));
    }
}

fn deduplicate_follow_up_payloads(rows: &[PerformanceDeltaRow]) -> Vec<PerformanceFollowUpPayload> {
    let mut payloads = BTreeMap::new();
    for row in rows {
        if let Some(payload) = &row.follow_up_payload {
            payloads
                .entry(follow_up_payload_key(payload))
                .or_insert_with(|| payload.clone());
        }
    }
    payloads.into_values().collect()
}

fn follow_up_payload_key(payload: &PerformanceFollowUpPayload) -> String {
    format!(
        "{}:{}:{}",
        payload.follow_up_bead,
        payload.classification.label(),
        payload.workload_id
    )
}

fn count_classifications(rows: &[PerformanceDeltaRow]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for row in rows {
        *counts
            .entry(row.classification.label().to_owned())
            .or_insert(0) += 1;
    }
    counts
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn number_field(value: &Value, key: &str) -> Option<f64> {
    let raw = value.get(key)?;
    raw.as_f64()
        .or_else(|| raw.as_i64().map(|number| number as f64))
        .or_else(|| raw.as_u64().map(|number| number as f64))
}

fn percent_delta(current: f64, reference: f64) -> f64 {
    ((current - reference) / reference) * 100.0
}

fn release_claim_state(classification: PerformanceDeltaClassification) -> &'static str {
    match classification {
        PerformanceDeltaClassification::Improved
        | PerformanceDeltaClassification::WithinThreshold => "measured_local",
        PerformanceDeltaClassification::Warning => "experimental",
        PerformanceDeltaClassification::Regression
        | PerformanceDeltaClassification::Noisy
        | PerformanceDeltaClassification::StaleBaseline
        | PerformanceDeltaClassification::MissingReference
        | PerformanceDeltaClassification::EnvironmentMismatch
        | PerformanceDeltaClassification::MissingMeasurement
        | PerformanceDeltaClassification::UnsupportedWorkload
        | PerformanceDeltaClassification::OverBudgetInstrumentation
        | PerformanceDeltaClassification::PendingCapability
        | PerformanceDeltaClassification::Unmeasured => "unknown",
    }
}

fn measurement_follow_up_payload(
    bead: &str,
    current: &Measurement,
    reference: Option<&Measurement>,
    classification: PerformanceDeltaClassification,
    p99_delta: Option<f64>,
    throughput_delta: Option<f64>,
    config: &PerformanceDeltaCloseoutConfig,
) -> PerformanceFollowUpPayload {
    let (observed_value, threshold_value, unit) =
        payload_metric(classification, p99_delta, throughput_delta, current, config);
    let command = command_or_default(&current.command, &current.operation);
    PerformanceFollowUpPayload {
        follow_up_bead: bead.to_owned(),
        classification,
        workload_id: current.operation.clone(),
        command_template: command.clone(),
        profile: profile_from_command(&command),
        environment_manifest_id: current.environment_manifest_id.clone(),
        baseline_artifact_hash: reference.map_or_else(
            || "missing_reference".to_owned(),
            |row| row.artifact_hash.clone(),
        ),
        current_artifact_hash: current.artifact_hash.clone(),
        observed_value,
        threshold_value,
        unit,
        suspected_subsystem: suspected_subsystem(&current.operation),
        raw_logs: raw_logs_for([
            current.source_json.clone(),
            Some(current.source_artifact.clone()),
        ]),
        validation_command: command,
    }
}

struct ComparisonFollowUpPayloadInput<'a> {
    bead: &'a str,
    row: &'a Value,
    operation: &'a str,
    classification: PerformanceDeltaClassification,
    artifact: &'a str,
    artifact_hash: &'a str,
    environment_manifest_id: &'a str,
    p99_delta: Option<f64>,
    throughput_delta: Option<f64>,
    config: &'a PerformanceDeltaCloseoutConfig,
}

fn comparison_follow_up_payload(
    input: &ComparisonFollowUpPayloadInput<'_>,
) -> PerformanceFollowUpPayload {
    let (observed_value, threshold_value, unit) = comparison_payload_metric(
        input.classification,
        input.p99_delta,
        input.throughput_delta,
        input.config,
    );
    let command = format!(
        "cargo run -p ffs-harness -- performance-delta-closeout --config {DEFAULT_PERFORMANCE_DELTA_CLOSEOUT_CONFIG}"
    );
    PerformanceFollowUpPayload {
        follow_up_bead: input.bead.to_owned(),
        classification: input.classification,
        workload_id: input.operation.to_owned(),
        command_template: command.clone(),
        profile: string_field(input.row, "cargo_profile")
            .unwrap_or_else(|| "release-perf".to_owned()),
        environment_manifest_id: input.environment_manifest_id.to_owned(),
        baseline_artifact_hash: string_field(input.row, "reference_source_json").map_or_else(
            || "missing_reference".to_owned(),
            |path| hash_existing_or_marker(&path),
        ),
        current_artifact_hash: string_field(input.row, "current_source_json").map_or_else(
            || input.artifact_hash.to_owned(),
            |path| hash_existing_or_marker(&path),
        ),
        observed_value,
        threshold_value,
        unit,
        suspected_subsystem: suspected_subsystem(input.operation),
        raw_logs: raw_logs_for([
            string_field(input.row, "current_source_json"),
            string_field(input.row, "current_probe_report_json"),
            Some(input.artifact.to_owned()),
        ]),
        validation_command: command,
    }
}

fn claim_follow_up_payload(claim: &PerformanceUnmeasuredClaim) -> PerformanceFollowUpPayload {
    PerformanceFollowUpPayload {
        follow_up_bead: claim.follow_up_bead.clone(),
        classification: PerformanceDeltaClassification::Unmeasured,
        workload_id: claim.operation.clone(),
        command_template: claim.reproduction_command.clone(),
        profile: "deferred".to_owned(),
        environment_manifest_id: format!("claim:{}", sha256_hex(claim.reason.as_bytes())),
        baseline_artifact_hash: "missing_measurement".to_owned(),
        current_artifact_hash: format!("claim:{}", sha256_hex(claim.claim_id.as_bytes())),
        observed_value: 0.0,
        threshold_value: 0.0,
        unit: "claim_state".to_owned(),
        suspected_subsystem: suspected_subsystem(&claim.operation),
        raw_logs: vec![claim.claim_id.clone()],
        validation_command: claim.reproduction_command.clone(),
    }
}

fn payload_metric(
    classification: PerformanceDeltaClassification,
    p99_delta: Option<f64>,
    throughput_delta: Option<f64>,
    current: &Measurement,
    config: &PerformanceDeltaCloseoutConfig,
) -> (f64, f64, String) {
    if matches!(classification, PerformanceDeltaClassification::Regression)
        && throughput_delta.is_some_and(|delta| delta <= config.policy.throughput_fail_percent)
        && !p99_delta.is_some_and(|delta| delta >= config.policy.p99_fail_percent)
    {
        return (
            throughput_delta.unwrap_or_default(),
            config.policy.throughput_fail_percent,
            "throughput_delta_percent".to_owned(),
        );
    }
    if let Some(delta) = p99_delta {
        let threshold = if matches!(classification, PerformanceDeltaClassification::Warning) {
            config.policy.p99_warn_percent
        } else {
            config.policy.p99_fail_percent
        };
        return (delta, threshold, "p99_delta_percent".to_owned());
    }
    if let Some(throughput) = current.throughput_ops_sec {
        return (throughput, 0.0, "throughput_ops_sec".to_owned());
    }
    (current.p99_us.unwrap_or_default(), 0.0, "p99_us".to_owned())
}

fn comparison_payload_metric(
    classification: PerformanceDeltaClassification,
    p99_delta: Option<f64>,
    throughput_delta: Option<f64>,
    config: &PerformanceDeltaCloseoutConfig,
) -> (f64, f64, String) {
    if matches!(classification, PerformanceDeltaClassification::Regression)
        && throughput_delta.is_some_and(|delta| delta <= config.policy.throughput_fail_percent)
        && !p99_delta.is_some_and(|delta| delta >= config.policy.p99_fail_percent)
    {
        return (
            throughput_delta.unwrap_or_default(),
            config.policy.throughput_fail_percent,
            "throughput_delta_percent".to_owned(),
        );
    }
    if let Some(delta) = p99_delta {
        let threshold = if matches!(classification, PerformanceDeltaClassification::Warning) {
            config.policy.p99_warn_percent
        } else {
            config.policy.p99_fail_percent
        };
        return (delta, threshold, "p99_delta_percent".to_owned());
    }
    (
        throughput_delta.unwrap_or_default(),
        config.policy.throughput_fail_percent,
        "throughput_delta_percent".to_owned(),
    )
}

fn command_or_default(command: &str, operation: &str) -> String {
    if command.trim().is_empty() {
        format!(
            "cargo run -p ffs-harness -- performance-delta-closeout --config {DEFAULT_PERFORMANCE_DELTA_CLOSEOUT_CONFIG} --workload {operation}"
        )
    } else {
        command.to_owned()
    }
}

fn profile_from_command(command: &str) -> String {
    let mut parts = command.split_whitespace();
    while let Some(part) = parts.next() {
        if part == "--profile" {
            return parts.next().unwrap_or("release").to_owned();
        }
    }
    "release".to_owned()
}

fn suspected_subsystem(operation: &str) -> String {
    operation
        .split('_')
        .next()
        .filter(|part| !part.is_empty())
        .unwrap_or("performance")
        .to_owned()
}

fn raw_logs_for<const N: usize>(logs: [Option<String>; N]) -> Vec<String> {
    logs.into_iter()
        .flatten()
        .filter(|log| !log.trim().is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn hash_existing_or_marker(path: &str) -> String {
    fs::read(path).map_or_else(
        |_| format!("missing:{path}"),
        |bytes| format!("sha256:{}", sha256_hex(&bytes)),
    )
}

fn environment_manifest_id(value: &Value, artifact: &str) -> String {
    let manifest = value
        .get("environment")
        .or_else(|| value.get("current_baseline"))
        .or_else(|| value.get("reference_baseline"))
        .unwrap_or(value);
    serde_json::to_vec(manifest).map_or_else(
        |_| format!("artifact:{}", hash_existing_or_marker(artifact)),
        |bytes| format!("sha256:{}", sha256_hex(&bytes)),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn reference_rationale(
    current: &Measurement,
    reference: &Measurement,
    classification: PerformanceDeltaClassification,
) -> String {
    format!(
        "same-operation comparison against {}; classified as {}",
        reference.source_artifact,
        classification.label()
    )
    .replace(&current.source_artifact, "")
}

fn comparison_rationale(row: &Value, classification: PerformanceDeltaClassification) -> String {
    let verdict = string_field(row, "verdict").unwrap_or_else(|| "unknown".to_owned());
    format!(
        "comparison artifact verdict={verdict}; classified as {}",
        classification.label()
    )
}

fn missing_reference_rationale(
    current: &Measurement,
    classification: PerformanceDeltaClassification,
) -> String {
    match classification {
        PerformanceDeltaClassification::MissingReference => format!(
            "measured in {} but no checked-in same-operation reference baseline exists",
            current.source_artifact
        ),
        PerformanceDeltaClassification::PendingCapability => format!(
            "artifact {} is pending because required host capability was unavailable",
            current.source_artifact
        ),
        PerformanceDeltaClassification::Unmeasured => {
            format!(
                "artifact {} did not produce a measured row",
                current.source_artifact
            )
        }
        other => format!("classified as {}", other.label()),
    }
}

fn format_optional_percent(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), |number| format!("{number:.3}%"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write as _, path::PathBuf};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn issue_ids() -> BTreeSet<String> {
        [
            "bd-rchk5.5",
            "bd-rchk5.6",
            "bd-rchk5.7",
            "bd-rchk5.8",
            "bd-9vzzk",
            "bd-t21em",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
    }

    fn test_issue_ledger_diagnostics() -> PerformanceIssueLedgerDiagnostics {
        PerformanceIssueLedgerDiagnostics {
            path: ".beads/issues.jsonl".to_owned(),
            issue_count: 6,
            sha256: "sha256:test-ledger".to_owned(),
            missing_follow_up_beads: Vec::new(),
        }
    }

    fn write_issue_ledger(ids: &[&str]) -> std::io::Result<tempfile::NamedTempFile> {
        let mut file = tempfile::NamedTempFile::new()?;
        for id in ids {
            writeln!(file, r#"{{"id":"{id}"}}"#)?;
        }
        Ok(file)
    }

    fn base_config() -> PerformanceDeltaCloseoutConfig {
        PerformanceDeltaCloseoutConfig {
            schema_version: PERFORMANCE_DELTA_CLOSEOUT_SCHEMA_VERSION,
            closeout_id: "test-closeout".to_owned(),
            source_bead_id: "bd-rchk5.4".to_owned(),
            generated_at: "2026-05-03T00:00:00Z".to_owned(),
            issues_path: ".beads/issues.jsonl".to_owned(),
            reference_baselines: vec!["reference.json".to_owned()],
            current_baselines: vec!["current.json".to_owned()],
            comparison_artifacts: Vec::new(),
            policy: PerformanceDeltaPolicy {
                p99_warn_percent: 10.0,
                p99_fail_percent: 50.0,
                throughput_fail_percent: -25.0,
                missing_reference_follow_up_bead: "bd-rchk5.8".to_owned(),
            },
            follow_up_overrides: vec![PerformanceDeltaFollowUpOverride {
                operation: "mount_cold".to_owned(),
                follow_up_bead: "bd-rchk5.5".to_owned(),
                classification: Some(PerformanceDeltaClassification::Regression),
                source_contains: None,
            }],
            unmeasured_claims: Vec::new(),
            missing_reference_decisions: vec![PerformanceMissingReferenceDecision {
                operation: "wal_commit_4k_sync".to_owned(),
                no_reference_claim_state: "reference_limited_experimental".to_owned(),
                comparison_target_rationale: "no same-operation reference baseline exists"
                    .to_owned(),
                release_wording: "Treat as reference-limited experimental until a same-operation baseline exists."
                    .to_owned(),
                raw_logs: vec!["raw/current.json".to_owned()],
                reproduction_command:
                    "cargo bench --profile release-perf -p ffs-mvcc --bench wal_throughput -- wal_commit_4k_sync"
                        .to_owned(),
                validation_command:
                    "cargo run -p ffs-harness -- performance-delta-closeout --config benchmarks/performance_delta_closeout.json"
                        .to_owned(),
            }],
        }
    }

    fn workspace_path(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }

    /// Replace the machine-absolute crate manifest prefix with a stable
    /// placeholder so snapshots do not embed the checkout path (which differs
    /// between local `/data/projects/frankenfs` and CI `/home/runner/work/...`).
    fn normalize_manifest_dir(value: &str) -> String {
        value.replace(env!("CARGO_MANIFEST_DIR"), "{MANIFEST_DIR}")
    }

    fn absolutize_paths(
        mut config: PerformanceDeltaCloseoutConfig,
    ) -> PerformanceDeltaCloseoutConfig {
        config.issues_path = workspace_path(&config.issues_path).display().to_string();
        config.reference_baselines = config
            .reference_baselines
            .iter()
            .map(|path| workspace_path(path).display().to_string())
            .collect();
        config.current_baselines = config
            .current_baselines
            .iter()
            .map(|path| workspace_path(path).display().to_string())
            .collect();
        config.comparison_artifacts = config
            .comparison_artifacts
            .iter()
            .map(|path| workspace_path(path).display().to_string())
            .collect();
        config
    }

    #[test]
    fn classify_delta_marks_reference_regression() {
        let config = base_config();
        let class = classify_delta(Some(55.0), Some(-5.0), &config);
        assert_eq!(class, PerformanceDeltaClassification::Regression);
    }

    #[test]
    fn classify_delta_marks_throughput_regression() {
        let config = base_config();
        let class = classify_delta(Some(1.0), Some(-30.0), &config);
        assert_eq!(class, PerformanceDeltaClassification::Regression);
    }

    #[test]
    fn classify_delta_marks_improvement() {
        let config = base_config();
        let class = classify_delta(Some(-80.0), Some(70.0), &config);
        assert_eq!(class, PerformanceDeltaClassification::Improved);
    }

    #[test]
    fn missing_reference_uses_policy_follow_up() {
        let mut errors = Vec::new();
        let follow_up = follow_up_for(
            "wal_commit_4k_sync",
            PerformanceDeltaClassification::MissingReference,
            "current.json",
            &base_config(),
            &issue_ids(),
            &mut errors,
        );
        assert_eq!(follow_up.as_deref(), Some("bd-rchk5.8"));
        assert_eq!(errors, [] as [String; 0]);
    }

    #[test]
    fn missing_override_bead_is_invalid() {
        let mut errors = Vec::new();
        let follow_up = follow_up_for(
            "mount_cold",
            PerformanceDeltaClassification::Regression,
            "comparison.json",
            &base_config(),
            &BTreeSet::new(),
            &mut errors,
        );
        assert_eq!(follow_up.as_deref(), Some("bd-rchk5.5"));
        assert!(errors.iter().any(|error| error.contains("bd-rchk5.5")));
    }

    #[test]
    fn missing_follow_up_diagnostics_are_sorted_and_deduplicated() {
        let mut config = base_config();
        config.unmeasured_claims.push(PerformanceUnmeasuredClaim {
            claim_id: "unmeasured".to_owned(),
            operation: "long_campaign".to_owned(),
            reason: "not measured yet".to_owned(),
            follow_up_bead: "bd-zmissing".to_owned(),
            reproduction_command: "cargo test".to_owned(),
        });
        config
            .follow_up_overrides
            .push(PerformanceDeltaFollowUpOverride {
                operation: "mount_recovery".to_owned(),
                follow_up_bead: "bd-rchk5.5".to_owned(),
                classification: Some(PerformanceDeltaClassification::Regression),
                source_contains: None,
            });
        let issue_ids = BTreeSet::from(["bd-rchk5.8".to_owned()]);
        let row = PerformanceDeltaRow {
            row_id: "comparison:mount_cold".to_owned(),
            row_kind: "comparison".to_owned(),
            operation: "mount_cold".to_owned(),
            source_artifact: "comparison.json".to_owned(),
            reference_artifact: None,
            current_source_json: None,
            reference_p99_us: None,
            current_p99_us: None,
            p99_delta_percent: None,
            reference_throughput_ops_sec: None,
            current_throughput_ops_sec: None,
            throughput_delta_percent: None,
            classification: PerformanceDeltaClassification::Regression,
            release_claim_state: "unknown".to_owned(),
            follow_up_bead: Some("bd-zmissing".to_owned()),
            follow_up_present: false,
            follow_up_payload: None,
            raw_logs: Vec::new(),
            comparison_target_rationale: None,
            release_wording: None,
            validation_command: None,
            rationale: "missing tracker row".to_owned(),
            reproduction_command: "cargo test".to_owned(),
        };

        assert_eq!(
            missing_follow_up_beads(&config, &[row], &issue_ids),
            vec!["bd-rchk5.5".to_owned(), "bd-zmissing".to_owned()]
        );
    }

    #[test]
    fn run_report_summarizes_issue_ledger_when_followups_are_missing() -> TestResult {
        let dir = tempfile::tempdir()?;
        let reference_path = dir.path().join("reference.json");
        let current_path = dir.path().join("current.json");
        fs::write(
            &reference_path,
            r#"{"environment":{"id":"test"},"measurements":[{"operation":"mount_cold","status":"measured","p99_us":100.0,"throughput_ops_sec":10.0,"command":"cargo bench"}]}"#,
        )?;
        fs::write(
            &current_path,
            r#"{"environment":{"id":"test"},"measurements":[{"operation":"mount_cold","status":"measured","p99_us":200.0,"throughput_ops_sec":10.0,"command":"cargo bench"}]}"#,
        )?;
        let issue_ledger = write_issue_ledger(&["bd-rchk5.8"])?;
        let mut config = base_config();
        config.issues_path = issue_ledger.path().display().to_string();
        config.reference_baselines = vec![reference_path.display().to_string()];
        config.current_baselines = vec![current_path.display().to_string()];
        config.comparison_artifacts.clear();
        config.unmeasured_claims.clear();

        let report = run_performance_delta_closeout(&config)?;

        assert!(!report.valid);
        assert_eq!(report.issue_ledger.issue_count, 1);
        assert_eq!(
            report.issue_ledger.missing_follow_up_beads,
            vec!["bd-rchk5.5".to_owned()]
        );
        assert!(report.issue_ledger.sha256.starts_with("sha256:"));
        assert!(report.errors.iter().any(|error| {
            error.contains("issue ledger")
                && error.contains("issue_count=1")
                && error.contains("bd-rchk5.5")
        }));
        Ok(())
    }

    #[test]
    fn checked_in_closeout_config_validates_and_links_followups() -> TestResult {
        let config = load_performance_delta_closeout_config(Path::new(&workspace_path(
            DEFAULT_PERFORMANCE_DELTA_CLOSEOUT_CONFIG,
        )))?;
        let issue_ledger = write_issue_ledger(&[
            "bd-rchk5.5",
            "bd-rchk5.6",
            "bd-rchk5.7",
            "bd-rchk5.8",
            "bd-9vzzk",
            "bd-t21em",
        ])?;
        let mut config = absolutize_paths(config);
        config.issues_path = issue_ledger.path().display().to_string();
        let report = run_performance_delta_closeout(&config)?;
        assert!(report.valid, "{:?}", report.errors);
        assert!(report.row_count >= 10);
        assert!(
            report
                .classification_counts
                .contains_key(PerformanceDeltaClassification::Regression.label())
        );
        assert!(
            report
                .classification_counts
                .contains_key(PerformanceDeltaClassification::MissingReference.label())
        );
        assert!(
            report
                .follow_up_beads
                .iter()
                .any(|bead| bead == "bd-rchk5.5")
        );
        assert!(
            report
                .follow_up_beads
                .iter()
                .any(|bead| bead == "bd-rchk5.8")
        );
        let required_no_reference = [
            "block_cache_sharded_arc_concurrent_hot_read_64threads",
            "block_cache_sharded_s3fifo_concurrent_hot_read_64threads",
            "cli_metadata_parse_conformance",
            "repair_symbol_refresh_staleness_latency",
            "wal_commit_4k_sync",
        ];
        for operation in required_no_reference {
            let maybe_row = report.rows.iter().find(|row| {
                row.operation == operation
                    && row.classification == PerformanceDeltaClassification::MissingReference
            });
            assert!(
                maybe_row.is_some(),
                "missing no-reference row for {operation}"
            );
            let Some(row) = maybe_row else { continue };
            assert_eq!(row.release_claim_state, "reference_limited_experimental");
            assert_ne!(row.raw_logs, [] as [String; 0]);
            assert!(row.comparison_target_rationale.is_some());
            assert!(row.release_wording.is_some());
            assert!(row.validation_command.is_some());
        }
        Ok(())
    }

    #[test]
    fn performance_delta_closeout_report_json_shape() -> TestResult {
        let config = load_performance_delta_closeout_config(Path::new(&workspace_path(
            DEFAULT_PERFORMANCE_DELTA_CLOSEOUT_CONFIG,
        )))?;
        let issue_ledger = write_issue_ledger(&[
            "bd-rchk5.5",
            "bd-rchk5.6",
            "bd-rchk5.7",
            "bd-rchk5.8",
            "bd-9vzzk",
            "bd-t21em",
        ])?;
        let mut config = absolutize_paths(config);
        config.issues_path = issue_ledger.path().display().to_string();
        let report = run_performance_delta_closeout(&config)?;
        assert!(report.valid, "{:?}", report.errors);

        let full_json = serde_json::to_string_pretty(&report)?;
        let decoded: PerformanceDeltaCloseoutReport = serde_json::from_str(&full_json)?;
        let original_json: Value = serde_json::from_str(&full_json)?;
        assert_eq!(serde_json::to_value(&decoded)?, original_json);
        // Normalize through JSON text so finite f64s use the artifact representation.
        let normalized_json = serde_json::to_string(&report)?;
        let normalized_report: PerformanceDeltaCloseoutReport =
            serde_json::from_str(&normalized_json)?;
        assert_eq!(decoded, normalized_report);
        assert_eq!(decoded.schema_version, report.schema_version);
        assert_eq!(decoded.closeout_id, report.closeout_id);
        assert_eq!(decoded.source_bead_id, report.source_bead_id);
        assert_eq!(decoded.valid, report.valid);
        assert_eq!(decoded.row_count, report.row_count);
        assert_eq!(decoded.classification_counts, report.classification_counts);
        assert_eq!(decoded.follow_up_beads, report.follow_up_beads);
        assert_eq!(
            decoded.follow_up_payloads.len(),
            report.follow_up_payloads.len()
        );
        assert_eq!(decoded.rows.len(), report.rows.len());
        assert_eq!(
            decoded
                .rows
                .iter()
                .map(|row| &row.row_id)
                .collect::<Vec<_>>(),
            report
                .rows
                .iter()
                .map(|row| &row.row_id)
                .collect::<Vec<_>>()
        );
        assert_eq!(decoded.errors, report.errors);
        assert!(
            decoded
                .follow_up_beads
                .iter()
                .any(|bead| bead == "bd-rchk5.5")
        );
        assert!(
            decoded
                .classification_counts
                .contains_key(PerformanceDeltaClassification::MissingReference.label())
        );

        let row_samples = report
            .rows
            .iter()
            .take(4)
            .map(|row| {
                serde_json::json!({
                    "row_id": normalize_manifest_dir(&row.row_id),
                    "row_kind": &row.row_kind,
                    "operation": &row.operation,
                    "classification": row.classification,
                    "release_claim_state": &row.release_claim_state,
                    "follow_up_present": row.follow_up_present,
                    "has_follow_up_payload": row.follow_up_payload.is_some(),
                    "has_validation_command": row.validation_command.is_some(),
                })
            })
            .collect::<Vec<_>>();

        let shape = serde_json::json!({
            "schema_version": report.schema_version,
            "closeout_id": report.closeout_id,
            "source_bead_id": report.source_bead_id,
            "generated_at": report.generated_at,
            "valid": report.valid,
            "row_count": report.row_count,
            "classification_counts": report.classification_counts,
            "follow_up_beads": report.follow_up_beads,
            "follow_up_payload_count": report.follow_up_payloads.len(),
            "rows_requiring_follow_up": report.rows_requiring_follow_up,
            "issue_ledger_issue_count": report.issue_ledger.issue_count,
            "issue_ledger_sha256": report.issue_ledger.sha256,
            "missing_follow_up_count": report.issue_ledger.missing_follow_up_beads.len(),
            "row_samples": row_samples,
            "errors": report.errors,
        });
        insta::assert_snapshot!(
            "performance_delta_closeout_report_json_shape",
            serde_json::to_string_pretty(&shape)?
        );
        Ok(())
    }

    #[test]
    fn markdown_mentions_follow_up_beads() {
        let report = PerformanceDeltaCloseoutReport {
            schema_version: PERFORMANCE_DELTA_CLOSEOUT_SCHEMA_VERSION,
            closeout_id: "test".to_owned(),
            source_bead_id: "bd-rchk5.4".to_owned(),
            generated_at: "now".to_owned(),
            issue_ledger: test_issue_ledger_diagnostics(),
            valid: true,
            row_count: 1,
            classification_counts: BTreeMap::from([("regression".to_owned(), 1)]),
            follow_up_beads: vec!["bd-rchk5.5".to_owned()],
            follow_up_payloads: vec![PerformanceFollowUpPayload {
                follow_up_bead: "bd-rchk5.5".to_owned(),
                classification: PerformanceDeltaClassification::Regression,
                workload_id: "mount_cold".to_owned(),
                command_template: "cargo run".to_owned(),
                profile: "release".to_owned(),
                environment_manifest_id: "sha256:test".to_owned(),
                baseline_artifact_hash: "sha256:base".to_owned(),
                current_artifact_hash: "sha256:current".to_owned(),
                observed_value: 100.0,
                threshold_value: 50.0,
                unit: "p99_delta_percent".to_owned(),
                suspected_subsystem: "mount".to_owned(),
                raw_logs: vec!["comparison.json".to_owned()],
                validation_command: "cargo run".to_owned(),
            }],
            rows_requiring_follow_up: 1,
            rows: vec![PerformanceDeltaRow {
                row_id: "comparison:mount_cold".to_owned(),
                row_kind: "comparison".to_owned(),
                operation: "mount_cold".to_owned(),
                source_artifact: "comparison.json".to_owned(),
                reference_artifact: None,
                current_source_json: None,
                reference_p99_us: Some(10.0),
                current_p99_us: Some(20.0),
                p99_delta_percent: Some(100.0),
                reference_throughput_ops_sec: None,
                current_throughput_ops_sec: None,
                throughput_delta_percent: None,
                classification: PerformanceDeltaClassification::Regression,
                release_claim_state: "unknown".to_owned(),
                follow_up_bead: Some("bd-rchk5.5".to_owned()),
                follow_up_present: true,
                follow_up_payload: None,
                raw_logs: vec!["comparison.json".to_owned()],
                comparison_target_rationale: None,
                release_wording: None,
                validation_command: Some("cargo run".to_owned()),
                rationale: "slow".to_owned(),
                reproduction_command: "cargo run".to_owned(),
            }],
            errors: Vec::new(),
        };
        let markdown = render_performance_delta_closeout_markdown(&report);
        assert!(markdown.contains("bd-rchk5.5"));
        assert!(markdown.contains("mount_cold"));
        insta::assert_snapshot!(
            "render_performance_delta_closeout_markdown_regression_sample",
            markdown
        );
    }

    #[test]
    fn status_classification_covers_closeout_dispositions() {
        let cases = [
            ("noisy", PerformanceDeltaClassification::Noisy),
            (
                "stale_baseline",
                PerformanceDeltaClassification::StaleBaseline,
            ),
            (
                "environment_mismatch",
                PerformanceDeltaClassification::EnvironmentMismatch,
            ),
            (
                "missing_measurement",
                PerformanceDeltaClassification::MissingMeasurement,
            ),
            (
                "unsupported_workload",
                PerformanceDeltaClassification::UnsupportedWorkload,
            ),
            (
                "over_budget_instrumentation",
                PerformanceDeltaClassification::OverBudgetInstrumentation,
            ),
        ];
        for (status, expected) in cases {
            assert_eq!(classification_from_status(status), Some(expected));
        }
    }

    #[test]
    fn follow_up_payload_contains_bisect_ready_fields() {
        let current = Measurement {
            operation: "mount_cold".to_owned(),
            source_artifact: "current.json".to_owned(),
            source_json: Some("raw/current.json".to_owned()),
            p99_us: Some(200.0),
            throughput_ops_sec: Some(5.0),
            status: "measured".to_owned(),
            command: "cargo bench --profile release-perf -p ffs-cli --bench mount".to_owned(),
            environment_manifest_id: "sha256:env".to_owned(),
            artifact_hash: "sha256:current".to_owned(),
        };
        let reference = Measurement {
            operation: "mount_cold".to_owned(),
            source_artifact: "reference.json".to_owned(),
            source_json: Some("raw/reference.json".to_owned()),
            p99_us: Some(100.0),
            throughput_ops_sec: Some(10.0),
            status: "measured".to_owned(),
            command: String::new(),
            environment_manifest_id: "sha256:old-env".to_owned(),
            artifact_hash: "sha256:reference".to_owned(),
        };
        let payload = measurement_follow_up_payload(
            "bd-rchk5.5",
            &current,
            Some(&reference),
            PerformanceDeltaClassification::Regression,
            Some(100.0),
            Some(-50.0),
            &base_config(),
        );
        assert_eq!(payload.workload_id, "mount_cold");
        assert_eq!(payload.command_template, current.command);
        assert_eq!(payload.profile, "release-perf");
        assert_eq!(payload.environment_manifest_id, "sha256:env");
        assert_eq!(payload.baseline_artifact_hash, "sha256:reference");
        assert_eq!(payload.current_artifact_hash, "sha256:current");
        assert!((payload.observed_value - 100.0).abs() < f64::EPSILON);
        assert!((payload.threshold_value - 50.0).abs() < f64::EPSILON);
        assert_eq!(payload.unit, "p99_delta_percent");
        assert_eq!(payload.suspected_subsystem, "mount");
        assert!(payload.raw_logs.contains(&"raw/current.json".to_owned()));
        assert_eq!(payload.validation_command, current.command);
    }

    #[test]
    fn report_suppresses_duplicate_follow_up_payloads() {
        let payload = PerformanceFollowUpPayload {
            follow_up_bead: "bd-rchk5.5".to_owned(),
            classification: PerformanceDeltaClassification::Regression,
            workload_id: "mount_cold".to_owned(),
            command_template: "cargo bench".to_owned(),
            profile: "release-perf".to_owned(),
            environment_manifest_id: "sha256:env".to_owned(),
            baseline_artifact_hash: "sha256:base".to_owned(),
            current_artifact_hash: "sha256:current".to_owned(),
            observed_value: 100.0,
            threshold_value: 50.0,
            unit: "p99_delta_percent".to_owned(),
            suspected_subsystem: "mount".to_owned(),
            raw_logs: vec!["raw.json".to_owned()],
            validation_command: "cargo bench".to_owned(),
        };
        let row = PerformanceDeltaRow {
            row_id: "comparison:mount_cold".to_owned(),
            row_kind: "comparison".to_owned(),
            operation: "mount_cold".to_owned(),
            source_artifact: "comparison.json".to_owned(),
            reference_artifact: None,
            current_source_json: None,
            reference_p99_us: Some(10.0),
            current_p99_us: Some(20.0),
            p99_delta_percent: Some(100.0),
            reference_throughput_ops_sec: None,
            current_throughput_ops_sec: None,
            throughput_delta_percent: None,
            classification: PerformanceDeltaClassification::Regression,
            release_claim_state: "unknown".to_owned(),
            follow_up_bead: Some("bd-rchk5.5".to_owned()),
            follow_up_present: true,
            follow_up_payload: Some(payload),
            raw_logs: vec!["raw.json".to_owned()],
            comparison_target_rationale: None,
            release_wording: None,
            validation_command: Some("cargo bench".to_owned()),
            rationale: "slow".to_owned(),
            reproduction_command: "cargo bench".to_owned(),
        };
        assert_eq!(deduplicate_follow_up_payloads(&[row.clone(), row]).len(), 1);
    }
}
