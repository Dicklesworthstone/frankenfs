#![allow(
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

//! Operator recovery drill contract for `bd-rchk0.5.8`.
//!
//! Repair confidence is necessary but not sufficient. This module validates the
//! operator-facing workflow that turns corruption evidence into a safe decision:
//! detect, dry-run, optionally mutate, verify, and preserve rollback/refusal
//! evidence that a proof bundle can carry forward.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const OPERATOR_RECOVERY_DRILL_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_OPERATOR_RECOVERY_DRILL_PATH: &str = "docs/operator-recovery-drill.json";

const REQUIRED_LOG_FIELDS: [&str; 10] = [
    "exact_commands",
    "image_hashes",
    "corruption_manifest",
    "confidence_threshold",
    "repair_plan",
    "operator_warnings",
    "post_repair_verification",
    "rollback_or_refusal_outcome",
    "cleanup_status",
    "reproduction_command",
];

const REQUIRED_OUTCOMES: [OperatorRecoveryOutcome; 4] = [
    OperatorRecoveryOutcome::DetectionOnly,
    OperatorRecoveryOutcome::DryRunSuccess,
    OperatorRecoveryOutcome::MutatingRepairVerified,
    OperatorRecoveryOutcome::UnsafeRefused,
];

const REQUIRED_CONSUMERS: [&str; 3] = [
    "proof_bundle",
    "release_gate",
    "operational_readiness_report",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorRecoveryDrillSpec {
    pub schema_version: u32,
    pub drill_id: String,
    pub bead_id: String,
    pub proof_bundle_lane: String,
    pub release_gate_consumers: Vec<String>,
    pub required_log_fields: Vec<String>,
    pub scenarios: Vec<OperatorRecoveryScenario>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorRecoveryScenario {
    pub scenario_id: String,
    pub title: String,
    pub phase: OperatorRecoveryPhase,
    pub expected_outcome: OperatorRecoveryOutcome,
    pub preflight_checks: Vec<OperatorPreflightCheck>,
    pub commands: Vec<OperatorCommand>,
    pub image_hashes: OperatorImageHashes,
    pub corruption_manifest: CorruptionManifestRef,
    pub confidence_threshold: ConfidenceThresholdRef,
    pub repair_plan: OperatorRepairPlan,
    pub operator_warnings: Vec<String>,
    pub verification: OperatorVerificationSummary,
    pub rollback: OperatorRollbackSummary,
    pub expected_artifacts: Vec<OperatorRecoveryArtifact>,
    pub expected_logs: Vec<OperatorRecoveryLog>,
    pub cleanup: OperatorCleanupSummary,
    pub proof_bundle_lane: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRecoveryPhase {
    Detect,
    DryRun,
    Mutate,
    Refuse,
}

impl OperatorRecoveryPhase {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Detect => "detect",
            Self::DryRun => "dry_run",
            Self::Mutate => "mutate",
            Self::Refuse => "refuse",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRecoveryOutcome {
    DetectionOnly,
    DryRunSuccess,
    MutatingRepairVerified,
    UnsafeRefused,
}

impl OperatorRecoveryOutcome {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DetectionOnly => "detection_only",
            Self::DryRunSuccess => "dry_run_success",
            Self::MutatingRepairVerified => "mutating_repair_verified",
            Self::UnsafeRefused => "unsafe_refused",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorPreflightCheck {
    pub check_id: String,
    pub description: String,
    pub passed: bool,
    pub blocks_mutation: bool,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorCommand {
    pub command_id: String,
    pub command: String,
    pub purpose: String,
    pub side_effect: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorImageHashes {
    pub original_image_hash: String,
    pub pre_repair_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_repair_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorruptionManifestRef {
    pub manifest_id: String,
    pub path: String,
    pub sha256: String,
    pub corruption_class: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceThresholdRef {
    pub threshold_id: String,
    pub confidence_score: f64,
    pub residual_risk: f64,
    pub mutation_allowed_by_threshold: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorRepairPlan {
    pub plan_id: String,
    pub dry_run_validated: bool,
    pub mutation_requested: bool,
    pub rollback_available: bool,
    pub operator_approval_required: bool,
    pub plan_steps: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorVerificationSummary {
    pub verification_id: String,
    pub status: String,
    pub post_repair_scrub_clean: bool,
    pub reopened_image: bool,
    pub summary_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorRollbackSummary {
    pub rollback_available: bool,
    pub rollback_artifact: String,
    pub rollback_or_refusal_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorRecoveryArtifact {
    pub path: String,
    pub kind: String,
    pub required: bool,
    pub consumers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorRecoveryLog {
    pub marker: String,
    pub required_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorCleanupSummary {
    pub cleanup_status: String,
    pub temp_paths_removed: bool,
    pub mount_unmounted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorRecoveryDrillReport {
    pub schema_version: u32,
    pub drill_id: String,
    pub bead_id: String,
    pub proof_bundle_lane: String,
    pub valid: bool,
    pub scenario_count: usize,
    pub by_outcome: BTreeMap<String, usize>,
    pub by_phase: BTreeMap<String, usize>,
    pub mutation_allowed_count: usize,
    pub mutation_refused_count: usize,
    pub missing_required_outcomes: Vec<String>,
    pub missing_required_log_fields: Vec<String>,
    pub missing_required_consumers: Vec<String>,
    pub scenario_reports: Vec<OperatorRecoveryScenarioReport>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorRecoveryScenarioReport {
    pub scenario_id: String,
    pub phase: OperatorRecoveryPhase,
    pub expected_outcome: OperatorRecoveryOutcome,
    pub drill_decision: String,
    pub mutation_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
    pub proof_bundle_lane: String,
    pub artifact_paths: Vec<String>,
    pub log_line: String,
    pub reproduction_command: String,
}

pub fn load_operator_recovery_drill_spec(path: &Path) -> Result<OperatorRecoveryDrillSpec> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read operator recovery drill {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid operator recovery drill JSON {}", path.display()))
}

#[must_use]
pub fn validate_operator_recovery_drill(
    spec: &OperatorRecoveryDrillSpec,
) -> OperatorRecoveryDrillReport {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut by_outcome = BTreeMap::<String, usize>::new();
    let mut by_phase = BTreeMap::<String, usize>::new();
    let mut scenario_reports = Vec::new();
    let mut mutation_allowed_count = 0usize;
    let mut mutation_refused_count = 0usize;

    validate_header(spec, &mut errors);

    let mut observed_outcomes = BTreeSet::new();
    let mut scenario_ids = BTreeMap::<&str, usize>::new();

    for scenario in &spec.scenarios {
        *scenario_ids
            .entry(scenario.scenario_id.as_str())
            .or_default() += 1;
        *by_outcome
            .entry(scenario.expected_outcome.label().to_owned())
            .or_default() += 1;
        *by_phase
            .entry(scenario.phase.label().to_owned())
            .or_default() += 1;
        observed_outcomes.insert(scenario.expected_outcome);

        let report = evaluate_scenario(scenario);
        if report.mutation_allowed {
            mutation_allowed_count += 1;
        } else if scenario.repair_plan.mutation_requested {
            mutation_refused_count += 1;
        }

        validate_scenario(scenario, spec, &report, &mut errors, &mut warnings);
        scenario_reports.push(report);
    }

    for (scenario_id, count) in scenario_ids {
        if count > 1 {
            errors.push(format!("duplicate scenario_id {scenario_id}"));
        }
    }

    let missing_required_outcomes = REQUIRED_OUTCOMES
        .iter()
        .filter(|outcome| !observed_outcomes.contains(outcome))
        .map(|outcome| outcome.label().to_owned())
        .collect::<Vec<_>>();
    if !missing_required_outcomes.is_empty() {
        errors.push(format!(
            "missing required operator recovery outcomes: {}",
            missing_required_outcomes.join(", ")
        ));
    }

    let log_fields = spec
        .required_log_fields
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let missing_required_log_fields = REQUIRED_LOG_FIELDS
        .iter()
        .filter(|field| !log_fields.contains(**field))
        .map(|field| (*field).to_owned())
        .collect::<Vec<_>>();
    if !missing_required_log_fields.is_empty() {
        errors.push(format!(
            "missing required operator recovery log fields: {}",
            missing_required_log_fields.join(", ")
        ));
    }

    let consumers = spec
        .release_gate_consumers
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let missing_required_consumers = REQUIRED_CONSUMERS
        .iter()
        .filter(|consumer| !consumers.contains(**consumer))
        .map(|consumer| (*consumer).to_owned())
        .collect::<Vec<_>>();
    if !missing_required_consumers.is_empty() {
        errors.push(format!(
            "missing required operator recovery consumers: {}",
            missing_required_consumers.join(", ")
        ));
    }

    OperatorRecoveryDrillReport {
        schema_version: spec.schema_version,
        drill_id: spec.drill_id.clone(),
        bead_id: spec.bead_id.clone(),
        proof_bundle_lane: spec.proof_bundle_lane.clone(),
        valid: errors.is_empty(),
        scenario_count: spec.scenarios.len(),
        by_outcome,
        by_phase,
        mutation_allowed_count,
        mutation_refused_count,
        missing_required_outcomes,
        missing_required_log_fields,
        missing_required_consumers,
        scenario_reports,
        errors,
        warnings,
    }
}

pub fn fail_on_operator_recovery_drill_errors(report: &OperatorRecoveryDrillReport) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "operator recovery drill validation failed: {}",
            report.errors.join("; ")
        )
    }
}

#[must_use]
pub fn render_operator_recovery_drill_markdown(report: &OperatorRecoveryDrillReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Operator Recovery Drill Summary");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Drill: `{}`", report.drill_id);
    let _ = writeln!(out, "- Bead: `{}`", report.bead_id);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Proof bundle lane: `{}`", report.proof_bundle_lane);
    let _ = writeln!(out, "- Scenarios: `{}`", report.scenario_count);
    let _ = writeln!(
        out,
        "- Mutation allowed/refused: `{}` / `{}`",
        report.mutation_allowed_count, report.mutation_refused_count
    );
    let _ = writeln!(out);
    render_counts(&mut out, "Outcome Coverage", &report.by_outcome);
    render_counts(&mut out, "Phase Coverage", &report.by_phase);
    let _ = writeln!(out, "## Drill Decisions");
    for scenario in &report.scenario_reports {
        let _ = writeln!(out, "- `{}`", scenario.log_line);
    }
    out
}

fn validate_header(spec: &OperatorRecoveryDrillSpec, errors: &mut Vec<String>) {
    if spec
        .schema_version
        .ne(&OPERATOR_RECOVERY_DRILL_SCHEMA_VERSION)
    {
        errors.push(format!(
            "schema_version must be {OPERATOR_RECOVERY_DRILL_SCHEMA_VERSION}, got {}",
            spec.schema_version
        ));
    }
    validate_stable_id("drill_id", &spec.drill_id, errors);
    validate_nonempty("bead_id", &spec.bead_id, errors);
    validate_stable_id("proof_bundle_lane", &spec.proof_bundle_lane, errors);
    validate_nonempty_vec(
        "release_gate_consumers",
        &spec.release_gate_consumers,
        errors,
    );
    validate_nonempty_vec("required_log_fields", &spec.required_log_fields, errors);
    validate_nonempty("reproduction_command", &spec.reproduction_command, errors);
    if spec.scenarios.is_empty() {
        errors.push("scenarios must not be empty".to_owned());
    }
}

fn validate_scenario(
    scenario: &OperatorRecoveryScenario,
    spec: &OperatorRecoveryDrillSpec,
    report: &OperatorRecoveryScenarioReport,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    validate_stable_id("scenario_id", &scenario.scenario_id, errors);
    validate_nonempty("scenario.title", &scenario.title, errors);
    validate_nonempty(
        "scenario.reproduction_command",
        &scenario.reproduction_command,
        errors,
    );
    if scenario.proof_bundle_lane.ne(&spec.proof_bundle_lane) {
        errors.push(format!(
            "scenario {} proof_bundle_lane {} does not match spec lane {}",
            scenario.scenario_id, scenario.proof_bundle_lane, spec.proof_bundle_lane
        ));
    }
    validate_preflight(scenario, report, errors);
    validate_commands(scenario, errors);
    validate_image_hashes(scenario, errors);
    validate_manifest(scenario, errors);
    validate_threshold(scenario, errors);
    validate_plan(scenario, errors);
    validate_verification(scenario, errors);
    validate_rollback(scenario, errors);
    validate_artifacts(scenario, errors);
    validate_logs(scenario, errors);
    validate_cleanup(scenario, errors);
    validate_outcome_contract(scenario, report, errors, warnings);
}

fn validate_preflight(
    scenario: &OperatorRecoveryScenario,
    report: &OperatorRecoveryScenarioReport,
    errors: &mut Vec<String>,
) {
    if scenario.preflight_checks.is_empty() {
        errors.push(format!(
            "scenario {} must declare preflight checks",
            scenario.scenario_id
        ));
    }
    let blocks_mutation = scenario
        .preflight_checks
        .iter()
        .any(|check| !check.passed && check.blocks_mutation);
    if blocks_mutation && report.mutation_allowed {
        errors.push(format!(
            "scenario {} allowed mutation despite blocking preflight failure",
            scenario.scenario_id
        ));
    }
    if blocks_mutation
        && scenario
            .expected_outcome
            .ne(&OperatorRecoveryOutcome::UnsafeRefused)
    {
        errors.push(format!(
            "scenario {} blocking preflight failure must produce unsafe_refused",
            scenario.scenario_id
        ));
    }
    for check in &scenario.preflight_checks {
        validate_stable_id("preflight.check_id", &check.check_id, errors);
        validate_nonempty("preflight.description", &check.description, errors);
        validate_nonempty("preflight.remediation", &check.remediation, errors);
    }
}

fn validate_commands(scenario: &OperatorRecoveryScenario, errors: &mut Vec<String>) {
    if scenario.commands.is_empty() {
        errors.push(format!(
            "scenario {} must preserve exact commands",
            scenario.scenario_id
        ));
    }
    for command in &scenario.commands {
        validate_stable_id("command.command_id", &command.command_id, errors);
        validate_nonempty("command.command", &command.command, errors);
        validate_nonempty("command.purpose", &command.purpose, errors);
        validate_one_of(
            "command.side_effect",
            &command.side_effect,
            &["read_only", "dry_run", "mutating", "verification"],
            errors,
        );
    }
}

fn validate_image_hashes(scenario: &OperatorRecoveryScenario, errors: &mut Vec<String>) {
    validate_hash(
        "image_hashes.original_image_hash",
        &scenario.image_hashes.original_image_hash,
        errors,
    );
    validate_hash(
        "image_hashes.pre_repair_hash",
        &scenario.image_hashes.pre_repair_hash,
        errors,
    );
    if let Some(hash) = &scenario.image_hashes.post_repair_hash {
        validate_hash("image_hashes.post_repair_hash", hash, errors);
    }
}

fn validate_manifest(scenario: &OperatorRecoveryScenario, errors: &mut Vec<String>) {
    validate_stable_id(
        "corruption_manifest.manifest_id",
        &scenario.corruption_manifest.manifest_id,
        errors,
    );
    validate_nonempty(
        "corruption_manifest.path",
        &scenario.corruption_manifest.path,
        errors,
    );
    validate_hash(
        "corruption_manifest.sha256",
        &scenario.corruption_manifest.sha256,
        errors,
    );
    validate_nonempty(
        "corruption_manifest.corruption_class",
        &scenario.corruption_manifest.corruption_class,
        errors,
    );
}

fn validate_threshold(scenario: &OperatorRecoveryScenario, errors: &mut Vec<String>) {
    validate_nonempty(
        "confidence_threshold.threshold_id",
        &scenario.confidence_threshold.threshold_id,
        errors,
    );
    validate_ratio(
        "confidence_threshold.confidence_score",
        scenario.confidence_threshold.confidence_score,
        errors,
    );
    validate_ratio(
        "confidence_threshold.residual_risk",
        scenario.confidence_threshold.residual_risk,
        errors,
    );
}

fn validate_plan(scenario: &OperatorRecoveryScenario, errors: &mut Vec<String>) {
    let plan = &scenario.repair_plan;
    validate_stable_id("repair_plan.plan_id", &plan.plan_id, errors);
    validate_nonempty_vec("repair_plan.plan_steps", &plan.plan_steps, errors);
    if plan.mutation_requested {
        if !plan.dry_run_validated {
            errors.push(format!(
                "scenario {} mutation request must follow a validated dry run",
                scenario.scenario_id
            ));
        }
        if !plan.rollback_available {
            errors.push(format!(
                "scenario {} mutation request must declare rollback availability",
                scenario.scenario_id
            ));
        }
        if !plan.operator_approval_required {
            errors.push(format!(
                "scenario {} mutation request must require operator approval",
                scenario.scenario_id
            ));
        }
    }
    if scenario
        .expected_outcome
        .eq(&OperatorRecoveryOutcome::UnsafeRefused)
    {
        validate_optional_nonempty(
            "repair_plan.refusal_reason",
            plan.refusal_reason.as_deref(),
            errors,
        );
    }
}

fn validate_verification(scenario: &OperatorRecoveryScenario, errors: &mut Vec<String>) {
    let verification = &scenario.verification;
    validate_stable_id(
        "verification.verification_id",
        &verification.verification_id,
        errors,
    );
    validate_one_of(
        "verification.status",
        &verification.status,
        &["not_run", "dry_run_verified", "passed", "failed", "refused"],
        errors,
    );
    validate_nonempty(
        "verification.summary_path",
        &verification.summary_path,
        errors,
    );
}

fn validate_rollback(scenario: &OperatorRecoveryScenario, errors: &mut Vec<String>) {
    let rollback = &scenario.rollback;
    validate_nonempty(
        "rollback.rollback_or_refusal_outcome",
        &rollback.rollback_or_refusal_outcome,
        errors,
    );
    if rollback.rollback_available {
        validate_nonempty(
            "rollback.rollback_artifact",
            &rollback.rollback_artifact,
            errors,
        );
    }
}

fn validate_artifacts(scenario: &OperatorRecoveryScenario, errors: &mut Vec<String>) {
    if scenario.expected_artifacts.is_empty() {
        errors.push(format!(
            "scenario {} must declare expected artifacts",
            scenario.scenario_id
        ));
    }
    if !scenario
        .expected_artifacts
        .iter()
        .any(|artifact| artifact.required)
    {
        errors.push(format!(
            "scenario {} must have at least one required artifact",
            scenario.scenario_id
        ));
    }
    if !scenario.expected_artifacts.iter().any(|artifact| {
        artifact
            .consumers
            .iter()
            .any(|consumer| consumer.as_str().eq("proof_bundle"))
    }) {
        errors.push(format!(
            "scenario {} must feed a proof_bundle artifact consumer",
            scenario.scenario_id
        ));
    }
    for artifact in &scenario.expected_artifacts {
        validate_nonempty("artifact.path", &artifact.path, errors);
        validate_nonempty("artifact.kind", &artifact.kind, errors);
        validate_nonempty_vec("artifact.consumers", &artifact.consumers, errors);
    }
}

fn validate_logs(scenario: &OperatorRecoveryScenario, errors: &mut Vec<String>) {
    if scenario.expected_logs.is_empty() {
        errors.push(format!(
            "scenario {} must declare expected logs",
            scenario.scenario_id
        ));
    }
    let fields = scenario
        .expected_logs
        .iter()
        .flat_map(|log| log.required_fields.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    for required in REQUIRED_LOG_FIELDS {
        if !fields.contains(required) {
            errors.push(format!(
                "scenario {} logs missing required field {required}",
                scenario.scenario_id
            ));
        }
    }
    for log in &scenario.expected_logs {
        validate_nonempty("log.marker", &log.marker, errors);
        validate_nonempty_vec("log.required_fields", &log.required_fields, errors);
    }
}

fn validate_cleanup(scenario: &OperatorRecoveryScenario, errors: &mut Vec<String>) {
    validate_one_of(
        "cleanup.cleanup_status",
        &scenario.cleanup.cleanup_status,
        &["complete", "not_required", "refused_before_mutation"],
        errors,
    );
}

fn validate_outcome_contract(
    scenario: &OperatorRecoveryScenario,
    report: &OperatorRecoveryScenarioReport,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    match scenario.expected_outcome {
        OperatorRecoveryOutcome::DetectionOnly => {
            if scenario.repair_plan.mutation_requested || report.mutation_allowed {
                errors.push(format!(
                    "detection-only scenario {} must not request or allow mutation",
                    scenario.scenario_id
                ));
            }
            if scenario.image_hashes.post_repair_hash.is_some() {
                warnings.push(format!(
                    "detection-only scenario {} records a post-repair hash",
                    scenario.scenario_id
                ));
            }
        }
        OperatorRecoveryOutcome::DryRunSuccess => {
            if !scenario.repair_plan.dry_run_validated {
                errors.push(format!(
                    "dry-run scenario {} must validate the repair plan",
                    scenario.scenario_id
                ));
            }
            if scenario.repair_plan.mutation_requested || report.mutation_allowed {
                errors.push(format!(
                    "dry-run scenario {} must not mutate the image",
                    scenario.scenario_id
                ));
            }
            if scenario.verification.status.as_str().ne("dry_run_verified") {
                errors.push(format!(
                    "dry-run scenario {} must emit dry_run_verified verification",
                    scenario.scenario_id
                ));
            }
        }
        OperatorRecoveryOutcome::MutatingRepairVerified => {
            if !report.mutation_allowed {
                errors.push(format!(
                    "mutating scenario {} was not allowed by the drill",
                    scenario.scenario_id
                ));
            }
            let Some(post_hash) = scenario.image_hashes.post_repair_hash.as_deref() else {
                errors.push(format!(
                    "mutating scenario {} must record post_repair_hash",
                    scenario.scenario_id
                ));
                return;
            };
            if post_hash.eq(scenario.image_hashes.pre_repair_hash.as_str()) {
                errors.push(format!(
                    "mutating scenario {} must change post_repair_hash",
                    scenario.scenario_id
                ));
            }
            if scenario.verification.status.as_str().ne("passed")
                || !scenario.verification.post_repair_scrub_clean
                || !scenario.verification.reopened_image
            {
                errors.push(format!(
                    "mutating scenario {} must pass post-repair verification",
                    scenario.scenario_id
                ));
            }
        }
        OperatorRecoveryOutcome::UnsafeRefused => {
            if report.mutation_allowed {
                errors.push(format!(
                    "unsafe-refused scenario {} allowed mutation",
                    scenario.scenario_id
                ));
            }
            if !scenario
                .rollback
                .rollback_or_refusal_outcome
                .contains("refused")
            {
                errors.push(format!(
                    "unsafe-refused scenario {} must record refusal outcome",
                    scenario.scenario_id
                ));
            }
        }
    }
}

#[must_use]
fn evaluate_scenario(scenario: &OperatorRecoveryScenario) -> OperatorRecoveryScenarioReport {
    let blocking_preflight_failure = scenario
        .preflight_checks
        .iter()
        .any(|check| !check.passed && check.blocks_mutation);
    let threshold = &scenario.confidence_threshold;
    let plan = &scenario.repair_plan;
    let verification = &scenario.verification;
    let mut refusal_reason = None;

    let mutation_allowed = scenario
        .expected_outcome
        .eq(&OperatorRecoveryOutcome::MutatingRepairVerified)
        && !blocking_preflight_failure
        && threshold.mutation_allowed_by_threshold
        && threshold.confidence_score >= 0.95
        && threshold.residual_risk <= 0.02
        && plan.mutation_requested
        && plan.dry_run_validated
        && plan.rollback_available
        && plan.operator_approval_required
        && verification.status.as_str().eq("passed")
        && verification.post_repair_scrub_clean
        && verification.reopened_image
        && scenario.image_hashes.post_repair_hash.is_some();

    let drill_decision = if mutation_allowed {
        "mutate_allowed"
    } else if blocking_preflight_failure {
        refusal_reason = Some("blocking_preflight_failed".to_owned());
        "preflight_failed_refused"
    } else {
        match scenario.expected_outcome {
            OperatorRecoveryOutcome::DetectionOnly => {
                refusal_reason = Some("detection_only".to_owned());
                "detection_only"
            }
            OperatorRecoveryOutcome::DryRunSuccess => {
                refusal_reason = Some("dry_run_only".to_owned());
                "dry_run_ready"
            }
            OperatorRecoveryOutcome::MutatingRepairVerified => {
                refusal_reason = Some("mutation_precondition_failed".to_owned());
                "mutation_refused"
            }
            OperatorRecoveryOutcome::UnsafeRefused => {
                refusal_reason = scenario
                    .repair_plan
                    .refusal_reason
                    .clone()
                    .or_else(|| Some("unsafe_to_repair".to_owned()));
                "unsafe_refused"
            }
        }
    }
    .to_owned();

    let artifact_paths = scenario
        .expected_artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();
    let exact_commands = scenario
        .commands
        .iter()
        .map(|command| command.command.as_str())
        .collect::<Vec<_>>()
        .join(";;");
    let image_hashes = format!(
        "original={},pre={},post={}",
        scenario.image_hashes.original_image_hash,
        scenario.image_hashes.pre_repair_hash,
        scenario
            .image_hashes
            .post_repair_hash
            .as_deref()
            .unwrap_or("none")
    );
    let command_count = scenario.commands.len();
    let log_line = format!(
        "OPERATOR_RECOVERY_DRILL|scenario_id={}|outcome={}|phase={}|drill_decision={}|mutation_allowed={}|confidence_threshold={}|confidence_score={:.4}|residual_risk={:.4}|command_count={}|exact_commands={}|image_hashes={}|pre_image_hash={}|post_image_hash={}|corruption_manifest={}|repair_plan={}|operator_warnings={}|post_repair_verification={}|rollback_or_refusal_outcome={}|cleanup_status={}|proof_bundle_lane={}|refusal_reason={}|reproduction_command={}",
        scenario.scenario_id,
        scenario.expected_outcome.label(),
        scenario.phase.label(),
        drill_decision,
        mutation_allowed,
        threshold.threshold_id,
        threshold.confidence_score,
        threshold.residual_risk,
        command_count,
        exact_commands,
        image_hashes,
        scenario.image_hashes.pre_repair_hash,
        scenario
            .image_hashes
            .post_repair_hash
            .as_deref()
            .unwrap_or("none"),
        scenario.corruption_manifest.path,
        scenario.repair_plan.plan_id,
        scenario.operator_warnings.len(),
        scenario.verification.status,
        scenario.rollback.rollback_or_refusal_outcome,
        scenario.cleanup.cleanup_status,
        scenario.proof_bundle_lane,
        refusal_reason.as_deref().unwrap_or("none"),
        scenario.reproduction_command
    );

    OperatorRecoveryScenarioReport {
        scenario_id: scenario.scenario_id.clone(),
        phase: scenario.phase,
        expected_outcome: scenario.expected_outcome,
        drill_decision,
        mutation_allowed,
        refusal_reason,
        proof_bundle_lane: scenario.proof_bundle_lane.clone(),
        artifact_paths,
        log_line,
        reproduction_command: scenario.reproduction_command.clone(),
    }
}

fn render_counts(out: &mut String, title: &str, counts: &BTreeMap<String, usize>) {
    let _ = writeln!(out, "## {title}");
    for (key, count) in counts {
        let _ = writeln!(out, "- `{key}`: `{count}`");
    }
    let _ = writeln!(out);
}

fn validate_hash(field: &str, value: &str, errors: &mut Vec<String>) {
    validate_nonempty(field, value, errors);
    if !is_sha256_digest(value) {
        errors.push(format!("{field} must be sha256:<64-hex>"));
    }
}

fn is_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len().eq(&64) && hex.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn validate_nonempty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
}

fn validate_optional_nonempty(field: &str, value: Option<&str>, errors: &mut Vec<String>) {
    if value.is_none_or(|raw| raw.trim().is_empty()) {
        errors.push(format!("{field} must not be empty"));
    }
}

fn validate_nonempty_vec(field: &str, values: &[String], errors: &mut Vec<String>) {
    if values.is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
    for value in values {
        if value.trim().is_empty() {
            errors.push(format!("{field} must not contain empty values"));
        }
    }
}

fn validate_ratio(field: &str, value: f64, errors: &mut Vec<String>) {
    if !(0.0..=1.0).contains(&value) {
        errors.push(format!("{field} must be between 0.0 and 1.0"));
    }
}

fn validate_one_of(field: &str, value: &str, allowed: &[&str], errors: &mut Vec<String>) {
    if !allowed.contains(&value) {
        errors.push(format!(
            "{field} must be one of {}, got {value}",
            allowed.join(", ")
        ));
    }
}

fn validate_stable_id(field: &str, value: &str, errors: &mut Vec<String>) {
    validate_nonempty(field, value, errors);
    let valid = value.split('_').all(|segment| !segment.is_empty())
        && value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch.eq(&'_'));
    if !valid {
        errors.push(format!("{field} {value} must be lowercase snake-case"));
    }
}

/// Mutation precondition gate for the operator repair workflow.
///
/// Tracks bd-x63b9: ensures no irreversible image mutation runs until preflight
/// freshness, artifact schema, image hash agreement, rollback artifact, operator
/// confirmation, confidence threshold, and backup-strategy guidance all agree.
/// Each refusal carries a stable reason code so release gates and remediation
/// catalog entries can fail closed without parsing prose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MutationPreconditionGate {
    pub preflight_evaluated_at_unix: u64,
    pub preflight_freshness_ttl_seconds: u64,
    pub now_unix: u64,
    pub artifact_schema_version: u32,
    pub expected_artifact_schema_version: u32,
    pub planned_image_hash: String,
    pub current_image_hash: String,
    pub operator_confirmation_hash: String,
    pub rollback_artifact_path: String,
    pub rollback_artifact_present: bool,
    pub backup_strategy: String,
    pub confidence_score: f64,
    pub min_confidence_for_mutation: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum MutationPreconditionDecision {
    Allow,
    Refuse { reason: String, remediation: String },
}

const ALLOWED_BACKUP_STRATEGIES: [&str; 4] = [
    "snapshot",
    "copy_on_write_image",
    "external_backup_verified",
    "image_clone_verified",
];

#[must_use]
pub fn evaluate_mutation_preconditions(
    gate: &MutationPreconditionGate,
) -> MutationPreconditionDecision {
    if gate.preflight_freshness_ttl_seconds.eq(&0) {
        return refuse(
            "stale_preflight",
            "rerun preflight checks before requesting mutation",
        );
    }
    if gate.preflight_evaluated_at_unix > gate.now_unix {
        return refuse(
            "future_preflight",
            "rerun preflight checks with a non-future evaluation timestamp before mutating",
        );
    }
    let elapsed = gate
        .now_unix
        .saturating_sub(gate.preflight_evaluated_at_unix);
    if elapsed > gate.preflight_freshness_ttl_seconds {
        return refuse(
            "stale_preflight",
            "rerun preflight checks within the freshness window",
        );
    }
    if gate
        .artifact_schema_version
        .ne(&gate.expected_artifact_schema_version)
    {
        return refuse(
            "stale_artifact_schema",
            "regenerate proof artifacts against the current schema before mutating",
        );
    }
    if !is_sha256_digest(&gate.planned_image_hash)
        || !is_sha256_digest(&gate.current_image_hash)
        || !is_sha256_digest(&gate.operator_confirmation_hash)
    {
        return refuse(
            "image_hash_malformed",
            "re-hash the image and rebuild the dry-run plan with sha256:<64-hex> digests",
        );
    }
    if gate.current_image_hash.ne(&gate.planned_image_hash) {
        return refuse(
            "image_hash_drifted",
            "image hash changed since dry-run; rebuild the plan against the current image",
        );
    }
    if !gate.rollback_artifact_present || gate.rollback_artifact_path.trim().is_empty() {
        return refuse(
            "rollback_unavailable",
            "stage a rollback artifact (snapshot, image copy) before mutating",
        );
    }
    if gate.operator_confirmation_hash.ne(&gate.planned_image_hash) {
        return refuse(
            "operator_confirmation_mismatch",
            "operator must confirm the planned image hash before mutating",
        );
    }
    if gate.min_confidence_for_mutation <= 0.0 {
        return refuse(
            "low_confidence",
            "configure a positive minimum mutation confidence before mutating",
        );
    }
    if gate.confidence_score < gate.min_confidence_for_mutation {
        return refuse(
            "low_confidence",
            "raise repair confidence above the configured threshold or stay in dry-run",
        );
    }
    if gate.backup_strategy.trim().is_empty() || gate.backup_strategy.as_str().eq("none") {
        return refuse(
            "missing_backup",
            "select a backup strategy (snapshot, copy_on_write_image, external backup) before mutating",
        );
    }
    if !ALLOWED_BACKUP_STRATEGIES.contains(&gate.backup_strategy.as_str()) {
        return refuse(
            "unsupported_backup_strategy",
            "use one of: snapshot, copy_on_write_image, external_backup_verified, image_clone_verified",
        );
    }
    MutationPreconditionDecision::Allow
}

fn refuse(reason: &str, remediation: &str) -> MutationPreconditionDecision {
    MutationPreconditionDecision::Refuse {
        reason: reason.to_owned(),
        remediation: remediation.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECKED_IN_SPEC_JSON: &str = include_str!("../../../docs/operator-recovery-drill.json");

    fn checked_in_spec() -> Result<OperatorRecoveryDrillSpec> {
        serde_json::from_str(CHECKED_IN_SPEC_JSON)
            .context("checked-in operator recovery drill is valid JSON")
    }

    fn report_for(mut spec: OperatorRecoveryDrillSpec) -> OperatorRecoveryDrillReport {
        spec.drill_id = "test_operator_recovery_drill".to_owned();
        validate_operator_recovery_drill(&spec)
    }

    fn mutating_scenario_mut(
        spec: &mut OperatorRecoveryDrillSpec,
    ) -> Result<&mut OperatorRecoveryScenario> {
        spec.scenarios
            .iter_mut()
            .find(|scenario| {
                scenario
                    .expected_outcome
                    .eq(&OperatorRecoveryOutcome::MutatingRepairVerified)
            })
            .context("fixture includes mutating scenario")
    }

    fn dry_run_scenario_mut(
        spec: &mut OperatorRecoveryDrillSpec,
    ) -> Result<&mut OperatorRecoveryScenario> {
        spec.scenarios
            .iter_mut()
            .find(|scenario| {
                scenario
                    .expected_outcome
                    .eq(&OperatorRecoveryOutcome::DryRunSuccess)
            })
            .context("fixture includes dry-run scenario")
    }

    #[test]
    fn checked_in_drill_validates_required_contract() -> Result<()> {
        let spec = checked_in_spec()?;
        let report = validate_operator_recovery_drill(&spec);
        assert!(report.valid, "{:#?}", report.errors);
        assert_eq!(report.scenario_count, 4);
        assert_eq!(report.proof_bundle_lane, "operator_recovery_drill");
        assert_eq!(report.mutation_allowed_count, 1);
        assert!(report.mutation_refused_count >= 1);
        assert_eq!(report.missing_required_outcomes, [] as [String; 0]);
        assert_eq!(report.missing_required_log_fields, [] as [String; 0]);
        assert_eq!(report.missing_required_consumers, [] as [String; 0]);
        Ok(())
    }

    #[test]
    fn malformed_image_hash_payloads_are_rejected() -> Result<()> {
        let mut spec = checked_in_spec()?;
        let scenario = mutating_scenario_mut(&mut spec)?;
        scenario.image_hashes.original_image_hash = "sha256:not-a-real-digest".to_owned();
        scenario.image_hashes.pre_repair_hash =
            "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_owned();
        scenario.image_hashes.post_repair_hash = Some("sha256:short".to_owned());
        scenario.corruption_manifest.sha256 = "sha256:also-not-hex".to_owned();

        let report = report_for(spec);

        assert!(!report.valid);
        for expected in [
            "image_hashes.original_image_hash must be sha256:<64-hex>",
            "image_hashes.pre_repair_hash must be sha256:<64-hex>",
            "image_hashes.post_repair_hash must be sha256:<64-hex>",
            "corruption_manifest.sha256 must be sha256:<64-hex>",
        ] {
            assert!(
                report.errors.iter().any(|error| error.contains(expected)),
                "expected {expected} error, got {:#?}",
                report.errors
            );
        }
        Ok(())
    }

    #[test]
    fn mutating_repair_requires_rollback_and_verification() -> Result<()> {
        let mut spec = checked_in_spec()?;
        let scenario = mutating_scenario_mut(&mut spec)?;
        scenario.repair_plan.rollback_available = false;
        scenario.verification.post_repair_scrub_clean = false;
        let report = report_for(spec);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("rollback availability"))
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("post-repair verification"))
        );
        Ok(())
    }

    #[test]
    fn blocking_preflight_failure_cannot_mutate() -> Result<()> {
        let mut spec = checked_in_spec()?;
        let scenario = mutating_scenario_mut(&mut spec)?;
        let preflight = scenario
            .preflight_checks
            .first_mut()
            .context("mutating scenario includes preflight check")?;
        preflight.passed = false;
        let report = report_for(spec);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("blocking preflight failure"))
        );
        Ok(())
    }

    #[test]
    fn dry_run_scenario_cannot_request_mutation() -> Result<()> {
        let mut spec = checked_in_spec()?;
        let scenario = dry_run_scenario_mut(&mut spec)?;
        scenario.repair_plan.mutation_requested = true;
        let report = report_for(spec);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("must not mutate the image"))
        );
        Ok(())
    }

    #[test]
    fn missing_log_field_is_rejected() -> Result<()> {
        let mut spec = checked_in_spec()?;
        spec.required_log_fields
            .retain(|field| field.as_str().ne("rollback_or_refusal_outcome"));
        let report = report_for(spec);
        assert!(!report.valid);
        assert!(
            report
                .missing_required_log_fields
                .contains(&"rollback_or_refusal_outcome".to_owned())
        );
        Ok(())
    }

    #[test]
    fn proof_bundle_consumer_is_required() -> Result<()> {
        let mut spec = checked_in_spec()?;
        let scenario = spec
            .scenarios
            .first_mut()
            .context("fixture includes first scenario")?;
        for artifact in &mut scenario.expected_artifacts {
            artifact
                .consumers
                .retain(|consumer| consumer.as_str().ne("proof_bundle"));
        }
        let report = report_for(spec);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("proof_bundle artifact consumer"))
        );
        Ok(())
    }

    fn happy_gate() -> MutationPreconditionGate {
        MutationPreconditionGate {
            preflight_evaluated_at_unix: 1_000,
            preflight_freshness_ttl_seconds: 600,
            now_unix: 1_300,
            artifact_schema_version: 1,
            expected_artifact_schema_version: 1,
            planned_image_hash:
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            current_image_hash:
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            operator_confirmation_hash:
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            rollback_artifact_path: "artifacts/rollback/<image_hash>.snapshot".to_owned(),
            rollback_artifact_present: true,
            backup_strategy: "snapshot".to_owned(),
            confidence_score: 0.97,
            min_confidence_for_mutation: 0.95,
        }
    }

    fn refusal_reason(decision: &MutationPreconditionDecision) -> Option<&str> {
        if let MutationPreconditionDecision::Refuse { reason, .. } = decision {
            Some(reason.as_str())
        } else {
            None
        }
    }

    #[test]
    fn happy_path_allows_mutation() {
        let decision = evaluate_mutation_preconditions(&happy_gate());
        assert!(matches!(decision, MutationPreconditionDecision::Allow));
    }

    #[test]
    fn stale_preflight_refuses_mutation() {
        let mut gate = happy_gate();
        gate.now_unix = gate.preflight_evaluated_at_unix + gate.preflight_freshness_ttl_seconds + 1;
        let decision = evaluate_mutation_preconditions(&gate);
        assert_eq!(refusal_reason(&decision), Some("stale_preflight"));
    }

    #[test]
    fn future_preflight_refuses_mutation() {
        let mut gate = happy_gate();
        gate.preflight_evaluated_at_unix = gate.now_unix + 1;
        let decision = evaluate_mutation_preconditions(&gate);
        assert_eq!(refusal_reason(&decision), Some("future_preflight"));
    }

    #[test]
    fn zero_ttl_refuses_mutation() {
        let mut gate = happy_gate();
        gate.preflight_freshness_ttl_seconds = 0;
        let decision = evaluate_mutation_preconditions(&gate);
        assert_eq!(refusal_reason(&decision), Some("stale_preflight"));
    }

    #[test]
    fn stale_artifact_schema_refuses_mutation() {
        let mut gate = happy_gate();
        gate.artifact_schema_version = 0;
        let decision = evaluate_mutation_preconditions(&gate);
        assert_eq!(refusal_reason(&decision), Some("stale_artifact_schema"));
    }

    #[test]
    fn newer_artifact_schema_refuses_mutation() {
        let mut gate = happy_gate();
        gate.expected_artifact_schema_version = 2;
        let decision = evaluate_mutation_preconditions(&gate);
        assert_eq!(refusal_reason(&decision), Some("stale_artifact_schema"));
    }

    #[test]
    fn image_hash_drift_refuses_mutation() {
        let mut gate = happy_gate();
        gate.current_image_hash =
            "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_owned();
        let decision = evaluate_mutation_preconditions(&gate);
        assert_eq!(refusal_reason(&decision), Some("image_hash_drifted"));
    }

    #[test]
    fn missing_image_hash_refuses_mutation() {
        let mut gate = happy_gate();
        gate.current_image_hash = String::new();
        let decision = evaluate_mutation_preconditions(&gate);
        assert_eq!(refusal_reason(&decision), Some("image_hash_malformed"));
    }

    #[test]
    fn malformed_image_hash_refuses_mutation() {
        let mut gate = happy_gate();
        gate.planned_image_hash = "sha256:not-a-real-digest".to_owned();
        gate.current_image_hash = gate.planned_image_hash.clone();
        gate.operator_confirmation_hash = gate.planned_image_hash.clone();
        let decision = evaluate_mutation_preconditions(&gate);
        assert_eq!(refusal_reason(&decision), Some("image_hash_malformed"));
    }

    #[test]
    fn rollback_unavailable_refuses_mutation() {
        let mut gate = happy_gate();
        gate.rollback_artifact_present = false;
        let decision = evaluate_mutation_preconditions(&gate);
        assert_eq!(refusal_reason(&decision), Some("rollback_unavailable"));
    }

    #[test]
    fn empty_rollback_path_refuses_mutation() {
        let mut gate = happy_gate();
        gate.rollback_artifact_path = String::new();
        let decision = evaluate_mutation_preconditions(&gate);
        assert_eq!(refusal_reason(&decision), Some("rollback_unavailable"));
    }

    #[test]
    fn operator_confirmation_mismatch_refuses_mutation() {
        let mut gate = happy_gate();
        gate.operator_confirmation_hash =
            "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_owned();
        let decision = evaluate_mutation_preconditions(&gate);
        assert_eq!(
            refusal_reason(&decision),
            Some("operator_confirmation_mismatch")
        );
    }

    #[test]
    fn low_confidence_refuses_mutation() {
        let mut gate = happy_gate();
        gate.confidence_score = 0.5;
        let decision = evaluate_mutation_preconditions(&gate);
        assert_eq!(refusal_reason(&decision), Some("low_confidence"));
    }

    #[test]
    fn zero_min_confidence_refuses_mutation() {
        let mut gate = happy_gate();
        gate.min_confidence_for_mutation = 0.0;
        let decision = evaluate_mutation_preconditions(&gate);
        assert_eq!(refusal_reason(&decision), Some("low_confidence"));
    }

    #[test]
    fn missing_backup_strategy_refuses_mutation() {
        let mut gate = happy_gate();
        gate.backup_strategy = String::new();
        let decision = evaluate_mutation_preconditions(&gate);
        assert_eq!(refusal_reason(&decision), Some("missing_backup"));
    }

    #[test]
    fn none_backup_strategy_refuses_mutation() {
        let mut gate = happy_gate();
        gate.backup_strategy = "none".to_owned();
        let decision = evaluate_mutation_preconditions(&gate);
        assert_eq!(refusal_reason(&decision), Some("missing_backup"));
    }

    #[test]
    fn unsupported_backup_strategy_refuses_mutation() {
        let mut gate = happy_gate();
        gate.backup_strategy = "rsync_to_thumb_drive".to_owned();
        let decision = evaluate_mutation_preconditions(&gate);
        assert_eq!(
            refusal_reason(&decision),
            Some("unsupported_backup_strategy")
        );
    }

    #[test]
    fn allowed_backup_strategies_include_external_backup_verified() {
        let mut gate = happy_gate();
        gate.backup_strategy = "external_backup_verified".to_owned();
        let decision = evaluate_mutation_preconditions(&gate);
        assert!(matches!(decision, MutationPreconditionDecision::Allow));
    }

    /// bd-z57pf — Golden-artifact pin for the operator recovery
    /// drill markdown emitter. The 18+ sibling tests cover validation
    /// logic; this snapshot catches whitespace, heading-level,
    /// ordering, and bullet-format drift in the markdown bytes that
    /// silently breaks downstream proof-bundle / release-gate
    /// dashboard parsers.
    #[test]
    fn render_operator_recovery_drill_markdown_default_sample() -> Result<()> {
        let report = report_for(checked_in_spec()?);
        let markdown = render_operator_recovery_drill_markdown(&report);
        insta::assert_snapshot!(markdown);
        Ok(())
    }

    #[test]
    fn operator_recovery_drill_report_json_shape() -> Result<()> {
        let spec = checked_in_spec()?;
        let report = validate_operator_recovery_drill(&spec);
        let json = serde_json::to_string_pretty(&report)?;
        let parsed: OperatorRecoveryDrillReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);

        let expected_log_line_keys = report
            .scenario_reports
            .first()
            .map(|scenario| log_line_keys(&scenario.log_line))
            .unwrap_or_default();
        for scenario in &report.scenario_reports {
            assert_eq!(log_line_keys(&scenario.log_line), expected_log_line_keys);
        }

        let scenario_rows = report
            .scenario_reports
            .iter()
            .map(|scenario| {
                serde_json::json!({
                    "scenario_id": &scenario.scenario_id,
                    "phase": scenario.phase.label(),
                    "expected_outcome": scenario.expected_outcome.label(),
                    "drill_decision": &scenario.drill_decision,
                    "mutation_allowed": scenario.mutation_allowed,
                    "refusal_reason": &scenario.refusal_reason,
                    "artifact_paths": &scenario.artifact_paths,
                    "proof_bundle_lane": &scenario.proof_bundle_lane,
                    "reproduction_command": &scenario.reproduction_command,
                })
            })
            .collect::<Vec<_>>();

        let shape = serde_json::json!({
            "schema_version": report.schema_version,
            "drill_id": &report.drill_id,
            "bead_id": &report.bead_id,
            "proof_bundle_lane": &report.proof_bundle_lane,
            "valid": report.valid,
            "scenario_count": report.scenario_count,
            "by_outcome": &report.by_outcome,
            "by_phase": &report.by_phase,
            "mutation_allowed_count": report.mutation_allowed_count,
            "mutation_refused_count": report.mutation_refused_count,
            "missing_required_outcomes": &report.missing_required_outcomes,
            "missing_required_log_fields": &report.missing_required_log_fields,
            "missing_required_consumers": &report.missing_required_consumers,
            "log_line_keys": expected_log_line_keys,
            "scenario_reports": scenario_rows,
            "errors": &report.errors,
            "warnings": &report.warnings,
        });
        insta::assert_snapshot!(
            "operator_recovery_drill_report_json_shape",
            serde_json::to_string_pretty(&shape)?
        );
        Ok(())
    }

    fn log_line_keys(line: &str) -> Vec<&str> {
        line.split('|')
            .skip(1)
            .map(|field| field.split_once('=').map_or(field, |(key, _value)| key))
            .collect()
    }
}
