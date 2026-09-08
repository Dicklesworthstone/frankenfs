#![allow(
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

//! Repair confidence and mutation-safety gate for `bd-rchk0.5.3.1`.
//!
//! This module keeps automatic repair conservative: every scenario is classified
//! as detection-only, dry-run-ready, mutation-allowed, unsafe-to-repair, or
//! verification-failed from explicit thresholds and evidence fields.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const REPAIR_CONFIDENCE_LAB_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_REPAIR_CONFIDENCE_LAB_PATH: &str = "docs/repair-confidence-mutation-safety.json";

const REQUIRED_LOG_FIELDS: [&str; 13] = [
    "scenario_id",
    "corruption_class",
    "evidence_ledger_state",
    "repair_symbol_budget",
    "candidate_repair_plan",
    "threshold_id",
    "confidence_score",
    "threshold_decision",
    "mutation_decision",
    "pre_image_hash",
    "post_image_hash",
    "verification_verdict",
    "reproduction_command",
];

const REQUIRED_DOC_CLAIMS: [&str; 3] = [
    "automatic_mutating_repair",
    "detection_only_scrub",
    "unsupported_corruption_class",
];

const REQUIRED_OUTCOMES: [RepairConfidenceOutcome; 5] = [
    RepairConfidenceOutcome::DetectOnly,
    RepairConfidenceOutcome::DryRunSuccess,
    RepairConfidenceOutcome::MutatingRepairVerified,
    RepairConfidenceOutcome::UnsafeToRepair,
    RepairConfidenceOutcome::FailedVerification,
];

const REQUIRED_CALIBRATION_CLASSES: [&str; 9] = [
    "recoverable_single_block",
    "recoverable_multi_block_within_budget",
    "unrecoverable_beyond_budget",
    "stale_symbols",
    "insufficient_symbols",
    "ledger_tamper",
    "wrong_image_ledger",
    "hostile_path",
    "verification_failure",
];

const REQUIRED_REFUSAL_REASONS: [&str; 6] = [
    "beyond_symbol_budget",
    "stale_symbols",
    "insufficient_symbols",
    "ledger_tamper",
    "wrong_image_ledger",
    "hostile_path",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairConfidenceLabSpec {
    pub schema_version: u32,
    pub lab_id: String,
    pub bead_id: String,
    pub thresholds: Vec<MutationSafetyThreshold>,
    pub scenarios: Vec<RepairConfidenceScenario>,
    pub calibration_corpus: Vec<RepairCalibrationCase>,
    pub required_log_fields: Vec<String>,
    pub release_gate_consumers: Vec<String>,
    pub docs_claims: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MutationSafetyThreshold {
    pub threshold_id: String,
    pub min_confidence_score: f64,
    pub min_symbol_coverage: f64,
    pub min_ledger_integrity: f64,
    pub max_residual_risk: f64,
    pub allows_mutation: bool,
    pub evidence_artifact: String,
    pub experimental: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_bead: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairConfidenceScenario {
    pub scenario_id: String,
    pub title: String,
    pub phase: RepairConfidencePhase,
    pub expected_outcome: RepairConfidenceOutcome,
    pub corruption_class: String,
    pub threshold_id: String,
    pub repair_symbol_budget: RepairSymbolBudget,
    pub confidence_inputs: RepairConfidenceInputs,
    pub candidate_repair_plan: CandidateRepairPlan,
    pub evidence_ledger: RepairEvidenceLedger,
    pub expected_artifacts: Vec<ExpectedRepairArtifact>,
    pub expected_logs: Vec<ExpectedRepairLog>,
    pub public_docs_claim: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairConfidencePhase {
    Detect,
    DryRun,
    Mutate,
    Verify,
    Refuse,
}

impl RepairConfidencePhase {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Detect => "detect",
            Self::DryRun => "dry_run",
            Self::Mutate => "mutate",
            Self::Verify => "verify",
            Self::Refuse => "refuse",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairConfidenceOutcome {
    DetectOnly,
    DryRunSuccess,
    MutatingRepairVerified,
    UnsafeToRepair,
    FailedVerification,
}

impl RepairConfidenceOutcome {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DetectOnly => "detect_only",
            Self::DryRunSuccess => "dry_run_success",
            Self::MutatingRepairVerified => "mutating_repair_verified",
            Self::UnsafeToRepair => "unsafe_to_repair",
            Self::FailedVerification => "failed_verification",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairSymbolBudget {
    pub data_symbols: u32,
    pub repair_symbols_available: u32,
    pub repair_symbols_required: u32,
    pub erasures: u32,
    pub adversarial_mutations: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairConfidenceInputs {
    pub recovered_symbols: u32,
    pub required_symbols: u32,
    pub ledger_integrity_score: f64,
    pub residual_risk: f64,
    pub verification_passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRepairPlan {
    pub plan_id: String,
    pub dry_run_validated: bool,
    pub mutation_requested: bool,
    pub rollback_available: bool,
    pub changed_paths: Vec<String>,
    pub pre_image_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_image_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairEvidenceLedger {
    pub evidence_ledger_state: String,
    pub artifact_hashes: Vec<String>,
    pub ledger_rows: u32,
    pub tamper_detected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedRepairArtifact {
    pub path: String,
    pub kind: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedRepairLog {
    pub marker: String,
    pub required_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairCalibrationCase {
    pub corpus_id: String,
    pub seed: u64,
    pub corruption_class: String,
    pub expected_recoverability: CalibrationRecoverability,
    pub expected_outcome: RepairConfidenceOutcome,
    pub threshold_id: String,
    pub original_image_hash: String,
    pub corrupted_image_hash: String,
    pub corruption_manifest_hash: String,
    pub repair_symbol_budget: RepairSymbolBudget,
    pub decoder_parameters: RepairDecoderParameters,
    pub confidence_inputs: RepairConfidenceInputs,
    pub ledger_expectation: CalibrationLedgerExpectation,
    pub cleanup_status: String,
    pub artifact_path: String,
    pub reproduction_command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationRecoverability {
    Recoverable,
    Refuse,
    VerificationFailure,
}

impl CalibrationRecoverability {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Recoverable => "recoverable",
            Self::Refuse => "refuse",
            Self::VerificationFailure => "verification_failure",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairDecoderParameters {
    pub codec: String,
    pub data_symbols: u32,
    pub repair_symbols: u32,
    pub symbol_size_bytes: u32,
    pub max_decode_iterations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationLedgerExpectation {
    pub ledger_id: String,
    pub expected_rows: u32,
    pub require_image_hash_match: bool,
    pub require_symbol_generation_match: bool,
    pub allow_tamper: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairConfidenceLabReport {
    pub schema_version: u32,
    pub lab_id: String,
    pub bead_id: String,
    pub valid: bool,
    pub scenario_count: usize,
    pub by_outcome: BTreeMap<String, usize>,
    pub by_phase: BTreeMap<String, usize>,
    pub decision_counts: BTreeMap<String, usize>,
    pub mutation_allowed_count: usize,
    pub mutation_refused_count: usize,
    pub calibration_case_count: usize,
    pub calibration_outcome_counts: BTreeMap<String, usize>,
    pub missing_required_calibration_classes: Vec<String>,
    pub missing_required_refusal_reasons: Vec<String>,
    pub missing_required_outcomes: Vec<String>,
    pub missing_required_log_fields: Vec<String>,
    pub missing_docs_claims: Vec<String>,
    pub scenario_reports: Vec<RepairConfidenceScenarioReport>,
    pub calibration_reports: Vec<RepairCalibrationCaseReport>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairConfidenceScenarioReport {
    pub scenario_id: String,
    pub phase: RepairConfidencePhase,
    pub expected_outcome: RepairConfidenceOutcome,
    pub corruption_class: String,
    pub threshold_id: String,
    pub confidence_score: f64,
    pub symbol_coverage: f64,
    pub ledger_integrity: f64,
    pub residual_risk: f64,
    pub threshold_decision: String,
    pub mutation_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
    pub log_line: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairCalibrationCaseReport {
    pub corpus_id: String,
    pub seed: u64,
    pub corruption_class: String,
    pub expected_recoverability: CalibrationRecoverability,
    pub expected_outcome: RepairConfidenceOutcome,
    pub confidence_score: f64,
    pub threshold_decision: String,
    pub observed_outcome: RepairConfidenceOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
    pub ledger_row_ids: String,
    pub artifact_path: String,
    pub log_line: String,
    pub reproduction_command: String,
}

pub fn load_repair_confidence_lab_spec(path: &Path) -> Result<RepairConfidenceLabSpec> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read repair confidence lab {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid repair confidence lab JSON {}", path.display()))
}

#[must_use]
pub fn validate_repair_confidence_lab(spec: &RepairConfidenceLabSpec) -> RepairConfidenceLabReport {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut by_outcome = BTreeMap::<String, usize>::new();
    let mut by_phase = BTreeMap::<String, usize>::new();
    let mut decision_counts = BTreeMap::<String, usize>::new();
    let mut calibration_outcome_counts = BTreeMap::<String, usize>::new();
    let mut scenario_reports = Vec::new();
    let mut calibration_reports = Vec::new();
    let mut mutation_allowed_count = 0usize;
    let mut mutation_refused_count = 0usize;

    validate_header(spec, &mut errors);

    let thresholds = spec
        .thresholds
        .iter()
        .map(|threshold| (threshold.threshold_id.as_str(), threshold))
        .collect::<BTreeMap<_, _>>();

    validate_thresholds(spec, &mut errors);

    let mut observed_outcomes = BTreeSet::new();
    let mut scenario_ids = BTreeMap::<&str, usize>::new();
    let mut observed_calibration_classes = BTreeSet::new();
    let mut observed_refusal_reasons = BTreeSet::new();

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

        let report = evaluate_scenario(scenario, thresholds.get(scenario.threshold_id.as_str()));
        *decision_counts
            .entry(report.threshold_decision.clone())
            .or_default() += 1;
        if report.mutation_allowed {
            mutation_allowed_count += 1;
        } else if scenario.candidate_repair_plan.mutation_requested {
            mutation_refused_count += 1;
        }

        validate_scenario(
            scenario,
            thresholds.get(scenario.threshold_id.as_str()),
            &report,
            spec,
            &mut errors,
            &mut warnings,
        );
        scenario_reports.push(report);
    }

    let mut corpus_ids = BTreeMap::<&str, usize>::new();
    for case in &spec.calibration_corpus {
        *corpus_ids.entry(case.corpus_id.as_str()).or_default() += 1;
        observed_calibration_classes.insert(case.corruption_class.as_str());
        if let Some(refusal_reason) = case.refusal_reason.as_deref() {
            observed_refusal_reasons.insert(refusal_reason);
        }
        let report = evaluate_calibration_case(case, thresholds.get(case.threshold_id.as_str()));
        *calibration_outcome_counts
            .entry(report.observed_outcome.label().to_owned())
            .or_default() += 1;
        validate_calibration_case(
            case,
            thresholds.get(case.threshold_id.as_str()),
            &report,
            &mut errors,
        );
        calibration_reports.push(report);
    }

    for (scenario_id, count) in scenario_ids {
        if count > 1 {
            errors.push(format!("duplicate scenario_id {scenario_id}"));
        }
    }
    for (corpus_id, count) in corpus_ids {
        if count > 1 {
            errors.push(format!("duplicate calibration corpus_id {corpus_id}"));
        }
    }

    let missing_required_outcomes = REQUIRED_OUTCOMES
        .iter()
        .filter(|outcome| !observed_outcomes.contains(outcome))
        .map(|outcome| outcome.label().to_owned())
        .collect::<Vec<_>>();
    if !missing_required_outcomes.is_empty() {
        errors.push(format!(
            "missing required repair confidence outcomes: {}",
            missing_required_outcomes.join(", ")
        ));
    }

    let missing_required_calibration_classes = REQUIRED_CALIBRATION_CLASSES
        .iter()
        .filter(|class| !observed_calibration_classes.contains(**class))
        .map(|class| (*class).to_owned())
        .collect::<Vec<_>>();
    if !missing_required_calibration_classes.is_empty() {
        errors.push(format!(
            "missing required calibration classes: {}",
            missing_required_calibration_classes.join(", ")
        ));
    }

    let missing_required_refusal_reasons = REQUIRED_REFUSAL_REASONS
        .iter()
        .filter(|reason| !observed_refusal_reasons.contains(**reason))
        .map(|reason| (*reason).to_owned())
        .collect::<Vec<_>>();
    if !missing_required_refusal_reasons.is_empty() {
        errors.push(format!(
            "missing required calibration refusal reasons: {}",
            missing_required_refusal_reasons.join(", ")
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
            "missing required repair confidence log fields: {}",
            missing_required_log_fields.join(", ")
        ));
    }

    let docs_claims = spec
        .docs_claims
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let missing_docs_claims = REQUIRED_DOC_CLAIMS
        .iter()
        .filter(|claim| !docs_claims.contains(**claim))
        .map(|claim| (*claim).to_owned())
        .collect::<Vec<_>>();
    if !missing_docs_claims.is_empty() {
        errors.push(format!(
            "missing required repair confidence docs claims: {}",
            missing_docs_claims.join(", ")
        ));
    }

    RepairConfidenceLabReport {
        schema_version: spec.schema_version,
        lab_id: spec.lab_id.clone(),
        bead_id: spec.bead_id.clone(),
        valid: errors.is_empty(),
        scenario_count: spec.scenarios.len(),
        by_outcome,
        by_phase,
        decision_counts,
        mutation_allowed_count,
        mutation_refused_count,
        calibration_case_count: spec.calibration_corpus.len(),
        calibration_outcome_counts,
        missing_required_calibration_classes,
        missing_required_refusal_reasons,
        missing_required_outcomes,
        missing_required_log_fields,
        missing_docs_claims,
        scenario_reports,
        calibration_reports,
        errors,
        warnings,
    }
}

pub fn fail_on_repair_confidence_lab_errors(report: &RepairConfidenceLabReport) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "repair confidence lab validation failed: {}",
            report.errors.join("; ")
        )
    }
}

#[must_use]
pub fn render_repair_confidence_lab_markdown(report: &RepairConfidenceLabReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Repair Confidence Lab Summary");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Lab: `{}`", report.lab_id);
    let _ = writeln!(out, "- Bead: `{}`", report.bead_id);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Scenarios: `{}`", report.scenario_count);
    let _ = writeln!(
        out,
        "- Mutation allowed/refused: `{}` / `{}`",
        report.mutation_allowed_count, report.mutation_refused_count
    );
    let _ = writeln!(out);
    render_counts(&mut out, "Outcome Coverage", &report.by_outcome);
    render_counts(&mut out, "Phase Coverage", &report.by_phase);
    render_counts(&mut out, "Decision Coverage", &report.decision_counts);
    render_counts(
        &mut out,
        "Calibration Outcome Coverage",
        &report.calibration_outcome_counts,
    );
    let _ = writeln!(out, "## Scenario Decisions");
    for scenario in &report.scenario_reports {
        let _ = writeln!(out, "- `{}`", scenario.log_line);
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Calibration Corpus");
    for case in &report.calibration_reports {
        let _ = writeln!(out, "- `{}`", case.log_line);
    }
    out
}

fn validate_header(spec: &RepairConfidenceLabSpec, errors: &mut Vec<String>) {
    if spec.schema_version != REPAIR_CONFIDENCE_LAB_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {REPAIR_CONFIDENCE_LAB_SCHEMA_VERSION}, got {}",
            spec.schema_version
        ));
    }
    validate_nonempty("lab_id", &spec.lab_id, errors);
    validate_nonempty("bead_id", &spec.bead_id, errors);
    validate_nonempty("reproduction_command", &spec.reproduction_command, errors);
    validate_nonempty_vec("required_log_fields", &spec.required_log_fields, errors);
    validate_nonempty_vec(
        "release_gate_consumers",
        &spec.release_gate_consumers,
        errors,
    );
    validate_nonempty_vec("docs_claims", &spec.docs_claims, errors);
    if spec.thresholds.is_empty() {
        errors.push("thresholds must not be empty".to_owned());
    }
    if spec.scenarios.is_empty() {
        errors.push("scenarios must not be empty".to_owned());
    }
    if spec.calibration_corpus.is_empty() {
        errors.push("calibration_corpus must not be empty".to_owned());
    }
}

fn validate_thresholds(spec: &RepairConfidenceLabSpec, errors: &mut Vec<String>) {
    let mut threshold_ids = BTreeMap::<&str, usize>::new();
    for threshold in &spec.thresholds {
        *threshold_ids
            .entry(threshold.threshold_id.as_str())
            .or_default() += 1;
        validate_nonempty("threshold.threshold_id", &threshold.threshold_id, errors);
        validate_ratio(
            "threshold.min_confidence_score",
            threshold.min_confidence_score,
            errors,
        );
        validate_ratio(
            "threshold.min_symbol_coverage",
            threshold.min_symbol_coverage,
            errors,
        );
        validate_ratio(
            "threshold.min_ledger_integrity",
            threshold.min_ledger_integrity,
            errors,
        );
        validate_ratio(
            "threshold.max_residual_risk",
            threshold.max_residual_risk,
            errors,
        );
        if threshold.experimental {
            validate_optional_nonempty(
                "threshold.follow_up_bead",
                threshold.follow_up_bead.as_deref(),
                errors,
            );
        } else {
            validate_nonempty(
                "threshold.evidence_artifact",
                &threshold.evidence_artifact,
                errors,
            );
        }
    }
    for (threshold_id, count) in threshold_ids {
        if count > 1 {
            errors.push(format!("duplicate threshold_id {threshold_id}"));
        }
    }
}

fn validate_scenario(
    scenario: &RepairConfidenceScenario,
    threshold: Option<&&MutationSafetyThreshold>,
    report: &RepairConfidenceScenarioReport,
    spec: &RepairConfidenceLabSpec,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    validate_stable_id("scenario_id", &scenario.scenario_id, errors);
    validate_nonempty("scenario.title", &scenario.title, errors);
    validate_nonempty(
        "scenario.corruption_class",
        &scenario.corruption_class,
        errors,
    );
    validate_nonempty("scenario.threshold_id", &scenario.threshold_id, errors);
    validate_nonempty(
        "scenario.reproduction_command",
        &scenario.reproduction_command,
        errors,
    );
    if threshold.is_none() {
        errors.push(format!(
            "scenario {} references unknown threshold {}",
            scenario.scenario_id, scenario.threshold_id
        ));
    }
    if !spec
        .docs_claims
        .iter()
        .any(|claim| claim == &scenario.public_docs_claim)
    {
        errors.push(format!(
            "scenario {} references unknown docs claim {}",
            scenario.scenario_id, scenario.public_docs_claim
        ));
    }
    validate_artifacts(scenario, errors);
    validate_logs(scenario, errors);
    validate_symbol_budget(scenario, errors);
    validate_confidence_inputs(scenario, errors);
    validate_candidate_plan(scenario, errors);
    validate_ledger(scenario, errors);
    validate_outcome_contract(scenario, report, errors, warnings);
}

fn validate_calibration_case(
    case: &RepairCalibrationCase,
    threshold: Option<&&MutationSafetyThreshold>,
    report: &RepairCalibrationCaseReport,
    errors: &mut Vec<String>,
) {
    validate_stable_id("calibration.corpus_id", &case.corpus_id, errors);
    validate_nonempty(
        "calibration.corruption_class",
        &case.corruption_class,
        errors,
    );
    validate_nonempty("calibration.threshold_id", &case.threshold_id, errors);
    validate_nonempty(
        "calibration.original_image_hash",
        &case.original_image_hash,
        errors,
    );
    validate_nonempty(
        "calibration.corrupted_image_hash",
        &case.corrupted_image_hash,
        errors,
    );
    validate_nonempty(
        "calibration.corruption_manifest_hash",
        &case.corruption_manifest_hash,
        errors,
    );
    validate_nonempty("calibration.cleanup_status", &case.cleanup_status, errors);
    validate_nonempty("calibration.artifact_path", &case.artifact_path, errors);
    validate_nonempty(
        "calibration.reproduction_command",
        &case.reproduction_command,
        errors,
    );
    if threshold.is_none() {
        errors.push(format!(
            "calibration {} references unknown threshold {}",
            case.corpus_id, case.threshold_id
        ));
    }
    validate_calibration_budget(case, errors);
    validate_confidence_input_values(
        &format!("calibration {}", case.corpus_id),
        &case.confidence_inputs,
        errors,
    );
    validate_decoder_parameters(case, errors);
    validate_ledger_expectation(case, errors);
    validate_calibration_outcome(case, report, errors);
}

fn validate_calibration_budget(case: &RepairCalibrationCase, errors: &mut Vec<String>) {
    let budget = &case.repair_symbol_budget;
    if budget.repair_symbols_required == 0 {
        errors.push(format!(
            "calibration {} repair_symbols_required must be positive",
            case.corpus_id
        ));
    }
    if matches!(
        case.expected_recoverability,
        CalibrationRecoverability::Recoverable
    ) && budget.repair_symbols_available < budget.repair_symbols_required
    {
        errors.push(format!(
            "calibration {} recoverable case must have enough symbols",
            case.corpus_id
        ));
    }
}

fn validate_decoder_parameters(case: &RepairCalibrationCase, errors: &mut Vec<String>) {
    let decoder = &case.decoder_parameters;
    validate_nonempty("decoder.codec", &decoder.codec, errors);
    if decoder.data_symbols == 0
        || decoder.repair_symbols == 0
        || decoder.symbol_size_bytes == 0
        || decoder.max_decode_iterations == 0
    {
        errors.push(format!(
            "calibration {} decoder parameters must be positive",
            case.corpus_id
        ));
    }
    if decoder.data_symbols != case.repair_symbol_budget.data_symbols {
        errors.push(format!(
            "calibration {} decoder data_symbols must match repair budget",
            case.corpus_id
        ));
    }
}

fn validate_ledger_expectation(case: &RepairCalibrationCase, errors: &mut Vec<String>) {
    let ledger = &case.ledger_expectation;
    validate_stable_id("ledger.ledger_id", &ledger.ledger_id, errors);
    if ledger.expected_rows == 0 {
        errors.push(format!(
            "calibration {} ledger expectation must require rows",
            case.corpus_id
        ));
    }
    if case.corruption_class == "wrong_image_ledger" && ledger.require_image_hash_match {
        errors.push(format!(
            "calibration {} wrong-image ledger must require mismatch refusal",
            case.corpus_id
        ));
    }
    if case.corruption_class == "ledger_tamper" && !ledger.allow_tamper {
        errors.push(format!(
            "calibration {} ledger tamper case must model tamper evidence",
            case.corpus_id
        ));
    }
}

fn validate_calibration_outcome(
    case: &RepairCalibrationCase,
    report: &RepairCalibrationCaseReport,
    errors: &mut Vec<String>,
) {
    if report.observed_outcome != case.expected_outcome {
        errors.push(format!(
            "calibration {} expected {:?} but observed {:?}",
            case.corpus_id, case.expected_outcome, report.observed_outcome
        ));
    }
    match case.expected_recoverability {
        CalibrationRecoverability::Recoverable => {
            if case.refusal_reason.is_some() {
                errors.push(format!(
                    "calibration {} recoverable case must not declare refusal_reason",
                    case.corpus_id
                ));
            }
        }
        CalibrationRecoverability::Refuse | CalibrationRecoverability::VerificationFailure => {
            validate_optional_nonempty(
                "calibration.refusal_reason",
                case.refusal_reason.as_deref(),
                errors,
            );
            if report.refusal_reason.is_none() {
                errors.push(format!(
                    "calibration {} refused case must report refusal_reason",
                    case.corpus_id
                ));
            }
        }
    }
}

fn validate_outcome_contract(
    scenario: &RepairConfidenceScenario,
    report: &RepairConfidenceScenarioReport,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    match scenario.expected_outcome {
        RepairConfidenceOutcome::DetectOnly => {
            if scenario.candidate_repair_plan.mutation_requested || report.mutation_allowed {
                errors.push(format!(
                    "detect-only scenario {} must not request or allow mutation",
                    scenario.scenario_id
                ));
            }
        }
        RepairConfidenceOutcome::DryRunSuccess => {
            if !scenario.candidate_repair_plan.dry_run_validated {
                errors.push(format!(
                    "dry-run scenario {} must validate the dry-run plan",
                    scenario.scenario_id
                ));
            }
            if scenario.candidate_repair_plan.mutation_requested || report.mutation_allowed {
                errors.push(format!(
                    "dry-run scenario {} must not mutate the image",
                    scenario.scenario_id
                ));
            }
        }
        RepairConfidenceOutcome::MutatingRepairVerified => {
            if !report.mutation_allowed {
                errors.push(format!(
                    "mutating scenario {} was not allowed by thresholds",
                    scenario.scenario_id
                ));
            }
            if scenario
                .candidate_repair_plan
                .post_image_hash
                .as_deref()
                .is_none_or(str::is_empty)
            {
                errors.push(format!(
                    "mutating scenario {} must record post_image_hash",
                    scenario.scenario_id
                ));
            }
        }
        RepairConfidenceOutcome::UnsafeToRepair => {
            if report.mutation_allowed {
                errors.push(format!(
                    "unsafe-to-repair scenario {} allowed mutation",
                    scenario.scenario_id
                ));
            }
            if scenario.evidence_ledger.tamper_detected {
                warnings.push(format!(
                    "unsafe scenario {} records ledger tamper evidence",
                    scenario.scenario_id
                ));
            }
        }
        RepairConfidenceOutcome::FailedVerification => {
            if scenario.confidence_inputs.verification_passed || report.mutation_allowed {
                errors.push(format!(
                    "failed-verification scenario {} must fail verification and refuse mutation",
                    scenario.scenario_id
                ));
            }
        }
    }
}

fn validate_artifacts(scenario: &RepairConfidenceScenario, errors: &mut Vec<String>) {
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
    for artifact in &scenario.expected_artifacts {
        validate_nonempty("artifact.path", &artifact.path, errors);
        validate_nonempty("artifact.kind", &artifact.kind, errors);
    }
}

fn validate_logs(scenario: &RepairConfidenceScenario, errors: &mut Vec<String>) {
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

fn validate_symbol_budget(scenario: &RepairConfidenceScenario, errors: &mut Vec<String>) {
    let budget = &scenario.repair_symbol_budget;
    if budget.repair_symbols_required == 0 {
        errors.push(format!(
            "scenario {} repair_symbols_required must be positive",
            scenario.scenario_id
        ));
    }
    if budget.repair_symbols_available > budget.data_symbols + budget.repair_symbols_required {
        errors.push(format!(
            "scenario {} repair_symbols_available exceeds declared symbol envelope",
            scenario.scenario_id
        ));
    }
}

fn validate_confidence_inputs(scenario: &RepairConfidenceScenario, errors: &mut Vec<String>) {
    let inputs = &scenario.confidence_inputs;
    validate_confidence_input_values(&scenario.scenario_id, inputs, errors);
}

fn validate_confidence_input_values(
    owner: &str,
    inputs: &RepairConfidenceInputs,
    errors: &mut Vec<String>,
) {
    if inputs.required_symbols == 0 {
        errors.push(format!("{owner} required_symbols must be positive"));
    }
    validate_ratio(
        "confidence_inputs.ledger_integrity_score",
        inputs.ledger_integrity_score,
        errors,
    );
    validate_ratio(
        "confidence_inputs.residual_risk",
        inputs.residual_risk,
        errors,
    );
}

fn validate_candidate_plan(scenario: &RepairConfidenceScenario, errors: &mut Vec<String>) {
    let plan = &scenario.candidate_repair_plan;
    validate_stable_id("plan_id", &plan.plan_id, errors);
    validate_nonempty("plan.pre_image_hash", &plan.pre_image_hash, errors);
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
    }
    if matches!(
        scenario.expected_outcome,
        RepairConfidenceOutcome::MutatingRepairVerified
    ) {
        validate_nonempty_vec("plan.changed_paths", &plan.changed_paths, errors);
        if plan.post_image_hash.as_deref() == Some(plan.pre_image_hash.as_str()) {
            errors.push(format!(
                "scenario {} mutating repair must change the image hash",
                scenario.scenario_id
            ));
        }
    }
}

fn validate_ledger(scenario: &RepairConfidenceScenario, errors: &mut Vec<String>) {
    let ledger = &scenario.evidence_ledger;
    validate_nonempty(
        "ledger.evidence_ledger_state",
        &ledger.evidence_ledger_state,
        errors,
    );
    validate_nonempty_vec("ledger.artifact_hashes", &ledger.artifact_hashes, errors);
    if ledger.ledger_rows == 0 {
        errors.push(format!(
            "scenario {} evidence ledger must include at least one row",
            scenario.scenario_id
        ));
    }
    if ledger.tamper_detected
        && !matches!(
            scenario.expected_outcome,
            RepairConfidenceOutcome::UnsafeToRepair | RepairConfidenceOutcome::FailedVerification
        )
    {
        errors.push(format!(
            "scenario {} ledger tamper requires unsafe/refused outcome",
            scenario.scenario_id
        ));
    }
}

#[must_use]
fn evaluate_scenario(
    scenario: &RepairConfidenceScenario,
    threshold: Option<&&MutationSafetyThreshold>,
) -> RepairConfidenceScenarioReport {
    let symbol_coverage = ratio(
        scenario.repair_symbol_budget.repair_symbols_available,
        scenario.repair_symbol_budget.repair_symbols_required,
    );
    let recovery_ratio = ratio(
        scenario.confidence_inputs.recovered_symbols,
        scenario.confidence_inputs.required_symbols,
    );
    let verification_score = if scenario.confidence_inputs.verification_passed {
        1.0
    } else {
        0.0
    };
    let confidence_score = recovery_ratio
        .min(symbol_coverage)
        .min(scenario.confidence_inputs.ledger_integrity_score)
        .min(1.0 - scenario.confidence_inputs.residual_risk)
        .min(verification_score);
    let ledger_integrity = scenario.confidence_inputs.ledger_integrity_score;
    let residual_risk = scenario.confidence_inputs.residual_risk;

    let (threshold_decision, mutation_allowed, refusal_reason) = threshold.map_or_else(
        || {
            (
                "missing_threshold".to_owned(),
                false,
                Some("threshold_missing".to_owned()),
            )
        },
        |threshold| {
            decide_with_threshold(
                scenario,
                threshold,
                confidence_score,
                symbol_coverage,
                ledger_integrity,
                residual_risk,
            )
        },
    );

    let log_line = format!(
        "REPAIR_CONFIDENCE_DECISION|scenario_id={}|outcome={}|phase={}|corruption_class={}|threshold_id={}|confidence_score={:.4}|threshold_decision={}|mutation_allowed={}|refusal_reason={}|reproduction_command={}",
        scenario.scenario_id,
        scenario.expected_outcome.label(),
        scenario.phase.label(),
        scenario.corruption_class,
        scenario.threshold_id,
        confidence_score,
        threshold_decision,
        mutation_allowed,
        refusal_reason.as_deref().unwrap_or("none"),
        scenario.reproduction_command
    );

    RepairConfidenceScenarioReport {
        scenario_id: scenario.scenario_id.clone(),
        phase: scenario.phase,
        expected_outcome: scenario.expected_outcome,
        corruption_class: scenario.corruption_class.clone(),
        threshold_id: scenario.threshold_id.clone(),
        confidence_score,
        symbol_coverage,
        ledger_integrity,
        residual_risk,
        threshold_decision,
        mutation_allowed,
        refusal_reason,
        log_line,
        reproduction_command: scenario.reproduction_command.clone(),
    }
}

#[must_use]
fn evaluate_calibration_case(
    case: &RepairCalibrationCase,
    threshold: Option<&&MutationSafetyThreshold>,
) -> RepairCalibrationCaseReport {
    let symbol_coverage = ratio(
        case.repair_symbol_budget.repair_symbols_available,
        case.repair_symbol_budget.repair_symbols_required,
    );
    let recovery_ratio = ratio(
        case.confidence_inputs.recovered_symbols,
        case.confidence_inputs.required_symbols,
    );
    let verification_score = if case.confidence_inputs.verification_passed {
        1.0
    } else {
        0.0
    };
    let confidence_score = recovery_ratio
        .min(symbol_coverage)
        .min(case.confidence_inputs.ledger_integrity_score)
        .min(1.0 - case.confidence_inputs.residual_risk)
        .min(verification_score);

    let passes_threshold = threshold.is_some_and(|threshold| {
        confidence_score >= threshold.min_confidence_score
            && symbol_coverage >= threshold.min_symbol_coverage
            && case.confidence_inputs.ledger_integrity_score >= threshold.min_ledger_integrity
            && case.confidence_inputs.residual_risk <= threshold.max_residual_risk
    });

    let (observed_outcome, threshold_decision, refusal_reason) = match case.expected_recoverability
    {
        CalibrationRecoverability::Recoverable if passes_threshold => {
            if threshold.is_some_and(|threshold| threshold.allows_mutation) {
                (
                    RepairConfidenceOutcome::MutatingRepairVerified,
                    "calibration_mutation_ready".to_owned(),
                    None,
                )
            } else {
                (
                    RepairConfidenceOutcome::DryRunSuccess,
                    "calibration_dry_run_ready".to_owned(),
                    None,
                )
            }
        }
        CalibrationRecoverability::Recoverable => (
            RepairConfidenceOutcome::UnsafeToRepair,
            "calibration_threshold_failed".to_owned(),
            Some("threshold_failed".to_owned()),
        ),
        CalibrationRecoverability::Refuse => (
            RepairConfidenceOutcome::UnsafeToRepair,
            "calibration_refused".to_owned(),
            case.refusal_reason.clone(),
        ),
        CalibrationRecoverability::VerificationFailure => (
            RepairConfidenceOutcome::FailedVerification,
            "calibration_verification_failed".to_owned(),
            case.refusal_reason.clone(),
        ),
    };

    let ledger_row_ids = (1..=case.ledger_expectation.expected_rows)
        .map(|row| format!("{}:{row}", case.ledger_expectation.ledger_id))
        .collect::<Vec<_>>()
        .join(",");
    let log_line = format!(
        "REPAIR_CONFIDENCE_CALIBRATION|corpus_id={}|seed={}|corruption_class={}|expected_recoverability={}|expected_outcome={}|observed_outcome={}|confidence_score={:.4}|threshold_decision={}|refusal_reason={}|ledger_row_ids={}|artifact_path={}|cleanup_status={}|reproduction_command={}",
        case.corpus_id,
        case.seed,
        case.corruption_class,
        case.expected_recoverability.label(),
        case.expected_outcome.label(),
        observed_outcome.label(),
        confidence_score,
        threshold_decision,
        refusal_reason.as_deref().unwrap_or("none"),
        ledger_row_ids,
        case.artifact_path,
        case.cleanup_status,
        case.reproduction_command
    );

    RepairCalibrationCaseReport {
        corpus_id: case.corpus_id.clone(),
        seed: case.seed,
        corruption_class: case.corruption_class.clone(),
        expected_recoverability: case.expected_recoverability,
        expected_outcome: case.expected_outcome,
        confidence_score,
        threshold_decision,
        observed_outcome,
        refusal_reason,
        ledger_row_ids,
        artifact_path: case.artifact_path.clone(),
        log_line,
        reproduction_command: case.reproduction_command.clone(),
    }
}

fn decide_with_threshold(
    scenario: &RepairConfidenceScenario,
    threshold: &MutationSafetyThreshold,
    confidence_score: f64,
    symbol_coverage: f64,
    ledger_integrity: f64,
    residual_risk: f64,
) -> (String, bool, Option<String>) {
    let passes_threshold = confidence_score >= threshold.min_confidence_score
        && symbol_coverage >= threshold.min_symbol_coverage
        && ledger_integrity >= threshold.min_ledger_integrity
        && residual_risk <= threshold.max_residual_risk
        && !scenario.evidence_ledger.tamper_detected
        && scenario.candidate_repair_plan.dry_run_validated;

    match scenario.expected_outcome {
        RepairConfidenceOutcome::DetectOnly => (
            "detection_only".to_owned(),
            false,
            Some("detect_only".to_owned()),
        ),
        RepairConfidenceOutcome::DryRunSuccess => {
            if passes_threshold {
                (
                    "dry_run_ready".to_owned(),
                    false,
                    Some("dry_run_only".to_owned()),
                )
            } else {
                (
                    "dry_run_threshold_failed".to_owned(),
                    false,
                    Some("threshold_failed".to_owned()),
                )
            }
        }
        RepairConfidenceOutcome::MutatingRepairVerified => {
            let plan = &scenario.candidate_repair_plan;
            let may_mutate = passes_threshold
                && threshold.allows_mutation
                && plan.mutation_requested
                && plan.rollback_available
                && plan.post_image_hash.is_some()
                && scenario.confidence_inputs.verification_passed;
            if may_mutate {
                ("mutate_allowed".to_owned(), true, None)
            } else {
                (
                    "mutate_refused".to_owned(),
                    false,
                    Some("mutation_precondition_failed".to_owned()),
                )
            }
        }
        RepairConfidenceOutcome::UnsafeToRepair => (
            "unsafe_refused".to_owned(),
            false,
            Some("unsafe_to_repair".to_owned()),
        ),
        RepairConfidenceOutcome::FailedVerification => (
            "verification_failed_refused".to_owned(),
            false,
            Some("verification_failed".to_owned()),
        ),
    }
}

fn render_counts(out: &mut String, title: &str, counts: &BTreeMap<String, usize>) {
    let _ = writeln!(out, "## {title}");
    for (key, count) in counts {
        let _ = writeln!(out, "- `{key}`: `{count}`");
    }
    let _ = writeln!(out);
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

fn validate_stable_id(field: &str, value: &str, errors: &mut Vec<String>) {
    validate_nonempty(field, value, errors);
    let valid = value.split('_').all(|segment| !segment.is_empty())
        && value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_');
    if !valid {
        errors.push(format!("{field} {value} must be lowercase snake-case"));
    }
}

#[must_use]
fn ratio(numerator: u32, denominator: u32) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        (f64::from(numerator) / f64::from(denominator)).min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECKED_IN_SPEC_JSON: &str =
        include_str!("../../../docs/repair-confidence-mutation-safety.json");

    fn checked_in_spec() -> Result<RepairConfidenceLabSpec> {
        serde_json::from_str(CHECKED_IN_SPEC_JSON)
            .context("checked-in repair confidence lab is valid JSON")
    }

    fn report_for(mut spec: RepairConfidenceLabSpec) -> RepairConfidenceLabReport {
        spec.lab_id = "test_repair_confidence_lab".to_owned();
        validate_repair_confidence_lab(&spec)
    }

    fn calibration_report<'a>(
        reports: &BTreeMap<&str, &'a RepairCalibrationCaseReport>,
        corpus_id: &str,
    ) -> Result<&'a RepairCalibrationCaseReport> {
        reports
            .get(corpus_id)
            .copied()
            .with_context(|| format!("fixture includes calibration case {corpus_id}"))
    }

    fn calibration_case_mut<'a>(
        spec: &'a mut RepairConfidenceLabSpec,
        corpus_id: &str,
    ) -> Result<&'a mut RepairCalibrationCase> {
        spec.calibration_corpus
            .iter_mut()
            .find(|case| case.corpus_id == corpus_id)
            .with_context(|| format!("fixture includes calibration case {corpus_id}"))
    }

    fn scenario_with_outcome_mut(
        spec: &mut RepairConfidenceLabSpec,
        outcome: RepairConfidenceOutcome,
    ) -> Result<&mut RepairConfidenceScenario> {
        spec.scenarios
            .iter_mut()
            .find(|scenario| scenario.expected_outcome == outcome)
            .with_context(|| format!("fixture includes {outcome:?} repair scenario"))
    }

    fn first_scenario_mut(
        spec: &mut RepairConfidenceLabSpec,
    ) -> Result<&mut RepairConfidenceScenario> {
        spec.scenarios
            .first_mut()
            .context("fixture includes at least one repair confidence scenario")
    }

    fn first_threshold_mut(
        spec: &mut RepairConfidenceLabSpec,
    ) -> Result<&mut MutationSafetyThreshold> {
        spec.thresholds
            .first_mut()
            .context("fixture includes at least one mutation safety threshold")
    }

    #[test]
    fn checked_in_lab_validates_required_contract() -> Result<()> {
        let spec = checked_in_spec()?;
        let report = validate_repair_confidence_lab(&spec);
        assert!(report.valid, "{:#?}", report.errors);
        assert_eq!(report.scenario_count, 5);
        assert_eq!(report.calibration_case_count, 9);
        assert!(report.mutation_allowed_count >= 1);
        assert!(report.mutation_refused_count >= 2);
        assert_eq!(report.missing_required_outcomes, [] as [String; 0]);
        assert_eq!(
            report.missing_required_calibration_classes,
            [] as [String; 0]
        );
        assert_eq!(report.missing_required_refusal_reasons, [] as [String; 0]);
        assert_eq!(report.missing_required_log_fields, [] as [String; 0]);
        Ok(())
    }

    #[test]
    fn render_repair_confidence_lab_markdown_checked_in_spec_snapshot() -> Result<()> {
        let spec = checked_in_spec()?;
        let report = validate_repair_confidence_lab(&spec);
        assert!(report.valid, "{:#?}", report.errors);
        assert_eq!(report.scenario_count, 5);
        assert_eq!(report.calibration_case_count, 9);
        assert_eq!(report.mutation_allowed_count, 1);
        assert_eq!(report.mutation_refused_count, 2);

        let markdown = render_repair_confidence_lab_markdown(&report);
        insta::assert_snapshot!(
            "render_repair_confidence_lab_markdown_checked_in_spec",
            markdown
        );
        Ok(())
    }

    #[test]
    fn repair_confidence_lab_report_json_shape() -> Result<()> {
        let spec = checked_in_spec()?;
        let report = validate_repair_confidence_lab(&spec);
        assert!(report.valid, "{:#?}", report.errors);

        let full_json = serde_json::to_string_pretty(&report)?;
        let parsed: RepairConfidenceLabReport = serde_json::from_str(&full_json)?;
        assert_eq!(parsed, report);

        let expected_scenario_log_keys = report
            .scenario_reports
            .first()
            .map(|scenario| log_line_keys(&scenario.log_line))
            .unwrap_or_default();
        for scenario in &report.scenario_reports {
            assert_eq!(
                log_line_keys(&scenario.log_line),
                expected_scenario_log_keys
            );
        }

        let expected_calibration_log_keys = report
            .calibration_reports
            .first()
            .map(|case| log_line_keys(&case.log_line))
            .unwrap_or_default();
        for case in &report.calibration_reports {
            assert_eq!(log_line_keys(&case.log_line), expected_calibration_log_keys);
        }

        let scenario_rows = report
            .scenario_reports
            .iter()
            .map(|scenario| {
                serde_json::json!({
                    "scenario_id": &scenario.scenario_id,
                    "phase": scenario.phase.label(),
                    "expected_outcome": scenario.expected_outcome.label(),
                    "corruption_class": &scenario.corruption_class,
                    "threshold_id": &scenario.threshold_id,
                    "confidence_score": scenario.confidence_score,
                    "symbol_coverage": scenario.symbol_coverage,
                    "ledger_integrity": scenario.ledger_integrity,
                    "residual_risk": scenario.residual_risk,
                    "threshold_decision": &scenario.threshold_decision,
                    "mutation_allowed": scenario.mutation_allowed,
                    "refusal_reason": &scenario.refusal_reason,
                    "reproduction_command": &scenario.reproduction_command,
                })
            })
            .collect::<Vec<_>>();

        let calibration_rows = report
            .calibration_reports
            .iter()
            .map(|case| {
                serde_json::json!({
                    "corpus_id": &case.corpus_id,
                    "seed": case.seed,
                    "corruption_class": &case.corruption_class,
                    "expected_recoverability": case.expected_recoverability.label(),
                    "expected_outcome": case.expected_outcome.label(),
                    "observed_outcome": case.observed_outcome.label(),
                    "confidence_score": case.confidence_score,
                    "threshold_decision": &case.threshold_decision,
                    "refusal_reason": &case.refusal_reason,
                    "ledger_row_ids": &case.ledger_row_ids,
                    "artifact_path": &case.artifact_path,
                    "reproduction_command": &case.reproduction_command,
                })
            })
            .collect::<Vec<_>>();

        let shape = serde_json::json!({
            "schema_version": report.schema_version,
            "lab_id": &report.lab_id,
            "bead_id": &report.bead_id,
            "valid": report.valid,
            "scenario_count": report.scenario_count,
            "by_outcome": &report.by_outcome,
            "by_phase": &report.by_phase,
            "decision_counts": &report.decision_counts,
            "mutation_allowed_count": report.mutation_allowed_count,
            "mutation_refused_count": report.mutation_refused_count,
            "calibration_case_count": report.calibration_case_count,
            "calibration_outcome_counts": &report.calibration_outcome_counts,
            "missing_required_calibration_classes": &report.missing_required_calibration_classes,
            "missing_required_refusal_reasons": &report.missing_required_refusal_reasons,
            "missing_required_outcomes": &report.missing_required_outcomes,
            "missing_required_log_fields": &report.missing_required_log_fields,
            "missing_docs_claims": &report.missing_docs_claims,
            "scenario_log_line_keys": expected_scenario_log_keys,
            "calibration_log_line_keys": expected_calibration_log_keys,
            "scenario_reports": scenario_rows,
            "calibration_reports": calibration_rows,
            "errors": &report.errors,
            "warnings": &report.warnings,
        });
        insta::assert_snapshot!(
            "repair_confidence_lab_report_json_shape",
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

    #[test]
    fn calibration_corpus_covers_recovery_refusal_and_verification() -> Result<()> {
        let spec = checked_in_spec()?;
        let report = validate_repair_confidence_lab(&spec);
        let reports = report
            .calibration_reports
            .iter()
            .map(|case| (case.corpus_id.as_str(), case))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(
            calibration_report(&reports, "cal_recoverable_single_block")?.observed_outcome,
            RepairConfidenceOutcome::DryRunSuccess
        );
        assert_eq!(
            calibration_report(&reports, "cal_recoverable_multi_block")?.observed_outcome,
            RepairConfidenceOutcome::MutatingRepairVerified
        );
        assert_eq!(
            calibration_report(&reports, "cal_unrecoverable_beyond_budget")?
                .refusal_reason
                .as_deref(),
            Some("beyond_symbol_budget")
        );
        assert_eq!(
            calibration_report(&reports, "cal_wrong_image_ledger")?
                .refusal_reason
                .as_deref(),
            Some("wrong_image_ledger")
        );
        assert_eq!(
            calibration_report(&reports, "cal_verification_failure")?.observed_outcome,
            RepairConfidenceOutcome::FailedVerification
        );
        assert!(reports.values().all(|case| {
            case.log_line.contains("REPAIR_CONFIDENCE_CALIBRATION")
                && case.log_line.contains("ledger_row_ids=")
                && case.log_line.contains("reproduction_command=")
        }));
        Ok(())
    }

    #[test]
    fn calibration_rejects_missing_required_class_and_refusal_reason() -> Result<()> {
        let mut spec = checked_in_spec()?;
        spec.calibration_corpus
            .retain(|case| case.corruption_class != "wrong_image_ledger");
        let report = report_for(spec);
        assert!(!report.valid);
        assert!(
            report
                .missing_required_calibration_classes
                .contains(&"wrong_image_ledger".to_owned())
        );
        assert!(
            report
                .missing_required_refusal_reasons
                .contains(&"wrong_image_ledger".to_owned())
        );
        Ok(())
    }

    #[test]
    fn calibration_rejects_bad_decoder_and_ledger_expectation() -> Result<()> {
        let mut spec = checked_in_spec()?;
        let case = calibration_case_mut(&mut spec, "cal_wrong_image_ledger")?;
        case.decoder_parameters.data_symbols = 99;
        case.ledger_expectation.require_image_hash_match = true;
        let report = report_for(spec);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("decoder data_symbols"))
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("wrong-image ledger"))
        );
        Ok(())
    }

    #[test]
    fn mutating_repair_requires_verified_thresholds() -> Result<()> {
        let mut spec = checked_in_spec()?;
        let scenario =
            scenario_with_outcome_mut(&mut spec, RepairConfidenceOutcome::MutatingRepairVerified)?;
        scenario.confidence_inputs.verification_passed = false;
        let report = report_for(spec);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("was not allowed by thresholds"))
        );
        Ok(())
    }

    #[test]
    fn dry_run_scenario_cannot_request_mutation() -> Result<()> {
        let mut spec = checked_in_spec()?;
        let scenario =
            scenario_with_outcome_mut(&mut spec, RepairConfidenceOutcome::DryRunSuccess)?;
        scenario.candidate_repair_plan.mutation_requested = true;
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
    fn unknown_threshold_is_rejected() -> Result<()> {
        let mut spec = checked_in_spec()?;
        first_scenario_mut(&mut spec)?.threshold_id = "missing_threshold".to_owned();
        let report = report_for(spec);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("references unknown threshold"))
        );
        Ok(())
    }

    #[test]
    fn experimental_threshold_requires_follow_up() -> Result<()> {
        let mut spec = checked_in_spec()?;
        let threshold = first_threshold_mut(&mut spec)?;
        threshold.experimental = true;
        threshold.follow_up_bead = None;
        let report = report_for(spec);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("threshold.follow_up_bead"))
        );
        Ok(())
    }

    #[test]
    fn missing_log_field_is_rejected() -> Result<()> {
        let mut spec = checked_in_spec()?;
        spec.required_log_fields
            .retain(|field| field != "verification_verdict");
        let report = report_for(spec);
        assert!(!report.valid);
        assert!(
            report
                .missing_required_log_fields
                .contains(&"verification_verdict".to_owned())
        );
        Ok(())
    }

    #[test]
    fn ledger_tamper_requires_refusal_outcome() -> Result<()> {
        let mut spec = checked_in_spec()?;
        first_scenario_mut(&mut spec)?
            .evidence_ledger
            .tamper_detected = true;
        let report = report_for(spec);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("ledger tamper requires unsafe/refused outcome"))
        );
        Ok(())
    }
}
