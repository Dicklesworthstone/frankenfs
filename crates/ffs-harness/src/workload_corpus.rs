#![allow(clippy::too_many_lines)]

//! Versioned real-world workload corpus validation for `bd-rchk0.5.7`.
//!
//! The corpus is the shared proof substrate for user-risk scenarios consumed by
//! invariant, mounted differential, repair, crash/replay, proof-bundle, and
//! release-gate workflows.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const WORKLOAD_CORPUS_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_WORKLOAD_CORPUS_PATH: &str = "tests/workload-corpus/p1_workload_corpus.json";

const REQUIRED_SCENARIO_STATUSES: [WorkloadScenarioStatus; 4] = [
    WorkloadScenarioStatus::Positive,
    WorkloadScenarioStatus::Negative,
    WorkloadScenarioStatus::Unsupported,
    WorkloadScenarioStatus::HostSkip,
];

const HIGH_RISK_USER_RISKS: &[&str] = &[
    "data_loss",
    "metadata_incoherence",
    "repair_overclaim",
    "permission_boundary",
];

struct CorpusVocabularies<'a> {
    user_risks: BTreeSet<&'a str>,
    operations: BTreeSet<&'a str>,
    filesystems: BTreeSet<&'a str>,
    capabilities: BTreeSet<&'a str>,
    proof_consumers: BTreeSet<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadCorpus {
    pub schema_version: u32,
    pub corpus_id: String,
    pub corpus_version: String,
    pub bead_id: String,
    pub scenario_id_regex: String,
    pub user_risks: Vec<String>,
    pub operation_classes: Vec<String>,
    pub filesystem_flavors: Vec<String>,
    pub capability_vocabulary: Vec<String>,
    pub proof_consumers: Vec<String>,
    pub scenarios: Vec<WorkloadScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadScenario {
    pub scenario_id: String,
    pub title: String,
    pub status: WorkloadScenarioStatus,
    pub user_risk: String,
    pub operation_class: String,
    pub supported_filesystems: Vec<String>,
    pub required_capabilities: Vec<String>,
    pub expected_artifacts: Vec<ExpectedWorkloadArtifact>,
    pub expected_logs: Vec<ExpectedWorkloadLog>,
    pub linked_proof_consumers: Vec<String>,
    pub linked_e2e_suites: Vec<String>,
    pub reproduction_command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsupported_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_skip_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_bead: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub non_goal_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedWorkloadArtifact {
    pub path: String,
    pub kind: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedWorkloadLog {
    pub marker: String,
    pub required_fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadScenarioStatus {
    Positive,
    Negative,
    Unsupported,
    HostSkip,
}

impl WorkloadScenarioStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::Negative => "negative",
            Self::Unsupported => "unsupported",
            Self::HostSkip => "host_skip",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadCorpusValidationReport {
    pub schema_version: u32,
    pub coverage_matrix_version: u32,
    pub corpus_id: String,
    pub corpus_version: String,
    pub bead_id: String,
    pub valid: bool,
    pub scenario_count: usize,
    pub status_counts: BTreeMap<String, usize>,
    pub by_user_risk: BTreeMap<String, usize>,
    pub by_filesystem_flavor: BTreeMap<String, usize>,
    pub by_proof_consumer: BTreeMap<String, usize>,
    pub proof_bundle_coverage: WorkloadProofBundleCoverage,
    pub coverage_matrix: Vec<WorkloadCoverageMatrixRow>,
    pub duplicate_scenario_ids: Vec<String>,
    pub missing_high_risk_user_risks: Vec<String>,
    pub missing_required_statuses: Vec<String>,
    pub host_skip_scenarios: Vec<String>,
    pub btrfs_default_permissions_scenarios: Vec<String>,
    pub scenario_logs: Vec<WorkloadScenarioLog>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadProofBundleCoverage {
    pub scenario_ids: Vec<String>,
    pub by_user_risk: BTreeMap<String, usize>,
    pub by_filesystem_flavor: BTreeMap<String, usize>,
    pub ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadCoverageMatrixRow {
    pub matrix_version: u32,
    pub claim_id: String,
    pub scenario_id: String,
    pub status: WorkloadScenarioStatus,
    pub user_risk: String,
    pub risk_tier: String,
    pub filesystem_scope: Vec<String>,
    pub operation_class: String,
    pub required_capabilities: Vec<String>,
    pub proof_consumers: Vec<String>,
    pub unit_test_obligations: Vec<String>,
    pub e2e_obligations: Vec<String>,
    pub fuzz_or_soak_obligations: Vec<String>,
    pub expected_log_fields: Vec<String>,
    pub expected_artifact_fields: Vec<String>,
    pub non_applicability_rationale: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadScenarioLog {
    pub scenario_id: String,
    pub status: WorkloadScenarioStatus,
    pub user_risk: String,
    pub filesystem_flavors: Vec<String>,
    pub proof_consumers: Vec<String>,
    pub reproduction_command: String,
    pub log_line: String,
}

pub fn load_workload_corpus(path: &Path) -> Result<WorkloadCorpus> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read workload corpus {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid workload corpus JSON {}", path.display()))
}

#[must_use]
pub fn find_workload_scenario<'a>(
    corpus: &'a WorkloadCorpus,
    scenario_id: &str,
) -> Option<&'a WorkloadScenario> {
    corpus
        .scenarios
        .iter()
        .find(|scenario| scenario.scenario_id == scenario_id)
}

pub fn validate_selected_workload_scenario(
    corpus: &WorkloadCorpus,
    scenario_id: &str,
) -> Result<()> {
    if find_workload_scenario(corpus, scenario_id).is_some() {
        Ok(())
    } else {
        bail!("workload corpus does not contain selected scenario {scenario_id}")
    }
}

#[must_use]
pub fn validate_workload_corpus(corpus: &WorkloadCorpus) -> WorkloadCorpusValidationReport {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut duplicate_scenario_ids = Vec::new();
    let mut scenario_ids = BTreeMap::<&str, usize>::new();
    let mut status_counts = BTreeMap::<String, usize>::new();
    let mut by_user_risk = BTreeMap::<String, usize>::new();
    let mut by_filesystem_flavor = BTreeMap::<String, usize>::new();
    let mut by_proof_consumer = BTreeMap::<String, usize>::new();
    let mut host_skip_scenarios = Vec::new();
    let mut btrfs_default_permissions_scenarios = Vec::new();
    let mut scenario_logs = Vec::new();
    let mut coverage_matrix = Vec::new();

    validate_header(corpus, &mut errors);

    let vocabularies = CorpusVocabularies {
        user_risks: corpus.user_risks.iter().map(String::as_str).collect(),
        operations: corpus
            .operation_classes
            .iter()
            .map(String::as_str)
            .collect(),
        filesystems: corpus
            .filesystem_flavors
            .iter()
            .map(String::as_str)
            .collect(),
        capabilities: corpus
            .capability_vocabulary
            .iter()
            .map(String::as_str)
            .collect(),
        proof_consumers: corpus.proof_consumers.iter().map(String::as_str).collect(),
    };

    for scenario in &corpus.scenarios {
        *scenario_ids
            .entry(scenario.scenario_id.as_str())
            .or_default() += 1;
        *status_counts
            .entry(scenario.status.label().to_owned())
            .or_default() += 1;
        *by_user_risk.entry(scenario.user_risk.clone()).or_default() += 1;
        for filesystem in &scenario.supported_filesystems {
            *by_filesystem_flavor.entry(filesystem.clone()).or_default() += 1;
        }
        for consumer in &scenario.linked_proof_consumers {
            *by_proof_consumer.entry(consumer.clone()).or_default() += 1;
        }
        if scenario.status == WorkloadScenarioStatus::HostSkip {
            host_skip_scenarios.push(scenario.scenario_id.clone());
        }
        if scenario.scenario_id.contains("btrfs_default_permissions")
            || scenario
                .title
                .to_ascii_lowercase()
                .contains("defaultpermissions")
        {
            btrfs_default_permissions_scenarios.push(scenario.scenario_id.clone());
        }
        validate_scenario(scenario, &vocabularies, &mut errors, &mut warnings);
        scenario_logs.push(build_scenario_log(scenario));
        coverage_matrix.push(build_coverage_matrix_row(scenario));
    }

    for (scenario_id, count) in scenario_ids {
        if count > 1 {
            duplicate_scenario_ids.push(scenario_id.to_owned());
        }
    }
    for duplicate in &duplicate_scenario_ids {
        errors.push(format!("duplicate scenario_id {duplicate}"));
    }

    let missing_required_statuses = REQUIRED_SCENARIO_STATUSES
        .iter()
        .filter_map(|status| {
            let label = status.label();
            (!status_counts.contains_key(label)).then(|| label.to_owned())
        })
        .collect::<Vec<_>>();
    for status in &missing_required_statuses {
        errors.push(format!("missing required scenario status {status}"));
    }

    if host_skip_scenarios.is_empty() {
        errors.push("corpus must include at least one host capability skip scenario".to_owned());
    }
    if btrfs_default_permissions_scenarios.is_empty() {
        errors.push(
            "corpus must include a btrfs DefaultPermissions image-ownership diagnostic scenario"
                .to_owned(),
        );
    }

    let missing_high_risk_user_risks = HIGH_RISK_USER_RISKS
        .iter()
        .filter(|risk| !by_user_risk.contains_key(**risk))
        .map(|risk| (*risk).to_owned())
        .collect::<Vec<_>>();
    for risk in &missing_high_risk_user_risks {
        errors.push(format!(
            "high-risk user risk {risk} has no workload scenario"
        ));
    }

    let proof_bundle_coverage = summarize_proof_bundle_coverage(corpus);
    if !proof_bundle_coverage.ready {
        errors.push(
            "proof_bundle consumer must cover at least one user risk and filesystem flavor"
                .to_owned(),
        );
    }

    WorkloadCorpusValidationReport {
        schema_version: corpus.schema_version,
        coverage_matrix_version: WORKLOAD_CORPUS_SCHEMA_VERSION,
        corpus_id: corpus.corpus_id.clone(),
        corpus_version: corpus.corpus_version.clone(),
        bead_id: corpus.bead_id.clone(),
        valid: errors.is_empty(),
        scenario_count: corpus.scenarios.len(),
        status_counts,
        by_user_risk,
        by_filesystem_flavor,
        by_proof_consumer,
        proof_bundle_coverage,
        coverage_matrix,
        duplicate_scenario_ids,
        missing_high_risk_user_risks,
        missing_required_statuses,
        host_skip_scenarios,
        btrfs_default_permissions_scenarios,
        scenario_logs,
        errors,
        warnings,
    }
}

pub fn fail_on_workload_corpus_errors(report: &WorkloadCorpusValidationReport) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    bail!(
        "workload corpus validation failed: {}",
        report.errors.join("; ")
    )
}

#[must_use]
pub fn render_workload_corpus_markdown(report: &WorkloadCorpusValidationReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Workload Corpus Validation");
    let _ = writeln!(out);
    let _ = writeln!(out, "- corpus: `{}`", report.corpus_id);
    let _ = writeln!(out, "- version: `{}`", report.corpus_version);
    let _ = writeln!(out, "- bead: `{}`", report.bead_id);
    let _ = writeln!(out, "- valid: `{}`", report.valid);
    let _ = writeln!(out, "- scenarios: `{}`", report.scenario_count);
    let _ = writeln!(out);
    render_counts(&mut out, "Status Coverage", &report.status_counts);
    render_counts(&mut out, "User Risk Coverage", &report.by_user_risk);
    render_counts(
        &mut out,
        "Filesystem Coverage",
        &report.by_filesystem_flavor,
    );
    render_counts(
        &mut out,
        "Proof Consumer Coverage",
        &report.by_proof_consumer,
    );
    let _ = writeln!(out, "## Coverage Matrix");
    let _ = writeln!(
        out,
        "| Claim | Scenario | Risk | Tier | Filesystems | Operation | Consumers | E2E/Fuzz/Soak |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|---|---|");
    for row in &report.coverage_matrix {
        let consumers = row.proof_consumers.join(", ");
        let filesystems = row.filesystem_scope.join(", ");
        let lanes = row
            .e2e_obligations
            .iter()
            .chain(row.fuzz_or_soak_obligations.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |",
            row.claim_id,
            row.scenario_id,
            row.user_risk,
            row.risk_tier,
            filesystems,
            row.operation_class,
            consumers,
            lanes
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Scenario Logs");
    for log in &report.scenario_logs {
        let _ = writeln!(out, "- `{}`", log.log_line);
    }
    out
}

fn render_counts(out: &mut String, title: &str, counts: &BTreeMap<String, usize>) {
    let _ = writeln!(out, "## {title}");
    for (key, count) in counts {
        let _ = writeln!(out, "- `{key}`: `{count}`");
    }
    let _ = writeln!(out);
}

fn validate_header(corpus: &WorkloadCorpus, errors: &mut Vec<String>) {
    if corpus.schema_version != WORKLOAD_CORPUS_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {WORKLOAD_CORPUS_SCHEMA_VERSION}, got {}",
            corpus.schema_version
        ));
    }
    validate_nonempty("corpus_id", &corpus.corpus_id, errors);
    validate_nonempty("corpus_version", &corpus.corpus_version, errors);
    validate_nonempty("bead_id", &corpus.bead_id, errors);
    validate_nonempty("scenario_id_regex", &corpus.scenario_id_regex, errors);
    validate_nonempty_vec("user_risks", &corpus.user_risks, errors);
    validate_nonempty_vec("operation_classes", &corpus.operation_classes, errors);
    validate_nonempty_vec("filesystem_flavors", &corpus.filesystem_flavors, errors);
    validate_nonempty_vec(
        "capability_vocabulary",
        &corpus.capability_vocabulary,
        errors,
    );
    validate_nonempty_vec("proof_consumers", &corpus.proof_consumers, errors);
    if corpus.scenarios.is_empty() {
        errors.push("scenarios must not be empty".to_owned());
    }
}

fn validate_scenario(
    scenario: &WorkloadScenario,
    vocabularies: &CorpusVocabularies<'_>,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    validate_stable_scenario_id(&scenario.scenario_id, errors);
    validate_nonempty("scenario.title", &scenario.title, errors);
    validate_member(
        "user_risk",
        &scenario.user_risk,
        &vocabularies.user_risks,
        &scenario.scenario_id,
        errors,
    );
    validate_member(
        "operation_class",
        &scenario.operation_class,
        &vocabularies.operations,
        &scenario.scenario_id,
        errors,
    );
    validate_members(
        "supported_filesystems",
        &scenario.supported_filesystems,
        &vocabularies.filesystems,
        &scenario.scenario_id,
        errors,
    );
    validate_members(
        "required_capabilities",
        &scenario.required_capabilities,
        &vocabularies.capabilities,
        &scenario.scenario_id,
        errors,
    );
    validate_members(
        "linked_proof_consumers",
        &scenario.linked_proof_consumers,
        &vocabularies.proof_consumers,
        &scenario.scenario_id,
        errors,
    );
    if scenario.linked_proof_consumers.len() < 2 {
        errors.push(format!(
            "scenario {} must be reusable by at least two proof consumers",
            scenario.scenario_id
        ));
    }
    if is_user_visible_risk(&scenario.user_risk) && scenario.linked_e2e_suites.is_empty() {
        errors.push(format!(
            "scenario {} maps user-visible risk {} without an E2E or long-campaign proof lane",
            scenario.scenario_id, scenario.user_risk
        ));
    }
    validate_artifacts(scenario, errors);
    validate_logs(scenario, errors);
    validate_nonempty(
        "reproduction_command",
        &scenario.reproduction_command,
        errors,
    );
    if scenario.linked_e2e_suites.is_empty() {
        errors.push(format!(
            "scenario {} must link at least one E2E suite",
            scenario.scenario_id
        ));
    }
    validate_status_specific_fields(scenario, errors, warnings);
}

fn validate_stable_scenario_id(scenario_id: &str, errors: &mut Vec<String>) {
    if scenario_id.is_empty() {
        errors.push("scenario_id must not be empty".to_owned());
        return;
    }
    let segments = scenario_id.split('_').collect::<Vec<_>>();
    let valid = segments.len() >= 3
        && scenario_id
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_lowercase())
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        });
    if !valid {
        errors.push(format!(
            "scenario_id {scenario_id} must be lowercase snake-case with at least three segments"
        ));
    }
}

fn validate_artifacts(scenario: &WorkloadScenario, errors: &mut Vec<String>) {
    if scenario.expected_artifacts.is_empty() {
        errors.push(format!(
            "scenario {} must declare expected_artifacts",
            scenario.scenario_id
        ));
    }
    for artifact in &scenario.expected_artifacts {
        validate_nonempty("artifact.path", &artifact.path, errors);
        validate_nonempty("artifact.kind", &artifact.kind, errors);
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
}

fn validate_logs(scenario: &WorkloadScenario, errors: &mut Vec<String>) {
    if scenario.expected_logs.is_empty() {
        errors.push(format!(
            "scenario {} must declare expected_logs",
            scenario.scenario_id
        ));
    }
    for log in &scenario.expected_logs {
        validate_nonempty("log.marker", &log.marker, errors);
        validate_nonempty_vec("log.required_fields", &log.required_fields, errors);
        for required in ["scenario_id", "reproduction_command"] {
            if !log.required_fields.iter().any(|field| field == required) {
                errors.push(format!(
                    "scenario {} log {} missing required field {required}",
                    scenario.scenario_id, log.marker
                ));
            }
        }
    }
}

fn validate_status_specific_fields(
    scenario: &WorkloadScenario,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    match scenario.status {
        WorkloadScenarioStatus::Positive => {
            if scenario.follow_up_bead.is_some() {
                warnings.push(format!(
                    "positive scenario {} carries follow_up_bead",
                    scenario.scenario_id
                ));
            }
        }
        WorkloadScenarioStatus::Negative => {
            require_follow_up_or_non_goal(scenario, errors);
        }
        WorkloadScenarioStatus::Unsupported => {
            validate_optional_nonempty(
                "unsupported_reason",
                scenario.unsupported_reason.as_deref(),
                &scenario.scenario_id,
                errors,
            );
            require_follow_up_or_non_goal(scenario, errors);
        }
        WorkloadScenarioStatus::HostSkip => {
            validate_optional_nonempty(
                "host_skip_reason",
                scenario.host_skip_reason.as_deref(),
                &scenario.scenario_id,
                errors,
            );
            if !scenario
                .required_capabilities
                .iter()
                .any(|capability| capability.contains("fuse") || capability.contains("host"))
            {
                errors.push(format!(
                    "host-skip scenario {} must require a host or FUSE capability",
                    scenario.scenario_id
                ));
            }
        }
    }
}

fn require_follow_up_or_non_goal(scenario: &WorkloadScenario, errors: &mut Vec<String>) {
    let has_follow_up = scenario
        .follow_up_bead
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let has_non_goal = scenario
        .non_goal_reason
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    if !has_follow_up && !has_non_goal {
        errors.push(format!(
            "scenario {} must declare follow_up_bead or non_goal_reason",
            scenario.scenario_id
        ));
    }
}

fn summarize_proof_bundle_coverage(corpus: &WorkloadCorpus) -> WorkloadProofBundleCoverage {
    let mut scenario_ids = Vec::new();
    let mut by_user_risk = BTreeMap::<String, usize>::new();
    let mut by_filesystem_flavor = BTreeMap::<String, usize>::new();

    for scenario in &corpus.scenarios {
        if !scenario
            .linked_proof_consumers
            .iter()
            .any(|consumer| consumer == "proof_bundle")
        {
            continue;
        }
        scenario_ids.push(scenario.scenario_id.clone());
        *by_user_risk.entry(scenario.user_risk.clone()).or_default() += 1;
        for filesystem in &scenario.supported_filesystems {
            *by_filesystem_flavor.entry(filesystem.clone()).or_default() += 1;
        }
    }

    WorkloadProofBundleCoverage {
        ready: !scenario_ids.is_empty()
            && !by_user_risk.is_empty()
            && by_filesystem_flavor.len() >= 2,
        scenario_ids,
        by_user_risk,
        by_filesystem_flavor,
    }
}

fn build_coverage_matrix_row(scenario: &WorkloadScenario) -> WorkloadCoverageMatrixRow {
    let expected_log_fields = scenario
        .expected_logs
        .iter()
        .flat_map(|log| log.required_fields.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let expected_artifact_fields = ["path", "kind", "required"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let fuzz_or_soak_obligations = scenario
        .linked_proof_consumers
        .iter()
        .filter(|consumer| {
            matches!(
                consumer.as_str(),
                "crash_replay_lab" | "repair_lab" | "performance_baseline"
            )
        })
        .cloned()
        .collect::<Vec<_>>();

    WorkloadCoverageMatrixRow {
        matrix_version: WORKLOAD_CORPUS_SCHEMA_VERSION,
        claim_id: format!("claim_{}", scenario.scenario_id),
        scenario_id: scenario.scenario_id.clone(),
        status: scenario.status,
        user_risk: scenario.user_risk.clone(),
        risk_tier: risk_tier(&scenario.user_risk).to_owned(),
        filesystem_scope: scenario.supported_filesystems.clone(),
        operation_class: scenario.operation_class.clone(),
        required_capabilities: scenario.required_capabilities.clone(),
        proof_consumers: scenario.linked_proof_consumers.clone(),
        unit_test_obligations: vec![
            "workload_corpus_schema".to_owned(),
            "coverage_matrix_row".to_owned(),
        ],
        e2e_obligations: scenario.linked_e2e_suites.clone(),
        fuzz_or_soak_obligations,
        expected_log_fields,
        expected_artifact_fields,
        non_applicability_rationale: scenario
            .unsupported_reason
            .clone()
            .or_else(|| scenario.non_goal_reason.clone())
            .or_else(|| scenario.host_skip_reason.clone()),
    }
}

fn is_user_visible_risk(user_risk: &str) -> bool {
    matches!(risk_tier(user_risk), "p1" | "p2")
}

fn risk_tier(user_risk: &str) -> &'static str {
    if HIGH_RISK_USER_RISKS.contains(&user_risk) {
        "p1"
    } else {
        match user_risk {
            "tail_latency" | "unsupported_scope_hidden" | "host_capability_ambiguity" => "p2",
            _ => "p3",
        }
    }
}

fn build_scenario_log(scenario: &WorkloadScenario) -> WorkloadScenarioLog {
    let proof_consumers = scenario.linked_proof_consumers.join(",");
    let filesystem_flavors = scenario.supported_filesystems.join(",");
    let log_line = format!(
        "WORKLOAD_CORPUS_SCENARIO|scenario_id={}|status={}|user_risk={}|filesystems={}|proof_consumers={}|reproduction_command={}",
        scenario.scenario_id,
        scenario.status.label(),
        scenario.user_risk,
        filesystem_flavors,
        proof_consumers,
        scenario.reproduction_command
    );
    WorkloadScenarioLog {
        scenario_id: scenario.scenario_id.clone(),
        status: scenario.status,
        user_risk: scenario.user_risk.clone(),
        filesystem_flavors: scenario.supported_filesystems.clone(),
        proof_consumers: scenario.linked_proof_consumers.clone(),
        reproduction_command: scenario.reproduction_command.clone(),
        log_line,
    }
}

fn validate_nonempty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
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

fn validate_optional_nonempty(
    field: &str,
    value: Option<&str>,
    scenario_id: &str,
    errors: &mut Vec<String>,
) {
    if value.is_none_or(|raw| raw.trim().is_empty()) {
        errors.push(format!("scenario {scenario_id} must declare {field}"));
    }
}

fn validate_member(
    field: &str,
    value: &str,
    vocabulary: &BTreeSet<&str>,
    scenario_id: &str,
    errors: &mut Vec<String>,
) {
    if !vocabulary.contains(value) {
        errors.push(format!(
            "scenario {scenario_id} {field} references unknown value {value}"
        ));
    }
}

fn validate_members(
    field: &str,
    values: &[String],
    vocabulary: &BTreeSet<&str>,
    scenario_id: &str,
    errors: &mut Vec<String>,
) {
    if values.is_empty() {
        errors.push(format!("scenario {scenario_id} {field} must not be empty"));
    }
    for value in values {
        validate_member(field, value, vocabulary, scenario_id, errors);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_corpus() -> Result<WorkloadCorpus> {
        serde_json::from_str(include_str!(
            "../../../tests/workload-corpus/p1_workload_corpus.json"
        ))
        .context("checked-in corpus is valid JSON")
    }

    fn coverage_row<'a>(
        report: &'a WorkloadCorpusValidationReport,
        scenario_id: &str,
    ) -> Result<&'a WorkloadCoverageMatrixRow> {
        report
            .coverage_matrix
            .iter()
            .find(|row| row.scenario_id == scenario_id)
            .with_context(|| format!("coverage matrix includes row {scenario_id}"))
    }

    fn first_scenario_mut(corpus: &mut WorkloadCorpus) -> Result<&mut WorkloadScenario> {
        corpus
            .scenarios
            .first_mut()
            .context("fixture corpus includes at least one scenario")
    }

    fn first_two_scenarios_mut(
        corpus: &mut WorkloadCorpus,
    ) -> Result<(&mut WorkloadScenario, &mut WorkloadScenario)> {
        let (first, rest) = corpus
            .scenarios
            .split_first_mut()
            .context("fixture corpus includes at least one scenario")?;
        let second = rest
            .first_mut()
            .context("fixture corpus includes at least two scenarios")?;
        Ok((first, second))
    }

    fn scenario_with_status_mut(
        corpus: &mut WorkloadCorpus,
        status: WorkloadScenarioStatus,
    ) -> Result<&mut WorkloadScenario> {
        corpus
            .scenarios
            .iter_mut()
            .find(|scenario| scenario.status == status)
            .with_context(|| format!("fixture corpus includes {} scenario", status.label()))
    }

    #[test]
    fn checked_in_corpus_validates_required_contract() -> Result<()> {
        let corpus = fixture_corpus()?;
        let report = validate_workload_corpus(&corpus);
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.bead_id, "bd-rchk0.5.7");
        assert!(report.scenario_count >= 11);
        for status in ["positive", "negative", "unsupported", "host_skip"] {
            assert!(report.status_counts.contains_key(status));
        }
        assert_ne!(report.host_skip_scenarios, [] as [String; 0]);
        assert_ne!(
            report.btrfs_default_permissions_scenarios,
            [] as [String; 0]
        );
        assert!(report.proof_bundle_coverage.ready);
        assert_eq!(report.coverage_matrix.len(), report.scenario_count);
        assert_eq!(report.missing_high_risk_user_risks, [] as [String; 0]);
        Ok(())
    }

    #[test]
    fn render_workload_corpus_markdown_checked_in_corpus() -> Result<()> {
        let corpus = fixture_corpus()?;
        let report = validate_workload_corpus(&corpus);
        assert!(report.valid, "{:?}", report.errors);
        let markdown = render_workload_corpus_markdown(&report);
        assert!(markdown.contains("# Workload Corpus Validation"));
        assert!(markdown.contains("## Coverage Matrix"));
        assert!(markdown.contains("## Scenario Logs"));
        assert!(markdown.contains("WORKLOAD_CORPUS_SCENARIO|scenario_id="));
        insta::assert_snapshot!(
            "render_workload_corpus_markdown_checked_in_corpus",
            markdown
        );
        Ok(())
    }

    #[test]
    fn workload_corpus_report_json_shape() -> Result<()> {
        let corpus = fixture_corpus()?;
        let report = validate_workload_corpus(&corpus);
        assert!(report.valid, "{:?}", report.errors);

        let full_json = serde_json::to_string_pretty(&report)?;
        let parsed: WorkloadCorpusValidationReport = serde_json::from_str(&full_json)?;
        assert_eq!(parsed, report);

        let shape = serde_json::json!({
            "schema_version": report.schema_version,
            "coverage_matrix_version": report.coverage_matrix_version,
            "corpus_id": &report.corpus_id,
            "corpus_version": &report.corpus_version,
            "bead_id": &report.bead_id,
            "valid": report.valid,
            "scenario_count": report.scenario_count,
            "status_counts": &report.status_counts,
            "by_user_risk": &report.by_user_risk,
            "by_filesystem_flavor": &report.by_filesystem_flavor,
            "by_proof_consumer": &report.by_proof_consumer,
            "proof_bundle_coverage": &report.proof_bundle_coverage,
            "coverage_matrix_count": report.coverage_matrix.len(),
            "coverage_matrix_first": report.coverage_matrix.first(),
            "coverage_matrix_last": report.coverage_matrix.last(),
            "duplicate_scenario_ids": &report.duplicate_scenario_ids,
            "missing_high_risk_user_risks": &report.missing_high_risk_user_risks,
            "missing_required_statuses": &report.missing_required_statuses,
            "host_skip_scenarios": &report.host_skip_scenarios,
            "btrfs_default_permissions_scenarios": &report.btrfs_default_permissions_scenarios,
            "scenario_log_count": report.scenario_logs.len(),
            "scenario_log_first": report.scenario_logs.first(),
            "scenario_log_last": report.scenario_logs.last(),
            "errors": &report.errors,
            "warnings": &report.warnings,
        });
        let json = serde_json::to_string_pretty(&shape)?;
        insta::assert_snapshot!("workload_corpus_report_json_shape", json);
        let parsed_shape: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(parsed_shape, shape);
        Ok(())
    }

    #[test]
    fn validates_selected_reproduction_scenario() -> Result<()> {
        let corpus = fixture_corpus()?;
        validate_selected_workload_scenario(&corpus, "workload_editor_save_atomic_ext4")?;
        let scenario = find_workload_scenario(&corpus, "workload_editor_save_atomic_ext4")
            .context("selected scenario should be returned")?;
        assert_eq!(scenario.operation_class, "editor_save");
        assert!(
            scenario
                .linked_proof_consumers
                .iter()
                .any(|consumer| consumer == "crash_replay_lab")
        );
        Ok(())
    }

    #[test]
    fn rejects_unknown_selected_reproduction_scenario() -> Result<()> {
        let corpus = fixture_corpus()?;
        let err = validate_selected_workload_scenario(&corpus, "workload_missing_scenario")
            .err()
            .context("missing selected workload scenario should be rejected")?;
        assert!(
            err.to_string()
                .contains("workload corpus does not contain selected scenario")
        );
        Ok(())
    }

    #[test]
    fn coverage_matrix_contains_user_risk_and_consumer_axes() -> Result<()> {
        let corpus = fixture_corpus()?;
        let report = validate_workload_corpus(&corpus);
        let row = coverage_row(&report, "workload_editor_save_atomic_ext4")?;
        assert_eq!(row.claim_id, "claim_workload_editor_save_atomic_ext4");
        assert_eq!(row.risk_tier, "p1");
        assert_eq!(row.user_risk, "data_loss");
        assert_eq!(row.operation_class, "editor_save");
        assert!(row.filesystem_scope.iter().any(|fs| fs == "ext4"));
        assert!(
            row.required_capabilities
                .iter()
                .any(|cap| cap == "crash_replay")
        );
        assert!(
            row.proof_consumers
                .iter()
                .any(|consumer| consumer == "proof_bundle")
        );
        assert!(
            row.unit_test_obligations
                .iter()
                .any(|obligation| obligation == "coverage_matrix_row")
        );
        assert!(
            row.e2e_obligations
                .iter()
                .any(|path| path.ends_with("ffs_crash_matrix_e2e.sh"))
        );
        assert!(
            row.expected_log_fields
                .iter()
                .any(|field| field == "scenario_id")
        );
        assert!(
            row.expected_artifact_fields
                .iter()
                .any(|field| field == "required")
        );
        Ok(())
    }

    #[test]
    fn rejects_duplicate_scenario_ids() -> Result<()> {
        let mut corpus = fixture_corpus()?;
        let (first, second) = first_two_scenarios_mut(&mut corpus)?;
        second.scenario_id = first.scenario_id.clone();
        let report = validate_workload_corpus(&corpus);
        assert!(!report.valid);
        assert_eq!(report.duplicate_scenario_ids.len(), 1);
        Ok(())
    }

    #[test]
    fn rejects_unknown_capability_tags() -> Result<()> {
        let mut corpus = fixture_corpus()?;
        first_scenario_mut(&mut corpus)?
            .required_capabilities
            .push("unknown_capability".to_owned());
        let report = validate_workload_corpus(&corpus);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("unknown_capability"))
        );
        Ok(())
    }

    #[test]
    fn rejects_missing_user_risk_field() -> Result<()> {
        let mut corpus = fixture_corpus()?;
        first_scenario_mut(&mut corpus)?.user_risk.clear();
        let report = validate_workload_corpus(&corpus);
        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("user_risk") && error.contains("references unknown value")
        }));
        Ok(())
    }

    #[test]
    fn rejects_orphaned_high_risk_categories() -> Result<()> {
        let mut corpus = fixture_corpus()?;
        corpus
            .scenarios
            .retain(|scenario| scenario.user_risk != "repair_overclaim");
        let report = validate_workload_corpus(&corpus);
        assert!(!report.valid);
        assert_eq!(
            report.missing_high_risk_user_risks,
            vec!["repair_overclaim".to_owned()]
        );
        assert!(report.errors.iter().any(|error| {
            error.contains("high-risk user risk repair_overclaim has no workload scenario")
        }));
        Ok(())
    }

    #[test]
    fn rejects_user_visible_rows_without_e2e_lane() -> Result<()> {
        let mut corpus = fixture_corpus()?;
        first_scenario_mut(&mut corpus)?.linked_e2e_suites.clear();
        let report = validate_workload_corpus(&corpus);
        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("workload_editor_save_atomic_ext4")
                && error.contains("without an E2E or long-campaign proof lane")
        }));
        Ok(())
    }

    #[test]
    fn rejects_missing_required_artifact_declarations() -> Result<()> {
        let mut corpus = fixture_corpus()?;
        first_scenario_mut(&mut corpus)?.expected_artifacts.clear();
        let report = validate_workload_corpus(&corpus);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("expected_artifacts"))
        );
        Ok(())
    }

    #[test]
    fn rejects_unsupported_without_classification() -> Result<()> {
        let mut corpus = fixture_corpus()?;
        let scenario = scenario_with_status_mut(&mut corpus, WorkloadScenarioStatus::Unsupported)?;
        scenario.unsupported_reason = None;
        scenario.follow_up_bead = None;
        scenario.non_goal_reason = None;
        let report = validate_workload_corpus(&corpus);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("unsupported_reason"))
        );
        Ok(())
    }

    #[test]
    fn rejects_host_skip_without_host_capability() -> Result<()> {
        let mut corpus = fixture_corpus()?;
        let scenario = scenario_with_status_mut(&mut corpus, WorkloadScenarioStatus::HostSkip)?;
        scenario.required_capabilities = vec!["metadata_ops".to_owned()];
        let report = validate_workload_corpus(&corpus);
        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("host-skip") && error.contains("host or FUSE capability")
        }));
        Ok(())
    }
}
