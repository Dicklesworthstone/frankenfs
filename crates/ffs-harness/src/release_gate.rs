#![allow(clippy::module_name_repetitions, clippy::too_many_lines)]

//! Fail-closed release-gate evaluator for `bd-rchk0.5.6.1`.
//!
//! The evaluator consumes a proof-bundle validation report plus a policy-as-data
//! file. It produces machine-readable feature states and generated public
//! wording so README / FEATURE_PARITY claims cannot outrun gate evidence.

use crate::proof_bundle::{
    ProofBundleClaimEffect, ProofBundleLaneProvenanceReport, ProofBundleLaneReport,
    ProofBundleOutcome, ProofBundleValidationReport,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const RELEASE_GATE_POLICY_SCHEMA_VERSION: u32 = 1;

const REQUIRED_RELEASE_GATE_LOG_FIELDS: [&str; 12] = [
    "feature_id",
    "previous_state",
    "proposed_state",
    "final_state",
    "transition_reason",
    "controlling_artifact_hash",
    "threshold_value",
    "observed_value",
    "remediation_id",
    "docs_wording_id",
    "output_path",
    "reproduction_command",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureState {
    Hidden,
    Disabled,
    DeprecatedBlocked,
    DryRunOnly,
    DetectionOnly,
    Experimental,
    OptInMutating,
    Validated,
}

impl FeatureState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Hidden => "hidden",
            Self::Disabled => "disabled",
            Self::DeprecatedBlocked => "deprecated_blocked",
            Self::DryRunOnly => "dry_run_only",
            Self::DetectionOnly => "detection_only",
            Self::Experimental => "experimental",
            Self::OptInMutating => "opt_in_mutating",
            Self::Validated => "validated",
        }
    }

    #[must_use]
    pub const fn trust_rank(self) -> u8 {
        match self {
            Self::Hidden => 0,
            Self::Disabled | Self::DeprecatedBlocked => 1,
            Self::DryRunOnly => 2,
            Self::DetectionOnly => 3,
            Self::Experimental => 4,
            Self::OptInMutating => 5,
            Self::Validated => 6,
        }
    }

    #[must_use]
    pub fn public_wording(self, feature_id: &str) -> String {
        match self {
            Self::Hidden => format!(
                "{feature_id} is hidden from public readiness claims until required gate evidence exists."
            ),
            Self::Disabled => {
                format!("{feature_id} is disabled because the release gate failed closed.")
            }
            Self::DeprecatedBlocked => format!(
                "{feature_id} is deprecated or blocked and must not be presented as supported."
            ),
            Self::DryRunOnly => format!(
                "{feature_id} is dry-run-only; it may inspect or plan but must not mutate user data."
            ),
            Self::DetectionOnly => format!(
                "{feature_id} is detection-only; it may report findings but must not repair or mutate."
            ),
            Self::Experimental => {
                format!("{feature_id} is experimental and requires operator caution.")
            }
            Self::OptInMutating => format!(
                "{feature_id} is opt-in mutating and requires explicit operator intent plus fresh gate evidence."
            ),
            Self::Validated => {
                format!("{feature_id} is validated by fresh release-gate evidence.")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGatePolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub features: Vec<ReleaseGateFeaturePolicy>,
    #[serde(default)]
    pub required_log_fields: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGateFeaturePolicy {
    pub feature_id: String,
    pub docs_wording_id: String,
    pub previous_state: FeatureState,
    pub target_state: FeatureState,
    #[serde(default)]
    pub required_lanes: Vec<RequiredReleaseLane>,
    #[serde(default)]
    pub thresholds: Vec<ReleaseGateThreshold>,
    #[serde(default)]
    pub kill_switches: Vec<ReleaseGateKillSwitch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explicit_deferral: Option<ReleaseGateDeferral>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredReleaseLane {
    pub lane_id: String,
    pub expected_outcome: ProofBundleOutcome,
    pub missing_state: FeatureState,
    pub failed_state: FeatureState,
    #[serde(default = "default_required_lane_risk_class")]
    pub risk_class: RequiredLaneRiskClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped_state: Option<FeatureState>,
    #[serde(default)]
    pub allow_capability_skip: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredLaneRiskClass {
    Generic,
    SecurityRefused,
    UnsafeRepairRefused,
    NoisyPerformance,
    HostCapabilitySkip,
}

impl RequiredLaneRiskClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::SecurityRefused => "security_refused",
            Self::UnsafeRepairRefused => "unsafe_repair_refused",
            Self::NoisyPerformance => "noisy_performance",
            Self::HostCapabilitySkip => "host_capability_skip",
        }
    }

    #[must_use]
    pub const fn failure_reason_id(self, observed: ProofBundleOutcome) -> &'static str {
        match (self, observed) {
            (Self::Generic, _) => "required_lane_not_passing",
            (Self::SecurityRefused, _) => "security_refused",
            (Self::UnsafeRepairRefused, _) => "unsafe_repair_refused",
            (Self::NoisyPerformance, _) => "noisy_performance",
            (Self::HostCapabilitySkip, ProofBundleOutcome::Skip) => "capability_blocked",
            (Self::HostCapabilitySkip, _) => "host_capability_failed",
        }
    }

    #[must_use]
    pub const fn skip_reason_id(self) -> &'static str {
        match self {
            Self::HostCapabilitySkip => "host_capability_skip",
            Self::Generic => "capability_skip",
            Self::SecurityRefused => "security_refused_skip",
            Self::UnsafeRepairRefused => "unsafe_repair_refused_skip",
            Self::NoisyPerformance => "noisy_performance_skip",
        }
    }
}

const fn default_required_lane_risk_class() -> RequiredLaneRiskClass {
    RequiredLaneRiskClass::Generic
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGateDeferral {
    pub deferral_id: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_bead: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub non_goal_rationale: Option<String>,
}

impl ReleaseGateDeferral {
    #[must_use]
    fn remediation_id(&self) -> Option<String> {
        self.owner_bead.clone().or_else(|| {
            self.non_goal_rationale
                .as_ref()
                .map(|_| self.deferral_id.clone())
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGateThreshold {
    pub metric: ReleaseGateMetric,
    pub comparator: ThresholdComparator,
    pub value: usize,
    pub downgrade_to: FeatureState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseGateMetric {
    PassLanes,
    FailLanes,
    SkipLanes,
    ErrorLanes,
    BrokenLinks,
    HashMismatches,
    RedactionErrors,
    ReportErrors,
    MissingRequiredLanes,
    DuplicateScenarioIds,
    TotalLanes,
}

impl ReleaseGateMetric {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PassLanes => "pass_lanes",
            Self::FailLanes => "fail_lanes",
            Self::SkipLanes => "skip_lanes",
            Self::ErrorLanes => "error_lanes",
            Self::BrokenLinks => "broken_links",
            Self::HashMismatches => "hash_mismatches",
            Self::RedactionErrors => "redaction_errors",
            Self::ReportErrors => "report_errors",
            Self::MissingRequiredLanes => "missing_required_lanes",
            Self::DuplicateScenarioIds => "duplicate_scenario_ids",
            Self::TotalLanes => "total_lanes",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdComparator {
    AtLeast,
    AtMost,
    Equal,
}

impl ThresholdComparator {
    #[must_use]
    pub fn passes(self, observed: usize, expected: usize) -> bool {
        match self {
            Self::AtLeast => observed >= expected,
            Self::AtMost => observed <= expected,
            Self::Equal => observed == expected,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AtLeast => "at_least",
            Self::AtMost => "at_most",
            Self::Equal => "equal",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGateKillSwitch {
    pub switch_id: String,
    pub trigger: KillSwitchTrigger,
    pub downgrade_to: FeatureState,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchTrigger {
    ProofBundleInvalid,
    AnyRequiredLaneMissing,
    AnyRequiredLaneFailed,
    AnyRequiredLaneSkipped,
    StaleEvidence,
    BrokenArtifact,
    ThresholdFailure,
}

impl KillSwitchTrigger {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ProofBundleInvalid => "proof_bundle_invalid",
            Self::AnyRequiredLaneMissing => "any_required_lane_missing",
            Self::AnyRequiredLaneFailed => "any_required_lane_failed",
            Self::AnyRequiredLaneSkipped => "any_required_lane_skipped",
            Self::StaleEvidence => "stale_evidence",
            Self::BrokenArtifact => "broken_artifact",
            Self::ThresholdFailure => "threshold_failure",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGateEvaluationReport {
    pub schema_version: u32,
    pub policy_id: String,
    pub bundle_id: String,
    pub valid: bool,
    pub release_ready: bool,
    pub proof_bundle_valid: bool,
    pub feature_reports: Vec<ReleaseGateFeatureReport>,
    pub findings: Vec<ReleaseGateFinding>,
    pub generated_wording: Vec<ReleaseGateWording>,
    pub required_log_fields: Vec<String>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGateFeatureReport {
    pub feature_id: String,
    pub docs_wording_id: String,
    pub previous_state: FeatureState,
    pub target_state: FeatureState,
    pub final_state: FeatureState,
    pub upgrade_allowed: bool,
    pub finding_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGateWording {
    pub docs_wording_id: String,
    pub feature_id: String,
    pub state: FeatureState,
    pub wording: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGateFinding {
    pub finding_id: String,
    pub feature_id: String,
    pub severity: ReleaseGateFindingSeverity,
    pub previous_state: FeatureState,
    pub proposed_state: FeatureState,
    pub final_state: FeatureState,
    pub transition_reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controlling_lane: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controlling_artifact_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_value: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_value: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation_id: Option<String>,
    pub docs_wording_id: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseGateFindingSeverity {
    Info,
    Warn,
    Block,
}

impl ReleaseGateFindingSeverity {
    #[must_use]
    pub const fn blocks_release(self) -> bool {
        matches!(self, Self::Block)
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Default)]
struct GateFacts {
    triggers: BTreeSet<KillSwitchTrigger>,
}

#[derive(Debug)]
struct FeatureEvaluation {
    final_state: FeatureState,
    findings: Vec<ReleaseGateFinding>,
    finding_ids: Vec<String>,
}

#[derive(Debug)]
struct FindingInput {
    severity: ReleaseGateFindingSeverity,
    proposed_state: FeatureState,
    reason_id: String,
    transition_reason: String,
    controlling_lane: Option<String>,
    controlling_artifact_hash: Option<String>,
    threshold_value: Option<usize>,
    observed_value: Option<usize>,
    remediation_id: Option<String>,
}

impl FindingInput {
    fn new(
        severity: ReleaseGateFindingSeverity,
        proposed_state: FeatureState,
        reason_id: impl Into<String>,
        transition_reason: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            proposed_state,
            reason_id: reason_id.into(),
            transition_reason: transition_reason.into(),
            controlling_lane: None,
            controlling_artifact_hash: None,
            threshold_value: None,
            observed_value: None,
            remediation_id: None,
        }
    }
}

pub fn load_release_gate_policy(path: &Path) -> Result<ReleaseGatePolicy> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read release gate policy {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid release gate policy JSON {}", path.display()))
}

#[must_use]
pub fn evaluate_release_gates(
    policy: &ReleaseGatePolicy,
    proof: &ProofBundleValidationReport,
) -> ReleaseGateEvaluationReport {
    let mut errors = validate_policy(policy);
    let mut warnings = Vec::new();
    let mut findings = Vec::new();
    let mut feature_reports = Vec::new();
    let mut generated_wording = Vec::new();
    let required_log_fields = release_gate_required_log_fields(policy);

    for feature in &policy.features {
        let evaluation = evaluate_feature(feature, policy, proof);
        let upgrade_allowed = evaluation.final_state == feature.target_state
            && evaluation
                .findings
                .iter()
                .all(|finding| !finding.severity.blocks_release());

        feature_reports.push(ReleaseGateFeatureReport {
            feature_id: feature.feature_id.clone(),
            docs_wording_id: feature.docs_wording_id.clone(),
            previous_state: feature.previous_state,
            target_state: feature.target_state,
            final_state: evaluation.final_state,
            upgrade_allowed,
            finding_ids: evaluation.finding_ids,
        });
        generated_wording.push(ReleaseGateWording {
            docs_wording_id: feature.docs_wording_id.clone(),
            feature_id: feature.feature_id.clone(),
            state: evaluation.final_state,
            wording: evaluation.final_state.public_wording(&feature.feature_id),
        });
        findings.extend(evaluation.findings);
    }

    for finding in &findings {
        if finding.severity.blocks_release() && finding.remediation_id.is_none() {
            errors.push(format!(
                "blocking finding {} for feature {} lacks remediation_id or explicit non-goal",
                finding.finding_id, finding.feature_id
            ));
        }
        if !required_log_fields.iter().all(|field| {
            REQUIRED_RELEASE_GATE_LOG_FIELDS
                .iter()
                .any(|required| required == field)
        }) {
            warnings.push(
                "policy required_log_fields contains non-standard fields; output still includes required fields"
                    .to_owned(),
            );
        }
    }

    let blocking_findings = findings
        .iter()
        .any(|finding| finding.severity.blocks_release());
    let release_ready = !blocking_findings
        && errors.is_empty()
        && feature_reports
            .iter()
            .all(|feature| feature.final_state == feature.target_state);
    let valid = errors.is_empty() && !blocking_findings;

    ReleaseGateEvaluationReport {
        schema_version: RELEASE_GATE_POLICY_SCHEMA_VERSION,
        policy_id: policy.policy_id.clone(),
        bundle_id: proof.bundle_id.clone(),
        valid,
        release_ready,
        proof_bundle_valid: proof.valid,
        feature_reports,
        findings,
        generated_wording,
        required_log_fields,
        errors,
        warnings,
        reproduction_command: policy.reproduction_command.clone(),
    }
}

#[must_use]
pub fn render_release_gate_markdown(report: &ReleaseGateEvaluationReport) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# FrankenFS Release Gate").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "- Policy: `{}`", report.policy_id).ok();
    writeln!(&mut out, "- Bundle: `{}`", report.bundle_id).ok();
    writeln!(&mut out, "- Valid: `{}`", report.valid).ok();
    writeln!(&mut out, "- Release ready: `{}`", report.release_ready).ok();
    writeln!(
        &mut out,
        "- Diagnostics: findings={} errors={} warnings={}",
        report.findings.len(),
        report.errors.len(),
        report.warnings.len()
    )
    .ok();
    writeln!(
        &mut out,
        "- Reproduction: `{}`",
        report.reproduction_command
    )
    .ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Feature States").ok();
    writeln!(
        &mut out,
        "| Feature | Previous | Target | Final | Upgrade allowed | Wording ID |"
    )
    .ok();
    writeln!(&mut out, "|---|---:|---:|---:|---:|---|").ok();
    for feature in &report.feature_reports {
        writeln!(
            &mut out,
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |",
            feature.feature_id,
            feature.previous_state.label(),
            feature.target_state.label(),
            feature.final_state.label(),
            feature.upgrade_allowed,
            feature.docs_wording_id
        )
        .ok();
    }

    writeln!(&mut out).ok();
    writeln!(&mut out, "## Generated Wording").ok();
    for wording in &report.generated_wording {
        writeln!(
            &mut out,
            "- `{}` / `{}`: {}",
            wording.feature_id, wording.docs_wording_id, wording.wording
        )
        .ok();
    }

    if !report.findings.is_empty() {
        writeln!(&mut out).ok();
        writeln!(&mut out, "## Findings").ok();
        writeln!(
            &mut out,
            "| ID | Feature | Severity | Final | Reason | Remediation |"
        )
        .ok();
        writeln!(&mut out, "|---|---|---:|---:|---|---|").ok();
        for finding in &report.findings {
            writeln!(
                &mut out,
                "| `{}` | `{}` | `{}` | `{}` | {} | `{}` |",
                finding.finding_id,
                finding.feature_id,
                finding.severity.label(),
                finding.final_state.label(),
                escape_markdown_table_cell(&finding.transition_reason),
                finding.remediation_id.as_deref().unwrap_or("missing")
            )
            .ok();
        }
    }

    out
}

pub fn fail_on_release_gate_errors(report: &ReleaseGateEvaluationReport) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "release gate evaluation failed with {} blocking finding(s) and {} error(s)",
            report
                .findings
                .iter()
                .filter(|finding| finding.severity.blocks_release())
                .count(),
            report.errors.len()
        )
    }
}

#[must_use]
fn release_gate_required_log_fields(policy: &ReleaseGatePolicy) -> Vec<String> {
    let mut fields: BTreeSet<String> = REQUIRED_RELEASE_GATE_LOG_FIELDS
        .iter()
        .map(|field| (*field).to_owned())
        .collect();
    fields.extend(policy.required_log_fields.iter().cloned());
    fields.into_iter().collect()
}

#[must_use]
fn validate_policy(policy: &ReleaseGatePolicy) -> Vec<String> {
    let mut errors = Vec::new();
    if policy.schema_version != RELEASE_GATE_POLICY_SCHEMA_VERSION {
        errors.push(format!(
            "stale release gate schema_version {} expected {}",
            policy.schema_version, RELEASE_GATE_POLICY_SCHEMA_VERSION
        ));
    }
    validate_nonempty("policy_id", &policy.policy_id, &mut errors);
    validate_nonempty(
        "reproduction_command",
        &policy.reproduction_command,
        &mut errors,
    );
    if !policy
        .reproduction_command
        .contains("evaluate-release-gates")
    {
        errors.push(
            "reproduction_command must preserve evaluate-release-gates invocation".to_owned(),
        );
    }
    if policy.features.is_empty() {
        errors.push("policy must declare at least one feature".to_owned());
    }

    let mut feature_ids = BTreeMap::<String, usize>::new();
    for feature in &policy.features {
        validate_nonempty("feature_id", &feature.feature_id, &mut errors);
        validate_nonempty("docs_wording_id", &feature.docs_wording_id, &mut errors);
        *feature_ids.entry(feature.feature_id.clone()).or_default() += 1;
        if feature.required_lanes.is_empty() {
            errors.push(format!(
                "feature {} must declare at least one required lane",
                feature.feature_id
            ));
        }
        for lane in &feature.required_lanes {
            validate_nonempty("required lane id", &lane.lane_id, &mut errors);
        }
        for switch in &feature.kill_switches {
            validate_nonempty("kill switch id", &switch.switch_id, &mut errors);
            validate_nonempty("kill switch reason", &switch.reason, &mut errors);
        }
    }
    for (feature_id, count) in feature_ids {
        if count > 1 {
            errors.push(format!("duplicate feature_id {feature_id}"));
        }
    }
    errors
}

fn evaluate_feature(
    feature: &ReleaseGateFeaturePolicy,
    policy: &ReleaseGatePolicy,
    proof: &ProofBundleValidationReport,
) -> FeatureEvaluation {
    let lane_reports: BTreeMap<&str, &ProofBundleLaneReport> = proof
        .lanes
        .iter()
        .map(|lane| (lane.lane_id.as_str(), lane))
        .collect();
    let provenance_reports: BTreeMap<&str, &ProofBundleLaneProvenanceReport> = proof
        .lane_provenance
        .iter()
        .map(|provenance| (provenance.lane_id.as_str(), provenance))
        .collect();
    let mut final_state = feature.target_state;
    let mut facts = GateFacts::default();
    let mut findings = Vec::new();

    if !proof.valid {
        facts.triggers.insert(KillSwitchTrigger::ProofBundleInvalid);
        let mut input = FindingInput::new(
            ReleaseGateFindingSeverity::Block,
            FeatureState::Disabled,
            "proof_bundle_invalid",
            "proof bundle validator reported errors",
        );
        input.controlling_artifact_hash = Some(controlling_artifact_hash(proof));
        input.remediation_id = feature_remediation(feature);
        push_finding(&mut findings, feature, policy, input);
        final_state = more_conservative(final_state, FeatureState::Disabled);
    }

    if proof.stale_git_sha.is_some() || proof.stale_timestamp.is_some() {
        facts.triggers.insert(KillSwitchTrigger::StaleEvidence);
        let mut input = FindingInput::new(
            ReleaseGateFindingSeverity::Block,
            FeatureState::Disabled,
            "stale_evidence",
            "proof bundle evidence is stale by git SHA or timestamp",
        );
        input.controlling_artifact_hash = Some(controlling_artifact_hash(proof));
        input.remediation_id = feature_remediation(feature);
        push_finding(&mut findings, feature, policy, input);
        final_state = more_conservative(final_state, FeatureState::Disabled);
    }

    if !proof.broken_links.is_empty() || !proof.artifact_hash_mismatches.is_empty() {
        facts.triggers.insert(KillSwitchTrigger::BrokenArtifact);
    }

    for lane in &feature.required_lanes {
        let observed_lane = lane_reports
            .get(lane.lane_id.as_str())
            .map(|lane_report| lane_report.status);
        let capability_skip_state = if lane.allow_capability_skip {
            lane.skipped_state
        } else {
            None
        };
        match (observed_lane, capability_skip_state) {
            (None, _) => {
                facts
                    .triggers
                    .insert(KillSwitchTrigger::AnyRequiredLaneMissing);
                let proposed = lane.missing_state;
                let remediation = lane_remediation(lane, feature);
                let mut input = FindingInput::new(
                    ReleaseGateFindingSeverity::Block,
                    proposed,
                    "missing_required_lane",
                    format!("required lane {} is missing", lane.lane_id),
                );
                input.controlling_lane = Some(lane.lane_id.clone());
                input.controlling_artifact_hash = Some(controlling_artifact_hash(proof));
                input.remediation_id = remediation;
                push_finding(&mut findings, feature, policy, input);
                final_state = more_conservative(final_state, proposed);
            }
            (Some(observed), _) if observed == lane.expected_outcome => {
                if lane.expected_outcome == ProofBundleOutcome::Pass
                    && let Some(provenance) = provenance_reports.get(lane.lane_id.as_str())
                    && !provenance.claim_effect.strengthens_public_claim()
                {
                    let proposed = provenance_downgrade_state(provenance.claim_effect);
                    let remediation = lane_remediation(lane, feature);
                    let mut input = FindingInput::new(
                        ReleaseGateFindingSeverity::Block,
                        proposed,
                        "lane_provenance_not_authoritative",
                        format!(
                            "required lane {} observed pass but provenance={} claim_effect={} cannot strengthen public readiness: {}",
                            lane.lane_id,
                            provenance.provenance_class.label(),
                            provenance.claim_effect.label(),
                            provenance.rationale
                        ),
                    );
                    input.controlling_lane = Some(lane.lane_id.clone());
                    input.controlling_artifact_hash = Some(controlling_artifact_hash(proof));
                    input.remediation_id = remediation;
                    push_finding(&mut findings, feature, policy, input);
                    final_state = more_conservative(final_state, proposed);
                }
            }
            (Some(ProofBundleOutcome::Skip), Some(proposed)) => {
                facts
                    .triggers
                    .insert(KillSwitchTrigger::AnyRequiredLaneSkipped);
                let remediation = lane_remediation(lane, feature);
                let mut input = FindingInput::new(
                    ReleaseGateFindingSeverity::Warn,
                    proposed,
                    lane.risk_class.skip_reason_id(),
                    format!(
                        "required lane {} skipped due to host capability; risk_class={}",
                        lane.lane_id,
                        lane.risk_class.label()
                    ),
                );
                input.controlling_lane = Some(lane.lane_id.clone());
                input.controlling_artifact_hash = Some(controlling_artifact_hash(proof));
                input.remediation_id = remediation;
                push_finding(&mut findings, feature, policy, input);
                final_state = more_conservative(final_state, proposed);
            }
            (Some(observed), _) => {
                facts
                    .triggers
                    .insert(KillSwitchTrigger::AnyRequiredLaneFailed);
                let proposed = lane.failed_state;
                let remediation = lane_remediation(lane, feature);
                let context =
                    lane_metadata_context(lane_reports.get(lane.lane_id.as_str()).copied());
                let mut input = FindingInput::new(
                    ReleaseGateFindingSeverity::Block,
                    proposed,
                    lane.risk_class.failure_reason_id(observed),
                    format!(
                        "required lane {} observed {} expected {}; risk_class={}{}",
                        lane.lane_id,
                        observed.label(),
                        lane.expected_outcome.label(),
                        lane.risk_class.label(),
                        context
                    ),
                );
                input.controlling_lane = Some(lane.lane_id.clone());
                input.controlling_artifact_hash = Some(controlling_artifact_hash(proof));
                input.remediation_id = remediation;
                push_finding(&mut findings, feature, policy, input);
                final_state = more_conservative(final_state, proposed);
            }
        }
    }

    for threshold in &feature.thresholds {
        let observed = metric_value(proof, threshold.metric);
        if !threshold.comparator.passes(observed, threshold.value) {
            facts.triggers.insert(KillSwitchTrigger::ThresholdFailure);
            let mut input = FindingInput::new(
                ReleaseGateFindingSeverity::Block,
                threshold.downgrade_to,
                "threshold_failure",
                format!(
                    "threshold {} {} {} observed {}",
                    threshold.metric.label(),
                    threshold.comparator.label(),
                    threshold.value,
                    observed
                ),
            );
            input.controlling_artifact_hash = Some(controlling_artifact_hash(proof));
            input.threshold_value = Some(threshold.value);
            input.observed_value = Some(observed);
            input.remediation_id = threshold
                .remediation_id
                .clone()
                .or_else(|| feature_remediation(feature));
            push_finding(&mut findings, feature, policy, input);
            final_state = more_conservative(final_state, threshold.downgrade_to);
        }
    }

    for switch in &feature.kill_switches {
        if kill_switch_triggered(switch.trigger, &facts) {
            let mut input = FindingInput::new(
                ReleaseGateFindingSeverity::Block,
                switch.downgrade_to,
                format!("kill_switch_{}", switch.switch_id),
                format!(
                    "kill switch {} triggered by {}: {}",
                    switch.switch_id,
                    switch.trigger.label(),
                    switch.reason
                ),
            );
            input.controlling_artifact_hash = Some(controlling_artifact_hash(proof));
            input.remediation_id = switch
                .remediation_id
                .clone()
                .or_else(|| feature_remediation(feature));
            push_finding(&mut findings, feature, policy, input);
            final_state = more_conservative(final_state, switch.downgrade_to);
        }
    }

    for finding in &mut findings {
        finding.final_state = final_state;
    }

    let finding_ids = findings
        .iter()
        .map(|finding| finding.finding_id.clone())
        .collect();

    FeatureEvaluation {
        final_state,
        findings,
        finding_ids,
    }
}

fn push_finding(
    findings: &mut Vec<ReleaseGateFinding>,
    feature: &ReleaseGateFeaturePolicy,
    policy: &ReleaseGatePolicy,
    input: FindingInput,
) {
    let finding_id = format!(
        "{}::{}::{}",
        feature.feature_id,
        input.reason_id,
        findings.len() + 1
    );
    findings.push(ReleaseGateFinding {
        finding_id,
        feature_id: feature.feature_id.clone(),
        severity: input.severity,
        previous_state: feature.previous_state,
        proposed_state: input.proposed_state,
        final_state: input.proposed_state,
        transition_reason: input.transition_reason,
        controlling_lane: input.controlling_lane,
        controlling_artifact_hash: input.controlling_artifact_hash,
        threshold_value: input.threshold_value,
        observed_value: input.observed_value,
        remediation_id: input.remediation_id,
        docs_wording_id: feature.docs_wording_id.clone(),
        reproduction_command: policy.reproduction_command.clone(),
    });
}

fn lane_metadata_context(lane: Option<&ProofBundleLaneReport>) -> String {
    let Some(lane) = lane else {
        return String::new();
    };
    let mut parts = Vec::new();
    for key in [
        "scenario_id",
        "run_id",
        "release_claim_state",
        "host_classification",
        "cleanup_status",
    ] {
        if let Some(value) = lane.metadata.get(key)
            && !value.trim().is_empty()
        {
            parts.push(format!("{key}={value}"));
        }
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("; {}", parts.join(" "))
    }
}

const fn provenance_downgrade_state(effect: ProofBundleClaimEffect) -> FeatureState {
    match effect {
        ProofBundleClaimEffect::StrengthensPublicClaim => FeatureState::Validated,
        ProofBundleClaimEffect::BlocksPublicClaim
        | ProofBundleClaimEffect::EvidenceProductionFailure => FeatureState::Disabled,
        ProofBundleClaimEffect::ExperimentalOnly => FeatureState::Experimental,
        ProofBundleClaimEffect::HandoffOnly => FeatureState::DryRunOnly,
        ProofBundleClaimEffect::DoesNotStrengthenPublicClaim => FeatureState::Hidden,
    }
}

#[must_use]
fn metric_value(proof: &ProofBundleValidationReport, metric: ReleaseGateMetric) -> usize {
    match metric {
        ReleaseGateMetric::PassLanes => proof.totals.pass,
        ReleaseGateMetric::FailLanes => proof.totals.fail,
        ReleaseGateMetric::SkipLanes => proof.totals.skip,
        ReleaseGateMetric::ErrorLanes => proof.totals.error,
        ReleaseGateMetric::BrokenLinks => proof.broken_links.len(),
        ReleaseGateMetric::HashMismatches => proof.artifact_hash_mismatches.len(),
        ReleaseGateMetric::RedactionErrors => proof.redaction_errors.len(),
        ReleaseGateMetric::ReportErrors => proof.errors.len(),
        ReleaseGateMetric::MissingRequiredLanes => proof.missing_required_lanes.len(),
        ReleaseGateMetric::DuplicateScenarioIds => proof.duplicate_scenario_ids.len(),
        ReleaseGateMetric::TotalLanes => proof.totals.lanes,
    }
}

#[must_use]
fn kill_switch_triggered(trigger: KillSwitchTrigger, facts: &GateFacts) -> bool {
    facts.triggers.contains(&trigger)
}

#[must_use]
fn more_conservative(left: FeatureState, right: FeatureState) -> FeatureState {
    if right.trust_rank() < left.trust_rank() {
        right
    } else {
        left
    }
}

#[must_use]
fn feature_remediation(feature: &ReleaseGateFeaturePolicy) -> Option<String> {
    feature.remediation_id.clone().or_else(|| {
        feature
            .explicit_deferral
            .as_ref()
            .and_then(ReleaseGateDeferral::remediation_id)
    })
}

#[must_use]
fn lane_remediation(
    lane: &RequiredReleaseLane,
    feature: &ReleaseGateFeaturePolicy,
) -> Option<String> {
    lane.remediation_id
        .clone()
        .or_else(|| feature_remediation(feature))
}

#[must_use]
fn controlling_artifact_hash(proof: &ProofBundleValidationReport) -> String {
    proof
        .artifact_hash_mismatches
        .first()
        .map(|mismatch| mismatch.actual_sha256.clone())
        .or_else(|| {
            proof
                .stale_git_sha
                .as_ref()
                .map(|stale| stale.observed.clone())
        })
        .unwrap_or_else(|| proof.bundle_id.clone())
}

fn validate_nonempty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
}

fn escape_markdown_table_cell(raw: &str) -> String {
    raw.replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_bundle::{
        ProofBundleBrokenLink, ProofBundleClaimEffect, ProofBundleLaneProvenanceReport,
        ProofBundleLaneReport, ProofBundleProvenanceClass, ProofBundleTotals,
        StaleProofBundleGitSha, proof_bundle_required_lanes,
    };

    fn passing_proof() -> ProofBundleValidationReport {
        let lanes = proof_bundle_required_lanes()
            .into_iter()
            .map(|lane| ProofBundleLaneReport {
                lane_id: lane.clone(),
                status: ProofBundleOutcome::Pass,
                raw_log_path: format!("logs/{lane}.log"),
                summary_path: format!("summaries/{lane}.md"),
                scenario_count: 1,
                artifact_count: 1,
                metadata: BTreeMap::new(),
            })
            .collect::<Vec<_>>();
        let lane_provenance = lanes
            .iter()
            .map(|lane| ProofBundleLaneProvenanceReport {
                lane_id: lane.lane_id.clone(),
                status: lane.status,
                provenance_class: ProofBundleProvenanceClass::ExecutedProductEvidence,
                claim_effect: ProofBundleClaimEffect::StrengthensPublicClaim,
                artifact_roles: vec!["primary_evidence".to_owned()],
                source_command: format!("cargo test -p ffs-harness {}", lane.lane_id),
                git_sha: "abcdef1".to_owned(),
                freshness: "fresh".to_owned(),
                host_class: "permissioned_large_host".to_owned(),
                raw_log_path: lane.raw_log_path.clone(),
                raw_log_present: true,
                rationale: "executed product evidence".to_owned(),
            })
            .collect::<Vec<_>>();
        let lane_count = lanes.len();

        ProofBundleValidationReport {
            schema_version: 1,
            bundle_id: "release-gate-proof".to_owned(),
            manifest_path: "manifest.json".to_owned(),
            valid: true,
            totals: ProofBundleTotals {
                pass: lane_count,
                fail: 0,
                skip: 0,
                error: 0,
                lanes: lane_count,
                scenarios: lane_count,
                artifacts: lane_count,
            },
            missing_required_lanes: Vec::new(),
            duplicate_lane_ids: Vec::new(),
            duplicate_scenario_ids: Vec::new(),
            stale_git_sha: None,
            stale_timestamp: None,
            broken_links: Vec::new(),
            raw_log_hash_mismatches: Vec::new(),
            artifact_hash_mismatches: Vec::new(),
            artifact_hash_chain: None,
            artifact_reports: Vec::new(),
            redaction_errors: Vec::new(),
            redaction_leaks: Vec::new(),
            integrity_errors: Vec::new(),
            lanes,
            lane_provenance,
            executed_evidence: Vec::new(),
            swarm_evidence: Vec::new(),
            adaptive_runtime_evidence: Vec::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
            reproduction_command: "validate-proof-bundle --bundle manifest.json".to_owned(),
        }
    }

    fn sample_policy() -> ReleaseGatePolicy {
        ReleaseGatePolicy {
            schema_version: RELEASE_GATE_POLICY_SCHEMA_VERSION,
            policy_id: "bd-rchk0.5.6.1-release-gate".to_owned(),
            reproduction_command: "cargo run -p ffs-harness -- evaluate-release-gates --bundle manifest.json --policy release_gate.json".to_owned(),
            required_log_fields: Vec::new(),
            features: vec![ReleaseGateFeaturePolicy {
                feature_id: "writeback_cache".to_owned(),
                docs_wording_id: "readme.writeback_cache".to_owned(),
                previous_state: FeatureState::Experimental,
                target_state: FeatureState::Validated,
                required_lanes: vec![
                    required_lane("writeback_cache"),
                    required_lane("release_gates"),
                    required_lane("crash_replay"),
                ],
                thresholds: vec![
                    ReleaseGateThreshold {
                        metric: ReleaseGateMetric::PassLanes,
                        comparator: ThresholdComparator::AtLeast,
                        value: 9,
                        downgrade_to: FeatureState::Experimental,
                        remediation_id: Some("bd-rchk0.5.6.1".to_owned()),
                    },
                    ReleaseGateThreshold {
                        metric: ReleaseGateMetric::FailLanes,
                        comparator: ThresholdComparator::AtMost,
                        value: 0,
                        downgrade_to: FeatureState::Disabled,
                        remediation_id: Some("bd-rchk0.5.6.1".to_owned()),
                    },
                ],
                kill_switches: vec![
                    ReleaseGateKillSwitch {
                        switch_id: "stale-proof".to_owned(),
                        trigger: KillSwitchTrigger::StaleEvidence,
                        downgrade_to: FeatureState::Disabled,
                        reason: "stale evidence cannot enable writeback-cache".to_owned(),
                        remediation_id: Some("bd-rchk0.5.6.1".to_owned()),
                    },
                    ReleaseGateKillSwitch {
                        switch_id: "missing-proof".to_owned(),
                        trigger: KillSwitchTrigger::AnyRequiredLaneMissing,
                        downgrade_to: FeatureState::Hidden,
                        reason: "missing required lane hides public claim".to_owned(),
                        remediation_id: Some("bd-rchk0.5.6.1".to_owned()),
                    },
                ],
                remediation_id: Some("bd-rchk0.5.6.1".to_owned()),
                explicit_deferral: None,
            }],
        }
    }

    fn required_lane(lane_id: &str) -> RequiredReleaseLane {
        RequiredReleaseLane {
            lane_id: lane_id.to_owned(),
            expected_outcome: ProofBundleOutcome::Pass,
            missing_state: FeatureState::Hidden,
            failed_state: FeatureState::Disabled,
            risk_class: RequiredLaneRiskClass::Generic,
            skipped_state: Some(FeatureState::Experimental),
            allow_capability_skip: true,
            remediation_id: Some("bd-rchk0.5.6.1".to_owned()),
        }
    }

    fn set_lane_status(
        proof: &mut ProofBundleValidationReport,
        lane_id: &str,
        status: ProofBundleOutcome,
    ) {
        let lane = proof
            .lanes
            .iter_mut()
            .find(|lane| lane.lane_id == lane_id)
            .expect("lane present");
        lane.status = status;
        proof.totals.pass = proof
            .lanes
            .iter()
            .filter(|lane| lane.status == ProofBundleOutcome::Pass)
            .count();
        proof.totals.fail = proof
            .lanes
            .iter()
            .filter(|lane| lane.status == ProofBundleOutcome::Fail)
            .count();
        proof.totals.skip = proof
            .lanes
            .iter()
            .filter(|lane| lane.status == ProofBundleOutcome::Skip)
            .count();
        proof.totals.error = proof
            .lanes
            .iter()
            .filter(|lane| lane.status == ProofBundleOutcome::Error)
            .count();
    }

    fn set_lane_provenance_effect(
        proof: &mut ProofBundleValidationReport,
        lane_id: &str,
        provenance_class: ProofBundleProvenanceClass,
        claim_effect: ProofBundleClaimEffect,
    ) {
        let provenance = proof
            .lane_provenance
            .iter_mut()
            .find(|provenance| provenance.lane_id == lane_id)
            .expect("lane provenance present");
        provenance.provenance_class = provenance_class;
        provenance.claim_effect = claim_effect;
        provenance.rationale = format!(
            "{} evidence cannot strengthen public readiness",
            provenance_class.label()
        );
    }

    fn one_lane_policy(
        lane_id: &str,
        previous_state: FeatureState,
        target_state: FeatureState,
        failed_state: FeatureState,
        risk_class: RequiredLaneRiskClass,
    ) -> ReleaseGatePolicy {
        let mut policy = sample_policy();
        let feature = &mut policy.features[0];
        feature.previous_state = previous_state;
        feature.target_state = target_state;
        feature.required_lanes = vec![RequiredReleaseLane {
            failed_state,
            risk_class,
            ..required_lane(lane_id)
        }];
        feature.thresholds.clear();
        feature.kill_switches.clear();
        policy
    }

    #[test]
    fn passing_policy_upgrades_to_validated() {
        let report = evaluate_release_gates(&sample_policy(), &passing_proof());
        assert!(report.valid, "{:?}", report.errors);
        assert!(report.release_ready);
        assert_eq!(report.findings, [] as [ReleaseGateFinding; 0]);
        assert_eq!(
            report.feature_reports[0].final_state,
            FeatureState::Validated
        );
        assert!(report.generated_wording[0].wording.contains("validated"));
    }

    #[test]
    fn pass_lane_requires_authoritative_provenance() {
        let mut proof = passing_proof();
        set_lane_provenance_effect(
            &mut proof,
            "writeback_cache",
            ProofBundleProvenanceClass::DryRunHandoff,
            ProofBundleClaimEffect::HandoffOnly,
        );

        let report = evaluate_release_gates(&sample_policy(), &proof);

        assert!(!report.valid);
        assert_eq!(
            report.feature_reports[0].final_state,
            FeatureState::DryRunOnly
        );
        assert!(report.findings.iter().any(|finding| {
            finding
                .finding_id
                .contains("lane_provenance_not_authoritative")
                && finding.controlling_lane.as_deref() == Some("writeback_cache")
        }));
    }

    #[test]
    fn redaction_provenance_failure_disables_release_claim() {
        let mut proof = passing_proof();
        proof
            .redaction_errors
            .push("redaction leak lane=writeback_cache marker=SECRET_TOKEN".to_owned());
        set_lane_provenance_effect(
            &mut proof,
            "writeback_cache",
            ProofBundleProvenanceClass::RedactionFailure,
            ProofBundleClaimEffect::EvidenceProductionFailure,
        );

        let report = evaluate_release_gates(&sample_policy(), &proof);

        assert!(!report.valid);
        assert_eq!(
            report.feature_reports[0].final_state,
            FeatureState::Disabled
        );
        assert!(report.findings.iter().any(|finding| {
            finding
                .transition_reason
                .contains("claim_effect=evidence_production_failure")
                && finding.controlling_lane.as_deref() == Some("writeback_cache")
        }));
    }

    #[test]
    fn missing_required_lane_fails_closed_to_hidden() {
        let mut proof = passing_proof();
        proof.lanes.retain(|lane| lane.lane_id != "release_gates");
        proof.totals.lanes = 8;
        let report = evaluate_release_gates(&sample_policy(), &proof);
        assert!(!report.valid);
        assert_eq!(report.feature_reports[0].final_state, FeatureState::Hidden);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.transition_reason.contains("missing"))
        );
    }

    #[test]
    fn stale_artifact_triggers_kill_switch() {
        let mut proof = passing_proof();
        proof.valid = false;
        proof.stale_git_sha = Some(StaleProofBundleGitSha {
            observed: "old".to_owned(),
            expected: "new".to_owned(),
        });
        proof
            .errors
            .push("stale git_sha old expected new".to_owned());
        let report = evaluate_release_gates(&sample_policy(), &proof);
        assert!(!report.valid);
        assert_eq!(
            report.feature_reports[0].final_state,
            FeatureState::Disabled
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.transition_reason.contains("stale evidence"))
        );
    }

    #[test]
    fn threshold_failures_downgrade_feature_state() {
        let mut proof = passing_proof();
        proof.totals.pass = 8;
        let report = evaluate_release_gates(&sample_policy(), &proof);
        assert!(!report.valid);
        assert_eq!(
            report.feature_reports[0].final_state,
            FeatureState::Experimental
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.threshold_value == Some(9))
        );
    }

    #[test]
    fn capability_skip_is_warn_and_downgrades_without_blocking() {
        let mut proof = passing_proof();
        set_lane_status(&mut proof, "writeback_cache", ProofBundleOutcome::Skip);
        let mut policy = sample_policy();
        policy.features[0].thresholds.clear();
        policy.features[0].required_lanes[0].risk_class = RequiredLaneRiskClass::HostCapabilitySkip;
        let report = evaluate_release_gates(&policy, &proof);
        assert!(report.valid, "{:?}", report.errors);
        assert!(!report.release_ready);
        assert_eq!(
            report.feature_reports[0].final_state,
            FeatureState::Experimental
        );
        assert_eq!(
            report.findings[0].severity,
            ReleaseGateFindingSeverity::Warn
        );
        assert!(
            report.findings[0]
                .finding_id
                .contains("host_capability_skip")
        );
    }

    #[test]
    fn unsafe_repair_refusal_downgrades_opt_in_mutating_to_detection_only() {
        let mut proof = passing_proof();
        set_lane_status(&mut proof, "repair_lab", ProofBundleOutcome::Fail);
        let policy = one_lane_policy(
            "repair_lab",
            FeatureState::OptInMutating,
            FeatureState::OptInMutating,
            FeatureState::DetectionOnly,
            RequiredLaneRiskClass::UnsafeRepairRefused,
        );
        let report = evaluate_release_gates(&policy, &proof);
        assert!(!report.valid);
        assert_eq!(
            report.feature_reports[0].final_state,
            FeatureState::DetectionOnly
        );
        assert!(report.findings.iter().any(|finding| {
            finding.finding_id.contains("unsafe_repair_refused")
                && finding
                    .transition_reason
                    .contains("risk_class=unsafe_repair_refused")
        }));
    }

    #[test]
    fn security_refusal_disables_supported_feature_claim() {
        let mut proof = passing_proof();
        set_lane_status(&mut proof, "conformance", ProofBundleOutcome::Fail);
        let policy = one_lane_policy(
            "conformance",
            FeatureState::OptInMutating,
            FeatureState::Validated,
            FeatureState::Disabled,
            RequiredLaneRiskClass::SecurityRefused,
        );
        let report = evaluate_release_gates(&policy, &proof);
        assert!(!report.valid);
        assert_eq!(
            report.feature_reports[0].final_state,
            FeatureState::Disabled
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.finding_id.contains("security_refused")
                    && finding.remediation_id.as_deref() == Some("bd-rchk0.5.6.1"))
        );
    }

    #[test]
    fn noisy_performance_reduces_validated_claim_to_experimental() {
        let mut proof = passing_proof();
        set_lane_status(&mut proof, "performance", ProofBundleOutcome::Fail);
        let policy = one_lane_policy(
            "performance",
            FeatureState::Validated,
            FeatureState::Validated,
            FeatureState::Experimental,
            RequiredLaneRiskClass::NoisyPerformance,
        );
        let report = evaluate_release_gates(&policy, &proof);
        assert!(!report.valid);
        assert_eq!(
            report.feature_reports[0].final_state,
            FeatureState::Experimental
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.finding_id.contains("noisy_performance"))
        );
    }

    #[test]
    fn capability_blocked_ready_claim_fails_closed_to_hidden() {
        let mut proof = passing_proof();
        set_lane_status(&mut proof, "fuse", ProofBundleOutcome::Skip);
        let mut policy = one_lane_policy(
            "fuse",
            FeatureState::Experimental,
            FeatureState::Validated,
            FeatureState::Hidden,
            RequiredLaneRiskClass::HostCapabilitySkip,
        );
        policy.features[0].required_lanes[0].allow_capability_skip = false;
        policy.features[0].required_lanes[0].skipped_state = None;
        let report = evaluate_release_gates(&policy, &proof);
        assert!(!report.valid);
        assert_eq!(report.feature_reports[0].final_state, FeatureState::Hidden);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.finding_id.contains("capability_blocked"))
        );
    }

    #[test]
    fn explicit_deferral_satisfies_remediation_requirement() {
        let mut proof = passing_proof();
        proof.lanes.clear();
        proof.totals.lanes = 0;
        let mut policy = sample_policy();
        policy.features[0].remediation_id = None;
        policy.features[0].explicit_deferral = Some(ReleaseGateDeferral {
            deferral_id: "writeback-cache-non-goal".to_owned(),
            reason: "not enabled in V1.x".to_owned(),
            owner_bead: None,
            non_goal_rationale: Some("kernel writeback-cache remains blocked".to_owned()),
        });
        let report = evaluate_release_gates(&policy, &proof);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .all(|error| !error.contains("lacks remediation"))
        );
    }

    #[test]
    fn blocking_downgrade_without_remediation_is_rejected() {
        let mut proof = passing_proof();
        proof.lanes.clear();
        proof.totals.lanes = 0;
        let mut policy = sample_policy();
        policy.features[0].remediation_id = None;
        for lane in &mut policy.features[0].required_lanes {
            lane.remediation_id = None;
        }
        for switch in &mut policy.features[0].kill_switches {
            switch.remediation_id = None;
        }
        let report = evaluate_release_gates(&policy, &proof);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("lacks remediation_id"))
        );
    }

    #[test]
    fn generated_wording_changes_after_downgrade() {
        let passing = evaluate_release_gates(&sample_policy(), &passing_proof());
        let mut proof = passing_proof();
        proof.broken_links.push(ProofBundleBrokenLink {
            lane_id: "release_gates".to_owned(),
            field: "artifact".to_owned(),
            path: "missing.json".to_owned(),
            diagnostic: "file does not exist".to_owned(),
        });
        proof.valid = false;
        proof.errors.push("broken link".to_owned());
        let failing = evaluate_release_gates(&sample_policy(), &proof);
        assert_ne!(
            passing.generated_wording[0].wording,
            failing.generated_wording[0].wording
        );
        assert!(failing.generated_wording[0].wording.contains("disabled"));
    }

    #[test]
    fn hand_edited_public_claim_cannot_override_gate_data() {
        let mut proof = passing_proof();
        set_lane_status(&mut proof, "conformance", ProofBundleOutcome::Fail);
        let mut policy = one_lane_policy(
            "conformance",
            FeatureState::Experimental,
            FeatureState::Validated,
            FeatureState::Disabled,
            RequiredLaneRiskClass::SecurityRefused,
        );
        policy.features[0].docs_wording_id =
            "feature_parity.hand_edited.validated_claim".to_owned();
        let report = evaluate_release_gates(&policy, &proof);
        assert!(!report.valid);
        assert_eq!(
            report.feature_reports[0].target_state,
            FeatureState::Validated
        );
        assert_eq!(
            report.generated_wording[0].docs_wording_id,
            "feature_parity.hand_edited.validated_claim"
        );
        assert_eq!(report.generated_wording[0].state, FeatureState::Disabled);
        assert!(report.generated_wording[0].wording.contains("disabled"));
        assert!(!report.generated_wording[0].wording.contains("validated by"));
    }

    #[test]
    fn report_contains_required_log_fields() {
        let report = evaluate_release_gates(&sample_policy(), &passing_proof());
        for field in REQUIRED_RELEASE_GATE_LOG_FIELDS {
            assert!(report.required_log_fields.contains(&field.to_owned()));
        }
    }

    #[test]
    fn canonical_release_gate_policy_covers_required_domains() {
        let policy = load_release_gate_policy(&canonical_policy_path()).expect("canonical policy");
        let report = evaluate_release_gates(&policy, &passing_proof());
        assert!(report.valid, "{:?}", report.errors);
        assert!(report.release_ready);
        assert_eq!(report.policy_id, "frankenfs_release_gate_policy_v1");

        let feature_ids = policy
            .features
            .iter()
            .map(|feature| feature.feature_id.as_str())
            .collect::<BTreeSet<_>>();
        for required in [
            "mount.rw.ext4",
            "mount.rw.btrfs",
            "repair.rw.writeback",
            "writeback_cache",
            "background_scrub_mutation",
            "conformance.claims",
            "xfstests.baseline",
            "performance.baseline",
            "swarm.responsiveness",
            "fuzz.conformance",
            "crash_replay.evidence",
        ] {
            assert!(feature_ids.contains(required), "missing feature {required}");
        }

        let lane_ids = policy
            .features
            .iter()
            .flat_map(|feature| feature.required_lanes.iter())
            .map(|lane| lane.lane_id.as_str())
            .collect::<BTreeSet<_>>();
        for required in [
            "conformance",
            "xfstests",
            "fuse",
            "repair_lab",
            "crash_replay",
            "performance",
            "swarm_workload_harness",
            "swarm_tail_latency",
            "adaptive_runtime",
            "writeback_cache",
            "scrub_repair_status",
            "known_deferrals",
            "release_gates",
        ] {
            assert!(lane_ids.contains(required), "missing lane {required}");
        }

        assert!(
            policy.features.iter().all(|feature| {
                feature.remediation_id.is_some()
                    || feature.explicit_deferral.as_ref().is_some_and(|deferral| {
                        deferral.owner_bead.is_some() || deferral.non_goal_rationale.is_some()
                    })
            }),
            "all release-gate caveats need a remediation bead or explicit non-goal"
        );
    }

    #[test]
    fn canonical_release_gate_policy_fails_closed_on_missing_xfstests() {
        let policy = load_release_gate_policy(&canonical_policy_path()).expect("canonical policy");
        let mut proof = passing_proof();
        proof.lanes.retain(|lane| lane.lane_id != "xfstests");
        proof.totals.lanes = proof.lanes.len();
        proof.totals.pass = proof.lanes.len();

        let report = evaluate_release_gates(&policy, &proof);

        assert!(!report.valid);
        let xfstests_report = report
            .feature_reports
            .iter()
            .find(|feature| feature.feature_id == "xfstests.baseline")
            .expect("xfstests feature report");
        assert_eq!(xfstests_report.final_state, FeatureState::Hidden);
        assert!(report.findings.iter().any(|finding| {
            finding.feature_id == "xfstests.baseline"
                && finding.finding_id.contains("missing_required_lane")
                && finding.remediation_id.as_deref() == Some("bd-rchk3")
        }));
    }

    #[test]
    fn render_release_gate_markdown_canonical_missing_xfstests_snapshot() {
        let policy = load_release_gate_policy(&canonical_policy_path()).expect("canonical policy");
        let mut proof = passing_proof();
        proof.lanes.retain(|lane| lane.lane_id != "xfstests");
        proof.totals.lanes = proof.lanes.len();
        proof.totals.pass = proof.lanes.len();

        let report = evaluate_release_gates(&policy, &proof);
        assert!(!report.valid);
        assert!(!report.release_ready);
        assert!(report.findings.iter().any(|finding| {
            finding.feature_id == "xfstests.baseline"
                && finding.remediation_id.as_deref() == Some("bd-rchk3")
        }));

        let markdown = render_release_gate_markdown(&report);
        insta::assert_snapshot!(
            "render_release_gate_markdown_canonical_missing_xfstests",
            markdown
        );
    }

    #[test]
    fn canonical_release_gate_policy_fails_closed_on_missing_swarm_p99() {
        let policy = load_release_gate_policy(&canonical_policy_path()).expect("canonical policy");
        let mut proof = passing_proof();
        proof
            .lanes
            .retain(|lane| lane.lane_id != "swarm_tail_latency");
        proof.totals.lanes = proof.lanes.len();
        proof.totals.pass = proof.lanes.len();

        let report = evaluate_release_gates(&policy, &proof);

        assert!(!report.valid);
        let swarm_report = report
            .feature_reports
            .iter()
            .find(|feature| feature.feature_id == "swarm.responsiveness")
            .expect("swarm responsiveness feature report");
        assert_eq!(swarm_report.final_state, FeatureState::Hidden);
        assert!(report.findings.iter().any(|finding| {
            finding.feature_id == "swarm.responsiveness"
                && finding.finding_id.contains("missing_required_lane")
                && finding.controlling_lane.as_deref() == Some("swarm_tail_latency")
                && finding.remediation_id.as_deref() == Some("bd-rchk0.53.5")
        }));
    }

    #[test]
    fn canonical_release_gate_policy_fails_closed_on_missing_adaptive_runtime() {
        let policy = load_release_gate_policy(&canonical_policy_path()).expect("canonical policy");
        let mut proof = passing_proof();
        proof
            .lanes
            .retain(|lane| lane.lane_id != "adaptive_runtime");
        proof.totals.lanes = proof.lanes.len();
        proof.totals.pass = proof.lanes.len();

        let report = evaluate_release_gates(&policy, &proof);

        assert!(!report.valid);
        let swarm_report = report
            .feature_reports
            .iter()
            .find(|feature| feature.feature_id == "swarm.responsiveness")
            .expect("swarm responsiveness feature report");
        assert_eq!(swarm_report.final_state, FeatureState::Hidden);
        assert!(report.findings.iter().any(|finding| {
            finding.feature_id == "swarm.responsiveness"
                && finding.finding_id.contains("missing_required_lane")
                && finding.controlling_lane.as_deref() == Some("adaptive_runtime")
                && finding.remediation_id.as_deref() == Some("bd-jv6pj.6")
        }));
    }

    #[test]
    fn canonical_release_gate_policy_names_rejected_adaptive_runtime_run() {
        let policy = load_release_gate_policy(&canonical_policy_path()).expect("canonical policy");
        let mut proof = passing_proof();
        let lane = proof
            .lanes
            .iter_mut()
            .find(|lane| lane.lane_id == "adaptive_runtime")
            .expect("adaptive runtime lane");
        lane.status = ProofBundleOutcome::Skip;
        lane.metadata.insert(
            "scenario_id".to_owned(),
            "adaptive_runtime_local_smoke".to_owned(),
        );
        lane.metadata.insert(
            "run_id".to_owned(),
            "adaptive-runtime-run-local-smoke".to_owned(),
        );
        lane.metadata.insert(
            "release_claim_state".to_owned(),
            "small_host_smoke".to_owned(),
        );
        lane.metadata.insert(
            "host_classification".to_owned(),
            "below_large_host_floor".to_owned(),
        );
        lane.metadata
            .insert("cleanup_status".to_owned(), "clean".to_owned());
        set_lane_status(&mut proof, "adaptive_runtime", ProofBundleOutcome::Skip);

        let report = evaluate_release_gates(&policy, &proof);

        assert!(!report.valid);
        assert!(report.findings.iter().any(|finding| {
            finding.feature_id == "swarm.responsiveness"
                && finding.controlling_lane.as_deref() == Some("adaptive_runtime")
                && finding
                    .transition_reason
                    .contains("scenario_id=adaptive_runtime_local_smoke")
                && finding
                    .transition_reason
                    .contains("run_id=adaptive-runtime-run-local-smoke")
                && finding
                    .transition_reason
                    .contains("release_claim_state=small_host_smoke")
        }));
    }

    #[test]
    fn render_release_gate_markdown_canonical_missing_swarm_p99_snapshot() {
        let policy = load_release_gate_policy(&canonical_policy_path()).expect("canonical policy");
        let mut proof = passing_proof();
        proof
            .lanes
            .retain(|lane| lane.lane_id != "swarm_tail_latency");
        proof.totals.lanes = proof.lanes.len();
        proof.totals.pass = proof.lanes.len();

        let report = evaluate_release_gates(&policy, &proof);
        assert!(!report.valid);
        assert!(!report.release_ready);
        assert!(report.findings.iter().any(|finding| {
            finding.feature_id == "swarm.responsiveness"
                && finding.controlling_lane.as_deref() == Some("swarm_tail_latency")
                && finding.remediation_id.as_deref() == Some("bd-rchk0.53.5")
        }));

        let markdown = render_release_gate_markdown(&report);
        insta::assert_snapshot!(
            "render_release_gate_markdown_canonical_missing_swarm_p99",
            markdown
        );
    }

    #[test]
    fn markdown_renders_feature_states_and_findings() {
        let mut proof = passing_proof();
        proof.totals.pass = 8;
        let report = evaluate_release_gates(&sample_policy(), &proof);
        let markdown = render_release_gate_markdown(&report);
        assert!(markdown.contains("FrankenFS Release Gate"));
        assert!(markdown.contains("writeback_cache"));
        assert!(markdown.contains("threshold"));
    }

    /// bd-4lro0 — golden-output snapshot for
    /// `render_release_gate_markdown` on the deterministic
    /// `evaluate_release_gates(&sample_policy(), &proof)` fixture
    /// (passing_proof with totals.pass = 8 to deliberately fail the
    /// pass_lanes >= 9 threshold and produce a single
    /// `threshold_failure` finding).
    ///
    /// Pins:
    ///   * the title line `# FrankenFS Release Gate`
    ///   * the 6-bullet metadata header (Policy / Bundle / Valid /
    ///     Release ready / Diagnostics / Reproduction)
    ///   * the Feature States section with its 6-column table
    ///   * the Generated Wording section
    ///   * the Findings section with its 6-column table
    ///
    /// Substring-only assertions in
    /// `markdown_renders_feature_states_and_findings` cannot detect
    /// column reorders, section ordering swaps, or table-cell drift;
    /// this snapshot does. Sixth in the golden-snapshot series for
    /// ffs-harness markdown renderers.
    #[test]
    fn render_release_gate_markdown_failing_threshold_snapshot() {
        let mut proof = passing_proof();
        proof.totals.pass = 8;
        let report = evaluate_release_gates(&sample_policy(), &proof);
        let markdown = render_release_gate_markdown(&report);
        insta::assert_snapshot!("render_release_gate_markdown_failing_threshold", markdown);
    }

    #[test]
    fn release_gate_evaluation_report_json_shape() -> Result<()> {
        let mut proof = passing_proof();
        proof.totals.pass = 8;
        let report = evaluate_release_gates(&sample_policy(), &proof);

        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("release_gate_evaluation_report_json_shape", json);
        let parsed: ReleaseGateEvaluationReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    fn canonical_policy_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/release-gates/release_gate_policy_v1.json")
    }

    // C4: release-gate execution tests (lane fails closed on non-zero/absent command)

    #[test]
    fn c4_lane_fails_closed_on_nonzero_exit_code_error() {
        // C4: When proof has errors about non-zero exit code, release gate fails closed
        let mut proof = passing_proof();
        proof.valid = false;
        proof.errors.push(
            "lane conformance is marked pass but ExecutedEvidence exit_code=Some(1) (expected 0). \
             A pass lane requires exit_code==0."
                .to_owned(),
        );

        let report = evaluate_release_gates(&sample_policy(), &proof);

        // Release gate should fail closed due to invalid proof
        assert!(
            !report.valid,
            "release gate should fail when proof has exit_code errors"
        );
        // Feature should be disabled due to invalid bundle
        assert_eq!(
            report.feature_reports[0].final_state,
            FeatureState::Disabled,
            "feature should be disabled when proof has exit_code errors"
        );
        // Findings should mention proof bundle errors
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.transition_reason.contains("proof bundle")
                    || f.transition_reason.contains("errors")),
            "findings should show proof bundle validation failure: {:?}",
            report.findings
        );
    }

    #[test]
    fn c4_lane_fails_closed_on_absent_evidence_error() {
        // C4: When proof has errors about missing evidence, release gate fails closed
        let mut proof = passing_proof();
        proof.valid = false;
        proof.errors.push(
            "lane fuse is marked pass but has no ExecutedEvidence. \
             A pass lane for an executable lane requires fresh executed evidence, \
             not just checked-in artifact hashes."
                .to_owned(),
        );

        let report = evaluate_release_gates(&sample_policy(), &proof);

        // Release gate should fail closed due to invalid proof
        assert!(
            !report.valid,
            "release gate should fail when proof has missing evidence errors"
        );
        // Feature should be disabled due to invalid bundle
        assert_eq!(
            report.feature_reports[0].final_state,
            FeatureState::Disabled,
            "feature should be disabled when proof has missing evidence errors"
        );
    }

    #[test]
    fn c4_lane_pass_requires_valid_proof_bundle() {
        // C4: A lane cannot be pass without a valid proof bundle
        let mut proof = passing_proof();
        proof.valid = false; // Mark proof invalid
        proof
            .errors
            .push("proof bundle validation failed".to_owned());

        let report = evaluate_release_gates(&sample_policy(), &proof);

        // Release gate must fail closed
        assert!(
            !report.valid,
            "release gate must fail when proof bundle is invalid"
        );

        // When proof is invalid, features should downgrade
        assert!(
            report.feature_reports[0].final_state < FeatureState::Validated,
            "feature state should be below Validated when proof is invalid"
        );
    }
}
