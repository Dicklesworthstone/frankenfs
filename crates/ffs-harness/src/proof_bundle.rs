#![allow(clippy::too_many_lines)]

//! Versioned proof-bundle validation for `bd-rchk0.5.4.1`.
//!
//! Proof bundles are offline release-readiness packs: they preserve the raw
//! logs, summaries, gate inputs, artifact hashes, runtime fingerprint, and
//! redaction policy needed to inspect a readiness claim without a live build
//! tree.

use crate::adaptive_runtime_manifest::{
    AdaptiveRuntimeReleaseClaimState, AdaptiveRuntimeRunnerClassification,
};
use crate::executed_evidence::{ExecutedEvidence, ExecutionOutcome, HostClass};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const PROOF_BUNDLE_SCHEMA_VERSION: u32 = 1;
pub const REQUIRED_PROOF_BUNDLE_LANES: [&str; 14] = [
    "conformance",
    "xfstests",
    "fuse",
    "differential_oracle",
    "repair_lab",
    "crash_replay",
    "performance",
    "swarm_workload_harness",
    "swarm_tail_latency",
    "writeback_cache",
    "scrub_repair_status",
    "known_deferrals",
    "release_gates",
    "adaptive_runtime",
];

const EXECUTABLE_PROOF_BUNDLE_LANES: [&str; 4] =
    ["conformance", "fuse", "repair_lab", "crash_replay"];

/// C3: Lanes that require special permissions or infrastructure to execute.
/// These are labeled documentation-only until G1-G4 beads enable execution.
const DOCUMENTATION_ONLY_LANES: [&str; 1] = ["xfstests"];

/// C3: Lanes that are deferred for V1.x (not yet executable).
const DEFERRED_LANES: [&str; 0] = [];

/// C3: Lane execution classification.
///
/// Determines whether a lane can contribute 'pass' based on execution capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneExecutionClass {
    /// Lane requires ExecutedEvidence with exit_code==0 to pass.
    Executable,
    /// Lane cannot be executed on typical hosts (permissioned infrastructure).
    /// Cannot contribute 'pass' until G1-G4 beads enable execution.
    DocumentationOnly,
    /// Lane execution deferred to V1.x (not yet implemented).
    /// Cannot contribute 'pass'.
    Deferred,
    /// Lane uses alternative verification (swarm, adaptive_runtime, etc.).
    AlternativeVerification,
}

impl LaneExecutionClass {
    /// Classify a lane by its ID.
    #[must_use]
    pub fn classify(lane_id: &str) -> Self {
        if EXECUTABLE_PROOF_BUNDLE_LANES.contains(&lane_id) {
            Self::Executable
        } else if DOCUMENTATION_ONLY_LANES.contains(&lane_id) {
            Self::DocumentationOnly
        } else if DEFERRED_LANES.contains(&lane_id) {
            Self::Deferred
        } else {
            Self::AlternativeVerification
        }
    }

    /// Whether this lane can contribute 'pass' to release readiness.
    #[must_use]
    pub const fn can_contribute_pass(self) -> bool {
        match self {
            Self::Executable | Self::AlternativeVerification => true,
            Self::DocumentationOnly | Self::Deferred => false,
        }
    }

    /// Label for display.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Executable => "executable",
            Self::DocumentationOnly => "documentation_only",
            Self::Deferred => "deferred",
            Self::AlternativeVerification => "alternative_verification",
        }
    }
}

const EXECUTED_EVIDENCE_COMMAND_KEY: &str = "executed_evidence_command";
const EXECUTED_EVIDENCE_ARGS_JSON_KEY: &str = "executed_evidence_args_json";
const SWARM_WORKLOAD_HARNESS_LANE: &str = "swarm_workload_harness";
const SWARM_TAIL_LATENCY_LANE: &str = "swarm_tail_latency";
const SWARM_VALIDATOR_REPORT_ROLE: &str = "swarm_validator_report";
const SWARM_P99_ATTRIBUTION_ROLE: &str = "p99_attribution_ledger";
const ADAPTIVE_RUNTIME_LANE: &str = "adaptive_runtime";
const ADAPTIVE_RUNTIME_VALIDATOR_REPORT_ROLE: &str = "adaptive_runtime_validator_report";
const ADAPTIVE_RUNTIME_RUNNER_REPORT_ROLE: &str = "adaptive_runtime_runner_report";
const PERMISSIONED_CAMPAIGN_HANDOFF_ARTIFACT_ROLE: &str = "permissioned_campaign_handoff_packet";
const PERMISSIONED_CAMPAIGN_BROKER_REPORT_ROLE: &str = "permissioned_campaign_broker_report";
const PERMISSIONED_CAMPAIGN_PACKET_STATUS_KEY: &str = "permissioned_campaign_packet_status";
const PERMISSIONED_CAMPAIGN_PRODUCT_EVIDENCE_KEY: &str =
    "permissioned_campaign_product_evidence_claim";
const PERMISSIONED_CAMPAIGN_READY_STATUS: &str = "ready_for_operator_approval";
const PERMISSIONED_CAMPAIGN_NO_PRODUCT_EVIDENCE: &str = "none";

const PRESERVED_REDACTION_FIELDS: [&str; 5] = [
    "reproduction_command",
    "git_sha",
    "bundle_id",
    "artifact_paths",
    "scenario_ids",
];
const FORBIDDEN_ENV_SECRET_MARKERS: [&str; 8] = [
    "AWS_SECRET_ACCESS_KEY=",
    "GITHUB_TOKEN=",
    "SECRET_TOKEN=",
    "SECRET_KEY=",
    "API_KEY=",
    "ACCESS_TOKEN=",
    "AUTH_TOKEN=",
    "PASSWORD=",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBundleValidationConfig {
    pub manifest_path: PathBuf,
    pub current_git_sha: Option<String>,
    pub max_age_days: Option<u64>,
    pub execute_configured_lanes: bool,
}

impl ProofBundleValidationConfig {
    #[must_use]
    pub fn new(manifest_path: impl Into<PathBuf>) -> Self {
        Self {
            manifest_path: manifest_path.into(),
            current_git_sha: None,
            max_age_days: None,
            execute_configured_lanes: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleManifest {
    pub schema_version: u32,
    pub bundle_id: String,
    pub generated_at: String,
    pub git_sha: String,
    pub toolchain: String,
    pub kernel: String,
    pub mount_capability: String,
    pub required_lanes: Vec<String>,
    pub lanes: Vec<ProofBundleLane>,
    #[serde(default)]
    pub redaction: ProofBundleRedactionPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<ProofBundleIntegrityPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleLane {
    pub lane_id: String,
    pub status: ProofBundleOutcome,
    pub raw_log_path: String,
    #[serde(default)]
    pub raw_log_sha256: String,
    pub summary_path: String,
    pub scenario_ids: Vec<String>,
    pub gate_inputs: Vec<String>,
    pub artifacts: Vec<ProofBundleArtifact>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBundleOutcome {
    Pass,
    Fail,
    Skip,
    Error,
}

impl ProofBundleOutcome {
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
pub struct ProofBundleArtifact {
    pub path: String,
    pub sha256: String,
    pub redacted: bool,
    pub role: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleRedactionPolicy {
    pub redacted_fields: Vec<String>,
    pub preserved_fields: Vec<String>,
    pub reproduction_command: String,
    #[serde(default = "default_redaction_policy_version")]
    pub policy_version: String,
    #[serde(default = "default_redacted_value_placeholder")]
    pub redacted_value_placeholder: String,
    #[serde(default)]
    pub forbidden_unredacted_markers: Vec<String>,
    #[serde(default)]
    pub require_placeholder_in_redacted_artifacts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleIntegrityPolicy {
    pub artifact_hash_chain_sha256: String,
    pub artifact_count: usize,
    pub redaction_policy_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleValidationReport {
    pub schema_version: u32,
    pub bundle_id: String,
    pub manifest_path: String,
    pub valid: bool,
    pub totals: ProofBundleTotals,
    pub missing_required_lanes: Vec<String>,
    pub duplicate_lane_ids: Vec<String>,
    pub duplicate_scenario_ids: Vec<String>,
    pub stale_git_sha: Option<StaleProofBundleGitSha>,
    pub stale_timestamp: Option<StaleProofBundleTimestamp>,
    pub broken_links: Vec<ProofBundleBrokenLink>,
    pub raw_log_hash_mismatches: Vec<ProofBundleRawLogHashMismatch>,
    pub artifact_hash_mismatches: Vec<ProofBundleHashMismatch>,
    pub artifact_hash_chain: Option<ProofBundleHashChainReport>,
    pub artifact_reports: Vec<ProofBundleArtifactReport>,
    pub redaction_errors: Vec<String>,
    pub redaction_leaks: Vec<ProofBundleRedactionLeak>,
    pub integrity_errors: Vec<String>,
    pub lanes: Vec<ProofBundleLaneReport>,
    #[serde(default)]
    pub lane_provenance: Vec<ProofBundleLaneProvenanceReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub executed_evidence: Vec<ProofBundleExecutedEvidenceReport>,
    pub swarm_evidence: Vec<ProofBundleSwarmEvidenceReport>,
    pub adaptive_runtime_evidence: Vec<ProofBundleAdaptiveRuntimeEvidenceReport>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleTotals {
    pub pass: usize,
    pub fail: usize,
    pub skip: usize,
    pub error: usize,
    pub lanes: usize,
    pub scenarios: usize,
    pub artifacts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleProofBundleGitSha {
    pub observed: String,
    pub expected: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleProofBundleTimestamp {
    pub generated_at: String,
    pub max_age_days: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleBrokenLink {
    pub lane_id: String,
    pub field: String,
    pub path: String,
    pub diagnostic: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleRawLogHashMismatch {
    pub lane_id: String,
    pub path: String,
    pub expected_sha256: String,
    pub actual_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleHashMismatch {
    pub lane_id: String,
    pub path: String,
    pub expected_sha256: String,
    pub actual_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleHashChainReport {
    pub expected_sha256: String,
    pub observed_sha256: String,
    pub artifact_count: usize,
    pub redaction_policy_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleArtifactReport {
    pub lane_id: String,
    pub path: String,
    pub sha256: String,
    pub redacted: bool,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleRedactionLeak {
    pub lane_id: String,
    pub field: String,
    pub path: String,
    pub marker: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleLaneReport {
    pub lane_id: String,
    pub status: ProofBundleOutcome,
    pub raw_log_path: String,
    pub summary_path: String,
    pub scenario_count: usize,
    pub artifact_count: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBundleProvenanceClass {
    ExecutedProductEvidence,
    DryRunHandoff,
    SmallHostSmoke,
    CapabilityDowngrade,
    StaleArtifact,
    MissingRawLog,
    RedactionFailure,
    UnsupportedFutureScope,
}

impl ProofBundleProvenanceClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExecutedProductEvidence => "executed_product_evidence",
            Self::DryRunHandoff => "dry_run_handoff",
            Self::SmallHostSmoke => "small_host_smoke",
            Self::CapabilityDowngrade => "capability_downgrade",
            Self::StaleArtifact => "stale_artifact",
            Self::MissingRawLog => "missing_raw_log",
            Self::RedactionFailure => "redaction_failure",
            Self::UnsupportedFutureScope => "unsupported_future_scope",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBundleClaimEffect {
    StrengthensPublicClaim,
    BlocksPublicClaim,
    ExperimentalOnly,
    HandoffOnly,
    EvidenceProductionFailure,
    DoesNotStrengthenPublicClaim,
}

impl ProofBundleClaimEffect {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::StrengthensPublicClaim => "strengthens_public_claim",
            Self::BlocksPublicClaim => "blocks_public_claim",
            Self::ExperimentalOnly => "experimental_only",
            Self::HandoffOnly => "handoff_only",
            Self::EvidenceProductionFailure => "evidence_production_failure",
            Self::DoesNotStrengthenPublicClaim => "does_not_strengthen_public_claim",
        }
    }

    #[must_use]
    pub const fn strengthens_public_claim(self) -> bool {
        matches!(self, Self::StrengthensPublicClaim)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleLaneProvenanceReport {
    pub lane_id: String,
    pub status: ProofBundleOutcome,
    pub provenance_class: ProofBundleProvenanceClass,
    pub claim_effect: ProofBundleClaimEffect,
    pub artifact_roles: Vec<String>,
    pub source_command: String,
    pub git_sha: String,
    pub freshness: String,
    pub host_class: String,
    pub raw_log_path: String,
    pub raw_log_present: bool,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleExecutedEvidenceReport {
    pub lane_id: String,
    pub command: String,
    pub args: Vec<String>,
    pub exit_code: Option<i32>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub duration_ms: u64,
    pub ran_at: u64,
    pub git_sha: String,
    pub host_class: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleSwarmEvidenceReport {
    pub lane_id: String,
    pub status: ProofBundleOutcome,
    pub raw_log_path: String,
    pub host_class: String,
    pub manifest_hash: String,
    pub validator_report: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p99_attribution_artifact: Option<String>,
    pub freshness: String,
    pub release_claim: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downgrade_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleAdaptiveRuntimeEvidenceReport {
    pub lane_id: String,
    pub status: ProofBundleOutcome,
    pub raw_log_path: String,
    pub scenario_id: String,
    pub run_id: String,
    pub release_claim_state: String,
    pub freshness: String,
    pub host_classification: String,
    pub cleanup_status: String,
    pub validator_report: String,
    pub runner_report: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downgrade_reason: Option<String>,
}

#[must_use]
pub fn proof_bundle_required_lanes() -> Vec<String> {
    REQUIRED_PROOF_BUNDLE_LANES
        .iter()
        .map(|lane| (*lane).to_owned())
        .collect()
}

fn permissioned_campaign_metadata<'a>(
    lane: &'a ProofBundleLane,
    preferred_key: &str,
    fallback_key: &str,
) -> Option<&'a str> {
    lane.metadata
        .get(preferred_key)
        .or_else(|| lane.metadata.get(fallback_key))
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn default_redaction_policy_version() -> String {
    "v1".to_owned()
}

fn default_redacted_value_placeholder() -> String {
    "[REDACTED]".to_owned()
}

pub fn load_proof_bundle_manifest(path: &Path) -> Result<ProofBundleManifest> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read proof bundle {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid proof bundle JSON {}", path.display()))
}

pub fn validate_proof_bundle(
    config: &ProofBundleValidationConfig,
) -> Result<ProofBundleValidationReport> {
    let manifest = load_proof_bundle_manifest(&config.manifest_path)?;
    let bundle_root = config
        .manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let mut report = validate_proof_bundle_manifest(
        &manifest,
        bundle_root,
        &config.manifest_path,
        config.current_git_sha.as_deref(),
        config.max_age_days,
    );
    if config.execute_configured_lanes {
        attach_configured_lane_executed_evidence(
            &manifest,
            &mut report,
            config.current_git_sha.as_deref(),
        );
    }
    Ok(report)
}

#[must_use]
pub fn validate_proof_bundle_manifest(
    manifest: &ProofBundleManifest,
    bundle_root: &Path,
    manifest_path: &Path,
    current_git_sha: Option<&str>,
    max_age_days: Option<u64>,
) -> ProofBundleValidationReport {
    let mut builder = ProofBundleReportBuilder::new(manifest_path);

    builder.validate_top_level(manifest, current_git_sha, max_age_days);
    builder.validate_lanes(manifest, bundle_root);
    builder.validate_integrity_policy(manifest);
    builder.validate_redaction_policy(&manifest.redaction);
    builder.validate_redaction_contents(manifest, bundle_root);
    builder.build_lane_provenance(manifest, bundle_root);

    builder.finish(manifest)
}

#[must_use]
pub fn validate_proof_bundle_manifest_with_execution(
    manifest: &ProofBundleManifest,
    bundle_root: &Path,
    manifest_path: &Path,
    current_git_sha: Option<&str>,
    max_age_days: Option<u64>,
) -> ProofBundleValidationReport {
    let mut report = validate_proof_bundle_manifest(
        manifest,
        bundle_root,
        manifest_path,
        current_git_sha,
        max_age_days,
    );
    attach_configured_lane_executed_evidence(manifest, &mut report, current_git_sha);
    report
}

#[must_use]
pub fn render_proof_bundle_markdown(report: &ProofBundleValidationReport) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# FrankenFS Proof Bundle").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "- Bundle: `{}`", report.bundle_id).ok();
    writeln!(&mut out, "- Manifest: `{}`", report.manifest_path).ok();
    writeln!(&mut out, "- Valid: `{}`", report.valid).ok();
    writeln!(
        &mut out,
        "- Totals: pass={} fail={} skip={} error={} lanes={} scenarios={} artifacts={}",
        report.totals.pass,
        report.totals.fail,
        report.totals.skip,
        report.totals.error,
        report.totals.lanes,
        report.totals.scenarios,
        report.totals.artifacts
    )
    .ok();
    writeln!(
        &mut out,
        "- Diagnostics: missing_lanes={} duplicate_lanes={} duplicate_scenarios={} broken_links={} raw_log_hash_mismatches={} hash_mismatches={} redaction_errors={} redaction_leaks={} integrity_errors={} errors={} warnings={}",
        report.missing_required_lanes.len(),
        report.duplicate_lane_ids.len(),
        report.duplicate_scenario_ids.len(),
        report.broken_links.len(),
        report.raw_log_hash_mismatches.len(),
        report.artifact_hash_mismatches.len(),
        report.redaction_errors.len(),
        report.redaction_leaks.len(),
        report.integrity_errors.len(),
        report.errors.len(),
        report.warnings.len()
    )
    .ok();
    if let Some(chain) = &report.artifact_hash_chain {
        writeln!(
            &mut out,
            "- Artifact hash chain: observed=`{}` expected=`{}` artifacts={} redaction_policy_version=`{}`",
            chain.observed_sha256,
            chain.expected_sha256,
            chain.artifact_count,
            chain.redaction_policy_version
        )
        .ok();
    }
    writeln!(
        &mut out,
        "- Reproduction: `{}`",
        escape_markdown_table_cell(&report.reproduction_command)
    )
    .ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Lanes").ok();
    writeln!(
        &mut out,
        "| Lane | Outcome | Scenarios | Artifacts | Raw log | Summary |"
    )
    .ok();
    writeln!(&mut out, "|---|---:|---:|---:|---|---|").ok();
    for lane in &report.lanes {
        writeln!(
            &mut out,
            "| `{}` | `{}` | {} | {} | [{}]({}) | [{}]({}) |",
            lane.lane_id,
            lane.status.label(),
            lane.scenario_count,
            lane.artifact_count,
            lane.raw_log_path,
            lane.raw_log_path,
            lane.summary_path,
            lane.summary_path
        )
        .ok();
    }
    if !report.lane_provenance.is_empty() {
        writeln!(&mut out).ok();
        writeln!(&mut out, "## Lane Provenance").ok();
        writeln!(
            &mut out,
            "| Lane | Outcome | Provenance | Claim effect | Artifact roles | Source command | Git SHA | Freshness | Host class | Raw log | Rationale |"
        )
        .ok();
        writeln!(&mut out, "|---|---:|---|---|---|---|---|---|---|---|---|").ok();
        for provenance in &report.lane_provenance {
            writeln!(
                &mut out,
                "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | [{}]({}) | `{}` |",
                provenance.lane_id,
                provenance.status.label(),
                provenance.provenance_class.label(),
                provenance.claim_effect.label(),
                escape_markdown_table_cell(&provenance.artifact_roles.join(",")),
                escape_markdown_table_cell(&provenance.source_command),
                escape_markdown_table_cell(&provenance.git_sha),
                escape_markdown_table_cell(&provenance.freshness),
                escape_markdown_table_cell(&provenance.host_class),
                provenance.raw_log_path,
                provenance.raw_log_path,
                escape_markdown_table_cell(&provenance.rationale)
            )
            .ok();
        }
    }
    if !report.executed_evidence.is_empty() {
        writeln!(&mut out).ok();
        writeln!(&mut out, "## Executed Evidence").ok();
        writeln!(
            &mut out,
            "| Lane | Outcome | Exit | Command | Stdout SHA-256 | Stderr SHA-256 | Git SHA | Host class | Duration ms |"
        )
        .ok();
        writeln!(&mut out, "|---|---|---:|---|---|---|---|---|---:|").ok();
        for evidence in &report.executed_evidence {
            let exit_code = evidence
                .exit_code
                .map_or_else(|| "signal".to_owned(), |code| code.to_string());
            let command = format!("{} {}", evidence.command, evidence.args.join(" "));
            writeln!(
                &mut out,
                "| `{}` | `{}` | {} | `{}` | `{}` | `{}` | `{}` | `{}` | {} |",
                evidence.lane_id,
                escape_markdown_table_cell(&evidence.outcome),
                exit_code,
                escape_markdown_table_cell(command.trim()),
                evidence.stdout_sha256,
                evidence.stderr_sha256,
                escape_markdown_table_cell(&evidence.git_sha),
                escape_markdown_table_cell(&evidence.host_class),
                evidence.duration_ms
            )
            .ok();
        }
    }
    if !report.swarm_evidence.is_empty() {
        writeln!(&mut out).ok();
        writeln!(&mut out, "## Swarm Evidence").ok();
        writeln!(
            &mut out,
            "| Lane | Outcome | Host class | Freshness | Release claim | Manifest hash | Validator report | P99 artifact | Raw log | Downgrade/skip rationale |"
        )
        .ok();
        writeln!(&mut out, "|---|---:|---|---|---|---|---|---|---|---|").ok();
        for evidence in &report.swarm_evidence {
            let p99_artifact = evidence
                .p99_attribution_artifact
                .as_deref()
                .unwrap_or("n/a");
            let downgrade_reason = evidence.downgrade_reason.as_deref().unwrap_or("n/a");
            writeln!(
                &mut out,
                "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | [{}]({}) | `{}` |",
                evidence.lane_id,
                evidence.status.label(),
                escape_markdown_table_cell(&evidence.host_class),
                escape_markdown_table_cell(&evidence.freshness),
                escape_markdown_table_cell(&evidence.release_claim),
                evidence.manifest_hash,
                escape_markdown_table_cell(&evidence.validator_report),
                escape_markdown_table_cell(p99_artifact),
                evidence.raw_log_path,
                evidence.raw_log_path,
                escape_markdown_table_cell(downgrade_reason)
            )
            .ok();
        }
    }
    if !report.adaptive_runtime_evidence.is_empty() {
        writeln!(&mut out).ok();
        writeln!(&mut out, "## Adaptive Runtime Evidence").ok();
        writeln!(
            &mut out,
            "| Lane | Outcome | Scenario | Run | Freshness | Release claim | Host class | Cleanup | Validator report | Runner report | Raw log | Downgrade/skip rationale |"
        )
        .ok();
        writeln!(
            &mut out,
            "|---|---:|---|---|---|---|---|---|---|---|---|---|"
        )
        .ok();
        for evidence in &report.adaptive_runtime_evidence {
            let downgrade_reason = evidence.downgrade_reason.as_deref().unwrap_or("n/a");
            writeln!(
                &mut out,
                "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | [{}]({}) | `{}` |",
                evidence.lane_id,
                evidence.status.label(),
                escape_markdown_table_cell(&evidence.scenario_id),
                escape_markdown_table_cell(&evidence.run_id),
                escape_markdown_table_cell(&evidence.freshness),
                escape_markdown_table_cell(&evidence.release_claim_state),
                escape_markdown_table_cell(&evidence.host_classification),
                escape_markdown_table_cell(&evidence.cleanup_status),
                escape_markdown_table_cell(&evidence.validator_report),
                escape_markdown_table_cell(&evidence.runner_report),
                evidence.raw_log_path,
                evidence.raw_log_path,
                escape_markdown_table_cell(downgrade_reason)
            )
            .ok();
        }
    }
    if !report.errors.is_empty() {
        writeln!(&mut out).ok();
        writeln!(&mut out, "## Errors").ok();
        for error in &report.errors {
            writeln!(&mut out, "- {}", escape_markdown_table_cell(error)).ok();
        }
    }
    out
}

pub fn fail_on_proof_bundle_errors(report: &ProofBundleValidationReport) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "proof bundle validation failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        )
    }
}

pub fn sha256_file_hex(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to open artifact {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read artifact {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

struct ProofBundleReportBuilder {
    manifest_path: String,
    totals: ProofBundleTotals,
    missing_required_lanes: Vec<String>,
    duplicate_lane_ids: Vec<String>,
    duplicate_scenario_ids: Vec<String>,
    stale_git_sha: Option<StaleProofBundleGitSha>,
    stale_timestamp: Option<StaleProofBundleTimestamp>,
    broken_links: Vec<ProofBundleBrokenLink>,
    raw_log_hash_mismatches: Vec<ProofBundleRawLogHashMismatch>,
    artifact_hash_mismatches: Vec<ProofBundleHashMismatch>,
    artifact_hash_chain: Option<ProofBundleHashChainReport>,
    artifact_reports: Vec<ProofBundleArtifactReport>,
    redaction_errors: Vec<String>,
    redaction_leaks: Vec<ProofBundleRedactionLeak>,
    redaction_policy_invalid: bool,
    redaction_blocked_lane_ids: BTreeSet<String>,
    integrity_errors: Vec<String>,
    lanes: Vec<ProofBundleLaneReport>,
    lane_provenance: Vec<ProofBundleLaneProvenanceReport>,
    swarm_evidence: Vec<ProofBundleSwarmEvidenceReport>,
    adaptive_runtime_evidence: Vec<ProofBundleAdaptiveRuntimeEvidenceReport>,
    errors: Vec<String>,
    warnings: Vec<String>,
}

impl ProofBundleReportBuilder {
    fn new(manifest_path: &Path) -> Self {
        Self {
            manifest_path: manifest_path.display().to_string(),
            totals: ProofBundleTotals::default(),
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
            redaction_policy_invalid: false,
            redaction_blocked_lane_ids: BTreeSet::new(),
            integrity_errors: Vec::new(),
            lanes: Vec::new(),
            lane_provenance: Vec::new(),
            swarm_evidence: Vec::new(),
            adaptive_runtime_evidence: Vec::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn validate_top_level(
        &mut self,
        manifest: &ProofBundleManifest,
        current_git_sha: Option<&str>,
        max_age_days: Option<u64>,
    ) {
        if manifest.schema_version != PROOF_BUNDLE_SCHEMA_VERSION {
            self.errors.push(format!(
                "stale schema_version {} expected {}",
                manifest.schema_version, PROOF_BUNDLE_SCHEMA_VERSION
            ));
        }
        validate_nonempty("bundle_id", &manifest.bundle_id, &mut self.errors);
        validate_nonempty("generated_at", &manifest.generated_at, &mut self.errors);
        validate_nonempty("git_sha", &manifest.git_sha, &mut self.errors);
        validate_nonempty("toolchain", &manifest.toolchain, &mut self.errors);
        validate_nonempty("kernel", &manifest.kernel, &mut self.errors);
        validate_nonempty(
            "mount_capability",
            &manifest.mount_capability,
            &mut self.errors,
        );

        let declared_required: BTreeSet<&str> =
            manifest.required_lanes.iter().map(String::as_str).collect();
        for required in REQUIRED_PROOF_BUNDLE_LANES {
            if !declared_required.contains(required) {
                self.errors
                    .push(format!("required_lanes missing lane {required}"));
            }
        }

        if let Some(expected) = current_git_sha
            && expected != manifest.git_sha
        {
            self.stale_git_sha = Some(StaleProofBundleGitSha {
                observed: manifest.git_sha.clone(),
                expected: expected.to_owned(),
            });
            self.errors.push(format!(
                "stale git_sha {} expected {expected}",
                manifest.git_sha
            ));
        }

        match parse_utc_timestamp_seconds(&manifest.generated_at) {
            Ok(generated_seconds) => {
                if let Some(days) = max_age_days {
                    match classify_timestamp_recency(generated_seconds, days) {
                        TimestampRecency::Fresh => {}
                        TimestampRecency::Future => {
                            self.stale_timestamp = Some(StaleProofBundleTimestamp {
                                generated_at: manifest.generated_at.clone(),
                                max_age_days: days,
                            });
                            self.errors.push(format!(
                                "future generated_at {} is after the current timestamp",
                                manifest.generated_at
                            ));
                        }
                        TimestampRecency::Stale => {
                            self.stale_timestamp = Some(StaleProofBundleTimestamp {
                                generated_at: manifest.generated_at.clone(),
                                max_age_days: days,
                            });
                            self.errors.push(format!(
                                "stale generated_at {} older than {days} day(s)",
                                manifest.generated_at
                            ));
                        }
                    }
                }
            }
            Err(error) => self
                .errors
                .push(format!("generated_at must be UTC RFC3339 seconds: {error}")),
        }
    }

    fn validate_lanes(&mut self, manifest: &ProofBundleManifest, bundle_root: &Path) {
        let mut lane_ids = BTreeMap::<String, usize>::new();
        let mut scenario_ids = BTreeMap::<String, usize>::new();

        for lane in &manifest.lanes {
            *lane_ids.entry(lane.lane_id.clone()).or_default() += 1;
            self.validate_lane(lane, bundle_root, &mut scenario_ids);
        }

        self.duplicate_lane_ids = lane_ids
            .into_iter()
            .filter_map(|(lane_id, count)| (count > 1).then_some(lane_id))
            .collect();
        for lane_id in &self.duplicate_lane_ids {
            self.errors.push(format!("duplicate lane_id {lane_id}"));
        }

        self.duplicate_scenario_ids = scenario_ids
            .into_iter()
            .filter_map(|(scenario_id, count)| (count > 1).then_some(scenario_id))
            .collect();
        for scenario_id in &self.duplicate_scenario_ids {
            self.errors
                .push(format!("duplicate scenario_id {scenario_id}"));
        }

        let lane_id_set: BTreeSet<&str> = manifest
            .lanes
            .iter()
            .map(|lane| lane.lane_id.as_str())
            .collect();
        for required in REQUIRED_PROOF_BUNDLE_LANES {
            if !lane_id_set.contains(required) {
                self.missing_required_lanes.push(required.to_owned());
                self.errors
                    .push(format!("lanes missing required lane {required}"));
            }
        }
    }

    fn validate_lane(
        &mut self,
        lane: &ProofBundleLane,
        bundle_root: &Path,
        scenario_ids: &mut BTreeMap<String, usize>,
    ) {
        validate_nonempty("lane_id", &lane.lane_id, &mut self.errors);
        self.totals.lanes += 1;
        self.count_outcome(lane.status);
        self.totals.scenarios += lane.scenario_ids.len();
        self.totals.artifacts += lane.artifacts.len();

        if lane.scenario_ids.is_empty() {
            self.errors
                .push(format!("lane {} has no scenario_ids", lane.lane_id));
        }
        for scenario_id in &lane.scenario_ids {
            validate_nonempty(
                &format!("lane {} scenario_id", lane.lane_id),
                scenario_id,
                &mut self.errors,
            );
            *scenario_ids.entry(scenario_id.clone()).or_default() += 1;
        }

        if let Some(raw_log_path) = self.validate_existing_file(
            bundle_root,
            &lane.lane_id,
            "raw_log_path",
            &lane.raw_log_path,
        ) {
            self.validate_raw_log_hash(&lane.lane_id, &lane.raw_log_path, &raw_log_path, lane);
        }
        self.validate_existing_file(
            bundle_root,
            &lane.lane_id,
            "summary_path",
            &lane.summary_path,
        );

        if lane.gate_inputs.is_empty() {
            self.errors
                .push(format!("lane {} has no gate_inputs", lane.lane_id));
        }
        for gate_input in &lane.gate_inputs {
            self.validate_existing_file(bundle_root, &lane.lane_id, "gate_input", gate_input);
        }

        if lane.artifacts.is_empty() {
            self.errors
                .push(format!("lane {} has no artifacts", lane.lane_id));
        }
        for artifact in &lane.artifacts {
            self.validate_artifact(bundle_root, &lane.lane_id, artifact);
        }

        self.validate_swarm_lane_contract(lane);
        self.validate_adaptive_runtime_lane_contract(lane);
        self.validate_permissioned_campaign_broker_boundary(lane);

        self.lanes.push(ProofBundleLaneReport {
            lane_id: lane.lane_id.clone(),
            status: lane.status,
            raw_log_path: lane.raw_log_path.clone(),
            summary_path: lane.summary_path.clone(),
            scenario_count: lane.scenario_ids.len(),
            artifact_count: lane.artifacts.len(),
            metadata: lane.metadata.clone(),
        });
    }

    fn count_outcome(&mut self, outcome: ProofBundleOutcome) {
        match outcome {
            ProofBundleOutcome::Pass => self.totals.pass += 1,
            ProofBundleOutcome::Fail => self.totals.fail += 1,
            ProofBundleOutcome::Skip => self.totals.skip += 1,
            ProofBundleOutcome::Error => self.totals.error += 1,
        }
    }

    fn validate_swarm_lane_contract(&mut self, lane: &ProofBundleLane) {
        match lane.lane_id.as_str() {
            SWARM_WORKLOAD_HARNESS_LANE => {
                self.validate_swarm_common(lane);
                self.validate_swarm_artifact_reference(
                    lane,
                    "validator_report",
                    SWARM_VALIDATOR_REPORT_ROLE,
                );
                self.swarm_evidence.push(swarm_evidence_report(lane, None));
            }
            SWARM_TAIL_LATENCY_LANE => {
                self.validate_swarm_common(lane);
                self.validate_swarm_artifact_reference(
                    lane,
                    "validator_report",
                    SWARM_VALIDATOR_REPORT_ROLE,
                );
                let p99_artifact = self.validate_swarm_artifact_reference(
                    lane,
                    "p99_attribution_artifact",
                    SWARM_P99_ATTRIBUTION_ROLE,
                );
                self.swarm_evidence
                    .push(swarm_evidence_report(lane, p99_artifact));
            }
            _ => {}
        }
    }

    fn validate_adaptive_runtime_lane_contract(&mut self, lane: &ProofBundleLane) {
        if lane.lane_id != ADAPTIVE_RUNTIME_LANE {
            return;
        }

        let scenario_id = self.required_adaptive_runtime_metadata(lane, "scenario_id");
        let run_id = self.required_adaptive_runtime_metadata(lane, "run_id");
        let freshness = self.required_adaptive_runtime_metadata(lane, "freshness");
        let release_claim_state =
            self.required_adaptive_runtime_metadata(lane, "release_claim_state");
        let host_classification =
            self.required_adaptive_runtime_metadata(lane, "host_classification");
        let cleanup_status = self.required_adaptive_runtime_metadata(lane, "cleanup_status");
        let downgrade_reason = lane.metadata.get("downgrade_reason").map(String::as_str);
        let validator_report = self.validate_adaptive_runtime_artifact_reference(
            lane,
            "validator_report",
            ADAPTIVE_RUNTIME_VALIDATOR_REPORT_ROLE,
        );
        let runner_report = self.validate_adaptive_runtime_artifact_reference(
            lane,
            "runner_report",
            ADAPTIVE_RUNTIME_RUNNER_REPORT_ROLE,
        );
        let context = adaptive_runtime_lane_context(lane, scenario_id, run_id);

        if let Some(freshness) = freshness
            && freshness != "fresh"
        {
            self.errors.push(format!(
                "stale adaptive runtime artifact {context} freshness={freshness}"
            ));
        }

        if lane.status != ProofBundleOutcome::Pass {
            self.errors.push(format!(
                "adaptive runtime lane {context} observed {} expected pass",
                lane.status.label()
            ));
        }

        if let Some(release_claim_state) = release_claim_state
            && release_claim_state != AdaptiveRuntimeReleaseClaimState::AcceptedLargeHost.label()
        {
            self.errors.push(format!(
                "adaptive runtime lane {context} release_claim_state={release_claim_state} rejected; expected accepted_large_host"
            ));
        }

        if let Some(host_classification) = host_classification
            && host_classification != AdaptiveRuntimeRunnerClassification::AcceptedLargeHost.label()
        {
            self.errors.push(format!(
                "adaptive runtime lane {context} host_classification={host_classification} rejected; expected accepted_large_host"
            ));
        }

        if let Some(cleanup_status) = cleanup_status
            && cleanup_status != "clean"
        {
            self.errors.push(format!(
                "adaptive runtime lane {context} cleanup_status={cleanup_status} rejected; expected clean"
            ));
        }

        if lane.status != ProofBundleOutcome::Pass && !is_nonempty_metadata(downgrade_reason) {
            self.errors.push(format!(
                "adaptive runtime lane {context} non-pass evidence requires downgrade_reason"
            ));
        }

        self.adaptive_runtime_evidence
            .push(adaptive_runtime_evidence_report(
                lane,
                validator_report,
                runner_report,
            ));
    }

    fn validate_swarm_common(&mut self, lane: &ProofBundleLane) {
        let host_class = self.required_swarm_metadata(lane, "host_class");
        let manifest_hash = self.required_swarm_metadata(lane, "manifest_hash");
        let freshness = self.required_swarm_metadata(lane, "freshness");
        let release_claim = self.required_swarm_metadata(lane, "release_claim");
        let downgrade_reason = lane.metadata.get("downgrade_reason").map(String::as_str);

        if let Some(manifest_hash) = manifest_hash
            && !is_valid_sha256_hex(manifest_hash)
        {
            self.errors.push(format!(
                "swarm lane {} manifest_hash must be SHA-256 hex",
                lane.lane_id
            ));
        }

        if let Some(freshness) = freshness
            && freshness != "fresh"
        {
            self.errors.push(format!(
                "stale swarm artifact lane={} freshness={freshness}",
                lane.lane_id
            ));
        }

        let Some(host_class) = host_class else {
            return;
        };
        let Some(release_claim) = release_claim else {
            return;
        };

        match lane.status {
            ProofBundleOutcome::Pass => {
                if release_claim != "authoritative_large_host" {
                    self.errors.push(format!(
                        "swarm lane {} pass requires release_claim=authoritative_large_host",
                        lane.lane_id
                    ));
                }
                if !is_large_host_class(host_class) {
                    self.errors.push(format!(
                        "swarm lane {} authoritative pass requires large host_class, observed {host_class}",
                        lane.lane_id
                    ));
                }
            }
            ProofBundleOutcome::Skip => {
                if !is_small_host_smoke_claim(release_claim) {
                    self.errors.push(format!(
                        "swarm lane {} skip must use small-host smoke release_claim, observed {release_claim}",
                        lane.lane_id
                    ));
                }
                if !is_nonempty_metadata(downgrade_reason) {
                    self.errors.push(format!(
                        "swarm lane {} skip requires downgrade_reason",
                        lane.lane_id
                    ));
                }
            }
            ProofBundleOutcome::Fail | ProofBundleOutcome::Error => {
                if !matches!(release_claim, "blocked" | "failed" | "error") {
                    self.errors.push(format!(
                        "swarm lane {} {} requires blocked/failed/error release_claim, observed {release_claim}",
                        lane.lane_id,
                        lane.status.label()
                    ));
                }
                if !is_nonempty_metadata(downgrade_reason) {
                    self.errors.push(format!(
                        "swarm lane {} {} requires downgrade_reason",
                        lane.lane_id,
                        lane.status.label()
                    ));
                }
            }
        }
    }

    fn validate_permissioned_campaign_broker_boundary(&mut self, lane: &ProofBundleLane) {
        let contains_broker_artifact = lane.artifacts.iter().any(|artifact| {
            matches!(
                artifact.role.as_str(),
                PERMISSIONED_CAMPAIGN_HANDOFF_ARTIFACT_ROLE
                    | PERMISSIONED_CAMPAIGN_BROKER_REPORT_ROLE
            )
        });
        let packet_status = permissioned_campaign_metadata(
            lane,
            PERMISSIONED_CAMPAIGN_PACKET_STATUS_KEY,
            "packet_status",
        );
        let product_evidence_claim = permissioned_campaign_metadata(
            lane,
            PERMISSIONED_CAMPAIGN_PRODUCT_EVIDENCE_KEY,
            "product_evidence_claim",
        );
        if !contains_broker_artifact && packet_status.is_none() && product_evidence_claim.is_none()
        {
            return;
        }

        if contains_broker_artifact && packet_status.is_none() {
            self.errors.push(format!(
                "lane {} permissioned campaign broker artifact requires {PERMISSIONED_CAMPAIGN_PACKET_STATUS_KEY}={PERMISSIONED_CAMPAIGN_READY_STATUS}",
                lane.lane_id
            ));
        }
        if contains_broker_artifact && product_evidence_claim.is_none() {
            self.errors.push(format!(
                "lane {} permissioned campaign broker artifact requires {PERMISSIONED_CAMPAIGN_PRODUCT_EVIDENCE_KEY}={PERMISSIONED_CAMPAIGN_NO_PRODUCT_EVIDENCE}",
                lane.lane_id
            ));
        }

        if lane.status == ProofBundleOutcome::Pass {
            self.errors.push(format!(
                "lane {} contains permissioned campaign broker handoff material but is pass; broker packets are authorization handoff material only and cannot upgrade readiness claims",
                lane.lane_id
            ));
        }

        if let Some(product_evidence_claim) = product_evidence_claim
            && product_evidence_claim != PERMISSIONED_CAMPAIGN_NO_PRODUCT_EVIDENCE
        {
            self.errors.push(format!(
                "lane {} permissioned campaign product_evidence_claim={product_evidence_claim} rejected; broker packets cannot count as product evidence",
                lane.lane_id
            ));
        }

        if let Some(packet_status) = packet_status
            && packet_status != PERMISSIONED_CAMPAIGN_READY_STATUS
        {
            self.errors.push(format!(
                "lane {} permissioned campaign packet_status={packet_status} rejected; broker packet metadata must remain {PERMISSIONED_CAMPAIGN_READY_STATUS}",
                lane.lane_id
            ));
        }

        if let Some(release_claim) = lane.metadata.get("release_claim")
            && release_claim == "authoritative_large_host"
        {
            self.errors.push(format!(
                "lane {} release_claim=authoritative_large_host cannot be backed by a permissioned campaign broker packet",
                lane.lane_id
            ));
        }
    }

    fn required_swarm_metadata<'a>(
        &mut self,
        lane: &'a ProofBundleLane,
        key: &str,
    ) -> Option<&'a str> {
        match lane.metadata.get(key).map(String::as_str) {
            Some(value) if !value.trim().is_empty() => Some(value),
            _ => {
                self.errors.push(format!(
                    "swarm lane {} metadata.{key} missing",
                    lane.lane_id
                ));
                None
            }
        }
    }

    fn required_adaptive_runtime_metadata<'a>(
        &mut self,
        lane: &'a ProofBundleLane,
        key: &str,
    ) -> Option<&'a str> {
        match lane.metadata.get(key).map(String::as_str) {
            Some(value) if !value.trim().is_empty() => Some(value),
            _ => {
                self.errors.push(format!(
                    "adaptive runtime lane {} metadata.{key} missing",
                    lane.lane_id
                ));
                None
            }
        }
    }

    fn validate_swarm_artifact_reference(
        &mut self,
        lane: &ProofBundleLane,
        metadata_key: &str,
        expected_role: &str,
    ) -> Option<String> {
        let path = self.required_swarm_metadata(lane, metadata_key)?;
        let found = lane
            .artifacts
            .iter()
            .any(|artifact| artifact.path == path && artifact.role == expected_role);
        if !found {
            self.errors.push(format!(
                "swarm lane {} metadata.{metadata_key}={path} must reference artifact role {expected_role}",
                lane.lane_id
            ));
        }
        Some(path.to_owned())
    }

    fn validate_adaptive_runtime_artifact_reference(
        &mut self,
        lane: &ProofBundleLane,
        metadata_key: &str,
        expected_role: &str,
    ) -> Option<String> {
        let path = self.required_adaptive_runtime_metadata(lane, metadata_key)?;
        let found = lane
            .artifacts
            .iter()
            .any(|artifact| artifact.path == path && artifact.role == expected_role);
        if !found {
            self.errors.push(format!(
                "adaptive runtime lane {} metadata.{metadata_key}={path} must reference artifact role {expected_role}",
                lane.lane_id
            ));
        }
        Some(path.to_owned())
    }

    fn validate_artifact(
        &mut self,
        bundle_root: &Path,
        lane_id: &str,
        artifact: &ProofBundleArtifact,
    ) {
        self.artifact_reports.push(ProofBundleArtifactReport {
            lane_id: lane_id.to_owned(),
            path: artifact.path.clone(),
            sha256: artifact.sha256.clone(),
            redacted: artifact.redacted,
            role: artifact.role.clone(),
        });
        validate_nonempty(
            &format!("lane {lane_id} artifact role"),
            &artifact.role,
            &mut self.errors,
        );
        if !is_valid_sha256_hex(&artifact.sha256) {
            self.errors.push(format!(
                "lane {lane_id} artifact {} has invalid sha256",
                artifact.path
            ));
            return;
        }

        let Some(path) =
            self.validate_existing_file(bundle_root, lane_id, "artifact", &artifact.path)
        else {
            return;
        };

        match sha256_file_hex(&path) {
            Ok(actual) if actual == artifact.sha256 => {}
            Ok(actual) => {
                self.artifact_hash_mismatches.push(ProofBundleHashMismatch {
                    lane_id: lane_id.to_owned(),
                    path: artifact.path.clone(),
                    expected_sha256: artifact.sha256.clone(),
                    actual_sha256: actual.clone(),
                });
                self.errors.push(format!(
                    "artifact hash mismatch lane={lane_id} path={} expected={} actual={actual}",
                    artifact.path, artifact.sha256
                ));
            }
            Err(error) => self.errors.push(format!(
                "failed to hash lane {lane_id} artifact {}: {error:#}",
                artifact.path
            )),
        }
    }

    fn validate_raw_log_hash(
        &mut self,
        lane_id: &str,
        raw_log_path: &str,
        path: &Path,
        lane: &ProofBundleLane,
    ) {
        if !is_valid_sha256_hex(&lane.raw_log_sha256) {
            self.errors.push(format!(
                "lane {lane_id} raw_log_sha256 for {raw_log_path} must be SHA-256 hex"
            ));
            return;
        }

        match sha256_file_hex(path) {
            Ok(actual) if actual == lane.raw_log_sha256 => {}
            Ok(actual) => {
                self.raw_log_hash_mismatches
                    .push(ProofBundleRawLogHashMismatch {
                        lane_id: lane_id.to_owned(),
                        path: raw_log_path.to_owned(),
                        expected_sha256: lane.raw_log_sha256.clone(),
                        actual_sha256: actual.clone(),
                    });
                self.errors.push(format!(
                    "raw log hash mismatch lane={lane_id} path={raw_log_path} expected={} actual={actual}",
                    lane.raw_log_sha256
                ));
            }
            Err(error) => self.errors.push(format!(
                "failed to hash lane {lane_id} raw log {raw_log_path}: {error:#}"
            )),
        }
    }

    fn validate_existing_file(
        &mut self,
        bundle_root: &Path,
        lane_id: &str,
        field: &str,
        raw_path: &str,
    ) -> Option<PathBuf> {
        match confined_existing_file_path(bundle_root, raw_path) {
            Ok(path) => Some(path),
            Err(error) => {
                let diagnostic = error.to_string();
                self.broken_links.push(ProofBundleBrokenLink {
                    lane_id: lane_id.to_owned(),
                    field: field.to_owned(),
                    path: raw_path.to_owned(),
                    diagnostic: diagnostic.clone(),
                });
                if diagnostic == "file does not exist" {
                    self.errors.push(format!(
                        "broken link lane={lane_id} field={field} path={raw_path}"
                    ));
                } else {
                    self.errors.push(format!(
                        "lane {lane_id} {field} path {raw_path:?} invalid: {diagnostic}"
                    ));
                }
                None
            }
        }
    }

    fn validate_integrity_policy(&mut self, manifest: &ProofBundleManifest) {
        let Some(integrity) = &manifest.integrity else {
            self.warnings
                .push("proof bundle has no artifact hash-chain integrity policy".to_owned());
            return;
        };

        validate_nonempty(
            "integrity.redaction_policy_version",
            &integrity.redaction_policy_version,
            &mut self.errors,
        );
        let observed_sha256 = artifact_hash_chain_sha256(manifest);
        self.artifact_hash_chain = Some(ProofBundleHashChainReport {
            expected_sha256: integrity.artifact_hash_chain_sha256.clone(),
            observed_sha256: observed_sha256.clone(),
            artifact_count: manifest_artifact_count(manifest),
            redaction_policy_version: integrity.redaction_policy_version.clone(),
        });

        if !is_valid_sha256_hex(&integrity.artifact_hash_chain_sha256) {
            self.integrity_errors
                .push("integrity artifact_hash_chain_sha256 must be SHA-256 hex".to_owned());
        } else if integrity.artifact_hash_chain_sha256 != observed_sha256 {
            self.integrity_errors.push(format!(
                "artifact hash-chain mismatch expected={} observed={observed_sha256}",
                integrity.artifact_hash_chain_sha256
            ));
        }

        let observed_artifact_count = manifest_artifact_count(manifest);
        if integrity.artifact_count != observed_artifact_count {
            self.integrity_errors.push(format!(
                "integrity artifact_count {} observed {observed_artifact_count}",
                integrity.artifact_count
            ));
        }
        if integrity.redaction_policy_version != manifest.redaction.policy_version {
            self.integrity_errors.push(format!(
                "integrity redaction_policy_version {} observed {}",
                integrity.redaction_policy_version, manifest.redaction.policy_version
            ));
        }

        for error in &self.integrity_errors {
            self.errors.push(error.clone());
        }
    }

    fn validate_redaction_policy(&mut self, policy: &ProofBundleRedactionPolicy) {
        self.validate_redaction_nonempty(
            "redaction.reproduction_command",
            &policy.reproduction_command,
        );
        self.validate_redaction_nonempty("redaction.policy_version", &policy.policy_version);
        self.validate_redaction_nonempty(
            "redaction.redacted_value_placeholder",
            &policy.redacted_value_placeholder,
        );
        if !policy
            .reproduction_command
            .contains("validate-proof-bundle")
        {
            self.push_redaction_policy_error(
                "redaction reproduction_command must preserve validate-proof-bundle invocation"
                    .to_owned(),
            );
        }
        if let Some(marker) = env_secret_marker(policy.reproduction_command.as_bytes()) {
            self.push_redaction_policy_error(format!(
                "redaction reproduction_command contains unredacted environment secret marker {marker}"
            ));
        }

        let preserved: BTreeSet<&str> =
            policy.preserved_fields.iter().map(String::as_str).collect();
        let redacted: BTreeSet<&str> = policy.redacted_fields.iter().map(String::as_str).collect();

        for field in PRESERVED_REDACTION_FIELDS {
            if !preserved.contains(field) {
                self.push_redaction_policy_error(format!(
                    "redaction preserved_fields missing required field {field}"
                ));
            }
            if redacted.contains(field) {
                self.push_redaction_policy_error(format!(
                    "redaction may not remove required field {field}"
                ));
            }
        }

        for error in &self.redaction_errors {
            if !self.errors.contains(error) {
                self.errors.push(error.clone());
            }
        }
    }

    fn validate_redaction_nonempty(&mut self, field: &str, value: &str) {
        if value.trim().is_empty() {
            self.push_redaction_policy_error(format!("{field} must not be empty"));
        }
    }

    fn push_redaction_policy_error(&mut self, error: String) {
        self.redaction_policy_invalid = true;
        self.redaction_errors.push(error);
    }

    fn validate_redaction_contents(&mut self, manifest: &ProofBundleManifest, bundle_root: &Path) {
        if manifest.redaction.forbidden_unredacted_markers.is_empty()
            && !manifest.redaction.require_placeholder_in_redacted_artifacts
        {
            return;
        }

        for lane in &manifest.lanes {
            self.scan_redaction_file(
                bundle_root,
                &lane.lane_id,
                "raw_log_path",
                &lane.raw_log_path,
                &manifest.redaction,
                false,
            );
            self.scan_redaction_file(
                bundle_root,
                &lane.lane_id,
                "summary_path",
                &lane.summary_path,
                &manifest.redaction,
                false,
            );
            for gate_input in &lane.gate_inputs {
                self.scan_redaction_file(
                    bundle_root,
                    &lane.lane_id,
                    "gate_input",
                    gate_input,
                    &manifest.redaction,
                    false,
                );
            }
            for artifact in &lane.artifacts {
                self.scan_redaction_file(
                    bundle_root,
                    &lane.lane_id,
                    "artifact",
                    &artifact.path,
                    &manifest.redaction,
                    artifact.redacted,
                );
            }
        }

        for leak in &self.redaction_leaks {
            self.redaction_errors.push(format!(
                "redaction leak lane={} field={} path={} marker={}",
                leak.lane_id, leak.field, leak.path, leak.marker
            ));
        }
        for error in &self.redaction_errors {
            if !self.errors.contains(error) {
                self.errors.push(error.clone());
            }
        }
    }

    fn scan_redaction_file(
        &mut self,
        bundle_root: &Path,
        lane_id: &str,
        field: &str,
        raw_path: &str,
        policy: &ProofBundleRedactionPolicy,
        artifact_is_redacted: bool,
    ) {
        let Ok(path) = confined_existing_file_path(bundle_root, raw_path) else {
            return;
        };
        let Ok(bytes) = fs::read(&path) else {
            return;
        };

        for marker in &policy.forbidden_unredacted_markers {
            if marker.is_empty() {
                continue;
            }
            if bytes_contains(&bytes, marker.as_bytes()) {
                self.redaction_leaks.push(ProofBundleRedactionLeak {
                    lane_id: lane_id.to_owned(),
                    field: field.to_owned(),
                    path: raw_path.to_owned(),
                    marker: marker.clone(),
                });
                self.redaction_blocked_lane_ids.insert(lane_id.to_owned());
            }
        }
        if let Some(marker) = env_secret_marker(&bytes) {
            self.redaction_leaks.push(ProofBundleRedactionLeak {
                lane_id: lane_id.to_owned(),
                field: field.to_owned(),
                path: raw_path.to_owned(),
                marker: marker.to_owned(),
            });
            self.redaction_blocked_lane_ids.insert(lane_id.to_owned());
        }

        if policy.require_placeholder_in_redacted_artifacts
            && artifact_is_redacted
            && !bytes_contains(&bytes, policy.redacted_value_placeholder.as_bytes())
        {
            self.redaction_errors.push(format!(
                "redacted artifact lane={lane_id} path={raw_path} lacks placeholder {}",
                policy.redacted_value_placeholder
            ));
            self.redaction_blocked_lane_ids.insert(lane_id.to_owned());
        }
    }

    fn build_lane_provenance(&mut self, manifest: &ProofBundleManifest, bundle_root: &Path) {
        let manifest_is_stale = self.stale_git_sha.is_some() || self.stale_timestamp.is_some();
        for lane in &manifest.lanes {
            let redaction_failure = if self.redaction_policy_invalid {
                Some("bundle redaction policy is invalid or missing")
            } else if self.redaction_blocked_lane_ids.contains(&lane.lane_id) {
                Some("lane has unredacted sensitive content or an invalid redacted artifact")
            } else {
                None
            };
            self.lane_provenance.push(proof_bundle_lane_provenance(
                lane,
                bundle_root,
                &manifest.git_sha,
                manifest_is_stale,
                redaction_failure,
            ));
        }
    }

    fn finish(self, manifest: &ProofBundleManifest) -> ProofBundleValidationReport {
        let valid = self.errors.is_empty();
        ProofBundleValidationReport {
            schema_version: PROOF_BUNDLE_SCHEMA_VERSION,
            bundle_id: manifest.bundle_id.clone(),
            manifest_path: self.manifest_path,
            valid,
            totals: self.totals,
            missing_required_lanes: self.missing_required_lanes,
            duplicate_lane_ids: self.duplicate_lane_ids,
            duplicate_scenario_ids: self.duplicate_scenario_ids,
            stale_git_sha: self.stale_git_sha,
            stale_timestamp: self.stale_timestamp,
            broken_links: self.broken_links,
            raw_log_hash_mismatches: self.raw_log_hash_mismatches,
            artifact_hash_mismatches: self.artifact_hash_mismatches,
            artifact_hash_chain: self.artifact_hash_chain,
            artifact_reports: self.artifact_reports,
            redaction_errors: self.redaction_errors,
            redaction_leaks: self.redaction_leaks,
            integrity_errors: self.integrity_errors,
            lanes: self.lanes,
            lane_provenance: self.lane_provenance,
            executed_evidence: Vec::new(),
            swarm_evidence: self.swarm_evidence,
            adaptive_runtime_evidence: self.adaptive_runtime_evidence,
            errors: self.errors,
            warnings: self.warnings,
            reproduction_command: manifest.redaction.reproduction_command.clone(),
        }
    }
}

impl ProofBundleExecutedEvidenceReport {
    fn from_executed_evidence(lane_id: &str, evidence: &ExecutedEvidence) -> Self {
        let host_class = executed_evidence_host_class_label(evidence.host_class()).to_owned();
        let outcome = executed_evidence_outcome_label(evidence.outcome()).to_owned();
        let outcome_detail = executed_evidence_outcome_detail(evidence.outcome());
        Self {
            lane_id: lane_id.to_owned(),
            command: evidence.command().to_owned(),
            args: evidence.args().to_vec(),
            exit_code: evidence.exit_code(),
            stdout_sha256: evidence.stdout_sha256().to_owned(),
            stderr_sha256: evidence.stderr_sha256().to_owned(),
            duration_ms: evidence.duration_ms(),
            ran_at: evidence.ran_at(),
            git_sha: evidence.git_sha().to_owned(),
            host_class,
            outcome,
            outcome_detail,
        }
    }
}

fn adaptive_runtime_evidence_report(
    lane: &ProofBundleLane,
    validator_report: Option<String>,
    runner_report: Option<String>,
) -> ProofBundleAdaptiveRuntimeEvidenceReport {
    ProofBundleAdaptiveRuntimeEvidenceReport {
        lane_id: lane.lane_id.clone(),
        status: lane.status,
        raw_log_path: lane.raw_log_path.clone(),
        scenario_id: lane
            .metadata
            .get("scenario_id")
            .cloned()
            .unwrap_or_default(),
        run_id: lane.metadata.get("run_id").cloned().unwrap_or_default(),
        release_claim_state: lane
            .metadata
            .get("release_claim_state")
            .cloned()
            .unwrap_or_default(),
        freshness: lane.metadata.get("freshness").cloned().unwrap_or_default(),
        host_classification: lane
            .metadata
            .get("host_classification")
            .cloned()
            .unwrap_or_default(),
        cleanup_status: lane
            .metadata
            .get("cleanup_status")
            .cloned()
            .unwrap_or_default(),
        validator_report: validator_report.unwrap_or_default(),
        runner_report: runner_report.unwrap_or_default(),
        downgrade_reason: lane.metadata.get("downgrade_reason").cloned(),
    }
}

fn proof_bundle_lane_provenance(
    lane: &ProofBundleLane,
    bundle_root: &Path,
    git_sha: &str,
    manifest_is_stale: bool,
    redaction_failure: Option<&str>,
) -> ProofBundleLaneProvenanceReport {
    let artifact_roles = lane
        .artifacts
        .iter()
        .map(|artifact| artifact.role.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let source_command = lane_metadata_first(
        &lane.metadata,
        &[
            "source_command",
            "reproduction_command",
            "command",
            "exact_command",
        ],
    )
    .map_or_else(|| lane.gate_inputs.join(","), ToOwned::to_owned);
    let freshness = lane.metadata.get("freshness").cloned().unwrap_or_else(|| {
        if manifest_is_stale {
            "stale".to_owned()
        } else {
            "freshness_not_declared".to_owned()
        }
    });
    let host_class = lane_metadata_first(
        &lane.metadata,
        &[
            "host_class",
            "host_classification",
            "runner_class",
            "capability_class",
        ],
    )
    .unwrap_or("not_declared")
    .to_owned();
    let raw_log_present = proof_bundle_path_exists(bundle_root, &lane.raw_log_path);
    let provenance_class = classify_proof_bundle_lane_provenance(
        lane,
        &artifact_roles,
        &freshness,
        &host_class,
        &source_command,
        ProofBundleLaneProvenanceSignals {
            raw_log_present,
            manifest_is_stale,
            redaction_failure: redaction_failure.is_some(),
        },
    );
    let claim_effect = proof_bundle_claim_effect(provenance_class, lane.status);
    let rationale = redaction_failure.map_or_else(
        || proof_bundle_provenance_rationale(provenance_class, claim_effect, lane.status),
        |reason| {
            format!("{reason}; evidence production failed before product readiness can be claimed")
        },
    );

    ProofBundleLaneProvenanceReport {
        lane_id: lane.lane_id.clone(),
        status: lane.status,
        provenance_class,
        claim_effect,
        artifact_roles,
        source_command,
        git_sha: git_sha.to_owned(),
        freshness,
        host_class,
        raw_log_path: lane.raw_log_path.clone(),
        raw_log_present,
        rationale,
    }
}

fn lane_metadata_first<'a>(
    metadata: &'a BTreeMap<String, String>,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| metadata.get(*key).map(String::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn attach_configured_lane_executed_evidence(
    manifest: &ProofBundleManifest,
    report: &mut ProofBundleValidationReport,
    expected_git_sha: Option<&str>,
) {
    for lane_id in EXECUTABLE_PROOF_BUNDLE_LANES {
        let Some(lane) = manifest.lanes.iter().find(|lane| lane.lane_id == lane_id) else {
            continue;
        };
        match lane_executed_evidence_command(lane) {
            Ok((command, args)) => {
                let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
                let evidence = ExecutedEvidence::run(&command, &arg_refs);
                let launch_failed =
                    matches!(evidence.outcome(), ExecutionOutcome::LaunchFailed { .. });
                let evidence_report =
                    ProofBundleExecutedEvidenceReport::from_executed_evidence(lane_id, &evidence);
                if launch_failed {
                    report.errors.push(format!(
                        "lane {lane_id} configured ExecutedEvidence command failed to launch: {} {:?}",
                        evidence_report.command, evidence_report.args
                    ));
                }
                report.executed_evidence.push(evidence_report);
            }
            Err(error) => report.errors.push(error),
        }
    }
    // C2: validate that pass lanes have green executed evidence at expected git SHA
    let expected_sha = expected_git_sha.unwrap_or(&manifest.git_sha);
    validate_executable_lane_pass_requires_evidence(manifest, report, expected_sha);
    report.valid = report.errors.is_empty();
}

/// C2: A lane can only be 'pass' if backed by ExecutedEvidence with exit_code==0 and git_sha==HEAD.
///
/// For executable proof bundle lanes:
/// - A lane marked Pass MUST have executed evidence with outcome Success (exit_code 0)
/// - A lane marked Pass MUST have executed evidence with git_sha matching expected HEAD
/// - A lane backed only by checked-in artifact hashes (no evidence) fails validation
fn validate_executable_lane_pass_requires_evidence(
    manifest: &ProofBundleManifest,
    report: &mut ProofBundleValidationReport,
    expected_git_sha: &str,
) {
    for lane_id in EXECUTABLE_PROOF_BUNDLE_LANES {
        let Some(lane) = manifest.lanes.iter().find(|l| l.lane_id == lane_id) else {
            continue;
        };

        // Only validate pass lanes - other statuses don't require green evidence
        if lane.status != ProofBundleOutcome::Pass {
            continue;
        }

        // Find the evidence for this lane
        let evidence = report
            .executed_evidence
            .iter()
            .find(|e| e.lane_id == lane_id);

        match evidence {
            Some(ev) => {
                // Evidence exists - check exit_code is 0
                if ev.exit_code != Some(0) {
                    report.errors.push(format!(
                        "lane {} is marked pass but ExecutedEvidence exit_code={:?} (expected 0). \
                         A pass lane requires exit_code==0.",
                        lane_id, ev.exit_code
                    ));
                }
                // Check git_sha matches expected HEAD
                if ev.git_sha != expected_git_sha {
                    report.errors.push(format!(
                        "lane {} is marked pass but ExecutedEvidence git_sha={} does not match \
                         expected HEAD {}. A pass lane requires evidence from the current commit.",
                        lane_id, ev.git_sha, expected_git_sha
                    ));
                }
            }
            None => {
                // No evidence - pass lane must have evidence
                report.errors.push(format!(
                    "lane {lane_id} is marked pass but has no ExecutedEvidence. \
                     A pass lane for an executable lane requires fresh executed evidence, \
                     not just checked-in artifact hashes."
                ));
            }
        }
    }
}

fn allowlisted_lane_command_prefixes(lane_id: &str) -> &'static [&'static [&'static str]] {
    match lane_id {
        "conformance" => &[
            &["test", "-p", "ffs-harness", "--test", "conformance"],
            &[
                "test",
                "-p",
                "ffs-harness",
                "--lib",
                "tests::ext4_fixture_parses",
            ],
            &["test", "-p", "ffs-harness", "--lib", "parity::"],
            &["run", "-p", "ffs-harness", "--", "check-fixtures"],
            &[
                "run",
                "--quiet",
                "-p",
                "ffs-harness",
                "--",
                "check-fixtures",
            ],
        ],
        "fuse" => &[
            &["test", "-p", "ffs-harness", "--test", "fuse_e2e"],
            &["test", "-p", "ffs-fuse", "--lib"],
            &[
                "test",
                "-p",
                "ffs-harness",
                "--lib",
                "mounted_write_matrix::tests::",
            ],
            &[
                "run",
                "-p",
                "ffs-harness",
                "--",
                "validate-mounted-write-matrix",
            ],
            &[
                "run",
                "--quiet",
                "-p",
                "ffs-harness",
                "--",
                "validate-mounted-write-matrix",
            ],
        ],
        "repair_lab" => &[
            &["test", "-p", "ffs-repair"],
            &[
                "test",
                "-p",
                "ffs-harness",
                "--lib",
                "chaos_replay_lab::tests::",
            ],
            &[
                "run",
                "-p",
                "ffs-harness",
                "--",
                "validate-chaos-replay-lab",
            ],
            &[
                "run",
                "--quiet",
                "-p",
                "ffs-harness",
                "--",
                "validate-chaos-replay-lab",
            ],
        ],
        "crash_replay" => &[
            &["test", "-p", "ffs-harness", "--lib", "e2e::tests::"],
            &[
                "test",
                "-p",
                "ffs-harness",
                "--lib",
                "writeback_cache_audit::tests::crash_replay_oracle_accepts_complete_matrix",
            ],
            &["run", "-p", "ffs-harness", "--", "crash-replay-suite"],
            &[
                "run",
                "--quiet",
                "-p",
                "ffs-harness",
                "--",
                "crash-replay-suite",
            ],
        ],
        _ => &[],
    }
}

/// Returns the default allowlisted `(command, args)` for an executable proof-bundle lane.
#[must_use]
pub fn default_allowlisted_lane_command(lane_id: &str) -> Option<(&'static str, Vec<String>)> {
    let args: &[&str] = match lane_id {
        "conformance" => &[
            "test",
            "-p",
            "ffs-harness",
            "--lib",
            "tests::ext4_fixture_parses",
            "--",
            "--exact",
        ],
        "fuse" => &[
            "test",
            "-p",
            "ffs-harness",
            "--lib",
            "mounted_write_matrix::tests::default_matrix_validates_required_write_workload_contract",
            "--",
            "--exact",
        ],
        "repair_lab" => &[
            "test",
            "-p",
            "ffs-harness",
            "--lib",
            "chaos_replay_lab::tests::default_lab_validates_required_taxonomy_coverage",
            "--",
            "--exact",
        ],
        "crash_replay" => &[
            "test",
            "-p",
            "ffs-harness",
            "--lib",
            "writeback_cache_audit::tests::crash_replay_oracle_accepts_complete_matrix",
            "--",
            "--exact",
        ],
        _ => return None,
    };
    Some(("cargo", args.iter().map(|arg| (*arg).to_owned()).collect()))
}

fn is_safe_test_filter_token(token: &str) -> bool {
    !token.is_empty()
        && !token.starts_with('-')
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b':')
}

fn is_allowlisted_trailing_arg(token: &str) -> bool {
    matches!(
        token,
        "--" | "--exact" | "--nocapture" | "--quiet" | "--lib"
    ) || is_safe_test_filter_token(token)
}

fn matches_allowlisted_prefix(args: &[String], prefix: &[&str]) -> bool {
    if prefix.is_empty() || args.len() < prefix.len() {
        return false;
    }
    let last_idx = prefix.len() - 1;
    if args[..last_idx]
        .iter()
        .zip(&prefix[..last_idx])
        .any(|(actual, expected)| actual != expected)
    {
        return false;
    }
    let last_expected = prefix[last_idx];
    let last_actual = args[last_idx].as_str();
    let last_matches = if last_expected.ends_with("::") {
        last_actual.starts_with(last_expected) && is_safe_test_filter_token(last_actual)
    } else {
        last_actual == last_expected
    };
    if !last_matches {
        return false;
    }
    args[prefix.len()..]
        .iter()
        .all(|arg| is_allowlisted_trailing_arg(arg))
}

fn validate_allowlisted_lane_command(
    lane_id: &str,
    command: &str,
    args: &[String],
) -> std::result::Result<(), String> {
    if command != "cargo" {
        return Err(format!(
            "lane {lane_id} metadata.{EXECUTED_EVIDENCE_COMMAND_KEY}={command:?} is not in the pinned command allowlist for lane {lane_id} (expected \"cargo\")"
        ));
    }
    let prefixes = allowlisted_lane_command_prefixes(lane_id);
    if !prefixes
        .iter()
        .any(|prefix| matches_allowlisted_prefix(args, prefix))
    {
        return Err(format!(
            "lane {lane_id} metadata.{EXECUTED_EVIDENCE_ARGS_JSON_KEY}={args:?} does not match any pinned command allowlist entry for lane {lane_id}"
        ));
    }
    Ok(())
}

fn lane_executed_evidence_command(
    lane: &ProofBundleLane,
) -> std::result::Result<(String, Vec<String>), String> {
    let command = lane
        .metadata
        .get(EXECUTED_EVIDENCE_COMMAND_KEY)
        .map(String::as_str)
        .map(str::trim)
        .filter(|command| !command.is_empty())
        .ok_or_else(|| {
            format!(
                "lane {} metadata.{EXECUTED_EVIDENCE_COMMAND_KEY} missing for executable proof lane",
                lane.lane_id
            )
        })?
        .to_owned();

    let args = match lane
        .metadata
        .get(EXECUTED_EVIDENCE_ARGS_JSON_KEY)
        .map(String::as_str)
        .map(str::trim)
        .filter(|args| !args.is_empty())
    {
        Some(raw_args) => serde_json::from_str::<Vec<String>>(raw_args).map_err(|error| {
            format!(
                "lane {} metadata.{EXECUTED_EVIDENCE_ARGS_JSON_KEY} must be a JSON string array: {error}",
                lane.lane_id
            )
        })?,
        None => Vec::new(),
    };

    validate_allowlisted_lane_command(&lane.lane_id, &command, &args)?;
    Ok((command, args))
}

#[cfg(test)]
fn is_executable_proof_bundle_lane(lane_id: &str) -> bool {
    EXECUTABLE_PROOF_BUNDLE_LANES.contains(&lane_id)
}

fn executed_evidence_host_class_label(host_class: HostClass) -> &'static str {
    match host_class {
        HostClass::Full => "full",
        HostClass::Ci => "ci",
        HostClass::LocalUnprivileged => "local_unprivileged",
        HostClass::RchWorker => "rch_worker",
        HostClass::Unknown => "unknown",
    }
}

fn executed_evidence_outcome_label(outcome: &ExecutionOutcome) -> &'static str {
    match outcome {
        ExecutionOutcome::Success => "success",
        ExecutionOutcome::Failed { .. } => "failed",
        ExecutionOutcome::Signaled => "signaled",
        ExecutionOutcome::Skipped { .. } => "skipped",
        ExecutionOutcome::LaunchFailed { .. } => "launch_failed",
    }
}

fn executed_evidence_outcome_detail(outcome: &ExecutionOutcome) -> Option<String> {
    match outcome {
        ExecutionOutcome::Failed { exit_code } => Some(format!("exit_code={exit_code}")),
        ExecutionOutcome::Skipped { reason } => Some(reason.clone()),
        ExecutionOutcome::LaunchFailed { error } => Some(error.clone()),
        ExecutionOutcome::Success | ExecutionOutcome::Signaled => None,
    }
}

fn proof_bundle_path_exists(bundle_root: &Path, raw_path: &str) -> bool {
    confined_existing_file_path(bundle_root, raw_path).is_ok()
}

#[derive(Debug, Clone, Copy)]
struct ProofBundleLaneProvenanceSignals {
    raw_log_present: bool,
    manifest_is_stale: bool,
    redaction_failure: bool,
}

fn classify_proof_bundle_lane_provenance(
    lane: &ProofBundleLane,
    artifact_roles: &[String],
    freshness: &str,
    host_class: &str,
    source_command: &str,
    signals: ProofBundleLaneProvenanceSignals,
) -> ProofBundleProvenanceClass {
    if signals.redaction_failure {
        return ProofBundleProvenanceClass::RedactionFailure;
    }
    if !signals.raw_log_present {
        return ProofBundleProvenanceClass::MissingRawLog;
    }
    if signals.manifest_is_stale || freshness == "stale" {
        return ProofBundleProvenanceClass::StaleArtifact;
    }
    if contains_permissioned_campaign_handoff(lane, artifact_roles)
        || source_command.contains("--dry-run")
    {
        return ProofBundleProvenanceClass::DryRunHandoff;
    }
    if lane.lane_id == "known_deferrals"
        || metadata_value_eq(&lane.metadata, "release_claim", "unsupported_future_scope")
        || metadata_value_eq(
            &lane.metadata,
            "release_claim_state",
            "unsupported_future_scope",
        )
    {
        return ProofBundleProvenanceClass::UnsupportedFutureScope;
    }
    if has_capability_downgrade(lane, host_class) {
        return ProofBundleProvenanceClass::CapabilityDowngrade;
    }
    if metadata_value_eq(&lane.metadata, "release_claim", "small_host_smoke")
        || metadata_value_eq(&lane.metadata, "release_claim_state", "small_host_smoke")
        || matches!(host_class, "developer_smoke" | "small_host_smoke")
    {
        return ProofBundleProvenanceClass::SmallHostSmoke;
    }
    ProofBundleProvenanceClass::ExecutedProductEvidence
}

fn contains_permissioned_campaign_handoff(
    lane: &ProofBundleLane,
    artifact_roles: &[String],
) -> bool {
    artifact_roles.iter().any(|role| {
        matches!(
            role.as_str(),
            PERMISSIONED_CAMPAIGN_HANDOFF_ARTIFACT_ROLE | PERMISSIONED_CAMPAIGN_BROKER_REPORT_ROLE
        )
    }) || lane
        .metadata
        .contains_key(PERMISSIONED_CAMPAIGN_PACKET_STATUS_KEY)
        || lane
            .metadata
            .contains_key(PERMISSIONED_CAMPAIGN_PRODUCT_EVIDENCE_KEY)
}

fn has_capability_downgrade(lane: &ProofBundleLane, host_class: &str) -> bool {
    let downgrade_reason = lane
        .metadata
        .get("downgrade_reason")
        .map(String::as_str)
        .unwrap_or_default();
    metadata_value_eq(
        &lane.metadata,
        "release_claim",
        "capability_downgraded_smoke",
    ) || metadata_value_eq(
        &lane.metadata,
        "release_claim_state",
        "capability_downgraded_smoke",
    ) || host_class == "capability_downgraded_smoke"
        || downgrade_reason.contains("capability")
        || downgrade_reason.contains("unavailable")
        || downgrade_reason.contains("FUSE")
}

fn metadata_value_eq(metadata: &BTreeMap<String, String>, key: &str, expected: &str) -> bool {
    metadata
        .get(key)
        .map(String::as_str)
        .is_some_and(|value| value == expected)
}

const fn proof_bundle_claim_effect(
    provenance_class: ProofBundleProvenanceClass,
    status: ProofBundleOutcome,
) -> ProofBundleClaimEffect {
    match provenance_class {
        ProofBundleProvenanceClass::ExecutedProductEvidence => match status {
            ProofBundleOutcome::Pass => ProofBundleClaimEffect::StrengthensPublicClaim,
            ProofBundleOutcome::Fail | ProofBundleOutcome::Error => {
                ProofBundleClaimEffect::BlocksPublicClaim
            }
            ProofBundleOutcome::Skip => ProofBundleClaimEffect::DoesNotStrengthenPublicClaim,
        },
        ProofBundleProvenanceClass::DryRunHandoff => ProofBundleClaimEffect::HandoffOnly,
        ProofBundleProvenanceClass::SmallHostSmoke
        | ProofBundleProvenanceClass::CapabilityDowngrade => {
            ProofBundleClaimEffect::ExperimentalOnly
        }
        ProofBundleProvenanceClass::StaleArtifact
        | ProofBundleProvenanceClass::MissingRawLog
        | ProofBundleProvenanceClass::RedactionFailure => {
            ProofBundleClaimEffect::EvidenceProductionFailure
        }
        ProofBundleProvenanceClass::UnsupportedFutureScope => {
            ProofBundleClaimEffect::DoesNotStrengthenPublicClaim
        }
    }
}

fn proof_bundle_provenance_rationale(
    provenance_class: ProofBundleProvenanceClass,
    claim_effect: ProofBundleClaimEffect,
    status: ProofBundleOutcome,
) -> String {
    match provenance_class {
        ProofBundleProvenanceClass::ExecutedProductEvidence => format!(
            "executed product evidence with outcome={} has claim_effect={}",
            status.label(),
            claim_effect.label()
        ),
        ProofBundleProvenanceClass::DryRunHandoff => {
            "dry-run or permissioned handoff material cannot be promoted into product readiness"
                .to_owned()
        }
        ProofBundleProvenanceClass::SmallHostSmoke => {
            "small-host smoke evidence is useful for regression checks but only supports experimental claims"
                .to_owned()
        }
        ProofBundleProvenanceClass::CapabilityDowngrade => {
            "capability-downgraded evidence records an environment limitation and cannot strengthen public readiness"
                .to_owned()
        }
        ProofBundleProvenanceClass::StaleArtifact => {
            "stale proof-bundle evidence must be refreshed before it can affect readiness"
                .to_owned()
        }
        ProofBundleProvenanceClass::MissingRawLog => {
            "missing raw logs make the lane unauditable and fail evidence production".to_owned()
        }
        ProofBundleProvenanceClass::RedactionFailure => {
            "redaction or path-confinement failures make the lane unsafe to publish and fail evidence production"
                .to_owned()
        }
        ProofBundleProvenanceClass::UnsupportedFutureScope => {
            "unsupported future-scope material is tracked as deferral context only".to_owned()
        }
    }
}

fn adaptive_runtime_lane_context(
    lane: &ProofBundleLane,
    scenario_id: Option<&str>,
    run_id: Option<&str>,
) -> String {
    format!(
        "lane={} scenario_id={} run_id={}",
        lane.lane_id,
        scenario_id.unwrap_or("<missing>"),
        run_id.unwrap_or("<missing>")
    )
}

fn validate_nonempty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
}

fn swarm_evidence_report(
    lane: &ProofBundleLane,
    p99_attribution_artifact: Option<String>,
) -> ProofBundleSwarmEvidenceReport {
    ProofBundleSwarmEvidenceReport {
        lane_id: lane.lane_id.clone(),
        status: lane.status,
        raw_log_path: lane.raw_log_path.clone(),
        host_class: lane.metadata.get("host_class").cloned().unwrap_or_default(),
        manifest_hash: lane
            .metadata
            .get("manifest_hash")
            .cloned()
            .unwrap_or_default(),
        validator_report: lane
            .metadata
            .get("validator_report")
            .cloned()
            .unwrap_or_default(),
        p99_attribution_artifact,
        freshness: lane.metadata.get("freshness").cloned().unwrap_or_default(),
        release_claim: lane
            .metadata
            .get("release_claim")
            .cloned()
            .unwrap_or_default(),
        downgrade_reason: lane
            .metadata
            .get("downgrade_reason")
            .filter(|reason| !reason.trim().is_empty())
            .cloned(),
    }
}

fn is_large_host_class(host_class: &str) -> bool {
    matches!(host_class, "large_host" | "permissioned_large_host")
}

fn is_small_host_smoke_claim(release_claim: &str) -> bool {
    matches!(
        release_claim,
        "small_host_smoke" | "capability_downgraded_smoke"
    )
}

fn is_nonempty_metadata(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

fn validate_relative_path(raw: &str) -> Result<()> {
    if raw.trim().is_empty() {
        bail!("path is empty");
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        bail!("path must be relative");
    }
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => bail!("path must not contain parent traversal"),
            Component::RootDir | Component::Prefix(_) => bail!("path must be relative"),
        }
    }
    Ok(())
}

fn confined_existing_file_path(bundle_root: &Path, raw_path: &str) -> Result<PathBuf> {
    validate_relative_path(raw_path)?;
    let path = bundle_root.join(raw_path);
    if !path.is_file() {
        bail!("file does not exist");
    }

    let canonical_root = fs::canonicalize(bundle_root).with_context(|| {
        format!(
            "proof bundle root {} cannot be canonicalized",
            bundle_root.display()
        )
    })?;
    let canonical_file = fs::canonicalize(&path)
        .with_context(|| format!("path {raw_path:?} cannot be canonicalized"))?;
    if !canonical_file.starts_with(&canonical_root) {
        bail!("path escapes proof bundle root after symlink resolution");
    }
    Ok(path)
}

fn is_valid_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn manifest_artifact_count(manifest: &ProofBundleManifest) -> usize {
    manifest.lanes.iter().map(|lane| lane.artifacts.len()).sum()
}

fn artifact_hash_chain_sha256(manifest: &ProofBundleManifest) -> String {
    let mut hasher = Sha256::new();
    for lane in &manifest.lanes {
        hash_chain_part(&mut hasher, "lane");
        hash_chain_part(&mut hasher, &lane.lane_id);
        hash_chain_part(&mut hasher, "raw_log");
        hash_chain_part(&mut hasher, &lane.raw_log_path);
        hash_chain_part(&mut hasher, &lane.raw_log_sha256);
        for artifact in &lane.artifacts {
            hash_chain_part(&mut hasher, "artifact");
            hash_chain_part(&mut hasher, &artifact.path);
            hash_chain_part(&mut hasher, &artifact.sha256);
            hash_chain_part(
                &mut hasher,
                if artifact.redacted {
                    "redacted"
                } else {
                    "clear"
                },
            );
            hash_chain_part(&mut hasher, &artifact.role);
        }
    }
    hex::encode(hasher.finalize())
}

fn hash_chain_part(hasher: &mut Sha256, value: &str) {
    hasher.update(value.len().to_string().as_bytes());
    hasher.update(b":");
    hasher.update(value.as_bytes());
    hasher.update(b";");
}

fn bytes_contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn env_secret_marker(bytes: &[u8]) -> Option<&'static str> {
    FORBIDDEN_ENV_SECRET_MARKERS
        .iter()
        .copied()
        .find(|marker| bytes_contains(bytes, marker.as_bytes()))
}

fn parse_utc_timestamp_seconds(raw: &str) -> Result<i64> {
    let trimmed = raw.trim();
    let without_z = trimmed
        .strip_suffix('Z')
        .context("timestamp must end with Z")?;
    let (date, time) = without_z
        .split_once('T')
        .context("timestamp must contain T separator")?;
    let mut date_parts = date.split('-');
    let year = parse_i64_part(date_parts.next(), "year")?;
    let month = parse_i64_part(date_parts.next(), "month")?;
    let day = parse_i64_part(date_parts.next(), "day")?;
    if date_parts.next().is_some() {
        bail!("date has too many components");
    }

    let time_no_fraction = time.split_once('.').map_or(time, |(seconds, _)| seconds);
    let mut time_parts = time_no_fraction.split(':');
    let hour = parse_i64_part(time_parts.next(), "hour")?;
    let minute = parse_i64_part(time_parts.next(), "minute")?;
    let second = parse_i64_part(time_parts.next(), "second")?;
    if time_parts.next().is_some() {
        bail!("time has too many components");
    }
    validate_timestamp_ranges(month, day, hour, minute, second)?;
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn parse_i64_part(part: Option<&str>, field: &str) -> Result<i64> {
    part.context(format!("{field} missing"))?
        .parse()
        .with_context(|| format!("{field} is not an integer"))
}

fn validate_timestamp_ranges(
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> Result<()> {
    if !(1..=12).contains(&month) {
        bail!("month out of range");
    }
    if !(1..=31).contains(&day) {
        bail!("day out of range");
    }
    if !(0..=23).contains(&hour) {
        bail!("hour out of range");
    }
    if !(0..=59).contains(&minute) {
        bail!("minute out of range");
    }
    if !(0..=60).contains(&second) {
        bail!("second out of range");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimestampRecency {
    Fresh,
    Future,
    Stale,
}

fn classify_timestamp_recency(generated_seconds: i64, max_age_days: u64) -> TimestampRecency {
    let now_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let Ok(generated_seconds) = u64::try_from(generated_seconds) else {
        return TimestampRecency::Stale;
    };
    if generated_seconds > now_seconds {
        return TimestampRecency::Future;
    }
    if now_seconds - generated_seconds > max_age_days.saturating_mul(86_400) {
        TimestampRecency::Stale
    } else {
        TimestampRecency::Fresh
    }
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = if month <= 2 { year - 1 } else { year };
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn escape_markdown_table_cell(raw: &str) -> String {
    raw.replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    use tempfile::TempDir;

    struct SampleBundle {
        root: TempDir,
        manifest: ProofBundleManifest,
    }

    fn current_git_sha_for_test() -> String {
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    String::from_utf8(o.stdout)
                        .ok()
                        .map(|s| s.trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn sample_bundle() -> Result<SampleBundle> {
        let root = tempfile::tempdir()?;
        let mut lanes = Vec::new();
        for (index, lane_id) in REQUIRED_PROOF_BUNDLE_LANES.iter().enumerate() {
            let raw_log_path = format!("logs/{lane_id}.log");
            let summary_path = format!("summaries/{lane_id}.md");
            let input_path = format!("inputs/{lane_id}.json");
            let artifact_path = format!("artifacts/{lane_id}.json");
            let p99_artifact_path = format!("artifacts/{lane_id}_p99_attribution.json");
            let runner_artifact_path = format!("artifacts/{lane_id}_runner.json");

            write_file(root.path(), &raw_log_path, &format!("{lane_id} raw log\n"))?;
            write_file(root.path(), &summary_path, &format!("# {lane_id}\n"))?;
            write_file(
                root.path(),
                &input_path,
                &format!("{{\"lane\":\"{lane_id}\"}}\n"),
            )?;
            write_file(
                root.path(),
                &artifact_path,
                &format!("{{\"artifact\":\"{lane_id}\"}}\n"),
            )?;

            let raw_log_hash = sha256_file_hex(&root.path().join(&raw_log_path))?;
            let artifact_hash = sha256_file_hex(&root.path().join(&artifact_path))?;
            let status = if *lane_id == ADAPTIVE_RUNTIME_LANE {
                ProofBundleOutcome::Pass
            } else {
                match index % 4 {
                    0 => ProofBundleOutcome::Pass,
                    1 => ProofBundleOutcome::Fail,
                    2 => ProofBundleOutcome::Skip,
                    _ => ProofBundleOutcome::Error,
                }
            };
            let mut artifacts = vec![ProofBundleArtifact {
                path: artifact_path.clone(),
                sha256: artifact_hash,
                redacted: index % 2 == 0,
                role: if *lane_id == ADAPTIVE_RUNTIME_LANE {
                    ADAPTIVE_RUNTIME_VALIDATOR_REPORT_ROLE
                } else if matches!(
                    *lane_id,
                    SWARM_WORKLOAD_HARNESS_LANE | SWARM_TAIL_LATENCY_LANE
                ) {
                    SWARM_VALIDATOR_REPORT_ROLE
                } else {
                    "primary_evidence"
                }
                .to_owned(),
            }];
            let mut metadata = BTreeMap::new();
            if matches!(
                *lane_id,
                SWARM_WORKLOAD_HARNESS_LANE | SWARM_TAIL_LATENCY_LANE
            ) {
                metadata.insert("manifest_hash".to_owned(), "a".repeat(64));
                metadata.insert("validator_report".to_owned(), artifact_path.clone());
                metadata.insert("freshness".to_owned(), "fresh".to_owned());
                match status {
                    ProofBundleOutcome::Pass => {
                        metadata.insert(
                            "host_class".to_owned(),
                            "permissioned_large_host".to_owned(),
                        );
                        metadata.insert(
                            "release_claim".to_owned(),
                            "authoritative_large_host".to_owned(),
                        );
                    }
                    ProofBundleOutcome::Skip => {
                        metadata.insert("host_class".to_owned(), "developer_smoke".to_owned());
                        metadata.insert("release_claim".to_owned(), "small_host_smoke".to_owned());
                        metadata.insert(
                            "downgrade_reason".to_owned(),
                            "small host smoke cannot support release wording".to_owned(),
                        );
                    }
                    ProofBundleOutcome::Fail => {
                        metadata.insert("host_class".to_owned(), "developer_smoke".to_owned());
                        metadata.insert("release_claim".to_owned(), "failed".to_owned());
                        metadata.insert(
                            "downgrade_reason".to_owned(),
                            "swarm evidence failed and blocks release wording".to_owned(),
                        );
                    }
                    ProofBundleOutcome::Error => {
                        metadata.insert("host_class".to_owned(), "developer_smoke".to_owned());
                        metadata.insert("release_claim".to_owned(), "error".to_owned());
                        metadata.insert(
                            "downgrade_reason".to_owned(),
                            "swarm evidence errored and blocks release wording".to_owned(),
                        );
                    }
                }
            }
            if *lane_id == SWARM_TAIL_LATENCY_LANE {
                write_file(
                    root.path(),
                    &p99_artifact_path,
                    &format!("{{\"p99_attribution\":\"{lane_id}\"}}\n"),
                )?;
                let p99_artifact_hash = sha256_file_hex(&root.path().join(&p99_artifact_path))?;
                metadata.insert(
                    "p99_attribution_artifact".to_owned(),
                    p99_artifact_path.clone(),
                );
                artifacts.push(ProofBundleArtifact {
                    path: p99_artifact_path,
                    sha256: p99_artifact_hash,
                    redacted: false,
                    role: SWARM_P99_ATTRIBUTION_ROLE.to_owned(),
                });
            }
            if *lane_id == ADAPTIVE_RUNTIME_LANE {
                write_file(
                    root.path(),
                    &runner_artifact_path,
                    &format!("{{\"runner\":\"{lane_id}\"}}\n"),
                )?;
                let runner_artifact_hash =
                    sha256_file_hex(&root.path().join(&runner_artifact_path))?;
                metadata.insert(
                    "scenario_id".to_owned(),
                    "adaptive_runtime_accepted_large_host".to_owned(),
                );
                metadata.insert(
                    "run_id".to_owned(),
                    "adaptive-runtime-run-20260507T000000Z".to_owned(),
                );
                metadata.insert("freshness".to_owned(), "fresh".to_owned());
                metadata.insert(
                    "release_claim_state".to_owned(),
                    "accepted_large_host".to_owned(),
                );
                metadata.insert(
                    "host_classification".to_owned(),
                    "accepted_large_host".to_owned(),
                );
                metadata.insert("cleanup_status".to_owned(), "clean".to_owned());
                metadata.insert("validator_report".to_owned(), artifact_path.clone());
                metadata.insert("runner_report".to_owned(), runner_artifact_path.clone());
                artifacts.push(ProofBundleArtifact {
                    path: runner_artifact_path,
                    sha256: runner_artifact_hash,
                    redacted: false,
                    role: ADAPTIVE_RUNTIME_RUNNER_REPORT_ROLE.to_owned(),
                });
            }
            metadata.insert(
                "source_command".to_owned(),
                format!("cargo run -p ffs-harness -- validate-{lane_id}"),
            );
            lanes.push(ProofBundleLane {
                lane_id: (*lane_id).to_owned(),
                status,
                raw_log_path,
                raw_log_sha256: raw_log_hash,
                summary_path,
                scenario_ids: vec![format!("{lane_id}_scenario_primary")],
                gate_inputs: vec![input_path],
                artifacts,
                metadata,
            });
        }

        let mut manifest = ProofBundleManifest {
            schema_version: PROOF_BUNDLE_SCHEMA_VERSION,
            bundle_id: "proof-bundle-sample".to_owned(),
            generated_at: "2026-05-01T00:00:00Z".to_owned(),
            git_sha: "abcdef1".to_owned(),
            toolchain: "rustc 1.85.0-nightly".to_owned(),
            kernel: "Linux 6.10.0".to_owned(),
            mount_capability: "available".to_owned(),
            required_lanes: proof_bundle_required_lanes(),
            lanes,
            redaction: ProofBundleRedactionPolicy {
                redacted_fields: vec!["hostname".to_owned(), "api_key".to_owned()],
                preserved_fields: PRESERVED_REDACTION_FIELDS
                    .iter()
                    .map(|field| (*field).to_owned())
                    .collect(),
                reproduction_command:
                    "cargo run -p ffs-harness -- validate-proof-bundle --bundle manifest.json"
                        .to_owned(),
                policy_version: "redaction-v1".to_owned(),
                redacted_value_placeholder: "[REDACTED]".to_owned(),
                forbidden_unredacted_markers: vec!["SECRET_TOKEN".to_owned()],
                require_placeholder_in_redacted_artifacts: false,
            },
            integrity: None,
        };
        manifest.integrity = Some(integrity_for(&manifest));
        Ok(SampleBundle { root, manifest })
    }

    fn integrity_for(manifest: &ProofBundleManifest) -> ProofBundleIntegrityPolicy {
        ProofBundleIntegrityPolicy {
            artifact_hash_chain_sha256: artifact_hash_chain_sha256(manifest),
            artifact_count: manifest_artifact_count(manifest),
            redaction_policy_version: manifest.redaction.policy_version.clone(),
        }
    }

    fn write_file(root: &Path, relative: &str, text: &str) -> Result<()> {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, text)?;
        Ok(())
    }

    fn validate_sample(sample: &SampleBundle) -> ProofBundleValidationReport {
        validate_proof_bundle_manifest(
            &sample.manifest,
            sample.root.path(),
            &sample.root.path().join("manifest.json"),
            Some("abcdef1"),
            Some(10_000),
        )
    }

    fn validate_sample_with_execution(sample: &SampleBundle) -> ProofBundleValidationReport {
        // For execution tests, use the real git SHA so evidence matches
        let current_sha = current_git_sha_for_test();
        let mut manifest = sample.manifest.clone();
        manifest.git_sha = current_sha.clone();
        // Recalculate integrity since git_sha changed
        manifest.integrity = Some(integrity_for(&manifest));
        validate_proof_bundle_manifest_with_execution(
            &manifest,
            sample.root.path(),
            &sample.root.path().join("manifest.json"),
            Some(&current_sha),
            Some(10_000),
        )
    }

    fn configure_executable_lane_commands(manifest: &mut ProofBundleManifest) -> Result<()> {
        for lane in &mut manifest.lanes {
            if let Some((command, args)) = default_allowlisted_lane_command(&lane.lane_id) {
                lane.metadata
                    .insert(EXECUTED_EVIDENCE_COMMAND_KEY.to_owned(), command.to_owned());
                lane.metadata.insert(
                    EXECUTED_EVIDENCE_ARGS_JSON_KEY.to_owned(),
                    serde_json::to_string(&args)?,
                );
            }
        }
        Ok(())
    }

    fn first_lane_mut(manifest: &mut ProofBundleManifest) -> Result<&mut ProofBundleLane> {
        manifest
            .lanes
            .first_mut()
            .context("fixture manifest has at least one lane")
    }

    fn second_lane_mut(manifest: &mut ProofBundleManifest) -> Result<&mut ProofBundleLane> {
        manifest
            .lanes
            .get_mut(1)
            .context("fixture manifest has at least two lanes")
    }

    fn first_artifact_mut(lane: &mut ProofBundleLane) -> Result<&mut ProofBundleArtifact> {
        lane.artifacts
            .first_mut()
            .context("fixture lane has at least one artifact")
    }

    fn first_scenario_id_mut(lane: &mut ProofBundleLane) -> Result<&mut String> {
        lane.scenario_ids
            .first_mut()
            .context("fixture lane has at least one scenario id")
    }

    fn integrity_mut(
        manifest: &mut ProofBundleManifest,
    ) -> Result<&mut ProofBundleIntegrityPolicy> {
        manifest
            .integrity
            .as_mut()
            .context("fixture manifest has integrity policy")
    }

    fn artifact_report_by_lane<'a>(
        report: &'a ProofBundleValidationReport,
        lane_id: &str,
    ) -> Result<&'a ProofBundleArtifactReport> {
        report
            .artifact_reports
            .iter()
            .find(|artifact| artifact.lane_id == lane_id)
            .with_context(|| format!("artifact report should exist for lane {lane_id}"))
    }

    fn lane_provenance_by_lane<'a>(
        report: &'a ProofBundleValidationReport,
        lane_id: &str,
    ) -> Result<&'a ProofBundleLaneProvenanceReport> {
        report
            .lane_provenance
            .iter()
            .find(|provenance| provenance.lane_id == lane_id)
            .with_context(|| format!("lane provenance should exist for {lane_id}"))
    }

    fn swarm_evidence_by_lane<'a>(
        report: &'a ProofBundleValidationReport,
        lane_id: &str,
    ) -> Result<&'a ProofBundleSwarmEvidenceReport> {
        report
            .swarm_evidence
            .iter()
            .find(|evidence| evidence.lane_id == lane_id)
            .with_context(|| format!("swarm evidence should exist for lane {lane_id}"))
    }

    fn adaptive_runtime_evidence_by_lane<'a>(
        report: &'a ProofBundleValidationReport,
        lane_id: &str,
    ) -> Result<&'a ProofBundleAdaptiveRuntimeEvidenceReport> {
        report
            .adaptive_runtime_evidence
            .iter()
            .find(|evidence| evidence.lane_id == lane_id)
            .with_context(|| format!("adaptive runtime evidence should exist for lane {lane_id}"))
    }

    fn executed_evidence_by_lane<'a>(
        report: &'a ProofBundleValidationReport,
        lane_id: &str,
    ) -> Result<&'a ProofBundleExecutedEvidenceReport> {
        report
            .executed_evidence
            .iter()
            .find(|evidence| evidence.lane_id == lane_id)
            .with_context(|| format!("executed evidence should exist for lane {lane_id}"))
    }

    fn swarm_lane_mut<'a>(
        manifest: &'a mut ProofBundleManifest,
        lane_id: &str,
    ) -> Result<&'a mut ProofBundleLane> {
        manifest
            .lanes
            .iter_mut()
            .find(|lane| lane.lane_id == lane_id)
            .with_context(|| format!("proof bundle lane should exist: {lane_id}"))
    }

    fn set_swarm_lane_for_large_host(
        manifest: &mut ProofBundleManifest,
        lane_id: &str,
    ) -> Result<()> {
        let lane = swarm_lane_mut(manifest, lane_id)?;
        lane.status = ProofBundleOutcome::Pass;
        lane.metadata.insert(
            "host_class".to_owned(),
            "permissioned_large_host".to_owned(),
        );
        lane.metadata.insert(
            "release_claim".to_owned(),
            "authoritative_large_host".to_owned(),
        );
        lane.metadata.remove("downgrade_reason");
        Ok(())
    }

    fn set_swarm_lane_for_small_host_smoke(
        manifest: &mut ProofBundleManifest,
        lane_id: &str,
    ) -> Result<()> {
        let lane = swarm_lane_mut(manifest, lane_id)?;
        lane.status = ProofBundleOutcome::Skip;
        lane.metadata
            .insert("host_class".to_owned(), "developer_smoke".to_owned());
        lane.metadata
            .insert("release_claim".to_owned(), "small_host_smoke".to_owned());
        lane.metadata.insert(
            "downgrade_reason".to_owned(),
            "developer smoke host cannot support release wording".to_owned(),
        );
        Ok(())
    }

    fn adaptive_runtime_lane_mut(
        manifest: &mut ProofBundleManifest,
    ) -> Result<&mut ProofBundleLane> {
        manifest
            .lanes
            .iter_mut()
            .find(|lane| lane.lane_id == ADAPTIVE_RUNTIME_LANE)
            .context("adaptive runtime lane")
    }

    fn attach_permissioned_campaign_packet(sample: &mut SampleBundle, lane_id: &str) -> Result<()> {
        let packet_path = format!("artifacts/{lane_id}_permissioned_handoff_packet.json");
        write_file(
            sample.root.path(),
            &packet_path,
            "{\"authorization_notice\":\"not executed evidence\"}\n",
        )?;
        let packet_hash = sha256_file_hex(&sample.root.path().join(&packet_path))?;
        let lane = sample
            .manifest
            .lanes
            .iter_mut()
            .find(|lane| lane.lane_id == lane_id)
            .context("proof lane")?;
        lane.artifacts.push(ProofBundleArtifact {
            path: packet_path,
            sha256: packet_hash,
            redacted: false,
            role: PERMISSIONED_CAMPAIGN_HANDOFF_ARTIFACT_ROLE.to_owned(),
        });
        lane.metadata.insert(
            PERMISSIONED_CAMPAIGN_PACKET_STATUS_KEY.to_owned(),
            "ready_for_operator_approval".to_owned(),
        );
        lane.metadata.insert(
            PERMISSIONED_CAMPAIGN_PRODUCT_EVIDENCE_KEY.to_owned(),
            "none".to_owned(),
        );
        sample.manifest.integrity = Some(integrity_for(&sample.manifest));
        Ok(())
    }

    #[test]
    fn valid_sample_bundle_passes() -> Result<()> {
        let sample = sample_bundle()?;
        let report = validate_sample(&sample);
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.totals.lanes, REQUIRED_PROOF_BUNDLE_LANES.len());
        assert_eq!(report.totals.pass, 5);
        assert_eq!(report.totals.fail, 3);
        assert_eq!(report.totals.skip, 3);
        assert_eq!(report.totals.error, 3);
        assert_eq!(
            report.lane_provenance.len(),
            REQUIRED_PROOF_BUNDLE_LANES.len()
        );
        assert_eq!(report.swarm_evidence.len(), 2);
        assert_eq!(report.adaptive_runtime_evidence.len(), 1);
        Ok(())
    }

    #[test]
    fn executable_lanes_attach_process_run_evidence() -> Result<()> {
        let mut sample = sample_bundle()?;
        configure_executable_lane_commands(&mut sample.manifest)?;
        let report = validate_sample_with_execution(&sample);
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(
            report.executed_evidence.len(),
            EXECUTABLE_PROOF_BUNDLE_LANES.len()
        );
        for lane_id in EXECUTABLE_PROOF_BUNDLE_LANES {
            let evidence = executed_evidence_by_lane(&report, lane_id)?;
            let (expected_command, expected_args) =
                default_allowlisted_lane_command(lane_id).context("allowlisted lane command")?;
            assert_eq!(evidence.command, expected_command);
            assert_eq!(evidence.exit_code, Some(0));
            assert_eq!(evidence.outcome, "success");
            assert_eq!(evidence.stdout_sha256.len(), 64);
            assert_eq!(evidence.stderr_sha256.len(), 64);
            assert_eq!(
                evidence.args, expected_args,
                "lane {lane_id} did not preserve configured args"
            );
        }

        let conformance = executed_evidence_by_lane(&report, "conformance")?;
        let conformance_lane = report
            .lanes
            .iter()
            .find(|lane| lane.lane_id == "conformance")
            .context("conformance lane report")?;
        assert_eq!(conformance_lane.status, ProofBundleOutcome::Pass);
        assert_eq!(conformance.exit_code, Some(0));

        let summary = render_proof_bundle_markdown(&report);
        assert!(summary.contains("## Executed Evidence"));
        assert!(summary.contains("conformance"));
        assert!(summary.contains("Stdout SHA-256"));
        Ok(())
    }

    #[test]
    fn manifest_naming_printf_for_executable_lane_is_rejected_bd_jtk24() -> Result<()> {
        let mut sample = sample_bundle()?;
        configure_executable_lane_commands(&mut sample.manifest)?;
        let conformance = sample
            .manifest
            .lanes
            .iter_mut()
            .find(|lane| lane.lane_id == "conformance")
            .context("conformance lane")?;
        conformance.metadata.insert(
            EXECUTED_EVIDENCE_COMMAND_KEY.to_owned(),
            "printf".to_owned(),
        );
        conformance.metadata.insert(
            EXECUTED_EVIDENCE_ARGS_JSON_KEY.to_owned(),
            serde_json::to_string(&["conformance executed\n"])?,
        );

        let report = validate_sample_with_execution(&sample);

        assert!(!report.valid);
        assert!(
            report.errors.iter().any(|error| {
                error.contains("lane conformance")
                    && error.contains("printf")
                    && error.contains("pinned command allowlist")
            }),
            "expected printf rejection in errors: {:?}",
            report.errors
        );
        Ok(())
    }

    #[test]
    fn manifest_naming_cross_lane_command_is_rejected_bd_jtk24() -> Result<()> {
        let mut sample = sample_bundle()?;
        configure_executable_lane_commands(&mut sample.manifest)?;
        let (_, conformance_args) =
            default_allowlisted_lane_command("conformance").context("conformance command")?;
        let fuse = sample
            .manifest
            .lanes
            .iter_mut()
            .find(|lane| lane.lane_id == "fuse")
            .context("fuse lane")?;
        fuse.metadata.insert(
            EXECUTED_EVIDENCE_ARGS_JSON_KEY.to_owned(),
            serde_json::to_string(&conformance_args)?,
        );

        let report = validate_sample_with_execution(&sample);

        assert!(!report.valid);
        assert!(
            report.errors.iter().any(|error| {
                error.contains("lane fuse") && error.contains("pinned command allowlist")
            }),
            "expected cross-lane command rejection in errors: {:?}",
            report.errors
        );
        Ok(())
    }

    #[test]
    fn executable_lane_missing_command_fails_closed() -> Result<()> {
        let mut sample = sample_bundle()?;
        configure_executable_lane_commands(&mut sample.manifest)?;
        let fuse = sample
            .manifest
            .lanes
            .iter_mut()
            .find(|lane| lane.lane_id == "fuse")
            .context("fuse lane")?;
        fuse.metadata.remove(EXECUTED_EVIDENCE_COMMAND_KEY);

        let report = validate_sample_with_execution(&sample);

        assert!(!report.valid);
        assert!(report.executed_evidence.len() < EXECUTABLE_PROOF_BUNDLE_LANES.len());
        assert!(report.errors.iter().any(|error| {
            error.contains("lane fuse") && error.contains(EXECUTED_EVIDENCE_COMMAND_KEY)
        }));
        Ok(())
    }

    #[test]
    fn required_lanes_cover_operator_readiness_sections() {
        let lanes = proof_bundle_required_lanes();
        for required in [
            "conformance",
            "xfstests",
            "fuse",
            "differential_oracle",
            "repair_lab",
            "crash_replay",
            "performance",
            "swarm_workload_harness",
            "swarm_tail_latency",
            "writeback_cache",
            "scrub_repair_status",
            "known_deferrals",
            "release_gates",
            "adaptive_runtime",
        ] {
            assert!(
                lanes.iter().any(|lane| lane == required),
                "missing required proof-bundle lane {required}"
            );
        }
    }

    #[test]
    fn missing_required_lane_is_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        sample
            .manifest
            .lanes
            .retain(|lane| lane.lane_id != "known_deferrals");
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert!(
            report
                .missing_required_lanes
                .contains(&"known_deferrals".to_owned())
        );
        Ok(())
    }

    #[test]
    fn stale_sha_and_schema_are_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        sample.manifest.schema_version = 0;
        let report = validate_proof_bundle_manifest(
            &sample.manifest,
            sample.root.path(),
            &sample.root.path().join("manifest.json"),
            Some("1234567"),
            Some(10_000),
        );
        assert!(!report.valid);
        assert!(report.stale_git_sha.is_some());
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("stale schema_version"))
        );
        Ok(())
    }

    #[test]
    fn stale_timestamp_is_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        sample.manifest.generated_at = "2000-01-01T00:00:00Z".to_owned();
        let report = validate_proof_bundle_manifest(
            &sample.manifest,
            sample.root.path(),
            &sample.root.path().join("manifest.json"),
            Some("abcdef1"),
            Some(1),
        );
        assert!(!report.valid);
        assert!(report.stale_timestamp.is_some());
        Ok(())
    }

    #[test]
    fn future_timestamp_is_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        sample.manifest.generated_at = "2999-01-01T00:00:00Z".to_owned();
        let report = validate_proof_bundle_manifest(
            &sample.manifest,
            sample.root.path(),
            &sample.root.path().join("manifest.json"),
            Some("abcdef1"),
            Some(1),
        );
        assert!(!report.valid);
        assert!(report.stale_timestamp.is_some());
        assert!(report.errors.iter().any(|error| {
            error
                .contains("future generated_at 2999-01-01T00:00:00Z is after the current timestamp")
        }));
        Ok(())
    }

    #[test]
    fn artifact_hash_mismatch_is_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        first_artifact_mut(first_lane_mut(&mut sample.manifest)?)?.sha256 =
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned();
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert_eq!(report.artifact_hash_mismatches.len(), 1);
        Ok(())
    }

    #[test]
    fn broken_links_are_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        first_lane_mut(&mut sample.manifest)?.raw_log_path = "logs/missing.log".to_owned();
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("broken link"))
        );
        Ok(())
    }

    #[test]
    fn missing_raw_log_hash_is_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        first_lane_mut(&mut sample.manifest)?.raw_log_sha256.clear();
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| { error.contains("raw_log_sha256") && error.contains("SHA-256 hex") })
        );
        Ok(())
    }

    #[test]
    fn raw_log_hash_mismatch_is_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        first_lane_mut(&mut sample.manifest)?.raw_log_sha256 =
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned();
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert_eq!(report.raw_log_hash_mismatches.len(), 1);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("raw log hash mismatch"))
        );
        Ok(())
    }

    #[test]
    fn relative_parent_traversal_is_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        first_lane_mut(&mut sample.manifest)?.summary_path = "../outside-summary.md".to_owned();
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert!(report.broken_links.iter().any(|link| {
            link.field == "summary_path" && link.diagnostic.contains("parent traversal")
        }));
        Ok(())
    }

    #[test]
    fn absolute_paths_are_rejected_by_default() -> Result<()> {
        let mut sample = sample_bundle()?;
        first_lane_mut(&mut sample.manifest)?.summary_path =
            "/tmp/frankenfs-proof-summary.md".to_owned();
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert!(report.broken_links.iter().any(|link| {
            link.field == "summary_path" && link.diagnostic.contains("path must be relative")
        }));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        let outside = tempfile::tempdir()?;
        let outside_raw = outside.path().join("outside.log");
        fs::write(&outside_raw, "escaped raw log\n")?;
        let escaped_link = sample.root.path().join("logs/escaped.log");
        std::os::unix::fs::symlink(&outside_raw, &escaped_link)?;

        let first_lane = first_lane_mut(&mut sample.manifest)?;
        first_lane.raw_log_path = "logs/escaped.log".to_owned();
        first_lane.raw_log_sha256 = sha256_file_hex(&outside_raw)?;
        sample.manifest.integrity = Some(integrity_for(&sample.manifest));

        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert!(report.broken_links.iter().any(|link| {
            link.field == "raw_log_path"
                && link
                    .diagnostic
                    .contains("escapes proof bundle root after symlink resolution")
        }));
        Ok(())
    }

    #[test]
    fn duplicate_scenario_ids_are_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        let duplicate = first_scenario_id_mut(first_lane_mut(&mut sample.manifest)?)?.clone();
        *first_scenario_id_mut(second_lane_mut(&mut sample.manifest)?)? = duplicate;
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert_eq!(report.duplicate_scenario_ids.len(), 1);
        Ok(())
    }

    #[test]
    fn redaction_cannot_remove_reproduction_command() -> Result<()> {
        let mut sample = sample_bundle()?;
        sample.manifest.redaction.redacted_fields = vec!["reproduction_command".to_owned()];
        sample
            .manifest
            .redaction
            .preserved_fields
            .retain(|field| field != "reproduction_command");
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert!(
            report
                .redaction_errors
                .iter()
                .any(|error| error.contains("reproduction_command"))
        );
        Ok(())
    }

    #[test]
    fn missing_redaction_policy_is_reported_and_blocks_lane_provenance() -> Result<()> {
        let sample = sample_bundle()?;
        let mut manifest_value = serde_json::to_value(&sample.manifest)?;
        manifest_value
            .as_object_mut()
            .context("manifest object")?
            .remove("redaction");
        let manifest: ProofBundleManifest = serde_json::from_value(manifest_value)?;

        let report = validate_proof_bundle_manifest(
            &manifest,
            sample.root.path(),
            &sample.root.path().join("manifest.json"),
            Some("abcdef1"),
            Some(10_000),
        );

        assert!(!report.valid);
        assert!(report.redaction_errors.iter().any(|error| {
            error.contains("redaction.reproduction_command") && error.contains("must not be empty")
        }));
        assert!(
            report.lane_provenance.iter().all(|provenance| {
                provenance.provenance_class == ProofBundleProvenanceClass::RedactionFailure
                    && provenance.claim_effect == ProofBundleClaimEffect::EvidenceProductionFailure
            }),
            "{:?}",
            report.lane_provenance
        );
        Ok(())
    }

    #[test]
    fn artifact_hash_chain_mismatch_is_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        integrity_mut(&mut sample.manifest)?.artifact_hash_chain_sha256 =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert!(
            report
                .integrity_errors
                .iter()
                .any(|error| error.contains("artifact hash-chain mismatch"))
        );
        assert!(report.artifact_hash_chain.is_some());
        Ok(())
    }

    #[test]
    fn artifact_count_and_redaction_version_are_integrity_checked() -> Result<()> {
        let mut sample = sample_bundle()?;
        let integrity = integrity_mut(&mut sample.manifest)?;
        integrity.artifact_count += 1;
        integrity.redaction_policy_version = "wrong-redaction-version".to_owned();
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert!(
            report
                .integrity_errors
                .iter()
                .any(|error| error.contains("artifact_count"))
        );
        assert!(
            report
                .integrity_errors
                .iter()
                .any(|error| error.contains("redaction_policy_version"))
        );
        Ok(())
    }

    #[test]
    fn artifact_reports_preserve_lane_path_hash_and_role() -> Result<()> {
        let sample = sample_bundle()?;
        let report = validate_sample(&sample);
        assert_eq!(
            report.artifact_reports.len(),
            manifest_artifact_count(&sample.manifest)
        );
        let conformance = artifact_report_by_lane(&report, "conformance")?;
        assert_eq!(conformance.path, "artifacts/conformance.json");
        assert_eq!(conformance.sha256.len(), 64);
        assert_eq!(conformance.role, "primary_evidence");
        Ok(())
    }

    #[test]
    fn lane_provenance_classifies_claim_effects() -> Result<()> {
        let mut sample = sample_bundle()?;
        let conformance = sample
            .manifest
            .lanes
            .iter_mut()
            .find(|lane| lane.lane_id == "conformance")
            .context("conformance lane")?;
        conformance.status = ProofBundleOutcome::Pass;

        attach_permissioned_campaign_packet(&mut sample, "xfstests")?;
        set_swarm_lane_for_small_host_smoke(&mut sample.manifest, SWARM_WORKLOAD_HARNESS_LANE)?;
        let fuse = sample
            .manifest
            .lanes
            .iter_mut()
            .find(|lane| lane.lane_id == "fuse")
            .context("fuse lane")?;
        fuse.status = ProofBundleOutcome::Skip;
        fuse.metadata.insert(
            "release_claim_state".to_owned(),
            "capability_downgraded_smoke".to_owned(),
        );
        fuse.metadata.insert(
            "host_classification".to_owned(),
            "below_large_host_floor".to_owned(),
        );
        fuse.metadata.insert(
            "downgrade_reason".to_owned(),
            "FUSE capability unavailable".to_owned(),
        );
        let repair = sample
            .manifest
            .lanes
            .iter_mut()
            .find(|lane| lane.lane_id == "repair_lab")
            .context("repair lane")?;
        repair
            .metadata
            .insert("freshness".to_owned(), "stale".to_owned());
        let crash = sample
            .manifest
            .lanes
            .iter_mut()
            .find(|lane| lane.lane_id == "crash_replay")
            .context("crash lane")?;
        crash.raw_log_path = "logs/missing-crash-replay.log".to_owned();
        sample.manifest.integrity = Some(integrity_for(&sample.manifest));

        let report = validate_sample(&sample);
        let by_lane = report
            .lane_provenance
            .iter()
            .map(|provenance| (provenance.lane_id.as_str(), provenance))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(
            by_lane["conformance"].provenance_class,
            ProofBundleProvenanceClass::ExecutedProductEvidence
        );
        assert_eq!(
            by_lane["conformance"].claim_effect,
            ProofBundleClaimEffect::StrengthensPublicClaim
        );
        assert_eq!(
            by_lane["xfstests"].provenance_class,
            ProofBundleProvenanceClass::DryRunHandoff
        );
        assert_eq!(
            by_lane["xfstests"].claim_effect,
            ProofBundleClaimEffect::HandoffOnly
        );
        assert_eq!(
            by_lane[SWARM_WORKLOAD_HARNESS_LANE].provenance_class,
            ProofBundleProvenanceClass::SmallHostSmoke
        );
        assert_eq!(
            by_lane["fuse"].provenance_class,
            ProofBundleProvenanceClass::CapabilityDowngrade
        );
        assert_eq!(
            by_lane["repair_lab"].provenance_class,
            ProofBundleProvenanceClass::StaleArtifact
        );
        assert_eq!(
            by_lane["crash_replay"].provenance_class,
            ProofBundleProvenanceClass::MissingRawLog
        );
        assert_eq!(
            by_lane["known_deferrals"].provenance_class,
            ProofBundleProvenanceClass::UnsupportedFutureScope
        );
        Ok(())
    }

    #[test]
    fn permissioned_broker_packet_is_allowed_as_blocker_context() -> Result<()> {
        let mut sample = sample_bundle()?;
        attach_permissioned_campaign_packet(&mut sample, "xfstests")?;

        let report = validate_sample(&sample);

        assert!(report.valid, "{:?}", report.errors);
        assert!(report.artifact_reports.iter().any(|artifact| {
            artifact.lane_id == "xfstests"
                && artifact.role == PERMISSIONED_CAMPAIGN_HANDOFF_ARTIFACT_ROLE
        }));
        Ok(())
    }

    #[test]
    fn xfstests_broker_packet_cannot_mark_lane_pass() -> Result<()> {
        let mut sample = sample_bundle()?;
        let lane = sample
            .manifest
            .lanes
            .iter_mut()
            .find(|lane| lane.lane_id == "xfstests")
            .context("xfstests lane")?;
        lane.status = ProofBundleOutcome::Pass;
        attach_permissioned_campaign_packet(&mut sample, "xfstests")?;

        let report = validate_sample(&sample);

        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("lane xfstests")
                && error.contains("broker packets are authorization handoff material only")
        }));
        Ok(())
    }

    #[test]
    fn permissioned_broker_packet_requires_explicit_boundary_metadata() -> Result<()> {
        let mut sample = sample_bundle()?;
        attach_permissioned_campaign_packet(&mut sample, "xfstests")?;
        let lane = sample
            .manifest
            .lanes
            .iter_mut()
            .find(|lane| lane.lane_id == "xfstests")
            .context("xfstests lane")?;
        lane.metadata
            .remove(PERMISSIONED_CAMPAIGN_PACKET_STATUS_KEY);
        lane.metadata
            .remove(PERMISSIONED_CAMPAIGN_PRODUCT_EVIDENCE_KEY);
        sample.manifest.integrity = Some(integrity_for(&sample.manifest));

        let report = validate_sample(&sample);

        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains(PERMISSIONED_CAMPAIGN_PACKET_STATUS_KEY)
                && error.contains(PERMISSIONED_CAMPAIGN_READY_STATUS)
        }));
        assert!(report.errors.iter().any(|error| {
            error.contains(PERMISSIONED_CAMPAIGN_PRODUCT_EVIDENCE_KEY)
                && error.contains(PERMISSIONED_CAMPAIGN_NO_PRODUCT_EVIDENCE)
        }));
        Ok(())
    }

    #[test]
    fn permissioned_broker_packet_rejects_non_ready_status_metadata() -> Result<()> {
        let mut sample = sample_bundle()?;
        attach_permissioned_campaign_packet(&mut sample, "xfstests")?;
        let lane = sample
            .manifest
            .lanes
            .iter_mut()
            .find(|lane| lane.lane_id == "xfstests")
            .context("xfstests lane")?;
        lane.metadata.insert(
            PERMISSIONED_CAMPAIGN_PACKET_STATUS_KEY.to_owned(),
            "executed_evidence".to_owned(),
        );
        sample.manifest.integrity = Some(integrity_for(&sample.manifest));

        let report = validate_sample(&sample);

        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("packet_status=executed_evidence")
                && error.contains(PERMISSIONED_CAMPAIGN_READY_STATUS)
        }));
        Ok(())
    }

    #[test]
    fn swarm_broker_packet_cannot_back_authoritative_release_claim() -> Result<()> {
        let mut sample = sample_bundle()?;
        set_swarm_lane_for_large_host(&mut sample.manifest, SWARM_WORKLOAD_HARNESS_LANE)?;
        attach_permissioned_campaign_packet(&mut sample, SWARM_WORKLOAD_HARNESS_LANE)?;

        let report = validate_sample(&sample);

        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("release_claim=authoritative_large_host")
                && error.contains("permissioned campaign broker packet")
        }));
        Ok(())
    }

    #[test]
    fn accepted_large_host_swarm_evidence_is_preserved() -> Result<()> {
        let mut sample = sample_bundle()?;
        set_swarm_lane_for_large_host(&mut sample.manifest, SWARM_WORKLOAD_HARNESS_LANE)?;
        set_swarm_lane_for_large_host(&mut sample.manifest, SWARM_TAIL_LATENCY_LANE)?;
        sample.manifest.integrity = Some(integrity_for(&sample.manifest));

        let report = validate_sample(&sample);

        assert!(report.valid, "{:?}", report.errors);
        let workload = swarm_evidence_by_lane(&report, SWARM_WORKLOAD_HARNESS_LANE)?;
        assert_eq!(workload.status, ProofBundleOutcome::Pass);
        assert_eq!(workload.host_class, "permissioned_large_host");
        assert_eq!(workload.release_claim, "authoritative_large_host");
        assert_eq!(workload.freshness, "fresh");
        assert_eq!(workload.manifest_hash.len(), 64);

        let tail_latency = swarm_evidence_by_lane(&report, SWARM_TAIL_LATENCY_LANE)?;
        assert_eq!(
            tail_latency.p99_attribution_artifact.as_deref(),
            Some("artifacts/swarm_tail_latency_p99_attribution.json")
        );
        Ok(())
    }

    #[test]
    fn accepted_adaptive_runtime_evidence_is_preserved() -> Result<()> {
        let sample = sample_bundle()?;
        let report = validate_sample(&sample);

        assert!(report.valid, "{:?}", report.errors);
        let evidence = adaptive_runtime_evidence_by_lane(&report, ADAPTIVE_RUNTIME_LANE)?;
        assert_eq!(evidence.status, ProofBundleOutcome::Pass);
        assert_eq!(evidence.scenario_id, "adaptive_runtime_accepted_large_host");
        assert_eq!(evidence.run_id, "adaptive-runtime-run-20260507T000000Z");
        assert_eq!(evidence.release_claim_state, "accepted_large_host");
        assert_eq!(evidence.host_classification, "accepted_large_host");
        assert_eq!(evidence.cleanup_status, "clean");
        assert_eq!(
            evidence.runner_report,
            "artifacts/adaptive_runtime_runner.json"
        );
        Ok(())
    }

    #[test]
    fn stale_adaptive_runtime_manifest_is_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        let lane = adaptive_runtime_lane_mut(&mut sample.manifest)?;
        lane.metadata
            .insert("freshness".to_owned(), "stale".to_owned());

        let report = validate_sample(&sample);

        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("stale adaptive runtime artifact")
                && error.contains("scenario_id=adaptive_runtime_accepted_large_host")
                && error.contains("run_id=adaptive-runtime-run-20260507T000000Z")
        }));
        Ok(())
    }

    #[test]
    fn small_host_adaptive_runtime_evidence_fails_closed() -> Result<()> {
        let mut sample = sample_bundle()?;
        let lane = adaptive_runtime_lane_mut(&mut sample.manifest)?;
        lane.status = ProofBundleOutcome::Skip;
        lane.metadata.insert(
            "release_claim_state".to_owned(),
            "small_host_smoke".to_owned(),
        );
        lane.metadata.insert(
            "host_classification".to_owned(),
            "below_large_host_floor".to_owned(),
        );
        lane.metadata
            .insert("downgrade_reason".to_owned(), "local smoke only".to_owned());

        let report = validate_sample(&sample);

        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("release_claim_state=small_host_smoke rejected")
                && error.contains("adaptive-runtime-run-20260507T000000Z")
        }));
        Ok(())
    }

    #[test]
    fn capability_downgraded_adaptive_runtime_evidence_fails_closed() -> Result<()> {
        let mut sample = sample_bundle()?;
        let lane = adaptive_runtime_lane_mut(&mut sample.manifest)?;
        lane.status = ProofBundleOutcome::Skip;
        lane.metadata.insert(
            "release_claim_state".to_owned(),
            "capability_downgraded_smoke".to_owned(),
        );
        lane.metadata.insert(
            "host_classification".to_owned(),
            "below_large_host_floor".to_owned(),
        );
        lane.metadata.insert(
            "downgrade_reason".to_owned(),
            "FUSE capability was unavailable".to_owned(),
        );

        let report = validate_sample(&sample);

        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("release_claim_state=capability_downgraded_smoke rejected")
        }));
        Ok(())
    }

    #[test]
    fn failed_cleanup_adaptive_runtime_evidence_fails_closed() -> Result<()> {
        let mut sample = sample_bundle()?;
        let lane = adaptive_runtime_lane_mut(&mut sample.manifest)?;
        lane.status = ProofBundleOutcome::Fail;
        lane.metadata
            .insert("cleanup_status".to_owned(), "failed".to_owned());
        lane.metadata.insert(
            "release_claim_state".to_owned(),
            "failed_cleanup".to_owned(),
        );
        lane.metadata.insert(
            "downgrade_reason".to_owned(),
            "scratch mount cleanup failed".to_owned(),
        );

        let report = validate_sample(&sample);

        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("cleanup_status=failed rejected")
                && error.contains("scenario_id=adaptive_runtime_accepted_large_host")
        }));
        Ok(())
    }

    #[test]
    fn accepted_small_host_swarm_smoke_is_downgraded() -> Result<()> {
        let mut sample = sample_bundle()?;
        set_swarm_lane_for_small_host_smoke(&mut sample.manifest, SWARM_WORKLOAD_HARNESS_LANE)?;
        set_swarm_lane_for_small_host_smoke(&mut sample.manifest, SWARM_TAIL_LATENCY_LANE)?;
        sample.manifest.integrity = Some(integrity_for(&sample.manifest));

        let report = validate_sample(&sample);

        assert!(report.valid, "{:?}", report.errors);
        assert!(report.swarm_evidence.iter().all(|evidence| {
            evidence.status == ProofBundleOutcome::Skip
                && evidence.host_class == "developer_smoke"
                && evidence.release_claim == "small_host_smoke"
                && evidence.downgrade_reason.is_some()
        }));
        Ok(())
    }

    #[test]
    fn stale_swarm_artifact_is_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        let lane = swarm_lane_mut(&mut sample.manifest, SWARM_WORKLOAD_HARNESS_LANE)?;
        lane.metadata
            .insert("freshness".to_owned(), "stale".to_owned());

        let report = validate_sample(&sample);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("stale swarm artifact"))
        );
        Ok(())
    }

    #[test]
    fn missing_p99_ledger_is_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        let lane = swarm_lane_mut(&mut sample.manifest, SWARM_TAIL_LATENCY_LANE)?;
        lane.artifacts
            .retain(|artifact| artifact.role != SWARM_P99_ATTRIBUTION_ROLE);
        sample.manifest.integrity = Some(integrity_for(&sample.manifest));

        let report = validate_sample(&sample);

        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("p99_attribution_artifact") && error.contains(SWARM_P99_ATTRIBUTION_ROLE)
        }));
        Ok(())
    }

    #[test]
    fn swarm_host_class_mismatch_is_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        set_swarm_lane_for_large_host(&mut sample.manifest, SWARM_WORKLOAD_HARNESS_LANE)?;
        let lane = swarm_lane_mut(&mut sample.manifest, SWARM_WORKLOAD_HARNESS_LANE)?;
        lane.metadata
            .insert("host_class".to_owned(), "developer_smoke".to_owned());
        sample.manifest.integrity = Some(integrity_for(&sample.manifest));

        let report = validate_sample(&sample);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("authoritative pass requires large host_class"))
        );
        Ok(())
    }

    #[test]
    fn missing_swarm_raw_log_is_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        let lane = swarm_lane_mut(&mut sample.manifest, SWARM_WORKLOAD_HARNESS_LANE)?;
        lane.raw_log_path = "logs/missing-swarm-workload.log".to_owned();

        let report = validate_sample(&sample);

        assert!(!report.valid);
        assert!(report.broken_links.iter().any(
            |link| link.lane_id == SWARM_WORKLOAD_HARNESS_LANE && link.field == "raw_log_path"
        ));
        Ok(())
    }

    #[test]
    fn redaction_leaks_are_rejected_from_artifacts_and_summaries() -> Result<()> {
        let sample = sample_bundle()?;
        write_file(
            sample.root.path(),
            "summaries/conformance.md",
            "# conformance\nSECRET_TOKEN\n",
        )?;
        write_file(
            sample.root.path(),
            "artifacts/conformance.json",
            "{\"token\":\"SECRET_TOKEN\"}\n",
        )?;
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert_eq!(report.redaction_leaks.len(), 2);
        assert!(
            report
                .redaction_errors
                .iter()
                .any(|error| error.contains("redaction leak"))
        );
        Ok(())
    }

    #[test]
    fn redaction_leak_turns_passing_lane_into_evidence_production_failure() -> Result<()> {
        let mut sample = sample_bundle()?;
        let lane = swarm_lane_mut(&mut sample.manifest, "conformance")?;
        lane.status = ProofBundleOutcome::Pass;
        write_file(
            sample.root.path(),
            "summaries/conformance.md",
            "# conformance\nSECRET_TOKEN\n",
        )?;

        let report = validate_sample(&sample);

        let conformance = lane_provenance_by_lane(&report, "conformance")?;
        assert_eq!(
            conformance.provenance_class,
            ProofBundleProvenanceClass::RedactionFailure
        );
        assert_eq!(
            conformance.claim_effect,
            ProofBundleClaimEffect::EvidenceProductionFailure
        );
        assert!(
            conformance
                .rationale
                .contains("evidence production failed before product readiness")
        );
        Ok(())
    }

    #[test]
    fn env_like_secret_markers_are_rejected_without_policy_entry() -> Result<()> {
        let sample = sample_bundle()?;
        write_file(
            sample.root.path(),
            "summaries/conformance.md",
            "# conformance\nAWS_SECRET_ACCESS_KEY=unredacted\n",
        )?;

        let report = validate_sample(&sample);

        assert!(!report.valid);
        assert!(report.redaction_leaks.iter().any(|leak| {
            leak.path == "summaries/conformance.md" && leak.marker == "AWS_SECRET_ACCESS_KEY="
        }));
        Ok(())
    }

    #[test]
    fn reproduction_command_env_secret_marker_is_rejected() -> Result<()> {
        let mut sample = sample_bundle()?;
        sample.manifest.redaction.reproduction_command =
            "AWS_SECRET_ACCESS_KEY=unredacted cargo run -p ffs-harness -- validate-proof-bundle --bundle manifest.json"
                .to_owned();

        let report = validate_sample(&sample);

        assert!(!report.valid);
        assert!(report.redaction_errors.iter().any(|error| {
            error.contains("reproduction_command") && error.contains("AWS_SECRET_ACCESS_KEY=")
        }));
        Ok(())
    }

    #[test]
    fn redacted_artifact_placeholder_can_be_required() -> Result<()> {
        let mut sample = sample_bundle()?;
        sample
            .manifest
            .redaction
            .require_placeholder_in_redacted_artifacts = true;
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert!(
            report
                .redaction_errors
                .iter()
                .any(|error| error.contains("lacks placeholder"))
        );

        for lane in &mut sample.manifest.lanes {
            for artifact in &mut lane.artifacts {
                if artifact.redacted {
                    write_file(
                        sample.root.path(),
                        &artifact.path,
                        "{\"redacted\":\"[REDACTED]\"}\n",
                    )?;
                    artifact.sha256 = sha256_file_hex(&sample.root.path().join(&artifact.path))?;
                }
            }
        }
        sample.manifest.integrity = Some(integrity_for(&sample.manifest));
        let report = validate_sample(&sample);
        assert!(report.valid, "{:?}", report.errors);
        Ok(())
    }

    #[test]
    fn summary_contains_totals_lanes_logs_and_artifacts() -> Result<()> {
        let sample = sample_bundle()?;
        let report = validate_sample(&sample);
        let summary = render_proof_bundle_markdown(&report);
        assert!(summary.contains("Totals: pass=5 fail=3 skip=3 error=3"));
        assert!(summary.contains("[logs/conformance.log](logs/conformance.log)"));
        assert!(summary.contains("scrub_repair_status"));
        assert!(summary.contains("known_deferrals"));
        assert!(summary.contains("writeback_cache"));
        assert!(summary.contains("Swarm Evidence"));
        assert!(summary.contains("swarm_workload_harness"));
        assert!(summary.contains("swarm_tail_latency"));
        assert!(summary.contains("authoritative_large_host"));
        assert!(summary.contains("Lane Provenance"));
        assert!(summary.contains("strengthens_public_claim"));
        assert!(summary.contains("unsupported_future_scope"));
        assert!(summary.contains("Adaptive Runtime Evidence"));
        assert!(summary.contains("adaptive-runtime-run-20260507T000000Z"));
        assert!(summary.contains("Artifact hash chain"));
        Ok(())
    }

    #[test]
    fn render_proof_bundle_markdown_sample_bundle_snapshot() -> Result<()> {
        let sample = sample_bundle()?;
        let mut report = validate_sample(&sample);
        let bundle_root = sample.root.path().display().to_string();
        report.manifest_path = report.manifest_path.replace(&bundle_root, "$BUNDLE");

        let markdown = render_proof_bundle_markdown(&report);

        assert!(markdown.contains("# FrankenFS Proof Bundle"));
        assert!(markdown.contains("## Lanes"));
        assert!(markdown.contains("## Lane Provenance"));
        assert!(markdown.contains("## Swarm Evidence"));
        assert!(markdown.contains("## Adaptive Runtime Evidence"));
        insta::assert_snapshot!("render_proof_bundle_markdown_sample_bundle", markdown);
        Ok(())
    }

    #[test]
    fn proof_bundle_validation_report_json_shape() -> Result<()> {
        let sample = sample_bundle()?;
        let mut report = validate_sample(&sample);
        let bundle_root = sample.root.path().display().to_string();
        report.manifest_path = report.manifest_path.replace(&bundle_root, "$BUNDLE");

        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("proof_bundle_validation_report_json_shape", json);
        let parsed: ProofBundleValidationReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn summary_separates_pass_skip_fail_and_error_outcomes() -> Result<()> {
        let sample = sample_bundle()?;
        let report = validate_sample(&sample);
        let summary = render_proof_bundle_markdown(&report);

        for label in ["`pass`", "`skip`", "`fail`", "`error`"] {
            assert!(summary.contains(label), "summary missing {label}");
        }
        Ok(())
    }

    #[test]
    fn c2_pass_lane_requires_executed_evidence_exit_code_zero() -> Result<()> {
        // C2: A pass lane for an executable lane requires ExecutedEvidence with exit_code==0
        let mut sample = sample_bundle()?;
        configure_executable_lane_commands(&mut sample.manifest)?;

        // Run validation with execution enabled
        let report = validate_sample_with_execution(&sample);

        // All executable lanes should have evidence
        assert!(
            !report.executed_evidence.is_empty(),
            "executable lanes should have attached evidence"
        );

        // Verify pass lanes have exit_code==0
        for ev in &report.executed_evidence {
            if is_executable_proof_bundle_lane(&ev.lane_id) {
                // Our test fixture uses printf which succeeds with exit_code 0
                assert_eq!(
                    ev.exit_code,
                    Some(0),
                    "pass lane {} should have exit_code==0",
                    ev.lane_id
                );
            }
        }

        // Report should be valid (all pass lanes have green evidence)
        assert!(
            report.valid,
            "report should be valid when pass lanes have exit_code==0: errors={:?}",
            report.errors
        );

        Ok(())
    }

    #[test]
    fn c2_pass_lane_without_evidence_is_rejected() {
        // C2: A lane backed only by checked-in artifact hashes (no evidence) should fail
        // This simulates a pass lane without running the actual command
        let mut report = ProofBundleValidationReport {
            schema_version: PROOF_BUNDLE_SCHEMA_VERSION,
            bundle_id: "test".to_owned(),
            manifest_path: "test.json".to_owned(),
            valid: true,
            totals: ProofBundleTotals::default(),
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
            lanes: Vec::new(),
            lane_provenance: Vec::new(),
            executed_evidence: Vec::new(), // NO EVIDENCE
            swarm_evidence: Vec::new(),
            adaptive_runtime_evidence: Vec::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
            reproduction_command: String::new(),
        };

        // Create a manifest with a pass lane but no evidence
        let mut manifest = ProofBundleManifest {
            schema_version: PROOF_BUNDLE_SCHEMA_VERSION,
            bundle_id: "test".to_owned(),
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
            git_sha: "abc123".to_owned(),
            toolchain: "test".to_owned(),
            kernel: "test".to_owned(),
            mount_capability: "test".to_owned(),
            required_lanes: Vec::new(),
            lanes: Vec::new(),
            redaction: ProofBundleRedactionPolicy::default(),
            integrity: None,
        };

        // Add a pass lane for an executable lane
        manifest.lanes.push(ProofBundleLane {
            lane_id: "conformance".to_owned(), // executable lane
            status: ProofBundleOutcome::Pass,
            raw_log_path: "log.txt".to_owned(),
            raw_log_sha256: String::new(),
            summary_path: "summary.txt".to_owned(),
            scenario_ids: vec!["s1".to_owned()],
            gate_inputs: vec!["g1".to_owned()],
            artifacts: Vec::new(),
            metadata: BTreeMap::new(),
        });

        // Run the validation
        validate_executable_lane_pass_requires_evidence(&manifest, &mut report, "abc123");

        // Should have an error about missing evidence
        assert!(
            !report.errors.is_empty(),
            "pass lane without evidence should generate an error"
        );
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("no ExecutedEvidence")),
            "error should mention missing ExecutedEvidence: {:?}",
            report.errors
        );
    }

    #[test]
    fn c2_pass_lane_with_nonzero_exit_code_is_rejected() {
        // C2: A pass lane with exit_code != 0 should fail
        let mut report = ProofBundleValidationReport {
            schema_version: PROOF_BUNDLE_SCHEMA_VERSION,
            bundle_id: "test".to_owned(),
            manifest_path: "test.json".to_owned(),
            valid: true,
            totals: ProofBundleTotals::default(),
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
            lanes: Vec::new(),
            lane_provenance: Vec::new(),
            executed_evidence: vec![ProofBundleExecutedEvidenceReport {
                lane_id: "conformance".to_owned(),
                command: "false".to_owned(),
                args: vec![],
                exit_code: Some(1), // NON-ZERO EXIT
                stdout_sha256: String::new(),
                stderr_sha256: String::new(),
                duration_ms: 0,
                ran_at: 0,
                git_sha: "abc".to_owned(),
                host_class: "ci".to_owned(),
                outcome: "failed".to_owned(),
                outcome_detail: Some("exit_code=1".to_owned()),
            }],
            swarm_evidence: Vec::new(),
            adaptive_runtime_evidence: Vec::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
            reproduction_command: String::new(),
        };

        let mut manifest = ProofBundleManifest {
            schema_version: PROOF_BUNDLE_SCHEMA_VERSION,
            bundle_id: "test".to_owned(),
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
            git_sha: "abc123".to_owned(),
            toolchain: "test".to_owned(),
            kernel: "test".to_owned(),
            mount_capability: "test".to_owned(),
            required_lanes: Vec::new(),
            lanes: Vec::new(),
            redaction: ProofBundleRedactionPolicy::default(),
            integrity: None,
        };

        manifest.lanes.push(ProofBundleLane {
            lane_id: "conformance".to_owned(),
            status: ProofBundleOutcome::Pass, // Marked as pass but exit_code=1
            raw_log_path: "log.txt".to_owned(),
            raw_log_sha256: String::new(),
            summary_path: "summary.txt".to_owned(),
            scenario_ids: vec!["s1".to_owned()],
            gate_inputs: vec!["g1".to_owned()],
            artifacts: Vec::new(),
            metadata: BTreeMap::new(),
        });

        validate_executable_lane_pass_requires_evidence(&manifest, &mut report, "abc");

        assert!(
            !report.errors.is_empty(),
            "pass lane with non-zero exit_code should generate an error"
        );
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("exit_code") && e.contains("expected 0")),
            "error should mention exit_code mismatch: {:?}",
            report.errors
        );
    }

    #[test]
    fn c2_pass_lane_with_mismatched_git_sha_is_rejected() {
        // C2: A pass lane with evidence from wrong git SHA should fail
        let mut report = ProofBundleValidationReport {
            schema_version: PROOF_BUNDLE_SCHEMA_VERSION,
            bundle_id: "test".to_owned(),
            manifest_path: "test.json".to_owned(),
            valid: true,
            totals: ProofBundleTotals::default(),
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
            lanes: Vec::new(),
            lane_provenance: Vec::new(),
            executed_evidence: vec![ProofBundleExecutedEvidenceReport {
                lane_id: "conformance".to_owned(),
                command: "true".to_owned(),
                args: vec![],
                exit_code: Some(0), // exit_code is good
                stdout_sha256: String::new(),
                stderr_sha256: String::new(),
                duration_ms: 0,
                ran_at: 0,
                git_sha: "stale_abc123".to_owned(), // WRONG GIT SHA
                host_class: "ci".to_owned(),
                outcome: "success".to_owned(),
                outcome_detail: None,
            }],
            swarm_evidence: Vec::new(),
            adaptive_runtime_evidence: Vec::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
            reproduction_command: String::new(),
        };

        let mut manifest = ProofBundleManifest {
            schema_version: PROOF_BUNDLE_SCHEMA_VERSION,
            bundle_id: "test".to_owned(),
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
            git_sha: "current_head_sha".to_owned(),
            toolchain: "test".to_owned(),
            kernel: "test".to_owned(),
            mount_capability: "test".to_owned(),
            required_lanes: Vec::new(),
            lanes: Vec::new(),
            redaction: ProofBundleRedactionPolicy::default(),
            integrity: None,
        };

        manifest.lanes.push(ProofBundleLane {
            lane_id: "conformance".to_owned(),
            status: ProofBundleOutcome::Pass,
            raw_log_path: "log.txt".to_owned(),
            raw_log_sha256: String::new(),
            summary_path: "summary.txt".to_owned(),
            scenario_ids: vec!["s1".to_owned()],
            gate_inputs: vec!["g1".to_owned()],
            artifacts: Vec::new(),
            metadata: BTreeMap::new(),
        });

        // Validate with expected git SHA that differs from evidence
        validate_executable_lane_pass_requires_evidence(&manifest, &mut report, "current_head_sha");

        assert!(
            !report.errors.is_empty(),
            "pass lane with mismatched git_sha should generate an error"
        );
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("git_sha") && e.contains("does not match")),
            "error should mention git_sha mismatch: {:?}",
            report.errors
        );
    }

    // C3: lane execution classification tests

    #[test]
    fn c3_lane_execution_class_covers_all_required_lanes() {
        // C3: Every required lane must have an explicit classification
        for lane_id in REQUIRED_PROOF_BUNDLE_LANES {
            let class = LaneExecutionClass::classify(lane_id);
            // Classification should be deterministic
            assert_eq!(
                class,
                LaneExecutionClass::classify(lane_id),
                "lane {lane_id} classification should be deterministic"
            );
        }
    }

    #[test]
    fn c3_documentation_only_lanes_cannot_contribute_pass() {
        // C3: Documentation-only lanes cannot contribute 'pass'
        for lane_id in DOCUMENTATION_ONLY_LANES {
            let class = LaneExecutionClass::classify(lane_id);
            assert_eq!(
                class,
                LaneExecutionClass::DocumentationOnly,
                "lane {lane_id} should be classified as documentation_only"
            );
            assert!(
                !class.can_contribute_pass(),
                "documentation_only lane {lane_id} must not contribute pass"
            );
        }
    }

    #[test]
    fn c3_deferred_lanes_cannot_contribute_pass() {
        // C3: Deferred lanes cannot contribute 'pass'
        for lane_id in DEFERRED_LANES {
            let class = LaneExecutionClass::classify(lane_id);
            assert_eq!(
                class,
                LaneExecutionClass::Deferred,
                "lane {lane_id} should be classified as deferred"
            );
            assert!(
                !class.can_contribute_pass(),
                "deferred lane {lane_id} must not contribute pass"
            );
        }
    }

    #[test]
    fn c3_executable_lanes_can_contribute_pass() {
        // C3: Executable lanes CAN contribute 'pass' (with evidence)
        for lane_id in EXECUTABLE_PROOF_BUNDLE_LANES {
            let class = LaneExecutionClass::classify(lane_id);
            assert_eq!(
                class,
                LaneExecutionClass::Executable,
                "lane {lane_id} should be classified as executable"
            );
            assert!(
                class.can_contribute_pass(),
                "executable lane {lane_id} should be able to contribute pass"
            );
        }
    }

    #[test]
    fn c3_xfstests_is_documentation_only() {
        // C3: xfstests requires permissioned infrastructure - documentation_only until G1-G4
        let class = LaneExecutionClass::classify("xfstests");
        assert_eq!(class, LaneExecutionClass::DocumentationOnly);
        assert!(!class.can_contribute_pass());
        assert_eq!(class.label(), "documentation_only");
    }
}
