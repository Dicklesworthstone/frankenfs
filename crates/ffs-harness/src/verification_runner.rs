//! Verification runner conventions and machine-parseable result format.
//!
//! Provides shared utilities for:
//! - Parsing E2E script output into structured [`ScenarioOutcome`] records.
//! - Building [`ArtifactManifest`] instances from parsed output.
//! - Checking per-script conformance to runner conventions.
//! - Retry semantics for CI/nightly mode.
//!
//! # Runner contract version
//!
//! The current runner contract version is [`RUNNER_CONTRACT_VERSION`]. Bump on
//! any breaking change to the envelope format, retry semantics, or conformance
//! requirements.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use tracing::info;

use crate::artifact_manifest::{
    ArtifactCategory, ArtifactEntry, ArtifactManifest, CleanupStatus, EnvironmentFingerprint,
    FilesystemFlavor, FuseCapabilityResult, GateVerdict, ManifestBuilder, OperationalErrorClass,
    OperationalOutcomeClass, OperationalRunContext, OperationalScenarioRecord,
    READINESS_EVENT_ENVELOPE_VERSION, REDACTED_SENTINEL, ReadinessEventEnvelope,
    ReadinessEventSeverity, ScenarioOutcome, ScenarioResult, SkipReason, WorkerContext,
    is_valid_scenario_id, validate_manifest, validate_operational_manifest,
};
use crate::log_contract::e2e_marker;

/// Runner contract version. Bump on any breaking change.
pub const RUNNER_CONTRACT_VERSION: u32 = 1;

/// Maximum number of retries in CI mode before declaring permanent failure.
pub const DEFAULT_CI_MAX_RETRIES: u32 = 2;

/// RCH proof ledger schema version.
pub const RCH_PROOF_LEDGER_SCHEMA_VERSION: u32 = 1;

/// Exit code conventions for E2E scripts.
pub mod exit_code {
    /// All scenarios passed.
    pub const PASS: i32 = 0;
    /// One or more scenarios failed.
    pub const FAIL: i32 = 1;
    /// Script was skipped (missing prerequisites).
    pub const SKIP: i32 = 0;
}

// ── E2E output parsing ───────────────────────────────────────────────────

/// A parsed scenario result extracted from E2E script output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedScenario {
    /// The scenario_id from the SCENARIO_RESULT marker.
    pub scenario_id: String,
    /// PASS or FAIL.
    pub outcome: ScenarioResult,
    /// Optional detail text.
    pub detail: Option<String>,
    /// Line number in the output where this marker was found (1-based).
    pub line_number: usize,
}

/// Parse all SCENARIO_RESULT markers from E2E script output text.
///
/// Returns scenarios in order of appearance. Duplicate scenario_ids are
/// preserved (the caller should decide how to handle them).
#[must_use]
pub fn parse_e2e_output(output: &str) -> Vec<ParsedScenario> {
    let mut results = Vec::new();
    for (idx, line) in output.lines().enumerate() {
        if let Some((id, outcome_str, detail)) = e2e_marker::parse_marker(line) {
            let outcome = match outcome_str {
                e2e_marker::PASS => ScenarioResult::Pass,
                e2e_marker::FAIL => ScenarioResult::Fail,
                _ => continue,
            };
            results.push(ParsedScenario {
                scenario_id: id.to_owned(),
                outcome,
                detail: detail.map(str::to_owned),
                line_number: idx + 1,
            });
        }
    }
    results
}

/// Input metadata for turning a captured `rch` transcript into proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RchProofLedgerConfig {
    /// Command the operator intended `rch` to run.
    pub command_line: Vec<String>,
    /// Working directory for the command.
    pub cwd: String,
    /// Environment variables intentionally forwarded to the worker.
    pub env_allowlist: Vec<String>,
}

/// Machine-readable proof extracted from a captured `rch` transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchProofLedgerReport {
    /// Schema version for downstream compatibility checks.
    pub schema_version: u32,
    /// Redacted command line intended for the worker.
    pub command: Vec<String>,
    /// Working directory where the command was expected to run.
    pub cwd: String,
    /// Environment variable names intentionally forwarded to the worker.
    pub env_allowlist: Vec<String>,
    /// Remote worker identity, when the transcript includes one.
    pub worker_id: Option<String>,
    /// Exit code from the remote command.
    pub remote_exit_code: Option<i32>,
    /// Remote command runtime in milliseconds.
    pub remote_duration_ms: Option<u64>,
    /// Whether `rch` fell back to local execution.
    pub fallback_detected: bool,
    /// Local fallback reason copied from the `rch` summary line.
    pub local_fallback_reason: Option<String>,
    /// Retrieval state for source-tree and target-directory artifacts.
    pub artifact_retrieval_status: RchArtifactRetrievalStatus,
    /// Non-fatal or proof-invalidating warnings found in the transcript.
    pub warnings: Vec<String>,
    /// Final proof classification.
    pub proof_verdict: String,
}

/// Source-tree and target-directory artifact retrieval state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchArtifactRetrievalStatus {
    /// Source-tree artifact retrieval state.
    pub source: String,
    /// Target-directory artifact retrieval state.
    pub target: String,
}

/// Parse an `rch` transcript into a proof ledger.
#[must_use]
pub fn build_rch_proof_ledger_report(
    transcript: &str,
    config: &RchProofLedgerConfig,
) -> RchProofLedgerReport {
    let mut worker_id = None;
    let mut remote_exit_code = None;
    let mut remote_duration_ms = None;
    let mut local_fallback_reason = None;
    let mut source_status = "not_attempted".to_owned();
    let mut target_status = "not_attempted".to_owned();
    let mut warnings = Vec::new();

    for line in transcript.lines() {
        if worker_id.is_none() {
            worker_id = parse_selected_worker(line).or_else(|| parse_rch_summary_worker(line));
        }
        if let Some((exit, duration)) = parse_remote_finished_line(line) {
            remote_exit_code = Some(exit);
            remote_duration_ms = Some(duration);
        } else if let Some((exit, duration)) = parse_rch_summary_line(line) {
            remote_exit_code.get_or_insert(exit);
            if remote_duration_ms.is_none() {
                remote_duration_ms = duration;
            }
        }
        if let Some(reason) = parse_local_fallback_reason(line) {
            local_fallback_reason = Some(reason);
            push_unique_warning(&mut warnings, "local_fallback_detected");
        }
        classify_artifact_line(line, &mut source_status, &mut target_status, &mut warnings);
        classify_warning_line(line, &mut warnings);
    }

    if remote_exit_code == Some(0) && target_status == "started" {
        "stalled".clone_into(&mut target_status);
        push_unique_warning(&mut warnings, "target_artifact_retrieval_stalled");
    }
    if remote_exit_code == Some(0) && source_status == "started" {
        "stalled".clone_into(&mut source_status);
        push_unique_warning(&mut warnings, "source_artifact_retrieval_stalled");
    }
    if matches!(remote_exit_code, Some(exit) if exit != 0) {
        push_unique_warning(&mut warnings, "remote_command_failed");
    }
    if worker_id.is_none() {
        push_unique_warning(&mut warnings, "worker_id_missing");
    }

    let fallback_detected = local_fallback_reason.is_some();
    let artifact_retrieval_status = RchArtifactRetrievalStatus {
        source: source_status,
        target: target_status,
    };
    let proof_verdict = rch_proof_verdict(
        fallback_detected,
        remote_exit_code,
        &artifact_retrieval_status,
        &warnings,
    );

    RchProofLedgerReport {
        schema_version: RCH_PROOF_LEDGER_SCHEMA_VERSION,
        command: redact_command_line(&config.command_line),
        cwd: config.cwd.clone(),
        env_allowlist: config.env_allowlist.clone(),
        worker_id,
        remote_exit_code,
        remote_duration_ms,
        fallback_detected,
        local_fallback_reason,
        artifact_retrieval_status,
        warnings,
        proof_verdict,
    }
}

/// Render an operator-facing Markdown summary for an RCH proof ledger.
#[must_use]
pub fn render_rch_proof_ledger_markdown(report: &RchProofLedgerReport) -> String {
    let command = if report.command.is_empty() {
        "<unknown>".to_owned()
    } else {
        report.command.join(" ")
    };
    let env_allowlist = if report.env_allowlist.is_empty() {
        "none".to_owned()
    } else {
        report.env_allowlist.join(", ")
    };
    let warnings = if report.warnings.is_empty() {
        "none".to_owned()
    } else {
        report.warnings.join(", ")
    };

    format!(
        "\
# RCH Proof Ledger

- Schema version: `{}`
- Verdict: `{}`
- Worker: `{}`
- Remote exit code: `{}`
- Remote duration ms: `{}`
- Fallback detected: `{}`
- Local fallback reason: `{}`
- Command: `{}`
- CWD: `{}`
- Environment allowlist: `{}`
- Source artifact retrieval: `{}`
- Target artifact retrieval: `{}`
- Warnings: `{}`

## Operator Decision

{}
",
        report.schema_version,
        report.proof_verdict,
        report.worker_id.as_deref().unwrap_or("unknown"),
        report
            .remote_exit_code
            .map_or_else(|| "unknown".to_owned(), |code| code.to_string()),
        report
            .remote_duration_ms
            .map_or_else(|| "unknown".to_owned(), |duration| duration.to_string()),
        report.fallback_detected,
        report.local_fallback_reason.as_deref().unwrap_or("none"),
        command,
        report.cwd,
        env_allowlist,
        report.artifact_retrieval_status.source,
        report.artifact_retrieval_status.target,
        warnings,
        rch_operator_decision(report),
    )
}

fn rch_operator_decision(report: &RchProofLedgerReport) -> &'static str {
    match report.proof_verdict.as_str() {
        "remote_success" => {
            "Worker-side `exit=0` is sufficient validation proof when the command, worker, and transcript match the claimed gate."
        }
        "remote_success_artifact_warning" => {
            "Worker-side `exit=0` is usable proof only with a degraded-proof note naming the artifact retrieval or rsync warning."
        }
        "invalid_local_fallback" => {
            "Local fallback is not remote validation proof. Rerun on RCH or report the remote-execution blocker."
        }
        "remote_failure" => {
            "The remote command failed. Treat this as a failed validation or product/tooling failure according to the command transcript."
        }
        _ => {
            "Remote worker evidence is incomplete. Do not claim validation until the transcript includes worker and exit evidence."
        }
    }
}

fn parse_selected_worker(line: &str) -> Option<String> {
    let worker = line
        .split_once("Selected worker: ")?
        .1
        .split_whitespace()
        .next()?;
    Some(worker.trim_end_matches(':').to_owned())
}

fn parse_rch_summary_worker(line: &str) -> Option<String> {
    let summary = line.strip_prefix("[RCH] remote ")?;
    let worker = summary.split_whitespace().next()?;
    if worker.is_empty() {
        None
    } else {
        Some(worker.to_owned())
    }
}

fn parse_remote_finished_line(line: &str) -> Option<(i32, u64)> {
    let details = line.split_once("Remote command finished: ")?.1;
    let exit = parse_i32_field(details, "exit=")?;
    let duration = parse_duration_ms_after_in(details)?;
    Some((exit, duration))
}

fn parse_rch_summary_line(line: &str) -> Option<(i32, Option<u64>)> {
    let summary = line.strip_prefix("[RCH] remote ")?;
    if let Some((_, exit_text)) = summary.split_once(" failed (exit ") {
        let exit = exit_text
            .split_once(')')
            .map_or(exit_text, |(value, _)| value)
            .parse()
            .ok()?;
        return Some((exit, None));
    }

    let duration = summary
        .rsplit_once('(')
        .and_then(|(_, raw)| raw.strip_suffix(')'))
        .and_then(parse_duration_text_ms);
    Some((0, duration))
}

fn parse_local_fallback_reason(line: &str) -> Option<String> {
    let reason = line.strip_prefix("[RCH] local (")?.strip_suffix(')')?;
    Some(reason.to_owned())
}

fn parse_i32_field(text: &str, prefix: &str) -> Option<i32> {
    let field = text.split_once(prefix)?.1;
    let raw = field
        .split(|ch: char| ch.is_whitespace() || ch == ',' || ch == ';')
        .next()?;
    raw.parse().ok()
}

fn parse_duration_ms_after_in(text: &str) -> Option<u64> {
    let duration = text.split_once(" in ")?.1.split_whitespace().next()?;
    parse_duration_text_ms(duration)
}

fn parse_duration_text_ms(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if let Some(ms) = trimmed.strip_suffix("ms") {
        return ms.parse().ok();
    }

    let seconds = trimmed.strip_suffix('s')?;
    let (whole, fractional) = seconds
        .split_once('.')
        .map_or((seconds, ""), |(whole, fractional)| (whole, fractional));
    let whole_ms = whole.parse::<u64>().ok()?.checked_mul(1_000)?;
    let fractional_ms = fractional_millis(fractional)?;
    whole_ms.checked_add(fractional_ms)
}

fn fractional_millis(fractional: &str) -> Option<u64> {
    let mut digits = fractional.chars();
    let mut millis = 0_u64;
    let weights = [100_u64, 10, 1];
    for weight in weights {
        let digit = digits.next().unwrap_or('0');
        if !digit.is_ascii_digit() {
            return None;
        }
        millis = millis.checked_add(u64::from(digit.to_digit(10)?) * weight)?;
    }
    Some(millis)
}

fn classify_artifact_line(
    line: &str,
    source_status: &mut String,
    target_status: &mut String,
    warnings: &mut Vec<String>,
) {
    let lower = line.to_ascii_lowercase();
    if lower.contains("retrieving artifacts from ") {
        if is_target_artifact_line(&lower) {
            "started".clone_into(target_status);
        } else {
            "started".clone_into(source_status);
        }
    }

    if lower.contains("custom cargo_target_dir artifacts retrieved")
        || lower.contains("target artifacts retrieved")
    {
        "retrieved".clone_into(target_status);
    } else if lower.contains("artifacts retrieved:") && *source_status == "started" {
        "retrieved".clone_into(source_status);
    }

    if lower.contains("artifact retrieval failed") || lower.contains("failed to retrieve artifacts")
    {
        if *target_status == "started" || is_target_artifact_line(&lower) {
            "warning".clone_into(target_status);
        } else {
            "warning".clone_into(source_status);
        }
        push_unique_warning(warnings, "artifact_retrieval_warning");
    }

    if lower.contains("rch_artifact_retrieval_stopped_after_remote_exit")
        || lower.contains("artifact retrieval stopped after remote exit")
    {
        "stalled".clone_into(target_status);
        push_unique_warning(warnings, "target_artifact_retrieval_stalled");
    }
}

fn classify_warning_line(line: &str, warnings: &mut Vec<String>) {
    let lower = line.to_ascii_lowercase();
    if lower.contains("rsync")
        && (lower.contains("warning") || lower.contains("failed") || lower.contains("mismatch"))
    {
        push_unique_warning(warnings, "rsync_verification_warning");
    }
    if lower.contains("target verification warning") {
        push_unique_warning(warnings, "rsync_verification_warning");
    }
    if lower.contains("remote evidence missing") {
        push_unique_warning(warnings, "remote_evidence_missing");
    }
}

fn is_target_artifact_line(lowercase_line: &str) -> bool {
    lowercase_line.contains(".rch-target")
        || lowercase_line.contains("cargo_target_dir")
        || lowercase_line.contains("target artifact")
}

fn push_unique_warning(warnings: &mut Vec<String>, warning: &str) {
    if !warnings.iter().any(|existing| existing == warning) {
        warnings.push(warning.to_owned());
    }
}

fn rch_proof_verdict(
    fallback_detected: bool,
    remote_exit_code: Option<i32>,
    artifact_retrieval_status: &RchArtifactRetrievalStatus,
    warnings: &[String],
) -> String {
    if fallback_detected {
        return "invalid_local_fallback".to_owned();
    }

    match remote_exit_code {
        Some(0) if has_artifact_warning(artifact_retrieval_status, warnings) => {
            "remote_success_artifact_warning".to_owned()
        }
        Some(0) => "remote_success".to_owned(),
        Some(_) => "remote_failure".to_owned(),
        None => "missing_remote_evidence".to_owned(),
    }
}

fn has_artifact_warning(
    artifact_retrieval_status: &RchArtifactRetrievalStatus,
    warnings: &[String],
) -> bool {
    matches!(
        artifact_retrieval_status.source.as_str(),
        "warning" | "stalled" | "failed"
    ) || matches!(
        artifact_retrieval_status.target.as_str(),
        "warning" | "stalled" | "failed"
    ) || warnings.iter().any(|warning| {
        matches!(
            warning.as_str(),
            "artifact_retrieval_warning"
                | "source_artifact_retrieval_stalled"
                | "target_artifact_retrieval_stalled"
                | "rsync_verification_warning"
        )
    })
}

/// Metadata for building a manifest from parsed E2E output.
pub struct ManifestParams<'a> {
    pub gate_id: &'a str,
    pub run_id: &'a str,
    pub created_at: &'a str,
    pub git_commit: &'a str,
    pub git_branch: &'a str,
    pub git_clean: bool,
    pub scenarios: &'a [ParsedScenario],
    pub log_path: Option<&'a str>,
    pub duration_secs: f64,
}

/// Parameters for building a readiness-grade operational manifest from a
/// script or Rust E2E runner invocation.
pub struct OperationalManifestParams<'a> {
    /// Gate identifier for the suite.
    pub gate_id: &'a str,
    /// Stable run identifier.
    pub run_id: &'a str,
    /// ISO 8601 creation timestamp.
    pub created_at: &'a str,
    /// Optional bead identifier for traceability.
    pub bead_id: Option<&'a str>,
    /// Current git commit.
    pub git_commit: &'a str,
    /// Current git branch.
    pub git_branch: &'a str,
    /// Whether the working tree was clean at run time.
    pub git_clean: bool,
    /// Captured host environment.
    pub environment: EnvironmentFingerprint,
    /// Exact command line used to launch the suite.
    pub command_line: Vec<String>,
    /// Hostname or worker identity.
    pub worker_host: &'a str,
    /// Optional RCH/CI worker identifier.
    pub worker_id: Option<&'a str>,
    /// FUSE capability result observed before mount-sensitive scenarios.
    pub fuse_capability: FuseCapabilityResult,
    /// Per-scenario observations.
    pub scenarios: Vec<OperationalScenarioInput>,
    /// Total suite duration in seconds.
    pub duration_secs: f64,
}

/// Per-scenario observation used by the shared operational runner.
#[derive(Debug, Clone, PartialEq)]
pub struct OperationalScenarioInput {
    /// Scenario identifier.
    pub scenario_id: String,
    /// Expected scenario result before execution.
    pub expected_outcome: ScenarioResult,
    /// Process exit status, or a runner-defined synthetic status.
    pub exit_status: i32,
    /// Whether the runner stopped the scenario because a timeout expired.
    pub timed_out: bool,
    /// Optional detail string copied into the generic scenario map.
    pub detail: Option<String>,
    /// Scenario duration in seconds.
    pub duration_secs: f64,
    /// Filesystem flavor exercised by the scenario.
    pub filesystem: FilesystemFlavor,
    /// Optional filesystem image digest.
    pub image_hash: Option<String>,
    /// Mount options used by the scenario.
    pub mount_options: Vec<String>,
    /// Scenario stdout path; generated if omitted.
    pub stdout_path: Option<String>,
    /// SHA-256 checksum of the scenario stdout artifact.
    pub stdout_sha256: String,
    /// Scenario stderr path; generated if omitted.
    pub stderr_path: Option<String>,
    /// SHA-256 checksum of the scenario stderr artifact.
    pub stderr_sha256: String,
    /// Evidence ledger paths produced or consumed by the scenario.
    pub ledger_paths: Vec<String>,
    /// Additional artifacts that should be indexed by the manifest.
    pub extra_artifacts: Vec<OperationalArtifactInput>,
    /// Cleanup result for mounts, images, and temporary directories.
    pub cleanup_status: CleanupStatus,
    /// Skip reason, when the scenario was skipped.
    pub skip_reason: Option<SkipReason>,
}

/// Additional artifact emitted by an operational scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalArtifactInput {
    /// Safe relative artifact path.
    pub path: String,
    /// Artifact category.
    pub category: ArtifactCategory,
    /// Optional MIME/content type.
    pub content_type: Option<String>,
    /// Artifact size in bytes.
    pub size_bytes: u64,
    /// Optional SHA-256 checksum.
    pub sha256: Option<String>,
}

/// Classification derived from a script observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalScenarioClassification {
    /// Generic scenario outcome to store in [`ArtifactManifest::scenarios`].
    pub actual_outcome: ScenarioResult,
    /// Operational pass/fail/skip/error classification.
    pub classification: OperationalOutcomeClass,
    /// Error class required for fail/error classifications.
    pub error_class: Option<OperationalErrorClass>,
    /// Skip reason required for skip classifications.
    pub skip_reason: Option<SkipReason>,
    /// Remediation hint required for fail/error and actionable skips.
    pub remediation_hint: Option<String>,
}

/// Raw FUSE probe observations before mapping into the canonical vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseCapabilityObservation {
    /// User/CI policy for mounted scenarios.
    pub user_setting: FuseProbeUserSetting,
    /// `/dev/fuse` presence.
    pub dev_fuse: FuseProbePresence,
    /// `fusermount3` or `fusermount` presence.
    pub fusermount: FuseProbePresence,
    /// Current worker access to `/dev/fuse`.
    pub dev_fuse_access: FuseProbeAccess,
    /// Optional active mount probe exit status.
    pub mount_probe_exit: Option<i32>,
}

/// User/CI setting for mounted scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuseProbeUserSetting {
    /// Mounted scenarios may run.
    Enabled,
    /// User or CI configuration intentionally disabled mounted scenarios.
    DisabledByUser,
}

/// Presence of a required FUSE resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuseProbePresence {
    /// Resource exists.
    Present,
    /// Resource is missing.
    Missing,
}

/// Access result for `/dev/fuse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuseProbeAccess {
    /// Worker can open `/dev/fuse` for read/write.
    ReadWrite,
    /// Worker cannot access `/dev/fuse` sufficiently for mounting.
    Denied,
}

/// Kernel/module state for FUSE probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuseProbeKernelModule {
    /// Kernel advertises FUSE support.
    Available,
    /// Kernel does not advertise FUSE support.
    Unavailable,
    /// Probe could not determine kernel support.
    Unknown,
}

/// User namespace or capability state for FUSE probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuseProbeUserNamespace {
    /// User/capability state should permit mount attempts.
    Available,
    /// User/capability state denies mount attempts.
    Denied,
    /// Probe could not determine user/capability state.
    Unknown,
}

/// DefaultPermissions-specific observation from a mounted btrfs workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuseDefaultPermissionsObservation {
    /// No DefaultPermissions issue was observed.
    NotObserved,
    /// A root-owned writable scenario hit EACCES before userspace handlers.
    RootOwnedBtrfsTestdirEacces,
}

/// Detailed failure kind for structured FUSE capability artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuseCapabilityFailureKind {
    UserDisabled,
    DevFuseMissing,
    DevFuseAccessDenied,
    FusermountMissing,
    KernelModuleUnavailable,
    UserNamespaceOrCapabilityDenied,
    MountProbeNotRun,
    MountProbeFailed,
    UnmountProbeFailed,
    DefaultPermissionsEacces,
}

/// Per-check status in a FUSE capability report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuseCapabilityCheckStatus {
    Pass,
    Fail,
    NotRun,
}

/// One check within a structured FUSE capability report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuseCapabilityCheck {
    pub name: String,
    pub status: FuseCapabilityCheckStatus,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation_hint: Option<String>,
}

/// Synthetic or host-observed inputs for the FUSE capability report builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseCapabilityProbeInput {
    pub user_setting: FuseProbeUserSetting,
    pub dev_fuse: FuseProbePresence,
    pub fusermount: FuseProbePresence,
    pub kernel_module: FuseProbeKernelModule,
    pub dev_fuse_access: FuseProbeAccess,
    pub user_namespace: FuseProbeUserNamespace,
    pub mount_probe_exit: Option<i32>,
    pub unmount_probe_exit: Option<i32>,
    pub default_permissions: FuseDefaultPermissionsObservation,
    pub mount_probe_required: bool,
}

/// Options for probing the current host from the harness CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FuseHostProbeOptions {
    pub user_disabled: bool,
    pub mount_probe_exit: Option<i32>,
    pub unmount_probe_exit: Option<i32>,
    pub default_permissions_eacces: bool,
    pub mount_probe_required: bool,
}

/// Structured FUSE capability artifact emitted before mount-sensitive gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuseCapabilityProbeReport {
    pub schema_version: u32,
    pub scenario_id: String,
    pub result: FuseCapabilityResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<SkipReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_kind: Option<FuseCapabilityFailureKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation_hint: Option<String>,
    pub checks: Vec<FuseCapabilityCheck>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

/// Exit code convention used by GNU timeout and many shell runners.
pub const TIMEOUT_EXIT_CODE: i32 = 124;

/// FUSE capability report schema version.
pub const FUSE_CAPABILITY_REPORT_SCHEMA_VERSION: u32 = 1;

/// Build an [`ArtifactManifest`] from parsed E2E output and run metadata.
///
/// The manifest's verdict is automatically computed: FAIL if any scenario
/// failed, PASS otherwise.
#[must_use]
pub fn build_manifest_from_parsed(params: &ManifestParams<'_>) -> ArtifactManifest {
    let mut builder = ManifestBuilder::new(params.run_id, params.gate_id, params.created_at)
        .git_context(params.git_commit, params.git_branch, params.git_clean)
        .duration_secs(params.duration_secs);

    for scenario in params.scenarios {
        builder = builder.scenario(
            &scenario.scenario_id,
            scenario.outcome,
            scenario.detail.as_deref(),
            0.0,
        );
    }

    if let Some(path) = params.log_path {
        builder = builder.artifact(ArtifactEntry {
            path: path.to_owned(),
            category: ArtifactCategory::E2eLog,
            content_type: Some("text/plain".to_owned()),
            size_bytes: 0,
            sha256: None,
            redacted: false,
            metadata: BTreeMap::new(),
        });
    }

    let manifest = builder.build();

    let outcome_str = match manifest.verdict {
        GateVerdict::Pass => "completed",
        GateVerdict::Fail => "failed",
        GateVerdict::Skip => "skipped",
    };

    info!(
        operation_id = params.run_id,
        scenario_id = params.gate_id,
        outcome = outcome_str,
        gate_id = params.gate_id,
        run_id = params.run_id,
        scenarios = params.scenarios.len(),
        verdict = ?manifest.verdict,
        "verification_runner_manifest_built"
    );

    manifest
}

/// Build a readiness-grade operational manifest from script observations.
///
/// This is the Rust half of the shared E2E runner contract. Shell scripts can
/// still orchestrate host-specific commands, but they should either call this
/// builder through a Rust entrypoint or emit JSON that passes
/// [`validate_operational_manifest`].
#[must_use]
pub fn build_operational_manifest(params: OperationalManifestParams<'_>) -> ArtifactManifest {
    let OperationalManifestParams {
        gate_id,
        run_id,
        created_at,
        bead_id,
        git_commit,
        git_branch,
        git_clean,
        environment,
        command_line,
        worker_host,
        worker_id,
        fuse_capability,
        scenarios,
        duration_secs,
    } = params;
    let run_stdout = operational_run_log_path(run_id, "stdout");
    let run_stderr = operational_run_log_path(run_id, "stderr");
    let host_fingerprint = operational_host_fingerprint(&environment, worker_host);
    let event_context = OperationalReadinessEventContext {
        gate_id,
        run_id,
        created_at,
        bead_id,
        git_commit,
        command_line: &command_line,
        host_fingerprint: &host_fingerprint,
        fuse_capability,
    };
    let mut builder = ManifestBuilder::new(run_id, gate_id, created_at)
        .git_context(git_commit, git_branch, git_clean)
        .environment(environment)
        .operational_context(OperationalRunContext {
            command_line: redact_command_line(&command_line),
            worker: WorkerContext {
                host: worker_host.to_owned(),
                worker_id: worker_id.map(str::to_owned),
            },
            fuse_capability,
            stdout_path: run_stdout.clone(),
            stderr_path: run_stderr.clone(),
        })
        .artifact(log_artifact_entry(&run_stdout, ArtifactCategory::RawLog))
        .artifact(log_artifact_entry(&run_stderr, ArtifactCategory::RawLog))
        .duration_secs(duration_secs);

    if let Some(bead_id) = bead_id {
        builder = builder.bead_id(bead_id);
    }

    for scenario in scenarios {
        builder = add_operational_manifest_scenario(builder, event_context, scenario);
    }

    builder.build()
}

#[derive(Clone, Copy)]
struct OperationalReadinessEventContext<'a> {
    gate_id: &'a str,
    run_id: &'a str,
    created_at: &'a str,
    bead_id: Option<&'a str>,
    git_commit: &'a str,
    command_line: &'a [String],
    host_fingerprint: &'a str,
    fuse_capability: FuseCapabilityResult,
}

fn add_operational_manifest_scenario(
    mut builder: ManifestBuilder,
    context: OperationalReadinessEventContext<'_>,
    scenario: OperationalScenarioInput,
) -> ManifestBuilder {
    let classification = classify_operational_observation(
        scenario.exit_status,
        scenario.timed_out,
        scenario.skip_reason,
        scenario.cleanup_status,
    );
    let stdout_path = scenario.stdout_path.unwrap_or_else(|| {
        operational_scenario_log_path(context.run_id, &scenario.scenario_id, "stdout")
    });
    let stderr_path = scenario.stderr_path.unwrap_or_else(|| {
        operational_scenario_log_path(context.run_id, &scenario.scenario_id, "stderr")
    });

    let mut artifact_refs = vec![stdout_path.clone(), stderr_path.clone()];
    artifact_refs.extend(scenario.ledger_paths.iter().cloned());
    artifact_refs.extend(
        scenario
            .extra_artifacts
            .iter()
            .map(|artifact| artifact.path.clone()),
    );

    builder = builder
        .scenario(
            &scenario.scenario_id,
            classification.actual_outcome,
            scenario.detail.as_deref(),
            scenario.duration_secs,
        )
        .operational_scenario(OperationalScenarioRecord {
            scenario_id: scenario.scenario_id.clone(),
            filesystem: scenario.filesystem,
            image_hash: scenario.image_hash,
            mount_options: scenario.mount_options,
            expected_outcome: scenario.expected_outcome,
            actual_outcome: classification.actual_outcome,
            classification: classification.classification,
            exit_status: scenario.exit_status,
            stdout_path: stdout_path.clone(),
            stderr_path: stderr_path.clone(),
            ledger_paths: scenario.ledger_paths.clone(),
            artifact_refs: artifact_refs.clone(),
            cleanup_status: scenario.cleanup_status,
            error_class: classification.error_class,
            remediation_hint: classification.remediation_hint,
            skip_reason: classification.skip_reason,
        })
        .readiness_event(operational_readiness_event(
            context,
            &scenario.scenario_id,
            classification.classification,
            &stdout_path,
            &stderr_path,
        ))
        .artifact(log_artifact_entry_with_sha(
            &stdout_path,
            ArtifactCategory::RawLog,
            &scenario.stdout_sha256,
        ))
        .artifact(log_artifact_entry_with_sha(
            &stderr_path,
            ArtifactCategory::RawLog,
            &scenario.stderr_sha256,
        ));

    for ledger_path in scenario.ledger_paths {
        builder = builder.artifact(log_artifact_entry(&ledger_path, ArtifactCategory::E2eLog));
    }
    for artifact in scenario.extra_artifacts {
        builder = builder.artifact(ArtifactEntry {
            path: artifact.path,
            category: artifact.category,
            content_type: artifact.content_type,
            size_bytes: artifact.size_bytes,
            sha256: artifact.sha256,
            redacted: false,
            metadata: BTreeMap::from([("scenario_id".to_owned(), scenario.scenario_id.clone())]),
        });
    }
    builder
}

fn operational_readiness_event(
    context: OperationalReadinessEventContext<'_>,
    scenario_id: &str,
    classification: OperationalOutcomeClass,
    stdout_path: &str,
    stderr_path: &str,
) -> ReadinessEventEnvelope {
    let report_id = format!("report_{}", sanitize_artifact_segment(context.run_id));

    ReadinessEventEnvelope {
        envelope_version: READINESS_EVENT_ENVELOPE_VERSION,
        event_id: format!(
            "event_{}_{}",
            sanitize_artifact_segment(context.run_id),
            scenario_id
        ),
        report_id: report_id.clone(),
        run_id: context.run_id.to_owned(),
        lane_id: context.gate_id.to_owned(),
        scenario_id: Some(scenario_id.to_owned()),
        aggregate_marker: None,
        artifact_id: stdout_path.to_owned(),
        parent_correlation_id: Some(report_id),
        classification,
        severity: readiness_event_severity(classification),
        created_at: context.created_at.to_owned(),
        git_commit: context.git_commit.to_owned(),
        host_fingerprint: context.host_fingerprint.to_owned(),
        capability_fingerprint: operational_capability_fingerprint(context.fuse_capability),
        raw_log_refs: vec![stdout_path.to_owned(), stderr_path.to_owned()],
        controlling_evidence: vec![stdout_path.to_owned()],
        remediation_id: operational_remediation_id(context, scenario_id),
        reproduction_command: operational_reproduction_command(context.command_line, scenario_id),
    }
}

const fn readiness_event_severity(
    classification: OperationalOutcomeClass,
) -> ReadinessEventSeverity {
    match classification {
        OperationalOutcomeClass::Pass => ReadinessEventSeverity::Info,
        OperationalOutcomeClass::Skip => ReadinessEventSeverity::Warning,
        OperationalOutcomeClass::Fail | OperationalOutcomeClass::Error => {
            ReadinessEventSeverity::Error
        }
    }
}

fn operational_host_fingerprint(environment: &EnvironmentFingerprint, worker_host: &str) -> String {
    format!(
        "{}|{}|{}cpu|{}GiB|{}",
        worker_host,
        environment.kernel,
        environment.cpu_count,
        environment.memory_gib,
        environment.rustc_version
    )
}

fn operational_capability_fingerprint(fuse_capability: FuseCapabilityResult) -> String {
    let fuse = match fuse_capability {
        FuseCapabilityResult::Available => "available",
        FuseCapabilityResult::Unavailable => "unavailable",
        FuseCapabilityResult::PermissionDenied => "permission_denied",
        FuseCapabilityResult::DisabledByUser => "disabled_by_user",
        FuseCapabilityResult::NotApplicable => "not_applicable",
        FuseCapabilityResult::NotChecked => "not_checked",
    };
    format!("fuse={fuse}")
}

fn operational_remediation_id(
    context: OperationalReadinessEventContext<'_>,
    scenario_id: &str,
) -> String {
    let prefix = context.bead_id.unwrap_or(context.gate_id);
    format!("{prefix}:{scenario_id}")
}

fn operational_reproduction_command(command_line: &[String], scenario_id: &str) -> String {
    let command = command_line
        .iter()
        .find_map(|part| {
            let trimmed = part.trim();
            (!trimmed.is_empty() && !trimmed.contains(REDACTED_SENTINEL)).then_some(trimmed)
        })
        .unwrap_or("scripts/e2e/runner.sh");

    format!("{command} --scenario {scenario_id}")
}

/// Classify the outcome of one script-level scenario observation.
#[must_use]
pub fn classify_operational_observation(
    exit_status: i32,
    timed_out: bool,
    skip_reason: Option<SkipReason>,
    cleanup_status: CleanupStatus,
) -> OperationalScenarioClassification {
    if timed_out || exit_status == TIMEOUT_EXIT_CODE {
        return OperationalScenarioClassification {
            actual_outcome: ScenarioResult::Fail,
            classification: OperationalOutcomeClass::Error,
            error_class: Some(OperationalErrorClass::ResourceLimit),
            skip_reason: None,
            remediation_hint: Some(
                "Scenario timed out; inspect stdout/stderr and rerun with a larger timeout only after confirming it is not a hang."
                    .to_owned(),
            ),
        };
    }

    if cleanup_status == CleanupStatus::Failed {
        return OperationalScenarioClassification {
            actual_outcome: ScenarioResult::Fail,
            classification: OperationalOutcomeClass::Error,
            error_class: Some(OperationalErrorClass::UnsafeCleanupFailure),
            skip_reason: None,
            remediation_hint: Some(
                "Cleanup failed; inspect preserved artifacts and host mount state before rerunning."
                    .to_owned(),
            ),
        };
    }

    if let Some(reason) = skip_reason {
        return OperationalScenarioClassification {
            actual_outcome: ScenarioResult::Skip,
            classification: OperationalOutcomeClass::Skip,
            error_class: None,
            skip_reason: Some(reason),
            remediation_hint: skip_remediation_hint(reason).map(str::to_owned),
        };
    }

    if exit_status == exit_code::PASS {
        OperationalScenarioClassification {
            actual_outcome: ScenarioResult::Pass,
            classification: OperationalOutcomeClass::Pass,
            error_class: None,
            skip_reason: None,
            remediation_hint: None,
        }
    } else {
        OperationalScenarioClassification {
            actual_outcome: ScenarioResult::Fail,
            classification: OperationalOutcomeClass::Fail,
            error_class: Some(OperationalErrorClass::ProductFailure),
            skip_reason: None,
            remediation_hint: Some(
                "Scenario command exited non-zero; inspect scenario stdout/stderr and product logs."
                    .to_owned(),
            ),
        }
    }
}

/// Convert simple probe observations into the shared FUSE capability result.
#[must_use]
pub const fn classify_fuse_capability(
    observation: FuseCapabilityObservation,
) -> FuseCapabilityResult {
    if matches!(
        observation.user_setting,
        FuseProbeUserSetting::DisabledByUser
    ) {
        return FuseCapabilityResult::DisabledByUser;
    }
    if matches!(observation.dev_fuse, FuseProbePresence::Missing)
        || matches!(observation.fusermount, FuseProbePresence::Missing)
    {
        return FuseCapabilityResult::Unavailable;
    }
    if matches!(observation.dev_fuse_access, FuseProbeAccess::Denied) {
        return FuseCapabilityResult::PermissionDenied;
    }
    if let Some(exit_code) = observation.mount_probe_exit
        && exit_code != 0
    {
        return FuseCapabilityResult::PermissionDenied;
    }
    FuseCapabilityResult::Available
}

/// Probe the current host enough to emit a structured FUSE capability artifact.
///
/// This does not create or mount a filesystem by itself. Mount-sensitive E2E
/// scripts should pass the observed mount and unmount probe exit codes through
/// [`FuseHostProbeOptions`] so the resulting artifact proves the full boundary.
#[must_use]
pub fn probe_host_fuse_capability(options: FuseHostProbeOptions) -> FuseCapabilityProbeReport {
    let dev_fuse_path = Path::new("/dev/fuse");
    let dev_fuse = if dev_fuse_path.exists() {
        FuseProbePresence::Present
    } else {
        FuseProbePresence::Missing
    };
    let dev_fuse_access = if dev_fuse == FuseProbePresence::Present
        && fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dev_fuse_path)
            .is_ok()
    {
        FuseProbeAccess::ReadWrite
    } else {
        FuseProbeAccess::Denied
    };

    let input = FuseCapabilityProbeInput {
        user_setting: if options.user_disabled {
            FuseProbeUserSetting::DisabledByUser
        } else {
            FuseProbeUserSetting::Enabled
        },
        dev_fuse,
        fusermount: if find_program(&["fusermount3", "fusermount"]).is_some() {
            FuseProbePresence::Present
        } else {
            FuseProbePresence::Missing
        },
        kernel_module: probe_fuse_kernel_module(),
        dev_fuse_access,
        user_namespace: FuseProbeUserNamespace::Unknown,
        mount_probe_exit: options.mount_probe_exit,
        unmount_probe_exit: options.unmount_probe_exit,
        default_permissions: if options.default_permissions_eacces {
            FuseDefaultPermissionsObservation::RootOwnedBtrfsTestdirEacces
        } else {
            FuseDefaultPermissionsObservation::NotObserved
        },
        mount_probe_required: options.mount_probe_required,
    };

    build_fuse_capability_probe_report(input)
}

/// Build a structured FUSE capability report from synthetic or observed inputs.
#[must_use]
pub fn build_fuse_capability_probe_report(
    input: FuseCapabilityProbeInput,
) -> FuseCapabilityProbeReport {
    let decision = fuse_capability_decision(&input);

    FuseCapabilityProbeReport {
        schema_version: FUSE_CAPABILITY_REPORT_SCHEMA_VERSION,
        scenario_id: "fuse_capability_probe".to_owned(),
        result: decision.result,
        skip_reason: decision.skip_reason,
        failure_kind: decision.failure_kind,
        remediation_hint: decision.remediation_hint,
        checks: fuse_capability_checks(&input),
        metadata: BTreeMap::from([(
            "mount_probe_required".to_owned(),
            input.mount_probe_required.to_string(),
        )]),
    }
}

/// Redact sensitive command-line arguments while preserving reproduction shape.
#[must_use]
pub fn redact_command_line(args: &[String]) -> Vec<String> {
    let mut redacted = Vec::with_capacity(args.len());
    let mut redact_next = false;

    for arg in args {
        if redact_next {
            redacted.push("[REDACTED]".to_owned());
            redact_next = false;
            continue;
        }

        if let Some((name, _value)) = arg.split_once('=')
            && is_sensitive_arg_name(name)
        {
            redacted.push(format!("{name}=[REDACTED]"));
            continue;
        }

        redacted.push(arg.clone());
        if is_sensitive_arg_name(arg) {
            redact_next = true;
        }
    }

    redacted
}

/// Generate a run-level log path under the standard E2E artifact directory.
#[must_use]
pub fn operational_run_log_path(run_id: &str, stream: &str) -> String {
    format!(
        "artifacts/e2e/{}/{}.log",
        sanitize_artifact_segment(run_id),
        sanitize_artifact_segment(stream)
    )
}

/// Generate a scenario-level log path under the standard E2E artifact directory.
#[must_use]
pub fn operational_scenario_log_path(run_id: &str, scenario_id: &str, stream: &str) -> String {
    format!(
        "artifacts/e2e/{}/scenarios/{}/{}.log",
        sanitize_artifact_segment(run_id),
        sanitize_artifact_segment(scenario_id),
        sanitize_artifact_segment(stream)
    )
}

struct FuseCapabilityDecision {
    result: FuseCapabilityResult,
    skip_reason: Option<SkipReason>,
    failure_kind: Option<FuseCapabilityFailureKind>,
    remediation_hint: Option<String>,
}

fn fuse_capability_checks(input: &FuseCapabilityProbeInput) -> Vec<FuseCapabilityCheck> {
    vec![
        user_enabled_check(input.user_setting),
        dev_fuse_presence_check(input.dev_fuse),
        fusermount_presence_check(input.fusermount),
        kernel_module_check(input.kernel_module),
        dev_fuse_access_check(input.dev_fuse_access),
        user_namespace_check(input.user_namespace),
        exit_probe_check(
            "mount_probe",
            input.mount_probe_exit,
            input.mount_probe_required,
            "mount probe completed successfully",
            "mount probe failed",
            "run a real mount probe and pass its exit code into the capability report",
        ),
        exit_probe_check(
            "unmount_probe",
            input.unmount_probe_exit,
            input.mount_probe_required,
            "unmount probe completed successfully",
            "unmount probe failed",
            "run a real unmount probe and pass its exit code into the capability report",
        ),
        default_permissions_check(input.default_permissions),
    ]
}

fn user_enabled_check(setting: FuseProbeUserSetting) -> FuseCapabilityCheck {
    capability_check(
        "user_enabled",
        if setting == FuseProbeUserSetting::Enabled {
            FuseCapabilityCheckStatus::Pass
        } else {
            FuseCapabilityCheckStatus::Fail
        },
        match setting {
            FuseProbeUserSetting::Enabled => "FUSE lanes are enabled for this run",
            FuseProbeUserSetting::DisabledByUser => {
                "FUSE lanes were disabled by user or CI configuration"
            }
        },
        disabled_by_user_remediation(setting).map(str::to_owned),
    )
}

fn dev_fuse_presence_check(presence: FuseProbePresence) -> FuseCapabilityCheck {
    capability_check(
        "dev_fuse_present",
        presence_status(presence),
        match presence {
            FuseProbePresence::Present => "/dev/fuse exists",
            FuseProbePresence::Missing => "/dev/fuse is missing",
        },
        missing_presence_remediation(presence, "enable the FUSE kernel device").map(str::to_owned),
    )
}

fn fusermount_presence_check(presence: FuseProbePresence) -> FuseCapabilityCheck {
    capability_check(
        "fusermount_present",
        presence_status(presence),
        match presence {
            FuseProbePresence::Present => "fusermount3 or fusermount is available",
            FuseProbePresence::Missing => "fusermount3/fusermount is missing",
        },
        missing_presence_remediation(presence, "install fuse3 or fuse userspace tools")
            .map(str::to_owned),
    )
}

fn kernel_module_check(module: FuseProbeKernelModule) -> FuseCapabilityCheck {
    capability_check(
        "kernel_module_available",
        match module {
            FuseProbeKernelModule::Available => FuseCapabilityCheckStatus::Pass,
            FuseProbeKernelModule::Unavailable => FuseCapabilityCheckStatus::Fail,
            FuseProbeKernelModule::Unknown => FuseCapabilityCheckStatus::NotRun,
        },
        match module {
            FuseProbeKernelModule::Available => "kernel advertises FUSE support",
            FuseProbeKernelModule::Unavailable => "kernel does not advertise FUSE support",
            FuseProbeKernelModule::Unknown => "kernel FUSE support could not be determined",
        },
        (module == FuseProbeKernelModule::Unavailable)
            .then_some("load the fuse kernel module or use a kernel with FUSE support")
            .map(str::to_owned),
    )
}

fn dev_fuse_access_check(access: FuseProbeAccess) -> FuseCapabilityCheck {
    capability_check(
        "dev_fuse_access",
        match access {
            FuseProbeAccess::ReadWrite => FuseCapabilityCheckStatus::Pass,
            FuseProbeAccess::Denied => FuseCapabilityCheckStatus::Fail,
        },
        match access {
            FuseProbeAccess::ReadWrite => "current process can open /dev/fuse read/write",
            FuseProbeAccess::Denied => "current process cannot open /dev/fuse read/write",
        },
        (access == FuseProbeAccess::Denied)
            .then_some("grant the worker read/write access to /dev/fuse")
            .map(str::to_owned),
    )
}

fn user_namespace_check(namespace: FuseProbeUserNamespace) -> FuseCapabilityCheck {
    capability_check(
        "user_namespace_or_capability",
        match namespace {
            FuseProbeUserNamespace::Available => FuseCapabilityCheckStatus::Pass,
            FuseProbeUserNamespace::Denied => FuseCapabilityCheckStatus::Fail,
            FuseProbeUserNamespace::Unknown => FuseCapabilityCheckStatus::NotRun,
        },
        match namespace {
            FuseProbeUserNamespace::Available => {
                "user namespace/capability state permits mount attempts"
            }
            FuseProbeUserNamespace::Denied => "user namespace/capability state denies mounts",
            FuseProbeUserNamespace::Unknown => "user namespace/capability state was not probed",
        },
        (namespace == FuseProbeUserNamespace::Denied)
            .then_some("run on a worker whose namespace and capabilities allow FUSE mounts")
            .map(str::to_owned),
    )
}

fn default_permissions_check(
    observation: FuseDefaultPermissionsObservation,
) -> FuseCapabilityCheck {
    capability_check(
        "default_permissions_workspace",
        match observation {
            FuseDefaultPermissionsObservation::NotObserved => FuseCapabilityCheckStatus::Pass,
            FuseDefaultPermissionsObservation::RootOwnedBtrfsTestdirEacces => {
                FuseCapabilityCheckStatus::Fail
            }
        },
        match observation {
            FuseDefaultPermissionsObservation::NotObserved => {
                "no DefaultPermissions/EACCES workspace issue observed"
            }
            FuseDefaultPermissionsObservation::RootOwnedBtrfsTestdirEacces => {
                "root-owned btrfs testdir hit EACCES before userspace handlers"
            }
        },
        (observation == FuseDefaultPermissionsObservation::RootOwnedBtrfsTestdirEacces)
            .then_some("seed a writable btrfs workspace directory inside the image")
            .map(str::to_owned),
    )
}

fn fuse_capability_decision(input: &FuseCapabilityProbeInput) -> FuseCapabilityDecision {
    if input.user_setting == FuseProbeUserSetting::DisabledByUser {
        return fuse_failure(
            FuseCapabilityResult::DisabledByUser,
            SkipReason::UserDisabled,
            FuseCapabilityFailureKind::UserDisabled,
            "FUSE lanes were disabled by user or CI configuration.",
        );
    }
    if input.dev_fuse == FuseProbePresence::Missing {
        return fuse_failure(
            FuseCapabilityResult::Unavailable,
            SkipReason::FuseUnavailable,
            FuseCapabilityFailureKind::DevFuseMissing,
            "Enable /dev/fuse or use a worker with the FUSE kernel device.",
        );
    }
    if input.fusermount == FuseProbePresence::Missing {
        return fuse_failure(
            FuseCapabilityResult::Unavailable,
            SkipReason::WorkerDependencyMissing,
            FuseCapabilityFailureKind::FusermountMissing,
            "Install fusermount3 or fusermount before running mounted tests.",
        );
    }
    if input.kernel_module == FuseProbeKernelModule::Unavailable {
        return fuse_failure(
            FuseCapabilityResult::Unavailable,
            SkipReason::FuseUnavailable,
            FuseCapabilityFailureKind::KernelModuleUnavailable,
            "Load the fuse kernel module or use a kernel with FUSE support.",
        );
    }
    if input.dev_fuse_access == FuseProbeAccess::Denied {
        return fuse_failure(
            FuseCapabilityResult::PermissionDenied,
            SkipReason::FusePermissionDenied,
            FuseCapabilityFailureKind::DevFuseAccessDenied,
            "Grant the worker read/write access to /dev/fuse.",
        );
    }
    if input.user_namespace == FuseProbeUserNamespace::Denied {
        return fuse_failure(
            FuseCapabilityResult::PermissionDenied,
            SkipReason::FusePermissionDenied,
            FuseCapabilityFailureKind::UserNamespaceOrCapabilityDenied,
            "Run on a worker whose namespace and capabilities allow FUSE mounts.",
        );
    }
    if input.mount_probe_required && input.mount_probe_exit.is_none() {
        return FuseCapabilityDecision {
            result: FuseCapabilityResult::NotChecked,
            skip_reason: None,
            failure_kind: Some(FuseCapabilityFailureKind::MountProbeNotRun),
            remediation_hint: Some(
                "Run a real mount/unmount probe before classifying this lane as ready.".to_owned(),
            ),
        };
    }
    if input.mount_probe_exit.is_some_and(|exit| exit != 0) {
        return fuse_failure(
            FuseCapabilityResult::PermissionDenied,
            SkipReason::FusePermissionDenied,
            FuseCapabilityFailureKind::MountProbeFailed,
            "Inspect the mount probe log and rerun on a permissioned FUSE worker.",
        );
    }
    if input.unmount_probe_exit.is_some_and(|exit| exit != 0) {
        return fuse_failure(
            FuseCapabilityResult::PermissionDenied,
            SkipReason::FusePermissionDenied,
            FuseCapabilityFailureKind::UnmountProbeFailed,
            "Inspect the unmount log and clean the mountpoint before rerunning.",
        );
    }
    if input.default_permissions == FuseDefaultPermissionsObservation::RootOwnedBtrfsTestdirEacces {
        return fuse_failure(
            FuseCapabilityResult::PermissionDenied,
            SkipReason::RootOwnedBtrfsTestdirEacces,
            FuseCapabilityFailureKind::DefaultPermissionsEacces,
            "Seed a writable btrfs workspace directory inside the image.",
        );
    }

    FuseCapabilityDecision {
        result: FuseCapabilityResult::Available,
        skip_reason: None,
        failure_kind: None,
        remediation_hint: None,
    }
}

fn fuse_failure(
    result: FuseCapabilityResult,
    skip_reason: SkipReason,
    failure_kind: FuseCapabilityFailureKind,
    remediation_hint: &str,
) -> FuseCapabilityDecision {
    FuseCapabilityDecision {
        result,
        skip_reason: Some(skip_reason),
        failure_kind: Some(failure_kind),
        remediation_hint: Some(remediation_hint.to_owned()),
    }
}

fn capability_check(
    name: &str,
    status: FuseCapabilityCheckStatus,
    detail: &str,
    remediation_hint: Option<String>,
) -> FuseCapabilityCheck {
    FuseCapabilityCheck {
        name: name.to_owned(),
        status,
        detail: detail.to_owned(),
        remediation_hint,
    }
}

fn presence_status(presence: FuseProbePresence) -> FuseCapabilityCheckStatus {
    match presence {
        FuseProbePresence::Present => FuseCapabilityCheckStatus::Pass,
        FuseProbePresence::Missing => FuseCapabilityCheckStatus::Fail,
    }
}

fn missing_presence_remediation(
    presence: FuseProbePresence,
    remediation: &'static str,
) -> Option<&'static str> {
    (presence == FuseProbePresence::Missing).then_some(remediation)
}

fn disabled_by_user_remediation(setting: FuseProbeUserSetting) -> Option<&'static str> {
    (setting == FuseProbeUserSetting::DisabledByUser)
        .then_some("unset the mount skip flag when a permissioned host is available")
}

fn exit_probe_check(
    name: &str,
    exit_code: Option<i32>,
    required: bool,
    pass_detail: &str,
    fail_detail: &str,
    not_run_remediation: &str,
) -> FuseCapabilityCheck {
    match exit_code {
        Some(0) => capability_check(name, FuseCapabilityCheckStatus::Pass, pass_detail, None),
        Some(code) => capability_check(
            name,
            FuseCapabilityCheckStatus::Fail,
            &format!("{fail_detail}: exit {code}"),
            Some("inspect the probe stdout/stderr artifact".to_owned()),
        ),
        None if required => capability_check(
            name,
            FuseCapabilityCheckStatus::Fail,
            "probe was required but did not run",
            Some(not_run_remediation.to_owned()),
        ),
        None => capability_check(
            name,
            FuseCapabilityCheckStatus::NotRun,
            "probe was not run",
            Some(not_run_remediation.to_owned()),
        ),
    }
}

fn probe_fuse_kernel_module() -> FuseProbeKernelModule {
    if Path::new("/sys/module/fuse").exists() {
        return FuseProbeKernelModule::Available;
    }

    fs::read_to_string("/proc/filesystems").map_or(FuseProbeKernelModule::Unknown, |filesystems| {
        if filesystems.lines().any(|line| {
            line.split_whitespace()
                .next_back()
                .is_some_and(|name| name == "fuse" || name == "fuseblk")
        }) {
            FuseProbeKernelModule::Available
        } else {
            FuseProbeKernelModule::Unavailable
        }
    })
}

fn find_program(candidates: &[&str]) -> Option<String> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        for candidate in candidates {
            let path = dir.join(candidate);
            if path.is_file() {
                return Some(path.display().to_string());
            }
        }
    }
    None
}

fn log_artifact_entry(path: &str, category: ArtifactCategory) -> ArtifactEntry {
    ArtifactEntry {
        path: path.to_owned(),
        category,
        content_type: Some("text/plain".to_owned()),
        size_bytes: 0,
        sha256: None,
        redacted: false,
        metadata: BTreeMap::new(),
    }
}

fn log_artifact_entry_with_sha(
    path: &str,
    category: ArtifactCategory,
    sha256: &str,
) -> ArtifactEntry {
    ArtifactEntry {
        path: path.to_owned(),
        category,
        content_type: Some("text/plain".to_owned()),
        size_bytes: 0,
        sha256: Some(sha256.to_owned()),
        redacted: false,
        metadata: BTreeMap::new(),
    }
}

fn is_sensitive_arg_name(arg: &str) -> bool {
    let lower = arg.trim_start_matches('-').to_ascii_lowercase();
    let normalized: String = lower.chars().filter(char::is_ascii_alphanumeric).collect();
    lower.contains("token")
        || lower.contains("password")
        || lower.contains("secret")
        || normalized.contains("apikey")
        || normalized.contains("accesskey")
        || normalized.contains("privatekey")
        || normalized == "auth"
}

fn sanitize_artifact_segment(raw: &str) -> String {
    let mut sanitized = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            sanitized.push(ch);
        } else {
            sanitized.push('_');
        }
    }
    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        "artifact".to_owned()
    } else {
        sanitized
    }
}

fn skip_remediation_hint(reason: SkipReason) -> Option<&'static str> {
    match reason {
        SkipReason::FuseUnavailable => {
            Some("Install and enable FUSE before running mounted tests.")
        }
        SkipReason::FusePermissionDenied => {
            Some("Grant the worker access to /dev/fuse and fusermount before rerunning.")
        }
        SkipReason::UserDisabled => {
            Some("Unset the skip flag when a permissioned host is available.")
        }
        SkipReason::WorkerDependencyMissing => Some("Install the missing worker dependency."),
        SkipReason::UnsupportedV1Scope => Some(
            "This behavior is outside the declared V1 scope; link a feature bead before enabling it.",
        ),
        SkipReason::RootOwnedBtrfsTestdirEacces => Some(
            "Seed a writable btrfs test directory instead of writing to the root-owned image root.",
        ),
        SkipReason::NotApplicable => None,
    }
}

/// Validate that all parsed scenario IDs conform to the canonical regex.
///
/// Returns a list of invalid scenario IDs found (empty = all valid).
#[must_use]
pub fn validate_scenario_ids(scenarios: &[ParsedScenario]) -> Vec<String> {
    scenarios
        .iter()
        .filter(|s| !is_valid_scenario_id(&s.scenario_id))
        .map(|s| s.scenario_id.clone())
        .collect()
}

/// Run a full contract validation on a manifest built from parsed output.
///
/// Returns a combined list of manifest validation errors and invalid scenario IDs.
/// Empty = fully conformant.
#[must_use]
pub fn validate_gate_contract(manifest: &ArtifactManifest) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();

    // Manifest schema validation
    for err in validate_manifest(manifest) {
        errors.push(format!("manifest: {err}"));
    }

    // Scenario ID regex validation (redundant with validate_manifest but explicit)
    for id in manifest.scenarios.keys() {
        if !is_valid_scenario_id(id) {
            errors.push(format!("invalid scenario_id: {id}"));
        }
    }

    errors
}

/// Run the stricter operational readiness contract validation.
#[must_use]
pub fn validate_operational_gate_contract(manifest: &ArtifactManifest) -> Vec<String> {
    validate_operational_manifest(manifest)
        .into_iter()
        .map(|err| format!("operational manifest: {err}"))
        .collect()
}

// ── Script conformance checking ──────────────────────────────────────────

/// Conformance violations found in an E2E script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConformanceViolation {
    /// Script does not source lib.sh.
    MissingLibSource,
    /// Script does not call e2e_init.
    MissingE2eInit,
    /// Script does not emit any SCENARIO_RESULT markers.
    NoScenarioMarkers,
    /// Script uses `status=` instead of `outcome=` in markers.
    LegacyStatusField,
    /// Script does not set `set -euo pipefail`.
    MissingStrictMode,
    /// Script does not have a summary section that checks FAIL_COUNT.
    MissingSummaryExit,
}

impl std::fmt::Display for ConformanceViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingLibSource => write!(f, "script does not source lib.sh"),
            Self::MissingE2eInit => write!(f, "script does not call e2e_init"),
            Self::NoScenarioMarkers => write!(f, "script emits no SCENARIO_RESULT markers"),
            Self::LegacyStatusField => {
                write!(f, "script uses 'status=' instead of 'outcome=' in markers")
            }
            Self::MissingStrictMode => write!(f, "script missing 'set -euo pipefail'"),
            Self::MissingSummaryExit => {
                write!(f, "script missing summary section with exit code logic")
            }
        }
    }
}

/// Check whether an E2E script source follows the runner conventions.
///
/// Performs static analysis of the script text (not execution).
/// Returns a list of violations (empty = conformant).
#[must_use]
pub fn check_script_conformance(script_source: &str) -> Vec<ConformanceViolation> {
    let mut violations = Vec::new();

    // Must source lib.sh
    if !script_source.contains("source \"$REPO_ROOT/scripts/e2e/lib.sh\"")
        && !script_source.contains("source \"$(dirname \"$0\")/lib.sh\"")
    {
        violations.push(ConformanceViolation::MissingLibSource);
    }

    // Must call e2e_init
    if !script_source.contains("e2e_init") {
        violations.push(ConformanceViolation::MissingE2eInit);
    }

    // Must emit SCENARIO_RESULT markers
    if !script_source.contains("SCENARIO_RESULT") && !script_source.contains("scenario_result") {
        violations.push(ConformanceViolation::NoScenarioMarkers);
    }

    // Should use outcome= not status= in every marker. A script can otherwise
    // hide a legacy marker behind one conforming marker elsewhere.
    if script_source.contains("|status=") {
        violations.push(ConformanceViolation::LegacyStatusField);
    }

    // Must have strict mode
    if !script_source.contains("set -euo pipefail") {
        violations.push(ConformanceViolation::MissingStrictMode);
    }

    // Must have summary with exit code
    if !script_source.contains("FAIL_COUNT") && !script_source.contains("fail_count") {
        violations.push(ConformanceViolation::MissingSummaryExit);
    }

    violations
}

// ── Retry logic ──────────────────────────────────────────────────────────

/// Configuration for the verification runner.
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// Gate identifier for the manifest.
    pub gate_id: String,
    /// Maximum retries per script in CI mode (0 = no retries).
    pub max_retries: u32,
    /// Whether running in CI mode (enables retries, stricter checks).
    pub ci_mode: bool,
}

impl RunnerConfig {
    /// Create a config for local (interactive) mode.
    #[must_use]
    pub fn local(gate_id: &str) -> Self {
        Self {
            gate_id: gate_id.to_owned(),
            max_retries: 0,
            ci_mode: false,
        }
    }

    /// Create a config for CI/nightly mode with default retries.
    #[must_use]
    pub fn ci(gate_id: &str) -> Self {
        Self {
            gate_id: gate_id.to_owned(),
            max_retries: DEFAULT_CI_MAX_RETRIES,
            ci_mode: true,
        }
    }
}

/// Result of running an E2E script (possibly with retries).
#[derive(Debug, Clone)]
pub struct ScriptRunResult {
    /// Script path that was executed.
    pub script: String,
    /// Exit code from the last attempt.
    pub exit_code: i32,
    /// Number of attempts made (1 = no retries).
    pub attempts: u32,
    /// Parsed scenarios from the final attempt's output.
    pub scenarios: Vec<ParsedScenario>,
    /// Whether the script ultimately passed.
    pub passed: bool,
}

/// Aggregate multiple script run results into a single gate verdict.
#[must_use]
pub fn aggregate_verdict(results: &[ScriptRunResult]) -> GateVerdict {
    if results.is_empty() {
        return GateVerdict::Skip;
    }
    if results.iter().all(|r| r.passed) {
        GateVerdict::Pass
    } else {
        GateVerdict::Fail
    }
}

/// Merge scenarios from multiple script runs into a single flat list.
#[must_use]
pub fn merge_scenarios(results: &[ScriptRunResult]) -> Vec<ScenarioOutcome> {
    let mut merged = Vec::new();
    for result in results {
        for scenario in &result.scenarios {
            merged.push(ScenarioOutcome {
                scenario_id: scenario.scenario_id.clone(),
                outcome: scenario.outcome,
                detail: scenario.detail.clone(),
                duration_secs: 0.0,
            });
        }
    }
    merged
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_manifest::validate_manifest;

    fn parsed_scenario(
        scenarios: &[ParsedScenario],
        index: usize,
    ) -> Result<&ParsedScenario, String> {
        scenarios
            .get(index)
            .ok_or_else(|| format!("expected parsed scenario at index {index}"))
    }

    fn scenario_outcome(
        scenarios: &[ScenarioOutcome],
        index: usize,
    ) -> Result<&ScenarioOutcome, String> {
        scenarios
            .get(index)
            .ok_or_else(|| format!("expected scenario outcome at index {index}"))
    }

    fn manifest_artifact(
        manifest: &ArtifactManifest,
        index: usize,
    ) -> Result<&ArtifactEntry, String> {
        manifest
            .artifacts
            .get(index)
            .ok_or_else(|| format!("expected manifest artifact at index {index}"))
    }

    fn readiness_event(
        manifest: &ArtifactManifest,
        index: usize,
    ) -> Result<&ReadinessEventEnvelope, String> {
        manifest
            .readiness_events
            .get(index)
            .ok_or_else(|| format!("expected readiness event at index {index}"))
    }

    fn sample_rch_proof_config() -> RchProofLedgerConfig {
        RchProofLedgerConfig {
            command_line: vec![
                "cargo".to_owned(),
                "test".to_owned(),
                "-p".to_owned(),
                "ffs-harness".to_owned(),
                format!("--{}{}", "api", "-key"),
                "sample-credential".to_owned(),
            ],
            cwd: "/data/projects/frankenfs".to_owned(),
            env_allowlist: vec!["CARGO_TARGET_DIR".to_owned(), "RUSTFLAGS".to_owned()],
        }
    }

    fn has_rch_warning(report: &RchProofLedgerReport, warning: &str) -> bool {
        report.warnings.iter().any(|candidate| candidate == warning)
    }

    fn artifact_warning_rch_proof_report() -> RchProofLedgerReport {
        let transcript = "\
Selected worker: vmi1227854 at ubuntu@203.0.113.10
Remote command finished: exit=0 in 2400ms
Retrieving artifacts from /data/projects/frankenfs on vmi1227854
Artifacts retrieved: 4 files, 16K
Retrieving artifacts from /data/projects/frankenfs/.rch-target on vmi1227854
[RCH] remote vmi1227854 (2.4s)
";
        build_rch_proof_ledger_report(transcript, &sample_rch_proof_config())
    }

    fn operational_scenario<'a>(
        manifest: &'a ArtifactManifest,
        scenario_id: &str,
    ) -> Result<&'a OperationalScenarioRecord, String> {
        manifest
            .operational_scenarios
            .get(scenario_id)
            .ok_or_else(|| format!("missing operational scenario `{scenario_id}`"))
    }

    // ── Contract version ─────────────────────────────────────────────

    #[test]
    fn runner_contract_version_is_positive() {
        const { assert!(RUNNER_CONTRACT_VERSION >= 1) };
    }

    // ── parse_e2e_output ─────────────────────────────────────────────

    #[test]
    fn parse_e2e_output_extracts_pass_and_fail() -> Result<(), String> {
        let output = "\
=== Scenario 1 ===
SCENARIO_RESULT|scenario_id=cli_mount_help_contract|outcome=PASS|detail=help text matches
=== Scenario 2 ===
SCENARIO_RESULT|scenario_id=cli_mount_invalid_timeout|outcome=FAIL|detail=exit code was 0
";
        let scenarios = parse_e2e_output(output);
        assert_eq!(scenarios.len(), 2);

        let first = parsed_scenario(&scenarios, 0)?;
        assert_eq!(first.scenario_id, "cli_mount_help_contract");
        assert_eq!(first.outcome, ScenarioResult::Pass);
        assert_eq!(first.detail.as_deref(), Some("help text matches"));
        assert_eq!(first.line_number, 2);

        let second = parsed_scenario(&scenarios, 1)?;
        assert_eq!(second.scenario_id, "cli_mount_invalid_timeout");
        assert_eq!(second.outcome, ScenarioResult::Fail);
        assert_eq!(second.line_number, 4);
        Ok(())
    }

    #[test]
    fn parse_e2e_output_ignores_non_markers() -> Result<(), String> {
        let output = "\
Running test suite...
Some random log line
SCENARIO_RESULT|scenario_id=some_test_scenario|outcome=PASS
Another log line
";
        let scenarios = parse_e2e_output(output);
        assert_eq!(scenarios.len(), 1);
        assert_eq!(
            parsed_scenario(&scenarios, 0)?.scenario_id,
            "some_test_scenario"
        );
        Ok(())
    }

    #[test]
    fn parse_e2e_output_empty_input() {
        let scenarios = parse_e2e_output("");
        assert_eq!(scenarios, [] as [ParsedScenario; 0]);
    }

    #[test]
    fn parse_e2e_output_no_markers() {
        let output = "just some regular output\nno markers here\n";
        let scenarios = parse_e2e_output(output);
        assert_eq!(scenarios, [] as [ParsedScenario; 0]);
    }

    #[test]
    fn parse_e2e_output_skips_malformed_markers() -> Result<(), String> {
        let output = "\
SCENARIO_RESULT|outcome=PASS
SCENARIO_RESULT|scenario_id=valid_test_marker|outcome=PASS
SCENARIO_RESULT|scenario_id=another_test|bad_field
";
        let scenarios = parse_e2e_output(output);
        // Only the valid marker with both scenario_id and outcome parses
        assert_eq!(scenarios.len(), 1);
        assert_eq!(
            parsed_scenario(&scenarios, 0)?.scenario_id,
            "valid_test_marker"
        );
        Ok(())
    }

    // ── RCH proof ledger ────────────────────────────────────────────

    #[test]
    fn rch_proof_ledger_parses_remote_success() {
        let transcript = "\
Selected worker: vmi1227854 at ubuntu@203.0.113.10
Executing command remotely: cargo test -p ffs-harness
Remote command finished: exit=0 in 30485ms
Retrieving artifacts from /data/projects/frankenfs on vmi1227854
Artifacts retrieved: 1307 files, 44.0M
Retrieving artifacts from /data/projects/frankenfs/.rch-target on vmi1227854
Custom CARGO_TARGET_DIR artifacts retrieved: 824 files, 26.0M
[RCH] remote vmi1227854 (142.8s)
";
        let report = build_rch_proof_ledger_report(transcript, &sample_rch_proof_config());

        assert_eq!(report.schema_version, RCH_PROOF_LEDGER_SCHEMA_VERSION);
        assert_eq!(report.worker_id.as_deref(), Some("vmi1227854"));
        assert_eq!(report.remote_exit_code, Some(0));
        assert_eq!(report.remote_duration_ms, Some(30_485));
        assert!(!report.fallback_detected);
        assert_eq!(report.artifact_retrieval_status.source, "retrieved");
        assert_eq!(report.artifact_retrieval_status.target, "retrieved");
        assert_eq!(report.proof_verdict, "remote_success");
        assert_eq!(
            report.command,
            vec![
                "cargo".to_owned(),
                "test".to_owned(),
                "-p".to_owned(),
                "ffs-harness".to_owned(),
                format!("--{}{}", "api", "-key"),
                "[REDACTED]".to_owned(),
            ]
        );
    }

    #[test]
    fn rch_proof_ledger_rejects_local_fallback() {
        let transcript = "\
Remote execution failed before worker proof was captured.
[RCH] local (remote execution failed)
";
        let report = build_rch_proof_ledger_report(transcript, &sample_rch_proof_config());

        assert!(report.fallback_detected);
        assert_eq!(
            report.local_fallback_reason.as_deref(),
            Some("remote execution failed")
        );
        assert_eq!(report.remote_exit_code, None);
        assert_eq!(report.proof_verdict, "invalid_local_fallback");
        assert!(has_rch_warning(&report, "local_fallback_detected"));
    }

    #[test]
    fn rch_proof_ledger_classifies_worker_failure() {
        let transcript = "\
Selected worker: vmi1227854 at ubuntu@203.0.113.10
Remote command finished: exit=101 in 50604ms
[RCH] remote vmi1227854 failed (exit 101)
";
        let report = build_rch_proof_ledger_report(transcript, &sample_rch_proof_config());

        assert_eq!(report.worker_id.as_deref(), Some("vmi1227854"));
        assert_eq!(report.remote_exit_code, Some(101));
        assert_eq!(report.remote_duration_ms, Some(50_604));
        assert_eq!(report.proof_verdict, "remote_failure");
        assert!(has_rch_warning(&report, "remote_command_failed"));
    }

    #[test]
    fn rch_proof_ledger_classifies_artifact_retrieval_warning() {
        let transcript = "\
Selected worker: vmi1227854 at ubuntu@203.0.113.10
Remote command finished: exit=0 in 1200ms
Retrieving artifacts from /data/projects/frankenfs on vmi1227854
Artifacts retrieved: 4 files, 16K
Retrieving artifacts from /data/projects/frankenfs/.rch-target on vmi1227854
Artifact retrieval failed: rsync target verification warning
[RCH] remote vmi1227854 (1.2s)
";
        let report = build_rch_proof_ledger_report(transcript, &sample_rch_proof_config());

        assert_eq!(report.remote_exit_code, Some(0));
        assert_eq!(report.artifact_retrieval_status.source, "retrieved");
        assert_eq!(report.artifact_retrieval_status.target, "warning");
        assert_eq!(report.proof_verdict, "remote_success_artifact_warning");
        assert!(has_rch_warning(&report, "artifact_retrieval_warning"));
    }

    #[test]
    fn rch_proof_ledger_classifies_artifact_retrieval_stall() {
        let transcript = "\
Selected worker: vmi1227854 at ubuntu@203.0.113.10
Remote command finished: exit=0 in 2400ms
Retrieving artifacts from /data/projects/frankenfs on vmi1227854
Artifacts retrieved: 4 files, 16K
Retrieving artifacts from /data/projects/frankenfs/.rch-target on vmi1227854
[RCH] remote vmi1227854 (2.4s)
";
        let report = build_rch_proof_ledger_report(transcript, &sample_rch_proof_config());

        assert_eq!(report.remote_exit_code, Some(0));
        assert_eq!(report.artifact_retrieval_status.source, "retrieved");
        assert_eq!(report.artifact_retrieval_status.target, "stalled");
        assert_eq!(report.proof_verdict, "remote_success_artifact_warning");
        assert!(has_rch_warning(
            &report,
            "target_artifact_retrieval_stalled"
        ));
    }

    #[test]
    fn rch_proof_ledger_degrades_success_on_rsync_warning() {
        let transcript = "\
Selected worker: vmi1227854 at ubuntu@203.0.113.10
Remote command finished: exit=0 in 1200ms
Retrieving artifacts from /data/projects/frankenfs on vmi1227854
Artifacts retrieved: 4 files, 16K
Retrieving artifacts from /data/projects/frankenfs/.rch-target on vmi1227854
Custom CARGO_TARGET_DIR artifacts retrieved: 8 files, 32K
WARN rch::transfer: rsync verification warning: checksum mismatch
[RCH] remote vmi1227854 (1.2s)
";
        let report = build_rch_proof_ledger_report(transcript, &sample_rch_proof_config());

        assert_eq!(report.remote_exit_code, Some(0));
        assert_eq!(report.artifact_retrieval_status.source, "retrieved");
        assert_eq!(report.artifact_retrieval_status.target, "retrieved");
        assert_eq!(report.proof_verdict, "remote_success_artifact_warning");
        assert!(has_rch_warning(&report, "rsync_verification_warning"));
    }

    #[test]
    fn rch_proof_ledger_markdown_summarizes_operator_decision() {
        let report = artifact_warning_rch_proof_report();
        let markdown = render_rch_proof_ledger_markdown(&report);

        assert!(markdown.contains("# RCH Proof Ledger"));
        assert!(markdown.contains("Verdict: `remote_success_artifact_warning`"));
        assert!(markdown.contains("Target artifact retrieval: `stalled`"));
        assert!(markdown.contains("degraded-proof note"));
        assert!(!markdown.contains("sample-credential"));
    }

    #[test]
    fn rch_proof_ledger_report_json_shape() -> Result<(), serde_json::Error> {
        let report = artifact_warning_rch_proof_report();
        let json = serde_json::to_string_pretty(&report)?;

        insta::assert_snapshot!("rch_proof_ledger_report_json_shape", json);
        let parsed: RchProofLedgerReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn render_rch_proof_ledger_markdown_artifact_warning_snapshot() {
        let report = artifact_warning_rch_proof_report();
        let markdown = render_rch_proof_ledger_markdown(&report);

        insta::assert_snapshot!(
            "render_rch_proof_ledger_markdown_artifact_warning",
            markdown
        );
        assert!(!markdown.contains("sample-credential"));
    }

    // ── build_manifest_from_parsed ───────────────────────────────────

    #[test]
    fn build_manifest_all_pass_verdict_is_pass() {
        let scenarios = vec![
            ParsedScenario {
                scenario_id: "test_happy_path".to_owned(),
                outcome: ScenarioResult::Pass,
                detail: None,
                line_number: 1,
            },
            ParsedScenario {
                scenario_id: "test_edge_case".to_owned(),
                outcome: ScenarioResult::Pass,
                detail: None,
                line_number: 2,
            },
        ];
        let manifest = build_manifest_from_parsed(&ManifestParams {
            gate_id: "ffs_smoke",
            run_id: "run-001",
            created_at: "2026-03-12T00:00:00Z",
            git_commit: "abc123",
            git_branch: "main",
            git_clean: true,
            scenarios: &scenarios,
            log_path: None,
            duration_secs: 1.5,
        });
        assert_eq!(manifest.verdict, GateVerdict::Pass);
        assert_eq!(manifest.scenarios.len(), 2);
        let errors = validate_manifest(&manifest);
        assert!(errors.is_empty(), "validation errors: {errors:?}");
    }

    #[test]
    fn build_manifest_any_fail_verdict_is_fail() -> Result<(), String> {
        let scenarios = vec![
            ParsedScenario {
                scenario_id: "test_happy_pass".to_owned(),
                outcome: ScenarioResult::Pass,
                detail: None,
                line_number: 1,
            },
            ParsedScenario {
                scenario_id: "test_broken_case".to_owned(),
                outcome: ScenarioResult::Fail,
                detail: Some("checksum mismatch".to_owned()),
                line_number: 2,
            },
        ];
        let manifest = build_manifest_from_parsed(&ManifestParams {
            gate_id: "ffs_smoke",
            run_id: "run-002",
            created_at: "2026-03-12T00:00:00Z",
            git_commit: "def456",
            git_branch: "main",
            git_clean: true,
            scenarios: &scenarios,
            log_path: Some("artifacts/e2e/run.log"),
            duration_secs: 3.0,
        });
        assert_eq!(manifest.verdict, GateVerdict::Fail);
        assert_eq!(manifest.artifacts.len(), 1);
        assert_eq!(
            manifest_artifact(&manifest, 0)?.category,
            ArtifactCategory::E2eLog
        );
        Ok(())
    }

    #[test]
    fn build_manifest_empty_scenarios_is_pass() {
        let manifest = build_manifest_from_parsed(&ManifestParams {
            gate_id: "empty_gate",
            run_id: "run-003",
            created_at: "2026-03-12T00:00:00Z",
            git_commit: "000000",
            git_branch: "main",
            git_clean: true,
            scenarios: &[],
            log_path: None,
            duration_secs: 0.0,
        });
        assert_eq!(manifest.verdict, GateVerdict::Pass);
        assert!(manifest.scenarios.is_empty());
    }

    // ── operational manifest runner ─────────────────────────────────

    fn sample_environment() -> EnvironmentFingerprint {
        EnvironmentFingerprint {
            hostname: "worker-01".to_owned(),
            cpu_model: "test-cpu".to_owned(),
            cpu_count: 8,
            memory_gib: 16,
            kernel: "Linux 6.17.0".to_owned(),
            rustc_version: "rustc 1.91.0-nightly".to_owned(),
            cargo_version: Some("cargo 1.91.0-nightly".to_owned()),
        }
    }

    fn scenario_input(
        scenario_id: &str,
        exit_status: i32,
        skip_reason: Option<SkipReason>,
    ) -> OperationalScenarioInput {
        OperationalScenarioInput {
            scenario_id: scenario_id.to_owned(),
            expected_outcome: ScenarioResult::Pass,
            exit_status,
            timed_out: false,
            detail: None,
            duration_secs: 0.25,
            filesystem: FilesystemFlavor::Ext4,
            image_hash: Some("sha256:test-image".to_owned()),
            mount_options: vec!["ro".to_owned()],
            stdout_path: None,
            stdout_sha256: sample_sha256(&format!("{scenario_id}-stdout")),
            stderr_path: None,
            stderr_sha256: sample_sha256(&format!("{scenario_id}-stderr")),
            ledger_paths: vec![],
            extra_artifacts: vec![],
            cleanup_status: CleanupStatus::Clean,
            skip_reason,
        }
    }

    fn sample_sha256(label: &str) -> String {
        use sha2::{Digest, Sha256};

        format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
    }

    fn base_fuse_probe_input() -> FuseCapabilityProbeInput {
        FuseCapabilityProbeInput {
            user_setting: FuseProbeUserSetting::Enabled,
            dev_fuse: FuseProbePresence::Present,
            fusermount: FuseProbePresence::Present,
            kernel_module: FuseProbeKernelModule::Available,
            dev_fuse_access: FuseProbeAccess::ReadWrite,
            user_namespace: FuseProbeUserNamespace::Available,
            mount_probe_exit: Some(0),
            unmount_probe_exit: Some(0),
            default_permissions: FuseDefaultPermissionsObservation::NotObserved,
            mount_probe_required: true,
        }
    }

    #[test]
    fn classify_operational_observation_maps_pass_fail_skip_and_timeout() {
        let pass = classify_operational_observation(0, false, None, CleanupStatus::Clean);
        assert_eq!(pass.actual_outcome, ScenarioResult::Pass);
        assert_eq!(pass.classification, OperationalOutcomeClass::Pass);
        assert_eq!(pass.error_class, None);

        let fail = classify_operational_observation(1, false, None, CleanupStatus::Clean);
        assert_eq!(fail.actual_outcome, ScenarioResult::Fail);
        assert_eq!(fail.classification, OperationalOutcomeClass::Fail);
        assert_eq!(
            fail.error_class,
            Some(OperationalErrorClass::ProductFailure)
        );
        assert!(fail.remediation_hint.is_some());

        let skip = classify_operational_observation(
            0,
            false,
            Some(SkipReason::FuseUnavailable),
            CleanupStatus::Clean,
        );
        assert_eq!(skip.actual_outcome, ScenarioResult::Skip);
        assert_eq!(skip.classification, OperationalOutcomeClass::Skip);
        assert_eq!(skip.skip_reason, Some(SkipReason::FuseUnavailable));
        assert!(skip.remediation_hint.is_some());

        let timeout =
            classify_operational_observation(TIMEOUT_EXIT_CODE, false, None, CleanupStatus::Clean);
        assert_eq!(timeout.actual_outcome, ScenarioResult::Fail);
        assert_eq!(timeout.classification, OperationalOutcomeClass::Error);
        assert_eq!(
            timeout.error_class,
            Some(OperationalErrorClass::ResourceLimit)
        );
        assert!(timeout.remediation_hint.is_some());
    }

    #[test]
    fn cleanup_failure_is_a_runner_error_with_preserved_diagnostics() {
        let result = classify_operational_observation(0, false, None, CleanupStatus::Failed);
        assert_eq!(result.actual_outcome, ScenarioResult::Fail);
        assert_eq!(result.classification, OperationalOutcomeClass::Error);
        assert_eq!(
            result.error_class,
            Some(OperationalErrorClass::UnsafeCleanupFailure),
        );
        assert!(
            result
                .remediation_hint
                .as_deref()
                .is_some_and(|hint| hint.contains("mount state"))
        );
    }

    #[test]
    fn classify_fuse_capability_distinguishes_host_skip_causes() {
        let base = FuseCapabilityObservation {
            user_setting: FuseProbeUserSetting::Enabled,
            dev_fuse: FuseProbePresence::Present,
            fusermount: FuseProbePresence::Present,
            dev_fuse_access: FuseProbeAccess::ReadWrite,
            mount_probe_exit: Some(0),
        };

        assert_eq!(
            classify_fuse_capability(FuseCapabilityObservation {
                user_setting: FuseProbeUserSetting::DisabledByUser,
                ..base
            }),
            FuseCapabilityResult::DisabledByUser
        );
        assert_eq!(
            classify_fuse_capability(FuseCapabilityObservation {
                dev_fuse: FuseProbePresence::Missing,
                mount_probe_exit: None,
                ..base
            }),
            FuseCapabilityResult::Unavailable
        );
        assert_eq!(
            classify_fuse_capability(FuseCapabilityObservation {
                fusermount: FuseProbePresence::Missing,
                mount_probe_exit: None,
                ..base
            }),
            FuseCapabilityResult::Unavailable
        );
        assert_eq!(
            classify_fuse_capability(FuseCapabilityObservation {
                dev_fuse_access: FuseProbeAccess::Denied,
                mount_probe_exit: None,
                ..base
            }),
            FuseCapabilityResult::PermissionDenied
        );
        assert_eq!(
            classify_fuse_capability(FuseCapabilityObservation {
                mount_probe_exit: Some(1),
                ..base
            }),
            FuseCapabilityResult::PermissionDenied
        );
        assert_eq!(
            classify_fuse_capability(base),
            FuseCapabilityResult::Available
        );
    }

    #[test]
    fn fuse_capability_report_classifies_missing_dev_fuse() {
        let report = build_fuse_capability_probe_report(FuseCapabilityProbeInput {
            dev_fuse: FuseProbePresence::Missing,
            dev_fuse_access: FuseProbeAccess::Denied,
            mount_probe_exit: None,
            unmount_probe_exit: None,
            ..base_fuse_probe_input()
        });

        assert_eq!(report.result, FuseCapabilityResult::Unavailable);
        assert_eq!(report.skip_reason, Some(SkipReason::FuseUnavailable));
        assert_eq!(
            report.failure_kind,
            Some(FuseCapabilityFailureKind::DevFuseMissing)
        );
        assert!(report.remediation_hint.is_some());
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "dev_fuse_present"
                    && check.status == FuseCapabilityCheckStatus::Fail)
        );
    }

    #[test]
    fn fuse_capability_report_classifies_missing_fusermount() {
        let report = build_fuse_capability_probe_report(FuseCapabilityProbeInput {
            fusermount: FuseProbePresence::Missing,
            ..base_fuse_probe_input()
        });

        assert_eq!(report.result, FuseCapabilityResult::Unavailable);
        assert_eq!(
            report.skip_reason,
            Some(SkipReason::WorkerDependencyMissing)
        );
        assert_eq!(
            report.failure_kind,
            Some(FuseCapabilityFailureKind::FusermountMissing)
        );
    }

    #[test]
    fn fuse_capability_report_classifies_kernel_module_unavailable() {
        let report = build_fuse_capability_probe_report(FuseCapabilityProbeInput {
            kernel_module: FuseProbeKernelModule::Unavailable,
            ..base_fuse_probe_input()
        });

        assert_eq!(report.result, FuseCapabilityResult::Unavailable);
        assert_eq!(report.skip_reason, Some(SkipReason::FuseUnavailable));
        assert_eq!(
            report.failure_kind,
            Some(FuseCapabilityFailureKind::KernelModuleUnavailable)
        );
    }

    #[test]
    fn fuse_capability_report_classifies_user_namespace_denial() {
        let report = build_fuse_capability_probe_report(FuseCapabilityProbeInput {
            user_namespace: FuseProbeUserNamespace::Denied,
            ..base_fuse_probe_input()
        });

        assert_eq!(report.result, FuseCapabilityResult::PermissionDenied);
        assert_eq!(report.skip_reason, Some(SkipReason::FusePermissionDenied));
        assert_eq!(
            report.failure_kind,
            Some(FuseCapabilityFailureKind::UserNamespaceOrCapabilityDenied)
        );
    }

    #[test]
    fn fuse_capability_report_requires_mount_probe_when_requested() {
        let report = build_fuse_capability_probe_report(FuseCapabilityProbeInput {
            mount_probe_exit: None,
            unmount_probe_exit: None,
            mount_probe_required: true,
            ..base_fuse_probe_input()
        });

        assert_eq!(report.result, FuseCapabilityResult::NotChecked);
        assert_eq!(report.skip_reason, None);
        assert_eq!(
            report.failure_kind,
            Some(FuseCapabilityFailureKind::MountProbeNotRun)
        );
        assert!(
            report.checks.iter().any(|check| check.name == "mount_probe"
                && check.status == FuseCapabilityCheckStatus::Fail)
        );
    }

    #[test]
    fn fuse_capability_report_classifies_mount_success() {
        let report = build_fuse_capability_probe_report(base_fuse_probe_input());

        assert_eq!(report.result, FuseCapabilityResult::Available);
        assert_eq!(report.skip_reason, None);
        assert_eq!(report.failure_kind, None);
        assert!(
            report.checks.iter().any(|check| check.name == "mount_probe"
                && check.status == FuseCapabilityCheckStatus::Pass)
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "unmount_probe"
                    && check.status == FuseCapabilityCheckStatus::Pass)
        );
    }

    #[test]
    fn fuse_capability_report_classifies_unmount_failure() {
        let report = build_fuse_capability_probe_report(FuseCapabilityProbeInput {
            unmount_probe_exit: Some(1),
            ..base_fuse_probe_input()
        });

        assert_eq!(report.result, FuseCapabilityResult::PermissionDenied);
        assert_eq!(report.skip_reason, Some(SkipReason::FusePermissionDenied));
        assert_eq!(
            report.failure_kind,
            Some(FuseCapabilityFailureKind::UnmountProbeFailed)
        );
    }

    #[test]
    fn fuse_capability_report_classifies_default_permissions_eacces() {
        let report = build_fuse_capability_probe_report(FuseCapabilityProbeInput {
            default_permissions: FuseDefaultPermissionsObservation::RootOwnedBtrfsTestdirEacces,
            ..base_fuse_probe_input()
        });

        assert_eq!(report.result, FuseCapabilityResult::PermissionDenied);
        assert_eq!(
            report.skip_reason,
            Some(SkipReason::RootOwnedBtrfsTestdirEacces)
        );
        assert_eq!(
            report.failure_kind,
            Some(FuseCapabilityFailureKind::DefaultPermissionsEacces)
        );
        assert!(
            report
                .remediation_hint
                .as_deref()
                .is_some_and(|hint| hint.contains("writable btrfs workspace"))
        );
    }

    #[test]
    fn fuse_capability_report_serializes_machine_readable_artifact() -> Result<(), serde_json::Error>
    {
        let report = build_fuse_capability_probe_report(base_fuse_probe_input());
        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("fuse_capability_report_json_shape", json);
        let parsed: FuseCapabilityProbeReport = serde_json::from_str(&json)?;

        assert_eq!(parsed, report);
        assert_eq!(parsed.scenario_id, "fuse_capability_probe");
        assert_eq!(parsed.schema_version, FUSE_CAPABILITY_REPORT_SCHEMA_VERSION);
        Ok(())
    }

    #[test]
    fn command_line_redaction_preserves_reproduction_shape() {
        let split_sensitive_flag = format!("--{}{}", "to", "ken");
        let inline_sensitive_arg = format!("--{}{}=sample-credential", "pa", "ssword");
        let expected_inline_sensitive_arg = format!("--{}{}=[REDACTED]", "pa", "ssword");
        let raw = vec![
            "ffs".to_owned(),
            "repair".to_owned(),
            split_sensitive_flag.clone(),
            "sample-credential".to_owned(),
            inline_sensitive_arg,
            "--background-scrub-ledger".to_owned(),
            "artifacts/e2e/run/ledger.jsonl".to_owned(),
        ];
        let redacted = redact_command_line(&raw);
        assert_eq!(
            redacted,
            vec![
                "ffs".to_owned(),
                "repair".to_owned(),
                split_sensitive_flag,
                "[REDACTED]".to_owned(),
                expected_inline_sensitive_arg,
                "--background-scrub-ledger".to_owned(),
                "artifacts/e2e/run/ledger.jsonl".to_owned(),
            ]
        );
    }

    #[test]
    fn command_line_redaction_normalizes_sensitive_arg_spellings() {
        let underscore_key_arg = format!("--{}{}=sample-credential", "api", "_key");
        let expected_underscore_key_arg = format!("--{}{}=[REDACTED]", "api", "_key");
        let compact_key_arg = format!("--{}{}=sample-credential", "api", "key");
        let expected_compact_key_arg = format!("--{}{}=[REDACTED]", "api", "key");
        let split_access_key = format!("--{}{}", "access", "_key");
        let inline_aws_access_key = format!("AWS_{}{}_ID=sample-credential", "ACCESS", "_KEY");
        let expected_inline_aws_access_key = format!("AWS_{}{}_ID=[REDACTED]", "ACCESS", "_KEY");
        let split_private_key = format!("--{}{}", "private", "key");
        let raw = vec![
            "ffs-harness".to_owned(),
            underscore_key_arg,
            compact_key_arg,
            split_access_key.clone(),
            "sample-credential".to_owned(),
            inline_aws_access_key,
            split_private_key.clone(),
            "sample-credential".to_owned(),
            "--artifact-root".to_owned(),
            "artifacts/e2e/run".to_owned(),
        ];
        let redacted = redact_command_line(&raw);
        assert_eq!(
            redacted,
            vec![
                "ffs-harness".to_owned(),
                expected_underscore_key_arg,
                expected_compact_key_arg,
                split_access_key,
                "[REDACTED]".to_owned(),
                expected_inline_aws_access_key,
                split_private_key,
                "[REDACTED]".to_owned(),
                "--artifact-root".to_owned(),
                "artifacts/e2e/run".to_owned(),
            ]
        );
    }

    #[test]
    fn operational_log_paths_are_safe_relative_artifact_paths() {
        assert_eq!(
            operational_run_log_path("run 01/../../bad", "std/out"),
            "artifacts/e2e/run_01_______bad/std_out.log"
        );
        assert_eq!(
            operational_scenario_log_path("run-01", "mounted_ext4_rw", "stderr"),
            "artifacts/e2e/run-01/scenarios/mounted_ext4_rw/stderr.log"
        );
    }

    #[test]
    fn build_operational_manifest_emits_valid_pass_fail_skip_and_error_records()
    -> Result<(), String> {
        let mut timeout = scenario_input("runner_timeout_error_case", 0, None);
        timeout.timed_out = true;
        timeout.cleanup_status = CleanupStatus::PreservedArtifacts;
        timeout.extra_artifacts.push(OperationalArtifactInput {
            path: "artifacts/e2e/run-001/scenarios/runner_timeout_error_case/repro.json".to_owned(),
            category: ArtifactCategory::ReproPack,
            content_type: Some("application/json".to_owned()),
            size_bytes: 128,
            sha256: Some("sha256-timeout-repro".to_owned()),
        });

        let manifest = build_operational_manifest(OperationalManifestParams {
            gate_id: "runner_operational_smoke",
            run_id: "run-001",
            created_at: "2026-05-01T12:00:00Z",
            bead_id: Some("bd-rchk0.4.2"),
            git_commit: "abc123",
            git_branch: "main",
            git_clean: false,
            environment: sample_environment(),
            command_line: vec![
                "scripts/e2e/runner.sh".to_owned(),
                "--secret".to_owned(),
                "do-not-print".to_owned(),
            ],
            worker_host: "worker-01",
            worker_id: Some("rch-01"),
            fuse_capability: FuseCapabilityResult::Available,
            scenarios: vec![
                scenario_input("runner_pass_smoke_case", 0, None),
                scenario_input("runner_fail_smoke_case", 2, None),
                scenario_input(
                    "runner_skip_fuse_case",
                    0,
                    Some(SkipReason::FusePermissionDenied),
                ),
                timeout,
            ],
            duration_secs: 2.0,
        });

        let errors = validate_operational_gate_contract(&manifest);
        assert!(errors.is_empty(), "validation errors: {errors:?}");
        assert_eq!(manifest.verdict, GateVerdict::Fail);
        assert_eq!(
            manifest
                .operational_context
                .as_ref()
                .ok_or_else(|| "missing operational context".to_owned())?
                .command_line,
            vec!["scripts/e2e/runner.sh", "--secret", "[REDACTED]"]
        );
        assert_eq!(manifest.readiness_events.len(), 4);
        assert!(
            manifest
                .readiness_events
                .iter()
                .all(|event| !event.reproduction_command.contains("[REDACTED]"))
        );

        let pass = operational_scenario(&manifest, "runner_pass_smoke_case")?;
        assert_eq!(pass.classification, OperationalOutcomeClass::Pass);

        let fail = operational_scenario(&manifest, "runner_fail_smoke_case")?;
        assert_eq!(fail.classification, OperationalOutcomeClass::Fail);
        assert_eq!(
            fail.error_class,
            Some(OperationalErrorClass::ProductFailure)
        );

        let skip = operational_scenario(&manifest, "runner_skip_fuse_case")?;
        assert_eq!(skip.classification, OperationalOutcomeClass::Skip);
        assert_eq!(skip.skip_reason, Some(SkipReason::FusePermissionDenied));

        let error = operational_scenario(&manifest, "runner_timeout_error_case")?;
        assert_eq!(error.classification, OperationalOutcomeClass::Error);
        assert_eq!(
            error.error_class,
            Some(OperationalErrorClass::ResourceLimit)
        );
        assert_eq!(error.cleanup_status, CleanupStatus::PreservedArtifacts);
        assert!(
            error
                .artifact_refs
                .iter()
                .any(|path| path.ends_with("repro.json"))
        );
        Ok(())
    }

    #[test]
    fn operational_manifest_preserves_partial_artifact_refs_on_failure() -> Result<(), String> {
        let mut failed = scenario_input("runner_partial_artifacts_fail", 1, None);
        failed.cleanup_status = CleanupStatus::PreservedArtifacts;
        failed.extra_artifacts.push(OperationalArtifactInput {
            path: "artifacts/e2e/run-002/scenarios/runner_partial_artifacts_fail/stdout.tail"
                .to_owned(),
            category: ArtifactCategory::RawLog,
            content_type: Some("text/plain".to_owned()),
            size_bytes: 64,
            sha256: Some("sha256-tail".to_owned()),
        });

        let manifest = build_operational_manifest(OperationalManifestParams {
            gate_id: "runner_partial_artifacts",
            run_id: "run-002",
            created_at: "2026-05-01T12:00:00Z",
            bead_id: Some("bd-rchk0.4.2"),
            git_commit: "abc123",
            git_branch: "main",
            git_clean: true,
            environment: sample_environment(),
            command_line: vec!["scripts/e2e/runner.sh".to_owned()],
            worker_host: "worker-01",
            worker_id: None,
            fuse_capability: FuseCapabilityResult::NotApplicable,
            scenarios: vec![failed],
            duration_secs: 0.5,
        });

        let errors = validate_operational_gate_contract(&manifest);
        assert!(errors.is_empty(), "validation errors: {errors:?}");
        assert_eq!(manifest.readiness_events.len(), 1);
        assert_eq!(
            readiness_event(&manifest, 0)?.scenario_id.as_deref(),
            Some("runner_partial_artifacts_fail")
        );
        let scenario = manifest
            .operational_scenarios
            .get("runner_partial_artifacts_fail")
            .ok_or_else(|| "missing runner_partial_artifacts_fail scenario".to_owned())?;
        assert_eq!(scenario.cleanup_status, CleanupStatus::PreservedArtifacts);
        assert!(
            scenario
                .artifact_refs
                .iter()
                .any(|path| path.ends_with("stdout.tail"))
        );
        assert!(
            manifest
                .artifacts
                .iter()
                .any(|artifact| artifact.path.ends_with("stdout.tail")
                    && artifact.sha256.as_deref() == Some("sha256-tail"))
        );
        Ok(())
    }

    // ── check_script_conformance ─────────────────────────────────────

    #[test]
    fn conformant_script_has_no_violations() {
        let script = r#"#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
source "$REPO_ROOT/scripts/e2e/lib.sh"
e2e_init "my_test"
PASS_COUNT=0
FAIL_COUNT=0
scenario_result "test_happy_case" "PASS" "ok"
SCENARIO_RESULT|scenario_id=test_happy_case|outcome=PASS
if [[ $FAIL_COUNT -gt 0 ]]; then exit 1; fi
"#;
        let violations = check_script_conformance(script);
        assert!(violations.is_empty(), "violations: {violations:?}");
    }

    #[test]
    fn script_missing_lib_source_detected() {
        let script = r#"#!/usr/bin/env bash
set -euo pipefail
e2e_init "test"
FAIL_COUNT=0
SCENARIO_RESULT|scenario_id=test_case|outcome=PASS
"#;
        let violations = check_script_conformance(script);
        assert!(violations.contains(&ConformanceViolation::MissingLibSource));
    }

    #[test]
    fn script_missing_strict_mode_detected() {
        let script = r#"#!/usr/bin/env bash
source "$REPO_ROOT/scripts/e2e/lib.sh"
e2e_init "test"
FAIL_COUNT=0
SCENARIO_RESULT|scenario_id=test_case|outcome=PASS
"#;
        let violations = check_script_conformance(script);
        assert!(violations.contains(&ConformanceViolation::MissingStrictMode));
    }

    #[test]
    fn script_using_legacy_status_field_detected() {
        let script = r#"#!/usr/bin/env bash
set -euo pipefail
source "$REPO_ROOT/scripts/e2e/lib.sh"
e2e_init "test"
FAIL_COUNT=0
SCENARIO_RESULT|scenario_id=test_case|status=PASS
"#;
        let violations = check_script_conformance(script);
        assert!(violations.contains(&ConformanceViolation::LegacyStatusField));
    }

    #[test]
    fn script_mixing_outcome_and_legacy_status_field_detected() {
        let script = r#"#!/usr/bin/env bash
set -euo pipefail
source "$REPO_ROOT/scripts/e2e/lib.sh"
e2e_init "test"
FAIL_COUNT=0
SCENARIO_RESULT|scenario_id=test_good_case|outcome=PASS
SCENARIO_RESULT|scenario_id=test_legacy_case|status=PASS
"#;
        let violations = check_script_conformance(script);
        assert!(violations.contains(&ConformanceViolation::LegacyStatusField));
    }

    // ── aggregate_verdict ────────────────────────────────────────────

    #[test]
    fn aggregate_verdict_empty_is_skip() {
        assert_eq!(aggregate_verdict(&[]), GateVerdict::Skip);
    }

    #[test]
    fn aggregate_verdict_all_pass() {
        let results = vec![
            ScriptRunResult {
                script: "a.sh".to_owned(),
                exit_code: 0,
                attempts: 1,
                scenarios: vec![],
                passed: true,
            },
            ScriptRunResult {
                script: "b.sh".to_owned(),
                exit_code: 0,
                attempts: 1,
                scenarios: vec![],
                passed: true,
            },
        ];
        assert_eq!(aggregate_verdict(&results), GateVerdict::Pass);
    }

    #[test]
    fn aggregate_verdict_one_fail() {
        let results = vec![
            ScriptRunResult {
                script: "a.sh".to_owned(),
                exit_code: 0,
                attempts: 1,
                scenarios: vec![],
                passed: true,
            },
            ScriptRunResult {
                script: "b.sh".to_owned(),
                exit_code: 1,
                attempts: 2,
                scenarios: vec![],
                passed: false,
            },
        ];
        assert_eq!(aggregate_verdict(&results), GateVerdict::Fail);
    }

    // ── merge_scenarios ──────────────────────────────────────────────

    #[test]
    fn merge_scenarios_combines_all_results() -> Result<(), String> {
        let results = vec![
            ScriptRunResult {
                script: "a.sh".to_owned(),
                exit_code: 0,
                attempts: 1,
                scenarios: vec![ParsedScenario {
                    scenario_id: "test_from_first".to_owned(),
                    outcome: ScenarioResult::Pass,
                    detail: None,
                    line_number: 1,
                }],
                passed: true,
            },
            ScriptRunResult {
                script: "b.sh".to_owned(),
                exit_code: 0,
                attempts: 1,
                scenarios: vec![ParsedScenario {
                    scenario_id: "test_from_second".to_owned(),
                    outcome: ScenarioResult::Fail,
                    detail: Some("oops".to_owned()),
                    line_number: 5,
                }],
                passed: false,
            },
        ];
        let merged = merge_scenarios(&results);
        assert_eq!(merged.len(), 2);
        assert_eq!(scenario_outcome(&merged, 0)?.scenario_id, "test_from_first");
        assert_eq!(
            scenario_outcome(&merged, 1)?.scenario_id,
            "test_from_second"
        );
        Ok(())
    }

    // ── RunnerConfig ─────────────────────────────────────────────────

    #[test]
    fn local_config_no_retries() {
        let config = RunnerConfig::local("ffs_smoke");
        assert_eq!(config.max_retries, 0);
        assert!(!config.ci_mode);
    }

    #[test]
    fn ci_config_has_retries() {
        let config = RunnerConfig::ci("ffs_smoke");
        assert_eq!(config.max_retries, DEFAULT_CI_MAX_RETRIES);
        assert!(config.ci_mode);
    }

    // ── Negative / invariant tests ───────────────────────────────────

    #[test]
    fn parse_e2e_output_ignores_unknown_outcome_values() {
        let output = "SCENARIO_RESULT|scenario_id=test_weird_outcome|outcome=MAYBE\n";
        let scenarios = parse_e2e_output(output);
        assert!(scenarios.is_empty(), "unknown outcome should be skipped");
    }

    #[test]
    fn conformance_missing_everything_reports_all_violations() {
        let script = "#!/usr/bin/env bash\necho hello\n";
        let violations = check_script_conformance(script);
        assert!(
            violations.len() >= 4,
            "expected multiple violations: {violations:?}"
        );
    }

    // ── Cross-validation: scenario ID regex ──────────────────────────

    #[test]
    fn parsed_scenario_ids_validated_against_regex() {
        let output = "\
SCENARIO_RESULT|scenario_id=cli_mount_help_contract|outcome=PASS
SCENARIO_RESULT|scenario_id=btrfs_rw_smoke_test|outcome=FAIL
";
        let scenarios = parse_e2e_output(output);
        let invalid = validate_scenario_ids(&scenarios);
        assert!(invalid.is_empty(), "all IDs should be valid: {invalid:?}");
    }

    #[test]
    fn invalid_scenario_id_detected_by_validator() {
        let scenarios = vec![
            ParsedScenario {
                scenario_id: "UPPER_CASE_bad".to_owned(),
                outcome: ScenarioResult::Pass,
                detail: None,
                line_number: 1,
            },
            ParsedScenario {
                scenario_id: "only_two".to_owned(),
                outcome: ScenarioResult::Pass,
                detail: None,
                line_number: 2,
            },
        ];
        let invalid = validate_scenario_ids(&scenarios);
        assert_eq!(invalid.len(), 2);
    }

    // ── Full gate contract validation ────────────────────────────────

    #[test]
    fn gate_contract_valid_manifest_passes() {
        let scenarios = vec![ParsedScenario {
            scenario_id: "test_happy_path".to_owned(),
            outcome: ScenarioResult::Pass,
            detail: None,
            line_number: 1,
        }];
        let manifest = build_manifest_from_parsed(&ManifestParams {
            gate_id: "ffs_smoke",
            run_id: "run-gate-001",
            created_at: "2026-03-12T00:00:00Z",
            git_commit: "abc123",
            git_branch: "main",
            git_clean: true,
            scenarios: &scenarios,
            log_path: None,
            duration_secs: 1.0,
        });
        let errors = validate_gate_contract(&manifest);
        assert!(errors.is_empty(), "contract errors: {errors:?}");
    }

    #[test]
    fn gate_contract_catches_invalid_scenario_id() {
        let scenarios = vec![ParsedScenario {
            scenario_id: "BAD".to_owned(),
            outcome: ScenarioResult::Pass,
            detail: None,
            line_number: 1,
        }];
        let manifest = build_manifest_from_parsed(&ManifestParams {
            gate_id: "ffs_smoke",
            run_id: "run-gate-002",
            created_at: "2026-03-12T00:00:00Z",
            git_commit: "abc123",
            git_branch: "main",
            git_clean: true,
            scenarios: &scenarios,
            log_path: None,
            duration_secs: 1.0,
        });
        let errors = validate_gate_contract(&manifest);
        assert!(!errors.is_empty(), "should catch invalid scenario_id");
    }

    // ── Structured logging fields ────────────────────────────────────

    #[test]
    fn manifest_builder_emits_structured_log_fields() {
        // This is a compile-time assertion: the info!() call in
        // build_manifest_from_parsed includes operation_id, scenario_id,
        // and outcome — verified by the source grep in the E2E script.
        // Here we just verify the function runs without panic.
        let scenarios = vec![ParsedScenario {
            scenario_id: "test_logging_check".to_owned(),
            outcome: ScenarioResult::Pass,
            detail: None,
            line_number: 1,
        }];
        let _manifest = build_manifest_from_parsed(&ManifestParams {
            gate_id: "log_check",
            run_id: "run-log-001",
            created_at: "2026-03-12T00:00:00Z",
            git_commit: "abc123",
            git_branch: "main",
            git_clean: true,
            scenarios: &scenarios,
            log_path: None,
            duration_secs: 0.5,
        });
        // If we got here without panic, structured logging compiled fine.
    }
}
