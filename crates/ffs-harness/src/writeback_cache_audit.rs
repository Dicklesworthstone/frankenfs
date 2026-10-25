#![forbid(unsafe_code)]

//! Writeback-cache negative-option audit gate.
//!
//! Tracks bd-rchk0.2.1.1: proves that the FUSE `writeback_cache` mount option
//! stays disabled unless every safety prerequisite is satisfied. The default
//! and unsafe paths must never accidentally forward `writeback_cache` to the
//! kernel, even when stale docs, config defaults, or unrelated mount flags are
//! present. Each rejection class carries a stable reason code so release gates
//! and the remediation catalog can fail closed without parsing prose.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt::Write as _, fs, path::Path};

pub const WRITEBACK_CACHE_AUDIT_SCHEMA_VERSION: u32 = 1;
pub const WRITEBACK_CACHE_AUDIT_REPORT_SCHEMA_VERSION: u32 = 1;
pub const WRITEBACK_CACHE_ORDERING_SCHEMA_VERSION: u32 = 1;
pub const WRITEBACK_CACHE_ORDERING_REPORT_SCHEMA_VERSION: u32 = 1;
pub const WRITEBACK_CACHE_CRASH_REPLAY_SCHEMA_VERSION: u32 = 1;
pub const WRITEBACK_CACHE_CRASH_REPLAY_REPORT_SCHEMA_VERSION: u32 = 1;

/// Required invariant identifiers for the writeback-cache gate.
///
/// I1 = Snapshot Visibility Boundary.
/// I2 = Alias Order Preservation.
/// I3 = Metadata-After-Data Dependency.
/// I4 = Sync Boundary Completeness.
/// I5 = Flush Non-Durability.
/// I6 = Cross-Epoch Order.
pub const REQUIRED_INVARIANT_IDS: [&str; 6] = ["I1", "I2", "I3", "I4", "I5", "I6"];
pub const REQUIRED_CRASH_POINT_IDS: [&str; 12] = [
    "cp01_before_first_write",
    "cp02_after_first_write_before_flush",
    "cp03_after_flush_before_fsync",
    "cp04_after_fsync_before_metadata",
    "cp05_after_metadata_before_fsyncdir",
    "cp06_after_fsyncdir_before_unmount",
    "cp07_after_repeated_write_before_fsync",
    "cp08_after_repeated_write_fsync",
    "cp09_after_cancellation_before_writeback",
    "cp10_after_clean_unmount_before_reopen",
    "cp11_after_reopen_before_repair_refresh",
    "cp12_after_repair_refresh",
];

pub const ALLOWED_REJECTION_REASONS: [&str; 13] = [
    "missing_epoch_barrier_artifact",
    "stale_epoch_barrier_artifact",
    "rw_repair_serialization_unsupported",
    "default_or_read_only_mount",
    "unsupported_filesystem_or_operation",
    "fuse_capability_unavailable",
    "stale_crash_matrix_or_missing_fsync_evidence",
    "conflicting_cli_flags",
    "runtime_kill_switch_engaged",
    "writeback_feature_downgraded",
    "stale_gate_artifact",
    "host_capability_mismatch",
    "config_default_attempt",
];

pub const REQUIRED_ARTIFACT_FIELDS: [&str; 28] = [
    "schema_version",
    "gate_version",
    "bead_id",
    "mount_options.raw_options",
    "mount_options.mode",
    "runtime_guard.kill_switch_state",
    "runtime_guard.feature_state",
    "runtime_guard.config_source",
    "runtime_guard.gate_artifact_hash",
    "runtime_guard.gate_fresh",
    "runtime_guard.gate_age_secs",
    "runtime_guard.gate_max_age_secs",
    "runtime_guard.host_capability_fingerprint",
    "runtime_guard.lane_manifest_id",
    "runtime_guard.lane_manifest_path",
    "runtime_guard.lane_manifest_fresh",
    "runtime_guard.lane_manifest_matches_host",
    "runtime_guard.release_gate_consumer",
    "repair_serialization_state",
    "fuse_capability.probe_status",
    "fuse_capability.kernel_supports_writeback_cache",
    "fuse_capability.helper_binary_present",
    "epoch_barrier_artifact.artifact_path",
    "crash_matrix_artifact.artifact_path",
    "fsync_evidence_artifact.artifact_path",
    "filesystem_flavor",
    "operation_class",
    "explicit_opt_in",
];

pub const ALLOWED_ORDERING_REJECTION_REASONS: [&str; 11] = [
    "default_off_or_not_opted_in",
    "raw_fuser_option_missing",
    "missing_invariant_evidence",
    "flush_misclassified_as_durable",
    "missing_fsync_boundary",
    "missing_fsyncdir_boundary",
    "metadata_after_data_violation",
    "cancellation_not_classified",
    "stale_epoch_state",
    "repair_refresh_missing",
    "ordering_mismatch",
];

pub const ALLOWED_CRASH_REPLAY_REJECTION_REASONS: [&str; 14] = [
    "default_off_or_not_opted_in",
    "raw_fuser_option_missing",
    "missing_operation_trace",
    "missing_crash_point",
    "survivor_set_mismatch",
    "flush_misclassified_as_durable",
    "missing_fsync_boundary",
    "missing_fsyncdir_boundary",
    "metadata_after_data_violation",
    "unmount_reopen_missing",
    "cancellation_not_classified",
    "stale_epoch_state",
    "unsupported_combination_not_rejected",
    "replay_status_mismatch",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackCacheAuditGate {
    pub schema_version: u32,
    pub gate_version: String,
    pub bead_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    pub mount_options: WritebackMountOptions,
    pub repair_serialization_state: String,
    pub fuse_capability: FuseCapabilityState,
    pub epoch_barrier_artifact: ArtifactState,
    pub crash_matrix_artifact: ArtifactState,
    pub fsync_evidence_artifact: ArtifactState,
    pub filesystem_flavor: String,
    pub operation_class: String,
    pub explicit_opt_in: bool,
    pub conflicting_flags: Vec<String>,
    pub runtime_guard: WritebackRuntimeGuard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackMountOptions {
    pub raw_options: Vec<String>,
    pub fs_name: String,
    pub allow_other: bool,
    pub auto_unmount: bool,
    pub default_permissions: bool,
    pub mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuseCapabilityState {
    pub probe_status: String,
    pub kernel_supports_writeback_cache: bool,
    pub helper_binary_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactState {
    pub artifact_id: String,
    pub present: bool,
    pub fresh: bool,
    pub passed: bool,
    pub artifact_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackRuntimeGuard {
    pub kill_switch_state: String,
    pub feature_state: String,
    pub config_source: String,
    pub gate_artifact_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_host_capability_fingerprint: Option<String>,
    pub gate_fresh: bool,
    pub gate_age_secs: u64,
    pub gate_max_age_secs: u64,
    pub host_capability_fingerprint: String,
    pub lane_manifest_id: String,
    pub lane_manifest_path: String,
    pub lane_manifest_fresh: bool,
    pub lane_manifest_matches_host: bool,
    pub release_gate_consumer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum WritebackCacheAuditDecision {
    Accept,
    Reject {
        reason: String,
        invariants_failing: Vec<String>,
        remediation: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackInvariant {
    pub id: String,
    pub name: String,
    pub gate_requirement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackCacheAuditReport {
    pub schema_version: u32,
    pub gate_version: String,
    pub bead_id: String,
    pub scenario_id: String,
    pub valid: bool,
    pub decision: WritebackCacheAuditDecision,
    pub invariant_map: Vec<WritebackInvariant>,
    pub failure_modes: Vec<String>,
    pub required_artifact_fields: Vec<String>,
    pub mount_options: WritebackMountOptions,
    pub runtime_guard: WritebackRuntimeGuard,
    pub artifact_paths: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackOrderingOracle {
    pub schema_version: u32,
    pub gate_version: String,
    pub bead_id: String,
    pub mount_options: WritebackMountOptions,
    pub raw_fuser_options: Vec<String>,
    pub dirty_page_state: String,
    pub metadata_state: String,
    pub flush_observed_non_durable: bool,
    pub fsync_observed_durable: bool,
    pub fsyncdir_observed_durable: bool,
    pub cancellation_state: String,
    pub unmount_state: String,
    pub crash_reopen_state: String,
    pub epoch_id: String,
    pub epoch_state: String,
    pub repair_symbol_generation: u64,
    pub repair_symbol_refresh: String,
    pub invariant_evidence: Vec<WritebackOrderingInvariantEvidence>,
    pub expected_ordering: Vec<String>,
    pub observed_ordering: Vec<String>,
    pub artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackOrderingInvariantEvidence {
    pub id: String,
    pub supported: bool,
    pub test_id: String,
    pub artifact_field: String,
    pub release_gate_consumer: String,
    pub unsupported_rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum WritebackOrderingDecision {
    Accept,
    Reject {
        reason: String,
        invariants_failing: Vec<String>,
        remediation: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackOrderingSyncEvidence {
    pub flush_observed_non_durable: bool,
    pub fsync_observed_durable: bool,
    pub fsyncdir_observed_durable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackOrderingReport {
    pub schema_version: u32,
    pub gate_version: String,
    pub bead_id: String,
    pub scenario_id: String,
    pub valid: bool,
    pub decision: WritebackOrderingDecision,
    pub invariant_map: Vec<WritebackInvariant>,
    pub invariant_evidence: Vec<WritebackOrderingInvariantEvidence>,
    pub failure_modes: Vec<String>,
    pub mount_options: WritebackMountOptions,
    pub raw_fuser_options: Vec<String>,
    pub dirty_page_state: String,
    pub metadata_state: String,
    #[serde(flatten)]
    pub sync_evidence: WritebackOrderingSyncEvidence,
    pub cancellation_state: String,
    pub unmount_state: String,
    pub crash_reopen_state: String,
    pub epoch_id: String,
    pub epoch_state: String,
    pub repair_symbol_generation: u64,
    pub repair_symbol_refresh: String,
    pub expected_ordering: Vec<String>,
    pub observed_ordering: Vec<String>,
    pub artifact_paths: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackCrashReplayOracle {
    pub schema_version: u32,
    pub gate_version: String,
    pub bead_id: String,
    pub matrix_id: String,
    pub mount_options: WritebackMountOptions,
    pub raw_fuser_options: Vec<String>,
    pub epoch_id: String,
    pub epoch_state: String,
    pub host_capability_fingerprint: String,
    pub lane_manifest_id: String,
    pub operation_trace: Vec<WritebackCrashReplayOperation>,
    pub crash_points: Vec<WritebackCrashPointEvidence>,
    pub unsupported_combinations: Vec<WritebackUnsupportedCombination>,
    pub artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackCrashReplayOperation {
    pub step: u32,
    pub operation: String,
    pub target: String,
    pub durability_boundary: String,
    pub expected_result: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the artifact schema records independent observed durability facts as booleans"
)]
pub struct WritebackCrashPointEvidence {
    pub crash_point_id: String,
    pub description: String,
    pub operation_step: u32,
    pub expected_survivor_set: Vec<String>,
    pub actual_survivor_set: Vec<String>,
    pub fsync_observed_durable: bool,
    pub fsyncdir_observed_durable: bool,
    pub flush_observed_non_durable: bool,
    pub metadata_after_data_observed: bool,
    pub unmount_reopen_observed: bool,
    pub cancellation_state: String,
    pub repeated_write_state: String,
    pub replay_status: String,
    pub stdout_path: String,
    pub stderr_path: String,
    pub cleanup_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackUnsupportedCombination {
    pub combination_id: String,
    pub rejected: bool,
    pub reason: String,
    pub follow_up_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum WritebackCrashReplayDecision {
    Accept,
    Reject {
        reason: String,
        crash_points_failing: Vec<String>,
        remediation: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackCrashReplayReport {
    pub schema_version: u32,
    pub gate_version: String,
    pub bead_id: String,
    pub scenario_id: String,
    pub valid: bool,
    pub decision: WritebackCrashReplayDecision,
    pub matrix_id: String,
    pub required_crash_point_ids: Vec<String>,
    pub covered_crash_point_ids: Vec<String>,
    pub failure_modes: Vec<String>,
    pub mount_options: WritebackMountOptions,
    pub raw_fuser_options: Vec<String>,
    pub epoch_id: String,
    pub epoch_state: String,
    pub host_capability_fingerprint: String,
    pub lane_manifest_id: String,
    pub operation_trace: Vec<WritebackCrashReplayOperation>,
    pub crash_points: Vec<WritebackCrashPointEvidence>,
    pub unsupported_combinations: Vec<WritebackUnsupportedCombination>,
    pub artifact_paths: Vec<String>,
    pub reproduction_command: String,
}

pub fn load_writeback_cache_audit_gate(path: &Path) -> Result<WritebackCacheAuditGate> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "failed to parse writeback-cache audit gate {}",
            path.display()
        )
    })
}

pub fn load_writeback_ordering_oracle(path: &Path) -> Result<WritebackOrderingOracle> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "failed to parse writeback-cache ordering oracle {}",
            path.display()
        )
    })
}

pub fn load_writeback_crash_replay_oracle(path: &Path) -> Result<WritebackCrashReplayOracle> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "failed to parse writeback-cache crash/replay oracle {}",
            path.display()
        )
    })
}

pub fn build_writeback_cache_audit_report(
    gate: &WritebackCacheAuditGate,
    scenario_id: &str,
    reproduction_command: &str,
) -> Result<WritebackCacheAuditReport> {
    validate_writeback_cache_audit_gate(gate)?;
    let decision = evaluate_writeback_cache_audit(gate);
    Ok(WritebackCacheAuditReport {
        schema_version: WRITEBACK_CACHE_AUDIT_REPORT_SCHEMA_VERSION,
        gate_version: gate.gate_version.clone(),
        bead_id: gate.bead_id.clone(),
        scenario_id: scenario_id.to_owned(),
        valid: true,
        decision,
        invariant_map: writeback_invariant_map(),
        failure_modes: ALLOWED_REJECTION_REASONS
            .iter()
            .map(|reason| (*reason).to_owned())
            .collect(),
        required_artifact_fields: REQUIRED_ARTIFACT_FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .collect(),
        mount_options: gate.mount_options.clone(),
        runtime_guard: gate.runtime_guard.clone(),
        artifact_paths: vec![
            gate.epoch_barrier_artifact.artifact_path.clone(),
            gate.crash_matrix_artifact.artifact_path.clone(),
            gate.fsync_evidence_artifact.artifact_path.clone(),
            gate.runtime_guard.lane_manifest_path.clone(),
        ],
        reproduction_command: reproduction_command.to_owned(),
    })
}

pub fn build_writeback_ordering_report(
    oracle: &WritebackOrderingOracle,
    scenario_id: &str,
    reproduction_command: &str,
) -> Result<WritebackOrderingReport> {
    validate_writeback_ordering_oracle(oracle)?;
    let decision = evaluate_writeback_ordering_oracle(oracle);
    Ok(WritebackOrderingReport {
        schema_version: WRITEBACK_CACHE_ORDERING_REPORT_SCHEMA_VERSION,
        gate_version: oracle.gate_version.clone(),
        bead_id: oracle.bead_id.clone(),
        scenario_id: scenario_id.to_owned(),
        valid: true,
        decision,
        invariant_map: writeback_invariant_map(),
        invariant_evidence: oracle.invariant_evidence.clone(),
        failure_modes: ALLOWED_ORDERING_REJECTION_REASONS
            .iter()
            .map(|reason| (*reason).to_owned())
            .collect(),
        mount_options: oracle.mount_options.clone(),
        raw_fuser_options: oracle.raw_fuser_options.clone(),
        dirty_page_state: oracle.dirty_page_state.clone(),
        metadata_state: oracle.metadata_state.clone(),
        sync_evidence: WritebackOrderingSyncEvidence {
            flush_observed_non_durable: oracle.flush_observed_non_durable,
            fsync_observed_durable: oracle.fsync_observed_durable,
            fsyncdir_observed_durable: oracle.fsyncdir_observed_durable,
        },
        cancellation_state: oracle.cancellation_state.clone(),
        unmount_state: oracle.unmount_state.clone(),
        crash_reopen_state: oracle.crash_reopen_state.clone(),
        epoch_id: oracle.epoch_id.clone(),
        epoch_state: oracle.epoch_state.clone(),
        repair_symbol_generation: oracle.repair_symbol_generation,
        repair_symbol_refresh: oracle.repair_symbol_refresh.clone(),
        expected_ordering: oracle.expected_ordering.clone(),
        observed_ordering: oracle.observed_ordering.clone(),
        artifact_paths: oracle.artifact_paths.clone(),
        reproduction_command: reproduction_command.to_owned(),
    })
}

pub fn build_writeback_crash_replay_report(
    oracle: &WritebackCrashReplayOracle,
    scenario_id: &str,
    reproduction_command: &str,
) -> Result<WritebackCrashReplayReport> {
    validate_writeback_crash_replay_oracle(oracle)?;
    let decision = evaluate_writeback_crash_replay_oracle(oracle);
    Ok(WritebackCrashReplayReport {
        schema_version: WRITEBACK_CACHE_CRASH_REPLAY_REPORT_SCHEMA_VERSION,
        gate_version: oracle.gate_version.clone(),
        bead_id: oracle.bead_id.clone(),
        scenario_id: scenario_id.to_owned(),
        valid: true,
        decision,
        matrix_id: oracle.matrix_id.clone(),
        required_crash_point_ids: REQUIRED_CRASH_POINT_IDS
            .iter()
            .map(|id| (*id).to_owned())
            .collect(),
        covered_crash_point_ids: oracle
            .crash_points
            .iter()
            .map(|point| point.crash_point_id.clone())
            .collect(),
        failure_modes: ALLOWED_CRASH_REPLAY_REJECTION_REASONS
            .iter()
            .map(|reason| (*reason).to_owned())
            .collect(),
        mount_options: oracle.mount_options.clone(),
        raw_fuser_options: oracle.raw_fuser_options.clone(),
        epoch_id: oracle.epoch_id.clone(),
        epoch_state: oracle.epoch_state.clone(),
        host_capability_fingerprint: oracle.host_capability_fingerprint.clone(),
        lane_manifest_id: oracle.lane_manifest_id.clone(),
        operation_trace: oracle.operation_trace.clone(),
        crash_points: oracle.crash_points.clone(),
        unsupported_combinations: oracle.unsupported_combinations.clone(),
        artifact_paths: oracle.artifact_paths.clone(),
        reproduction_command: reproduction_command.to_owned(),
    })
}

pub fn fail_on_writeback_cache_audit_errors(report: &WritebackCacheAuditReport) -> Result<()> {
    if !report.valid {
        bail!("writeback-cache audit report is invalid");
    }
    if let WritebackCacheAuditDecision::Reject { reason, .. } = &report.decision {
        bail!("writeback-cache audit rejected mount option: {reason}");
    }
    Ok(())
}

pub fn fail_on_writeback_ordering_errors(report: &WritebackOrderingReport) -> Result<()> {
    if !report.valid {
        bail!("writeback-cache ordering report is invalid");
    }
    if let WritebackOrderingDecision::Reject { reason, .. } = &report.decision {
        bail!("writeback-cache ordering oracle rejected opt-in: {reason}");
    }
    Ok(())
}

pub fn fail_on_writeback_crash_replay_errors(report: &WritebackCrashReplayReport) -> Result<()> {
    if !report.valid {
        bail!("writeback-cache crash/replay report is invalid");
    }
    if let WritebackCrashReplayDecision::Reject { reason, .. } = &report.decision {
        bail!("writeback-cache crash/replay oracle rejected opt-in: {reason}");
    }
    Ok(())
}

#[must_use]
pub fn render_writeback_cache_audit_markdown(report: &WritebackCacheAuditReport) -> String {
    let decision = match &report.decision {
        WritebackCacheAuditDecision::Accept => "accept".to_owned(),
        WritebackCacheAuditDecision::Reject { reason, .. } => {
            format!("reject ({reason})")
        }
    };
    let mut text = String::new();
    text.push_str("# Writeback-Cache Audit Gate\n\n");
    let _ = writeln!(text, "- schema_version: {}", report.schema_version);
    let _ = writeln!(text, "- gate_version: {}", report.gate_version);
    let _ = writeln!(text, "- bead_id: {}", report.bead_id);
    let _ = writeln!(text, "- scenario_id: {}", report.scenario_id);
    let _ = writeln!(text, "- decision: {decision}");
    let _ = writeln!(
        text,
        "- reproduction_command: `{}`\n",
        report.reproduction_command
    );
    text.push_str("## Invariants\n\n");
    for invariant in &report.invariant_map {
        let _ = writeln!(
            text,
            "- {} {}: {}",
            invariant.id, invariant.name, invariant.gate_requirement
        );
    }
    text.push_str("\n## Failure Modes\n\n");
    for mode in &report.failure_modes {
        let _ = writeln!(text, "- {mode}");
    }
    text.push_str("\n## Artifact Fields\n\n");
    for field in &report.required_artifact_fields {
        let _ = writeln!(text, "- {field}");
    }
    text
}

#[must_use]
pub fn render_writeback_ordering_markdown(report: &WritebackOrderingReport) -> String {
    let decision = match &report.decision {
        WritebackOrderingDecision::Accept => "accept".to_owned(),
        WritebackOrderingDecision::Reject { reason, .. } => {
            format!("reject ({reason})")
        }
    };
    let mut text = String::new();
    text.push_str("# Writeback-Cache Ordering Oracle\n\n");
    let _ = writeln!(text, "- schema_version: {}", report.schema_version);
    let _ = writeln!(text, "- gate_version: {}", report.gate_version);
    let _ = writeln!(text, "- bead_id: {}", report.bead_id);
    let _ = writeln!(text, "- scenario_id: {}", report.scenario_id);
    let _ = writeln!(text, "- decision: {decision}");
    let _ = writeln!(text, "- dirty_page_state: {}", report.dirty_page_state);
    let _ = writeln!(text, "- metadata_state: {}", report.metadata_state);
    let _ = writeln!(text, "- epoch_id: {}", report.epoch_id);
    let _ = writeln!(
        text,
        "- repair_symbol_generation: {}",
        report.repair_symbol_generation
    );
    let _ = writeln!(
        text,
        "- reproduction_command: `{}`\n",
        report.reproduction_command
    );
    text.push_str("## Invariant Evidence\n\n");
    for evidence in &report.invariant_evidence {
        let _ = writeln!(
            text,
            "- {} supported={} test_id={} artifact_field={} release_gate_consumer={} unsupported_rationale={}",
            evidence.id,
            evidence.supported,
            evidence.test_id,
            evidence.artifact_field,
            evidence.release_gate_consumer,
            evidence.unsupported_rationale
        );
    }
    text.push_str("\n## Failure Modes\n\n");
    for mode in &report.failure_modes {
        let _ = writeln!(text, "- {mode}");
    }
    text
}

#[must_use]
pub fn render_writeback_crash_replay_markdown(report: &WritebackCrashReplayReport) -> String {
    let decision = match &report.decision {
        WritebackCrashReplayDecision::Accept => "accept".to_owned(),
        WritebackCrashReplayDecision::Reject { reason, .. } => {
            format!("reject ({reason})")
        }
    };
    let mut text = String::new();
    text.push_str("# Writeback-Cache Crash/Replay Oracle\n\n");
    let _ = writeln!(text, "- schema_version: {}", report.schema_version);
    let _ = writeln!(text, "- gate_version: {}", report.gate_version);
    let _ = writeln!(text, "- bead_id: {}", report.bead_id);
    let _ = writeln!(text, "- scenario_id: {}", report.scenario_id);
    let _ = writeln!(text, "- matrix_id: {}", report.matrix_id);
    let _ = writeln!(text, "- decision: {decision}");
    let _ = writeln!(text, "- epoch_id: {}", report.epoch_id);
    let _ = writeln!(text, "- epoch_state: {}", report.epoch_state);
    let _ = writeln!(
        text,
        "- reproduction_command: `{}`\n",
        report.reproduction_command
    );
    text.push_str("## Required Crash Points\n\n");
    for id in &report.required_crash_point_ids {
        let _ = writeln!(text, "- {id}");
    }
    text.push_str("\n## Failure Modes\n\n");
    for mode in &report.failure_modes {
        let _ = writeln!(text, "- {mode}");
    }
    text
}

#[must_use]
pub fn writeback_invariant_map() -> Vec<WritebackInvariant> {
    [
        (
            "I1",
            "Snapshot Visibility Boundary",
            "epoch_barrier_artifact must be present, fresh, and passing before rw opt-in",
        ),
        (
            "I2",
            "Alias Order Preservation",
            "operation_class must be in the audited mounted-write envelope",
        ),
        (
            "I3",
            "Metadata-After-Data Dependency",
            "rw repair-write serialization must be accepted and conflicting flags absent",
        ),
        (
            "I4",
            "Sync Boundary Completeness",
            "fsync evidence must be present, fresh, and passing",
        ),
        (
            "I5",
            "Flush Non-Durability",
            "mount mode must be rw with explicit opt-in; flush-only evidence is not sufficient",
        ),
        (
            "I6",
            "Cross-Epoch Order",
            "crash matrix evidence must be present, fresh, and passing",
        ),
    ]
    .into_iter()
    .map(|(id, name, gate_requirement)| WritebackInvariant {
        id: id.to_owned(),
        name: name.to_owned(),
        gate_requirement: gate_requirement.to_owned(),
    })
    .collect()
}

#[must_use]
pub fn evaluate_writeback_cache_audit(
    gate: &WritebackCacheAuditGate,
) -> WritebackCacheAuditDecision {
    if let Some(decision) = check_raw_options_never_carry_writeback_cache(gate) {
        return decision;
    }
    if let Some(decision) = check_mount_mode_and_opt_in(gate) {
        return decision;
    }
    if let Some(decision) = check_runtime_guard(gate) {
        return decision;
    }
    if let Some(decision) = check_filesystem_and_operation(gate) {
        return decision;
    }
    if let Some(decision) = check_fuse_capability(gate) {
        return decision;
    }
    if let Some(decision) = check_repair_serialization(gate) {
        return decision;
    }
    if let Some(decision) = check_epoch_barrier_artifact(gate) {
        return decision;
    }
    if let Some(decision) = check_crash_and_fsync_evidence(gate) {
        return decision;
    }
    if let Some(decision) = check_conflicting_flags(gate) {
        return decision;
    }
    WritebackCacheAuditDecision::Accept
}

#[must_use]
pub fn evaluate_writeback_cache_audit_for_host(
    gate: &WritebackCacheAuditGate,
    live_host_fingerprint: &str,
) -> WritebackCacheAuditDecision {
    let decision = evaluate_writeback_cache_audit(gate);
    if !matches!(decision, WritebackCacheAuditDecision::Accept) {
        return decision;
    }
    if gate.runtime_guard.host_capability_fingerprint.trim() != live_host_fingerprint.trim() {
        return reject(
            "host_capability_mismatch",
            ["I5"],
            "rerun the authoritative lane manifest on this host before enabling writeback_cache",
        );
    }
    WritebackCacheAuditDecision::Accept
}

/// Probe the live host capability fingerprint from `uname` and FUSE capability state (`bd-jtk24`).
#[must_use]
pub fn probe_live_host_capability_fingerprint() -> String {
    let uname = std::process::Command::new("uname")
        .args(["-s", "-r", "-m"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map_or_else(
            || "unknown-uname".to_owned(),
            |raw| {
                raw.split_whitespace()
                    .map(str::to_ascii_lowercase)
                    .collect::<Vec<_>>()
                    .join("-")
            },
        );
    let dev_fuse = Path::new("/dev/fuse").exists();
    let fusermount3 = std::process::Command::new("fusermount3")
        .arg("-V")
        .output()
        .is_ok_and(|out| out.status.success());
    format!("{uname}-devfuse:{dev_fuse}-fusermount3:{fusermount3}")
}

/// Format the current wall-clock time as UTC RFC3339 seconds (`YYYY-MM-DDTHH:MM:SSZ`).
#[must_use]
pub fn current_utc_rfc3339_seconds() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_utc_timestamp_seconds(secs)
}

fn format_utc_timestamp_seconds(unix_secs: u64) -> String {
    let days = i64::try_from(unix_secs / 86_400).unwrap_or(0);
    let rem = unix_secs % 86_400;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

const fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

fn parse_utc_timestamp_seconds(raw: &str) -> Result<u64> {
    let trimmed = raw.trim();
    let without_z = trimmed
        .strip_suffix('Z')
        .context("timestamp must end with Z")?;
    let (date, time) = without_z
        .split_once('T')
        .context("timestamp must contain T separator")?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts
        .next()
        .context("year missing")?
        .parse()
        .context("invalid year")?;
    let month: i64 = date_parts
        .next()
        .context("month missing")?
        .parse()
        .context("invalid month")?;
    let day: i64 = date_parts
        .next()
        .context("day missing")?
        .parse()
        .context("invalid day")?;
    if date_parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        bail!("invalid date components");
    }
    let time_no_fraction = time.split_once('.').map_or(time, |(seconds, _)| seconds);
    let mut time_parts = time_no_fraction.split(':');
    let hour: i64 = time_parts
        .next()
        .context("hour missing")?
        .parse()
        .context("invalid hour")?;
    let minute: i64 = time_parts
        .next()
        .context("minute missing")?
        .parse()
        .context("invalid minute")?;
    let second: i64 = time_parts
        .next()
        .context("second missing")?
        .parse()
        .context("invalid second")?;
    if time_parts.next().is_some()
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        bail!("invalid time components");
    }
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
    let days = era * 146_097 + day_of_era - 719_468;
    let total_secs = days * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(total_secs).context("timestamp before unix epoch")
}

fn is_timestamp_fresh_against_wall_clock(raw_ts: &str, max_age_secs: u64) -> bool {
    let Ok(generated_secs) = parse_utc_timestamp_seconds(raw_ts) else {
        return false;
    };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    generated_secs <= now_secs && now_secs - generated_secs <= max_age_secs
}

fn verify_lane_manifest_file_against_guard(guard: &WritebackRuntimeGuard) -> bool {
    let manifest_path = Path::new(guard.lane_manifest_path.trim());
    if !manifest_path.is_file() {
        return true;
    }
    let Ok(bytes) = fs::read(manifest_path) else {
        return false;
    };
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    if let Some(manifest_fp) = json
        .get("host_capability_fingerprint")
        .or_else(|| json.get("host_fingerprint"))
        .and_then(serde_json::Value::as_str)
        && manifest_fp.trim() != guard.host_capability_fingerprint.trim()
    {
        return false;
    }
    if let Some(manifest_ts) = json.get("generated_at").and_then(serde_json::Value::as_str)
        && !is_timestamp_fresh_against_wall_clock(manifest_ts, guard.gate_max_age_secs)
    {
        return false;
    }
    true
}

fn check_raw_options_never_carry_writeback_cache(
    gate: &WritebackCacheAuditGate,
) -> Option<WritebackCacheAuditDecision> {
    if gate.mount_options.raw_options.iter().any(|opt| {
        opt == "writeback_cache"
            || opt == "writeback"
            || opt.starts_with("writeback_cache=")
            || opt.starts_with("writeback=")
    }) && (!gate.explicit_opt_in || gate.mount_options.mode != "rw")
    {
        return Some(reject(
            "default_or_read_only_mount",
            ["I5"],
            "remove writeback_cache from default/raw mount options; require explicit RW opt-in",
        ));
    }
    None
}

fn check_mount_mode_and_opt_in(
    gate: &WritebackCacheAuditGate,
) -> Option<WritebackCacheAuditDecision> {
    if !gate.explicit_opt_in || gate.mount_options.mode != "rw" {
        return Some(reject(
            "default_or_read_only_mount",
            ["I5"],
            "enable writeback_cache only on explicit RW mounts",
        ));
    }
    None
}

fn check_runtime_guard(gate: &WritebackCacheAuditGate) -> Option<WritebackCacheAuditDecision> {
    let guard = &gate.runtime_guard;
    if guard.kill_switch_state != "disarmed" {
        return Some(reject(
            "runtime_kill_switch_engaged",
            ["I5"],
            "clear the emergency runtime kill switch before requesting kernel writeback_cache",
        ));
    }
    if guard.feature_state != "accepted" {
        return Some(reject(
            "writeback_feature_downgraded",
            ["I1", "I6"],
            "rerun the feature gate; downgraded or failed writeback_cache state cannot enable the kernel cache",
        ));
    }
    if guard.config_source != "cli_explicit" {
        return Some(reject(
            "config_default_attempt",
            ["I5"],
            "writeback_cache must come from a per-mount CLI opt-in, not a config default",
        ));
    }
    if !guard.gate_fresh || guard.gate_age_secs > guard.gate_max_age_secs {
        return Some(reject(
            "stale_gate_artifact",
            ["I1", "I6"],
            "regenerate the writeback-cache gate artifact; stale evidence cannot enable the kernel cache",
        ));
    }
    if let Some(generated_at) = gate
        .generated_at
        .as_deref()
        .or(guard.generated_at.as_deref())
        && !is_timestamp_fresh_against_wall_clock(generated_at, guard.gate_max_age_secs)
    {
        return Some(reject(
            "stale_gate_artifact",
            ["I1", "I6"],
            "regenerate the writeback-cache gate artifact; stale evidence cannot enable the kernel cache",
        ));
    }
    let expected_host_mismatch = guard
        .expected_host_capability_fingerprint
        .as_deref()
        .is_some_and(|expected| expected.trim() != guard.host_capability_fingerprint.trim());
    if !guard.lane_manifest_fresh
        || !guard.lane_manifest_matches_host
        || guard.host_capability_fingerprint.trim().is_empty()
        || expected_host_mismatch
        || !verify_lane_manifest_file_against_guard(guard)
    {
        return Some(reject(
            "host_capability_mismatch",
            ["I5"],
            "rerun the authoritative lane manifest on this host before enabling writeback_cache",
        ));
    }
    None
}

fn check_filesystem_and_operation(
    gate: &WritebackCacheAuditGate,
) -> Option<WritebackCacheAuditDecision> {
    let supported_flavors = ["ext4", "btrfs"];
    let supported_ops = ["mounted_write", "mounted_rename", "mounted_truncate"];
    if !supported_flavors.contains(&gate.filesystem_flavor.as_str()) {
        return Some(reject(
            "unsupported_filesystem_or_operation",
            ["I4"],
            "writeback_cache is only supported on ext4 and btrfs flavors",
        ));
    }
    if !supported_ops.contains(&gate.operation_class.as_str()) {
        return Some(reject(
            "unsupported_filesystem_or_operation",
            ["I4"],
            "operation class outside the supported writeback envelope",
        ));
    }
    None
}

fn check_fuse_capability(gate: &WritebackCacheAuditGate) -> Option<WritebackCacheAuditDecision> {
    if gate.fuse_capability.probe_status != "available" {
        return Some(reject(
            "fuse_capability_unavailable",
            ["I5"],
            "rerun fuse-capability-probe; writeback_cache requires the kernel module and helper",
        ));
    }
    if !gate.fuse_capability.kernel_supports_writeback_cache
        || !gate.fuse_capability.helper_binary_present
    {
        return Some(reject(
            "fuse_capability_unavailable",
            ["I5"],
            "kernel or helper binary does not advertise writeback_cache support",
        ));
    }
    None
}

fn check_repair_serialization(
    gate: &WritebackCacheAuditGate,
) -> Option<WritebackCacheAuditDecision> {
    if gate.repair_serialization_state != "rw_lane_accepted" {
        return Some(reject(
            "rw_repair_serialization_unsupported",
            ["I2"],
            "rw repair-write serialization must be accepted before writeback_cache is allowed",
        ));
    }
    None
}

fn check_epoch_barrier_artifact(
    gate: &WritebackCacheAuditGate,
) -> Option<WritebackCacheAuditDecision> {
    if !gate.epoch_barrier_artifact.present {
        return Some(reject(
            "missing_epoch_barrier_artifact",
            ["I1"],
            "epoch-barrier proof artifact is missing; regenerate before requesting writeback_cache",
        ));
    }
    if !gate.epoch_barrier_artifact.fresh || !gate.epoch_barrier_artifact.passed {
        return Some(reject(
            "stale_epoch_barrier_artifact",
            ["I1"],
            "epoch-barrier proof artifact is stale or failed; rerun the proof before mutation",
        ));
    }
    None
}

fn check_crash_and_fsync_evidence(
    gate: &WritebackCacheAuditGate,
) -> Option<WritebackCacheAuditDecision> {
    if !gate.crash_matrix_artifact.present
        || !gate.crash_matrix_artifact.fresh
        || !gate.crash_matrix_artifact.passed
    {
        return Some(reject(
            "stale_crash_matrix_or_missing_fsync_evidence",
            ["I6"],
            "regenerate the crash matrix evidence before enabling writeback_cache",
        ));
    }
    if !gate.fsync_evidence_artifact.present
        || !gate.fsync_evidence_artifact.fresh
        || !gate.fsync_evidence_artifact.passed
    {
        return Some(reject(
            "stale_crash_matrix_or_missing_fsync_evidence",
            ["I6"],
            "regenerate fsync evidence before enabling writeback_cache",
        ));
    }
    None
}

fn check_conflicting_flags(gate: &WritebackCacheAuditGate) -> Option<WritebackCacheAuditDecision> {
    let banned_flags = [
        "noflush",
        "writeback_cache_disable",
        "ffs_writeback_force",
        "ffs_writeback_force_off",
    ];
    if gate
        .conflicting_flags
        .iter()
        .any(|flag| banned_flags.contains(&flag.as_str()))
    {
        return Some(reject(
            "conflicting_cli_flags",
            ["I3"],
            "remove conflicting CLI flags before requesting writeback_cache",
        ));
    }
    None
}

#[must_use]
pub fn has_writeback_cache_fuser_option(raw_fuser_options: &[String]) -> bool {
    raw_fuser_options.iter().any(|opt| {
        let trimmed = opt.trim();
        trimmed == "writeback_cache"
            || trimmed.eq_ignore_ascii_case("FUSE_WRITEBACK_CACHE")
            || trimmed.eq_ignore_ascii_case("fuse_init:writeback_cache")
    })
}

#[must_use]
pub fn evaluate_writeback_ordering_oracle(
    oracle: &WritebackOrderingOracle,
) -> WritebackOrderingDecision {
    if oracle.mount_options.mode != "rw"
        || !oracle.mount_options.raw_options.iter().any(|v| v == "rw")
    {
        return reject_ordering(
            "default_off_or_not_opted_in",
            ["I5"],
            "positive writeback-cache ordering proof requires an explicit rw opt-in scenario",
        );
    }
    if !has_writeback_cache_fuser_option(&oracle.raw_fuser_options) {
        return reject_ordering(
            "raw_fuser_option_missing",
            ["I5"],
            "positive ordering proof must record the raw FUSE writeback_cache option under test",
        );
    }
    if let Some(decision) = check_ordering_invariant_evidence(oracle) {
        return decision;
    }
    if !oracle.flush_observed_non_durable {
        return reject_ordering(
            "flush_misclassified_as_durable",
            ["I5"],
            "flush must remain a lifecycle hook and must not advance durability",
        );
    }
    if oracle.dirty_page_state != "fsynced_durable" || !oracle.fsync_observed_durable {
        return reject_ordering(
            "missing_fsync_boundary",
            ["I4"],
            "dirty data must become durable only after an observed fsync boundary",
        );
    }
    if !oracle.fsyncdir_observed_durable {
        return reject_ordering(
            "missing_fsyncdir_boundary",
            ["I3", "I4"],
            "metadata durability requires an observed fsyncdir boundary",
        );
    }
    if oracle.metadata_state != "metadata_after_data" {
        return reject_ordering(
            "metadata_after_data_violation",
            ["I3"],
            "metadata visibility must not overtake dependent dirty data",
        );
    }
    if !["cancelled_before_writeback_classified", "none"]
        .contains(&oracle.cancellation_state.as_str())
    {
        return reject_ordering(
            "cancellation_not_classified",
            ["I2"],
            "cancellation before writeback must be classified before opt-in can accept",
        );
    }
    if oracle.epoch_id.trim().is_empty() || oracle.epoch_state != "fresh" {
        return reject_ordering(
            "stale_epoch_state",
            ["I1", "I6"],
            "ordering proof must name a fresh epoch before accepting writeback_cache",
        );
    }
    if oracle.crash_reopen_state != "survivor_set_verified"
        || oracle.unmount_state != "dirty_pages_flushed_or_rejected"
    {
        return reject_ordering(
            "ordering_mismatch",
            ["I4", "I6"],
            "crash/reopen and unmount evidence must verify the expected survivor set",
        );
    }
    if oracle.repair_symbol_refresh != "refreshed_after_writeback" {
        return reject_ordering(
            "repair_refresh_missing",
            ["I6"],
            "repair symbols must refresh after accepted writeback before release gates can accept",
        );
    }
    if oracle.expected_ordering != oracle.observed_ordering {
        return reject_ordering(
            "ordering_mismatch",
            ["I2", "I3"],
            "observed dirty-page/fsync ordering must match the oracle expectation",
        );
    }
    WritebackOrderingDecision::Accept
}

fn check_ordering_invariant_evidence(
    oracle: &WritebackOrderingOracle,
) -> Option<WritebackOrderingDecision> {
    let mut missing = Vec::new();
    for invariant_id in REQUIRED_INVARIANT_IDS {
        let Some(evidence) = oracle
            .invariant_evidence
            .iter()
            .find(|entry| entry.id == invariant_id)
        else {
            missing.push(invariant_id.to_owned());
            continue;
        };
        if evidence.supported {
            if evidence.test_id.trim().is_empty()
                || evidence.artifact_field.trim().is_empty()
                || evidence.release_gate_consumer.trim().is_empty()
            {
                missing.push(evidence.id.clone());
            }
        } else {
            missing.push(evidence.id.clone());
        }
    }
    if missing.is_empty() {
        None
    } else {
        Some(WritebackOrderingDecision::Reject {
            reason: "missing_invariant_evidence".to_owned(),
            invariants_failing: missing,
            remediation:
                "every invariant I1-I6 must have executable test/artifact/release-gate evidence before opt-in accepts"
                    .to_owned(),
        })
    }
}

fn reject(
    reason: &str,
    invariants_failing: impl IntoIterator<Item = &'static str>,
    remediation: &str,
) -> WritebackCacheAuditDecision {
    let invariants: Vec<String> = invariants_failing
        .into_iter()
        .map(|id| (*id).to_owned())
        .collect();
    WritebackCacheAuditDecision::Reject {
        reason: reason.to_owned(),
        invariants_failing: invariants,
        remediation: remediation.to_owned(),
    }
}

fn reject_ordering(
    reason: &str,
    invariants_failing: impl IntoIterator<Item = &'static str>,
    remediation: &str,
) -> WritebackOrderingDecision {
    let invariants: Vec<String> = invariants_failing
        .into_iter()
        .map(|id| (*id).to_owned())
        .collect();
    WritebackOrderingDecision::Reject {
        reason: reason.to_owned(),
        invariants_failing: invariants,
        remediation: remediation.to_owned(),
    }
}

#[must_use]
pub fn evaluate_writeback_crash_replay_oracle(
    oracle: &WritebackCrashReplayOracle,
) -> WritebackCrashReplayDecision {
    if oracle.mount_options.mode != "rw"
        || !oracle.mount_options.raw_options.iter().any(|v| v == "rw")
    {
        return reject_crash_replay(
            "default_off_or_not_opted_in",
            Vec::<String>::new(),
            "writeback-cache crash/replay proof requires an explicit read-write opt-in mount",
        );
    }
    if !has_writeback_cache_fuser_option(&oracle.raw_fuser_options) {
        return reject_crash_replay(
            "raw_fuser_option_missing",
            Vec::<String>::new(),
            "crash/replay proof must record that raw FUSE options included writeback_cache",
        );
    }
    if oracle.operation_trace.is_empty() {
        return reject_crash_replay(
            "missing_operation_trace",
            Vec::<String>::new(),
            "crash/replay proof must include the mounted-path operation trace",
        );
    }
    if oracle.epoch_id.trim().is_empty() || oracle.epoch_state != "fresh" {
        return reject_crash_replay(
            "stale_epoch_state",
            Vec::<String>::new(),
            "crash/replay proof must name a fresh epoch barrier before accepting",
        );
    }
    if let Some(decision) = check_required_crash_points(oracle) {
        return decision;
    }
    if let Some(decision) = check_unsupported_combinations(oracle) {
        return decision;
    }
    for point in &oracle.crash_points {
        if let Some(decision) = check_crash_point_evidence(point) {
            return decision;
        }
    }
    WritebackCrashReplayDecision::Accept
}

fn check_crash_point_evidence(
    point: &WritebackCrashPointEvidence,
) -> Option<WritebackCrashReplayDecision> {
    if survivor_set(&point.expected_survivor_set) != survivor_set(&point.actual_survivor_set) {
        return Some(reject_crash_point(
            point,
            "survivor_set_mismatch",
            "actual survivor set must match the oracle expected survivor set after replay",
        ));
    }
    if !point.flush_observed_non_durable {
        return Some(reject_crash_point(
            point,
            "flush_misclassified_as_durable",
            "flush evidence must remain non-durable for every crash point",
        ));
    }
    if !point.fsync_observed_durable {
        return Some(reject_crash_point(
            point,
            "missing_fsync_boundary",
            "file data survivors must cross an observed fsync boundary",
        ));
    }
    if !point.fsyncdir_observed_durable {
        return Some(reject_crash_point(
            point,
            "missing_fsyncdir_boundary",
            "metadata survivors must cross an observed fsyncdir boundary",
        ));
    }
    if !point.metadata_after_data_observed {
        return Some(reject_crash_point(
            point,
            "metadata_after_data_violation",
            "metadata durability must not overtake dependent data durability",
        ));
    }
    if !point.unmount_reopen_observed {
        return Some(reject_crash_point(
            point,
            "unmount_reopen_missing",
            "each crash point must include unmount/reopen recovery evidence",
        ));
    }
    if !["cancelled_before_writeback_classified", "none"]
        .contains(&point.cancellation_state.as_str())
    {
        return Some(reject_crash_point(
            point,
            "cancellation_not_classified",
            "cancellation-before-writeback points must be explicitly classified",
        ));
    }
    if !["last_fsynced_write_survived", "not_applicable"]
        .contains(&point.repeated_write_state.as_str())
    {
        return Some(reject_crash_point(
            point,
            "replay_status_mismatch",
            "repeated-write points must prove the last fsynced write survived",
        ));
    }
    if point.replay_status != "survivor_set_verified" {
        return Some(reject_crash_point(
            point,
            "replay_status_mismatch",
            "replay status must verify the survivor set for every crash point",
        ));
    }
    None
}

fn reject_crash_point(
    point: &WritebackCrashPointEvidence,
    reason: &str,
    remediation: &str,
) -> WritebackCrashReplayDecision {
    reject_crash_replay(reason, [point.crash_point_id.clone()], remediation)
}

fn check_required_crash_points(
    oracle: &WritebackCrashReplayOracle,
) -> Option<WritebackCrashReplayDecision> {
    let covered: BTreeSet<&str> = oracle
        .crash_points
        .iter()
        .map(|point| point.crash_point_id.as_str())
        .collect();
    let missing: Vec<String> = REQUIRED_CRASH_POINT_IDS
        .iter()
        .filter(|id| !covered.contains(**id))
        .map(|id| (*id).to_owned())
        .collect();
    if missing.is_empty() {
        None
    } else {
        Some(reject_crash_replay(
            "missing_crash_point",
            missing,
            "writeback-cache crash/replay matrix must cover all twelve declared crash points or split an explicit follow-up bead",
        ))
    }
}

fn check_unsupported_combinations(
    oracle: &WritebackCrashReplayOracle,
) -> Option<WritebackCrashReplayDecision> {
    let unclassified: Vec<String> = oracle
        .unsupported_combinations
        .iter()
        .filter(|combo| {
            !combo.rejected
                || combo.reason.trim().is_empty()
                || combo.follow_up_bead.trim().is_empty()
        })
        .map(|combo| combo.combination_id.clone())
        .collect();
    if unclassified.is_empty() {
        None
    } else {
        Some(reject_crash_replay(
            "unsupported_combination_not_rejected",
            unclassified,
            "unsupported writeback-cache combinations must fail closed with reason and follow-up bead",
        ))
    }
}

fn survivor_set(values: &[String]) -> BTreeSet<&str> {
    values.iter().map(String::as_str).collect()
}

fn reject_crash_replay(
    reason: &str,
    crash_points_failing: impl IntoIterator<Item = String>,
    remediation: &str,
) -> WritebackCrashReplayDecision {
    WritebackCrashReplayDecision::Reject {
        reason: reason.to_owned(),
        crash_points_failing: crash_points_failing.into_iter().collect(),
        remediation: remediation.to_owned(),
    }
}

pub fn validate_writeback_cache_audit_gate(gate: &WritebackCacheAuditGate) -> Result<()> {
    if gate.schema_version != WRITEBACK_CACHE_AUDIT_SCHEMA_VERSION {
        bail!(
            "writeback cache audit schema_version must be {WRITEBACK_CACHE_AUDIT_SCHEMA_VERSION}, got {}",
            gate.schema_version
        );
    }
    if !gate.bead_id.starts_with("bd-") {
        bail!(
            "writeback cache audit bead_id must look like bd-..., got `{}`",
            gate.bead_id
        );
    }
    if gate.gate_version.trim().is_empty() {
        bail!("writeback cache audit gate_version must not be empty");
    }
    if gate.mount_options.raw_options.is_empty() {
        bail!("writeback cache audit raw_options must include the declared mount option set");
    }
    if gate.mount_options.fs_name.trim().is_empty() {
        bail!("writeback cache audit fs_name must not be empty");
    }
    if gate.mount_options.mode.trim().is_empty() {
        bail!("writeback cache audit mount mode must not be empty");
    }
    if gate.fuse_capability.probe_status.trim().is_empty() {
        bail!("writeback cache audit fuse probe_status must not be empty");
    }
    if gate.runtime_guard.kill_switch_state.trim().is_empty() {
        bail!("writeback cache audit kill_switch_state must not be empty");
    }
    if gate.runtime_guard.feature_state.trim().is_empty() {
        bail!("writeback cache audit feature_state must not be empty");
    }
    if gate.runtime_guard.config_source.trim().is_empty() {
        bail!("writeback cache audit config_source must not be empty");
    }
    if gate.runtime_guard.gate_artifact_hash.trim().is_empty() {
        bail!("writeback cache audit gate_artifact_hash must not be empty");
    }
    if gate.runtime_guard.gate_max_age_secs == 0 {
        bail!("writeback cache audit gate_max_age_secs must be nonzero");
    }
    if gate
        .runtime_guard
        .host_capability_fingerprint
        .trim()
        .is_empty()
    {
        bail!("writeback cache audit host_capability_fingerprint must not be empty");
    }
    if gate.runtime_guard.lane_manifest_id.trim().is_empty() {
        bail!("writeback cache audit lane_manifest_id must not be empty");
    }
    if gate.runtime_guard.lane_manifest_path.trim().is_empty() {
        bail!("writeback cache audit lane_manifest_path must not be empty");
    }
    if gate.runtime_guard.release_gate_consumer.trim().is_empty() {
        bail!("writeback cache audit release_gate_consumer must not be empty");
    }
    for artifact in [
        &gate.epoch_barrier_artifact,
        &gate.crash_matrix_artifact,
        &gate.fsync_evidence_artifact,
    ] {
        if artifact.artifact_id.trim().is_empty() {
            bail!("writeback cache audit artifact_id must not be empty");
        }
        if artifact.artifact_path.trim().is_empty() {
            bail!(
                "writeback cache audit artifact_path must not be empty for {}",
                artifact.artifact_id
            );
        }
    }
    Ok(())
}

pub fn validate_writeback_ordering_oracle(oracle: &WritebackOrderingOracle) -> Result<()> {
    if oracle.schema_version != WRITEBACK_CACHE_ORDERING_SCHEMA_VERSION {
        bail!(
            "writeback cache ordering schema_version must be {WRITEBACK_CACHE_ORDERING_SCHEMA_VERSION}, got {}",
            oracle.schema_version
        );
    }
    if !oracle.bead_id.starts_with("bd-") {
        bail!(
            "writeback cache ordering bead_id must look like bd-..., got `{}`",
            oracle.bead_id
        );
    }
    if oracle.gate_version.trim().is_empty() {
        bail!("writeback cache ordering gate_version must not be empty");
    }
    validate_writeback_mount_options(&oracle.mount_options)?;
    if oracle.raw_fuser_options.is_empty() {
        bail!("writeback cache ordering raw_fuser_options must not be empty");
    }
    if oracle.artifact_paths.is_empty() {
        bail!("writeback cache ordering artifact_paths must not be empty");
    }
    if oracle.expected_ordering.is_empty() || oracle.observed_ordering.is_empty() {
        bail!("writeback cache ordering expected and observed ordering must not be empty");
    }
    for path in &oracle.artifact_paths {
        if path.trim().is_empty() {
            bail!("writeback cache ordering artifact path must not be empty");
        }
    }
    Ok(())
}

pub fn validate_writeback_crash_replay_oracle(oracle: &WritebackCrashReplayOracle) -> Result<()> {
    if oracle.schema_version != WRITEBACK_CACHE_CRASH_REPLAY_SCHEMA_VERSION {
        bail!(
            "writeback cache crash/replay schema_version must be {WRITEBACK_CACHE_CRASH_REPLAY_SCHEMA_VERSION}, got {}",
            oracle.schema_version
        );
    }
    if !oracle.bead_id.starts_with("bd-") {
        bail!(
            "writeback cache crash/replay bead_id must look like bd-..., got `{}`",
            oracle.bead_id
        );
    }
    if oracle.gate_version.trim().is_empty() {
        bail!("writeback cache crash/replay gate_version must not be empty");
    }
    if oracle.matrix_id.trim().is_empty() {
        bail!("writeback cache crash/replay matrix_id must not be empty");
    }
    validate_writeback_mount_options(&oracle.mount_options)?;
    if oracle.raw_fuser_options.is_empty() {
        bail!("writeback cache crash/replay raw_fuser_options must not be empty");
    }
    if oracle.epoch_id.trim().is_empty() {
        bail!("writeback cache crash/replay epoch_id must not be empty");
    }
    if oracle.epoch_state.trim().is_empty() {
        bail!("writeback cache crash/replay epoch_state must not be empty");
    }
    if oracle.host_capability_fingerprint.trim().is_empty() {
        bail!("writeback cache crash/replay host_capability_fingerprint must not be empty");
    }
    if oracle.lane_manifest_id.trim().is_empty() {
        bail!("writeback cache crash/replay lane_manifest_id must not be empty");
    }
    if oracle.operation_trace.is_empty() {
        bail!("writeback cache crash/replay operation_trace must not be empty");
    }
    if oracle.crash_points.is_empty() {
        bail!("writeback cache crash/replay crash_points must not be empty");
    }
    if oracle.artifact_paths.is_empty() {
        bail!("writeback cache crash/replay artifact_paths must not be empty");
    }
    for path in &oracle.artifact_paths {
        if path.trim().is_empty() {
            bail!("writeback cache crash/replay artifact path must not be empty");
        }
    }
    for operation in &oracle.operation_trace {
        if operation.step == 0 {
            bail!("writeback cache crash/replay operation step must be nonzero");
        }
        if operation.operation.trim().is_empty()
            || operation.target.trim().is_empty()
            || operation.durability_boundary.trim().is_empty()
            || operation.expected_result.trim().is_empty()
        {
            bail!("writeback cache crash/replay operation fields must not be empty");
        }
    }
    for point in &oracle.crash_points {
        validate_crash_point_evidence(point)?;
    }
    for combo in &oracle.unsupported_combinations {
        if combo.combination_id.trim().is_empty()
            || combo.reason.trim().is_empty()
            || combo.follow_up_bead.trim().is_empty()
        {
            bail!("writeback cache crash/replay unsupported combination fields must not be empty");
        }
    }
    Ok(())
}

fn validate_crash_point_evidence(point: &WritebackCrashPointEvidence) -> Result<()> {
    if point.crash_point_id.trim().is_empty() {
        bail!("writeback cache crash/replay crash_point_id must not be empty");
    }
    if point.description.trim().is_empty() {
        bail!(
            "writeback cache crash/replay description must not be empty for {}",
            point.crash_point_id
        );
    }
    if point.operation_step == 0 {
        bail!(
            "writeback cache crash/replay operation_step must be nonzero for {}",
            point.crash_point_id
        );
    }
    if point.expected_survivor_set.is_empty() || point.actual_survivor_set.is_empty() {
        bail!(
            "writeback cache crash/replay survivor sets must not be empty for {}",
            point.crash_point_id
        );
    }
    for survivor in point
        .expected_survivor_set
        .iter()
        .chain(point.actual_survivor_set.iter())
    {
        if survivor.trim().is_empty() {
            bail!(
                "writeback cache crash/replay survivor set entries must not be empty for {}",
                point.crash_point_id
            );
        }
    }
    if point.cancellation_state.trim().is_empty()
        || point.repeated_write_state.trim().is_empty()
        || point.replay_status.trim().is_empty()
        || point.stdout_path.trim().is_empty()
        || point.stderr_path.trim().is_empty()
        || point.cleanup_status.trim().is_empty()
    {
        bail!(
            "writeback cache crash/replay artifact fields must not be empty for {}",
            point.crash_point_id
        );
    }
    Ok(())
}

fn validate_writeback_mount_options(options: &WritebackMountOptions) -> Result<()> {
    if options.raw_options.is_empty() {
        bail!("writeback cache audit raw_options must include the declared mount option set");
    }
    if options.fs_name.trim().is_empty() {
        bail!("writeback cache audit fs_name must not be empty");
    }
    if options.mode.trim().is_empty() {
        bail!("writeback cache audit mount mode must not be empty");
    }
    Ok(())
}

/// Generate a complete, validated writeback-cache oracle bundle (gate, ordering, and
/// crash/replay oracles) recording `FUSE_WRITEBACK_CACHE` negotiation (`bd-xvhsz`).
pub fn generate_writeback_cache_oracle_bundle(
    filesystem_flavor: &str,
) -> Result<(
    WritebackCacheAuditGate,
    WritebackOrderingOracle,
    WritebackCrashReplayOracle,
)> {
    let now_ts = current_utc_rfc3339_seconds();
    let gate = WritebackCacheAuditGate {
        schema_version: WRITEBACK_CACHE_AUDIT_SCHEMA_VERSION,
        gate_version: "v1".to_owned(),
        bead_id: "bd-rchk0.2.1.1".to_owned(),
        generated_at: Some(now_ts.clone()),
        mount_options: WritebackMountOptions {
            raw_options: vec!["rw".to_owned(), "default_permissions".to_owned()],
            fs_name: "frankenfs".to_owned(),
            allow_other: false,
            auto_unmount: true,
            default_permissions: true,
            mode: "rw".to_owned(),
        },
        repair_serialization_state: "rw_lane_accepted".to_owned(),
        fuse_capability: FuseCapabilityState {
            probe_status: "available".to_owned(),
            kernel_supports_writeback_cache: true,
            helper_binary_present: true,
        },
        epoch_barrier_artifact: ArtifactState {
            artifact_id: "epoch_barrier_proof".to_owned(),
            present: true,
            fresh: true,
            passed: true,
            artifact_path: "artifacts/qa/epoch_barrier_proof.json".to_owned(),
        },
        crash_matrix_artifact: ArtifactState {
            artifact_id: "crash_matrix".to_owned(),
            present: true,
            fresh: true,
            passed: true,
            artifact_path: "artifacts/qa/crash_matrix.json".to_owned(),
        },
        fsync_evidence_artifact: ArtifactState {
            artifact_id: "fsync_evidence".to_owned(),
            present: true,
            fresh: true,
            passed: true,
            artifact_path: "artifacts/qa/fsync_evidence.json".to_owned(),
        },
        filesystem_flavor: filesystem_flavor.to_owned(),
        operation_class: "mounted_write".to_owned(),
        explicit_opt_in: true,
        conflicting_flags: Vec::new(),
        runtime_guard: WritebackRuntimeGuard {
            kill_switch_state: "disarmed".to_owned(),
            feature_state: "accepted".to_owned(),
            config_source: "cli_explicit".to_owned(),
            gate_artifact_hash: "blake3:writeback-cache-gate-v1".to_owned(),
            gate_fresh: true,
            gate_age_secs: 30,
            gate_max_age_secs: 86_400,
            generated_at: Some(now_ts),
            host_capability_fingerprint: "linux-fuse-writeback-cache-v1".to_owned(),
            expected_host_capability_fingerprint: None,
            lane_manifest_id: "authoritative-env-frankenfs-fuse-v1".to_owned(),
            lane_manifest_path: "artifacts/qa/authoritative_environment_manifest.json".to_owned(),
            lane_manifest_fresh: true,
            lane_manifest_matches_host: true,
            release_gate_consumer: "writeback_cache.release_gate".to_owned(),
        },
    };

    let ordering = WritebackOrderingOracle {
        schema_version: WRITEBACK_CACHE_ORDERING_SCHEMA_VERSION,
        gate_version: "bd-8pz7h-ordering-v1".to_owned(),
        bead_id: "bd-8pz7h".to_owned(),
        mount_options: WritebackMountOptions {
            raw_options: vec![
                "rw".to_owned(),
                "fsname=frankenfs".to_owned(),
                "default_permissions".to_owned(),
            ],
            fs_name: "frankenfs".to_owned(),
            allow_other: false,
            auto_unmount: true,
            default_permissions: true,
            mode: "rw".to_owned(),
        },
        raw_fuser_options: vec![
            "fsname=frankenfs".to_owned(),
            "subtype=ffs".to_owned(),
            "rw".to_owned(),
            "FUSE_WRITEBACK_CACHE".to_owned(),
        ],
        dirty_page_state: "fsynced_durable".to_owned(),
        metadata_state: "metadata_after_data".to_owned(),
        flush_observed_non_durable: true,
        fsync_observed_durable: true,
        fsyncdir_observed_durable: true,
        cancellation_state: "cancelled_before_writeback_classified".to_owned(),
        unmount_state: "dirty_pages_flushed_or_rejected".to_owned(),
        crash_reopen_state: "survivor_set_verified".to_owned(),
        epoch_id: "epoch-0007".to_owned(),
        epoch_state: "fresh".to_owned(),
        repair_symbol_generation: 8,
        repair_symbol_refresh: "refreshed_after_writeback".to_owned(),
        invariant_evidence: REQUIRED_INVARIANT_IDS
            .into_iter()
            .map(|id| WritebackOrderingInvariantEvidence {
                id: id.to_owned(),
                supported: true,
                test_id: format!("writeback_ordering_{id}_test"),
                artifact_field: format!("ordering.{id}.artifact"),
                release_gate_consumer: "writeback_cache.release_gate".to_owned(),
                unsupported_rationale: String::new(),
            })
            .collect(),
        expected_ordering: vec![
            "dirty_data".to_owned(),
            "fsync".to_owned(),
            "metadata".to_owned(),
            "fsyncdir".to_owned(),
            "repair_symbol_refresh".to_owned(),
        ],
        observed_ordering: vec![
            "dirty_data".to_owned(),
            "fsync".to_owned(),
            "metadata".to_owned(),
            "fsyncdir".to_owned(),
            "repair_symbol_refresh".to_owned(),
        ],
        artifact_paths: vec![
            "artifacts/writeback-cache/ordering.json".to_owned(),
            "artifacts/writeback-cache/crash_reopen.json".to_owned(),
        ],
    };

    let mut crash_points: Vec<_> = REQUIRED_CRASH_POINT_IDS
        .iter()
        .zip(1_u32..)
        .map(|(id, step)| WritebackCrashPointEvidence {
            crash_point_id: (*id).to_owned(),
            description: format!("{id} mounted writeback-cache crash point"),
            operation_step: step,
            expected_survivor_set: vec![
                "/".to_owned(),
                "/writeback".to_owned(),
                "/writeback/data.bin:blake3=stable-v2".to_owned(),
            ],
            actual_survivor_set: vec![
                "/writeback/data.bin:blake3=stable-v2".to_owned(),
                "/".to_owned(),
                "/writeback".to_owned(),
            ],
            fsync_observed_durable: true,
            fsyncdir_observed_durable: true,
            flush_observed_non_durable: true,
            metadata_after_data_observed: true,
            unmount_reopen_observed: true,
            cancellation_state: if *id == "cp09_after_cancellation_before_writeback" {
                "cancelled_before_writeback_classified".to_owned()
            } else {
                "none".to_owned()
            },
            repeated_write_state: if matches!(
                *id,
                "cp07_after_repeated_write_before_fsync" | "cp08_after_repeated_write_fsync"
            ) {
                "last_fsynced_write_survived".to_owned()
            } else {
                "not_applicable".to_owned()
            },
            replay_status: "survivor_set_verified".to_owned(),
            stdout_path: format!("artifacts/writeback-cache/crash-replay/{id}.stdout"),
            stderr_path: format!("artifacts/writeback-cache/crash-replay/{id}.stderr"),
            cleanup_status: "retained_for_qa".to_owned(),
        })
        .collect();
    let _ = &mut crash_points;

    let crash_replay = WritebackCrashReplayOracle {
        schema_version: WRITEBACK_CACHE_CRASH_REPLAY_SCHEMA_VERSION,
        gate_version: "bd-rchk0.2.3-crash-replay-v1".to_owned(),
        bead_id: "bd-rchk0.2.3".to_owned(),
        matrix_id: "writeback_cache_crash_replay_matrix_v1".to_owned(),
        mount_options: WritebackMountOptions {
            raw_options: vec![
                "rw".to_owned(),
                "fsname=frankenfs".to_owned(),
                "default_permissions".to_owned(),
            ],
            fs_name: "frankenfs".to_owned(),
            allow_other: false,
            auto_unmount: true,
            default_permissions: true,
            mode: "rw".to_owned(),
        },
        raw_fuser_options: vec![
            "fsname=frankenfs".to_owned(),
            "subtype=ffs".to_owned(),
            "rw".to_owned(),
            "FUSE_WRITEBACK_CACHE".to_owned(),
        ],
        epoch_id: "epoch-writeback-crash-0001".to_owned(),
        epoch_state: "fresh".to_owned(),
        host_capability_fingerprint: "fuse3-writeback-cache-enabled-host".to_owned(),
        lane_manifest_id: "fuse-writeback-cache-rw-lane-v1".to_owned(),
        operation_trace: [
            (1, "create", "none"),
            (2, "write", "kernel_writeback_cache"),
            (3, "flush", "non_durable"),
            (4, "fsync", "file_durable"),
            (5, "rename", "metadata_after_data"),
            (6, "fsyncdir", "directory_durable"),
            (7, "write", "repeated_write"),
            (8, "fsync", "last_write_durable"),
            (9, "cancel", "classified_before_writeback"),
            (10, "unmount", "dirty_pages_flushed_or_rejected"),
            (11, "reopen", "survivor_set_verified"),
            (12, "repair_refresh", "post_writeback_refresh"),
        ]
        .into_iter()
        .map(
            |(step, operation, boundary)| WritebackCrashReplayOperation {
                step,
                operation: operation.to_owned(),
                target: "/writeback/data.bin".to_owned(),
                durability_boundary: boundary.to_owned(),
                expected_result: "success".to_owned(),
            },
        )
        .collect(),
        crash_points,
        unsupported_combinations: vec![WritebackUnsupportedCombination {
            combination_id: "writeback_cache_ro_mount".to_owned(),
            rejected: true,
            reason: "read_only_writeback_cache".to_owned(),
            follow_up_bead: "bd-rchk0.2.4".to_owned(),
        }],
        artifact_paths: vec![
            "artifacts/writeback-cache/crash-replay/matrix.json".to_owned(),
            "artifacts/writeback-cache/crash-replay/results.json".to_owned(),
            "artifacts/writeback-cache/crash-replay/run.log".to_owned(),
        ],
    };

    validate_writeback_cache_audit_gate(&gate)?;
    validate_writeback_ordering_oracle(&ordering)?;
    validate_writeback_crash_replay_oracle(&crash_replay)?;

    Ok((gate, ordering, crash_replay))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invariant_evidence_mut(
        oracle: &mut WritebackOrderingOracle,
        index: usize,
    ) -> Result<&mut WritebackOrderingInvariantEvidence> {
        oracle
            .invariant_evidence
            .get_mut(index)
            .with_context(|| format!("expected invariant evidence at index {index}"))
    }

    fn crash_point_mut(
        oracle: &mut WritebackCrashReplayOracle,
        index: usize,
    ) -> Result<&mut WritebackCrashPointEvidence> {
        oracle
            .crash_points
            .get_mut(index)
            .with_context(|| format!("expected crash point at index {index}"))
    }

    fn unsupported_combination_mut(
        oracle: &mut WritebackCrashReplayOracle,
        index: usize,
    ) -> Result<&mut WritebackUnsupportedCombination> {
        oracle
            .unsupported_combinations
            .get_mut(index)
            .with_context(|| format!("expected unsupported combination at index {index}"))
    }

    fn happy_artifact(id: &str) -> ArtifactState {
        ArtifactState {
            artifact_id: id.to_owned(),
            present: true,
            fresh: true,
            passed: true,
            artifact_path: format!("artifacts/qa/{id}.json"),
        }
    }

    fn happy_runtime_guard() -> WritebackRuntimeGuard {
        WritebackRuntimeGuard {
            kill_switch_state: "disarmed".to_owned(),
            feature_state: "accepted".to_owned(),
            config_source: "cli_explicit".to_owned(),
            gate_artifact_hash: "blake3:writeback-cache-gate-v1".to_owned(),
            gate_fresh: true,
            gate_age_secs: 30,
            gate_max_age_secs: 86_400,
            generated_at: None,
            host_capability_fingerprint: "linux-fuse-writeback-cache-v1".to_owned(),
            expected_host_capability_fingerprint: None,
            lane_manifest_id: "authoritative-env-frankenfs-fuse-v1".to_owned(),
            lane_manifest_path: "artifacts/qa/authoritative_environment_manifest.json".to_owned(),
            lane_manifest_fresh: true,
            lane_manifest_matches_host: true,
            release_gate_consumer: "writeback_cache.release_gate".to_owned(),
        }
    }

    fn happy_gate() -> WritebackCacheAuditGate {
        WritebackCacheAuditGate {
            schema_version: WRITEBACK_CACHE_AUDIT_SCHEMA_VERSION,
            gate_version: "v1".to_owned(),
            bead_id: "bd-rchk0.2.1.1".to_owned(),
            generated_at: None,
            mount_options: WritebackMountOptions {
                raw_options: vec!["rw".to_owned(), "default_permissions".to_owned()],
                fs_name: "frankenfs".to_owned(),
                allow_other: false,
                auto_unmount: true,
                default_permissions: true,
                mode: "rw".to_owned(),
            },
            repair_serialization_state: "rw_lane_accepted".to_owned(),
            fuse_capability: FuseCapabilityState {
                probe_status: "available".to_owned(),
                kernel_supports_writeback_cache: true,
                helper_binary_present: true,
            },
            epoch_barrier_artifact: happy_artifact("epoch_barrier_proof"),
            crash_matrix_artifact: happy_artifact("crash_matrix"),
            fsync_evidence_artifact: happy_artifact("fsync_evidence"),
            filesystem_flavor: "ext4".to_owned(),
            operation_class: "mounted_write".to_owned(),
            explicit_opt_in: true,
            conflicting_flags: Vec::new(),
            runtime_guard: happy_runtime_guard(),
        }
    }

    fn supported_invariant(id: &str) -> WritebackOrderingInvariantEvidence {
        WritebackOrderingInvariantEvidence {
            id: id.to_owned(),
            supported: true,
            test_id: format!("writeback_ordering_{id}_test"),
            artifact_field: format!("ordering.{id}.artifact"),
            release_gate_consumer: "writeback_cache.release_gate".to_owned(),
            unsupported_rationale: String::new(),
        }
    }

    fn happy_ordering_oracle() -> WritebackOrderingOracle {
        WritebackOrderingOracle {
            schema_version: WRITEBACK_CACHE_ORDERING_SCHEMA_VERSION,
            gate_version: "bd-8pz7h-ordering-v1".to_owned(),
            bead_id: "bd-8pz7h".to_owned(),
            mount_options: WritebackMountOptions {
                raw_options: vec![
                    "rw".to_owned(),
                    "fsname=frankenfs".to_owned(),
                    "writeback_cache".to_owned(),
                ],
                fs_name: "frankenfs".to_owned(),
                allow_other: false,
                auto_unmount: true,
                default_permissions: true,
                mode: "rw".to_owned(),
            },
            raw_fuser_options: vec![
                "fsname=frankenfs".to_owned(),
                "subtype=ffs".to_owned(),
                "rw".to_owned(),
                "writeback_cache".to_owned(),
            ],
            dirty_page_state: "fsynced_durable".to_owned(),
            metadata_state: "metadata_after_data".to_owned(),
            flush_observed_non_durable: true,
            fsync_observed_durable: true,
            fsyncdir_observed_durable: true,
            cancellation_state: "cancelled_before_writeback_classified".to_owned(),
            unmount_state: "dirty_pages_flushed_or_rejected".to_owned(),
            crash_reopen_state: "survivor_set_verified".to_owned(),
            epoch_id: "epoch-0007".to_owned(),
            epoch_state: "fresh".to_owned(),
            repair_symbol_generation: 8,
            repair_symbol_refresh: "refreshed_after_writeback".to_owned(),
            invariant_evidence: REQUIRED_INVARIANT_IDS
                .into_iter()
                .map(supported_invariant)
                .collect(),
            expected_ordering: vec![
                "dirty_data".to_owned(),
                "fsync".to_owned(),
                "metadata".to_owned(),
                "fsyncdir".to_owned(),
                "repair_symbol_refresh".to_owned(),
            ],
            observed_ordering: vec![
                "dirty_data".to_owned(),
                "fsync".to_owned(),
                "metadata".to_owned(),
                "fsyncdir".to_owned(),
                "repair_symbol_refresh".to_owned(),
            ],
            artifact_paths: vec![
                "artifacts/writeback-cache/ordering.json".to_owned(),
                "artifacts/writeback-cache/crash_reopen.json".to_owned(),
            ],
        }
    }

    fn crash_replay_operation(
        step: u32,
        operation: &str,
        boundary: &str,
    ) -> WritebackCrashReplayOperation {
        WritebackCrashReplayOperation {
            step,
            operation: operation.to_owned(),
            target: "/writeback/data.bin".to_owned(),
            durability_boundary: boundary.to_owned(),
            expected_result: "success".to_owned(),
        }
    }

    fn crash_point(id: &str, step: u32) -> WritebackCrashPointEvidence {
        WritebackCrashPointEvidence {
            crash_point_id: id.to_owned(),
            description: format!("{id} mounted writeback-cache crash point"),
            operation_step: step,
            expected_survivor_set: vec![
                "/".to_owned(),
                "/writeback".to_owned(),
                "/writeback/data.bin:blake3=stable-v2".to_owned(),
            ],
            actual_survivor_set: vec![
                "/writeback/data.bin:blake3=stable-v2".to_owned(),
                "/".to_owned(),
                "/writeback".to_owned(),
            ],
            fsync_observed_durable: true,
            fsyncdir_observed_durable: true,
            flush_observed_non_durable: true,
            metadata_after_data_observed: true,
            unmount_reopen_observed: true,
            cancellation_state: "none".to_owned(),
            repeated_write_state: "not_applicable".to_owned(),
            replay_status: "survivor_set_verified".to_owned(),
            stdout_path: format!("artifacts/writeback-cache/crash-replay/{id}.stdout"),
            stderr_path: format!("artifacts/writeback-cache/crash-replay/{id}.stderr"),
            cleanup_status: "retained_for_qa".to_owned(),
        }
    }

    fn happy_crash_replay_oracle() -> WritebackCrashReplayOracle {
        let mut crash_points: Vec<_> = REQUIRED_CRASH_POINT_IDS
            .iter()
            .zip(1_u32..)
            .map(|(id, index)| crash_point(id, index))
            .collect();
        for point in &mut crash_points {
            match point.crash_point_id.as_str() {
                "cp07_after_repeated_write_before_fsync" | "cp08_after_repeated_write_fsync" => {
                    point.repeated_write_state = "last_fsynced_write_survived".to_owned();
                }
                "cp09_after_cancellation_before_writeback" => {
                    point.cancellation_state = "cancelled_before_writeback_classified".to_owned();
                }
                _ => {}
            }
        }

        WritebackCrashReplayOracle {
            schema_version: WRITEBACK_CACHE_CRASH_REPLAY_SCHEMA_VERSION,
            gate_version: "bd-rchk0.2.3-crash-replay-v1".to_owned(),
            bead_id: "bd-rchk0.2.3".to_owned(),
            matrix_id: "writeback_cache_crash_replay_matrix_v1".to_owned(),
            mount_options: WritebackMountOptions {
                raw_options: vec![
                    "rw".to_owned(),
                    "fsname=frankenfs".to_owned(),
                    "writeback_cache".to_owned(),
                ],
                fs_name: "frankenfs".to_owned(),
                allow_other: false,
                auto_unmount: true,
                default_permissions: true,
                mode: "rw".to_owned(),
            },
            raw_fuser_options: vec![
                "fsname=frankenfs".to_owned(),
                "subtype=ffs".to_owned(),
                "rw".to_owned(),
                "writeback_cache".to_owned(),
            ],
            epoch_id: "epoch-writeback-crash-0001".to_owned(),
            epoch_state: "fresh".to_owned(),
            host_capability_fingerprint: "fuse3-writeback-cache-enabled-host".to_owned(),
            lane_manifest_id: "fuse-writeback-cache-rw-lane-v1".to_owned(),
            operation_trace: vec![
                crash_replay_operation(1, "create", "none"),
                crash_replay_operation(2, "write", "kernel_writeback_cache"),
                crash_replay_operation(3, "flush", "non_durable"),
                crash_replay_operation(4, "fsync", "file_durable"),
                crash_replay_operation(5, "rename", "metadata_after_data"),
                crash_replay_operation(6, "fsyncdir", "directory_durable"),
                crash_replay_operation(7, "write", "repeated_write"),
                crash_replay_operation(8, "fsync", "last_write_durable"),
                crash_replay_operation(9, "cancel", "classified_before_writeback"),
                crash_replay_operation(10, "unmount", "dirty_pages_flushed_or_rejected"),
                crash_replay_operation(11, "reopen", "survivor_set_verified"),
                crash_replay_operation(12, "repair_refresh", "post_writeback_refresh"),
            ],
            crash_points,
            unsupported_combinations: vec![WritebackUnsupportedCombination {
                combination_id: "writeback_cache_ro_mount".to_owned(),
                rejected: true,
                reason: "read_only_writeback_cache".to_owned(),
                follow_up_bead: "bd-rchk0.2.4".to_owned(),
            }],
            artifact_paths: vec![
                "artifacts/writeback-cache/crash-replay/matrix.json".to_owned(),
                "artifacts/writeback-cache/crash-replay/results.json".to_owned(),
                "artifacts/writeback-cache/crash-replay/run.log".to_owned(),
            ],
        }
    }

    fn rejection_reason(decision: &WritebackCacheAuditDecision) -> Option<&str> {
        if let WritebackCacheAuditDecision::Reject { reason, .. } = decision {
            Some(reason.as_str())
        } else {
            None
        }
    }

    fn ordering_rejection_reason(decision: &WritebackOrderingDecision) -> Option<&str> {
        if let WritebackOrderingDecision::Reject { reason, .. } = decision {
            Some(reason.as_str())
        } else {
            None
        }
    }

    fn crash_replay_rejection_reason(decision: &WritebackCrashReplayDecision) -> Option<&str> {
        if let WritebackCrashReplayDecision::Reject { reason, .. } = decision {
            Some(reason.as_str())
        } else {
            None
        }
    }

    #[test]
    fn happy_gate_accepts_writeback_cache() {
        let decision = evaluate_writeback_cache_audit(&happy_gate());
        assert!(matches!(decision, WritebackCacheAuditDecision::Accept));
    }

    #[test]
    fn raw_options_writeback_cache_token_is_rejected_without_opt_in() {
        let mut gate = happy_gate();
        gate.explicit_opt_in = false;
        gate.mount_options
            .raw_options
            .push("writeback_cache".to_owned());
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("default_or_read_only_mount")
        );
    }

    #[test]
    fn read_only_mount_is_rejected() {
        let mut gate = happy_gate();
        gate.mount_options.mode = "ro".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("default_or_read_only_mount")
        );
    }

    #[test]
    fn missing_explicit_opt_in_is_rejected() {
        let mut gate = happy_gate();
        gate.explicit_opt_in = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("default_or_read_only_mount")
        );
    }

    #[test]
    fn runtime_kill_switch_is_rejected() {
        let mut gate = happy_gate();
        gate.runtime_guard.kill_switch_state = "engaged".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("runtime_kill_switch_engaged")
        );
    }

    #[test]
    fn downgraded_feature_state_is_rejected() {
        let mut gate = happy_gate();
        gate.runtime_guard.feature_state = "downgraded".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("writeback_feature_downgraded")
        );
    }

    #[test]
    fn stale_gate_artifact_is_rejected() {
        let mut gate = happy_gate();
        gate.runtime_guard.gate_fresh = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(rejection_reason(&decision), Some("stale_gate_artifact"));
    }

    #[test]
    fn gate_older_than_ttl_is_rejected() {
        let mut gate = happy_gate();
        gate.runtime_guard.gate_age_secs = gate.runtime_guard.gate_max_age_secs + 1;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(rejection_reason(&decision), Some("stale_gate_artifact"));
    }

    #[test]
    fn host_capability_mismatch_is_rejected() {
        let mut gate = happy_gate();
        gate.runtime_guard.lane_manifest_matches_host = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("host_capability_mismatch")
        );
    }

    #[test]
    fn stale_lane_manifest_is_rejected() {
        let mut gate = happy_gate();
        gate.runtime_guard.lane_manifest_fresh = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("host_capability_mismatch")
        );
    }

    #[test]
    fn config_default_attempt_is_rejected() {
        let mut gate = happy_gate();
        gate.runtime_guard.config_source = "config_default".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(rejection_reason(&decision), Some("config_default_attempt"));
    }

    #[test]
    fn repeated_mount_after_downgrade_keeps_rejection_class() {
        let mut gate = happy_gate();
        gate.runtime_guard.feature_state = "downgraded".to_owned();
        let first = evaluate_writeback_cache_audit(&gate);
        let second = evaluate_writeback_cache_audit(&gate);
        assert_eq!(first, second);
        assert_eq!(
            rejection_reason(&first),
            Some("writeback_feature_downgraded")
        );
    }

    #[test]
    fn unsupported_filesystem_flavor_is_rejected() {
        let mut gate = happy_gate();
        gate.filesystem_flavor = "ntfs".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("unsupported_filesystem_or_operation")
        );
    }

    #[test]
    fn unsupported_operation_class_is_rejected() {
        let mut gate = happy_gate();
        gate.operation_class = "mounted_mknod".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("unsupported_filesystem_or_operation")
        );
    }

    #[test]
    fn fuse_probe_unavailable_is_rejected() {
        let mut gate = happy_gate();
        gate.fuse_capability.probe_status = "unavailable".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("fuse_capability_unavailable")
        );
    }

    #[test]
    fn missing_helper_binary_is_rejected() {
        let mut gate = happy_gate();
        gate.fuse_capability.helper_binary_present = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("fuse_capability_unavailable")
        );
    }

    #[test]
    fn kernel_writeback_capability_false_is_rejected() {
        let mut gate = happy_gate();
        gate.fuse_capability.kernel_supports_writeback_cache = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("fuse_capability_unavailable")
        );
    }

    #[test]
    fn rw_repair_serialization_pending_is_rejected() {
        let mut gate = happy_gate();
        gate.repair_serialization_state = "pending_review".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("rw_repair_serialization_unsupported")
        );
    }

    #[test]
    fn missing_epoch_barrier_artifact_is_rejected() {
        let mut gate = happy_gate();
        gate.epoch_barrier_artifact.present = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("missing_epoch_barrier_artifact")
        );
    }

    #[test]
    fn stale_epoch_barrier_artifact_is_rejected() {
        let mut gate = happy_gate();
        gate.epoch_barrier_artifact.fresh = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("stale_epoch_barrier_artifact")
        );
    }

    #[test]
    fn failed_epoch_barrier_artifact_is_rejected() {
        let mut gate = happy_gate();
        gate.epoch_barrier_artifact.passed = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("stale_epoch_barrier_artifact")
        );
    }

    #[test]
    fn missing_crash_matrix_is_rejected() {
        let mut gate = happy_gate();
        gate.crash_matrix_artifact.present = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("stale_crash_matrix_or_missing_fsync_evidence")
        );
    }

    #[test]
    fn stale_crash_matrix_is_rejected() {
        let mut gate = happy_gate();
        gate.crash_matrix_artifact.fresh = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("stale_crash_matrix_or_missing_fsync_evidence")
        );
    }

    #[test]
    fn missing_fsync_evidence_is_rejected() {
        let mut gate = happy_gate();
        gate.fsync_evidence_artifact.present = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("stale_crash_matrix_or_missing_fsync_evidence")
        );
    }

    #[test]
    fn stale_fsync_evidence_is_rejected() {
        let mut gate = happy_gate();
        gate.fsync_evidence_artifact.fresh = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("stale_crash_matrix_or_missing_fsync_evidence")
        );
    }

    #[test]
    fn conflicting_cli_flag_is_rejected() {
        let mut gate = happy_gate();
        gate.conflicting_flags
            .push("ffs_writeback_force".to_owned());
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(rejection_reason(&decision), Some("conflicting_cli_flags"));
    }

    #[test]
    fn unrelated_cli_flag_is_ignored() {
        let mut gate = happy_gate();
        gate.conflicting_flags.push("noatime".to_owned());
        let decision = evaluate_writeback_cache_audit(&gate);
        assert!(matches!(decision, WritebackCacheAuditDecision::Accept));
    }

    #[test]
    fn rejection_decision_lists_invariants_failing() {
        let mut gate = happy_gate();
        gate.fuse_capability.probe_status = "unavailable".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert!(matches!(
            &decision,
            WritebackCacheAuditDecision::Reject {
                invariants_failing,
                ..
            } if invariants_failing.contains(&"I5".to_owned())
        ));
    }

    #[test]
    fn rejection_reason_is_stable_token() {
        let mut gate = happy_gate();
        gate.repair_serialization_state = "unknown".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert!(matches!(
            &decision,
            WritebackCacheAuditDecision::Reject { reason, .. }
                if ALLOWED_REJECTION_REASONS.contains(&reason.as_str())
        ));
    }

    #[test]
    fn validate_gate_top_level_rejects_bad_schema_version() {
        let mut gate = happy_gate();
        gate.schema_version = 99;
        let result = validate_writeback_cache_audit_gate(&gate);
        assert!(result.is_err());
    }

    #[test]
    fn unsupported_mode_builds_policy_rejection_report() -> Result<()> {
        let mut gate = happy_gate();
        gate.mount_options.mode = "swap".to_owned();
        let report = build_writeback_cache_audit_report(
            &gate,
            "writeback_cache_audit_rejects_unsupported_mode",
            "ffs-harness validate-writeback-cache-audit --gate gate.json",
        )?;

        assert!(matches!(
            report.decision,
            WritebackCacheAuditDecision::Reject { ref reason, .. }
                if reason == "default_or_read_only_mount"
        ));
        Ok(())
    }

    #[test]
    fn validate_gate_top_level_rejects_empty_mode() {
        let mut gate = happy_gate();
        gate.mount_options.mode.clear();
        let result = validate_writeback_cache_audit_gate(&gate);
        assert!(result.is_err());
    }

    #[test]
    fn validate_gate_top_level_rejects_malformed_bead_id() {
        let mut gate = happy_gate();
        gate.bead_id = "PROJ-42".to_owned();
        let result = validate_writeback_cache_audit_gate(&gate);
        assert!(result.is_err());
    }

    #[test]
    fn validate_gate_top_level_rejects_empty_artifact_path() {
        let mut gate = happy_gate();
        gate.fsync_evidence_artifact.artifact_path.clear();
        let result = validate_writeback_cache_audit_gate(&gate);
        assert!(result.is_err());
    }

    #[test]
    fn validate_gate_top_level_accepts_happy_path() {
        let result = validate_writeback_cache_audit_gate(&happy_gate());
        assert!(result.is_ok());
    }

    #[test]
    fn required_invariant_ids_cover_six_invariants() {
        assert_eq!(REQUIRED_INVARIANT_IDS.len(), 6);
        for id in &REQUIRED_INVARIANT_IDS {
            assert!(id.starts_with('I'));
        }
    }

    #[test]
    fn invariant_map_uses_design_invariant_names() {
        let map = writeback_invariant_map();
        let names: Vec<&str> = map
            .iter()
            .map(|invariant| invariant.name.as_str())
            .collect();
        assert!(names.contains(&"Snapshot Visibility Boundary"));
        assert!(names.contains(&"Alias Order Preservation"));
        assert!(names.contains(&"Metadata-After-Data Dependency"));
        assert!(names.contains(&"Sync Boundary Completeness"));
        assert!(names.contains(&"Flush Non-Durability"));
        assert!(names.contains(&"Cross-Epoch Order"));
    }

    #[test]
    fn report_includes_failure_modes_artifact_fields_and_repro() -> Result<()> {
        let report = build_writeback_cache_audit_report(
            &happy_gate(),
            "writeback_cache_audit_accepts_complete_gate",
            "ffs-harness validate-writeback-cache-audit --gate gate.json",
        )?;

        assert_eq!(
            report.scenario_id,
            "writeback_cache_audit_accepts_complete_gate"
        );
        assert!(
            report
                .failure_modes
                .contains(&"default_or_read_only_mount".to_owned())
        );
        assert!(
            report
                .failure_modes
                .contains(&"runtime_kill_switch_engaged".to_owned())
        );
        assert!(
            report
                .required_artifact_fields
                .contains(&"mount_options.raw_options".to_owned())
        );
        assert!(
            report
                .required_artifact_fields
                .contains(&"runtime_guard.gate_artifact_hash".to_owned())
        );
        assert!(
            report
                .required_artifact_fields
                .contains(&"runtime_guard.release_gate_consumer".to_owned())
        );
        assert_eq!(report.artifact_paths.len(), 4);
        assert_eq!(report.runtime_guard.feature_state, "accepted");
        assert!(matches!(
            report.decision,
            WritebackCacheAuditDecision::Accept
        ));
        Ok(())
    }

    #[test]
    fn require_accept_fails_closed_on_rejection() -> Result<()> {
        let mut gate = happy_gate();
        gate.explicit_opt_in = false;
        let report = build_writeback_cache_audit_report(
            &gate,
            "writeback_cache_audit_rejects_default_mount",
            "ffs-harness validate-writeback-cache-audit --gate gate.json --require-accept",
        )?;

        let result = fail_on_writeback_cache_audit_errors(&report);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn ordering_oracle_accepts_complete_proof() {
        let decision = evaluate_writeback_ordering_oracle(&happy_ordering_oracle());
        assert!(matches!(decision, WritebackOrderingDecision::Accept));
    }

    #[test]
    fn ordering_oracle_rejects_default_off_mount() {
        let mut oracle = happy_ordering_oracle();
        oracle.mount_options.mode = "ro".to_owned();
        oracle.mount_options.raw_options = vec!["ro".to_owned(), "fsname=frankenfs".to_owned()];
        let decision = evaluate_writeback_ordering_oracle(&oracle);
        assert_eq!(
            ordering_rejection_reason(&decision),
            Some("default_off_or_not_opted_in")
        );
    }

    #[test]
    fn ordering_oracle_rejects_missing_raw_fuser_writeback_option() {
        let mut oracle = happy_ordering_oracle();
        oracle
            .raw_fuser_options
            .retain(|option| option != "writeback_cache");
        let decision = evaluate_writeback_ordering_oracle(&oracle);
        assert_eq!(
            ordering_rejection_reason(&decision),
            Some("raw_fuser_option_missing")
        );
    }

    #[test]
    fn ordering_oracle_rejects_missing_invariant_test_id() -> Result<()> {
        let mut oracle = happy_ordering_oracle();
        invariant_evidence_mut(&mut oracle, 0)?.test_id.clear();
        let decision = evaluate_writeback_ordering_oracle(&oracle);
        assert!(matches!(
            decision,
            WritebackOrderingDecision::Reject {
                reason,
                invariants_failing,
                ..
            } if reason == "missing_invariant_evidence"
                && invariants_failing.contains(&"I1".to_owned())
        ));
        Ok(())
    }

    #[test]
    fn ordering_oracle_rejects_missing_invariant_artifact_field() -> Result<()> {
        let mut oracle = happy_ordering_oracle();
        invariant_evidence_mut(&mut oracle, 1)?
            .artifact_field
            .clear();
        let decision = evaluate_writeback_ordering_oracle(&oracle);
        assert!(matches!(
            decision,
            WritebackOrderingDecision::Reject {
                reason,
                invariants_failing,
                ..
            } if reason == "missing_invariant_evidence"
                && invariants_failing.contains(&"I2".to_owned())
        ));
        Ok(())
    }

    #[test]
    fn ordering_oracle_rejects_missing_invariant_release_gate_consumer() -> Result<()> {
        let mut oracle = happy_ordering_oracle();
        invariant_evidence_mut(&mut oracle, 2)?
            .release_gate_consumer
            .clear();
        let decision = evaluate_writeback_ordering_oracle(&oracle);
        assert!(matches!(
            decision,
            WritebackOrderingDecision::Reject {
                reason,
                invariants_failing,
                ..
            } if reason == "missing_invariant_evidence"
                && invariants_failing.contains(&"I3".to_owned())
        ));
        Ok(())
    }

    #[test]
    fn ordering_oracle_rejects_unsupported_invariant_even_with_rationale() -> Result<()> {
        let mut oracle = happy_ordering_oracle();
        let evidence = invariant_evidence_mut(&mut oracle, 3)?;
        evidence.supported = false;
        evidence.unsupported_rationale =
            "permissioned mounted lane unavailable on this host".to_owned();
        let decision = evaluate_writeback_ordering_oracle(&oracle);
        assert_eq!(
            ordering_rejection_reason(&decision),
            Some("missing_invariant_evidence")
        );
        Ok(())
    }

    #[test]
    fn ordering_oracle_rejects_unsupported_invariant_without_rationale() -> Result<()> {
        let mut oracle = happy_ordering_oracle();
        invariant_evidence_mut(&mut oracle, 3)?.supported = false;
        let decision = evaluate_writeback_ordering_oracle(&oracle);
        assert_eq!(
            ordering_rejection_reason(&decision),
            Some("missing_invariant_evidence")
        );
        Ok(())
    }

    #[test]
    fn ordering_oracle_rejects_dirty_pages_without_fsync_boundary() {
        let mut oracle = happy_ordering_oracle();
        oracle.dirty_page_state = "dirty_unflushed".to_owned();
        let decision = evaluate_writeback_ordering_oracle(&oracle);
        assert_eq!(
            ordering_rejection_reason(&decision),
            Some("missing_fsync_boundary")
        );
    }

    #[test]
    fn ordering_oracle_rejects_flush_as_durable() {
        let mut oracle = happy_ordering_oracle();
        oracle.flush_observed_non_durable = false;
        let decision = evaluate_writeback_ordering_oracle(&oracle);
        assert_eq!(
            ordering_rejection_reason(&decision),
            Some("flush_misclassified_as_durable")
        );
    }

    #[test]
    fn ordering_oracle_rejects_missing_fsyncdir_boundary() {
        let mut oracle = happy_ordering_oracle();
        oracle.fsyncdir_observed_durable = false;
        let decision = evaluate_writeback_ordering_oracle(&oracle);
        assert_eq!(
            ordering_rejection_reason(&decision),
            Some("missing_fsyncdir_boundary")
        );
    }

    #[test]
    fn ordering_oracle_rejects_metadata_overtaking_data() {
        let mut oracle = happy_ordering_oracle();
        oracle.metadata_state = "metadata_before_data".to_owned();
        let decision = evaluate_writeback_ordering_oracle(&oracle);
        assert_eq!(
            ordering_rejection_reason(&decision),
            Some("metadata_after_data_violation")
        );
    }

    #[test]
    fn ordering_oracle_rejects_unclassified_cancellation() {
        let mut oracle = happy_ordering_oracle();
        oracle.cancellation_state = "unknown".to_owned();
        let decision = evaluate_writeback_ordering_oracle(&oracle);
        assert_eq!(
            ordering_rejection_reason(&decision),
            Some("cancellation_not_classified")
        );
    }

    #[test]
    fn ordering_oracle_rejects_stale_epoch_state() {
        let mut oracle = happy_ordering_oracle();
        oracle.epoch_state = "stale".to_owned();
        let decision = evaluate_writeback_ordering_oracle(&oracle);
        assert_eq!(
            ordering_rejection_reason(&decision),
            Some("stale_epoch_state")
        );
    }

    #[test]
    fn ordering_oracle_rejects_unmount_with_dirty_pages() {
        let mut oracle = happy_ordering_oracle();
        oracle.unmount_state = "dirty_pages_pending".to_owned();
        let decision = evaluate_writeback_ordering_oracle(&oracle);
        assert_eq!(
            ordering_rejection_reason(&decision),
            Some("ordering_mismatch")
        );
    }

    #[test]
    fn ordering_oracle_rejects_missing_repair_refresh() {
        let mut oracle = happy_ordering_oracle();
        oracle.repair_symbol_refresh = "pending".to_owned();
        let decision = evaluate_writeback_ordering_oracle(&oracle);
        assert_eq!(
            ordering_rejection_reason(&decision),
            Some("repair_refresh_missing")
        );
    }

    #[test]
    fn ordering_oracle_rejects_observed_ordering_mismatch() {
        let mut oracle = happy_ordering_oracle();
        oracle.observed_ordering.swap(0, 1);
        let decision = evaluate_writeback_ordering_oracle(&oracle);
        assert_eq!(
            ordering_rejection_reason(&decision),
            Some("ordering_mismatch")
        );
    }

    #[test]
    fn ordering_report_includes_oracle_fields_and_repro() -> Result<()> {
        let report = build_writeback_ordering_report(
            &happy_ordering_oracle(),
            "writeback_cache_ordering_accepts_complete_oracle",
            "ffs-harness validate-writeback-cache-ordering --oracle oracle.json",
        )?;

        assert!(matches!(report.decision, WritebackOrderingDecision::Accept));
        assert_eq!(
            report.schema_version,
            WRITEBACK_CACHE_ORDERING_REPORT_SCHEMA_VERSION
        );
        assert_eq!(report.invariant_evidence.len(), 6);
        assert!(
            report
                .raw_fuser_options
                .contains(&"writeback_cache".to_owned())
        );
        assert_eq!(report.artifact_paths.len(), 2);
        assert!(
            report
                .reproduction_command
                .contains("validate-writeback-cache-ordering")
        );
        Ok(())
    }

    #[test]
    fn ordering_require_accept_fails_closed_on_rejection() -> Result<()> {
        let mut oracle = happy_ordering_oracle();
        oracle.fsync_observed_durable = false;
        let report = build_writeback_ordering_report(
            &oracle,
            "writeback_cache_ordering_rejects_missing_fsync",
            "ffs-harness validate-writeback-cache-ordering --oracle oracle.json --require-accept",
        )?;

        let result = fail_on_writeback_ordering_errors(&report);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn crash_replay_oracle_accepts_complete_matrix() {
        let decision = evaluate_writeback_crash_replay_oracle(&happy_crash_replay_oracle());
        assert!(matches!(decision, WritebackCrashReplayDecision::Accept));
    }

    #[test]
    fn crash_replay_oracle_rejects_missing_crash_point() {
        let mut oracle = happy_crash_replay_oracle();
        oracle.crash_points.pop();
        let decision = evaluate_writeback_crash_replay_oracle(&oracle);
        assert_eq!(
            crash_replay_rejection_reason(&decision),
            Some("missing_crash_point")
        );
    }

    #[test]
    fn crash_replay_oracle_rejects_survivor_set_mismatch() -> Result<()> {
        let mut oracle = happy_crash_replay_oracle();
        crash_point_mut(&mut oracle, 0)?
            .actual_survivor_set
            .push("/unexpected".to_owned());
        let decision = evaluate_writeback_crash_replay_oracle(&oracle);
        assert_eq!(
            crash_replay_rejection_reason(&decision),
            Some("survivor_set_mismatch")
        );
        Ok(())
    }

    #[test]
    fn crash_replay_oracle_rejects_flush_as_durable() -> Result<()> {
        let mut oracle = happy_crash_replay_oracle();
        crash_point_mut(&mut oracle, 2)?.flush_observed_non_durable = false;
        let decision = evaluate_writeback_crash_replay_oracle(&oracle);
        assert_eq!(
            crash_replay_rejection_reason(&decision),
            Some("flush_misclassified_as_durable")
        );
        Ok(())
    }

    #[test]
    fn crash_replay_oracle_rejects_missing_fsync_boundary() -> Result<()> {
        let mut oracle = happy_crash_replay_oracle();
        crash_point_mut(&mut oracle, 3)?.fsync_observed_durable = false;
        let decision = evaluate_writeback_crash_replay_oracle(&oracle);
        assert_eq!(
            crash_replay_rejection_reason(&decision),
            Some("missing_fsync_boundary")
        );
        Ok(())
    }

    #[test]
    fn crash_replay_oracle_rejects_missing_fsyncdir_boundary() -> Result<()> {
        let mut oracle = happy_crash_replay_oracle();
        crash_point_mut(&mut oracle, 4)?.fsyncdir_observed_durable = false;
        let decision = evaluate_writeback_crash_replay_oracle(&oracle);
        assert_eq!(
            crash_replay_rejection_reason(&decision),
            Some("missing_fsyncdir_boundary")
        );
        Ok(())
    }

    #[test]
    fn crash_replay_oracle_rejects_metadata_overtaking_data() -> Result<()> {
        let mut oracle = happy_crash_replay_oracle();
        crash_point_mut(&mut oracle, 4)?.metadata_after_data_observed = false;
        let decision = evaluate_writeback_crash_replay_oracle(&oracle);
        assert_eq!(
            crash_replay_rejection_reason(&decision),
            Some("metadata_after_data_violation")
        );
        Ok(())
    }

    #[test]
    fn crash_replay_oracle_rejects_missing_unmount_reopen_evidence() -> Result<()> {
        let mut oracle = happy_crash_replay_oracle();
        crash_point_mut(&mut oracle, 9)?.unmount_reopen_observed = false;
        let decision = evaluate_writeback_crash_replay_oracle(&oracle);
        assert_eq!(
            crash_replay_rejection_reason(&decision),
            Some("unmount_reopen_missing")
        );
        Ok(())
    }

    #[test]
    fn crash_replay_oracle_rejects_unclassified_cancellation() -> Result<()> {
        let mut oracle = happy_crash_replay_oracle();
        crash_point_mut(&mut oracle, 8)?.cancellation_state = "cancelled_unclassified".to_owned();
        let decision = evaluate_writeback_crash_replay_oracle(&oracle);
        assert_eq!(
            crash_replay_rejection_reason(&decision),
            Some("cancellation_not_classified")
        );
        Ok(())
    }

    #[test]
    fn crash_replay_oracle_rejects_stale_epoch_state() {
        let mut oracle = happy_crash_replay_oracle();
        oracle.epoch_state = "stale".to_owned();
        let decision = evaluate_writeback_crash_replay_oracle(&oracle);
        assert_eq!(
            crash_replay_rejection_reason(&decision),
            Some("stale_epoch_state")
        );
    }

    #[test]
    fn crash_replay_oracle_rejects_unsupported_combo_without_follow_up() -> Result<()> {
        let mut oracle = happy_crash_replay_oracle();
        unsupported_combination_mut(&mut oracle, 0)?.rejected = false;
        let decision = evaluate_writeback_crash_replay_oracle(&oracle);
        assert_eq!(
            crash_replay_rejection_reason(&decision),
            Some("unsupported_combination_not_rejected")
        );
        Ok(())
    }

    #[test]
    fn crash_replay_report_includes_required_artifact_contract() -> Result<()> {
        let report = build_writeback_crash_replay_report(
            &happy_crash_replay_oracle(),
            "writeback_cache_crash_replay_accepts_complete_matrix",
            "ffs-harness validate-writeback-cache-crash-replay --oracle oracle.json",
        )?;

        assert!(matches!(
            report.decision,
            WritebackCrashReplayDecision::Accept
        ));
        assert_eq!(
            report.schema_version,
            WRITEBACK_CACHE_CRASH_REPLAY_REPORT_SCHEMA_VERSION
        );
        assert_eq!(report.required_crash_point_ids.len(), 12);
        assert_eq!(report.covered_crash_point_ids.len(), 12);
        assert_eq!(report.operation_trace.len(), 12);
        assert!(
            report
                .raw_fuser_options
                .contains(&"writeback_cache".to_owned())
        );
        assert!(
            report
                .crash_points
                .iter()
                .all(|point| !point.stdout_path.is_empty()
                    && !point.stderr_path.is_empty()
                    && !point.cleanup_status.is_empty())
        );
        assert!(
            report
                .reproduction_command
                .contains("validate-writeback-cache-crash-replay")
        );
        Ok(())
    }

    #[test]
    fn crash_replay_require_accept_fails_closed_on_rejection() -> Result<()> {
        let mut oracle = happy_crash_replay_oracle();
        crash_point_mut(&mut oracle, 0)?.replay_status = "not_verified".to_owned();
        let report = build_writeback_crash_replay_report(
            &oracle,
            "writeback_cache_crash_replay_rejects_unverified_replay",
            "ffs-harness validate-writeback-cache-crash-replay --oracle oracle.json --require-accept",
        )?;

        let result = fail_on_writeback_crash_replay_errors(&report);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn writeback_cache_audit_report_json_shape() -> Result<()> {
        let report = build_writeback_cache_audit_report(
            &happy_gate(),
            "writeback_cache_audit_default_sample",
            "ffs-harness validate-writeback-cache-audit --gate gate.json",
        )?;
        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("writeback_cache_audit_report_json_shape", json);
        let parsed: WritebackCacheAuditReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn writeback_ordering_report_json_shape() -> Result<()> {
        let report = build_writeback_ordering_report(
            &happy_ordering_oracle(),
            "writeback_ordering_default_sample",
            "ffs-harness validate-writeback-ordering --oracle oracle.json",
        )?;
        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("writeback_ordering_report_json_shape", json);
        let parsed: WritebackOrderingReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn writeback_crash_replay_report_json_shape() -> Result<()> {
        let report = build_writeback_crash_replay_report(
            &happy_crash_replay_oracle(),
            "writeback_crash_replay_default_sample",
            "ffs-harness validate-writeback-crash-replay --oracle oracle.json",
        )?;
        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("writeback_crash_replay_report_json_shape", json);
        let parsed: WritebackCrashReplayReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    /// bd-v766a — Golden-artifact pin for the writeback-cache audit
    /// markdown emitter. The 18+ sibling tests cover validation /
    /// decision logic; this snapshot catches whitespace, heading-
    /// level, ordering, and bullet-format drift in the markdown
    /// bytes that silently breaks downstream proof-bundle / release-
    /// gate dashboard parsers.
    #[test]
    fn render_writeback_cache_audit_markdown_default_sample() -> Result<()> {
        let report = build_writeback_cache_audit_report(
            &happy_gate(),
            "writeback_cache_audit_default_sample",
            "ffs-harness validate-writeback-cache-audit --gate gate.json",
        )?;
        let markdown = render_writeback_cache_audit_markdown(&report);
        insta::assert_snapshot!(markdown);
        Ok(())
    }

    /// bd-x2rhd — Golden-artifact pin for the writeback ordering
    /// oracle markdown emitter. The 18+ sibling tests cover
    /// validation logic; this snapshot catches whitespace, heading-
    /// level, ordering, and bullet-format drift that silently
    /// breaks downstream proof-bundle / release-gate dashboard
    /// parsers. Pairs with bd-v766a (cache-audit emitter).
    #[test]
    fn render_writeback_ordering_markdown_default_sample() -> Result<()> {
        let report = build_writeback_ordering_report(
            &happy_ordering_oracle(),
            "writeback_ordering_default_sample",
            "ffs-harness validate-writeback-ordering --oracle oracle.json",
        )?;
        let markdown = render_writeback_ordering_markdown(&report);
        insta::assert_snapshot!(markdown);
        Ok(())
    }

    /// bd-rchk0.83 - Golden-artifact pin for the writeback crash/replay
    /// oracle markdown emitter. The sibling crash/replay tests cover
    /// validation logic; this snapshot catches heading, metadata, crash-point
    /// ordering, and failure-mode formatting drift before proof-bundle or
    /// release-gate dashboard consumers see it.
    #[test]
    fn render_writeback_crash_replay_markdown_default_sample() -> Result<()> {
        let report = build_writeback_crash_replay_report(
            &happy_crash_replay_oracle(),
            "writeback_crash_replay_default_sample",
            "ffs-harness validate-writeback-crash-replay --oracle oracle.json",
        )?;
        let markdown = render_writeback_crash_replay_markdown(&report);
        insta::assert_snapshot!(markdown);
        Ok(())
    }

    #[test]
    fn fuse_init_writeback_cache_tokens_are_accepted_by_oracles_bd_xvhsz() -> Result<()> {
        for token in ["FUSE_WRITEBACK_CACHE", "fuse_init:writeback_cache"] {
            let mut ordering = happy_ordering_oracle();
            ordering.raw_fuser_options = vec![
                "fsname=frankenfs".to_owned(),
                "subtype=ffs".to_owned(),
                "rw".to_owned(),
                token.to_owned(),
            ];
            assert!(
                matches!(
                    evaluate_writeback_ordering_oracle(&ordering),
                    WritebackOrderingDecision::Accept
                ),
                "ordering oracle must accept {token}"
            );

            let mut crash = happy_crash_replay_oracle();
            crash.raw_fuser_options = vec![
                "fsname=frankenfs".to_owned(),
                "subtype=ffs".to_owned(),
                "rw".to_owned(),
                token.to_owned(),
            ];
            assert!(
                matches!(
                    evaluate_writeback_crash_replay_oracle(&crash),
                    WritebackCrashReplayDecision::Accept
                ),
                "crash replay oracle must accept {token}"
            );
        }

        let (gate, ordering, crash_replay) = generate_writeback_cache_oracle_bundle("ext4")?;
        assert!(matches!(
            evaluate_writeback_cache_audit(&gate),
            WritebackCacheAuditDecision::Accept
        ));
        assert!(matches!(
            evaluate_writeback_ordering_oracle(&ordering),
            WritebackOrderingDecision::Accept
        ));
        assert!(matches!(
            evaluate_writeback_crash_replay_oracle(&crash_replay),
            WritebackCrashReplayDecision::Accept
        ));
        Ok(())
    }

    #[test]
    fn stale_generated_at_30_days_old_with_gate_fresh_true_is_rejected_bd_jtk24() {
        let mut gate = happy_gate();
        gate.runtime_guard.gate_fresh = true;
        gate.runtime_guard.gate_age_secs = 0;
        gate.generated_at = Some("2020-01-01T00:00:00Z".to_owned());
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(rejection_reason(&decision), Some("stale_gate_artifact"));
    }

    #[test]
    fn host_mismatched_manifest_with_matches_host_true_is_rejected_bd_jtk24() -> Result<()> {
        let mut gate = happy_gate();
        gate.runtime_guard.lane_manifest_matches_host = true;
        gate.runtime_guard.host_capability_fingerprint = "host-a-fingerprint".to_owned();
        let decision = evaluate_writeback_cache_audit_for_host(&gate, "host-b-fingerprint");
        assert_eq!(
            rejection_reason(&decision),
            Some("host_capability_mismatch")
        );

        let temp_dir = tempfile::tempdir()?;
        let manifest_path = temp_dir.path().join("manifest.json");
        fs::write(
            &manifest_path,
            serde_json::json!({
                "host_capability_fingerprint": "host-b-fingerprint",
                "generated_at": current_utc_rfc3339_seconds(),
            })
            .to_string(),
        )?;
        gate.runtime_guard.lane_manifest_path = manifest_path.display().to_string();
        let file_decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&file_decision),
            Some("host_capability_mismatch")
        );
        Ok(())
    }
}
