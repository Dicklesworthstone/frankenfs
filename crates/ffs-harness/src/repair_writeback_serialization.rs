#![allow(
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]
#![forbid(unsafe_code)]

//! Executable repair/writeback serialization contract for `bd-rchk0.1.1`.
//!
//! The live read-write mount path intentionally rejects mutating background
//! repair. This module keeps that policy precise: it validates the state
//! machine, rejection cases, risk decision, evidence fields, and dry-run
//! scenarios that must hold until repair writeback shares one serializer with
//! client writes.

use crate::artifact_manifest::{
    ArtifactCategory, ArtifactEntry, ArtifactManifest, EnvironmentFingerprint, ManifestBuilder,
    ScenarioResult,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const REPAIR_WRITEBACK_SERIALIZATION_SCHEMA_VERSION: u32 = 1;
pub const REPAIR_WRITEBACK_PROOF_SUMMARY_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_REPAIR_WRITEBACK_CONTRACT_PATH: &str =
    "docs/repair-writeback-serialization-contract.json";

const REQUIRED_STATES: [&str; 10] = [
    "detection_only_scrub",
    "repair_planning",
    "repair_lease_held",
    "client_write_in_flight",
    "fsync_boundary",
    "repair_writeback_blocked_rw",
    "repair_writeback_staged",
    "repair_symbol_refresh",
    "writeback_failure",
    "cleanup_complete",
];

const REQUIRED_INVARIANTS: [&str; 8] = [
    "I1_snapshot_epoch_cut",
    "I2_single_writer_serializer",
    "I3_dirty_cache_before_repair",
    "I4_fsync_fsyncdir_boundary",
    "I5_repair_lease_exclusive",
    "I6_repair_symbol_freshness",
    "I7_cancel_cleanup_no_partial_mutation",
    "I8_failure_refuses_symbol_refresh",
];

const REQUIRED_EVIDENCE_FIELDS: [&str; 12] = [
    "operation_id",
    "scenario_id",
    "snapshot_epoch",
    "lease_id",
    "repair_symbol_version",
    "expected_state",
    "observed_state",
    "error_class",
    "artifact_paths",
    "cleanup_status",
    "reproduction_command",
    "follow_up_bead",
];

const REQUIRED_IDENTITY_EVIDENCE_FIELDS: [&str; 8] = [
    "transition_id",
    "epoch_id",
    "lease_generation",
    "snapshot_id",
    "repair_symbol_generation",
    "block_range",
    "stale_refusal_reason",
    "ledger_row_ids",
];

const REQUIRED_IDENTITY_GUARDS: [&str; 7] = [
    "epoch_generation_monotonic",
    "lease_generation_monotonic",
    "snapshot_id_mismatch_rejected",
    "repair_symbol_generation_monotonic",
    "block_range_epoch_guard",
    "retry_generation_advances_after_abort",
    "halfway_failure_preserves_generation",
];

const REQUIRED_REJECTION_CASES: [&str; 7] = [
    "rw_repair_serializer_missing",
    "client_write_in_flight",
    "dirty_cache_not_fsynced",
    "stale_repair_symbol",
    "lease_expired_or_missing",
    "writeback_failure_no_refresh",
    "cancelled_repair_cleanup",
];

const REQUIRED_COVERAGE_TAGS: [&str; 9] = [
    "fail_closed_rw_repair",
    "mvcc_snapshot_boundary",
    "dirty_cache_flush",
    "fsync_fsyncdir_boundary",
    "repair_lease",
    "stale_repair_symbol",
    "cancellation",
    "writeback_failure",
    "halfway_recovery_failure",
];

const REQUIRED_CONSUMERS: [&str; 4] = [
    "operator_proof_bundle",
    "release_gate_evaluator",
    "operational_readiness_report",
    "mounted_write_matrix",
];

const REQUIRED_RACE_COVERAGE_CASES: [&str; 11] = [
    "repair_before_write",
    "write_before_repair",
    "overlapping_writes",
    "disjoint_writes",
    "fsync_during_repair",
    "cancellation_during_decode",
    "cancellation_during_writeback",
    "symbol_refresh_races_client_write",
    "unmount_pending_repair",
    "reopen_after_failed_repair",
    "retry_after_abort",
];

const REQUIRED_SCHEDULE_LOG_FIELDS: [&str; 12] = [
    "scheduler_version",
    "schedule_id",
    "seed",
    "explored_schedule_count",
    "pruned_schedule_count",
    "timeout_decision",
    "liveness_decision",
    "operation_trace",
    "classification",
    "artifact_paths",
    "follow_up_bead",
    "reproduction_command",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairWritebackSerializationContract {
    pub schema_version: u32,
    pub contract_id: String,
    pub bead_id: String,
    pub current_policy: CurrentRepairWritebackPolicy,
    pub artifact_consumers: Vec<String>,
    pub required_evidence_fields: Vec<String>,
    pub invariants: Vec<SerializationInvariant>,
    pub states: Vec<SerializationState>,
    pub transitions: Vec<SerializationTransition>,
    pub rejection_cases: Vec<SerializationRejectionCase>,
    pub identity_guards: Vec<SerializationIdentityGuard>,
    pub scenarios: Vec<SerializationScenario>,
    pub race_schedule_manifest: RepairRaceScheduleManifest,
    pub risk_decision: SerializationRiskDecision,
    pub follow_up_beads: Vec<SerializationFollowUp>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentRepairWritebackPolicy {
    pub policy_id: String,
    pub read_write_repair_state: String,
    pub mutating_rw_repair_enabled: bool,
    pub serialization_point: String,
    pub fail_closed_error_class: String,
    pub docs_wording_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationInvariant {
    pub invariant_id: String,
    pub description: String,
    pub required_log_fields: Vec<String>,
    pub failure_error_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationState {
    pub state_id: String,
    pub description: String,
    pub client_writes_allowed: bool,
    pub repair_writeback_allowed: bool,
    pub mutates_image: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationTransition {
    pub transition_id: String,
    pub from_state: String,
    pub event: String,
    pub to_state: String,
    pub allowed: bool,
    pub mutation_allowed: bool,
    pub error_class: String,
    pub guard: String,
    #[serde(default)]
    pub requires_active_lease: bool,
    #[serde(default)]
    pub requires_fresh_symbol: bool,
    #[serde(default)]
    pub requires_fsync_boundary: bool,
    pub required_evidence_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_bead: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationRejectionCase {
    pub case_id: String,
    pub error_class: String,
    pub state: String,
    pub condition: String,
    pub no_mutation_required: bool,
    pub preserves_reproduction_data: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_bead: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationIdentityGuard {
    pub guard_id: String,
    pub identity_kind: String,
    pub monotonic_field: String,
    pub aba_fixture_id: String,
    pub refusal_error_class: String,
    pub persisted_across_reopen: bool,
    pub rejects_structural_aba: bool,
    pub required_log_fields: Vec<String>,
    pub downstream_beads: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationScenario {
    pub scenario_id: String,
    pub title: String,
    pub coverage_tags: Vec<String>,
    pub initial_state: String,
    pub events: Vec<String>,
    pub expected_final_state: String,
    pub expected_outcome: String,
    pub expected_error_class: String,
    pub requires_lease: bool,
    pub requires_fsync_boundary: bool,
    pub requires_symbol_freshness: bool,
    pub proves_no_lost_client_write: bool,
    pub preserves_reproduction_data: bool,
    pub artifact_paths: Vec<String>,
    pub reproduction_command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_bead: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairRaceScheduleManifest {
    pub scheduler_version: String,
    pub exploration_strategy: String,
    pub max_explored_schedules: u32,
    pub max_pruned_schedules: u32,
    pub liveness_timeout_ms: u64,
    pub allowed_yield_points: Vec<String>,
    pub required_log_fields: Vec<String>,
    pub operation_dependencies: Vec<ScheduleDependency>,
    pub schedules: Vec<RepairRaceSchedule>,
    #[serde(default)]
    pub deferred_coverage: Vec<DeferredRaceCoverage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleDependency {
    pub before_operation: String,
    pub after_operation: String,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairRaceSchedule {
    pub schedule_id: String,
    pub coverage_case: String,
    pub seed: u64,
    pub operation_trace: Vec<String>,
    pub yield_points: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_injection: Option<CancellationInjection>,
    pub minimization: ScheduleMinimization,
    pub expected_survivor_set: Vec<String>,
    pub observed_survivor_set: Vec<String>,
    pub ledger_outcomes: Vec<String>,
    pub classification: String,
    pub explored_schedule_count: u32,
    pub pruned_schedule_count: u32,
    pub timeout_decision: String,
    pub liveness_decision: String,
    pub artifact_paths: Vec<String>,
    pub cleanup_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness_quarantine: Option<LivenessQuarantine>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_bead: Option<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationInjection {
    pub operation: String,
    pub yield_point: String,
    pub expected_cleanup: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleMinimization {
    pub minimized: bool,
    pub minimized_trace: Vec<String>,
    pub original_trace_len: u32,
    pub minimized_trace_len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivenessQuarantine {
    pub owner: String,
    pub expires_at: String,
    pub user_risk_rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredRaceCoverage {
    pub coverage_case: String,
    pub follow_up_bead: String,
    pub owner: String,
    pub expires_at: String,
    pub user_risk_rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationRiskDecision {
    pub decision_id: String,
    pub chosen_option: String,
    pub rejected_option: String,
    pub options: Vec<SerializationRiskOption>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationRiskOption {
    pub option_id: String,
    pub decision: String,
    pub semantic_failure_probability_ppm: u32,
    pub severity_points: u32,
    pub operational_cost_points: u32,
    pub expected_loss_points: u32,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationFollowUp {
    pub bead_id: String,
    pub reason: String,
    pub required_before_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairWritebackSerializationReport {
    pub schema_version: u32,
    pub contract_id: String,
    pub bead_id: String,
    pub valid: bool,
    pub state_count: usize,
    pub transition_count: usize,
    pub rejection_case_count: usize,
    pub identity_guard_count: usize,
    pub scenario_count: usize,
    pub schedule_count: usize,
    pub required_states: Vec<String>,
    pub required_race_coverage_cases: Vec<String>,
    pub missing_required_states: Vec<String>,
    pub missing_required_invariants: Vec<String>,
    pub missing_required_evidence_fields: Vec<String>,
    pub missing_required_rejection_cases: Vec<String>,
    pub missing_required_identity_guards: Vec<String>,
    pub missing_required_coverage_tags: Vec<String>,
    pub missing_required_consumers: Vec<String>,
    pub missing_required_race_coverage: Vec<String>,
    pub missing_required_schedule_log_fields: Vec<String>,
    pub duplicate_ids: Vec<String>,
    pub transition_evaluations: Vec<TransitionEvaluation>,
    pub identity_guard_reports: Vec<SerializationIdentityGuardReport>,
    pub scenario_reports: Vec<SerializationScenarioReport>,
    pub schedule_reports: Vec<RepairRaceScheduleReport>,
    pub risk_report: SerializationRiskReport,
    pub artifact_root: String,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionEvaluation {
    pub from_state: String,
    pub event: String,
    pub to_state: String,
    pub allowed: bool,
    pub mutation_allowed: bool,
    pub error_class: String,
    pub required_evidence_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_bead: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationScenarioReport {
    pub scenario_id: String,
    pub expected_outcome: String,
    pub expected_error_class: String,
    pub final_state: String,
    pub coverage_tags: Vec<String>,
    pub artifact_paths: Vec<String>,
    pub proves_no_lost_client_write: bool,
    pub preserves_reproduction_data: bool,
    pub valid: bool,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationIdentityGuardReport {
    pub guard_id: String,
    pub identity_kind: String,
    pub monotonic_field: String,
    pub aba_fixture_id: String,
    pub refusal_error_class: String,
    pub persisted_across_reopen: bool,
    pub rejects_structural_aba: bool,
    pub downstream_beads: Vec<String>,
    pub valid: bool,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairRaceScheduleReport {
    pub schedule_id: String,
    pub coverage_case: String,
    pub seed: u64,
    pub operation_trace: Vec<String>,
    pub yield_points: Vec<String>,
    pub explored_schedule_count: u32,
    pub pruned_schedule_count: u32,
    pub classification: String,
    pub timeout_decision: String,
    pub liveness_decision: String,
    pub expected_survivor_set: Vec<String>,
    pub observed_survivor_set: Vec<String>,
    pub ledger_outcomes: Vec<String>,
    pub minimized: bool,
    pub artifact_paths: Vec<String>,
    pub cleanup_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_bead: Option<String>,
    pub valid: bool,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationRiskReport {
    pub decision_id: String,
    pub chosen_option: String,
    pub rejected_option: String,
    pub chosen_expected_loss_points: u32,
    pub rejected_expected_loss_points: u32,
    pub fail_closed_is_lower_loss: bool,
    pub valid: bool,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairWritebackProofSummary {
    pub schema_version: u32,
    pub summary_id: String,
    pub producer_bead_id: String,
    pub source_bead_id: String,
    pub contract_id: String,
    pub valid: bool,
    pub read_write_repair_state: String,
    pub fail_closed_error_class: String,
    pub mutating_rw_repair_enabled: bool,
    pub safe_to_enable_rw_repair: bool,
    pub artifact_root: String,
    pub required_evidence_fields: Vec<String>,
    pub transition_guards: Vec<ProofTransitionGuard>,
    pub scenario_inputs: Vec<ProofScenarioInput>,
    pub race_schedule_inputs: Vec<ProofRaceScheduleInput>,
    pub identity_guard_inputs: Vec<ProofIdentityGuardInput>,
    pub downstream_inputs: Vec<ProofDownstreamInput>,
    pub reproduction_command: String,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTransitionGuard {
    pub from_state: String,
    pub event: String,
    pub to_state: String,
    pub allowed: bool,
    pub mutation_allowed: bool,
    pub error_class: String,
    pub follow_up_bead: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofScenarioInput {
    pub scenario_id: String,
    pub expected_outcome: String,
    pub expected_error_class: String,
    pub final_state: String,
    pub proves_no_lost_client_write: bool,
    pub preserves_reproduction_data: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRaceScheduleInput {
    pub schedule_id: String,
    pub coverage_case: String,
    pub classification: String,
    pub timeout_decision: String,
    pub liveness_decision: String,
    pub follow_up_bead: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofIdentityGuardInput {
    pub guard_id: String,
    pub identity_kind: String,
    pub monotonic_field: String,
    pub aba_fixture_id: String,
    pub refusal_error_class: String,
    pub persisted_across_reopen: bool,
    pub downstream_beads: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofDownstreamInput {
    pub bead_id: String,
    pub required_before_state: String,
    pub reason: String,
    pub required_fields: Vec<String>,
}

pub fn load_repair_writeback_serialization_contract(
    path: &Path,
) -> Result<RepairWritebackSerializationContract> {
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read repair/writeback contract {}",
            path.display()
        )
    })?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid repair/writeback contract JSON {}", path.display()))
}

#[must_use]
pub fn validate_repair_writeback_serialization_contract(
    contract: &RepairWritebackSerializationContract,
    artifact_root: &str,
) -> RepairWritebackSerializationReport {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    validate_top_level(contract, &mut errors);
    let duplicate_ids = collect_duplicate_ids(contract);
    errors.extend(
        duplicate_ids
            .iter()
            .map(|id| format!("duplicate contract id {id}")),
    );

    let state_ids = collect_state_ids(contract);
    let invariant_ids = collect_invariant_ids(contract);
    let rejection_case_ids = collect_rejection_case_ids(contract);
    let identity_guard_ids = collect_identity_guard_ids(contract);
    let coverage_tags = collect_coverage_tags(contract);
    let race_coverage_cases = collect_race_coverage_cases(contract);
    let consumers = collect_strings(&contract.artifact_consumers);
    let evidence_fields = collect_strings(&contract.required_evidence_fields);
    let schedule_log_fields = collect_strings(&contract.race_schedule_manifest.required_log_fields);

    let missing_required_states = missing_required(&state_ids, &REQUIRED_STATES);
    let missing_required_invariants = missing_required(&invariant_ids, &REQUIRED_INVARIANTS);
    let mut missing_required_evidence_fields =
        missing_required(&evidence_fields, &REQUIRED_EVIDENCE_FIELDS);
    missing_required_evidence_fields.extend(missing_required(
        &evidence_fields,
        &REQUIRED_IDENTITY_EVIDENCE_FIELDS,
    ));
    let missing_required_rejection_cases =
        missing_required(&rejection_case_ids, &REQUIRED_REJECTION_CASES);
    let missing_required_identity_guards =
        missing_required(&identity_guard_ids, &REQUIRED_IDENTITY_GUARDS);
    let missing_required_coverage_tags = missing_required(&coverage_tags, &REQUIRED_COVERAGE_TAGS);
    let missing_required_consumers = missing_required(&consumers, &REQUIRED_CONSUMERS);
    let missing_required_race_coverage =
        missing_required(&race_coverage_cases, &REQUIRED_RACE_COVERAGE_CASES);
    let missing_required_schedule_log_fields =
        missing_required(&schedule_log_fields, &REQUIRED_SCHEDULE_LOG_FIELDS);

    extend_missing(
        &mut errors,
        "missing required state",
        &missing_required_states,
    );
    extend_missing(
        &mut errors,
        "missing required invariant",
        &missing_required_invariants,
    );
    extend_missing(
        &mut errors,
        "missing required evidence field",
        &missing_required_evidence_fields,
    );
    extend_missing(
        &mut errors,
        "missing required rejection case",
        &missing_required_rejection_cases,
    );
    extend_missing(
        &mut errors,
        "missing required identity guard",
        &missing_required_identity_guards,
    );
    extend_missing(
        &mut errors,
        "missing required coverage tag",
        &missing_required_coverage_tags,
    );
    extend_missing(
        &mut errors,
        "missing required artifact consumer",
        &missing_required_consumers,
    );
    extend_missing(
        &mut errors,
        "missing required race coverage case",
        &missing_required_race_coverage,
    );
    extend_missing(
        &mut errors,
        "missing required schedule log field",
        &missing_required_schedule_log_fields,
    );

    validate_states(contract, &state_ids, &mut errors);
    validate_transitions(contract, &state_ids, &evidence_fields, &mut errors);
    validate_rejection_cases(contract, &mut errors);

    let identity_guard_reports = validate_identity_guards(contract, &evidence_fields, &mut errors);
    let scenario_reports = validate_scenarios(contract, &state_ids, artifact_root, &mut errors);
    let schedule_reports = validate_schedule_manifest(contract, artifact_root, &mut errors);
    let risk_report = validate_risk_decision(contract, &mut errors);
    if !risk_report.fail_closed_is_lower_loss {
        warnings
            .push("fail-closed policy is not lower expected loss than rejected path".to_owned());
    }

    let transition_evaluations = required_transition_evaluations(contract);

    RepairWritebackSerializationReport {
        schema_version: contract.schema_version,
        contract_id: contract.contract_id.clone(),
        bead_id: contract.bead_id.clone(),
        valid: errors.is_empty(),
        state_count: contract.states.len(),
        transition_count: contract.transitions.len(),
        rejection_case_count: contract.rejection_cases.len(),
        identity_guard_count: contract.identity_guards.len(),
        scenario_count: contract.scenarios.len(),
        schedule_count: contract.race_schedule_manifest.schedules.len(),
        required_states: REQUIRED_STATES.iter().map(ToString::to_string).collect(),
        required_race_coverage_cases: REQUIRED_RACE_COVERAGE_CASES
            .iter()
            .map(ToString::to_string)
            .collect(),
        missing_required_states,
        missing_required_invariants,
        missing_required_evidence_fields,
        missing_required_rejection_cases,
        missing_required_identity_guards,
        missing_required_coverage_tags,
        missing_required_consumers,
        missing_required_race_coverage,
        missing_required_schedule_log_fields,
        duplicate_ids,
        transition_evaluations,
        identity_guard_reports,
        scenario_reports,
        schedule_reports,
        risk_report,
        artifact_root: artifact_root.to_owned(),
        errors,
        warnings,
        reproduction_command: contract.reproduction_command.clone(),
    }
}

#[must_use]
pub fn evaluate_transition(
    contract: &RepairWritebackSerializationContract,
    from_state: &str,
    event: &str,
) -> TransitionEvaluation {
    contract
        .transitions
        .iter()
        .find(|transition| transition.from_state == from_state && transition.event == event)
        .map_or_else(
            || TransitionEvaluation {
                from_state: from_state.to_owned(),
                event: event.to_owned(),
                to_state: from_state.to_owned(),
                allowed: false,
                mutation_allowed: false,
                error_class: "transition_missing".to_owned(),
                required_evidence_fields: REQUIRED_EVIDENCE_FIELDS
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                follow_up_bead: Some("bd-rchk0.1.1.1".to_owned()),
            },
            |transition| TransitionEvaluation {
                from_state: transition.from_state.clone(),
                event: transition.event.clone(),
                to_state: transition.to_state.clone(),
                allowed: transition.allowed,
                mutation_allowed: transition.mutation_allowed,
                error_class: transition.error_class.clone(),
                required_evidence_fields: transition.required_evidence_fields.clone(),
                follow_up_bead: transition.follow_up_bead.clone(),
            },
        )
}

#[must_use]
pub fn render_repair_writeback_serialization_markdown(
    report: &RepairWritebackSerializationReport,
) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# Repair Writeback Serialization Contract").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "- Contract: `{}`", report.contract_id).ok();
    writeln!(&mut out, "- Bead: `{}`", report.bead_id).ok();
    writeln!(&mut out, "- Valid: `{}`", report.valid).ok();
    writeln!(
        &mut out,
        "- Counts: states={} transitions={} rejection_cases={} identity_guards={} scenarios={} schedules={}",
        report.state_count,
        report.transition_count,
        report.rejection_case_count,
        report.identity_guard_count,
        report.scenario_count,
        report.schedule_count
    )
    .ok();
    writeln!(
        &mut out,
        "- Risk decision: `{}` chosen_loss={} rejected_loss={} lower_loss={}",
        report.risk_report.chosen_option,
        report.risk_report.chosen_expected_loss_points,
        report.risk_report.rejected_expected_loss_points,
        report.risk_report.fail_closed_is_lower_loss
    )
    .ok();
    writeln!(&mut out, "- Reproduce: `{}`", report.reproduction_command).ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Required Transition Checks").ok();
    for transition in &report.transition_evaluations {
        writeln!(
            &mut out,
            "- `{}` + `{}` -> `{}` allowed={} mutation={} error_class=`{}`",
            transition.from_state,
            transition.event,
            transition.to_state,
            transition.allowed,
            transition.mutation_allowed,
            transition.error_class
        )
        .ok();
    }
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Identity Guards").ok();
    for guard in &report.identity_guard_reports {
        writeln!(
            &mut out,
            "- `{}` kind=`{}` field=`{}` fixture=`{}` refusal=`{}` persisted={} aba_rejected={}",
            guard.guard_id,
            guard.identity_kind,
            guard.monotonic_field,
            guard.aba_fixture_id,
            guard.refusal_error_class,
            guard.persisted_across_reopen,
            guard.rejects_structural_aba
        )
        .ok();
    }
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Scenarios").ok();
    for scenario in &report.scenario_reports {
        writeln!(
            &mut out,
            "- `{}` outcome=`{}` error_class=`{}` final_state=`{}` no_lost_write={} repro_preserved={}",
            scenario.scenario_id,
            scenario.expected_outcome,
            scenario.expected_error_class,
            scenario.final_state,
            scenario.proves_no_lost_client_write,
            scenario.preserves_reproduction_data
        )
        .ok();
    }
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Race Schedules").ok();
    for schedule in &report.schedule_reports {
        writeln!(
            &mut out,
            "- `{}` coverage=`{}` classification=`{}` seed={} explored={} pruned={} liveness=`{}` cleanup=`{}`",
            schedule.schedule_id,
            schedule.coverage_case,
            schedule.classification,
            schedule.seed,
            schedule.explored_schedule_count,
            schedule.pruned_schedule_count,
            schedule.liveness_decision,
            schedule.cleanup_status
        )
        .ok();
    }
    if !report.errors.is_empty() {
        writeln!(&mut out).ok();
        writeln!(&mut out, "## Errors").ok();
        for error in &report.errors {
            writeln!(&mut out, "- {error}").ok();
        }
    }
    out
}

#[must_use]
pub fn build_repair_writeback_serialization_sample_artifact_manifest(
    contract: &RepairWritebackSerializationContract,
    artifact_root: &str,
    report: &RepairWritebackSerializationReport,
) -> ArtifactManifest {
    let mut builder = ManifestBuilder::new(
        "bd-rchk0.1.1-repair-writeback-serialization",
        "repair_writeback_serialization",
        "2026-05-03T00:00:00Z",
    )
    .bead_id("bd-rchk0.1.1")
    .git_context("dry-run", "main", true)
    .environment(EnvironmentFingerprint {
        hostname: "dry-run".to_owned(),
        cpu_model: "contract-validator".to_owned(),
        cpu_count: 64,
        memory_gib: 256,
        kernel: "linux-fuse-contract".to_owned(),
        rustc_version: "nightly-rust-2024".to_owned(),
        cargo_version: Some("cargo-2024".to_owned()),
    });

    for scenario in &report.scenario_reports {
        let detail = format!(
            "{}:{}:{}",
            scenario.final_state, scenario.expected_outcome, scenario.expected_error_class
        );
        builder = builder.scenario(
            &scenario.scenario_id,
            if scenario.valid {
                ScenarioResult::Pass
            } else {
                ScenarioResult::Fail
            },
            Some(&detail),
            0.01,
        );
    }

    for path in [
        "repair_writeback_serialization_report.json",
        "repair_writeback_serialization_proof_summary.json",
        "repair_writeback_serialization_summary.md",
        "repair_writeback_serialization_repro.log",
    ] {
        let mut metadata = BTreeMap::new();
        metadata.insert("contract_id".to_owned(), contract.contract_id.clone());
        metadata.insert(
            "proof_bundle_lane".to_owned(),
            "repair_rw_writeback".to_owned(),
        );
        metadata.insert(
            "release_gate_feature".to_owned(),
            "repair.rw.writeback".to_owned(),
        );
        let extension = Path::new(path).extension();
        let is_markdown = extension.is_some_and(|ext| ext.eq_ignore_ascii_case("md"));
        let is_log = extension.is_some_and(|ext| ext.eq_ignore_ascii_case("log"));
        builder = builder.artifact(ArtifactEntry {
            path: format!("{artifact_root}/{path}"),
            category: if is_markdown {
                ArtifactCategory::SummaryReport
            } else {
                ArtifactCategory::ProofArtifact
            },
            content_type: Some(if is_markdown {
                "text/markdown".to_owned()
            } else if is_log {
                "text/plain".to_owned()
            } else {
                "application/json".to_owned()
            }),
            size_bytes: 1024,
            sha256: None,
            redacted: false,
            metadata,
        });
    }

    builder.duration_secs(0.5).build()
}

#[must_use]
pub fn build_repair_writeback_proof_summary(
    contract: &RepairWritebackSerializationContract,
    report: &RepairWritebackSerializationReport,
) -> RepairWritebackProofSummary {
    let downstream_inputs = contract
        .follow_up_beads
        .iter()
        .filter(|follow_up| follow_up.bead_id != "bd-rchk0.1.1.1")
        .map(|follow_up| ProofDownstreamInput {
            bead_id: follow_up.bead_id.clone(),
            required_before_state: follow_up.required_before_state.clone(),
            reason: follow_up.reason.clone(),
            required_fields: vec![
                "transition_guards".to_owned(),
                "scenario_inputs".to_owned(),
                "race_schedule_inputs".to_owned(),
                "required_evidence_fields".to_owned(),
            ],
        })
        .collect();

    RepairWritebackProofSummary {
        schema_version: REPAIR_WRITEBACK_PROOF_SUMMARY_SCHEMA_VERSION,
        summary_id: "bd-rchk0.1.1.1-repair-writeback-proof-summary-v1".to_owned(),
        producer_bead_id: "bd-rchk0.1.1.1".to_owned(),
        source_bead_id: contract.bead_id.clone(),
        contract_id: contract.contract_id.clone(),
        valid: report.valid,
        read_write_repair_state: contract.current_policy.read_write_repair_state.clone(),
        fail_closed_error_class: contract.current_policy.fail_closed_error_class.clone(),
        mutating_rw_repair_enabled: contract.current_policy.mutating_rw_repair_enabled,
        safe_to_enable_rw_repair: report.valid
            && contract.current_policy.mutating_rw_repair_enabled
            && contract.current_policy.serialization_point != "not_implemented",
        artifact_root: report.artifact_root.clone(),
        required_evidence_fields: contract.required_evidence_fields.clone(),
        transition_guards: report
            .transition_evaluations
            .iter()
            .map(|transition| ProofTransitionGuard {
                from_state: transition.from_state.clone(),
                event: transition.event.clone(),
                to_state: transition.to_state.clone(),
                allowed: transition.allowed,
                mutation_allowed: transition.mutation_allowed,
                error_class: transition.error_class.clone(),
                follow_up_bead: transition.follow_up_bead.clone(),
            })
            .collect(),
        scenario_inputs: report
            .scenario_reports
            .iter()
            .map(|scenario| ProofScenarioInput {
                scenario_id: scenario.scenario_id.clone(),
                expected_outcome: scenario.expected_outcome.clone(),
                expected_error_class: scenario.expected_error_class.clone(),
                final_state: scenario.final_state.clone(),
                proves_no_lost_client_write: scenario.proves_no_lost_client_write,
                preserves_reproduction_data: scenario.preserves_reproduction_data,
            })
            .collect(),
        race_schedule_inputs: report
            .schedule_reports
            .iter()
            .map(|schedule| ProofRaceScheduleInput {
                schedule_id: schedule.schedule_id.clone(),
                coverage_case: schedule.coverage_case.clone(),
                classification: schedule.classification.clone(),
                timeout_decision: schedule.timeout_decision.clone(),
                liveness_decision: schedule.liveness_decision.clone(),
                follow_up_bead: schedule.follow_up_bead.clone(),
            })
            .collect(),
        identity_guard_inputs: report
            .identity_guard_reports
            .iter()
            .map(|guard| ProofIdentityGuardInput {
                guard_id: guard.guard_id.clone(),
                identity_kind: guard.identity_kind.clone(),
                monotonic_field: guard.monotonic_field.clone(),
                aba_fixture_id: guard.aba_fixture_id.clone(),
                refusal_error_class: guard.refusal_error_class.clone(),
                persisted_across_reopen: guard.persisted_across_reopen,
                downstream_beads: guard.downstream_beads.clone(),
            })
            .collect(),
        downstream_inputs,
        reproduction_command: report.reproduction_command.clone(),
        errors: report.errors.clone(),
    }
}

pub fn fail_on_repair_writeback_serialization_errors(
    report: &RepairWritebackSerializationReport,
) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        for error in &report.errors {
            eprintln!("repair/writeback serialization error: {error}");
        }
        bail!(
            "repair/writeback serialization validation failed with {} error(s)",
            report.errors.len()
        )
    }
}

fn validate_top_level(contract: &RepairWritebackSerializationContract, errors: &mut Vec<String>) {
    if contract.schema_version != REPAIR_WRITEBACK_SERIALIZATION_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {REPAIR_WRITEBACK_SERIALIZATION_SCHEMA_VERSION}, got {}",
            contract.schema_version
        ));
    }
    if contract.bead_id != "bd-rchk0.1.1" {
        errors.push(format!(
            "bead_id must be bd-rchk0.1.1, got {}",
            contract.bead_id
        ));
    }
    if contract.current_policy.mutating_rw_repair_enabled {
        errors.push("mutating read-write repair must remain disabled for this contract".to_owned());
    }
    if contract.current_policy.read_write_repair_state != "fail_closed" {
        errors.push(format!(
            "read_write_repair_state must be fail_closed, got {}",
            contract.current_policy.read_write_repair_state
        ));
    }
    if contract.current_policy.fail_closed_error_class != "rw_repair_serialization_missing" {
        errors.push(format!(
            "fail_closed_error_class must be rw_repair_serialization_missing, got {}",
            contract.current_policy.fail_closed_error_class
        ));
    }
    if contract.reproduction_command.is_empty() {
        errors.push("reproduction_command is required".to_owned());
    }
}

fn validate_states(
    contract: &RepairWritebackSerializationContract,
    state_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    for state in &contract.states {
        if state.state_id == "repair_writeback_staged" && !state.repair_writeback_allowed {
            errors.push("repair_writeback_staged must allow repair writeback".to_owned());
        }
        if state.state_id == "repair_writeback_blocked_rw" && state.mutates_image {
            errors.push("repair_writeback_blocked_rw must not mutate the image".to_owned());
        }
    }
    for transition in &contract.transitions {
        if !state_ids.contains(&transition.from_state) {
            errors.push(format!(
                "{} references unknown from_state {}",
                transition.transition_id, transition.from_state
            ));
        }
        if !state_ids.contains(&transition.to_state) {
            errors.push(format!(
                "{} references unknown to_state {}",
                transition.transition_id, transition.to_state
            ));
        }
    }
}

fn validate_transitions(
    contract: &RepairWritebackSerializationContract,
    state_ids: &BTreeSet<String>,
    evidence_fields: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    let _ = state_ids;
    for transition in &contract.transitions {
        if !transition.allowed && transition.mutation_allowed {
            errors.push(format!(
                "{} is forbidden but still allows mutation",
                transition.transition_id
            ));
        }
        for field in &transition.required_evidence_fields {
            if !evidence_fields.contains(field) {
                errors.push(format!(
                    "{} requires undeclared evidence field {}",
                    transition.transition_id, field
                ));
            }
        }
        if !transition.allowed
            && transition.error_class == "none"
            && transition.event != "detect_only_scrub"
        {
            errors.push(format!(
                "{} is forbidden but does not name an error class",
                transition.transition_id
            ));
        }
    }

    let rw_block = evaluate_transition(
        contract,
        "client_write_in_flight",
        "repair_writeback_requested",
    );
    if rw_block.allowed
        || rw_block.mutation_allowed
        || rw_block.error_class != "rw_repair_serialization_missing"
        || rw_block.to_state != "repair_writeback_blocked_rw"
    {
        errors.push(
            "client-write plus repair-writeback transition must fail closed without mutation"
                .to_owned(),
        );
    }

    let flush = evaluate_transition(contract, "client_write_in_flight", "flush_observed");
    if flush.allowed || flush.mutation_allowed || flush.error_class != "flush_non_durable" {
        errors.push("flush transition must be non-durable and must not publish repair".to_owned());
    }
}

fn validate_rejection_cases(
    contract: &RepairWritebackSerializationContract,
    errors: &mut Vec<String>,
) {
    for case in &contract.rejection_cases {
        if !case.no_mutation_required {
            errors.push(format!("{} must require no mutation", case.case_id));
        }
        if !case.preserves_reproduction_data {
            errors.push(format!("{} must preserve reproduction data", case.case_id));
        }
        if case.follow_up_bead.is_none() && case.case_id != "rw_repair_serializer_missing" {
            errors.push(format!("{} must link a follow-up bead", case.case_id));
        }
    }
}

fn validate_identity_guards(
    contract: &RepairWritebackSerializationContract,
    evidence_fields: &BTreeSet<String>,
    errors: &mut Vec<String>,
) -> Vec<SerializationIdentityGuardReport> {
    let mut reports = Vec::new();
    for guard in &contract.identity_guards {
        let mut diagnostics = Vec::new();
        if !matches!(
            guard.identity_kind.as_str(),
            "epoch" | "lease" | "snapshot" | "repair_symbol" | "block_range" | "retry"
        ) {
            diagnostics.push(format!("unsupported identity_kind {}", guard.identity_kind));
        }
        if guard.monotonic_field.is_empty() {
            diagnostics.push("monotonic_field is required".to_owned());
        }
        if guard.aba_fixture_id.is_empty() || !guard.aba_fixture_id.starts_with("aba_") {
            diagnostics.push("aba_fixture_id must be nonempty and start with aba_".to_owned());
        }
        if guard.refusal_error_class == "none" || guard.refusal_error_class.is_empty() {
            diagnostics.push("refusal_error_class must fail closed".to_owned());
        }
        if !guard.rejects_structural_aba {
            diagnostics.push("identity guard must reject structural ABA reuse".to_owned());
        }
        if guard.required_log_fields.is_empty() {
            diagnostics.push("identity guard must name required_log_fields".to_owned());
        }
        if !guard.required_log_fields.contains(&guard.monotonic_field) {
            diagnostics.push(format!(
                "required_log_fields must include monotonic field {}",
                guard.monotonic_field
            ));
        }
        for required in [
            "operation_id",
            "scenario_id",
            "transition_id",
            "stale_refusal_reason",
            "ledger_row_ids",
        ] {
            if !guard
                .required_log_fields
                .iter()
                .any(|field| field == required)
            {
                diagnostics.push(format!("required_log_fields missing {required}"));
            }
        }
        for field in &guard.required_log_fields {
            if !evidence_fields.contains(field) {
                diagnostics.push(format!("requires undeclared evidence field {field}"));
            }
        }
        if guard.downstream_beads.is_empty() {
            diagnostics.push("identity guard must name downstream_beads".to_owned());
        }
        if guard
            .downstream_beads
            .iter()
            .any(|bead| !bead.starts_with("bd-"))
        {
            diagnostics.push("downstream_beads must contain bead ids".to_owned());
        }

        errors.extend(
            diagnostics
                .iter()
                .map(|diagnostic| format!("{}: {diagnostic}", guard.guard_id)),
        );
        reports.push(SerializationIdentityGuardReport {
            guard_id: guard.guard_id.clone(),
            identity_kind: guard.identity_kind.clone(),
            monotonic_field: guard.monotonic_field.clone(),
            aba_fixture_id: guard.aba_fixture_id.clone(),
            refusal_error_class: guard.refusal_error_class.clone(),
            persisted_across_reopen: guard.persisted_across_reopen,
            rejects_structural_aba: guard.rejects_structural_aba,
            downstream_beads: guard.downstream_beads.clone(),
            valid: diagnostics.is_empty(),
            diagnostics,
        });
    }
    reports
}

fn validate_scenarios(
    contract: &RepairWritebackSerializationContract,
    state_ids: &BTreeSet<String>,
    artifact_root: &str,
    errors: &mut Vec<String>,
) -> Vec<SerializationScenarioReport> {
    let mut reports = Vec::new();
    for scenario in &contract.scenarios {
        let mut diagnostics = Vec::new();
        if !state_ids.contains(&scenario.initial_state) {
            diagnostics.push(format!("unknown initial_state {}", scenario.initial_state));
        }
        if !state_ids.contains(&scenario.expected_final_state) {
            diagnostics.push(format!(
                "unknown expected_final_state {}",
                scenario.expected_final_state
            ));
        }
        if scenario.events.is_empty() {
            diagnostics.push("scenario must include at least one event".to_owned());
        }
        if !matches!(
            scenario.expected_outcome.as_str(),
            "accepted" | "rejected" | "skipped" | "error"
        ) {
            diagnostics.push(format!(
                "invalid expected_outcome {}",
                scenario.expected_outcome
            ));
        }
        if scenario.expected_outcome != "accepted" && scenario.expected_error_class == "none" {
            diagnostics.push("non-accepted scenario must name an error class".to_owned());
        }
        if scenario.expected_outcome == "rejected" && !scenario.proves_no_lost_client_write {
            diagnostics.push("rejected scenario must prove no lost client write".to_owned());
        }
        if (scenario.expected_outcome == "rejected" || scenario.expected_outcome == "error")
            && !scenario.preserves_reproduction_data
        {
            diagnostics.push("failure scenario must preserve reproduction data".to_owned());
        }
        if scenario.artifact_paths.is_empty() {
            diagnostics.push("scenario must list artifact paths".to_owned());
        }
        for path in &scenario.artifact_paths {
            if !is_safe_relative_artifact_path(path) {
                diagnostics.push(format!("unsafe artifact path {path}"));
            }
            if !path.starts_with(artifact_root) {
                diagnostics.push(format!(
                    "artifact path {path} must live under artifact root {artifact_root}"
                ));
            }
        }
        if scenario.reproduction_command.is_empty() {
            diagnostics.push("scenario must include reproduction_command".to_owned());
        }
        if scenario
            .coverage_tags
            .iter()
            .any(|tag| tag == "fail_closed_rw_repair")
            && scenario.follow_up_bead.is_none()
        {
            diagnostics.push(
                "fail-closed RW repair scenario must link the serializer follow-up".to_owned(),
            );
        }

        errors.extend(
            diagnostics
                .iter()
                .map(|diagnostic| format!("{}: {diagnostic}", scenario.scenario_id)),
        );

        reports.push(SerializationScenarioReport {
            scenario_id: scenario.scenario_id.clone(),
            expected_outcome: scenario.expected_outcome.clone(),
            expected_error_class: scenario.expected_error_class.clone(),
            final_state: scenario.expected_final_state.clone(),
            coverage_tags: scenario.coverage_tags.clone(),
            artifact_paths: scenario.artifact_paths.clone(),
            proves_no_lost_client_write: scenario.proves_no_lost_client_write,
            preserves_reproduction_data: scenario.preserves_reproduction_data,
            valid: diagnostics.is_empty(),
            diagnostics,
        });
    }
    reports
}

fn validate_schedule_manifest(
    contract: &RepairWritebackSerializationContract,
    artifact_root: &str,
    errors: &mut Vec<String>,
) -> Vec<RepairRaceScheduleReport> {
    let manifest = &contract.race_schedule_manifest;
    let mut manifest_diagnostics = Vec::new();

    if manifest.scheduler_version.is_empty() {
        manifest_diagnostics.push("scheduler_version is required".to_owned());
    }
    if !matches!(
        manifest.exploration_strategy.as_str(),
        "bounded_dpor" | "seeded_trace_replay"
    ) {
        manifest_diagnostics.push(format!(
            "unsupported exploration_strategy {}",
            manifest.exploration_strategy
        ));
    }
    if manifest.max_explored_schedules == 0 {
        manifest_diagnostics.push("max_explored_schedules must be positive".to_owned());
    }
    if manifest.liveness_timeout_ms == 0 {
        manifest_diagnostics.push("liveness_timeout_ms must be positive".to_owned());
    }
    if manifest.allowed_yield_points.is_empty() {
        manifest_diagnostics.push("allowed_yield_points must be nonempty".to_owned());
    }
    let allowed_yield_points = collect_strings(&manifest.allowed_yield_points);
    if allowed_yield_points.len() != manifest.allowed_yield_points.len() {
        manifest_diagnostics.push("allowed_yield_points must not contain duplicates".to_owned());
    }
    if manifest.schedules.is_empty() {
        manifest_diagnostics.push("at least one race schedule is required".to_owned());
    }
    if !manifest.schedules.is_empty()
        && manifest
            .schedules
            .iter()
            .all(|schedule| schedule.classification == "accepted")
    {
        manifest_diagnostics.push(
            "race schedule coverage must include rejected or unsupported interleavings".to_owned(),
        );
    }

    let operation_ids = collect_schedule_operations(manifest);
    validate_schedule_dependencies(manifest, &operation_ids, &mut manifest_diagnostics);
    validate_deferred_coverage(manifest, &mut manifest_diagnostics);

    errors.extend(
        manifest_diagnostics
            .iter()
            .map(|diagnostic| format!("race_schedule_manifest: {diagnostic}")),
    );

    let mut reports = Vec::new();
    for schedule in &manifest.schedules {
        let diagnostics =
            validate_race_schedule(schedule, manifest, &allowed_yield_points, artifact_root);
        errors.extend(
            diagnostics
                .iter()
                .map(|diagnostic| format!("{}: {diagnostic}", schedule.schedule_id)),
        );
        reports.push(RepairRaceScheduleReport {
            schedule_id: schedule.schedule_id.clone(),
            coverage_case: schedule.coverage_case.clone(),
            seed: schedule.seed,
            operation_trace: schedule.operation_trace.clone(),
            yield_points: schedule.yield_points.clone(),
            explored_schedule_count: schedule.explored_schedule_count,
            pruned_schedule_count: schedule.pruned_schedule_count,
            classification: schedule.classification.clone(),
            timeout_decision: schedule.timeout_decision.clone(),
            liveness_decision: schedule.liveness_decision.clone(),
            expected_survivor_set: schedule.expected_survivor_set.clone(),
            observed_survivor_set: schedule.observed_survivor_set.clone(),
            ledger_outcomes: schedule.ledger_outcomes.clone(),
            minimized: schedule.minimization.minimized,
            artifact_paths: schedule.artifact_paths.clone(),
            cleanup_status: schedule.cleanup_status.clone(),
            follow_up_bead: schedule.follow_up_bead.clone(),
            valid: diagnostics.is_empty(),
            diagnostics,
        });
    }
    reports
}

fn validate_schedule_dependencies(
    manifest: &RepairRaceScheduleManifest,
    operation_ids: &BTreeSet<String>,
    diagnostics: &mut Vec<String>,
) {
    let mut dependency_edges = BTreeSet::new();
    for dependency in &manifest.operation_dependencies {
        if dependency.before_operation.is_empty()
            || dependency.after_operation.is_empty()
            || dependency.rationale.is_empty()
        {
            diagnostics.push(
                "operation dependencies must name both operations and a rationale".to_owned(),
            );
        }
        if !operation_ids.contains(&dependency.before_operation) {
            diagnostics.push(format!(
                "dependency references unknown before_operation {}",
                dependency.before_operation
            ));
        }
        if !operation_ids.contains(&dependency.after_operation) {
            diagnostics.push(format!(
                "dependency references unknown after_operation {}",
                dependency.after_operation
            ));
        }
        if !dependency_edges.insert((
            dependency.before_operation.clone(),
            dependency.after_operation.clone(),
        )) {
            diagnostics.push(format!(
                "duplicate dependency edge {} -> {}",
                dependency.before_operation, dependency.after_operation
            ));
        }
    }
    if dependency_graph_has_cycle(&manifest.operation_dependencies) {
        diagnostics.push("operation dependency graph must be acyclic".to_owned());
    }
}

fn validate_deferred_coverage(
    manifest: &RepairRaceScheduleManifest,
    diagnostics: &mut Vec<String>,
) {
    for deferred in &manifest.deferred_coverage {
        if deferred.coverage_case.is_empty()
            || deferred.follow_up_bead.is_empty()
            || deferred.owner.is_empty()
            || deferred.expires_at.is_empty()
            || deferred.user_risk_rationale.is_empty()
        {
            diagnostics.push("deferred coverage must include case, follow-up, owner, expiry, and user-risk rationale".to_owned());
        }
        if REQUIRED_RACE_COVERAGE_CASES.contains(&deferred.coverage_case.as_str()) {
            diagnostics.push(format!(
                "required race coverage case {} cannot be deferred",
                deferred.coverage_case
            ));
        }
    }
}

fn validate_race_schedule(
    schedule: &RepairRaceSchedule,
    manifest: &RepairRaceScheduleManifest,
    allowed_yield_points: &BTreeSet<String>,
    artifact_root: &str,
) -> Vec<String> {
    let mut diagnostics = Vec::new();
    if schedule.schedule_id.is_empty() {
        diagnostics.push("schedule_id is required".to_owned());
    }
    if schedule.coverage_case.is_empty() {
        diagnostics.push("coverage_case is required".to_owned());
    }
    if schedule.seed == 0 {
        diagnostics.push("seed must be nonzero".to_owned());
    }
    if schedule.operation_trace.is_empty() {
        diagnostics.push("operation_trace must be nonempty".to_owned());
    }
    if schedule.yield_points.is_empty() {
        diagnostics.push("yield_points must be nonempty".to_owned());
    }
    for yield_point in &schedule.yield_points {
        if !allowed_yield_points.contains(yield_point) {
            diagnostics.push(format!("yield point {yield_point} is not allowed"));
        }
    }
    if !is_valid_schedule_classification(&schedule.classification) {
        diagnostics.push(format!(
            "invalid classification {}",
            schedule.classification
        ));
    }
    if !matches!(
        schedule.timeout_decision.as_str(),
        "completed" | "not_applicable" | "timeout_quarantined"
    ) {
        diagnostics.push(format!(
            "invalid timeout_decision {}",
            schedule.timeout_decision
        ));
    }
    if !matches!(
        schedule.liveness_decision.as_str(),
        "within_deadline" | "timeout_quarantined" | "deferred_long_campaign"
    ) {
        diagnostics.push(format!(
            "invalid liveness_decision {}",
            schedule.liveness_decision
        ));
    }
    if schedule.explored_schedule_count == 0 {
        diagnostics.push("explored_schedule_count must be positive".to_owned());
    }
    if schedule.pruned_schedule_count > schedule.explored_schedule_count {
        diagnostics.push("pruned_schedule_count cannot exceed explored_schedule_count".to_owned());
    }
    if schedule.explored_schedule_count > manifest.max_explored_schedules {
        diagnostics.push("explored_schedule_count exceeds manifest cap".to_owned());
    }
    if schedule.pruned_schedule_count > manifest.max_pruned_schedules {
        diagnostics.push("pruned_schedule_count exceeds manifest cap".to_owned());
    }
    if schedule.expected_survivor_set.is_empty() {
        diagnostics.push("expected_survivor_set must be nonempty".to_owned());
    }
    if schedule.observed_survivor_set.is_empty() {
        diagnostics.push("observed_survivor_set must be nonempty".to_owned());
    }
    if matches!(schedule.classification.as_str(), "accepted" | "rejected")
        && schedule.expected_survivor_set != schedule.observed_survivor_set
    {
        diagnostics.push("expected and observed survivor sets must match".to_owned());
    }
    if schedule.ledger_outcomes.is_empty() {
        diagnostics.push("ledger_outcomes must be nonempty".to_owned());
    }
    validate_minimization(&schedule.minimization, &mut diagnostics);
    validate_schedule_cancellation(schedule, allowed_yield_points, &mut diagnostics);
    validate_schedule_liveness_quarantine(schedule, &mut diagnostics);
    validate_schedule_follow_up(schedule, &mut diagnostics);
    if schedule.artifact_paths.is_empty() {
        diagnostics.push("schedule must list artifact paths".to_owned());
    }
    for path in &schedule.artifact_paths {
        if !is_safe_relative_artifact_path(path) {
            diagnostics.push(format!("unsafe artifact path {path}"));
        }
        if !path.starts_with(artifact_root) {
            diagnostics.push(format!(
                "artifact path {path} must live under artifact root {artifact_root}"
            ));
        }
    }
    if schedule.cleanup_status.is_empty() {
        diagnostics.push("cleanup_status is required".to_owned());
    }
    if schedule.reproduction_command.is_empty() {
        diagnostics.push("reproduction_command is required".to_owned());
    }
    diagnostics
}

fn validate_minimization(minimization: &ScheduleMinimization, diagnostics: &mut Vec<String>) {
    if minimization.original_trace_len == 0 {
        diagnostics.push("minimization original_trace_len must be positive".to_owned());
    }
    if minimization.minimized_trace_len == 0 {
        diagnostics.push("minimization minimized_trace_len must be positive".to_owned());
    }
    if minimization.minimized_trace_len > minimization.original_trace_len {
        diagnostics.push("minimized_trace_len cannot exceed original_trace_len".to_owned());
    }
    if minimization.minimized && minimization.minimized_trace.is_empty() {
        diagnostics.push("minimized schedules must preserve a minimized_trace".to_owned());
    }
    if minimization.minimized {
        match u32::try_from(minimization.minimized_trace.len()) {
            Ok(trace_len) if trace_len == minimization.minimized_trace_len => {}
            Ok(trace_len) => diagnostics.push(format!(
                "minimized_trace_len {} does not match minimized_trace length {trace_len}",
                minimization.minimized_trace_len
            )),
            Err(_) => diagnostics.push("minimized_trace length exceeds u32".to_owned()),
        }
    }
}

fn validate_schedule_cancellation(
    schedule: &RepairRaceSchedule,
    allowed_yield_points: &BTreeSet<String>,
    diagnostics: &mut Vec<String>,
) {
    if !schedule.coverage_case.contains("cancellation") {
        return;
    }
    let Some(injection) = &schedule.cancellation_injection else {
        diagnostics.push("cancellation coverage requires cancellation_injection".to_owned());
        return;
    };
    if injection.operation.is_empty()
        || injection.yield_point.is_empty()
        || injection.expected_cleanup.is_empty()
    {
        diagnostics.push(
            "cancellation_injection must name operation, yield point, and cleanup".to_owned(),
        );
    }
    if !schedule.operation_trace.contains(&injection.operation) {
        diagnostics.push(format!(
            "cancellation operation {} is not in operation_trace",
            injection.operation
        ));
    }
    if !allowed_yield_points.contains(&injection.yield_point) {
        diagnostics.push(format!(
            "cancellation yield point {} is not allowed",
            injection.yield_point
        ));
    }
}

fn validate_schedule_liveness_quarantine(
    schedule: &RepairRaceSchedule,
    diagnostics: &mut Vec<String>,
) {
    let needs_quarantine = schedule.classification == "quarantined_liveness"
        || schedule.timeout_decision == "timeout_quarantined"
        || schedule.liveness_decision == "timeout_quarantined";
    if !needs_quarantine {
        return;
    }
    let Some(quarantine) = &schedule.liveness_quarantine else {
        diagnostics
            .push("liveness quarantine requires owner, expiry, and user-risk rationale".to_owned());
        return;
    };
    if quarantine.owner.is_empty()
        || quarantine.expires_at.is_empty()
        || quarantine.user_risk_rationale.is_empty()
    {
        diagnostics.push(
            "liveness quarantine must include owner, expiry, and user-risk rationale".to_owned(),
        );
    }
}

fn validate_schedule_follow_up(schedule: &RepairRaceSchedule, diagnostics: &mut Vec<String>) {
    if matches!(
        schedule.classification.as_str(),
        "unsupported_interleaving" | "quarantined_liveness" | "deferred_long_campaign"
    ) && schedule.follow_up_bead.is_none()
    {
        diagnostics.push(
            "unsupported, quarantined, or deferred schedules require follow_up_bead".to_owned(),
        );
    }
}

fn validate_risk_decision(
    contract: &RepairWritebackSerializationContract,
    errors: &mut Vec<String>,
) -> SerializationRiskReport {
    let chosen = contract
        .risk_decision
        .options
        .iter()
        .find(|option| option.option_id == contract.risk_decision.chosen_option);
    let rejected = contract
        .risk_decision
        .options
        .iter()
        .find(|option| option.option_id == contract.risk_decision.rejected_option);

    let mut diagnostics = Vec::new();
    if contract.risk_decision.chosen_option != "fail_closed_until_unified_serializer" {
        diagnostics.push(format!(
            "chosen option must be fail_closed_until_unified_serializer, got {}",
            contract.risk_decision.chosen_option
        ));
    }
    if contract.risk_decision.rejected_option != "enable_rw_repair_without_serializer" {
        diagnostics.push(format!(
            "rejected option must be enable_rw_repair_without_serializer, got {}",
            contract.risk_decision.rejected_option
        ));
    }

    let chosen_loss = chosen.map_or(0, |option| option.expected_loss_points);
    let rejected_loss = rejected.map_or(0, |option| option.expected_loss_points);
    let fail_closed_is_lower_loss = chosen_loss < rejected_loss;
    if chosen.is_none() {
        diagnostics.push("chosen risk option is missing from options".to_owned());
    }
    if rejected.is_none() {
        diagnostics.push("rejected risk option is missing from options".to_owned());
    }
    if !fail_closed_is_lower_loss {
        diagnostics.push(format!(
            "chosen expected loss {chosen_loss} must be lower than rejected {rejected_loss}"
        ));
    }
    for option in &contract.risk_decision.options {
        if option.rationale.is_empty() {
            diagnostics.push(format!("{} is missing rationale", option.option_id));
        }
    }

    errors.extend(diagnostics.iter().cloned());

    SerializationRiskReport {
        decision_id: contract.risk_decision.decision_id.clone(),
        chosen_option: contract.risk_decision.chosen_option.clone(),
        rejected_option: contract.risk_decision.rejected_option.clone(),
        chosen_expected_loss_points: chosen_loss,
        rejected_expected_loss_points: rejected_loss,
        fail_closed_is_lower_loss,
        valid: diagnostics.is_empty(),
        diagnostics,
    }
}

fn required_transition_evaluations(
    contract: &RepairWritebackSerializationContract,
) -> Vec<TransitionEvaluation> {
    [
        ("client_write_in_flight", "repair_writeback_requested"),
        ("client_write_in_flight", "flush_observed"),
        ("repair_lease_held", "repair_symbol_stale"),
        ("repair_lease_held", "fsync_boundary_missing"),
        ("repair_writeback_staged", "writeback_failed"),
        ("repair_writeback_staged", "repair_cancelled"),
    ]
    .into_iter()
    .map(|(from_state, event)| evaluate_transition(contract, from_state, event))
    .collect()
}

fn collect_state_ids(contract: &RepairWritebackSerializationContract) -> BTreeSet<String> {
    contract
        .states
        .iter()
        .map(|state| state.state_id.clone())
        .collect()
}

fn collect_invariant_ids(contract: &RepairWritebackSerializationContract) -> BTreeSet<String> {
    contract
        .invariants
        .iter()
        .map(|invariant| invariant.invariant_id.clone())
        .collect()
}

fn collect_rejection_case_ids(contract: &RepairWritebackSerializationContract) -> BTreeSet<String> {
    contract
        .rejection_cases
        .iter()
        .map(|case| case.case_id.clone())
        .collect()
}

fn collect_identity_guard_ids(contract: &RepairWritebackSerializationContract) -> BTreeSet<String> {
    contract
        .identity_guards
        .iter()
        .map(|guard| guard.guard_id.clone())
        .collect()
}

fn collect_coverage_tags(contract: &RepairWritebackSerializationContract) -> BTreeSet<String> {
    contract
        .scenarios
        .iter()
        .flat_map(|scenario| scenario.coverage_tags.iter().cloned())
        .collect()
}

fn collect_race_coverage_cases(
    contract: &RepairWritebackSerializationContract,
) -> BTreeSet<String> {
    contract
        .race_schedule_manifest
        .schedules
        .iter()
        .filter(|schedule| {
            !matches!(
                schedule.classification.as_str(),
                "quarantined_liveness" | "deferred_long_campaign"
            )
        })
        .map(|schedule| schedule.coverage_case.clone())
        .collect()
}

fn collect_strings(values: &[String]) -> BTreeSet<String> {
    values.iter().cloned().collect()
}

fn collect_schedule_operations(manifest: &RepairRaceScheduleManifest) -> BTreeSet<String> {
    manifest
        .schedules
        .iter()
        .flat_map(|schedule| schedule.operation_trace.iter().cloned())
        .collect()
}

fn collect_duplicate_ids(contract: &RepairWritebackSerializationContract) -> Vec<String> {
    let mut duplicates = BTreeSet::new();
    collect_duplicate_namespace(
        contract.states.iter().map(|state| state.state_id.as_str()),
        &mut duplicates,
    );
    collect_duplicate_namespace(
        contract
            .invariants
            .iter()
            .map(|item| item.invariant_id.as_str()),
        &mut duplicates,
    );
    collect_duplicate_namespace(
        contract
            .transitions
            .iter()
            .map(|item| item.transition_id.as_str()),
        &mut duplicates,
    );
    collect_duplicate_namespace(
        contract
            .rejection_cases
            .iter()
            .map(|item| item.case_id.as_str()),
        &mut duplicates,
    );
    collect_duplicate_namespace(
        contract
            .identity_guards
            .iter()
            .map(|item| item.guard_id.as_str()),
        &mut duplicates,
    );
    collect_duplicate_namespace(
        contract
            .scenarios
            .iter()
            .map(|item| item.scenario_id.as_str()),
        &mut duplicates,
    );
    collect_duplicate_namespace(
        contract
            .follow_up_beads
            .iter()
            .map(|item| item.bead_id.as_str()),
        &mut duplicates,
    );
    collect_duplicate_namespace(
        contract
            .race_schedule_manifest
            .schedules
            .iter()
            .map(|item| item.schedule_id.as_str()),
        &mut duplicates,
    );
    duplicates.into_iter().collect()
}

fn collect_duplicate_namespace<'a>(
    ids: impl Iterator<Item = &'a str>,
    duplicates: &mut BTreeSet<String>,
) {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id.to_owned()) {
            duplicates.insert(id.to_owned());
        }
    }
}

fn missing_required(observed: &BTreeSet<String>, required: &[&str]) -> Vec<String> {
    required
        .iter()
        .filter(|item| !observed.contains(**item))
        .map(|item| (*item).to_owned())
        .collect()
}

fn extend_missing(errors: &mut Vec<String>, prefix: &str, missing: &[String]) {
    errors.extend(missing.iter().map(|item| format!("{prefix}: {item}")));
}

fn is_safe_relative_artifact_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path
            .split('/')
            .any(|component| matches!(component, "" | "." | ".."))
}

fn is_valid_schedule_classification(classification: &str) -> bool {
    matches!(
        classification,
        "accepted"
            | "rejected"
            | "unsupported_interleaving"
            | "quarantined_liveness"
            | "deferred_long_campaign"
    )
}

fn dependency_graph_has_cycle(dependencies: &[ScheduleDependency]) -> bool {
    let mut graph = BTreeMap::<String, Vec<String>>::new();
    for dependency in dependencies {
        graph
            .entry(dependency.before_operation.clone())
            .or_default()
            .push(dependency.after_operation.clone());
        graph.entry(dependency.after_operation.clone()).or_default();
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for node in graph.keys() {
        if dependency_visit_has_cycle(node, &graph, &mut visiting, &mut visited) {
            return true;
        }
    }
    false
}

fn dependency_visit_has_cycle(
    node: &str,
    graph: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) -> bool {
    if visited.contains(node) {
        return false;
    }
    if !visiting.insert(node.to_owned()) {
        return true;
    }
    if let Some(children) = graph.get(node) {
        for child in children {
            if dependency_visit_has_cycle(child, graph, visiting, visited) {
                return true;
            }
        }
    }
    visiting.remove(node);
    visited.insert(node.to_owned());
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_manifest::validate_manifest;

    const CHECKED_IN_CONTRACT: &str =
        include_str!("../../../docs/repair-writeback-serialization-contract.json");
    const ARTIFACT_ROOT: &str = "artifacts/repair-writeback/dry-run";

    fn sample_contract() -> Result<RepairWritebackSerializationContract> {
        serde_json::from_str(CHECKED_IN_CONTRACT).context("checked-in contract parses")
    }

    fn schedule_mut<'a>(
        contract: &'a mut RepairWritebackSerializationContract,
        schedule_id: &str,
    ) -> Result<&'a mut RepairRaceSchedule> {
        contract
            .race_schedule_manifest
            .schedules
            .iter_mut()
            .find(|schedule| schedule.schedule_id == schedule_id)
            .with_context(|| format!("checked-in contract includes schedule {schedule_id}"))
    }

    fn identity_guard_mut<'a>(
        contract: &'a mut RepairWritebackSerializationContract,
        guard_id: &str,
    ) -> Result<&'a mut SerializationIdentityGuard> {
        contract
            .identity_guards
            .iter_mut()
            .find(|guard| guard.guard_id == guard_id)
            .with_context(|| format!("checked-in contract includes identity guard {guard_id}"))
    }

    fn state<'a>(
        contract: &'a RepairWritebackSerializationContract,
        state_id: &str,
    ) -> Result<&'a SerializationState> {
        contract
            .states
            .iter()
            .find(|state| state.state_id == state_id)
            .with_context(|| format!("checked-in contract includes state {state_id}"))
    }

    #[test]
    fn checked_in_contract_validates() -> Result<()> {
        let contract = sample_contract()?;
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.missing_required_states, Vec::<String>::new());
        assert_eq!(report.missing_required_invariants, Vec::<String>::new());
        assert_eq!(report.missing_required_race_coverage, Vec::<String>::new());
        assert_eq!(
            report.missing_required_schedule_log_fields,
            Vec::<String>::new()
        );
        assert_eq!(
            report.missing_required_identity_guards,
            Vec::<String>::new()
        );
        assert_eq!(report.identity_guard_count, REQUIRED_IDENTITY_GUARDS.len());
        assert!(report.risk_report.fail_closed_is_lower_loss);
        Ok(())
    }

    #[test]
    fn render_repair_writeback_serialization_markdown_checked_in_contract_snapshot() -> Result<()> {
        let contract = sample_contract()?;
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(
            report.contract_id,
            "bd-rchk0.1.1-repair-writeback-serialization-v1"
        );
        assert_eq!(report.bead_id, "bd-rchk0.1.1");
        assert_eq!(report.identity_guard_count, REQUIRED_IDENTITY_GUARDS.len());
        assert!(report.risk_report.fail_closed_is_lower_loss);

        let markdown = render_repair_writeback_serialization_markdown(&report);
        insta::assert_snapshot!(
            "render_repair_writeback_serialization_markdown_checked_in_contract",
            markdown
        );
        Ok(())
    }

    #[test]
    fn repair_writeback_serialization_report_json_shape() -> Result<()> {
        let contract = sample_contract()?;
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(
            report.contract_id,
            "bd-rchk0.1.1-repair-writeback-serialization-v1"
        );
        assert_eq!(report.bead_id, "bd-rchk0.1.1");

        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("repair_writeback_serialization_report_json_shape", json);

        let roundtrip: RepairWritebackSerializationReport = serde_json::from_str(&json)?;
        assert_eq!(roundtrip, report);
        Ok(())
    }

    #[test]
    fn model_rejects_repair_writeback_during_client_write() -> Result<()> {
        let contract = sample_contract()?;
        let transition = evaluate_transition(
            &contract,
            "client_write_in_flight",
            "repair_writeback_requested",
        );
        assert!(!transition.allowed);
        assert!(!transition.mutation_allowed);
        assert_eq!(transition.to_state, "repair_writeback_blocked_rw");
        assert_eq!(transition.error_class, "rw_repair_serialization_missing");
        assert!(transition.follow_up_bead.is_some());
        Ok(())
    }

    #[test]
    fn flush_does_not_create_a_durability_or_repair_boundary() -> Result<()> {
        let contract = sample_contract()?;
        let transition = evaluate_transition(&contract, "client_write_in_flight", "flush_observed");
        assert!(!transition.allowed);
        assert!(!transition.mutation_allowed);
        assert_eq!(transition.error_class, "flush_non_durable");
        Ok(())
    }

    #[test]
    fn stale_symbol_is_rejected_before_writeback() -> Result<()> {
        let contract = sample_contract()?;
        let transition = evaluate_transition(&contract, "repair_lease_held", "repair_symbol_stale");
        assert!(!transition.allowed);
        assert!(!transition.mutation_allowed);
        assert_eq!(transition.error_class, "stale_repair_symbol");
        Ok(())
    }

    #[test]
    fn fsync_boundary_missing_rejects_repair_mutation() -> Result<()> {
        let contract = sample_contract()?;
        let transition =
            evaluate_transition(&contract, "repair_lease_held", "fsync_boundary_missing");
        assert!(!transition.allowed);
        assert!(!transition.mutation_allowed);
        assert_eq!(transition.error_class, "dirty_cache_not_fsynced");
        Ok(())
    }

    #[test]
    fn cancellation_goes_to_cleanup_without_mutation() -> Result<()> {
        let contract = sample_contract()?;
        let transition =
            evaluate_transition(&contract, "repair_writeback_staged", "repair_cancelled");
        assert!(transition.allowed);
        assert!(!transition.mutation_allowed);
        assert_eq!(transition.to_state, "cleanup_complete");
        Ok(())
    }

    #[test]
    fn halfway_writeback_failure_blocks_symbol_refresh() -> Result<()> {
        let contract = sample_contract()?;
        let transition =
            evaluate_transition(&contract, "repair_writeback_staged", "writeback_failed");
        assert!(transition.allowed);
        assert!(!transition.mutation_allowed);
        assert_eq!(transition.to_state, "writeback_failure");
        assert_eq!(transition.error_class, "writeback_failure_no_refresh");
        Ok(())
    }

    #[test]
    fn race_schedule_manifest_covers_required_interleavings() -> Result<()> {
        let contract = sample_contract()?;
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(report.valid, "{:?}", report.errors);
        assert!(report.schedule_count >= REQUIRED_RACE_COVERAGE_CASES.len());
        assert_eq!(report.missing_required_race_coverage, [] as [String; 0]);
        assert!(
            report
                .schedule_reports
                .iter()
                .any(|schedule| schedule.classification == "unsupported_interleaving")
        );
        assert!(
            report
                .schedule_reports
                .iter()
                .any(|schedule| schedule.coverage_case == "cancellation_during_decode")
        );
        assert!(
            report
                .schedule_reports
                .iter()
                .any(|schedule| schedule.coverage_case == "cancellation_during_writeback")
        );
        Ok(())
    }

    #[test]
    fn dependency_cycle_in_race_manifest_fails() -> Result<()> {
        let mut contract = sample_contract()?;
        contract
            .race_schedule_manifest
            .operation_dependencies
            .push(ScheduleDependency {
                before_operation: "repair_decode".to_owned(),
                after_operation: "repair_detect_corruption".to_owned(),
                rationale: "synthetic cycle".to_owned(),
            });
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("dependency graph must be acyclic"))
        );
        Ok(())
    }

    #[test]
    fn cancellation_schedule_requires_injection_metadata() -> Result<()> {
        let mut contract = sample_contract()?;
        let schedule = schedule_mut(&mut contract, "rw-repair-race-cancel-decode")?;
        schedule.cancellation_injection = None;
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("requires cancellation_injection"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_interleaving_requires_follow_up() -> Result<()> {
        let mut contract = sample_contract()?;
        let schedule = schedule_mut(&mut contract, "rw-repair-race-unsupported-epoch-rewind")?;
        schedule.follow_up_bead = None;
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("require follow_up_bead"))
        );
        Ok(())
    }

    #[test]
    fn survivor_set_mismatch_fails_for_deterministic_schedule() -> Result<()> {
        let mut contract = sample_contract()?;
        let schedule = schedule_mut(&mut contract, "rw-repair-race-repair-before-write")?;
        schedule
            .observed_survivor_set
            .push("unexpected_block".to_owned());
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("survivor sets must match"))
        );
        Ok(())
    }

    #[test]
    fn missing_identity_guard_is_rejected() -> Result<()> {
        let mut contract = sample_contract()?;
        contract
            .identity_guards
            .retain(|guard| guard.guard_id != "lease_generation_monotonic");
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(!report.valid);
        assert!(
            report
                .missing_required_identity_guards
                .contains(&"lease_generation_monotonic".to_owned())
        );
        Ok(())
    }

    #[test]
    fn identity_guard_must_reject_structural_aba() -> Result<()> {
        let mut contract = sample_contract()?;
        let guard = identity_guard_mut(&mut contract, "epoch_generation_monotonic")?;
        guard.rejects_structural_aba = false;
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("must reject structural ABA reuse"))
        );
        Ok(())
    }

    #[test]
    fn identity_guard_log_fields_must_be_declared() -> Result<()> {
        let mut contract = sample_contract()?;
        let guard = identity_guard_mut(&mut contract, "snapshot_id_mismatch_rejected")?;
        guard
            .required_log_fields
            .push("undeclared_identity".to_owned());
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("undeclared evidence field"))
        );
        Ok(())
    }

    #[test]
    fn invalid_contract_missing_evidence_field_fails() -> Result<()> {
        let mut contract = sample_contract()?;
        contract
            .required_evidence_fields
            .retain(|field| field != "reproduction_command");
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(!report.valid);
        assert!(
            report
                .missing_required_evidence_fields
                .contains(&"reproduction_command".to_owned())
        );
        Ok(())
    }

    #[test]
    fn invalid_unsafe_risk_choice_fails() -> Result<()> {
        let mut contract = sample_contract()?;
        contract.risk_decision.chosen_option = "enable_rw_repair_without_serializer".to_owned();
        contract.risk_decision.rejected_option = "fail_closed_until_unified_serializer".to_owned();
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(!report.valid);
        assert!(!report.risk_report.fail_closed_is_lower_loss);
        Ok(())
    }

    #[test]
    fn duplicate_state_ids_fail() -> Result<()> {
        let mut contract = sample_contract()?;
        let duplicate_state_id = "detection_only_scrub";
        let duplicate_state = state(&contract, duplicate_state_id)?.clone();
        contract.states.push(duplicate_state);
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(!report.valid);
        assert!(
            report
                .duplicate_ids
                .contains(&duplicate_state_id.to_owned())
        );
        Ok(())
    }

    #[test]
    fn sample_artifact_manifest_is_valid() -> Result<()> {
        let contract = sample_contract()?;
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        let manifest = build_repair_writeback_serialization_sample_artifact_manifest(
            &contract,
            ARTIFACT_ROOT,
            &report,
        );
        let errors = validate_manifest(&manifest);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(manifest.gate_id, "repair_writeback_serialization");
        assert_eq!(manifest.bead_id.as_deref(), Some("bd-rchk0.1.1"));
        Ok(())
    }

    #[test]
    fn proof_summary_is_downstream_consumable() -> Result<()> {
        let contract = sample_contract()?;
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        let summary = build_repair_writeback_proof_summary(&contract, &report);
        assert_eq!(
            summary.schema_version,
            REPAIR_WRITEBACK_PROOF_SUMMARY_SCHEMA_VERSION
        );
        assert_eq!(summary.producer_bead_id, "bd-rchk0.1.1.1");
        assert_eq!(summary.source_bead_id, "bd-rchk0.1.1");
        assert!(summary.valid);
        assert!(!summary.safe_to_enable_rw_repair);
        assert_eq!(
            summary.fail_closed_error_class,
            "rw_repair_serialization_missing"
        );
        assert!(
            summary.transition_guards.iter().any(|guard| {
                guard.from_state == "client_write_in_flight"
                    && guard.event == "repair_writeback_requested"
                    && !guard.allowed
                    && !guard.mutation_allowed
                    && guard.error_class == "rw_repair_serialization_missing"
            }),
            "summary must preserve the fail-closed transition guard"
        );
        for bead_id in ["bd-rchk0.1.2", "bd-rchk0.1.3", "bd-rchk0.1.4"] {
            assert!(
                summary
                    .downstream_inputs
                    .iter()
                    .any(|input| input.bead_id == bead_id),
                "missing downstream input for {bead_id}"
            );
        }
        assert!(summary.scenario_inputs.iter().any(|scenario| {
            scenario.scenario_id == "repair_writeback_rw_fail_closed"
                && scenario.proves_no_lost_client_write
                && scenario.preserves_reproduction_data
        }));
        assert!(
            REQUIRED_RACE_COVERAGE_CASES.iter().all(|coverage_case| {
                summary
                    .race_schedule_inputs
                    .iter()
                    .any(|schedule| schedule.coverage_case == *coverage_case)
            }),
            "summary must expose all required race coverage cases"
        );
        assert!(
            REQUIRED_IDENTITY_GUARDS.iter().all(|guard_id| {
                summary
                    .identity_guard_inputs
                    .iter()
                    .any(|guard| guard.guard_id == *guard_id)
            }),
            "summary must expose all required identity guards"
        );
        Ok(())
    }
}
