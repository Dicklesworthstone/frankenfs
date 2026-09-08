#![forbid(unsafe_code)]

//! Inventory of public serialized report schemas emitted by `ffs-harness`.
//!
//! This module is intentionally read-only. It records which durable JSON report
//! contracts already have typed serde round-trip coverage and JSON-shape
//! snapshots, without running permissioned xfstests, mounted mutation, or
//! large-host campaigns.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path};

pub const REPORT_SCHEMA_INVENTORY_SCHEMA_VERSION: u32 = 1;
pub const REPORT_SCHEMA_INVENTORY_ID: &str = "ffs_harness_serialized_report_schema_inventory_v1";
pub const REPORT_SCHEMA_INVENTORY_PRODUCT_EVIDENCE_CLAIM: &str = "none";
pub const REPORT_SCHEMA_INVENTORY_REPRODUCTION_COMMAND: &str = "ffs-ops validate-report-schema-inventory --out artifacts/report-schema-inventory/report.json --summary-out artifacts/report-schema-inventory/report.md";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSchemaInventory {
    pub schema_version: u32,
    pub inventory_id: String,
    pub rows: Vec<ReportSchemaInventoryRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSchemaInventoryRow {
    pub report_id: String,
    pub module_path: String,
    pub rust_type: String,
    pub producer: String,
    pub downstream_consumer: String,
    pub coverage_requirement: ReportSchemaCoverageRequirement,
    pub coverage_status: ReportSchemaCoverageStatus,
    pub evidence_test: String,
    pub snapshot_path: String,
    pub exclusion_reason: String,
    pub claim_effect: ReportSchemaClaimEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportSchemaCoverageRequirement {
    Required,
    AdvisoryOnly,
    PermissionedOnly,
    Excluded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportSchemaCoverageStatus {
    Covered,
    Missing,
    Excluded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportSchemaClaimEffect {
    ProductEvidenceNone,
    AdvisoryOnlyNoPublicReadinessChange,
    ExistingReleaseGateInput,
    InternalOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSchemaInventoryReport {
    pub schema_version: u32,
    pub inventory_id: String,
    pub product_evidence_claim: String,
    pub reproduction_command: String,
    pub valid: bool,
    pub total_rows: usize,
    pub required_rows: usize,
    pub advisory_only_rows: usize,
    pub permissioned_only_rows: usize,
    pub covered_rows: usize,
    pub missing_rows: usize,
    pub excluded_rows: usize,
    pub report_ids: Vec<String>,
    pub uncovered_required_report_ids: Vec<String>,
    pub row_results: Vec<ReportSchemaInventoryRowResult>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSchemaInventoryRowResult {
    pub report_id: String,
    pub module_path: String,
    pub rust_type: String,
    pub downstream_consumer: String,
    pub coverage_requirement: ReportSchemaCoverageRequirement,
    pub coverage_status: ReportSchemaCoverageStatus,
    pub evidence_test: String,
    pub snapshot_path: String,
    pub exclusion_reason: String,
    pub claim_effect: ReportSchemaClaimEffect,
    pub missing_evidence: Vec<String>,
    pub errors: Vec<String>,
}

#[must_use]
pub fn current_report_schema_inventory() -> ReportSchemaInventory {
    let mut rows = advisory_report_rows();
    rows.extend(required_report_rows());
    rows.push(permissioned_campaign_reports_row());
    rows.push(readiness_action_dry_run_metadata_row());

    ReportSchemaInventory {
        schema_version: REPORT_SCHEMA_INVENTORY_SCHEMA_VERSION,
        inventory_id: REPORT_SCHEMA_INVENTORY_ID.to_owned(),
        rows,
    }
}

fn advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    let mut rows = readiness_foundation_advisory_report_rows();
    rows.extend(open_ended_inventory_advisory_report_rows());
    rows.extend(mounted_writeback_advisory_report_rows());
    rows.extend(mounted_write_errno_advisory_report_rows());
    rows.extend(mounted_oracle_recovery_advisory_report_rows());
    rows.extend(adaptive_swarm_advisory_report_rows());
    rows.extend(proof_risk_advisory_report_rows());
    rows.extend(recovery_remediation_advisory_report_rows());
    rows.extend(governance_durability_advisory_report_rows());
    rows.extend(control_plane_contract_advisory_report_rows());
    rows.extend(corpus_and_workload_advisory_report_rows());
    rows.extend(e2e_repro_advisory_report_rows());
    rows.extend(performance_advisory_report_rows());
    rows.extend([
        covered_advisory_row(
            "readiness_lab_numa_p99_replay_report",
            "crates/ffs-harness/src/readiness_lab.rs",
            "ReadinessLabNumaP99ReplayReport",
            "readiness-lab NUMA/p99 replay",
            "large-host swarm responsiveness advisory replay lane",
            "readiness_lab_numa_p99_replay_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__readiness_lab__tests__readiness_lab_numa_p99_replay_report_json_shape.snap",
        ),
        covered_advisory_row(
            "readiness_action_autopilot_source_reports",
            "tools/ffs-ops/src/readiness_action_autopilot.rs",
            "Vec<ReadinessActionAutopilotReport>",
            "readiness-action source fixture planner",
            "readiness-action dry-run planner",
            "readiness_action_autopilot_report_json_shape",
            "tools/ffs-ops/src/snapshots/ffs_harness__readiness_action_autopilot__tests__readiness_action_autopilot_report_json_shape.snap",
        ),
        covered_advisory_row(
            "readiness_action_planning_result",
            "tools/ffs-ops/src/readiness_action_autopilot.rs",
            "ReadinessActionPlanningResult",
            "plan_readiness_actions",
            "readiness-action dry-run and operator action selection",
            "readiness_action_planner_result_order_stable",
            "tools/ffs-ops/src/snapshots/ffs_harness__readiness_action_autopilot__tests__readiness_action_planner_result_order_stable.snap",
        ),
        covered_advisory_row(
            "readiness_action_dry_run_report",
            "tools/ffs-ops/src/readiness_action_autopilot.rs",
            "ReadinessActionDryRunReport",
            "recommend-readiness-actions",
            "readiness-action operator dry-run handoff",
            "readiness_action_dry_run_json_report",
            "tools/ffs-ops/src/snapshots/ffs_harness__readiness_action_autopilot__tests__readiness_action_dry_run_json_report.snap",
        ),
    ]);
    rows
}

fn readiness_foundation_advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    let mut rows = vec![
        covered_advisory_row(
            "readiness_lab_validation_report",
            "crates/ffs-harness/src/readiness_lab.rs",
            "ReadinessLabValidationReport",
            "validate-readiness-lab-contracts",
            "readiness-lab advisory contracts and dashboard rows",
            "readiness_lab_validation_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__readiness_lab__tests__readiness_lab_validation_report_json_shape.snap",
        ),
        covered_advisory_row(
            "readiness_lab_rch_lane_schedule_report",
            "crates/ffs-harness/src/readiness_lab.rs",
            "ReadinessLabRchLaneScheduleReport",
            "plan-readiness-lab-rch-lanes",
            "readiness-lab RCH dry-run scheduler",
            "readiness_lab_rch_lane_schedule_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__readiness_lab__tests__readiness_lab_rch_lane_schedule_report_json_shape.snap",
        ),
        covered_advisory_row(
            "readiness_lab_host_simulation_report",
            "crates/ffs-harness/src/readiness_lab.rs",
            "ReadinessLabHostSimulationReport",
            "simulate-readiness-lab-hosts",
            "readiness-lab advisory host-capability handoff",
            "readiness_lab_host_simulation_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__readiness_lab__tests__readiness_lab_host_simulation_report_json_shape.snap",
        ),
        covered_advisory_row(
            "readiness_lab_truth_graph_report",
            "crates/ffs-harness/src/readiness_lab.rs",
            "ReadinessLabTruthGraphReport",
            "build-readiness-lab-truth-graph",
            "readiness-lab advisory evidence graph",
            "readiness_lab_truth_graph_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__readiness_lab__tests__readiness_lab_truth_graph_report_json_shape.snap",
        ),
        covered_advisory_row(
            "tracker_source_hygiene_report",
            "crates/ffs-harness/src/tracker_source_hygiene.rs",
            "TrackerSourceHygieneReport",
            "validate-tracker-source-hygiene",
            "source-aware tracker queue state and local graph exports",
            "tracker_source_hygiene_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__tracker_source_hygiene__tests__tracker_source_hygiene_report_json_shape.snap",
        ),
        covered_advisory_row(
            "agent_mail_reservation_snapshot_report",
            "crates/ffs-harness/src/tracker_source_hygiene.rs",
            "AgentMailReservationSnapshotReport",
            "analyze_agent_mail_reservation_snapshot_json",
            "source-aware tracker reservation conflict diagnostics",
            "agent_mail_reservation_snapshot_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__tracker_source_hygiene__tests__agent_mail_reservation_snapshot_report_json_shape.snap",
        ),
        covered_advisory_row(
            "claimability_plan_report",
            "crates/ffs-harness/src/claimability_plan.rs",
            "ClaimabilityPlanReport",
            "claimability-plan",
            "source-aware queue guidance and Agent Mail reservation handoff",
            "claimability_plan_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__claimability_plan__tests__claimability_plan_report_json_shape.snap",
        ),
    ];
    rows.extend(rch_capacity_preflight_report_rows());
    rows.extend([
        covered_advisory_row(
            "low_privilege_demo_report",
            "crates/ffs-harness/src/low_privilege_demo.rs",
            "LowPrivilegeDemoReport",
            "validate-low-privilege-demo",
            "non-permissioned low-privilege demo manifest validation",
            "low_privilege_demo_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__low_privilege_demo__tests__low_privilege_demo_report_json_shape.snap",
        ),
        covered_advisory_row(
            "swarm_operator_validation_report",
            "crates/ffs-harness/src/swarm_operator_report.rs",
            "SwarmOperatorValidationReport",
            "validate-swarm-operator-report",
            "swarm operator report CLI validation and E2E proof handoff",
            "swarm_operator_validation_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__swarm_operator_report__tests__swarm_operator_validation_report_json_shape.snap",
        ),
        covered_advisory_row(
            "readiness_action_fixture_validation_report",
            "tools/ffs-ops/src/readiness_action_autopilot.rs",
            "ReadinessActionFixtureValidationReport",
            "validate_readiness_action_fixture_set",
            "readiness-action planner fixture validation and dry-run recommendation coverage",
            "readiness_action_fixture_validation_report_json_shape",
            "tools/ffs-ops/src/snapshots/ffs_harness__readiness_action_autopilot__tests__readiness_action_fixture_validation_report_json_shape.snap",
        ),
    ]);
    rows
}

fn rch_capacity_preflight_report_rows() -> Vec<ReportSchemaInventoryRow> {
    vec![
        covered_advisory_row(
            "rch_capacity_preflight_report",
            "crates/ffs-harness/src/rch_capacity_preflight.rs",
            "RchCapacityPreflightReport",
            "ffs_rch_capacity_preflight_e2e.sh",
            "RCH capacity outage gating and proof-handoff diagnostics",
            "rch_capacity_preflight_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__rch_capacity_preflight__tests__rch_capacity_preflight_report_json_shape.snap",
        ),
        covered_advisory_row(
            "rch_capacity_preflight_validation_report",
            "crates/ffs-harness/src/rch_capacity_preflight.rs",
            "RchCapacityPreflightValidationReport",
            "validate-rch-capacity-preflight",
            "RCH capacity outage gating and proof-handoff diagnostics",
            "rch_capacity_preflight_validation_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__rch_capacity_preflight__tests__rch_capacity_preflight_validation_report_json_shape.snap",
        ),
    ]
}

fn open_ended_inventory_advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    vec![
        covered_advisory_row(
            "open_ended_inventory_report",
            "tools/ffs-ops/src/open_ended_inventory.rs",
            "OpenEndedInventoryReport",
            "validate-open-ended-inventory",
            "open-ended fuzz and conformance inventory gate",
            "open_ended_inventory_report_json_shape",
            "tools/ffs-ops/src/snapshots/ffs_harness__open_ended_inventory__tests__open_ended_inventory_report_json_shape.snap",
        ),
        covered_advisory_row(
            "open_ended_note_scan_report",
            "tools/ffs-ops/src/open_ended_inventory.rs",
            "OpenEndedNoteScanReport",
            "open-ended-note-scanner",
            "open-ended note scanner operator handoff",
            "open_ended_note_scan_report_json_shape",
            "tools/ffs-ops/src/snapshots/ffs_harness__open_ended_inventory__tests__open_ended_note_scan_report_json_shape.snap",
        ),
        covered_advisory_row(
            "source_scope_manifest_report",
            "tools/ffs-ops/src/open_ended_inventory.rs",
            "SourceScopeManifestReport",
            "validate-source-scope-manifest",
            "source-scope manifest validation gate",
            "source_scope_manifest_report_json_shape",
            "tools/ffs-ops/src/snapshots/ffs_harness__open_ended_inventory__tests__source_scope_manifest_report_json_shape.snap",
        ),
        covered_advisory_row(
            "source_scope_scan_report",
            "tools/ffs-ops/src/open_ended_inventory.rs",
            "SourceScopeScanReport",
            "validate-source-scope-manifest",
            "source-scope workspace scan and dirty-workspace diagnostics",
            "source_scope_scan_report_json_shape",
            "tools/ffs-ops/src/snapshots/ffs_harness__open_ended_inventory__tests__source_scope_scan_report_json_shape.snap",
        ),
    ]
}

fn mounted_writeback_advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    let mut rows = vec![
        rch_proof_ledger_report_row(),
        covered_advisory_row(
            "fuse_capability_report",
            "crates/ffs-harness/src/verification_runner.rs",
            "FuseCapabilityProbeReport",
            "fuse-capability-probe",
            "mounted FUSE capability and skip/fail diagnostics",
            "fuse_capability_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__verification_runner__tests__fuse_capability_report_json_shape.snap",
        ),
    ];
    rows.extend(mounted_lane_gate_report_rows());
    rows.extend([
        covered_advisory_row(
            "mounted_repair_policy_report",
            "crates/ffs-harness/src/mounted_repair_policy.rs",
            "MountedRepairPolicyReport",
            "validate_default_mounted_repair_policy",
            "mounted repair policy fixture validation",
            "mounted_repair_policy_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__mounted_repair_policy__tests__mounted_repair_policy_report_json_shape.snap",
        ),
        covered_advisory_row(
            "mounted_repair_mutation_boundary_report",
            "crates/ffs-harness/src/mounted_repair_mutation_boundary.rs",
            "MountedRepairMutationBoundaryReport",
            "validate-mounted-repair-mutation-boundary",
            "mounted repair mutation boundary validator",
            "mounted_repair_mutation_boundary_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__mounted_repair_mutation_boundary__tests__mounted_repair_mutation_boundary_report_json_shape.snap",
        ),
        covered_advisory_row(
            "mounted_write_matrix_report",
            "crates/ffs-harness/src/mounted_write_matrix.rs",
            "MountedWriteMatrixReport",
            "validate-mounted-write-matrix",
            "mounted write matrix validator",
            "mounted_write_matrix_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__mounted_write_matrix__tests__mounted_write_matrix_report_json_shape.snap",
        ),
        covered_advisory_row(
            "mounted_write_error_report",
            "crates/ffs-harness/src/mounted_write_error_classes.rs",
            "MountedWriteErrorReport",
            "validate-mounted-write-error-classes",
            "mounted write error-class catalog validator",
            "mounted_write_error_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__mounted_write_error_classes__tests__mounted_write_error_report_json_shape.snap",
        ),
        covered_advisory_row(
            "repair_writeback_serialization_report",
            "crates/ffs-harness/src/repair_writeback_serialization.rs",
            "RepairWritebackSerializationReport",
            "validate-repair-writeback-serialization",
            "read-write repair serialization contract validator",
            "repair_writeback_serialization_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__repair_writeback_serialization__tests__repair_writeback_serialization_report_json_shape.snap",
        ),
        rw_background_repair_gate_report_row(),
        covered_advisory_row(
            "writeback_cache_audit_report",
            "crates/ffs-harness/src/writeback_cache_audit.rs",
            "WritebackCacheAuditReport",
            "validate-writeback-cache-audit",
            "writeback-cache acceptance gate validator",
            "writeback_cache_audit_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__writeback_cache_audit__tests__writeback_cache_audit_report_json_shape.snap",
        ),
        covered_advisory_row(
            "writeback_ordering_report",
            "crates/ffs-harness/src/writeback_cache_audit.rs",
            "WritebackOrderingReport",
            "validate-writeback-cache-ordering",
            "writeback-cache ordering oracle validator",
            "writeback_ordering_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__writeback_cache_audit__tests__writeback_ordering_report_json_shape.snap",
        ),
        covered_advisory_row(
            "writeback_crash_replay_report",
            "crates/ffs-harness/src/writeback_cache_audit.rs",
            "WritebackCrashReplayReport",
            "validate-writeback-cache-crash-replay",
            "writeback-cache crash/replay oracle validator",
            "writeback_crash_replay_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__writeback_cache_audit__tests__writeback_crash_replay_report_json_shape.snap",
        ),
    ]);
    rows
}

fn mounted_lane_gate_report_rows() -> Vec<ReportSchemaInventoryRow> {
    vec![
        covered_advisory_row(
            "mounted_lane_decision",
            "crates/ffs-harness/src/mounted_lane_gate.rs",
            "MountedLaneDecision",
            "mounted lane fail-closed gate evaluator",
            "mounted FUSE lane skip/fail/pass decision gate",
            "mounted_lane_decision_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__mounted_lane_gate__tests__mounted_lane_decision_json_shape.snap",
        ),
        covered_advisory_row(
            "mounted_lane_gate",
            "crates/ffs-harness/src/mounted_lane_gate.rs",
            "MountedLaneGate",
            "mounted lane fail-closed gate evaluator",
            "mounted matrix permissioned-lane fail-closed gate input",
            "mounted_lane_gate_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__mounted_lane_gate__tests__mounted_lane_gate_json_shape.snap",
        ),
    ]
}

fn rw_background_repair_gate_report_row() -> ReportSchemaInventoryRow {
    covered_advisory_row(
        "rw_background_repair_gate",
        "crates/ffs-harness/src/rw_background_repair_gate.rs",
        "RwBackgroundRepairGate",
        "evaluate_rw_background_repair_gate",
        "rw background-repair opt-in gate and fail-closed operator workflow",
        "happy_gate_json_shape",
        "crates/ffs-harness/src/snapshots/ffs_harness__rw_background_repair_gate__tests__happy_gate_json_shape.snap",
    )
}

fn rch_proof_ledger_report_row() -> ReportSchemaInventoryRow {
    covered_advisory_row(
        "rch_proof_ledger_report",
        "crates/ffs-harness/src/verification_runner.rs",
        "RchProofLedgerReport",
        "rch-proof-ledger",
        "remote RCH proof preservation and readiness action autopilot degraded-proof decisions",
        "rch_proof_ledger_report_json_shape",
        "crates/ffs-harness/src/snapshots/ffs_harness__verification_runner__tests__rch_proof_ledger_report_json_shape.snap",
    )
}

fn mounted_write_errno_advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    vec![covered_advisory_row(
        "mounted_write_errno_budget_report",
        "crates/ffs-harness/src/mounted_write_errno_budget.rs",
        "MountedWriteErrnoBudgetReport",
        "validate_default_mounted_write_errno_budget",
        "mounted write errno parity budget and broad-fallback follow-up gating",
        "default_budget_report_json_shape",
        "crates/ffs-harness/src/snapshots/ffs_harness__mounted_write_errno_budget__tests__default_budget_report_json_shape.snap",
    )]
}

fn mounted_oracle_recovery_advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    vec![
        covered_advisory_row(
            "mounted_checkpoint_survivor_report",
            "crates/ffs-harness/src/mounted_checkpoint_survivor.rs",
            "MountedCheckpointSurvivorReport",
            "validate-mounted-checkpoint-survivor",
            "mounted checkpoint survivor validator",
            "mounted_checkpoint_survivor_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__mounted_checkpoint_survivor__tests__mounted_checkpoint_survivor_report_json_shape.snap",
        ),
        covered_advisory_row(
            "mounted_differential_validation_report",
            "crates/ffs-harness/src/mounted_differential_oracle.rs",
            "MountedDifferentialValidationReport",
            "validate-mounted-differential-oracle",
            "mounted differential oracle validation report",
            "mounted_differential_validation_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__mounted_differential_oracle__tests__mounted_differential_validation_report_json_shape.snap",
        ),
        covered_advisory_row(
            "mounted_recovery_matrix_report",
            "crates/ffs-harness/src/mounted_recovery_matrix.rs",
            "MountedRecoveryMatrixReport",
            "validate-mounted-recovery-matrix",
            "mounted recovery matrix validator",
            "mounted_recovery_matrix_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__mounted_recovery_matrix__tests__mounted_recovery_matrix_report_json_shape.snap",
        ),
    ]
}

fn adaptive_swarm_advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    vec![
        covered_advisory_row(
            "adaptive_runtime_evidence_report",
            "crates/ffs-harness/src/adaptive_runtime_manifest.rs",
            "AdaptiveRuntimeEvidenceReport",
            "validate-adaptive-runtime-manifest",
            "adaptive runtime evidence manifest validator",
            "adaptive_runtime_evidence_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__adaptive_runtime_manifest__tests__adaptive_runtime_evidence_report_json_shape.snap",
        ),
        covered_advisory_row(
            "adaptive_runtime_runner_report",
            "crates/ffs-harness/src/adaptive_runtime_manifest.rs",
            "AdaptiveRuntimeRunnerReport",
            "adaptive-runtime-runner",
            "adaptive runtime dry-run and capability probe runner",
            "adaptive_runtime_runner_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__adaptive_runtime_manifest__tests__adaptive_runtime_runner_report_json_shape.snap",
        ),
        covered_advisory_row(
            "runtime_console_report",
            "crates/ffs-harness/src/runtime_console_report.rs",
            "RuntimeConsoleReport + RuntimeConsoleValidationReport",
            "validate_runtime_console_report",
            "managed/per-core mount runtime console artifact contract",
            "runtime_console_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__runtime_console_report__tests__runtime_console_report_json_shape.snap",
        ),
        covered_advisory_row(
            "numa_allocation_placement_report",
            "crates/ffs-harness/src/numa_allocation_placement_report.rs",
            "NumaAllocationPlacementReport + NumaPlacementValidationReport",
            "validate-numa-allocation-placement",
            "NUMA allocation placement replay/p99 evidence contract",
            "numa_allocation_placement_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__numa_allocation_placement_report__tests__numa_allocation_placement_report_json_shape.snap",
        ),
        covered_advisory_row(
            "topology_runtime_advisor_report",
            "crates/ffs-harness/src/topology_runtime_advisor.rs",
            "TopologyRuntimeAdvisorReport",
            "validate-topology-runtime-advisor",
            "topology runtime advisor manifest validator",
            "topology_runtime_advisor_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__topology_runtime_advisor__tests__topology_runtime_advisor_report_json_shape.snap",
        ),
        covered_advisory_row(
            "topology_runtime_advisor_scoring_report",
            "crates/ffs-harness/src/topology_runtime_advisor.rs",
            "TopologyRuntimeAdvisorScoringReport",
            "score-topology-runtime-advisor",
            "topology runtime advisor scoring gate",
            "topology_runtime_advisor_scoring_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__topology_runtime_advisor__tests__topology_runtime_advisor_scoring_report_json_shape.snap",
        ),
        covered_advisory_row(
            "swarm_cache_controller_report",
            "crates/ffs-harness/src/swarm_cache_controller.rs",
            "SwarmCacheValidationReport",
            "validate-swarm-cache-controller",
            "swarm cache controller contract validator",
            "swarm_cache_controller_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__swarm_cache_controller__tests__swarm_cache_controller_report_json_shape.snap",
        ),
        covered_advisory_row(
            "swarm_tail_latency_report",
            "crates/ffs-harness/src/swarm_tail_latency.rs",
            "SwarmTailLatencyReport",
            "validate-swarm-tail-latency",
            "large-host swarm tail latency evidence validator",
            "swarm_tail_latency_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__swarm_tail_latency__tests__swarm_tail_latency_report_json_shape.snap",
        ),
    ]
}

fn proof_risk_advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    vec![
        covered_advisory_row(
            "adversarial_threat_model_report",
            "crates/ffs-harness/src/adversarial_threat_model.rs",
            "AdversarialThreatModelReport",
            "validate-adversarial-threat-model",
            "hostile-image safety threat model validator",
            "adversarial_threat_model_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__adversarial_threat_model__tests__adversarial_threat_model_report_json_shape.snap",
        ),
        covered_advisory_row(
            "ambition_evidence_matrix_report",
            "tools/ffs-ops/src/ambition_evidence_matrix.rs",
            "AmbitionEvidenceMatrixReport",
            "validate-ambition-evidence-matrix",
            "ambition evidence matrix validator",
            "ambition_evidence_matrix_report_json_shape",
            "tools/ffs-ops/src/snapshots/ffs_harness__ambition_evidence_matrix__tests__ambition_evidence_matrix_report_json_shape.snap",
        ),
        covered_advisory_row(
            "cross_oracle_arbitration_report",
            "crates/ffs-harness/src/cross_oracle_arbitration.rs",
            "CrossOracleArbitrationReport",
            "validate-cross-oracle-arbitration",
            "cross-oracle arbitration proof-bundle input",
            "cross_oracle_arbitration_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__cross_oracle_arbitration__tests__cross_oracle_arbitration_report_json_shape.snap",
        ),
        covered_advisory_row(
            "cross_oracle_arbitration_validation_report",
            "crates/ffs-harness/src/cross_oracle_arbitration.rs",
            "CrossOracleArbitrationValidationReport",
            "validate-cross-oracle-arbitration",
            "cross-oracle arbitration validation gate",
            "cross_oracle_arbitration_validation_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__cross_oracle_arbitration__tests__cross_oracle_arbitration_validation_report_json_shape.snap",
        ),
        covered_advisory_row(
            "invariant_oracle_consumer_report",
            "crates/ffs-harness/src/invariant_oracle.rs",
            "InvariantOracleConsumerReport",
            "validate-invariant-oracle --report",
            "invariant oracle proof-bundle consumer validation",
            "invariant_oracle_consumer_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__invariant_oracle__tests__invariant_oracle_consumer_report_json_shape.snap",
        ),
        covered_advisory_row(
            "invariant_oracle_report",
            "crates/ffs-harness/src/invariant_oracle.rs",
            "InvariantOracleReport",
            "validate-invariant-oracle",
            "invariant oracle trace validator",
            "invariant_oracle_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__invariant_oracle__tests__invariant_oracle_report_json_shape.snap",
        ),
        covered_advisory_row(
            "proof_overhead_budget_report",
            "crates/ffs-harness/src/proof_overhead_budget.rs",
            "ProofOverheadBudgetReport",
            "validate-proof-overhead-budget",
            "proof overhead budget validator",
            "proof_overhead_budget_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__proof_overhead_budget__tests__proof_overhead_budget_report_json_shape.snap",
        ),
    ]
}

fn recovery_remediation_advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    vec![
        covered_advisory_row(
            "operator_recovery_drill_report",
            "crates/ffs-harness/src/operator_recovery_drill.rs",
            "OperatorRecoveryDrillReport",
            "validate-operator-recovery-drill",
            "operator recovery drill validator",
            "operator_recovery_drill_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__operator_recovery_drill__tests__operator_recovery_drill_report_json_shape.snap",
        ),
        covered_advisory_row(
            "tabletop_drill_canonical_drills",
            "crates/ffs-harness/src/tabletop_drill.rs",
            "Vec<DrillScenario>",
            "canonical_drills",
            "operator tooling gate and tabletop drill E2E catalog",
            "canonical_drills_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__tabletop_drill__tests__canonical_drills_json_shape.snap",
        ),
        covered_advisory_row(
            "tabletop_drill_result",
            "crates/ffs-harness/src/tabletop_drill.rs",
            "Vec<DrillResult>",
            "execute_all_drills",
            "operator tabletop drill remediation-gap tracker and E2E gates",
            "drill_result_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__tabletop_drill__tests__drill_result_json_shape.snap",
        ),
        covered_advisory_row(
            "remediation_catalog_report",
            "crates/ffs-harness/src/remediation_catalog.rs",
            "RemediationCatalogReport",
            "validate-remediation-catalog",
            "remediation catalog validator",
            "remediation_catalog_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__remediation_catalog__tests__remediation_catalog_report_json_shape.snap",
        ),
        covered_advisory_row(
            "remediation_severity_gate_report",
            "crates/ffs-harness/src/remediation_severity_gate.rs",
            "RemediationSeverityGateReport",
            "validate-remediation-severity-gate",
            "remediation severity gate validator",
            "remediation_severity_gate_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__remediation_severity_gate__tests__remediation_severity_gate_report_json_shape.snap",
        ),
        covered_advisory_row(
            "repair_confidence_lab_report",
            "crates/ffs-harness/src/repair_confidence_lab.rs",
            "RepairConfidenceLabReport",
            "validate-repair-confidence-lab",
            "repair confidence lab validator",
            "repair_confidence_lab_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__repair_confidence_lab__tests__repair_confidence_lab_report_json_shape.snap",
        ),
        covered_advisory_row(
            "scrub_repair_scheduler_report",
            "crates/ffs-harness/src/scrub_repair_scheduler.rs",
            "ScrubRepairSchedulerReport",
            "validate-scrub-repair-scheduler",
            "scrub repair scheduler manifest validator",
            "scrub_repair_scheduler_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__scrub_repair_scheduler__tests__scrub_repair_scheduler_report_json_shape.snap",
        ),
        covered_advisory_row(
            "support_state_accounting_report",
            "crates/ffs-harness/src/support_state_accounting.rs",
            "SupportStateAccountingReport",
            "validate-support-state-accounting",
            "support-state accounting validator",
            "support_state_accounting_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__support_state_accounting__tests__support_state_accounting_report_json_shape.snap",
        ),
    ]
}

fn governance_durability_advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    let mut rows = vec![
        covered_advisory_row(
            "chaos_replay_lab_report",
            "crates/ffs-harness/src/chaos_replay_lab.rs",
            "ChaosReplayLabReport",
            "validate-chaos-replay-lab",
            "chaos replay lab validator",
            "chaos_replay_lab_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__chaos_replay_lab__tests__chaos_replay_lab_report_json_shape.snap",
        ),
        covered_advisory_row(
            "deferred_parity_audit_report",
            "crates/ffs-harness/src/deferred_parity_audit.rs",
            "DeferredParityAuditReport",
            "validate-deferred-parity-audit",
            "deferred parity audit validator",
            "deferred_parity_audit_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__deferred_parity_audit__tests__deferred_parity_audit_report_json_shape.snap",
        ),
        covered_advisory_row(
            "deferred_parity_audit_gap_classes",
            "crates/ffs-harness/src/deferred_parity_audit.rs",
            "[&str; 20]",
            "GAP_CLASSES",
            "deferred parity audit classifier and release-gate downgrade policy",
            "gap_classes_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__deferred_parity_audit__tests__gap_classes_json_shape.snap",
        ),
        covered_advisory_row(
            "docs_status_drift_report",
            "tools/ffs-ops/src/docs_status_drift.rs",
            "DocsStatusDriftReport",
            "validate-docs-status-drift",
            "docs/status drift validator",
            "docs_status_drift_report_json_shape",
            "tools/ffs-ops/src/snapshots/ffs_harness__docs_status_drift__tests__docs_status_drift_report_json_shape.snap",
        ),
        covered_advisory_row(
            "operational_evidence_index",
            "crates/ffs-harness/src/operational_evidence_index.rs",
            "OperationalEvidenceIndex",
            "operational-evidence-index",
            "readiness dashboard latest-truth aggregation and operator handoff",
            "operational_evidence_index_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__operational_evidence_index__tests__operational_evidence_index_json_shape.snap",
        ),
    ];

    rows.extend(governance_durability_decision_advisory_report_rows());
    rows.extend([
        covered_advisory_row(
            "inventory_closeout_gate_report",
            "crates/ffs-harness/src/inventory_closeout_gate.rs",
            "InventoryCloseoutReport",
            "validate-inventory-closeout-gate",
            "inventory closeout gate validator",
            "inventory_closeout_gate_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__inventory_closeout_gate__tests__inventory_closeout_gate_report_json_shape.snap",
        ),
        covered_advisory_row(
            "low_privilege_demo_sandbox_report",
            "crates/ffs-harness/src/low_privilege_demo_sandbox.rs",
            "LowPrivilegeDemoSandboxReport",
            "validate-low-privilege-demo-sandbox",
            "low-privilege demo sandbox validator",
            "low_privilege_demo_sandbox_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__low_privilege_demo_sandbox__tests__low_privilege_demo_sandbox_report_json_shape.snap",
        ),
        covered_advisory_row(
            "soak_canary_campaign_report",
            "crates/ffs-harness/src/soak_canary_campaign.rs",
            "SoakCanaryCampaignReport",
            "validate-soak-canary-campaigns",
            "endurance and canary campaign proof-bundle/release-gate consumers",
            "soak_canary_campaign_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__soak_canary_campaign__tests__soak_canary_campaign_report_json_shape.snap",
        ),
        covered_advisory_row(
            "wal_group_commit_gate_report",
            "crates/ffs-harness/src/wal_group_commit_gate.rs",
            "WalGroupCommitGateReport",
            "validate-wal-group-commit-gate",
            "WAL group commit gate validator",
            "wal_group_commit_gate_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__wal_group_commit_gate__tests__wal_group_commit_gate_report_json_shape.snap",
        ),
    ]);

    rows
}

fn governance_durability_decision_advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    vec![
        covered_advisory_row(
            "oq_decision_matrix_canonical_matrix",
            "crates/ffs-harness/src/oq_decision_matrix.rs",
            "Vec<OqDecision>",
            "canonical_matrix",
            "OQ decision integration gate and program-gate decision capture",
            "canonical_matrix_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__oq_decision_matrix__tests__canonical_matrix_json_shape.snap",
        ),
        covered_advisory_row(
            "xfstests_baseline_manifest",
            "crates/ffs-harness/src/xfstests.rs",
            "XfstestsBaselineManifest",
            "xfstests-baseline-manifest",
            "xfstests baseline dry-run evidence and failure triage input",
            "xfstests_baseline_manifest_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__xfstests__tests__xfstests_baseline_manifest_json_shape.snap",
        ),
        covered_advisory_row(
            "xfstests_failure_triage_report",
            "crates/ffs-harness/src/xfstests.rs",
            "XfstestsFailureTriageReport",
            "xfstests-failure-triage",
            "xfstests product-failure triage and follow-up bead extraction",
            "xfstests_failure_triage_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__xfstests__tests__xfstests_failure_triage_report_json_shape.snap",
        ),
    ]
}

fn control_plane_contract_advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    vec![
        covered_advisory_row(
            "artifact_schema_fixture_report",
            "crates/ffs-harness/src/artifact_manifest.rs",
            "ArtifactSchemaFixtureReport",
            "validate-artifact-schema-fixtures",
            "artifact manifest fixture suite and proof-bundle schema guard",
            "artifact_schema_fixture_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__artifact_manifest__tests__artifact_schema_fixture_report_json_shape.snap",
        ),
        covered_advisory_row(
            "btrfs_capability_drift_contract",
            "crates/ffs-harness/src/btrfs_capability_drift.rs",
            "Vec<CapabilityContractRow> + Vec<DriftCheckResult>",
            "btrfs capability drift detector",
            "FEATURE_PARITY btrfs experimental RW contract drift guard",
            "btrfs_capability_drift_contract_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__btrfs_capability_drift__tests__btrfs_capability_drift_contract_json_shape.snap",
        ),
        covered_advisory_row(
            "canonical_error_scenarios",
            "crates/ffs-harness/src/error_taxonomy.rs",
            "Vec<ErrorScenario>",
            "canonical error taxonomy",
            "operator error remediation and runbook taxonomy",
            "canonical_error_scenarios_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__error_taxonomy__tests__canonical_error_scenarios_json_shape.snap",
        ),
        covered_advisory_row(
            "consistency_verdict",
            "crates/ffs-harness/src/health_consistency.rs",
            "ConsistencyVerdict",
            "health consistency validator",
            "CLI/TUI/log health surface drift guard",
            "consistency_verdict_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__health_consistency__tests__consistency_verdict_json_shape.snap",
        ),
        covered_advisory_row(
            "benchmark_taxonomy",
            "crates/ffs-harness/src/benchmark_taxonomy.rs",
            "Taxonomy",
            "canonical benchmark taxonomy",
            "performance regression taxonomy and benchmark coverage gates",
            "canonical_taxonomy_json_snapshot",
            "crates/ffs-harness/src/snapshots/ffs_harness__benchmark_taxonomy__tests__canonical_taxonomy_v1.snap",
        ),
        covered_advisory_row(
            "metrics_snapshot",
            "crates/ffs-harness/src/metrics.rs",
            "MetricsSnapshot",
            "metrics registry snapshot",
            "runtime metrics JSON export",
            "snapshot_json_serialization_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__metrics__tests__snapshot_json_serialization_shape.snap",
        ),
        covered_advisory_row(
            "promotion_result",
            "crates/ffs-harness/src/crash_promotion.rs",
            "PromotionResult",
            "crash promotion pipeline",
            "fuzz crash regression promotion handoff",
            "promotion_result_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__crash_promotion__tests__promotion_result_json_shape.snap",
        ),
        covered_advisory_row(
            "structured_log_contract",
            "crates/ffs-harness/src/log_contract.rs",
            "Structured log contract constants",
            "structured log contract",
            "E2E scenario markers and operator log consumers",
            "structured_log_contract_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__log_contract__tests__structured_log_contract_json_shape.snap",
        ),
    ]
}

fn corpus_and_workload_advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    let mut rows = vec![covered_advisory_row(
        "fault_injection_corpus_report",
        "crates/ffs-harness/src/fault_injection_corpus.rs",
        "FaultInjectionCorpusReport",
        "validate-fault-injection-corpus",
        "repair confidence and fault coverage corpus gates",
        "fault_injection_corpus_report_json_shape",
        "crates/ffs-harness/src/snapshots/ffs_harness__fault_injection_corpus__tests__fault_injection_corpus_report_json_shape.snap",
    )];

    rows.extend(fuzz_dashboard_advisory_report_rows());
    rows.extend([
        covered_advisory_row(
            "fuzz_smoke_report",
            "crates/ffs-harness/src/fuzz_smoke.rs",
            "FuzzSmokeReport",
            "validate-fuzz-smoke",
            "fuzz target smoke validation and CI dashboard gates",
            "fuzz_smoke_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__fuzz_smoke__tests__fuzz_smoke_report_json_shape.snap",
        ),
        covered_advisory_row(
            "btrfs_send_receive_corpus_report",
            "crates/ffs-harness/src/btrfs_send_receive_corpus.rs",
            "BtrfsSendReceiveCorpusReport",
            "validate-btrfs-send-receive-corpus",
            "btrfs send/receive parser and refusal corpus gates",
            "btrfs_send_receive_corpus_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__btrfs_send_receive_corpus__tests__btrfs_send_receive_corpus_report_json_shape.snap",
        ),
        covered_advisory_row(
            "btrfs_multidev_corpus_report",
            "crates/ffs-harness/src/btrfs_multidevice_corpus.rs",
            "BtrfsMultidevCorpusReport",
            "validate-btrfs-multidevice-corpus",
            "btrfs multi-device profile and scrub/repair corpus gates",
            "btrfs_multidev_corpus_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__btrfs_multidevice_corpus__tests__btrfs_multidev_corpus_report_json_shape.snap",
        ),
        covered_advisory_row(
            "casefold_corpus_report",
            "crates/ffs-harness/src/casefold_corpus.rs",
            "CasefoldCorpusReport",
            "validate-casefold-corpus",
            "ext4 casefold lookup/create/rename corpus gates",
            "casefold_corpus_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__casefold_corpus__tests__casefold_corpus_report_json_shape.snap",
        ),
        covered_advisory_row(
            "repair_corpus_report",
            "crates/ffs-harness/src/repair_corpus.rs",
            "RepairCorpusReport",
            "validate-repair-corpus",
            "self-healing repair corpus validation gates",
            "repair_corpus_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__repair_corpus__tests__repair_corpus_report_json_shape.snap",
        ),
        covered_advisory_row(
            "workload_corpus_report",
            "crates/ffs-harness/src/workload_corpus.rs",
            "WorkloadCorpusValidationReport",
            "validate-workload-corpus",
            "P1 user-risk workload corpus proof-bundle coverage gates",
            "workload_corpus_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__workload_corpus__tests__workload_corpus_report_json_shape.snap",
        ),
        covered_advisory_row(
            "metamorphic_workload_seed_catalog_report",
            "crates/ffs-harness/src/metamorphic_workload_seed_catalog.rs",
            "MetamorphicWorkloadSeedCatalogReport",
            "validate-metamorphic-workload-seeds",
            "metamorphic workload seed coverage catalog gates",
            "metamorphic_workload_seed_catalog_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__metamorphic_workload_seed_catalog__tests__metamorphic_workload_seed_catalog_report_json_shape.snap",
        ),
        covered_advisory_row(
            "swarm_workload_harness_report",
            "crates/ffs-harness/src/swarm_workload_harness.rs",
            "SwarmWorkloadHarnessReport",
            "validate-swarm-workload-harness",
            "large-host swarm workload manifest validation gates",
            "swarm_workload_harness_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__swarm_workload_harness__tests__swarm_workload_harness_report_json_shape.snap",
        ),
    ]);

    rows
}

fn fuzz_dashboard_advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    vec![
        covered_advisory_row(
            "fuzz_dashboard_campaign_summary",
            "crates/ffs-harness/src/fuzz_dashboard.rs",
            "CampaignSummary",
            "fuzz/scripts/nightly_fuzz.sh",
            "fuzz dashboard health assessment and trend visibility gates",
            "campaign_summary_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__fuzz_dashboard__tests__campaign_summary_json_shape.snap",
        ),
        covered_advisory_row(
            "fuzz_dashboard_regression_alert",
            "crates/ffs-harness/src/fuzz_dashboard.rs",
            "RegressionAlert",
            "detect_regressions",
            "fuzz dashboard regression alerts and operator triage",
            "regression_alert_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__fuzz_dashboard__tests__regression_alert_json_shape.snap",
        ),
    ]
}

fn e2e_repro_advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    vec![
        covered_advisory_row(
            "crash_replay_artifact_report",
            "crates/ffs-harness/src/crash_replay_artifact.rs",
            "CrashReplayArtifactReport",
            "validate_default_crash_replay_artifact",
            "crash replay artifact survivor-set verification and fail-closed proof handoff",
            "crash_replay_artifact_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__crash_replay_artifact__tests__crash_replay_artifact_report_json_shape.snap",
        ),
        covered_advisory_row(
            "crash_replay_suite_report",
            "crates/ffs-harness/src/e2e.rs",
            "CrashReplaySuiteReport",
            "run-crash-replay",
            "deterministic crash replay schedule artifacts and repro packs",
            "crash_replay_suite_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__e2e__tests__crash_replay_suite_report_json_shape.snap",
        ),
        covered_advisory_row(
            "fsx_stress_report",
            "crates/ffs-harness/src/e2e.rs",
            "FsxStressReport",
            "run-fsx-stress",
            "fsx-style stress artifacts and repair-integrity repro packs",
            "fsx_stress_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__e2e__tests__fsx_stress_report_json_shape.snap",
        ),
    ]
}

fn performance_advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    vec![
        covered_advisory_row(
            "performance_baseline_manifest_report",
            "crates/ffs-harness/src/performance_baseline_manifest.rs",
            "PerformanceBaselineManifestReport",
            "validate-performance-baseline-manifest",
            "performance baseline manifest and release evidence dry-run gates",
            "performance_baseline_manifest_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__performance_baseline_manifest__tests__performance_baseline_manifest_report_json_shape.snap",
        ),
        covered_advisory_row(
            "performance_delta_closeout_report",
            "crates/ffs-harness/src/performance_delta_closeout.rs",
            "PerformanceDeltaCloseoutReport",
            "performance-delta-closeout",
            "performance delta closeout and release evidence follow-up gates",
            "performance_delta_closeout_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__performance_delta_closeout__tests__performance_delta_closeout_report_json_shape.snap",
        ),
        covered_advisory_row(
            "perf_comparison_context",
            "crates/ffs-harness/src/perf_comparison.rs",
            "ComparisonContext",
            "RegressionComparator::compare_with_context",
            "performance comparator structured log context and regression triage consumers",
            "comparison_context_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__perf_comparison__tests__comparison_context_json_shape.snap",
        ),
        covered_advisory_row(
            "hysteresis_tracker",
            "crates/ffs-harness/src/perf_comparison.rs",
            "HysteresisTracker",
            "HysteresisTracker::record",
            "performance regression anti-flake state and runbook triage consumers",
            "hysteresis_tracker_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__perf_comparison__tests__hysteresis_tracker_json_shape.snap",
        ),
        covered_advisory_row(
            "perf_regression_baseline",
            "crates/ffs-harness/src/perf_regression.rs",
            "PerfBaseline",
            "parse_baseline",
            "benchmark_record baseline parser and performance regression thresholds",
            "perf_baseline_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__perf_regression__tests__perf_baseline_json_shape.snap",
        ),
        covered_advisory_row(
            "perf_triage_decision",
            "crates/ffs-harness/src/perf_triage.rs",
            "TriageDecision",
            "classify_triage",
            "performance regression triage runbook and operator follow-up routing",
            "triage_decision_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__perf_triage__tests__triage_decision_json_shape.snap",
        ),
        covered_advisory_row(
            "profile_read_path_report",
            "crates/ffs-harness/src/lib.rs",
            "ProfileReadPathReport",
            "profile-read-path",
            "repeatable in-process inspect and FUSE read profiling loops",
            "profile_read_path_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__tests__profile_read_path_report_json_shape.snap",
        ),
    ]
}

fn required_report_rows() -> Vec<ReportSchemaInventoryRow> {
    let mut rows = vec![
        covered_required_row(
            "parity_report",
            "crates/ffs-harness/src/lib.rs",
            "ParityReport",
            "parity",
            "FEATURE_PARITY quantitative CLI output and tracked V1 parity claims",
            "parity_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__tests__parity_report_json_shape.snap",
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange,
        ),
        covered_required_row(
            "swarm_operator_report",
            "crates/ffs-harness/src/swarm_operator_report.rs",
            "SwarmOperatorReport",
            "swarm operator report renderer",
            "proof-bundle and release-gate operator consumers",
            "swarm_operator_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__swarm_operator_report__tests__swarm_operator_report_json_shape.snap",
            ReportSchemaClaimEffect::ExistingReleaseGateInput,
        ),
        covered_required_row(
            "proof_bundle_validation_report",
            "crates/ffs-harness/src/proof_bundle.rs",
            "ProofBundleValidationReport",
            "validate-proof-bundle",
            "portable release proof bundle inspection",
            "proof_bundle_validation_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__proof_bundle__tests__proof_bundle_validation_report_json_shape.snap",
            ReportSchemaClaimEffect::ExistingReleaseGateInput,
        ),
        covered_required_row(
            "release_gate_evaluation_report",
            "crates/ffs-harness/src/release_gate.rs",
            "ReleaseGateEvaluationReport",
            "release gate policy evaluator",
            "public readiness wording gate",
            "release_gate_evaluation_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__release_gate__tests__release_gate_evaluation_report_json_shape.snap",
            ReportSchemaClaimEffect::ExistingReleaseGateInput,
        ),
        covered_required_row(
            "operational_readiness_report",
            "crates/ffs-harness/src/operational_readiness_report.rs",
            "OperationalReadinessReport",
            "operational readiness report aggregator",
            "readiness proof and runbook consumers",
            "operational_readiness_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__operational_readiness_report__tests__operational_readiness_report_json_shape.snap",
            ReportSchemaClaimEffect::ExistingReleaseGateInput,
        ),
        covered_required_row(
            "readiness_dashboard_report",
            "crates/ffs-harness/src/readiness_dashboard.rs",
            "ReadinessDashboardReport",
            "readiness dashboard renderer",
            "operator dashboard advisory rows",
            "readiness_dashboard_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__readiness_dashboard__tests__readiness_dashboard_report_json_shape.snap",
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange,
        ),
    ];
    rows.extend(authoritative_control_plane_required_rows());
    rows
}

fn authoritative_control_plane_required_rows() -> Vec<ReportSchemaInventoryRow> {
    vec![
        covered_required_row(
            "authoritative_lane_manifest",
            "crates/ffs-harness/src/authoritative_lane_manifest.rs",
            "AuthoritativeLaneManifest",
            "authoritative lane manifest evaluator",
            "proof-bundle lane promotion and release gates",
            "authoritative_lane_manifest_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__authoritative_lane_manifest__tests__authoritative_lane_manifest_json_shape.snap",
            ReportSchemaClaimEffect::ExistingReleaseGateInput,
        ),
        covered_required_row(
            "authoritative_lane_decision",
            "crates/ffs-harness/src/authoritative_lane_manifest.rs",
            "AuthoritativeLaneDecision",
            "authoritative lane manifest evaluator",
            "proof-bundle lane promotion and release gates",
            "authoritative_lane_decision_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__authoritative_lane_manifest__tests__authoritative_lane_decision_json_shape.snap",
            ReportSchemaClaimEffect::ExistingReleaseGateInput,
        ),
        covered_required_row(
            "authoritative_environment_manifest",
            "crates/ffs-harness/src/authoritative_environment_manifest.rs",
            "AuthoritativeEnvironmentManifest",
            "record-authoritative-environment-manifest",
            "authoritative worker replay and release-gate environment checks",
            "authoritative_environment_manifest_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__authoritative_environment_manifest__tests__authoritative_environment_manifest_json_shape.snap",
            ReportSchemaClaimEffect::ExistingReleaseGateInput,
        ),
        covered_required_row(
            "authoritative_environment_decision",
            "crates/ffs-harness/src/authoritative_environment_manifest.rs",
            "AuthoritativeEnvironmentDecision",
            "record-authoritative-environment-manifest",
            "authoritative worker replay and release-gate environment checks",
            "authoritative_environment_decision_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__authoritative_environment_manifest__tests__authoritative_environment_decision_json_shape.snap",
            ReportSchemaClaimEffect::ExistingReleaseGateInput,
        ),
    ]
}

fn permissioned_campaign_reports_row() -> ReportSchemaInventoryRow {
    covered_permissioned_row(
        "permissioned_campaign_reports",
        "tools/ffs-ops/src/permissioned_campaign_broker.rs",
        "PermissionedCampaignBrokerReport + PermissionedCampaignExecutionLedgerReport + SwarmCapabilityCalibrationReport",
        "permissioned campaign broker validators",
        "operator handoff packets for xfstests and large-host swarm campaigns",
        "permissioned_campaign_reports_json_shape",
        "tools/ffs-ops/src/snapshots/ffs_harness__permissioned_campaign_broker__tests__permissioned_campaign_reports_json_shape.snap",
    )
}

fn readiness_action_dry_run_metadata_row() -> ReportSchemaInventoryRow {
    excluded_row(
        "readiness_action_dry_run_metadata",
        "tools/ffs-ops/src/readiness_action_autopilot.rs",
        "ReadinessActionDryRunMetadata",
        "nested dry-run metadata helper",
        "nested inside ReadinessActionDryRunReport",
        "Nested metadata is not emitted as a standalone durable report; the enclosing dry-run JSON report owns the serialized artifact contract.",
    )
}

#[must_use]
pub fn validate_report_schema_inventory(
    inventory: &ReportSchemaInventory,
) -> ReportSchemaInventoryReport {
    let mut errors = Vec::new();
    let mut report_ids = BTreeSet::new();
    let mut required_rows = 0;
    let mut advisory_only_rows = 0;
    let mut permissioned_only_rows = 0;
    let mut covered_rows = 0;
    let mut missing_rows = 0;
    let mut excluded_rows = 0;
    let mut row_results = Vec::new();

    if inventory.schema_version != REPORT_SCHEMA_INVENTORY_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {REPORT_SCHEMA_INVENTORY_SCHEMA_VERSION}, got {}",
            inventory.schema_version
        ));
    }
    if inventory.inventory_id != REPORT_SCHEMA_INVENTORY_ID {
        errors.push(format!(
            "inventory_id must be `{REPORT_SCHEMA_INVENTORY_ID}`, got `{}`",
            inventory.inventory_id
        ));
    }
    if inventory.rows.is_empty() {
        errors.push("report schema inventory must declare at least one row".to_owned());
    }

    for row in &inventory.rows {
        let row_result = validate_row(
            row,
            &mut report_ids,
            &mut required_rows,
            &mut advisory_only_rows,
            &mut permissioned_only_rows,
            &mut covered_rows,
            &mut missing_rows,
            &mut excluded_rows,
        );
        errors.extend(row_result.errors.iter().cloned());
        row_results.push(row_result);
    }
    row_results.sort_by(|left, right| left.report_id.cmp(&right.report_id));
    errors.sort();
    let uncovered_required_report_ids = row_results
        .iter()
        .filter(|row| {
            row.coverage_requirement == ReportSchemaCoverageRequirement::Required
                && !row.missing_evidence.is_empty()
        })
        .map(|row| row.report_id.clone())
        .collect();

    ReportSchemaInventoryReport {
        schema_version: inventory.schema_version,
        inventory_id: inventory.inventory_id.clone(),
        product_evidence_claim: REPORT_SCHEMA_INVENTORY_PRODUCT_EVIDENCE_CLAIM.to_owned(),
        reproduction_command: REPORT_SCHEMA_INVENTORY_REPRODUCTION_COMMAND.to_owned(),
        valid: errors.is_empty(),
        total_rows: inventory.rows.len(),
        required_rows,
        advisory_only_rows,
        permissioned_only_rows,
        covered_rows,
        missing_rows,
        excluded_rows,
        report_ids: report_ids.into_iter().collect(),
        uncovered_required_report_ids,
        row_results,
        errors,
    }
}

pub fn fail_on_report_schema_inventory_errors(report: &ReportSchemaInventoryReport) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    bail!(
        "report schema inventory failed with {} error(s): {}",
        report.errors.len(),
        report.errors.join("; ")
    );
}

#[must_use]
pub fn render_report_schema_inventory_markdown(report: &ReportSchemaInventoryReport) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "# Report Schema Inventory");
    let _ = writeln!(output);
    let _ = writeln!(output, "- Inventory ID: `{}`", report.inventory_id);
    let _ = writeln!(output, "- Valid: `{}`", report.valid);
    let _ = writeln!(
        output,
        "- Product evidence claim: `{}`",
        report.product_evidence_claim
    );
    let _ = writeln!(
        output,
        "- Reproduction command: `{}`",
        report.reproduction_command
    );
    let _ = writeln!(output);
    let _ = writeln!(output, "## Counts");
    let _ = writeln!(output);
    let _ = writeln!(output, "| Metric | Count |");
    let _ = writeln!(output, "|---|---:|");
    let _ = writeln!(output, "| Total rows | {} |", report.total_rows);
    let _ = writeln!(output, "| Required rows | {} |", report.required_rows);
    let _ = writeln!(
        output,
        "| Advisory-only rows | {} |",
        report.advisory_only_rows
    );
    let _ = writeln!(
        output,
        "| Permissioned-only rows | {} |",
        report.permissioned_only_rows
    );
    let _ = writeln!(output, "| Covered rows | {} |", report.covered_rows);
    let _ = writeln!(output, "| Missing rows | {} |", report.missing_rows);
    let _ = writeln!(output, "| Excluded rows | {} |", report.excluded_rows);
    let _ = writeln!(output);

    let _ = writeln!(output, "## Uncovered Required Reports");
    let _ = writeln!(output);
    if report.uncovered_required_report_ids.is_empty() {
        let _ = writeln!(output, "None.");
    } else {
        for report_id in &report.uncovered_required_report_ids {
            let _ = writeln!(output, "- `{report_id}`");
        }
    }

    let _ = writeln!(output);
    let _ = writeln!(output, "## Row Results");
    let _ = writeln!(output);
    let _ = writeln!(
        output,
        "| Report ID | Requirement | Status | Missing Evidence | Errors |"
    );
    let _ = writeln!(output, "|---|---|---|---|---|");
    for row in &report.row_results {
        let missing = if row.missing_evidence.is_empty() {
            "none".to_owned()
        } else {
            row.missing_evidence.join(", ")
        };
        let errors = if row.errors.is_empty() {
            "none".to_owned()
        } else {
            row.errors.join("; ")
        };
        let _ = writeln!(
            output,
            "| `{}` | `{:?}` | `{:?}` | {} | {} |",
            row.report_id, row.coverage_requirement, row.coverage_status, missing, errors
        );
    }

    output
}

#[allow(clippy::too_many_arguments)]
fn validate_row(
    row: &ReportSchemaInventoryRow,
    report_ids: &mut BTreeSet<String>,
    required_rows: &mut usize,
    advisory_only_rows: &mut usize,
    permissioned_only_rows: &mut usize,
    covered_rows: &mut usize,
    missing_rows: &mut usize,
    excluded_rows: &mut usize,
) -> ReportSchemaInventoryRowResult {
    let mut errors = Vec::new();
    let mut missing_evidence = Vec::new();

    if row.report_id.trim().is_empty() {
        errors.push("report schema row missing report_id".to_owned());
    } else if !report_ids.insert(row.report_id.clone()) {
        errors.push(format!("duplicate report_id `{}`", row.report_id));
    }

    match row.coverage_requirement {
        ReportSchemaCoverageRequirement::Required => *required_rows += 1,
        ReportSchemaCoverageRequirement::AdvisoryOnly => *advisory_only_rows += 1,
        ReportSchemaCoverageRequirement::PermissionedOnly => *permissioned_only_rows += 1,
        ReportSchemaCoverageRequirement::Excluded => *excluded_rows += 1,
    }

    match row.coverage_status {
        ReportSchemaCoverageStatus::Covered => *covered_rows += 1,
        ReportSchemaCoverageStatus::Missing => *missing_rows += 1,
        ReportSchemaCoverageStatus::Excluded => {}
    }

    validate_non_empty(row, "module_path", &row.module_path, &mut errors);
    validate_non_empty(row, "rust_type", &row.rust_type, &mut errors);
    validate_non_empty(row, "producer", &row.producer, &mut errors);
    validate_non_empty(
        row,
        "downstream_consumer",
        &row.downstream_consumer,
        &mut errors,
    );
    validate_safe_relative_path(row, "module_path", &row.module_path, &mut errors);
    if !row.module_path.is_empty() {
        validate_existing_module_path(row, &row.module_path, &mut errors);
    }

    if !row.snapshot_path.is_empty() {
        validate_safe_relative_path(row, "snapshot_path", &row.snapshot_path, &mut errors);
        validate_existing_snapshot_path(row, &row.snapshot_path, &mut errors);
        validate_snapshot_path_matches_evidence(row, &row.snapshot_path, &mut errors);
        validate_snapshot_path_matches_module(row, &row.snapshot_path, &mut errors);
    }

    validate_coverage_fields(row, &mut missing_evidence, &mut errors);
    validate_claim_effect(row, &mut missing_evidence, &mut errors);
    missing_evidence.sort();
    missing_evidence.dedup();
    errors.sort();

    ReportSchemaInventoryRowResult {
        report_id: row.report_id.clone(),
        module_path: row.module_path.clone(),
        rust_type: row.rust_type.clone(),
        downstream_consumer: row.downstream_consumer.clone(),
        coverage_requirement: row.coverage_requirement,
        coverage_status: row.coverage_status,
        evidence_test: row.evidence_test.clone(),
        snapshot_path: row.snapshot_path.clone(),
        exclusion_reason: row.exclusion_reason.clone(),
        claim_effect: row.claim_effect,
        missing_evidence,
        errors,
    }
}

fn validate_coverage_fields(
    row: &ReportSchemaInventoryRow,
    missing_evidence: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    match (row.coverage_requirement, row.coverage_status) {
        (ReportSchemaCoverageRequirement::Excluded, ReportSchemaCoverageStatus::Excluded) => {
            if row.exclusion_reason.trim().is_empty() {
                missing_evidence.push("explicit_exclusion_reason".to_owned());
                errors.push(format!(
                    "row `{}` is excluded but missing exclusion_reason",
                    row.report_id
                ));
            }
        }
        (ReportSchemaCoverageRequirement::Excluded, status) => {
            errors.push(format!(
                "row `{}` has excluded requirement but status {status:?}",
                row.report_id
            ));
        }
        (_, ReportSchemaCoverageStatus::Excluded) => {
            errors.push(format!(
                "row `{}` has non-excluded requirement but excluded status",
                row.report_id
            ));
        }
        (_, ReportSchemaCoverageStatus::Covered) => {
            if row.evidence_test.trim().is_empty() {
                missing_evidence.push("typed_serde_round_trip_evidence".to_owned());
                missing_evidence.push("valid_evidence_test_name".to_owned());
                errors.push(format!(
                    "row `{}` is covered but missing evidence_test",
                    row.report_id
                ));
            } else if !is_valid_rust_test_name(&row.evidence_test) {
                missing_evidence.push("valid_evidence_test_name".to_owned());
                errors.push(format!(
                    "row `{}` evidence_test is not a valid rust test name: `{}`",
                    row.report_id, row.evidence_test
                ));
            }
            if row.snapshot_path.trim().is_empty() {
                missing_evidence.push("compact_json_shape_snapshot".to_owned());
                errors.push(format!(
                    "row `{}` is covered but missing snapshot_path",
                    row.report_id
                ));
            }
            if !row.exclusion_reason.trim().is_empty() {
                errors.push(format!(
                    "row `{}` is covered but has exclusion_reason",
                    row.report_id
                ));
            }
        }
        (_, ReportSchemaCoverageStatus::Missing) => {
            if row.coverage_requirement == ReportSchemaCoverageRequirement::Required {
                missing_evidence.push("typed_serde_round_trip_evidence".to_owned());
                missing_evidence.push("compact_json_shape_snapshot".to_owned());
                errors.push(format!(
                    "row `{}` is a required public report but remains uncovered",
                    row.report_id
                ));
            }
            if !row.evidence_test.trim().is_empty() || !row.snapshot_path.trim().is_empty() {
                errors.push(format!(
                    "row `{}` is missing but already names evidence",
                    row.report_id
                ));
            }
        }
    }
}

fn validate_claim_effect(
    row: &ReportSchemaInventoryRow,
    missing_evidence: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    match row.coverage_requirement {
        ReportSchemaCoverageRequirement::Required => {
            if matches!(
                row.claim_effect,
                ReportSchemaClaimEffect::ProductEvidenceNone
                    | ReportSchemaClaimEffect::InternalOnly
            ) {
                missing_evidence.push("valid_claim_effect".to_owned());
                errors.push(format!(
                    "row `{}` is required but claim_effect is not public-facing",
                    row.report_id
                ));
            }
        }
        ReportSchemaCoverageRequirement::AdvisoryOnly => {
            if row.claim_effect != ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange {
                missing_evidence.push("valid_claim_effect".to_owned());
                errors.push(format!(
                    "row `{}` is advisory_only but claim_effect is not advisory_only_no_public_readiness_change",
                    row.report_id
                ));
            }
        }
        ReportSchemaCoverageRequirement::PermissionedOnly => {
            if row.claim_effect != ReportSchemaClaimEffect::ProductEvidenceNone {
                missing_evidence.push("valid_claim_effect".to_owned());
                errors.push(format!(
                    "row `{}` is permissioned_only but claim_effect is not product_evidence_none",
                    row.report_id
                ));
            }
        }
        ReportSchemaCoverageRequirement::Excluded => {
            if row.claim_effect != ReportSchemaClaimEffect::InternalOnly {
                missing_evidence.push("valid_claim_effect".to_owned());
                errors.push(format!(
                    "row `{}` is excluded but claim_effect is not internal_only",
                    row.report_id
                ));
            }
        }
    }
}

fn is_valid_rust_test_name(value: &str) -> bool {
    let trimmed = value.trim();
    let Some(first) = trimmed.chars().next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && !trimmed.ends_with('_')
        && !trimmed.contains("__")
        && trimmed.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
}

fn validate_non_empty(
    row: &ReportSchemaInventoryRow,
    field: &str,
    value: &str,
    errors: &mut Vec<String>,
) {
    if value.trim().is_empty() {
        errors.push(format!("row `{}` missing {field}", row.report_id));
    }
}

fn validate_safe_relative_path(
    row: &ReportSchemaInventoryRow,
    field: &str,
    value: &str,
    errors: &mut Vec<String>,
) {
    if !is_safe_relative_path(value) {
        errors.push(format!(
            "row `{}` {field} must be a safe relative path, got `{value}`",
            row.report_id
        ));
    }
}

fn validate_existing_module_path(
    row: &ReportSchemaInventoryRow,
    value: &str,
    errors: &mut Vec<String>,
) {
    if !is_safe_relative_path(value) {
        return;
    }
    if Path::new(value).extension().and_then(|ext| ext.to_str()) != Some("rs") {
        errors.push(format!(
            "row `{}` module_path must point at a .rs source file, got `{value}`",
            row.report_id
        ));
        return;
    }
    if !workspace_relative_path(value).is_file() {
        errors.push(format!(
            "row `{}` module_path must point at an existing .rs source file, got `{value}`",
            row.report_id
        ));
    }
}

fn validate_existing_snapshot_path(
    row: &ReportSchemaInventoryRow,
    value: &str,
    errors: &mut Vec<String>,
) {
    if !is_safe_relative_path(value) {
        return;
    }
    if Path::new(value).extension().and_then(|ext| ext.to_str()) != Some("snap") {
        errors.push(format!(
            "row `{}` snapshot_path must point at a .snap file, got `{value}`",
            row.report_id
        ));
        return;
    }
    if !workspace_relative_path(value).is_file() {
        errors.push(format!(
            "row `{}` snapshot_path must point at an existing .snap file, got `{value}`",
            row.report_id
        ));
    }
}

fn validate_snapshot_path_matches_evidence(
    row: &ReportSchemaInventoryRow,
    value: &str,
    errors: &mut Vec<String>,
) {
    if !is_safe_relative_path(value) || row.evidence_test.trim().is_empty() {
        return;
    }

    if !snapshot_path_matches_evidence_test(row, value) {
        errors.push(format!(
            "row `{}` snapshot_path must match evidence_test `{}` or a snapshot label asserted by that test, got `{value}`",
            row.report_id, row.evidence_test
        ));
    }
}

fn snapshot_path_matches_evidence_test(
    row: &ReportSchemaInventoryRow,
    snapshot_path: &str,
) -> bool {
    let Some(file_name) = Path::new(snapshot_path)
        .file_name()
        .and_then(|file_name| file_name.to_str())
    else {
        return false;
    };

    snapshot_suffixes_for_evidence_test(row)
        .iter()
        .any(|expected_suffix| file_name.ends_with(expected_suffix))
}

fn snapshot_suffixes_for_evidence_test(row: &ReportSchemaInventoryRow) -> BTreeSet<String> {
    let mut suffixes = BTreeSet::from([format!("__tests__{}.snap", row.evidence_test)]);
    if !is_safe_relative_path(&row.module_path) {
        return suffixes;
    }

    let Ok(source) = fs::read_to_string(workspace_relative_path(&row.module_path)) else {
        return suffixes;
    };
    let Some(test_body) = rust_function_body(&source, &row.evidence_test) else {
        return suffixes;
    };

    for label in asserted_snapshot_labels(test_body) {
        suffixes.insert(format!("__tests__{label}.snap"));
    }
    suffixes
}

fn validate_snapshot_path_matches_module(
    row: &ReportSchemaInventoryRow,
    value: &str,
    errors: &mut Vec<String>,
) {
    if !is_safe_relative_path(value) || !is_safe_relative_path(&row.module_path) {
        return;
    }

    let Some(actual_prefix) = snapshot_module_prefix(value) else {
        return;
    };
    let Some(expected_prefix) = expected_snapshot_module_prefix(&row.module_path) else {
        return;
    };

    if actual_prefix != expected_prefix {
        errors.push(format!(
            "row `{}` snapshot_path module prefix must match module_path `{}`, got `{actual_prefix}`",
            row.report_id, row.module_path
        ));
    }
}

fn snapshot_module_prefix(snapshot_path: &str) -> Option<&str> {
    let file_name = Path::new(snapshot_path).file_name()?.to_str()?;
    let snapshot_name = file_name.strip_suffix(".snap")?;
    snapshot_name
        .split_once("__tests__")
        .map(|(module_prefix, _test_name)| module_prefix)
}

fn expected_snapshot_module_prefix(module_path: &str) -> Option<String> {
    let path = Path::new(module_path);
    if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
        return None;
    }

    let relative = path
        .strip_prefix("crates/ffs-harness/src")
        .or_else(|_| path.strip_prefix("tools/ffs-ops/src"))
        .ok()?;
    let without_extension = relative.with_extension("");
    let mut pieces = vec!["ffs_harness".to_owned()];
    for component in without_extension.components() {
        let Component::Normal(piece) = component else {
            return None;
        };
        pieces.push(piece.to_str()?.to_owned());
    }

    if pieces.len() == 2 && pieces.get(1).is_some_and(|piece| piece == "lib") {
        Some("ffs_harness".to_owned())
    } else {
        Some(pieces.join("__"))
    }
}

fn rust_function_body<'a>(source: &'a str, function_name: &str) -> Option<&'a str> {
    let needle = format!("fn {function_name}");
    let function_start = source.find(&needle)?;
    let body_start = function_start + source[function_start..].find('{')?;
    let mut depth = 0usize;

    for (offset, byte) in source[body_start..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return source.get(body_start + 1..body_start + offset);
                }
            }
            _ => {}
        }
    }

    None
}

fn asserted_snapshot_labels(test_body: &str) -> BTreeSet<String> {
    let mut labels = BTreeSet::new();
    for macro_name in ["assert_snapshot!(", "assert_json_snapshot!("] {
        let mut remaining = test_body;
        while let Some(index) = remaining.find(macro_name) {
            remaining = &remaining[index + macro_name.len()..];
            let Some(label) = first_string_argument(remaining) else {
                continue;
            };
            if is_valid_rust_test_name(label) {
                labels.insert(label.to_owned());
            }
        }
    }
    labels
}

fn first_string_argument(arguments: &str) -> Option<&str> {
    let mut escaped = false;
    let after_quote = arguments.trim_start().strip_prefix('"')?;
    for (index, character) in after_quote.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '"' => return Some(&after_quote[..index]),
            _ => {}
        }
    }
    None
}

fn is_safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
}

fn workspace_relative_path(value: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(value)
}

#[allow(clippy::too_many_arguments)]
fn covered_required_row(
    report_id: &str,
    module_path: &str,
    rust_type: &str,
    producer: &str,
    downstream_consumer: &str,
    evidence_test: &str,
    snapshot_path: &str,
    claim_effect: ReportSchemaClaimEffect,
) -> ReportSchemaInventoryRow {
    ReportSchemaInventoryRow {
        report_id: report_id.to_owned(),
        module_path: module_path.to_owned(),
        rust_type: rust_type.to_owned(),
        producer: producer.to_owned(),
        downstream_consumer: downstream_consumer.to_owned(),
        coverage_requirement: ReportSchemaCoverageRequirement::Required,
        coverage_status: ReportSchemaCoverageStatus::Covered,
        evidence_test: evidence_test.to_owned(),
        snapshot_path: snapshot_path.to_owned(),
        exclusion_reason: String::new(),
        claim_effect,
    }
}

fn covered_advisory_row(
    report_id: &str,
    module_path: &str,
    rust_type: &str,
    producer: &str,
    downstream_consumer: &str,
    evidence_test: &str,
    snapshot_path: &str,
) -> ReportSchemaInventoryRow {
    ReportSchemaInventoryRow {
        coverage_requirement: ReportSchemaCoverageRequirement::AdvisoryOnly,
        claim_effect: ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange,
        ..covered_required_row(
            report_id,
            module_path,
            rust_type,
            producer,
            downstream_consumer,
            evidence_test,
            snapshot_path,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange,
        )
    }
}

fn covered_permissioned_row(
    report_id: &str,
    module_path: &str,
    rust_type: &str,
    producer: &str,
    downstream_consumer: &str,
    evidence_test: &str,
    snapshot_path: &str,
) -> ReportSchemaInventoryRow {
    ReportSchemaInventoryRow {
        coverage_requirement: ReportSchemaCoverageRequirement::PermissionedOnly,
        claim_effect: ReportSchemaClaimEffect::ProductEvidenceNone,
        ..covered_required_row(
            report_id,
            module_path,
            rust_type,
            producer,
            downstream_consumer,
            evidence_test,
            snapshot_path,
            ReportSchemaClaimEffect::ProductEvidenceNone,
        )
    }
}

fn excluded_row(
    report_id: &str,
    module_path: &str,
    rust_type: &str,
    producer: &str,
    downstream_consumer: &str,
    exclusion_reason: &str,
) -> ReportSchemaInventoryRow {
    ReportSchemaInventoryRow {
        report_id: report_id.to_owned(),
        module_path: module_path.to_owned(),
        rust_type: rust_type.to_owned(),
        producer: producer.to_owned(),
        downstream_consumer: downstream_consumer.to_owned(),
        coverage_requirement: ReportSchemaCoverageRequirement::Excluded,
        coverage_status: ReportSchemaCoverageStatus::Excluded,
        evidence_test: String::new(),
        snapshot_path: String::new(),
        exclusion_reason: exclusion_reason.to_owned(),
        claim_effect: ReportSchemaClaimEffect::InternalOnly,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, bail};
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::path::Path;

    struct ReportInventoryExpectation {
        report_id: &'static str,
        module_path: &'static str,
        rust_type: &'static str,
        producer: &'static str,
        evidence_test: &'static str,
        snapshot_suffix: &'static str,
    }

    const EXEMPT_JSON_SHAPE_SNAPSHOT_EVIDENCE: &[(&str, &str)] = &[
        (
            "claimability_plan_rch_blocked_report_json_shape",
            "RCH-blocked scenario variant of the claimability_plan_report shape; the durable report contract is the tracked claimability_plan_report_json_shape row",
        ),
        (
            "crash_replay_suite_config_json_shape",
            "CrashReplaySuiteConfig is a repro input config, while the public output contract is crash_replay_suite_report_json_shape",
        ),
        (
            "e2e_test_result_json_shape",
            "E2eTestResult is the generic harness-internal scenario result carrier, not a durable product report schema",
        ),
        (
            "fsx_stress_config_json_shape",
            "FsxStressConfig is a repro input config, while the public output contract is fsx_stress_report_json_shape",
        ),
    ];

    fn json_shape_snapshot_evidence_tests() -> Result<BTreeSet<String>> {
        let snapshots_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/snapshots");
        let mut evidence_tests = BTreeSet::new();
        for entry in std::fs::read_dir(&snapshots_dir)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                bail!("snapshot path is not valid UTF-8: {:?}", entry.path());
            };
            let Some(snapshot_name) = file_name.strip_suffix(".snap") else {
                continue;
            };
            if !snapshot_name.ends_with("_json_shape") {
                continue;
            }
            let Some((_module_prefix, evidence_test)) = snapshot_name.split_once("__tests__")
            else {
                bail!("snapshot name missing `__tests__` marker: {file_name}");
            };
            evidence_tests.insert(evidence_test.to_owned());
        }
        Ok(evidence_tests)
    }

    const MOUNTED_WRITEBACK_REPORT_EXPECTATIONS: &[ReportInventoryExpectation] = &[
        ReportInventoryExpectation {
            report_id: "rch_proof_ledger_report",
            module_path: "crates/ffs-harness/src/verification_runner.rs",
            rust_type: "RchProofLedgerReport",
            producer: "rch-proof-ledger",
            evidence_test: "rch_proof_ledger_report_json_shape",
            snapshot_suffix: "ffs_harness__verification_runner__tests__rch_proof_ledger_report_json_shape.snap",
        },
        ReportInventoryExpectation {
            report_id: "fuse_capability_report",
            module_path: "crates/ffs-harness/src/verification_runner.rs",
            rust_type: "FuseCapabilityProbeReport",
            producer: "fuse-capability-probe",
            evidence_test: "fuse_capability_report_json_shape",
            snapshot_suffix: "ffs_harness__verification_runner__tests__fuse_capability_report_json_shape.snap",
        },
        ReportInventoryExpectation {
            report_id: "mounted_lane_decision",
            module_path: "crates/ffs-harness/src/mounted_lane_gate.rs",
            rust_type: "MountedLaneDecision",
            producer: "mounted lane fail-closed gate evaluator",
            evidence_test: "mounted_lane_decision_json_shape",
            snapshot_suffix: "ffs_harness__mounted_lane_gate__tests__mounted_lane_decision_json_shape.snap",
        },
        ReportInventoryExpectation {
            report_id: "mounted_lane_gate",
            module_path: "crates/ffs-harness/src/mounted_lane_gate.rs",
            rust_type: "MountedLaneGate",
            producer: "mounted lane fail-closed gate evaluator",
            evidence_test: "mounted_lane_gate_json_shape",
            snapshot_suffix: "ffs_harness__mounted_lane_gate__tests__mounted_lane_gate_json_shape.snap",
        },
        ReportInventoryExpectation {
            report_id: "mounted_repair_policy_report",
            module_path: "crates/ffs-harness/src/mounted_repair_policy.rs",
            rust_type: "MountedRepairPolicyReport",
            producer: "validate_default_mounted_repair_policy",
            evidence_test: "mounted_repair_policy_report_json_shape",
            snapshot_suffix: "ffs_harness__mounted_repair_policy__tests__mounted_repair_policy_report_json_shape.snap",
        },
        ReportInventoryExpectation {
            report_id: "mounted_repair_mutation_boundary_report",
            module_path: "crates/ffs-harness/src/mounted_repair_mutation_boundary.rs",
            rust_type: "MountedRepairMutationBoundaryReport",
            producer: "validate-mounted-repair-mutation-boundary",
            evidence_test: "mounted_repair_mutation_boundary_report_json_shape",
            snapshot_suffix: "ffs_harness__mounted_repair_mutation_boundary__tests__mounted_repair_mutation_boundary_report_json_shape.snap",
        },
        ReportInventoryExpectation {
            report_id: "mounted_write_matrix_report",
            module_path: "crates/ffs-harness/src/mounted_write_matrix.rs",
            rust_type: "MountedWriteMatrixReport",
            producer: "validate-mounted-write-matrix",
            evidence_test: "mounted_write_matrix_report_json_shape",
            snapshot_suffix: "ffs_harness__mounted_write_matrix__tests__mounted_write_matrix_report_json_shape.snap",
        },
        ReportInventoryExpectation {
            report_id: "mounted_write_error_report",
            module_path: "crates/ffs-harness/src/mounted_write_error_classes.rs",
            rust_type: "MountedWriteErrorReport",
            producer: "validate-mounted-write-error-classes",
            evidence_test: "mounted_write_error_report_json_shape",
            snapshot_suffix: "ffs_harness__mounted_write_error_classes__tests__mounted_write_error_report_json_shape.snap",
        },
        ReportInventoryExpectation {
            report_id: "mounted_write_errno_budget_report",
            module_path: "crates/ffs-harness/src/mounted_write_errno_budget.rs",
            rust_type: "MountedWriteErrnoBudgetReport",
            producer: "validate_default_mounted_write_errno_budget",
            evidence_test: "default_budget_report_json_shape",
            snapshot_suffix: "ffs_harness__mounted_write_errno_budget__tests__default_budget_report_json_shape.snap",
        },
        ReportInventoryExpectation {
            report_id: "repair_writeback_serialization_report",
            module_path: "crates/ffs-harness/src/repair_writeback_serialization.rs",
            rust_type: "RepairWritebackSerializationReport",
            producer: "validate-repair-writeback-serialization",
            evidence_test: "repair_writeback_serialization_report_json_shape",
            snapshot_suffix: "ffs_harness__repair_writeback_serialization__tests__repair_writeback_serialization_report_json_shape.snap",
        },
        ReportInventoryExpectation {
            report_id: "rw_background_repair_gate",
            module_path: "crates/ffs-harness/src/rw_background_repair_gate.rs",
            rust_type: "RwBackgroundRepairGate",
            producer: "evaluate_rw_background_repair_gate",
            evidence_test: "happy_gate_json_shape",
            snapshot_suffix: "ffs_harness__rw_background_repair_gate__tests__happy_gate_json_shape.snap",
        },
        ReportInventoryExpectation {
            report_id: "writeback_cache_audit_report",
            module_path: "crates/ffs-harness/src/writeback_cache_audit.rs",
            rust_type: "WritebackCacheAuditReport",
            producer: "validate-writeback-cache-audit",
            evidence_test: "writeback_cache_audit_report_json_shape",
            snapshot_suffix: "ffs_harness__writeback_cache_audit__tests__writeback_cache_audit_report_json_shape.snap",
        },
        ReportInventoryExpectation {
            report_id: "writeback_ordering_report",
            module_path: "crates/ffs-harness/src/writeback_cache_audit.rs",
            rust_type: "WritebackOrderingReport",
            producer: "validate-writeback-cache-ordering",
            evidence_test: "writeback_ordering_report_json_shape",
            snapshot_suffix: "ffs_harness__writeback_cache_audit__tests__writeback_ordering_report_json_shape.snap",
        },
        ReportInventoryExpectation {
            report_id: "writeback_crash_replay_report",
            module_path: "crates/ffs-harness/src/writeback_cache_audit.rs",
            rust_type: "WritebackCrashReplayReport",
            producer: "validate-writeback-cache-crash-replay",
            evidence_test: "writeback_crash_replay_report_json_shape",
            snapshot_suffix: "ffs_harness__writeback_cache_audit__tests__writeback_crash_replay_report_json_shape.snap",
        },
    ];

    fn row_result<'a>(
        report: &'a ReportSchemaInventoryReport,
        report_id: &str,
    ) -> &'a ReportSchemaInventoryRowResult {
        report
            .row_results
            .iter()
            .find(|row| row.report_id == report_id)
            .expect("row result should exist")
    }

    #[test]
    fn default_report_schema_inventory_is_valid() {
        let inventory = current_report_schema_inventory();
        let report = validate_report_schema_inventory(&inventory);

        assert!(report.valid);
        assert_eq!(
            report.product_evidence_claim,
            REPORT_SCHEMA_INVENTORY_PRODUCT_EVIDENCE_CLAIM
        );
        assert_eq!(
            report.reproduction_command,
            REPORT_SCHEMA_INVENTORY_REPRODUCTION_COMMAND
        );
        assert!(
            report.errors.is_empty(),
            "default inventory should be valid: {:?}",
            report.errors
        );
        assert_eq!(
            report.schema_version,
            REPORT_SCHEMA_INVENTORY_SCHEMA_VERSION
        );
        assert_eq!(report.total_rows, 113);
        assert_eq!(report.required_rows, 10);
        assert_eq!(report.advisory_only_rows, 101);
        assert_eq!(report.permissioned_only_rows, 1);
        assert_eq!(report.excluded_rows, 1);
        assert_eq!(report.covered_rows, 112);
        assert_eq!(report.missing_rows, 0);
        for report_id in [
            "swarm_operator_report",
            "readiness_action_dry_run_report",
            "readiness_action_planning_result",
            "performance_baseline_manifest_report",
            "performance_delta_closeout_report",
            "profile_read_path_report",
            "operational_evidence_index",
            "invariant_oracle_consumer_report",
            "perf_comparison_context",
            "perf_regression_baseline",
            "perf_triage_decision",
            "hysteresis_tracker",
            "rw_background_repair_gate",
            "fuzz_dashboard_campaign_summary",
            "fuzz_dashboard_regression_alert",
            "tabletop_drill_canonical_drills",
            "tabletop_drill_result",
            "deferred_parity_audit_gap_classes",
            "oq_decision_matrix_canonical_matrix",
            "fuzz_smoke_report",
            "swarm_operator_validation_report",
            "soak_canary_campaign_report",
            "xfstests_baseline_manifest",
            "xfstests_failure_triage_report",
            "parity_report",
            "crash_replay_artifact_report",
            "mounted_write_errno_budget_report",
            "mounted_lane_gate",
            "readiness_action_fixture_validation_report",
            "cross_oracle_arbitration_report",
            "claimability_plan_report",
            "rch_capacity_preflight_report",
            "rch_capacity_preflight_validation_report",
            "agent_mail_reservation_snapshot_report",
            "crash_replay_suite_report",
            "fsx_stress_report",
            "runtime_console_report",
        ] {
            assert!(
                report.report_ids.iter().any(|id| id == report_id),
                "missing report id {report_id}"
            );
        }
        assert_eq!(report.row_results.len(), report.total_rows);
        assert_eq!(
            report.row_results[0].report_id,
            "adaptive_runtime_evidence_report"
        );
        assert_eq!(report.uncovered_required_report_ids, [] as [String; 0]);
        assert!(report.row_results.iter().all(|row| row.errors.is_empty()));
    }

    #[test]
    fn duplicate_report_ids_fail() {
        let mut inventory = current_report_schema_inventory();
        inventory.rows[1].report_id = inventory.rows[0].report_id.clone();

        let report = validate_report_schema_inventory(&inventory);

        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("duplicate report_id")),
            "{:?}",
            report.errors
        );
    }

    #[test]
    fn covered_rows_require_snapshot_and_test_evidence() {
        let mut inventory = current_report_schema_inventory();
        inventory.rows[0].evidence_test.clear();
        inventory.rows[0].snapshot_path.clear();
        let report_id = inventory.rows[0].report_id.clone();

        let report = validate_report_schema_inventory(&inventory);
        let result = row_result(&report, &report_id);

        assert!(!report.valid);
        assert!(
            result
                .missing_evidence
                .contains(&"typed_serde_round_trip_evidence".to_owned()),
            "{result:?}"
        );
        assert!(
            result
                .missing_evidence
                .contains(&"compact_json_shape_snapshot".to_owned()),
            "{result:?}"
        );
        assert!(
            result
                .missing_evidence
                .contains(&"valid_evidence_test_name".to_owned()),
            "{result:?}"
        );
    }

    #[test]
    fn invalid_evidence_test_name_fails() {
        let mut inventory = current_report_schema_inventory();
        inventory.rows[0].evidence_test = "Bad-Test-Name".to_owned();
        let report_id = inventory.rows[0].report_id.clone();

        let report = validate_report_schema_inventory(&inventory);
        let result = row_result(&report, &report_id);

        assert!(!report.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("valid rust test name")),
            "{result:?}"
        );
    }

    #[test]
    fn invalid_claim_effect_fails() {
        let mut inventory = current_report_schema_inventory();
        inventory.rows[0].claim_effect = ReportSchemaClaimEffect::ExistingReleaseGateInput;
        let report_id = inventory.rows[0].report_id.clone();

        let report = validate_report_schema_inventory(&inventory);
        let result = row_result(&report, &report_id);

        assert!(!report.valid);
        assert!(
            result
                .missing_evidence
                .contains(&"valid_claim_effect".to_owned()),
            "{result:?}"
        );
    }

    #[test]
    fn missing_module_path_fails() {
        let mut inventory = current_report_schema_inventory();
        let report_id = inventory.rows[0].report_id.clone();
        inventory.rows[0].module_path =
            "crates/ffs-harness/src/missing_report_schema_inventory_module.rs".to_owned();

        let report = validate_report_schema_inventory(&inventory);
        let result = row_result(&report, &report_id);

        assert!(!report.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("existing .rs source file")),
            "{result:?}"
        );
    }

    #[test]
    fn non_rust_module_path_fails() {
        let mut inventory = current_report_schema_inventory();
        let report_id = inventory.rows[0].report_id.clone();
        inventory.rows[0].module_path = "README.md".to_owned();

        let report = validate_report_schema_inventory(&inventory);
        let result = row_result(&report, &report_id);

        assert!(!report.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains(".rs source file")),
            "{result:?}"
        );
    }

    #[test]
    fn unsafe_snapshot_path_fails() {
        let mut inventory = current_report_schema_inventory();
        inventory.rows[0].snapshot_path = "../outside.snap".to_owned();

        let report = validate_report_schema_inventory(&inventory);

        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("snapshot_path must be a safe relative path")),
            "{:?}",
            report.errors
        );
    }

    #[test]
    fn missing_snapshot_path_fails() {
        let mut inventory = current_report_schema_inventory();
        let report_id = inventory.rows[0].report_id.clone();
        inventory.rows[0].snapshot_path =
            "crates/ffs-harness/src/snapshots/missing_report_schema_inventory_snapshot.snap"
                .to_owned();

        let report = validate_report_schema_inventory(&inventory);
        let result = row_result(&report, &report_id);

        assert!(!report.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("existing .snap file")),
            "{result:?}"
        );
    }

    #[test]
    fn mismatched_snapshot_evidence_test_fails() {
        let mut inventory = current_report_schema_inventory();
        let report_id = inventory.rows[0].report_id.clone();
        inventory.rows[0].snapshot_path = inventory.rows[1].snapshot_path.clone();

        let report = validate_report_schema_inventory(&inventory);
        let result = row_result(&report, &report_id);

        assert!(!report.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("snapshot_path must match evidence_test")),
            "{result:?}"
        );
    }

    #[test]
    fn mismatched_snapshot_module_path_fails() {
        let mut inventory = current_report_schema_inventory();
        let report_id = inventory.rows[0].report_id.clone();
        inventory.rows[0].module_path = "crates/ffs-harness/src/metrics.rs".to_owned();

        let report = validate_report_schema_inventory(&inventory);
        let result = row_result(&report, &report_id);

        assert!(!report.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("snapshot_path module prefix")),
            "{result:?}"
        );
    }

    #[test]
    fn excluded_rows_require_reason() {
        let mut inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter_mut()
            .find(|row| row.coverage_requirement == ReportSchemaCoverageRequirement::Excluded)
            .expect("fixture includes an excluded helper row");
        row.exclusion_reason.clear();

        let report = validate_report_schema_inventory(&inventory);

        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("missing exclusion_reason")),
            "{:?}",
            report.errors
        );
    }

    #[test]
    fn required_missing_rows_fail_with_row_context() {
        let mut inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter_mut()
            .find(|row| row.report_id == "swarm_operator_report")
            .expect("fixture includes swarm operator report");
        row.coverage_status = ReportSchemaCoverageStatus::Missing;
        row.evidence_test.clear();
        row.snapshot_path.clear();
        let report_id = row.report_id.clone();

        let report = validate_report_schema_inventory(&inventory);
        let result = row_result(&report, &report_id);

        assert!(!report.valid);
        assert_eq!(report.missing_rows, 1);
        assert_eq!(
            result.module_path,
            "crates/ffs-harness/src/swarm_operator_report.rs"
        );
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("required public report")),
            "{result:?}"
        );
        assert_eq!(
            report.uncovered_required_report_ids,
            vec!["swarm_operator_report"]
        );
    }

    #[test]
    fn report_results_are_deterministically_ordered() {
        let mut inventory = current_report_schema_inventory();
        inventory.rows.reverse();

        let report = validate_report_schema_inventory(&inventory);
        let row_ids = report
            .row_results
            .iter()
            .map(|row| row.report_id.as_str())
            .collect::<Vec<_>>();
        let mut sorted_ids = row_ids.clone();
        sorted_ids.sort_unstable();

        assert_eq!(row_ids, sorted_ids);
        assert_eq!(report.report_ids, sorted_ids);
    }

    #[test]
    fn covered_rows_name_checked_in_snapshot_files() {
        let inventory = current_report_schema_inventory();
        let missing_snapshots = inventory
            .rows
            .iter()
            .filter(|row| row.coverage_status == ReportSchemaCoverageStatus::Covered)
            .filter(|row| !workspace_relative_path(&row.snapshot_path).is_file())
            .map(|row| (row.report_id.clone(), row.snapshot_path.clone()))
            .collect::<Vec<_>>();

        assert!(
            missing_snapshots.is_empty(),
            "covered report schema rows must name existing snapshot files: {missing_snapshots:?}"
        );
    }

    #[test]
    fn covered_rows_correlate_snapshot_paths_to_evidence_tests() {
        let inventory = current_report_schema_inventory();
        let mismatched_snapshots = inventory
            .rows
            .iter()
            .filter(|row| row.coverage_status == ReportSchemaCoverageStatus::Covered)
            .filter(|row| !snapshot_path_matches_evidence_test(row, &row.snapshot_path))
            .map(|row| {
                (
                    row.report_id.clone(),
                    row.evidence_test.clone(),
                    row.snapshot_path.clone(),
                )
            })
            .collect::<Vec<_>>();

        assert!(
            mismatched_snapshots.is_empty(),
            "covered report schema rows must correlate snapshot_path to evidence_test: {mismatched_snapshots:?}"
        );
    }

    #[test]
    fn covered_rows_correlate_snapshot_paths_to_modules() {
        let inventory = current_report_schema_inventory();
        let mismatched_modules = inventory
            .rows
            .iter()
            .filter(|row| row.coverage_status == ReportSchemaCoverageStatus::Covered)
            .filter(|row| {
                snapshot_module_prefix(&row.snapshot_path)
                    != expected_snapshot_module_prefix(&row.module_path).as_deref()
            })
            .map(|row| {
                (
                    row.report_id.clone(),
                    row.module_path.clone(),
                    row.snapshot_path.clone(),
                )
            })
            .collect::<Vec<_>>();

        assert!(
            mismatched_modules.is_empty(),
            "covered report schema rows must correlate snapshot_path to module_path: {mismatched_modules:?}"
        );
    }

    #[test]
    fn inventory_rows_name_checked_in_rust_modules() {
        let inventory = current_report_schema_inventory();
        let missing_modules = inventory
            .rows
            .iter()
            .filter(|row| {
                Path::new(&row.module_path)
                    .extension()
                    .and_then(|ext| ext.to_str())
                    != Some("rs")
                    || !workspace_relative_path(&row.module_path).is_file()
            })
            .map(|row| (row.report_id.clone(), row.module_path.clone()))
            .collect::<Vec<_>>();

        assert!(
            missing_modules.is_empty(),
            "report schema rows must name existing Rust module files: {missing_modules:?}"
        );
    }

    #[test]
    fn json_shape_snapshots_are_inventory_tracked_or_explicitly_exempt() -> Result<()> {
        let inventory = current_report_schema_inventory();
        let inventory_evidence = inventory
            .rows
            .iter()
            .filter(|row| row.coverage_status == ReportSchemaCoverageStatus::Covered)
            .map(|row| row.evidence_test.clone())
            .collect::<BTreeSet<_>>();
        let exempt_evidence = EXEMPT_JSON_SHAPE_SNAPSHOT_EVIDENCE
            .iter()
            .map(|(evidence_test, _reason)| (*evidence_test).to_owned())
            .collect::<BTreeSet<_>>();

        for (evidence_test, reason) in EXEMPT_JSON_SHAPE_SNAPSHOT_EVIDENCE {
            assert!(
                !reason.trim().is_empty(),
                "exempt JSON-shape snapshot `{evidence_test}` must document why it is not a report schema row"
            );
        }

        let snapshot_evidence = json_shape_snapshot_evidence_tests()?;
        let missing_inventory = snapshot_evidence
            .difference(&inventory_evidence)
            .filter(|evidence_test| !exempt_evidence.contains(*evidence_test))
            .cloned()
            .collect::<Vec<_>>();
        let stale_exemptions = exempt_evidence
            .difference(&snapshot_evidence)
            .cloned()
            .collect::<Vec<_>>();

        assert!(
            missing_inventory.is_empty(),
            "JSON-shape snapshots must be represented in report_schema_inventory or named in EXEMPT_JSON_SHAPE_SNAPSHOT_EVIDENCE: {missing_inventory:?}"
        );
        assert!(
            stale_exemptions.is_empty(),
            "JSON-shape snapshot exemptions should be removed when their snapshots disappear: {stale_exemptions:?}"
        );

        Ok(())
    }

    #[test]
    fn report_markdown_summary_names_claim_and_uncovered_rows() {
        let mut inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter_mut()
            .find(|row| row.report_id == "swarm_operator_report")
            .expect("fixture includes swarm operator report row");
        row.coverage_status = ReportSchemaCoverageStatus::Missing;
        row.evidence_test.clear();
        row.snapshot_path.clear();

        let report = validate_report_schema_inventory(&inventory);
        let markdown = render_report_schema_inventory_markdown(&report);

        assert!(markdown.contains("# Report Schema Inventory"));
        assert!(markdown.contains("Product evidence claim: `none`"));
        assert!(markdown.contains("`swarm_operator_report`"));
        assert!(fail_on_report_schema_inventory_errors(&report).is_err());
    }

    #[test]
    fn inventory_tracks_readiness_action_dry_run_report() {
        let inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter()
            .find(|row| row.report_id == "readiness_action_dry_run_report")
            .expect("inventory includes readiness action dry-run report");

        assert_eq!(
            row.rust_type, "ReadinessActionDryRunReport",
            "inventory must track the durable report emitted by recommend-readiness-actions"
        );
        assert_eq!(row.producer, "recommend-readiness-actions");
        assert_eq!(
            row.coverage_requirement,
            ReportSchemaCoverageRequirement::AdvisoryOnly
        );
        assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
        assert_eq!(row.evidence_test, "readiness_action_dry_run_json_report");
        assert!(row.snapshot_path.ends_with(
            "ffs_harness__readiness_action_autopilot__tests__readiness_action_dry_run_json_report.snap"
        ));
        assert_eq!(
            row.claim_effect,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
        );
    }

    #[test]
    fn inventory_tracks_readiness_action_planning_result() {
        let inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter()
            .find(|row| row.report_id == "readiness_action_planning_result")
            .expect("inventory includes readiness action planning result");

        assert_eq!(
            row.module_path,
            "tools/ffs-ops/src/readiness_action_autopilot.rs"
        );
        assert_eq!(row.rust_type, "ReadinessActionPlanningResult");
        assert_eq!(row.producer, "plan_readiness_actions");
        assert_eq!(
            row.downstream_consumer,
            "readiness-action dry-run and operator action selection"
        );
        assert_eq!(
            row.coverage_requirement,
            ReportSchemaCoverageRequirement::AdvisoryOnly
        );
        assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
        assert_eq!(
            row.evidence_test,
            "readiness_action_planner_result_order_stable"
        );
        assert!(row.snapshot_path.ends_with(
            "ffs_harness__readiness_action_autopilot__tests__readiness_action_planner_result_order_stable.snap"
        ));
        assert_eq!(
            row.claim_effect,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
        );
    }

    #[test]
    fn inventory_tracks_public_parity_report() {
        let inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter()
            .find(|row| row.report_id == "parity_report")
            .expect("inventory includes public parity report");

        assert_eq!(row.module_path, "crates/ffs-harness/src/lib.rs");
        assert_eq!(row.rust_type, "ParityReport");
        assert_eq!(row.producer, "parity");
        assert_eq!(
            row.downstream_consumer,
            "FEATURE_PARITY quantitative CLI output and tracked V1 parity claims"
        );
        assert_eq!(
            row.coverage_requirement,
            ReportSchemaCoverageRequirement::Required
        );
        assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
        assert_eq!(row.evidence_test, "parity_report_json_shape");
        assert!(
            row.snapshot_path
                .ends_with("ffs_harness__tests__parity_report_json_shape.snap")
        );
        assert_eq!(
            row.claim_effect,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
        );
    }

    #[test]
    fn inventory_tracks_readiness_action_fixture_validation_report() {
        let inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter()
            .find(|row| row.report_id == "readiness_action_fixture_validation_report")
            .expect("inventory includes readiness action fixture validation report");

        assert_eq!(
            row.module_path,
            "tools/ffs-ops/src/readiness_action_autopilot.rs"
        );
        assert_eq!(row.rust_type, "ReadinessActionFixtureValidationReport");
        assert_eq!(row.producer, "validate_readiness_action_fixture_set");
        assert_eq!(
            row.coverage_requirement,
            ReportSchemaCoverageRequirement::AdvisoryOnly
        );
        assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
        assert_eq!(
            row.evidence_test,
            "readiness_action_fixture_validation_report_json_shape"
        );
        assert!(row.snapshot_path.ends_with(
            "ffs_harness__readiness_action_autopilot__tests__readiness_action_fixture_validation_report_json_shape.snap"
        ));
        assert_eq!(
            row.claim_effect,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
        );
    }

    #[test]
    fn inventory_tracks_claimability_plan_report() {
        let inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter()
            .find(|row| row.report_id == "claimability_plan_report")
            .expect("inventory includes claimability plan report");

        assert_eq!(
            row.module_path,
            "crates/ffs-harness/src/claimability_plan.rs"
        );
        assert_eq!(row.rust_type, "ClaimabilityPlanReport");
        assert_eq!(row.producer, "claimability-plan");
        assert_eq!(
            row.downstream_consumer,
            "source-aware queue guidance and Agent Mail reservation handoff"
        );
        assert_eq!(
            row.coverage_requirement,
            ReportSchemaCoverageRequirement::AdvisoryOnly
        );
        assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
        assert_eq!(row.evidence_test, "claimability_plan_report_json_shape");
        assert!(row.snapshot_path.ends_with(
            "ffs_harness__claimability_plan__tests__claimability_plan_report_json_shape.snap"
        ));
        assert_eq!(
            row.claim_effect,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
        );
    }

    #[test]
    fn inventory_tracks_rch_capacity_preflight_reports() {
        let inventory = current_report_schema_inventory();
        for (report_id, rust_type, producer, evidence_test, snapshot_suffix) in [
            (
                "rch_capacity_preflight_report",
                "RchCapacityPreflightReport",
                "ffs_rch_capacity_preflight_e2e.sh",
                "rch_capacity_preflight_report_json_shape",
                "ffs_harness__rch_capacity_preflight__tests__rch_capacity_preflight_report_json_shape.snap",
            ),
            (
                "rch_capacity_preflight_validation_report",
                "RchCapacityPreflightValidationReport",
                "validate-rch-capacity-preflight",
                "rch_capacity_preflight_validation_report_json_shape",
                "ffs_harness__rch_capacity_preflight__tests__rch_capacity_preflight_validation_report_json_shape.snap",
            ),
        ] {
            let row = inventory
                .rows
                .iter()
                .find(|row| row.report_id == report_id)
                .expect("inventory includes RCH capacity preflight report row");

            assert_eq!(
                row.module_path,
                "crates/ffs-harness/src/rch_capacity_preflight.rs"
            );
            assert_eq!(row.rust_type, rust_type);
            assert_eq!(row.producer, producer);
            assert_eq!(
                row.downstream_consumer,
                "RCH capacity outage gating and proof-handoff diagnostics"
            );
            assert_eq!(
                row.coverage_requirement,
                ReportSchemaCoverageRequirement::AdvisoryOnly
            );
            assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
            assert_eq!(row.evidence_test, evidence_test);
            assert!(row.snapshot_path.ends_with(snapshot_suffix));
            assert_eq!(
                row.claim_effect,
                ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
            );
        }
    }

    #[test]
    fn inventory_tracks_rch_proof_ledger_report() {
        let inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter()
            .find(|row| row.report_id == "rch_proof_ledger_report")
            .expect("inventory includes rch proof ledger report");

        assert_eq!(
            row.module_path,
            "crates/ffs-harness/src/verification_runner.rs"
        );
        assert_eq!(row.rust_type, "RchProofLedgerReport");
        assert_eq!(row.producer, "rch-proof-ledger");
        assert_eq!(
            row.downstream_consumer,
            "remote RCH proof preservation and readiness action autopilot degraded-proof decisions"
        );
        assert_eq!(
            row.coverage_requirement,
            ReportSchemaCoverageRequirement::AdvisoryOnly
        );
        assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
        assert_eq!(row.evidence_test, "rch_proof_ledger_report_json_shape");
        assert!(row.snapshot_path.ends_with(
            "ffs_harness__verification_runner__tests__rch_proof_ledger_report_json_shape.snap"
        ));
        assert_eq!(
            row.claim_effect,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
        );
    }

    #[test]
    fn inventory_tracks_swarm_operator_validation_report() {
        let inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter()
            .find(|row| row.report_id == "swarm_operator_validation_report")
            .expect("inventory includes swarm operator validation report");

        assert_eq!(
            row.module_path,
            "crates/ffs-harness/src/swarm_operator_report.rs"
        );
        assert_eq!(row.rust_type, "SwarmOperatorValidationReport");
        assert_eq!(row.producer, "validate-swarm-operator-report");
        assert_eq!(
            row.coverage_requirement,
            ReportSchemaCoverageRequirement::AdvisoryOnly
        );
        assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
        assert_eq!(
            row.evidence_test,
            "swarm_operator_validation_report_json_shape"
        );
        assert!(row.snapshot_path.ends_with(
            "ffs_harness__swarm_operator_report__tests__swarm_operator_validation_report_json_shape.snap"
        ));
        assert_eq!(
            row.claim_effect,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
        );
    }

    #[test]
    fn inventory_tracks_readiness_lab_control_plane_reports() {
        let inventory = current_report_schema_inventory();
        for (report_id, rust_type, producer, evidence_test, snapshot_suffix) in [
            (
                "readiness_lab_host_simulation_report",
                "ReadinessLabHostSimulationReport",
                "simulate-readiness-lab-hosts",
                "readiness_lab_host_simulation_report_json_shape",
                "ffs_harness__readiness_lab__tests__readiness_lab_host_simulation_report_json_shape.snap",
            ),
            (
                "readiness_lab_truth_graph_report",
                "ReadinessLabTruthGraphReport",
                "build-readiness-lab-truth-graph",
                "readiness_lab_truth_graph_report_json_shape",
                "ffs_harness__readiness_lab__tests__readiness_lab_truth_graph_report_json_shape.snap",
            ),
        ] {
            let row = inventory
                .rows
                .iter()
                .find(|row| row.report_id == report_id)
                .expect("inventory includes readiness-lab control-plane report");

            assert_eq!(row.rust_type, rust_type);
            assert_eq!(row.producer, producer);
            assert_eq!(
                row.coverage_requirement,
                ReportSchemaCoverageRequirement::AdvisoryOnly
            );
            assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
            assert_eq!(row.evidence_test, evidence_test);
            assert!(row.snapshot_path.ends_with(snapshot_suffix));
            assert_eq!(
                row.claim_effect,
                ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
            );
        }
    }

    #[test]
    fn inventory_tracks_open_ended_and_source_scope_reports() {
        let inventory = current_report_schema_inventory();
        for (report_id, rust_type, producer, evidence_test, snapshot_suffix) in [
            (
                "open_ended_inventory_report",
                "OpenEndedInventoryReport",
                "validate-open-ended-inventory",
                "open_ended_inventory_report_json_shape",
                "ffs_harness__open_ended_inventory__tests__open_ended_inventory_report_json_shape.snap",
            ),
            (
                "open_ended_note_scan_report",
                "OpenEndedNoteScanReport",
                "open-ended-note-scanner",
                "open_ended_note_scan_report_json_shape",
                "ffs_harness__open_ended_inventory__tests__open_ended_note_scan_report_json_shape.snap",
            ),
            (
                "source_scope_manifest_report",
                "SourceScopeManifestReport",
                "validate-source-scope-manifest",
                "source_scope_manifest_report_json_shape",
                "ffs_harness__open_ended_inventory__tests__source_scope_manifest_report_json_shape.snap",
            ),
            (
                "source_scope_scan_report",
                "SourceScopeScanReport",
                "validate-source-scope-manifest",
                "source_scope_scan_report_json_shape",
                "ffs_harness__open_ended_inventory__tests__source_scope_scan_report_json_shape.snap",
            ),
        ] {
            let row = inventory
                .rows
                .iter()
                .find(|row| row.report_id == report_id)
                .expect("inventory includes open-ended/source-scope report");

            assert_eq!(row.module_path, "tools/ffs-ops/src/open_ended_inventory.rs");
            assert_eq!(row.rust_type, rust_type);
            assert_eq!(row.producer, producer);
            assert_eq!(
                row.coverage_requirement,
                ReportSchemaCoverageRequirement::AdvisoryOnly
            );
            assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
            assert_eq!(row.evidence_test, evidence_test);
            assert!(row.snapshot_path.ends_with(snapshot_suffix));
            assert_eq!(
                row.claim_effect,
                ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
            );
        }
    }

    #[test]
    fn inventory_tracks_mounted_writeback_reports() {
        let inventory = current_report_schema_inventory();
        for expectation in MOUNTED_WRITEBACK_REPORT_EXPECTATIONS {
            let row = inventory
                .rows
                .iter()
                .find(|row| row.report_id == expectation.report_id)
                .expect("inventory includes mounted/writeback report");

            assert_eq!(row.module_path, expectation.module_path);
            assert_eq!(row.rust_type, expectation.rust_type);
            assert_eq!(row.producer, expectation.producer);
            assert_eq!(
                row.coverage_requirement,
                ReportSchemaCoverageRequirement::AdvisoryOnly
            );
            assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
            assert_eq!(row.evidence_test, expectation.evidence_test);
            assert!(row.snapshot_path.ends_with(expectation.snapshot_suffix));
            assert_eq!(
                row.claim_effect,
                ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
            );
        }
    }

    #[test]
    fn inventory_tracks_mounted_oracle_recovery_reports() {
        let inventory = current_report_schema_inventory();
        for (report_id, module_path, rust_type, producer, evidence_test, snapshot_suffix) in [
            (
                "mounted_checkpoint_survivor_report",
                "crates/ffs-harness/src/mounted_checkpoint_survivor.rs",
                "MountedCheckpointSurvivorReport",
                "validate-mounted-checkpoint-survivor",
                "mounted_checkpoint_survivor_report_json_shape",
                "ffs_harness__mounted_checkpoint_survivor__tests__mounted_checkpoint_survivor_report_json_shape.snap",
            ),
            (
                "mounted_differential_validation_report",
                "crates/ffs-harness/src/mounted_differential_oracle.rs",
                "MountedDifferentialValidationReport",
                "validate-mounted-differential-oracle",
                "mounted_differential_validation_report_json_shape",
                "ffs_harness__mounted_differential_oracle__tests__mounted_differential_validation_report_json_shape.snap",
            ),
            (
                "mounted_recovery_matrix_report",
                "crates/ffs-harness/src/mounted_recovery_matrix.rs",
                "MountedRecoveryMatrixReport",
                "validate-mounted-recovery-matrix",
                "mounted_recovery_matrix_report_json_shape",
                "ffs_harness__mounted_recovery_matrix__tests__mounted_recovery_matrix_report_json_shape.snap",
            ),
        ] {
            let row = inventory
                .rows
                .iter()
                .find(|row| row.report_id == report_id)
                .expect("inventory includes mounted/oracle recovery report");

            assert_eq!(row.module_path, module_path);
            assert_eq!(row.rust_type, rust_type);
            assert_eq!(row.producer, producer);
            assert_eq!(
                row.coverage_requirement,
                ReportSchemaCoverageRequirement::AdvisoryOnly
            );
            assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
            assert_eq!(row.evidence_test, evidence_test);
            assert!(row.snapshot_path.ends_with(snapshot_suffix));
            assert_eq!(
                row.claim_effect,
                ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
            );
        }
    }

    #[test]
    fn inventory_tracks_adaptive_runtime_and_swarm_reports() {
        let inventory = current_report_schema_inventory();
        for (report_id, module_path, rust_type, producer, evidence_test, snapshot_suffix) in [
            (
                "adaptive_runtime_evidence_report",
                "crates/ffs-harness/src/adaptive_runtime_manifest.rs",
                "AdaptiveRuntimeEvidenceReport",
                "validate-adaptive-runtime-manifest",
                "adaptive_runtime_evidence_report_json_shape",
                "ffs_harness__adaptive_runtime_manifest__tests__adaptive_runtime_evidence_report_json_shape.snap",
            ),
            (
                "adaptive_runtime_runner_report",
                "crates/ffs-harness/src/adaptive_runtime_manifest.rs",
                "AdaptiveRuntimeRunnerReport",
                "adaptive-runtime-runner",
                "adaptive_runtime_runner_report_json_shape",
                "ffs_harness__adaptive_runtime_manifest__tests__adaptive_runtime_runner_report_json_shape.snap",
            ),
            (
                "runtime_console_report",
                "crates/ffs-harness/src/runtime_console_report.rs",
                "RuntimeConsoleReport + RuntimeConsoleValidationReport",
                "validate_runtime_console_report",
                "runtime_console_report_json_shape",
                "ffs_harness__runtime_console_report__tests__runtime_console_report_json_shape.snap",
            ),
            (
                "numa_allocation_placement_report",
                "crates/ffs-harness/src/numa_allocation_placement_report.rs",
                "NumaAllocationPlacementReport + NumaPlacementValidationReport",
                "validate-numa-allocation-placement",
                "numa_allocation_placement_report_json_shape",
                "ffs_harness__numa_allocation_placement_report__tests__numa_allocation_placement_report_json_shape.snap",
            ),
            (
                "topology_runtime_advisor_report",
                "crates/ffs-harness/src/topology_runtime_advisor.rs",
                "TopologyRuntimeAdvisorReport",
                "validate-topology-runtime-advisor",
                "topology_runtime_advisor_report_json_shape",
                "ffs_harness__topology_runtime_advisor__tests__topology_runtime_advisor_report_json_shape.snap",
            ),
            (
                "topology_runtime_advisor_scoring_report",
                "crates/ffs-harness/src/topology_runtime_advisor.rs",
                "TopologyRuntimeAdvisorScoringReport",
                "score-topology-runtime-advisor",
                "topology_runtime_advisor_scoring_report_json_shape",
                "ffs_harness__topology_runtime_advisor__tests__topology_runtime_advisor_scoring_report_json_shape.snap",
            ),
            (
                "swarm_cache_controller_report",
                "crates/ffs-harness/src/swarm_cache_controller.rs",
                "SwarmCacheValidationReport",
                "validate-swarm-cache-controller",
                "swarm_cache_controller_report_json_shape",
                "ffs_harness__swarm_cache_controller__tests__swarm_cache_controller_report_json_shape.snap",
            ),
            (
                "swarm_tail_latency_report",
                "crates/ffs-harness/src/swarm_tail_latency.rs",
                "SwarmTailLatencyReport",
                "validate-swarm-tail-latency",
                "swarm_tail_latency_report_json_shape",
                "ffs_harness__swarm_tail_latency__tests__swarm_tail_latency_report_json_shape.snap",
            ),
        ] {
            let row = inventory
                .rows
                .iter()
                .find(|row| row.report_id == report_id)
                .expect("inventory includes adaptive-runtime/swarm report");

            assert_eq!(row.module_path, module_path);
            assert_eq!(row.rust_type, rust_type);
            assert_eq!(row.producer, producer);
            assert_eq!(
                row.coverage_requirement,
                ReportSchemaCoverageRequirement::AdvisoryOnly
            );
            assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
            assert_eq!(row.evidence_test, evidence_test);
            assert!(row.snapshot_path.ends_with(snapshot_suffix));
            assert_eq!(
                row.claim_effect,
                ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
            );
        }
    }

    #[test]
    fn inventory_tracks_proof_and_risk_reports() {
        let inventory = current_report_schema_inventory();
        for (report_id, module_path, rust_type, producer, evidence_test, snapshot_suffix) in [
            (
                "adversarial_threat_model_report",
                "crates/ffs-harness/src/adversarial_threat_model.rs",
                "AdversarialThreatModelReport",
                "validate-adversarial-threat-model",
                "adversarial_threat_model_report_json_shape",
                "ffs_harness__adversarial_threat_model__tests__adversarial_threat_model_report_json_shape.snap",
            ),
            (
                "ambition_evidence_matrix_report",
                "tools/ffs-ops/src/ambition_evidence_matrix.rs",
                "AmbitionEvidenceMatrixReport",
                "validate-ambition-evidence-matrix",
                "ambition_evidence_matrix_report_json_shape",
                "ffs_harness__ambition_evidence_matrix__tests__ambition_evidence_matrix_report_json_shape.snap",
            ),
            (
                "cross_oracle_arbitration_report",
                "crates/ffs-harness/src/cross_oracle_arbitration.rs",
                "CrossOracleArbitrationReport",
                "validate-cross-oracle-arbitration",
                "cross_oracle_arbitration_report_json_shape",
                "ffs_harness__cross_oracle_arbitration__tests__cross_oracle_arbitration_report_json_shape.snap",
            ),
            (
                "cross_oracle_arbitration_validation_report",
                "crates/ffs-harness/src/cross_oracle_arbitration.rs",
                "CrossOracleArbitrationValidationReport",
                "validate-cross-oracle-arbitration",
                "cross_oracle_arbitration_validation_report_json_shape",
                "ffs_harness__cross_oracle_arbitration__tests__cross_oracle_arbitration_validation_report_json_shape.snap",
            ),
            (
                "invariant_oracle_consumer_report",
                "crates/ffs-harness/src/invariant_oracle.rs",
                "InvariantOracleConsumerReport",
                "validate-invariant-oracle --report",
                "invariant_oracle_consumer_report_json_shape",
                "ffs_harness__invariant_oracle__tests__invariant_oracle_consumer_report_json_shape.snap",
            ),
            (
                "invariant_oracle_report",
                "crates/ffs-harness/src/invariant_oracle.rs",
                "InvariantOracleReport",
                "validate-invariant-oracle",
                "invariant_oracle_report_json_shape",
                "ffs_harness__invariant_oracle__tests__invariant_oracle_report_json_shape.snap",
            ),
            (
                "proof_overhead_budget_report",
                "crates/ffs-harness/src/proof_overhead_budget.rs",
                "ProofOverheadBudgetReport",
                "validate-proof-overhead-budget",
                "proof_overhead_budget_report_json_shape",
                "ffs_harness__proof_overhead_budget__tests__proof_overhead_budget_report_json_shape.snap",
            ),
        ] {
            let row = inventory
                .rows
                .iter()
                .find(|row| row.report_id == report_id)
                .expect("inventory includes proof/risk report");

            assert_eq!(row.module_path, module_path);
            assert_eq!(row.rust_type, rust_type);
            assert_eq!(row.producer, producer);
            assert_eq!(
                row.coverage_requirement,
                ReportSchemaCoverageRequirement::AdvisoryOnly
            );
            assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
            assert_eq!(row.evidence_test, evidence_test);
            assert!(row.snapshot_path.ends_with(snapshot_suffix));
            assert_eq!(
                row.claim_effect,
                ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
            );
        }
    }

    #[test]
    fn inventory_tracks_recovery_and_remediation_reports() {
        let inventory = current_report_schema_inventory();
        for (report_id, module_path, rust_type, producer, evidence_test, snapshot_suffix) in [
            (
                "operator_recovery_drill_report",
                "crates/ffs-harness/src/operator_recovery_drill.rs",
                "OperatorRecoveryDrillReport",
                "validate-operator-recovery-drill",
                "operator_recovery_drill_report_json_shape",
                "ffs_harness__operator_recovery_drill__tests__operator_recovery_drill_report_json_shape.snap",
            ),
            (
                "remediation_catalog_report",
                "crates/ffs-harness/src/remediation_catalog.rs",
                "RemediationCatalogReport",
                "validate-remediation-catalog",
                "remediation_catalog_report_json_shape",
                "ffs_harness__remediation_catalog__tests__remediation_catalog_report_json_shape.snap",
            ),
            (
                "remediation_severity_gate_report",
                "crates/ffs-harness/src/remediation_severity_gate.rs",
                "RemediationSeverityGateReport",
                "validate-remediation-severity-gate",
                "remediation_severity_gate_report_json_shape",
                "ffs_harness__remediation_severity_gate__tests__remediation_severity_gate_report_json_shape.snap",
            ),
            (
                "repair_confidence_lab_report",
                "crates/ffs-harness/src/repair_confidence_lab.rs",
                "RepairConfidenceLabReport",
                "validate-repair-confidence-lab",
                "repair_confidence_lab_report_json_shape",
                "ffs_harness__repair_confidence_lab__tests__repair_confidence_lab_report_json_shape.snap",
            ),
            (
                "scrub_repair_scheduler_report",
                "crates/ffs-harness/src/scrub_repair_scheduler.rs",
                "ScrubRepairSchedulerReport",
                "validate-scrub-repair-scheduler",
                "scrub_repair_scheduler_report_json_shape",
                "ffs_harness__scrub_repair_scheduler__tests__scrub_repair_scheduler_report_json_shape.snap",
            ),
            (
                "support_state_accounting_report",
                "crates/ffs-harness/src/support_state_accounting.rs",
                "SupportStateAccountingReport",
                "validate-support-state-accounting",
                "support_state_accounting_report_json_shape",
                "ffs_harness__support_state_accounting__tests__support_state_accounting_report_json_shape.snap",
            ),
        ] {
            let row = inventory
                .rows
                .iter()
                .find(|row| row.report_id == report_id)
                .expect("inventory includes recovery/remediation report");

            assert_eq!(row.module_path, module_path);
            assert_eq!(row.rust_type, rust_type);
            assert_eq!(row.producer, producer);
            assert_eq!(
                row.coverage_requirement,
                ReportSchemaCoverageRequirement::AdvisoryOnly
            );
            assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
            assert_eq!(row.evidence_test, evidence_test);
            assert!(row.snapshot_path.ends_with(snapshot_suffix));
            assert_eq!(
                row.claim_effect,
                ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
            );
        }
    }

    #[test]
    fn inventory_tracks_tabletop_drill_json_contracts() {
        let inventory = current_report_schema_inventory();
        for (report_id, rust_type, producer, downstream_consumer, evidence_test, snapshot_suffix) in [
            (
                "tabletop_drill_canonical_drills",
                "Vec<DrillScenario>",
                "canonical_drills",
                "operator tooling gate and tabletop drill E2E catalog",
                "canonical_drills_json_shape",
                "ffs_harness__tabletop_drill__tests__canonical_drills_json_shape.snap",
            ),
            (
                "tabletop_drill_result",
                "Vec<DrillResult>",
                "execute_all_drills",
                "operator tabletop drill remediation-gap tracker and E2E gates",
                "drill_result_json_shape",
                "ffs_harness__tabletop_drill__tests__drill_result_json_shape.snap",
            ),
        ] {
            let row = inventory
                .rows
                .iter()
                .find(|row| row.report_id == report_id)
                .expect("inventory includes tabletop drill JSON contract");

            assert_eq!(row.module_path, "crates/ffs-harness/src/tabletop_drill.rs");
            assert_eq!(row.rust_type, rust_type);
            assert_eq!(row.producer, producer);
            assert_eq!(row.downstream_consumer, downstream_consumer);
            assert_eq!(
                row.coverage_requirement,
                ReportSchemaCoverageRequirement::AdvisoryOnly
            );
            assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
            assert_eq!(row.evidence_test, evidence_test);
            assert!(row.snapshot_path.ends_with(snapshot_suffix));
            assert_eq!(
                row.claim_effect,
                ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
            );
        }
    }

    #[test]
    fn inventory_tracks_deferred_parity_gap_class_contract() {
        let inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter()
            .find(|row| row.report_id == "deferred_parity_audit_gap_classes")
            .expect("inventory includes deferred parity audit gap classes");

        assert_eq!(
            row.module_path,
            "crates/ffs-harness/src/deferred_parity_audit.rs"
        );
        assert_eq!(row.rust_type, "[&str; 20]");
        assert_eq!(row.producer, "GAP_CLASSES");
        assert_eq!(
            row.downstream_consumer,
            "deferred parity audit classifier and release-gate downgrade policy"
        );
        assert_eq!(
            row.coverage_requirement,
            ReportSchemaCoverageRequirement::AdvisoryOnly
        );
        assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
        assert_eq!(row.evidence_test, "gap_classes_json_shape");
        assert!(
            row.snapshot_path.ends_with(
                "ffs_harness__deferred_parity_audit__tests__gap_classes_json_shape.snap"
            )
        );
        assert_eq!(
            row.claim_effect,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
        );
    }

    #[test]
    fn inventory_tracks_performance_baseline_manifest_report() {
        let inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter()
            .find(|row| row.report_id == "performance_baseline_manifest_report")
            .expect("inventory includes performance baseline manifest report");

        assert_eq!(
            row.module_path,
            "crates/ffs-harness/src/performance_baseline_manifest.rs"
        );
        assert_eq!(row.rust_type, "PerformanceBaselineManifestReport");
        assert_eq!(row.producer, "validate-performance-baseline-manifest");
        assert_eq!(
            row.coverage_requirement,
            ReportSchemaCoverageRequirement::AdvisoryOnly
        );
        assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
        assert_eq!(
            row.evidence_test,
            "performance_baseline_manifest_report_json_shape"
        );
        assert!(row.snapshot_path.ends_with(
            "ffs_harness__performance_baseline_manifest__tests__performance_baseline_manifest_report_json_shape.snap"
        ));
        assert_eq!(
            row.claim_effect,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
        );
    }

    #[test]
    fn inventory_tracks_performance_delta_closeout_report() {
        let inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter()
            .find(|row| row.report_id == "performance_delta_closeout_report")
            .expect("inventory includes performance delta closeout report");

        assert_eq!(
            row.module_path,
            "crates/ffs-harness/src/performance_delta_closeout.rs"
        );
        assert_eq!(row.rust_type, "PerformanceDeltaCloseoutReport");
        assert_eq!(row.producer, "performance-delta-closeout");
        assert_eq!(
            row.coverage_requirement,
            ReportSchemaCoverageRequirement::AdvisoryOnly
        );
        assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
        assert_eq!(
            row.evidence_test,
            "performance_delta_closeout_report_json_shape"
        );
        assert!(row.snapshot_path.ends_with(
            "ffs_harness__performance_delta_closeout__tests__performance_delta_closeout_report_json_shape.snap"
        ));
        assert_eq!(
            row.claim_effect,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
        );
    }

    #[test]
    fn inventory_tracks_performance_helper_schemas() {
        let inventory = current_report_schema_inventory();
        for (
            report_id,
            module_path,
            rust_type,
            producer,
            downstream_consumer,
            evidence_test,
            snapshot_suffix,
        ) in [
            (
                "perf_comparison_context",
                "crates/ffs-harness/src/perf_comparison.rs",
                "ComparisonContext",
                "RegressionComparator::compare_with_context",
                "performance comparator structured log context and regression triage consumers",
                "comparison_context_json_shape",
                "ffs_harness__perf_comparison__tests__comparison_context_json_shape.snap",
            ),
            (
                "hysteresis_tracker",
                "crates/ffs-harness/src/perf_comparison.rs",
                "HysteresisTracker",
                "HysteresisTracker::record",
                "performance regression anti-flake state and runbook triage consumers",
                "hysteresis_tracker_json_shape",
                "ffs_harness__perf_comparison__tests__hysteresis_tracker_json_shape.snap",
            ),
            (
                "perf_regression_baseline",
                "crates/ffs-harness/src/perf_regression.rs",
                "PerfBaseline",
                "parse_baseline",
                "benchmark_record baseline parser and performance regression thresholds",
                "perf_baseline_json_shape",
                "ffs_harness__perf_regression__tests__perf_baseline_json_shape.snap",
            ),
            (
                "perf_triage_decision",
                "crates/ffs-harness/src/perf_triage.rs",
                "TriageDecision",
                "classify_triage",
                "performance regression triage runbook and operator follow-up routing",
                "triage_decision_json_shape",
                "ffs_harness__perf_triage__tests__triage_decision_json_shape.snap",
            ),
        ] {
            let row = inventory
                .rows
                .iter()
                .find(|row| row.report_id == report_id)
                .expect("inventory includes performance helper schema");

            assert_eq!(row.module_path, module_path);
            assert_eq!(row.rust_type, rust_type);
            assert_eq!(row.producer, producer);
            assert_eq!(row.downstream_consumer, downstream_consumer);
            assert_eq!(
                row.coverage_requirement,
                ReportSchemaCoverageRequirement::AdvisoryOnly
            );
            assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
            assert_eq!(row.evidence_test, evidence_test);
            assert!(row.snapshot_path.ends_with(snapshot_suffix));
            assert_eq!(
                row.claim_effect,
                ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
            );
        }
    }

    #[test]
    fn inventory_tracks_fuzz_dashboard_json_contracts() {
        let inventory = current_report_schema_inventory();
        for (report_id, rust_type, producer, downstream_consumer, evidence_test, snapshot_suffix) in [
            (
                "fuzz_dashboard_campaign_summary",
                "CampaignSummary",
                "fuzz/scripts/nightly_fuzz.sh",
                "fuzz dashboard health assessment and trend visibility gates",
                "campaign_summary_json_shape",
                "ffs_harness__fuzz_dashboard__tests__campaign_summary_json_shape.snap",
            ),
            (
                "fuzz_dashboard_regression_alert",
                "RegressionAlert",
                "detect_regressions",
                "fuzz dashboard regression alerts and operator triage",
                "regression_alert_json_shape",
                "ffs_harness__fuzz_dashboard__tests__regression_alert_json_shape.snap",
            ),
        ] {
            let row = inventory
                .rows
                .iter()
                .find(|row| row.report_id == report_id)
                .expect("inventory includes fuzz dashboard JSON contract");

            assert_eq!(row.module_path, "crates/ffs-harness/src/fuzz_dashboard.rs");
            assert_eq!(row.rust_type, rust_type);
            assert_eq!(row.producer, producer);
            assert_eq!(row.downstream_consumer, downstream_consumer);
            assert_eq!(
                row.coverage_requirement,
                ReportSchemaCoverageRequirement::AdvisoryOnly
            );
            assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
            assert_eq!(row.evidence_test, evidence_test);
            assert!(row.snapshot_path.ends_with(snapshot_suffix));
            assert_eq!(
                row.claim_effect,
                ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
            );
        }
    }

    #[test]
    fn inventory_tracks_fuzz_smoke_report() {
        let inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter()
            .find(|row| row.report_id == "fuzz_smoke_report")
            .expect("inventory includes fuzz smoke report");

        assert_eq!(row.module_path, "crates/ffs-harness/src/fuzz_smoke.rs");
        assert_eq!(row.rust_type, "FuzzSmokeReport");
        assert_eq!(row.producer, "validate-fuzz-smoke");
        assert_eq!(
            row.coverage_requirement,
            ReportSchemaCoverageRequirement::AdvisoryOnly
        );
        assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
        assert_eq!(row.evidence_test, "fuzz_smoke_report_json_shape");
        assert!(
            row.snapshot_path
                .ends_with("ffs_harness__fuzz_smoke__tests__fuzz_smoke_report_json_shape.snap")
        );
        assert_eq!(
            row.claim_effect,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
        );
    }

    #[test]
    fn inventory_tracks_xfstests_baseline_manifest() {
        let inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter()
            .find(|row| row.report_id == "xfstests_baseline_manifest")
            .expect("inventory includes xfstests baseline manifest");

        assert_eq!(row.module_path, "crates/ffs-harness/src/xfstests.rs");
        assert_eq!(row.rust_type, "XfstestsBaselineManifest");
        assert_eq!(row.producer, "xfstests-baseline-manifest");
        assert_eq!(
            row.downstream_consumer,
            "xfstests baseline dry-run evidence and failure triage input"
        );
        assert_eq!(
            row.coverage_requirement,
            ReportSchemaCoverageRequirement::AdvisoryOnly
        );
        assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
        assert_eq!(row.evidence_test, "xfstests_baseline_manifest_json_shape");
        assert!(
            row.snapshot_path.ends_with(
                "ffs_harness__xfstests__tests__xfstests_baseline_manifest_json_shape.snap"
            )
        );
        assert_eq!(
            row.claim_effect,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
        );
    }

    #[test]
    fn inventory_tracks_xfstests_failure_triage_report() {
        let inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter()
            .find(|row| row.report_id == "xfstests_failure_triage_report")
            .expect("inventory includes xfstests failure triage report");

        assert_eq!(row.module_path, "crates/ffs-harness/src/xfstests.rs");
        assert_eq!(row.rust_type, "XfstestsFailureTriageReport");
        assert_eq!(row.producer, "xfstests-failure-triage");
        assert_eq!(
            row.downstream_consumer,
            "xfstests product-failure triage and follow-up bead extraction"
        );
        assert_eq!(
            row.coverage_requirement,
            ReportSchemaCoverageRequirement::AdvisoryOnly
        );
        assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
        assert_eq!(
            row.evidence_test,
            "xfstests_failure_triage_report_json_shape"
        );
        assert!(row.snapshot_path.ends_with(
            "ffs_harness__xfstests__tests__xfstests_failure_triage_report_json_shape.snap"
        ));
        assert_eq!(
            row.claim_effect,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
        );
    }

    #[test]
    fn inventory_tracks_e2e_repro_report_schemas() {
        let inventory = current_report_schema_inventory();
        for (report_id, rust_type, producer, downstream_consumer, evidence_test, snapshot_suffix) in [
            (
                "crash_replay_suite_report",
                "CrashReplaySuiteReport",
                "run-crash-replay",
                "deterministic crash replay schedule artifacts and repro packs",
                "crash_replay_suite_report_json_shape",
                "ffs_harness__e2e__tests__crash_replay_suite_report_json_shape.snap",
            ),
            (
                "fsx_stress_report",
                "FsxStressReport",
                "run-fsx-stress",
                "fsx-style stress artifacts and repair-integrity repro packs",
                "fsx_stress_report_json_shape",
                "ffs_harness__e2e__tests__fsx_stress_report_json_shape.snap",
            ),
        ] {
            let row = inventory
                .rows
                .iter()
                .find(|row| row.report_id == report_id)
                .expect("inventory includes e2e repro report");

            assert_eq!(row.module_path, "crates/ffs-harness/src/e2e.rs");
            assert_eq!(row.rust_type, rust_type);
            assert_eq!(row.producer, producer);
            assert_eq!(row.downstream_consumer, downstream_consumer);
            assert_eq!(
                row.coverage_requirement,
                ReportSchemaCoverageRequirement::AdvisoryOnly
            );
            assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
            assert_eq!(row.evidence_test, evidence_test);
            assert!(row.snapshot_path.ends_with(snapshot_suffix));
            assert_eq!(
                row.claim_effect,
                ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
            );
        }
    }

    #[test]
    fn inventory_tracks_crash_replay_artifact_report() {
        let inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter()
            .find(|row| row.report_id == "crash_replay_artifact_report")
            .expect("inventory includes crash replay artifact report");

        assert_eq!(
            row.module_path,
            "crates/ffs-harness/src/crash_replay_artifact.rs"
        );
        assert_eq!(row.rust_type, "CrashReplayArtifactReport");
        assert_eq!(row.producer, "validate_default_crash_replay_artifact");
        assert_eq!(
            row.downstream_consumer,
            "crash replay artifact survivor-set verification and fail-closed proof handoff"
        );
        assert_eq!(
            row.coverage_requirement,
            ReportSchemaCoverageRequirement::AdvisoryOnly
        );
        assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
        assert_eq!(row.evidence_test, "crash_replay_artifact_report_json_shape");
        assert!(row.snapshot_path.ends_with(
            "ffs_harness__crash_replay_artifact__tests__crash_replay_artifact_report_json_shape.snap"
        ));
        assert_eq!(
            row.claim_effect,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
        );
    }

    #[test]
    fn inventory_tracks_governance_and_durability_reports() {
        let inventory = current_report_schema_inventory();
        for (report_id, module_path, rust_type, producer, evidence_test, snapshot_suffix) in [
            (
                "chaos_replay_lab_report",
                "crates/ffs-harness/src/chaos_replay_lab.rs",
                "ChaosReplayLabReport",
                "validate-chaos-replay-lab",
                "chaos_replay_lab_report_json_shape",
                "ffs_harness__chaos_replay_lab__tests__chaos_replay_lab_report_json_shape.snap",
            ),
            (
                "deferred_parity_audit_report",
                "crates/ffs-harness/src/deferred_parity_audit.rs",
                "DeferredParityAuditReport",
                "validate-deferred-parity-audit",
                "deferred_parity_audit_report_json_shape",
                "ffs_harness__deferred_parity_audit__tests__deferred_parity_audit_report_json_shape.snap",
            ),
            (
                "deferred_parity_audit_gap_classes",
                "crates/ffs-harness/src/deferred_parity_audit.rs",
                "[&str; 20]",
                "GAP_CLASSES",
                "gap_classes_json_shape",
                "ffs_harness__deferred_parity_audit__tests__gap_classes_json_shape.snap",
            ),
            (
                "docs_status_drift_report",
                "tools/ffs-ops/src/docs_status_drift.rs",
                "DocsStatusDriftReport",
                "validate-docs-status-drift",
                "docs_status_drift_report_json_shape",
                "ffs_harness__docs_status_drift__tests__docs_status_drift_report_json_shape.snap",
            ),
            (
                "oq_decision_matrix_canonical_matrix",
                "crates/ffs-harness/src/oq_decision_matrix.rs",
                "Vec<OqDecision>",
                "canonical_matrix",
                "canonical_matrix_json_shape",
                "ffs_harness__oq_decision_matrix__tests__canonical_matrix_json_shape.snap",
            ),
            (
                "inventory_closeout_gate_report",
                "crates/ffs-harness/src/inventory_closeout_gate.rs",
                "InventoryCloseoutReport",
                "validate-inventory-closeout-gate",
                "inventory_closeout_gate_report_json_shape",
                "ffs_harness__inventory_closeout_gate__tests__inventory_closeout_gate_report_json_shape.snap",
            ),
            (
                "low_privilege_demo_sandbox_report",
                "crates/ffs-harness/src/low_privilege_demo_sandbox.rs",
                "LowPrivilegeDemoSandboxReport",
                "validate-low-privilege-demo-sandbox",
                "low_privilege_demo_sandbox_report_json_shape",
                "ffs_harness__low_privilege_demo_sandbox__tests__low_privilege_demo_sandbox_report_json_shape.snap",
            ),
            (
                "soak_canary_campaign_report",
                "crates/ffs-harness/src/soak_canary_campaign.rs",
                "SoakCanaryCampaignReport",
                "validate-soak-canary-campaigns",
                "soak_canary_campaign_report_json_shape",
                "ffs_harness__soak_canary_campaign__tests__soak_canary_campaign_report_json_shape.snap",
            ),
            (
                "wal_group_commit_gate_report",
                "crates/ffs-harness/src/wal_group_commit_gate.rs",
                "WalGroupCommitGateReport",
                "validate-wal-group-commit-gate",
                "wal_group_commit_gate_report_json_shape",
                "ffs_harness__wal_group_commit_gate__tests__wal_group_commit_gate_report_json_shape.snap",
            ),
        ] {
            let row = inventory
                .rows
                .iter()
                .find(|row| row.report_id == report_id)
                .expect("inventory includes governance/durability report");

            assert_eq!(row.module_path, module_path);
            assert_eq!(row.rust_type, rust_type);
            assert_eq!(row.producer, producer);
            assert_eq!(
                row.coverage_requirement,
                ReportSchemaCoverageRequirement::AdvisoryOnly
            );
            assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
            assert_eq!(row.evidence_test, evidence_test);
            assert!(row.snapshot_path.ends_with(snapshot_suffix));
            assert_eq!(
                row.claim_effect,
                ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
            );
        }
    }

    #[test]
    fn inventory_tracks_oq_decision_matrix_schema() {
        let inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter()
            .find(|row| row.report_id == "oq_decision_matrix_canonical_matrix")
            .expect("inventory includes OQ decision matrix schema");

        assert_eq!(
            row.module_path,
            "crates/ffs-harness/src/oq_decision_matrix.rs"
        );
        assert_eq!(row.rust_type, "Vec<OqDecision>");
        assert_eq!(row.producer, "canonical_matrix");
        assert_eq!(
            row.downstream_consumer,
            "OQ decision integration gate and program-gate decision capture"
        );
        assert_eq!(
            row.coverage_requirement,
            ReportSchemaCoverageRequirement::AdvisoryOnly
        );
        assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
        assert_eq!(row.evidence_test, "canonical_matrix_json_shape");
        assert!(
            row.snapshot_path.ends_with(
                "ffs_harness__oq_decision_matrix__tests__canonical_matrix_json_shape.snap"
            )
        );
        assert_eq!(
            row.claim_effect,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
        );
    }

    #[test]
    fn inventory_tracks_required_control_plane_contract_schema() {
        let inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter()
            .find(|row| row.report_id == "authoritative_environment_decision")
            .expect("inventory includes authoritative environment decision");

        assert_eq!(
            row.module_path,
            "crates/ffs-harness/src/authoritative_environment_manifest.rs"
        );
        assert_eq!(row.rust_type, "AuthoritativeEnvironmentDecision");
        assert_eq!(row.producer, "record-authoritative-environment-manifest");
        assert_eq!(
            row.coverage_requirement,
            ReportSchemaCoverageRequirement::Required
        );
        assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
        assert_eq!(
            row.evidence_test,
            "authoritative_environment_decision_json_shape"
        );
        assert!(row.snapshot_path.ends_with(
            "ffs_harness__authoritative_environment_manifest__tests__authoritative_environment_decision_json_shape.snap"
        ));
        assert_eq!(
            row.claim_effect,
            ReportSchemaClaimEffect::ExistingReleaseGateInput
        );
    }

    #[test]
    fn inventory_tracks_required_authoritative_manifest_contract_schemas() {
        let inventory = current_report_schema_inventory();
        for (report_id, module_path, rust_type, producer, evidence_test, snapshot_suffix) in [
            (
                "authoritative_lane_manifest",
                "crates/ffs-harness/src/authoritative_lane_manifest.rs",
                "AuthoritativeLaneManifest",
                "authoritative lane manifest evaluator",
                "authoritative_lane_manifest_json_shape",
                "ffs_harness__authoritative_lane_manifest__tests__authoritative_lane_manifest_json_shape.snap",
            ),
            (
                "authoritative_environment_manifest",
                "crates/ffs-harness/src/authoritative_environment_manifest.rs",
                "AuthoritativeEnvironmentManifest",
                "record-authoritative-environment-manifest",
                "authoritative_environment_manifest_json_shape",
                "ffs_harness__authoritative_environment_manifest__tests__authoritative_environment_manifest_json_shape.snap",
            ),
        ] {
            let row = inventory
                .rows
                .iter()
                .find(|row| row.report_id == report_id)
                .expect("inventory includes authoritative manifest contract");

            assert_eq!(row.module_path, module_path);
            assert_eq!(row.rust_type, rust_type);
            assert_eq!(row.producer, producer);
            assert_eq!(
                row.coverage_requirement,
                ReportSchemaCoverageRequirement::Required
            );
            assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
            assert_eq!(row.evidence_test, evidence_test);
            assert!(row.snapshot_path.ends_with(snapshot_suffix));
            assert_eq!(
                row.claim_effect,
                ReportSchemaClaimEffect::ExistingReleaseGateInput
            );
        }
    }

    #[test]
    fn inventory_tracks_advisory_control_plane_contract_schemas() {
        let inventory = current_report_schema_inventory();
        for (report_id, module_path, rust_type, producer, evidence_test, snapshot_suffix) in [
            (
                "artifact_schema_fixture_report",
                "crates/ffs-harness/src/artifact_manifest.rs",
                "ArtifactSchemaFixtureReport",
                "validate-artifact-schema-fixtures",
                "artifact_schema_fixture_report_json_shape",
                "ffs_harness__artifact_manifest__tests__artifact_schema_fixture_report_json_shape.snap",
            ),
            (
                "btrfs_capability_drift_contract",
                "crates/ffs-harness/src/btrfs_capability_drift.rs",
                "Vec<CapabilityContractRow> + Vec<DriftCheckResult>",
                "btrfs capability drift detector",
                "btrfs_capability_drift_contract_json_shape",
                "ffs_harness__btrfs_capability_drift__tests__btrfs_capability_drift_contract_json_shape.snap",
            ),
            (
                "canonical_error_scenarios",
                "crates/ffs-harness/src/error_taxonomy.rs",
                "Vec<ErrorScenario>",
                "canonical error taxonomy",
                "canonical_error_scenarios_json_shape",
                "ffs_harness__error_taxonomy__tests__canonical_error_scenarios_json_shape.snap",
            ),
            (
                "consistency_verdict",
                "crates/ffs-harness/src/health_consistency.rs",
                "ConsistencyVerdict",
                "health consistency validator",
                "consistency_verdict_json_shape",
                "ffs_harness__health_consistency__tests__consistency_verdict_json_shape.snap",
            ),
            (
                "benchmark_taxonomy",
                "crates/ffs-harness/src/benchmark_taxonomy.rs",
                "Taxonomy",
                "canonical benchmark taxonomy",
                "canonical_taxonomy_json_snapshot",
                "ffs_harness__benchmark_taxonomy__tests__canonical_taxonomy_v1.snap",
            ),
            (
                "metrics_snapshot",
                "crates/ffs-harness/src/metrics.rs",
                "MetricsSnapshot",
                "metrics registry snapshot",
                "snapshot_json_serialization_shape",
                "ffs_harness__metrics__tests__snapshot_json_serialization_shape.snap",
            ),
            (
                "promotion_result",
                "crates/ffs-harness/src/crash_promotion.rs",
                "PromotionResult",
                "crash promotion pipeline",
                "promotion_result_json_shape",
                "ffs_harness__crash_promotion__tests__promotion_result_json_shape.snap",
            ),
            (
                "structured_log_contract",
                "crates/ffs-harness/src/log_contract.rs",
                "Structured log contract constants",
                "structured log contract",
                "structured_log_contract_json_shape",
                "ffs_harness__log_contract__tests__structured_log_contract_json_shape.snap",
            ),
        ] {
            let row = inventory
                .rows
                .iter()
                .find(|row| row.report_id == report_id)
                .expect("inventory includes control-plane schema report");

            assert_eq!(row.module_path, module_path);
            assert_eq!(row.rust_type, rust_type);
            assert_eq!(row.producer, producer);
            assert_eq!(
                row.coverage_requirement,
                ReportSchemaCoverageRequirement::AdvisoryOnly
            );
            assert_eq!(row.coverage_status, ReportSchemaCoverageStatus::Covered);
            assert_eq!(row.evidence_test, evidence_test);
            assert!(row.snapshot_path.ends_with(snapshot_suffix));
            assert_eq!(
                row.claim_effect,
                ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange
            );
        }
    }

    #[test]
    fn render_report_schema_inventory_markdown_default_report() -> Result<()> {
        let inventory = current_report_schema_inventory();
        let report = validate_report_schema_inventory(&inventory);
        if !report.errors.is_empty() {
            bail!("default inventory has errors: {:?}", report.errors);
        }

        let markdown = render_report_schema_inventory_markdown(&report);
        insta::assert_snapshot!(
            "render_report_schema_inventory_markdown_default_report",
            markdown
        );
        Ok(())
    }

    #[test]
    fn report_schema_inventory_shape() -> Result<()> {
        let inventory = current_report_schema_inventory();
        let report = validate_report_schema_inventory(&inventory);
        if !report.errors.is_empty() {
            bail!("default inventory has errors: {:?}", report.errors);
        }

        let encoded = serde_json::to_string(&inventory)?;
        let decoded: ReportSchemaInventory = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, inventory);
        let report_json = serde_json::to_string_pretty(&report)?;
        let decoded_report: ReportSchemaInventoryReport = serde_json::from_str(&report_json)?;
        assert_eq!(decoded_report, report);

        let shape = json!({
            "schema_version": inventory.schema_version,
            "inventory_id": inventory.inventory_id,
            "product_evidence_claim": report.product_evidence_claim,
            "reproduction_command": report.reproduction_command,
            "report_valid": report.valid,
            "counts": {
                "total_rows": report.total_rows,
                "required_rows": report.required_rows,
                "advisory_only_rows": report.advisory_only_rows,
                "permissioned_only_rows": report.permissioned_only_rows,
                "covered_rows": report.covered_rows,
                "missing_rows": report.missing_rows,
                "excluded_rows": report.excluded_rows,
            },
            "uncovered_required_report_ids": report.uncovered_required_report_ids,
            "first_row": {
                "report_id": inventory.rows[0].report_id,
                "module_path": inventory.rows[0].module_path,
                "rust_type": inventory.rows[0].rust_type,
                "producer": inventory.rows[0].producer,
                "downstream_consumer": inventory.rows[0].downstream_consumer,
                "coverage_requirement": inventory.rows[0].coverage_requirement,
                "coverage_status": inventory.rows[0].coverage_status,
                "evidence_test": inventory.rows[0].evidence_test,
                "snapshot_path": inventory.rows[0].snapshot_path,
                "claim_effect": inventory.rows[0].claim_effect,
            },
            "first_row_result": {
                "report_id": report.row_results[0].report_id,
                "coverage_requirement": report.row_results[0].coverage_requirement,
                "coverage_status": report.row_results[0].coverage_status,
                "module_path": report.row_results[0].module_path,
                "rust_type": report.row_results[0].rust_type,
                "downstream_consumer": report.row_results[0].downstream_consumer,
                "evidence_test": report.row_results[0].evidence_test,
                "snapshot_path": report.row_results[0].snapshot_path,
                "claim_effect": report.row_results[0].claim_effect,
                "missing_evidence": report.row_results[0].missing_evidence,
                "errors": report.row_results[0].errors,
            },
            "required_report_ids": inventory
                .rows
                .iter()
                .filter(|row| row.coverage_requirement == ReportSchemaCoverageRequirement::Required)
                .map(|row| row.report_id.as_str())
                .collect::<Vec<_>>(),
            "excluded_report_ids": inventory
                .rows
                .iter()
                .filter(|row| row.coverage_status == ReportSchemaCoverageStatus::Excluded)
                .map(|row| row.report_id.as_str())
                .collect::<Vec<_>>(),
            "permissioned_only_report_ids": inventory
                .rows
                .iter()
                .filter(|row| {
                    row.coverage_requirement == ReportSchemaCoverageRequirement::PermissionedOnly
                })
                .map(|row| row.report_id.as_str())
                .collect::<Vec<_>>(),
        });
        let json = serde_json::to_string_pretty(&shape)?;

        insta::assert_snapshot!("report_schema_inventory_shape", json);
        Ok(())
    }
}
