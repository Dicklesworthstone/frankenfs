#![allow(clippy::module_name_repetitions, clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! Non-permissioned readiness-lab artifact contracts.
//!
//! These contracts let future agents rehearse large-host and xfstests evidence
//! flows without producing authoritative product evidence. The validator is
//! intentionally strict about advisory claim boundaries so simulated artifacts
//! cannot be promoted into proof-bundle or release-gate pass evidence.

use crate::permissioned_campaign_broker::{
    SwarmCapabilityCalibrationArtifactPlan, SwarmCapabilityCalibrationFuse,
    SwarmCapabilityCalibrationFuseState, SwarmCapabilityCalibrationHost,
    SwarmCapabilityCalibrationIsolation, SwarmCapabilityCalibrationManifest,
    SwarmCapabilityCalibrationResourceCaps, SwarmCapabilityCalibrationValidationConfig,
    SwarmCapabilityCalibrationWorker, validate_swarm_capability_calibration_manifest,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const READINESS_LAB_SCHEMA_VERSION: u32 = 1;
pub const READINESS_LAB_REPORT_SCHEMA_VERSION: u32 = 1;
pub const READINESS_LAB_HOST_SIMULATION_REPORT_SCHEMA_VERSION: u32 = 1;
pub const READINESS_LAB_RCH_LANE_SCHEDULE_REPORT_SCHEMA_VERSION: u32 = 1;
pub const READINESS_LAB_TRUTH_GRAPH_REPORT_SCHEMA_VERSION: u32 = 1;
pub const READINESS_LAB_NUMA_P99_REPLAY_REPORT_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_READINESS_LAB_NUMA_P99_REPLAY_MANIFEST: &str =
    "tests/readiness-lab/numa_p99_replay_fixtures.json";
pub const READINESS_LAB_ADVISORY_NOTICE: &str =
    "advisory readiness-lab material only; not product evidence";
pub const READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM: &str = "none";
pub const READINESS_LAB_ADVISORY_RELEASE_GATE_EFFECT: &str = "advisory_only";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessLabValidationConfig {
    pub manifest_path: String,
    pub reference_epoch_days: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabContractBundle {
    pub schema_version: u32,
    pub lab_id: String,
    pub generated_at_epoch_days: u32,
    pub advisory_notice: String,
    pub artifacts: Vec<ReadinessLabArtifactContract>,
    pub lane_plans: Vec<ReadinessLabLanePlan>,
    pub rch_assumptions: Vec<ReadinessLabRchAssumption>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabArtifactContract {
    pub artifact_id: String,
    pub artifact_kind: ReadinessLabArtifactKind,
    pub source_bead: String,
    pub path: String,
    pub product_evidence_claim: ReadinessLabProductEvidenceClaim,
    pub freshness: ReadinessLabFreshnessMetadata,
    pub required_fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabArtifactKind {
    SimulatedHostCapability,
    PlannedWorkloadLane,
    RchSchedulingPlan,
    EvidenceTruthGraph,
    PermissionedRunRehearsal,
    ReplayFixture,
    DashboardAdvisory,
}

impl ReadinessLabArtifactKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SimulatedHostCapability => "simulated_host_capability",
            Self::PlannedWorkloadLane => "planned_workload_lane",
            Self::RchSchedulingPlan => "rch_scheduling_plan",
            Self::EvidenceTruthGraph => "evidence_truth_graph",
            Self::PermissionedRunRehearsal => "permissioned_run_rehearsal",
            Self::ReplayFixture => "replay_fixture",
            Self::DashboardAdvisory => "dashboard_advisory",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabProductEvidenceClaim {
    None,
    AdvisoryOnly,
    ProductPassFail,
}

impl ReadinessLabProductEvidenceClaim {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::AdvisoryOnly => "advisory_only",
            Self::ProductPassFail => "product_pass_fail",
        }
    }

    #[must_use]
    pub const fn is_advisory(self) -> bool {
        matches!(self, Self::None | Self::AdvisoryOnly)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabFreshnessMetadata {
    pub observed_at_epoch_days: u32,
    pub max_age_days: u32,
    pub git_sha: String,
    pub host_class: ReadinessLabHostClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabHostClass {
    Synthetic,
    DeveloperSmoke,
    CandidateLargeHost,
    PermissionedLargeHost,
    NotApplicable,
}

impl ReadinessLabHostClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Synthetic => "synthetic",
            Self::DeveloperSmoke => "developer_smoke",
            Self::CandidateLargeHost => "candidate_large_host",
            Self::PermissionedLargeHost => "permissioned_large_host",
            Self::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabLanePlan {
    pub lane_id: String,
    pub lane_kind: ReadinessLabLaneKind,
    pub expected_artifact_ids: Vec<String>,
    pub next_safe_command: String,
    pub permission_boundary: ReadinessLabPermissionBoundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabLaneKind {
    XfstestsRehearsal,
    LargeHostSwarmSimulation,
    RchValidationDryRun,
    EvidenceTruthGraph,
    DashboardAdvisory,
    NumaP99Replay,
}

impl ReadinessLabLaneKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::XfstestsRehearsal => "xfstests_rehearsal",
            Self::LargeHostSwarmSimulation => "large_host_swarm_simulation",
            Self::RchValidationDryRun => "rch_validation_dry_run",
            Self::EvidenceTruthGraph => "evidence_truth_graph",
            Self::DashboardAdvisory => "dashboard_advisory",
            Self::NumaP99Replay => "numa_p99_replay",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabPermissionBoundary {
    NoPermissionNeeded,
    RequiresOperatorAck,
    RequiresLargeHostAck,
    RequiresXfstestsAck,
}

impl ReadinessLabPermissionBoundary {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NoPermissionNeeded => "no_permission_needed",
            Self::RequiresOperatorAck => "requires_operator_ack",
            Self::RequiresLargeHostAck => "requires_large_host_ack",
            Self::RequiresXfstestsAck => "requires_xfstests_ack",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabRchAssumption {
    pub assumption_id: String,
    pub command: String,
    pub target_dir: String,
    pub env_allowlist: Vec<String>,
    pub executes_cargo: bool,
    pub local_fallback_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessLabValidationReport {
    pub schema_version: u32,
    pub lab_id: String,
    pub manifest_path: String,
    pub valid: bool,
    pub artifact_count: usize,
    pub lane_count: usize,
    pub rch_assumption_count: usize,
    pub advisory_artifact_count: usize,
    pub stale_artifact_count: usize,
    pub future_artifact_count: usize,
    pub product_claim_violation_count: usize,
    pub missing_required_field_count: usize,
    pub duplicate_id_count: usize,
    pub errors: Vec<ReadinessLabFinding>,
    pub warnings: Vec<ReadinessLabFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessLabFinding {
    pub finding_id: String,
    pub severity: ReadinessLabFindingSeverity,
    pub message: String,
    pub artifact_id: Option<String>,
    pub lane_id: Option<String>,
    pub assumption_id: Option<String>,
    pub field: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabFindingSeverity {
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessLabHostSimulationConfig {
    pub manifest_path: String,
    pub reference_epoch_days: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabHostSimulationManifest {
    pub schema_version: u32,
    pub simulation_id: String,
    pub generated_at_epoch_days: u32,
    pub advisory_notice: String,
    pub source_bead: String,
    pub real_campaign_bead: String,
    pub expected_artifact_root: String,
    pub release_gate_policy_path: String,
    pub hosts: Vec<ReadinessLabSyntheticHostInventory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ReadinessLabSyntheticHostInventory {
    pub host_id: String,
    pub observed_at_epoch_days: u32,
    pub max_age_days: u32,
    pub logical_cpus: u32,
    pub ram_total_gib: u32,
    pub ram_available_gib: u32,
    pub numa_topology_visible: bool,
    pub numa_nodes: Option<u32>,
    pub storage_class: String,
    pub storage_visible: bool,
    pub fuse_available: bool,
    pub runner_configured: bool,
    pub swarm_ack_configured: bool,
    pub rch_worker_identity: String,
    pub worker_fingerprint: String,
    pub queue_isolation: ReadinessLabSimulationQueueIsolation,
    pub target_dir_isolated: bool,
    pub target_dir: String,
    pub artifact_root: String,
    pub max_threads: u32,
    pub max_memory_gib: u32,
    pub max_temp_storage_gib: u32,
    pub max_queue_depth: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabSimulationQueueIsolation {
    Dedicated,
    Shared,
    Unknown,
}

impl ReadinessLabSimulationQueueIsolation {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Dedicated => "dedicated",
            Self::Shared => "shared",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessLabHostSimulationReport {
    pub schema_version: u32,
    pub simulation_id: String,
    pub manifest_path: String,
    pub valid: bool,
    pub product_evidence_claim: String,
    pub release_gate_effect: String,
    pub source_bead: String,
    pub real_campaign_bead: String,
    pub expected_artifact_root: String,
    pub host_count: usize,
    pub candidate_count: usize,
    pub small_host_count: usize,
    pub capability_downgrade_count: usize,
    pub blocked_count: usize,
    pub stale_inventory_count: usize,
    pub future_inventory_count: usize,
    pub rows: Vec<ReadinessLabHostSimulationRow>,
    pub errors: Vec<ReadinessLabFinding>,
    pub warnings: Vec<ReadinessLabFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ReadinessLabHostSimulationRow {
    pub host_id: String,
    pub valid: bool,
    pub classification: String,
    pub candidate_for_authorized_run: bool,
    pub product_evidence_claim: String,
    pub release_gate_effect: String,
    pub logical_cpus: u32,
    pub ram_total_gib: u32,
    pub numa_topology_visible: bool,
    pub numa_nodes: Option<u32>,
    pub storage_visible: bool,
    pub fuse_available: bool,
    pub runner_configured: bool,
    pub swarm_ack_configured: bool,
    pub worker_identity: String,
    pub queue_isolation: String,
    pub target_dir_isolated: bool,
    pub artifact_root: String,
    pub blocker_count: usize,
    pub blockers: Vec<String>,
    pub downgrade_count: usize,
    pub downgrade_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessLabRchLaneScheduleConfig {
    pub manifest_path: String,
    pub reference_epoch_days: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabRchLaneScheduleManifest {
    pub schema_version: u32,
    pub plan_id: String,
    pub generated_at_epoch_days: u32,
    pub advisory_notice: String,
    pub source_bead: String,
    pub artifact_root: String,
    pub lanes: Vec<ReadinessLabRchValidationLane>,
    pub evidence: Vec<ReadinessLabRchEvidence>,
    pub worker_hints: Vec<ReadinessLabRchWorkerHint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabRchValidationLane {
    pub lane_id: String,
    pub lane_kind: ReadinessLabRchValidationLaneKind,
    pub command: String,
    pub dependencies: Vec<String>,
    pub target_dir: String,
    pub artifact_path: String,
    pub env_allowlist: Vec<String>,
    pub estimated_cost_units: u32,
    pub required_evidence_ids: Vec<String>,
    pub worker_hint: Option<String>,
    pub executes_cargo: bool,
    pub local_fallback_allowed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabRchValidationLaneKind {
    CargoCheck,
    CargoTest,
    CargoClippy,
    ReadinessDashboard,
    Other,
}

impl ReadinessLabRchValidationLaneKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CargoCheck => "cargo_check",
            Self::CargoTest => "cargo_test",
            Self::CargoClippy => "cargo_clippy",
            Self::ReadinessDashboard => "readiness_dashboard",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabRchEvidence {
    pub evidence_id: String,
    pub observed_at_epoch_days: u32,
    pub max_age_days: u32,
    pub worker_identity: String,
    pub rch_available: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabRchWorkerHint {
    pub worker_id: String,
    pub logical_cpus: u32,
    pub ram_gib: u32,
    pub max_parallel_lanes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessLabRchLaneScheduleReport {
    pub schema_version: u32,
    pub plan_id: String,
    pub manifest_path: String,
    pub valid: bool,
    pub dry_run_only: bool,
    pub product_evidence_claim: String,
    pub release_gate_effect: String,
    pub source_bead: String,
    pub artifact_root: String,
    pub lane_count: usize,
    pub planned_lane_count: usize,
    pub coalesced_duplicate_count: usize,
    pub target_dir_conflict_count: usize,
    pub missing_evidence_count: usize,
    pub local_fallback_violation_count: usize,
    pub rows: Vec<ReadinessLabRchLaneScheduleRow>,
    pub errors: Vec<ReadinessLabFinding>,
    pub warnings: Vec<ReadinessLabFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessLabRchLaneScheduleRow {
    pub ordinal: usize,
    pub lane_id: String,
    pub lane_kind: String,
    pub command: String,
    pub target_dir: String,
    pub artifact_path: String,
    pub env_allowlist: Vec<String>,
    pub estimated_cost_units: u32,
    pub dependencies: Vec<String>,
    pub required_evidence_ids: Vec<String>,
    pub worker_hint: Option<String>,
    pub coalesced_from: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessLabTruthGraphConfig {
    pub manifest_path: String,
    pub reference_epoch_days: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabTruthGraphManifest {
    pub schema_version: u32,
    pub graph_id: String,
    pub generated_at_epoch_days: u32,
    pub advisory_notice: String,
    pub source_bead: String,
    pub sources: Vec<ReadinessLabTruthGraphSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabTruthGraphSource {
    pub source_id: String,
    pub source_kind: ReadinessLabTruthGraphSourceKind,
    pub path: String,
    pub valid: bool,
    pub claims: Vec<ReadinessLabTruthGraphClaimInput>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabTruthGraphSourceKind {
    ProofBundleReport,
    ReleaseGateReport,
    OperationalEvidenceIndex,
    PermissionedCampaignPacket,
    ReadinessLabReport,
    TopologyRuntimeAdvisorReport,
}

impl ReadinessLabTruthGraphSourceKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ProofBundleReport => "proof_bundle_report",
            Self::ReleaseGateReport => "release_gate_report",
            Self::OperationalEvidenceIndex => "operational_evidence_index",
            Self::PermissionedCampaignPacket => "permissioned_campaign_packet",
            Self::ReadinessLabReport => "readiness_lab_report",
            Self::TopologyRuntimeAdvisorReport => "topology_runtime_advisor_report",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabTruthGraphClaimInput {
    pub claim_id: String,
    pub claim_state: ReadinessLabTruthGraphClaimState,
    pub product_evidence_claim: ReadinessLabProductEvidenceClaim,
    pub validator_report_path: String,
    pub source_bead: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default)]
    pub artifacts: Vec<ReadinessLabTruthGraphArtifactInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<ReadinessLabTruthGraphHostInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness: Option<ReadinessLabFreshnessMetadata>,
    #[serde(default)]
    pub blockers: Vec<ReadinessLabTruthGraphBlockerInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<ReadinessLabTruthGraphPermissionRequirement>,
    #[serde(default)]
    pub supersedes_claim_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topology_advisor: Option<ReadinessLabTruthGraphTopologyAdvisorInput>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabTruthGraphClaimState {
    Validated,
    Blocked,
    Stale,
    Simulated,
    HandoffOnly,
    DryRunOnly,
    Unknown,
}

impl ReadinessLabTruthGraphClaimState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::Blocked => "blocked",
            Self::Stale => "stale",
            Self::Simulated => "simulated",
            Self::HandoffOnly => "handoff_only",
            Self::DryRunOnly => "dry_run_only",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabTruthGraphArtifactInput {
    pub artifact_id: String,
    pub artifact_kind: ReadinessLabArtifactKind,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub raw_log_required: bool,
    pub raw_log_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabTruthGraphTopologyAdvisorInput {
    pub topology_advisor_report_path: String,
    pub score_report_path: String,
    pub structured_log_path: String,
    pub source_bead: String,
    pub real_campaign_bead: String,
    pub manifest_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    #[serde(default)]
    pub rejected_candidates: Vec<String>,
    #[serde(default)]
    pub blocked_claims: Vec<String>,
    pub advisory_only: bool,
    pub product_evidence_claim: ReadinessLabProductEvidenceClaim,
    pub release_gate_effect: String,
    pub artifact_root: String,
    #[serde(default)]
    pub artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabTruthGraphHostInput {
    pub host_id: String,
    pub host_class: ReadinessLabHostClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_cpus: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ram_total_gib: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub numa_topology_visible: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabTruthGraphBlockerInput {
    pub blocker_id: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator_report_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bead_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabTruthGraphPermissionRequirement {
    pub permission_id: String,
    pub boundary: ReadinessLabPermissionBoundary,
    pub bead_id: String,
    pub ack_env: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessLabTruthGraphReport {
    pub schema_version: u32,
    pub graph_id: String,
    pub manifest_path: String,
    pub valid: bool,
    pub dry_run_only: bool,
    pub product_evidence_claim: String,
    pub release_gate_effect: String,
    pub source_bead: String,
    pub source_count: usize,
    pub claim_count: usize,
    pub node_count: usize,
    pub edge_count: usize,
    pub stale_claim_count: usize,
    pub contradictory_claim_count: usize,
    pub missing_raw_log_count: usize,
    pub permission_requirement_count: usize,
    pub simulated_node_count: usize,
    pub blocker_edge_count: usize,
    pub nodes: Vec<ReadinessLabTruthGraphNode>,
    pub edges: Vec<ReadinessLabTruthGraphEdge>,
    pub contradictions: Vec<ReadinessLabTruthGraphContradiction>,
    pub errors: Vec<ReadinessLabFinding>,
    pub warnings: Vec<ReadinessLabFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessLabTruthGraphNode {
    pub node_id: String,
    pub node_kind: String,
    pub label: String,
    pub source_path: Option<String>,
    pub bead_id: Option<String>,
    pub claim_state: Option<String>,
    pub host_class: Option<String>,
    pub freshness_status: Option<String>,
    pub product_evidence_claim: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessLabTruthGraphEdge {
    pub from_node_id: String,
    pub to_node_id: String,
    pub edge_kind: String,
    pub label: String,
    pub validator_report_path: Option<String>,
    pub bead_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessLabTruthGraphContradiction {
    pub claim_id: String,
    pub observed_states: Vec<String>,
    pub claim_node_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessLabNumaP99ReplayConfig {
    pub manifest_path: String,
    pub reference_epoch_days: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabNumaP99ReplayManifest {
    pub schema_version: u32,
    pub replay_id: String,
    pub generated_at_epoch_days: u32,
    pub advisory_notice: String,
    pub source_bead: String,
    pub product_evidence_claim: ReadinessLabProductEvidenceClaim,
    pub fixtures: Vec<ReadinessLabNumaP99ReplayFixture>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabNumaP99ReplayFixture {
    pub fixture_id: String,
    pub fixture_shape: ReadinessLabNumaP99FixtureShape,
    pub source_bead: String,
    pub observed_at_epoch_days: u32,
    pub max_age_days: u32,
    pub host: ReadinessLabNumaP99HostShape,
    pub workload: ReadinessLabNumaP99WorkloadShape,
    pub latency: ReadinessLabNumaP99LatencyHistogram,
    pub queue_depth: ReadinessLabNumaP99QueueDepth,
    pub raw_log_path: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabNumaP99FixtureShape {
    BalancedNuma,
    SkewedNuma,
    MetadataReadHotShards,
    RepairScrubInterference,
    RchWorkerContention,
    MemoryPressure,
}

impl ReadinessLabNumaP99FixtureShape {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::BalancedNuma => "balanced_numa",
            Self::SkewedNuma => "skewed_numa",
            Self::MetadataReadHotShards => "metadata_read_hot_shards",
            Self::RepairScrubInterference => "repair_scrub_interference",
            Self::RchWorkerContention => "rch_worker_contention",
            Self::MemoryPressure => "memory_pressure",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabNumaP99HostShape {
    pub logical_cpus: u32,
    pub numa_nodes: Option<u32>,
    pub ram_total_gib: f64,
    pub ram_available_gib: f64,
    pub storage_class: String,
    pub rch_worker_identity: String,
    pub queue_isolation: ReadinessLabSimulationQueueIsolation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabNumaP99WorkloadShape {
    pub operation_count: u64,
    pub duration_ms: i64,
    pub worker_count: u32,
    pub hot_shard_count: u32,
    pub repair_scrub_active: bool,
    pub memory_pressure_percent: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabNumaP99LatencyHistogram {
    pub p50_latency_us: Option<f64>,
    pub p95_latency_us: Option<f64>,
    pub p99_latency_us: Option<f64>,
    pub attribution: Vec<ReadinessLabNumaP99AttributionBucket>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabNumaP99AttributionBucket {
    pub component: ReadinessLabNumaP99Component,
    pub p50_us: Option<f64>,
    pub p95_us: Option<f64>,
    pub p99_us: Option<f64>,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabNumaP99Component {
    Queueing,
    Service,
    Io,
    Synchronization,
    Allocator,
    RepairBacklog,
    CachePressure,
    RchWorkerContention,
    NumaRemoteAccess,
    MemoryReclaim,
}

impl ReadinessLabNumaP99Component {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Queueing => "queueing",
            Self::Service => "service",
            Self::Io => "io",
            Self::Synchronization => "synchronization",
            Self::Allocator => "allocator",
            Self::RepairBacklog => "repair_backlog",
            Self::CachePressure => "cache_pressure",
            Self::RchWorkerContention => "rch_worker_contention",
            Self::NumaRemoteAccess => "numa_remote_access",
            Self::MemoryReclaim => "memory_reclaim",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabNumaP99QueueDepth {
    pub average: f64,
    pub p99: Option<f64>,
    pub max: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReadinessLabNumaP99ReplayReport {
    pub schema_version: u32,
    pub replay_id: String,
    pub manifest_path: String,
    pub valid: bool,
    pub replay_only: bool,
    pub product_evidence_claim: String,
    pub release_gate_effect: String,
    pub source_bead: String,
    pub fixture_count: usize,
    pub row_count: usize,
    pub invalid_fixture_count: usize,
    pub missing_shape_count: usize,
    pub missing_p99_bucket_count: usize,
    pub malformed_histogram_count: usize,
    pub impossible_cpu_count: usize,
    pub negative_duration_count: usize,
    pub stale_fixture_count: usize,
    pub future_fixture_count: usize,
    pub shape_counts: BTreeMap<String, usize>,
    pub rows: Vec<ReadinessLabNumaP99ReplayRow>,
    pub errors: Vec<ReadinessLabFinding>,
    pub warnings: Vec<ReadinessLabFinding>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReadinessLabNumaP99ReplayRow {
    pub fixture_id: String,
    pub fixture_shape: String,
    pub classification: String,
    pub product_evidence_claim: String,
    pub release_gate_effect: String,
    pub logical_cpus: u32,
    pub numa_nodes: Option<u32>,
    pub worker_count: u32,
    pub hot_shard_count: u32,
    pub memory_pressure_percent: u32,
    pub duration_ms: i64,
    pub p50_latency_us: Option<f64>,
    pub p95_latency_us: Option<f64>,
    pub p99_latency_us: Option<f64>,
    pub component_p99_sum_us: f64,
    pub dominant_component: String,
    pub dominant_component_p99_us: f64,
    pub queue_depth_p99: Option<f64>,
    pub raw_log_path: String,
    pub reproduction_command: String,
    pub finding_count: usize,
}

#[must_use]
pub fn validate_readiness_lab_contract_bundle(
    bundle: &ReadinessLabContractBundle,
    config: &ReadinessLabValidationConfig,
) -> ReadinessLabValidationReport {
    let mut validator = ReadinessLabValidator::new(bundle, config);
    validator.validate_bundle();
    validator.finish()
}

pub fn load_readiness_lab_contract_bundle(
    path: impl AsRef<Path>,
) -> Result<ReadinessLabContractBundle> {
    let path = path.as_ref();
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read readiness lab contract {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("failed to parse readiness lab contract {}", path.display()))
}

#[must_use]
pub fn render_readiness_lab_contract_markdown(report: &ReadinessLabValidationReport) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# FrankenFS Readiness Lab Contract Report").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "- Lab: `{}`", report.lab_id).ok();
    writeln!(&mut out, "- Manifest: `{}`", report.manifest_path).ok();
    writeln!(&mut out, "- Valid: `{}`", report.valid).ok();
    writeln!(&mut out, "- Artifacts: `{}`", report.artifact_count).ok();
    writeln!(&mut out, "- Lanes: `{}`", report.lane_count).ok();
    writeln!(
        &mut out,
        "- RCH assumptions: `{}`",
        report.rch_assumption_count
    )
    .ok();
    writeln!(
        &mut out,
        "- Advisory artifacts: `{}`",
        report.advisory_artifact_count
    )
    .ok();
    writeln!(
        &mut out,
        "- Product-claim violations: `{}`",
        report.product_claim_violation_count
    )
    .ok();
    writeln!(&mut out).ok();

    render_findings(&mut out, "Errors", &report.errors);
    render_findings(&mut out, "Warnings", &report.warnings);
    out
}

pub fn fail_on_readiness_lab_contract_errors(report: &ReadinessLabValidationReport) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    let first = report
        .errors
        .first()
        .map_or("readiness lab contract failed validation", |finding| {
            finding.message.as_str()
        });
    anyhow::bail!(
        "readiness lab contract validation failed with {} error(s): {first}",
        report.errors.len()
    )
}

pub fn load_readiness_lab_host_simulation_manifest(
    path: impl AsRef<Path>,
) -> Result<ReadinessLabHostSimulationManifest> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read readiness lab host simulation {}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| {
        format!(
            "failed to parse readiness lab host simulation {}",
            path.display()
        )
    })
}

#[must_use]
pub fn simulate_readiness_lab_hosts(
    manifest: &ReadinessLabHostSimulationManifest,
    config: &ReadinessLabHostSimulationConfig,
) -> ReadinessLabHostSimulationReport {
    let mut errors = Vec::new();
    let warnings = Vec::new();
    validate_host_simulation_manifest(manifest, &mut errors);

    let mut seen_hosts = BTreeSet::new();
    for host in &manifest.hosts {
        if !host.host_id.trim().is_empty() && !seen_hosts.insert(host.host_id.as_str()) {
            push_readiness_lab_finding(
                &mut errors,
                "duplicate_host_id",
                "host_id values must be unique",
                FindingScope::artifact(host.host_id.as_str()).field("host_id"),
            );
        }
    }

    let mut rows = Vec::new();
    let mut candidate_count = 0;
    let mut small_host_count = 0;
    let mut capability_downgrade_count = 0;
    let mut blocked_count = 0;
    let mut stale_inventory_count = 0;
    let mut future_inventory_count = 0;

    for host in &manifest.hosts {
        let row = simulate_readiness_lab_host(manifest, host, config);
        if row
            .blockers
            .iter()
            .any(|blocker| blocker.starts_with("stale_inventory"))
        {
            stale_inventory_count += 1;
        }
        if row
            .blockers
            .iter()
            .any(|blocker| blocker.starts_with("future_inventory"))
        {
            future_inventory_count += 1;
        }
        match row.classification.as_str() {
            "authoritative_large_host_candidate" => candidate_count += 1,
            "small_host_smoke" => small_host_count += 1,
            "capability_downgraded_smoke" => capability_downgrade_count += 1,
            "blocked" => blocked_count += 1,
            _ => {}
        }
        rows.push(row);
    }

    ReadinessLabHostSimulationReport {
        schema_version: READINESS_LAB_HOST_SIMULATION_REPORT_SCHEMA_VERSION,
        simulation_id: manifest.simulation_id.clone(),
        manifest_path: config.manifest_path.clone(),
        valid: errors.is_empty(),
        product_evidence_claim: READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM.to_owned(),
        release_gate_effect: format!(
            "simulator output is advisory only; swarm.responsiveness remains hidden or blocked until {} records executed large-host proof-bundle lanes and release-gate output",
            manifest.real_campaign_bead
        ),
        source_bead: manifest.source_bead.clone(),
        real_campaign_bead: manifest.real_campaign_bead.clone(),
        expected_artifact_root: manifest.expected_artifact_root.clone(),
        host_count: manifest.hosts.len(),
        candidate_count,
        small_host_count,
        capability_downgrade_count,
        blocked_count,
        stale_inventory_count,
        future_inventory_count,
        rows,
        errors,
        warnings,
    }
}

#[must_use]
pub fn render_readiness_lab_host_simulation_markdown(
    report: &ReadinessLabHostSimulationReport,
) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# FrankenFS Readiness Lab Host Simulation").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "- Simulation: `{}`", report.simulation_id).ok();
    writeln!(&mut out, "- Manifest: `{}`", report.manifest_path).ok();
    writeln!(&mut out, "- Valid: `{}`", report.valid).ok();
    writeln!(
        &mut out,
        "- Product evidence claim: `{}`",
        report.product_evidence_claim
    )
    .ok();
    writeln!(
        &mut out,
        "- Release-gate effect: {}",
        report.release_gate_effect
    )
    .ok();
    writeln!(&mut out, "- Hosts: `{}`", report.host_count).ok();
    writeln!(&mut out, "- Candidates: `{}`", report.candidate_count).ok();
    writeln!(
        &mut out,
        "- Small-host smoke: `{}`",
        report.small_host_count
    )
    .ok();
    writeln!(
        &mut out,
        "- Capability downgrades: `{}`",
        report.capability_downgrade_count
    )
    .ok();
    writeln!(&mut out, "- Blocked: `{}`", report.blocked_count).ok();
    writeln!(&mut out).ok();
    writeln!(
        &mut out,
        "| host | classification | candidate | cpu | ram_gib | numa | runner | ack | blockers | downgrades |"
    )
    .ok();
    writeln!(&mut out, "|---|---|---:|---:|---:|---|---|---|---:|---:|").ok();
    for row in &report.rows {
        let numa = row.numa_nodes.map_or_else(
            || "missing".to_owned(),
            |nodes| {
                if row.numa_topology_visible {
                    nodes.to_string()
                } else {
                    format!("{nodes} (hidden)")
                }
            },
        );
        writeln!(
            &mut out,
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |",
            row.host_id,
            row.classification,
            row.candidate_for_authorized_run,
            row.logical_cpus,
            row.ram_total_gib,
            numa,
            row.runner_configured,
            row.swarm_ack_configured,
            row.blocker_count,
            row.downgrade_count
        )
        .ok();
    }
    writeln!(&mut out).ok();
    render_findings(&mut out, "Errors", &report.errors);
    render_findings(&mut out, "Warnings", &report.warnings);
    out
}

pub fn fail_on_readiness_lab_host_simulation_errors(
    report: &ReadinessLabHostSimulationReport,
) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    let first = report.errors.first().map_or(
        "readiness lab host simulation failed validation",
        |finding| finding.message.as_str(),
    );
    anyhow::bail!(
        "readiness lab host simulation validation failed with {} error(s): {first}",
        report.errors.len()
    )
}

pub fn load_readiness_lab_rch_lane_schedule_manifest(
    path: impl AsRef<Path>,
) -> Result<ReadinessLabRchLaneScheduleManifest> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read readiness lab RCH lane schedule {}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| {
        format!(
            "failed to parse readiness lab RCH lane schedule {}",
            path.display()
        )
    })
}

#[must_use]
pub fn plan_readiness_lab_rch_lanes(
    manifest: &ReadinessLabRchLaneScheduleManifest,
    config: &ReadinessLabRchLaneScheduleConfig,
) -> ReadinessLabRchLaneScheduleReport {
    let mut planner = ReadinessLabRchLanePlanner::new(manifest, config);
    planner.validate_manifest();
    planner.plan();
    planner.finish()
}

#[must_use]
pub fn render_readiness_lab_rch_lane_schedule_markdown(
    report: &ReadinessLabRchLaneScheduleReport,
) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# FrankenFS Readiness Lab RCH Lane Schedule").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "- Plan: `{}`", report.plan_id).ok();
    writeln!(&mut out, "- Manifest: `{}`", report.manifest_path).ok();
    writeln!(&mut out, "- Valid: `{}`", report.valid).ok();
    writeln!(&mut out, "- Dry run only: `{}`", report.dry_run_only).ok();
    writeln!(
        &mut out,
        "- Product evidence claim: `{}`",
        report.product_evidence_claim
    )
    .ok();
    writeln!(
        &mut out,
        "- Release-gate effect: {}",
        report.release_gate_effect
    )
    .ok();
    writeln!(&mut out, "- Source bead: `{}`", report.source_bead).ok();
    writeln!(&mut out, "- Lanes: `{}`", report.lane_count).ok();
    writeln!(&mut out, "- Planned lanes: `{}`", report.planned_lane_count).ok();
    writeln!(
        &mut out,
        "- Coalesced duplicates: `{}`",
        report.coalesced_duplicate_count
    )
    .ok();
    writeln!(
        &mut out,
        "- Local fallback violations: `{}`",
        report.local_fallback_violation_count
    )
    .ok();
    writeln!(&mut out).ok();
    writeln!(
        &mut out,
        "| order | lane | kind | deps | target_dir | artifact | cost | coalesced |"
    )
    .ok();
    writeln!(&mut out, "|---:|---|---|---:|---|---|---:|---:|").ok();
    for row in &report.rows {
        writeln!(
            &mut out,
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |",
            row.ordinal,
            row.lane_id,
            row.lane_kind,
            row.dependencies.len(),
            row.target_dir,
            row.artifact_path,
            row.estimated_cost_units,
            row.coalesced_from.len()
        )
        .ok();
    }
    writeln!(&mut out).ok();
    render_findings(&mut out, "Errors", &report.errors);
    render_findings(&mut out, "Warnings", &report.warnings);
    out
}

pub fn fail_on_readiness_lab_rch_lane_schedule_errors(
    report: &ReadinessLabRchLaneScheduleReport,
) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    let first = report.errors.first().map_or(
        "readiness lab RCH lane schedule failed validation",
        |finding| finding.message.as_str(),
    );
    anyhow::bail!(
        "readiness lab RCH lane schedule validation failed with {} error(s): {first}",
        report.errors.len()
    )
}

pub fn load_readiness_lab_truth_graph_manifest(
    path: impl AsRef<Path>,
) -> Result<ReadinessLabTruthGraphManifest> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read readiness lab truth graph {}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| {
        format!(
            "failed to parse readiness lab truth graph {}",
            path.display()
        )
    })
}

#[must_use]
pub fn build_readiness_lab_truth_graph(
    manifest: &ReadinessLabTruthGraphManifest,
    config: &ReadinessLabTruthGraphConfig,
) -> ReadinessLabTruthGraphReport {
    let mut builder = ReadinessLabTruthGraphBuilder::new(manifest, config);
    builder.validate_manifest();
    builder.build();
    builder.finish()
}

#[must_use]
pub fn render_readiness_lab_truth_graph_markdown(report: &ReadinessLabTruthGraphReport) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# FrankenFS Readiness Lab Truth Graph").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "- Graph: `{}`", report.graph_id).ok();
    writeln!(&mut out, "- Manifest: `{}`", report.manifest_path).ok();
    writeln!(&mut out, "- Valid: `{}`", report.valid).ok();
    writeln!(&mut out, "- Dry run only: `{}`", report.dry_run_only).ok();
    writeln!(
        &mut out,
        "- Product evidence claim: `{}`",
        report.product_evidence_claim
    )
    .ok();
    writeln!(
        &mut out,
        "- Release gate effect: `{}`",
        report.release_gate_effect
    )
    .ok();
    writeln!(&mut out, "- Sources: `{}`", report.source_count).ok();
    writeln!(&mut out, "- Claims: `{}`", report.claim_count).ok();
    writeln!(&mut out, "- Nodes: `{}`", report.node_count).ok();
    writeln!(&mut out, "- Edges: `{}`", report.edge_count).ok();
    writeln!(&mut out, "- Stale claims: `{}`", report.stale_claim_count).ok();
    writeln!(
        &mut out,
        "- Contradictory claims: `{}`",
        report.contradictory_claim_count
    )
    .ok();
    writeln!(
        &mut out,
        "- Missing raw logs: `{}`",
        report.missing_raw_log_count
    )
    .ok();
    writeln!(
        &mut out,
        "- Permission requirements: `{}`",
        report.permission_requirement_count
    )
    .ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Blocker Edges").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "| from | to | validator_report | bead | reason |").ok();
    writeln!(&mut out, "|---|---|---|---|---|").ok();
    for edge in report
        .edges
        .iter()
        .filter(|edge| edge.edge_kind == "blocks")
    {
        writeln!(
            &mut out,
            "| `{}` | `{}` | `{}` | `{}` | {} |",
            edge.from_node_id,
            edge.to_node_id,
            edge.validator_report_path.as_deref().unwrap_or(""),
            edge.bead_id.as_deref().unwrap_or(""),
            edge.label
        )
        .ok();
    }
    writeln!(&mut out).ok();
    render_findings(&mut out, "Errors", &report.errors);
    render_findings(&mut out, "Warnings", &report.warnings);
    out
}

pub fn fail_on_readiness_lab_truth_graph_errors(
    report: &ReadinessLabTruthGraphReport,
) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    let first = report
        .errors
        .first()
        .map_or("readiness lab truth graph failed validation", |finding| {
            finding.message.as_str()
        });
    anyhow::bail!(
        "readiness lab truth graph validation failed with {} error(s): {first}",
        report.errors.len()
    )
}

pub fn load_readiness_lab_numa_p99_replay_manifest(
    path: impl AsRef<Path>,
) -> Result<ReadinessLabNumaP99ReplayManifest> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read readiness lab NUMA/p99 replay {}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| {
        format!(
            "failed to parse readiness lab NUMA/p99 replay {}",
            path.display()
        )
    })
}

#[must_use]
pub fn validate_readiness_lab_numa_p99_replay(
    manifest: &ReadinessLabNumaP99ReplayManifest,
    config: &ReadinessLabNumaP99ReplayConfig,
) -> ReadinessLabNumaP99ReplayReport {
    let mut validator = ReadinessLabNumaP99ReplayValidator::new(manifest, config);
    validator.validate_manifest();
    validator.finish()
}

#[must_use]
pub fn render_readiness_lab_numa_p99_replay_markdown(
    report: &ReadinessLabNumaP99ReplayReport,
) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# FrankenFS Readiness Lab NUMA/p99 Replay").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "- Replay: `{}`", report.replay_id).ok();
    writeln!(&mut out, "- Manifest: `{}`", report.manifest_path).ok();
    writeln!(&mut out, "- Valid: `{}`", report.valid).ok();
    writeln!(&mut out, "- Replay only: `{}`", report.replay_only).ok();
    writeln!(
        &mut out,
        "- Product evidence claim: `{}`",
        report.product_evidence_claim
    )
    .ok();
    writeln!(
        &mut out,
        "- Release-gate effect: {}",
        report.release_gate_effect
    )
    .ok();
    writeln!(&mut out, "- Fixtures: `{}`", report.fixture_count).ok();
    writeln!(
        &mut out,
        "- Missing fixture shapes: `{}`",
        report.missing_shape_count
    )
    .ok();
    writeln!(
        &mut out,
        "- Missing p99 buckets: `{}`",
        report.missing_p99_bucket_count
    )
    .ok();
    writeln!(
        &mut out,
        "- Malformed histograms: `{}`",
        report.malformed_histogram_count
    )
    .ok();
    writeln!(&mut out).ok();
    writeln!(
        &mut out,
        "| fixture | shape | class | cpu | numa | workers | p50 | p95 | p99 | dominant | component_sum | findings |"
    )
    .ok();
    writeln!(
        &mut out,
        "|---|---|---|---:|---:|---:|---:|---:|---:|---|---:|---:|"
    )
    .ok();
    for row in &report.rows {
        writeln!(
            &mut out,
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{:.1}` | `{}` |",
            row.fixture_id,
            row.fixture_shape,
            row.classification,
            row.logical_cpus,
            row.numa_nodes
                .map_or_else(|| "missing".to_owned(), |nodes| nodes.to_string()),
            row.worker_count,
            format_optional_f64(row.p50_latency_us),
            format_optional_f64(row.p95_latency_us),
            format_optional_f64(row.p99_latency_us),
            row.dominant_component,
            row.component_p99_sum_us,
            row.finding_count
        )
        .ok();
    }
    writeln!(&mut out).ok();
    render_findings(&mut out, "Errors", &report.errors);
    render_findings(&mut out, "Warnings", &report.warnings);
    out
}

pub fn fail_on_readiness_lab_numa_p99_replay_errors(
    report: &ReadinessLabNumaP99ReplayReport,
) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    let first = report.errors.first().map_or(
        "readiness lab NUMA/p99 replay failed validation",
        |finding| finding.message.as_str(),
    );
    anyhow::bail!(
        "readiness lab NUMA/p99 replay validation failed with {} error(s): {first}",
        report.errors.len()
    )
}

fn render_findings(out: &mut String, heading: &str, findings: &[ReadinessLabFinding]) {
    writeln!(out, "## {heading}").ok();
    writeln!(out).ok();
    if findings.is_empty() {
        writeln!(out, "- none").ok();
        writeln!(out).ok();
        return;
    }
    for finding in findings {
        let mut scope = Vec::new();
        if let Some(artifact_id) = &finding.artifact_id {
            scope.push(format!("artifact={artifact_id}"));
        }
        if let Some(lane_id) = &finding.lane_id {
            scope.push(format!("lane={lane_id}"));
        }
        if let Some(assumption_id) = &finding.assumption_id {
            scope.push(format!("assumption={assumption_id}"));
        }
        if let Some(field) = &finding.field {
            scope.push(format!("field={field}"));
        }
        if scope.is_empty() {
            writeln!(out, "- `{}`: {}", finding.finding_id, finding.message).ok();
        } else {
            writeln!(
                out,
                "- `{}` [{}]: {}",
                finding.finding_id,
                scope.join(", "),
                finding.message
            )
            .ok();
        }
    }
    writeln!(out).ok();
}

struct ReadinessLabValidator<'a> {
    bundle: &'a ReadinessLabContractBundle,
    config: &'a ReadinessLabValidationConfig,
    errors: Vec<ReadinessLabFinding>,
    warnings: Vec<ReadinessLabFinding>,
    advisory_artifact_count: usize,
    stale_artifact_count: usize,
    future_artifact_count: usize,
    product_claim_violation_count: usize,
    missing_required_field_count: usize,
    duplicate_id_count: usize,
}

impl<'a> ReadinessLabValidator<'a> {
    fn new(
        bundle: &'a ReadinessLabContractBundle,
        config: &'a ReadinessLabValidationConfig,
    ) -> Self {
        Self {
            bundle,
            config,
            errors: Vec::new(),
            warnings: Vec::new(),
            advisory_artifact_count: 0,
            stale_artifact_count: 0,
            future_artifact_count: 0,
            product_claim_violation_count: 0,
            missing_required_field_count: 0,
            duplicate_id_count: 0,
        }
    }

    fn validate_bundle(&mut self) {
        self.check_schema_and_identity();
        self.check_duplicates();
        let artifact_ids = self
            .bundle
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.as_str())
            .collect::<BTreeSet<_>>();
        for artifact in &self.bundle.artifacts {
            self.validate_artifact(artifact);
        }
        for lane in &self.bundle.lane_plans {
            self.validate_lane(lane, &artifact_ids);
        }
        for assumption in &self.bundle.rch_assumptions {
            self.validate_rch_assumption(assumption);
        }
    }

    fn check_schema_and_identity(&mut self) {
        if self.bundle.schema_version != READINESS_LAB_SCHEMA_VERSION {
            self.error(
                "unsupported_schema_version",
                format!(
                    "schema_version must be {READINESS_LAB_SCHEMA_VERSION}, got {}",
                    self.bundle.schema_version
                ),
                FindingScope::default().field("schema_version"),
            );
        }
        if self.bundle.lab_id.trim().is_empty() {
            self.error(
                "missing_lab_id",
                "lab_id must be non-empty",
                FindingScope::default().field("lab_id"),
            );
        }
        if self.bundle.generated_at_epoch_days == 0 {
            self.error(
                "missing_generated_at_epoch_days",
                "generated_at_epoch_days must be non-zero",
                FindingScope::default().field("generated_at_epoch_days"),
            );
        }
        if self.bundle.advisory_notice.trim() != READINESS_LAB_ADVISORY_NOTICE {
            self.error(
                "invalid_advisory_notice",
                format!("advisory_notice must be exactly {READINESS_LAB_ADVISORY_NOTICE:?}"),
                FindingScope::default().field("advisory_notice"),
            );
        }
    }

    fn check_duplicates(&mut self) {
        self.duplicate_id_count += duplicate_count(
            self.bundle
                .artifacts
                .iter()
                .map(|artifact| artifact.artifact_id.as_str()),
        );
        self.duplicate_id_count += duplicate_count(
            self.bundle
                .lane_plans
                .iter()
                .map(|lane| lane.lane_id.as_str()),
        );
        self.duplicate_id_count += duplicate_count(
            self.bundle
                .rch_assumptions
                .iter()
                .map(|assumption| assumption.assumption_id.as_str()),
        );
        if self.duplicate_id_count > 0 {
            self.error(
                "duplicate_ids",
                format!(
                    "readiness lab contract contains {} duplicate id(s)",
                    self.duplicate_id_count
                ),
                FindingScope::default(),
            );
        }
    }

    fn validate_artifact(&mut self, artifact: &ReadinessLabArtifactContract) {
        if artifact.artifact_id.trim().is_empty() {
            self.error(
                "missing_artifact_id",
                "artifact_id must be non-empty",
                FindingScope::default().field("artifact_id"),
            );
        }
        if !artifact.source_bead.starts_with("bd-") {
            self.error(
                "malformed_source_bead",
                "source_bead must look like bd-...",
                FindingScope::artifact(artifact.artifact_id.as_str()).field("source_bead"),
            );
        }
        if artifact.path.trim().is_empty() {
            self.error(
                "missing_artifact_path",
                "artifact path must be non-empty",
                FindingScope::artifact(artifact.artifact_id.as_str()).field("path"),
            );
        }
        if artifact.product_evidence_claim.is_advisory() {
            self.advisory_artifact_count += 1;
        } else {
            self.product_claim_violation_count += 1;
            self.error(
                "product_evidence_claim_violation",
                "readiness lab artifacts must not claim product pass/fail evidence",
                FindingScope::artifact(artifact.artifact_id.as_str())
                    .field("product_evidence_claim"),
            );
        }
        self.validate_required_fields(artifact);
        self.validate_freshness(artifact);
    }

    fn validate_required_fields(&mut self, artifact: &ReadinessLabArtifactContract) {
        if artifact.required_fields.is_empty() {
            self.missing_required_field_count += 1;
            self.error(
                "empty_required_fields",
                "required_fields must list the fields a future validator must inspect",
                FindingScope::artifact(artifact.artifact_id.as_str()).field("required_fields"),
            );
            return;
        }
        for field in &artifact.required_fields {
            if field.trim().is_empty() {
                self.missing_required_field_count += 1;
                self.error(
                    "blank_required_field",
                    "required_fields entries must be non-empty",
                    FindingScope::artifact(artifact.artifact_id.as_str()).field("required_fields"),
                );
            }
        }
    }

    fn validate_freshness(&mut self, artifact: &ReadinessLabArtifactContract) {
        let freshness = &artifact.freshness;
        if freshness.observed_at_epoch_days == 0 {
            self.error(
                "missing_observed_at_epoch_days",
                "freshness.observed_at_epoch_days must be non-zero",
                FindingScope::artifact(artifact.artifact_id.as_str())
                    .field("freshness.observed_at_epoch_days"),
            );
        }
        if freshness.max_age_days == 0 {
            self.error(
                "zero_max_age_days",
                "freshness.max_age_days must be greater than zero",
                FindingScope::artifact(artifact.artifact_id.as_str())
                    .field("freshness.max_age_days"),
            );
        }
        if freshness.git_sha.trim().len() < 7 {
            self.error(
                "missing_git_sha",
                "freshness.git_sha must include at least a short git SHA",
                FindingScope::artifact(artifact.artifact_id.as_str()).field("freshness.git_sha"),
            );
        }

        let Some(reference_epoch_days) = self.config.reference_epoch_days else {
            return;
        };
        if freshness.observed_at_epoch_days > reference_epoch_days {
            self.future_artifact_count += 1;
            self.error(
                "future_artifact_timestamp",
                "readiness lab artifact timestamp is newer than the reference date",
                FindingScope::artifact(artifact.artifact_id.as_str())
                    .field("freshness.observed_at_epoch_days"),
            );
        }
        if freshness
            .observed_at_epoch_days
            .saturating_add(freshness.max_age_days)
            < reference_epoch_days
        {
            self.stale_artifact_count += 1;
            self.error(
                "stale_artifact",
                "readiness lab artifact is older than its max_age_days window",
                FindingScope::artifact(artifact.artifact_id.as_str()).field("freshness"),
            );
        }
    }

    fn validate_lane(&mut self, lane: &ReadinessLabLanePlan, artifact_ids: &BTreeSet<&str>) {
        if lane.lane_id.trim().is_empty() {
            self.error(
                "missing_lane_id",
                "lane_id must be non-empty",
                FindingScope::default().field("lane_id"),
            );
        }
        if lane.next_safe_command.trim().is_empty() {
            self.error(
                "missing_next_safe_command",
                "next_safe_command must be non-empty",
                FindingScope::lane(lane.lane_id.as_str()).field("next_safe_command"),
            );
        }
        if lane.expected_artifact_ids.is_empty() {
            self.error(
                "empty_expected_artifact_ids",
                "lane must reference at least one expected artifact",
                FindingScope::lane(lane.lane_id.as_str()).field("expected_artifact_ids"),
            );
        }
        for artifact_id in &lane.expected_artifact_ids {
            if !artifact_ids.contains(artifact_id.as_str()) {
                self.error(
                    "missing_expected_artifact",
                    format!("lane references unknown artifact_id {artifact_id:?}"),
                    FindingScope::lane(lane.lane_id.as_str()).field("expected_artifact_ids"),
                );
            }
        }
    }

    fn validate_rch_assumption(&mut self, assumption: &ReadinessLabRchAssumption) {
        if assumption.assumption_id.trim().is_empty() {
            self.error(
                "missing_assumption_id",
                "assumption_id must be non-empty",
                FindingScope::default().field("assumption_id"),
            );
        }
        if assumption.command.trim().is_empty() {
            self.error(
                "missing_rch_command",
                "RCH assumption command must be non-empty",
                FindingScope::assumption(assumption.assumption_id.as_str()).field("command"),
            );
        }
        if assumption.target_dir.trim().is_empty() {
            self.error(
                "missing_target_dir",
                "RCH assumption target_dir must be non-empty",
                FindingScope::assumption(assumption.assumption_id.as_str()).field("target_dir"),
            );
        }
        if assumption.local_fallback_allowed {
            self.error(
                "local_fallback_allowed",
                "readiness lab contracts must reject local cargo fallback for heavy lanes",
                FindingScope::assumption(assumption.assumption_id.as_str())
                    .field("local_fallback_allowed"),
            );
        }
        if assumption.executes_cargo {
            if !assumption.command.contains("rch exec") {
                self.error(
                    "cargo_without_rch_exec",
                    "cargo-executing assumptions must route through rch exec",
                    FindingScope::assumption(assumption.assumption_id.as_str()).field("command"),
                );
            }
            if !assumption
                .env_allowlist
                .iter()
                .any(|entry| entry == "CARGO_TARGET_DIR")
            {
                self.error(
                    "missing_cargo_target_dir_allowlist",
                    "cargo-executing assumptions must allowlist CARGO_TARGET_DIR",
                    FindingScope::assumption(assumption.assumption_id.as_str())
                        .field("env_allowlist"),
                );
            }
        }
    }

    fn finish(self) -> ReadinessLabValidationReport {
        ReadinessLabValidationReport {
            schema_version: READINESS_LAB_REPORT_SCHEMA_VERSION,
            lab_id: self.bundle.lab_id.clone(),
            manifest_path: self.config.manifest_path.clone(),
            valid: self.errors.is_empty(),
            artifact_count: self.bundle.artifacts.len(),
            lane_count: self.bundle.lane_plans.len(),
            rch_assumption_count: self.bundle.rch_assumptions.len(),
            advisory_artifact_count: self.advisory_artifact_count,
            stale_artifact_count: self.stale_artifact_count,
            future_artifact_count: self.future_artifact_count,
            product_claim_violation_count: self.product_claim_violation_count,
            missing_required_field_count: self.missing_required_field_count,
            duplicate_id_count: self.duplicate_id_count,
            errors: self.errors,
            warnings: self.warnings,
        }
    }

    fn error(
        &mut self,
        finding_id: impl Into<String>,
        message: impl Into<String>,
        scope: FindingScope,
    ) {
        self.errors.push(scope.into_finding(
            finding_id.into(),
            ReadinessLabFindingSeverity::Error,
            message.into(),
        ));
    }
}

struct ReadinessLabRchLanePlanner<'a> {
    manifest: &'a ReadinessLabRchLaneScheduleManifest,
    config: &'a ReadinessLabRchLaneScheduleConfig,
    errors: Vec<ReadinessLabFinding>,
    warnings: Vec<ReadinessLabFinding>,
    coalesced_duplicate_count: usize,
    target_dir_conflict_count: usize,
    missing_evidence_count: usize,
    local_fallback_violation_count: usize,
    rows: Vec<ReadinessLabRchLaneScheduleRow>,
}

impl<'a> ReadinessLabRchLanePlanner<'a> {
    fn new(
        manifest: &'a ReadinessLabRchLaneScheduleManifest,
        config: &'a ReadinessLabRchLaneScheduleConfig,
    ) -> Self {
        Self {
            manifest,
            config,
            errors: Vec::new(),
            warnings: Vec::new(),
            coalesced_duplicate_count: 0,
            target_dir_conflict_count: 0,
            missing_evidence_count: 0,
            local_fallback_violation_count: 0,
            rows: Vec::new(),
        }
    }

    fn validate_manifest(&mut self) {
        self.check_identity();
        self.check_evidence();
        self.check_worker_hints();
        for lane in &self.manifest.lanes {
            self.validate_lane(lane);
        }
    }

    fn check_identity(&mut self) {
        if self.manifest.schema_version != READINESS_LAB_SCHEMA_VERSION {
            self.error(
                "unsupported_schema_version",
                format!(
                    "schema_version must be {READINESS_LAB_SCHEMA_VERSION}, got {}",
                    self.manifest.schema_version
                ),
                FindingScope::default().field("schema_version"),
            );
        }
        if self.manifest.plan_id.trim().is_empty() {
            self.error(
                "missing_plan_id",
                "plan_id must be non-empty",
                FindingScope::default().field("plan_id"),
            );
        }
        if self.manifest.generated_at_epoch_days == 0 {
            self.error(
                "missing_generated_at_epoch_days",
                "generated_at_epoch_days must be non-zero",
                FindingScope::default().field("generated_at_epoch_days"),
            );
        }
        if self.manifest.advisory_notice.trim() != READINESS_LAB_ADVISORY_NOTICE {
            self.error(
                "invalid_advisory_notice",
                format!("advisory_notice must be exactly {READINESS_LAB_ADVISORY_NOTICE:?}"),
                FindingScope::default().field("advisory_notice"),
            );
        }
        if !self.manifest.source_bead.starts_with("bd-") {
            self.error(
                "malformed_source_bead",
                "source_bead must look like bd-...",
                FindingScope::default().field("source_bead"),
            );
        }
        if self.manifest.artifact_root.trim().is_empty() {
            self.error(
                "missing_artifact_root",
                "artifact_root must be non-empty",
                FindingScope::default().field("artifact_root"),
            );
        }
        if self.manifest.lanes.is_empty() {
            self.error(
                "empty_lane_schedule",
                "lanes must include at least one dry-run validation lane",
                FindingScope::default().field("lanes"),
            );
        }
    }

    fn check_evidence(&mut self) {
        if duplicate_count(
            self.manifest
                .evidence
                .iter()
                .map(|evidence| evidence.evidence_id.as_str()),
        ) > 0
        {
            self.error(
                "duplicate_evidence_ids",
                "evidence_id values must be unique",
                FindingScope::default().field("evidence"),
            );
        }

        for evidence in &self.manifest.evidence {
            if evidence.evidence_id.trim().is_empty() {
                self.error(
                    "missing_evidence_id",
                    "evidence_id must be non-empty",
                    FindingScope::default().field("evidence_id"),
                );
            }
            if evidence.observed_at_epoch_days == 0 {
                self.error(
                    "missing_evidence_observed_at",
                    "evidence observed_at_epoch_days must be non-zero",
                    FindingScope::assumption(evidence.evidence_id.as_str())
                        .field("observed_at_epoch_days"),
                );
            }
            if evidence.max_age_days == 0 {
                self.error(
                    "zero_evidence_max_age_days",
                    "evidence max_age_days must be greater than zero",
                    FindingScope::assumption(evidence.evidence_id.as_str()).field("max_age_days"),
                );
            }
            if evidence.worker_identity.trim().is_empty() {
                self.error(
                    "missing_evidence_worker_identity",
                    "evidence worker_identity must be non-empty",
                    FindingScope::assumption(evidence.evidence_id.as_str())
                        .field("worker_identity"),
                );
            }
            if !evidence.rch_available {
                self.missing_evidence_count += 1;
                self.error(
                    "rch_evidence_unavailable",
                    "required RCH evidence says rch_available=false",
                    FindingScope::assumption(evidence.evidence_id.as_str()).field("rch_available"),
                );
            }
            if let Some(reference_epoch_days) = self.config.reference_epoch_days {
                if evidence.observed_at_epoch_days > reference_epoch_days {
                    self.error(
                        "future_rch_evidence",
                        "RCH evidence timestamp is newer than the reference date",
                        FindingScope::assumption(evidence.evidence_id.as_str())
                            .field("observed_at_epoch_days"),
                    );
                }
                if evidence
                    .observed_at_epoch_days
                    .saturating_add(evidence.max_age_days)
                    < reference_epoch_days
                {
                    self.error(
                        "stale_rch_evidence",
                        "RCH evidence is older than its max_age_days window",
                        FindingScope::assumption(evidence.evidence_id.as_str())
                            .field("max_age_days"),
                    );
                }
            }
        }
    }

    fn check_worker_hints(&mut self) {
        if duplicate_count(
            self.manifest
                .worker_hints
                .iter()
                .map(|worker| worker.worker_id.as_str()),
        ) > 0
        {
            self.error(
                "duplicate_worker_hints",
                "worker_id values must be unique",
                FindingScope::default().field("worker_hints"),
            );
        }
        for worker in &self.manifest.worker_hints {
            if worker.worker_id.trim().is_empty() {
                self.error(
                    "missing_worker_id",
                    "worker_id must be non-empty",
                    FindingScope::default().field("worker_id"),
                );
            }
            if worker.logical_cpus == 0 {
                self.error(
                    "zero_worker_logical_cpus",
                    "worker logical_cpus must be greater than zero",
                    FindingScope::assumption(worker.worker_id.as_str()).field("logical_cpus"),
                );
            }
            if worker.ram_gib == 0 {
                self.error(
                    "zero_worker_ram_gib",
                    "worker ram_gib must be greater than zero",
                    FindingScope::assumption(worker.worker_id.as_str()).field("ram_gib"),
                );
            }
            if worker.max_parallel_lanes == 0 {
                self.error(
                    "zero_worker_max_parallel_lanes",
                    "worker max_parallel_lanes must be greater than zero",
                    FindingScope::assumption(worker.worker_id.as_str()).field("max_parallel_lanes"),
                );
            }
        }
    }

    fn validate_lane(&mut self, lane: &ReadinessLabRchValidationLane) {
        if lane.lane_id.trim().is_empty() {
            self.error(
                "missing_lane_id",
                "lane_id must be non-empty",
                FindingScope::default().field("lane_id"),
            );
        }
        if lane.command.trim().is_empty() {
            self.error(
                "missing_lane_command",
                "lane command must be non-empty",
                FindingScope::lane(lane.lane_id.as_str()).field("command"),
            );
        }
        if lane.target_dir.trim().is_empty() {
            self.error(
                "missing_target_dir",
                "lane target_dir must be non-empty",
                FindingScope::lane(lane.lane_id.as_str()).field("target_dir"),
            );
        }
        if lane.artifact_path.trim().is_empty() {
            self.error(
                "missing_artifact_path",
                "lane artifact_path must be non-empty",
                FindingScope::lane(lane.lane_id.as_str()).field("artifact_path"),
            );
        }
        if lane.estimated_cost_units == 0 {
            self.error(
                "zero_estimated_cost_units",
                "estimated_cost_units must be greater than zero",
                FindingScope::lane(lane.lane_id.as_str()).field("estimated_cost_units"),
            );
        }
        if lane.local_fallback_allowed {
            self.local_fallback_violation_count += 1;
            self.error(
                "local_fallback_allowed",
                "RCH lane schedules must reject local cargo fallback",
                FindingScope::lane(lane.lane_id.as_str()).field("local_fallback_allowed"),
            );
        }
        if lane.executes_cargo {
            if !lane.command.contains("rch exec -- cargo") {
                self.error(
                    "cargo_without_rch_exec",
                    "cargo-executing lanes must route through rch exec",
                    FindingScope::lane(lane.lane_id.as_str()).field("command"),
                );
            }
            if !lane.command.contains("CARGO_TARGET_DIR=")
                || !lane.command.contains(lane.target_dir.as_str())
            {
                self.error(
                    "missing_target_dir_env",
                    "cargo-executing lanes must bind CARGO_TARGET_DIR to the lane target_dir",
                    FindingScope::lane(lane.lane_id.as_str()).field("command"),
                );
            }
            if !lane
                .env_allowlist
                .iter()
                .any(|entry| entry == "CARGO_TARGET_DIR")
            {
                self.error(
                    "missing_cargo_target_dir_allowlist",
                    "cargo-executing lanes must allowlist CARGO_TARGET_DIR",
                    FindingScope::lane(lane.lane_id.as_str()).field("env_allowlist"),
                );
            }
        }
    }

    fn plan(&mut self) {
        let evidence_ids = self
            .manifest
            .evidence
            .iter()
            .map(|evidence| evidence.evidence_id.as_str())
            .collect::<BTreeSet<_>>();
        let worker_ids = self
            .manifest
            .worker_hints
            .iter()
            .map(|worker| worker.worker_id.as_str())
            .collect::<BTreeSet<_>>();

        let mut work_key_to_canonical = BTreeMap::<String, String>::new();
        let mut lane_to_canonical = BTreeMap::<String, String>::new();
        let mut canonical_lanes = Vec::<&ReadinessLabRchValidationLane>::new();
        let mut coalesced_from = BTreeMap::<String, Vec<String>>::new();
        let mut duplicate_lane_ids = BTreeSet::new();

        for lane in &self.manifest.lanes {
            if !lane.lane_id.trim().is_empty()
                && lane_to_canonical.contains_key(lane.lane_id.as_str())
            {
                duplicate_lane_ids.insert(lane.lane_id.clone());
                continue;
            }

            let key = lane_work_key(lane);
            if let Some(canonical) = work_key_to_canonical.get(&key) {
                self.coalesced_duplicate_count += 1;
                lane_to_canonical.insert(lane.lane_id.clone(), canonical.clone());
                coalesced_from
                    .entry(canonical.clone())
                    .or_default()
                    .push(lane.lane_id.clone());
            } else {
                let canonical = lane.lane_id.clone();
                work_key_to_canonical.insert(key, canonical.clone());
                lane_to_canonical.insert(lane.lane_id.clone(), canonical.clone());
                coalesced_from.entry(canonical).or_default();
                canonical_lanes.push(lane);
            }
        }

        for duplicate_lane_id in duplicate_lane_ids {
            self.error(
                "duplicate_lane_id",
                format!("duplicate lane_id {duplicate_lane_id:?} is not schedulable"),
                FindingScope::lane(duplicate_lane_id.as_str()).field("lane_id"),
            );
        }

        let canonical_ids = canonical_lanes
            .iter()
            .map(|lane| lane.lane_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut canonical_dependencies = BTreeMap::<String, BTreeSet<String>>::new();
        let mut target_dir_owner = BTreeMap::<String, String>::new();

        for lane in &canonical_lanes {
            let mut deps = BTreeSet::new();
            for dependency in &lane.dependencies {
                match lane_to_canonical.get(dependency) {
                    Some(canonical) if canonical != &lane.lane_id => {
                        deps.insert(canonical.clone());
                    }
                    Some(_) => {
                        self.error(
                            "self_dependency",
                            "lane depends on itself after duplicate coalescing",
                            FindingScope::lane(lane.lane_id.as_str()).field("dependencies"),
                        );
                    }
                    None => self.error(
                        "missing_lane_dependency",
                        format!("lane depends on unknown lane_id {dependency:?}"),
                        FindingScope::lane(lane.lane_id.as_str()).field("dependencies"),
                    ),
                }
            }
            for evidence_id in &lane.required_evidence_ids {
                if !evidence_ids.contains(evidence_id.as_str()) {
                    self.missing_evidence_count += 1;
                    self.error(
                        "missing_rch_evidence",
                        format!("lane requires missing evidence_id {evidence_id:?}"),
                        FindingScope::lane(lane.lane_id.as_str()).field("required_evidence_ids"),
                    );
                }
            }
            if let Some(worker_hint) = &lane.worker_hint
                && !worker_ids.contains(worker_hint.as_str())
            {
                self.error(
                    "missing_worker_hint",
                    format!("lane references unknown worker_hint {worker_hint:?}"),
                    FindingScope::lane(lane.lane_id.as_str()).field("worker_hint"),
                );
            }
            if lane.executes_cargo
                && let Some(owner) =
                    target_dir_owner.insert(lane.target_dir.clone(), lane.lane_id.clone())
            {
                self.target_dir_conflict_count += 1;
                self.error(
                    "target_dir_conflict",
                    format!(
                        "cargo lanes {owner:?} and {:?} share target_dir {:?}",
                        lane.lane_id, lane.target_dir
                    ),
                    FindingScope::lane(lane.lane_id.as_str()).field("target_dir"),
                );
            }
            canonical_dependencies.insert(lane.lane_id.clone(), deps);
        }

        self.rows = self.ordered_rows(
            &canonical_lanes,
            &canonical_ids,
            &canonical_dependencies,
            &coalesced_from,
        );
    }

    fn ordered_rows(
        &mut self,
        canonical_lanes: &[&'a ReadinessLabRchValidationLane],
        canonical_ids: &BTreeSet<&str>,
        canonical_dependencies: &BTreeMap<String, BTreeSet<String>>,
        coalesced_from: &BTreeMap<String, Vec<String>>,
    ) -> Vec<ReadinessLabRchLaneScheduleRow> {
        let mut planned = BTreeSet::<String>::new();
        let mut rows = Vec::new();

        while planned.len() < canonical_ids.len() {
            let mut progressed = false;
            for lane in canonical_lanes {
                if planned.contains(lane.lane_id.as_str()) {
                    continue;
                }
                let deps = canonical_dependencies
                    .get(lane.lane_id.as_str())
                    .cloned()
                    .unwrap_or_default();
                if deps.iter().all(|dependency| planned.contains(dependency)) {
                    rows.push(Self::row_for_lane(
                        lane,
                        rows.len() + 1,
                        &deps,
                        coalesced_from,
                    ));
                    planned.insert(lane.lane_id.clone());
                    progressed = true;
                }
            }
            if !progressed {
                let remaining = canonical_lanes
                    .iter()
                    .filter(|lane| !planned.contains(lane.lane_id.as_str()))
                    .map(|lane| lane.lane_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                self.error(
                    "lane_dependency_cycle",
                    format!("lane dependencies could not be ordered: {remaining}"),
                    FindingScope::default().field("dependencies"),
                );
                for lane in canonical_lanes {
                    if !planned.contains(lane.lane_id.as_str()) {
                        let deps = canonical_dependencies
                            .get(lane.lane_id.as_str())
                            .cloned()
                            .unwrap_or_default();
                        rows.push(Self::row_for_lane(
                            lane,
                            rows.len() + 1,
                            &deps,
                            coalesced_from,
                        ));
                        planned.insert(lane.lane_id.clone());
                    }
                }
            }
        }

        rows
    }

    fn row_for_lane(
        lane: &ReadinessLabRchValidationLane,
        ordinal: usize,
        deps: &BTreeSet<String>,
        coalesced_from: &BTreeMap<String, Vec<String>>,
    ) -> ReadinessLabRchLaneScheduleRow {
        ReadinessLabRchLaneScheduleRow {
            ordinal,
            lane_id: lane.lane_id.clone(),
            lane_kind: lane.lane_kind.label().to_owned(),
            command: lane.command.clone(),
            target_dir: lane.target_dir.clone(),
            artifact_path: lane.artifact_path.clone(),
            env_allowlist: lane.env_allowlist.clone(),
            estimated_cost_units: lane.estimated_cost_units,
            dependencies: deps.iter().cloned().collect(),
            required_evidence_ids: lane.required_evidence_ids.clone(),
            worker_hint: lane.worker_hint.clone(),
            coalesced_from: coalesced_from
                .get(lane.lane_id.as_str())
                .cloned()
                .unwrap_or_default(),
        }
    }

    fn finish(self) -> ReadinessLabRchLaneScheduleReport {
        ReadinessLabRchLaneScheduleReport {
            schema_version: READINESS_LAB_RCH_LANE_SCHEDULE_REPORT_SCHEMA_VERSION,
            plan_id: self.manifest.plan_id.clone(),
            manifest_path: self.config.manifest_path.clone(),
            valid: self.errors.is_empty(),
            dry_run_only: true,
            product_evidence_claim: READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM.to_owned(),
            release_gate_effect:
                "RCH lane scheduler output is advisory dry-run planning only; it never executes cargo lanes and cannot promote readiness claims"
                    .to_owned(),
            source_bead: self.manifest.source_bead.clone(),
            artifact_root: self.manifest.artifact_root.clone(),
            lane_count: self.manifest.lanes.len(),
            planned_lane_count: self.rows.len(),
            coalesced_duplicate_count: self.coalesced_duplicate_count,
            target_dir_conflict_count: self.target_dir_conflict_count,
            missing_evidence_count: self.missing_evidence_count,
            local_fallback_violation_count: self.local_fallback_violation_count,
            rows: self.rows,
            errors: self.errors,
            warnings: self.warnings,
        }
    }

    fn error(
        &mut self,
        finding_id: impl Into<String>,
        message: impl Into<String>,
        scope: FindingScope,
    ) {
        self.errors.push(scope.into_finding(
            finding_id.into(),
            ReadinessLabFindingSeverity::Error,
            message.into(),
        ));
    }
}

struct ReadinessLabTruthGraphBuilder<'a> {
    manifest: &'a ReadinessLabTruthGraphManifest,
    config: &'a ReadinessLabTruthGraphConfig,
    nodes: BTreeMap<String, ReadinessLabTruthGraphNode>,
    edges: Vec<ReadinessLabTruthGraphEdge>,
    claim_observations: BTreeMap<String, Vec<TruthGraphClaimObservation>>,
    explicit_supersedes: Vec<(String, String, String)>,
    errors: Vec<ReadinessLabFinding>,
    warnings: Vec<ReadinessLabFinding>,
    stale_claim_count: usize,
    contradictory_claim_count: usize,
    missing_raw_log_count: usize,
    permission_requirement_count: usize,
    simulated_node_count: usize,
    blocker_edge_count: usize,
    claim_count: usize,
    contradictions: Vec<ReadinessLabTruthGraphContradiction>,
}

impl<'a> ReadinessLabTruthGraphBuilder<'a> {
    fn new(
        manifest: &'a ReadinessLabTruthGraphManifest,
        config: &'a ReadinessLabTruthGraphConfig,
    ) -> Self {
        Self {
            manifest,
            config,
            nodes: BTreeMap::new(),
            edges: Vec::new(),
            claim_observations: BTreeMap::new(),
            explicit_supersedes: Vec::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
            stale_claim_count: 0,
            contradictory_claim_count: 0,
            missing_raw_log_count: 0,
            permission_requirement_count: 0,
            simulated_node_count: 0,
            blocker_edge_count: 0,
            claim_count: 0,
            contradictions: Vec::new(),
        }
    }

    fn validate_manifest(&mut self) {
        if self.manifest.schema_version != READINESS_LAB_SCHEMA_VERSION {
            self.error(
                "unsupported_schema_version",
                format!(
                    "schema_version must be {READINESS_LAB_SCHEMA_VERSION}, got {}",
                    self.manifest.schema_version
                ),
                FindingScope::default().field("schema_version"),
            );
        }
        if self.manifest.graph_id.trim().is_empty() {
            self.error(
                "missing_graph_id",
                "graph_id must be non-empty",
                FindingScope::default().field("graph_id"),
            );
        }
        if self.manifest.generated_at_epoch_days == 0 {
            self.error(
                "missing_generated_at_epoch_days",
                "generated_at_epoch_days must be non-zero",
                FindingScope::default().field("generated_at_epoch_days"),
            );
        }
        if self.manifest.advisory_notice.trim() != READINESS_LAB_ADVISORY_NOTICE {
            self.error(
                "invalid_advisory_notice",
                format!("advisory_notice must be exactly {READINESS_LAB_ADVISORY_NOTICE:?}"),
                FindingScope::default().field("advisory_notice"),
            );
        }
        if !self.manifest.source_bead.starts_with("bd-") {
            self.error(
                "malformed_source_bead",
                "source_bead must look like bd-...",
                FindingScope::default().field("source_bead"),
            );
        }
        if self.manifest.sources.is_empty() {
            self.error(
                "empty_truth_graph_sources",
                "truth graph sources must include at least one validator or lab report",
                FindingScope::default().field("sources"),
            );
        }
        if duplicate_count(
            self.manifest
                .sources
                .iter()
                .map(|source| source.source_id.as_str()),
        ) > 0
        {
            self.error(
                "duplicate_truth_graph_source_ids",
                "source_id values must be unique",
                FindingScope::default().field("sources"),
            );
        }

        for source in &self.manifest.sources {
            self.validate_source(source);
        }
    }

    fn validate_source(&mut self, source: &ReadinessLabTruthGraphSource) {
        if source.source_id.trim().is_empty() {
            self.error(
                "missing_truth_graph_source_id",
                "source_id must be non-empty",
                FindingScope::default().field("source_id"),
            );
        }
        if source.path.trim().is_empty() {
            self.error(
                "missing_truth_graph_source_path",
                "source path must be non-empty",
                FindingScope::assumption(source.source_id.as_str()).field("path"),
            );
        }
        if !source.valid {
            self.error(
                "source_validator_failed",
                "truth graph source report says valid=false",
                FindingScope::assumption(source.source_id.as_str()).field("valid"),
            );
        }
        if source.claims.is_empty() {
            self.error(
                "source_without_claims",
                "truth graph sources must expose at least one claim",
                FindingScope::assumption(source.source_id.as_str()).field("claims"),
            );
        }
        if duplicate_count(source.claims.iter().map(|claim| claim.claim_id.as_str())) > 0 {
            self.error(
                "duplicate_source_claim_ids",
                "claim_id values must be unique within a source",
                FindingScope::assumption(source.source_id.as_str()).field("claims"),
            );
        }
        if matches!(
            source.source_kind,
            ReadinessLabTruthGraphSourceKind::TopologyRuntimeAdvisorReport
        ) && source
            .claims
            .iter()
            .any(|claim| claim.topology_advisor.is_none())
        {
            self.error(
                "missing_topology_advisor_metadata",
                "topology runtime advisor sources must include topology_advisor metadata on each claim",
                FindingScope::assumption(source.source_id.as_str()).field("claims"),
            );
        }
        for claim in &source.claims {
            self.validate_claim(source, claim);
        }
    }

    fn validate_claim(
        &mut self,
        source: &ReadinessLabTruthGraphSource,
        claim: &ReadinessLabTruthGraphClaimInput,
    ) {
        if claim.claim_id.trim().is_empty() {
            self.error(
                "missing_truth_graph_claim_id",
                "claim_id must be non-empty",
                FindingScope::assumption(source.source_id.as_str()).field("claim_id"),
            );
        }
        if claim.validator_report_path.trim().is_empty() {
            self.error(
                "missing_validator_report_path",
                "claim validator_report_path must be non-empty",
                FindingScope::lane(claim.claim_id.as_str()).field("validator_report_path"),
            );
        }
        if !claim.source_bead.starts_with("bd-") {
            self.error(
                "malformed_claim_source_bead",
                "claim source_bead must look like bd-...",
                FindingScope::lane(claim.claim_id.as_str()).field("source_bead"),
            );
        }
        if matches!(
            claim.claim_state,
            ReadinessLabTruthGraphClaimState::Validated
        ) && !matches!(
            claim.product_evidence_claim,
            ReadinessLabProductEvidenceClaim::ProductPassFail
        ) {
            self.warning(
                "validated_claim_without_product_evidence",
                "validated claims should identify the product pass/fail evidence they derive from",
                FindingScope::lane(claim.claim_id.as_str()).field("product_evidence_claim"),
            );
        }
        for artifact in &claim.artifacts {
            if artifact.artifact_id.trim().is_empty() {
                self.error(
                    "missing_truth_graph_artifact_id",
                    "artifact_id must be non-empty",
                    FindingScope::lane(claim.claim_id.as_str()).field("artifacts"),
                );
            }
            if artifact.path.trim().is_empty() {
                self.error(
                    "missing_truth_graph_artifact_path",
                    "artifact path must be non-empty",
                    FindingScope::artifact(artifact.artifact_id.as_str()).field("path"),
                );
            }
            if !is_safe_readiness_lab_relative_path(&artifact.path) {
                self.error(
                    "unsafe_truth_graph_artifact_path",
                    "artifact path must be a safe relative path without parent traversal",
                    FindingScope::artifact(artifact.artifact_id.as_str()).field("path"),
                );
            }
        }
        for blocker in &claim.blockers {
            if blocker.blocker_id.trim().is_empty() {
                self.error(
                    "missing_truth_graph_blocker_id",
                    "blocker_id must be non-empty",
                    FindingScope::lane(claim.claim_id.as_str()).field("blockers"),
                );
            }
            if blocker.reason.trim().is_empty() {
                self.error(
                    "missing_truth_graph_blocker_reason",
                    "blocker reason must be non-empty",
                    FindingScope::assumption(blocker.blocker_id.as_str()).field("reason"),
                );
            }
            if blocker_link_missing(
                blocker.validator_report_path.as_deref(),
                blocker.bead_id.as_deref(),
            ) {
                self.error(
                    "blocker_without_report_or_bead",
                    "every blocker edge must link to a validator report path or bead id",
                    FindingScope::assumption(blocker.blocker_id.as_str()),
                );
            }
        }
        if let Some(permission) = &claim.permission {
            if permission.permission_id.trim().is_empty() {
                self.error(
                    "missing_permission_id",
                    "permission_id must be non-empty",
                    FindingScope::lane(claim.claim_id.as_str()).field("permission"),
                );
            }
            if !permission.bead_id.starts_with("bd-") {
                self.error(
                    "malformed_permission_bead",
                    "permission bead_id must look like bd-...",
                    FindingScope::assumption(permission.permission_id.as_str()).field("bead_id"),
                );
            }
            if permission.ack_env.trim().is_empty() {
                self.error(
                    "missing_permission_ack_env",
                    "permission ack_env must be non-empty",
                    FindingScope::assumption(permission.permission_id.as_str()).field("ack_env"),
                );
            }
        }
        if let Some(advisor) = &claim.topology_advisor {
            self.validate_topology_advisor_claim(source, claim, advisor);
        }
    }

    fn validate_topology_advisor_claim(
        &mut self,
        source: &ReadinessLabTruthGraphSource,
        claim: &ReadinessLabTruthGraphClaimInput,
        advisor: &ReadinessLabTruthGraphTopologyAdvisorInput,
    ) {
        if !matches!(
            source.source_kind,
            ReadinessLabTruthGraphSourceKind::TopologyRuntimeAdvisorReport
        ) {
            self.error(
                "topology_advisor_wrong_source_kind",
                "topology_advisor metadata is only valid on topology_runtime_advisor_report sources",
                FindingScope::lane(claim.claim_id.as_str()).field("topology_advisor"),
            );
        }
        if advisor.source_bead != claim.source_bead {
            self.error(
                "topology_advisor_source_bead_mismatch",
                "topology advisor source_bead must match the truth graph claim source_bead",
                FindingScope::lane(claim.claim_id.as_str()).field("topology_advisor.source_bead"),
            );
        }
        if !advisor.real_campaign_bead.starts_with("bd-") {
            self.error(
                "topology_advisor_real_campaign_bead_malformed",
                "topology advisor real_campaign_bead must look like bd-...",
                FindingScope::lane(claim.claim_id.as_str())
                    .field("topology_advisor.real_campaign_bead"),
            );
        }
        if claim.claim_id == "swarm.responsiveness" && advisor.real_campaign_bead != "bd-rchk0.53.8"
        {
            self.error(
                "topology_advisor_real_campaign_bead_mismatch",
                "swarm.responsiveness topology advisor metadata must point at bd-rchk0.53.8",
                FindingScope::lane(claim.claim_id.as_str())
                    .field("topology_advisor.real_campaign_bead"),
            );
        }
        if !advisor.advisory_only {
            self.error(
                "topology_advisor_not_advisory_only",
                "topology advisor metadata must keep advisory_only=true",
                FindingScope::lane(claim.claim_id.as_str()).field("topology_advisor.advisory_only"),
            );
        }
        if advisor.product_evidence_claim != ReadinessLabProductEvidenceClaim::None {
            self.error(
                "topology_advisor_product_evidence_claim",
                "topology advisor metadata must use product_evidence_claim=none",
                FindingScope::lane(claim.claim_id.as_str())
                    .field("topology_advisor.product_evidence_claim"),
            );
        }
        if advisor.release_gate_effect != READINESS_LAB_ADVISORY_RELEASE_GATE_EFFECT {
            self.error(
                "topology_advisor_release_gate_effect",
                "topology advisor metadata must use release_gate_effect=advisory_only",
                FindingScope::lane(claim.claim_id.as_str())
                    .field("topology_advisor.release_gate_effect"),
            );
        }
        if claim.product_evidence_claim != ReadinessLabProductEvidenceClaim::None {
            self.error(
                "topology_advisor_claim_product_evidence",
                "topology advisor truth graph claims must use product_evidence_claim=none",
                FindingScope::lane(claim.claim_id.as_str()).field("product_evidence_claim"),
            );
        }
        if matches!(
            claim.claim_state,
            ReadinessLabTruthGraphClaimState::Validated
        ) {
            self.error(
                "topology_advisor_claim_validated",
                "topology advisor claims must stay blocked, simulated, dry_run_only, or handoff_only",
                FindingScope::lane(claim.claim_id.as_str()).field("claim_state"),
            );
        }
        if claim.claim_id == "swarm.responsiveness"
            && !advisor
                .blocked_claims
                .iter()
                .any(|blocked| blocked == "swarm.responsiveness")
        {
            self.error(
                "topology_advisor_missing_swarm_block",
                "swarm.responsiveness must remain listed in topology advisor blocked_claims",
                FindingScope::lane(claim.claim_id.as_str())
                    .field("topology_advisor.blocked_claims"),
            );
        }
        if advisor.manifest_hash.trim().is_empty() {
            self.error(
                "topology_advisor_missing_manifest_hash",
                "topology advisor metadata must include a manifest hash",
                FindingScope::lane(claim.claim_id.as_str()).field("topology_advisor.manifest_hash"),
            );
        }
        for path_field in [
            (
                "topology_advisor.topology_advisor_report_path",
                advisor.topology_advisor_report_path.as_str(),
            ),
            (
                "topology_advisor.score_report_path",
                advisor.score_report_path.as_str(),
            ),
            (
                "topology_advisor.structured_log_path",
                advisor.structured_log_path.as_str(),
            ),
            (
                "topology_advisor.artifact_root",
                advisor.artifact_root.as_str(),
            ),
        ] {
            if !is_safe_readiness_lab_relative_path(path_field.1) {
                self.error(
                    "topology_advisor_unsafe_path",
                    "topology advisor paths must be safe relative paths without parent traversal",
                    FindingScope::lane(claim.claim_id.as_str()).field(path_field.0),
                );
            }
        }
        for (index, artifact_path) in advisor.artifact_paths.iter().enumerate() {
            if !is_safe_readiness_lab_relative_path(artifact_path) {
                let field = format!("topology_advisor.artifact_paths[{index}]");
                self.error(
                    "topology_advisor_unsafe_artifact_path",
                    "topology advisor artifact paths must be safe relative paths without parent traversal",
                    FindingScope::lane(claim.claim_id.as_str()).field(&field),
                );
            }
        }
        if claim.artifacts.iter().any(|artifact| {
            artifact
                .sha256
                .as_deref()
                .is_none_or(|hash| hash.trim().is_empty())
        }) {
            self.error(
                "topology_advisor_missing_artifact_hash",
                "topology advisor graph artifacts must include sha256 hashes",
                FindingScope::lane(claim.claim_id.as_str()).field("artifacts"),
            );
        }
        if let Some(freshness) = &claim.freshness {
            let freshness_status = self.freshness_status(freshness);
            if matches!(freshness_status.as_str(), "stale" | "future") {
                self.error(
                    "topology_advisor_stale_report",
                    "topology advisor reports must be fresh before they enter the truth graph",
                    FindingScope::lane(claim.claim_id.as_str()).field("freshness"),
                );
            }
        }
        self.validate_topology_forbidden_wording(claim, advisor);
    }

    fn validate_topology_forbidden_wording(
        &mut self,
        claim: &ReadinessLabTruthGraphClaimInput,
        advisor: &ReadinessLabTruthGraphTopologyAdvisorInput,
    ) {
        for (field, value) in [
            (
                "topology_advisor.topology_advisor_report_path",
                advisor.topology_advisor_report_path.as_str(),
            ),
            (
                "topology_advisor.score_report_path",
                advisor.score_report_path.as_str(),
            ),
            (
                "topology_advisor.structured_log_path",
                advisor.structured_log_path.as_str(),
            ),
            (
                "topology_advisor.manifest_hash",
                advisor.manifest_hash.as_str(),
            ),
            (
                "topology_advisor.recommendation",
                advisor.recommendation.as_deref().unwrap_or(""),
            ),
            (
                "topology_advisor.artifact_root",
                advisor.artifact_root.as_str(),
            ),
            (
                "topology_advisor.release_gate_effect",
                advisor.release_gate_effect.as_str(),
            ),
        ] {
            if contains_forbidden_topology_claim_wording(value) {
                self.error(
                    "topology_advisor_forbidden_promotion_wording",
                    "topology advisor metadata must not contain accepted_large_host or product pass wording",
                    FindingScope::lane(claim.claim_id.as_str()).field(field),
                );
            }
        }
        for (index, candidate) in advisor.rejected_candidates.iter().enumerate() {
            if contains_forbidden_topology_claim_wording(candidate) {
                let field = format!("topology_advisor.rejected_candidates[{index}]");
                self.error(
                    "topology_advisor_forbidden_promotion_wording",
                    "topology advisor rejected candidates must not contain accepted_large_host or product pass wording",
                    FindingScope::lane(claim.claim_id.as_str()).field(&field),
                );
            }
        }
        for (index, blocked_claim) in advisor.blocked_claims.iter().enumerate() {
            if contains_forbidden_topology_claim_wording(blocked_claim) {
                let field = format!("topology_advisor.blocked_claims[{index}]");
                self.error(
                    "topology_advisor_forbidden_promotion_wording",
                    "topology advisor blocked claims must not contain accepted_large_host or product pass wording",
                    FindingScope::lane(claim.claim_id.as_str()).field(&field),
                );
            }
        }
        for (index, artifact_path) in advisor.artifact_paths.iter().enumerate() {
            if contains_forbidden_topology_claim_wording(artifact_path) {
                let field = format!("topology_advisor.artifact_paths[{index}]");
                self.error(
                    "topology_advisor_forbidden_promotion_wording",
                    "topology advisor artifact paths must not contain accepted_large_host or product pass wording",
                    FindingScope::lane(claim.claim_id.as_str()).field(&field),
                );
            }
        }
    }

    fn build(&mut self) {
        self.insert_node(ReadinessLabTruthGraphNode {
            node_id: format!("bead:{}", self.manifest.source_bead),
            node_kind: "bead".to_owned(),
            label: self.manifest.source_bead.clone(),
            source_path: None,
            bead_id: Some(self.manifest.source_bead.clone()),
            claim_state: None,
            host_class: None,
            freshness_status: None,
            product_evidence_claim: None,
            metadata: BTreeMap::new(),
        });

        for source in &self.manifest.sources {
            self.build_source(source);
        }
        self.link_explicit_supersedes();
        self.link_fresh_observations_over_stale();
        self.detect_contradictions();
    }

    fn build_source(&mut self, source: &ReadinessLabTruthGraphSource) {
        let report_node_id = truth_node_id("report", &[source.source_id.as_str()]);
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "source_kind".to_owned(),
            source.source_kind.label().to_owned(),
        );
        self.insert_node(ReadinessLabTruthGraphNode {
            node_id: report_node_id.clone(),
            node_kind: "report".to_owned(),
            label: source.source_id.clone(),
            source_path: Some(source.path.clone()),
            bead_id: None,
            claim_state: None,
            host_class: None,
            freshness_status: None,
            product_evidence_claim: None,
            metadata,
        });

        for claim in &source.claims {
            self.build_claim(source, claim, report_node_id.as_str());
        }
    }

    fn build_claim(
        &mut self,
        source: &ReadinessLabTruthGraphSource,
        claim: &ReadinessLabTruthGraphClaimInput,
        report_node_id: &str,
    ) {
        self.claim_count += 1;
        let claim_node_id = truth_node_id(
            "claim",
            &[source.source_id.as_str(), claim.claim_id.as_str()],
        );
        let freshness_status = claim
            .freshness
            .as_ref()
            .map(|freshness| self.freshness_status(freshness));
        if freshness_status.as_deref() == Some("stale") {
            self.stale_claim_count += 1;
        }
        if matches!(
            claim.claim_state,
            ReadinessLabTruthGraphClaimState::Simulated
                | ReadinessLabTruthGraphClaimState::DryRunOnly
                | ReadinessLabTruthGraphClaimState::HandoffOnly
        ) {
            self.simulated_node_count += 1;
        }

        self.insert_node(ReadinessLabTruthGraphNode {
            node_id: claim_node_id.clone(),
            node_kind: "claim".to_owned(),
            label: claim.claim_id.clone(),
            source_path: Some(source.path.clone()),
            bead_id: Some(claim.source_bead.clone()),
            claim_state: Some(claim.claim_state.label().to_owned()),
            host_class: claim
                .freshness
                .as_ref()
                .map(|freshness| freshness.host_class.label().to_owned()),
            freshness_status: freshness_status.clone(),
            product_evidence_claim: Some(claim.product_evidence_claim.label().to_owned()),
            metadata: BTreeMap::new(),
        });
        self.claim_observations
            .entry(claim.claim_id.clone())
            .or_default()
            .push(TruthGraphClaimObservation {
                node_id: claim_node_id.clone(),
                effective_state: effective_claim_state(claim, freshness_status.as_deref()),
                freshness_status: freshness_status.clone(),
                validator_report_path: claim.validator_report_path.clone(),
                source_bead: claim.source_bead.clone(),
            });

        self.edge(
            report_node_id,
            &claim_node_id,
            "derives_from",
            "claim extracted from source report",
            Some(source.path.as_str()),
            None,
        );
        if matches!(
            claim.claim_state,
            ReadinessLabTruthGraphClaimState::Validated
        ) && freshness_status.as_deref() != Some("stale")
        {
            self.edge(
                report_node_id,
                &claim_node_id,
                "validates",
                "source report validates this readiness claim",
                Some(claim.validator_report_path.as_str()),
                Some(claim.source_bead.as_str()),
            );
        }
        self.build_claim_bead_edge(claim, claim_node_id.as_str());
        self.build_command_node(claim, claim_node_id.as_str());
        self.build_artifact_nodes(claim, claim_node_id.as_str());
        self.build_host_node(claim, claim_node_id.as_str());
        self.build_freshness_node(claim, claim_node_id.as_str());
        self.build_topology_advisor_node(claim, claim_node_id.as_str());
        self.build_permission_node(claim, claim_node_id.as_str());
        self.build_blocker_nodes(claim, claim_node_id.as_str());
        for superseded_claim_id in &claim.supersedes_claim_ids {
            self.explicit_supersedes.push((
                claim_node_id.clone(),
                claim.claim_id.clone(),
                superseded_claim_id.clone(),
            ));
        }
    }

    fn build_claim_bead_edge(
        &mut self,
        claim: &ReadinessLabTruthGraphClaimInput,
        claim_node_id: &str,
    ) {
        let bead_node_id = truth_node_id("bead", &[claim.source_bead.as_str()]);
        self.insert_node(ReadinessLabTruthGraphNode {
            node_id: bead_node_id.clone(),
            node_kind: "bead".to_owned(),
            label: claim.source_bead.clone(),
            source_path: None,
            bead_id: Some(claim.source_bead.clone()),
            claim_state: None,
            host_class: None,
            freshness_status: None,
            product_evidence_claim: None,
            metadata: BTreeMap::new(),
        });
        self.edge(
            claim_node_id,
            &bead_node_id,
            "derives_from",
            "claim is tracked by bead",
            Some(claim.validator_report_path.as_str()),
            Some(claim.source_bead.as_str()),
        );
    }

    fn build_command_node(
        &mut self,
        claim: &ReadinessLabTruthGraphClaimInput,
        claim_node_id: &str,
    ) {
        let Some(command) = &claim.command else {
            return;
        };
        if command.trim().is_empty() {
            return;
        }
        let command_node_id = truth_node_id("command", &[claim_node_id]);
        let mut metadata = BTreeMap::new();
        metadata.insert("command".to_owned(), command.clone());
        self.insert_node(ReadinessLabTruthGraphNode {
            node_id: command_node_id.clone(),
            node_kind: "command".to_owned(),
            label: command.clone(),
            source_path: None,
            bead_id: Some(claim.source_bead.clone()),
            claim_state: None,
            host_class: None,
            freshness_status: None,
            product_evidence_claim: None,
            metadata,
        });
        self.edge(
            claim_node_id,
            &command_node_id,
            "derives_from",
            "claim includes reproduction command",
            Some(claim.validator_report_path.as_str()),
            Some(claim.source_bead.as_str()),
        );
    }

    fn build_artifact_nodes(
        &mut self,
        claim: &ReadinessLabTruthGraphClaimInput,
        claim_node_id: &str,
    ) {
        for artifact in &claim.artifacts {
            let artifact_node_id =
                truth_node_id("artifact", &[claim_node_id, artifact.artifact_id.as_str()]);
            let mut metadata = BTreeMap::new();
            metadata.insert(
                "artifact_kind".to_owned(),
                artifact.artifact_kind.label().to_owned(),
            );
            metadata.insert(
                "raw_log_required".to_owned(),
                artifact.raw_log_required.to_string(),
            );
            metadata.insert(
                "raw_log_present".to_owned(),
                artifact.raw_log_present.to_string(),
            );
            if let Some(sha256) = &artifact.sha256 {
                metadata.insert("sha256".to_owned(), sha256.clone());
            }
            self.insert_node(ReadinessLabTruthGraphNode {
                node_id: artifact_node_id.clone(),
                node_kind: "artifact".to_owned(),
                label: artifact.artifact_id.clone(),
                source_path: Some(artifact.path.clone()),
                bead_id: Some(claim.source_bead.clone()),
                claim_state: None,
                host_class: None,
                freshness_status: None,
                product_evidence_claim: None,
                metadata,
            });
            if matches!(
                artifact.artifact_kind,
                ReadinessLabArtifactKind::SimulatedHostCapability
                    | ReadinessLabArtifactKind::RchSchedulingPlan
                    | ReadinessLabArtifactKind::PermissionedRunRehearsal
                    | ReadinessLabArtifactKind::ReplayFixture
            ) {
                self.simulated_node_count += 1;
            }
            self.edge(
                claim_node_id,
                &artifact_node_id,
                "derives_from",
                "claim derives from artifact",
                Some(claim.validator_report_path.as_str()),
                Some(claim.source_bead.as_str()),
            );
            if artifact.raw_log_required && !artifact.raw_log_present {
                self.missing_raw_log_count += 1;
                self.error(
                    "missing_required_raw_log",
                    format!(
                        "required raw log is missing for artifact {}",
                        artifact.artifact_id
                    ),
                    FindingScope::artifact(artifact.artifact_id.as_str()),
                );
                let blocker_node_id = truth_node_id(
                    "blocker",
                    &[
                        claim_node_id,
                        "missing_raw_log",
                        artifact.artifact_id.as_str(),
                    ],
                );
                self.insert_blocker_node(
                    &blocker_node_id,
                    "missing required raw log",
                    claim.source_bead.as_str(),
                );
                self.blocking_edge(
                    &blocker_node_id,
                    claim_node_id,
                    format!(
                        "required raw log missing for artifact {}",
                        artifact.artifact_id
                    ),
                    Some(claim.validator_report_path.as_str()),
                    Some(claim.source_bead.as_str()),
                );
            }
        }
    }

    fn build_host_node(&mut self, claim: &ReadinessLabTruthGraphClaimInput, claim_node_id: &str) {
        let Some(host) = &claim.host else {
            return;
        };
        let host_node_id = truth_node_id("host", &[claim_node_id, host.host_id.as_str()]);
        let mut metadata = BTreeMap::new();
        if let Some(logical_cpus) = host.logical_cpus {
            metadata.insert("logical_cpus".to_owned(), logical_cpus.to_string());
        }
        if let Some(ram_total_gib) = host.ram_total_gib {
            metadata.insert("ram_total_gib".to_owned(), ram_total_gib.to_string());
        }
        if let Some(numa_topology_visible) = host.numa_topology_visible {
            metadata.insert(
                "numa_topology_visible".to_owned(),
                numa_topology_visible.to_string(),
            );
        }
        self.insert_node(ReadinessLabTruthGraphNode {
            node_id: host_node_id.clone(),
            node_kind: "host_capability".to_owned(),
            label: host.host_id.clone(),
            source_path: None,
            bead_id: Some(claim.source_bead.clone()),
            claim_state: None,
            host_class: Some(host.host_class.label().to_owned()),
            freshness_status: None,
            product_evidence_claim: None,
            metadata,
        });
        if matches!(
            host.host_class,
            ReadinessLabHostClass::Synthetic | ReadinessLabHostClass::DeveloperSmoke
        ) {
            self.simulated_node_count += 1;
        }
        self.edge(
            claim_node_id,
            &host_node_id,
            "derives_from",
            "claim derives from host capability",
            Some(claim.validator_report_path.as_str()),
            Some(claim.source_bead.as_str()),
        );
    }

    fn build_freshness_node(
        &mut self,
        claim: &ReadinessLabTruthGraphClaimInput,
        claim_node_id: &str,
    ) {
        let Some(freshness) = &claim.freshness else {
            return;
        };
        let freshness_status = self.freshness_status(freshness);
        let freshness_node_id = truth_node_id("freshness", &[claim_node_id]);
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "observed_at_epoch_days".to_owned(),
            freshness.observed_at_epoch_days.to_string(),
        );
        metadata.insert(
            "max_age_days".to_owned(),
            freshness.max_age_days.to_string(),
        );
        metadata.insert("git_sha".to_owned(), freshness.git_sha.clone());
        self.insert_node(ReadinessLabTruthGraphNode {
            node_id: freshness_node_id.clone(),
            node_kind: "freshness_window".to_owned(),
            label: freshness_status.clone(),
            source_path: None,
            bead_id: Some(claim.source_bead.clone()),
            claim_state: None,
            host_class: Some(freshness.host_class.label().to_owned()),
            freshness_status: Some(freshness_status.clone()),
            product_evidence_claim: None,
            metadata,
        });
        self.edge(
            claim_node_id,
            &freshness_node_id,
            "derives_from",
            "claim derives from freshness window",
            Some(claim.validator_report_path.as_str()),
            Some(claim.source_bead.as_str()),
        );
        if matches!(freshness_status.as_str(), "stale" | "future") {
            let blocker_node_id =
                truth_node_id("blocker", &[claim_node_id, freshness_status.as_str()]);
            self.insert_blocker_node(
                &blocker_node_id,
                format!("claim freshness is {freshness_status}"),
                claim.source_bead.as_str(),
            );
            self.blocking_edge(
                &blocker_node_id,
                claim_node_id,
                format!("claim freshness is {freshness_status}"),
                Some(claim.validator_report_path.as_str()),
                Some(claim.source_bead.as_str()),
            );
        }
    }

    fn build_topology_advisor_node(
        &mut self,
        claim: &ReadinessLabTruthGraphClaimInput,
        claim_node_id: &str,
    ) {
        let Some(advisor) = &claim.topology_advisor else {
            return;
        };
        let advisor_node_id = truth_node_id(
            "topology_advisor",
            &[claim_node_id, advisor.topology_advisor_report_path.as_str()],
        );
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "topology_advisor_report_path".to_owned(),
            advisor.topology_advisor_report_path.clone(),
        );
        metadata.insert(
            "score_report_path".to_owned(),
            advisor.score_report_path.clone(),
        );
        metadata.insert(
            "structured_log_path".to_owned(),
            advisor.structured_log_path.clone(),
        );
        metadata.insert("source_bead".to_owned(), advisor.source_bead.clone());
        metadata.insert(
            "real_campaign_bead".to_owned(),
            advisor.real_campaign_bead.clone(),
        );
        metadata.insert("manifest_hash".to_owned(), advisor.manifest_hash.clone());
        metadata.insert(
            "recommendation".to_owned(),
            advisor
                .recommendation
                .clone()
                .unwrap_or_else(|| "none".to_owned()),
        );
        metadata.insert(
            "rejected_candidates".to_owned(),
            advisor.rejected_candidates.join(","),
        );
        metadata.insert(
            "blocked_claims".to_owned(),
            advisor.blocked_claims.join(","),
        );
        metadata.insert(
            "advisory_only".to_owned(),
            advisor.advisory_only.to_string(),
        );
        metadata.insert(
            "product_evidence_claim".to_owned(),
            advisor.product_evidence_claim.label().to_owned(),
        );
        metadata.insert(
            "release_gate_effect".to_owned(),
            advisor.release_gate_effect.clone(),
        );
        metadata.insert("artifact_root".to_owned(), advisor.artifact_root.clone());
        metadata.insert(
            "artifact_paths".to_owned(),
            advisor.artifact_paths.join(","),
        );
        self.insert_node(ReadinessLabTruthGraphNode {
            node_id: advisor_node_id.clone(),
            node_kind: "topology_runtime_advisor".to_owned(),
            label: advisor
                .recommendation
                .as_ref()
                .map_or_else(|| "topology-runtime-advisor".to_owned(), Clone::clone),
            source_path: Some(advisor.topology_advisor_report_path.clone()),
            bead_id: Some(advisor.source_bead.clone()),
            claim_state: Some(
                ReadinessLabTruthGraphClaimState::DryRunOnly
                    .label()
                    .to_owned(),
            ),
            host_class: Some(ReadinessLabHostClass::CandidateLargeHost.label().to_owned()),
            freshness_status: claim
                .freshness
                .as_ref()
                .map(|freshness| self.freshness_status(freshness)),
            product_evidence_claim: Some(advisor.product_evidence_claim.label().to_owned()),
            metadata,
        });
        self.edge(
            claim_node_id,
            &advisor_node_id,
            "derives_from",
            "claim derives from topology runtime advisor report",
            Some(advisor.topology_advisor_report_path.as_str()),
            Some(advisor.source_bead.as_str()),
        );
        let campaign_node_id = truth_node_id("bead", &[advisor.real_campaign_bead.as_str()]);
        self.insert_node(ReadinessLabTruthGraphNode {
            node_id: campaign_node_id.clone(),
            node_kind: "bead".to_owned(),
            label: advisor.real_campaign_bead.clone(),
            source_path: None,
            bead_id: Some(advisor.real_campaign_bead.clone()),
            claim_state: None,
            host_class: None,
            freshness_status: None,
            product_evidence_claim: None,
            metadata: BTreeMap::new(),
        });
        self.edge(
            &advisor_node_id,
            &campaign_node_id,
            "preflights",
            "topology advisor is advisory preflight for real campaign bead",
            Some(advisor.topology_advisor_report_path.as_str()),
            Some(advisor.real_campaign_bead.as_str()),
        );
    }

    fn build_permission_node(
        &mut self,
        claim: &ReadinessLabTruthGraphClaimInput,
        claim_node_id: &str,
    ) {
        let Some(permission) = &claim.permission else {
            return;
        };
        self.permission_requirement_count += 1;
        let permission_node_id = truth_node_id(
            "permission",
            &[claim_node_id, permission.permission_id.as_str()],
        );
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "boundary".to_owned(),
            permission.boundary.label().to_owned(),
        );
        metadata.insert("ack_env".to_owned(), permission.ack_env.clone());
        self.insert_node(ReadinessLabTruthGraphNode {
            node_id: permission_node_id.clone(),
            node_kind: "permission_requirement".to_owned(),
            label: permission.permission_id.clone(),
            source_path: None,
            bead_id: Some(permission.bead_id.clone()),
            claim_state: None,
            host_class: None,
            freshness_status: None,
            product_evidence_claim: None,
            metadata,
        });
        self.edge(
            claim_node_id,
            &permission_node_id,
            "requires_permission",
            "claim requires explicit operator permission",
            Some(claim.validator_report_path.as_str()),
            Some(permission.bead_id.as_str()),
        );
    }

    fn build_blocker_nodes(
        &mut self,
        claim: &ReadinessLabTruthGraphClaimInput,
        claim_node_id: &str,
    ) {
        for blocker in &claim.blockers {
            let blocker_node_id =
                truth_node_id("blocker", &[claim_node_id, blocker.blocker_id.as_str()]);
            self.insert_blocker_node(
                &blocker_node_id,
                blocker.reason.as_str(),
                blocker
                    .bead_id
                    .as_deref()
                    .unwrap_or(claim.source_bead.as_str()),
            );
            self.blocking_edge(
                &blocker_node_id,
                claim_node_id,
                blocker.reason.clone(),
                blocker.validator_report_path.as_deref(),
                blocker.bead_id.as_deref(),
            );
        }
    }

    fn link_explicit_supersedes(&mut self) {
        let explicit_supersedes = std::mem::take(&mut self.explicit_supersedes);
        for (from_node_id, claim_id, superseded_claim_id) in explicit_supersedes {
            let Some(observations) = self.claim_observations.get(&superseded_claim_id).cloned()
            else {
                self.error(
                    "missing_superseded_claim",
                    format!(
                        "claim {claim_id:?} supersedes unknown claim_id {superseded_claim_id:?}"
                    ),
                    FindingScope::lane(claim_id.as_str()).field("supersedes_claim_ids"),
                );
                continue;
            };
            for observation in observations {
                self.edge(
                    &from_node_id,
                    &observation.node_id,
                    "supersedes",
                    "claim explicitly supersedes older evidence",
                    Some(observation.validator_report_path.as_str()),
                    Some(observation.source_bead.as_str()),
                );
            }
        }
    }

    fn link_fresh_observations_over_stale(&mut self) {
        let observation_groups = self.claim_observations.clone();
        for observations in observation_groups.values() {
            let fresh = observations
                .iter()
                .filter(|observation| observation.freshness_status.as_deref() != Some("stale"))
                .collect::<Vec<_>>();
            let stale = observations
                .iter()
                .filter(|observation| observation.freshness_status.as_deref() == Some("stale"))
                .collect::<Vec<_>>();
            if fresh.is_empty() || stale.is_empty() {
                continue;
            }
            for fresh_observation in &fresh {
                for stale_observation in &stale {
                    self.edge(
                        &fresh_observation.node_id,
                        &stale_observation.node_id,
                        "supersedes",
                        "fresh evidence supersedes stale observation",
                        Some(fresh_observation.validator_report_path.as_str()),
                        Some(fresh_observation.source_bead.as_str()),
                    );
                }
            }
        }
    }

    fn detect_contradictions(&mut self) {
        let observation_groups = self.claim_observations.clone();
        for (claim_id, observations) in observation_groups {
            let states = observations
                .iter()
                .filter(|observation| observation.freshness_status.as_deref() != Some("stale"))
                .map(|observation| observation.effective_state.clone())
                .collect::<BTreeSet<_>>();
            if states.len() <= 1 {
                continue;
            }
            self.contradictory_claim_count += 1;
            let claim_node_ids = observations
                .iter()
                .map(|observation| observation.node_id.clone())
                .collect::<Vec<_>>();
            self.contradictions
                .push(ReadinessLabTruthGraphContradiction {
                    claim_id: claim_id.clone(),
                    observed_states: states.iter().cloned().collect(),
                    claim_node_ids: claim_node_ids.clone(),
                });
            self.error(
                "contradictory_claim_states",
                format!("claim {claim_id:?} has contradictory non-stale states"),
                FindingScope::lane(claim_id.as_str()),
            );
            let blocker_node_id = truth_node_id("blocker", &["contradiction", claim_id.as_str()]);
            self.insert_blocker_node(
                &blocker_node_id,
                "contradictory claim states",
                self.manifest.source_bead.as_str(),
            );
            for observation in observations {
                if observation.freshness_status.as_deref() == Some("stale") {
                    continue;
                }
                self.blocking_edge(
                    &blocker_node_id,
                    &observation.node_id,
                    "contradictory non-stale claim states",
                    Some(observation.validator_report_path.as_str()),
                    Some(observation.source_bead.as_str()),
                );
            }
        }
    }

    fn freshness_status(&self, freshness: &ReadinessLabFreshnessMetadata) -> String {
        let Some(reference_epoch_days) = self.config.reference_epoch_days else {
            return "unknown".to_owned();
        };
        if freshness.observed_at_epoch_days > reference_epoch_days {
            "future".to_owned()
        } else if freshness
            .observed_at_epoch_days
            .saturating_add(freshness.max_age_days)
            < reference_epoch_days
        {
            "stale".to_owned()
        } else {
            "fresh".to_owned()
        }
    }

    fn insert_node(&mut self, node: ReadinessLabTruthGraphNode) {
        self.nodes.entry(node.node_id.clone()).or_insert(node);
    }

    fn insert_blocker_node(&mut self, node_id: &str, label: impl Into<String>, bead_id: &str) {
        self.insert_node(ReadinessLabTruthGraphNode {
            node_id: node_id.to_owned(),
            node_kind: "blocker".to_owned(),
            label: label.into(),
            source_path: None,
            bead_id: Some(bead_id.to_owned()),
            claim_state: None,
            host_class: None,
            freshness_status: None,
            product_evidence_claim: None,
            metadata: BTreeMap::new(),
        });
    }

    fn blocking_edge(
        &mut self,
        from_node_id: &str,
        to_node_id: &str,
        label: impl Into<String>,
        validator_report_path: Option<&str>,
        bead_id: Option<&str>,
    ) {
        self.blocker_edge_count += 1;
        if blocker_link_missing(validator_report_path, bead_id) {
            self.error(
                "blocker_edge_without_report_or_bead",
                "blocker edge is missing both validator_report_path and bead_id",
                FindingScope::default(),
            );
        }
        self.edge(
            from_node_id,
            to_node_id,
            "blocks",
            label,
            validator_report_path,
            bead_id,
        );
    }

    fn edge(
        &mut self,
        from_node_id: &str,
        to_node_id: &str,
        edge_kind: &str,
        label: impl Into<String>,
        validator_report_path: Option<&str>,
        bead_id: Option<&str>,
    ) {
        self.edges.push(ReadinessLabTruthGraphEdge {
            from_node_id: from_node_id.to_owned(),
            to_node_id: to_node_id.to_owned(),
            edge_kind: edge_kind.to_owned(),
            label: label.into(),
            validator_report_path: validator_report_path.map(str::to_owned),
            bead_id: bead_id.map(str::to_owned),
        });
    }

    fn finish(self) -> ReadinessLabTruthGraphReport {
        let node_count = self.nodes.len();
        let edge_count = self.edges.len();
        ReadinessLabTruthGraphReport {
            schema_version: READINESS_LAB_TRUTH_GRAPH_REPORT_SCHEMA_VERSION,
            graph_id: self.manifest.graph_id.clone(),
            manifest_path: self.config.manifest_path.clone(),
            valid: self.errors.is_empty(),
            dry_run_only: true,
            product_evidence_claim: READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM.to_owned(),
            release_gate_effect: READINESS_LAB_ADVISORY_RELEASE_GATE_EFFECT.to_owned(),
            source_bead: self.manifest.source_bead.clone(),
            source_count: self.manifest.sources.len(),
            claim_count: self.claim_count,
            node_count,
            edge_count,
            stale_claim_count: self.stale_claim_count,
            contradictory_claim_count: self.contradictory_claim_count,
            missing_raw_log_count: self.missing_raw_log_count,
            permission_requirement_count: self.permission_requirement_count,
            simulated_node_count: self.simulated_node_count,
            blocker_edge_count: self.blocker_edge_count,
            nodes: self.nodes.into_values().collect(),
            edges: self.edges,
            contradictions: self.contradictions,
            errors: self.errors,
            warnings: self.warnings,
        }
    }

    fn error(
        &mut self,
        finding_id: impl Into<String>,
        message: impl Into<String>,
        scope: FindingScope,
    ) {
        self.errors.push(scope.into_finding(
            finding_id.into(),
            ReadinessLabFindingSeverity::Error,
            message.into(),
        ));
    }

    fn warning(
        &mut self,
        finding_id: impl Into<String>,
        message: impl Into<String>,
        scope: FindingScope,
    ) {
        self.warnings.push(scope.into_finding(
            finding_id.into(),
            ReadinessLabFindingSeverity::Warning,
            message.into(),
        ));
    }
}

struct ReadinessLabNumaP99ReplayValidator<'a> {
    manifest: &'a ReadinessLabNumaP99ReplayManifest,
    config: &'a ReadinessLabNumaP99ReplayConfig,
    errors: Vec<ReadinessLabFinding>,
    warnings: Vec<ReadinessLabFinding>,
    rows: Vec<ReadinessLabNumaP99ReplayRow>,
    shape_counts: BTreeMap<String, usize>,
    invalid_fixture_ids: BTreeSet<String>,
    missing_p99_bucket_count: usize,
    malformed_histogram_count: usize,
    impossible_cpu_count: usize,
    negative_duration_count: usize,
    stale_fixture_count: usize,
    future_fixture_count: usize,
}

impl<'a> ReadinessLabNumaP99ReplayValidator<'a> {
    fn new(
        manifest: &'a ReadinessLabNumaP99ReplayManifest,
        config: &'a ReadinessLabNumaP99ReplayConfig,
    ) -> Self {
        Self {
            manifest,
            config,
            errors: Vec::new(),
            warnings: Vec::new(),
            rows: Vec::new(),
            shape_counts: BTreeMap::new(),
            invalid_fixture_ids: BTreeSet::new(),
            missing_p99_bucket_count: 0,
            malformed_histogram_count: 0,
            impossible_cpu_count: 0,
            negative_duration_count: 0,
            stale_fixture_count: 0,
            future_fixture_count: 0,
        }
    }

    fn validate_manifest(&mut self) {
        self.check_manifest_identity();
        self.check_shape_coverage();
        if duplicate_count(
            self.manifest
                .fixtures
                .iter()
                .map(|fixture| fixture.fixture_id.as_str()),
        ) > 0
        {
            self.error(
                "duplicate_replay_fixture_ids",
                "fixture_id values must be unique",
                FindingScope::default().field("fixtures"),
            );
        }
        for fixture in &self.manifest.fixtures {
            self.validate_fixture(fixture);
        }
    }

    fn check_manifest_identity(&mut self) {
        if self.manifest.schema_version != READINESS_LAB_SCHEMA_VERSION {
            self.error(
                "unsupported_schema_version",
                format!(
                    "schema_version must be {READINESS_LAB_SCHEMA_VERSION}, got {}",
                    self.manifest.schema_version
                ),
                FindingScope::default().field("schema_version"),
            );
        }
        if self.manifest.replay_id.trim().is_empty() {
            self.error(
                "missing_replay_id",
                "replay_id must be non-empty",
                FindingScope::default().field("replay_id"),
            );
        }
        if self.manifest.generated_at_epoch_days == 0 {
            self.error(
                "missing_generated_at_epoch_days",
                "generated_at_epoch_days must be non-zero",
                FindingScope::default().field("generated_at_epoch_days"),
            );
        }
        if self.manifest.advisory_notice.trim() != READINESS_LAB_ADVISORY_NOTICE {
            self.error(
                "invalid_advisory_notice",
                format!("advisory_notice must be exactly {READINESS_LAB_ADVISORY_NOTICE:?}"),
                FindingScope::default().field("advisory_notice"),
            );
        }
        if !self.manifest.source_bead.starts_with("bd-") {
            self.error(
                "malformed_source_bead",
                "source_bead must look like bd-...",
                FindingScope::default().field("source_bead"),
            );
        }
        if !matches!(
            self.manifest.product_evidence_claim,
            ReadinessLabProductEvidenceClaim::None
        ) {
            self.error(
                "product_evidence_claim_violation",
                "NUMA/p99 replay manifests must keep product_evidence_claim=none",
                FindingScope::default().field("product_evidence_claim"),
            );
        }
        if self.manifest.fixtures.is_empty() {
            self.error(
                "empty_replay_fixture_matrix",
                "fixtures must include every required contention shape",
                FindingScope::default().field("fixtures"),
            );
        }
    }

    fn check_shape_coverage(&mut self) {
        for fixture in &self.manifest.fixtures {
            *self
                .shape_counts
                .entry(fixture.fixture_shape.label().to_owned())
                .or_default() += 1;
        }
        for shape in required_numa_p99_fixture_shapes() {
            if !self.shape_counts.contains_key(shape.label()) {
                self.error(
                    "missing_replay_fixture_shape",
                    format!("fixtures must include shape {}", shape.label()),
                    FindingScope::default().field("fixtures"),
                );
            }
        }
    }

    fn validate_fixture(&mut self, fixture: &ReadinessLabNumaP99ReplayFixture) {
        let before = self.errors.len();
        if fixture.fixture_id.trim().is_empty() {
            self.error(
                "missing_replay_fixture_id",
                "fixture_id must be non-empty",
                FindingScope::default().field("fixture_id"),
            );
        }
        if !fixture.source_bead.starts_with("bd-") {
            self.error(
                "malformed_fixture_source_bead",
                "fixture source_bead must look like bd-...",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("source_bead"),
            );
        }
        self.validate_freshness(fixture);
        self.validate_host(fixture);
        self.validate_workload(fixture);
        self.validate_queue_depth(fixture);
        self.validate_latency(fixture);
        if fixture.raw_log_path.trim().is_empty() {
            self.error(
                "missing_raw_log_path",
                "fixture raw_log_path must be non-empty",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("raw_log_path"),
            );
        }
        if fixture.reproduction_command.trim().is_empty() {
            self.error(
                "missing_reproduction_command",
                "fixture reproduction_command must be non-empty",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("reproduction_command"),
            );
        }
        let finding_count = self.errors.len().saturating_sub(before);
        if finding_count > 0 {
            self.invalid_fixture_ids.insert(fixture.fixture_id.clone());
        }
        self.rows
            .push(Self::row_for_fixture(fixture, finding_count));
    }

    fn validate_freshness(&mut self, fixture: &ReadinessLabNumaP99ReplayFixture) {
        if fixture.observed_at_epoch_days == 0 {
            self.error(
                "missing_observed_at_epoch_days",
                "fixture observed_at_epoch_days must be non-zero",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("observed_at_epoch_days"),
            );
        }
        if fixture.max_age_days == 0 {
            self.error(
                "zero_max_age_days",
                "fixture max_age_days must be greater than zero",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("max_age_days"),
            );
        }
        let Some(reference_epoch_days) = self.config.reference_epoch_days else {
            return;
        };
        if fixture.observed_at_epoch_days > reference_epoch_days {
            self.future_fixture_count += 1;
            self.error(
                "future_replay_fixture",
                "fixture observed_at_epoch_days is newer than the reference date",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("observed_at_epoch_days"),
            );
        }
        if fixture
            .observed_at_epoch_days
            .saturating_add(fixture.max_age_days)
            < reference_epoch_days
        {
            self.stale_fixture_count += 1;
            self.error(
                "stale_replay_fixture",
                "fixture is older than max_age_days",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("max_age_days"),
            );
        }
    }

    fn validate_host(&mut self, fixture: &ReadinessLabNumaP99ReplayFixture) {
        let host = &fixture.host;
        if host.logical_cpus == 0 || host.logical_cpus > 4096 {
            self.impossible_cpu_count += 1;
            self.error(
                "impossible_logical_cpu_count",
                "logical_cpus must be within 1..=4096 for replay fixtures",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("host.logical_cpus"),
            );
        }
        match host.numa_nodes {
            Some(nodes) if nodes > 0 && nodes <= host.logical_cpus => {}
            _ => {
                self.error(
                    "invalid_numa_nodes",
                    "numa_nodes must be present, positive, and no larger than logical_cpus",
                    FindingScope::artifact(fixture.fixture_id.as_str()).field("host.numa_nodes"),
                );
            }
        }
        if host.ram_total_gib <= 0.0 || host.ram_available_gib <= 0.0 {
            self.error(
                "invalid_ram_shape",
                "ram_total_gib and ram_available_gib must be positive",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("host"),
            );
        }
        if host.ram_available_gib > host.ram_total_gib {
            self.error(
                "available_ram_exceeds_total",
                "ram_available_gib must not exceed ram_total_gib",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("host.ram_available_gib"),
            );
        }
        if host.storage_class.trim().is_empty() {
            self.error(
                "missing_storage_class",
                "host.storage_class must be non-empty",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("host.storage_class"),
            );
        }
        if host.rch_worker_identity.trim().is_empty() {
            self.error(
                "missing_rch_worker_identity",
                "host.rch_worker_identity must be non-empty",
                FindingScope::artifact(fixture.fixture_id.as_str())
                    .field("host.rch_worker_identity"),
            );
        }
    }

    fn validate_workload(&mut self, fixture: &ReadinessLabNumaP99ReplayFixture) {
        let workload = &fixture.workload;
        if workload.operation_count == 0 {
            self.error(
                "zero_operation_count",
                "workload.operation_count must be positive",
                FindingScope::artifact(fixture.fixture_id.as_str())
                    .field("workload.operation_count"),
            );
        }
        if workload.duration_ms <= 0 {
            if workload.duration_ms < 0 {
                self.negative_duration_count += 1;
            }
            self.error(
                "non_positive_duration_ms",
                "workload.duration_ms must be positive",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("workload.duration_ms"),
            );
        }
        if workload.worker_count == 0 || workload.worker_count > fixture.host.logical_cpus {
            self.error(
                "invalid_worker_count",
                "workload.worker_count must be positive and no larger than logical_cpus",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("workload.worker_count"),
            );
        }
        if workload.hot_shard_count == 0 {
            self.error(
                "zero_hot_shard_count",
                "workload.hot_shard_count must be positive",
                FindingScope::artifact(fixture.fixture_id.as_str())
                    .field("workload.hot_shard_count"),
            );
        }
        if workload.memory_pressure_percent > 100 {
            self.error(
                "invalid_memory_pressure_percent",
                "memory_pressure_percent must be <= 100",
                FindingScope::artifact(fixture.fixture_id.as_str())
                    .field("workload.memory_pressure_percent"),
            );
        }
    }

    fn validate_queue_depth(&mut self, fixture: &ReadinessLabNumaP99ReplayFixture) {
        let queue = &fixture.queue_depth;
        if queue.average < 0.0 {
            self.error(
                "negative_queue_depth_average",
                "queue_depth.average must be non-negative",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("queue_depth.average"),
            );
        }
        match queue.p99 {
            Some(p99) if p99 >= 0.0 && p99 >= queue.average && p99 <= f64::from(queue.max) => {}
            Some(_) => self.error(
                "malformed_queue_depth_p99",
                "queue_depth.p99 must be non-negative, >= average, and <= max",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("queue_depth.p99"),
            ),
            None => {
                self.missing_p99_bucket_count += 1;
                self.error(
                    "missing_queue_depth_p99",
                    "queue_depth.p99 is required",
                    FindingScope::artifact(fixture.fixture_id.as_str()).field("queue_depth.p99"),
                );
            }
        }
    }

    fn validate_latency(&mut self, fixture: &ReadinessLabNumaP99ReplayFixture) {
        let latency = &fixture.latency;
        let p50 = self.require_positive_bucket(
            fixture.fixture_id.as_str(),
            "latency.p50_latency_us",
            latency.p50_latency_us,
        );
        let p95 = self.require_positive_bucket(
            fixture.fixture_id.as_str(),
            "latency.p95_latency_us",
            latency.p95_latency_us,
        );
        let p99 = self.require_p99_bucket(
            fixture.fixture_id.as_str(),
            "latency.p99_latency_us",
            latency.p99_latency_us,
        );
        if let (Some(p50), Some(p95), Some(p99)) = (p50, p95, p99)
            && (p50 > p95 || p95 > p99)
        {
            self.malformed_histogram_count += 1;
            self.error(
                "malformed_latency_histogram_order",
                "latency buckets must satisfy p50 <= p95 <= p99",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("latency"),
            );
        }
        if latency.attribution.is_empty() {
            self.malformed_histogram_count += 1;
            self.error(
                "empty_latency_attribution",
                "latency.attribution must include at least one component bucket",
                FindingScope::artifact(fixture.fixture_id.as_str()).field("latency.attribution"),
            );
        }

        let mut seen_components = BTreeSet::new();
        for bucket in &latency.attribution {
            let component = bucket.component.label();
            if !seen_components.insert(component) {
                self.malformed_histogram_count += 1;
                self.error(
                    "duplicate_latency_component",
                    format!("duplicate attribution component {component}"),
                    FindingScope::artifact(fixture.fixture_id.as_str())
                        .field("latency.attribution"),
                );
            }
            let p50 = self.require_non_negative_component_bucket(
                fixture.fixture_id.as_str(),
                component,
                "p50_us",
                bucket.p50_us,
            );
            let p95 = self.require_non_negative_component_bucket(
                fixture.fixture_id.as_str(),
                component,
                "p95_us",
                bucket.p95_us,
            );
            let p99 = self.require_p99_bucket(
                fixture.fixture_id.as_str(),
                &format!("latency.attribution.{component}.p99_us"),
                bucket.p99_us,
            );
            if let (Some(p50), Some(p95), Some(p99)) = (p50, p95, p99)
                && (p50 > p95 || p95 > p99)
            {
                self.malformed_histogram_count += 1;
                self.error(
                    "malformed_component_histogram_order",
                    format!("component {component} buckets must satisfy p50 <= p95 <= p99"),
                    FindingScope::artifact(fixture.fixture_id.as_str())
                        .field("latency.attribution"),
                );
            }
            if let (Some(component_p99), Some(row_p99)) = (bucket.p99_us, latency.p99_latency_us)
                && component_p99 > row_p99
            {
                self.malformed_histogram_count += 1;
                self.error(
                    "component_p99_exceeds_row_p99",
                    format!("component {component} p99_us exceeds row p99_latency_us"),
                    FindingScope::artifact(fixture.fixture_id.as_str())
                        .field("latency.attribution"),
                );
            }
            if bucket.detail.trim().is_empty() {
                self.error(
                    "missing_component_detail",
                    format!("component {component} must include detail"),
                    FindingScope::artifact(fixture.fixture_id.as_str())
                        .field("latency.attribution.detail"),
                );
            }
        }
    }

    fn require_positive_bucket(
        &mut self,
        fixture_id: &str,
        field: &str,
        value: Option<f64>,
    ) -> Option<f64> {
        match value {
            Some(value) if value.is_finite() && value > 0.0 => Some(value),
            Some(_) => {
                self.malformed_histogram_count += 1;
                self.error(
                    "malformed_latency_bucket",
                    format!("{field} must be finite and positive"),
                    FindingScope::artifact(fixture_id).field(field),
                );
                None
            }
            None => {
                self.malformed_histogram_count += 1;
                self.error(
                    "missing_latency_bucket",
                    format!("{field} is required"),
                    FindingScope::artifact(fixture_id).field(field),
                );
                None
            }
        }
    }

    fn require_non_negative_component_bucket(
        &mut self,
        fixture_id: &str,
        component: &str,
        field: &str,
        value: Option<f64>,
    ) -> Option<f64> {
        match value {
            Some(value) if value.is_finite() && value >= 0.0 => Some(value),
            Some(_) => {
                self.malformed_histogram_count += 1;
                self.error(
                    "malformed_component_bucket",
                    format!("component {component} {field} must be finite and non-negative"),
                    FindingScope::artifact(fixture_id).field("latency.attribution"),
                );
                None
            }
            None => {
                self.malformed_histogram_count += 1;
                self.error(
                    "missing_component_bucket",
                    format!("component {component} {field} is required"),
                    FindingScope::artifact(fixture_id).field("latency.attribution"),
                );
                None
            }
        }
    }

    fn require_p99_bucket(
        &mut self,
        fixture_id: &str,
        field: &str,
        value: Option<f64>,
    ) -> Option<f64> {
        match value {
            Some(value) if value.is_finite() && value > 0.0 => Some(value),
            Some(_) => {
                self.malformed_histogram_count += 1;
                self.error(
                    "malformed_p99_bucket",
                    format!("{field} must be finite and positive"),
                    FindingScope::artifact(fixture_id).field(field),
                );
                None
            }
            None => {
                self.missing_p99_bucket_count += 1;
                self.error(
                    "missing_p99_bucket",
                    format!("{field} is required"),
                    FindingScope::artifact(fixture_id).field(field),
                );
                None
            }
        }
    }

    fn row_for_fixture(
        fixture: &ReadinessLabNumaP99ReplayFixture,
        finding_count: usize,
    ) -> ReadinessLabNumaP99ReplayRow {
        let (dominant_component, dominant_component_p99_us) =
            dominant_numa_p99_component(&fixture.latency);
        ReadinessLabNumaP99ReplayRow {
            fixture_id: fixture.fixture_id.clone(),
            fixture_shape: fixture.fixture_shape.label().to_owned(),
            classification: if finding_count == 0 {
                "advisory_replay_fixture".to_owned()
            } else {
                "invalid_replay_fixture".to_owned()
            },
            product_evidence_claim: READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM.to_owned(),
            release_gate_effect: "replay fixture is advisory only; public readiness unchanged"
                .to_owned(),
            logical_cpus: fixture.host.logical_cpus,
            numa_nodes: fixture.host.numa_nodes,
            worker_count: fixture.workload.worker_count,
            hot_shard_count: fixture.workload.hot_shard_count,
            memory_pressure_percent: fixture.workload.memory_pressure_percent,
            duration_ms: fixture.workload.duration_ms,
            p50_latency_us: fixture.latency.p50_latency_us,
            p95_latency_us: fixture.latency.p95_latency_us,
            p99_latency_us: fixture.latency.p99_latency_us,
            component_p99_sum_us: component_p99_sum_us(&fixture.latency),
            dominant_component,
            dominant_component_p99_us,
            queue_depth_p99: fixture.queue_depth.p99,
            raw_log_path: fixture.raw_log_path.clone(),
            reproduction_command: fixture.reproduction_command.clone(),
            finding_count,
        }
    }

    fn finish(self) -> ReadinessLabNumaP99ReplayReport {
        let missing_shape_count = required_numa_p99_fixture_shapes()
            .iter()
            .filter(|shape| !self.shape_counts.contains_key(shape.label()))
            .count();
        ReadinessLabNumaP99ReplayReport {
            schema_version: READINESS_LAB_NUMA_P99_REPLAY_REPORT_SCHEMA_VERSION,
            replay_id: self.manifest.replay_id.clone(),
            manifest_path: self.config.manifest_path.clone(),
            valid: self.errors.is_empty(),
            replay_only: true,
            product_evidence_claim: READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM.to_owned(),
            release_gate_effect:
                "NUMA/p99 replay fixtures are simulation artifacts; public readiness unchanged until permissioned large-host evidence records raw workload logs, p99 attribution, proof-bundle lanes, and release-gate output"
                    .to_owned(),
            source_bead: self.manifest.source_bead.clone(),
            fixture_count: self.manifest.fixtures.len(),
            row_count: self.rows.len(),
            invalid_fixture_count: self.invalid_fixture_ids.len(),
            missing_shape_count,
            missing_p99_bucket_count: self.missing_p99_bucket_count,
            malformed_histogram_count: self.malformed_histogram_count,
            impossible_cpu_count: self.impossible_cpu_count,
            negative_duration_count: self.negative_duration_count,
            stale_fixture_count: self.stale_fixture_count,
            future_fixture_count: self.future_fixture_count,
            shape_counts: self.shape_counts,
            rows: self.rows,
            errors: self.errors,
            warnings: self.warnings,
        }
    }

    fn error(
        &mut self,
        finding_id: impl Into<String>,
        message: impl Into<String>,
        scope: FindingScope,
    ) {
        self.errors.push(scope.into_finding(
            finding_id.into(),
            ReadinessLabFindingSeverity::Error,
            message.into(),
        ));
    }
}

#[derive(Debug, Clone)]
struct TruthGraphClaimObservation {
    node_id: String,
    effective_state: String,
    freshness_status: Option<String>,
    validator_report_path: String,
    source_bead: String,
}

#[derive(Debug, Default)]
struct FindingScope {
    artifact_id: Option<String>,
    lane_id: Option<String>,
    assumption_id: Option<String>,
    field: Option<String>,
}

impl FindingScope {
    fn artifact(artifact_id: &str) -> Self {
        Self {
            artifact_id: Some(artifact_id.to_owned()),
            ..Self::default()
        }
    }

    fn lane(lane_id: &str) -> Self {
        Self {
            lane_id: Some(lane_id.to_owned()),
            ..Self::default()
        }
    }

    fn assumption(assumption_id: &str) -> Self {
        Self {
            assumption_id: Some(assumption_id.to_owned()),
            ..Self::default()
        }
    }

    fn field(mut self, field: &str) -> Self {
        self.field = Some(field.to_owned());
        self
    }

    fn into_finding(
        self,
        finding_id: String,
        severity: ReadinessLabFindingSeverity,
        message: String,
    ) -> ReadinessLabFinding {
        ReadinessLabFinding {
            finding_id,
            severity,
            message,
            artifact_id: self.artifact_id,
            lane_id: self.lane_id,
            assumption_id: self.assumption_id,
            field: self.field,
        }
    }
}

fn validate_host_simulation_manifest(
    manifest: &ReadinessLabHostSimulationManifest,
    errors: &mut Vec<ReadinessLabFinding>,
) {
    if manifest.schema_version != READINESS_LAB_SCHEMA_VERSION {
        push_readiness_lab_finding(
            errors,
            "unsupported_schema_version",
            format!(
                "schema_version must be {READINESS_LAB_SCHEMA_VERSION}, got {}",
                manifest.schema_version
            ),
            FindingScope::default().field("schema_version"),
        );
    }
    if manifest.simulation_id.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_simulation_id",
            "simulation_id must be non-empty",
            FindingScope::default().field("simulation_id"),
        );
    }
    if manifest.generated_at_epoch_days == 0 {
        push_readiness_lab_finding(
            errors,
            "missing_generated_at_epoch_days",
            "generated_at_epoch_days must be non-zero",
            FindingScope::default().field("generated_at_epoch_days"),
        );
    }
    if manifest.advisory_notice.trim() != READINESS_LAB_ADVISORY_NOTICE {
        push_readiness_lab_finding(
            errors,
            "invalid_advisory_notice",
            format!("advisory_notice must be exactly {READINESS_LAB_ADVISORY_NOTICE:?}"),
            FindingScope::default().field("advisory_notice"),
        );
    }
    if !manifest.source_bead.starts_with("bd-") {
        push_readiness_lab_finding(
            errors,
            "malformed_source_bead",
            "source_bead must look like bd-...",
            FindingScope::default().field("source_bead"),
        );
    }
    if !manifest.real_campaign_bead.starts_with("bd-") {
        push_readiness_lab_finding(
            errors,
            "malformed_real_campaign_bead",
            "real_campaign_bead must look like bd-...",
            FindingScope::default().field("real_campaign_bead"),
        );
    }
    if manifest.expected_artifact_root.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_expected_artifact_root",
            "expected_artifact_root must be non-empty",
            FindingScope::default().field("expected_artifact_root"),
        );
    }
    if manifest.release_gate_policy_path.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_release_gate_policy_path",
            "release_gate_policy_path must be non-empty",
            FindingScope::default().field("release_gate_policy_path"),
        );
    }
    if manifest.hosts.is_empty() {
        push_readiness_lab_finding(
            errors,
            "empty_host_matrix",
            "hosts must include at least one synthetic inventory row",
            FindingScope::default().field("hosts"),
        );
    }
    for host in &manifest.hosts {
        validate_synthetic_host_inventory(host, errors);
    }
}

fn validate_synthetic_host_inventory(
    host: &ReadinessLabSyntheticHostInventory,
    errors: &mut Vec<ReadinessLabFinding>,
) {
    let scope = || FindingScope::artifact(host.host_id.as_str());
    if host.host_id.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_host_id",
            "host_id must be non-empty",
            FindingScope::default().field("host_id"),
        );
    }
    if host.observed_at_epoch_days == 0 {
        push_readiness_lab_finding(
            errors,
            "missing_observed_at_epoch_days",
            "observed_at_epoch_days must be non-zero",
            scope().field("observed_at_epoch_days"),
        );
    }
    if host.max_age_days == 0 {
        push_readiness_lab_finding(
            errors,
            "zero_max_age_days",
            "max_age_days must be greater than zero",
            scope().field("max_age_days"),
        );
    }
    if host.storage_class.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_storage_class",
            "storage_class must be non-empty",
            scope().field("storage_class"),
        );
    }
    if host.rch_worker_identity.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_rch_worker_identity",
            "rch_worker_identity must be non-empty",
            scope().field("rch_worker_identity"),
        );
    }
    if host.worker_fingerprint.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_worker_fingerprint",
            "worker_fingerprint must be non-empty",
            scope().field("worker_fingerprint"),
        );
    }
    if host.target_dir.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_target_dir",
            "target_dir must be non-empty",
            scope().field("target_dir"),
        );
    }
    if host.artifact_root.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_artifact_root",
            "artifact_root must be non-empty",
            scope().field("artifact_root"),
        );
    }
    if host.max_threads == 0 {
        push_readiness_lab_finding(
            errors,
            "zero_max_threads",
            "max_threads must be greater than zero",
            scope().field("max_threads"),
        );
    }
    if host.max_memory_gib == 0 {
        push_readiness_lab_finding(
            errors,
            "zero_max_memory_gib",
            "max_memory_gib must be greater than zero",
            scope().field("max_memory_gib"),
        );
    }
    if host.max_temp_storage_gib == 0 {
        push_readiness_lab_finding(
            errors,
            "zero_max_temp_storage_gib",
            "max_temp_storage_gib must be greater than zero",
            scope().field("max_temp_storage_gib"),
        );
    }
    if host.max_queue_depth == 0 {
        push_readiness_lab_finding(
            errors,
            "zero_max_queue_depth",
            "max_queue_depth must be greater than zero",
            scope().field("max_queue_depth"),
        );
    }
}

fn simulate_readiness_lab_host(
    manifest: &ReadinessLabHostSimulationManifest,
    host: &ReadinessLabSyntheticHostInventory,
    config: &ReadinessLabHostSimulationConfig,
) -> ReadinessLabHostSimulationRow {
    let calibration_manifest = calibration_manifest_for_host(manifest, host);
    let calibration_report = validate_swarm_capability_calibration_manifest(
        &calibration_manifest,
        &SwarmCapabilityCalibrationValidationConfig {
            reference_epoch_days: config
                .reference_epoch_days
                .unwrap_or(manifest.generated_at_epoch_days),
        },
    );
    let mut blockers = calibration_report.blockers;
    let mut downgrade_reasons = calibration_report.downgrade_reasons;

    if !host.runner_configured {
        blockers.push("permissioned_runner_configured=false".to_owned());
    }
    if !host.swarm_ack_configured {
        blockers.push("swarm_real_run_ack_configured=false".to_owned());
    }
    if !host.storage_visible {
        downgrade_reasons.push("storage_visible=false".to_owned());
    }
    if let Some(reference_epoch_days) = config.reference_epoch_days {
        if host.observed_at_epoch_days > reference_epoch_days {
            blockers.push(format!(
                "future_inventory observed_at_epoch_days={} reference_epoch_days={reference_epoch_days}",
                host.observed_at_epoch_days
            ));
        }
        if host
            .observed_at_epoch_days
            .saturating_add(host.max_age_days)
            < reference_epoch_days
        {
            blockers.push(format!(
                "stale_inventory observed_at_epoch_days={} max_age_days={} reference_epoch_days={reference_epoch_days}",
                host.observed_at_epoch_days, host.max_age_days
            ));
        }
    }

    let mut classification = calibration_report.classification;
    if !calibration_report.valid || !blockers.is_empty() {
        "blocked".clone_into(&mut classification);
    } else if classification == "authoritative_large_host_candidate"
        && !downgrade_reasons.is_empty()
    {
        "capability_downgraded_smoke".clone_into(&mut classification);
    }
    let candidate_for_authorized_run =
        classification == "authoritative_large_host_candidate" && blockers.is_empty();
    let blocker_count = blockers.len();
    let downgrade_count = downgrade_reasons.len();

    ReadinessLabHostSimulationRow {
        host_id: host.host_id.clone(),
        valid: calibration_report.valid,
        classification,
        candidate_for_authorized_run,
        product_evidence_claim: READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM.to_owned(),
        release_gate_effect: calibration_report.release_gate_effect,
        logical_cpus: host.logical_cpus,
        ram_total_gib: host.ram_total_gib,
        numa_topology_visible: host.numa_topology_visible,
        numa_nodes: host.numa_nodes,
        storage_visible: host.storage_visible,
        fuse_available: host.fuse_available,
        runner_configured: host.runner_configured,
        swarm_ack_configured: host.swarm_ack_configured,
        worker_identity: host.rch_worker_identity.clone(),
        queue_isolation: host.queue_isolation.label().to_owned(),
        target_dir_isolated: host.target_dir_isolated,
        artifact_root: host.artifact_root.clone(),
        blocker_count,
        blockers,
        downgrade_count,
        downgrade_reasons,
    }
}

fn calibration_manifest_for_host(
    manifest: &ReadinessLabHostSimulationManifest,
    host: &ReadinessLabSyntheticHostInventory,
) -> SwarmCapabilityCalibrationManifest {
    SwarmCapabilityCalibrationManifest {
        schema_version: READINESS_LAB_SCHEMA_VERSION,
        packet_id: format!("{}-{}", manifest.simulation_id, host.host_id),
        generated_at: manifest.generated_at_epoch_days.to_string(),
        target_beads: vec![
            manifest.source_bead.clone(),
            manifest.real_campaign_bead.clone(),
        ],
        host: SwarmCapabilityCalibrationHost {
            logical_cpus: host.logical_cpus,
            ram_total_gib: f64::from(host.ram_total_gib),
            ram_available_gib: f64::from(host.ram_available_gib),
            numa_topology_visible: host.numa_topology_visible,
            numa_nodes: host.numa_nodes,
            storage_class: host.storage_class.clone(),
            fuse: SwarmCapabilityCalibrationFuse {
                state: if host.fuse_available {
                    SwarmCapabilityCalibrationFuseState::Available
                } else {
                    SwarmCapabilityCalibrationFuseState::Missing
                },
                detail: if host.fuse_available {
                    "synthetic readiness-lab inventory reports FUSE available".to_owned()
                } else {
                    "synthetic readiness-lab inventory reports FUSE missing".to_owned()
                },
            },
        },
        worker: SwarmCapabilityCalibrationWorker {
            rch_worker_identity: host.rch_worker_identity.clone(),
            worker_fingerprint: host.worker_fingerprint.clone(),
            worker_fingerprint_observed_at_epoch_days: host.observed_at_epoch_days,
            worker_fingerprint_max_age_days: host.max_age_days,
            queue_isolation: match host.queue_isolation {
                ReadinessLabSimulationQueueIsolation::Dedicated => {
                    SwarmCapabilityCalibrationIsolation::Dedicated
                }
                ReadinessLabSimulationQueueIsolation::Shared => {
                    SwarmCapabilityCalibrationIsolation::Shared
                }
                ReadinessLabSimulationQueueIsolation::Unknown => {
                    SwarmCapabilityCalibrationIsolation::Unknown
                }
            },
            target_dir_isolated: host.target_dir_isolated,
            target_dir: host.target_dir.clone(),
        },
        artifact_plan: SwarmCapabilityCalibrationArtifactPlan {
            expected_artifact_root: manifest.expected_artifact_root.clone(),
            observed_artifact_root: host.artifact_root.clone(),
        },
        resource_caps: SwarmCapabilityCalibrationResourceCaps {
            max_duration_secs: 1,
            max_threads: host.max_threads,
            max_memory_gib: f64::from(host.max_memory_gib),
            max_temp_storage_gib: f64::from(host.max_temp_storage_gib),
            max_queue_depth: host.max_queue_depth,
        },
        release_gate_policy_path: manifest.release_gate_policy_path.clone(),
        real_campaign_bead: manifest.real_campaign_bead.clone(),
        handoff_summary:
            "readiness-lab host simulation only; run the real campaign for product evidence"
                .to_owned(),
    }
}

fn push_readiness_lab_finding(
    findings: &mut Vec<ReadinessLabFinding>,
    finding_id: impl Into<String>,
    message: impl Into<String>,
    scope: FindingScope,
) {
    findings.push(scope.into_finding(
        finding_id.into(),
        ReadinessLabFindingSeverity::Error,
        message.into(),
    ));
}

fn lane_work_key(lane: &ReadinessLabRchValidationLane) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        lane.lane_kind.label(),
        lane.command.trim(),
        lane.target_dir.trim(),
        lane.artifact_path.trim()
    )
}

fn truth_node_id(prefix: &str, parts: &[&str]) -> String {
    let mut out = String::from(prefix);
    for part in parts {
        out.push(':');
        out.push_str(part.trim());
    }
    out
}

fn effective_claim_state(
    claim: &ReadinessLabTruthGraphClaimInput,
    freshness_status: Option<&str>,
) -> String {
    if freshness_status == Some("stale") {
        "stale".to_owned()
    } else {
        claim.claim_state.label().to_owned()
    }
}

fn blocker_link_missing(validator_report_path: Option<&str>, bead_id: Option<&str>) -> bool {
    let has_report = validator_report_path.is_some_and(|path| !path.trim().is_empty());
    let has_bead = bead_id.is_some_and(|id| id.starts_with("bd-"));
    !has_report && !has_bead
}

fn is_safe_readiness_lab_relative_path(value: &str) -> bool {
    if value.trim().is_empty() {
        return false;
    }
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn contains_forbidden_topology_claim_wording(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("accepted_large_host")
        || normalized.contains("product pass")
        || normalized.contains("product_pass")
        || normalized.contains("product-pass")
        || normalized.contains("product evidence pass")
}

fn required_numa_p99_fixture_shapes() -> [ReadinessLabNumaP99FixtureShape; 6] {
    [
        ReadinessLabNumaP99FixtureShape::BalancedNuma,
        ReadinessLabNumaP99FixtureShape::SkewedNuma,
        ReadinessLabNumaP99FixtureShape::MetadataReadHotShards,
        ReadinessLabNumaP99FixtureShape::RepairScrubInterference,
        ReadinessLabNumaP99FixtureShape::RchWorkerContention,
        ReadinessLabNumaP99FixtureShape::MemoryPressure,
    ]
}

fn component_p99_sum_us(latency: &ReadinessLabNumaP99LatencyHistogram) -> f64 {
    latency
        .attribution
        .iter()
        .filter_map(|bucket| bucket.p99_us)
        .sum()
}

fn dominant_numa_p99_component(latency: &ReadinessLabNumaP99LatencyHistogram) -> (String, f64) {
    latency
        .attribution
        .iter()
        .filter_map(|bucket| {
            bucket
                .p99_us
                .map(|p99| (bucket.component.label().to_owned(), p99))
        })
        .max_by(|left, right| left.1.total_cmp(&right.1))
        .unwrap_or_else(|| ("missing".to_owned(), 0.0))
}

fn format_optional_f64(value: Option<f64>) -> String {
    value.map_or_else(|| "missing".to_owned(), |value| format!("{value:.1}"))
}

fn duplicate_count<'a>(ids: impl Iterator<Item = &'a str>) -> usize {
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for id in ids {
        if id.trim().is_empty() {
            continue;
        }
        if !seen.insert(id) {
            duplicates.insert(id);
        }
    }
    duplicates.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bundle() -> ReadinessLabContractBundle {
        ReadinessLabContractBundle {
            schema_version: READINESS_LAB_SCHEMA_VERSION,
            lab_id: "readiness-lab-fixture".to_owned(),
            generated_at_epoch_days: 20_000,
            advisory_notice: READINESS_LAB_ADVISORY_NOTICE.to_owned(),
            artifacts: vec![
                ReadinessLabArtifactContract {
                    artifact_id: "host-sim".to_owned(),
                    artifact_kind: ReadinessLabArtifactKind::SimulatedHostCapability,
                    source_bead: "bd-4532j".to_owned(),
                    path: "artifacts/readiness-lab/host-sim.json".to_owned(),
                    product_evidence_claim: ReadinessLabProductEvidenceClaim::None,
                    freshness: sample_freshness(),
                    required_fields: vec![
                        "logical_cpus".to_owned(),
                        "ram_gib".to_owned(),
                        "numa_nodes".to_owned(),
                    ],
                },
                ReadinessLabArtifactContract {
                    artifact_id: "rch-plan".to_owned(),
                    artifact_kind: ReadinessLabArtifactKind::RchSchedulingPlan,
                    source_bead: "bd-hejjl".to_owned(),
                    path: "artifacts/readiness-lab/rch-plan.json".to_owned(),
                    product_evidence_claim: ReadinessLabProductEvidenceClaim::AdvisoryOnly,
                    freshness: sample_freshness(),
                    required_fields: vec![
                        "command".to_owned(),
                        "target_dir".to_owned(),
                        "env_allowlist".to_owned(),
                    ],
                },
            ],
            lane_plans: vec![ReadinessLabLanePlan {
                lane_id: "swarm-simulation".to_owned(),
                lane_kind: ReadinessLabLaneKind::LargeHostSwarmSimulation,
                expected_artifact_ids: vec!["host-sim".to_owned(), "rch-plan".to_owned()],
                next_safe_command:
                    "rch exec -- cargo run -p ffs-harness -- validate-readiness-lab-contracts"
                        .to_owned(),
                permission_boundary: ReadinessLabPermissionBoundary::NoPermissionNeeded,
            }],
            rch_assumptions: vec![ReadinessLabRchAssumption {
                assumption_id: "harness-unit-tests".to_owned(),
                command: "rch exec -- cargo test -p ffs-harness readiness_lab".to_owned(),
                target_dir: "/data/tmp/rch_target_frankenfs_readiness_lab".to_owned(),
                env_allowlist: vec!["CARGO_TARGET_DIR".to_owned()],
                executes_cargo: true,
                local_fallback_allowed: false,
            }],
        }
    }

    fn sample_freshness() -> ReadinessLabFreshnessMetadata {
        ReadinessLabFreshnessMetadata {
            observed_at_epoch_days: 20_000,
            max_age_days: 7,
            git_sha: "1234567".to_owned(),
            host_class: ReadinessLabHostClass::Synthetic,
        }
    }

    fn sample_host_simulation_manifest() -> ReadinessLabHostSimulationManifest {
        ReadinessLabHostSimulationManifest {
            schema_version: READINESS_LAB_SCHEMA_VERSION,
            simulation_id: "host-matrix".to_owned(),
            generated_at_epoch_days: 20_000,
            advisory_notice: READINESS_LAB_ADVISORY_NOTICE.to_owned(),
            source_bead: "bd-4532j".to_owned(),
            real_campaign_bead: "bd-rchk0.53.8".to_owned(),
            expected_artifact_root: "artifacts/swarm/large-host".to_owned(),
            release_gate_policy_path: "artifacts/swarm/release_gate_policy.json".to_owned(),
            hosts: vec![capable_host("candidate")],
        }
    }

    fn capable_host(host_id: &str) -> ReadinessLabSyntheticHostInventory {
        ReadinessLabSyntheticHostInventory {
            host_id: host_id.to_owned(),
            observed_at_epoch_days: 20_000,
            max_age_days: 7,
            logical_cpus: 64,
            ram_total_gib: 256,
            ram_available_gib: 220,
            numa_topology_visible: true,
            numa_nodes: Some(2),
            storage_class: "local-nvme".to_owned(),
            storage_visible: true,
            fuse_available: true,
            runner_configured: true,
            swarm_ack_configured: true,
            rch_worker_identity: "vmi-sim-64c-256gb".to_owned(),
            worker_fingerprint: "sim-abcdef1".to_owned(),
            queue_isolation: ReadinessLabSimulationQueueIsolation::Dedicated,
            target_dir_isolated: true,
            target_dir: "artifacts/swarm/target".to_owned(),
            artifact_root: "artifacts/swarm/large-host".to_owned(),
            max_threads: 64,
            max_memory_gib: 192,
            max_temp_storage_gib: 256,
            max_queue_depth: 32,
        }
    }

    fn validate(bundle: &ReadinessLabContractBundle) -> ReadinessLabValidationReport {
        validate_readiness_lab_contract_bundle(
            bundle,
            &ReadinessLabValidationConfig {
                manifest_path: "fixture.json".to_owned(),
                reference_epoch_days: Some(20_001),
            },
        )
    }

    fn simulate_hosts(
        manifest: &ReadinessLabHostSimulationManifest,
    ) -> ReadinessLabHostSimulationReport {
        simulate_readiness_lab_hosts(
            manifest,
            &ReadinessLabHostSimulationConfig {
                manifest_path: "hosts.json".to_owned(),
                reference_epoch_days: Some(20_001),
            },
        )
    }

    fn sample_rch_lane_schedule_manifest() -> ReadinessLabRchLaneScheduleManifest {
        let check_command = rch_lane_command(
            "/data/tmp/rch_target_frankenfs_readiness_lab_check",
            "cargo check -p ffs-harness --all-targets",
        );
        ReadinessLabRchLaneScheduleManifest {
            schema_version: READINESS_LAB_SCHEMA_VERSION,
            plan_id: "readiness-lab-rch-plan".to_owned(),
            generated_at_epoch_days: 20_000,
            advisory_notice: READINESS_LAB_ADVISORY_NOTICE.to_owned(),
            source_bead: "bd-hejjl".to_owned(),
            artifact_root: "artifacts/readiness-lab/rch-schedule".to_owned(),
            lanes: vec![
                ReadinessLabRchValidationLane {
                    lane_id: "check".to_owned(),
                    lane_kind: ReadinessLabRchValidationLaneKind::CargoCheck,
                    command: check_command.clone(),
                    dependencies: vec![],
                    target_dir: "/data/tmp/rch_target_frankenfs_readiness_lab_check".to_owned(),
                    artifact_path: "artifacts/readiness-lab/rch-schedule/check.json".to_owned(),
                    env_allowlist: vec!["CARGO_TARGET_DIR".to_owned()],
                    estimated_cost_units: 2,
                    required_evidence_ids: vec!["rch-worker-fresh".to_owned()],
                    worker_hint: Some("worker-a".to_owned()),
                    executes_cargo: true,
                    local_fallback_allowed: false,
                },
                ReadinessLabRchValidationLane {
                    lane_id: "test".to_owned(),
                    lane_kind: ReadinessLabRchValidationLaneKind::CargoTest,
                    command: rch_lane_command(
                        "/data/tmp/rch_target_frankenfs_readiness_lab_test",
                        "cargo test -p ffs-harness --lib readiness_lab",
                    ),
                    dependencies: vec!["check".to_owned()],
                    target_dir: "/data/tmp/rch_target_frankenfs_readiness_lab_test".to_owned(),
                    artifact_path: "artifacts/readiness-lab/rch-schedule/test.json".to_owned(),
                    env_allowlist: vec!["CARGO_TARGET_DIR".to_owned()],
                    estimated_cost_units: 4,
                    required_evidence_ids: vec!["rch-worker-fresh".to_owned()],
                    worker_hint: Some("worker-a".to_owned()),
                    executes_cargo: true,
                    local_fallback_allowed: false,
                },
                ReadinessLabRchValidationLane {
                    lane_id: "clippy".to_owned(),
                    lane_kind: ReadinessLabRchValidationLaneKind::CargoClippy,
                    command: rch_lane_command(
                        "/data/tmp/rch_target_frankenfs_readiness_lab_clippy",
                        "cargo clippy -p ffs-harness --all-targets -- -D warnings",
                    ),
                    dependencies: vec!["check".to_owned()],
                    target_dir: "/data/tmp/rch_target_frankenfs_readiness_lab_clippy".to_owned(),
                    artifact_path: "artifacts/readiness-lab/rch-schedule/clippy.json".to_owned(),
                    env_allowlist: vec!["CARGO_TARGET_DIR".to_owned()],
                    estimated_cost_units: 6,
                    required_evidence_ids: vec!["rch-worker-fresh".to_owned()],
                    worker_hint: Some("worker-a".to_owned()),
                    executes_cargo: true,
                    local_fallback_allowed: false,
                },
                ReadinessLabRchValidationLane {
                    lane_id: "dashboard".to_owned(),
                    lane_kind: ReadinessLabRchValidationLaneKind::ReadinessDashboard,
                    command: rch_lane_command(
                        "/data/tmp/rch_target_frankenfs_readiness_lab_dashboard",
                        "cargo run -p ffs-harness -- readiness-dashboard --format json",
                    ),
                    dependencies: vec!["test".to_owned(), "clippy".to_owned()],
                    target_dir: "/data/tmp/rch_target_frankenfs_readiness_lab_dashboard".to_owned(),
                    artifact_path: "artifacts/readiness-lab/rch-schedule/dashboard.json".to_owned(),
                    env_allowlist: vec!["CARGO_TARGET_DIR".to_owned()],
                    estimated_cost_units: 3,
                    required_evidence_ids: vec!["rch-worker-fresh".to_owned()],
                    worker_hint: Some("worker-a".to_owned()),
                    executes_cargo: true,
                    local_fallback_allowed: false,
                },
                ReadinessLabRchValidationLane {
                    lane_id: "check-duplicate".to_owned(),
                    lane_kind: ReadinessLabRchValidationLaneKind::CargoCheck,
                    command: check_command,
                    dependencies: vec![],
                    target_dir: "/data/tmp/rch_target_frankenfs_readiness_lab_check".to_owned(),
                    artifact_path: "artifacts/readiness-lab/rch-schedule/check.json".to_owned(),
                    env_allowlist: vec!["CARGO_TARGET_DIR".to_owned()],
                    estimated_cost_units: 2,
                    required_evidence_ids: vec!["rch-worker-fresh".to_owned()],
                    worker_hint: Some("worker-a".to_owned()),
                    executes_cargo: true,
                    local_fallback_allowed: false,
                },
            ],
            evidence: vec![ReadinessLabRchEvidence {
                evidence_id: "rch-worker-fresh".to_owned(),
                observed_at_epoch_days: 20_000,
                max_age_days: 7,
                worker_identity: "vmi-sim".to_owned(),
                rch_available: true,
                detail: Some("fresh RCH scheduler evidence fixture".to_owned()),
            }],
            worker_hints: vec![ReadinessLabRchWorkerHint {
                worker_id: "worker-a".to_owned(),
                logical_cpus: 32,
                ram_gib: 128,
                max_parallel_lanes: 4,
            }],
        }
    }

    fn rch_lane_command(target_dir: &str, cargo_command: &str) -> String {
        format!(
            "CARGO_TARGET_DIR={target_dir} RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR rch exec -- {cargo_command}"
        )
    }

    fn plan_rch_lanes(
        manifest: &ReadinessLabRchLaneScheduleManifest,
    ) -> ReadinessLabRchLaneScheduleReport {
        plan_readiness_lab_rch_lanes(
            manifest,
            &ReadinessLabRchLaneScheduleConfig {
                manifest_path: "rch-lanes.json".to_owned(),
                reference_epoch_days: Some(20_001),
            },
        )
    }

    fn sample_truth_graph_manifest() -> ReadinessLabTruthGraphManifest {
        ReadinessLabTruthGraphManifest {
            schema_version: READINESS_LAB_SCHEMA_VERSION,
            graph_id: "readiness-lab-truth-graph".to_owned(),
            generated_at_epoch_days: 20_000,
            advisory_notice: READINESS_LAB_ADVISORY_NOTICE.to_owned(),
            source_bead: "bd-xyypn".to_owned(),
            sources: vec![
                truth_graph_source(
                    "proof-old",
                    ReadinessLabTruthGraphSourceKind::ProofBundleReport,
                    "artifacts/proof/old-report.json",
                    truth_graph_claim(
                        "swarm.responsiveness",
                        ReadinessLabTruthGraphClaimState::Validated,
                        ReadinessLabProductEvidenceClaim::ProductPassFail,
                        "artifacts/proof/old-report.json",
                        "bd-rchk0.53.8",
                        19_990,
                    ),
                ),
                truth_graph_source(
                    "proof-fresh",
                    ReadinessLabTruthGraphSourceKind::ReleaseGateReport,
                    "artifacts/proof/fresh-release-gate.json",
                    truth_graph_claim(
                        "swarm.responsiveness",
                        ReadinessLabTruthGraphClaimState::Validated,
                        ReadinessLabProductEvidenceClaim::ProductPassFail,
                        "artifacts/proof/fresh-release-gate.json",
                        "bd-rchk0.53.8",
                        20_000,
                    ),
                ),
                truth_graph_source(
                    "host-sim",
                    ReadinessLabTruthGraphSourceKind::ReadinessLabReport,
                    "artifacts/readiness-lab/host-simulation.json",
                    simulated_truth_graph_claim(),
                ),
                truth_graph_source(
                    "xfstests-handoff",
                    ReadinessLabTruthGraphSourceKind::PermissionedCampaignPacket,
                    "artifacts/readiness-lab/xfstests-handoff.json",
                    permissioned_handoff_truth_graph_claim(),
                ),
            ],
        }
    }

    fn truth_graph_source(
        source_id: &str,
        source_kind: ReadinessLabTruthGraphSourceKind,
        path: &str,
        claim: ReadinessLabTruthGraphClaimInput,
    ) -> ReadinessLabTruthGraphSource {
        ReadinessLabTruthGraphSource {
            source_id: source_id.to_owned(),
            source_kind,
            path: path.to_owned(),
            valid: true,
            claims: vec![claim],
        }
    }

    fn truth_graph_claim(
        claim_id: &str,
        claim_state: ReadinessLabTruthGraphClaimState,
        product_evidence_claim: ReadinessLabProductEvidenceClaim,
        validator_report_path: &str,
        source_bead: &str,
        observed_at_epoch_days: u32,
    ) -> ReadinessLabTruthGraphClaimInput {
        ReadinessLabTruthGraphClaimInput {
            claim_id: claim_id.to_owned(),
            claim_state,
            product_evidence_claim,
            validator_report_path: validator_report_path.to_owned(),
            source_bead: source_bead.to_owned(),
            command: Some(format!(
                "cat {validator_report_path} && br show {source_bead} --no-db --json"
            )),
            artifacts: vec![ReadinessLabTruthGraphArtifactInput {
                artifact_id: format!("{claim_id}-raw-log"),
                artifact_kind: ReadinessLabArtifactKind::PlannedWorkloadLane,
                path: format!("artifacts/raw/{claim_id}.log"),
                sha256: Some("sha256:truth-graph-fixture".to_owned()),
                raw_log_required: true,
                raw_log_present: true,
            }],
            host: None,
            freshness: Some(ReadinessLabFreshnessMetadata {
                observed_at_epoch_days,
                max_age_days: 7,
                git_sha: "1234567".to_owned(),
                host_class: ReadinessLabHostClass::PermissionedLargeHost,
            }),
            blockers: Vec::new(),
            permission: None,
            supersedes_claim_ids: Vec::new(),
            topology_advisor: None,
        }
    }

    fn simulated_truth_graph_claim() -> ReadinessLabTruthGraphClaimInput {
        ReadinessLabTruthGraphClaimInput {
            claim_id: "swarm.capability.simulated".to_owned(),
            claim_state: ReadinessLabTruthGraphClaimState::Simulated,
            product_evidence_claim: ReadinessLabProductEvidenceClaim::None,
            validator_report_path: "artifacts/readiness-lab/host-simulation.json".to_owned(),
            source_bead: "bd-4532j".to_owned(),
            command: Some("ffs-harness simulate-readiness-lab-hosts --format json".to_owned()),
            artifacts: vec![ReadinessLabTruthGraphArtifactInput {
                artifact_id: "host-simulation".to_owned(),
                artifact_kind: ReadinessLabArtifactKind::SimulatedHostCapability,
                path: "artifacts/readiness-lab/host-simulation.json".to_owned(),
                sha256: None,
                raw_log_required: false,
                raw_log_present: false,
            }],
            host: Some(ReadinessLabTruthGraphHostInput {
                host_id: "candidate-sim".to_owned(),
                host_class: ReadinessLabHostClass::Synthetic,
                logical_cpus: Some(64),
                ram_total_gib: Some(256),
                numa_topology_visible: Some(true),
            }),
            freshness: Some(ReadinessLabFreshnessMetadata {
                observed_at_epoch_days: 20_000,
                max_age_days: 7,
                git_sha: "1234567".to_owned(),
                host_class: ReadinessLabHostClass::Synthetic,
            }),
            blockers: Vec::new(),
            permission: None,
            supersedes_claim_ids: Vec::new(),
            topology_advisor: None,
        }
    }

    fn permissioned_handoff_truth_graph_claim() -> ReadinessLabTruthGraphClaimInput {
        ReadinessLabTruthGraphClaimInput {
            claim_id: "xfstests.baseline".to_owned(),
            claim_state: ReadinessLabTruthGraphClaimState::HandoffOnly,
            product_evidence_claim: ReadinessLabProductEvidenceClaim::None,
            validator_report_path: "artifacts/readiness-lab/xfstests-handoff.json".to_owned(),
            source_bead: "bd-c7fqh".to_owned(),
            command: Some("br show bd-rchk3 --no-db --json".to_owned()),
            artifacts: vec![ReadinessLabTruthGraphArtifactInput {
                artifact_id: "xfstests-handoff-packet".to_owned(),
                artifact_kind: ReadinessLabArtifactKind::PermissionedRunRehearsal,
                path: "artifacts/readiness-lab/xfstests-handoff.json".to_owned(),
                sha256: None,
                raw_log_required: false,
                raw_log_present: false,
            }],
            host: None,
            freshness: Some(sample_freshness()),
            blockers: vec![ReadinessLabTruthGraphBlockerInput {
                blocker_id: "operator-ack-missing".to_owned(),
                reason: "real xfstests run requires explicit operator ack".to_owned(),
                validator_report_path: None,
                bead_id: Some("bd-rchk3".to_owned()),
            }],
            permission: Some(ReadinessLabTruthGraphPermissionRequirement {
                permission_id: "xfstests-real-run-ack".to_owned(),
                boundary: ReadinessLabPermissionBoundary::RequiresXfstestsAck,
                bead_id: "bd-rchk3".to_owned(),
                ack_env: "XFSTESTS_REAL_RUN_ACK".to_owned(),
            }),
            supersedes_claim_ids: Vec::new(),
            topology_advisor: None,
        }
    }

    fn topology_advisor_truth_graph_claim() -> ReadinessLabTruthGraphClaimInput {
        ReadinessLabTruthGraphClaimInput {
            claim_id: "swarm.responsiveness".to_owned(),
            claim_state: ReadinessLabTruthGraphClaimState::Blocked,
            product_evidence_claim: ReadinessLabProductEvidenceClaim::None,
            validator_report_path: "artifacts/topology-advisor/score.json".to_owned(),
            source_bead: "bd-rchk0.212".to_owned(),
            command: Some(
                "ffs-harness score-topology-runtime-advisor --manifest docs/topology-runtime-advisor-manifest.json".to_owned(),
            ),
            artifacts: vec![
                ReadinessLabTruthGraphArtifactInput {
                    artifact_id: "topology-advisor-score".to_owned(),
                    artifact_kind: ReadinessLabArtifactKind::RchSchedulingPlan,
                    path: "artifacts/topology-advisor/score.json".to_owned(),
                    sha256: Some("sha256:topology-score-fixture".to_owned()),
                    raw_log_required: true,
                    raw_log_present: true,
                },
                ReadinessLabTruthGraphArtifactInput {
                    artifact_id: "topology-advisor-structured-log".to_owned(),
                    artifact_kind: ReadinessLabArtifactKind::RchSchedulingPlan,
                    path: "artifacts/topology-advisor/structured.jsonl".to_owned(),
                    sha256: Some("sha256:topology-log-fixture".to_owned()),
                    raw_log_required: true,
                    raw_log_present: true,
                },
            ],
            host: Some(ReadinessLabTruthGraphHostInput {
                host_id: "candidate-large-host".to_owned(),
                host_class: ReadinessLabHostClass::CandidateLargeHost,
                logical_cpus: Some(96),
                ram_total_gib: Some(512),
                numa_topology_visible: Some(true),
            }),
            freshness: Some(ReadinessLabFreshnessMetadata {
                observed_at_epoch_days: 20_000,
                max_age_days: 7,
                git_sha: "1234567".to_owned(),
                host_class: ReadinessLabHostClass::CandidateLargeHost,
            }),
            blockers: vec![ReadinessLabTruthGraphBlockerInput {
                blocker_id: "permissioned-large-host-missing".to_owned(),
                reason:
                    "advisor is preflight only until real large-host swarm lanes execute".to_owned(),
                validator_report_path: Some("artifacts/topology-advisor/score.json".to_owned()),
                bead_id: Some("bd-rchk0.53.8".to_owned()),
            }],
            permission: None,
            supersedes_claim_ids: Vec::new(),
            topology_advisor: Some(ReadinessLabTruthGraphTopologyAdvisorInput {
                topology_advisor_report_path: "artifacts/topology-advisor/report.json".to_owned(),
                score_report_path: "artifacts/topology-advisor/score.json".to_owned(),
                structured_log_path: "artifacts/topology-advisor/structured.jsonl".to_owned(),
                source_bead: "bd-rchk0.212".to_owned(),
                real_campaign_bead: "bd-rchk0.53.8".to_owned(),
                manifest_hash: "sha256:topology-manifest-fixture".to_owned(),
                recommendation: Some("managed".to_owned()),
                rejected_candidates: vec!["per_core: awaiting permissioned large-host lane".to_owned()],
                blocked_claims: vec!["swarm.responsiveness".to_owned()],
                advisory_only: true,
                product_evidence_claim: ReadinessLabProductEvidenceClaim::None,
                release_gate_effect: READINESS_LAB_ADVISORY_RELEASE_GATE_EFFECT.to_owned(),
                artifact_root: "artifacts/topology-advisor".to_owned(),
                artifact_paths: vec![
                    "artifacts/topology-advisor/report.json".to_owned(),
                    "artifacts/topology-advisor/score.json".to_owned(),
                    "artifacts/topology-advisor/structured.jsonl".to_owned(),
                ],
            }),
        }
    }

    fn topology_advisor_truth_graph_manifest() -> ReadinessLabTruthGraphManifest {
        ReadinessLabTruthGraphManifest {
            schema_version: READINESS_LAB_SCHEMA_VERSION,
            graph_id: "topology-advisor-truth-graph".to_owned(),
            generated_at_epoch_days: 20_000,
            advisory_notice: READINESS_LAB_ADVISORY_NOTICE.to_owned(),
            source_bead: "bd-rchk0.212.4".to_owned(),
            sources: vec![truth_graph_source(
                "topology-advisor",
                ReadinessLabTruthGraphSourceKind::TopologyRuntimeAdvisorReport,
                "artifacts/topology-advisor/score.json",
                topology_advisor_truth_graph_claim(),
            )],
        }
    }

    fn build_truth_graph(
        manifest: &ReadinessLabTruthGraphManifest,
    ) -> ReadinessLabTruthGraphReport {
        build_readiness_lab_truth_graph(
            manifest,
            &ReadinessLabTruthGraphConfig {
                manifest_path: "truth-graph.json".to_owned(),
                reference_epoch_days: Some(20_001),
            },
        )
    }

    fn sample_numa_p99_replay_manifest() -> ReadinessLabNumaP99ReplayManifest {
        ReadinessLabNumaP99ReplayManifest {
            schema_version: READINESS_LAB_SCHEMA_VERSION,
            replay_id: "readiness-lab-numa-p99-fixtures".to_owned(),
            generated_at_epoch_days: 20_000,
            advisory_notice: READINESS_LAB_ADVISORY_NOTICE.to_owned(),
            source_bead: "bd-w6nuy".to_owned(),
            product_evidence_claim: ReadinessLabProductEvidenceClaim::None,
            fixtures: required_numa_p99_fixture_shapes()
                .into_iter()
                .map(replay_fixture)
                .collect(),
        }
    }

    fn replay_fixture(shape: ReadinessLabNumaP99FixtureShape) -> ReadinessLabNumaP99ReplayFixture {
        let (suffix, dominant, p99, workers, hot_shards, repair, memory_pressure) = match shape {
            ReadinessLabNumaP99FixtureShape::BalancedNuma => (
                "balanced",
                ReadinessLabNumaP99Component::Service,
                9_000.0,
                64,
                16,
                false,
                45,
            ),
            ReadinessLabNumaP99FixtureShape::SkewedNuma => (
                "skewed",
                ReadinessLabNumaP99Component::NumaRemoteAccess,
                15_000.0,
                64,
                8,
                false,
                50,
            ),
            ReadinessLabNumaP99FixtureShape::MetadataReadHotShards => (
                "metadata-hot",
                ReadinessLabNumaP99Component::Synchronization,
                18_000.0,
                72,
                2,
                false,
                55,
            ),
            ReadinessLabNumaP99FixtureShape::RepairScrubInterference => (
                "repair-scrub",
                ReadinessLabNumaP99Component::RepairBacklog,
                21_000.0,
                64,
                12,
                true,
                60,
            ),
            ReadinessLabNumaP99FixtureShape::RchWorkerContention => (
                "rch-contention",
                ReadinessLabNumaP99Component::RchWorkerContention,
                24_000.0,
                48,
                12,
                false,
                62,
            ),
            ReadinessLabNumaP99FixtureShape::MemoryPressure => (
                "memory-pressure",
                ReadinessLabNumaP99Component::MemoryReclaim,
                27_000.0,
                56,
                10,
                true,
                88,
            ),
        };
        ReadinessLabNumaP99ReplayFixture {
            fixture_id: format!("fixture-{suffix}"),
            fixture_shape: shape,
            source_bead: "bd-w6nuy".to_owned(),
            observed_at_epoch_days: 20_000,
            max_age_days: 7,
            host: ReadinessLabNumaP99HostShape {
                logical_cpus: 96,
                numa_nodes: Some(4),
                ram_total_gib: 384.0,
                ram_available_gib: 300.0,
                storage_class: "local-nvme".to_owned(),
                rch_worker_identity: "synthetic-rch-large-host".to_owned(),
                queue_isolation: ReadinessLabSimulationQueueIsolation::Dedicated,
            },
            workload: ReadinessLabNumaP99WorkloadShape {
                operation_count: 250_000,
                duration_ms: 90_000,
                worker_count: workers,
                hot_shard_count: hot_shards,
                repair_scrub_active: repair,
                memory_pressure_percent: memory_pressure,
            },
            latency: ReadinessLabNumaP99LatencyHistogram {
                p50_latency_us: Some(p99 / 4.0),
                p95_latency_us: Some(p99 / 2.0),
                p99_latency_us: Some(p99),
                attribution: replay_components(dominant, p99),
            },
            queue_depth: ReadinessLabNumaP99QueueDepth {
                average: 8.0,
                p99: Some(28.0),
                max: 64,
            },
            raw_log_path: format!("artifacts/readiness-lab/numa-p99/{suffix}.log"),
            reproduction_command: format!(
                "cargo run -p ffs-harness -- validate-readiness-lab-numa-p99-replay --select {suffix}"
            ),
        }
    }

    fn replay_components(
        dominant: ReadinessLabNumaP99Component,
        row_p99: f64,
    ) -> Vec<ReadinessLabNumaP99AttributionBucket> {
        [
            ReadinessLabNumaP99Component::Queueing,
            ReadinessLabNumaP99Component::Service,
            ReadinessLabNumaP99Component::Io,
            ReadinessLabNumaP99Component::Synchronization,
            ReadinessLabNumaP99Component::Allocator,
            ReadinessLabNumaP99Component::RepairBacklog,
            ReadinessLabNumaP99Component::CachePressure,
            ReadinessLabNumaP99Component::RchWorkerContention,
            ReadinessLabNumaP99Component::NumaRemoteAccess,
            ReadinessLabNumaP99Component::MemoryReclaim,
        ]
        .into_iter()
        .map(|component| {
            let p99 = if component == dominant {
                row_p99 * 0.32
            } else {
                row_p99 * 0.06
            };
            ReadinessLabNumaP99AttributionBucket {
                component,
                p50_us: Some(p99 / 4.0),
                p95_us: Some(p99 / 2.0),
                p99_us: Some(p99),
                detail: format!("synthetic {} attribution", component.label()),
            }
        })
        .collect()
    }

    fn validate_numa_p99_replay(
        manifest: &ReadinessLabNumaP99ReplayManifest,
    ) -> ReadinessLabNumaP99ReplayReport {
        validate_readiness_lab_numa_p99_replay(
            manifest,
            &ReadinessLabNumaP99ReplayConfig {
                manifest_path: "numa-p99-replay.json".to_owned(),
                reference_epoch_days: Some(20_001),
            },
        )
    }

    #[test]
    fn valid_contract_bundle_passes_and_renders_markdown() {
        let report = validate(&sample_bundle());

        assert!(report.valid);
        assert_eq!(report.artifact_count, 2);
        assert_eq!(report.advisory_artifact_count, 2);
        assert_eq!(report.product_claim_violation_count, 0);
        let markdown = render_readiness_lab_contract_markdown(&report);
        assert!(markdown.contains("FrankenFS Readiness Lab Contract Report"));
        assert!(markdown.contains("Product-claim violations: `0`"));
    }

    /// bd-rchk0.53.22 - exact-output snapshot for the readiness-lab
    /// contract markdown consumed by operator handoffs.
    ///
    /// The validation tests prove the contract semantics. This snapshot pins
    /// the rendered lab identity, manifest path, aggregate counters,
    /// advisory/product-claim wording, and empty findings sections.
    #[test]
    fn render_readiness_lab_contract_markdown_sample_snapshot() {
        let report = validate(&sample_bundle());
        let markdown = render_readiness_lab_contract_markdown(&report);

        insta::assert_snapshot!("render_readiness_lab_contract_markdown_sample", markdown);
    }

    #[test]
    fn readiness_lab_validation_report_json_shape() -> serde_json::Result<()> {
        let report = validate(&sample_bundle());
        assert!(report.valid);

        let full_json = serde_json::to_string_pretty(&report)?;
        let decoded: ReadinessLabValidationReport = serde_json::from_str(&full_json)?;

        assert_eq!(decoded, report);
        assert_eq!(decoded.artifact_count, 2);
        assert_eq!(decoded.lane_count, 1);
        assert_eq!(decoded.rch_assumption_count, 1);
        assert_eq!(decoded.product_claim_violation_count, 0);

        let shape = serde_json::json!({
            "schema_version": report.schema_version,
            "lab_id": report.lab_id,
            "manifest_path": report.manifest_path,
            "valid": report.valid,
            "artifact_count": report.artifact_count,
            "lane_count": report.lane_count,
            "rch_assumption_count": report.rch_assumption_count,
            "advisory_artifact_count": report.advisory_artifact_count,
            "stale_artifact_count": report.stale_artifact_count,
            "future_artifact_count": report.future_artifact_count,
            "product_claim_violation_count": report.product_claim_violation_count,
            "missing_required_field_count": report.missing_required_field_count,
            "duplicate_id_count": report.duplicate_id_count,
            "errors": report.errors,
            "warnings": report.warnings,
        });
        insta::assert_snapshot!(
            "readiness_lab_validation_report_json_shape",
            serde_json::to_string_pretty(&shape)?
        );
        Ok(())
    }

    #[test]
    fn serialization_roundtrip_preserves_bundle() -> serde_json::Result<()> {
        let bundle = sample_bundle();
        let encoded = serde_json::to_string_pretty(&bundle)?;
        let decoded = serde_json::from_str::<ReadinessLabContractBundle>(&encoded)?;

        assert_eq!(decoded, bundle);
        Ok(())
    }

    #[test]
    fn product_pass_fail_claim_is_rejected() {
        let mut bundle = sample_bundle();
        bundle.artifacts[0].product_evidence_claim =
            ReadinessLabProductEvidenceClaim::ProductPassFail;

        let report = validate(&bundle);

        assert!(!report.valid);
        assert_eq!(report.product_claim_violation_count, 1);
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "product_evidence_claim_violation")
        );
    }

    #[test]
    fn future_and_stale_artifact_timestamps_fail_closed() {
        let mut bundle = sample_bundle();
        bundle.artifacts[0].freshness.observed_at_epoch_days = 20_010;
        bundle.artifacts[1].freshness.observed_at_epoch_days = 19_900;

        let report = validate(&bundle);

        assert!(!report.valid);
        assert_eq!(report.future_artifact_count, 1);
        assert_eq!(report.stale_artifact_count, 1);
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "future_artifact_timestamp")
        );
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "stale_artifact")
        );
    }

    #[test]
    fn serde_rejects_unknown_manifest_fields() {
        let raw = r#"{
            "schema_version": 1,
            "lab_id": "fixture",
            "generated_at_epoch_days": 20000,
            "advisory_notice": "advisory readiness-lab material only; not product evidence",
            "artifacts": [],
            "lane_plans": [],
            "rch_assumptions": [],
            "unexpected": true
        }"#;

        let err = serde_json::from_str::<ReadinessLabContractBundle>(raw)
            .expect_err("unknown fields must fail closed");

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn duplicate_ids_missing_refs_and_required_fields_are_rejected() {
        let mut bundle = sample_bundle();
        bundle.artifacts[1].artifact_id = "host-sim".to_owned();
        bundle.artifacts[0].required_fields.clear();
        bundle.lane_plans[0]
            .expected_artifact_ids
            .push("missing-artifact".to_owned());

        let report = validate(&bundle);

        assert!(!report.valid);
        assert_eq!(report.duplicate_id_count, 1);
        assert_eq!(report.missing_required_field_count, 1);
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "missing_expected_artifact")
        );
    }

    #[test]
    fn rch_assumptions_reject_local_fallback_and_bare_cargo() {
        let mut bundle = sample_bundle();
        bundle.rch_assumptions[0].command = "cargo test -p ffs-harness readiness_lab".to_owned();
        bundle.rch_assumptions[0].env_allowlist.clear();
        bundle.rch_assumptions[0].local_fallback_allowed = true;

        let report = validate(&bundle);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "local_fallback_allowed")
        );
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "cargo_without_rch_exec")
        );
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "missing_cargo_target_dir_allowlist")
        );
    }

    #[test]
    fn host_simulator_accepts_borderline_large_host_as_advisory_candidate() {
        let report = simulate_hosts(&sample_host_simulation_manifest());

        assert!(report.valid);
        assert_eq!(
            report.product_evidence_claim,
            READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM
        );
        assert_eq!(report.candidate_count, 1);
        assert_eq!(
            report.rows[0].classification,
            "authoritative_large_host_candidate"
        );
        assert!(report.rows[0].candidate_for_authorized_run);
        assert!(
            report
                .release_gate_effect
                .contains("swarm.responsiveness remains hidden")
        );
    }

    /// bd-rchk0.53.23 - exact-output snapshot for the readiness-lab
    /// host-simulation markdown consumed by operator handoffs.
    ///
    /// The simulator tests prove classification behavior. This snapshot pins
    /// the rendered advisory/product-evidence wording, release-gate effect,
    /// host counters, classification table, and empty findings sections.
    #[test]
    fn render_readiness_lab_host_simulation_markdown_sample_snapshot() {
        let report = simulate_hosts(&sample_host_simulation_manifest());
        let markdown = render_readiness_lab_host_simulation_markdown(&report);

        insta::assert_snapshot!(
            "render_readiness_lab_host_simulation_markdown_sample",
            markdown
        );
    }

    #[test]
    fn readiness_lab_host_simulation_report_json_shape() -> serde_json::Result<()> {
        let report = simulate_hosts(&sample_host_simulation_manifest());
        assert!(report.valid);

        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("readiness_lab_host_simulation_report_json_shape", json);
        let decoded: ReadinessLabHostSimulationReport = serde_json::from_str(&json)?;

        assert_eq!(decoded, report);
        assert_eq!(
            decoded.product_evidence_claim,
            READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM
        );
        assert!(
            decoded
                .release_gate_effect
                .contains("swarm.responsiveness remains hidden"),
            "{}",
            decoded.release_gate_effect
        );
        Ok(())
    }

    #[test]
    fn host_simulator_classifies_small_cpu_or_ram_as_smoke_only() {
        let mut manifest = sample_host_simulation_manifest();
        manifest.hosts[0].logical_cpus = 16;
        manifest.hosts[0].ram_total_gib = 128;
        manifest.hosts[0].max_threads = 16;
        manifest.hosts[0].max_memory_gib = 96;

        let report = simulate_hosts(&manifest);

        assert!(report.valid);
        assert_eq!(report.small_host_count, 1);
        assert_eq!(report.rows[0].classification, "small_host_smoke");
        assert!(!report.rows[0].candidate_for_authorized_run);
    }

    #[test]
    fn host_simulator_downgrades_missing_numa_storage_or_fuse() {
        let mut manifest = sample_host_simulation_manifest();
        manifest.hosts[0].numa_topology_visible = false;
        manifest.hosts[0].numa_nodes = None;
        manifest.hosts[0].storage_visible = false;
        manifest.hosts[0].fuse_available = false;

        let report = simulate_hosts(&manifest);

        assert!(report.valid);
        assert_eq!(report.capability_downgrade_count, 1);
        assert_eq!(report.rows[0].classification, "capability_downgraded_smoke");
        assert!(
            report.rows[0]
                .downgrade_reasons
                .iter()
                .any(|reason| reason == "storage_visible=false")
        );
    }

    #[test]
    fn host_simulator_blocks_missing_runner_or_ack() {
        let mut manifest = sample_host_simulation_manifest();
        manifest.hosts[0].runner_configured = false;
        manifest.hosts[0].swarm_ack_configured = false;

        let report = simulate_hosts(&manifest);

        assert!(report.valid);
        assert_eq!(report.blocked_count, 1);
        assert_eq!(report.rows[0].classification, "blocked");
        assert!(
            report.rows[0]
                .blockers
                .iter()
                .any(|blocker| blocker == "permissioned_runner_configured=false")
        );
        assert!(
            report.rows[0]
                .blockers
                .iter()
                .any(|blocker| blocker == "swarm_real_run_ack_configured=false")
        );
    }

    #[test]
    fn host_simulator_blocks_stale_future_and_mismatched_artifact_roots() {
        let mut manifest = sample_host_simulation_manifest();
        manifest.hosts = vec![
            capable_host("stale"),
            capable_host("future"),
            capable_host("root"),
        ];
        manifest.hosts[0].observed_at_epoch_days = 19_900;
        manifest.hosts[1].observed_at_epoch_days = 20_010;
        manifest.hosts[2].artifact_root = "artifacts/swarm/wrong-root".to_owned();

        let report = simulate_hosts(&manifest);

        assert!(report.valid);
        assert_eq!(report.blocked_count, 3);
        assert_eq!(report.stale_inventory_count, 1);
        assert_eq!(report.future_inventory_count, 1);
        assert!(
            report.rows[2]
                .blockers
                .iter()
                .any(|blocker| blocker.contains("artifact_root_mismatch"))
        );
    }

    #[test]
    fn host_simulator_rejects_unknown_manifest_fields() {
        let raw = r#"{
            "schema_version": 1,
            "simulation_id": "host-matrix",
            "generated_at_epoch_days": 20000,
            "advisory_notice": "advisory readiness-lab material only; not product evidence",
            "source_bead": "bd-4532j",
            "real_campaign_bead": "bd-rchk0.53.8",
            "expected_artifact_root": "artifacts/swarm/large-host",
            "release_gate_policy_path": "artifacts/swarm/release_gate_policy.json",
            "hosts": [],
            "unexpected": true
        }"#;

        let err = serde_json::from_str::<ReadinessLabHostSimulationManifest>(raw)
            .expect_err("unknown fields must fail closed");

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn rch_lane_scheduler_orders_dependencies_and_coalesces_duplicates() {
        let report = plan_rch_lanes(&sample_rch_lane_schedule_manifest());

        assert!(report.valid);
        assert_eq!(report.lane_count, 5);
        assert_eq!(report.planned_lane_count, 4);
        assert_eq!(report.coalesced_duplicate_count, 1);
        assert_eq!(report.product_evidence_claim, "none");
        assert!(report.dry_run_only);
        assert_eq!(report.rows[0].lane_id, "check");
        assert_eq!(report.rows[0].coalesced_from, vec!["check-duplicate"]);
        let dashboard = report
            .rows
            .iter()
            .find(|row| row.lane_id == "dashboard")
            .expect("dashboard lane must be scheduled");
        assert_eq!(
            dashboard.dependencies,
            vec!["clippy".to_owned(), "test".to_owned()]
        );
        assert!(dashboard.ordinal > report.rows[1].ordinal);
        assert!(
            render_readiness_lab_rch_lane_schedule_markdown(&report)
                .contains("FrankenFS Readiness Lab RCH Lane Schedule")
        );
    }

    /// bd-rchk0.53.21 - exact-output snapshot for the dry-run RCH
    /// schedule markdown consumed by readiness-lab operator handoffs.
    ///
    /// The scheduler tests prove ordering and validation semantics. This
    /// snapshot pins the rendered advisory/product-evidence wording, lane
    /// ordering, coalesced duplicate count, target dirs, artifact paths, and
    /// empty findings sections.
    #[test]
    fn render_readiness_lab_rch_lane_schedule_markdown_sample_snapshot() {
        let report = plan_rch_lanes(&sample_rch_lane_schedule_manifest());
        let markdown = render_readiness_lab_rch_lane_schedule_markdown(&report);

        insta::assert_snapshot!(
            "render_readiness_lab_rch_lane_schedule_markdown_sample",
            markdown
        );
    }

    #[test]
    fn readiness_lab_rch_lane_schedule_report_json_shape() -> serde_json::Result<()> {
        let report = plan_rch_lanes(&sample_rch_lane_schedule_manifest());
        assert!(report.valid);

        let full_json = serde_json::to_string_pretty(&report)?;
        let decoded: ReadinessLabRchLaneScheduleReport = serde_json::from_str(&full_json)?;

        assert_eq!(decoded, report);
        assert_eq!(decoded.lane_count, 5);
        assert_eq!(decoded.planned_lane_count, 4);
        assert_eq!(decoded.coalesced_duplicate_count, 1);
        assert_eq!(decoded.target_dir_conflict_count, 0);
        assert_eq!(decoded.missing_evidence_count, 0);
        assert_eq!(decoded.local_fallback_violation_count, 0);
        assert!(decoded.dry_run_only);
        assert_eq!(decoded.product_evidence_claim, "none");

        let rows = report
            .rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "ordinal": row.ordinal,
                    "lane_id": row.lane_id,
                    "lane_kind": row.lane_kind,
                    "target_dir": row.target_dir,
                    "artifact_path": row.artifact_path,
                    "dependency_count": row.dependencies.len(),
                    "required_evidence_count": row.required_evidence_ids.len(),
                    "env_allowlist": row.env_allowlist,
                    "estimated_cost_units": row.estimated_cost_units,
                    "worker_hint": row.worker_hint,
                    "coalesced_from": row.coalesced_from,
                })
            })
            .collect::<Vec<_>>();
        let shape = serde_json::json!({
            "schema_version": report.schema_version,
            "plan_id": report.plan_id,
            "manifest_path": report.manifest_path,
            "valid": report.valid,
            "dry_run_only": report.dry_run_only,
            "product_evidence_claim": report.product_evidence_claim,
            "release_gate_effect": report.release_gate_effect,
            "source_bead": report.source_bead,
            "artifact_root": report.artifact_root,
            "lane_count": report.lane_count,
            "planned_lane_count": report.planned_lane_count,
            "coalesced_duplicate_count": report.coalesced_duplicate_count,
            "target_dir_conflict_count": report.target_dir_conflict_count,
            "missing_evidence_count": report.missing_evidence_count,
            "local_fallback_violation_count": report.local_fallback_violation_count,
            "rows": rows,
            "errors": report.errors,
            "warnings": report.warnings,
        });
        insta::assert_snapshot!(
            "readiness_lab_rch_lane_schedule_report_json_shape",
            serde_json::to_string_pretty(&shape)?
        );
        Ok(())
    }

    #[test]
    fn rch_lane_scheduler_rejects_shared_target_dir_and_missing_evidence() {
        let mut manifest = sample_rch_lane_schedule_manifest();
        manifest.lanes[1].target_dir = manifest.lanes[0].target_dir.clone();
        manifest.lanes[1].command = rch_lane_command(
            manifest.lanes[1].target_dir.as_str(),
            "cargo test -p ffs-harness --lib readiness_lab",
        );
        manifest.lanes[2]
            .required_evidence_ids
            .push("missing-rch-evidence".to_owned());

        let report = plan_rch_lanes(&manifest);

        assert!(!report.valid);
        assert_eq!(report.target_dir_conflict_count, 1);
        assert_eq!(report.missing_evidence_count, 1);
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "target_dir_conflict")
        );
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "missing_rch_evidence")
        );
    }

    #[test]
    fn rch_lane_scheduler_rejects_local_fallback_and_bare_cargo() {
        let mut manifest = sample_rch_lane_schedule_manifest();
        manifest.lanes[0].command = "cargo check -p ffs-harness --all-targets".to_owned();
        manifest.lanes[0].env_allowlist.clear();
        manifest.lanes[0].local_fallback_allowed = true;

        let report = plan_rch_lanes(&manifest);

        assert!(!report.valid);
        assert_eq!(report.local_fallback_violation_count, 1);
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "local_fallback_allowed")
        );
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "cargo_without_rch_exec")
        );
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "missing_cargo_target_dir_allowlist")
        );
    }

    #[test]
    fn rch_lane_scheduler_rejects_unknown_manifest_fields() {
        let raw = r#"{
            "schema_version": 1,
            "plan_id": "rch-plan",
            "generated_at_epoch_days": 20000,
            "advisory_notice": "advisory readiness-lab material only; not product evidence",
            "source_bead": "bd-hejjl",
            "artifact_root": "artifacts/readiness-lab/rch-schedule",
            "lanes": [],
            "evidence": [],
            "worker_hints": [],
            "unexpected": true
        }"#;

        let err = serde_json::from_str::<ReadinessLabRchLaneScheduleManifest>(raw)
            .expect_err("unknown fields must fail closed");

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn truth_graph_supersedes_stale_observations_with_fresh_claims() {
        let report = build_truth_graph(&sample_truth_graph_manifest());

        assert!(report.valid);
        assert_eq!(report.stale_claim_count, 1);
        assert_eq!(report.contradictory_claim_count, 0);
        assert!(
            report
                .edges
                .iter()
                .any(|edge| edge.edge_kind == "supersedes"
                    && edge.label == "fresh evidence supersedes stale observation")
        );
        assert!(
            render_readiness_lab_truth_graph_markdown(&report)
                .contains("FrankenFS Readiness Lab Truth Graph")
        );
    }

    /// bd-rchk0.53.24 - exact-output snapshot for the readiness-lab
    /// truth-graph markdown consumed by operator handoffs.
    ///
    /// The graph tests prove stale-claim and permission-boundary behavior.
    /// This snapshot pins the advisory/product-evidence wording, graph
    /// counters, blocker edge table, and empty findings sections.
    #[test]
    fn render_readiness_lab_truth_graph_markdown_sample_snapshot() {
        let report = build_truth_graph(&sample_truth_graph_manifest());
        let markdown = render_readiness_lab_truth_graph_markdown(&report);

        insta::assert_snapshot!("render_readiness_lab_truth_graph_markdown_sample", markdown);
    }

    #[test]
    fn readiness_lab_truth_graph_report_json_shape() -> serde_json::Result<()> {
        let report = build_truth_graph(&sample_truth_graph_manifest());
        assert!(report.valid);

        let full_json = serde_json::to_string_pretty(&report)?;
        let decoded: ReadinessLabTruthGraphReport = serde_json::from_str(&full_json)?;
        assert_eq!(decoded, report);
        assert_eq!(
            decoded.product_evidence_claim,
            READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM
        );
        assert!(
            decoded.edges.iter().any(|edge| edge.edge_kind == "blocks"),
            "{:?}",
            decoded.edges
        );

        let shape = serde_json::json!({
            "schema_version": report.schema_version,
            "graph_id": report.graph_id,
            "valid": report.valid,
            "dry_run_only": report.dry_run_only,
            "product_evidence_claim": report.product_evidence_claim,
            "release_gate_effect": report.release_gate_effect,
            "source_count": report.source_count,
            "claim_count": report.claim_count,
            "node_count": report.node_count,
            "edge_count": report.edge_count,
            "stale_claim_count": report.stale_claim_count,
            "contradictory_claim_count": report.contradictory_claim_count,
            "permission_requirement_count": report.permission_requirement_count,
            "simulated_node_count": report.simulated_node_count,
            "blocker_edge_count": report.blocker_edge_count,
            "errors": report.errors,
            "warnings": report.warnings,
        });
        insta::assert_snapshot!(
            "readiness_lab_truth_graph_report_json_shape",
            serde_json::to_string_pretty(&shape)?
        );
        Ok(())
    }

    #[test]
    fn truth_graph_exposes_contradictory_non_stale_claims() {
        let mut manifest = sample_truth_graph_manifest();
        manifest.sources[0].claims[0]
            .freshness
            .as_mut()
            .expect("fixture claim has freshness")
            .observed_at_epoch_days = 20_000;
        manifest.sources[1].claims[0].claim_state = ReadinessLabTruthGraphClaimState::Blocked;
        manifest.sources[1].claims[0].product_evidence_claim =
            ReadinessLabProductEvidenceClaim::None;

        let report = build_truth_graph(&manifest);

        assert!(!report.valid);
        assert_eq!(report.contradictory_claim_count, 1);
        assert_eq!(report.contradictions[0].claim_id, "swarm.responsiveness");
        assert!(report.edges.iter().any(|edge| edge.edge_kind == "blocks"
            && edge.label == "contradictory non-stale claim states"));
    }

    #[test]
    fn truth_graph_turns_missing_raw_logs_into_linked_blockers() {
        let mut manifest = sample_truth_graph_manifest();
        manifest.sources[1].claims[0].artifacts[0].raw_log_present = false;

        let report = build_truth_graph(&manifest);

        assert!(!report.valid);
        assert_eq!(report.missing_raw_log_count, 1);
        let blocker = report
            .edges
            .iter()
            .find(|edge| edge.label.contains("required raw log missing"))
            .expect("missing raw log must emit blocker edge");
        assert_eq!(
            blocker.validator_report_path.as_deref(),
            Some("artifacts/proof/fresh-release-gate.json")
        );
    }

    #[test]
    fn truth_graph_links_permissioned_handoff_to_bead_and_ack() {
        let report = build_truth_graph(&sample_truth_graph_manifest());

        assert!(report.valid);
        assert_eq!(report.permission_requirement_count, 1);
        assert!(
            report
                .edges
                .iter()
                .any(|edge| edge.edge_kind == "requires_permission"
                    && edge.bead_id.as_deref() == Some("bd-rchk3"))
        );
        assert!(report.nodes.iter().any(|node| {
            node.node_kind == "permission_requirement"
                && node
                    .metadata
                    .get("ack_env")
                    .is_some_and(|ack| ack == "XFSTESTS_REAL_RUN_ACK")
        }));
    }

    #[test]
    fn truth_graph_surfaces_simulated_evidence_nodes_without_product_claims() {
        let report = build_truth_graph(&sample_truth_graph_manifest());

        assert!(report.valid);
        assert_eq!(
            report.product_evidence_claim,
            READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM
        );
        assert!(report.simulated_node_count >= 2);
        assert!(
            report
                .nodes
                .iter()
                .any(|node| node.node_kind == "host_capability"
                    && node.host_class.as_deref() == Some("synthetic"))
        );
    }

    #[test]
    fn truth_graph_rejects_blockers_without_validator_report_or_bead() {
        let mut manifest = sample_truth_graph_manifest();
        manifest.sources[3].claims[0].blockers[0].bead_id = None;

        let report = build_truth_graph(&manifest);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "blocker_without_report_or_bead")
        );
    }

    #[test]
    fn truth_graph_renders_topology_advisor_as_advisory_node() {
        let report = build_truth_graph(&topology_advisor_truth_graph_manifest());

        assert!(report.valid);
        assert_eq!(
            report.product_evidence_claim,
            READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM
        );
        assert_eq!(
            report.release_gate_effect,
            READINESS_LAB_ADVISORY_RELEASE_GATE_EFFECT
        );
        assert!(report.blocker_edge_count >= 1);
        let node = report
            .nodes
            .iter()
            .find(|node| node.node_kind == "topology_runtime_advisor")
            .expect("topology advisor node should be rendered");
        assert_eq!(
            node.metadata.get("topology_advisor_report_path"),
            Some(&"artifacts/topology-advisor/report.json".to_owned())
        );
        assert_eq!(
            node.metadata.get("real_campaign_bead"),
            Some(&"bd-rchk0.53.8".to_owned())
        );
        assert_eq!(
            node.metadata.get("recommendation"),
            Some(&"managed".to_owned())
        );
        assert_eq!(
            node.metadata.get("blocked_claims"),
            Some(&"swarm.responsiveness".to_owned())
        );
        assert_eq!(node.metadata.get("advisory_only"), Some(&"true".to_owned()));
        assert!(
            report.edges.iter().any(|edge| edge.edge_kind == "blocks"
                && edge.bead_id.as_deref() == Some("bd-rchk0.53.8"))
        );
    }

    #[test]
    fn truth_graph_rejects_stale_topology_advisor_report() {
        let mut manifest = topology_advisor_truth_graph_manifest();
        manifest.sources[0].claims[0]
            .freshness
            .as_mut()
            .expect("topology advisor has freshness")
            .observed_at_epoch_days = 19_990;

        let report = build_truth_graph(&manifest);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|finding| { finding.finding_id == "topology_advisor_stale_report" })
        );
    }

    #[test]
    fn truth_graph_rejects_topology_advisor_bead_mismatches() {
        let mut manifest = topology_advisor_truth_graph_manifest();
        let claim = &mut manifest.sources[0].claims[0];
        claim
            .topology_advisor
            .as_mut()
            .expect("topology advisor metadata")
            .source_bead = "bd-other".to_owned();
        claim
            .topology_advisor
            .as_mut()
            .expect("topology advisor metadata")
            .real_campaign_bead = "bd-wrong-campaign".to_owned();

        let report = build_truth_graph(&manifest);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|finding| { finding.finding_id == "topology_advisor_source_bead_mismatch" })
        );
        assert!(report.errors.iter().any(|finding| {
            finding.finding_id == "topology_advisor_real_campaign_bead_mismatch"
        }));
    }

    #[test]
    fn truth_graph_rejects_topology_advisor_missing_hashes_and_unsafe_paths() {
        let mut manifest = topology_advisor_truth_graph_manifest();
        let claim = &mut manifest.sources[0].claims[0];
        claim.artifacts[0].sha256 = None;
        claim.artifacts[1].path = "../escape/structured.jsonl".to_owned();
        claim
            .topology_advisor
            .as_mut()
            .expect("topology advisor metadata")
            .artifact_paths
            .push("/tmp/escape/report.json".to_owned());

        let report = build_truth_graph(&manifest);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|finding| { finding.finding_id == "topology_advisor_missing_artifact_hash" })
        );
        assert!(
            report
                .errors
                .iter()
                .any(|finding| { finding.finding_id == "unsafe_truth_graph_artifact_path" })
        );
        assert!(
            report
                .errors
                .iter()
                .any(|finding| { finding.finding_id == "topology_advisor_unsafe_artifact_path" })
        );
    }

    #[test]
    fn truth_graph_rejects_topology_advisor_promotion_wording() {
        let mut manifest = topology_advisor_truth_graph_manifest();
        let claim = &mut manifest.sources[0].claims[0];
        claim.claim_state = ReadinessLabTruthGraphClaimState::Validated;
        claim.product_evidence_claim = ReadinessLabProductEvidenceClaim::ProductPassFail;
        let advisor = claim
            .topology_advisor
            .as_mut()
            .expect("topology advisor metadata");
        advisor.advisory_only = false;
        advisor.product_evidence_claim = ReadinessLabProductEvidenceClaim::ProductPassFail;
        advisor.release_gate_effect = "strengthens_product_pass".to_owned();
        advisor.recommendation = Some("accepted_large_host".to_owned());

        let report = build_truth_graph(&manifest);

        assert!(!report.valid);
        for expected in [
            "topology_advisor_not_advisory_only",
            "topology_advisor_product_evidence_claim",
            "topology_advisor_release_gate_effect",
            "topology_advisor_claim_product_evidence",
            "topology_advisor_claim_validated",
            "topology_advisor_forbidden_promotion_wording",
        ] {
            assert!(
                report
                    .errors
                    .iter()
                    .any(|finding| finding.finding_id == expected),
                "missing {expected}"
            );
        }
    }

    #[test]
    fn numa_p99_replay_covers_all_shapes_and_preserves_advisory_claims() {
        let report = validate_numa_p99_replay(&sample_numa_p99_replay_manifest());

        assert!(report.valid);
        assert!(report.replay_only);
        assert_eq!(report.fixture_count, 6);
        assert_eq!(report.row_count, 6);
        assert_eq!(report.missing_shape_count, 0);
        assert_eq!(
            report.product_evidence_claim,
            READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM
        );
        assert!(
            report
                .release_gate_effect
                .contains("public readiness unchanged")
        );
        for shape in required_numa_p99_fixture_shapes() {
            assert_eq!(report.shape_counts.get(shape.label()), Some(&1));
        }
        assert!(
            report
                .rows
                .iter()
                .any(|row| row.fixture_shape == "skewed_numa"
                    && row.dominant_component == "numa_remote_access")
        );
        assert!(
            render_readiness_lab_numa_p99_replay_markdown(&report)
                .contains("FrankenFS Readiness Lab NUMA/p99 Replay")
        );
    }

    /// bd-rchk0.53.25 - exact-output snapshot for the readiness-lab
    /// NUMA/p99 replay markdown consumed by operator handoffs.
    ///
    /// The replay tests prove fixture coverage and advisory-only semantics.
    /// This snapshot pins the rendered release-gate wording, fixture counters,
    /// replay rows, dominant components, component sums, and empty findings.
    #[test]
    fn render_readiness_lab_numa_p99_replay_markdown_sample_snapshot() {
        let report = validate_numa_p99_replay(&sample_numa_p99_replay_manifest());
        let markdown = render_readiness_lab_numa_p99_replay_markdown(&report);

        insta::assert_snapshot!(
            "render_readiness_lab_numa_p99_replay_markdown_sample",
            markdown
        );
    }

    #[test]
    fn readiness_lab_numa_p99_replay_report_json_shape() -> serde_json::Result<()> {
        let report = validate_numa_p99_replay(&sample_numa_p99_replay_manifest());
        assert!(report.valid);
        assert!(report.replay_only);

        let full_json = serde_json::to_string_pretty(&report)?;
        let decoded: ReadinessLabNumaP99ReplayReport = serde_json::from_str(&full_json)?;
        assert_eq!(decoded, report);
        assert_eq!(
            decoded.product_evidence_claim,
            READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM
        );
        assert!(
            decoded
                .release_gate_effect
                .contains("public readiness unchanged")
        );
        assert!(
            decoded
                .rows
                .iter()
                .any(|row| row.fixture_shape == "skewed_numa"
                    && row.dominant_component == "numa_remote_access"
                    && row.product_evidence_claim == READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM)
        );

        let row_shapes: Vec<_> = report
            .rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "fixture_id": row.fixture_id,
                    "fixture_shape": row.fixture_shape,
                    "dominant_component": row.dominant_component,
                })
            })
            .collect();
        let skewed_row = report
            .rows
            .iter()
            .find(|row| row.fixture_shape == "skewed_numa")
            .expect("sample fixture set includes skewed NUMA row");
        let representative_row = serde_json::json!({
            "fixture_id": skewed_row.fixture_id,
            "fixture_shape": skewed_row.fixture_shape,
            "classification": skewed_row.classification,
            "product_evidence_claim": skewed_row.product_evidence_claim,
            "release_gate_effect": skewed_row.release_gate_effect,
            "logical_cpus": skewed_row.logical_cpus,
            "numa_nodes": skewed_row.numa_nodes,
            "worker_count": skewed_row.worker_count,
            "hot_shard_count": skewed_row.hot_shard_count,
            "memory_pressure_percent": skewed_row.memory_pressure_percent,
            "duration_ms": skewed_row.duration_ms,
            "p50_latency_us": skewed_row.p50_latency_us,
            "p95_latency_us": skewed_row.p95_latency_us,
            "p99_latency_us": skewed_row.p99_latency_us,
            "component_p99_sum_us": skewed_row.component_p99_sum_us,
            "dominant_component": skewed_row.dominant_component,
            "dominant_component_p99_us": skewed_row.dominant_component_p99_us,
            "queue_depth_p99": skewed_row.queue_depth_p99,
            "raw_log_path": skewed_row.raw_log_path,
            "reproduction_command": skewed_row.reproduction_command,
            "finding_count": skewed_row.finding_count,
        });

        let shape = serde_json::json!({
            "schema_version": report.schema_version,
            "replay_id": report.replay_id,
            "manifest_path": report.manifest_path,
            "valid": report.valid,
            "replay_only": report.replay_only,
            "product_evidence_claim": report.product_evidence_claim,
            "release_gate_effect": report.release_gate_effect,
            "source_bead": report.source_bead,
            "fixture_count": report.fixture_count,
            "row_count": report.row_count,
            "invalid_fixture_count": report.invalid_fixture_count,
            "missing_shape_count": report.missing_shape_count,
            "missing_p99_bucket_count": report.missing_p99_bucket_count,
            "malformed_histogram_count": report.malformed_histogram_count,
            "impossible_cpu_count": report.impossible_cpu_count,
            "negative_duration_count": report.negative_duration_count,
            "stale_fixture_count": report.stale_fixture_count,
            "future_fixture_count": report.future_fixture_count,
            "shape_counts": report.shape_counts,
            "row_shapes": row_shapes,
            "representative_row": representative_row,
            "errors": report.errors,
            "warnings": report.warnings,
        });
        insta::assert_snapshot!(
            "readiness_lab_numa_p99_replay_report_json_shape",
            serde_json::to_string_pretty(&shape)?
        );
        Ok(())
    }

    #[test]
    fn checked_in_numa_p99_replay_fixture_manifest_validates() {
        let manifest = serde_json::from_str::<ReadinessLabNumaP99ReplayManifest>(include_str!(
            "../../../tests/readiness-lab/numa_p99_replay_fixtures.json"
        ))
        .expect("checked-in replay fixture parses");

        let report = validate_readiness_lab_numa_p99_replay(
            &manifest,
            &ReadinessLabNumaP99ReplayConfig {
                manifest_path: DEFAULT_READINESS_LAB_NUMA_P99_REPLAY_MANIFEST.to_owned(),
                reference_epoch_days: Some(20_001),
            },
        );

        assert!(
            report.valid,
            "checked-in replay fixture errors: {:?}",
            report.errors
        );
        assert_eq!(report.fixture_count, 6);
        assert_eq!(report.missing_shape_count, 0);
    }

    #[test]
    fn numa_p99_replay_rejects_malformed_histograms_missing_p99_cpu_and_duration() {
        let mut manifest = sample_numa_p99_replay_manifest();
        manifest.fixtures[0].latency.p95_latency_us = Some(20_000.0);
        manifest.fixtures[0].latency.p99_latency_us = Some(10_000.0);
        manifest.fixtures[1].latency.p99_latency_us = None;
        manifest.fixtures[2].host.logical_cpus = 0;
        manifest.fixtures[3].workload.duration_ms = -1;
        manifest.fixtures[4].latency.attribution[0].p99_us = None;

        let report = validate_numa_p99_replay(&manifest);

        assert!(!report.valid);
        assert_eq!(report.missing_p99_bucket_count, 2);
        assert!(report.malformed_histogram_count >= 1);
        assert_eq!(report.impossible_cpu_count, 1);
        assert_eq!(report.negative_duration_count, 1);
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "malformed_latency_histogram_order")
        );
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "missing_p99_bucket")
        );
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "impossible_logical_cpu_count")
        );
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "non_positive_duration_ms")
        );
    }

    #[test]
    fn numa_p99_replay_rejects_missing_shapes_and_product_claims() {
        let mut manifest = sample_numa_p99_replay_manifest();
        manifest.product_evidence_claim = ReadinessLabProductEvidenceClaim::ProductPassFail;
        manifest.fixtures.retain(|fixture| {
            fixture.fixture_shape != ReadinessLabNumaP99FixtureShape::MemoryPressure
        });

        let report = validate_numa_p99_replay(&manifest);

        assert!(!report.valid);
        assert_eq!(report.missing_shape_count, 1);
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "product_evidence_claim_violation")
        );
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "missing_replay_fixture_shape")
        );
    }
}
