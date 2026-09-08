#![allow(clippy::module_name_repetitions, clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! Schema and deterministic fixtures for readiness-action planning.
//!
//! This module does not choose or execute actions. It defines the evidence
//! envelope consumed by the planner beads that follow `bd-rchk0.98.1`.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

pub const READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION: u32 = 1;
pub const READINESS_ACTION_FIXTURE_VALIDATOR_VERSION: u32 = 1;
pub const READINESS_ACTION_DRY_RUN_REPORT_VERSION: u32 = 1;

const REQUIRED_FIXTURE_CLASSIFICATIONS: [ReadinessFixtureClassification; 4] = [
    ReadinessFixtureClassification::LocalSafe,
    ReadinessFixtureClassification::PermissionedBlocked,
    ReadinessFixtureClassification::StaleEvidence,
    ReadinessFixtureClassification::ContradictoryEvidence,
];

const REQUIRED_INPUT_KINDS: [ReadinessActionInputKind; 7] = [
    ReadinessActionInputKind::BeadsJsonl,
    ReadinessActionInputKind::ReleaseGatePolicy,
    ReadinessActionInputKind::ProofBundleReport,
    ReadinessActionInputKind::OperationalReadinessReport,
    ReadinessActionInputKind::HostCapabilityArtifact,
    ReadinessActionInputKind::ClaimabilityPlanReport,
    ReadinessActionInputKind::RchProofLedger,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionAutopilotFixtureSet {
    pub schema_version: u32,
    pub fixture_set_id: String,
    pub fixtures: Vec<ReadinessActionAutopilotFixture>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionAutopilotFixture {
    pub fixture_id: String,
    pub expected_classification: ReadinessFixtureClassification,
    pub report: ReadinessActionAutopilotReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessFixtureClassification {
    LocalSafe,
    PermissionedBlocked,
    StaleEvidence,
    ContradictoryEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionAutopilotReport {
    pub schema_version: u32,
    pub report_id: String,
    pub generated_at: String,
    pub source_inputs: Vec<ReadinessActionInput>,
    pub recommendations: Vec<ReadinessActionRecommendation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionInput {
    pub input_id: String,
    pub kind: ReadinessActionInputKind,
    pub path: String,
    pub required: bool,
    pub state: ReadinessActionInputState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessActionInputKind {
    BeadsJsonl,
    ReleaseGatePolicy,
    ProofBundleReport,
    OperationalReadinessReport,
    HostCapabilityArtifact,
    ClaimabilityPlanReport,
    RchProofLedger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessActionInputState {
    Present,
    Missing,
    Stale,
    Contradictory,
    PermissionRequired,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionRecommendation {
    pub action_id: String,
    pub title: String,
    pub safety_class: ReadinessActionSafetyClass,
    pub controlling_bead: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail_thread_id: Option<String>,
    pub evidence_tier: ReadinessEvidenceTier,
    pub ack_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservation_artifact_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_artifact_path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub safe_next_commands: Vec<String>,
    pub reproduction_command: String,
    pub rationale: String,
    pub public_claim_effect: PublicClaimEffect,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<ReadinessActionDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessActionSafetyClass {
    LocalSafe,
    Permissioned,
    Destructive,
    Impossible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessEvidenceTier {
    TrackerOnly,
    Smoke,
    ProofBundle,
    OperationalReadiness,
    Authoritative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicClaimEffect {
    NoChange,
    BlockUpgrade,
    DowngradeRequired,
    UpgradeEligible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionDiagnostic {
    pub diagnostic_id: String,
    pub severity: ReadinessActionDiagnosticSeverity,
    pub source_kind: ReadinessActionInputKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    pub message: String,
    pub remediation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_age_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness_ttl_days: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessActionDiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionFixtureValidationReport {
    pub schema_version: u32,
    pub validator_version: u32,
    pub fixture_set_id: String,
    pub fixture_count: usize,
    pub valid: bool,
    pub classifications_seen: Vec<ReadinessFixtureClassification>,
    pub input_kinds_seen: Vec<ReadinessActionInputKind>,
    pub safety_classes_seen: Vec<ReadinessActionSafetyClass>,
    pub evidence_tiers_seen: Vec<ReadinessEvidenceTier>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionPlanningInput {
    pub report_id: String,
    pub generated_at: String,
    pub source_reports: Vec<ReadinessActionAutopilotReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_tracker_issues: Vec<ReadinessActionTrackerIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionTrackerIssue {
    pub issue_id: String,
    pub title: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionPlanningResult {
    pub report: ReadinessActionAutopilotReport,
    pub suppressed_duplicates: Vec<ReadinessActionSuppressedDuplicate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionSuppressedDuplicate {
    pub action_id: String,
    pub controlling_bead: String,
    pub duplicate_issue_id: String,
    pub duplicate_issue_title: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionDryRunReport {
    pub schema_version: u32,
    pub report_id: String,
    pub generated_at: String,
    pub dry_run: bool,
    pub command_metadata: ReadinessActionDryRunMetadata,
    pub planner_result: ReadinessActionPlanningResult,
    pub scenarios: Vec<ReadinessActionDryRunScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionDryRunMetadata {
    pub invocation: String,
    pub json_report_path: String,
    pub markdown_report_path: String,
    pub stdout_log_path: String,
    pub stderr_log_path: String,
    pub cleanup_status: String,
    pub output_paths: Vec<ReadinessActionDryRunOutputPath>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionDryRunOutputPath {
    pub kind: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionDryRunScenario {
    pub scenario_id: String,
    pub action_id: String,
    pub title: String,
    pub safety_class: ReadinessActionSafetyClass,
    pub ack_required: bool,
    pub evidence_tier: ReadinessEvidenceTier,
    pub public_claim_effect: PublicClaimEffect,
    pub controlling_bead: String,
    pub reproduction_command: String,
    pub diagnostic_count: usize,
    pub dry_run_note: String,
}

#[must_use]
pub fn default_readiness_action_autopilot_fixture_set() -> ReadinessActionAutopilotFixtureSet {
    ReadinessActionAutopilotFixtureSet {
        schema_version: READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION,
        fixture_set_id: "frankenfs_readiness_action_autopilot_fixtures_v1".to_owned(),
        fixtures: vec![
            ReadinessActionAutopilotFixture {
                fixture_id: "local_safe_schema_slice".to_owned(),
                expected_classification: ReadinessFixtureClassification::LocalSafe,
                report: ReadinessActionAutopilotReport {
                    schema_version: READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION,
                    report_id: "readiness_action_local_safe_schema_slice".to_owned(),
                    generated_at: "2026-05-07T00:00:00Z".to_owned(),
                    source_inputs: vec![
                        input(
                            "beads-open-queue",
                            ReadinessActionInputKind::BeadsJsonl,
                            ".beads/issues.jsonl",
                            ReadinessActionInputState::Present,
                        ),
                        input(
                            "release-gate-policy",
                            ReadinessActionInputKind::ReleaseGatePolicy,
                            "crates/ffs-harness/fixtures/release_gate_policy_v1.json",
                            ReadinessActionInputState::Present,
                        ),
                    ],
                    recommendations: vec![ReadinessActionRecommendation {
                        action_id: "define-readiness-action-schema".to_owned(),
                        title: "Define readiness action autopilot schema and fixtures".to_owned(),
                        safety_class: ReadinessActionSafetyClass::LocalSafe,
                        controlling_bead: "bd-rchk0.98.1".to_owned(),
                        mail_thread_id: None,
                        evidence_tier: ReadinessEvidenceTier::TrackerOnly,
                        ack_required: false,
                        reservation_artifact_path: None,
                        proof_artifact_path: None,
                        safe_next_commands: Vec::new(),
                        reproduction_command:
                            "cargo test -p ffs-harness readiness_action_autopilot"
                                .to_owned(),
                        rationale: "The only required changes are local schema and fixture tests."
                            .to_owned(),
                        public_claim_effect: PublicClaimEffect::NoChange,
                        diagnostics: Vec::new(),
                    }],
                },
            },
            ReadinessActionAutopilotFixture {
                fixture_id: "permissioned_xfstests_blocked".to_owned(),
                expected_classification: ReadinessFixtureClassification::PermissionedBlocked,
                report: ReadinessActionAutopilotReport {
                    schema_version: READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION,
                    report_id: "readiness_action_permissioned_xfstests_blocked".to_owned(),
                    generated_at: "2026-05-07T00:00:00Z".to_owned(),
                    source_inputs: vec![
                        input(
                            "beads-open-queue",
                            ReadinessActionInputKind::BeadsJsonl,
                            ".beads/issues.jsonl",
                            ReadinessActionInputState::Present,
                        ),
                        input(
                            "operational-readiness-report",
                            ReadinessActionInputKind::OperationalReadinessReport,
                            "artifacts/readiness/operational_readiness_report.json",
                            ReadinessActionInputState::Missing,
                        ),
                    ],
                    recommendations: vec![ReadinessActionRecommendation {
                        action_id: "run-permissioned-xfstests-baseline".to_owned(),
                        title: "Run permissioned xfstests baseline".to_owned(),
                        safety_class: ReadinessActionSafetyClass::Permissioned,
                        controlling_bead: "bd-rchk3.3".to_owned(),
                        mail_thread_id: None,
                        evidence_tier: ReadinessEvidenceTier::OperationalReadiness,
                        ack_required: true,
                        reservation_artifact_path: None,
                        proof_artifact_path: None,
                        safe_next_commands: Vec::new(),
                        reproduction_command: "XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices scripts/e2e/ffs_xfstests_e2e.sh".to_owned(),
                        rationale: "The current queue contains xfstests work that cannot run without explicit mutation authorization.".to_owned(),
                        public_claim_effect: PublicClaimEffect::BlockUpgrade,
                        diagnostics: vec![diagnostic(
                            "xfstests-real-run-ack-missing",
                            ReadinessActionDiagnosticSeverity::Error,
                            ReadinessActionInputKind::OperationalReadinessReport,
                            Some("artifacts/readiness/operational_readiness_report.json"),
                            "No real xfstests pass/fail artifact is present.",
                            "Obtain explicit operator authorization before running the mutating baseline.",
                        )],
                    }],
                },
            },
            ReadinessActionAutopilotFixture {
                fixture_id: "stale_large_host_swarm_evidence".to_owned(),
                expected_classification: ReadinessFixtureClassification::StaleEvidence,
                report: ReadinessActionAutopilotReport {
                    schema_version: READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION,
                    report_id: "readiness_action_stale_large_host_swarm_evidence".to_owned(),
                    generated_at: "2026-05-07T00:00:00Z".to_owned(),
                    source_inputs: vec![
                        input(
                            "proof-bundle-report",
                            ReadinessActionInputKind::ProofBundleReport,
                            "artifacts/proof_bundles/swarm_tail_latency.json",
                            ReadinessActionInputState::Stale,
                        ),
                        input(
                            "host-capability-manifest",
                            ReadinessActionInputKind::HostCapabilityArtifact,
                            "artifacts/hosts/large_host_capability.json",
                            ReadinessActionInputState::PermissionRequired,
                        ),
                    ],
                    recommendations: vec![ReadinessActionRecommendation {
                        action_id: "refresh-large-host-swarm-campaign".to_owned(),
                        title: "Refresh large-host swarm responsiveness evidence".to_owned(),
                        safety_class: ReadinessActionSafetyClass::Permissioned,
                        controlling_bead: "bd-rchk0.53.8".to_owned(),
                        mail_thread_id: None,
                        evidence_tier: ReadinessEvidenceTier::Authoritative,
                        ack_required: true,
                        reservation_artifact_path: None,
                        proof_artifact_path: None,
                        safe_next_commands: Vec::new(),
                        reproduction_command: "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1 FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host scripts/e2e/ffs_swarm_workload_harness_e2e.sh".to_owned(),
                        rationale: "Large-host responsiveness claims require fresh authoritative host evidence.".to_owned(),
                        public_claim_effect: PublicClaimEffect::DowngradeRequired,
                        diagnostics: vec![ReadinessActionDiagnostic {
                            diagnostic_id: "swarm-evidence-stale".to_owned(),
                            severity: ReadinessActionDiagnosticSeverity::Warning,
                            source_kind: ReadinessActionInputKind::ProofBundleReport,
                            source_path: Some(
                                "artifacts/proof_bundles/swarm_tail_latency.json".to_owned(),
                            ),
                            message: "The swarm tail-latency proof bundle is beyond its freshness window.".to_owned(),
                            remediation: "Rerun on a permissioned large host before upgrading readiness wording.".to_owned(),
                            stale_age_days: Some(31),
                            freshness_ttl_days: Some(14),
                        }],
                    }],
                },
            },
            ReadinessActionAutopilotFixture {
                fixture_id: "contradictory_release_gate_claim".to_owned(),
                expected_classification: ReadinessFixtureClassification::ContradictoryEvidence,
                report: ReadinessActionAutopilotReport {
                    schema_version: READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION,
                    report_id: "readiness_action_contradictory_release_gate_claim".to_owned(),
                    generated_at: "2026-05-07T00:00:00Z".to_owned(),
                    source_inputs: vec![
                        input(
                            "release-gate-policy",
                            ReadinessActionInputKind::ReleaseGatePolicy,
                            "crates/ffs-harness/fixtures/release_gate_policy_v1.json",
                            ReadinessActionInputState::Present,
                        ),
                        input(
                            "proof-bundle-report",
                            ReadinessActionInputKind::ProofBundleReport,
                            "artifacts/proof_bundles/release_gate.json",
                            ReadinessActionInputState::Contradictory,
                        ),
                    ],
                    recommendations: vec![ReadinessActionRecommendation {
                        action_id: "refuse-contradictory-readiness-upgrade".to_owned(),
                        title: "Refuse contradictory readiness upgrade".to_owned(),
                        safety_class: ReadinessActionSafetyClass::Impossible,
                        controlling_bead: "bd-rchk0".to_owned(),
                        mail_thread_id: None,
                        evidence_tier: ReadinessEvidenceTier::ProofBundle,
                        ack_required: false,
                        reservation_artifact_path: None,
                        proof_artifact_path: None,
                        safe_next_commands: Vec::new(),
                        reproduction_command: "cargo test -p ffs-harness release_gate -- --nocapture".to_owned(),
                        rationale: "A public readiness upgrade is impossible while proof-bundle and release-gate evidence disagree.".to_owned(),
                        public_claim_effect: PublicClaimEffect::BlockUpgrade,
                        diagnostics: vec![diagnostic(
                            "release-gate-proof-contradiction",
                            ReadinessActionDiagnosticSeverity::Error,
                            ReadinessActionInputKind::ProofBundleReport,
                            Some("artifacts/proof_bundles/release_gate.json"),
                            "The proof bundle contradicts the release-gate policy state.",
                            "Resolve the artifact conflict before changing README or FEATURE_PARITY readiness claims.",
                        )],
                    }],
                },
            },
            ReadinessActionAutopilotFixture {
                fixture_id: "claimability_and_rch_operator_evidence".to_owned(),
                expected_classification: ReadinessFixtureClassification::LocalSafe,
                report: ReadinessActionAutopilotReport {
                    schema_version: READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION,
                    report_id: "readiness_action_claimability_rch_operator_evidence".to_owned(),
                    generated_at: "2026-05-14T00:00:00Z".to_owned(),
                    source_inputs: vec![
                        input(
                            "claimability-plan-polluted",
                            ReadinessActionInputKind::ClaimabilityPlanReport,
                            "artifacts/claimability_autopilot/polluted_one_claimable/claimability_plan.json",
                            ReadinessActionInputState::Present,
                        ),
                        input(
                            "claimability-plan-permission-gated",
                            ReadinessActionInputKind::ClaimabilityPlanReport,
                            "artifacts/claimability_autopilot/permission_gated_zero_claimable/claimability_plan.json",
                            ReadinessActionInputState::Present,
                        ),
                        input(
                            "rch-proof-ledger-degraded",
                            ReadinessActionInputKind::RchProofLedger,
                            "artifacts/rch/proof_ledgers/remote_success_artifact_warning.json",
                            ReadinessActionInputState::Present,
                        ),
                    ],
                    recommendations: vec![
                        ReadinessActionRecommendation {
                            action_id: "claim-source-aware-task".to_owned(),
                            title: "Claim source-aware task from claimability plan".to_owned(),
                            safety_class: ReadinessActionSafetyClass::LocalSafe,
                            controlling_bead: "bd-0chpv.5".to_owned(),
                            mail_thread_id: Some("bd-0chpv.5".to_owned()),
                            evidence_tier: ReadinessEvidenceTier::TrackerOnly,
                            ack_required: false,
                            reservation_artifact_path: Some(
                                "artifacts/agent_mail/reservations/bd-0chpv.5.json".to_owned(),
                            ),
                            proof_artifact_path: None,
                            safe_next_commands: vec![
                                "br update --no-db --json --actor <agent> --claim bd-0chpv.5"
                                    .to_owned(),
                                "file_reservation_paths(project_key, agent_name, exact_paths, reason=\"bd-0chpv.5\")"
                                    .to_owned(),
                            ],
                            reproduction_command:
                                "ffs-harness claimability-plan --tracker-report tracker_source_hygiene_report.json"
                                    .to_owned(),
                            rationale: "Claimability planner output can identify one safe local task, but it is operator evidence only and does not change readiness claims."
                                .to_owned(),
                            public_claim_effect: PublicClaimEffect::NoChange,
                            diagnostics: Vec::new(),
                        },
                        ReadinessActionRecommendation {
                            action_id: "block-permission-gated-claimability-row".to_owned(),
                            title: "Block permission-gated claimability row".to_owned(),
                            safety_class: ReadinessActionSafetyClass::Permissioned,
                            controlling_bead: "bd-rchk3.3".to_owned(),
                            mail_thread_id: Some("bd-rchk3.3".to_owned()),
                            evidence_tier: ReadinessEvidenceTier::TrackerOnly,
                            ack_required: true,
                            reservation_artifact_path: None,
                            proof_artifact_path: None,
                            safe_next_commands: vec![
                                "do not run without XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices"
                                    .to_owned(),
                            ],
                            reproduction_command: "XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices scripts/e2e/ffs_xfstests_e2e.sh".to_owned(),
                            rationale: "The claimability plan preserves permission-gated rows as blocked work until the exact operator ACK is present.".to_owned(),
                            public_claim_effect: PublicClaimEffect::BlockUpgrade,
                            diagnostics: vec![diagnostic(
                                "claimability-permission-gate-present",
                                ReadinessActionDiagnosticSeverity::Warning,
                                ReadinessActionInputKind::ClaimabilityPlanReport,
                                Some("artifacts/claimability_autopilot/permission_gated_zero_claimable/claimability_plan.json"),
                                "Claimability planner reported a permission-gated queue row.",
                                "keep the action dry-run-only until the operator supplies the exact ACK",
                            )],
                        },
                        ReadinessActionRecommendation {
                            action_id: "preserve-foreign-owner-handoff".to_owned(),
                            title: "Preserve foreign tracker rows for owner handoff".to_owned(),
                            safety_class: ReadinessActionSafetyClass::LocalSafe,
                            controlling_bead: "bd-0chpv.2".to_owned(),
                            mail_thread_id: Some("tracker-hygiene".to_owned()),
                            evidence_tier: ReadinessEvidenceTier::TrackerOnly,
                            ack_required: false,
                            reservation_artifact_path: None,
                            proof_artifact_path: None,
                            safe_next_commands: vec![
                                "message owner project before moving, closing, rewriting, or claiming foreign rows"
                                    .to_owned(),
                            ],
                            reproduction_command:
                                "ffs-harness claimability-plan --tracker-report polluted_tracker_source_hygiene_report.json"
                                    .to_owned(),
                            rationale: "Polluted tracker rows are advisory owner-handoff evidence, not local readiness work."
                                .to_owned(),
                            public_claim_effect: PublicClaimEffect::NoChange,
                            diagnostics: Vec::new(),
                        },
                        ReadinessActionRecommendation {
                            action_id: "preserve-degraded-rch-proof-ledger".to_owned(),
                            title: "Preserve degraded RCH proof ledger".to_owned(),
                            safety_class: ReadinessActionSafetyClass::LocalSafe,
                            controlling_bead: "bd-0chpv.4".to_owned(),
                            mail_thread_id: Some("bd-0chpv.4".to_owned()),
                            evidence_tier: ReadinessEvidenceTier::ProofBundle,
                            ack_required: false,
                            reservation_artifact_path: None,
                            proof_artifact_path: Some(
                                "artifacts/rch/proof_ledgers/remote_success_artifact_warning.json"
                                    .to_owned(),
                            ),
                            safe_next_commands: vec![
                                "preserve worker exit=0 transcript and artifact warning before deciding whether to rerun"
                                    .to_owned(),
                                "reject [RCH] local fallback as proof".to_owned(),
                            ],
                            reproduction_command:
                                "ffs-harness rch-proof-ledger --transcript artifacts/rch/transcripts/cargo_check.raw"
                                    .to_owned(),
                            rationale: "A degraded RCH proof ledger is useful operator evidence, but it must not upgrade readiness by itself."
                                .to_owned(),
                            public_claim_effect: PublicClaimEffect::NoChange,
                            diagnostics: vec![diagnostic(
                                "rch-proof-ledger-artifact-warning",
                                ReadinessActionDiagnosticSeverity::Warning,
                                ReadinessActionInputKind::RchProofLedger,
                                Some("artifacts/rch/proof_ledgers/remote_success_artifact_warning.json"),
                                "Remote worker success has an artifact retrieval warning.",
                                "preserve the transcript and use degraded-proof wording instead of upgrading readiness",
                            )],
                        },
                    ],
                },
            },
        ],
    }
}

#[must_use]
pub fn build_readiness_action_dry_run_report(
    input: &ReadinessActionPlanningInput,
    command_metadata: ReadinessActionDryRunMetadata,
) -> ReadinessActionDryRunReport {
    let planner_result = plan_readiness_actions(input);
    let scenarios = planner_result
        .report
        .recommendations
        .iter()
        .map(readiness_action_dry_run_scenario)
        .collect();

    ReadinessActionDryRunReport {
        schema_version: READINESS_ACTION_DRY_RUN_REPORT_VERSION,
        report_id: input.report_id.clone(),
        generated_at: input.generated_at.clone(),
        dry_run: true,
        command_metadata,
        planner_result,
        scenarios,
    }
}

#[must_use]
pub fn render_readiness_action_dry_run_markdown(report: &ReadinessActionDryRunReport) -> String {
    let mut markdown = String::new();
    markdown.push_str("# Readiness Action Dry-Run Report\n\n");
    let _ = writeln!(markdown, "- Report: `{}`", report.report_id);
    let _ = writeln!(markdown, "- Generated at: `{}`", report.generated_at);
    let _ = writeln!(markdown, "- Dry run: `{}`", report.dry_run);
    let _ = writeln!(
        markdown,
        "- Recommendations: `{}`",
        report.planner_result.report.recommendations.len()
    );
    let _ = writeln!(
        markdown,
        "- Suppressed duplicates: `{}`",
        report.planner_result.suppressed_duplicates.len()
    );
    let _ = writeln!(
        markdown,
        "- Cleanup status: `{}`",
        report.command_metadata.cleanup_status
    );

    markdown.push_str("\n## Command Metadata\n\n");
    let _ = writeln!(
        markdown,
        "- Invocation: `{}`",
        report.command_metadata.invocation
    );
    let _ = writeln!(
        markdown,
        "- Stdout log: `{}`",
        report.command_metadata.stdout_log_path
    );
    let _ = writeln!(
        markdown,
        "- Stderr log: `{}`",
        report.command_metadata.stderr_log_path
    );

    markdown.push_str("\n## Output Paths\n\n");
    markdown.push_str("| Kind | Path |\n|---|---|\n");
    for path in &report.command_metadata.output_paths {
        let _ = writeln!(
            markdown,
            "| {} | `{}` |",
            markdown_table_cell(&path.kind),
            markdown_table_cell(&path.path)
        );
    }

    markdown.push_str("\n## Recommendations\n\n");
    markdown.push_str(
        "| Action | Safety | Ack | Claim | Evidence | Diagnostics | Reproduction Command |\n",
    );
    markdown.push_str("|---|---:|---:|---|---|---:|---|\n");
    for scenario in &report.scenarios {
        let _ = writeln!(
            markdown,
            "| {} | {:?} | {} | {:?} | {:?} | {} | `{}` |",
            markdown_table_cell(&scenario.action_id),
            scenario.safety_class,
            scenario.ack_required,
            scenario.public_claim_effect,
            scenario.evidence_tier,
            scenario.diagnostic_count,
            markdown_table_cell(&scenario.reproduction_command)
        );
    }

    let operator_evidence_rows = report
        .planner_result
        .report
        .recommendations
        .iter()
        .filter(|recommendation| {
            recommendation.mail_thread_id.is_some()
                || recommendation.reservation_artifact_path.is_some()
                || recommendation.proof_artifact_path.is_some()
                || !recommendation.safe_next_commands.is_empty()
        })
        .collect::<Vec<_>>();
    if !operator_evidence_rows.is_empty() {
        markdown.push_str("\n## Operator Evidence\n\n");
        markdown.push_str("| Action | Mail Thread | Reservation Artifact | Proof Artifact | Safe Next Commands |\n|---|---|---|---|---|\n");
        for recommendation in operator_evidence_rows {
            let safe_next_commands = if recommendation.safe_next_commands.is_empty() {
                "none".to_owned()
            } else {
                recommendation.safe_next_commands.join("<br>")
            };
            let _ = writeln!(
                markdown,
                "| {} | {} | {} | {} | {} |",
                markdown_table_cell(&recommendation.action_id),
                markdown_table_cell(recommendation.mail_thread_id.as_deref().unwrap_or("none")),
                markdown_table_cell(
                    recommendation
                        .reservation_artifact_path
                        .as_deref()
                        .unwrap_or("none")
                ),
                markdown_table_cell(
                    recommendation
                        .proof_artifact_path
                        .as_deref()
                        .unwrap_or("none")
                ),
                markdown_table_cell(&safe_next_commands)
            );
        }
    }

    if !report.planner_result.suppressed_duplicates.is_empty() {
        markdown.push_str("\n## Suppressed Duplicates\n\n");
        markdown.push_str("| Action | Controlling Bead | Duplicate Issue |\n|---|---|---|\n");
        for duplicate in &report.planner_result.suppressed_duplicates {
            let _ = writeln!(
                markdown,
                "| {} | {} | {} |",
                markdown_table_cell(&duplicate.action_id),
                markdown_table_cell(&duplicate.controlling_bead),
                markdown_table_cell(&duplicate.duplicate_issue_id)
            );
        }
    }

    markdown
}

#[must_use]
pub fn plan_readiness_actions(
    input: &ReadinessActionPlanningInput,
) -> ReadinessActionPlanningResult {
    let active_tracker_index = ActiveTrackerIndex::new(&input.active_tracker_issues);
    let mut source_inputs = BTreeMap::new();
    let mut ranked_recommendations = Vec::new();
    let mut suppressed_duplicates = Vec::new();

    for report in &input.source_reports {
        merge_source_inputs(&mut source_inputs, &report.source_inputs);
        let input_diagnostics = input_state_diagnostics(&report.source_inputs);
        let report_penalty = report_input_penalty(&report.source_inputs);

        for recommendation in &report.recommendations {
            if let Some(duplicate) = active_tracker_index.duplicate_for(recommendation) {
                suppressed_duplicates.push(ReadinessActionSuppressedDuplicate {
                    action_id: recommendation.action_id.clone(),
                    controlling_bead: recommendation.controlling_bead.clone(),
                    duplicate_issue_id: duplicate.issue_id.clone(),
                    duplicate_issue_title: duplicate.title.clone(),
                });
                continue;
            }

            let mut recommendation = recommendation.clone();
            append_missing_input_diagnostics(&mut recommendation, &input_diagnostics);
            apply_fail_closed_guards(&mut recommendation, &report.source_inputs);
            ranked_recommendations.push(ScoredReadinessAction {
                rank: ReadinessActionRank::for_recommendation(&recommendation, report_penalty),
                recommendation,
            });
        }
    }

    ranked_recommendations.sort_by(|left, right| left.rank.cmp(&right.rank));
    suppressed_duplicates.sort_by(|left, right| {
        (
            left.controlling_bead.as_str(),
            left.action_id.as_str(),
            left.duplicate_issue_id.as_str(),
        )
            .cmp(&(
                right.controlling_bead.as_str(),
                right.action_id.as_str(),
                right.duplicate_issue_id.as_str(),
            ))
    });

    ReadinessActionPlanningResult {
        report: ReadinessActionAutopilotReport {
            schema_version: READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION,
            report_id: input.report_id.clone(),
            generated_at: input.generated_at.clone(),
            source_inputs: source_inputs.into_values().collect(),
            recommendations: ranked_recommendations
                .into_iter()
                .map(|scored| scored.recommendation)
                .collect(),
        },
        suppressed_duplicates,
    }
}

#[must_use]
pub fn validate_readiness_action_fixture_set(
    fixture_set: &ReadinessActionAutopilotFixtureSet,
) -> ReadinessActionFixtureValidationReport {
    let mut errors = Vec::new();
    let mut classifications_seen = BTreeSet::new();
    let mut input_kinds_seen = BTreeSet::new();
    let mut safety_classes_seen = BTreeSet::new();
    let mut evidence_tiers_seen = BTreeSet::new();

    if fixture_set.schema_version != READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION {
        errors.push(format!(
            "fixture_set schema_version {} must equal {READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION}",
            fixture_set.schema_version
        ));
    }
    if fixture_set.fixture_set_id.trim().is_empty() {
        errors.push("fixture_set_id must be non-empty".to_owned());
    }
    if fixture_set.fixtures.is_empty() {
        errors.push("fixture set must include at least one fixture".to_owned());
    }

    let mut fixture_ids = BTreeSet::new();
    for fixture in &fixture_set.fixtures {
        validate_fixture(
            fixture,
            &mut fixture_ids,
            &mut classifications_seen,
            &mut input_kinds_seen,
            &mut safety_classes_seen,
            &mut evidence_tiers_seen,
            &mut errors,
        );
    }

    for required in REQUIRED_FIXTURE_CLASSIFICATIONS {
        if !classifications_seen.contains(&required) {
            errors.push(format!(
                "missing required fixture classification {required:?}"
            ));
        }
    }
    for required in REQUIRED_INPUT_KINDS {
        if !input_kinds_seen.contains(&required) {
            errors.push(format!("missing required input kind {required:?}"));
        }
    }

    ReadinessActionFixtureValidationReport {
        schema_version: READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION,
        validator_version: READINESS_ACTION_FIXTURE_VALIDATOR_VERSION,
        fixture_set_id: fixture_set.fixture_set_id.clone(),
        fixture_count: fixture_set.fixtures.len(),
        valid: errors.is_empty(),
        classifications_seen: classifications_seen.into_iter().collect(),
        input_kinds_seen: input_kinds_seen.into_iter().collect(),
        safety_classes_seen: safety_classes_seen.into_iter().collect(),
        evidence_tiers_seen: evidence_tiers_seen.into_iter().collect(),
        errors,
    }
}

fn readiness_action_dry_run_scenario(
    recommendation: &ReadinessActionRecommendation,
) -> ReadinessActionDryRunScenario {
    ReadinessActionDryRunScenario {
        scenario_id: format!("dry-run-{}", recommendation.action_id),
        action_id: recommendation.action_id.clone(),
        title: recommendation.title.clone(),
        safety_class: recommendation.safety_class,
        ack_required: recommendation.ack_required,
        evidence_tier: recommendation.evidence_tier,
        public_claim_effect: recommendation.public_claim_effect,
        controlling_bead: recommendation.controlling_bead.clone(),
        reproduction_command: recommendation.reproduction_command.clone(),
        diagnostic_count: recommendation.diagnostics.len(),
        dry_run_note: "planner report only; no reproduction command was executed".to_owned(),
    }
}

fn markdown_table_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveTrackerIndex<'a> {
    issues: Vec<&'a ReadinessActionTrackerIssue>,
    normalized_titles: BTreeMap<String, &'a ReadinessActionTrackerIssue>,
}

impl<'a> ActiveTrackerIndex<'a> {
    fn new(issues: &'a [ReadinessActionTrackerIssue]) -> Self {
        let mut active_issues = Vec::new();
        let mut normalized_titles = BTreeMap::new();

        for issue in issues {
            if !is_active_tracker_status(&issue.status) {
                continue;
            }
            active_issues.push(issue);
            normalized_titles.insert(normalized_title(&issue.title), issue);
        }

        Self {
            issues: active_issues,
            normalized_titles,
        }
    }

    fn duplicate_for(
        &self,
        recommendation: &ReadinessActionRecommendation,
    ) -> Option<&'a ReadinessActionTrackerIssue> {
        if let Some(issue) = self
            .issues
            .iter()
            .copied()
            .find(|issue| issue.issue_id == recommendation.controlling_bead)
        {
            return Some(issue);
        }
        self.normalized_titles
            .get(&normalized_title(&recommendation.title))
            .copied()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScoredReadinessAction {
    rank: ReadinessActionRank,
    recommendation: ReadinessActionRecommendation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ReadinessActionRank {
    safety_rank: u8,
    input_penalty: u8,
    public_claim_rank: u8,
    evidence_rank: u8,
    ack_rank: u8,
    controlling_bead: String,
    action_id: String,
    title: String,
}

impl ReadinessActionRank {
    fn for_recommendation(
        recommendation: &ReadinessActionRecommendation,
        input_penalty: u8,
    ) -> Self {
        Self {
            safety_rank: safety_rank(recommendation.safety_class),
            input_penalty,
            public_claim_rank: public_claim_rank(recommendation.public_claim_effect),
            evidence_rank: evidence_rank(recommendation.evidence_tier),
            ack_rank: u8::from(recommendation.ack_required),
            controlling_bead: recommendation.controlling_bead.clone(),
            action_id: recommendation.action_id.clone(),
            title: recommendation.title.clone(),
        }
    }
}

fn merge_source_inputs(
    source_inputs: &mut BTreeMap<String, ReadinessActionInput>,
    new_inputs: &[ReadinessActionInput],
) {
    for input in new_inputs {
        let key = source_input_key(input);
        source_inputs
            .entry(key)
            .and_modify(|existing| {
                if input_state_penalty(input.state) > input_state_penalty(existing.state) {
                    *existing = input.clone();
                }
            })
            .or_insert_with(|| input.clone());
    }
}

fn input_state_diagnostics(inputs: &[ReadinessActionInput]) -> Vec<ReadinessActionDiagnostic> {
    let mut diagnostics = Vec::new();
    for input in inputs {
        if !input.required || is_ready_input_state(input.state) {
            continue;
        }
        diagnostics.push(ReadinessActionDiagnostic {
            diagnostic_id: format!(
                "planner-input-{}-{}",
                input.input_id,
                input_state_label(input.state)
            ),
            severity: input_state_severity(input.state),
            source_kind: input.kind,
            source_path: Some(input.path.clone()),
            message: format!(
                "Required {} input {} is {}.",
                input_kind_label(input.kind),
                input.input_id,
                input_state_label(input.state)
            ),
            remediation: input_state_remediation(input.state).to_owned(),
            stale_age_days: None,
            freshness_ttl_days: None,
        });
    }
    diagnostics.sort_by(|left, right| left.diagnostic_id.cmp(&right.diagnostic_id));
    diagnostics
}

fn append_missing_input_diagnostics(
    recommendation: &mut ReadinessActionRecommendation,
    input_diagnostics: &[ReadinessActionDiagnostic],
) {
    let mut existing_ids: BTreeSet<String> = recommendation
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.diagnostic_id.clone())
        .collect();

    for diagnostic in input_diagnostics {
        if existing_ids.insert(diagnostic.diagnostic_id.clone()) {
            recommendation.diagnostics.push(diagnostic.clone());
        }
    }
    recommendation
        .diagnostics
        .sort_by(|left, right| left.diagnostic_id.cmp(&right.diagnostic_id));
}

fn apply_fail_closed_guards(
    recommendation: &mut ReadinessActionRecommendation,
    inputs: &[ReadinessActionInput],
) {
    apply_input_state_guards(recommendation, inputs);
    for boundary in guard_boundaries(recommendation) {
        apply_boundary_guard(recommendation, inputs, boundary);
    }
    apply_smoke_evidence_guard(recommendation);
    enforce_ack_requirement(recommendation);
    recommendation
        .diagnostics
        .sort_by(|left, right| left.diagnostic_id.cmp(&right.diagnostic_id));
}

fn apply_input_state_guards(
    recommendation: &mut ReadinessActionRecommendation,
    inputs: &[ReadinessActionInput],
) {
    for input in inputs {
        if !input.required {
            continue;
        }

        match input.state {
            ReadinessActionInputState::Present | ReadinessActionInputState::NotApplicable => {}
            ReadinessActionInputState::Stale => {
                if is_upgrade_eligible(recommendation.public_claim_effect)
                    || is_no_change_public_claim(recommendation.public_claim_effect)
                {
                    recommendation.public_claim_effect = PublicClaimEffect::DowngradeRequired;
                }
            }
            ReadinessActionInputState::Missing => {
                if is_upgrade_eligible(recommendation.public_claim_effect) {
                    recommendation.public_claim_effect = PublicClaimEffect::BlockUpgrade;
                }
            }
            ReadinessActionInputState::PermissionRequired => {
                enforce_minimum_safety_class(
                    recommendation,
                    ReadinessActionSafetyClass::Permissioned,
                );
                if is_upgrade_eligible(recommendation.public_claim_effect) {
                    recommendation.public_claim_effect = PublicClaimEffect::BlockUpgrade;
                }
            }
            ReadinessActionInputState::Contradictory => {
                recommendation.safety_class = ReadinessActionSafetyClass::Impossible;
                recommendation.ack_required = false;
                recommendation.public_claim_effect = PublicClaimEffect::BlockUpgrade;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ReadinessActionGuardBoundary {
    XfstestsRealRun,
    LargeHostSwarm,
    WritebackCacheUpgrade,
    MountedMutation,
    RepairWriteback,
}

impl ReadinessActionGuardBoundary {
    const fn required_safety_class(self) -> ReadinessActionSafetyClass {
        match self {
            Self::XfstestsRealRun | Self::LargeHostSwarm | Self::WritebackCacheUpgrade => {
                ReadinessActionSafetyClass::Permissioned
            }
            Self::MountedMutation | Self::RepairWriteback => {
                ReadinessActionSafetyClass::Destructive
            }
        }
    }

    const fn source_kind(self) -> ReadinessActionInputKind {
        match self {
            Self::XfstestsRealRun | Self::MountedMutation => {
                ReadinessActionInputKind::OperationalReadinessReport
            }
            Self::LargeHostSwarm => ReadinessActionInputKind::HostCapabilityArtifact,
            Self::WritebackCacheUpgrade | Self::RepairWriteback => {
                ReadinessActionInputKind::ProofBundleReport
            }
        }
    }

    const fn diagnostic_stem(self) -> &'static str {
        match self {
            Self::XfstestsRealRun => "xfstests-real-run",
            Self::LargeHostSwarm => "large-host-swarm",
            Self::WritebackCacheUpgrade => "writeback-cache-upgrade",
            Self::MountedMutation => "mounted-mutation",
            Self::RepairWriteback => "repair-writeback",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::XfstestsRealRun => "xfstests real run",
            Self::LargeHostSwarm => "large-host swarm campaign",
            Self::WritebackCacheUpgrade => "writeback-cache upgrade",
            Self::MountedMutation => "mounted mutation",
            Self::RepairWriteback => "repair writeback",
        }
    }
}

fn guard_boundaries(
    recommendation: &ReadinessActionRecommendation,
) -> Vec<ReadinessActionGuardBoundary> {
    let text = guard_search_text(recommendation);
    let compact_text = normalized_title(&text);
    let mut boundaries = Vec::new();

    if text.contains("xfstests") || text.contains("xfstests_real_run_ack") {
        boundaries.push(ReadinessActionGuardBoundary::XfstestsRealRun);
    }
    if text.contains("swarm") || compact_text.contains("largehost") {
        boundaries.push(ReadinessActionGuardBoundary::LargeHostSwarm);
    }
    if compact_text.contains("writebackcache") {
        boundaries.push(ReadinessActionGuardBoundary::WritebackCacheUpgrade);
    }
    if compact_text.contains("mountedmutation") || text.contains("scratch_mnt") {
        boundaries.push(ReadinessActionGuardBoundary::MountedMutation);
    }
    if compact_text.contains("repairwriteback") {
        boundaries.push(ReadinessActionGuardBoundary::RepairWriteback);
    }

    boundaries.sort_unstable();
    boundaries.dedup();
    boundaries
}

fn guard_search_text(recommendation: &ReadinessActionRecommendation) -> String {
    format!(
        "{} {} {} {}",
        recommendation.action_id,
        recommendation.title,
        recommendation.reproduction_command,
        recommendation.rationale
    )
    .to_ascii_lowercase()
}

fn apply_boundary_guard(
    recommendation: &mut ReadinessActionRecommendation,
    inputs: &[ReadinessActionInput],
    boundary: ReadinessActionGuardBoundary,
) {
    if enforce_minimum_safety_class(recommendation, boundary.required_safety_class()) {
        push_guard_diagnostic(
            recommendation,
            &format!("planner-{}-safety-boundary", boundary.diagnostic_stem()),
            ReadinessActionDiagnosticSeverity::Warning,
            boundary.source_kind(),
            first_input_path(inputs, boundary.source_kind()),
            &format!(
                "{} is permission-boundary work and cannot remain local-safe.",
                boundary.label()
            ),
            "keep the action dry-run-only until explicit operator authorization is present",
        );
    }

    if boundary_requires_authoritative_evidence(boundary)
        && !is_authoritative_evidence_tier(recommendation.evidence_tier)
        && is_upgrade_eligible(recommendation.public_claim_effect)
    {
        recommendation.public_claim_effect = PublicClaimEffect::BlockUpgrade;
        push_guard_diagnostic(
            recommendation,
            &format!(
                "planner-{}-authoritative-evidence-required",
                boundary.diagnostic_stem()
            ),
            ReadinessActionDiagnosticSeverity::Error,
            boundary.source_kind(),
            first_input_path(inputs, boundary.source_kind()),
            &format!(
                "{} requires real authoritative evidence before upgrading public claims.",
                boundary.label()
            ),
            "publish real-run artifacts before changing public readiness wording",
        );
    }

    match boundary {
        ReadinessActionGuardBoundary::XfstestsRealRun => {
            apply_xfstests_real_run_guard(recommendation, inputs);
        }
        ReadinessActionGuardBoundary::LargeHostSwarm => {
            apply_large_host_swarm_guard(recommendation, inputs);
        }
        ReadinessActionGuardBoundary::WritebackCacheUpgrade
        | ReadinessActionGuardBoundary::MountedMutation
        | ReadinessActionGuardBoundary::RepairWriteback => {}
    }
}

const fn boundary_requires_authoritative_evidence(boundary: ReadinessActionGuardBoundary) -> bool {
    matches!(
        boundary,
        ReadinessActionGuardBoundary::XfstestsRealRun
            | ReadinessActionGuardBoundary::LargeHostSwarm
            | ReadinessActionGuardBoundary::WritebackCacheUpgrade
            | ReadinessActionGuardBoundary::MountedMutation
            | ReadinessActionGuardBoundary::RepairWriteback
    )
}

fn apply_xfstests_real_run_guard(
    recommendation: &mut ReadinessActionRecommendation,
    inputs: &[ReadinessActionInput],
) {
    if !has_present_input_kind(inputs, ReadinessActionInputKind::OperationalReadinessReport) {
        recommendation.public_claim_effect = PublicClaimEffect::BlockUpgrade;
        push_guard_diagnostic(
            recommendation,
            "planner-xfstests-real-run-evidence-missing",
            ReadinessActionDiagnosticSeverity::Error,
            ReadinessActionInputKind::OperationalReadinessReport,
            first_input_path(inputs, ReadinessActionInputKind::OperationalReadinessReport),
            "No current xfstests real-run report is present for this action.",
            "capture pass/fail/not-run artifacts before upgrading xfstests readiness claims",
        );
    }

    if !recommendation
        .reproduction_command
        .contains("XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices")
    {
        push_guard_diagnostic(
            recommendation,
            "planner-xfstests-real-run-ack-token-missing",
            ReadinessActionDiagnosticSeverity::Error,
            ReadinessActionInputKind::OperationalReadinessReport,
            first_input_path(inputs, ReadinessActionInputKind::OperationalReadinessReport),
            "The xfstests command is missing the explicit real-run acknowledgement token.",
            "include the exact xfstests mutation acknowledgement before any real run",
        );
    }
}

fn apply_large_host_swarm_guard(
    recommendation: &mut ReadinessActionRecommendation,
    inputs: &[ReadinessActionInput],
) {
    if !recommendation
        .reproduction_command
        .contains("FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host")
    {
        if is_upgrade_eligible(recommendation.public_claim_effect) {
            recommendation.public_claim_effect = PublicClaimEffect::BlockUpgrade;
        }
        push_guard_diagnostic(
            recommendation,
            "planner-large-host-swarm-ack-token-missing",
            ReadinessActionDiagnosticSeverity::Error,
            ReadinessActionInputKind::HostCapabilityArtifact,
            first_input_path(inputs, ReadinessActionInputKind::HostCapabilityArtifact),
            "The large-host swarm command is missing the explicit real-run acknowledgement token.",
            "include the exact large-host swarm acknowledgement before any real run",
        );
    }

    if !has_present_input_kind(inputs, ReadinessActionInputKind::HostCapabilityArtifact) {
        recommendation.public_claim_effect = PublicClaimEffect::DowngradeRequired;
        push_guard_diagnostic(
            recommendation,
            "planner-large-host-capability-missing",
            ReadinessActionDiagnosticSeverity::Error,
            ReadinessActionInputKind::HostCapabilityArtifact,
            first_input_path(inputs, ReadinessActionInputKind::HostCapabilityArtifact),
            "No present large-host capability artifact backs this swarm action.",
            "publish host capability proof before treating large-host evidence as authoritative",
        );
    }
}

fn apply_smoke_evidence_guard(recommendation: &mut ReadinessActionRecommendation) {
    if is_smoke_evidence_tier(recommendation.evidence_tier)
        && is_upgrade_eligible(recommendation.public_claim_effect)
    {
        recommendation.public_claim_effect = PublicClaimEffect::BlockUpgrade;
        push_guard_diagnostic(
            recommendation,
            "planner-smoke-evidence-blocks-public-upgrade",
            ReadinessActionDiagnosticSeverity::Error,
            ReadinessActionInputKind::ProofBundleReport,
            None,
            "Smoke evidence cannot upgrade public readiness claims.",
            "replace smoke evidence with real-run or authoritative artifacts before upgrading claims",
        );
    }
}

fn enforce_ack_requirement(recommendation: &mut ReadinessActionRecommendation) {
    if !requires_ack(recommendation.safety_class) || recommendation.ack_required {
        return;
    }

    recommendation.ack_required = true;
    push_guard_diagnostic(
        recommendation,
        "planner-permission-boundary-ack-required",
        ReadinessActionDiagnosticSeverity::Warning,
        ReadinessActionInputKind::ReleaseGatePolicy,
        None,
        "Permissioned or destructive readiness actions require explicit acknowledgement.",
        "keep the action blocked until explicit operator authorization is present",
    );
}

fn enforce_minimum_safety_class(
    recommendation: &mut ReadinessActionRecommendation,
    minimum: ReadinessActionSafetyClass,
) -> bool {
    if safety_rank(recommendation.safety_class) >= safety_rank(minimum) {
        return false;
    }

    recommendation.safety_class = minimum;
    true
}

fn push_guard_diagnostic(
    recommendation: &mut ReadinessActionRecommendation,
    diagnostic_id: &str,
    severity: ReadinessActionDiagnosticSeverity,
    source_kind: ReadinessActionInputKind,
    source_path: Option<String>,
    message: &str,
    remediation: &str,
) {
    if recommendation
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.diagnostic_id == diagnostic_id)
    {
        return;
    }

    recommendation.diagnostics.push(ReadinessActionDiagnostic {
        diagnostic_id: diagnostic_id.to_owned(),
        severity,
        source_kind,
        source_path,
        message: message.to_owned(),
        remediation: remediation.to_owned(),
        stale_age_days: None,
        freshness_ttl_days: None,
    });
}

fn first_input_path(
    inputs: &[ReadinessActionInput],
    source_kind: ReadinessActionInputKind,
) -> Option<String> {
    inputs
        .iter()
        .find(|input| input.kind == source_kind)
        .map(|input| input.path.clone())
}

fn has_present_input_kind(
    inputs: &[ReadinessActionInput],
    source_kind: ReadinessActionInputKind,
) -> bool {
    inputs
        .iter()
        .any(|input| input.kind == source_kind && is_present_input_state(input.state))
}

fn report_input_penalty(inputs: &[ReadinessActionInput]) -> u8 {
    inputs
        .iter()
        .filter(|input| input.required)
        .map(|input| input_state_penalty(input.state))
        .max()
        .unwrap_or(0)
}

fn source_input_key(input: &ReadinessActionInput) -> String {
    format!(
        "{}:{}:{}",
        input_kind_label(input.kind),
        input.input_id,
        input.path
    )
}

fn normalized_title(title: &str) -> String {
    title
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_active_tracker_status(status: &str) -> bool {
    status.eq_ignore_ascii_case("open") || status.eq_ignore_ascii_case("in_progress")
}

const fn is_ready_input_state(state: ReadinessActionInputState) -> bool {
    matches!(
        state,
        ReadinessActionInputState::Present | ReadinessActionInputState::NotApplicable
    )
}

const fn is_not_applicable_input_state(state: ReadinessActionInputState) -> bool {
    matches!(state, ReadinessActionInputState::NotApplicable)
}

const fn is_present_input_state(state: ReadinessActionInputState) -> bool {
    matches!(state, ReadinessActionInputState::Present)
}

const fn is_smoke_evidence_tier(evidence_tier: ReadinessEvidenceTier) -> bool {
    matches!(evidence_tier, ReadinessEvidenceTier::Smoke)
}

const fn is_authoritative_evidence_tier(evidence_tier: ReadinessEvidenceTier) -> bool {
    matches!(evidence_tier, ReadinessEvidenceTier::Authoritative)
}

const fn is_upgrade_eligible(public_claim_effect: PublicClaimEffect) -> bool {
    matches!(public_claim_effect, PublicClaimEffect::UpgradeEligible)
}

const fn is_no_change_public_claim(public_claim_effect: PublicClaimEffect) -> bool {
    matches!(public_claim_effect, PublicClaimEffect::NoChange)
}

const fn input_state_penalty(state: ReadinessActionInputState) -> u8 {
    match state {
        ReadinessActionInputState::Present | ReadinessActionInputState::NotApplicable => 0,
        ReadinessActionInputState::Stale => 1,
        ReadinessActionInputState::Missing => 2,
        ReadinessActionInputState::PermissionRequired => 3,
        ReadinessActionInputState::Contradictory => 4,
    }
}

const fn safety_rank(safety_class: ReadinessActionSafetyClass) -> u8 {
    match safety_class {
        ReadinessActionSafetyClass::LocalSafe => 0,
        ReadinessActionSafetyClass::Permissioned => 2,
        ReadinessActionSafetyClass::Destructive => 3,
        ReadinessActionSafetyClass::Impossible => 4,
    }
}

const fn public_claim_rank(public_claim_effect: PublicClaimEffect) -> u8 {
    match public_claim_effect {
        PublicClaimEffect::DowngradeRequired => 0,
        PublicClaimEffect::BlockUpgrade => 1,
        PublicClaimEffect::NoChange => 2,
        PublicClaimEffect::UpgradeEligible => 3,
    }
}

const fn evidence_rank(evidence_tier: ReadinessEvidenceTier) -> u8 {
    match evidence_tier {
        ReadinessEvidenceTier::Authoritative => 0,
        ReadinessEvidenceTier::OperationalReadiness => 1,
        ReadinessEvidenceTier::ProofBundle => 2,
        ReadinessEvidenceTier::Smoke => 3,
        ReadinessEvidenceTier::TrackerOnly => 4,
    }
}

const fn input_state_severity(
    state: ReadinessActionInputState,
) -> ReadinessActionDiagnosticSeverity {
    match state {
        ReadinessActionInputState::Present | ReadinessActionInputState::NotApplicable => {
            ReadinessActionDiagnosticSeverity::Info
        }
        ReadinessActionInputState::Stale | ReadinessActionInputState::PermissionRequired => {
            ReadinessActionDiagnosticSeverity::Warning
        }
        ReadinessActionInputState::Missing | ReadinessActionInputState::Contradictory => {
            ReadinessActionDiagnosticSeverity::Error
        }
    }
}

const fn input_kind_label(kind: ReadinessActionInputKind) -> &'static str {
    match kind {
        ReadinessActionInputKind::BeadsJsonl => "beads_jsonl",
        ReadinessActionInputKind::ReleaseGatePolicy => "release_gate_policy",
        ReadinessActionInputKind::ProofBundleReport => "proof_bundle_report",
        ReadinessActionInputKind::OperationalReadinessReport => "operational_readiness_report",
        ReadinessActionInputKind::HostCapabilityArtifact => "host_capability_artifact",
        ReadinessActionInputKind::ClaimabilityPlanReport => "claimability_plan_report",
        ReadinessActionInputKind::RchProofLedger => "rch_proof_ledger",
    }
}

const fn input_state_label(state: ReadinessActionInputState) -> &'static str {
    match state {
        ReadinessActionInputState::Present => "present",
        ReadinessActionInputState::Missing => "missing",
        ReadinessActionInputState::Stale => "stale",
        ReadinessActionInputState::Contradictory => "contradictory",
        ReadinessActionInputState::PermissionRequired => "permission_required",
        ReadinessActionInputState::NotApplicable => "not_applicable",
    }
}

const fn input_state_remediation(state: ReadinessActionInputState) -> &'static str {
    match state {
        ReadinessActionInputState::Present | ReadinessActionInputState::NotApplicable => {
            "no remediation needed"
        }
        ReadinessActionInputState::Missing => "provide the missing artifact before acting",
        ReadinessActionInputState::Stale => "refresh the stale artifact before acting",
        ReadinessActionInputState::Contradictory => "resolve contradictory evidence before acting",
        ReadinessActionInputState::PermissionRequired => {
            "obtain explicit operator authorization before acting"
        }
    }
}

fn validate_fixture(
    fixture: &ReadinessActionAutopilotFixture,
    fixture_ids: &mut BTreeSet<String>,
    classifications_seen: &mut BTreeSet<ReadinessFixtureClassification>,
    input_kinds_seen: &mut BTreeSet<ReadinessActionInputKind>,
    safety_classes_seen: &mut BTreeSet<ReadinessActionSafetyClass>,
    evidence_tiers_seen: &mut BTreeSet<ReadinessEvidenceTier>,
    errors: &mut Vec<String>,
) {
    let fixture_label = if fixture.fixture_id.trim().is_empty() {
        "<missing-fixture-id>"
    } else {
        fixture.fixture_id.as_str()
    };

    if fixture.fixture_id.trim().is_empty() {
        errors.push("fixture_id must be non-empty".to_owned());
    }
    if !fixture_ids.insert(fixture.fixture_id.clone()) {
        errors.push(format!("duplicate fixture_id {}", fixture.fixture_id));
    }
    classifications_seen.insert(fixture.expected_classification);

    validate_report(
        fixture_label,
        &fixture.report,
        input_kinds_seen,
        safety_classes_seen,
        evidence_tiers_seen,
        errors,
    );
}

fn validate_report(
    fixture_label: &str,
    report: &ReadinessActionAutopilotReport,
    input_kinds_seen: &mut BTreeSet<ReadinessActionInputKind>,
    safety_classes_seen: &mut BTreeSet<ReadinessActionSafetyClass>,
    evidence_tiers_seen: &mut BTreeSet<ReadinessEvidenceTier>,
    errors: &mut Vec<String>,
) {
    if report.schema_version != READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION {
        errors.push(format!(
            "{fixture_label}: report schema_version {} must equal {READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION}",
            report.schema_version
        ));
    }
    if report.report_id.trim().is_empty() {
        errors.push(format!("{fixture_label}: report_id must be non-empty"));
    }
    if report.generated_at.trim().is_empty() {
        errors.push(format!("{fixture_label}: generated_at must be non-empty"));
    }
    if report.source_inputs.is_empty() {
        errors.push(format!(
            "{fixture_label}: source_inputs must include at least one input"
        ));
    }
    if report.recommendations.is_empty() {
        errors.push(format!(
            "{fixture_label}: recommendations must include at least one action"
        ));
    }

    validate_inputs(
        fixture_label,
        &report.source_inputs,
        input_kinds_seen,
        errors,
    );
    validate_recommendations(
        fixture_label,
        &report.recommendations,
        safety_classes_seen,
        evidence_tiers_seen,
        errors,
    );
}

fn validate_inputs(
    fixture_label: &str,
    inputs: &[ReadinessActionInput],
    input_kinds_seen: &mut BTreeSet<ReadinessActionInputKind>,
    errors: &mut Vec<String>,
) {
    let mut input_ids = BTreeSet::new();
    for input in inputs {
        if input.input_id.trim().is_empty() {
            errors.push(format!("{fixture_label}: input_id must be non-empty"));
        }
        if !input_ids.insert(input.input_id.clone()) {
            errors.push(format!(
                "{fixture_label}: duplicate input_id {}",
                input.input_id
            ));
        }
        if input.path.trim().is_empty() {
            errors.push(format!(
                "{fixture_label}: input {} path must be non-empty",
                input.input_id
            ));
        }
        if input.required && is_not_applicable_input_state(input.state) {
            errors.push(format!(
                "{fixture_label}: required input {} cannot be not_applicable",
                input.input_id
            ));
        }
        input_kinds_seen.insert(input.kind);
    }
}

fn validate_recommendations(
    fixture_label: &str,
    recommendations: &[ReadinessActionRecommendation],
    safety_classes_seen: &mut BTreeSet<ReadinessActionSafetyClass>,
    evidence_tiers_seen: &mut BTreeSet<ReadinessEvidenceTier>,
    errors: &mut Vec<String>,
) {
    let mut action_ids = BTreeSet::new();
    for recommendation in recommendations {
        validate_recommendation(
            fixture_label,
            recommendation,
            &mut action_ids,
            safety_classes_seen,
            evidence_tiers_seen,
            errors,
        );
    }
}

fn validate_recommendation(
    fixture_label: &str,
    recommendation: &ReadinessActionRecommendation,
    action_ids: &mut BTreeSet<String>,
    safety_classes_seen: &mut BTreeSet<ReadinessActionSafetyClass>,
    evidence_tiers_seen: &mut BTreeSet<ReadinessEvidenceTier>,
    errors: &mut Vec<String>,
) {
    if recommendation.action_id.trim().is_empty() {
        errors.push(format!("{fixture_label}: action_id must be non-empty"));
    }
    if !action_ids.insert(recommendation.action_id.clone()) {
        errors.push(format!(
            "{fixture_label}: duplicate action_id {}",
            recommendation.action_id
        ));
    }
    if recommendation.title.trim().is_empty() {
        errors.push(format!(
            "{fixture_label}: action {} title must be non-empty",
            recommendation.action_id
        ));
    }
    if !recommendation.controlling_bead.starts_with("bd-") {
        errors.push(format!(
            "{fixture_label}: action {} controlling_bead must start with bd-",
            recommendation.action_id
        ));
    }
    if recommendation
        .mail_thread_id
        .as_ref()
        .is_some_and(|thread| thread.trim().is_empty())
    {
        errors.push(format!(
            "{fixture_label}: action {} mail_thread_id must be non-empty when supplied",
            recommendation.action_id
        ));
    }
    if recommendation
        .reservation_artifact_path
        .as_ref()
        .is_some_and(|path| path.trim().is_empty())
    {
        errors.push(format!(
            "{fixture_label}: action {} reservation_artifact_path must be non-empty when supplied",
            recommendation.action_id
        ));
    }
    if recommendation
        .proof_artifact_path
        .as_ref()
        .is_some_and(|path| path.trim().is_empty())
    {
        errors.push(format!(
            "{fixture_label}: action {} proof_artifact_path must be non-empty when supplied",
            recommendation.action_id
        ));
    }
    if recommendation
        .safe_next_commands
        .iter()
        .any(|command| command.trim().is_empty())
    {
        errors.push(format!(
            "{fixture_label}: action {} safe_next_commands must not contain empty commands",
            recommendation.action_id
        ));
    }
    if recommendation.reproduction_command.trim().is_empty() {
        errors.push(format!(
            "{fixture_label}: action {} missing reproduction_command",
            recommendation.action_id
        ));
    }
    if recommendation.rationale.trim().is_empty() {
        errors.push(format!(
            "{fixture_label}: action {} rationale must be non-empty",
            recommendation.action_id
        ));
    }
    if requires_ack(recommendation.safety_class) && !recommendation.ack_required {
        errors.push(format!(
            "{fixture_label}: action {} requires ack for {:?}",
            recommendation.action_id, recommendation.safety_class
        ));
    }
    if recommendation.safety_class == ReadinessActionSafetyClass::Impossible
        && recommendation.ack_required
    {
        errors.push(format!(
            "{fixture_label}: action {} cannot require ack for Impossible",
            recommendation.action_id
        ));
    }
    if recommendation.safety_class == ReadinessActionSafetyClass::Impossible
        && !recommendation
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == ReadinessActionDiagnosticSeverity::Error)
    {
        errors.push(format!(
            "{fixture_label}: action {} must include an error diagnostic for Impossible",
            recommendation.action_id
        ));
    }
    if is_smoke_evidence_tier(recommendation.evidence_tier)
        && is_upgrade_eligible(recommendation.public_claim_effect)
    {
        errors.push(format!(
            "{fixture_label}: action {} cannot upgrade public claims from smoke evidence",
            recommendation.action_id
        ));
    }
    if requires_diagnostics(recommendation.safety_class) && recommendation.diagnostics.is_empty() {
        errors.push(format!(
            "{fixture_label}: action {} must include diagnostics for {:?}",
            recommendation.action_id, recommendation.safety_class
        ));
    }

    validate_diagnostics(fixture_label, recommendation, errors);
    safety_classes_seen.insert(recommendation.safety_class);
    evidence_tiers_seen.insert(recommendation.evidence_tier);
}

fn validate_diagnostics(
    fixture_label: &str,
    recommendation: &ReadinessActionRecommendation,
    errors: &mut Vec<String>,
) {
    let mut diagnostic_ids = BTreeSet::new();
    for diagnostic in &recommendation.diagnostics {
        if diagnostic.diagnostic_id.trim().is_empty() {
            errors.push(format!(
                "{fixture_label}: action {} diagnostic_id must be non-empty",
                recommendation.action_id
            ));
        }
        if !diagnostic_ids.insert(diagnostic.diagnostic_id.clone()) {
            errors.push(format!(
                "{fixture_label}: action {} duplicate diagnostic_id {}",
                recommendation.action_id, diagnostic.diagnostic_id
            ));
        }
        if diagnostic.message.trim().is_empty() {
            errors.push(format!(
                "{fixture_label}: diagnostic {} message must be non-empty",
                diagnostic.diagnostic_id
            ));
        }
        if diagnostic.remediation.trim().is_empty() {
            errors.push(format!(
                "{fixture_label}: diagnostic {} remediation must be non-empty",
                diagnostic.diagnostic_id
            ));
        }
        if diagnostic.stale_age_days.is_some() != diagnostic.freshness_ttl_days.is_some() {
            errors.push(format!(
                "{fixture_label}: diagnostic {} stale age and ttl must be provided together",
                diagnostic.diagnostic_id
            ));
        }
    }
}

const fn requires_ack(safety_class: ReadinessActionSafetyClass) -> bool {
    matches!(
        safety_class,
        ReadinessActionSafetyClass::Permissioned | ReadinessActionSafetyClass::Destructive
    )
}

const fn requires_diagnostics(safety_class: ReadinessActionSafetyClass) -> bool {
    matches!(
        safety_class,
        ReadinessActionSafetyClass::Permissioned
            | ReadinessActionSafetyClass::Destructive
            | ReadinessActionSafetyClass::Impossible
    )
}

fn input(
    input_id: &str,
    kind: ReadinessActionInputKind,
    path: &str,
    state: ReadinessActionInputState,
) -> ReadinessActionInput {
    ReadinessActionInput {
        input_id: input_id.to_owned(),
        kind,
        path: path.to_owned(),
        required: true,
        state,
        schema_version: Some(READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION),
        digest: None,
    }
}

fn diagnostic(
    diagnostic_id: &str,
    severity: ReadinessActionDiagnosticSeverity,
    source_kind: ReadinessActionInputKind,
    source_path: Option<&str>,
    message: &str,
    remediation: &str,
) -> ReadinessActionDiagnostic {
    ReadinessActionDiagnostic {
        diagnostic_id: diagnostic_id.to_owned(),
        severity,
        source_kind,
        source_path: source_path.map(str::to_owned),
        message: message.to_owned(),
        remediation: remediation.to_owned(),
        stale_age_days: None,
        freshness_ttl_days: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};

    #[test]
    fn default_fixture_set_covers_required_schema_surface() {
        let fixture_set = default_readiness_action_autopilot_fixture_set();
        let report = validate_readiness_action_fixture_set(&fixture_set);

        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.fixture_count, 5);
        assert_eq!(
            report.classifications_seen,
            REQUIRED_FIXTURE_CLASSIFICATIONS
        );
        assert_eq!(report.input_kinds_seen, REQUIRED_INPUT_KINDS);
        assert_eq!(
            report.safety_classes_seen,
            vec![
                ReadinessActionSafetyClass::LocalSafe,
                ReadinessActionSafetyClass::Permissioned,
                ReadinessActionSafetyClass::Impossible,
            ]
        );
    }

    #[test]
    fn readiness_action_fixture_validation_report_json_shape() -> serde_json::Result<()> {
        let fixture_set = default_readiness_action_autopilot_fixture_set();
        let report = validate_readiness_action_fixture_set(&fixture_set);
        assert!(report.valid, "{:?}", report.errors);

        let json = serde_json::to_string_pretty(&report)?;
        let decoded: ReadinessActionFixtureValidationReport = serde_json::from_str(&json)?;
        assert_eq!(decoded, report);

        let shape = serde_json::json!({
            "schema_version": report.schema_version,
            "validator_version": report.validator_version,
            "fixture_set_id": report.fixture_set_id,
            "fixture_count": report.fixture_count,
            "valid": report.valid,
            "classifications_seen": report.classifications_seen,
            "input_kinds_seen": report.input_kinds_seen,
            "safety_classes_seen": report.safety_classes_seen,
            "evidence_tiers_seen": report.evidence_tiers_seen,
            "error_count": report.errors.len(),
        });
        insta::assert_snapshot!(
            "readiness_action_fixture_validation_report_json_shape",
            serde_json::to_string_pretty(&shape)?
        );
        Ok(())
    }

    #[test]
    fn readiness_action_autopilot_report_json_shape() -> serde_json::Result<()> {
        let reports = default_source_reports();
        let json = serde_json::to_string_pretty(&reports)?;
        let decoded: Vec<ReadinessActionAutopilotReport> = serde_json::from_str(&json)?;

        assert_eq!(decoded, reports);
        assert_eq!(
            decoded.len(),
            default_readiness_action_autopilot_fixture_set()
                .fixtures
                .len()
        );
        assert!(
            decoded
                .iter()
                .all(|report| report.schema_version == READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION)
        );

        let report_rows = decoded
            .iter()
            .map(|report| {
                let input_rows = report
                    .source_inputs
                    .iter()
                    .map(|input| {
                        serde_json::json!({
                            "input_id": &input.input_id,
                            "kind": input.kind,
                            "state": input.state,
                            "required": input.required,
                            "has_schema_version": input.schema_version.is_some(),
                            "has_digest": input.digest.is_some(),
                        })
                    })
                    .collect::<Vec<_>>();
                let recommendation_rows = report
                    .recommendations
                    .iter()
                    .map(|recommendation| {
                        let diagnostic_rows = recommendation
                            .diagnostics
                            .iter()
                            .map(|diagnostic| {
                                serde_json::json!({
                                    "diagnostic_id": &diagnostic.diagnostic_id,
                                    "severity": diagnostic.severity,
                                    "source_kind": diagnostic.source_kind,
                                    "has_source_path": diagnostic.source_path.is_some(),
                                    "has_stale_window": diagnostic.stale_age_days.is_some()
                                        && diagnostic.freshness_ttl_days.is_some(),
                                })
                            })
                            .collect::<Vec<_>>();
                        serde_json::json!({
                            "action_id": &recommendation.action_id,
                            "safety_class": recommendation.safety_class,
                            "controlling_bead": &recommendation.controlling_bead,
                            "evidence_tier": recommendation.evidence_tier,
                            "ack_required": recommendation.ack_required,
                            "public_claim_effect": recommendation.public_claim_effect,
                            "diagnostic_count": recommendation.diagnostics.len(),
                            "diagnostics": diagnostic_rows,
                        })
                    })
                    .collect::<Vec<_>>();

                serde_json::json!({
                    "report_id": &report.report_id,
                    "generated_at": &report.generated_at,
                    "source_input_count": report.source_inputs.len(),
                    "recommendation_count": report.recommendations.len(),
                    "source_inputs": input_rows,
                    "recommendations": recommendation_rows,
                })
            })
            .collect::<Vec<_>>();
        let shape = serde_json::json!({
            "schema_version": READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION,
            "report_count": decoded.len(),
            "report_ids": decoded
                .iter()
                .map(|report| report.report_id.as_str())
                .collect::<Vec<_>>(),
            "reports": report_rows,
        });

        insta::assert_snapshot!(
            "readiness_action_autopilot_report_json_shape",
            serde_json::to_string_pretty(&shape)?
        );
        Ok(())
    }

    #[test]
    fn fixtures_round_trip_with_stable_json() -> serde_json::Result<()> {
        let fixture_set = default_readiness_action_autopilot_fixture_set();
        let first = serde_json::to_string_pretty(&fixture_set)?;
        let reparsed: ReadinessActionAutopilotFixtureSet = serde_json::from_str(&first)?;
        let second = serde_json::to_string_pretty(&reparsed)?;

        assert_eq!(fixture_set, reparsed);
        assert_eq!(first, second);
        assert!(
            first.contains(
                "\"fixture_set_id\": \"frankenfs_readiness_action_autopilot_fixtures_v1\""
            )
        );
        Ok(())
    }

    #[test]
    fn validation_rejects_missing_required_fields() -> Result<()> {
        let mut fixture_set = default_readiness_action_autopilot_fixture_set();
        let fixture = fixture_set
            .fixtures
            .first_mut()
            .context("default fixture set has a first fixture")?;
        fixture.report.source_inputs.clear();
        fixture
            .report
            .recommendations
            .first_mut()
            .context("default first fixture has a recommendation")?
            .reproduction_command
            .clear();

        let report = validate_readiness_action_fixture_set(&fixture_set);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("source_inputs must include at least one input"))
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("missing reproduction_command"))
        );
        Ok(())
    }

    #[test]
    fn validation_rejects_destructive_actions_without_diagnostics() -> Result<()> {
        let mut fixture_set = default_readiness_action_autopilot_fixture_set();
        let recommendation = fixture_set
            .fixtures
            .first_mut()
            .and_then(|fixture| fixture.report.recommendations.first_mut())
            .context("default fixture set has a first recommendation")?;
        recommendation.safety_class = ReadinessActionSafetyClass::Destructive;
        recommendation.ack_required = true;
        recommendation.diagnostics.clear();

        let report = validate_readiness_action_fixture_set(&fixture_set);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| { error.contains("must include diagnostics for Destructive") })
        );
        Ok(())
    }

    #[test]
    fn validation_rejects_impossible_actions_that_request_ack() -> Result<()> {
        let mut fixture_set = default_readiness_action_autopilot_fixture_set();
        let recommendation = fixture_set
            .fixtures
            .first_mut()
            .and_then(|fixture| fixture.report.recommendations.first_mut())
            .context("default fixture set has a first recommendation")?;
        recommendation.safety_class = ReadinessActionSafetyClass::Impossible;
        recommendation.ack_required = true;
        recommendation.diagnostics = vec![diagnostic(
            "impossible-action-diagnostic",
            ReadinessActionDiagnosticSeverity::Error,
            ReadinessActionInputKind::ReleaseGatePolicy,
            None,
            "The action is impossible until contradictory evidence is resolved.",
            "resolve the contradiction instead of requesting operator authorization",
        )];

        let report = validate_readiness_action_fixture_set(&fixture_set);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| { error.contains("cannot require ack for Impossible") })
        );
        Ok(())
    }

    #[test]
    fn validation_rejects_impossible_actions_without_error_diagnostics() -> Result<()> {
        let mut fixture_set = default_readiness_action_autopilot_fixture_set();
        let recommendation = fixture_set
            .fixtures
            .first_mut()
            .and_then(|fixture| fixture.report.recommendations.first_mut())
            .context("default fixture set has a first recommendation")?;
        recommendation.safety_class = ReadinessActionSafetyClass::Impossible;
        recommendation.ack_required = false;
        recommendation.diagnostics = vec![diagnostic(
            "impossible-action-warning",
            ReadinessActionDiagnosticSeverity::Warning,
            ReadinessActionInputKind::ReleaseGatePolicy,
            None,
            "The action is blocked by unresolved evidence.",
            "resolve the blocker before continuing",
        )];

        let report = validate_readiness_action_fixture_set(&fixture_set);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| { error.contains("must include an error diagnostic for Impossible") })
        );
        Ok(())
    }

    #[test]
    fn planner_ranks_local_safe_work_before_permissioned_actions() {
        let result = plan_readiness_actions(&planning_input(default_source_reports(), Vec::new()));
        let action_ids: Vec<&str> = result
            .report
            .recommendations
            .iter()
            .map(|recommendation| recommendation.action_id.as_str())
            .collect();

        assert_eq!(
            action_ids,
            vec![
                "preserve-degraded-rch-proof-ledger",
                "preserve-foreign-owner-handoff",
                "claim-source-aware-task",
                "define-readiness-action-schema",
                "block-permission-gated-claimability-row",
                "run-permissioned-xfstests-baseline",
                "refresh-large-host-swarm-campaign",
                "refuse-contradictory-readiness-upgrade",
            ]
        );
        assert_eq!(
            result.suppressed_duplicates,
            [] as [ReadinessActionSuppressedDuplicate; 0]
        );
    }

    #[test]
    fn planner_suppresses_actions_already_represented_by_active_beads() {
        let result = plan_readiness_actions(&planning_input(
            default_source_reports(),
            vec![
                active_issue(
                    "bd-rchk3.3",
                    "Execute the fresh xfstests baseline and publish artifacts",
                ),
                active_issue(
                    "bd-rchk0.53.8",
                    "Run authoritative swarm responsiveness campaign on permissioned large host",
                ),
            ],
        ));
        let action_ids: Vec<&str> = result
            .report
            .recommendations
            .iter()
            .map(|recommendation| recommendation.action_id.as_str())
            .collect();
        let suppressed: Vec<(&str, &str)> = result
            .suppressed_duplicates
            .iter()
            .map(|duplicate| {
                (
                    duplicate.controlling_bead.as_str(),
                    duplicate.action_id.as_str(),
                )
            })
            .collect();

        assert_eq!(
            action_ids,
            vec![
                "preserve-degraded-rch-proof-ledger",
                "preserve-foreign-owner-handoff",
                "claim-source-aware-task",
                "define-readiness-action-schema",
                "refuse-contradictory-readiness-upgrade",
            ]
        );
        assert_eq!(
            suppressed,
            vec![
                ("bd-rchk0.53.8", "refresh-large-host-swarm-campaign"),
                ("bd-rchk3.3", "block-permission-gated-claimability-row"),
                ("bd-rchk3.3", "run-permissioned-xfstests-baseline"),
            ]
        );
    }

    #[test]
    fn planner_adds_missing_input_diagnostics_to_recommendations() -> Result<()> {
        let result = plan_readiness_actions(&planning_input(default_source_reports(), Vec::new()));
        let xfstests = result
            .report
            .recommendations
            .iter()
            .find(|recommendation| recommendation.action_id == "run-permissioned-xfstests-baseline")
            .context("xfstests recommendation")?;
        let diagnostic_ids: Vec<&str> = xfstests
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.diagnostic_id.as_str())
            .collect();

        assert_eq!(
            diagnostic_ids,
            vec![
                "planner-input-operational-readiness-report-missing",
                "planner-xfstests-real-run-evidence-missing",
                "xfstests-real-run-ack-missing",
            ]
        );
        Ok(())
    }

    #[test]
    fn default_permissioned_reproduction_commands_point_to_existing_repo_scripts() -> Result<()> {
        let fixture_set = default_readiness_action_autopilot_fixture_set();
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

        for (action_id, expected_script, stale_script, required_ack) in [
            (
                "run-permissioned-xfstests-baseline",
                "scripts/e2e/ffs_xfstests_e2e.sh",
                "scripts/e2e/run_xfstests_baseline.sh",
                "XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices",
            ),
            (
                "refresh-large-host-swarm-campaign",
                "scripts/e2e/ffs_swarm_workload_harness_e2e.sh",
                "scripts/e2e/run_swarm_workload_campaign.sh",
                "FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host",
            ),
        ] {
            let recommendation = fixture_set
                .fixtures
                .iter()
                .flat_map(|fixture| fixture.report.recommendations.iter())
                .find(|recommendation| recommendation.action_id == action_id)
                .context("permissioned recommendation")?;

            assert!(
                recommendation
                    .reproduction_command
                    .contains(expected_script),
                "{action_id} command must point at {expected_script}"
            );
            assert!(
                !recommendation.reproduction_command.contains(stale_script),
                "{action_id} command must not point at missing {stale_script}"
            );
            assert!(
                recommendation.reproduction_command.contains(required_ack),
                "{action_id} command must retain the explicit ack token"
            );
            assert!(
                repo_root.join(expected_script).is_file(),
                "{expected_script} must exist in this checkout"
            );
        }
        Ok(())
    }

    #[test]
    fn planner_preserves_claimability_and_rch_operator_evidence() -> Result<()> {
        let result = plan_readiness_actions(&planning_input(default_source_reports(), Vec::new()));
        let claim = planned_action(&result, "claim-source-aware-task")?;
        assert_eq!(claim.mail_thread_id.as_deref(), Some("bd-0chpv.5"));
        assert_eq!(
            claim.reservation_artifact_path.as_deref(),
            Some("artifacts/agent_mail/reservations/bd-0chpv.5.json")
        );
        assert!(
            claim
                .safe_next_commands
                .iter()
                .any(|command| command.contains("file_reservation_paths"))
        );

        let proof = planned_action(&result, "preserve-degraded-rch-proof-ledger")?;
        assert_eq!(proof.mail_thread_id.as_deref(), Some("bd-0chpv.4"));
        assert_eq!(
            proof.proof_artifact_path.as_deref(),
            Some("artifacts/rch/proof_ledgers/remote_success_artifact_warning.json")
        );
        assert_eq!(proof.public_claim_effect, PublicClaimEffect::NoChange);
        assert!(
            proof
                .safe_next_commands
                .iter()
                .any(|command| command.contains("[RCH] local fallback"))
        );
        Ok(())
    }

    #[test]
    fn advisory_planning_inputs_cannot_upgrade_public_claims() {
        let result = plan_readiness_actions(&planning_input(default_source_reports(), Vec::new()));
        let advisory_actions = [
            "claim-source-aware-task",
            "block-permission-gated-claimability-row",
            "preserve-foreign-owner-handoff",
            "preserve-degraded-rch-proof-ledger",
        ];

        for action_id in advisory_actions {
            let recommendation = result
                .report
                .recommendations
                .iter()
                .find(|recommendation| recommendation.action_id == action_id)
                .expect("advisory action exists");
            assert_ne!(
                recommendation.public_claim_effect,
                PublicClaimEffect::UpgradeEligible,
                "{action_id} must not upgrade public readiness"
            );
        }
        assert!(
            result
                .report
                .recommendations
                .iter()
                .all(|recommendation| recommendation.action_id != "claim-raw-bv-parent-epic")
        );
    }

    #[test]
    fn planner_downgrades_stale_evidence_public_claims() -> Result<()> {
        let mut recommendation = recommendation("upgrade-writeback-cache-claim");
        recommendation.title = "Upgrade writeback-cache readiness claim".to_owned();
        recommendation.evidence_tier = ReadinessEvidenceTier::ProofBundle;
        recommendation.public_claim_effect = PublicClaimEffect::UpgradeEligible;
        recommendation.reproduction_command =
            "cargo test -p ffs-harness writeback_cache_readiness".to_owned();

        let result = plan_readiness_actions(&planning_input(
            vec![report(
                vec![input(
                    "stale-proof-bundle",
                    ReadinessActionInputKind::ProofBundleReport,
                    "artifacts/proof_bundles/writeback_cache.json",
                    ReadinessActionInputState::Stale,
                )],
                vec![recommendation],
            )],
            Vec::new(),
        ));
        let planned = planned_action(&result, "upgrade-writeback-cache-claim")?;

        assert_eq!(
            planned.public_claim_effect,
            PublicClaimEffect::DowngradeRequired
        );
        assert!(planned.ack_required);
        assert_eq!(
            planned.safety_class,
            ReadinessActionSafetyClass::Permissioned
        );
        assert!(diagnostic_ids(planned).contains(&"planner-input-stale-proof-bundle-stale"));
        Ok(())
    }

    #[test]
    fn planner_blocks_missing_large_host_capability() -> Result<()> {
        let mut recommendation = recommendation("refresh-large-host-swarm-campaign");
        recommendation.title = "Refresh large-host swarm responsiveness evidence".to_owned();
        recommendation.evidence_tier = ReadinessEvidenceTier::Smoke;
        recommendation.public_claim_effect = PublicClaimEffect::UpgradeEligible;
        recommendation.reproduction_command =
            "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1 scripts/e2e/ffs_swarm_workload_harness_e2e.sh"
                .to_owned();

        let result = plan_readiness_actions(&planning_input(
            vec![report(
                vec![input(
                    "host-capability-manifest",
                    ReadinessActionInputKind::HostCapabilityArtifact,
                    "artifacts/hosts/large_host_capability.json",
                    ReadinessActionInputState::Missing,
                )],
                vec![recommendation],
            )],
            Vec::new(),
        ));
        let planned = planned_action(&result, "refresh-large-host-swarm-campaign")?;

        assert!(planned.ack_required);
        assert_eq!(
            planned.safety_class,
            ReadinessActionSafetyClass::Permissioned
        );
        assert_eq!(
            planned.public_claim_effect,
            PublicClaimEffect::DowngradeRequired
        );
        let diagnostic_ids = diagnostic_ids(planned);
        assert!(diagnostic_ids.contains(&"planner-input-host-capability-manifest-missing"));
        assert!(diagnostic_ids.contains(&"planner-large-host-capability-missing"));
        Ok(())
    }

    #[test]
    fn planner_blocks_large_host_swarm_without_ack_token() -> Result<()> {
        let mut recommendation = recommendation("refresh-large-host-swarm-campaign");
        recommendation.title = "Refresh large-host swarm responsiveness evidence".to_owned();
        recommendation.evidence_tier = ReadinessEvidenceTier::Authoritative;
        recommendation.public_claim_effect = PublicClaimEffect::UpgradeEligible;
        recommendation.reproduction_command =
            "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1 scripts/e2e/ffs_swarm_workload_harness_e2e.sh"
                .to_owned();

        let result = plan_readiness_actions(&planning_input(
            vec![report(
                vec![input(
                    "host-capability-manifest",
                    ReadinessActionInputKind::HostCapabilityArtifact,
                    "artifacts/hosts/large_host_capability.json",
                    ReadinessActionInputState::Present,
                )],
                vec![recommendation],
            )],
            Vec::new(),
        ));
        let planned = planned_action(&result, "refresh-large-host-swarm-campaign")?;

        assert!(planned.ack_required);
        assert_eq!(
            planned.safety_class,
            ReadinessActionSafetyClass::Permissioned
        );
        assert_eq!(planned.public_claim_effect, PublicClaimEffect::BlockUpgrade);
        let diagnostic_ids = diagnostic_ids(planned);
        assert!(diagnostic_ids.contains(&"planner-large-host-swarm-ack-token-missing"));
        assert!(!diagnostic_ids.contains(&"planner-large-host-capability-missing"));
        Ok(())
    }

    #[test]
    fn planner_refuses_contradictory_artifacts() -> Result<()> {
        let mut recommendation = recommendation("upgrade-release-gate-claim");
        recommendation.evidence_tier = ReadinessEvidenceTier::ProofBundle;
        recommendation.public_claim_effect = PublicClaimEffect::UpgradeEligible;

        let result = plan_readiness_actions(&planning_input(
            vec![report(
                vec![input(
                    "release-gate-proof",
                    ReadinessActionInputKind::ProofBundleReport,
                    "artifacts/proof_bundles/release_gate.json",
                    ReadinessActionInputState::Contradictory,
                )],
                vec![recommendation],
            )],
            Vec::new(),
        ));
        let planned = planned_action(&result, "upgrade-release-gate-claim")?;

        assert!(!planned.ack_required);
        assert_eq!(planned.safety_class, ReadinessActionSafetyClass::Impossible);
        assert_eq!(planned.public_claim_effect, PublicClaimEffect::BlockUpgrade);
        assert!(
            diagnostic_ids(planned).contains(&"planner-input-release-gate-proof-contradictory")
        );
        Ok(())
    }

    #[test]
    fn planner_marks_permissioned_and_destructive_boundaries_ack_required() -> Result<()> {
        let mut writeback = recommendation("upgrade-writeback-cache");
        writeback.title = "Upgrade writeback-cache mode".to_owned();
        writeback.reproduction_command = "cargo test -p ffs-harness writeback_cache".to_owned();

        let mut mounted_mutation = recommendation("run-mounted-mutation");
        mounted_mutation.title = "Run mounted mutation validation".to_owned();
        mounted_mutation.reproduction_command =
            "SCRATCH_MNT=/mnt/ffs-test scripts/e2e/run_mounted_mutation.sh".to_owned();

        let mut repair_writeback = recommendation("publish-repair-writeback-claim");
        repair_writeback.title = "Publish repair-writeback claim".to_owned();
        repair_writeback.reproduction_command =
            "cargo test -p ffs-harness repair_writeback".to_owned();

        let result = plan_readiness_actions(&planning_input(
            vec![report(
                vec![input(
                    "proof-bundle-report",
                    ReadinessActionInputKind::ProofBundleReport,
                    "artifacts/proof_bundles/writeback.json",
                    ReadinessActionInputState::Present,
                )],
                vec![writeback, mounted_mutation, repair_writeback],
            )],
            Vec::new(),
        ));
        let writeback = planned_action(&result, "upgrade-writeback-cache")?;
        let mounted_mutation = planned_action(&result, "run-mounted-mutation")?;
        let repair_writeback = planned_action(&result, "publish-repair-writeback-claim")?;

        assert!(writeback.ack_required);
        assert_eq!(
            writeback.safety_class,
            ReadinessActionSafetyClass::Permissioned
        );
        assert!(mounted_mutation.ack_required);
        assert_eq!(
            mounted_mutation.safety_class,
            ReadinessActionSafetyClass::Destructive
        );
        assert!(repair_writeback.ack_required);
        assert_eq!(
            repair_writeback.safety_class,
            ReadinessActionSafetyClass::Destructive
        );
        Ok(())
    }

    #[test]
    fn planner_blocks_public_claim_upgrade_from_smoke_evidence() -> Result<()> {
        let mut recommendation = recommendation("upgrade-smoke-readiness-claim");
        recommendation.evidence_tier = ReadinessEvidenceTier::Smoke;
        recommendation.public_claim_effect = PublicClaimEffect::UpgradeEligible;

        let result = plan_readiness_actions(&planning_input(
            vec![report(
                vec![input(
                    "proof-bundle-report",
                    ReadinessActionInputKind::ProofBundleReport,
                    "artifacts/proof_bundles/smoke.json",
                    ReadinessActionInputState::Present,
                )],
                vec![recommendation],
            )],
            Vec::new(),
        ));
        let planned = planned_action(&result, "upgrade-smoke-readiness-claim")?;

        assert_eq!(planned.public_claim_effect, PublicClaimEffect::BlockUpgrade);
        assert!(diagnostic_ids(planned).contains(&"planner-smoke-evidence-blocks-public-upgrade"));
        Ok(())
    }

    #[test]
    fn dry_run_report_preserves_output_paths_and_scenarios() {
        let report = build_readiness_action_dry_run_report(
            &planning_input(default_source_reports(), Vec::new()),
            dry_run_metadata(),
        );

        assert_eq!(
            report.schema_version,
            READINESS_ACTION_DRY_RUN_REPORT_VERSION
        );
        assert!(report.dry_run);
        assert_eq!(report.command_metadata.cleanup_status, "not_required");

        let output_kinds: Vec<&str> = report
            .command_metadata
            .output_paths
            .iter()
            .map(|path| path.kind.as_str())
            .collect();
        assert!(output_kinds.contains(&"json_report"));
        assert!(output_kinds.contains(&"markdown_report"));
        assert!(output_kinds.contains(&"stdout_log"));
        assert!(output_kinds.contains(&"stderr_log"));

        let action_ids: Vec<&str> = report
            .scenarios
            .iter()
            .map(|scenario| scenario.action_id.as_str())
            .collect();
        assert!(action_ids.contains(&"claim-source-aware-task"));
        assert!(action_ids.contains(&"define-readiness-action-schema"));
        assert!(action_ids.contains(&"run-permissioned-xfstests-baseline"));
        assert!(action_ids.contains(&"refresh-large-host-swarm-campaign"));
        assert!(report.scenarios.iter().all(|scenario| {
            scenario
                .dry_run_note
                .contains("no reproduction command was executed")
        }));
    }

    #[test]
    fn dry_run_markdown_lists_local_permissioned_and_stale_scenarios() {
        let report = build_readiness_action_dry_run_report(
            &planning_input(default_source_reports(), Vec::new()),
            dry_run_metadata(),
        );

        let markdown = render_readiness_action_dry_run_markdown(&report);

        assert!(markdown.contains("# Readiness Action Dry-Run Report"));
        assert!(markdown.contains("## Operator Evidence"));
        assert!(markdown.contains("claim-source-aware-task"));
        assert!(
            markdown.contains("artifacts/rch/proof_ledgers/remote_success_artifact_warning.json")
        );
        assert!(markdown.contains("define-readiness-action-schema"));
        assert!(markdown.contains("run-permissioned-xfstests-baseline"));
        assert!(markdown.contains("refresh-large-host-swarm-campaign"));
        assert!(markdown.contains("LocalSafe"));
        assert!(markdown.contains("Permissioned"));
        assert!(markdown.contains("DowngradeRequired"));
        assert!(markdown.contains("artifacts/readiness/actions/report.json"));
        assert!(markdown.contains("artifacts/readiness/actions/stderr.log"));
    }

    #[test]
    fn dry_run_json_report_matches_golden() -> serde_json::Result<()> {
        let report = build_readiness_action_dry_run_report(
            &planning_input(default_source_reports(), Vec::new()),
            dry_run_metadata(),
        );
        let json = serde_json::to_string_pretty(&report)?;
        let decoded: ReadinessActionDryRunReport = serde_json::from_str(&json)?;

        assert_eq!(decoded, report);
        insta::assert_snapshot!("readiness_action_dry_run_json_report", json);
        Ok(())
    }

    #[test]
    fn dry_run_markdown_report_matches_golden() {
        let report = build_readiness_action_dry_run_report(
            &planning_input(default_source_reports(), Vec::new()),
            dry_run_metadata(),
        );
        let markdown = render_readiness_action_dry_run_markdown(&report);

        insta::assert_snapshot!("readiness_action_dry_run_markdown_report", markdown);
    }

    #[test]
    fn planner_output_is_stable_when_source_report_order_changes() -> serde_json::Result<()> {
        let mut reversed_reports = default_source_reports();
        reversed_reports.reverse();

        let normal = plan_readiness_actions(&planning_input(default_source_reports(), Vec::new()));
        let reversed = plan_readiness_actions(&planning_input(reversed_reports, Vec::new()));
        let normal_json = serde_json::to_string_pretty(&normal)?;
        let reversed_json = serde_json::to_string_pretty(&reversed)?;

        assert_eq!(normal, reversed);
        assert_eq!(normal_json, reversed_json);
        insta::assert_snapshot!("readiness_action_planner_result_order_stable", normal_json);
        Ok(())
    }

    #[test]
    fn validation_rejects_smoke_upgrade_claims() -> Result<()> {
        let mut fixture_set = default_readiness_action_autopilot_fixture_set();
        let recommendation = fixture_set
            .fixtures
            .first_mut()
            .and_then(|fixture| fixture.report.recommendations.first_mut())
            .context("default fixture set has a first recommendation")?;
        recommendation.evidence_tier = ReadinessEvidenceTier::Smoke;
        recommendation.public_claim_effect = PublicClaimEffect::UpgradeEligible;

        let report = validate_readiness_action_fixture_set(&fixture_set);

        assert!(!report.valid);
        assert!(
            report.errors.iter().any(|error| {
                error.contains("cannot upgrade public claims from smoke evidence")
            })
        );
        Ok(())
    }

    fn default_source_reports() -> Vec<ReadinessActionAutopilotReport> {
        default_readiness_action_autopilot_fixture_set()
            .fixtures
            .into_iter()
            .map(|fixture| fixture.report)
            .collect()
    }

    fn planning_input(
        source_reports: Vec<ReadinessActionAutopilotReport>,
        active_tracker_issues: Vec<ReadinessActionTrackerIssue>,
    ) -> ReadinessActionPlanningInput {
        ReadinessActionPlanningInput {
            report_id: "readiness_action_planner_test_report".to_owned(),
            generated_at: "2026-05-07T00:00:00Z".to_owned(),
            source_reports,
            active_tracker_issues,
        }
    }

    fn active_issue(issue_id: &str, title: &str) -> ReadinessActionTrackerIssue {
        ReadinessActionTrackerIssue {
            issue_id: issue_id.to_owned(),
            title: title.to_owned(),
            status: "open".to_owned(),
        }
    }

    fn report(
        source_inputs: Vec<ReadinessActionInput>,
        recommendations: Vec<ReadinessActionRecommendation>,
    ) -> ReadinessActionAutopilotReport {
        ReadinessActionAutopilotReport {
            schema_version: READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION,
            report_id: "guard_test_report".to_owned(),
            generated_at: "2026-05-07T00:00:00Z".to_owned(),
            source_inputs,
            recommendations,
        }
    }

    fn recommendation(action_id: &str) -> ReadinessActionRecommendation {
        ReadinessActionRecommendation {
            action_id: action_id.to_owned(),
            title: action_id.replace('-', " "),
            safety_class: ReadinessActionSafetyClass::LocalSafe,
            controlling_bead: "bd-rchk0.98.3".to_owned(),
            mail_thread_id: None,
            evidence_tier: ReadinessEvidenceTier::TrackerOnly,
            ack_required: false,
            reservation_artifact_path: None,
            proof_artifact_path: None,
            safe_next_commands: Vec::new(),
            reproduction_command: "cargo test -p ffs-harness readiness_action_autopilot".to_owned(),
            rationale: "Synthetic planner guard test action.".to_owned(),
            public_claim_effect: PublicClaimEffect::NoChange,
            diagnostics: Vec::new(),
        }
    }

    fn planned_action<'a>(
        result: &'a ReadinessActionPlanningResult,
        action_id: &str,
    ) -> Result<&'a ReadinessActionRecommendation> {
        result
            .report
            .recommendations
            .iter()
            .find(|recommendation| recommendation.action_id == action_id)
            .context("planned action")
    }

    fn diagnostic_ids(recommendation: &ReadinessActionRecommendation) -> Vec<&str> {
        recommendation
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.diagnostic_id.as_str())
            .collect()
    }

    fn dry_run_metadata() -> ReadinessActionDryRunMetadata {
        ReadinessActionDryRunMetadata {
            invocation: "ffs-harness recommend-readiness-actions".to_owned(),
            json_report_path: "artifacts/readiness/actions/report.json".to_owned(),
            markdown_report_path: "artifacts/readiness/actions/report.md".to_owned(),
            stdout_log_path: "artifacts/readiness/actions/stdout.log".to_owned(),
            stderr_log_path: "artifacts/readiness/actions/stderr.log".to_owned(),
            cleanup_status: "not_required".to_owned(),
            output_paths: vec![
                ReadinessActionDryRunOutputPath {
                    kind: "json_report".to_owned(),
                    path: "artifacts/readiness/actions/report.json".to_owned(),
                },
                ReadinessActionDryRunOutputPath {
                    kind: "markdown_report".to_owned(),
                    path: "artifacts/readiness/actions/report.md".to_owned(),
                },
                ReadinessActionDryRunOutputPath {
                    kind: "stdout_log".to_owned(),
                    path: "artifacts/readiness/actions/stdout.log".to_owned(),
                },
                ReadinessActionDryRunOutputPath {
                    kind: "stderr_log".to_owned(),
                    path: "artifacts/readiness/actions/stderr.log".to_owned(),
                },
            ],
        }
    }
}
