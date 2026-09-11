#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_core::{OpenFs, OpenOptions};
use ffs_fuse::{FrankenFuse, MountOptions};
use ffs_harness::{
    ExecutionGatedParityReport, ParityExecutor, ProfileReadPathReport,
    adaptive_runtime_manifest::{
        AdaptiveRuntimeEvidenceValidationConfig, AdaptiveRuntimeRunnerCleanupStatus,
        AdaptiveRuntimeRunnerConfig, AdaptiveRuntimeRunnerMode,
        DEFAULT_ADAPTIVE_RUNTIME_EVIDENCE_MANIFEST, DEFAULT_ADAPTIVE_RUNTIME_REAL_RUN_ACK_ENV,
        DEFAULT_ADAPTIVE_RUNTIME_REAL_RUN_ACK_VALUE, DEFAULT_ADAPTIVE_RUNTIME_RUNNER_ARTIFACT_ROOT,
        build_adaptive_runtime_runner_artifacts, collect_adaptive_runtime_runner_host_facts,
        default_adaptive_runtime_runner_path_plan, fail_on_adaptive_runtime_evidence_errors,
        fail_on_adaptive_runtime_runner_errors, load_adaptive_runtime_evidence_manifest,
        render_adaptive_runtime_evidence_markdown, render_adaptive_runtime_runner_markdown,
        validate_adaptive_runtime_evidence_manifest_with_config,
    },
    adversarial_threat_model::{
        build_adversarial_threat_model_sample_artifact_manifest,
        fail_on_adversarial_threat_model_errors, load_adversarial_threat_model,
        validate_adversarial_threat_model,
    },
    ambition_evidence_matrix::{
        AmbitionEvidenceMatrixConfig, fail_on_ambition_evidence_matrix_errors,
        run_ambition_evidence_matrix,
    },
    artifact_manifest::{
        ArtifactManifest, READINESS_EVENT_ENVELOPE_VERSION, parse_manifest_timestamp_epoch_days,
        render_artifact_schema_fixture_markdown, validate_artifact_schema_fixture_dir,
        validate_operational_manifest,
    },
    authoritative_environment_manifest::{
        AUTHORITATIVE_ENVIRONMENT_MANIFEST_SCHEMA_VERSION, AuthoritativeEnvironmentDecision,
        AuthoritativeEnvironmentManifest, MkfsVersion, ResourceLimits,
        evaluate_authoritative_environment,
    },
    btrfs_multidevice_corpus::{
        DEFAULT_BTRFS_MULTIDEV_CORPUS_PATH, fail_on_btrfs_multidev_corpus_errors,
        load_btrfs_multidev_corpus, render_btrfs_multidev_corpus_markdown,
        validate_btrfs_multidev_corpus,
    },
    btrfs_send_receive_corpus::{
        DEFAULT_BTRFS_SEND_RECEIVE_CORPUS_PATH, fail_on_btrfs_send_receive_corpus_errors,
        load_btrfs_send_receive_corpus, render_btrfs_send_receive_corpus_markdown,
        validate_btrfs_send_receive_corpus,
    },
    casefold_corpus::{
        DEFAULT_CASEFOLD_CORPUS_PATH, fail_on_casefold_corpus_errors, load_casefold_corpus,
        render_casefold_corpus_markdown, validate_casefold_corpus,
    },
    chaos_replay_lab::{
        DEFAULT_CHAOS_REPLAY_LAB_PATH, fail_on_chaos_replay_lab_errors, load_chaos_replay_lab,
        render_chaos_replay_lab_markdown, validate_chaos_replay_lab,
    },
    claimability_plan::{
        ClaimabilityPlanConfig, ClaimabilityRchCapacityPreflightInput,
        build_claimability_plan_report, fail_on_claimability_plan_errors,
        render_claimability_plan_markdown,
    },
    cross_oracle_arbitration::{
        DEFAULT_CROSS_ORACLE_ARBITRATION_REPORT, fail_on_cross_oracle_arbitration_errors,
        load_cross_oracle_arbitration_report, render_cross_oracle_arbitration_markdown,
        validate_cross_oracle_arbitration_report,
    },
    deferred_parity_audit::{
        DeferredParityAuditConfig, fail_on_audit_errors, run_deferred_parity_audit,
    },
    docs_status_drift::{
        DocsStatusDriftConfig, fail_on_docs_status_drift_errors, render_docs_status_drift_markdown,
        run_docs_status_drift,
    },
    e2e::{CrashReplaySuiteConfig, FsxStressConfig, run_crash_replay_suite, run_fsx_stress},
    extract_btrfs_superblock, extract_ext4_superblock, extract_region,
    fault_injection_corpus::{
        DEFAULT_FAULT_INJECTION_CORPUS_PATH, fail_on_fault_injection_corpus_errors,
        load_fault_injection_corpus, render_fault_injection_corpus_markdown,
        validate_fault_injection_corpus,
    },
    fuzz_smoke::{
        DEFAULT_FUZZ_SMOKE_MANIFEST_PATH, fail_on_fuzz_smoke_errors, load_fuzz_smoke_manifest,
        run_fuzz_smoke_manifest,
    },
    invariant_oracle::{
        build_invariant_oracle_consumer_report, fail_on_invariant_oracle_errors,
        load_invariant_oracle_report, load_invariant_trace, render_invariant_oracle_markdown,
        validate_invariant_trace,
    },
    inventory_closeout_gate::{
        DEFAULT_INVENTORY_CLOSEOUT_GATE_PATH, fail_on_inventory_closeout_gate_errors,
        load_inventory_closeout_gate, render_inventory_closeout_gate_markdown,
        validate_inventory_closeout_gate,
    },
    low_privilege_demo::{
        DEFAULT_LOW_PRIVILEGE_DEMO_PATH, fail_on_low_privilege_demo_errors,
        load_low_privilege_demo_manifest, render_low_privilege_demo_markdown,
        validate_low_privilege_demo_manifest,
    },
    low_privilege_demo_sandbox::{
        DEFAULT_LOW_PRIVILEGE_DEMO_SANDBOX_PATH, fail_on_low_privilege_demo_sandbox_errors,
        load_low_privilege_demo_sandbox, render_low_privilege_demo_sandbox_markdown,
        validate_low_privilege_demo_sandbox,
    },
    metamorphic_workload_seed_catalog::{
        DEFAULT_METAMORPHIC_WORKLOAD_SEED_CATALOG_PATH,
        fail_on_metamorphic_workload_seed_catalog_errors, load_metamorphic_workload_seed_catalog,
        render_metamorphic_workload_seed_catalog_markdown,
        validate_metamorphic_workload_seed_catalog,
    },
    mounted_checkpoint_survivor::{
        DEFAULT_MOUNTED_CHECKPOINT_SURVIVOR_PATH, fail_on_mounted_checkpoint_survivor_errors,
        load_mounted_checkpoint_survivor, render_mounted_checkpoint_survivor_markdown,
        validate_mounted_checkpoint_survivor,
    },
    mounted_differential_oracle::{
        DEFAULT_MOUNTED_DIFFERENTIAL_REPORT, fail_on_mounted_differential_oracle_errors,
        load_mounted_differential_oracle_report, render_mounted_differential_oracle_markdown,
        validate_mounted_differential_oracle_report,
    },
    mounted_recovery_matrix::{
        DEFAULT_RECOVERY_MATRIX_PATH, fail_on_mounted_recovery_matrix_errors,
        load_mounted_recovery_matrix, validate_mounted_recovery_matrix,
    },
    mounted_repair_mutation_boundary::{
        DEFAULT_MOUNTED_REPAIR_MUTATION_BOUNDARY_PATH,
        fail_on_mounted_repair_mutation_boundary_errors, load_mounted_repair_mutation_boundary,
        render_mounted_repair_mutation_boundary_markdown,
        validate_mounted_repair_mutation_boundary,
    },
    mounted_write_error_classes::{
        DEFAULT_MOUNTED_WRITE_ERROR_CLASSES_PATH, fail_on_mounted_write_error_classes_errors,
        parse_mounted_write_error_classes, validate_mounted_write_error_classes_with_matrix,
    },
    mounted_write_matrix::{
        DEFAULT_MATRIX_PATH, fail_on_mounted_write_matrix_errors, load_mounted_write_matrix,
        validate_mounted_write_matrix,
    },
    numa_allocation_placement_report::{
        NumaPlacementValidationConfig, fail_on_numa_allocation_placement_errors,
        render_numa_allocation_placement_markdown, validate_numa_allocation_placement_report_json,
    },
    open_ended_inventory::{
        DEFAULT_SOURCE_SCOPE_MANIFEST_PATH, OpenEndedNoteSource, load_source_scope_manifest,
        scan_open_ended_notes, scan_source_scope_manifest, validate_current_inventory,
    },
    operational_evidence_index::{
        OperationalEvidenceIndexConfig, build_operational_evidence_index,
        render_operational_evidence_index_markdown,
    },
    operational_readiness_report::{
        OperationalReadinessReportConfig, build_operational_readiness_report,
        render_operational_readiness_markdown,
    },
    operator_recovery_drill::{
        DEFAULT_OPERATOR_RECOVERY_DRILL_PATH, fail_on_operator_recovery_drill_errors,
        load_operator_recovery_drill_spec, render_operator_recovery_drill_markdown,
        validate_operator_recovery_drill,
    },
    performance_baseline_manifest::{
        PerformanceBaselineManifest, build_performance_sample_artifact_manifest,
        fail_on_performance_baseline_manifest_errors, load_performance_baseline_manifest,
        validate_performance_baseline_manifest,
    },
    performance_delta_closeout::{
        DEFAULT_PERFORMANCE_DELTA_CLOSEOUT_CONFIG, fail_on_performance_delta_closeout_errors,
        load_performance_delta_closeout_config, render_performance_delta_closeout_markdown,
        run_performance_delta_closeout,
    },
    permissioned_campaign_broker::{
        DEFAULT_PERMISSIONED_CAMPAIGN_BROKER_MANIFEST, PermissionedCampaignBrokerValidationConfig,
        PermissionedCampaignExecutionLedgerValidationConfig, PermissionedCampaignHandoffGeneration,
        SwarmCapabilityCalibrationValidationConfig, fail_on_permissioned_campaign_broker_errors,
        fail_on_permissioned_campaign_execution_ledger_errors,
        fail_on_swarm_capability_calibration_errors, generate_permissioned_campaign_handoff_packet,
        load_permissioned_campaign_broker_manifest, load_permissioned_campaign_execution_ledger,
        load_swarm_capability_calibration_manifest, render_permissioned_campaign_broker_markdown,
        render_permissioned_campaign_execution_ledger_markdown,
        render_permissioned_campaign_handoff_markdown,
        render_swarm_capability_calibration_markdown,
        validate_permissioned_campaign_broker_manifest,
        validate_permissioned_campaign_execution_ledger,
        validate_swarm_capability_calibration_manifest,
    },
    proof_bundle::{
        ProofBundleValidationConfig, fail_on_proof_bundle_errors, render_proof_bundle_markdown,
        validate_proof_bundle,
    },
    proof_overhead_budget::{
        evaluate_proof_overhead_budget, fail_on_proof_overhead_budget_errors,
        load_observed_proof_metrics, load_proof_overhead_budget_config,
    },
    rch_capacity_preflight::{
        fail_on_rch_capacity_preflight_errors, load_rch_capacity_preflight_report,
        render_rch_capacity_preflight_markdown, validate_rch_capacity_preflight_report,
    },
    readiness_action_autopilot::{
        ReadinessActionDryRunMetadata, ReadinessActionDryRunOutputPath,
        ReadinessActionDryRunReport, ReadinessActionPlanningInput,
        build_readiness_action_dry_run_report, default_readiness_action_autopilot_fixture_set,
        render_readiness_action_dry_run_markdown,
    },
    readiness_dashboard::{
        ReadinessDashboardConfig, build_readiness_dashboard, render_readiness_dashboard_markdown,
    },
    readiness_lab::{
        DEFAULT_READINESS_LAB_NUMA_P99_REPLAY_MANIFEST, ReadinessLabHostSimulationConfig,
        ReadinessLabNumaP99ReplayConfig, ReadinessLabRchLaneScheduleConfig,
        ReadinessLabTruthGraphConfig, ReadinessLabValidationConfig,
        fail_on_readiness_lab_contract_errors, fail_on_readiness_lab_host_simulation_errors,
        fail_on_readiness_lab_numa_p99_replay_errors,
        fail_on_readiness_lab_rch_lane_schedule_errors, fail_on_readiness_lab_truth_graph_errors,
        load_readiness_lab_contract_bundle, load_readiness_lab_host_simulation_manifest,
        load_readiness_lab_numa_p99_replay_manifest, load_readiness_lab_rch_lane_schedule_manifest,
        load_readiness_lab_truth_graph_manifest, plan_readiness_lab_rch_lanes,
        render_readiness_lab_contract_markdown, render_readiness_lab_host_simulation_markdown,
        render_readiness_lab_numa_p99_replay_markdown,
        render_readiness_lab_rch_lane_schedule_markdown, render_readiness_lab_truth_graph_markdown,
        simulate_readiness_lab_hosts, validate_readiness_lab_contract_bundle,
        validate_readiness_lab_numa_p99_replay,
    },
    release_gate::{
        evaluate_release_gates, fail_on_release_gate_errors, load_release_gate_policy,
        render_release_gate_markdown,
    },
    remediation_catalog::{
        DEFAULT_REMEDIATION_CATALOG_PATH, parse_remediation_catalog, render_remediation_markdown,
        validate_remediation_catalog,
    },
    remediation_severity_gate::{
        DEFAULT_REMEDIATION_SEVERITY_GATE_PATH, fail_on_remediation_severity_gate_errors,
        load_remediation_severity_gate, render_remediation_severity_gate_markdown,
        validate_remediation_severity_gate,
    },
    repair_confidence_lab::{
        DEFAULT_REPAIR_CONFIDENCE_LAB_PATH, fail_on_repair_confidence_lab_errors,
        load_repair_confidence_lab_spec, render_repair_confidence_lab_markdown,
        validate_repair_confidence_lab,
    },
    repair_corpus::{
        DEFAULT_REPAIR_CORPUS_PATH, fail_on_repair_corpus_errors, load_repair_corpus,
        render_repair_corpus_markdown, validate_repair_corpus,
    },
    repair_writeback_serialization::{
        build_repair_writeback_proof_summary,
        build_repair_writeback_serialization_sample_artifact_manifest,
        fail_on_repair_writeback_serialization_errors,
        load_repair_writeback_serialization_contract,
        render_repair_writeback_serialization_markdown,
        validate_repair_writeback_serialization_contract,
    },
    report_schema_inventory::{
        current_report_schema_inventory, fail_on_report_schema_inventory_errors,
        render_report_schema_inventory_markdown, validate_report_schema_inventory,
    },
    runtime_console_report::{
        RuntimeConsoleValidationConfig, fail_on_runtime_console_report_errors,
        render_runtime_console_report_markdown, validate_runtime_console_report_json,
    },
    scrub_repair_scheduler::{
        DEFAULT_SCRUB_REPAIR_SCHEDULER_MANIFEST, fail_on_scrub_repair_scheduler_errors,
        load_scrub_repair_scheduler_manifest, render_scrub_repair_scheduler_markdown,
        validate_scrub_repair_scheduler_manifest,
    },
    soak_canary_campaign::{
        build_soak_canary_sample_artifact_manifest, fail_on_soak_canary_campaign_errors,
        load_soak_canary_campaign_manifest, render_soak_canary_campaign_markdown,
        validate_soak_canary_campaign_manifest,
    },
    support_state_accounting::{
        SupportStateAccountingConfig, fail_on_support_state_accounting_errors,
        render_support_state_markdown, run_support_state_accounting,
    },
    swarm_cache_controller::{
        DEFAULT_SWARM_CACHE_CONTROLLER_CONTRACT, fail_on_swarm_cache_controller_errors,
        load_swarm_cache_controller_contract, render_swarm_cache_controller_markdown,
        validate_swarm_cache_controller_contract,
    },
    swarm_operator_report::{
        DEFAULT_SWARM_OPERATOR_REPORT, fail_on_swarm_operator_report_errors,
        load_swarm_operator_report, render_swarm_operator_report_markdown,
        validate_swarm_operator_report,
    },
    swarm_tail_latency::{
        DEFAULT_SWARM_TAIL_LATENCY_LEDGER, fail_on_swarm_tail_latency_errors,
        load_swarm_tail_latency_ledger, render_swarm_tail_latency_markdown,
        validate_swarm_tail_latency_ledger,
    },
    swarm_workload_harness::{
        DEFAULT_SWARM_WORKLOAD_HARNESS_MANIFEST, DEFAULT_SWARM_WORKLOAD_HARNESS_MAX_AGE_DAYS,
        SwarmWorkloadHarnessValidationConfig, fail_on_swarm_workload_harness_errors,
        load_swarm_workload_harness_manifest, render_swarm_workload_harness_markdown,
        validate_swarm_workload_harness_manifest_with_config,
    },
    topology_runtime_advisor::{
        TopologyRuntimeAdvisorValidationConfig, fail_on_topology_runtime_advisor_errors,
        fail_on_topology_runtime_advisor_score_errors, load_topology_runtime_advisor_manifest,
        render_topology_runtime_advisor_markdown, render_topology_runtime_advisor_score_markdown,
        render_topology_runtime_advisor_score_structured_log,
        render_topology_runtime_advisor_structured_log,
        score_topology_runtime_advisor_manifest_with_config,
        validate_topology_runtime_advisor_manifest_with_config,
    },
    tracker_source_hygiene::{
        AgentMailReservationSnapshotReport, TrackerLocalGraphExportPaths,
        TrackerSourceHygieneConfig, TrackerSourceHygieneReport,
        fail_on_tracker_source_hygiene_errors, run_tracker_source_hygiene,
        write_tracker_source_hygiene_local_graph_exports,
    },
    validate_btrfs_fixture, validate_ext4_fixture,
    verification_runner::{
        FuseHostProbeOptions, RchProofLedgerConfig, build_rch_proof_ledger_report,
        probe_host_fuse_capability, render_rch_proof_ledger_markdown,
    },
    wal_group_commit_gate::{
        DEFAULT_WAL_GROUP_COMMIT_GATE_MANIFEST, fail_on_wal_group_commit_gate_errors,
        load_wal_group_commit_gate_manifest, render_wal_group_commit_gate_markdown,
        validate_wal_group_commit_gate_manifest,
    },
    workload_corpus::{
        DEFAULT_WORKLOAD_CORPUS_PATH, fail_on_workload_corpus_errors, load_workload_corpus,
        render_workload_corpus_markdown, validate_selected_workload_scenario,
        validate_workload_corpus,
    },
    writeback_cache_audit::{
        build_writeback_cache_audit_report, build_writeback_crash_replay_report,
        build_writeback_ordering_report, fail_on_writeback_cache_audit_errors,
        fail_on_writeback_crash_replay_errors, fail_on_writeback_ordering_errors,
        load_writeback_cache_audit_gate, load_writeback_crash_replay_oracle,
        load_writeback_ordering_oracle, render_writeback_cache_audit_markdown,
        render_writeback_crash_replay_markdown, render_writeback_ordering_markdown,
    },
    xfstests::{
        XfstestsBaselineManifest, XfstestsBaselineManifestInput, XfstestsFailureTriageInput,
        XfstestsRun, XfstestsStatus, apply_allowlist, build_xfstests_baseline_manifest,
        build_xfstests_failure_triage_report, compare_against_baseline, load_allowlist,
        load_baseline, load_selected_tests, parse_check_output, render_xfstests_baseline_markdown,
        render_xfstests_failure_triage_markdown, summarize_uniform,
        validate_xfstests_baseline_manifest, write_junit_xml,
    },
};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::hint::black_box;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ffs_types::{BlockNumber, InodeNumber};

#[derive(Debug, Default)]
struct XfstestsReportConfig {
    selected: Option<String>,
    check_log: Option<String>,
    results_json: Option<String>,
    junit_xml: Option<String>,
    allowlist_json: Option<String>,
    baseline_json: Option<String>,
    uniform_status: Option<XfstestsStatus>,
    uniform_note: Option<String>,
    check_rc: i32,
    dry_run: bool,
}

#[derive(Debug, Default)]
struct XfstestsBaselineManifestConfig {
    selected: Option<String>,
    results_json: Option<String>,
    manifest_out: Option<String>,
    summary_out: Option<String>,
    baseline_id: Option<String>,
    subset_version: Option<String>,
    environment_manifest_id: Option<String>,
    environment_age_secs: u64,
    environment_max_age_secs: u64,
    command_transcript: Option<String>,
    checkpoint_id: Option<String>,
    resume_command: Option<String>,
    cleanup_status: Option<String>,
    reproduction_command: Option<String>,
    raw_artifacts: Vec<String>,
    output_paths: Vec<(String, String)>,
}

#[derive(Debug, Default)]
struct XfstestsFailureTriageConfig {
    baseline_manifest: Option<String>,
    triage_out: Option<String>,
    summary_out: Option<String>,
    triage_id: Option<String>,
    reproduction_command: Option<String>,
}

#[derive(Debug)]
struct RecommendReadinessActionsCmdArgs {
    input_path: Option<String>,
    out_json_path: String,
    out_markdown_path: String,
    stdout_log_path: String,
    stderr_log_path: String,
    report_id: Option<String>,
    generated_at: Option<String>,
    invocation: String,
}

#[derive(Debug)]
struct AdaptiveRuntimeManifestCmdArgs {
    manifest_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
    reference_timestamp: Option<String>,
    current_git_sha: Option<String>,
}

#[derive(Debug, Default)]
struct AuthoritativeEnvironmentRecordCmdArgs {
    out_path: Option<String>,
    manifest_id: Option<String>,
    bead_id: Option<String>,
    lane_id: Option<String>,
    authoritative: bool,
    host_id: Option<String>,
    worker_id: Option<String>,
    kernel: Option<String>,
    fuse_kernel_version: Option<String>,
    fuser_helper_version: Option<String>,
    mkfs_versions: Vec<MkfsVersion>,
    cargo_toolchain: Option<String>,
    rustc_version: Option<String>,
    mount_namespace: Option<String>,
    privilege_model: Option<String>,
    fs_tools: Vec<String>,
    git_sha: Option<String>,
    artifact_schema_version: Option<u32>,
    probe_at_unix: Option<u64>,
    freshness_ttl_seconds: Option<u64>,
    now_unix: Option<u64>,
    replay_command: Option<String>,
    max_open_files: Option<u64>,
    max_address_space_bytes: Option<u64>,
    max_processes: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
enum HostProbeCommand {
    Uname,
    Hostname,
    Git,
    Fusermount3,
    Fusermount,
    MkfsExt4,
    MkfsBtrfs,
    Cargo,
    Rustc,
    E2fsck,
    Btrfs,
    Fsck,
}

#[derive(Debug)]
struct TopologyRuntimeAdvisorCmdArgs {
    manifest_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    structured_log_out_path: Option<String>,
    format: ProofBundleFormat,
    reference_timestamp: Option<String>,
    max_age_days: u32,
}

#[derive(Debug)]
struct PermissionedCampaignBrokerCmdArgs {
    manifest_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
    reference_timestamp: Option<String>,
}

#[derive(Debug)]
struct PermissionedCampaignLedgerCmdArgs {
    manifest_path: String,
    ledger_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
    current_git_sha: Option<String>,
}

#[derive(Debug)]
struct PermissionedCampaignPacketCmdArgs {
    manifest_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
    reference_timestamp: Option<String>,
    generated_at: String,
    generated_by: String,
    git_sha: String,
}

#[derive(Debug)]
struct SwarmCapabilityCalibrationCmdArgs {
    manifest_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
    reference_timestamp: Option<String>,
}

#[derive(Debug)]
struct AdaptiveRuntimeRunnerCmdArgs {
    mode: AdaptiveRuntimeRunnerMode,
    artifact_root: String,
    out_path: String,
    summary_out_path: String,
    raw_stdout_path: Option<String>,
    raw_stderr_path: Option<String>,
    structured_log_path: Option<String>,
    runner_manifest_path: Option<String>,
    cleanup_report_path: Option<String>,
    host_facts_path: Option<String>,
    test_dir: Option<String>,
    scratch_mnt: Option<String>,
    ack_env: String,
    ack_value: String,
    generated_at: String,
    git_sha: String,
    reproduction_command: String,
    cleanup_status: AdaptiveRuntimeRunnerCleanupStatus,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run_manifest_command(command: Option<&str>, args: &[String]) -> Option<Result<()>> {
    match command {
        Some("validate-adaptive-runtime-manifest") => {
            Some(validate_adaptive_runtime_manifest_cmd(args))
        }
        Some("record-environment-manifest") => {
            Some(record_authoritative_environment_manifest_cmd(args))
        }
        Some("validate-topology-runtime-advisor") => {
            Some(validate_topology_runtime_advisor_cmd(args))
        }
        Some("score-topology-runtime-advisor") => Some(score_topology_runtime_advisor_cmd(args)),
        Some("validate-permissioned-campaign-broker") => {
            Some(validate_permissioned_campaign_broker_cmd(args))
        }
        Some("validate-permissioned-campaign-ledger") => {
            Some(validate_permissioned_campaign_ledger_cmd(args))
        }
        Some("generate-permissioned-campaign-packet") => {
            Some(generate_permissioned_campaign_packet_cmd(args))
        }
        Some("validate-swarm-capability-calibration") => {
            Some(validate_swarm_capability_calibration_cmd(args))
        }
        _ => None,
    }
}

#[allow(clippy::too_many_lines)]
fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str);
    let command_args = args.get(1..).unwrap_or(&[]);
    if let Some(result) = run_manifest_command(cmd, command_args) {
        return result;
    }

    match cmd {
        Some("parity") => parity_cmd(command_args),
        Some("gates") => gates_cmd(command_args),
        Some("check-fixtures") => check_fixtures_cmd(),
        Some("profile-read-path") => profile_read_path_cmd(&args[1..]),
        Some("generate-fixture") => generate_fixture(&args[1..]),
        Some("run-crash-replay") => run_crash_replay(&args[1..]),
        Some("run-fsx-stress") => run_fsx_stress_cmd(&args[1..]),
        Some("xfstests-report") => xfstests_report(&args[1..]),
        Some("xfstests-baseline-manifest") => xfstests_baseline_manifest(&args[1..]),
        Some("xfstests-failure-triage") => xfstests_failure_triage(&args[1..]),
        Some("validate-operational-manifest") => validate_operational_manifest_cmd(&args[1..]),
        Some("validate-artifact-schema-fixtures") => {
            validate_artifact_schema_fixtures_cmd(&args[1..])
        }
        Some("fuse-capability-probe") => fuse_capability_probe_cmd(&args[1..]),
        Some("validate-open-ended-inventory") => validate_open_ended_inventory_cmd(&args[1..]),
        Some("open-ended-note-scanner") => open_ended_note_scanner_cmd(&args[1..]),
        Some("validate-source-scope-manifest") => validate_source_scope_manifest_cmd(&args[1..]),
        Some("validate-deferred-parity-audit") => validate_deferred_parity_audit_cmd(&args[1..]),
        Some("validate-ambition-evidence-matrix") => {
            validate_ambition_evidence_matrix_cmd(&args[1..])
        }
        Some("validate-support-state-accounting") => {
            validate_support_state_accounting_cmd(&args[1..])
        }
        Some("validate-docs-status-drift") => validate_docs_status_drift_cmd(&args[1..]),
        Some("validate-tracker-source-hygiene") => validate_tracker_source_hygiene_cmd(&args[1..]),
        Some("claimability-plan") => claimability_plan_cmd(&args[1..]),
        Some("rch-proof-ledger") => rch_proof_ledger_cmd(&args[1..]),
        Some("validate-rch-capacity-preflight") => validate_rch_capacity_preflight_cmd(&args[1..]),
        Some("validate-runtime-console") => validate_runtime_console_cmd(&args[1..]),
        Some("validate-numa-allocation-placement") => {
            validate_numa_allocation_placement_cmd(&args[1..])
        }
        Some("validate-fuzz-smoke") => validate_fuzz_smoke_cmd(&args[1..]),
        Some("validate-proof-overhead-budget") => validate_proof_overhead_budget_cmd(&args[1..]),
        Some("adaptive-runtime-runner") => adaptive_runtime_runner_cmd(&args[1..]),
        Some("validate-proof-bundle") => validate_proof_bundle_cmd(&args[1..]),
        Some("evaluate-release-gates") => evaluate_release_gates_cmd(&args[1..]),
        Some("validate-performance-baseline-manifest") => {
            validate_performance_baseline_manifest_cmd(&args[1..])
        }
        Some("performance-delta-closeout") => performance_delta_closeout_cmd(&args[1..]),
        Some("validate-swarm-cache-controller") => validate_swarm_cache_controller_cmd(&args[1..]),
        Some("validate-swarm-operator-report") => validate_swarm_operator_report_cmd(&args[1..]),
        Some("validate-swarm-tail-latency") => validate_swarm_tail_latency_cmd(&args[1..]),
        Some("validate-swarm-workload-harness") => validate_swarm_workload_harness_cmd(&args[1..]),
        Some("validate-wal-group-commit-gate") => validate_wal_group_commit_gate_cmd(&args[1..]),
        Some("validate-scrub-repair-scheduler") => validate_scrub_repair_scheduler_cmd(&args[1..]),
        Some("validate-adversarial-threat-model") => {
            validate_adversarial_threat_model_cmd(&args[1..])
        }
        Some("validate-invariant-oracle") => validate_invariant_oracle_cmd(&args[1..]),
        Some("validate-mounted-differential-oracle") => {
            validate_mounted_differential_oracle_cmd(&args[1..])
        }
        Some("validate-mounted-repair-mutation-boundary") => {
            validate_mounted_repair_mutation_boundary_cmd(&args[1..])
        }
        Some("validate-cross-oracle-arbitration") => {
            validate_cross_oracle_arbitration_cmd(&args[1..])
        }
        Some("validate-soak-canary-campaigns") => validate_soak_canary_campaigns_cmd(&args[1..]),
        Some("validate-repair-confidence-lab") => validate_repair_confidence_lab_cmd(&args[1..]),
        Some("validate-operator-recovery-drill") => {
            validate_operator_recovery_drill_cmd(&args[1..])
        }
        Some("validate-repair-writeback-serialization") => {
            validate_repair_writeback_serialization_cmd(&args[1..])
        }
        Some("validate-chaos-replay-lab") => validate_chaos_replay_lab_cmd(&args[1..]),
        Some("validate-inventory-closeout-gate") => {
            validate_inventory_closeout_gate_cmd(&args[1..])
        }
        Some("validate-report-schema-inventory") => {
            validate_report_schema_inventory_cmd(&args[1..])
        }
        Some("validate-remediation-catalog") => validate_remediation_catalog_cmd(&args[1..]),
        Some("validate-remediation-severity-gate") => {
            validate_remediation_severity_gate_cmd(&args[1..])
        }
        Some("validate-writeback-cache-audit") => validate_writeback_cache_audit_cmd(&args[1..]),
        Some("validate-writeback-cache-ordering") => {
            validate_writeback_cache_ordering_cmd(&args[1..])
        }
        Some("validate-writeback-cache-crash-replay") => {
            validate_writeback_cache_crash_replay_cmd(&args[1..])
        }
        Some("validate-workload-corpus") => validate_workload_corpus_cmd(&args[1..]),
        Some("validate-btrfs-send-receive-corpus") => {
            validate_btrfs_send_receive_corpus_cmd(&args[1..])
        }
        Some("validate-btrfs-multidevice-corpus") => {
            validate_btrfs_multidevice_corpus_cmd(&args[1..])
        }
        Some("validate-casefold-corpus") => validate_casefold_corpus_cmd(&args[1..]),
        Some("validate-fault-injection-corpus") => validate_fault_injection_corpus_cmd(&args[1..]),
        Some("validate-repair-corpus") => validate_repair_corpus_cmd(&args[1..]),
        Some("validate-mounted-checkpoint-survivor") => {
            validate_mounted_checkpoint_survivor_cmd(&args[1..])
        }
        Some("validate-low-privilege-demo") => validate_low_privilege_demo_cmd(&args[1..]),
        Some("validate-low-privilege-demo-sandbox") => {
            validate_low_privilege_demo_sandbox_cmd(&args[1..])
        }
        Some("validate-metamorphic-workload-seeds") => {
            validate_metamorphic_workload_seed_catalog_cmd(&args[1..])
        }
        Some("operational-readiness-report") => operational_readiness_report_cmd(&args[1..]),
        Some("operational-evidence-index") => operational_evidence_index_cmd(&args[1..]),
        Some("recommend-readiness-actions") => recommend_readiness_actions_cmd(&args[1..]),
        Some("readiness-dashboard") => readiness_dashboard_cmd(&args[1..]),
        Some("validate-readiness-lab-contracts") => {
            validate_readiness_lab_contracts_cmd(&args[1..])
        }
        Some("simulate-readiness-lab-hosts") => simulate_readiness_lab_hosts_cmd(&args[1..]),
        Some("plan-readiness-lab-rch-lanes") => plan_readiness_lab_rch_lanes_cmd(&args[1..]),
        Some("build-readiness-lab-truth-graph") => build_readiness_lab_truth_graph_cmd(&args[1..]),
        Some("validate-readiness-lab-numa-p99-replay") => {
            validate_readiness_lab_numa_p99_replay_cmd(&args[1..])
        }
        Some("validate-mounted-write-error-classes") => {
            validate_mounted_write_error_classes_cmd(&args[1..])
        }
        Some("validate-mounted-write-matrix") => validate_mounted_write_matrix_cmd(&args[1..]),
        Some("validate-mounted-recovery-matrix") => {
            validate_mounted_recovery_matrix_cmd(&args[1..])
        }
        Some("--help" | "-h" | "help") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            print_usage();
            bail!("unknown command: {other}")
        }
    }
}

fn parity_cmd(args: &[String]) -> Result<()> {
    let mut suites = Vec::new();
    let mut gates = Vec::new();
    let mut executor = ParityExecutor::Rch;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--verify" => suites.push(args.next().context("--verify requires a suite")?.clone()),
            "--gate" => gates.push(args.next().context("--gate requires a gate id")?.clone()),
            "--local" => executor = ParityExecutor::Cargo,
            _ => bail!("unknown parity argument: {arg}"),
        }
    }
    if executor == ParityExecutor::Cargo && suites.is_empty() && gates.is_empty() {
        bail!("--local requires --verify or --gate");
    }
    let report = ExecutionGatedParityReport::run_with_gates(&suites, &gates, executor)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !suites.is_empty() || !gates.is_empty() {
        report.require_evidence().map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

/// Execute the canonical spec §22 gate commands and report their real status.
///
/// The gates are named exactly as §22.1 names them, and a filter that selects no
/// test is reported as `not_implemented` rather than passing. Exits nonzero only
/// when a gate that has executable tests fails to pass.
fn gates_cmd(args: &[String]) -> Result<()> {
    use ffs_harness::canonical_gates::{self, CanonicalGateReport, CanonicalGateStatus};

    let mut gate_ids: Vec<String> = Vec::new();
    let mut executor = ParityExecutor::Rch;
    let mut out_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--gate" => {
                i += 1;
                gate_ids.push(args.get(i).context("--gate requires a gate id")?.clone());
            }
            "--all" => gate_ids.push(canonical_gates::ALL_GATES_ARG.to_owned()),
            "--local" => executor = ParityExecutor::Cargo,
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.clone());
            }
            "--help" | "-h" => {
                print_gates_usage();
                return Ok(());
            }
            other => bail!("unknown gates argument: {other}"),
        }
        i += 1;
    }
    if gate_ids.is_empty() {
        gate_ids.push(canonical_gates::ALL_GATES_ARG.to_owned());
    }
    let report = CanonicalGateReport::run(&gate_ids, executor)?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        std::fs::write(&path, format!("{json}\n"))
            .with_context(|| format!("write canonical gate report to {path}"))?;
    }
    println!("{json}");
    let failed = report.failed_gates();
    let not_implemented = report.not_implemented_gates();
    eprintln!(
        "canonical §22 gates: {} passed, {} failed, {} not implemented (readiness_verified=false while any gate is not passed)",
        report.passed_gates().len(),
        failed.len(),
        not_implemented.len()
    );
    if !not_implemented.is_empty() {
        eprintln!(
            "not implemented: {} (each names its §22 command and criteria in the report)",
            not_implemented.join(", ")
        );
    }
    if !failed.is_empty() {
        let reasons = report
            .gates
            .iter()
            .filter(|gate| gate.status == CanonicalGateStatus::Failed)
            .map(|gate| {
                format!(
                    "{}: {}",
                    gate.gate_id,
                    gate.reason.as_deref().unwrap_or("-")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        bail!("canonical gates failed: {reasons}");
    }
    Ok(())
}

fn check_fixtures_cmd() -> Result<()> {
    let ext4 = Path::new("conformance/fixtures/ext4_superblock_sparse.json");
    let btrfs = Path::new("conformance/fixtures/btrfs_superblock_sparse.json");
    let ext4_sb = validate_ext4_fixture(ext4)?;
    let btrfs_sb = validate_btrfs_fixture(btrfs)?;

    println!(
        "ext4: block_size={} volume={}",
        ext4_sb.block_size, ext4_sb.volume_name
    );
    println!(
        "btrfs: nodesize={} label={}",
        btrfs_sb.nodesize, btrfs_sb.label
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileReadPathMode {
    CliInspect,
    DirectRead,
    FuseRead,
}

impl ProfileReadPathMode {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "cli-inspect" => Ok(Self::CliInspect),
            "direct-read" => Ok(Self::DirectRead),
            "fuse-read" => Ok(Self::FuseRead),
            other => bail!("unknown profile-read-path mode: {other}"),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::CliInspect => "cli-inspect",
            Self::DirectRead => "direct-read",
            Self::FuseRead => "fuse-read",
        }
    }
}

#[derive(Debug)]
struct ProfileReadPathCmdArgs {
    fixture: PathBuf,
    duration: Duration,
    iterations: Option<u64>,
    mode: ProfileReadPathMode,
}

fn parse_profile_read_path_args(args: &[String]) -> Result<ProfileReadPathCmdArgs> {
    let mut fixture = PathBuf::from("conformance/golden/ext4_8mb_reference.ext4");
    let mut duration = Duration::from_secs(30);
    let mut iterations = None;
    let mut mode = ProfileReadPathMode::CliInspect;
    let mut idx = 0;

    while idx < args.len() {
        match args[idx].as_str() {
            "--fixture" => {
                let value = args
                    .get(idx + 1)
                    .context("--fixture requires a path argument")?;
                fixture = PathBuf::from(value);
                idx += 2;
            }
            "--duration-sec" => {
                let value = args
                    .get(idx + 1)
                    .context("--duration-sec requires an integer argument")?;
                duration = Duration::from_secs(value.parse().context("parse --duration-sec")?);
                idx += 2;
            }
            "--iterations" => {
                let value = args
                    .get(idx + 1)
                    .context("--iterations requires an integer argument")?;
                iterations = Some(value.parse().context("parse --iterations")?);
                idx += 2;
            }
            "--mode" => {
                let value = args.get(idx + 1).context("--mode requires an argument")?;
                mode = ProfileReadPathMode::parse(value)?;
                idx += 2;
            }
            "-h" | "--help" => {
                println!(
                    "usage: ffs-harness profile-read-path --fixture PATH --duration-sec N [--iterations N] [--mode cli-inspect|direct-read|fuse-read]"
                );
                return Ok(ProfileReadPathCmdArgs {
                    fixture,
                    duration: Duration::ZERO,
                    iterations: Some(0),
                    mode,
                });
            }
            other => bail!("unknown profile-read-path argument: {other}"),
        }
    }

    Ok(ProfileReadPathCmdArgs {
        fixture,
        duration,
        iterations,
        mode,
    })
}

fn profile_read_path_iteration(
    cx: &Cx,
    args: &ProfileReadPathCmdArgs,
    cached_fs: &mut Option<OpenFs>,
    cached_fuse: &mut Option<(FrankenFuse, u64)>,
) -> Result<u64> {
    let checksum = match args.mode {
        ProfileReadPathMode::CliInspect => {
            let fs = OpenFs::open_with_options(cx, &args.fixture, &OpenOptions::default())
                .with_context(|| format!("open fixture {}", args.fixture.display()))?;
            let summary = fs.free_space_summary(cx)?;
            let orphans = fs.read_ext4_orphan_list(cx)?;
            let root_inode = fs.read_inode(cx, InodeNumber(2))?;
            let mut metadata = fs.read_contiguous_block_vecs(cx, BlockNumber(0), 2)?;
            let group_descriptor = metadata.pop().context("group descriptor block missing")?;
            let superblock = metadata.pop().context("superblock block missing")?;
            black_box(summary.free_blocks_total)
                ^ black_box(summary.free_inodes_total)
                ^ u64::from(black_box(root_inode.mode))
                ^ u64::try_from(black_box(orphans.count())).unwrap_or(u64::MAX)
                ^ u64::try_from(black_box(superblock.len())).unwrap_or(u64::MAX)
                ^ u64::try_from(black_box(group_descriptor.len())).unwrap_or(u64::MAX)
        }
        ProfileReadPathMode::DirectRead => {
            if cached_fs.is_none() {
                *cached_fs = Some(
                    OpenFs::open_with_options(cx, &args.fixture, &OpenOptions::default())
                        .with_context(|| format!("open fixture {}", args.fixture.display()))?,
                );
            }
            let fs = cached_fs.as_ref().context("cached filesystem missing")?;
            let root_inode = fs.read_inode(cx, InodeNumber(2))?;
            let mut metadata = fs.read_contiguous_block_vecs(cx, BlockNumber(0), 2)?;
            let group_descriptor = metadata.pop().context("group descriptor block missing")?;
            let superblock = metadata.pop().context("superblock block missing")?;
            u64::from(black_box(root_inode.mode))
                ^ u64::try_from(black_box(superblock.len())).unwrap_or(u64::MAX)
                ^ u64::try_from(black_box(group_descriptor.len())).unwrap_or(u64::MAX)
        }
        ProfileReadPathMode::FuseRead => {
            if cached_fuse.is_none() {
                let fs = OpenFs::open_with_options(cx, &args.fixture, &OpenOptions::default())
                    .with_context(|| format!("open fixture {}", args.fixture.display()))?;
                let fuse = FrankenFuse::with_options(
                    Box::new(fs),
                    &MountOptions {
                        read_only: true,
                        ..MountOptions::default()
                    },
                );
                let attr = fuse
                    .lookup_for_fuzzing(2, b"readme.txt")
                    .map_err(|errno| anyhow::anyhow!("fuse lookup_for_fuzzing errno {errno}"))?;
                *cached_fuse = Some((fuse, attr.ino.0));
            }
            let (fuse, ino) = cached_fuse
                .as_ref()
                .context("cached fuse adapter missing")?;
            let data = fuse
                .read_for_fuzzing(*ino, 0, 1024 * 1024)
                .map_err(|errno| anyhow::anyhow!("fuse read_for_fuzzing errno {errno}"))?;
            u64::try_from(black_box(data.len())).unwrap_or(u64::MAX)
        }
    };

    Ok(checksum)
}

fn profile_read_path_cmd(args: &[String]) -> Result<()> {
    let args = parse_profile_read_path_args(args)?;
    if args.iterations == Some(0) {
        return Ok(());
    }

    let cx = Cx::for_testing();
    let deadline = Instant::now() + args.duration;
    let mut cached_fs = None;
    let mut cached_fuse = None;
    let mut iterations = 0_u64;
    let mut checksum = 0_u64;

    loop {
        checksum ^= profile_read_path_iteration(&cx, &args, &mut cached_fs, &mut cached_fuse)?;
        iterations = iterations.saturating_add(1);
        if args.iterations.is_some_and(|limit| iterations >= limit) || Instant::now() >= deadline {
            break;
        }
    }

    let report = ProfileReadPathReport {
        mode: args.mode.label().to_owned(),
        fixture: args.fixture.display().to_string(),
        duration_ms: args.duration.as_millis(),
        iterations,
        checksum,
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadinessReportFormat {
    Json,
    Markdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofBundleFormat {
    Json,
    Markdown,
}

#[derive(Debug)]
struct ReleaseGateCmdArgs {
    bundle_path: String,
    policy_path: String,
    current_git_sha: Option<String>,
    max_age_days: Option<u64>,
    out_path: Option<String>,
    wording_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct PerformanceManifestCmdArgs {
    manifest_path: Option<String>,
    manifest_json_env: Option<String>,
    artifact_root: String,
    out_path: Option<String>,
    artifact_out_path: Option<String>,
}

#[derive(Debug)]
struct PerformanceDeltaCloseoutCmdArgs {
    config_path: String,
    issues_path: Option<String>,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct AdversarialThreatModelCmdArgs {
    model_path: Option<String>,
    model_json_env: Option<String>,
    artifact_root: String,
    out_path: Option<String>,
    artifact_out_path: Option<String>,
    wording_out_path: Option<String>,
}

#[derive(Debug)]
struct SoakCanaryCampaignCmdArgs {
    manifest_path: String,
    artifact_root: String,
    out_path: Option<String>,
    artifact_out_path: Option<String>,
    summary_out_path: Option<String>,
}

#[derive(Debug)]
struct RepairWritebackSerializationCmdArgs {
    contract_path: Option<String>,
    contract_json_env: Option<String>,
    artifact_root: String,
    out_path: Option<String>,
    artifact_out_path: Option<String>,
    summary_out_path: Option<String>,
    proof_summary_out_path: Option<String>,
}

#[derive(Debug)]
struct ArtifactSchemaFixturesCmdArgs {
    fixture_dir: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    reproduction_command: String,
}

#[derive(Debug)]
struct WritebackCacheAuditCmdArgs {
    gate_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    scenario_id: String,
    reproduction_command: Option<String>,
    require_accept: bool,
}

#[derive(Debug)]
struct WritebackCacheOrderingCmdArgs {
    oracle_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    scenario_id: String,
    reproduction_command: Option<String>,
    require_accept: bool,
}

#[derive(Debug)]
struct WritebackCacheCrashReplayCmdArgs {
    oracle_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    scenario_id: String,
    reproduction_command: Option<String>,
    require_accept: bool,
}

#[derive(Debug)]
struct RepairConfidenceLabCmdArgs {
    spec_path: String,
    spec_json_env: Option<String>,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct OperatorRecoveryDrillCmdArgs {
    spec_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct WorkloadCorpusCmdArgs {
    corpus_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    selected_scenario_id: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct BtrfsSendReceiveCorpusCmdArgs {
    corpus_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct BtrfsMultideviceCorpusCmdArgs {
    corpus_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct CasefoldCorpusCmdArgs {
    corpus_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct FaultInjectionCorpusCmdArgs {
    corpus_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct RepairCorpusCmdArgs {
    corpus_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct ChaosReplayLabCmdArgs {
    lab_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct InventoryCloseoutGateCmdArgs {
    gate_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct ReportSchemaInventoryCmdArgs {
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct RemediationSeverityGateCmdArgs {
    gate_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct MountedCheckpointSurvivorCmdArgs {
    matrix_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct MountedRepairMutationBoundaryCmdArgs {
    matrix_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct LowPrivilegeDemoCmdArgs {
    manifest_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct LowPrivilegeDemoSandboxCmdArgs {
    manifest_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct MetamorphicWorkloadSeedCatalogCmdArgs {
    catalog_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct SwarmCacheControllerCmdArgs {
    contract_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct SwarmOperatorReportCmdArgs {
    report_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct SwarmTailLatencyCmdArgs {
    ledger_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct SwarmWorkloadHarnessCmdArgs {
    manifest_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
    max_age_days: u32,
    reference_timestamp: Option<String>,
}

#[derive(Debug)]
struct WalGroupCommitGateCmdArgs {
    manifest_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct ScrubRepairSchedulerCmdArgs {
    manifest_path: String,
    out_path: Option<String>,
    summary_out_path: Option<String>,
    format: ProofBundleFormat,
}

fn validate_workload_corpus_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_workload_corpus_cmd_args(args)? else {
        return Ok(());
    };
    let corpus = load_workload_corpus(Path::new(&cmd_args.corpus_path))?;
    if let Some(scenario_id) = cmd_args.selected_scenario_id.as_deref() {
        validate_selected_workload_scenario(&corpus, scenario_id)?;
    }
    let report = validate_workload_corpus(&corpus);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_workload_corpus_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "workload corpus report written: {} valid={} scenarios={}",
            path, report.valid, report.scenario_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_workload_corpus_markdown(&report)),
        )?;
        println!("workload corpus summary written: {path}");
    }

    fail_on_workload_corpus_errors(&report)
}

fn parse_workload_corpus_cmd_args(args: &[String]) -> Result<Option<WorkloadCorpusCmdArgs>> {
    let mut corpus_path = DEFAULT_WORKLOAD_CORPUS_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut selected_scenario_id: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--corpus" => {
                i += 1;
                args.get(i)
                    .context("--corpus requires a path")?
                    .clone_into(&mut corpus_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--select" => {
                i += 1;
                selected_scenario_id = Some(
                    args.get(i)
                        .context("--select requires a scenario id")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_workload_corpus_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-workload-corpus argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(WorkloadCorpusCmdArgs {
        corpus_path,
        out_path,
        summary_out_path,
        selected_scenario_id,
        format,
    }))
}

fn validate_btrfs_send_receive_corpus_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_btrfs_send_receive_corpus_cmd_args(args)? else {
        return Ok(());
    };
    let corpus = load_btrfs_send_receive_corpus(Path::new(&cmd_args.corpus_path))?;
    let report = validate_btrfs_send_receive_corpus(&corpus);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_btrfs_send_receive_corpus_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "btrfs send/receive corpus report written: {} valid={} cases={}",
            path, report.valid, report.case_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_btrfs_send_receive_corpus_markdown(&report)),
        )?;
        println!("btrfs send/receive corpus summary written: {path}");
    }

    fail_on_btrfs_send_receive_corpus_errors(&report)
}

fn parse_btrfs_send_receive_corpus_cmd_args(
    args: &[String],
) -> Result<Option<BtrfsSendReceiveCorpusCmdArgs>> {
    let mut corpus_path = DEFAULT_BTRFS_SEND_RECEIVE_CORPUS_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--corpus" => {
                i += 1;
                args.get(i)
                    .context("--corpus requires a path")?
                    .clone_into(&mut corpus_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_btrfs_send_receive_corpus_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-btrfs-send-receive-corpus argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(BtrfsSendReceiveCorpusCmdArgs {
        corpus_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_btrfs_multidevice_corpus_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_btrfs_multidevice_corpus_cmd_args(args)? else {
        return Ok(());
    };
    let corpus = load_btrfs_multidev_corpus(Path::new(&cmd_args.corpus_path))?;
    let report = validate_btrfs_multidev_corpus(&corpus);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_btrfs_multidev_corpus_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "btrfs multi-device corpus report written: {} valid={} scenarios={}",
            path, report.valid, report.scenario_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_btrfs_multidev_corpus_markdown(&report)),
        )?;
        println!("btrfs multi-device corpus summary written: {path}");
    }

    fail_on_btrfs_multidev_corpus_errors(&report)
}

fn parse_btrfs_multidevice_corpus_cmd_args(
    args: &[String],
) -> Result<Option<BtrfsMultideviceCorpusCmdArgs>> {
    let mut corpus_path = DEFAULT_BTRFS_MULTIDEV_CORPUS_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--corpus" => {
                i += 1;
                args.get(i)
                    .context("--corpus requires a path")?
                    .clone_into(&mut corpus_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_btrfs_multidevice_corpus_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-btrfs-multidevice-corpus argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(BtrfsMultideviceCorpusCmdArgs {
        corpus_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_casefold_corpus_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_casefold_corpus_cmd_args(args)? else {
        return Ok(());
    };
    let corpus = load_casefold_corpus(Path::new(&cmd_args.corpus_path))?;
    let report = validate_casefold_corpus(&corpus);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_casefold_corpus_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "casefold corpus report written: {} valid={} cases={}",
            path, report.valid, report.case_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_casefold_corpus_markdown(&report)),
        )?;
        println!("casefold corpus summary written: {path}");
    }

    fail_on_casefold_corpus_errors(&report)
}

fn parse_casefold_corpus_cmd_args(args: &[String]) -> Result<Option<CasefoldCorpusCmdArgs>> {
    let mut corpus_path = DEFAULT_CASEFOLD_CORPUS_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--corpus" => {
                i += 1;
                args.get(i)
                    .context("--corpus requires a path")?
                    .clone_into(&mut corpus_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_casefold_corpus_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-casefold-corpus argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(CasefoldCorpusCmdArgs {
        corpus_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_fault_injection_corpus_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_fault_injection_corpus_cmd_args(args)? else {
        return Ok(());
    };
    let corpus = load_fault_injection_corpus(Path::new(&cmd_args.corpus_path))?;
    let report = validate_fault_injection_corpus(&corpus);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_fault_injection_corpus_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "fault injection corpus report written: {} valid={} cases={}",
            path, report.valid, report.case_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_fault_injection_corpus_markdown(&report)),
        )?;
        println!("fault injection corpus summary written: {path}");
    }

    fail_on_fault_injection_corpus_errors(&report)
}

fn parse_fault_injection_corpus_cmd_args(
    args: &[String],
) -> Result<Option<FaultInjectionCorpusCmdArgs>> {
    let mut corpus_path = DEFAULT_FAULT_INJECTION_CORPUS_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--corpus" => {
                i += 1;
                args.get(i)
                    .context("--corpus requires a path")?
                    .clone_into(&mut corpus_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_fault_injection_corpus_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-fault-injection-corpus argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(FaultInjectionCorpusCmdArgs {
        corpus_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_repair_corpus_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_repair_corpus_cmd_args(args)? else {
        return Ok(());
    };
    let corpus = load_repair_corpus(Path::new(&cmd_args.corpus_path))?;
    let report = validate_repair_corpus(&corpus);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_repair_corpus_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "repair corpus report written: {} valid={} cases={}",
            path, report.valid, report.case_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_repair_corpus_markdown(&report)),
        )?;
        println!("repair corpus summary written: {path}");
    }

    fail_on_repair_corpus_errors(&report)
}

fn parse_repair_corpus_cmd_args(args: &[String]) -> Result<Option<RepairCorpusCmdArgs>> {
    let mut corpus_path = DEFAULT_REPAIR_CORPUS_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--corpus" => {
                i += 1;
                args.get(i)
                    .context("--corpus requires a path")?
                    .clone_into(&mut corpus_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_repair_corpus_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-repair-corpus argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(RepairCorpusCmdArgs {
        corpus_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_mounted_checkpoint_survivor_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_mounted_checkpoint_survivor_cmd_args(args)? else {
        return Ok(());
    };
    let matrix = load_mounted_checkpoint_survivor(Path::new(&cmd_args.matrix_path))?;
    let report = validate_mounted_checkpoint_survivor(&matrix);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_mounted_checkpoint_survivor_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "mounted checkpoint survivor report written: {} valid={} scenarios={}",
            path, report.valid, report.scenario_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_mounted_checkpoint_survivor_markdown(&report)),
        )?;
        println!("mounted checkpoint survivor summary written: {path}");
    }

    fail_on_mounted_checkpoint_survivor_errors(&report)
}

fn parse_mounted_checkpoint_survivor_cmd_args(
    args: &[String],
) -> Result<Option<MountedCheckpointSurvivorCmdArgs>> {
    let mut matrix_path = DEFAULT_MOUNTED_CHECKPOINT_SURVIVOR_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--matrix" => {
                i += 1;
                args.get(i)
                    .context("--matrix requires a path")?
                    .clone_into(&mut matrix_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_mounted_checkpoint_survivor_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-mounted-checkpoint-survivor argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(MountedCheckpointSurvivorCmdArgs {
        matrix_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_low_privilege_demo_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_low_privilege_demo_cmd_args(args)? else {
        return Ok(());
    };
    let manifest = load_low_privilege_demo_manifest(Path::new(&cmd_args.manifest_path))?;
    let report = validate_low_privilege_demo_manifest(&manifest);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_low_privilege_demo_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "low-privilege demo report written: {} valid={} lanes={}",
            path, report.valid, report.lane_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_low_privilege_demo_markdown(&report)),
        )?;
        println!("low-privilege demo summary written: {path}");
    }

    fail_on_low_privilege_demo_errors(&report)
}

fn parse_low_privilege_demo_cmd_args(args: &[String]) -> Result<Option<LowPrivilegeDemoCmdArgs>> {
    let mut manifest_path = DEFAULT_LOW_PRIVILEGE_DEMO_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                args.get(i)
                    .context("--manifest requires a path")?
                    .clone_into(&mut manifest_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_low_privilege_demo_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-low-privilege-demo argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(LowPrivilegeDemoCmdArgs {
        manifest_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_low_privilege_demo_sandbox_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_low_privilege_demo_sandbox_cmd_args(args)? else {
        return Ok(());
    };
    let manifest = load_low_privilege_demo_sandbox(Path::new(&cmd_args.manifest_path))?;
    let report = validate_low_privilege_demo_sandbox(&manifest);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_low_privilege_demo_sandbox_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "low-privilege demo sandbox report written: {} valid={} lanes={}",
            path, report.valid, report.lane_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_low_privilege_demo_sandbox_markdown(&report)),
        )?;
        println!("low-privilege demo sandbox summary written: {path}");
    }

    fail_on_low_privilege_demo_sandbox_errors(&report)
}

fn parse_low_privilege_demo_sandbox_cmd_args(
    args: &[String],
) -> Result<Option<LowPrivilegeDemoSandboxCmdArgs>> {
    let mut manifest_path = DEFAULT_LOW_PRIVILEGE_DEMO_SANDBOX_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                args.get(i)
                    .context("--manifest requires a path")?
                    .clone_into(&mut manifest_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_low_privilege_demo_sandbox_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-low-privilege-demo-sandbox argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(LowPrivilegeDemoSandboxCmdArgs {
        manifest_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_metamorphic_workload_seed_catalog_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_metamorphic_workload_seed_catalog_cmd_args(args)? else {
        return Ok(());
    };
    let catalog = load_metamorphic_workload_seed_catalog(Path::new(&cmd_args.catalog_path))?;
    let report = validate_metamorphic_workload_seed_catalog(&catalog);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_metamorphic_workload_seed_catalog_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "metamorphic workload seed catalog report written: {} valid={} seeds={}",
            path, report.valid, report.seed_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!(
                "{}\n",
                render_metamorphic_workload_seed_catalog_markdown(&report)
            ),
        )?;
        println!("metamorphic workload seed catalog summary written: {path}");
    }

    fail_on_metamorphic_workload_seed_catalog_errors(&report)
}

fn parse_metamorphic_workload_seed_catalog_cmd_args(
    args: &[String],
) -> Result<Option<MetamorphicWorkloadSeedCatalogCmdArgs>> {
    let mut catalog_path = DEFAULT_METAMORPHIC_WORKLOAD_SEED_CATALOG_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--catalog" => {
                i += 1;
                args.get(i)
                    .context("--catalog requires a path")?
                    .clone_into(&mut catalog_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_metamorphic_workload_seed_catalog_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-metamorphic-workload-seeds argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(MetamorphicWorkloadSeedCatalogCmdArgs {
        catalog_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn operational_readiness_report_cmd(args: &[String]) -> Result<()> {
    let mut config = OperationalReadinessReportConfig::new("artifacts/e2e");
    let mut out_path: Option<String> = None;
    let mut format = ReadinessReportFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--artifacts" => {
                i += 1;
                config.artifacts_dir =
                    Path::new(args.get(i).context("--artifacts requires a path")?).to_path_buf();
            }
            "--current-git-sha" => {
                i += 1;
                config.current_git_sha = Some(
                    args.get(i)
                        .context("--current-git-sha requires a value")?
                        .to_owned(),
                );
            }
            "--max-age-days" => {
                i += 1;
                config.max_artifact_age_days = Some(
                    args.get(i)
                        .context("--max-age-days requires a value")?
                        .parse::<u32>()
                        .context("invalid --max-age-days value")?,
                );
            }
            "--recency-reference-timestamp" => {
                i += 1;
                let timestamp = args
                    .get(i)
                    .context("--recency-reference-timestamp requires a value")?;
                config.recency_reference_epoch_days = Some(
                    parse_manifest_timestamp_epoch_days(timestamp).with_context(|| {
                        format!("invalid --recency-reference-timestamp value: {timestamp}")
                    })?,
                );
            }
            "--format" => {
                i += 1;
                format = parse_readiness_report_format(
                    args.get(i).context("--format requires json or markdown")?,
                )?;
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--help" | "-h" => {
                print_operational_readiness_report_usage();
                return Ok(());
            }
            other => bail!("unknown operational-readiness-report argument: {other}"),
        }
        i += 1;
    }

    let report = build_operational_readiness_report(&config)?;
    let output = match format {
        ReadinessReportFormat::Json => serde_json::to_string_pretty(&report)?,
        ReadinessReportFormat::Markdown => render_operational_readiness_markdown(&report),
    };

    if let Some(path) = out_path {
        let path = Path::new(&path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, format!("{output}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "{}",
            operational_readiness_report_summary(&report, &path.display().to_string())
        );
    } else {
        println!("{output}");
        std::io::stdout().flush().ok();
        eprintln!(
            "{}",
            operational_readiness_report_summary(&report, "<stdout>")
        );
    }
    Ok(())
}

fn operational_readiness_report_summary(
    report: &ffs_harness::operational_readiness_report::OperationalReadinessReport,
    output_path: &str,
) -> String {
    let rejected_event_diagnostics = report
        .contract_violations
        .iter()
        .filter(|violation| {
            matches!(
                violation.remediation_id.as_str(),
                "bd-slp26:manifest-validation"
            )
        })
        .count();
    format!(
        "operational readiness report written: {output_path} scenarios={} envelope_version={} event_count={} lane_ids={} rejected_event_diagnostics={} stale_artifacts={} invalid_timestamps={} correlation_graph=event_nodes:{} parent_edges:{} orphan_parent_edges:{} aggregate_events:{} reproduction_commands={} output_path={output_path}",
        report.scenario_count,
        READINESS_EVENT_ENVELOPE_VERSION,
        report.readiness_event_count,
        report.readiness_event_lane_ids.join(","),
        rejected_event_diagnostics,
        report.stale_artifacts.len(),
        report.invalid_artifact_timestamps.len(),
        report.correlation_graph_summary.event_nodes,
        report.correlation_graph_summary.parent_edges,
        report.correlation_graph_summary.orphan_parent_edges,
        report.correlation_graph_summary.aggregate_events,
        report
            .scenarios
            .iter()
            .filter(|row| row.reproduction_command.is_some())
            .count(),
    )
}

fn operational_evidence_index_cmd(args: &[String]) -> Result<()> {
    let mut config = OperationalEvidenceIndexConfig::new("artifacts/e2e");
    let mut out_path: Option<String> = None;
    let mut format = ReadinessReportFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--artifacts" => {
                i += 1;
                config.artifacts_dir =
                    Path::new(args.get(i).context("--artifacts requires a path")?).to_path_buf();
            }
            "--current-git-sha" => {
                i += 1;
                config.current_git_sha = Some(
                    args.get(i)
                        .context("--current-git-sha requires a value")?
                        .to_owned(),
                );
            }
            "--max-age-days" => {
                i += 1;
                config.max_artifact_age_days = Some(
                    args.get(i)
                        .context("--max-age-days requires a value")?
                        .parse::<u32>()
                        .context("invalid --max-age-days value")?,
                );
            }
            "--recency-reference-timestamp" => {
                i += 1;
                let timestamp = args
                    .get(i)
                    .context("--recency-reference-timestamp requires a value")?;
                config.recency_reference_epoch_days = Some(
                    parse_manifest_timestamp_epoch_days(timestamp).with_context(|| {
                        format!("invalid --recency-reference-timestamp value: {timestamp}")
                    })?,
                );
            }
            "--format" => {
                i += 1;
                format = parse_readiness_report_format(
                    args.get(i).context("--format requires json or markdown")?,
                )?;
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--help" | "-h" => {
                print_operational_evidence_index_usage();
                return Ok(());
            }
            other => bail!("unknown operational-evidence-index argument: {other}"),
        }
        i += 1;
    }

    let index = build_operational_evidence_index(&config)?;
    let output = match format {
        ReadinessReportFormat::Json => serde_json::to_string_pretty(&index)?,
        ReadinessReportFormat::Markdown => render_operational_evidence_index_markdown(&index),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "{}",
            operational_evidence_index_summary(&index, path.as_str())
        );
    } else {
        println!("{output}");
        std::io::stdout().flush().ok();
        eprintln!("{}", operational_evidence_index_summary(&index, "<stdout>"));
    }
    Ok(())
}

fn operational_evidence_index_summary(
    index: &ffs_harness::operational_evidence_index::OperationalEvidenceIndex,
    output_path: &str,
) -> String {
    format!(
        "operational evidence index written: {output_path} records={} authoritative={} selected={} stale={} missing_raw_logs={} conflicts={} duplicate_run_ids={} host_downgrades={} output_path={output_path}",
        index.source_record_count,
        index.authoritative_record_count,
        index.selected_record_count,
        index.stale_record_count,
        index.missing_raw_log_record_count,
        index.conflict_count,
        index.duplicate_run_id_count,
        index.host_downgrade_count
    )
}

#[allow(clippy::too_many_lines)]
fn readiness_dashboard_cmd(args: &[String]) -> Result<()> {
    let mut config = ReadinessDashboardConfig::default();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ReadinessReportFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--proof-bundle-report" => {
                i += 1;
                config.proof_bundle_reports.push(PathBuf::from(
                    args.get(i)
                        .context("--proof-bundle-report requires a path")?
                        .as_str(),
                ));
            }
            "--release-gate-report" => {
                i += 1;
                config.release_gate_reports.push(PathBuf::from(
                    args.get(i)
                        .context("--release-gate-report requires a path")?
                        .as_str(),
                ));
            }
            "--operational-evidence-index" => {
                i += 1;
                config.operational_evidence_indexes.push(PathBuf::from(
                    args.get(i)
                        .context("--operational-evidence-index requires a path")?
                        .as_str(),
                ));
            }
            "--permissioned-campaign-report" => {
                i += 1;
                config.permissioned_campaign_reports.push(PathBuf::from(
                    args.get(i)
                        .context("--permissioned-campaign-report requires a path")?
                        .as_str(),
                ));
            }
            "--readiness-lab-report" => {
                i += 1;
                config.readiness_lab_reports.push(PathBuf::from(
                    args.get(i)
                        .context("--readiness-lab-report requires a path")?
                        .as_str(),
                ));
            }
            "--beads" => {
                i += 1;
                config.beads_path = Some(PathBuf::from(
                    args.get(i).context("--beads requires a path")?.as_str(),
                ));
            }
            "--default-remediation-bead" => {
                i += 1;
                config.default_remediation_bead = Some(
                    args.get(i)
                        .context("--default-remediation-bead requires a value")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format = parse_readiness_report_format(
                    args.get(i).context("--format requires json or markdown")?,
                )?;
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_readiness_dashboard_usage();
                return Ok(());
            }
            other => bail!("unknown readiness-dashboard argument: {other}"),
        }
        i += 1;
    }

    let report = build_readiness_dashboard(&config)?;
    let json = serde_json::to_string_pretty(&report)?;
    let markdown = render_readiness_dashboard_markdown(&report);
    let output = match format {
        ReadinessReportFormat::Json => json.as_str(),
        ReadinessReportFormat::Markdown => markdown.as_str(),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!("{}", readiness_dashboard_summary(&report, path.as_str()));
    } else {
        println!("{output}");
        std::io::stdout().flush().ok();
        eprintln!("{}", readiness_dashboard_summary(&report, "<stdout>"));
    }

    if let Some(path) = summary_out_path {
        write_text_file(Path::new(&path), &format!("{markdown}\n"))?;
        println!("readiness dashboard summary written: {path}");
    }

    Ok(())
}

fn readiness_dashboard_summary(
    report: &ffs_harness::readiness_dashboard::ReadinessDashboardReport,
    output_path: &str,
) -> String {
    format!(
        "readiness dashboard written: {output_path} valid={} sources={} source_validator_failures={} claims={} recommendations={} tracker_follow_up_beads={} output_path={output_path}",
        report.valid,
        report.source_report_count,
        report.source_validator_failure_count,
        report.claim_count,
        report.recommendation_count,
        report.tracker_follow_up_beads.len()
    )
}

fn validate_readiness_lab_contracts_cmd(args: &[String]) -> Result<()> {
    let mut manifest_path: Option<String> = None;
    let mut reference_epoch_days: Option<u32> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ReadinessReportFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest_path = Some(
                    args.get(i)
                        .context("--manifest requires a path")?
                        .to_owned(),
                );
            }
            "--reference-epoch-days" => {
                i += 1;
                reference_epoch_days = Some(
                    args.get(i)
                        .context("--reference-epoch-days requires a value")?
                        .parse()
                        .context("invalid --reference-epoch-days value")?,
                );
            }
            "--format" => {
                i += 1;
                format = parse_readiness_report_format(
                    args.get(i).context("--format requires json or markdown")?,
                )?;
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_readiness_lab_contracts_usage();
                return Ok(());
            }
            other => bail!("unknown validate-readiness-lab-contracts argument: {other}"),
        }
        i += 1;
    }

    let manifest_path = manifest_path.context("--manifest is required")?;
    let bundle = load_readiness_lab_contract_bundle(&manifest_path)?;
    let config = ReadinessLabValidationConfig {
        manifest_path,
        reference_epoch_days,
    };
    let report = validate_readiness_lab_contract_bundle(&bundle, &config);
    let json = serde_json::to_string_pretty(&report)?;
    let markdown = render_readiness_lab_contract_markdown(&report);
    let output = match format {
        ReadinessReportFormat::Json => json.as_str(),
        ReadinessReportFormat::Markdown => markdown.as_str(),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "readiness lab contract report written: {path} valid={} artifacts={} lanes={} errors={}",
            report.valid,
            report.artifact_count,
            report.lane_count,
            report.errors.len()
        );
    } else {
        println!("{output}");
        std::io::stdout().flush().ok();
    }

    if let Some(path) = summary_out_path {
        write_text_file(Path::new(&path), &format!("{markdown}\n"))?;
        println!("readiness lab contract summary written: {path}");
    }

    fail_on_readiness_lab_contract_errors(&report)
}

fn print_readiness_lab_contracts_usage() {
    println!(
        "ffs-harness validate-readiness-lab-contracts --manifest FILE [--reference-epoch-days N] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  Validates advisory-only readiness-lab artifacts; it never runs permissioned campaigns."
    );
}

fn simulate_readiness_lab_hosts_cmd(args: &[String]) -> Result<()> {
    let mut manifest_path: Option<String> = None;
    let mut reference_epoch_days: Option<u32> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ReadinessReportFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest_path = Some(
                    args.get(i)
                        .context("--manifest requires a path")?
                        .to_owned(),
                );
            }
            "--reference-epoch-days" => {
                i += 1;
                reference_epoch_days = Some(
                    args.get(i)
                        .context("--reference-epoch-days requires a value")?
                        .parse()
                        .context("invalid --reference-epoch-days value")?,
                );
            }
            "--format" => {
                i += 1;
                format = parse_readiness_report_format(
                    args.get(i).context("--format requires json or markdown")?,
                )?;
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_readiness_lab_host_simulation_usage();
                return Ok(());
            }
            other => bail!("unknown simulate-readiness-lab-hosts argument: {other}"),
        }
        i += 1;
    }

    let manifest_path = manifest_path.context("--manifest is required")?;
    let manifest = load_readiness_lab_host_simulation_manifest(&manifest_path)?;
    let config = ReadinessLabHostSimulationConfig {
        manifest_path,
        reference_epoch_days,
    };
    let report = simulate_readiness_lab_hosts(&manifest, &config);
    let json = serde_json::to_string_pretty(&report)?;
    let markdown = render_readiness_lab_host_simulation_markdown(&report);
    let output = match format {
        ReadinessReportFormat::Json => json.as_str(),
        ReadinessReportFormat::Markdown => markdown.as_str(),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "readiness lab host simulation report written: {path} valid={} hosts={} candidates={} blocked={}",
            report.valid, report.host_count, report.candidate_count, report.blocked_count
        );
    } else {
        println!("{output}");
        std::io::stdout().flush().ok();
    }

    if let Some(path) = summary_out_path {
        write_text_file(Path::new(&path), &format!("{markdown}\n"))?;
        println!("readiness lab host simulation summary written: {path}");
    }

    fail_on_readiness_lab_host_simulation_errors(&report)
}

fn print_readiness_lab_host_simulation_usage() {
    println!(
        "ffs-harness simulate-readiness-lab-hosts --manifest FILE [--reference-epoch-days N] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!("  Classifies synthetic host inventories as advisory readiness-lab material only.");
}

fn plan_readiness_lab_rch_lanes_cmd(args: &[String]) -> Result<()> {
    let mut manifest_path: Option<String> = None;
    let mut reference_epoch_days: Option<u32> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ReadinessReportFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest_path = Some(
                    args.get(i)
                        .context("--manifest requires a path")?
                        .to_owned(),
                );
            }
            "--reference-epoch-days" => {
                i += 1;
                reference_epoch_days = Some(
                    args.get(i)
                        .context("--reference-epoch-days requires a value")?
                        .parse()
                        .context("invalid --reference-epoch-days value")?,
                );
            }
            "--format" => {
                i += 1;
                format = parse_readiness_report_format(
                    args.get(i).context("--format requires json or markdown")?,
                )?;
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_readiness_lab_rch_lane_schedule_usage();
                return Ok(());
            }
            other => bail!("unknown plan-readiness-lab-rch-lanes argument: {other}"),
        }
        i += 1;
    }

    let manifest_path = manifest_path.context("--manifest is required")?;
    let manifest = load_readiness_lab_rch_lane_schedule_manifest(&manifest_path)?;
    let config = ReadinessLabRchLaneScheduleConfig {
        manifest_path,
        reference_epoch_days,
    };
    let report = plan_readiness_lab_rch_lanes(&manifest, &config);
    let json = serde_json::to_string_pretty(&report)?;
    let markdown = render_readiness_lab_rch_lane_schedule_markdown(&report);
    let output = match format {
        ReadinessReportFormat::Json => json.as_str(),
        ReadinessReportFormat::Markdown => markdown.as_str(),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "readiness lab RCH lane schedule written: {path} valid={} lanes={} planned={} coalesced={}",
            report.valid,
            report.lane_count,
            report.planned_lane_count,
            report.coalesced_duplicate_count
        );
    } else {
        println!("{output}");
        std::io::stdout().flush().ok();
    }

    if let Some(path) = summary_out_path {
        write_text_file(Path::new(&path), &format!("{markdown}\n"))?;
        println!("readiness lab RCH lane schedule summary written: {path}");
    }

    fail_on_readiness_lab_rch_lane_schedule_errors(&report)
}

fn print_readiness_lab_rch_lane_schedule_usage() {
    println!(
        "ffs-harness plan-readiness-lab-rch-lanes --manifest FILE [--reference-epoch-days N] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!("  Emits a dry-run RCH validation lane schedule; it never executes planned lanes.");
}

fn build_readiness_lab_truth_graph_cmd(args: &[String]) -> Result<()> {
    let mut manifest_path: Option<String> = None;
    let mut reference_epoch_days: Option<u32> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ReadinessReportFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest_path = Some(
                    args.get(i)
                        .context("--manifest requires a path")?
                        .to_owned(),
                );
            }
            "--reference-epoch-days" => {
                i += 1;
                reference_epoch_days = Some(
                    args.get(i)
                        .context("--reference-epoch-days requires a value")?
                        .parse()
                        .context("invalid --reference-epoch-days value")?,
                );
            }
            "--format" => {
                i += 1;
                format = parse_readiness_report_format(
                    args.get(i).context("--format requires json or markdown")?,
                )?;
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_readiness_lab_truth_graph_usage();
                return Ok(());
            }
            other => bail!("unknown build-readiness-lab-truth-graph argument: {other}"),
        }
        i += 1;
    }

    let manifest_path = manifest_path.context("--manifest is required")?;
    let manifest = load_readiness_lab_truth_graph_manifest(&manifest_path)?;
    let config = ReadinessLabTruthGraphConfig {
        manifest_path,
        reference_epoch_days,
    };
    let report = ffs_harness::readiness_lab::build_readiness_lab_truth_graph(&manifest, &config);
    let json = serde_json::to_string_pretty(&report)?;
    let markdown = render_readiness_lab_truth_graph_markdown(&report);
    let output = match format {
        ReadinessReportFormat::Json => json.as_str(),
        ReadinessReportFormat::Markdown => markdown.as_str(),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "readiness lab truth graph written: {path} valid={} sources={} claims={} nodes={} edges={} blockers={}",
            report.valid,
            report.source_count,
            report.claim_count,
            report.node_count,
            report.edge_count,
            report.blocker_edge_count
        );
    } else {
        println!("{output}");
        std::io::stdout().flush().ok();
    }

    if let Some(path) = summary_out_path {
        write_text_file(Path::new(&path), &format!("{markdown}\n"))?;
        println!("readiness lab truth graph summary written: {path}");
    }

    fail_on_readiness_lab_truth_graph_errors(&report)
}

fn print_readiness_lab_truth_graph_usage() {
    println!(
        "ffs-harness build-readiness-lab-truth-graph --manifest FILE [--reference-epoch-days N] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!("  Emits a read-only evidence truth graph over readiness/proof/lab summaries.");
}

fn validate_readiness_lab_numa_p99_replay_cmd(args: &[String]) -> Result<()> {
    let mut manifest_path: Option<String> = None;
    let mut reference_epoch_days: Option<u32> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ReadinessReportFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest_path = Some(
                    args.get(i)
                        .context("--manifest requires a path")?
                        .to_owned(),
                );
            }
            "--reference-epoch-days" => {
                i += 1;
                reference_epoch_days = Some(
                    args.get(i)
                        .context("--reference-epoch-days requires a value")?
                        .parse()
                        .context("invalid --reference-epoch-days value")?,
                );
            }
            "--format" => {
                i += 1;
                format = parse_readiness_report_format(
                    args.get(i).context("--format requires json or markdown")?,
                )?;
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--select" => {
                i += 1;
                let _ = args.get(i).context("--select requires a fixture id")?;
            }
            "--help" | "-h" => {
                print_readiness_lab_numa_p99_replay_usage();
                return Ok(());
            }
            other => bail!("unknown validate-readiness-lab-numa-p99-replay argument: {other}"),
        }
        i += 1;
    }

    let manifest_path =
        manifest_path.unwrap_or_else(|| DEFAULT_READINESS_LAB_NUMA_P99_REPLAY_MANIFEST.to_owned());
    let manifest = load_readiness_lab_numa_p99_replay_manifest(&manifest_path)?;
    let config = ReadinessLabNumaP99ReplayConfig {
        manifest_path,
        reference_epoch_days,
    };
    let report = validate_readiness_lab_numa_p99_replay(&manifest, &config);
    let json = serde_json::to_string_pretty(&report)?;
    let markdown = render_readiness_lab_numa_p99_replay_markdown(&report);
    let output = match format {
        ReadinessReportFormat::Json => json.as_str(),
        ReadinessReportFormat::Markdown => markdown.as_str(),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "readiness lab NUMA/p99 replay report written: {path} valid={} fixtures={} invalid={} missing_p99={}",
            report.valid,
            report.fixture_count,
            report.invalid_fixture_count,
            report.missing_p99_bucket_count
        );
    } else {
        println!("{output}");
        std::io::stdout().flush().ok();
    }

    if let Some(path) = summary_out_path {
        write_text_file(Path::new(&path), &format!("{markdown}\n"))?;
        println!("readiness lab NUMA/p99 replay summary written: {path}");
    }

    fail_on_readiness_lab_numa_p99_replay_errors(&report)
}

fn print_readiness_lab_numa_p99_replay_usage() {
    println!(
        "ffs-harness validate-readiness-lab-numa-p99-replay [--manifest FILE] [--reference-epoch-days N] [--format json|markdown] [--out FILE] [--summary-out FILE] [--select FIXTURE_ID]"
    );
    println!(
        "  Validates advisory NUMA/p99 replay fixtures; it never executes workload lanes or changes public readiness."
    );
}

fn print_readiness_dashboard_usage() {
    println!(
        "ffs-harness readiness-dashboard [--proof-bundle-report FILE ...] [--release-gate-report FILE ...] [--operational-evidence-index FILE ...] [--permissioned-campaign-report FILE ...] [--readiness-lab-report FILE ...] [--beads FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  Renders a read-only operator dashboard over strict validator reports; it never upgrades readiness on its own."
    );
}

fn recommend_readiness_actions_cmd(args: &[String]) -> Result<()> {
    let Some(config) = parse_recommend_readiness_actions_args(args)? else {
        return Ok(());
    };
    let mut input = load_readiness_action_planning_input(&config)?;
    if let Some(report_id) = &config.report_id {
        input.report_id.clone_from(report_id);
    }
    if let Some(generated_at) = &config.generated_at {
        input.generated_at.clone_from(generated_at);
    }

    let metadata = readiness_action_dry_run_metadata(&config);
    let report = build_readiness_action_dry_run_report(&input, metadata);
    let json = serde_json::to_string_pretty(&report)?;
    let markdown = render_readiness_action_dry_run_markdown(&report);
    let stdout_log = readiness_action_dry_run_stdout_log(&report);
    let stderr_log = readiness_action_dry_run_stderr_log(&report);

    write_text_file(Path::new(&config.out_json_path), &format!("{json}\n"))?;
    write_text_file(
        Path::new(&config.out_markdown_path),
        &format!("{markdown}\n"),
    )?;
    write_text_file(Path::new(&config.stdout_log_path), &stdout_log)?;
    write_text_file(Path::new(&config.stderr_log_path), &stderr_log)?;

    println!("{}", readiness_action_dry_run_summary(&report));
    Ok(())
}

fn parse_recommend_readiness_actions_args(
    args: &[String],
) -> Result<Option<RecommendReadinessActionsCmdArgs>> {
    let mut input_path = None;
    let mut out_json_path = None;
    let mut out_markdown_path = None;
    let mut stdout_log_path = None;
    let mut stderr_log_path = None;
    let mut report_id = None;
    let mut generated_at = None;
    let mut invocation = "ffs-harness recommend-readiness-actions".to_owned();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                input_path = Some(require_value(args, i, "--input")?.clone());
                i += 1;
            }
            "--out-json" => {
                out_json_path = Some(require_value(args, i, "--out-json")?.clone());
                i += 1;
            }
            "--out-md" | "--out-markdown" => {
                out_markdown_path = Some(require_value(args, i, args[i].as_str())?.clone());
                i += 1;
            }
            "--stdout-log" => {
                stdout_log_path = Some(require_value(args, i, "--stdout-log")?.clone());
                i += 1;
            }
            "--stderr-log" => {
                stderr_log_path = Some(require_value(args, i, "--stderr-log")?.clone());
                i += 1;
            }
            "--report-id" => {
                report_id = Some(require_value(args, i, "--report-id")?.clone());
                i += 1;
            }
            "--generated-at" => {
                generated_at = Some(require_value(args, i, "--generated-at")?.clone());
                i += 1;
            }
            "--invocation" => {
                invocation.clone_from(require_value(args, i, "--invocation")?);
                i += 1;
            }
            "--help" | "-h" => {
                print_recommend_readiness_actions_usage();
                return Ok(None);
            }
            other => bail!("unknown recommend-readiness-actions argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(RecommendReadinessActionsCmdArgs {
        input_path,
        out_json_path: out_json_path.context("--out-json is required")?,
        out_markdown_path: out_markdown_path.context("--out-md is required")?,
        stdout_log_path: stdout_log_path.context("--stdout-log is required")?,
        stderr_log_path: stderr_log_path.context("--stderr-log is required")?,
        report_id,
        generated_at,
        invocation,
    }))
}

fn load_readiness_action_planning_input(
    config: &RecommendReadinessActionsCmdArgs,
) -> Result<ReadinessActionPlanningInput> {
    if let Some(input_path) = &config.input_path {
        let input = fs::read_to_string(input_path)
            .with_context(|| format!("failed to read {input_path}"))?;
        return serde_json::from_str(&input)
            .with_context(|| format!("failed to parse readiness action input {input_path}"));
    }

    Ok(ReadinessActionPlanningInput {
        report_id: "readiness_action_dry_run_report".to_owned(),
        generated_at: "1970-01-01T00:00:00Z".to_owned(),
        source_reports: default_readiness_action_autopilot_fixture_set()
            .fixtures
            .into_iter()
            .map(|fixture| fixture.report)
            .collect(),
        active_tracker_issues: Vec::new(),
    })
}

fn readiness_action_dry_run_metadata(
    config: &RecommendReadinessActionsCmdArgs,
) -> ReadinessActionDryRunMetadata {
    ReadinessActionDryRunMetadata {
        invocation: config.invocation.clone(),
        json_report_path: config.out_json_path.clone(),
        markdown_report_path: config.out_markdown_path.clone(),
        stdout_log_path: config.stdout_log_path.clone(),
        stderr_log_path: config.stderr_log_path.clone(),
        cleanup_status: "not_required_dry_run".to_owned(),
        output_paths: vec![
            ReadinessActionDryRunOutputPath {
                kind: "json_report".to_owned(),
                path: config.out_json_path.clone(),
            },
            ReadinessActionDryRunOutputPath {
                kind: "markdown_report".to_owned(),
                path: config.out_markdown_path.clone(),
            },
            ReadinessActionDryRunOutputPath {
                kind: "stdout_log".to_owned(),
                path: config.stdout_log_path.clone(),
            },
            ReadinessActionDryRunOutputPath {
                kind: "stderr_log".to_owned(),
                path: config.stderr_log_path.clone(),
            },
        ],
    }
}

fn readiness_action_dry_run_summary(report: &ReadinessActionDryRunReport) -> String {
    format!(
        "readiness action dry-run report written: json={} markdown={} stdout_log={} stderr_log={} recommendations={} scenarios={} suppressed_duplicates={} cleanup_status={}",
        report.command_metadata.json_report_path,
        report.command_metadata.markdown_report_path,
        report.command_metadata.stdout_log_path,
        report.command_metadata.stderr_log_path,
        report.planner_result.report.recommendations.len(),
        report.scenarios.len(),
        report.planner_result.suppressed_duplicates.len(),
        report.command_metadata.cleanup_status
    )
}

fn readiness_action_dry_run_stdout_log(report: &ReadinessActionDryRunReport) -> String {
    format!(
        "readiness-action-dry-run\nreport_id={}\ndry_run={}\nrecommendations={}\nsuppressed_duplicates={}\nscenarios={}\njson_report_path={}\nmarkdown_report_path={}\nstdout_log_path={}\nstderr_log_path={}\ncleanup_status={}\n",
        report.report_id,
        report.dry_run,
        report.planner_result.report.recommendations.len(),
        report.planner_result.suppressed_duplicates.len(),
        report.scenarios.len(),
        report.command_metadata.json_report_path,
        report.command_metadata.markdown_report_path,
        report.command_metadata.stdout_log_path,
        report.command_metadata.stderr_log_path,
        report.command_metadata.cleanup_status
    )
}

fn readiness_action_dry_run_stderr_log(report: &ReadinessActionDryRunReport) -> String {
    format!(
        "readiness-action-dry-run stderr\nno reproduction commands executed\npermissioned, destructive, and stale-evidence commands stayed dry-run only\ncleanup_status={}\n",
        report.command_metadata.cleanup_status
    )
}

fn parse_readiness_report_format(raw: &str) -> Result<ReadinessReportFormat> {
    match raw {
        "json" => Ok(ReadinessReportFormat::Json),
        "markdown" | "md" => Ok(ReadinessReportFormat::Markdown),
        other => bail!("invalid --format value: {other}"),
    }
}

fn rch_proof_ledger_cmd(args: &[String]) -> Result<()> {
    let mut transcript_path: Option<String> = None;
    let mut command_line = Vec::new();
    let mut cwd = env::current_dir()
        .context("failed to read current directory")?
        .display()
        .to_string();
    let mut env_allowlist = Vec::new();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ReadinessReportFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--transcript" => {
                i += 1;
                transcript_path = Some(
                    args.get(i)
                        .context("--transcript requires a path")?
                        .to_owned(),
                );
            }
            "--command-arg" => {
                i += 1;
                command_line.push(
                    args.get(i)
                        .context("--command-arg requires a value")?
                        .to_owned(),
                );
            }
            "--cwd" => {
                i += 1;
                args.get(i)
                    .context("--cwd requires a path")?
                    .clone_into(&mut cwd);
            }
            "--env" => {
                i += 1;
                env_allowlist.push(args.get(i).context("--env requires a name")?.to_owned());
            }
            "--format" => {
                i += 1;
                format = parse_readiness_report_format(
                    args.get(i).context("--format requires json or markdown")?,
                )?;
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_rch_proof_ledger_usage();
                return Ok(());
            }
            other => bail!("unknown rch-proof-ledger argument: {other}"),
        }
        i += 1;
    }

    let transcript_path = transcript_path.context("--transcript is required")?;
    let transcript = fs::read_to_string(&transcript_path)
        .with_context(|| format!("failed to read {transcript_path}"))?;
    let report = build_rch_proof_ledger_report(
        &transcript,
        &RchProofLedgerConfig {
            command_line,
            cwd,
            env_allowlist,
        },
    );
    let markdown = render_rch_proof_ledger_markdown(&report);
    let output = match format {
        ReadinessReportFormat::Json => serde_json::to_string_pretty(&report)?,
        ReadinessReportFormat::Markdown => markdown.clone(),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "rch proof ledger written: {path} verdict={}",
            report.proof_verdict
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = summary_out_path {
        write_text_file(Path::new(&path), &markdown)?;
    }

    Ok(())
}

fn print_rch_proof_ledger_usage() {
    println!(
        "Usage: ffs-harness rch-proof-ledger --transcript FILE [--command-arg ARG ...] [--cwd DIR] [--env NAME ...] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn validate_rch_capacity_preflight_cmd(args: &[String]) -> Result<()> {
    let mut report_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ReadinessReportFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--report" => {
                i += 1;
                report_path = Some(args.get(i).context("--report requires a path")?.to_owned());
            }
            "--format" => {
                i += 1;
                format = parse_readiness_report_format(
                    args.get(i).context("--format requires json or markdown")?,
                )?;
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_rch_capacity_preflight_usage();
                return Ok(());
            }
            other => bail!("unknown validate-rch-capacity-preflight argument: {other}"),
        }
        i += 1;
    }

    let report_path = report_path.context("--report is required")?;
    let source_report = load_rch_capacity_preflight_report(&report_path)?;
    let validation = validate_rch_capacity_preflight_report(&source_report, report_path);
    let markdown = render_rch_capacity_preflight_markdown(&validation);
    let output = match format {
        ReadinessReportFormat::Json => serde_json::to_string_pretty(&validation)?,
        ReadinessReportFormat::Markdown => markdown.clone(),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "RCH capacity preflight validation written: {path} valid={} verdict={}",
            validation.valid, validation.capacity_verdict
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = summary_out_path {
        write_text_file(Path::new(&path), &format!("{markdown}\n"))?;
    }

    fail_on_rch_capacity_preflight_errors(&validation)
}

fn print_rch_capacity_preflight_usage() {
    println!(
        "Usage: ffs-harness validate-rch-capacity-preflight --report FILE [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

/// Non-permissioned validator for `runtime_console_report` JSON artifacts.
///
/// This is an operational observability validator. It checks the schema/safety
/// contract of a console artifact and never promotes the artifact into product
/// evidence. `--reference-timestamp` and `--max-age-days` keep fixture-driven
/// validation deterministic; without them the current wall clock is used.
fn validate_runtime_console_cmd(args: &[String]) -> Result<()> {
    let mut report_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ReadinessReportFormat::Json;
    let mut reference_timestamp: Option<String> = None;
    let mut max_age_days: Option<u32> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--report" => {
                i += 1;
                report_path = Some(args.get(i).context("--report requires a path")?.to_owned());
            }
            "--format" => {
                i += 1;
                format = parse_readiness_report_format(
                    args.get(i).context("--format requires json or markdown")?,
                )?;
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--reference-timestamp" => {
                i += 1;
                reference_timestamp = Some(
                    args.get(i)
                        .context("--reference-timestamp requires an RFC3339 value")?
                        .to_owned(),
                );
            }
            "--max-age-days" => {
                i += 1;
                max_age_days = Some(
                    args.get(i)
                        .context("--max-age-days requires a value")?
                        .parse()
                        .context("--max-age-days must be a non-negative integer")?,
                );
            }
            "--help" | "-h" => {
                print_runtime_console_usage();
                return Ok(());
            }
            other => bail!("unknown validate-runtime-console argument: {other}"),
        }
        i += 1;
    }

    let report_path = report_path.context("--report is required")?;
    let json = fs::read_to_string(&report_path)
        .with_context(|| format!("read runtime console report: {report_path}"))?;

    let config = if let Some(timestamp) = reference_timestamp {
        let reference_epoch_days = parse_manifest_timestamp_epoch_days(&timestamp)
            .with_context(|| format!("--reference-timestamp must be RFC3339-like: {timestamp}"))?;
        RuntimeConsoleValidationConfig {
            reference_epoch_days: Some(reference_epoch_days),
            max_age_days: max_age_days.or(Some(7)),
        }
    } else {
        let mut config = RuntimeConsoleValidationConfig::with_current_reference();
        if let Some(days) = max_age_days {
            config.max_age_days = Some(days);
        }
        config
    };

    let validation = validate_runtime_console_report_json(&json, &config);
    let markdown = render_runtime_console_report_markdown(&validation);
    let output = match format {
        ReadinessReportFormat::Json => serde_json::to_string_pretty(&validation)?,
        ReadinessReportFormat::Markdown => markdown.clone(),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "runtime console validation written: {path} valid={} mode={} cleanup={}",
            validation.valid, validation.runtime_mode, validation.cleanup_status
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = summary_out_path {
        write_text_file(Path::new(&path), &format!("{markdown}\n"))?;
    }

    fail_on_runtime_console_report_errors(&validation)
}

fn print_runtime_console_usage() {
    println!(
        "Usage: ffs-harness validate-runtime-console --report FILE [--format json|markdown] \
         [--out FILE] [--summary-out FILE] [--reference-timestamp RFC3339] [--max-age-days N]"
    );
}

/// Validator for `numa_allocation_placement_report` JSON artifacts.
///
/// This is advisory replay/downgrade evidence: it checks the placement report's
/// schema and safety contract but never promotes NUMA placement into a
/// `swarm.responsiveness` claim. `--reference-unix-secs` keeps fixture-driven
/// topology-freshness validation deterministic.
fn validate_numa_allocation_placement_cmd(args: &[String]) -> Result<()> {
    let mut report_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ReadinessReportFormat::Json;
    let mut reference_unix_secs: Option<u64> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--report" => {
                i += 1;
                report_path = Some(args.get(i).context("--report requires a path")?.to_owned());
            }
            "--format" => {
                i += 1;
                format = parse_readiness_report_format(
                    args.get(i).context("--format requires json or markdown")?,
                )?;
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--reference-unix-secs" => {
                i += 1;
                reference_unix_secs = Some(
                    args.get(i)
                        .context("--reference-unix-secs requires a value")?
                        .parse()
                        .context("--reference-unix-secs must be a non-negative integer")?,
                );
            }
            "--help" | "-h" => {
                print_numa_allocation_placement_usage();
                return Ok(());
            }
            other => bail!("unknown validate-numa-allocation-placement argument: {other}"),
        }
        i += 1;
    }

    let report_path = report_path.context("--report is required")?;
    let json = fs::read_to_string(&report_path)
        .with_context(|| format!("read numa allocation placement report: {report_path}"))?;
    let config = NumaPlacementValidationConfig {
        reference_unix_secs,
    };
    let validation = validate_numa_allocation_placement_report_json(&json, &config);
    let markdown = render_numa_allocation_placement_markdown(&validation);
    let output = match format {
        ReadinessReportFormat::Json => serde_json::to_string_pretty(&validation)?,
        ReadinessReportFormat::Markdown => markdown.clone(),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "numa allocation placement validation written: {path} valid={} topology={}",
            validation.valid, validation.topology_source
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = summary_out_path {
        write_text_file(Path::new(&path), &format!("{markdown}\n"))?;
    }

    fail_on_numa_allocation_placement_errors(&validation)
}

fn print_numa_allocation_placement_usage() {
    println!(
        "Usage: ffs-harness validate-numa-allocation-placement --report FILE \
         [--format json|markdown] [--out FILE] [--summary-out FILE] \
         [--reference-unix-secs N]"
    );
}

fn validate_proof_bundle_cmd(args: &[String]) -> Result<()> {
    let mut bundle_path: Option<String> = None;
    let mut current_git_sha: Option<String> = None;
    let mut max_age_days: Option<u64> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut execute_configured_lanes = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--bundle" => {
                i += 1;
                bundle_path = Some(args.get(i).context("--bundle requires a path")?.to_owned());
            }
            "--current-git-sha" => {
                i += 1;
                current_git_sha = Some(
                    args.get(i)
                        .context("--current-git-sha requires a value")?
                        .to_owned(),
                );
            }
            "--max-age-days" => {
                i += 1;
                max_age_days = Some(
                    args.get(i)
                        .context("--max-age-days requires a value")?
                        .parse()
                        .context("invalid --max-age-days value")?,
                );
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--execute-configured-lanes" => {
                execute_configured_lanes = true;
            }
            "--help" | "-h" => {
                print_proof_bundle_usage();
                return Ok(());
            }
            other => bail!("unknown validate-proof-bundle argument: {other}"),
        }
        i += 1;
    }

    let bundle_path = bundle_path.context("--bundle is required")?;
    let mut config = ProofBundleValidationConfig::new(&bundle_path);
    config.current_git_sha = current_git_sha;
    config.max_age_days = max_age_days;
    config.execute_configured_lanes = execute_configured_lanes;

    let report = validate_proof_bundle(&config)?;
    let output = match format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_proof_bundle_markdown(&report),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "proof bundle report written: {} valid={} lanes={} artifacts={}",
            path, report.valid, report.totals.lanes, report.totals.artifacts
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = summary_out_path {
        let summary = render_proof_bundle_markdown(&report);
        write_text_file(Path::new(&path), &format!("{summary}\n"))?;
        println!("proof bundle summary written: {path}");
    }

    fail_on_proof_bundle_errors(&report)
}

fn parse_proof_bundle_format(raw: &str) -> Result<ProofBundleFormat> {
    match raw {
        "json" => Ok(ProofBundleFormat::Json),
        "markdown" | "md" => Ok(ProofBundleFormat::Markdown),
        other => bail!("invalid --format value: {other}"),
    }
}

fn validate_invariant_oracle_cmd(args: &[String]) -> Result<()> {
    let mut trace_path: Option<String> = None;
    let mut report_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--trace" => {
                i += 1;
                trace_path = Some(args.get(i).context("--trace requires a path")?.to_owned());
            }
            "--report" => {
                i += 1;
                report_path = Some(args.get(i).context("--report requires a path")?.to_owned());
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_invariant_oracle_usage();
                return Ok(());
            }
            other => bail!("unknown validate-invariant-oracle argument: {other}"),
        }
        i += 1;
    }

    if report_path.is_some() {
        if trace_path.is_some() {
            bail!("validate-invariant-oracle accepts exactly one of --trace or --report");
        }
        return validate_invariant_oracle_report_cmd(
            report_path.as_deref().context("--report is required")?,
            out_path.as_deref(),
            format,
        );
    }

    let trace_path = trace_path.context("--trace or --report is required")?;
    let trace = load_invariant_trace(Path::new(&trace_path))?;
    let report = validate_invariant_trace(&trace);
    let output = match format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_invariant_oracle_markdown(&report),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "invariant oracle report written: {} valid={} operations={} expected_failures={} unexpected_failures={}",
            path,
            report.valid,
            report.operation_count,
            report.expected_failure_count,
            report.unexpected_failure_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = summary_out_path {
        let summary = render_invariant_oracle_markdown(&report);
        write_text_file(Path::new(&path), &format!("{summary}\n"))?;
        println!("invariant oracle summary written: {path}");
    }

    fail_on_invariant_oracle_errors(&report)
}

fn validate_invariant_oracle_report_cmd(
    report_path: &str,
    out_path: Option<&str>,
    format: ProofBundleFormat,
) -> Result<()> {
    let report = load_invariant_oracle_report(Path::new(report_path))?;
    let consumer_report = build_invariant_oracle_consumer_report(&report);
    let output = match format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&consumer_report)?,
        ProofBundleFormat::Markdown => {
            let mut summary = String::new();
            summary.push_str("# Invariant Oracle Consumer Report\n\n");
            let _ = writeln!(summary, "- Trace: `{}`", consumer_report.trace_id);
            let _ = writeln!(
                summary,
                "- Model version: `{}`",
                consumer_report.model_version
            );
            let _ = writeln!(summary, "- Valid: `{}`", consumer_report.valid);
            if !consumer_report.errors.is_empty() {
                summary.push_str("\n## Errors\n\n");
                for error in &consumer_report.errors {
                    let _ = writeln!(summary, "- {error}");
                }
            }
            summary
        }
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(path), &format!("{output}\n"))?;
        println!(
            "invariant oracle consumer report written: {path} valid={}",
            consumer_report.valid
        );
    } else {
        println!("{output}");
    }

    if !consumer_report.valid {
        bail!(
            "invariant oracle report artifact validation failed: errors={}",
            consumer_report.errors.len()
        );
    }
    Ok(())
}

fn validate_mounted_differential_oracle_cmd(args: &[String]) -> Result<()> {
    let mut report_path = DEFAULT_MOUNTED_DIFFERENTIAL_REPORT.to_owned();
    let mut out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--report" => {
                i += 1;
                args.get(i)
                    .context("--report requires a path")?
                    .clone_into(&mut report_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_mounted_differential_oracle_usage();
                return Ok(());
            }
            other => bail!("unknown validate-mounted-differential-oracle argument: {other}"),
        }
        i += 1;
    }

    let report = load_mounted_differential_oracle_report(Path::new(&report_path))?;
    let validation = validate_mounted_differential_oracle_report(&report);
    let output = match format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&validation)?,
        ProofBundleFormat::Markdown => render_mounted_differential_oracle_markdown(&validation),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "mounted differential oracle report written: {} valid={} scenarios={} allowlists={}",
            path, validation.valid, validation.scenario_count, validation.allowlist_count
        );
    } else {
        println!("{output}");
    }

    fail_on_mounted_differential_oracle_errors(&validation)
}

fn validate_cross_oracle_arbitration_cmd(args: &[String]) -> Result<()> {
    let mut report_path = DEFAULT_CROSS_ORACLE_ARBITRATION_REPORT.to_owned();
    let mut out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--report" => {
                i += 1;
                args.get(i)
                    .context("--report requires a path")?
                    .clone_into(&mut report_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_cross_oracle_arbitration_usage();
                return Ok(());
            }
            other => bail!("unknown validate-cross-oracle-arbitration argument: {other}"),
        }
        i += 1;
    }

    let report = load_cross_oracle_arbitration_report(Path::new(&report_path))?;
    let validation = validate_cross_oracle_arbitration_report(&report);
    let output = match format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&validation)?,
        ProofBundleFormat::Markdown => render_cross_oracle_arbitration_markdown(&validation),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "cross-oracle arbitration report written: {} valid={} arbitrations={} fail_closed={}",
            path, validation.valid, validation.arbitration_count, validation.fail_closed_count
        );
    } else {
        println!("{output}");
    }

    fail_on_cross_oracle_arbitration_errors(&validation)
}

fn evaluate_release_gates_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_release_gate_cmd_args(args)? else {
        return Ok(());
    };

    let mut bundle_config = ProofBundleValidationConfig::new(&cmd_args.bundle_path);
    bundle_config.current_git_sha = cmd_args.current_git_sha;
    bundle_config.max_age_days = cmd_args.max_age_days;
    // Release-gate evaluation controls public readiness wording, so executable
    // lanes must be re-run instead of accepting checked-in artifact hashes alone.
    bundle_config.execute_configured_lanes = true;

    let policy = load_release_gate_policy(Path::new(&cmd_args.policy_path))?;
    let proof_report = validate_proof_bundle(&bundle_config)?;
    let report = evaluate_release_gates(&policy, &proof_report);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_release_gate_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "release gate report written: {} valid={} features={} findings={}",
            path,
            report.valid,
            report.feature_reports.len(),
            report.findings.len()
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.wording_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", release_gate_wording(&report)),
        )?;
        println!("release gate wording written: {path}");
    }

    fail_on_release_gate_errors(&report)
}

fn parse_release_gate_cmd_args(args: &[String]) -> Result<Option<ReleaseGateCmdArgs>> {
    let mut bundle_path: Option<String> = None;
    let mut policy_path: Option<String> = None;
    let mut current_git_sha: Option<String> = None;
    let mut max_age_days: Option<u64> = None;
    let mut out_path: Option<String> = None;
    let mut wording_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--bundle" => {
                i += 1;
                bundle_path = Some(args.get(i).context("--bundle requires a path")?.to_owned());
            }
            "--policy" => {
                i += 1;
                policy_path = Some(args.get(i).context("--policy requires a path")?.to_owned());
            }
            "--current-git-sha" => {
                i += 1;
                current_git_sha = Some(
                    args.get(i)
                        .context("--current-git-sha requires a value")?
                        .to_owned(),
                );
            }
            "--max-age-days" => {
                i += 1;
                max_age_days = Some(
                    args.get(i)
                        .context("--max-age-days requires a value")?
                        .parse()
                        .context("invalid --max-age-days value")?,
                );
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--wording-out" => {
                i += 1;
                wording_out_path = Some(
                    args.get(i)
                        .context("--wording-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_release_gate_usage();
                return Ok(None);
            }
            other => bail!("unknown evaluate-release-gates argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(ReleaseGateCmdArgs {
        bundle_path: bundle_path.context("--bundle is required for release gate evaluation")?,
        policy_path: policy_path.context("--policy is required for release gate evaluation")?,
        current_git_sha,
        max_age_days,
        out_path,
        wording_out_path,
        format,
    }))
}

fn release_gate_wording(report: &ffs_harness::release_gate::ReleaseGateEvaluationReport) -> String {
    report
        .generated_wording
        .iter()
        .map(|entry| {
            format!(
                "{}\t{}\t{}\t{}",
                entry.feature_id,
                entry.docs_wording_id,
                entry.state.label(),
                entry.wording
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn validate_performance_baseline_manifest_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_performance_manifest_cmd_args(args)? else {
        return Ok(());
    };
    let manifest = match (&cmd_args.manifest_path, &cmd_args.manifest_json_env) {
        (Some(path), None) => load_performance_baseline_manifest(Path::new(path))?,
        (None, Some(env_name)) => {
            let raw = env::var(env_name)
                .with_context(|| format!("--manifest-json-env variable {env_name} is not set"))?;
            serde_json::from_str::<PerformanceBaselineManifest>(&raw)
                .with_context(|| format!("invalid performance manifest JSON from {env_name}"))?
        }
        (Some(_), Some(_)) => bail!("use either --manifest or --manifest-json-env, not both"),
        (None, None) => {
            bail!(
                "--manifest or --manifest-json-env is required for performance manifest validation"
            )
        }
    };
    let report = validate_performance_baseline_manifest(&manifest, &cmd_args.artifact_root);
    let output = serde_json::to_string_pretty(&report)?;

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "performance baseline manifest report written: {} valid={} workloads={}",
            path, report.valid, report.workload_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.artifact_out_path {
        let artifact_manifest =
            build_performance_sample_artifact_manifest(&manifest, &cmd_args.artifact_root);
        write_text_file(
            Path::new(&path),
            &format!("{}\n", serde_json::to_string_pretty(&artifact_manifest)?),
        )?;
        println!("performance baseline sample artifact manifest written: {path}");
    }

    fail_on_performance_baseline_manifest_errors(&report)
}

fn parse_performance_manifest_cmd_args(
    args: &[String],
) -> Result<Option<PerformanceManifestCmdArgs>> {
    let mut manifest_path: Option<String> = None;
    let mut manifest_json_env: Option<String> = None;
    let mut artifact_root = "artifacts/performance/dry-run".to_owned();
    let mut out_path: Option<String> = None;
    let mut artifact_out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest_path = Some(
                    args.get(i)
                        .context("--manifest requires a path")?
                        .to_owned(),
                );
            }
            "--manifest-json-env" => {
                i += 1;
                manifest_json_env = Some(
                    args.get(i)
                        .context("--manifest-json-env requires a variable name")?
                        .to_owned(),
                );
            }
            "--artifact-root" => {
                i += 1;
                args.get(i)
                    .context("--artifact-root requires a path")?
                    .clone_into(&mut artifact_root);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--artifact-out" => {
                i += 1;
                artifact_out_path = Some(
                    args.get(i)
                        .context("--artifact-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_performance_manifest_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-performance-baseline-manifest argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(PerformanceManifestCmdArgs {
        manifest_path,
        manifest_json_env,
        artifact_root,
        out_path,
        artifact_out_path,
    }))
}

fn performance_delta_closeout_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_performance_delta_closeout_cmd_args(args)? else {
        return Ok(());
    };
    let mut config = load_performance_delta_closeout_config(Path::new(&cmd_args.config_path))?;
    if let Some(issues_path) = cmd_args.issues_path {
        config.issues_path = issues_path;
    }
    let report = run_performance_delta_closeout(&config)?;
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_performance_delta_closeout_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "performance delta closeout written: {} valid={} rows={} followups={}",
            path,
            report.valid,
            report.row_count,
            report.follow_up_beads.len()
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        let summary = render_performance_delta_closeout_markdown(&report);
        write_text_file(Path::new(&path), &format!("{summary}\n"))?;
        println!("performance delta closeout summary written: {path}");
    }

    fail_on_performance_delta_closeout_errors(&report)
}

fn parse_performance_delta_closeout_cmd_args(
    args: &[String],
) -> Result<Option<PerformanceDeltaCloseoutCmdArgs>> {
    let mut config_path = DEFAULT_PERFORMANCE_DELTA_CLOSEOUT_CONFIG.to_owned();
    let mut issues_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                args.get(i)
                    .context("--config requires a path")?
                    .clone_into(&mut config_path);
            }
            "--issues" => {
                i += 1;
                issues_path = Some(args.get(i).context("--issues requires a path")?.to_owned());
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_performance_delta_closeout_usage();
                return Ok(None);
            }
            other => bail!("unknown performance-delta-closeout argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(PerformanceDeltaCloseoutCmdArgs {
        config_path,
        issues_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_swarm_cache_controller_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_swarm_cache_controller_cmd_args(args)? else {
        return Ok(());
    };
    let contract = load_swarm_cache_controller_contract(Path::new(&cmd_args.contract_path))?;
    let report = validate_swarm_cache_controller_contract(&contract);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_swarm_cache_controller_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "swarm cache controller report written: {} valid={} scenarios={} candidates={}",
            path, report.valid, report.scenario_count, report.candidate_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_swarm_cache_controller_markdown(&report)),
        )?;
        println!("swarm cache controller summary written: {path}");
    }

    fail_on_swarm_cache_controller_errors(&report)
}

fn parse_swarm_cache_controller_cmd_args(
    args: &[String],
) -> Result<Option<SwarmCacheControllerCmdArgs>> {
    let mut contract_path = DEFAULT_SWARM_CACHE_CONTROLLER_CONTRACT.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--contract" => {
                i += 1;
                args.get(i)
                    .context("--contract requires a path")?
                    .clone_into(&mut contract_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_swarm_cache_controller_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-swarm-cache-controller argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(SwarmCacheControllerCmdArgs {
        contract_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_swarm_operator_report_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_swarm_operator_report_cmd_args(args)? else {
        return Ok(());
    };
    let report = load_swarm_operator_report(Path::new(&cmd_args.report_path))?;
    let validation = validate_swarm_operator_report(&report);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&validation)?,
        ProofBundleFormat::Markdown => render_swarm_operator_report_markdown(&validation),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "swarm operator report written: {} valid={} cards={}",
            path, validation.valid, validation.card_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_swarm_operator_report_markdown(&validation)),
        )?;
        println!("swarm operator report summary written: {path}");
    }

    fail_on_swarm_operator_report_errors(&validation)
}

fn parse_swarm_operator_report_cmd_args(
    args: &[String],
) -> Result<Option<SwarmOperatorReportCmdArgs>> {
    let mut report_path = DEFAULT_SWARM_OPERATOR_REPORT.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--report" => {
                i += 1;
                args.get(i)
                    .context("--report requires a path")?
                    .clone_into(&mut report_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_swarm_operator_report_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-swarm-operator-report argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(SwarmOperatorReportCmdArgs {
        report_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_swarm_tail_latency_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_swarm_tail_latency_cmd_args(args)? else {
        return Ok(());
    };
    let ledger = load_swarm_tail_latency_ledger(Path::new(&cmd_args.ledger_path))?;
    let report = validate_swarm_tail_latency_ledger(&ledger);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_swarm_tail_latency_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "swarm tail-latency report written: {} valid={} rows={} alerts={}",
            path, report.valid, report.row_count, report.component_dominance_alert_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_swarm_tail_latency_markdown(&report)),
        )?;
        println!("swarm tail-latency summary written: {path}");
    }

    fail_on_swarm_tail_latency_errors(&report)
}

fn parse_swarm_tail_latency_cmd_args(args: &[String]) -> Result<Option<SwarmTailLatencyCmdArgs>> {
    let mut ledger_path = DEFAULT_SWARM_TAIL_LATENCY_LEDGER.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--ledger" => {
                i += 1;
                args.get(i)
                    .context("--ledger requires a path")?
                    .clone_into(&mut ledger_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_swarm_tail_latency_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-swarm-tail-latency argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(SwarmTailLatencyCmdArgs {
        ledger_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn adaptive_runtime_runner_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_adaptive_runtime_runner_cmd_args(args)? else {
        return Ok(());
    };
    let mut path_plan = default_adaptive_runtime_runner_path_plan(cmd_args.artifact_root.clone());
    if let Some(path) = cmd_args.raw_stdout_path {
        path_plan.raw_stdout_path = path;
    }
    if let Some(path) = cmd_args.raw_stderr_path {
        path_plan.raw_stderr_path = path;
    }
    if let Some(path) = cmd_args.structured_log_path {
        path_plan.structured_log_path = path;
    }
    if let Some(path) = cmd_args.runner_manifest_path {
        path_plan.runner_manifest_path = path;
    }
    if let Some(path) = cmd_args.cleanup_report_path {
        path_plan.cleanup_report_path = path;
    }
    if let Some(path) = cmd_args.host_facts_path {
        path_plan.host_facts_path = path;
    }
    path_plan.test_dir = cmd_args.test_dir;
    path_plan.scratch_mnt = cmd_args.scratch_mnt;

    let observed_ack_value = env::var(&cmd_args.ack_env).ok();
    let artifacts = build_adaptive_runtime_runner_artifacts(AdaptiveRuntimeRunnerConfig {
        mode: cmd_args.mode,
        path_plan,
        ack_env: cmd_args.ack_env,
        ack_value: cmd_args.ack_value,
        observed_ack_value,
        generated_at: cmd_args.generated_at,
        git_sha: cmd_args.git_sha,
        reproduction_command: cmd_args.reproduction_command,
        host_facts: collect_adaptive_runtime_runner_host_facts(),
        cleanup_status: cmd_args.cleanup_status,
    });
    let report = &artifacts.report;

    write_text_file(
        Path::new(&report.path_plan.runner_manifest_path),
        &format!(
            "{}\n",
            serde_json::to_string_pretty(&artifacts.plan_manifest)?
        ),
    )?;
    write_text_file(
        Path::new(&report.path_plan.cleanup_report_path),
        &format!(
            "{}\n",
            serde_json::to_string_pretty(&artifacts.cleanup_report)?
        ),
    )?;
    write_text_file(
        Path::new(&report.path_plan.host_facts_path),
        &format!("{}\n", serde_json::to_string_pretty(&report.host_facts)?),
    )?;
    write_text_file(
        Path::new(&report.path_plan.raw_stdout_path),
        &artifacts.stdout_log,
    )?;
    write_text_file(
        Path::new(&report.path_plan.raw_stderr_path),
        &artifacts.stderr_log,
    )?;
    write_text_file(
        Path::new(&report.path_plan.structured_log_path),
        &artifacts.structured_log,
    )?;
    write_text_file(
        Path::new(&cmd_args.out_path),
        &format!("{}\n", serde_json::to_string_pretty(report)?),
    )?;
    write_text_file(
        Path::new(&cmd_args.summary_out_path),
        &format!("{}\n", render_adaptive_runtime_runner_markdown(report)),
    )?;

    println!(
        "adaptive runtime runner report written: {} valid={} classification={} permissioned_real_allowed={} artifact_root={}",
        cmd_args.out_path,
        report.valid,
        report.classification,
        report.execution.permissioned_real_allowed,
        report.path_plan.artifact_root
    );

    fail_on_adaptive_runtime_runner_errors(report)
}

#[allow(clippy::too_many_lines)]
fn parse_adaptive_runtime_runner_cmd_args(
    args: &[String],
) -> Result<Option<AdaptiveRuntimeRunnerCmdArgs>> {
    let mut mode = AdaptiveRuntimeRunnerMode::DryRun;
    let mut artifact_root = DEFAULT_ADAPTIVE_RUNTIME_RUNNER_ARTIFACT_ROOT.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut raw_stdout_path = None;
    let mut raw_stderr_path = None;
    let mut structured_log_path = None;
    let mut runner_manifest_path = None;
    let mut cleanup_report_path = None;
    let mut host_facts_path = None;
    let mut test_dir = None;
    let mut scratch_mnt = None;
    let mut ack_env = DEFAULT_ADAPTIVE_RUNTIME_REAL_RUN_ACK_ENV.to_owned();
    let mut ack_value = DEFAULT_ADAPTIVE_RUNTIME_REAL_RUN_ACK_VALUE.to_owned();
    let mut generated_at: Option<String> = None;
    let mut git_sha: Option<String> = None;
    let mut reproduction_command = "cargo run -p ffs-harness -- adaptive-runtime-runner".to_owned();
    let mut cleanup_status = AdaptiveRuntimeRunnerCleanupStatus::NotStartedDryRun;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--mode" => {
                mode = parse_adaptive_runtime_runner_mode(require_value(args, i, "--mode")?)?;
                i += 1;
            }
            "--artifact-root" => {
                artifact_root.clone_from(require_value(args, i, "--artifact-root")?);
                i += 1;
            }
            "--out" => {
                out_path = Some(require_value(args, i, "--out")?.clone());
                i += 1;
            }
            "--summary-out" => {
                summary_out_path = Some(require_value(args, i, "--summary-out")?.clone());
                i += 1;
            }
            "--stdout-log" => {
                raw_stdout_path = Some(require_value(args, i, "--stdout-log")?.clone());
                i += 1;
            }
            "--stderr-log" => {
                raw_stderr_path = Some(require_value(args, i, "--stderr-log")?.clone());
                i += 1;
            }
            "--structured-log" => {
                structured_log_path = Some(require_value(args, i, "--structured-log")?.clone());
                i += 1;
            }
            "--manifest-out" => {
                runner_manifest_path = Some(require_value(args, i, "--manifest-out")?.clone());
                i += 1;
            }
            "--cleanup-out" => {
                cleanup_report_path = Some(require_value(args, i, "--cleanup-out")?.clone());
                i += 1;
            }
            "--host-facts-out" => {
                host_facts_path = Some(require_value(args, i, "--host-facts-out")?.clone());
                i += 1;
            }
            "--test-dir" => {
                test_dir = Some(require_value(args, i, "--test-dir")?.clone());
                i += 1;
            }
            "--scratch-mnt" => {
                scratch_mnt = Some(require_value(args, i, "--scratch-mnt")?.clone());
                i += 1;
            }
            "--ack-env" => {
                ack_env.clone_from(require_value(args, i, "--ack-env")?);
                i += 1;
            }
            "--ack-value" => {
                ack_value.clone_from(require_value(args, i, "--ack-value")?);
                i += 1;
            }
            "--generated-at" => {
                generated_at = Some(require_value(args, i, "--generated-at")?.clone());
                i += 1;
            }
            "--git-sha" => {
                git_sha = Some(require_value(args, i, "--git-sha")?.clone());
                i += 1;
            }
            "--reproduction-command" => {
                reproduction_command.clone_from(require_value(args, i, "--reproduction-command")?);
                i += 1;
            }
            "--cleanup-status" => {
                cleanup_status = parse_adaptive_runtime_runner_cleanup_status(require_value(
                    args,
                    i,
                    "--cleanup-status",
                )?)?;
                i += 1;
            }
            "--help" | "-h" => {
                print_adaptive_runtime_runner_usage();
                return Ok(None);
            }
            other => bail!("unknown adaptive-runtime-runner argument: {other}"),
        }
        i += 1;
    }

    let out_path = out_path.unwrap_or_else(|| {
        Path::new(&artifact_root)
            .join("report.json")
            .display()
            .to_string()
    });
    let summary_out_path = summary_out_path.unwrap_or_else(|| {
        Path::new(&artifact_root)
            .join("report.md")
            .display()
            .to_string()
    });
    let generated_at = generated_at.unwrap_or_else(current_unix_timestamp_label);
    let git_sha = git_sha
        .or_else(|| env::var("GIT_SHA").ok())
        .unwrap_or_else(|| "unknown".to_owned());

    Ok(Some(AdaptiveRuntimeRunnerCmdArgs {
        mode,
        artifact_root,
        out_path,
        summary_out_path,
        raw_stdout_path,
        raw_stderr_path,
        structured_log_path,
        runner_manifest_path,
        cleanup_report_path,
        host_facts_path,
        test_dir,
        scratch_mnt,
        ack_env,
        ack_value,
        generated_at,
        git_sha,
        reproduction_command,
        cleanup_status,
    }))
}

fn parse_adaptive_runtime_runner_mode(value: &str) -> Result<AdaptiveRuntimeRunnerMode> {
    match value {
        "dry-run" | "dry_run" => Ok(AdaptiveRuntimeRunnerMode::DryRun),
        "capability-probe" | "capability_probe" => Ok(AdaptiveRuntimeRunnerMode::CapabilityProbe),
        "permissioned-real" | "permissioned_real" => {
            Ok(AdaptiveRuntimeRunnerMode::PermissionedReal)
        }
        other => bail!("invalid --mode value: {other}"),
    }
}

fn parse_adaptive_runtime_runner_cleanup_status(
    value: &str,
) -> Result<AdaptiveRuntimeRunnerCleanupStatus> {
    match value {
        "not-started-dry-run" | "not_started_dry_run" => {
            Ok(AdaptiveRuntimeRunnerCleanupStatus::NotStartedDryRun)
        }
        "clean" => Ok(AdaptiveRuntimeRunnerCleanupStatus::Clean),
        "preserved-artifacts" | "preserved_artifacts" => {
            Ok(AdaptiveRuntimeRunnerCleanupStatus::PreservedArtifacts)
        }
        "failed" => Ok(AdaptiveRuntimeRunnerCleanupStatus::Failed),
        other => bail!("invalid --cleanup-status value: {other}"),
    }
}

fn current_unix_timestamp_label() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    format!("unix:{secs}")
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn record_authoritative_environment_manifest_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_authoritative_environment_record_cmd_args(args)? else {
        return Ok(());
    };
    let out_path = cmd_args.out_path.as_deref().context("--out is required")?;
    let manifest = build_recorded_authoritative_environment_manifest(&cmd_args);
    let decision = evaluate_authoritative_environment(&manifest, &manifest);

    if manifest.authoritative
        && !matches!(
            decision,
            AuthoritativeEnvironmentDecision::Authoritative { .. }
        )
    {
        bail!("recorded authoritative environment manifest is not authoritative: {decision:?}");
    }

    write_text_file(
        Path::new(out_path),
        &format!("{}\n", serde_json::to_string_pretty(&manifest)?),
    )?;
    println!(
        "authoritative environment manifest written: {} manifest_id={} authoritative={} decision={}",
        out_path,
        manifest.manifest_id,
        manifest.authoritative,
        authoritative_environment_decision_label(&decision),
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn parse_authoritative_environment_record_cmd_args(
    args: &[String],
) -> Result<Option<AuthoritativeEnvironmentRecordCmdArgs>> {
    let mut config = AuthoritativeEnvironmentRecordCmdArgs::default();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                config.out_path = Some(require_value(args, i, "--out")?.clone());
                i += 2;
            }
            "--manifest-id" => {
                config.manifest_id = Some(require_value(args, i, "--manifest-id")?.clone());
                i += 2;
            }
            "--bead-id" => {
                config.bead_id = Some(require_value(args, i, "--bead-id")?.clone());
                i += 2;
            }
            "--lane-id" => {
                config.lane_id = Some(require_value(args, i, "--lane-id")?.clone());
                i += 2;
            }
            "--authoritative" => {
                config.authoritative = true;
                i += 1;
            }
            "--non-authoritative" => {
                config.authoritative = false;
                i += 1;
            }
            "--host-id" => {
                config.host_id = Some(require_value(args, i, "--host-id")?.clone());
                i += 2;
            }
            "--worker-id" => {
                config.worker_id = Some(require_value(args, i, "--worker-id")?.clone());
                i += 2;
            }
            "--kernel" => {
                config.kernel = Some(require_value(args, i, "--kernel")?.clone());
                i += 2;
            }
            "--fuse-kernel-version" => {
                config.fuse_kernel_version =
                    Some(require_value(args, i, "--fuse-kernel-version")?.clone());
                i += 2;
            }
            "--fuser-helper-version" => {
                config.fuser_helper_version =
                    Some(require_value(args, i, "--fuser-helper-version")?.clone());
                i += 2;
            }
            "--mkfs" => {
                config
                    .mkfs_versions
                    .push(parse_mkfs_version_arg(require_value(args, i, "--mkfs")?)?);
                i += 2;
            }
            "--cargo-toolchain" => {
                config.cargo_toolchain = Some(require_value(args, i, "--cargo-toolchain")?.clone());
                i += 2;
            }
            "--rustc-version" => {
                config.rustc_version = Some(require_value(args, i, "--rustc-version")?.clone());
                i += 2;
            }
            "--mount-namespace" => {
                config.mount_namespace = Some(require_value(args, i, "--mount-namespace")?.clone());
                i += 2;
            }
            "--privilege-model" => {
                config.privilege_model = Some(require_value(args, i, "--privilege-model")?.clone());
                i += 2;
            }
            "--fs-tool" => {
                config
                    .fs_tools
                    .push(require_value(args, i, "--fs-tool")?.clone());
                i += 2;
            }
            "--git-sha" => {
                config.git_sha = Some(require_value(args, i, "--git-sha")?.clone());
                i += 2;
            }
            "--artifact-schema-version" => {
                config.artifact_schema_version = Some(
                    require_value(args, i, "--artifact-schema-version")?
                        .parse()
                        .context("invalid --artifact-schema-version value")?,
                );
                i += 2;
            }
            "--probe-at-unix" => {
                config.probe_at_unix = Some(
                    require_value(args, i, "--probe-at-unix")?
                        .parse()
                        .context("invalid --probe-at-unix value")?,
                );
                i += 2;
            }
            "--freshness-ttl-seconds" => {
                config.freshness_ttl_seconds = Some(
                    require_value(args, i, "--freshness-ttl-seconds")?
                        .parse()
                        .context("invalid --freshness-ttl-seconds value")?,
                );
                i += 2;
            }
            "--now-unix" => {
                config.now_unix = Some(
                    require_value(args, i, "--now-unix")?
                        .parse()
                        .context("invalid --now-unix value")?,
                );
                i += 2;
            }
            "--replay-command" => {
                config.replay_command = Some(require_value(args, i, "--replay-command")?.clone());
                i += 2;
            }
            "--max-open-files" => {
                config.max_open_files = Some(
                    require_value(args, i, "--max-open-files")?
                        .parse()
                        .context("invalid --max-open-files value")?,
                );
                i += 2;
            }
            "--max-address-space-bytes" => {
                config.max_address_space_bytes = Some(
                    require_value(args, i, "--max-address-space-bytes")?
                        .parse()
                        .context("invalid --max-address-space-bytes value")?,
                );
                i += 2;
            }
            "--max-processes" => {
                config.max_processes = Some(
                    require_value(args, i, "--max-processes")?
                        .parse()
                        .context("invalid --max-processes value")?,
                );
                i += 2;
            }
            "--help" | "-h" => {
                print_authoritative_environment_manifest_usage();
                return Ok(None);
            }
            other => bail!("unknown record-environment-manifest argument: {other}"),
        }
    }

    if config.out_path.is_none() {
        bail!("--out is required");
    }
    Ok(Some(config))
}

fn build_recorded_authoritative_environment_manifest(
    config: &AuthoritativeEnvironmentRecordCmdArgs,
) -> AuthoritativeEnvironmentManifest {
    let now_unix = config.now_unix.unwrap_or_else(current_unix_seconds);
    let probe_at_unix = config.probe_at_unix.unwrap_or(now_unix);
    let git_sha = config.git_sha.clone().unwrap_or_else(default_git_sha);
    let out_path = config
        .out_path
        .as_deref()
        .unwrap_or("artifacts/env-manifest.json");

    AuthoritativeEnvironmentManifest {
        schema_version: AUTHORITATIVE_ENVIRONMENT_MANIFEST_SCHEMA_VERSION,
        manifest_id: config
            .manifest_id
            .clone()
            .unwrap_or_else(|| format!("env_{}", short_identifier(&git_sha))),
        bead_id: config
            .bead_id
            .clone()
            .unwrap_or_else(|| "bd-7mj5d".to_owned()),
        lane_id: config
            .lane_id
            .clone()
            .unwrap_or_else(|| "rchk_authoritative_v1".to_owned()),
        authoritative: config.authoritative,
        host_id: config.host_id.clone().unwrap_or_else(default_host_id),
        worker_id: config.worker_id.clone().unwrap_or_else(default_worker_id),
        kernel: config.kernel.clone().unwrap_or_else(|| {
            command_output_line(HostProbeCommand::Uname, &["-r"])
                .unwrap_or_else(|| "unknown".to_owned())
        }),
        fuse_kernel_version: config
            .fuse_kernel_version
            .clone()
            .unwrap_or_else(default_fuse_kernel_version),
        fuser_helper_version: config
            .fuser_helper_version
            .clone()
            .unwrap_or_else(default_fuser_helper_version),
        mkfs_versions: if config.mkfs_versions.is_empty() {
            default_mkfs_versions()
        } else {
            config.mkfs_versions.clone()
        },
        cargo_toolchain: config.cargo_toolchain.clone().unwrap_or_else(|| {
            command_output_line(HostProbeCommand::Cargo, &["--version"])
                .unwrap_or_else(|| "cargo:unknown".to_owned())
        }),
        rustc_version: config.rustc_version.clone().unwrap_or_else(|| {
            command_output_line(HostProbeCommand::Rustc, &["--version"])
                .unwrap_or_else(|| "rustc:unknown".to_owned())
        }),
        mount_namespace: config
            .mount_namespace
            .clone()
            .unwrap_or_else(default_mount_namespace),
        privilege_model: config.privilege_model.clone().unwrap_or_else(|| {
            if config.authoritative {
                "sudo_capability".to_owned()
            } else {
                "unprivileged".to_owned()
            }
        }),
        fs_tools: if config.fs_tools.is_empty() {
            default_fs_tools()
        } else {
            config.fs_tools.clone()
        },
        resource_limits: ResourceLimits {
            max_open_files: config
                .max_open_files
                .or_else(|| proc_limit_soft_value("Max open files"))
                .unwrap_or(1),
            max_address_space_bytes: config
                .max_address_space_bytes
                .or_else(|| proc_limit_soft_value("Max address space"))
                .unwrap_or(u64::MAX),
            max_processes: config
                .max_processes
                .or_else(|| proc_limit_soft_value("Max processes"))
                .unwrap_or(1),
        },
        git_sha,
        artifact_schema_version: config.artifact_schema_version.unwrap_or(1),
        probe_at_unix,
        freshness_ttl_seconds: config.freshness_ttl_seconds.unwrap_or(3_600),
        now_unix,
        replay_command: config.replay_command.clone().unwrap_or_else(|| {
            format!("cargo run -p ffs-harness -- record-environment-manifest --out {out_path}")
        }),
    }
}

fn parse_mkfs_version_arg(raw: &str) -> Result<MkfsVersion> {
    let mut parts = raw.splitn(3, ':');
    let flavor = parts
        .next()
        .filter(|value| !value.trim().is_empty())
        .context("--mkfs must use FLAVOR:BINARY:VERSION")?;
    let binary = parts
        .next()
        .filter(|value| !value.trim().is_empty())
        .context("--mkfs must use FLAVOR:BINARY:VERSION")?;
    let version = parts
        .next()
        .filter(|value| !value.trim().is_empty())
        .context("--mkfs must use FLAVOR:BINARY:VERSION")?;
    Ok(MkfsVersion {
        flavor: flavor.to_owned(),
        binary: binary.to_owned(),
        version: version.to_owned(),
    })
}

fn authoritative_environment_decision_label(decision: &AuthoritativeEnvironmentDecision) -> &str {
    match decision {
        AuthoritativeEnvironmentDecision::Authoritative { .. } => "authoritative",
        AuthoritativeEnvironmentDecision::Skip { .. } => "skip",
        AuthoritativeEnvironmentDecision::RejectMismatch { .. } => "reject_mismatch",
    }
}

fn short_identifier(value: &str) -> String {
    value.chars().take(12).collect()
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn default_host_id() -> String {
    non_empty_env("HOSTNAME")
        .or_else(|| {
            fs::read_to_string("/etc/hostname")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .or_else(|| command_output_line(HostProbeCommand::Hostname, &[]))
        .unwrap_or_else(|| "unknown-host".to_owned())
}

fn default_worker_id() -> String {
    non_empty_env("RCH_WORKER_ID")
        .or_else(|| non_empty_env("RCH_WORKER_NAME"))
        .or_else(|| non_empty_env("HOSTNAME"))
        .unwrap_or_else(|| "local-worker".to_owned())
}

fn default_git_sha() -> String {
    non_empty_env("GIT_SHA")
        .or_else(|| command_output_line(HostProbeCommand::Git, &["rev-parse", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn default_fuse_kernel_version() -> String {
    fs::read_to_string("/sys/module/fuse/version")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn default_fuser_helper_version() -> String {
    command_output_line(HostProbeCommand::Fusermount3, &["--version"])
        .or_else(|| command_output_line(HostProbeCommand::Fusermount, &["--version"]))
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn default_mount_namespace() -> String {
    fs::read_link("/proc/self/ns/mnt").map_or_else(
        |_| "mnt:[unknown]".to_owned(),
        |path| path.display().to_string(),
    )
}

fn default_mkfs_versions() -> Vec<MkfsVersion> {
    vec![
        MkfsVersion {
            flavor: "ext4".to_owned(),
            binary: "mkfs.ext4".to_owned(),
            version: command_version_or_unavailable(HostProbeCommand::MkfsExt4, &["-V"]),
        },
        MkfsVersion {
            flavor: "btrfs".to_owned(),
            binary: "mkfs.btrfs".to_owned(),
            version: command_version_or_unavailable(HostProbeCommand::MkfsBtrfs, &["--version"]),
        },
    ]
}

fn default_fs_tools() -> Vec<String> {
    vec![
        command_tool_summary(HostProbeCommand::E2fsck, &["-V"]),
        command_tool_summary(HostProbeCommand::Btrfs, &["--version"]),
        command_tool_summary(HostProbeCommand::Fsck, &["--version"]),
    ]
}

fn command_version_or_unavailable(command: HostProbeCommand, args: &[&str]) -> String {
    command_output_line(command, args).unwrap_or_else(|| "unavailable".to_owned())
}

fn command_tool_summary(command: HostProbeCommand, args: &[&str]) -> String {
    let version = command_version_or_unavailable(command, args);
    let program = command.label();
    format!("{program}:{version}")
}

fn command_output_line(command: HostProbeCommand, args: &[&str]) -> Option<String> {
    let output = command.output(args)?;
    let text = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr)
    } else {
        String::from_utf8_lossy(&output.stdout)
    };
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
}

impl HostProbeCommand {
    fn label(self) -> &'static str {
        match self {
            Self::Uname => "uname",
            Self::Hostname => "hostname",
            Self::Git => "git",
            Self::Fusermount3 => "fusermount3",
            Self::Fusermount => "fusermount",
            Self::MkfsExt4 => "mkfs.ext4",
            Self::MkfsBtrfs => "mkfs.btrfs",
            Self::Cargo => "cargo",
            Self::Rustc => "rustc",
            Self::E2fsck => "e2fsck",
            Self::Btrfs => "btrfs",
            Self::Fsck => "fsck",
        }
    }

    fn output(self, args: &[&str]) -> Option<std::process::Output> {
        let mut command = match self {
            Self::Uname => Command::new("uname"),
            Self::Hostname => Command::new("hostname"),
            Self::Git => Command::new("git"),
            Self::Fusermount3 => Command::new("fusermount3"),
            Self::Fusermount => Command::new("fusermount"),
            Self::MkfsExt4 => Command::new("mkfs.ext4"),
            Self::MkfsBtrfs => Command::new("mkfs.btrfs"),
            Self::Cargo => Command::new("cargo"),
            Self::Rustc => Command::new("rustc"),
            Self::E2fsck => Command::new("e2fsck"),
            Self::Btrfs => Command::new("btrfs"),
            Self::Fsck => Command::new("fsck"),
        };
        command.args(args).output().ok()
    }
}

fn proc_limit_soft_value(label: &str) -> Option<u64> {
    let limits = fs::read_to_string("/proc/self/limits").ok()?;
    limits.lines().find_map(|line| {
        let rest = line.strip_prefix(label)?;
        let value = rest.split_whitespace().next()?;
        if value == "unlimited" {
            Some(u64::MAX)
        } else {
            value.parse().ok()
        }
    })
}

fn validate_adaptive_runtime_manifest_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_adaptive_runtime_manifest_cmd_args(args)? else {
        return Ok(());
    };
    let manifest = load_adaptive_runtime_evidence_manifest(Path::new(&cmd_args.manifest_path))?;
    let reference_epoch_days = match &cmd_args.reference_timestamp {
        Some(timestamp) => Some(
            parse_manifest_timestamp_epoch_days(timestamp)
                .with_context(|| format!("invalid --reference-timestamp {timestamp}"))?,
        ),
        None => {
            AdaptiveRuntimeEvidenceValidationConfig::with_current_reference().reference_epoch_days
        }
    };
    let validation_config = AdaptiveRuntimeEvidenceValidationConfig {
        reference_epoch_days,
        current_git_sha: cmd_args.current_git_sha,
    };
    let report =
        validate_adaptive_runtime_evidence_manifest_with_config(&manifest, &validation_config);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_adaptive_runtime_evidence_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "adaptive runtime manifest report written: {} valid={} accepted={}",
            path, report.valid, report.runtime_controls_accepted
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_adaptive_runtime_evidence_markdown(&report)),
        )?;
        println!("adaptive runtime manifest summary written: {path}");
    }

    fail_on_adaptive_runtime_evidence_errors(&report)
}

fn parse_adaptive_runtime_manifest_cmd_args(
    args: &[String],
) -> Result<Option<AdaptiveRuntimeManifestCmdArgs>> {
    let mut manifest_path = DEFAULT_ADAPTIVE_RUNTIME_EVIDENCE_MANIFEST.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut reference_timestamp: Option<String> = None;
    let mut current_git_sha: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                args.get(i)
                    .context("--manifest requires a path")?
                    .clone_into(&mut manifest_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--reference-timestamp" => {
                i += 1;
                reference_timestamp = Some(
                    args.get(i)
                        .context("--reference-timestamp requires a value")?
                        .to_owned(),
                );
            }
            "--current-git-sha" => {
                i += 1;
                current_git_sha = Some(
                    args.get(i)
                        .context("--current-git-sha requires a value")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_adaptive_runtime_manifest_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-adaptive-runtime-manifest argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(AdaptiveRuntimeManifestCmdArgs {
        manifest_path,
        out_path,
        summary_out_path,
        format,
        reference_timestamp,
        current_git_sha,
    }))
}

fn validate_topology_runtime_advisor_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_topology_runtime_advisor_cmd_args(args)? else {
        return Ok(());
    };
    let manifest = load_topology_runtime_advisor_manifest(Path::new(&cmd_args.manifest_path))?;
    let reference_epoch_days = match &cmd_args.reference_timestamp {
        Some(timestamp) => Some(
            parse_manifest_timestamp_epoch_days(timestamp)
                .with_context(|| format!("invalid --reference-timestamp {timestamp}"))?,
        ),
        None => TopologyRuntimeAdvisorValidationConfig::default().reference_epoch_days,
    };
    let report = validate_topology_runtime_advisor_manifest_with_config(
        &manifest,
        &TopologyRuntimeAdvisorValidationConfig {
            reference_epoch_days,
            max_age_days: cmd_args.max_age_days,
        },
    );
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_topology_runtime_advisor_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "topology runtime advisor report written: {} valid={} advisory_only={}",
            path, report.valid, report.advisory_only
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_topology_runtime_advisor_markdown(&report)),
        )?;
        println!("topology runtime advisor summary written: {path}");
    }

    if let Some(path) = cmd_args.structured_log_out_path {
        write_text_file(
            Path::new(&path),
            &render_topology_runtime_advisor_structured_log(&report),
        )?;
        println!("topology runtime advisor structured log written: {path}");
    }

    fail_on_topology_runtime_advisor_errors(&report)
}

fn score_topology_runtime_advisor_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_topology_runtime_advisor_cmd_args(args)? else {
        return Ok(());
    };
    let manifest = load_topology_runtime_advisor_manifest(Path::new(&cmd_args.manifest_path))?;
    let reference_epoch_days = match &cmd_args.reference_timestamp {
        Some(timestamp) => Some(
            parse_manifest_timestamp_epoch_days(timestamp)
                .with_context(|| format!("invalid --reference-timestamp {timestamp}"))?,
        ),
        None => TopologyRuntimeAdvisorValidationConfig::default().reference_epoch_days,
    };
    let report = score_topology_runtime_advisor_manifest_with_config(
        &manifest,
        &TopologyRuntimeAdvisorValidationConfig {
            reference_epoch_days,
            max_age_days: cmd_args.max_age_days,
        },
    );
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_topology_runtime_advisor_score_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "topology runtime advisor score written: {} valid={} recommendation={}",
            path,
            report.valid,
            report.recommendation.as_deref().unwrap_or("none")
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!(
                "{}\n",
                render_topology_runtime_advisor_score_markdown(&report)
            ),
        )?;
        println!("topology runtime advisor score summary written: {path}");
    }

    if let Some(path) = cmd_args.structured_log_out_path {
        write_text_file(
            Path::new(&path),
            &render_topology_runtime_advisor_score_structured_log(&report),
        )?;
        println!("topology runtime advisor score structured log written: {path}");
    }

    fail_on_topology_runtime_advisor_score_errors(&report)
}

fn parse_topology_runtime_advisor_cmd_args(
    args: &[String],
) -> Result<Option<TopologyRuntimeAdvisorCmdArgs>> {
    let mut manifest_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut structured_log_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut reference_timestamp: Option<String> = None;
    let mut max_age_days = TopologyRuntimeAdvisorValidationConfig::default().max_age_days;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest_path = Some(
                    args.get(i)
                        .context("--manifest requires a path")?
                        .to_owned(),
                );
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--structured-log-out" => {
                i += 1;
                structured_log_out_path = Some(
                    args.get(i)
                        .context("--structured-log-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--reference-timestamp" => {
                i += 1;
                reference_timestamp = Some(
                    args.get(i)
                        .context("--reference-timestamp requires a value")?
                        .to_owned(),
                );
            }
            "--max-age-days" => {
                i += 1;
                let raw = args.get(i).context("--max-age-days requires a value")?;
                max_age_days = raw
                    .parse::<u32>()
                    .with_context(|| format!("invalid --max-age-days {raw}"))?;
            }
            "--help" | "-h" => {
                print_topology_runtime_advisor_usage();
                return Ok(None);
            }
            other => bail!("unknown topology-runtime-advisor argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(TopologyRuntimeAdvisorCmdArgs {
        manifest_path: manifest_path.context("--manifest is required")?,
        out_path,
        summary_out_path,
        structured_log_out_path,
        format,
        reference_timestamp,
        max_age_days,
    }))
}

fn validate_permissioned_campaign_broker_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_permissioned_campaign_broker_cmd_args(args)? else {
        return Ok(());
    };
    let manifest = load_permissioned_campaign_broker_manifest(Path::new(&cmd_args.manifest_path))?;
    let reference_epoch_days = match &cmd_args.reference_timestamp {
        Some(timestamp) => parse_manifest_timestamp_epoch_days(timestamp)
            .with_context(|| format!("invalid --reference-timestamp {timestamp}"))?,
        None => {
            PermissionedCampaignBrokerValidationConfig::with_current_reference()
                .reference_epoch_days
        }
    };
    let validation_config = PermissionedCampaignBrokerValidationConfig {
        reference_epoch_days,
    };
    let report = validate_permissioned_campaign_broker_manifest(&manifest, &validation_config);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_permissioned_campaign_broker_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "permissioned campaign broker report written: {} valid={} issues={}",
            path, report.valid, report.issue_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!(
                "{}\n",
                render_permissioned_campaign_broker_markdown(&report)
            ),
        )?;
        println!("permissioned campaign broker summary written: {path}");
    }

    fail_on_permissioned_campaign_broker_errors(&report)
}

fn parse_permissioned_campaign_broker_cmd_args(
    args: &[String],
) -> Result<Option<PermissionedCampaignBrokerCmdArgs>> {
    let mut manifest_path = DEFAULT_PERMISSIONED_CAMPAIGN_BROKER_MANIFEST.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut reference_timestamp: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                args.get(i)
                    .context("--manifest requires a path")?
                    .clone_into(&mut manifest_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--reference-timestamp" => {
                i += 1;
                reference_timestamp = Some(
                    args.get(i)
                        .context("--reference-timestamp requires a value")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_permissioned_campaign_broker_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-permissioned-campaign-broker argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(PermissionedCampaignBrokerCmdArgs {
        manifest_path,
        out_path,
        summary_out_path,
        format,
        reference_timestamp,
    }))
}

fn validate_permissioned_campaign_ledger_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_permissioned_campaign_ledger_cmd_args(args)? else {
        return Ok(());
    };
    let manifest = load_permissioned_campaign_broker_manifest(Path::new(&cmd_args.manifest_path))?;
    let ledger = load_permissioned_campaign_execution_ledger(Path::new(&cmd_args.ledger_path))?;
    let report = validate_permissioned_campaign_execution_ledger(
        &manifest,
        &ledger,
        &PermissionedCampaignExecutionLedgerValidationConfig {
            current_git_sha: cmd_args.current_git_sha,
        },
    );
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => {
            render_permissioned_campaign_execution_ledger_markdown(&report)
        }
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "permissioned campaign execution ledger report written: {} valid={} issues={}",
            path, report.valid, report.issue_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!(
                "{}\n",
                render_permissioned_campaign_execution_ledger_markdown(&report)
            ),
        )?;
        println!("permissioned campaign execution ledger summary written: {path}");
    }

    fail_on_permissioned_campaign_execution_ledger_errors(&report)
}

fn parse_permissioned_campaign_ledger_cmd_args(
    args: &[String],
) -> Result<Option<PermissionedCampaignLedgerCmdArgs>> {
    let mut manifest_path = DEFAULT_PERMISSIONED_CAMPAIGN_BROKER_MANIFEST.to_owned();
    let mut ledger_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut current_git_sha: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                args.get(i)
                    .context("--manifest requires a path")?
                    .clone_into(&mut manifest_path);
            }
            "--ledger" => {
                i += 1;
                ledger_path = Some(args.get(i).context("--ledger requires a path")?.to_owned());
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--current-git-sha" => {
                i += 1;
                current_git_sha = Some(
                    args.get(i)
                        .context("--current-git-sha requires a value")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_permissioned_campaign_ledger_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-permissioned-campaign-ledger argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(PermissionedCampaignLedgerCmdArgs {
        manifest_path,
        ledger_path: ledger_path.context("--ledger is required")?,
        out_path,
        summary_out_path,
        format,
        current_git_sha,
    }))
}

fn generate_permissioned_campaign_packet_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_permissioned_campaign_packet_cmd_args(args)? else {
        return Ok(());
    };
    let manifest = load_permissioned_campaign_broker_manifest(Path::new(&cmd_args.manifest_path))?;
    let reference_epoch_days = match &cmd_args.reference_timestamp {
        Some(timestamp) => parse_manifest_timestamp_epoch_days(timestamp)
            .with_context(|| format!("invalid --reference-timestamp {timestamp}"))?,
        None => {
            PermissionedCampaignBrokerValidationConfig::with_current_reference()
                .reference_epoch_days
        }
    };
    let validation_config = PermissionedCampaignBrokerValidationConfig {
        reference_epoch_days,
    };
    let generation = PermissionedCampaignHandoffGeneration {
        generated_at: cmd_args.generated_at,
        generated_by: cmd_args.generated_by,
        git_sha: cmd_args.git_sha,
    };
    let packet =
        generate_permissioned_campaign_handoff_packet(&manifest, &validation_config, generation)?;
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&packet)?,
        ProofBundleFormat::Markdown => render_permissioned_campaign_handoff_markdown(&packet),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "permissioned campaign handoff packet written: {} packet_id={}",
            path, packet.packet_id
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!(
                "{}\n",
                render_permissioned_campaign_handoff_markdown(&packet)
            ),
        )?;
        println!("permissioned campaign handoff summary written: {path}");
    }

    Ok(())
}

fn parse_permissioned_campaign_packet_cmd_args(
    args: &[String],
) -> Result<Option<PermissionedCampaignPacketCmdArgs>> {
    let mut manifest_path = DEFAULT_PERMISSIONED_CAMPAIGN_BROKER_MANIFEST.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut reference_timestamp: Option<String> = None;
    let mut generated_at: Option<String> = None;
    let mut generated_by: Option<String> = None;
    let mut git_sha: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                args.get(i)
                    .context("--manifest requires a path")?
                    .clone_into(&mut manifest_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--reference-timestamp" => {
                i += 1;
                reference_timestamp = Some(
                    args.get(i)
                        .context("--reference-timestamp requires a value")?
                        .to_owned(),
                );
            }
            "--generated-at" => {
                i += 1;
                generated_at = Some(
                    args.get(i)
                        .context("--generated-at requires a value")?
                        .to_owned(),
                );
            }
            "--generated-by" => {
                i += 1;
                generated_by = Some(
                    args.get(i)
                        .context("--generated-by requires a value")?
                        .to_owned(),
                );
            }
            "--git-sha" => {
                i += 1;
                git_sha = Some(
                    args.get(i)
                        .context("--git-sha requires a value")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_permissioned_campaign_packet_usage();
                return Ok(None);
            }
            other => bail!("unknown generate-permissioned-campaign-packet argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(PermissionedCampaignPacketCmdArgs {
        manifest_path,
        out_path,
        summary_out_path,
        format,
        reference_timestamp,
        generated_at: generated_at.unwrap_or_else(current_unix_timestamp_label),
        generated_by: generated_by
            .or_else(|| env::var("AGENT_NAME").ok())
            .unwrap_or_else(|| "unknown-agent".to_owned()),
        git_sha: git_sha
            .or_else(|| env::var("GIT_SHA").ok())
            .unwrap_or_else(|| "unknown".to_owned()),
    }))
}

fn validate_swarm_capability_calibration_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_swarm_capability_calibration_cmd_args(args)? else {
        return Ok(());
    };
    let manifest = load_swarm_capability_calibration_manifest(Path::new(&cmd_args.manifest_path))?;
    let reference_epoch_days = match &cmd_args.reference_timestamp {
        Some(timestamp) => parse_manifest_timestamp_epoch_days(timestamp)
            .with_context(|| format!("invalid --reference-timestamp {timestamp}"))?,
        None => SwarmCapabilityCalibrationValidationConfig::default().reference_epoch_days,
    };
    let report = validate_swarm_capability_calibration_manifest(
        &manifest,
        &SwarmCapabilityCalibrationValidationConfig {
            reference_epoch_days,
        },
    );
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_swarm_capability_calibration_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "swarm capability calibration report written: {} valid={} classification={}",
            path, report.valid, report.classification
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!(
                "{}\n",
                render_swarm_capability_calibration_markdown(&report)
            ),
        )?;
        println!("swarm capability calibration summary written: {path}");
    }

    fail_on_swarm_capability_calibration_errors(&report)
}

fn parse_swarm_capability_calibration_cmd_args(
    args: &[String],
) -> Result<Option<SwarmCapabilityCalibrationCmdArgs>> {
    let mut manifest_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut reference_timestamp: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest_path = Some(
                    args.get(i)
                        .context("--manifest requires a path")?
                        .to_owned(),
                );
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--reference-timestamp" => {
                i += 1;
                reference_timestamp = Some(
                    args.get(i)
                        .context("--reference-timestamp requires a value")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_swarm_capability_calibration_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-swarm-capability-calibration argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(SwarmCapabilityCalibrationCmdArgs {
        manifest_path: manifest_path.context("--manifest is required")?,
        out_path,
        summary_out_path,
        format,
        reference_timestamp,
    }))
}

fn validate_swarm_workload_harness_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_swarm_workload_harness_cmd_args(args)? else {
        return Ok(());
    };
    let manifest = load_swarm_workload_harness_manifest(Path::new(&cmd_args.manifest_path))?;
    let reference_epoch_days = match &cmd_args.reference_timestamp {
        Some(timestamp) => Some(
            parse_manifest_timestamp_epoch_days(timestamp)
                .with_context(|| format!("invalid --reference-timestamp {timestamp}"))?,
        ),
        None => SwarmWorkloadHarnessValidationConfig::with_current_reference().reference_epoch_days,
    };
    let validation_config = SwarmWorkloadHarnessValidationConfig {
        reference_epoch_days,
        max_age_days: cmd_args.max_age_days,
    };
    let report =
        validate_swarm_workload_harness_manifest_with_config(&manifest, &validation_config);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_swarm_workload_harness_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "swarm workload harness report written: {} valid={} profiles={} scenarios={}",
            path, report.valid, report.profile_count, report.scenario_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_swarm_workload_harness_markdown(&report)),
        )?;
        println!("swarm workload harness summary written: {path}");
    }

    fail_on_swarm_workload_harness_errors(&report)
}

fn parse_swarm_workload_harness_cmd_args(
    args: &[String],
) -> Result<Option<SwarmWorkloadHarnessCmdArgs>> {
    let mut manifest_path = DEFAULT_SWARM_WORKLOAD_HARNESS_MANIFEST.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut max_age_days = DEFAULT_SWARM_WORKLOAD_HARNESS_MAX_AGE_DAYS;
    let mut reference_timestamp: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                args.get(i)
                    .context("--manifest requires a path")?
                    .clone_into(&mut manifest_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--max-age-days" => {
                i += 1;
                max_age_days = args
                    .get(i)
                    .context("--max-age-days requires a value")?
                    .parse()
                    .context("--max-age-days must be an integer")?;
            }
            "--reference-timestamp" => {
                i += 1;
                reference_timestamp = Some(
                    args.get(i)
                        .context("--reference-timestamp requires a value")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_swarm_workload_harness_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-swarm-workload-harness argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(SwarmWorkloadHarnessCmdArgs {
        manifest_path,
        out_path,
        summary_out_path,
        format,
        max_age_days,
        reference_timestamp,
    }))
}

fn validate_wal_group_commit_gate_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_wal_group_commit_gate_cmd_args(args)? else {
        return Ok(());
    };
    let manifest = load_wal_group_commit_gate_manifest(Path::new(&cmd_args.manifest_path))?;
    let report = validate_wal_group_commit_gate_manifest(&manifest);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_wal_group_commit_gate_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "WAL group-commit gate report written: {} valid={} scenarios={} measurements={}",
            path, report.valid, report.scenario_count, report.measurement_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_wal_group_commit_gate_markdown(&report)),
        )?;
        println!("WAL group-commit gate summary written: {path}");
    }

    fail_on_wal_group_commit_gate_errors(&report)
}

fn parse_wal_group_commit_gate_cmd_args(
    args: &[String],
) -> Result<Option<WalGroupCommitGateCmdArgs>> {
    let mut manifest_path = DEFAULT_WAL_GROUP_COMMIT_GATE_MANIFEST.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                args.get(i)
                    .context("--manifest requires a path")?
                    .clone_into(&mut manifest_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_wal_group_commit_gate_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-wal-group-commit-gate argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(WalGroupCommitGateCmdArgs {
        manifest_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_scrub_repair_scheduler_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_scrub_repair_scheduler_cmd_args(args)? else {
        return Ok(());
    };
    let manifest = load_scrub_repair_scheduler_manifest(Path::new(&cmd_args.manifest_path))?;
    let report = validate_scrub_repair_scheduler_manifest(&manifest);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_scrub_repair_scheduler_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "scrub/repair scheduler report written: {} valid={} scenarios={}",
            path, report.valid, report.scenario_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_scrub_repair_scheduler_markdown(&report)),
        )?;
        println!("scrub/repair scheduler summary written: {path}");
    }

    fail_on_scrub_repair_scheduler_errors(&report)
}

fn parse_scrub_repair_scheduler_cmd_args(
    args: &[String],
) -> Result<Option<ScrubRepairSchedulerCmdArgs>> {
    let mut manifest_path = DEFAULT_SCRUB_REPAIR_SCHEDULER_MANIFEST.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                args.get(i)
                    .context("--manifest requires a path")?
                    .clone_into(&mut manifest_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_scrub_repair_scheduler_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-scrub-repair-scheduler argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(ScrubRepairSchedulerCmdArgs {
        manifest_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_adversarial_threat_model_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_adversarial_threat_model_cmd_args(args)? else {
        return Ok(());
    };
    let model = match (&cmd_args.model_path, &cmd_args.model_json_env) {
        (Some(path), None) => load_adversarial_threat_model(Path::new(path))?,
        (None, Some(env_name)) => {
            let raw = env::var(env_name)
                .with_context(|| format!("--model-json-env variable {env_name} is not set"))?;
            serde_json::from_str(&raw)
                .with_context(|| format!("invalid adversarial threat model JSON from {env_name}"))?
        }
        (Some(_), Some(_)) => bail!("use either --model or --model-json-env, not both"),
        (None, None) => {
            bail!("--model or --model-json-env is required for threat model validation")
        }
    };
    let report = validate_adversarial_threat_model(&model, &cmd_args.artifact_root);
    let output = serde_json::to_string_pretty(&report)?;

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "adversarial threat model report written: {} valid={} scenarios={}",
            path, report.valid, report.scenario_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.artifact_out_path {
        let artifact_manifest = build_adversarial_threat_model_sample_artifact_manifest(
            &model,
            &cmd_args.artifact_root,
            &report.evaluated_scenarios,
        );
        write_text_file(
            Path::new(&path),
            &format!("{}\n", serde_json::to_string_pretty(&artifact_manifest)?),
        )?;
        println!("adversarial threat model sample artifact manifest written: {path}");
    }

    if let Some(path) = cmd_args.wording_out_path {
        write_text_file(Path::new(&path), &adversarial_threat_model_wording(&report))?;
        println!("adversarial threat model wording written: {path}");
    }

    fail_on_adversarial_threat_model_errors(&report)
}

fn adversarial_threat_model_wording(
    report: &ffs_harness::adversarial_threat_model::AdversarialThreatModelReport,
) -> String {
    let mut lines = report
        .generated_security_wording
        .iter()
        .map(|entry| {
            format!(
                "{}\t{}\t{}\t{}",
                entry.feature_id, entry.docs_wording_id, entry.state, entry.wording
            )
        })
        .collect::<Vec<_>>();
    lines.push(String::new());
    lines.join("\n")
}

fn parse_adversarial_threat_model_cmd_args(
    args: &[String],
) -> Result<Option<AdversarialThreatModelCmdArgs>> {
    let mut model_path: Option<String> = None;
    let mut model_json_env: Option<String> = None;
    let mut artifact_root = "artifacts/security/dry-run".to_owned();
    let mut out_path: Option<String> = None;
    let mut artifact_out_path: Option<String> = None;
    let mut wording_out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--model" => {
                i += 1;
                model_path = Some(args.get(i).context("--model requires a path")?.to_owned());
            }
            "--model-json-env" => {
                i += 1;
                model_json_env = Some(
                    args.get(i)
                        .context("--model-json-env requires a variable name")?
                        .to_owned(),
                );
            }
            "--artifact-root" => {
                i += 1;
                args.get(i)
                    .context("--artifact-root requires a path")?
                    .clone_into(&mut artifact_root);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--artifact-out" => {
                i += 1;
                artifact_out_path = Some(
                    args.get(i)
                        .context("--artifact-out requires a path")?
                        .to_owned(),
                );
            }
            "--wording-out" => {
                i += 1;
                wording_out_path = Some(
                    args.get(i)
                        .context("--wording-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_adversarial_threat_model_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-adversarial-threat-model argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(AdversarialThreatModelCmdArgs {
        model_path,
        model_json_env,
        artifact_root,
        out_path,
        artifact_out_path,
        wording_out_path,
    }))
}

fn validate_soak_canary_campaigns_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_soak_canary_campaign_cmd_args(args)? else {
        return Ok(());
    };
    let manifest = load_soak_canary_campaign_manifest(Path::new(&cmd_args.manifest_path))?;
    let report = validate_soak_canary_campaign_manifest(&manifest, &cmd_args.artifact_root);
    let output = serde_json::to_string_pretty(&report)?;

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "soak/canary campaign report written: {} valid={} profiles={} workloads={}",
            path, report.valid, report.profile_count, report.workload_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.artifact_out_path {
        let artifact_manifest = build_soak_canary_sample_artifact_manifest(
            &manifest,
            &cmd_args.artifact_root,
            &report.failure_evaluations,
        );
        write_text_file(
            Path::new(&path),
            &format!("{}\n", serde_json::to_string_pretty(&artifact_manifest)?),
        )?;
        println!("soak/canary sample artifact manifest written: {path}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &render_soak_canary_campaign_markdown(&report),
        )?;
        println!("soak/canary campaign summary written: {path}");
    }

    fail_on_soak_canary_campaign_errors(&report)
}

fn parse_soak_canary_campaign_cmd_args(
    args: &[String],
) -> Result<Option<SoakCanaryCampaignCmdArgs>> {
    let mut manifest_path: Option<String> = None;
    let mut artifact_root = "artifacts/soak/dry-run".to_owned();
    let mut out_path: Option<String> = None;
    let mut artifact_out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest_path = Some(
                    args.get(i)
                        .context("--manifest requires a path")?
                        .to_owned(),
                );
            }
            "--artifact-root" => {
                i += 1;
                args.get(i)
                    .context("--artifact-root requires a path")?
                    .clone_into(&mut artifact_root);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--artifact-out" => {
                i += 1;
                artifact_out_path = Some(
                    args.get(i)
                        .context("--artifact-out requires a path")?
                        .to_owned(),
                );
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_soak_canary_campaign_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-soak-canary-campaigns argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(SoakCanaryCampaignCmdArgs {
        manifest_path: manifest_path
            .context("--manifest is required for soak/canary campaign validation")?,
        artifact_root,
        out_path,
        artifact_out_path,
        summary_out_path,
    }))
}

fn validate_repair_confidence_lab_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_repair_confidence_lab_cmd_args(args)? else {
        return Ok(());
    };
    let spec = if let Some(env_name) = cmd_args.spec_json_env.as_deref() {
        let spec_json = env::var(env_name)
            .with_context(|| format!("--spec-json-env variable {env_name} is unset"))?;
        serde_json::from_str(&spec_json)
            .with_context(|| format!("invalid repair confidence lab JSON in ${env_name}"))?
    } else {
        load_repair_confidence_lab_spec(Path::new(&cmd_args.spec_path))?
    };
    let report = validate_repair_confidence_lab(&spec);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_repair_confidence_lab_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "repair confidence lab report written: {} valid={} scenarios={} mutation_allowed={} mutation_refused={}",
            path,
            report.valid,
            report.scenario_count,
            report.mutation_allowed_count,
            report.mutation_refused_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &render_repair_confidence_lab_markdown(&report),
        )?;
        println!("repair confidence lab summary written: {path}");
    }

    fail_on_repair_confidence_lab_errors(&report)
}

fn parse_repair_confidence_lab_cmd_args(
    args: &[String],
) -> Result<Option<RepairConfidenceLabCmdArgs>> {
    let mut spec_path = DEFAULT_REPAIR_CONFIDENCE_LAB_PATH.to_owned();
    let mut spec_json_env: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--spec" => {
                i += 1;
                args.get(i)
                    .context("--spec requires a path")?
                    .clone_into(&mut spec_path);
            }
            "--spec-json-env" => {
                i += 1;
                spec_json_env = Some(
                    args.get(i)
                        .context("--spec-json-env requires an environment variable name")?
                        .to_owned(),
                );
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--select" => {
                i += 1;
                let _ = args.get(i).context("--select requires a scenario id")?;
            }
            "--help" | "-h" => {
                print_repair_confidence_lab_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-repair-confidence-lab argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(RepairConfidenceLabCmdArgs {
        spec_path,
        spec_json_env,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_operator_recovery_drill_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_operator_recovery_drill_cmd_args(args)? else {
        return Ok(());
    };
    let spec = load_operator_recovery_drill_spec(Path::new(&cmd_args.spec_path))?;
    let report = validate_operator_recovery_drill(&spec);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_operator_recovery_drill_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "operator recovery drill report written: {} valid={} scenarios={} mutation_allowed={} mutation_refused={}",
            path,
            report.valid,
            report.scenario_count,
            report.mutation_allowed_count,
            report.mutation_refused_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &render_operator_recovery_drill_markdown(&report),
        )?;
        println!("operator recovery drill summary written: {path}");
    }

    fail_on_operator_recovery_drill_errors(&report)
}

fn parse_operator_recovery_drill_cmd_args(
    args: &[String],
) -> Result<Option<OperatorRecoveryDrillCmdArgs>> {
    let mut spec_path = DEFAULT_OPERATOR_RECOVERY_DRILL_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--spec" => {
                i += 1;
                args.get(i)
                    .context("--spec requires a path")?
                    .clone_into(&mut spec_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--select" => {
                i += 1;
                let _ = args.get(i).context("--select requires a scenario id")?;
            }
            "--help" | "-h" => {
                print_operator_recovery_drill_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-operator-recovery-drill argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(OperatorRecoveryDrillCmdArgs {
        spec_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_repair_writeback_serialization_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_repair_writeback_serialization_cmd_args(args)? else {
        return Ok(());
    };
    let contract = match (&cmd_args.contract_path, &cmd_args.contract_json_env) {
        (Some(path), None) => load_repair_writeback_serialization_contract(Path::new(path))?,
        (None, Some(env_name)) => {
            let raw = env::var(env_name)
                .with_context(|| format!("--contract-json-env variable {env_name} is not set"))?;
            serde_json::from_str(&raw).with_context(|| {
                format!("invalid repair/writeback contract JSON from {env_name}")
            })?
        }
        (Some(_), Some(_)) => bail!("use either --contract or --contract-json-env, not both"),
        (None, None) => {
            bail!(
                "--contract or --contract-json-env is required for repair/writeback serialization validation"
            )
        }
    };
    let report =
        validate_repair_writeback_serialization_contract(&contract, &cmd_args.artifact_root);
    let output = serde_json::to_string_pretty(&report)?;

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "repair/writeback serialization report written: {} valid={} scenarios={} transitions={}",
            path, report.valid, report.scenario_count, report.transition_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.artifact_out_path {
        let artifact_manifest = build_repair_writeback_serialization_sample_artifact_manifest(
            &contract,
            &cmd_args.artifact_root,
            &report,
        );
        write_text_file(
            Path::new(&path),
            &format!("{}\n", serde_json::to_string_pretty(&artifact_manifest)?),
        )?;
        println!("repair/writeback sample artifact manifest written: {path}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &render_repair_writeback_serialization_markdown(&report),
        )?;
        println!("repair/writeback serialization summary written: {path}");
    }

    if let Some(path) = cmd_args.proof_summary_out_path {
        let proof_summary = build_repair_writeback_proof_summary(&contract, &report);
        write_text_file(
            Path::new(&path),
            &format!("{}\n", serde_json::to_string_pretty(&proof_summary)?),
        )?;
        println!("repair/writeback proof summary written: {path}");
    }

    fail_on_repair_writeback_serialization_errors(&report)
}

fn parse_repair_writeback_serialization_cmd_args(
    args: &[String],
) -> Result<Option<RepairWritebackSerializationCmdArgs>> {
    let mut contract_path: Option<String> = None;
    let mut contract_json_env: Option<String> = None;
    let mut artifact_root = "artifacts/repair-writeback/dry-run".to_owned();
    let mut out_path: Option<String> = None;
    let mut artifact_out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut proof_summary_out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--contract" => {
                i += 1;
                contract_path = Some(
                    args.get(i)
                        .context("--contract requires a path")?
                        .to_owned(),
                );
            }
            "--contract-json-env" => {
                i += 1;
                contract_json_env = Some(
                    args.get(i)
                        .context("--contract-json-env requires a variable name")?
                        .to_owned(),
                );
            }
            "--artifact-root" => {
                i += 1;
                args.get(i)
                    .context("--artifact-root requires a path")?
                    .clone_into(&mut artifact_root);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--artifact-out" => {
                i += 1;
                artifact_out_path = Some(
                    args.get(i)
                        .context("--artifact-out requires a path")?
                        .to_owned(),
                );
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--proof-summary-out" => {
                i += 1;
                proof_summary_out_path = Some(
                    args.get(i)
                        .context("--proof-summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_repair_writeback_serialization_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-repair-writeback-serialization argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(RepairWritebackSerializationCmdArgs {
        contract_path,
        contract_json_env,
        artifact_root,
        out_path,
        artifact_out_path,
        summary_out_path,
        proof_summary_out_path,
    }))
}

fn validate_writeback_cache_audit_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_writeback_cache_audit_cmd_args(args)? else {
        return Ok(());
    };
    let gate = load_writeback_cache_audit_gate(Path::new(&cmd_args.gate_path))?;
    let reproduction_command = cmd_args.reproduction_command.clone().unwrap_or_else(|| {
        format!(
            "ffs-harness validate-writeback-cache-audit --gate {} --scenario-id {}",
            cmd_args.gate_path, cmd_args.scenario_id
        )
    });
    let report =
        build_writeback_cache_audit_report(&gate, &cmd_args.scenario_id, &reproduction_command)?;
    let output = serde_json::to_string_pretty(&report)?;

    if let Some(path) = &cmd_args.out_path {
        write_text_file(Path::new(path), &format!("{output}\n"))?;
        println!(
            "writeback-cache audit report written: {} scenario={} require_accept={}",
            path, report.scenario_id, cmd_args.require_accept
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = &cmd_args.summary_out_path {
        write_text_file(
            Path::new(path),
            &render_writeback_cache_audit_markdown(&report),
        )?;
        println!("writeback-cache audit summary written: {path}");
    }

    if cmd_args.require_accept {
        fail_on_writeback_cache_audit_errors(&report)?;
    }
    Ok(())
}

fn parse_writeback_cache_audit_cmd_args(
    args: &[String],
) -> Result<Option<WritebackCacheAuditCmdArgs>> {
    let mut gate_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut scenario_id = "writeback_cache_audit_cli".to_owned();
    let mut reproduction_command: Option<String> = None;
    let mut require_accept = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--gate" => {
                i += 1;
                gate_path = Some(args.get(i).context("--gate requires a path")?.to_owned());
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--scenario-id" => {
                i += 1;
                args.get(i)
                    .context("--scenario-id requires a scenario id")?
                    .clone_into(&mut scenario_id);
            }
            "--reproduction-command" => {
                i += 1;
                reproduction_command = Some(
                    args.get(i)
                        .context("--reproduction-command requires a command string")?
                        .to_owned(),
                );
            }
            "--require-accept" => {
                require_accept = true;
            }
            "--help" | "-h" => {
                print_writeback_cache_audit_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-writeback-cache-audit argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(WritebackCacheAuditCmdArgs {
        gate_path: gate_path.context("--gate is required for writeback-cache audit validation")?,
        out_path,
        summary_out_path,
        scenario_id,
        reproduction_command,
        require_accept,
    }))
}

fn validate_writeback_cache_ordering_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_writeback_cache_ordering_cmd_args(args)? else {
        return Ok(());
    };
    let oracle = load_writeback_ordering_oracle(Path::new(&cmd_args.oracle_path))?;
    let reproduction_command = cmd_args.reproduction_command.clone().unwrap_or_else(|| {
        format!(
            "ffs-harness validate-writeback-cache-ordering --oracle {} --scenario-id {}",
            cmd_args.oracle_path, cmd_args.scenario_id
        )
    });
    let report =
        build_writeback_ordering_report(&oracle, &cmd_args.scenario_id, &reproduction_command)?;
    let output = serde_json::to_string_pretty(&report)?;

    if let Some(path) = &cmd_args.out_path {
        write_text_file(Path::new(path), &format!("{output}\n"))?;
        println!(
            "writeback-cache ordering report written: {} scenario={} require_accept={}",
            path, report.scenario_id, cmd_args.require_accept
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = &cmd_args.summary_out_path {
        write_text_file(
            Path::new(path),
            &render_writeback_ordering_markdown(&report),
        )?;
        println!("writeback-cache ordering summary written: {path}");
    }

    if cmd_args.require_accept {
        fail_on_writeback_ordering_errors(&report)?;
    }
    Ok(())
}

fn parse_writeback_cache_ordering_cmd_args(
    args: &[String],
) -> Result<Option<WritebackCacheOrderingCmdArgs>> {
    let mut oracle_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut scenario_id = "writeback_cache_ordering_cli".to_owned();
    let mut reproduction_command: Option<String> = None;
    let mut require_accept = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--oracle" => {
                i += 1;
                oracle_path = Some(args.get(i).context("--oracle requires a path")?.to_owned());
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--scenario-id" => {
                i += 1;
                args.get(i)
                    .context("--scenario-id requires a scenario id")?
                    .clone_into(&mut scenario_id);
            }
            "--reproduction-command" => {
                i += 1;
                reproduction_command = Some(
                    args.get(i)
                        .context("--reproduction-command requires a command string")?
                        .to_owned(),
                );
            }
            "--require-accept" => {
                require_accept = true;
            }
            "--help" | "-h" => {
                print_writeback_cache_ordering_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-writeback-cache-ordering argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(WritebackCacheOrderingCmdArgs {
        oracle_path: oracle_path
            .context("--oracle is required for writeback-cache ordering validation")?,
        out_path,
        summary_out_path,
        scenario_id,
        reproduction_command,
        require_accept,
    }))
}

fn validate_writeback_cache_crash_replay_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_writeback_cache_crash_replay_cmd_args(args)? else {
        return Ok(());
    };
    let oracle = load_writeback_crash_replay_oracle(Path::new(&cmd_args.oracle_path))?;
    let reproduction_command = cmd_args.reproduction_command.clone().unwrap_or_else(|| {
        format!(
            "ffs-harness validate-writeback-cache-crash-replay --oracle {} --scenario-id {}",
            cmd_args.oracle_path, cmd_args.scenario_id
        )
    });
    let report =
        build_writeback_crash_replay_report(&oracle, &cmd_args.scenario_id, &reproduction_command)?;
    let output = serde_json::to_string_pretty(&report)?;

    if let Some(path) = &cmd_args.out_path {
        write_text_file(Path::new(path), &format!("{output}\n"))?;
        println!(
            "writeback-cache crash/replay report written: {} scenario={} require_accept={}",
            path, report.scenario_id, cmd_args.require_accept
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = &cmd_args.summary_out_path {
        write_text_file(
            Path::new(path),
            &render_writeback_crash_replay_markdown(&report),
        )?;
        println!("writeback-cache crash/replay summary written: {path}");
    }

    if cmd_args.require_accept {
        fail_on_writeback_crash_replay_errors(&report)?;
    }
    Ok(())
}

fn parse_writeback_cache_crash_replay_cmd_args(
    args: &[String],
) -> Result<Option<WritebackCacheCrashReplayCmdArgs>> {
    let mut oracle_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut scenario_id = "writeback_cache_crash_replay_cli".to_owned();
    let mut reproduction_command: Option<String> = None;
    let mut require_accept = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--oracle" => {
                i += 1;
                oracle_path = Some(args.get(i).context("--oracle requires a path")?.to_owned());
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--scenario-id" => {
                i += 1;
                args.get(i)
                    .context("--scenario-id requires a scenario id")?
                    .clone_into(&mut scenario_id);
            }
            "--reproduction-command" => {
                i += 1;
                reproduction_command = Some(
                    args.get(i)
                        .context("--reproduction-command requires a command string")?
                        .to_owned(),
                );
            }
            "--require-accept" => {
                require_accept = true;
            }
            "--help" | "-h" => {
                print_writeback_cache_crash_replay_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-writeback-cache-crash-replay argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(WritebackCacheCrashReplayCmdArgs {
        oracle_path: oracle_path
            .context("--oracle is required for writeback-cache crash/replay validation")?,
        out_path,
        summary_out_path,
        scenario_id,
        reproduction_command,
        require_accept,
    }))
}

fn validate_proof_overhead_budget_cmd(args: &[String]) -> Result<()> {
    let mut budget_path: Option<String> = None;
    let mut metrics_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--budget" => {
                i += 1;
                budget_path = Some(args.get(i).context("--budget requires a path")?.to_owned());
            }
            "--metrics" => {
                i += 1;
                metrics_path = Some(args.get(i).context("--metrics requires a path")?.to_owned());
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--help" | "-h" => {
                print_proof_overhead_budget_usage();
                return Ok(());
            }
            other => bail!("unknown validate-proof-overhead-budget argument: {other}"),
        }
        i += 1;
    }

    let budget = load_proof_overhead_budget_config(Path::new(
        budget_path.as_deref().context("--budget is required")?,
    ))?;
    let metrics = load_observed_proof_metrics(Path::new(
        metrics_path.as_deref().context("--metrics is required")?,
    ))?;
    let report = evaluate_proof_overhead_budget(&budget, &metrics);
    let json = serde_json::to_string_pretty(&report)?;

    if let Some(path) = out_path {
        let path = Path::new(&path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "proof overhead budget report written: {} verdict={}",
            path.display(),
            report.release_gate_verdict.label()
        );
    } else {
        println!("{json}");
    }

    fail_on_proof_overhead_budget_errors(&report)
}

fn xfstests_report(args: &[String]) -> Result<()> {
    let config = parse_xfstests_report_config(args)?;
    let selected_path = Path::new(
        config
            .selected
            .as_deref()
            .context("--selected is required")?,
    );
    let results_path = Path::new(
        config
            .results_json
            .as_deref()
            .context("--results-json is required")?,
    );
    let junit_path = Path::new(
        config
            .junit_xml
            .as_deref()
            .context("--junit-xml is required")?,
    );
    let selected_tests = load_selected_tests(selected_path)?;
    let mut run = build_xfstests_run(&config, &selected_tests)?;
    apply_xfstests_metadata(&config, &mut run)?;

    fs::write(results_path, serde_json::to_string_pretty(&run)? + "\n")
        .with_context(|| format!("failed to write {}", results_path.display()))?;
    write_junit_xml(junit_path, &run)?;
    println!("{}", serde_json::to_string_pretty(&run)?);
    Ok(())
}

fn xfstests_baseline_manifest(args: &[String]) -> Result<()> {
    let config = parse_xfstests_baseline_manifest_config(args)?;
    let selected_path = Path::new(
        config
            .selected
            .as_deref()
            .context("--selected is required")?,
    );
    let results_path = Path::new(
        config
            .results_json
            .as_deref()
            .context("--results-json is required")?,
    );
    let manifest_out_path = Path::new(
        config
            .manifest_out
            .as_deref()
            .context("--manifest-out is required")?,
    );
    let summary_out_path = Path::new(
        config
            .summary_out
            .as_deref()
            .context("--summary-out is required")?,
    );
    let selected_tests = load_selected_tests(selected_path)?;
    let run: XfstestsRun = serde_json::from_str(
        &fs::read_to_string(results_path)
            .with_context(|| format!("failed to read {}", results_path.display()))?,
    )
    .with_context(|| format!("invalid xfstests results JSON {}", results_path.display()))?;
    let raw_artifact_paths = config
        .raw_artifacts
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let raw_artifact_refs = raw_artifact_paths
        .iter()
        .map(PathBuf::as_path)
        .collect::<Vec<_>>();
    let output_paths = config.output_paths.into_iter().collect();

    let manifest = build_xfstests_baseline_manifest(XfstestsBaselineManifestInput {
        baseline_id: config
            .baseline_id
            .as_deref()
            .context("--baseline-id is required")?,
        subset_version: config
            .subset_version
            .as_deref()
            .context("--subset-version is required")?,
        environment_manifest_id: config
            .environment_manifest_id
            .as_deref()
            .context("--environment-manifest-id is required")?,
        environment_age_secs: config.environment_age_secs,
        environment_max_age_secs: config.environment_max_age_secs,
        selected_tests: &selected_tests,
        run: &run,
        raw_artifact_paths: &raw_artifact_refs,
        generated_summary_path: summary_out_path,
        command_transcript: config
            .command_transcript
            .as_deref()
            .context("--command-transcript is required")?,
        checkpoint_id: config
            .checkpoint_id
            .as_deref()
            .context("--checkpoint-id is required")?,
        resume_command: config
            .resume_command
            .as_deref()
            .context("--resume-command is required")?,
        cleanup_status: config
            .cleanup_status
            .as_deref()
            .context("--cleanup-status is required")?,
        reproduction_command: config
            .reproduction_command
            .as_deref()
            .context("--reproduction-command is required")?,
        output_paths,
    })?;
    let errors = validate_xfstests_baseline_manifest(&manifest);
    if !errors.is_empty() {
        bail!(
            "xfstests baseline manifest validation failed: {}",
            errors.join("; ")
        );
    }

    write_text_file(
        manifest_out_path,
        &(serde_json::to_string_pretty(&manifest)? + "\n"),
    )?;
    write_text_file(
        summary_out_path,
        &render_xfstests_baseline_markdown(&manifest),
    )?;
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

fn xfstests_failure_triage(args: &[String]) -> Result<()> {
    let config = parse_xfstests_failure_triage_config(args)?;
    let baseline_manifest_path = Path::new(
        config
            .baseline_manifest
            .as_deref()
            .context("--baseline-manifest is required")?,
    );
    let triage_out_path = Path::new(
        config
            .triage_out
            .as_deref()
            .context("--triage-out is required")?,
    );
    let summary_out_path = Path::new(
        config
            .summary_out
            .as_deref()
            .context("--summary-out is required")?,
    );
    let baseline_manifest: XfstestsBaselineManifest = serde_json::from_str(
        &fs::read_to_string(baseline_manifest_path)
            .with_context(|| format!("failed to read {}", baseline_manifest_path.display()))?,
    )
    .with_context(|| {
        format!(
            "invalid xfstests baseline manifest JSON {}",
            baseline_manifest_path.display()
        )
    })?;
    let report = build_xfstests_failure_triage_report(XfstestsFailureTriageInput {
        triage_id: config
            .triage_id
            .as_deref()
            .context("--triage-id is required")?,
        baseline_manifest_path,
        baseline_manifest: &baseline_manifest,
        reproduction_command: config
            .reproduction_command
            .as_deref()
            .context("--reproduction-command is required")?,
    })?;

    write_text_file(
        triage_out_path,
        &(serde_json::to_string_pretty(&report)? + "\n"),
    )?;
    write_text_file(
        summary_out_path,
        &render_xfstests_failure_triage_markdown(&report),
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn parse_xfstests_report_config(args: &[String]) -> Result<XfstestsReportConfig> {
    let mut config = XfstestsReportConfig::default();
    let mut index = 0_usize;

    while index < args.len() {
        match args[index].as_str() {
            "--selected" => {
                config.selected = Some(require_value(args, index, "--selected")?.clone());
                index += 2;
            }
            "--check-log" => {
                config.check_log = Some(require_value(args, index, "--check-log")?.clone());
                index += 2;
            }
            "--results-json" => {
                config.results_json = Some(require_value(args, index, "--results-json")?.clone());
                index += 2;
            }
            "--junit-xml" => {
                config.junit_xml = Some(require_value(args, index, "--junit-xml")?.clone());
                index += 2;
            }
            "--allowlist-json" => {
                config.allowlist_json =
                    Some(require_value(args, index, "--allowlist-json")?.clone());
                index += 2;
            }
            "--baseline-json" => {
                config.baseline_json = Some(require_value(args, index, "--baseline-json")?.clone());
                index += 2;
            }
            "--check-rc" => {
                config.check_rc = require_value(args, index, "--check-rc")?
                    .parse()
                    .context("invalid --check-rc value")?;
                index += 2;
            }
            "--dry-run" => {
                config.dry_run = require_value(args, index, "--dry-run")?
                    .parse::<u8>()
                    .context("invalid --dry-run value")?
                    != 0;
                index += 2;
            }
            "--uniform-status" => {
                config.uniform_status = Some(parse_xfstests_status(require_value(
                    args,
                    index,
                    "--uniform-status",
                )?)?);
                index += 2;
            }
            "--uniform-note" => {
                config.uniform_note = Some(require_value(args, index, "--uniform-note")?.clone());
                index += 2;
            }
            other => bail!("unknown xfstests-report option: {other}"),
        }
    }

    Ok(config)
}

fn parse_xfstests_baseline_manifest_config(
    args: &[String],
) -> Result<XfstestsBaselineManifestConfig> {
    let mut config = XfstestsBaselineManifestConfig {
        environment_max_age_secs: 3600,
        ..XfstestsBaselineManifestConfig::default()
    };
    let mut index = 0_usize;

    while index < args.len() {
        match args[index].as_str() {
            "--selected" => {
                config.selected = Some(require_value(args, index, "--selected")?.clone());
                index += 2;
            }
            "--results-json" => {
                config.results_json = Some(require_value(args, index, "--results-json")?.clone());
                index += 2;
            }
            "--manifest-out" => {
                config.manifest_out = Some(require_value(args, index, "--manifest-out")?.clone());
                index += 2;
            }
            "--summary-out" => {
                config.summary_out = Some(require_value(args, index, "--summary-out")?.clone());
                index += 2;
            }
            "--baseline-id" => {
                config.baseline_id = Some(require_value(args, index, "--baseline-id")?.clone());
                index += 2;
            }
            "--subset-version" => {
                config.subset_version =
                    Some(require_value(args, index, "--subset-version")?.clone());
                index += 2;
            }
            "--environment-manifest-id" => {
                config.environment_manifest_id =
                    Some(require_value(args, index, "--environment-manifest-id")?.clone());
                index += 2;
            }
            "--environment-age-secs" => {
                config.environment_age_secs = require_value(args, index, "--environment-age-secs")?
                    .parse()
                    .context("invalid --environment-age-secs value")?;
                index += 2;
            }
            "--environment-max-age-secs" => {
                config.environment_max_age_secs =
                    require_value(args, index, "--environment-max-age-secs")?
                        .parse()
                        .context("invalid --environment-max-age-secs value")?;
                index += 2;
            }
            "--command-transcript" => {
                config.command_transcript =
                    Some(require_value(args, index, "--command-transcript")?.clone());
                index += 2;
            }
            "--checkpoint-id" => {
                config.checkpoint_id = Some(require_value(args, index, "--checkpoint-id")?.clone());
                index += 2;
            }
            "--resume-command" => {
                config.resume_command =
                    Some(require_value(args, index, "--resume-command")?.clone());
                index += 2;
            }
            "--cleanup-status" => {
                config.cleanup_status =
                    Some(require_value(args, index, "--cleanup-status")?.clone());
                index += 2;
            }
            "--reproduction-command" => {
                config.reproduction_command =
                    Some(require_value(args, index, "--reproduction-command")?.clone());
                index += 2;
            }
            "--raw-artifact" => {
                config
                    .raw_artifacts
                    .push(require_value(args, index, "--raw-artifact")?.clone());
                index += 2;
            }
            "--output-path" => {
                let (key, value) = parse_key_value(require_value(args, index, "--output-path")?)?;
                config.output_paths.push((key, value));
                index += 2;
            }
            other => bail!("unknown xfstests-baseline-manifest option: {other}"),
        }
    }

    if config.raw_artifacts.is_empty() {
        bail!("--raw-artifact is required at least once");
    }
    Ok(config)
}

fn parse_xfstests_failure_triage_config(args: &[String]) -> Result<XfstestsFailureTriageConfig> {
    let mut config = XfstestsFailureTriageConfig::default();
    let mut index = 0_usize;

    while index < args.len() {
        match args[index].as_str() {
            "--baseline-manifest" => {
                config.baseline_manifest =
                    Some(require_value(args, index, "--baseline-manifest")?.clone());
                index += 2;
            }
            "--triage-out" => {
                config.triage_out = Some(require_value(args, index, "--triage-out")?.clone());
                index += 2;
            }
            "--summary-out" => {
                config.summary_out = Some(require_value(args, index, "--summary-out")?.clone());
                index += 2;
            }
            "--triage-id" => {
                config.triage_id = Some(require_value(args, index, "--triage-id")?.clone());
                index += 2;
            }
            "--reproduction-command" => {
                config.reproduction_command =
                    Some(require_value(args, index, "--reproduction-command")?.clone());
                index += 2;
            }
            other => bail!("unknown xfstests-failure-triage option: {other}"),
        }
    }

    Ok(config)
}

fn parse_key_value(raw: &str) -> Result<(String, String)> {
    let (key, value) = raw
        .split_once('=')
        .with_context(|| format!("expected KEY=VALUE, got {raw}"))?;
    if key.is_empty() || value.is_empty() {
        bail!("expected non-empty KEY=VALUE, got {raw}");
    }
    Ok((key.to_owned(), value.to_owned()))
}

fn require_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a String> {
    args.get(index + 1)
        .with_context(|| format!("{flag} requires a value"))
}

fn write_text_file(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, text).with_context(|| format!("failed to write {}", path.display()))
}

fn parse_xfstests_status(raw: &str) -> Result<XfstestsStatus> {
    match raw {
        "passed" => Ok(XfstestsStatus::Passed),
        "failed" => Ok(XfstestsStatus::Failed),
        "skipped" => Ok(XfstestsStatus::Skipped),
        "not_run" => Ok(XfstestsStatus::NotRun),
        "planned" => Ok(XfstestsStatus::Planned),
        other => bail!("invalid --uniform-status value: {other}"),
    }
}

fn build_xfstests_run(
    config: &XfstestsReportConfig,
    selected_tests: &[String],
) -> Result<ffs_harness::xfstests::XfstestsRun> {
    if let Some(status) = config.uniform_status {
        return Ok(summarize_uniform(
            selected_tests,
            status,
            config.uniform_note.as_deref(),
        ));
    }

    let check_log_path = Path::new(
        config
            .check_log
            .as_deref()
            .context("--check-log is required")?,
    );
    let check_log_text = fs::read_to_string(check_log_path)
        .with_context(|| format!("failed to read {}", check_log_path.display()))?;
    Ok(parse_check_output(
        selected_tests,
        &check_log_text,
        config.check_rc,
        config.dry_run,
    ))
}

fn apply_xfstests_metadata(
    config: &XfstestsReportConfig,
    run: &mut ffs_harness::xfstests::XfstestsRun,
) -> Result<()> {
    apply_allowlist_if_present(run, config.allowlist_json.as_deref())?;
    emit_baseline_comparison_if_present(run, config.baseline_json.as_deref())
}

fn apply_allowlist_if_present(
    run: &mut ffs_harness::xfstests::XfstestsRun,
    allowlist_json: Option<&str>,
) -> Result<()> {
    let Some(path) = allowlist_json else {
        return Ok(());
    };
    let allowlist_path = Path::new(path);
    if allowlist_path.exists() {
        let allowlist = load_allowlist(allowlist_path)?;
        apply_allowlist(run, &allowlist);
    }
    Ok(())
}

fn emit_baseline_comparison_if_present(
    run: &mut ffs_harness::xfstests::XfstestsRun,
    baseline_json: Option<&str>,
) -> Result<()> {
    let Some(path) = baseline_json else {
        return Ok(());
    };
    let baseline_path = Path::new(path);
    if !baseline_path.exists() {
        return Ok(());
    }

    let baseline = load_baseline(baseline_path)?;
    let comparison = compare_against_baseline(run, &baseline);
    if !comparison.regressions.is_empty()
        || !comparison.improvements.is_empty()
        || !comparison.unchanged.is_empty()
    {
        eprintln!("{}", serde_json::to_string_pretty(&comparison)?);
    }
    Ok(())
}

fn validate_operational_manifest_cmd(args: &[String]) -> Result<()> {
    let manifest_path = Path::new(
        args.first()
            .context("usage: ffs-harness validate-operational-manifest <manifest.json>")?,
    );
    if args.len() != 1 {
        bail!("usage: ffs-harness validate-operational-manifest <manifest.json>");
    }

    let manifest_text = fs::read_to_string(manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;
    let manifest: ArtifactManifest = serde_json::from_str(&manifest_text)
        .with_context(|| format!("invalid manifest json {}", manifest_path.display()))?;
    let errors = validate_operational_manifest(&manifest);
    if !errors.is_empty() {
        for error in &errors {
            eprintln!("manifest validation error: {error}");
        }
        bail!(
            "operational manifest validation failed with {} error(s)",
            errors.len()
        );
    }

    println!(
        "operational manifest valid: run_id={} gate_id={} scenarios={} artifacts={}",
        manifest.run_id,
        manifest.gate_id,
        manifest.scenarios.len(),
        manifest.artifacts.len()
    );
    Ok(())
}

fn validate_artifact_schema_fixtures_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_artifact_schema_fixtures_args(args)? else {
        return Ok(());
    };
    let report = validate_artifact_schema_fixture_dir(
        Path::new(&cmd_args.fixture_dir),
        &cmd_args.reproduction_command,
    );
    let output = serde_json::to_string_pretty(&report)?;

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "artifact schema fixture report written: {} valid={} fixtures={} positive={} negative={} validator_version={} reproduction_command={}",
            path,
            report.valid,
            report.fixture_count,
            report.positive_count,
            report.negative_count,
            report.validator_version,
            report.reproduction_command,
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        let summary = render_artifact_schema_fixture_markdown(&report);
        write_text_file(Path::new(&path), &format!("{summary}\n"))?;
        println!("artifact schema fixture summary written: {path}");
    }

    if !report.valid {
        bail!(
            "artifact schema fixture validation failed: fixtures={} suite_errors={}",
            report.fixture_count,
            report.errors.len()
        );
    }
    Ok(())
}

fn parse_artifact_schema_fixtures_args(
    args: &[String],
) -> Result<Option<ArtifactSchemaFixturesCmdArgs>> {
    let mut fixture_dir = "tests/artifact-schema-fixtures".to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut reproduction_command =
        "ffs-harness validate-artifact-schema-fixtures --fixtures tests/artifact-schema-fixtures"
            .to_owned();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--fixtures" => {
                i += 1;
                args.get(i)
                    .context("--fixtures requires a path")?
                    .clone_into(&mut fixture_dir);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--reproduction-command" => {
                i += 1;
                args.get(i)
                    .context("--reproduction-command requires a value")?
                    .clone_into(&mut reproduction_command);
            }
            "--help" | "-h" => {
                print_artifact_schema_fixtures_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-artifact-schema-fixtures argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(ArtifactSchemaFixturesCmdArgs {
        fixture_dir,
        out_path,
        summary_out_path,
        reproduction_command,
    }))
}

fn validate_open_ended_inventory_cmd(args: &[String]) -> Result<()> {
    let mut out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--help" | "-h" => {
                print_open_ended_inventory_usage();
                return Ok(());
            }
            other => bail!("unknown validate-open-ended-inventory argument: {other}"),
        }
        i += 1;
    }

    let report = validate_current_inventory()?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        let path = Path::new(&path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "open-ended inventory report written: {} rows={}",
            path.display(),
            report.row_count
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

fn open_ended_note_scanner_cmd(args: &[String]) -> Result<()> {
    let mut source_paths = Vec::new();
    let mut out_path: Option<String> = None;
    let mut allow_invalid = false;
    let mut reproduction_command: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--source" => {
                i += 1;
                source_paths.push(args.get(i).context("--source requires a path")?.to_owned());
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--allow-invalid" => {
                allow_invalid = true;
            }
            "--reproduction-command" => {
                i += 1;
                reproduction_command = Some(
                    args.get(i)
                        .context("--reproduction-command requires a value")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_open_ended_note_scanner_usage();
                return Ok(());
            }
            other => bail!("unknown open-ended-note-scanner argument: {other}"),
        }
        i += 1;
    }

    if source_paths.is_empty() {
        bail!("open-ended-note-scanner requires at least one --source FILE");
    }

    let sources = source_paths
        .iter()
        .map(|source_path| {
            fs::read_to_string(source_path)
                .with_context(|| format!("failed to read {source_path}"))
                .map(|text| OpenEndedNoteSource {
                    source_path: source_path.to_owned(),
                    text,
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let output_path = out_path.as_deref().unwrap_or("stdout");
    let reproduction_command = reproduction_command.unwrap_or_else(|| {
        let mut command = "ffs-harness open-ended-note-scanner".to_owned();
        for source_path in &source_paths {
            command.push_str(" --source ");
            command.push_str(source_path);
        }
        if let Some(path) = &out_path {
            command.push_str(" --out ");
            command.push_str(path);
        }
        command
    });

    let report = scan_open_ended_notes(&sources, output_path, &reproduction_command);
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        let path = Path::new(&path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "open-ended note scan report written: {} matches={} unresolved={} valid={}",
            path.display(),
            report.match_count,
            report.unresolved_note_count,
            report.valid
        );
    } else {
        println!("{json}");
    }

    if !report.valid && !allow_invalid {
        bail!(
            "open-ended note scanner failed: {}",
            report.errors.join("; ")
        );
    }
    Ok(())
}

fn validate_source_scope_manifest_cmd(args: &[String]) -> Result<()> {
    let mut manifest_path = DEFAULT_SOURCE_SCOPE_MANIFEST_PATH.to_owned();
    let mut workspace_root = ".".to_owned();
    let mut out_path: Option<String> = None;
    let mut remove_source_family: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                args.get(i)
                    .context("--manifest requires a path")?
                    .clone_into(&mut manifest_path);
            }
            "--workspace-root" => {
                i += 1;
                args.get(i)
                    .context("--workspace-root requires a path")?
                    .clone_into(&mut workspace_root);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--remove-source-family" => {
                i += 1;
                remove_source_family = Some(
                    args.get(i)
                        .context("--remove-source-family requires a source family")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_source_scope_manifest_usage();
                return Ok(());
            }
            other => bail!("unknown validate-source-scope-manifest argument: {other}"),
        }
        i += 1;
    }

    let mut manifest = load_source_scope_manifest(&manifest_path)?;
    if let Some(source_family) = &remove_source_family {
        manifest
            .sources
            .retain(|entry| entry.source_family != *source_family);
    }
    let out = out_path.as_deref().map(Path::new);
    let reproduction_command = format!(
        "cargo run -p ffs-harness -- validate-source-scope-manifest --manifest {manifest_path} --workspace-root {workspace_root}"
    );
    let report = scan_source_scope_manifest(
        &manifest,
        Path::new(&workspace_root),
        out,
        &reproduction_command,
    );
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "source scope manifest report written: {} sources={} valid={}",
            path.display(),
            report.source_count,
            report.valid
        );
    } else {
        println!("{json}");
    }
    if !report.valid {
        bail!(
            "source scope manifest failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(())
}

fn validate_deferred_parity_audit_cmd(args: &[String]) -> Result<()> {
    let mut config = DeferredParityAuditConfig::default();
    let mut out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--issues" => {
                i += 1;
                config.issues_jsonl =
                    Path::new(args.get(i).context("--issues requires a path")?).to_path_buf();
            }
            "--report" => {
                i += 1;
                config.report_markdown =
                    Path::new(args.get(i).context("--report requires a path")?).to_path_buf();
            }
            "--doc" => {
                i += 1;
                config
                    .docs
                    .push(Path::new(args.get(i).context("--doc requires a path")?).to_path_buf());
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--help" | "-h" => {
                print_deferred_parity_audit_usage();
                return Ok(());
            }
            other => bail!("unknown validate-deferred-parity-audit argument: {other}"),
        }
        i += 1;
    }

    let report = run_deferred_parity_audit(&config)?;
    fail_on_audit_errors(&report)?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        let path = Path::new(&path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "deferred parity audit report written: {} rows={} findings={}",
            path.display(),
            report.registry_row_count,
            report.detected_gap_count
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

fn validate_ambition_evidence_matrix_cmd(args: &[String]) -> Result<()> {
    let mut config = AmbitionEvidenceMatrixConfig::default();
    let mut out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--issues" => {
                i += 1;
                config.issues_jsonl =
                    Path::new(args.get(i).context("--issues requires a path")?).to_path_buf();
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--help" | "-h" => {
                print_ambition_evidence_matrix_usage();
                return Ok(());
            }
            other => bail!("unknown validate-ambition-evidence-matrix argument: {other}"),
        }
        i += 1;
    }

    if let Some(path) = &out_path {
        config.generated_artifact_paths = vec![path.clone()];
    }

    let report = run_ambition_evidence_matrix(&config)?;
    fail_on_ambition_evidence_matrix_errors(&report)?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        let path = Path::new(&path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "ambition evidence matrix report written: {} rows={}",
            path.display(),
            report.row_count
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

fn validate_support_state_accounting_cmd(args: &[String]) -> Result<()> {
    let mut config = SupportStateAccountingConfig::default();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--issues" => {
                i += 1;
                config.issues_jsonl =
                    Path::new(args.get(i).context("--issues requires a path")?).to_path_buf();
            }
            "--feature-parity" => {
                i += 1;
                config.feature_parity_markdown =
                    Path::new(args.get(i).context("--feature-parity requires a path")?)
                        .to_path_buf();
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_support_state_accounting_usage();
                return Ok(());
            }
            other => bail!("unknown validate-support-state-accounting argument: {other}"),
        }
        i += 1;
    }

    config.generated_artifact_paths = match (&out_path, &summary_out_path) {
        (Some(json), Some(markdown)) => vec![json.clone(), markdown.clone()],
        (Some(json), None) => vec![json.clone()],
        (None, Some(markdown)) => vec![markdown.clone()],
        (None, None) => config.generated_artifact_paths,
    };

    let report = run_support_state_accounting(&config)?;
    fail_on_support_state_accounting_errors(&report)?;
    let json = serde_json::to_string_pretty(&report)?;
    let output = match format {
        ProofBundleFormat::Json => json,
        ProofBundleFormat::Markdown => render_support_state_markdown(&report),
    };
    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "support-state accounting report written: {} rows={} states={}",
            path,
            report.row_count,
            report.grouped_by_support_state.len()
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_support_state_markdown(&report)),
        )?;
        println!("support-state accounting markdown written: {path}");
    }
    Ok(())
}

fn validate_docs_status_drift_cmd(args: &[String]) -> Result<()> {
    let mut config = DocsStatusDriftConfig::default();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--issues" => {
                i += 1;
                config.issues_jsonl =
                    Path::new(args.get(i).context("--issues requires a path")?).to_path_buf();
            }
            "--feature-parity" => {
                i += 1;
                config.feature_parity_markdown =
                    Path::new(args.get(i).context("--feature-parity requires a path")?)
                        .to_path_buf();
            }
            "--snippets" => {
                i += 1;
                config.snippets_json = Some(
                    Path::new(args.get(i).context("--snippets requires a path")?).to_path_buf(),
                );
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_docs_status_drift_usage();
                return Ok(());
            }
            other => bail!("unknown validate-docs-status-drift argument: {other}"),
        }
        i += 1;
    }

    config.generated_artifact_paths = match (&out_path, &summary_out_path) {
        (Some(json), Some(markdown)) => vec![json.clone(), markdown.clone()],
        (Some(json), None) => vec![json.clone()],
        (None, Some(markdown)) => vec![markdown.clone()],
        (None, None) => config.generated_artifact_paths,
    };

    let report = run_docs_status_drift(&config)?;
    let json = serde_json::to_string_pretty(&report)?;
    let output = match format {
        ProofBundleFormat::Json => json,
        ProofBundleFormat::Markdown => render_docs_status_drift_markdown(&report),
    };
    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "docs status drift report written: {} rules={} observations={} release_gate_pass={}",
            path, report.rule_count, report.observation_count, report.release_gate_pass
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_docs_status_drift_markdown(&report)),
        )?;
        println!("docs status drift markdown written: {path}");
    }
    fail_on_docs_status_drift_errors(&report)
}

#[allow(clippy::too_many_lines)]
fn claimability_plan_cmd(args: &[String]) -> Result<()> {
    let mut tracker_report_path: Option<String> = None;
    let mut reservation_report_path: Option<String> = None;
    let mut bv_report_path: Option<String> = None;
    let mut rch_capacity_preflight_report_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut generated_at = current_unix_timestamp_label();
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--tracker-report" => {
                tracker_report_path = Some(require_value(args, i, "--tracker-report")?.to_owned());
                i += 2;
            }
            "--reservation-report" => {
                reservation_report_path =
                    Some(require_value(args, i, "--reservation-report")?.to_owned());
                i += 2;
            }
            "--bv-report" => {
                bv_report_path = Some(require_value(args, i, "--bv-report")?.to_owned());
                i += 2;
            }
            "--rch-capacity-preflight-report" => {
                rch_capacity_preflight_report_path =
                    Some(require_value(args, i, "--rch-capacity-preflight-report")?.to_owned());
                i += 2;
            }
            "--generated-at" => {
                require_value(args, i, "--generated-at")?.clone_into(&mut generated_at);
                i += 2;
            }
            "--format" => {
                format = parse_proof_bundle_format(require_value(args, i, "--format")?)?;
                i += 2;
            }
            "--out" => {
                out_path = Some(require_value(args, i, "--out")?.to_owned());
                i += 2;
            }
            "--summary-out" => {
                summary_out_path = Some(require_value(args, i, "--summary-out")?.to_owned());
                i += 2;
            }
            "--help" | "-h" => {
                print_claimability_plan_usage();
                return Ok(());
            }
            other => bail!("unknown claimability-plan argument: {other}"),
        }
    }

    let tracker_report_path = tracker_report_path.context("--tracker-report is required")?;
    let tracker_json = fs::read_to_string(&tracker_report_path)
        .with_context(|| format!("failed to read {tracker_report_path}"))?;
    let tracker_report: TrackerSourceHygieneReport = serde_json::from_str(&tracker_json)
        .with_context(|| format!("failed to parse tracker report {tracker_report_path}"))?;

    let reservation_report = if let Some(path) = &reservation_report_path {
        let json = fs::read_to_string(path).with_context(|| format!("failed to read {path}"))?;
        Some(
            serde_json::from_str::<AgentMailReservationSnapshotReport>(&json)
                .with_context(|| format!("failed to parse reservation report {path}"))?,
        )
    } else {
        None
    };
    let bv_snapshot = if let Some(path) = &bv_report_path {
        let json = fs::read_to_string(path).with_context(|| format!("failed to read {path}"))?;
        Some(
            serde_json::from_str::<serde_json::Value>(&json)
                .with_context(|| format!("failed to parse bv report {path}"))?,
        )
    } else {
        None
    };
    let rch_capacity_preflight = if let Some(path) = &rch_capacity_preflight_report_path {
        let source_report = load_rch_capacity_preflight_report(path)?;
        let validation_report =
            validate_rch_capacity_preflight_report(&source_report, path.clone());
        Some((source_report, validation_report))
    } else {
        None
    };
    let config = ClaimabilityPlanConfig {
        generated_at,
        tracker_report_path,
        reservation_report_path,
        bv_report_path,
        rch_capacity_preflight_report_path,
    };
    let rch_capacity_preflight_input =
        rch_capacity_preflight
            .as_ref()
            .map(
                |(source_report, validation_report)| ClaimabilityRchCapacityPreflightInput {
                    source_report,
                    validation_report,
                },
            );
    let report = build_claimability_plan_report(
        &config,
        &tracker_report,
        reservation_report.as_ref(),
        bv_snapshot.as_ref(),
        rch_capacity_preflight_input,
    );
    let json = serde_json::to_string_pretty(&report)?;
    let markdown = render_claimability_plan_markdown(&report);
    let output = match format {
        ProofBundleFormat::Json => format!("{json}\n"),
        ProofBundleFormat::Markdown => markdown.clone(),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &output)?;
        println!(
            "claimability plan written: {} rows={} status={}",
            path,
            report.rows.len(),
            report.status
        );
    } else {
        print!("{output}");
    }
    if let Some(path) = summary_out_path {
        write_text_file(Path::new(&path), &markdown)?;
        println!("claimability plan markdown written: {path}");
    }
    fail_on_claimability_plan_errors(&report)
}

fn validate_tracker_source_hygiene_cmd(args: &[String]) -> Result<()> {
    let mut config = tracker_source_hygiene_config_from_env()?;
    let mut out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--issues" => {
                config.issues_jsonl = Path::new(require_value(args, i, "--issues")?).to_path_buf();
                i += 2;
            }
            "--out" => {
                out_path = Some(require_value(args, i, "--out")?.to_owned());
                i += 2;
            }
            "--strict" => {
                config.strict = true;
                i += 1;
            }
            "--now-epoch" => {
                config.report_now_epoch = require_value(args, i, "--now-epoch")?
                    .parse()
                    .context("invalid --now-epoch value")?;
                i += 2;
            }
            "--stale-in-progress-seconds" => {
                config.stale_in_progress_seconds =
                    require_value(args, i, "--stale-in-progress-seconds")?
                        .parse()
                        .context("invalid --stale-in-progress-seconds value")?;
                i += 2;
            }
            "--xfstests-real-run-ack" => {
                config.xfstests_real_run_ack =
                    Some(require_value(args, i, "--xfstests-real-run-ack")?.to_owned());
                i += 2;
            }
            "--swarm-workload-enabled" => {
                config.swarm_workload_enabled = true;
                i += 1;
            }
            "--swarm-workload-real-run-ack" => {
                config.swarm_workload_real_run_ack =
                    Some(require_value(args, i, "--swarm-workload-real-run-ack")?.to_owned());
                i += 2;
            }
            "--export-dir" => {
                config.local_graph_export_paths = Some(TrackerLocalGraphExportPaths::for_dir(
                    Path::new(require_value(args, i, "--export-dir")?),
                ));
                i += 2;
            }
            "--help" | "-h" => {
                print_tracker_source_hygiene_usage();
                return Ok(());
            }
            other => bail!("unknown validate-tracker-source-hygiene argument: {other}"),
        }
    }

    let report = run_tracker_source_hygiene(&config)?;
    write_tracker_source_hygiene_local_graph_exports(&config, &report)?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{json}\n"))?;
        println!(
            "tracker source hygiene report written: {} local_open={} ready={} foreign_open={}",
            path,
            report.local_open,
            report.source_aware_ready_rows.len(),
            report.foreign_open
        );
    } else {
        println!("{json}");
    }
    fail_on_tracker_source_hygiene_errors(&report)
}

fn tracker_source_hygiene_config_from_env() -> Result<TrackerSourceHygieneConfig> {
    let mut config = TrackerSourceHygieneConfig {
        xfstests_real_run_ack: env::var("XFSTESTS_REAL_RUN_ACK").ok(),
        swarm_workload_enabled: env::var("FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD")
            .is_ok_and(|value| value == "1"),
        swarm_workload_real_run_ack: env::var("FFS_SWARM_WORKLOAD_REAL_RUN_ACK").ok(),
        ..TrackerSourceHygieneConfig::default()
    };

    if env::var("TRACKER_SOURCE_HYGIENE_STRICT").is_ok_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    }) {
        config.strict = true;
    }
    if let Ok(value) = env::var("TRACKER_SOURCE_HYGIENE_NOW_EPOCH") {
        config.report_now_epoch = value
            .parse()
            .context("invalid TRACKER_SOURCE_HYGIENE_NOW_EPOCH value")?;
    }
    if let Ok(value) = env::var("TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS") {
        config.stale_in_progress_seconds = value
            .parse()
            .context("invalid TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS value")?;
    }

    Ok(config)
}

fn validate_fuzz_smoke_cmd(args: &[String]) -> Result<()> {
    let mut manifest_path = DEFAULT_FUZZ_SMOKE_MANIFEST_PATH.to_owned();
    let mut workspace_root = ".".to_owned();
    let mut out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                args.get(i)
                    .context("--manifest requires a path")?
                    .clone_into(&mut manifest_path);
            }
            "--workspace-root" => {
                i += 1;
                args.get(i)
                    .context("--workspace-root requires a path")?
                    .clone_into(&mut workspace_root);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--help" | "-h" => {
                print_fuzz_smoke_usage();
                return Ok(());
            }
            other => bail!("unknown validate-fuzz-smoke argument: {other}"),
        }
        i += 1;
    }

    let manifest = load_fuzz_smoke_manifest(Path::new(&manifest_path))?;
    let report = run_fuzz_smoke_manifest(&manifest, Path::new(&workspace_root));
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{json}\n"))?;
        println!(
            "fuzz-smoke report written: {} seeds={} checksum={}",
            path, report.seed_count, report.corpus_checksum
        );
    } else {
        println!("{json}");
    }
    fail_on_fuzz_smoke_errors(&report)
}

fn validate_mounted_write_matrix_cmd(args: &[String]) -> Result<()> {
    let mut matrix_path = DEFAULT_MATRIX_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--matrix" => {
                i += 1;
                args.get(i)
                    .context("--matrix requires a path")?
                    .clone_into(&mut matrix_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--help" | "-h" => {
                print_mounted_write_matrix_usage();
                return Ok(());
            }
            other => bail!("unknown validate-mounted-write-matrix argument: {other}"),
        }
        i += 1;
    }

    let matrix = load_mounted_write_matrix(Path::new(&matrix_path))?;
    let report = validate_mounted_write_matrix(&matrix);
    fail_on_mounted_write_matrix_errors(&report)?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        let path = Path::new(&path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "mounted write matrix report written: {} scenarios={}",
            path.display(),
            report.scenario_count
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

fn validate_mounted_write_error_classes_cmd(args: &[String]) -> Result<()> {
    let mut catalog_path = DEFAULT_MOUNTED_WRITE_ERROR_CLASSES_PATH.to_owned();
    let mut matrix_path = DEFAULT_MATRIX_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--catalog" => {
                i += 1;
                args.get(i)
                    .context("--catalog requires a path")?
                    .clone_into(&mut catalog_path);
            }
            "--matrix" => {
                i += 1;
                args.get(i)
                    .context("--matrix requires a path")?
                    .clone_into(&mut matrix_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--help" | "-h" => {
                print_mounted_write_error_classes_usage();
                return Ok(());
            }
            other => bail!("unknown validate-mounted-write-error-classes argument: {other}"),
        }
        i += 1;
    }

    let text = fs::read_to_string(&catalog_path)
        .with_context(|| format!("failed to read mounted write error classes {catalog_path}"))?;
    let catalog = parse_mounted_write_error_classes(&text)?;
    let matrix = load_mounted_write_matrix(Path::new(&matrix_path))?;
    let matrix_report = validate_mounted_write_matrix(&matrix);
    fail_on_mounted_write_matrix_errors(&matrix_report)?;
    let report = validate_mounted_write_error_classes_with_matrix(&catalog, &matrix);
    fail_on_mounted_write_error_classes_errors(&report)?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{json}\n"))?;
        println!(
            "mounted write error classes report written: {} entries={} broad_fallbacks={}",
            path, report.entry_count, report.broad_fallback_count
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

fn validate_mounted_repair_mutation_boundary_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_mounted_repair_mutation_boundary_cmd_args(args)? else {
        return Ok(());
    };
    let matrix = load_mounted_repair_mutation_boundary(Path::new(&cmd_args.matrix_path))?;
    let report = validate_mounted_repair_mutation_boundary(&matrix);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_mounted_repair_mutation_boundary_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "mounted repair mutation boundary report written: {} valid={} scenarios={}",
            path, report.valid, report.scenario_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!(
                "{}\n",
                render_mounted_repair_mutation_boundary_markdown(&report)
            ),
        )?;
        println!("mounted repair mutation boundary summary written: {path}");
    }

    fail_on_mounted_repair_mutation_boundary_errors(&report)
}

fn parse_mounted_repair_mutation_boundary_cmd_args(
    args: &[String],
) -> Result<Option<MountedRepairMutationBoundaryCmdArgs>> {
    let mut matrix_path = DEFAULT_MOUNTED_REPAIR_MUTATION_BOUNDARY_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--matrix" => {
                i += 1;
                args.get(i)
                    .context("--matrix requires a path")?
                    .clone_into(&mut matrix_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_mounted_repair_mutation_boundary_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-mounted-repair-mutation-boundary argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(MountedRepairMutationBoundaryCmdArgs {
        matrix_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_chaos_replay_lab_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_chaos_replay_lab_cmd_args(args)? else {
        return Ok(());
    };
    let lab = load_chaos_replay_lab(Path::new(&cmd_args.lab_path))?;
    let report = validate_chaos_replay_lab(&lab);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_chaos_replay_lab_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "chaos replay lab report written: {} valid={} schedules={}",
            path, report.valid, report.schedule_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_chaos_replay_lab_markdown(&report)),
        )?;
        println!("chaos replay lab summary written: {path}");
    }

    fail_on_chaos_replay_lab_errors(&report)
}

fn parse_chaos_replay_lab_cmd_args(args: &[String]) -> Result<Option<ChaosReplayLabCmdArgs>> {
    let mut lab_path = DEFAULT_CHAOS_REPLAY_LAB_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--lab" => {
                i += 1;
                args.get(i)
                    .context("--lab requires a path")?
                    .clone_into(&mut lab_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_chaos_replay_lab_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-chaos-replay-lab argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(ChaosReplayLabCmdArgs {
        lab_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_inventory_closeout_gate_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_inventory_closeout_gate_cmd_args(args)? else {
        return Ok(());
    };
    let gate = load_inventory_closeout_gate(Path::new(&cmd_args.gate_path))?;
    let report = validate_inventory_closeout_gate(&gate);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_inventory_closeout_gate_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "inventory closeout gate report written: {} valid={} rows={}",
            path, report.valid, report.total_rows
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_inventory_closeout_gate_markdown(&report)),
        )?;
        println!("inventory closeout gate summary written: {path}");
    }

    fail_on_inventory_closeout_gate_errors(&report)
}

fn validate_report_schema_inventory_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_report_schema_inventory_cmd_args(args)? else {
        return Ok(());
    };
    let inventory = current_report_schema_inventory();
    let report = validate_report_schema_inventory(&inventory);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_report_schema_inventory_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "report schema inventory written: {} valid={} rows={} product_evidence_claim={}",
            path, report.valid, report.total_rows, report.product_evidence_claim
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_report_schema_inventory_markdown(&report)),
        )?;
        println!("report schema inventory summary written: {path}");
    }

    fail_on_report_schema_inventory_errors(&report)
}

fn parse_report_schema_inventory_cmd_args(
    args: &[String],
) -> Result<Option<ReportSchemaInventoryCmdArgs>> {
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_report_schema_inventory_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-report-schema-inventory argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(ReportSchemaInventoryCmdArgs {
        out_path,
        summary_out_path,
        format,
    }))
}

fn parse_inventory_closeout_gate_cmd_args(
    args: &[String],
) -> Result<Option<InventoryCloseoutGateCmdArgs>> {
    let mut gate_path = DEFAULT_INVENTORY_CLOSEOUT_GATE_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--gate" => {
                i += 1;
                args.get(i)
                    .context("--gate requires a path")?
                    .clone_into(&mut gate_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_inventory_closeout_gate_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-inventory-closeout-gate argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(InventoryCloseoutGateCmdArgs {
        gate_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_remediation_catalog_cmd(args: &[String]) -> Result<()> {
    let mut catalog_path = DEFAULT_REMEDIATION_CATALOG_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--catalog" => {
                i += 1;
                args.get(i)
                    .context("--catalog requires a path")?
                    .clone_into(&mut catalog_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_remediation_catalog_usage();
                return Ok(());
            }
            other => bail!("unknown validate-remediation-catalog argument: {other}"),
        }
        i += 1;
    }

    let text = fs::read_to_string(&catalog_path)
        .with_context(|| format!("failed to read remediation catalog {catalog_path}"))?;
    let catalog = parse_remediation_catalog(&text)?;
    let report = validate_remediation_catalog(&catalog);
    if !report.valid {
        bail!(
            "remediation catalog failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    let output = match format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_remediation_markdown(&catalog),
    };
    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "remediation catalog report written: {} entries={}",
            path, report.entry_count
        );
    } else {
        println!("{output}");
    }
    if let Some(path) = summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_remediation_markdown(&catalog)),
        )?;
        println!("remediation catalog summary written: {path}");
    }
    Ok(())
}

fn validate_remediation_severity_gate_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_remediation_severity_gate_cmd_args(args)? else {
        return Ok(());
    };
    let gate = load_remediation_severity_gate(Path::new(&cmd_args.gate_path))?;
    let report = validate_remediation_severity_gate(&gate);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_remediation_severity_gate_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "remediation severity gate report written: {} valid={} entries={}",
            path, report.valid, report.entry_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_remediation_severity_gate_markdown(&report)),
        )?;
        println!("remediation severity gate summary written: {path}");
    }

    fail_on_remediation_severity_gate_errors(&report)
}

fn parse_remediation_severity_gate_cmd_args(
    args: &[String],
) -> Result<Option<RemediationSeverityGateCmdArgs>> {
    let mut gate_path = DEFAULT_REMEDIATION_SEVERITY_GATE_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--gate" => {
                i += 1;
                args.get(i)
                    .context("--gate requires a path")?
                    .clone_into(&mut gate_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_remediation_severity_gate_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-remediation-severity-gate argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(RemediationSeverityGateCmdArgs {
        gate_path,
        out_path,
        summary_out_path,
        format,
    }))
}

fn validate_mounted_recovery_matrix_cmd(args: &[String]) -> Result<()> {
    let mut matrix_path = DEFAULT_RECOVERY_MATRIX_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--matrix" => {
                i += 1;
                args.get(i)
                    .context("--matrix requires a path")?
                    .clone_into(&mut matrix_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--help" | "-h" => {
                print_mounted_recovery_matrix_usage();
                return Ok(());
            }
            other => bail!("unknown validate-mounted-recovery-matrix argument: {other}"),
        }
        i += 1;
    }

    let matrix = load_mounted_recovery_matrix(Path::new(&matrix_path))?;
    let report = validate_mounted_recovery_matrix(&matrix);
    fail_on_mounted_recovery_matrix_errors(&report)?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        let path = Path::new(&path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "mounted recovery matrix report written: {} scenarios={}",
            path.display(),
            report.scenario_count
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

fn fuse_capability_probe_cmd(args: &[String]) -> Result<()> {
    let mut out_path: Option<String> = None;
    let mut options = FuseHostProbeOptions::default();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--user-disabled" => options.user_disabled = true,
            "--default-permissions-eacces" => options.default_permissions_eacces = true,
            "--require-mount-probe" => options.mount_probe_required = true,
            "--mount-probe-exit" => {
                i += 1;
                options.mount_probe_exit = Some(parse_i32_arg(args.get(i), "--mount-probe-exit")?);
            }
            "--unmount-probe-exit" => {
                i += 1;
                options.unmount_probe_exit =
                    Some(parse_i32_arg(args.get(i), "--unmount-probe-exit")?);
            }
            "--help" | "-h" => {
                print_fuse_capability_probe_usage();
                return Ok(());
            }
            other => bail!("unknown fuse-capability-probe argument: {other}"),
        }
        i += 1;
    }

    let report = probe_host_fuse_capability(options);
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        let path = Path::new(&path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "fuse capability report written: {} result={:?}",
            path.display(),
            report.result
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

fn parse_i32_arg(value: Option<&String>, flag: &str) -> Result<i32> {
    value
        .with_context(|| format!("{flag} requires an integer"))?
        .parse()
        .with_context(|| format!("invalid integer for {flag}"))
}

fn generate_fixture(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!(
            "usage: ffs-harness generate-fixture <image> [ext4-superblock|btrfs-superblock|region <offset> <len>]"
        );
    }

    let image_path = Path::new(args.first().context("generate-fixture requires <image>")?);
    let image_data =
        fs::read(image_path).with_context(|| format!("failed to read {}", image_path.display()))?;

    let kind = args.get(1).map_or("auto", String::as_str);

    let fixture = match kind {
        "ext4-superblock" => extract_ext4_superblock(&image_data)?,
        "btrfs-superblock" => extract_btrfs_superblock(&image_data)?,
        "region" => {
            let offset: usize = args
                .get(2)
                .context("region requires <offset>")?
                .parse()
                .context("invalid offset")?;
            let len: usize = args
                .get(3)
                .context("region requires <len>")?
                .parse()
                .context("invalid len")?;
            extract_region(&image_data, offset, len)?
        }
        "auto" => {
            // Try ext4 first, then btrfs.
            if let Ok(f) = extract_ext4_superblock(&image_data) {
                eprintln!("detected: ext4 superblock");
                f
            } else if let Ok(f) = extract_btrfs_superblock(&image_data) {
                eprintln!("detected: btrfs superblock");
                f
            } else {
                bail!("could not detect ext4 or btrfs superblock; use explicit mode");
            }
        }
        _ => bail!("unknown fixture kind: {kind}"),
    };

    println!("{}", serde_json::to_string_pretty(&fixture)?);
    Ok(())
}

fn run_crash_replay(args: &[String]) -> Result<()> {
    let mut config = CrashReplaySuiteConfig::default();
    let mut index = 0_usize;
    while index < args.len() {
        match args[index].as_str() {
            "--count" => {
                let raw = args.get(index + 1).context("--count requires a value")?;
                config.schedule_count = raw.parse().context("invalid --count value")?;
                index += 2;
            }
            "--seed" => {
                let raw = args.get(index + 1).context("--seed requires a value")?;
                config.base_seed = raw.parse().context("invalid --seed value")?;
                index += 2;
            }
            "--min-ops" => {
                let raw = args.get(index + 1).context("--min-ops requires a value")?;
                config.min_operations = raw.parse().context("invalid --min-ops value")?;
                index += 2;
            }
            "--max-ops" => {
                let raw = args.get(index + 1).context("--max-ops requires a value")?;
                config.max_operations = raw.parse().context("invalid --max-ops value")?;
                index += 2;
            }
            "--out" => {
                let raw = args.get(index + 1).context("--out requires a value")?;
                config.output_dir = Some(Path::new(raw).to_path_buf());
                index += 2;
            }
            other => {
                bail!("unknown run-crash-replay option: {other}");
            }
        }
    }

    let report = run_crash_replay_suite(&config)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.failed_schedules > 0 {
        bail!(
            "crash replay suite reported {} failing schedule(s)",
            report.failed_schedules
        );
    }
    Ok(())
}

fn run_fsx_stress_cmd(args: &[String]) -> Result<()> {
    let mut config = FsxStressConfig::default();
    let mut index = 0_usize;
    while index < args.len() {
        match args[index].as_str() {
            "--ops" => {
                let raw = args.get(index + 1).context("--ops requires a value")?;
                config.operation_count = raw.parse().context("invalid --ops value")?;
                index += 2;
            }
            "--seed" => {
                let raw = args.get(index + 1).context("--seed requires a value")?;
                config.seed = raw.parse().context("invalid --seed value")?;
                index += 2;
            }
            "--max-file-bytes" => {
                let raw = args
                    .get(index + 1)
                    .context("--max-file-bytes requires a value")?;
                config.max_file_size_bytes =
                    raw.parse().context("invalid --max-file-bytes value")?;
                index += 2;
            }
            "--corrupt-every" => {
                let raw = args
                    .get(index + 1)
                    .context("--corrupt-every requires a value")?;
                config.corruption_every_ops =
                    raw.parse().context("invalid --corrupt-every value")?;
                index += 2;
            }
            "--verify-every" => {
                let raw = args
                    .get(index + 1)
                    .context("--verify-every requires a value")?;
                config.full_verify_every_ops =
                    raw.parse().context("invalid --verify-every value")?;
                index += 2;
            }
            "--out" => {
                let raw = args.get(index + 1).context("--out requires a value")?;
                config.output_dir = Some(Path::new(raw).to_path_buf());
                index += 2;
            }
            other => {
                bail!("unknown run-fsx-stress option: {other}");
            }
        }
    }

    let report = run_fsx_stress(&config)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.passed {
        bail!("fsx stress reported a mismatch");
    }
    Ok(())
}

fn print_usage() {
    println!("ffs-harness — fixture management and parity reporting");
    println!();
    println!("USAGE:");
    print_usage_commands();
    println!();
    println!("FIXTURE GENERATION:");
    println!("  Extracts sparse JSON fixtures from real filesystem images.");
    println!("  In 'auto' mode (default), detects ext4/btrfs and extracts the superblock.");
    println!("  Use 'region' mode to extract arbitrary byte ranges for group descriptors,");
    println!("  inodes, directory blocks, or any other metadata structure.");
    println!();
    println!("CRASH REPLAY:");
    println!("  Runs deterministic crash/replay schedules and emits a JSON summary.");
    println!("  Use --out DIR to persist schedule artifacts + repro pack.");
    println!();
    println!("FSX STRESS:");
    println!(
        "  Runs weighted fsx-style read/write/truncate/fsync/fallocate/punch-hole/reopen operations."
    );
    println!(
        "  Periodically injects corruption and verifies deterministic repair + full-file integrity."
    );
    println!();
    println!("EXAMPLES:");
    print_usage_examples();
}

#[allow(clippy::too_many_lines)]
fn print_usage_core_commands() {
    println!("  ffs-harness parity");
    println!("  ffs-harness gates [--gate ID|all] [--local] [--out FILE]");
    println!("  ffs-harness check-fixtures");
    println!(
        "  ffs-harness profile-read-path --fixture PATH --duration-sec N [--mode cli-inspect|direct-read|fuse-read]"
    );
    println!(
        "  ffs-harness generate-fixture <image> [ext4-superblock|btrfs-superblock|region <offset> <len>]"
    );
    println!(
        "  ffs-harness run-crash-replay [--count N] [--seed S] [--min-ops N] [--max-ops N] [--out DIR]"
    );
    println!(
        "  ffs-harness run-fsx-stress [--ops N] [--seed S] [--max-file-bytes N] [--corrupt-every N] [--verify-every N] [--out DIR]"
    );
    println!(
        "  ffs-harness xfstests-report --selected FILE --results-json FILE --junit-xml FILE [--check-log FILE --check-rc N --dry-run 0|1] [--allowlist-json FILE] [--baseline-json FILE] [--uniform-status STATUS --uniform-note NOTE]"
    );
    println!(
        "  ffs-harness xfstests-baseline-manifest --selected FILE --results-json FILE --manifest-out FILE --summary-out FILE --baseline-id ID --subset-version VERSION --environment-manifest-id ID --command-transcript CMD --checkpoint-id ID --resume-command CMD --cleanup-status STATUS --reproduction-command CMD --raw-artifact FILE [--raw-artifact FILE ...]"
    );
    println!(
        "  ffs-harness xfstests-failure-triage --baseline-manifest FILE --triage-out FILE --summary-out FILE --triage-id ID --reproduction-command CMD"
    );
    println!(
        "  ffs-harness record-environment-manifest --out FILE [--authoritative] [--bead-id ID] [--lane-id ID]"
    );
    println!("  ffs-harness validate-operational-manifest <manifest.json>");
    println!(
        "  ffs-harness validate-artifact-schema-fixtures [--fixtures DIR] [--out FILE] [--summary-out FILE] [--reproduction-command CMD]"
    );
    println!(
        "  ffs-harness operational-readiness-report [--artifacts DIR] [--current-git-sha SHA] [--max-age-days N] [--format json|markdown] [--out FILE]"
    );
    println!(
        "  ffs-harness operational-evidence-index [--artifacts DIR] [--current-git-sha SHA] [--max-age-days N] [--format json|markdown] [--out FILE]"
    );
    println!(
        "  ffs-harness recommend-readiness-actions [--input FILE] --out-json FILE --out-md FILE --stdout-log FILE --stderr-log FILE [--report-id ID] [--generated-at TS] [--invocation CMD]"
    );
    println!(
        "  ffs-harness readiness-dashboard [--proof-bundle-report FILE ...] [--release-gate-report FILE ...] [--operational-evidence-index FILE ...] [--permissioned-campaign-report FILE ...] [--readiness-lab-report FILE ...] [--beads FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness validate-readiness-lab-contracts --manifest FILE [--reference-epoch-days N] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness simulate-readiness-lab-hosts --manifest FILE [--reference-epoch-days N] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness plan-readiness-lab-rch-lanes --manifest FILE [--reference-epoch-days N] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness build-readiness-lab-truth-graph --manifest FILE [--reference-epoch-days N] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness validate-readiness-lab-numa-p99-replay [--manifest FILE] [--reference-epoch-days N] [--format json|markdown] [--out FILE] [--summary-out FILE] [--select FIXTURE_ID]"
    );
    println!(
        "  ffs-harness fuse-capability-probe [--out FILE] [--require-mount-probe] [--mount-probe-exit N] [--unmount-probe-exit N] [--user-disabled] [--default-permissions-eacces]"
    );
    println!("  ffs-harness validate-open-ended-inventory [--out FILE]");
    println!(
        "  ffs-harness open-ended-note-scanner --source FILE [--source FILE ...] [--out FILE] [--allow-invalid] [--reproduction-command CMD]"
    );
    println!(
        "  ffs-harness validate-source-scope-manifest [--manifest FILE] [--workspace-root DIR] [--out FILE]"
    );
    println!(
        "  ffs-harness validate-deferred-parity-audit [--issues FILE] [--report FILE] [--doc FILE] [--out FILE]"
    );
    println!("  ffs-harness validate-ambition-evidence-matrix [--issues FILE] [--out FILE]");
    println!(
        "  ffs-harness validate-support-state-accounting [--issues FILE] [--feature-parity FILE] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness validate-docs-status-drift [--issues FILE] [--feature-parity FILE] [--snippets FILE] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness validate-tracker-source-hygiene [--issues FILE] [--strict] [--out FILE]"
    );
    println!(
        "  ffs-harness claimability-plan --tracker-report FILE [--reservation-report FILE] [--bv-report FILE] [--rch-capacity-preflight-report FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness validate-report-schema-inventory [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness validate-fuzz-smoke [--manifest FILE] [--workspace-root DIR] [--out FILE]"
    );
    println!(
        "  ffs-harness validate-proof-overhead-budget --budget FILE --metrics FILE [--out FILE]"
    );
    println!(
        "  ffs-harness adaptive-runtime-runner [--mode dry-run|capability-probe|permissioned-real] [--artifact-root DIR] [--out FILE] [--summary-out FILE] [--test-dir DIR] [--scratch-mnt DIR]"
    );
    println!(
        "  ffs-harness validate-adaptive-runtime-manifest [--manifest FILE] [--current-git-sha SHA] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness validate-topology-runtime-advisor --manifest FILE [--format json|markdown] [--out FILE] [--summary-out FILE] [--structured-log-out FILE]"
    );
    println!(
        "  ffs-harness score-topology-runtime-advisor --manifest FILE [--format json|markdown] [--out FILE] [--summary-out FILE] [--structured-log-out FILE]"
    );
    println!(
        "  ffs-harness validate-permissioned-campaign-broker [--manifest FILE] [--format json|markdown] [--out FILE] [--summary-out FILE] [--reference-timestamp TS]"
    );
    println!(
        "  ffs-harness validate-permissioned-campaign-ledger --manifest FILE --ledger FILE [--current-git-sha SHA] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness generate-permissioned-campaign-packet [--manifest FILE] [--format json|markdown] [--out FILE] [--summary-out FILE] [--generated-at TS] [--generated-by NAME] [--git-sha SHA]"
    );
    println!(
        "  ffs-harness validate-swarm-capability-calibration --manifest FILE [--format json|markdown] [--out FILE] [--summary-out FILE] [--reference-timestamp TS]"
    );
    println!(
        "  ffs-harness validate-proof-bundle --bundle FILE [--current-git-sha SHA] [--max-age-days N] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness validate-invariant-oracle --trace FILE|--report FILE [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness validate-mounted-differential-oracle [--report FILE] [--format json|markdown] [--out FILE]"
    );
    println!(
        "  ffs-harness validate-mounted-repair-mutation-boundary [--matrix FILE] [--out FILE]"
    );
    println!(
        "  ffs-harness validate-cross-oracle-arbitration [--report FILE] [--format json|markdown] [--out FILE]"
    );
    println!(
        "  ffs-harness evaluate-release-gates --bundle FILE --policy FILE [--current-git-sha SHA] [--max-age-days N] [--format json|markdown] [--out FILE] [--wording-out FILE]"
    );
}

fn print_usage_commands() {
    print_usage_core_commands();
    print_performance_baseline_manifest_usage_summary();
    print_performance_delta_closeout_usage_summary();
    print_swarm_cache_controller_usage_summary();
    print_swarm_operator_report_usage_summary();
    print_swarm_tail_latency_usage_summary();
    print_swarm_workload_harness_usage_summary();
    print_wal_group_commit_gate_usage_summary();
    print_scrub_repair_scheduler_usage_summary();
    print_adversarial_threat_model_usage_summary();
    print_soak_canary_campaign_usage_summary();
    print_repair_confidence_lab_usage_summary();
    print_operator_recovery_drill_usage_summary();
    print_repair_writeback_serialization_usage_summary();
    print_chaos_replay_lab_usage_summary();
    print_inventory_closeout_gate_usage_summary();
    print_report_schema_inventory_usage_summary();
    println!(
        "  ffs-harness rch-proof-ledger --transcript FILE [--command-arg ARG ...] [--cwd DIR] [--env NAME ...] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness validate-rch-capacity-preflight --report FILE [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness validate-runtime-console --report FILE [--format json|markdown] [--out FILE] [--summary-out FILE] [--reference-timestamp RFC3339] [--max-age-days N]"
    );
    println!(
        "  ffs-harness validate-numa-allocation-placement --report FILE [--format json|markdown] [--out FILE] [--summary-out FILE] [--reference-unix-secs N]"
    );
    println!(
        "  ffs-harness validate-remediation-catalog [--catalog FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    print_remediation_severity_gate_usage_summary();
    print_writeback_cache_audit_usage_summary();
    print_writeback_cache_ordering_usage_summary();
    print_writeback_cache_crash_replay_usage_summary();
    print_workload_corpus_usage_summary();
    print_btrfs_send_receive_corpus_usage_summary();
    print_btrfs_multidevice_corpus_usage_summary();
    print_casefold_corpus_usage_summary();
    print_fault_injection_corpus_usage_summary();
    print_repair_corpus_usage_summary();
    print_mounted_checkpoint_survivor_usage_summary();
    print_low_privilege_demo_usage_summary();
    print_low_privilege_demo_sandbox_usage_summary();
    print_metamorphic_workload_seed_catalog_usage_summary();
    println!(
        "  ffs-harness validate-mounted-write-error-classes [--catalog FILE] [--matrix FILE] [--out FILE]"
    );
    println!("  ffs-harness validate-mounted-write-matrix [--matrix FILE] [--out FILE]");
    println!("  ffs-harness validate-mounted-recovery-matrix [--matrix FILE] [--out FILE]");
}

#[allow(clippy::too_many_lines)]
fn print_usage_examples() {
    println!("  ffs-harness generate-fixture my_ext4.img > conformance/fixtures/my_ext4.json");
    println!(
        "  ffs-harness generate-fixture my_ext4.img region 2048 32 > conformance/fixtures/gd.json"
    );
    println!("  ffs-harness run-crash-replay --count 500 --out artifacts/crash_replay");
    println!("  ffs-harness run-fsx-stress --ops 100000 --seed 123 --out artifacts/fsx");
    println!(
        "  ffs-harness validate-operational-manifest artifacts/e2e/run/operational_manifest.json"
    );
    println!(
        "  ffs-harness validate-artifact-schema-fixtures --out artifacts/artifact-schema-fixtures/report.json --summary-out artifacts/artifact-schema-fixtures/report.md"
    );
    println!(
        "  ffs-harness operational-readiness-report --artifacts artifacts/e2e --current-git-sha $(git rev-parse --short HEAD) --max-age-days 14 --format markdown --out artifacts/e2e/readiness.md"
    );
    println!(
        "  ffs-harness operational-evidence-index --artifacts artifacts/e2e --current-git-sha $(git rev-parse --short HEAD) --max-age-days 14 --format markdown --out artifacts/e2e/evidence-index.md"
    );
    println!(
        "  ffs-harness recommend-readiness-actions --out-json artifacts/readiness/actions/report.json --out-md artifacts/readiness/actions/report.md --stdout-log artifacts/readiness/actions/stdout.log --stderr-log artifacts/readiness/actions/stderr.log"
    );
    println!(
        "  ffs-harness readiness-dashboard --proof-bundle-report artifacts/proof/report.json --release-gate-report artifacts/proof/release_gate.json --operational-evidence-index artifacts/e2e/evidence-index.json --readiness-lab-report artifacts/readiness-lab/truth-graph.json --beads .beads/issues.jsonl --format markdown"
    );
    println!(
        "  ffs-harness validate-readiness-lab-contracts --manifest artifacts/readiness-lab/contracts.json --reference-epoch-days 20001 --format markdown"
    );
    println!(
        "  ffs-harness simulate-readiness-lab-hosts --manifest artifacts/readiness-lab/host_matrix.json --reference-epoch-days 20001 --format markdown"
    );
    println!(
        "  ffs-harness plan-readiness-lab-rch-lanes --manifest artifacts/readiness-lab/rch_lanes.json --reference-epoch-days 20001 --format markdown"
    );
    println!(
        "  ffs-harness build-readiness-lab-truth-graph --manifest artifacts/readiness-lab/truth_graph.json --reference-epoch-days 20001 --format markdown"
    );
    println!(
        "  ffs-harness validate-readiness-lab-numa-p99-replay --manifest tests/readiness-lab/numa_p99_replay_fixtures.json --reference-epoch-days 20001 --format markdown"
    );
    println!("  ffs-harness fuse-capability-probe --out artifacts/e2e/run/fuse_capability.json");
    println!(
        "  ffs-harness validate-open-ended-inventory --out artifacts/conformance/open_ended_inventory.json"
    );
    println!(
        "  ffs-harness open-ended-note-scanner --source tests/open-ended-inventory/scanner_fixture_positive.md --out artifacts/conformance/open_ended_note_scan.json"
    );
    println!(
        "  ffs-harness validate-source-scope-manifest --out artifacts/conformance/source_scope_manifest.json"
    );
    println!(
        "  ffs-harness validate-deferred-parity-audit --out artifacts/parity/deferred_parity_audit.json"
    );
    println!(
        "  ffs-harness validate-ambition-evidence-matrix --out artifacts/ambition/evidence_matrix.json"
    );
    println!(
        "  ffs-harness validate-support-state-accounting --out artifacts/parity/support_state_accounting.json --summary-out artifacts/parity/support_state_accounting.md"
    );
    println!(
        "  ffs-harness validate-docs-status-drift --out artifacts/docs-status/docs_status_drift.json --summary-out artifacts/docs-status/docs_status_drift.md"
    );
    println!(
        "  ffs-harness validate-tracker-source-hygiene --issues .beads/issues.jsonl --out artifacts/tracker/source_hygiene.json"
    );
    println!(
        "  ffs-harness validate-report-schema-inventory --out artifacts/report-schema-inventory/report.json --summary-out artifacts/report-schema-inventory/report.md"
    );
    println!("  ffs-harness validate-fuzz-smoke --out artifacts/fuzz-smoke/fuzz_smoke_report.json");
    println!(
        "  ffs-harness validate-proof-overhead-budget --budget artifacts/proof/budget.json --metrics artifacts/proof/metrics.json --out artifacts/proof/budget_report.json"
    );
    println!(
        "  ffs-harness adaptive-runtime-runner --artifact-root artifacts/adaptive-runtime/dry-run --out artifacts/adaptive-runtime/dry-run/report.json --summary-out artifacts/adaptive-runtime/dry-run/report.md"
    );
    println!("  ffs-harness record-environment-manifest --out artifacts/env-manifest.json");
    println!(
        "  ffs-harness validate-adaptive-runtime-manifest --manifest docs/adaptive-runtime-evidence-manifest.json --out artifacts/adaptive-runtime/report.json --summary-out artifacts/adaptive-runtime/report.md"
    );
    println!(
        "  ffs-harness score-topology-runtime-advisor --manifest docs/topology-runtime-advisor-manifest.json --out artifacts/topology-advisor/score.json --summary-out artifacts/topology-advisor/score.md --structured-log-out artifacts/topology-advisor/score.jsonl"
    );
    print_permissioned_campaign_broker_example();
    print_permissioned_campaign_packet_example();
    println!(
        "  ffs-harness validate-proof-bundle --bundle artifacts/proof/bundle/manifest.json --out artifacts/proof/bundle/report.json --summary-out artifacts/proof/bundle/summary.md"
    );
    println!(
        "  ffs-harness validate-invariant-oracle --trace artifacts/invariant/trace.json --out artifacts/invariant/oracle_report.json --summary-out artifacts/invariant/oracle_report.md"
    );
    println!(
        "  ffs-harness validate-mounted-differential-oracle --report artifacts/e2e/mounted_differential_oracle/report.json --out artifacts/e2e/mounted_differential_oracle/validation.json"
    );
    println!(
        "  ffs-harness validate-mounted-repair-mutation-boundary --out artifacts/e2e/mounted_repair_mutation_boundary.json"
    );
    println!(
        "  ffs-harness validate-cross-oracle-arbitration --report artifacts/e2e/cross_oracle_arbitration/report.json --out artifacts/e2e/cross_oracle_arbitration/validation.json"
    );
    println!(
        "  ffs-harness evaluate-release-gates --bundle artifacts/proof/bundle/manifest.json --policy artifacts/proof/release_gate_policy.json --out artifacts/proof/release_gate.json --wording-out artifacts/proof/release_gate_wording.tsv"
    );
    print_performance_baseline_manifest_example();
    print_performance_delta_closeout_example();
    print_swarm_cache_controller_example();
    print_swarm_operator_report_example();
    print_swarm_tail_latency_example();
    print_swarm_workload_harness_example();
    print_wal_group_commit_gate_example();
    print_scrub_repair_scheduler_example();
    print_adversarial_threat_model_example();
    print_soak_canary_campaign_example();
    print_repair_confidence_lab_example();
    print_operator_recovery_drill_example();
    print_repair_writeback_serialization_example();
    print_chaos_replay_lab_example();
    println!(
        "  ffs-harness validate-remediation-catalog --out artifacts/remediation/catalog_report.json --summary-out artifacts/remediation/catalog_summary.md"
    );
    print_inventory_closeout_gate_example();
    print_remediation_severity_gate_example();
    print_writeback_cache_audit_example();
    print_writeback_cache_ordering_example();
    print_writeback_cache_crash_replay_example();
    print_workload_corpus_example();
    print_btrfs_send_receive_corpus_example();
    print_btrfs_multidevice_corpus_example();
    print_casefold_corpus_example();
    print_fault_injection_corpus_example();
    print_repair_corpus_example();
    print_mounted_checkpoint_survivor_example();
    print_low_privilege_demo_example();
    print_low_privilege_demo_sandbox_example();
    print_metamorphic_workload_seed_catalog_example();
    println!(
        "  ffs-harness validate-mounted-write-error-classes --out artifacts/e2e/mounted_write_error_classes.json"
    );
    println!(
        "  ffs-harness validate-mounted-write-matrix --out artifacts/e2e/mounted_write_matrix.json"
    );
    println!(
        "  ffs-harness validate-mounted-recovery-matrix --out artifacts/e2e/mounted_recovery_matrix.json"
    );
}

fn print_permissioned_campaign_broker_example() {
    println!(
        "  ffs-harness validate-permissioned-campaign-broker --manifest artifacts/permissioned/broker.json --out artifacts/permissioned/broker_report.json --summary-out artifacts/permissioned/broker_report.md"
    );
    print_permissioned_campaign_ledger_example();
}

fn print_permissioned_campaign_ledger_example() {
    println!(
        "  ffs-harness validate-permissioned-campaign-ledger --manifest artifacts/permissioned/broker.json --ledger artifacts/permissioned/execution_ledger.json --current-git-sha $(git rev-parse HEAD) --out artifacts/permissioned/ledger_report.json --summary-out artifacts/permissioned/ledger_report.md"
    );
}

fn print_permissioned_campaign_packet_example() {
    println!(
        "  ffs-harness generate-permissioned-campaign-packet --manifest artifacts/permissioned/broker.json --out artifacts/permissioned/handoff_packet.json --summary-out artifacts/permissioned/handoff_packet.md"
    );
    println!(
        "  ffs-harness validate-swarm-capability-calibration --manifest artifacts/swarm/calibration/candidate.json --out artifacts/swarm/calibration/candidate_report.json --summary-out artifacts/swarm/calibration/candidate_report.md"
    );
}

fn print_artifact_schema_fixtures_usage() {
    println!("USAGE:");
    println!(
        "  ffs-harness validate-artifact-schema-fixtures [--fixtures DIR] [--out FILE] [--summary-out FILE] [--reproduction-command CMD]"
    );
    println!();
    println!("Validates every *.fixture.json case under the fixture directory.");
    println!("Accept fixtures must produce zero diagnostics; reject fixtures must");
    println!("produce exactly the listed code/path diagnostics.");
}

fn print_fuzz_smoke_usage() {
    println!(
        "ffs-harness validate-fuzz-smoke [--manifest FILE] [--workspace-root DIR] [--out FILE]"
    );
    println!();
    println!(
        "Validates fixed fuzz-smoke seeds against parser error classes, panic classification, timeout budgets, and artifact contract fields."
    );
}

fn print_performance_baseline_manifest_usage_summary() {
    println!(
        "  ffs-harness validate-performance-baseline-manifest (--manifest FILE | --manifest-json-env VAR) [--artifact-root DIR] [--out FILE] [--artifact-out FILE]"
    );
}

fn print_performance_baseline_manifest_example() {
    println!(
        "  ffs-harness validate-performance-baseline-manifest --manifest benchmarks/performance_baseline_manifest.json --out artifacts/performance/manifest_report.json --artifact-out artifacts/performance/sample_artifact_manifest.json"
    );
}

fn print_performance_delta_closeout_usage_summary() {
    println!(
        "  ffs-harness performance-delta-closeout [--config FILE] [--issues FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_performance_delta_closeout_example() {
    println!(
        "  ffs-harness performance-delta-closeout --config benchmarks/performance_delta_closeout.json --out artifacts/performance/delta_closeout.json --summary-out artifacts/performance/delta_closeout.md"
    );
}

fn print_swarm_cache_controller_usage_summary() {
    println!(
        "  ffs-harness validate-swarm-cache-controller [--contract FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_swarm_cache_controller_example() {
    println!(
        "  ffs-harness validate-swarm-cache-controller --contract benchmarks/swarm_cache_controller_contract.json --out artifacts/performance/swarm_cache_controller.json --summary-out artifacts/performance/swarm_cache_controller.md"
    );
}

fn print_swarm_operator_report_usage_summary() {
    println!(
        "  ffs-harness validate-swarm-operator-report [--report FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_swarm_operator_report_example() {
    println!(
        "  ffs-harness validate-swarm-operator-report --report benchmarks/swarm_operator_report.json --out artifacts/performance/swarm_operator_report.json --summary-out artifacts/performance/swarm_operator_report.md"
    );
}

fn print_swarm_tail_latency_usage_summary() {
    println!(
        "  ffs-harness validate-swarm-tail-latency [--ledger FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_swarm_tail_latency_example() {
    println!(
        "  ffs-harness validate-swarm-tail-latency --ledger benchmarks/swarm_tail_latency_ledger.json --out artifacts/performance/swarm_tail_latency.json --summary-out artifacts/performance/swarm_tail_latency.md"
    );
}

fn print_swarm_workload_harness_usage_summary() {
    println!(
        "  ffs-harness validate-swarm-workload-harness [--manifest FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_swarm_workload_harness_example() {
    println!(
        "  ffs-harness validate-swarm-workload-harness --manifest benchmarks/swarm_workload_harness_manifest.json --out artifacts/performance/swarm_workload_harness.json --summary-out artifacts/performance/swarm_workload_harness.md"
    );
}

fn print_wal_group_commit_gate_usage_summary() {
    println!(
        "  ffs-harness validate-wal-group-commit-gate [--manifest FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_wal_group_commit_gate_example() {
    println!(
        "  ffs-harness validate-wal-group-commit-gate --manifest benchmarks/wal_group_commit_gate_manifest.json --out artifacts/performance/wal_group_commit_gate.json --summary-out artifacts/performance/wal_group_commit_gate.md"
    );
}

fn print_scrub_repair_scheduler_usage_summary() {
    println!(
        "  ffs-harness validate-scrub-repair-scheduler [--manifest FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_scrub_repair_scheduler_example() {
    println!(
        "  ffs-harness validate-scrub-repair-scheduler --manifest benchmarks/scrub_repair_scheduler_manifest.json --out artifacts/performance/scrub_repair_scheduler.json --summary-out artifacts/performance/scrub_repair_scheduler.md"
    );
}

fn print_adversarial_threat_model_usage_summary() {
    println!(
        "  ffs-harness validate-adversarial-threat-model (--model FILE | --model-json-env VAR) [--artifact-root DIR] [--out FILE] [--artifact-out FILE] [--wording-out FILE]"
    );
}

fn print_adversarial_threat_model_example() {
    println!(
        "  ffs-harness validate-adversarial-threat-model --model security/adversarial_image_threat_model.json --out artifacts/security/threat_model_report.json --artifact-out artifacts/security/sample_artifact_manifest.json --wording-out artifacts/security/security_wording.tsv"
    );
}

fn print_soak_canary_campaign_usage_summary() {
    println!(
        "  ffs-harness validate-soak-canary-campaigns --manifest FILE [--artifact-root DIR] [--out FILE] [--artifact-out FILE] [--summary-out FILE]"
    );
}

fn print_soak_canary_campaign_example() {
    println!(
        "  ffs-harness validate-soak-canary-campaigns --manifest benchmarks/soak_canary_campaign_manifest.json --out artifacts/soak/campaign_report.json --artifact-out artifacts/soak/sample_artifact_manifest.json --summary-out artifacts/soak/campaign_summary.md"
    );
}

fn print_repair_confidence_lab_usage_summary() {
    println!(
        "  ffs-harness validate-repair-confidence-lab [--spec FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_repair_confidence_lab_example() {
    println!(
        "  ffs-harness validate-repair-confidence-lab --spec docs/repair-confidence-mutation-safety.json --out artifacts/repair-confidence/lab_report.json --summary-out artifacts/repair-confidence/lab_summary.md"
    );
}

fn print_operator_recovery_drill_usage_summary() {
    println!(
        "  ffs-harness validate-operator-recovery-drill [--spec FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_operator_recovery_drill_example() {
    println!(
        "  ffs-harness validate-operator-recovery-drill --spec docs/operator-recovery-drill.json --out artifacts/operator-recovery/drill_report.json --summary-out artifacts/operator-recovery/drill_summary.md"
    );
}

fn print_repair_writeback_serialization_usage_summary() {
    println!(
        "  ffs-harness validate-repair-writeback-serialization (--contract FILE | --contract-json-env VAR) [--artifact-root DIR] [--out FILE] [--artifact-out FILE] [--summary-out FILE]"
    );
}

fn print_repair_writeback_serialization_example() {
    println!(
        "  ffs-harness validate-repair-writeback-serialization --contract docs/repair-writeback-serialization-contract.json --out artifacts/repair-writeback/contract_report.json --artifact-out artifacts/repair-writeback/sample_artifact_manifest.json --summary-out artifacts/repair-writeback/contract_summary.md"
    );
}

fn print_chaos_replay_lab_usage_summary() {
    println!(
        "  ffs-harness validate-chaos-replay-lab [--lab FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_chaos_replay_lab_example() {
    println!(
        "  ffs-harness validate-chaos-replay-lab --lab tests/chaos-replay-lab/chaos_replay_lab.json --out artifacts/chaos-replay/lab_report.json --summary-out artifacts/chaos-replay/lab_summary.md"
    );
}

fn print_writeback_cache_audit_usage_summary() {
    println!(
        "  ffs-harness validate-writeback-cache-audit --gate FILE [--scenario-id ID] [--require-accept] [--out FILE] [--summary-out FILE]"
    );
}

fn print_writeback_cache_audit_example() {
    println!(
        "  ffs-harness validate-writeback-cache-audit --gate artifacts/writeback-cache/gate.json --scenario-id writeback_cache_audit_accepts_complete_gate --require-accept --out artifacts/writeback-cache/report.json --summary-out artifacts/writeback-cache/summary.md"
    );
}

fn print_writeback_cache_ordering_usage_summary() {
    println!(
        "  ffs-harness validate-writeback-cache-ordering --oracle FILE [--scenario-id ID] [--require-accept] [--out FILE] [--summary-out FILE]"
    );
}

fn print_writeback_cache_ordering_example() {
    println!(
        "  ffs-harness validate-writeback-cache-ordering --oracle artifacts/writeback-cache/ordering_oracle.json --scenario-id writeback_cache_ordering_accepts_complete_oracle --require-accept --out artifacts/writeback-cache/ordering_report.json --summary-out artifacts/writeback-cache/ordering_summary.md"
    );
}

fn print_writeback_cache_crash_replay_usage_summary() {
    println!(
        "  ffs-harness validate-writeback-cache-crash-replay --oracle FILE [--scenario-id ID] [--require-accept] [--out FILE] [--summary-out FILE]"
    );
}

fn print_writeback_cache_crash_replay_example() {
    println!(
        "  ffs-harness validate-writeback-cache-crash-replay --oracle artifacts/writeback-cache/crash_replay_oracle.json --scenario-id writeback_cache_crash_replay_accepts_complete_matrix --require-accept --out artifacts/writeback-cache/crash_replay_report.json --summary-out artifacts/writeback-cache/crash_replay_summary.md"
    );
}

fn print_workload_corpus_usage_summary() {
    println!(
        "  ffs-harness validate-workload-corpus [--corpus FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_workload_corpus_example() {
    println!(
        "  ffs-harness validate-workload-corpus --corpus tests/workload-corpus/p1_workload_corpus.json --out artifacts/workload_corpus/report.json --summary-out artifacts/workload_corpus/summary.md"
    );
}

fn print_btrfs_send_receive_corpus_usage_summary() {
    println!(
        "  ffs-harness validate-btrfs-send-receive-corpus [--corpus FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_btrfs_send_receive_corpus_example() {
    println!(
        "  ffs-harness validate-btrfs-send-receive-corpus --corpus tests/btrfs-send-receive-corpus/btrfs_send_receive_corpus.json --out artifacts/btrfs-send-receive/report.json --summary-out artifacts/btrfs-send-receive/summary.md"
    );
}

fn print_btrfs_multidevice_corpus_usage_summary() {
    println!(
        "  ffs-harness validate-btrfs-multidevice-corpus [--corpus FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_btrfs_multidevice_corpus_example() {
    println!(
        "  ffs-harness validate-btrfs-multidevice-corpus --corpus tests/btrfs-multidevice-corpus/btrfs_multidevice_corpus.json --out artifacts/btrfs-multidevice/report.json --summary-out artifacts/btrfs-multidevice/summary.md"
    );
}

fn print_casefold_corpus_usage_summary() {
    println!(
        "  ffs-harness validate-casefold-corpus [--corpus FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_casefold_corpus_example() {
    println!(
        "  ffs-harness validate-casefold-corpus --corpus tests/casefold-corpus/casefold_corpus.json --out artifacts/casefold/report.json --summary-out artifacts/casefold/summary.md"
    );
}

fn print_fault_injection_corpus_usage_summary() {
    println!(
        "  ffs-harness validate-fault-injection-corpus [--corpus FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_fault_injection_corpus_example() {
    println!(
        "  ffs-harness validate-fault-injection-corpus --corpus tests/fault-injection-corpus/fault_injection_corpus.json --out artifacts/fault-injection/report.json --summary-out artifacts/fault-injection/summary.md"
    );
}

fn print_repair_corpus_usage_summary() {
    println!(
        "  ffs-harness validate-repair-corpus [--corpus FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_repair_corpus_example() {
    println!(
        "  ffs-harness validate-repair-corpus --corpus tests/repair-corpus/repair_corpus.json --out artifacts/repair-corpus/report.json --summary-out artifacts/repair-corpus/summary.md"
    );
}

fn print_mounted_checkpoint_survivor_usage_summary() {
    println!(
        "  ffs-harness validate-mounted-checkpoint-survivor [--matrix FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_mounted_checkpoint_survivor_example() {
    println!(
        "  ffs-harness validate-mounted-checkpoint-survivor --matrix tests/mounted-checkpoint-survivor/mounted_checkpoint_survivor.json --out artifacts/mounted-checkpoint-survivor/report.json --summary-out artifacts/mounted-checkpoint-survivor/summary.md"
    );
}

fn print_low_privilege_demo_usage_summary() {
    println!(
        "  ffs-harness validate-low-privilege-demo [--manifest FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_low_privilege_demo_example() {
    println!(
        "  ffs-harness validate-low-privilege-demo --manifest tests/low-privilege-demo/low_privilege_demo_manifest.json --out artifacts/low-privilege-demo/report.json --summary-out artifacts/low-privilege-demo/summary.md"
    );
}

fn print_low_privilege_demo_sandbox_usage_summary() {
    println!(
        "  ffs-harness validate-low-privilege-demo-sandbox [--manifest FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_low_privilege_demo_sandbox_example() {
    println!(
        "  ffs-harness validate-low-privilege-demo-sandbox --manifest tests/low-privilege-demo-sandbox/low_privilege_demo_sandbox.json --out artifacts/low-privilege-demo-sandbox/report.json --summary-out artifacts/low-privilege-demo-sandbox/summary.md"
    );
}

fn print_metamorphic_workload_seed_catalog_usage_summary() {
    println!(
        "  ffs-harness validate-metamorphic-workload-seeds [--catalog FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_metamorphic_workload_seed_catalog_example() {
    println!(
        "  ffs-harness validate-metamorphic-workload-seeds --catalog tests/metamorphic-workload-seeds/metamorphic_workload_seed_catalog.json --out artifacts/metamorphic-seeds/report.json --summary-out artifacts/metamorphic-seeds/summary.md"
    );
}

fn print_fuse_capability_probe_usage() {
    println!("Usage: ffs-harness fuse-capability-probe [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --out FILE                         Write JSON report to FILE");
    println!("  --require-mount-probe              Treat missing mount probe exit as not checked");
    println!("  --mount-probe-exit N               Exit code from an actual mount probe");
    println!("  --unmount-probe-exit N             Exit code from an actual unmount probe");
    println!("  --user-disabled                    Classify FUSE lanes as intentionally disabled");
    println!(
        "  --default-permissions-eacces       Classify btrfs DefaultPermissions root-owned EACCES"
    );
}

fn print_operational_readiness_report_usage() {
    println!("Usage: ffs-harness operational-readiness-report [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --artifacts DIR                    Read manifest/result JSON under DIR");
    println!("  --current-git-sha SHA              Flag sources captured from a different SHA");
    println!(
        "  --max-age-days N                   Fail when artifact created_at is older than N days"
    );
    println!(
        "  --recency-reference-timestamp TS   Compare artifact ages against TS instead of now"
    );
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write report to FILE");
}

fn print_operational_evidence_index_usage() {
    println!("Usage: ffs-harness operational-evidence-index [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --artifacts DIR                    Read manifest/result JSON under DIR");
    println!(
        "  --current-git-sha SHA              Downgrade sources captured from a different SHA"
    );
    println!("  --max-age-days N                   Downgrade artifacts older than N days");
    println!(
        "  --recency-reference-timestamp TS   Compare artifact ages against TS instead of now"
    );
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write index to FILE");
}

fn print_recommend_readiness_actions_usage() {
    println!("Usage: ffs-harness recommend-readiness-actions [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --input FILE                       Read readiness action planning input JSON");
    println!("  --out-json FILE                    Write dry-run JSON report");
    println!("  --out-md FILE                      Write dry-run Markdown report");
    println!("  --stdout-log FILE                  Write deterministic stdout log");
    println!("  --stderr-log FILE                  Write deterministic stderr log");
    println!("  --report-id ID                     Override report_id in the emitted report");
    println!("  --generated-at TS                  Override generated_at in the emitted report");
    println!("  --invocation CMD                   Preserve the exact command invocation");
}

fn print_open_ended_inventory_usage() {
    println!("Usage: ffs-harness validate-open-ended-inventory [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --out FILE                         Write JSON report to FILE");
}

fn print_open_ended_note_scanner_usage() {
    println!("Usage: ffs-harness open-ended-note-scanner [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --source FILE                      Markdown/doc source to scan; repeatable");
    println!("  --out FILE                         Write JSON report to FILE");
    println!("  --allow-invalid                    Exit zero after writing an invalid report");
    println!("  --reproduction-command CMD         Preserve exact reproduction command in JSON");
}

fn print_source_scope_manifest_usage() {
    println!("Usage: ffs-harness validate-source-scope-manifest [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --manifest FILE                    Source scope manifest JSON");
    println!("  --workspace-root DIR               Workspace root to scan (default: .)");
    println!("  --out FILE                         Write JSON report to FILE");
    println!(
        "  --remove-source-family FAMILY      Negative smoke: omit a required family before validation"
    );
}

fn print_gates_usage() {
    println!("Usage: ffs-harness gates [OPTIONS]");
    println!();
    println!("Execute the canonical spec §22.1 gate commands and report their real");
    println!("status. A filter that selects zero tests is reported as `not_implemented`");
    println!("and never as `passed`; the command exits nonzero only when a gate that HAS");
    println!("executable tests fails to pass.");
    println!();
    println!("Options:");
    println!(
        "  --gate ID                          Execute one gate (gate1..gate7 or all); repeatable"
    );
    println!("  --all                              Execute every gate (same as --gate all)");
    println!("  --local                            Run Cargo directly in CI or on a build worker");
    println!("  --out FILE                         Write the JSON report to FILE");
    println!("  --help, -h                         Print this help");
    println!();
    println!(
        "Gates: {}",
        ffs_harness::canonical_gates::canonical_gate_ids().join(", ")
    );
}

fn print_deferred_parity_audit_usage() {
    println!("Usage: ffs-harness validate-deferred-parity-audit [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --issues FILE                      Read bead JSONL from FILE");
    println!("  --report FILE                      Read audit registry markdown from FILE");
    println!("  --doc FILE                         Check a public status doc; repeatable");
    println!("  --out FILE                         Write JSON report to FILE");
}

fn print_ambition_evidence_matrix_usage() {
    println!("Usage: ffs-harness validate-ambition-evidence-matrix [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --issues FILE                      Read bead JSONL from FILE");
    println!("  --out FILE                         Write JSON report to FILE");
}

fn print_support_state_accounting_usage() {
    println!("Usage: ffs-harness validate-support-state-accounting [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --issues FILE                      Read bead JSONL from FILE");
    println!("  --feature-parity FILE              Read FEATURE_PARITY markdown from FILE");
    println!("  --format json|markdown             Output format (default: json)");
    println!(
        "  --out FILE                         Write selected-format support-state report to FILE"
    );
    println!("  --summary-out FILE                 Write Markdown inspection summary");
}

fn print_docs_status_drift_usage() {
    println!("Usage: ffs-harness validate-docs-status-drift [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --issues FILE                      Read bead JSONL from FILE");
    println!("  --feature-parity FILE              Read FEATURE_PARITY markdown from FILE");
    println!("  --snippets FILE                    Read observed docs-status snippets JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write selected-format drift report to FILE");
    println!("  --summary-out FILE                 Write Markdown docs-status summary");
}

fn print_tracker_source_hygiene_usage() {
    println!("Usage: ffs-harness validate-tracker-source-hygiene [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --issues FILE                      Read bead JSONL from FILE");
    println!("  --strict                           Fail when foreign-looking open rows exist");
    println!("  --now-epoch SECONDS                Use deterministic Unix epoch seconds");
    println!("  --stale-in-progress-seconds N      Stale threshold for claimed local rows");
    println!("  --xfstests-real-run-ack VALUE      Override XFSTESTS_REAL_RUN_ACK");
    println!("  --swarm-workload-enabled           Treat large-host swarm permission as enabled");
    println!("  --swarm-workload-real-run-ack VALUE Override FFS_SWARM_WORKLOAD_REAL_RUN_ACK");
    println!(
        "  --export-dir DIR                   Write local graph JSONL exports and .sha256 files"
    );
    println!("  --out FILE                         Write JSON report to FILE");
}

fn print_claimability_plan_usage() {
    println!("Usage: ffs-harness claimability-plan [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --tracker-report FILE              Read tracker source hygiene report JSON");
    println!(
        "  --reservation-report FILE          Read optional Agent Mail reservation report JSON"
    );
    println!("  --bv-report FILE                   Read optional bv robot JSON snapshot");
    println!("  --rch-capacity-preflight-report FILE Read optional RCH capacity preflight JSON");
    println!("  --generated-at VALUE               Override generated_at label");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write selected-format report to FILE");
    println!("  --summary-out FILE                 Write Markdown summary to FILE");
}

fn print_proof_overhead_budget_usage() {
    println!("Usage: ffs-harness validate-proof-overhead-budget [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --budget FILE                      Read proof overhead budget schema JSON");
    println!("  --metrics FILE                     Read observed proof workflow metrics JSON");
    println!("  --out FILE                         Write JSON release-gate report to FILE");
}

fn print_authoritative_environment_manifest_usage() {
    println!("Usage: ffs-harness record-environment-manifest [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --out FILE                         Write authoritative environment manifest JSON");
    println!("  --authoritative                    Mark the recorded lane authoritative");
    println!("  --non-authoritative                Mark the recorded lane non-authoritative");
    println!("  --manifest-id ID                   Override manifest id");
    println!("  --bead-id ID                       Override bead id (default: bd-7mj5d)");
    println!("  --lane-id ID                       Override lane id");
    println!("  --host-id ID                       Override host id");
    println!("  --worker-id ID                     Override worker id");
    println!("  --kernel VERSION                   Override kernel version");
    println!("  --fuse-kernel-version VERSION      Override FUSE kernel version");
    println!("  --fuser-helper-version VERSION     Override fuser helper version");
    println!("  --mkfs FLAVOR:BINARY:VERSION       Add mkfs version entry");
    println!("  --fs-tool TOOL                     Add filesystem tool version entry");
    println!("  --cargo-toolchain VERSION          Override cargo toolchain");
    println!("  --rustc-version VERSION            Override rustc version");
    println!("  --mount-namespace NS               Override mount namespace");
    println!(
        "  --privilege-model MODEL            unprivileged|user_namespace|sudo_capability|rootful"
    );
    println!("  --git-sha SHA                      Override git SHA");
    println!("  --artifact-schema-version N        Override artifact schema version");
    println!("  --probe-at-unix N                  Override probe timestamp");
    println!("  --freshness-ttl-seconds N          Override freshness TTL");
    println!("  --now-unix N                       Override freshness reference timestamp");
    println!("  --replay-command CMD               Override replay command");
    println!("  --max-open-files N                 Override max open files limit");
    println!("  --max-address-space-bytes N        Override max address-space limit");
    println!("  --max-processes N                  Override max processes limit");
}

fn print_adaptive_runtime_manifest_usage() {
    println!("Usage: ffs-harness validate-adaptive-runtime-manifest [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --manifest FILE                    Read adaptive runtime manifest JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write selected-format validation report");
    println!("  --summary-out FILE                 Write Markdown inspection summary");
    println!("  --reference-timestamp RFC3339      Freshness reference timestamp (default: now)");
    println!("  --current-git-sha SHA              Strictly require manifest git_sha to match SHA");
}

fn print_topology_runtime_advisor_usage() {
    println!(
        "Usage: ffs-harness validate-topology-runtime-advisor|score-topology-runtime-advisor [OPTIONS]"
    );
    println!();
    println!("Options:");
    println!("  --manifest FILE                    Read topology advisor manifest JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write selected-format validation report");
    println!("  --summary-out FILE                 Write Markdown inspection summary");
    println!("  --structured-log-out FILE          Write structured JSONL validation log");
    println!("  --reference-timestamp RFC3339      Freshness reference timestamp (default: now)");
    println!("  --max-age-days N                   Maximum manifest age in days (default: 14)");
}

fn print_permissioned_campaign_broker_usage() {
    println!("Usage: ffs-harness validate-permissioned-campaign-broker [OPTIONS]");
    println!();
    println!("Options:");
    println!(
        "  --manifest FILE                    Read permissioned campaign broker manifest JSON"
    );
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write selected-format validation report");
    println!("  --summary-out FILE                 Write Markdown inspection summary");
    println!("  --reference-timestamp RFC3339      Freshness reference timestamp (default: now)");
}

fn print_permissioned_campaign_ledger_usage() {
    println!("Usage: ffs-harness validate-permissioned-campaign-ledger [OPTIONS]");
    println!();
    println!("Options:");
    println!(
        "  --manifest FILE                    Read permissioned campaign broker manifest JSON"
    );
    println!("  --ledger FILE                      Read permissioned execution ledger JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write selected-format ledger report");
    println!("  --summary-out FILE                 Write Markdown ledger summary");
    println!("  --current-git-sha SHA              Strictly require ledger git_sha to match SHA");
}

fn print_permissioned_campaign_packet_usage() {
    println!("Usage: ffs-harness generate-permissioned-campaign-packet [OPTIONS]");
    println!();
    println!("Options:");
    println!(
        "  --manifest FILE                    Read permissioned campaign broker manifest JSON"
    );
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write selected-format handoff packet");
    println!("  --summary-out FILE                 Write Markdown handoff packet");
    println!("  --reference-timestamp RFC3339      Freshness reference timestamp (default: now)");
    println!("  --generated-at TS                  Override packet generated_at");
    println!("  --generated-by NAME                Override packet generator identity");
    println!("  --git-sha SHA                      Override packet git_sha");
}

fn print_swarm_capability_calibration_usage() {
    println!("Usage: ffs-harness validate-swarm-capability-calibration [OPTIONS]");
    println!();
    println!("Options:");
    println!(
        "  --manifest FILE                    Read swarm capability calibration manifest JSON"
    );
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write selected-format calibration report");
    println!("  --summary-out FILE                 Write Markdown calibration summary");
    println!("  --reference-timestamp RFC3339      Freshness reference timestamp (default: now)");
}

fn print_adaptive_runtime_runner_usage() {
    println!("Usage: ffs-harness adaptive-runtime-runner [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --mode dry-run|capability-probe|permissioned-real");
    println!("                                      Runner mode (default: dry-run)");
    println!("  --artifact-root DIR                Artifact-scoped output root");
    println!("  --out FILE                         Write JSON runner report");
    println!("  --summary-out FILE                 Write Markdown runner summary");
    println!("  --stdout-log FILE                  Write captured stdout log");
    println!("  --stderr-log FILE                  Write captured stderr log");
    println!("  --structured-log FILE              Write structured JSONL log");
    println!("  --manifest-out FILE                Write runner plan manifest");
    println!("  --cleanup-out FILE                 Write cleanup report");
    println!("  --host-facts-out FILE              Write host facts JSON");
    println!("  --test-dir DIR                     Permissioned TEST_DIR-style path");
    println!("  --scratch-mnt DIR                  Permissioned SCRATCH_MNT-style path");
    println!(
        "  --ack-env NAME                     ACK env var (default: FFS_ADAPTIVE_RUNTIME_REAL_RUN_ACK)"
    );
    println!(
        "  --ack-value VALUE                  Required ACK token (default: adaptive-runtime-may-mount-and-generate-load)"
    );
    println!("  --generated-at TS                  Override generated_at in artifacts");
    println!("  --git-sha SHA                      Git SHA captured in artifacts");
    println!("  --reproduction-command CMD         Exact command to preserve in artifacts");
    println!(
        "  --cleanup-status STATUS            not-started-dry-run|clean|preserved-artifacts|failed"
    );
}

fn print_proof_bundle_usage() {
    println!("Usage: ffs-harness validate-proof-bundle [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --bundle FILE                      Read proof bundle manifest JSON");
    println!("  --current-git-sha SHA              Flag manifest captured from a different SHA");
    println!("  --max-age-days N                   Fail when generated_at is older than N days");
    println!("  --format json|markdown             Output format (default: json)");
    println!(
        "  --out FILE                         Write selected-format validation report to FILE"
    );
    println!("  --summary-out FILE                 Write Markdown inspection summary to FILE");
    println!(
        "  --execute-configured-lanes         Run configured executable lanes and attach ExecutedEvidence"
    );
}

fn print_invariant_oracle_usage() {
    println!("Usage: ffs-harness validate-invariant-oracle [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --trace FILE                       Read invariant trace JSON");
    println!("  --report FILE                      Validate existing invariant oracle report JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write selected-format oracle report to FILE");
    println!("  --summary-out FILE                 Write Markdown inspection summary to FILE");
}

fn print_release_gate_usage() {
    println!("Usage: ffs-harness evaluate-release-gates [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --bundle FILE                      Read proof bundle manifest JSON");
    println!("  --policy FILE                      Read release-gate policy JSON");
    println!("  --current-git-sha SHA              Fail when bundle SHA differs");
    println!("  --max-age-days N                   Fail when bundle generated_at is stale");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write release-gate report to FILE");
    println!("  --wording-out FILE                 Write generated docs-safe wording TSV");
}

fn print_performance_manifest_usage() {
    println!("Usage: ffs-harness validate-performance-baseline-manifest [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --manifest FILE                    Read performance baseline manifest JSON");
    println!(
        "  --manifest-json-env VAR            Read performance baseline manifest JSON from env var"
    );
    println!("  --artifact-root DIR                Root for dry-run expanded artifacts");
    println!("  --out FILE                         Write validation report JSON");
    println!("  --artifact-out FILE                Write sample shared QA artifact manifest JSON");
}

fn print_performance_delta_closeout_usage() {
    println!("Usage: ffs-harness performance-delta-closeout [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --config FILE                      Read performance delta closeout JSON");
    println!("  --issues FILE                      Override bead JSONL path from config");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write selected-format closeout report");
    println!("  --summary-out FILE                 Write Markdown closeout summary");
}

fn print_swarm_cache_controller_usage() {
    println!("Usage: ffs-harness validate-swarm-cache-controller [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --contract FILE                    Read swarm cache controller contract JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write selected-format validation report");
    println!("  --summary-out FILE                 Write Markdown inspection summary");
}

fn print_swarm_operator_report_usage() {
    println!("Usage: ffs-harness validate-swarm-operator-report [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --report FILE                      Read swarm operator decision report JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write selected-format validation report");
    println!("  --summary-out FILE                 Write Markdown inspection summary");
}

fn print_swarm_tail_latency_usage() {
    println!("Usage: ffs-harness validate-swarm-tail-latency [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --ledger FILE                      Read swarm tail-latency ledger JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write selected-format validation report");
    println!("  --summary-out FILE                 Write Markdown inspection summary");
}

fn print_swarm_workload_harness_usage() {
    println!("Usage: ffs-harness validate-swarm-workload-harness [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --manifest FILE                    Read swarm workload harness manifest JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write selected-format validation report");
    println!("  --summary-out FILE                 Write Markdown inspection summary");
    println!(
        "  --max-age-days N                   Reject manifests older than N days (default: 14)"
    );
    println!("  --reference-timestamp RFC3339      Freshness reference timestamp (default: now)");
}

fn print_wal_group_commit_gate_usage() {
    println!("Usage: ffs-harness validate-wal-group-commit-gate [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --manifest FILE                    Read WAL group-commit gate manifest JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write selected-format validation report");
    println!("  --summary-out FILE                 Write Markdown inspection summary");
}

fn print_scrub_repair_scheduler_usage() {
    println!("Usage: ffs-harness validate-scrub-repair-scheduler [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --manifest FILE                    Read scrub/repair scheduler manifest JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write selected-format validation report");
    println!("  --summary-out FILE                 Write Markdown inspection summary");
}

fn print_adversarial_threat_model_usage() {
    println!("Usage: ffs-harness validate-adversarial-threat-model [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --model FILE                       Read adversarial threat model JSON");
    println!(
        "  --model-json-env VAR               Read adversarial threat model JSON from env var"
    );
    println!("  --artifact-root DIR                Root for dry-run security artifacts");
    println!("  --out FILE                         Write validation report JSON");
    println!("  --artifact-out FILE                Write sample shared QA artifact manifest JSON");
    println!("  --wording-out FILE                 Write generated docs-safe wording TSV");
}

fn print_soak_canary_campaign_usage() {
    println!("Usage: ffs-harness validate-soak-canary-campaigns [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --manifest FILE                    Read soak/canary campaign manifest JSON");
    println!("  --artifact-root DIR                Root for dry-run campaign artifacts");
    println!("  --out FILE                         Write validation report JSON");
    println!("  --artifact-out FILE                Write sample shared QA artifact manifest JSON");
    println!("  --summary-out FILE                 Write Markdown campaign summary");
}

fn print_repair_confidence_lab_usage() {
    println!("Usage: ffs-harness validate-repair-confidence-lab [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --spec FILE                        Read repair confidence lab JSON");
    println!("  --spec-json-env VAR                Read repair confidence lab JSON from env var");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report");
    println!("  --summary-out FILE                 Write Markdown lab summary");
    println!(
        "  --select SCENARIO_ID               Accepted by repro commands; validates the lab envelope"
    );
}

fn print_operator_recovery_drill_usage() {
    println!("Usage: ffs-harness validate-operator-recovery-drill [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --spec FILE                        Read operator recovery drill JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report");
    println!("  --summary-out FILE                 Write Markdown drill summary");
    println!(
        "  --select SCENARIO_ID               Accepted by repro commands; validates the drill envelope"
    );
}

fn print_repair_writeback_serialization_usage() {
    println!("Usage: ffs-harness validate-repair-writeback-serialization [OPTIONS]");
    println!();
    println!("Options:");
    println!(
        "  --contract FILE                    Read repair/writeback serialization contract JSON"
    );
    println!(
        "  --contract-json-env VAR            Read repair/writeback serialization contract JSON from env var"
    );
    println!("  --artifact-root DIR                Root for dry-run serialization artifacts");
    println!("  --out FILE                         Write validation report JSON");
    println!("  --artifact-out FILE                Write sample shared QA artifact manifest JSON");
    println!("  --summary-out FILE                 Write Markdown contract summary");
    println!("  --proof-summary-out FILE           Write downstream proof summary JSON");
}

fn print_writeback_cache_audit_usage() {
    println!("Usage: ffs-harness validate-writeback-cache-audit [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --gate FILE                        Read writeback-cache audit gate JSON");
    println!("  --scenario-id ID                   Scenario identifier for the emitted report");
    println!(
        "  --reproduction-command CMD         Command captured in the report reproduction field"
    );
    println!("  --require-accept                   Exit nonzero unless the gate accepts");
    println!("  --out FILE                         Write validation report JSON");
    println!("  --summary-out FILE                 Write Markdown gate summary");
}

fn print_writeback_cache_ordering_usage() {
    println!("Usage: ffs-harness validate-writeback-cache-ordering [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --oracle FILE                      Read writeback-cache ordering oracle JSON");
    println!("  --scenario-id ID                   Scenario identifier for the emitted report");
    println!(
        "  --reproduction-command CMD         Command captured in the report reproduction field"
    );
    println!("  --require-accept                   Exit nonzero unless the oracle accepts");
    println!("  --out FILE                         Write validation report JSON");
    println!("  --summary-out FILE                 Write Markdown oracle summary");
}

fn print_writeback_cache_crash_replay_usage() {
    println!("Usage: ffs-harness validate-writeback-cache-crash-replay [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --oracle FILE                      Read writeback-cache crash/replay oracle JSON");
    println!("  --scenario-id ID                   Scenario identifier for the emitted report");
    println!(
        "  --reproduction-command CMD         Command captured in the report reproduction field"
    );
    println!("  --require-accept                   Exit nonzero unless the oracle accepts");
    println!("  --out FILE                         Write validation report JSON");
    println!("  --summary-out FILE                 Write Markdown oracle summary");
}

fn print_workload_corpus_usage() {
    println!("Usage: ffs-harness validate-workload-corpus [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --corpus FILE                      Read workload corpus JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report");
    println!("  --summary-out FILE                 Write Markdown corpus summary");
    println!(
        "  --select SCENARIO_ID               Accepted by repro commands; validates the corpus envelope"
    );
}

fn print_btrfs_send_receive_corpus_usage() {
    println!("Usage: ffs-harness validate-btrfs-send-receive-corpus [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --corpus FILE                      Read btrfs send/receive corpus JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report");
    println!("  --summary-out FILE                 Write Markdown corpus summary");
}

fn print_btrfs_multidevice_corpus_usage() {
    println!("Usage: ffs-harness validate-btrfs-multidevice-corpus [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --corpus FILE                      Read btrfs multi-device corpus JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report");
    println!("  --summary-out FILE                 Write Markdown corpus summary");
}

fn print_casefold_corpus_usage() {
    println!("Usage: ffs-harness validate-casefold-corpus [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --corpus FILE                      Read ext4 casefold corpus JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report");
    println!("  --summary-out FILE                 Write Markdown corpus summary");
}

fn print_fault_injection_corpus_usage() {
    println!("Usage: ffs-harness validate-fault-injection-corpus [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --corpus FILE                      Read fault injection corpus JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report");
    println!("  --summary-out FILE                 Write Markdown corpus summary");
}

fn print_repair_corpus_usage() {
    println!("Usage: ffs-harness validate-repair-corpus [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --corpus FILE                      Read repair corpus JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report");
    println!("  --summary-out FILE                 Write Markdown corpus summary");
}

fn print_mounted_checkpoint_survivor_usage() {
    println!("Usage: ffs-harness validate-mounted-checkpoint-survivor [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --matrix FILE                      Read mounted checkpoint survivor JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report");
    println!("  --summary-out FILE                 Write Markdown survivor summary");
}

fn print_low_privilege_demo_usage() {
    println!("Usage: ffs-harness validate-low-privilege-demo [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --manifest FILE                    Read low-privilege demo JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report");
    println!("  --summary-out FILE                 Write Markdown demo summary");
}

fn print_low_privilege_demo_sandbox_usage() {
    println!("Usage: ffs-harness validate-low-privilege-demo-sandbox [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --manifest FILE                    Read low-privilege demo sandbox JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report");
    println!("  --summary-out FILE                 Write Markdown sandbox summary");
}

fn print_metamorphic_workload_seed_catalog_usage() {
    println!("Usage: ffs-harness validate-metamorphic-workload-seeds [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --catalog FILE                     Read metamorphic workload seed catalog JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report");
    println!("  --summary-out FILE                 Write Markdown catalog summary");
}

fn print_mounted_write_matrix_usage() {
    println!("Usage: ffs-harness validate-mounted-write-matrix [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --matrix FILE                      Read matrix JSON from FILE");
    println!("  --out FILE                         Write JSON validation report to FILE");
}

fn print_mounted_write_error_classes_usage() {
    println!("Usage: ffs-harness validate-mounted-write-error-classes [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --catalog FILE                     Read mounted write error class JSON");
    println!("  --matrix FILE                      Read mounted write matrix JSON");
    println!("  --out FILE                         Write JSON validation report to FILE");
}

fn print_mounted_differential_oracle_usage() {
    println!("Usage: ffs-harness validate-mounted-differential-oracle [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --report FILE                      Read mounted differential report JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report to FILE");
}

fn print_mounted_repair_mutation_boundary_usage() {
    println!("Usage: ffs-harness validate-mounted-repair-mutation-boundary [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --matrix FILE                      Read mounted repair mutation boundary JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report to FILE");
    println!("  --summary-out FILE                 Write Markdown mutation-boundary summary");
}

fn print_chaos_replay_lab_usage() {
    println!("Usage: ffs-harness validate-chaos-replay-lab [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --lab FILE                         Read chaos replay lab JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report");
    println!("  --summary-out FILE                 Write Markdown lab summary");
}

fn print_remediation_catalog_usage() {
    println!("Usage: ffs-harness validate-remediation-catalog [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --catalog FILE                     Read remediation catalog JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report to FILE");
    println!("  --summary-out FILE                 Write Markdown catalog summary to FILE");
}

fn print_inventory_closeout_gate_usage_summary() {
    println!(
        "  ffs-harness validate-inventory-closeout-gate [--gate FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_inventory_closeout_gate_example() {
    println!(
        "  ffs-harness validate-inventory-closeout-gate --gate tests/inventory-closeout-gate/inventory_closeout_gate.json --out artifacts/inventory-closeout/gate_report.json --summary-out artifacts/inventory-closeout/gate_summary.md"
    );
}

fn print_inventory_closeout_gate_usage() {
    println!("Usage: ffs-harness validate-inventory-closeout-gate [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --gate FILE                        Read inventory closeout gate JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report");
    println!("  --summary-out FILE                 Write Markdown inventory summary");
}

fn print_report_schema_inventory_usage_summary() {
    println!(
        "  ffs-harness validate-report-schema-inventory [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_report_schema_inventory_usage() {
    println!("Usage: ffs-harness validate-report-schema-inventory [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report");
    println!("  --summary-out FILE                 Write Markdown inventory summary");
}

fn print_remediation_severity_gate_usage_summary() {
    println!(
        "  ffs-harness validate-remediation-severity-gate [--gate FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_remediation_severity_gate_example() {
    println!(
        "  ffs-harness validate-remediation-severity-gate --gate tests/remediation-severity-gate/remediation_severity_gate.json --out artifacts/remediation/severity_gate_report.json --summary-out artifacts/remediation/severity_gate_summary.md"
    );
}

fn print_remediation_severity_gate_usage() {
    println!("Usage: ffs-harness validate-remediation-severity-gate [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --gate FILE                        Read remediation severity gate JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report");
    println!("  --summary-out FILE                 Write Markdown severity summary");
}

fn print_cross_oracle_arbitration_usage() {
    println!("Usage: ffs-harness validate-cross-oracle-arbitration [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --report FILE                      Read cross-oracle arbitration JSON");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write validation report to FILE");
}

fn print_mounted_recovery_matrix_usage() {
    println!("Usage: ffs-harness validate-mounted-recovery-matrix [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --matrix FILE                      Read mounted recovery matrix JSON from FILE");
    println!("  --out FILE                         Write JSON validation report to FILE");
}

#[cfg(test)]
mod authoritative_environment_manifest_cli_tests {
    use super::*;

    #[test]
    fn record_environment_manifest_cmd_writes_replayable_manifest() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let manifest_path = dir.path().join("env-manifest.json");
        let args = vec![
            "--out".to_owned(),
            manifest_path.display().to_string(),
            "--manifest-id".to_owned(),
            "env_cli_test".to_owned(),
            "--bead-id".to_owned(),
            "bd-7mj5d".to_owned(),
            "--lane-id".to_owned(),
            "rchk_authoritative_v1".to_owned(),
            "--authoritative".to_owned(),
            "--host-id".to_owned(),
            "worker-vmi1153651".to_owned(),
            "--worker-id".to_owned(),
            "rch-worker-vmi1153651".to_owned(),
            "--kernel".to_owned(),
            "linux-6.x.y".to_owned(),
            "--fuse-kernel-version".to_owned(),
            "fuse-3.16".to_owned(),
            "--fuser-helper-version".to_owned(),
            "fuser-0.16".to_owned(),
            "--mkfs".to_owned(),
            "ext4:mkfs.ext4:1.47.0".to_owned(),
            "--mkfs".to_owned(),
            "btrfs:mkfs.btrfs:6.5.1".to_owned(),
            "--cargo-toolchain".to_owned(),
            "nightly-2024-edition-pinned".to_owned(),
            "--rustc-version".to_owned(),
            "rustc 1.85.0-nightly".to_owned(),
            "--mount-namespace".to_owned(),
            "mnt:[4026531840]".to_owned(),
            "--privilege-model".to_owned(),
            "sudo_capability".to_owned(),
            "--fs-tool".to_owned(),
            "e2fsck:1.47.0".to_owned(),
            "--fs-tool".to_owned(),
            "btrfs:6.5.1".to_owned(),
            "--git-sha".to_owned(),
            "abcdef1234567890".to_owned(),
            "--artifact-schema-version".to_owned(),
            "1".to_owned(),
            "--probe-at-unix".to_owned(),
            "1000".to_owned(),
            "--freshness-ttl-seconds".to_owned(),
            "3600".to_owned(),
            "--now-unix".to_owned(),
            "1500".to_owned(),
            "--max-open-files".to_owned(),
            "65536".to_owned(),
            "--max-address-space-bytes".to_owned(),
            "8589934592".to_owned(),
            "--max-processes".to_owned(),
            "4096".to_owned(),
            "--replay-command".to_owned(),
            "rch exec -- cargo run -p ffs-harness -- record-environment-manifest --out artifacts/env-manifest.json"
                .to_owned(),
        ];

        record_authoritative_environment_manifest_cmd(&args)?;

        let manifest_json = std::fs::read_to_string(&manifest_path)?;
        let manifest: AuthoritativeEnvironmentManifest = serde_json::from_str(&manifest_json)?;
        assert_eq!(
            manifest.schema_version,
            AUTHORITATIVE_ENVIRONMENT_MANIFEST_SCHEMA_VERSION
        );
        assert_eq!(manifest.manifest_id, "env_cli_test");
        assert!(manifest.authoritative);
        assert_eq!(
            manifest.replay_command,
            "rch exec -- cargo run -p ffs-harness -- record-environment-manifest --out artifacts/env-manifest.json"
        );
        assert!(matches!(
            evaluate_authoritative_environment(&manifest, &manifest),
            AuthoritativeEnvironmentDecision::Authoritative { .. }
        ));
        Ok(())
    }

    #[test]
    fn record_environment_manifest_rejects_malformed_mkfs_arg() {
        let args = vec![
            "--out".to_owned(),
            "artifacts/env-manifest.json".to_owned(),
            "--mkfs".to_owned(),
            "ext4:mkfs.ext4".to_owned(),
        ];
        let error = parse_authoritative_environment_record_cmd_args(&args)
            .expect_err("malformed mkfs entry should be rejected");
        assert!(error.to_string().contains("FLAVOR:BINARY:VERSION"));
    }
}

#[cfg(test)]
mod readiness_action_cli_tests {
    use super::*;

    #[test]
    fn recommend_readiness_actions_cmd_writes_dry_run_report_pack() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let json_path = dir.path().join("readiness-actions.json");
        let markdown_path = dir.path().join("readiness-actions.md");
        let stdout_log_path = dir.path().join("stdout.log");
        let stderr_log_path = dir.path().join("stderr.log");

        let args = vec![
            "--out-json".to_owned(),
            json_path.display().to_string(),
            "--out-md".to_owned(),
            markdown_path.display().to_string(),
            "--stdout-log".to_owned(),
            stdout_log_path.display().to_string(),
            "--stderr-log".to_owned(),
            stderr_log_path.display().to_string(),
            "--report-id".to_owned(),
            "cli_dry_run_test".to_owned(),
            "--generated-at".to_owned(),
            "2026-05-07T00:00:00Z".to_owned(),
            "--invocation".to_owned(),
            "ffs-harness recommend-readiness-actions --dry-run-test".to_owned(),
        ];

        recommend_readiness_actions_cmd(&args)?;

        let json = std::fs::read_to_string(&json_path)?;
        let report: ReadinessActionDryRunReport = serde_json::from_str(&json)?;
        assert!(report.dry_run);
        assert_eq!(report.report_id, "cli_dry_run_test");
        assert_eq!(report.generated_at, "2026-05-07T00:00:00Z");
        assert_eq!(
            report.command_metadata.cleanup_status,
            "not_required_dry_run"
        );

        let action_ids: Vec<&str> = report
            .scenarios
            .iter()
            .map(|scenario| scenario.action_id.as_str())
            .collect();
        assert!(action_ids.contains(&"define-readiness-action-schema"));
        assert!(action_ids.contains(&"claim-source-aware-task"));
        assert!(action_ids.contains(&"preserve-degraded-rch-proof-ledger"));
        assert!(action_ids.contains(&"run-permissioned-xfstests-baseline"));
        assert!(action_ids.contains(&"refresh-large-host-swarm-campaign"));

        let markdown = std::fs::read_to_string(&markdown_path)?;
        assert!(markdown.contains("# Readiness Action Dry-Run Report"));
        assert!(markdown.contains("## Operator Evidence"));
        assert!(markdown.contains("LocalSafe"));
        assert!(markdown.contains("Permissioned"));
        assert!(markdown.contains("DowngradeRequired"));

        let stdout_log = std::fs::read_to_string(&stdout_log_path)?;
        let temp_dir = dir.path().display().to_string();
        let normalized_stdout_log = stdout_log.replace(&temp_dir, "[TMP]");
        insta::assert_snapshot!("readiness_action_cli_stdout_log", normalized_stdout_log);
        assert!(stdout_log.contains("readiness-action-dry-run"));
        assert!(stdout_log.contains("recommendations=8"));
        assert!(stdout_log.contains("scenarios=8"));
        assert!(stdout_log.contains("cleanup_status=not_required_dry_run"));

        let stderr_log = std::fs::read_to_string(&stderr_log_path)?;
        insta::assert_snapshot!("readiness_action_cli_stderr_log", stderr_log);
        assert!(stderr_log.contains("no reproduction commands executed"));
        assert!(stderr_log.contains("stale-evidence commands stayed dry-run only"));
        Ok(())
    }
}
