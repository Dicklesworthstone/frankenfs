#![forbid(unsafe_code)]

//! One-command operational readiness aggregation for `bd-rchk0.4.3`.
//!
//! The report consumes the existing artifact-manifest schema plus legacy
//! `scripts/e2e` `result.json` summaries. It intentionally stays read-only:
//! raw logs and artifacts remain where the producing gate wrote them, while
//! this module groups outcomes, preserves links, and separates product failures
//! from host or worker blockers.

use crate::artifact_manifest::{
    ArtifactManifest, GateVerdict, ManifestValidationError, OperationalErrorClass,
    OperationalOutcomeClass, READINESS_EVENT_ENVELOPE_VERSION, ReadinessEventEnvelope,
    ScenarioOutcome, ScenarioResult, SkipReason, parse_manifest_timestamp_epoch_days,
    validate_operational_manifest,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const READINESS_REPORT_SCHEMA_VERSION: u32 = 1;
const REQUIRED_WORKSTREAMS: [&str; 9] = [
    "xfstests",
    "fuse_lane",
    "mounted_scenario_matrix",
    "repair_policy",
    "writeback_cache",
    "fuzz_smoke",
    "performance",
    "proof_bundle",
    "release_gate",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalReadinessReportConfig {
    pub artifacts_dir: PathBuf,
    pub current_git_sha: Option<String>,
    pub max_artifact_age_days: Option<u32>,
    pub recency_reference_epoch_days: Option<u32>,
}

impl OperationalReadinessReportConfig {
    #[must_use]
    pub fn new(artifacts_dir: impl Into<PathBuf>) -> Self {
        Self {
            artifacts_dir: artifacts_dir.into(),
            current_git_sha: None,
            max_artifact_age_days: None,
            recency_reference_epoch_days: None,
        }
    }

    fn effective_recency_reference_epoch_days(&self) -> Result<Option<u32>> {
        if self.max_artifact_age_days.is_none() {
            return Ok(None);
        }
        if let Some(epoch_days) = self.recency_reference_epoch_days {
            return Ok(Some(epoch_days));
        }
        current_manifest_epoch_days()
            .context("failed to compute current day for readiness artifact recency")
            .map(Some)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalReadinessReport {
    pub schema_version: u32,
    pub report_id: String,
    pub source_root: String,
    pub source_manifest_count: usize,
    pub source_legacy_summary_count: usize,
    pub ignored_json_count: usize,
    pub scenario_count: usize,
    pub readiness_event_count: usize,
    pub readiness_event_envelope_version: u32,
    pub readiness_event_lane_ids: Vec<String>,
    pub correlation_graph_summary: ReadinessCorrelationGraphSummary,
    pub totals: ReadinessCounts,
    pub workstreams: BTreeMap<String, ReadinessCounts>,
    pub required_workstreams_missing: Vec<String>,
    pub contract_failed: bool,
    pub contract_violations: Vec<ReadinessContractViolation>,
    pub duplicate_scenario_ids: Vec<String>,
    pub stale_git_shas: Vec<StaleGitSha>,
    pub stale_artifacts: Vec<StaleArtifact>,
    pub invalid_artifact_timestamps: Vec<InvalidArtifactTimestamp>,
    pub missing_log_paths: Vec<MissingLogPath>,
    pub scenarios: Vec<ReadinessScenarioRow>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessCounts {
    pub pass: usize,
    pub fail: usize,
    pub skip: usize,
    pub error: usize,
    pub product_failures: usize,
    pub environment_blockers: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessCorrelationGraphSummary {
    pub event_nodes: usize,
    pub parent_edges: usize,
    pub orphan_parent_edges: usize,
    pub aggregate_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleGitSha {
    pub source_path: String,
    pub gate_id: String,
    pub run_id: String,
    pub observed: String,
    pub expected: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleArtifact {
    pub source_path: String,
    pub gate_id: String,
    pub run_id: String,
    pub created_at: String,
    pub age_days: u32,
    pub max_age_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidArtifactTimestamp {
    pub source_path: String,
    pub gate_id: String,
    pub run_id: String,
    pub created_at: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRecencyState {
    NotChecked,
    Fresh,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingLogPath {
    pub source_path: String,
    pub scenario_id: Option<String>,
    pub field: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessContractViolation {
    pub source_path: String,
    pub scenario_id: Option<String>,
    pub violation: String,
    pub remediation_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessOutcome {
    Pass,
    Fail,
    Skip,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessTaxonomyClass {
    Pass,
    ProductFailure,
    HostCapabilitySkip,
    AuthoritativeLaneUnavailable,
    HarnessFailure,
    UnsupportedByScope,
    StaleArtifact,
    MissingArtifact,
    NoisyMeasurement,
    SecurityRefusal,
    UnsafeRepairRefusal,
    PassWithExperimentalCaveat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessScenarioRow {
    pub source_path: String,
    pub source_kind: SourceKind,
    pub gate_id: String,
    pub run_id: String,
    pub workstream: String,
    pub scenario_id: String,
    pub outcome: ReadinessOutcome,
    pub taxonomy_class: ReadinessTaxonomyClass,
    pub failure_kind: Option<String>,
    pub skip_reason: Option<String>,
    pub environment_only_blocker: bool,
    pub product_failure: bool,
    pub git_commit: String,
    pub stale_git_sha: bool,
    pub artifact_recency: ArtifactRecencyState,
    pub artifact_age_days: Option<u32>,
    pub manifest_schema_version: Option<u32>,
    pub host_fingerprint: Option<String>,
    pub stdout_path: Option<String>,
    pub stderr_path: Option<String>,
    pub artifact_refs: Vec<String>,
    pub controlling_artifact: Option<String>,
    pub readiness_event_ids: Vec<String>,
    pub parent_correlation_ids: Vec<String>,
    pub event_artifact_ids: Vec<String>,
    pub event_severities: Vec<String>,
    pub reproduction_command: Option<String>,
    pub cleanup_status: Option<String>,
    pub remediation_hint: Option<String>,
    pub owner_bead: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    ArtifactManifest,
    LegacyE2eSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct LegacyE2eSummary {
    gate_id: String,
    run_id: String,
    #[serde(default)]
    created_at: Option<String>,
    git_context: LegacyGitContext,
    scenarios: Vec<LegacyScenario>,
    verdict: String,
    duration_secs: u64,
    log_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct LegacyGitContext {
    commit: String,
    branch: String,
    clean: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct LegacyScenario {
    scenario_id: String,
    outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Default)]
struct ReportBuilder {
    source_manifest_count: usize,
    source_legacy_summary_count: usize,
    ignored_json_count: usize,
    readiness_event_count: usize,
    readiness_event_lane_ids: BTreeSet<String>,
    correlation_graph_summary: ReadinessCorrelationGraphSummary,
    totals: ReadinessCounts,
    workstreams: BTreeMap<String, ReadinessCounts>,
    seen_scenarios: BTreeMap<String, usize>,
    stale_git_shas: Vec<StaleGitSha>,
    stale_artifacts: Vec<StaleArtifact>,
    invalid_artifact_timestamps: Vec<InvalidArtifactTimestamp>,
    missing_log_paths: Vec<MissingLogPath>,
    contract_violations: Vec<ReadinessContractViolation>,
    scenarios: Vec<ReadinessScenarioRow>,
}

#[derive(Clone, Copy)]
struct LogSource<'a> {
    source_path: &'a Path,
    source_path_text: &'a str,
    scenario_id: Option<&'a str>,
}

struct TaxonomyInput<'a> {
    outcome: ReadinessOutcome,
    error_class: Option<OperationalErrorClass>,
    skip_reason: Option<SkipReason>,
    workstream: &'a str,
    stale_git_sha: bool,
    stale_artifact: bool,
    artifact_refs: &'a [String],
    detail: Option<&'a str>,
    remediation_hint: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ArtifactRecency {
    state: Option<ArtifactRecencyState>,
    age_days: Option<u32>,
}

impl ArtifactRecency {
    fn not_checked() -> Self {
        Self {
            state: Some(ArtifactRecencyState::NotChecked),
            age_days: None,
        }
    }

    fn fresh(age_days: u32) -> Self {
        Self {
            state: Some(ArtifactRecencyState::Fresh),
            age_days: Some(age_days),
        }
    }

    fn stale(age_days: u32) -> Self {
        Self {
            state: Some(ArtifactRecencyState::Stale),
            age_days: Some(age_days),
        }
    }

    fn state(self) -> ArtifactRecencyState {
        self.state.unwrap_or(ArtifactRecencyState::NotChecked)
    }

    fn is_stale(self) -> bool {
        self.state() == ArtifactRecencyState::Stale
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceDiagnostics {
    stale_git_sha: bool,
    artifact_recency: ArtifactRecency,
}

pub fn build_operational_readiness_report(
    config: &OperationalReadinessReportConfig,
) -> Result<OperationalReadinessReport> {
    let recency_reference_epoch_days = config.effective_recency_reference_epoch_days()?;
    let source_paths = collect_json_paths(&config.artifacts_dir)
        .with_context(|| format!("failed to scan {}", config.artifacts_dir.display()))?;
    let mut builder = ReportBuilder::default();

    for source_path in source_paths {
        let text = fs::read_to_string(&source_path)
            .with_context(|| format!("failed to read {}", source_path.display()))?;
        if let Ok(manifest) = serde_json::from_str::<ArtifactManifest>(&text) {
            builder.ingest_manifest(
                config,
                recency_reference_epoch_days,
                &source_path,
                &manifest,
            );
        } else if let Ok(summary) = serde_json::from_str::<LegacyE2eSummary>(&text) {
            builder.ingest_legacy_summary(
                config,
                recency_reference_epoch_days,
                &source_path,
                &summary,
            );
        } else {
            builder.ignored_json_count += 1;
        }
    }

    Ok(builder.finish(config))
}

#[must_use]
pub fn render_operational_readiness_markdown(report: &OperationalReadinessReport) -> String {
    let mut out = String::new();
    render_operational_readiness_markdown_summary(&mut out, report);
    writeln!(&mut out).ok();
    if !report.stale_artifacts.is_empty() {
        writeln!(&mut out, "## Stale Artifacts").ok();
        for stale in &report.stale_artifacts {
            writeln!(
                &mut out,
                "- `{}` `{}` run `{}` age={}d max={}d created_at={}",
                stale.source_path,
                stale.gate_id,
                stale.run_id,
                stale.age_days,
                stale.max_age_days,
                stale.created_at
            )
            .ok();
        }
        writeln!(&mut out).ok();
    }
    if !report.invalid_artifact_timestamps.is_empty() {
        writeln!(&mut out, "## Invalid Artifact Timestamps").ok();
        for invalid in &report.invalid_artifact_timestamps {
            let created_at = invalid.created_at.as_deref().unwrap_or("<missing>");
            writeln!(
                &mut out,
                "- `{}` `{}` run `{}` created_at={} reason={}",
                invalid.source_path, invalid.gate_id, invalid.run_id, created_at, invalid.reason
            )
            .ok();
        }
        writeln!(&mut out).ok();
    }
    writeln!(&mut out, "## Workstreams").ok();
    for (workstream, counts) in &report.workstreams {
        writeln!(
            &mut out,
            "- `{workstream}`: pass={} fail={} skip={} error={} product_failures={} environment_blockers={}",
            counts.pass,
            counts.fail,
            counts.skip,
            counts.error,
            counts.product_failures,
            counts.environment_blockers
        )
        .ok();
    }
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Scenarios").ok();
    writeln!(
        &mut out,
        "| Workstream | Scenario | Outcome | Failure kind | Events | Source | Logs |"
    )
    .ok();
    writeln!(&mut out, "|---|---|---:|---|---|---|---|").ok();
    for row in &report.scenarios {
        let failure_kind = row.failure_kind.as_deref().unwrap_or("");
        let taxonomy_class = serialized_enum_name(row.taxonomy_class);
        let logs = render_log_links(row);
        writeln!(
            &mut out,
            "| `{}` | `{}` | `{:?}` | {} / {} | {} | `{}` | {} |",
            row.workstream,
            row.scenario_id,
            row.outcome,
            taxonomy_class,
            failure_kind,
            render_event_links(row),
            row.source_path,
            logs
        )
        .ok();
    }
    out
}

fn render_operational_readiness_markdown_summary(
    out: &mut String,
    report: &OperationalReadinessReport,
) {
    writeln!(out, "# FrankenFS Operational Readiness").ok();
    writeln!(out).ok();
    writeln!(out, "- Source root: `{}`", report.source_root).ok();
    writeln!(
        out,
        "- Sources: {} manifests, {} legacy summaries, {} ignored JSON files",
        report.source_manifest_count, report.source_legacy_summary_count, report.ignored_json_count
    )
    .ok();
    writeln!(out, "- Readiness events: {}", report.readiness_event_count).ok();
    writeln!(
        out,
        "- Readiness event envelope: version={} lanes={}",
        report.readiness_event_envelope_version,
        report.readiness_event_lane_ids.join(",")
    )
    .ok();
    writeln!(
        out,
        "- Correlation graph: event_nodes={} parent_edges={} orphan_parent_edges={} aggregate_events={}",
        report.correlation_graph_summary.event_nodes,
        report.correlation_graph_summary.parent_edges,
        report.correlation_graph_summary.orphan_parent_edges,
        report.correlation_graph_summary.aggregate_events
    )
    .ok();
    writeln!(
        out,
        "- Totals: pass={} fail={} skip={} error={} product_failures={} environment_blockers={}",
        report.totals.pass,
        report.totals.fail,
        report.totals.skip,
        report.totals.error,
        report.totals.product_failures,
        report.totals.environment_blockers
    )
    .ok();
    writeln!(
        out,
        "- Diagnostics: duplicate_scenarios={} stale_git_shas={} stale_artifacts={} invalid_timestamps={} missing_logs={}",
        report.duplicate_scenario_ids.len(),
        report.stale_git_shas.len(),
        report.stale_artifacts.len(),
        report.invalid_artifact_timestamps.len(),
        report.missing_log_paths.len()
    )
    .ok();
    writeln!(
        out,
        "- Contract: failed={} missing_workstreams={} violations={}",
        report.contract_failed,
        report.required_workstreams_missing.len(),
        report.contract_violations.len()
    )
    .ok();
}

impl ReportBuilder {
    fn ingest_manifest(
        &mut self,
        config: &OperationalReadinessReportConfig,
        recency_reference_epoch_days: Option<u32>,
        source_path: &Path,
        manifest: &ArtifactManifest,
    ) {
        self.source_manifest_count += 1;
        let source_path_text = display_path(source_path);
        let stale_git_sha = self.record_stale_git_sha(
            config,
            &source_path_text,
            &manifest.gate_id,
            &manifest.run_id,
            &manifest.git_context.commit,
        );
        let recency = self.record_artifact_recency(
            config,
            recency_reference_epoch_days,
            &source_path_text,
            &manifest.gate_id,
            &manifest.run_id,
            Some(&manifest.created_at),
        );
        let diagnostics = SourceDiagnostics {
            stale_git_sha,
            artifact_recency: recency,
        };
        self.record_manifest_run_logs(config, source_path, &source_path_text, manifest);
        self.readiness_event_count += manifest.readiness_events.len();
        self.record_readiness_event_graph(manifest);
        self.record_manifest_validation_errors(&source_path_text, manifest);
        let readiness_events = readiness_events_by_scenario(manifest);

        for (scenario_id, scenario) in &manifest.scenarios {
            let operational = manifest.operational_scenarios.get(scenario_id);
            let events = readiness_events
                .get(scenario_id.as_str())
                .map_or_else(Vec::new, Clone::clone);
            if let Some(record) = operational {
                self.record_scenario_log_paths(
                    config,
                    LogSource {
                        source_path,
                        source_path_text: &source_path_text,
                        scenario_id: Some(scenario_id),
                    },
                    manifest,
                    &record.stdout_path,
                    &record.stderr_path,
                );
                if events.is_empty() {
                    self.record_contract_violation(
                        &source_path_text,
                        Some(scenario_id),
                        format!("missing readiness event envelope for `{scenario_id}`"),
                        "bd-slp26:missing-readiness-event",
                    );
                }
            }
            self.push_row(build_manifest_row(
                &source_path_text,
                manifest,
                scenario_id,
                scenario,
                operational,
                &events,
                diagnostics,
            ));
        }

        if manifest.verdict == GateVerdict::Skip && manifest.scenarios.is_empty() {
            self.push_row(build_skipped_gate_row(
                source_path_text,
                manifest,
                diagnostics,
            ));
        }
    }

    fn ingest_legacy_summary(
        &mut self,
        config: &OperationalReadinessReportConfig,
        recency_reference_epoch_days: Option<u32>,
        source_path: &Path,
        summary: &LegacyE2eSummary,
    ) {
        self.source_legacy_summary_count += 1;
        let source_path_text = display_path(source_path);
        let stale_git_sha = self.record_stale_git_sha(
            config,
            &source_path_text,
            &summary.gate_id,
            &summary.run_id,
            &summary.git_context.commit,
        );
        let recency = self.record_artifact_recency(
            config,
            recency_reference_epoch_days,
            &source_path_text,
            &summary.gate_id,
            &summary.run_id,
            summary.created_at.as_deref(),
        );
        self.record_log_path(
            config,
            LogSource {
                source_path,
                source_path_text: &source_path_text,
                scenario_id: None,
            },
            "log_file",
            &summary.log_file,
            &BTreeSet::new(),
        );

        for scenario in &summary.scenarios {
            let outcome = outcome_from_legacy(&scenario.outcome, &summary.verdict);
            let artifact_refs = vec![summary.log_file.clone()];
            let environment_only_blocker =
                is_environment_only_blocker(None, None, scenario.detail.as_deref());
            let product_failure = is_product_failure(outcome, None, environment_only_blocker);
            let workstream =
                classify_workstream(&summary.gate_id, &scenario.scenario_id, &artifact_refs);
            let taxonomy_class = classify_taxonomy(&TaxonomyInput {
                outcome,
                error_class: None,
                skip_reason: None,
                workstream: &workstream,
                stale_git_sha,
                stale_artifact: recency.is_stale(),
                artifact_refs: &artifact_refs,
                detail: scenario.detail.as_deref(),
                remediation_hint: scenario.detail.as_deref(),
            });
            let row = ReadinessScenarioRow {
                source_path: source_path_text.clone(),
                source_kind: SourceKind::LegacyE2eSummary,
                gate_id: summary.gate_id.clone(),
                run_id: summary.run_id.clone(),
                workstream,
                scenario_id: scenario.scenario_id.clone(),
                outcome,
                taxonomy_class,
                failure_kind: if product_failure {
                    Some("product_failure".to_owned())
                } else if environment_only_blocker {
                    Some("environment_blocker".to_owned())
                } else {
                    None
                },
                skip_reason: None,
                environment_only_blocker,
                product_failure,
                git_commit: summary.git_context.commit.clone(),
                stale_git_sha,
                artifact_recency: recency.state(),
                artifact_age_days: recency.age_days,
                manifest_schema_version: None,
                host_fingerprint: Some(format!(
                    "legacy:{}:{}",
                    summary.git_context.branch, summary.git_context.clean
                )),
                stdout_path: Some(summary.log_file.clone()),
                stderr_path: None,
                artifact_refs,
                controlling_artifact: Some(summary.log_file.clone()),
                readiness_event_ids: Vec::new(),
                parent_correlation_ids: Vec::new(),
                event_artifact_ids: Vec::new(),
                event_severities: Vec::new(),
                reproduction_command: Some(format!("inspect legacy e2e log {}", summary.log_file)),
                cleanup_status: None,
                remediation_hint: scenario.detail.clone(),
                owner_bead: None,
                detail: scenario.detail.clone(),
            };
            self.push_row(row);
        }
    }

    fn finish(mut self, config: &OperationalReadinessReportConfig) -> OperationalReadinessReport {
        let duplicate_scenario_ids = self
            .seen_scenarios
            .iter()
            .filter(|(_, count)| **count > 1)
            .map(|(scenario_id, _)| scenario_id.clone())
            .collect();
        let required_workstreams_missing = REQUIRED_WORKSTREAMS
            .iter()
            .filter(|workstream| !self.workstreams.contains_key(**workstream))
            .map(|workstream| (*workstream).to_owned())
            .collect::<Vec<_>>();

        self.scenarios.sort_by(|left, right| {
            left.workstream
                .cmp(&right.workstream)
                .then_with(|| left.gate_id.cmp(&right.gate_id))
                .then_with(|| left.scenario_id.cmp(&right.scenario_id))
        });

        OperationalReadinessReport {
            schema_version: READINESS_REPORT_SCHEMA_VERSION,
            report_id: format!(
                "operational-readiness:{}:{}",
                display_path(&config.artifacts_dir),
                config.current_git_sha.as_deref().unwrap_or("unknown")
            ),
            source_root: display_path(&config.artifacts_dir),
            source_manifest_count: self.source_manifest_count,
            source_legacy_summary_count: self.source_legacy_summary_count,
            ignored_json_count: self.ignored_json_count,
            scenario_count: self.scenarios.len(),
            readiness_event_count: self.readiness_event_count,
            readiness_event_envelope_version: READINESS_EVENT_ENVELOPE_VERSION,
            readiness_event_lane_ids: self.readiness_event_lane_ids.into_iter().collect(),
            correlation_graph_summary: self.correlation_graph_summary,
            totals: self.totals,
            workstreams: self.workstreams,
            contract_failed: !required_workstreams_missing.is_empty()
                || !self.contract_violations.is_empty()
                || !self.missing_log_paths.is_empty()
                || !self.stale_git_shas.is_empty()
                || !self.stale_artifacts.is_empty()
                || !self.invalid_artifact_timestamps.is_empty(),
            required_workstreams_missing,
            contract_violations: self.contract_violations,
            duplicate_scenario_ids,
            stale_git_shas: self.stale_git_shas,
            stale_artifacts: self.stale_artifacts,
            invalid_artifact_timestamps: self.invalid_artifact_timestamps,
            missing_log_paths: self.missing_log_paths,
            scenarios: self.scenarios,
        }
    }

    fn push_row(&mut self, row: ReadinessScenarioRow) {
        self.seen_scenarios
            .entry(row.scenario_id.clone())
            .and_modify(|count| *count += 1)
            .or_insert(1);
        self.totals.record(&row);
        self.workstreams
            .entry(row.workstream.clone())
            .or_default()
            .record(&row);
        self.scenarios.push(row);
    }

    fn record_stale_git_sha(
        &mut self,
        config: &OperationalReadinessReportConfig,
        source_path: &str,
        gate_id: &str,
        run_id: &str,
        observed: &str,
    ) -> bool {
        let Some(expected) = config.current_git_sha.as_deref() else {
            return false;
        };
        if same_git_ref(observed, expected) {
            return false;
        }
        self.stale_git_shas.push(StaleGitSha {
            source_path: source_path.to_owned(),
            gate_id: gate_id.to_owned(),
            run_id: run_id.to_owned(),
            observed: observed.to_owned(),
            expected: expected.to_owned(),
        });
        true
    }

    fn record_artifact_recency(
        &mut self,
        config: &OperationalReadinessReportConfig,
        recency_reference_epoch_days: Option<u32>,
        source_path: &str,
        gate_id: &str,
        run_id: &str,
        created_at: Option<&str>,
    ) -> ArtifactRecency {
        let Some(max_age_days) = config.max_artifact_age_days else {
            return ArtifactRecency::not_checked();
        };
        let Some(reference_epoch_days) = recency_reference_epoch_days else {
            return ArtifactRecency::not_checked();
        };
        let Some(created_at) = created_at else {
            self.record_invalid_artifact_timestamp(
                source_path,
                gate_id,
                run_id,
                None,
                "missing created_at while --max-age-days is enforced",
            );
            return ArtifactRecency::not_checked();
        };
        let Some(created_epoch_days) = parse_manifest_timestamp_epoch_days(created_at) else {
            self.record_invalid_artifact_timestamp(
                source_path,
                gate_id,
                run_id,
                Some(created_at),
                "created_at is not a valid ISO 8601 timestamp",
            );
            return ArtifactRecency::not_checked();
        };

        if created_epoch_days > reference_epoch_days {
            self.record_invalid_artifact_timestamp(
                source_path,
                gate_id,
                run_id,
                Some(created_at),
                "created_at is after the recency reference timestamp",
            );
            return ArtifactRecency::not_checked();
        }

        let age_days = reference_epoch_days - created_epoch_days;
        if age_days <= max_age_days {
            return ArtifactRecency::fresh(age_days);
        }

        self.stale_artifacts.push(StaleArtifact {
            source_path: source_path.to_owned(),
            gate_id: gate_id.to_owned(),
            run_id: run_id.to_owned(),
            created_at: created_at.to_owned(),
            age_days,
            max_age_days,
        });
        ArtifactRecency::stale(age_days)
    }

    fn record_invalid_artifact_timestamp(
        &mut self,
        source_path: &str,
        gate_id: &str,
        run_id: &str,
        created_at: Option<&str>,
        reason: &str,
    ) {
        self.invalid_artifact_timestamps
            .push(InvalidArtifactTimestamp {
                source_path: source_path.to_owned(),
                gate_id: gate_id.to_owned(),
                run_id: run_id.to_owned(),
                created_at: created_at.map(str::to_owned),
                reason: reason.to_owned(),
            });
        self.record_contract_violation(
            source_path,
            None,
            format!("{reason} for `{gate_id}` run `{run_id}`"),
            "bd-7pw36:artifact-recency-timestamp",
        );
    }

    fn record_manifest_run_logs(
        &mut self,
        config: &OperationalReadinessReportConfig,
        source_path: &Path,
        source_path_text: &str,
        manifest: &ArtifactManifest,
    ) {
        if let Some(context) = &manifest.operational_context {
            let artifacts = artifact_path_set(manifest);
            self.record_log_path(
                config,
                LogSource {
                    source_path,
                    source_path_text,
                    scenario_id: None,
                },
                "operational_context.stdout_path",
                &context.stdout_path,
                &artifacts,
            );
            self.record_log_path(
                config,
                LogSource {
                    source_path,
                    source_path_text,
                    scenario_id: None,
                },
                "operational_context.stderr_path",
                &context.stderr_path,
                &artifacts,
            );
        }
    }

    fn record_readiness_event_graph(&mut self, manifest: &ArtifactManifest) {
        let event_ids = manifest
            .readiness_events
            .iter()
            .map(|event| event.event_id.as_str())
            .collect::<BTreeSet<_>>();

        for event in &manifest.readiness_events {
            if !event.lane_id.trim().is_empty() {
                self.readiness_event_lane_ids.insert(event.lane_id.clone());
            }
            self.correlation_graph_summary.event_nodes += 1;
            if event.aggregate_marker.is_some() {
                self.correlation_graph_summary.aggregate_events += 1;
            }
            if let Some(parent_id) = event.parent_correlation_id.as_deref() {
                self.correlation_graph_summary.parent_edges += 1;
                if parent_id != event.report_id && !event_ids.contains(parent_id) {
                    self.correlation_graph_summary.orphan_parent_edges += 1;
                }
            }
        }
    }

    fn record_manifest_validation_errors(
        &mut self,
        source_path_text: &str,
        manifest: &ArtifactManifest,
    ) {
        for error in validate_operational_manifest(manifest) {
            let scenario_id = validation_error_scenario_id(&error);
            self.record_contract_violation(
                source_path_text,
                scenario_id,
                format!("rejected manifest validation error: {error}"),
                "bd-slp26:manifest-validation",
            );
        }
    }

    fn record_scenario_log_paths(
        &mut self,
        config: &OperationalReadinessReportConfig,
        source: LogSource<'_>,
        manifest: &ArtifactManifest,
        stdout_path: &str,
        stderr_path: &str,
    ) {
        let artifacts = artifact_path_set(manifest);
        self.record_log_path(config, source, "stdout_path", stdout_path, &artifacts);
        self.record_log_path(config, source, "stderr_path", stderr_path, &artifacts);
    }

    fn record_log_path(
        &mut self,
        config: &OperationalReadinessReportConfig,
        source: LogSource<'_>,
        field: &str,
        path: &str,
        artifact_paths: &BTreeSet<String>,
    ) {
        if log_path_is_resolved(
            &config.artifacts_dir,
            source.source_path,
            path,
            artifact_paths,
        ) {
            return;
        }
        self.missing_log_paths.push(MissingLogPath {
            source_path: source.source_path_text.to_owned(),
            scenario_id: source.scenario_id.map(str::to_owned),
            field: field.to_owned(),
            path: path.to_owned(),
        });
        self.contract_violations.push(ReadinessContractViolation {
            source_path: source.source_path_text.to_owned(),
            scenario_id: source.scenario_id.map(str::to_owned),
            violation: format!("missing required log path `{field}`: {path}"),
            remediation_id: "bd-un9xt:missing-log-path".to_owned(),
        });
    }

    fn record_contract_violation(
        &mut self,
        source_path: &str,
        scenario_id: Option<&str>,
        violation: String,
        remediation_id: &str,
    ) {
        self.contract_violations.push(ReadinessContractViolation {
            source_path: source_path.to_owned(),
            scenario_id: scenario_id.map(str::to_owned),
            violation,
            remediation_id: remediation_id.to_owned(),
        });
    }
}

impl ReadinessCounts {
    fn record(&mut self, row: &ReadinessScenarioRow) {
        match row.outcome {
            ReadinessOutcome::Pass => self.pass += 1,
            ReadinessOutcome::Fail => self.fail += 1,
            ReadinessOutcome::Skip => self.skip += 1,
            ReadinessOutcome::Error => self.error += 1,
        }
        if row.product_failure {
            self.product_failures += 1;
        }
        if row.environment_only_blocker {
            self.environment_blockers += 1;
        }
    }
}

fn collect_json_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    collect_json_paths_inner(root, &mut paths)?;
    paths.sort();
    Ok(paths)
}

fn current_manifest_epoch_days() -> Option<u32> {
    let unix_epoch_days = parse_manifest_timestamp_epoch_days("1970-01-01T00:00:00Z")?;
    let elapsed_days = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() / 86_400;
    let total_days = u64::from(unix_epoch_days).checked_add(elapsed_days)?;
    u32::try_from(total_days).ok()
}

fn collect_json_paths_inner(root: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root).with_context(|| format!("failed to read {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_json_paths_inner(&path, paths)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            paths.push(path);
        }
    }
    Ok(())
}

fn artifact_path_set(manifest: &ArtifactManifest) -> BTreeSet<String> {
    manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect()
}

fn readiness_events_by_scenario(
    manifest: &ArtifactManifest,
) -> BTreeMap<&str, Vec<&ReadinessEventEnvelope>> {
    let mut events = BTreeMap::<&str, Vec<&ReadinessEventEnvelope>>::new();
    for event in &manifest.readiness_events {
        if let Some(scenario_id) = event.scenario_id.as_deref() {
            events.entry(scenario_id).or_default().push(event);
        }
    }
    events
}

fn validation_error_scenario_id(error: &ManifestValidationError) -> Option<&str> {
    match error {
        ManifestValidationError::MissingOperationalScenario(id)
        | ManifestValidationError::MissingCleanupStatus(id)
        | ManifestValidationError::MissingReadinessEvent(id) => Some(id),
        ManifestValidationError::OperationalScenarioIdMismatch { key, .. }
        | ManifestValidationError::MissingOperationalLogPath {
            scenario_id: key, ..
        }
        | ManifestValidationError::InvalidOperationalClassification {
            scenario_id: key, ..
        }
        | ManifestValidationError::UnknownArtifactRef {
            scenario_id: key, ..
        } => Some(key),
        ManifestValidationError::UnsupportedVersion(_)
        | ManifestValidationError::EmptyRunId
        | ManifestValidationError::EmptyGateId
        | ManifestValidationError::InvalidTimestamp(_)
        | ManifestValidationError::EmptyGitCommit
        | ManifestValidationError::InvalidScenarioId(_)
        | ManifestValidationError::EmptyArtifactPath
        | ManifestValidationError::MalformedArtifactPath(_)
        | ManifestValidationError::DuplicateScenarioId(_)
        | ManifestValidationError::ScenarioIdMismatch { .. }
        | ManifestValidationError::InconsistentVerdict
        | ManifestValidationError::MissingOperationalContext
        | ManifestValidationError::EmptyOperationalCommandLine
        | ManifestValidationError::EmptyOperationalHost
        | ManifestValidationError::FuseCapabilityNotChecked
        | ManifestValidationError::InvalidReadinessEvent { .. } => None,
    }
}

fn build_skipped_gate_row(
    source_path_text: String,
    manifest: &ArtifactManifest,
    diagnostics: SourceDiagnostics,
) -> ReadinessScenarioRow {
    ReadinessScenarioRow {
        source_path: source_path_text,
        source_kind: SourceKind::ArtifactManifest,
        gate_id: manifest.gate_id.clone(),
        run_id: manifest.run_id.clone(),
        workstream: classify_workstream(&manifest.gate_id, "gate_skipped", &[]),
        scenario_id: "gate_skipped".to_owned(),
        outcome: ReadinessOutcome::Skip,
        taxonomy_class: ReadinessTaxonomyClass::AuthoritativeLaneUnavailable,
        failure_kind: None,
        skip_reason: Some("gate_verdict_skip".to_owned()),
        environment_only_blocker: true,
        product_failure: false,
        git_commit: manifest.git_context.commit.clone(),
        stale_git_sha: diagnostics.stale_git_sha,
        artifact_recency: diagnostics.artifact_recency.state(),
        artifact_age_days: diagnostics.artifact_recency.age_days,
        manifest_schema_version: Some(manifest.schema_version),
        host_fingerprint: Some(manifest_host_fingerprint(manifest)),
        stdout_path: None,
        stderr_path: None,
        artifact_refs: Vec::new(),
        controlling_artifact: None,
        readiness_event_ids: Vec::new(),
        parent_correlation_ids: Vec::new(),
        event_artifact_ids: Vec::new(),
        event_severities: Vec::new(),
        reproduction_command: manifest
            .operational_context
            .as_ref()
            .map(|context| context.command_line.join(" ")),
        cleanup_status: None,
        remediation_hint: Some("inspect gate-level skip reason in source manifest".to_owned()),
        owner_bead: manifest.bead_id.clone(),
        detail: None,
    }
}

fn build_manifest_row(
    source_path_text: &str,
    manifest: &ArtifactManifest,
    scenario_id: &str,
    scenario: &ScenarioOutcome,
    operational: Option<&crate::artifact_manifest::OperationalScenarioRecord>,
    readiness_events: &[&ReadinessEventEnvelope],
    diagnostics: SourceDiagnostics,
) -> ReadinessScenarioRow {
    let artifact_refs = operational
        .map(|record| record.artifact_refs.clone())
        .unwrap_or_default();
    let workstream = classify_workstream(&manifest.gate_id, scenario_id, &artifact_refs);
    let outcome = operational.map_or_else(
        || outcome_from_scenario_result(scenario.outcome),
        |record| outcome_from_operational(record.classification, record.actual_outcome),
    );
    let error_class = operational.and_then(|record| record.error_class);
    let skip_reason = operational.and_then(|record| record.skip_reason);
    let detail = scenario.detail.clone();
    let environment_only_blocker =
        is_environment_only_blocker(error_class, skip_reason, detail.as_deref());
    let product_failure = is_product_failure(outcome, error_class, environment_only_blocker);
    let taxonomy_class = classify_taxonomy(&TaxonomyInput {
        outcome,
        error_class,
        skip_reason,
        workstream: &workstream,
        stale_git_sha: diagnostics.stale_git_sha,
        stale_artifact: diagnostics.artifact_recency.is_stale(),
        artifact_refs: &artifact_refs,
        detail: detail.as_deref(),
        remediation_hint: operational.and_then(|record| record.remediation_hint.as_deref()),
    });
    let reproduction_command = manifest
        .operational_context
        .as_ref()
        .map(|context| context.command_line.join(" "));
    let controlling_artifact = artifact_refs.first().cloned();
    let readiness_event_ids = readiness_events
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<Vec<_>>();
    let parent_correlation_ids = readiness_events
        .iter()
        .filter_map(|event| event.parent_correlation_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let event_artifact_ids = readiness_events
        .iter()
        .map(|event| event.artifact_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let event_severities = readiness_events
        .iter()
        .map(|event| serialized_enum_name(event.severity))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    ReadinessScenarioRow {
        source_path: source_path_text.to_owned(),
        source_kind: SourceKind::ArtifactManifest,
        gate_id: manifest.gate_id.clone(),
        run_id: manifest.run_id.clone(),
        workstream,
        scenario_id: scenario_id.to_owned(),
        outcome,
        taxonomy_class,
        failure_kind: error_class.map(serialized_enum_name),
        skip_reason: skip_reason.map(serialized_enum_name),
        environment_only_blocker,
        product_failure,
        git_commit: manifest.git_context.commit.clone(),
        stale_git_sha: diagnostics.stale_git_sha,
        artifact_recency: diagnostics.artifact_recency.state(),
        artifact_age_days: diagnostics.artifact_recency.age_days,
        manifest_schema_version: Some(manifest.schema_version),
        host_fingerprint: Some(manifest_host_fingerprint(manifest)),
        stdout_path: operational.map(|record| record.stdout_path.clone()),
        stderr_path: operational.map(|record| record.stderr_path.clone()),
        artifact_refs,
        controlling_artifact,
        readiness_event_ids,
        parent_correlation_ids,
        event_artifact_ids,
        event_severities,
        reproduction_command,
        cleanup_status: operational.map(|record| serialized_enum_name(record.cleanup_status)),
        remediation_hint: operational.and_then(|record| record.remediation_hint.clone()),
        owner_bead: manifest.bead_id.clone(),
        detail,
    }
}

fn manifest_host_fingerprint(manifest: &ArtifactManifest) -> String {
    format!(
        "{}|{}|{}cpu|{}GiB|{}",
        manifest.environment.hostname,
        manifest.environment.cpu_model,
        manifest.environment.cpu_count,
        manifest.environment.memory_gib,
        manifest.environment.kernel
    )
}

fn log_path_is_resolved(
    root: &Path,
    source_path: &Path,
    log_path: &str,
    artifact_paths: &BTreeSet<String>,
) -> bool {
    if log_path.trim().is_empty() {
        return false;
    }
    if artifact_paths.contains(log_path) {
        return true;
    }

    let path = Path::new(log_path);
    if path.is_absolute() {
        return path.exists();
    }
    if root.join(path).exists() {
        return true;
    }
    source_path
        .parent()
        .is_some_and(|parent| parent.join(path).exists())
}

fn outcome_from_operational(
    classification: OperationalOutcomeClass,
    actual_outcome: ScenarioResult,
) -> ReadinessOutcome {
    match classification {
        OperationalOutcomeClass::Pass => ReadinessOutcome::Pass,
        OperationalOutcomeClass::Fail => ReadinessOutcome::Fail,
        OperationalOutcomeClass::Skip => ReadinessOutcome::Skip,
        OperationalOutcomeClass::Error => ReadinessOutcome::Error,
    }
    .max_by_actual_outcome(actual_outcome)
}

fn outcome_from_scenario_result(result: ScenarioResult) -> ReadinessOutcome {
    match result {
        ScenarioResult::Pass => ReadinessOutcome::Pass,
        ScenarioResult::Fail => ReadinessOutcome::Fail,
        ScenarioResult::Skip => ReadinessOutcome::Skip,
    }
}

fn outcome_from_legacy(raw_outcome: &str, raw_verdict: &str) -> ReadinessOutcome {
    match raw_outcome.to_ascii_uppercase().as_str() {
        "PASS" => ReadinessOutcome::Pass,
        "SKIP" => ReadinessOutcome::Skip,
        "FAIL" => {
            if raw_verdict.eq_ignore_ascii_case("ERROR") {
                ReadinessOutcome::Error
            } else {
                ReadinessOutcome::Fail
            }
        }
        _ => ReadinessOutcome::Error,
    }
}

trait OutcomeConsistency {
    fn max_by_actual_outcome(self, actual_outcome: ScenarioResult) -> Self;
}

impl OutcomeConsistency for ReadinessOutcome {
    fn max_by_actual_outcome(self, actual_outcome: ScenarioResult) -> Self {
        match (self, actual_outcome) {
            (Self::Pass, ScenarioResult::Fail) => Self::Fail,
            (Self::Pass, ScenarioResult::Skip) => Self::Skip,
            (outcome, _) => outcome,
        }
    }
}

fn classify_workstream(gate_id: &str, scenario_id: &str, artifact_refs: &[String]) -> String {
    let mut haystack = gate_id.to_ascii_lowercase();
    haystack.push(' ');
    haystack.push_str(&scenario_id.to_ascii_lowercase());
    for artifact in artifact_refs {
        haystack.push(' ');
        haystack.push_str(&artifact.to_ascii_lowercase());
    }

    if haystack.contains("release") && haystack.contains("gate") {
        "release_gate".to_owned()
    } else if haystack.contains("proof") || haystack.contains("bundle") {
        "proof_bundle".to_owned()
    } else if haystack.contains("xfstest") {
        "xfstests".to_owned()
    } else if haystack.contains("writeback") {
        "writeback_cache".to_owned()
    } else if haystack.contains("mounted") || haystack.contains("mount_matrix") {
        "mounted_scenario_matrix".to_owned()
    } else if haystack.contains("fuse") {
        "fuse_lane".to_owned()
    } else if haystack.contains("fuzz") {
        "fuzz_smoke".to_owned()
    } else if haystack.contains("repair") {
        "repair_policy".to_owned()
    } else if haystack.contains("perf") || haystack.contains("bench") {
        "performance".to_owned()
    } else {
        "other".to_owned()
    }
}

fn classify_taxonomy(input: &TaxonomyInput<'_>) -> ReadinessTaxonomyClass {
    let detail = input.detail.unwrap_or("").to_ascii_lowercase();
    let remediation_hint = input.remediation_hint.unwrap_or("").to_ascii_lowercase();
    let text = format!("{detail} {remediation_hint}");

    if input.stale_git_sha
        || input.stale_artifact
        || matches!(
            input.error_class,
            Some(OperationalErrorClass::StaleTrackerToolingFailure)
        )
    {
        return ReadinessTaxonomyClass::StaleArtifact;
    }
    if input.artifact_refs.is_empty() {
        return ReadinessTaxonomyClass::MissingArtifact;
    }
    if text.contains("security") || text.contains("refusal") && text.contains("hostile") {
        return ReadinessTaxonomyClass::SecurityRefusal;
    }
    if text.contains("unsafe repair") || text.contains("unsafe_repair") {
        return ReadinessTaxonomyClass::UnsafeRepairRefusal;
    }
    if matches!(
        input.error_class,
        Some(
            OperationalErrorClass::WorkerDependencyMissing
                | OperationalErrorClass::FusePermissionSkip
                | OperationalErrorClass::RootOwnedBtrfsTestdirEacces
                | OperationalErrorClass::HostEnvironmentFailure
        )
    ) || matches!(
        input.skip_reason,
        Some(
            SkipReason::FuseUnavailable
                | SkipReason::FusePermissionDenied
                | SkipReason::WorkerDependencyMissing
                | SkipReason::RootOwnedBtrfsTestdirEacces
        )
    ) {
        return if text.contains("authoritative") || text.contains("required lane") {
            ReadinessTaxonomyClass::AuthoritativeLaneUnavailable
        } else {
            ReadinessTaxonomyClass::HostCapabilitySkip
        };
    }
    if matches!(
        input.error_class,
        Some(OperationalErrorClass::UnsupportedV1Scope)
    ) || matches!(input.skip_reason, Some(SkipReason::UnsupportedV1Scope))
    {
        return ReadinessTaxonomyClass::UnsupportedByScope;
    }
    if matches!(
        input.error_class,
        Some(OperationalErrorClass::HarnessBug | OperationalErrorClass::UnsafeCleanupFailure)
    ) {
        return ReadinessTaxonomyClass::HarnessFailure;
    }
    if matches!(
        input.error_class,
        Some(OperationalErrorClass::ResourceLimit)
    ) && input.workstream == "performance"
    {
        return ReadinessTaxonomyClass::NoisyMeasurement;
    }
    if matches!(
        input.error_class,
        Some(OperationalErrorClass::ProductFailure)
    ) {
        return ReadinessTaxonomyClass::ProductFailure;
    }
    if matches!(input.outcome, ReadinessOutcome::Pass)
        && (text.contains("experimental") || text.contains("caveat"))
    {
        return ReadinessTaxonomyClass::PassWithExperimentalCaveat;
    }
    match input.outcome {
        ReadinessOutcome::Pass => ReadinessTaxonomyClass::Pass,
        ReadinessOutcome::Fail => ReadinessTaxonomyClass::ProductFailure,
        ReadinessOutcome::Skip => ReadinessTaxonomyClass::HostCapabilitySkip,
        ReadinessOutcome::Error => ReadinessTaxonomyClass::HarnessFailure,
    }
}

fn is_environment_only_blocker(
    error_class: Option<OperationalErrorClass>,
    skip_reason: Option<SkipReason>,
    detail: Option<&str>,
) -> bool {
    if matches!(
        error_class,
        Some(
            OperationalErrorClass::WorkerDependencyMissing
                | OperationalErrorClass::FusePermissionSkip
                | OperationalErrorClass::RootOwnedBtrfsTestdirEacces
                | OperationalErrorClass::HostEnvironmentFailure
                | OperationalErrorClass::ResourceLimit
        )
    ) {
        return true;
    }
    if matches!(
        skip_reason,
        Some(
            SkipReason::FuseUnavailable
                | SkipReason::FusePermissionDenied
                | SkipReason::UserDisabled
                | SkipReason::WorkerDependencyMissing
                | SkipReason::RootOwnedBtrfsTestdirEacces
        )
    ) {
        return true;
    }

    let Some(detail) = detail else {
        return false;
    };
    let detail = detail.to_ascii_lowercase();
    detail.contains("fuse")
        || detail.contains("permission")
        || detail.contains("worker")
        || detail.contains("dependency")
        || detail.contains("environment")
}

fn is_product_failure(
    outcome: ReadinessOutcome,
    error_class: Option<OperationalErrorClass>,
    environment_only_blocker: bool,
) -> bool {
    if matches!(error_class, Some(OperationalErrorClass::ProductFailure)) {
        return true;
    }
    if error_class.is_some() {
        return false;
    }
    matches!(outcome, ReadinessOutcome::Fail) && !environment_only_blocker
}

fn serialized_enum_name<T>(value: T) -> String
where
    T: Serialize + std::fmt::Debug,
{
    serde_json::to_value(&value)
        .ok()
        .and_then(|json| json.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{value:?}"))
}

fn same_git_ref(observed: &str, expected: &str) -> bool {
    let observed = observed.trim();
    let expected = expected.trim();
    let observed_matches_expected = observed.starts_with(expected);
    let expected_matches_observed = expected.starts_with(observed);
    !observed.is_empty()
        && !expected.is_empty()
        && (observed_matches_expected || expected_matches_observed)
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

fn render_log_links(row: &ReadinessScenarioRow) -> String {
    let mut links = Vec::new();
    if let Some(path) = &row.stdout_path {
        links.push(format!("stdout `{path}`"));
    }
    if let Some(path) = &row.stderr_path {
        links.push(format!("stderr `{path}`"));
    }
    for artifact in &row.artifact_refs {
        links.push(format!("artifact `{artifact}`"));
    }
    links.join("<br>")
}

fn render_event_links(row: &ReadinessScenarioRow) -> String {
    let mut links = Vec::new();
    for event_id in &row.readiness_event_ids {
        links.push(format!("event `{event_id}`"));
    }
    for parent_id in &row.parent_correlation_ids {
        links.push(format!("parent `{parent_id}`"));
    }
    for artifact_id in &row.event_artifact_ids {
        links.push(format!("artifact `{artifact_id}`"));
    }
    links.join("<br>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_manifest::{
        ArtifactCategory, ArtifactEntry, CleanupStatus, EnvironmentFingerprint,
        FuseCapabilityResult, GitContext, OperationalRunContext, OperationalScenarioRecord,
        ReadinessEventEnvelope, ReadinessEventSeverity, WorkerContext,
    };
    use tempfile::TempDir;

    fn stale_git_sha(report: &OperationalReadinessReport, index: usize) -> Result<&StaleGitSha> {
        report
            .stale_git_shas
            .get(index)
            .with_context(|| format!("expected stale git sha at index {index}"))
    }

    fn operational_scenario_mut<'a>(
        manifest: &'a mut ArtifactManifest,
        scenario_id: &str,
    ) -> Result<&'a mut OperationalScenarioRecord> {
        manifest
            .operational_scenarios
            .get_mut(scenario_id)
            .with_context(|| format!("expected operational scenario `{scenario_id}`"))
    }

    fn readiness_event_mut<'a>(
        manifest: &'a mut ArtifactManifest,
        scenario_id: &str,
    ) -> Result<&'a mut ReadinessEventEnvelope> {
        manifest
            .readiness_events
            .iter_mut()
            .find(|event| event.scenario_id.as_deref() == Some(scenario_id))
            .with_context(|| format!("expected readiness event for `{scenario_id}`"))
    }

    fn normalize_report_source_paths(report: &mut OperationalReadinessReport, fixture_root: &str) {
        report.report_id = report.report_id.replace(fixture_root, "$FIXTURE");
        report.source_root = "$FIXTURE".to_owned();
        for row in &mut report.scenarios {
            row.source_path = row.source_path.replace(fixture_root, "$FIXTURE");
        }
        for stale in &mut report.stale_artifacts {
            stale.source_path = stale.source_path.replace(fixture_root, "$FIXTURE");
        }
        for invalid in &mut report.invalid_artifact_timestamps {
            invalid.source_path = invalid.source_path.replace(fixture_root, "$FIXTURE");
        }
    }

    #[test]
    fn aggregates_mixed_operational_manifest_outcomes() -> Result<()> {
        let fixture = ReadinessFixture::new()?;
        let manifest = sample_operational_manifest("abc123");
        fixture.write_manifest("operational.json", &manifest)?;

        let report = fixture.report(Some("abc123"))?;

        assert_eq!(report.source_manifest_count, 1);
        assert_eq!(report.scenario_count, 9);
        assert_eq!(report.readiness_event_count, 9);
        assert_eq!(
            report.readiness_event_envelope_version,
            crate::artifact_manifest::READINESS_EVENT_ENVELOPE_VERSION
        );
        assert_eq!(report.correlation_graph_summary.event_nodes, 9);
        assert_eq!(report.correlation_graph_summary.parent_edges, 9);
        assert_eq!(report.correlation_graph_summary.orphan_parent_edges, 0);
        assert_eq!(report.totals.pass, 2);
        assert_eq!(report.totals.fail, 3);
        assert_eq!(report.totals.skip, 2);
        assert_eq!(report.totals.error, 2);
        assert_eq!(report.totals.product_failures, 2);
        assert_eq!(report.totals.environment_blockers, 3);
        assert!(!report.contract_failed);
        assert_eq!(report.required_workstreams_missing, [] as [String; 0]);
        assert!(report.workstreams.contains_key("xfstests"));
        assert!(report.workstreams.contains_key("fuse_lane"));
        assert!(report.workstreams.contains_key("mounted_scenario_matrix"));
        assert!(report.workstreams.contains_key("repair_policy"));
        assert!(report.workstreams.contains_key("writeback_cache"));
        assert!(report.workstreams.contains_key("fuzz_smoke"));
        assert!(report.workstreams.contains_key("performance"));
        assert!(report.workstreams.contains_key("proof_bundle"));
        assert!(report.workstreams.contains_key("release_gate"));
        assert!(
            report
                .readiness_event_lane_ids
                .contains(&"xfstests".to_owned())
        );
        assert!(
            report
                .readiness_event_lane_ids
                .contains(&"release_gate".to_owned())
        );
        assert!(report.scenarios.iter().any(|row| {
            row.scenario_id == "proof_bundle_stale"
                && row.taxonomy_class == ReadinessTaxonomyClass::StaleArtifact
        }));
        assert!(report.scenarios.iter().any(|row| {
            row.scenario_id == "release_gate_unsupported"
                && row.taxonomy_class == ReadinessTaxonomyClass::UnsupportedByScope
        }));
        assert!(report.scenarios.iter().any(|row| {
            row.scenario_id == "mounted_ext4_rw"
                && row.readiness_event_ids == vec!["event_mounted_ext4_rw"]
                && row.parent_correlation_ids == vec!["report_run-operational"]
                && row.event_artifact_ids == vec!["mounted/ext4_rw.json"]
        }));
        Ok(())
    }

    #[test]
    fn detects_duplicate_scenario_ids_and_stale_git_shas() -> Result<()> {
        let fixture = ReadinessFixture::new()?;
        let first = sample_legacy_summary("oldsha", "shared_scenario");
        let second = sample_legacy_summary("newsha", "shared_scenario");
        fixture.write_legacy("first.json", &first)?;
        fixture.write_legacy("second.json", &second)?;

        let report = fixture.report(Some("newsha"))?;

        assert_eq!(report.source_legacy_summary_count, 2);
        assert_eq!(report.duplicate_scenario_ids, vec!["shared_scenario"]);
        assert_eq!(report.stale_git_shas.len(), 1);
        assert_eq!(stale_git_sha(&report, 0)?.observed, "oldsha");
        Ok(())
    }

    #[test]
    fn max_age_flags_manifest_and_legacy_summary_staleness() -> Result<()> {
        let fixture = ReadinessFixture::new()?;
        let mut manifest = sample_operational_manifest("abc123");
        manifest.created_at = "2026-05-01T00:00:00Z".to_owned();
        let mut legacy = sample_legacy_summary("abc123", "legacy_fuse_capability");
        legacy.created_at = Some("2026-05-01T12:00:00Z".to_owned());
        fixture.write_manifest("manifest.json", &manifest)?;
        fixture.write_legacy("legacy_result.json", &legacy)?;
        fs::write(fixture.dir.path().join("run.log"), "legacy log")
            .context("write legacy run log")?;

        let mut report = fixture.report_with_recency(Some("abc123"), 3, "2026-05-06T00:00:00Z")?;

        assert!(report.contract_failed);
        assert_eq!(report.stale_artifacts.len(), 2);
        assert_eq!(
            report.invalid_artifact_timestamps,
            [] as [InvalidArtifactTimestamp; 0]
        );
        assert!(
            report
                .stale_artifacts
                .iter()
                .any(|stale| stale.gate_id == "operational_readiness"
                    && stale.age_days == 5
                    && stale.max_age_days == 3)
        );
        assert!(report.scenarios.iter().any(|row| {
            row.gate_id == "operational_readiness"
                && row.artifact_recency == ArtifactRecencyState::Stale
                && row.artifact_age_days == Some(5)
                && row.taxonomy_class == ReadinessTaxonomyClass::StaleArtifact
        }));
        assert!(report.scenarios.iter().any(|row| {
            row.gate_id == "legacy_fuse_gate"
                && row.artifact_recency == ArtifactRecencyState::Stale
                && row.artifact_age_days == Some(5)
                && row.taxonomy_class == ReadinessTaxonomyClass::StaleArtifact
        }));
        let fixture_root = fixture.dir.path().display().to_string();
        normalize_report_source_paths(&mut report, &fixture_root);
        let markdown = render_operational_readiness_markdown(&report);
        assert!(markdown.contains("## Stale Artifacts"));
        assert!(markdown.contains("age=5d max=3d"));
        insta::assert_snapshot!(
            "render_operational_readiness_markdown_stale_recency",
            markdown
        );
        Ok(())
    }

    #[test]
    fn max_age_requires_parseable_timestamps() -> Result<()> {
        let fixture = ReadinessFixture::new()?;
        let mut manifest = sample_operational_manifest("abc123");
        manifest.created_at = "not-a-timestamp".to_owned();
        let mut legacy = sample_legacy_summary("abc123", "legacy_missing_timestamp");
        legacy.created_at = None;
        fixture.write_manifest("manifest.json", &manifest)?;
        fixture.write_legacy("legacy_result.json", &legacy)?;
        fs::write(fixture.dir.path().join("run.log"), "legacy log")
            .context("write legacy run log")?;

        let report = fixture.report_with_recency(Some("abc123"), 3, "2026-05-06T00:00:00Z")?;

        assert!(report.contract_failed);
        assert_eq!(report.stale_artifacts, [] as [StaleArtifact; 0]);
        assert_eq!(report.invalid_artifact_timestamps.len(), 2);
        assert!(report.invalid_artifact_timestamps.iter().any(|invalid| {
            invalid.gate_id == "operational_readiness"
                && invalid.created_at.as_deref() == Some("not-a-timestamp")
        }));
        assert!(report.invalid_artifact_timestamps.iter().any(|invalid| {
            invalid.gate_id == "legacy_fuse_gate" && invalid.created_at.is_none()
        }));
        assert!(report.contract_violations.iter().any(|violation| {
            violation.remediation_id == "bd-7pw36:artifact-recency-timestamp"
                && violation.violation.contains("created_at")
        }));
        Ok(())
    }

    #[test]
    fn max_age_rejects_future_dated_artifacts() -> Result<()> {
        let fixture = ReadinessFixture::new()?;
        let mut manifest = sample_operational_manifest("abc123");
        manifest.created_at = "2026-05-08T00:00:00Z".to_owned();
        let mut legacy = sample_legacy_summary("abc123", "legacy_future_timestamp");
        legacy.created_at = Some("2026-05-09T00:00:00Z".to_owned());
        fixture.write_manifest("manifest.json", &manifest)?;
        fixture.write_legacy("legacy_result.json", &legacy)?;
        fs::write(fixture.dir.path().join("run.log"), "legacy log")
            .context("write legacy run log")?;

        let mut report = fixture.report_with_recency(Some("abc123"), 3, "2026-05-06T00:00:00Z")?;

        assert!(report.contract_failed);
        assert_eq!(report.stale_artifacts, [] as [StaleArtifact; 0]);
        assert_eq!(report.invalid_artifact_timestamps.len(), 2);
        assert!(report.invalid_artifact_timestamps.iter().any(|invalid| {
            invalid.gate_id == "operational_readiness"
                && invalid.created_at.as_deref() == Some("2026-05-08T00:00:00Z")
                && invalid.reason.contains("after the recency reference")
        }));
        assert!(report.invalid_artifact_timestamps.iter().any(|invalid| {
            invalid.gate_id == "legacy_fuse_gate"
                && invalid.created_at.as_deref() == Some("2026-05-09T00:00:00Z")
                && invalid.reason.contains("after the recency reference")
        }));
        assert!(report.scenarios.iter().any(|row| {
            row.gate_id == "operational_readiness"
                && row.artifact_recency == ArtifactRecencyState::NotChecked
                && row.artifact_age_days.is_none()
        }));
        assert!(report.scenarios.iter().any(|row| {
            row.gate_id == "legacy_fuse_gate"
                && row.artifact_recency == ArtifactRecencyState::NotChecked
                && row.artifact_age_days.is_none()
        }));
        assert!(report.contract_violations.iter().any(|violation| {
            violation.remediation_id == "bd-7pw36:artifact-recency-timestamp"
                && violation.violation.contains("after the recency reference")
        }));
        let fixture_root = fixture.dir.path().display().to_string();
        normalize_report_source_paths(&mut report, &fixture_root);
        let markdown = render_operational_readiness_markdown(&report);
        assert!(markdown.contains("## Invalid Artifact Timestamps"));
        assert!(markdown.contains("after the recency reference"));
        insta::assert_snapshot!(
            "render_operational_readiness_markdown_future_timestamp_refusal",
            markdown
        );
        Ok(())
    }

    #[test]
    fn reports_missing_log_paths_without_failing_aggregation() -> Result<()> {
        let fixture = ReadinessFixture::new()?;
        let mut manifest = sample_operational_manifest("abc123");
        operational_scenario_mut(&mut manifest, "mounted_ext4_rw")?.stdout_path =
            "missing/stdout.log".to_owned();
        fixture.write_manifest("manifest.json", &manifest)?;

        let report = fixture.report(Some("abc123"))?;

        assert!(report.missing_log_paths.iter().any(|missing| {
            missing.scenario_id.as_deref() == Some("mounted_ext4_rw")
                && missing.field == "stdout_path"
        }));
        assert!(report.contract_failed);
        assert!(report.contract_violations.iter().any(|violation| {
            violation.scenario_id.as_deref() == Some("mounted_ext4_rw")
                && violation.violation.contains("missing required log path")
        }));
        Ok(())
    }

    #[test]
    fn markdown_preserves_links_and_counts() -> Result<()> {
        let fixture = ReadinessFixture::new()?;
        let manifest = sample_operational_manifest("abc123");
        fixture.write_manifest("operational.json", &manifest)?;

        let report = fixture.report(Some("abc123"))?;
        let markdown = render_operational_readiness_markdown(&report);

        assert!(markdown.contains("Totals: pass=2 fail=3 skip=2 error=2"));
        assert!(markdown.contains("`mounted_ext4_rw`"));
        assert!(markdown.contains("artifact `mounted/ext4_rw.json`"));
        assert!(markdown.contains("Readiness events: 9"));
        assert!(markdown.contains("Readiness event envelope: version=1"));
        assert!(markdown.contains("Correlation graph: event_nodes=9 parent_edges=9"));
        assert!(markdown.contains("event `event_mounted_ext4_rw`"));
        assert!(markdown.contains("Contract: failed=false missing_workstreams=0 violations=0"));
        Ok(())
    }

    #[test]
    fn render_operational_readiness_markdown_mixed_manifest_snapshot() -> Result<()> {
        let fixture = ReadinessFixture::new()?;
        let manifest = sample_operational_manifest("abc123");
        fixture.write_manifest("operational.json", &manifest)?;

        let mut report = fixture.report(Some("abc123"))?;
        let fixture_root = fixture.dir.path().display().to_string();
        normalize_report_source_paths(&mut report, &fixture_root);
        let markdown = render_operational_readiness_markdown(&report);

        assert!(markdown.contains("# FrankenFS Operational Readiness"));
        assert!(markdown.contains("## Workstreams"));
        assert!(markdown.contains("## Scenarios"));
        insta::assert_snapshot!(
            "render_operational_readiness_markdown_mixed_manifest",
            markdown
        );
        Ok(())
    }

    #[test]
    fn operational_readiness_report_json_shape() -> Result<()> {
        let fixture = ReadinessFixture::new()?;
        let manifest = sample_operational_manifest("abc123");
        fixture.write_manifest("operational.json", &manifest)?;

        let mut report = fixture.report(Some("abc123"))?;
        let fixture_root = fixture.dir.path().display().to_string();
        normalize_report_source_paths(&mut report, &fixture_root);

        let json = serde_json::to_string_pretty(&report)?;
        let parsed: OperationalReadinessReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);

        let scenario_shape = report
            .scenarios
            .iter()
            .map(|row| {
                serde_json::json!({
                    "workstream": row.workstream,
                    "scenario_id": row.scenario_id,
                    "outcome": row.outcome,
                    "taxonomy_class": row.taxonomy_class,
                    "environment_only_blocker": row.environment_only_blocker,
                    "product_failure": row.product_failure,
                    "readiness_event_ids": row.readiness_event_ids,
                    "event_severities": row.event_severities,
                    "owner_bead": row.owner_bead,
                })
            })
            .collect::<Vec<_>>();
        let shape = serde_json::json!({
            "schema_version": report.schema_version,
            "report_id": report.report_id,
            "source_root": report.source_root,
            "source_manifest_count": report.source_manifest_count,
            "source_legacy_summary_count": report.source_legacy_summary_count,
            "ignored_json_count": report.ignored_json_count,
            "scenario_count": report.scenario_count,
            "readiness_event_count": report.readiness_event_count,
            "readiness_event_envelope_version": report.readiness_event_envelope_version,
            "readiness_event_lane_ids": report.readiness_event_lane_ids,
            "correlation_graph_summary": report.correlation_graph_summary,
            "totals": report.totals,
            "workstreams": report.workstreams,
            "required_workstreams_missing": report.required_workstreams_missing,
            "contract_failed": report.contract_failed,
            "contract_violation_count": report.contract_violations.len(),
            "duplicate_scenario_ids": report.duplicate_scenario_ids,
            "stale_git_sha_count": report.stale_git_shas.len(),
            "stale_artifact_count": report.stale_artifacts.len(),
            "invalid_artifact_timestamp_count": report.invalid_artifact_timestamps.len(),
            "missing_log_path_count": report.missing_log_paths.len(),
            "scenarios": scenario_shape,
        });
        insta::assert_snapshot!(
            "operational_readiness_report_json_shape",
            serde_json::to_string_pretty(&shape)?
        );
        Ok(())
    }

    #[test]
    fn missing_readiness_event_fails_report_contract() -> Result<()> {
        let fixture = ReadinessFixture::new()?;
        let mut manifest = sample_operational_manifest("abc123");
        manifest
            .readiness_events
            .retain(|event| event.scenario_id.as_deref() != Some("mounted_ext4_rw"));
        fixture.write_manifest("operational.json", &manifest)?;

        let report = fixture.report(Some("abc123"))?;

        assert!(report.contract_failed);
        assert!(report.contract_violations.iter().any(|violation| {
            violation.scenario_id.as_deref() == Some("mounted_ext4_rw")
                && violation.remediation_id == "bd-slp26:missing-readiness-event"
        }));
        Ok(())
    }

    #[test]
    fn invalid_readiness_event_fails_report_contract() -> Result<()> {
        let fixture = ReadinessFixture::new()?;
        let mut manifest = sample_operational_manifest("abc123");
        let event = readiness_event_mut(&mut manifest, "mounted_ext4_rw")?;
        event.raw_log_refs.clear();
        event.parent_correlation_id = Some("missing-parent-event".to_owned());
        fixture.write_manifest("operational.json", &manifest)?;

        let report = fixture.report(Some("abc123"))?;

        assert!(report.contract_failed);
        assert_eq!(report.correlation_graph_summary.orphan_parent_edges, 1);
        assert!(report.contract_violations.iter().any(|violation| {
            violation.remediation_id == "bd-slp26:manifest-validation"
                && violation.violation.contains("raw_log_refs")
        }));
        assert!(report.contract_violations.iter().any(|violation| {
            violation.remediation_id == "bd-slp26:manifest-validation"
                && violation.violation.contains("parent_correlation_id")
        }));
        Ok(())
    }

    #[test]
    fn taxonomy_covers_actionable_failure_contract_values() {
        for case in taxonomy_primary_cases()
            .into_iter()
            .chain(taxonomy_secondary_cases())
        {
            let artifact_refs = case
                .artifact_refs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            assert_eq!(
                classify_taxonomy(&TaxonomyInput {
                    outcome: case.outcome,
                    error_class: case.error_class,
                    skip_reason: case.skip_reason,
                    workstream: case.workstream,
                    stale_git_sha: case.stale_git_sha,
                    stale_artifact: false,
                    artifact_refs: &artifact_refs,
                    detail: Some(case.detail),
                    remediation_hint: Some(case.remediation_hint),
                }),
                case.expected
            );
        }
    }

    #[derive(Clone, Copy)]
    struct TaxonomyCase {
        expected: ReadinessTaxonomyClass,
        outcome: ReadinessOutcome,
        error_class: Option<OperationalErrorClass>,
        skip_reason: Option<SkipReason>,
        workstream: &'static str,
        stale_git_sha: bool,
        artifact_refs: &'static [&'static str],
        detail: &'static str,
        remediation_hint: &'static str,
    }

    fn taxonomy_primary_cases() -> [TaxonomyCase; 6] {
        [
            TaxonomyCase {
                expected: ReadinessTaxonomyClass::ProductFailure,
                outcome: ReadinessOutcome::Fail,
                error_class: Some(OperationalErrorClass::ProductFailure),
                skip_reason: None,
                workstream: "repair_policy",
                stale_git_sha: false,
                artifact_refs: &["repair/policy.json"],
                detail: "",
                remediation_hint: "open repair policy bead",
            },
            TaxonomyCase {
                expected: ReadinessTaxonomyClass::HostCapabilitySkip,
                outcome: ReadinessOutcome::Skip,
                error_class: Some(OperationalErrorClass::FusePermissionSkip),
                skip_reason: Some(SkipReason::FusePermissionDenied),
                workstream: "fuse_lane",
                stale_git_sha: false,
                artifact_refs: &["fuse/capability.json"],
                detail: "",
                remediation_hint: "rerun with /dev/fuse access",
            },
            TaxonomyCase {
                expected: ReadinessTaxonomyClass::AuthoritativeLaneUnavailable,
                outcome: ReadinessOutcome::Skip,
                error_class: Some(OperationalErrorClass::HostEnvironmentFailure),
                skip_reason: Some(SkipReason::WorkerDependencyMissing),
                workstream: "mounted_scenario_matrix",
                stale_git_sha: false,
                artifact_refs: &["mounted/capability.json"],
                detail: "authoritative required lane unavailable",
                remediation_hint: "rerun on permissioned worker",
            },
            TaxonomyCase {
                expected: ReadinessTaxonomyClass::HarnessFailure,
                outcome: ReadinessOutcome::Error,
                error_class: Some(OperationalErrorClass::HarnessBug),
                skip_reason: None,
                workstream: "xfstests",
                stale_git_sha: false,
                artifact_refs: &["xfstests/raw.log"],
                detail: "",
                remediation_hint: "fix harness parser",
            },
            TaxonomyCase {
                expected: ReadinessTaxonomyClass::UnsupportedByScope,
                outcome: ReadinessOutcome::Skip,
                error_class: Some(OperationalErrorClass::UnsupportedV1Scope),
                skip_reason: Some(SkipReason::UnsupportedV1Scope),
                workstream: "release_gate",
                stale_git_sha: false,
                artifact_refs: &["release/unsupported.json"],
                detail: "",
                remediation_hint: "explicit V1 non-goal",
            },
            TaxonomyCase {
                expected: ReadinessTaxonomyClass::StaleArtifact,
                outcome: ReadinessOutcome::Fail,
                error_class: Some(OperationalErrorClass::StaleTrackerToolingFailure),
                skip_reason: None,
                workstream: "proof_bundle",
                stale_git_sha: false,
                artifact_refs: &["proof/stale.json"],
                detail: "",
                remediation_hint: "refresh proof bundle",
            },
        ]
    }

    fn taxonomy_secondary_cases() -> [TaxonomyCase; 5] {
        [
            TaxonomyCase {
                expected: ReadinessTaxonomyClass::MissingArtifact,
                outcome: ReadinessOutcome::Error,
                error_class: None,
                skip_reason: None,
                workstream: "proof_bundle",
                stale_git_sha: false,
                artifact_refs: &[],
                detail: "",
                remediation_hint: "attach missing report",
            },
            TaxonomyCase {
                expected: ReadinessTaxonomyClass::NoisyMeasurement,
                outcome: ReadinessOutcome::Error,
                error_class: Some(OperationalErrorClass::ResourceLimit),
                skip_reason: None,
                workstream: "performance",
                stale_git_sha: false,
                artifact_refs: &["perf/baseline.json"],
                detail: "",
                remediation_hint: "rerun with isolated worker",
            },
            TaxonomyCase {
                expected: ReadinessTaxonomyClass::SecurityRefusal,
                outcome: ReadinessOutcome::Fail,
                error_class: Some(OperationalErrorClass::ProductFailure),
                skip_reason: None,
                workstream: "release_gate",
                stale_git_sha: false,
                artifact_refs: &["security/refusal.json"],
                detail: "security refusal for hostile proof path",
                remediation_hint: "keep release blocked",
            },
            TaxonomyCase {
                expected: ReadinessTaxonomyClass::UnsafeRepairRefusal,
                outcome: ReadinessOutcome::Fail,
                error_class: Some(OperationalErrorClass::ProductFailure),
                skip_reason: None,
                workstream: "repair_policy",
                stale_git_sha: false,
                artifact_refs: &["repair/refusal.json"],
                detail: "unsafe repair refused before mutation",
                remediation_hint: "use dry-run first",
            },
            TaxonomyCase {
                expected: ReadinessTaxonomyClass::PassWithExperimentalCaveat,
                outcome: ReadinessOutcome::Pass,
                error_class: None,
                skip_reason: None,
                workstream: "performance",
                stale_git_sha: false,
                artifact_refs: &["perf/smoke.json"],
                detail: "pass with experimental caveat",
                remediation_hint: "",
            },
        ]
    }

    struct ReadinessFixture {
        dir: TempDir,
    }

    impl ReadinessFixture {
        fn new() -> Result<Self> {
            Ok(Self {
                dir: TempDir::new().context("create readiness tempdir")?,
            })
        }

        fn report(&self, current_git_sha: Option<&str>) -> Result<OperationalReadinessReport> {
            let config = OperationalReadinessReportConfig {
                artifacts_dir: self.dir.path().to_path_buf(),
                current_git_sha: current_git_sha.map(str::to_owned),
                max_artifact_age_days: None,
                recency_reference_epoch_days: None,
            };
            build_operational_readiness_report(&config)
        }

        fn report_with_recency(
            &self,
            current_git_sha: Option<&str>,
            max_artifact_age_days: u32,
            reference_timestamp: &str,
        ) -> Result<OperationalReadinessReport> {
            let config = OperationalReadinessReportConfig {
                artifacts_dir: self.dir.path().to_path_buf(),
                current_git_sha: current_git_sha.map(str::to_owned),
                max_artifact_age_days: Some(max_artifact_age_days),
                recency_reference_epoch_days: Some(
                    parse_manifest_timestamp_epoch_days(reference_timestamp).with_context(
                        || format!("parse reference timestamp `{reference_timestamp}`"),
                    )?,
                ),
            };
            build_operational_readiness_report(&config)
        }

        fn write_manifest(&self, name: &str, manifest: &ArtifactManifest) -> Result<()> {
            let path = self.dir.path().join(name);
            let json = serde_json::to_string_pretty(manifest)
                .with_context(|| format!("serialize manifest `{name}`"))?;
            fs::write(&path, json).with_context(|| format!("write manifest {}", path.display()))
        }

        fn write_legacy(&self, name: &str, summary: &LegacyE2eSummary) -> Result<()> {
            let path = self.dir.path().join(name);
            let json = serde_json::to_string_pretty(summary)
                .with_context(|| format!("serialize legacy summary `{name}`"))?;
            fs::write(&path, json)
                .with_context(|| format!("write legacy summary {}", path.display()))
        }
    }

    fn sample_operational_manifest(commit: &str) -> ArtifactManifest {
        let mut manifest = ArtifactManifest {
            schema_version: crate::artifact_manifest::SCHEMA_VERSION,
            run_id: "run-operational".to_owned(),
            created_at: "2026-05-03T00:00:00Z".to_owned(),
            gate_id: "operational_readiness".to_owned(),
            bead_id: Some("bd-rchk0.4.3".to_owned()),
            git_context: GitContext {
                commit: commit.to_owned(),
                branch: "main".to_owned(),
                clean: true,
            },
            environment: EnvironmentFingerprint {
                hostname: "host".to_owned(),
                cpu_model: "cpu".to_owned(),
                cpu_count: 64,
                memory_gib: 256,
                kernel: "Linux 6.17.0".to_owned(),
                rustc_version: "rustc 1.85.0".to_owned(),
                cargo_version: Some("cargo 1.85.0".to_owned()),
            },
            scenarios: BTreeMap::new(),
            operational_context: Some(OperationalRunContext {
                command_line: vec!["scripts/e2e/operational.sh".to_owned()],
                worker: WorkerContext {
                    host: "host".to_owned(),
                    worker_id: Some("worker-a".to_owned()),
                },
                fuse_capability: FuseCapabilityResult::PermissionDenied,
                stdout_path: "run/stdout.log".to_owned(),
                stderr_path: "run/stderr.log".to_owned(),
            }),
            operational_scenarios: BTreeMap::new(),
            readiness_events: Vec::new(),
            artifacts: vec![
                artifact("run/stdout.log", ArtifactCategory::RawLog),
                artifact("run/stderr.log", ArtifactCategory::RawLog),
            ],
            verdict: GateVerdict::Fail,
            duration_secs: 7.0,
            retention: None,
        };

        for case in sample_cases() {
            add_case(&mut manifest, case);
        }
        manifest
    }

    #[derive(Clone, Copy)]
    struct Case {
        scenario_id: &'static str,
        gate_hint: &'static str,
        result: ScenarioResult,
        classification: OperationalOutcomeClass,
        error_class: Option<OperationalErrorClass>,
        skip_reason: Option<SkipReason>,
        remediation_hint: Option<&'static str>,
    }

    fn sample_cases() -> [Case; 9] {
        [
            Case {
                scenario_id: "xfstests_generic_subset",
                gate_hint: "xfstests/results.json",
                result: ScenarioResult::Pass,
                classification: OperationalOutcomeClass::Pass,
                error_class: None,
                skip_reason: None,
                remediation_hint: None,
            },
            Case {
                scenario_id: "fuse_capability_probe",
                gate_hint: "fuse/capability.json",
                result: ScenarioResult::Skip,
                classification: OperationalOutcomeClass::Skip,
                error_class: Some(OperationalErrorClass::FusePermissionSkip),
                skip_reason: Some(SkipReason::FusePermissionDenied),
                remediation_hint: Some("rerun on worker with /dev/fuse access"),
            },
            Case {
                scenario_id: "mounted_ext4_rw",
                gate_hint: "mounted/ext4_rw.json",
                result: ScenarioResult::Pass,
                classification: OperationalOutcomeClass::Pass,
                error_class: None,
                skip_reason: None,
                remediation_hint: None,
            },
            Case {
                scenario_id: "repair_policy_refusal",
                gate_hint: "repair/policy.json",
                result: ScenarioResult::Fail,
                classification: OperationalOutcomeClass::Fail,
                error_class: Some(OperationalErrorClass::ProductFailure),
                skip_reason: None,
                remediation_hint: Some("open repair policy bead with artifact"),
            },
            Case {
                scenario_id: "writeback_crash_matrix",
                gate_hint: "writeback/crash.json",
                result: ScenarioResult::Fail,
                classification: OperationalOutcomeClass::Fail,
                error_class: Some(OperationalErrorClass::ProductFailure),
                skip_reason: None,
                remediation_hint: Some("open writeback crash-consistency bead"),
            },
            Case {
                scenario_id: "fuzz_repair_smoke",
                gate_hint: "fuzz/repair.json",
                result: ScenarioResult::Fail,
                classification: OperationalOutcomeClass::Error,
                error_class: Some(OperationalErrorClass::WorkerDependencyMissing),
                skip_reason: None,
                remediation_hint: Some("run on fuzz-capable worker"),
            },
            Case {
                scenario_id: "perf_baseline_run",
                gate_hint: "perf/baseline.json",
                result: ScenarioResult::Fail,
                classification: OperationalOutcomeClass::Error,
                error_class: Some(OperationalErrorClass::HostEnvironmentFailure),
                skip_reason: Some(SkipReason::WorkerDependencyMissing),
                remediation_hint: Some("run on performance worker"),
            },
            Case {
                scenario_id: "proof_bundle_stale",
                gate_hint: "proof/bundle.json",
                result: ScenarioResult::Fail,
                classification: OperationalOutcomeClass::Fail,
                error_class: Some(OperationalErrorClass::StaleTrackerToolingFailure),
                skip_reason: None,
                remediation_hint: Some("refresh proof bundle before release"),
            },
            Case {
                scenario_id: "release_gate_unsupported",
                gate_hint: "release/unsupported.json",
                result: ScenarioResult::Skip,
                classification: OperationalOutcomeClass::Skip,
                error_class: Some(OperationalErrorClass::UnsupportedV1Scope),
                skip_reason: Some(SkipReason::UnsupportedV1Scope),
                remediation_hint: Some("document explicit V1 non-goal"),
            },
        ]
    }

    fn add_case(manifest: &mut ArtifactManifest, case: Case) {
        let stdout_path = format!("{}/stdout.log", case.scenario_id);
        let stderr_path = format!("{}/stderr.log", case.scenario_id);

        manifest.scenarios.insert(
            case.scenario_id.to_owned(),
            crate::artifact_manifest::ScenarioOutcome {
                scenario_id: case.scenario_id.to_owned(),
                outcome: case.result,
                detail: case.remediation_hint.map(str::to_owned),
                duration_secs: 1.0,
            },
        );
        manifest
            .artifacts
            .push(artifact(case.gate_hint, ArtifactCategory::SummaryReport));
        manifest
            .artifacts
            .push(artifact(&stdout_path, ArtifactCategory::RawLog));
        manifest
            .artifacts
            .push(artifact(&stderr_path, ArtifactCategory::RawLog));
        manifest.operational_scenarios.insert(
            case.scenario_id.to_owned(),
            OperationalScenarioRecord {
                scenario_id: case.scenario_id.to_owned(),
                filesystem: crate::artifact_manifest::FilesystemFlavor::NotApplicable,
                image_hash: None,
                mount_options: Vec::new(),
                expected_outcome: case.result,
                actual_outcome: case.result,
                classification: case.classification,
                exit_status: i32::from(case.result != ScenarioResult::Pass),
                stdout_path: stdout_path.clone(),
                stderr_path: stderr_path.clone(),
                ledger_paths: Vec::new(),
                artifact_refs: vec![case.gate_hint.to_owned()],
                cleanup_status: CleanupStatus::Clean,
                error_class: case.error_class,
                remediation_hint: case.remediation_hint.map(str::to_owned),
                skip_reason: case.skip_reason,
            },
        );
        manifest
            .readiness_events
            .push(readiness_event_for_case(case, &stdout_path, &stderr_path));
    }

    fn readiness_event_for_case(
        case: Case,
        stdout_path: &str,
        stderr_path: &str,
    ) -> ReadinessEventEnvelope {
        ReadinessEventEnvelope {
            envelope_version: crate::artifact_manifest::READINESS_EVENT_ENVELOPE_VERSION,
            event_id: format!("event_{}", case.scenario_id),
            report_id: "report_run-operational".to_owned(),
            run_id: "run-operational".to_owned(),
            lane_id: classify_workstream(
                "operational_readiness",
                case.scenario_id,
                &[case.gate_hint.to_owned()],
            ),
            scenario_id: Some(case.scenario_id.to_owned()),
            aggregate_marker: None,
            artifact_id: case.gate_hint.to_owned(),
            parent_correlation_id: Some("report_run-operational".to_owned()),
            classification: case.classification,
            severity: match case.classification {
                OperationalOutcomeClass::Pass => ReadinessEventSeverity::Info,
                OperationalOutcomeClass::Skip => ReadinessEventSeverity::Warning,
                OperationalOutcomeClass::Fail | OperationalOutcomeClass::Error => {
                    ReadinessEventSeverity::Error
                }
            },
            created_at: "2026-05-03T00:00:01Z".to_owned(),
            git_commit: "abc123".to_owned(),
            host_fingerprint: "host|Linux 6.17.0|64cpu".to_owned(),
            capability_fingerprint: "fuse=permission_denied".to_owned(),
            raw_log_refs: vec![stdout_path.to_owned(), stderr_path.to_owned()],
            controlling_evidence: vec![case.gate_hint.to_owned()],
            remediation_id: format!("bd-slp26:{}", case.scenario_id),
            reproduction_command: format!(
                "scripts/e2e/operational.sh --scenario {}",
                case.scenario_id
            ),
        }
    }

    fn artifact(path: &str, category: ArtifactCategory) -> ArtifactEntry {
        ArtifactEntry {
            path: path.to_owned(),
            category,
            content_type: Some("application/json".to_owned()),
            size_bytes: 128,
            sha256: Some(format!("checksum-for-{}", path.replace('/', "-"))),
            redacted: false,
            metadata: BTreeMap::new(),
        }
    }

    fn sample_legacy_summary(commit: &str, scenario_id: &str) -> LegacyE2eSummary {
        LegacyE2eSummary {
            gate_id: "legacy_fuse_gate".to_owned(),
            run_id: format!("run-{commit}"),
            created_at: Some("2026-05-03T00:00:00Z".to_owned()),
            git_context: LegacyGitContext {
                commit: commit.to_owned(),
                branch: "main".to_owned(),
                clean: true,
            },
            scenarios: vec![LegacyScenario {
                scenario_id: scenario_id.to_owned(),
                outcome: "FAIL".to_owned(),
                detail: Some("FUSE permission denied on worker".to_owned()),
            }],
            verdict: "FAIL".to_owned(),
            duration_secs: 4,
            log_file: "run.log".to_owned(),
        }
    }
}
