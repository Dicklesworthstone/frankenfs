use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum XfstestsStatus {
    Passed,
    Failed,
    Skipped,
    NotRun,
    Planned,
}

impl XfstestsStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::NotRun => "not_run",
            Self::Planned => "planned",
        }
    }

    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::NotRun | Self::Planned => 1,
            Self::Skipped => 2,
            Self::Passed => 3,
            Self::Failed => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XfstestsCase {
    pub id: String,
    pub status: XfstestsStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_row_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_risk_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_operation_class: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracker_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comparison: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XfstestsRun {
    pub source: String,
    pub check_rc: i32,
    pub dry_run: bool,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub not_run: usize,
    pub planned: usize,
    pub pass_rate: f64,
    pub policy_summary: XfstestsPolicySummary,
    pub tests: Vec<XfstestsCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct XfstestsPolicySummary {
    pub by_allowlist_status: BTreeMap<String, usize>,
    pub by_classification: BTreeMap<String, usize>,
    pub by_expected_outcome: BTreeMap<String, usize>,
    pub by_user_risk_category: BTreeMap<String, usize>,
    pub by_operation_class: BTreeMap<String, usize>,
    pub not_run_by_classification: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct XfstestsAllowlistEntry {
    pub test_id: String,
    pub failure_reason: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_row_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem_flavor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v1_scope_mapping: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_operation_class: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operation_class_tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_risk_category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_decision: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_requirements: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracker_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repro_command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_plan: Option<XfstestsCommandPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct XfstestsCommandPlan {
    pub plan_id: String,
    pub execution_lane: String,
    pub image_path: String,
    pub scratch_path: String,
    pub mountpoint: String,
    pub test_device: String,
    pub scratch_device: String,
    pub image_hash: String,
    #[serde(default)]
    pub helper_binaries: Vec<String>,
    #[serde(default)]
    pub required_privileges: Vec<String>,
    pub mutation_surface: String,
    pub cleanup_action: String,
    #[serde(default)]
    pub argv: Vec<String>,
    #[serde(default)]
    pub destructive: bool,
    pub expected_plan_outcome: String,
    pub command_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfstestsBaselineEntry {
    pub test_id: String,
    pub expected_status: XfstestsStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum XfstestsBaselineRowStatus {
    Passed,
    Failed,
    Skipped,
    NotRun,
    Unsupported,
    HostBlocked,
    HarnessFailed,
    Interrupted,
    Resumed,
}

impl XfstestsBaselineRowStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::NotRun => "not_run",
            Self::Unsupported => "unsupported",
            Self::HostBlocked => "host_blocked",
            Self::HarnessFailed => "harness_failed",
            Self::Interrupted => "interrupted",
            Self::Resumed => "resumed",
        }
    }
}

pub const XFSTESTS_BASELINE_STATUS_VOCABULARY: &[XfstestsBaselineRowStatus] = &[
    XfstestsBaselineRowStatus::Passed,
    XfstestsBaselineRowStatus::Failed,
    XfstestsBaselineRowStatus::Skipped,
    XfstestsBaselineRowStatus::NotRun,
    XfstestsBaselineRowStatus::Unsupported,
    XfstestsBaselineRowStatus::HostBlocked,
    XfstestsBaselineRowStatus::HarnessFailed,
    XfstestsBaselineRowStatus::Interrupted,
    XfstestsBaselineRowStatus::Resumed,
];
pub const XFSTESTS_BASELINE_BEAD_ID: &str = "bd-rchk3.3";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfstestsRawArtifact {
    pub path: String,
    pub sha256: String,
    pub immutable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfstestsBaselineEnvironment {
    pub manifest_id: String,
    pub age_secs: u64,
    pub max_age_secs: u64,
    pub freshness_verdict: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfstestsBaselineCase {
    pub test_id: String,
    pub status: XfstestsBaselineRowStatus,
    pub raw_artifact_refs: Vec<String>,
    pub raw_log_hash: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_run_reason: Option<String>,
    pub partial_run_checkpoint: String,
    pub resume_command: String,
    pub cleanup_status: String,
    pub immutable_raw_artifacts: bool,
    pub classification: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfstestsBaselineManifest {
    pub schema_version: u32,
    pub baseline_id: String,
    pub bead_id: String,
    pub subset_version: String,
    pub environment: XfstestsBaselineEnvironment,
    pub status_vocabulary: Vec<String>,
    pub raw_artifact_policy: String,
    pub generated_summary_path: String,
    pub command_transcript: String,
    pub checkpoint_id: String,
    pub resume_command: String,
    pub cleanup_status: String,
    pub output_paths: BTreeMap<String, String>,
    pub reproduction_command: String,
    pub disposition_counts: BTreeMap<String, usize>,
    pub raw_artifacts: Vec<XfstestsRawArtifact>,
    pub cases: Vec<XfstestsBaselineCase>,
}

#[derive(Debug, Clone)]
pub struct XfstestsBaselineManifestInput<'a> {
    pub baseline_id: &'a str,
    pub subset_version: &'a str,
    pub environment_manifest_id: &'a str,
    pub environment_age_secs: u64,
    pub environment_max_age_secs: u64,
    pub selected_tests: &'a [String],
    pub run: &'a XfstestsRun,
    pub raw_artifact_paths: &'a [&'a Path],
    pub generated_summary_path: &'a Path,
    pub command_transcript: &'a str,
    pub checkpoint_id: &'a str,
    pub resume_command: &'a str,
    pub cleanup_status: &'a str,
    pub reproduction_command: &'a str,
    pub output_paths: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy)]
pub struct XfstestsFailureTriageInput<'a> {
    pub triage_id: &'a str,
    pub baseline_manifest_path: &'a Path,
    pub baseline_manifest: &'a XfstestsBaselineManifest,
    pub reproduction_command: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfstestsFailureTriageReport {
    pub schema_version: u32,
    pub triage_id: String,
    pub baseline_id: String,
    pub subset_version: String,
    pub source_baseline_manifest: String,
    pub live_bead_creation_enabled: bool,
    pub disposition_counts: BTreeMap<String, usize>,
    pub duplicate_groups: Vec<XfstestsFailureDuplicateGroup>,
    pub proposed_beads: Vec<XfstestsProposedFailureBead>,
    pub fixture_recipes: Vec<XfstestsSparseFixtureRecipe>,
    pub excluded_rows: Vec<XfstestsFailureTriageExcludedRow>,
    pub proposed_br_commands: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfstestsProposedFailureBead {
    pub proposed_id_placeholder: String,
    pub title: String,
    pub failing_test_id: String,
    pub related_test_ids: Vec<String>,
    pub filesystem_flavor: String,
    pub exact_command: String,
    pub normalized_outcome: String,
    pub expected_behavior: String,
    pub actual_behavior: String,
    pub suspected_crate_boundary: String,
    pub minimized_repro_command: Option<String>,
    pub minimization_status: String,
    pub duplicate_key: String,
    pub labels: Vec<String>,
    pub dependency_beads: Vec<String>,
    pub dependency_rationale: String,
    pub validation_command: String,
    pub raw_log_refs: Vec<String>,
    pub raw_log_hash: String,
    pub fixture_recipe: XfstestsSparseFixtureRecipe,
    pub live_create: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfstestsFailureDuplicateGroup {
    pub duplicate_key: String,
    pub primary_test_id: String,
    pub merged_test_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfstestsFailureTriageExcludedRow {
    pub test_id: String,
    pub status: String,
    pub classification: String,
    pub reason: String,
    pub raw_log_hash: String,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfstestsSparseFixtureRecipe {
    pub schema_version: u32,
    pub recipe_id: String,
    pub source_xfstests_id: String,
    pub related_test_ids: Vec<String>,
    pub filesystem_flavor: String,
    pub suspected_crate_boundary: String,
    pub fixture_manifest_kind: String,
    pub proposed_fixture_path: String,
    pub source_raw_log_refs: Vec<String>,
    pub source_raw_log_hash: String,
    pub minimized_reproducer_command: String,
    pub expected_behavior: String,
    pub actual_behavior: String,
    pub validation_command: String,
    pub dependency_hints: Vec<String>,
    pub recipe_steps: Vec<String>,
    pub promotion_status: String,
    pub live_fixture_write_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct XfstestsComparison {
    pub regressions: Vec<String>,
    pub improvements: Vec<String>,
    pub unchanged: Vec<String>,
}

const REQUIRED_XFSTESTS_OPERATION_CLASSES: &[&str] = &[
    "read_only_mount",
    "rw_file_lifecycle",
    "directory_mutation",
    "rename_link_semantics",
    "xattr_semantics",
    "fsync_boundary",
    "writeback_cache_unsupported",
    "host_capability_skip",
];

const REQUIRED_XFSTESTS_FILESYSTEM_FLAVORS: &[&str] = &["generic", "ext4", "btrfs"];

const KNOWN_XFSTESTS_RISK_CATEGORIES: &[&str] = &[
    "data_visibility",
    "data_integrity",
    "metadata_integrity",
    "namespace_integrity",
    "operator_honesty",
    "unsupported_feature",
    "host_environment",
];

const KNOWN_XFSTESTS_OUTCOMES: &[&str] = &[
    "expected_pass",
    "product_actionable_failure",
    "environment_blocked",
    "unsupported_by_v1",
    "expected_failure",
];

const KNOWN_XFSTESTS_TRIAGE_BOUNDARIES: &[&str] = &[
    "ffs-core",
    "ffs-fuse",
    "ffs-ext4",
    "ffs-btrfs",
    "ffs-dir",
    "ffs-xattr",
    "ffs-inode",
    "ffs-journal",
    "ffs-harness",
];

const REQUIRED_XFSTESTS_ARTIFACTS: &[&str] = &[
    "selected_tests.txt",
    "policy_plan.json",
    "policy_report.md",
    "summary.json",
    "results.json",
    "junit.xml",
    "check.log",
];

const REQUIRED_XFSTESTS_BASELINE_OUTPUT_PATHS: &[&str] =
    &["baseline_manifest_json", "baseline_report_md"];

const KNOWN_XFSTESTS_COMMAND_PLAN_LANES: &[&str] = &[
    "dry_run_only",
    "fixture_only",
    "permissioned_real",
    "host_skip",
    "unsupported_by_scope",
];

const KNOWN_XFSTESTS_COMMAND_PLAN_PRIVILEGES: &[&str] = &[
    "none",
    "user_mount",
    "fuse_mount",
    "root_required",
    "cap_sys_admin",
    "scratch_device",
    "host_tooling",
];

const KNOWN_XFSTESTS_COMMAND_PLAN_OUTCOMES: &[&str] = &[
    "dry_run_only",
    "fixture_only",
    "permissioned_real",
    "host_skip",
    "unsupported_by_scope",
    "product_failure",
    "harness_failure",
    "cleanup_failure",
];

pub fn load_selected_tests(path: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read selected tests {}", path.display()))?;
    Ok(text
        .lines()
        .map(|line| line.split_once('#').map_or(line, |(prefix, _)| prefix))
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

pub fn load_allowlist(path: &Path) -> Result<Vec<XfstestsAllowlistEntry>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read allowlist {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid allowlist json {}", path.display()))
}

pub fn load_baseline(path: &Path) -> Result<Vec<XfstestsBaselineEntry>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read baseline {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("invalid baseline json {}", path.display()))
}

pub fn build_xfstests_baseline_manifest(
    input: XfstestsBaselineManifestInput<'_>,
) -> Result<XfstestsBaselineManifest> {
    let raw_artifacts = input
        .raw_artifact_paths
        .iter()
        .map(|path| hash_raw_artifact(path))
        .collect::<Result<Vec<_>>>()?;
    let artifact_refs = raw_artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();
    let raw_log_hash = hash_raw_artifact_set(&raw_artifacts);

    let run_by_id = input
        .run
        .tests
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let immutable_raw_artifacts = raw_artifacts.iter().all(|artifact| artifact.immutable);
    let cases = input
        .selected_tests
        .iter()
        .map(|test_id| {
            let case = run_by_id.get(test_id.as_str());
            let status = case.map_or(XfstestsBaselineRowStatus::NotRun, |case| {
                baseline_status_for_case(case, input.cleanup_status)
            });
            let not_run_reason = case
                .and_then(|case| {
                    case.output_snippet
                        .clone()
                        .or_else(|| case.failure_reason.clone())
                })
                .filter(|_| {
                    matches!(
                        status,
                        XfstestsBaselineRowStatus::NotRun
                            | XfstestsBaselineRowStatus::Interrupted
                            | XfstestsBaselineRowStatus::HostBlocked
                            | XfstestsBaselineRowStatus::HarnessFailed
                            | XfstestsBaselineRowStatus::Unsupported
                    )
                });
            let remediation = remediation_for_status(status, input.resume_command);
            XfstestsBaselineCase {
                test_id: test_id.clone(),
                status,
                raw_artifact_refs: artifact_refs.clone(),
                raw_log_hash: raw_log_hash.clone(),
                command: input.command_transcript.to_owned(),
                not_run_reason,
                partial_run_checkpoint: input.checkpoint_id.to_owned(),
                resume_command: input.resume_command.to_owned(),
                cleanup_status: input.cleanup_status.to_owned(),
                immutable_raw_artifacts,
                classification: case
                    .and_then(|case| case.classification.clone())
                    .unwrap_or_else(|| "unclassified".to_owned()),
                remediation,
            }
        })
        .collect::<Vec<_>>();

    let disposition_counts = disposition_counts(&cases);
    let environment_manifest_missing = input.environment_manifest_id.trim() == "preflight:missing";
    let freshness_verdict = if environment_manifest_missing {
        "missing"
    } else if input.environment_age_secs <= input.environment_max_age_secs {
        "fresh"
    } else {
        "stale"
    }
    .to_owned();

    Ok(XfstestsBaselineManifest {
        schema_version: 1,
        baseline_id: input.baseline_id.to_owned(),
        bead_id: XFSTESTS_BASELINE_BEAD_ID.to_owned(),
        subset_version: input.subset_version.to_owned(),
        environment: XfstestsBaselineEnvironment {
            manifest_id: input.environment_manifest_id.to_owned(),
            age_secs: input.environment_age_secs,
            max_age_secs: input.environment_max_age_secs,
            freshness_verdict,
        },
        status_vocabulary: XFSTESTS_BASELINE_STATUS_VOCABULARY
            .iter()
            .map(|status| status.as_str().to_owned())
            .collect(),
        raw_artifact_policy:
            "raw artifacts are immutable inputs; summaries are derived and may not rewrite raw logs"
                .to_owned(),
        generated_summary_path: input.generated_summary_path.display().to_string(),
        command_transcript: input.command_transcript.to_owned(),
        checkpoint_id: input.checkpoint_id.to_owned(),
        resume_command: input.resume_command.to_owned(),
        cleanup_status: input.cleanup_status.to_owned(),
        output_paths: input.output_paths,
        reproduction_command: input.reproduction_command.to_owned(),
        disposition_counts,
        raw_artifacts,
        cases,
    })
}

#[must_use]
pub fn validate_xfstests_baseline_manifest(manifest: &XfstestsBaselineManifest) -> Vec<String> {
    let mut errors = Vec::new();

    if manifest.schema_version != 1 {
        errors.push("xfstests baseline manifest schema_version must be 1".to_owned());
    }
    if manifest.bead_id != XFSTESTS_BASELINE_BEAD_ID {
        errors.push(format!(
            "xfstests baseline manifest bead_id must be {XFSTESTS_BASELINE_BEAD_ID}"
        ));
    }
    require_non_empty("baseline_id", &manifest.baseline_id, &mut errors);
    require_non_empty("subset_version", &manifest.subset_version, &mut errors);
    require_non_empty(
        "environment.manifest_id",
        &manifest.environment.manifest_id,
        &mut errors,
    );
    if manifest.environment.manifest_id.trim() == "preflight:missing" {
        errors.push("xfstests baseline environment manifest is missing preflight proof".to_owned());
    }
    require_non_empty(
        "command_transcript",
        &manifest.command_transcript,
        &mut errors,
    );
    require_non_empty("checkpoint_id", &manifest.checkpoint_id, &mut errors);
    require_non_empty("resume_command", &manifest.resume_command, &mut errors);
    require_non_empty("cleanup_status", &manifest.cleanup_status, &mut errors);
    require_non_empty(
        "reproduction_command",
        &manifest.reproduction_command,
        &mut errors,
    );
    for required_output in REQUIRED_XFSTESTS_BASELINE_OUTPUT_PATHS {
        match manifest.output_paths.get(*required_output) {
            Some(path) if !path.trim().is_empty() => {}
            _ => errors.push(format!(
                "xfstests baseline output_paths missing {required_output}"
            )),
        }
    }
    if manifest.environment.age_secs > manifest.environment.max_age_secs
        || manifest.environment.freshness_verdict != "fresh"
    {
        errors.push(format!(
            "xfstests baseline environment manifest is stale: age_secs={} max_age_secs={} verdict={}",
            manifest.environment.age_secs,
            manifest.environment.max_age_secs,
            manifest.environment.freshness_verdict
        ));
    }
    let expected_vocabulary = XFSTESTS_BASELINE_STATUS_VOCABULARY
        .iter()
        .map(|status| status.as_str().to_owned())
        .collect::<Vec<_>>();
    if manifest.status_vocabulary != expected_vocabulary {
        errors.push(
            "xfstests baseline status_vocabulary does not match required statuses".to_owned(),
        );
    }
    if manifest.raw_artifact_policy.trim().is_empty() {
        errors.push("xfstests baseline raw_artifact_policy is required".to_owned());
    }
    if manifest.raw_artifacts.is_empty() {
        errors.push("xfstests baseline raw_artifacts must not be empty".to_owned());
    }
    if manifest.cases.is_empty() {
        errors.push("xfstests baseline cases must not be empty".to_owned());
    }
    let raw_by_path = manifest
        .raw_artifacts
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    for artifact in &manifest.raw_artifacts {
        validate_raw_artifact(artifact, &mut errors);
    }

    let mut seen = BTreeSet::new();
    for case in &manifest.cases {
        if !seen.insert(case.test_id.as_str()) {
            errors.push(format!(
                "xfstests baseline has duplicate test row: {}",
                case.test_id
            ));
        }
        validate_baseline_case(case, &mut errors);
        if !case.raw_artifact_refs.is_empty() {
            validate_case_raw_refs("baseline", case, &raw_by_path, &mut errors);
        }
    }
    let actual_disposition_counts = disposition_counts(&manifest.cases);
    if manifest.disposition_counts != actual_disposition_counts {
        errors.push(format!(
            "xfstests baseline disposition_counts mismatch: declared={:?} actual={actual_disposition_counts:?}",
            manifest.disposition_counts
        ));
    }

    errors
}

pub fn build_xfstests_failure_triage_report(
    input: XfstestsFailureTriageInput<'_>,
) -> Result<XfstestsFailureTriageReport> {
    let baseline_errors = validate_xfstests_baseline_manifest(input.baseline_manifest);
    if !baseline_errors.is_empty() {
        anyhow::bail!(
            "xfstests baseline manifest is not consumable for failure triage: {}",
            baseline_errors.join("; ")
        );
    }
    let raw_by_path = input
        .baseline_manifest
        .raw_artifacts
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let mut raw_ref_errors = Vec::new();
    for case in &input.baseline_manifest.cases {
        validate_case_raw_refs("triage", case, &raw_by_path, &mut raw_ref_errors);
    }
    if !raw_ref_errors.is_empty() {
        anyhow::bail!(
            "xfstests baseline raw artifact refs are not consumable for failure triage: {}",
            raw_ref_errors.join("; ")
        );
    }

    let mut proposed_by_key: BTreeMap<String, XfstestsProposedFailureBead> = BTreeMap::new();
    let mut excluded_rows = Vec::new();
    for case in &input.baseline_manifest.cases {
        if is_product_failure_row(case) {
            let proposed = proposed_failure_bead(
                proposed_by_key.len() + 1,
                case,
                input.baseline_manifest,
                input.reproduction_command,
            );
            match proposed_by_key.get_mut(&proposed.duplicate_key) {
                Some(existing) => {
                    if !existing.related_test_ids.contains(&case.test_id) {
                        existing.related_test_ids.push(case.test_id.clone());
                    }
                    merge_raw_refs(existing, case);
                }
                None => {
                    proposed_by_key.insert(proposed.duplicate_key.clone(), proposed);
                }
            }
        } else {
            excluded_rows.push(excluded_triage_row(case));
        }
    }

    let proposed_beads = proposed_by_key.into_values().collect::<Vec<_>>();
    let duplicate_groups = failure_triage_duplicate_groups(&proposed_beads);
    let fixture_recipes = proposed_beads
        .iter()
        .map(|bead| bead.fixture_recipe.clone())
        .collect::<Vec<_>>();
    let proposed_br_commands = proposed_beads
        .iter()
        .map(XfstestsProposedFailureBead::proposed_br_command)
        .collect::<Vec<_>>();
    let report = XfstestsFailureTriageReport {
        schema_version: 1,
        triage_id: input.triage_id.to_owned(),
        baseline_id: input.baseline_manifest.baseline_id.clone(),
        subset_version: input.baseline_manifest.subset_version.clone(),
        source_baseline_manifest: input.baseline_manifest_path.display().to_string(),
        live_bead_creation_enabled: false,
        disposition_counts: input.baseline_manifest.disposition_counts.clone(),
        duplicate_groups,
        proposed_beads,
        fixture_recipes,
        excluded_rows,
        proposed_br_commands,
        reproduction_command: input.reproduction_command.to_owned(),
    };
    let errors = validate_xfstests_failure_triage_report(&report);
    if !errors.is_empty() {
        anyhow::bail!(
            "xfstests failure triage report validation failed: {}",
            errors.join("; ")
        );
    }
    Ok(report)
}

#[must_use]
pub fn validate_xfstests_failure_triage_report(
    report: &XfstestsFailureTriageReport,
) -> Vec<String> {
    let mut errors = Vec::new();
    if report.schema_version != 1 {
        errors.push("xfstests failure triage schema_version must be 1".to_owned());
    }
    require_non_empty("triage_id", &report.triage_id, &mut errors);
    require_non_empty("baseline_id", &report.baseline_id, &mut errors);
    require_non_empty("subset_version", &report.subset_version, &mut errors);
    require_non_empty(
        "source_baseline_manifest",
        &report.source_baseline_manifest,
        &mut errors,
    );
    require_non_empty(
        "reproduction_command",
        &report.reproduction_command,
        &mut errors,
    );
    if report.live_bead_creation_enabled {
        errors.push("xfstests failure triage must remain dry-run only".to_owned());
    }
    if report.proposed_br_commands.len() != report.proposed_beads.len() {
        errors.push("xfstests failure triage proposed_br_commands count mismatch".to_owned());
    }
    let expected_fixture_recipes = report
        .proposed_beads
        .iter()
        .map(|bead| bead.fixture_recipe.clone())
        .collect::<Vec<_>>();
    if report.fixture_recipes != expected_fixture_recipes {
        errors.push("xfstests failure triage fixture_recipes mismatch proposed beads".to_owned());
    }
    let expected_duplicate_groups = failure_triage_duplicate_groups(&report.proposed_beads);
    if report.duplicate_groups != expected_duplicate_groups {
        errors.push(format!(
            "xfstests failure triage duplicate_groups mismatch: declared={:?} actual={expected_duplicate_groups:?}",
            report.duplicate_groups
        ));
    }
    validate_failure_triage_row_uniqueness(report, &mut errors);
    for (index, bead) in report.proposed_beads.iter().enumerate() {
        let Some(command) = report.proposed_br_commands.get(index) else {
            continue;
        };
        if !command.starts_with("DRY_RUN br create ") {
            errors.push(format!(
                "xfstests failure triage proposed_br_commands[{index}] must be a dry-run br create command"
            ));
        }
        let expected = bead.proposed_br_command();
        if command != &expected {
            errors.push(format!(
                "xfstests failure triage proposed_br_commands[{index}] does not match proposed bead {}",
                bead.proposed_id_placeholder
            ));
        }
    }
    let actual_disposition_counts = failure_triage_disposition_counts(report);
    if report.disposition_counts != actual_disposition_counts {
        errors.push(format!(
            "xfstests failure triage disposition_counts mismatch: declared={:?} actual={actual_disposition_counts:?}",
            report.disposition_counts
        ));
    }
    let mut duplicate_keys = BTreeSet::new();
    for bead in &report.proposed_beads {
        validate_proposed_failure_bead(bead, &mut duplicate_keys, &mut errors);
    }
    let mut recipe_ids = BTreeSet::new();
    for recipe in &report.fixture_recipes {
        validate_sparse_fixture_recipe(recipe, &mut recipe_ids, &mut errors);
    }
    for excluded in &report.excluded_rows {
        validate_failure_triage_excluded_row(excluded, &mut errors);
    }
    errors
}

fn validate_sparse_fixture_recipe(
    recipe: &XfstestsSparseFixtureRecipe,
    recipe_ids: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if recipe.schema_version != 1 {
        errors.push(format!(
            "xfstests sparse fixture recipe {} schema_version must be 1",
            recipe.recipe_id
        ));
    }
    require_non_empty("fixture.recipe_id", &recipe.recipe_id, errors);
    require_non_empty(
        "fixture.source_xfstests_id",
        &recipe.source_xfstests_id,
        errors,
    );
    require_non_empty(
        "fixture.filesystem_flavor",
        &recipe.filesystem_flavor,
        errors,
    );
    require_non_empty(
        "fixture.suspected_crate_boundary",
        &recipe.suspected_crate_boundary,
        errors,
    );
    require_non_empty(
        "fixture.proposed_fixture_path",
        &recipe.proposed_fixture_path,
        errors,
    );
    require_non_empty(
        "fixture.minimized_reproducer_command",
        &recipe.minimized_reproducer_command,
        errors,
    );
    require_non_empty(
        "fixture.expected_behavior",
        &recipe.expected_behavior,
        errors,
    );
    require_non_empty("fixture.actual_behavior", &recipe.actual_behavior, errors);
    require_non_empty(
        "fixture.validation_command",
        &recipe.validation_command,
        errors,
    );
    if !recipe.recipe_id.starts_with("xfstests-sparse-fixture-") {
        errors.push(format!(
            "xfstests sparse fixture recipe {} has malformed recipe_id",
            recipe.recipe_id
        ));
    }
    if !recipe_ids.insert(recipe.recipe_id.clone()) {
        errors.push(format!(
            "xfstests sparse fixture duplicate recipe_id: {}",
            recipe.recipe_id
        ));
    }
    if recipe.fixture_manifest_kind != "sparse_fixture_generation_recipe" {
        errors.push(format!(
            "xfstests sparse fixture recipe {} has unsupported fixture_manifest_kind {}",
            recipe.recipe_id, recipe.fixture_manifest_kind
        ));
    }
    if recipe.promotion_status != "dry_run_recipe_only" {
        errors.push(format!(
            "xfstests sparse fixture recipe {} must remain dry-run only",
            recipe.recipe_id
        ));
    }
    if recipe.live_fixture_write_enabled {
        errors.push(format!(
            "xfstests sparse fixture recipe {} must not write live fixtures",
            recipe.recipe_id
        ));
    }
    validate_sparse_fixture_recipe_path(recipe, errors);
    validate_sparse_fixture_recipe_links(recipe, errors);
}

fn validate_sparse_fixture_recipe_path(
    recipe: &XfstestsSparseFixtureRecipe,
    errors: &mut Vec<String>,
) {
    let proposed_path = Path::new(&recipe.proposed_fixture_path);
    if proposed_path.is_absolute()
        || recipe.proposed_fixture_path.contains("..")
        || !recipe
            .proposed_fixture_path
            .starts_with("conformance/fixtures/xfstests/")
        || !path_has_json_extension(proposed_path)
    {
        errors.push(format!(
            "xfstests sparse fixture recipe {} has unsafe proposed_fixture_path {}",
            recipe.recipe_id, recipe.proposed_fixture_path
        ));
    }
}

fn path_has_json_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
}

fn validate_sparse_fixture_recipe_links(
    recipe: &XfstestsSparseFixtureRecipe,
    errors: &mut Vec<String>,
) {
    if !KNOWN_XFSTESTS_TRIAGE_BOUNDARIES.contains(&recipe.suspected_crate_boundary.as_str()) {
        errors.push(format!(
            "xfstests sparse fixture recipe {} has unknown suspected boundary {}",
            recipe.recipe_id, recipe.suspected_crate_boundary
        ));
    }
    if recipe.related_test_ids.is_empty()
        || !recipe.related_test_ids.contains(&recipe.source_xfstests_id)
    {
        errors.push(format!(
            "xfstests sparse fixture recipe {} must include source_xfstests_id in related_test_ids",
            recipe.recipe_id
        ));
    }
    if recipe.source_raw_log_refs.is_empty() || !is_canonical_sha256(&recipe.source_raw_log_hash) {
        errors.push(format!(
            "xfstests sparse fixture recipe {} missing source raw log refs/hash",
            recipe.recipe_id
        ));
    }
    if recipe.dependency_hints.is_empty()
        || !recipe
            .dependency_hints
            .iter()
            .any(|hint| hint.contains("bd-rchk3.4"))
    {
        errors.push(format!(
            "xfstests sparse fixture recipe {} missing bd-rchk3.4 dependency hint",
            recipe.recipe_id
        ));
    }
    if recipe.recipe_steps.len() < 3 {
        errors.push(format!(
            "xfstests sparse fixture recipe {} needs a concrete minimization recipe",
            recipe.recipe_id
        ));
    }
}

#[must_use]
pub fn render_xfstests_failure_triage_markdown(report: &XfstestsFailureTriageReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# xfstests failure triage `{}`", report.triage_id);
    let _ = writeln!(out);
    let _ = writeln!(out, "- baseline: `{}`", report.baseline_id);
    let _ = writeln!(out, "- subset version: `{}`", report.subset_version);
    let _ = writeln!(
        out,
        "- live bead creation enabled: `{}`",
        report.live_bead_creation_enabled
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Proposed Product Beads");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Placeholder | Tests | Flavor | Boundary | Expected | Actual | Raw hash | Validation | Dependencies |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|---|---|---|");
    for bead in &report.proposed_beads {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | `{}` | `{}` | {} |",
            bead.proposed_id_placeholder,
            bead.related_test_ids.join(", "),
            bead.filesystem_flavor,
            bead.suspected_crate_boundary,
            bead.expected_behavior,
            bead.actual_behavior,
            bead.raw_log_hash,
            bead.validation_command,
            bead.dependency_beads.join(", ")
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Sparse Fixture Recipes");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Recipe | Tests | Proposed fixture | Status | Steps |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|");
    for recipe in &report.fixture_recipes {
        let _ = writeln!(
            out,
            "| {} | {} | `{}` | {} | {} |",
            recipe.recipe_id,
            recipe.related_test_ids.join(", "),
            recipe.proposed_fixture_path,
            recipe.promotion_status,
            recipe.recipe_steps.join("<br>")
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Excluded Rows");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Test | Status | Classification | Reason |");
    let _ = writeln!(out, "|---|---|---|---|");
    for row in &report.excluded_rows {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            row.test_id, row.status, row.classification, row.reason
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Dry-Run br Commands");
    let _ = writeln!(out);
    for command in &report.proposed_br_commands {
        let _ = writeln!(out, "- `{command}`");
    }
    out
}

#[must_use]
pub fn render_xfstests_baseline_markdown(manifest: &XfstestsBaselineManifest) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# xfstests baseline manifest `{}`",
        manifest.baseline_id
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "- subset version: `{}`", manifest.subset_version);
    let _ = writeln!(
        out,
        "- environment manifest: `{}` ({})",
        manifest.environment.manifest_id, manifest.environment.freshness_verdict
    );
    let _ = writeln!(out, "- checkpoint: `{}`", manifest.checkpoint_id);
    let _ = writeln!(out, "- resume command: `{}`", manifest.resume_command);
    let _ = writeln!(out, "- cleanup status: `{}`", manifest.cleanup_status);
    let _ = writeln!(out);
    let _ = writeln!(out, "## Dispositions");
    let _ = writeln!(out);
    for (status, count) in &manifest.disposition_counts {
        let _ = writeln!(out, "- {status}: {count}");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Cases");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Test | Status | Classification | Raw hash | Resume |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|");
    for case in &manifest.cases {
        let _ = writeln!(
            out,
            "| {} | {} | {} | `{}` | `{}` |",
            case.test_id,
            case.status.as_str(),
            case.classification,
            case.raw_log_hash,
            case.resume_command
        );
    }
    out
}

#[must_use]
pub fn validate_xfstests_policy(
    selected: &[String],
    allowlist: &[XfstestsAllowlistEntry],
) -> Vec<String> {
    let mut errors = Vec::new();
    let mut selected_ids = BTreeSet::new();

    for test_id in selected {
        if !selected_ids.insert(test_id.as_str()) {
            errors.push(format!("duplicate selected xfstests id: {test_id}"));
        }
    }

    let mut policy_ids = BTreeSet::new();
    for entry in allowlist {
        if !policy_ids.insert(entry.test_id.as_str()) {
            errors.push(format!("duplicate xfstests policy id: {}", entry.test_id));
        }

        validate_policy_entry(
            entry,
            selected_ids.contains(entry.test_id.as_str()),
            &mut errors,
        );
    }

    for test_id in &selected_ids {
        if !policy_ids.contains(test_id) {
            errors.push(format!(
                "selected xfstests id lacks policy metadata: {test_id}"
            ));
        }
    }

    for test_id in &policy_ids {
        if !selected_ids.contains(test_id) {
            errors.push(format!(
                "xfstests policy references unselected id: {test_id}"
            ));
        }
    }

    errors
}

#[must_use]
pub fn validate_xfstests_policy_coverage(allowlist: &[XfstestsAllowlistEntry]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut covered = BTreeSet::new();
    let mut flavors = BTreeSet::new();

    for entry in allowlist {
        if let Some(filesystem_flavor) = entry.filesystem_flavor.as_deref() {
            flavors.insert(filesystem_flavor.to_owned());
        }
        if let Some(operation_class) = entry.expected_operation_class.as_deref() {
            covered.insert(operation_class.to_owned());
        }
        for operation_class in &entry.operation_class_tags {
            covered.insert(operation_class.clone());
        }
    }

    for required in REQUIRED_XFSTESTS_OPERATION_CLASSES {
        if !covered.contains(*required) {
            errors.push(format!(
                "xfstests policy is missing representative operation class: {required}"
            ));
        }
    }

    for required in REQUIRED_XFSTESTS_FILESYSTEM_FLAVORS {
        if !flavors.contains(*required) {
            errors.push(format!(
                "xfstests policy is missing representative filesystem flavor: {required}"
            ));
        }
    }

    errors
}

fn validate_policy_entry(entry: &XfstestsAllowlistEntry, selected: bool, errors: &mut Vec<String>) {
    if !selected {
        return;
    }

    validate_policy_identity(entry, errors);
    validate_policy_scope(entry, errors);
    validate_policy_risk(entry, errors);
    validate_policy_artifacts(entry, errors);
    validate_policy_command_plan(entry, errors);
    validate_policy_outcome(entry, errors);
    validate_policy_links(entry, errors);
}

fn validate_policy_identity(entry: &XfstestsAllowlistEntry, errors: &mut Vec<String>) {
    let test_prefix = entry.test_id.split('/').next().unwrap_or_default();
    if !matches!(test_prefix, "generic" | "ext4" | "btrfs") {
        errors.push(format!(
            "xfstests policy has unsupported test id format: {}",
            entry.test_id
        ));
    }

    match entry.status.as_str() {
        "expected_pass" | "known_fail" | "wont_fix" | "likely_pass" => {}
        other => errors.push(format!(
            "xfstests policy {} has unknown status: {other}",
            entry.test_id
        )),
    }

    match entry.policy_row_id.as_deref() {
        Some(row_id) if row_id.starts_with("xfstests-policy-") => {}
        Some(row_id) => errors.push(format!(
            "xfstests policy {} has malformed policy_row_id: {row_id}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing policy_row_id",
            entry.test_id
        )),
    }

    match entry.filesystem_flavor.as_deref() {
        Some("generic" | "ext4" | "btrfs")
            if entry.filesystem_flavor.as_deref() == Some(test_prefix) => {}
        Some("generic" | "ext4" | "btrfs") => errors.push(format!(
            "xfstests policy {} has filesystem_flavor that does not match id prefix",
            entry.test_id
        )),
        Some(other) => errors.push(format!(
            "xfstests policy {} has unknown filesystem_flavor: {other}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing filesystem_flavor",
            entry.test_id
        )),
    }
}

fn validate_policy_scope(entry: &XfstestsAllowlistEntry, errors: &mut Vec<String>) {
    match entry.v1_scope_mapping.as_deref() {
        Some(reference) if is_supported_scope_reference(reference) => {}
        Some(reference) => errors.push(format!(
            "xfstests policy {} has stale V1 scope mapping: {reference}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing V1 scope mapping",
            entry.test_id
        )),
    }

    match entry.expected_operation_class.as_deref() {
        Some(operation_class) if is_known_operation_class(operation_class) => {}
        Some(operation_class) => errors.push(format!(
            "xfstests policy {} has unknown expected operation class: {operation_class}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing expected operation class",
            entry.test_id
        )),
    }
    for operation_class in &entry.operation_class_tags {
        if !is_known_operation_class(operation_class) {
            errors.push(format!(
                "xfstests policy {} has unknown operation class tag: {operation_class}",
                entry.test_id
            ));
        }
    }
}

fn validate_policy_risk(entry: &XfstestsAllowlistEntry, errors: &mut Vec<String>) {
    match entry.user_risk_category.as_deref() {
        Some(category) if KNOWN_XFSTESTS_RISK_CATEGORIES.contains(&category) => {}
        Some(category) => errors.push(format!(
            "xfstests policy {} has unknown user risk category: {category}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing user risk category",
            entry.test_id
        )),
    }

    match entry.expected_outcome.as_deref() {
        Some(outcome) if KNOWN_XFSTESTS_OUTCOMES.contains(&outcome) => {}
        Some(outcome) => errors.push(format!(
            "xfstests policy {} has unknown expected outcome: {outcome}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing expected outcome",
            entry.test_id
        )),
    }

    if let Some(outcome) = entry.expected_outcome.as_deref() {
        let expected = expected_outcome_for_classification(entry);
        if outcome != expected {
            errors.push(format!(
                "xfstests policy {} expected_outcome={outcome} does not match status/classification expectation {expected}",
                entry.test_id
            ));
        }
    }

    match entry.selection_decision.as_deref() {
        Some("selected" | "skipped") => {}
        Some(decision) => errors.push(format!(
            "xfstests policy {} has unknown selection decision: {decision}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing selection decision",
            entry.test_id
        )),
    }
}

fn validate_policy_artifacts(entry: &XfstestsAllowlistEntry, errors: &mut Vec<String>) {
    for required_artifact in REQUIRED_XFSTESTS_ARTIFACTS {
        if !entry
            .artifact_requirements
            .iter()
            .any(|artifact| artifact == required_artifact)
        {
            errors.push(format!(
                "xfstests policy {} is missing artifact requirement: {required_artifact}",
                entry.test_id
            ));
        }
    }

    if entry.required_capabilities.is_empty() {
        errors.push(format!(
            "xfstests policy {} is missing required_capabilities",
            entry.test_id
        ));
    }
}

fn validate_policy_command_plan(entry: &XfstestsAllowlistEntry, errors: &mut Vec<String>) {
    let Some(plan) = entry.command_plan.as_ref() else {
        errors.push(format!(
            "xfstests policy {} is missing command_plan",
            entry.test_id
        ));
        return;
    };

    validate_command_plan_identity(entry, plan, errors);
    validate_command_plan_paths(entry, plan, errors);
    validate_command_plan_helpers(entry, plan, errors);
    validate_command_plan_argv(entry, plan, errors);

    if plan.destructive && plan.execution_lane != "permissioned_real" {
        errors.push(format!(
            "xfstests policy {} command plan marks destructive action outside permissioned_real lane",
            entry.test_id
        ));
    }
}

fn validate_command_plan_identity(
    entry: &XfstestsAllowlistEntry,
    plan: &XfstestsCommandPlan,
    errors: &mut Vec<String>,
) {
    if !plan.plan_id.starts_with("xfstests-plan-") {
        errors.push(format!(
            "xfstests policy {} has malformed command plan id: {}",
            entry.test_id, plan.plan_id
        ));
    }

    if !KNOWN_XFSTESTS_COMMAND_PLAN_LANES.contains(&plan.execution_lane.as_str()) {
        errors.push(format!(
            "xfstests policy {} has unknown command plan lane: {}",
            entry.test_id, plan.execution_lane
        ));
    }

    if !KNOWN_XFSTESTS_COMMAND_PLAN_OUTCOMES.contains(&plan.expected_plan_outcome.as_str()) {
        errors.push(format!(
            "xfstests policy {} command plan has unknown expected outcome: {}",
            entry.test_id, plan.expected_plan_outcome
        ));
    }
}

fn validate_command_plan_paths(
    entry: &XfstestsAllowlistEntry,
    plan: &XfstestsCommandPlan,
    errors: &mut Vec<String>,
) {
    let test_fragment = command_plan_test_fragment(&entry.test_id);
    if !is_temp_scoped_path(&plan.image_path) {
        errors.push(format!(
            "xfstests policy {} command plan uses non-temporary image path: {}",
            entry.test_id, plan.image_path
        ));
    }
    validate_command_plan_path_fragment(
        entry,
        "image path",
        &plan.image_path,
        &test_fragment,
        errors,
    );

    if !is_temp_scoped_path(&plan.scratch_path) {
        errors.push(format!(
            "xfstests policy {} command plan uses non-temporary scratch path: {}",
            entry.test_id, plan.scratch_path
        ));
    }
    validate_command_plan_path_fragment(
        entry,
        "scratch path",
        &plan.scratch_path,
        &test_fragment,
        errors,
    );

    if !is_temp_scoped_path(&plan.mountpoint) {
        errors.push(format!(
            "xfstests policy {} command plan uses non-temporary mountpoint: {}",
            entry.test_id, plan.mountpoint
        ));
    }
    validate_command_plan_path_fragment(
        entry,
        "mountpoint",
        &plan.mountpoint,
        &test_fragment,
        errors,
    );

    if !is_temp_scoped_path(&plan.test_device) {
        errors.push(format!(
            "xfstests policy {} command plan uses non-temporary test device placeholder: {}",
            entry.test_id, plan.test_device
        ));
    }
    validate_command_plan_path_fragment(
        entry,
        "test device placeholder",
        &plan.test_device,
        &test_fragment,
        errors,
    );

    if !is_temp_scoped_path(&plan.scratch_device) {
        errors.push(format!(
            "xfstests policy {} command plan uses non-temporary scratch device placeholder: {}",
            entry.test_id, plan.scratch_device
        ));
    }
    validate_command_plan_path_fragment(
        entry,
        "scratch device placeholder",
        &plan.scratch_device,
        &test_fragment,
        errors,
    );

    if !plan.image_hash.starts_with("sha256:") || plan.image_hash.len() <= "sha256:".len() {
        errors.push(format!(
            "xfstests policy {} command plan is missing image hash",
            entry.test_id
        ));
    }
}

fn validate_command_plan_helpers(
    entry: &XfstestsAllowlistEntry,
    plan: &XfstestsCommandPlan,
    errors: &mut Vec<String>,
) {
    if plan.helper_binaries.is_empty() {
        errors.push(format!(
            "xfstests policy {} command plan is missing helper binaries",
            entry.test_id
        ));
    }
    for helper in &plan.helper_binaries {
        if is_broad_shell_token(helper) || helper.contains('<') || helper.trim().is_empty() {
            errors.push(format!(
                "xfstests policy {} command plan has unresolved helper binary: {helper}",
                entry.test_id
            ));
        }
    }

    if plan.required_privileges.is_empty() {
        errors.push(format!(
            "xfstests policy {} command plan is missing required privileges",
            entry.test_id
        ));
    }
    for privilege in &plan.required_privileges {
        if !KNOWN_XFSTESTS_COMMAND_PLAN_PRIVILEGES.contains(&privilege.as_str()) {
            errors.push(format!(
                "xfstests policy {} command plan has unknown privilege requirement: {privilege}",
                entry.test_id
            ));
        }
    }

    if plan.cleanup_action.trim().is_empty() {
        errors.push(format!(
            "xfstests policy {} command plan is missing cleanup action",
            entry.test_id
        ));
    } else if has_unsafe_cleanup_action(&plan.cleanup_action) {
        errors.push(format!(
            "xfstests policy {} command plan has unsafe cleanup action: {}",
            entry.test_id, plan.cleanup_action
        ));
    }

    if plan.mutation_surface.trim().is_empty() {
        errors.push(format!(
            "xfstests policy {} command plan is missing mutation surface",
            entry.test_id
        ));
    }

    if plan.command_summary.trim().is_empty() {
        errors.push(format!(
            "xfstests policy {} command plan is missing human-readable command summary",
            entry.test_id
        ));
    }
}

fn validate_command_plan_argv(
    entry: &XfstestsAllowlistEntry,
    plan: &XfstestsCommandPlan,
    errors: &mut Vec<String>,
) {
    if plan.argv.is_empty() {
        errors.push(format!(
            "xfstests policy {} command plan is missing argv",
            entry.test_id
        ));
    }
    if !plan.argv.iter().any(|arg| arg == &entry.test_id) {
        errors.push(format!(
            "xfstests policy {} command plan argv does not name the test id",
            entry.test_id
        ));
    }
    for arg in &plan.argv {
        if is_broad_shell_token(arg) || arg.contains("&&") || arg.contains(';') || arg.contains('*')
        {
            errors.push(format!(
                "xfstests policy {} command plan has broad shell command token: {arg}",
                entry.test_id
            ));
        }
    }
}

fn validate_command_plan_path_fragment(
    entry: &XfstestsAllowlistEntry,
    field: &str,
    path: &str,
    test_fragment: &str,
    errors: &mut Vec<String>,
) {
    if !path.contains(test_fragment) {
        errors.push(format!(
            "xfstests policy {} command plan {field} does not include test id fragment {test_fragment}: {path}",
            entry.test_id
        ));
    }
}

fn validate_policy_outcome(entry: &XfstestsAllowlistEntry, errors: &mut Vec<String>) {
    match entry.classification.as_deref() {
        Some(
            "expected_failure"
            | "environment_blocked"
            | "unsupported_by_v1"
            | "harness_blocked"
            | "product_actionable",
        ) => {}
        Some(other) => errors.push(format!(
            "xfstests policy {} has unknown classification: {other}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing classification",
            entry.test_id
        )),
    }

    if entry.failure_reason.trim().is_empty() {
        errors.push(format!(
            "xfstests policy {} is missing outcome rationale",
            entry.test_id
        ));
    }

    let needs_skip_reason = entry.status != "expected_pass";
    if needs_skip_reason && entry.failure_reason.trim().is_empty() {
        errors.push(format!(
            "xfstests policy {} is missing skip reason",
            entry.test_id
        ));
    }

    if entry.classification.as_deref() == Some("unsupported_by_v1") {
        match entry.scope_reference.as_deref() {
            Some(reference) if is_supported_scope_reference(reference) => {}
            Some(reference) => errors.push(format!(
                "xfstests policy {} has stale scope reference: {reference}",
                entry.test_id
            )),
            None => errors.push(format!(
                "xfstests policy {} marks unsupported_by_v1 without scope_reference",
                entry.test_id
            )),
        }
    }

    if entry.status == "wont_fix" && entry.classification.as_deref() != Some("unsupported_by_v1") {
        errors.push(format!(
            "xfstests policy {} is wont_fix without unsupported_by_v1 classification",
            entry.test_id
        ));
    }
}

fn validate_policy_links(entry: &XfstestsAllowlistEntry, errors: &mut Vec<String>) {
    match entry.tracker_id.as_deref() {
        Some(tracker_id) if tracker_id.starts_with("bd-") => {}
        Some(tracker_id) => errors.push(format!(
            "xfstests policy {} has malformed tracker_id: {tracker_id}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing tracker_id",
            entry.test_id
        )),
    }

    match entry.repro_command.as_deref() {
        Some(command) if !command.is_empty() => {}
        Some(_) | None => errors.push(format!(
            "xfstests policy {} is missing reproduction command",
            entry.test_id
        )),
    }
}

fn is_supported_scope_reference(reference: &str) -> bool {
    reference.starts_with("README.md#")
        || reference.starts_with("FEATURE_PARITY.md#")
        || reference == "README.md"
        || reference == "FEATURE_PARITY.md"
}

fn is_known_operation_class(operation_class: &str) -> bool {
    REQUIRED_XFSTESTS_OPERATION_CLASSES.contains(&operation_class)
}

fn is_temp_scoped_path(path: &str) -> bool {
    path.starts_with("${TMPDIR:-/tmp}/frankenfs-xfstests/")
        || path.starts_with("$TMPDIR/frankenfs-xfstests/")
        || path.starts_with("/tmp/frankenfs-xfstests/")
}

fn is_broad_shell_token(token: &str) -> bool {
    matches!(token, "sh" | "bash" | "zsh" | "-c" | "shell")
}

fn has_unsafe_cleanup_action(action: &str) -> bool {
    let lower = action.to_ascii_lowercase();
    lower.contains("rm ")
        || lower.contains("rm-")
        || lower.contains("rm\t")
        || lower.contains("rm -")
        || lower.contains("delete /")
        || lower.contains("remove /")
        || lower.contains("/*")
        || lower.contains("$(")
        || lower.contains('`')
        || lower.contains("&&")
        || lower.contains("||")
}

fn command_plan_test_fragment(test_id: &str) -> String {
    test_id.replace('/', "-")
}

fn expected_outcome_for_classification(entry: &XfstestsAllowlistEntry) -> &'static str {
    match (entry.status.as_str(), entry.classification.as_deref()) {
        ("expected_pass", _) => "expected_pass",
        (_, Some("product_actionable")) => "product_actionable_failure",
        (_, Some("environment_blocked" | "harness_blocked")) => "environment_blocked",
        (_, Some("unsupported_by_v1")) => "unsupported_by_v1",
        _ => "expected_failure",
    }
}

#[must_use]
pub fn parse_check_output(
    selected: &[String],
    check_log: &str,
    check_rc: i32,
    dry_run: bool,
) -> XfstestsRun {
    let mut cases: Vec<XfstestsCase> = selected
        .iter()
        .map(|id| XfstestsCase {
            id: id.clone(),
            status: XfstestsStatus::NotRun,
            duration_secs: None,
            output_snippet: None,
            allowlist_status: None,
            failure_reason: None,
            policy_row_id: None,
            classification: None,
            expected_outcome: None,
            user_risk_category: None,
            expected_operation_class: None,
            required_capabilities: Vec::new(),
            tracker_id: None,
            comparison: Vec::new(),
        })
        .collect();

    for line in check_log.lines() {
        let lower = line.to_ascii_lowercase();
        for case in &mut cases {
            if !line_mentions_test_id(line, case.id.as_str()) {
                continue;
            }

            let candidate = if lower.contains("not run") || lower.contains("notrun") {
                Some(XfstestsStatus::NotRun)
            } else if lower.contains("skipped") {
                Some(XfstestsStatus::Skipped)
            } else if contains_word(&lower, "fail")
                || contains_word(&lower, "failed")
                || contains_word(&lower, "error")
            {
                Some(XfstestsStatus::Failed)
            } else if contains_word(&lower, "pass")
                || contains_word(&lower, "passed")
                || contains_word(&lower, "ok")
                || contains_word(&lower, "success")
            {
                Some(XfstestsStatus::Passed)
            } else {
                None
            };

            if let Some(next) = candidate {
                if next.rank() >= case.status.rank() {
                    case.status = next;
                    case.output_snippet = Some(line.trim().to_owned());
                }
                if case.duration_secs.is_none() {
                    case.duration_secs = parse_duration_secs(line);
                }
            }
        }
    }

    summarize_run("check-log", check_rc, dry_run, cases)
}

#[must_use]
pub fn summarize_uniform(
    selected: &[String],
    status: XfstestsStatus,
    note: Option<&str>,
) -> XfstestsRun {
    let cases = selected
        .iter()
        .map(|id| XfstestsCase {
            id: id.clone(),
            status,
            duration_secs: None,
            output_snippet: note.map(ToOwned::to_owned),
            allowlist_status: None,
            failure_reason: None,
            policy_row_id: None,
            classification: None,
            expected_outcome: None,
            user_risk_category: None,
            expected_operation_class: None,
            required_capabilities: Vec::new(),
            tracker_id: None,
            comparison: Vec::new(),
        })
        .collect();
    summarize_run("uniform", 0, false, cases)
}

pub fn apply_allowlist(run: &mut XfstestsRun, allowlist: &[XfstestsAllowlistEntry]) {
    let by_test: BTreeMap<&str, &XfstestsAllowlistEntry> = allowlist
        .iter()
        .map(|entry| (entry.test_id.as_str(), entry))
        .collect();
    for case in &mut run.tests {
        if let Some(entry) = by_test.get(case.id.as_str()) {
            case.allowlist_status = Some(entry.status.clone());
            case.failure_reason = Some(entry.failure_reason.clone());
            case.policy_row_id = entry.policy_row_id.clone();
            case.classification = entry.classification.clone();
            case.expected_outcome = entry.expected_outcome.clone();
            case.user_risk_category = entry.user_risk_category.clone();
            case.expected_operation_class = entry.expected_operation_class.clone();
            case.required_capabilities = entry.required_capabilities.clone();
            case.tracker_id = entry.tracker_id.clone();
        }
    }
    refresh_policy_summary(run);
}

pub fn compare_against_baseline(
    run: &mut XfstestsRun,
    baseline: &[XfstestsBaselineEntry],
) -> XfstestsComparison {
    let baseline_map: BTreeMap<&str, XfstestsStatus> = baseline
        .iter()
        .map(|entry| (entry.test_id.as_str(), entry.expected_status))
        .collect();
    let mut comparison = XfstestsComparison::default();

    for case in &mut run.tests {
        let Some(expected) = baseline_map.get(case.id.as_str()).copied() else {
            continue;
        };

        if expected == case.status {
            comparison.unchanged.push(case.id.clone());
            case.comparison
                .push(format!("baseline match: {}", expected.as_str()));
            continue;
        }

        let message = format!("{} -> {}", expected.as_str(), case.status.as_str());
        match (expected, case.status) {
            (
                XfstestsStatus::Passed,
                XfstestsStatus::Failed | XfstestsStatus::Skipped | XfstestsStatus::NotRun,
            ) => {
                comparison
                    .regressions
                    .push(format!("{} ({message})", case.id));
                case.comparison.push(format!("regression: {message}"));
            }
            (
                XfstestsStatus::Failed | XfstestsStatus::Skipped | XfstestsStatus::NotRun,
                XfstestsStatus::Passed,
            ) => {
                comparison
                    .improvements
                    .push(format!("{} ({message})", case.id));
                case.comparison.push(format!("improvement: {message}"));
            }
            _ => {
                comparison.unchanged.push(case.id.clone());
                case.comparison.push(format!("status drift: {message}"));
            }
        }
    }

    comparison
}

pub fn write_junit_xml(path: &Path, run: &XfstestsRun) -> Result<()> {
    let failures = run.failed;
    let skipped = run.skipped + run.not_run + run.planned;
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        xml,
        "<testsuite name=\"ffs_xfstests_e2e\" tests=\"{}\" failures=\"{}\" skipped=\"{}\">",
        run.total, failures, skipped
    );

    for case in &run.tests {
        let _ = write!(
            xml,
            "  <testcase name=\"{}\" time=\"{:.3}\">",
            escape_xml(&case.id),
            case.duration_secs.unwrap_or(0.0)
        );
        match case.status {
            XfstestsStatus::Failed => {
                let detail = case
                    .output_snippet
                    .as_deref()
                    .or(case.failure_reason.as_deref())
                    .unwrap_or("xfstests failure");
                let detail = escape_xml(detail);
                let _ = write!(
                    xml,
                    "<failure message=\"xfstests failure\">{detail}</failure>"
                );
            }
            XfstestsStatus::Skipped | XfstestsStatus::NotRun | XfstestsStatus::Planned => {
                let detail = escape_xml(case.status.as_str());
                let _ = write!(xml, "<skipped message=\"{detail}\"/>");
            }
            XfstestsStatus::Passed => {}
        }
        xml.push_str("</testcase>\n");
    }
    xml.push_str("</testsuite>\n");
    fs::write(path, xml).with_context(|| format!("failed to write junit xml {}", path.display()))
}

fn summarize_run(
    source: &str,
    check_rc: i32,
    dry_run: bool,
    tests: Vec<XfstestsCase>,
) -> XfstestsRun {
    let mut passed = 0_usize;
    let mut failed = 0_usize;
    let mut skipped = 0_usize;
    let mut not_run = 0_usize;
    let mut planned = 0_usize;

    for case in &tests {
        match case.status {
            XfstestsStatus::Passed => passed += 1,
            XfstestsStatus::Failed => failed += 1,
            XfstestsStatus::Skipped => skipped += 1,
            XfstestsStatus::NotRun => not_run += 1,
            XfstestsStatus::Planned => planned += 1,
        }
    }

    let total = tests.len();
    let pass_rate = if total == 0 {
        0.0
    } else {
        passed as f64 / total as f64
    };

    XfstestsRun {
        source: source.to_owned(),
        check_rc,
        dry_run,
        total,
        passed,
        failed,
        skipped,
        not_run,
        planned,
        pass_rate,
        policy_summary: XfstestsPolicySummary::default(),
        tests,
    }
}

fn refresh_policy_summary(run: &mut XfstestsRun) {
    let mut summary = XfstestsPolicySummary::default();

    for case in &run.tests {
        bump_count_if_present(
            &mut summary.by_allowlist_status,
            case.allowlist_status.as_deref(),
        );
        bump_count_if_present(
            &mut summary.by_classification,
            case.classification.as_deref(),
        );
        bump_count_if_present(
            &mut summary.by_expected_outcome,
            case.expected_outcome.as_deref(),
        );
        bump_count_if_present(
            &mut summary.by_user_risk_category,
            case.user_risk_category.as_deref(),
        );
        bump_count_if_present(
            &mut summary.by_operation_class,
            case.expected_operation_class.as_deref(),
        );

        if case.status == XfstestsStatus::NotRun
            && let Some(classification) = case.classification.as_ref()
        {
            *summary
                .not_run_by_classification
                .entry(classification.clone())
                .or_default() += 1;
        }
    }

    run.policy_summary = summary;
}

fn bump_count_if_present(counts: &mut BTreeMap<String, usize>, value: Option<&str>) {
    if let Some(value) = value {
        *counts.entry(value.to_owned()).or_default() += 1;
    }
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    haystack
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '/')
        .any(|part| part == needle)
}

fn line_mentions_test_id(line: &str, test_id: &str) -> bool {
    line.split_whitespace().any(|part| part == test_id)
}

fn parse_duration_secs(line: &str) -> Option<f64> {
    for token in line.split_whitespace() {
        if let Some(raw) = token.strip_suffix('s')
            && let Ok(value) = raw.parse::<f64>()
        {
            return Some(value);
        }
    }
    None
}

fn escape_xml(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn baseline_status_for_case(
    case: &XfstestsCase,
    cleanup_status: &str,
) -> XfstestsBaselineRowStatus {
    if cleanup_status.contains("interrupted") {
        return XfstestsBaselineRowStatus::Interrupted;
    }
    if cleanup_status.contains("resumed") {
        return XfstestsBaselineRowStatus::Resumed;
    }

    match case.status {
        XfstestsStatus::Passed => XfstestsBaselineRowStatus::Passed,
        XfstestsStatus::Failed => XfstestsBaselineRowStatus::Failed,
        XfstestsStatus::Skipped => XfstestsBaselineRowStatus::Skipped,
        XfstestsStatus::Planned | XfstestsStatus::NotRun => match case.classification.as_deref() {
            Some("unsupported_by_v1") => XfstestsBaselineRowStatus::Unsupported,
            Some("environment_blocked") => XfstestsBaselineRowStatus::HostBlocked,
            Some("harness_blocked") => XfstestsBaselineRowStatus::HarnessFailed,
            _ => XfstestsBaselineRowStatus::NotRun,
        },
    }
}

fn remediation_for_status(
    status: XfstestsBaselineRowStatus,
    resume_command: &str,
) -> Option<String> {
    match status {
        XfstestsBaselineRowStatus::NotRun
        | XfstestsBaselineRowStatus::Interrupted
        | XfstestsBaselineRowStatus::HostBlocked
        | XfstestsBaselineRowStatus::HarnessFailed => Some(resume_command.to_owned()),
        XfstestsBaselineRowStatus::Unsupported => {
            Some("document unsupported scope rationale before failure triage".to_owned())
        }
        XfstestsBaselineRowStatus::Passed
        | XfstestsBaselineRowStatus::Failed
        | XfstestsBaselineRowStatus::Skipped
        | XfstestsBaselineRowStatus::Resumed => None,
    }
}

fn disposition_counts(cases: &[XfstestsBaselineCase]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for case in cases {
        *counts.entry(case.status.as_str().to_owned()).or_default() += 1;
    }
    counts
}

fn failure_triage_disposition_counts(
    report: &XfstestsFailureTriageReport,
) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for bead in &report.proposed_beads {
        *counts
            .entry(XfstestsBaselineRowStatus::Failed.as_str().to_owned())
            .or_default() += bead.related_test_ids.len();
    }
    for excluded in &report.excluded_rows {
        *counts.entry(excluded.status.clone()).or_default() += 1;
    }
    counts
}

fn failure_triage_duplicate_groups(
    proposed_beads: &[XfstestsProposedFailureBead],
) -> Vec<XfstestsFailureDuplicateGroup> {
    proposed_beads
        .iter()
        .filter(|bead| bead.related_test_ids.len() > 1)
        .map(|bead| XfstestsFailureDuplicateGroup {
            duplicate_key: bead.duplicate_key.clone(),
            primary_test_id: bead.failing_test_id.clone(),
            merged_test_ids: bead.related_test_ids.clone(),
        })
        .collect()
}

fn validate_failure_triage_row_uniqueness(
    report: &XfstestsFailureTriageReport,
    errors: &mut Vec<String>,
) {
    let mut owner_by_test_id = BTreeMap::new();
    for bead in &report.proposed_beads {
        let owner = format!("proposed bead {}", bead.proposed_id_placeholder);
        let mut local_related_ids = BTreeSet::new();
        for test_id in &bead.related_test_ids {
            if !local_related_ids.insert(test_id.as_str()) {
                errors.push(format!(
                    "xfstests failure triage proposed bead {} repeats related_test_id {test_id}",
                    bead.proposed_id_placeholder
                ));
            }
            if let Some(previous_owner) = owner_by_test_id.insert(test_id.clone(), owner.clone()) {
                errors.push(format!(
                    "xfstests failure triage row {test_id} appears in multiple dispositions: {previous_owner}; {owner}"
                ));
            }
        }
    }
    for excluded in &report.excluded_rows {
        let owner = format!("excluded row {}", excluded.test_id);
        if let Some(previous_owner) =
            owner_by_test_id.insert(excluded.test_id.clone(), owner.clone())
        {
            errors.push(format!(
                "xfstests failure triage row {} appears in multiple dispositions: {previous_owner}; {owner}",
                excluded.test_id
            ));
        }
    }
}

fn validate_failure_triage_excluded_row(
    excluded: &XfstestsFailureTriageExcludedRow,
    errors: &mut Vec<String>,
) {
    require_non_empty("excluded.test_id", &excluded.test_id, errors);
    require_non_empty("excluded.status", &excluded.status, errors);
    require_non_empty("excluded.classification", &excluded.classification, errors);
    require_non_empty("excluded.reason", &excluded.reason, errors);
    if !XFSTESTS_BASELINE_STATUS_VOCABULARY
        .iter()
        .any(|status| excluded.status == status.as_str())
    {
        errors.push(format!(
            "xfstests failure triage excluded row {} has unknown status {}",
            excluded.test_id, excluded.status
        ));
    }
    if !is_canonical_sha256(&excluded.raw_log_hash) {
        errors.push(format!(
            "xfstests failure triage excluded row {} has malformed raw_log_hash",
            excluded.test_id
        ));
    }
    if excluded.status == XfstestsBaselineRowStatus::Failed.as_str()
        && excluded.classification == "product_actionable"
    {
        errors.push(format!(
            "xfstests failure triage excluded row {} is product_actionable and must be proposed as a product bead",
            excluded.test_id
        ));
    }
}

fn is_canonical_sha256(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}

fn hash_raw_artifact(path: &Path) -> Result<XfstestsRawArtifact> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read raw xfstests artifact {}", path.display()))?;
    Ok(XfstestsRawArtifact {
        path: path.display().to_string(),
        sha256: sha256_hex(&bytes),
        immutable: true,
    })
}

fn hash_raw_artifact_set(raw_artifacts: &[XfstestsRawArtifact]) -> String {
    let mut hasher = Sha256::new();
    for artifact in raw_artifacts {
        hasher.update(artifact.path.as_bytes());
        hasher.update([0]);
        hasher.update(artifact.sha256.as_bytes());
        hasher.update([0]);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn require_non_empty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("xfstests baseline manifest missing {field}"));
    }
}

fn validate_raw_artifact(artifact: &XfstestsRawArtifact, errors: &mut Vec<String>) {
    if artifact.path.trim().is_empty() {
        errors.push("xfstests baseline raw artifact missing path".to_owned());
        return;
    }
    if !artifact.immutable {
        errors.push(format!(
            "xfstests baseline raw artifact {} is not immutable",
            artifact.path
        ));
    }
    if !is_canonical_sha256(&artifact.sha256) {
        errors.push(format!(
            "xfstests baseline raw artifact {} has malformed sha256",
            artifact.path
        ));
        return;
    }
    match fs::read(&artifact.path) {
        Ok(bytes) => {
            let actual = sha256_hex(&bytes);
            if actual != artifact.sha256 {
                errors.push(format!(
                    "xfstests baseline raw artifact hash changed: {} expected={} actual={actual}",
                    artifact.path, artifact.sha256
                ));
            }
        }
        Err(err) => errors.push(format!(
            "xfstests baseline raw artifact missing: {} ({err})",
            artifact.path
        )),
    }
}

fn validate_case_raw_refs(
    consumer: &str,
    case: &XfstestsBaselineCase,
    raw_by_path: &BTreeMap<&str, &XfstestsRawArtifact>,
    errors: &mut Vec<String>,
) {
    let mut artifacts: Vec<XfstestsRawArtifact> = Vec::new();
    for raw_ref in &case.raw_artifact_refs {
        match raw_by_path.get(raw_ref.as_str()) {
            Some(artifact) if artifact.immutable => artifacts.push((*artifact).clone()),
            Some(_) => errors.push(format!(
                "xfstests {consumer} case {} references mutable raw artifact {}",
                case.test_id, raw_ref
            )),
            None => errors.push(format!(
                "xfstests {consumer} case {} references unknown raw artifact {}",
                case.test_id, raw_ref
            )),
        }
    }
    if artifacts.is_empty() {
        errors.push(format!(
            "xfstests {consumer} case {} has no consumable raw artifacts",
            case.test_id
        ));
        return;
    }
    let actual_hash = hash_raw_artifact_set(&artifacts);
    if case.raw_log_hash != actual_hash {
        errors.push(format!(
            "xfstests {consumer} case {} raw_log_hash does not match referenced immutable artifacts: expected={} actual={actual_hash}",
            case.test_id, case.raw_log_hash
        ));
    }
}

fn validate_baseline_case(case: &XfstestsBaselineCase, errors: &mut Vec<String>) {
    require_non_empty("case.test_id", &case.test_id, errors);
    require_non_empty("case.command", &case.command, errors);
    require_non_empty(
        "case.partial_run_checkpoint",
        &case.partial_run_checkpoint,
        errors,
    );
    require_non_empty("case.resume_command", &case.resume_command, errors);
    require_non_empty("case.cleanup_status", &case.cleanup_status, errors);
    if case.raw_artifact_refs.is_empty() {
        errors.push(format!(
            "xfstests baseline case {} has no raw artifact refs",
            case.test_id
        ));
    }
    if !is_canonical_sha256(&case.raw_log_hash) {
        errors.push(format!(
            "xfstests baseline case {} has malformed raw_log_hash",
            case.test_id
        ));
    }
    if !case.immutable_raw_artifacts {
        errors.push(format!(
            "xfstests baseline case {} does not prove immutable raw artifacts",
            case.test_id
        ));
    }
    if matches!(
        case.status,
        XfstestsBaselineRowStatus::NotRun
            | XfstestsBaselineRowStatus::Interrupted
            | XfstestsBaselineRowStatus::HostBlocked
            | XfstestsBaselineRowStatus::HarnessFailed
    ) && case
        .remediation
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        errors.push(format!(
            "xfstests baseline case {} lacks remediation for {:?}",
            case.test_id, case.status
        ));
    }
}

fn is_product_failure_row(case: &XfstestsBaselineCase) -> bool {
    case.status == XfstestsBaselineRowStatus::Failed && case.classification == "product_actionable"
}

fn xfstests_id_fragment(test_id: &str) -> String {
    test_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn trim_known_xfstests_env_assignments(command: &str) -> &str {
    let mut rest = command.trim_start();
    loop {
        let Some(split_index) = rest.find(char::is_whitespace) else {
            return rest;
        };
        let (token, tail) = rest.split_at(split_index);
        if [
            "XFSTESTS_MODE=",
            "XFSTESTS_FILTER=",
            "XFSTESTS_DRY_RUN=",
            "XFSTESTS_SYNTHETIC_TRIAGE_FIXTURE=",
        ]
        .iter()
        .any(|prefix| token.starts_with(prefix))
        {
            rest = tail.trim_start();
        } else {
            return rest;
        }
    }
}

fn failure_triage_validation_command(
    filesystem_flavor: &str,
    reproduction_command: &str,
) -> String {
    let invocation = trim_known_xfstests_env_assignments(reproduction_command);
    if synthetic_triage_fixture_enabled(reproduction_command) {
        format!(
            "XFSTESTS_SYNTHETIC_TRIAGE_FIXTURE=1 XFSTESTS_MODE=plan XFSTESTS_DRY_RUN=1 XFSTESTS_FILTER=all {invocation}"
        )
    } else {
        format!(
            "XFSTESTS_MODE=run XFSTESTS_FILTER={filesystem_flavor} XFSTESTS_DRY_RUN=0 {invocation}"
        )
    }
}

fn synthetic_triage_fixture_enabled(command: &str) -> bool {
    command.split_whitespace().any(|token| {
        matches!(
            token.strip_prefix("XFSTESTS_SYNTHETIC_TRIAGE_FIXTURE="),
            Some("1")
        )
    })
}

fn proposed_failure_bead(
    index: usize,
    case: &XfstestsBaselineCase,
    manifest: &XfstestsBaselineManifest,
    reproduction_command: &str,
) -> XfstestsProposedFailureBead {
    let filesystem_flavor = filesystem_flavor_for_test(&case.test_id);
    let suspected_crate_boundary = suspected_boundary_for_test(&case.test_id).to_owned();
    let actual_behavior = actual_behavior_for_case(case);
    let expected_behavior = expected_behavior_for_case(case, &filesystem_flavor);
    let duplicate_key = duplicate_key_for_case(case, &suspected_crate_boundary, &actual_behavior);
    let validation_command =
        failure_triage_validation_command(&filesystem_flavor, reproduction_command);
    let title = format!(
        "xfstests {} product failure in {}",
        case.test_id, suspected_crate_boundary
    );
    let fixture_recipe = sparse_fixture_recipe_for_case(
        case,
        &filesystem_flavor,
        &suspected_crate_boundary,
        &expected_behavior,
        &actual_behavior,
        &validation_command,
    );
    XfstestsProposedFailureBead {
        proposed_id_placeholder: format!("dry-run-xfstests-product-failure-{index:04}"),
        title,
        failing_test_id: case.test_id.clone(),
        related_test_ids: vec![case.test_id.clone()],
        filesystem_flavor: filesystem_flavor.clone(),
        exact_command: case.command.clone(),
        normalized_outcome: case.status.as_str().to_owned(),
        expected_behavior,
        actual_behavior,
        suspected_crate_boundary,
        minimized_repro_command: Some(case.command.clone()),
        minimization_status: "command_is_single_xfstests_row".to_owned(),
        duplicate_key,
        labels: vec![
            "xfstests".to_owned(),
            "conformance".to_owned(),
            "product-bug".to_owned(),
            filesystem_flavor,
        ],
        dependency_beads: vec!["bd-rchk3.4".to_owned(), manifest.baseline_id.clone()],
        dependency_rationale:
            "proposed product bead depends on reviewed xfstests triage policy and immutable baseline artifacts"
                .to_owned(),
        validation_command,
        raw_log_refs: case.raw_artifact_refs.clone(),
        raw_log_hash: case.raw_log_hash.clone(),
        fixture_recipe,
        live_create: false,
    }
}

fn merge_raw_refs(existing: &mut XfstestsProposedFailureBead, case: &XfstestsBaselineCase) {
    for raw_ref in &case.raw_artifact_refs {
        if !existing.raw_log_refs.contains(raw_ref) {
            existing.raw_log_refs.push(raw_ref.clone());
        }
        if !existing
            .fixture_recipe
            .source_raw_log_refs
            .contains(raw_ref)
        {
            existing
                .fixture_recipe
                .source_raw_log_refs
                .push(raw_ref.clone());
        }
    }
    if !existing
        .fixture_recipe
        .related_test_ids
        .contains(&case.test_id)
    {
        existing
            .fixture_recipe
            .related_test_ids
            .push(case.test_id.clone());
    }
}

fn sparse_fixture_recipe_for_case(
    case: &XfstestsBaselineCase,
    filesystem_flavor: &str,
    suspected_crate_boundary: &str,
    expected_behavior: &str,
    actual_behavior: &str,
    validation_command: &str,
) -> XfstestsSparseFixtureRecipe {
    let test_fragment = xfstests_id_fragment(&case.test_id);
    let proposed_fixture_path = format!("conformance/fixtures/xfstests/{test_fragment}.json");
    XfstestsSparseFixtureRecipe {
        schema_version: 1,
        recipe_id: format!("xfstests-sparse-fixture-{test_fragment}"),
        source_xfstests_id: case.test_id.clone(),
        related_test_ids: vec![case.test_id.clone()],
        filesystem_flavor: filesystem_flavor.to_owned(),
        suspected_crate_boundary: suspected_crate_boundary.to_owned(),
        fixture_manifest_kind: "sparse_fixture_generation_recipe".to_owned(),
        proposed_fixture_path: proposed_fixture_path.clone(),
        source_raw_log_refs: case.raw_artifact_refs.clone(),
        source_raw_log_hash: case.raw_log_hash.clone(),
        minimized_reproducer_command: case.command.clone(),
        expected_behavior: expected_behavior.to_owned(),
        actual_behavior: actual_behavior.to_owned(),
        validation_command: validation_command.to_owned(),
        dependency_hints: vec![
            "bd-rchk3.4".to_owned(),
            "review immutable xfstests baseline before live bead creation".to_owned(),
            format!("suspected boundary: {suspected_crate_boundary}"),
        ],
        recipe_steps: vec![
            format!("replay the single xfstests row with `{}`", case.command),
            "capture the smallest failing filesystem image or metadata region after reproducing the failure".to_owned(),
            format!(
                "convert the minimized bytes into `{}` using `ffs-harness generate-fixture <image> region <offset> <len>` when a bounded region is known",
                proposed_fixture_path
            ),
            "add a fixture-driven harness assertion before changing product code".to_owned(),
        ],
        promotion_status: "dry_run_recipe_only".to_owned(),
        live_fixture_write_enabled: false,
    }
}

fn excluded_triage_row(case: &XfstestsBaselineCase) -> XfstestsFailureTriageExcludedRow {
    let reason = match (case.status, case.classification.as_str()) {
        (XfstestsBaselineRowStatus::Passed, _) => "passed rows do not create failure beads",
        (XfstestsBaselineRowStatus::Skipped, _) => "skipped rows require no product bead",
        (XfstestsBaselineRowStatus::NotRun, _) => "not-run rows require remediation or rerun first",
        (XfstestsBaselineRowStatus::Unsupported, _) => {
            "unsupported-scope rows must not pollute product backlog"
        }
        (XfstestsBaselineRowStatus::HostBlocked, _) => "host-blocked rows are environment work",
        (XfstestsBaselineRowStatus::HarnessFailed, _) => "harness failures are harness work",
        (XfstestsBaselineRowStatus::Interrupted, _) => {
            "interrupted rows need resume before failure triage"
        }
        (XfstestsBaselineRowStatus::Resumed, _) => {
            "resumed rows are evidence metadata, not product failures"
        }
        (XfstestsBaselineRowStatus::Failed, "environment_blocked") => {
            "environment failure excluded from product backlog"
        }
        (XfstestsBaselineRowStatus::Failed, "harness_blocked") => {
            "harness failure excluded from product backlog"
        }
        (XfstestsBaselineRowStatus::Failed, "unsupported_by_v1") => {
            "unsupported failure excluded from product backlog"
        }
        (XfstestsBaselineRowStatus::Failed, _) => "failed row is not classified product_actionable",
    };
    XfstestsFailureTriageExcludedRow {
        test_id: case.test_id.clone(),
        status: case.status.as_str().to_owned(),
        classification: case.classification.clone(),
        reason: reason.to_owned(),
        raw_log_hash: case.raw_log_hash.clone(),
        remediation: case.remediation.clone(),
    }
}

fn validate_proposed_failure_bead(
    bead: &XfstestsProposedFailureBead,
    duplicate_keys: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    require_non_empty(
        "proposed.proposed_id_placeholder",
        &bead.proposed_id_placeholder,
        errors,
    );
    require_non_empty("proposed.title", &bead.title, errors);
    require_non_empty("proposed.failing_test_id", &bead.failing_test_id, errors);
    require_non_empty("proposed.exact_command", &bead.exact_command, errors);
    require_non_empty(
        "proposed.expected_behavior",
        &bead.expected_behavior,
        errors,
    );
    require_non_empty("proposed.actual_behavior", &bead.actual_behavior, errors);
    require_non_empty("proposed.duplicate_key", &bead.duplicate_key, errors);
    require_non_empty(
        "proposed.validation_command",
        &bead.validation_command,
        errors,
    );
    if !duplicate_keys.insert(bead.duplicate_key.clone()) {
        errors.push(format!(
            "xfstests failure triage duplicate proposed bead key: {}",
            bead.duplicate_key
        ));
    }
    if !KNOWN_XFSTESTS_TRIAGE_BOUNDARIES.contains(&bead.suspected_crate_boundary.as_str()) {
        errors.push(format!(
            "xfstests failure triage has unknown suspected boundary: {}",
            bead.suspected_crate_boundary
        ));
    }
    if bead.related_test_ids.is_empty() || !bead.related_test_ids.contains(&bead.failing_test_id) {
        errors.push(format!(
            "xfstests failure triage proposed bead {} must include primary failing test in related_test_ids",
            bead.proposed_id_placeholder
        ));
    }
    if bead.minimized_repro_command.is_none() && !bead.minimization_status.contains("non_minimized")
    {
        errors.push(format!(
            "xfstests failure triage proposed bead {} needs minimized repro or explicit non-minimized follow-up",
            bead.proposed_id_placeholder
        ));
    }
    if !bead.labels.iter().any(|label| label == "xfstests")
        || !bead.labels.iter().any(|label| label == "product-bug")
    {
        errors.push(format!(
            "xfstests failure triage proposed bead {} missing required labels",
            bead.proposed_id_placeholder
        ));
    }
    if bead.dependency_beads.is_empty() || bead.dependency_rationale.trim().is_empty() {
        errors.push(format!(
            "xfstests failure triage proposed bead {} missing dependency rationale",
            bead.proposed_id_placeholder
        ));
    }
    if bead.raw_log_refs.is_empty() || !is_canonical_sha256(&bead.raw_log_hash) {
        errors.push(format!(
            "xfstests failure triage proposed bead {} missing raw log refs/hash",
            bead.proposed_id_placeholder
        ));
    }
    validate_proposed_failure_bead_fixture_link(bead, errors);
    if bead.live_create {
        errors.push(format!(
            "xfstests failure triage proposed bead {} must not create live beads",
            bead.proposed_id_placeholder
        ));
    }
}

fn validate_proposed_failure_bead_fixture_link(
    bead: &XfstestsProposedFailureBead,
    errors: &mut Vec<String>,
) {
    if bead.fixture_recipe.source_xfstests_id != bead.failing_test_id {
        errors.push(format!(
            "xfstests failure triage proposed bead {} fixture source does not match failing_test_id",
            bead.proposed_id_placeholder
        ));
    }
    if bead.fixture_recipe.source_raw_log_hash != bead.raw_log_hash {
        errors.push(format!(
            "xfstests failure triage proposed bead {} fixture raw hash does not match bead raw hash",
            bead.proposed_id_placeholder
        ));
    }
    if bead.fixture_recipe.validation_command != bead.validation_command {
        errors.push(format!(
            "xfstests failure triage proposed bead {} fixture validation command drifted",
            bead.proposed_id_placeholder
        ));
    }
    if bead.fixture_recipe.expected_behavior != bead.expected_behavior
        || bead.fixture_recipe.actual_behavior != bead.actual_behavior
    {
        errors.push(format!(
            "xfstests failure triage proposed bead {} fixture behavior summary drifted",
            bead.proposed_id_placeholder
        ));
    }
    for related_test_id in &bead.related_test_ids {
        if !bead
            .fixture_recipe
            .related_test_ids
            .contains(related_test_id)
        {
            errors.push(format!(
                "xfstests failure triage proposed bead {} fixture recipe missing related test {related_test_id}",
                bead.proposed_id_placeholder
            ));
        }
    }
}

impl XfstestsProposedFailureBead {
    fn proposed_br_command(&self) -> String {
        format!(
            "DRY_RUN br create --title '{}' --type bug --priority 1 --labels '{}' --description '{}' --depends-on '{}' --no-db --json",
            shell_single_quote(&self.title),
            shell_single_quote(&self.labels.join(",")),
            shell_single_quote(&format!(
                "xfstests={} expected={} actual={} validation={} raw_hash={} duplicate_key={}",
                self.failing_test_id,
                self.expected_behavior,
                self.actual_behavior,
                self.validation_command,
                self.raw_log_hash,
                self.duplicate_key
            )),
            shell_single_quote(&self.dependency_beads.join(","))
        )
    }
}

fn filesystem_flavor_for_test(test_id: &str) -> String {
    test_id
        .split_once('/')
        .map_or("generic", |(prefix, _)| prefix)
        .to_owned()
}

fn suspected_boundary_for_test(test_id: &str) -> &'static str {
    if test_id.starts_with("ext4/") {
        "ffs-ext4"
    } else if test_id.starts_with("btrfs/") {
        "ffs-btrfs"
    } else {
        "ffs-core"
    }
}

fn expected_behavior_for_case(case: &XfstestsBaselineCase, filesystem_flavor: &str) -> String {
    format!(
        "{} should satisfy Linux xfstests row {} for the {} compatibility surface",
        case.command, case.test_id, filesystem_flavor
    )
}

fn actual_behavior_for_case(case: &XfstestsBaselineCase) -> String {
    case.not_run_reason.clone().unwrap_or_else(|| {
        format!(
            "xfstests row {} ended with normalized status {}",
            case.test_id,
            case.status.as_str()
        )
    })
}

fn duplicate_key_for_case(
    case: &XfstestsBaselineCase,
    suspected_boundary: &str,
    actual_behavior: &str,
) -> String {
    format!(
        "{}:{}:{}",
        suspected_boundary,
        case.status.as_str(),
        normalize_duplicate_fragment(actual_behavior)
    )
}

fn normalize_duplicate_fragment(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .take(12)
        .collect::<Vec<_>>()
        .join("-")
}

fn shell_single_quote(value: &str) -> String {
    value.replace('\'', "'\\''")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn repo_xfstests_allowlist_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("scripts")
            .join("e2e")
            .join("xfstests_allowlist.json")
    }

    fn repo_xfstests_list_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("scripts")
            .join("e2e")
            .join(name)
    }

    fn valid_policy_entry(test_id: &str) -> XfstestsAllowlistEntry {
        let filesystem_flavor = test_id.split('/').next().unwrap_or("generic").to_owned();
        XfstestsAllowlistEntry {
            test_id: test_id.to_owned(),
            failure_reason: "selected canary; failure is product-actionable".to_owned(),
            status: "expected_pass".to_owned(),
            policy_row_id: Some(format!("xfstests-policy-{}", test_id.replace('/', "-"))),
            filesystem_flavor: Some(filesystem_flavor),
            v1_scope_mapping: Some("README.md#v1-filesystem-scope".to_owned()),
            expected_operation_class: Some("read_only_mount".to_owned()),
            operation_class_tags: Vec::new(),
            user_risk_category: Some("data_visibility".to_owned()),
            expected_outcome: Some("expected_pass".to_owned()),
            selection_decision: Some("selected".to_owned()),
            artifact_requirements: REQUIRED_XFSTESTS_ARTIFACTS
                .iter()
                .map(|artifact| (*artifact).to_owned())
                .collect(),
            required_capabilities: vec!["fuse_mount".to_owned()],
            classification: Some("product_actionable".to_owned()),
            scope_reference: None,
            tracker_id: Some("bd-rchk3.2".to_owned()),
            repro_command: Some(format!("./check -n {test_id}")),
            command_plan: Some(XfstestsCommandPlan {
                plan_id: format!("xfstests-plan-{}", test_id.replace('/', "-")),
                execution_lane: "dry_run_only".to_owned(),
                image_path: format!(
                    "${{TMPDIR:-/tmp}}/frankenfs-xfstests/images/{}.img",
                    test_id.replace('/', "-")
                ),
                scratch_path: format!(
                    "${{TMPDIR:-/tmp}}/frankenfs-xfstests/scratch/{}",
                    test_id.replace('/', "-")
                ),
                mountpoint: format!(
                    "${{TMPDIR:-/tmp}}/frankenfs-xfstests/mnt/{}",
                    test_id.replace('/', "-")
                ),
                test_device: format!(
                    "${{TMPDIR:-/tmp}}/frankenfs-xfstests/devices/{}.test.img",
                    test_id.replace('/', "-")
                ),
                scratch_device: format!(
                    "${{TMPDIR:-/tmp}}/frankenfs-xfstests/devices/{}.scratch.img",
                    test_id.replace('/', "-")
                ),
                image_hash: format!("sha256:test-fixture-{}", test_id.replace('/', "-")),
                helper_binaries: vec![
                    "xfstests/check".to_owned(),
                    "ffs-cli".to_owned(),
                    "fusermount3".to_owned(),
                ],
                required_privileges: vec!["none".to_owned(), "fuse_mount".to_owned()],
                mutation_surface: "dry-run command selection under temp root".to_owned(),
                cleanup_action: "umount temp mountpoint if mounted; remove temp scratch root"
                    .to_owned(),
                argv: vec!["./check".to_owned(), "-n".to_owned(), test_id.to_owned()],
                destructive: false,
                expected_plan_outcome: "dry_run_only".to_owned(),
                command_summary: format!("dry-run xfstests plan for {test_id} under temp root"),
            }),
        }
    }

    fn test_case(id: &str, status: XfstestsStatus, classification: Option<&str>) -> XfstestsCase {
        XfstestsCase {
            id: id.to_owned(),
            status,
            duration_secs: None,
            output_snippet: Some(format!("{id} {status:?}")),
            allowlist_status: None,
            failure_reason: None,
            policy_row_id: None,
            classification: classification.map(ToOwned::to_owned),
            expected_outcome: None,
            user_risk_category: None,
            expected_operation_class: None,
            required_capabilities: Vec::new(),
            tracker_id: None,
            comparison: Vec::new(),
        }
    }

    fn baseline_case(id: &str, status: XfstestsBaselineRowStatus) -> XfstestsBaselineCase {
        XfstestsBaselineCase {
            test_id: id.to_owned(),
            status,
            raw_artifact_refs: vec!["raw.log".to_owned()],
            raw_log_hash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
            command: "./check generic/001".to_owned(),
            not_run_reason: None,
            partial_run_checkpoint: "checkpoint:001".to_owned(),
            resume_command: "XFSTESTS_MODE=run ./scripts/e2e/ffs_xfstests_e2e.sh".to_owned(),
            cleanup_status: "artifacts_preserved".to_owned(),
            immutable_raw_artifacts: true,
            classification: "product_actionable".to_owned(),
            remediation: matches!(
                status,
                XfstestsBaselineRowStatus::NotRun
                    | XfstestsBaselineRowStatus::Interrupted
                    | XfstestsBaselineRowStatus::HostBlocked
                    | XfstestsBaselineRowStatus::HarnessFailed
                    | XfstestsBaselineRowStatus::Unsupported
            )
            .then(|| "rerun or classify before triage".to_owned()),
        }
    }

    fn canonicalize_baseline_case_hashes(manifest: &mut XfstestsBaselineManifest) {
        const CANONICAL_RAW_LOG_HASH: &str =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        for case in &mut manifest.cases {
            case.raw_log_hash = CANONICAL_RAW_LOG_HASH.to_owned();
        }
    }

    fn canonicalize_failure_triage_hashes(report: &mut XfstestsFailureTriageReport) {
        const CANONICAL_RAW_LOG_HASH: &str =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        for bead in &mut report.proposed_beads {
            bead.raw_log_hash = CANONICAL_RAW_LOG_HASH.to_owned();
            bead.fixture_recipe.source_raw_log_hash = CANONICAL_RAW_LOG_HASH.to_owned();
        }
        report.fixture_recipes = report
            .proposed_beads
            .iter()
            .map(|bead| bead.fixture_recipe.clone())
            .collect();
        for row in &mut report.excluded_rows {
            row.raw_log_hash = CANONICAL_RAW_LOG_HASH.to_owned();
        }
        report.proposed_br_commands = report
            .proposed_beads
            .iter()
            .map(XfstestsProposedFailureBead::proposed_br_command)
            .collect();
    }

    fn baseline_output_paths() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "baseline_manifest_json".to_owned(),
                "baseline_manifest.json".to_owned(),
            ),
            (
                "baseline_report_md".to_owned(),
                "baseline_report.md".to_owned(),
            ),
        ])
    }

    fn manifest_with_cases(
        raw_path: &std::path::Path,
        cases: Vec<XfstestsBaselineCase>,
    ) -> XfstestsBaselineManifest {
        let raw_artifacts = vec![hash_raw_artifact(raw_path).expect("hash raw artifact")];
        let raw_refs = raw_artifacts
            .iter()
            .map(|artifact| artifact.path.clone())
            .collect::<Vec<_>>();
        let raw_log_hash = hash_raw_artifact_set(&raw_artifacts);
        let cases = cases
            .into_iter()
            .map(|mut case| {
                case.raw_artifact_refs.clone_from(&raw_refs);
                case.raw_log_hash.clone_from(&raw_log_hash);
                case
            })
            .collect::<Vec<_>>();
        XfstestsBaselineManifest {
            schema_version: 1,
            baseline_id: "xfstests-baseline-test".to_owned(),
            bead_id: XFSTESTS_BASELINE_BEAD_ID.to_owned(),
            subset_version: "xfstests-curated-v1".to_owned(),
            environment: XfstestsBaselineEnvironment {
                manifest_id: "sha256:env".to_owned(),
                age_secs: 0,
                max_age_secs: 3600,
                freshness_verdict: "fresh".to_owned(),
            },
            status_vocabulary: XFSTESTS_BASELINE_STATUS_VOCABULARY
                .iter()
                .map(|status| status.as_str().to_owned())
                .collect(),
            raw_artifact_policy: "raw artifacts are immutable inputs".to_owned(),
            generated_summary_path: "baseline_report.md".to_owned(),
            command_transcript: "./check generic/001".to_owned(),
            checkpoint_id: "checkpoint:001".to_owned(),
            resume_command: "XFSTESTS_MODE=run ./scripts/e2e/ffs_xfstests_e2e.sh".to_owned(),
            cleanup_status: "artifacts_preserved".to_owned(),
            output_paths: baseline_output_paths(),
            reproduction_command: "XFSTESTS_MODE=run ./scripts/e2e/ffs_xfstests_e2e.sh".to_owned(),
            disposition_counts: disposition_counts(&cases),
            raw_artifacts,
            cases,
        }
    }

    fn compact_baseline_manifest_shape(manifest: &XfstestsBaselineManifest) -> serde_json::Value {
        let cases = manifest
            .cases
            .iter()
            .map(|case| {
                serde_json::json!({
                    "test_id": &case.test_id,
                    "status": case.status.as_str(),
                    "raw_artifact_ref_count": case.raw_artifact_refs.len(),
                    "has_raw_log_hash": !case.raw_log_hash.is_empty(),
                    "has_not_run_reason": case.not_run_reason.is_some(),
                    "has_resume_command": !case.resume_command.is_empty(),
                    "cleanup_status": &case.cleanup_status,
                    "immutable_raw_artifacts": case.immutable_raw_artifacts,
                    "classification": &case.classification,
                    "has_remediation": case.remediation.is_some(),
                })
            })
            .collect::<Vec<_>>();

        serde_json::json!({
            "schema_version": manifest.schema_version,
            "baseline_id": &manifest.baseline_id,
            "bead_id": &manifest.bead_id,
            "subset_version": &manifest.subset_version,
            "environment": {
                "manifest_id": &manifest.environment.manifest_id,
                "age_secs": manifest.environment.age_secs,
                "max_age_secs": manifest.environment.max_age_secs,
                "freshness_verdict": &manifest.environment.freshness_verdict,
            },
            "status_vocabulary": &manifest.status_vocabulary,
            "raw_artifact_policy": &manifest.raw_artifact_policy,
            "generated_summary_path": &manifest.generated_summary_path,
            "checkpoint_id": &manifest.checkpoint_id,
            "cleanup_status": &manifest.cleanup_status,
            "output_paths": &manifest.output_paths,
            "disposition_counts": &manifest.disposition_counts,
            "raw_artifact_count": manifest.raw_artifacts.len(),
            "case_count": manifest.cases.len(),
            "cases": cases,
        })
    }

    #[test]
    fn parse_check_output_classifies_statuses_and_duration() {
        let selected = vec![
            "generic/001".to_owned(),
            "ext4/003".to_owned(),
            "generic/030".to_owned(),
        ];
        let log = "\
generic/001  1s ... pass\n\
ext4/003  2.5s ... failed due to mismatch\n\
generic/030  skipped: needs root\n";

        let run = parse_check_output(&selected, log, 1, false);

        assert_eq!(run.passed, 1);
        assert_eq!(run.failed, 1);
        assert_eq!(run.skipped, 1);
        assert_eq!(run.not_run, 0);
        assert_eq!(run.tests[0].duration_secs, Some(1.0));
        assert_eq!(run.tests[1].duration_secs, Some(2.5));
        assert_eq!(run.tests[0].status, XfstestsStatus::Passed);
        assert_eq!(run.tests[1].status, XfstestsStatus::Failed);
        assert_eq!(run.tests[2].status, XfstestsStatus::Skipped);
    }

    #[test]
    fn parse_check_output_preserves_unmentioned_rows_on_clean_non_dry_run() {
        let selected = vec!["generic/001".to_owned(), "generic/002".to_owned()];
        let run = parse_check_output(&selected, "generic/001  1s ... pass\n", 0, false);

        assert_eq!(run.tests[0].status, XfstestsStatus::Passed);
        assert_eq!(run.tests[1].status, XfstestsStatus::NotRun);
        assert_eq!(run.passed, 1);
        assert_eq!(run.not_run, 1);
    }

    #[test]
    fn parse_check_output_preserves_explicit_not_run_status() {
        let selected = vec!["generic/001".to_owned(), "generic/030".to_owned()];
        let log = "\
generic/001  -- not run: requires aio-stress\n\
generic/030  skipped: needs root\n";

        let run = parse_check_output(&selected, log, 0, false);

        assert_eq!(run.not_run, 1);
        assert_eq!(run.skipped, 1);
        assert_eq!(run.passed, 0);
        assert_eq!(run.tests[0].status, XfstestsStatus::NotRun);
        assert_eq!(run.tests[1].status, XfstestsStatus::Skipped);
    }

    #[test]
    fn parse_check_output_requires_exact_test_id_match() {
        let selected = vec!["generic/001".to_owned(), "generic/0010".to_owned()];
        let log = "\
generic/0010  1s ... failed due to mismatch\n\
generic/001  2s ... pass\n";

        let run = parse_check_output(&selected, log, 1, false);

        assert_eq!(run.tests[0].status, XfstestsStatus::Passed);
        assert_eq!(run.tests[1].status, XfstestsStatus::Failed);
    }

    #[test]
    fn allowlist_annotations_are_applied() {
        let selected = vec!["generic/001".to_owned()];
        let mut run = summarize_uniform(&selected, XfstestsStatus::Failed, Some("boom"));
        let allowlist = vec![XfstestsAllowlistEntry {
            test_id: "generic/001".to_owned(),
            failure_reason: "requires unsupported ioctl".to_owned(),
            status: "known_fail".to_owned(),
            classification: Some("expected_failure".to_owned()),
            expected_outcome: Some("expected_failure".to_owned()),
            ..XfstestsAllowlistEntry::default()
        }];

        apply_allowlist(&mut run, &allowlist);

        assert_eq!(run.tests[0].allowlist_status.as_deref(), Some("known_fail"));
        assert_eq!(
            run.tests[0].failure_reason.as_deref(),
            Some("requires unsupported ioctl")
        );
        assert_eq!(
            run.tests[0].classification.as_deref(),
            Some("expected_failure")
        );
        assert_eq!(
            run.tests[0].expected_outcome.as_deref(),
            Some("expected_failure")
        );
        assert_eq!(
            run.policy_summary.by_classification.get("expected_failure"),
            Some(&1)
        );
    }

    #[test]
    fn policy_summary_separates_not_run_rows_by_classification() {
        let selected = vec!["generic/003".to_owned(), "generic/030".to_owned()];
        let mut run = summarize_uniform(&selected, XfstestsStatus::NotRun, Some("blocked"));
        let mut environment = valid_policy_entry("generic/003");
        environment.status = "likely_pass".to_owned();
        environment.classification = Some("environment_blocked".to_owned());
        environment.expected_outcome = Some("environment_blocked".to_owned());
        environment.user_risk_category = Some("host_environment".to_owned());
        environment.expected_operation_class = Some("host_capability_skip".to_owned());

        let mut product = valid_policy_entry("generic/030");
        product.status = "known_fail".to_owned();
        product.classification = Some("product_actionable".to_owned());
        product.expected_outcome = Some("product_actionable_failure".to_owned());
        product.user_risk_category = Some("data_integrity".to_owned());
        product.expected_operation_class = Some("rw_file_lifecycle".to_owned());

        apply_allowlist(&mut run, &[environment, product]);

        assert_eq!(
            run.policy_summary
                .not_run_by_classification
                .get("environment_blocked"),
            Some(&1)
        );
        assert_eq!(
            run.policy_summary
                .not_run_by_classification
                .get("product_actionable"),
            Some(&1)
        );
        assert_eq!(
            run.policy_summary
                .by_expected_outcome
                .get("product_actionable_failure"),
            Some(&1)
        );
        assert_eq!(
            run.tests[0].required_capabilities,
            vec!["fuse_mount".to_owned()]
        );
    }

    #[test]
    fn ext4_ioctl_allowlist_entries_match_current_runtime_evidence() {
        let allowlist = load_allowlist(&repo_xfstests_allowlist_path()).expect("load allowlist");
        let by_test: BTreeMap<&str, &XfstestsAllowlistEntry> = allowlist
            .iter()
            .map(|entry| (entry.test_id.as_str(), entry))
            .collect();

        let ext4_001 = by_test.get("ext4/001").expect("ext4/001 allowlist entry");
        assert_eq!(ext4_001.status, "likely_pass");
        assert!(
            ext4_001.failure_reason.contains("ZERO_RANGE"),
            "ext4/001 should reference zero-range coverage: {}",
            ext4_001.failure_reason
        );
        assert!(
            ext4_001.failure_reason.contains("FIEMAP"),
            "ext4/001 should reference fiemap coverage: {}",
            ext4_001.failure_reason
        );
        assert!(
            ext4_001
                .failure_reason
                .contains("no longer blocked on missing FIEMAP forwarding"),
            "ext4/001 should not regress to the stale FIEMAP-forwarding claim: {}",
            ext4_001.failure_reason
        );

        let ext4_005 = by_test.get("ext4/005").expect("ext4/005 allowlist entry");
        assert_eq!(ext4_005.status, "known_fail");
        assert!(
            ext4_005.failure_reason.contains("chattr -e"),
            "ext4/005 should name the real xfstests operation: {}",
            ext4_005.failure_reason
        );
        assert!(
            ext4_005.failure_reason.contains("EXT4_EXTENTS_FL"),
            "ext4/005 should call out the system-managed extent flag: {}",
            ext4_005.failure_reason
        );
        assert!(
            ext4_005
                .failure_reason
                .contains("mounted-path EXT4_IOC_GETFLAGS")
                && ext4_005.failure_reason.contains("EXT4_IOC_SETFLAGS"),
            "ext4/005 should distinguish the unsupported extent conversion from supported flag ioctls: {}",
            ext4_005.failure_reason
        );
    }

    #[test]
    fn repo_xfstests_policy_covers_curated_subset() -> Result<()> {
        let mut selected = load_selected_tests(&repo_xfstests_list_path("xfstests_generic.list"))?;
        selected.extend(load_selected_tests(&repo_xfstests_list_path(
            "xfstests_ext4.list",
        ))?);
        selected.extend(load_selected_tests(&repo_xfstests_list_path(
            "xfstests_btrfs.list",
        ))?);
        let allowlist = load_allowlist(&repo_xfstests_allowlist_path())?;

        let mut errors = validate_xfstests_policy(&selected, &allowlist);
        errors.extend(validate_xfstests_policy_coverage(&allowlist));

        assert!(
            errors.is_empty(),
            "xfstests policy must cover the curated subset cleanly: {errors:#?}"
        );
        Ok(())
    }

    #[test]
    fn xfstests_policy_rejects_missing_artifact_requirements() {
        let selected = vec!["generic/001".to_owned()];
        let mut entry = valid_policy_entry("generic/001");
        entry
            .artifact_requirements
            .retain(|artifact| artifact != "policy_report.md");

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing artifact requirement: policy_report.md")),
            "expected missing artifact requirement error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_rejects_missing_check_log_artifact_requirement() {
        let selected = vec!["generic/001".to_owned()];
        let mut entry = valid_policy_entry("generic/001");
        entry
            .artifact_requirements
            .retain(|artifact| artifact != "check.log");

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing artifact requirement: check.log")),
            "expected missing check.log artifact requirement error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_rejects_missing_risk_outcome_or_operation_metadata() {
        let selected = vec!["generic/001".to_owned()];
        let mut entry = valid_policy_entry("generic/001");
        entry.expected_operation_class = None;
        entry.user_risk_category = None;
        entry.expected_outcome = None;

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing expected operation class")),
            "expected missing operation class error, got {errors:#?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing user risk category")),
            "expected missing risk category error, got {errors:#?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing expected outcome")),
            "expected missing expected outcome error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_rejects_missing_command_plan() {
        let selected = vec!["generic/001".to_owned()];
        let mut entry = valid_policy_entry("generic/001");
        entry.command_plan = None;

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing command_plan")),
            "expected missing command plan error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_rejects_unsafe_command_plan_fields() {
        let selected = vec!["generic/001".to_owned()];
        let mut entry = valid_policy_entry("generic/001");
        let plan = entry.command_plan.as_mut().expect("command plan");
        plan.image_path = "/var/lib/frankenfs/fixture.img".to_owned();
        plan.scratch_path = "/srv/xfstests/scratch".to_owned();
        plan.mountpoint.clear();
        plan.test_device = "/dev/loop0".to_owned();
        plan.scratch_device = "/dev/loop1".to_owned();
        plan.image_hash.clear();
        plan.helper_binaries = vec!["bash".to_owned()];
        plan.required_privileges = vec!["magic_admin".to_owned()];
        plan.cleanup_action.clear();
        plan.command_summary.clear();
        plan.argv = vec!["bash".to_owned(), "-c".to_owned(), "rm *".to_owned()];

        let errors = validate_xfstests_policy(&selected, &[entry]);

        for expected in [
            "non-temporary image path",
            "non-temporary scratch path",
            "non-temporary mountpoint",
            "non-temporary test device placeholder",
            "non-temporary scratch device placeholder",
            "missing image hash",
            "unresolved helper binary",
            "unknown privilege requirement",
            "missing cleanup action",
            "missing human-readable command summary",
            "does not name the test id",
            "broad shell command token",
        ] {
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "expected {expected} error, got {errors:#?}"
            );
        }
    }

    #[test]
    fn xfstests_policy_rejects_command_plan_paths_not_bound_to_test_id() {
        let selected = vec!["generic/001".to_owned()];
        let mut entry = valid_policy_entry("generic/001");
        let plan = entry.command_plan.as_mut().expect("command plan");
        plan.image_path = "${TMPDIR:-/tmp}/frankenfs-xfstests/images/shared.img".to_owned();
        plan.scratch_path = "${TMPDIR:-/tmp}/frankenfs-xfstests/scratch/shared".to_owned();
        plan.mountpoint = "${TMPDIR:-/tmp}/frankenfs-xfstests/mnt/shared".to_owned();
        plan.test_device = "${TMPDIR:-/tmp}/frankenfs-xfstests/devices/shared.test.img".to_owned();
        plan.scratch_device =
            "${TMPDIR:-/tmp}/frankenfs-xfstests/devices/shared.scratch.img".to_owned();

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .filter(|error| error.contains("does not include test id fragment generic-001"))
                .count()
                >= 5,
            "expected per-test sandbox errors, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_rejects_unsafe_cleanup_action() {
        let selected = vec!["generic/001".to_owned()];
        let mut entry = valid_policy_entry("generic/001");
        let plan = entry.command_plan.as_mut().expect("command plan");
        plan.cleanup_action = "rm -rf /var/lib/frankenfs && sync".to_owned();

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("unsafe cleanup action")),
            "expected unsafe cleanup action error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_rejects_destructive_plan_outside_permissioned_lane() {
        let selected = vec!["generic/001".to_owned()];
        let mut entry = valid_policy_entry("generic/001");
        let plan = entry.command_plan.as_mut().expect("command plan");
        plan.destructive = true;
        plan.execution_lane = "dry_run_only".to_owned();

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("outside permissioned_real lane")),
            "expected destructive lane error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_accepts_command_plan_lanes_and_outcome_classes() {
        for (lane, expected_outcome, destructive) in [
            ("dry_run_only", "dry_run_only", false),
            ("fixture_only", "fixture_only", false),
            ("permissioned_real", "permissioned_real", true),
            ("host_skip", "host_skip", false),
            ("unsupported_by_scope", "unsupported_by_scope", false),
            ("dry_run_only", "product_failure", false),
            ("dry_run_only", "harness_failure", false),
            ("dry_run_only", "cleanup_failure", false),
        ] {
            let selected = vec!["generic/001".to_owned()];
            let mut entry = valid_policy_entry("generic/001");
            let plan = entry.command_plan.as_mut().expect("command plan");
            plan.execution_lane = lane.to_owned();
            plan.expected_plan_outcome = expected_outcome.to_owned();
            plan.destructive = destructive;

            let errors = validate_xfstests_policy(&selected, &[entry]);

            assert!(
                errors.is_empty(),
                "expected command plan lane={lane} outcome={expected_outcome} to validate, got {errors:#?}"
            );
        }
    }

    #[test]
    fn xfstests_policy_coverage_requires_representative_operation_classes() {
        let mut allowlist = Vec::new();
        for operation_class in REQUIRED_XFSTESTS_OPERATION_CLASSES {
            let mut entry = valid_policy_entry("generic/001");
            entry.test_id = format!("generic/{:03}", allowlist.len() + 1);
            entry.policy_row_id = Some(format!(
                "xfstests-policy-{}",
                entry.test_id.replace('/', "-")
            ));
            entry.expected_operation_class = Some((*operation_class).to_owned());
            allowlist.push(entry);
        }
        allowlist
            .last_mut()
            .expect("allowlist entry")
            .expected_operation_class = Some("read_only_mount".to_owned());

        let errors = validate_xfstests_policy_coverage(&allowlist);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("host_capability_skip")),
            "expected missing representative operation class error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_coverage_requires_representative_filesystem_flavors() {
        let allowlist = vec![
            valid_policy_entry("generic/001"),
            valid_policy_entry("ext4/001"),
        ];

        let errors = validate_xfstests_policy_coverage(&allowlist);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("filesystem flavor: btrfs")),
            "expected missing btrfs flavor error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_rejects_duplicate_ids() {
        let selected = vec!["generic/001".to_owned()];
        let allowlist = vec![
            valid_policy_entry("generic/001"),
            valid_policy_entry("generic/001"),
        ];

        let errors = validate_xfstests_policy(&selected, &allowlist);

        assert!(errors.iter().any(|error| error.contains("duplicate")));
    }

    #[test]
    fn xfstests_policy_rejects_missing_skip_reasons() {
        let selected = vec!["generic/030".to_owned()];
        let mut entry = valid_policy_entry("generic/030");
        entry.status = "known_fail".to_owned();
        entry.classification = Some("expected_failure".to_owned());
        entry.failure_reason.clear();

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing skip reason")),
            "expected missing skip reason error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_rejects_unknown_classifications() {
        let selected = vec!["generic/001".to_owned()];
        let mut entry = valid_policy_entry("generic/001");
        entry.classification = Some("surprising".to_owned());

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("unknown classification")),
            "expected unknown classification error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_rejects_unsupported_tests_without_scope_rationale() {
        let selected = vec!["generic/068".to_owned()];
        let mut entry = valid_policy_entry("generic/068");
        entry.status = "wont_fix".to_owned();
        entry.classification = Some("unsupported_by_v1".to_owned());
        entry.scope_reference = None;

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("without scope_reference")),
            "expected missing scope reference error, got {errors:#?}"
        );
    }

    #[test]
    fn baseline_comparison_detects_regressions_and_improvements() {
        let selected = vec!["generic/001".to_owned(), "generic/013".to_owned()];
        let mut run = XfstestsRun {
            source: "check-log".to_owned(),
            check_rc: 1,
            dry_run: false,
            total: 2,
            passed: 1,
            failed: 1,
            skipped: 0,
            not_run: 0,
            planned: 0,
            pass_rate: 0.5,
            tests: vec![
                XfstestsCase {
                    id: "generic/001".to_owned(),
                    status: XfstestsStatus::Failed,
                    duration_secs: None,
                    output_snippet: None,
                    allowlist_status: None,
                    failure_reason: None,
                    policy_row_id: None,
                    classification: None,
                    expected_outcome: None,
                    user_risk_category: None,
                    expected_operation_class: None,
                    required_capabilities: Vec::new(),
                    tracker_id: None,
                    comparison: Vec::new(),
                },
                XfstestsCase {
                    id: "generic/013".to_owned(),
                    status: XfstestsStatus::Passed,
                    duration_secs: None,
                    output_snippet: None,
                    allowlist_status: None,
                    failure_reason: None,
                    policy_row_id: None,
                    classification: None,
                    expected_outcome: None,
                    user_risk_category: None,
                    expected_operation_class: None,
                    required_capabilities: Vec::new(),
                    tracker_id: None,
                    comparison: Vec::new(),
                },
            ],
            policy_summary: XfstestsPolicySummary::default(),
        };
        let baseline = vec![
            XfstestsBaselineEntry {
                test_id: "generic/001".to_owned(),
                expected_status: XfstestsStatus::Passed,
            },
            XfstestsBaselineEntry {
                test_id: "generic/013".to_owned(),
                expected_status: XfstestsStatus::Failed,
            },
        ];

        let comparison = compare_against_baseline(&mut run, &baseline);

        assert_eq!(
            comparison.regressions,
            vec!["generic/001 (passed -> failed)"]
        );
        assert_eq!(
            comparison.improvements,
            vec!["generic/013 (failed -> passed)"]
        );
        assert!(run.tests[0].comparison[0].contains("regression"));
        assert!(run.tests[1].comparison[0].contains("improvement"));
        let _ = selected;
    }

    #[test]
    fn baseline_manifest_accepts_required_fields_and_status_vocabulary() {
        let tmp = tempdir().expect("tempdir");
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "generic/001 pass\n").expect("write raw log");
        let cases = vec![
            baseline_case("generic/001", XfstestsBaselineRowStatus::Passed),
            baseline_case("generic/002", XfstestsBaselineRowStatus::Failed),
            baseline_case("generic/003", XfstestsBaselineRowStatus::Skipped),
            baseline_case("generic/004", XfstestsBaselineRowStatus::NotRun),
            baseline_case("generic/005", XfstestsBaselineRowStatus::Unsupported),
            baseline_case("generic/006", XfstestsBaselineRowStatus::HostBlocked),
            baseline_case("generic/007", XfstestsBaselineRowStatus::HarnessFailed),
            baseline_case("generic/008", XfstestsBaselineRowStatus::Interrupted),
            baseline_case("generic/009", XfstestsBaselineRowStatus::Resumed),
        ];
        let manifest = manifest_with_cases(&raw, cases);

        let errors = validate_xfstests_baseline_manifest(&manifest);

        assert!(
            errors.is_empty(),
            "expected valid manifest, got {errors:#?}"
        );
        assert_eq!(manifest.disposition_counts.get("passed"), Some(&1));
        assert_eq!(manifest.disposition_counts.get("interrupted"), Some(&1));
        assert_eq!(
            manifest.status_vocabulary,
            vec![
                "passed",
                "failed",
                "skipped",
                "not_run",
                "unsupported",
                "host_blocked",
                "harness_failed",
                "interrupted",
                "resumed",
            ]
        );
    }

    #[test]
    fn build_baseline_manifest_hashes_raw_artifacts_and_classifies_rows() -> Result<()> {
        let tmp = tempdir()?;
        let raw = tmp.path().join("check.log");
        fs::write(
            &raw,
            "generic/001 pass\ngeneric/002 failed\ngeneric/003 skipped\ngeneric/004 not run\n",
        )?;
        let summary = tmp.path().join("baseline_report.md");
        let selected = vec![
            "generic/001".to_owned(),
            "generic/002".to_owned(),
            "generic/003".to_owned(),
            "generic/004".to_owned(),
            "generic/005".to_owned(),
            "generic/006".to_owned(),
            "generic/007".to_owned(),
        ];
        let run = summarize_run(
            "fixture",
            1,
            false,
            vec![
                test_case(
                    "generic/001",
                    XfstestsStatus::Passed,
                    Some("product_actionable"),
                ),
                test_case(
                    "generic/002",
                    XfstestsStatus::Failed,
                    Some("product_actionable"),
                ),
                test_case(
                    "generic/003",
                    XfstestsStatus::Skipped,
                    Some("expected_failure"),
                ),
                test_case("generic/004", XfstestsStatus::NotRun, None),
                test_case(
                    "generic/005",
                    XfstestsStatus::NotRun,
                    Some("unsupported_by_v1"),
                ),
                test_case(
                    "generic/006",
                    XfstestsStatus::NotRun,
                    Some("environment_blocked"),
                ),
                test_case(
                    "generic/007",
                    XfstestsStatus::NotRun,
                    Some("harness_blocked"),
                ),
            ],
        );
        let manifest = build_xfstests_baseline_manifest(XfstestsBaselineManifestInput {
            baseline_id: "xfstests-baseline-fixture",
            subset_version: "xfstests-curated-v1",
            environment_manifest_id: "sha256:env",
            environment_age_secs: 0,
            environment_max_age_secs: 3600,
            selected_tests: &selected,
            run: &run,
            raw_artifact_paths: &[raw.as_path()],
            generated_summary_path: &summary,
            command_transcript: "./check generic/001 generic/002",
            checkpoint_id: "checkpoint:fixture",
            resume_command: "XFSTESTS_MODE=run RESULT_BASE=fixture ./scripts/e2e/ffs_xfstests_e2e.sh",
            cleanup_status: "partial_artifacts_preserved",
            reproduction_command: "XFSTESTS_MODE=run ./scripts/e2e/ffs_xfstests_e2e.sh",
            output_paths: baseline_output_paths(),
        })?;

        let errors = validate_xfstests_baseline_manifest(&manifest);

        assert!(
            errors.is_empty(),
            "expected valid manifest, got {errors:#?}"
        );
        assert_eq!(
            manifest.raw_artifacts[0].sha256,
            sha256_hex(&fs::read(&raw)?)
        );
        assert_eq!(manifest.bead_id, XFSTESTS_BASELINE_BEAD_ID);
        assert_eq!(manifest.cases[0].status, XfstestsBaselineRowStatus::Passed);
        assert_eq!(manifest.cases[1].status, XfstestsBaselineRowStatus::Failed);
        assert_eq!(manifest.cases[2].status, XfstestsBaselineRowStatus::Skipped);
        assert_eq!(manifest.cases[3].status, XfstestsBaselineRowStatus::NotRun);
        assert_eq!(
            manifest.cases[4].status,
            XfstestsBaselineRowStatus::Unsupported
        );
        assert_eq!(
            manifest.cases[5].status,
            XfstestsBaselineRowStatus::HostBlocked
        );
        assert_eq!(
            manifest.cases[6].status,
            XfstestsBaselineRowStatus::HarnessFailed
        );
        assert!(manifest.cases[3].remediation.is_some());
        Ok(())
    }

    #[test]
    fn baseline_manifest_rejects_missing_preflight_proof() -> Result<()> {
        let tmp = tempdir()?;
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "generic/001 not run\n")?;
        let summary = tmp.path().join("baseline_report.md");
        let selected = vec!["generic/001".to_owned()];
        let run = summarize_run(
            "fixture",
            0,
            true,
            vec![test_case(
                "generic/001",
                XfstestsStatus::NotRun,
                Some("environment_blocked"),
            )],
        );

        let manifest = build_xfstests_baseline_manifest(XfstestsBaselineManifestInput {
            baseline_id: "xfstests-baseline-missing-preflight",
            subset_version: "xfstests-curated-v1",
            environment_manifest_id: "preflight:missing",
            environment_age_secs: 0,
            environment_max_age_secs: 3600,
            selected_tests: &selected,
            run: &run,
            raw_artifact_paths: &[raw.as_path()],
            generated_summary_path: &summary,
            command_transcript: "./check -n generic/001",
            checkpoint_id: "checkpoint:missing-preflight",
            resume_command: "XFSTESTS_MODE=run RESULT_BASE=fixture ./scripts/e2e/ffs_xfstests_e2e.sh",
            cleanup_status: "plan_mode_no_xfstests_check_invoked",
            reproduction_command: "XFSTESTS_MODE=plan ./scripts/e2e/ffs_xfstests_e2e.sh",
            output_paths: baseline_output_paths(),
        })?;

        assert_eq!(manifest.environment.freshness_verdict, "missing");
        let errors = validate_xfstests_baseline_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing preflight proof")),
            "expected missing preflight proof error, got {errors:#?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("environment manifest is stale")),
            "expected non-fresh environment error, got {errors:#?}"
        );
        Ok(())
    }

    #[test]
    fn baseline_manifest_rejects_duplicate_missing_changed_and_stale_inputs() {
        let tmp = tempdir().expect("tempdir");
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "generic/001 pass\n").expect("write raw log");
        let mut manifest = manifest_with_cases(
            &raw,
            vec![
                baseline_case("generic/001", XfstestsBaselineRowStatus::Passed),
                baseline_case("generic/001", XfstestsBaselineRowStatus::Failed),
            ],
        );

        let errors = validate_xfstests_baseline_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("duplicate test row")),
            "expected duplicate row error, got {errors:#?}"
        );

        manifest.raw_artifacts[0].path = tmp.path().join("missing.log").display().to_string();
        let errors = validate_xfstests_baseline_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("raw artifact missing")),
            "expected missing raw artifact error, got {errors:#?}"
        );

        let mut changed = manifest_with_cases(
            &raw,
            vec![baseline_case(
                "generic/001",
                XfstestsBaselineRowStatus::Passed,
            )],
        );
        fs::write(&raw, "generic/001 failed\n").expect("mutate raw log");
        let errors = validate_xfstests_baseline_manifest(&changed);
        assert!(
            errors.iter().any(|error| error.contains("hash changed")),
            "expected changed hash error, got {errors:#?}"
        );

        changed.environment.age_secs = 7_200;
        changed.environment.max_age_secs = 3_600;
        changed.environment.freshness_verdict = "stale".to_owned();
        changed.cases[0].command.clear();
        let errors = validate_xfstests_baseline_manifest(&changed);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("environment manifest is stale")),
            "expected stale environment error, got {errors:#?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing case.command")),
            "expected missing command error, got {errors:#?}"
        );
    }

    #[test]
    fn render_xfstests_baseline_markdown_not_run_snapshot() {
        let tmp = tempdir().expect("tempdir");
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "generic/001 not run\n").expect("write raw log");
        let mut manifest = manifest_with_cases(
            &raw,
            vec![
                baseline_case("generic/001", XfstestsBaselineRowStatus::NotRun),
                baseline_case("generic/002", XfstestsBaselineRowStatus::Interrupted),
            ],
        );
        canonicalize_baseline_case_hashes(&mut manifest);

        let markdown = render_xfstests_baseline_markdown(&manifest);

        assert!(markdown.contains("- not_run: 1"));
        assert!(markdown.contains("- interrupted: 1"));
        assert!(!markdown.contains("- passed: 2"));
        assert!(markdown.contains("XFSTESTS_MODE=run"));
        insta::assert_snapshot!(
            "render_xfstests_baseline_markdown_not_run_snapshot",
            markdown
        );
    }

    /// bd-rchk0.349 - exact-output snapshot for mixed xfstests baseline
    /// dispositions. The not-run snapshot above pins resume/interruption
    /// wording; this fixture pins disposition ordering and row formatting when
    /// pass, fail, skip, not-run, interrupted, and resumed rows are present in
    /// one baseline report.
    #[test]
    fn render_xfstests_baseline_markdown_mixed_dispositions_snapshot() {
        const CANONICAL_RAW_LOG_HASH: &str =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let tmp = tempdir().expect("tempdir");
        let raw = tmp.path().join("check.log");
        fs::write(
            &raw,
            "generic/001 pass\n\
generic/002 failed\n\
generic/003 skipped\n\
generic/004 not run\n\
generic/005 interrupted\n\
generic/006 resumed\n",
        )
        .expect("write raw log");

        let mut passed = baseline_case("generic/001", XfstestsBaselineRowStatus::Passed);
        passed.classification = "expected_pass".to_owned();
        let mut failed = baseline_case("generic/002", XfstestsBaselineRowStatus::Failed);
        failed.classification = "product_actionable".to_owned();
        let mut skipped = baseline_case("generic/003", XfstestsBaselineRowStatus::Skipped);
        skipped.classification = "environment_blocked".to_owned();
        let mut not_run = baseline_case("generic/004", XfstestsBaselineRowStatus::NotRun);
        not_run.classification = "harness_blocked".to_owned();
        let mut interrupted = baseline_case("generic/005", XfstestsBaselineRowStatus::Interrupted);
        interrupted.classification = "harness_blocked".to_owned();
        let mut resumed = baseline_case("generic/006", XfstestsBaselineRowStatus::Resumed);
        resumed.classification = "expected_pass".to_owned();

        let manifest = manifest_with_cases(
            &raw,
            vec![passed, failed, skipped, not_run, interrupted, resumed],
        );

        let validation_errors = validate_xfstests_baseline_manifest(&manifest);
        assert!(
            validation_errors.is_empty(),
            "unexpected baseline manifest errors: {validation_errors:?}"
        );

        let rendered_raw_hash = manifest
            .cases
            .first()
            .expect("fixture has cases")
            .raw_log_hash
            .clone();
        let markdown = render_xfstests_baseline_markdown(&manifest)
            .replace(&rendered_raw_hash, CANONICAL_RAW_LOG_HASH);

        assert!(markdown.contains("- failed: 1"));
        assert!(markdown.contains("- resumed: 1"));
        assert!(markdown.contains("generic/006"));
        insta::assert_snapshot!(
            "render_xfstests_baseline_markdown_mixed_dispositions",
            markdown
        );
    }

    #[test]
    fn xfstests_baseline_manifest_json_shape() -> Result<()> {
        let tmp = tempdir()?;
        let raw = tmp.path().join("check.log");
        fs::write(
            &raw,
            "generic/001 pass\ngeneric/002 failed\ngeneric/003 skipped\ngeneric/004 not run\ngeneric/005 interrupted\ngeneric/006 resumed\n",
        )?;
        let mut failed = baseline_case("generic/002", XfstestsBaselineRowStatus::Failed);
        failed.not_run_reason = Some("EIO after fsync boundary".to_owned());
        let mut not_run = baseline_case("generic/004", XfstestsBaselineRowStatus::NotRun);
        not_run.not_run_reason = Some("selected row did not execute".to_owned());
        let interrupted = baseline_case("generic/005", XfstestsBaselineRowStatus::Interrupted);
        let resumed = baseline_case("generic/006", XfstestsBaselineRowStatus::Resumed);
        let manifest = manifest_with_cases(
            &raw,
            vec![
                baseline_case("generic/001", XfstestsBaselineRowStatus::Passed),
                failed,
                baseline_case("generic/003", XfstestsBaselineRowStatus::Skipped),
                not_run,
                interrupted,
                resumed,
            ],
        );

        let json = serde_json::to_string_pretty(&manifest)?;
        let parsed: XfstestsBaselineManifest = serde_json::from_str(&json)?;
        assert_eq!(parsed, manifest);
        assert!(validate_xfstests_baseline_manifest(&parsed).is_empty());
        assert_eq!(parsed.bead_id, XFSTESTS_BASELINE_BEAD_ID);
        assert_eq!(parsed.cases.len(), 6);
        assert_eq!(parsed.disposition_counts.get("passed"), Some(&1));
        assert_eq!(parsed.disposition_counts.get("failed"), Some(&1));
        assert_eq!(parsed.disposition_counts.get("skipped"), Some(&1));
        assert_eq!(parsed.disposition_counts.get("not_run"), Some(&1));
        assert_eq!(parsed.disposition_counts.get("interrupted"), Some(&1));
        assert_eq!(parsed.disposition_counts.get("resumed"), Some(&1));

        let shape_json = serde_json::to_string_pretty(&compact_baseline_manifest_shape(&parsed))?;
        insta::assert_snapshot!("xfstests_baseline_manifest_json_shape", shape_json);
        Ok(())
    }

    #[test]
    fn baseline_manifest_rejects_disposition_count_drift() {
        let tmp = tempdir().expect("tempdir");
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "generic/001 failed\n").expect("write raw log");
        let mut manifest = manifest_with_cases(
            &raw,
            vec![baseline_case(
                "generic/001",
                XfstestsBaselineRowStatus::Failed,
            )],
        );
        manifest.disposition_counts.insert("failed".to_owned(), 0);
        manifest.disposition_counts.insert("passed".to_owned(), 1);

        let errors = validate_xfstests_baseline_manifest(&manifest);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("disposition_counts mismatch")),
            "expected disposition count mismatch error, got {errors:#?}"
        );
    }

    #[test]
    fn baseline_manifest_rejects_empty_case_list() {
        let tmp = tempdir().expect("tempdir");
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "generic/001 pass\n").expect("write raw log");
        let manifest = manifest_with_cases(&raw, Vec::new());

        let errors = validate_xfstests_baseline_manifest(&manifest);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("cases must not be empty")),
            "expected empty cases error, got {errors:#?}"
        );
    }

    #[test]
    fn baseline_manifest_rejects_missing_output_paths() {
        let tmp = tempdir().expect("tempdir");
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "generic/001 pass\n").expect("write raw log");
        let mut manifest = manifest_with_cases(
            &raw,
            vec![baseline_case(
                "generic/001",
                XfstestsBaselineRowStatus::Passed,
            )],
        );

        manifest.output_paths.clear();
        let errors = validate_xfstests_baseline_manifest(&manifest);
        for expected in [
            "output_paths missing baseline_manifest_json",
            "output_paths missing baseline_report_md",
        ] {
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "expected {expected} error, got {errors:#?}"
            );
        }

        manifest.output_paths = baseline_output_paths();
        manifest
            .output_paths
            .insert("baseline_report_md".to_owned(), "   ".to_owned());
        let errors = validate_xfstests_baseline_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("output_paths missing baseline_report_md")),
            "expected blank report path error, got {errors:#?}"
        );
    }

    #[test]
    fn baseline_manifest_rejects_unknown_raw_artifact_refs() {
        let tmp = tempdir().expect("tempdir");
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "generic/001 failed\n").expect("write raw log");
        let mut manifest = manifest_with_cases(
            &raw,
            vec![baseline_case(
                "generic/001",
                XfstestsBaselineRowStatus::Failed,
            )],
        );
        let case = manifest.cases.first_mut().expect("single baseline case");
        case.raw_artifact_refs = vec!["missing-check.log".to_owned()];

        let errors = validate_xfstests_baseline_manifest(&manifest);

        assert!(
            errors.iter().any(|error| {
                error.contains(
                    "baseline case generic/001 references unknown raw artifact missing-check.log",
                )
            }),
            "expected unknown raw artifact ref error, got {errors:#?}"
        );
    }

    #[test]
    fn baseline_manifest_rejects_case_raw_log_hash_drift() {
        let tmp = tempdir().expect("tempdir");
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "generic/001 failed\n").expect("write raw log");
        let mut manifest = manifest_with_cases(
            &raw,
            vec![baseline_case(
                "generic/001",
                XfstestsBaselineRowStatus::Failed,
            )],
        );
        let case = manifest.cases.first_mut().expect("single baseline case");
        case.raw_log_hash =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();

        let errors = validate_xfstests_baseline_manifest(&manifest);

        assert!(
            errors.iter().any(|error| {
                error.contains(
                    "baseline case generic/001 raw_log_hash does not match referenced immutable artifacts",
                )
            }),
            "expected raw_log_hash drift error, got {errors:#?}"
        );
    }

    #[test]
    fn baseline_manifest_rejects_malformed_sha256_payloads() {
        let tmp = tempdir().expect("tempdir");
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "generic/001 failed\n").expect("write raw log");
        let mut manifest = manifest_with_cases(
            &raw,
            vec![baseline_case(
                "generic/001",
                XfstestsBaselineRowStatus::Failed,
            )],
        );
        manifest
            .raw_artifacts
            .first_mut()
            .expect("single raw artifact")
            .sha256 =
            "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_owned();
        manifest
            .cases
            .first_mut()
            .expect("single baseline case")
            .raw_log_hash =
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();

        let errors = validate_xfstests_baseline_manifest(&manifest);

        for expected in [
            "raw artifact",
            "has malformed sha256",
            "case generic/001 has malformed raw_log_hash",
        ] {
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "expected {expected} error, got {errors:#?}"
            );
        }
    }

    #[test]
    fn failure_triage_extracts_products_excludes_non_products_and_merges_duplicates() -> Result<()>
    {
        let tmp = tempdir()?;
        let raw = tmp.path().join("check.log");
        fs::write(
            &raw,
            "generic/001 failed EIO\ngeneric/002 failed EIO\next4/001 host blocked\nbtrfs/001 unsupported\n",
        )?;
        let mut first = baseline_case("generic/001", XfstestsBaselineRowStatus::Failed);
        first.not_run_reason = Some("EIO after fsync boundary".to_owned());
        let mut second = baseline_case("generic/002", XfstestsBaselineRowStatus::Failed);
        second.not_run_reason = Some("EIO after fsync boundary".to_owned());
        let mut host = baseline_case("ext4/001", XfstestsBaselineRowStatus::HostBlocked);
        host.classification = "environment_blocked".to_owned();
        let mut unsupported = baseline_case("btrfs/001", XfstestsBaselineRowStatus::Unsupported);
        unsupported.classification = "unsupported_by_v1".to_owned();
        let manifest = manifest_with_cases(&raw, vec![first, second, host, unsupported]);

        let report = build_xfstests_failure_triage_report(XfstestsFailureTriageInput {
            triage_id: "triage-fixture",
            baseline_manifest_path: tmp.path().join("baseline_manifest.json").as_path(),
            baseline_manifest: &manifest,
            reproduction_command: "./scripts/e2e/ffs_xfstests_e2e.sh",
        })?;

        assert_eq!(report.proposed_beads.len(), 1);
        assert_eq!(
            report.proposed_beads[0].related_test_ids,
            vec!["generic/001".to_owned(), "generic/002".to_owned()]
        );
        assert_eq!(report.fixture_recipes.len(), 1);
        assert_eq!(
            report.fixture_recipes[0].related_test_ids,
            vec!["generic/001".to_owned(), "generic/002".to_owned()]
        );
        assert_eq!(
            report.fixture_recipes[0].proposed_fixture_path,
            "conformance/fixtures/xfstests/generic-001.json"
        );
        assert!(
            report.fixture_recipes[0]
                .dependency_hints
                .iter()
                .any(|hint| hint.contains("bd-rchk3.4"))
        );
        assert_eq!(report.duplicate_groups.len(), 1);
        assert_eq!(report.excluded_rows.len(), 2);
        assert!(report.proposed_br_commands[0].starts_with("DRY_RUN br create"));
        assert!(
            report
                .excluded_rows
                .iter()
                .any(|row| row.reason.contains("environment work"))
        );
        assert!(
            report
                .excluded_rows
                .iter()
                .any(|row| row.reason.contains("unsupported-scope"))
        );
        Ok(())
    }

    fn fixture_failure_triage_report(
        tmp_path: &std::path::Path,
    ) -> Result<XfstestsFailureTriageReport> {
        let raw = tmp_path.join("check.log");
        fs::write(
            &raw,
            "generic/001 failed EIO\ngeneric/002 failed EIO\next4/001 host blocked\nbtrfs/001 unsupported\n",
        )?;
        let mut first = baseline_case("generic/001", XfstestsBaselineRowStatus::Failed);
        first.not_run_reason = Some("EIO after fsync boundary".to_owned());
        let mut second = baseline_case("generic/002", XfstestsBaselineRowStatus::Failed);
        second.not_run_reason = Some("EIO after fsync boundary".to_owned());
        let mut host = baseline_case("ext4/001", XfstestsBaselineRowStatus::HostBlocked);
        host.classification = "environment_blocked".to_owned();
        let mut unsupported = baseline_case("btrfs/001", XfstestsBaselineRowStatus::Unsupported);
        unsupported.classification = "unsupported_by_v1".to_owned();
        let manifest = manifest_with_cases(&raw, vec![first, second, host, unsupported]);

        let mut report = build_xfstests_failure_triage_report(XfstestsFailureTriageInput {
            triage_id: "triage-fixture",
            baseline_manifest_path: tmp_path.join("baseline_manifest.json").as_path(),
            baseline_manifest: &manifest,
            reproduction_command: "./scripts/e2e/ffs_xfstests_e2e.sh",
        })?;
        report.source_baseline_manifest = "baseline_manifest.json".to_owned();
        canonicalize_failure_triage_hashes(&mut report);
        Ok(report)
    }

    fn compact_failure_triage_report_shape(
        report: &XfstestsFailureTriageReport,
    ) -> serde_json::Value {
        let proposed = report
            .proposed_beads
            .iter()
            .map(|bead| {
                serde_json::json!({
                    "proposed_id_placeholder": &bead.proposed_id_placeholder,
                    "failing_test_id": &bead.failing_test_id,
                    "related_test_ids": &bead.related_test_ids,
                    "filesystem_flavor": &bead.filesystem_flavor,
                    "normalized_outcome": &bead.normalized_outcome,
                    "suspected_crate_boundary": &bead.suspected_crate_boundary,
                    "minimization_status": &bead.minimization_status,
                    "duplicate_key": &bead.duplicate_key,
                    "labels": &bead.labels,
                    "dependency_beads": &bead.dependency_beads,
                    "raw_log_ref_count": bead.raw_log_refs.len(),
                    "raw_log_hash": &bead.raw_log_hash,
                    "fixture_recipe_id": &bead.fixture_recipe.recipe_id,
                    "live_create": bead.live_create,
                })
            })
            .collect::<Vec<_>>();
        let fixtures = report
            .fixture_recipes
            .iter()
            .map(|recipe| {
                serde_json::json!({
                    "recipe_id": &recipe.recipe_id,
                    "source_xfstests_id": &recipe.source_xfstests_id,
                    "related_test_ids": &recipe.related_test_ids,
                    "filesystem_flavor": &recipe.filesystem_flavor,
                    "suspected_crate_boundary": &recipe.suspected_crate_boundary,
                    "fixture_manifest_kind": &recipe.fixture_manifest_kind,
                    "proposed_fixture_path": &recipe.proposed_fixture_path,
                    "source_raw_log_ref_count": recipe.source_raw_log_refs.len(),
                    "source_raw_log_hash": &recipe.source_raw_log_hash,
                    "dependency_hint_count": recipe.dependency_hints.len(),
                    "recipe_step_count": recipe.recipe_steps.len(),
                    "promotion_status": &recipe.promotion_status,
                    "live_fixture_write_enabled": recipe.live_fixture_write_enabled,
                })
            })
            .collect::<Vec<_>>();
        let excluded = report
            .excluded_rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "test_id": &row.test_id,
                    "status": &row.status,
                    "classification": &row.classification,
                    "reason": &row.reason,
                    "raw_log_hash": &row.raw_log_hash,
                    "has_remediation": row.remediation.is_some(),
                })
            })
            .collect::<Vec<_>>();

        serde_json::json!({
            "schema_version": report.schema_version,
            "triage_id": &report.triage_id,
            "baseline_id": &report.baseline_id,
            "subset_version": &report.subset_version,
            "source_baseline_manifest": &report.source_baseline_manifest,
            "live_bead_creation_enabled": report.live_bead_creation_enabled,
            "disposition_counts": &report.disposition_counts,
            "duplicate_groups": &report.duplicate_groups,
            "proposed_bead_count": report.proposed_beads.len(),
            "fixture_recipe_count": report.fixture_recipes.len(),
            "excluded_row_count": report.excluded_rows.len(),
            "proposed_br_command_count": report.proposed_br_commands.len(),
            "proposed": proposed,
            "fixtures": fixtures,
            "excluded": excluded,
        })
    }

    #[test]
    fn xfstests_failure_triage_report_json_shape() -> Result<()> {
        let tmp = tempdir()?;
        let report = fixture_failure_triage_report(tmp.path())?;

        let json = serde_json::to_string_pretty(&report)?;
        let parsed: XfstestsFailureTriageReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        assert!(validate_xfstests_failure_triage_report(&parsed).is_empty());
        assert_eq!(parsed.proposed_beads.len(), 1);
        assert_eq!(parsed.fixture_recipes.len(), 1);
        assert_eq!(parsed.duplicate_groups.len(), 1);
        assert_eq!(parsed.excluded_rows.len(), 2);
        assert_eq!(
            parsed.proposed_br_commands.len(),
            parsed.proposed_beads.len()
        );
        assert_eq!(parsed.disposition_counts.get("failed"), Some(&2));
        assert_eq!(parsed.disposition_counts.get("host_blocked"), Some(&1));
        assert_eq!(parsed.disposition_counts.get("unsupported"), Some(&1));

        let shape_json =
            serde_json::to_string_pretty(&compact_failure_triage_report_shape(&parsed))?;
        insta::assert_snapshot!("xfstests_failure_triage_report_json_shape", shape_json);
        Ok(())
    }

    #[test]
    fn failure_triage_rejects_duplicate_group_drift() -> Result<()> {
        let tmp = tempdir()?;
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "generic/001 failed EIO\ngeneric/002 failed EIO\n")?;
        let mut first = baseline_case("generic/001", XfstestsBaselineRowStatus::Failed);
        first.not_run_reason = Some("EIO after fsync boundary".to_owned());
        let mut second = baseline_case("generic/002", XfstestsBaselineRowStatus::Failed);
        second.not_run_reason = Some("EIO after fsync boundary".to_owned());
        let manifest = manifest_with_cases(&raw, vec![first, second]);
        let mut report = build_xfstests_failure_triage_report(XfstestsFailureTriageInput {
            triage_id: "triage-fixture",
            baseline_manifest_path: tmp.path().join("baseline_manifest.json").as_path(),
            baseline_manifest: &manifest,
            reproduction_command: "./scripts/e2e/ffs_xfstests_e2e.sh",
        })?;
        assert_eq!(report.duplicate_groups.len(), 1);
        report.duplicate_groups.clear();

        let errors = validate_xfstests_failure_triage_report(&report);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("duplicate_groups mismatch")),
            "expected duplicate_groups mismatch error, got {errors:#?}"
        );
        Ok(())
    }

    #[test]
    fn failure_triage_rejects_proposed_excluded_row_overlap() -> Result<()> {
        let tmp = tempdir()?;
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "generic/001 failed EIO\next4/001 host blocked\n")?;
        let mut product = baseline_case("generic/001", XfstestsBaselineRowStatus::Failed);
        product.not_run_reason = Some("EIO after fsync boundary".to_owned());
        let mut host = baseline_case("ext4/001", XfstestsBaselineRowStatus::HostBlocked);
        host.classification = "environment_blocked".to_owned();
        let manifest = manifest_with_cases(&raw, vec![product, host]);
        let mut report = build_xfstests_failure_triage_report(XfstestsFailureTriageInput {
            triage_id: "triage-fixture",
            baseline_manifest_path: tmp.path().join("baseline_manifest.json").as_path(),
            baseline_manifest: &manifest,
            reproduction_command: "./scripts/e2e/ffs_xfstests_e2e.sh",
        })?;
        let mut duplicated_exclusion = report
            .excluded_rows
            .first()
            .context("missing excluded row")?
            .clone();
        duplicated_exclusion.test_id = "generic/001".to_owned();
        duplicated_exclusion.status = XfstestsBaselineRowStatus::Failed.as_str().to_owned();
        duplicated_exclusion.reason = "duplicated proposed product row".to_owned();
        report.excluded_rows.push(duplicated_exclusion);
        report.disposition_counts = failure_triage_disposition_counts(&report);

        let errors = validate_xfstests_failure_triage_report(&report);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("row generic/001 appears in multiple dispositions")),
            "expected row ownership overlap error, got {errors:#?}"
        );
        Ok(())
    }

    #[test]
    fn failure_triage_rejects_duplicate_proposed_row_assignment() -> Result<()> {
        let tmp = tempdir()?;
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "generic/001 failed EIO\n")?;
        let mut product = baseline_case("generic/001", XfstestsBaselineRowStatus::Failed);
        product.not_run_reason = Some("EIO after fsync boundary".to_owned());
        let manifest = manifest_with_cases(&raw, vec![product]);
        let mut report = build_xfstests_failure_triage_report(XfstestsFailureTriageInput {
            triage_id: "triage-fixture",
            baseline_manifest_path: tmp.path().join("baseline_manifest.json").as_path(),
            baseline_manifest: &manifest,
            reproduction_command: "./scripts/e2e/ffs_xfstests_e2e.sh",
        })?;
        let mut duplicate_bead = report
            .proposed_beads
            .first()
            .context("missing proposed bead")?
            .clone();
        duplicate_bead.proposed_id_placeholder = "dry-run-xfstests-product-failure-9999".to_owned();
        duplicate_bead.duplicate_key = format!("{}:manual-duplicate", duplicate_bead.duplicate_key);
        report.proposed_beads.push(duplicate_bead);
        report.proposed_br_commands = report
            .proposed_beads
            .iter()
            .map(XfstestsProposedFailureBead::proposed_br_command)
            .collect();
        report.duplicate_groups = failure_triage_duplicate_groups(&report.proposed_beads);
        report.disposition_counts = failure_triage_disposition_counts(&report);

        let errors = validate_xfstests_failure_triage_report(&report);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("row generic/001 appears in multiple dispositions")),
            "expected duplicate proposed row ownership error, got {errors:#?}"
        );
        Ok(())
    }

    #[test]
    fn failure_triage_rejects_excluded_product_actionable_failure() {
        let mut report = XfstestsFailureTriageReport {
            schema_version: 1,
            triage_id: "triage-fixture".to_owned(),
            baseline_id: "baseline".to_owned(),
            subset_version: "subset".to_owned(),
            source_baseline_manifest: "baseline_manifest.json".to_owned(),
            live_bead_creation_enabled: false,
            disposition_counts: BTreeMap::new(),
            duplicate_groups: Vec::new(),
            proposed_beads: Vec::new(),
            fixture_recipes: Vec::new(),
            excluded_rows: vec![XfstestsFailureTriageExcludedRow {
                test_id: "generic/001".to_owned(),
                status: XfstestsBaselineRowStatus::Failed.as_str().to_owned(),
                classification: "product_actionable".to_owned(),
                reason: "hand-edited excluded product failure".to_owned(),
                raw_log_hash:
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_owned(),
                remediation: None,
            }],
            proposed_br_commands: Vec::new(),
            reproduction_command: "./scripts/e2e/ffs_xfstests_e2e.sh".to_owned(),
        };
        report.disposition_counts = failure_triage_disposition_counts(&report);

        let errors = validate_xfstests_failure_triage_report(&report);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("product_actionable")),
            "expected product_actionable exclusion error, got {errors:#?}"
        );
    }

    #[test]
    fn failure_triage_rejects_excluded_payload_drift() -> Result<()> {
        let tmp = tempdir()?;
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "ext4/001 host blocked\n")?;
        let mut host = baseline_case("ext4/001", XfstestsBaselineRowStatus::HostBlocked);
        host.classification = "environment_blocked".to_owned();
        let manifest = manifest_with_cases(&raw, vec![host]);
        let mut report = build_xfstests_failure_triage_report(XfstestsFailureTriageInput {
            triage_id: "triage-fixture",
            baseline_manifest_path: tmp.path().join("baseline_manifest.json").as_path(),
            baseline_manifest: &manifest,
            reproduction_command: "./scripts/e2e/ffs_xfstests_e2e.sh",
        })?;
        let excluded = report
            .excluded_rows
            .first_mut()
            .context("missing excluded row")?;
        excluded.status = "ghost_status".to_owned();
        excluded.classification.clear();
        excluded.raw_log_hash = "sha256:not-a-real-digest".to_owned();
        report.disposition_counts = failure_triage_disposition_counts(&report);

        let errors = validate_xfstests_failure_triage_report(&report);

        for expected in [
            "unknown status ghost_status",
            "missing excluded.classification",
            "malformed raw_log_hash",
        ] {
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "expected {expected} error, got {errors:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn failure_triage_rejects_disposition_count_drift() -> Result<()> {
        let tmp = tempdir()?;
        let raw = tmp.path().join("check.log");
        fs::write(
            &raw,
            "generic/001 failed EIO\ngeneric/002 failed EIO\next4/001 host blocked\n",
        )?;
        let mut first = baseline_case("generic/001", XfstestsBaselineRowStatus::Failed);
        first.not_run_reason = Some("EIO after fsync boundary".to_owned());
        let mut second = baseline_case("generic/002", XfstestsBaselineRowStatus::Failed);
        second.not_run_reason = Some("EIO after fsync boundary".to_owned());
        let mut host = baseline_case("ext4/001", XfstestsBaselineRowStatus::HostBlocked);
        host.classification = "environment_blocked".to_owned();
        let manifest = manifest_with_cases(&raw, vec![first, second, host]);
        let mut report = build_xfstests_failure_triage_report(XfstestsFailureTriageInput {
            triage_id: "triage-fixture",
            baseline_manifest_path: tmp.path().join("baseline_manifest.json").as_path(),
            baseline_manifest: &manifest,
            reproduction_command: "./scripts/e2e/ffs_xfstests_e2e.sh",
        })?;
        report.disposition_counts.insert("failed".to_owned(), 1);
        report.disposition_counts.insert("passed".to_owned(), 1);

        let errors = validate_xfstests_failure_triage_report(&report);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("disposition_counts mismatch")),
            "expected disposition count mismatch error, got {errors:#?}"
        );
        Ok(())
    }

    #[test]
    fn failure_triage_rejects_mutated_proposed_br_command() -> Result<()> {
        let tmp = tempdir()?;
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "generic/001 failed EIO\n")?;
        let mut product = baseline_case("generic/001", XfstestsBaselineRowStatus::Failed);
        product.not_run_reason = Some("EIO after fsync boundary".to_owned());
        let manifest = manifest_with_cases(&raw, vec![product]);
        let mut report = build_xfstests_failure_triage_report(XfstestsFailureTriageInput {
            triage_id: "triage-fixture",
            baseline_manifest_path: tmp.path().join("baseline_manifest.json").as_path(),
            baseline_manifest: &manifest,
            reproduction_command: "./scripts/e2e/ffs_xfstests_e2e.sh",
        })?;
        let command = report
            .proposed_br_commands
            .first_mut()
            .context("missing proposed br command")?;
        *command = "br create --title live-product-bug --type bug".to_owned();

        let errors = validate_xfstests_failure_triage_report(&report);

        for expected in [
            "must be a dry-run br create command",
            "does not match proposed bead",
        ] {
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "expected {expected} error, got {errors:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn failure_triage_validates_fixture_recipes_and_synthetic_statuses() -> Result<()> {
        let tmp = tempdir()?;
        let raw = tmp.path().join("check.log");
        fs::write(
            &raw,
            "generic/001 failed EIO\ngeneric/002 passed\ngeneric/003 skipped\ngeneric/004 interrupted\ngeneric/005 resumed\n",
        )?;
        let mut product = baseline_case("generic/001", XfstestsBaselineRowStatus::Failed);
        product.not_run_reason = Some("EIO after fsync boundary".to_owned());
        let passed = baseline_case("generic/002", XfstestsBaselineRowStatus::Passed);
        let skipped = baseline_case("generic/003", XfstestsBaselineRowStatus::Skipped);
        let interrupted = baseline_case("generic/004", XfstestsBaselineRowStatus::Interrupted);
        let resumed = baseline_case("generic/005", XfstestsBaselineRowStatus::Resumed);
        let manifest =
            manifest_with_cases(&raw, vec![product, passed, skipped, interrupted, resumed]);
        let mut report = build_xfstests_failure_triage_report(XfstestsFailureTriageInput {
            triage_id: "triage-fixture",
            baseline_manifest_path: tmp.path().join("baseline_manifest.json").as_path(),
            baseline_manifest: &manifest,
            reproduction_command: "./scripts/e2e/ffs_xfstests_e2e.sh",
        })?;

        assert_eq!(report.proposed_beads.len(), 1);
        assert_eq!(report.fixture_recipes.len(), 1);
        let recipe = &report.fixture_recipes[0];
        assert_eq!(recipe.source_xfstests_id, "generic/001");
        assert_eq!(recipe.promotion_status, "dry_run_recipe_only");
        assert!(!recipe.live_fixture_write_enabled);
        assert_eq!(
            recipe.validation_command,
            "XFSTESTS_MODE=run XFSTESTS_FILTER=generic XFSTESTS_DRY_RUN=0 ./scripts/e2e/ffs_xfstests_e2e.sh"
        );
        let synthetic_report = build_xfstests_failure_triage_report(XfstestsFailureTriageInput {
            triage_id: "triage-fixture-synthetic",
            baseline_manifest_path: tmp.path().join("baseline_manifest.json").as_path(),
            baseline_manifest: &manifest,
            reproduction_command: "XFSTESTS_SYNTHETIC_TRIAGE_FIXTURE=1 XFSTESTS_MODE=plan XFSTESTS_DRY_RUN=1 XFSTESTS_FILTER=all ./scripts/e2e/ffs_xfstests_e2e.sh",
        })?;
        assert_eq!(
            synthetic_report.fixture_recipes[0].validation_command,
            "XFSTESTS_SYNTHETIC_TRIAGE_FIXTURE=1 XFSTESTS_MODE=plan XFSTESTS_DRY_RUN=1 XFSTESTS_FILTER=all ./scripts/e2e/ffs_xfstests_e2e.sh"
        );
        assert!(
            report
                .excluded_rows
                .iter()
                .any(|row| row.test_id == "generic/003" && row.status == "skipped")
        );
        assert!(
            report
                .excluded_rows
                .iter()
                .any(|row| row.test_id == "generic/004" && row.status == "interrupted")
        );
        assert!(
            report
                .excluded_rows
                .iter()
                .any(|row| row.test_id == "generic/005" && row.status == "resumed")
        );

        report.fixture_recipes[0].proposed_fixture_path = "../escape.json".to_owned();
        report.fixture_recipes[0].recipe_steps.clear();
        report.fixture_recipes[0].live_fixture_write_enabled = true;
        let errors = validate_xfstests_failure_triage_report(&report);
        for expected in [
            "fixture_recipes mismatch",
            "unsafe proposed_fixture_path",
            "must not write live fixtures",
            "needs a concrete minimization recipe",
        ] {
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "expected {expected} error, got {errors:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn failure_triage_rejects_stale_raw_refs_missing_command_and_bad_payloads() {
        let tmp = tempdir().expect("tempdir");
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "generic/001 failed\n").expect("write raw log");
        let mut product = baseline_case("generic/001", XfstestsBaselineRowStatus::Failed);
        product.not_run_reason = Some("lost write after fsync".to_owned());
        let mut manifest = manifest_with_cases(&raw, vec![product]);
        fs::write(&raw, "generic/001 changed\n").expect("mutate raw log");

        let error = build_xfstests_failure_triage_report(XfstestsFailureTriageInput {
            triage_id: "triage-fixture",
            baseline_manifest_path: tmp.path().join("baseline_manifest.json").as_path(),
            baseline_manifest: &manifest,
            reproduction_command: "./scripts/e2e/ffs_xfstests_e2e.sh",
        })
        .expect_err("changed raw artifact must be rejected")
        .to_string();
        assert!(
            error.contains("hash changed"),
            "expected raw hash drift error, got {error}"
        );

        fs::write(&raw, "generic/001 failed\n").expect("restore raw log");
        manifest = manifest_with_cases(
            &raw,
            vec![baseline_case(
                "generic/001",
                XfstestsBaselineRowStatus::Failed,
            )],
        );
        manifest.cases[0].command.clear();
        let error = build_xfstests_failure_triage_report(XfstestsFailureTriageInput {
            triage_id: "triage-fixture",
            baseline_manifest_path: tmp.path().join("baseline_manifest.json").as_path(),
            baseline_manifest: &manifest,
            reproduction_command: "./scripts/e2e/ffs_xfstests_e2e.sh",
        })
        .expect_err("missing command must be rejected")
        .to_string();
        assert!(
            error.contains("missing case.command"),
            "expected missing command error, got {error}"
        );
    }

    #[test]
    fn failure_triage_rejects_bad_proposed_and_fixture_payloads() {
        let report = XfstestsFailureTriageReport {
            schema_version: 1,
            triage_id: "triage-fixture".to_owned(),
            baseline_id: "baseline".to_owned(),
            subset_version: "subset".to_owned(),
            source_baseline_manifest: "baseline_manifest.json".to_owned(),
            live_bead_creation_enabled: false,
            disposition_counts: BTreeMap::new(),
            duplicate_groups: Vec::new(),
            proposed_beads: vec![XfstestsProposedFailureBead {
                proposed_id_placeholder: "dry-run".to_owned(),
                title: "missing fields".to_owned(),
                failing_test_id: "generic/001".to_owned(),
                related_test_ids: vec!["generic/001".to_owned()],
                filesystem_flavor: "generic".to_owned(),
                exact_command: "./check generic/001".to_owned(),
                normalized_outcome: "failed".to_owned(),
                expected_behavior: String::new(),
                actual_behavior: String::new(),
                suspected_crate_boundary: "mystery-crate".to_owned(),
                minimized_repro_command: None,
                minimization_status: "unknown".to_owned(),
                duplicate_key: "dup".to_owned(),
                labels: vec!["xfstests".to_owned()],
                dependency_beads: Vec::new(),
                dependency_rationale: String::new(),
                validation_command: "./check generic/001".to_owned(),
                raw_log_refs: vec!["check.log".to_owned()],
                raw_log_hash:
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_owned(),
                fixture_recipe: XfstestsSparseFixtureRecipe {
                    schema_version: 1,
                    recipe_id: "xfstests-sparse-fixture-generic-001".to_owned(),
                    source_xfstests_id: "generic/001".to_owned(),
                    related_test_ids: vec!["generic/001".to_owned()],
                    filesystem_flavor: "generic".to_owned(),
                    suspected_crate_boundary: "mystery-crate".to_owned(),
                    fixture_manifest_kind: "sparse_fixture_generation_recipe".to_owned(),
                    proposed_fixture_path: "conformance/fixtures/xfstests/generic-001.json"
                        .to_owned(),
                    source_raw_log_refs: vec!["check.log".to_owned()],
                    source_raw_log_hash:
                        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                            .to_owned(),
                    minimized_reproducer_command: "./check generic/001".to_owned(),
                    expected_behavior: String::new(),
                    actual_behavior: String::new(),
                    validation_command: "./check generic/001".to_owned(),
                    dependency_hints: Vec::new(),
                    recipe_steps: Vec::new(),
                    promotion_status: "dry_run_recipe_only".to_owned(),
                    live_fixture_write_enabled: false,
                },
                live_create: true,
            }],
            fixture_recipes: Vec::new(),
            excluded_rows: Vec::new(),
            proposed_br_commands: Vec::new(),
            reproduction_command: "./scripts/e2e/ffs_xfstests_e2e.sh".to_owned(),
        };
        let errors = validate_xfstests_failure_triage_report(&report);
        for expected in [
            "missing proposed.expected_behavior",
            "missing proposed.actual_behavior",
            "unknown suspected boundary",
            "minimized repro",
            "missing required labels",
            "missing dependency rationale",
            "must not create live beads",
            "proposed_br_commands count mismatch",
        ] {
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "expected {expected} error, got {errors:#?}"
            );
        }
    }

    #[test]
    fn render_xfstests_failure_triage_markdown_dry_run_snapshot() -> Result<()> {
        let tmp = tempdir()?;
        let raw = tmp.path().join("check.log");
        fs::write(&raw, "ext4/001 failed\ngeneric/002 not run\n")?;
        let mut product = baseline_case("ext4/001", XfstestsBaselineRowStatus::Failed);
        product.not_run_reason = Some("flag mismatch".to_owned());
        product.command = "./check ext4/001".to_owned();
        let manifest = manifest_with_cases(
            &raw,
            vec![
                product,
                baseline_case("generic/002", XfstestsBaselineRowStatus::NotRun),
            ],
        );
        let mut report = build_xfstests_failure_triage_report(XfstestsFailureTriageInput {
            triage_id: "triage-fixture",
            baseline_manifest_path: tmp.path().join("baseline_manifest.json").as_path(),
            baseline_manifest: &manifest,
            reproduction_command: "./scripts/e2e/ffs_xfstests_e2e.sh",
        })?;
        canonicalize_failure_triage_hashes(&mut report);

        let markdown = render_xfstests_failure_triage_markdown(&report);

        assert!(markdown.contains("live bead creation enabled: `false`"));
        assert!(markdown.contains("ext4/001"));
        assert!(markdown.contains("ffs-ext4"));
        assert!(markdown.contains("DRY_RUN br create"));
        assert!(markdown.contains("generic/002"));
        assert!(markdown.contains("not-run rows require remediation or rerun first"));
        insta::assert_snapshot!(
            "render_xfstests_failure_triage_markdown_dry_run_snapshot",
            markdown
        );
        Ok(())
    }
}
