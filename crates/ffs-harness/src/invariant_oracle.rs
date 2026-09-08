#![allow(clippy::module_name_repetitions)]

//! Replayable invariant-oracle trace validation for `bd-rchk0.5.1`.
//!
//! This module intentionally models externally meaningful filesystem state:
//! paths, file sizes, durable paths, extent ownership, snapshots, journal
//! replay, repair writeback authority, operation ordering, and structured
//! failure evidence. It is not a parallel implementation of FrankenFS internals.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const INVARIANT_ORACLE_SCHEMA_VERSION: u32 = 1;
pub const INVARIANT_ORACLE_MODEL_VERSION: &str = "ffs-invariant-oracle-model-v1";
pub const DEFAULT_INVARIANT_ORACLE_ARTIFACT: &str = "artifacts/invariant/oracle_report.json";
pub const INVARIANT_ORACLE_REPRODUCTION_COMMAND: &str = "ffs-harness validate-invariant-oracle --trace artifacts/invariant/trace.json --out artifacts/invariant/oracle_report.json";

const ROOT_PATH: &str = "/";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantTrace {
    pub schema_version: u32,
    pub model_version: String,
    pub trace_id: String,
    pub seed: u64,
    pub reproduction_command: String,
    pub operations: Vec<InvariantTraceOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantTraceOperation {
    pub operation_id: String,
    pub operation_index: usize,
    pub action: InvariantAction,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_written: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extent_start: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extent_len: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_authority: Option<String>,
    pub precondition: String,
    pub expected_model_delta: String,
    pub observed_subsystem_event: String,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    pub expected_state: InvariantModelState,
    pub observed_state: InvariantModelState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_violation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_class: Option<InvariantFailureClass>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantAction {
    CreateFile,
    WriteFile,
    FsyncFile,
    Mkdir,
    RenamePath,
    UnlinkPath,
    AllocateExtent,
    SnapshotRead,
    JournalReplay,
    RepairWriteback,
    UnsupportedOperation,
    ModelInvariantProbe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantFailureClass {
    ModelBug,
    ProductionBug,
    UnsupportedOperation,
    HarnessBug,
}

impl InvariantFailureClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ModelBug => "model_bug",
            Self::ProductionBug => "production_bug",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::HarnessBug => "harness_bug",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantModelState {
    #[serde(default)]
    pub directories: Vec<String>,
    #[serde(default)]
    pub files: Vec<InvariantFileState>,
    #[serde(default)]
    pub durable_paths: Vec<String>,
    #[serde(default)]
    pub extents: Vec<InvariantExtentState>,
    #[serde(default)]
    pub snapshots: Vec<InvariantSnapshotState>,
    #[serde(default)]
    pub journal_replay_count: u64,
    #[serde(default)]
    pub repair_writeback_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantFileState {
    pub path: String,
    pub size: u64,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InvariantExtentState {
    pub path: String,
    pub start: u64,
    pub len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InvariantSnapshotState {
    pub snapshot_id: String,
    pub visible_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantOracleReport {
    pub schema_version: u32,
    pub model_version: String,
    pub trace_id: String,
    pub seed: u64,
    pub operation_count: usize,
    pub deterministic_replay_id: String,
    pub valid: bool,
    pub expected_failure_count: usize,
    pub unexpected_failure_count: usize,
    pub failure_class_counts: BTreeMap<String, usize>,
    pub violations: Vec<InvariantViolationReport>,
    pub errors: Vec<String>,
    pub reproduction_command: String,
    pub required_artifacts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantOracleConsumerReport {
    pub schema_version: u32,
    pub model_version: String,
    pub trace_id: String,
    pub valid: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantViolationReport {
    pub model_version: String,
    pub trace_id: String,
    pub operation_index: usize,
    pub operation_id: String,
    pub violated_invariant: String,
    pub classification: String,
    pub expected: bool,
    pub failure_class: InvariantFailureClass,
    pub pre_state_hash: String,
    pub post_state_hash: String,
    pub expected_invariant_result: bool,
    pub observed_invariant_result: bool,
    pub expected_state: InvariantModelState,
    pub observed_state: InvariantModelState,
    pub minimized_trace: MinimizedInvariantTrace,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub non_minimized_follow_up: Option<String>,
    pub reproduction_command: String,
    pub artifact_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimizedInvariantTrace {
    pub original_trace_len: usize,
    pub minimized_trace_len: usize,
    pub minimized: bool,
    pub operation_ids: Vec<String>,
    pub shrink_steps: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayState {
    directories: BTreeSet<String>,
    files: BTreeMap<String, ReplayFile>,
    durable_paths: BTreeSet<String>,
    extents: Vec<InvariantExtentState>,
    snapshots: BTreeMap<String, Vec<String>>,
    journal_replay_count: u64,
    repair_writeback_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayFile {
    size: u64,
    content_hash: String,
}

#[derive(Debug, Clone)]
struct ViolationEvidence {
    pre_state_hash: String,
    post_state_hash: String,
    expected_invariant_result: bool,
    observed_invariant_result: bool,
    expected_state: InvariantModelState,
    observed_state: InvariantModelState,
    force_expected: bool,
}

pub fn load_invariant_trace(path: &Path) -> Result<InvariantTrace> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read invariant trace {}", path.display()))?;
    parse_invariant_trace(&text)
        .with_context(|| format!("invalid invariant trace {}", path.display()))
}

pub fn load_invariant_oracle_report(path: &Path) -> Result<InvariantOracleReport> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read invariant oracle report {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid invariant oracle report {}", path.display()))
}

pub fn parse_invariant_trace(text: &str) -> Result<InvariantTrace> {
    serde_json::from_str(text).context("failed to parse invariant trace JSON")
}

#[must_use]
pub fn validate_invariant_trace(trace: &InvariantTrace) -> InvariantOracleReport {
    let mut errors = Vec::new();
    let mut operation_ids = BTreeSet::new();
    let mut state = ReplayState::new();
    let mut violations = Vec::new();

    validate_trace_header(trace, &mut errors);

    for (sequence_index, operation) in trace.operations.iter().enumerate() {
        validate_operation_shape(operation, sequence_index, &mut operation_ids, &mut errors);

        let pre_state_hash = model_state_hash(&state.to_model_state());
        let replay_violations = state.apply(operation);
        let replay_state = state.to_model_state();
        let replay_state_hash = model_state_hash(&replay_state);
        if replay_state != operation.expected_state {
            violations.push(build_violation(
                trace,
                operation,
                "model_replay_matches_expected_state",
                InvariantFailureClass::ModelBug,
                ViolationEvidence {
                    pre_state_hash: pre_state_hash.clone(),
                    post_state_hash: replay_state_hash.clone(),
                    expected_invariant_result: true,
                    observed_invariant_result: false,
                    expected_state: replay_state,
                    observed_state: operation.expected_state.clone(),
                    force_expected: true,
                },
            ));
        }

        for invariant in replay_violations {
            violations.push(build_violation(
                trace,
                operation,
                invariant,
                InvariantFailureClass::ModelBug,
                ViolationEvidence {
                    pre_state_hash: pre_state_hash.clone(),
                    post_state_hash: replay_state_hash.clone(),
                    expected_invariant_result: true,
                    observed_invariant_result: false,
                    expected_state: operation.expected_state.clone(),
                    observed_state: operation.observed_state.clone(),
                    force_expected: false,
                },
            ));
        }

        for invariant in compare_states(&operation.expected_state, &operation.observed_state) {
            let failure_class = operation.failure_class.unwrap_or_else(|| {
                if operation.action == InvariantAction::UnsupportedOperation {
                    InvariantFailureClass::UnsupportedOperation
                } else {
                    InvariantFailureClass::ProductionBug
                }
            });
            violations.push(build_violation(
                trace,
                operation,
                invariant,
                failure_class,
                ViolationEvidence {
                    pre_state_hash: pre_state_hash.clone(),
                    post_state_hash: model_state_hash(&operation.observed_state),
                    expected_invariant_result: true,
                    observed_invariant_result: false,
                    expected_state: operation.expected_state.clone(),
                    observed_state: operation.observed_state.clone(),
                    force_expected: false,
                },
            ));
        }

        validate_expected_violation(operation, &violations, &mut errors);
    }

    let unexpected_failure_count = violations
        .iter()
        .filter(|violation| !violation.expected)
        .count();
    let expected_failure_count = violations.len() - unexpected_failure_count;
    let failure_class_counts = count_failure_classes(&violations);

    InvariantOracleReport {
        schema_version: INVARIANT_ORACLE_SCHEMA_VERSION,
        model_version: trace.model_version.clone(),
        trace_id: trace.trace_id.clone(),
        seed: trace.seed,
        operation_count: trace.operations.len(),
        deterministic_replay_id: deterministic_replay_id(trace),
        valid: errors.is_empty() && unexpected_failure_count == 0,
        expected_failure_count,
        unexpected_failure_count,
        failure_class_counts,
        violations,
        errors,
        reproduction_command: trace.reproduction_command.clone(),
        required_artifacts: collect_required_artifacts(trace),
    }
}

#[must_use]
pub fn build_invariant_oracle_consumer_report(
    report: &InvariantOracleReport,
) -> InvariantOracleConsumerReport {
    let errors = validate_invariant_oracle_report(report);
    InvariantOracleConsumerReport {
        schema_version: report.schema_version,
        model_version: report.model_version.clone(),
        trace_id: report.trace_id.clone(),
        valid: errors.is_empty(),
        errors,
    }
}

#[must_use]
pub fn validate_invariant_oracle_report(report: &InvariantOracleReport) -> Vec<String> {
    let mut errors = Vec::new();
    if report.schema_version != INVARIANT_ORACLE_SCHEMA_VERSION {
        errors.push(format!(
            "report schema_version must be {INVARIANT_ORACLE_SCHEMA_VERSION}, got {}",
            report.schema_version
        ));
    }
    if report.model_version != INVARIANT_ORACLE_MODEL_VERSION {
        errors.push(format!(
            "report model_version must be {INVARIANT_ORACLE_MODEL_VERSION}, got {}",
            report.model_version
        ));
    }
    if !report.valid {
        errors.push("report valid flag must be true for proof-bundle consumption".to_owned());
    }
    if !is_sha256_hex(&report.deterministic_replay_id) {
        errors.push("deterministic_replay_id must be SHA-256 hex".to_owned());
    }
    validate_reproduction_command(
        "report.reproduction_command",
        &report.reproduction_command,
        &mut errors,
    );
    if !report.errors.is_empty() {
        errors.push(format!(
            "report carries {} trace validation error(s)",
            report.errors.len()
        ));
    }

    let expected_failure_count = report
        .violations
        .iter()
        .filter(|violation| violation.expected)
        .count();
    let unexpected_failure_count = report.violations.len() - expected_failure_count;
    if expected_failure_count != report.expected_failure_count {
        errors.push(format!(
            "expected_failure_count {} does not match {} violation(s)",
            report.expected_failure_count, expected_failure_count
        ));
    }
    if unexpected_failure_count != report.unexpected_failure_count {
        errors.push(format!(
            "unexpected_failure_count {} does not match {} violation(s)",
            report.unexpected_failure_count, unexpected_failure_count
        ));
    }
    let failure_class_counts = count_failure_classes(&report.violations);
    if failure_class_counts != report.failure_class_counts {
        errors.push("failure_class_counts does not match violations".to_owned());
    }

    for violation in &report.violations {
        validate_violation_report(report, violation, &mut errors);
    }
    errors
}

fn validate_violation_report(
    report: &InvariantOracleReport,
    violation: &InvariantViolationReport,
    errors: &mut Vec<String>,
) {
    if violation.model_version != report.model_version {
        errors.push(format!(
            "violation {} model_version {} does not match report model_version {}",
            violation.operation_id, violation.model_version, report.model_version
        ));
    }
    if violation.classification != violation.failure_class.label() {
        errors.push(format!(
            "violation {} classification must be {}",
            violation.operation_id,
            violation.failure_class.label()
        ));
    }
    if !is_sha256_hex(&violation.pre_state_hash) {
        errors.push(format!(
            "violation {} pre_state_hash must be SHA-256 hex",
            violation.operation_id
        ));
    }
    if !is_sha256_hex(&violation.post_state_hash) {
        errors.push(format!(
            "violation {} post_state_hash must be SHA-256 hex",
            violation.operation_id
        ));
    }
    if violation.expected_invariant_result == violation.observed_invariant_result {
        errors.push(format!(
            "violation {} must record disagreeing expected/observed invariant results",
            violation.operation_id
        ));
    }
    if violation.minimized_trace.shrink_steps.is_empty() {
        errors.push(format!(
            "violation {} must include shrink_steps",
            violation.operation_id
        ));
    }
    if !violation.minimized_trace.minimized
        && violation
            .non_minimized_follow_up
            .as_deref()
            .is_none_or(str::is_empty)
    {
        errors.push(format!(
            "violation {} non-minimized failure requires follow-up bead",
            violation.operation_id
        ));
    }
    validate_reproduction_command(
        "violation.reproduction_command",
        &violation.reproduction_command,
        errors,
    );
    validate_reproduction_command(
        "violation.minimized_trace.reproduction_command",
        &violation.minimized_trace.reproduction_command,
        errors,
    );
}

pub fn fail_on_invariant_oracle_errors(report: &InvariantOracleReport) -> Result<()> {
    let report_errors = validate_invariant_oracle_report(report);
    if !report.errors.is_empty() || report.unexpected_failure_count > 0 || !report_errors.is_empty()
    {
        for error in &report.errors {
            eprintln!("invariant oracle validation error: {error}");
        }
        for error in &report_errors {
            eprintln!("invariant oracle report artifact error: {error}");
        }
        for violation in report
            .violations
            .iter()
            .filter(|violation| !violation.expected)
        {
            eprintln!(
                "unexpected invariant violation: trace={} op={} invariant={} class={}",
                violation.trace_id,
                violation.operation_id,
                violation.violated_invariant,
                violation.failure_class.label()
            );
        }
        bail!(
            "invariant oracle validation failed: errors={} report_errors={} unexpected_failures={}",
            report.errors.len(),
            report_errors.len(),
            report.unexpected_failure_count
        );
    }
    Ok(())
}

#[must_use]
pub fn render_invariant_oracle_markdown(report: &InvariantOracleReport) -> String {
    let mut out = String::new();
    out.push_str("# Invariant Oracle Report\n\n");
    let _ = writeln!(out, "- Model version: `{}`", report.model_version);
    let _ = writeln!(out, "- Trace: `{}`", report.trace_id);
    let _ = writeln!(out, "- Seed: `{}`", report.seed);
    let _ = writeln!(
        out,
        "- Deterministic replay id: `{}`",
        report.deterministic_replay_id
    );
    let _ = writeln!(
        out,
        "- Operations: {} expected_failures={} unexpected_failures={} errors={}",
        report.operation_count,
        report.expected_failure_count,
        report.unexpected_failure_count,
        report.errors.len()
    );
    let _ = writeln!(out, "- Reproduction: `{}`", report.reproduction_command);
    out.push('\n');

    if report.violations.is_empty() {
        out.push_str("No invariant violations were reported.\n");
    } else {
        out.push_str("## Violations\n\n");
        for violation in &report.violations {
            let _ = writeln!(
                out,
                "- op `{}` index={} invariant=`{}` class=`{}` expected={} minimized={}/{} pre={} post={}",
                violation.operation_id,
                violation.operation_index,
                violation.violated_invariant,
                violation.failure_class.label(),
                violation.expected,
                violation.minimized_trace.minimized_trace_len,
                violation.minimized_trace.original_trace_len,
                violation.pre_state_hash,
                violation.post_state_hash
            );
        }
    }

    out
}

fn validate_trace_header(trace: &InvariantTrace, errors: &mut Vec<String>) {
    if trace.schema_version != INVARIANT_ORACLE_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {INVARIANT_ORACLE_SCHEMA_VERSION}, got {}",
            trace.schema_version
        ));
    }
    if trace.model_version != INVARIANT_ORACLE_MODEL_VERSION {
        errors.push(format!(
            "model_version must be {INVARIANT_ORACLE_MODEL_VERSION}, got {}",
            trace.model_version
        ));
    }
    validate_nonempty("trace_id", &trace.trace_id, errors);
    validate_reproduction_command("reproduction_command", &trace.reproduction_command, errors);
    if trace.operations.is_empty() {
        errors.push("trace must contain at least one operation".to_owned());
    }
}

fn validate_reproduction_command(field: &str, command: &str, errors: &mut Vec<String>) {
    validate_nonempty(field, command, errors);
    if !command.contains("validate-invariant-oracle") {
        errors.push(format!(
            "{field} must include validate-invariant-oracle invocation"
        ));
    }
}

fn validate_operation_shape(
    operation: &InvariantTraceOperation,
    sequence_index: usize,
    operation_ids: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    validate_nonempty("operation_id", &operation.operation_id, errors);
    validate_nonempty("precondition", &operation.precondition, errors);
    validate_nonempty(
        "expected_model_delta",
        &operation.expected_model_delta,
        errors,
    );
    validate_nonempty(
        "observed_subsystem_event",
        &operation.observed_subsystem_event,
        errors,
    );
    validate_path("operation.path", &operation.path, errors);
    if let Some(target_path) = &operation.target_path {
        validate_path("operation.target_path", target_path, errors);
    }
    if !operation_ids.insert(operation.operation_id.clone()) {
        errors.push(format!("duplicate operation_id {}", operation.operation_id));
    }
    if operation.operation_index != sequence_index {
        errors.push(format!(
            "operation {} operation_index {} must match sequence index {sequence_index}",
            operation.operation_id, operation.operation_index
        ));
    }
    if operation.failure_class.is_some() && operation.expected_violation.is_none() {
        errors.push(format!(
            "operation {} failure_class requires expected_violation",
            operation.operation_id
        ));
    }
    if operation.action == InvariantAction::WriteFile && operation.bytes_written.is_none() {
        errors.push(format!(
            "operation {} write_file requires bytes_written",
            operation.operation_id
        ));
    }
    if operation.action == InvariantAction::RenamePath && operation.target_path.is_none() {
        errors.push(format!(
            "operation {} rename_path requires target_path",
            operation.operation_id
        ));
    }
    if operation.action == InvariantAction::AllocateExtent
        && (operation.extent_start.is_none() || operation.extent_len.is_none())
    {
        errors.push(format!(
            "operation {} allocate_extent requires extent_start and extent_len",
            operation.operation_id
        ));
    }
    if operation.action == InvariantAction::SnapshotRead && operation.snapshot_id.is_none() {
        errors.push(format!(
            "operation {} snapshot_read requires snapshot_id",
            operation.operation_id
        ));
    }
    if operation.action == InvariantAction::RepairWriteback && operation.repair_authority.is_none()
    {
        errors.push(format!(
            "operation {} repair_writeback requires repair_authority",
            operation.operation_id
        ));
    }
    validate_state_paths("expected_state", &operation.expected_state, errors);
    validate_state_paths("observed_state", &operation.observed_state, errors);
}

fn validate_expected_violation(
    operation: &InvariantTraceOperation,
    violations: &[InvariantViolationReport],
    errors: &mut Vec<String>,
) {
    let Some(expected_violation) = &operation.expected_violation else {
        return;
    };
    let matched = violations.iter().any(|violation| {
        violation.operation_id == operation.operation_id
            && violation.violated_invariant == *expected_violation
    });
    if !matched {
        errors.push(format!(
            "operation {} expected violation {} did not fire",
            operation.operation_id, expected_violation
        ));
    }
}

fn validate_nonempty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must be nonempty"));
    }
}

fn validate_state_paths(prefix: &str, state: &InvariantModelState, errors: &mut Vec<String>) {
    for path in &state.directories {
        validate_path(&format!("{prefix}.directories"), path, errors);
    }
    for path in &state.durable_paths {
        validate_path(&format!("{prefix}.durable_paths"), path, errors);
    }
    for file in &state.files {
        validate_path(&format!("{prefix}.files.path"), &file.path, errors);
        if !is_sha256_hex(&file.content_hash) {
            errors.push(format!(
                "{prefix}.files {} content_hash must be SHA-256 hex",
                file.path
            ));
        }
    }
    for extent in &state.extents {
        validate_path(&format!("{prefix}.extents.path"), &extent.path, errors);
        if extent.len == 0 {
            errors.push(format!(
                "{prefix}.extents {} length must be nonzero",
                extent.path
            ));
        }
    }
    for snapshot in &state.snapshots {
        validate_nonempty(
            &format!("{prefix}.snapshots.snapshot_id"),
            &snapshot.snapshot_id,
            errors,
        );
        for path in &snapshot.visible_paths {
            validate_path(&format!("{prefix}.snapshots.visible_paths"), path, errors);
        }
    }
}

fn validate_path(field: &str, path: &str, errors: &mut Vec<String>) {
    if !path.starts_with(ROOT_PATH) {
        errors.push(format!("{field} {path} must be absolute"));
    }
    if path.contains("..") {
        errors.push(format!("{field} {path} must not contain parent traversal"));
    }
}

impl ReplayState {
    fn new() -> Self {
        Self {
            directories: BTreeSet::from([ROOT_PATH.to_owned()]),
            files: BTreeMap::new(),
            durable_paths: BTreeSet::new(),
            extents: Vec::new(),
            snapshots: BTreeMap::new(),
            journal_replay_count: 0,
            repair_writeback_count: 0,
        }
    }

    fn apply(&mut self, operation: &InvariantTraceOperation) -> Vec<&'static str> {
        match operation.action {
            InvariantAction::CreateFile => self.apply_create_file(operation),
            InvariantAction::WriteFile => self.apply_write_file(operation),
            InvariantAction::FsyncFile => self.apply_fsync_file(operation),
            InvariantAction::Mkdir => self.apply_mkdir(operation),
            InvariantAction::RenamePath => self.apply_rename_path(operation),
            InvariantAction::UnlinkPath => self.apply_unlink_path(operation),
            InvariantAction::AllocateExtent => self.apply_allocate_extent(operation),
            InvariantAction::SnapshotRead => self.apply_snapshot_read(operation),
            InvariantAction::JournalReplay => {
                if self.journal_replay_count == 0 {
                    self.journal_replay_count = 1;
                }
                Vec::new()
            }
            InvariantAction::RepairWriteback => self.apply_repair_writeback(operation),
            InvariantAction::UnsupportedOperation | InvariantAction::ModelInvariantProbe => {
                Vec::new()
            }
        }
    }

    fn apply_create_file(&mut self, operation: &InvariantTraceOperation) -> Vec<&'static str> {
        let mut violations = Vec::new();
        if !self.parent_dir_exists(&operation.path) {
            violations.push("parent_directory_exists");
        }
        self.files.insert(
            operation.path.clone(),
            ReplayFile {
                size: 0,
                content_hash: EMPTY_SHA256.to_owned(),
            },
        );
        violations
    }

    fn apply_write_file(&mut self, operation: &InvariantTraceOperation) -> Vec<&'static str> {
        let mut violations = Vec::new();
        let Some(file) = self.files.get_mut(&operation.path) else {
            violations.push("file_exists_before_write");
            return violations;
        };
        let bytes_written = operation.bytes_written.unwrap_or(0);
        file.size = file.size.saturating_add(bytes_written);
        file.content_hash = synthetic_content_hash(&operation.path, file.size);
        violations
    }

    fn apply_fsync_file(&mut self, operation: &InvariantTraceOperation) -> Vec<&'static str> {
        let mut violations = Vec::new();
        if self.files.contains_key(&operation.path) {
            self.durable_paths.insert(operation.path.clone());
        } else {
            violations.push("fsync_target_exists");
        }
        violations
    }

    fn apply_mkdir(&mut self, operation: &InvariantTraceOperation) -> Vec<&'static str> {
        let mut violations = Vec::new();
        if !self.parent_dir_exists(&operation.path) {
            violations.push("parent_directory_exists");
        }
        self.directories.insert(operation.path.clone());
        violations
    }

    fn apply_rename_path(&mut self, operation: &InvariantTraceOperation) -> Vec<&'static str> {
        let mut violations = Vec::new();
        let Some(target_path) = operation.target_path.as_deref() else {
            violations.push("rename_target_path_present");
            return violations;
        };
        if operation.path == ROOT_PATH {
            violations.push("rename_source_not_root");
        }
        if !self.files.contains_key(&operation.path) && !self.directories.contains(&operation.path)
        {
            violations.push("rename_source_exists");
        }
        if !self.parent_dir_exists(target_path) {
            violations.push("rename_target_parent_exists");
        }
        if self.files.contains_key(target_path) || self.directories.contains(target_path) {
            violations.push("rename_target_absent");
        }
        if violations.is_empty() {
            self.rebase_path_tree(&operation.path, target_path);
        }
        violations
    }

    fn apply_unlink_path(&mut self, operation: &InvariantTraceOperation) -> Vec<&'static str> {
        let mut violations = Vec::new();
        if self.files.remove(&operation.path).is_none() {
            violations.push("unlink_target_exists");
        }
        self.durable_paths.remove(&operation.path);
        self.extents.retain(|extent| extent.path != operation.path);
        violations
    }

    fn apply_allocate_extent(&mut self, operation: &InvariantTraceOperation) -> Vec<&'static str> {
        let mut violations = Vec::new();
        let Some(start) = operation.extent_start else {
            violations.push("extent_fields_present");
            return violations;
        };
        let Some(len) = operation.extent_len else {
            violations.push("extent_fields_present");
            return violations;
        };
        if !self.files.contains_key(&operation.path) {
            violations.push("extent_owner_file_exists");
        }
        if len == 0 || start.checked_add(len).is_none() {
            violations.push("extent_range_valid");
        } else if self.extent_overlaps(start, len) {
            violations.push("extent_range_does_not_overlap");
        }
        if violations.is_empty() {
            self.extents.push(InvariantExtentState {
                path: operation.path.clone(),
                start,
                len,
            });
            self.extents.sort();
        }
        violations
    }

    fn apply_snapshot_read(&mut self, operation: &InvariantTraceOperation) -> Vec<&'static str> {
        let mut violations = Vec::new();
        let Some(snapshot_id) = operation.snapshot_id.as_deref() else {
            violations.push("snapshot_id_present");
            return violations;
        };
        if snapshot_id.trim().is_empty() {
            violations.push("snapshot_id_present");
        }
        if violations.is_empty() {
            self.snapshots
                .insert(snapshot_id.to_owned(), self.files.keys().cloned().collect());
        }
        violations
    }

    fn apply_repair_writeback(&mut self, operation: &InvariantTraceOperation) -> Vec<&'static str> {
        let mut violations = Vec::new();
        if !self.files.contains_key(&operation.path) {
            violations.push("repair_target_exists");
        }
        if operation.repair_authority.as_deref() != Some("mounted_mutation_authority") {
            violations.push("repair_writeback_uses_mutation_authority");
        }
        if violations.is_empty() {
            self.repair_writeback_count = self.repair_writeback_count.saturating_add(1);
        }
        violations
    }

    fn parent_dir_exists(&self, path: &str) -> bool {
        if path == ROOT_PATH {
            return true;
        }
        let Some((parent, _name)) = path.rsplit_once('/') else {
            return false;
        };
        let parent = if parent.is_empty() { ROOT_PATH } else { parent };
        self.directories.contains(parent)
    }

    fn extent_overlaps(&self, start: u64, len: u64) -> bool {
        self.extents
            .iter()
            .any(|extent| ranges_overlap(start, len, extent.start, extent.len))
    }

    fn rebase_path_tree(&mut self, source: &str, target: &str) {
        self.directories = self
            .directories
            .iter()
            .map(|path| rebase_path(path, source, target))
            .collect();
        self.files = std::mem::take(&mut self.files)
            .into_iter()
            .map(|(path, file)| (rebase_path(&path, source, target), file))
            .collect();
        self.durable_paths = self
            .durable_paths
            .iter()
            .map(|path| rebase_path(path, source, target))
            .collect();
        for extent in &mut self.extents {
            extent.path = rebase_path(&extent.path, source, target);
        }
        self.extents.sort();
    }

    fn to_model_state(&self) -> InvariantModelState {
        InvariantModelState {
            directories: self.directories.iter().cloned().collect(),
            files: self
                .files
                .iter()
                .map(|(path, file)| InvariantFileState {
                    path: path.clone(),
                    size: file.size,
                    content_hash: file.content_hash.clone(),
                })
                .collect(),
            durable_paths: self.durable_paths.iter().cloned().collect(),
            extents: self.extents.clone(),
            snapshots: self
                .snapshots
                .iter()
                .map(|(snapshot_id, visible_paths)| InvariantSnapshotState {
                    snapshot_id: snapshot_id.clone(),
                    visible_paths: visible_paths.clone(),
                })
                .collect(),
            journal_replay_count: self.journal_replay_count,
            repair_writeback_count: self.repair_writeback_count,
        }
    }
}

fn compare_states(
    expected: &InvariantModelState,
    observed: &InvariantModelState,
) -> Vec<&'static str> {
    let expected_dirs: BTreeSet<&str> = expected.directories.iter().map(String::as_str).collect();
    let observed_dirs: BTreeSet<&str> = observed.directories.iter().map(String::as_str).collect();
    let expected_durable: BTreeSet<&str> =
        expected.durable_paths.iter().map(String::as_str).collect();
    let observed_durable: BTreeSet<&str> =
        observed.durable_paths.iter().map(String::as_str).collect();
    let expected_files = file_map(expected);
    let observed_files = file_map(observed);
    let expected_extents: BTreeSet<&InvariantExtentState> = expected.extents.iter().collect();
    let observed_extents: BTreeSet<&InvariantExtentState> = observed.extents.iter().collect();
    let expected_snapshots: BTreeSet<&InvariantSnapshotState> = expected.snapshots.iter().collect();
    let observed_snapshots: BTreeSet<&InvariantSnapshotState> = observed.snapshots.iter().collect();

    let mut invariants = Vec::new();
    if !observed_dirs.contains(ROOT_PATH) {
        invariants.push("root_directory_exists");
    }
    if expected_dirs != observed_dirs {
        invariants.push("directory_set_matches_model");
    }
    if expected_durable != observed_durable {
        invariants.push("durability_set_matches_model");
    }
    if expected_extents != observed_extents {
        invariants.push("extent_set_matches_model");
    }
    if state_has_overlapping_extents(observed) {
        invariants.push("extent_range_does_not_overlap");
    }
    if expected_snapshots != observed_snapshots {
        invariants.push("snapshot_set_matches_model");
    }
    if expected.journal_replay_count != observed.journal_replay_count {
        invariants.push("journal_replay_idempotent");
    }
    if expected.repair_writeback_count != observed.repair_writeback_count {
        invariants.push("repair_writeback_count_matches_model");
    }
    for (path, expected_file) in &expected_files {
        let Some(observed_file) = observed_files.get(path) else {
            invariants.push("observed_file_exists");
            continue;
        };
        if expected_file.size != observed_file.size {
            invariants.push("file_size_matches_model");
        } else if expected_file.content_hash != observed_file.content_hash {
            invariants.push("file_content_hash_matches_model");
        }
    }
    for path in observed_files.keys() {
        if !expected_files.contains_key(path) {
            invariants.push("observed_no_extra_files");
        }
    }
    invariants.sort_unstable();
    invariants.dedup();
    invariants
}

fn file_map(state: &InvariantModelState) -> BTreeMap<&str, &InvariantFileState> {
    state
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect()
}

fn build_violation(
    trace: &InvariantTrace,
    operation: &InvariantTraceOperation,
    invariant: &str,
    failure_class: InvariantFailureClass,
    evidence: ViolationEvidence,
) -> InvariantViolationReport {
    let expected = evidence.force_expected
        || operation
            .expected_violation
            .as_ref()
            .is_some_and(|expected| expected == invariant);
    InvariantViolationReport {
        model_version: trace.model_version.clone(),
        trace_id: trace.trace_id.clone(),
        operation_index: operation.operation_index,
        operation_id: operation.operation_id.clone(),
        violated_invariant: invariant.to_owned(),
        classification: failure_class.label().to_owned(),
        expected,
        failure_class,
        pre_state_hash: evidence.pre_state_hash,
        post_state_hash: evidence.post_state_hash,
        expected_invariant_result: evidence.expected_invariant_result,
        observed_invariant_result: evidence.observed_invariant_result,
        expected_state: evidence.expected_state,
        observed_state: evidence.observed_state,
        minimized_trace: minimize_trace(trace, operation.operation_index),
        non_minimized_follow_up: None,
        reproduction_command: trace.reproduction_command.clone(),
        artifact_refs: operation.artifact_refs.clone(),
    }
}

fn minimize_trace(trace: &InvariantTrace, operation_index: usize) -> MinimizedInvariantTrace {
    let limit = operation_index
        .saturating_add(1)
        .min(trace.operations.len());
    MinimizedInvariantTrace {
        original_trace_len: trace.operations.len(),
        minimized_trace_len: limit,
        minimized: true,
        operation_ids: trace
            .operations
            .iter()
            .take(limit)
            .map(|operation| operation.operation_id.clone())
            .collect(),
        shrink_steps: shrink_steps(trace, operation_index, limit),
        reproduction_command: trace.reproduction_command.clone(),
    }
}

fn shrink_steps(trace: &InvariantTrace, operation_index: usize, limit: usize) -> Vec<String> {
    let dropped_suffix = trace.operations.len().saturating_sub(limit);
    vec![
        format!("seed={}", trace.seed),
        format!("kept prefix through failing operation index {operation_index}"),
        format!("dropped_suffix_operations={dropped_suffix}"),
    ]
}

fn deterministic_replay_id(trace: &InvariantTrace) -> String {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, &trace.model_version);
    hash_part(&mut hasher, &trace.trace_id);
    hash_part(&mut hasher, &trace.seed.to_string());
    let mut state = ReplayState::new();
    for operation in &trace.operations {
        hash_part(&mut hasher, &operation.operation_id);
        hash_part(&mut hasher, &operation.operation_index.to_string());
        hash_part(&mut hasher, action_label(operation.action));
        hash_part(&mut hasher, &operation.path);
        hash_part(
            &mut hasher,
            operation.target_path.as_deref().unwrap_or_default(),
        );
        hash_part(
            &mut hasher,
            &operation.bytes_written.unwrap_or_default().to_string(),
        );
        hash_part(
            &mut hasher,
            &operation.extent_start.unwrap_or_default().to_string(),
        );
        hash_part(
            &mut hasher,
            &operation.extent_len.unwrap_or_default().to_string(),
        );
        hash_part(
            &mut hasher,
            operation.snapshot_id.as_deref().unwrap_or_default(),
        );
        hash_part(
            &mut hasher,
            operation.repair_authority.as_deref().unwrap_or_default(),
        );
        state.apply(operation);
        hash_model_state(&mut hasher, &state.to_model_state());
    }
    hex::encode(hasher.finalize())
}

fn action_label(action: InvariantAction) -> &'static str {
    match action {
        InvariantAction::CreateFile => "create_file",
        InvariantAction::WriteFile => "write_file",
        InvariantAction::FsyncFile => "fsync_file",
        InvariantAction::Mkdir => "mkdir",
        InvariantAction::RenamePath => "rename_path",
        InvariantAction::UnlinkPath => "unlink_path",
        InvariantAction::AllocateExtent => "allocate_extent",
        InvariantAction::SnapshotRead => "snapshot_read",
        InvariantAction::JournalReplay => "journal_replay",
        InvariantAction::RepairWriteback => "repair_writeback",
        InvariantAction::UnsupportedOperation => "unsupported_operation",
        InvariantAction::ModelInvariantProbe => "model_invariant_probe",
    }
}

fn hash_model_state(hasher: &mut Sha256, state: &InvariantModelState) {
    hash_part(hasher, "directories");
    hash_part(hasher, &state.directories.len().to_string());
    for directory in &state.directories {
        hash_part(hasher, directory);
    }
    hash_part(hasher, "files");
    hash_part(hasher, &state.files.len().to_string());
    for file in &state.files {
        hash_part(hasher, &file.path);
        hash_part(hasher, &file.size.to_string());
        hash_part(hasher, &file.content_hash);
    }
    hash_part(hasher, "durable_paths");
    hash_part(hasher, &state.durable_paths.len().to_string());
    for durable_path in &state.durable_paths {
        hash_part(hasher, durable_path);
    }
    hash_part(hasher, "extents");
    hash_part(hasher, &state.extents.len().to_string());
    for extent in &state.extents {
        hash_part(hasher, &extent.path);
        hash_part(hasher, &extent.start.to_string());
        hash_part(hasher, &extent.len.to_string());
    }
    hash_part(hasher, "snapshots");
    hash_part(hasher, &state.snapshots.len().to_string());
    for snapshot in &state.snapshots {
        hash_part(hasher, &snapshot.snapshot_id);
        hash_part(hasher, &snapshot.visible_paths.len().to_string());
        for path in &snapshot.visible_paths {
            hash_part(hasher, path);
        }
    }
    hash_part(hasher, "journal_replay_count");
    hash_part(hasher, &state.journal_replay_count.to_string());
    hash_part(hasher, "repair_writeback_count");
    hash_part(hasher, &state.repair_writeback_count.to_string());
}

fn model_state_hash(state: &InvariantModelState) -> String {
    let mut hasher = Sha256::new();
    hash_model_state(&mut hasher, state);
    hex::encode(hasher.finalize())
}

fn hash_part(hasher: &mut Sha256, value: &str) {
    hasher.update(value.len().to_string().as_bytes());
    hasher.update(b":");
    hasher.update(value.as_bytes());
    hasher.update(b";");
}

fn synthetic_content_hash(path: &str, size: u64) -> String {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, path);
    hash_part(&mut hasher, &size.to_string());
    hex::encode(hasher.finalize())
}

fn is_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn count_failure_classes(violations: &[InvariantViolationReport]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for violation in violations {
        *counts
            .entry(violation.failure_class.label().to_owned())
            .or_insert(0) += 1;
    }
    counts
}

fn collect_required_artifacts(trace: &InvariantTrace) -> Vec<String> {
    let mut artifacts = BTreeSet::new();
    for operation in &trace.operations {
        artifacts.extend(operation.artifact_refs.iter().cloned());
    }
    artifacts.into_iter().collect()
}

fn ranges_overlap(a_start: u64, a_len: u64, b_start: u64, b_len: u64) -> bool {
    let Some(a_end) = a_start.checked_add(a_len) else {
        return true;
    };
    let Some(b_end) = b_start.checked_add(b_len) else {
        return true;
    };
    a_start < b_end && b_start < a_end
}

fn state_has_overlapping_extents(state: &InvariantModelState) -> bool {
    for (index, left) in state.extents.iter().enumerate() {
        for right in state.extents.iter().skip(index + 1) {
            if ranges_overlap(left.start, left.len, right.start, right.len) {
                return true;
            }
        }
    }
    false
}

fn rebase_path(path: &str, source: &str, target: &str) -> String {
    if path == source {
        return target.to_owned();
    }
    if source == ROOT_PATH {
        return path.to_owned();
    }
    let Some(suffix) = path.strip_prefix(source) else {
        return path.to_owned();
    };
    if !suffix.starts_with('/') {
        return path.to_owned();
    }
    format!("{target}{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(files: &[(&str, u64)], durable: &[&str]) -> InvariantModelState {
        InvariantModelState {
            directories: vec![ROOT_PATH.to_owned()],
            files: files
                .iter()
                .map(|(path, size)| InvariantFileState {
                    path: (*path).to_owned(),
                    size: *size,
                    content_hash: if *size == 0 {
                        EMPTY_SHA256.to_owned()
                    } else {
                        synthetic_content_hash(path, *size)
                    },
                })
                .collect(),
            durable_paths: durable.iter().map(|path| (*path).to_owned()).collect(),
            ..InvariantModelState::default()
        }
    }

    fn state_with_dirs(
        directories: &[&str],
        files: &[(&str, u64)],
        durable: &[&str],
    ) -> InvariantModelState {
        InvariantModelState {
            directories: directories
                .iter()
                .map(|directory| (*directory).to_owned())
                .collect(),
            files: files
                .iter()
                .map(|(path, size)| InvariantFileState {
                    path: (*path).to_owned(),
                    size: *size,
                    content_hash: if *size == 0 {
                        EMPTY_SHA256.to_owned()
                    } else {
                        synthetic_content_hash(path, *size)
                    },
                })
                .collect(),
            durable_paths: durable.iter().map(|path| (*path).to_owned()).collect(),
            ..InvariantModelState::default()
        }
    }

    fn with_extents(
        mut state: InvariantModelState,
        extents: &[(&str, u64, u64)],
    ) -> InvariantModelState {
        state.extents = extents
            .iter()
            .map(|(path, start, len)| InvariantExtentState {
                path: (*path).to_owned(),
                start: *start,
                len: *len,
            })
            .collect();
        state.extents.sort();
        state
    }

    fn with_snapshots(
        mut state: InvariantModelState,
        snapshots: &[(&str, &[&str])],
    ) -> InvariantModelState {
        state.snapshots = snapshots
            .iter()
            .map(|(snapshot_id, visible_paths)| InvariantSnapshotState {
                snapshot_id: (*snapshot_id).to_owned(),
                visible_paths: visible_paths
                    .iter()
                    .map(|path| (*path).to_owned())
                    .collect(),
            })
            .collect();
        state.snapshots.sort();
        state
    }

    fn with_counts(
        mut state: InvariantModelState,
        journal_replay_count: u64,
        repair_writeback_count: u64,
    ) -> InvariantModelState {
        state.journal_replay_count = journal_replay_count;
        state.repair_writeback_count = repair_writeback_count;
        state
    }

    fn op(
        operation_index: usize,
        action: InvariantAction,
        path: &str,
        bytes_written: Option<u64>,
        expected_state: InvariantModelState,
        observed_state: InvariantModelState,
    ) -> InvariantTraceOperation {
        InvariantTraceOperation {
            operation_id: format!("op-{operation_index}"),
            operation_index,
            action,
            path: path.to_owned(),
            target_path: None,
            bytes_written,
            extent_start: None,
            extent_len: None,
            snapshot_id: None,
            repair_authority: None,
            precondition: "model precondition recorded".to_owned(),
            expected_model_delta: "model delta recorded".to_owned(),
            observed_subsystem_event: "OpenFs operation event".to_owned(),
            artifact_refs: vec![format!("logs/op-{operation_index}.jsonl")],
            expected_state,
            observed_state,
            expected_violation: None,
            failure_class: None,
        }
    }

    fn valid_trace() -> InvariantTrace {
        InvariantTrace {
            schema_version: INVARIANT_ORACLE_SCHEMA_VERSION,
            model_version: INVARIANT_ORACLE_MODEL_VERSION.to_owned(),
            trace_id: "trace-valid-write".to_owned(),
            seed: 42,
            reproduction_command:
                "ffs-harness validate-invariant-oracle --trace artifacts/invariant/trace.json"
                    .to_owned(),
            operations: vec![
                op(
                    0,
                    InvariantAction::CreateFile,
                    "/alpha",
                    None,
                    state(&[("/alpha", 0)], &[]),
                    state(&[("/alpha", 0)], &[]),
                ),
                op(
                    1,
                    InvariantAction::WriteFile,
                    "/alpha",
                    Some(5),
                    state(&[("/alpha", 5)], &[]),
                    state(&[("/alpha", 5)], &[]),
                ),
                op(
                    2,
                    InvariantAction::FsyncFile,
                    "/alpha",
                    None,
                    state(&[("/alpha", 5)], &["/alpha"]),
                    state(&[("/alpha", 5)], &["/alpha"]),
                ),
            ],
        }
    }

    fn first_violation(report: &InvariantOracleReport) -> Result<&InvariantViolationReport> {
        report
            .violations
            .first()
            .context("missing invariant violation")
    }

    fn first_violation_mut(
        report: &mut InvariantOracleReport,
    ) -> Result<&mut InvariantViolationReport> {
        report
            .violations
            .first_mut()
            .context("missing invariant violation")
    }

    #[test]
    fn parses_trace_schema_and_replays_deterministically() -> anyhow::Result<()> {
        let trace = valid_trace();
        let text = serde_json::to_string(&trace)?;
        let parsed = parse_invariant_trace(&text)?;
        let first = validate_invariant_trace(&parsed);
        let second = validate_invariant_trace(&parsed);
        assert!(first.valid, "{:?}", first.errors);
        assert_eq!(
            first.deterministic_replay_id,
            second.deterministic_replay_id
        );
        assert_eq!(first.model_version, INVARIANT_ORACLE_MODEL_VERSION);
        assert_eq!(validate_invariant_oracle_report(&first), [] as [String; 0]);
        assert_eq!(first.operation_count, 3);
        Ok(())
    }

    #[test]
    fn false_positive_guard_allows_zero_write_and_repeated_fsync() {
        let mut trace = valid_trace();
        trace.operations.push(op(
            3,
            InvariantAction::WriteFile,
            "/alpha",
            Some(0),
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 5)], &["/alpha"]),
        ));
        trace.operations.push(op(
            4,
            InvariantAction::FsyncFile,
            "/alpha",
            None,
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 5)], &["/alpha"]),
        ));
        let report = validate_invariant_trace(&trace);
        assert!(report.valid, "{report:?}");
        assert_eq!(report.violations, [] as [InvariantViolationReport; 0]);
    }

    #[test]
    fn expected_invariant_failure_is_reported_without_failing_trace() -> Result<()> {
        let mut trace = valid_trace();
        let mut bad = op(
            3,
            InvariantAction::ModelInvariantProbe,
            "/alpha",
            None,
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 4)], &["/alpha"]),
        );
        bad.expected_violation = Some("file_size_matches_model".to_owned());
        bad.failure_class = Some(InvariantFailureClass::ProductionBug);
        trace.operations.push(bad);

        let report = validate_invariant_trace(&trace);
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.expected_failure_count, 1);
        assert_eq!(report.unexpected_failure_count, 0);
        let violation = first_violation(&report)?;
        assert_eq!(violation.violated_invariant, "file_size_matches_model");
        assert_eq!(
            violation.failure_class,
            InvariantFailureClass::ProductionBug
        );
        assert_eq!(
            violation.classification,
            InvariantFailureClass::ProductionBug.label()
        );
        assert!(is_sha256_hex(&violation.pre_state_hash));
        assert!(is_sha256_hex(&violation.post_state_hash));
        assert!(violation.expected_invariant_result);
        assert!(!violation.observed_invariant_result);
        Ok(())
    }

    #[test]
    fn unexpected_invariant_failure_fails_trace() {
        let mut trace = valid_trace();
        trace.operations.push(op(
            3,
            InvariantAction::ModelInvariantProbe,
            "/alpha",
            None,
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 4)], &["/alpha"]),
        ));
        let report = validate_invariant_trace(&trace);
        assert!(!report.valid);
        assert_eq!(report.unexpected_failure_count, 1);
    }

    #[test]
    fn minimizer_keeps_prefix_through_failing_operation() -> Result<()> {
        let mut trace = valid_trace();
        let mut bad = op(
            3,
            InvariantAction::ModelInvariantProbe,
            "/alpha",
            None,
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 9)], &["/alpha"]),
        );
        bad.expected_violation = Some("file_size_matches_model".to_owned());
        bad.failure_class = Some(InvariantFailureClass::ProductionBug);
        trace.operations.push(bad);
        let report = validate_invariant_trace(&trace);
        let minimized = &first_violation(&report)?.minimized_trace;
        assert_eq!(minimized.original_trace_len, 4);
        assert_eq!(minimized.minimized_trace_len, 4);
        assert_eq!(
            minimized.operation_ids,
            vec!["op-0", "op-1", "op-2", "op-3"]
        );
        assert!(minimized.minimized);
        assert!(
            minimized
                .shrink_steps
                .iter()
                .any(|step| step.contains("failing operation index 3"))
        );
        Ok(())
    }

    #[test]
    fn report_consumer_rejects_unknown_model_version() {
        let trace = valid_trace();
        let mut report = validate_invariant_trace(&trace);
        report.model_version = "unknown-model".to_owned();
        let errors = validate_invariant_oracle_report(&report);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("report model_version"))
        );
    }

    #[test]
    fn report_consumer_rejects_missing_classification() -> Result<()> {
        let mut trace = valid_trace();
        let mut bad = op(
            3,
            InvariantAction::ModelInvariantProbe,
            "/alpha",
            None,
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 4)], &["/alpha"]),
        );
        bad.expected_violation = Some("file_size_matches_model".to_owned());
        bad.failure_class = Some(InvariantFailureClass::ProductionBug);
        trace.operations.push(bad);
        let mut report = validate_invariant_trace(&trace);
        first_violation_mut(&mut report)?.classification.clear();
        let errors = validate_invariant_oracle_report(&report);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("classification must be production_bug"))
        );
        Ok(())
    }

    #[test]
    fn report_consumer_rejects_non_minimized_without_follow_up() -> Result<()> {
        let mut trace = valid_trace();
        let mut bad = op(
            3,
            InvariantAction::ModelInvariantProbe,
            "/alpha",
            None,
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 4)], &["/alpha"]),
        );
        bad.expected_violation = Some("file_size_matches_model".to_owned());
        bad.failure_class = Some(InvariantFailureClass::ProductionBug);
        trace.operations.push(bad);
        let mut report = validate_invariant_trace(&trace);
        first_violation_mut(&mut report)?.minimized_trace.minimized = false;
        let errors = validate_invariant_oracle_report(&report);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("non-minimized failure requires follow-up bead"))
        );
        Ok(())
    }

    #[test]
    fn model_bug_and_unsupported_operation_classes_are_distinguishable() {
        let mut trace = valid_trace();
        let mut unsupported = op(
            3,
            InvariantAction::UnsupportedOperation,
            "/alpha",
            None,
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 5), ("/extra", 1)], &["/alpha"]),
        );
        unsupported.expected_violation = Some("observed_no_extra_files".to_owned());
        unsupported.failure_class = Some(InvariantFailureClass::UnsupportedOperation);
        trace.operations.push(unsupported);
        let report = validate_invariant_trace(&trace);
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.failure_class_counts["unsupported_operation"], 1);
    }

    #[test]
    fn nested_directory_rename_and_unlink_edges_replay() {
        let mut trace = InvariantTrace {
            schema_version: INVARIANT_ORACLE_SCHEMA_VERSION,
            model_version: INVARIANT_ORACLE_MODEL_VERSION.to_owned(),
            trace_id: "trace-rename-unlink".to_owned(),
            seed: 77,
            reproduction_command:
                "ffs-harness validate-invariant-oracle --trace artifacts/invariant/rename.json"
                    .to_owned(),
            operations: Vec::new(),
        };
        trace.operations.push(op(
            0,
            InvariantAction::Mkdir,
            "/projects",
            None,
            state_with_dirs(&["/", "/projects"], &[], &[]),
            state_with_dirs(&["/", "/projects"], &[], &[]),
        ));
        trace.operations.push(op(
            1,
            InvariantAction::CreateFile,
            "/projects/alpha",
            None,
            state_with_dirs(&["/", "/projects"], &[("/projects/alpha", 0)], &[]),
            state_with_dirs(&["/", "/projects"], &[("/projects/alpha", 0)], &[]),
        ));
        let mut rename = op(
            2,
            InvariantAction::RenamePath,
            "/projects/alpha",
            None,
            state_with_dirs(&["/", "/projects"], &[("/projects/beta", 0)], &[]),
            state_with_dirs(&["/", "/projects"], &[("/projects/beta", 0)], &[]),
        );
        rename.target_path = Some("/projects/beta".to_owned());
        trace.operations.push(rename);
        trace.operations.push(op(
            3,
            InvariantAction::UnlinkPath,
            "/projects/beta",
            None,
            state_with_dirs(&["/", "/projects"], &[], &[]),
            state_with_dirs(&["/", "/projects"], &[], &[]),
        ));

        let report = validate_invariant_trace(&trace);
        assert!(report.valid, "{report:?}");
        assert_eq!(report.violations, [] as [InvariantViolationReport; 0]);
    }

    #[test]
    fn extent_ownership_rejects_overlapping_live_ranges() -> Result<()> {
        let mut trace = valid_trace();
        let mut first_extent = op(
            3,
            InvariantAction::AllocateExtent,
            "/alpha",
            None,
            with_extents(state(&[("/alpha", 5)], &["/alpha"]), &[("/alpha", 0, 4)]),
            with_extents(state(&[("/alpha", 5)], &["/alpha"]), &[("/alpha", 0, 4)]),
        );
        first_extent.extent_start = Some(0);
        first_extent.extent_len = Some(4);
        trace.operations.push(first_extent);
        let mut second_extent = op(
            4,
            InvariantAction::AllocateExtent,
            "/alpha",
            None,
            with_extents(
                state(&[("/alpha", 5)], &["/alpha"]),
                &[("/alpha", 0, 4), ("/alpha", 4, 4)],
            ),
            with_extents(
                state(&[("/alpha", 5)], &["/alpha"]),
                &[("/alpha", 0, 4), ("/alpha", 4, 4)],
            ),
        );
        second_extent.extent_start = Some(4);
        second_extent.extent_len = Some(4);
        trace.operations.push(second_extent);
        let mut overlap = op(
            5,
            InvariantAction::AllocateExtent,
            "/alpha",
            None,
            with_extents(
                state(&[("/alpha", 5)], &["/alpha"]),
                &[("/alpha", 0, 4), ("/alpha", 4, 4)],
            ),
            with_extents(
                state(&[("/alpha", 5)], &["/alpha"]),
                &[("/alpha", 0, 4), ("/alpha", 4, 4)],
            ),
        );
        overlap.extent_start = Some(2);
        overlap.extent_len = Some(2);
        overlap.expected_violation = Some("extent_range_does_not_overlap".to_owned());
        overlap.failure_class = Some(InvariantFailureClass::ModelBug);
        trace.operations.push(overlap);

        let report = validate_invariant_trace(&trace);
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.expected_failure_count, 1);
        assert_eq!(
            first_violation(&report)?.violated_invariant,
            "extent_range_does_not_overlap"
        );
        Ok(())
    }

    #[test]
    fn snapshots_and_journal_replay_are_stable_under_repeat_replay() {
        let mut trace = valid_trace();
        let base = state(&[("/alpha", 5)], &["/alpha"]);
        let snap_state = with_snapshots(base, &[("snap-1", &["/alpha"])]);
        let mut snapshot = op(
            3,
            InvariantAction::SnapshotRead,
            "/",
            None,
            snap_state.clone(),
            snap_state.clone(),
        );
        snapshot.snapshot_id = Some("snap-1".to_owned());
        trace.operations.push(snapshot);
        trace.operations.push(op(
            4,
            InvariantAction::JournalReplay,
            "/",
            None,
            with_counts(snap_state.clone(), 1, 0),
            with_counts(snap_state.clone(), 1, 0),
        ));
        trace.operations.push(op(
            5,
            InvariantAction::JournalReplay,
            "/",
            None,
            with_counts(snap_state.clone(), 1, 0),
            with_counts(snap_state, 1, 0),
        ));

        let report = validate_invariant_trace(&trace);
        assert!(report.valid, "{report:?}");
        assert_eq!(report.violations, [] as [InvariantViolationReport; 0]);
    }

    #[test]
    fn repair_writeback_requires_mounted_mutation_authority() -> Result<()> {
        let mut trace = valid_trace();
        let accepted = with_counts(state(&[("/alpha", 5)], &["/alpha"]), 0, 1);
        let mut repair = op(
            3,
            InvariantAction::RepairWriteback,
            "/alpha",
            None,
            accepted.clone(),
            accepted,
        );
        repair.repair_authority = Some("mounted_mutation_authority".to_owned());
        trace.operations.push(repair);
        let mut bypass = op(
            4,
            InvariantAction::RepairWriteback,
            "/alpha",
            None,
            with_counts(state(&[("/alpha", 5)], &["/alpha"]), 0, 1),
            with_counts(state(&[("/alpha", 5)], &["/alpha"]), 0, 1),
        );
        bypass.repair_authority = Some("direct_block_writer".to_owned());
        bypass.expected_violation = Some("repair_writeback_uses_mutation_authority".to_owned());
        bypass.failure_class = Some(InvariantFailureClass::ModelBug);
        trace.operations.push(bypass);

        let report = validate_invariant_trace(&trace);
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.expected_failure_count, 1);
        assert_eq!(
            first_violation(&report)?.violated_invariant,
            "repair_writeback_uses_mutation_authority"
        );
        Ok(())
    }

    #[test]
    fn structured_markdown_includes_violation_and_reproduction() {
        let mut trace = valid_trace();
        let mut bad = op(
            3,
            InvariantAction::ModelInvariantProbe,
            "/alpha",
            None,
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 4)], &["/alpha"]),
        );
        bad.expected_violation = Some("file_size_matches_model".to_owned());
        bad.failure_class = Some(InvariantFailureClass::ProductionBug);
        trace.operations.push(bad);
        let report = validate_invariant_trace(&trace);
        let markdown = render_invariant_oracle_markdown(&report);
        assert!(markdown.contains("Invariant Oracle Report"));
        assert!(markdown.contains("file_size_matches_model"));
        assert!(markdown.contains("validate-invariant-oracle"));
    }

    #[test]
    fn invariant_oracle_report_json_shape() -> Result<()> {
        let mut trace = valid_trace();
        let mut bad = op(
            3,
            InvariantAction::ModelInvariantProbe,
            "/alpha",
            None,
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 4)], &["/alpha"]),
        );
        bad.expected_violation = Some("file_size_matches_model".to_owned());
        bad.failure_class = Some(InvariantFailureClass::ProductionBug);
        trace.operations.push(bad);

        let report = validate_invariant_trace(&trace);
        assert!(report.valid, "{:?}", report.errors);

        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("invariant_oracle_report_json_shape", json);

        let roundtrip: InvariantOracleReport = serde_json::from_str(&json)?;
        assert_eq!(roundtrip, report);
        Ok(())
    }

    #[test]
    fn invariant_oracle_consumer_report_json_shape() -> Result<()> {
        let mut report = validate_invariant_trace(&valid_trace());
        report.model_version = "unknown-model".to_owned();

        let consumer_report = build_invariant_oracle_consumer_report(&report);
        assert!(!consumer_report.valid);
        assert_eq!(consumer_report.errors.len(), 1);

        let json = serde_json::to_string_pretty(&consumer_report)?;
        insta::assert_snapshot!("invariant_oracle_consumer_report_json_shape", json);

        let roundtrip: InvariantOracleConsumerReport = serde_json::from_str(&json)?;
        assert_eq!(roundtrip, consumer_report);
        Ok(())
    }

    /// bd-bogcc — golden-output snapshot for
    /// `render_invariant_oracle_markdown` on a deterministic trace
    /// fixture (valid_trace + one synthetic violation). Pins the
    /// title, header bullet structure (model_version / trace / seed /
    /// deterministic_replay_id / operations summary / reproduction),
    /// the violations section heading, the per-violation line shape
    /// with all 9 fields (op id / index / invariant / class /
    /// expected / minimized/original trace lengths / pre+post state
    /// hashes), and the trailing newlines. Substring-only assertions
    /// in `structured_markdown_includes_violation_and_reproduction`
    /// cannot detect column reorders or section-heading drift; this
    /// snapshot does.
    #[test]
    fn render_invariant_oracle_markdown_with_violation_snapshot() {
        let mut trace = valid_trace();
        let mut bad = op(
            3,
            InvariantAction::ModelInvariantProbe,
            "/alpha",
            None,
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 4)], &["/alpha"]),
        );
        bad.expected_violation = Some("file_size_matches_model".to_owned());
        bad.failure_class = Some(InvariantFailureClass::ProductionBug);
        trace.operations.push(bad);
        let report = validate_invariant_trace(&trace);
        let markdown = render_invariant_oracle_markdown(&report);
        insta::assert_snapshot!("render_invariant_oracle_markdown_with_violation", markdown);
    }
}
