#![forbid(unsafe_code)]

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const INVENTORY_MARKDOWN: &str =
    include_str!("../../../docs/reports/FUZZ_AND_CONFORMANCE_INVENTORY.md");
const INVENTORY_HEADING: &str = "## Open-Ended Inventory Registry";

const REQUIRED_HEADERS: [&str; 12] = [
    "ID",
    "Source location",
    "Risk surface",
    "Current evidence",
    "Required proof type",
    "Expected unit coverage",
    "Expected E2E/fuzz-smoke coverage",
    "Log/artifact expectations",
    "Decision",
    "Linked bead or artifact",
    "Owner/status",
    "Non-applicability rationale",
];

const PROOF_TYPES: [&str; 8] = [
    "parser-unit",
    "mounted-e2e",
    "corpus-seed",
    "golden-fixture",
    "long-campaign",
    "property-test",
    "security-audit",
    "docs-non-goal",
];

const DECISIONS: [&str; 4] = [
    "active-bead",
    "artifact-covered",
    "explicit-non-goal",
    "needs-follow-up",
];

const COVERAGE_STATES: [&str; 4] = ["required", "existing", "not-applicable", "deferred"];
const REQUIRED_LOG_TOKENS: [&str; 4] =
    ["source_path", "row_id", "decision", "reproduction_command"];
const REQUIRED_ARTIFACT_TOKENS: [&str; 2] = ["artifact_path", "owner_status"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenEndedInventoryReport {
    pub row_count: usize,
    pub proof_types: Vec<String>,
    pub decisions: Vec<String>,
    pub rows: Vec<OpenEndedInventoryRow>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenEndedInventoryRow {
    pub id: String,
    pub source_location: String,
    pub risk_surface: String,
    pub current_evidence: String,
    pub required_proof_type: String,
    pub expected_unit_coverage: String,
    pub expected_e2e_fuzz_smoke_coverage: String,
    pub log_artifact_expectations: String,
    pub decision: String,
    pub linked_bead_or_artifact: String,
    pub owner_status: String,
    pub non_applicability_rationale: String,
}

#[must_use]
pub fn analyze_inventory(markdown: &str) -> OpenEndedInventoryReport {
    let mut errors = Vec::new();
    let rows = parse_inventory_rows(markdown, &mut errors);
    let seen_ids = rows.iter().map(|row| row.id.as_str()).collect::<Vec<_>>();
    validate_unique_ids(&seen_ids, &mut errors);
    for row in &rows {
        validate_row(row, &mut errors);
    }

    OpenEndedInventoryReport {
        row_count: rows.len(),
        proof_types: PROOF_TYPES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        decisions: DECISIONS.iter().map(|value| (*value).to_owned()).collect(),
        rows,
        errors,
    }
}

pub fn validate_current_inventory() -> Result<OpenEndedInventoryReport> {
    let report = analyze_inventory(INVENTORY_MARKDOWN);
    if !report.errors.is_empty() {
        bail!(
            "open-ended inventory validation failed: {}",
            report.errors.join("; ")
        );
    }
    Ok(report)
}

fn parse_inventory_rows(markdown: &str, errors: &mut Vec<String>) -> Vec<OpenEndedInventoryRow> {
    let Some(table_lines) = inventory_table_lines(markdown) else {
        errors.push(format!("missing inventory heading `{INVENTORY_HEADING}`"));
        return Vec::new();
    };

    if table_lines.len() < 3 {
        errors.push("inventory table must include header, separator, and rows".to_owned());
        return Vec::new();
    }

    let Some((header_line, body_lines)) = table_lines.split_first() else {
        errors.push("inventory table must include header, separator, and rows".to_owned());
        return Vec::new();
    };

    let header = split_table_row(header_line);
    if header != REQUIRED_HEADERS {
        errors.push(format!(
            "inventory table header mismatch: expected {REQUIRED_HEADERS:?}, got {header:?}"
        ));
        return Vec::new();
    }

    body_lines
        .iter()
        .skip(1)
        .filter_map(|line| {
            let cells = split_table_row(line);
            let [
                id,
                source_location,
                risk_surface,
                current_evidence,
                required_proof_type,
                expected_unit_coverage,
                expected_e2e_fuzz_smoke_coverage,
                log_artifact_expectations,
                decision,
                linked_bead_or_artifact,
                owner_status,
                non_applicability_rationale,
            ] = cells.as_slice()
            else {
                errors.push(format!(
                    "inventory row has {} cells, expected {}: {line}",
                    cells.len(),
                    REQUIRED_HEADERS.len()
                ));
                return None;
            };
            Some(OpenEndedInventoryRow {
                id: id.clone(),
                source_location: source_location.clone(),
                risk_surface: risk_surface.clone(),
                current_evidence: current_evidence.clone(),
                required_proof_type: required_proof_type.clone(),
                expected_unit_coverage: expected_unit_coverage.clone(),
                expected_e2e_fuzz_smoke_coverage: expected_e2e_fuzz_smoke_coverage.clone(),
                log_artifact_expectations: log_artifact_expectations.clone(),
                decision: decision.clone(),
                linked_bead_or_artifact: linked_bead_or_artifact.clone(),
                owner_status: owner_status.clone(),
                non_applicability_rationale: non_applicability_rationale.clone(),
            })
        })
        .collect()
}

fn inventory_table_lines(markdown: &str) -> Option<Vec<&str>> {
    let mut in_section = false;
    let mut lines = Vec::new();

    for line in markdown.lines() {
        if line.trim() == INVENTORY_HEADING {
            in_section = true;
            continue;
        }
        if in_section && line.starts_with("## ") {
            break;
        }
        if in_section && line.trim_start().starts_with('|') {
            lines.push(line);
        }
    }

    (!lines.is_empty()).then_some(lines)
}

fn split_table_row(line: &str) -> Vec<String> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(|cell| normalize_cell(cell.trim()))
        .collect()
}

fn normalize_cell(cell: &str) -> String {
    cell.replace("<br>", "; ")
        .replace("&nbsp;", " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn validate_unique_ids(ids: &[&str], errors: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(*id) {
            errors.push(format!("duplicate inventory row id `{id}`"));
        }
    }
}

fn validate_row(row: &OpenEndedInventoryRow, errors: &mut Vec<String>) {
    validate_row_id(&row.id, errors);
    validate_non_empty_fields(row, errors);
    validate_vocabulary(row, errors);
    validate_log_and_artifact_fields(row, errors);
    validate_linkage(row, errors);
}

fn validate_row_id(id: &str, errors: &mut Vec<String>) {
    let mut chars = id.chars();
    let Some(prefix) = chars.next() else {
        errors.push("inventory row id is empty".to_owned());
        return;
    };
    if !prefix.is_ascii_uppercase() || !chars.all(|ch| ch.is_ascii_digit()) {
        errors.push(format!("inventory row id `{id}` must look like A1"));
    }
}

fn validate_non_empty_fields(row: &OpenEndedInventoryRow, errors: &mut Vec<String>) {
    let fields = [
        ("source_location", &row.source_location),
        ("risk_surface", &row.risk_surface),
        ("current_evidence", &row.current_evidence),
        ("required_proof_type", &row.required_proof_type),
        ("expected_unit_coverage", &row.expected_unit_coverage),
        (
            "expected_e2e_fuzz_smoke_coverage",
            &row.expected_e2e_fuzz_smoke_coverage,
        ),
        ("log_artifact_expectations", &row.log_artifact_expectations),
        ("decision", &row.decision),
        ("linked_bead_or_artifact", &row.linked_bead_or_artifact),
        ("owner_status", &row.owner_status),
        (
            "non_applicability_rationale",
            &row.non_applicability_rationale,
        ),
    ];

    for (field, value) in fields {
        if value.trim().is_empty() || value == "-" {
            errors.push(format!("row {} has empty {field}", row.id));
        }
    }
    if !row.source_location.contains(':') && !row.source_location.contains('/') {
        errors.push(format!(
            "row {} source_location must name a file/anchor",
            row.id
        ));
    }
}

fn validate_vocabulary(row: &OpenEndedInventoryRow, errors: &mut Vec<String>) {
    validate_allowed(
        row,
        "required_proof_type",
        &row.required_proof_type,
        &PROOF_TYPES,
        errors,
    );
    validate_allowed(row, "decision", &row.decision, &DECISIONS, errors);
    validate_allowed(
        row,
        "expected_unit_coverage",
        &row.expected_unit_coverage,
        &COVERAGE_STATES,
        errors,
    );
    validate_allowed(
        row,
        "expected_e2e_fuzz_smoke_coverage",
        &row.expected_e2e_fuzz_smoke_coverage,
        &COVERAGE_STATES,
        errors,
    );
}

fn validate_allowed(
    row: &OpenEndedInventoryRow,
    field: &str,
    value: &str,
    allowed: &[&str],
    errors: &mut Vec<String>,
) {
    if !allowed.contains(&value) {
        errors.push(format!(
            "row {} {field} `{value}` is not in {:?}",
            row.id, allowed
        ));
    }
}

fn validate_log_and_artifact_fields(row: &OpenEndedInventoryRow, errors: &mut Vec<String>) {
    for token in REQUIRED_LOG_TOKENS {
        if !row.log_artifact_expectations.contains(token) {
            errors.push(format!(
                "row {} log_artifact_expectations missing `{token}`",
                row.id
            ));
        }
    }
    for token in REQUIRED_ARTIFACT_TOKENS {
        if !row.log_artifact_expectations.contains(token) {
            errors.push(format!(
                "row {} log_artifact_expectations missing `{token}`",
                row.id
            ));
        }
    }
}

fn validate_linkage(row: &OpenEndedInventoryRow, errors: &mut Vec<String>) {
    let has_bead = row.linked_bead_or_artifact.contains("bd-");
    let has_artifact = row.linked_bead_or_artifact.contains('/');
    if !has_bead && !has_artifact {
        errors.push(format!(
            "row {} linked_bead_or_artifact must include a bead id or artifact path",
            row.id
        ));
    }

    if row.decision == "explicit-non-goal" && row.non_applicability_rationale == "n/a" {
        errors.push(format!(
            "row {} explicit non-goal needs a concrete rationale",
            row.id
        ));
    }
    if row.decision != "explicit-non-goal" && row.non_applicability_rationale != "n/a" {
        errors.push(format!(
            "row {} non_applicability_rationale must be n/a unless decision is explicit-non-goal",
            row.id
        ));
    }
}

pub const SOURCE_SCOPE_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_SOURCE_SCOPE_MANIFEST_PATH: &str =
    "tests/source-scope-manifest/source_scope_manifest.json";
const DEFAULT_SOURCE_SCOPE_MANIFEST_JSON: &str =
    include_str!("../../../tests/source-scope-manifest/source_scope_manifest.json");

const REQUIRED_SOURCE_FAMILIES: [&str; 25] = [
    "readme_status_docs",
    "agent_workflow_docs",
    "feature_parity_doc",
    "canonical_spec_docs",
    "architecture_design_docs",
    "conformance_docs",
    "conformance_fixture_artifacts",
    "conformance_generated_image_artifacts",
    "fixture_manifests",
    "test_control_artifacts",
    "tests",
    "crate_manifest_and_benchmark_sources",
    "checked_in_evidence_artifacts",
    "fuzz_campaign_artifacts",
    "fuzz_corpus_notes",
    "fuzz_targets",
    "fuzz_orchestration",
    "operational_scripts",
    "harness_scripts",
    "operator_runbook_docs",
    "operational_evidence_artifacts",
    "mounted_lane_docs",
    "repair_docs",
    "performance_control_artifacts",
    "performance_xfstests_notes",
];

const CANONICAL_SPEC_DOCS: [&str; 5] = [
    "COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md",
    "PLAN_TO_PORT_FRANKENFS_TO_RUST.md",
    "EXISTING_EXT4_BTRFS_STRUCTURE.md",
    "PROPOSED_ARCHITECTURE.md",
    "FEATURE_PARITY.md",
];

const AGENT_WORKFLOW_DOCS: [&str; 1] = ["AGENTS.md"];

const ARCHITECTURE_DESIGN_DOC_GLOBS: [&str; 3] =
    ["docs/design-*.md", "docs/oq*.md", "docs/perf/README.md"];

const CONFORMANCE_FIXTURE_ARTIFACT_GLOBS: [&str; 8] = [
    "conformance/COVERAGE.md",
    "conformance/DISCREPANCIES.md",
    "conformance/PROVENANCE.md",
    "conformance/fixtures/*.json",
    "conformance/fixtures/checksums.sha256",
    "conformance/golden/*.json",
    "conformance/golden/*.txt",
    "conformance/golden/checksums.sha256",
];

const CONFORMANCE_GENERATED_IMAGE_ARTIFACT_GLOBS: [&str; 1] = ["conformance/golden/*.ext4"];

const OPERATOR_RUNBOOK_DOC_GLOBS: [&str; 5] = [
    "docs/runbooks/*.md",
    "docs/release/*.md",
    "docs/templates/*.md",
    "docs/tracker-hygiene.md",
    "docs/xfstests-known-failures.md",
];

const OPERATIONAL_EVIDENCE_ARTIFACT_GLOBS: [&str; 6] = [
    "security/*.json",
    "docs/*-manifest.json",
    "docs/*-contract.json",
    "docs/operator-recovery-drill.json",
    "docs/repair-confidence-mutation-safety.json",
    "docs/reports/*.md",
];

const FUZZ_CAMPAIGN_ARTIFACT_GLOBS: [&str; 3] = [
    "artifacts/fuzz/*/campaign_summary.json",
    "artifacts/fuzz/*/command_transcript.txt",
    "artifacts/fuzz/*/logs/*.log",
];

const CHECKED_IN_EVIDENCE_ARTIFACT_GLOBS: [&str; 9] = [
    "artifacts/benchmarks/*.json",
    "artifacts/optimization/*.json",
    "artifacts/optimization/*.md",
    "artifacts/optimization/*.tsv",
    "artifacts/optimization/*.txt",
    "artifacts/e2e/*/run.log",
    "artifacts/e2e/*/*.log",
    "artifacts/e2e/*/result.json",
    "artifacts/parity-deferred-followups.md",
];

const CRATE_MANIFEST_AND_BENCHMARK_SOURCE_GLOBS: [&str; 4] = [
    "Cargo.toml",
    "rust-toolchain.toml",
    "crates/*/Cargo.toml",
    "crates/*/benches/*.rs",
];

const TEST_CONTROL_ARTIFACT_GLOBS: [&str; 16] = [
    "tests/artifact-schema-fixtures/**/*.json",
    "tests/btrfs-*-corpus/*.json",
    "tests/casefold-corpus/*.json",
    "tests/chaos-replay-lab/*.json",
    "tests/crash-replay-artifact/*.json",
    "tests/fault-injection-corpus/*.json",
    "tests/fuzz-smoke/*.json",
    "tests/inventory-closeout-gate/*.json",
    "tests/low-privilege-demo*/*.json",
    "tests/metamorphic-workload-seeds/*.json",
    "tests/mounted-*/*.json",
    "tests/open-ended-inventory/*.md",
    "tests/readiness-lab/*.json",
    "tests/release-gates/*.json",
    "tests/remediation-*/*.json",
    "tests/repair-corpus/*.json",
];

const PERFORMANCE_CONTROL_ARTIFACT_GLOBS: [&str; 6] = [
    "benchmarks/*.json",
    "benchmarks/*.toml",
    "benchmarks/baselines/latest.json",
    "benchmarks/baselines/history/*.json",
    "baselines/*.md",
    "profiles/*.meta.json",
];

const HARNESS_SCRIPT_GLOBS: [&str; 3] = [
    "scripts/e2e/**/*.sh",
    "scripts/e2e/**/*.py",
    "scripts/e2e/**/*.json",
];

const ALLOWED_RISK_CATEGORIES: [&str; 9] = [
    "data_safety",
    "parser",
    "mounted_path",
    "repair",
    "fuzz",
    "conformance",
    "performance",
    "observability",
    "docs_only",
];

const ALLOWED_SOURCE_STATUSES: [&str; 4] = ["active", "deferred", "sunset", "non_applicable"];

const ALLOWED_FRESHNESS_STATES: [&str; 3] = ["fresh", "stale", "exempt"];
const NOTE_MATCH_TOKENS: [&str; 14] = [
    "TODO",
    "FIXME",
    "NOTE",
    "HACK",
    "XXX",
    "non-goal",
    "bd-",
    "fake",
    "mock",
    "dummy",
    "placeholder",
    "stub",
    "not yet implemented",
    "thread::sleep",
];
pub const OPEN_ENDED_NOTE_SCANNER_VERSION: &str = "bd-mockscan-open-ended-note-scanner-v2";

const OPEN_ENDED_NOTE_PATTERNS: [&str; 17] = [
    "add more cases",
    "expand corpus",
    "TODO fuzz",
    "HACK",
    "XXX",
    "future edge cases",
    "adversarial inputs",
    "more goldens",
    "known gaps",
    "fake delay",
    "mock implementation",
    "dummy implementation",
    "placeholder implementation",
    "stub implementation",
    "not yet implemented",
    "temporary sleep",
    "thread::sleep",
];

const REQUIRED_NOTE_LOG_FIELDS: [&str; 8] = [
    "scanner_version",
    "search_patterns",
    "source_path",
    "row_id",
    "matched_text_snippet_hash",
    "decision",
    "linked_bead_or_artifact",
    "reproduction_command",
];

const REQUIRED_NOTE_ARTIFACT_FIELDS: [&str; 3] = ["report_json", "run_log", "scanner_fixture_path"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenEndedNoteSource {
    pub source_path: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenEndedNoteScanReport {
    pub schema_version: u32,
    pub scanner_version: String,
    pub source_count: usize,
    pub search_patterns: Vec<String>,
    pub match_count: usize,
    pub real_open_note_count: usize,
    pub false_positive_count: usize,
    pub unresolved_note_count: usize,
    pub rows: Vec<OpenEndedNoteMatch>,
    pub output_path: String,
    pub reproduction_command: String,
    pub valid: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenEndedNoteMatch {
    pub source_path: String,
    pub line_number: usize,
    pub section_id: String,
    pub matched_phrase: String,
    pub matched_text_snippet_hash: String,
    pub decision: String,
    pub false_positive_reason: String,
    pub linked_bead_or_artifact: String,
    pub risk_surface: String,
    pub existing_evidence: String,
    pub proof_type: String,
    pub unit_test_expectation: String,
    pub e2e_fuzz_smoke_expectation: String,
    pub required_log_fields: Vec<String>,
    pub required_artifacts: Vec<String>,
    pub non_applicability_rationale: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceScopeManifest {
    pub schema_version: u32,
    pub manifest_id: String,
    pub bead_id: String,
    pub sources: Vec<SourceScopeEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceScopeEntry {
    pub id: String,
    pub source_family: String,
    pub included_globs: Vec<String>,
    pub excluded_globs: Vec<String>,
    pub risk_category: String,
    pub owner: String,
    pub status: String,
    pub expected_proof_types: Vec<String>,
    pub freshness_ttl_days: u32,
    pub freshness_state: String,
    #[serde(default)]
    pub source_hash: String,
    #[serde(default)]
    pub non_applicability_rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceScopeManifestReport {
    pub schema_version: u32,
    pub manifest_id: String,
    pub bead_id: String,
    pub source_count: usize,
    pub source_families: Vec<String>,
    pub non_applicable_families: Vec<String>,
    pub stale_sources: Vec<String>,
    pub valid: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceScopeScanReport {
    pub schema_version: u32,
    pub manifest_id: String,
    pub bead_id: String,
    pub workspace_root: String,
    pub workspace_file_source: String,
    pub workspace_file_source_reason: String,
    pub untracked_matched_path_count: usize,
    pub source_count: usize,
    pub source_manifest_version: u32,
    pub scanned_sources: Vec<SourceScopeScanEntry>,
    pub stale_sources: Vec<String>,
    pub output_path: String,
    pub reproduction_command: String,
    pub valid: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceScopeScanEntry {
    pub id: String,
    pub source_family: String,
    pub included_globs: Vec<String>,
    pub excluded_globs: Vec<String>,
    pub inclusion_decision: String,
    pub exclusion_reason: String,
    pub file_or_directory_hash: String,
    pub matched_note_count: usize,
    pub linked_bead_or_artifact_count: usize,
    pub stale_allowance: String,
    pub output_path: String,
    pub reproduction_command: String,
    pub matched_paths: Vec<SourceScopePathDecision>,
    pub untracked_matched_path_count: usize,
    pub untracked_matched_paths: Vec<SourceScopeUntrackedPathDecision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceScopePathDecision {
    pub source_path: String,
    pub source_glob: String,
    pub inclusion_decision: String,
    pub exclusion_reason: String,
    pub file_hash: String,
    pub matched_note_count: usize,
    pub linked_bead_or_artifact_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceScopeUntrackedPathDecision {
    pub source_path: String,
    pub source_glob: String,
    pub inclusion_decision: String,
    pub exclusion_reason: String,
}

pub fn parse_source_scope_manifest(text: &str) -> Result<SourceScopeManifest> {
    serde_json::from_str(text)
        .map_err(|err| anyhow::anyhow!("failed to parse source scope manifest JSON: {err}"))
}

pub fn load_source_scope_manifest(path: impl AsRef<Path>) -> Result<SourceScopeManifest> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).map_err(|err| {
        anyhow::anyhow!(
            "failed to read source scope manifest {}: {err}",
            path.display()
        )
    })?;
    parse_source_scope_manifest(&text)
}

pub fn validate_default_source_scope_manifest() -> Result<SourceScopeManifestReport> {
    let manifest = parse_source_scope_manifest(DEFAULT_SOURCE_SCOPE_MANIFEST_JSON)?;
    let report = validate_source_scope_manifest(&manifest);
    if !report.valid {
        bail!(
            "source scope manifest failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(report)
}

#[must_use]
pub fn scan_source_scope_manifest(
    manifest: &SourceScopeManifest,
    workspace_root: &Path,
    output_path: Option<&Path>,
    reproduction_command: &str,
) -> SourceScopeScanReport {
    let manifest_report = validate_source_scope_manifest(manifest);
    let mut errors = manifest_report.errors.clone();
    let workspace_files = match collect_workspace_files(workspace_root, manifest) {
        Ok(collection) => collection,
        Err(err) => {
            errors.push(err.to_string());
            WorkspaceFileCollection {
                files: Vec::new(),
                untracked_files: Vec::new(),
                source: "error".to_owned(),
                reason: err.to_string(),
            }
        }
    };
    let output_path =
        output_path.map_or_else(|| "<stdout>".to_owned(), |path| path.display().to_string());

    let scanned_sources = manifest
        .sources
        .iter()
        .map(|entry| {
            scan_source_scope_entry(
                entry,
                workspace_root,
                &workspace_files.files,
                &workspace_files.untracked_files,
                &output_path,
                reproduction_command,
                &mut errors,
            )
        })
        .collect::<Vec<_>>();
    let untracked_matched_path_count = scanned_sources
        .iter()
        .map(|entry| entry.untracked_matched_path_count)
        .sum();

    SourceScopeScanReport {
        schema_version: SOURCE_SCOPE_MANIFEST_SCHEMA_VERSION,
        manifest_id: manifest.manifest_id.clone(),
        bead_id: manifest.bead_id.clone(),
        workspace_root: workspace_root.display().to_string(),
        workspace_file_source: workspace_files.source,
        workspace_file_source_reason: workspace_files.reason,
        untracked_matched_path_count,
        source_count: manifest.sources.len(),
        source_manifest_version: manifest.schema_version,
        scanned_sources,
        stale_sources: manifest_report.stale_sources,
        output_path,
        reproduction_command: reproduction_command.to_owned(),
        valid: errors.is_empty(),
        errors,
    }
}

#[must_use]
pub fn validate_source_scope_manifest(manifest: &SourceScopeManifest) -> SourceScopeManifestReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut families_seen = BTreeSet::new();
    let mut non_applicable_families = BTreeSet::new();
    let mut stale_sources = Vec::new();

    validate_source_manifest_top_level(manifest, &mut errors);

    for entry in &manifest.sources {
        validate_source_scope_entry(
            entry,
            &mut ids,
            &mut families_seen,
            &mut non_applicable_families,
            &mut stale_sources,
            &mut errors,
        );
    }

    validate_source_family_coverage(&families_seen, &non_applicable_families, &mut errors);

    SourceScopeManifestReport {
        schema_version: manifest.schema_version,
        manifest_id: manifest.manifest_id.clone(),
        bead_id: manifest.bead_id.clone(),
        source_count: manifest.sources.len(),
        source_families: families_seen.into_iter().collect(),
        non_applicable_families: non_applicable_families.into_iter().collect(),
        stale_sources,
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_source_manifest_top_level(manifest: &SourceScopeManifest, errors: &mut Vec<String>) {
    if manifest.schema_version != SOURCE_SCOPE_MANIFEST_SCHEMA_VERSION {
        errors.push(format!(
            "source scope manifest schema_version must be {SOURCE_SCOPE_MANIFEST_SCHEMA_VERSION}, got {}",
            manifest.schema_version
        ));
    }
    if manifest.manifest_id.trim().is_empty() {
        errors.push("source scope manifest missing manifest_id".to_owned());
    }
    if !manifest.bead_id.starts_with("bd-") {
        errors.push(format!(
            "source scope manifest bead_id must look like bd-..., got `{}`",
            manifest.bead_id
        ));
    }
    if manifest.sources.is_empty() {
        errors.push("source scope manifest must declare at least one source".to_owned());
    }
}

fn validate_source_scope_entry(
    entry: &SourceScopeEntry,
    ids: &mut BTreeSet<String>,
    families_seen: &mut BTreeSet<String>,
    non_applicable_families: &mut BTreeSet<String>,
    stale_sources: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    if !ids.insert(entry.id.clone()) {
        errors.push(format!("duplicate source scope entry id `{}`", entry.id));
    }
    if entry.id.trim().is_empty() {
        errors.push("source scope entry has empty id".to_owned());
    }

    if REQUIRED_SOURCE_FAMILIES.contains(&entry.source_family.as_str()) {
        families_seen.insert(entry.source_family.clone());
    } else {
        errors.push(format!(
            "source `{}` has unsupported source_family `{}`",
            entry.id, entry.source_family
        ));
    }

    let has_rationale = !entry.non_applicability_rationale.trim().is_empty();
    if has_rationale {
        non_applicable_families.insert(entry.source_family.clone());
    }

    if entry.included_globs.is_empty() && !has_rationale {
        errors.push(format!(
            "source `{}` must declare included_globs unless non_applicability_rationale is set",
            entry.id
        ));
    }
    for glob in &entry.included_globs {
        if glob.trim().is_empty() {
            errors.push(format!("source `{}` has empty included glob", entry.id));
        }
    }
    for glob in &entry.excluded_globs {
        if glob.trim().is_empty() {
            errors.push(format!("source `{}` has empty excluded glob", entry.id));
        }
    }

    if !ALLOWED_RISK_CATEGORIES.contains(&entry.risk_category.as_str()) {
        errors.push(format!(
            "source `{}` has unsupported risk_category `{}`",
            entry.id, entry.risk_category
        ));
    }

    if entry.owner.trim().is_empty() {
        errors.push(format!("source `{}` missing owner", entry.id));
    }
    if !ALLOWED_SOURCE_STATUSES.contains(&entry.status.as_str()) {
        errors.push(format!(
            "source `{}` has unsupported status `{}`",
            entry.id, entry.status
        ));
    }
    if entry.status == "non_applicable" && !has_rationale {
        errors.push(format!(
            "source `{}` status non_applicable requires non_applicability_rationale",
            entry.id
        ));
    }

    if entry.expected_proof_types.is_empty() && !has_rationale {
        errors.push(format!(
            "source `{}` must declare at least one expected_proof_type",
            entry.id
        ));
    }
    for proof in &entry.expected_proof_types {
        if !PROOF_TYPES.contains(&proof.as_str()) {
            errors.push(format!(
                "source `{}` references unsupported proof type `{}`",
                entry.id, proof
            ));
        }
    }

    if entry.freshness_ttl_days == 0 && entry.freshness_state != "exempt" {
        errors.push(format!(
            "source `{}` freshness_ttl_days must be positive unless freshness_state is exempt",
            entry.id
        ));
    }
    if !ALLOWED_FRESHNESS_STATES.contains(&entry.freshness_state.as_str()) {
        errors.push(format!(
            "source `{}` has unsupported freshness_state `{}`",
            entry.id, entry.freshness_state
        ));
    }
    if entry.freshness_state == "stale" {
        stale_sources.push(entry.id.clone());
    }

    if !entry.source_hash.is_empty() && !is_valid_source_hash(&entry.source_hash) {
        errors.push(format!(
            "source `{}` has malformed source_hash `{}` (expected sha256:<64-hex>)",
            entry.id, entry.source_hash
        ));
    }
    if entry.freshness_state == "stale" && entry.source_hash.is_empty() {
        errors.push(format!(
            "source `{}` freshness_state stale requires source_hash",
            entry.id
        ));
    }

    validate_source_exclusion_policy(entry, errors);
}

fn validate_source_family_coverage(
    families_seen: &BTreeSet<String>,
    non_applicable_families: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    for required in REQUIRED_SOURCE_FAMILIES {
        if !families_seen.contains(required) {
            errors.push(format!(
                "source scope manifest missing required family `{required}`; declare it with non_applicability_rationale if intentionally excluded"
            ));
        }
    }
    for family in non_applicable_families {
        if !REQUIRED_SOURCE_FAMILIES.contains(&family.as_str()) {
            errors.push(format!(
                "non_applicability rationale provided for non-required family `{family}`"
            ));
        }
    }
}

fn is_valid_source_hash(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("sha256:") else {
        return false;
    };
    suffix.len() == 64 && suffix.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn validate_source_exclusion_policy(entry: &SourceScopeEntry, errors: &mut Vec<String>) {
    let excluded = entry.excluded_globs.join("\n");
    let missing_target_paths = !has_build_target_exclusions(&excluded);
    match entry.source_family.as_str() {
        "readme_status_docs"
            if !excluded.contains("_generated") || !excluded.contains("_drafts") =>
        {
            errors.push(format!(
                "source `{}` must exclude generated status docs and drafts",
                entry.id
            ));
        }
        "agent_workflow_docs" => validate_agent_workflow_docs(entry, &excluded, errors),
        "canonical_spec_docs" => validate_canonical_spec_docs_coverage(entry, errors),
        "architecture_design_docs" => validate_architecture_design_docs(entry, &excluded, errors),
        "tests" => validate_tests_exclusions(entry, &excluded, missing_target_paths, errors),
        "conformance_docs" if missing_target_paths => {
            errors.push(format!(
                "source `{}` must exclude build target paths from conformance source scope",
                entry.id
            ));
        }
        "conformance_fixture_artifacts" => {
            validate_conformance_fixture_artifacts(entry, &excluded, errors);
        }
        "conformance_generated_image_artifacts" => {
            validate_conformance_generated_image_artifacts(entry, &excluded, errors);
        }
        "test_control_artifacts" => validate_test_control_artifacts(entry, &excluded, errors),
        "crate_manifest_and_benchmark_sources" => {
            validate_crate_manifest_and_benchmark_sources(entry, &excluded, errors);
        }
        "checked_in_evidence_artifacts" => {
            validate_checked_in_evidence_artifacts(entry, &excluded, errors);
        }
        "fuzz_campaign_artifacts" => validate_fuzz_campaign_artifacts(entry, &excluded, errors),
        "fuzz_targets" => validate_fuzz_targets_exclusions(entry, &excluded, errors),
        "fuzz_orchestration" => validate_fuzz_orchestration_exclusions(entry, &excluded, errors),
        "operational_scripts" => validate_operational_scripts_exclusions(entry, &excluded, errors),
        "harness_scripts" => validate_harness_scripts(entry, &excluded, errors),
        "operator_runbook_docs" => validate_operator_runbook_docs(entry, &excluded, errors),
        "operational_evidence_artifacts" => {
            validate_operational_evidence_artifacts(entry, &excluded, errors);
        }
        "performance_control_artifacts" => {
            validate_performance_control_artifacts(entry, &excluded, errors);
        }
        _ => {}
    }
}

fn has_build_target_exclusions(excluded: &str) -> bool {
    excluded.contains("target")
        && excluded.contains(".rch-target/**")
        && excluded.contains(".rch-target-*")
}

fn validate_crate_manifest_and_benchmark_sources(
    entry: &SourceScopeEntry,
    excluded: &str,
    errors: &mut Vec<String>,
) {
    for required_glob in CRATE_MANIFEST_AND_BENCHMARK_SOURCE_GLOBS {
        if !entry
            .included_globs
            .iter()
            .any(|glob| glob == required_glob)
        {
            errors.push(format!(
                "source `{}` must include crate manifest and benchmark source glob `{required_glob}`",
                entry.id
            ));
        }
    }
    if !has_build_target_exclusions(excluded) {
        errors.push(format!(
            "source `{}` must exclude build target paths from crate manifests and benchmark sources",
            entry.id
        ));
    }
    if !excluded.contains("vendor") {
        errors.push(format!(
            "source `{}` must exclude vendor paths from crate manifests and benchmark sources",
            entry.id
        ));
    }
}

fn validate_checked_in_evidence_artifacts(
    entry: &SourceScopeEntry,
    excluded: &str,
    errors: &mut Vec<String>,
) {
    for required_glob in CHECKED_IN_EVIDENCE_ARTIFACT_GLOBS {
        if !entry
            .included_globs
            .iter()
            .any(|glob| glob == required_glob)
        {
            errors.push(format!(
                "source `{}` must include checked-in evidence artifact glob `{required_glob}`",
                entry.id
            ));
        }
    }
    if !has_build_target_exclusions(excluded) {
        errors.push(format!(
            "source `{}` must exclude build target paths from checked-in evidence artifacts",
            entry.id
        ));
    }
    if !excluded.contains("_generated") || !excluded.contains("_artifacts") {
        errors.push(format!(
            "source `{}` must exclude generated checked-in evidence artifact directories",
            entry.id
        ));
    }
}

fn validate_fuzz_campaign_artifacts(
    entry: &SourceScopeEntry,
    excluded: &str,
    errors: &mut Vec<String>,
) {
    for required_glob in FUZZ_CAMPAIGN_ARTIFACT_GLOBS {
        if !entry
            .included_globs
            .iter()
            .any(|glob| glob == required_glob)
        {
            errors.push(format!(
                "source `{}` must include fuzz campaign artifact glob `{required_glob}`",
                entry.id
            ));
        }
    }
    if !has_build_target_exclusions(excluded) {
        errors.push(format!(
            "source `{}` must exclude build target paths from fuzz campaign artifacts",
            entry.id
        ));
    }
    if !excluded.contains("_generated") || !excluded.contains("artifacts/fuzz/*/artifacts/**") {
        errors.push(format!(
            "source `{}` must exclude generated fuzz campaign artifact directories",
            entry.id
        ));
    }
}

fn validate_agent_workflow_docs(
    entry: &SourceScopeEntry,
    excluded: &str,
    errors: &mut Vec<String>,
) {
    for required_doc in AGENT_WORKFLOW_DOCS {
        if !entry.included_globs.iter().any(|glob| glob == required_doc) {
            errors.push(format!(
                "source `{}` must include agent workflow doc `{required_doc}`",
                entry.id
            ));
        }
    }
    if !has_build_target_exclusions(excluded) {
        errors.push(format!(
            "source `{}` must exclude build target paths from agent workflow docs",
            entry.id
        ));
    }
}

fn validate_architecture_design_docs(
    entry: &SourceScopeEntry,
    excluded: &str,
    errors: &mut Vec<String>,
) {
    for required_glob in ARCHITECTURE_DESIGN_DOC_GLOBS {
        if !entry
            .included_globs
            .iter()
            .any(|glob| glob == required_glob)
        {
            errors.push(format!(
                "source `{}` must include architecture design doc glob `{required_glob}`",
                entry.id
            ));
        }
    }
    if !has_build_target_exclusions(excluded) {
        errors.push(format!(
            "source `{}` must exclude build target paths from architecture design docs",
            entry.id
        ));
    }
    if !excluded.contains("_generated") || !excluded.contains("_artifacts") {
        errors.push(format!(
            "source `{}` must exclude generated architecture design doc directories",
            entry.id
        ));
    }
}

fn validate_operational_evidence_artifacts(
    entry: &SourceScopeEntry,
    excluded: &str,
    errors: &mut Vec<String>,
) {
    for required_glob in OPERATIONAL_EVIDENCE_ARTIFACT_GLOBS {
        if !entry
            .included_globs
            .iter()
            .any(|glob| glob == required_glob)
        {
            errors.push(format!(
                "source `{}` must include operational evidence artifact glob `{required_glob}`",
                entry.id
            ));
        }
    }
    if !has_build_target_exclusions(excluded) {
        errors.push(format!(
            "source `{}` must exclude build target paths from operational evidence artifacts",
            entry.id
        ));
    }
    if !excluded.contains("_generated") || !excluded.contains("_artifacts") {
        errors.push(format!(
            "source `{}` must exclude generated operational evidence artifact directories",
            entry.id
        ));
    }
}

fn validate_test_control_artifacts(
    entry: &SourceScopeEntry,
    excluded: &str,
    errors: &mut Vec<String>,
) {
    for required_glob in TEST_CONTROL_ARTIFACT_GLOBS {
        if !entry
            .included_globs
            .iter()
            .any(|glob| glob == required_glob)
        {
            errors.push(format!(
                "source `{}` must include test control artifact glob `{required_glob}`",
                entry.id
            ));
        }
    }
    if !has_build_target_exclusions(excluded) {
        errors.push(format!(
            "source `{}` must exclude build target paths from test control artifacts",
            entry.id
        ));
    }
    if !excluded.contains("_generated") || !excluded.contains("_artifacts") {
        errors.push(format!(
            "source `{}` must exclude generated test control artifact directories",
            entry.id
        ));
    }
}

fn validate_operator_runbook_docs(
    entry: &SourceScopeEntry,
    excluded: &str,
    errors: &mut Vec<String>,
) {
    for required_glob in OPERATOR_RUNBOOK_DOC_GLOBS {
        if !entry
            .included_globs
            .iter()
            .any(|glob| glob == required_glob)
        {
            errors.push(format!(
                "source `{}` must include operator runbook doc glob `{required_glob}`",
                entry.id
            ));
        }
    }
    if !has_build_target_exclusions(excluded) {
        errors.push(format!(
            "source `{}` must exclude build target paths from operator runbook docs",
            entry.id
        ));
    }
}

fn validate_conformance_fixture_artifacts(
    entry: &SourceScopeEntry,
    excluded: &str,
    errors: &mut Vec<String>,
) {
    for required_glob in CONFORMANCE_FIXTURE_ARTIFACT_GLOBS {
        if !entry
            .included_globs
            .iter()
            .any(|glob| glob == required_glob)
        {
            errors.push(format!(
                "source `{}` must include conformance fixture artifact glob `{required_glob}`",
                entry.id
            ));
        }
    }
    if entry
        .included_globs
        .iter()
        .any(|glob| glob == "conformance/golden/*.ext4")
    {
        errors.push(format!(
            "source `{}` must not include generated ext4 image glob `conformance/golden/*.ext4` as a tracked checksum artifact; use `conformance_generated_image_artifacts`",
            entry.id
        ));
    }
    if !has_build_target_exclusions(excluded) {
        errors.push(format!(
            "source `{}` must exclude build target paths from conformance fixture artifacts",
            entry.id
        ));
    }
}

fn validate_conformance_generated_image_artifacts(
    entry: &SourceScopeEntry,
    excluded: &str,
    errors: &mut Vec<String>,
) {
    for required_glob in CONFORMANCE_GENERATED_IMAGE_ARTIFACT_GLOBS {
        if !entry
            .included_globs
            .iter()
            .any(|glob| glob == required_glob)
        {
            errors.push(format!(
                "source `{}` must include generated conformance image artifact glob `{required_glob}`",
                entry.id
            ));
        }
    }
    if !has_build_target_exclusions(excluded) {
        errors.push(format!(
            "source `{}` must exclude build target paths from generated conformance image artifacts",
            entry.id
        ));
    }
    if entry.status != "non_applicable" {
        errors.push(format!(
            "source `{}` must mark generated ext4 images as non_applicable to committed checksum coverage",
            entry.id
        ));
    }
    if entry.freshness_state != "exempt" || entry.freshness_ttl_days != 0 {
        errors.push(format!(
            "source `{}` generated ext4 images must use freshness_state=exempt and ttl_days=0",
            entry.id
        ));
    }
    if !entry.expected_proof_types.is_empty() {
        errors.push(format!(
            "source `{}` generated ext4 images must not declare checksum proof types",
            entry.id
        ));
    }
    let rationale = entry.non_applicability_rationale.to_ascii_lowercase();
    for required_term in ["regenerated", "gitignored", "checksum"] {
        if !rationale.contains(required_term) {
            errors.push(format!(
                "source `{}` generated ext4 image rationale must mention `{required_term}`",
                entry.id
            ));
        }
    }
}

fn validate_canonical_spec_docs_coverage(entry: &SourceScopeEntry, errors: &mut Vec<String>) {
    for required_doc in CANONICAL_SPEC_DOCS {
        if !entry.included_globs.iter().any(|glob| glob == required_doc) {
            errors.push(format!(
                "source `{}` must include required canonical spec doc `{required_doc}`",
                entry.id
            ));
        }
    }
}

fn validate_performance_control_artifacts(
    entry: &SourceScopeEntry,
    excluded: &str,
    errors: &mut Vec<String>,
) {
    for required_glob in PERFORMANCE_CONTROL_ARTIFACT_GLOBS {
        if !entry
            .included_globs
            .iter()
            .any(|glob| glob == required_glob)
        {
            errors.push(format!(
                "source `{}` must include performance control artifact glob `{required_glob}`",
                entry.id
            ));
        }
    }
    if !has_build_target_exclusions(excluded) {
        errors.push(format!(
            "source `{}` must exclude build target paths from performance control artifacts",
            entry.id
        ));
    }
    if !excluded.contains("baselines/hyperfine") {
        errors.push(format!(
            "source `{}` must exclude generated hyperfine baseline outputs",
            entry.id
        ));
    }
    if !excluded.contains("profiles/smoke-") {
        errors.push(format!(
            "source `{}` must exclude generated profile smoke outputs",
            entry.id
        ));
    }
}

fn validate_operational_scripts_exclusions(
    entry: &SourceScopeEntry,
    excluded: &str,
    errors: &mut Vec<String>,
) {
    if !has_build_target_exclusions(excluded) {
        errors.push(format!(
            "source `{}` must exclude build target paths from operational script source scope",
            entry.id
        ));
    }
    if !excluded.contains("scripts/e2e") {
        errors.push(format!(
            "source `{}` must keep E2E scripts in the dedicated harness script source scope",
            entry.id
        ));
    }
    if !excluded.contains("scripts/archive") {
        errors.push(format!(
            "source `{}` must exclude archived scratch scripts from operational script source scope",
            entry.id
        ));
    }
}

fn validate_harness_scripts(entry: &SourceScopeEntry, excluded: &str, errors: &mut Vec<String>) {
    for required_glob in HARNESS_SCRIPT_GLOBS {
        if !entry
            .included_globs
            .iter()
            .any(|glob| glob == required_glob)
        {
            errors.push(format!(
                "source `{}` must include harness script glob `{required_glob}`",
                entry.id
            ));
        }
    }
    if !excluded.contains("scripts/e2e/_artifacts") {
        errors.push(format!(
            "source `{}` must exclude generated e2e artifact directories",
            entry.id
        ));
    }
}

fn validate_fuzz_orchestration_exclusions(
    entry: &SourceScopeEntry,
    excluded: &str,
    errors: &mut Vec<String>,
) {
    if !has_build_target_exclusions(excluded) {
        errors.push(format!(
            "source `{}` must exclude build target paths from fuzz orchestration source scope",
            entry.id
        ));
    }
    if !excluded.contains("vendor") {
        errors.push(format!(
            "source `{}` must exclude vendor paths from fuzz orchestration source scope",
            entry.id
        ));
    }
}

fn validate_fuzz_targets_exclusions(
    entry: &SourceScopeEntry,
    excluded: &str,
    errors: &mut Vec<String>,
) {
    if !has_build_target_exclusions(excluded) {
        errors.push(format!(
            "source `{}` must exclude build target paths from fuzz target source scope",
            entry.id
        ));
    }
    if !excluded.contains("vendor") {
        errors.push(format!(
            "source `{}` must exclude vendor paths from fuzz target source scope",
            entry.id
        ));
    }
}

fn validate_tests_exclusions(
    entry: &SourceScopeEntry,
    excluded: &str,
    missing_target_paths: bool,
    errors: &mut Vec<String>,
) {
    if !excluded.contains("vendor") {
        errors.push(format!(
            "source `{}` must exclude vendor paths from test source scope",
            entry.id
        ));
    }
    if missing_target_paths {
        errors.push(format!(
            "source `{}` must exclude build target paths from test source scope",
            entry.id
        ));
    }
}

fn scan_source_scope_entry(
    entry: &SourceScopeEntry,
    workspace_root: &Path,
    workspace_files: &[PathBuf],
    untracked_files: &[PathBuf],
    output_path: &str,
    reproduction_command: &str,
    errors: &mut Vec<String>,
) -> SourceScopeScanEntry {
    let stale_allowance = format_stale_allowance(entry);
    if !entry.non_applicability_rationale.trim().is_empty() {
        return non_applicable_scan_entry(
            entry,
            output_path,
            reproduction_command,
            stale_allowance,
        );
    }

    let matched_paths = collect_matched_paths(entry, workspace_root, workspace_files, errors);
    let untracked_matched_paths = collect_untracked_matched_paths(entry, untracked_files);
    let untracked_matched_path_count = untracked_matched_paths.len();
    let included_paths: Vec<&SourceScopePathDecision> = matched_paths
        .iter()
        .filter(|path| path.inclusion_decision == "included")
        .collect();
    if included_paths.is_empty() {
        errors.push(format!(
            "source `{}` matched no files for included_globs {:?}",
            entry.id, entry.included_globs
        ));
    }

    let matched_note_count = included_paths
        .iter()
        .map(|path| path.matched_note_count)
        .sum();
    let linked_bead_or_artifact_count = included_paths
        .iter()
        .map(|path| path.linked_bead_or_artifact_count)
        .sum();
    let file_or_directory_hash = directory_hash(&included_paths);
    let inclusion_decision = if included_paths.is_empty() {
        "missing"
    } else {
        "included"
    };

    SourceScopeScanEntry {
        id: entry.id.clone(),
        source_family: entry.source_family.clone(),
        included_globs: entry.included_globs.clone(),
        excluded_globs: entry.excluded_globs.clone(),
        inclusion_decision: inclusion_decision.to_owned(),
        exclusion_reason: String::new(),
        file_or_directory_hash,
        matched_note_count,
        linked_bead_or_artifact_count,
        stale_allowance,
        output_path: output_path.to_owned(),
        reproduction_command: reproduction_command.to_owned(),
        matched_paths,
        untracked_matched_path_count,
        untracked_matched_paths,
    }
}

fn format_stale_allowance(entry: &SourceScopeEntry) -> String {
    format!(
        "freshness_state={} ttl_days={} source_hash={}",
        entry.freshness_state,
        entry.freshness_ttl_days,
        if entry.source_hash.is_empty() {
            "<none>"
        } else {
            entry.source_hash.as_str()
        }
    )
}

fn non_applicable_scan_entry(
    entry: &SourceScopeEntry,
    output_path: &str,
    reproduction_command: &str,
    stale_allowance: String,
) -> SourceScopeScanEntry {
    SourceScopeScanEntry {
        id: entry.id.clone(),
        source_family: entry.source_family.clone(),
        included_globs: entry.included_globs.clone(),
        excluded_globs: entry.excluded_globs.clone(),
        inclusion_decision: "non_applicable".to_owned(),
        exclusion_reason: entry.non_applicability_rationale.clone(),
        file_or_directory_hash: String::new(),
        matched_note_count: 0,
        linked_bead_or_artifact_count: 0,
        stale_allowance,
        output_path: output_path.to_owned(),
        reproduction_command: reproduction_command.to_owned(),
        matched_paths: Vec::new(),
        untracked_matched_path_count: 0,
        untracked_matched_paths: Vec::new(),
    }
}

fn collect_matched_paths(
    entry: &SourceScopeEntry,
    workspace_root: &Path,
    workspace_files: &[PathBuf],
    errors: &mut Vec<String>,
) -> Vec<SourceScopePathDecision> {
    let mut matched_paths = Vec::new();
    for relative_path in workspace_files {
        let relative = normalize_path(relative_path);
        let Some(included_glob) = entry
            .included_globs
            .iter()
            .find(|glob| glob_matches(glob, &relative))
        else {
            continue;
        };
        let excluded_glob = entry
            .excluded_globs
            .iter()
            .find(|glob| glob_matches(glob, &relative));
        let full_path = workspace_root.join(relative_path);
        let file_hash = hash_file(&full_path).unwrap_or_else(|err| {
            errors.push(format!("failed to hash source path `{relative}`: {err}"));
            String::new()
        });
        let text = fs::read_to_string(&full_path).unwrap_or_default();
        let matched_note_count = count_note_matches(&text);
        let linked_bead_or_artifact_count = count_linked_beads_or_artifacts(&text);

        let (inclusion_decision, exclusion_reason) = excluded_glob.map_or_else(
            || ("included".to_owned(), String::new()),
            |glob| {
                (
                    "excluded".to_owned(),
                    format!("matched excluded_glob `{glob}`"),
                )
            },
        );
        matched_paths.push(SourceScopePathDecision {
            source_path: relative,
            source_glob: included_glob.clone(),
            inclusion_decision,
            exclusion_reason,
            file_hash,
            matched_note_count,
            linked_bead_or_artifact_count,
        });
    }
    matched_paths
}

fn collect_untracked_matched_paths(
    entry: &SourceScopeEntry,
    untracked_files: &[PathBuf],
) -> Vec<SourceScopeUntrackedPathDecision> {
    let mut matched_paths = Vec::new();
    for relative_path in untracked_files {
        let relative = normalize_path(relative_path);
        if source_scope_path_is_pruned(&relative) {
            continue;
        }
        let Some(included_glob) = entry
            .included_globs
            .iter()
            .find(|glob| glob_matches(glob, &relative))
        else {
            continue;
        };
        if entry
            .excluded_globs
            .iter()
            .any(|glob| glob_matches(glob, &relative))
        {
            continue;
        }
        matched_paths.push(SourceScopeUntrackedPathDecision {
            source_path: relative,
            source_glob: included_glob.clone(),
            inclusion_decision: "untracked_excluded".to_owned(),
            exclusion_reason: "untracked path excluded from canonical source hash".to_owned(),
        });
    }
    matched_paths
}

struct WorkspaceFileCollection {
    files: Vec<PathBuf>,
    untracked_files: Vec<PathBuf>,
    source: String,
    reason: String,
}

fn collect_workspace_files(
    workspace_root: &Path,
    manifest: &SourceScopeManifest,
) -> Result<WorkspaceFileCollection> {
    match collect_git_tracked_workspace_files(workspace_root) {
        Ok(files) => {
            let untracked_files = collect_git_untracked_workspace_files(workspace_root)?;
            let missing_sources = unmatched_source_scope_entries(manifest, &files);
            if missing_sources.is_empty() {
                Ok(WorkspaceFileCollection {
                    files,
                    untracked_files,
                    source: "git_ls_files".to_owned(),
                    reason: "canonical scan uses git-tracked paths".to_owned(),
                })
            } else {
                let filesystem_files = collect_filesystem_workspace_files(workspace_root)?;
                let filesystem_missing =
                    unmatched_source_scope_entries(manifest, &filesystem_files);
                if filesystem_missing.len() < missing_sources.len() {
                    Ok(WorkspaceFileCollection {
                        files: filesystem_files,
                        untracked_files: Vec::new(),
                        source: "filesystem_fallback".to_owned(),
                        reason: format!(
                            "git-tracked scan incomplete for {}; filesystem fallback missing {}",
                            missing_sources.join(","),
                            format_missing_sources(&filesystem_missing)
                        ),
                    })
                } else {
                    Ok(WorkspaceFileCollection {
                        files,
                        untracked_files,
                        source: "git_ls_files".to_owned(),
                        reason: format!(
                            "canonical scan uses git-tracked paths; missing {}",
                            missing_sources.join(",")
                        ),
                    })
                }
            }
        }
        Err(git_err) => {
            let files = collect_filesystem_workspace_files(workspace_root)?;
            Ok(WorkspaceFileCollection {
                files,
                untracked_files: Vec::new(),
                source: "filesystem_fallback".to_owned(),
                reason: format!("git-tracked scan unavailable: {git_err}"),
            })
        }
    }
}

fn collect_filesystem_workspace_files(workspace_root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_workspace_files_from(workspace_root, workspace_root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_git_tracked_workspace_files(workspace_root: &Path) -> Result<Vec<PathBuf>> {
    collect_git_workspace_files(workspace_root, &["ls-files", "-z"])
}

fn collect_git_untracked_workspace_files(workspace_root: &Path) -> Result<Vec<PathBuf>> {
    collect_git_workspace_files(
        workspace_root,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )
}

fn collect_git_workspace_files(workspace_root: &Path, args: &[&str]) -> Result<Vec<PathBuf>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace_root)
        .args(args)
        .output()
        .map_err(|err| anyhow::anyhow!("failed to run git {}: {err}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git {} exited with status {}: {}",
            args.join(" "),
            output.status,
            stderr.trim()
        );
    }

    let mut files = Vec::new();
    for raw_path in output.stdout.split(|byte| *byte == 0) {
        if raw_path.is_empty() {
            continue;
        }
        let relative = PathBuf::from(String::from_utf8_lossy(raw_path).into_owned());
        if workspace_root.join(&relative).is_file() {
            files.push(relative);
        }
    }
    files.sort();
    Ok(files)
}

fn unmatched_source_scope_entries(
    manifest: &SourceScopeManifest,
    workspace_files: &[PathBuf],
) -> Vec<String> {
    manifest
        .sources
        .iter()
        .filter(|entry| entry.non_applicability_rationale.trim().is_empty())
        .filter(|entry| !source_scope_entry_has_included_match(entry, workspace_files))
        .map(|entry| entry.id.clone())
        .collect()
}

fn source_scope_entry_has_included_match(
    entry: &SourceScopeEntry,
    workspace_files: &[PathBuf],
) -> bool {
    workspace_files.iter().any(|relative_path| {
        let relative = normalize_path(relative_path);
        entry
            .included_globs
            .iter()
            .any(|glob| glob_matches(glob, &relative))
            && !entry
                .excluded_globs
                .iter()
                .any(|glob| glob_matches(glob, &relative))
    })
}

fn format_missing_sources(missing_sources: &[String]) -> String {
    if missing_sources.is_empty() {
        "<none>".to_owned()
    } else {
        missing_sources.join(",")
    }
}

fn collect_workspace_files_from(
    root: &Path,
    current: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(current).map_err(|err| {
        anyhow::anyhow!("failed to read workspace path {}: {err}", current.display())
    })? {
        let entry = entry.map_err(|err| {
            anyhow::anyhow!(
                "failed to read workspace entry under {}: {err}",
                current.display()
            )
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|err| {
            anyhow::anyhow!(
                "failed to inspect workspace entry {}: {err}",
                path.display()
            )
        })?;
        if file_type.is_dir() {
            if should_skip_walk_dir(root, &path) {
                continue;
            }
            collect_workspace_files_from(root, &path, files)?;
        } else if file_type.is_file() {
            let relative = path.strip_prefix(root).map_err(|err| {
                anyhow::anyhow!(
                    "failed to relativize workspace entry {}: {err}",
                    path.display()
                )
            })?;
            files.push(relative.to_path_buf());
        }
    }
    Ok(())
}

fn should_skip_walk_dir(root: &Path, path: &Path) -> bool {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let relative = normalize_path(relative);
    source_scope_path_is_pruned(&relative)
}

fn source_scope_path_is_pruned(relative: &str) -> bool {
    let first_segment = relative.split('/').next().unwrap_or(relative);
    matches!(first_segment, ".git" | "target" | ".rch-target" | "vendor")
        || first_segment.starts_with(".rch-target-")
        || relative == "data/tmp"
        || relative.starts_with("data/tmp/")
}

fn normalize_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn glob_matches(pattern: &str, path: &str) -> bool {
    let pattern_segments = pattern.split('/').collect::<Vec<_>>();
    let path_segments = path.split('/').collect::<Vec<_>>();
    glob_segments_match(&pattern_segments, &path_segments)
}

fn glob_segments_match(pattern: &[&str], path: &[&str]) -> bool {
    let Some((pattern_head, pattern_tail)) = pattern.split_first() else {
        return path.is_empty();
    };
    if *pattern_head == "**" {
        return glob_segments_match(pattern_tail, path)
            || path
                .split_first()
                .is_some_and(|(_, path_tail)| glob_segments_match(pattern, path_tail));
    }
    let Some((path_head, path_tail)) = path.split_first() else {
        return false;
    };
    glob_segment_match(pattern_head, path_head) && glob_segments_match(pattern_tail, path_tail)
}

fn glob_segment_match(pattern: &str, segment: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let parts = pattern.split('*').collect::<Vec<_>>();
    if parts.len() == 1 {
        return pattern == segment;
    }

    let mut remainder = segment;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if index == 0 {
            let Some(stripped) = remainder.strip_prefix(part) else {
                return false;
            };
            remainder = stripped;
        } else if let Some(position) = remainder.find(part) {
            let Some(stripped) = remainder.get(position + part.len()..) else {
                return false;
            };
            remainder = stripped;
        } else {
            return false;
        }
    }
    pattern.ends_with('*') || remainder.is_empty()
}

fn hash_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path)
        .map_err(|err| anyhow::anyhow!("failed to read {} for hashing: {err}", path.display()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn directory_hash(paths: &[&SourceScopePathDecision]) -> String {
    if paths.is_empty() {
        return String::new();
    }
    let mut hasher = Sha256::new();
    for path in paths {
        hasher.update(path.source_path.as_bytes());
        hasher.update(b"\0");
        hasher.update(path.file_hash.as_bytes());
        hasher.update(b"\0");
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn count_note_matches(text: &str) -> usize {
    NOTE_MATCH_TOKENS
        .iter()
        .map(|token| count_note_token_matches(text, token))
        .sum()
}

fn count_note_token_matches(text: &str, token: &str) -> usize {
    match token {
        "bd-" | "thread::sleep" => text.matches(token).count(),
        _ => count_ascii_bounded_matches(text, token),
    }
}

fn count_ascii_bounded_matches(text: &str, token: &str) -> usize {
    text.match_indices(token)
        .filter(|(start, _)| {
            let end = start.saturating_add(token.len());
            has_ascii_note_boundary(text, *start, end)
        })
        .count()
}

fn has_ascii_note_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(is_ascii_note_token_char) && !after.is_some_and(is_ascii_note_token_char)
}

fn is_ascii_note_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn count_linked_beads_or_artifacts(text: &str) -> usize {
    text.matches("bd-").count() + text.matches("artifact").count()
}

#[must_use]
pub fn scan_open_ended_notes(
    sources: &[OpenEndedNoteSource],
    output_path: &str,
    reproduction_command: &str,
) -> OpenEndedNoteScanReport {
    let mut errors = Vec::new();
    if output_path.trim().is_empty() {
        errors.push("open-ended note scan output_path must be nonempty".to_owned());
    }
    if !reproduction_command.contains("open_ended_note_scanner")
        && !reproduction_command.contains("open-ended-note-scanner")
    {
        errors.push(
            "open-ended note scan reproduction_command must name open_ended_note_scanner or open-ended-note-scanner"
                .to_owned(),
        );
    }

    let rows = sources
        .iter()
        .flat_map(|source| scan_open_ended_note_source(source, reproduction_command, &mut errors))
        .collect::<Vec<_>>();

    let real_open_note_count = rows
        .iter()
        .filter(|row| row.decision == "requires_inventory_row")
        .count();
    let false_positive_count = rows
        .iter()
        .filter(|row| row.decision == "false_positive")
        .count();
    let unresolved_note_count = rows
        .iter()
        .filter(|row| {
            row.decision == "requires_inventory_row" && row.linked_bead_or_artifact == "missing"
        })
        .count();

    for row in &rows {
        validate_open_ended_note_match(row, &mut errors);
        if row.decision == "requires_inventory_row" && row.linked_bead_or_artifact == "missing" {
            errors.push(format!(
                "{}:{} matched `{}` but lacks linked bead/artifact or inventory row",
                row.source_path, row.line_number, row.matched_phrase
            ));
        }
    }

    OpenEndedNoteScanReport {
        schema_version: SOURCE_SCOPE_MANIFEST_SCHEMA_VERSION,
        scanner_version: OPEN_ENDED_NOTE_SCANNER_VERSION.to_owned(),
        source_count: sources.len(),
        search_patterns: OPEN_ENDED_NOTE_PATTERNS
            .iter()
            .map(|pattern| (*pattern).to_owned())
            .collect(),
        match_count: rows.len(),
        real_open_note_count,
        false_positive_count,
        unresolved_note_count,
        rows,
        output_path: output_path.to_owned(),
        reproduction_command: reproduction_command.to_owned(),
        valid: errors.is_empty(),
        errors,
    }
}

fn scan_open_ended_note_source(
    source: &OpenEndedNoteSource,
    reproduction_command: &str,
    errors: &mut Vec<String>,
) -> Vec<OpenEndedNoteMatch> {
    if source.source_path.trim().is_empty() {
        errors.push("open-ended note scan source_path must be nonempty".to_owned());
    }
    let mut rows = Vec::new();
    let mut section_id = "root".to_owned();
    let mut in_fenced_code = false;

    for (index, line) in source.text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") {
            in_fenced_code = !in_fenced_code;
        }
        if !in_fenced_code && trimmed.starts_with('#') {
            section_id = slugify_heading(trimmed);
        }
        for pattern in matched_open_ended_patterns(line) {
            rows.push(build_note_match(
                source,
                index + 1,
                &section_id,
                line,
                pattern,
                in_fenced_code,
                reproduction_command,
            ));
        }
    }

    rows
}

fn matched_open_ended_patterns(line: &str) -> Vec<&'static str> {
    let lower = line.to_ascii_lowercase();
    OPEN_ENDED_NOTE_PATTERNS
        .iter()
        .copied()
        .filter(|pattern| lower.contains(&pattern.to_ascii_lowercase()))
        .collect()
}

fn build_note_match(
    source: &OpenEndedNoteSource,
    line_number: usize,
    section_id: &str,
    line: &str,
    matched_phrase: &str,
    in_fenced_code: bool,
    reproduction_command: &str,
) -> OpenEndedNoteMatch {
    let (decision, false_positive_reason, linked_bead_or_artifact) =
        classify_open_ended_note(line, in_fenced_code);
    let risk_surface = infer_note_risk_surface(line, matched_phrase);

    OpenEndedNoteMatch {
        source_path: source.source_path.clone(),
        line_number,
        section_id: section_id.to_owned(),
        matched_phrase: matched_phrase.to_owned(),
        matched_text_snippet_hash: snippet_hash(line),
        decision: decision.to_owned(),
        false_positive_reason: false_positive_reason.to_owned(),
        existing_evidence: note_existing_evidence(
            decision,
            false_positive_reason,
            &linked_bead_or_artifact,
        ),
        proof_type: note_proof_type(decision, risk_surface).to_owned(),
        unit_test_expectation: "open_ended_note_scanner_fixture_docs_emit_expected_rows".to_owned(),
        e2e_fuzz_smoke_expectation: "scripts/e2e/ffs_open_ended_inventory_scanner_e2e.sh"
            .to_owned(),
        linked_bead_or_artifact,
        risk_surface: risk_surface.to_owned(),
        required_log_fields: REQUIRED_NOTE_LOG_FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .collect(),
        required_artifacts: REQUIRED_NOTE_ARTIFACT_FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .collect(),
        non_applicability_rationale: note_non_applicability_rationale(
            decision,
            false_positive_reason,
        ),
        reproduction_command: reproduction_command.to_owned(),
    }
}

fn classify_open_ended_note(
    line: &str,
    in_fenced_code: bool,
) -> (&'static str, &'static str, String) {
    let trimmed = line.trim_start();
    if in_fenced_code || trimmed.starts_with('>') {
        return (
            "false_positive",
            "quoted_or_example",
            "not_applicable".to_owned(),
        );
    }
    let lower = line.to_ascii_lowercase();
    if lower.contains("historical")
        || lower.contains("closed bead")
        || lower.contains("status: closed")
        || lower.contains("already closed")
    {
        return (
            "false_positive",
            "historical_closed_context",
            first_linked_bead_or_artifact(line).unwrap_or_else(|| "historical-context".to_owned()),
        );
    }
    if lower.contains("phrases scanned")
        || lower.contains("search performed")
        || lower.contains("scanner patterns")
    {
        return (
            "false_positive",
            "scanner_methodology",
            "scanner-methodology".to_owned(),
        );
    }
    if let Some(link) = first_linked_bead_or_artifact(line) {
        return ("already_linked", "n/a", link);
    }
    ("requires_inventory_row", "n/a", "missing".to_owned())
}

fn first_linked_bead_or_artifact(line: &str) -> Option<String> {
    line.split_whitespace().find_map(|raw| {
        let token = raw.trim_matches(|ch: char| {
            matches!(
                ch,
                '`' | '\'' | '"' | ',' | ';' | ':' | ')' | '(' | '[' | ']' | '.'
            )
        });
        if token.starts_with("bd-") {
            return Some(token.to_owned());
        }
        if token.contains('/')
            && Path::new(token)
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("md") || extension.eq_ignore_ascii_case("json")
                })
        {
            return Some(token.to_owned());
        }
        if token.contains("artifact") {
            return Some(token.to_owned());
        }
        None
    })
}

fn infer_note_risk_surface(line: &str, matched_phrase: &str) -> &'static str {
    let lower = format!(
        "{} {}",
        line.to_ascii_lowercase(),
        matched_phrase.to_ascii_lowercase()
    );
    if lower.contains("fuzz") || lower.contains("adversarial") {
        "fuzz"
    } else if lower.contains("sleep") || lower.contains("delay") || lower.contains("backoff") {
        "runtime-liveness"
    } else if lower.contains("fake")
        || lower.contains("mock")
        || lower.contains("dummy")
        || lower.contains("hack")
        || lower.contains("xxx")
        || lower.contains("stub")
        || lower.contains("placeholder")
        || lower.contains("not yet implemented")
        || lower.contains("not implemented")
    {
        "implementation-placeholder"
    } else if lower.contains("golden") {
        "golden-fixture"
    } else if lower.contains("corpus") {
        "corpus"
    } else if lower.contains("parser") {
        "parser"
    } else {
        "conformance"
    }
}

fn note_existing_evidence(
    decision: &str,
    false_positive_reason: &str,
    linked_bead_or_artifact: &str,
) -> String {
    match decision {
        "already_linked" => format!("linked bead or artifact: {linked_bead_or_artifact}"),
        "false_positive" => format!("false-positive classification: {false_positive_reason}"),
        _ => "missing".to_owned(),
    }
}

fn note_proof_type(decision: &str, risk_surface: &str) -> &'static str {
    if decision == "false_positive" {
        return "docs-non-goal";
    }
    match risk_surface {
        "fuzz" => "property-test",
        "runtime-liveness" | "implementation-placeholder" => "long-campaign",
        "golden-fixture" => "golden-fixture",
        "corpus" => "corpus-seed",
        "parser" => "parser-unit",
        _ => "mounted-e2e",
    }
}

fn note_non_applicability_rationale(decision: &str, false_positive_reason: &str) -> String {
    if decision == "false_positive" {
        false_positive_reason.to_owned()
    } else {
        "n/a".to_owned()
    }
}

fn slugify_heading(line: &str) -> String {
    let slug = line
        .trim_start_matches('#')
        .trim()
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
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if slug.is_empty() {
        "root".to_owned()
    } else {
        slug
    }
}

fn snippet_hash(line: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(line.as_bytes())))
}

fn validate_open_ended_note_match(row: &OpenEndedNoteMatch, errors: &mut Vec<String>) {
    if row.source_path.trim().is_empty() {
        errors.push("open-ended note row missing source_path".to_owned());
    }
    if row.line_number == 0 {
        errors.push(format!(
            "open-ended note row {} missing line_number",
            row.source_path
        ));
    }
    if row.section_id.trim().is_empty() {
        errors.push(format!(
            "open-ended note row {}:{} missing section_id",
            row.source_path, row.line_number
        ));
    }
    if !row.matched_text_snippet_hash.starts_with("sha256:") {
        errors.push(format!(
            "open-ended note row {}:{} missing snippet hash",
            row.source_path, row.line_number
        ));
    }
    if !matches!(
        row.decision.as_str(),
        "requires_inventory_row" | "already_linked" | "false_positive"
    ) {
        errors.push(format!(
            "open-ended note row {}:{} has invalid decision {}",
            row.source_path, row.line_number, row.decision
        ));
    }
    if row.decision == "false_positive" && row.false_positive_reason == "n/a" {
        errors.push(format!(
            "open-ended note row {}:{} false_positive needs reason",
            row.source_path, row.line_number
        ));
    }
    if row.decision != "requires_inventory_row" && row.linked_bead_or_artifact == "missing" {
        errors.push(format!(
            "open-ended note row {}:{} non-open note missing linkage marker",
            row.source_path, row.line_number
        ));
    }
    if row.existing_evidence.trim().is_empty() {
        errors.push(format!(
            "open-ended note row {}:{} missing existing_evidence",
            row.source_path, row.line_number
        ));
    }
    if row.decision != "requires_inventory_row" && row.existing_evidence == "missing" {
        errors.push(format!(
            "open-ended note row {}:{} non-open note missing existing_evidence",
            row.source_path, row.line_number
        ));
    }
    if !PROOF_TYPES.contains(&row.proof_type.as_str()) {
        errors.push(format!(
            "open-ended note row {}:{} invalid proof_type {}",
            row.source_path, row.line_number, row.proof_type
        ));
    }
    if row.unit_test_expectation.trim().is_empty() {
        errors.push(format!(
            "open-ended note row {}:{} missing unit_test_expectation",
            row.source_path, row.line_number
        ));
    }
    if row.e2e_fuzz_smoke_expectation.trim().is_empty() {
        errors.push(format!(
            "open-ended note row {}:{} missing e2e_fuzz_smoke_expectation",
            row.source_path, row.line_number
        ));
    }
    if row.decision == "false_positive" && row.non_applicability_rationale == "n/a" {
        errors.push(format!(
            "open-ended note row {}:{} false_positive needs non_applicability_rationale",
            row.source_path, row.line_number
        ));
    }
    if row.decision != "false_positive" && row.non_applicability_rationale != "n/a" {
        errors.push(format!(
            "open-ended note row {}:{} applicable note must use n/a non_applicability_rationale",
            row.source_path, row.line_number
        ));
    }
    for field in REQUIRED_NOTE_LOG_FIELDS {
        if !row.required_log_fields.iter().any(|value| value == field) {
            errors.push(format!(
                "open-ended note row {}:{} missing log field {field}",
                row.source_path, row.line_number
            ));
        }
    }
    for field in REQUIRED_NOTE_ARTIFACT_FIELDS {
        if !row.required_artifacts.iter().any(|value| value == field) {
            errors.push(format!(
                "open-ended note row {}:{} missing artifact field {field}",
                row.source_path, row.line_number
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DECISIONS, INVENTORY_MARKDOWN, OPEN_ENDED_NOTE_PATTERNS, OpenEndedInventoryReport,
        OpenEndedNoteScanReport, OpenEndedNoteSource, PROOF_TYPES, analyze_inventory,
        scan_open_ended_notes, validate_current_inventory,
    };
    use std::fs;
    use std::path::Path;
    use std::process::Command;
    use tempfile::TempDir;

    const POSITIVE_SCANNER_FIXTURE: &str =
        include_str!("../../../tests/open-ended-inventory/scanner_fixture_positive.md");
    const NEGATIVE_SCANNER_FIXTURE: &str =
        include_str!("../../../tests/open-ended-inventory/scanner_fixture_negative.md");

    fn note_source(path: &str, text: &str) -> OpenEndedNoteSource {
        OpenEndedNoteSource {
            source_path: path.to_owned(),
            text: text.to_owned(),
        }
    }

    #[test]
    fn current_inventory_has_valid_rows_and_vocabularies() {
        let report = validate_current_inventory().expect("inventory should validate");
        assert!(report.row_count >= 10, "expected substantive inventory");
        assert_eq!(
            report.proof_types,
            PROOF_TYPES
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            report.decisions,
            DECISIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn open_ended_inventory_report_json_shape() -> anyhow::Result<()> {
        let report = validate_current_inventory()?;
        let json = serde_json::to_string_pretty(&report)?;
        let parsed: OpenEndedInventoryReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        assert!(parsed.row_count >= 10, "expected substantive inventory");
        assert_eq!(parsed.errors, [] as [String; 0]);
        assert!(
            parsed
                .rows
                .iter()
                .any(|row| row.linked_bead_or_artifact.contains("bd-"))
        );

        let row_samples = report
            .rows
            .iter()
            .take(4)
            .map(|row| {
                serde_json::json!({
                    "id": &row.id,
                    "source_location": &row.source_location,
                    "required_proof_type": &row.required_proof_type,
                    "decision": &row.decision,
                    "linked_bead_or_artifact": &row.linked_bead_or_artifact,
                    "owner_status": &row.owner_status,
                    "has_non_applicability_rationale": row.non_applicability_rationale != "n/a",
                })
            })
            .collect::<Vec<_>>();
        let shape = serde_json::json!({
            "row_count": report.row_count,
            "proof_types": &report.proof_types,
            "decisions": &report.decisions,
            "error_count": report.errors.len(),
            "row_samples": row_samples,
        });
        insta::assert_snapshot!(
            "open_ended_inventory_report_json_shape",
            serde_json::to_string_pretty(&shape)?
        );
        Ok(())
    }

    #[test]
    fn current_inventory_links_every_row_to_beads_or_artifacts() {
        let report = validate_current_inventory().expect("inventory should validate");
        for row in report.rows {
            assert!(
                row.linked_bead_or_artifact.contains("bd-")
                    || row.linked_bead_or_artifact.contains('/'),
                "row {} has weak linkage",
                row.id
            );
        }
    }

    #[test]
    fn current_inventory_requires_log_and_artifact_tokens() {
        let report = validate_current_inventory().expect("inventory should validate");
        for row in report.rows {
            for token in [
                "source_path",
                "row_id",
                "decision",
                "reproduction_command",
                "artifact_path",
                "owner_status",
            ] {
                assert!(
                    row.log_artifact_expectations.contains(token),
                    "row {} missing {token}",
                    row.id
                );
            }
        }
    }

    #[test]
    fn malformed_inventory_reports_schema_errors() {
        let bad = r"
## Open-Ended Inventory Registry

| ID | Source location | Risk surface | Current evidence | Required proof type | Expected unit coverage | Expected E2E/fuzz-smoke coverage | Log/artifact expectations | Decision | Linked bead or artifact | Owner/status | Non-applicability rationale |
|----|-----------------|--------------|------------------|---------------------|------------------------|----------------------------------|---------------------------|----------|-------------------------|--------------|-----------------------------|
| aa | nowhere | risk | evidence | vibes | maybe | maybe | source_path,row_id | maybe | none | open | not n/a |
";
        let report = analyze_inventory(bad);
        assert!(report.errors.iter().any(|err| err.contains("must look")));
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("required_proof_type"))
        );
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("artifact_path"))
        );
        assert!(report.errors.iter().any(|err| err.contains("linked_bead")));
    }

    #[test]
    fn inventory_document_names_the_acceptance_bead() {
        assert!(INVENTORY_MARKDOWN.contains("bd-rchk7.1"));
    }

    #[test]
    fn open_ended_note_scanner_fixture_docs_emit_expected_rows() {
        let reproduction_command =
            "cargo test -p ffs-harness open_ended_note_scanner -- --nocapture";
        let positive = scan_open_ended_notes(
            &[note_source(
                "tests/open-ended-inventory/scanner_fixture_positive.md",
                POSITIVE_SCANNER_FIXTURE,
            )],
            "artifacts/open-ended-inventory/positive_report.json",
            reproduction_command,
        );
        println!(
            "OPEN_ENDED_NOTE_SCAN|fixture=positive|valid={}|matches={}|false_positives={}|unresolved={}|scanner_version={}",
            positive.valid,
            positive.match_count,
            positive.false_positive_count,
            positive.unresolved_note_count,
            positive.scanner_version
        );
        assert!(positive.valid, "{:?}", positive.errors);
        assert!(
            positive.match_count >= 4,
            "positive fixture should scan real rows"
        );
        assert!(
            positive.false_positive_count >= 2,
            "positive fixture should include false-positive controls"
        );
        assert_eq!(positive.unresolved_note_count, 0);
        for row in &positive.rows {
            assert_ne!(row.existing_evidence, "");
            assert!(PROOF_TYPES.contains(&row.proof_type.as_str()));
            assert_eq!(
                row.unit_test_expectation,
                "open_ended_note_scanner_fixture_docs_emit_expected_rows"
            );
            assert_eq!(
                row.e2e_fuzz_smoke_expectation,
                "scripts/e2e/ffs_open_ended_inventory_scanner_e2e.sh"
            );
            if row.decision == "false_positive" {
                assert_ne!(row.non_applicability_rationale, "n/a");
            } else {
                assert_eq!(row.non_applicability_rationale, "n/a");
            }
        }

        let negative = scan_open_ended_notes(
            &[note_source(
                "tests/open-ended-inventory/scanner_fixture_negative.md",
                NEGATIVE_SCANNER_FIXTURE,
            )],
            "artifacts/open-ended-inventory/negative_report.json",
            reproduction_command,
        );
        println!(
            "OPEN_ENDED_NOTE_SCAN|fixture=negative|valid={}|matches={}|false_positives={}|unresolved={}|scanner_version={}",
            negative.valid,
            negative.match_count,
            negative.false_positive_count,
            negative.unresolved_note_count,
            negative.scanner_version
        );
        assert!(!negative.valid);
        assert_eq!(negative.unresolved_note_count, 3);
        assert!(
            negative
                .errors
                .iter()
                .any(|error| error.contains("lacks linked bead/artifact"))
        );
        assert!(negative.rows.iter().any(|row| {
            row.matched_phrase == "fake delay" && row.risk_surface == "runtime-liveness"
        }));
        assert!(negative.rows.iter().any(|row| {
            row.matched_phrase == "not yet implemented"
                && row.risk_surface == "implementation-placeholder"
        }));
    }

    #[test]
    fn open_ended_note_scan_report_json_shape() -> anyhow::Result<()> {
        let reproduction_command =
            "cargo test -p ffs-harness open_ended_note_scanner -- --nocapture";
        let report = scan_open_ended_notes(
            &[note_source(
                "tests/open-ended-inventory/scanner_fixture_positive.md",
                POSITIVE_SCANNER_FIXTURE,
            )],
            "artifacts/open-ended-inventory/positive_report.json",
            reproduction_command,
        );
        assert!(report.valid, "{:?}", report.errors);

        let json = serde_json::to_string_pretty(&report)?;
        let parsed: OpenEndedNoteScanReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        assert_eq!(parsed.unresolved_note_count, 0);
        assert!(parsed.match_count >= 4);
        assert!(parsed.false_positive_count >= 2);

        let row_samples = parsed
            .rows
            .iter()
            .take(4)
            .map(|row| {
                serde_json::json!({
                    "source_path": &row.source_path,
                    "line_number": row.line_number,
                    "section_id": &row.section_id,
                    "matched_phrase": &row.matched_phrase,
                    "decision": &row.decision,
                    "linked_bead_or_artifact": &row.linked_bead_or_artifact,
                    "proof_type": &row.proof_type,
                    "required_log_field_count": row.required_log_fields.len(),
                    "required_artifact_count": row.required_artifacts.len(),
                })
            })
            .collect::<Vec<_>>();
        let shape = serde_json::json!({
            "schema_version": parsed.schema_version,
            "scanner_version": &parsed.scanner_version,
            "source_count": parsed.source_count,
            "search_pattern_count": parsed.search_patterns.len(),
            "match_count": parsed.match_count,
            "real_open_note_count": parsed.real_open_note_count,
            "false_positive_count": parsed.false_positive_count,
            "unresolved_note_count": parsed.unresolved_note_count,
            "output_path": &parsed.output_path,
            "reproduction_command": &parsed.reproduction_command,
            "valid": parsed.valid,
            "error_count": parsed.errors.len(),
            "row_samples": row_samples,
        });
        insta::assert_snapshot!(
            "open_ended_note_scan_report_json_shape",
            serde_json::to_string_pretty(&shape)?
        );
        Ok(())
    }

    #[test]
    fn open_ended_note_scanner_covers_pattern_vocabulary() {
        let text = OPEN_ENDED_NOTE_PATTERNS
            .iter()
            .enumerate()
            .map(|(index, pattern)| {
                format!(
                    "- {pattern} is tracked by bd-l7ov7 with artifact tests/open-ended-inventory/pattern-{index}.json"
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let report = scan_open_ended_notes(
            &[note_source("docs/patterns.md", &text)],
            "artifacts/open-ended-inventory/patterns.json",
            "cargo test -p ffs-harness open_ended_note_scanner -- --nocapture",
        );
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.match_count, OPEN_ENDED_NOTE_PATTERNS.len());
        for pattern in OPEN_ENDED_NOTE_PATTERNS {
            assert!(
                report.rows.iter().any(|row| row.matched_phrase == pattern),
                "missing pattern {pattern}"
            );
        }
        assert!(report.rows.iter().any(|row| {
            row.matched_phrase == "thread::sleep" && row.proof_type == "long-campaign"
        }));
        assert!(report.rows.iter().any(|row| {
            row.matched_phrase == "HACK" && row.risk_surface == "implementation-placeholder"
        }));
        assert!(report.rows.iter().any(|row| {
            row.matched_phrase == "XXX" && row.risk_surface == "implementation-placeholder"
        }));
    }

    #[test]
    fn open_ended_note_scanner_separates_false_positive_classes() {
        let text = "
## Scanner Examples

Historical context: closed bead bd-rchk7.1 asked to expand corpus before the inventory existed.

> Add more cases for the parser is shown here as a quoted example only.

```
TODO fuzz: future edge cases in a code block are examples, not source notes.
```

The known gaps are already linked to bd-l7ov7 and artifact reports/open-ended.json.
";
        let report = scan_open_ended_notes(
            &[note_source("docs/scanner-examples.md", text)],
            "artifacts/open-ended-inventory/examples.json",
            "cargo test -p ffs-harness open_ended_note_scanner -- --nocapture",
        );
        assert!(report.valid, "{:?}", report.errors);
        assert!(report.rows.iter().any(|row| {
            row.decision == "false_positive"
                && row.false_positive_reason == "historical_closed_context"
        }));
        assert!(report.rows.iter().any(|row| {
            row.decision == "false_positive" && row.false_positive_reason == "quoted_or_example"
        }));
        assert!(report.rows.iter().any(|row| {
            row.decision == "already_linked" && row.linked_bead_or_artifact == "bd-l7ov7"
        }));
    }

    #[test]
    fn open_ended_note_scanner_real_inventory_sample_has_no_unresolved_notes() {
        let report = scan_open_ended_notes(
            &[note_source(
                "docs/reports/FUZZ_AND_CONFORMANCE_INVENTORY.md",
                INVENTORY_MARKDOWN,
            )],
            "artifacts/open-ended-inventory/current_inventory_scan.json",
            "cargo test -p ffs-harness open_ended_note_scanner -- --nocapture",
        );
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.unresolved_note_count, 0);
        for row in report.rows {
            assert_ne!(row.source_path, "");
            assert!(row.line_number > 0);
            assert_ne!(row.section_id, "");
            assert!(row.matched_text_snippet_hash.starts_with("sha256:"));
            assert!(
                row.required_log_fields
                    .iter()
                    .any(|field| field == "row_id")
            );
            assert!(
                row.required_artifacts
                    .iter()
                    .any(|field| field == "report_json")
            );
        }
    }

    use super::{
        DEFAULT_SOURCE_SCOPE_MANIFEST_JSON, REQUIRED_SOURCE_FAMILIES,
        SOURCE_SCOPE_MANIFEST_SCHEMA_VERSION, SourceScopeManifest, SourceScopeManifestReport,
        SourceScopeScanReport, count_note_matches, parse_source_scope_manifest,
        scan_source_scope_manifest, validate_default_source_scope_manifest,
        validate_source_scope_manifest,
    };

    fn fixture_manifest() -> SourceScopeManifest {
        parse_source_scope_manifest(DEFAULT_SOURCE_SCOPE_MANIFEST_JSON)
            .expect("default source scope manifest parses")
    }

    fn write_sample_file(root: &Path, path: &str, text: &str) -> anyhow::Result<()> {
        let path = root.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, text)?;
        Ok(())
    }

    fn write_sample_files(root: &Path, files: &[(&str, &str)]) -> anyhow::Result<()> {
        for (path, text) in files {
            write_sample_file(root, path, text)?;
        }
        Ok(())
    }

    fn run_git(root: &Path, args: &[&str]) -> anyhow::Result<()> {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()?;
        if !output.status.success() {
            anyhow::bail!(
                "git {:?} failed with status {}: {}",
                args,
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    fn index_source_scope_workspace(root: &Path) -> anyhow::Result<()> {
        run_git(root, &["init"])?;
        run_git(root, &["add", "."])
    }

    fn populate_source_scope_workspace(root: &Path) -> anyhow::Result<()> {
        populate_core_source_scope_workspace(root)?;
        populate_conformance_fixture_source_scope_workspace(root)?;
        populate_test_control_artifact_source_scope_workspace(root)?;
        populate_operator_runbook_source_scope_workspace(root)?;
        populate_operational_evidence_artifact_source_scope_workspace(root)?;
        populate_architecture_design_doc_source_scope_workspace(root)?;
        populate_fuzz_campaign_artifact_source_scope_workspace(root)?;
        populate_checked_in_evidence_artifact_source_scope_workspace(root)?;
        populate_crate_manifest_and_benchmark_source_scope_workspace(root)?;
        populate_performance_source_scope_workspace(root)
    }

    fn populate_core_source_scope_workspace(root: &Path) -> anyhow::Result<()> {
        write_sample_files(
            root,
            &[
                ("README.md", "NOTE bd-rchk7.1 artifact coverage\n"),
                ("AGENTS.md", "NOTE agent workflow bd-rchk0.284 artifact\n"),
                ("FEATURE_PARITY.md", "bd-rchk7.1 artifact coverage\n"),
                (
                    "COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md",
                    "NOTE canonical spec bd-rchk7.1 artifact\n",
                ),
                (
                    "PLAN_TO_PORT_FRANKENFS_TO_RUST.md",
                    "NOTE canonical porting plan bd-rchk7.1 artifact\n",
                ),
                (
                    "EXISTING_EXT4_BTRFS_STRUCTURE.md",
                    "NOTE extracted behavior bd-rchk7.1 artifact\n",
                ),
                (
                    "PROPOSED_ARCHITECTURE.md",
                    "NOTE architecture bd-rchk7.1 artifact\n",
                ),
                (
                    "docs/reports/CONFORMANCE_SAMPLE.md",
                    "NOTE conformance bd-rchk7.1 artifact\n",
                ),
                (
                    "tests/fixtures/sample.json",
                    "{\"note\":\"bd-rchk7.1 artifact\"}\n",
                ),
                (
                    "crates/ffs-harness/src/sample.rs",
                    "// NOTE bd-rchk7.1 artifact\n",
                ),
                (
                    "tests/fuzz_corpus/README.md",
                    "TODO fuzz bd-rchk7.1 artifact\n",
                ),
                (
                    "fuzz/fuzz_targets/fuzz_sample.rs",
                    "// NOTE fuzz target bd-rchk7.1 artifact\n",
                ),
                (
                    "fuzz/scripts/smoke_gate.sh",
                    "# NOTE fuzz orchestration bd-rchk7.1 artifact\n",
                ),
                (
                    "scripts/verify_golden.sh",
                    "# NOTE operational script bd-rchk7.1 artifact\n",
                ),
                (
                    "scripts/e2e/sample.sh",
                    "# NOTE mounted-e2e bd-rchk7.1 artifact\n",
                ),
                (
                    "docs/mounted/README.md",
                    "NOTE mounted path bd-rchk7.1 artifact\n",
                ),
                ("docs/repair/README.md", "NOTE repair bd-rchk7.1 artifact\n"),
                (
                    "docs/performance/README.md",
                    "NOTE xfstests perf bd-rchk7.1 artifact\n",
                ),
            ],
        )
    }

    fn populate_conformance_fixture_source_scope_workspace(root: &Path) -> anyhow::Result<()> {
        write_sample_files(
            root,
            &[
                (
                    "conformance/COVERAGE.md",
                    "NOTE conformance coverage bd-rchk7.1 artifact\n",
                ),
                (
                    "conformance/DISCREPANCIES.md",
                    "NOTE conformance discrepancies bd-rchk7.1 artifact\n",
                ),
                (
                    "conformance/PROVENANCE.md",
                    "NOTE conformance provenance bd-rchk7.1 artifact\n",
                ),
                (
                    "conformance/fixtures/ext4_superblock_sparse.json",
                    "{\"note\":\"bd-rchk7.1 conformance fixture\"}\n",
                ),
                (
                    "conformance/fixtures/checksums.sha256",
                    "bd-rchk7.1  ext4_superblock_sparse.json\n",
                ),
                (
                    "conformance/golden/ext4_8mb_reference.json",
                    "{\"note\":\"bd-rchk7.1 conformance golden\"}\n",
                ),
                (
                    "conformance/golden/btrfs_item_payloads.txt",
                    "NOTE conformance golden bd-rchk7.1 artifact\n",
                ),
                (
                    "conformance/golden/ext4_8mb_reference.ext4",
                    "bd-rchk7.1 binary fixture placeholder\n",
                ),
                (
                    "conformance/golden/checksums.sha256",
                    "bd-rchk7.1  ext4_8mb_reference.json\n",
                ),
            ],
        )
    }

    fn populate_test_control_artifact_source_scope_workspace(root: &Path) -> anyhow::Result<()> {
        write_sample_files(
            root,
            &[
                (
                    "tests/artifact-schema-fixtures/positive/positive_matrix.fixture.json",
                    "{\"note\":\"bd-rchk7.1 artifact schema fixture\"}\n",
                ),
                (
                    "tests/btrfs-multidevice-corpus/btrfs_multidevice_corpus.json",
                    "{\"note\":\"bd-rchk7.1 btrfs multidevice corpus\"}\n",
                ),
                (
                    "tests/btrfs-send-receive-corpus/btrfs_send_receive_corpus.json",
                    "{\"note\":\"bd-rchk7.1 btrfs send receive corpus\"}\n",
                ),
                (
                    "tests/casefold-corpus/casefold_corpus.json",
                    "{\"note\":\"bd-rchk7.1 casefold corpus\"}\n",
                ),
                (
                    "tests/chaos-replay-lab/chaos_replay_lab.json",
                    "{\"note\":\"bd-rchk7.1 chaos replay lab\"}\n",
                ),
                (
                    "tests/crash-replay-artifact/crash_replay_artifact.json",
                    "{\"note\":\"bd-rchk7.1 crash replay artifact\"}\n",
                ),
                (
                    "tests/fault-injection-corpus/fault_injection_corpus.json",
                    "{\"note\":\"bd-rchk7.1 fault injection corpus\"}\n",
                ),
                (
                    "tests/fuzz-smoke/fuzz_smoke_manifest.json",
                    "{\"note\":\"bd-rchk7.1 fuzz smoke manifest\"}\n",
                ),
                (
                    "tests/inventory-closeout-gate/inventory_closeout_gate.json",
                    "{\"note\":\"bd-rchk7.1 inventory closeout gate\"}\n",
                ),
                (
                    "tests/low-privilege-demo/low_privilege_demo_manifest.json",
                    "{\"note\":\"bd-rchk7.1 low privilege demo\"}\n",
                ),
                (
                    "tests/low-privilege-demo-sandbox/low_privilege_demo_sandbox.json",
                    "{\"note\":\"bd-rchk7.1 low privilege sandbox\"}\n",
                ),
                (
                    "tests/metamorphic-workload-seeds/metamorphic_workload_seed_catalog.json",
                    "{\"note\":\"bd-rchk7.1 metamorphic workload seeds\"}\n",
                ),
                (
                    "tests/mounted-write-error-classes/mounted_write_error_classes.json",
                    "{\"note\":\"bd-rchk7.1 mounted write error classes\"}\n",
                ),
                (
                    "tests/open-ended-inventory/scanner_fixture_positive.md",
                    "NOTE open-ended scanner fixture bd-rchk7.1 artifact\n",
                ),
                (
                    "tests/readiness-lab/numa_p99_replay_fixtures.json",
                    "{\"note\":\"bd-rchk7.1 readiness lab replay\"}\n",
                ),
                (
                    "tests/release-gates/release_gate_policy_v1.json",
                    "{\"note\":\"bd-rchk7.1 release gate policy\"}\n",
                ),
                (
                    "tests/remediation-catalog/remediation_catalog.json",
                    "{\"note\":\"bd-rchk7.1 remediation catalog\"}\n",
                ),
                (
                    "tests/repair-corpus/repair_corpus.json",
                    "{\"note\":\"bd-rchk7.1 repair corpus\"}\n",
                ),
            ],
        )
    }

    fn populate_operator_runbook_source_scope_workspace(root: &Path) -> anyhow::Result<()> {
        write_sample_files(
            root,
            &[
                (
                    "docs/runbooks/readiness-action-autopilot.md",
                    "NOTE operator runbook bd-rchk7.1 artifact\n",
                ),
                (
                    "docs/release/V1.2_test_waivers.md",
                    "NOTE release waiver bd-rchk7.1 artifact\n",
                ),
                (
                    "docs/templates/ISOMORPHISM_PROOF_TEMPLATE.md",
                    "NOTE operator template bd-rchk7.1 artifact\n",
                ),
                (
                    "docs/tracker-hygiene.md",
                    "NOTE tracker hygiene bd-rchk7.1 artifact\n",
                ),
                (
                    "docs/xfstests-known-failures.md",
                    "NOTE xfstests blocker bd-rchk7.1 artifact\n",
                ),
            ],
        )
    }

    fn populate_operational_evidence_artifact_source_scope_workspace(
        root: &Path,
    ) -> anyhow::Result<()> {
        write_sample_files(
            root,
            &[
                (
                    "security/adversarial_image_threat_model.json",
                    "{\"note\":\"bd-rchk0.5.11 hostile image evidence\"}\n",
                ),
                (
                    "docs/adaptive-runtime-evidence-manifest.json",
                    "{\"note\":\"bd-rchk0.53 adaptive runtime evidence\"}\n",
                ),
                (
                    "docs/operator-recovery-drill.json",
                    "{\"note\":\"bd-rchk0.5.8 operator recovery drill\"}\n",
                ),
                (
                    "docs/topology-runtime-advisor-manifest.json",
                    "{\"note\":\"bd-rchk0.212 topology runtime advisor\"}\n",
                ),
                (
                    "docs/repair-writeback-serialization-contract.json",
                    "{\"note\":\"bd-rchk0.1.1 repair writeback serialization\"}\n",
                ),
                (
                    "docs/repair-confidence-mutation-safety.json",
                    "{\"note\":\"bd-rchk6 repair confidence safety\"}\n",
                ),
                (
                    "docs/reports/ADVERSARIAL_IMAGE_THREAT_MODEL.md",
                    "NOTE adversarial image threat model bd-rchk0.5.11 artifact\n",
                ),
                (
                    "docs/reports/SOAK_CANARY_CAMPAIGNS.md",
                    "NOTE soak canary campaign bd-rchk0.5.9 artifact\n",
                ),
                (
                    "docs/reports/PERFORMANCE_BASELINE_MANIFEST.md",
                    "NOTE performance baseline manifest bd-rchk5 artifact\n",
                ),
            ],
        )
    }

    fn populate_architecture_design_doc_source_scope_workspace(root: &Path) -> anyhow::Result<()> {
        write_sample_files(
            root,
            &[
                (
                    "docs/design-adaptive-refresh.md",
                    "NOTE adaptive refresh design bd-m5wf.4.1 artifact\n",
                ),
                (
                    "docs/oq1-native-mode-boundary.md",
                    "NOTE native mode boundary bd-h6nz.6.1 artifact\n",
                ),
                (
                    "docs/perf/README.md",
                    "NOTE perf runbook bd-rchk5 artifact\n",
                ),
            ],
        )
    }

    fn populate_fuzz_campaign_artifact_source_scope_workspace(root: &Path) -> anyhow::Result<()> {
        write_sample_files(
            root,
            &[
                (
                    "artifacts/fuzz/20260506_bd-rchk0_59_high_cursor_warm/campaign_summary.json",
                    "{\"bead_id\":\"bd-rchk0.59\",\"note\":\"NOTE fuzz campaign artifact\"}\n",
                ),
                (
                    "artifacts/fuzz/20260506_bd-rchk0_59_high_cursor_warm/command_transcript.txt",
                    "bead_id=bd-rchk0.59\nNOTE fuzz command transcript artifact\n",
                ),
                (
                    "artifacts/fuzz/20260506_bd-rchk0_59_high_cursor_warm/logs/fuzz_ioctl_dispatch.log",
                    "NOTE fuzz ioctl dispatch artifact bd-rchk0.59\n",
                ),
            ],
        )
    }

    fn populate_checked_in_evidence_artifact_source_scope_workspace(
        root: &Path,
    ) -> anyhow::Result<()> {
        write_sample_files(
            root,
            &[
                (
                    "artifacts/benchmarks/ebr_memory_usage.json",
                    "{\"bead_id\":\"bd-rchk5\",\"note\":\"NOTE benchmark evidence artifact\"}\n",
                ),
                (
                    "artifacts/optimization/open_beads_alien_matrix.json",
                    "{\"bead_id\":\"bd-rchk0\",\"note\":\"NOTE optimization matrix artifact\"}\n",
                ),
                (
                    "artifacts/optimization/open_beads_alien_matrix.md",
                    "NOTE optimization matrix bd-rchk0 artifact\n",
                ),
                (
                    "artifacts/optimization/open_beads_alien_matrix.tsv",
                    "row_id\tbead_id\tnote\n1\tbd-rchk0\tNOTE optimization artifact\n",
                ),
                (
                    "artifacts/optimization/strace_backpressure_before.txt",
                    "NOTE strace backpressure artifact bd-rchk0.53\n",
                ),
                (
                    "artifacts/e2e/20260213_153535_ffs_ext4_rw_smoke/run.log",
                    "SCENARIO_RESULT|scenario_id=ext4_rw|outcome=PASS|bead_id=bd-rchk0\n",
                ),
                (
                    "artifacts/e2e/20260213_153535_ffs_ext4_rw_smoke/mount_rw_mnt_rw.log",
                    "NOTE mounted evidence artifact bd-rchk0.3\n",
                ),
                (
                    "artifacts/e2e/20260503_010213_ffs_operational_readiness_report/result.json",
                    "{\"bead_id\":\"bd-rchk0.4.3\",\"status\":\"PASS\"}\n",
                ),
                (
                    "artifacts/parity-deferred-followups.md",
                    "NOTE parity deferred follow-up artifact bd-rchk0\n",
                ),
            ],
        )
    }

    fn populate_crate_manifest_and_benchmark_source_scope_workspace(
        root: &Path,
    ) -> anyhow::Result<()> {
        write_sample_files(
            root,
            &[
                (
                    "Cargo.toml",
                    "# NOTE workspace manifest bd-rchk0 artifact\n",
                ),
                (
                    "rust-toolchain.toml",
                    "# NOTE Rust toolchain manifest bd-rchk0 artifact\n",
                ),
                (
                    "crates/ffs-block/Cargo.toml",
                    "# NOTE crate manifest bd-rchk0 artifact\n",
                ),
                (
                    "crates/ffs-block/benches/arc_cache.rs",
                    "// bd-rchk5 benchmark source artifact\n",
                ),
            ],
        )
    }

    fn populate_performance_source_scope_workspace(root: &Path) -> anyhow::Result<()> {
        write_sample_files(
            root,
            &[
                (
                    "benchmarks/performance_baseline_manifest.json",
                    "{\"note\":\"bd-rchk5 artifact\"}\n",
                ),
                (
                    "benchmarks/thresholds.toml",
                    "# NOTE benchmark thresholds bd-rchk5 artifact\n",
                ),
                (
                    "benchmarks/baselines/latest.json",
                    "{\"note\":\"bd-rchk5 latest baseline artifact\"}\n",
                ),
                (
                    "benchmarks/baselines/history/current.json",
                    "{\"note\":\"bd-rchk5 history artifact\"}\n",
                ),
                (
                    "baselines/README.md",
                    "NOTE baseline summary bd-rchk5 artifact\n",
                ),
                (
                    "profiles/flamegraph_cli_inspect.meta.json",
                    "{\"note\":\"bd-1ieht profile artifact\"}\n",
                ),
            ],
        )
    }

    #[test]
    fn default_source_scope_manifest_validates_required_families() {
        let report = validate_default_source_scope_manifest().expect("default manifest validates");
        assert_eq!(report.schema_version, SOURCE_SCOPE_MANIFEST_SCHEMA_VERSION);
        assert_eq!(report.bead_id, "bd-lm0g9");
        assert_eq!(report.source_count, REQUIRED_SOURCE_FAMILIES.len());
        for family in REQUIRED_SOURCE_FAMILIES {
            assert!(
                report.source_families.iter().any(|f| f == family),
                "missing required family {family}"
            );
        }
        assert_eq!(report.stale_sources, [] as [String; 0]);
    }

    #[test]
    fn source_scope_manifest_report_json_shape() -> anyhow::Result<()> {
        let report = validate_default_source_scope_manifest()?;
        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("source_scope_manifest_report_json_shape", json);
        let parsed: SourceScopeManifestReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn missing_required_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "tests");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `tests`"))
        );
    }

    #[test]
    fn missing_canonical_spec_docs_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "canonical_spec_docs");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `canonical_spec_docs`"))
        );
    }

    #[test]
    fn missing_agent_workflow_docs_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "agent_workflow_docs");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `agent_workflow_docs`"))
        );
    }

    #[test]
    fn missing_conformance_fixture_artifacts_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "conformance_fixture_artifacts");
        let report = validate_source_scope_manifest(&manifest);
        assert!(report.errors.iter().any(|err| {
            err.contains("missing required family `conformance_fixture_artifacts`")
        }));
    }

    #[test]
    fn missing_test_control_artifacts_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "test_control_artifacts");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `test_control_artifacts`"))
        );
    }

    #[test]
    fn missing_repair_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "repair_docs");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `repair_docs`"))
        );
    }

    #[test]
    fn missing_fuzz_corpus_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "fuzz_corpus_notes");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `fuzz_corpus_notes`"))
        );
    }

    #[test]
    fn missing_fuzz_campaign_artifacts_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "fuzz_campaign_artifacts");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `fuzz_campaign_artifacts`"))
        );
    }

    #[test]
    fn missing_checked_in_evidence_artifacts_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "checked_in_evidence_artifacts");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `checked_in_evidence_artifacts`"))
        );
    }

    #[test]
    fn missing_crate_manifest_and_benchmark_sources_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "crate_manifest_and_benchmark_sources");
        let report = validate_source_scope_manifest(&manifest);
        assert!(report.errors.iter().any(|err| {
            err.contains("missing required family `crate_manifest_and_benchmark_sources`")
        }));
    }

    #[test]
    fn missing_fuzz_targets_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "fuzz_targets");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `fuzz_targets`"))
        );
    }

    #[test]
    fn missing_fuzz_orchestration_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "fuzz_orchestration");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `fuzz_orchestration`"))
        );
    }

    #[test]
    fn missing_operational_scripts_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "operational_scripts");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `operational_scripts`"))
        );
    }

    #[test]
    fn missing_harness_scripts_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "harness_scripts");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `harness_scripts`"))
        );
    }

    #[test]
    fn missing_operator_runbook_docs_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "operator_runbook_docs");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| { err.contains("missing required family `operator_runbook_docs`") })
        );
    }

    #[test]
    fn missing_operational_evidence_artifacts_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "operational_evidence_artifacts");
        let report = validate_source_scope_manifest(&manifest);
        assert!(report.errors.iter().any(|err| {
            err.contains("missing required family `operational_evidence_artifacts`")
        }));
    }

    #[test]
    fn missing_architecture_design_docs_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "architecture_design_docs");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `architecture_design_docs`"))
        );
    }

    #[test]
    fn missing_performance_control_artifacts_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "performance_control_artifacts");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `performance_control_artifacts`"))
        );
    }

    #[test]
    fn duplicate_source_id_is_rejected() {
        let mut manifest = fixture_manifest();
        let duplicate_id = manifest.sources[0].id.clone();
        manifest.sources[1].id = duplicate_id;
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate source scope entry id"))
        );
    }

    #[test]
    fn invalid_risk_category_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].risk_category = "vibes".to_owned();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported risk_category"))
        );
    }

    #[test]
    fn unsupported_proof_type_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].expected_proof_types = vec!["telepathy".to_owned()];
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported proof type"))
        );
    }

    #[test]
    fn empty_included_globs_without_rationale_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].included_globs.clear();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must declare included_globs"))
        );
    }

    #[test]
    fn non_applicability_rationale_allows_empty_globs() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].included_globs.clear();
        manifest.sources[0].expected_proof_types.clear();
        manifest.sources[0].non_applicability_rationale =
            "intentionally absent: status sourced from beads".to_owned();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report.valid,
            "non-applicability path should pass: {:?}",
            report.errors
        );
    }

    #[test]
    fn missing_owner_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].owner = String::new();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing owner"))
        );
    }

    #[test]
    fn invalid_status_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].status = "spelunking".to_owned();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported status"))
        );
    }

    #[test]
    fn non_applicable_status_requires_rationale() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].status = "non_applicable".to_owned();
        manifest.sources[0].non_applicability_rationale = String::new();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("non_applicable requires non_applicability_rationale"))
        );
    }

    #[test]
    fn stale_freshness_state_is_surfaced() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].freshness_state = "stale".to_owned();
        manifest.sources[0].source_hash =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned();
        let report = validate_source_scope_manifest(&manifest);
        assert!(report.valid, "stale state alone should not fail validation");
        assert!(
            report
                .stale_sources
                .iter()
                .any(|id| id == &manifest.sources[0].id)
        );
    }

    #[test]
    fn invalid_freshness_state_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].freshness_state = "ancient".to_owned();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported freshness_state"))
        );
    }

    #[test]
    fn zero_ttl_without_exempt_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].freshness_ttl_days = 0;
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("freshness_ttl_days must be positive"))
        );
    }

    #[test]
    fn malformed_source_hash_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].source_hash = "sha1:not-the-right-format".to_owned();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("malformed source_hash"))
        );
    }

    #[test]
    fn stale_freshness_state_requires_source_hash() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].freshness_state = "stale".to_owned();
        manifest.sources[0].source_hash = String::new();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("stale requires source_hash"))
        );
    }

    #[test]
    fn well_formed_sha256_hash_is_accepted() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].source_hash =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report.valid,
            "well-formed sha256 should pass: {:?}",
            report.errors
        );
    }

    #[test]
    fn empty_sources_list_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources.clear();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one source"))
        );
    }

    #[test]
    fn unsupported_source_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].source_family = "blog_drafts".to_owned();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported source_family"))
        );
    }

    #[test]
    fn required_generated_and_vendor_exclusions_are_validated() {
        let mut manifest = fixture_manifest();
        let canonical_specs = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "canonical_spec_docs")
            .expect("canonical spec docs source exists");
        canonical_specs
            .included_globs
            .retain(|glob| glob != "PROPOSED_ARCHITECTURE.md");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("PROPOSED_ARCHITECTURE.md"))
        );

        let mut manifest = fixture_manifest();
        let tests = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "tests")
            .expect("tests source exists");
        tests.excluded_globs.retain(|glob| !glob.contains("vendor"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must exclude vendor paths"))
        );

        let mut manifest = fixture_manifest();
        let readme = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "readme_status_docs")
            .expect("readme status source exists");
        readme
            .excluded_globs
            .retain(|glob| !glob.contains("_generated"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("generated status docs"))
        );

        let mut manifest = fixture_manifest();
        let fuzz_targets = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "fuzz_targets")
            .expect("fuzz target source exists");
        fuzz_targets
            .excluded_globs
            .retain(|glob| !glob.contains("vendor"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("vendor paths from fuzz target source scope"))
        );

        let mut manifest = fixture_manifest();
        let fuzz_orchestration = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "fuzz_orchestration")
            .expect("fuzz orchestration source exists");
        fuzz_orchestration
            .excluded_globs
            .retain(|glob| !glob.contains("vendor"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("vendor paths from fuzz orchestration source scope"))
        );

        let mut manifest = fixture_manifest();
        let operational_scripts = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "operational_scripts")
            .expect("operational script source exists");
        operational_scripts
            .excluded_globs
            .retain(|glob| !glob.contains("scripts/e2e"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("dedicated harness script source scope"))
        );
    }

    #[test]
    fn rch_worker_target_glob_exclusion_is_validated() {
        let mut manifest = fixture_manifest();
        let tests = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "tests")
            .expect("tests source exists");
        tests
            .excluded_globs
            .retain(|glob| !glob.contains(".rch-target-*"));

        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("build target paths from test source scope")),
            "missing worker-suffixed RCH target glob should be rejected: {:?}",
            report.errors
        );
    }

    #[test]
    fn rch_exact_target_glob_exclusion_is_validated() {
        let mut manifest = fixture_manifest();
        let tests = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "tests")
            .expect("tests source exists");
        tests
            .excluded_globs
            .retain(|glob| !glob.contains(".rch-target/**"));

        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("build target paths from test source scope")),
            "missing exact RCH target glob should be rejected: {:?}",
            report.errors
        );
    }

    #[test]
    fn harness_script_source_globs_are_validated() {
        let mut manifest = fixture_manifest();
        let harness_scripts = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "harness_scripts")
            .expect("harness script source exists");
        harness_scripts
            .included_globs
            .retain(|glob| glob == "scripts/e2e/**/*.sh");
        harness_scripts
            .excluded_globs
            .retain(|glob| !glob.contains("_artifacts"));

        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("scripts/e2e/**/*.py")),
            "missing Python harness glob should be rejected: {:?}",
            report.errors
        );
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("scripts/e2e/**/*.json")),
            "missing JSON harness glob should be rejected: {:?}",
            report.errors
        );
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("generated e2e artifact directories")),
            "missing generated-artifact exclusion should be rejected: {:?}",
            report.errors
        );
    }

    #[test]
    fn performance_control_artifacts_exclusions_are_validated() {
        let mut manifest = fixture_manifest();
        let performance = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "performance_control_artifacts")
            .expect("performance control source exists");
        performance
            .included_globs
            .retain(|glob| glob != "benchmarks/baselines/latest.json");
        performance
            .excluded_globs
            .retain(|glob| !glob.contains("baselines/hyperfine"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(report.errors.iter().any(|err| {
            err.contains("benchmarks/baselines/latest.json")
                || err.contains("generated hyperfine baseline outputs")
        }));
    }

    #[test]
    fn conformance_fixture_artifacts_coverage_is_validated() {
        let mut manifest = fixture_manifest();
        let conformance = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "conformance_fixture_artifacts")
            .expect("conformance fixture source exists");
        conformance
            .included_globs
            .retain(|glob| glob != "conformance/golden/*.json");
        conformance
            .excluded_globs
            .retain(|glob| !glob.contains(".rch-target"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(report.errors.iter().any(|err| {
            err.contains("conformance/golden/*.json")
                || err.contains("build target paths from conformance fixture artifacts")
        }));
    }

    #[test]
    fn generated_ext4_images_are_not_checksum_covered_tracked_artifacts() {
        let mut manifest = fixture_manifest();
        let conformance = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "conformance_fixture_artifacts")
            .expect("conformance fixture source exists");
        conformance
            .included_globs
            .push("conformance/golden/*.ext4".to_owned());

        let generated = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "conformance_generated_image_artifacts")
            .expect("generated image source exists");
        generated.status = "active".to_owned();
        generated.expected_proof_types = vec!["golden-fixture".to_owned()];
        generated.freshness_ttl_days = 30;
        generated.freshness_state = "fresh".to_owned();
        generated.non_applicability_rationale.clear();

        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report.errors.iter().any(|err| {
                err.contains("must not include generated ext4 image glob")
                    && err.contains("tracked checksum artifact")
            }),
            "tracked conformance source must reject generated ext4 images: {:?}",
            report.errors
        );
        assert!(
            report.errors.iter().any(|err| {
                err.contains("must mark generated ext4 images as non_applicable")
                    || err.contains("generated ext4 images must use freshness_state=exempt")
                    || err.contains("generated ext4 images must not declare checksum proof types")
                    || err.contains("status non_applicable requires non_applicability_rationale")
            }),
            "generated ext4 image source must require regenerated-local non-applicability semantics: {:?}",
            report.errors
        );
    }

    #[test]
    fn generated_ext4_image_source_requires_regeneration_contract() {
        let mut manifest = fixture_manifest();
        let generated = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "conformance_generated_image_artifacts")
            .expect("generated image source exists");
        generated
            .included_globs
            .retain(|glob| glob != "conformance/golden/*.ext4");
        generated.non_applicability_rationale =
            "generated locally and intentionally excluded".to_owned();

        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report.errors.iter().any(|err| {
                err.contains(
                    "generated conformance image artifact glob `conformance/golden/*.ext4`",
                ) || err.contains("generated ext4 image rationale must mention `regenerated`")
                    || err.contains("generated ext4 image rationale must mention `gitignored`")
                    || err.contains("generated ext4 image rationale must mention `checksum`")
            }),
            "generated ext4 image source must preserve ext4 glob and regeneration rationale: {:?}",
            report.errors
        );
    }

    #[test]
    fn test_control_artifacts_coverage_is_validated() {
        let mut manifest = fixture_manifest();
        let test_artifacts = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "test_control_artifacts")
            .expect("test control artifact source exists");
        test_artifacts
            .included_globs
            .retain(|glob| glob != "tests/remediation-*/*.json");
        test_artifacts
            .excluded_globs
            .retain(|glob| !glob.contains("_generated"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(report.errors.iter().any(|err| {
            err.contains("tests/remediation-*/*.json")
                || err.contains("generated test control artifact directories")
        }));
    }

    #[test]
    fn operator_runbook_docs_coverage_is_validated() {
        let mut manifest = fixture_manifest();
        let operator_docs = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "operator_runbook_docs")
            .expect("operator runbook source exists");
        operator_docs
            .included_globs
            .retain(|glob| glob != "docs/tracker-hygiene.md");
        operator_docs
            .excluded_globs
            .retain(|glob| !glob.contains(".rch-target"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(report.errors.iter().any(|err| {
            err.contains("docs/tracker-hygiene.md")
                || err.contains("build target paths from operator runbook docs")
        }));
    }

    #[test]
    fn operational_evidence_artifacts_coverage_is_validated() {
        let mut manifest = fixture_manifest();
        let operational_evidence = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "operational_evidence_artifacts")
            .expect("operational evidence source exists");
        operational_evidence
            .included_globs
            .retain(|glob| glob != "security/*.json");
        operational_evidence
            .excluded_globs
            .retain(|glob| !glob.contains("_artifacts"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(report.errors.iter().any(|err| {
            err.contains("security/*.json")
                || err.contains("generated operational evidence artifact directories")
        }));
    }

    #[test]
    fn architecture_design_docs_coverage_is_validated() {
        let mut manifest = fixture_manifest();
        let architecture_docs = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "architecture_design_docs")
            .expect("architecture design docs source exists");
        architecture_docs
            .included_globs
            .retain(|glob| glob != "docs/oq*.md");
        architecture_docs
            .excluded_globs
            .retain(|glob| !glob.contains("_generated"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(report.errors.iter().any(|err| {
            err.contains("docs/oq*.md")
                || err.contains("generated architecture design doc directories")
        }));
    }

    #[test]
    fn agent_workflow_docs_coverage_is_validated() {
        let mut manifest = fixture_manifest();
        let agent_docs = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "agent_workflow_docs")
            .expect("agent workflow docs source exists");
        agent_docs.included_globs.retain(|glob| glob != "AGENTS.md");
        agent_docs
            .excluded_globs
            .retain(|glob| !glob.contains(".rch-target"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(report.errors.iter().any(|err| {
            err.contains("AGENTS.md") || err.contains("build target paths from agent workflow docs")
        }));
    }

    #[test]
    fn fuzz_campaign_artifacts_coverage_is_validated() {
        let mut manifest = fixture_manifest();
        let fuzz_campaign = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "fuzz_campaign_artifacts")
            .expect("fuzz campaign artifact source exists");
        fuzz_campaign
            .included_globs
            .retain(|glob| glob != "artifacts/fuzz/*/command_transcript.txt");
        fuzz_campaign
            .excluded_globs
            .retain(|glob| !glob.contains("artifacts/fuzz/*/artifacts/**"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(report.errors.iter().any(|err| {
            err.contains("artifacts/fuzz/*/command_transcript.txt")
                || err.contains("generated fuzz campaign artifact directories")
        }));
    }

    #[test]
    fn checked_in_evidence_artifacts_coverage_is_validated() {
        let mut manifest = fixture_manifest();
        let checked_in_artifacts = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "checked_in_evidence_artifacts")
            .expect("checked-in evidence artifact source exists");
        checked_in_artifacts
            .included_globs
            .retain(|glob| glob != "artifacts/optimization/*.json");
        checked_in_artifacts
            .excluded_globs
            .retain(|glob| !glob.contains("_artifacts"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(report.errors.iter().any(|err| {
            err.contains("artifacts/optimization/*.json")
                || err.contains("generated checked-in evidence artifact directories")
        }));
    }

    #[test]
    fn crate_manifest_and_benchmark_sources_coverage_is_validated() {
        let mut manifest = fixture_manifest();
        let crate_sources = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "crate_manifest_and_benchmark_sources")
            .expect("crate manifest and benchmark source exists");
        crate_sources
            .included_globs
            .retain(|glob| glob != "crates/*/benches/*.rs");
        crate_sources
            .excluded_globs
            .retain(|glob| !glob.contains("vendor"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(report.errors.iter().any(|err| {
            err.contains("crates/*/benches/*.rs")
                || err.contains("vendor paths from crate manifests and benchmark sources")
        }));
    }

    #[test]
    fn source_scope_scan_logs_workspace_hashes_and_counts() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        populate_source_scope_workspace(temp.path())?;
        let report = scan_source_scope_manifest(
            &fixture_manifest(),
            temp.path(),
            Some(Path::new("artifacts/source_scope_scan.json")),
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );
        assert!(report.valid, "scan should validate: {:?}", report.errors);
        assert_eq!(report.workspace_file_source, "filesystem_fallback");
        // A temp directory outside a checkout has no Git scan; under TMPDIR
        // inside a checkout its fixture files are untracked instead.
        let reason = &report.workspace_file_source_reason;
        assert!(
            reason.starts_with("git-tracked scan unavailable:")
                || (reason.starts_with("git-tracked scan incomplete for ")
                    && reason.ends_with("; filesystem fallback missing <none>")),
            "temp fixtures should record why they used filesystem fallback: {reason}"
        );
        assert_eq!(report.source_count, REQUIRED_SOURCE_FAMILIES.len());
        assert_eq!(
            report.source_manifest_version,
            SOURCE_SCOPE_MANIFEST_SCHEMA_VERSION
        );
        assert_eq!(report.output_path, "artifacts/source_scope_scan.json");
        for source in &report.scanned_sources {
            if source.source_family == "conformance_generated_image_artifacts" {
                assert_eq!(source.inclusion_decision, "non_applicable");
                assert!(
                    source.exclusion_reason.contains("regenerated")
                        && source.exclusion_reason.contains("checksum"),
                    "generated image source should explain regeneration and checksum exclusion"
                );
                assert_eq!(source.file_or_directory_hash, "");
                assert_eq!(source.matched_note_count, 0);
                assert_eq!(source.linked_bead_or_artifact_count, 0);
                assert!(source.output_path.ends_with("source_scope_scan.json"));
                assert!(
                    source
                        .reproduction_command
                        .contains("validate-source-scope")
                );
                continue;
            }
            assert_eq!(source.inclusion_decision, "included");
            assert!(
                source.file_or_directory_hash.starts_with("sha256:"),
                "source {} missing aggregate hash",
                source.id
            );
            assert!(
                source.matched_note_count > 0,
                "source {} should count open-ended note tokens",
                source.id
            );
            assert!(
                source.linked_bead_or_artifact_count > 0,
                "source {} should count linked beads/artifacts",
                source.id
            );
            assert!(source.output_path.ends_with("source_scope_scan.json"));
            assert!(
                source
                    .reproduction_command
                    .contains("validate-source-scope")
            );
        }
        Ok(())
    }

    #[test]
    fn source_scope_scan_uses_git_tracked_files_for_canonical_hashes() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        populate_source_scope_workspace(temp.path())?;
        index_source_scope_workspace(temp.path())?;

        let clean_report = scan_source_scope_manifest(
            &fixture_manifest(),
            temp.path(),
            None,
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );
        assert!(
            clean_report.valid,
            "clean git-backed scan should validate: {:?}",
            clean_report.errors
        );
        assert_eq!(clean_report.workspace_file_source, "git_ls_files");
        assert!(
            clean_report
                .workspace_file_source_reason
                .contains("git-tracked paths")
        );

        let clean_evidence = clean_report
            .scanned_sources
            .iter()
            .find(|source| source.source_family == "checked_in_evidence_artifacts")
            .expect("checked-in evidence source scanned");
        let clean_hash = clean_evidence.file_or_directory_hash.clone();
        let clean_path_count = clean_evidence.matched_paths.len();

        write_sample_file(
            temp.path(),
            "artifacts/e2e/20990101_000000_untracked_local/run.log",
            "SCENARIO_RESULT|scenario_id=local_dirty|outcome=PASS|bead_id=bd-rchk0\n",
        )?;

        let dirty_report = scan_source_scope_manifest(
            &fixture_manifest(),
            temp.path(),
            None,
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );
        assert!(
            dirty_report.valid,
            "dirty git-backed scan should validate: {:?}",
            dirty_report.errors
        );
        assert_eq!(dirty_report.workspace_file_source, "git_ls_files");
        let dirty_evidence = dirty_report
            .scanned_sources
            .iter()
            .find(|source| source.source_family == "checked_in_evidence_artifacts")
            .expect("checked-in evidence source scanned");

        assert_eq!(
            dirty_evidence.file_or_directory_hash, clean_hash,
            "untracked local artifacts must not perturb canonical source hashes"
        );
        assert_eq!(
            dirty_evidence.matched_paths.len(),
            clean_path_count,
            "untracked local artifacts must not increase canonical matched paths"
        );
        assert!(
            dirty_evidence.matched_paths.iter().all(|path| {
                path.source_path != "artifacts/e2e/20990101_000000_untracked_local/run.log"
            }),
            "untracked local artifact should not be part of canonical matched paths"
        );
        assert_eq!(dirty_report.untracked_matched_path_count, 1);
        assert_eq!(dirty_evidence.untracked_matched_path_count, 1);
        assert_eq!(dirty_evidence.untracked_matched_paths.len(), 1);
        let untracked_path = dirty_evidence
            .untracked_matched_paths
            .first()
            .expect("untracked source-scope diagnostic");
        assert_eq!(
            untracked_path.source_path,
            "artifacts/e2e/20990101_000000_untracked_local/run.log"
        );
        assert_eq!(untracked_path.inclusion_decision, "untracked_excluded");
        assert!(
            untracked_path
                .exclusion_reason
                .contains("canonical source hash")
        );
        assert!(
            dirty_evidence.matched_paths.iter().any(|path| {
                path.source_path == "artifacts/e2e/20260213_153535_ffs_ext4_rw_smoke/run.log"
                    && path.inclusion_decision == "included"
                    && path.file_hash.starts_with("sha256:")
            }),
            "tracked evidence artifact should remain canonical and hash-bearing"
        );
        Ok(())
    }

    #[test]
    fn source_scope_scan_ignores_untracked_files_that_match_no_source_glob() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        populate_source_scope_workspace(temp.path())?;
        index_source_scope_workspace(temp.path())?;
        write_sample_file(
            temp.path(),
            "scratch/local-only.tmp",
            "NOTE local scratch bd-rchk0 should not match source-scope globs\n",
        )?;

        let report = scan_source_scope_manifest(
            &fixture_manifest(),
            temp.path(),
            None,
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );

        assert!(report.valid, "scan should validate: {:?}", report.errors);
        assert_eq!(report.workspace_file_source, "git_ls_files");
        assert_eq!(report.untracked_matched_path_count, 0);
        assert!(report.scanned_sources.iter().all(|source| {
            source
                .untracked_matched_paths
                .iter()
                .all(|path| path.source_path != "scratch/local-only.tmp")
        }));
        Ok(())
    }

    #[test]
    fn source_scope_scan_report_json_shape() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        populate_source_scope_workspace(temp.path())?;
        index_source_scope_workspace(temp.path())?;
        write_sample_file(
            temp.path(),
            "artifacts/e2e/20990101_000000_untracked_local/run.log",
            "SCENARIO_RESULT|scenario_id=local_dirty|outcome=PASS|bead_id=bd-rchk0\n",
        )?;

        let report = scan_source_scope_manifest(
            &fixture_manifest(),
            temp.path(),
            None,
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );
        assert!(report.valid, "scan should validate: {:?}", report.errors);
        let evidence = report
            .scanned_sources
            .iter()
            .find(|source| source.source_family == "checked_in_evidence_artifacts")
            .expect("checked-in evidence source scanned");

        let shape = serde_json::json!({
            "schema_version": report.schema_version,
            "workspace_file_source": report.workspace_file_source,
            "untracked_matched_path_count": report.untracked_matched_path_count,
            "checked_in_evidence_artifacts": {
                "matched_path_count": evidence.matched_paths.len(),
                "untracked_matched_path_count": evidence.untracked_matched_path_count,
                "untracked_matched_paths": evidence.untracked_matched_paths,
            }
        });
        let shape_json = serde_json::to_string_pretty(&shape)?;
        insta::assert_snapshot!("source_scope_scan_report_json_shape", shape_json);

        let json = serde_json::to_string_pretty(&report)?;
        let parsed: SourceScopeScanReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn source_scope_scan_falls_back_when_git_index_is_incomplete() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        populate_source_scope_workspace(temp.path())?;
        run_git(temp.path(), &["init"])?;
        run_git(temp.path(), &["add", "README.md"])?;

        let report = scan_source_scope_manifest(
            &fixture_manifest(),
            temp.path(),
            None,
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );

        assert!(
            report.valid,
            "filesystem fallback should recover from incomplete git metadata: {:?}",
            report.errors
        );
        assert_eq!(report.workspace_file_source, "filesystem_fallback");
        assert!(
            report
                .workspace_file_source_reason
                .contains("git-tracked scan incomplete"),
            "fallback reason should identify incomplete git metadata"
        );
        assert!(
            report
                .workspace_file_source_reason
                .contains("agent_workflow_docs"),
            "fallback reason should preserve missing source ids"
        );
        Ok(())
    }

    #[test]
    fn source_scope_note_counter_requires_token_boundaries() {
        assert_eq!(
            count_note_matches("FfsError::NotEmpty maps to ENOTEMPTY"),
            0,
            "errno constants and Rust identifiers must not count as NOTE markers"
        );
        assert_eq!(
            count_note_matches("fake_source mock_impl dummyValue placeholderName stubbed"),
            0,
            "implementation-placeholder words inside identifiers are scanner noise"
        );
        assert_eq!(
            count_note_matches(
                "// NOTE: TODO fuzz FIXME bd-rchk7.1 non-goal not yet implemented thread::sleep fake mock dummy placeholder stub"
            ),
            12,
            "standalone markers, tracked beads, explicit phrases, and sleep markers still count"
        );
    }

    #[test]
    fn source_scope_scan_ignores_note_inside_errno_identifier() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        populate_source_scope_workspace(temp.path())?;
        write_sample_file(
            temp.path(),
            "crates/ffs-error/src/lib.rs",
            "pub enum FfsError { NotEmpty }\nconst ERRNO: &str = \"ENOTEMPTY\";\n",
        )?;

        let report = scan_source_scope_manifest(
            &fixture_manifest(),
            temp.path(),
            None,
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );
        assert!(report.valid, "scan should validate: {:?}", report.errors);
        let tests = report
            .scanned_sources
            .iter()
            .find(|source| source.source_family == "tests")
            .expect("tests source scanned");
        let errno_path = tests
            .matched_paths
            .iter()
            .find(|path| path.source_path == "crates/ffs-error/src/lib.rs")
            .expect("errno fixture path logged");
        assert_eq!(errno_path.matched_note_count, 0);
        assert_eq!(errno_path.linked_bead_or_artifact_count, 0);
        Ok(())
    }

    #[test]
    fn source_scope_scan_logs_excluded_generated_paths() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        populate_source_scope_workspace(temp.path())?;
        write_sample_file(
            temp.path(),
            "docs/status/_generated/ignored.md",
            "NOTE generated bd-rchk7.1 artifact\n",
        )?;
        let report = scan_source_scope_manifest(
            &fixture_manifest(),
            temp.path(),
            None,
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );
        let readme = report
            .scanned_sources
            .iter()
            .find(|source| source.source_family == "readme_status_docs")
            .expect("readme status source scanned");
        assert!(
            readme.matched_paths.iter().any(|path| {
                path.source_path == "docs/status/_generated/ignored.md"
                    && path.inclusion_decision == "excluded"
                    && path.exclusion_reason.contains("excluded_glob")
                    && path.file_hash.starts_with("sha256:")
            }),
            "generated status path should be logged as excluded"
        );
        Ok(())
    }

    #[test]
    fn source_scope_scan_skips_vendor_tree_before_matching() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        populate_source_scope_workspace(temp.path())?;
        write_sample_file(
            temp.path(),
            "vendor/fuser/src/lib.rs",
            "// TODO vendored dependency note should not enter project source scope\n",
        )?;

        let mut manifest = fixture_manifest();
        let tests = manifest
            .sources
            .iter_mut()
            .find(|source| source.source_family == "tests")
            .expect("tests source exists");
        tests.included_globs = vec!["**/*.rs".to_owned()];

        let report = scan_source_scope_manifest(
            &manifest,
            temp.path(),
            None,
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );
        assert!(report.valid, "scan should validate: {:?}", report.errors);
        let tests = report
            .scanned_sources
            .iter()
            .find(|source| source.source_family == "tests")
            .expect("tests source scanned");
        assert!(
            tests
                .matched_paths
                .iter()
                .all(|path| !path.source_path.starts_with("vendor/")),
            "vendor tree should be pruned before source matching"
        );
        Ok(())
    }

    #[test]
    fn source_scope_scan_skips_rch_worker_target_tree_before_matching() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        populate_source_scope_workspace(temp.path())?;
        write_sample_file(
            temp.path(),
            ".rch-target-ts2-job-123/crates/ffs-harness/src/lib.rs",
            "// TODO generated RCH target should not enter project source scope\n",
        )?;

        let mut manifest = fixture_manifest();
        let tests = manifest
            .sources
            .iter_mut()
            .find(|source| source.source_family == "tests")
            .expect("tests source exists");
        tests.included_globs = vec!["**/*.rs".to_owned()];

        let report = scan_source_scope_manifest(
            &manifest,
            temp.path(),
            None,
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );
        assert!(report.valid, "scan should validate: {:?}", report.errors);
        assert_eq!(report.workspace_file_source, "filesystem_fallback");
        let tests = report
            .scanned_sources
            .iter()
            .find(|source| source.source_family == "tests")
            .expect("tests source scanned");
        assert!(
            tests
                .matched_paths
                .iter()
                .all(|path| !path.source_path.starts_with(".rch-target-")),
            "RCH worker target tree should be pruned before source matching"
        );
        Ok(())
    }

    #[test]
    fn source_scope_scan_excludes_untracked_rch_worker_target_tree() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        populate_source_scope_workspace(temp.path())?;
        index_source_scope_workspace(temp.path())?;
        write_sample_file(
            temp.path(),
            ".rch-target-ts2-job-123/crates/ffs-harness/src/lib.rs",
            "// TODO generated RCH target should not enter project source scope\n",
        )?;

        let mut manifest = fixture_manifest();
        let tests = manifest
            .sources
            .iter_mut()
            .find(|source| source.source_family == "tests")
            .expect("tests source exists");
        tests.included_globs = vec!["**/*.rs".to_owned()];

        let report = scan_source_scope_manifest(
            &manifest,
            temp.path(),
            None,
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );
        assert!(report.valid, "scan should validate: {:?}", report.errors);
        assert_eq!(report.workspace_file_source, "git_ls_files");
        let tests = report
            .scanned_sources
            .iter()
            .find(|source| source.source_family == "tests")
            .expect("tests source scanned");
        assert!(
            tests
                .untracked_matched_paths
                .iter()
                .all(|path| !path.source_path.starts_with(".rch-target-")),
            "RCH worker target tree should be pruned before untracked source diagnostics"
        );
        assert!(
            report.scanned_sources.iter().all(|source| {
                source
                    .untracked_matched_paths
                    .iter()
                    .all(|path| !path.source_path.starts_with(".rch-target-"))
            }),
            "no source family should report untracked RCH target files"
        );
        Ok(())
    }

    #[test]
    fn source_scope_scan_reports_precise_removed_family() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        populate_source_scope_workspace(temp.path())?;
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "feature_parity_doc");
        let report = scan_source_scope_manifest(
            &manifest,
            temp.path(),
            None,
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `feature_parity_doc`"))
        );
        Ok(())
    }

    #[test]
    fn source_scope_scan_rejects_unmatched_required_source() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let report = scan_source_scope_manifest(
            &fixture_manifest(),
            temp.path(),
            None,
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("source `readme_status_docs` matched no files"))
        );
        Ok(())
    }
}
