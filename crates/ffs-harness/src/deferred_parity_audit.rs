#![forbid(unsafe_code)]

//! Closed-bead deferred parity audit for `bd-39lau`.
//!
//! This module keeps historical closure text from silently becoming public
//! readiness evidence. It scans tracker JSONL and public-status docs for
//! deferred, partial, parse-only, experimental, host-blocked, or stale evidence
//! language, then checks those findings against a machine-readable audit table.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub const AUDIT_RUN_ID: &str = "bd-39lau-deferred-parity-audit-v1";
const DEFAULT_REPORT: &str = include_str!("../../../docs/reports/DEFERRED_PARITY_AUDIT.md");
const REGISTRY_HEADING: &str = "## Deferred Closure Audit Registry";

const REQUIRED_HEADERS: [&str; 12] = [
    "Row",
    "Source bead",
    "Source status",
    "Matched phrase",
    "Gap class",
    "Docs/spec claim checked",
    "Release-gate effect",
    "Decision",
    "Linked follow-up or non-goal",
    "Required logs",
    "Required artifacts",
    "Reproduction command",
];

const GAP_CLASSES: [&str; 20] = [
    "validated",
    "implemented-unvalidated",
    "partial",
    "basic-coverage",
    "parse-only",
    "single-device-only",
    "experimental",
    "detection-only",
    "dry-run-only",
    "opt-in-mutating",
    "disabled",
    "unsupported",
    "deferred",
    "not-run",
    "host-blocked",
    "stale-evidence",
    "superseded",
    "explicit-non-goal",
    "security-refused",
    "non-authoritative-local-only",
];

const DECISIONS: [&str; 5] = [
    "active-follow-up",
    "docs-downgrade",
    "release-gate-downgrade",
    "explicit-non-goal",
    "validated-artifact",
];

const REQUIRED_LOG_TOKENS: [&str; 8] = [
    "audit_run_id",
    "source_bead_id",
    "source_status",
    "matched_vocabulary_rule",
    "docs_claim_checked",
    "release_gate_effect",
    "artifact_path",
    "reproduction_command",
];

const REQUIRED_ARTIFACT_TOKENS: [&str; 5] = [
    "report_json",
    "human_report",
    "source_bead_id",
    "docs_claim_checked",
    "output_report_path",
];

const HIGH_RISK_LABELS: [&str; 15] = [
    "multidevice",
    "send-receive",
    "casefold",
    "rw",
    "mount",
    "fuse",
    "repair",
    "writeback-cache",
    "xfstests",
    "performance",
    "proof",
    "release-gates",
    "safety",
    "security",
    "parity",
];

const VOCABULARY_RULES: [(&str, &str); 28] = [
    ("full export deferred", "deferred"),
    ("deferred", "deferred"),
    ("partial", "partial"),
    ("basic coverage", "basic-coverage"),
    ("parse-only", "parse-only"),
    ("parse only", "parse-only"),
    ("single-device", "single-device-only"),
    ("single device", "single-device-only"),
    ("experimental", "experimental"),
    ("detection-only", "detection-only"),
    ("detection only", "detection-only"),
    ("dry-run", "dry-run-only"),
    ("dry run", "dry-run-only"),
    ("opt-in mutating", "opt-in-mutating"),
    ("opt-in-only", "opt-in-mutating"),
    ("disabled", "disabled"),
    ("unsupported", "unsupported"),
    ("not run", "not-run"),
    ("not-run", "not-run"),
    ("host-blocked", "host-blocked"),
    ("blocked by host", "host-blocked"),
    ("stale", "stale-evidence"),
    ("superseded", "superseded"),
    ("non-goal", "explicit-non-goal"),
    ("security-refused", "security-refused"),
    ("non-authoritative", "non-authoritative-local-only"),
    ("local-only", "non-authoritative-local-only"),
    ("weak-coverage", "implemented-unvalidated"),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredParityAuditConfig {
    pub issues_jsonl: PathBuf,
    pub report_markdown: PathBuf,
    pub docs: Vec<PathBuf>,
}

impl Default for DeferredParityAuditConfig {
    fn default() -> Self {
        Self {
            issues_jsonl: PathBuf::from(".beads/issues.jsonl"),
            report_markdown: PathBuf::from("docs/reports/DEFERRED_PARITY_AUDIT.md"),
            docs: vec![
                PathBuf::from("README.md"),
                PathBuf::from("FEATURE_PARITY.md"),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredParityAuditReport {
    pub audit_run_id: String,
    pub source_issue_count: usize,
    pub detected_gap_count: usize,
    pub registry_row_count: usize,
    pub docs_claim_count: usize,
    pub findings: Vec<DeferredClosureFinding>,
    pub docs_claims: Vec<DocsClaimFinding>,
    pub registry_rows: Vec<DeferredParityAuditRow>,
    pub errors: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredClosureFinding {
    pub source_bead_id: String,
    pub title: String,
    pub labels: Vec<String>,
    pub gap_class: String,
    pub matched_phrase: String,
    pub matched_vocabulary_rule: String,
    pub close_reason_excerpt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsClaimFinding {
    pub source_path: String,
    pub section: String,
    pub matched_phrase: String,
    pub risk_surface: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredParityAuditRow {
    pub row_id: String,
    pub source_bead_id: String,
    pub source_status: String,
    pub matched_phrase: String,
    pub gap_class: String,
    pub docs_claim_checked: String,
    pub release_gate_effect: String,
    pub decision: String,
    pub linked_follow_up_or_non_goal: String,
    pub required_logs: String,
    pub required_artifacts: String,
    pub reproduction_command: String,
}

pub fn run_deferred_parity_audit(
    config: &DeferredParityAuditConfig,
) -> Result<DeferredParityAuditReport> {
    let issues_jsonl = fs::read_to_string(&config.issues_jsonl)
        .with_context(|| format!("failed to read {}", config.issues_jsonl.display()))?;
    let report_markdown = if config.report_markdown.exists() {
        fs::read_to_string(&config.report_markdown)
            .with_context(|| format!("failed to read {}", config.report_markdown.display()))?
    } else {
        DEFAULT_REPORT.to_owned()
    };
    let docs = read_docs(&config.docs)?;
    Ok(analyze_deferred_parity_audit(
        &issues_jsonl,
        &report_markdown,
        &docs,
    ))
}

#[must_use]
pub fn analyze_deferred_parity_audit(
    issues_jsonl: &str,
    report_markdown: &str,
    docs: &[(String, String)],
) -> DeferredParityAuditReport {
    let mut errors = Vec::new();
    let issue_statuses = issue_status_by_id(issues_jsonl, &mut errors);
    let findings = detect_deferred_closure_findings(issues_jsonl, &mut errors);
    let registry_rows = parse_registry_rows(report_markdown, &mut errors);
    validate_registry_rows(&registry_rows, &findings, &issue_statuses, &mut errors);
    let docs_claims = detect_docs_claims(docs);
    validate_docs_claims(&registry_rows, &docs_claims, &mut errors);

    DeferredParityAuditReport {
        audit_run_id: AUDIT_RUN_ID.to_owned(),
        source_issue_count: issues_jsonl.lines().filter(|line| !line.trim().is_empty()).count(),
        detected_gap_count: findings.len(),
        registry_row_count: registry_rows.len(),
        docs_claim_count: docs_claims.len(),
        findings,
        docs_claims,
        registry_rows,
        errors,
        reproduction_command:
            "ffs-harness validate-deferred-parity-audit --issues .beads/issues.jsonl --report docs/reports/DEFERRED_PARITY_AUDIT.md --doc README.md --doc FEATURE_PARITY.md".to_owned(),
    }
}

fn read_docs(paths: &[PathBuf]) -> Result<Vec<(String, String)>> {
    paths
        .iter()
        .map(|path| {
            fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))
                .map(|contents| (display_path(path), contents))
        })
        .collect()
}

fn detect_deferred_closure_findings(
    issues_jsonl: &str,
    errors: &mut Vec<String>,
) -> Vec<DeferredClosureFinding> {
    issues_jsonl
        .lines()
        .enumerate()
        .filter_map(|(line_no, line)| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let value = match serde_json::from_str::<Value>(line) {
                Ok(value) => value,
                Err(err) => {
                    errors.push(format!("invalid issue json at line {}: {err}", line_no + 1));
                    return None;
                }
            };
            finding_from_issue(&value)
        })
        .collect()
}

fn issue_status_by_id(issues_jsonl: &str, errors: &mut Vec<String>) -> BTreeMap<String, String> {
    let mut statuses = BTreeMap::new();
    for (line_no, line) in issues_jsonl.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value = match serde_json::from_str::<Value>(line) {
            Ok(value) => value,
            Err(err) => {
                errors.push(format!("invalid issue json at line {}: {err}", line_no + 1));
                continue;
            }
        };
        let id = string_field(&value, "id");
        let status = string_field(&value, "status");
        if !id.is_empty() && !status.is_empty() {
            statuses.insert(id, status);
        }
    }
    statuses
}

fn finding_from_issue(value: &Value) -> Option<DeferredClosureFinding> {
    if value.get("status").and_then(Value::as_str) != Some("closed") {
        return None;
    }

    let labels = labels_from_issue(value);
    let haystack = issue_haystack(value);
    let (matched_vocabulary_rule, gap_class) = classify_gap(&haystack)?;
    if !is_high_risk(&labels, &haystack, gap_class) {
        return None;
    }

    Some(DeferredClosureFinding {
        source_bead_id: string_field(value, "id"),
        title: string_field(value, "title"),
        labels,
        gap_class: gap_class.to_owned(),
        matched_phrase: matched_vocabulary_rule.to_owned(),
        matched_vocabulary_rule: matched_vocabulary_rule.to_owned(),
        close_reason_excerpt: excerpt(&string_field(value, "close_reason")),
    })
}

fn issue_haystack(value: &Value) -> String {
    let mut text = String::new();
    for field in [
        "title",
        "description",
        "design",
        "acceptance_criteria",
        "notes",
        "close_reason",
    ] {
        if let Some(raw) = value.get(field).and_then(Value::as_str) {
            text.push(' ');
            text.push_str(raw);
        }
    }
    text.to_ascii_lowercase()
}

fn classify_gap(haystack: &str) -> Option<(&'static str, &'static str)> {
    VOCABULARY_RULES
        .iter()
        .find(|(phrase, _)| haystack.contains(phrase))
        .copied()
}

fn is_high_risk(labels: &[String], haystack: &str, gap_class: &str) -> bool {
    gap_class != "validated"
        && (labels
            .iter()
            .any(|label| HIGH_RISK_LABELS.contains(&label.as_str()))
            || haystack.contains("readiness")
            || haystack.contains("feature_parity")
            || haystack.contains("proof bundle")
            || haystack.contains("release gate"))
}

fn labels_from_issue(value: &Value) -> Vec<String> {
    value
        .get("labels")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn parse_registry_rows(markdown: &str, errors: &mut Vec<String>) -> Vec<DeferredParityAuditRow> {
    let Some(table_lines) = registry_table_lines(markdown) else {
        errors.push(format!("missing registry heading `{REGISTRY_HEADING}`"));
        return Vec::new();
    };
    if table_lines.len() < 3 {
        errors.push("deferred parity registry must include header, separator, and rows".to_owned());
        return Vec::new();
    }

    let Some(header_line) = table_lines.first() else {
        errors.push("deferred parity registry must include a header row".to_owned());
        return Vec::new();
    };
    let header = split_table_row(header_line);
    if header != REQUIRED_HEADERS {
        errors.push(format!(
            "deferred parity registry header mismatch: expected {REQUIRED_HEADERS:?}, got {header:?}"
        ));
        return Vec::new();
    }

    table_lines
        .iter()
        .skip(2)
        .filter_map(|line| row_from_table_line(line, errors))
        .collect()
}

fn registry_table_lines(markdown: &str) -> Option<Vec<&str>> {
    let mut in_section = false;
    let mut lines = Vec::new();
    for line in markdown.lines() {
        if line.trim() == REGISTRY_HEADING {
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

fn row_from_table_line(line: &str, errors: &mut Vec<String>) -> Option<DeferredParityAuditRow> {
    let cells = split_table_row(line);
    if cells
        .iter()
        .all(|cell| cell.chars().all(|ch| ch == '-' || ch == ':'))
    {
        return None;
    }
    let [
        row_id,
        source_bead_id,
        source_status,
        matched_phrase,
        gap_class,
        docs_claim_checked,
        release_gate_effect,
        decision,
        linked_follow_up_or_non_goal,
        required_logs,
        required_artifacts,
        reproduction_command,
    ] = cells.as_slice()
    else {
        errors.push(format!(
            "deferred parity registry row has {} cells, expected {}: {line}",
            cells.len(),
            REQUIRED_HEADERS.len()
        ));
        return None;
    };
    Some(DeferredParityAuditRow {
        row_id: row_id.clone(),
        source_bead_id: source_bead_id.clone(),
        source_status: source_status.clone(),
        matched_phrase: matched_phrase.clone(),
        gap_class: gap_class.clone(),
        docs_claim_checked: docs_claim_checked.clone(),
        release_gate_effect: release_gate_effect.clone(),
        decision: decision.clone(),
        linked_follow_up_or_non_goal: linked_follow_up_or_non_goal.clone(),
        required_logs: required_logs.clone(),
        required_artifacts: required_artifacts.clone(),
        reproduction_command: reproduction_command.clone(),
    })
}

fn validate_registry_rows(
    rows: &[DeferredParityAuditRow],
    findings: &[DeferredClosureFinding],
    issue_status_by_id: &BTreeMap<String, String>,
    errors: &mut Vec<String>,
) {
    let mut seen = BTreeSet::new();
    let finding_by_id: BTreeMap<&str, &DeferredClosureFinding> = findings
        .iter()
        .map(|finding| (finding.source_bead_id.as_str(), finding))
        .collect();

    for row in rows {
        validate_row_shape(row, &mut seen, errors);
        validate_active_follow_up_status(row, issue_status_by_id, errors);
        if let Some(finding) = finding_by_id.get(row.source_bead_id.as_str())
            && row.gap_class != finding.gap_class
        {
            errors.push(format!(
                "row {} gap_class {} disagrees with detected {} for {}",
                row.row_id, row.gap_class, finding.gap_class, row.source_bead_id
            ));
        }
    }

    for required_id in ["bd-nzv3.24", "bd-nzv3.15", "bd-nzv3.21"] {
        if !rows.iter().any(|row| row.source_bead_id == required_id) {
            errors.push(format!(
                "registry must cover required historical deferred bead {required_id}"
            ));
        }
    }
}

fn validate_active_follow_up_status(
    row: &DeferredParityAuditRow,
    issue_status_by_id: &BTreeMap<String, String>,
    errors: &mut Vec<String>,
) {
    if row.decision != "active-follow-up" {
        return;
    }

    let linked_ids = linked_bead_ids(&row.linked_follow_up_or_non_goal);
    if linked_ids.is_empty() {
        errors.push(format!(
            "row {} active-follow-up must link at least one bead id",
            row.row_id
        ));
        return;
    }

    for linked_id in linked_ids {
        match issue_status_by_id.get(linked_id) {
            Some(status) if status == "open" || status == "in_progress" => {}
            Some(status) => errors.push(format!(
                "row {} active-follow-up {} is {status}; use validated-artifact, docs-downgrade, release-gate-downgrade, or explicit-non-goal instead of stale active ownership",
                row.row_id, linked_id
            )),
            None => errors.push(format!(
                "row {} active-follow-up {} is missing from tracker",
                row.row_id, linked_id
            )),
        }
    }
}

fn linked_bead_ids(value: &str) -> Vec<&str> {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' || ch == '_'))
        .filter(|part| part.starts_with("bd-"))
        .collect()
}

fn validate_row_shape(
    row: &DeferredParityAuditRow,
    seen: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !seen.insert(row.row_id.clone()) {
        errors.push(format!("duplicate audit row id {}", row.row_id));
    }
    if !row.row_id.starts_with('D') || row.row_id.len() < 2 {
        errors.push(format!("row id {} must start with D", row.row_id));
    }
    if !row.source_bead_id.starts_with("bd-") && !row.source_bead_id.starts_with("docs:") {
        errors.push(format!(
            "row {} source bead must be bd-* or docs:*",
            row.row_id
        ));
    }
    if !GAP_CLASSES.contains(&row.gap_class.as_str()) {
        errors.push(format!(
            "row {} invalid gap class {}",
            row.row_id, row.gap_class
        ));
    }
    if !DECISIONS.contains(&row.decision.as_str()) {
        errors.push(format!(
            "row {} invalid decision {}",
            row.row_id, row.decision
        ));
    }
    if !row.linked_follow_up_or_non_goal.contains("bd-")
        && !row.linked_follow_up_or_non_goal.contains("non-goal")
    {
        errors.push(format!(
            "row {} needs follow-up bead or explicit non-goal",
            row.row_id
        ));
    }
    validate_tokens(
        &row.required_logs,
        &REQUIRED_LOG_TOKENS,
        "log",
        &row.row_id,
        errors,
    );
    validate_tokens(
        &row.required_artifacts,
        &REQUIRED_ARTIFACT_TOKENS,
        "artifact",
        &row.row_id,
        errors,
    );
    if !row
        .reproduction_command
        .contains("ffs-harness validate-deferred-parity-audit")
    {
        errors.push(format!("row {} missing reproduction command", row.row_id));
    }
}

fn validate_tokens(
    value: &str,
    required: &[&str],
    label: &str,
    row_id: &str,
    errors: &mut Vec<String>,
) {
    for token in required {
        if !value.contains(token) {
            errors.push(format!(
                "row {row_id} missing required {label} token {token}"
            ));
        }
    }
}

fn detect_docs_claims(docs: &[(String, String)]) -> Vec<DocsClaimFinding> {
    let mut claims = Vec::new();
    for (path, contents) in docs {
        for (line_index, line) in contents.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            let strong_claim = lower.contains("100%")
                || lower.contains("fully tracked")
                || lower.contains("full tracked")
                || lower.contains("tracked v1 parity");
            let risky_surface = lower.contains("parity")
                || lower.contains("readiness")
                || lower.contains("mount")
                || lower.contains("repair")
                || lower.contains("writeback");
            if strong_claim && risky_surface {
                claims.push(DocsClaimFinding {
                    source_path: path.clone(),
                    section: format!("line {}", line_index + 1),
                    matched_phrase: excerpt(line),
                    risk_surface: "flat parity or readiness wording".to_owned(),
                });
            }
        }
    }
    claims
}

fn validate_docs_claims(
    rows: &[DeferredParityAuditRow],
    claims: &[DocsClaimFinding],
    errors: &mut Vec<String>,
) {
    if claims.is_empty() {
        errors.push("audit must observe at least one public docs/status claim".to_owned());
    }

    for claim in claims {
        let covered = rows.iter().any(|row| {
            row.source_bead_id.starts_with("docs:")
                && row.docs_claim_checked.contains(&claim.source_path)
        });
        if !covered {
            errors.push(format!(
                "docs claim {} {} lacks a registry row",
                claim.source_path, claim.section
            ));
        }
    }
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

fn string_field(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn excerpt(value: &str) -> String {
    const MAX_LEN: usize = 180;
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.len() <= MAX_LEN {
        normalized
    } else {
        format!(
            "{}...",
            normalized.chars().take(MAX_LEN).collect::<String>()
        )
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub fn fail_on_audit_errors(report: &DeferredParityAuditReport) -> Result<()> {
    if report.errors.is_empty() {
        Ok(())
    } else {
        bail!(
            "deferred parity audit failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIRED_LOGS: &str = "audit_run_id,source_bead_id,source_status,matched_vocabulary_rule,docs_claim_checked,release_gate_effect,artifact_path,reproduction_command";
    const REQUIRED_ARTIFACTS: &str =
        "report_json,human_report,source_bead_id,docs_claim_checked,output_report_path";
    const REPRO: &str = "ffs-harness validate-deferred-parity-audit --issues .beads/issues.jsonl --report docs/reports/DEFERRED_PARITY_AUDIT.md --doc README.md --doc FEATURE_PARITY.md";

    fn fixture_issues() -> String {
        [
            r#"{"id":"bd-nzv3.24","title":"btrfs multi-device RAID corpus","status":"closed","labels":["btrfs","multidevice","raid"],"close_reason":"Multi-image layout corpus deferred — single-device tests cover the read path."}"#,
            r#"{"id":"bd-nzv3.15","title":"btrfs send/receive export","status":"closed","labels":["btrfs","send-receive"],"close_reason":"Send stream parse implemented. Full export deferred."}"#,
            r#"{"id":"bd-nzv3.21","title":"ext4 casefold corpus","status":"closed","labels":["casefold","ext4"],"close_reason":"Casefold adversarial fixtures: basic coverage exists."}"#,
            r#"{"id":"bd-ch373","title":"btrfs multi-device follow-up","status":"open","labels":["btrfs","multidevice"]}"#,
            r#"{"id":"bd-naww5","title":"btrfs send/receive follow-up","status":"open","labels":["btrfs","send-receive"]}"#,
            r#"{"id":"bd-9er6s","title":"ext4 casefold follow-up","status":"in_progress","labels":["casefold","ext4"]}"#,
            r#"{"id":"bd-mpcse","title":"tiered support-state accounting","status":"open","labels":["parity","docs"]}"#,
            r#"{"id":"bd-ok","title":"validated thing","status":"closed","labels":["docs"],"close_reason":"Validated with fresh artifacts."}"#,
        ]
        .join("\n")
    }

    fn fixture_report() -> String {
        format!(
            r"
# Deferred Parity Audit

## Deferred Closure Audit Registry

| Row | Source bead | Source status | Matched phrase | Gap class | Docs/spec claim checked | Release-gate effect | Decision | Linked follow-up or non-goal | Required logs | Required artifacts | Reproduction command |
|-----|-------------|---------------|----------------|-----------|-------------------------|---------------------|----------|------------------------------|---------------|--------------------|----------------------|
| D1 | bd-nzv3.24 | closed | deferred | deferred | README.md parity wording | downgrade multidevice readiness | active-follow-up | bd-ch373 | {REQUIRED_LOGS} | {REQUIRED_ARTIFACTS} | {REPRO} |
| D2 | bd-nzv3.15 | closed | full export deferred | deferred | FEATURE_PARITY.md send/receive wording | downgrade send/receive readiness | active-follow-up | bd-naww5 | {REQUIRED_LOGS} | {REQUIRED_ARTIFACTS} | {REPRO} |
| D3 | bd-nzv3.21 | closed | basic coverage | basic-coverage | README.md casefold wording | downgrade casefold readiness | active-follow-up | bd-9er6s | {REQUIRED_LOGS} | {REQUIRED_ARTIFACTS} | {REPRO} |
| D4 | docs:flat-parity | current | 100% | implemented-unvalidated | README.md | fail if flat parity feeds readiness without tiered accounting | active-follow-up | bd-mpcse | {REQUIRED_LOGS} | {REQUIRED_ARTIFACTS} | {REPRO} |
"
        )
    }

    #[test]
    fn classifies_required_deferred_closure_vocabularies() {
        let report = analyze_deferred_parity_audit(
            &fixture_issues(),
            &fixture_report(),
            &[("README.md".to_owned(), "Tracked V1 parity 100%".to_owned())],
        );
        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );
        let classes = report
            .findings
            .iter()
            .map(|finding| (finding.source_bead_id.as_str(), finding.gap_class.as_str()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(classes.get("bd-nzv3.24"), Some(&"deferred"));
        assert_eq!(classes.get("bd-nzv3.15"), Some(&"deferred"));
        assert_eq!(classes.get("bd-nzv3.21"), Some(&"basic-coverage"));
    }

    #[test]
    fn exposes_full_gap_vocabulary_for_schema_tests() -> Result<()> {
        let json = serde_json::to_string_pretty(&GAP_CLASSES)?;
        insta::assert_snapshot!("gap_classes_json_shape", json);
        let parsed: Vec<String> = serde_json::from_str(&json)?;
        let expected = GAP_CLASSES
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(parsed, expected);

        assert!(GAP_CLASSES.contains(&"validated"));
        assert!(GAP_CLASSES.contains(&"implemented-unvalidated"));
        assert!(GAP_CLASSES.contains(&"partial"));
        assert!(GAP_CLASSES.contains(&"basic-coverage"));
        assert!(GAP_CLASSES.contains(&"parse-only"));
        assert!(GAP_CLASSES.contains(&"single-device-only"));
        assert!(GAP_CLASSES.contains(&"experimental"));
        assert!(GAP_CLASSES.contains(&"detection-only"));
        assert!(GAP_CLASSES.contains(&"dry-run-only"));
        assert!(GAP_CLASSES.contains(&"opt-in-mutating"));
        assert!(GAP_CLASSES.contains(&"disabled"));
        assert!(GAP_CLASSES.contains(&"unsupported"));
        assert!(GAP_CLASSES.contains(&"deferred"));
        assert!(GAP_CLASSES.contains(&"not-run"));
        assert!(GAP_CLASSES.contains(&"host-blocked"));
        assert!(GAP_CLASSES.contains(&"stale-evidence"));
        assert!(GAP_CLASSES.contains(&"superseded"));
        assert!(GAP_CLASSES.contains(&"explicit-non-goal"));
        assert!(GAP_CLASSES.contains(&"security-refused"));
        assert!(GAP_CLASSES.contains(&"non-authoritative-local-only"));
        Ok(())
    }

    #[test]
    fn deferred_parity_audit_report_json_shape() -> Result<()> {
        let report = analyze_deferred_parity_audit(
            &fixture_issues(),
            &fixture_report(),
            &[("README.md".to_owned(), "Tracked V1 parity 100%".to_owned())],
        );
        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );

        let shape = serde_json::json!({
            "audit_run_id": &report.audit_run_id,
            "counts": {
                "source_issue_count": report.source_issue_count,
                "detected_gap_count": report.detected_gap_count,
                "registry_row_count": report.registry_row_count,
                "docs_claim_count": report.docs_claim_count,
            },
            "findings": report
                .findings
                .iter()
                .map(|finding| {
                    serde_json::json!({
                        "source_bead_id": finding.source_bead_id.as_str(),
                        "gap_class": finding.gap_class.as_str(),
                        "matched_vocabulary_rule": finding.matched_vocabulary_rule.as_str(),
                        "labels": &finding.labels,
                    })
                })
                .collect::<Vec<_>>(),
            "docs_claims": report
                .docs_claims
                .iter()
                .map(|claim| {
                    serde_json::json!({
                        "source_path": claim.source_path.as_str(),
                        "section": claim.section.as_str(),
                        "risk_surface": claim.risk_surface.as_str(),
                    })
                })
                .collect::<Vec<_>>(),
            "registry_rows": report
                .registry_rows
                .iter()
                .map(|row| {
                    serde_json::json!({
                        "row_id": row.row_id.as_str(),
                        "source_bead_id": row.source_bead_id.as_str(),
                        "gap_class": row.gap_class.as_str(),
                        "decision": row.decision.as_str(),
                        "linked_follow_up_or_non_goal": row
                            .linked_follow_up_or_non_goal
                            .as_str(),
                    })
                })
                .collect::<Vec<_>>(),
            "errors": &report.errors,
            "reproduction_command": &report.reproduction_command,
        });
        let json = serde_json::to_string_pretty(&shape)?;
        insta::assert_snapshot!("deferred_parity_audit_report_json_shape", json);

        let full_json = serde_json::to_string_pretty(&report)?;
        let roundtrip: DeferredParityAuditReport = serde_json::from_str(&full_json)?;
        assert_eq!(roundtrip, report);
        Ok(())
    }

    #[test]
    fn missing_required_historical_bead_fails() {
        let report = analyze_deferred_parity_audit(
            &fixture_issues(),
            &fixture_report().replace("bd-nzv3.24", "bd-other"),
            &[("README.md".to_owned(), "Tracked V1 parity 100%".to_owned())],
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("bd-nzv3.24"))
        );
    }

    #[test]
    fn missing_log_or_artifact_tokens_fail() {
        let report = analyze_deferred_parity_audit(
            &fixture_issues(),
            &fixture_report().replace("audit_run_id,", ""),
            &[("README.md".to_owned(), "Tracked V1 parity 100%".to_owned())],
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("audit_run_id"))
        );
    }

    #[test]
    fn active_follow_up_with_closed_tracker_row_fails() {
        let issues = fixture_issues().replace(
            r#""id":"bd-ch373","title":"btrfs multi-device follow-up","status":"open""#,
            r#""id":"bd-ch373","title":"btrfs multi-device follow-up","status":"closed""#,
        );
        let report = analyze_deferred_parity_audit(
            &issues,
            &fixture_report(),
            &[("README.md".to_owned(), "Tracked V1 parity 100%".to_owned())],
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("row D1 active-follow-up bd-ch373 is closed")),
            "expected stale active-follow-up error, got {:?}",
            report.errors
        );
    }

    #[test]
    fn validated_artifact_accepts_closed_tracker_row() {
        let issues = fixture_issues().replace(
            r#""id":"bd-ch373","title":"btrfs multi-device follow-up","status":"open""#,
            r#""id":"bd-ch373","title":"btrfs multi-device follow-up","status":"closed""#,
        );
        let report_markdown = fixture_report().replace(
            "active-follow-up | bd-ch373",
            "validated-artifact | bd-ch373",
        );
        let report = analyze_deferred_parity_audit(
            &issues,
            &report_markdown,
            &[("README.md".to_owned(), "Tracked V1 parity 100%".to_owned())],
        );
        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );
    }

    #[test]
    fn docs_claim_without_registry_row_fails() {
        let report = analyze_deferred_parity_audit(
            &fixture_issues(),
            &fixture_report().replace("docs:flat-parity", "docs:other"),
            &[(
                "FEATURE_PARITY.md".to_owned(),
                "tracked parity is 100%".to_owned(),
            )],
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("docs claim"))
        );
    }
}
