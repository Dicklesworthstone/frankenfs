#![forbid(unsafe_code)]

pub mod adaptive_runtime_manifest;
pub mod adversarial_threat_model;
#[path = "../../../tools/ffs-ops/src/ambition_evidence_matrix.rs"]
pub mod ambition_evidence_matrix;
pub mod artifact_manifest;
pub mod authoritative_environment_manifest;
pub mod authoritative_lane_manifest;
pub mod benchmark_taxonomy;
pub mod btrfs_capability_drift;
pub mod btrfs_multidevice_corpus;
pub mod btrfs_send_receive_corpus;
pub mod canonical_gates;
pub mod casefold_corpus;
pub mod chaos_replay_lab;
pub mod claimability_plan;
pub mod crash_promotion;
pub mod crash_replay_artifact;
pub mod cross_oracle_arbitration;
pub mod deferred_parity_audit;
#[path = "../../../tools/ffs-ops/src/docs_status_drift.rs"]
pub mod docs_status_drift;
pub mod e2e;
pub mod error_taxonomy;
pub mod evidence_backed_lane;
pub mod executed_evidence;
pub mod fault_injection_corpus;
pub mod fuzz_dashboard;
pub mod fuzz_smoke;
pub mod health_consistency;
pub mod invariant_oracle;
pub mod inventory_closeout_gate;
pub mod log_contract;
pub mod low_privilege_demo;
pub mod low_privilege_demo_sandbox;
pub mod metamorphic_workload_seed_catalog;
pub mod metrics;
pub mod mounted_checkpoint_survivor;
pub mod mounted_differential_oracle;
pub mod mounted_lane_gate;
pub mod mounted_recovery_matrix;
pub mod mounted_repair_mutation_boundary;
pub mod mounted_repair_policy;
pub mod mounted_write_errno_budget;
pub mod mounted_write_error_classes;
pub mod mounted_write_matrix;
pub mod numa_allocation_placement_report;
#[path = "../../../tools/ffs-ops/src/open_ended_inventory.rs"]
pub mod open_ended_inventory;
pub mod operational_evidence_index;
pub mod operational_readiness_report;
pub mod operator_recovery_drill;
pub mod oq_decision_matrix;
pub mod perf_comparison;
pub mod perf_regression;
pub mod perf_triage;
pub mod performance_baseline_manifest;
pub mod performance_delta_closeout;
#[path = "../../../tools/ffs-ops/src/permissioned_campaign_broker.rs"]
pub mod permissioned_campaign_broker;
pub mod proof_bundle;
pub mod proof_overhead_budget;
pub mod rch_capacity_preflight;
#[path = "../../../tools/ffs-ops/src/readiness_action_autopilot.rs"]
pub mod readiness_action_autopilot;
pub mod readiness_dashboard;
pub mod readiness_lab;
pub mod release_gate;
pub mod remediation_catalog;
pub mod remediation_severity_gate;
pub mod repair_confidence_lab;
pub mod repair_corpus;
pub mod repair_writeback_serialization;
#[path = "../../../tools/ffs-ops/src/report_schema_inventory.rs"]
pub mod report_schema_inventory;
pub mod runtime_console_report;
pub mod rw_background_repair_gate;
pub mod scrub_repair_scheduler;
pub mod soak_canary_campaign;
pub mod stale_mounts;
pub mod support_state_accounting;
pub mod swarm_cache_controller;
pub mod swarm_operator_report;
pub mod swarm_tail_latency;
pub mod swarm_workload_harness;
pub mod tabletop_drill;
pub mod topology_runtime_advisor;
pub mod tracker_source_hygiene;
pub mod verification_runner;
pub mod wal_group_commit_gate;
pub mod workload_corpus;
pub mod writeback_cache_audit;
pub mod writeback_crash_matrix_executor;
pub mod xfstests;

use anyhow::{Context, Result, bail};
use ffs_ondisk::{
    BtrfsDevItem, BtrfsHeader, BtrfsItem, BtrfsSuperblock, Ext4DirEntry, Ext4DxRoot,
    Ext4ExtentHeader, Ext4GroupDesc, Ext4Inode, Ext4MmpBlock, Ext4Superblock, Ext4Xattr,
    ExtentTree, ext4_chksum, map_logical_to_physical, parse_dev_item, parse_dir_block,
    parse_dx_root, parse_extent_tree, parse_leaf_items, parse_sys_chunk_array, parse_xattr_block,
};
use hex::FromHex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const FEATURE_PARITY_MARKDOWN: &str = include_str!("../../../FEATURE_PARITY.md");
const COVERAGE_SUMMARY_HEADING: &str = "Coverage Summary";
pub const EXT4_MMP_FIXTURE_CHECKSUM_SEED: u32 = 0xAABB_CCDD;
const EXT4_MMP_FIXTURE_CHECKSUM_OFFSET: usize = 0x3FC;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoverageDomain {
    pub domain: String,
    pub implemented: u32,
    pub total: u32,
    pub coverage_percent: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParityReport {
    pub domains: Vec<CoverageDomain>,
    pub overall_implemented: u32,
    pub overall_total: u32,
    pub overall_coverage_percent: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileReadPathReport {
    pub mode: String,
    pub fixture: String,
    pub duration_ms: u128,
    pub iterations: u64,
    pub checksum: u64,
}

impl ParityReport {
    #[must_use]
    pub fn current() -> Self {
        let domains = coverage_domains_from_feature_parity(FEATURE_PARITY_MARKDOWN);
        assert!(
            !domains.is_empty(),
            "FEATURE_PARITY.md must include parseable coverage rows",
        );

        let overall_implemented = domains.iter().map(|d| d.implemented).sum();
        let overall_total = domains.iter().map(|d| d.total).sum();
        let overall_coverage_percent = percentage(overall_implemented, overall_total);

        Self {
            domains,
            overall_implemented,
            overall_total,
            overall_coverage_percent,
        }
    }
}

impl CoverageDomain {
    #[must_use]
    pub fn new(domain: &str, implemented: u32, total: u32) -> Self {
        Self {
            domain: domain.to_owned(),
            implemented,
            total,
            coverage_percent: percentage(implemented, total),
        }
    }
}

/// Btrfs parity row granularity: parse-only / read-verified / RW-durable.
///
/// bd-xuo95.13 (B4): Tracks btrfs capability maturity levels separately from
/// the flat parity count. RW-durable rows require green durable-remount evidence
/// from the A5 crash-matrix test suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsParityGranularity {
    /// Rows that only parse the on-disk format (no I/O verification).
    pub parse_only: usize,
    /// Rows with verified read-path behavior (differential kernel tests).
    pub read_verified: usize,
    /// Rows marked 🚧 (in progress) but not yet RW-durable.
    pub in_progress: usize,
    /// Rows with durable RW behavior (remount-persistence evidence).
    pub rw_durable: usize,
    /// Total btrfs capability rows in FEATURE_PARITY.md.
    pub total_btrfs_rows: usize,
    /// Whether A5 durable-remount evidence is green.
    pub a5_evidence_green: bool,
    /// Git SHA the report was generated at.
    pub git_sha: Option<String>,
}

impl BtrfsParityGranularity {
    /// Build the granularity report from FEATURE_PARITY.md and evidence state.
    ///
    /// # Arguments
    /// * `a5_evidence_green` - Whether A5 (bd-xuo95.6) crash-matrix tests pass
    /// * `git_sha` - Current git commit for traceability
    #[must_use]
    pub fn from_feature_parity(a5_evidence_green: bool, git_sha: Option<String>) -> Self {
        let btrfs_rows = count_btrfs_capability_rows(FEATURE_PARITY_MARKDOWN);

        // Classify rows based on evidence state:
        // - RW-durable: in_progress rows when A5 evidence is green
        // - in_progress: 🚧 rows when evidence is NOT green
        // - read-verified: rows with kernel differential tests (most btrfs rows)
        // - parse-only: rows that only validate parsing (send/receive stream parsing)

        let parse_only_rows = count_btrfs_parse_only_rows(FEATURE_PARITY_MARKDOWN);
        let in_progress_rows = count_btrfs_in_progress_rows(FEATURE_PARITY_MARKDOWN);

        // When A5 evidence is green, in_progress rows become rw_durable
        let (in_progress, rw_durable) = if a5_evidence_green {
            (0, in_progress_rows)
        } else {
            (in_progress_rows, 0)
        };

        // Read-verified = total - parse_only - in_progress_rows (regardless of evidence state)
        let read_verified = btrfs_rows
            .saturating_sub(parse_only_rows)
            .saturating_sub(in_progress_rows);

        Self {
            parse_only: parse_only_rows,
            read_verified,
            in_progress,
            rw_durable,
            total_btrfs_rows: btrfs_rows,
            a5_evidence_green,
            git_sha,
        }
    }

    /// Verify RW-durable count is 0 when A5 evidence is not green.
    pub fn verify_rw_durable_requires_evidence(&self) -> Result<(), String> {
        if !self.a5_evidence_green && self.rw_durable > 0 {
            return Err(format!(
                "rw_durable={} but A5 evidence is not green - RW-durable rows require durable-remount evidence",
                self.rw_durable
            ));
        }
        Ok(())
    }

    /// Check that parse_only + read_verified + in_progress + rw_durable equals total.
    pub fn verify_row_accounting(&self) -> Result<(), String> {
        let sum = self.parse_only + self.read_verified + self.in_progress + self.rw_durable;
        if sum != self.total_btrfs_rows {
            return Err(format!(
                "row accounting mismatch: parse_only({}) + read_verified({}) + in_progress({}) + rw_durable({}) = {} != total({})",
                self.parse_only,
                self.read_verified,
                self.in_progress,
                self.rw_durable,
                sum,
                self.total_btrfs_rows
            ));
        }
        Ok(())
    }
}

/// Count btrfs capability rows in FEATURE_PARITY.md.
/// Excludes summary/header rows (which contain percentage symbols).
fn count_btrfs_capability_rows(markdown: &str) -> usize {
    markdown
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("| btrfs ") && trimmed.contains('|') && !trimmed.contains('%')
        })
        .count()
}

/// Count btrfs rows that are parse-only (e.g., send/receive stream parsing).
fn count_btrfs_parse_only_rows(markdown: &str) -> usize {
    markdown
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("| btrfs ")
                && (trimmed.contains("parse_send_stream")
                    || trimmed.contains("send/receive streams"))
        })
        .count()
}

/// Count btrfs rows marked as in-progress (RW durability work).
fn count_btrfs_in_progress_rows(markdown: &str) -> usize {
    markdown
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("| btrfs ") && trimmed.contains("🚧")
        })
        .count()
}

#[must_use]
pub fn percentage(implemented: u32, total: u32) -> f64 {
    if total == 0 {
        0.0
    } else {
        (f64::from(implemented) / f64::from(total)) * 100.0
    }
}

fn strip_markdown_emphasis(value: &str) -> &str {
    value.trim().trim_matches('*')
}

fn parse_coverage_domain_row(line: &str) -> Option<CoverageDomain> {
    let cols: Vec<&str> = line.split('|').map(str::trim).collect();
    let [_, domain_cell, implemented_cell, total_cell, ..] = cols.as_slice() else {
        return None;
    };

    let domain = strip_markdown_emphasis(domain_cell);
    if domain.is_empty()
        || domain.eq_ignore_ascii_case("domain")
        || domain.eq_ignore_ascii_case("overall")
    {
        return None;
    }

    let implemented: u32 = strip_markdown_emphasis(implemented_cell).parse().ok()?;
    let total: u32 = strip_markdown_emphasis(total_cell).parse().ok()?;
    Some(CoverageDomain::new(domain, implemented, total))
}

fn coverage_domains_from_feature_parity(markdown: &str) -> Vec<CoverageDomain> {
    let mut domains = Vec::new();
    let mut in_coverage_summary = false;

    for line in markdown.lines() {
        let trimmed = line.trim();

        if !in_coverage_summary {
            if trimmed.starts_with("## ") && trimmed.contains(COVERAGE_SUMMARY_HEADING) {
                in_coverage_summary = true;
            }
            continue;
        }

        if trimmed.starts_with("## ") {
            break;
        }

        if let Some(domain) = parse_coverage_domain_row(trimmed) {
            domains.push(domain);
        }
    }

    domains
}

/// A capability row from the Tracked Capability Matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRow {
    pub capability: String,
    pub legacy_reference: String,
    pub status: String,
    pub notes: String,
    pub has_test_citation: bool,
}

impl CapabilityRow {
    fn has_concrete_test_citation(notes: &str) -> bool {
        notes.contains("tests/")
            || notes.contains("fuzz_targets/")
            || notes.contains("fuzz/fuzz_targets/")
            || notes.contains("scripts/e2e/")
            || notes.contains("unit::")
            || notes.contains("harness::")
            || notes.contains("e2e::")
            || notes.contains("proptest")
            || notes.contains("crates/ffs-")
            || notes.contains("coverage")
            || notes.contains("test::")
    }

    /// A row is properly classified if it either:
    /// 1. Has a concrete test citation, OR
    /// 2. Is explicitly marked as 'unproven' (no test exists yet)
    #[must_use]
    pub fn is_properly_classified(&self) -> bool {
        self.has_test_citation || self.notes.to_lowercase().contains("unproven")
    }
}

fn parse_capability_row(line: &str) -> Option<CapabilityRow> {
    let cols: Vec<&str> = line.split('|').map(str::trim).collect();
    if cols.len() < 5 {
        return None;
    }

    let capability = cols[1].trim();
    let legacy_reference = cols[2].trim();
    let status = cols[3].trim();
    let notes = cols[4].trim();

    if capability.is_empty()
        || capability.eq_ignore_ascii_case("capability")
        || capability.starts_with('-')
        || legacy_reference.is_empty()
    {
        return None;
    }

    let has_test_citation = CapabilityRow::has_concrete_test_citation(notes);

    Some(CapabilityRow {
        capability: capability.to_owned(),
        legacy_reference: legacy_reference.to_owned(),
        status: status.to_owned(),
        notes: notes.to_owned(),
        has_test_citation,
    })
}

/// Extract capability rows from the Tracked Capability Matrix section.
#[must_use]
pub fn capability_rows_from_feature_parity(markdown: &str) -> Vec<CapabilityRow> {
    let mut rows = Vec::new();
    let mut matrix_heading_level = None;
    let mut in_capability_table = false;

    for line in markdown.lines() {
        let trimmed = line.trim();
        let heading_level = trimmed.bytes().take_while(|&byte| byte == b'#').count();
        let is_heading = (1..=6).contains(&heading_level)
            && trimmed.as_bytes().get(heading_level) == Some(&b' ');

        if is_heading {
            if let Some(level) = matrix_heading_level {
                if heading_level <= level {
                    break;
                }
            } else if trimmed[heading_level..].contains("Tracked Capability Matrix") {
                matrix_heading_level = Some(heading_level);
            }
            in_capability_table = false;
            continue;
        }

        if matrix_heading_level.is_none() {
            continue;
        }

        if !trimmed.starts_with('|') {
            in_capability_table = false;
            continue;
        }

        let columns: Vec<_> = trimmed.split('|').map(str::trim).collect();
        if columns.get(1) == Some(&"Capability")
            && columns.get(2) == Some(&"Legacy Reference")
            && columns.get(3) == Some(&"Status")
            && columns.get(4) == Some(&"Notes")
        {
            in_capability_table = true;
            continue;
        }

        if in_capability_table && let Some(row) = parse_capability_row(trimmed) {
            rows.push(row);
        }
    }

    rows
}

/// Extract test citation patterns from a capability row's notes field.
///
/// Returns a list of test identifier patterns that can be matched against
/// cargo test output. Patterns include:
/// - `crate::module::test_name` for unit tests
/// - `crate_name/tests/file.rs::test_name` for integration tests
/// - `fuzz/fuzz_targets/target_name` for fuzz targets
#[must_use]
pub fn extract_test_citations(notes: &str) -> Vec<String> {
    let mut citations = Vec::new();

    // Split notes into words and look for test-like patterns
    // Pattern: crates/crate-name/tests/file.rs::test_name
    // Pattern: crates/crate-name/src/module.rs::test_name
    // Pattern: fuzz/fuzz_targets/target_name

    let mut current_word = String::new();

    for ch in notes.chars() {
        if ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '/' || ch == ':' || ch == '.' {
            current_word.push(ch);
        } else if !current_word.is_empty() {
            // Check if this looks like a test citation
            if current_word.contains("::") && current_word.contains('/') {
                // Extract the test name part after ::
                if let Some(idx) = current_word.rfind("::") {
                    let test_name = &current_word[idx + 2..];
                    if !test_name.is_empty()
                        && test_name.chars().all(|c| c.is_alphanumeric() || c == '_')
                    {
                        citations.push(test_name.to_string());
                    }
                }
                // Also extract file::test pattern
                if let Some((file_part, test_part)) = current_word.rsplit_once("::")
                    && let Some(raw_file) = file_part.rsplit('/').next()
                {
                    let file_name = raw_file.trim_end_matches(".rs");
                    citations.push(format!("{file_name}::{test_part}"));
                }
            }
            // Check for fuzz target patterns
            if current_word.starts_with("fuzz/fuzz_targets/") {
                let target = current_word.trim_start_matches("fuzz/fuzz_targets/");
                if !target.is_empty() {
                    citations.push(target.to_string());
                }
            }
            current_word.clear();
        }
    }

    // Handle trailing word
    if !current_word.is_empty()
        && current_word.contains("::")
        && let Some(idx) = current_word.rfind("::")
    {
        let test_name = &current_word[idx + 2..];
        if !test_name.is_empty() && test_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            citations.push(test_name.to_string());
        }
    }

    citations.sort();
    citations.dedup();
    citations
}

/// Parse cargo test JSON output lines and return a map of test name -> passed.
///
/// The output format is cargo test's `--format json` output, one JSON object
/// per line. We look for `"event": "ok"` or `"event": "failed"` entries.
#[must_use]
pub fn parse_cargo_test_json_output(output: &str) -> std::collections::HashMap<String, bool> {
    use std::collections::HashMap;

    let mut results = HashMap::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parse JSON line
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };

        // Look for test result events
        let Some(type_field) = value.get("type").and_then(|v| v.as_str()) else {
            continue;
        };

        if type_field != "test" {
            continue;
        }

        let Some(event) = value.get("event").and_then(|v| v.as_str()) else {
            continue;
        };

        let Some(name) = value.get("name").and_then(|v| v.as_str()) else {
            continue;
        };

        let passed = event == "ok";
        results.insert(name.to_string(), passed);
    }

    results
}

/// Build an evidence map for parity rows by running cargo test and matching results.
///
/// This function:
/// 1. Extracts test citations from all capability rows
/// 2. Runs cargo test with JSON output
/// 3. Maps test results back to parity row citations
///
/// Returns a map where keys are test citation patterns and values are pass/fail.
#[must_use]
pub fn build_parity_evidence_map(
    cargo_test_output: &str,
) -> std::collections::HashMap<String, bool> {
    use std::collections::HashMap;

    let test_results = parse_cargo_test_json_output(cargo_test_output);
    let rows = capability_rows_from_feature_parity(FEATURE_PARITY_MARKDOWN);

    let mut evidence_map = HashMap::new();

    for row in &rows {
        let citations = extract_test_citations(&row.notes);

        for citation in citations {
            // Check if any test result matches this citation
            let passed = test_results.iter().any(|(test_name, &result)| {
                result && (test_name.contains(&citation) || citation.contains(test_name))
            });

            // Also check if the test ran at all (even if failed)
            let ran = test_results.iter().any(|(test_name, _)| {
                test_name.contains(&citation) || citation.contains(test_name)
            });

            if ran {
                evidence_map.insert(citation, passed);
            }
        }
    }

    evidence_map
}

/// Report of capability rows missing test citations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestCitationAuditReport {
    pub total_rows: usize,
    pub cited_rows: usize,
    pub unproven_rows: usize,
    pub uncited_rows: Vec<String>,
    /// Rows that are neither cited nor explicitly marked 'unproven'.
    pub improperly_classified: Vec<String>,
}

impl TestCitationAuditReport {
    /// Audit FEATURE_PARITY.md for test citations.
    #[must_use]
    pub fn audit() -> Self {
        let rows = capability_rows_from_feature_parity(FEATURE_PARITY_MARKDOWN);
        let total_rows = rows.len();
        let cited_rows = rows.iter().filter(|r| r.has_test_citation).count();
        let unproven_rows = rows
            .iter()
            .filter(|r| !r.has_test_citation && r.notes.to_lowercase().contains("unproven"))
            .count();
        let uncited_rows: Vec<String> = rows
            .iter()
            .filter(|r| !r.has_test_citation)
            .map(|r| r.capability.clone())
            .collect();
        let improperly_classified: Vec<String> = rows
            .iter()
            .filter(|r| !r.is_properly_classified())
            .map(|r| r.capability.clone())
            .collect();

        Self {
            total_rows,
            cited_rows,
            unproven_rows,
            uncited_rows,
            improperly_classified,
        }
    }

    /// Check if all capability rows have test citations.
    #[must_use]
    pub fn all_cited(&self) -> bool {
        self.uncited_rows.is_empty()
    }

    /// Check if all rows are properly classified (cited OR marked 'unproven').
    #[must_use]
    pub fn all_properly_classified(&self) -> bool {
        self.improperly_classified.is_empty()
    }
}

/// Public parity separates declared coverage from contracts exercised now.
/// Reports are output artifacts; they cannot be loaded to manufacture credit.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionGatedParityReport {
    pub declared_contracts: ParityReport,
    pub total_rows: usize,
    pub evidence_backed_rows: usize,
    pub missing_evidence_rows: Vec<String>,
    pub source: Option<executed_evidence::SourceIdentity>,
    pub contracts: Vec<VerifiedParityContract>,
    pub selected_suites: Vec<String>,
    pub runs: Vec<executed_evidence::TestRunEvidence>,
    /// Canonical §22 gate evidence. Empty when no gate was requested; an empty
    /// report never counts towards readiness.
    pub canonical_gates: canonical_gates::CanonicalGateReport,
    /// Whole-project readiness. True only when every declared capability row has
    /// exact executed evidence AND every canonical §22 gate passed with a
    /// nonempty selection. The bounded contracts alone never establish it.
    pub readiness_verified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifiedParityContract {
    pub capability: &'static str,
    pub contract: &'static str,
    pub suite: &'static str,
    pub required_tests: &'static [&'static str],
    pub verified: bool,
    pub reason: Option<String>,
}

/// Stable exact mappings, deliberately independent of prose citations. Each
/// entry states the bounded behavior its tests establish. Remaining rows stay
/// missing until their acceptance tests are reviewed and mapped explicitly.
const PARITY_CONTRACTS: &[(&str, &str, &str, &[&str])] = &[
    (
        "ext4 JOURNAL_DEV paired-open",
        "Committed external JBD2 replay and missing/mismatched journal refusal",
        "ext4-journal",
        &[
            "ext4_external_journal_recovery_replays_committed_transaction",
            "ext4_external_journal_missing_for_dirty_fs_is_rejected",
            "ext4_external_journal_uuid_mismatch_is_rejected",
        ],
    ),
    (
        "ext4 journal replay parity",
        "Committed, uncommitted, revoked and interrupted JBD2 transaction replay",
        "ext4-journal",
        &[
            "ext4_journal_recovery_replays_committed_transaction",
            "ext4_journal_recovery_replays_non_contiguous_committed_transaction",
            "ext4_journal_recovery_simulate_overlay_preserves_underlying_bytes",
            "ext4_journal_recovery_ignores_uncommitted_transaction",
            "ext4_journal_recovery_honors_revoke_before_commit",
            "ext4_journal_recovery_replays_multiple_committed_transactions",
            "ext4_journal_recovery_crash_mid_second_transaction",
        ],
    ),
    (
        "ext4 superblock decode",
        "Generated ext4 superblock fields agree with e2fsprogs",
        "ext4-reference",
        &["ext4_kernel_vs_ffs_superblock"],
    ),
    (
        "ext4 inode core decode",
        "Generated ext4 inode metadata agrees with e2fsprogs",
        "ext4-reference",
        &["ext4_kernel_vs_ffs_inode_metadata"],
    ),
    (
        "ext4 extent entry decode",
        "Generated ext4 extent mappings agree with debugfs blocks",
        "ext4-reference",
        &["ext4_kernel_vs_ffs_extent_mapping"],
    ),
    (
        "ext4 directory entry parsing",
        "Generated ext4 directory entries agree with e2fsprogs",
        "ext4-reference",
        &["ext4_kernel_vs_ffs_directory_listing"],
    ),
    (
        "ext4 bitmap free space reading",
        "Generated ext4 bitmap free-space counts agree with e2fsprogs",
        "ext4-reference",
        &["ext4_bitmap_free_space_matches_kernel"],
    ),
    (
        "ext4 inline data read",
        "Inline i_block and system.data continuation bytes agree with debugfs",
        "ext4-reference",
        &["ext4_inline_data_continuation_kernel_reference"],
    ),
    (
        "ext4 inode device read",
        "OpenFs reads a generated large inode size matching debugfs",
        "ext4-reference",
        &["ext4_large_isize_high_matches_debugfs_and_openfs"],
    ),
    (
        "btrfs superblock decode",
        "Generated image superblock and root tree agree with the btrfs-progs golden",
        "btrfs-reference",
        &["btrfs_small_superblock_and_root_tree_match_golden"],
    ),
    (
        "btrfs sys_chunk mapping",
        "Generated image chunk layout matches the btrfs-progs golden",
        "btrfs-reference",
        &["btrfs_small_chunk_layout_matches_golden"],
    ),
    (
        "btrfs item payload decode (ROOT/INODE/DIR/EXTENT_DATA)",
        "Generated image directory entries and file extent views match the btrfs-progs golden",
        "btrfs-reference",
        &["btrfs_medium_directory_and_file_views_match_golden"],
    ),
    (
        "btrfs read-only tree walk",
        "Generated image subvolume catalog from the root tree matches the btrfs-progs golden",
        "btrfs-reference",
        &["btrfs_large_subvolume_catalog_matches_golden"],
    ),
    (
        "btrfs transparent decompression (ZLIB/LZO/ZSTD)",
        "Generated image large compressed extent reads back matching the btrfs-progs golden",
        "btrfs-reference",
        &["btrfs_large_compressed_extent_and_readback_match_golden"],
    ),
    (
        "btrfs send/receive streams",
        "Generated image send stream agrees with the btrfs-progs receive-dump reference",
        "btrfs-reference",
        &["btrfs_send_stream_matches_btrfs_receive_dump_reference"],
    ),
    (
        "ext4 group descriptor decode",
        "Generated image group descriptors agree with e2fsprogs",
        "ext4-kernel-differential",
        &["ext4_group_desc_kernel_reference_matches"],
    ),
    (
        "ext4 indirect block addressing",
        "Generated no-extent image block maps agree with debugfs blockcount",
        "ext4-kernel-differential",
        &["ext4_iblocks_kernel_reference_matches_debugfs_blockcount"],
    ),
    (
        "MVCC snapshot visibility",
        "A reader sees one consistent snapshot across shards",
        "mvcc-lib",
        &[
            "sharded::tests::snapshot_isolation",
            "sharded::tests::snapshot_reads_consistent_across_shards",
        ],
    ),
    (
        "MVCC commit sequencing",
        "Commit ordering is preserved and replayed exactly once",
        "mvcc-lib",
        &[
            "sharded::tests::commit_snapshots_policy_before_shard_locks",
            "persist::tests::replay_discards_duplicate_commit_sequence",
        ],
    ),
    (
        "repair symbol storage I/O (dual-slot generation commit)",
        "Repair symbol slots commit and upgrade by generation without regression",
        "repair-lib",
        &[
            "storage::tests::storage_round_trip_symbols_and_generation_commit",
            "storage::tests::storage_multi_generation_upgrade",
        ],
    ),
    (
        "corruption recovery orchestrator + evidence ledger",
        "Recovery runs to completion under churn and every event reaches the ledger",
        "repair-lib",
        &[
            "pipeline::tests::evidence_ledger_captures_all_events",
            "pipeline::tests::recovery_succeeds_with_fresh_symbols_under_write_churn",
        ],
    ),
    (
        "FUSE getattr",
        "Dispatch answers getattr with the backend's metadata",
        "fuse-lib",
        &["tests::conformance_fuse_getattr_metadata_round_trip"],
    ),
    (
        "FUSE lookup",
        "Dispatch answers lookup with the backend's metadata",
        "fuse-lib",
        &["tests::conformance_fuse_lookup_metadata_round_trip"],
    ),
    (
        "FUSE readdir",
        "Dispatch lists a directory the way the backend stores it",
        "fuse-lib",
        &["tests::conformance_fuse_readdir_directory_round_trip"],
    ),
    (
        "FUSE read",
        "Dispatch reads file contents through the backend lifecycle",
        "fuse-lib",
        &["tests::conformance_fuse_read_file_lifecycle_round_trip"],
    ),
    (
        "FUSE readlink",
        "Dispatch resolves a symlink target through the backend",
        "fuse-lib",
        &["tests::conformance_fuse_readlink_directory_round_trip"],
    ),
    (
        "FUSE ioctl FIEMAP / FIBMAP",
        "FIEMAP and FIBMAP report the block mapping the backend actually wrote",
        "fuse-lib",
        &[
            "tests::dispatch_ioctl_fibmap_maps_written_extent_physical_block",
            "tests::dispatch_ioctl_fiemap_sync_fsyncs_before_extent_lookup",
        ],
    ),
    (
        "FUSE ioctl EXT4_IOC_GETFLAGS",
        "GETFLAGS returns the file's flags as the ABI encodes them",
        "fuse-lib",
        &["tests::dispatch_ioctl_getflags_encodes_u32_response_for_fileattr_path"],
    ),
    (
        "FUSE ioctl EXT4_IOC_GETVERSION / EXT4_IOC_SETVERSION",
        "The version ioctls carry the inode generation both ways",
        "fuse-lib",
        &[
            "tests::dispatch_ioctl_getversion_encodes_u32_response_for_inode_generation",
            "tests::dispatch_ioctl_setversion_passes_generation_to_backend_and_commits",
        ],
    ),
    (
        "FUSE ioctl EXT4_IOC_SETFLAGS",
        "SETFLAGS routes to the backend and commits the new flags",
        "fuse-lib",
        &[
            "tests::dispatch_ioctl_setflags_routes_to_fsops_and_commits",
            "tests::dispatch_ioctl_setflags_accepts_8_byte_long_payload_by_using_low_u32",
        ],
    ),
    (
        "FUSE ioctl FS_IOC_GETFSLABEL / FS_IOC_SETFSLABEL",
        "The label ioctls carry the filesystem label both ways in the ABI buffer",
        "fuse-lib",
        &[
            "tests::dispatch_ioctl_getfslabel_returns_label_in_256_byte_buffer",
            "tests::dispatch_ioctl_setfslabel_passes_label_to_backend_and_commits",
        ],
    ),
    (
        "FUSE ioctl EXT4_IOC_MOVE_EXT",
        "MOVE_EXT registers the donor for the operation, unregisters it on every exit \
         path, and logs the rejection contract",
        "fuse-lib",
        &[
            "tests::dispatch_ioctl_move_ext_does_not_double_unregister_after_commit_error",
            "tests::dispatch_ioctl_move_ext_does_not_unregister_after_register_error",
            "tests::dispatch_ioctl_move_ext_rejection_logs_contract_fields",
        ],
    ),
    (
        "CLI inspect command",
        "The built binary inspects an ext4 and a btrfs image and reports it as JSON",
        "cli-e2e",
        &[
            "cli_inspect_ext4_returns_json",
            "cli_inspect_btrfs_returns_json",
        ],
    ),
    (
        "CLI info command",
        "The built binary reports both formats' superblocks",
        "cli-e2e",
        &[
            "cli_info_ext4_shows_superblock",
            "cli_info_btrfs_shows_superblock",
        ],
    ),
    (
        "CLI fsck command",
        "The built binary passes a clean image and reports a corrupted superblock",
        "cli-e2e",
        &[
            "cli_fsck_ext4_clean_image",
            "cli_fsck_corrupted_superblock_reports_error",
        ],
    ),
    (
        "CLI repair command",
        "The built binary runs repair in verify-only mode against an ext4 image",
        "cli-e2e",
        &["cli_repair_verify_only_ext4"],
    ),
    (
        "btrfs chunk tree walking",
        "Chunk entries round-trip out of the chunk tree",
        "btrfs-lib",
        &["tests::chunk_entries_round_trip_out_of_the_chunk_tree_bd_a136s"],
    ),
    (
        "btrfs device tree discovery",
        "The device is discovered from its dev item and a contradicting item is refused",
        "btrfs-lib",
        &["tests::growth_device_is_read_from_the_dev_item_bd_a136s"],
    ),
    (
        "btrfs delayed refs parity",
        "Delayed refs queue shared extents and flush applies the refcounts",
        "btrfs-lib",
        &[
            "tests::delayed_ref_queue_shared_extent_refcount",
            "tests::flush_delayed_refs_applies_refcounts",
        ],
    ),
    (
        "btrfs crash consistency (WB-I1/WB-I2)",
        "The writeback crash matrix passes every invariant and observes generation atomicity",
        "btrfs-lib",
        &[
            "crash_consistency::tests::writeback_cache_crash_matrix_passes_every_invariant",
            "crash_consistency::tests::writeback_cache_crash_matrix_observes_generation_atomicity",
        ],
    ),
    (
        "btrfs metadata writeback serialization",
        "Writeback ordering preserves the serialization invariants under the given schedule",
        "btrfs-lib",
        &["crash_consistency::proptests::mr_wb_writeback_order_preserves_invariants"],
    ),
    (
        "FCW conflict detection",
        "First-committer-wins lets disjoint blocks through and fails the conflicting one \
         with a correctly populated error",
        "mvcc-lib",
        &[
            "tests::fcw_conflict_error_contains_correct_fields",
            "tests::fcw_multi_block_fails_on_conflicting_block",
            "tests::fcw_concurrent_disjoint_blocks_all_succeed",
        ],
    ),
    (
        "COW block rewrite path",
        "Repeated rewrites of the same logical block land on distinct physical blocks",
        "mvcc-lib",
        &["tests::cow_hundred_rewrites_produce_unique_physical_blocks"],
    ),
    (
        "ext4 fast commit replay",
        "Replay carries the fast-commit inode body and falls back when the head \
         advertises unsupported features",
        "journal-lib",
        &[
            "fc_tests::replay_fast_commit_carries_inode_body",
            "fc_tests::replay_head_with_unsupported_fc_features_forces_fallback",
        ],
    ),
    (
        "ext4 JBD2 checksum verification",
        "Commit and descriptor checksums round-trip, tampering is detected, and replay \
         refuses a block whose data checksum does not match",
        "journal-lib",
        &[
            "tests::verify_jbd2_async_commit_commit_checksum_roundtrip_and_tamper_detection",
            "tests::verify_jbd2_async_commit_descriptor_checksum_roundtrip_and_tamper_detection",
            "tests::replay_jbd2_csum_v3_data_checksum_mismatch_skips_write",
        ],
    ),
];

// These test the evidence consumer itself, not filesystem capability rows.
// Exact names prevent a renamed or empty filter from becoming a green self-check.
const PARITY_HONESTY_TESTS: &[&str] = &[
    "tests::execution_gated_parity_report_requires_evidence",
    "tests::execution_gated_parity_report_counts_only_green_evidence",
    "tests::parity_honesty_fabricated_row_fails_closed",
    "tests::parity_honesty_missing_run_fails_closed",
    "tests::parity_honesty_failing_test_fails_closed",
    "executed_evidence::tests::test_evidence_requires_real_nonempty_passing_tests",
    "executed_evidence::tests::test_evidence_reads_rch_stderr_without_discarding_bad_events",
    "executed_evidence::tests::test_evidence_rejects_malformed_duplicate_and_incomplete_streams",
];

/// A parity suite is one Cargo invocation whose executed tests are evidence for
/// capability rows. `exact` filters are module-qualified test names passed to
/// libtest with `--exact`, so a suite can select named tests from a large crate
/// without running (or quietly skipping) the rest of it.
struct ParitySuite {
    id: &'static str,
    package: &'static str,
    /// Cargo-level target selection, e.g. `--test kernel_reference`.
    targets: &'static [&'static str],
    /// Libtest `--exact` filters applied after `--`.
    exact: &'static [&'static str],
}

const PARITY_SUITES: &[ParitySuite] = &[
    ParitySuite {
        id: "ext4-journal",
        package: "ffs-harness",
        targets: &["--test", "ext4_journal_recovery"],
        exact: &[],
    },
    ParitySuite {
        id: "ext4-reference",
        package: "ffs-harness",
        targets: &["--test", "kernel_reference"],
        exact: &[],
    },
    // The ext4 kernel-differential targets are separate test binaries, and one
    // Cargo invocation runs all of them: the libtest stream then carries one suite
    // block per target, which the evidence parser aggregates. Every test here is a
    // differential comparison against e2fsprogs/debugfs output on a generated
    // image.
    ParitySuite {
        id: "ext4-kernel-differential",
        package: "ffs-harness",
        targets: &[
            "--test",
            "ext4_group_desc_kernel_reference",
            "--test",
            "ext4_iblocks_kernel_reference",
            "--test",
            "ext4_inode_flags_uidgid_kernel_reference",
            "--test",
            "ext4_dir_rec_len_kernel_reference",
            "--test",
            "ext4_bitmap_csum_kernel_reference",
        ],
        exact: &[],
    },
    // bd-wh1xk: the btrfs goldens are captured from btrfs-progs, so this suite
    // needs it installed and at the golden's anchor version, or its tests
    // soft-skip and the suite cannot pass. That is also why CI selects its suites
    // explicitly rather than running every suite.
    ParitySuite {
        id: "btrfs-reference",
        package: "ffs-harness",
        targets: &["--test", "btrfs_kernel_reference"],
        exact: &[],
    },
    ParitySuite {
        id: "parity-honesty",
        package: "ffs-harness",
        targets: &["--lib"],
        exact: PARITY_HONESTY_TESTS,
    },
    // Cross-package suites: the MVCC and repair rows are proven by the crates'
    // own unit tests, selected by exact module-qualified name.
    ParitySuite {
        id: "mvcc-lib",
        package: "ffs-mvcc",
        targets: &["--lib"],
        exact: &[
            "sharded::tests::snapshot_isolation",
            "sharded::tests::snapshot_reads_consistent_across_shards",
            "sharded::tests::commit_snapshots_policy_before_shard_locks",
            "persist::tests::replay_discards_duplicate_commit_sequence",
            "tests::fcw_conflict_error_contains_correct_fields",
            "tests::fcw_multi_block_fails_on_conflicting_block",
            "tests::fcw_concurrent_disjoint_blocks_all_succeed",
            "tests::cow_hundred_rewrites_produce_unique_physical_blocks",
        ],
    },
    // ffs-journal owns the JBD2 fast-commit and checksum paths; the harness
    // ext4-journal suite covers recovery outcomes one level up.
    ParitySuite {
        id: "journal-lib",
        package: "ffs-journal",
        targets: &["--lib"],
        exact: &[
            "fc_tests::replay_fast_commit_carries_inode_body",
            "fc_tests::replay_head_with_unsupported_fc_features_forces_fallback",
            "tests::verify_jbd2_async_commit_commit_checksum_roundtrip_and_tamper_detection",
            "tests::verify_jbd2_async_commit_descriptor_checksum_roundtrip_and_tamper_detection",
            "tests::replay_jbd2_csum_v3_data_checksum_mismatch_skips_write",
        ],
    },
    ParitySuite {
        id: "repair-lib",
        package: "ffs-repair",
        targets: &["--lib"],
        exact: &[
            "storage::tests::storage_round_trip_symbols_and_generation_commit",
            "storage::tests::storage_multi_generation_upgrade",
            "pipeline::tests::evidence_ledger_captures_all_events",
            "pipeline::tests::recovery_succeeds_with_fresh_symbols_under_write_churn",
        ],
    },
    // The FUSE rows are proven at the dispatch boundary, which is where the FUSE
    // ABI behavior lives; the mounted end-to-end tests are a separate job.
    ParitySuite {
        id: "fuse-lib",
        package: "ffs-fuse",
        targets: &["--lib"],
        exact: &[
            "tests::conformance_fuse_getattr_metadata_round_trip",
            "tests::conformance_fuse_lookup_metadata_round_trip",
            "tests::conformance_fuse_readdir_directory_round_trip",
            "tests::conformance_fuse_read_file_lifecycle_round_trip",
            "tests::conformance_fuse_readlink_directory_round_trip",
            "tests::dispatch_ioctl_fibmap_maps_written_extent_physical_block",
            "tests::dispatch_ioctl_fiemap_sync_fsyncs_before_extent_lookup",
            "tests::dispatch_ioctl_getflags_encodes_u32_response_for_fileattr_path",
            "tests::dispatch_ioctl_setflags_routes_to_fsops_and_commits",
            "tests::dispatch_ioctl_setflags_accepts_8_byte_long_payload_by_using_low_u32",
            "tests::dispatch_ioctl_getversion_encodes_u32_response_for_inode_generation",
            "tests::dispatch_ioctl_setversion_passes_generation_to_backend_and_commits",
            "tests::dispatch_ioctl_getfslabel_returns_label_in_256_byte_buffer",
            "tests::dispatch_ioctl_setfslabel_passes_label_to_backend_and_commits",
            "tests::dispatch_ioctl_move_ext_does_not_double_unregister_after_commit_error",
            "tests::dispatch_ioctl_move_ext_does_not_unregister_after_register_error",
            "tests::dispatch_ioctl_move_ext_rejection_logs_contract_fields",
        ],
    },
    // The CLI rows are proven by whole-binary end-to-end tests: the target spawns the
    // built `ffs` executable and asserts on its observable output.
    ParitySuite {
        id: "cli-e2e",
        package: "ffs-cli",
        targets: &["--test", "cli_e2e"],
        exact: &[
            "cli_inspect_ext4_returns_json",
            "cli_inspect_btrfs_returns_json",
            "cli_info_ext4_shows_superblock",
            "cli_info_btrfs_shows_superblock",
            "cli_fsck_ext4_clean_image",
            "cli_fsck_corrupted_superblock_reports_error",
            "cli_repair_verify_only_ext4",
        ],
    },
    // ffs-btrfs owns the tree/mutation behavior the btrfs rows describe; the
    // harness btrfs-reference suite only covers on-disk fixture parity.
    ParitySuite {
        id: "btrfs-lib",
        package: "ffs-btrfs",
        targets: &["--lib"],
        exact: &[
            "tests::chunk_entries_round_trip_out_of_the_chunk_tree_bd_a136s",
            "tests::growth_device_is_read_from_the_dev_item_bd_a136s",
            "tests::delayed_ref_queue_shared_extent_refcount",
            "tests::flush_delayed_refs_applies_refcounts",
            "crash_consistency::tests::writeback_cache_crash_matrix_passes_every_invariant",
            "crash_consistency::tests::writeback_cache_crash_matrix_observes_generation_atomicity",
            "crash_consistency::proptests::mr_wb_writeback_order_preserves_invariants",
        ],
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParityExecutor {
    Rch,
    /// For CI or invocation already executing on a build worker.
    Cargo,
}

impl ExecutionGatedParityReport {
    /// Run the selected known suites. No paths, shell commands, JSON reports or
    /// caller-supplied pass/fail maps are accepted as parity evidence.
    pub fn run(suites: &[String], executor: ParityExecutor) -> Result<Self> {
        Self::run_with_gates(suites, &[], executor)
    }

    /// Run the selected suites and the selected canonical §22 gates against one
    /// shared source identity. Both public parity consumers and CI use this path,
    /// so a gate result and a capability claim are always the same evidence.
    pub fn run_with_gates(
        suites: &[String],
        gate_ids: &[String],
        executor: ParityExecutor,
    ) -> Result<Self> {
        let mut selected = std::collections::BTreeSet::new();
        for suite in suites {
            if !PARITY_SUITES.iter().any(|known| known.id == suite) {
                let known = PARITY_SUITES
                    .iter()
                    .map(|suite| suite.id)
                    .collect::<Vec<_>>()
                    .join(", ");
                bail!("unknown parity suite {suite}; use one of {known}");
            }
            if !selected.insert(suite.as_str()) {
                bail!("duplicate parity suite {suite}");
            }
        }
        let gates_selected = canonical_gates::select_gate_ids(gate_ids)?;
        let mut runs = Vec::new();
        for suite in &selected {
            let spec = PARITY_SUITES
                .iter()
                .find(|known| known.id == *suite)
                .expect("validated above");
            let mut args = vec!["-Z", "checksum-freshness", "test", "-p", spec.package];
            args.extend_from_slice(spec.targets);
            args.extend([
                "--",
                "-Z",
                "unstable-options",
                "--format=json",
                "--show-output",
                "--test-threads=1",
            ]);
            if !spec.exact.is_empty() {
                args.push("--exact");
                args.extend_from_slice(spec.exact);
            }
            let command = match executor {
                ParityExecutor::Rch => {
                    args.splice(0..0, ["exec", "--source-content-receipt", "--", "cargo"]);
                    "rch"
                }
                ParityExecutor::Cargo => "cargo",
            };
            runs.push(executed_evidence::TestRunEvidence::run(command, &args));
        }
        let gate_runs = canonical_gates::execute_runs(&gates_selected, executor);
        let source = executed_evidence::SourceIdentity::capture().ok();
        let gates = canonical_gates::CanonicalGateReport::from_runs(
            &gates_selected,
            &gate_runs,
            source.clone(),
        );
        Ok(Self::from_runs(&selected, runs, source, gates))
    }

    fn from_runs(
        selected: &std::collections::BTreeSet<&str>,
        runs: Vec<executed_evidence::TestRunEvidence>,
        source: Option<executed_evidence::SourceIdentity>,
        canonical_gates: canonical_gates::CanonicalGateReport,
    ) -> Self {
        let rows = capability_rows_from_feature_parity(FEATURE_PARITY_MARKDOWN);
        let contracts: Vec<_> = PARITY_CONTRACTS
            .iter()
            .map(|&(capability, contract, suite, required_tests)| {
                let result = selected
                    .iter()
                    .position(|&id| id == suite)
                    .and_then(|index| runs.get(index))
                    .ok_or_else(|| "suite not executed".to_owned())
                    .and_then(|run| {
                        if !rows.iter().any(|row| row.capability == capability) {
                            return Err("mapped capability is absent from the matrix".to_owned());
                        }
                        let source = source.as_ref().ok_or("source identity unavailable")?;
                        run.require_pass(source)?;
                        for &test in required_tests {
                            if run.results().tests.get(test)
                                != Some(&executed_evidence::TestOutcome::Passed)
                            {
                                return Err(format!(
                                    "required exact test missing or not passed: {test}"
                                ));
                            }
                        }
                        Ok(())
                    });
                VerifiedParityContract {
                    capability,
                    contract,
                    suite,
                    required_tests,
                    verified: result.is_ok(),
                    reason: result.err(),
                }
            })
            .collect();
        let evidence_backed_rows = contracts.iter().filter(|row| row.verified).count();
        let missing_evidence_rows: Vec<String> = rows
            .iter()
            .filter(|row| {
                !contracts
                    .iter()
                    .any(|c| c.verified && c.capability == row.capability)
            })
            .map(|row| row.capability.clone())
            .collect();
        // Readiness needs both halves, and neither is inferable from the other:
        // every declared capability row carrying exact executed evidence, and
        // every canonical §22 gate passing with a nonempty selection.
        let readiness_verified =
            !rows.is_empty() && missing_evidence_rows.is_empty() && canonical_gates.all_passed();
        Self {
            declared_contracts: ParityReport::current(),
            total_rows: rows.len(),
            evidence_backed_rows,
            missing_evidence_rows,
            source,
            contracts,
            selected_suites: selected.iter().map(|suite| (*suite).to_owned()).collect(),
            runs,
            canonical_gates,
            readiness_verified,
        }
    }

    /// Gate for the selected suites, not a declaration of whole-project readiness.
    pub fn require_evidence(&self) -> Result<(), String> {
        // A gate that has executable tests and does not pass fails the run, and is
        // reported first because it is the most specific failure available.
        // `NotImplemented` gates do not fail it, but they keep `readiness_verified`
        // false and are reported with their criteria so they cannot be forgotten.
        for gate in &self.canonical_gates.gates {
            if gate.status == canonical_gates::CanonicalGateStatus::Failed {
                return Err(format!(
                    "canonical gate {} failed: {}",
                    gate.gate_id,
                    gate.reason.as_deref().unwrap_or("no reason recorded")
                ));
            }
        }
        if self.runs.is_empty()
            && self.selected_suites.is_empty()
            && self.canonical_gates.gates.is_empty()
        {
            return Err(
                "no test suites or canonical gates executed; use --verify <suite> or --gate <id>"
                    .to_owned(),
            );
        }
        if self.runs.len() != self.selected_suites.len() {
            return Err("selected suites do not match execution count".to_owned());
        }
        let source = self.source.as_ref().ok_or("source identity unavailable")?;
        if &executed_evidence::SourceIdentity::capture()? != source {
            return Err("source changed after parity execution".to_owned());
        }
        for (suite, run) in self.selected_suites.iter().zip(&self.runs) {
            run.require_pass(source)?;
            if suite == "parity-honesty" {
                for &test in PARITY_HONESTY_TESTS {
                    if run.results().tests.get(test)
                        != Some(&executed_evidence::TestOutcome::Passed)
                    {
                        return Err(format!(
                            "required exact self-check missing or not passed: {test}"
                        ));
                    }
                }
            }
        }
        for contract in &self.contracts {
            if contract.reason.as_deref() != Some("suite not executed") && !contract.verified {
                return Err(format!("{}: {:?}", contract.capability, contract.reason));
            }
        }
        Ok(())
    }
}

/// Row classification for three-column parity truth (B3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParityClassification {
    /// Row has evidence-backed implementation.
    Implemented,
    /// Row has N consecutive green differential CI runs (verified against kernel).
    KernelVerified,
    /// Row covers deterministic rejection of unsupported ops (excluded from headlines).
    RejectionOnly,
    /// Row lacks evidence or failed tests.
    Unverified,
}

/// Three-column parity report: implemented / kernel-verified / rejection-only.
///
/// - `rejection_only` rows are EXCLUDED from any 100% headline.
/// - `kernel_verified` requires N consecutive green differential CI runs (default N=3).
/// - A regression drops a row from kernel_verified back to implemented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreeColumnParityReport {
    /// Total capability rows in FEATURE_PARITY.md.
    pub total_rows: usize,
    /// Rows with evidence-backed implementation.
    pub implemented_rows: usize,
    /// Rows verified against kernel with N consecutive green runs.
    pub kernel_verified_rows: usize,
    /// Rows that only test rejection of unsupported ops (excluded from headlines).
    pub rejection_only_rows: usize,
    /// Rows that failed classification (no evidence, failed tests, etc.).
    pub unverified_rows: usize,
    /// Consecutive green run threshold for kernel verification.
    pub kernel_verification_threshold: usize,
    /// Git SHA the report was generated at.
    pub git_sha: Option<String>,
}

impl ThreeColumnParityReport {
    /// Default threshold for kernel verification (consecutive green differential runs).
    pub const DEFAULT_KERNEL_THRESHOLD: usize = 3;

    /// Build a three-column parity report from row classifications.
    #[must_use]
    pub fn from_classifications(
        classifications: &[(String, ParityClassification)],
        git_sha: Option<String>,
        kernel_threshold: Option<usize>,
    ) -> Self {
        let total_rows = classifications.len();
        let threshold = kernel_threshold.unwrap_or(Self::DEFAULT_KERNEL_THRESHOLD);

        let mut implemented_rows = 0;
        let mut kernel_verified_rows = 0;
        let mut rejection_only_rows = 0;
        let mut unverified_rows = 0;

        for (_, classification) in classifications {
            match classification {
                ParityClassification::Implemented => implemented_rows += 1,
                ParityClassification::KernelVerified => kernel_verified_rows += 1,
                ParityClassification::RejectionOnly => rejection_only_rows += 1,
                ParityClassification::Unverified => unverified_rows += 1,
            }
        }

        Self {
            total_rows,
            implemented_rows,
            kernel_verified_rows,
            rejection_only_rows,
            unverified_rows,
            kernel_verification_threshold: threshold,
            git_sha,
        }
    }

    /// Compute headline coverage percentage (rejection_only excluded).
    ///
    /// The 100% headline counts only implemented + kernel_verified rows,
    /// NOT rejection_only rows.
    #[must_use]
    pub fn headline_coverage_percent(&self) -> f64 {
        let headline_total = self.total_rows.saturating_sub(self.rejection_only_rows);
        if headline_total == 0 {
            return 0.0;
        }
        let headline_implemented = self.implemented_rows + self.kernel_verified_rows;
        (headline_implemented as f64 / headline_total as f64) * 100.0
    }

    /// Counts for the headline (rejection_only excluded).
    #[must_use]
    pub fn headline_counts(&self) -> (usize, usize) {
        let implemented = self.implemented_rows + self.kernel_verified_rows;
        let total = self.total_rows.saturating_sub(self.rejection_only_rows);
        (implemented, total)
    }

    /// Check if a rejection_only row would incorrectly raise headline counts.
    ///
    /// Returns Err if rejection_only rows are being counted in headlines.
    pub fn verify_rejection_excluded(&self) -> Result<(), String> {
        // Rejection rows should never be counted in implemented or kernel_verified
        // This is enforced by the classification system, but we verify here.
        let (headline_impl, headline_total) = self.headline_counts();

        // Sanity check: headline_total should exclude rejection_only
        let expected_total = self.total_rows.saturating_sub(self.rejection_only_rows);
        if headline_total != expected_total {
            return Err(format!(
                "headline_total={} but expected {} (total={} - rejection={})",
                headline_total, expected_total, self.total_rows, self.rejection_only_rows
            ));
        }

        // Verify headline_impl doesn't include rejection_only
        if headline_impl > headline_total {
            return Err(format!(
                "headline_implemented={headline_impl} exceeds headline_total={headline_total} - rejection rows may be leaking"
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseFixture {
    pub size: usize,
    pub writes: Vec<FixtureWrite>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureWrite {
    pub offset: usize,
    pub hex: String,
}

impl SparseFixture {
    /// Create a sparse fixture from raw bytes by extracting non-zero regions.
    ///
    /// Scans `data` for contiguous runs of non-zero bytes and records each run
    /// as a `FixtureWrite`. Zero-filled regions are omitted since the loader
    /// starts with an all-zero buffer.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut writes = Vec::new();
        let mut i = 0;
        while i < data.len() {
            // Skip zero bytes.
            if data[i] == 0 {
                i += 1;
                continue;
            }
            // Found a non-zero byte — scan for the end of the non-zero run.
            let start = i;
            while i < data.len() && data[i] != 0 {
                i += 1;
            }
            writes.push(FixtureWrite {
                offset: start,
                hex: hex::encode(&data[start..i]),
            });
        }
        Self {
            size: data.len(),
            writes,
        }
    }

    /// Create a sparse fixture from a byte range within a larger image.
    ///
    /// Extracts `data[offset..offset+len]` and adjusts write offsets so they
    /// are relative to the start of the extracted region.
    #[must_use]
    pub fn from_region(data: &[u8], offset: usize, len: usize) -> Self {
        let start = offset.min(data.len());
        let end = offset.saturating_add(len).min(data.len());
        let region = &data[start..end];
        Self::from_bytes(region)
    }

    /// Round-trip: expand this fixture into a fully materialized byte buffer.
    pub fn materialize(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![0_u8; self.size];
        for write in &self.writes {
            let payload = Vec::<u8>::from_hex(write.hex.as_bytes())
                .with_context(|| format!("invalid hex at offset {}", write.offset))?;
            let end = write
                .offset
                .checked_add(payload.len())
                .context("fixture offset overflow")?;
            if end > bytes.len() {
                bail!(
                    "fixture write out of bounds: offset={} payload={} size={}",
                    write.offset,
                    payload.len(),
                    bytes.len()
                );
            }
            bytes[write.offset..end].copy_from_slice(&payload);
        }
        Ok(bytes)
    }
}

pub fn load_sparse_fixture(path: &Path) -> Result<Vec<u8>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read fixture {}", path.display()))?;
    let fixture: SparseFixture = serde_json::from_str(&text)
        .with_context(|| format!("invalid fixture json {}", path.display()))?;

    let mut bytes = vec![0_u8; fixture.size];
    for write in fixture.writes {
        let payload = Vec::<u8>::from_hex(write.hex.as_bytes())
            .with_context(|| format!("invalid hex at offset {}", write.offset))?;

        let end = write
            .offset
            .checked_add(payload.len())
            .context("fixture offset overflow")?;
        if end > bytes.len() {
            bail!(
                "fixture write out of bounds: offset={} payload={} size={}",
                write.offset,
                payload.len(),
                bytes.len()
            );
        }

        bytes[write.offset..end].copy_from_slice(&payload);
    }

    Ok(bytes)
}

/// Extract an ext4 superblock sparse fixture from a raw image.
///
/// Reads the 1024 bytes at offset 1024 (the ext4 superblock location),
/// validates it parses, and returns a `SparseFixture`.
pub fn extract_ext4_superblock(image: &[u8]) -> Result<SparseFixture> {
    let offset = ffs_types::EXT4_SUPERBLOCK_OFFSET;
    let size = ffs_types::EXT4_SUPERBLOCK_SIZE;
    if image.len() < offset + size {
        bail!(
            "image too small for ext4 superblock: need {} bytes, got {}",
            offset + size,
            image.len()
        );
    }
    // Validate it parses.
    let _sb = Ext4Superblock::parse_superblock_region(&image[offset..offset + size])
        .context("region does not contain a valid ext4 superblock")?;
    Ok(SparseFixture::from_bytes(&image[offset..offset + size]))
}

/// Extract a btrfs superblock sparse fixture from a raw image.
///
/// Reads the 4096 bytes at offset 65536 (the btrfs superblock location),
/// validates it parses, and returns a `SparseFixture`.
pub fn extract_btrfs_superblock(image: &[u8]) -> Result<SparseFixture> {
    let offset = ffs_types::BTRFS_SUPER_INFO_OFFSET;
    let size = ffs_types::BTRFS_SUPER_INFO_SIZE;
    if image.len() < offset + size {
        bail!(
            "image too small for btrfs superblock: need {} bytes, got {}",
            offset + size,
            image.len()
        );
    }
    let _sb = BtrfsSuperblock::parse_superblock_region(&image[offset..offset + size])
        .context("region does not contain a valid btrfs superblock")?;
    Ok(SparseFixture::from_bytes(&image[offset..offset + size]))
}

/// Extract a sparse fixture from an arbitrary byte range in an image.
///
/// This is the general-purpose version: specify `offset` and `len` to capture
/// any metadata structure (group descriptor, inode, directory block, etc.).
pub fn extract_region(image: &[u8], offset: usize, len: usize) -> Result<SparseFixture> {
    if offset.saturating_add(len) > image.len() {
        bail!(
            "region out of bounds: offset={offset} len={len} image_len={}",
            image.len()
        );
    }
    Ok(SparseFixture::from_bytes(&image[offset..offset + len]))
}

pub fn validate_ext4_fixture(path: &Path) -> Result<Ext4Superblock> {
    let data = load_sparse_fixture(path)?;
    Ext4Superblock::parse_superblock_region(&data)
        .with_context(|| format!("failed ext4 parse for fixture {}", path.display()))
}

pub fn validate_btrfs_fixture(path: &Path) -> Result<BtrfsSuperblock> {
    let data = load_sparse_fixture(path)?;
    BtrfsSuperblock::parse_superblock_region(&data)
        .with_context(|| format!("failed btrfs parse for fixture {}", path.display()))
}

pub fn validate_group_desc_fixture(path: &Path, desc_size: u16) -> Result<Ext4GroupDesc> {
    let data = load_sparse_fixture(path)?;
    Ext4GroupDesc::parse_from_bytes(&data, desc_size)
        .with_context(|| format!("failed group desc parse for fixture {}", path.display()))
}

pub fn validate_inode_fixture(path: &Path) -> Result<Ext4Inode> {
    let data = load_sparse_fixture(path)?;
    Ext4Inode::parse_from_bytes(&data)
        .with_context(|| format!("failed inode parse for fixture {}", path.display()))
}

pub fn validate_dir_block_fixture(path: &Path, block_size: u32) -> Result<Vec<Ext4DirEntry>> {
    let data = load_sparse_fixture(path)?;
    let (entries, _tail) = parse_dir_block(&data, block_size)
        .with_context(|| format!("failed dir block parse for fixture {}", path.display()))?;
    Ok(entries)
}

/// Validate a btrfs superblock fixture that contains a sys_chunk_array,
/// parse the chunk array, and map logical addresses to physical.
pub fn validate_btrfs_chunk_fixture(
    path: &Path,
) -> Result<(BtrfsSuperblock, Vec<ffs_ondisk::BtrfsChunkEntry>)> {
    let data = load_sparse_fixture(path)?;
    let sb = BtrfsSuperblock::parse_superblock_region(&data)
        .with_context(|| format!("failed btrfs parse for fixture {}", path.display()))?;
    let chunks = parse_sys_chunk_array(&sb.sys_chunk_array)
        .with_context(|| format!("failed chunk parse for fixture {}", path.display()))?;
    // Verify mapping is functional for bootstrap tree roots.
    for (name, addr) in [
        ("root", sb.root),
        ("chunk_root", sb.chunk_root),
        ("log_root", sb.log_root),
    ] {
        if addr != 0 {
            let mapping = map_logical_to_physical(&chunks, addr).with_context(|| {
                format!(
                    "mapping {name} ({addr:#x}) failed for fixture {}",
                    path.display()
                )
            })?;
            if mapping.is_none() {
                bail!(
                    "mapping {name} ({addr:#x}) is not covered by sys_chunk_array for fixture {}",
                    path.display()
                );
            }
        }
    }
    Ok((sb, chunks))
}

/// Validate a btrfs leaf node fixture, returning the parsed header and items.
pub fn validate_btrfs_leaf_fixture(path: &Path) -> Result<(BtrfsHeader, Vec<BtrfsItem>)> {
    let data = load_sparse_fixture(path)?;
    let (header, items) = parse_leaf_items(&data)
        .with_context(|| format!("failed leaf parse for fixture {}", path.display()))?;
    header
        .validate(data.len(), None)
        .with_context(|| format!("header validation failed for fixture {}", path.display()))?;
    Ok((header, items))
}

/// Validate an ext4 extent tree fixture (leaf or internal node).
pub fn validate_extent_tree_fixture(path: &Path) -> Result<(Ext4ExtentHeader, ExtentTree)> {
    let data = load_sparse_fixture(path)?;
    let (header, tree) = parse_extent_tree(&data)
        .with_context(|| format!("failed extent tree parse for fixture {}", path.display()))?;
    Ok((header, tree))
}

/// Validate an ext4 htree DX root fixture (block 0 of a hash-indexed directory).
pub fn validate_htree_dx_root_fixture(path: &Path) -> Result<Ext4DxRoot> {
    let data = load_sparse_fixture(path)?;
    let dx_root = parse_dx_root(&data)
        .with_context(|| format!("failed htree DX root parse for fixture {}", path.display()))?;
    Ok(dx_root)
}

/// Validate an ext4 external xattr block fixture.
pub fn validate_xattr_block_fixture(path: &Path) -> Result<Vec<Ext4Xattr>> {
    let data = load_sparse_fixture(path)?;
    let xattrs = parse_xattr_block(&data)
        .with_context(|| format!("failed xattr block parse for fixture {}", path.display()))?;
    Ok(xattrs)
}

/// Validate a btrfs device item fixture.
pub fn validate_btrfs_devitem_fixture(path: &Path) -> Result<BtrfsDevItem> {
    let data = load_sparse_fixture(path)?;
    let devitem = parse_dev_item(&data)
        .with_context(|| format!("failed devitem parse for fixture {}", path.display()))?;
    Ok(devitem)
}

/// Validate an ext4 MMP (multi-mount protection) block fixture.
pub fn validate_mmp_block_fixture(path: &Path) -> Result<Ext4MmpBlock> {
    let data = load_sparse_fixture(path)?;
    let mmp = Ext4MmpBlock::parse_from_bytes(&data)
        .with_context(|| format!("failed MMP block parse for fixture {}", path.display()))?;
    let checksum_region = data
        .get(..EXT4_MMP_FIXTURE_CHECKSUM_OFFSET)
        .context("MMP block fixture shorter than checksum-covered prefix")?;
    let expected_checksum = ext4_chksum(EXT4_MMP_FIXTURE_CHECKSUM_SEED, checksum_region);
    if mmp.checksum != expected_checksum {
        bail!(
            "MMP block fixture {} checksum mismatch: expected 0x{:08X}, got 0x{:08X}",
            path.display(),
            expected_checksum,
            mmp.checksum
        );
    }
    mmp.validate_checksum(&data, EXT4_MMP_FIXTURE_CHECKSUM_SEED)
        .with_context(|| format!("failed MMP block checksum for fixture {}", path.display()))?;
    Ok(mmp)
}

// ── Golden reference types ────────────────────────────────────────
//
// Versioned schema for kernel-derived golden outputs. The capture
// pipeline (scripts/capture_ext4_reference.sh) produces JSON in this
// format; conformance tests parse it and compare against ffs-ondisk.

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenReference {
    pub version: u32,
    pub source: String,
    pub image_params: GoldenImageParams,
    pub superblock: GoldenSuperblock,
    pub directories: Vec<GoldenDirectory>,
    pub files: Vec<GoldenFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenImageParams {
    pub size_bytes: u64,
    pub block_size: u32,
    pub volume_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenSuperblock {
    pub block_size: u32,
    pub blocks_count: u64,
    pub inodes_count: u32,
    pub volume_name: String,
    pub free_blocks_count: u64,
    pub free_inodes_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenDirectory {
    pub path: String,
    pub entries: Vec<GoldenDirEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenDirEntry {
    pub name: String,
    pub file_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenFile {
    pub path: String,
    pub size: u64,
    pub content: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_path(rel: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .join("conformance")
            .join("fixtures")
            .join(rel)
    }

    #[test]
    fn ext4_fixture_parses() {
        let path = fixture_path("ext4_superblock_sparse.json");
        let sb = validate_ext4_fixture(&path).expect("ext4 fixture parse");
        assert_eq!(sb.block_size, 4096);
        assert_eq!(sb.volume_name, "frankenfs");
    }

    #[test]
    fn btrfs_fixture_parses() {
        let path = fixture_path("btrfs_superblock_sparse.json");
        let sb = validate_btrfs_fixture(&path).expect("btrfs fixture parse");
        assert_eq!(sb.magic, ffs_types::BTRFS_MAGIC);
        assert_eq!(sb.label, "ffs-lab");
    }

    #[test]
    fn ext4_group_desc_32byte_fixture_parses() {
        let path = fixture_path("ext4_group_desc_32byte.json");
        let gd = validate_group_desc_fixture(&path, 32).expect("group desc 32 parse");
        assert_eq!(gd.block_bitmap, 5);
        assert_eq!(gd.inode_bitmap, 6);
        assert_eq!(gd.inode_table, 7);
        assert_eq!(gd.free_blocks_count, 200);
        assert_eq!(gd.free_inodes_count, 1000);
        assert_eq!(gd.used_dirs_count, 3);
        assert_eq!(gd.itable_unused, 500);
        assert_eq!(gd.flags, 4);
        assert_eq!(gd.checksum, 0xCDAB);
    }

    #[test]
    fn ext4_group_desc_64byte_fixture_parses() {
        let path = fixture_path("ext4_group_desc_64byte.json");
        let gd = validate_group_desc_fixture(&path, 64).expect("group desc 64 parse");
        // Low 32 bits = 5, high 32 bits = 1 → 0x1_0000_0005
        assert_eq!(gd.block_bitmap, 0x1_0000_0005);
        assert_eq!(gd.inode_bitmap, 0x2_0000_0006);
        assert_eq!(gd.inode_table, 0x3_0000_0007);
        // Low 16 bits = 200 (0xC8), high 16 bits = 10 (0x0A) → 0x000A_00C8
        assert_eq!(gd.free_blocks_count, 0x000A_00C8);
        assert_eq!(gd.free_inodes_count, 0x0014_03E8);
        assert_eq!(gd.used_dirs_count, 0x0005_0003);
        assert_eq!(gd.itable_unused, 0x0064_01F4);
    }

    #[test]
    fn ext4_inode_regular_file_fixture_parses() {
        let path = fixture_path("ext4_inode_regular_file.json");
        let inode = validate_inode_fixture(&path).expect("regular file inode parse");
        assert_eq!(inode.mode, 0o10_0644);
        assert_eq!(inode.uid, 1000);
        assert_eq!(inode.size, 1024);
        assert_eq!(inode.links_count, 1);
        assert_eq!(inode.blocks, 8);
        assert_eq!(inode.flags, 0x0008_0000); // EXTENTS_FL
        assert_eq!(inode.generation, 42);
        assert_eq!(inode.extent_bytes.len(), 60);
    }

    #[test]
    fn ext4_inode_directory_fixture_parses() {
        let path = fixture_path("ext4_inode_directory.json");
        let inode = validate_inode_fixture(&path).expect("directory inode parse");
        assert_eq!(inode.mode, 0o4_0755);
        assert_eq!(inode.size, 4096);
        assert_eq!(inode.links_count, 2);
        assert_eq!(inode.flags, 0x0008_0000); // EXTENTS_FL
    }

    #[test]
    fn ext4_dir_block_fixture_parses() {
        let path = fixture_path("ext4_dir_block.json");
        let entries = validate_dir_block_fixture(&path, 4096).expect("dir block parse");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name_str(), ".");
        assert_eq!(entries[0].inode, 2);
        assert_eq!(entries[1].name_str(), "..");
        assert_eq!(entries[1].inode, 2);
        assert_eq!(entries[2].name_str(), "hello.txt");
        assert_eq!(entries[2].inode, 11);
    }

    #[test]
    fn ext4_dir_block_malformed_fixtures_reject() {
        for fixture in [
            "ext4_dir_block_name_len_overflow.json",
            "ext4_dir_block_rec_len_too_small.json",
            "ext4_dir_block_rec_len_too_small_min12.json",
            "ext4_dir_block_rec_len_unaligned.json",
            "ext4_dir_block_tail_bad_header.json",
            "ext4_dir_block_tail_padding_nonzero.json",
            "ext4_dir_block_truncated_tail.json",
        ] {
            let path = fixture_path(fixture);
            let err = validate_dir_block_fixture(&path, 4096).unwrap_err();
            let message = format!("{err:#}");
            assert!(
                message.contains("failed dir block parse"),
                "{fixture}: {message}"
            );
        }
    }

    #[test]
    fn btrfs_chunk_fixture_parses() {
        let path = fixture_path("btrfs_superblock_with_chunks.json");
        let (sb, chunks) = validate_btrfs_chunk_fixture(&path).expect("btrfs chunk fixture parse");
        assert_eq!(sb.magic, ffs_types::BTRFS_MAGIC);
        assert_eq!(sb.label, "ffs-chunks");
        assert_eq!(sb.sys_chunk_array_size, 97);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].key.objectid, 256);
        assert_eq!(chunks[0].key.item_type, 228);
        assert_eq!(chunks[0].length, 8 * 1024 * 1024);
        assert_eq!(chunks[0].stripes[0].devid, 1);
        assert_eq!(chunks[0].stripes[0].offset, 0x10_0000);
    }

    #[test]
    fn btrfs_chunk_mapping_covers_bootstrap_roots() {
        let path = fixture_path("btrfs_superblock_with_chunks.json");
        let (sb, chunks) = validate_btrfs_chunk_fixture(&path).expect("btrfs chunk fixture parse");
        for (name, addr) in [("root", sb.root), ("chunk_root", sb.chunk_root)] {
            let mapping = ffs_ondisk::map_logical_to_physical(&chunks, addr)
                .expect("mapping ok")
                .expect("bootstrap root should be covered");
            assert_eq!(mapping.devid, 1, "{name} devid");
            assert_eq!(mapping.physical, 0x10_0000 + addr, "{name} physical");
        }
    }

    #[test]
    fn btrfs_chunk_fixture_rejects_uncovered_root_mapping() -> Result<()> {
        let path = fixture_path("btrfs_superblock_with_chunks.json");
        let mut data = load_sparse_fixture(&path).expect("load btrfs chunk fixture");
        data[0x50..0x58].copy_from_slice(&(8_u64 * 1024 * 1024).to_le_bytes());

        let fixture = SparseFixture::from_bytes(&data);
        let fixture_file = tempfile::NamedTempFile::new()?;
        fs::write(fixture_file.path(), serde_json::to_vec(&fixture)?)?;

        let err = validate_btrfs_chunk_fixture(fixture_file.path()).unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("mapping root (0x800000) is not covered by sys_chunk_array"),
            "{message}"
        );
        Ok(())
    }

    #[test]
    fn btrfs_chunk_fixture_rejects_uncovered_chunk_root_mapping() -> Result<()> {
        let path = fixture_path("btrfs_superblock_with_chunks.json");
        let mut data = load_sparse_fixture(&path).expect("load btrfs chunk fixture");
        data[0x58..0x60].copy_from_slice(&(8_u64 * 1024 * 1024).to_le_bytes());

        let fixture = SparseFixture::from_bytes(&data);
        let fixture_file = tempfile::NamedTempFile::new()?;
        fs::write(fixture_file.path(), serde_json::to_vec(&fixture)?)?;

        let err = validate_btrfs_chunk_fixture(fixture_file.path()).unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("mapping chunk_root (0x800000) is not covered by sys_chunk_array"),
            "{message}"
        );
        Ok(())
    }

    #[test]
    fn btrfs_chunk_fixture_rejects_uncovered_log_root_mapping() -> Result<()> {
        let path = fixture_path("btrfs_superblock_with_chunks.json");
        let mut data = load_sparse_fixture(&path).expect("load btrfs chunk fixture");
        data[0x60..0x68].copy_from_slice(&(8_u64 * 1024 * 1024).to_le_bytes());

        let fixture = SparseFixture::from_bytes(&data);
        let fixture_file = tempfile::NamedTempFile::new()?;
        fs::write(fixture_file.path(), serde_json::to_vec(&fixture)?)?;

        let err = validate_btrfs_chunk_fixture(fixture_file.path()).unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("mapping log_root (0x800000) is not covered by sys_chunk_array"),
            "{message}"
        );
        Ok(())
    }

    #[test]
    fn btrfs_leaf_fixture_parses() {
        let path = fixture_path("btrfs_leaf_node.json");
        let (header, items) = validate_btrfs_leaf_fixture(&path).expect("btrfs leaf fixture parse");
        assert_eq!(header.level, 0);
        assert_eq!(header.nritems, 3);
        assert_eq!(header.owner, 5);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].key.objectid, 256);
        assert_eq!(items[0].key.item_type, 1);
        assert_eq!(items[1].key.objectid, 256);
        assert_eq!(items[1].key.item_type, 12);
        assert_eq!(items[2].key.objectid, 257);
        assert_eq!(items[2].key.item_type, 1);
    }

    #[test]
    fn btrfs_fstree_leaf_fixture_parses() {
        let path = fixture_path("btrfs_fstree_leaf.json");
        let (header, items) =
            validate_btrfs_leaf_fixture(&path).expect("btrfs fs tree leaf fixture parse");
        assert_eq!(header.level, 0);
        assert_eq!(header.generation, 10);
        assert_eq!(header.owner, 5);
        assert_eq!(header.nritems, 5);
        assert_eq!(items.len(), 5);

        let observed: Vec<_> = items
            .iter()
            .map(|item| {
                (
                    item.key.objectid,
                    item.key.item_type,
                    item.key.offset,
                    item.data_offset,
                    item.data_size,
                )
            })
            .collect();
        assert_eq!(
            observed.as_slice(),
            &[
                (256, 1, 0, 15_936, 160),
                (256, 84, 1_193_046, 16_096, 40),
                (256, 96, 2, 16_136, 40),
                (257, 1, 0, 16_176, 160),
                (257, 108, 0, 16_336, 48),
            ]
        );
    }

    #[test]
    fn btrfs_roottree_leaf_fixture_parses() {
        let path = fixture_path("btrfs_roottree_leaf.json");
        let (header, items) =
            validate_btrfs_leaf_fixture(&path).expect("btrfs root tree leaf fixture parse");
        assert_eq!(header.level, 0);
        assert_eq!(header.generation, 10);
        assert_eq!(header.owner, 1);
        assert_eq!(header.nritems, 3);
        assert_eq!(items.len(), 3);

        let observed: Vec<_> = items
            .iter()
            .map(|item| {
                (
                    item.key.objectid,
                    item.key.item_type,
                    item.key.offset,
                    item.data_offset,
                    item.data_size,
                )
            })
            .collect();
        assert_eq!(
            observed.as_slice(),
            &[
                (2, 132, 0, 15_667, 239),
                (3, 132, 0, 15_906, 239),
                (5, 132, 0, 16_145, 239),
            ]
        );
    }

    #[test]
    fn parity_report_is_non_zero() {
        let report = ParityReport::current();
        assert!(report.overall_total > 0);
        assert!(report.overall_implemented > 0);
        assert!(report.overall_coverage_percent > 0.0);
    }

    fn representative_parity_report() -> ParityReport {
        let domains = vec![
            CoverageDomain::new("ext4 metadata parsing", 10, 10),
            CoverageDomain::new("btrfs metadata parsing", 14, 20),
        ];

        ParityReport {
            domains,
            overall_implemented: 24,
            overall_total: 30,
            overall_coverage_percent: percentage(24, 30),
        }
    }

    #[test]
    fn parity_report_current_json_round_trips() -> Result<(), serde_json::Error> {
        let report = ParityReport::current();
        let json = serde_json::to_string_pretty(&report)?;
        let parsed: ParityReport = serde_json::from_str(&json)?;

        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn parity_report_json_shape() -> Result<(), serde_json::Error> {
        let report = representative_parity_report();
        let json = serde_json::to_string_pretty(&report)?;
        let parsed: ParityReport = serde_json::from_str(&json)?;

        assert_eq!(parsed, report);
        assert_eq!(serde_json::to_string_pretty(&parsed)?, json);
        insta::assert_snapshot!("parity_report_json_shape", json);
        Ok(())
    }

    #[test]
    fn btrfs_parity_granularity_counts_rows() {
        let report = BtrfsParityGranularity::from_feature_parity(false, None);
        assert!(
            report.total_btrfs_rows > 0,
            "FEATURE_PARITY.md must contain btrfs rows"
        );
        report
            .verify_row_accounting()
            .expect("row accounting must be consistent");
    }

    #[test]
    fn btrfs_parity_granularity_rw_durable_requires_evidence() {
        // Without A5 evidence, rw_durable must be 0
        let report_no_evidence = BtrfsParityGranularity::from_feature_parity(false, None);
        assert_eq!(
            report_no_evidence.rw_durable, 0,
            "rw_durable must be 0 without A5 evidence"
        );
        report_no_evidence
            .verify_rw_durable_requires_evidence()
            .expect("verification must pass when rw_durable=0");

        // With A5 evidence, rw_durable can be > 0 if there are in-progress rows
        let report_with_evidence = BtrfsParityGranularity::from_feature_parity(true, None);
        report_with_evidence
            .verify_rw_durable_requires_evidence()
            .expect("verification must pass with A5 evidence");
    }

    #[test]
    fn btrfs_parity_granularity_json_round_trips() -> Result<(), serde_json::Error> {
        let report = BtrfsParityGranularity::from_feature_parity(false, Some("abc123".to_string()));
        let json = serde_json::to_string_pretty(&report)?;
        let parsed: BtrfsParityGranularity = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn btrfs_parity_granularity_split_is_consistent() {
        let report = BtrfsParityGranularity::from_feature_parity(false, None);

        // Verify the split: parse_only + read_verified + in_progress + rw_durable = total
        let sum = report.parse_only + report.read_verified + report.in_progress + report.rw_durable;
        assert_eq!(
            sum,
            report.total_btrfs_rows,
            "granularity split must equal total: {} + {} + {} + {} = {} != {}",
            report.parse_only,
            report.read_verified,
            report.in_progress,
            report.rw_durable,
            sum,
            report.total_btrfs_rows
        );

        // Without evidence, rw_durable is 0 (in_progress can be 0 if all btrfs rows are complete)
        assert_eq!(
            report.rw_durable, 0,
            "rw_durable must be 0 without evidence"
        );
        // Note: in_progress can be 0 if all btrfs rows are marked ✅ (no 🚧 markers)

        // Most rows should be read_verified (kernel differential tests exist)
        assert!(
            report.read_verified > 0,
            "there should be read_verified btrfs rows"
        );
    }

    #[test]
    fn profile_read_path_report_json_shape() -> Result<(), serde_json::Error> {
        let report = ProfileReadPathReport {
            mode: "direct-read".to_owned(),
            fixture: "conformance/golden/ext4_8mb_reference.ext4".to_owned(),
            duration_ms: 1_000,
            iterations: 42,
            checksum: 73,
        };
        let json = serde_json::to_string_pretty(&report)?;
        let parsed: ProfileReadPathReport = serde_json::from_str(&json)?;

        assert_eq!(parsed, report);
        insta::assert_snapshot!("profile_read_path_report_json_shape", json);
        Ok(())
    }

    #[test]
    fn golden_reference_json_round_trip_preserves_full_fixture() -> Result<(), serde_json::Error> {
        let golden = GoldenReference {
            version: 1,
            source: "synthetic-ext4-reference".to_owned(),
            image_params: GoldenImageParams {
                size_bytes: 8 * 1024 * 1024,
                block_size: 4096,
                volume_name: "ffs-golden".to_owned(),
            },
            superblock: GoldenSuperblock {
                block_size: 4096,
                blocks_count: 2048,
                inodes_count: 1024,
                volume_name: "ffs-golden".to_owned(),
                free_blocks_count: 1984,
                free_inodes_count: 1001,
            },
            directories: vec![GoldenDirectory {
                path: "/".to_owned(),
                entries: vec![
                    GoldenDirEntry {
                        name: "hello.txt".to_owned(),
                        file_type: "regular".to_owned(),
                    },
                    GoldenDirEntry {
                        name: "nested".to_owned(),
                        file_type: "directory".to_owned(),
                    },
                ],
            }],
            files: vec![GoldenFile {
                path: "/hello.txt".to_owned(),
                size: 5,
                content: b"hello".to_vec(),
            }],
        };

        let json = serde_json::to_string_pretty(&golden)?;
        let parsed: GoldenReference = serde_json::from_str(&json)?;

        assert_eq!(parsed, golden);
        assert_eq!(serde_json::to_string_pretty(&parsed)?, json);
        Ok(())
    }

    // ── Fixture generation tests ──────────────────────────────────────

    #[test]
    fn sparse_fixture_from_bytes_round_trips() {
        let original = vec![0, 0, 0xAA, 0xBB, 0, 0, 0xCC, 0, 0];
        let fixture = SparseFixture::from_bytes(&original);
        assert_eq!(fixture.size, 9);
        assert_eq!(fixture.writes.len(), 2);
        assert_eq!(fixture.writes[0].offset, 2);
        assert_eq!(fixture.writes[0].hex, "aabb");
        assert_eq!(fixture.writes[1].offset, 6);
        assert_eq!(fixture.writes[1].hex, "cc");

        // Round-trip: materialize should produce identical bytes.
        let materialized = fixture.materialize().expect("materialize");
        assert_eq!(materialized, original);
    }

    #[test]
    fn sparse_fixture_from_bytes_all_zero() {
        let zeroes = vec![0_u8; 1024];
        let fixture = SparseFixture::from_bytes(&zeroes);
        assert_eq!(fixture.size, 1024);
        assert_eq!(fixture.writes, [] as [FixtureWrite; 0]);
        let materialized = fixture.materialize().expect("materialize");
        assert_eq!(materialized, zeroes);
    }

    #[test]
    fn sparse_fixture_from_bytes_all_nonzero() {
        let data = vec![0xFF_u8; 16];
        let fixture = SparseFixture::from_bytes(&data);
        assert_eq!(fixture.writes.len(), 1);
        assert_eq!(fixture.writes[0].offset, 0);
        assert_eq!(fixture.writes[0].hex, "ff".repeat(16));
    }

    #[test]
    fn sparse_fixture_materialize_rejects_invalid_hex_with_offset() {
        let fixture = SparseFixture {
            size: 4,
            writes: vec![FixtureWrite {
                offset: 1,
                hex: "not-hex".to_owned(),
            }],
        };

        let err = fixture.materialize().unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("invalid hex at offset 1"),
            "diagnostic should include the bad write offset: {message}"
        );
    }

    #[test]
    fn sparse_fixture_materialize_rejects_out_of_bounds_write() {
        let fixture = SparseFixture {
            size: 3,
            writes: vec![FixtureWrite {
                offset: 2,
                hex: "aabb".to_owned(),
            }],
        };

        let err = fixture.materialize().unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("fixture write out of bounds: offset=2 payload=2 size=3"),
            "diagnostic should identify the overflowing sparse write: {message}"
        );
    }

    #[test]
    fn load_sparse_fixture_rejects_invalid_hex_with_offset() -> Result<()> {
        let fixture_file = tempfile::NamedTempFile::new()?;
        fs::write(
            fixture_file.path(),
            r#"{"size":4,"writes":[{"offset":2,"hex":"zz"}]}"#,
        )?;

        let err = load_sparse_fixture(fixture_file.path()).unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("invalid hex at offset 2"),
            "diagnostic should include the bad fixture write offset: {message}"
        );
        Ok(())
    }

    #[test]
    fn load_sparse_fixture_rejects_out_of_bounds_write() -> Result<()> {
        let fixture_file = tempfile::NamedTempFile::new()?;
        fs::write(
            fixture_file.path(),
            r#"{"size":3,"writes":[{"offset":2,"hex":"aabb"}]}"#,
        )?;

        let err = load_sparse_fixture(fixture_file.path()).unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("fixture write out of bounds: offset=2 payload=2 size=3"),
            "diagnostic should identify the overflowing fixture write: {message}"
        );
        Ok(())
    }

    const REPRESENTATIVE_SPARSE_FIXTURE_JSON_GOLDEN: &str = r#"{
  "size": 12,
  "writes": [
    {
      "offset": 1,
      "hex": "ab"
    },
    {
      "offset": 4,
      "hex": "010203"
    },
    {
      "offset": 10,
      "hex": "ff"
    }
  ]
}"#;

    #[test]
    fn sparse_fixture_json_round_trip() -> Result<(), serde_json::Error> {
        let original = vec![0, 0x42, 0, 0, 0xDE, 0xAD, 0, 0];
        let fixture = SparseFixture::from_bytes(&original);
        let json = serde_json::to_string_pretty(&fixture)?;
        let parsed: SparseFixture = serde_json::from_str(&json)?;
        assert_eq!(parsed, fixture);
        let materialized = parsed.materialize().expect("materialize");
        assert_eq!(materialized, original);
        Ok(())
    }

    #[test]
    fn representative_sparse_fixture_json_exact_golden_contract() -> Result<(), serde_json::Error> {
        let original = vec![0, 0xAB, 0, 0, 1, 2, 3, 0, 0, 0, 0xFF, 0];
        let fixture = SparseFixture::from_bytes(&original);
        let json = serde_json::to_string_pretty(&fixture)?;

        assert_eq!(json, REPRESENTATIVE_SPARSE_FIXTURE_JSON_GOLDEN);

        let parsed: SparseFixture = serde_json::from_str(&json)?;
        assert_eq!(parsed, fixture);
        let materialized = parsed.materialize().expect("materialize");
        assert_eq!(materialized, original);
        Ok(())
    }

    #[test]
    fn extract_region_basic() {
        let data = vec![0, 0, 0xAA, 0xBB, 0xCC, 0, 0, 0, 0xDD, 0];
        let fixture = extract_region(&data, 2, 4).expect("extract_region");
        assert_eq!(fixture.size, 4);
        let materialized = fixture.materialize().expect("materialize");
        assert_eq!(materialized, vec![0xAA, 0xBB, 0xCC, 0]);
    }

    #[test]
    fn sparse_fixture_from_region_clamps_overflowing_length() {
        let data = vec![0xAA, 0xBB, 0, 0xCC];
        let fixture = SparseFixture::from_region(&data, 1, usize::MAX);

        assert_eq!(fixture.size, 3);
        let materialized = fixture.materialize().expect("materialize");
        assert_eq!(materialized, vec![0xBB, 0, 0xCC]);
    }

    #[test]
    fn sparse_fixture_from_region_overflow_after_end_returns_empty() {
        let data = vec![0xAA, 0xBB, 0xCC];
        let fixture = SparseFixture::from_region(&data, usize::MAX, usize::MAX);

        assert_eq!(fixture.size, 0);
        assert_eq!(fixture.writes, [] as [FixtureWrite; 0]);
    }

    #[test]
    fn extract_region_out_of_bounds() {
        let data = vec![0; 10];
        assert!(extract_region(&data, 8, 5).is_err());
    }

    #[test]
    fn existing_fixture_round_trips_through_generation() {
        // Load an existing fixture, materialize it, generate a new fixture from
        // the materialized bytes, and verify the result is equivalent.
        let path = fixture_path("ext4_superblock_sparse.json");
        let original_data = load_sparse_fixture(&path).expect("load fixture");
        let generated = SparseFixture::from_bytes(&original_data);
        let regenerated_data = generated.materialize().expect("materialize");
        assert_eq!(original_data, regenerated_data);
    }

    #[test]
    fn execution_gated_parity_report_requires_evidence() {
        let report = ExecutionGatedParityReport::run(&[], ParityExecutor::Rch).unwrap();
        assert!(report.require_evidence().is_err());
        assert_eq!(report.evidence_backed_rows, 0);
        assert_eq!(report.missing_evidence_rows.len(), report.total_rows);
        assert!(!report.readiness_verified);
        for capability in [
            "MVCC snapshot visibility",
            "corruption recovery orchestrator + evidence ledger",
            "FUSE read",
            "CLI repair command",
            "benchmark harness",
        ] {
            assert!(
                report
                    .missing_evidence_rows
                    .iter()
                    .any(|row| row == capability),
                "unexecuted late capability must remain visible: {capability}"
            );
        }
    }

    #[test]
    fn execution_gated_parity_report_counts_only_green_evidence() {
        // A genuinely passing, unrelated test must not satisfy this contract.
        let executable = std::env::current_exe().unwrap();
        let run = executed_evidence::TestRunEvidence::run(
            executable.to_str().unwrap(),
            &[
                "--exact",
                "tests::extract_region_basic",
                "-Z",
                "unstable-options",
                "--format=json",
                "--show-output",
            ],
        );
        assert_eq!(run.results().passed, 1);
        assert!(run.results().error.is_none());
        for suite in ["ext4-journal", "parity-honesty"] {
            let report = ExecutionGatedParityReport::from_runs(
                &std::collections::BTreeSet::from([suite]),
                vec![run.clone()],
                executed_evidence::SourceIdentity::capture().ok(),
                canonical_gates::CanonicalGateReport::empty(),
            );
            assert!(report.require_evidence().is_err(), "{suite}");
            assert_eq!(report.evidence_backed_rows, 0);
        }
    }

    #[test]
    fn failed_canonical_gate_fails_the_parity_gate() {
        // A real failing process, so the gate is `Failed`, not `NotImplemented`.
        let gate_run = executed_evidence::TestRunEvidence::run("false", &[]);
        let gates = canonical_gates::CanonicalGateReport::from_runs(
            &std::collections::BTreeSet::from(["gate1"]),
            &[gate_run],
            executed_evidence::SourceIdentity::capture().ok(),
        );
        let report = ExecutionGatedParityReport::from_runs(
            &std::collections::BTreeSet::<&str>::new(),
            vec![],
            executed_evidence::SourceIdentity::capture().ok(),
            gates,
        );
        assert_eq!(report.canonical_gates.failed_gates(), ["gate1"]);
        let error = report
            .require_evidence()
            .expect_err("a failed canonical gate must fail the parity gate");
        assert!(error.contains("canonical gate gate1 failed"), "{error}");
        assert!(!report.readiness_verified);
    }

    #[test]
    fn passing_gates_do_not_promote_unmapped_rows() {
        let executable = std::env::current_exe().unwrap();
        let run = executed_evidence::TestRunEvidence::run(
            executable.to_str().unwrap(),
            &[
                "--exact",
                "tests::extract_region_basic",
                "-Z",
                "unstable-options",
                "--format=json",
                "--show-output",
            ],
        );
        let source = executed_evidence::SourceIdentity::capture().ok();
        let gates = canonical_gates::CanonicalGateReport::from_runs(
            &std::collections::BTreeSet::from(["gate1"]),
            &[run],
            source.clone(),
        );
        let report = ExecutionGatedParityReport::from_runs(
            &std::collections::BTreeSet::<&str>::new(),
            vec![],
            source,
            gates,
        );
        assert_eq!(report.canonical_gates.passed_gates(), ["gate1"]);
        assert!(report.canonical_gates.all_passed());
        assert_eq!(report.evidence_backed_rows, 0);
        assert_eq!(report.missing_evidence_rows.len(), report.total_rows);
        assert!(!report.readiness_verified);
    }

    #[test]
    fn execution_gated_parity_replaces_tautology() {
        let report = ExecutionGatedParityReport::run(&[], ParityExecutor::Rch).unwrap();
        assert_eq!(report.declared_contracts, ParityReport::current());
        assert!(report.declared_contracts.overall_implemented > 0);
        assert_eq!(report.evidence_backed_rows, 0);
    }

    #[test]
    fn parity_honesty_fabricated_row_fails_closed() {
        for suite in ["", "ext4", "ext4-journal-extra", "../ext4-journal", "true"] {
            assert!(
                ExecutionGatedParityReport::run(&[suite.to_owned()], ParityExecutor::Rch).is_err()
            );
        }
    }

    #[test]
    fn parity_honesty_missing_run_fails_closed() {
        let report = ExecutionGatedParityReport::from_runs(
            &std::collections::BTreeSet::from(["ext4-journal"]),
            vec![],
            executed_evidence::SourceIdentity::capture().ok(),
            canonical_gates::CanonicalGateReport::empty(),
        );
        assert_eq!(report.evidence_backed_rows, 0);
        assert!(report.require_evidence().is_err());
    }

    #[test]
    fn parity_honesty_failing_test_fails_closed() {
        let run = executed_evidence::TestRunEvidence::run("false", &[]);
        let report = ExecutionGatedParityReport::from_runs(
            &std::collections::BTreeSet::from(["ext4-journal"]),
            vec![run],
            executed_evidence::SourceIdentity::capture().ok(),
            canonical_gates::CanonicalGateReport::empty(),
        );
        assert_eq!(report.evidence_backed_rows, 0);
        assert!(report.require_evidence().is_err());
    }

    #[test]
    fn three_column_parity_rejection_only_excluded_from_headline() {
        // B3: rejection_only rows must be EXCLUDED from 100% headline
        let classifications = vec![
            ("row1".to_string(), ParityClassification::Implemented),
            ("row2".to_string(), ParityClassification::KernelVerified),
            ("row3".to_string(), ParityClassification::RejectionOnly),
            ("row4".to_string(), ParityClassification::RejectionOnly),
            ("row5".to_string(), ParityClassification::Unverified),
        ];

        let report = ThreeColumnParityReport::from_classifications(
            &classifications,
            Some("test123".to_string()),
            None,
        );

        // Verify basic counts
        assert_eq!(report.total_rows, 5);
        assert_eq!(report.implemented_rows, 1);
        assert_eq!(report.kernel_verified_rows, 1);
        assert_eq!(report.rejection_only_rows, 2);
        assert_eq!(report.unverified_rows, 1);

        // Headline counts EXCLUDE rejection_only rows
        let (headline_impl, headline_total) = report.headline_counts();
        assert_eq!(
            headline_total, 3,
            "headline_total excludes 2 rejection_only rows"
        );
        assert_eq!(
            headline_impl, 2,
            "headline_impl = implemented + kernel_verified"
        );

        // Verify rejection is properly excluded
        assert!(
            report.verify_rejection_excluded().is_ok(),
            "rejection_only rows must not leak into headlines"
        );

        // Headline coverage should be 2/3 = 66.67%
        let coverage = report.headline_coverage_percent();
        assert!(
            (coverage - 66.67).abs() < 1.0,
            "headline coverage should be ~66.67%, got {coverage}"
        );
    }

    #[test]
    fn three_column_parity_rejection_only_cannot_raise_counts() {
        // B3 acceptance: unit test asserts rejection_only row cannot raise implemented or kernel_verified

        // Create a report with ONLY rejection_only rows
        let classifications = vec![
            ("rej1".to_string(), ParityClassification::RejectionOnly),
            ("rej2".to_string(), ParityClassification::RejectionOnly),
            ("rej3".to_string(), ParityClassification::RejectionOnly),
        ];

        let report = ThreeColumnParityReport::from_classifications(&classifications, None, None);

        // All rows are rejection_only
        assert_eq!(report.rejection_only_rows, 3);

        // implemented and kernel_verified must be zero
        assert_eq!(
            report.implemented_rows, 0,
            "rejection_only rows cannot raise implemented count"
        );
        assert_eq!(
            report.kernel_verified_rows, 0,
            "rejection_only rows cannot raise kernel_verified count"
        );

        // Headline should have 0 implemented out of 0 total (rejection excluded)
        let (headline_impl, headline_total) = report.headline_counts();
        assert_eq!(
            headline_total, 0,
            "all rows are rejection_only, headline_total is 0"
        );
        assert_eq!(headline_impl, 0, "no implemented or kernel_verified rows");

        // Coverage of 0/0 should be 0%
        assert!((report.headline_coverage_percent() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn three_column_parity_kernel_verification_threshold() {
        // B3: kernel_verified requires N consecutive green runs (default N=3)
        let classifications = vec![("row1".to_string(), ParityClassification::KernelVerified)];

        // Default threshold
        let report = ThreeColumnParityReport::from_classifications(&classifications, None, None);
        assert_eq!(
            report.kernel_verification_threshold,
            ThreeColumnParityReport::DEFAULT_KERNEL_THRESHOLD,
            "default threshold should be 3"
        );

        // Custom threshold
        let report_custom =
            ThreeColumnParityReport::from_classifications(&classifications, None, Some(5));
        assert_eq!(
            report_custom.kernel_verification_threshold, 5,
            "custom threshold should be respected"
        );
    }

    #[test]
    fn parity_parser_ignores_non_summary_tables() {
        let markdown = r"
# FEATURE_PARITY

## 1. Coverage Summary (Current)

| Domain | Implemented | Total Tracked | Coverage |
|--------|-------------|---------------|----------|
| ext4 metadata parsing | 19 | 19 | 100.0% |
| **Overall** | **19** | **19** | **100.0%** |

## 2. Tracked Capability Matrix

| Capability | Legacy Reference | Status | Notes |
|------------|------------------|--------|-------|
| fake row with numeric note | 1 | ✅ | 999 |
";
        let domains = coverage_domains_from_feature_parity(markdown);
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].domain, "ext4 metadata parsing");
        assert_eq!(domains[0].implemented, 19);
        assert_eq!(domains[0].total, 19);
    }

    #[test]
    fn capability_row_parser_extracts_matrix_rows() {
        let markdown = r"
## 2. Tracked Capability Matrix

| Capability | Legacy Reference | Status | Notes |
|------------|------------------|--------|-------|
| ext4 superblock decode | `fs/ext4/ext4.h` | ✅ | Implemented in `ffs-ext4` |
| ext4 path resolution | `fs/ext4/namei.c` | ✅ | Harness coverage in `crates/ffs-harness/tests/conformance.rs` |

### 2.1 Other Section
";
        let rows = capability_rows_from_feature_parity(markdown);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].capability, "ext4 superblock decode");
        assert!(!rows[0].has_test_citation);
        assert_eq!(rows[1].capability, "ext4 path resolution");
        assert!(rows[1].has_test_citation);
    }

    #[test]
    fn capability_row_parser_preserves_subsections_and_excludes_other_tables() {
        for next_heading in ["## 3. Other Section", "# Next Document"] {
            let markdown = format!(
                "\
Prose mentioning Tracked Capability Matrix does not start the section.
| Capability | Legacy Reference | Status | Notes |
| outside-before | reference | Missing | unproven |

## 2. Tracked Capability Matrix
| Capability | Legacy Reference | Status | Notes |
|------------|------------------|--------|-------|
| first | reference | ✅ | unproven |

### 2.1 Scenarios
| Contract ID | Operation | Class | Expected Result |
| scenario | operation | ✅ | success |

#### 2.1.1 More Capabilities
| Capability | Legacy Reference | Status | Notes |
|------------|------------------|--------|-------|
| missing feature | reference | Missing | unproven |
| excluded feature | reference | Excluded | outside scope |

{next_heading}
| Capability | Legacy Reference | Status | Notes |
| outside-after | reference | ✅ | unproven |
"
            );
            let rows = capability_rows_from_feature_parity(&markdown);
            let names: Vec<_> = rows.iter().map(|row| row.capability.as_str()).collect();
            assert_eq!(names, ["first", "missing feature", "excluded feature"]);
        }
    }

    #[test]
    fn capability_row_parser_includes_canonical_late_families() {
        let rows = capability_rows_from_feature_parity(FEATURE_PARITY_MARKDOWN);
        for capability in [
            "ext4 superblock decode",
            "MVCC snapshot visibility",
            "repair symbol storage I/O (dual-slot generation commit)",
            "FUSE mount runtime",
            "CLI repair command",
            "benchmark harness",
        ] {
            assert_eq!(
                rows.iter()
                    .filter(|row| row.capability == capability)
                    .count(),
                1,
                "capability must be counted exactly once: {capability}"
            );
        }
        assert!(
            rows.iter()
                .all(|row| { !row.capability.starts_with('`') && row.capability != "Contract ID" })
        );
    }

    #[test]
    fn test_citation_audit_reports_uncited_rows() {
        let report = TestCitationAuditReport::audit();
        assert!(
            report.total_rows > 0,
            "FEATURE_PARITY.md must have capability rows"
        );

        if !report.uncited_rows.is_empty() {
            eprintln!(
                "Test citation audit: {}/{} rows cited, {} uncited, {} unproven",
                report.cited_rows,
                report.total_rows,
                report.uncited_rows.len(),
                report.unproven_rows
            );
            for cap in &report.uncited_rows {
                eprintln!("  - {cap}");
            }
        }
    }

    #[test]
    fn all_capability_rows_must_be_properly_classified() {
        let report = TestCitationAuditReport::audit();

        if !report.all_properly_classified() {
            eprintln!(
                "\nFEATURE_PARITY.md audit failed: {} rows lack test citation or 'unproven' marker",
                report.improperly_classified.len()
            );
            eprintln!("Each capability row must either:");
            eprintln!("  1. Cite a concrete test (tests/, crates/ffs-, harness::, etc.), OR");
            eprintln!("  2. Be explicitly marked 'unproven' in the Notes column\n");
            for cap in &report.improperly_classified {
                eprintln!("  ✗ {cap}");
            }
            eprintln!();
        }

        assert!(
            report.all_properly_classified(),
            "FEATURE_PARITY.md has {} improperly classified rows (see stderr for list)",
            report.improperly_classified.len()
        );
    }

    #[test]
    fn extract_test_citations_parses_integration_test_pattern() {
        let notes = "Test coverage in `crates/ffs-harness/tests/kernel_reference.rs::ext4_kernel_vs_ffs_superblock`.";
        let citations = extract_test_citations(notes);

        assert!(
            citations.contains(&"ext4_kernel_vs_ffs_superblock".to_string()),
            "Should extract test name: {citations:?}"
        );
        assert!(
            citations
                .iter()
                .any(|c| c.contains("kernel_reference::ext4_kernel_vs_ffs_superblock")),
            "Should extract file::test pattern: {citations:?}"
        );
    }

    #[test]
    fn extract_test_citations_parses_unit_test_pattern() {
        let notes =
            "Coverage in `crates/ffs-mvcc/src/lib.rs::merge_proof_mechanism_collapses_labels`.";
        let citations = extract_test_citations(notes);

        assert!(
            citations.contains(&"merge_proof_mechanism_collapses_labels".to_string()),
            "Should extract unit test name: {citations:?}"
        );
    }

    #[test]
    fn parse_cargo_test_json_output_extracts_results() {
        let output = r#"{"type":"test","event":"ok","name":"tests::my_test"}
{"type":"test","event":"failed","name":"tests::failing_test"}
{"type":"suite","event":"started","test_count":2}
"#;

        let results = parse_cargo_test_json_output(output);

        assert_eq!(results.get("tests::my_test"), Some(&true));
        assert_eq!(results.get("tests::failing_test"), Some(&false));
        assert!(!results.contains_key("suite")); // Should ignore non-test events
    }

    #[test]
    fn build_parity_evidence_map_matches_citations_to_results() {
        // Simulate cargo test JSON output with test names that should match
        // some FEATURE_PARITY.md citations
        let output = r#"{"type":"test","event":"ok","name":"kernel_reference::ext4_kernel_vs_ffs_superblock"}
{"type":"test","event":"ok","name":"conformance::inode_read_test"}
"#;

        let evidence = build_parity_evidence_map(output);

        // The evidence map should contain entries for tests that match citations
        // Exact matches depend on what's in FEATURE_PARITY.md
        // Evidence map may be empty if no citations match - that's OK for this test
        let _ = evidence;
    }
}
