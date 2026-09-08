//! Structured logging schema and correlation contracts.
//!
//! Defines the canonical field names, outcome vocabularies, severity mappings,
//! and error classification taxonomy used across all FrankenFS crates. The
//! contract is versioned and enforced by unit tests that detect drift.
//!
//! # Contract version
//!
//! The current contract version is [`CONTRACT_VERSION`]. Any change to field
//! semantics, required fields, or outcome vocabularies MUST bump this version.
//!
//! # Usage
//!
//! Crates should import field name constants from this module rather than
//! hardcoding strings:
//!
//! ```text
//! use ffs_harness::log_contract::{field, outcome};
//!
//! info!(
//!     target: "ffs::mvcc",
//!     { field::OPERATION_ID } = op_id,
//!     { field::SCENARIO_ID } = scenario,
//!     { field::OUTCOME } = outcome::APPLIED,
//!     { field::DURATION_US } = elapsed.as_micros() as u64,
//!     "mvcc_commit"
//! );
//! ```

use serde::{Deserialize, Serialize};

/// Schema contract version. Bump on any breaking change.
pub const CONTRACT_VERSION: u32 = 1;

// ── Canonical field names ─────────────────────────────────────────────────

/// Canonical structured log field name constants.
///
/// Every critical log event across FrankenFS SHOULD use these field names.
/// This ensures log aggregation, alerting, and post-mortem tools can reliably
/// extract structured data without per-crate field mapping.
pub mod field {
    /// Unique identifier for the logical operation (e.g., hash-derived from
    /// inode + offset + length, or a UUID for CLI commands).
    pub const OPERATION_ID: &str = "operation_id";

    /// Stable scenario identifier for E2E and contract tests.
    /// Format: `snake_case`, e.g., `"btrfs_rw_fallocate_prealloc"`.
    pub const SCENARIO_ID: &str = "scenario_id";

    /// Operation outcome. Values MUST come from the [`super::outcome`] vocabulary.
    pub const OUTCOME: &str = "outcome";

    /// Error classification when outcome is a failure.
    /// Format: `snake_case`, e.g., `"read_only"`, `"unsupported_punch_hole_mode"`.
    pub const ERROR_CLASS: &str = "error_class";

    /// Subsystem or crate that owns this log event.
    /// Uses the `target:` field of `tracing` macros (e.g., `"ffs::mvcc"`).
    pub const SUBSYSTEM: &str = "target";

    /// Duration in microseconds. This is the canonical timing unit.
    /// All latency measurements SHOULD use microseconds for consistency.
    pub const DURATION_US: &str = "duration_us";

    /// Transaction ID for MVCC operations.
    pub const TXN_ID: &str = "txn_id";

    /// Commit sequence number for versioned operations.
    pub const COMMIT_SEQ: &str = "commit_seq";

    /// Block group identifier for repair/scrub operations.
    pub const GROUP_ID: &str = "group_id";

    /// Inode number for file-level operations.
    pub const INO: &str = "ino";

    /// Byte offset within a file or device.
    pub const OFFSET: &str = "offset";

    /// Total number of fields in the canonical schema.
    pub const CANONICAL_FIELDS: &[&str] = &[
        OPERATION_ID,
        SCENARIO_ID,
        OUTCOME,
        ERROR_CLASS,
        SUBSYSTEM,
        DURATION_US,
        TXN_ID,
        COMMIT_SEQ,
        GROUP_ID,
        INO,
        OFFSET,
    ];
}

// ── Outcome vocabulary ────────────────────────────────────────────────────

/// Canonical outcome values for the `outcome` field.
///
/// All log events that report an outcome SHOULD use one of these values.
/// This closed vocabulary enables reliable alerting and aggregation.
pub mod outcome {
    /// Operation is beginning (entry point).
    pub const START: &str = "start";

    /// Operation completed successfully and changes were applied.
    pub const APPLIED: &str = "applied";

    /// Operation was rejected before execution (precondition failure).
    pub const REJECTED: &str = "rejected";

    /// Operation completed normally (generic success without mutation).
    pub const COMPLETED: &str = "completed";

    /// Operation failed during execution (runtime error).
    pub const FAILED: &str = "failed";

    /// Operation was skipped (not applicable in this context).
    pub const SKIPPED: &str = "skipped";

    /// All valid outcome values.
    pub const VOCABULARY: &[&str] = &[START, APPLIED, REJECTED, COMPLETED, FAILED, SKIPPED];
}

// ── Severity mapping ──────────────────────────────────────────────────────

/// Log severity levels and their semantic meaning in FrankenFS.
///
/// Maps to `tracing` levels with explicit guidance on when to use each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogSeverity {
    /// Detailed diagnostic information. No operational impact.
    /// Use for: internal state dumps, cache hit/miss details, parse steps.
    Trace,

    /// Development-time diagnostic. Useful for debugging but too noisy for
    /// production. Use for: intermediate computation results, lookup paths.
    Debug,

    /// Normal operational events. Use for: operation start/complete, config
    /// loaded, daemon started, mount succeeded.
    Info,

    /// Recoverable anomaly. The system compensated but the condition may
    /// indicate a developing problem. Use for: retried I/O, degraded mode
    /// entry, threshold approached but not breached.
    Warn,

    /// Operation failed or integrity violation detected. Requires attention.
    /// Use for: commit failure, checksum mismatch, unrecoverable I/O error.
    Error,
}

impl LogSeverity {
    /// Convert to the `tracing::Level` equivalent string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

// ── Error classification taxonomy ─────────────────────────────────────────

/// Canonical error classification categories.
///
/// The `error_class` field SHOULD use values from this taxonomy. Categories
/// are intentionally broad — specific error_class strings are freeform
/// `snake_case` within these categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    /// Precondition not met (e.g., read-only mode, unsupported operation).
    Precondition,
    /// I/O failure (device error, timeout, sync failure).
    Io,
    /// Data integrity violation (checksum mismatch, structural invariant).
    Integrity,
    /// Concurrency conflict (serialization failure, lock timeout).
    Concurrency,
    /// Resource exhaustion (out of space, too many open files).
    Resource,
    /// Configuration or input validation error.
    Validation,
    /// Internal invariant violation (should not happen).
    Internal,
}

impl ErrorCategory {
    /// Check if an error_class string belongs to this category.
    ///
    /// Uses a prefix convention: `"io_device_timeout"` belongs to `Io`.
    #[must_use]
    pub fn matches(self, error_class: &str) -> bool {
        let prefix = match self {
            Self::Precondition => "precondition_",
            Self::Io => "io_",
            Self::Integrity => "integrity_",
            Self::Concurrency => "concurrency_",
            Self::Resource => "resource_",
            Self::Validation => "validation_",
            Self::Internal => "internal_",
        };
        error_class.starts_with(prefix)
    }
}

// ── E2E marker contract ──────────────────────────────────────────────────

/// Canonical E2E scenario result marker format.
///
/// All E2E scripts MUST emit markers in this format for machine parsing:
///
/// ```text
/// SCENARIO_RESULT|scenario_id=<id>|outcome=<PASS|FAIL>
/// SCENARIO_RESULT|scenario_id=<id>|outcome=<PASS|FAIL>|detail=<text>
/// ```
///
/// The `scenario_id` MUST match the regex `^[a-z][a-z0-9]*(_[a-z0-9]+){2,}$`
/// (at least 3 underscore-separated segments, all lowercase alphanumeric).
/// Optional extension fields may appear before `detail`; `detail` is the final
/// field and cannot contain the pipe separator.
pub mod e2e_marker {
    /// Marker prefix for all E2E scenario results.
    pub const PREFIX: &str = "SCENARIO_RESULT";

    /// Field separator in markers.
    pub const SEP: &str = "|";

    /// Outcome value for passing scenarios.
    pub const PASS: &str = "PASS";

    /// Outcome value for failing scenarios.
    pub const FAIL: &str = "FAIL";

    /// Scenario ID regex pattern.
    pub const SCENARIO_ID_REGEX: &str = r"^[a-z][a-z0-9]*(_[a-z0-9]+){2,}$";

    /// Return true when `id` matches [`SCENARIO_ID_REGEX`].
    #[must_use]
    pub fn is_valid_scenario_id(id: &str) -> bool {
        let mut segments = id.split('_');
        let Some(first) = segments.next() else {
            return false;
        };

        if first.is_empty()
            || !first.starts_with(|ch: char| ch.is_ascii_lowercase())
            || !is_lower_alnum(first)
        {
            return false;
        }

        let mut remaining_segments = 0usize;
        for segment in segments {
            if segment.is_empty() || !is_lower_alnum(segment) {
                return false;
            }
            remaining_segments += 1;
        }

        remaining_segments >= 2
    }

    fn is_lower_alnum(segment: &str) -> bool {
        segment
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
    }

    /// Parse a SCENARIO_RESULT marker line into (scenario_id, outcome, detail).
    ///
    /// Returns `None` if the line is not a valid marker. The prefix must start
    /// at byte 0 to match the shell E2E summary and gate parsers.
    #[must_use]
    pub fn parse_marker(line: &str) -> Option<(&str, &str, Option<&str>)> {
        let mut parts = line.split(SEP);
        if parts.next()? != PREFIX {
            return None;
        }

        let mut scenario_id = None;
        let mut outcome_val = None;
        let mut detail = None;

        let mut parts = parts.peekable();
        while let Some(part) = parts.next() {
            if let Some(val) = part.strip_prefix("scenario_id=") {
                if scenario_id.is_some() {
                    return None;
                }
                scenario_id = Some(val);
            } else if let Some(val) = part.strip_prefix("outcome=") {
                if outcome_val.is_some() {
                    return None;
                }
                outcome_val = Some(val);
            } else if let Some(val) = part.strip_prefix("detail=") {
                if detail.is_some() {
                    return None;
                }
                if parts.peek().is_some() {
                    return None;
                }
                detail = Some(val);
            } else {
                let (key, _) = part.split_once('=')?;
                if key.is_empty() {
                    return None;
                }
            }
        }

        let scenario_id = scenario_id?;
        let outcome_val = outcome_val?;
        if !is_valid_scenario_id(scenario_id) || !matches!(outcome_val, PASS | FAIL) {
            return None;
        }

        Some((scenario_id, outcome_val, detail))
    }
}

// ── Cross-surface consistency ─────────────────────────────────────────────

/// Known subsystem target prefixes and their owning crates.
///
/// Used by drift checks to verify that log target strings match the
/// expected crate ownership.
pub const SUBSYSTEM_TARGETS: &[(&str, &str)] = &[
    ("ffs::cli", "ffs-cli"),
    ("ffs::cli::mount", "ffs-cli"),
    ("ffs::cli::inspect", "ffs-cli"),
    ("ffs::cli::scrub", "ffs-cli"),
    ("ffs::cli::fsck", "ffs-cli"),
    ("ffs::cli::parity", "ffs-cli"),
    ("ffs::cli::evidence", "ffs-cli"),
    ("ffs::cli::repair", "ffs-cli"),
    ("ffs::mvcc", "ffs-core"),
    ("ffs::write", "ffs-core"),
    ("ffs::journal", "ffs-core"),
    ("ffs::btrfs::rw", "ffs-core"),
    ("ffs::btrfs::alloc", "ffs-btrfs"),
    ("ffs::btrfs::txn", "ffs-btrfs"),
    ("ffs::durability", "ffs-core"),
    ("ffs::fuse::io", "ffs-fuse"),
    ("ffs::wal_buffer", "ffs-journal"),
    ("ffs::group_commit", "ffs-journal"),
    ("ffs::bwtree", "ffs-btree"),
    ("ffs::repair::refresh", "ffs-repair"),
    ("ffs::repair::policy", "ffs-repair"),
    ("ffs::repair::daemon", "ffs-repair"),
    ("ffs::checksum", "ffs-types"),
    ("ffs::benchmark_taxonomy", "ffs-harness"),
];

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_version_is_set() {
        const { assert!(CONTRACT_VERSION >= 1) };
    }

    #[test]
    fn outcome_vocabulary_is_non_empty() {
        assert_ne!(outcome::VOCABULARY, [] as [&str; 0]);
    }

    #[test]
    fn outcome_vocabulary_has_no_duplicates() {
        let mut sorted = outcome::VOCABULARY.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), outcome::VOCABULARY.len());
    }

    #[test]
    fn canonical_fields_has_no_duplicates() {
        let mut sorted = field::CANONICAL_FIELDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), field::CANONICAL_FIELDS.len());
    }

    #[test]
    fn canonical_fields_include_declared_schema_constants() {
        let declared = [
            field::OPERATION_ID,
            field::SCENARIO_ID,
            field::OUTCOME,
            field::ERROR_CLASS,
            field::SUBSYSTEM,
            field::DURATION_US,
            field::TXN_ID,
            field::COMMIT_SEQ,
            field::GROUP_ID,
            field::INO,
            field::OFFSET,
        ];

        for field_name in declared {
            assert!(
                field::CANONICAL_FIELDS.contains(&field_name),
                "canonical field list is missing declared field {field_name}",
            );
        }
    }

    #[test]
    fn canonical_fields_are_snake_case() {
        for field_name in field::CANONICAL_FIELDS {
            assert!(
                field_name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_'),
                "field {field_name} is not snake_case",
            );
        }
    }

    #[test]
    fn outcome_values_are_lowercase() {
        for val in outcome::VOCABULARY {
            assert!(
                val.chars().all(|c| c.is_ascii_lowercase()),
                "outcome value {val} is not lowercase",
            );
        }
    }

    #[test]
    fn severity_ordering_is_correct() {
        assert!(LogSeverity::Trace < LogSeverity::Debug);
        assert!(LogSeverity::Debug < LogSeverity::Info);
        assert!(LogSeverity::Info < LogSeverity::Warn);
        assert!(LogSeverity::Warn < LogSeverity::Error);
    }

    #[test]
    fn error_category_matches_prefix() {
        assert!(ErrorCategory::Io.matches("io_device_timeout"));
        assert!(ErrorCategory::Integrity.matches("integrity_checksum_mismatch"));
        assert!(ErrorCategory::Precondition.matches("precondition_read_only"));
        assert!(!ErrorCategory::Io.matches("integrity_checksum_mismatch"));
    }

    #[test]
    fn error_category_no_false_positives() {
        // A string without a known prefix should not match any category.
        let unknown = "some_random_error";
        let categories = [
            ErrorCategory::Precondition,
            ErrorCategory::Io,
            ErrorCategory::Integrity,
            ErrorCategory::Concurrency,
            ErrorCategory::Resource,
            ErrorCategory::Validation,
            ErrorCategory::Internal,
        ];
        for cat in &categories {
            assert!(
                !cat.matches(unknown),
                "category {cat:?} should not match {unknown}",
            );
        }
    }

    #[test]
    fn structured_log_contract_json_shape() -> Result<(), serde_json::Error> {
        let shape = serde_json::json!({
            "contract_version": CONTRACT_VERSION,
            "canonical_fields": field::CANONICAL_FIELDS,
            "outcome_vocabulary": outcome::VOCABULARY,
            "severity_levels": [
                LogSeverity::Trace,
                LogSeverity::Debug,
                LogSeverity::Info,
                LogSeverity::Warn,
                LogSeverity::Error,
            ],
            "severity_tracing_levels": [
                LogSeverity::Trace.as_str(),
                LogSeverity::Debug.as_str(),
                LogSeverity::Info.as_str(),
                LogSeverity::Warn.as_str(),
                LogSeverity::Error.as_str(),
            ],
            "error_categories": [
                ErrorCategory::Precondition,
                ErrorCategory::Io,
                ErrorCategory::Integrity,
                ErrorCategory::Concurrency,
                ErrorCategory::Resource,
                ErrorCategory::Validation,
                ErrorCategory::Internal,
            ],
            "e2e_marker": {
                "prefix": e2e_marker::PREFIX,
                "separator": e2e_marker::SEP,
                "pass": e2e_marker::PASS,
                "fail": e2e_marker::FAIL,
                "scenario_id_regex": e2e_marker::SCENARIO_ID_REGEX,
            },
            "subsystem_targets": SUBSYSTEM_TARGETS,
        });

        insta::assert_snapshot!(
            "structured_log_contract_json_shape",
            serde_json::to_string_pretty(&shape)?
        );
        Ok(())
    }

    #[test]
    fn e2e_marker_parse_valid() -> Result<(), &'static str> {
        let line = "SCENARIO_RESULT|scenario_id=taxonomy_builds_clean|outcome=PASS";
        let (id, outcome_val, detail) =
            e2e_marker::parse_marker(line).ok_or("expected valid e2e marker")?;
        assert_eq!(id, "taxonomy_builds_clean");
        assert_eq!(outcome_val, "PASS");
        assert!(detail.is_none());
        Ok(())
    }

    #[test]
    fn e2e_marker_parse_with_detail() -> Result<(), &'static str> {
        let line =
            "SCENARIO_RESULT|scenario_id=thresholds_toml_valid|outcome=FAIL|detail=missing_key_x";
        let (id, outcome_val, detail) =
            e2e_marker::parse_marker(line).ok_or("expected detailed e2e marker")?;
        assert_eq!(id, "thresholds_toml_valid");
        assert_eq!(outcome_val, "FAIL");
        assert_eq!(detail, Some("missing_key_x"));
        Ok(())
    }

    #[test]
    fn e2e_marker_parse_preserves_detail_whitespace() -> Result<(), &'static str> {
        let line =
            "SCENARIO_RESULT|scenario_id=thresholds_toml_valid|outcome=FAIL|detail=missing key  ";
        let (id, outcome_val, detail) =
            e2e_marker::parse_marker(line).ok_or("expected detailed e2e marker")?;
        assert_eq!(id, "thresholds_toml_valid");
        assert_eq!(outcome_val, "FAIL");
        assert_eq!(detail, Some("missing key  "));
        Ok(())
    }

    #[test]
    fn e2e_marker_parse_allows_extension_fields() -> Result<(), &'static str> {
        let line = "SCENARIO_RESULT|scenario_id=mounted_diff_ext4_case|outcome=PASS|duration_ms=7";
        let (id, outcome_val, detail) =
            e2e_marker::parse_marker(line).ok_or("expected extension e2e marker")?;
        assert_eq!(id, "mounted_diff_ext4_case");
        assert_eq!(outcome_val, "PASS");
        assert!(detail.is_none());
        Ok(())
    }

    #[test]
    fn e2e_marker_parse_allows_extension_fields_before_detail() -> Result<(), &'static str> {
        let line = "SCENARIO_RESULT|scenario_id=mounted_diff_ext4_case|outcome=PASS|duration_ms=7|detail=done";
        let (id, outcome_val, detail) =
            e2e_marker::parse_marker(line).ok_or("expected extension e2e marker")?;
        assert_eq!(id, "mounted_diff_ext4_case");
        assert_eq!(outcome_val, "PASS");
        assert_eq!(detail, Some("done"));
        Ok(())
    }

    #[test]
    fn e2e_marker_parse_invalid() {
        assert!(e2e_marker::parse_marker("not a marker").is_none());
        assert!(
            e2e_marker::parse_marker(" SCENARIO_RESULT|scenario_id=valid_test_marker|outcome=PASS")
                .is_none()
        );
        assert!(e2e_marker::parse_marker("SCENARIO_RESULT|outcome=PASS").is_none());
        assert!(e2e_marker::parse_marker("SCENARIO_RESULT|scenario_id=x").is_none());
    }

    #[test]
    fn e2e_marker_parse_rejects_duplicate_core_fields() {
        assert!(
            e2e_marker::parse_marker(
                "SCENARIO_RESULT|scenario_id=first_valid_marker|scenario_id=second_valid_marker|outcome=PASS"
            )
            .is_none()
        );
        assert!(
            e2e_marker::parse_marker(
                "SCENARIO_RESULT|scenario_id=valid_test_marker|outcome=PASS|outcome=FAIL"
            )
            .is_none()
        );
        assert!(
            e2e_marker::parse_marker(
                "SCENARIO_RESULT|scenario_id=valid_test_marker|outcome=FAIL|detail=one|detail=two"
            )
            .is_none()
        );
        assert!(
            e2e_marker::parse_marker(
                "SCENARIO_RESULT|scenario_id=valid_test_marker|outcome=PASS|detail=one|extra=two"
            )
            .is_none()
        );
        assert!(
            e2e_marker::parse_marker(
                "SCENARIO_RESULT|scenario_id=valid_test_marker|outcome=PASS|detail=one|two"
            )
            .is_none()
        );
        assert!(
            e2e_marker::parse_marker(
                "SCENARIO_RESULT|scenario_id=valid_test_marker|outcome=PASS|bad_field"
            )
            .is_none()
        );
        assert!(
            e2e_marker::parse_marker(
                "SCENARIO_RESULT|scenario_id=valid_test_marker|outcome=PASS|=bad"
            )
            .is_none()
        );
        assert!(
            e2e_marker::parse_marker("SCENARIO_RESULT|scenario_id=valid_test_marker|outcome=PASS|")
                .is_none()
        );
    }

    #[test]
    fn e2e_marker_parse_rejects_invalid_contract_fields() {
        assert!(
            e2e_marker::parse_marker("SCENARIO_RESULT|scenario_id=too_short|outcome=PASS")
                .is_none()
        );
        assert!(
            e2e_marker::parse_marker("SCENARIO_RESULT|scenario_id=Upper_case_bad|outcome=PASS")
                .is_none()
        );
        assert!(
            e2e_marker::parse_marker("SCENARIO_RESULT|scenario_id=valid_test_marker|outcome=SKIP")
                .is_none()
        );
        assert!(
            e2e_marker::parse_marker(
                "SCENARIO_RESULT_EXTRA|scenario_id=valid_test_marker|outcome=PASS"
            )
            .is_none()
        );
    }

    #[test]
    fn e2e_marker_scenario_id_validator_matches_documented_shape() {
        assert!(e2e_marker::is_valid_scenario_id("taxonomy_builds_clean"));
        assert!(e2e_marker::is_valid_scenario_id("a1_b2_c3"));
        assert!(!e2e_marker::is_valid_scenario_id(""));
        assert!(!e2e_marker::is_valid_scenario_id("two_segments"));
        assert!(!e2e_marker::is_valid_scenario_id("1starts_with_digit_bad"));
        assert!(!e2e_marker::is_valid_scenario_id("has-hyphen_bad_id"));
        assert!(!e2e_marker::is_valid_scenario_id("has__empty_segment"));
    }

    #[test]
    fn subsystem_targets_are_valid() {
        for (target, crate_name) in SUBSYSTEM_TARGETS {
            assert!(
                target.starts_with("ffs::"),
                "target {target} must start with 'ffs::'",
            );
            assert!(
                crate_name.starts_with("ffs-"),
                "crate {crate_name} must start with 'ffs-'",
            );
        }
    }

    #[test]
    fn subsystem_targets_no_duplicate_targets() {
        let mut targets: Vec<&str> = SUBSYSTEM_TARGETS.iter().map(|(t, _)| *t).collect();
        targets.sort_unstable();
        let original_len = targets.len();
        targets.dedup();
        assert_eq!(
            targets.len(),
            original_len,
            "duplicate subsystem targets found"
        );
    }

    #[test]
    fn duration_field_uses_microseconds() {
        // Contract invariant: the canonical duration field is _us (microseconds).
        assert!(field::DURATION_US.ends_with("_us"));
    }

    #[test]
    fn log_severity_roundtrip_json() -> Result<(), serde_json::Error> {
        for severity in [
            LogSeverity::Trace,
            LogSeverity::Debug,
            LogSeverity::Info,
            LogSeverity::Warn,
            LogSeverity::Error,
        ] {
            let json = serde_json::to_string(&severity)?;
            let parsed: LogSeverity = serde_json::from_str(&json)?;
            assert_eq!(parsed, severity);
        }
        Ok(())
    }

    #[test]
    fn error_category_roundtrip_json() -> Result<(), serde_json::Error> {
        for cat in [
            ErrorCategory::Precondition,
            ErrorCategory::Io,
            ErrorCategory::Integrity,
            ErrorCategory::Concurrency,
            ErrorCategory::Resource,
            ErrorCategory::Validation,
            ErrorCategory::Internal,
        ] {
            let json = serde_json::to_string(&cat)?;
            let parsed: ErrorCategory = serde_json::from_str(&json)?;
            assert_eq!(parsed, cat);
        }
        Ok(())
    }
}
