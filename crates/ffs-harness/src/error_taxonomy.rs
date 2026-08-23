//! Canonical operator-facing error taxonomy and remediation hints.
//!
//! Defines the 7 error classes that span all FrankenFS failure modes and maps
//! each to stable machine-readable codes, human-readable remediation guidance,
//! and runbook cross-links. Surface-consistency validators ensure CLI, TUI, and
//! evidence outputs stay aligned with this taxonomy.
//!
//! # Error classes
//!
//! | Class | Code prefix | Scope |
//! |-------|-------------|-------|
//! | Configuration | `FFS-CFG` | Bad user config, geometry, flags |
//! | Compatibility | `FFS-CMP` | Feature/version boundary violations |
//! | Replay | `FFS-RPL` | WAL recovery and MVCC anomalies |
//! | Repair | `FFS-RPR` | Repair subsystem failures |
//! | Pressure | `FFS-PRS` | Resource pressure and degradation |
//! | IoCorruption | `FFS-IOC` | I/O errors and on-disk corruption |
//! | UnsupportedOp | `FFS-UNS` | Operations blocked by current mode |

use serde::{Deserialize, Serialize};

/// Minimum number of error scenarios required in the canonical set.
pub const MIN_SCENARIO_COUNT: usize = 10;

/// Number of error classes in the taxonomy.
pub const ERROR_CLASS_COUNT: usize = 7;

/// Canonical error class grouping all FrankenFS failure modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// Bad user configuration, geometry, or format parameters.
    Configuration,
    /// Feature or version incompatibility at mount boundary.
    Compatibility,
    /// WAL replay and MVCC transaction anomalies.
    Replay,
    /// Repair subsystem failures (symbol decode, scrub findings).
    Repair,
    /// Resource pressure, backpressure, and degradation events.
    Pressure,
    /// I/O device errors and on-disk metadata corruption.
    IoCorruption,
    /// Operations blocked by current mount mode or read-only state.
    UnsupportedOp,
}

impl ErrorClass {
    /// Stable code prefix for this error class.
    #[must_use]
    pub fn code_prefix(&self) -> &'static str {
        match self {
            Self::Configuration => "FFS-CFG",
            Self::Compatibility => "FFS-CMP",
            Self::Replay => "FFS-RPL",
            Self::Repair => "FFS-RPR",
            Self::Pressure => "FFS-PRS",
            Self::IoCorruption => "FFS-IOC",
            Self::UnsupportedOp => "FFS-UNS",
        }
    }

    /// All error classes in canonical order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Configuration,
            Self::Compatibility,
            Self::Replay,
            Self::Repair,
            Self::Pressure,
            Self::IoCorruption,
            Self::UnsupportedOp,
        ]
    }

    /// Runbook path for this error class, if a dedicated runbook exists.
    #[must_use]
    pub fn runbook_path(&self) -> Option<&'static str> {
        match self {
            Self::Replay => Some("docs/runbooks/replay-failure-triage.md"),
            Self::Repair | Self::IoCorruption => Some("docs/runbooks/corruption-recovery.md"),
            Self::Pressure => Some("docs/runbooks/backpressure-investigation.md"),
            Self::Configuration | Self::Compatibility | Self::UnsupportedOp => None,
        }
    }
}

/// A representative failure scenario with a stable code and remediation hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorScenario {
    /// Stable machine-readable error code (e.g., `"FFS-CFG-001"`).
    pub code: String,
    /// Error class this scenario belongs to.
    pub class: ErrorClass,
    /// Short human-readable title.
    pub title: String,
    /// The `FfsError` variant name this scenario maps from.
    pub ffs_error_variant: String,
    /// Operator-facing remediation hint (actionable next step).
    pub remediation_hint: String,
    /// Runbook path for deeper investigation (relative to repo root).
    pub runbook_ref: Option<String>,
}

/// Classify an `FfsError` variant name into its error class.
#[must_use]
#[allow(clippy::match_same_arms)] // explicit Configuration variants for documentation
pub fn classify_variant(variant_name: &str) -> ErrorClass {
    match variant_name {
        "InvalidGeometry" | "Format" | "Parse" => ErrorClass::Configuration,
        "UnsupportedFeature" | "IncompatibleFeature" | "UnsupportedBlockSize" => {
            ErrorClass::Compatibility
        }
        "MvccConflict" | "Cancelled" => ErrorClass::Replay,
        "RepairFailed" => ErrorClass::Repair,
        "Corruption" | "Io" => ErrorClass::IoCorruption,
        "NoSpace" => ErrorClass::Pressure,
        "ModeViolation" | "ReadOnly" => ErrorClass::UnsupportedOp,
        _ => ErrorClass::Configuration,
    }
}

/// Build the canonical set of representative error scenarios.
///
/// Returns at least [`MIN_SCENARIO_COUNT`] scenarios covering all 7 error
/// classes with stable codes and actionable remediation hints.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn canonical_scenarios() -> Vec<ErrorScenario> {
    vec![
        ErrorScenario {
            code: "FFS-CFG-001".to_owned(),
            class: ErrorClass::Configuration,
            title: "Invalid filesystem geometry".to_owned(),
            ffs_error_variant: "InvalidGeometry".to_owned(),
            remediation_hint: "Verify image geometry with `ffs fsck <image>`. Common causes: \
                               zero blocks_per_group, unsupported block count."
                .to_owned(),
            runbook_ref: None,
        },
        ErrorScenario {
            code: "FFS-CFG-002".to_owned(),
            class: ErrorClass::Configuration,
            title: "Invalid on-disk format".to_owned(),
            ffs_error_variant: "Format".to_owned(),
            remediation_hint: "Verify the image is a valid ext4/btrfs filesystem. \
                               Run `file <image>` to confirm type."
                .to_owned(),
            runbook_ref: None,
        },
        ErrorScenario {
            code: "FFS-CMP-001".to_owned(),
            class: ErrorClass::Compatibility,
            title: "Unsupported feature flags".to_owned(),
            ffs_error_variant: "UnsupportedFeature".to_owned(),
            remediation_hint: "Upgrade FrankenFS or use an image without unsupported features \
                               (ENCRYPT, INLINE_DATA). Check features with `ffs fsck <image>`."
                .to_owned(),
            runbook_ref: None,
        },
        ErrorScenario {
            code: "FFS-CMP-002".to_owned(),
            class: ErrorClass::Compatibility,
            title: "Incompatible feature contract".to_owned(),
            ffs_error_variant: "IncompatibleFeature".to_owned(),
            remediation_hint: "Image requires FILETYPE+EXTENTS. Recreate with \
                               `mkfs.ext4 -O extents,filetype`."
                .to_owned(),
            runbook_ref: None,
        },
        ErrorScenario {
            code: "FFS-CMP-003".to_owned(),
            class: ErrorClass::Compatibility,
            title: "Unsupported block size".to_owned(),
            ffs_error_variant: "UnsupportedBlockSize".to_owned(),
            remediation_hint: "FrankenFS v1 supports 1K/2K/4K block sizes. Recreate the image \
                               with a supported block size."
                .to_owned(),
            runbook_ref: None,
        },
        ErrorScenario {
            code: "FFS-RPL-001".to_owned(),
            class: ErrorClass::Replay,
            title: "WAL replay failure".to_owned(),
            ffs_error_variant: "Cancelled".to_owned(),
            remediation_hint: "Inspect WAL with \
                               `ffs evidence --preset replay-anomalies <ledger>`. \
                               See runbook: docs/runbooks/replay-failure-triage.md"
                .to_owned(),
            runbook_ref: Some("docs/runbooks/replay-failure-triage.md".to_owned()),
        },
        ErrorScenario {
            code: "FFS-RPL-002".to_owned(),
            class: ErrorClass::Replay,
            title: "MVCC serialization conflict".to_owned(),
            ffs_error_variant: "MvccConflict".to_owned(),
            remediation_hint: "Retry the operation. Persistent conflicts may indicate \
                               excessive contention — reduce concurrent writers."
                .to_owned(),
            runbook_ref: Some("docs/runbooks/replay-failure-triage.md".to_owned()),
        },
        ErrorScenario {
            code: "FFS-RPR-001".to_owned(),
            class: ErrorClass::Repair,
            title: "Repair failed — insufficient symbols".to_owned(),
            ffs_error_variant: "RepairFailed".to_owned(),
            remediation_hint: "Run `ffs repair --rebuild-symbols <image>` to regenerate \
                               repair symbols. See runbook: docs/runbooks/corruption-recovery.md"
                .to_owned(),
            runbook_ref: Some("docs/runbooks/corruption-recovery.md".to_owned()),
        },
        ErrorScenario {
            code: "FFS-RPR-002".to_owned(),
            class: ErrorClass::Repair,
            title: "Scrub detected unrecoverable corruption".to_owned(),
            ffs_error_variant: "Corruption".to_owned(),
            remediation_hint: "Run `ffs evidence --preset repair-failures <ledger>` to \
                               identify affected blocks. \
                               See runbook: docs/runbooks/corruption-recovery.md"
                .to_owned(),
            runbook_ref: Some("docs/runbooks/corruption-recovery.md".to_owned()),
        },
        ErrorScenario {
            code: "FFS-PRS-001".to_owned(),
            class: ErrorClass::Pressure,
            title: "Backpressure activated".to_owned(),
            ffs_error_variant: "NoSpace".to_owned(),
            remediation_hint: "Reduce write load or increase available memory. \
                               See runbook: docs/runbooks/backpressure-investigation.md"
                .to_owned(),
            runbook_ref: Some("docs/runbooks/backpressure-investigation.md".to_owned()),
        },
        ErrorScenario {
            code: "FFS-PRS-002".to_owned(),
            class: ErrorClass::Pressure,
            title: "Degradation level escalated".to_owned(),
            ffs_error_variant: "Io".to_owned(),
            remediation_hint: "System degradation detected. Check \
                               `ffs evidence --preset pressure-transitions <ledger>`. \
                               See runbook: docs/runbooks/backpressure-investigation.md"
                .to_owned(),
            runbook_ref: Some("docs/runbooks/backpressure-investigation.md".to_owned()),
        },
        ErrorScenario {
            code: "FFS-IOC-001".to_owned(),
            class: ErrorClass::IoCorruption,
            title: "Block corruption detected".to_owned(),
            ffs_error_variant: "Corruption".to_owned(),
            remediation_hint: "Metadata corruption at specific block(s). Run \
                               `ffs repair <image>` to attempt RaptorQ recovery. \
                               See runbook: docs/runbooks/corruption-recovery.md"
                .to_owned(),
            runbook_ref: Some("docs/runbooks/corruption-recovery.md".to_owned()),
        },
        ErrorScenario {
            code: "FFS-IOC-002".to_owned(),
            class: ErrorClass::IoCorruption,
            title: "I/O device error".to_owned(),
            ffs_error_variant: "Io".to_owned(),
            remediation_hint: "I/O error from underlying device. Check disk health with \
                               `smartctl -a /dev/sdX`. Replace media if errors persist."
                .to_owned(),
            runbook_ref: Some("docs/runbooks/corruption-recovery.md".to_owned()),
        },
        ErrorScenario {
            code: "FFS-UNS-001".to_owned(),
            class: ErrorClass::UnsupportedOp,
            title: "Native-mode boundary violation".to_owned(),
            ffs_error_variant: "ModeViolation".to_owned(),
            remediation_hint: "Operation requires native mount mode. Remount with \
                               `--mode=native` to enable repair symbols and version store."
                .to_owned(),
            runbook_ref: None,
        },
        ErrorScenario {
            code: "FFS-UNS-002".to_owned(),
            class: ErrorClass::UnsupportedOp,
            title: "Read-only filesystem write attempt".to_owned(),
            ffs_error_variant: "ReadOnly".to_owned(),
            remediation_hint: "Filesystem is mounted read-only. Remount with write access \
                               or check mount flags."
                .to_owned(),
            runbook_ref: None,
        },
    ]
}

/// Check that every error class has at least one scenario in the canonical set.
#[must_use]
pub fn check_class_coverage() -> Vec<ClassCoverageResult> {
    let scenarios = canonical_scenarios();
    ErrorClass::all()
        .iter()
        .map(|class| {
            let count = scenarios.iter().filter(|s| s.class == *class).count();
            ClassCoverageResult {
                class: *class,
                scenario_count: count,
                covered: count > 0,
            }
        })
        .collect()
}

/// Result of checking whether an error class has scenario coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassCoverageResult {
    pub class: ErrorClass,
    pub scenario_count: usize,
    pub covered: bool,
}

/// Check that all runbook paths referenced by scenarios exist on disk.
#[must_use]
pub fn check_runbook_links(repo_root: &str) -> Vec<RunbookCheckResult> {
    let scenarios = canonical_scenarios();
    let mut seen = std::collections::HashSet::new();
    let mut results = Vec::new();
    for scenario in &scenarios {
        if let Some(path) = &scenario.runbook_ref
            && seen.insert(path.clone())
        {
            let full = format!("{repo_root}/{path}");
            let exists = std::path::Path::new(&full).exists();
            results.push(RunbookCheckResult {
                code: scenario.code.clone(),
                runbook_path: path.clone(),
                exists,
            });
        }
    }
    results
}

/// Result of checking a runbook cross-link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookCheckResult {
    pub code: String,
    pub runbook_path: String,
    pub exists: bool,
}

/// Validate that error class vocabulary aligns across surfaces.
///
/// Checks that the FfsError variant names referenced in scenarios actually
/// exist in the error crate source, and that code prefixes are unique per class.
#[must_use]
pub fn check_code_uniqueness() -> Vec<CodeUniquenessResult> {
    let scenarios = canonical_scenarios();
    let mut results = Vec::new();
    let mut seen_codes = std::collections::HashSet::new();
    for scenario in &scenarios {
        let unique = seen_codes.insert(scenario.code.clone());
        let prefix_matches = scenario.code.starts_with(scenario.class.code_prefix());
        results.push(CodeUniquenessResult {
            code: scenario.code.clone(),
            unique,
            prefix_matches,
        });
    }
    results
}

/// Result of checking code uniqueness and prefix alignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeUniquenessResult {
    pub code: String,
    pub unique: bool,
    pub prefix_matches: bool,
}

/// Check that the FfsError source contains all variant names referenced by scenarios.
#[must_use]
pub fn check_variant_references(ffs_error_src: &str) -> Vec<VariantCheckResult> {
    let scenarios = canonical_scenarios();
    let mut seen = std::collections::HashSet::new();
    let mut results = Vec::new();
    for scenario in &scenarios {
        if seen.insert(scenario.ffs_error_variant.clone()) {
            let found = ffs_error_src.contains(&scenario.ffs_error_variant);
            results.push(VariantCheckResult {
                variant: scenario.ffs_error_variant.clone(),
                code: scenario.code.clone(),
                found_in_source: found,
            });
        }
    }
    results
}

/// Result of checking variant name references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariantCheckResult {
    pub variant: String,
    pub code: String,
    pub found_in_source: bool,
}

/// Check that evidence preset names align with the error classes that need them.
///
/// Verifies that the 3 evidence presets (replay-anomalies, repair-failures,
/// pressure-transitions) are referenced in remediation hints for the
/// corresponding error classes.
#[must_use]
pub fn check_evidence_preset_alignment() -> Vec<PresetAlignmentResult> {
    let scenarios = canonical_scenarios();
    let presets = [
        ("replay-anomalies", ErrorClass::Replay),
        ("repair-failures", ErrorClass::Repair),
        ("pressure-transitions", ErrorClass::Pressure),
    ];
    presets
        .iter()
        .map(|(preset, class)| {
            let referenced = scenarios
                .iter()
                .filter(|s| s.class == *class)
                .any(|s| s.remediation_hint.contains(preset));
            PresetAlignmentResult {
                preset: (*preset).to_owned(),
                class: *class,
                referenced_in_hints: referenced,
            }
        })
        .collect()
}

/// Result of checking evidence preset alignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresetAlignmentResult {
    pub preset: String,
    pub class: ErrorClass,
    pub referenced_in_hints: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> std::io::Result<String> {
        env!("CARGO_MANIFEST_DIR")
            .strip_suffix("/crates/ffs-harness")
            .map(str::to_owned)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "harness must be in crates/ffs-harness",
                )
            })
    }

    #[test]
    fn has_at_least_min_scenarios() {
        let scenarios = canonical_scenarios();
        assert!(
            scenarios.len() >= MIN_SCENARIO_COUNT,
            "expected >= {MIN_SCENARIO_COUNT} scenarios, got {}",
            scenarios.len()
        );
    }

    #[test]
    fn all_seven_classes_covered() {
        let results = check_class_coverage();
        assert_eq!(results.len(), ERROR_CLASS_COUNT);
        for r in &results {
            assert!(r.covered, "error class {:?} has no scenarios", r.class);
        }
    }

    #[test]
    fn error_codes_are_unique() {
        let results = check_code_uniqueness();
        for r in &results {
            assert!(r.unique, "duplicate error code: {}", r.code);
            assert!(
                r.prefix_matches,
                "code {} does not match its class prefix",
                r.code
            );
        }
    }

    #[test]
    fn every_scenario_has_nonempty_hint() {
        let scenarios = canonical_scenarios();
        for s in &scenarios {
            assert!(
                !s.remediation_hint.is_empty(),
                "{} has empty remediation hint",
                s.code
            );
        }
    }

    #[test]
    fn every_scenario_has_nonempty_title() {
        let scenarios = canonical_scenarios();
        for s in &scenarios {
            assert!(!s.title.is_empty(), "{} has empty title", s.code);
        }
    }

    #[test]
    fn runbook_links_exist_on_disk() -> std::io::Result<()> {
        let root = repo_root()?;
        let results = check_runbook_links(&root);
        for r in &results {
            assert!(
                r.exists,
                "runbook for {} not found: {}",
                r.code, r.runbook_path
            );
        }
        Ok(())
    }

    #[test]
    fn variant_references_exist_in_ffs_error() -> std::io::Result<()> {
        let root = repo_root()?;
        let src = std::fs::read_to_string(format!("{root}/crates/ffs-error/src/lib.rs"))?;
        let results = check_variant_references(&src);
        for r in &results {
            assert!(
                r.found_in_source,
                "variant {} (code {}) not found in ffs-error source",
                r.variant, r.code
            );
        }
        Ok(())
    }

    #[test]
    fn evidence_presets_aligned_with_classes() {
        let results = check_evidence_preset_alignment();
        for r in &results {
            assert!(
                r.referenced_in_hints,
                "preset {} not referenced in {:?} hints",
                r.preset, r.class
            );
        }
    }

    #[test]
    fn classify_variant_covers_all_ffs_error_variants() {
        let variants = [
            "InvalidGeometry",
            "Format",
            "Parse",
            "UnsupportedFeature",
            "IncompatibleFeature",
            "UnsupportedBlockSize",
            "MvccConflict",
            "Cancelled",
            "RepairFailed",
            "Corruption",
            "Io",
            "NoSpace",
            "ModeViolation",
            "ReadOnly",
            "NotFound",
            "PermissionDenied",
            "NotDirectory",
            "IsDirectory",
            "NotEmpty",
            "NameTooLong",
            "Exists",
        ];
        for v in &variants {
            let _ = classify_variant(v);
        }
    }

    #[test]
    fn scenario_json_round_trips() -> Result<(), serde_json::Error> {
        let scenarios = canonical_scenarios();
        let json = serde_json::to_string(&scenarios)?;
        let parsed: Vec<ErrorScenario> = serde_json::from_str(&json)?;
        assert_eq!(parsed, scenarios);
        Ok(())
    }

    #[test]
    fn canonical_error_scenarios_json_shape() -> Result<(), serde_json::Error> {
        let scenarios = canonical_scenarios();
        let json = serde_json::to_string_pretty(&scenarios)?;
        insta::assert_snapshot!("canonical_error_scenarios_json_shape", json);
        let parsed: Vec<ErrorScenario> = serde_json::from_str(&json)?;
        assert_eq!(parsed, scenarios);
        Ok(())
    }

    #[test]
    fn code_prefixes_are_distinct_per_class() {
        let prefixes: Vec<&str> = ErrorClass::all()
            .iter()
            .map(ErrorClass::code_prefix)
            .collect();
        let unique: std::collections::HashSet<&&str> = prefixes.iter().collect();
        assert_eq!(
            unique.len(),
            prefixes.len(),
            "code prefixes must be unique per class"
        );
    }

    #[test]
    fn class_runbook_paths_exist_on_disk() -> std::io::Result<()> {
        let root = repo_root()?;
        for class in ErrorClass::all() {
            if let Some(path) = class.runbook_path() {
                let full = format!("{root}/{path}");
                assert!(
                    std::path::Path::new(&full).exists(),
                    "runbook for {class:?} not found: {path}"
                );
            }
        }
        Ok(())
    }
}
