//! Crash minimization and auto-promotion pipeline for fuzz artifacts.
//!
//! Provides a structured workflow for converting fuzz-discovered crashes into
//! deterministic regression tests:
//!
//! 1. **Discover** — scan campaign artifacts for crash files.
//! 2. **Minimize** — shrink crash inputs via `cargo fuzz tmin`.
//! 3. **Promote** — generate a regression test file with metadata tags.
//! 4. **Validate** — verify the regression test compiles and the corpus seed exists.
//!
//! Each promoted test is tagged with metadata linking it back to the originating
//! crash artifact (target, campaign ID, commit SHA, timestamp).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

fn sanitize_path_component(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "unknown".to_owned()
    } else {
        sanitized
    }
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':'))
        && !value.is_empty()
    {
        return value.to_owned();
    }

    let mut quoted = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn rust_string_literal_contents(value: &str) -> String {
    value.escape_default().to_string()
}

fn manifest_fuzz_targets(repo_root: &Path) -> Vec<String> {
    let manifest_path = repo_root.join("fuzz").join("Cargo.toml");
    let Ok(contents) = std::fs::read_to_string(&manifest_path) else {
        return Vec::new();
    };

    let mut targets = contents
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let name = trimmed.strip_prefix("name = \"")?.strip_suffix('"')?;
            name.starts_with("fuzz_").then(|| name.to_owned())
        })
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    targets
}

fn source_fuzz_targets(repo_root: &Path) -> Vec<String> {
    let targets_dir = repo_root.join("fuzz").join("fuzz_targets");
    let Ok(entries) = std::fs::read_dir(&targets_dir) else {
        return Vec::new();
    };

    let mut targets = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "rs") {
                return None;
            }
            path.file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
        })
        .collect::<Vec<_>>();
    targets.sort();
    targets
}

fn fuzz_target_registration_check(
    source_targets: &[String],
    manifest_targets: &[String],
) -> PipelineCheck {
    let unregistered_source_targets = source_targets
        .iter()
        .filter(|target| !manifest_targets.contains(target))
        .cloned()
        .collect::<Vec<_>>();

    PipelineCheck {
        component: "fuzz_target_registration".to_owned(),
        passed: unregistered_source_targets.is_empty(),
        detail: if unregistered_source_targets.is_empty() {
            format!(
                "{} source fuzz targets are registered in fuzz/Cargo.toml",
                source_targets.len()
            )
        } else {
            format!(
                "unregistered source fuzz targets: {}",
                unregistered_source_targets.join(", ")
            )
        },
    }
}

fn pipeline_script_check(repo_root: &Path, component: &str, script_name: &str) -> PipelineCheck {
    let path = repo_root.join("fuzz").join("scripts").join(script_name);
    let found = path.exists();
    PipelineCheck {
        component: component.to_owned(),
        passed: found,
        detail: if found {
            format!("{script_name} found")
        } else {
            format!("{script_name} missing")
        },
    }
}

/// A discovered crash artifact from a fuzz campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashArtifact {
    /// Fuzz target that discovered this crash.
    pub target: String,
    /// Path to the crash-reproducing input file.
    pub crash_path: PathBuf,
    /// Campaign ID (timestamp-based) if from a nightly run.
    pub campaign_id: Option<String>,
    /// Git commit SHA at time of discovery.
    pub commit_sha: Option<String>,
    /// Whether this crash has been minimized.
    pub minimized: bool,
    /// Size of the crash input in bytes.
    pub input_size: u64,
}

/// Metadata tag embedded in promoted regression tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionTag {
    /// Originating fuzz target.
    pub target: String,
    /// Campaign ID (if from nightly).
    pub campaign_id: String,
    /// Commit SHA at discovery.
    pub commit_sha: String,
    /// Timestamp of promotion.
    pub promoted_at: String,
    /// Whether the input was minimized before promotion.
    pub minimized: bool,
    /// Corpus seed filename.
    pub corpus_seed: String,
}

/// A promoted regression test case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionCase {
    /// Test function name (e.g., `regression_fuzz_ext4_metadata_20260312`).
    pub test_name: String,
    /// Metadata linking back to the crash.
    pub tag: RegressionTag,
    /// Path where the corpus seed is stored.
    pub seed_path: PathBuf,
    /// Path where the regression test source would be generated.
    pub test_path: PathBuf,
}

/// Promotion step outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionStep {
    Discovered,
    Minimized,
    SeedCopied,
    TestGenerated,
    Validated,
}

/// Result of a promotion attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionResult {
    pub crash: CrashArtifact,
    pub steps_completed: Vec<PromotionStep>,
    pub regression_case: Option<RegressionCase>,
    pub error: Option<String>,
}

/// Scan a campaign directory for crash artifacts.
#[must_use]
pub fn discover_crashes(campaign_dir: &Path) -> Vec<CrashArtifact> {
    let mut crashes = Vec::new();
    if !campaign_dir.exists() {
        return crashes;
    }

    let Ok(entries) = std::fs::read_dir(campaign_dir) else {
        return crashes;
    };

    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        let target = entry.file_name().to_string_lossy().into_owned();
        if !target.starts_with("fuzz_") {
            continue;
        }

        let target_dir = entry.path();
        let candidate_dirs = [target_dir.join("crashes"), target_dir];

        for search_dir in candidate_dirs {
            let Ok(dir_entries) = std::fs::read_dir(&search_dir) else {
                continue;
            };
            for candidate in dir_entries.flatten() {
                let path = candidate.path();
                let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if !path.is_file() || !file_name.starts_with("crash-") {
                    continue;
                }

                let size = std::fs::metadata(&path).map_or(0, |m| m.len());
                crashes.push(CrashArtifact {
                    target: target.clone(),
                    crash_path: path,
                    campaign_id: campaign_dir
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned()),
                    commit_sha: None,
                    minimized: false,
                    input_size: size,
                });
            }
        }
    }
    crashes
}

/// Generate the `cargo fuzz tmin` command for minimizing a crash input.
#[must_use]
pub fn minimize_command(target: &str, crash_path: &Path) -> String {
    format!(
        "cargo fuzz tmin {} --fuzz-dir fuzz -- {}",
        shell_quote(target),
        shell_quote(&crash_path.to_string_lossy())
    )
}

/// Generate the corpus seed filename from a crash artifact.
#[must_use]
pub fn seed_filename(crash: &CrashArtifact) -> String {
    let campaign = crash.campaign_id.as_deref().unwrap_or("manual");
    format!(
        "regression_{}_{}_{}bytes",
        sanitize_path_component(&crash.target),
        sanitize_path_component(campaign),
        crash.input_size
    )
}

/// Generate the regression test function name.
#[must_use]
pub fn test_function_name(crash: &CrashArtifact) -> String {
    let campaign = crash.campaign_id.as_deref().unwrap_or("manual");
    // Sanitize for Rust identifier
    let sanitized: String = format!("regression_{}_{}", crash.target, campaign)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    sanitized
}

/// Generate the Rust source for a regression test function.
///
/// The generated test loads the corpus seed and feeds it to the same parser
/// exercised by the fuzz target, ensuring panic-freedom is preserved.
#[must_use]
pub fn generate_regression_test_source(case: &RegressionCase) -> String {
    let tag = &case.tag;
    let seed_path = rust_string_literal_contents(&case.seed_path.display().to_string());
    format!(
        r#"/// Regression test promoted from fuzz crash.
///
/// - Fuzz target: `{target}`
/// - Campaign: `{campaign_id}`
/// - Commit at discovery: `{commit_sha}`
/// - Promoted: `{promoted_at}`
/// - Minimized: `{minimized}`
/// - Corpus seed: `{corpus_seed}`
#[test]
fn {test_name}() -> std::io::Result<()> {{
    let seed = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("{seed_path}")
    )?;

    // Feed to the same parser as the fuzz target; parsing failures are acceptable.
    let _ = ffs_ondisk::Ext4Superblock::parse_superblock_region(&seed);
    let _ = ffs_ondisk::Ext4Inode::parse_from_bytes(&seed);
    let _ = ffs_ondisk::Ext4GroupDesc::parse_from_bytes(&seed, 32);
    let _ = ffs_ondisk::Ext4GroupDesc::parse_from_bytes(&seed, 64);
    let _ = ffs_ondisk::parse_dir_block(&seed, 4096);
    let _ = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(&seed);
    Ok(())
}}
"#,
        target = tag.target,
        campaign_id = tag.campaign_id,
        commit_sha = tag.commit_sha,
        promoted_at = tag.promoted_at,
        minimized = tag.minimized,
        corpus_seed = tag.corpus_seed,
        test_name = case.test_name,
        seed_path = seed_path,
    )
}

/// Validate the promotion pipeline structure is intact.
///
/// Checks that all required infrastructure exists: fuzz targets, corpus dirs,
/// crash artifact dir, minimize script, and regression test directory.
#[must_use]
pub fn validate_pipeline(repo_root: &str) -> Vec<PipelineCheck> {
    let mut checks = Vec::new();
    let repo_root_path = Path::new(repo_root);
    let manifest_targets = manifest_fuzz_targets(repo_root_path);
    let source_targets = source_fuzz_targets(repo_root_path);
    let target_count = manifest_targets.len();
    let missing_source_targets = manifest_targets
        .iter()
        .filter(|target| !source_targets.contains(target))
        .cloned()
        .collect::<Vec<_>>();

    // Check fuzz targets exist
    checks.push(PipelineCheck {
        component: "fuzz_targets".to_owned(),
        passed: target_count > 0 && missing_source_targets.is_empty(),
        detail: if missing_source_targets.is_empty() {
            format!("{target_count} manifest targets have matching source files")
        } else {
            format!(
                "{target_count} manifest targets, missing source files for {}",
                missing_source_targets.join(", ")
            )
        },
    });

    // Check source fuzz targets are registered so checked-in fuzzers run in campaigns.
    checks.push(fuzz_target_registration_check(
        &source_targets,
        &manifest_targets,
    ));

    // Check corpus directories exist
    let corpus_count = manifest_targets
        .iter()
        .filter(|t| Path::new(&format!("{repo_root}/fuzz/corpus/{t}")).is_dir())
        .count();
    checks.push(PipelineCheck {
        component: "corpus_dirs".to_owned(),
        passed: target_count > 0 && corpus_count == target_count,
        detail: format!("{corpus_count}/{target_count} corpus directories found"),
    });

    // Check minimize script exists
    checks.push(pipeline_script_check(
        repo_root_path,
        "minimize_script",
        "minimize_corpus.sh",
    ));

    // Check nightly campaign script exists
    checks.push(pipeline_script_check(
        repo_root_path,
        "nightly_script",
        "nightly_fuzz.sh",
    ));

    // Check crash promotion script exists
    checks.push(pipeline_script_check(
        repo_root_path,
        "promote_script",
        "promote_crash.sh",
    ));

    // Check dictionaries exist
    let dict_count = ["ext4.dict", "btrfs.dict"]
        .iter()
        .filter(|d| Path::new(&format!("{repo_root}/fuzz/dictionaries/{d}")).exists())
        .count();
    checks.push(PipelineCheck {
        component: "dictionaries".to_owned(),
        passed: dict_count == 2,
        detail: format!("{dict_count}/2 dictionaries found"),
    });

    // Check adversarial corpus exists
    let adversarial_exists = Path::new(&format!("{repo_root}/tests/fuzz_corpus")).is_dir();
    checks.push(PipelineCheck {
        component: "adversarial_corpus".to_owned(),
        passed: adversarial_exists,
        detail: if adversarial_exists {
            "adversarial corpus directory found".to_owned()
        } else {
            "adversarial corpus directory missing".to_owned()
        },
    });

    // Check artifact manifest includes fuzz categories
    let manifest_src = format!("{repo_root}/crates/ffs-harness/src/artifact_manifest.rs");
    let manifest_has_fuzz = std::fs::read_to_string(&manifest_src)
        .is_ok_and(|s| s.contains("FuzzCrash") && s.contains("FuzzCorpus"));
    checks.push(PipelineCheck {
        component: "artifact_manifest".to_owned(),
        passed: manifest_has_fuzz,
        detail: if manifest_has_fuzz {
            "FuzzCrash + FuzzCorpus in artifact manifest".to_owned()
        } else {
            "artifact manifest missing fuzz categories".to_owned()
        },
    });

    checks
}

/// Result of checking a pipeline component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineCheck {
    pub component: String,
    pub passed: bool,
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn repo_root() -> std::io::Result<String> {
        env!("CARGO_MANIFEST_DIR")
            .strip_suffix("/crates/ffs-harness")
            .map(ToOwned::to_owned)
            .ok_or_else(|| std::io::Error::other("harness must be in crates/ffs-harness"))
    }

    fn write_minimal_pipeline_fixture(
        root: &Path,
        manifest_targets: &[&str],
        source_targets: &[&str],
        include_promote_script: bool,
    ) -> std::io::Result<()> {
        let fuzz_dir = root.join("fuzz");
        let source_dir = fuzz_dir.join("fuzz_targets");
        let corpus_dir = fuzz_dir.join("corpus");
        let script_dir = fuzz_dir.join("scripts");
        let dictionary_dir = fuzz_dir.join("dictionaries");
        let artifact_manifest_dir = root.join("crates/ffs-harness/src");

        std::fs::create_dir_all(&source_dir)?;
        std::fs::create_dir_all(&corpus_dir)?;
        std::fs::create_dir_all(&script_dir)?;
        std::fs::create_dir_all(&dictionary_dir)?;
        std::fs::create_dir_all(root.join("tests/fuzz_corpus"))?;
        std::fs::create_dir_all(&artifact_manifest_dir)?;

        let mut manifest = String::new();
        for target in manifest_targets {
            manifest.push_str("[[bin]]\nname = \"");
            manifest.push_str(target);
            manifest.push_str("\"\npath = \"fuzz_targets/");
            manifest.push_str(target);
            manifest.push_str(".rs\"\ntest = false\ndoc = false\nbench = false\n\n");
        }
        std::fs::write(fuzz_dir.join("Cargo.toml"), manifest)?;

        for target in manifest_targets {
            std::fs::create_dir_all(corpus_dir.join(target))?;
        }
        for target in source_targets {
            std::fs::write(source_dir.join(format!("{target}.rs")), "fn main() {}\n")?;
        }

        std::fs::write(script_dir.join("minimize_corpus.sh"), "#!/bin/sh\n")?;
        std::fs::write(script_dir.join("nightly_fuzz.sh"), "#!/bin/sh\n")?;
        if include_promote_script {
            std::fs::write(script_dir.join("promote_crash.sh"), "#!/bin/sh\n")?;
        }
        std::fs::write(dictionary_dir.join("ext4.dict"), "\"ext4\"\n")?;
        std::fs::write(dictionary_dir.join("btrfs.dict"), "\"btrfs\"\n")?;
        std::fs::write(
            artifact_manifest_dir.join("artifact_manifest.rs"),
            "enum ArtifactKind { FuzzCrash, FuzzCorpus }\n",
        )?;

        Ok(())
    }

    #[test]
    fn manifest_targets_match_source_files() -> TestResult {
        let root = repo_root()?;
        let targets = manifest_fuzz_targets(Path::new(&root));
        assert!(
            !targets.is_empty(),
            "fuzz/Cargo.toml should register at least one fuzz target"
        );
        for target in &targets {
            let path = format!("{root}/fuzz/fuzz_targets/{target}.rs");
            assert!(
                Path::new(&path).exists(),
                "fuzz target {target}.rs not found at {path}"
            );
        }
        Ok(())
    }

    #[test]
    fn pipeline_validation_rejects_unregistered_source_targets() -> TestResult {
        let temp = tempfile::tempdir()?;
        write_minimal_pipeline_fixture(
            temp.path(),
            &["fuzz_registered"],
            &["fuzz_registered", "fuzz_unregistered"],
            true,
        )?;

        let root = temp
            .path()
            .to_str()
            .ok_or_else(|| std::io::Error::other("temp path must be utf-8"))?;
        let checks = validate_pipeline(root);
        let registration = checks
            .iter()
            .find(|check| check.component == "fuzz_target_registration")
            .ok_or_else(|| std::io::Error::other("registration check missing"))?;

        assert!(
            !registration.passed,
            "source-only fuzz target should fail registration check"
        );
        assert!(
            registration.detail.contains("fuzz_unregistered"),
            "registration detail should identify the source-only target: {}",
            registration.detail
        );
        Ok(())
    }

    #[test]
    fn pipeline_validation_rejects_missing_promote_script() -> TestResult {
        let temp = tempfile::tempdir()?;
        write_minimal_pipeline_fixture(
            temp.path(),
            &["fuzz_registered"],
            &["fuzz_registered"],
            false,
        )?;

        let root = temp
            .path()
            .to_str()
            .ok_or_else(|| std::io::Error::other("temp path must be utf-8"))?;
        let checks = validate_pipeline(root);
        let promote = checks
            .iter()
            .find(|check| check.component == "promote_script")
            .ok_or_else(|| std::io::Error::other("promote script check missing"))?;

        assert!(
            !promote.passed,
            "missing promote_crash.sh should fail pipeline validation"
        );
        assert!(
            promote.detail.contains("promote_crash.sh missing"),
            "promote detail should identify the missing script: {}",
            promote.detail
        );
        Ok(())
    }

    #[test]
    fn corpus_directories_exist() -> TestResult {
        let root = repo_root()?;
        let targets = manifest_fuzz_targets(Path::new(&root));
        for target in &targets {
            let path = format!("{root}/fuzz/corpus/{target}");
            assert!(
                Path::new(&path).is_dir(),
                "corpus dir for {target} not found at {path}"
            );
        }
        Ok(())
    }

    #[test]
    fn pipeline_validation_passes() -> TestResult {
        let root = repo_root()?;
        let checks = validate_pipeline(&root);
        for check in &checks {
            assert!(
                check.passed,
                "pipeline check '{}' failed: {}",
                check.component, check.detail
            );
        }
        Ok(())
    }

    #[test]
    fn minimize_command_format() {
        let cmd = minimize_command("fuzz_ext4_metadata", Path::new("/tmp/crash-abc"));
        insta::assert_snapshot!("minimize_command_format", cmd);
    }

    #[test]
    fn minimize_command_shell_quotes_untrusted_tokens() {
        let cmd = minimize_command("fuzz target", Path::new("/tmp/crash; touch injected"));
        insta::assert_snapshot!("minimize_command_shell_quotes_untrusted_tokens", cmd);
    }

    #[test]
    fn seed_filename_includes_target_and_campaign() {
        let crash = CrashArtifact {
            target: "fuzz_ext4_metadata".to_owned(),
            crash_path: PathBuf::from("/tmp/crash-abc"),
            campaign_id: Some("20260312T120000Z".to_owned()),
            commit_sha: Some("abc1234".to_owned()),
            minimized: true,
            input_size: 42,
        };
        let name = seed_filename(&crash);
        assert!(name.contains("fuzz_ext4_metadata"));
        assert!(name.contains("20260312T120000Z"));
        assert!(name.contains("42bytes"));
    }

    #[test]
    fn seed_filename_sanitizes_path_components() {
        let crash = CrashArtifact {
            target: "fuzz_ext4/metadata".to_owned(),
            crash_path: PathBuf::from("/tmp/crash-abc"),
            campaign_id: Some("campaign with spaces".to_owned()),
            commit_sha: None,
            minimized: false,
            input_size: 7,
        };
        assert_eq!(
            seed_filename(&crash),
            "regression_fuzz_ext4_metadata_campaign_with_spaces_7bytes"
        );
    }

    #[test]
    fn test_function_name_is_valid_rust_identifier() {
        let crash = CrashArtifact {
            target: "fuzz_ext4_metadata".to_owned(),
            crash_path: PathBuf::from("/tmp/crash-abc"),
            campaign_id: Some("20260312T120000Z".to_owned()),
            commit_sha: None,
            minimized: false,
            input_size: 100,
        };
        let name = test_function_name(&crash);
        assert!(
            name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "test name must be valid Rust identifier: {name}"
        );
        assert!(name.starts_with("regression_"));
    }

    #[test]
    fn generate_regression_test_includes_metadata() {
        let case = RegressionCase {
            test_name: "regression_fuzz_ext4_metadata_20260312".to_owned(),
            tag: RegressionTag {
                target: "fuzz_ext4_metadata".to_owned(),
                campaign_id: "20260312T120000Z".to_owned(),
                commit_sha: "abc1234".to_owned(),
                promoted_at: "2026-03-12".to_owned(),
                minimized: true,
                corpus_seed: "regression_fuzz_ext4_metadata_20260312T120000Z_42bytes".to_owned(),
            },
            seed_path: PathBuf::from("tests/fuzz_corpus/regression_seed.bin"),
            test_path: PathBuf::from("tests/fuzz_regressions.rs"),
        };
        let source = generate_regression_test_source(&case);
        assert!(source.contains("#[test]"));
        assert!(source.contains("regression_fuzz_ext4_metadata_20260312"));
        assert!(source.contains("Campaign: `20260312T120000Z`"));
        assert!(source.contains("Commit at discovery: `abc1234`"));
        assert!(source.contains("Minimized: `true`"));
        assert!(source.contains("parse_superblock_region"));
        insta::assert_snapshot!("generate_regression_test_source_includes_metadata", source);
    }

    #[test]
    fn generate_regression_test_escapes_seed_path_literal() {
        let case = RegressionCase {
            test_name: "regression_fuzz_ext4_metadata_quoted".to_owned(),
            tag: RegressionTag {
                target: "fuzz_ext4_metadata".to_owned(),
                campaign_id: "quoted".to_owned(),
                commit_sha: "abc1234".to_owned(),
                promoted_at: "2026-03-12".to_owned(),
                minimized: false,
                corpus_seed: "quoted".to_owned(),
            },
            seed_path: PathBuf::from("tests/fuzz_corpus/quote\"and\\slash.bin"),
            test_path: PathBuf::from("tests/fuzz_regressions.rs"),
        };
        let source = generate_regression_test_source(&case);
        assert!(source.contains("quote\\\"and\\\\slash.bin"));
        assert!(!source.contains("quote\"and\\slash.bin"));
    }

    #[test]
    fn discover_crashes_returns_empty_for_nonexistent_dir() {
        let crashes = discover_crashes(Path::new("/nonexistent/campaign"));
        assert_eq!(crashes, [] as [CrashArtifact; 0]);
    }

    #[test]
    fn promotion_result_json_round_trips() -> Result<(), serde_json::Error> {
        let result = PromotionResult {
            crash: CrashArtifact {
                target: "fuzz_ext4_metadata".to_owned(),
                crash_path: PathBuf::from("/tmp/crash"),
                campaign_id: Some("test".to_owned()),
                commit_sha: Some("abc".to_owned()),
                minimized: false,
                input_size: 10,
            },
            steps_completed: vec![PromotionStep::Discovered, PromotionStep::Minimized],
            regression_case: None,
            error: None,
        };
        let json = serde_json::to_string_pretty(&result)?;
        insta::assert_snapshot!("promotion_result_json_shape", json);
        let parsed: PromotionResult = serde_json::from_str(&json)?;
        assert_eq!(parsed, result);
        Ok(())
    }

    #[test]
    fn adversarial_corpus_exists_and_has_samples() -> TestResult {
        let root = repo_root()?;
        let corpus_dir = format!("{root}/tests/fuzz_corpus");
        assert!(
            Path::new(&corpus_dir).is_dir(),
            "adversarial corpus dir missing"
        );
        let count = std::fs::read_dir(&corpus_dir)?
            .filter(|e| e.as_ref().is_ok_and(|e| e.path().is_file()))
            .count();
        assert!(
            count >= 10,
            "adversarial corpus should have >= 10 samples, got {count}"
        );
        Ok(())
    }

    #[test]
    fn dictionaries_have_tokens() -> TestResult {
        let root = repo_root()?;
        for dict in ["ext4.dict", "btrfs.dict"] {
            let path = format!("{root}/fuzz/dictionaries/{dict}");
            let content = std::fs::read_to_string(&path)?;
            let token_count = content
                .lines()
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .count();
            assert!(
                token_count >= 5,
                "{dict} should have >= 5 tokens, got {token_count}"
            );
        }
        Ok(())
    }

    #[test]
    fn pipeline_check_fails_for_missing_repo() {
        let checks = validate_pipeline("/nonexistent/repo");
        assert!(
            checks.iter().any(|c| !c.passed),
            "pipeline should fail for missing repo"
        );
    }
}
