#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn readme_quantitative_claims_match_code() -> Result<(), String> {
    let root = workspace_root()?;
    let readme = read_quantitative_readme(&root)?;

    let mismatches = collect_mismatches(&root, &readme)?;
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "README quantitative claims drifted:\n{}",
            mismatches.join("\n")
        ))
    }
}

#[test]
fn injected_readme_count_drift_is_detected() -> Result<(), String> {
    let root = workspace_root()?;
    let readme = read_quantitative_readme(&root)?;
    let fuzz_targets = git_ls_files_count(&root, "fuzz/fuzz_targets/*.rs")?;
    let mutated = readme.replace(&format!("{fuzz_targets} fuzz targets"), "999 fuzz targets");

    let mismatches = collect_mismatches(&root, &mutated)?;
    if mismatches
        .iter()
        .any(|mismatch| mismatch.contains("fuzz targets"))
    {
        Ok(())
    } else {
        Err(format!(
            "injected fuzz-target drift was not detected: {mismatches:?}"
        ))
    }
}

#[test]
fn injected_readme_benchmark_file_count_drift_is_detected() -> Result<(), String> {
    let root = workspace_root()?;
    let readme = read_quantitative_readme(&root)?;
    let benchmark_files = git_ls_files_count(&root, "crates/*/benches/*.rs")?;
    let original = format!("{benchmark_files} Rust benchmark files");
    if !readme.contains(&original) {
        return Err(format!("benchmark inventory claim is missing: {original}"));
    }
    let mutated = readme.replace(
        &original,
        &format!("{} Rust benchmark files", benchmark_files + 1),
    );
    let mismatches = collect_mismatches(&root, &mutated)?;
    if mismatches
        .iter()
        .any(|mismatch| mismatch.starts_with("Rust benchmark file count:"))
    {
        Ok(())
    } else {
        Err(format!(
            "injected benchmark-file drift was not detected: {mismatches:?}"
        ))
    }
}

#[test]
fn injected_readme_merge_mechanism_count_drift_is_detected() -> Result<(), String> {
    let root = workspace_root()?;
    let readme = read_quantitative_readme(&root)?;
    let source = read_to_string(&root, "crates/ffs-mvcc/src/lib.rs")?;
    let outcomes = count_enum_variants(&source, "MergeProofMechanism")?;
    let mechanisms = outcomes
        .checked_sub(1)
        .ok_or_else(|| "merge outcome enum has no refusal outcome".to_owned())?;
    let original = format!("{mechanisms} executable same-block merge mechanisms");
    if !readme.contains(&original) {
        return Err(format!("merge mechanism claim is missing: {original}"));
    }
    let mutated = readme.replace(
        &original,
        &format!("{outcomes} executable same-block merge mechanisms"),
    );
    let mismatches = collect_mismatches(&root, &mutated)?;
    if mismatches
        .iter()
        .any(|mismatch| mismatch.starts_with("executable MergeProof mechanism count:"))
    {
        Ok(())
    } else {
        Err(format!(
            "counting the refusal outcome as a merge mechanism was not detected: {mismatches:?}"
        ))
    }
}

#[test]
fn workspace_docs_have_no_stale_open_bead_claims() -> Result<(), String> {
    let root = workspace_root()?;
    let issues_jsonl = read_to_string(&root, ".beads/issues.jsonl")?;
    let mut all_errors = Vec::new();
    for doc in [
        "README.md",
        "README_EXT4_BTRFS.md",
        "FEATURE_PARITY.md",
        "PROPOSED_ARCHITECTURE.md",
        "PLAN_TO_PORT_FRANKENFS_TO_RUST.md",
        "COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md",
    ] {
        let text = read_to_string(&root, doc)?;
        all_errors.extend(ffs_harness::docs_status_drift::find_stale_open_bead_claims(
            &issues_jsonl,
            doc,
            &text,
        ));
    }
    if all_errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "stale open-bead claims in workspace docs:\n{}",
            all_errors.join("\n")
        ))
    }
}

#[test]
fn injected_stale_open_bead_claim_is_detected() -> Result<(), String> {
    let root = workspace_root()?;
    let issues_jsonl = read_to_string(&root, ".beads/issues.jsonl")?;
    let synthetic = "Follow-on items remain open under `bd-9rutw` and `bd-uzt72`.\n";
    let errors = ffs_harness::docs_status_drift::find_stale_open_bead_claims(
        &issues_jsonl,
        "README.md",
        synthetic,
    );
    let saw_closed = errors
        .iter()
        .any(|err| err.contains("bd-9rutw") && err.contains("status=closed"));
    let saw_missing = errors
        .iter()
        .any(|err| err.contains("bd-uzt72") && err.contains("status=missing"));
    if saw_closed && saw_missing {
        Ok(())
    } else {
        Err(format!(
            "injected stale/missing open-bead claims not detected: {errors:?}"
        ))
    }
}

#[test]
fn mounted_scorecards_have_no_verdict_or_summary_drift() -> Result<(), String> {
    let root = workspace_root()?;
    let mut all_errors = Vec::new();
    for doc in [
        "docs/MOUNTED_KERNEL_SCORECARD.md",
        "docs/MOUNTED_BTRFS_SCORECARD.md",
    ] {
        let text = read_to_string(&root, doc)?;
        all_errors.extend(ffs_harness::docs_status_drift::find_scorecard_verdict_drift(doc, &text));
    }
    if all_errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "mounted scorecard verdict/summary drift:\n{}",
            all_errors.join("\n")
        ))
    }
}

#[test]
fn injected_scorecard_verdict_drift_is_detected() -> Result<(), String> {
    let root = workspace_root()?;
    let btrfs_scorecard = read_to_string(&root, "docs/MOUNTED_BTRFS_SCORECARD.md")?;
    let mutated = btrfs_scorecard.replacen(
        "| **Multi-file parallel read** |",
        "| **Multi-file parallel read** | `1.140683x` slower (`verdict=HONEST_LOSS`; THE WIN IS WITHDRAWN) | **WIN** |\n| **Shadow row** |",
        1,
    );
    let errors = ffs_harness::docs_status_drift::find_scorecard_verdict_drift(
        "docs/MOUNTED_BTRFS_SCORECARD.md",
        &mutated,
    );
    if errors.iter().any(|err| {
        err.contains("scorecard verdict drift") || err.contains("scorecard summary drift")
    }) {
        Ok(())
    } else {
        Err(format!(
            "injected scorecard verdict drift not detected: {errors:?}"
        ))
    }
}

#[test]
fn comprehensive_spec_trait_mapping_section_names_live_workspace_traits() -> Result<(), String> {
    let root = workspace_root()?;
    let spec = read_to_string(&root, "COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md")?;
    if !spec.contains("### 9.9 Concrete Workspace Trait & Type Mapping") {
        return Err("COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md missing §9.9 trait mapping".to_owned());
    }
    for (rel_path, needle) in [
        ("crates/ffs-block/src/lib.rs", "pub trait ByteDevice"),
        ("crates/ffs-block/src/lib.rs", "pub trait BlockDevice"),
        ("crates/ffs-core/src/vfs.rs", "pub trait FsOps"),
        (
            "crates/ffs-repair/src/recovery.rs",
            "pub trait BlockValidator",
        ),
        (
            "crates/ffs-repair/src/recovery.rs",
            "pub trait RecoveryWriteback",
        ),
        ("crates/ffs-mvcc/src/persist.rs", "pub trait WalWriter"),
    ] {
        let src = read_to_string(&root, rel_path)?;
        if !src.contains(needle) {
            return Err(format!("{rel_path} missing `{needle}` referenced by §9.9"));
        }
    }
    Ok(())
}

fn collect_mismatches(root: &Path, readme: &str) -> Result<Vec<String>, String> {
    let crate_count = git_ls_files_count(root, "crates/*/Cargo.toml")?;
    let fuzz_target_count = git_ls_files_count(root, "fuzz/fuzz_targets/*.rs")?;
    let e2e_script_count = git_ls_files_count(root, "scripts/e2e/*.sh")?;
    let benchmark_file_count = git_ls_files_count(root, "crates/*/benches/*.rs")?;
    let snapshot_count = git_ls_files_count(root, "*.snap")?;

    let btrfs_source = read_to_string(root, "crates/ffs-btrfs/src/lib.rs")?;
    let btrfs_backrefs = read_to_string(root, "crates/ffs-btrfs/src/backrefs.rs")?;
    let btrfs_combined = format!("{btrfs_source}\n{btrfs_backrefs}");
    let btrfs_item_type_count = count_btrfs_item_type_constants(&btrfs_combined);
    let send_command_count = count_enum_variants(&btrfs_source, "SendCommand")?;

    let evidence_source = read_to_string(root, "crates/ffs-repair/src/evidence.rs")?;
    let evidence_event_type_count = count_enum_variants(&evidence_source, "EvidenceEventType")?;

    let mvcc_source = read_to_string(root, "crates/ffs-mvcc/src/lib.rs")?;
    let merge_mechanism_count = count_enum_variants(&mvcc_source, "MergeProofMechanism")?;
    let executable_merge_mechanism_count =
        merge_mechanism_count.saturating_sub(usize::from(merge_mechanism_count > 0));

    let mut mismatches = Vec::new();
    require_contains(
        readme,
        &format!("{crate_count} crates"),
        "crates-directory package count",
        &mut mismatches,
    );
    require_contains(
        readme,
        "source-derived test inventory",
        "test inventory wording",
        &mut mismatches,
    );
    require_absent(
        readme,
        "7,442",
        "stale exact test-entry count",
        &mut mismatches,
    );
    require_absent(readme, "7,389", "stale #[test] count", &mut mismatches);

    require_contains(
        readme,
        &format!("fuzz%20targets-{fuzz_target_count}"),
        "fuzz-target badge count",
        &mut mismatches,
    );
    require_contains(
        readme,
        &format!("{fuzz_target_count} fuzz targets"),
        "fuzz-target prose count",
        &mut mismatches,
    );
    require_absent(
        readme,
        "60 fuzz targets",
        "stale fuzz-target count",
        &mut mismatches,
    );

    require_contains(
        readme,
        &format!("{benchmark_file_count} Rust benchmark files"),
        "Rust benchmark file count",
        &mut mismatches,
    );
    require_contains(
        readme,
        &format!("{e2e_script_count} tracked E2E scripts"),
        "tracked E2E script count",
        &mut mismatches,
    );
    require_contains(
        readme,
        &format!("Decision 10: {e2e_script_count} E2E gate scripts"),
        "E2E decision heading count",
        &mut mismatches,
    );
    require_absent(readme, "114 E2E", "stale E2E script count", &mut mismatches);
    require_absent(
        readme,
        "114 end-to-end",
        "stale end-to-end script count",
        &mut mismatches,
    );

    require_contains(
        readme,
        &format!("{evidence_event_type_count} evidence-event types"),
        "evidence event type count",
        &mut mismatches,
    );
    require_contains(
        readme,
        &format!("{snapshot_count} tracked insta snapshot"),
        "insta snapshot count",
        &mut mismatches,
    );
    require_absent(
        readme,
        "167+ insta",
        "stale insta snapshot count",
        &mut mismatches,
    );

    require_contains(
        readme,
        &format!("{send_command_count} command variants"),
        "btrfs send command variant count",
        &mut mismatches,
    );
    require_absent(
        readme,
        "22 command types",
        "stale btrfs send command count",
        &mut mismatches,
    );
    require_contains(
        readme,
        &format!("({btrfs_item_type_count} currently)"),
        "btrfs item-type constant count",
        &mut mismatches,
    );
    require_absent(
        readme,
        "All 22 item types",
        "stale btrfs item-type count",
        &mut mismatches,
    );

    require_contains(
        readme,
        &format!("{executable_merge_mechanism_count} executable same-block merge mechanisms"),
        "executable MergeProof mechanism count",
        &mut mismatches,
    );
    require_contains(
        readme,
        &format!("{merge_mechanism_count}-outcome `MergeProofMechanism` enum"),
        "MergeProofMechanism enum outcome count",
        &mut mismatches,
    );

    Ok(mismatches)
}

fn require_contains(readme: &str, expected: &str, label: &str, mismatches: &mut Vec<String>) {
    if !readme.contains(expected) {
        mismatches.push(format!("{label}: missing `{expected}`"));
    }
}

fn require_absent(readme: &str, forbidden: &str, label: &str, mismatches: &mut Vec<String>) {
    if readme.contains(forbidden) {
        mismatches.push(format!("{label}: still contains `{forbidden}`"));
    }
}

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "ffs-harness lives under crates/ffs-harness".to_owned())
}

fn read_to_string(root: &Path, relative: &str) -> Result<String, String> {
    let path = root.join(relative);
    std::fs::read_to_string(&path).map_err(|err| format!("read {}: {err}", path.display()))
}

fn read_quantitative_readme(root: &Path) -> Result<String, String> {
    let readme = read_to_string(root, "README.md")?;
    if readme.contains("README_EXT4_BTRFS.md") && root.join("README_EXT4_BTRFS.md").is_file() {
        let detailed = read_to_string(root, "README_EXT4_BTRFS.md")?;
        Ok(format!("{readme}\n{detailed}"))
    } else {
        Ok(readme)
    }
}

fn git_ls_files_count(root: &Path, pathspec: &str) -> Result<usize, String> {
    let output = Command::new("git")
        .args(["ls-files", pathspec])
        .current_dir(root)
        .output()
        .map_err(|err| format!("run git ls-files {pathspec}: {err}"))?;
    if !output.status.success() {
        if option_env!("RCH_BUILD_SOURCE").is_some() && !root.join(".git").exists() {
            return paired_checkout_files_count(root, pathspec);
        }
        return Err(format!(
            "git ls-files {pathspec} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count())
}

fn paired_checkout_files_count(root: &Path, pathspec: &str) -> Result<usize, String> {
    if pathspec == "*.snap" {
        return count_extension_recursive(root, root, "snap");
    }
    let segments: Vec<&str> = pathspec.split('/').collect();
    count_matching_segments(root, &segments)
}

fn count_matching_segments(current: &Path, segments: &[&str]) -> Result<usize, String> {
    let Some((&first, rest)) = segments.split_first() else {
        return Ok(usize::from(current.is_file()));
    };
    if rest.is_empty() {
        if let Some(ext) = first.strip_prefix("*.") {
            let mut count = 0usize;
            for entry in std::fs::read_dir(current).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let path = entry.path();
                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some(ext) {
                    count += 1;
                }
            }
            return Ok(count);
        }
        return Ok(usize::from(current.join(first).is_file()));
    }
    if first == "*" {
        let mut count = 0usize;
        for entry in std::fs::read_dir(current).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if path.is_dir() {
                count += count_matching_segments(&path, rest)?;
            }
        }
        return Ok(count);
    }
    let next = current.join(first);
    if !next.is_dir() {
        return Ok(0);
    }
    count_matching_segments(&next, rest)
}

fn count_extension_recursive(root: &Path, current: &Path, ext: &str) -> Result<usize, String> {
    let mut count = 0usize;
    for entry in std::fs::read_dir(current).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if current == root
            && (name_str == ".git"
                || name_str == ".beads"
                || name_str == "target"
                || name_str.starts_with(".rch-"))
        {
            continue;
        }
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if meta.is_dir() {
            count += count_extension_recursive(root, &path, ext)?;
        } else if meta.is_file() && path.extension().and_then(|s| s.to_str()) == Some(ext) {
            count += 1;
        }
    }
    Ok(count)
}

fn count_btrfs_item_type_constants(source: &str) -> usize {
    source
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub const BTRFS_ITEM_"))
        .filter_map(|rest| rest.split_once(':').map(|(name, _)| name))
        .filter(|name| *name != "SIZE")
        .collect::<BTreeSet<_>>()
        .len()
}

fn count_enum_variants(source: &str, enum_name: &str) -> Result<usize, String> {
    let marker = format!("pub enum {enum_name}");
    let start = source
        .find(&marker)
        .ok_or_else(|| format!("missing enum {enum_name}"))?;
    let body = source
        .get(start..)
        .ok_or_else(|| format!("invalid enum start for {enum_name}"))?
        .split_once('{')
        .ok_or_else(|| format!("missing enum body for {enum_name}"))?
        .1;

    Ok(body
        .lines()
        .take_while(|line| line.trim() != "}")
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.ends_with(',')
                && trimmed
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_uppercase())
        })
        .count())
}
