#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn readme_quantitative_claims_match_code() -> Result<(), String> {
    let root = workspace_root()?;
    let readme = read_to_string(&root, "README.md")?;

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
    let readme = read_to_string(&root, "README.md")?;
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
    let readme = read_to_string(&root, "README.md")?;
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
    let readme = read_to_string(&root, "README.md")?;
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

fn collect_mismatches(root: &Path, readme: &str) -> Result<Vec<String>, String> {
    let crate_count = git_ls_files_count(root, "crates/*/Cargo.toml")?;
    let fuzz_target_count = git_ls_files_count(root, "fuzz/fuzz_targets/*.rs")?;
    let e2e_script_count = git_ls_files_count(root, "scripts/e2e/*.sh")?;
    let benchmark_file_count = git_ls_files_count(root, "crates/*/benches/*.rs")?;
    let snapshot_count = git_ls_files_count(root, "*.snap")?;

    let btrfs_source = read_to_string(root, "crates/ffs-btrfs/src/lib.rs")?;
    let btrfs_item_type_count = count_btrfs_item_type_constants(&btrfs_source);
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

fn git_ls_files_count(root: &Path, pathspec: &str) -> Result<usize, String> {
    let output = Command::new("git")
        .args(["ls-files", pathspec])
        .current_dir(root)
        .output()
        .map_err(|err| format!("run git ls-files {pathspec}: {err}"))?;
    if !output.status.success() {
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
