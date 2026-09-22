#![forbid(unsafe_code)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::UNIX_EPOCH;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidData, message.into()))
}

fn repo_root() -> TestResult<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .ok_or_else(|| {
            test_error("ffs-harness crate should be two levels below the repository root")
        })?
        .to_path_buf();
    Ok(root)
}

fn read_json(path: &Path) -> TestResult<Value> {
    let text = fs::read_to_string(path)
        .map_err(|err| test_error(format!("read {}: {err}", path.display())))?;
    let value = serde_json::from_str(&text)
        .map_err(|err| test_error(format!("parse {}: {err}", path.display())))?;
    Ok(value)
}

fn fixture_reference_time(path: &str) -> TestResult<i64> {
    let semantic = fixture_semantic_commit_time(path)?;
    if let Some(timestamp) = semantic {
        return Ok(timestamp);
    }
    let root = repo_root()?;
    let output = Command::new("git")
        .args(["log", "-n1", "--format=%ct", "--", path])
        .current_dir(&root)
        .output()
        .map_err(|err| test_error(format!("git log for {path}: {err}")))?;
    if !output.status.success() {
        let modified = fs::metadata(root.join(path))
            .map_err(|err| test_error(format!("metadata for {path}: {err}")))?
            .modified()
            .map_err(|err| test_error(format!("{path} modified before unix epoch: {err}")))?;
        return Ok(i64::try_from(
            modified
                .duration_since(UNIX_EPOCH)
                .map_err(|err| test_error(format!("{path} modified before unix epoch: {err}")))?
                .as_secs(),
        )
        .unwrap_or(i64::MAX));
    }
    let timestamp = String::from_utf8(output.stdout)
        .map_err(|err| test_error(format!("git timestamp for {path} should be utf8: {err}")))?
        .trim()
        .parse()
        .map_err(|err| test_error(format!("git timestamp for {path} should parse: {err}")))?;
    Ok(timestamp)
}

/// Newest commit at which `path`'s PARSED JSON content changed (bd-awvjj).
///
/// Formatting-only rewrites (pretty-printing, whitespace, key-independent
/// layout) leave `serde_json::Value` equality intact, so they do not move the
/// semantic reference time. The freshness invariant this test enforces —
/// profile provenance must postdate the fixture content it was measured
/// against — keeps its full strength against every content change while no
/// longer false-firing on pure byte churn (win). The admitted cost: an edit
/// that changes parsed content still counts even if semantically trivial
/// (e.g. a number reformatted 1.0 -> 1) — the gate errs strict, never loose.
fn fixture_semantic_commit_time(path: &str) -> TestResult<Option<i64>> {
    let root = repo_root()?;
    let log = Command::new("git")
        .args(["log", "--format=%H %ct", "--", path])
        .current_dir(&root)
        .output()
        .map_err(|err| test_error(format!("git log for {path}: {err}")))?;
    if !log.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8(log.stdout)
        .map_err(|err| test_error(format!("git log for {path} should be utf8: {err}")))?;
    let commits: Vec<(&str, i64)> = stdout
        .lines()
        .filter_map(|line| line.split_once(' '))
        .filter_map(|(hash, ts)| ts.parse::<i64>().ok().map(|t| (hash, t)))
        .collect();
    if commits.is_empty() {
        return Ok(None);
    }
    let content_at = |hash: &str| -> TestResult<Option<serde_json::Value>> {
        let blob = Command::new("git")
            .args(["show", &format!("{hash}:{path}")])
            .current_dir(&root)
            .output()
            .map_err(|err| test_error(format!("git show for {path}: {err}")))?;
        if !blob.status.success() {
            // File absent at this revision (creation or deletion boundary):
            // treat as a content change.
            return Ok(None);
        }
        Ok(serde_json::from_slice(&blob.stdout).ok())
    };
    let contents: Vec<Option<serde_json::Value>> = commits
        .iter()
        .map(|(hash, _)| content_at(hash))
        .collect::<TestResult<Vec<_>>>()?;
    // Walk newest -> oldest over adjacent pairs. The first pair whose parsed
    // content differs attributes the last semantic change to the NEWER commit
    // of the pair (the one that introduced the difference).
    for index in 0..commits.len() - 1 {
        match (&contents[index], &contents[index + 1]) {
            (Some(newer), Some(older)) if newer == older => {}
            _ => return Ok(Some(commits[index].1)),
        }
    }
    // Every revision parsed identically: content was born once and only
    // reformatted since. The semantic reference is the birth commit.
    Ok(commits.last().map(|(_, ts)| *ts))
}

fn iso8601_to_epoch(timestamp: &str) -> TestResult<i64> {
    let output = Command::new("date")
        .args(["-u", "-d", timestamp, "+%s"])
        .output()
        .map_err(|err| test_error(format!("date should parse {timestamp}: {err}")))?;
    if !output.status.success() {
        return Err(test_error(format!(
            "date failed for {timestamp}: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let epoch = String::from_utf8(output.stdout)
        .map_err(|err| test_error(format!("date output should be utf8: {err}")))?
        .trim()
        .parse()
        .map_err(|err| test_error(format!("epoch should parse for {timestamp}: {err}")))?;
    Ok(epoch)
}

#[test]
fn canonical_profile_artifacts_are_committed_and_structured() -> TestResult {
    let root = repo_root()?;
    let fixture_commit = fixture_reference_time("conformance/golden/ext4_8mb_reference.json")?;
    let cases = [
        (
            "profiles/flamegraph_cli_inspect.svg",
            "profiles/flamegraph_cli_inspect.meta.json",
            [
                "profile_read_path",
                "read_block_vec",
                "read_inode",
                "free_space_summary",
            ],
        ),
        (
            "profiles/flamegraph_fuse_read.svg",
            "profiles/flamegraph_fuse_read.meta.json",
            [
                "FrankenFuse",
                "read_for_fuzzing",
                "read_with_readahead",
                "read_block_vec",
            ],
        ),
        (
            "profiles/flamegraph_diff_vs_baseline.svg",
            "profiles/flamegraph_diff_vs_baseline.meta.json",
            [
                "read_block",
                "parse_inode",
                "BlockDevice::read",
                "fuse::read",
            ],
        ),
    ];

    for (svg_rel, meta_rel, markers) in cases {
        let svg_path = root.join(svg_rel);
        let meta_path = root.join(meta_rel);
        let svg = fs::read_to_string(&svg_path)
            .map_err(|err| test_error(format!("read {}: {err}", svg_path.display())))?;
        assert!(
            svg.len() > 10 * 1024,
            "{} should be a non-empty flamegraph-sized SVG, got {} bytes",
            svg_rel,
            svg.len()
        );
        assert!(
            svg.trim_start().starts_with("<?xml") && svg.contains("<svg"),
            "{svg_rel} should be valid-looking SVG XML"
        );
        for marker in markers {
            assert!(
                svg.contains(marker),
                "{svg_rel} should contain expected stack marker {marker}"
            );
        }

        let meta = read_json(&meta_path)?;
        assert_eq!(field_u64(&meta, meta_rel, "schema_version")?, 1);
        assert_eq!(field_str(&meta, meta_rel, "source_bead")?, "bd-1ieht");
        assert_eq!(field_u64(&meta, meta_rel, "sample_threshold")?, 1000);
        assert!(
            field_u64(&meta, meta_rel, "samples")? >= 1000,
            "{meta_rel} should record at least 1000 samples"
        );
        assert!(
            field_u64(&meta, meta_rel, "duration_ms")? > 0
                || field_str(&meta, meta_rel, "target")? == "diff_vs_baseline",
            "{meta_rel} should record a positive profiling duration"
        );
        for field in [
            "profiler_tool",
            "started_at",
            "finished_at",
            "command",
            "canonical_fixture",
            "baseline",
            "git_head",
            "git_clean",
            "kernel",
            "cpu_model",
            "cpu_governor",
            "aslr",
            "rustc",
            "cargo",
            "system_loadavg",
        ] {
            field_value(&meta, meta_rel, field)?;
        }
        assert_eq!(
            field_str(&meta, meta_rel, "canonical_fixture")?,
            "conformance/golden/ext4_8mb_reference.ext4"
        );
        let profile_started = iso8601_to_epoch(field_str(&meta, meta_rel, "started_at")?)?;
        assert!(
            profile_started > fixture_commit,
            "{meta_rel} should be fresher than ext4_8mb_reference.json"
        );
    }
    Ok(())
}

#[test]
fn profile_metadata_has_no_duplicate_required_markers() -> TestResult {
    let root = repo_root()?;
    for meta_rel in [
        "profiles/flamegraph_cli_inspect.meta.json",
        "profiles/flamegraph_fuse_read.meta.json",
        "profiles/flamegraph_diff_vs_baseline.meta.json",
    ] {
        let meta = read_json(&root.join(meta_rel))?;
        let markers = field_array(&meta, meta_rel, "required_stack_markers")?;
        let mut seen = BTreeSet::new();
        for marker in markers {
            let marker = marker
                .as_str()
                .ok_or_else(|| test_error(format!("{meta_rel} marker should be string")))?;
            assert!(
                seen.insert(marker.to_owned()),
                "{meta_rel} duplicate {marker}"
            );
        }
    }
    Ok(())
}

fn field_value<'a>(meta: &'a Value, meta_rel: &str, field: &str) -> TestResult<&'a Value> {
    meta.get(field).ok_or_else(|| {
        test_error(format!(
            "{meta_rel} missing required metadata field {field}"
        ))
    })
}

fn field_str<'a>(meta: &'a Value, meta_rel: &str, field: &str) -> TestResult<&'a str> {
    field_value(meta, meta_rel, field)?
        .as_str()
        .ok_or_else(|| test_error(format!("{meta_rel} field {field} should be string")))
}

fn field_u64(meta: &Value, meta_rel: &str, field: &str) -> TestResult<u64> {
    field_value(meta, meta_rel, field)?
        .as_u64()
        .ok_or_else(|| test_error(format!("{meta_rel} field {field} should be u64")))
}

fn field_array<'a>(meta: &'a Value, meta_rel: &str, field: &str) -> TestResult<&'a [Value]> {
    field_value(meta, meta_rel, field)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| test_error(format!("{meta_rel} field {field} should be array")))
}
