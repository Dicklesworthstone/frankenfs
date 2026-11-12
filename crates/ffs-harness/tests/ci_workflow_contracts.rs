#![forbid(unsafe_code)]
//! CI workflow hygiene, benchmark registration, and strict parity gate contracts
//! (`bd-fix-broken-ci-workflows-and-benches-h5t78`).

use ffs_harness::{
    ExecutionGatedParityReport, ParityExecutor, StrictParityFailureDiagnostic, canonical_gates,
    parity_suite_ids,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn collect_bench_rs_stems(benches_dir: &Path) -> BTreeSet<String> {
    let mut stems = BTreeSet::new();
    let Ok(entries) = fs::read_dir(benches_dir) else {
        return stems;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file()
            && path.extension().and_then(|ext| ext.to_str()) == Some("rs")
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            stems.insert(stem.to_owned());
        }
    }
    stems
}

fn parse_declared_benches(cargo_toml: &Path) -> BTreeSet<String> {
    let raw = fs::read_to_string(cargo_toml).expect("read Cargo.toml");
    let parsed: toml::Value = toml::from_str(&raw).expect("parse Cargo.toml");
    let mut names = BTreeSet::new();
    if let Some(benches) = parsed.get("bench").and_then(toml::Value::as_array) {
        for bench in benches {
            if let Some(name) = bench.get("name").and_then(toml::Value::as_str) {
                names.insert(name.to_owned());
            }
        }
    }
    names
}

fn audit_workflow_text(filename: &str, text: &str) -> Vec<String> {
    let mut violations = Vec::new();
    if text.contains("git hash-object") {
        violations.push(format!(
            "{filename}: contains hardcoded `git hash-object` blob assertion"
        ));
    }
    if text.contains("PATCH_SHA") {
        violations.push(format!("{filename}: contains historical `PATCH_SHA` pin"));
    }
    if text.contains("permissions:\n      contents: write")
        || text.contains("permissions:\n  contents: write")
    {
        violations.push(format!(
            "{filename}: requests unnecessary `contents: write` permission"
        ));
    }

    // Detect build-failure or missing-baseline soft-skipping (`exit 0` masking).
    let lines: Vec<&str> = text.lines().collect();
    for (idx, window) in lines.windows(5).enumerate() {
        let joined = window.join("\n");
        if (joined.contains("cargo build") && joined.contains("|| {") && joined.contains("exit 0"))
            || (joined.contains("skipping size gate") && joined.contains("exit 0"))
            || (joined.contains("skipping regression gate") && joined.contains("exit 0"))
            || (joined.contains("recording current size as baseline") && joined.contains("exit 0"))
        {
            violations.push(format!(
                "{filename}:{}: masks build failure or missing baseline with `exit 0`",
                idx + 1
            ));
        }
    }

    // Hosted `ubuntu-latest` workflows must never hardcode `/data/projects` target dirs or
    // invoke `rch check` unconditionally without a `command -v rch` fallback.
    if text.contains("runs-on: ubuntu-latest") {
        if text.contains("CARGO_TARGET_DIR: /data/projects/") {
            violations.push(format!(
                "{filename}: hardcodes `/data/projects/` CARGO_TARGET_DIR on hosted `ubuntu-latest`"
            ));
        }
        if text.contains("rch check") && !text.contains("if command -v rch") {
            violations.push(format!(
                "{filename}: invokes `rch check` on `ubuntu-latest` without portable local fallback"
            ));
        }
    }

    // GitHub Actions rejects `${{ runner.* }}` inside workflow-level (`indent == 0`) or
    // job-level (`indent == 4`) `env:` blocks; `runner.*` is only valid inside `steps`.
    let mut in_non_step_env = false;
    let mut env_indent = 0_usize;
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start_matches(' ').len();
        if in_non_step_env && indent <= env_indent {
            in_non_step_env = false;
        }
        if trimmed == "env:" && indent <= 4 {
            in_non_step_env = true;
            env_indent = indent;
            continue;
        }
        if in_non_step_env && trimmed.contains("runner.") {
            violations.push(format!(
                "{filename}:{}: references `runner.*` context inside workflow/job-level `env:` (only valid inside `steps`)",
                idx + 1
            ));
        }
    }

    violations
}

#[test]
fn every_crate_bench_rs_file_is_registered_in_cargo_toml() {
    let root = workspace_root();
    let crates_dir = root.join("crates");
    let mut total_rs_files = 0_usize;
    let mut total_registered = 0_usize;
    let mut mismatches = BTreeMap::new();

    for entry in fs::read_dir(&crates_dir).expect("read crates/") {
        let entry = entry.expect("dir entry");
        let pkg_dir = entry.path();
        if !pkg_dir.is_dir() {
            continue;
        }
        let cargo_toml = pkg_dir.join("Cargo.toml");
        if !cargo_toml.is_file() {
            continue;
        }
        let benches_dir = pkg_dir.join("benches");
        let on_disk = collect_bench_rs_stems(&benches_dir);
        let declared = parse_declared_benches(&cargo_toml);
        total_rs_files += on_disk.len();
        total_registered += declared.len();
        if on_disk != declared {
            let unregistered: Vec<_> = on_disk.difference(&declared).cloned().collect();
            let missing_files: Vec<_> = declared.difference(&on_disk).cloned().collect();
            mismatches.insert(
                pkg_dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("<unknown>")
                    .to_owned(),
                format!("unregistered={unregistered:?}, missing_files={missing_files:?}"),
            );
        }
    }

    assert!(
        mismatches.is_empty(),
        "every crates/*/benches/*.rs file must have a matching [[bench]] entry: {mismatches:#?}"
    );
    assert!(
        total_rs_files >= 173,
        "expected at least 173 benchmark .rs files across crates/, found {total_rs_files}"
    );
    assert_eq!(total_rs_files, total_registered);
}

#[test]
fn workflows_have_tracked_nonempty_baselines_and_zero_vacuous_patterns() {
    let root = workspace_root();
    let workflows_dir = root.join(".github").join("workflows");
    let mut workflow_files = Vec::new();
    for entry in fs::read_dir(&workflows_dir).expect("read .github/workflows") {
        let path = entry.expect("workflow entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("yml") {
            workflow_files.push(path);
        }
    }
    workflow_files.sort();
    assert!(
        !workflow_files.is_empty(),
        ".github/workflows must contain workflow YAML files"
    );

    let mut all_violations = Vec::new();
    for path in &workflow_files {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let text = fs::read_to_string(path).expect("read workflow file");
        all_violations.extend(audit_workflow_text(name, &text));
    }
    assert!(
        all_violations.is_empty(),
        "CI workflow hygiene violations detected:\n{}",
        all_violations.join("\n")
    );

    // Check ci.yml enforces strict all-suites parity and builds all six-format companion CLIs.
    let ci_yml = fs::read_to_string(workflows_dir.join("ci.yml")).expect("read ci.yml");
    assert!(
        ci_yml.contains("--strict-all-suites"),
        "ci.yml must enforce `parity --strict-all-suites`"
    );
    for required_bin in [
        "--bin ffs-cli",
        "--bin ffs-protected-mount",
        "--bin ffs-fat",
        "--bin ffs-ntfs",
        "--bin ffs-zfs",
    ] {
        assert!(
            ci_yml.contains(required_bin),
            "ci.yml fuse-e2e must build companion binary `{required_bin}`"
        );
    }

    // Every required baseline referenced by workflows must exist on disk, be non-empty,
    // and not be ignored by git (`git check-ignore -q` must exit non-zero).
    let required_baselines = [
        "benchmarks/baselines/binary_size.txt",
        "benchmarks/baselines/binary_sizes.json",
        "benchmarks/baselines/perf_baseline.json",
        "benchmarks/baselines/latest.json",
        "benchmarks/thresholds.toml",
        "conformance/fixtures/checksums.sha256",
        "conformance/golden/checksums.sha256",
        "scripts/e2e/xfstests_baseline.json",
        "scripts/e2e/xfstests_baseline_btrfs.json",
    ];
    for rel_path in required_baselines {
        let full = root.join(rel_path);
        let meta = fs::metadata(&full)
            .unwrap_or_else(|err| panic!("required workflow baseline missing: {rel_path} ({err})"));
        assert!(
            meta.len() > 0,
            "required workflow baseline must be non-empty: {rel_path}"
        );

        if root.join(".git").exists() {
            let ignore_status = Command::new("git")
                .args(["check-ignore", "-q", rel_path])
                .current_dir(&root)
                .status()
                .expect("run git check-ignore");
            assert_eq!(
                ignore_status.code(),
                Some(1),
                "required workflow baseline `{rel_path}` must NOT be matched by .gitignore (expected git check-ignore exit 1, got {ignore_status:?})"
            );

            let ls_files = Command::new("git")
                .args([
                    "ls-files",
                    "--cached",
                    "--others",
                    "--exclude-standard",
                    "--",
                    rel_path,
                ])
                .current_dir(&root)
                .output()
                .expect("run git ls-files");
            assert!(
                ls_files.status.success()
                    && !String::from_utf8_lossy(&ls_files.stdout).trim().is_empty(),
                "required workflow baseline `{rel_path}` must be tracked or trackable via git ls-files"
            );
        }
    }

    // Validate binary_size.txt and binary_sizes.json agree and record positive byte counts.
    let size_txt = fs::read_to_string(root.join("benchmarks/baselines/binary_size.txt"))
        .expect("read binary_size.txt");
    let cli_bytes: u64 = size_txt
        .trim()
        .parse()
        .expect("binary_size.txt must contain an integer byte size");
    assert!(
        cli_bytes > 100_000,
        "ffs-cli release size must be > 100 KiB"
    );

    let sizes_json: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(root.join("benchmarks/baselines/binary_sizes.json"))
            .expect("read binary_sizes.json"),
    )
    .expect("parse binary_sizes.json");
    assert_eq!(
        sizes_json["binaries"]["ffs-cli"]["size_bytes"].as_u64(),
        Some(cli_bytes),
        "binary_size.txt and binary_sizes.json must agree on ffs-cli size_bytes"
    );
    assert!(
        sizes_json["binaries"]["ffs-protected-mount"]["size_bytes"]
            .as_u64()
            .unwrap_or(0)
            > 100_000,
        "ffs-protected-mount release size must be > 100 KiB"
    );

    // Both workspace Cargo.lock and fuzz/Cargo.lock must satisfy `--locked` so CI workflows
    // using `cargo test --locked` never fail on manifest drift.
    for manifest_rel in ["Cargo.toml", "fuzz/Cargo.toml"] {
        let manifest = root.join(manifest_rel);
        let lock_out = Command::new("cargo")
            .args([
                "metadata",
                "--manifest-path",
                manifest.to_str().expect("utf8 manifest path"),
                "--locked",
                "--format-version",
                "1",
            ])
            .current_dir(&root)
            .output()
            .expect("run cargo metadata --locked");
        assert!(
            lock_out.status.success(),
            "`cargo metadata --locked` failed for `{manifest_rel}`:\n{}",
            String::from_utf8_lossy(&lock_out.stderr)
        );
    }

    // bd-uu90b: ffs_xfstests_e2e.sh must reset SIGPIPE to SIG_DFL before exec'ing ./check so
    // runner/sudo-rs SIG_IGN inheritance never strands generic/310 (`_pkill -PIPE` + `wait`),
    // and generic/310 must remain selected + regression-gated on both ext4 and btrfs.
    let xfstests_e2e = fs::read_to_string(root.join("scripts/e2e/ffs_xfstests_e2e.sh"))
        .expect("read ffs_xfstests_e2e.sh");
    assert!(
        xfstests_e2e.contains("signal.signal(signal.SIGPIPE, signal.SIG_DFL)"),
        "ffs_xfstests_e2e.sh must restore SIGPIPE=SIG_DFL before exec'ing ./check (bd-uu90b)"
    );
    for xfstests_rel in [
        "scripts/e2e/xfstests_generic.list",
        "scripts/e2e/xfstests_allowlist.json",
        "scripts/e2e/xfstests_baseline.json",
        "scripts/e2e/xfstests_baseline_btrfs.json",
    ] {
        let text = fs::read_to_string(root.join(xfstests_rel)).expect("read xfstests config");
        assert!(
            text.contains("generic/310"),
            "`{xfstests_rel}` must include `generic/310` (bd-uu90b)"
        );
    }
}

#[test]
fn planted_red_workflow_auditor_rejects_vacuous_and_broken_patterns() {
    let broken_artifact_gate = r#"
jobs:
  binary-size:
    runs-on: ubuntu-latest
    steps:
      - run: |
          if [ ! -f "$BASELINE_FILE" ]; then
            echo "recording current size as baseline"
            exit 0
          fi
          cargo build --release --bin ffs-harness || {
            echo "skipping"
            exit 0
          }
"#;
    let violations = audit_workflow_text("broken-artifact-gates.yml", broken_artifact_gate);
    assert!(
        violations.len() >= 2,
        "expected planted-red violations for baseline recording + build masking, got {violations:?}"
    );

    let broken_v12 = r"
env:
  CARGO_TARGET_DIR: /data/projects/.cargo-target-broken
jobs:
  gate:
    runs-on: ubuntu-latest
    env:
      CARGO_TARGET_DIR: ${{ runner.temp }}/cargo-target-v12
    steps:
      - run: |
          command -v rch
          rch check
";
    let v12_violations = audit_workflow_text("broken-v12.yml", broken_v12);
    assert_eq!(v12_violations.len(), 3, "{v12_violations:?}");

    let broken_blob = r#"
jobs:
  validate:
    permissions:
      contents: write
    steps:
      - run: |
          PATCH_SHA=deadbeef
          test "$(git hash-object crates/ffs-core/src/lib.rs)" = "1ad941d65c"
"#;
    let blob_violations = audit_workflow_text("broken-btrfs.yml", broken_blob);
    assert_eq!(blob_violations.len(), 3, "{blob_violations:?}");
}

#[test]
fn planted_red_require_evidence_strict_rejects_omitted_suites_and_gates_with_json_diagnostics() {
    // 1. Empty parity run: missing all 17 suites and all 7 canonical gates.
    let empty_report =
        ExecutionGatedParityReport::run(&[], ParityExecutor::Rch).expect("empty report");
    let err_json = empty_report
        .require_evidence_strict()
        .expect_err("empty report must fail require_evidence_strict");
    let diag: StrictParityFailureDiagnostic = serde_json::from_str(&err_json)
        .expect("require_evidence_strict error must be valid StrictParityFailureDiagnostic JSON");
    assert!(!diag.readiness_verified);
    assert_eq!(diag.missing_suites.len(), parity_suite_ids().len());
    assert!(diag.missing_suites.iter().any(|s| s == "btrfs-reference"));
    assert!(diag.missing_suites.iter().any(|s| s == "xfstests-lib"));
    assert_eq!(
        diag.missing_gates,
        canonical_gates::canonical_gate_ids()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert_eq!(diag.missing_evidence_rows.len(), diag.total_rows);

    // 2. Execute ONE real lightweight suite (`xfstests-lib`) WITHOUT the other 16 suites or `--gate`:
    //    `require_evidence()` passes (subset-only check), whereas `require_evidence_strict()`
    //    MUST fail closed with structured JSON listing the 16 omitted suites and 7 omitted gates!
    let partial_report =
        ExecutionGatedParityReport::run(&["xfstests-lib".to_owned()], ParityExecutor::Cargo)
            .expect("run xfstests-lib parity subset");
    partial_report
        .require_evidence()
        .expect("subset require_evidence should pass when xfstests-lib passes");
    assert!(
        !partial_report.readiness_verified,
        "partial suite execution must never mark readiness_verified=true"
    );

    let partial_err = partial_report
        .require_evidence_strict()
        .expect_err("partial suite execution without all suites + gates must fail strict check");
    let partial_diag: StrictParityFailureDiagnostic = serde_json::from_str(&partial_err)
        .expect("partial strict error must parse as StrictParityFailureDiagnostic JSON");
    assert_eq!(partial_diag.error, "incomplete_parity_or_gate_execution");
    assert!(!partial_diag.readiness_verified);
    assert!(
        !partial_diag
            .missing_suites
            .iter()
            .any(|s| s == "xfstests-lib"),
        "executed passing suite xfstests-lib must not appear in missing_suites"
    );
    assert_eq!(
        partial_diag.missing_suites.len(),
        parity_suite_ids().len() - 1
    );
    assert!(
        partial_diag
            .missing_suites
            .iter()
            .any(|s| s == "btrfs-reference")
    );
    assert_eq!(partial_diag.missing_gates.len(), 7);
}
