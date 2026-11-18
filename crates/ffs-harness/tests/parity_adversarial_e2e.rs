//! bd-lc132: adversarial end-to-end proofs over the public parity entry point.
//!
//! These tests spawn the real `ffs-harness` binary — the same CI-facing entry
//! `cargo run -p ffs-harness -- parity` uses — and never feed hand-authored
//! `passed=true` data into the decision. They prove that public parity
//! decisions change with real executed outcomes:
//!
//! 1. One real suite run (`mvcc-lib`, exact-selected ffs-mvcc unit tests)
//!    promotes exactly the capability rows its exact mapping names and keeps
//!    every other row explicitly unverified, while whole-project readiness
//!    stays false because no canonical gate was selected.
//! 2. An injected failure of the same suite run flips those rows back to
//!    unverified and makes the public gate exit nonzero.
//!
//! The report itself carries the structured audit trail asserted here:
//! command evidence with output hashes, source identity, build environment,
//! per-row reasons and exact libtest counts.

use std::process::Command;

/// Run the public parity command against one real suite and return both the
/// process output and the parsed JSON report.
fn run_public_parity(injected_env: &[(&str, &str)]) -> (std::process::Output, serde_json::Value) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ffs-harness"));
    command.args(["parity", "--verify", "mvcc-lib", "--local"]);
    for (key, value) in injected_env {
        command.env(key, value);
    }
    let output = command.output().expect("spawn ffs-harness parity");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "parity report parse failed ({error}); status={:?} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
        });
    (output, report)
}

fn contracts(report: &serde_json::Value) -> Vec<(String, bool, Option<String>, String)> {
    report["contracts"]
        .as_array()
        .expect("report carries contracts")
        .iter()
        .map(|contract| {
            (
                contract["suite"].as_str().unwrap_or_default().to_owned(),
                contract["verified"].as_bool().unwrap_or(false),
                contract["reason"].as_str().map(str::to_owned),
                contract["capability"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            )
        })
        .collect()
}

#[test]
fn real_suite_run_promotes_exactly_its_mapped_capability_rows() {
    let (output, report) = run_public_parity(&[]);
    assert!(
        output.status.success(),
        "green real evidence must pass the public gate: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Nonzero selection enforced: the suite ran real tests and every selected
    // test passed, bound to one source identity.
    let run = &report["runs"][0];
    assert_eq!(run["execution"]["outcome"], "success");
    assert_eq!(run["execution"]["exit_code"], 0);
    assert_eq!(run["execution"]["command"], "cargo");
    assert!(
        run["execution"]["stdout_sha256"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
    let results = &run["results"];
    assert!(results["error"].is_null(), "well-formed libtest stream");
    assert_eq!(results["empty_selection"], false);
    assert_eq!(results["selected"], results["executed"]);
    assert_eq!(results["selected"], results["passed"]);
    let selected = results["selected"].as_u64().unwrap();
    assert!(
        selected >= 4,
        "both mapped MVCC rows need their tests: {selected}"
    );
    let source = &run["source"]["git_sha"];
    assert!(source.as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(
        source, &report["source"]["git_sha"],
        "one shared source identity"
    );
    assert!(
        run["build_environment"].is_object(),
        "build configuration recorded for audit"
    );

    // Exact mapping: only rows mapped to the executed suite verify; every
    // other row stays explicitly unverified with the same reason.
    let rows = contracts(&report);
    let verified_count = rows.iter().filter(|(_, verified, _, _)| *verified).count();
    for (suite, verified, reason, capability) in &rows {
        if suite != "mvcc-lib" {
            assert!(!verified, "{capability} credited without execution");
            assert_eq!(
                reason.as_deref(),
                Some("suite not executed"),
                "{capability} must stay visible as missing evidence"
            );
        }
    }
    assert!(
        rows.iter()
            .any(|(_, verified, _, capability)| *verified
                && capability == "MVCC snapshot visibility"),
        "the intended capability is promoted by its real tests"
    );
    assert_eq!(
        verified_count,
        report["evidence_backed_rows"].as_u64().unwrap() as usize
    );

    // A bounded suite never establishes whole-project readiness, and declared
    // contract coverage is a declaration, never execution credit.
    assert_eq!(report["readiness_verified"], false);
    let declared = report["declared_contracts"]["overall_implemented"]
        .as_u64()
        .unwrap();
    assert!(
        declared > report["evidence_backed_rows"].as_u64().unwrap(),
        "declared coverage ({declared}) must not collapse into executed credit"
    );
}

#[test]
fn injected_failure_flips_rows_and_fails_the_public_gate() {
    // An uninstalled target triple makes the nested cargo fail deterministically,
    // even on a fully warm target directory: the executed outcome genuinely
    // changes, and with it the public decision.
    let injected = [("CARGO_BUILD_TARGET", "x86_64-unknown-none")];
    let (output, report) = run_public_parity(&injected);
    assert!(
        !output.status.success(),
        "the public gate must fail when the executed suite fails"
    );

    // The run evidence records what actually happened, including the injected
    // build configuration.
    let run = &report["runs"][0];
    assert_eq!(
        run["execution"]["outcome"]["failed"]["exit_code"], 101,
        "nested cargo failed with its build-error exit code"
    );
    assert_eq!(
        run["build_environment"]["CARGO_BUILD_TARGET"],
        "x86_64-unknown-none"
    );

    // Every row the green run promoted is unverified again: missing, failed,
    // skipped or empty evidence cannot promote readiness.
    for (suite, verified, reason, capability) in contracts(&report) {
        assert!(!verified, "{capability} credited from a failed run");
        if suite == "mvcc-lib" {
            assert!(
                reason.is_some(),
                "{capability} must state why its evidence was rejected"
            );
        }
    }
    assert_eq!(report["evidence_backed_rows"], 0);
    assert_eq!(report["readiness_verified"], false);
}

#[test]
fn strict_mode_rejects_omitted_suites_while_offline_declarations_stay_zero_credit() {
    // 1. `parity --strict --verify mvcc-lib --local` MUST fail closed because 16
    //    suites and all 7 canonical gates were omitted (`"suite not executed"`).
    let strict_out = Command::new(env!("CARGO_BIN_EXE_ffs-harness"))
        .args(["parity", "--strict", "--verify", "mvcc-lib", "--local"])
        .output()
        .expect("spawn ffs-harness parity --strict");
    assert!(
        !strict_out.status.success(),
        "strict parity must fail closed when suites or canonical gates are omitted"
    );
    let strict_report: serde_json::Value =
        serde_json::from_slice(&strict_out.stdout).expect("parse strict parity JSON");
    assert_eq!(strict_report["readiness_verified"], false);
    let stderr = String::from_utf8_lossy(&strict_out.stderr);
    assert!(
        stderr.contains("omitted_suites") && stderr.contains("canonical gates were omitted"),
        "strict failure diagnostic must enumerate omitted suites and gates, got: {stderr}"
    );

    // 2. Declaration-only `parity` (no `--verify`, no `--gate`, no `--strict`)
    //    keeps `evidence_backed_rows == 0` and `readiness_verified == false`.
    let decl_out = Command::new(env!("CARGO_BIN_EXE_ffs-harness"))
        .args(["parity"])
        .output()
        .expect("spawn declaration-only ffs-harness parity");
    assert!(decl_out.status.success());
    let decl_report: serde_json::Value =
        serde_json::from_slice(&decl_out.stdout).expect("parse decl parity JSON");
    assert_eq!(decl_report["evidence_backed_rows"], 0);
    assert_eq!(decl_report["readiness_verified"], false);
}

#[test]
fn public_gates_command_and_parity_gate_flag_fail_closed_on_injected_failure() {
    // Force nested Cargo gate run to fail deterministically via uninstalled target.
    let gates_out = Command::new(env!("CARGO_BIN_EXE_ffs-harness"))
        .args(["gates", "--gate", "gate4", "--local"])
        .env("CARGO_BUILD_TARGET", "x86_64-unknown-none")
        .output()
        .expect("spawn ffs-harness gates");
    assert!(
        !gates_out.status.success(),
        "`ffs-harness gates` must exit non-zero when a selected gate fails"
    );
    let gates_json: serde_json::Value =
        serde_json::from_slice(&gates_out.stdout).expect("parse gates report JSON");
    assert_eq!(gates_json["gates"][0]["gate_id"], "gate4");
    assert_eq!(gates_json["gates"][0]["status"], "failed");

    let parity_gate_out = Command::new(env!("CARGO_BIN_EXE_ffs-harness"))
        .args(["parity", "--gate", "gate4", "--local"])
        .env("CARGO_BUILD_TARGET", "x86_64-unknown-none")
        .output()
        .expect("spawn ffs-harness parity --gate gate4");
    assert!(
        !parity_gate_out.status.success(),
        "`ffs-harness parity --gate` must fail closed when the selected gate does not pass"
    );
}

#[test]
fn rejection_only_rows_stay_excluded_from_headlines_with_structured_audit_fields() {
    use ffs_harness::{ParityClassification, ThreeColumnParityReport};

    let sample = vec![
        (
            "ext4 superblock".to_owned(),
            ParityClassification::KernelVerified,
        ),
        (
            "MVCC snapshot visibility".to_owned(),
            ParityClassification::Implemented,
        ),
        (
            "btrfs RAID56 write rejection contract".to_owned(),
            ParityClassification::RejectionOnly,
        ),
        (
            "unexecuted suite row".to_owned(),
            ParityClassification::Unverified,
        ),
    ];
    let three_col =
        ThreeColumnParityReport::from_classifications(&sample, Some("deadbeef".into()), None);
    three_col
        .verify_rejection_excluded()
        .expect("rejection-only contract coverage must stay excluded from headline counts");
    assert_eq!(three_col.headline_counts(), (2, 3));
    assert_eq!(three_col.rejection_only_rows, 1);

    let (_, report) = run_public_parity(&[]);
    let git_sha = report["source"]["git_sha"].as_str().unwrap_or_default();
    let dirty_sha = report["source"]["dirty_source_sha256"]
        .as_str()
        .unwrap_or_default();
    let stdout_sha = report["runs"][0]["execution"]["stdout_sha256"]
        .as_str()
        .unwrap_or_default();
    assert!(!git_sha.is_empty() && !dirty_sha.is_empty() && !stdout_sha.is_empty());
    println!(
        "SCENARIO_RESULT|scenario_id=parity_adversarial_audit|command=cargo|stdout_sha256={stdout_sha}|git_sha={git_sha}|dirty_source_sha256={dirty_sha}|expected=rejection_excluded|actual=verified"
    );
}
