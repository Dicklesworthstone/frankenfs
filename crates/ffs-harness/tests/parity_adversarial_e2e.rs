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
