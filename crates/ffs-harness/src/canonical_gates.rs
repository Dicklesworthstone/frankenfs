//! Canonical spec §22 verification gates, executed rather than declared.
//!
//! `COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md` §22.1 names seven gates and gives each
//! an exact Cargo command; §22.2 says every gate is a `#[test]` function behind
//! `#[ignore]`, run through `--include-ignored`. Nothing in this workspace ran
//! those commands, so `cargo test -p ffs-ondisk -- --include-ignored gate1` exited
//! 0 having selected ZERO tests: a green result for a gate that executed nothing.
//!
//! This module executes the command §22 names, through the same
//! [`crate::executed_evidence::TestRunEvidence`] path the public parity consumers
//! already use, and classifies the result fail-closed:
//!
//! * [`CanonicalGateStatus::Passed`] — the command selected at least one test and
//!   every selected test passed, bound to the current source bytes.
//! * [`CanonicalGateStatus::Failed`] — the gate has executable tests and they
//!   failed, were skipped or ignored, or the run could not be read.
//! * [`CanonicalGateStatus::NotImplemented`] — the filter selected no test at all.
//!   A zero-match Cargo filter is never reported as `Passed`, and it never
//!   promotes readiness.
//!
//! Reports are execution artifacts: `Serialize` but deliberately not
//! `Deserialize`, so a saved report cannot be loaded back to manufacture credit.
//! The raw libtest counts, exact test names and the process evidence behind each
//! status stay in the report for independent review.

use crate::ParityExecutor;
use crate::executed_evidence::{ExecutedEvidence, SourceIdentity, TestOutcome, TestRunEvidence};
use anyhow::{Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// One canonical verification gate from spec §22.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalGate {
    /// Stable gate id, which is also the libtest filter the spec names.
    pub id: &'static str,
    /// Spec phase the gate closes.
    pub phase: &'static str,
    /// Short title.
    pub title: &'static str,
    /// The command §22.1 names, verbatim. [`gate_invocation`] derives argv from
    /// [`Self::packages`] and [`Self::filter`]; a test asserts the two agree, so
    /// the catalog cannot drift away from the spec text.
    pub spec_command: &'static str,
    /// `cargo -p` package selection, in the spec command's order. Empty means the
    /// spec command selects with `--workspace`.
    pub packages: &'static [&'static str],
    /// libtest filter: the spec command's trailing positional argument.
    pub filter: &'static str,
    /// Condensed §22.1 acceptance criteria, reported so an unimplemented gate
    /// states what it still has to prove.
    pub criteria: &'static [&'static str],
}

/// The seven gates of §22.1, in spec order.
pub const CANONICAL_GATES: &[CanonicalGate] = &[
    CanonicalGate {
        id: "gate1",
        phase: "Phase 2 (on-disk format parsing)",
        title: "On-disk format parsing",
        spec_command: "cargo test -p ffs-ondisk -- --include-ignored gate1",
        packages: &["ffs-ondisk"],
        filter: "gate1",
        criteria: &[
            "10 real ext4 images covering 1 KiB / 2 KiB / 4 KiB blocks, the declared feature combinations, 1 MB to 10 GB sizes and 4.x/5.x/6.x source kernels",
            "byte-for-byte superblock parse/serialize round trip per image",
            "32-byte and 64-byte group descriptors parsed with checksums verified",
            "every inode in every group parsed with its checksum verified",
            "zero panics or unwrap failures across 10,000 mutated images",
        ],
    },
    CanonicalGate {
        id: "gate2",
        phase: "Phase 4 (extent resolution)",
        title: "Extent resolution",
        spec_command: "cargo test -p ffs-btree -p ffs-extent -- --include-ignored gate2",
        packages: &["ffs-btree", "ffs-extent"],
        filter: "gate2",
        criteria: &[
            "every extent of every regular file resolved on each Gate 1 image",
            "physical block numbers match `debugfs -R 'blocks <ino>'` exactly",
            "sparse holes return no mapping",
            "depth-0, depth-1 and depth-2 extent trees handled",
            "a 10,000-extent file resolves in under 100 ms",
        ],
    },
    CanonicalGate {
        id: "gate3",
        phase: "Phase 5 (directory listing)",
        title: "Directory listing",
        spec_command: "cargo test -p ffs-dir -- --include-ignored gate3",
        packages: &["ffs-dir"],
        filter: "gate3",
        criteria: &[
            "`ls -laR` output matches kernel ext4 on each test image",
            "htree hashes match `debugfs -R 'htree <dir>'`",
            "linear directory scan works without `dir_index`",
            "`.` and `..` present and correct in every directory",
            "`d_type` matches inode mode and directory block checksums verify",
        ],
    },
    CanonicalGate {
        id: "gate4",
        phase: "Phase 6 (MVCC concurrency)",
        title: "MVCC concurrency",
        spec_command: "cargo test -p ffs-mvcc -- --include-ignored gate4",
        packages: &["ffs-mvcc"],
        filter: "gate4",
        criteria: &[
            "visibility correct across bounded LabRuntime interleavings of 4 transactions on 8 blocks",
            "SSI aborts one side of at least 10 distinct write-skew patterns",
            "GC never prunes a version visible to an active snapshot",
            "8 threads x 10,000 transactions with zero assertion failures under the thread sanitizer",
            "cache-hit read under 500 ns and version-creating write under 2 us",
        ],
    },
    CanonicalGate {
        id: "gate5",
        phase: "Phase 7 (FUSE mount and POSIX operations)",
        title: "FUSE mount and POSIX operations",
        spec_command: "cargo test -p ffs-fuse -- --include-ignored gate5",
        packages: &["ffs-fuse"],
        filter: "gate5",
        criteria: &[
            "each Gate 1 image mounts over FUSE in JBD2-compatible mode",
            "open/read/write/lseek/stat/mkdir/rmdir/rename/unlink/symlink/chmod/fsync/truncate behave correctly",
            "crash without unmount then remount preserves every fsync'd byte",
            "error paths return the correct errno",
            "a clean unmount then kernel ext4 read returns the written pattern",
        ],
    },
    CanonicalGate {
        id: "gate6",
        phase: "Phase 8 (RaptorQ self-healing)",
        title: "RaptorQ self-healing",
        spec_command: "cargo test -p ffs-repair -- --include-ignored gate6",
        packages: &["ffs-repair"],
        filter: "gate6",
        criteria: &[
            "1% injected block corruption recovers 100% against a known-good copy",
            "uncorrupted blocks are not rewritten",
            "repair symbols are refreshed after new writes protect the new data",
            "a corrupted repair symbol still permits recovery through the systematic property",
            "a 128 MB group at 5% corruption repairs in under 5 s",
        ],
    },
    CanonicalGate {
        id: "gate7",
        phase: "Phase 9 (full conformance and user-facing tools)",
        title: "Full conformance and user-facing tools",
        spec_command: "cargo test --workspace -- --include-ignored gate7",
        packages: &[],
        filter: "gate7",
        criteria: &[
            "gates 1-6 pass in a single CI run",
            "the mount / info / scrub / umount / fsck CLI sequence completes",
            "the TUI dashboard reports cache, MVCC, repair and I/O statistics at 1 Hz",
            "user-facing errors name what failed and what to do next",
            "umount completes within 5 s and an hour of load leaks no file descriptor or unbounded memory",
        ],
    },
];

/// Every gate id, in spec order, for error messages and CLI defaults.
#[must_use]
pub fn canonical_gate_ids() -> Vec<&'static str> {
    CANONICAL_GATES.iter().map(|gate| gate.id).collect()
}

/// Selection token that expands to every gate.
pub const ALL_GATES_ARG: &str = "all";

/// Look up one gate by id.
#[must_use]
pub fn canonical_gate(id: &str) -> Option<&'static CanonicalGate> {
    CANONICAL_GATES.iter().find(|gate| gate.id == id)
}

/// Validate a caller-supplied gate selection. `all` expands to every gate.
///
/// Unknown ids are refused rather than ignored: a misspelled gate must not
/// silently run nothing.
pub(crate) fn select_gate_ids(gate_ids: &[String]) -> Result<BTreeSet<&'static str>> {
    let mut selected = BTreeSet::new();
    for id in gate_ids {
        let ids = if id == ALL_GATES_ARG {
            canonical_gate_ids()
        } else {
            vec![
                canonical_gate(id)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "unknown canonical gate {id}; expected {ALL_GATES_ARG} or one of {}",
                            canonical_gate_ids().join(", ")
                        )
                    })?
                    .id,
            ]
        };
        for gate_id in ids {
            if !selected.insert(gate_id) {
                bail!("duplicate canonical gate {gate_id}");
            }
        }
    }
    Ok(selected)
}

/// Build the argv for one gate: the spec command plus the machine-readable
/// libtest stream the evidence parser requires.
fn gate_invocation(gate: &CanonicalGate, executor: ParityExecutor) -> (&'static str, Vec<String>) {
    let mut args: Vec<String> = ["-Z", "checksum-freshness", "test"]
        .iter()
        .map(|arg| (*arg).to_owned())
        .collect();
    if gate.packages.is_empty() {
        args.push("--workspace".to_owned());
    } else {
        for package in gate.packages {
            args.push("-p".to_owned());
            args.push((*package).to_owned());
        }
    }
    args.extend(
        [
            "--",
            "--include-ignored",
            gate.filter,
            "-Z",
            "unstable-options",
            "--format=json",
            "--show-output",
            "--test-threads=1",
        ]
        .iter()
        .map(|arg| (*arg).to_owned()),
    );
    match executor {
        ParityExecutor::Cargo => ("cargo", args),
        ParityExecutor::Rch => {
            let mut prefixed: Vec<String> = ["exec", "--source-content-receipt", "--", "cargo"]
                .iter()
                .map(|arg| (*arg).to_owned())
                .collect();
            prefixed.extend(args);
            ("rch", prefixed)
        }
    }
}

/// Execute every selected gate, in id order, returning one run per gate.
///
/// Exposed so a caller that already captured a [`SourceIdentity`] can bind the
/// gate runs to the same source bytes as its own runs.
pub fn execute_runs(
    selected: &BTreeSet<&'static str>,
    executor: ParityExecutor,
) -> Vec<TestRunEvidence> {
    selected
        .iter()
        .map(|id| {
            let gate = canonical_gate(id).expect("selected ids come from the catalog");
            let (command, args) = gate_invocation(gate, executor);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            TestRunEvidence::run(command, &args)
        })
        .collect()
}

/// Classification of one gate after execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalGateStatus {
    /// At least one test was selected and every selected test passed.
    Passed,
    /// Tests exist for this gate and the run did not pass, or the run could not
    /// be read, or the source binding was lost.
    Failed,
    /// The filter selected no test: the gate has no executable test yet.
    NotImplemented,
}

/// Executed evidence for one gate.
#[derive(Debug, Clone, Serialize)]
pub struct CanonicalGateEvidence {
    /// Gate id from §22.1.
    pub gate_id: &'static str,
    /// Spec phase the gate closes.
    pub phase: &'static str,
    /// The command §22.1 names.
    pub spec_command: &'static str,
    /// What the gate still has to prove.
    pub criteria: &'static [&'static str],
    /// Fail-closed classification.
    pub status: CanonicalGateStatus,
    /// Why the gate did not pass; `None` only for [`CanonicalGateStatus::Passed`].
    pub reason: Option<String>,
    /// Tests selected by the filter.
    pub selected: u64,
    /// Tests that actually ran.
    pub executed: u64,
    /// Tests that passed.
    pub passed: u64,
    /// Tests that failed.
    pub failed: u64,
    /// Tests skipped, ignored or soft-skipped.
    pub skipped: u64,
    /// Tests in the target that the filter excluded.
    pub filtered_out: u64,
    /// Exact per-test outcomes, by test name.
    pub tests: BTreeMap<String, TestOutcome>,
    /// Process evidence for the invocation itself. `None` when the gate produced
    /// no execution at all, which is never a pass.
    pub execution: Option<ExecutedEvidence>,
}

/// Gate results for one selection. Not `Deserialize` by design.
#[derive(Debug, Clone, Serialize)]
pub struct CanonicalGateReport {
    /// One entry per selected gate, in catalog order.
    pub gates: Vec<CanonicalGateEvidence>,
    /// Selected gate ids, in catalog order.
    pub selected_gates: Vec<String>,
    /// Source identity the runs were bound to.
    pub source: Option<SourceIdentity>,
}

impl CanonicalGateReport {
    /// Report for a run that requested no gate. Never claims readiness.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            gates: Vec::new(),
            selected_gates: Vec::new(),
            source: None,
        }
    }

    /// Execute the named gates. No paths, shell strings, reports or
    /// caller-supplied pass/fail maps are accepted as gate evidence.
    pub fn run(gate_ids: &[String], executor: ParityExecutor) -> Result<Self> {
        let selected = select_gate_ids(gate_ids)?;
        let source = SourceIdentity::capture().ok();
        let runs = execute_runs(&selected, executor);
        Ok(Self::from_runs(&selected, &runs, source))
    }

    pub(crate) fn from_runs(
        selected: &BTreeSet<&'static str>,
        runs: &[TestRunEvidence],
        source: Option<SourceIdentity>,
    ) -> Self {
        let gates = CANONICAL_GATES
            .iter()
            .filter(|gate| selected.iter().any(|id| *id == gate.id))
            .map(|gate| {
                let run = selected
                    .iter()
                    .position(|id| *id == gate.id)
                    .and_then(|index| runs.get(index));
                evidence_for(gate, run, source.as_ref())
            })
            .collect();
        Self {
            gates,
            selected_gates: selected.iter().map(|id| (*id).to_owned()).collect(),
            source,
        }
    }

    /// Gates that executed a nonempty suite and passed.
    #[must_use]
    pub fn passed_gates(&self) -> Vec<&str> {
        self.with_status(CanonicalGateStatus::Passed)
    }

    /// Gates that have executable tests and did not pass.
    #[must_use]
    pub fn failed_gates(&self) -> Vec<&str> {
        self.with_status(CanonicalGateStatus::Failed)
    }

    /// Gates whose filter selected no test.
    #[must_use]
    pub fn not_implemented_gates(&self) -> Vec<&str> {
        self.with_status(CanonicalGateStatus::NotImplemented)
    }

    fn with_status(&self, status: CanonicalGateStatus) -> Vec<&str> {
        self.gates
            .iter()
            .filter(|gate| gate.status == status)
            .map(|gate| gate.gate_id)
            .collect()
    }

    /// True only when at least one gate ran and every selected gate passed.
    ///
    /// An empty selection and `NotImplemented` gates are both `false`: absence of
    /// evidence is never readiness.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        !self.gates.is_empty()
            && self.failed_gates().is_empty()
            && self.not_implemented_gates().is_empty()
    }

    /// Fail-closed readiness gate. `NotImplemented` counts as not passed.
    pub fn require_all_passed(&self) -> Result<(), String> {
        if self.gates.is_empty() {
            return Err("no canonical gate was executed".to_owned());
        }
        let mut blockers = Vec::new();
        for gate in &self.gates {
            match gate.status {
                CanonicalGateStatus::Passed => {}
                CanonicalGateStatus::NotImplemented => blockers.push(format!(
                    "{}: not implemented ({})",
                    gate.gate_id,
                    gate.reason.as_deref().unwrap_or("no test selected")
                )),
                CanonicalGateStatus::Failed => blockers.push(format!(
                    "{}: failed ({})",
                    gate.gate_id,
                    gate.reason.as_deref().unwrap_or("no reason recorded")
                )),
            }
        }
        if blockers.is_empty() {
            Ok(())
        } else {
            Err(blockers.join("; "))
        }
    }
}

fn evidence_for(
    gate: &CanonicalGate,
    run: Option<&TestRunEvidence>,
    source: Option<&SourceIdentity>,
) -> CanonicalGateEvidence {
    let (status, reason) = classify(gate, run, source);
    let results = run.map(TestRunEvidence::results);
    CanonicalGateEvidence {
        gate_id: gate.id,
        phase: gate.phase,
        spec_command: gate.spec_command,
        criteria: gate.criteria,
        status,
        reason,
        selected: results.map_or(0, |results| results.selected),
        executed: results.map_or(0, |results| results.executed),
        passed: results.map_or(0, |results| results.passed),
        failed: results.map_or(0, |results| results.failed),
        skipped: results.map_or(0, |results| results.skipped),
        filtered_out: results.map_or(0, |results| results.filtered_out),
        tests: results.map_or_else(BTreeMap::new, |results| results.tests.clone()),
        execution: run.map(|run| run.execution().clone()),
    }
}

fn classify(
    gate: &CanonicalGate,
    run: Option<&TestRunEvidence>,
    source: Option<&SourceIdentity>,
) -> (CanonicalGateStatus, Option<String>) {
    let Some(run) = run else {
        return (
            CanonicalGateStatus::Failed,
            Some("gate was selected but produced no execution evidence".to_owned()),
        );
    };
    let Some(source) = source else {
        return (
            CanonicalGateStatus::Failed,
            Some(
                "source identity unavailable; a gate cannot pass unbound to source bytes"
                    .to_owned(),
            ),
        );
    };
    let Err(reason) = run.require_pass(source) else {
        return (CanonicalGateStatus::Passed, None);
    };
    let results = run.results();
    // A Cargo filter that matches nothing exits 0 having run nothing. That is the
    // exact false green this module exists to reject, and the parser marks it
    // distinctly from a malformed or truncated stream.
    if results.empty_selection && run.execution().outcome().is_success() {
        return (
            CanonicalGateStatus::NotImplemented,
            Some(format!(
                "filter `{}` selected 0 tests ({} filtered out), so `{}` exits 0 without executing anything; the gate has no test yet",
                gate.filter, results.filtered_out, gate.spec_command
            )),
        );
    }
    (CanonicalGateStatus::Failed, Some(reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The catalog is derived data; the spec document is the source of truth.
    /// Re-parse §22.1's `**Test Command:**` lines and prove each catalog command
    /// is byte-identical to the one the spec names.
    #[test]
    fn catalog_commands_equal_the_spec_document() {
        const SPEC: &str = include_str!("../../../COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md");
        let declared: Vec<&str> = SPEC
            .lines()
            .filter_map(|line| line.trim().strip_prefix("**Test Command:**"))
            .filter_map(|rest| {
                rest.trim()
                    .strip_prefix('`')
                    .and_then(|rest| rest.strip_suffix('`'))
            })
            .collect();
        assert_eq!(
            declared.len(),
            CANONICAL_GATES.len(),
            "spec §22 command count changed"
        );
        for (gate, command) in CANONICAL_GATES.iter().zip(&declared) {
            assert_eq!(
                gate.spec_command, *command,
                "{} drifted from the spec's Test Command",
                gate.id
            );
        }
    }

    /// The catalog is derived data; §22.1 is the source of truth. Re-parse the
    /// spec command text and prove `packages` + `filter` are exactly what it says.
    #[test]
    fn catalog_commands_match_spec_section_22() {
        let mut seen = BTreeSet::new();
        for gate in CANONICAL_GATES {
            assert!(seen.insert(gate.id), "duplicate gate id {}", gate.id);
            assert!(
                gate.criteria.len() >= 4,
                "{} must state the criteria it asserts",
                gate.id
            );
            let (packages, filter) = parse_spec_command(gate.spec_command);
            assert_eq!(
                packages,
                gate.packages.to_vec(),
                "{} packages drifted from the §22 command",
                gate.id
            );
            assert_eq!(
                filter, gate.filter,
                "{} filter drifted from the §22 command",
                gate.id
            );
        }
        assert_eq!(
            canonical_gate_ids(),
            [
                "gate1", "gate2", "gate3", "gate4", "gate5", "gate6", "gate7"
            ]
        );
    }

    /// Derive `-p` packages and the trailing libtest filter from the spec text.
    fn parse_spec_command(command: &str) -> (Vec<&str>, &str) {
        let tokens: Vec<&str> = command.split_whitespace().collect();
        assert_eq!(&tokens[..2], ["cargo", "test"], "unexpected command shape");
        let separator = tokens
            .iter()
            .position(|token| *token == "--")
            .expect("spec command has a -- separator");
        let head = &tokens[2..separator];
        let packages = head
            .windows(2)
            .filter(|window| window[0] == "-p")
            .map(|window| window[1])
            .collect::<Vec<_>>();
        if packages.is_empty() {
            assert_eq!(head, ["--workspace"], "unexpected workspace selection");
        } else {
            assert_eq!(head.len(), packages.len() * 2, "unexpected package tokens");
        }
        let tail = &tokens[separator + 1..];
        assert_eq!(tail[0], "--include-ignored");
        assert_eq!(tail.len(), 2, "spec command tail must be filter only");
        (packages, tail[1])
    }

    #[test]
    fn gate_arg_argv_keeps_the_spec_selection() {
        for gate in CANONICAL_GATES {
            let (command, args) = gate_invocation(gate, ParityExecutor::Cargo);
            assert_eq!(command, "cargo");
            assert!(args.contains(&gate.filter.to_owned()));
            assert!(args.contains(&"--include-ignored".to_owned()));
            assert_eq!(args[0], "-Z");
            if gate.packages.is_empty() {
                assert!(args.contains(&"--workspace".to_owned()));
            } else {
                for package in gate.packages {
                    assert!(
                        args.windows(2).any(|w| w == ["-p", package]),
                        "{} lost package {package}",
                        gate.id
                    );
                }
            }
            let (remote_command, remote_args) = gate_invocation(gate, ParityExecutor::Rch);
            assert_eq!(remote_command, "rch");
            assert!(remote_args.starts_with(&[
                "exec".to_owned(),
                "--source-content-receipt".to_owned(),
                "--".to_owned(),
                "cargo".to_owned()
            ]));
            assert_eq!(remote_args.len(), args.len() + 4);
        }
    }

    #[test]
    fn selection_rejects_unknown_and_duplicate_gates() {
        assert!(select_gate_ids(&["gate1".to_owned()]).is_ok());
        for bad in ["", "gate0", "gate8", "gate1 ", "GATE1", "--include-ignored"] {
            assert!(
                select_gate_ids(&[bad.to_owned()])
                    .expect_err("unknown gate must be refused")
                    .to_string()
                    .contains("unknown canonical gate"),
                "{bad} was accepted"
            );
        }
        assert!(
            select_gate_ids(&["gate1".to_owned(), "gate1".to_owned()])
                .expect_err("duplicate gate must be refused")
                .to_string()
                .contains("duplicate canonical gate")
        );
        assert_eq!(
            select_gate_ids(&[ALL_GATES_ARG.to_owned()])
                .expect("all expands")
                .len(),
            CANONICAL_GATES.len()
        );
        assert!(select_gate_ids(&[ALL_GATES_ARG.to_owned(), "gate3".to_owned()]).is_err());
    }

    fn child_run(case: &str, name: &str) -> TestRunEvidence {
        let executable = std::env::current_exe().expect("test binary path");
        TestRunEvidence::run(
            "env",
            &[
                &format!("FFS_TEST_EVIDENCE_CHILD={case}"),
                executable.to_str().expect("utf-8 test binary path"),
                "--exact",
                name,
                "-Z",
                "unstable-options",
                "--format=json",
                "--show-output",
            ],
        )
    }

    const CHILD_PROBE: &str = "executed_evidence::tests::test_evidence_child_probe";
    const CHILD_IGNORED_PROBE: &str = "executed_evidence::tests::ignored_evidence_child_probe";

    fn single_gate_report(gate_id: &'static str, run: &TestRunEvidence) -> CanonicalGateReport {
        CanonicalGateReport::from_runs(
            &BTreeSet::from([gate_id]),
            std::slice::from_ref(run),
            SourceIdentity::capture().ok(),
        )
    }

    /// The whole point of the module: a filter that selects nothing can never be
    /// reported as a passing gate, and it is named as unimplemented instead.
    #[test]
    fn zero_selected_filter_is_not_implemented_never_passed() {
        let report = single_gate_report("gate1", &child_run("pass", "no_such_test_exists"));
        assert_eq!(report.gates[0].status, CanonicalGateStatus::NotImplemented);
        assert_eq!(report.gates[0].selected, 0);
        assert_eq!(report.gates[0].executed, 0);
        assert_eq!(
            report.gates[0]
                .execution
                .as_ref()
                .expect("executed")
                .exit_code(),
            Some(0)
        );
        assert_eq!(report.not_implemented_gates(), ["gate1"]);
        assert_eq!(report.failed_gates(), [] as [&str; 0]);
        assert!(!report.all_passed());
        assert!(report.require_all_passed().is_err());

        // The control: the same classification path does report a real pass.
        let passing = single_gate_report("gate1", &child_run("pass", CHILD_PROBE));
        assert_eq!(passing.gates[0].status, CanonicalGateStatus::Passed);
        assert_eq!(passing.gates[0].selected, 1);
        assert_eq!(passing.gates[0].passed, 1);
        assert!(passing.all_passed());
        assert_eq!(passing.require_all_passed(), Ok(()));
    }

    #[test]
    fn failing_skipped_and_ignored_gates_fail_closed() {
        for (case, name) in [
            ("fail", CHILD_PROBE),
            ("skip", CHILD_PROBE),
            ("scenario-skip", CHILD_PROBE),
            ("pass", CHILD_IGNORED_PROBE),
        ] {
            let report = single_gate_report("gate6", &child_run(case, name));
            assert_eq!(
                report.gates[0].status,
                CanonicalGateStatus::Failed,
                "{case}/{name} must not pass"
            );
            assert!(report.gates[0].reason.is_some());
            assert!(!report.all_passed());
            assert!(report.require_all_passed().is_err());
        }
    }

    #[test]
    fn gates_are_bound_to_source_bytes_and_selection_identity() {
        let run = child_run("pass", CHILD_PROBE);
        let mut other_source = SourceIdentity::capture().expect("source identity");
        other_source.dirty_source_sha256.push('0');
        let report = CanonicalGateReport::from_runs(
            &BTreeSet::from(["gate1"]),
            std::slice::from_ref(&run),
            Some(other_source),
        );
        assert_eq!(report.gates[0].status, CanonicalGateStatus::Failed);

        // A missing execution for a selected gate fails closed too.
        let report = CanonicalGateReport::from_runs(
            &BTreeSet::from(["gate2"]),
            &[],
            SourceIdentity::capture().ok(),
        );
        assert_eq!(report.gates[0].status, CanonicalGateStatus::Failed);
        assert!(!report.all_passed());

        assert!(!CanonicalGateReport::empty().all_passed());
        assert!(CanonicalGateReport::empty().require_all_passed().is_err());
    }

    #[test]
    fn report_keeps_exact_names_and_counts_for_review() {
        let report = single_gate_report("gate3", &child_run("pass", CHILD_PROBE));
        let evidence = &report.gates[0];
        assert_eq!(evidence.gate_id, "gate3");
        assert_eq!(evidence.tests.get(CHILD_PROBE), Some(&TestOutcome::Passed));
        assert_eq!(
            evidence.spec_command,
            "cargo test -p ffs-dir -- --include-ignored gate3"
        );
        assert_eq!(evidence.criteria.len(), 5);
        assert_eq!(
            evidence.execution.as_ref().expect("executed").command(),
            "env"
        );
    }
}
