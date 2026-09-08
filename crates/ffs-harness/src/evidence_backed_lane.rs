//! Evidence-backed lane execution for release gate validation.
//!
//! Each release gate lane (fuse, repair_lab, crash_replay, conformance) executes
//! a real command and captures `ExecutedEvidence` proving the execution happened.
//! The evidence includes command, args, exit code, output hashes, and git state.

use crate::executed_evidence::{ExecutedEvidence, ExecutionOutcome};
use crate::proof_bundle::ProofBundleOutcome;
use serde::Serialize;

/// A release-gate lane backed by real execution evidence.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceBackedLane {
    /// Lane identifier matching REQUIRED_PROOF_BUNDLE_LANES.
    pub lane_id: String,
    /// The lane outcome derived from execution.
    pub outcome: ProofBundleOutcome,
    /// Evidence of the actual execution.
    pub evidence: ExecutedEvidence,
    /// Human-readable summary of the lane result.
    pub summary: String,
}

impl EvidenceBackedLane {
    /// Derive lane outcome from execution evidence.
    fn outcome_from_evidence(evidence: &ExecutedEvidence) -> ProofBundleOutcome {
        match evidence.outcome() {
            ExecutionOutcome::Success => ProofBundleOutcome::Pass,
            ExecutionOutcome::Failed { .. } | ExecutionOutcome::Signaled => {
                ProofBundleOutcome::Fail
            }
            ExecutionOutcome::Skipped { .. } => ProofBundleOutcome::Skip,
            ExecutionOutcome::LaunchFailed { .. } => ProofBundleOutcome::Error,
        }
    }

    fn build_summary(lane_id: &str, evidence: &ExecutedEvidence) -> String {
        let status = match evidence.outcome() {
            ExecutionOutcome::Success => "passed",
            ExecutionOutcome::Failed { exit_code } => {
                let stdout_sha256 = evidence.stdout_sha256();
                return format!(
                    "lane {lane_id} failed with exit code {exit_code}; stdout_sha256={stdout_sha256}"
                );
            }
            ExecutionOutcome::Signaled => "terminated by signal",
            ExecutionOutcome::Skipped { reason } => {
                return format!("lane {lane_id} skipped: {reason}");
            }
            ExecutionOutcome::LaunchFailed { error } => {
                return format!("lane {lane_id} launch failed: {error}");
            }
        };
        format!(
            "lane {} {}; command={} exit_code={:?} duration_ms={} stdout_sha256={}",
            lane_id,
            status,
            evidence.command(),
            evidence.exit_code(),
            evidence.duration_ms(),
            evidence.stdout_sha256()
        )
    }
}

/// Configuration for a lane's execution command.
#[derive(Debug, Clone)]
pub struct LaneCommand {
    pub lane_id: &'static str,
    pub command: &'static str,
    pub args: &'static [&'static str],
    pub capability_check: Option<fn() -> Result<(), String>>,
}

/// The canonical release-gate lane commands.
pub const RELEASE_GATE_LANE_COMMANDS: &[LaneCommand] = &[
    LaneCommand {
        lane_id: "fuse",
        command: "cargo",
        args: &[
            "test",
            "-p",
            "ffs-harness",
            "--",
            "--test-threads=1",
            "fuse_capability",
        ],
        capability_check: Some(check_fuse_capability),
    },
    LaneCommand {
        lane_id: "repair_lab",
        command: "cargo",
        args: &[
            "test",
            "-p",
            "ffs-harness",
            "--",
            "--test-threads=1",
            "repair_confidence_lab",
        ],
        capability_check: None,
    },
    LaneCommand {
        lane_id: "crash_replay",
        command: "cargo",
        args: &[
            "test",
            "-p",
            "ffs-harness",
            "--",
            "--test-threads=1",
            "crash_replay",
        ],
        capability_check: None,
    },
    LaneCommand {
        lane_id: "conformance",
        command: "cargo",
        args: &[
            "test",
            "-p",
            "ffs-harness",
            "--",
            "--test-threads=1",
            "conformance",
        ],
        capability_check: None,
    },
];

fn check_fuse_capability() -> Result<(), String> {
    if !std::path::Path::new("/dev/fuse").exists() {
        return Err("FUSE device /dev/fuse not available".to_string());
    }
    let fusermount_check = std::process::Command::new("which")
        .arg("fusermount3")
        .output();
    match fusermount_check {
        Ok(output) if output.status.success() => Ok(()),
        Ok(_) => {
            let fallback = std::process::Command::new("which")
                .arg("fusermount")
                .output();
            match fallback {
                Ok(out) if out.status.success() => Ok(()),
                _ => Err("fusermount3 or fusermount not found in PATH".to_string()),
            }
        }
        Err(e) => Err(format!("failed to check fusermount availability: {e}")),
    }
}

fn check_xfstests_capability() -> Result<(), String> {
    let xfstests_paths = ["third_party/xfstests-dev/check", "/opt/xfstests-dev/check"];
    let mut xfstests_found = false;
    for path in &xfstests_paths {
        if std::path::Path::new(path).exists() {
            xfstests_found = true;
            break;
        }
    }
    if !xfstests_found {
        return Err("xfstests not available (checked third_party/xfstests-dev/check and /opt/xfstests-dev/check)".to_string());
    }

    let mut missing = Vec::new();

    let fsstress = std::process::Command::new("which").arg("fsstress").output();
    if !matches!(fsstress, Ok(ref o) if o.status.success()) {
        missing.push("fsstress (from ltp-fsstress)");
    }

    let test_dir = std::env::var("TEST_DIR").ok();
    let scratch_mnt = std::env::var("SCRATCH_MNT").ok();
    if test_dir.is_none() || scratch_mnt.is_none() {
        missing.push("TEST_DIR and SCRATCH_MNT environment variables");
    }

    if !missing.is_empty() {
        return Err(format!(
            "xfstests prerequisites missing: {}; set up xfstests environment or run via ffs_xfstests_preflight_e2e.sh",
            missing.join(", ")
        ));
    }

    Ok(())
}

/// Permissioned lanes that require explicit ACK environment variables.
/// These are separate from RELEASE_GATE_LANE_COMMANDS because they run
/// shell scripts with ACK requirements, not cargo test commands.
pub const PERMISSIONED_LANE_COMMANDS: &[LaneCommand] = &[LaneCommand {
    lane_id: "xfstests",
    command: "scripts/e2e/ffs_xfstests_executed_evidence_e2e.sh",
    args: &[],
    capability_check: Some(check_xfstests_capability),
}];

/// Execute the xfstests lane with ExecutedEvidence capture.
#[must_use]
pub fn execute_xfstests_lane() -> EvidenceBackedLane {
    let lane_cmd = PERMISSIONED_LANE_COMMANDS
        .iter()
        .find(|cmd| cmd.lane_id == "xfstests")
        .expect("xfstests lane must exist in PERMISSIONED_LANE_COMMANDS");
    execute_lane(lane_cmd)
}

/// Find a permissioned lane command by lane_id.
#[must_use]
pub fn find_permissioned_lane_command(lane_id: &str) -> Option<&'static LaneCommand> {
    PERMISSIONED_LANE_COMMANDS
        .iter()
        .find(|cmd| cmd.lane_id == lane_id)
}

/// Execute a single lane and capture evidence.
#[must_use]
pub fn execute_lane(lane_cmd: &LaneCommand) -> EvidenceBackedLane {
    let evidence = lane_cmd.capability_check.map_or_else(
        || ExecutedEvidence::run(lane_cmd.command, lane_cmd.args),
        |check| ExecutedEvidence::run_with_prerequisite(lane_cmd.command, lane_cmd.args, check),
    );

    let outcome = EvidenceBackedLane::outcome_from_evidence(&evidence);
    let summary = EvidenceBackedLane::build_summary(lane_cmd.lane_id, &evidence);

    EvidenceBackedLane {
        lane_id: lane_cmd.lane_id.to_string(),
        outcome,
        evidence,
        summary,
    }
}

/// Execute all release-gate lanes and collect evidence.
#[must_use]
pub fn execute_all_release_gate_lanes() -> Vec<EvidenceBackedLane> {
    RELEASE_GATE_LANE_COMMANDS
        .iter()
        .map(execute_lane)
        .collect()
}

/// Find the lane command definition for a given lane_id.
#[must_use]
pub fn find_lane_command(lane_id: &str) -> Option<&'static LaneCommand> {
    RELEASE_GATE_LANE_COMMANDS
        .iter()
        .find(|cmd| cmd.lane_id == lane_id)
}

/// Report summarizing evidence-backed lane execution.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceBackedLaneReport {
    pub lanes: Vec<EvidenceBackedLane>,
    pub all_passed: bool,
    pub pass_count: usize,
    pub fail_count: usize,
    pub skip_count: usize,
    pub error_count: usize,
}

impl EvidenceBackedLaneReport {
    #[must_use]
    pub fn from_lanes(lanes: Vec<EvidenceBackedLane>) -> Self {
        let pass_count = lanes
            .iter()
            .filter(|l| l.outcome == ProofBundleOutcome::Pass)
            .count();
        let fail_count = lanes
            .iter()
            .filter(|l| l.outcome == ProofBundleOutcome::Fail)
            .count();
        let skip_count = lanes
            .iter()
            .filter(|l| l.outcome == ProofBundleOutcome::Skip)
            .count();
        let error_count = lanes
            .iter()
            .filter(|l| l.outcome == ProofBundleOutcome::Error)
            .count();
        let all_passed = !lanes.is_empty()
            && pass_count == lanes.len()
            && fail_count == 0
            && skip_count == 0
            && error_count == 0;

        Self {
            lanes,
            all_passed,
            pass_count,
            fail_count,
            skip_count,
            error_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executed_evidence::HostClass;

    #[test]
    fn outcome_from_evidence_maps_success_to_pass() {
        let evidence = ExecutedEvidence::run("true", &[]);
        assert!(evidence.outcome().is_success());
        assert_eq!(
            EvidenceBackedLane::outcome_from_evidence(&evidence),
            ProofBundleOutcome::Pass
        );
    }

    #[test]
    fn outcome_from_evidence_maps_failure_to_fail() {
        let evidence = ExecutedEvidence::run("false", &[]);
        assert!(evidence.outcome().is_failure());
        assert_eq!(
            EvidenceBackedLane::outcome_from_evidence(&evidence),
            ProofBundleOutcome::Fail
        );
    }

    #[test]
    fn outcome_from_evidence_maps_skipped_to_skip() {
        let evidence =
            ExecutedEvidence::run_with_prerequisite("true", &[], || Err("test skip".to_string()));
        assert!(evidence.outcome().is_skipped());
        assert_eq!(
            EvidenceBackedLane::outcome_from_evidence(&evidence),
            ProofBundleOutcome::Skip
        );
    }

    #[test]
    fn outcome_from_evidence_maps_launch_failure_to_error() {
        let evidence = ExecutedEvidence::run("nonexistent_command_xyz_123", &[]);
        assert!(matches!(
            evidence.outcome(),
            ExecutionOutcome::LaunchFailed { .. }
        ));
        assert_eq!(
            EvidenceBackedLane::outcome_from_evidence(&evidence),
            ProofBundleOutcome::Error
        );
    }

    #[test]
    fn execute_lane_captures_evidence_for_passing_command() {
        let lane_cmd = LaneCommand {
            lane_id: "test_lane",
            command: "echo",
            args: &["hello"],
            capability_check: None,
        };

        let result = execute_lane(&lane_cmd);

        assert_eq!(result.lane_id, "test_lane");
        assert_eq!(result.outcome, ProofBundleOutcome::Pass);
        assert_eq!(result.evidence.command(), "echo");
        assert_eq!(result.evidence.args(), ["hello"]);
        assert_eq!(result.evidence.exit_code(), Some(0));
        assert!(result.evidence.outcome().is_success());
        assert_ne!(result.evidence.stdout_sha256(), "");
        assert_ne!(result.evidence.git_sha(), "");
        assert!(result.summary.contains("passed"));
        assert!(result.summary.contains("stdout_sha256="));
    }

    #[test]
    fn execute_lane_captures_evidence_for_failing_command() {
        let lane_cmd = LaneCommand {
            lane_id: "fail_lane",
            command: "false",
            args: &[],
            capability_check: None,
        };

        let result = execute_lane(&lane_cmd);

        assert_eq!(result.lane_id, "fail_lane");
        assert_eq!(result.outcome, ProofBundleOutcome::Fail);
        assert_eq!(result.evidence.exit_code(), Some(1));
        assert!(result.evidence.outcome().is_failure());
        assert!(result.summary.contains("failed"));
        assert!(result.summary.contains("exit code 1"));
    }

    #[test]
    fn execute_lane_respects_capability_check() {
        let lane_cmd = LaneCommand {
            lane_id: "gated_lane",
            command: "echo",
            args: &["should not run"],
            capability_check: Some(|| Err("capability missing".to_string())),
        };

        let result = execute_lane(&lane_cmd);

        assert_eq!(result.lane_id, "gated_lane");
        assert_eq!(result.outcome, ProofBundleOutcome::Skip);
        assert!(result.evidence.outcome().is_skipped());
        assert_eq!(result.evidence.duration_ms(), 0);
        assert!(result.summary.contains("skipped"));
        assert!(result.summary.contains("capability missing"));
    }

    #[test]
    fn execute_lane_runs_when_capability_check_passes() {
        let lane_cmd = LaneCommand {
            lane_id: "capable_lane",
            command: "echo",
            args: &["capable"],
            capability_check: Some(|| Ok(())),
        };

        let result = execute_lane(&lane_cmd);

        assert_eq!(result.outcome, ProofBundleOutcome::Pass);
        assert!(result.evidence.outcome().is_success());
    }

    #[test]
    fn find_lane_command_returns_known_lanes() {
        assert!(find_lane_command("fuse").is_some());
        assert!(find_lane_command("repair_lab").is_some());
        assert!(find_lane_command("crash_replay").is_some());
        assert!(find_lane_command("conformance").is_some());
        assert!(find_lane_command("nonexistent").is_none());
    }

    #[test]
    fn release_gate_lanes_have_correct_structure() {
        for lane_cmd in RELEASE_GATE_LANE_COMMANDS {
            assert_ne!(lane_cmd.lane_id, "");
            assert_ne!(lane_cmd.command, "");
            assert!(
                lane_cmd.command == "cargo",
                "release gate lanes use cargo test"
            );
        }
        assert_eq!(
            RELEASE_GATE_LANE_COMMANDS
                .iter()
                .filter(|cmd| cmd.capability_check.is_some())
                .count(),
            1,
            "only fuse lane has capability check"
        );
    }

    #[test]
    fn evidence_backed_lane_report_counts_outcomes() {
        let lanes = vec![
            EvidenceBackedLane {
                lane_id: "pass1".to_string(),
                outcome: ProofBundleOutcome::Pass,
                evidence: ExecutedEvidence::run("true", &[]),
                summary: "passed".to_string(),
            },
            EvidenceBackedLane {
                lane_id: "pass2".to_string(),
                outcome: ProofBundleOutcome::Pass,
                evidence: ExecutedEvidence::run("true", &[]),
                summary: "passed".to_string(),
            },
            EvidenceBackedLane {
                lane_id: "fail1".to_string(),
                outcome: ProofBundleOutcome::Fail,
                evidence: ExecutedEvidence::run("false", &[]),
                summary: "failed".to_string(),
            },
            EvidenceBackedLane {
                lane_id: "skip1".to_string(),
                outcome: ProofBundleOutcome::Skip,
                evidence: ExecutedEvidence::run_with_prerequisite("true", &[], || {
                    Err("skip".to_string())
                }),
                summary: "skipped".to_string(),
            },
        ];

        let report = EvidenceBackedLaneReport::from_lanes(lanes);

        assert_eq!(report.pass_count, 2);
        assert_eq!(report.fail_count, 1);
        assert_eq!(report.skip_count, 1);
        assert_eq!(report.error_count, 0);
        assert!(!report.all_passed);
    }

    #[test]
    fn evidence_backed_lane_report_all_passed_when_every_lane_passes() {
        let lanes = vec![
            EvidenceBackedLane {
                lane_id: "pass1".to_string(),
                outcome: ProofBundleOutcome::Pass,
                evidence: ExecutedEvidence::run("true", &[]),
                summary: "passed".to_string(),
            },
            EvidenceBackedLane {
                lane_id: "pass2".to_string(),
                outcome: ProofBundleOutcome::Pass,
                evidence: ExecutedEvidence::run("true", &[]),
                summary: "passed".to_string(),
            },
        ];

        let report = EvidenceBackedLaneReport::from_lanes(lanes);

        assert!(report.all_passed);
        assert_eq!(report.pass_count, 2);
        assert_eq!(report.skip_count, 0);
    }

    #[test]
    fn evidence_backed_lane_report_not_all_passed_when_any_lane_skips() {
        let lanes = vec![
            EvidenceBackedLane {
                lane_id: "pass1".to_string(),
                outcome: ProofBundleOutcome::Pass,
                evidence: ExecutedEvidence::run("true", &[]),
                summary: "passed".to_string(),
            },
            EvidenceBackedLane {
                lane_id: "skip1".to_string(),
                outcome: ProofBundleOutcome::Skip,
                evidence: ExecutedEvidence::run_with_prerequisite("true", &[], || {
                    Err("skip".to_string())
                }),
                summary: "skipped".to_string(),
            },
        ];

        let report = EvidenceBackedLaneReport::from_lanes(lanes);

        assert!(!report.all_passed);
        assert_eq!(report.pass_count, 1);
        assert_eq!(report.skip_count, 1);
    }

    #[test]
    fn evidence_backed_lane_report_empty_lanes_are_not_all_passed() {
        let report = EvidenceBackedLaneReport::from_lanes(Vec::new());

        assert!(!report.all_passed);
        assert_eq!(report.pass_count, 0);
        assert_eq!(report.skip_count, 0);
    }

    #[test]
    fn lane_evidence_captures_git_sha_and_host_class() {
        let lane_cmd = LaneCommand {
            lane_id: "meta_lane",
            command: "echo",
            args: &["meta"],
            capability_check: None,
        };

        let result = execute_lane(&lane_cmd);

        assert_ne!(result.evidence.git_sha(), "");
        assert!(!matches!(result.evidence.host_class(), HostClass::Unknown));
    }

    #[test]
    fn lane_evidence_is_serializable_to_json() {
        let lane_cmd = LaneCommand {
            lane_id: "json_lane",
            command: "echo",
            args: &["json"],
            capability_check: None,
        };

        let result = execute_lane(&lane_cmd);
        let json = serde_json::to_string(&result).unwrap();

        assert!(json.contains("\"lane_id\":\"json_lane\""));
        assert!(json.contains("\"outcome\":\"pass\""));
        assert!(json.contains("\"command\":\"echo\""));
        assert!(json.contains("\"stdout_sha256\":"));
        assert!(json.contains("\"git_sha\":"));
    }

    #[test]
    fn find_permissioned_lane_command_returns_xfstests() {
        assert!(find_permissioned_lane_command("xfstests").is_some());
        assert!(find_permissioned_lane_command("nonexistent").is_none());
    }

    #[test]
    fn permissioned_lane_commands_have_correct_structure() {
        for lane_cmd in PERMISSIONED_LANE_COMMANDS {
            assert_ne!(lane_cmd.lane_id, "");
            assert_ne!(lane_cmd.command, "");
            assert!(
                lane_cmd.capability_check.is_some(),
                "permissioned lanes require capability checks"
            );
        }
    }

    #[test]
    fn xfstests_lane_has_capability_check() {
        let xfstests_lane =
            find_permissioned_lane_command("xfstests").expect("xfstests lane must exist");
        assert_eq!(xfstests_lane.lane_id, "xfstests");
        assert!(xfstests_lane.command.contains("xfstests"));
        assert!(xfstests_lane.capability_check.is_some());
    }

    #[test]
    fn xfstests_lane_skips_when_prerequisites_missing() {
        let result = execute_xfstests_lane();
        assert_eq!(result.lane_id, "xfstests");
        assert!(
            result.outcome == ProofBundleOutcome::Skip,
            "xfstests lane should skip when prerequisites missing; got outcome={:?} summary={}",
            result.outcome,
            result.summary
        );
        assert!(result.evidence.outcome().is_skipped());
        assert!(result.summary.contains("skipped"));
    }
}
