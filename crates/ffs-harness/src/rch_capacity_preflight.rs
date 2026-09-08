use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const RCH_CAPACITY_PREFLIGHT_SCHEMA_VERSION: u32 = 1;
pub const RCH_CAPACITY_PREFLIGHT_VALIDATION_SCHEMA_VERSION: u32 = 1;

const EXPECTED_PROBE_COMMAND: &[&str] = &["cargo", "check", "-p", "ffs-error", "--lib"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchCapacityPreflightReport {
    pub schema_version: u32,
    pub capacity_verdict: String,
    pub status_capture: RchCapacityStatusCapture,
    pub daemon: RchCapacityDaemonSummary,
    pub worker_counts: RchCapacityWorkerCounts,
    #[serde(default)]
    pub blocker_reasons: Vec<String>,
    #[serde(default)]
    pub operator_actions: Vec<serde_json::Value>,
    pub probe: RchCapacityProbeReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchCapacityStatusCapture {
    pub exit_code: i32,
    pub success: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchCapacityDaemonSummary {
    pub workers_total: u64,
    pub workers_healthy: u64,
    pub slots_total: Option<u64>,
    pub slots_available: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchCapacityWorkerCounts {
    pub admissible: u64,
    pub critical_pressure: u64,
    pub telemetry_gap: u64,
    pub telemetry_stale: u64,
    pub unhealthy: u64,
    pub unreachable: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchCapacityProbeReport {
    pub requested: bool,
    pub command: Vec<String>,
    pub exit_code: Option<i32>,
    pub verdict: String,
    pub fail_closed: bool,
    pub raw_log: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchCapacityPreflightValidationReport {
    pub schema_version: u32,
    pub report_path: String,
    pub report_schema_version: u32,
    pub valid: bool,
    pub capacity_verdict: String,
    pub worker_counts: RchCapacityWorkerCounts,
    pub probe_verdict: String,
    pub diagnostics: Vec<RchCapacityPreflightDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchCapacityPreflightDiagnostic {
    pub severity: String,
    pub code: String,
    pub message: String,
}

pub fn load_rch_capacity_preflight_report(
    path: impl AsRef<Path>,
) -> Result<RchCapacityPreflightReport> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read RCH capacity preflight report {}",
            path.display()
        )
    })?;
    serde_json::from_str(&raw).with_context(|| {
        format!(
            "failed to parse RCH capacity preflight report {}",
            path.display()
        )
    })
}

#[must_use]
pub fn validate_rch_capacity_preflight_report(
    report: &RchCapacityPreflightReport,
    report_path: impl Into<String>,
) -> RchCapacityPreflightValidationReport {
    let mut diagnostics = Vec::new();

    validate_schema_version(report, &mut diagnostics);
    validate_capacity_verdict(report, &mut diagnostics);
    validate_worker_counts(report, &mut diagnostics);
    validate_blocker_explanations(report, &mut diagnostics);
    validate_status_capture(report, &mut diagnostics);
    validate_probe(report, &mut diagnostics);

    let valid = diagnostics
        .iter()
        .all(|diagnostic| diagnostic.severity != "error");

    RchCapacityPreflightValidationReport {
        schema_version: RCH_CAPACITY_PREFLIGHT_VALIDATION_SCHEMA_VERSION,
        report_path: report_path.into(),
        report_schema_version: report.schema_version,
        valid,
        capacity_verdict: report.capacity_verdict.clone(),
        worker_counts: report.worker_counts.clone(),
        probe_verdict: report.probe.verdict.clone(),
        diagnostics,
    }
}

pub fn fail_on_rch_capacity_preflight_errors(
    report: &RchCapacityPreflightValidationReport,
) -> Result<()> {
    let errors: Vec<&RchCapacityPreflightDiagnostic> = report
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == "error")
        .collect();
    if errors.is_empty() {
        return Ok(());
    }

    let summary = errors
        .iter()
        .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
        .collect::<Vec<_>>()
        .join("; ");
    bail!("RCH capacity preflight report failed validation: {summary}");
}

#[must_use]
pub fn render_rch_capacity_preflight_markdown(
    report: &RchCapacityPreflightValidationReport,
) -> String {
    let diagnostics = if report.diagnostics.is_empty() {
        "- none\n".to_owned()
    } else {
        let mut output = String::new();
        for diagnostic in &report.diagnostics {
            let _ = writeln!(
                output,
                "- `{}` `{}`: {}",
                diagnostic.severity, diagnostic.code, diagnostic.message
            );
        }
        output
    };

    format!(
        "\
# RCH Capacity Preflight Validation

- Valid: `{}`
- Capacity verdict: `{}`
- Probe verdict: `{}`
- Admissible workers: `{}`
- Critical pressure workers: `{}`
- Telemetry gap workers: `{}`
- Unreachable workers: `{}`

## Diagnostics

{}",
        report.valid,
        report.capacity_verdict,
        report.probe_verdict,
        report.worker_counts.admissible,
        report.worker_counts.critical_pressure,
        report.worker_counts.telemetry_gap,
        report.worker_counts.unreachable,
        diagnostics
    )
}

fn validate_schema_version(
    report: &RchCapacityPreflightReport,
    diagnostics: &mut Vec<RchCapacityPreflightDiagnostic>,
) {
    if report.schema_version != RCH_CAPACITY_PREFLIGHT_SCHEMA_VERSION {
        push_error(
            diagnostics,
            "schema_version_unsupported",
            format!(
                "expected schema_version={}, got {}",
                RCH_CAPACITY_PREFLIGHT_SCHEMA_VERSION, report.schema_version
            ),
        );
    }
}

fn validate_capacity_verdict(
    report: &RchCapacityPreflightReport,
    diagnostics: &mut Vec<RchCapacityPreflightDiagnostic>,
) {
    match report.capacity_verdict.as_str() {
        "admissible_capacity_available"
        | "no_admissible_workers"
        | "no_workers_reported"
        | "status_capture_failed" => {}
        other => push_error(
            diagnostics,
            "capacity_verdict_unknown",
            format!("unknown capacity verdict `{other}`"),
        ),
    }
}

fn validate_worker_counts(
    report: &RchCapacityPreflightReport,
    diagnostics: &mut Vec<RchCapacityPreflightDiagnostic>,
) {
    let counts = &report.worker_counts;
    if report.capacity_verdict == "admissible_capacity_available" && counts.admissible == 0 {
        push_error(
            diagnostics,
            "admissible_verdict_without_worker",
            "admissible_capacity_available requires at least one admissible worker",
        );
    }
    if report.capacity_verdict == "no_admissible_workers" && counts.admissible != 0 {
        push_error(
            diagnostics,
            "blocked_verdict_with_admissible_worker",
            "no_admissible_workers cannot report admissible workers",
        );
    }
    if counts.admissible > report.daemon.workers_total {
        push_error(
            diagnostics,
            "admissible_exceeds_total",
            "admissible worker count exceeds workers_total",
        );
    }
    if report.daemon.workers_healthy > report.daemon.workers_total {
        push_error(
            diagnostics,
            "healthy_exceeds_total",
            "healthy worker count exceeds workers_total",
        );
    }
}

fn validate_blocker_explanations(
    report: &RchCapacityPreflightReport,
    diagnostics: &mut Vec<RchCapacityPreflightDiagnostic>,
) {
    let blocked = matches!(
        report.capacity_verdict.as_str(),
        "no_admissible_workers" | "no_workers_reported" | "status_capture_failed"
    );
    if blocked && report.blocker_reasons.is_empty() && report.operator_actions.is_empty() {
        push_error(
            diagnostics,
            "blocked_without_explanation",
            "blocked capacity verdict requires blocker_reasons or operator_actions",
        );
    }
    require_reason_when_count_positive(
        diagnostics,
        report.worker_counts.critical_pressure,
        &report.blocker_reasons,
        "critical_pressure",
    );
    require_reason_when_count_positive(
        diagnostics,
        report.worker_counts.telemetry_gap,
        &report.blocker_reasons,
        "telemetry_gap",
    );
    require_reason_when_count_positive(
        diagnostics,
        report.worker_counts.unreachable,
        &report.blocker_reasons,
        "unreachable_workers",
    );
    require_reason_when_count_positive(
        diagnostics,
        report.worker_counts.unhealthy,
        &report.blocker_reasons,
        "unhealthy_workers",
    );
}

fn validate_status_capture(
    report: &RchCapacityPreflightReport,
    diagnostics: &mut Vec<RchCapacityPreflightDiagnostic>,
) {
    let status_failed =
        report.status_capture.exit_code != 0 || report.status_capture.success == Some(false);
    if status_failed && report.capacity_verdict != "status_capture_failed" {
        push_error(
            diagnostics,
            "status_failure_without_verdict",
            "failed rch status capture must use status_capture_failed verdict",
        );
    }
}

fn validate_probe(
    report: &RchCapacityPreflightReport,
    diagnostics: &mut Vec<RchCapacityPreflightDiagnostic>,
) {
    let probe = &report.probe;
    if probe.requested && !probe_command_matches(&probe.command) {
        push_error(
            diagnostics,
            "probe_command_unexpected",
            "requested probe must use cargo check -p ffs-error --lib",
        );
    }

    match (probe.requested, probe.verdict.as_str()) {
        (false, "not_run") => {
            if probe.exit_code.is_some() || probe.fail_closed {
                push_error(
                    diagnostics,
                    "probe_not_run_has_result",
                    "non-requested probe must not include exit code or fail_closed=true",
                );
            }
        }
        (false, other) => push_error(
            diagnostics,
            "probe_unrequested_verdict",
            format!("non-requested probe must use not_run verdict, got `{other}`"),
        ),
        (true, "remote_success") => {
            if probe.exit_code != Some(0) || probe.fail_closed {
                push_error(
                    diagnostics,
                    "remote_probe_success_not_clean",
                    "remote_success probe requires exit_code=0 and fail_closed=false",
                );
            }
        }
        (true, "local_fallback_rejected" | "remote_required_refused" | "remote_failure") => {
            if !probe.fail_closed {
                push_error(
                    diagnostics,
                    "probe_failure_not_fail_closed",
                    "failed or refused probe verdict must set fail_closed=true",
                );
            }
            if probe.exit_code == Some(0) {
                push_error(
                    diagnostics,
                    "probe_failure_exit_code_clean",
                    "failed or refused probe verdict cannot report exit_code=0",
                );
            }
        }
        (true, "no_remote_summary") => push_error(
            diagnostics,
            "probe_no_remote_summary",
            "requested probe produced neither remote summary nor explicit local-fallback refusal",
        ),
        (true, other) => push_error(
            diagnostics,
            "probe_verdict_unknown",
            format!("unknown probe verdict `{other}`"),
        ),
    }

    if probe.requested && probe.raw_log.trim().is_empty() {
        push_error(
            diagnostics,
            "probe_raw_log_missing",
            "requested probe must include raw_log path",
        );
    }
}

fn require_reason_when_count_positive(
    diagnostics: &mut Vec<RchCapacityPreflightDiagnostic>,
    count: u64,
    reasons: &[String],
    expected_reason: &str,
) {
    if count > 0 && !reasons.iter().any(|reason| reason == expected_reason) {
        push_error(
            diagnostics,
            "worker_count_without_reason",
            format!(
                "worker count for `{expected_reason}` is positive but blocker reason is absent"
            ),
        );
    }
}

fn probe_command_matches(command: &[String]) -> bool {
    command
        .iter()
        .map(String::as_str)
        .eq(EXPECTED_PROBE_COMMAND.iter().copied())
}

fn push_error(
    diagnostics: &mut Vec<RchCapacityPreflightDiagnostic>,
    code: &str,
    message: impl Into<String>,
) {
    diagnostics.push(RchCapacityPreflightDiagnostic {
        severity: "error".to_owned(),
        code: code.to_owned(),
        message: message.into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> RchCapacityPreflightReport {
        RchCapacityPreflightReport {
            schema_version: RCH_CAPACITY_PREFLIGHT_SCHEMA_VERSION,
            capacity_verdict: "no_admissible_workers".to_owned(),
            status_capture: RchCapacityStatusCapture {
                exit_code: 0,
                success: Some(true),
            },
            daemon: RchCapacityDaemonSummary {
                workers_total: 10,
                workers_healthy: 7,
                slots_total: Some(134),
                slots_available: Some(134),
            },
            worker_counts: RchCapacityWorkerCounts {
                admissible: 0,
                critical_pressure: 7,
                telemetry_gap: 3,
                telemetry_stale: 3,
                unhealthy: 3,
                unreachable: 2,
            },
            blocker_reasons: vec![
                "critical_pressure".to_owned(),
                "telemetry_gap".to_owned(),
                "unreachable_workers".to_owned(),
                "unhealthy_workers".to_owned(),
            ],
            operator_actions: vec![serde_json::json!({
                "source": "remediation_hints",
                "message": "worker under critical pressure",
            })],
            probe: RchCapacityProbeReport {
                requested: true,
                command: EXPECTED_PROBE_COMMAND
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                exit_code: Some(1),
                verdict: "local_fallback_rejected".to_owned(),
                fail_closed: true,
                raw_log: "artifacts/e2e/run/rch_capacity_probe.raw".to_owned(),
            },
        }
    }

    fn validate(report: &RchCapacityPreflightReport) -> RchCapacityPreflightValidationReport {
        validate_rch_capacity_preflight_report(report, "report.json")
    }

    #[test]
    fn accepts_no_admissible_workers_with_fail_closed_probe() {
        let report = sample_report();
        let validation = validate(&report);

        assert!(validation.valid);
        assert_eq!(
            validation.diagnostics,
            [] as [RchCapacityPreflightDiagnostic; 0]
        );
        assert_eq!(validation.capacity_verdict, "no_admissible_workers");
        assert_eq!(validation.probe_verdict, "local_fallback_rejected");
    }

    #[test]
    fn accepts_admissible_capacity_with_remote_success_probe() {
        let mut report = sample_report();
        report.capacity_verdict = "admissible_capacity_available".to_owned();
        report.worker_counts.admissible = 2;
        report.worker_counts.critical_pressure = 0;
        report.worker_counts.telemetry_gap = 0;
        report.worker_counts.unhealthy = 0;
        report.worker_counts.unreachable = 0;
        report.blocker_reasons.clear();
        report.operator_actions.clear();
        report.probe.exit_code = Some(0);
        report.probe.verdict = "remote_success".to_owned();
        report.probe.fail_closed = false;

        let validation = validate(&report);

        assert!(validation.valid);
        assert_eq!(
            validation.diagnostics,
            [] as [RchCapacityPreflightDiagnostic; 0]
        );
    }

    #[test]
    fn accepts_default_status_only_preflight() {
        let mut report = sample_report();
        report.probe.requested = false;
        report.probe.exit_code = None;
        report.probe.verdict = "not_run".to_owned();
        report.probe.fail_closed = false;

        let validation = validate(&report);

        assert!(validation.valid);
    }

    #[test]
    fn rejects_local_fallback_when_not_fail_closed() {
        let mut report = sample_report();
        report.probe.fail_closed = false;

        let validation = validate(&report);

        assert!(!validation.valid);
        assert!(has_code(&validation, "probe_failure_not_fail_closed"));
    }

    #[test]
    fn rejects_remote_failure_with_clean_exit_code() {
        let mut report = sample_report();
        report.probe.verdict = "remote_failure".to_owned();
        report.probe.exit_code = Some(0);

        let validation = validate(&report);

        assert!(!validation.valid);
        assert!(has_code(&validation, "probe_failure_exit_code_clean"));
    }

    #[test]
    fn rejects_probe_without_rch_summary() {
        let mut report = sample_report();
        report.probe.verdict = "no_remote_summary".to_owned();

        let validation = validate(&report);

        assert!(!validation.valid);
        assert!(has_code(&validation, "probe_no_remote_summary"));
    }

    #[test]
    fn rejects_blocked_capacity_without_explanation() {
        let mut report = sample_report();
        report.blocker_reasons.clear();
        report.operator_actions.clear();

        let validation = validate(&report);

        assert!(!validation.valid);
        assert!(has_code(&validation, "blocked_without_explanation"));
        assert!(has_code(&validation, "worker_count_without_reason"));
    }

    #[test]
    fn rch_capacity_preflight_report_json_shape() -> Result<()> {
        let report = sample_report();
        let encoded = serde_json::to_string(&report)?;
        let decoded: RchCapacityPreflightReport = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, report);

        let shape = serde_json::json!({
            "schema_version": report.schema_version,
            "capacity_verdict": report.capacity_verdict,
            "status_capture": report.status_capture,
            "daemon": report.daemon,
            "worker_counts": report.worker_counts,
            "blocker_reasons": report.blocker_reasons,
            "operator_actions": report.operator_actions,
            "probe": report.probe,
        });
        let json = serde_json::to_string_pretty(&shape)?;

        insta::assert_snapshot!("rch_capacity_preflight_report_json_shape", json);
        Ok(())
    }

    #[test]
    fn rch_capacity_preflight_validation_report_json_shape() -> Result<()> {
        let report = sample_report();
        let validation = validate(&report);
        let encoded = serde_json::to_string(&validation)?;
        let decoded: RchCapacityPreflightValidationReport = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, validation);

        let shape = serde_json::json!({
            "schema_version": validation.schema_version,
            "report_path": validation.report_path,
            "report_schema_version": validation.report_schema_version,
            "valid": validation.valid,
            "capacity_verdict": validation.capacity_verdict,
            "worker_counts": validation.worker_counts,
            "probe_verdict": validation.probe_verdict,
            "diagnostics": validation.diagnostics,
        });
        let json = serde_json::to_string_pretty(&shape)?;

        insta::assert_snapshot!("rch_capacity_preflight_validation_report_json_shape", json);
        Ok(())
    }

    #[test]
    fn render_rch_capacity_preflight_markdown_no_admissible_workers() {
        let report = sample_report();
        let validation = validate(&report);
        let markdown = render_rch_capacity_preflight_markdown(&validation);

        insta::assert_snapshot!(
            "render_rch_capacity_preflight_markdown_no_admissible_workers",
            markdown
        );
    }

    fn has_code(report: &RchCapacityPreflightValidationReport, code: &str) -> bool {
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == code)
    }
}
