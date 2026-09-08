//! Fuzz campaign dashboard: per-target metrics, trend tracking, and regression alerts.
//!
//! Parses `campaign_summary.json` files produced by `nightly_fuzz.sh` and
//! provides trend analysis across historical campaigns to identify:
//!
//! - Underperforming targets (low throughput, zero coverage growth).
//! - Regression signals (throughput/coverage drops between campaigns).
//! - Crash-discovery velocity for prioritizing triage effort.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

/// Default threshold: throughput drop of more than 50% triggers a regression alert.
pub const THROUGHPUT_REGRESSION_THRESHOLD: f64 = 0.5;

/// Default threshold: coverage drop of more than 20% triggers a regression alert.
pub const COVERAGE_REGRESSION_THRESHOLD: f64 = 0.2;

// ── Campaign summary schema (matches nightly_fuzz.sh output) ──────────

/// Top-level campaign summary produced by `nightly_fuzz.sh`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignSummary {
    pub campaign_id: String,
    pub commit_sha: String,
    pub timestamp: String,
    pub config: CampaignConfig,
    pub totals: CampaignTotals,
    pub targets: Vec<TargetResult>,
}

/// Campaign configuration parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignConfig {
    pub duration_per_target: u64,
    pub jobs: u32,
    pub target_count: u32,
}

/// Aggregate campaign totals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignTotals {
    pub elapsed_seconds: u64,
    pub total_crashes: u64,
    pub total_coverage: u64,
    pub total_runs: u64,
}

/// Per-target fuzzing result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetResult {
    pub target: String,
    pub status: String,
    pub exit_code: i32,
    pub coverage: u64,
    pub total_runs: u64,
    pub corpus_size: u64,
    pub crash_count: u64,
    pub new_inputs: u64,
    pub elapsed_seconds: u64,
}

impl TargetResult {
    /// Compute executions per second for this target.
    #[must_use]
    pub fn execs_per_sec(&self) -> f64 {
        if self.elapsed_seconds == 0 {
            return 0.0;
        }
        self.total_runs as f64 / self.elapsed_seconds as f64
    }
}

// ── Dashboard health assessment ───────────────────────────────────────

/// Health status for a fuzz target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetHealth {
    /// Target is performing well.
    Healthy,
    /// Target shows signs of stagnation (no new inputs, no coverage growth).
    Stagnant,
    /// Target has discovered crashes that need triage.
    CrashesFound,
    /// Target failed to run or had an unexpected error.
    Error,
}

/// Per-target health assessment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TargetHealthReport {
    pub target: String,
    pub health: TargetHealth,
    pub execs_per_sec: f64,
    pub coverage: u64,
    pub crash_count: u64,
    pub corpus_size: u64,
    pub new_inputs: u64,
    pub detail: String,
}

/// Assess health for all targets in a campaign.
#[must_use]
pub fn assess_campaign_health(summary: &CampaignSummary) -> Vec<TargetHealthReport> {
    summary
        .targets
        .iter()
        .map(|t| {
            let health = if t.exit_code != 0 && t.crash_count == 0 {
                TargetHealth::Error
            } else if t.crash_count > 0 {
                TargetHealth::CrashesFound
            } else if t.new_inputs == 0 && t.coverage == 0 {
                TargetHealth::Stagnant
            } else {
                TargetHealth::Healthy
            };

            let detail = match health {
                TargetHealth::Healthy => {
                    format!(
                        "{:.0} exec/s, {} coverage, {} new inputs",
                        t.execs_per_sec(),
                        t.coverage,
                        t.new_inputs
                    )
                }
                TargetHealth::Stagnant => {
                    "zero new inputs and zero coverage — consider new seeds".to_owned()
                }
                TargetHealth::CrashesFound => {
                    format!("{} crash(es) need triage", t.crash_count)
                }
                TargetHealth::Error => {
                    format!("exit code {} — check run log", t.exit_code)
                }
            };

            TargetHealthReport {
                target: t.target.clone(),
                health,
                execs_per_sec: t.execs_per_sec(),
                coverage: t.coverage,
                crash_count: t.crash_count,
                corpus_size: t.corpus_size,
                new_inputs: t.new_inputs,
                detail,
            }
        })
        .collect()
}

// ── Trend comparison ──────────────────────────────────────────────────

/// Regression alert for a target between two campaigns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegressionAlert {
    pub target: String,
    pub metric: String,
    pub baseline_value: f64,
    pub current_value: f64,
    pub change_pct: f64,
    pub threshold_pct: f64,
    pub severity: AlertSeverity,
}

/// Alert severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Warning,
    Critical,
}

/// Compare two campaigns and detect regressions.
///
/// Returns alerts for any target where throughput or coverage has regressed
/// beyond the configured thresholds.
#[must_use]
pub fn detect_regressions(
    baseline: &CampaignSummary,
    current: &CampaignSummary,
) -> Vec<RegressionAlert> {
    let mut alerts = Vec::new();

    for current_target in &current.targets {
        let Some(baseline_target) = baseline
            .targets
            .iter()
            .find(|t| t.target == current_target.target)
        else {
            continue;
        };

        // Throughput regression check
        let base_eps = baseline_target.execs_per_sec();
        let curr_eps = current_target.execs_per_sec();
        if base_eps > 0.0 {
            let change = (curr_eps - base_eps) / base_eps;
            if change < -THROUGHPUT_REGRESSION_THRESHOLD {
                alerts.push(RegressionAlert {
                    target: current_target.target.clone(),
                    metric: "execs_per_sec".to_owned(),
                    baseline_value: base_eps,
                    current_value: curr_eps,
                    change_pct: change * 100.0,
                    threshold_pct: -THROUGHPUT_REGRESSION_THRESHOLD * 100.0,
                    severity: AlertSeverity::Warning,
                });
            }
        }

        // Coverage regression check
        let base_cov = baseline_target.coverage as f64;
        let curr_cov = current_target.coverage as f64;
        if base_cov > 0.0 {
            let change = (curr_cov - base_cov) / base_cov;
            if change < -COVERAGE_REGRESSION_THRESHOLD {
                alerts.push(RegressionAlert {
                    target: current_target.target.clone(),
                    metric: "coverage".to_owned(),
                    baseline_value: base_cov,
                    current_value: curr_cov,
                    change_pct: change * 100.0,
                    threshold_pct: -COVERAGE_REGRESSION_THRESHOLD * 100.0,
                    severity: AlertSeverity::Critical,
                });
            }
        }
    }

    alerts
}

/// Parse a campaign summary from JSON string.
///
/// # Errors
///
/// Returns an error if the JSON is malformed or missing required fields.
pub fn parse_campaign_summary(json: &str) -> Result<CampaignSummary, String> {
    let summary =
        serde_json::from_str(json).map_err(|e| format!("failed to parse campaign summary: {e}"))?;
    let errors = validate_campaign_summary(&summary);
    if errors.is_empty() {
        Ok(summary)
    } else {
        Err(format!("invalid campaign summary: {}", errors.join("; ")))
    }
}

/// Validate cross-field invariants for a parsed campaign summary.
#[must_use]
pub fn validate_campaign_summary(summary: &CampaignSummary) -> Vec<String> {
    let mut errors = Vec::new();

    if summary.campaign_id.trim().is_empty() {
        errors.push("campaign_id must not be empty".to_owned());
    }
    if summary.commit_sha.trim().is_empty() {
        errors.push("commit_sha must not be empty".to_owned());
    }
    if summary.timestamp.trim().is_empty() {
        errors.push("timestamp must not be empty".to_owned());
    }
    if summary.config.duration_per_target == 0 {
        errors.push("config.duration_per_target must be positive".to_owned());
    }
    if summary.config.jobs == 0 {
        errors.push("config.jobs must be positive".to_owned());
    }
    if summary.targets.is_empty() {
        errors.push("targets must not be empty".to_owned());
    }

    let actual_target_count = u32::try_from(summary.targets.len()).unwrap_or(u32::MAX);
    if summary.config.target_count != actual_target_count {
        errors.push(format!(
            "config.target_count {} does not match {} target row(s)",
            summary.config.target_count,
            summary.targets.len()
        ));
    }

    let mut target_names = BTreeSet::new();
    let mut total_crashes = 0_u64;
    let mut total_coverage = 0_u64;
    let mut total_runs = 0_u64;
    for target in &summary.targets {
        if target.target.trim().is_empty() {
            errors.push("target row has empty target name".to_owned());
        } else if !target_names.insert(target.target.as_str()) {
            errors.push(format!("duplicate target row {}", target.target));
        }
        if target.status.trim().is_empty() {
            errors.push(format!("target {} has empty status", target.target));
        }
        total_crashes = total_crashes.saturating_add(target.crash_count);
        total_coverage = total_coverage.saturating_add(target.coverage);
        total_runs = total_runs.saturating_add(target.total_runs);
    }

    if summary.totals.total_crashes != total_crashes {
        errors.push(format!(
            "totals.total_crashes {} does not match target sum {total_crashes}",
            summary.totals.total_crashes
        ));
    }
    if summary.totals.total_coverage != total_coverage {
        errors.push(format!(
            "totals.total_coverage {} does not match target sum {total_coverage}",
            summary.totals.total_coverage
        ));
    }
    if summary.totals.total_runs != total_runs {
        errors.push(format!(
            "totals.total_runs {} does not match target sum {total_runs}",
            summary.totals.total_runs
        ));
    }

    errors
}

/// Check that the nightly campaign script produces the expected JSON schema.
#[must_use]
pub fn validate_campaign_schema(json: &str) -> Vec<SchemaCheck> {
    let parsed = serde_json::from_str::<Value>(json).ok();
    let root = parsed.as_ref().and_then(Value::as_object);

    ["campaign_id", "commit_sha", "config", "totals", "targets"]
        .into_iter()
        .map(|field| SchemaCheck {
            field: field.to_owned(),
            present: root.is_some_and(|object| object.contains_key(field)),
        })
        .collect()
}

/// Result of checking a required field in the campaign schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaCheck {
    pub field: String,
    pub present: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_campaign() -> CampaignSummary {
        CampaignSummary {
            campaign_id: "20260312T120000Z".to_owned(),
            commit_sha: "abc1234".to_owned(),
            timestamp: "20260312T120000Z".to_owned(),
            config: CampaignConfig {
                duration_per_target: 60,
                jobs: 1,
                target_count: 4,
            },
            totals: CampaignTotals {
                elapsed_seconds: 240,
                total_crashes: 0,
                total_coverage: 5000,
                total_runs: 100_000,
            },
            targets: vec![
                TargetResult {
                    target: "fuzz_ext4_metadata".to_owned(),
                    status: "ok".to_owned(),
                    exit_code: 0,
                    coverage: 1500,
                    total_runs: 30_000,
                    corpus_size: 55,
                    crash_count: 0,
                    new_inputs: 3,
                    elapsed_seconds: 60,
                },
                TargetResult {
                    target: "fuzz_btrfs_metadata".to_owned(),
                    status: "ok".to_owned(),
                    exit_code: 0,
                    coverage: 1200,
                    total_runs: 25_000,
                    corpus_size: 45,
                    crash_count: 0,
                    new_inputs: 2,
                    elapsed_seconds: 60,
                },
                TargetResult {
                    target: "fuzz_ext4_dir_extent".to_owned(),
                    status: "ok".to_owned(),
                    exit_code: 0,
                    coverage: 1800,
                    total_runs: 35_000,
                    corpus_size: 27,
                    crash_count: 0,
                    new_inputs: 5,
                    elapsed_seconds: 60,
                },
                TargetResult {
                    target: "fuzz_ext4_xattr".to_owned(),
                    status: "ok".to_owned(),
                    exit_code: 0,
                    coverage: 500,
                    total_runs: 10_000,
                    corpus_size: 179,
                    crash_count: 0,
                    new_inputs: 1,
                    elapsed_seconds: 60,
                },
            ],
        }
    }

    fn sample_campaign_with_crashes() -> Result<CampaignSummary, String> {
        let mut c = sample_campaign();
        let ext4 = target_mut(&mut c, "fuzz_ext4_metadata")?;
        ext4.crash_count = 2;
        ext4.exit_code = 77;
        c.totals.total_crashes = 2;
        Ok(c)
    }

    fn target<'a>(summary: &'a CampaignSummary, target: &str) -> Result<&'a TargetResult, String> {
        summary
            .targets
            .iter()
            .find(|result| result.target == target)
            .ok_or_else(|| format!("missing {target} target"))
    }

    fn target_mut<'a>(
        summary: &'a mut CampaignSummary,
        target: &str,
    ) -> Result<&'a mut TargetResult, String> {
        summary
            .targets
            .iter_mut()
            .find(|result| result.target == target)
            .ok_or_else(|| format!("missing {target} target"))
    }

    fn first_alert(alerts: &[RegressionAlert]) -> Result<&RegressionAlert, String> {
        alerts
            .first()
            .ok_or_else(|| "missing regression alert".to_owned())
    }

    fn parse_campaign_summary_error(json: &str) -> Result<String, String> {
        match parse_campaign_summary(json) {
            Ok(_) => Err("campaign summary unexpectedly parsed".to_owned()),
            Err(err) => Ok(err),
        }
    }

    #[test]
    fn execs_per_sec_calculation() {
        let t = TargetResult {
            target: "test".to_owned(),
            status: "ok".to_owned(),
            exit_code: 0,
            coverage: 100,
            total_runs: 6000,
            corpus_size: 10,
            crash_count: 0,
            new_inputs: 1,
            elapsed_seconds: 60,
        };
        let eps = t.execs_per_sec();
        assert!((eps - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn execs_per_sec_zero_time() {
        let t = TargetResult {
            target: "test".to_owned(),
            status: "ok".to_owned(),
            exit_code: 0,
            coverage: 0,
            total_runs: 0,
            corpus_size: 0,
            crash_count: 0,
            new_inputs: 0,
            elapsed_seconds: 0,
        };
        assert!((t.execs_per_sec() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn assess_health_all_healthy() {
        let summary = sample_campaign();
        let reports = assess_campaign_health(&summary);
        assert_eq!(reports.len(), 4);
        for r in &reports {
            assert_eq!(r.health, TargetHealth::Healthy, "{} not healthy", r.target);
        }
    }

    #[test]
    fn assess_health_detects_crashes() -> Result<(), String> {
        let summary = sample_campaign_with_crashes()?;
        let reports = assess_campaign_health(&summary);
        let ext4 = reports
            .iter()
            .find(|r| r.target == "fuzz_ext4_metadata")
            .ok_or_else(|| "missing fuzz_ext4_metadata report".to_owned())?;
        assert_eq!(ext4.health, TargetHealth::CrashesFound);
        assert!(ext4.detail.contains("2 crash"));
        Ok(())
    }

    #[test]
    fn assess_health_detects_stagnant() -> Result<(), String> {
        let mut summary = sample_campaign();
        let xattr = target_mut(&mut summary, "fuzz_ext4_xattr")?;
        xattr.new_inputs = 0;
        xattr.coverage = 0;
        let reports = assess_campaign_health(&summary);
        let xattr = reports
            .iter()
            .find(|r| r.target == "fuzz_ext4_xattr")
            .ok_or_else(|| "missing fuzz_ext4_xattr report".to_owned())?;
        assert_eq!(xattr.health, TargetHealth::Stagnant);
        Ok(())
    }

    #[test]
    fn assess_health_detects_error() -> Result<(), String> {
        let mut summary = sample_campaign();
        target_mut(&mut summary, "fuzz_btrfs_metadata")?.exit_code = 1;
        let reports = assess_campaign_health(&summary);
        let btrfs = reports
            .iter()
            .find(|r| r.target == "fuzz_btrfs_metadata")
            .ok_or_else(|| "missing fuzz_btrfs_metadata report".to_owned())?;
        assert_eq!(btrfs.health, TargetHealth::Error);
        Ok(())
    }

    #[test]
    fn detect_regressions_no_alerts_for_improvement() -> Result<(), String> {
        let baseline = sample_campaign();
        let mut current = sample_campaign();
        // Improve throughput
        target_mut(&mut current, "fuzz_ext4_metadata")?.total_runs = 60_000;
        let alerts = detect_regressions(&baseline, &current);
        assert_eq!(alerts, [] as [RegressionAlert; 0]);
        Ok(())
    }

    #[test]
    fn detect_regressions_throughput_drop() -> Result<(), String> {
        let baseline = sample_campaign();
        let mut current = sample_campaign();
        // Drop throughput by 60% (below 50% threshold)
        target_mut(&mut current, "fuzz_ext4_metadata")?.total_runs = 12_000;
        let alerts = detect_regressions(&baseline, &current);
        assert_ne!(alerts, [] as [RegressionAlert; 0]);
        let alert = first_alert(&alerts)?;
        assert_eq!(alert.target, "fuzz_ext4_metadata");
        assert_eq!(alert.metric, "execs_per_sec");
        assert_eq!(alert.severity, AlertSeverity::Warning);
        Ok(())
    }

    #[test]
    fn detect_regressions_coverage_drop() -> Result<(), String> {
        let baseline = sample_campaign();
        let mut current = sample_campaign();
        // Drop coverage by 30% (below 20% threshold)
        target_mut(&mut current, "fuzz_ext4_dir_extent")?.coverage = 1200;
        let alerts = detect_regressions(&baseline, &current);
        let cov_alert = alerts.iter().find(|a| a.metric == "coverage");
        let cov_alert = cov_alert.ok_or_else(|| "missing coverage alert".to_owned())?;
        assert_eq!(cov_alert.severity, AlertSeverity::Critical);
        Ok(())
    }

    #[test]
    fn campaign_json_round_trips() -> Result<(), String> {
        let summary = sample_campaign();
        let json = serde_json::to_string_pretty(&summary).map_err(|err| err.to_string())?;
        let parsed = parse_campaign_summary(&json)?;
        assert_eq!(parsed, summary);
        Ok(())
    }

    #[test]
    fn campaign_summary_json_shape() -> Result<(), String> {
        let summary = sample_campaign();
        let json = serde_json::to_string_pretty(&summary).map_err(|err| err.to_string())?;

        insta::assert_snapshot!("campaign_summary_json_shape", json);
        let parsed = parse_campaign_summary(&json)?;
        assert_eq!(parsed, summary);
        Ok(())
    }

    #[test]
    fn parses_nightly_fuzz_script_summary_shape() -> Result<(), String> {
        let json = r#"{
          "schema_version": 1,
          "campaign_id": "nightly_20260506_120000",
          "timestamp": "2026-05-06T12:00:00+00:00",
          "created_at": "2026-05-06T12:00:00+00:00",
          "duration_per_target_secs": 60,
          "commit_sha": "abc1234",
          "config": {
            "duration_per_target": 60,
            "jobs": 1,
            "target_count": 2
          },
          "totals": {
            "elapsed_seconds": 123,
            "total_crashes": 1,
            "total_coverage": 55,
            "total_runs": 3000
          },
          "targets": [
            {
              "target": "fuzz_ext4_metadata",
              "status": "ok",
              "exit_code": 0,
              "coverage": 25,
              "total_runs": 1000,
              "corpus_size": 12,
              "crash_count": 0,
              "new_inputs": 2,
              "elapsed_seconds": 60
            },
            {
              "target": "fuzz_btrfs_metadata",
              "status": "crashes_found",
              "exit_code": 77,
              "coverage": 30,
              "total_runs": 2000,
              "corpus_size": 18,
              "crash_count": 1,
              "new_inputs": 0,
              "elapsed_seconds": 63
            }
          ]
        }"#;

        let parsed = parse_campaign_summary(json)?;
        assert_eq!(parsed.config.target_count, 2);
        assert_eq!(parsed.totals.total_runs, 3000);
        assert_eq!(target(&parsed, "fuzz_btrfs_metadata")?.crash_count, 1);
        Ok(())
    }

    #[test]
    fn parse_campaign_summary_rejects_garbage() {
        let result = parse_campaign_summary("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn parse_campaign_summary_rejects_target_count_drift() -> Result<(), String> {
        let mut summary = sample_campaign();
        summary.config.target_count = 99;
        let json = serde_json::to_string(&summary).map_err(|err| err.to_string())?;
        let err = parse_campaign_summary_error(&json)?;
        assert!(err.contains("config.target_count 99 does not match 4 target row"));
        Ok(())
    }

    #[test]
    fn parse_campaign_summary_rejects_totals_drift() -> Result<(), String> {
        let mut summary = sample_campaign();
        summary.totals.total_runs += 1;
        summary.totals.total_coverage += 1;
        summary.totals.total_crashes += 1;
        let json = serde_json::to_string(&summary).map_err(|err| err.to_string())?;
        let err = parse_campaign_summary_error(&json)?;
        assert!(err.contains("totals.total_runs"));
        assert!(err.contains("totals.total_coverage"));
        assert!(err.contains("totals.total_crashes"));
        Ok(())
    }

    #[test]
    fn validate_campaign_summary_rejects_duplicate_targets() -> Result<(), String> {
        let mut summary = sample_campaign();
        let duplicate_target = target(&summary, "fuzz_ext4_metadata")?.target.clone();
        target_mut(&mut summary, "fuzz_btrfs_metadata")?.target = duplicate_target;
        let errors = validate_campaign_summary(&summary);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("duplicate target row fuzz_ext4_metadata")),
            "expected duplicate target error, got {errors:?}",
        );
        Ok(())
    }

    #[test]
    fn validate_schema_checks_all_fields() -> Result<(), serde_json::Error> {
        let summary = sample_campaign();
        let json = serde_json::to_string(&summary)?;
        let checks = validate_campaign_schema(&json);
        assert_eq!(checks.len(), 5);
        for check in &checks {
            assert!(check.present, "field {} missing", check.field);
        }
        Ok(())
    }

    #[test]
    fn validate_schema_checks_ignore_string_literal_false_positives() {
        let json = r#"{
            "notes": "\"campaign_id\" \"commit_sha\" \"config\" \"totals\" \"targets\""
        }"#;

        let checks = validate_campaign_schema(json);
        assert_eq!(checks.len(), 5);
        for check in &checks {
            assert!(
                !check.present,
                "schema field {} should not be satisfied by string contents",
                check.field
            );
        }
    }

    #[test]
    fn validate_schema_checks_malformed_json_as_absent_fields() {
        let checks = validate_campaign_schema(r#"{"campaign_id": "unterminated"#);
        assert_eq!(checks.len(), 5);
        assert!(checks.iter().all(|check| !check.present));
    }

    #[test]
    fn nightly_script_produces_expected_schema_fields() -> std::io::Result<()> {
        let root = env!("CARGO_MANIFEST_DIR")
            .strip_suffix("/crates/ffs-harness")
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "harness must be in crates/ffs-harness",
                )
            })?;
        let script = format!("{root}/fuzz/scripts/nightly_fuzz.sh");
        let content = std::fs::read_to_string(&script)?;
        // Verify the script generates all required JSON fields
        assert!(
            content.contains("campaign_id"),
            "missing campaign_id in script"
        );
        assert!(
            content.contains("commit_sha"),
            "missing commit_sha in script"
        );
        assert!(content.contains("\"config\""), "missing config in script");
        assert!(
            content.contains("\"target_count\""),
            "missing config.target_count in script"
        );
        assert!(content.contains("\"totals\""), "missing totals in script");
        assert!(
            content.contains("\"total_crashes\""),
            "missing totals.total_crashes in script"
        );
        assert!(
            content.contains("\"total_coverage\""),
            "missing totals.total_coverage in script"
        );
        assert!(
            content.contains("\"total_runs\""),
            "missing totals.total_runs in script"
        );
        assert!(content.contains("\"targets\""), "missing targets in script");
        assert!(
            content.contains("crash_count"),
            "missing target crash_count in script"
        );
        assert!(
            content.contains("\"elapsed_seconds\""),
            "missing target elapsed_seconds in script"
        );
        Ok(())
    }

    #[test]
    fn regression_alert_json_round_trips() -> Result<(), serde_json::Error> {
        let alert = RegressionAlert {
            target: "fuzz_ext4_metadata".to_owned(),
            metric: "execs_per_sec".to_owned(),
            baseline_value: 500.0,
            current_value: 200.0,
            change_pct: -60.0,
            threshold_pct: -50.0,
            severity: AlertSeverity::Warning,
        };
        let json = serde_json::to_string(&alert)?;
        let parsed: RegressionAlert = serde_json::from_str(&json)?;
        assert_eq!(parsed, alert);
        Ok(())
    }

    #[test]
    fn regression_alert_json_shape() -> Result<(), serde_json::Error> {
        let alert = RegressionAlert {
            target: "fuzz_ext4_metadata".to_owned(),
            metric: "execs_per_sec".to_owned(),
            baseline_value: 500.0,
            current_value: 200.0,
            change_pct: -60.0,
            threshold_pct: -50.0,
            severity: AlertSeverity::Warning,
        };
        let json = serde_json::to_string_pretty(&alert)?;

        insta::assert_snapshot!("regression_alert_json_shape", json);
        let parsed: RegressionAlert = serde_json::from_str(&json)?;
        assert_eq!(parsed, alert);
        Ok(())
    }
}
