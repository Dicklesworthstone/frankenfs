#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

// ── Baseline file format ────────────────────────────────────────────────────

/// Structured performance baseline as emitted by `benchmark_record.sh`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerfBaseline {
    pub generated_at: String,
    #[serde(default)]
    pub commit: String,
    #[serde(default)]
    pub branch: String,
    pub p99_warn_threshold_percent: f64,
    pub p99_fail_threshold_percent: f64,
    #[serde(default)]
    pub measurements: Vec<BaselineMeasurement>,
}

/// A single operation measurement within a baseline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineMeasurement {
    pub operation: String,
    #[serde(default)]
    pub metric: String,
    #[serde(default)]
    pub p50_us: f64,
    #[serde(default)]
    pub p95_us: f64,
    #[serde(default)]
    pub p99_us: f64,
    #[serde(default)]
    pub throughput_ops_sec: f64,
    pub status: String,
}

/// Parse a baseline JSON string into a `PerfBaseline`.
pub fn parse_baseline(json: &str) -> Result<PerfBaseline, serde_json::Error> {
    serde_json::from_str(json)
}

// ── Throughput regression ───────────────────────────────────────────────────

/// Compare current throughput against a baseline and classify the result.
///
/// A throughput **drop** is a regression (lower is worse), which is the inverse
/// of latency regression (higher is worse). Returns `None` when
/// `baseline_ops_sec` is not positive.
#[must_use]
pub fn classify_throughput_regression(
    baseline_ops_sec: f64,
    current_ops_sec: f64,
    threshold: RegressionThreshold,
) -> Option<RegressionOutcome> {
    if baseline_ops_sec <= 0.0 {
        return None;
    }

    // Throughput drop is negative delta — invert so a drop is reported as positive regression.
    let delta_percent = ((baseline_ops_sec - current_ops_sec) / baseline_ops_sec) * 100.0;
    let status = if delta_percent > threshold.fail_percent {
        RegressionStatus::Fail
    } else if delta_percent > threshold.warn_percent {
        RegressionStatus::Warn
    } else {
        RegressionStatus::Ok
    };

    Some(RegressionOutcome {
        status,
        delta_percent,
    })
}

// ── Regression threshold and classification ─────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RegressionThreshold {
    pub warn_percent: f64,
    pub fail_percent: f64,
}

impl RegressionThreshold {
    #[must_use]
    pub const fn new(warn_percent: f64, fail_percent: f64) -> Self {
        Self {
            warn_percent,
            fail_percent,
        }
    }
}

impl Default for RegressionThreshold {
    fn default() -> Self {
        Self::new(10.0, 20.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegressionStatus {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RegressionOutcome {
    pub status: RegressionStatus,
    pub delta_percent: f64,
}

/// Compare current p99 latency against a baseline and classify the result.
///
/// Returns `None` when `baseline_ms` is not positive, because a ratio would
/// be undefined for threshold evaluation.
#[must_use]
pub fn classify_latency_regression(
    baseline_ms: f64,
    current_ms: f64,
    threshold: RegressionThreshold,
) -> Option<RegressionOutcome> {
    if baseline_ms <= 0.0 {
        return None;
    }

    let delta_percent = ((current_ms - baseline_ms) / baseline_ms) * 100.0;
    let status = if delta_percent > threshold.fail_percent {
        RegressionStatus::Fail
    } else if delta_percent > threshold.warn_percent {
        RegressionStatus::Warn
    } else {
        RegressionStatus::Ok
    };

    Some(RegressionOutcome {
        status,
        delta_percent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_returns_none_for_non_positive_baseline() {
        let threshold = RegressionThreshold::default();
        assert!(classify_latency_regression(0.0, 10.0, threshold).is_none());
        assert!(classify_latency_regression(-1.0, 10.0, threshold).is_none());
    }

    #[test]
    fn classify_ok_when_within_warn_threshold() -> Result<(), &'static str> {
        let threshold = RegressionThreshold::new(10.0, 20.0);
        let outcome = classify_latency_regression(100.0, 108.0, threshold)
            .ok_or("positive baseline should produce an outcome")?;
        assert_eq!(outcome.status, RegressionStatus::Ok);
        Ok(())
    }

    #[test]
    fn classify_warn_when_above_warn_below_fail() -> Result<(), &'static str> {
        let threshold = RegressionThreshold::new(10.0, 20.0);
        let outcome = classify_latency_regression(100.0, 112.0, threshold)
            .ok_or("positive baseline should produce an outcome")?;
        assert_eq!(outcome.status, RegressionStatus::Warn);
        Ok(())
    }

    #[test]
    fn classify_fail_when_above_fail_threshold() -> Result<(), &'static str> {
        let threshold = RegressionThreshold::new(10.0, 20.0);
        let outcome = classify_latency_regression(100.0, 130.0, threshold)
            .ok_or("positive baseline should produce an outcome")?;
        assert_eq!(outcome.status, RegressionStatus::Fail);
        Ok(())
    }

    // ── bd-3ib.3: Performance baseline and regression detection tests ──

    #[test]
    fn perf_baseline_json_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        // Verify the PerfBaseline struct serializes and deserializes correctly.
        let baseline = PerfBaseline {
            generated_at: "2026-02-17T00:00:00Z".to_owned(),
            commit: "abc123".to_owned(),
            branch: "main".to_owned(),
            p99_warn_threshold_percent: 10.0,
            p99_fail_threshold_percent: 20.0,
            measurements: vec![
                BaselineMeasurement {
                    operation: "metadata_parity_cli".to_owned(),
                    metric: "latency".to_owned(),
                    p50_us: 800.0,
                    p95_us: 1100.0,
                    p99_us: 1450.0,
                    throughput_ops_sec: 1011.5,
                    status: "measured".to_owned(),
                },
                BaselineMeasurement {
                    operation: "write_seq_4k".to_owned(),
                    metric: "latency".to_owned(),
                    p50_us: 0.0,
                    p95_us: 0.0,
                    p99_us: 0.0,
                    throughput_ops_sec: 0.0,
                    status: "pending".to_owned(),
                },
            ],
        };

        let json = serde_json::to_string_pretty(&baseline)?;
        insta::assert_snapshot!("perf_baseline_json_shape", json);

        let parsed = parse_baseline(&json)?;
        assert_eq!(parsed, baseline);
        assert_eq!(parsed.generated_at, "2026-02-17T00:00:00Z");
        assert_eq!(parsed.commit, "abc123");
        assert_eq!(parsed.measurements.len(), 2);
        let metadata = parsed
            .measurements
            .iter()
            .find(|measurement| measurement.operation == "metadata_parity_cli")
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "metadata_parity_cli measurement present",
                )
            })?;
        assert!((metadata.p99_us - 1450.0).abs() < f64::EPSILON);
        let pending = parsed
            .measurements
            .iter()
            .find(|measurement| measurement.status == "pending")
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "pending measurement present",
                )
            })?;
        assert_eq!(pending.operation, "write_seq_4k");
        Ok(())
    }

    #[test]
    fn perf_baseline_comparison_detects_regression() -> Result<(), &'static str> {
        // Compare two baselines where one measurement regressed.
        let threshold = RegressionThreshold::new(10.0, 20.0);
        let baseline_p99 = 1000.0; // 1000 μs
        let current_p99 = 1250.0; // 25% worse → Fail

        let outcome = classify_latency_regression(baseline_p99, current_p99, threshold)
            .ok_or("valid baseline")?;
        assert_eq!(outcome.status, RegressionStatus::Fail);
        assert!((outcome.delta_percent - 25.0).abs() < 0.01);
        Ok(())
    }

    #[test]
    fn perf_baseline_comparison_passes_within_threshold() -> Result<(), &'static str> {
        // Compare two baselines where measurements are similar.
        let threshold = RegressionThreshold::new(10.0, 20.0);
        let baseline_p99 = 1000.0;
        let current_p99 = 1050.0; // 5% worse → Ok

        let outcome = classify_latency_regression(baseline_p99, current_p99, threshold)
            .ok_or("valid baseline")?;
        assert_eq!(outcome.status, RegressionStatus::Ok);
        assert!((outcome.delta_percent - 5.0).abs() < 0.01);
        Ok(())
    }

    #[test]
    fn perf_baseline_empty_measurements_is_valid() -> Result<(), serde_json::Error> {
        // An empty baseline (no measurements yet) is a valid state.
        let json = r#"{
            "generated_at": "2026-02-17T00:00:00Z",
            "p99_warn_threshold_percent": 10.0,
            "p99_fail_threshold_percent": 20.0,
            "measurements": []
        }"#;
        let baseline = parse_baseline(json)?;
        assert_eq!(baseline.measurements, [] as [BaselineMeasurement; 0]);
        assert_eq!(baseline.commit, ""); // defaults to empty
        Ok(())
    }

    #[test]
    fn perf_throughput_10pct_drop_detected() -> Result<(), &'static str> {
        // A 10% throughput drop should be flagged as a warning with default thresholds.
        let threshold = RegressionThreshold::default(); // 10% warn, 20% fail
        let baseline_ops = 1000.0;
        let current_ops = 880.0; // 12% drop

        let outcome = classify_throughput_regression(baseline_ops, current_ops, threshold)
            .ok_or("valid baseline")?;
        assert_eq!(outcome.status, RegressionStatus::Warn);
        assert!((outcome.delta_percent - 12.0).abs() < 0.01);
        Ok(())
    }

    #[test]
    fn perf_throughput_improvement_passes() -> Result<(), &'static str> {
        // Throughput *improvement* (higher ops/sec) is not a regression.
        let threshold = RegressionThreshold::default();
        let baseline_ops = 1000.0;
        let current_ops = 1200.0; // 20% improvement

        let outcome = classify_throughput_regression(baseline_ops, current_ops, threshold)
            .ok_or("valid baseline")?;
        assert_eq!(outcome.status, RegressionStatus::Ok);
        // delta_percent should be negative (improvement).
        assert!(outcome.delta_percent < 0.0);
        Ok(())
    }

    #[test]
    fn perf_normal_variance_under_3pct_passes() -> Result<(), &'static str> {
        // Normal run-to-run variance under 3% should always pass, even with
        // tight thresholds (warn=5%, fail=10%).
        let threshold = RegressionThreshold::new(5.0, 10.0);

        // Latency: 2.5% increase → Ok.
        let outcome =
            classify_latency_regression(100.0, 102.5, threshold).ok_or("valid baseline")?;
        assert_eq!(outcome.status, RegressionStatus::Ok);

        // Throughput: 2.5% drop → Ok.
        let outcome =
            classify_throughput_regression(1000.0, 975.0, threshold).ok_or("valid baseline")?;
        assert_eq!(outcome.status, RegressionStatus::Ok);
        Ok(())
    }

    #[test]
    fn perf_custom_threshold_overrides_default() -> Result<(), &'static str> {
        // Custom thresholds: very tight (3% warn, 8% fail).
        let tight = RegressionThreshold::new(3.0, 8.0);

        // 5% latency increase: would be Ok with defaults (10%/20%),
        // but is Warn with tight thresholds.
        let outcome = classify_latency_regression(100.0, 105.0, tight).ok_or("valid baseline")?;
        assert_eq!(outcome.status, RegressionStatus::Warn);

        // Same value with default thresholds: Ok.
        let outcome = classify_latency_regression(100.0, 105.0, RegressionThreshold::default())
            .ok_or("valid baseline")?;
        assert_eq!(outcome.status, RegressionStatus::Ok);
        Ok(())
    }
}
